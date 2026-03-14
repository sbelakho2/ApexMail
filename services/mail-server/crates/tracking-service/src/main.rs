//! ApexMail Tracking Service — entry point.
//!
//! Startup sequence:
//!   1. Load configuration from environment variables.
//!   2. Derive crypto codec from `TRACKING_SECRET_KEY`.
//!   3. Connect to PostgreSQL and Redis.
//!   4. Build bot detector (AhoCorasick automaton).
//!   5. Assemble `AppState` and start the WAL flush processor.
//!   6. Bind axum HTTP server + (optionally) metrics listener.
//!   7. Serve until SIGTERM / SIGINT → graceful shutdown.
//!
//! Graceful shutdown:
//!   • Stops accepting new connections.
//!   • Waits for in-flight requests to complete (tower graceful shutdown).
//!   • Drains the Redis WAL → Postgres (EventProcessor::stop).

mod bot;
mod codec;
mod config;
mod processor;
mod routes;
mod state;
mod templates;

use std::sync::atomic::Ordering;
use std::sync::Arc;

use anyhow::{Context, Result};
use deadpool_redis::{Config as RedisPoolConfig, Runtime};
use sqlx::postgres::PgPoolOptions;
use tokio::signal;
use tracing::info;
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

use crate::bot::BotDetector;
use crate::codec::TrackingCodec;
use crate::config::load as load_config;
use crate::processor::EventProcessor;
use crate::routes::{build_router, health::SHUTTING_DOWN};
use crate::state::AppState;

#[tokio::main]
async fn main() -> Result<()> {
    // ── Structured logging ────────────────────────────────────────────
    tracing_subscriber::registry()
        .with(fmt::layer().json())
        .with(EnvFilter::from_default_env().add_directive("tracking_service=info".parse()?))
        .init();

    info!("ApexMail Tracking Service starting");

    // ── Config ────────────────────────────────────────────────────────
    let cfg = load_config().context("Failed to load configuration")?;
    let addr = cfg.server.addr;

    // ── Crypto codec ──────────────────────────────────────────────────
    let codec = TrackingCodec::new(&cfg.secret_key);

    // ── PostgreSQL ────────────────────────────────────────────────────
    let db = PgPoolOptions::new()
        .max_connections(cfg.database.max_connections)
        .acquire_timeout(std::time::Duration::from_secs(10))
        .idle_timeout(std::time::Duration::from_secs(300))
        .max_lifetime(std::time::Duration::from_secs(1800))
        .connect(&cfg.database.url)
        .await
        .context("Failed to connect to PostgreSQL")?;

    info!(max_conns = cfg.database.max_connections, "PostgreSQL pool ready");

    // ── Redis ─────────────────────────────────────────────────────────
    let redis_cfg = RedisPoolConfig::from_url(&cfg.redis.url);
    let redis_pool = redis_cfg
        .builder()
        .context("Failed to create Redis pool builder")?
        .max_size(cfg.redis.pool_size)
        .runtime(Runtime::Tokio1)
        .build()
        .context("Failed to build Redis pool")?;

    // Verify connectivity
    {
        let mut conn = redis_pool.get().await.context("Redis connection check")?;
        let _: String = redis::cmd("PING").query_async(&mut *conn).await.context("Redis PING")?;
    }
    info!(pool_size = cfg.redis.pool_size, "Redis pool ready");

    // ── Bot detector ──────────────────────────────────────────────────
    let bot_detector = BotDetector::new();

    // ── Event processor ───────────────────────────────────────────────
    let processor_arc = Arc::new(EventProcessor::new(db.clone(), redis_pool.clone()));
    {
        let p = processor_arc.clone();
        p.start();
    }
    info!("Event processor started");

    // ── Optional metrics server ───────────────────────────────────────
    if cfg.metrics.enabled {
        let metrics_addr: std::net::SocketAddr =
            format!("0.0.0.0:{}", cfg.metrics.port).parse().context("Bad metrics port")?;
        let builder = metrics_exporter_prometheus::PrometheusBuilder::new();
        builder
            .with_http_listener(metrics_addr)
            .install_recorder()
            .context("Failed to install Prometheus recorder")?;
        info!(port = cfg.metrics.port, "Prometheus metrics server ready");
    }

    // ── App state ─────────────────────────────────────────────────────
    let state = AppState::new(
        codec,
        db.clone(),
        redis_pool.clone(),
        processor_arc.clone(),
        bot_detector,
        cfg.clone(),
    );

    let router = build_router(state)
        .into_make_service_with_connect_info::<std::net::SocketAddr>();

    // ── Bind and serve ────────────────────────────────────────────────
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .context(format!("Failed to bind to {addr}"))?;
    info!(addr = %addr, "HTTP server listening");

    // Graceful shutdown via SIGTERM or SIGINT
    let shutdown_signal = async {
        let ctrl_c = async { signal::ctrl_c().await.ok() };
        #[cfg(unix)]
        let sigterm = async {
            match signal::unix::signal(signal::unix::SignalKind::terminate()) {
                Ok(mut signal) => {
                    signal.recv().await;
                }
                Err(error) => {
                    tracing::error!(?error, "SIGTERM handler setup failed");
                }
            }
        };
        #[cfg(not(unix))]
        let sigterm = std::future::pending::<()>();

        tokio::select! {
            _ = ctrl_c => info!("SIGINT received"),
            _ = sigterm => info!("SIGTERM received"),
        }

        // Signal health check to return 503 immediately (FIX-500-354)
        SHUTTING_DOWN.store(true, Ordering::SeqCst);
        info!("Shutdown signal received — draining connections");
    };

    axum::serve(listener, router)
        .with_graceful_shutdown(shutdown_signal)
        .await
        .context("axum server error")?;

    // ── Drain WAL on shutdown ─────────────────────────────────────────
    info!("HTTP server stopped — draining Redis WAL");
    processor_arc.stop().await;
    info!("ApexMail Tracking Service stopped cleanly");

    Ok(())
}
