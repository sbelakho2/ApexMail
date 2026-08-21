//! ApexMail Tracking Service — entry point.
//!
//! Startup sequence://! 1. Load configuration from environment variables.
//! 2. Derive crypto codec from `TRACKING_SECRET_KEY`.
//! 3. Connect to PostgreSQL and Redis.
//! 4. Build bot detector (AhoCorasick automaton).
//! 5. Assemble `AppState` and start the WAL flush processor.
//! 6. Bind axum HTTP server + (optionally) metrics listener.
//! 7. Serve until SIGTERM / SIGINT → graceful shutdown.
//!
//! Graceful shutdown://! • Stops accepting new connections.
//! • Waits for in-flight requests to complete (tower graceful shutdown).
//! • Drains the Redis WAL → Postgres (EventProcessor::stop).

use std::sync::atomic::Ordering;
use std::sync::Arc;

use anyhow::{Context, Result};
use deadpool_redis::{Config as RedisPoolConfig, Runtime};
use observability_service::otlp_exporter::{
    init_otlp_tracing, is_otlp_enabled, OtlpConfig, TracingGuard,
};
use sqlx::postgres::PgPoolOptions;
use tokio::signal;
use tracing::info;
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

// The service is built as a library (src/lib.rs) plus this thin binary so
// other ApexMail components (worker-processors) can share the codec exactly.
use tracking_service::bot::BotDetector;
use tracking_service::codec::TrackingCodec;
use tracking_service::config::load as load_config;
use tracking_service::processor::EventProcessor;
use tracking_service::routes::{build_router, health::SHUTTING_DOWN};
use tracking_service::state::AppState;

#[tokio::main]
async fn main() -> Result<()> {
    // ── Structured logging / OTLP tracing ────────────────────────────
    let _tracing_guard = init_tracing()?;

    info!("ApexMail Tracking Service starting");

    // ── Config ────────────────────────────────────────────────────────
    let cfg = load_config().context("Failed to load configuration")?;
    let addr = cfg.server.addr;

    // ── Crypto codec ──────────────────────────────────────────────────
    let codec = TrackingCodec::new(&cfg.secret_key);

    // ── PostgreSQL ────────────────────────────────────────────────────
    // PERF-100: Statement caching enabled (capacity 100) to avoid
    // re-preparation roundtrips for repeated queries.
    let connect_opts = cfg
        .database
        .url
        .parse::<sqlx::postgres::PgConnectOptions>()
        .context("Failed to parse database URL")?
        .statement_cache_capacity(100);
    let db = PgPoolOptions::new()
        .max_connections(cfg.database.max_connections)
        .acquire_timeout(std::time::Duration::from_secs(10))
        .idle_timeout(std::time::Duration::from_secs(300))
        .max_lifetime(std::time::Duration::from_secs(1800))
        .connect_with(connect_opts)
        .await
        .context("Failed to connect to PostgreSQL")?;

    info!(
        max_conns = cfg.database.max_connections,
        "PostgreSQL pool ready"
    );

    // ── Redis ─────────────────────────────────────────────────────────
    // PP-002: Configure pool timeouts so Redis outages don't hang indefinitely.
    // `create_timeout` limits how long we wait for a new Redis connection to be
    // established (TCP connect).  `wait_timeout` limits how long we wait for a
    // pooled connection to become available (acquire).
    let redis_cfg = RedisPoolConfig::from_url(&cfg.redis.url);
    let redis_pool = redis_cfg
        .builder()
        .context("Failed to create Redis pool builder")?
        .max_size(cfg.redis.pool_size)
        .runtime(Runtime::Tokio1)
        .create_timeout(Some(std::time::Duration::from_secs(10)))
        .wait_timeout(Some(std::time::Duration::from_secs(5)))
        .build()
        .context("Failed to build Redis pool")?;

    // Verify connectivity
    {
        let mut conn = redis_pool.get().await.context("Redis connection check")?;
        let _: String = redis::cmd("PING")
            .query_async(&mut *conn)
            .await
            .context("Redis PING")?;
    }
    info!(pool_size = cfg.redis.pool_size, "Redis pool ready");

    // ── Bot detector ──────────────────────────────────────────────────
    let bot_detector = BotDetector::new();

    // ── ClickHouse (OLAP event ingest) ────────────────────────────────
    let clickhouse = clickhouse::Client::default()
        .with_url(&cfg.clickhouse.url)
        .with_database(&cfg.clickhouse.database)
        .with_user(&cfg.clickhouse.user)
        .with_password(&cfg.clickhouse.password)
        .with_compression(clickhouse::Compression::Lz4);
    if !cfg.clickhouse.password.is_empty() || cfg.clickhouse.user != "default" {
        // Verify connectivity eagerly so a misconfigured ClickHouse is
        // visible at startup (log-only — tracking must not fail to boot).
        match clickhouse.query("SELECT 1").execute().await {
            Ok(()) => info!(
                url = %cfg.clickhouse.url,
                database = %cfg.clickhouse.database,
                user = %cfg.clickhouse.user,
                "ClickHouse connection verified"
            ),
            Err(error) => tracing::warn!(
                url = %cfg.clickhouse.url,
                error = %error,
                "ClickHouse unreachable — events will be written to Postgres only"
            ),
        }
    }

    // ── Event processor ───────────────────────────────────────────────
    let processor_arc = Arc::new(EventProcessor::new(
        db.clone(),
        redis_pool.clone(),
        clickhouse,
        std::time::Duration::from_secs(cfg.clickhouse.insert_timeout_seconds),
    ));
    {
        let p = processor_arc.clone();
        p.start();
    }
    info!("Event processor started");

    // ── Optional metrics server ───────────────────────────────────────
    if cfg.metrics.enabled {
        // G.2: metrics are unauthenticated — bind to loopback by default.
        // Set METRICS_BIND_ADDR (e.g. 0.0.0.0) to expose them on other
        // interfaces, restricted by network policy.
        let bind_addr = std::env::var("METRICS_BIND_ADDR")
            .unwrap_or_else(|_| "127.0.0.1".into());
        let metrics_addr: std::net::SocketAddr =
            format!("{}:{}", bind_addr.trim(), cfg.metrics.port)
                .parse()
                .with_context(|| format!("Bad metrics bind address '{bind_addr}'"))?;
        let builder = metrics_exporter_prometheus::PrometheusBuilder::new();
        builder
            .with_http_listener(metrics_addr)
            .install_recorder()
            .context("Failed to install Prometheus recorder")?;
        info!(%metrics_addr, "Prometheus metrics server ready");
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

    let router = build_router(state).into_make_service_with_connect_info::<std::net::SocketAddr>();

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

        // Signal health check to return 503 immediately (-500-354)
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

/// Initialize tracing subscriber with OTLP support.
/// Falls back to JSON logging when OTLP is not configured.
fn init_tracing() -> Result<Option<TracingGuard>> {
    if is_otlp_enabled() {
        let config = OtlpConfig {
            service_name: "tracking-service".into(),
            service_version: option_env!("CARGO_PKG_VERSION").map(str::to_string),
            environment: std::env::var("APP_ENV").ok(),
            ..Default::default()
        };

        match init_otlp_tracing(config) {
            Ok(guard) => return Ok(Some(guard)),
            Err(error) => tracing::error!("failed to initialize OTLP tracing: {error}"),
        }
    }

    tracing_subscriber::registry()
        .with(fmt::layer().json())
        .with(EnvFilter::from_default_env().add_directive("tracking_service=info".parse()?))
        .init();
    Ok(None)
}
