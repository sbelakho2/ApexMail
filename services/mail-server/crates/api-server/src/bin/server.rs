//! API server binary — entry point.
//!
//! Loads configuration, creates connection pools, builds the Axum app,
//! and serves with graceful shutdown on SIGTERM / SIGINT.

use std::net::SocketAddr;
use tokio::net::TcpListener;
use tokio::signal;
use tracing_subscriber::EnvFilter;

use api_server::app::build_app;
use api_server::config::Config;
use api_server::state::AppStateInner;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // ── Logging ─────────────────────────────────────────────
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .json()
        .init();

    // ── Config ──────────────────────────────────────────────
    let config = Config::from_env()?;
    tracing::info!(
        port = config.port,
        host = %config.host,
        environment = ?config.environment,
        "loaded configuration"
    );

    // ── Database pool ───────────────────────────────────────
    let db = apexmail_db::pool::create_pool_from_config(
        &config.db_host,
        config.db_port,
        &config.db_name,
        &config.db_user,
        &config.db_password,
        config.db_max_connections,
    )
    .await?;
    tracing::info!("database pool created");

    // ── Redis pool ──────────────────────────────────────────
    let redis_cfg = deadpool_redis::Config::from_url(&config.redis_url());
    let redis = redis_cfg
        .create_pool(Some(deadpool_redis::Runtime::Tokio1))
        .expect("failed to create Redis pool");
    tracing::info!("redis pool created");

    // ── App state ───────────────────────────────────────────
    let state = AppStateInner::new(db, redis, config.clone());

    // ── Build & serve ───────────────────────────────────────
    let app = build_app(state);

    let addr: SocketAddr = format!("{}:{}", config.host, config.port).parse()?;
    let listener = TcpListener::bind(addr).await?;
    tracing::info!(%addr, "listening");

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    tracing::info!("server shut down gracefully");
    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => tracing::info!("received Ctrl+C"),
        _ = terminate => tracing::info!("received SIGTERM"),
    }
}
