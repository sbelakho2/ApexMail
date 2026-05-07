//! Entry point for the ops-service binary.

use anyhow::Context;
use dashmap::DashMap;
use ops_service::config::OpsConfig;
use ops_service::health::HealthChecker;
use ops_service::incidents::IncidentManager;
use ops_service::routes::{router, AppState};
use ops_service::slo::SloTracker;
use ops_service::warmup::IpWarmupManager;
use std::sync::Arc;
use tracing::info;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialise tracing
    tracing_subscriber::fmt::init();

    let config = OpsConfig::from_env();
    info!(?config, "ops-service starting");

    // Connect to database
    let db = sqlx::postgres::PgPoolOptions::new()
        .max_connections(10)
        .acquire_timeout(std::time::Duration::from_secs(10))
        .idle_timeout(std::time::Duration::from_secs(300))
        .max_lifetime(std::time::Duration::from_secs(1800))
        .connect(&config.database_url)
        .await
        .context("failed to connect to database")?;

    let state = AppState {
        db: db.clone(),
        health: HealthChecker::new(1000),
        incidents: IncidentManager::new(db.clone()),
        slo: SloTracker::new(),
        warmup: IpWarmupManager::new(db),
        api_key: config.ops_api_key.clone(),
        // O-23.5: Pass all valid API keys (legacy single key + rotation keys).
        api_keys: config.all_api_keys(),
        trust_cache: Arc::new(DashMap::new()),
    };

    // Load existing state from database
    if let Err(e) = state.incidents.load_from_db().await {
        tracing::warn!(?e, "Failed to load incidents from database");
    }
    if let Err(e) = state.warmup.load_from_db().await {
        tracing::warn!(?e, "Failed to load warmup schedules from database");
    }

    let app = router(state);

    let addr = format!("0.0.0.0:{}", config.port);
    info!(addr, "listening");

    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .context("failed to bind TCP listener")?;

    let shutdown = async {
        let ctrl_c = async {
            let _ = tokio::signal::ctrl_c().await;
        };
        #[cfg(unix)]
        let terminate = async {
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .expect("failed to install SIGTERM handler")
                .recv()
                .await;
        };
        #[cfg(not(unix))]
        let terminate = std::future::pending::<()>();
        tokio::select! {
            _ = ctrl_c => tracing::info!("received Ctrl+C — shutting down"),
            _ = terminate => tracing::info!("received SIGTERM — shutting down"),
        }
    };
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown)
        .await
        .context("server error")?;

    Ok(())
}
