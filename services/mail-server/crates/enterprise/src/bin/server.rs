use std::sync::Arc;
use tokio::signal;
use tracing::info;

use enterprise::config::Config;
use enterprise::routes::{router, AppState};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Load .env if present
    dotenvy::dotenv().ok();

    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .json()
        .init();

    // Load configuration
    let config = Config::from_env()
        .map_err(|err| anyhow::anyhow!("Invalid enterprise config: {err}"))?;
    if let Err(err) = config.validate() {
        return Err(anyhow::anyhow!("Invalid enterprise config: {err}"));
    }
    let bind_addr = format!("{}:{}", config.host, config.port);
    info!(host = %config.host, port = config.port, "Starting enterprise service");

    // Connect to PostgreSQL
    let db = sqlx::postgres::PgPoolOptions::new()
        .max_connections(config.db.max_connections)
        .connect_lazy(&config.db.url())
        .map_err(|e| anyhow::anyhow!("Database pool: {e}"))?;

    // Build app state
    let state = Arc::new(AppState::new(db.clone(), config));

    // Build router
    let app = router(state.clone());

    // Spawn background jobs
    spawn_background_jobs(state.clone(), db.clone());

    // Start server
    let listener = tokio::net::TcpListener::bind(&bind_addr).await?;
    info!(addr = %bind_addr, "Enterprise server listening");

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    info!("Enterprise server shutdown complete");
    Ok(())
}

/// Spawn background jobs for enterprise features
fn spawn_background_jobs(state: Arc<AppState>, _db: sqlx::PgPool) {
    // Job 1: Check SLA breaches every 60 seconds
    let sla_state = state.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(60));
        loop {
            interval.tick().await;
            match sla_state.support.check_sla_breaches().await {
                Ok(breaches) if !breaches.is_empty() => {
                    info!(count = breaches.len(), "SLA breaches detected");
                }
                Err(e) => tracing::error!(error = %e, "SLA breach check failed"),
                _ => {}
            }
        }
    });

    // Job 2: Auto-escalate tickets every 5 minutes
    let escalate_state = state.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(300));
        loop {
            interval.tick().await;
            match escalate_state.support.auto_escalate().await {
                Ok(count) if count > 0 => {
                    info!(escalated = count, "Auto-escalated tickets");
                }
                Err(e) => tracing::error!(error = %e, "Auto-escalation failed"),
                _ => {}
            }
        }
    });

    // Job 3: Cleanup expired SSO sessions every hour
    let session_state = state.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(3600));
        loop {
            interval.tick().await;
            match session_state.sso.cleanup_expired_sessions().await {
                Ok(count) if count > 0 => {
                    info!(cleaned = count, "Expired SSO sessions cleaned");
                }
                Err(e) => tracing::error!(error = %e, "Session cleanup failed"),
                _ => {}
            }
        }
    });

    info!("Background jobs started: SLA check (60s), auto-escalation (5m), session cleanup (1h)");
}

/// Wait for Ctrl+C or SIGTERM for graceful shutdown
async fn shutdown_signal() {
    let ctrl_c = async {
        if let Err(error) = signal::ctrl_c().await {
            tracing::error!(?error, "Failed to install Ctrl+C handler");
        }
    };

    #[cfg(unix)]
    let terminate = async {
        match signal::unix::signal(signal::unix::SignalKind::terminate()) {
            Ok(mut signal) => {
                signal.recv().await;
            }
            Err(error) => {
                tracing::error!(?error, "Failed to install signal handler");
            }
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => { info!("Received Ctrl+C, shutting down"); }
        _ = terminate => { info!("Received SIGTERM, shutting down"); }
    }
}
