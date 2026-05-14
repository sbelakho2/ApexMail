//! HA service binary — HTTP server on port 4300, background cron jobs.

use ha::backup::BackupService;
use ha::chaos::ChaosEngineeringService;
use ha::circuit_breaker::CircuitBreakerService;
use ha::config::Config;
use ha::failover::FailoverService;
use ha::health_check::HealthCheckService;
use ha::multi_region::MultiRegionService;
use ha::replication::ReplicationService;
use ha::routes::{build_router, AppState};
use ha::types::HealthStatus;

use std::error::Error;
use std::sync::Arc;
use tokio::net::TcpListener;
use tracing::{error, info};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    tracing_subscriber::fmt()
        .json()
        .with_target(true)
        .with_env_filter("info")
        .init();

    let config = Arc::new(Config::from_env());
    info!(
        port = config.port,
        version = config.version,
        "Starting HA service"
    );

    // Build DB pool
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(config.database.pool_max)
        .idle_timeout(std::time::Duration::from_millis(
            config.database.idle_timeout_ms,
        ))
        .acquire_timeout(std::time::Duration::from_millis(
            config.database.connection_timeout_ms,
        ))
        .max_lifetime(std::time::Duration::from_secs(1800))
        .connect(&config.database.primary_url())
        .await?;

    // Build shared state
    let config_for_services = Arc::clone(&config);
    // BackupService::new returns Result to validate encryption key at startup
    let backup_service = BackupService::new(pool.clone(), Arc::clone(&config_for_services))
        .map_err(|e| anyhow::anyhow!("Failed to initialize backup service: {}", e))?;
    let state = Arc::new(AppState {
        health: HealthCheckService::new(pool.clone(), Arc::clone(&config_for_services)),
        failover: FailoverService::new(pool.clone(), Arc::clone(&config_for_services)),
        backup: backup_service,
        replication: ReplicationService::new(pool.clone(), Arc::clone(&config_for_services)),
        multi_region: MultiRegionService::new(pool.clone(), Arc::clone(&config_for_services)),
        circuit_breaker: CircuitBreakerService::new(Arc::clone(&config_for_services)),
        chaos: ChaosEngineeringService::new(pool.clone(), Arc::clone(&config_for_services)),
        config: config_for_services,
    });

    // Background cron:health checks
    {
        let s = state.clone();
        let interval = config.health.interval_ms;
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(std::time::Duration::from_millis(interval));
            loop {
                tick.tick().await;
                let health = s.health.check_all().await;
                if health.overall != HealthStatus::Healthy {
                    tracing::warn!(status = %health.overall, region = %health.region, "Health check reported non-healthy state");
                }
            }
        });
    }

    // Background cron:replication lag recording
    {
        let s = state.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(std::time::Duration::from_secs(30));
            loop {
                tick.tick().await;
                if let Err(e) = s.replication.record_lag().await {
                    error!(error = %e, "Replication lag recording failed");
                }
            }
        });
    }

    // Background cron:backup retention cleanup (daily)
    {
        let s = state.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(std::time::Duration::from_secs(86400));
            loop {
                tick.tick().await;
                match s.backup.enforce_retention().await {
                    Ok(deleted) => {
                        if deleted > 0 {
                            info!(deleted, "Backup retention cleanup completed");
                        }
                    }
                    Err(e) => error!(error = %e, "Backup retention cleanup failed"),
                }
            }
        });
    }

    // Background cron:replication lag history cleanup (hourly)
    {
        let s = state.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(std::time::Duration::from_secs(3600));
            loop {
                tick.tick().await;
                if let Err(e) = s.replication.cleanup_lag_history(72).await {
                    tracing::warn!(error = %e, "Replication lag history cleanup failed");
                }
            }
        });
    }

    // Start HTTP server
    let app = build_router(state);
    let addr = format!("0.0.0.0:{}", config.port);
    let listener = TcpListener::bind(&addr).await?;
    info!(addr, "HA service listening");

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
            _ = ctrl_c => info!("received Ctrl+C — shutting down"),
            _ = terminate => info!("received SIGTERM — shutting down"),
        }
    };
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown)
        .await?;
    Ok(())
}
