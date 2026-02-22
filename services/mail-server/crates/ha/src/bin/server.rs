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

use std::sync::Arc;
use tokio::net::TcpListener;
use tracing::{error, info};

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt().with_env_filter("info").init();

    let config = Arc::new(Config::from_env());
    info!(port = config.port, version = config.version, "Starting HA service");

    // Build DB pool
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(config.database.pool_max)
        .idle_timeout(std::time::Duration::from_millis(config.database.idle_timeout_ms))
        .acquire_timeout(std::time::Duration::from_millis(config.database.connection_timeout_ms))
        .connect(&config.database.primary_url())
        .await
        .expect("Failed to connect to database");

    // Build shared state
    let state = Arc::new(AppState {
        health: HealthCheckService::new(pool.clone(), config.clone()),
        failover: FailoverService::new(pool.clone(), config.clone()),
        backup: BackupService::new(pool.clone(), config.clone()),
        replication: ReplicationService::new(pool.clone(), config.clone()),
        multi_region: MultiRegionService::new(pool.clone(), config.clone()),
        circuit_breaker: CircuitBreakerService::new(config.clone()),
        chaos: ChaosEngineeringService::new(pool.clone(), config.clone()),
        config: config.clone(),
    });

    // Background cron: health checks
    {
        let s = state.clone();
        let interval = config.health.interval_ms;
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(std::time::Duration::from_millis(interval));
            loop {
                tick.tick().await;
                let _ = s.health.check_all().await;
            }
        });
    }

    // Background cron: replication lag recording
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

    // Background cron: backup retention cleanup (daily)
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

    // Background cron: replication lag history cleanup (hourly)
    {
        let s = state.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(std::time::Duration::from_secs(3600));
            loop {
                tick.tick().await;
                let _ = s.replication.cleanup_lag_history(72).await;
            }
        });
    }

    // Start HTTP server
    let app = build_router(state);
    let addr = format!("0.0.0.0:{}", config.port);
    let listener = TcpListener::bind(&addr).await.expect("Failed to bind");
    info!(addr, "HA service listening");
    axum::serve(listener, app).await.expect("Server failed");
}
