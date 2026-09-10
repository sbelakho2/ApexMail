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
use observability_service::otlp_exporter::{
    init_otlp_tracing, is_otlp_enabled, OtlpConfig, TracingGuard,
};

use std::error::Error;
use std::sync::Arc;
use tokio::net::TcpListener;
use tracing::{error, info};

fn init_tracing() -> Option<TracingGuard> {
    if is_otlp_enabled() {
        let config = OtlpConfig {
            service_name: "ha-server".to_string(),
            ..OtlpConfig::default()
        };
        match init_otlp_tracing(config) {
            Ok(guard) => return Some(guard),
            Err(e) => tracing::warn!("OTLP tracing disabled: {e}"),
        }
    }
    // Fallback: structured JSON logging
    tracing_subscriber::fmt()
        .json()
        .with_target(true)
        .with_env_filter("info")
        .init();
    None
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let _guard = init_tracing();

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

    // Fix #14: the HA tables (ha_failover_events, ha_replication_lag_history)
    // are written by this service but exist in NO migration — ensure them
    // idempotently at startup. LOUD failure: abort startup rather than run
    // with inserts that would fail at runtime.
    if let Err(e) = ha::failover::bootstrap_tables(&pool).await {
        error!(
            error = %e,
            "Failed to ensure HA tables (ha_failover_events, ha_replication_lag_history) — aborting startup"
        );
        return Err(format!("HA table bootstrap failed: {e}").into());
    }
    info!("HA tables ensured (ha_failover_events, ha_replication_lag_history)");

    // F63: the health-check persistence contract (ha_health_checks, canonical
    // migration 194) must exist before this service starts recording results.
    // Failing readiness here is honest: without the relation every check
    // result is warn-discarded while the service still reports healthy.
    let health_service = HealthCheckService::new(pool.clone(), Arc::clone(&config));
    if !health_service.persistence_ready().await {
        error!(
            "ha_health_checks relation missing — canonical migration 194 not applied; \
             aborting startup (health results could not be persisted)"
        );
        return Err("HA health-check schema missing (migration 194)".into());
    }

    // Build shared state
    let config_for_services = Arc::clone(&config);
    // BackupService::new returns Result to validate encryption key at startup
    let backup_service = BackupService::new(pool.clone(), Arc::clone(&config_for_services))
        .map_err(|e| anyhow::anyhow!("Failed to initialize backup service: {}", e))?;
    let state = Arc::new(AppState {
        health: health_service,
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

    // Background cron:primary claim refresh (fix #12). Without a refresh,
    // PRIMARY_CLAIM_TTL (300s) expired and split-brain detection went blind
    // after five minutes on a perfectly healthy primary.
    {
        let s = state.clone();
        // Refresh at 1/3 of the TTL: at most one failed refresh can elapse
        // before the next attempt, keeping the claim continuously alive.
        let interval = std::time::Duration::from_secs(ha::failover::PRIMARY_CLAIM_TTL_SECS / 3);
        tokio::spawn(async move {
            s.failover.run_claim_refresh_loop(interval).await;
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

    // Background cron:health-check history retention cleanup (daily, F63).
    // ha_health_checks is append-only per observation — without this the
    // relation grows forever.
    {
        let s = state.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(std::time::Duration::from_secs(86400));
            loop {
                tick.tick().await;
                match s.health.cleanup_history(30).await {
                    Ok(deleted) if deleted > 0 => {
                        info!(deleted, "Health-check history cleanup completed")
                    }
                    Ok(_) => {}
                    Err(e) => error!(error = %e, "Health-check history cleanup failed"),
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
