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

/// The circuit that guards a health-check component's dependency.
///
/// `database` and `redis` have dedicated circuits; the replication probe is
/// a database round trip and reports to the database circuit. Components
/// without an outbound dependency (disk, memory, persistence-schema) have no
/// circuit.
fn circuit_for_component(component: &str) -> Option<&'static str> {
    match component {
        "database" | "replication" => Some("database"),
        "redis" => Some("redis"),
        _ => None,
    }
}

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

    // SEC fix: from_env is fallible now — production REFUSES missing
    // INTERNAL_API_KEY / ADMIN_API_KEY / DB_PASSWORD instead of generating
    // synthetic credentials (EX_CONFIG, mirroring the isolation crate's
    // exit-78 convention).
    let config = match Config::from_env() {
        Ok(config) => Arc::new(config),
        Err(error) => {
            error!(
                "SECURITY: HA configuration refused to load: {error} — set the required \
                 environment variables and restart (exit 78 / EX_CONFIG)"
            );
            std::process::exit(78); // EX_CONFIG
        }
    };
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
            // SM10 F2: this cron is now WIRED to the automatic-failover
            // pipeline — previously it only logged, so `report_failure` had
            // zero production callers and nothing was ever failed over
            // automatically. Each per-component sample goes through the
            // flap-damped gate: an `Unhealthy` component is forwarded to
            // `report_failure` only after FLAP_DAMPING_SAMPLES consecutive
            // unhealthy ticks (a single blip must not push a component
            // toward the threshold), a `Healthy` tick resets that
            // component's failure counter, and `Degraded`/`Unknown` hold
            // the run untouched. `report_failure` itself no-ops unless
            // `failover.enabled`, so a disabled config keeps the old
            // observe-and-warn behavior.
            let mut gate =
                ha::failover::FlapDampedHealthGate::new(ha::failover::FLAP_DAMPING_SAMPLES);
            loop {
                tick.tick().await;
                let health = s.health.check_all().await;
                if health.overall != HealthStatus::Healthy {
                    tracing::warn!(status = %health.overall, region = %health.region, "Health check reported non-healthy state");
                }
                for component in &health.components {
                    // Feed the per-component outcome to the matching
                    // circuit breaker. Without this the CircuitBreakerService
                    // counters never moved: nothing reported outcomes, so
                    // every circuit stayed CLOSED with zero calls and the
                    // /api/v1/circuit-breakers surface was inert.
                    if let Some(circuit) = circuit_for_component(&component.name) {
                        match component.status {
                            HealthStatus::Healthy => {
                                if let Err(e) = s.circuit_breaker.report_success(circuit).await {
                                    error!(circuit, error = %e, "circuit success report failed");
                                }
                            }
                            HealthStatus::Unhealthy => {
                                if let Err(e) = s.circuit_breaker.report_failure(circuit).await {
                                    error!(circuit, error = %e, "circuit failure report failed");
                                }
                            }
                            // Degraded/Unknown hold the breaker state: a
                            // slowness signal must not open a circuit that
                            // guards availability, and it must not count as
                            // a success either.
                            _ => {}
                        }
                    }
                    match gate.observe(&component.name, &component.status) {
                        ha::failover::HealthObservation::ReportFailure => {
                            info!(
                                component = %component.name,
                                samples = ha::failover::FLAP_DAMPING_SAMPLES,
                                "component persistently unhealthy — forwarding to the \
                                 automatic-failover pipeline"
                            );
                            if let Err(e) = s.failover.report_failure(&component.name).await {
                                error!(
                                    component = %component.name,
                                    error = %e,
                                    "automatic failover attempt failed"
                                );
                            }
                        }
                        ha::failover::HealthObservation::ResetFailures => {
                            s.failover.reset_failures_for(&component.name).await;
                        }
                        // Damped (inside the damping window) / Hold — take
                        // no failover-pipeline action this tick.
                        ha::failover::HealthObservation::Damped
                        | ha::failover::HealthObservation::Hold => {}
                    }
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

    // Background cron:replication sync-mode reconciliation (external audit
    // #10). The desired mode persisted by set_sync_mode is durable
    // configuration — this bounded loop repairs drift between that intent
    // and the live synchronous_standby_names (e.g. after a crash between
    // persisting the intent and applying it).
    {
        let s = state.clone();
        tokio::spawn(async move {
            s.replication
                .run_sync_mode_reconcile_loop(std::time::Duration::from_secs(30))
                .await;
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
