//! Compliance server binary — a long-running service: HTTP API on port 3011
//! (liveness `GET /health`, readiness `GET /health/ready`), 8 background
//! cron jobs and graceful shutdown (SIGTERM/SIGINT → in-flight requests
//! drain, DB pool closes).
//!
//! ## Service contract (docker-compose)
//!
//! * Service name: `compliance`; container port `3011` (env `COMPLIANCE_PORT`
//!   overrides; CLI `--port` wins over both).
//! * Required env: `DATABASE_URL` (Postgres), `REDIS_URL`,
//!   `COMPLIANCE_AUTH_TOKEN` (bearer token every route requires; in
//!   production `NODE_ENV=production` an ephemeral token is generated with a
//!   warning when unset), `AUDIT_SIGNING_KEY` (or `AUDIT_SIGNING_KEY_FILE`
//!   when `NODE_ENV=production` — the service refuses to start on an
//!   ephemeral key), `SECRETS_ENCRYPTION_KEY`, `CONSENT_SIGNING_KEY`.
//! * Optional env: `CORS_ORIGIN`, `GDPR_EXPORT_BASE_URL`,
//!   `GDPR_VERIFY_BASE_URL`, `AUDIT_RETENTION_DAYS`, DSAR rate-limit vars,
//!   and the ClickHouse erasure vars (`GDPR_CLICKHOUSE_ERASURE_ENABLED`,
//!   `CLICKHOUSE_URL`, `CLICKHOUSE_DATABASE`, `CLICKHOUSE_USER`,
//!   `CLICKHOUSE_PASSWORD`) — off unless enabled.
//!
//! ## Schema ownership
//!
//! The compliance service owns NO runtime DDL. Every table it reads/writes is
//! created by numbered migrations (`services/mail-server/migrations`),
//! applied by the `migrator` deploy gate before this binary starts. Startup
//! therefore works with a DML-only database role; the release test
//! `compliance_boots_and_processes_with_dml_only_role`
//! (`crates/compliance/tests/gdpr_governance_release_tests.rs`) proves it.
//! Startup writes are limited to idempotent DML seeds (SOC2 catalog, GDPR
//! governance registry / retention classes).
//!
//! Cron jobs (all idempotent, retried on the next tick on failure):
//! 1. DSR queue processing + stuck-entry recovery — every 30s
//! 2. Secret auto-rotation — every 60min
//! 3. GDPR request/token expiry — every 5min
//! 4. Audit archival — daily
//! 5. Data retention enforcement (consents/exports) — daily
//! 6. Retention sweep (registry-driven canonical-store purges + report) — daily
//! 7. DSR verification-outbox flush — every 60s
//! 8. Statutory ledger sweeps (payroll/expenses unposted → accounting-core) — every 5min

use clap::Parser;
use observability_service::otlp_exporter::{
    init_otlp_tracing, is_otlp_enabled, OtlpConfig, TracingGuard,
};
use std::sync::Arc;
use tokio::signal;
use tokio::time::{interval, Duration};
use tracing::{error, info};

use compliance::bootstrap::build_state;
use compliance::config::ComplianceConfig;
use compliance::dsr_outbox_flush::DsrOutboxFlusher;
use compliance::routes::create_router;
use compliance::routes::AppState;

#[derive(Parser)]
#[command(name = "compliance-server")]
struct Cli {
    /// Override port (default from COMPLIANCE_PORT or 3011)
    #[arg(short, long)]
    port: Option<u16>,
}

fn init_tracing() -> Option<TracingGuard> {
    if is_otlp_enabled() {
        let config = OtlpConfig {
            service_name: "compliance-server".to_string(),
            ..OtlpConfig::default()
        };
        match init_otlp_tracing(config) {
            Ok(guard) => return Some(guard),
            Err(e) => tracing::warn!("OTLP tracing disabled: {e}"),
        }
    }
    // Fallback: structured JSON logging
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "compliance=info,tower_http=info".into()),
        )
        .init();
    None
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let _guard = init_tracing();

    dotenvy::dotenv().ok();

    let cli = Cli::parse();
    let config = ComplianceConfig::from_env();
    let port = cli.port.unwrap_or(config.port);

    // One shared construction path with the DML-only release test: connect,
    // build every service, run idempotent DML seeds. No runtime DDL.
    let (state, seeds) = build_state(&config).await.map_err(|e| anyhow::anyhow!(e))?;
    info!(
        soc2_controls = seeds.soc2_controls,
        governance_activities = seeds.governance_activities,
        retention_classes = seeds.retention_classes,
        awaiting_legal_input = seeds.awaiting_legal_input,
        "Compliance services bootstrapped"
    );

    // Build router with middleware
    let cors = if config.cors_origin == "*" {
        tower_http::cors::CorsLayer::permissive()
    } else {
        tower_http::cors::CorsLayer::new()
            .allow_origin(
                config
                    .cors_origin
                    .parse::<axum::http::HeaderValue>()
                    .expect("CORS_ORIGIN must be a valid header value"),
            )
            .allow_methods([
                axum::http::Method::GET,
                axum::http::Method::POST,
                axum::http::Method::PUT,
                axum::http::Method::DELETE,
            ])
            .allow_headers(tower_http::cors::Any)
    };
    let app = create_router(state.clone())
        .layer(tower_http::trace::TraceLayer::new_for_http())
        .layer(cors);

    // Start background cron jobs
    let cron_state = state.clone();
    // D: DSR verification-outbox flush — queues pending tokens as real mail
    // through the platform's system-email path (email_queue).
    let outbox_flusher = DsrOutboxFlusher::new(state.db.clone(), config.gdpr.clone());
    let cron_handle = tokio::spawn(async move {
        run_cron_jobs(cron_state, outbox_flusher).await;
    });

    // Start HTTP server
    let addr = format!("0.0.0.0:{port}");
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    info!("Compliance server listening on {}", addr);

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    info!("Shutting down...");
    cron_handle.abort();
    state.db.close().await;

    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        if let Err(error) = signal::ctrl_c().await {
            error!(?error, "Failed to install Ctrl+C handler");
        }
    };

    #[cfg(unix)]
    let terminate = async {
        match signal::unix::signal(signal::unix::SignalKind::terminate()) {
            Ok(mut signal) => {
                signal.recv().await;
            }
            Err(error) => {
                error!(?error, "Failed to install SIGTERM handler");
            }
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }

    info!("Shutdown signal received");
}

/// 8 background cron jobs:
/// 1. GDPR queue processing — every 30s
/// 2. Secret auto-rotation — every 60min
/// 3. GDPR request expiry — every 5min
/// 4. Audit archival — daily (every 24h)
/// 5. Data retention enforcement (consents/exports) — daily (every 24h)
/// 6. Retention sweep (H-6: registry-driven event-store purges + report) — daily
/// 7. DSR verification-outbox flush (D: queue tokens as system email) — every 60s
/// 8. Statutory ledger sweeps (payroll/expenses) — every 5min
async fn run_cron_jobs(state: Arc<AppState>, outbox_flusher: DsrOutboxFlusher) {
    let mut gdpr_ticker = interval(Duration::from_secs(30));
    let mut rotation_ticker = interval(Duration::from_secs(3600));
    let mut expiry_ticker = interval(Duration::from_secs(300));
    let mut archive_ticker = interval(Duration::from_secs(86400));
    let mut retention_ticker = interval(Duration::from_secs(86400));
    let mut sweep_ticker = interval(Duration::from_secs(86400));
    let mut outbox_flush_ticker = interval(Duration::from_secs(60));
    // Interim host for the payroll/expense sweeps: there is no accounting
    // service or payroll-run writer yet; see compliance::ledger_sweep.
    let mut ledger_ticker = interval(Duration::from_secs(300));

    loop {
        tokio::select! {
                    _ = gdpr_ticker.tick() => {
                        // F: recover entries stranded in the processing list
                        // by crashed workers (older than 5 minutes) before
                        // processing a new batch.
                        match state.gdpr.recover_stuck_processing(300).await {
                            Ok(n) if n > 0 => info!(count = n, "Recovered stuck GDPR queue entries"),
                            Err(e) => error!(error = %e, "GDPR queue recovery sweep failed"),
                            _ => {}
                        }
                        match state.gdpr.process_queue_batch(10).await {
                            Ok(results) if !results.is_empty() => {
                                info!(count = results.len(), "Processed GDPR queue batch");
                            }
                            Err(e) => error!(error = %e, "GDPR queue processing failed"),
                            _ => {}
                        }
                    }
                    _ = rotation_ticker.tick() => {
                        match state.secret_manager.process_auto_rotations().await {
                            Ok(result) if !result.rotated.is_empty() => {
                                info!(count = result.rotated.len(), "Auto-rotated secrets");
                            }
                            Err(e) => error!(error = %e, "Secret auto-rotation failed"),
                            _ => {}
                        }
                    }
                    _ = expiry_ticker.tick() => {
        // Expire overdue GDPR requests
                        match state.gdpr.expire_overdue_requests().await {
                            Ok(n) if n > 0 => info!(count = n, "Expired overdue GDPR requests"),
                            Err(e) => error!(error = %e, "GDPR expiry check failed"),
                            _ => {}
                        }
        // Expire stale double-opt-in tokens
                        match state.gdpr.expire_stale_opt_in_tokens().await {
                            Ok(n) if n > 0 => info!(count = n, "Expired stale DOI tokens"),
                            Err(e) => error!(error = %e, "DOI token expiry failed"),
                            _ => {}
                        }
                    }
                    _ = archive_ticker.tick() => {
                        let older_than = chrono::Utc::now() - chrono::Duration::days(state.config.audit.retention_days);
                        match state.audit_logger.archive(older_than).await {
                            Ok(n) if n > 0 => info!(count = n, "Archived old audit logs"),
                            Err(e) => error!(error = %e, "Audit archival failed"),
                            _ => {}
                        }
                    }
                    _ = retention_ticker.tick() => {
                        match state.gdpr.enforce_retention().await {
                            Ok((c, e)) if c > 0 || e > 0 => {
                                info!(consents = c, exports = e, "Retention enforcement completed");
                            }
                            Err(e) => error!(error = %e, "Retention enforcement failed"),
                            _ => {}
                        }
                    }
                    _ = outbox_flush_ticker.tick() => {
                        // D: drain pending dsr_verification_outbox rows into
                        // email_queue under the system sender. Bounded batch;
                        // failures retry next tick until the attempts cap.
                        match outbox_flusher.flush_once().await {
                            Ok(summary) if summary.queued > 0 || summary.failed > 0 => {
                                info!(
                                    queued = summary.queued,
                                    failed = summary.failed,
                                    "DSR verification outbox flush completed"
                                );
                            }
                            Ok(_) => {}
                            Err(e) => error!(error = %e, "DSR verification outbox flush failed"),
                        }
                    }
                    _ = sweep_ticker.tick() => {
                        // H-6: enforce the RET-001..023 registry durations for
                        // the stores this crate owns (event tables, gdpr_exports,
                        // audit_logs via archive(), dsr outbox), advance the
                        // legally-restricted archive through expiry → deletion,
                        // and persist a retention_report row.
                        match state.retention_sweeper.run_sweep(&state.audit_logger).await {
                            Ok(report) => {
                                let deleted: i64 =
                                    report.categories.iter().map(|c| c.deleted).sum();
                                let held: i64 = report
                                    .categories
                                    .iter()
                                    .map(|c| c.skipped_legal_hold)
                                    .sum();
                                info!(
                                    deleted,
                                    skipped_legal_hold = held,
                                    exports = report.gdpr_exports_deleted,
                                    outbox_purged = report.dsr_outbox_purged,
                                    audit_archived = report.audit_logs_archived,
                                    archive_expired = report.archive_expired,
                                    archive_deleted = report.archive_deleted,
                                    archive_sources_deleted = report.archive_source_records_deleted,
                                    "Retention sweep completed — retention_report row written"
                                );
                            }
                            Err(e) => error!(error = %e, "Retention sweep failed"),
                        }
                    }
                    _ = ledger_ticker.tick() => {
                        // Follow-up: the payroll/expense adapters had no
                        // production writer. The sweeps post every unposted
                        // source row idempotently (SKIP LOCKED claim + post in
                        // one transaction), so a payroll run / expense entry
                        // written by any future writer (or psql) reaches the
                        // statutory ledger with no further wiring.
                        match compliance::ledger_sweep::sweep_payroll_and_expenses(&state.db).await {
                            Ok(report) if report.total_posted() > 0 => {
                                info!(
                                    payroll_posted = report.payroll.posted,
                                    payroll_failed = report.payroll.failed,
                                    payroll_unpostable = report.payroll.unpostable,
                                    expenses_posted = report.expenses.posted,
                                    expenses_failed = report.expenses.failed,
                                    expenses_source_table_missing =
                                        report.expenses.source_table_missing,
                                    "Statutory ledger sweep posted source documents"
                                );
                            }
                            Ok(_) => {}
                            Err(e) => error!(error = %e, "Statutory ledger sweep failed"),
                        }
                    }
                }
    }
}
