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
//!   `COMPLIANCE_AUTH_TOKEN` (bearer token every route requires; when
//!   `NODE_ENV=production` the service REFUSES to start — exit 78 — when it
//!   is unset: no ephemeral token is ever generated in production), `AUDIT_SIGNING_KEY`
//!   (or `AUDIT_SIGNING_KEY_FILE` when `NODE_ENV=production` — the service
//!   refuses to start on an ephemeral key), `SECRETS_ENCRYPTION_KEY` (same
//!   production refusal), `CONSENT_SIGNING_KEY`. In development, missing
//!   auth/encryption values are generated ephemerally with a warning.
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
//! 8. Statutory ledger sweeps (payroll/expenses/bank statement lines unposted
//!    → accounting-core) — every 5min. The bank ingest route
//!    (`POST /accounting/bank-statements/import`) is the writer the sweep
//!    posts from, so the statement ledger loop is live end to end.

use clap::Parser;
use observability_service::otlp_exporter::{
    init_otlp_tracing, is_otlp_enabled, OtlpConfig, TracingGuard,
};
use std::sync::Arc;
use tokio::signal;
use tokio::time::{interval, Duration};
use tracing::{error, info, warn};

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

    /// Run the DSR queue + expiry sweep ONCE against the live database, print
    /// the counts and exit (one-shot ops entrypoint; the cron ticks are
    /// otherwise the only trigger — parity with the billing-service
    /// `--sweep-overage-only` flag, live dogfood 2026-10-08).
    #[arg(long, env = "COMPLIANCE_SWEEP_ONCE", default_value_t = false)]
    sweep_once: bool,
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
    // SEC fix: from_env is fallible now — production REFUSES ephemeral
    // COMPLIANCE_AUTH_TOKEN / SECRETS_ENCRYPTION_KEY (EX_CONFIG, mirroring
    // the isolation crate's exit-78 convention).
    let config = match ComplianceConfig::from_env() {
        Ok(config) => config,
        Err(error) => {
            error!(
                "SECURITY: compliance configuration refused to load: {error} — set the \
                 required environment variables and restart (exit 78 / EX_CONFIG)"
            );
            std::process::exit(78); // EX_CONFIG
        }
    };
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

    // On-demand DSR sweep: the exact production path cron jobs 1 (queue
    // recovery + batch) and 3 (request/DOI expiry + statutory-overdue count)
    // run, triggered once and reported on stdout. Exits 0 with a
    // machine-readable report line; any failed step exits non-zero AFTER
    // printing it, so an ops wrapper can alert on the exit code alone
    // (live dogfood 2026-10-08: the periodic ticks were the only trigger,
    // mirroring the billing-service `--sweep-overage-only` pattern).
    if cli.sweep_once {
        let queue = dsr_queue_tick(&state).await;
        let expiry = dsr_expiry_tick(&state).await;
        println!(
            "dsr sweep: recovered={} processed={} expired_requests={} expired_tokens={} \
             statutory_overdue={} failed_steps={}",
            queue.recovered,
            queue.processed,
            expiry.expired_requests,
            expiry.expired_tokens,
            expiry.statutory_overdue,
            queue.failed + expiry.failed,
        );
        state.db.close().await;
        if queue.failed + expiry.failed > 0 {
            anyhow::bail!(
                "dsr sweep finished with {} failed step(s) — see the log lines above",
                queue.failed + expiry.failed
            );
        }
        return Ok(());
    }

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

    wait_for_shutdown_signal(ctrl_c, terminate).await;
}

/// The select between the two shutdown sources, split out so tests can drive
/// each arm with fabricated futures.
async fn wait_for_shutdown_signal(
    ctrl_c: impl std::future::Future<Output = ()>,
    terminate: impl std::future::Future<Output = ()>,
) {
    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }

    info!("Shutdown signal received");
}

/// Counts + failures from one DSR queue tick (cron job 1), shared by the 30s
/// cron arm and the `--sweep-once` CLI.
#[derive(Debug, Default, Clone, Copy)]
struct DsrQueueTick {
    recovered: usize,
    processed: usize,
    failed: usize,
}

/// F: recover entries stranded in the processing list by crashed workers
/// (older than 5 minutes) before processing a new batch. Logs the same lines
/// the cron arm always logged; returns the counts for the one-shot report.
async fn dsr_queue_tick(state: &AppState) -> DsrQueueTick {
    let mut tick = DsrQueueTick::default();
    match state.gdpr.recover_stuck_processing(300).await {
        Ok(n) if n > 0 => {
            info!(count = n, "Recovered stuck GDPR queue entries");
            tick.recovered = n;
        }
        Err(e) => {
            error!(error = %e, "GDPR queue recovery sweep failed");
            tick.failed += 1;
        }
        _ => {}
    }
    match state.gdpr.process_queue_batch(10).await {
        Ok(results) if !results.is_empty() => {
            info!(count = results.len(), "Processed GDPR queue batch");
            tick.processed = results.len();
        }
        Err(e) => {
            error!(error = %e, "GDPR queue processing failed");
            tick.failed += 1;
        }
        _ => {}
    }
    tick
}

/// Counts + failures from one DSR expiry tick (cron job 3), shared by the 5min
/// cron arm and the `--sweep-once` CLI.
#[derive(Debug, Default, Clone, Copy)]
struct DsrExpiryTick {
    expired_requests: u64,
    expired_tokens: u64,
    statutory_overdue: u64,
    failed: usize,
}

/// Expire overdue GDPR requests and stale double-opt-in tokens, then flag OPEN
/// requests past their statutory (or extended) Art. 12(3) deadline. The
/// E-DSR-SLA check is warn-level so it surfaces in the deployed container's
/// logs; /gdpr/stats carries the same count.
async fn dsr_expiry_tick(state: &AppState) -> DsrExpiryTick {
    let mut tick = DsrExpiryTick::default();
    match state.gdpr.expire_overdue_requests().await {
        Ok(n) if n > 0 => {
            info!(count = n, "Expired overdue GDPR requests");
            tick.expired_requests = n;
        }
        Err(e) => {
            error!(error = %e, "GDPR expiry check failed");
            tick.failed += 1;
        }
        _ => {}
    }
    match state.gdpr.expire_stale_opt_in_tokens().await {
        Ok(n) if n > 0 => {
            info!(count = n, "Expired stale DOI tokens");
            tick.expired_tokens = n;
        }
        Err(e) => {
            error!(error = %e, "DOI token expiry failed");
            tick.failed += 1;
        }
        _ => {}
    }
    match state.gdpr.count_statutorily_overdue(None).await {
        Ok(n) if n > 0 => {
            warn!(
                overdue = n,
                "GDPR DSR(s) past the statutory response deadline — SLA breach open"
            );
            tick.statutory_overdue = n;
        }
        Err(e) => {
            error!(error = %e, "GDPR statutory-overdue check failed");
            tick.failed += 1;
        }
        _ => {}
    }
    tick
}

/// 9 background cron jobs:
/// 1. GDPR queue processing — every 30s
/// 2. Secret auto-rotation — every 60min
/// 3. GDPR request expiry — every 5min
/// 4. Audit archival — daily (every 24h)
/// 5. Data retention enforcement (consents/exports) — daily (every 24h)
/// 6. Retention sweep (H-6: registry-driven event-store purges + report) — daily
/// 7. DSR verification-outbox flush (D: queue tokens as system email) — every 60s
/// 8. Statutory ledger sweeps (payroll/expenses/bank statement lines) — every 5min
/// 9. Statutory obligation sync (derive/upsert `statutory_obligations` for every
///    legal entity + mark overdue) — daily. Dogfood 2026-10-06 wave B: the
///    obligations engine existed only for tests and the table stayed empty.
async fn run_cron_jobs(state: Arc<AppState>, outbox_flusher: DsrOutboxFlusher) {
    run_cron_jobs_with_intervals(
        state,
        outbox_flusher,
        CronIntervals {
            gdpr: Duration::from_secs(30),
            rotation: Duration::from_secs(3600),
            expiry: Duration::from_secs(300),
            archive: Duration::from_secs(86400),
            retention: Duration::from_secs(86400),
            sweep: Duration::from_secs(86400),
            outbox_flush: Duration::from_secs(60),
            ledger: Duration::from_secs(300),
            obligations: Duration::from_secs(86400),
        },
    )
    .await;
}

/// Tick periods for the nine cron jobs, in declaration order. Split from
/// [`run_cron_jobs`] so tests can drive every job arm in milliseconds.
#[derive(Clone, Copy)]
struct CronIntervals {
    gdpr: Duration,
    rotation: Duration,
    expiry: Duration,
    archive: Duration,
    retention: Duration,
    sweep: Duration,
    outbox_flush: Duration,
    ledger: Duration,
    obligations: Duration,
}

async fn run_cron_jobs_with_intervals(
    state: Arc<AppState>,
    outbox_flusher: DsrOutboxFlusher,
    intervals: CronIntervals,
) {
    let mut gdpr_ticker = interval(intervals.gdpr);
    let mut rotation_ticker = interval(intervals.rotation);
    let mut expiry_ticker = interval(intervals.expiry);
    let mut archive_ticker = interval(intervals.archive);
    let mut retention_ticker = interval(intervals.retention);
    let mut sweep_ticker = interval(intervals.sweep);
    let mut outbox_flush_ticker = interval(intervals.outbox_flush);
    // Host for the payroll/expense/bank statement sweeps: there is no
    // dedicated accounting service; see compliance::ledger_sweep. Bank lines
    // arrive through the compliance route POST /accounting/bank-statements/import.
    let mut ledger_ticker = interval(intervals.ledger);
    // Statutory filing calendar: derive/upsert every entity's obligations and
    // mark pending-but-past-due rows overdue (dogfood 2026-10-06 wave B — the
    // engine previously had no production caller and the table stayed empty).
    let mut obligations_ticker = interval(intervals.obligations);

    loop {
        tokio::select! {
            _ = gdpr_ticker.tick() => {
                // Shared with the `--sweep-once` CLI: one code path,
                // same logs and counts either way.
                let _ = dsr_queue_tick(&state).await;
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
                // Shared with the `--sweep-once` CLI: one code path,
                // same logs and counts either way.
                let _ = dsr_expiry_tick(&state).await;
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
                // Payroll/expense/bank statement adapters post every
                // unposted source row idempotently (SKIP LOCKED claim
                // + post in one transaction). Bank lines are written
                // by POST /accounting/bank-statements/import; payroll
                // and expense writers remain future features, and any
                // row they (or psql) create is posted the same way.
                // Reported whenever the tick did anything at all —
                // including unpostable rows, which are RETAINED and
                // must be visible to an operator.
                match compliance::ledger_sweep::sweep_ledger_sources(&state.db).await {
                    Ok(report) if !report.is_idle() => {
                        info!(
                            payroll_claimed = report.payroll.claimed,
                            payroll_posted = report.payroll.posted,
                            payroll_failed = report.payroll.failed,
                            payroll_unpostable = report.payroll.unpostable,
                            expenses_claimed = report.expenses.claimed,
                            expenses_posted = report.expenses.posted,
                            expenses_failed = report.expenses.failed,
                            expenses_source_table_missing =
                                report.expenses.source_table_missing,
                            bank_claimed = report.bank_statement_lines.claimed,
                            bank_posted = report.bank_statement_lines.posted,
                            bank_already_posted =
                                report.bank_statement_lines.already_posted,
                            bank_failed = report.bank_statement_lines.failed,
                            bank_unpostable = report.bank_statement_lines.unpostable,
                            invoices_claimed = report.invoices.claimed,
                            invoices_posted = report.invoices.posted,
                            invoices_failed = report.invoices.failed,
                            invoices_unpostable = report.invoices.unpostable,
                            allocations_claimed = report.payment_allocations.claimed,
                            allocations_posted = report.payment_allocations.posted,
                            allocations_failed = report.payment_allocations.failed,
                            allocations_unpostable = report.payment_allocations.unpostable,
                            credit_notes_claimed = report.credit_notes.claimed,
                            credit_notes_posted = report.credit_notes.posted,
                            credit_notes_failed = report.credit_notes.failed,
                            credit_notes_unpostable = report.credit_notes.unpostable,
                            "Statutory ledger sweep ran"
                        );
                    }
                    Ok(_) => {}
                    Err(e) => error!(error = %e, "Statutory ledger sweep failed"),
                }
            }
            _ = obligations_ticker.tick() => {
                // 9: derive/upsert every legal entity's statutory
                // filing obligations (KMD/TSD/VD/OSS/annual report)
                // over the forward year and mark pending-but-past-due
                // rows overdue. Idempotent; the upsert only touches
                // pending rows.
                let today = chrono::Utc::now().date_naive();
                match compliance::obligations::sync_all_obligations(&state.db, today).await {
                    Ok(run) => info!(
                        entities = run.entities,
                        upserted = run.upserted,
                        marked_overdue = run.marked_overdue,
                        "Statutory obligation sync completed"
                    ),
                    Err(e) => error!(error = %e, "Statutory obligation sync failed"),
                }
            }
        }
    }
}

// ── Tests ──────────────────────────────────────────────────────────────────
//
// The binary's guts are exercised directly: the cron loop is driven with
// millisecond intervals against a real canonical database (every job arm
// runs once against the production SQL), the shutdown select is driven with
// fabricated signal futures, and the tracing fallback is proven.

#[cfg(test)]
mod tests {
    use super::*;
    use compliance::config::ComplianceConfig;

    fn test_database_url() -> Option<String> {
        migrator::test_support::assert_soft_skip_allowed("TEST_DATABASE_URL");
        std::env::var("TEST_DATABASE_URL")
            .ok()
            .filter(|value| !value.trim().is_empty())
    }

    /// A canonical database + the full service state, as the binary builds it.
    async fn boot_state(test_name: &str) -> Option<(Arc<AppState>, ComplianceConfig)> {
        let url = test_database_url()?;
        // The secret manager's KDF contract (the binary normally gets these
        // from the deploy env; the test provides fixed values).
        if std::env::var("SECRETS_KDF_SALT").is_err() {
            std::env::set_var("SECRETS_KDF_SALT", "bin-test-kdf-salt-0123456789");
        }
        if std::env::var("SECRETS_ENCRYPTION_KEY").is_err() {
            std::env::set_var("SECRETS_ENCRYPTION_KEY", "bin-test-master-key-0123456789");
        }
        // SEC fix: from_env no longer fabricates a token in production mode —
        // pin the env the test needs to load under any NODE_ENV.
        if std::env::var("COMPLIANCE_AUTH_TOKEN").is_err() {
            std::env::set_var("COMPLIANCE_AUTH_TOKEN", "bin-test-compliance-token");
        }
        let db_name = format!("apexmail_ci_bin_server_{test_name}");
        let _pool = match migrator::test_support::fresh_canonical_db(&url, &db_name).await {
            Ok(pool) => pool?,
            Err(error) => panic!("{}", error.panic_message()),
        };
        let mut config = ComplianceConfig::from_env()
            .expect("compliance config must load in the test environment");
        config.database_url = url;
        config.redis_url = std::env::var("TEST_REDIS_URL").unwrap_or_default();
        config.auth_token = "bin-test-token".into();
        let (state, _seeds) = compliance::bootstrap::build_state(&config)
            .await
            .expect("boot state");
        Some((state, config))
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn every_cron_job_arm_runs_against_the_canonical_schema() {
        let Some((state, config)) = boot_state("cron_matrix").await else {
            eprintln!("skipping: set TEST_DATABASE_URL");
            return;
        };
        let outbox_flusher = DsrOutboxFlusher::new(state.db.clone(), config.gdpr.clone());

        // All nine tickers fire their first tick immediately and then every
        // 5 ms: one loop pass exercises every job arm against real SQL.
        let task = tokio::spawn(run_cron_jobs_with_intervals(
            state.clone(),
            outbox_flusher,
            CronIntervals {
                gdpr: Duration::from_millis(5),
                rotation: Duration::from_millis(5),
                expiry: Duration::from_millis(5),
                archive: Duration::from_millis(5),
                retention: Duration::from_millis(5),
                sweep: Duration::from_millis(5),
                outbox_flush: Duration::from_millis(5),
                ledger: Duration::from_millis(5),
                obligations: Duration::from_millis(5),
            },
        ));
        tokio::time::sleep(Duration::from_millis(50)).await;
        task.abort();
        let _ = state.db.close().await;
    }

    /// The `--sweep-once` entrypoint's shared ticks (live dogfood 2026-10-08:
    /// the periodic ticks were the only DSR trigger). The expiry tick must
    /// expire an overdue request + a stale DOI token and report the open
    /// statutory breach; a second run proves the expiries are idempotent and
    /// the breach stays visible; the queue tick must run the same claim path
    /// the cron arm uses without erroring. The queue counts themselves are
    /// NOT asserted: the test Redis is shared across concurrent test
    /// processes, and the queue's processing semantics are covered by the
    /// gdpr_automation suite.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn dsr_sweep_ticks_process_overdue_state_and_report_counts() {
        let Some((state, _config)) = boot_state("sweep_once").await else {
            eprintln!("skipping: set TEST_DATABASE_URL");
            return;
        };
        let tenant = "t-sweep-once-bin";

        // The per-test clone is REUSED across runs (fresh_canonical_db keeps
        // an existing clone), so clear this test's fixed-id fixtures first or
        // a re-run dies on the primary key.
        for id in ["REQ-sweep-exp", "REQ-sweep-over"] {
            sqlx::query("DELETE FROM data_subject_requests WHERE id = $1")
                .bind(id)
                .execute(&state.db)
                .await
                .expect("clear prior request fixture");
        }
        sqlx::query("DELETE FROM double_opt_in_tokens WHERE tenant_id = $1")
            .bind(tenant)
            .execute(&state.db)
            .await
            .expect("clear prior DOI fixture");

        // An unverified request past its verification window: expires.
        sqlx::query(
            "INSERT INTO data_subject_requests
               (id, tenant_id, request_type, email, verification_token_hash, verified, status,
                requested_at, received_at, statutory_due_at, expires_at)
             VALUES ('REQ-sweep-exp', $1, 'erasure', 'exp@example.test', 'hash', false,
                     'pending_verification', NOW() - INTERVAL '40 days', NOW() - INTERVAL '40 days',
                     NOW() + INTERVAL '10 days', NOW() - INTERVAL '1 hour')",
        )
        .bind(tenant)
        .execute(&state.db)
        .await
        .expect("expired-window request");

        // An OPEN request past its statutory deadline (future expiry window):
        // must be COUNTED as a breach, never silently expired.
        sqlx::query(
            "INSERT INTO data_subject_requests
               (id, tenant_id, request_type, email, verification_token_hash, verified, status,
                requested_at, received_at, statutory_due_at, expires_at)
             VALUES ('REQ-sweep-over', $1, 'access', 'over@example.test', 'hash', true,
                     'verified', NOW() - INTERVAL '40 days', NOW() - INTERVAL '40 days',
                     NOW() - INTERVAL '2 days', NOW() + INTERVAL '30 days')",
        )
        .bind(tenant)
        .execute(&state.db)
        .await
        .expect("statutorily overdue request");

        // A stale double-opt-in token: deleted by the expiry tick.
        sqlx::query(
            "INSERT INTO double_opt_in_tokens
               (tenant_id, subscriber_id, consent_type, email, token_hash, expires_at, created_at)
             VALUES ($1, 'sweep-gone', 'marketing', 'sweep@example.test', 'h',
                     NOW() - INTERVAL '1 hour', NOW())",
        )
        .bind(tenant)
        .execute(&state.db)
        .await
        .expect("stale DOI token");

        let tick = dsr_expiry_tick(&state).await;
        assert_eq!(tick.failed, 0, "no expiry step may fail: {tick:?}");
        assert!(
            tick.expired_requests >= 1,
            "the overdue window must expire: {tick:?}"
        );
        assert!(
            tick.expired_tokens >= 1,
            "the stale DOI token must be deleted: {tick:?}"
        );
        assert!(
            tick.statutory_overdue >= 1,
            "the backdated open request must be reported as a breach: {tick:?}"
        );

        let expired: String = sqlx::query_scalar(
            "SELECT status FROM data_subject_requests WHERE id = 'REQ-sweep-exp'",
        )
        .fetch_one(&state.db)
        .await
        .expect("expired row");
        assert_eq!(expired, "expired");
        let kept: String = sqlx::query_scalar(
            "SELECT status FROM data_subject_requests WHERE id = 'REQ-sweep-over'",
        )
        .fetch_one(&state.db)
        .await
        .expect("open row");
        assert_eq!(
            kept, "verified",
            "an open in-window request is never expired"
        );
        let remaining: i64 = sqlx::query_scalar(
            "SELECT COUNT(*)::bigint FROM double_opt_in_tokens WHERE tenant_id = $1",
        )
        .bind(tenant)
        .fetch_one(&state.db)
        .await
        .expect("remaining tokens");
        assert_eq!(remaining, 0, "the stale token must be gone");

        // Second run: expiries are idempotent; the breach stays visible.
        let again = dsr_expiry_tick(&state).await;
        assert_eq!(
            (again.expired_requests, again.expired_tokens, again.failed),
            (0, 0, 0),
            "{again:?}"
        );
        assert!(
            again.statutory_overdue >= 1,
            "an open breach stays reported until resolved: {again:?}"
        );

        // The queue arm of the same CLI: the claim path runs without error.
        let queue = dsr_queue_tick(&state).await;
        assert_eq!(
            queue.failed, 0,
            "the queue claim path must not fail: {queue:?}"
        );

        let _ = state.db.close().await;
    }

    #[tokio::test]
    async fn shutdown_signal_returns_on_the_ctrl_c_arm() {
        let fired = tokio::time::timeout(
            Duration::from_secs(5),
            wait_for_shutdown_signal(std::future::ready(()), std::future::pending()),
        )
        .await;
        assert!(fired.is_ok(), "a ready ctrl_c future must end the wait");
    }

    #[tokio::test]
    async fn shutdown_signal_returns_on_the_terminate_arm() {
        let fired = tokio::time::timeout(
            Duration::from_secs(5),
            wait_for_shutdown_signal(std::future::pending(), std::future::ready(())),
        )
        .await;
        assert!(fired.is_ok(), "a ready terminate future must end the wait");
    }

    #[test]
    fn tracing_fallback_initialises_without_otlp() {
        // The OTLP exporter is env-gated and off in tests: init_tracing must
        // take the structured-logging fallback and return None (no guard).
        std::env::remove_var("OTEL_EXPORTER_OTLP_ENDPOINT");
        let guard = init_tracing();
        assert!(guard.is_none(), "OTLP disabled => no tracing guard");
    }
}
