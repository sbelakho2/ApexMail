#![deny(unsafe_code)]
//! Outbound MTA relay daemon.
//!
//! Consumes the durable outbound queue (`outbound_relay_ledger`) and exposes
//! a health endpoint:
//!
//! * every poll tick: reclaim expired delivery leases (crashed attempts) and
//!   claim due rows, delivering them through [`outbound_mta::Relay`];
//! * `GET /healthz` and `GET /readyz`: process liveness + ledger queue stats
//!   (a ledger failure is reported 503, never masked).
//!
//! Configuration (environment):
//!
//! | Variable | Default | Meaning |
//! |----------|---------|---------|
//! | `DATABASE_URL` | required | Postgres connection string |
//! | `OUTBOUND_MTA_HEALTH_ADDR` | `127.0.0.1:8093` | health listener |
//! | `OUTBOUND_MTA_HELO_DOMAIN` | `relay.apexmail.ee` | EHLO name |
//! | `OUTBOUND_MTA_REPORTING_MTA` | HELO domain | DSN `Reporting-MTA` |
//! | `OUTBOUND_MTA_POLL_SECS` | `5` | queue sweep interval |
//! | `OUTBOUND_MTA_BATCH_SIZE` | `100` | rows claimed per sweep |
//! | `OUTBOUND_MTA_MAX_ATTEMPTS` | `12` | retry ceiling |
//!
//! SIGINT and SIGTERM both trigger the graceful drain (container runtimes
//! stop daemons with SIGTERM).

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::get;
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use serde_json::json;
use sqlx::postgres::PgPoolOptions;
use tokio::time::MissedTickBehavior;
use tracing::{error, info, warn};

use outbound_mta::ledger::{PgLedger, RelayLedger};
use outbound_mta::mx::{DnsMxResolver, MxResolver};
use outbound_mta::{Relay, RelayConfig};

#[derive(Debug)]
struct DaemonConfig {
    database_url: String,
    health_addr: SocketAddr,
    poll_interval: Duration,
    batch_size: i64,
    relay: RelayConfig,
}

impl DaemonConfig {
    fn from_env() -> Result<Self> {
        let database_url = std::env::var("DATABASE_URL")
            .context("DATABASE_URL must be set (the service entrypoint assembles it)")?;
        if database_url.trim().is_empty() {
            anyhow::bail!("DATABASE_URL must not be empty");
        }
        let health_addr: SocketAddr = env_parse("OUTBOUND_MTA_HEALTH_ADDR", "127.0.0.1:8093")?;
        let helo_domain = std::env::var("OUTBOUND_MTA_HELO_DOMAIN")
            .unwrap_or_else(|_| "relay.apexmail.ee".to_string());
        let reporting_mta =
            std::env::var("OUTBOUND_MTA_REPORTING_MTA").unwrap_or_else(|_| helo_domain.clone());
        let poll_secs: u64 = env_parse("OUTBOUND_MTA_POLL_SECS", "5")?;
        if poll_secs == 0 {
            anyhow::bail!("OUTBOUND_MTA_POLL_SECS must be greater than zero");
        }
        let batch_size: i64 = env_parse("OUTBOUND_MTA_BATCH_SIZE", "100")?;
        if batch_size <= 0 {
            anyhow::bail!("OUTBOUND_MTA_BATCH_SIZE must be greater than zero");
        }
        let max_attempts: u32 = env_parse("OUTBOUND_MTA_MAX_ATTEMPTS", "12")?;
        if max_attempts == 0 {
            anyhow::bail!("OUTBOUND_MTA_MAX_ATTEMPTS must be greater than zero");
        }
        let mut relay = RelayConfig {
            helo_domain,
            reporting_mta,
            ..RelayConfig::default()
        };
        relay.retry.max_attempts = max_attempts;
        Ok(Self {
            database_url,
            health_addr,
            poll_interval: Duration::from_secs(poll_secs),
            batch_size,
            relay,
        })
    }
}

fn env_parse<T>(name: &str, default: &str) -> Result<T>
where
    T: std::str::FromStr,
    T::Err: std::error::Error + Send + Sync + 'static,
{
    let raw = std::env::var(name).unwrap_or_else(|_| default.to_string());
    raw.trim()
        .parse::<T>()
        .with_context(|| format!("{name}='{raw}' is not valid"))
}

#[derive(Default)]
struct Counters {
    sweeps: AtomicU64,
    reconciled: AtomicU64,
    claimed: AtomicU64,
    accepted: AtomicU64,
    retry_scheduled: AtomicU64,
    permanently_failed: AtomicU64,
    errors: AtomicU64,
}

impl Counters {
    fn snapshot(&self) -> serde_json::Value {
        json!({
            "sweeps": self.sweeps.load(Ordering::Relaxed),
            "reconciled": self.reconciled.load(Ordering::Relaxed),
            "claimed": self.claimed.load(Ordering::Relaxed),
            "accepted": self.accepted.load(Ordering::Relaxed),
            "retry_scheduled": self.retry_scheduled.load(Ordering::Relaxed),
            "permanently_failed": self.permanently_failed.load(Ordering::Relaxed),
            "errors": self.errors.load(Ordering::Relaxed),
        })
    }
}

#[derive(Clone)]
struct AppState {
    started_at: DateTime<Utc>,
    ledger: Arc<dyn RelayLedger>,
    counters: Arc<Counters>,
}

async fn healthz(State(state): State<AppState>) -> impl IntoResponse {
    match state.ledger.stats().await {
        Ok(stats) => (
            StatusCode::OK,
            Json(json!({
                "status": "ok",
                "service": "outbound-mta",
                "uptime_secs": (Utc::now() - state.started_at).num_seconds().max(0),
                "queue": stats,
                "counters": state.counters.snapshot(),
            })),
        ),
        Err(error) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({
                "status": "degraded",
                "service": "outbound-mta",
                "error": error.to_string(),
            })),
        ),
    }
}

/// Prometheus text exposition for the daemon's own counters and the ledger
/// queue stats. The pending-oldest-age gauge backs the
/// OutboundMtaPendingOldestAgeSlo alert (deploy/alerting-rules.yml).
async fn metrics(State(state): State<AppState>) -> impl IntoResponse {
    let counters = state.counters.snapshot();
    let mut body = String::new();
    fn metric_line(body: &mut String, kind: &str, name: &str, help: &str, value: i64) {
        body.push_str(&format!(
            "# HELP {name} {help}\n# TYPE {name} {kind}\n{name} {value}\n"
        ));
    }
    match state.ledger.stats().await {
        Ok(stats) => {
            metric_line(
                &mut body,
                "gauge",
                "apexmail_outbound_mta_queue_pending",
                "Rows in outbound_relay_ledger state=pending.",
                stats.pending,
            );
            metric_line(
                &mut body,
                "gauge",
                "apexmail_outbound_mta_queue_delivering",
                "Rows in outbound_relay_ledger state=delivering.",
                stats.delivering,
            );
            metric_line(
                &mut body,
                "gauge",
                "apexmail_outbound_mta_queue_accepted",
                "Rows in outbound_relay_ledger state=accepted.",
                stats.accepted,
            );
            metric_line(
                &mut body,
                "gauge",
                "apexmail_outbound_mta_queue_failed",
                "Rows in outbound_relay_ledger state=failed.",
                stats.failed,
            );
            metric_line(
                &mut body,
                "gauge",
                "apexmail_outbound_mta_pending_oldest_age_seconds",
                "Age of the oldest pending durable retry (SLO signal; 0 when empty).",
                stats.oldest_pending_age_secs,
            );
        }
        Err(error) => {
            // A ledger failure must be visible in scrape output, not masked.
            body.push_str(&format!(
                "# HELP apexmail_outbound_mta_ledger_up Ledger stats readable\n\
                 # TYPE apexmail_outbound_mta_ledger_up gauge\n\
                 apexmail_outbound_mta_ledger_up 0\n\
                 # ledger error: {error}\n"
            ));
            let _ = error;
        }
    }
    let counter_value = |key: &str| counters[key].as_i64().unwrap_or(0);
    metric_line(
        &mut body,
        "counter",
        "apexmail_outbound_mta_sweeps_total",
        "Queue sweep ticks completed.",
        counter_value("sweeps"),
    );
    metric_line(
        &mut body,
        "counter",
        "apexmail_outbound_mta_reconciled_total",
        "Daemon acceptances projected onto the worker acceptance ledger.",
        counter_value("reconciled"),
    );
    metric_line(
        &mut body,
        "counter",
        "apexmail_outbound_mta_claimed_total",
        "Rows claimed for delivery.",
        counter_value("claimed"),
    );
    metric_line(
        &mut body,
        "counter",
        "apexmail_outbound_mta_accepted_total",
        "Deliveries accepted (post-DATA 250).",
        counter_value("accepted"),
    );
    metric_line(
        &mut body,
        "counter",
        "apexmail_outbound_mta_retry_scheduled_total",
        "Transient failures scheduled for retry.",
        counter_value("retry_scheduled"),
    );
    metric_line(
        &mut body,
        "counter",
        "apexmail_outbound_mta_permanently_failed_total",
        "Permanently failed deliveries (DSN'd).",
        counter_value("permanently_failed"),
    );
    metric_line(
        &mut body,
        "counter",
        "apexmail_outbound_mta_errors_total",
        "Delivery attempts returning an internal error.",
        counter_value("errors"),
    );
    (
        StatusCode::OK,
        [("content-type", "text/plain; version=0.0.4")],
        body,
    )
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let config = DaemonConfig::from_env()?;
    info!(
        health_addr = %config.health_addr,
        poll_secs = config.poll_interval.as_secs(),
        batch_size = config.batch_size,
        "starting outbound MTA relay"
    );

    let pool = PgPoolOptions::new()
        .max_connections(5)
        .acquire_timeout(Duration::from_secs(30))
        .connect(&config.database_url)
        .await
        .context("failed to connect to DATABASE_URL")?;
    let ledger: Arc<dyn RelayLedger> = Arc::new(PgLedger::new(pool.clone()));
    // SSRF escape hatch (finding: MX → internal IP was an unfiltered
    // surface). Default OFF: recipient domains are tenant controlled, so a
    // private/reserved MX address is refused. The override exists ONLY for
    // loopback test setups.
    let allow_private_mx = std::env::var("RELAY_ALLOW_PRIVATE_MX")
        .map(|value| {
            matches!(
                value.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(false);
    if allow_private_mx {
        warn!(
            "RELAY_ALLOW_PRIVATE_MX=true: MX addresses in private/reserved ranges are \
             deliverable. This is for loopback test setups only; never enable in production."
        );
    }
    let resolver = Arc::new(
        DnsMxResolver::new()
            .context("failed to build the MX resolver")?
            .with_allow_private_addresses(allow_private_mx),
    );
    run(config, pool, ledger, resolver, shutdown_signal()).await
}

/// Await SIGINT or SIGTERM. Split out of `run` so the shutdown contract is
/// observable: container runtimes stop daemons with SIGTERM, so listening
/// only for SIGINT (ctrl_c) would skip the drain entirely — in-flight
/// delivery attempts killed mid-DATA, the health server never closed and
/// held leases left to expire on their own.
async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut terminate) => {
                terminate.recv().await;
            }
            Err(error) => {
                error!(%error, "failed to install SIGTERM handler; falling back to SIGINT only");
                std::future::pending::<()>().await;
            }
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! {
        _ = ctrl_c => info!("SIGINT received — shutting down"),
        _ = terminate => info!("SIGTERM received — shutting down"),
    }
}

/// Assemble the health router. Extracted so the endpoint contract is
/// assertable without a live process.
fn build_router(app_state: AppState) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/readyz", get(healthz))
        .route("/metrics", get(metrics))
        .with_state(app_state)
}

/// One queue sweep: reclaim expired leases, deliver due rows, then project
/// daemon acceptances onto the worker acceptance ledger. Every failure
/// increments the error counter — a broken sweep must be visible in
/// /metrics, never silently swallowed.
async fn sweep_once(relay: &Relay, pool: &sqlx::PgPool, counters: &Counters, batch_size: i64) {
    let now = Utc::now();
    if let Err(error) = relay.reclaim_expired(now).await {
        counters.errors.fetch_add(1, Ordering::Relaxed);
        error!(%error, "failed to reclaim expired delivery leases");
    }
    match relay.process_due(now, batch_size).await {
        Ok(report) => {
            counters
                .claimed
                .fetch_add(report.claimed, Ordering::Relaxed);
            counters
                .accepted
                .fetch_add(report.accepted, Ordering::Relaxed);
            counters
                .retry_scheduled
                .fetch_add(report.retry_scheduled, Ordering::Relaxed);
            counters
                .permanently_failed
                .fetch_add(report.permanently_failed, Ordering::Relaxed);
            counters.errors.fetch_add(report.errors, Ordering::Relaxed);
            if report.claimed > 0 {
                info!(
                    claimed = report.claimed,
                    accepted = report.accepted,
                    retry_scheduled = report.retry_scheduled,
                    permanently_failed = report.permanently_failed,
                    "outbound queue sweep complete"
                );
            }
        }
        Err(error) => {
            counters.errors.fetch_add(1, Ordering::Relaxed);
            error!(%error, "outbound queue sweep failed");
        }
    }

    // Ledger→acceptance projection: a send the DAEMON accepted
    // must not wait for the worker to happen to retry before
    // the application learns SMTP already accepted it.
    match outbound_mta::reconcile::reconcile_acceptances(pool).await {
        Ok(reconciled) => {
            if !reconciled.is_empty() {
                counters
                    .reconciled
                    .fetch_add(reconciled.len() as u64, Ordering::Relaxed);
                info!(
                    count = reconciled.len(),
                    "projected daemon acceptances onto the worker acceptance ledger"
                );
            }
        }
        Err(error) => {
            counters.errors.fetch_add(1, Ordering::Relaxed);
            error!(%error, "acceptance reconciliation sweep failed");
        }
    }
}

/// Serve the queue relay until `shutdown` resolves. Split out of `main` so
/// the startup sequence (bind, spawn, sweep loop, drain) is exercisable by
/// tests with a stub ledger and an injected shutdown — the production `main`
/// passes [`shutdown_signal`].
async fn run(
    config: DaemonConfig,
    pool: sqlx::PgPool,
    ledger: Arc<dyn RelayLedger>,
    resolver: Arc<dyn MxResolver>,
    shutdown: impl std::future::Future<Output = ()>,
) -> Result<()> {
    let relay = Arc::new(Relay::new(
        Arc::clone(&ledger),
        resolver,
        config.relay.clone(),
    ));
    let counters = Arc::new(Counters::default());

    let app_state = AppState {
        started_at: Utc::now(),
        ledger,
        counters: Arc::clone(&counters),
    };
    let app = build_router(app_state);
    let listener = tokio::net::TcpListener::bind(config.health_addr)
        .await
        .with_context(|| format!("failed to bind health listener on {}", config.health_addr))?;
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let server = tokio::spawn(async move {
        let served = axum::serve(listener, app)
            .with_graceful_shutdown(async move {
                let _ = shutdown_rx.await;
            })
            .await;
        if let Err(error) = served {
            error!(%error, "health server stopped with an error");
        }
    });

    let mut interval = tokio::time::interval(config.poll_interval);
    interval.set_missed_tick_behavior(MissedTickBehavior::Delay);
    tokio::pin!(shutdown);
    loop {
        tokio::select! {
            _ = &mut shutdown => {
                info!("shutdown signal received");
                break;
            }
            _ = interval.tick() => {
                counters.sweeps.fetch_add(1, Ordering::Relaxed);
                sweep_once(relay.as_ref(), &pool, counters.as_ref(), config.batch_size).await;
            }
        }
    }

    let _ = shutdown_tx.send(());
    let _ = server.await;
    info!("outbound MTA relay stopped");
    Ok(())
}

#[cfg(test)]
mod tests {
    //! The daemon's configuration parser and health contract are pure enough
    //! to pin without a live broker: a misconfigured environment must refuse
    //! to start, and a ledger outage must surface as 503, never as "ok".

    use super::*;
    use async_trait::async_trait;
    use outbound_mta::ledger::{ClaimOutcome, LedgerError, QueuedSubmission};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// Run `body` with exactly `vars` set (all other daemon variables are
    /// removed first), restoring nothing afterwards — the lock keeps other
    /// tests from observing the mutation.
    fn with_env<T>(vars: &[(&str, &str)], body: impl FnOnce() -> T) -> T {
        let _guard = ENV_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        for name in [
            "DATABASE_URL",
            "OUTBOUND_MTA_HEALTH_ADDR",
            "OUTBOUND_MTA_HELO_DOMAIN",
            "OUTBOUND_MTA_REPORTING_MTA",
            "OUTBOUND_MTA_POLL_SECS",
            "OUTBOUND_MTA_BATCH_SIZE",
            "OUTBOUND_MTA_MAX_ATTEMPTS",
        ] {
            std::env::remove_var(name);
        }
        for (name, value) in vars {
            std::env::set_var(name, value);
        }
        body()
    }

    #[derive(Default)]
    struct StubLedger {
        fail: bool,
        /// Sweep-loop observability: how many times the daemon's tick called
        /// reclaim/claim against this ledger.
        reclaims: std::sync::atomic::AtomicUsize,
        claims: std::sync::atomic::AtomicUsize,
    }

    #[async_trait]
    impl RelayLedger for StubLedger {
        async fn claim_submission(
            &self,
            _new: outbound_mta::ledger::NewSubmission,
            _now: DateTime<Utc>,
            _lease: Duration,
        ) -> Result<ClaimOutcome, LedgerError> {
            Err(LedgerError::Corrupt {
                send_unit: "stub".to_string(),
                message: "not used".to_string(),
            })
        }

        async fn claim_due(
            &self,
            _now: DateTime<Utc>,
            _lease: Duration,
            _limit: i64,
        ) -> Result<Vec<QueuedSubmission>, LedgerError> {
            self.claims
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            Ok(Vec::new())
        }

        async fn record_retry(
            &self,
            _send_unit: &str,
            _attempt: u32,
            _next_attempt_at: DateTime<Utc>,
            _error: &str,
        ) -> Result<(), LedgerError> {
            Ok(())
        }

        async fn record_accepted(
            &self,
            _send_unit: &str,
            _record: &outbound_mta::AcceptanceRecord,
        ) -> Result<(), LedgerError> {
            Ok(())
        }

        async fn record_permanent(
            &self,
            _send_unit: &str,
            _attempt: u32,
            _error: &str,
        ) -> Result<(), LedgerError> {
            Ok(())
        }

        async fn enqueue_dsn(
            &self,
            _new: outbound_mta::ledger::NewSubmission,
            _now: DateTime<Utc>,
        ) -> Result<bool, LedgerError> {
            Ok(false)
        }

        async fn get(&self, _send_unit: &str) -> Result<Option<QueuedSubmission>, LedgerError> {
            Ok(None)
        }

        async fn reclaim_expired(&self, _now: DateTime<Utc>) -> Result<u64, LedgerError> {
            self.reclaims
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            Ok(0)
        }

        async fn stats(&self) -> Result<outbound_mta::ledger::LedgerStats, LedgerError> {
            if self.fail {
                return Err(LedgerError::Database("ledger is down".to_string()));
            }
            Ok(outbound_mta::ledger::LedgerStats {
                pending: 3,
                delivering: 1,
                accepted: 5,
                failed: 2,
                oldest_pending_age_secs: 42,
            })
        }
    }

    fn state(ledger: Arc<dyn RelayLedger>) -> AppState {
        AppState {
            started_at: Utc::now(),
            ledger,
            counters: Arc::new(Counters::default()),
        }
    }

    #[test]
    fn env_parse_defaults_overrides_and_rejects_garbage() {
        with_env(&[], || {
            let batch: i64 = env_parse("OUTBOUND_MTA_BATCH_SIZE", "100").expect("default");
            assert_eq!(batch, 100);
        });
        with_env(&[("OUTBOUND_MTA_BATCH_SIZE", " 7 ")], || {
            let batch: i64 = env_parse("OUTBOUND_MTA_BATCH_SIZE", "100").expect("override");
            assert_eq!(batch, 7, "surrounding whitespace is tolerated");
        });
        with_env(&[("OUTBOUND_MTA_BATCH_SIZE", "not-a-number")], || {
            let error = env_parse::<i64>("OUTBOUND_MTA_BATCH_SIZE", "100")
                .expect_err("garbage must refuse startup");
            let text = error.to_string();
            assert!(text.contains("OUTBOUND_MTA_BATCH_SIZE"), "error: {text}");
        });
    }

    #[test]
    fn daemon_config_refuses_incomplete_or_impossible_environments() {
        with_env(&[], || {
            let error = DaemonConfig::from_env().expect_err("DATABASE_URL is required");
            assert!(error.to_string().contains("DATABASE_URL"));
        });
        with_env(&[("DATABASE_URL", "   ")], || {
            let error = DaemonConfig::from_env().expect_err("blank DATABASE_URL is refused");
            assert!(error.to_string().contains("must not be empty"));
        });
        let valid = &[("DATABASE_URL", "postgres://localhost/db")];
        with_env(valid, || {
            let config = DaemonConfig::from_env().expect("defaults");
            assert_eq!(config.health_addr.to_string(), "127.0.0.1:8093");
            assert_eq!(config.poll_interval, Duration::from_secs(5));
            assert_eq!(config.batch_size, 100);
            assert_eq!(config.relay.retry.max_attempts, 12);
            assert_eq!(config.relay.helo_domain, "relay.apexmail.ee");
            assert_eq!(
                config.relay.reporting_mta, config.relay.helo_domain,
                "Reporting-MTA defaults to the HELO domain"
            );
        });
        with_env(
            &[
                ("DATABASE_URL", "postgres://localhost/db"),
                ("OUTBOUND_MTA_HEALTH_ADDR", "0.0.0.0:9999"),
                ("OUTBOUND_MTA_HELO_DOMAIN", "relay.test"),
                ("OUTBOUND_MTA_POLL_SECS", "1"),
                ("OUTBOUND_MTA_BATCH_SIZE", "1"),
                ("OUTBOUND_MTA_MAX_ATTEMPTS", "3"),
            ],
            || {
                let config = DaemonConfig::from_env().expect("overrides");
                assert_eq!(config.health_addr.to_string(), "0.0.0.0:9999");
                assert_eq!(config.relay.reporting_mta, "relay.test");
                assert_eq!(config.relay.retry.max_attempts, 3);
            },
        );
        for (name, value) in [
            ("OUTBOUND_MTA_POLL_SECS", "0"),
            ("OUTBOUND_MTA_BATCH_SIZE", "0"),
            ("OUTBOUND_MTA_MAX_ATTEMPTS", "0"),
            ("OUTBOUND_MTA_HEALTH_ADDR", "not-an-address"),
        ] {
            with_env(
                &[("DATABASE_URL", "postgres://localhost/db"), (name, value)],
                || {
                    let error = DaemonConfig::from_env()
                        .err()
                        .unwrap_or_else(|| panic!("{name}={value} must refuse"));
                    assert!(
                        error.to_string().contains(name),
                        "the failure must name the variable: {error}"
                    );
                },
            );
        }
    }

    #[test]
    fn counters_snapshot_exposes_every_field() {
        let counters = Counters::default();
        counters.sweeps.fetch_add(2, Ordering::Relaxed);
        counters.accepted.fetch_add(3, Ordering::Relaxed);
        let snapshot = counters.snapshot();
        assert_eq!(snapshot["sweeps"], 2);
        assert_eq!(snapshot["accepted"], 3);
        assert_eq!(snapshot["claimed"], 0);
        assert_eq!(snapshot["retry_scheduled"], 0);
        assert_eq!(snapshot["permanently_failed"], 0);
        assert_eq!(snapshot["errors"], 0);
    }

    #[tokio::test]
    async fn healthz_reports_queue_stats_and_fails_closed_on_a_ledger_outage() {
        let healthy = state(Arc::new(StubLedger::default()));
        let response = healthz(State(healthy)).await.into_response();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), 8192)
            .await
            .expect("body");
        let json: serde_json::Value = serde_json::from_slice(&body).expect("json");
        assert_eq!(json["status"], "ok");
        assert_eq!(json["queue"]["accepted"], 5);
        assert_eq!(json["queue"]["pending"], 3);

        let degraded = state(Arc::new(StubLedger {
            fail: true,
            ..StubLedger::default()
        }));
        let response = healthz(State(degraded)).await.into_response();
        assert_eq!(
            response.status(),
            StatusCode::SERVICE_UNAVAILABLE,
            "a ledger outage must never be reported as healthy"
        );
        let body = axum::body::to_bytes(response.into_body(), 8192)
            .await
            .expect("body");
        let json: serde_json::Value = serde_json::from_slice(&body).expect("json");
        assert_eq!(json["status"], "degraded");
        assert!(
            json["error"]
                .as_str()
                .unwrap_or("")
                .contains("ledger is down"),
            "json: {json}"
        );
    }

    // ── /metrics contract ──────────────────────────────────────────────────

    fn counter_value(body: &str, name: &str) -> Option<i64> {
        // Prometheus text: the sample line is `name value` after the HELP/TYPE
        // preamble; match the exact sample, not a HELP mention.
        body.lines()
            .rfind(|line| line.starts_with(name))
            .and_then(|line| line.split_whitespace().nth(1))
            .and_then(|value| value.parse().ok())
    }

    /// The scrape must carry every gauge and every counter with a HELP/TYPE
    /// preamble — a missing series silently breaks the pending-oldest-age
    /// SLO alert (deploy/alerting-rules.yml).
    #[tokio::test]
    async fn metrics_exposes_queue_gauges_and_all_counters() {
        let response = metrics(State(state(Arc::new(StubLedger::default()))))
            .await
            .into_response();
        assert_eq!(response.status(), StatusCode::OK);
        let content_type = response
            .headers()
            .get("content-type")
            .expect("content-type")
            .to_str()
            .expect("ascii");
        assert_eq!(content_type, "text/plain; version=0.0.4");

        let body = axum::body::to_bytes(response.into_body(), 65_536)
            .await
            .expect("body");
        let body = std::str::from_utf8(&body).expect("utf8");
        for name in [
            "apexmail_outbound_mta_queue_pending",
            "apexmail_outbound_mta_queue_delivering",
            "apexmail_outbound_mta_queue_accepted",
            "apexmail_outbound_mta_queue_failed",
            "apexmail_outbound_mta_pending_oldest_age_seconds",
            "apexmail_outbound_mta_sweeps_total",
            "apexmail_outbound_mta_reconciled_total",
            "apexmail_outbound_mta_claimed_total",
            "apexmail_outbound_mta_accepted_total",
            "apexmail_outbound_mta_retry_scheduled_total",
            "apexmail_outbound_mta_permanently_failed_total",
            "apexmail_outbound_mta_errors_total",
        ] {
            assert!(
                body.contains(&format!("# HELP {name} ")),
                "{name} must have a HELP line:\n{body}"
            );
            assert!(
                body.contains(&format!("# TYPE {name} ")),
                "{name} must have a TYPE line:\n{body}"
            );
            assert!(
                counter_value(body, name).is_some(),
                "{name} must have a sample line:\n{body}"
            );
        }
        // Stub values flow through verbatim.
        assert_eq!(
            counter_value(body, "apexmail_outbound_mta_queue_pending"),
            Some(3)
        );
        assert_eq!(
            counter_value(body, "apexmail_outbound_mta_pending_oldest_age_seconds"),
            Some(42)
        );
    }

    /// A ledger outage must be visible in scrape output (`ledger_up 0`),
    /// never masked as an empty queue — an empty queue and an unreadable
    /// queue look identical to an alert without the sentinel.
    #[tokio::test]
    async fn metrics_reports_a_ledger_outage_instead_of_masking_it() {
        let response = metrics(State(state(Arc::new(StubLedger {
            fail: true,
            ..StubLedger::default()
        }))))
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), 65_536)
            .await
            .expect("body");
        let body = std::str::from_utf8(&body).expect("utf8");
        assert_eq!(
            counter_value(body, "apexmail_outbound_mta_ledger_up"),
            Some(0),
            "the outage sentinel must read 0:\n{body}"
        );
        assert!(
            body.contains("ledger is down"),
            "the error text must be embedded as a comment:\n{body}"
        );
        assert!(
            !body.contains("apexmail_outbound_mta_queue_pending"),
            "queue gauges must be absent while the ledger is unreadable:\n{body}"
        );
        // Daemon counters still scrape.
        assert_eq!(
            counter_value(body, "apexmail_outbound_mta_sweeps_total"),
            Some(0)
        );
    }

    // ── run(): process orchestration ───────────────────────────────────────

    struct StubResolver;

    #[async_trait]
    impl MxResolver for StubResolver {
        async fn resolve(
            &self,
            _domain: &str,
        ) -> Result<Vec<outbound_mta::mx::MxTarget>, outbound_mta::mx::MxError> {
            Ok(Vec::new())
        }
    }

    fn reserve_addr() -> SocketAddr {
        std::net::TcpListener::bind("127.0.0.1:0")
            .expect("probe bind")
            .local_addr()
            .expect("addr")
    }

    fn test_database_url() -> Option<String> {
        match std::env::var("TEST_DATABASE_URL") {
            Ok(url) if !url.trim().is_empty() => Some(url),
            _ => None,
        }
    }

    fn daemon_config(
        health_addr: SocketAddr,
        poll_secs: u64,
        database_url: String,
    ) -> DaemonConfig {
        DaemonConfig {
            database_url,
            health_addr,
            poll_interval: Duration::from_secs(poll_secs),
            batch_size: 100,
            relay: RelayConfig::default(),
        }
    }

    /// Minimal HTTP/1.0 GET over a raw socket — no client dependency needed
    /// to assert the daemon's endpoint contract.
    async fn http_get(addr: SocketAddr, path: &str) -> std::io::Result<(u16, String)> {
        let mut stream = tokio::net::TcpStream::connect(addr).await?;
        stream
            .write_all(format!("GET {path} HTTP/1.0\r\nHost: {addr}\r\n\r\n").as_bytes())
            .await?;
        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).await?;
        let text = String::from_utf8_lossy(&buf).into_owned();
        let status: u16 = text
            .split_whitespace()
            .nth(1)
            .and_then(|code| code.parse().ok())
            .ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::InvalidData, "no status line")
            })?;
        Ok((status, text))
    }

    /// The full startup sequence on an ephemeral port: /healthz and /readyz
    /// answer from the live ledger, the sweep loop ticks (sweeps_total climbs
    /// and the ledger observed reclaim+claim), and the injected shutdown
    /// drains the HTTP server before `run` returns.
    #[tokio::test]
    async fn run_serves_endpoints_sweeps_and_shuts_down_cleanly() {
        let Some(database_url) = test_database_url() else {
            eprintln!("skipping: set TEST_DATABASE_URL to drive the daemon against Postgres");
            return;
        };
        let ledger = Arc::new(StubLedger::default());
        let addr = reserve_addr();
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        let task = tokio::spawn(run(
            daemon_config(addr, 1, database_url),
            // The pool is only used by the acceptance projection; the scratch
            // database provides it.
            sqlx::postgres::PgPoolOptions::new()
                .max_connections(1)
                .connect(&test_database_url().expect("url"))
                .await
                .expect("pool"),
            ledger.clone() as Arc<dyn RelayLedger>,
            Arc::new(StubResolver),
            async move {
                let _ = shutdown_rx.await;
            },
        ));

        // Bounded readiness wait: a hung bind must fail the test, not hang it.
        let mut health = None;
        for _ in 0..150 {
            match http_get(addr, "/healthz").await {
                Ok((200, body)) => {
                    health = Some(body);
                    break;
                }
                _ => tokio::time::sleep(Duration::from_millis(20)).await,
            }
        }
        let health = health.expect("the daemon must answer /healthz within 3s");
        assert!(health.contains("\"status\":\"ok\""), "{health}");
        assert!(health.contains("\"service\":\"outbound-mta\""), "{health}");

        let (status, ready) = http_get(addr, "/readyz").await.expect("readyz");
        assert_eq!(status, 200, "readyz shares the health contract: {ready}");

        // The sweep loop ran at least one tick and reached the ledger.
        let mut metrics_body = String::new();
        for _ in 0..150 {
            if let Ok((200, body)) = http_get(addr, "/metrics").await {
                metrics_body = body;
                if counter_value(&metrics_body, "apexmail_outbound_mta_sweeps_total").unwrap_or(0)
                    >= 1
                {
                    break;
                }
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(
            counter_value(&metrics_body, "apexmail_outbound_mta_sweeps_total").unwrap_or(0) >= 1,
            "the sweep loop must tick:\n{metrics_body}"
        );
        assert!(
            ledger.reclaims.load(std::sync::atomic::Ordering::Relaxed) >= 1,
            "every sweep must reclaim expired leases"
        );
        assert!(
            ledger.claims.load(std::sync::atomic::Ordering::Relaxed) >= 1,
            "every sweep must claim due rows"
        );

        shutdown_tx.send(()).expect("daemon still running");
        let result = tokio::time::timeout(Duration::from_secs(10), task)
            .await
            .expect("run must finish within 10s of shutdown")
            .expect("join");
        assert!(result.is_ok(), "clean drain: {result:?}");

        // The health port is released again — the server drained.
        let rebinding = tokio::net::TcpListener::bind(addr).await;
        assert!(
            rebinding.is_ok(),
            "the drained daemon must release its port"
        );
    }

    /// Duplicate-instance conflict: a second daemon on the same health
    /// address must refuse to start with an error naming the address, not
    /// run half-alive without its endpoints.
    #[tokio::test]
    async fn run_refuses_to_start_when_the_health_port_is_taken() {
        let Some(database_url) = test_database_url() else {
            eprintln!("skipping: set TEST_DATABASE_URL to drive the daemon against Postgres");
            return;
        };
        let listener = tokio::net::TcpListener::bind(reserve_addr())
            .await
            .expect("occupy the port");
        let addr = listener.local_addr().expect("addr");

        let result = run(
            daemon_config(addr, 3600, database_url),
            sqlx::postgres::PgPoolOptions::new()
                .max_connections(1)
                .connect(&test_database_url().expect("url"))
                .await
                .expect("pool"),
            Arc::new(StubLedger::default()) as Arc<dyn RelayLedger>,
            Arc::new(StubResolver),
            std::future::pending(),
        )
        .await;

        let error = result.expect_err("an occupied health port must refuse startup");
        assert!(
            error.to_string().contains("failed to bind health listener")
                && error.to_string().contains(&addr.to_string()),
            "error: {error}"
        );
    }

    /// A broken acceptance projection must not take the daemon down and must
    /// not be silent: the sweep error counter climbs in /metrics while
    /// /healthz keeps answering from the (healthy) ledger.
    #[tokio::test]
    async fn run_survives_a_failing_acceptance_projection_and_counts_errors() {
        let Some(database_url) = test_database_url() else {
            eprintln!("skipping: set TEST_DATABASE_URL to drive the daemon against Postgres");
            return;
        };
        let addr = reserve_addr();
        // Lazy pool against a dead port: connect() succeeds, every real use
        // fails — exactly what a Postgres outage mid-flight looks like.
        let dead_pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .acquire_timeout(Duration::from_secs(1))
            .connect_lazy("postgres://apexmail:bad@127.0.0.1:1/none")
            .expect("lazy pool never connects eagerly");
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        let task = tokio::spawn(run(
            daemon_config(addr, 1, database_url),
            dead_pool,
            Arc::new(StubLedger::default()) as Arc<dyn RelayLedger>,
            Arc::new(StubResolver),
            async move {
                let _ = shutdown_rx.await;
            },
        ));

        let mut metrics_body = String::new();
        for _ in 0..300 {
            if let Ok((200, body)) = http_get(addr, "/metrics").await {
                metrics_body = body;
                if counter_value(&metrics_body, "apexmail_outbound_mta_errors_total").unwrap_or(0)
                    >= 1
                {
                    break;
                }
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(
            counter_value(&metrics_body, "apexmail_outbound_mta_errors_total").unwrap_or(0) >= 1,
            "projection failures must surface in the error counter:\n{metrics_body}"
        );
        // The daemon is still alive: liveness reflects the ledger, which is
        // healthy, even while a projection sweep is failing.
        let (status, health) = http_get(addr, "/healthz").await.expect("healthz");
        assert_eq!(
            status, 200,
            "the daemon must survive projection failures: {health}"
        );

        shutdown_tx.send(()).expect("daemon still running");
        let result = tokio::time::timeout(Duration::from_secs(10), task)
            .await
            .expect("run must finish within 10s of shutdown")
            .expect("join");
        assert!(result.is_ok(), "clean drain: {result:?}");
    }

    /// SIGTERM (the container stop signal) must drain the daemon exactly
    /// like SIGINT: a plain ctrl_c-only listener would be killed by the
    /// default SIGTERM disposition mid-sweep.
    #[tokio::test]
    async fn shutdown_signal_fires_on_sigterm() {
        // Installing the handler swaps the default disposition for this
        // process; nextest runs every test in its own process, so no other
        // test observes it.
        let task = tokio::spawn(shutdown_signal());
        // Give the handler a moment to install, then SIGTERM ourselves via
        // the standard `kill` utility (no libc dependency).
        tokio::time::sleep(Duration::from_millis(50)).await;
        let self_pid = std::process::id().to_string();
        std::process::Command::new("kill")
            .args(["-TERM", &self_pid])
            .output()
            .expect("kill utility");
        tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .expect("shutdown_signal must complete on SIGTERM")
            .expect("join");
    }
}
