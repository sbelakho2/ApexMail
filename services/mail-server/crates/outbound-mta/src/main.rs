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
use tracing::{error, info};

use outbound_mta::ledger::{PgLedger, RelayLedger};
use outbound_mta::mx::DnsMxResolver;
use outbound_mta::{Relay, RelayConfig};

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
    let ledger: Arc<dyn RelayLedger> = Arc::new(PgLedger::new(pool));
    let resolver = Arc::new(DnsMxResolver::new().context("failed to build the MX resolver")?);
    let relay = Arc::new(Relay::new(ledger.clone(), resolver, config.relay.clone()));
    let counters = Arc::new(Counters::default());

    let app_state = AppState {
        started_at: Utc::now(),
        ledger: Arc::clone(&ledger),
        counters: Arc::clone(&counters),
    };
    let app = Router::new()
        .route("/healthz", get(healthz))
        .route("/readyz", get(healthz))
        .with_state(app_state);
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
    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                info!("shutdown signal received");
                break;
            }
            _ = interval.tick() => {
                counters.sweeps.fetch_add(1, Ordering::Relaxed);
                let now = Utc::now();
                if let Err(error) = relay.reclaim_expired(now).await {
                    counters.errors.fetch_add(1, Ordering::Relaxed);
                    error!(%error, "failed to reclaim expired delivery leases");
                }
                match relay.process_due(now, config.batch_size).await {
                    Ok(report) => {
                        counters.claimed.fetch_add(report.claimed, Ordering::Relaxed);
                        counters.accepted.fetch_add(report.accepted, Ordering::Relaxed);
                        counters.retry_scheduled.fetch_add(report.retry_scheduled, Ordering::Relaxed);
                        counters.permanently_failed.fetch_add(report.permanently_failed, Ordering::Relaxed);
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
            }
        }
    }

    let _ = shutdown_tx.send(());
    let _ = server.await;
    info!("outbound MTA relay stopped");
    Ok(())
}
