//! Process-liveness heartbeats — REAL process leases, never inferred from
//! queue traffic.
//!
//! Background: the Control Plane's `system_health` used to report "queue
//! writers" derived from `queue_jobs` activity because no process-heartbeat
//! registry existed. A busy queue is not a live worker: a dead process can
//! leave a backlog that keeps looking "active", and an idle-but-alive worker
//! looks dead. This module writes an explicit lease row per process into
//! `service_heartbeats` (migration 213):
//!
//! ```text
//! service_heartbeats(instance_id, service, version, started_at, last_seen_at,
//!                    capabilities, region)
//! ```
//!
//! * `instance_id` identifies one PROCESS (`{service}-{hostname}-{pid}`).
//!   A restarted process gets a new row (different pid); the previous row
//!   ages out as stale rather than silently continuing to look alive.
//! * `last_seen_at` is refreshed on every beat; `system_health` treats a row
//!   as LIVE only when the beat is fresh (see
//!   `system_health::HEARTBEAT_STALE_AFTER_SECS`), and reports an explicit
//!   `no_heartbeat` state for services with no row at all.
//! * `started_at` is set by the first insert and never moved by later beats.
//!
//! The emitter is best-effort: a failed beat logs a warning and the loop
//! continues, so a transient database error never kills the process. The
//! heartbeat is deliberately advisory to the DB (it is not a distributed
//! lock) — the reader decides liveness from freshness.

use sqlx::PgPool;
use std::time::Duration;

/// Default beat interval. Three missed beats (90 s) mark an instance stale.
pub const DEFAULT_HEARTBEAT_INTERVAL_SECS: u64 = 30;

/// Everything the emitter needs. Construct with [`HeartbeatConfig::new`] and
/// the chained setters, then hand it to [`spawn_service_heartbeat`].
#[derive(Debug, Clone)]
pub struct HeartbeatConfig {
    /// Stable identity of THIS process, e.g. `api-server-host-1234`.
    pub instance_id: String,
    /// Binary/service name (`api-server`, `worker`, ...).
    pub service: String,
    /// Build version (`env!("CARGO_PKG_VERSION")` from the binary).
    pub version: String,
    /// Human-readable capability labels (processors, surfaces).
    pub capabilities: Vec<String>,
    /// Optional deployment region.
    pub region: Option<String>,
    /// Beat interval.
    pub interval: Duration,
}

impl HeartbeatConfig {
    /// Build a config for `service` with a process-unique instance id.
    pub fn new(service: impl Into<String>, version: impl Into<String>) -> Self {
        let service = service.into();
        let instance_id = process_instance_id(&service);
        Self {
            instance_id,
            service,
            version: version.into(),
            capabilities: Vec::new(),
            region: None,
            interval: Duration::from_secs(DEFAULT_HEARTBEAT_INTERVAL_SECS),
        }
    }

    pub fn with_capabilities(mut self, capabilities: Vec<String>) -> Self {
        self.capabilities = capabilities;
        self
    }

    pub fn with_interval(mut self, interval: Duration) -> Self {
        self.interval = interval;
        self
    }

    /// Read the region from `HEARTBEAT_REGION` / `REGION` / `AWS_REGION`
    /// (first non-empty wins). Absent everywhere → `None`, never a guess.
    pub fn with_region_from_env(mut self) -> Self {
        self.region = region_from_env();
        self
    }

    /// Read the beat interval from `HEARTBEAT_INTERVAL_SECS`, falling back to
    /// [`DEFAULT_HEARTBEAT_INTERVAL_SECS`]. A non-positive/unparseable value
    /// is ignored rather than producing a busy loop.
    pub fn with_interval_from_env(mut self) -> Self {
        if let Some(interval) =
            interval_from_env_value(std::env::var("HEARTBEAT_INTERVAL_SECS").ok().as_deref())
        {
            self.interval = interval;
        }
        self
    }
}

fn interval_from_env_value(raw: Option<&str>) -> Option<Duration> {
    raw.and_then(|value| value.trim().parse::<u64>().ok())
        .filter(|secs| *secs > 0)
        .map(Duration::from_secs)
}

/// The lease upsert: `started_at` is written by the first insert only, and
/// every later beat advances `last_seen_at`. `instance_id` is the conflict
/// key, so one process has exactly one row.
const HEARTBEAT_UPSERT_SQL: &str = "INSERT INTO service_heartbeats
         (instance_id, service, version, started_at, last_seen_at, capabilities, region)
     VALUES ($1, $2, $3, NOW(), NOW(), $4, $5)
     ON CONFLICT (instance_id) DO UPDATE SET
         service = EXCLUDED.service,
         version = EXCLUDED.version,
         last_seen_at = NOW(),
         capabilities = EXCLUDED.capabilities,
         region = EXCLUDED.region";

/// `{service}-{hostname}-{pid}` — one row per OS process. Uses `HOSTNAME`
/// (set by Docker and most shells); falls back to `unknown-host`.
pub fn process_instance_id(service: &str) -> String {
    let host = std::env::var("HOSTNAME")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "unknown-host".to_string());
    instance_id_for(service, &host, std::process::id())
}

fn instance_id_for(service: &str, host: &str, pid: u32) -> String {
    format!("{service}-{host}-{pid}")
}

fn region_from_env() -> Option<String> {
    pick_region(
        std::env::var("HEARTBEAT_REGION").ok(),
        std::env::var("REGION").ok(),
        std::env::var("AWS_REGION").ok(),
    )
}

/// First non-empty value wins; whitespace-only values are ignored.
fn pick_region(
    heartbeat_region: Option<String>,
    region: Option<String>,
    aws_region: Option<String>,
) -> Option<String> {
    [heartbeat_region, region, aws_region]
        .into_iter()
        .flatten()
        .map(|value| value.trim().to_string())
        .find(|value| !value.is_empty())
}

/// Upsert one heartbeat row. `started_at` is set by the first insert and is
/// not moved by later beats; `last_seen_at` is always `NOW()`.
///
/// Exposed (not only used through [`spawn_service_heartbeat`]) so binaries
/// and tests can record a beat synchronously.
pub async fn record_heartbeat(pool: &PgPool, config: &HeartbeatConfig) -> Result<(), sqlx::Error> {
    sqlx::query(HEARTBEAT_UPSERT_SQL)
        .bind(&config.instance_id)
        .bind(&config.service)
        .bind(&config.version)
        .bind(sqlx::types::Json(&config.capabilities))
        .bind(&config.region)
        .execute(pool)
        .await
        .map(|_| ())
}

/// Spawn the background beat loop and return its `JoinHandle`.
///
/// The first beat happens immediately (so a freshly started process is
/// visible before the first interval elapses). Errors are logged, never
/// fatal. Dropping the handle detaches the task; abort it for a clean
/// shutdown if desired.
pub fn spawn_service_heartbeat(
    pool: PgPool,
    config: HeartbeatConfig,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(config.interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            ticker.tick().await;
            match record_heartbeat(&pool, &config).await {
                Ok(()) => tracing::trace!(
                    service = %config.service,
                    instance_id = %config.instance_id,
                    "service heartbeat recorded"
                ),
                Err(error) => tracing::warn!(
                    service = %config.service,
                    instance_id = %config.instance_id,
                    error = %error,
                    "service heartbeat failed (will retry on the next beat)"
                ),
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn instance_id_is_process_scoped_and_service_prefixed() {
        assert_eq!(
            instance_id_for("worker", "unit-test-host", 4242),
            "worker-unit-test-host-4242"
        );
        let live = process_instance_id("api-server");
        assert!(live.starts_with("api-server-"), "got {live}");
        assert!(live.ends_with(&std::process::id().to_string()));
    }

    #[test]
    fn config_defaults_are_explicit() {
        let config = HeartbeatConfig::new("api-server", "1.2.3");
        assert_eq!(config.service, "api-server");
        assert_eq!(config.version, "1.2.3");
        assert_eq!(config.interval, Duration::from_secs(30));
        assert!(config.capabilities.is_empty());
    }

    #[test]
    fn region_precedence_is_explicit_and_never_guesses() {
        assert_eq!(pick_region(None, None, None), None);
        assert_eq!(pick_region(Some("  ".into()), None, None), None);
        assert_eq!(
            pick_region(Some(" eu-central ".into()), Some("us-east-1".into()), None),
            Some("eu-central".into())
        );
        assert_eq!(
            pick_region(None, None, Some("us-west-2".into())),
            Some("us-west-2".into())
        );
    }

    #[test]
    fn interval_env_value_ignores_zero_and_garbage() {
        assert_eq!(interval_from_env_value(None), None);
        assert_eq!(interval_from_env_value(Some("0")), None);
        assert_eq!(interval_from_env_value(Some("-3")), None);
        assert_eq!(interval_from_env_value(Some("not-a-number")), None);
        assert_eq!(
            interval_from_env_value(Some(" 5 ")),
            Some(Duration::from_secs(5))
        );
    }

    /// The heartbeat must be a real process lease: the upsert refreshes
    /// `last_seen_at`, keeps `started_at` stable, and has nothing to do with
    /// queue activity.
    #[test]
    fn heartbeat_sql_is_a_process_lease_not_queue_activity() {
        assert!(HEARTBEAT_UPSERT_SQL.contains("INSERT INTO service_heartbeats"));
        assert!(HEARTBEAT_UPSERT_SQL.contains("ON CONFLICT (instance_id) DO UPDATE"));
        assert!(HEARTBEAT_UPSERT_SQL.contains("last_seen_at = NOW()"));
        assert!(!HEARTBEAT_UPSERT_SQL.contains("started_at = EXCLUDED"));
        assert!(!HEARTBEAT_UPSERT_SQL.contains("queue_jobs"));
    }
}
