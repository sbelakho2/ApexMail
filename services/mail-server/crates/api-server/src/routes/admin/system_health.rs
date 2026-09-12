//! System health endpoint — queues, queue-writer activity, REAL service
//! process liveness, IP pool addresses, alerts.
//!
//! **What these numbers are and are NOT**:
//!
//! * `serviceHeartbeats` / `serviceLiveness` are REAL process leases read
//!   from the `service_heartbeats` table (migration 215), written by each
//!   service binary's heartbeat emitter (`apexmail_lib::heartbeat`). A row is
//!   `live` when its beat is fresh (≤ [`HEARTBEAT_STALE_AFTER_SECS`]), else
//!   `stale`; a service with no rows is reported as `no_heartbeat`. Process
//!   health is NEVER inferred from queue traffic.
//! * `queueWriters` are queue activity OBSERVATIONS derived from `queue_jobs`
//!   (one entry per queue with recent activity) — NOT live worker processes.
//!   They remain because queue traffic is operationally useful, but they are
//!   labelled as observations and the `notes` field says so.
//! * `ipPoolAddresses` are rows of `ip_pool_addresses` (sending IP
//!   addresses), not MTA processes/nodes.
//!
//! `EXPECTED_SERVICES` lists the services whose emitters are wired in this
//! repository; each gets an explicit liveness entry even with zero rows
//! (`no_heartbeat`). Heartbeat rows for other services are still reported
//! (nothing is hidden), but no liveness claim is invented for services that
//! never register.

use axum::extract::State;
use axum::routing::get;
use axum::{Json, Router};
use serde::Serialize;

use crate::error::ApiError;
use crate::middleware::auth::AuthUser;
use crate::state::AppState;

/// Services whose heartbeat emitters are wired in this repository. An entry
/// is reported even when the service has never registered (explicit
/// `no_heartbeat` rather than silence).
pub const EXPECTED_SERVICES: &[&str] = &["api-server", "worker"];

/// A heartbeat older than this is `stale` (three missed 30-second beats).
pub const HEARTBEAT_STALE_AFTER_SECS: i64 = 90;

fn is_optional_schema_error(error: &sqlx::Error) -> bool {
    matches!(error, sqlx::Error::Database(db_error) if matches!(db_error.code().as_deref(), Some("42P01") | Some("42703")))
}

fn optional_relation_rows<T>(
    result: Result<Vec<T>, sqlx::Error>,
    table: &'static str,
) -> Result<Vec<T>, ApiError> {
    match result {
        Ok(rows) => Ok(rows),
        Err(error) if is_optional_schema_error(&error) => {
            tracing::warn!(
                table,
                "system health table missing; returning empty dataset"
            );
            Ok(Vec::new())
        }
        Err(error) => Err(error.into()),
    }
}

pub fn router() -> Router<AppState> {
    Router::new().route("/", get(system_health))
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SystemHealthResponse {
    pub queues: Vec<QueueStatus>,
    /// Queue writers OBSERVED via `queue_jobs` activity — NOT process
    /// heartbeats. Real liveness is in `service_liveness`.
    pub queue_writers: Vec<QueueWriterStatus>,
    /// Real process heartbeat rows, newest first. Inactive instances age out
    /// of this list after 7 days.
    pub service_heartbeats: Vec<ServiceHeartbeat>,
    /// One entry per expected (and per actually-registered) service, with an
    /// explicit `live` / `stale` / `no_heartbeat` state.
    pub service_liveness: Vec<ServiceLiveness>,
    /// Rows of `ip_pool_addresses` (sending IP addresses), not MTA processes.
    pub ip_pool_addresses: Vec<IpPoolAddress>,
    pub alerts: Vec<SystemAlert>,
    pub system_sender: SystemSenderHealth,
    /// Response-level caveats so a UI can label the data honestly.
    pub notes: Vec<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SystemSenderHealth {
    pub domain: String,
    pub status: String,
    pub ready: bool,
}

#[derive(Debug, Serialize)]
pub struct QueueStatus {
    pub name: String,
    pub depth: i64,
    pub processing: i64,
    pub status: String,
}

/// One queue writer observed from queue activity. `last_observed_activity`
/// is the most recent `queue_jobs.updated_at` a worker touched for that
/// queue — it is NOT a process heartbeat.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct QueueWriterStatus {
    pub id: String,
    pub name: String,
    pub r#type: String,
    /// "active" when the queue was touched recently, else "idle" — derived
    /// from job activity, not a process liveness signal.
    pub status: String,
    pub last_observed_activity: Option<String>,
}

/// One real process lease from `service_heartbeats`.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ServiceHeartbeat {
    pub instance_id: String,
    pub service: String,
    pub version: String,
    pub started_at: String,
    pub last_seen_at: String,
    /// Seconds since the last beat (never negative; clock skew is clamped).
    pub age_seconds: i64,
    pub capabilities: Vec<String>,
    pub region: Option<String>,
    /// `live` (fresh beat) or `stale` (row exists, beat older than
    /// [`HEARTBEAT_STALE_AFTER_SECS`]).
    pub status: String,
}

/// Aggregate liveness for one service.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ServiceLiveness {
    pub service: String,
    /// `live` | `stale` | `no_heartbeat`.
    pub status: String,
    pub live_instances: i64,
    pub stale_instances: i64,
    /// Freshest beat for the service, if any row exists in the 7-day window.
    pub last_seen_at: Option<String>,
}

/// A row of `ip_pool_addresses` — a sending IP address in an IP pool, not an
/// MTA process.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IpPoolAddress {
    pub id: String,
    pub ip_address: String,
    pub pool_id: Option<String>,
    pub status: String,
    pub warmup_day: Option<i32>,
    pub daily_limit: Option<i64>,
}

#[derive(Debug, Serialize)]
pub struct SystemAlert {
    pub id: String,
    pub severity: String,
    pub component: String,
    pub message: String,
    pub timestamp: String,
    pub acknowledged: bool,
}

/// The liveness verdict for one service. Pure so the explicit
/// `no_heartbeat` state is testable without a database.
fn liveness_status(live_instances: i64, stale_instances: i64) -> &'static str {
    if live_instances > 0 {
        "live"
    } else if stale_instances > 0 {
        "stale"
    } else {
        "no_heartbeat"
    }
}

#[derive(sqlx::FromRow)]
struct HeartbeatRow {
    instance_id: String,
    service: String,
    version: String,
    started_at: chrono::DateTime<chrono::Utc>,
    last_seen_at: chrono::DateTime<chrono::Utc>,
    capabilities: sqlx::types::Json<Vec<String>>,
    region: Option<String>,
    live: bool,
}

/// Turn heartbeat rows into the serialized list and per-service liveness.
/// Unknown services that did register are included after the expected ones,
/// so no row is hidden.
fn heartbeat_views(rows: Vec<HeartbeatRow>) -> (Vec<ServiceHeartbeat>, Vec<ServiceLiveness>) {
    let now = chrono::Utc::now();
    let heartbeats: Vec<ServiceHeartbeat> = rows
        .into_iter()
        .map(|row| {
            let age_seconds = now
                .signed_duration_since(row.last_seen_at)
                .num_seconds()
                .max(0);
            ServiceHeartbeat {
                instance_id: row.instance_id,
                service: row.service,
                version: row.version,
                started_at: row.started_at.to_rfc3339(),
                last_seen_at: row.last_seen_at.to_rfc3339(),
                age_seconds,
                capabilities: row.capabilities.0,
                region: row.region,
                status: if row.live { "live" } else { "stale" }.into(),
            }
        })
        .collect();

    let mut services: Vec<String> = EXPECTED_SERVICES.iter().map(|s| (*s).to_string()).collect();
    for heartbeat in &heartbeats {
        if !services.contains(&heartbeat.service) {
            services.push(heartbeat.service.clone());
        }
    }

    let liveness = services
        .into_iter()
        .map(|service| {
            let matching: Vec<&ServiceHeartbeat> =
                heartbeats.iter().filter(|h| h.service == service).collect();
            let live_instances = matching.iter().filter(|h| h.status == "live").count() as i64;
            let stale_instances = matching.len() as i64 - live_instances;
            let last_seen_at = matching.iter().map(|h| h.last_seen_at.clone()).max();
            ServiceLiveness {
                status: liveness_status(live_instances, stale_instances).into(),
                service,
                live_instances,
                stale_instances,
                last_seen_at,
            }
        })
        .collect();

    (heartbeats, liveness)
}

async fn system_health(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<Json<SystemHealthResponse>, ApiError> {
    crate::middleware::auth::require_scopes(&auth, &["*"])?;
    crate::middleware::auth::require_system_tenant(&state, &auth).await?;

    let system_sender = match crate::routes::domains::system_sender_status(&state).await {
        Ok(sender) => SystemSenderHealth {
            domain: sender.domain,
            status: sender.status,
            ready: sender.ready,
        },
        Err(error) => {
            tracing::warn!(error = %error, "system sender is unavailable in health check");
            SystemSenderHealth {
                domain: crate::routes::system_sender::SYSTEM_DOMAIN.into(),
                status: "unavailable".into(),
                ready: false,
            }
        }
    };

    // ── Queues ─────────────────────────────────────────────────
    let queue_rows = optional_relation_rows(
        sqlx::query_as::<_, (String, i64, i64)>(
            "SELECT queue_name,
                    SUM(CASE WHEN status = 'pending' THEN 1 ELSE 0 END) as depth,
                    SUM(CASE WHEN status = 'processing' THEN 1 ELSE 0 END) as proc
             FROM queue_jobs GROUP BY queue_name",
        )
        .fetch_all(&state.db)
        .await,
        "queue_jobs",
    )?;

    let queues: Vec<QueueStatus> = queue_rows
        .into_iter()
        .map(|(name, depth, proc)| {
            let status = if depth > 1000 { "warning" } else { "healthy" };
            QueueStatus {
                name,
                depth,
                processing: proc,
                status: status.into(),
            }
        })
        .collect();

    // ── Queue writers (OBSERVED from queue_jobs activity) ──────
    // queue_jobs has no worker_id column — derive one logical queue writer
    // per queue from the most recent job activity. These are observations of
    // queue activity, NOT process heartbeats; real liveness is below.
    let worker_rows = optional_relation_rows(
        sqlx::query_as::<_, (String, Option<chrono::DateTime<chrono::Utc>>)>(
            "SELECT COALESCE(queue_name, queue) AS worker_queue, MAX(updated_at)
             FROM queue_jobs
             WHERE status IN ('processing', 'completed', 'failed')
             GROUP BY COALESCE(queue_name, queue)",
        )
        .fetch_all(&state.db)
        .await,
        "queue_jobs",
    )?;

    let queue_writers: Vec<QueueWriterStatus> = worker_rows
        .into_iter()
        .map(|(queue, last_activity)| QueueWriterStatus {
            id: format!("queue-writer:{queue}"),
            name: format!("{queue}-queue-writer"),
            r#type: queue,
            status: if last_activity
                .map(|t| t > chrono::Utc::now() - chrono::Duration::minutes(5))
                .unwrap_or(false)
            {
                "active".into()
            } else {
                "idle".into()
            },
            last_observed_activity: last_activity.map(|t| t.to_rfc3339()),
        })
        .collect();

    // ── Service heartbeats (REAL process liveness) ─────────────
    // A busy queue is not a live process and an idle process is not dead:
    // liveness comes only from written leases. `live` is computed in SQL so
    // the freshness window is one constant (`HEARTBEAT_STALE_AFTER_SECS`).
    let heartbeat_rows = optional_relation_rows(
        sqlx::query_as::<_, HeartbeatRow>(
            "SELECT instance_id, service, version, started_at, last_seen_at,
                    capabilities, region,
                    (last_seen_at >= NOW() - make_interval(secs => $1::double precision)) AS live
             FROM service_heartbeats
             WHERE last_seen_at >= NOW() - INTERVAL '7 days'
             ORDER BY last_seen_at DESC
             LIMIT 100",
        )
        .bind(HEARTBEAT_STALE_AFTER_SECS as f64)
        .fetch_all(&state.db)
        .await,
        "service_heartbeats",
    )?;

    let (service_heartbeats, service_liveness) = heartbeat_views(heartbeat_rows);

    // ── IP pool addresses (rows of ip_pool_addresses) ──────────
    // These are sending IP ADDRESSES, not MTA processes/nodes.
    // `ip_pool_addresses.ip_address` is INET (migration 093:395): decoding
    // it directly into a Rust `String` fails on a real database, so the
    // host form is selected. `daily_limit` is INTEGER (093:399) and must be
    // widened to BIGINT for the `Option<i64>` field. `ORDER BY ip_address`
    // stays on the raw INET column so ordering keeps its natural (address)
    // semantics.
    let ip_rows = optional_relation_rows(
        sqlx::query_as::<
            _,
            (
                String,
                String,
                Option<String>,
                String,
                Option<i32>,
                Option<i64>,
            ),
        >(
            "SELECT id::text, host(ip_address) AS ip_address, pool_id::text, status,
                    warmup_day, daily_limit::bigint AS daily_limit
             FROM ip_pool_addresses ORDER BY ip_address LIMIT 50",
        )
        .fetch_all(&state.db)
        .await,
        "ip_pool_addresses",
    )?;

    let ip_pool_addresses: Vec<IpPoolAddress> = ip_rows
        .into_iter()
        .map(|(id, ip, pool, status, wd, dl)| IpPoolAddress {
            id,
            ip_address: ip,
            pool_id: pool,
            status,
            warmup_day: wd,
            daily_limit: dl,
        })
        .collect();

    // ── Alerts ─────────────────────────────────────────────────
    let alert_rows = optional_relation_rows(
        sqlx::query_as::<
            _,
            (
                String,
                String,
                String,
                String,
                chrono::DateTime<chrono::Utc>,
                bool,
            ),
        >(
            "SELECT id::text, severity, alert_type AS component, message, created_at AS timestamp, acknowledged
             FROM system_alerts ORDER BY created_at DESC LIMIT 50",
        )
        .fetch_all(&state.db)
        .await,
        "system_alerts",
    )?;

    let alerts: Vec<SystemAlert> = alert_rows
        .into_iter()
        .map(|(id, sev, comp, msg, ts, ack)| SystemAlert {
            id,
            severity: sev,
            component: comp,
            message: msg,
            timestamp: ts.to_rfc3339(),
            acknowledged: ack,
        })
        .collect();

    Ok(Json(SystemHealthResponse {
        queues,
        queue_writers,
        service_heartbeats,
        service_liveness,
        ip_pool_addresses,
        alerts,
        system_sender,
        notes: vec![
            format!(
                "serviceHeartbeats are real process leases from service_heartbeats; status live means a beat within the last {HEARTBEAT_STALE_AFTER_SECS} seconds. A service with no rows is reported as no_heartbeat — process liveness is never inferred from queue traffic."
            ),
            "queueWriters are queue activity observations derived from queue_jobs (one entry per queue), not process heartbeats; see serviceLiveness for process liveness."
                .to_string(),
            "ipPoolAddresses are ip_pool_addresses rows (sending IP addresses), not MTA processes/nodes."
                .to_string(),
        ],
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The response must say plainly that queue writers are activity
    /// observations (not process heartbeats), that service liveness comes
    /// from real leases, and that IP pool addresses are not MTA nodes.
    #[test]
    fn response_notes_label_activity_heartbeats_and_mta_nodes() {
        // Mirror the notes construction in the handler.
        let notes = vec![
            format!(
                "serviceHeartbeats are real process leases from service_heartbeats; status live means a beat within the last {HEARTBEAT_STALE_AFTER_SECS} seconds. A service with no rows is reported as no_heartbeat — process liveness is never inferred from queue traffic."
            ),
            "queueWriters are queue activity observations derived from queue_jobs (one entry per queue), not process heartbeats; see serviceLiveness for process liveness."
                .to_string(),
            "ipPoolAddresses are ip_pool_addresses rows (sending IP addresses), not MTA processes/nodes."
                .to_string(),
        ];
        assert!(notes[0].contains("real process leases"));
        assert!(notes[0].contains("no_heartbeat"));
        assert!(notes[0].contains("never inferred from queue traffic"));
        assert!(notes[1].contains("not process heartbeats"));
        assert!(notes[2].contains("not MTA processes"));
    }

    /// `no_heartbeat` is an explicit state: a service with no rows (and no
    /// stale rows) must never be reported as healthy or active.
    #[test]
    fn liveness_has_an_explicit_no_heartbeat_state() {
        assert_eq!(liveness_status(0, 0), "no_heartbeat");
        assert_eq!(liveness_status(2, 1), "live");
        assert_eq!(liveness_status(0, 3), "stale");
        // A stale instance is NOT live, even if other instances are absent.
        assert_ne!(liveness_status(0, 1), "live");
    }

    /// Expected services without rows still appear with `no_heartbeat`, so
    /// the control plane shows absence instead of hiding it.
    #[test]
    fn heartbeat_views_report_expected_services_without_rows() {
        let (heartbeats, liveness) = heartbeat_views(Vec::new());
        assert!(heartbeats.is_empty());
        assert_eq!(liveness.len(), EXPECTED_SERVICES.len());
        for entry in liveness {
            assert_eq!(entry.status, "no_heartbeat");
            assert_eq!(entry.live_instances, 0);
            assert_eq!(entry.stale_instances, 0);
            assert_eq!(entry.last_seen_at, None);
        }
    }

    /// The renamed structs must not carry the misleading "heartbeat" or
    /// "MTA node" vocabulary in their serialized shape.
    #[test]
    fn queue_writer_field_is_last_observed_activity_not_heartbeat() {
        let writer = QueueWriterStatus {
            id: "queue-writer:default".into(),
            name: "default-queue-writer".into(),
            r#type: "default".into(),
            status: "active".into(),
            last_observed_activity: None,
        };
        let json = serde_json::to_string(&writer).expect("serialize queue writer");
        assert!(json.contains("lastObservedActivity"));
        assert!(!json.contains("heartbeat"));
        assert!(!json.contains("worker"));

        let address = IpPoolAddress {
            id: "ip-1".into(),
            ip_address: "192.0.2.1".into(),
            pool_id: None,
            status: "active".into(),
            warmup_day: None,
            daily_limit: None,
        };
        let json = serde_json::to_string(&address).expect("serialize ip pool address");
        assert!(json.contains("ipAddress"));
        assert!(!json.contains("mtaNode"));
    }

    fn admin_auth() -> AuthUser {
        AuthUser {
            tenant_id: "system".into(),
            user_id: None,
            api_key_id: Some("test-static-key".into()),
            session_id: None,
            scopes: vec!["*".into()],
        }
    }

    /// Item 24: `ip_pool_addresses.ip_address` is INET (migration 093:395).
    /// Selecting it directly into a Rust `String` fails to decode on a real
    /// database; the handler must select `host(ip_address)` and the API must
    /// return the dotted-quad text.
    #[tokio::test]
    async fn ip_pool_inet_column_serializes_as_dotted_quad() {
        let Some(pool) = crate::test_db::canonical_pool("system_health_inet").await else {
            return;
        };

        // Insert a real INET value; a direct String decode of this column is
        // exactly what used to fail.
        sqlx::query(
            "INSERT INTO ip_pool_addresses (id, pool_id, ip_address, status, warmup_day, daily_limit)
             VALUES (gen_random_uuid(), $1, $2::inet, 'active', 0, 0)
             ON CONFLICT (ip_address) DO NOTHING",
        )
        .bind("health-inet-test-pool")
        .bind("192.0.2.25")
        .execute(&pool)
        .await
        .expect("seed an INET ip_pool_addresses row");

        let state = crate::app::test_support::test_state_over(pool.clone()).await;
        let response = system_health(State(state), admin_auth())
            .await
            .expect("system health must decode INET addresses");
        let body = serde_json::to_value(&response.0).expect("serialize system health");

        let addresses = body["ipPoolAddresses"]
            .as_array()
            .expect("ipPoolAddresses is an array");
        let entry = addresses
            .iter()
            .find(|row| row["ipAddress"] == "192.0.2.25")
            .expect("the seeded address is present in the response");
        assert_eq!(
            entry["ipAddress"], "192.0.2.25",
            "an INET address must serialize in host (dotted-quad) form"
        );

        let _ = sqlx::query("DELETE FROM ip_pool_addresses WHERE ip_address = $1::inet")
            .bind("192.0.2.25")
            .execute(&pool)
            .await;
    }

    /// End-to-end: the emitter writes a lease, `system_health` reports it as
    /// a LIVE process; a stale row is reported stale; a service with no row
    /// at all is reported `no_heartbeat` — never inferred from queue
    /// activity.
    #[tokio::test]
    async fn service_heartbeats_report_real_process_liveness() {
        let Some(pool) = crate::test_db::canonical_pool("system_health_heartbeats").await else {
            return;
        };

        // The emitter's real write path.
        let live_config = apexmail_lib::heartbeat::HeartbeatConfig::new("api-server", "9.9.9")
            .with_capabilities(vec!["http-api".into(), "control-plane".into()]);
        apexmail_lib::heartbeat::record_heartbeat(&pool, &live_config)
            .await
            .expect("record live heartbeat");

        // A worker row that stopped beating: stale, not live.
        sqlx::query(
            "INSERT INTO service_heartbeats
                 (instance_id, service, version, started_at, last_seen_at, capabilities, region)
             VALUES ('worker-test-host-1', 'worker', '9.9.9',
                     NOW() - INTERVAL '1 hour', NOW() - INTERVAL '10 minutes',
                     '[\"email\"]'::jsonb, NULL)
             ON CONFLICT (instance_id) DO UPDATE SET last_seen_at = EXCLUDED.last_seen_at",
        )
        .execute(&pool)
        .await
        .expect("seed stale worker heartbeat");

        // A dead instance from long ago must age out (outside the 7-day
        // window) and must NOT keep a service looking alive.
        sqlx::query(
            "INSERT INTO service_heartbeats
                 (instance_id, service, version, started_at, last_seen_at, capabilities)
             VALUES ('api-server-ancient-1', 'api-server', '0.0.1',
                     NOW() - INTERVAL '30 days', NOW() - INTERVAL '30 days', '[]'::jsonb)
             ON CONFLICT (instance_id) DO UPDATE SET last_seen_at = EXCLUDED.last_seen_at",
        )
        .execute(&pool)
        .await
        .expect("seed aged-out heartbeat");

        let state = crate::app::test_support::test_state_over(pool.clone()).await;
        let response = system_health(State(state), admin_auth())
            .await
            .expect("system health must read heartbeats");
        let body = serde_json::to_value(&response.0).expect("serialize system health");

        // The live lease is reported with its real instance identity.
        let heartbeats = body["serviceHeartbeats"]
            .as_array()
            .expect("serviceHeartbeats is an array");
        let live = heartbeats
            .iter()
            .find(|h| h["instanceId"] == live_config.instance_id)
            .expect("the recorded heartbeat is present");
        assert_eq!(live["service"], "api-server");
        assert_eq!(live["status"], "live");
        assert_eq!(live["capabilities"][0], "http-api");
        assert!(live["ageSeconds"].as_i64().expect("age") < HEARTBEAT_STALE_AFTER_SECS);

        // The aged-out row is not reported at all.
        assert!(
            !heartbeats
                .iter()
                .any(|h| h["instanceId"] == "api-server-ancient-1"),
            "heartbeat rows older than 7 days must age out"
        );

        // Liveness states: api-server live, worker stale (never live), and
        // the explicit aggregate verdicts.
        let liveness = body["serviceLiveness"]
            .as_array()
            .expect("serviceLiveness is an array");
        let api = liveness
            .iter()
            .find(|l| l["service"] == "api-server")
            .expect("api-server liveness entry");
        assert_eq!(api["status"], "live");
        assert!(api["liveInstances"].as_i64().expect("live count") >= 1);

        let worker = liveness
            .iter()
            .find(|l| l["service"] == "worker")
            .expect("worker liveness entry");
        assert_eq!(worker["status"], "stale");
        assert_eq!(worker["liveInstances"], 0);

        // Queue writers (activity observations) exist in the same response
        // shape but are explicitly NOT the liveness signal.
        assert!(body["queueWriters"].is_array());
        assert!(body["notes"][0]
            .as_str()
            .expect("note")
            .contains("never inferred from queue traffic"));

        pool.close().await;
    }
}
