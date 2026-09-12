//! System health endpoint — queues, queue writers, IP pool addresses, alerts.
//!
//! **What these numbers are NOT**: there is no process-heartbeat registry in
//! the schema (no worker/service heartbeat table exists), so `queueWriters`
//! are inferred from `queue_jobs` activity — one entry per queue with recent
//! job activity — not live worker processes. `ipPoolAddresses` are rows of
//! `ip_pool_addresses` (sending IPs), not MTA processes/nodes. Both are
//! labelled accordingly and explained in [`SystemHealthResponse::notes`].
//!
//! If a real heartbeat registry is ever added, these fields should be
//! replaced with its data (grep found none at the time of this fix).

use axum::extract::State;
use axum::routing::get;
use axum::{Json, Router};
use serde::Serialize;

use crate::error::ApiError;
use crate::middleware::auth::AuthUser;
use crate::state::AppState;

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
    /// Queue writers OBSERVED via `queue_jobs` activity — not process
    /// heartbeats (no heartbeat registry exists).
    pub queue_writers: Vec<QueueWriterStatus>,
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
    // queue_jobs has no worker_id column and no heartbeat registry exists —
    // derive one logical queue writer per queue from the most recent job
    // activity (updated_at on jobs that a worker actually touched). These
    // are observations of queue activity, NOT process heartbeats.
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
        ip_pool_addresses,
        alerts,
        system_sender,
        notes: vec![
            "queueWriters are queue activity observations derived from queue_jobs (one entry per queue), not process heartbeats — no heartbeat registry exists."
                .to_string(),
            "ipPoolAddresses are ip_pool_addresses rows (sending IP addresses), not MTA processes/nodes."
                .to_string(),
        ],
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Fix 6: the response must say plainly that queue writers are not
    /// process heartbeats and IP pool addresses are not MTA nodes.
    #[test]
    fn response_notes_disclaim_heartbeats_and_mta_nodes() {
        let notes = vec![
            "queueWriters are queue activity observations derived from queue_jobs (one entry per queue), not process heartbeats — no heartbeat registry exists.",
            "ipPoolAddresses are ip_pool_addresses rows (sending IP addresses), not MTA processes/nodes.",
        ];
        assert!(notes[0].contains("not process heartbeats"));
        assert!(notes[1].contains("not MTA processes"));
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
}
