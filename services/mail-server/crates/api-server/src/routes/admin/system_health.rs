//! System health endpoint — queues, workers, MTA nodes, alerts.
//!

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
            tracing::warn!(table, "system health table missing; returning empty dataset");
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
    pub workers: Vec<WorkerStatus>,
    pub mta_nodes: Vec<MtaNode>,
    pub alerts: Vec<SystemAlert>,
}

#[derive(Debug, Serialize)]
pub struct QueueStatus {
    pub name: String,
    pub depth: i64,
    pub processing: i64,
    pub status: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkerStatus {
    pub id: String,
    pub name: String,
    pub r#type: String,
    pub status: String,
    pub last_heartbeat: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MtaNode {
    pub id: String,
    pub ip_address: String,
    pub pool_id: Option<String>,
    pub status: String,
    pub warmup_day: Option<i32>,
    pub daily_limit: Option<i64>,
    pub daily_sent: Option<i64>,
    pub is_fully_warmed: bool,
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
            QueueStatus { name, depth, processing: proc, status: status.into() }
        })
        .collect();

// ── Workers (derived from queue_jobs.worker_id) ────────────
    let worker_rows = optional_relation_rows(
        sqlx::query_as::<_, (String, String, Option<chrono::DateTime<chrono::Utc>>)>(
            "SELECT DISTINCT worker_id, queue_name, MAX(updated_at)
             FROM queue_jobs WHERE worker_id IS NOT NULL
             GROUP BY worker_id, queue_name",
        )
        .fetch_all(&state.db)
        .await,
        "queue_jobs",
    )?;

    let workers: Vec<WorkerStatus> = worker_rows
        .into_iter()
        .map(|(id, queue, hb)| WorkerStatus {
            name: format!("{queue}-worker"),
            r#type: queue,
            status: if hb.map(|t| t > chrono::Utc::now() - chrono::Duration::minutes(5)).unwrap_or(false) {
                "running".into()
            } else {
                "idle".into()
            },
            last_heartbeat: hb.map(|t| t.to_rfc3339()),
            id,
        })
        .collect();

// ── MTA nodes from ip_pool_addresses ───────────────────────
    let mta_rows = optional_relation_rows(
        sqlx::query_as::<_, (
            String,
            String,
            Option<String>,
            String,
            Option<i32>,
            Option<i64>,
            Option<i64>,
            bool,
        )>(
            "SELECT id::text, ip_address, pool_id::text, status,
                    warmup_day, daily_limit, daily_sent, is_fully_warmed
             FROM ip_pool_addresses ORDER BY ip_address LIMIT 50",
        )
        .fetch_all(&state.db)
        .await,
        "ip_pool_addresses",
    )?;

    let mta_nodes: Vec<MtaNode> = mta_rows
        .into_iter()
        .map(|(id, ip, pool, status, wd, dl, ds, fw)| MtaNode {
            id, ip_address: ip, pool_id: pool, status,
            warmup_day: wd, daily_limit: dl, daily_sent: ds, is_fully_warmed: fw,
        })
        .collect();

// ── Alerts ─────────────────────────────────────────────────
    let alert_rows = optional_relation_rows(
        sqlx::query_as::<_, (
            String,
            String,
            String,
            String,
            chrono::DateTime<chrono::Utc>,
            bool,
        )>(
            "SELECT id::text, severity, component, message, timestamp, acknowledged
             FROM system_alerts ORDER BY timestamp DESC LIMIT 50",
        )
        .fetch_all(&state.db)
        .await,
        "system_alerts",
    )?;

    let alerts: Vec<SystemAlert> = alert_rows
        .into_iter()
        .map(|(id, sev, comp, msg, ts, ack)| SystemAlert {
            id, severity: sev, component: comp, message: msg,
            timestamp: ts.to_rfc3339(), acknowledged: ack,
        })
        .collect();

    Ok(Json(SystemHealthResponse { queues, workers, mta_nodes, alerts }))
}
