//! Audit log viewer endpoints.
//!

use axum::extract::{Query, State};
use axum::routing::get;
use axum::{Json, Router};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

use crate::error::ApiError;
use crate::middleware::auth::AuthUser;
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new().route("/", get(list_audit_logs))
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditListQuery {
    pub action: Option<String>,
    pub status: Option<String>,
    pub tenant_id: Option<String>,
    pub user_id: Option<String>,
    pub resource_type: Option<String>,
    pub from: Option<String>,
    pub to: Option<String>,
    #[serde(default = "default_limit")]
    pub limit: i64,
    #[serde(default)]
    pub offset: i64,
}

const DEFAULT_AUDIT_WINDOW_DAYS: i64 = 30;
const MAX_AUDIT_WINDOW_DAYS: i64 = 90;

fn default_limit() -> i64 {
    50
}

fn parse_audit_timestamp(raw: &str, field_name: &str) -> Result<DateTime<Utc>, ApiError> {
    DateTime::parse_from_rfc3339(raw)
        .map(|timestamp| timestamp.with_timezone(&Utc))
        .map_err(|_| {
            ApiError::Validation(vec![format!(
                "{field_name} must be a valid RFC3339 timestamp"
            )])
        })
}

fn resolve_audit_window(
    from: Option<&str>,
    to: Option<&str>,
    now: DateTime<Utc>,
) -> Result<(DateTime<Utc>, DateTime<Utc>), ApiError> {
    let window_end = match to {
        Some(value) => parse_audit_timestamp(value, "to")?,
        None => now,
    };
    let window_start = match from {
        Some(value) => parse_audit_timestamp(value, "from")?,
        None => window_end - Duration::days(DEFAULT_AUDIT_WINDOW_DAYS),
    };

    if window_start > window_end {
        return Err(ApiError::Validation(vec!["from must be before to".into()]));
    }

    if window_end - window_start > Duration::days(MAX_AUDIT_WINDOW_DAYS) {
        return Err(ApiError::Validation(vec![format!(
            "audit log window cannot exceed {MAX_AUDIT_WINDOW_DAYS} days"
        )]));
    }

    Ok((window_start, window_end))
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditLogEntry {
    pub id: String,
    pub timestamp: String,
    pub action: String,
    pub resource: String,
    pub resource_id: String,
    pub actor_type: String,
    pub actor_id: String,
    pub tenant_id: Option<String>,
    pub status: String,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub details: serde_json::Value,
}

async fn list_audit_logs(
    State(state): State<AppState>,
    auth: AuthUser,
    Query(params): Query<AuditListQuery>,
) -> Result<Json<Vec<AuditLogEntry>>, ApiError> {
    crate::middleware::auth::require_scopes(&auth, &["*"])?;

    let limit = params.limit.clamp(1, 200);
    let offset = params.offset.max(0);
    let (window_start, window_end) =
        resolve_audit_window(params.from.as_deref(), params.to.as_deref(), Utc::now())?;

    // Build dynamic WHERE clause
    let mut conditions: Vec<String> = vec!["timestamp >= $1".into(), "timestamp <= $2".into()];
    let mut param_idx = 3u32;
    let mut bind_values: Vec<String> = Vec::new();

    if let Some(ref action) = params.action {
        conditions.push(format!("action = ${param_idx}"));
        param_idx += 1;
        bind_values.push(action.clone());
    }
    if let Some(ref tenant_id) = params.tenant_id {
        conditions.push(format!("tenant_id = ${param_idx}"));
        param_idx += 1;
        bind_values.push(tenant_id.clone());
    }
    if let Some(ref user_id) = params.user_id {
        conditions.push(format!("user_id = ${param_idx}"));
        param_idx += 1;
        bind_values.push(user_id.clone());
    }
    if let Some(ref resource_type) = params.resource_type {
        conditions.push(format!("resource_type = ${param_idx}"));
        param_idx += 1;
        bind_values.push(resource_type.clone());
    }
    if let Some(ref status) = params.status {
        conditions.push(format!(
            "COALESCE(metadata->>'status', 'success') = ${param_idx}"
        ));
        param_idx += 1;
        bind_values.push(status.clone());
    }

    let where_clause = format!("WHERE {}", conditions.join(" AND "));

    let sql = format!(
        "SELECT id, timestamp, action, resource_type, resource_id,
                user_id, tenant_id, ip_address, user_agent, metadata
         FROM audit_logs
         {where_clause}
         ORDER BY timestamp DESC, id DESC
         LIMIT ${param_idx} OFFSET ${}",
        param_idx + 1
    );

    let mut query = sqlx::query_as::<
        _,
        (
            String,
            chrono::DateTime<chrono::Utc>,
            String,
            String,
            Option<String>,
            Option<String>,
            Option<String>,
            Option<String>,
            Option<String>,
            Option<serde_json::Value>,
        ),
    >(&sql);

    query = query.bind(window_start).bind(window_end);

    for val in &bind_values {
        query = query.bind(val);
    }
    query = query.bind(limit).bind(offset);

    let rows = query.fetch_all(&state.db).await?;

    let entries: Vec<AuditLogEntry> = rows
        .into_iter()
        .map(|r| {
            let metadata = r.9.unwrap_or(serde_json::json!({}));
            let status = metadata
                .get("status")
                .and_then(|v| v.as_str())
                .unwrap_or("success")
                .to_string();
            let details = metadata
                .get("details")
                .cloned()
                .unwrap_or_else(|| metadata.clone());

            AuditLogEntry {
                id: r.0,
                timestamp: r.1.to_rfc3339(),
                action: r.2,
                resource: r.3,
                resource_id: r.4.unwrap_or_default(),
                actor_type: if r.5.is_some() {
                    "user".into()
                } else {
                    "system".into()
                },
                actor_id: r.5.unwrap_or_else(|| "system".into()),
                tenant_id: r.6,
                status,
                ip_address: r.7,
                user_agent: r.8,
                details,
            }
        })
        .collect();

    Ok(Json(entries))
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    #[test]
    fn resolve_audit_window_defaults_to_last_thirty_days() {
        let now = Utc.with_ymd_and_hms(2026, 2, 1, 12, 0, 0).unwrap();
        let (from, to) =
            resolve_audit_window(None, None, now).expect("default window should resolve");

        assert_eq!(to, now);
        assert_eq!(from, now - Duration::days(DEFAULT_AUDIT_WINDOW_DAYS));
    }

    #[test]
    fn resolve_audit_window_rejects_inverted_ranges() {
        let now = Utc.with_ymd_and_hms(2026, 2, 1, 12, 0, 0).unwrap();

        assert!(matches!(
            resolve_audit_window(
                Some("2026-02-02T00:00:00Z"),
                Some("2026-02-01T00:00:00Z"),
                now,
            ),
            Err(ApiError::Validation(_))
        ));
    }

    #[test]
    fn resolve_audit_window_rejects_ranges_wider_than_ninety_days() {
        let now = Utc.with_ymd_and_hms(2026, 4, 15, 12, 0, 0).unwrap();

        assert!(matches!(
            resolve_audit_window(
                Some("2026-01-01T00:00:00Z"),
                Some("2026-04-15T00:00:00Z"),
                now,
            ),
            Err(ApiError::Validation(_))
        ));
    }
}
