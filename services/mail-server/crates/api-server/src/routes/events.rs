//! Event query routes.

use super::helpers::{clamp_limit, default_limit};
use axum::extract::{Path, Query, State};
use axum::routing::get;
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::ApiError;
use crate::middleware::auth::{require_scopes, AuthUser};
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/", get(list_events))
        .route("/stats", get(event_stats))
        .route("/timeseries", get(event_timeseries))
        .route("/:id", get(get_event))
}

// ─── Types ─────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ListEventsQuery {
    #[serde(default = "default_limit")]
    pub limit: i64,
    #[serde(default)]
    pub offset: i64,
    #[serde(default)]
    pub cursor: Option<i64>,
    #[serde(default)]
    pub event_type: Option<String>,
    #[serde(default)]
    pub message_id: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct EventResponse {
    pub id: String,
    pub message_id: Option<String>,
    pub event_type: String,
    pub recipient: Option<String>,
    pub metadata: Option<serde_json::Value>,
    pub timestamp: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StatsQuery {
    #[serde(default)]
    pub from: Option<DateTime<Utc>>,
    #[serde(default)]
    pub to: Option<DateTime<Utc>>,
}

#[derive(Debug, Serialize)]
pub struct EventStats {
    pub total: i64,
    pub delivered: i64,
    pub bounced: i64,
    pub complained: i64,
    pub opened: i64,
    pub clicked: i64,
}

#[derive(Debug, Serialize)]
pub struct TimeseriesPoint {
    pub timestamp: String,
    pub count: i64,
    pub event_type: String,
}

// ─── Handlers ──────────────────────────────────────────────────

async fn list_events(
    State(state): State<AppState>,
    auth: AuthUser,
    Query(params): Query<ListEventsQuery>,
) -> Result<Json<Vec<EventResponse>>, ApiError> {
    require_scopes(&auth, &["events:read"])?;

    let offset = params.cursor.unwrap_or(params.offset).clamp(0, 100_000);

    let mut sql = String::from(
        "SELECT id, message_id, event_type, recipient, metadata, timestamp FROM events WHERE tenant_id = $1",
    );
    let mut param_idx = 2u8;

    if params.event_type.is_some() {
        sql.push_str(&format!(" AND event_type = ${param_idx}"));
        param_idx += 1;
    }
    if params.message_id.is_some() {
        sql.push_str(&format!(" AND message_id = ${param_idx}"));
        param_idx += 1;
    }
    sql.push_str(&format!(
        " ORDER BY timestamp DESC LIMIT ${param_idx} OFFSET ${}",
        param_idx + 1
    ));

    // Build query dynamically
    let mut query = sqlx::query_as::<_, EventRow>(&sql).bind(&auth.tenant_id);
    if let Some(ref event_type) = params.event_type {
        query = query.bind(event_type);
    }
    if let Some(ref message_id) = params.message_id {
        query = query.bind(message_id);
    }
    query = query.bind(clamp_limit(params.limit, 200)).bind(offset);

    let rows = query.fetch_all(&state.db).await?;

    Ok(Json(rows.into_iter().map(Into::into).collect()))
}

async fn get_event(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<Uuid>,
) -> Result<Json<EventResponse>, ApiError> {
    require_scopes(&auth, &["events:read"])?;

    let row = sqlx::query_as::<_, EventRow>(
        "SELECT id, message_id, event_type, recipient, metadata, timestamp
         FROM events WHERE id = $1 AND tenant_id = $2",
    )
    .bind(id)
    .bind(&auth.tenant_id)
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| ApiError::NotFound("event not found".into()))?;

    Ok(Json(row.into()))
}

async fn event_stats(
    State(state): State<AppState>,
    auth: AuthUser,
    Query(params): Query<StatsQuery>,
) -> Result<Json<EventStats>, ApiError> {
    require_scopes(&auth, &["events:read"])?;

    let from = params
        .from
        .unwrap_or_else(|| Utc::now() - chrono::Duration::days(30));
    let to = params.to.unwrap_or_else(Utc::now);

    let row = sqlx::query_as::<_, StatsRow>(
        "SELECT
            COUNT(*) as total,
            COUNT(*) FILTER (WHERE event_type = 'delivered') as delivered,
            COUNT(*) FILTER (WHERE event_type = 'bounced') as bounced,
            COUNT(*) FILTER (WHERE event_type = 'complained') as complained,
            COUNT(*) FILTER (WHERE event_type = 'opened') as opened,
            COUNT(*) FILTER (WHERE event_type = 'clicked') as clicked
         FROM events
         WHERE tenant_id = $1 AND timestamp >= $2 AND timestamp <= $3",
    )
    .bind(&auth.tenant_id)
    .bind(from)
    .bind(to)
    .fetch_one(&state.db)
    .await?;

    Ok(Json(EventStats {
        total: row.total,
        delivered: row.delivered,
        bounced: row.bounced,
        complained: row.complained,
        opened: row.opened,
        clicked: row.clicked,
    }))
}

async fn event_timeseries(
    State(state): State<AppState>,
    auth: AuthUser,
    Query(params): Query<StatsQuery>,
) -> Result<Json<Vec<TimeseriesPoint>>, ApiError> {
    require_scopes(&auth, &["events:read"])?;

    let from = params
        .from
        .unwrap_or_else(|| Utc::now() - chrono::Duration::days(7));
    let to = params.to.unwrap_or_else(Utc::now);

    let rows = sqlx::query_as::<_, TimeseriesRow>(
        "SELECT date_trunc('hour', timestamp) as bucket, event_type, COUNT(*) as count
         FROM events
         WHERE tenant_id = $1 AND timestamp >= $2 AND timestamp <= $3
         GROUP BY bucket, event_type
         ORDER BY bucket",
    )
    .bind(&auth.tenant_id)
    .bind(from)
    .bind(to)
    .fetch_all(&state.db)
    .await?;

    Ok(Json(
        rows.into_iter()
            .map(|r| TimeseriesPoint {
                timestamp: r.bucket.to_rfc3339(),
                count: r.count,
                event_type: r.event_type,
            })
            .collect(),
    ))
}

// ─── Row types ─────────────────────────────────────────────────

#[derive(sqlx::FromRow)]
struct EventRow {
    id: String,
    message_id: Option<String>,
    event_type: String,
    recipient: Option<String>,
    metadata: Option<serde_json::Value>,
    timestamp: DateTime<Utc>,
}

impl From<EventRow> for EventResponse {
    fn from(r: EventRow) -> Self {
        Self {
            id: r.id,
            message_id: r.message_id,
            event_type: r.event_type,
            recipient: r.recipient,
            metadata: r.metadata,
            timestamp: r.timestamp.to_rfc3339(),
        }
    }
}

#[derive(sqlx::FromRow)]
struct StatsRow {
    total: i64,
    delivered: i64,
    bounced: i64,
    complained: i64,
    opened: i64,
    clicked: i64,
}

#[derive(sqlx::FromRow)]
struct TimeseriesRow {
    bucket: DateTime<Utc>,
    event_type: String,
    count: i64,
}

// ─── Tests ─────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_event_stats_serialisation() {
        let stats = EventStats {
            total: 1000,
            delivered: 950,
            bounced: 30,
            complained: 5,
            opened: 400,
            clicked: 100,
        };
        let json = serde_json::to_value(&stats).unwrap();
        assert_eq!(json["total"], 1000);
    }

    #[test]
    fn test_timeseries_point() {
        let p = TimeseriesPoint {
            timestamp: "2026-01-01T00:00:00Z".into(),
            count: 42,
            event_type: "delivered".into(),
        };
        let json = serde_json::to_value(&p).unwrap();
        assert_eq!(json["count"], 42);
    }

    #[test]
    fn test_event_response_serialisation() {
        let resp = EventResponse {
            id: String::new(),
            message_id: Some(Uuid::nil().to_string()),
            event_type: "opened".into(),
            recipient: Some("user@example.com".into()),
            metadata: None,
            timestamp: "2026-01-01T12:00:00Z".into(),
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["event_type"], "opened");
    }
}
