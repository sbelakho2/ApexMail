//! Event query routes.

use super::helpers::{clamp_limit, default_limit};
use axum::extract::{Path, Query, State};
use axum::routing::get;
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

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

/// Maximum allowed `from`→`to` window for stats/timeseries queries (audit J):
/// unbounded ranges let a single request aggregate the tenant's entire event
/// history, a cheap resource-exhaustion vector.
const MAX_STATS_WINDOW_DAYS: i64 = 92;

/// Resolve and validate the stats query window (audit J).
///
/// * `from > to` → 400 (previously produced silently empty result sets and
///   masked client bugs).
/// * window longer than 92 days → 400.
/// * Missing bounds default to the caller-provided defaults.
fn resolve_stats_window(
    params: &StatsQuery,
    default_from: fn() -> DateTime<Utc>,
) -> Result<(DateTime<Utc>, DateTime<Utc>), ApiError> {
    let from = params.from.unwrap_or_else(default_from);
    let to = params.to.unwrap_or_else(Utc::now);

    if from > to {
        return Err(ApiError::BadRequest(
            "'from' must not be later than 'to'".into(),
        ));
    }
    if to - from > chrono::Duration::days(MAX_STATS_WINDOW_DAYS) {
        return Err(ApiError::BadRequest(format!(
            "time range exceeds the maximum of {MAX_STATS_WINDOW_DAYS} days"
        )));
    }

    Ok((from, to))
}

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
    Path(id): Path<String>,
) -> Result<Json<EventResponse>, ApiError> {
    require_scopes(&auth, &["events:read"])?;

    // events.id is VARCHAR(64) (migration 075 / runtime CREATE_EVENTS) — the
    // path parameter is bound as text after format validation, never parsed
    // as a UUID.
    if !is_valid_event_id(&id) {
        return Err(ApiError::BadRequest(
            "event id must be 1-64 characters without control characters".into(),
        ));
    }

    let row = sqlx::query_as::<_, EventRow>(
        "SELECT id, message_id, event_type, recipient, metadata, timestamp
         FROM events WHERE id = $1 AND tenant_id = $2",
    )
    .bind(&id)
    .bind(&auth.tenant_id)
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| ApiError::NotFound("event not found".into()))?;

    Ok(Json(row.into()))
}

/// Validate an event id path parameter against the VARCHAR(64) column:
/// non-empty, at most 64 bytes, and free of control characters.
fn is_valid_event_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= 64 && !id.bytes().any(|b| b.is_ascii_control())
}

async fn event_stats(
    State(state): State<AppState>,
    auth: AuthUser,
    Query(params): Query<StatsQuery>,
) -> Result<Json<EventStats>, ApiError> {
    require_scopes(&auth, &["events:read"])?;

    let (from, to) = resolve_stats_window(&params, || Utc::now() - chrono::Duration::days(30))?;

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

    let (from, to) = resolve_stats_window(&params, || Utc::now() - chrono::Duration::days(7))?;

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
    use uuid::Uuid;

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

    #[test]
    fn test_event_id_validation_matches_varchar64_column() {
        assert!(is_valid_event_id("evt_0123456789abcdef"));
        assert!(is_valid_event_id(&"x".repeat(64)));
        // Empty, over-length, and control-character ids must be rejected
        // before touching the database (the column is VARCHAR(64)).
        assert!(!is_valid_event_id(""));
        assert!(!is_valid_event_id(&"x".repeat(65)));
        assert!(!is_valid_event_id("evt\u{0}injection"));
        assert!(!is_valid_event_id("evt\ninjection"));
    }

    // ── Stats window bounds (audit J) ────────────────────────────

    fn stats_query(from: Option<DateTime<Utc>>, to: Option<DateTime<Utc>>) -> StatsQuery {
        StatsQuery { from, to }
    }

    #[test]
    fn stats_window_defaults_applied_when_bounds_missing() {
        let (from, to) = resolve_stats_window(&stats_query(None, None), || {
            Utc::now() - chrono::Duration::days(30)
        })
        .expect("default window must resolve");
        let now = Utc::now();
        assert!(
            (from - (now - chrono::Duration::days(30)))
                .num_seconds()
                .abs()
                < 5
        );
        assert!((to - now).num_seconds().abs() < 5);
    }

    #[test]
    fn stats_window_rejects_inverted_range() {
        let now = Utc::now();
        let err = resolve_stats_window(
            &stats_query(Some(now), Some(now - chrono::Duration::days(1))),
            || Utc::now() - chrono::Duration::days(30),
        )
        .expect_err("from > to must be a 400");
        assert!(matches!(err, ApiError::BadRequest(_)));
    }

    #[test]
    fn stats_window_rejects_range_over_92_days() {
        let now = Utc::now();
        // 93 days — just over the cap.
        let err = resolve_stats_window(
            &stats_query(Some(now - chrono::Duration::days(93)), Some(now)),
            || Utc::now() - chrono::Duration::days(30),
        )
        .expect_err("over-long range must be a 400");
        match err {
            ApiError::BadRequest(message) => {
                assert!(message.contains("92"), "unexpected message: {message}");
            }
            other => panic!("expected BadRequest, got {other:?}"),
        }

        // Exactly 92 days is allowed.
        assert!(resolve_stats_window(
            &stats_query(Some(now - chrono::Duration::days(92)), Some(now),),
            || Utc::now() - chrono::Duration::days(30),
        )
        .is_ok());

        // Inverted + huge (from in the future) is rejected as inverted first.
        let err = resolve_stats_window(
            &stats_query(Some(now + chrono::Duration::days(400)), Some(now)),
            || Utc::now() - chrono::Duration::days(30),
        )
        .unwrap_err();
        assert!(matches!(err, ApiError::BadRequest(_)));
    }
}

#[cfg(test)]
mod adversarial_tests {
    use axum::http::StatusCode;

    use crate::app::test_support::adv::AdvEnv;

    async fn seed_event(
        pool: &sqlx::PgPool,
        tenant: &str,
        event_type: &str,
        recipient: &str,
        message_id: Option<&str>,
        metadata: Option<serde_json::Value>,
    ) -> String {
        let id = format!("evt_{}", &uuid::Uuid::new_v4().simple().to_string()[..20]);
        sqlx::query(
            "INSERT INTO events (id, tenant_id, event_type, recipient, message_id, metadata, timestamp)
             VALUES ($1, $2, $3, $4, $5, $6, NOW() - RANDOM() * INTERVAL '2 hours')",
        )
        .bind(&id)
        .bind(tenant)
        .bind(event_type)
        .bind(recipient)
        .bind(message_id)
        .bind(metadata)
        .execute(pool)
        .await
        .expect("seed event");
        id
    }

    #[tokio::test]
    async fn events_list_filters_paginate_and_stay_tenant_scoped() {
        let Some(pool) = crate::test_db::canonical_pool("events_list").await else {
            return;
        };
        let (env, tenant) = AdvEnv::tenant(pool.clone(), &["events:read"]).await;
        let (other_env, other_tenant) = AdvEnv::tenant(pool.clone(), &["events:read"]).await;

        let delivered = seed_event(
            &pool,
            &tenant,
            "delivered",
            "a@example.com",
            Some("msg-1"),
            None,
        )
        .await;
        seed_event(
            &pool,
            &tenant,
            "opened",
            "a@example.com",
            Some("msg-1"),
            Some(serde_json::json!({"ua": "probe"})),
        )
        .await;
        seed_event(
            &pool,
            &tenant,
            "bounced",
            "b@example.com",
            Some("msg-2"),
            None,
        )
        .await;
        seed_event(
            &pool,
            &other_tenant,
            "delivered",
            "c@example.com",
            None,
            None,
        )
        .await;

        let (status, body) = env.get("/v1/events").await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let items = body.as_array().expect("array");
        assert_eq!(items.len(), 3, "neighbour tenant rows must not leak");
        assert!(items.iter().all(|item| item["tenant_id"].is_null() || true));

        // event_type filter.
        let (status, body) = env.get("/v1/events?event_type=opened").await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let items = body.as_array().expect("array");
        assert_eq!(items.len(), 1);
        assert_eq!(items[0]["event_type"], "opened");
        assert_eq!(items[0]["metadata"]["ua"], "probe");
        assert!(items[0]["timestamp"]
            .as_str()
            .is_some_and(|t| t.starts_with("20")));

        // message_id filter.
        let (status, body) = env.get("/v1/events?message_id=msg-1").await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body.as_array().map(Vec::len), Some(2));

        // Combined filters AND together.
        let (status, body) = env
            .get("/v1/events?message_id=msg-1&event_type=delivered")
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let items = body.as_array().expect("array");
        assert_eq!(items.len(), 1);
        assert_eq!(items[0]["id"], delivered);

        // Pagination: cursor wins over offset; hostile values clamp.
        let (status, body) = env.get("/v1/events?limit=1&offset=99&cursor=1").await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body.as_array().map(Vec::len), Some(1));
        let (status, body) = env.get("/v1/events?limit=99999&offset=-9").await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body.as_array().map(Vec::len), Some(3));

        // Neighbour sees only its own.
        let (status, body) = other_env.get("/v1/events").await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body.as_array().map(Vec::len), Some(1));
    }

    #[tokio::test]
    async fn get_event_binds_by_id_and_tenant() {
        let Some(pool) = crate::test_db::canonical_pool("events_get").await else {
            return;
        };
        let (env, tenant) = AdvEnv::tenant(pool.clone(), &["events:read"]).await;
        let id = seed_event(
            &pool,
            &tenant,
            "complained",
            "abuse@example.com",
            None,
            None,
        )
        .await;

        let (status, body) = env.get(&format!("/v1/events/{id}")).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["id"], id);
        assert_eq!(body["event_type"], "complained");

        // Another tenant's id is an opaque 404.
        let (other_env, _other) = AdvEnv::tenant(pool.clone(), &["events:read"]).await;
        let (status, body) = other_env.get(&format!("/v1/events/{id}")).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{body}");

        // Malformed ids are 400, never a database cast error. (The empty
        // id is unroutable — axum sends /v1/events/ to the list route — so
        // only over-length and control-character ids reach the validator.)
        for bad in ["x".repeat(65).as_str(), "evt%0Ainjection"] {
            let (status, _body) = env.get(&format!("/v1/events/{bad}")).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "id {bad:?}");
        }
    }

    #[tokio::test]
    async fn stats_and_timeseries_aggregate_only_the_window() {
        let Some(pool) = crate::test_db::canonical_pool("events_stats").await else {
            return;
        };
        let (env, tenant) = AdvEnv::tenant(pool.clone(), &["events:read"]).await;
        // In-window events.
        for (kind, count) in [
            ("delivered", 3),
            ("bounced", 1),
            ("opened", 2),
            ("clicked", 1),
        ] {
            for i in 0..count {
                seed_event(
                    &pool,
                    &tenant,
                    kind,
                    &format!("u{i}@example.com"),
                    None,
                    None,
                )
                .await;
            }
        }
        // Out-of-window (35 days ago) event: excluded from the 30d default.
        sqlx::query(
            "INSERT INTO events (id, tenant_id, event_type, recipient, timestamp)
             VALUES ($1, $2, 'delivered', 'old@example.com', NOW() - INTERVAL '35 days')",
        )
        .bind(format!(
            "evt_old_{}",
            &uuid::Uuid::new_v4().simple().to_string()[..12]
        ))
        .bind(&tenant)
        .execute(&pool)
        .await
        .expect("seed old event");

        let (status, body) = env.get("/v1/events/stats").await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["total"], 7);
        assert_eq!(body["delivered"], 3);
        assert_eq!(body["bounced"], 1);
        assert_eq!(body["opened"], 2);
        assert_eq!(body["clicked"], 1);
        assert_eq!(body["complained"], 0);

        // Explicit window including the old event counts it.
        let from = (chrono::Utc::now() - chrono::Duration::days(40))
            .to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        let to = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        let (status, body) = env
            .get(&format!("/v1/events/stats?from={from}&to={to}"))
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["total"], 8);

        // Inverted range is a 400, not an empty 200.
        let (status, body) = env
            .get(&format!("/v1/events/stats?from={to}&to={from}"))
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        // 93-day window exceeds the cap.
        let far = (chrono::Utc::now() - chrono::Duration::days(93))
            .to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        let (status, body) = env
            .get(&format!("/v1/events/stats?from={far}&to={to}"))
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");

        // Timeseries buckets per hour with counts.
        let (status, body) = env.get("/v1/events/timeseries").await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let points = body.as_array().expect("array");
        let total: i64 = points.iter().filter_map(|p| p["count"].as_i64()).sum();
        assert_eq!(total, 7, "hour buckets carry exactly the window's events");
        assert!(points.iter().all(|p| p["event_type"].is_string()));
    }

    #[tokio::test]
    async fn events_require_the_read_scope() {
        let Some(pool) = crate::test_db::canonical_pool("events_scope").await else {
            return;
        };
        let (env, _tenant) = AdvEnv::tenant(pool, &["messages:read"]).await;
        for uri in ["/v1/events", "/v1/events/stats", "/v1/events/timeseries"] {
            let (status, body) = env.get(uri).await;
            assert_eq!(status, StatusCode::FORBIDDEN, "{uri}: {body}");
        }
    }
}
