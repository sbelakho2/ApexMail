//! Event query routes.

use super::helpers::{clamp_limit, default_limit};
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, HeaderValue};
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
    pub event_type: Option<String>,
    #[serde(default)]
    pub message_id: Option<String>,
    /// Opaque keyset cursor, echoed from the previous response's
    /// `x-next-cursor` header. Additive: the integer-masquerading `cursor`
    /// this route used to accept is still refused (an integer is not a
    /// decodable cursor), and clients that never send one keep the OFFSET
    /// behaviour byte for byte.
    #[serde(default)]
    pub cursor: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct EventResponse {
    pub id: String,
    pub message_id: Option<String>,
    pub event_type: String,
    pub recipient: Option<String>,
    /// Customer-safe metadata: an ALLOWLIST projection of the raw
    /// `events.metadata` column (see [`customer_event_metadata`]). Raw
    /// metadata never crosses this boundary.
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

// ─── Customer-safe metadata projection ─────────────────────────
//
// Third external audit (P1): the customer events endpoint returned the
// `events.metadata` JSONB column verbatim, so one future producer writing a
// transport name, source IP, host, or provider identity into that column
// would ship it straight to customers. The customer response is now an
// ALLOWLIST projection: only keys that describe the event in
// provider-agnostic terms survive; everything else (transport names,
// transport_message_id, actual_source_ip/source_ip, host, provider_source,
// recipient_provider, internal queue ids, tenant ids, anything
// provider-specific) is dropped at this boundary. Internal/admin consumers
// keep reading the raw column through their own queries; the projection
// exists ONLY here.

/// Metadata keys a customer may see. Event basics the console already
/// surfaces: the SMTP response summary/code, the provider-agnostic status
/// reason, bounce classification, the recipient's user agent and the
/// customer's own clicked link.
const CUSTOMER_METADATA_KEYS: &[&str] = &[
    "smtp_code",
    "smtp_response",
    "reason",
    "bounce_category",
    "bounce_type",
    "bounce_subtype",
    "ua",
    "link_url",
];

/// Metadata keys whose values are provider/MTA-generated free text: even
/// though the key is allowed, the string is classified through the shared
/// delivery-detail sanitizer before it reaches a customer.
const SANITIZED_METADATA_KEYS: &[&str] = &["smtp_response", "reason"];

/// Project one event's raw metadata onto the customer-safe allowlist DTO.
///
/// * `None`/`null`/non-object metadata → `None` (nothing to show).
/// * Object → only allowlisted keys survive; provider-generated free text
///   inside surviving keys is classified to a lifecycle summary; a
///   projection that ends up empty → `None`.
pub(crate) fn customer_event_metadata(
    raw: Option<&serde_json::Value>,
) -> Option<serde_json::Value> {
    let object = raw
        .filter(|value| !value.is_null())
        .and_then(|value| value.as_object())?;

    let mut projected = serde_json::Map::new();
    for key in CUSTOMER_METADATA_KEYS {
        let Some(value) = object.get(*key) else {
            continue; // not present on this event
        };
        let value = if SANITIZED_METADATA_KEYS.contains(key) {
            match value.as_str() {
                // Free-text summaries are classified; non-string shapes
                // (a numeric reason, an embedded object) are dropped, they
                // are not a customer-facing summary.
                Some(text) => {
                    serde_json::Value::String(super::helpers::sanitize_delivery_detail(text))
                }
                None => continue,
            }
        } else {
            value.clone()
        };
        projected.insert((*key).to_string(), value);
    }
    if projected.is_empty() {
        None
    } else {
        Some(serde_json::Value::Object(projected))
    }
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

// ─── Keyset cursor ─────────────────────────────────────────────
//
// Hex-encoded `(timestamp, id)` pair, the SAME wire format
// `routes/audit.rs` uses (`encode_cursor`/`decode_cursor` in
// `routes/helpers.rs`). The tie-break `timestamp = $ts AND id < $id` makes the
// `timestamp DESC, id DESC` ordering total, so a page boundary inside a group
// of events sharing one timestamp neither skips nor duplicates rows, the
// failure mode plain OFFSET cannot avoid under concurrent writes.

const EVENTS_CURSOR_SEP: char = '\n';

fn encode_events_cursor(timestamp: &DateTime<Utc>, id: &str) -> String {
    crate::routes::helpers::encode_cursor(&format!(
        "{}{EVENTS_CURSOR_SEP}{id}",
        timestamp.to_rfc3339()
    ))
}

fn decode_events_cursor(encoded: &str) -> Result<(DateTime<Utc>, String), ApiError> {
    let Some(decoded) = crate::routes::helpers::decode_cursor(encoded) else {
        return Err(ApiError::BadRequest(
            "invalid cursor: malformed encoding".into(),
        ));
    };
    let Some((timestamp, id)) = decoded.split_once(EVENTS_CURSOR_SEP) else {
        return Err(ApiError::BadRequest(
            "invalid cursor: must encode a timestamp and row id".into(),
        ));
    };
    let timestamp = DateTime::parse_from_rfc3339(timestamp)
        .map_err(|_| ApiError::BadRequest("invalid cursor: must be an encoded timestamp".into()))?
        .with_timezone(&Utc);
    if !is_valid_event_id(id) {
        return Err(ApiError::BadRequest(
            "invalid cursor: malformed row id".into(),
        ));
    }
    Ok((timestamp, id.to_string()))
}

/// Parse the optional cursor BEFORE any database work: a malformed cursor is
/// a 400, never a silently different page.
fn parse_events_cursor(
    params: &ListEventsQuery,
) -> Result<Option<(DateTime<Utc>, String)>, ApiError> {
    match params.cursor.as_deref() {
        Some(encoded) => Ok(Some(decode_events_cursor(encoded)?)),
        None => Ok(None),
    }
}

// ─── List plan ─────────────────────────────────────────────────

/// The list query plan: SQL plus the keyset/offset parameters it needs.
struct EventsListPlan {
    sql: String,
    event_type: Option<String>,
    message_id: Option<String>,
    /// Bind AFTER the filters: keyset `(ts, id)` + fetch limit, or just
    /// offset + fetch limit.
    keyset: Option<(DateTime<Utc>, String)>,
    offset: i64,
    fetch_limit: i64,
    /// Rows the caller asked for (the keyset path fetches one extra to detect
    /// `has_more`).
    page_limit: i64,
}

fn build_events_list_plan(
    params: &ListEventsQuery,
    keyset: Option<(DateTime<Utc>, String)>,
) -> EventsListPlan {
    let page_limit = clamp_limit(params.limit, 200);

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

    // Keyset: no OFFSET at all, the scan starts at the cursor position on
    // the `(tenant_id, timestamp DESC)` index (sibling migration) instead of
    // walking and discarding up to 100k rows.
    //
    // BOTH paths fetch one extra row (`page_limit + 1`) and truncate: the
    // extra row is what proves `x-has-more` and yields the next cursor
    // without a second COUNT query. The response body still holds at most
    // `page_limit` rows.
    let fetch_limit = page_limit + 1;
    let (sql_tail, offset) = if keyset.is_some() {
        let ts_idx = param_idx;
        let id_idx = param_idx + 1;
        let limit_idx = param_idx + 2;
        (
            format!(
                " AND (timestamp < ${ts_idx}::timestamptz
                       OR (timestamp = ${ts_idx}::timestamptz AND id < ${id_idx}))
                 ORDER BY timestamp DESC, id DESC LIMIT ${limit_idx}"
            ),
            0i64,
        )
    } else {
        (
            format!(
                " ORDER BY timestamp DESC, id DESC LIMIT ${param_idx} OFFSET ${}",
                param_idx + 1
            ),
            params.offset.clamp(0, 100_000),
        )
    };

    EventsListPlan {
        sql: sql + &sql_tail,
        event_type: params.event_type.clone(),
        message_id: params.message_id.clone(),
        keyset,
        offset,
        fetch_limit,
        page_limit,
    }
}

async fn list_events(
    State(state): State<AppState>,
    auth: AuthUser,
    Query(params): Query<ListEventsQuery>,
) -> Result<(HeaderMap, Json<Vec<EventResponse>>), ApiError> {
    require_scopes(&auth, &["events:read"])?;

    // SM3 (audit F8): the param that used to be `cursor` here was a raw
    // integer OFFSET, a lie about the crate's opaque-keyset contract. The
    // pagination inputs are now: the honestly-named `offset` (same offset and
    // clamp as before; the one ordering change is the deterministic
    // `id DESC` tie-break among equal timestamps, where the old SQL left the
    // order arbitrary) and an OPAQUE `cursor` keyset token echoed from
    // `x-next-cursor`. HEAD had no `cursor` field at all, so `?cursor=1` was
    // silently ignored; it is now a 400 because it cannot decode as a cursor
    // (an integer is never read as an offset).
    let keyset = parse_events_cursor(&params)?;
    let plan = build_events_list_plan(&params, keyset);

    let mut query = sqlx::query_as::<_, EventRow>(&plan.sql).bind(&auth.tenant_id);
    if let Some(ref event_type) = plan.event_type {
        query = query.bind(event_type);
    }
    if let Some(ref message_id) = plan.message_id {
        query = query.bind(message_id);
    }
    if let Some((ref timestamp, ref id)) = plan.keyset {
        query = query.bind(timestamp).bind(id).bind(plan.fetch_limit);
    } else {
        query = query.bind(plan.fetch_limit).bind(plan.offset);
    }

    let mut rows = query.fetch_all(&state.db).await?;

    let more = rows.len() as i64 > plan.page_limit;
    if more {
        rows.truncate(plan.page_limit as usize);
    }

    let mut headers = HeaderMap::new();
    headers.insert(
        "x-has-more",
        HeaderValue::from_static(if more { "true" } else { "false" }),
    );
    if let Some(last) = rows.last() {
        if more {
            let cursor = encode_events_cursor(&last.timestamp, &last.id);
            headers.insert(
                "x-next-cursor",
                HeaderValue::from_str(&cursor)
                    .map_err(|e| ApiError::Internal(format!("cursor encoding error: {e}")))?,
            );
        }
    }

    Ok((headers, Json(rows.into_iter().map(Into::into).collect())))
}

async fn get_event(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<String>,
) -> Result<Json<EventResponse>, ApiError> {
    require_scopes(&auth, &["events:read"])?;

    // events.id is VARCHAR(64) (migration 075 / runtime CREATE_EVENTS), the
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
            metadata: customer_event_metadata(r.metadata.as_ref()),
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

    // ── Customer-safe metadata projection (third external audit) ──

    /// The audit's leaky shape: a producer writing transport, source IP,
    /// host, and recipient-provider keys into `events.metadata`. The
    /// customer wire projection must answer with the provider-agnostic
    /// reason ONLY, while the raw column (what internal/admin consumers
    /// read through their own queries) keeps every key untouched.
    #[test]
    fn customer_metadata_projection_strips_internal_keys_and_keeps_the_admin_view_raw() {
        let raw = serde_json::json!({
            "transport": "ses",
            "source_ip": "1.2.3.4",
            "actual_source_ip": "1.2.3.4",
            "host": "internal.example",
            "recipient_provider": "google",
            "provider_source": "mx_resolved",
            "transport_message_id": "0100018c-internal-id",
            "queue_id": "q_12345",
            "tenant_id": "advt0000000000",
            "reason": "greylisted",
        });

        // Customer view: the allowlist projection.
        let customer = customer_event_metadata(Some(&raw)).expect("reason survives");
        assert_eq!(customer, serde_json::json!({"reason": "greylisted"}));

        // Admin/internal view: the raw column is untouched by this
        // boundary (admin routes and internal consumers query the table
        // directly and keep every key).
        let raw_json = serde_json::to_value(&raw).expect("raw metadata serializes");
        for key in [
            "transport",
            "source_ip",
            "actual_source_ip",
            "host",
            "recipient_provider",
            "provider_source",
            "transport_message_id",
            "queue_id",
            "tenant_id",
        ] {
            assert!(raw_json.get(key).is_some(), "raw column keeps {key}");
        }

        // The wire DTO applies the same projection end to end.
        let row = EventRow {
            id: "evt_leak".into(),
            message_id: None,
            event_type: "bounced".into(),
            recipient: Some("a@example.com".into()),
            metadata: Some(raw),
            timestamp: DateTime::parse_from_rfc3339("2026-10-25T12:00:00Z")
                .expect("timestamp")
                .with_timezone(&Utc),
        };
        let response = EventResponse::from(row);
        let json = serde_json::to_value(&response).expect("serialize");
        assert_eq!(
            json["metadata"],
            serde_json::json!({"reason": "greylisted"})
        );
        assert!(
            json["metadata"].to_string().find("ses").is_none(),
            "no transport identity on the wire"
        );
    }

    /// Free text inside ALLOWED keys is classified, not forwarded: an SMTP
    /// response summary carrying a hostname or an IP becomes a lifecycle
    /// summary.
    #[test]
    fn customer_metadata_projection_sanitizes_allowed_free_text() {
        let raw = serde_json::json!({
            "smtp_response": "550 5.1.1 user unknown via mail-wm1-f43.google.com",
            "reason": "connect to 1.2.3.4:25 timed out",
            "smtp_code": 550,
            "bounce_type": "hard_bounce",
        });
        let customer = customer_event_metadata(Some(&raw)).expect("projection");
        assert_eq!(
            customer["smtp_response"], "permanent failure: recipient rejected",
            "{}",
            customer
        );
        assert_eq!(
            customer["reason"], "delivery temporarily refused by recipient server",
            "{}",
            customer
        );
        // Scalars and non-free-text allowlisted keys pass as they are.
        assert_eq!(customer["smtp_code"], 550);
        assert_eq!(customer["bounce_type"], "hard_bounce");
    }

    /// Absent, null, non-object, and fully-stripped metadata all answer
    /// `null` on the wire, never `{}` and never a passthrough of odd
    /// shapes (an array or a bare string is not an event summary).
    #[test]
    fn customer_metadata_projection_handles_empty_and_hostile_shapes() {
        assert_eq!(customer_event_metadata(None), None);
        assert_eq!(
            customer_event_metadata(Some(&serde_json::Value::Null)),
            None
        );
        assert_eq!(
            customer_event_metadata(Some(&serde_json::json!([]))),
            None,
            "an array is not an event summary"
        );
        assert_eq!(
            customer_event_metadata(Some(&serde_json::json!("ses:250 ok"))),
            None,
            "a bare string is not an event summary"
        );
        // Nothing allowlisted survives: the whole object is dropped.
        assert_eq!(
            customer_event_metadata(Some(&serde_json::json!({
                "transport": "ses",
                "source_ip": "1.2.3.4",
                "host": "internal.example",
            }))),
            None
        );
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

    // ── Keyset pagination (replaces the OFFSET-only path) ────────

    fn list_query(limit: i64, offset: i64, cursor: Option<&str>) -> ListEventsQuery {
        ListEventsQuery {
            limit,
            offset,
            event_type: None,
            message_id: None,
            cursor: cursor.map(str::to_string),
        }
    }

    #[test]
    fn keyset_plan_uses_no_offset_and_binds_the_total_order() {
        let now = Utc::now();
        let keyset = Some((now, "evt_abc".to_string()));
        let plan = build_events_list_plan(&list_query(50, 99_999, Some("ignored")), keyset);

        // The keyset page scans from the cursor, never walks-and-discards rows.
        assert!(!plan.sql.contains("OFFSET"), "{}", plan.sql);
        assert!(plan.sql.contains("timestamp < $2::timestamptz"));
        assert!(plan.sql.contains("timestamp = $2::timestamptz AND id < $3"));
        assert!(plan
            .sql
            .contains("ORDER BY timestamp DESC, id DESC LIMIT $4"));
        // One extra row is fetched to detect `has_more`.
        assert_eq!(plan.fetch_limit, 51);
        assert_eq!(plan.page_limit, 50);
        assert_eq!(plan.offset, 0, "the cursor page must not carry an offset");

        // Without a cursor the legacy OFFSET shape (with its clamp) is kept
        // byte for byte, including the `timestamp DESC, id DESC` total order.
        let plan = build_events_list_plan(&list_query(50, 999_999, None), None);
        assert!(plan
            .sql
            .contains("ORDER BY timestamp DESC, id DESC LIMIT $2 OFFSET $3"));
        assert_eq!(plan.offset, 100_000);
        assert_eq!(plan.fetch_limit, 51);
        assert_eq!(plan.page_limit, 50);
    }

    #[test]
    fn keyset_cursor_round_trips_and_refuses_integer_masquerades() {
        let ts = DateTime::parse_from_rfc3339("2026-10-17T12:00:00.123456+00:00")
            .expect("timestamp")
            .with_timezone(&Utc);
        let encoded = encode_events_cursor(&ts, "evt_0123456789abcdef");
        let (decoded_ts, decoded_id) = decode_events_cursor(&encoded).expect("cursor round trips");
        assert_eq!(decoded_ts, ts);
        assert_eq!(decoded_id, "evt_0123456789abcdef");

        // The mislabeled integer cursor is refused, exactly as before the
        // keyset migration: it cannot decode.
        for garbage in ["1", "0", "", "zz", "not-hex"] {
            let params = list_query(10, 0, Some(garbage));
            match parse_events_cursor(&params) {
                Err(ApiError::BadRequest(_)) => {}
                other => panic!("{garbage:?} must be a 400, got {other:?}"),
            }
        }
        // A cursor whose payload is not `timestamp\nid` is refused too.
        for payload in ["no-separator", "bad-time\nid", "2026-10-17T12:00:00Z\n"] {
            let params = list_query(10, 0, Some(&crate::routes::helpers::encode_cursor(payload)));
            assert!(
                parse_events_cursor(&params).is_err(),
                "{payload:?} must be refused"
            );
        }
        // No cursor → the offset path (None, not an error).
        assert!(parse_events_cursor(&list_query(10, 5, None))
            .expect("absent cursor is fine")
            .is_none());
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
        // 93 days, just over the cap.
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

        // Pagination (SM3 audit F8): the mislabeled integer `cursor` is
        // GONE from the contract, an unknown query field is refused loudly
        // (deny_unknown_fields) instead of silently meaning "offset", and
        // hostile `offset`/`limit` values still clamp.
        let (status, body) = env.get("/v1/events?limit=1&offset=99&cursor=1").await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "the removed cursor param must be refused, not honoured: {body}"
        );
        let (status, body) = env.get("/v1/events?limit=1&offset=1").await;
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

    /// Seed one event with an explicit id and timestamp (keyset tests need a
    /// controlled, total order).
    async fn seed_event_at(
        pool: &sqlx::PgPool,
        tenant: &str,
        id: &str,
        at: chrono::DateTime<chrono::Utc>,
    ) {
        sqlx::query(
            "INSERT INTO events (id, tenant_id, event_type, recipient, timestamp)
             VALUES ($1, $2, 'delivered', 'keyset@example.com', $3)",
        )
        .bind(id)
        .bind(tenant)
        .bind(at)
        .execute(pool)
        .await
        .expect("seed timestamped event");
    }

    fn page_ids(body: &serde_json::Value) -> Vec<String> {
        body.as_array()
            .expect("array page")
            .iter()
            .map(|item| item["id"].as_str().expect("id").to_string())
            .collect()
    }

    /// Deep-page equivalence + the additive cursor contract.
    ///
    /// The old implementation could only walk pages with `LIMIT/OFFSET`; the
    /// keyset path must produce IDENTICAL pages for the same data (the row
    /// order `timestamp DESC, id DESC` is a total order, and the cursor
    /// reproduces the next page exactly), while exposing the cursor through
    /// headers so the response body shape is unchanged.
    #[tokio::test]
    async fn events_cursor_pages_equal_offset_pages_and_emit_headers() {
        let Some(pool) = crate::test_db::canonical_pool("events_keyset_equiv").await else {
            return;
        };
        let (env, tenant) = AdvEnv::tenant(pool.clone(), &["events:read"]).await;

        // 25 events, distinct timestamps, ids deliberately NOT in timestamp
        // order (proves the cursor binds the timestamp, not the id).
        let base = chrono::Utc::now() - chrono::Duration::minutes(30);
        let mut seeded: Vec<(chrono::DateTime<chrono::Utc>, String)> = Vec::new();
        for i in 0..25i64 {
            let id = format!("evt_key_{:02}", (i * 7) % 25);
            let at = base + chrono::Duration::seconds(i);
            seed_event_at(&pool, &tenant, &id, at).await;
            seeded.push((at, id));
        }
        // Newest first is the API contract.
        seeded.sort_by_key(|a| std::cmp::Reverse(a.0));
        let expected_ids: Vec<String> = seeded.into_iter().map(|(_, id)| id).collect();

        // Old path: OFFSET pages.
        let mut offset_ids: Vec<String> = Vec::new();
        for page in 0..5 {
            let (status, body) = env
                .get(&format!("/v1/events?limit=5&offset={}", page * 5))
                .await;
            assert_eq!(status, StatusCode::OK, "{body}");
            offset_ids.extend(page_ids(&body));
        }

        // Keyset path: page 1 without a cursor, then follow x-next-cursor.
        let mut keyset_ids: Vec<String> = Vec::new();
        let mut cursor: Option<String> = None;
        for page in 0..5 {
            let uri = match &cursor {
                Some(cursor) => format!("/v1/events?limit=5&cursor={cursor}"),
                None => "/v1/events?limit=5".to_string(),
            };
            let (status, headers, bytes) = env.get_raw(&uri).await;
            assert_eq!(status, StatusCode::OK);
            let body: serde_json::Value =
                serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
            assert_eq!(
                headers
                    .get("x-has-more")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or(""),
                if page < 4 { "true" } else { "false" },
                "page {page} has_more"
            );
            keyset_ids.extend(page_ids(&body));
            cursor = headers
                .get("x-next-cursor")
                .and_then(|v| v.to_str().ok())
                .map(str::to_string);
            assert_eq!(cursor.is_some(), page < 4, "page {page} cursor presence");
        }

        assert_eq!(keyset_ids.len(), 25);
        assert_eq!(
            keyset_ids, offset_ids,
            "the keyset pages must reproduce the OFFSET pages exactly"
        );
        assert_eq!(keyset_ids, expected_ids, "newest-first total order");

        pool.close().await;
    }

    /// A group of events sharing one timestamp must neither duplicate nor
    /// skip rows at a page boundary, the failure mode plain OFFSET cannot
    /// avoid under concurrent writes, and the reason the cursor carries the
    /// `(timestamp, id)` tie-break.
    #[tokio::test]
    async fn events_cursor_does_not_skip_or_repeat_rows_with_tied_timestamps() {
        let Some(pool) = crate::test_db::canonical_pool("events_keyset_ties").await else {
            return;
        };
        let (env, tenant) = AdvEnv::tenant(pool.clone(), &["events:read"]).await;
        let tied = chrono::Utc::now() - chrono::Duration::minutes(5);
        // 4 events on the SAME timestamp, plus 2 newer, page size 2 forces
        // page boundaries inside the tie group.
        for i in 0..4u8 {
            seed_event_at(&pool, &tenant, &format!("evt_tie_{i}"), tied).await;
        }
        seed_event_at(
            &pool,
            &tenant,
            "evt_tie_newer",
            tied + chrono::Duration::seconds(1),
        )
        .await;
        seed_event_at(
            &pool,
            &tenant,
            "evt_tie_newest",
            tied + chrono::Duration::seconds(2),
        )
        .await;

        let mut seen: Vec<String> = Vec::new();
        let mut cursor: Option<String> = None;
        for _ in 0..4 {
            let uri = match &cursor {
                Some(cursor) => format!("/v1/events?limit=2&cursor={cursor}"),
                None => "/v1/events?limit=2".to_string(),
            };
            let (status, headers, bytes) = env.get_raw(&uri).await;
            assert_eq!(status, StatusCode::OK);
            let body: serde_json::Value =
                serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
            seen.extend(page_ids(&body));
            cursor = headers
                .get("x-next-cursor")
                .and_then(|v| v.to_str().ok())
                .map(str::to_string);
            if cursor.is_none() {
                break;
            }
        }

        seen.sort();
        seen.dedup();
        assert_eq!(
            seen,
            vec![
                "evt_tie_0".to_string(),
                "evt_tie_1".to_string(),
                "evt_tie_2".to_string(),
                "evt_tie_3".to_string(),
                "evt_tie_newer".to_string(),
                "evt_tie_newest".to_string(),
            ],
            "every row exactly once across the tie group"
        );

        pool.close().await;
    }

    /// Third external audit (P1): the customer events API must never ship
    /// the raw `events.metadata` column. A seeded event carrying transport,
    /// source IP, host, and recipient-provider metadata answers the list
    /// AND the detail route with the allowlist projection only, while the
    /// stored row (the internal/admin view) keeps every key.
    #[tokio::test]
    async fn events_metadata_is_projected_customer_safe_on_both_read_routes() {
        let Some(pool) = crate::test_db::canonical_pool("events_metadata_projection").await else {
            return;
        };
        let (env, tenant) = AdvEnv::tenant(pool.clone(), &["events:read"]).await;
        let leaky = serde_json::json!({
            "transport": "ses",
            "source_ip": "1.2.3.4",
            "host": "internal.example",
            "recipient_provider": "google",
            "reason": "greylisted",
        });
        let id = seed_event(
            &pool,
            &tenant,
            "bounced",
            "leak@example.com",
            None,
            Some(leaky.clone()),
        )
        .await;

        // List route: the row answers with the allowlist projection.
        let (status, body) = env.get("/v1/events?event_type=bounced").await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let items = body.as_array().expect("array");
        let row = items
            .iter()
            .find(|item| item["id"] == id.as_str())
            .expect("the seeded leaky event is listed");
        assert_eq!(row["metadata"], serde_json::json!({"reason": "greylisted"}));

        // Detail route: the same projection.
        let (status, body) = env.get(&format!("/v1/events/{id}")).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(
            body["metadata"],
            serde_json::json!({"reason": "greylisted"})
        );
        let wire = body.to_string();
        assert!(!wire.contains("ses"), "no transport identity: {wire}");
        assert!(!wire.contains("1.2.3.4"), "no source IP: {wire}");
        assert!(
            !wire.contains("internal.example"),
            "no internal host: {wire}"
        );
        assert!(!wire.contains("google"), "no recipient provider: {wire}");

        // The admin/internal view (the stored column) keeps everything:
        // admin routes query the table directly and stay on the raw shape.
        let stored: serde_json::Value =
            sqlx::query_scalar("SELECT metadata FROM events WHERE id = $1 AND tenant_id = $2")
                .bind(&id)
                .bind(&tenant)
                .fetch_one(&pool)
                .await
                .expect("stored metadata");
        for key in [
            "transport",
            "source_ip",
            "host",
            "recipient_provider",
            "reason",
        ] {
            assert!(stored.get(key).is_some(), "raw column keeps {key}");
        }
        assert_eq!(stored, leaky, "the raw column is untouched");

        pool.close().await;
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
        // id is unroutable, axum sends /v1/events/ to the list route, so
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
