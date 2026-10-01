//! Audit log viewer endpoints.
//!

use axum::extract::{Query, State};
use axum::routing::get;
use axum::{Json, Router};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

use crate::error::ApiError;
use crate::middleware::auth::AuthUser;
use crate::routes::helpers::{decode_cursor, encode_cursor};
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/", get(list_audit_logs))
        // Full-text search + CSV export over the same audit logs. Mounted here
        // (rather than as a separate nest in app.rs) so the whole audit family
        // is reachable through the single `/v1/admin/audit` nest.
        .merge(super::audit_search::router())
}

// ─── Keyset cursor helpers ─────────────────────────────────────
//
// The list cursor encodes the `(timestamp, id)` pair of the last row of the
// previous page. A timestamp alone skips or duplicates rows that share a
// `timestamp` value (bulk audit writes do this constantly): the tie-break
// `timestamp = $ts AND id < $id` makes the `timestamp DESC, id DESC`
// ordering total.

/// Separator between the RFC3339 timestamp and the row id inside the
/// hex-encoded cursor payload (RFC3339 and audit ids never contain it).
const KEYSET_CURSOR_SEP: char = '\n';

/// Encode a `(timestamp, id)` keyset cursor as an opaque hex string.
///
/// The timestamp MUST be rendered with `to_rfc3339()`: `DateTime`'s
/// `Display` emits "2026-01-01 00:00:00 UTC", which
/// [`decode_audit_cursor`]'s `parse_from_rfc3339` rejects — a cursor this
/// function minted would fail its very next request with 400.
fn encode_audit_cursor(timestamp: &DateTime<Utc>, id: &str) -> String {
    encode_cursor(&format!(
        "{}{KEYSET_CURSOR_SEP}{id}",
        timestamp.to_rfc3339()
    ))
}

/// Decode and validate a `(timestamp, id)` keyset cursor. Malformed
/// encodings, unparsable timestamps, or ids that cannot name an audit row
/// are client errors (400) — an unvalidated cursor could otherwise surface
/// as a database error. audit_logs.id is TEXT; the writers produce
/// identifier-shaped ids (UUID text and short prefixed forms), so the id is
/// bounded and restricted to ASCII identifier characters — SQL
/// metacharacters are refused at the boundary even though every use binds
/// the value as a parameter.
fn decode_audit_cursor(encoded: &str) -> Result<(DateTime<Utc>, String), ApiError> {
    let Some(decoded) = decode_cursor(encoded) else {
        return Err(ApiError::BadRequest(
            "invalid cursor: malformed encoding".into(),
        ));
    };
    let Some((timestamp, id)) = decoded.split_once(KEYSET_CURSOR_SEP) else {
        return Err(ApiError::BadRequest(
            "invalid cursor: must encode a timestamp and row id".into(),
        ));
    };
    let timestamp = chrono::DateTime::parse_from_rfc3339(timestamp)
        .map_err(|_| ApiError::BadRequest("invalid cursor: must be an encoded timestamp".into()))?
        .with_timezone(&Utc);
    if id.is_empty()
        || id.len() > 128
        || !id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b':'))
    {
        return Err(ApiError::BadRequest(
            "invalid cursor: malformed row id".into(),
        ));
    }
    Ok((timestamp, id.to_string()))
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
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
    /// Opaque keyset cursor (hex-encoded `timestamp\nid` pair) returned as
    /// the `x-next-cursor` response header of the previous page. When
    /// present it wins over `offset`.
    #[serde(default)]
    pub cursor: Option<String>,
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

#[derive(Debug)]
struct AuditQueryPlan {
    sql: String,
    bind_values: Vec<String>,
    window_start: DateTime<Utc>,
    window_end: DateTime<Utc>,
    limit: i64,
    offset: i64,
    /// Decoded keyset cursor. When present it wins over `offset`: the SQL
    /// carries a `(timestamp, id)` strictly-less tuple predicate and no
    /// OFFSET clause at all.
    keyset: Option<(DateTime<Utc>, String)>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AuditFilterColumn {
    Action,
    TenantId,
    UserId,
    Resource,
    Outcome,
}

impl AuditFilterColumn {
    fn predicate(self, param_idx: u32) -> String {
        match self {
            Self::Action => format!("action = ${param_idx}"),
            Self::TenantId => format!("tenant_id = ${param_idx}"),
            Self::UserId => format!("user_id = ${param_idx}"),
            // audit_logs (migration 038) stores the affected entity in the
            // `resource` column and the result in `outcome` — the old
            // resource_type/metadata predicates targeted nonexistent columns.
            Self::Resource => format!("resource = ${param_idx}"),
            Self::Outcome => format!("outcome = ${param_idx}"),
        }
    }
}

fn push_audit_filter(
    conditions: &mut Vec<String>,
    bind_values: &mut Vec<String>,
    param_idx: &mut u32,
    column: AuditFilterColumn,
    value: &str,
) {
    conditions.push(column.predicate(*param_idx));
    *param_idx += 1;
    bind_values.push(value.to_string());
}

fn build_audit_query_plan(
    params: &AuditListQuery,
    now: DateTime<Utc>,
) -> Result<AuditQueryPlan, ApiError> {
    let limit = params.limit.clamp(1, 200);
    let offset = params.offset.max(0);
    let (window_start, window_end) =
        resolve_audit_window(params.from.as_deref(), params.to.as_deref(), now)?;
    // A cursor wins over offset. Both halves are validated BEFORE binding —
    // a bogus cursor must be a client 400, never a database cast error.
    let keyset = match params.cursor.as_deref() {
        Some(encoded) => Some(decode_audit_cursor(encoded)?),
        None => None,
    };

    let mut conditions: Vec<String> = vec!["timestamp >= $1".into(), "timestamp <= $2".into()];
    let mut param_idx = 3u32;
    let mut bind_values: Vec<String> = Vec::new();

    if let Some(ref action) = params.action {
        push_audit_filter(
            &mut conditions,
            &mut bind_values,
            &mut param_idx,
            AuditFilterColumn::Action,
            action,
        );
    }
    if let Some(ref tenant_id) = params.tenant_id {
        push_audit_filter(
            &mut conditions,
            &mut bind_values,
            &mut param_idx,
            AuditFilterColumn::TenantId,
            tenant_id,
        );
    }
    if let Some(ref user_id) = params.user_id {
        push_audit_filter(
            &mut conditions,
            &mut bind_values,
            &mut param_idx,
            AuditFilterColumn::UserId,
            user_id,
        );
    }
    if let Some(ref resource_type) = params.resource_type {
        push_audit_filter(
            &mut conditions,
            &mut bind_values,
            &mut param_idx,
            AuditFilterColumn::Resource,
            resource_type,
        );
    }
    if let Some(ref status) = params.status {
        push_audit_filter(
            &mut conditions,
            &mut bind_values,
            &mut param_idx,
            AuditFilterColumn::Outcome,
            status,
        );
    }

    let where_clause = format!("WHERE {}", conditions.join(" AND "));
    // Keyset path: strictly-less tuple comparison over the same
    // (timestamp, id) tuple the ORDER BY uses — the tuple the
    // idx_audit_logs_tenant_ts index shape supports. The value is cast once
    // (`$k::timestamptz`), never the indexed column.
    let sql = if keyset.is_some() {
        let ts_idx = param_idx;
        let id_idx = param_idx + 1;
        let limit_idx = param_idx + 2;
        format!(
            "SELECT id, timestamp, action, resource, resource_id,
                    user_id, tenant_id, ip_address, user_agent, details
             FROM audit_logs
             {where_clause}
               AND (timestamp < ${ts_idx}::timestamptz
                    OR (timestamp = ${ts_idx}::timestamptz AND id < ${id_idx}))
             ORDER BY timestamp DESC, id DESC
             LIMIT ${limit_idx}"
        )
    } else {
        format!(
            "SELECT id, timestamp, action, resource, resource_id,
                    user_id, tenant_id, ip_address, user_agent, details
             FROM audit_logs
             {where_clause}
             ORDER BY timestamp DESC, id DESC
             LIMIT ${param_idx} OFFSET ${}",
            param_idx + 1
        )
    };

    Ok(AuditQueryPlan {
        sql,
        bind_values,
        window_start,
        window_end,
        limit,
        offset,
        keyset,
    })
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

/// List audit logs.
///
/// The response body stays a bare JSON array (pinned by existing clients);
/// the keyset continuation rides ADDITIVE response headers:
///
/// * `x-has-more` — `"true"` when a further page exists;
/// * `x-next-cursor` — opaque keyset cursor (hex `(timestamp, id)` of the
///   last returned row) to pass back as `?cursor=`. Present whenever the
///   page is non-empty.
///
/// `offset` keeps working exactly as before; `cursor` wins when both are
/// supplied.
async fn list_audit_logs(
    State(state): State<AppState>,
    auth: AuthUser,
    Query(params): Query<AuditListQuery>,
) -> Result<(axum::http::HeaderMap, Json<Vec<AuditLogEntry>>), ApiError> {
    crate::middleware::auth::require_scopes(&auth, &["*"])?;
    crate::middleware::auth::require_system_tenant(&state, &auth).await?;

    let query_plan = build_audit_query_plan(&params, Utc::now())?;

    let fetch_limit = query_plan.limit + 1; // one extra row to detect has_more

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
    >(&query_plan.sql);

    query = query
        .bind(query_plan.window_start)
        .bind(query_plan.window_end);

    for val in &query_plan.bind_values {
        query = query.bind(val);
    }
    if let Some((ref ts, ref id)) = query_plan.keyset {
        query = query.bind(ts).bind(id).bind(fetch_limit);
    } else {
        query = query.bind(fetch_limit).bind(query_plan.offset);
    }

    let rows = query.fetch_all(&state.db).await?;

    let more = rows.len() as i64 > query_plan.limit;
    let kept = if more {
        query_plan.limit as usize
    } else {
        rows.len()
    };

    // The next cursor is the (timestamp, id) tuple of the last KEPT row —
    // the exact position this page stopped at.
    let next_cursor = if kept > 0 {
        let last = &rows[kept - 1];
        Some(encode_audit_cursor(&last.1, &last.0))
    } else {
        None
    };

    let entries: Vec<AuditLogEntry> = rows
        .into_iter()
        .take(kept)
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

    let mut headers = axum::http::HeaderMap::new();
    headers.insert(
        "x-has-more",
        axum::http::HeaderValue::from_static(if more { "true" } else { "false" }),
    );
    if let Some(cursor) = next_cursor {
        headers.insert(
            "x-next-cursor",
            axum::http::HeaderValue::from_str(&cursor)
                .map_err(|e| ApiError::Internal(format!("cursor encoding error: {e}")))?,
        );
    }

    Ok((headers, Json(entries)))
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

    #[test]
    fn keyset_cursor_decode_rejects_every_malformed_shape() {
        // Not even hex.
        assert!(matches!(
            decode_audit_cursor("zz"),
            Err(ApiError::BadRequest(message)) if message.contains("malformed encoding")
        ));
        // Valid hex, no separator.
        assert!(matches!(
            decode_audit_cursor(&encode_cursor("no-separator-here")),
            Err(ApiError::BadRequest(message)) if message.contains("timestamp and row id")
        ));
        // Bad RFC3339 timestamp.
        let bad_ts = encode_cursor(&format!("not-a-time{KEYSET_CURSOR_SEP}row-id"));
        assert!(matches!(
            decode_audit_cursor(&bad_ts),
            Err(ApiError::BadRequest(message)) if message.contains("encoded timestamp")
        ));
        // Malformed row ids: empty, over 128 bytes, control characters, and
        // SQL metacharacters are shape-checked before any bind.
        for bad_id in [
            "",
            &"i".repeat(129),
            "bad\u{7}id",
            "x'; DROP TABLE audit_logs; --",
        ] {
            let cursor = encode_cursor(&format!("2026-01-01T00:00:00Z{KEYSET_CURSOR_SEP}{bad_id}"));
            assert!(
                matches!(
                    decode_audit_cursor(&cursor),
                    Err(ApiError::BadRequest(message)) if message.contains("malformed row id")
                ),
                "id {bad_id:?} must be rejected"
            );
        }
        // A well-formed cursor round-trips (RFC 3339 payload — NOT
        // DateTime's Display form, which the decoder would reject).
        let ts = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
        let (decoded_ts, decoded_id) =
            decode_audit_cursor(&encode_audit_cursor(&ts, "cov-audit-0197d0e6f2b8"))
                .expect("valid cursor");
        assert_eq!(decoded_ts, ts);
        assert_eq!(decoded_id, "cov-audit-0197d0e6f2b8");
    }

    #[test]
    fn audit_filter_predicates_are_explicitly_allowlisted() {
        assert_eq!(AuditFilterColumn::Action.predicate(3), "action = $3");
        assert_eq!(AuditFilterColumn::TenantId.predicate(4), "tenant_id = $4");
        assert_eq!(AuditFilterColumn::UserId.predicate(5), "user_id = $5");
        assert_eq!(AuditFilterColumn::Resource.predicate(6), "resource = $6");
        assert_eq!(AuditFilterColumn::Outcome.predicate(7), "outcome = $7");
    }

    #[test]
    fn build_audit_query_plan_binds_filter_values() {
        let now = Utc.with_ymd_and_hms(2026, 2, 1, 12, 0, 0).unwrap();
        let params = AuditListQuery {
            action: Some("login' OR true --".into()),
            status: Some("failed".into()),
            tenant_id: Some("tenant-1".into()),
            user_id: Some("user-1".into()),
            resource_type: Some("message".into()),
            from: None,
            to: None,
            limit: 500,
            offset: -10,
            cursor: None,
        };

        let plan = build_audit_query_plan(&params, now).expect("query plan should build");

        assert!(plan.sql.contains("action = $3"));
        assert!(plan.sql.contains("tenant_id = $4"));
        assert!(plan.sql.contains("user_id = $5"));
        assert!(plan.sql.contains("resource = $6"));
        assert!(plan.sql.contains("outcome = $7"));
        assert!(plan.sql.contains("LIMIT $8 OFFSET $9"));
        assert!(!plan.sql.contains("login' OR true --"));
        assert_eq!(
            plan.bind_values,
            vec![
                "login' OR true --".to_string(),
                "tenant-1".to_string(),
                "user-1".to_string(),
                "message".to_string(),
                "failed".to_string(),
            ]
        );
        assert_eq!(plan.limit, 200);
        assert_eq!(plan.offset, 0);
    }

    fn viewer() -> AuthUser {
        AuthUser {
            tenant_id: "system".into(),
            user_id: Some("usr_audit_viewer".into()),
            api_key_id: None,
            session_id: None,
            scopes: vec!["*".into()],
        }
    }

    async fn seed_viewer_audit_row(
        pool: &sqlx::PgPool,
        tag: &str,
        user_id: Option<&str>,
        outcome: &str,
        details: serde_json::Value,
    ) {
        sqlx::query(
            "INSERT INTO audit_logs (id, tenant_id, user_id, action, resource, resource_id,
                 details, ip_address, user_agent, outcome, timestamp, hash, signature)
             VALUES ($1, 'system', $2, $3, 'audit_probe', $3, $4, '127.0.0.1', 'cov-test/1',
                     $5, NOW(), 'seed-hash', 'seed-sig')",
        )
        .bind(format!("cov-audit-{tag}-{}", uuid::Uuid::new_v4().simple()))
        .bind(user_id)
        .bind(format!("cov.probe.{tag}"))
        .bind(details)
        .bind(outcome)
        .execute(pool)
        .await
        .expect("seed audit row");
    }

    /// The viewer handler executes its plan against the canonical
    /// audit_logs table and maps both actor shapes (a user actor and a
    /// system actor with a NULL user_id) and both details shapes (a
    /// nested {status, details} envelope and a bare details object).
    #[tokio::test]
    async fn list_audit_logs_filters_maps_and_orders_rows() {
        let Some(pool) = crate::test_db::canonical_pool("audit_viewer_lists").await else {
            return;
        };
        let state = crate::app::test_support::test_state_over(pool.clone()).await;

        // A row whose details carry the status/details envelope, with a
        // user actor → actor_type "user", nested details preferred.
        seed_viewer_audit_row(
            &pool,
            "envelope",
            Some("usr_actor_1"),
            "failed",
            serde_json::json!({
                "status": "failed",
                "details": { "reason": "quota" },
                "other": "kept"
            }),
        )
        .await;
        // A bare-details row with a NULL user_id → system actor, status
        // defaults to "success", the whole metadata object is the details.
        seed_viewer_audit_row(
            &pool,
            "bare",
            None,
            "success",
            serde_json::json!({ "reason": "seeded" }),
        )
        .await;

        // Every filter column rides the same plan; the default limit comes
        // from the serde default (no explicit limit in the query string).
        let params = AuditListQuery {
            action: None,
            status: None,
            tenant_id: Some("system".into()),
            user_id: None,
            resource_type: Some("audit_probe".into()),
            from: None,
            to: None,
            limit: 50,
            offset: 0,
            cursor: None,
        };
        let (_headers, Json(entries)) =
            list_audit_logs(State(state.clone()), viewer(), Query(params))
                .await
                .expect("audit list query succeeds");

        let envelope = entries
            .iter()
            .find(|e| e.action == "cov.probe.envelope")
            .expect("envelope row listed");
        assert_eq!(envelope.status, "failed");
        assert_eq!(envelope.actor_type, "user");
        assert_eq!(envelope.actor_id, "usr_actor_1");
        assert_eq!(envelope.resource, "audit_probe");
        assert_eq!(envelope.resource_id, envelope.action);
        assert_eq!(envelope.tenant_id.as_deref(), Some("system"));
        assert_eq!(envelope.ip_address.as_deref(), Some("127.0.0.1"));
        assert_eq!(envelope.user_agent.as_deref(), Some("cov-test/1"));
        assert_eq!(envelope.details["reason"], "quota");
        // A nested details envelope REPLACES the flat details in the
        // viewer output — sibling metadata keys are not surfaced.
        assert_eq!(envelope.details["other"], serde_json::Value::Null);

        let bare = entries
            .iter()
            .find(|e| e.action == "cov.probe.bare")
            .expect("bare row listed");
        assert_eq!(bare.status, "success", "missing status defaults to success");
        assert_eq!(bare.actor_type, "system", "NULL user_id is a system actor");
        assert_eq!(bare.details["reason"], "seeded");

        // Action + status filters narrow to exactly one row; an
        // exhaustive match on the outcome column.
        let params = AuditListQuery {
            action: Some("cov.probe.envelope".into()),
            status: Some("failed".into()),
            tenant_id: None,
            user_id: None,
            resource_type: None,
            from: None,
            to: None,
            limit: 200,
            offset: 0,
            cursor: None,
        };
        let (_headers, Json(entries)) =
            list_audit_logs(State(state.clone()), viewer(), Query(params))
                .await
                .expect("filtered audit list");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].action, "cov.probe.envelope");

        // User-id filter matches the seeded NULL only against absent.
        let params = AuditListQuery {
            action: Some("cov.probe.bare".into()),
            status: None,
            tenant_id: None,
            user_id: Some("usr_nobody".into()),
            resource_type: None,
            from: None,
            to: None,
            limit: 10,
            offset: 0,
            cursor: None,
        };
        let (_headers, Json(entries)) =
            list_audit_logs(State(state.clone()), viewer(), Query(params))
                .await
                .expect("user-filtered audit list");
        assert!(entries.is_empty(), "NULL user_id never matches a filter");

        // Pagination is applied (limit clamps inside the plan; offset skips).
        let params = AuditListQuery {
            action: None,
            status: None,
            tenant_id: None,
            user_id: None,
            resource_type: Some("audit_probe".into()),
            from: None,
            to: None,
            limit: 1,
            offset: 1,
            cursor: None,
        };
        let (headers, Json(entries)) = list_audit_logs(State(state), viewer(), Query(params))
            .await
            .expect("paginated audit list");
        assert_eq!(entries.len(), 1, "offset=1&limit=1 leaves one of two rows");
        // Two probe rows seeded above: offset=1 is the FINAL page, so
        // has-more is honestly false — but a non-empty page still mints the
        // continuation cursor.
        assert_eq!(headers.get("x-has-more").unwrap(), "false");
        assert!(headers.contains_key("x-next-cursor"));
    }

    /// Malformed window bounds surface as validation errors from the
    /// handler itself (parse + ordering + width arms).
    #[tokio::test]
    async fn list_audit_logs_rejects_bad_windows() {
        let Some(pool) = crate::test_db::canonical_pool("audit_viewer_windows").await else {
            return;
        };
        let state = crate::app::test_support::test_state_over(pool).await;
        let build = |from: Option<String>, to: Option<String>| AuditListQuery {
            action: None,
            status: None,
            tenant_id: None,
            user_id: None,
            resource_type: None,
            from,
            to,
            limit: 10,
            offset: 0,
            cursor: None,
        };

        for params in [
            build(Some("not-a-timestamp".into()), None),
            build(None, Some("2026-13-40".into())),
        ] {
            let result = list_audit_logs(State(state.clone()), viewer(), Query(params)).await;
            assert!(
                matches!(result, Err(ApiError::Validation(_))),
                "malformed timestamp must be a validation error"
            );
        }

        let result = list_audit_logs(
            State(state.clone()),
            viewer(),
            Query(build(
                Some("2026-02-02T00:00:00Z".into()),
                Some("2026-02-01T00:00:00Z".into()),
            )),
        )
        .await;
        assert!(matches!(result, Err(ApiError::Validation(_))));

        let result = list_audit_logs(
            State(state),
            viewer(),
            Query(build(
                Some("2026-01-01T00:00:00Z".into()),
                Some("2026-04-15T00:00:00Z".into()),
            )),
        )
        .await;
        assert!(matches!(result, Err(ApiError::Validation(_))));
    }

    /// The system-tenant gate fires inside the handler: a customer-tenant
    /// caller with a wildcard scope is still refused.
    #[tokio::test]
    async fn list_audit_logs_refuses_non_system_tenants() {
        let Some(pool) = crate::test_db::canonical_pool("audit_viewer_gate").await else {
            return;
        };
        let state = crate::app::test_support::test_state_over(pool).await;
        let customer = AuthUser {
            tenant_id: "ten_customer".into(),
            user_id: None,
            api_key_id: None,
            session_id: None,
            scopes: vec!["*".into()],
        };
        let params = AuditListQuery {
            action: None,
            status: None,
            tenant_id: None,
            user_id: None,
            resource_type: None,
            from: None,
            to: None,
            limit: 10,
            offset: 0,
            cursor: None,
        };
        let result = list_audit_logs(State(state), customer, Query(params)).await;
        assert!(matches!(result, Err(ApiError::Forbidden(_))));
    }

    // ── Keyset cursor adversarial properties ─────────────────────

    const CURSOR_PROBE_SQL: &str =
        "INSERT INTO audit_logs (id, tenant_id, user_id, action, resource, resource_id, \
         details, ip_address, user_agent, outcome, timestamp, hash, signature)
         SELECT 'cur-' || lpad(g::text, 2, '0') || '-' || substr(gen_random_uuid()::text, 1, 8),
                $1, 'usr_cur', 'cov.cursor.' || g, 'audit_probe', 'res',
                '{\"reason\": \"seed\"}'::jsonb, '127.0.0.1', 'cur-test/1', 'success',
                NOW(), 'seed-hash', 'seed-sig'
         FROM generate_series(0, $2 - 1) AS g";

    fn list_params(
        resource: Option<String>,
        tenant: Option<String>,
        limit: i64,
        offset: i64,
        cursor: Option<String>,
    ) -> AuditListQuery {
        AuditListQuery {
            action: None,
            status: None,
            tenant_id: tenant,
            user_id: None,
            resource_type: resource,
            from: None,
            to: None,
            limit,
            offset,
            cursor,
        }
    }

    /// The resource cohort's total order per the SAME ORDER BY the endpoint
    /// uses — the ground truth every walk must reproduce exactly.
    async fn expected_audit_order(pool: &sqlx::PgPool) -> Vec<String> {
        sqlx::query_scalar(
            "SELECT id FROM audit_logs WHERE resource = 'audit_probe'
             ORDER BY timestamp DESC, id DESC",
        )
        .fetch_all(pool)
        .await
        .expect("expected audit order")
    }

    fn header_str(headers: &axum::http::HeaderMap, name: &str) -> String {
        headers
            .get(name)
            .unwrap_or_else(|| panic!("missing {name} header"))
            .to_str()
            .expect("header ascii")
            .to_string()
    }

    /// Page through the audit cohort one row at a time following the
    /// x-next-cursor header: the cursor walk must reproduce the offset walk
    /// and the database order exactly — zero skips, zero duplicates — even
    /// though every seeded row shares ONE timestamp (the bulk-write shape
    /// where a timestamp-only cursor is lossy). Cursor continuation also
    /// honours the tenantId filter on every page.
    #[tokio::test]
    async fn audit_cursor_sweep_matches_offset_and_stays_scoped() {
        let Some(pool) = crate::test_db::canonical_pool("audit_cursor_sweep").await else {
            return;
        };
        let state = crate::app::test_support::test_state_over(pool.clone()).await;

        // SIX rows in ONE statement → identical timestamps; ordering is
        // decided entirely by the id tie-break. Plus one foreign-tenant row
        // the tenantId-filtered walk must never surface.
        sqlx::query(CURSOR_PROBE_SQL)
            .bind("system")
            .bind(6i64)
            .execute(&pool)
            .await
            .expect("seed probe rows");
        sqlx::query(CURSOR_PROBE_SQL)
            .bind("other-tenant")
            .bind(1i64)
            .execute(&pool)
            .await
            .expect("seed foreign row");

        let expected = expected_audit_order(&pool).await;
        assert_eq!(expected.len(), 7, "one row per seeded tenant entry");
        let expected_system: Vec<String> = sqlx::query_scalar(
            "SELECT id FROM audit_logs WHERE resource = 'audit_probe' AND tenant_id = 'system'
             ORDER BY timestamp DESC, id DESC",
        )
        .fetch_all(&pool)
        .await
        .expect("expected system order");
        assert_eq!(expected_system.len(), 6);

        // Legacy offset sweep (backward compat) at limit=1.
        let mut by_offset = Vec::new();
        for offset in 0..expected.len() {
            let (headers, Json(entries)) = list_audit_logs(
                State(state.clone()),
                viewer(),
                Query(list_params(
                    Some("audit_probe".into()),
                    None,
                    1,
                    offset as i64,
                    None,
                )),
            )
            .await
            .expect("offset page");
            if entries.is_empty() {
                break;
            }
            // has-more mirrors exactly whether a further row exists.
            assert_eq!(
                header_str(&headers, "x-has-more"),
                if offset + 1 < expected.len() {
                    "true"
                } else {
                    "false"
                }
            );
            by_offset.push(entries[0].id.clone());
        }
        assert_eq!(by_offset, expected, "offset walk vs DB order");

        // Cursor sweep (limit=1): follow x-next-cursor; the tenantId filter
        // rides every continuation page.
        let mut by_cursor: Vec<String> = Vec::new();
        let mut cursor: Option<String> = None;
        loop {
            let (headers, Json(entries)) = list_audit_logs(
                State(state.clone()),
                viewer(),
                Query(list_params(
                    Some("audit_probe".into()),
                    Some("system".into()),
                    1,
                    0,
                    cursor,
                )),
            )
            .await
            .expect("cursor page");
            if entries.is_empty() {
                assert_eq!(header_str(&headers, "x-has-more"), "false");
                break;
            }
            assert_eq!(entries.len(), 1);
            assert!(
                entries
                    .iter()
                    .all(|e| e.tenant_id.as_deref() == Some("system")),
                "a foreign-tenant row leaked into the tenant-filtered walk"
            );
            by_cursor.push(entries[0].id.clone());
            // has-more mirrors exactly whether a further row exists.
            assert_eq!(
                header_str(&headers, "x-has-more"),
                if by_cursor.len() < expected_system.len() {
                    "true"
                } else {
                    "false"
                }
            );
            cursor = Some(
                headers
                    .get("x-next-cursor")
                    .expect("has-more implies next cursor")
                    .to_str()
                    .unwrap()
                    .to_string(),
            );
        }
        assert_eq!(
            by_cursor
                .iter()
                .collect::<std::collections::HashSet<_>>()
                .len(),
            by_cursor.len(),
            "a cursor sweep must never repeat a row"
        );
        assert_eq!(by_cursor, expected_system, "cursor walk vs DB order");

        // Cursor wins over offset: page 1's cursor plus a deep offset still
        // yields page 2 of the cursor position.
        let (headers, Json(_page1)) = list_audit_logs(
            State(state.clone()),
            viewer(),
            Query(list_params(Some("audit_probe".into()), None, 1, 0, None)),
        )
        .await
        .expect("first page");
        let minted = header_str(&headers, "x-next-cursor");
        let (_h, Json(page2)) = list_audit_logs(
            State(state.clone()),
            viewer(),
            Query(list_params(
                Some("audit_probe".into()),
                None,
                1,
                999,
                Some(minted),
            )),
        )
        .await
        .expect("cursor beats offset");
        assert_eq!(page2[0].id, expected[1], "cursor must beat offset");
        // ...and the offset path still pages from a deep position unchanged.
        let (_h, Json(deep)) = list_audit_logs(
            State(state.clone()),
            viewer(),
            Query(list_params(Some("audit_probe".into()), None, 1, 5, None)),
        )
        .await
        .expect("deep offset page");
        assert_eq!(deep[0].id, expected[5]);

        // The final page flips x-has-more without a cursor row beyond it.
        let (headers, Json(last)) = list_audit_logs(
            State(state.clone()),
            viewer(),
            Query(list_params(Some("audit_probe".into()), None, 200, 0, None)),
        )
        .await
        .expect("final page");
        assert_eq!(header_str(&headers, "x-has-more"), "false");
        assert_eq!(last.len(), 7);

        // Hostile cursors are 400s BEFORE any SQL runs.
        for bad in [
            "zz",
            encode_cursor("no-separator-here").as_str(),
            encode_cursor(&format!("not-a-time{KEYSET_CURSOR_SEP}row-id")).as_str(),
        ] {
            let result = list_audit_logs(
                State(state.clone()),
                viewer(),
                Query(list_params(
                    Some("audit_probe".into()),
                    None,
                    1,
                    0,
                    Some(bad.into()),
                )),
            )
            .await;
            assert!(
                matches!(result, Err(ApiError::BadRequest(message)) if message.contains("invalid cursor")),
                "cursor {bad:?} must be a client error"
            );
        }

        pool.close().await;
    }
}
