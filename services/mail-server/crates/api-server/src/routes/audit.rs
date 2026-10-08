//! Tenant-scoped audit trail: customer read and export.
//!
//! Audit rows and their tamper-evident hash chain have shipped since
//! migration 038; until this module the only read surface was the
//! operator-only `GET /v1/admin/audit` (system tenant + wildcard scope). This
//! is the CUSTOMER surface for the `audit_logs` capability that
//! `docs/pricing.md` sells on Growth and above.
//!
//! Every handler enforces BOTH gates:
//!
//! * scope **`audit:read`** — an API key or session without it is refused
//!   `403` before a row is read (RBAC);
//! * entitlement **`FeatureKey::AuditLogs`** — resolved from the tenant's
//!   effective plan (override-aware) and refused `403` naming the plan and
//!   the capability when the plan does not sell it.
//!
//! ## Endpoints
//!
//! * `GET /v1/audit` — keyset-paginated rows, newest first. The tenant is
//!   ALWAYS the authenticated tenant; there is deliberately no `tenantId`
//!   filter, so no request shape can widen the scope. The body is a bare
//!   JSON array (matching the operator viewer) with `x-has-more` and
//!   `x-next-cursor` continuation headers; `?cursor=` wins over `?offset=`.
//! * `GET /v1/audit/export?format=csv|jsonl` — streamed export of the same
//!   tenant-scoped rows, bounded to a 90-day window and 50,000 rows. The
//!   export is itself audited (`audit.trail.exported`).
//!
//! An empty trail is an honest `200` with `[]` and `x-has-more: false` —
//! never a 404 and never fabricated rows.

// Stream combinators (chain) resolve against futures, not Iterator.
use futures::StreamExt as _;

use axum::extract::{Query, State};
use axum::http::{header, HeaderMap, HeaderValue};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

use crate::error::ApiError;
use crate::middleware::auth::{require_scopes, AuthUser};
use crate::routes::helpers::{decode_cursor, encode_cursor};
use crate::state::AppState;
use billing_entitlements::FeatureKey;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/", get(list_audit_logs))
        .route("/export", get(export_audit_logs))
}

/// The scope a caller must hold to read the tenant audit trail.
pub const AUDIT_READ_SCOPE: &str = "audit:read";

const DEFAULT_AUDIT_WINDOW_DAYS: i64 = 30;
const MAX_AUDIT_WINDOW_DAYS: i64 = 90;
const MAX_LIST_LIMIT: i64 = 200;
const MAX_EXPORT_ROWS: i64 = 50_000;
const EXPORT_CHUNK_ROWS: i64 = 1_000;

fn default_limit() -> i64 {
    50
}

// ─── Keyset cursor ─────────────────────────────────────────────
//
// Hex-encoded `(timestamp, id)` pair, byte-compatible with the operator
// viewer's cursor format. A timestamp alone skips or duplicates rows that
// share a timestamp (bulk audit writes do this constantly); the tie-break
// `timestamp = $ts AND id < $id` makes the `timestamp DESC, id DESC`
// ordering total.

const KEYSET_CURSOR_SEP: char = '\n';

fn encode_audit_cursor(timestamp: &DateTime<Utc>, id: &str) -> String {
    encode_cursor(&format!(
        "{}{KEYSET_CURSOR_SEP}{id}",
        timestamp.to_rfc3339()
    ))
}

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
    let timestamp = DateTime::parse_from_rfc3339(timestamp)
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

// ─── Query types ───────────────────────────────────────────────

/// List filters. There is deliberately NO `tenantId` field: the tenant is
/// taken from the authenticated principal, and an unknown query parameter is
/// rejected by `deny_unknown_fields` instead of being silently ignored.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TenantAuditQuery {
    pub action: Option<String>,
    pub resource: Option<String>,
    pub from: Option<String>,
    pub to: Option<String>,
    #[serde(default = "default_limit")]
    pub limit: i64,
    #[serde(default)]
    pub offset: i64,
    #[serde(default)]
    pub cursor: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TenantAuditExportQuery {
    pub action: Option<String>,
    pub resource: Option<String>,
    pub from: Option<String>,
    pub to: Option<String>,
    #[serde(default)]
    pub format: ExportFormat,
    #[serde(default = "default_export_limit")]
    pub limit: i64,
}

fn default_export_limit() -> i64 {
    10_000
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ExportFormat {
    #[default]
    Csv,
    Jsonl,
}

impl ExportFormat {
    fn content_type(self) -> &'static str {
        match self {
            Self::Csv => "text/csv; charset=utf-8",
            Self::Jsonl => "application/x-ndjson; charset=utf-8",
        }
    }

    fn extension(self) -> &'static str {
        match self {
            Self::Csv => "csv",
            Self::Jsonl => "jsonl",
        }
    }
}

// ─── Window resolution ─────────────────────────────────────────

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

// ─── Row mapping ───────────────────────────────────────────────

/// One fetched audit row (canonical migration-038 shape).
#[derive(Debug, sqlx::FromRow)]
struct AuditRow {
    id: String,
    timestamp: DateTime<Utc>,
    action: String,
    resource: String,
    resource_id: Option<String>,
    user_id: Option<String>,
    tenant_id: Option<String>,
    details: serde_json::Value,
    ip_address: Option<String>,
    user_agent: Option<String>,
    outcome: String,
    error_message: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TenantAuditEntry {
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
    pub error_message: Option<String>,
}

impl AuditRow {
    fn into_entry(self) -> TenantAuditEntry {
        TenantAuditEntry {
            id: self.id,
            timestamp: self.timestamp.to_rfc3339(),
            action: self.action,
            resource: self.resource,
            resource_id: self.resource_id.unwrap_or_default(),
            actor_type: if self.user_id.is_some() {
                "user".into()
            } else {
                "system".into()
            },
            actor_id: self.user_id.unwrap_or_else(|| "system".into()),
            tenant_id: self.tenant_id,
            status: self.outcome,
            ip_address: self.ip_address,
            user_agent: self.user_agent,
            details: self.details,
            error_message: self.error_message,
        }
    }
}

const AUDIT_COLUMNS: &str = "id, timestamp, action, resource, resource_id, user_id, tenant_id, \
                             details, ip_address, user_agent, outcome, error_message";

// ─── Gates ─────────────────────────────────────────────────────

/// Scope + entitlement gate shared by both handlers.
async fn require_audit_read(state: &AppState, auth: &AuthUser) -> Result<(), ApiError> {
    require_scopes(auth, &[AUDIT_READ_SCOPE])?;
    crate::entitlements::require_feature(state, &auth.tenant_id, FeatureKey::AuditLogs)
        .await
        .map(|_| ())
}

// ─── List ──────────────────────────────────────────────────────

#[derive(Debug)]
struct AuditListPlan {
    sql: String,
    /// Bound filter values, in placeholder order after the tenant/window.
    filter_binds: Vec<String>,
    window_start: DateTime<Utc>,
    window_end: DateTime<Utc>,
    limit: i64,
    offset: i64,
    keyset: Option<(DateTime<Utc>, String)>,
}

fn build_audit_list_plan(
    tenant_id: &str,
    params: &TenantAuditQuery,
    now: DateTime<Utc>,
) -> Result<AuditListPlan, ApiError> {
    let limit = params.limit.clamp(1, MAX_LIST_LIMIT);
    let offset = params.offset.max(0);
    let (window_start, window_end) =
        resolve_audit_window(params.from.as_deref(), params.to.as_deref(), now)?;
    let keyset = match params.cursor.as_deref() {
        Some(encoded) => Some(decode_audit_cursor(encoded)?),
        None => None,
    };

    // $1 tenant, $2/$3 window; optional filters follow, then keyset/limit.
    let mut conditions: Vec<String> = vec![
        "tenant_id = $1".into(),
        "timestamp >= $2".into(),
        "timestamp <= $3".into(),
    ];
    let mut param_idx = 4u32;
    let mut filter_binds: Vec<String> = Vec::new();
    if let Some(ref action) = params.action {
        conditions.push(format!("action = ${param_idx}"));
        param_idx += 1;
        filter_binds.push(action.clone());
    }
    if let Some(ref resource) = params.resource {
        conditions.push(format!("resource = ${param_idx}"));
        param_idx += 1;
        filter_binds.push(resource.clone());
    }
    let where_clause = format!("WHERE {}", conditions.join(" AND "));

    let sql = if keyset.is_some() {
        let ts_idx = param_idx;
        let id_idx = param_idx + 1;
        let limit_idx = param_idx + 2;
        format!(
            "SELECT {AUDIT_COLUMNS} FROM audit_logs {where_clause}
               AND (timestamp < ${ts_idx}::timestamptz
                    OR (timestamp = ${ts_idx}::timestamptz AND id < ${id_idx}))
             ORDER BY timestamp DESC, id DESC
             LIMIT ${limit_idx}"
        )
    } else {
        format!(
            "SELECT {AUDIT_COLUMNS} FROM audit_logs {where_clause}
             ORDER BY timestamp DESC, id DESC
             LIMIT ${param_idx} OFFSET ${}",
            param_idx + 1
        )
    };

    // The tenant bind is the FIRST value bound (asserted by tests) — it is
    // never caller-supplied.
    let _ = tenant_id;
    Ok(AuditListPlan {
        sql,
        filter_binds,
        window_start,
        window_end,
        limit,
        offset,
        keyset,
    })
}

/// List the authenticated tenant's audit rows, newest first.
async fn list_audit_logs(
    State(state): State<AppState>,
    auth: AuthUser,
    Query(params): Query<TenantAuditQuery>,
) -> Result<(HeaderMap, Json<Vec<TenantAuditEntry>>), ApiError> {
    require_audit_read(&state, &auth).await?;

    let plan = build_audit_list_plan(&auth.tenant_id, &params, Utc::now())?;
    let fetch_limit = plan.limit + 1; // one extra row to detect has_more

    let mut query = sqlx::query_as::<_, AuditRow>(&plan.sql)
        .bind(&auth.tenant_id)
        .bind(plan.window_start)
        .bind(plan.window_end);
    for value in &plan.filter_binds {
        query = query.bind(value);
    }
    if let Some((ref ts, ref id)) = plan.keyset {
        query = query.bind(ts).bind(id).bind(fetch_limit);
    } else {
        query = query.bind(fetch_limit).bind(plan.offset);
    }

    let rows = query.fetch_all(&state.db).await?;

    let more = rows.len() as i64 > plan.limit;
    let kept = if more {
        plan.limit as usize
    } else {
        rows.len()
    };
    let next_cursor = if kept > 0 {
        let last = &rows[kept - 1];
        Some(encode_audit_cursor(&last.timestamp, &last.id))
    } else {
        None
    };

    let entries: Vec<TenantAuditEntry> = rows
        .into_iter()
        .take(kept)
        .map(AuditRow::into_entry)
        .collect();

    let mut headers = HeaderMap::new();
    headers.insert(
        "x-has-more",
        HeaderValue::from_static(if more { "true" } else { "false" }),
    );
    if let Some(cursor) = next_cursor {
        headers.insert(
            "x-next-cursor",
            HeaderValue::from_str(&cursor)
                .map_err(|e| ApiError::Internal(format!("cursor encoding error: {e}")))?,
        );
    }
    // An empty trail is a 200 with [] — honest, not a 404.
    Ok((headers, Json(entries)))
}

// ─── Export ────────────────────────────────────────────────────

/// Stream the tenant's audit rows as CSV or JSONL.
///
/// The body is produced in bounded 1,000-row chunks (`futures::stream::unfold`
/// owns the async block across polls — a hand-rolled Stream here once hung on
/// the first chunk, see `admin/audit_search.rs`). A mid-stream database error
/// terminates the body instead of hanging it.
async fn export_audit_logs(
    State(state): State<AppState>,
    auth: AuthUser,
    Query(params): Query<TenantAuditExportQuery>,
) -> Result<Response, ApiError> {
    require_audit_read(&state, &auth).await?;

    let (window_start, window_end) =
        resolve_audit_window(params.from.as_deref(), params.to.as_deref(), Utc::now())?;
    let limit = params.limit.clamp(1, MAX_EXPORT_ROWS);

    // An export is exactly the read the trail exists to record — audit it.
    crate::audit_log::insert_audit_log_best_effort_with_env(
        &state.db,
        state.config.environment.is_production(),
        Some(auth.tenant_id.as_str()),
        auth.user_id.as_deref(),
        "audit.trail.exported",
        "audit_log",
        None,
        serde_json::json!({
            "format": params.format.extension(),
            "filters": {
                "action": params.action,
                "resource": params.resource,
                "from": params.from,
                "to": params.to,
            },
            "limit": limit,
            "windowStart": window_start.to_rfc3339(),
            "windowEnd": window_end.to_rfc3339(),
        }),
        None,
        None,
    )
    .await;

    let export_state = ExportState {
        pool: state.db.clone(),
        tenant_id: auth.tenant_id.clone(),
        action: params.action.clone(),
        resource: params.resource.clone(),
        window_start,
        window_end,
        format: params.format,
        offset: 0,
        remaining: limit,
    };
    // CSV emits its header first; JSONL has none. `once` + `chain` keeps the
    // header outside the chunk loop while sharing one body stream.
    let header: Option<Vec<u8>> = match params.format {
        ExportFormat::Csv => {
            Some(export_csv_header().map_err(|e| ApiError::Internal(e.to_string()))?)
        }
        ExportFormat::Jsonl => None,
    };
    let stream = futures::stream::once(async move { Ok(header.unwrap_or_default()) })
        .chain(export_chunk_stream(export_state));

    let filename = format!(
        "audit_export_{}_{}.{}",
        sanitize_filename_component(&auth.tenant_id),
        Utc::now().format("%Y%m%dT%H%M%SZ"),
        params.format.extension()
    );
    let disposition = HeaderValue::from_str(&format!("attachment; filename=\"{filename}\""))
        .map_err(|e| ApiError::Internal(e.to_string()))?;

    let mut response = (
        [(header::CONTENT_TYPE, params.format.content_type())],
        axum::body::Body::from_stream(stream),
    )
        .into_response();
    response
        .headers_mut()
        .insert(header::CONTENT_DISPOSITION, disposition);
    Ok(response)
}

/// Keep the tenant id filename-safe even though ids are identifier-shaped.
fn sanitize_filename_component(value: &str) -> String {
    value
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_'))
        .take(64)
        .collect()
}

/// Owned state for the chunked export stream (no borrows of handler locals:
/// the stream outlives the handler).
struct ExportState {
    pool: sqlx::PgPool,
    tenant_id: String,
    action: Option<String>,
    resource: Option<String>,
    window_start: DateTime<Utc>,
    window_end: DateTime<Utc>,
    format: ExportFormat,
    offset: i64,
    remaining: i64,
}

/// Render the export chunk query. The tenant predicate is ALWAYS the first
/// condition and `$1` is always the authenticated tenant; optional
/// action/resource filters follow, then LIMIT/OFFSET. The bind order in
/// [`export_chunk_stream`] mirrors this exactly ($1 tenant, $2/$3 window,
/// filters, limit, offset).
fn build_export_chunk_sql(action: Option<&str>, resource: Option<&str>) -> String {
    let mut conditions: Vec<String> = vec![
        "tenant_id = $1".into(),
        "timestamp >= $2".into(),
        "timestamp <= $3".into(),
    ];
    let mut param_idx = 4u32;
    if action.is_some() {
        conditions.push(format!("action = ${param_idx}"));
        param_idx += 1;
    }
    if resource.is_some() {
        conditions.push(format!("resource = ${param_idx}"));
        param_idx += 1;
    }
    format!(
        "SELECT {AUDIT_COLUMNS} FROM audit_logs
         WHERE {}
         ORDER BY timestamp DESC, id DESC
         LIMIT ${param_idx} OFFSET ${}",
        conditions.join(" AND "),
        param_idx + 1
    )
}

fn export_chunk_stream(
    state: ExportState,
) -> impl futures::Stream<Item = Result<Vec<u8>, std::io::Error>> {
    futures::stream::unfold(Some(state), |maybe_state| async move {
        let mut state = maybe_state?;
        if state.remaining <= 0 {
            return None;
        }
        let chunk_limit = state.remaining.min(EXPORT_CHUNK_ROWS);

        let sql = build_export_chunk_sql(state.action.as_deref(), state.resource.as_deref());

        let mut query = sqlx::query_as::<_, AuditRow>(&sql)
            .bind(&state.tenant_id)
            .bind(state.window_start)
            .bind(state.window_end);
        if let Some(ref action) = state.action {
            query = query.bind(action.clone());
        }
        if let Some(ref resource) = state.resource {
            query = query.bind(resource.clone());
        }
        let result = query
            .bind(chunk_limit)
            .bind(state.offset)
            .fetch_all(&state.pool)
            .await;

        match result {
            Ok(rows) => {
                let fetched = rows.len() as i64;
                state.remaining -= fetched;
                state.offset += fetched;
                if fetched < chunk_limit {
                    state.remaining = 0;
                }
                if rows.is_empty() {
                    return None;
                }
                let buffer = match render_export_chunk(&rows, state.format) {
                    Ok(buffer) => buffer,
                    Err(error) => return Some((Err(error), Some(state))),
                };
                Some((Ok(buffer), Some(state)))
            }
            Err(error) => {
                state.remaining = 0;
                Some((Err(std::io::Error::other(error)), Some(state)))
            }
        }
    })
}

fn render_export_chunk(rows: &[AuditRow], format: ExportFormat) -> Result<Vec<u8>, std::io::Error> {
    match format {
        ExportFormat::Jsonl => {
            let mut buffer = Vec::with_capacity(rows.len() * 256);
            for row in rows {
                let entry = TenantAuditEntry {
                    id: row.id.clone(),
                    timestamp: row.timestamp.to_rfc3339(),
                    action: row.action.clone(),
                    resource: row.resource.clone(),
                    resource_id: row.resource_id.clone().unwrap_or_default(),
                    actor_type: if row.user_id.is_some() {
                        "user".into()
                    } else {
                        "system".into()
                    },
                    actor_id: row.user_id.clone().unwrap_or_else(|| "system".into()),
                    tenant_id: row.tenant_id.clone(),
                    status: row.outcome.clone(),
                    ip_address: row.ip_address.clone(),
                    user_agent: row.user_agent.clone(),
                    details: row.details.clone(),
                    error_message: row.error_message.clone(),
                };
                serde_json::to_writer(&mut buffer, &entry)?;
                buffer.push(b'\n');
            }
            Ok(buffer)
        }
        ExportFormat::Csv => {
            let mut writer = csv::Writer::from_writer(Vec::new());
            for row in rows {
                let timestamp = row.timestamp.to_rfc3339();
                let details = row.details.to_string();
                writer
                    .write_record([
                        row.id.as_str(),
                        timestamp.as_str(),
                        row.action.as_str(),
                        row.resource.as_str(),
                        row.resource_id.as_deref().unwrap_or_default(),
                        row.user_id.as_deref().unwrap_or_default(),
                        row.tenant_id.as_deref().unwrap_or_default(),
                        row.outcome.as_str(),
                        row.ip_address.as_deref().unwrap_or_default(),
                        row.user_agent.as_deref().unwrap_or_default(),
                        details.as_str(),
                        row.error_message.as_deref().unwrap_or_default(),
                    ])
                    .map_err(std::io::Error::other)?;
            }
            writer.flush()?;
            writer.into_inner().map_err(std::io::Error::other)
        }
    }
}

/// CSV header row, rendered with the same writer as the rows so escaping is
/// identical.
fn export_csv_header() -> Result<Vec<u8>, std::io::Error> {
    let mut writer = csv::Writer::from_writer(Vec::new());
    writer
        .write_record([
            "id",
            "timestamp",
            "action",
            "resource",
            "resource_id",
            "actor_id",
            "tenant_id",
            "status",
            "ip_address",
            "user_agent",
            "details",
            "error_message",
        ])
        .map_err(std::io::Error::other)?;
    writer.flush()?;
    writer.into_inner().map_err(std::io::Error::other)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::to_bytes;
    use chrono::TimeZone;

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 2, 1, 12, 0, 0).unwrap()
    }

    fn query() -> TenantAuditQuery {
        TenantAuditQuery {
            action: None,
            resource: None,
            from: None,
            to: None,
            limit: 50,
            offset: 0,
            cursor: None,
        }
    }

    #[test]
    fn window_defaults_to_thirty_days_and_rejects_wide_or_inverted_ranges() {
        let (from, to) = resolve_audit_window(None, None, now()).expect("default window");
        assert_eq!(to, now());
        assert_eq!(from, now() - Duration::days(30));

        assert!(resolve_audit_window(
            Some("2026-02-02T00:00:00Z"),
            Some("2026-02-01T00:00:00Z"),
            now(),
        )
        .is_err());
        assert!(resolve_audit_window(
            Some("2026-01-01T00:00:00Z"),
            Some("2026-04-15T00:00:00Z"),
            now(),
        )
        .is_err());
        assert!(resolve_audit_window(Some("not-a-time"), None, now()).is_err());
    }

    #[test]
    fn cursor_round_trips_and_rejects_malformed_shapes() {
        let ts = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
        let (decoded_ts, decoded_id) =
            decode_audit_cursor(&encode_audit_cursor(&ts, "cov-audit-01")).expect("valid cursor");
        assert_eq!(decoded_ts, ts);
        assert_eq!(decoded_id, "cov-audit-01");

        assert!(decode_audit_cursor("zz").is_err());
        assert!(decode_audit_cursor(&encode_cursor("no-separator")).is_err());
        assert!(decode_audit_cursor(&encode_cursor("bad-time\nid")).is_err());
        assert!(decode_audit_cursor(&encode_cursor(&format!(
            "2026-01-01T00:00:00Z{KEYSET_CURSOR_SEP}"
        )))
        .is_err());
    }

    #[test]
    fn list_plan_scopes_the_query_to_the_authenticated_tenant() {
        let plan = build_audit_list_plan("tenant-a", &query(), now()).expect("plan");
        assert!(
            plan.sql.contains("tenant_id = $1"),
            "tenant predicate must be first and bound: {}",
            plan.sql
        );
        assert!(
            !plan.sql.to_lowercase().contains("tenant_id = $4"),
            "no caller-supplied tenant filter may exist"
        );
        assert!(plan.sql.contains("LIMIT $4 OFFSET $5"));
        assert_eq!(plan.limit, 50);
        assert!(plan.filter_binds.is_empty());
    }

    #[test]
    fn list_plan_binds_filters_before_the_keyset_tail() {
        let params = TenantAuditQuery {
            action: Some("user.login".into()),
            resource: Some("session".into()),
            ..query()
        };
        let plan = build_audit_list_plan("tenant-a", &params, now()).expect("plan");
        assert!(plan.sql.contains("action = $4"));
        assert!(plan.sql.contains("resource = $5"));
        assert!(plan.sql.contains("LIMIT $6 OFFSET $7"));
        assert_eq!(
            plan.filter_binds,
            vec!["user.login".to_string(), "session".to_string()]
        );

        // A cursor wins over offset and appends the tuple predicate.
        let params = TenantAuditQuery {
            cursor: Some(encode_audit_cursor(&now(), "row-1")),
            ..query()
        };
        let plan = build_audit_list_plan("tenant-a", &params, now()).expect("plan");
        assert!(plan.sql.contains("timestamp < $4::timestamptz"));
        assert!(plan.sql.contains("id < $5"));
        assert!(plan.sql.contains("LIMIT $6"));
        assert!(!plan.sql.contains("OFFSET"));
        assert!(plan.keyset.is_some());
    }

    /// The export chunk query is tenant-scoped for every filter combination,
    /// with the tenant predicate first and the placeholders numbered in the
    /// exact bind order the stream uses.
    #[test]
    fn export_chunk_sql_is_tenant_scoped_for_every_filter_shape() {
        let plain = build_export_chunk_sql(None, None);
        assert!(plain.contains("tenant_id = $1"), "{plain}");
        assert!(plain.contains("LIMIT $4 OFFSET $5"), "{plain}");

        let filtered = build_export_chunk_sql(Some("user.login"), None);
        assert!(filtered.contains("tenant_id = $1"), "{filtered}");
        assert!(filtered.contains("action = $4"), "{filtered}");
        assert!(filtered.contains("LIMIT $5 OFFSET $6"), "{filtered}");

        let both = build_export_chunk_sql(Some("user.login"), Some("session"));
        assert!(both.contains("tenant_id = $1"), "{both}");
        assert!(both.contains("action = $4"), "{both}");
        assert!(both.contains("resource = $5"), "{both}");
        assert!(both.contains("LIMIT $6 OFFSET $7"), "{both}");
    }

    /// The rejection path for a wider-than-allowed request is never a silent
    /// filter: `tenantId` is not a field, so serde refuses the request.
    #[test]
    fn tenant_id_is_not_a_request_parameter() {
        let parsed: Result<TenantAuditQuery, _> =
            serde_json::from_value(serde_json::json!({"tenantId": "other-tenant"}));
        assert!(parsed.is_err(), "a cross-tenant filter must be rejected");
    }

    #[test]
    fn export_format_and_limit_are_bounded() {
        let parsed: TenantAuditExportQuery =
            serde_json::from_value(serde_json::json!({"format": "jsonl", "limit": 999_999}))
                .expect("query parses");
        assert_eq!(parsed.format, ExportFormat::Jsonl);
        assert_eq!(parsed.limit.clamp(1, MAX_EXPORT_ROWS), MAX_EXPORT_ROWS);

        let bad: Result<TenantAuditExportQuery, _> =
            serde_json::from_value(serde_json::json!({"format": "xml"}));
        assert!(bad.is_err(), "unknown formats are refused");
    }

    #[test]
    fn csv_header_and_rows_agree() {
        let header = String::from_utf8(export_csv_header().expect("header")).expect("utf8");
        assert_eq!(
            header.trim_end(),
            "id,timestamp,action,resource,resource_id,actor_id,tenant_id,status,ip_address,user_agent,details,error_message"
        );
        let row = AuditRow {
            id: "row-1".into(),
            timestamp: now(),
            action: "user.login".into(),
            resource: "session".into(),
            resource_id: Some("sess-1".into()),
            user_id: Some("usr-1".into()),
            tenant_id: Some("tenant-a".into()),
            details: serde_json::json!({"note": "quoted \"value\""}),
            ip_address: Some("127.0.0.1".into()),
            user_agent: None,
            outcome: "success".into(),
            error_message: None,
        };
        let rendered =
            String::from_utf8(render_export_chunk(&[row], ExportFormat::Csv).expect("csv"))
                .expect("utf8");
        // `has_headers(false)`: the production export writes its own header
        // row separately, so this parser must not swallow the first data row.
        let mut reader = csv::ReaderBuilder::new()
            .has_headers(false)
            .from_reader(rendered.as_bytes());
        let record = reader
            .records()
            .next()
            .expect("one csv record")
            .expect("csv record parses");
        assert_eq!(&record[0], "row-1");
        assert_eq!(&record[5], "usr-1", "actor_id column");
        // The JSON details survive CSV quoting round-trip.
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&record[10]).expect("details json"),
            serde_json::json!({"note": "quoted \"value\""})
        );

        let row = AuditRow {
            id: "row-2".into(),
            timestamp: now(),
            action: "user.login".into(),
            resource: "session".into(),
            resource_id: None,
            user_id: None,
            tenant_id: Some("tenant-a".into()),
            details: serde_json::json!({}),
            ip_address: None,
            user_agent: None,
            outcome: "failed".into(),
            error_message: Some("denied".into()),
        };
        let rendered =
            String::from_utf8(render_export_chunk(&[row], ExportFormat::Jsonl).expect("jsonl"))
                .expect("utf8");
        let parsed: serde_json::Value = serde_json::from_str(rendered.trim()).expect("json line");
        assert_eq!(parsed["id"], "row-2");
        assert_eq!(parsed["actorType"], "system");
        assert_eq!(parsed["status"], "failed");
    }

    // ── DB-backed handler tests (skipped without TEST_DATABASE_URL) ──
    //
    // The fixtures below ride the canonical per-test database and the real
    // entitlement resolution, so a passing test means the gate (not a mock)
    // admitted or refused.

    use billing_service::plans::PlanSeed;
    use billing_service::types::PlanFeatures;

    fn auth(tenant: &str, scopes: &[&str]) -> AuthUser {
        AuthUser {
            tenant_id: tenant.into(),
            user_id: Some("usr_audit".into()),
            api_key_id: None,
            session_id: None,
            scopes: scopes.iter().map(|s| s.to_string()).collect(),
        }
    }

    async fn seed_tenant_with_plan(
        pool: &sqlx::PgPool,
        tenant: &str,
        plan: &'static str,
        audit_logs: bool,
    ) {
        let seed = PlanSeed {
            name: plan,
            display_name: "Audit Test",
            description: "test",
            price_monthly: 0,
            price_yearly: 0,
            email_limit: 1_000,
            api_call_limit: 1_000,
            sort_order: 999,
            features: PlanFeatures {
                api_access: true,
                audit_logs,
                ..PlanFeatures::default()
            },
        };
        billing_service::plans::upsert_plan(pool, &seed)
            .await
            .expect("upsert test plan");
        sqlx::query(
            "INSERT INTO tenants (id, name, slug, plan, status, settings, metadata, created_at, updated_at) \
             VALUES ($1, 'Audit Test Tenant', $1, $2, 'active', '{}'::jsonb, '{}'::jsonb, NOW(), NOW())",
        )
        .bind(tenant)
        .bind(plan)
        .execute(pool)
        .await
        .expect("insert audit test tenant");
    }

    async fn seed_audit_row(pool: &sqlx::PgPool, tenant: &str, id: &str, action: &str) {
        sqlx::query(
            "INSERT INTO audit_logs (id, tenant_id, user_id, action, resource, resource_id, \
                 details, ip_address, user_agent, outcome, timestamp, hash, signature) \
             VALUES ($1, $2, 'usr_actor', $3, 'audit_probe', $1, '{}'::jsonb, '127.0.0.1', \
                     'cov-test/1', 'success', NOW() - INTERVAL '5 seconds', 'seed-hash', 'seed-sig')",
        )
        .bind(id)
        .bind(tenant)
        .bind(action)
        .execute(pool)
        .await
        .expect("seed audit row");
    }

    /// Rows of another tenant are invisible; an empty trail is an honest
    /// empty 200, not a 404.
    #[tokio::test]
    async fn list_is_tenant_scoped_and_honest_about_empty() {
        let Some(pool) = crate::test_db::canonical_pool("audit_list_scope").await else {
            return;
        };
        let state = crate::app::test_support::test_state_over(pool.clone()).await;
        seed_tenant_with_plan(&pool, "audit-a", "audit-test-entitled", true).await;
        seed_tenant_with_plan(&pool, "audit-b", "audit-test-entitled", true).await;
        seed_tenant_with_plan(&pool, "audit-empty", "audit-test-entitled", true).await;
        seed_audit_row(&pool, "audit-a", "cov-a-1", "probe.a").await;
        seed_audit_row(&pool, "audit-b", "cov-b-1", "probe.b").await;

        let (headers, Json(entries)) = list_audit_logs(
            State(state.clone()),
            auth("audit-a", &["audit:read"]),
            Query(query()),
        )
        .await
        .expect("tenant-scoped list");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].id, "cov-a-1");
        assert!(entries
            .iter()
            .all(|e| e.tenant_id.as_deref() == Some("audit-a")));
        assert_eq!(headers.get("x-has-more").unwrap(), "false");

        let (headers, Json(entries)) = list_audit_logs(
            State(state),
            auth("audit-empty", &["audit:read"]),
            Query(query()),
        )
        .await
        .expect("empty list is a 200");
        assert!(entries.is_empty(), "an empty trail returns []");
        assert_eq!(headers.get("x-has-more").unwrap(), "false");
        assert!(!headers.contains_key("x-next-cursor"));
    }

    /// RBAC: the scope is required, and `audit:read` is sufficient.
    #[tokio::test]
    async fn list_requires_the_audit_read_scope() {
        let Some(pool) = crate::test_db::canonical_pool("audit_list_scope_gate").await else {
            return;
        };
        let state = crate::app::test_support::test_state_over(pool.clone()).await;
        seed_tenant_with_plan(&pool, "audit-rbac", "audit-test-entitled", true).await;

        let denied = list_audit_logs(
            State(state.clone()),
            auth("audit-rbac", &["messages:read"]),
            Query(query()),
        )
        .await;
        assert!(
            matches!(denied, Err(ApiError::Forbidden(message)) if message.contains("audit:read"))
        );

        let allowed = list_audit_logs(
            State(state),
            auth("audit-rbac", &["audit:read"]),
            Query(query()),
        )
        .await;
        assert!(allowed.is_ok(), "audit:read must be sufficient");
    }

    /// Entitlement: a plan without `audit_logs` is refused naming the
    /// capability; the entitled plan passes. The scope is held in both cases,
    /// so the entitlement — not the scope — decides.
    #[tokio::test]
    async fn list_gates_on_the_plan_entitlement() {
        let Some(pool) = crate::test_db::canonical_pool("audit_list_entitlement").await else {
            return;
        };
        let state = crate::app::test_support::test_state_over(pool.clone()).await;
        seed_tenant_with_plan(&pool, "audit-free", "audit-test-free", false).await;
        seed_tenant_with_plan(&pool, "audit-paid", "audit-test-paid", true).await;

        let refused = list_audit_logs(
            State(state.clone()),
            auth("audit-free", &["audit:read"]),
            Query(query()),
        )
        .await;
        match refused {
            Err(ApiError::Forbidden(message)) => {
                assert!(message.contains("audit_logs"), "{message}");
                assert!(message.contains("audit-test-free"), "{message}");
            }
            other => panic!("expected a named 403, got {other:?}"),
        }

        let admitted = list_audit_logs(
            State(state),
            auth("audit-paid", &["audit:read"]),
            Query(query()),
        )
        .await;
        assert!(admitted.is_ok(), "an entitled plan must pass");
    }

    /// The cursor walk reproduces the database order exactly even when every
    /// row shares one timestamp — no skips, no duplicates.
    #[tokio::test]
    async fn cursor_walk_is_stable_with_tied_timestamps() {
        let Some(pool) = crate::test_db::canonical_pool("audit_cursor_walk").await else {
            return;
        };
        let state = crate::app::test_support::test_state_over(pool.clone()).await;
        seed_tenant_with_plan(&pool, "audit-walk", "audit-test-entitled", true).await;
        for i in 0..6 {
            seed_audit_row(&pool, "audit-walk", &format!("walk-{i}"), "probe.walk").await;
        }
        let expected: Vec<String> = sqlx::query_scalar(
            "SELECT id FROM audit_logs WHERE tenant_id = 'audit-walk'
             ORDER BY timestamp DESC, id DESC",
        )
        .fetch_all(&pool)
        .await
        .expect("expected order");

        let mut seen = Vec::new();
        let mut cursor: Option<String> = None;
        loop {
            let params = TenantAuditQuery {
                cursor: cursor.clone(),
                limit: 1,
                ..query()
            };
            let (headers, Json(entries)) = list_audit_logs(
                State(state.clone()),
                auth("audit-walk", &["audit:read"]),
                Query(params),
            )
            .await
            .expect("cursor page");
            if entries.is_empty() {
                break;
            }
            seen.push(entries[0].id.clone());
            cursor = Some(
                headers
                    .get("x-next-cursor")
                    .expect("non-empty page mints a cursor")
                    .to_str()
                    .unwrap()
                    .to_string(),
            );
        }
        assert_eq!(seen, expected, "cursor walk must equal the DB order");
        assert_eq!(
            seen.iter().collect::<std::collections::HashSet<_>>().len(),
            seen.len(),
            "no duplicates"
        );
    }

    /// The export streams only the caller's rows, in the requested format,
    /// and the same entitlement/scope gates apply.
    #[tokio::test]
    async fn export_streams_scoped_csv_and_jsonl() {
        let Some(pool) = crate::test_db::canonical_pool("audit_export").await else {
            return;
        };
        let state = crate::app::test_support::test_state_over(pool.clone()).await;
        seed_tenant_with_plan(&pool, "audit-exp", "audit-test-entitled", true).await;
        seed_tenant_with_plan(&pool, "audit-other", "audit-test-entitled", true).await;
        seed_audit_row(&pool, "audit-exp", "exp-1", "probe.export").await;
        seed_audit_row(&pool, "audit-other", "other-1", "probe.export").await;

        let response = export_audit_logs(
            State(state.clone()),
            auth("audit-exp", &["audit:read"]),
            Query(TenantAuditExportQuery {
                action: None,
                resource: None,
                from: None,
                to: None,
                format: ExportFormat::Csv,
                limit: 100,
            }),
        )
        .await
        .expect("csv export");
        assert_eq!(response.status(), axum::http::StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body");
        let csv = String::from_utf8(body.to_vec()).expect("utf8");
        assert!(csv.starts_with("id,timestamp,action,"), "{csv}");
        assert!(csv.contains("exp-1"), "{csv}");
        assert!(!csv.contains("other-1"), "cross-tenant leak: {csv}");
        // The export records itself (`audit.trail.exported`) for later
        // reads; that row's timestamp falls after this stream's window end,
        // so it is deliberately not asserted in the same body.

        let response = export_audit_logs(
            State(state.clone()),
            auth("audit-exp", &["audit:read"]),
            Query(TenantAuditExportQuery {
                action: None,
                resource: None,
                from: None,
                to: None,
                format: ExportFormat::Jsonl,
                limit: 100,
            }),
        )
        .await
        .expect("jsonl export");
        let body = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body");
        let lines: Vec<serde_json::Value> = String::from_utf8(body.to_vec())
            .expect("utf8")
            .lines()
            .map(|line| serde_json::from_str(line).expect("jsonl line"))
            .collect();
        assert!(
            lines.iter().any(|line| line["id"] == "exp-1"),
            "the seeded row must be exported: {lines:?}"
        );
        assert!(
            lines.iter().all(|line| line["tenantId"] == "audit-exp"),
            "cross-tenant leak: {lines:?}"
        );

        // A non-entitled tenant is refused before any stream starts.
        seed_tenant_with_plan(&pool, "audit-exp-free", "audit-test-free", false).await;
        let refused = export_audit_logs(
            State(state),
            auth("audit-exp-free", &["audit:read"]),
            Query(TenantAuditExportQuery {
                action: None,
                resource: None,
                from: None,
                to: None,
                format: ExportFormat::Csv,
                limit: 100,
            }),
        )
        .await;
        assert!(
            matches!(refused, Err(ApiError::Forbidden(message)) if message.contains("audit_logs"))
        );
    }
}
