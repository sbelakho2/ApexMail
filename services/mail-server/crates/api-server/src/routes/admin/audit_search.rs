//! Full-text search across audit logs with CSV export.
//!
//! Provides:
//! - GET  /v1/admin/audit/search  — ranked FTS with tsvector/tsquery
//! - POST /v1/admin/audit/export  — CSV export of filtered audit logs

// Stream combinators (chain) resolve against futures, not Iterator.
use futures::StreamExt as _;

use axum::extract::{Query, State};
use axum::http::header;
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

use crate::error::ApiError;
use crate::middleware::auth::AuthUser;
use crate::routes::helpers::{decode_cursor, encode_cursor};
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/search", get(audit_search))
        .route("/export", post(audit_export))
}

// ─── Keyset cursor helpers ─────────────────────────────────────
//
// The search cursor encodes the `(rank, timestamp, id)` triple of the last
// row of the previous page — the exact leading tuple of the ORDER BY. The
// rank component matters for the FTS path (ranked relevance ordering); on
// the non-FTS path every row's rank is the constant 0.0, so the triple
// degenerates to the plain (timestamp, id) keyset. The tie-break
// `... = $r AND (timestamp = $t AND id < $id)` makes the ordering total.

/// Separator inside the hex-encoded cursor payload (RFC3339, f64 text and
/// audit ids never contain it).
const KEYSET_CURSOR_SEP: char = '\n';

/// Encode a `(rank, timestamp, id)` keyset cursor as an opaque hex string.
///
/// The timestamp MUST be rendered with `to_rfc3339()` and the rank with
/// `f64`'s shortest round-trip `Display` — `parse::<f64>()` reads back the
/// exact same value.
fn encode_search_cursor(rank: f64, timestamp: &DateTime<Utc>, id: &str) -> String {
    encode_cursor(&format!(
        "{rank}{KEYSET_CURSOR_SEP}{}{KEYSET_CURSOR_SEP}{id}",
        timestamp.to_rfc3339()
    ))
}

/// Decode and validate a `(rank, timestamp, id)` keyset cursor. Malformed
/// encodings, unparsable numbers/timestamps, NaN ranks, or ids that cannot
/// name an audit row are client errors (400) — an unvalidated cursor could
/// otherwise surface as a database error.
fn decode_search_cursor(encoded: &str) -> Result<(f64, DateTime<Utc>, String), ApiError> {
    let Some(decoded) = decode_cursor(encoded) else {
        return Err(ApiError::BadRequest(
            "invalid cursor: malformed encoding".into(),
        ));
    };
    let mut parts = decoded.split(KEYSET_CURSOR_SEP);
    let parse_error = |field: &str| {
        ApiError::BadRequest(format!("invalid cursor: malformed {field}"))
    };
    let rank: f64 = parts
        .next()
        .and_then(|rank| rank.parse::<f64>().ok())
        .ok_or_else(|| parse_error("rank"))?;
    if rank.is_nan() {
        return Err(parse_error("rank"));
    }
    let timestamp = parts
        .next()
        .and_then(|ts| DateTime::parse_from_rfc3339(ts).ok())
        .ok_or_else(|| parse_error("timestamp"))?
        .with_timezone(&Utc);
    let id = parts.next().ok_or_else(|| parse_error("row id"))?;
    // The writers produce identifier-shaped ids (UUID text and short
    // prefixed forms): bounded and restricted to ASCII identifier
    // characters — SQL metacharacters are refused at the boundary even
    // though every use binds the value as a parameter.
    if id.is_empty()
        || id.len() > 128
        || !id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b':'))
    {
        return Err(parse_error("row id"));
    }
    if parts.next().is_some() {
        return Err(ApiError::BadRequest(
            "invalid cursor: unexpected trailing payload".into(),
        ));
    }
    Ok((rank, timestamp, id.to_string()))
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuditSearchQuery {
    pub q: Option<String>,
    pub tenant_id: Option<String>,
    pub action: Option<String>,
    pub from: Option<String>,
    pub to: Option<String>,
    #[serde(default = "default_search_limit")]
    pub limit: i64,
    #[serde(default)]
    pub offset: i64,
    /// Opaque keyset cursor (hex `(rank, timestamp, id)` triple) returned
    /// in the previous page's `nextCursor`. When present it wins over
    /// `offset`.
    #[serde(default)]
    pub cursor: Option<String>,
}

fn default_search_limit() -> i64 {
    50
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuditExportRequest {
    pub q: Option<String>,
    pub tenant_id: Option<String>,
    pub action: Option<String>,
    pub from: Option<String>,
    pub to: Option<String>,
    #[serde(default = "default_export_limit")]
    pub limit: i64,
}

fn default_export_limit() -> i64 {
    10_000
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditSearchResponse {
    pub results: Vec<AuditSearchResult>,
    pub total: i64,
    pub limit: i64,
    pub offset: i64,
    /// Whether a further page exists beyond this one.
    pub has_more: bool,
    /// Opaque keyset cursor for the next page, present whenever this page
    /// returned at least one row.
    pub next_cursor: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditSearchResult {
    pub id: String,
    pub timestamp: String,
    pub action: String,
    pub resource: String,
    pub resource_id: Option<String>,
    pub user_id: Option<String>,
    pub tenant_id: Option<String>,
    pub ip_address: Option<String>,
    pub rank: f64,
    pub highlights: serde_json::Value,
}

fn parse_optional_timestamp(raw: &str, field: &str) -> Result<DateTime<Utc>, ApiError> {
    DateTime::parse_from_rfc3339(raw)
        .map(|ts| ts.with_timezone(&Utc))
        .map_err(|_| {
            ApiError::Validation(vec![format!("{field} must be a valid RFC3339 timestamp")])
        })
}

const DEFAULT_SEARCH_WINDOW_DAYS: i64 = 30;
const MAX_SEARCH_WINDOW_DAYS: i64 = 90;

/// Resolve the [from, to] window shared by search, count and export.
/// Mirrors `audit.rs::resolve_audit_window`: inverted ranges and windows
/// wider than 90 days are validation errors (an unbounded window would
/// otherwise scan the whole audit history).
fn resolve_search_window(
    from: Option<&str>,
    to: Option<&str>,
    now: DateTime<Utc>,
) -> Result<(DateTime<Utc>, DateTime<Utc>), ApiError> {
    let window_end = to
        .map(|value| parse_optional_timestamp(value, "to"))
        .transpose()?
        .unwrap_or(now);
    let window_start = from
        .map(|value| parse_optional_timestamp(value, "from"))
        .transpose()?
        .unwrap_or(window_end - Duration::days(DEFAULT_SEARCH_WINDOW_DAYS));

    if window_start > window_end {
        return Err(ApiError::Validation(vec!["from must be before to".into()]));
    }
    if window_end - window_start > Duration::days(MAX_SEARCH_WINDOW_DAYS) {
        return Err(ApiError::Validation(vec![format!(
            "audit search window cannot exceed {MAX_SEARCH_WINDOW_DAYS} days"
        )]));
    }

    Ok((window_start, window_end))
}

/// Fully-rendered query pair for the search endpoint. Each query owns its
/// OWN bind list covering every placeholder after the two window
/// timestamps — the executors bind exactly `window_start, window_end,
/// ..binds (, limit, offset for the row query)` and nothing else, so the
/// placeholder count and the bind count can never diverge (the previous
/// shape re-bound tenant_id/action in the executors on top of the
/// builder's binds — a guaranteed parameter-count 500).
#[derive(Debug)]
struct AuditSearchPlan {
    search_sql: String,
    search_binds: Vec<String>,
    count_sql: String,
    count_binds: Vec<String>,
    window_start: DateTime<Utc>,
    window_end: DateTime<Utc>,
    limit: i64,
    offset: i64,
    /// Decoded keyset cursor. When present it wins over `offset`: the SQL
    /// carries a `(rank, timestamp, id)` strictly-less tuple predicate and
    /// no OFFSET clause.
    keyset: Option<(f64, DateTime<Utc>, String)>,
    /// Whether the FTS arm rendered the SQL (the keyset bind shape differs:
    /// the FTS predicate also takes the decoded rank).
    fts: bool,
}

fn build_search_plan(
    params: &AuditSearchQuery,
    now: DateTime<Utc>,
) -> Result<AuditSearchPlan, ApiError> {
    let has_fts = params.q.as_ref().is_some_and(|q| !q.trim().is_empty());
    let (window_start, window_end) =
        resolve_search_window(params.from.as_deref(), params.to.as_deref(), now)?;
    // A cursor wins over offset. Both halves are validated BEFORE binding —
    // a bogus cursor must be a client 400, never a database cast error.
    let keyset = match params.cursor.as_deref() {
        Some(encoded) => Some(decode_search_cursor(encoded)?),
        None => None,
    };

    let mut conditions: Vec<String> = vec!["timestamp >= $1".into(), "timestamp <= $2".into()];
    let mut filter_idx = 3u32;
    let mut filter_binds: Vec<String> = Vec::new();

    if let Some(ref tenant_id) = params.tenant_id {
        conditions.push(format!("tenant_id = ${filter_idx}"));
        filter_idx += 1;
        filter_binds.push(tenant_id.clone());
    }

    if let Some(ref action) = params.action {
        conditions.push(format!("action = ${filter_idx}"));
        filter_idx += 1;
        filter_binds.push(action.clone());
    }

    let where_clause = format!("WHERE {}", conditions.join(" AND "));
    let limit = params.limit.clamp(1, 200);
    let offset = params.offset.max(0);

    // Both orderings are the total (rank, timestamp, id) DESC tuple: the FTS
    // path ranks by relevance, the non-FTS path gives every row the constant
    // rank 0.0 — so the id tie-break is what keeps rows that share a
    // timestamp from being skipped or duplicated across page boundaries.
    let (search_sql, search_binds, has_fts_plan) = if has_fts {
        let q = params.q.as_deref().unwrap_or("").trim().to_string();
        let tsquery_param = filter_idx;
        let mut binds = filter_binds.clone();
        binds.push(q);
        // The rank expression is spelled out everywhere it is referenced —
        // the keyset predicate cannot use the output alias, and every
        // re-reference reuses the SAME tsquery bind parameter.
        let rank_expr =
            format!("ts_rank(fts_vector, plainto_tsquery('english', ${tsquery_param}))::double precision");
        let paging = if keyset.is_some() {
            // Keyset path: strictly-less tuple comparison over the same
            // (rank, timestamp, id) tuple the ORDER BY uses. The VALUE side
            // of every comparison is a bound parameter; the tsquery
            // placeholder is re-referenced, never re-bound.
            let rank_param = filter_idx + 1;
            let ts_param = filter_idx + 2;
            let id_param = filter_idx + 3;
            let limit_param = filter_idx + 4;
            format!(
                "       AND ({rank_expr} < ${rank_param}
                    OR ({rank_expr} = ${rank_param}
                        AND (timestamp < ${ts_param}
                             OR (timestamp = ${ts_param} AND id < ${id_param}))))
                 ORDER BY rank DESC, timestamp DESC, id DESC
                 LIMIT ${limit_param}"
            )
        } else {
            format!(
                "       ORDER BY rank DESC, timestamp DESC, id DESC
                 LIMIT ${} OFFSET ${}",
                filter_idx + 1,
                filter_idx + 2
            )
        };
        let sql = format!(
            "SELECT id, timestamp, action, resource, resource_id,
                    user_id, tenant_id, ip_address, details,
                    {rank_expr} as rank,
                    ts_headline('english', coalesce(details::text, ''), plainto_tsquery('english', ${tsquery_param}), 'MaxWords=50, MinWords=10, ShortWord=3') as headline
             FROM audit_logs
             {where_clause}
               AND fts_vector @@ plainto_tsquery('english', ${tsquery_param})
            {paging}"
        );
        (sql, binds, true)
    } else {
        let ts_param = filter_idx;
        let id_param = filter_idx + 1;
        let paging = if keyset.is_some() {
            // Non-FTS rank is the constant 0.0 for every row, so the tuple
            // keyset degenerates to the plain (timestamp, id) comparison.
            format!(
                "       AND (timestamp < ${ts_param}
                    OR (timestamp = ${ts_param} AND id < ${id_param}))
                 ORDER BY rank DESC, timestamp DESC, id DESC
                 LIMIT ${}",
                filter_idx + 2
            )
        } else {
            format!(
                "       ORDER BY rank DESC, timestamp DESC, id DESC
                 LIMIT ${ts_param} OFFSET ${id_param}"
            )
        };
        let sql = format!(
            "SELECT id, timestamp, action, resource, resource_id,
                    user_id, tenant_id, ip_address, details,
                    0.0::double precision as rank,
                    '' as headline
             FROM audit_logs
             {where_clause}
            {paging}"
        );
        (sql, filter_binds.clone(), false)
    };

    // The count query repeats the filter binds; with FTS active the
    // plainto_tsquery placeholder is the final bind (no LIMIT/OFFSET).
    let (count_sql, count_binds) = if has_fts {
        let q = params.q.as_deref().unwrap_or("").trim().to_string();
        let tsquery_param = filter_idx;
        let mut binds = filter_binds;
        binds.push(q);
        (
            format!(
                "SELECT COUNT(*) FROM audit_logs
                 {where_clause}
                   AND fts_vector @@ plainto_tsquery('english', ${tsquery_param})"
            ),
            binds,
        )
    } else {
        (
            format!("SELECT COUNT(*) FROM audit_logs {where_clause}"),
            filter_binds,
        )
    };

    Ok(AuditSearchPlan {
        search_sql,
        search_binds,
        count_sql,
        count_binds,
        window_start,
        window_end,
        limit,
        offset,
        keyset,
        fts: has_fts_plan,
    })
}

async fn audit_search(
    State(state): State<AppState>,
    auth: AuthUser,
    Query(params): Query<AuditSearchQuery>,
) -> Result<Json<AuditSearchResponse>, ApiError> {
    crate::middleware::auth::require_scopes(&auth, &["*"])?;
    crate::middleware::auth::require_system_tenant(&state, &auth).await?;

    let plan = build_search_plan(&params, Utc::now())?;

    // Run count and search concurrently. Both executors bind from the SAME
    // plan — the search row query appends either the keyset tuple + LIMIT
    // or the LIMIT/OFFSET pair as its final binds.
    let (count_result, search_page) = tokio::try_join!(
        execute_count(&state.db, &plan),
        execute_search(&state.db, &plan),
    )?;
    let (results, has_more, next_cursor) = search_page;

    Ok(Json(AuditSearchResponse {
        results,
        total: count_result,
        limit: plan.limit,
        offset: plan.offset,
        has_more,
        next_cursor,
    }))
}

async fn execute_count(db: &sqlx::PgPool, plan: &AuditSearchPlan) -> Result<i64, ApiError> {
    let mut query = sqlx::query_scalar::<_, i64>(&plan.count_sql)
        .bind(plan.window_start)
        .bind(plan.window_end);

    for bind in &plan.count_binds {
        query = query.bind(bind);
    }

    Ok(query.fetch_one(db).await?)
}

/// One fetched search row before DTO mapping.
type SearchRow = (
    String,
    chrono::DateTime<chrono::Utc>,
    String,
    String,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<serde_json::Value>,
    f64,
    String,
);

/// Execute the search row query and resolve the keyset continuation:
/// fetches `limit + 1` rows, truncates to `limit` and reports `(rows,
/// has_more, next_cursor)` — the cursor minted from the last KEPT row's
/// `(rank, timestamp, id)` tuple.
#[allow(clippy::type_complexity)]
async fn execute_search(
    db: &sqlx::PgPool,
    plan: &AuditSearchPlan,
) -> Result<(Vec<AuditSearchResult>, bool, Option<String>), ApiError> {
    let fetch_limit = plan.limit + 1; // one extra row to detect has_more

    let mut query = sqlx::query_as::<_, SearchRow>(&plan.search_sql)
        .bind(plan.window_start)
        .bind(plan.window_end);

    for bind in &plan.search_binds {
        query = query.bind(bind);
    }
    if let Some((rank, ref ts, ref id)) = plan.keyset {
        // Keyset binds follow the filters + q; the FTS arm additionally
        // takes the decoded rank. LIMIT is always the final bind.
        if plan.fts {
            query = query.bind(rank);
        }
        query = query.bind(ts).bind(id).bind(fetch_limit);
    } else {
        query = query.bind(fetch_limit).bind(plan.offset);
    }

    let rows: Vec<SearchRow> = query.fetch_all(db).await?;

    let more = rows.len() as i64 > plan.limit;
    let kept = if more {
        plan.limit as usize
    } else {
        rows.len()
    };
    // The next cursor is the (rank, timestamp, id) tuple of the last KEPT
    // row — the exact position this page stopped at.
    let next_cursor = if kept > 0 {
        let (id, ts, .., rank, _) = &rows[kept - 1];
        Some(encode_search_cursor(*rank, ts, id))
    } else {
        None
    };

    let results = rows
        .into_iter()
        .take(kept)
        .map(
            |(
                id,
                ts,
                action,
                resource,
                resource_id,
                user_id,
                tenant_id,
                ip,
                details,
                rank,
                headline,
            )| {
                AuditSearchResult {
                    id,
                    timestamp: ts.to_rfc3339(),
                    action,
                    resource,
                    resource_id,
                    user_id,
                    tenant_id,
                    ip_address: ip,
                    rank,
                    highlights: serde_json::json!({
                        "headline": headline,
                        "details": details.unwrap_or(serde_json::json!({})),
                    }),
                }
            },
        )
        .collect();

    Ok((results, more, next_cursor))
}

// ─── CSV Export ────────────────────────────────────────────

/// Audit export row shape (timestamp .. error_message).
type AuditExportRow = (
    chrono::DateTime<chrono::Utc>,
    String,
    String,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    String,
    Option<String>,
);

/// One CSV record as bytes. A fresh per-row writer is stateless and correct:
/// `write_record` emits a complete, self-delimited, properly quoted record,
/// so records can be streamed independently of each other.
fn csv_record_bytes(header: bool, row: Option<&AuditExportRow>) -> Result<Vec<u8>, std::io::Error> {
    let mut writer = csv::Writer::from_writer(Vec::new());
    if header {
        writer.write_record([
            "timestamp",
            "action",
            "resource",
            "resource_id",
            "user_id",
            "tenant_id",
            "ip_address",
            "outcome",
            "error_message",
        ])?;
    } else if let Some((
        timestamp,
        action,
        resource,
        resource_id,
        user_id,
        tenant_id,
        ip_address,
        outcome,
        error_message,
    )) = row
    {
        writer.write_record([
            timestamp.to_rfc3339(),
            action.clone(),
            resource.clone(),
            resource_id.clone().unwrap_or_default(),
            user_id.clone().unwrap_or_default(),
            tenant_id.clone().unwrap_or_default(),
            ip_address.clone().unwrap_or_default(),
            outcome.clone(),
            error_message.clone().unwrap_or_default(),
        ])?;
    }
    writer.flush()?;
    writer.into_inner().map_err(std::io::Error::other)
}

async fn audit_export(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(body): Json<AuditExportRequest>,
) -> Result<impl IntoResponse, ApiError> {
    crate::middleware::auth::require_scopes(&auth, &["*"])?;
    crate::middleware::auth::require_system_tenant(&state, &auth).await?;

    let (window_start, window_end) =
        resolve_search_window(body.from.as_deref(), body.to.as_deref(), Utc::now())?;
    let limit = body.limit.clamp(1, 50_000);

    // The export itself is audited (P2): an unaudited bulk export of the
    // compliance trail is precisely the read the trail exists to record.
    crate::audit_log::insert_audit_log_best_effort_with_env(
        &state.db,
        state.config.environment.is_production(),
        Some(auth.tenant_id.as_str()),
        auth.user_id.as_deref(),
        "control_plane.audit.exported",
        "audit_log",
        None,
        serde_json::json!({
            "filters": {
                "q": body.q,
                "tenantId": body.tenant_id,
                "action": body.action,
                "from": body.from,
                "to": body.to,
            },
            "limit": limit,
            "windowStart": window_start.to_rfc3339(),
            "windowEnd": window_end.to_rfc3339(),
        }),
        None,
        None,
    )
    .await;

    // Chunked streaming body (P2): the previous shape buffered up to 50k
    // rows (and the whole CSV) in memory before responding. Rows are now
    // fetched in bounded chunks (keyed by OFFSET on the same ordered query)
    // and each chunk flushed as one body write; a mid-stream DB error ends
    // the response instead of blocking on full materialization.
    let chunk_state = ExportChunkState {
        pool: state.db.clone(),
        tenant_id: body.tenant_id.clone(),
        action: body.action.clone(),
        q: body
            .q
            .as_ref()
            .map(|q| q.trim().to_string())
            .filter(|q| !q.is_empty()),
        window_start,
        window_end,
        offset: 0,
        remaining: limit,
    };

    let body_stream = futures::stream::once(async { csv_record_bytes(true, None) })
        .chain(export_chunk_stream(chunk_state));

    let filename = format!("audit_export_{}.csv", Utc::now().format("%Y%m%dT%H%M%SZ"));

    let disposition_value =
        axum::http::HeaderValue::from_str(&format!("attachment; filename=\"{filename}\""))
            .map_err(|e| ApiError::Internal(e.to_string()))?;

    let mut response = (
        [(header::CONTENT_TYPE, "text/csv; charset=utf-8")],
        axum::body::Body::from_stream(body_stream),
    )
        .into_response();
    response
        .headers_mut()
        .insert(header::CONTENT_DISPOSITION, disposition_value);
    Ok(response)
}

/// Rows fetched per chunk — bounded memory per step while keeping the
/// per-query bind count trivial.
const EXPORT_CHUNK_ROWS: i64 = 1_000;

/// Owned state for the chunked export stream. Every field is owned (no
/// borrows of handler locals): the stream outlives the handler.
struct ExportChunkState {
    pool: sqlx::PgPool,
    tenant_id: Option<String>,
    action: Option<String>,
    q: Option<String>,
    window_start: DateTime<Utc>,
    window_end: DateTime<Utc>,
    offset: i64,
    remaining: i64,
}

/// Render the WHERE clause shared by every chunk; parameter order is
/// window-start, window-end, then optional tenant/action/fts binds, then
/// LIMIT and OFFSET — binds MUST follow exactly that sequence.
fn build_export_chunk_conditions(state: &ExportChunkState) -> String {
    let mut conditions: Vec<String> = vec!["timestamp >= $1".into(), "timestamp <= $2".into()];
    if state.tenant_id.is_some() {
        conditions.push("tenant_id = $3".into());
    }
    if state.action.is_some() {
        let idx = 3 + usize::from(state.tenant_id.is_some());
        conditions.push(format!("action = ${idx}"));
    }
    if state.q.is_some() {
        let idx = 3 + usize::from(state.tenant_id.is_some()) + usize::from(state.action.is_some());
        conditions.push(format!("fts_vector @@ plainto_tsquery('english', ${idx})"));
    }
    conditions.join(" AND ")
}

/// Chunk stream over [`ExportChunkState`].
///
/// Built with `futures::stream::unfold` and NOT a hand-written
/// `futures::Stream` impl: a manual `poll_next` that constructs the chunk
/// query future inline (as this stream originally did) polls it ONCE and
/// then drops it. A Postgres fetch is pending at that first poll, so the
/// future — and the waker it registered — was destroyed before completion
/// and nothing ever re-polled the stream: `/v1/admin/audit/export` hung
/// forever on its first chunk. `unfold` owns the async block across polls,
/// making the Pending → wake → re-poll contract the executor's, not ours.
fn export_chunk_stream(
    state: ExportChunkState,
) -> impl futures::Stream<Item = Result<Vec<u8>, std::io::Error>> {
    futures::stream::unfold(state, |mut state| async move {
        if state.remaining <= 0 {
            return None;
        }
        let chunk_limit = state.remaining.min(EXPORT_CHUNK_ROWS);

        let conditions = build_export_chunk_conditions(&state);
        let filter_count = usize::from(state.tenant_id.is_some())
            + usize::from(state.action.is_some())
            + usize::from(state.q.is_some());
        let limit_idx = 3 + filter_count;
        let offset_idx = limit_idx + 1;
        let sql = format!(
            "SELECT timestamp, action, resource, resource_id, user_id, tenant_id, \
             ip_address, outcome, error_message
             FROM audit_logs
             WHERE {conditions}
             ORDER BY timestamp DESC
             LIMIT ${limit_idx} OFFSET ${offset_idx}"
        );

        let mut query = sqlx::query_as::<_, AuditExportRow>(&sql)
            .bind(state.window_start)
            .bind(state.window_end);
        if let Some(ref tenant_id) = state.tenant_id {
            query = query.bind(tenant_id.clone());
        }
        if let Some(ref action) = state.action {
            query = query.bind(action.clone());
        }
        if let Some(ref q) = state.q {
            query = query.bind(q.clone());
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
                    // Last chunk: stop the stream after draining it.
                    state.remaining = 0;
                }
                if rows.is_empty() {
                    return None;
                }
                let mut buffer = Vec::with_capacity(rows.len() * 128);
                for row in &rows {
                    match csv_record_bytes(false, Some(row)) {
                        Ok(record) => buffer.extend_from_slice(&record),
                        Err(error) => return Some((Err(error), state)),
                    }
                }
                Some((Ok(buffer), state))
            }
            Err(error) => {
                // End the body after surfacing the failure — a truncated,
                // error-terminated download beats a hung one.
                state.remaining = 0;
                Some((Err(std::io::Error::other(error)), state))
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Highest `$N` placeholder index in a rendered query.
    fn max_placeholder(sql: &str) -> usize {
        let mut max = 0usize;
        let bytes = sql.as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            if bytes[i] == b'$' {
                let mut j = i + 1;
                while j < bytes.len() && bytes[j].is_ascii_digit() {
                    j += 1;
                }
                if j > i + 1 {
                    if let Ok(n) = sql[i + 1..j].parse::<usize>() {
                        max = max.max(n);
                    }
                    i = j;
                    continue;
                }
            }
            i += 1;
        }
        max
    }

    /// Search with tenantId/action filters set previously produced a
    /// parameter-count mismatch (the filters were bound by the query
    /// builders AND re-bound by the executors) — a guaranteed 500. The
    /// rendered SQL's placeholder count and the executed bind sequence
    /// must agree exactly, with every filter bound once.
    #[tokio::test]
    async fn filtered_search_executes_without_parameter_mismatch() {
        let Some(pool) = crate::test_db::canonical_pool("audit_search_binds").await else {
            eprintln!("skipping filtered_search_executes_without_parameter_mismatch: no TEST_DATABASE_URL");
            return;
        };
        sqlx::raw_sql(
            "CREATE TABLE IF NOT EXISTS audit_logs (
                id TEXT PRIMARY KEY,
                tenant_id TEXT,
                user_id TEXT,
                action TEXT NOT NULL,
                resource TEXT NOT NULL,
                resource_id TEXT,
                details JSONB NOT NULL DEFAULT '{}'::jsonb,
                ip_address TEXT,
                user_agent TEXT,
                outcome TEXT,
                error_message TEXT,
                timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                fts_vector tsvector
            )",
        )
        .execute(&pool)
        .await
        .expect("audit_logs fixture DDL must apply");
        for n in 0..3 {
            sqlx::query(
                "INSERT INTO audit_logs (id, tenant_id, action, resource, details, timestamp, fts_vector,
                                         outcome, hash, signature)
                 VALUES ($1, 'tenant-a', 'user.login', 'session', '{\"who\":\"admin\"}'::jsonb, NOW() - make_interval(mins => $2),
                         to_tsvector('english', 'user.login session admin'),
                         'success', 'seed-hash', 'seed-signature')",
            )
            .bind(format!("row-{n}"))
            .bind(n)
            .execute(&pool)
            .await
            .expect("seed audit row");
        }

        let params = AuditSearchQuery {
            q: Some("admin".into()),
            tenant_id: Some("tenant-a".into()),
            action: Some("user.login".into()),
            from: None,
            to: None,
            limit: 10,
            offset: 0,
            cursor: None,
        };
        let plan = build_search_plan(&params, Utc::now()).expect("search plan");
        // tenant + action + q binds must match each query's placeholders
        // exactly (the row query appends the LIMIT/OFFSET pair).
        assert_eq!(
            max_placeholder(&plan.search_sql),
            2 + plan.search_binds.len() + 2,
            "search SQL placeholders must equal window(2) + binds + limit/offset"
        );
        assert_eq!(
            max_placeholder(&plan.count_sql),
            2 + plan.count_binds.len(),
            "count SQL placeholders must equal window(2) + binds"
        );

        let count = execute_count(&pool, &plan)
            .await
            .expect("count query must execute (no parameter mismatch)");
        assert_eq!(count, 3);
        let (results, more, cursor) = execute_search(&pool, &plan)
            .await
            .expect("search query must execute (no parameter mismatch)");
        assert_eq!(results.len(), 3);
        assert!(!more, "3 rows under limit 10 is a final page");
        assert!(cursor.is_some(), "a non-empty page mints a cursor");
    }

    /// Streamed export records are self-contained CSV lines: quoting of
    /// embedded separators/newlines must survive the per-row writer.
    #[test]
    fn csv_record_bytes_quotes_embedded_separators() {
        let header = csv_record_bytes(true, None).expect("header renders");
        let header_str = String::from_utf8(header).unwrap();
        assert!(header_str.starts_with("timestamp,action,resource"));

        let row = (
            Utc::now(),
            "user.login".into(),
            "session".into(),
            Some("id,with,commas".into()),
            None,
            Some("tenant-a".into()),
            Some("203.0.113.9".into()),
            "success".into(),
            Some("boom\nsecond line".into()),
        );
        let record = csv_record_bytes(false, Some(&row)).expect("record renders");
        let record_str = String::from_utf8(record).unwrap();
        assert!(record_str.contains("\"id,with,commas\""));
        assert!(record_str.contains("\"boom\nsecond line\""));
        assert_eq!(
            record_str.lines().count(),
            2,
            "embedded newline stays quoted"
        );
    }

    /// Time-window parity with the audit list route: an unbounded window
    /// must be rejected, not silently scanned.
    #[test]
    fn search_window_is_capped_at_ninety_days() {
        let now = Utc::now();
        let params = AuditSearchQuery {
            q: None,
            tenant_id: None,
            action: None,
            from: Some((now - Duration::days(120)).to_rfc3339()),
            to: Some(now.to_rfc3339()),
            limit: 10,
            offset: 0,
            cursor: None,
        };
        assert!(
            matches!(
                build_search_plan(&params, now),
                Err(ApiError::Validation(errors)) if errors.len() == 1
                    && errors[0].contains("90 days"),
            ),
            "a 120-day window must be rejected"
        );
        assert!(
            build_search_plan(
                &AuditSearchQuery {
                    q: None,
                    tenant_id: None,
                    action: None,
                    from: Some((now - Duration::days(89)).to_rfc3339()),
                    to: Some(now.to_rfc3339()),
                    limit: 10,
                    offset: 0,
                    cursor: None,
                },
                now,
            )
            .is_ok(),
            "an 89-day window must be accepted"
        );
    }

    /// The keyset cursor decoder's refusal arms + a round trip through the
    /// encoder (shortest-round-trip f64 rank, RFC3339 timestamp, TEXT id).
    #[test]
    fn search_cursor_decode_rejects_every_malformed_shape() {
        // Not even hex.
        assert!(matches!(
            decode_search_cursor("zz"),
            Err(ApiError::BadRequest(message)) if message.contains("malformed encoding")
        ));
        // Wrong part count: a single-part payload has no rank separator, so
        // the FIRST field (rank) is what fails to parse.
        assert!(matches!(
            decode_search_cursor(&encode_cursor("no-separator-here")),
            Err(ApiError::BadRequest(message)) if message.contains("malformed rank")
        ));
        assert!(matches!(
            decode_search_cursor(&encode_cursor("1.5\n2026-01-01T00:00:00Z\nid\nextra")),
            Err(ApiError::BadRequest(message))
                if message.contains("trailing payload")
        ));
        // Non-numeric / NaN rank.
        let bad_rank = encode_cursor(&format!(
            "not-a-number{KEYSET_CURSOR_SEP}2026-01-01T00:00:00Z{KEYSET_CURSOR_SEP}row-id"
        ));
        assert!(matches!(
            decode_search_cursor(&bad_rank),
            Err(ApiError::BadRequest(message)) if message.contains("malformed rank")
        ));
        let nan_rank = encode_cursor(&format!(
            "NaN{KEYSET_CURSOR_SEP}2026-01-01T00:00:00Z{KEYSET_CURSOR_SEP}row-id"
        ));
        assert!(matches!(
            decode_search_cursor(&nan_rank),
            Err(ApiError::BadRequest(message)) if message.contains("malformed rank")
        ));
        // Bad timestamp.
        let bad_ts = encode_cursor(&format!(
            "1.5{KEYSET_CURSOR_SEP}not-a-time{KEYSET_CURSOR_SEP}row-id"
        ));
        assert!(matches!(
            decode_search_cursor(&bad_ts),
            Err(ApiError::BadRequest(message)) if message.contains("malformed timestamp")
        ));
        // Malformed row ids: empty, over 128 bytes, control characters,
        // SQL metacharacters.
        for bad_id in [
            "",
            &"i".repeat(129),
            "bad\u{7}id",
            "x'; DROP TABLE audit_logs; --",
        ] {
            let cursor = encode_cursor(&format!(
                "1.5{KEYSET_CURSOR_SEP}2026-01-01T00:00:00Z{KEYSET_CURSOR_SEP}{bad_id}"
            ));
            assert!(
                matches!(
                    decode_search_cursor(&cursor),
                    Err(ApiError::BadRequest(message)) if message.contains("malformed row id")
                ),
                "id {bad_id:?} must be rejected"
            );
        }
        // A well-formed cursor round-trips bit-exact through the f64 text.
        let ts = Utc::now();
        let rank = 0.06079271525000001f64;
        let (decoded_rank, decoded_ts, decoded_id) =
            decode_search_cursor(&encode_search_cursor(rank, &ts, "row-1"))
                .expect("valid cursor");
        assert_eq!(decoded_rank, rank);
        assert_eq!(decoded_ts, ts);
        assert_eq!(decoded_id, "row-1");
    }
}

#[cfg(test)]
mod adversarial_tests {
    use axum::http::StatusCode;

    use super::encode_cursor;
    use crate::app::test_support::adv::AdvEnv;

    async fn seed_audit_row(
        pool: &sqlx::PgPool,
        tenant_id: &str,
        action: &str,
        details: serde_json::Value,
    ) {
        crate::audit_log::insert_audit_log(
            pool,
            Some(tenant_id),
            None,
            action,
            "probe_resource",
            Some("res-1"),
            details,
            Some("198.51.100.9"),
            Some("probe-agent"),
        )
        .await
        .expect("seed audit row");
    }

    #[tokio::test]
    async fn audit_search_filters_rank_and_paginates() {
        let Some(pool) = crate::test_db::canonical_pool("asearch_main").await else {
            return;
        };
        let env = AdvEnv::admin(pool.clone()).await;
        let tenant = format!("srch{}", &uuid::Uuid::new_v4().simple().to_string()[..16]);
        seed_audit_row(
            &pool,
            &tenant,
            "probe.alpha",
            serde_json::json!({"note": "billing invoice adjustment"}),
        )
        .await;
        seed_audit_row(
            &pool,
            &tenant,
            "probe.beta",
            serde_json::json!({"note": "unrelated content"}),
        )
        .await;
        seed_audit_row(
            &pool,
            "other-tenant",
            "probe.gamma",
            serde_json::json!({"note": "billing"}),
        )
        .await;

        // Full-text search finds the billing rows across tenants.
        let (status, body) = env.get("/v1/admin/audit/search?q=billing").await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let results = body["results"].as_array().cloned().unwrap_or_default();
        assert_eq!(results.len(), 2, "{body}");
        assert!(results
            .iter()
            .all(|r| r["rank"].as_f64().unwrap_or(0.0) > 0.0));
        assert!(results[0]["highlights"]["headline"].is_string());

        // Tenant filter scopes.
        let (status, body) = env
            .get(&format!(
                "/v1/admin/audit/search?tenantId={tenant}&q=billing"
            ))
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["results"].as_array().map(Vec::len), Some(1));
        assert_eq!(body["total"], 1);

        // Action filter (no FTS: rank is exactly 0).
        let (status, body) = env.get("/v1/admin/audit/search?action=probe.beta").await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let results = body["results"].as_array().cloned().unwrap_or_default();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0]["action"], "probe.beta");
        assert_eq!(results[0]["rank"], 0.0);
        assert_eq!(results[0]["ipAddress"], "198.51.100.9");

        // Pagination: limit clamps, offset pages, echoes resolved values.
        let (status, body) = env.get("/v1/admin/audit/search?limit=1&offset=1").await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["limit"], 1);
        assert_eq!(body["offset"], 1);
        assert_eq!(body["results"].as_array().map(Vec::len), Some(1));

        // Hostile params: negative offset floors to 0; huge limit clamps.
        let (status, body) = env
            .get("/v1/admin/audit/search?limit=99999&offset=-9")
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["limit"], 200);
        assert_eq!(body["offset"], 0);
    }

    #[tokio::test]
    async fn audit_search_window_validation() {
        let Some(pool) = crate::test_db::canonical_pool("asearch_window").await else {
            return;
        };
        let env = AdvEnv::admin(pool).await;
        let now = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        let past = (chrono::Utc::now() - chrono::Duration::days(3))
            .to_rfc3339_opts(chrono::SecondsFormat::Secs, true);

        // Malformed timestamps are a 400 naming the field.
        let (status, body) = env.get("/v1/admin/audit/search?from=yesterday").await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert!(body["error"]["details"].as_array().is_some_and(|d| d
            .iter()
            .any(|x| x.as_str().is_some_and(|x| x.contains("from")))));

        // Inverted range.
        let (status, body) = env
            .get(&format!("/v1/admin/audit/search?from={now}&to={past}"))
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");

        // Over-90-day window.
        let far = (chrono::Utc::now() - chrono::Duration::days(91))
            .to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        let (status, body) = env
            .get(&format!("/v1/admin/audit/search?from={far}&to={now}"))
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");

        // Exactly 90 days is fine.
        let edge = (chrono::Utc::now() - chrono::Duration::days(90))
            .to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        let (status, _body) = env
            .get(&format!("/v1/admin/audit/search?from={edge}&to={now}"))
            .await;
        assert_eq!(status, StatusCode::OK);

        // deny_unknown_fields on the query.
        let (status, _body) = env.get("/v1/admin/audit/search?surprise=1").await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn audit_export_streams_csv_and_escapes_and_audits_itself() {
        let Some(pool) = crate::test_db::canonical_pool("aexport").await else {
            return;
        };
        let env = AdvEnv::admin(pool.clone()).await;
        let tenant = format!("exp{}", &uuid::Uuid::new_v4().simple().to_string()[..19]);
        seed_audit_row(
            &pool,
            &tenant,
            "export,probe",
            serde_json::json!({"k": "v"}),
        )
        .await;

        let (status, headers, bytes) = env
            .post_raw(
                "/v1/admin/audit/export",
                &serde_json::json!({ "tenantId": tenant }).to_string(),
            )
            .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "{}",
            String::from_utf8_lossy(&bytes)
        );
        assert_eq!(
            headers.get("content-type").and_then(|v| v.to_str().ok()),
            Some("text/csv; charset=utf-8")
        );
        assert!(headers
            .get("content-disposition")
            .and_then(|v| v.to_str().ok())
            .is_some_and(|d| d.starts_with("attachment; filename=\"audit_export_")));
        let csv = String::from_utf8(bytes).expect("utf8 csv");
        // Header row + the seeded row, with the comma escaped by quoting.
        assert!(csv.starts_with("timestamp,action,resource,"), "{csv}");
        assert!(
            csv.contains("\"export,probe\""),
            "CSV quoting of embedded commas: {csv}"
        );
        assert!(csv.contains(&tenant));

        // The export audited itself.
        let (action,): (String,) = sqlx::query_as(
            "SELECT action FROM audit_logs WHERE action = 'control_plane.audit.exported' LIMIT 1",
        )
        .fetch_one(&pool)
        .await
        .expect("export audit");
        assert_eq!(action, "control_plane.audit.exported");

        // Export window validation mirrors search.
        let now = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        let status = env
            .post_raw(
                "/v1/admin/audit/export",
                &serde_json::json!({ "from": "not-a-time", "to": now }).to_string(),
            )
            .await
            .0;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn audit_search_gates() {
        let Some(pool) = crate::test_db::canonical_pool("asearch_gates").await else {
            return;
        };
        let key =
            crate::app::test_support::seed_api_key_for(&pool, "system", &["audit:read"]).await;
        let scoped = AdvEnv::over(pool.clone(), key).await;
        let (status, body) = scoped.get("/v1/admin/audit/search").await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{body}");

        let (customer, _tenant) = AdvEnv::tenant(pool, &["*"]).await;
        let (status, _body) = customer.get("/v1/admin/audit/search").await;
        assert!(matches!(status, StatusCode::FORBIDDEN));
    }

    const SEARCH_PROBE_SQL: &str = "INSERT INTO audit_logs (id, tenant_id, user_id, action, resource, resource_id, \
         details, ip_address, user_agent, outcome, timestamp, hash, signature, fts_vector)
         SELECT 'cur-' || lpad(g::text, 2, '0') || '-' || substr(gen_random_uuid()::text, 1, 8),
                $1, 'usr_srch', 'probe.search', 'probe_resource', 'res-1',
                $3::jsonb, '198.51.100.9', 'probe-agent', 'success',
                NOW(), 'seed-hash', 'seed-signature',
                to_tsvector('english', $3::text)
         FROM generate_series(0, $2 - 1) AS g";

    /// Page through an FTS-ranked result set one row at a time following
    /// `nextCursor`: the cursor sweep must reproduce the offset sweep
    /// exactly (zero skips/duplicates) even though every seeded row shares
    /// ONE timestamp AND one identical rank — the fully-tied ordering shape
    /// where the id tie-break is the only total component. The tenantId
    /// filter rides every continuation page and `total` stays the full
    /// window count.
    #[tokio::test]
    async fn search_cursor_sweep_matches_offset_and_stays_scoped() {
        let Some(pool) = crate::test_db::canonical_pool("asearch_cursor_sweep").await else {
            return;
        };
        let env = AdvEnv::admin(pool.clone()).await;
        let tenant = format!("srch{}", &uuid::Uuid::new_v4().simple().to_string()[..16]);
        let other = format!("srch{}", &uuid::Uuid::new_v4().simple().to_string()[..16]);

        // SIX matching rows for `tenant` in ONE statement — identical
        // timestamps AND identical fts ranks; plus one matching row of the
        // neighbour tenant and one non-matching row of `tenant`.
        sqlx::query(SEARCH_PROBE_SQL)
            .bind(&tenant)
            .bind(6i64)
            .bind("{\"note\": \"billing invoice adjustment\"}")
            .execute(&pool)
            .await
            .expect("seed probe rows");
        sqlx::query(SEARCH_PROBE_SQL)
            .bind(&other)
            .bind(1i64)
            .bind("{\"note\": \"billing invoice adjustment\"}")
            .execute(&pool)
            .await
            .expect("seed foreign row");
        sqlx::query(SEARCH_PROBE_SQL)
            .bind(&tenant)
            .bind(1i64)
            .bind("{\"note\": \"nothing relevant here\"}")
            .execute(&pool)
            .await
            .expect("seed non-matching row");

        let expected_ids: Vec<String> = sqlx::query_scalar(
            "SELECT id FROM audit_logs WHERE tenant_id = $1
               AND fts_vector @@ plainto_tsquery('english', 'billing')
             ORDER BY ts_rank(fts_vector, plainto_tsquery('english', 'billing'))::double precision DESC,
                      timestamp DESC, id DESC",
        )
        .bind(&tenant)
        .fetch_all(&pool)
        .await
        .expect("expected search order");
        assert_eq!(expected_ids.len(), 6, "six matching rows for the tenant");

        // ── FTS path: cursor walk at limit=1 ────────────────────────
        let mut by_cursor: Vec<String> = Vec::new();
        let mut cursor: Option<String> = None;
        let mut total_on_cursor_pages: Option<i64> = None;
        loop {
            let mut uri = format!("/v1/admin/audit/search?tenantId={tenant}&q=billing&limit=1");
            if let Some(ref cursor) = cursor {
                uri.push_str(&format!("&cursor={cursor}"));
            }
            let (status, body) = env.get(&uri).await;
            assert_eq!(status, StatusCode::OK, "{body}");
            let results = body["results"].as_array().expect("results array");
            if results.is_empty() {
                assert_eq!(body["hasMore"], false);
                break;
            }
            assert_eq!(results.len(), 1);
            assert_eq!(results[0]["tenantId"], tenant, "tenant filter scopes");
            by_cursor.push(results[0]["id"].as_str().unwrap().to_string());
            total_on_cursor_pages = Some(body["total"].as_i64().unwrap());
            // has-more mirrors exactly whether a further row exists.
            assert_eq!(
                body["hasMore"],
                by_cursor.len() < expected_ids.len(),
                "hasMore flipped early or late on page {}",
                by_cursor.len()
            );
            cursor = Some(
                body["nextCursor"]
                    .as_str()
                    .expect("hasMore implies nextCursor")
                    .to_string(),
            );
        }
        assert_eq!(
            by_cursor.iter().collect::<std::collections::HashSet<_>>().len(),
            by_cursor.len(),
            "a cursor sweep must never repeat a row"
        );
        assert_eq!(
            by_cursor, expected_ids,
            "cursor walk vs the same ORDER BY over the table"
        );
        assert_eq!(
            total_on_cursor_pages,
            Some(6),
            "total stays the full window count on cursor pages"
        );

        // ── Legacy offset sweep (backward compat): same rows, same order ──
        let mut by_offset: Vec<String> = Vec::new();
        let mut offset = 0i64;
        loop {
            let (status, body) = env
                .get(&format!(
                    "/v1/admin/audit/search?tenantId={tenant}&q=billing&limit=1&offset={offset}"
                ))
                .await;
            assert_eq!(status, StatusCode::OK, "{body}");
            let results = body["results"].as_array().expect("results array");
            if results.is_empty() {
                break;
            }
            by_offset.push(results[0]["id"].as_str().unwrap().to_string());
            offset += 1;
        }
        assert_eq!(by_offset, expected_ids, "offset walk vs DB order");
        assert_eq!(by_offset, by_cursor, "cursor page K == offset page K");

        // ── Non-FTS path: the rank is the constant 0.0, keyset degenerates
        //    to the (timestamp, id) pair; the action filter narrows to the
        //    seven probe rows.
        let (status, body) = env
            .get(&format!("/v1/admin/audit/search?tenantId={tenant}&action=probe.search&limit=1"))
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["results"].as_array().map(Vec::len), Some(1));
        assert!(body["nextCursor"].is_string(), "non-empty page mints a cursor");
        assert_eq!(body["hasMore"], true);
        assert_eq!(
            body["results"][0]["rank"], 0.0,
            "the non-FTS path pins rank 0.0"
        );
        // Following the non-FTS cursor yields the SECOND row — the keyset
        // continues the same ordering the offset path uses.
        let minted = body["nextCursor"].as_str().unwrap().to_string();
        let (status, body) = env
            .get(&format!(
                "/v1/admin/audit/search?tenantId={tenant}&action=probe.search&limit=1&cursor={minted}"
            ))
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["results"].as_array().map(Vec::len), Some(1));
        assert_eq!(body["hasMore"], true);
        assert_ne!(
            body["results"][0]["id"], "",
            "continuation returns a row"
        );

        // A cursor minted on the FINAL page (the full listing) honestly
        // continues to an empty page.
        let (status, body) = env
            .get(&format!("/v1/admin/audit/search?tenantId={tenant}&action=probe.search&limit=100"))
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["results"].as_array().map(Vec::len), Some(7));
        assert_eq!(body["hasMore"], false);
        let final_cursor = body["nextCursor"].as_str().unwrap().to_string();
        let (status, body) = env
            .get(&format!(
                "/v1/admin/audit/search?tenantId={tenant}&action=probe.search&limit=1&cursor={final_cursor}"
            ))
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["results"].as_array().map(Vec::len), Some(0));
        assert_eq!(body["hasMore"], false);

        // ── Hostile cursors are client errors, never database 500s. ──
        for bad in [
            "zz",
            encode_cursor("no-separator-here").as_str(),
            encode_cursor(&format!("1.5\nnot-a-time\nrow-id")).as_str(),
            encode_cursor(&format!("NaN\n2026-01-01T00:00:00Z\nrow-id")).as_str(),
            encode_cursor(&format!(
                "1.5\n2026-01-01T00:00:00Z\nx'; DROP TABLE audit_logs; --"
            ))
            .as_str(),
        ] {
            let (status, body) = env
                .get(&format!("/v1/admin/audit/search?cursor={bad}"))
                .await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "cursor {bad:?}: {body}");
            assert!(
                body.to_string().contains("invalid cursor"),
                "cursor {bad:?}: {body}"
            );
        }

        pool.close().await;
    }
}

// ─── Coverage residuals: filtered chunks and mid-stream failure ──

#[cfg(test)]
mod coverage_residual_tests {
    use super::*;
    use crate::middleware::auth::AuthUser;
    use axum::http::StatusCode;
    use axum::response::IntoResponse;

    fn admin() -> AuthUser {
        AuthUser {
            tenant_id: "system".into(),
            user_id: Some("usr_aexport_cov".into()),
            api_key_id: None,
            session_id: None,
            scopes: vec!["*".into()],
        }
    }

    async fn body_bytes(response: axum::response::Response) -> Vec<u8> {
        axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap()
            .to_vec()
    }

    /// Every filter combination shapes its own chunk query: tenant,
    /// action, and full-text `q` each add a placeholder, and the binds
    /// follow the same order.
    #[tokio::test]
    async fn export_chunks_honor_every_filter_combination() {
        let Some(pool) = crate::test_db::canonical_pool("aexport_filters").await else {
            return;
        };
        let state = crate::app::test_support::test_state_over(pool.clone()).await;
        let tenant = format!("flt{}", &uuid::Uuid::new_v4().simple().to_string()[..20]);

        // Seed rows readable by each filter arm.
        for action in ["cov.action.one", "cov.action.two"] {
            sqlx::query(
                "INSERT INTO audit_logs (id, tenant_id, user_id, action, resource, details,
                     outcome, timestamp, hash, signature, fts_vector)
                 VALUES (replace(gen_random_uuid()::text, '-', ''), $1, 'usr_1', $2,
                         'audit_probe', '{\"needle\": \"haystack\"}'::jsonb, 'success',
                         NOW(), 'h', 's',
                         to_tsvector('english', $2 || ' haystack'))",
            )
            .bind(&tenant)
            .bind(action)
            .execute(&pool)
            .await
            .expect("seed filter row");
        }

        // tenant + action + q together: three optional conditions.
        let response = audit_export(
            State(state.clone()),
            admin(),
            Json(AuditExportRequest {
                q: Some("haystack".into()),
                tenant_id: Some(tenant.clone()),
                action: Some("cov.action.one".into()),
                from: None,
                to: None,
                limit: 100,
            }),
        )
        .await
        .expect("filtered export")
        .into_response();
        assert_eq!(response.status(), StatusCode::OK);
        let csv = String::from_utf8(body_bytes(response).await).unwrap();
        assert!(csv.contains("cov.action.one"), "{csv}");
        assert!(
            !csv.contains("cov.action.two"),
            "the action filter narrows: {csv}"
        );

        // The condition builder mirrors the bind order for every subset.
        let mk = |tenant: Option<String>, action: Option<String>, q: Option<String>| {
            build_export_chunk_conditions(&ExportChunkState {
                pool: state.db.clone(),
                tenant_id: tenant,
                action,
                q,
                window_start: Utc::now() - chrono::Duration::days(1),
                window_end: Utc::now(),
                offset: 0,
                remaining: 10,
            })
        };
        assert_eq!(mk(None, None, None), "timestamp >= $1 AND timestamp <= $2");
        assert!(mk(Some("t".into()), None, None).contains("tenant_id = $3"));
        assert!(mk(None, Some("a".into()), None).contains("action = $3"));
        assert!(mk(Some("t".into()), Some("a".into()), None).contains("action = $4"));
        assert!(mk(Some("t".into()), Some("a".into()), Some("q".into()))
            .contains("fts_vector @@ plainto_tsquery('english', $5)"));
        pool.close().await;
    }

    /// A storage failure mid-stream ends the body with the error instead
    /// of hanging or fabricating rows, and a failing search surfaces it.
    #[tokio::test]
    async fn storage_failure_terminates_stream_and_search_honestly() {
        let Some(pool) = crate::test_db::canonical_pool("aexport_failure").await else {
            return;
        };
        let state = crate::app::test_support::test_state_over(pool.clone()).await;
        crate::routes::fault::hide_table(&pool, "audit_logs")
            .await
            .expect("hide audit_logs");

        // The chunk query fails: the stream ends with the error.
        let response = audit_export(
            State(state.clone()),
            admin(),
            Json(AuditExportRequest {
                q: None,
                tenant_id: None,
                action: None,
                from: None,
                to: None,
                limit: 100,
            }),
        )
        .await
        .expect("export response")
        .into_response();
        assert_eq!(response.status(), StatusCode::OK);
        // The chunk query fails: the stream ends with the error — a
        // truncated, error-terminated download, never a hang. The header
        // row may or may not have flushed before the failure.
        if let Ok(bytes) = axum::body::to_bytes(response.into_body(), usize::MAX).await {
            assert!(bytes.is_empty() || bytes.starts_with(b"timestamp,action"));
        }

        // The search handler surfaces the same failure from try_join.
        let error = audit_search(
            State(state),
            admin(),
            Query(AuditSearchQuery {
                q: None,
                tenant_id: None,
                action: None,
                from: None,
                to: None,
                limit: 10,
                offset: 0,
                cursor: None,
            }),
        )
        .await;
        assert!(matches!(error, Err(ApiError::Internal(_))), "got {error:?}");
        pool.close().await;
    }
}
