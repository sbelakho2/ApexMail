//! Full-text search across audit logs with CSV export.
//!
//! Provides:
//! - GET  /v1/admin/audit/search  — ranked FTS with tsvector/tsquery
//! - POST /v1/admin/audit/export  — CSV export of filtered audit logs

use std::future::Future;
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
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/search", get(audit_search))
        .route("/export", post(audit_export))
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
}

fn build_search_plan(
    params: &AuditSearchQuery,
    now: DateTime<Utc>,
) -> Result<AuditSearchPlan, ApiError> {
    let has_fts = params.q.as_ref().is_some_and(|q| !q.trim().is_empty());
    let (window_start, window_end) =
        resolve_search_window(params.from.as_deref(), params.to.as_deref(), now)?;

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

    let (search_sql, search_binds) = if has_fts {
        let q = params.q.as_deref().unwrap_or("").trim().to_string();
        let tsquery_param = filter_idx;
        let limit_param = filter_idx + 1;
        let mut binds = filter_binds.clone();
        binds.push(q);
        (
            format!(
                "SELECT id, timestamp, action, resource, resource_id,
                        user_id, tenant_id, ip_address, details,
                        ts_rank(fts_vector, plainto_tsquery('english', ${tsquery_param}))::double precision as rank,
                        ts_headline('english', coalesce(details::text, ''), plainto_tsquery('english', ${tsquery_param}), 'MaxWords=50, MinWords=10, ShortWord=3') as headline
                 FROM audit_logs
                 {where_clause}
                   AND fts_vector @@ plainto_tsquery('english', ${tsquery_param})
                 ORDER BY rank DESC, timestamp DESC
                 LIMIT ${limit_param} OFFSET ${}",
                limit_param + 1
            ),
            binds,
        )
    } else {
        (
            format!(
                "SELECT id, timestamp, action, resource, resource_id,
                        user_id, tenant_id, ip_address, details,
                        0.0::double precision as rank,
                        '' as headline
                 FROM audit_logs
                 {where_clause}
                 ORDER BY timestamp DESC, id DESC
                 LIMIT ${filter_idx} OFFSET ${}",
                filter_idx + 1
            ),
            filter_binds.clone(),
        )
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
    // plan — the search row query appends LIMIT/OFFSET as the final pair.
    let (count_result, search_result) = tokio::try_join!(
        execute_count(&state.db, &plan),
        execute_search(&state.db, &plan),
    )?;

    Ok(Json(AuditSearchResponse {
        results: search_result,
        total: count_result,
        limit: plan.limit,
        offset: plan.offset,
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

#[allow(clippy::type_complexity)]
async fn execute_search(
    db: &sqlx::PgPool,
    plan: &AuditSearchPlan,
) -> Result<Vec<AuditSearchResult>, ApiError> {
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
            Option<serde_json::Value>,
            f64,
            String,
        ),
    >(&plan.search_sql)
    .bind(plan.window_start)
    .bind(plan.window_end);

    for bind in &plan.search_binds {
        query = query.bind(bind);
    }
    query = query.bind(plan.limit).bind(plan.offset);

    let rows = query.fetch_all(db).await?;

    let results = rows
        .into_iter()
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

    Ok(results)
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

    let body_stream =
        futures::stream::once(async { csv_record_bytes(true, None) }).chain(chunk_state);

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

impl futures::Stream for ExportChunkState {
    type Item = Result<Vec<u8>, std::io::Error>;

    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        if self.remaining <= 0 {
            return std::task::Poll::Ready(None);
        }
        let state = &mut *self;
        let chunk_limit = state.remaining.min(EXPORT_CHUNK_ROWS);

        let conditions = build_export_chunk_conditions(state);
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

        // The future OWNS every bind input (pool clone is an Arc bump):
        // nothing borrows `state`, so the offset/remaining mutations after
        // the ready branch stay legal.
        let window_start = state.window_start;
        let window_end = state.window_end;
        let tenant_id = state.tenant_id.clone();
        let action = state.action.clone();
        let q = state.q.clone();
        let offset = state.offset;
        let pool = state.pool.clone();

        let mut fut = std::pin::pin!(async move {
            let mut query = sqlx::query_as::<_, AuditExportRow>(&sql)
                .bind(window_start)
                .bind(window_end);
            if let Some(ref tenant_id) = tenant_id {
                query = query.bind(tenant_id.clone());
            }
            if let Some(ref action) = action {
                query = query.bind(action.clone());
            }
            if let Some(ref q) = q {
                query = query.bind(q.clone());
            }
            query.bind(chunk_limit).bind(offset).fetch_all(&pool).await
        });

        match fut.as_mut().poll(cx) {
            std::task::Poll::Ready(Ok(rows)) => {
                let fetched = rows.len() as i64;
                state.remaining -= fetched;
                state.offset += fetched;
                if fetched < chunk_limit {
                    // Last chunk: stop the stream after draining it.
                    state.remaining = 0;
                }
                if rows.is_empty() {
                    return std::task::Poll::Ready(None);
                }
                let mut buffer = Vec::with_capacity(rows.len() * 128);
                for row in &rows {
                    let record = csv_record_bytes(false, Some(row))?;
                    buffer.extend_from_slice(&record);
                }
                std::task::Poll::Ready(Some(Ok(buffer)))
            }
            std::task::Poll::Ready(Err(error)) => {
                // End the body after surfacing the failure — a truncated,
                // error-terminated download beats a hung one.
                state.remaining = 0;
                std::task::Poll::Ready(Some(Err(std::io::Error::other(error))))
            }
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    }
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
                "INSERT INTO audit_logs (id, tenant_id, action, resource, details, timestamp, fts_vector)
                 VALUES ($1, 'tenant-a', 'user.login', 'session', '{\"who\":\"admin\"}'::jsonb, NOW() - make_interval(mins => $2),
                         to_tsvector('english', 'user.login session admin'))",
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
        let results = execute_search(&pool, &plan)
            .await
            .expect("search query must execute (no parameter mismatch)");
        assert_eq!(results.len(), 3);
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
                },
                now,
            )
            .is_ok(),
            "an 89-day window must be accepted"
        );
    }
}
