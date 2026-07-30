//! Full-text search across audit logs with CSV export.
//!
//! Provides:
//! - GET  /v1/admin/audit/search  — ranked FTS with tsvector/tsquery
//! - POST /v1/admin/audit/export  — CSV export of filtered audit logs

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
            ApiError::Validation(vec![format!(
                "{field} must be a valid RFC3339 timestamp"
            )])
        })
}

fn build_search_query(params: &AuditSearchQuery) -> Result<(String, Vec<String>), ApiError> {
    let has_fts = params.q.as_ref().map_or(false, |q| !q.trim().is_empty());
    let now = Utc::now();

    let window_end = params
        .to
        .as_deref()
        .map(|v| parse_optional_timestamp(v, "to"))
        .transpose()?
        .unwrap_or(now);
    let window_start = params
        .from
        .as_deref()
        .map(|v| parse_optional_timestamp(v, "from"))
        .transpose()?
        .unwrap_or(window_end - Duration::days(30));

    if window_start > window_end {
        return Err(ApiError::Validation(vec![
            "from must be before to".into()
        ]));
    }

    let mut conditions: Vec<String> = vec![
        "timestamp >= $1".into(),
        "timestamp <= $2".into(),
    ];
    let mut param_idx = 3u32;
    let mut bind_values: Vec<String> = Vec::new();

    if let Some(ref tenant_id) = params.tenant_id {
        conditions.push(format!("tenant_id = ${param_idx}"));
        param_idx += 1;
        bind_values.push(tenant_id.clone());
    }

    if let Some(ref action) = params.action {
        conditions.push(format!("action = ${param_idx}"));
        param_idx += 1;
        bind_values.push(action.clone());
    }

    let where_clause = format!("WHERE {}", conditions.join(" AND "));

    let sql = if has_fts {
        let q = params.q.as_deref().unwrap_or("").trim();
        let tsquery_param = param_idx;
        param_idx += 1;
        bind_values.push(q.to_string());

        format!(
            "SELECT id, timestamp, action, resource, resource_id,
                    user_id, tenant_id, ip_address, details,
                    ts_rank(fts_vector, plainto_tsquery('english', ${tsquery_param})) as rank,
                    ts_headline('english', coalesce(details::text, ''), plainto_tsquery('english', ${tsquery_param}), 'MaxWords=50, MinWords=10, ShortWord=3') as headline
             FROM audit_logs
             {where_clause}
               AND fts_vector @@ plainto_tsquery('english', ${tsquery_param})
             ORDER BY rank DESC, timestamp DESC
             LIMIT ${param_idx} OFFSET ${}",
            param_idx + 1
        )
    } else {
        format!(
            "SELECT id, timestamp, action, resource, resource_id,
                    user_id, tenant_id, ip_address, details,
                    0.0 as rank,
                    '' as headline
             FROM audit_logs
             {where_clause}
             ORDER BY timestamp DESC, id DESC
             LIMIT ${param_idx} OFFSET ${}",
            param_idx + 1
        )
    };

    Ok((sql, bind_values))
}

fn build_count_query(params: &AuditSearchQuery) -> Result<(String, Vec<String>), ApiError> {
    let has_fts = params.q.as_ref().map_or(false, |q| !q.trim().is_empty());
    let now = Utc::now();

    let window_end = params
        .to
        .as_deref()
        .map(|v| parse_optional_timestamp(v, "to"))
        .transpose()?
        .unwrap_or(now);
    let window_start = params
        .from
        .as_deref()
        .map(|v| parse_optional_timestamp(v, "from"))
        .transpose()?
        .unwrap_or(window_end - Duration::days(30));

    let mut conditions: Vec<String> = vec![
        "timestamp >= $1".into(),
        "timestamp <= $2".into(),
    ];
    let mut param_idx = 3u32;
    let mut bind_values: Vec<String> = Vec::new();

    if let Some(ref tenant_id) = params.tenant_id {
        conditions.push(format!("tenant_id = ${param_idx}"));
        param_idx += 1;
        bind_values.push(tenant_id.clone());
    }

    if let Some(ref action) = params.action {
        conditions.push(format!("action = ${param_idx}"));
        param_idx += 1;
        bind_values.push(action.clone());
    }

    let where_clause = format!("WHERE {}", conditions.join(" AND "));

    let sql = if has_fts {
        let q = params.q.as_deref().unwrap_or("").trim();
        bind_values.push(q.to_string());

        format!(
            "SELECT COUNT(*) FROM audit_logs
             {where_clause}
               AND fts_vector @@ plainto_tsquery('english', ${param_idx})"
        )
    } else {
        format!("SELECT COUNT(*) FROM audit_logs {where_clause}")
    };

    Ok((sql, bind_values))
}

async fn audit_search(
    State(state): State<AppState>,
    auth: AuthUser,
    Query(params): Query<AuditSearchQuery>,
) -> Result<Json<AuditSearchResponse>, ApiError> {
    crate::middleware::auth::require_scopes(&auth, &["*"])?;

    let (search_sql, search_binds) = build_search_query(&params)?;
    let (count_sql, count_binds) = build_count_query(&params)?;

    // Run count and search concurrently
    let (count_result, search_result) = tokio::try_join!(
        execute_count(&state.db, &count_sql, &count_binds, &params),
        execute_search(&state.db, &search_sql, &search_binds, &params),
    )?;

    Ok(Json(AuditSearchResponse {
        results: search_result,
        total: count_result,
        limit: params.limit.clamp(1, 200),
        offset: params.offset.max(0),
    }))
}

async fn execute_count(
    db: &sqlx::PgPool,
    sql: &str,
    binds: &[String],
    params: &AuditSearchQuery,
) -> Result<i64, ApiError> {
    let now = Utc::now();
    let window_end = params
        .to
        .as_deref()
        .map(|v| parse_optional_timestamp(v, "to"))
        .transpose()?
        .unwrap_or(now);
    let window_start = params
        .from
        .as_deref()
        .map(|v| parse_optional_timestamp(v, "from"))
        .transpose()?
        .unwrap_or(window_end - Duration::days(30));

    let mut query = sqlx::query_scalar::<_, i64>(sql)
        .bind(window_start)
        .bind(window_end);

    if let Some(ref tenant_id) = params.tenant_id {
        query = query.bind(tenant_id);
    }
    if let Some(ref action) = params.action {
        query = query.bind(action);
    }
    for bind in binds {
        query = query.bind(bind);
    }

    Ok(query.fetch_one(db).await?)
}

#[allow(clippy::type_complexity)]
async fn execute_search(
    db: &sqlx::PgPool,
    sql: &str,
    binds: &[String],
    params: &AuditSearchQuery,
) -> Result<Vec<AuditSearchResult>, ApiError> {
    let now = Utc::now();
    let window_end = params
        .to
        .as_deref()
        .map(|v| parse_optional_timestamp(v, "to"))
        .transpose()?
        .unwrap_or(now);
    let window_start = params
        .from
        .as_deref()
        .map(|v| parse_optional_timestamp(v, "from"))
        .transpose()?
        .unwrap_or(window_end - Duration::days(30));
    let limit = params.limit.clamp(1, 200);
    let offset = params.offset.max(0);

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
    >(sql)
    .bind(window_start)
    .bind(window_end);

    if let Some(ref tenant_id) = params.tenant_id {
        query = query.bind(tenant_id);
    }
    if let Some(ref action) = params.action {
        query = query.bind(action);
    }
    for bind in binds {
        query = query.bind(bind);
    }
    query = query.bind(limit).bind(offset);

    let rows = query.fetch_all(db).await?;

    let results = rows
        .into_iter()
        .map(
            |(id, ts, action, resource, resource_id, user_id, tenant_id, ip, details, rank, headline)| {
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

async fn audit_export(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(body): Json<AuditExportRequest>,
) -> Result<impl IntoResponse, ApiError> {
    crate::middleware::auth::require_scopes(&auth, &["*"])?;

    let now = Utc::now();
    let window_end = body
        .to
        .as_deref()
        .map(|v| parse_optional_timestamp(v, "to"))
        .transpose()?
        .unwrap_or(now);
    let window_start = body
        .from
        .as_deref()
        .map(|v| parse_optional_timestamp(v, "from"))
        .transpose()?
        .unwrap_or(window_end - Duration::days(30));
    let limit = body.limit.clamp(1, 50_000);

    let mut conditions: Vec<String> = vec![
        "timestamp >= $1".into(),
        "timestamp <= $2".into(),
    ];
    let mut param_idx = 3u32;

    if let Some(ref tenant_id) = body.tenant_id {
        conditions.push(format!("tenant_id = ${param_idx}"));
        param_idx += 1;
    }
    if let Some(ref action) = body.action {
        conditions.push(format!("action = ${param_idx}"));
        param_idx += 1;
    }

    let has_fts = body.q.as_ref().map_or(false, |q| !q.trim().is_empty());

    let sql = if has_fts {
        format!(
            "SELECT timestamp, action, resource, resource_id, user_id, tenant_id, ip_address, outcome, error_message
             FROM audit_logs
             WHERE {} AND fts_vector @@ plainto_tsquery('english', ${param_idx})
             ORDER BY timestamp DESC
             LIMIT ${}",
            conditions.join(" AND "),
            param_idx + 1
        )
    } else {
        format!(
            "SELECT timestamp, action, resource, resource_id, user_id, tenant_id, ip_address, outcome, error_message
             FROM audit_logs
             WHERE {}
             ORDER BY timestamp DESC
             LIMIT ${}",
            conditions.join(" AND "),
            param_idx + 1
        )
    };

    let mut csv_writer = csv::Writer::from_writer(Vec::new());
    csv_writer
        .write_record(&[
            "timestamp",
            "action",
            "resource",
            "resource_id",
            "user_id",
            "tenant_id",
            "ip_address",
            "outcome",
            "error_message",
        ])
        .map_err(|e| ApiError::Internal(e.to_string()))?;

    let rows = sqlx::query_as::<_, (
        chrono::DateTime<chrono::Utc>,
        String,
        String,
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
        String,
        Option<String>,
    )>(&sql)
    .bind(window_start)
    .bind(window_end);

    let rows = if let Some(ref tenant_id) = body.tenant_id {
        rows.bind(tenant_id)
    } else {
        rows
    };

    let rows = if let Some(ref action) = body.action {
        rows.bind(action)
    } else {
        rows
    };

    let rows = if let Some(ref q) = body.q {
        if !q.trim().is_empty() {
            rows.bind(q.trim())
        } else {
            rows
        }
    } else {
        rows
    };

    let rows = rows.bind(limit).fetch_all(&state.db).await?;

    for row in rows {
        csv_writer
            .write_record(&[
                row.0.to_rfc3339(),
                row.1,
                row.2,
                row.3.unwrap_or_default(),
                row.4.unwrap_or_default(),
                row.5.unwrap_or_default(),
                row.6.unwrap_or_default(),
                row.7,
                row.8.unwrap_or_default(),
            ])
            .map_err(|e| ApiError::Internal(e.to_string()))?;
    }

    csv_writer
        .flush()
        .map_err(|e| ApiError::Internal(e.to_string()))?;

    let csv_data = csv_writer
        .into_inner()
        .map_err(|e| ApiError::Internal(e.to_string()))?;

    let filename = format!(
        "audit_export_{}.csv",
        Utc::now().format("%Y%m%dT%H%M%SZ")
    );

    let disposition_value = axum::http::HeaderValue::from_str(&format!(
        "attachment; filename=\"{filename}\""
    ))
    .map_err(|e| ApiError::Internal(e.to_string()))?;

    let mut response = (
        [(header::CONTENT_TYPE, "text/csv; charset=utf-8")],
        csv_data,
    )
        .into_response();
    response
        .headers_mut()
        .insert(header::CONTENT_DISPOSITION, disposition_value);
    Ok(response)
}
