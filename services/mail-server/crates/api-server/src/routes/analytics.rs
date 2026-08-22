//! Analytics / reporting routes.

use apexmail_analytics::subject_line_analyzer::SubjectLineAnalyzer;
use apexmail_analytics::types::SubjectLineScore;
use axum::extract::{Path, Query, State};
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::{DateTime, TimeDelta, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::{success, ApiError, ApiResponse};
use crate::middleware::auth::{require_scopes, AuthUser};
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/dashboard", get(dashboard))
        .route("/volume", get(volume))
        .route("/engagement", get(engagement))
        .route("/deliverability", get(deliverability))
        .route("/subject-line", post(analyze_subject_line))
        .route("/export", get(export))
        .route("/export/pdf", get(export_pdf))
        .route("/export/:job_id", get(get_export_job))
        // L-28: real, authenticated download for completed exports. The job
        // used to return a fabricated `https://exports.apexmail.io/...`
        // presigned URL that nothing ever served.
        .route("/export/:job_id/download", get(download_export))
}

// ─── Types ─────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AnalyticsQuery {
    #[serde(default)]
    pub from: Option<DateTime<Utc>>,
    #[serde(default)]
    pub to: Option<DateTime<Utc>>,
    #[serde(default = "default_interval")]
    pub interval: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SubjectLineAnalyzeRequest {
    pub subject: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SubjectLineAnalyzeResponse {
    pub score: SubjectLineScore,
}

fn default_interval() -> String {
    "day".into()
}

fn safe_ratio(numerator: i64, denominator: i64) -> f64 {
    if denominator > 0 {
        numerator as f64 / denominator as f64
    } else {
        0.0
    }
}

fn volume_query_for_interval(interval: &str) -> &'static str {
    match interval {
        "hour" => {
            "SELECT
                date_trunc('hour', created_at) as day,
                COUNT(*) as sent,
                COUNT(*) FILTER (WHERE status = 'delivered') as delivered,
                COUNT(*) FILTER (WHERE status = 'bounced') as bounced
             FROM messages
             WHERE tenant_id = $1 AND created_at >= $2 AND created_at <= $3
             GROUP BY day ORDER BY day"
        }
        "week" => {
            "SELECT
                date_trunc('week', created_at) as day,
                COUNT(*) as sent,
                COUNT(*) FILTER (WHERE status = 'delivered') as delivered,
                COUNT(*) FILTER (WHERE status = 'bounced') as bounced
             FROM messages
             WHERE tenant_id = $1 AND created_at >= $2 AND created_at <= $3
             GROUP BY day ORDER BY day"
        }
        "month" => {
            "SELECT
                date_trunc('month', created_at) as day,
                COUNT(*) as sent,
                COUNT(*) FILTER (WHERE status = 'delivered') as delivered,
                COUNT(*) FILTER (WHERE status = 'bounced') as bounced
             FROM messages
             WHERE tenant_id = $1 AND created_at >= $2 AND created_at <= $3
             GROUP BY day ORDER BY day"
        }
        _ => {
            "SELECT
                date_trunc('day', created_at) as day,
                COUNT(*) as sent,
                COUNT(*) FILTER (WHERE status = 'delivered') as delivered,
                COUNT(*) FILTER (WHERE status = 'bounced') as bounced
             FROM messages
             WHERE tenant_id = $1 AND created_at >= $2 AND created_at <= $3
             GROUP BY day ORDER BY day"
        }
    }
}

fn build_deliverability_response(
    total_sent: i64,
    delivered: i64,
    bounced: i64,
    complained: i64,
) -> DeliverabilityResponse {
    DeliverabilityResponse {
        delivery_rate: safe_ratio(delivered, total_sent),
        bounce_rate: safe_ratio(bounced, total_sent),
        complaint_rate: safe_ratio(complained, delivered),
        inbox_rate: safe_ratio((delivered - complained).max(0), total_sent),
    }
}

fn analyze_subject_line_payload(subject: &str) -> Result<SubjectLineAnalyzeResponse, ApiError> {
    let subject = subject.trim();
    if subject.is_empty() {
        return Err(ApiError::Validation(vec!["subject is required".into()]));
    }
    if subject.chars().count() > 200 {
        return Err(ApiError::Validation(vec![
            "subject must be 200 characters or fewer".into(),
        ]));
    }

    let analyzer = SubjectLineAnalyzer::new();
    Ok(SubjectLineAnalyzeResponse {
        score: analyzer.analyze(subject),
    })
}

#[derive(Debug, Serialize)]
pub struct DashboardResponse {
    pub total_sent: i64,
    pub total_delivered: i64,
    pub total_bounced: i64,
    pub total_opened: i64,
    pub total_clicked: i64,
    pub delivery_rate: f64,
    pub open_rate: f64,
    pub click_rate: f64,
}

#[derive(Debug, Serialize)]
pub struct VolumePoint {
    pub date: String,
    pub sent: i64,
    pub delivered: i64,
    pub bounced: i64,
}

#[derive(Debug, Serialize)]
pub struct EngagementResponse {
    pub open_rate: f64,
    pub click_rate: f64,
    pub unsubscribe_rate: f64,
    pub timeseries: Vec<EngagementPoint>,
}

#[derive(Debug, Serialize)]
pub struct EngagementPoint {
    pub date: String,
    pub opens: i64,
    pub clicks: i64,
}

#[derive(Debug, Serialize)]
pub struct DeliverabilityResponse {
    pub delivery_rate: f64,
    pub bounce_rate: f64,
    pub complaint_rate: f64,
    pub inbox_rate: f64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExportQuery {
    #[serde(default)]
    pub from: Option<DateTime<Utc>>,
    #[serde(default)]
    pub to: Option<DateTime<Utc>>,
    #[serde(default = "default_format")]
    pub format: String,
}

fn default_format() -> String {
    "json".into()
}

#[derive(Debug, Serialize)]
pub struct ExportResponse {
    pub job_id: Option<String>,
    pub download_url: Option<String>,
    pub status: String,
}

// ─── Handlers ──────────────────────────────────────────────────

async fn dashboard(
    State(state): State<AppState>,
    auth: AuthUser,
    Query(params): Query<AnalyticsQuery>,
) -> Result<Json<ApiResponse<DashboardResponse>>, ApiError> {
    require_scopes(&auth, &["analytics:read"])?;

    let from = params
        .from
        .unwrap_or_else(|| Utc::now() - chrono::Duration::days(30));
    let to = params.to.unwrap_or_else(Utc::now);

    let row = sqlx::query_as::<_, DashboardCountsRow>(
        "SELECT
            COUNT(*) FILTER (WHERE status IN ('sent','delivered')) as total_sent,
            COUNT(*) FILTER (WHERE status = 'delivered') as total_delivered,
            COUNT(*) FILTER (WHERE status = 'bounced') as total_bounced
         FROM messages
         WHERE tenant_id = $1 AND created_at >= $2 AND created_at <= $3",
    )
    .bind(&auth.tenant_id)
    .bind(from)
    .bind(to)
    .fetch_one(&state.db)
    .await?;

    let events = sqlx::query_as::<_, DashboardEventsRow>(
        "SELECT
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

    let total_sent = row.total_sent;
    let total_delivered = row.total_delivered;

    Ok(success(DashboardResponse {
        total_sent,
        total_delivered,
        total_bounced: row.total_bounced,
        total_opened: events.opened,
        total_clicked: events.clicked,
        delivery_rate: safe_ratio(total_delivered, total_sent),
        open_rate: safe_ratio(events.opened, total_delivered),
        click_rate: safe_ratio(events.clicked, total_delivered),
    }))
}

async fn volume(
    State(state): State<AppState>,
    auth: AuthUser,
    Query(params): Query<AnalyticsQuery>,
) -> Result<Json<ApiResponse<Vec<VolumePoint>>>, ApiError> {
    require_scopes(&auth, &["analytics:read"])?;

    let from = params
        .from
        .unwrap_or_else(|| Utc::now() - chrono::Duration::days(30));
    let to = params.to.unwrap_or_else(Utc::now);

    let rows = sqlx::query_as::<_, VolumeRow>(volume_query_for_interval(&params.interval))
        .bind(&auth.tenant_id)
        .bind(from)
        .bind(to)
        .fetch_all(&state.db)
        .await?;

    Ok(success(
        rows.into_iter()
            .map(|r| VolumePoint {
                date: r.day.to_rfc3339(),
                sent: r.sent,
                delivered: r.delivered,
                bounced: r.bounced,
            })
            .collect(),
    ))
}

async fn engagement(
    State(state): State<AppState>,
    auth: AuthUser,
    Query(params): Query<AnalyticsQuery>,
) -> Result<Json<ApiResponse<EngagementResponse>>, ApiError> {
    require_scopes(&auth, &["analytics:read"])?;

    let from = params
        .from
        .unwrap_or_else(|| Utc::now() - chrono::Duration::days(30));
    let to = params.to.unwrap_or_else(Utc::now);

    let totals = sqlx::query_as::<_, EngagementTotalsRow>(
        "SELECT
            COUNT(*) FILTER (WHERE event_type = 'opened') as opens,
            COUNT(*) FILTER (WHERE event_type = 'clicked') as clicks,
            COUNT(*) FILTER (WHERE event_type = 'unsubscribed') as unsubs
         FROM events
         WHERE tenant_id = $1 AND timestamp >= $2 AND timestamp <= $3",
    )
    .bind(&auth.tenant_id)
    .bind(from)
    .bind(to)
    .fetch_one(&state.db)
    .await?;

    let total_delivered = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*)
         FROM messages
         WHERE tenant_id = $1 AND status = 'delivered' AND created_at >= $2 AND created_at <= $3",
    )
    .bind(&auth.tenant_id)
    .bind(from)
    .bind(to)
    .fetch_one(&state.db)
    .await?;

    let timeseries = sqlx::query_as::<_, EngagementTimeseriesRow>(
        "SELECT date_trunc('day', timestamp) as day,
            COUNT(*) FILTER (WHERE event_type = 'opened') as opens,
            COUNT(*) FILTER (WHERE event_type = 'clicked') as clicks
         FROM events
         WHERE tenant_id = $1 AND timestamp >= $2 AND timestamp <= $3
         GROUP BY day ORDER BY day",
    )
    .bind(&auth.tenant_id)
    .bind(from)
    .bind(to)
    .fetch_all(&state.db)
    .await?;

    Ok(success(EngagementResponse {
        open_rate: safe_ratio(totals.opens, total_delivered),
        click_rate: safe_ratio(totals.clicks, total_delivered),
        unsubscribe_rate: safe_ratio(totals.unsubs, total_delivered),
        timeseries: timeseries
            .into_iter()
            .map(|r| EngagementPoint {
                date: r.day.to_rfc3339(),
                opens: r.opens,
                clicks: r.clicks,
            })
            .collect(),
    }))
}

async fn deliverability(
    State(state): State<AppState>,
    auth: AuthUser,
    Query(params): Query<AnalyticsQuery>,
) -> Result<Json<ApiResponse<DeliverabilityResponse>>, ApiError> {
    require_scopes(&auth, &["analytics:read"])?;

    let from = params
        .from
        .unwrap_or_else(|| Utc::now() - chrono::Duration::days(30));
    let to = params.to.unwrap_or_else(Utc::now);

    let row = sqlx::query_as::<_, DeliverabilityRow>(
        "SELECT
            COUNT(*) FILTER (WHERE status IN ('sent', 'delivered', 'bounced')) as total_sent,
            COUNT(*) FILTER (WHERE status = 'delivered') as delivered,
            COUNT(*) FILTER (WHERE status = 'bounced') as bounced
         FROM messages
         WHERE tenant_id = $1 AND created_at >= $2 AND created_at <= $3",
    )
    .bind(&auth.tenant_id)
    .bind(from)
    .bind(to)
    .fetch_one(&state.db)
    .await?;

    let complained = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*)
         FROM events
         WHERE tenant_id = $1 AND event_type = 'complained' AND timestamp >= $2 AND timestamp <= $3",
    )
    .bind(&auth.tenant_id)
    .bind(from)
    .bind(to)
    .fetch_one(&state.db)
    .await?;

    Ok(success(build_deliverability_response(
        row.total_sent,
        row.delivered,
        row.bounced,
        complained,
    )))
}

async fn analyze_subject_line(
    auth: AuthUser,
    Json(body): Json<SubjectLineAnalyzeRequest>,
) -> Result<Json<ApiResponse<SubjectLineAnalyzeResponse>>, ApiError> {
    require_scopes(&auth, &["analytics:read"])?;
    Ok(success(analyze_subject_line_payload(&body.subject)?))
}

async fn export(
    State(state): State<AppState>,
    auth: AuthUser,
    Query(params): Query<ExportQuery>,
) -> Result<Json<ApiResponse<ExportResponse>>, ApiError> {
    require_scopes(&auth, &["analytics:read"])?;

    let from = params
        .from
        .unwrap_or_else(|| Utc::now() - chrono::Duration::days(30));
    let to = params.to.unwrap_or_else(Utc::now);
    let format = params.format.clone();
    let job_id = uuid::Uuid::new_v4();

    // Create export job record
    sqlx::query(
        "INSERT INTO export_jobs (id, tenant_id, job_type, status, format, date_range_start, date_range_end, created_by)
         VALUES ($1, $2, 'analytics', 'pending', $3, $4, $5, $6)"
    )
        .bind(job_id)
        .bind(&auth.tenant_id)
        .bind(&format)
        .bind(from)
        .bind(to)
        .bind(&auth.user_id)
        .execute(&state.db)
        .await?;

    let db = state.db.clone();
    let tenant_id = auth.tenant_id.clone();
    tokio::spawn(async move {
        let result = std::panic::AssertUnwindSafe(process_analytics_export(
            db.clone(),
            job_id,
            tenant_id,
            from,
            to,
            format,
        ));
        match futures::FutureExt::catch_unwind(result).await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => {
                let err_msg = e.to_string();
                tracing::error!(job_id = %job_id, error = %err_msg, "Export job failed");
                // Mark job as failed
                if let Err(db_err) = sqlx::query(
                    "UPDATE export_jobs SET status = 'failed', error_message = $1, completed_at = NOW() WHERE id = $2"
                )
                .bind(&err_msg)
                .bind(job_id)
                .execute(&db)
                .await
                {
                    tracing::error!(job_id = %job_id, error = %db_err, "Failed to mark export job as failed — job will be stuck");
                }
            }
            Err(_panic) => {
                tracing::error!(job_id = %job_id, "Export job panicked");
                // Mark job as failed due to panic
                if let Err(db_err) = sqlx::query(
                    "UPDATE export_jobs SET status = 'failed', error_message = 'internal error (panic)', completed_at = NOW() WHERE id = $1"
                )
                .bind(job_id)
                .execute(&db)
                .await
                {
                    tracing::error!(job_id = %job_id, error = %db_err, "Failed to mark panicked export job as failed — job will be stuck");
                }
            }
        }
    });

    Ok(success(ExportResponse {
        job_id: Some(job_id.to_string()),
        download_url: None,
        status: "processing".into(),
    }))
}

async fn process_analytics_export(
    db: sqlx::PgPool,
    job_id: uuid::Uuid,
    tenant_id: String,
    from: DateTime<Utc>,
    to: DateTime<Utc>,
    format: String,
) -> anyhow::Result<()> {
    // Mark job as processing
    sqlx::query("UPDATE export_jobs SET status = 'processing', started_at = NOW() WHERE id = $1")
        .bind(job_id)
        .execute(&db)
        .await?;

    // Query analytics data
    let rows: Vec<ExportRow> = sqlx::query_as(
        "SELECT
            m.message_id,
            m.subject,
            m.recipient,
            m.sent_at,
            COALESCE(e.event_type, 'sent') as last_event,
            e.created_at as event_time
         FROM messages m
         LEFT JOIN LATERAL (
             SELECT event_type, created_at
             FROM events
             WHERE message_id = m.message_id
             ORDER BY created_at DESC
             LIMIT 1
         ) e ON true
         WHERE m.tenant_id = $1 AND m.sent_at >= $2 AND m.sent_at < $3
         ORDER BY m.sent_at DESC
         LIMIT 100000",
    )
    .bind(&tenant_id)
    .bind(from)
    .bind(to)
    .fetch_all(&db)
    .await?;

    let total_rows = rows.len() as i64;

    // Generate export content based on format
    let content = match format.as_str() {
        "json" => {
            let json = serde_json::to_string_pretty(&rows)?;
            json.into_bytes()
        }
        _ => {
            // CSV format (default)
            let mut csv =
                String::from("message_id,subject,recipient,sent_at,last_event,event_time\n");
            for row in &rows {
                csv.push_str(&format!(
                    "{},{},{},{},{},{}\n",
                    escape_csv(&row.message_id),
                    escape_csv(&row.subject),
                    escape_csv(&row.recipient),
                    escape_csv(&row.sent_at.to_rfc3339()),
                    escape_csv(&row.last_event),
                    escape_csv(&row.event_time.map(|t| t.to_rfc3339()).unwrap_or_default())
                ));
            }
            csv.into_bytes()
        }
    };

    let file_size = content.len() as i64;

    // Store the export on the local exports volume and hand out a real,
    // authenticated download route (L-28: the previous presigned-style URL
    // pointed at `exports.apexmail.io`, which nothing serves).
    let object_key = export_object_key(&tenant_id, job_id, &format);
    store_export_file(&object_key, &content).await?;
    let download_url = format!("/v1/analytics/export/{job_id}/download");
    let expires_at = Utc::now() + TimeDelta::try_hours(24).unwrap_or(TimeDelta::zero());

    // Update job as completed
    sqlx::query(
        "UPDATE export_jobs SET
            status = 'completed',
            total_rows = $1,
            processed_rows = $1,
            file_size_bytes = $2,
            download_url = $3,
            download_expires_at = $4,
            completed_at = NOW()
         WHERE id = $5",
    )
    .bind(total_rows)
    .bind(file_size)
    .bind(&download_url)
    .bind(expires_at)
    .bind(job_id)
    .execute(&db)
    .await?;

    tracing::info!(job_id = %job_id, rows = total_rows, "Export completed");
    Ok(())
}

/// Prefixes dangerous characters with a single quote.
fn escape_csv(s: &str) -> String {
    let trimmed = s.trim_start();
    // CSV injection prevention:prefix = + - @ with single quote
    let needs_prefix = matches!(
        trimmed.chars().next(),
        Some('=' | '+' | '-' | '@' | '\t' | '\r')
    );

    let sanitized = if needs_prefix {
        format!("'{}", s)
    } else {
        s.to_string()
    };

    if sanitized.contains(',')
        || sanitized.contains('"')
        || sanitized.contains('\n')
        || sanitized.contains('\r')
    {
        format!("\"{}\"", sanitized.replace('"', "\"\""))
    } else {
        sanitized
    }
}

/// File extension for an export format. `json` is structured; everything
/// else was generated as CSV.
fn export_extension(format: &str) -> &'static str {
    match format {
        "json" => "json",
        _ => "csv",
    }
}

/// Storage key for an export artifact.
fn export_object_key(tenant_id: &str, job_id: uuid::Uuid, format: &str) -> String {
    format!(
        "exports/{}_{}.{}",
        tenant_id,
        job_id,
        export_extension(format)
    )
}

/// On-disk file name for a storage key (flat, no subdirectories — the key
/// separator is flattened so a crafted key can never traverse paths).
fn export_file_name(key: &str) -> String {
    key.replace('/', "_")
}

fn export_storage_dir() -> std::path::PathBuf {
    std::env::var("EXPORT_STORAGE_PATH")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| {
            // Use XDG data dir or fallback to a more secure location
            dirs::data_local_dir()
                .unwrap_or_else(|| std::path::PathBuf::from("/var/lib/apexmail"))
                .join("exports")
        })
}

/// Persist an export artifact to the local exports volume.
///
/// L-28: directory permission changes are blocking `std::fs` calls, so they
/// run on the blocking pool (`spawn_blocking`) instead of stalling the async
/// worker; file writes use `tokio::fs`.
async fn store_export_file(key: &str, content: &[u8]) -> anyhow::Result<()> {
    let export_dir = export_storage_dir();
    tokio::fs::create_dir_all(&export_dir).await?;

    // Set restrictive permissions on the directory (owner only) on the
    // blocking pool — std::fs::set_permissions blocks the runtime thread.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let dir = export_dir.clone();
        tokio::task::spawn_blocking(move || {
            let perms = std::fs::Permissions::from_mode(0o700);
            std::fs::set_permissions(&dir, perms).ok();
        })
        .await?;
    }

    let file_path = export_dir.join(export_file_name(key));
    tokio::fs::write(&file_path, content).await?;
    Ok(())
}

#[derive(sqlx::FromRow, Serialize)]
struct ExportRow {
    message_id: String,
    subject: String,
    recipient: String,
    sent_at: DateTime<Utc>,
    last_event: String,
    event_time: Option<DateTime<Utc>>,
}

async fn get_export_job(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(job_id): Path<Uuid>,
) -> Result<Json<ApiResponse<ExportJobStatus>>, ApiError> {
    require_scopes(&auth, &["analytics:read"])?;

    let row: Option<ExportJobRow> = sqlx::query_as(
        "SELECT id, status, total_rows, processed_rows, download_url, download_expires_at, error_message
         FROM export_jobs WHERE id = $1 AND tenant_id = $2"
    )
        .bind(job_id)
        .bind(&auth.tenant_id)
        .fetch_optional(&state.db)
        .await?;

    let job = row.ok_or_else(|| ApiError::NotFound("export job not found".into()))?;

    let download_url = if job.status == "completed" && job.download_expires_at > Some(Utc::now()) {
        job.download_url
    } else {
        None
    };

    Ok(success(ExportJobStatus {
        job_id: job.id.to_string(),
        status: job.status,
        total_rows: job.total_rows,
        processed_rows: job.processed_rows,
        download_url,
        error_message: job.error_message,
    }))
}

#[derive(sqlx::FromRow)]
struct ExportJobRow {
    id: String,
    status: String,
    total_rows: Option<i64>,
    processed_rows: i64,
    download_url: Option<String>,
    download_expires_at: Option<DateTime<Utc>>,
    error_message: Option<String>,
}

/// `GET /analytics/export/:job_id/download` — streams a completed export
/// artifact from the exports volume (L-28). Tenant-scoped: the job must
/// belong to the caller's tenant, be completed, and be inside its 24h
/// download window.
async fn download_export(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(job_id): Path<Uuid>,
) -> Result<axum::response::Response, ApiError> {
    use axum::http::header;

    require_scopes(&auth, &["analytics:read"])?;

    let row: Option<(String, Option<DateTime<Utc>>)> = sqlx::query_as(
        "SELECT format, download_expires_at
         FROM export_jobs
         WHERE id = $1 AND tenant_id = $2 AND status = 'completed'",
    )
    .bind(job_id)
    .bind(&auth.tenant_id)
    .fetch_optional(&state.db)
    .await?;

    let (format, expires_at) =
        row.ok_or_else(|| ApiError::NotFound("export job not found".into()))?;
    if expires_at <= Some(Utc::now()) {
        return Err(ApiError::NotFound(
            "export download link has expired".into(),
        ));
    }

    let object_key = export_object_key(&auth.tenant_id, job_id, &format);
    let file_path = export_storage_dir().join(export_file_name(&object_key));
    let content = tokio::fs::read(&file_path)
        .await
        .map_err(|e| ApiError::NotFound(format!("export artifact unavailable: {e}")))?;

    let (content_type, extension) = match format.as_str() {
        "json" => ("application/json", "json"),
        _ => ("text/csv", "csv"),
    };
    let filename = format!("analytics-export-{job_id}.{extension}");

    axum::response::Response::builder()
        .status(axum::http::StatusCode::OK)
        .header(header::CONTENT_TYPE, content_type)
        .header(
            header::CONTENT_DISPOSITION,
            format!("attachment; filename=\"{filename}\""),
        )
        .header(header::CACHE_CONTROL, "private, no-store")
        .body(axum::body::Body::from(content))
        .map_err(|e| ApiError::Internal(format!("failed to build export response: {e}")))
}

#[derive(Debug, Serialize)]
pub struct ExportJobStatus {
    pub job_id: String,
    pub status: String,
    pub total_rows: Option<i64>,
    pub processed_rows: i64,
    pub download_url: Option<String>,
    pub error_message: Option<String>,
}

// ─── Row types ─────────────────────────────────────────────────

#[derive(sqlx::FromRow)]
struct DashboardRow {
    total_sent: i64,
    total_delivered: i64,
    total_bounced: i64,
    total_opened: i64,
    total_clicked: i64,
}

/// Row shape for the dashboard's events sub-query (opened/clicked counts only).
#[derive(sqlx::FromRow)]
struct DashboardEventsRow {
    opened: i64,
    clicked: i64,
}

/// Row shape for the dashboard's messages sub-query (sent/delivered/bounced only).
#[derive(sqlx::FromRow)]
struct DashboardCountsRow {
    total_sent: i64,
    total_delivered: i64,
    total_bounced: i64,
}

#[derive(sqlx::FromRow)]
struct VolumeRow {
    day: DateTime<Utc>,
    sent: i64,
    delivered: i64,
    bounced: i64,
}

#[derive(sqlx::FromRow)]
struct EngagementTotalsRow {
    opens: i64,
    clicks: i64,
    unsubs: i64,
}

#[derive(sqlx::FromRow)]
struct EngagementTimeseriesRow {
    day: DateTime<Utc>,
    opens: i64,
    clicks: i64,
}

#[derive(sqlx::FromRow)]
struct DeliverabilityRow {
    total_sent: i64,
    delivered: i64,
    bounced: i64,
}

// ─── PDF Export (via pdf-renderer service) ─────────────────────

/// `GET /analytics/export/pdf?from=...&to=...`
/// Calls the pdf-renderer service to generate a PDF analytics export and
/// streams the result back to the client with `Content-Disposition:attachment`.
async fn export_pdf(
    State(state): State<AppState>,
    auth: AuthUser,
    Query(params): Query<AnalyticsQuery>,
) -> Result<axum::response::Response, ApiError> {
    use axum::http::header;

    require_scopes(&auth, &["analytics:read"])?;

    let from = params
        .from
        .unwrap_or_else(|| Utc::now() - chrono::Duration::days(30));
    let to = params.to.unwrap_or_else(Utc::now);

    // Gather summary data for the PDF template
    let summary: Option<DashboardRow> = sqlx::query_as(
        "SELECT
            COUNT(*) as total_sent,
            COUNT(*) FILTER (WHERE status = 'delivered') as total_delivered,
            COUNT(*) FILTER (WHERE status = 'bounced') as total_bounced,
            COUNT(*) FILTER (WHERE status = 'opened') as total_opened,
            COUNT(*) FILTER (WHERE status = 'clicked') as total_clicked
         FROM messages
         WHERE tenant_id = $1 AND sent_at >= $2 AND sent_at < $3",
    )
    .bind(&auth.tenant_id)
    .bind(from)
    .bind(to)
    .fetch_optional(&state.db)
    .await?;

    let s = summary.unwrap_or(DashboardRow {
        total_sent: 0,
        total_delivered: 0,
        total_bounced: 0,
        total_opened: 0,
        total_clicked: 0,
    });

    let total = s.total_sent as f64;

    let safe_rate = |numerator: i64| -> f64 {
        if s.total_sent > 0 {
            (numerator as f64 / total * 100.0 * 10.0).round() / 10.0
        } else {
            0.0
        }
    };

    let pdf_data = serde_json::json!({
        "tenant_name": auth.tenant_id.to_string(),
        "date_range": {
            "from": from.format("%Y-%m-%d").to_string(),
            "to": to.format("%Y-%m-%d").to_string(),
        },
        "generated_at": Utc::now().to_rfc3339(),
        "summary": {
            "total_sent": s.total_sent,
            "total_delivered": s.total_delivered,
            "total_bounced": s.total_bounced,
            "total_opened": s.total_opened,
            "total_clicked": s.total_clicked,
            "total_unsubscribed": 0,
            "total_complaints": 0,
            "delivery_rate": safe_rate(s.total_delivered),
            "open_rate": safe_rate(s.total_opened),
            "click_rate": safe_rate(s.total_clicked),
            "bounce_rate": safe_rate(s.total_bounced),
            "complaint_rate": 0.0,
        },
        "daily_stats": [],
        "top_campaigns": [],
        "domain_breakdown": [],
    });

    let render_request = serde_json::json!({
        "template": "analytics_export",
        "data": pdf_data,
    });

    let pdf_renderer_url =
        std::env::var("PDF_RENDERER_URL").unwrap_or_else(|_| "http://pdf-renderer:3004".into());

    let http_client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .map_err(|e| ApiError::Internal(format!("http client error: {e}")))?;
    let mut req = http_client
        .post(format!("{pdf_renderer_url}/v1/pdf/render"))
        .json(&render_request);
    // pdf-renderer requires the shared internal service token; only attach the
    // header when one is configured (empty token would 401 anyway).
    if let Some(token) = state.config.internal_service_token.as_deref() {
        if !token.is_empty() {
            req = req.header("x-api-key", token);
        }
    }
    let resp = req
        .send()
        .await
        .map_err(|e| ApiError::Internal(format!("PDF renderer error: {e}")))?;

    if !resp.status().is_success() {
        let body = resp.text().await.unwrap_or_default();
        return Err(ApiError::Internal(format!("PDF render failed: {body}")));
    }

    let pdf_bytes = resp
        .bytes()
        .await
        .map_err(|e| ApiError::Internal(format!("Failed to read PDF: {e}")))?;

    let filename = format!(
        "analytics-export-{}-{}.pdf",
        from.format("%Y%m%d"),
        to.format("%Y%m%d")
    );

    axum::response::Response::builder()
        .status(axum::http::StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/pdf")
        .header(
            header::CONTENT_DISPOSITION,
            format!("attachment; filename=\"{filename}\""),
        )
        .header(header::CACHE_CONTROL, "no-store")
        .body(axum::body::Body::from(pdf_bytes.to_vec()))
        .map_err(|e| ApiError::Internal(format!("Failed to build PDF response: {e}")))
}

// ─── Tests ─────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dashboard_response_rates() {
        let resp = DashboardResponse {
            total_sent: 1000,
            total_delivered: 950,
            total_bounced: 50,
            total_opened: 400,
            total_clicked: 100,
            delivery_rate: 0.95,
            open_rate: 0.42,
            click_rate: 0.105,
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["total_sent"], 1000);
        assert!(json["delivery_rate"].as_f64().unwrap() > 0.9);
    }

    #[test]
    fn test_deliverability_response() {
        let resp = DeliverabilityResponse {
            delivery_rate: 0.95,
            bounce_rate: 0.03,
            complaint_rate: 0.001,
            inbox_rate: 0.949,
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert!(json["bounce_rate"].as_f64().unwrap() < 0.1);
    }

    #[test]
    fn test_volume_query_for_interval_uses_static_query_fragments() {
        assert!(volume_query_for_interval("hour").contains("date_trunc('hour'"));
        assert!(volume_query_for_interval("week").contains("date_trunc('week'"));
        assert!(volume_query_for_interval("month").contains("date_trunc('month'"));
        assert!(volume_query_for_interval("unexpected").contains("date_trunc('day'"));
    }

    #[test]
    fn test_build_deliverability_response_uses_consistent_denominators() {
        let resp = build_deliverability_response(100, 90, 10, 5);

        assert_eq!(resp.delivery_rate, 0.9);
        assert_eq!(resp.bounce_rate, 0.1);
        assert_eq!(resp.complaint_rate, 5.0 / 90.0);
        assert_eq!(resp.inbox_rate, 0.85);
    }

    #[test]
    fn test_subject_line_analysis_uses_advanced_analytics_crate() {
        let resp = analyze_subject_line_payload("Your weekly delivery report is ready").unwrap();

        assert!(resp.score.overall_score > 0.0);
        assert_eq!(resp.score.word_count, 6);
    }

    #[test]
    fn test_subject_line_analysis_rejects_empty_subject() {
        let err = analyze_subject_line_payload("   ").unwrap_err();
        assert!(matches!(err, ApiError::Validation(_)));
    }

    #[test]
    fn test_escape_csv_prefixes_formula_like_values_without_stripping_content() {
        assert_eq!(escape_csv("=SUM(A1:A2)"), "'=SUM(A1:A2)");
        assert_eq!(escape_csv("  keep-leading-space"), "  keep-leading-space");
        assert_eq!(escape_csv("hello,world"), "\"hello,world\"");
    }

    #[test]
    fn test_export_keys_and_file_names_are_flat_and_deterministic() {
        let job_id = uuid::Uuid::new_v4();

        let json_key = export_object_key("ten_abc", job_id, "json");
        assert_eq!(json_key, format!("exports/ten_abc_{job_id}.json"));
        assert_eq!(export_extension("json"), "json");
        assert_eq!(export_extension("pdf"), "csv", "non-json formats are CSV");

        // The storage separator is flattened on disk: no subdirectories and
        // no traversal possible from the key.
        assert_eq!(export_file_name(&json_key), format!("exports_ten_abc_{job_id}.json"));
        assert!(!export_file_name(&json_key).contains('/'));
        assert_eq!(export_file_name("a/../../etc/passwd"), "a_.._.._etc_passwd");
    }

    /// Serialises tests that mutate the `EXPORT_STORAGE_PATH` process env var.
    static EXPORT_ENV_MUTEX: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[tokio::test]
    async fn test_store_export_file_writes_content_with_private_directory() {
        let _guard = EXPORT_ENV_MUTEX.lock().unwrap_or_else(|e| e.into_inner());

        let dir = std::env::temp_dir().join(format!("apexmail-export-test-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        std::env::set_var("EXPORT_STORAGE_PATH", &dir);

        let key = export_object_key("ten_test", uuid::Uuid::new_v4(), "json");
        let payload = b"{\"rows\":[]}".to_vec();
        store_export_file(&key, &payload).await.expect("stores export");

        let file_path = dir.join(export_file_name(&key));
        let stored = tokio::fs::read(&file_path).await.expect("artifact written");
        assert_eq!(stored, payload);

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&dir).unwrap().permissions().mode();
            assert_eq!(
                mode & 0o777,
                0o700,
                "exports directory must stay owner-only"
            );
        }

        std::fs::remove_dir_all(&dir).ok();
        std::env::remove_var("EXPORT_STORAGE_PATH");
    }
}
