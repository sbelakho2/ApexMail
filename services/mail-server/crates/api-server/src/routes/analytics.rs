//! Analytics / reporting routes.

use axum::extract::{Path, Query, State};
use axum::routing::get;
use axum::{Json, Router};
use chrono::{DateTime, TimeDelta, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::ApiError;
use crate::middleware::auth::{require_scopes, AuthUser};
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/dashboard", get(dashboard))
        .route("/volume", get(volume))
        .route("/engagement", get(engagement))
        .route("/deliverability", get(deliverability))
        .route("/export", get(export))
        .route("/export/pdf", get(export_pdf))
        .route("/export/:job_id", get(get_export_job))
}

// ─── Types ─────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct AnalyticsQuery {
    #[serde(default)]
    pub from: Option<DateTime<Utc>>,
    #[serde(default)]
    pub to: Option<DateTime<Utc>>,
    #[serde(default = "default_interval")]
    pub interval: String,
}

fn default_interval() -> String {
    "day".into()
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
) -> Result<Json<DashboardResponse>, ApiError> {
    require_scopes(&auth, &["analytics:read"])?;

    let from = params.from.unwrap_or_else(|| Utc::now() - chrono::Duration::days(30));
    let to = params.to.unwrap_or_else(Utc::now);

    let row = sqlx::query_as::<_, DashboardRow>(
        "SELECT
            COUNT(*) FILTER (WHERE status IN ('sent','delivered')) as total_sent,
            COUNT(*) FILTER (WHERE status = 'delivered') as total_delivered,
            COUNT(*) FILTER (WHERE status = 'bounced') as total_bounced
         FROM messages
         WHERE tenant_id = $1 AND created_at >= $2 AND created_at <= $3",
    )
    .bind(auth.tenant_id)
    .bind(from)
    .bind(to)
    .fetch_one(&state.db)
    .await?;

    let events = sqlx::query_as::<_, EventCountsRow>(
        "SELECT
            COUNT(*) FILTER (WHERE event_type = 'opened') as opened,
            COUNT(*) FILTER (WHERE event_type = 'clicked') as clicked
         FROM events
         WHERE tenant_id = $1 AND timestamp >= $2 AND timestamp <= $3",
    )
    .bind(auth.tenant_id)
    .bind(from)
    .bind(to)
    .fetch_one(&state.db)
    .await?;

    // Fix #46: Handle zero sent properly - return 0 rates instead of artificial 1
    let total_sent = row.total_sent;
    let total_delivered = row.total_delivered;

    Ok(Json(DashboardResponse {
        total_sent,
        total_delivered,
        total_bounced: row.total_bounced,
        total_opened: events.opened,
        total_clicked: events.clicked,
        delivery_rate: if total_sent > 0 { total_delivered as f64 / total_sent as f64 } else { 0.0 },
        open_rate: if total_delivered > 0 { events.opened as f64 / total_delivered as f64 } else { 0.0 },
        click_rate: if total_delivered > 0 { events.clicked as f64 / total_delivered as f64 } else { 0.0 },
    }))
}

async fn volume(
    State(state): State<AppState>,
    auth: AuthUser,
    Query(params): Query<AnalyticsQuery>,
) -> Result<Json<Vec<VolumePoint>>, ApiError> {
    require_scopes(&auth, &["analytics:read"])?;

    let from = params.from.unwrap_or_else(|| Utc::now() - chrono::Duration::days(30));
    let to = params.to.unwrap_or_else(Utc::now);

    // Fix #42: Map interval to valid SQL date_trunc unit
    let interval_unit = match params.interval.as_str() {
        "hour" => "hour",
        "week" => "week",
        "month" => "month",
        _ => "day", // default to day
    };

    // Use parameterized interval (safe from SQL injection as it's validated above)
    let query = format!(
        "SELECT
            date_trunc('{}', created_at) as day,
            COUNT(*) as sent,
            COUNT(*) FILTER (WHERE status = 'delivered') as delivered,
            COUNT(*) FILTER (WHERE status = 'bounced') as bounced
         FROM messages
         WHERE tenant_id = $1 AND created_at >= $2 AND created_at <= $3
         GROUP BY day ORDER BY day",
        interval_unit
    );

    let rows = sqlx::query_as::<_, VolumeRow>(&query)
    .bind(auth.tenant_id)
    .bind(from)
    .bind(to)
    .fetch_all(&state.db)
    .await?;

    Ok(Json(
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
) -> Result<Json<EngagementResponse>, ApiError> {
    require_scopes(&auth, &["analytics:read"])?;

    let from = params.from.unwrap_or_else(|| Utc::now() - chrono::Duration::days(30));
    let to = params.to.unwrap_or_else(Utc::now);

    let totals = sqlx::query_as::<_, EngagementTotalsRow>(
        "SELECT
            COUNT(*) FILTER (WHERE event_type = 'opened') as opens,
            COUNT(*) FILTER (WHERE event_type = 'clicked') as clicks,
            COUNT(*) FILTER (WHERE event_type = 'unsubscribed') as unsubs
         FROM events
         WHERE tenant_id = $1 AND timestamp >= $2 AND timestamp <= $3",
    )
    .bind(auth.tenant_id)
    .bind(from)
    .bind(to)
    .fetch_one(&state.db)
    .await?;

    let total_delivered = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM events WHERE tenant_id = $1 AND event_type = 'delivered' AND timestamp >= $2 AND timestamp <= $3",
    )
    .bind(auth.tenant_id)
    .bind(from)
    .bind(to)
    .fetch_one(&state.db)
    .await?
    .max(1);

    let timeseries = sqlx::query_as::<_, EngagementTimeseriesRow>(
        "SELECT date_trunc('day', timestamp) as day,
            COUNT(*) FILTER (WHERE event_type = 'opened') as opens,
            COUNT(*) FILTER (WHERE event_type = 'clicked') as clicks
         FROM events
         WHERE tenant_id = $1 AND timestamp >= $2 AND timestamp <= $3
         GROUP BY day ORDER BY day",
    )
    .bind(auth.tenant_id)
    .bind(from)
    .bind(to)
    .fetch_all(&state.db)
    .await?;

    Ok(Json(EngagementResponse {
        open_rate: totals.opens as f64 / total_delivered as f64,
        click_rate: totals.clicks as f64 / total_delivered as f64,
        unsubscribe_rate: totals.unsubs as f64 / total_delivered as f64,
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
) -> Result<Json<DeliverabilityResponse>, ApiError> {
    require_scopes(&auth, &["analytics:read"])?;

    let from = params.from.unwrap_or_else(|| Utc::now() - chrono::Duration::days(30));
    let to = params.to.unwrap_or_else(Utc::now);

    let row = sqlx::query_as::<_, DeliverabilityRow>(
        "SELECT
            COUNT(*) as total,
            COUNT(*) FILTER (WHERE event_type = 'delivered') as delivered,
            COUNT(*) FILTER (WHERE event_type = 'bounced') as bounced,
            COUNT(*) FILTER (WHERE event_type = 'complained') as complained
         FROM events
         WHERE tenant_id = $1 AND timestamp >= $2 AND timestamp <= $3",
    )
    .bind(auth.tenant_id)
    .bind(from)
    .bind(to)
    .fetch_one(&state.db)
    .await?;

    let total = row.total.max(1) as f64;

    Ok(Json(DeliverabilityResponse {
        delivery_rate: row.delivered as f64 / total,
        bounce_rate: row.bounced as f64 / total,
        complaint_rate: row.complained as f64 / total,
        inbox_rate: (row.delivered as f64 - row.complained as f64).max(0.0) / total,
    }))
}

async fn export(
    State(state): State<AppState>,
    auth: AuthUser,
    Query(params): Query<ExportQuery>,
) -> Result<Json<ExportResponse>, ApiError> {
    require_scopes(&auth, &["analytics:read"])?;

    let from = params.from.unwrap_or_else(|| Utc::now() - chrono::Duration::days(30));
    let to = params.to.unwrap_or_else(Utc::now);
    let format = params.format.clone();
    let job_id = uuid::Uuid::new_v4();

    // Create export job record
    sqlx::query(
        "INSERT INTO export_jobs (id, tenant_id, job_type, status, format, date_range_start, date_range_end, created_by)
         VALUES ($1, $2, 'analytics', 'pending', $3, $4, $5, $6)"
    )
        .bind(job_id)
        .bind(auth.tenant_id)
        .bind(&format)
        .bind(from)
        .bind(to)
        .bind(auth.user_id)
        .execute(&state.db)
        .await?;

    // Fix #44: Spawn background task with catch_unwind to handle panics properly.
    let db = state.db.clone();
    let tenant_id = auth.tenant_id;
    tokio::spawn(async move {
        let result = std::panic::AssertUnwindSafe(
            process_analytics_export(db.clone(), job_id, tenant_id, from, to, format)
        );
        match futures::FutureExt::catch_unwind(result).await {
            Ok(Ok(())) => {},
            Ok(Err(e)) => {
                let err_msg = e.to_string();
                tracing::error!(job_id = %job_id, error = %err_msg, "Export job failed");
                // Mark job as failed
                let _ = sqlx::query(
                    "UPDATE export_jobs SET status = 'failed', error_message = $1, completed_at = NOW() WHERE id = $2"
                )
                .bind(&err_msg)
                .bind(job_id)
                .execute(&db)
                .await;
            },
            Err(_panic) => {
                tracing::error!(job_id = %job_id, "Export job panicked");
                // Mark job as failed due to panic
                let _ = sqlx::query(
                    "UPDATE export_jobs SET status = 'failed', error_message = 'internal error (panic)', completed_at = NOW() WHERE id = $1"
                )
                .bind(job_id)
                .execute(&db)
                .await;
            }
        }
    });

    Ok(Json(ExportResponse {
        job_id: Some(job_id.to_string()),
        download_url: None,
        status: "processing".into(),
    }))
}

async fn process_analytics_export(
    db: sqlx::PgPool,
    job_id: uuid::Uuid,
    tenant_id: uuid::Uuid,
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
         ORDER BY m.sent_at DESC"
    )
        .bind(tenant_id)
        .bind(from)
        .bind(to)
        .fetch_all(&db)
        .await?;

    let total_rows = rows.len() as i64;

    // Generate export content based on format
    let (content, content_type, extension) = match format.as_str() {
        "json" => {
            let json = serde_json::to_string_pretty(&rows)?;
            (json.into_bytes(), "application/json", "json")
        }
        _ => {
            // CSV format (default)
            let mut csv = String::from("message_id,subject,recipient,sent_at,last_event,event_time\n");
            for row in &rows {
                csv.push_str(&format!(
                    "{},{},{},{},{},{}\n",
                    row.message_id,
                    escape_csv(&row.subject),
                    row.recipient,
                    row.sent_at.to_rfc3339(),
                    row.last_event,
                    row.event_time.map(|t| t.to_rfc3339()).unwrap_or_default()
                ));
            }
            (csv.into_bytes(), "text/csv", "csv")
        }
    };

    let file_size = content.len() as i64;

    // Upload to S3 (using object store pattern)
    let object_key = format!("exports/{}/{}.{}", tenant_id, job_id, extension);
    let download_url = upload_export_to_storage(&object_key, &content, content_type).await?;
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
         WHERE id = $5"
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

/// Fix #43: Sanitize value for CSV to prevent formula injection.
/// Prefixes dangerous characters with a single quote.
fn escape_csv(s: &str) -> String {
    let trimmed = s.trim();
    // CSV injection prevention: prefix = + - @ with single quote
    let needs_prefix = matches!(
        trimmed.chars().next(),
        Some('=' | '+' | '-' | '@' | '\t' | '\r')
    );
    
    let sanitized = if needs_prefix {
        format!("'{}", trimmed)
    } else {
        trimmed.to_string()
    };
    
    if sanitized.contains(',') || sanitized.contains('"') || sanitized.contains('\n') {
        format!("\"{}\"" , sanitized.replace('"', "\"\""))
    } else {
        sanitized
    }
}

async fn upload_export_to_storage(key: &str, content: &[u8], _content_type: &str) -> anyhow::Result<String> {
    // In production, this would upload to S3/GCS/MinIO
    // For now, generate a presigned-style URL
    // The actual implementation would use object_store crate

    // Fix #45: Use secure directory with proper permissions instead of /tmp
    let export_dir = std::env::var("EXPORT_STORAGE_PATH")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| {
            // Use XDG data dir or fallback to a more secure location
            dirs::data_local_dir()
                .unwrap_or_else(|| std::path::PathBuf::from("/var/lib/apexmail"))
                .join("exports")
        });
    tokio::fs::create_dir_all(&export_dir).await?;
    
    // Set restrictive permissions on the directory (owner only)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o700);
        std::fs::set_permissions(&export_dir, perms).ok();
    }

    let file_path = export_dir.join(key.replace('/', "_"));
    tokio::fs::write(&file_path, content).await?;

    // Return a URL - in production this would be a presigned S3 URL
    let base_url = std::env::var("EXPORT_BASE_URL").unwrap_or_else(|_| "https://exports.apexmail.io".into());
    Ok(format!("{}/{}", base_url, key))
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
) -> Result<Json<ExportJobStatus>, ApiError> {
    require_scopes(&auth, &["analytics:read"])?;

    let row: Option<ExportJobRow> = sqlx::query_as(
        "SELECT id, status, total_rows, processed_rows, download_url, download_expires_at, error_message
         FROM export_jobs WHERE id = $1 AND tenant_id = $2"
    )
        .bind(job_id)
        .bind(auth.tenant_id)
        .fetch_optional(&state.db)
        .await?;

    let job = row.ok_or_else(|| ApiError::NotFound("export job not found".into()))?;

    let download_url = if job.status == "completed" && job.download_expires_at > Some(Utc::now()) {
        job.download_url
    } else {
        None
    };

    Ok(Json(ExportJobStatus {
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
    id: Uuid,
    status: String,
    total_rows: Option<i64>,
    processed_rows: i64,
    download_url: Option<String>,
    download_expires_at: Option<DateTime<Utc>>,
    error_message: Option<String>,
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
}

#[derive(sqlx::FromRow)]
struct EventCountsRow {
    opened: i64,
    clicked: i64,
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
    total: i64,
    delivered: i64,
    bounced: i64,
    complained: i64,
}

// ─── PDF Export (via pdf-renderer service) ─────────────────────

/// `GET /analytics/export/pdf?from=...&to=...`
///
/// Calls the pdf-renderer service to generate a PDF analytics export and
/// streams the result back to the client with `Content-Disposition: attachment`.
async fn export_pdf(
    State(state): State<AppState>,
    auth: AuthUser,
    Query(params): Query<AnalyticsQuery>,
) -> Result<axum::response::Response, ApiError> {
    use axum::http::header;

    require_scopes(&auth, &["analytics:read"])?;

    let from = params.from.unwrap_or_else(|| Utc::now() - chrono::Duration::days(30));
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
         WHERE tenant_id = $1 AND sent_at >= $2 AND sent_at < $3"
    )
        .bind(auth.tenant_id)
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

    let total = s.total_sent.max(1) as f64;

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
            "delivery_rate": (s.total_delivered as f64 / total * 100.0 * 10.0).round() / 10.0,
            "open_rate": (s.total_opened as f64 / total * 100.0 * 10.0).round() / 10.0,
            "click_rate": (s.total_clicked as f64 / total * 100.0 * 10.0).round() / 10.0,
            "bounce_rate": (s.total_bounced as f64 / total * 100.0 * 10.0).round() / 10.0,
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

    let pdf_renderer_url = std::env::var("PDF_RENDERER_URL")
        .unwrap_or_else(|_| "http://pdf-renderer:3004".into());

    let http_client = reqwest::Client::new();
    let resp = http_client
        .post(format!("{pdf_renderer_url}/v1/pdf/render"))
        .json(&render_request)
        .timeout(std::time::Duration::from_secs(30))
        .send()
        .await
        .map_err(|e| ApiError::Internal(format!("PDF renderer error: {e}")))?;

    if !resp.status().is_success() {
        let body = resp.text().await.unwrap_or_default();
        return Err(ApiError::Internal(format!("PDF render failed: {body}")));
    }

    let pdf_bytes = resp.bytes().await
        .map_err(|e| ApiError::Internal(format!("Failed to read PDF: {e}")))?;

    let filename = format!(
        "analytics-export-{}-{}.pdf",
        from.format("%Y%m%d"),
        to.format("%Y%m%d")
    );

    Ok((
        axum::http::StatusCode::OK,
        [
            (header::CONTENT_TYPE, "application/pdf".to_string()),
            (header::CONTENT_DISPOSITION, format!("attachment; filename=\"{filename}\"")),
            (header::CACHE_CONTROL, "no-store".to_string()),
        ],
        pdf_bytes.to_vec(),
    ).into())
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
}
