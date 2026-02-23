//! Analytics / reporting routes.

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
        .route("/dashboard", get(dashboard))
        .route("/volume", get(volume))
        .route("/engagement", get(engagement))
        .route("/deliverability", get(deliverability))
        .route("/export", get(export))
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

    let total_sent = row.total_sent.max(1);
    let total_delivered = row.total_delivered;

    Ok(Json(DashboardResponse {
        total_sent: row.total_sent,
        total_delivered,
        total_bounced: row.total_bounced,
        total_opened: events.opened,
        total_clicked: events.clicked,
        delivery_rate: total_delivered as f64 / total_sent as f64,
        open_rate: events.opened as f64 / total_delivered.max(1) as f64,
        click_rate: events.clicked as f64 / total_delivered.max(1) as f64,
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

    let rows = sqlx::query_as::<_, VolumeRow>(
        "SELECT
            date_trunc('day', created_at) as day,
            COUNT(*) as sent,
            COUNT(*) FILTER (WHERE status = 'delivered') as delivered,
            COUNT(*) FILTER (WHERE status = 'bounced') as bounced
         FROM messages
         WHERE tenant_id = $1 AND created_at >= $2 AND created_at <= $3
         GROUP BY day ORDER BY day",
    )
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

    // Spawn background task to process the export
    let db = state.db.clone();
    let tenant_id = auth.tenant_id;
    tokio::spawn(async move {
        if let Err(e) = process_analytics_export(db, job_id, tenant_id, from, to, format).await {
            tracing::error!(job_id = %job_id, error = %e, "Export job failed");
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
    let expires_at = Utc::now() + chrono::Duration::hours(24);

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

fn escape_csv(s: &str) -> String {
    if s.contains(',') || s.contains('"') || s.contains('\n') {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

async fn upload_export_to_storage(key: &str, content: &[u8], _content_type: &str) -> anyhow::Result<String> {
    // In production, this would upload to S3/GCS/MinIO
    // For now, generate a presigned-style URL
    // The actual implementation would use object_store crate

    // Create local file for development/testing
    let export_dir = std::path::PathBuf::from("/tmp/apexmail-exports");
    tokio::fs::create_dir_all(&export_dir).await?;

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
