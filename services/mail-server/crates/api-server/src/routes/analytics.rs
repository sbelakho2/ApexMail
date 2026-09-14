//! Analytics / reporting routes.

use apexmail_analytics::subject_line_analyzer::SubjectLineAnalyzer;
use apexmail_analytics::types::SubjectLineScore;
use axum::extract::{Path, Query, State};
use axum::routing::{get, post};
use axum::{Json, Router};
use billing_entitlements::FeatureKey;
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

// ─── F4: bounded analytics date ranges ─────────────────────────

/// Maximum allowed width of an analytics `from`/`to` range.
const ANALYTICS_MAX_RANGE_DAYS: i64 = 366;

/// Earliest allowed analytics `from` (2020-01-01T00:00:00Z): the platform
/// holds no data before this date, and unbounded lower bounds turn the
/// range scans into expensive full-history scans.
fn analytics_earliest_from() -> DateTime<Utc> {
    DateTime::from_timestamp(1_577_836_800, 0).expect("2020-01-01T00:00:00Z is a valid timestamp")
}

/// Resolve and bound an analytics date range (F4).
///
/// - Defaults are unchanged: `from` = now−30d, `to` = now.
/// - `from` is floored at 2020-01-01.
/// - The width is capped at 366 days. An over-wide range is rejected with
///   400 rather than silently clamped, so callers see that their requested
///   window was not honored instead of receiving partial data.
fn resolve_analytics_range(
    from: Option<DateTime<Utc>>,
    to: Option<DateTime<Utc>>,
) -> Result<(DateTime<Utc>, DateTime<Utc>), ApiError> {
    let from = from.unwrap_or_else(|| Utc::now() - TimeDelta::days(30));
    let to = to.unwrap_or_else(Utc::now);

    let from = from.max(analytics_earliest_from());
    if to - from > TimeDelta::days(ANALYTICS_MAX_RANGE_DAYS) {
        return Err(ApiError::BadRequest(format!(
            "date range too wide: from/to must span at most {ANALYTICS_MAX_RANGE_DAYS} days"
        )));
    }

    Ok((from, to))
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

    let (from, to) = resolve_analytics_range(params.from, params.to)?;

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

    let (from, to) = resolve_analytics_range(params.from, params.to)?;

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

    // Entitlement gate: `advanced analytics` (403 Forbidden when the plan does not include it).
    crate::entitlements::require_feature(&state, &auth.tenant_id, FeatureKey::AdvancedAnalytics)
        .await?;

    let (from, to) = resolve_analytics_range(params.from, params.to)?;

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

    // Entitlement gate: `advanced analytics` (403 Forbidden when the plan does not include it).
    crate::entitlements::require_feature(&state, &auth.tenant_id, FeatureKey::AdvancedAnalytics)
        .await?;

    let (from, to) = resolve_analytics_range(params.from, params.to)?;

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

    // Entitlement gate: `data export` (403 Forbidden when the plan does not include it).
    crate::entitlements::require_feature(&state, &auth.tenant_id, FeatureKey::DataExport).await?;

    let (from, to) = resolve_analytics_range(params.from, params.to)?;
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

    // Query analytics data. Written against the real `messages` schema
    // (migration 073 / runtime CREATE_MESSAGES): id UUID, subject TEXT,
    // to_emails JSONB, created_at TIMESTAMPTZ — the previous query selected
    // nonexistent columns (m.message_id, m.recipient, m.sent_at) and keyed
    // the events join on them, so every export failed.
    let rows: Vec<ExportRow> = sqlx::query_as(
        "SELECT
            m.id::text AS message_id,
            m.subject,
            m.to_emails->>0 AS recipient,
            m.created_at AS created_at,
            COALESCE(e.event_type, 'sent') as last_event,
            e.timestamp as event_time
         FROM messages m
         LEFT JOIN LATERAL (
             SELECT event_type, timestamp
             FROM events
             WHERE message_id = m.id::text
             ORDER BY timestamp DESC
             LIMIT 1
         ) e ON true
         WHERE m.tenant_id = $1 AND m.created_at >= $2 AND m.created_at < $3
         ORDER BY m.created_at DESC
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
                String::from("message_id,subject,recipient,created_at,last_event,event_time\n");
            for row in &rows {
                csv.push_str(&format!(
                    "{},{},{},{},{},{}\n",
                    escape_csv(&row.message_id),
                    escape_csv(row.subject.as_deref().unwrap_or("")),
                    escape_csv(row.recipient.as_deref().unwrap_or("")),
                    escape_csv(&row.created_at.to_rfc3339()),
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
    // CSV injection prevention: a cell beginning with = + - @ (or with a TAB /
    // CR that a spreadsheet strips before evaluating the rest) is prefixed
    // with a single quote. The check runs against the ORIGINAL value: testing
    // the whitespace-trimmed copy silently dropped a leading TAB or CR, so
    // `"\t=1+1"` reached the cell unprefixed even though this function exists
    // to neutralise exactly that. Mirrors billing.rs's sanitize_csv_value; a
    // leading-space-then-formula value (`" =1+1"`) is neutralised too, because
    // spreadsheets strip the space as well.
    let first_non_space = s.trim_start().chars().next();
    let needs_prefix = matches!(s.chars().next(), Some('=' | '+' | '-' | '@' | '\t' | '\r'))
        || matches!(first_non_space, Some('=' | '+' | '-' | '@'));

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
    /// Nullable on the table (messages written without a subject) — a
    /// NULL must not fail the whole export (previously `String`, which
    /// made any subject-less message decode-error the job).
    subject: Option<String>,
    /// First entry of the JSONB `to_emails` array (NULL when empty).
    recipient: Option<String>,
    created_at: DateTime<Utc>,
    last_event: String,
    event_time: Option<DateTime<Utc>>,
}

async fn get_export_job(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(job_id): Path<Uuid>,
) -> Result<Json<ApiResponse<ExportJobStatus>>, ApiError> {
    require_scopes(&auth, &["analytics:read"])?;

    // Entitlement gate: `data export` (403 Forbidden when the plan does not include it).
    crate::entitlements::require_feature(&state, &auth.tenant_id, FeatureKey::DataExport).await?;

    let row: Option<ExportJobRow> = sqlx::query_as(
        // `id::text`: the column is UUID and the DTO is a string; sqlx
        // refuses to decode UUID into String, which used to 500 every
        // status read of an existing job.
        "SELECT id::text AS id, status, total_rows, processed_rows, download_url, download_expires_at, error_message
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

    // Entitlement gate: `data export` (403 Forbidden when the plan does not include it).
    crate::entitlements::require_feature(&state, &auth.tenant_id, FeatureKey::DataExport).await?;

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

    // Entitlement gate: `data export` (403 Forbidden when the plan does not include it).
    crate::entitlements::require_feature(&state, &auth.tenant_id, FeatureKey::DataExport).await?;

    let (from, to) = resolve_analytics_range(params.from, params.to)?;

    // Gather summary data for the PDF template. Sent/delivered/bounced come
    // from message statuses; opens/clicks come from the events table — the
    // previous query counted `messages.status = 'opened'/'clicked'`, statuses
    // that never exist, so PDFs always reported zero engagement.
    let counts = sqlx::query_as::<_, DashboardCountsRow>(
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

    let s = DashboardRow {
        total_sent: counts.total_sent,
        total_delivered: counts.total_delivered,
        total_bounced: counts.total_bounced,
        total_opened: events.opened,
        total_clicked: events.clicked,
    };

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

    // Reuse the shared process-wide client (state.http_client) instead of
    // building a fresh reqwest stack per export; the per-request timeout
    // below bounds the render round-trip.
    let mut req = state
        .http_client
        .post(format!("{pdf_renderer_url}/v1/pdf/render"))
        .timeout(std::time::Duration::from_secs(30))
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

    // ── F4: bounded analytics ranges ────────────────────────────

    #[test]
    fn test_resolve_analytics_range_defaults_to_thirty_days() {
        let (from, to) = resolve_analytics_range(None, None).expect("default range must resolve");
        let width = to - from;
        assert!(width > TimeDelta::days(29), "default width was {width:?}");
        assert!(width <= TimeDelta::days(30) + TimeDelta::minutes(1));
    }

    #[test]
    fn test_resolve_analytics_range_floors_from_at_2020() {
        let from = DateTime::from_timestamp(0, 0).unwrap(); // 1970
        let to = DateTime::from_timestamp(0, 0).unwrap() + TimeDelta::days(30);
        let (from, _) =
            resolve_analytics_range(Some(from), Some(to)).expect("pre-2020 range must resolve");
        assert_eq!(from, analytics_earliest_from());
    }

    #[test]
    fn test_resolve_analytics_range_rejects_over_wide_range() {
        // from is floored to 2020-01-01; a `to` more than 366 days later must
        // be rejected with 400 instead of running an unbounded scan.
        let from = analytics_earliest_from();
        let to = from + TimeDelta::days(400);
        match resolve_analytics_range(Some(from), Some(to)) {
            Err(ApiError::BadRequest(message)) => {
                assert!(message.contains("366"), "message was: {message}");
            }
            other => panic!("expected BadRequest for 400-day range, got {other:?}"),
        }
    }

    #[test]
    fn test_resolve_analytics_range_accepts_366_day_range() {
        let from = analytics_earliest_from() + TimeDelta::days(365);
        let to = from + TimeDelta::days(366);
        let (resolved_from, resolved_to) =
            resolve_analytics_range(Some(from), Some(to)).expect("366-day range must resolve");
        assert_eq!(resolved_from, from);
        assert_eq!(resolved_to, to);
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
        assert_eq!(
            export_file_name(&json_key),
            format!("exports_ten_abc_{job_id}.json")
        );
        assert!(!export_file_name(&json_key).contains('/'));
        assert_eq!(export_file_name("a/../../etc/passwd"), "a_.._.._etc_passwd");
    }

    /// Serialises tests that mutate the `EXPORT_STORAGE_PATH` process env var.
    /// Async-aware so the guard can legitimately be held across awaits.
    pub(super) static EXPORT_ENV_MUTEX: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    /// The guard is intentionally held across the awaited store call: the
    /// env var it protects is read on that path, so dropping it early would
    /// let concurrent tests race the process-global setting.
    #[allow(clippy::await_holding_lock)]
    #[tokio::test]
    async fn test_store_export_file_writes_content_with_private_directory() {
        let _guard = EXPORT_ENV_MUTEX.lock().await;

        let dir =
            std::env::temp_dir().join(format!("apexmail-export-test-{}", uuid::Uuid::new_v4())); // nosemgrep: rust.lang.security.temp-dir.temp-dir — test fixture under a unique pid/uuid path — no predictable-name temp collision
        std::fs::create_dir_all(&dir).unwrap();
        std::env::set_var("EXPORT_STORAGE_PATH", &dir);

        let key = export_object_key("ten_test", uuid::Uuid::new_v4(), "json");
        let payload = b"{\"rows\":[]}".to_vec();
        store_export_file(&key, &payload)
            .await
            .expect("stores export");

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

// ─── Adversarial DB-backed router tests ────────────────────────
//
// Every test drives the REAL router (`build_app`) with a real API key and
// asserts status, body, and database effects. Rows are scoped to a unique
// tenant id per test; the database is provisioned once per process.

#[cfg(test)]
mod adversarial_tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    use axum::body::Body;
    use axum::http::{header, Request, StatusCode};
    use axum::response::IntoResponse;
    use serde_json::json;
    use sqlx::PgPool;
    use tower::ServiceExt;

    use crate::app::build_app;

    /// Canonical DB shared by this module's tests. The pid suffix keeps a
    /// nextest run (one process per test) from contending on one database
    /// name while still sharing a single provisioned DB per cargo-test
    /// process. Config smoke tests (e.g. app.rs) run against the canonical
    /// schema, exactly like production.
    /// A canonical database dedicated to ONE test. `fresh_canonical_pool`
    /// drops + recreates + migrates it, so the name only needs to be unique
    /// per test (and per process under nextest, where every test is its own
    /// process — hence the pid in the shared prefix is unnecessary).
    async fn pool_for(test_name: &str) -> Option<PgPool> {
        crate::test_db::canonical_pool(&format!("adv_analytics_{test_name}")).await
    }

    fn unique_tenant() -> String {
        uuid::Uuid::new_v4().simple().to_string()[..26].to_string()
    }

    /// Seed the tenant plus the plan its entitlements resolve from.
    async fn seed_tenant(pool: &PgPool, tenant_id: &str, features: serde_json::Value) {
        let plan_name = format!("advplan{}", &tenant_id[..12]);
        sqlx::query(
            "INSERT INTO plans (id, name, display_name, description, price_monthly, price_yearly,
                                email_limit, api_call_limit, features, is_active, sort_order,
                                created_at, updated_at)
             VALUES (LEFT(REPLACE(gen_random_uuid()::text, '-', ''), 26), $1, $1, '', 0, 0,
                     1000, 1000, $2, true, 0, NOW(), NOW())
             ON CONFLICT (name) DO UPDATE SET features = EXCLUDED.features",
        )
        .bind(&plan_name)
        .bind(features)
        .execute(pool)
        .await
        .expect("seed plan");
        sqlx::query(
            "INSERT INTO tenants (id, name, slug, plan, status, settings, metadata, created_at, updated_at)
             VALUES ($1, 'adversarial analytics', $2, $3, 'active', '{}'::jsonb, '{}'::jsonb, NOW(), NOW())
             ON CONFLICT (id) DO NOTHING",
        )
        .bind(tenant_id)
        .bind(format!("adv-{tenant_id}"))
        .bind(&plan_name)
        .execute(pool)
        .await
        .expect("seed tenant");
    }

    fn full_features() -> serde_json::Value {
        let mut features =
            serde_json::to_value(billing_service::types::PlanFeatures::default()).unwrap();
        features["advanced_analytics"] = json!(true);
        features["data_export"] = json!(true);
        features
    }

    async fn seed_api_key(pool: &PgPool, tenant_id: &str, scopes: &[&str]) -> String {
        let key = format!("am_adv_{}", uuid::Uuid::new_v4().simple());
        let secret = crate::app::test_support::test_config().api_key_hash_secret;
        let hash = apexmail_lib::hash_api_key_with_secret(&key, &secret);
        sqlx::query(
            "INSERT INTO api_keys (id, tenant_id, name, key_hash, key_prefix, scopes, created_at, updated_at)
             VALUES (gen_random_uuid(), $1, 'adversarial', $2, $3, $4, NOW(), NOW())",
        )
        .bind(tenant_id)
        .bind(&hash)
        .bind(&key[..8])
        .bind(serde_json::to_value(scopes).unwrap())
        .execute(pool)
        .await
        .expect("seed api key");
        key
    }

    /// Seed a tenant whose plan carries `features`, and an API key.
    async fn tenant_with_key(
        pool: &PgPool,
        features: serde_json::Value,
        scopes: &[&str],
    ) -> (String, String) {
        let tenant_id = unique_tenant();
        seed_tenant(pool, &tenant_id, features).await;
        let key = seed_api_key(pool, &tenant_id, scopes).await;
        (tenant_id, key)
    }

    struct Harness {
        app: Router,
        pool: PgPool,
        tenant_id: String,
        key: String,
    }

    async fn harness(suffix: &str) -> Option<Harness> {
        let pool = pool_for(suffix).await?;
        let tenant_id = unique_tenant();
        seed_tenant(&pool, &tenant_id, full_features()).await;
        let key = seed_api_key(&pool, &tenant_id, &["analytics:read"]).await;
        let state = crate::app::test_support::test_state_over(pool.clone()).await;
        Some(Harness {
            app: build_app(state),
            pool,
            tenant_id,
            key,
        })
    }

    /// RFC 3339 with `Z` — `+00:00` would decode to a space in a query
    /// string and turn every ranged request into a 400.
    fn rfc(dt: DateTime<Utc>) -> String {
        dt.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
    }

    async fn json_response(response: axum::response::Response) -> (StatusCode, serde_json::Value) {
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("response body readable");
        let value = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
        (status, value)
    }

    /// The `error.code` of a JSON error body (empty when not JSON).
    fn body_json_code(body: &[u8]) -> String {
        serde_json::from_slice::<serde_json::Value>(body)
            .ok()
            .and_then(|value| value["error"]["code"].as_str().map(str::to_string))
            .unwrap_or_default()
    }

    async fn get(harness: &Harness, uri: &str) -> (StatusCode, serde_json::Value) {
        let response = harness
            .app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(uri)
                    .header("x-api-key", &harness.key)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        json_response(response).await
    }

    async fn get_raw(harness: &Harness, uri: &str) -> (StatusCode, axum::http::HeaderMap, Vec<u8>) {
        let response = harness
            .app
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(uri)
                    .header("x-api-key", &harness.key)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = response.status();
        let headers = response.headers().clone();
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap()
            .to_vec();
        (status, headers, bytes)
    }

    async fn post_json(
        harness: &Harness,
        uri: &str,
        content_type: Option<&str>,
        body: &str,
    ) -> (StatusCode, serde_json::Value) {
        let mut builder = Request::builder()
            .method("POST")
            .uri(uri)
            .header("x-api-key", &harness.key);
        if let Some(content_type) = content_type {
            builder = builder.header("content-type", content_type);
        }
        let response = harness
            .app
            .clone()
            .oneshot(builder.body(Body::from(body.to_string())).unwrap())
            .await
            .unwrap();
        json_response(response).await
    }

    async fn seed_message(
        pool: &PgPool,
        tenant: &str,
        status: &str,
        subject: &str,
        created_at: DateTime<Utc>,
    ) -> uuid::Uuid {
        let id = uuid::Uuid::new_v4();
        sqlx::query(
            "INSERT INTO messages (id, tenant_id, from_email, to_emails, subject, status, created_at, updated_at)
             VALUES ($1, $2, 'sender@apexmail.ee', $3, $4, $5, $6, $6)",
        )
        .bind(id)
        .bind(tenant)
        .bind(json!(["recipient@example.com"]))
        .bind(subject)
        .bind(status)
        .bind(created_at)
        .execute(pool)
        .await
        .expect("seed message");
        id
    }

    async fn seed_event(
        pool: &PgPool,
        tenant: &str,
        message_id: Option<uuid::Uuid>,
        event_type: &str,
        timestamp: DateTime<Utc>,
    ) {
        sqlx::query(
            "INSERT INTO events (id, tenant_id, message_id, event_type, timestamp)
             VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(uuid::Uuid::new_v4().simple().to_string())
        .bind(tenant)
        .bind(message_id.map(|id| id.to_string()))
        .bind(event_type)
        .bind(timestamp)
        .execute(pool)
        .await
        .expect("seed event");
    }

    fn approx(left: f64, right: f64) -> bool {
        (left - right).abs() < 1e-9
    }

    // ── authentication / scope / tenant-status contract ────────

    #[tokio::test]
    async fn adversarial_analytics_auth_and_scope_contract() {
        let Some(pool) = pool_for("auth_scope").await else {
            return;
        };
        let (tenant, key) = tenant_with_key(&pool, full_features(), &["analytics:read"]).await;
        let state = crate::app::test_support::test_state_over(pool.clone()).await;
        let app = build_app(state);

        // Missing credential.
        let response = app
            .clone()
            .oneshot(
                Request::get("/v1/analytics/dashboard")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        // Garbage credential.
        let response = app
            .clone()
            .oneshot(
                Request::get("/v1/analytics/dashboard")
                    .header("x-api-key", "am_not_a_real_key")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        // Valid identity but missing the analytics:read scope: 403.
        let no_scope_key = seed_api_key(&pool, &tenant, &["billing:read"]).await;
        let response = app
            .clone()
            .oneshot(
                Request::get("/v1/analytics/dashboard")
                    .header("x-api-key", &no_scope_key)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);

        // Expired key: authenticated shape, refused.
        let expired_key = format!("am_adv_{}", uuid::Uuid::new_v4().simple());
        let secret = crate::app::test_support::test_config().api_key_hash_secret;
        sqlx::query(
            "INSERT INTO api_keys (id, tenant_id, name, key_hash, key_prefix, scopes, expires_at, created_at, updated_at)
             VALUES (gen_random_uuid(), $1, 'expired', $2, $3, '[\"analytics:read\"]'::jsonb, NOW() - INTERVAL '1 hour', NOW(), NOW())",
        )
        .bind(&tenant)
        .bind(apexmail_lib::hash_api_key_with_secret(&expired_key, &secret))
        .bind(&expired_key[..8])
        .execute(&pool)
        .await
        .unwrap();
        let response = app
            .clone()
            .oneshot(
                Request::get("/v1/analytics/dashboard")
                    .header("x-api-key", &expired_key)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        // Suspended tenant: the analytics surface is NOT in the
        // billing-recovery allowlist, so a valid key stops authenticating.
        let suspended = unique_tenant();
        seed_tenant(&pool, &suspended, full_features()).await;
        sqlx::query("UPDATE tenants SET status = 'suspended' WHERE id = $1")
            .bind(&suspended)
            .execute(&pool)
            .await
            .unwrap();
        let suspended_key = seed_api_key(&pool, &suspended, &["analytics:read"]).await;
        let response = app
            .clone()
            .oneshot(
                Request::get("/v1/analytics/dashboard")
                    .header("x-api-key", &suspended_key)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        // Key for a tenant row that has vanished fails closed.
        let ghost_key = seed_api_key(&pool, &unique_tenant(), &["analytics:read"]).await;
        let response = app
            .oneshot(
                Request::get("/v1/analytics/dashboard")
                    .header("x-api-key", &ghost_key)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        // The good key still works and only sees its own tenant.
        let (status, body) = get(
            &Harness {
                app: build_app(crate::app::test_support::test_state_over(pool.clone()).await),
                pool: pool.clone(),
                tenant_id: tenant.clone(),
                key: key.clone(),
            },
            "/v1/analytics/dashboard",
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["data"]["total_sent"], 0);
    }

    // ── dashboard: counts, rates, ranges, isolation ─────────────

    #[tokio::test]
    async fn adversarial_dashboard_counts_rates_and_tenant_isolation() {
        let Some(h) = harness("dashboard_counts").await else {
            return;
        };
        let now = Utc::now();
        let delivered = seed_message(
            &h.pool,
            &h.tenant_id,
            "delivered",
            "ok",
            now - TimeDelta::hours(1),
        )
        .await;
        seed_message(
            &h.pool,
            &h.tenant_id,
            "sent",
            "ok",
            now - TimeDelta::hours(2),
        )
        .await;
        seed_message(
            &h.pool,
            &h.tenant_id,
            "bounced",
            "bad",
            now - TimeDelta::hours(3),
        )
        .await;
        // Non-counting statuses must be excluded from every numerator.
        seed_message(
            &h.pool,
            &h.tenant_id,
            "pending",
            "queued",
            now - TimeDelta::hours(4),
        )
        .await;
        seed_message(
            &h.pool,
            &h.tenant_id,
            "failed",
            "failed",
            now - TimeDelta::hours(5),
        )
        .await;
        seed_event(
            &h.pool,
            &h.tenant_id,
            Some(delivered),
            "opened",
            now - TimeDelta::hours(1),
        )
        .await;
        seed_event(
            &h.pool,
            &h.tenant_id,
            Some(delivered),
            "opened",
            now - TimeDelta::hours(1),
        )
        .await;
        seed_event(
            &h.pool,
            &h.tenant_id,
            Some(delivered),
            "clicked",
            now - TimeDelta::hours(1),
        )
        .await;
        seed_event(
            &h.pool,
            &h.tenant_id,
            Some(delivered),
            "complained",
            now - TimeDelta::hours(1),
        )
        .await;

        // Another tenant's data must never leak into the response.
        let other = unique_tenant();
        seed_tenant(&h.pool, &other, full_features()).await;
        seed_message(&h.pool, &other, "delivered", "other", now).await;
        seed_event(&h.pool, &other, None, "opened", now).await;

        let (status, body) = get(&h, "/v1/analytics/dashboard").await;
        assert_eq!(status, StatusCode::OK);
        let data = &body["data"];
        assert_eq!(
            data["total_sent"], 2,
            "only sent+delivered count as sent: {body}"
        );
        assert_eq!(data["total_delivered"], 1);
        assert_eq!(data["total_bounced"], 1);
        assert_eq!(data["total_opened"], 2);
        assert_eq!(data["total_clicked"], 1);
        assert!(approx(data["delivery_rate"].as_f64().unwrap(), 0.5));
        // safe_ratio does not clamp: 2 opens / 1 delivered.
        assert!(approx(data["open_rate"].as_f64().unwrap(), 2.0));
        assert!(approx(data["click_rate"].as_f64().unwrap(), 1.0));

        // Range excludes everything -> zeros, never division by zero NaNs.
        let from = rfc(now + TimeDelta::hours(1));
        let to = rfc(now + TimeDelta::hours(2));
        let (status, body) = get(&h, &format!("/v1/analytics/dashboard?from={from}&to={to}")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["data"]["total_sent"], 0);
        assert_eq!(body["data"]["delivery_rate"], 0.0);
        assert_eq!(body["data"]["open_rate"], 0.0);

        // `from` before 2020 is floored (no unbounded history scan).
        let (status, body) = get(
            &h,
            "/v1/analytics/dashboard?from=1970-01-01T00:00:00Z&to=1970-02-01T00:00:00Z",
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["data"]["total_sent"], 0);

        // Over-wide range is rejected, not silently clamped.
        let (status, body) = get(
            &h,
            "/v1/analytics/dashboard?from=2020-01-01T00:00:00Z&to=2021-06-01T00:00:00Z",
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(
            body["error"]["message"]
                .as_str()
                .unwrap_or_default()
                .contains("366"),
            "unexpected body: {body}"
        );

        // Hostile query surface: unknown field and malformed dates.
        let (status, _) = get(&h, "/v1/analytics/dashboard?bogus=1").await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        let (status, _) = get(&h, "/v1/analytics/dashboard?from=not-a-date").await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        let (status, _) = get(&h, "/v1/analytics/volume?from=2020-01-01").await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    // ── volume: interval buckets ────────────────────────────────

    #[tokio::test]
    async fn adversarial_volume_interval_buckets() {
        let Some(h) = harness("volume_buckets").await else {
            return;
        };
        let day1 = DateTime::from_timestamp(1_767_610_500, 0).unwrap(); // 2026-01-05T10:15:00Z
        let day1_late = DateTime::from_timestamp(1_767_615_900, 0).unwrap(); // 11:45Z
        let day2 = DateTime::from_timestamp(1_767_693_600, 0).unwrap(); // 2026-01-06T09:20Z
        seed_message(&h.pool, &h.tenant_id, "delivered", "a", day1).await;
        seed_message(&h.pool, &h.tenant_id, "bounced", "b", day1_late).await;
        seed_message(&h.pool, &h.tenant_id, "sent", "c", day2).await;

        let range = "from=2026-01-05T00:00:00Z&to=2026-01-07T00:00:00Z";
        for (interval, expected_points) in [
            ("day", 2usize),
            ("hour", 3),
            ("week", 1),
            ("month", 1),
            ("grapes", 2),
        ] {
            let (status, body) = get(
                &h,
                &format!("/v1/analytics/volume?{range}&interval={interval}"),
            )
            .await;
            assert_eq!(status, StatusCode::OK, "interval {interval}: {body}");
            let points = body["data"].as_array().expect("volume array");
            assert_eq!(
                points.len(),
                expected_points,
                "interval {interval} should bucket into {expected_points}: {body}"
            );
        }

        // Input is used only through the static query table: an SQL-ish
        // interval selects the day fallback, never a dynamic statement.
        let (status, body) = get(
            &h,
            &format!(
                "/v1/analytics/volume?{range}&interval=day%27%3B%20DROP%20TABLE%20messages%3B--"
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["data"].as_array().unwrap().len(), 2);

        // Tenant with no messages gets an empty series, not an error.
        let (empty_tenant, empty_key) =
            tenant_with_key(&h.pool, full_features(), &["analytics:read"]).await;
        let empty = Harness {
            app: h.app.clone(),
            pool: h.pool.clone(),
            tenant_id: empty_tenant,
            key: empty_key,
        };
        let (status, body) = get(&empty, &format!("/v1/analytics/volume?{range}")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["data"].as_array().unwrap().len(), 0);
    }

    // ── engagement / deliverability entitlement gates ───────────

    #[tokio::test]
    async fn adversarial_engagement_and_deliverability_gate_and_math() {
        let Some(pool) = pool_for("engagement_gate").await else {
            return;
        };
        // Plan WITHOUT advanced analytics: both endpoints must refuse
        // BEFORE running any query (fail closed).
        let mut basic = full_features();
        basic["advanced_analytics"] = json!(false);
        let (basic_tenant, basic_key) = tenant_with_key(&pool, basic, &["analytics:read"]).await;
        let state = crate::app::test_support::test_state_over(pool.clone()).await;
        let app = build_app(state);
        let basic = Harness {
            app: app.clone(),
            pool: pool.clone(),
            tenant_id: basic_tenant.clone(),
            key: basic_key,
        };
        for uri in ["/v1/analytics/engagement", "/v1/analytics/deliverability"] {
            let (status, body) = get(&basic, uri).await;
            assert_eq!(status, StatusCode::FORBIDDEN, "{uri}: {body}");
        }

        // Entitled tenant: exact rates including hostile numerators.
        let (tenant, key) = tenant_with_key(&pool, full_features(), &["analytics:read"]).await;
        let h = Harness {
            app,
            pool: pool.clone(),
            tenant_id: tenant,
            key,
        };
        let now = Utc::now();
        let m1 = seed_message(
            &h.pool,
            &h.tenant_id,
            "delivered",
            "a",
            now - TimeDelta::hours(2),
        )
        .await;
        seed_message(
            &h.pool,
            &h.tenant_id,
            "delivered",
            "b",
            now - TimeDelta::hours(2),
        )
        .await;
        seed_message(
            &h.pool,
            &h.tenant_id,
            "bounced",
            "c",
            now - TimeDelta::hours(2),
        )
        .await;
        seed_event(
            &h.pool,
            &h.tenant_id,
            Some(m1),
            "opened",
            now - TimeDelta::hours(1),
        )
        .await;
        seed_event(
            &h.pool,
            &h.tenant_id,
            Some(m1),
            "opened",
            now - TimeDelta::hours(1),
        )
        .await;
        seed_event(
            &h.pool,
            &h.tenant_id,
            Some(m1),
            "opened",
            now - TimeDelta::hours(1),
        )
        .await;
        seed_event(
            &h.pool,
            &h.tenant_id,
            Some(m1),
            "clicked",
            now - TimeDelta::hours(1),
        )
        .await;
        seed_event(
            &h.pool,
            &h.tenant_id,
            Some(m1),
            "unsubscribed",
            now - TimeDelta::hours(1),
        )
        .await;

        let (status, body) = get(&h, "/v1/analytics/engagement").await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let data = &body["data"];
        assert!(approx(data["open_rate"].as_f64().unwrap(), 1.5), "{data}");
        assert!(approx(data["click_rate"].as_f64().unwrap(), 0.5));
        assert!(approx(data["unsubscribe_rate"].as_f64().unwrap(), 0.5));
        assert_eq!(data["timeseries"].as_array().unwrap().len(), 1);

        // Deliverability: complaints may exceed deliveries; inbox_rate is
        // clamped at 0 and complaint_rate is allowed above 1 (honest ratio).
        for _ in 0..5 {
            seed_event(
                &h.pool,
                &h.tenant_id,
                Some(m1),
                "complained",
                now - TimeDelta::minutes(30),
            )
            .await;
        }
        let (status, body) = get(&h, "/v1/analytics/deliverability").await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let data = &body["data"];
        assert!(approx(data["delivery_rate"].as_f64().unwrap(), 2.0 / 3.0));
        assert!(approx(data["bounce_rate"].as_f64().unwrap(), 1.0 / 3.0));
        assert!(approx(data["complaint_rate"].as_f64().unwrap(), 2.5));
        assert_eq!(data["inbox_rate"], 0.0);

        // Zero traffic: every ratio is 0.0, never NaN.
        let (empty_tenant, empty_key) =
            tenant_with_key(&pool, full_features(), &["analytics:read"]).await;
        let empty = Harness {
            app: h.app.clone(),
            pool: h.pool.clone(),
            tenant_id: empty_tenant,
            key: empty_key,
        };
        let (status, body) = get(&empty, "/v1/analytics/deliverability").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["data"]["delivery_rate"], 0.0);
        assert_eq!(body["data"]["complaint_rate"], 0.0);
        assert_eq!(body["data"]["inbox_rate"], 0.0);
    }

    // ── subject-line analysis: body validation contract ─────────

    #[tokio::test]
    async fn adversarial_subject_line_validation_contract() {
        let Some(h) = harness("subject_line").await else {
            return;
        };
        let path = "/v1/analytics/subject-line";

        // Missing auth never reaches the body extractor.
        let response = h
            .app
            .clone()
            .oneshot(
                Request::post(path)
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"subject":"hello"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        // Wrong content type is a 415, not a silent success.
        let (status, _) = post_json(&h, path, Some("text/plain"), r#"{"subject":"hi"}"#).await;
        assert_eq!(status, StatusCode::UNSUPPORTED_MEDIA_TYPE);
        let (status, _) = post_json(&h, path, None, r#"{"subject":"hi"}"#).await;
        assert_eq!(status, StatusCode::UNSUPPORTED_MEDIA_TYPE);

        // Malformed JSON -> 400; unknown field / wrong type -> 422.
        let (status, _) = post_json(&h, path, Some("application/json"), "{not json").await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        let (status, _) = post_json(
            &h,
            path,
            Some("application/json"),
            r#"{"subject":"hi","extra":1}"#,
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        let (status, _) = post_json(&h, path, Some("application/json"), r#"{"subject":42}"#).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        // Duplicate keys are refused by serde's struct deserializer — no
        // "last one wins" ambiguity for a body the analyzer scores.
        let (status, _) = post_json(
            &h,
            path,
            Some("application/json"),
            r#"{"subject":"","subject":"first winner"}"#,
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);

        // Empty / whitespace-only subjects are refused. (U+200B is NOT
        // Unicode whitespace, so it is data — asserted below, not here.)
        for subject in ["", "   ", "\t\n"] {
            let (status, body) = post_json(
                &h,
                path,
                Some("application/json"),
                &json!({"subject": subject}).to_string(),
            )
            .await;
            assert_eq!(
                status,
                StatusCode::BAD_REQUEST,
                "subject {subject:?}: {body}"
            );
            assert_eq!(body["error"]["code"], "VALIDATION_ERROR", "{body}");
        }

        // Exactly 200 characters is the boundary; 201 is over the limit.
        let ok = "a".repeat(200);
        let (status, body) = post_json(
            &h,
            path,
            Some("application/json"),
            &json!({"subject": ok}).to_string(),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let over = "a".repeat(201);
        let (status, body) = post_json(
            &h,
            path,
            Some("application/json"),
            &json!({"subject": over}).to_string(),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        // Validation failures carry the human message in `details`.
        assert!(
            body["error"]["details"][0]
                .as_str()
                .unwrap_or_default()
                .contains("200"),
            "{body}"
        );
        assert_eq!(body["error"]["code"], "VALIDATION_ERROR");

        // The limit counts CHARACTERS, not bytes: 200 astral-plane emoji
        // (800 UTF-8 bytes) pass; 201 fail. A byte-based check would
        // reject the first as well.
        let emoji_ok = "🦄".repeat(200);
        let (status, body) = post_json(
            &h,
            path,
            Some("application/json"),
            &json!({"subject": emoji_ok}).to_string(),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let emoji_over = "🦄".repeat(201);
        let (status, _) = post_json(
            &h,
            path,
            Some("application/json"),
            &json!({"subject": emoji_over}).to_string(),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);

        // RTL / combining marks / NUL / SQL-ish content is data, not syntax
        // (NUL survives into the analyzer rather than panicking a char scan).
        for subject in [
            "\u{202e}gnp.exe",
            "e\u{0301}\u{0301}",
            "\0",
            " \u{200b} ",
            "'; DROP TABLE events; --",
        ] {
            let (status, _) = post_json(
                &h,
                path,
                Some("application/json"),
                &json!({"subject": subject}).to_string(),
            )
            .await;
            assert_eq!(status, StatusCode::OK, "subject {subject:?}");
        }
        // The events table still exists after the SQL-ish subject.
        let exists: bool =
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_tables WHERE tablename = 'events')")
                .fetch_one(&h.pool)
                .await
                .unwrap();
        assert!(exists);
    }

    // ── export lifecycle, artifact store, download ──────────────

    #[tokio::test]
    async fn adversarial_export_artifact_lifecycle_and_download() {
        let Some(h) = harness("export_lifecycle").await else {
            return;
        };
        let dir = std::env::temp_dir().join(format!("adv-analytics-{}", uuid::Uuid::new_v4()));
        let _guard = lock_export_env().await;
        std::env::set_var("EXPORT_STORAGE_PATH", &dir);

        let now = Utc::now();
        let from = now - TimeDelta::days(1);
        let to = now;
        let m1 = seed_message(
            &h.pool,
            &h.tenant_id,
            "delivered",
            "=SUM(A1:A2)",
            now - TimeDelta::hours(2),
        )
        .await;
        seed_event(
            &h.pool,
            &h.tenant_id,
            Some(m1),
            "opened",
            now - TimeDelta::minutes(30),
        )
        .await;
        // A message whose first recipient is NULL/empty must not fail the
        // whole export (JSONB array empty).
        sqlx::query(
            "INSERT INTO messages (id, tenant_id, from_email, to_emails, subject, status, created_at, updated_at)
             VALUES ($1, $2, 's@apexmail.ee', '[]'::jsonb, NULL, 'sent', $3, $3)",
        )
        .bind(uuid::Uuid::new_v4())
        .bind(&h.tenant_id)
        .bind(now - TimeDelta::hours(3))
        .execute(&h.pool)
        .await
        .unwrap();

        // CSV (default for unknown formats too).
        let csv_job = uuid::Uuid::new_v4();
        sqlx::query(
            "INSERT INTO export_jobs (id, tenant_id, job_type, status, format, date_range_start, date_range_end, created_by, created_at)
             VALUES ($1, $2, 'analytics', 'pending', 'csv', $3, $4, 'system', NOW())",
        )
        .bind(csv_job)
        .bind(&h.tenant_id)
        .bind(from)
        .bind(to)
        .execute(&h.pool)
        .await
        .unwrap();
        process_analytics_export(
            h.pool.clone(),
            csv_job,
            h.tenant_id.clone(),
            from,
            to,
            "xlsx".to_string(),
        )
        .await
        .expect("csv export must complete");

        let (status, total_rows, file_size, download_url, error): (
            String,
            Option<i64>,
            Option<i64>,
            Option<String>,
            Option<String>,
        ) = sqlx::query_as(
            "SELECT status, total_rows, file_size_bytes, download_url, error_message
             FROM export_jobs WHERE id = $1",
        )
        .bind(csv_job)
        .fetch_one(&h.pool)
        .await
        .unwrap();
        assert_eq!(status, "completed", "error: {error:?}");
        assert_eq!(total_rows, Some(2));
        assert!(file_size.unwrap_or(0) > 0);
        assert_eq!(
            download_url,
            Some(format!("/v1/analytics/export/{csv_job}/download"))
        );

        // Unknown format falls back to CSV content and extension.
        let artifact = dir.join(format!("exports_{}_{}.csv", h.tenant_id, csv_job));
        let csv = std::fs::read_to_string(&artifact).expect("csv artifact on disk");
        assert!(csv.starts_with("message_id,subject,recipient,created_at,last_event,event_time\n"));
        assert!(
            csv.contains("'=SUM(A1:A2)"),
            "formula-like subject must be neutralised: {csv}"
        );
        assert!(
            csv.contains("opened"),
            "last_event must reflect the event: {csv}"
        );

        // JSON export.
        let json_job = uuid::Uuid::new_v4();
        sqlx::query(
            "INSERT INTO export_jobs (id, tenant_id, job_type, status, format, date_range_start, date_range_end, created_by, created_at)
             VALUES ($1, $2, 'analytics', 'pending', 'json', $3, $4, 'system', NOW())",
        )
        .bind(json_job)
        .bind(&h.tenant_id)
        .bind(from)
        .bind(to)
        .execute(&h.pool)
        .await
        .unwrap();
        process_analytics_export(
            h.pool.clone(),
            json_job,
            h.tenant_id.clone(),
            from,
            to,
            "json".to_string(),
        )
        .await
        .expect("json export must complete");
        let json_artifact = dir.join(format!("exports_{}_{}.json", h.tenant_id, json_job));
        let raw = std::fs::read_to_string(&json_artifact).expect("json artifact");
        let parsed: serde_json::Value = serde_json::from_str(&raw).expect("pretty JSON array");
        assert_eq!(parsed.as_array().unwrap().len(), 2);
        assert_eq!(
            parsed[0]["subject"].as_str().unwrap_or_default(),
            "=SUM(A1:A2)"
        );

        // Router status view: real statuses, expired links hidden.
        let (status, body) = get(&h, &format!("/v1/analytics/export/{json_job}")).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["data"]["status"], "completed");
        assert_eq!(body["data"]["job_id"], json_job.to_string());
        assert!(body["data"]["download_url"].is_string(), "{body}");

        // Expired completed job hides the link.
        let expired_job = uuid::Uuid::new_v4();
        sqlx::query(
            "INSERT INTO export_jobs (id, tenant_id, job_type, status, format, date_range_start, date_range_end, download_url, download_expires_at, created_at)
             VALUES ($1, $2, 'analytics', 'completed', 'csv', $3, $4, '/x', NOW() - INTERVAL '1 hour', NOW())",
        )
        .bind(expired_job)
        .bind(&h.tenant_id)
        .bind(from)
        .bind(to)
        .execute(&h.pool)
        .await
        .unwrap();
        let (status, body) = get(&h, &format!("/v1/analytics/export/{expired_job}")).await;
        assert_eq!(status, StatusCode::OK);
        assert!(body["data"]["download_url"].is_null(), "{body}");

        // Unknown job and another tenant's job are both 404 (no existence oracle).
        let (status, _) = get(
            &h,
            &format!("/v1/analytics/export/{}", uuid::Uuid::new_v4()),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        let other = unique_tenant();
        seed_tenant(&h.pool, &other, full_features()).await;
        let other_job = uuid::Uuid::new_v4();
        sqlx::query(
            "INSERT INTO export_jobs (id, tenant_id, job_type, status, format, date_range_start, date_range_end, created_at)
             VALUES ($1, $2, 'analytics', 'completed', 'csv', $3, $4, NOW())",
        )
        .bind(other_job)
        .bind(&other)
        .bind(from)
        .bind(to)
        .execute(&h.pool)
        .await
        .unwrap();
        let (status, _) = get(&h, &format!("/v1/analytics/export/{other_job}")).await;
        assert_eq!(status, StatusCode::NOT_FOUND);

        // Download: real bytes with attachment headers.
        let (status, headers, bytes) =
            get_raw(&h, &format!("/v1/analytics/export/{csv_job}/download")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(headers[header::CONTENT_TYPE].to_str().unwrap(), "text/csv");
        assert_eq!(
            headers[header::CONTENT_DISPOSITION].to_str().unwrap(),
            format!("attachment; filename=\"analytics-export-{csv_job}.csv\"")
        );
        // The global security-headers middleware tightens the route's
        // `private, no-store`; the export must never be cacheable.
        assert!(
            headers[header::CACHE_CONTROL]
                .to_str()
                .unwrap()
                .contains("no-store"),
            "export artifact must not be cacheable: {:?}",
            headers[header::CACHE_CONTROL]
        );
        assert_eq!(bytes, std::fs::read(&artifact).unwrap());

        // Expired link refuses even though the artifact exists.
        let (status, _, body) =
            get_raw(&h, &format!("/v1/analytics/export/{expired_job}/download")).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert!(
            String::from_utf8_lossy(&body).contains("expired"),
            "unexpected body: {}",
            String::from_utf8_lossy(&body)
        );

        // Completed row whose artifact vanished: fail closed, no panic.
        let missing_job = uuid::Uuid::new_v4();
        sqlx::query(
            "INSERT INTO export_jobs (id, tenant_id, job_type, status, format, date_range_start, date_range_end, download_url, download_expires_at, created_at)
             VALUES ($1, $2, 'analytics', 'completed', 'csv', $3, $4, '/x', NOW() + INTERVAL '1 hour', NOW())",
        )
        .bind(missing_job)
        .bind(&h.tenant_id)
        .bind(from)
        .bind(to)
        .execute(&h.pool)
        .await
        .unwrap();
        let (status, _, body) =
            get_raw(&h, &format!("/v1/analytics/export/{missing_job}/download")).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert!(
            String::from_utf8_lossy(&body).contains("unavailable"),
            "unexpected body: {}",
            String::from_utf8_lossy(&body)
        );

        // Not-yet-completed jobs are 404 on the download route.
        let pending_job = uuid::Uuid::new_v4();
        sqlx::query(
            "INSERT INTO export_jobs (id, tenant_id, job_type, status, format, date_range_start, date_range_end, created_at)
             VALUES ($1, $2, 'analytics', 'failed', 'csv', $3, $4, NOW())",
        )
        .bind(pending_job)
        .bind(&h.tenant_id)
        .bind(from)
        .bind(to)
        .execute(&h.pool)
        .await
        .unwrap();
        let (status, _, _) =
            get_raw(&h, &format!("/v1/analytics/export/{pending_job}/download")).await;
        assert_eq!(status, StatusCode::NOT_FOUND);

        // Other tenant's artifact key is unreachable from this tenant.
        let (status, _, _) =
            get_raw(&h, &format!("/v1/analytics/export/{other_job}/download")).await;
        assert_eq!(status, StatusCode::NOT_FOUND);

        std::env::remove_var("EXPORT_STORAGE_PATH");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn adversarial_export_endpoint_fail_closed_and_job_row() {
        let Some(pool) = pool_for("export_endpoint").await else {
            return;
        };
        let dir = std::env::temp_dir().join(format!("adv-analytics-ep-{}", uuid::Uuid::new_v4()));
        let _guard = lock_export_env().await;
        std::env::set_var("EXPORT_STORAGE_PATH", &dir);

        // Tenant WITHOUT data_export: the handler must refuse and write NO row.
        let mut basic = full_features();
        basic["data_export"] = json!(false);
        let (basic_tenant, basic_key) = tenant_with_key(&pool, basic, &["analytics:read"]).await;
        let state = crate::app::test_support::test_state_over(pool.clone()).await;
        let app = build_app(state);
        let h = Harness {
            app: app.clone(),
            pool: pool.clone(),
            tenant_id: basic_tenant.clone(),
            key: basic_key,
        };
        let (status, body) = get(&h, "/v1/analytics/export").await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
        let rows: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM export_jobs WHERE tenant_id = $1")
            .bind(&basic_tenant)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(rows, 0, "refused export must not create a job row");

        // Over-wide range on an ENTITLED tenant also writes no row.
        let (tenant, key) = tenant_with_key(&pool, full_features(), &["analytics:read"]).await;
        let h = Harness {
            app,
            pool: pool.clone(),
            tenant_id: tenant.clone(),
            key,
        };
        let (status, _) = get(
            &h,
            "/v1/analytics/export?from=2020-01-01T00:00:00Z&to=2021-06-01T00:00:00Z",
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);

        // Valid request: 200 immediately with a processing job, and the
        // background worker marks it completed with a stored artifact.
        let now = Utc::now();
        let from = now - TimeDelta::days(2);
        seed_message(
            &h.pool,
            &h.tenant_id,
            "delivered",
            "export me",
            now - TimeDelta::hours(1),
        )
        .await;
        let uri = format!(
            "/v1/analytics/export?from={}&to={}&format=json",
            rfc(from),
            rfc(now)
        );
        let (status, body) = get(&h, &uri).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["data"]["status"], "processing");
        // The response is deliberately snake_case here (no rename attr).
        assert!(body["data"]["job_id"].is_string(), "{body}");
        assert!(body["data"]["download_url"].is_null());
        let job_id: uuid::Uuid = body["data"]["job_id"].as_str().unwrap().parse().unwrap();

        // Wait (bounded) for the spawned worker to finish.
        let mut final_status = String::new();
        for _ in 0..100 {
            let row: Option<(String, Option<String>)> =
                sqlx::query_as("SELECT status, error_message FROM export_jobs WHERE id = $1")
                    .bind(job_id)
                    .fetch_optional(&h.pool)
                    .await
                    .unwrap();
            match row {
                Some((status, _)) if status == "completed" || status == "failed" => {
                    final_status = status;
                    break;
                }
                _ => tokio::time::sleep(std::time::Duration::from_millis(50)).await,
            }
        }
        assert_eq!(final_status, "completed", "export worker never finished");
        let format: String = sqlx::query_scalar("SELECT format FROM export_jobs WHERE id = $1")
            .bind(job_id)
            .fetch_one(&h.pool)
            .await
            .unwrap();
        assert_eq!(format, "json");

        // A storage failure AFTER the job row exists must mark the job
        // `failed` with an error message (never leave it `pending` forever).
        // `EXPORT_STORAGE_PATH` pointing *under a regular file* is
        // uncreatable on every platform.
        let blocker = dir.join("blocker-file");
        std::fs::write(&blocker, b"not a directory").unwrap();
        std::env::set_var("EXPORT_STORAGE_PATH", blocker.join("nested"));
        let (status, body) = get(&h, &uri).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let failing_job: uuid::Uuid = body["data"]["job_id"].as_str().unwrap().parse().unwrap();
        let mut outcome: Option<(String, Option<String>)> = None;
        for _ in 0..100 {
            let row: Option<(String, Option<String>)> =
                sqlx::query_as("SELECT status, error_message FROM export_jobs WHERE id = $1")
                    .bind(failing_job)
                    .fetch_optional(&h.pool)
                    .await
                    .unwrap();
            match row {
                Some((status, error)) if status == "failed" => {
                    outcome = Some((status, error));
                    break;
                }
                Some((status, error)) if status == "completed" => {
                    outcome = Some((status, error));
                    break;
                }
                _ => tokio::time::sleep(std::time::Duration::from_millis(50)).await,
            }
        }
        let (failed_status, error_message) =
            outcome.expect("export job never reached a terminal state");
        assert_eq!(
            failed_status, "failed",
            "unwritable storage must fail the job, got {failed_status}"
        );
        assert!(
            !error_message.unwrap_or_default().is_empty(),
            "failed job must carry an error message"
        );

        std::env::remove_var("EXPORT_STORAGE_PATH");
        std::fs::remove_dir_all(&dir).ok();
    }

    // ── PDF export: renderer contract, fail closed ──────────────

    static PDF_ENV_MUTEX: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    /// The lock is deliberately held across awaits: it serialises tests that
    /// mutate a process-global env var, so the env cannot change mid-request.
    async fn lock_export_env() -> tokio::sync::MutexGuard<'static, ()> {
        super::tests::EXPORT_ENV_MUTEX.lock().await
    }

    async fn lock_pdf_env() -> tokio::sync::MutexGuard<'static, ()> {
        PDF_ENV_MUTEX.lock().await
    }

    #[tokio::test]
    async fn adversarial_export_pdf_renderer_contract() {
        let Some(h) = harness("export_pdf").await else {
            return;
        };
        let _guard = lock_pdf_env().await;

        // Local mock renderer: first call succeeds with a PDF, later calls
        // fail — both branches of the renderer contract are asserted.
        let calls = Arc::new(AtomicUsize::new(0));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let mock_calls = calls.clone();
        let mock = Router::new()
            .route(
                "/v1/pdf/render",
                post(move |Json(body): Json<serde_json::Value>| {
                    let calls = mock_calls.clone();
                    async move {
                        assert_eq!(body["template"], "analytics_export");
                        assert!(body["data"]["summary"].is_object());
                        if calls.fetch_add(1, Ordering::SeqCst) == 0 {
                            (
                                StatusCode::OK,
                                [(header::CONTENT_TYPE, "application/pdf")],
                                b"%PDF-1.4 mock".to_vec(),
                            )
                                .into_response()
                        } else {
                            (StatusCode::INTERNAL_SERVER_ERROR, "renderer exploded").into_response()
                        }
                    }
                }),
            )
            .with_state(());
        tokio::spawn(async move {
            let _ = axum::serve(listener, mock).await;
        });
        std::env::set_var("PDF_RENDERER_URL", format!("http://{addr}"));

        let now = Utc::now();
        let uri = format!(
            "/v1/analytics/export/pdf?from={}&to={}",
            rfc(now - TimeDelta::days(1)),
            rfc(now)
        );
        let (status, headers, bytes) = get_raw(&h, &uri).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "{}",
            String::from_utf8_lossy(&bytes)
        );
        assert_eq!(
            headers[header::CONTENT_TYPE].to_str().unwrap(),
            "application/pdf"
        );
        assert!(headers[header::CONTENT_DISPOSITION]
            .to_str()
            .unwrap()
            .starts_with("attachment; filename=\"analytics-export-"));
        assert_eq!(bytes, b"%PDF-1.4 mock");

        // Renderer failure is surfaced as a 500, never as a fake document.
        // (ApiError::Internal masks its message from clients; the proof the
        // renderer was consulted is the mock's own call counter.)
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        let (status, _, body) = get_raw(&h, &uri).await;
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(body_json_code(&body), "INTERNAL_ERROR");

        // Unreachable renderer: fail closed with a 500.
        std::env::set_var("PDF_RENDERER_URL", "http://127.0.0.1:1");
        let (status, _, body) = get_raw(&h, &uri).await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(body_json_code(&body), "INTERNAL_ERROR");

        // Entitlement refusal happens before any renderer call.
        std::env::set_var("PDF_RENDERER_URL", format!("http://{addr}"));
        let mut basic = full_features();
        basic["data_export"] = json!(false);
        let (basic_tenant, basic_key) = tenant_with_key(&h.pool, basic, &["analytics:read"]).await;
        let basic = Harness {
            app: h.app.clone(),
            pool: h.pool.clone(),
            tenant_id: basic_tenant,
            key: basic_key,
        };
        let (status, _, _) = get_raw(&basic, &uri).await;
        assert_eq!(status, StatusCode::FORBIDDEN);

        std::env::remove_var("PDF_RENDERER_URL");
    }

    // ── pure helpers: every arm, hostile values ─────────────────

    #[test]
    fn adversarial_analytics_pure_helper_edges() {
        // safe_ratio never divides by zero and preserves sign of a negative
        // numerator (no clamping, no NaN).
        assert_eq!(safe_ratio(0, 0), 0.0);
        assert_eq!(safe_ratio(5, 0), 0.0);
        assert_eq!(safe_ratio(-5, 0), 0.0);
        assert_eq!(safe_ratio(1, 2), 0.5);
        assert_eq!(safe_ratio(-1, 2), -0.5);
        assert_eq!(safe_ratio(i64::MAX, 1), i64::MAX as f64);

        // CSV escaping: formula prefixes, quoting, embedded quotes/newlines.
        assert_eq!(escape_csv(""), "");
        assert_eq!(escape_csv("plain"), "plain");
        assert_eq!(escape_csv("=1+1"), "'=1+1");
        assert_eq!(escape_csv("+1"), "'+1");
        assert_eq!(escape_csv("-1"), "'-1");
        assert_eq!(escape_csv("@cmd"), "'@cmd");
        // A leading TAB or CR is itself a formula-prefix hazard (spreadsheets
        // strip it before evaluating the rest), and a leading space followed
        // by a formula must be neutralised too. The earlier version trimmed
        // first, so `"\tx"` slipped through unprefixed; the check now runs
        // against the original value, matching billing.rs's
        // `sanitize_csv_value`.
        assert_eq!(escape_csv("\tx"), "'\tx");
        assert_eq!(escape_csv("\rx"), "\"'\rx\"");
        assert_eq!(escape_csv("\t=1+1"), "'\t=1+1");
        assert_eq!(escape_csv("a,b"), "\"a,b\"");
        assert_eq!(escape_csv("say \"hi\""), "\"say \"\"hi\"\"\"");
        assert_eq!(
            escape_csv("  =lead"),
            "'  =lead",
            "the prefix is added to the ORIGINAL value once trimming reveals it"
        );
        assert_eq!(escape_csv("line\nbreak"), "\"line\nbreak\"");

        // Export keys/extensions are exact and case-sensitive.
        let job = uuid::Uuid::nil();
        assert_eq!(export_extension("json"), "json");
        assert_eq!(export_extension("JSON"), "csv");
        assert_eq!(export_extension(""), "csv");
        assert_eq!(
            export_object_key("tenant/../x", job, "json"),
            format!("exports/tenant/../x_{job}.json")
        );
        assert_eq!(
            export_file_name("exports/a/../b.json"),
            "exports_a_.._b.json"
        );
        assert_eq!(export_file_name(""), "");

        // Range resolution: exact 366-day boundary and an inverted range are
        // both accepted unchanged (width is a positive-difference check only).
        let from = analytics_earliest_from();
        let (resolved_from, resolved_to) =
            resolve_analytics_range(Some(from), Some(from + TimeDelta::days(366))).unwrap();
        assert_eq!(resolved_from, from);
        assert_eq!(resolved_to, from + TimeDelta::days(366));
        let (resolved_from, resolved_to) =
            resolve_analytics_range(Some(from), Some(from - TimeDelta::days(1))).unwrap();
        assert_eq!(resolved_from, from);
        assert!(resolved_to < resolved_from);
        assert_eq!(
            analytics_earliest_from().timestamp(),
            1_577_836_800,
            "2020-01-01T00:00:00Z"
        );
        assert!(resolve_analytics_range(Some(from), Some(from + TimeDelta::days(367))).is_err());

        // Subject payload: trimming happens before the length/emptiness rules.
        assert_eq!(
            analyze_subject_line_payload("  hi  ")
                .unwrap()
                .score
                .word_count,
            1
        );
        let exactly_200 = "x".repeat(200);
        assert!(analyze_subject_line_payload(&exactly_200).is_ok());
        let over = "x".repeat(201);
        assert!(analyze_subject_line_payload(&over).is_err());

        // Query table: every interval maps to a static fragment.
        for (interval, needle) in [
            ("hour", "date_trunc('hour'"),
            ("week", "date_trunc('week'"),
            ("month", "date_trunc('month'"),
            ("day", "date_trunc('day'"),
            ("bogus", "date_trunc('day'"),
        ] {
            assert!(
                volume_query_for_interval(interval).contains(needle),
                "{interval}"
            );
        }
    }
}
