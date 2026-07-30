//! Automated report generation endpoints.
//!
//! Provides on-demand report generation, schedule management, and download.

use axum::extract::{Path, State};
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::{DateTime, Datelike, Duration, NaiveDate, NaiveTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;

use crate::admin_report_scheduler::ReportType;
use crate::error::ApiError;
use crate::middleware::auth::AuthUser;
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/generate", post(generate_report))
        .route("/schedule", get(get_schedule))
        .route("/schedule/toggle", post(toggle_schedule))
        .route("/latest", get(get_latest_reports))
        .route("/download/:id", get(download_report))
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GenerateReportRequest {
    pub r#type: String,
    #[serde(default = "default_format")]
    pub format: String,
}

fn default_format() -> String {
    "json".into()
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReportGenerationResponse {
    pub id: Uuid,
    pub report_type: String,
    pub format: String,
    pub period_start: String,
    pub period_end: String,
    pub download_url: String,
    pub generated_at: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScheduleStatusResponse {
    pub schedules: Vec<ScheduleInfo>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScheduleInfo {
    pub report_type: String,
    pub enabled: bool,
    pub next_run: String,
    pub description: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ToggleScheduleRequest {
    pub report_type: String,
    pub enabled: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LatestReportsResponse {
    pub daily: Option<ReportEntry>,
    pub weekly: Option<ReportEntry>,
    pub monthly: Option<ReportEntry>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReportEntry {
    pub id: Uuid,
    pub report_type: String,
    pub format: String,
    pub period_start: String,
    pub period_end: String,
    pub generated_at: String,
    pub data: serde_json::Value,
}

#[derive(Debug, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ReportSummary {
    pub emails_sent: i64,
    pub emails_delivered: i64,
    pub emails_bounced: i64,
    pub emails_complained: i64,
    pub revenue: f64,
}

fn parse_report_type(raw: &str) -> Result<ReportType, ApiError> {
    match raw {
        "daily" => Ok(ReportType::Daily),
        "weekly" => Ok(ReportType::Weekly),
        "monthly" => Ok(ReportType::Monthly),
        other => Err(ApiError::Validation(vec![format!(
            "invalid report_type '{}'. Must be daily, weekly, or monthly",
            other
        )])),
    }
}

fn validate_format(fmt: &str) -> Result<(), ApiError> {
    match fmt {
        "json" | "csv" | "pdf" => Ok(()),
        other => Err(ApiError::Validation(vec![format!(
            "invalid format '{}'. Must be json, csv, or pdf",
            other
        )])),
    }
}

fn report_type_period_start(report_type: ReportType, now: DateTime<Utc>) -> DateTime<Utc> {
    let today = now.date_naive();
    match report_type {
        ReportType::Daily => today.and_hms_opt(0, 0, 0).unwrap().and_utc(),
        ReportType::Weekly => {
            let weekday = today.weekday().num_days_from_monday();
            let monday = today - Duration::days(weekday as i64);
            monday.and_hms_opt(0, 0, 0).unwrap().and_utc()
        }
        ReportType::Monthly => NaiveDate::from_ymd_opt(today.year(), today.month(), 1)
            .unwrap()
            .and_hms_opt(0, 0, 0)
            .unwrap()
            .and_utc(),
    }
}

fn report_type_period_end(report_type: ReportType, now: DateTime<Utc>) -> DateTime<Utc> {
    match report_type {
        ReportType::Daily => report_type_period_start(report_type, now) + Duration::days(1),
        ReportType::Weekly => report_type_period_start(report_type, now) + Duration::days(7),
        ReportType::Monthly => {
            let start = report_type_period_start(report_type, now);
            let next_month = if start.month() == 12 {
                NaiveDate::from_ymd_opt(start.year() + 1, 1, 1)
            } else {
                NaiveDate::from_ymd_opt(start.year(), start.month() + 1, 1)
            };
            next_month.unwrap().and_hms_opt(0, 0, 0).unwrap().and_utc()
        }
    }
}

fn report_type_scheduled_time(report_type: ReportType) -> NaiveTime {
    match report_type {
        ReportType::Daily => NaiveTime::from_hms_opt(0, 5, 0).unwrap(),
        ReportType::Weekly => NaiveTime::from_hms_opt(0, 10, 0).unwrap(),
        ReportType::Monthly => NaiveTime::from_hms_opt(0, 15, 0).unwrap(),
    }
}

async fn collect_metrics(
    db: &PgPool,
    period_start: DateTime<Utc>,
    period_end: DateTime<Utc>,
) -> Result<ReportSummary, ApiError> {
    let (sent, delivered, bounced, complained): (i64, i64, i64, i64) =
        sqlx::query_as(
            "SELECT
                COALESCE(SUM(CASE WHEN event_type = 'send' THEN 1 ELSE 0 END), 0),
                COALESCE(SUM(CASE WHEN event_type = 'delivery' THEN 1 ELSE 0 END), 0),
                COALESCE(SUM(CASE WHEN event_type = 'bounce' THEN 1 ELSE 0 END), 0),
                COALESCE(SUM(CASE WHEN event_type = 'complaint' THEN 1 ELSE 0 END), 0)
             FROM events
             WHERE timestamp >= $1 AND timestamp < $2",
        )
        .bind(period_start)
        .bind(period_end)
        .fetch_one(db)
        .await?;

    let revenue: f64 = sqlx::query_scalar(
        "SELECT COALESCE(SUM(amount_cents) / 100.0, 0.0)
         FROM invoice_line_items
         WHERE created_at >= $1 AND created_at < $2",
    )
    .bind(period_start)
    .bind(period_end)
    .fetch_one(db)
    .await
    .unwrap_or(0.0);

    Ok(ReportSummary {
        emails_sent: sent,
        emails_delivered: delivered,
        emails_bounced: bounced,
        emails_complained: complained,
        revenue,
    })
}

async fn generate_report(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(body): Json<GenerateReportRequest>,
) -> Result<Json<ReportGenerationResponse>, ApiError> {
    crate::middleware::auth::require_scopes(&auth, &["*"])?;
    validate_format(&body.format)?;

    let report_type = parse_report_type(&body.r#type)?;
    let now = Utc::now();
    let period_start = report_type_period_start(report_type, now);
    let period_end = report_type_period_end(report_type, now);

    let summary = collect_metrics(&state.db, period_start, period_end).await?;

    let data = serde_json::to_value(&summary)
        .map_err(|e| ApiError::Internal(format!("serialization error: {e}")))?;

    let report_id = Uuid::new_v4();
    let download_url = format!("/v1/admin/reports/download/{}", report_id);

    sqlx::query(
        "INSERT INTO report_history (id, report_type, format, period_start, period_end, data, generated_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7)",
    )
    .bind(report_id)
    .bind(report_type.as_str())
    .bind(&body.format)
    .bind(period_start)
    .bind(period_end)
    .bind(&data)
    .bind(now)
    .execute(&state.db)
    .await?;

    Ok(Json(ReportGenerationResponse {
        id: report_id,
        report_type: report_type.as_str().to_string(),
        format: body.format,
        period_start: period_start.to_rfc3339(),
        period_end: period_end.to_rfc3339(),
        download_url,
        generated_at: now.to_rfc3339(),
    }))
}

async fn get_schedule(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<Json<ScheduleStatusResponse>, ApiError> {
    crate::middleware::auth::require_scopes(&auth, &["*"])?;

    let now = Utc::now();
    let schedule = state.report_schedule.as_ref();

    let schedules = vec![
        ScheduleInfo {
            report_type: "daily".into(),
            enabled: schedule.map_or(false, |s| s.is_enabled(ReportType::Daily)),
            next_run: compute_next_run(ReportType::Daily, now),
            description: "Generated daily at 00:05 UTC".into(),
        },
        ScheduleInfo {
            report_type: "weekly".into(),
            enabled: schedule.map_or(false, |s| s.is_enabled(ReportType::Weekly)),
            next_run: compute_next_run(ReportType::Weekly, now),
            description: "Generated Monday at 00:10 UTC".into(),
        },
        ScheduleInfo {
            report_type: "monthly".into(),
            enabled: schedule.map_or(false, |s| s.is_enabled(ReportType::Monthly)),
            next_run: compute_next_run(ReportType::Monthly, now),
            description: "Generated 1st of month at 00:15 UTC".into(),
        },
    ];

    Ok(Json(ScheduleStatusResponse { schedules }))
}

fn compute_next_run(report_type: ReportType, now: DateTime<Utc>) -> String {
    let today = now.date_naive();
    let scheduled_time = report_type_scheduled_time(report_type);
    let today_at_scheduled = today.and_time(scheduled_time).and_utc();

    let next = if now < today_at_scheduled {
        today_at_scheduled
    } else {
        match report_type {
            ReportType::Daily => today_at_scheduled + Duration::days(1),
            ReportType::Weekly => today_at_scheduled + Duration::days(7),
            ReportType::Monthly => {
                let next_month = if today.month() == 12 {
                    NaiveDate::from_ymd_opt(today.year() + 1, 1, 1)
                } else {
                    NaiveDate::from_ymd_opt(today.year(), today.month() + 1, 1)
                };
                next_month
                    .unwrap()
                    .and_time(scheduled_time)
                    .and_utc()
            }
        }
    };

    next.to_rfc3339()
}

async fn toggle_schedule(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(body): Json<ToggleScheduleRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    crate::middleware::auth::require_scopes(&auth, &["*"])?;

    let report_type = parse_report_type(&body.report_type)?;
    if let Some(ref schedule) = state.report_schedule {
        schedule.set_enabled(report_type, body.enabled);
    }

    Ok(Json(serde_json::json!({
        "reportType": body.report_type,
        "enabled": body.enabled,
        "message": format!(
            "{} report schedule turned {}",
            body.report_type,
            if body.enabled { "on" } else { "off" }
        )
    })))
}

async fn get_latest_reports(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<Json<LatestReportsResponse>, ApiError> {
    crate::middleware::auth::require_scopes(&auth, &["*"])?;

    let daily = fetch_latest_by_type(&state.db, "daily").await?;
    let weekly = fetch_latest_by_type(&state.db, "weekly").await?;
    let monthly = fetch_latest_by_type(&state.db, "monthly").await?;

    Ok(Json(LatestReportsResponse {
        daily,
        weekly,
        monthly,
    }))
}

async fn fetch_latest_by_type(
    db: &PgPool,
    report_type: &str,
) -> Result<Option<ReportEntry>, ApiError> {
    let row = sqlx::query_as::<
        _,
        (
            Uuid,
            String,
            String,
            DateTime<Utc>,
            DateTime<Utc>,
            DateTime<Utc>,
            serde_json::Value,
        ),
    >(
        "SELECT id, report_type, format, period_start, period_end, generated_at, data
         FROM report_history
         WHERE report_type = $1
         ORDER BY generated_at DESC
         LIMIT 1",
    )
    .bind(report_type)
    .fetch_optional(db)
    .await?;

    Ok(row.map(|(id, rt, fmt, ps, pe, ga, d)| ReportEntry {
        id,
        report_type: rt,
        format: fmt,
        period_start: ps.to_rfc3339(),
        period_end: pe.to_rfc3339(),
        generated_at: ga.to_rfc3339(),
        data: d,
    }))
}

async fn download_report(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, ApiError> {
    crate::middleware::auth::require_scopes(&auth, &["*"])?;

    let row = sqlx::query_as::<
        _,
        (
            Uuid,
            String,
            String,
            DateTime<Utc>,
            DateTime<Utc>,
            DateTime<Utc>,
            serde_json::Value,
            Option<String>,
        ),
    >(
        "SELECT id, report_type, format, period_start, period_end, generated_at, data, file_path
         FROM report_history
         WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| ApiError::NotFound(format!("report {} not found", id)))?;

    Ok(Json(serde_json::json!({
        "id": row.0,
        "reportType": row.1,
        "format": row.2,
        "periodStart": row.3.to_rfc3339(),
        "periodEnd": row.4.to_rfc3339(),
        "generatedAt": row.5.to_rfc3339(),
        "data": row.6,
        "filePath": row.7,
    })))
}
