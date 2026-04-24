//! Analytics endpoints — event stats, time series, provider breakdown.
//!

use axum::extract::{Query, State};
use axum::routing::get;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use crate::error::ApiError;
use crate::middleware::auth::AuthUser;
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new().route("/", get(get_analytics))
}

#[derive(Debug, Deserialize)]
pub struct AnalyticsQuery {
    #[serde(default = "default_range")]
    pub range: String,
}

fn default_range() -> String {
    "7d".into()
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AnalyticsResponse {
    pub stats: AnalyticsStats,
    pub time_series: Vec<TimeSeriesPoint>,
    pub providers: Vec<ProviderBreakdown>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AnalyticsStats {
    pub total_sent: i64,
    pub total_delivered: i64,
    pub total_opened: i64,
    pub total_clicked: i64,
    pub total_bounced: i64,
    pub total_complaints: i64,
    pub delivery_rate: f64,
    pub open_rate: f64,
    pub click_rate: f64,
    pub bounce_rate: f64,
    pub complaint_rate: f64,
}

#[derive(Debug, Serialize)]
pub struct TimeSeriesPoint {
    pub date: String,
    pub sent: i64,
    pub delivered: i64,
    pub opened: i64,
    pub clicked: i64,
}

#[derive(Debug, Serialize)]
pub struct ProviderBreakdown {
    pub provider: String,
    pub count: i64,
}

fn range_to_interval(range: &str) -> &str {
    match range {
        "24h" => "24 hours",
        "7d" => "7 days",
        "30d" => "30 days",
        "90d" => "90 days",
        "12m" => "365 days",
        _ => "7 days",
    }
}

async fn get_analytics(
    State(state): State<AppState>,
    auth: AuthUser,
    Query(params): Query<AnalyticsQuery>,
) -> Result<Json<AnalyticsResponse>, ApiError> {
    crate::middleware::auth::require_scopes(&auth, &["*"])?;

    let interval = range_to_interval(&params.range);

// Detect column names (event_type vs type, created_at vs timestamp)
    let type_col = detect_column(&state, "events", &["event_type", "type"])
        .await
        .unwrap_or_else(|| "event_type".into());
    let time_col = detect_column(&state, "events", &["created_at", "timestamp"])
        .await
        .unwrap_or_else(|| "created_at".into());

// Aggregate stats
    let stats_sql = format!(
        "SELECT
            COALESCE(SUM(CASE WHEN {type_col} = 'sent' THEN 1 ELSE 0 END), 0) as sent,
            COALESCE(SUM(CASE WHEN {type_col} = 'delivered' THEN 1 ELSE 0 END), 0) as delivered,
            COALESCE(SUM(CASE WHEN {type_col} = 'opened' THEN 1 ELSE 0 END), 0) as opened,
            COALESCE(SUM(CASE WHEN {type_col} = 'clicked' THEN 1 ELSE 0 END), 0) as clicked,
            COALESCE(SUM(CASE WHEN {type_col} = 'bounced' THEN 1 ELSE 0 END), 0) as bounced,
            COALESCE(SUM(CASE WHEN {type_col} = 'complained' THEN 1 ELSE 0 END), 0) as complaints
         FROM events WHERE {time_col} >= NOW() - '{interval}'::interval"
    );

    let row = sqlx::query_as::<_, (i64, i64, i64, i64, i64, i64)>(&stats_sql)
        .fetch_optional(&state.db)
        .await
        .unwrap_or(None)
        .unwrap_or((0, 0, 0, 0, 0, 0));

    let (sent, delivered, opened, clicked, bounced, complaints) = row;
    let safe_sent = if sent > 0 { sent as f64 } else { 1.0 };

    let stats = AnalyticsStats {
        total_sent: sent,
        total_delivered: delivered,
        total_opened: opened,
        total_clicked: clicked,
        total_bounced: bounced,
        total_complaints: complaints,
        delivery_rate: (delivered as f64 / safe_sent * 100.0).min(100.0),
        open_rate: (opened as f64 / safe_sent * 100.0).min(100.0),
        click_rate: (clicked as f64 / safe_sent * 100.0).min(100.0),
        bounce_rate: (bounced as f64 / safe_sent * 100.0).min(100.0),
        complaint_rate: (complaints as f64 / safe_sent * 100.0).min(100.0),
    };

// Time series
    let ts_sql = format!(
        "SELECT DATE({time_col})::text as d,
            COALESCE(SUM(CASE WHEN {type_col} = 'sent' THEN 1 ELSE 0 END), 0),
            COALESCE(SUM(CASE WHEN {type_col} = 'delivered' THEN 1 ELSE 0 END), 0),
            COALESCE(SUM(CASE WHEN {type_col} = 'opened' THEN 1 ELSE 0 END), 0),
            COALESCE(SUM(CASE WHEN {type_col} = 'clicked' THEN 1 ELSE 0 END), 0)
         FROM events WHERE {time_col} >= NOW() - '{interval}'::interval
         GROUP BY d ORDER BY d ASC"
    );

    let ts_rows = sqlx::query_as::<_, (String, i64, i64, i64, i64)>(&ts_sql)
        .fetch_all(&state.db)
        .await?;

    let time_series: Vec<TimeSeriesPoint> = ts_rows
        .into_iter()
        .map(|(date, s, d, o, c)| TimeSeriesPoint { date, sent: s, delivered: d, opened: o, clicked: c })
        .collect();

// Provider breakdown by recipient domain
    let prov_sql = format!(
        "SELECT
            CASE
              WHEN recipient LIKE '%@gmail.com' THEN 'Gmail'
              WHEN recipient LIKE '%@yahoo.%' THEN 'Yahoo'
              WHEN recipient LIKE '%@outlook.%' OR recipient LIKE '%@hotmail.%' THEN 'Microsoft'
              WHEN recipient LIKE '%@icloud.com' OR recipient LIKE '%@me.com' THEN 'iCloud'
              ELSE 'Other'
            END as provider,
            COUNT(*) as cnt
         FROM events WHERE {time_col} >= NOW() - '{interval}'::interval AND {type_col} = 'sent'
         GROUP BY provider ORDER BY cnt DESC"
    );

    let prov_rows = sqlx::query_as::<_, (String, i64)>(&prov_sql)
        .fetch_all(&state.db)
        .await?;

    let providers: Vec<ProviderBreakdown> = prov_rows
        .into_iter()
        .map(|(provider, count)| ProviderBreakdown { provider, count })
        .collect();

    Ok(Json(AnalyticsResponse { stats, time_series, providers }))
}

/// Detect which column name exists in a table.
pub async fn detect_column(state: &AppState, table: &str, candidates: &[&str]) -> Option<String> {
    for col in candidates {
        let exists: Option<(bool,)> = sqlx::query_as(
            "SELECT EXISTS(SELECT 1 FROM information_schema.columns WHERE table_name = $1 AND column_name = $2)",
        )
        .bind(table)
        .bind(*col)
        .fetch_optional(&state.db)
        .await
        .ok()
        .flatten();
        if exists.map(|r| r.0).unwrap_or(false) {
            return Some((*col).to_string());
        }
    }
    None
}
