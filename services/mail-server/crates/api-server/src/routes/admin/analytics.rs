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
    Router::new()
        .route("/", get(get_analytics))
        // Analytics-family routers are composed here rather than as separate
        // nests in app.rs, so they are all reachable through the single
        // `/v1/admin/analytics` nest while inheriting the same system-tenant
        // middleware stack.
        .nest("/delivery", super::delivery_analytics::router())
        .nest("/growth", super::growth_analytics::router())
        .nest("/insights", super::insights::router())
        .nest("/predictive", super::predictive_analytics::router())
        .nest("/cross-tenant", super::cross_tenant::router())
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventTypeColumn {
    EventType,
    LegacyType,
}

impl EventTypeColumn {
    pub(crate) fn as_sql(self) -> &'static str {
        match self {
            Self::EventType => "event_type",
            Self::LegacyType => "type",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventTimeColumn {
    CreatedAt,
    Timestamp,
}

impl EventTimeColumn {
    pub(crate) fn as_sql(self) -> &'static str {
        match self {
            Self::CreatedAt => "created_at",
            Self::Timestamp => "timestamp",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EventColumns {
    pub type_col: EventTypeColumn,
    pub time_col: EventTimeColumn,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnalyticsRange {
    Hours24,
    Days7,
    Days30,
    Days90,
    Months12,
}

impl AnalyticsRange {
    pub(crate) fn interval_sql(self) -> &'static str {
        match self {
            Self::Hours24 => "24 hours",
            Self::Days7 => "7 days",
            Self::Days30 => "30 days",
            Self::Days90 => "90 days",
            Self::Months12 => "365 days",
        }
    }
}

pub fn parse_analytics_range(range: &str) -> AnalyticsRange {
    match range {
        "24h" => AnalyticsRange::Hours24,
        "7d" => AnalyticsRange::Days7,
        "30d" => AnalyticsRange::Days30,
        "90d" => AnalyticsRange::Days90,
        "12m" => AnalyticsRange::Months12,
        _ => AnalyticsRange::Days7,
    }
}

pub fn select_event_columns(type_col: Option<&str>, time_col: Option<&str>) -> EventColumns {
    EventColumns {
        type_col: match type_col {
            Some("type") => EventTypeColumn::LegacyType,
            _ => EventTypeColumn::EventType,
        },
        time_col: match time_col {
            Some("timestamp") => EventTimeColumn::Timestamp,
            _ => EventTimeColumn::CreatedAt,
        },
    }
}

fn build_stats_query(columns: EventColumns, range: AnalyticsRange) -> String {
    let type_col = columns.type_col.as_sql();
    let time_col = columns.time_col.as_sql();
    let interval = range.interval_sql();

    format!(
        "SELECT
            COALESCE(SUM(CASE WHEN {type_col} = 'sent' THEN 1 ELSE 0 END), 0) as sent,
            COALESCE(SUM(CASE WHEN {type_col} = 'delivered' THEN 1 ELSE 0 END), 0) as delivered,
            COALESCE(SUM(CASE WHEN {type_col} = 'opened' THEN 1 ELSE 0 END), 0) as opened,
            COALESCE(SUM(CASE WHEN {type_col} = 'clicked' THEN 1 ELSE 0 END), 0) as clicked,
            COALESCE(SUM(CASE WHEN {type_col} = 'bounced' THEN 1 ELSE 0 END), 0) as bounced,
            COALESCE(SUM(CASE WHEN {type_col} = 'complained' THEN 1 ELSE 0 END), 0) as complaints
         FROM events WHERE {time_col} >= NOW() - '{interval}'::interval"
    )
}

fn build_time_series_query(columns: EventColumns, range: AnalyticsRange) -> String {
    let type_col = columns.type_col.as_sql();
    let time_col = columns.time_col.as_sql();
    let interval = range.interval_sql();

    format!(
        "SELECT DATE({time_col})::text as d,
            COALESCE(SUM(CASE WHEN {type_col} = 'sent' THEN 1 ELSE 0 END), 0),
            COALESCE(SUM(CASE WHEN {type_col} = 'delivered' THEN 1 ELSE 0 END), 0),
            COALESCE(SUM(CASE WHEN {type_col} = 'opened' THEN 1 ELSE 0 END), 0),
            COALESCE(SUM(CASE WHEN {type_col} = 'clicked' THEN 1 ELSE 0 END), 0)
         FROM events WHERE {time_col} >= NOW() - '{interval}'::interval
         GROUP BY d ORDER BY d ASC"
    )
}

fn build_provider_breakdown_query(columns: EventColumns, range: AnalyticsRange) -> String {
    let type_col = columns.type_col.as_sql();
    let time_col = columns.time_col.as_sql();
    let interval = range.interval_sql();

    format!(
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
    )
}

async fn detect_column(state: &AppState, table: &str, candidates: &[&str]) -> Option<String> {
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

pub async fn detect_event_columns(state: &AppState) -> EventColumns {
    let type_col = detect_column(state, "events", &["event_type", "type"]).await;
    let time_col = detect_column(state, "events", &["created_at", "timestamp"]).await;

    select_event_columns(type_col.as_deref(), time_col.as_deref())
}

async fn get_analytics(
    State(state): State<AppState>,
    auth: AuthUser,
    Query(params): Query<AnalyticsQuery>,
) -> Result<Json<AnalyticsResponse>, ApiError> {
    crate::middleware::auth::require_scopes(&auth, &["*"])?;
    crate::middleware::auth::require_system_tenant(&auth)?;

    let range = parse_analytics_range(&params.range);
    let columns = detect_event_columns(&state).await;

    // Aggregate stats
    let stats_sql = build_stats_query(columns, range);

    let row = sqlx::query_as::<_, (i64, i64, i64, i64, i64, i64)>(&stats_sql)
        .fetch_optional(&state.db)
        .await?
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
    let ts_sql = build_time_series_query(columns, range);

    let ts_rows = sqlx::query_as::<_, (String, i64, i64, i64, i64)>(&ts_sql)
        .fetch_all(&state.db)
        .await?;

    let time_series: Vec<TimeSeriesPoint> = ts_rows
        .into_iter()
        .map(|(date, s, d, o, c)| TimeSeriesPoint {
            date,
            sent: s,
            delivered: d,
            opened: o,
            clicked: c,
        })
        .collect();

    // Provider breakdown by recipient domain
    let prov_sql = build_provider_breakdown_query(columns, range);

    let prov_rows = sqlx::query_as::<_, (String, i64)>(&prov_sql)
        .fetch_all(&state.db)
        .await?;

    let providers: Vec<ProviderBreakdown> = prov_rows
        .into_iter()
        .map(|(provider, count)| ProviderBreakdown { provider, count })
        .collect();

    Ok(Json(AnalyticsResponse {
        stats,
        time_series,
        providers,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn select_event_columns_only_returns_whitelisted_variants() {
        let columns = select_event_columns(Some("unexpected"), Some("timestamp"));

        assert_eq!(columns.type_col, EventTypeColumn::EventType);
        assert_eq!(columns.time_col, EventTimeColumn::Timestamp);
    }

    #[test]
    fn parse_analytics_range_defaults_to_seven_days() {
        assert_eq!(parse_analytics_range("bogus"), AnalyticsRange::Days7);
    }
}
