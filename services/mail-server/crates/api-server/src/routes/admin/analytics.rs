//! Analytics endpoints — event stats, time series, provider breakdown.
//!
//! Metric conventions (single source of truth:
//! [`crate::analytics_metrics`]):
//!
//! * cohort time = event-OCCURRENCE timestamps (`events.timestamp`);
//! * `sent` = a successful `sent` event, never message creation;
//! * cardinality = DISTINCT message ids, so repeat opens/clicks on one
//!   message can never inflate a numerator (no clamping anywhere);
//! * rates are FRACTIONS in `0.0..=1.0`, never percentages.
//!
//! Provider identity prefers a persisted normalized provider dimension on
//! `events`; when the schema has none, only well-known consumer domains are
//! classified and every row is labelled `inferred`.

use axum::extract::{Query, State};
use axum::routing::get;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use crate::analytics_metrics::{
    distinct_message_counts, distinct_message_time_series, provider_breakdown,
};
use crate::error::ApiError;
use crate::middleware::auth::AuthUser;
use crate::state::AppState;

// Re-exported for the CSV/JSON export module (and route tests), which share
// the same column/range whitelists and column detection.
pub use crate::analytics_metrics::{
    detect_event_columns, parse_analytics_range, select_event_columns, AnalyticsRange,
    EventColumns, EventTimeColumn, EventTypeColumn,
};

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/", get(get_analytics))
        // ClickHouse-backed engagement time-series — the one real consumer
        // of the analytics crate's QueryEngine (previously zero consumers).
        .route("/clickhouse/engagement", get(get_clickhouse_engagement))
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
    /// Provenance and interpretation notes (provider inference, rate unit).
    /// The UI must surface these caveats rather than presenting inferred
    /// numbers as authoritative.
    pub notes: Vec<String>,
}

/// Aggregate engagement numbers.
///
/// Every count is a count of DISTINCT message ids and every rate is a
/// FRACTION in `0.0..=1.0` (delivered/sent etc.) over the event-occurrence
/// window. Because each numerator message also has a `sent` event, the
/// ratios are `<= 1.0` by construction — they are never clamped.
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

/// One day of distinct-message counts (event-occurrence buckets).
pub use crate::analytics_metrics::DistinctTimeSeriesPoint as TimeSeriesPoint;

/// One provider bucket. `inferred` is `true` when the provider was derived
/// from the recipient-domain suffix (no persisted provider dimension), so
/// the UI cannot present the fallback as authoritative.
pub use crate::analytics_metrics::ProviderCount as ProviderBreakdown;

/// Canonical distinct-message aggregate for the system tenant (fleet-wide).
async fn system_distinct_counts(
    state: &AppState,
    columns: EventColumns,
    range: AnalyticsRange,
) -> Result<crate::analytics_metrics::DistinctMessageCounts, ApiError> {
    distinct_message_counts(&state.db, None, range.interval_sql(), columns).await
}

async fn get_analytics(
    State(state): State<AppState>,
    auth: AuthUser,
    Query(params): Query<AnalyticsQuery>,
) -> Result<Json<AnalyticsResponse>, ApiError> {
    crate::middleware::auth::require_scopes(&auth, &["*"])?;
    crate::middleware::auth::require_system_tenant(&state, &auth).await?;

    let range = parse_analytics_range(&params.range);
    let columns = detect_event_columns(&state).await;

    // Aggregate stats — canonical distinct-message counts over
    // event-occurrence timestamps.
    let counts = system_distinct_counts(&state, columns, range).await?;

    let stats = AnalyticsStats {
        total_sent: counts.sent,
        total_delivered: counts.delivered,
        total_opened: counts.opened,
        total_clicked: counts.clicked,
        total_bounced: counts.bounced,
        total_complaints: counts.complained,
        delivery_rate: counts.delivery_rate(),
        open_rate: counts.open_rate(),
        click_rate: counts.click_rate(),
        bounce_rate: counts.bounce_rate(),
        complaint_rate: counts.complaint_rate(),
    };

    // Time series — same convention, bucketed per day.
    let time_series = distinct_message_time_series(&state.db, None, range, columns).await?;

    // Provider breakdown — persisted dimension when present, otherwise a
    // labelled consumer-domain-suffix inference.
    let breakdown = provider_breakdown(&state.db, None, range.interval_sql(), columns).await?;

    let mut notes = vec![
        "Counts are DISTINCT messages from event-occurrence timestamps; rates are fractions (0.0-1.0)."
            .to_string(),
    ];
    if let Some(note) = breakdown.note {
        notes.push(note);
    }

    Ok(Json(AnalyticsResponse {
        stats,
        time_series,
        providers: breakdown.providers,
        notes,
    }))
}

// ── ClickHouse engagement (analytics crate QueryEngine consumer) ──────────

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClickHouseEngagementQuery {
    /// Tenant whose engagement series to fetch (required — the ClickHouse
    /// engine is tenant-scoped).
    pub tenant_id: String,
    #[serde(default = "default_range")]
    pub range: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ClickHouseEngagementResponse {
    pub source: &'static str,
    pub available: bool,
    pub tenant_id: String,
    /// Engagement events per bucket (opened/clicked), ascending by time.
    pub time_series: Vec<apexmail_analytics::types::TimeSeriesPoint>,
    /// Time-to-engage histogram buckets from ClickHouse.
    pub engagement_histogram: Vec<apexmail_analytics::types::EngagementBucket>,
    /// Populated only when ClickHouse is unreachable — an honest note
    /// instead of fabricated zeros.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

/// Build the ClickHouse client configuration from the shared `CLICKHOUSE_*`
/// environment variables — the same names tracking-service reads
/// (CLICKHOUSE_URL / _DATABASE / _USER / _PASSWORD / _TLS_ENABLED), so a
/// deployment wires both services identically.
pub fn clickhouse_config_from_env() -> apexmail_analytics::config::ClickHouseConfig {
    apexmail_analytics::config::ClickHouseConfig {
        url: std::env::var("CLICKHOUSE_URL").unwrap_or_else(|_| "http://clickhouse:8123".into()),
        database: std::env::var("CLICKHOUSE_DATABASE").unwrap_or_else(|_| "apexmail".into()),
        user: std::env::var("CLICKHOUSE_USER").unwrap_or_else(|_| "default".into()),
        password: std::env::var("CLICKHOUSE_PASSWORD").unwrap_or_default(),
        tls_enabled: std::env::var("CLICKHOUSE_TLS_ENABLED")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(false),
        ..Default::default()
    }
}

fn clickhouse_window(range: &str) -> chrono::Duration {
    match range {
        "24h" => chrono::Duration::hours(24),
        "30d" => chrono::Duration::days(30),
        "90d" => chrono::Duration::days(90),
        _ => chrono::Duration::days(7),
    }
}

/// Serve a tenant's engagement time-series from ClickHouse via the analytics
/// crate's [`apexmail_analytics::QueryEngine`]. Degrades gracefully: when
/// ClickHouse is unreachable the response is `available: false` with empty
/// series and an explanatory note — the Postgres endpoints above remain the
/// source of truth.
async fn get_clickhouse_engagement(
    state: State<AppState>,
    auth: AuthUser,
    Query(params): Query<ClickHouseEngagementQuery>,
) -> Result<Json<ClickHouseEngagementResponse>, ApiError> {
    crate::middleware::auth::require_scopes(&auth, &["*"])?;
    crate::middleware::auth::require_system_tenant(&state, &auth).await?;

    if params.tenant_id.trim().is_empty() {
        return Err(ApiError::Validation(vec!["tenant_id is required".into()]));
    }

    let end = chrono::Utc::now();
    let start = end - clickhouse_window(&params.range);
    let query = apexmail_analytics::types::AnalyticsQuery {
        tenant_id: params.tenant_id.clone(),
        start_date: start,
        end_date: end,
        event_types: Some(vec!["opened".into(), "clicked".into()]),
        group_by: Some("day".into()),
        dimensions: None,
        limit: None,
    };

    let unavailable = |note: String| ClickHouseEngagementResponse {
        source: "clickhouse",
        available: false,
        tenant_id: params.tenant_id.clone(),
        time_series: Vec::new(),
        engagement_histogram: Vec::new(),
        note: Some(note),
    };

    let engine = match apexmail_analytics::ClickHouseEngine::new(clickhouse_config_from_env()).await
    {
        Ok(engine) => engine,
        Err(error) => {
            tracing::warn!(error = %error, "ClickHouse engine unavailable for engagement route");
            return Ok(Json(unavailable(
                "ClickHouse is unreachable — engagement series omitted (Postgres analytics remain available)".into(),
            )));
        }
    };

    if !engine.health_check().await.unwrap_or(false) {
        return Ok(Json(unavailable(
            "ClickHouse health check failed — engagement series omitted (Postgres analytics remain available)".into(),
        )));
    }

    let query_engine = apexmail_analytics::QueryEngine::new(engine);

    let time_series = match query_engine.get_time_series(&query).await {
        Ok(points) => points,
        Err(error) => {
            tracing::warn!(error = %error, "ClickHouse time-series query failed");
            return Ok(Json(unavailable(format!(
                "ClickHouse query failed: {error}"
            ))));
        }
    };

    let engagement_histogram = query_engine
        .get_engagement_histogram(&query)
        .await
        .unwrap_or_default();

    Ok(Json(ClickHouseEngagementResponse {
        source: "clickhouse",
        available: true,
        tenant_id: params.tenant_id,
        time_series,
        engagement_histogram,
        note: None,
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

    #[test]
    fn clickhouse_config_from_env_shares_tracking_service_variable_names() {
        // Same CLICKHOUSE_* variables tracking-service reads, with the same
        // defaults — a deployment wires both services identically.
        std::env::remove_var("CLICKHOUSE_URL");
        std::env::remove_var("CLICKHOUSE_DATABASE");
        std::env::remove_var("CLICKHOUSE_USER");
        let config = clickhouse_config_from_env();
        assert_eq!(config.url, "http://clickhouse:8123");
        assert_eq!(config.database, "apexmail");
        assert_eq!(config.user, "default");
        assert!(!config.tls_enabled);
    }

    #[test]
    fn clickhouse_window_maps_ranges() {
        assert_eq!(clickhouse_window("24h"), chrono::Duration::hours(24));
        assert_eq!(clickhouse_window("30d"), chrono::Duration::days(30));
        assert_eq!(clickhouse_window("90d"), chrono::Duration::days(90));
        // Unknown ranges fall back to the 7-day window.
        assert_eq!(clickhouse_window("bogus"), chrono::Duration::days(7));
    }

    /// Fix 1 + Fix 3: the response rates are FRACTIONS over DISTINCT
    /// messages, and multi-open on one message cannot push engagement above
    /// 100% — no clamping anywhere.
    #[test]
    fn stats_rates_are_fractions_over_distinct_messages() {
        let counts = crate::analytics_metrics::DistinctMessageCounts {
            sent: 10,
            delivered: 9,
            opened: 7,
            clicked: 2,
            bounced: 1,
            complained: 0,
        };
        let stats = AnalyticsStats {
            total_sent: counts.sent,
            total_delivered: counts.delivered,
            total_opened: counts.opened,
            total_clicked: counts.clicked,
            total_bounced: counts.bounced,
            total_complaints: counts.complained,
            delivery_rate: counts.delivery_rate(),
            open_rate: counts.open_rate(),
            click_rate: counts.click_rate(),
            bounce_rate: counts.bounce_rate(),
            complaint_rate: counts.complaint_rate(),
        };

        assert!((stats.delivery_rate - 0.9).abs() < 1e-9);
        assert!((stats.open_rate - 0.7).abs() < 1e-9);
        assert!((stats.bounce_rate - 0.1).abs() < 1e-9);
        for rate in [
            stats.delivery_rate,
            stats.open_rate,
            stats.click_rate,
            stats.bounce_rate,
            stats.complaint_rate,
        ] {
            assert!((0.0..=1.0).contains(&rate), "rate out of range: {rate}");
        }
    }
}
