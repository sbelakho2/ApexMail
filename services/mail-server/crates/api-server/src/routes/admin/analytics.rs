//! Analytics endpoints — event stats, time series, provider breakdown.
//!
//! Metric conventions (single source of truth:
//! [`crate::analytics_metrics`]):
//!
//! * the unit is a recipient-send cohort row `(message_id, lower(recipient))`
//!   whose `sent` event falls in the window; outcomes attach to that send;
//! * `sent` = a successful `sent` event, never message creation;
//! * outcomes use `BOOL_OR` per cohort, so repeat opens/clicks on one
//!   recipient-send can never inflate a numerator (no clamping anywhere);
//! * rates are FRACTIONS in `0.0..=1.0`, or `null`/absent when the send
//!   cohort is empty — never `0`, never percentages.
//!
//! Provider identity prefers a persisted normalized provider dimension on
//! `events` (migration 202); rows without one fall back to well-known
//! consumer domains only and are labelled `inferred`.

use axum::extract::{Query, State};
use axum::routing::get;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use crate::analytics_metrics::{provider_breakdown, send_cohort_counts, send_cohort_time_series};
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
/// Every count is a send-cohort row count `(message_id, lower(recipient))`
/// and every rate is a FRACTION in `0.0..=1.0` (delivered/sent etc.) over
/// the send-cohort window. Because each numerator cohort also has a `sent`
/// event, the ratios are `<= 1.0` by construction — they are never clamped.
///
/// A rate is `null` when the window has no send cohort at all: absent, never
/// a fabricated zero.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AnalyticsStats {
    pub total_sent: i64,
    pub total_delivered: i64,
    pub total_opened: i64,
    pub total_clicked: i64,
    pub total_bounced: i64,
    pub total_complaints: i64,
    pub delivery_rate: Option<f64>,
    pub open_rate: Option<f64>,
    pub click_rate: Option<f64>,
    pub bounce_rate: Option<f64>,
    pub complaint_rate: Option<f64>,
}

/// One `sent_at` day of send-cohort counts (outcomes attached to the cohort).
pub use crate::analytics_metrics::SendCohortTimeSeriesPoint as TimeSeriesPoint;

/// One provider bucket. `inferred` is `true` when the provider was derived
/// from the recipient-domain suffix (no persisted provider dimension), so
/// the UI cannot present the fallback as authoritative.
pub use crate::analytics_metrics::ProviderCount as ProviderBreakdown;

/// Canonical send-cohort aggregate for the system tenant (fleet-wide).
async fn system_send_cohort(
    state: &AppState,
    columns: EventColumns,
    range: AnalyticsRange,
) -> Result<crate::analytics_metrics::SendCohortCounts, ApiError> {
    send_cohort_counts(&state.db, None, range.interval_sql(), columns).await
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

    // Aggregate stats — canonical send-cohort counts over send time.
    let counts = system_send_cohort(&state, columns, range).await?;

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

    // Time series — same convention, bucketed per send day.
    let time_series = send_cohort_time_series(&state.db, None, range, columns).await?;

    // Provider breakdown — persisted dimension when present, otherwise a
    // labelled consumer-domain-suffix inference.
    let breakdown = provider_breakdown(&state.db, None, range.interval_sql(), columns).await?;

    let mut notes = vec![
        "Counts are send-cohort rows (message_id + lowercased recipient) whose send event falls in the window; outcomes attach to that send and rates are fractions (0.0-1.0), or null when the window has no sends."
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

    /// The response rates are FRACTIONS over send-cohort rows, and
    /// multi-open on one recipient-send cannot push engagement above 100% —
    /// no clamping anywhere. The zero-cohort case is `None`, never 0.
    #[test]
    fn stats_rates_are_fractions_over_the_send_cohort() {
        let counts = crate::analytics_metrics::SendCohortCounts {
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

        assert_eq!(stats.delivery_rate, Some(0.9));
        assert_eq!(stats.open_rate, Some(0.7));
        assert_eq!(stats.bounce_rate, Some(0.1));
        for rate in [
            stats.delivery_rate,
            stats.open_rate,
            stats.click_rate,
            stats.bounce_rate,
            stats.complaint_rate,
        ] {
            let rate = rate.expect("sent > 0");
            assert!((0.0..=1.0).contains(&rate), "rate out of range: {rate}");
        }

        // Empty cohort: every rate absent (null), never a fabricated 0.
        let empty = crate::analytics_metrics::SendCohortCounts::default();
        assert_eq!(empty.delivery_rate(), None);
        assert_eq!(empty.open_rate(), None);
    }
}

#[cfg(test)]
mod adversarial_tests {
    use axum::http::StatusCode;

    use crate::app::test_support::adv::AdvEnv;

    async fn seed_cohort_event(
        pool: &sqlx::PgPool,
        tenant: &str,
        message_id: &str,
        recipient: &str,
        event_type: &str,
    ) {
        sqlx::query(
            "INSERT INTO events (id, tenant_id, message_id, event_type, recipient, timestamp)
             VALUES ($1, $2, $3, $4, $5, NOW())",
        )
        .bind(format!(
            "evt_{}",
            &uuid::Uuid::new_v4().simple().to_string()[..20]
        ))
        .bind(tenant)
        .bind(message_id)
        .bind(event_type)
        .bind(recipient)
        .execute(pool)
        .await
        .expect("seed cohort event");
    }

    /// Cross-process env mutations for CLICKHOUSE_* are rare and read-only in
    /// this module's other tests; guard set/restore under one mutex.
    static CLICKHOUSE_ENV_MUTEX: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[tokio::test]
    async fn analytics_aggregates_send_cohorts_with_fractional_rates() {
        let Some(pool) = crate::test_db::canonical_pool("adv_analytics").await else {
            return;
        };
        let env = AdvEnv::admin(pool.clone()).await;
        // One send cohort of 4, one of 1: 5 sends total.
        for i in 0..4 {
            seed_cohort_event(
                &pool,
                "system_internal_tenant01",
                "msg-a",
                &format!("u{i}@example.com"),
                "sent",
            )
            .await;
            seed_cohort_event(
                &pool,
                "system_internal_tenant01",
                "msg-a",
                &format!("u{i}@example.com"),
                "delivered",
            )
            .await;
        }
        seed_cohort_event(
            &pool,
            "system_internal_tenant01",
            "msg-b",
            "vip@example.com",
            "sent",
        )
        .await;
        seed_cohort_event(
            &pool,
            "system_internal_tenant01",
            "msg-b",
            "vip@example.com",
            "opened",
        )
        .await;
        seed_cohort_event(
            &pool,
            "system_internal_tenant01",
            "msg-b",
            "vip@example.com",
            "clicked",
        )
        .await;

        let (status, body) = env.get("/v1/admin/analytics").await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let stats = &body["stats"];
        assert_eq!(stats["totalSent"], 5);
        assert_eq!(stats["totalDelivered"], 4);
        assert_eq!(stats["totalOpened"], 1);
        assert_eq!(stats["totalClicked"], 1);
        assert_eq!(stats["deliveryRate"], 0.8);
        assert_eq!(stats["openRate"], 0.2);
        assert_eq!(stats["clickRate"], 0.2);
        assert_eq!(stats["bounceRate"], 0.0);
        // Provenance notes always present.
        let notes = body["notes"].as_array().expect("notes");
        assert!(!notes.is_empty());
        assert!(body["timeSeries"].is_array());
        assert!(body["providers"].is_array());
    }

    #[tokio::test]
    async fn analytics_empty_window_reports_null_rates_never_zero() {
        let Some(pool) = crate::test_db::canonical_pool("adv_analytics_empty").await else {
            return;
        };
        let env = AdvEnv::admin(pool).await;
        let (status, body) = env.get("/v1/admin/analytics?range=24h").await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["stats"]["totalSent"], 0);
        assert_eq!(body["stats"]["deliveryRate"], serde_json::Value::Null);
        assert_eq!(body["stats"]["openRate"], serde_json::Value::Null);
    }

    #[tokio::test]
    async fn analytics_gates() {
        let Some(pool) = crate::test_db::canonical_pool("adv_analytics_gates").await else {
            return;
        };
        let key =
            crate::app::test_support::seed_api_key_for(&pool, "system", &["analytics:read"]).await;
        let scoped = AdvEnv::over(pool.clone(), key).await;
        let (status, body) = scoped.get("/v1/admin/analytics").await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{body}");

        let (customer, _tenant) = AdvEnv::tenant(pool.clone(), &["*"]).await;
        let (status, body) = customer.get("/v1/admin/analytics").await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{body}");

        // Unknown query field.
        let env = AdvEnv::admin(pool).await;
        let (status, _body) = env.get("/v1/admin/analytics?range=7d&span=year").await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn clickhouse_engagement_validates_tenant_and_degrades_honestly() {
        let Some(pool) = crate::test_db::canonical_pool("adv_ch_engagement").await else {
            return;
        };
        let env = AdvEnv::admin(pool.clone()).await;

        // Blank tenant id is a validation error.
        let (status, body) = env
            .get("/v1/admin/analytics/clickhouse/engagement?tenant_id=%20%20")
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");

        // With ClickHouse unreachable (dead local port pinned deterministically),
        // the endpoint answers 200 with available:false and an honest note.
        // Set/restore the env synchronously under the lock; the request runs
        // with the guard released (std guards must not cross await points).
        let previous = {
            let _guard = CLICKHOUSE_ENV_MUTEX
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            let previous = std::env::var("CLICKHOUSE_URL").ok();
            std::env::set_var("CLICKHOUSE_URL", "http://127.0.0.1:1");
            previous
        };
        let (status, body) = env
            .get("/v1/admin/analytics/clickhouse/engagement?tenant_id=tenant_probe&range=24h")
            .await;
        {
            let _guard = CLICKHOUSE_ENV_MUTEX
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            match previous {
                Some(value) => std::env::set_var("CLICKHOUSE_URL", value),
                None => std::env::remove_var("CLICKHOUSE_URL"),
            }
        }
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["available"], false);
        assert_eq!(body["source"], "clickhouse");
        assert!(body["note"].as_str().is_some_and(|n| !n.is_empty()));
        assert_eq!(body["timeSeries"].as_array().map(Vec::len), Some(0));

        // Missing tenant_id outright is a 400 (deny_unknown_fields aside, the
        // field is required).
        let (status, _body) = env.get("/v1/admin/analytics/clickhouse/engagement").await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }
}
