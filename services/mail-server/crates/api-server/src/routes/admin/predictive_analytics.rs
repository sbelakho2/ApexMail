//! Predictive analytics endpoint — churn-risk scoring, capacity planning,
//! volume trend extrapolation, and anomaly detection.
//!
//! **These outputs are HEURISTICS, not calibrated predictions.** There is no
//! trained model and no statistical confidence: the churn dashboard is a
//! threshold score over current activity, the volume figures are linear
//! extrapolations of observed successful sends, and anomalies are threshold
//! comparisons. Output fields are labelled `heuristic*` accordingly.
//!
//! Volume metrics count DISTINCT messages with a successful `sent` event
//! (event-occurrence timestamps) — never `messages.created_at`, which counts
//! mail that may never have left the queue.

use axum::extract::{Query, State};
use axum::routing::get;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use crate::error::ApiError;
use crate::middleware::auth::AuthUser;
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/", get(get_predictive_analytics))
        .route("/churn", get(get_churn_risk))
        .route("/capacity", get(get_capacity_planning))
        .route("/anomalies", get(get_anomalies))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PredictiveQuery {
    #[serde(default = "default_window")]
    pub window: String,
}

fn default_window() -> String {
    "90d".into()
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PredictiveAnalyticsResponse {
    pub churn_risk: ChurnRiskDashboard,
    pub capacity: CapacityPlanning,
    pub anomalies: Vec<Anomaly>,
    pub forecast: VolumeForecast,
    /// How to read every number in this response (heuristic provenance).
    pub method: String,
    pub generated_at: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ChurnRiskDashboard {
    pub at_risk_tenants: i64,
    pub high_risk_count: i64,
    pub medium_risk_count: i64,
    /// High-risk tenants / active tenants. A heuristic SNAPSHOT SHARE, not a
    /// calibrated probability of churn.
    pub heuristic_churn_risk_share: f64,
    pub top_risk_signals: Vec<RiskSignal>,
    pub at_risk_tenants_list: Vec<AtRiskTenant>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RiskSignal {
    pub signal: String,
    pub affected_tenants: i64,
    pub severity: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AtRiskTenant {
    pub tenant_id: String,
    pub days_inactive: i64,
    pub email_volume_decline_pct: f64,
    pub bounce_rate_30d: f64,
    pub risk_level: String,
    pub has_active_subscription: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CapacityPlanning {
    /// DISTINCT messages with a successful `sent` event today.
    pub current_daily_volume: i64,
    /// DISTINCT messages with a successful `sent` event in the last 30 days.
    pub current_monthly_volume: i64,
    pub volume_trend_30d: Vec<TrendPoint>,
    pub volume_trend_90d: Vec<TrendPoint>,
    /// Heuristic linear extrapolation of observed daily send volume; not a
    /// calibrated forecast.
    pub heuristic_projected_30d_volume: i64,
    pub heuristic_projected_90d_volume: i64,
    /// Observed week-over-week growth of successful sends (fraction).
    pub weekly_growth_rate: f64,
    /// Current backlog / configured capacity (fraction; > 1.0 means over).
    pub capacity_utilization: f64,
    /// `Some(0)` when the backlog already exceeds the configured capacity;
    /// `None` otherwise because backlog-growth history is not retained (no
    /// date can be projected honestly).
    pub days_until_capacity_limit: Option<i64>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TrendPoint {
    pub date: String,
    pub volume: i64,
    pub projected: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VolumeForecast {
    /// DISTINCT successfully-sent messages in the last 30 days.
    pub current_volume: i64,
    /// Heuristic linear extrapolations of observed daily send volume.
    pub heuristic_next_week: i64,
    pub heuristic_next_month: i64,
    pub heuristic_next_quarter: i64,
    /// Observed variability band (coefficient of variation of historical
    /// daily send volumes) — NOT a statistical confidence interval.
    pub variability_band: String,
    /// Static provenance string: these are heuristics, not a model.
    pub method: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Anomaly {
    pub anomaly_type: String,
    pub description: String,
    pub severity: String,
    pub detected_value: String,
    pub expected_range: String,
    pub detected_at: String,
    /// How the anomaly was detected — always a heuristic threshold
    /// comparison, never a trained model's output.
    pub method: String,
}

#[derive(sqlx::FromRow)]
struct InactiveTenantRow {
    tenant_id: String,
    days_inactive: Option<i64>,
    has_subscription: Option<bool>,
    bounce_rate: Option<f64>,
    recent_count: Option<i64>,
    prev_count: Option<i64>,
}

#[derive(sqlx::FromRow)]
struct VolumeRow {
    date: String,
    volume: i64,
}

fn parse_window_days(window: &str) -> i64 {
    match window {
        "30d" => 30,
        "60d" => 60,
        "90d" => 90,
        "180d" => 180,
        "365d" | "1y" => 365,
        _ => 90,
    }
}

/// Default sending-pipeline queue capacity: the backlog depth at which the
/// worker's email processor starts load-shedding (BackpressureConfig
/// default `max_backlog` in worker-processors). Overridable so deployments
/// that tune the worker can keep analytics in sync.
const DEFAULT_EMAIL_MAX_BACKLOG: i64 = 10_000;

/// Configured queue capacity (max backlog) from the environment. This is
/// the same capacity knob the worker's backpressure uses, read here so the
/// control plane reports utilization against real provisioning.
fn configured_queue_capacity() -> i64 {
    std::env::var("EMAIL_MAX_BACKLOG")
        .ok()
        .and_then(|v| v.trim().parse::<i64>().ok())
        .filter(|v| *v > 0)
        .unwrap_or(DEFAULT_EMAIL_MAX_BACKLOG)
}

/// Heuristic method label returned with forecasts and anomalies.
const HEURISTIC_METHOD: &str =
    "heuristic threshold/extrapolation over observed successful-send events; no trained model";

/// Queue utilization as a FRACTION of the configured capacity (0..1; values
/// above 1.0 mean the backlog exceeds the load-shedding threshold). The rate
/// unit is consistent with every other admin analytics endpoint.
fn compute_capacity_utilization(queue_depth: i64, capacity: i64) -> f64 {
    if capacity <= 0 {
        return 0.0;
    }
    queue_depth as f64 / capacity as f64
}

/// Days until the queue reaches its configured capacity. Some(0) when the
/// backlog already exceeds capacity; None otherwise because we do not track
/// backlog-growth history to project a date from (previously a hardcoded
/// None placeholder — still honest, now for a documented reason).
fn days_until_capacity_limit(queue_depth: i64, capacity: i64) -> Option<i64> {
    if capacity > 0 && queue_depth >= capacity {
        Some(0)
    } else {
        None
    }
}

/// Observed variability of daily send volumes: the coefficient of variation
/// (stdev / mean) over the trend window. With fewer than two daily data
/// points there is nothing to estimate variability from, so the band is
/// reported as unestimated — never a fabricated "±15%" and never labelled a
/// statistical confidence interval.
fn volume_variability_band(daily_volumes: &[i64]) -> String {
    if daily_volumes.len() < 2 {
        return "unestimated (insufficient daily-volume history)".into();
    }
    let n = daily_volumes.len() as f64;
    let mean = daily_volumes.iter().map(|&v| v as f64).sum::<f64>() / n;
    if mean <= f64::EPSILON {
        return "unestimated (no send volume)".into();
    }
    let variance = daily_volumes
        .iter()
        .map(|&v| {
            let d = v as f64 - mean;
            d * d
        })
        .sum::<f64>()
        / n;
    let cv = variance.sqrt() / mean;
    format!(
        "±{:.0}% (observed 30-day daily-volume variability; not a confidence interval)",
        (cv * 100.0).round()
    )
}

fn classify_risk(days: i64, has_sub: bool, bounce_rate: f64) -> String {
    if days > 60 && has_sub {
        "critical".into()
    } else if days > 30 && (has_sub || bounce_rate > 0.10) {
        "high".into()
    } else if days > 14 {
        "medium".into()
    } else {
        "low".into()
    }
}

// ── Successful-send volume helpers (event occurrence, DISTINCT messages) ──

/// DISTINCT messages with a successful `sent` event today.
async fn current_daily_sends(db: &sqlx::PgPool) -> i64 {
    sqlx::query_scalar(
        "SELECT COUNT(DISTINCT message_id)::bigint FROM events
         WHERE event_type = 'sent' AND timestamp >= CURRENT_DATE",
    )
    .fetch_one(db)
    .await
    .unwrap_or(0)
}

/// DISTINCT messages with a successful `sent` event in the last `days` days.
async fn recent_sends(db: &sqlx::PgPool, days: i32) -> i64 {
    sqlx::query_scalar(
        "SELECT COUNT(DISTINCT message_id)::bigint FROM events
         WHERE event_type = 'sent' AND timestamp >= NOW() - make_interval(days => $1::int)",
    )
    .bind(days)
    .fetch_one(db)
    .await
    .unwrap_or(0)
}

/// DISTINCT successful sends per day over the last `days` days.
async fn send_trend(db: &sqlx::PgPool, days: i32) -> Vec<TrendPoint> {
    sqlx::query_as::<_, VolumeRow>(
        "SELECT DATE(timestamp)::text as date, COUNT(DISTINCT message_id)::bigint as volume
         FROM events
         WHERE event_type = 'sent' AND timestamp >= NOW() - make_interval(days => $1::int)
         GROUP BY DATE(timestamp) ORDER BY 1",
    )
    .bind(days)
    .fetch_all(db)
    .await
    .unwrap_or_default()
    .into_iter()
    .map(|r| TrendPoint {
        date: r.date,
        volume: r.volume,
        projected: false,
    })
    .collect()
}

/// Distinct-message bounce rate (fraction) over a window of `window_hours`
/// ending `exclude_last_hours` before now. Bounce = distinct messages with a
/// bounced event / distinct messages with a sent event, both by event
/// occurrence — the same cardinality and time conventions as
/// [`crate::analytics_metrics`], so the two windows compared are
/// like-for-like.
async fn event_bounce_rate(db: &sqlx::PgPool, window_hours: i32, exclude_last_hours: i32) -> f64 {
    sqlx::query_scalar::<_, Option<f64>>(
        "SELECT
            CASE
                WHEN COUNT(DISTINCT message_id) FILTER (WHERE event_type = 'sent') > 0
                THEN COUNT(DISTINCT message_id) FILTER (WHERE event_type = 'bounced')::float8
                     / COUNT(DISTINCT message_id) FILTER (WHERE event_type = 'sent')
                ELSE 0
            END
         FROM events
         WHERE timestamp >= NOW() - make_interval(hours => $1::int)
           AND timestamp < NOW() - make_interval(hours => $2::int)",
    )
    .bind(window_hours)
    .bind(exclude_last_hours)
    .fetch_optional(db)
    .await
    .unwrap_or(None)
    .flatten()
    .unwrap_or(0.0)
}

async fn get_predictive_analytics(
    State(state): State<AppState>,
    auth: AuthUser,
    Query(params): Query<PredictiveQuery>,
) -> Result<Json<PredictiveAnalyticsResponse>, ApiError> {
    crate::middleware::auth::require_scopes(&auth, &["*"])?;

    let db = &state.db;
    let window = parse_window_days(&params.window);
    let _interval = format!("{window} days");
    let now = chrono::Utc::now();

    // ─── Churn Risk ─────────────────────────────────────────────────────
    // Subscription existence reads stripe_subscriptions — the table billing
    // webhooks write (the legacy `subscriptions` table has no writer).
    let inactive: Vec<InactiveTenantRow> = sqlx::query_as(
        "SELECT
            t.id::text as tenant_id,
            COALESCE(EXTRACT(EPOCH FROM (NOW() - MAX(m.created_at))) / 86400, 365)::bigint as days_inactive,
            MAX(m.created_at) as last_message_at,
            EXISTS(SELECT 1 FROM stripe_subscriptions s WHERE s.tenant_id::text = t.id::text AND s.status IN ('active', 'trialing', 'past_due')) as has_subscription,
            CASE
                WHEN COUNT(*) FILTER (WHERE m.status IN ('sent', 'delivered', 'bounced', 'failed')) > 0
                THEN COUNT(*) FILTER (WHERE m.status IN ('bounced', 'failed'))::float8
                     / NULLIF(COUNT(*) FILTER (WHERE m.status IN ('sent', 'delivered', 'bounced', 'failed')), 0)
                ELSE 0
            END as bounce_rate,
            COUNT(*) FILTER (WHERE m.created_at >= NOW() - INTERVAL '7 days') as recent_count,
            COUNT(*) FILTER (WHERE m.created_at >= NOW() - INTERVAL '14 days' AND m.created_at < NOW() - INTERVAL '7 days') as prev_count
         FROM tenants t
         LEFT JOIN messages m ON m.tenant_id::text = t.id::text
         WHERE t.status = 'active'
         GROUP BY t.id
         HAVING COALESCE(EXTRACT(EPOCH FROM (NOW() - MAX(m.created_at))) / 86400, 365) > 14
            OR EXISTS(SELECT 1 FROM stripe_subscriptions s WHERE s.tenant_id::text = t.id::text AND s.status = 'canceled')
         ORDER BY days_inactive DESC
         LIMIT 100",
    )
    .fetch_all(db)
    .await
    .unwrap_or_default();

    let at_risk_list: Vec<AtRiskTenant> = inactive
        .iter()
        .map(|r| {
            let days = r.days_inactive.unwrap_or(365);
            let has_sub = r.has_subscription.unwrap_or(false);
            let br = r.bounce_rate.unwrap_or(0.0);
            let recent = r.recent_count.unwrap_or(0);
            let prev = r.prev_count.unwrap_or(1);
            let decline = if prev > 0 && recent < prev {
                ((prev - recent) as f64 / prev as f64 * 100.0 * 10.0).round() / 10.0
            } else if days >= 30 {
                100.0
            } else if days >= 14 {
                50.0
            } else {
                0.0
            };
            AtRiskTenant {
                tenant_id: r.tenant_id.clone(),
                days_inactive: days,
                email_volume_decline_pct: decline,
                bounce_rate_30d: br,
                risk_level: classify_risk(days, has_sub, br),
                has_active_subscription: has_sub,
            }
        })
        .collect();

    let high_risk = at_risk_list
        .iter()
        .filter(|t| t.risk_level == "critical" || t.risk_level == "high")
        .count() as i64;
    let medium_risk = at_risk_list
        .iter()
        .filter(|t| t.risk_level == "medium")
        .count() as i64;

    let total_active: i64 =
        sqlx::query_scalar("SELECT COUNT(*)::bigint FROM tenants WHERE status = 'active'")
            .fetch_one(db)
            .await
            .unwrap_or(0);

    let heuristic_churn_risk_share = if total_active > 0 {
        high_risk as f64 / total_active as f64
    } else {
        0.0
    };

    // ─── Capacity Planning (heuristic extrapolation of real sends) ───────
    // Volume = DISTINCT messages with a successful `sent` event, bucketed by
    // event occurrence. `messages.created_at` would count mail that never
    // left the queue.
    let current_daily = current_daily_sends(db).await;
    let current_monthly = recent_sends(db, 30).await;
    let trend_30 = send_trend(db, 30).await;
    let trend_90 = send_trend(db, 90).await;

    // Weekly growth rate — compare last 7 days with the 7 before.
    let recent_7 = recent_sends(db, 7).await;
    let prev_7: i64 = sqlx::query_scalar(
        "SELECT COUNT(DISTINCT message_id)::bigint FROM events
         WHERE event_type = 'sent'
           AND timestamp >= NOW() - INTERVAL '14 days'
           AND timestamp < NOW() - INTERVAL '7 days'",
    )
    .fetch_one(db)
    .await
    .unwrap_or(1);

    let weekly_growth = if prev_7 > 0 {
        (recent_7 - prev_7) as f64 / prev_7 as f64
    } else {
        0.0
    };

    // Heuristic linear projection of the observed daily send volume.
    let avg_daily: f64 = if trend_30.len() > 1 {
        trend_30.iter().map(|p| p.volume as f64).sum::<f64>() / trend_30.len() as f64
    } else {
        current_daily as f64
    };

    let projected_30 = (avg_daily * 30.0 * (1.0 + weekly_growth.max(-0.5))).round() as i64;
    let projected_90 = (avg_daily * 90.0 * (1.0 + weekly_growth.max(-0.5))).round() as i64;

    // ─── Anomaly Detection (heuristic thresholds) ────────────────────────
    let mut anomalies: Vec<Anomaly> = Vec::new();
    let gen_at = now.to_rfc3339();

    // Anomaly: bounce rate spike (>2x the 30-day baseline). Both rates are
    // distinct-message rates over event occurrence, so they are like-for-like.
    let normal_bounce = event_bounce_rate(db, 30 * 24, 24).await;
    let today_bounce = event_bounce_rate(db, 24, 0).await;

    if normal_bounce > 0.0 && today_bounce > normal_bounce * 2.0 {
        anomalies.push(Anomaly {
            anomaly_type: "bounce_spike".into(),
            description: format!(
                "Bounce rate spike: {:.1}% today vs {:.1}% average (30-day baseline)",
                today_bounce * 100.0,
                normal_bounce * 100.0
            ),
            severity: if today_bounce > 0.10 {
                "critical"
            } else {
                "warning"
            }
            .into(),
            detected_value: format!("{:.2}%", today_bounce * 100.0),
            expected_range: format!("< {:.2}%", normal_bounce * 100.0 * 2.0),
            detected_at: gen_at.clone(),
            method: HEURISTIC_METHOD.into(),
        });
    }

    // Anomaly: backlog at/over the configured load-shedding capacity.
    // Like-for-like fix: the old code compared the CURRENT backlog against
    // the average number of queue rows CREATED per day — unlike quantities.
    // Backlog-growth history is not retained, so there is no historical
    // backlog baseline; the honest comparison is current backlog vs the
    // configured backlog threshold (EMAIL_MAX_BACKLOG).
    let current_queue: i64 = sqlx::query_scalar(
        "SELECT COUNT(*)::bigint FROM email_queue
         WHERE status IN ('pending', 'processing')",
    )
    .fetch_one(db)
    .await
    .unwrap_or(0);

    let capacity = configured_queue_capacity();
    if capacity > 0 && current_queue >= capacity {
        anomalies.push(Anomaly {
            anomaly_type: "queue_backlog_over_capacity".into(),
            description: format!(
                "Queue backlog: {} items pending/processing vs configured capacity {} (EMAIL_MAX_BACKLOG)",
                current_queue, capacity
            ),
            severity: if current_queue >= capacity.saturating_mul(2) {
                "critical"
            } else {
                "warning"
            }
            .into(),
            detected_value: format!("{} items", current_queue),
            expected_range: format!("< {} items", capacity),
            detected_at: gen_at.clone(),
            method: HEURISTIC_METHOD.into(),
        });
    }

    // Anomaly: zero-activity tenants with active subscriptions
    let zero_activity_paid: i64 = sqlx::query_scalar(
        "SELECT COUNT(*)::bigint FROM (
            SELECT t.id
            FROM tenants t
            JOIN stripe_subscriptions s ON s.tenant_id::text = t.id::text
            WHERE s.status IN ('active', 'trialing', 'past_due')
              AND NOT EXISTS (
                SELECT 1 FROM events e WHERE e.tenant_id::text = t.id::text
                  AND e.event_type = 'sent'
                  AND e.timestamp >= NOW() - INTERVAL '30 days'
              )
        ) sub",
    )
    .fetch_one(db)
    .await
    .unwrap_or(0);

    if zero_activity_paid > 0 {
        anomalies.push(Anomaly {
            anomaly_type: "paid_no_activity".into(),
            description: format!(
                "{} paying tenants have zero successful sends in the last 30 days",
                zero_activity_paid
            ),
            severity: if zero_activity_paid > 5 {
                "warning"
            } else {
                "info"
            }
            .into(),
            detected_value: format!("{} tenants", zero_activity_paid),
            expected_range: "0 tenants".into(),
            detected_at: gen_at.clone(),
            method: HEURISTIC_METHOD.into(),
        });
    }

    // ─── Volume Forecast (heuristic linear extrapolation) ────────────────
    // The variability band is derived from the observed 30-day daily-volume
    // variability (coefficient of variation) — not a hardcoded constant and
    // not a statistical confidence interval.
    let daily_volumes: Vec<i64> = trend_30.iter().map(|p| p.volume).collect();
    let forecast = VolumeForecast {
        current_volume: current_monthly,
        heuristic_next_week: (current_daily as f64 * 7.0 * (1.0 + weekly_growth.max(-0.5))).round()
            as i64,
        heuristic_next_month: projected_30,
        heuristic_next_quarter: projected_90,
        variability_band: volume_variability_band(&daily_volumes),
        method: HEURISTIC_METHOD.into(),
    };

    Ok(Json(PredictiveAnalyticsResponse {
        churn_risk: ChurnRiskDashboard {
            at_risk_tenants: at_risk_list.len() as i64,
            high_risk_count: high_risk,
            medium_risk_count: medium_risk,
            heuristic_churn_risk_share,
            top_risk_signals: vec![
                RiskSignal {
                    signal: "Inactive >30 days".into(),
                    affected_tenants: at_risk_list.iter().filter(|t| t.days_inactive > 30).count()
                        as i64,
                    severity:
                        if at_risk_list.iter().filter(|t| t.days_inactive > 30).count() > 10 {
                            "high"
                        } else {
                            "medium"
                        }
                        .into(),
                },
                RiskSignal {
                    signal: "High bounce rate (>5%)".into(),
                    affected_tenants: at_risk_list
                        .iter()
                        .filter(|t| t.bounce_rate_30d > 0.05)
                        .count() as i64,
                    severity: "medium".into(),
                },
            ],
            at_risk_tenants_list: at_risk_list,
        },
        capacity: CapacityPlanning {
            current_daily_volume: current_daily,
            current_monthly_volume: current_monthly,
            volume_trend_30d: trend_30,
            volume_trend_90d: trend_90,
            heuristic_projected_30d_volume: projected_30,
            heuristic_projected_90d_volume: projected_90,
            weekly_growth_rate: weekly_growth,
            capacity_utilization: compute_capacity_utilization(current_queue, capacity),
            days_until_capacity_limit: days_until_capacity_limit(current_queue, capacity),
        },
        anomalies,
        forecast,
        method: HEURISTIC_METHOD.into(),
        generated_at: gen_at,
    }))
}

async fn get_churn_risk(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<Json<ChurnRiskDashboard>, ApiError> {
    crate::middleware::auth::require_scopes(&auth, &["*"])?;

    let db = &state.db;

    let inactive: Vec<InactiveTenantRow> = sqlx::query_as(
        "SELECT
            t.id::text as tenant_id,
            COALESCE(EXTRACT(EPOCH FROM (NOW() - MAX(m.created_at))) / 86400, 365)::bigint as days_inactive,
            MAX(m.created_at) as last_message_at,
            EXISTS(SELECT 1 FROM stripe_subscriptions s WHERE s.tenant_id::text = t.id::text AND s.status IN ('active', 'trialing', 'past_due')) as has_subscription,
            CASE
                WHEN COUNT(*) FILTER (WHERE m.status IN ('sent', 'delivered', 'bounced', 'failed')) > 0
                THEN COUNT(*) FILTER (WHERE m.status IN ('bounced', 'failed'))::float8
                     / NULLIF(COUNT(*) FILTER (WHERE m.status IN ('sent', 'delivered', 'bounced', 'failed')), 0)
                ELSE 0
            END as bounce_rate,
            COUNT(*) FILTER (WHERE m.created_at >= NOW() - INTERVAL '7 days') as recent_count,
            COUNT(*) FILTER (WHERE m.created_at >= NOW() - INTERVAL '14 days' AND m.created_at < NOW() - INTERVAL '7 days') as prev_count
         FROM tenants t
         LEFT JOIN messages m ON m.tenant_id::text = t.id::text
         WHERE t.status = 'active'
         GROUP BY t.id
         HAVING COALESCE(EXTRACT(EPOCH FROM (NOW() - MAX(m.created_at))) / 86400, 365) > 14
         ORDER BY days_inactive DESC
         LIMIT 100",
    )
    .fetch_all(db)
    .await
    .unwrap_or_default();

    let at_risk_list: Vec<AtRiskTenant> = inactive
        .iter()
        .map(|r| {
            let days = r.days_inactive.unwrap_or(365);
            let has_sub = r.has_subscription.unwrap_or(false);
            let br = r.bounce_rate.unwrap_or(0.0);
            let recent = r.recent_count.unwrap_or(0);
            let prev = r.prev_count.unwrap_or(1);
            let decline = if prev > 0 && recent < prev {
                ((prev - recent) as f64 / prev as f64 * 100.0 * 10.0).round() / 10.0
            } else if days >= 30 {
                100.0
            } else if days >= 14 {
                50.0
            } else {
                0.0
            };
            AtRiskTenant {
                tenant_id: r.tenant_id.clone(),
                days_inactive: days,
                email_volume_decline_pct: decline,
                bounce_rate_30d: br,
                risk_level: classify_risk(days, has_sub, br),
                has_active_subscription: has_sub,
            }
        })
        .collect();

    let high_risk = at_risk_list
        .iter()
        .filter(|t| t.risk_level == "critical" || t.risk_level == "high")
        .count() as i64;
    let medium_risk = at_risk_list
        .iter()
        .filter(|t| t.risk_level == "medium")
        .count() as i64;

    let total_active: i64 =
        sqlx::query_scalar("SELECT COUNT(*)::bigint FROM tenants WHERE status = 'active'")
            .fetch_one(db)
            .await
            .unwrap_or(0);

    Ok(Json(ChurnRiskDashboard {
        at_risk_tenants: at_risk_list.len() as i64,
        high_risk_count: high_risk,
        medium_risk_count: medium_risk,
        heuristic_churn_risk_share: if total_active > 0 {
            high_risk as f64 / total_active as f64
        } else {
            0.0
        },
        top_risk_signals: vec![
            RiskSignal {
                signal: "Inactive >30 days".into(),
                affected_tenants: at_risk_list.iter().filter(|t| t.days_inactive > 30).count()
                    as i64,
                severity: "high".into(),
            },
            RiskSignal {
                signal: "High bounce rate (>5%)".into(),
                affected_tenants: at_risk_list
                    .iter()
                    .filter(|t| t.bounce_rate_30d > 0.05)
                    .count() as i64,
                severity: "medium".into(),
            },
        ],
        at_risk_tenants_list: at_risk_list,
    }))
}

async fn get_capacity_planning(
    State(state): State<AppState>,
    auth: AuthUser,
    Query(_params): Query<PredictiveQuery>,
) -> Result<Json<CapacityPlanning>, ApiError> {
    crate::middleware::auth::require_scopes(&auth, &["*"])?;

    let db = &state.db;

    // Volume = DISTINCT messages with a successful `sent` event, by event
    // occurrence. Extrapolations below are heuristic, not calibrated.
    let current_daily = current_daily_sends(db).await;
    let current_monthly = recent_sends(db, 30).await;
    let trend_30 = send_trend(db, 30).await;
    let trend_90 = send_trend(db, 90).await;

    let recent_7 = recent_sends(db, 7).await;

    let prev_7: i64 = sqlx::query_scalar(
        "SELECT COUNT(DISTINCT message_id)::bigint FROM events
         WHERE event_type = 'sent'
           AND timestamp >= NOW() - INTERVAL '14 days'
           AND timestamp < NOW() - INTERVAL '7 days'",
    )
    .fetch_one(db)
    .await
    .unwrap_or(1);

    let weekly_growth = if prev_7 > 0 {
        (recent_7 - prev_7) as f64 / prev_7 as f64
    } else {
        0.0
    };

    let avg_daily: f64 = if trend_30.len() > 1 {
        trend_30.iter().map(|p| p.volume as f64).sum::<f64>() / trend_30.len() as f64
    } else {
        current_daily as f64
    };

    // Queue depth vs the configured capacity the worker load-sheds at —
    // real utilization (fraction) instead of the previous 0.0 placeholder.
    let queue_depth: i64 = sqlx::query_scalar(
        "SELECT COUNT(*)::bigint FROM email_queue
         WHERE status IN ('pending', 'processing')",
    )
    .fetch_one(db)
    .await
    .unwrap_or(0);
    let capacity = configured_queue_capacity();

    Ok(Json(CapacityPlanning {
        current_daily_volume: current_daily,
        current_monthly_volume: current_monthly,
        volume_trend_30d: trend_30,
        volume_trend_90d: trend_90,
        heuristic_projected_30d_volume: (avg_daily * 30.0 * (1.0 + weekly_growth.max(-0.5))).round()
            as i64,
        heuristic_projected_90d_volume: (avg_daily * 90.0 * (1.0 + weekly_growth.max(-0.5))).round()
            as i64,
        weekly_growth_rate: weekly_growth,
        capacity_utilization: compute_capacity_utilization(queue_depth, capacity),
        days_until_capacity_limit: days_until_capacity_limit(queue_depth, capacity),
    }))
}

async fn get_anomalies(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<Json<Vec<Anomaly>>, ApiError> {
    crate::middleware::auth::require_scopes(&auth, &["*"])?;

    let db = &state.db;
    let now = chrono::Utc::now();
    let gen_at = now.to_rfc3339();
    let mut anomalies: Vec<Anomaly> = Vec::new();

    // Bounce rate anomaly — distinct-message rates over event occurrence
    // for both windows (like-for-like).
    let normal_bounce = event_bounce_rate(db, 30 * 24, 24).await;
    let today_bounce = event_bounce_rate(db, 24, 0).await;

    if normal_bounce > 0.0 && today_bounce > normal_bounce * 2.0 {
        anomalies.push(Anomaly {
            anomaly_type: "bounce_spike".into(),
            description: format!(
                "Bounce rate spike: {:.1}% today vs {:.1}% average",
                today_bounce * 100.0,
                normal_bounce * 100.0
            ),
            severity: if today_bounce > 0.10 {
                "critical"
            } else {
                "warning"
            }
            .into(),
            detected_value: format!("{:.2}%", today_bounce * 100.0),
            expected_range: format!("< {:.2}%", normal_bounce * 100.0 * 2.0),
            detected_at: gen_at.clone(),
            method: HEURISTIC_METHOD.into(),
        });
    }

    // Queue backlog anomaly — like-for-like: current backlog vs the
    // configured backlog threshold. Backlog-growth history is not retained,
    // so no historical backlog baseline is claimed.
    let current_queue: i64 = sqlx::query_scalar(
        "SELECT COUNT(*)::bigint FROM email_queue
         WHERE status IN ('pending', 'processing')",
    )
    .fetch_one(db)
    .await
    .unwrap_or(0);

    let capacity = configured_queue_capacity();
    if capacity > 0 && current_queue >= capacity {
        anomalies.push(Anomaly {
            anomaly_type: "queue_backlog_over_capacity".into(),
            description: format!(
                "Queue backlog: {} items pending/processing vs configured capacity {} (EMAIL_MAX_BACKLOG)",
                current_queue, capacity
            ),
            severity: if current_queue >= capacity.saturating_mul(2) {
                "critical"
            } else {
                "warning"
            }
            .into(),
            detected_value: format!("{} items", current_queue),
            expected_range: format!("< {} items", capacity),
            detected_at: gen_at.clone(),
            method: HEURISTIC_METHOD.into(),
        });
    }

    // Failed delivery spike
    let normal_failed: f64 = sqlx::query_scalar::<_, Option<f64>>(
        "SELECT AVG(cnt)::float8 FROM (
            SELECT COUNT(*)::float8 as cnt
            FROM email_queue
            WHERE status = 'failed'
              AND updated_at >= NOW() - INTERVAL '7 days'
              AND updated_at < NOW() - INTERVAL '1 hour'
            GROUP BY DATE(updated_at)
        ) sub",
    )
    .fetch_optional(db)
    .await
    .unwrap_or(None)
    .flatten()
    .unwrap_or(0.0);

    let today_failed: i64 = sqlx::query_scalar(
        "SELECT COUNT(*)::bigint FROM email_queue
         WHERE status = 'failed'
           AND updated_at >= NOW() - INTERVAL '24 hours'",
    )
    .fetch_one(db)
    .await
    .unwrap_or(0);

    if normal_failed > 0.0 && today_failed as f64 > normal_failed * 3.0 {
        anomalies.push(Anomaly {
            anomaly_type: "delivery_failure_spike".into(),
            description: format!(
                "Delivery failures spike: {} today vs {:.0} avg",
                today_failed, normal_failed
            ),
            severity: "warning".into(),
            detected_value: format!("{} failures", today_failed),
            expected_range: format!("< {} failures", (normal_failed * 3.0) as i64),
            detected_at: gen_at.clone(),
            method: HEURISTIC_METHOD.into(),
        });
    }

    Ok(Json(anomalies))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_risk_critical_for_long_inactive_with_subscription() {
        assert_eq!(classify_risk(90, true, 0.02), "critical");
    }

    #[test]
    fn classify_risk_high_for_medium_inactive_with_bounces() {
        assert_eq!(classify_risk(45, true, 0.15), "high");
    }

    #[test]
    fn classify_risk_high_for_paying_customer_inactive_40d() {
        assert_eq!(classify_risk(40, true, 0.0), "high");
    }

    #[test]
    fn classify_risk_medium_for_two_weeks() {
        assert_eq!(classify_risk(20, false, 0.01), "medium");
    }

    #[test]
    fn classify_risk_low_for_recent_activity() {
        assert_eq!(classify_risk(5, false, 0.0), "low");
    }

    #[test]
    fn parse_window_days_defaults() {
        assert_eq!(parse_window_days("unknown"), 90);
    }

    #[test]
    fn capacity_projection_stays_positive() {
        // Ensure projection formula doesn't go negative with negative growth
        let growth = -0.8f64;
        let adj = growth.max(-0.5);
        assert!((adj + 1.0) > 0.0);
    }

    #[test]
    fn capacity_utilization_computes_against_configured_backlog() {
        // 2_500 pending against a 10_000 capacity (worker default) → 0.25
        // FRACTION (the single rate unit across admin analytics).
        assert!((compute_capacity_utilization(2_500, 10_000) - 0.25).abs() < 0.001);
        // Over-capacity backlogs report above 1.0 rather than being clamped.
        assert!(compute_capacity_utilization(12_000, 10_000) > 1.0);
        // Degenerate capacity is safe.
        assert_eq!(compute_capacity_utilization(500, 0), 0.0);
    }

    #[test]
    fn configured_queue_capacity_uses_env_and_positive_default() {
        // Default mirrors the worker's BackpressureConfig max_backlog.
        std::env::remove_var("EMAIL_MAX_BACKLOG");
        assert_eq!(configured_queue_capacity(), DEFAULT_EMAIL_MAX_BACKLOG);
        assert_eq!(DEFAULT_EMAIL_MAX_BACKLOG, 10_000);
    }

    #[test]
    fn days_until_capacity_limit_only_fires_when_backlog_full() {
        assert_eq!(days_until_capacity_limit(10_000, 10_000), Some(0));
        assert_eq!(days_until_capacity_limit(11_000, 10_000), Some(0));
        // Without backlog-growth history a projection date is honestly None.
        assert_eq!(days_until_capacity_limit(9_999, 10_000), None);
    }

    #[test]
    fn volume_variability_band_is_observed_and_not_a_confidence_interval() {
        // Flat volumes → ±0% variability.
        let flat = volume_variability_band(&[100, 100, 100, 100]);
        assert!(flat.starts_with("±0%"), "got {flat}");

        // Volatile volumes → a non-zero band derived from the CV.
        let volatile = volume_variability_band(&[10, 200, 50, 140]);
        assert!(volatile.starts_with("±"), "got {volatile}");
        assert!(
            !volatile.contains("±15%"),
            "must not be the old hardcoded interval"
        );
        assert!(
            volatile.contains("not a confidence interval"),
            "the band must be labelled as observed variability: {volatile}"
        );

        // Too little history → honest "unestimated", not a made-up number.
        assert!(volume_variability_band(&[42]).contains("insufficient"));
        assert!(volume_variability_band(&[]).contains("insufficient"));
        assert!(volume_variability_band(&[0, 0]).contains("no send volume"));
    }

    #[test]
    fn heuristic_method_label_says_no_trained_model() {
        assert!(HEURISTIC_METHOD.contains("heuristic"));
        assert!(HEURISTIC_METHOD.contains("no trained model"));
    }

    /// Executes the real volume/bounce SQL against the canonical schema:
    /// volume counts DISTINCT sent messages, and the two bounce windows are
    /// like-for-like distinct-message rates. Gated on TEST_DATABASE_URL.
    #[tokio::test]
    async fn send_volume_and_bounce_rate_are_distinct_message_based() {
        let Some(pool) = crate::test_db::canonical_pool("predictive_send_volume").await else {
            eprintln!(
                "skipping send_volume_and_bounce_rate_are_distinct_message_based: no TEST_DATABASE_URL"
            );
            return;
        };

        let suffix = uuid::Uuid::new_v4().simple().to_string();
        let tenant = format!("t{}", &suffix[..25]);
        let message_a = format!("msg-{suffix}-a");
        let message_b = format!("msg-{suffix}-b");

        let seed = |message: String, event: &'static str| {
            let pool = pool.clone();
            let tenant = tenant.clone();
            async move {
                sqlx::query(
                    "INSERT INTO events (id, tenant_id, message_id, event_type, timestamp)
                     VALUES ($1, $2, $3, $4, NOW() - INTERVAL '10 minutes')",
                )
                .bind(format!("evt-{}", uuid::Uuid::new_v4().simple()))
                .bind(&tenant)
                .bind(&message)
                .bind(event)
                .execute(&pool)
                .await
                .expect("seed event");
            }
        };

        // Two sent messages (A sent twice), one bounce on A only.
        seed(message_a.clone(), "sent").await;
        seed(message_a.clone(), "sent").await;
        seed(message_b, "sent").await;
        seed(message_a, "bounced").await;

        let trend = send_trend(&pool, 30).await;
        let volume: i64 = trend.iter().map(|p| p.volume).sum();
        assert_eq!(volume, 2, "distinct sent messages, not 3 send events");

        // Distinct bounced (1) / distinct sent (2) = 0.5 in the last 24h.
        let today = event_bounce_rate(&pool, 24, 0).await;
        assert!((today - 0.5).abs() < 1e-9, "got {today}");

        // 30-day baseline excludes the last 24h, so it sees nothing here.
        let baseline = event_bounce_rate(&pool, 30 * 24, 24).await;
        assert_eq!(baseline, 0.0);

        pool.close().await;
    }
}
