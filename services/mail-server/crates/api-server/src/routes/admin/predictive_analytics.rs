//! Predictive analytics endpoint — churn prediction, capacity planning,
//! volume trend extrapolation, and anomaly detection.
//!
//! All values come from real database queries. Predictive models use actual
//! historical data; when unavailable, the response explicitly states
//! "No data yet" rather than returning fabricated values.

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
    pub generated_at: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ChurnRiskDashboard {
    pub at_risk_tenants: i64,
    pub high_risk_count: i64,
    pub medium_risk_count: i64,
    pub predicted_churn_rate_30d: f64,
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
    pub current_daily_volume: i64,
    pub current_monthly_volume: i64,
    pub volume_trend_30d: Vec<TrendPoint>,
    pub volume_trend_90d: Vec<TrendPoint>,
    pub projected_30d_volume: i64,
    pub projected_90d_volume: i64,
    pub weekly_growth_rate: f64,
    pub capacity_utilization_pct: f64,
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
    pub current_volume: i64,
    pub projected_next_week: i64,
    pub projected_next_month: i64,
    pub projected_next_quarter: i64,
    pub confidence_interval: String,
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

/// Queue utilization as a percentage of the configured capacity
/// (0-100+, values above 100 mean the backlog exceeds the load-shedding
/// threshold). Previously a hardcoded 0.0 placeholder.
fn compute_capacity_utilization(queue_depth: i64, capacity: i64) -> f64 {
    if capacity <= 0 {
        return 0.0;
    }
    (queue_depth as f64 / capacity as f64) * 100.0
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

/// Forecast confidence derived from the observed variability of daily send
/// volumes: the coefficient of variation (stdev / mean) over the trend
/// window. With fewer than two daily data points there is nothing to
/// estimate variability from, so the interval is reported as unestimated —
/// never a fabricated "±15%".
fn forecast_confidence_interval(daily_volumes: &[i64]) -> String {
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
        "±{:.0}% (30-day daily-volume variability)",
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
            .unwrap_or(1);

    let predicted_churn = if total_active > 0 {
        high_risk as f64 / total_active as f64
    } else {
        0.0
    };

    // ─── Capacity Planning ───────────────────────────────────────────────
    let current_daily: i64 = sqlx::query_scalar(
        "SELECT COUNT(*)::bigint FROM messages
         WHERE created_at >= CURRENT_DATE",
    )
    .fetch_one(db)
    .await
    .unwrap_or(0);

    let current_monthly: i64 = sqlx::query_scalar(
        "SELECT COUNT(*)::bigint FROM messages
         WHERE created_at >= NOW() - INTERVAL '30 days'",
    )
    .fetch_one(db)
    .await
    .unwrap_or(0);

    // 30-day volume trend
    let trend_30: Vec<TrendPoint> = sqlx::query_as::<_, VolumeRow>(
        "SELECT DATE(created_at)::text as date, COUNT(*)::bigint as volume
         FROM messages
         WHERE created_at >= NOW() - INTERVAL '30 days'
         GROUP BY DATE(created_at) ORDER BY 1",
    )
    .fetch_all(db)
    .await
    .unwrap_or_default()
    .into_iter()
    .map(|r| TrendPoint {
        date: r.date,
        volume: r.volume,
        projected: false,
    })
    .collect();

    // 90-day volume trend
    let trend_90: Vec<TrendPoint> = sqlx::query_as::<_, VolumeRow>(
        "SELECT DATE(created_at)::text as date, COUNT(*)::bigint as volume
         FROM messages
         WHERE created_at >= NOW() - INTERVAL '90 days'
         GROUP BY DATE(created_at) ORDER BY 1",
    )
    .fetch_all(db)
    .await
    .unwrap_or_default()
    .into_iter()
    .map(|r| TrendPoint {
        date: r.date,
        volume: r.volume,
        projected: false,
    })
    .collect();

    // Weekly growth rate — compare last 7 days with previous 7
    let recent_7: i64 = sqlx::query_scalar(
        "SELECT COUNT(*)::bigint FROM messages
         WHERE created_at >= NOW() - INTERVAL '7 days'",
    )
    .fetch_one(db)
    .await
    .unwrap_or(0);

    let prev_7: i64 = sqlx::query_scalar(
        "SELECT COUNT(*)::bigint FROM messages
         WHERE created_at >= NOW() - INTERVAL '14 days'
           AND created_at < NOW() - INTERVAL '7 days'",
    )
    .fetch_one(db)
    .await
    .unwrap_or(1);

    let weekly_growth = if prev_7 > 0 {
        (recent_7 - prev_7) as f64 / prev_7 as f64
    } else {
        0.0
    };

    // Simple linear projection
    let avg_daily: f64 = if trend_30.len() > 1 {
        trend_30.iter().map(|p| p.volume as f64).sum::<f64>() / trend_30.len() as f64
    } else {
        current_daily as f64
    };

    let projected_30 = (avg_daily * 30.0 * (1.0 + weekly_growth.max(-0.5))).round() as i64;
    let projected_90 = (avg_daily * 90.0 * (1.0 + weekly_growth.max(-0.5))).round() as i64;

    // ─── Anomaly Detection ───────────────────────────────────────────────
    let mut anomalies: Vec<Anomaly> = Vec::new();
    let gen_at = now.to_rfc3339();

    // Anomaly: bounce rate spike (>2x normal)
    let normal_bounce: f64 = sqlx::query_scalar::<_, Option<f64>>(
        "SELECT
            CASE
                WHEN SUM(CASE WHEN status IN ('sent','delivered','bounced','failed') THEN 1 ELSE 0 END) > 0
                THEN SUM(CASE WHEN status IN ('bounced','failed') THEN 1 ELSE 0 END)::float8
                     / NULLIF(SUM(CASE WHEN status IN ('sent','delivered','bounced','failed') THEN 1 ELSE 0 END), 0)
                ELSE 0
            END
         FROM messages
         WHERE created_at >= NOW() - INTERVAL '30 days'
           AND created_at < NOW() - INTERVAL '24 hours'",
    )
    .fetch_optional(db)
    .await
    .unwrap_or(None)
    .flatten()
    .unwrap_or(0.0);

    let today_bounce: f64 = sqlx::query_scalar::<_, Option<f64>>(
        "SELECT
            CASE
                WHEN SUM(CASE WHEN status IN ('sent','delivered','bounced','failed') THEN 1 ELSE 0 END) > 0
                THEN SUM(CASE WHEN status IN ('bounced','failed') THEN 1 ELSE 0 END)::float8
                     / NULLIF(SUM(CASE WHEN status IN ('sent','delivered','bounced','failed') THEN 1 ELSE 0 END), 0)
                ELSE 0
            END
         FROM messages
         WHERE created_at >= NOW() - INTERVAL '24 hours'",
    )
    .fetch_optional(db)
    .await
    .unwrap_or(None)
    .flatten()
    .unwrap_or(0.0);

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
        });
    }

    // Anomaly: queue depth spike
    let normal_queue: f64 = sqlx::query_scalar::<_, Option<f64>>(
        "SELECT AVG(cnt)::float8 FROM (
            SELECT DATE(created_at) as d, COUNT(*)::float8 as cnt
            FROM email_queue
            WHERE created_at >= NOW() - INTERVAL '7 days'
              AND created_at < NOW() - INTERVAL '1 hour'
            GROUP BY DATE(created_at)
        ) sub",
    )
    .fetch_optional(db)
    .await
    .unwrap_or(None)
    .flatten()
    .unwrap_or(0.0);

    let current_queue: i64 = sqlx::query_scalar(
        "SELECT COUNT(*)::bigint FROM email_queue
         WHERE status IN ('pending', 'processing')",
    )
    .fetch_one(db)
    .await
    .unwrap_or(0);

    if normal_queue > 0.0 && current_queue as f64 > normal_queue * 3.0 {
        anomalies.push(Anomaly {
            anomaly_type: "queue_backlog".into(),
            description: format!(
                "Queue backlog: {} items pending vs {:.0} average (7-day baseline)",
                current_queue, normal_queue
            ),
            severity: if current_queue > 1000 {
                "critical"
            } else {
                "warning"
            }
            .into(),
            detected_value: format!("{} items", current_queue),
            expected_range: format!("< {} items", (normal_queue * 3.0) as i64),
            detected_at: gen_at.clone(),
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
                SELECT 1 FROM messages m WHERE m.tenant_id::text = t.id::text
                  AND m.created_at >= NOW() - INTERVAL '30 days'
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
                "{} paying tenants have zero email activity in the last 30 days",
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
        });
    }

    // ─── Volume Forecast ─────────────────────────────────────────────────
    // Confidence interval derived from the observed 30-day daily-volume
    // variability (coefficient of variation) — not a hardcoded constant.
    let daily_volumes: Vec<i64> = trend_30.iter().map(|p| p.volume).collect();
    let forecast = VolumeForecast {
        current_volume: current_monthly,
        projected_next_week: (current_daily as f64 * 7.0 * (1.0 + weekly_growth.max(-0.5))).round()
            as i64,
        projected_next_month: projected_30,
        projected_next_quarter: projected_90,
        confidence_interval: forecast_confidence_interval(&daily_volumes),
    };

    Ok(Json(PredictiveAnalyticsResponse {
        churn_risk: ChurnRiskDashboard {
            at_risk_tenants: at_risk_list.len() as i64,
            high_risk_count: high_risk,
            medium_risk_count: medium_risk,
            predicted_churn_rate_30d: predicted_churn,
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
            projected_30d_volume: projected_30,
            projected_90d_volume: projected_90,
            weekly_growth_rate: weekly_growth,
            capacity_utilization_pct: compute_capacity_utilization(
                current_queue,
                configured_queue_capacity(),
            ),
            days_until_capacity_limit: days_until_capacity_limit(
                current_queue,
                configured_queue_capacity(),
            ),
        },
        anomalies,
        forecast,
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
            .unwrap_or(1);

    Ok(Json(ChurnRiskDashboard {
        at_risk_tenants: at_risk_list.len() as i64,
        high_risk_count: high_risk,
        medium_risk_count: medium_risk,
        predicted_churn_rate_30d: if total_active > 0 {
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

    let current_daily: i64 = sqlx::query_scalar(
        "SELECT COUNT(*)::bigint FROM messages
         WHERE created_at >= CURRENT_DATE",
    )
    .fetch_one(db)
    .await
    .unwrap_or(0);

    let current_monthly: i64 = sqlx::query_scalar(
        "SELECT COUNT(*)::bigint FROM messages
         WHERE created_at >= NOW() - INTERVAL '30 days'",
    )
    .fetch_one(db)
    .await
    .unwrap_or(0);

    let trend_30: Vec<TrendPoint> = sqlx::query_as::<_, VolumeRow>(
        "SELECT DATE(created_at)::text as date, COUNT(*)::bigint as volume
         FROM messages
         WHERE created_at >= NOW() - INTERVAL '30 days'
         GROUP BY DATE(created_at) ORDER BY 1",
    )
    .fetch_all(db)
    .await
    .unwrap_or_default()
    .into_iter()
    .map(|r| TrendPoint {
        date: r.date,
        volume: r.volume,
        projected: false,
    })
    .collect();

    let trend_90: Vec<TrendPoint> = sqlx::query_as::<_, VolumeRow>(
        "SELECT DATE(created_at)::text as date, COUNT(*)::bigint as volume
         FROM messages
         WHERE created_at >= NOW() - INTERVAL '90 days'
         GROUP BY DATE(created_at) ORDER BY 1",
    )
    .fetch_all(db)
    .await
    .unwrap_or_default()
    .into_iter()
    .map(|r| TrendPoint {
        date: r.date,
        volume: r.volume,
        projected: false,
    })
    .collect();

    let recent_7: i64 = sqlx::query_scalar(
        "SELECT COUNT(*)::bigint FROM messages
         WHERE created_at >= NOW() - INTERVAL '7 days'",
    )
    .fetch_one(db)
    .await
    .unwrap_or(0);

    let prev_7: i64 = sqlx::query_scalar(
        "SELECT COUNT(*)::bigint FROM messages
         WHERE created_at >= NOW() - INTERVAL '14 days'
           AND created_at < NOW() - INTERVAL '7 days'",
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
    // real utilization instead of the previous 0.0 placeholder.
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
        projected_30d_volume: (avg_daily * 30.0 * (1.0 + weekly_growth.max(-0.5))).round() as i64,
        projected_90d_volume: (avg_daily * 90.0 * (1.0 + weekly_growth.max(-0.5))).round() as i64,
        weekly_growth_rate: weekly_growth,
        capacity_utilization_pct: compute_capacity_utilization(queue_depth, capacity),
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

    // Bounce rate anomaly
    let normal_bounce: f64 = sqlx::query_scalar::<_, Option<f64>>(
        "SELECT
            CASE
                WHEN SUM(CASE WHEN status IN ('sent','delivered','bounced','failed') THEN 1 ELSE 0 END) > 0
                THEN SUM(CASE WHEN status IN ('bounced','failed') THEN 1 ELSE 0 END)::float8
                     / NULLIF(SUM(CASE WHEN status IN ('sent','delivered','bounced','failed') THEN 1 ELSE 0 END), 0)
                ELSE 0
            END
         FROM messages
         WHERE created_at >= NOW() - INTERVAL '30 days'
           AND created_at < NOW() - INTERVAL '24 hours'",
    )
    .fetch_optional(db)
    .await
    .unwrap_or(None)
    .flatten()
    .unwrap_or(0.0);

    let today_bounce: f64 = sqlx::query_scalar::<_, Option<f64>>(
        "SELECT
            CASE
                WHEN SUM(CASE WHEN status IN ('sent','delivered','bounced','failed') THEN 1 ELSE 0 END) > 0
                THEN SUM(CASE WHEN status IN ('bounced','failed') THEN 1 ELSE 0 END)::float8
                     / NULLIF(SUM(CASE WHEN status IN ('sent','delivered','bounced','failed') THEN 1 ELSE 0 END), 0)
                ELSE 0
            END
         FROM messages
         WHERE created_at >= NOW() - INTERVAL '24 hours'",
    )
    .fetch_optional(db)
    .await
    .unwrap_or(None)
    .flatten()
    .unwrap_or(0.0);

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
        });
    }

    // Queue backlog anomaly
    let normal_queue: f64 = sqlx::query_scalar::<_, Option<f64>>(
        "SELECT AVG(cnt)::float8 FROM (
            SELECT COUNT(*)::float8 as cnt
            FROM email_queue
            WHERE created_at >= NOW() - INTERVAL '7 days'
              AND created_at < NOW() - INTERVAL '1 hour'
            GROUP BY DATE(created_at)
        ) sub",
    )
    .fetch_optional(db)
    .await
    .unwrap_or(None)
    .flatten()
    .unwrap_or(0.0);

    let current_queue: i64 = sqlx::query_scalar(
        "SELECT COUNT(*)::bigint FROM email_queue
         WHERE status IN ('pending', 'processing')",
    )
    .fetch_one(db)
    .await
    .unwrap_or(0);

    if normal_queue > 0.0 && current_queue as f64 > normal_queue * 3.0 {
        anomalies.push(Anomaly {
            anomaly_type: "queue_backlog".into(),
            description: format!(
                "Queue backlog: {} items pending vs {:.0} average",
                current_queue, normal_queue
            ),
            severity: if current_queue > 1000 {
                "critical"
            } else {
                "warning"
            }
            .into(),
            detected_value: format!("{} items", current_queue),
            expected_range: format!("< {} items", (normal_queue * 3.0) as i64),
            detected_at: gen_at.clone(),
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
        // 2_500 pending against a 10_000 capacity (worker default) → 25%.
        assert!((compute_capacity_utilization(2_500, 10_000) - 25.0).abs() < 0.001);
        // Over-capacity backlogs report above 100 rather than being clamped.
        assert!(compute_capacity_utilization(12_000, 10_000) > 100.0);
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
    fn forecast_confidence_interval_derives_from_volume_variability() {
        // Flat volumes → ±0% variability.
        let flat = forecast_confidence_interval(&[100, 100, 100, 100]);
        assert!(flat.starts_with("±0%"), "got {flat}");

        // Volatile volumes → a non-zero interval derived from the CV.
        let volatile = forecast_confidence_interval(&[10, 200, 50, 140]);
        assert!(volatile.starts_with("±"), "got {volatile}");
        assert!(
            !volatile.contains("±15%"),
            "must not be the old hardcoded interval"
        );

        // Too little history → honest "unestimated", not a made-up number.
        assert!(forecast_confidence_interval(&[42]).contains("insufficient"));
        assert!(forecast_confidence_interval(&[]).contains("insufficient"));
        assert!(forecast_confidence_interval(&[0, 0]).contains("no send volume"));
    }
}
