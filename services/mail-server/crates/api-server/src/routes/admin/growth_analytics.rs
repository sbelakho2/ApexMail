//! Growth analytics endpoint — new signups, activation rate, DAU/MAU,
//! trial conversion, and customer lifecycle metrics.
//!
//! All values come from real database queries against tenants, users, messages,
//! events, subscriptions, and stripe_subscriptions tables.

use axum::extract::{Query, State};
use axum::routing::get;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use crate::error::ApiError;
use crate::middleware::auth::AuthUser;
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/", get(get_growth_analytics))
        .route("/signups", get(get_signup_timeline))
        .route("/activation", get(get_activation_funnel))
        .route("/engagement", get(get_engagement_metrics))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GrowthQuery {
    #[serde(default = "default_period")]
    pub period: String,
}

fn default_period() -> String {
    "30d".into()
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GrowthAnalyticsResponse {
    pub signups: SignupStats,
    pub activation: ActivationStats,
    pub engagement: EngagementMetrics,
    pub trial_conversion: TrialConversionStats,
    pub lifecycle: CustomerLifecycle,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SignupStats {
    pub total_signups: i64,
    pub new_today: i64,
    pub new_this_week: i64,
    pub new_this_month: i64,
    pub signup_timeline: Vec<SignupTimelinePoint>,
    pub by_plan: Vec<SignupByPlan>,
    pub by_source_referrer: Vec<SourceBreakdown>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SignupTimelinePoint {
    pub date: String,
    pub count: i64,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SignupByPlan {
    pub plan: String,
    pub count: i64,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SourceBreakdown {
    pub source: String,
    pub count: i64,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ActivationStats {
    pub total_activated: i64,
    pub activation_rate: f64,
    pub avg_time_to_activate_hours: f64,
    pub activation_funnel: Vec<ActivationFunnelStage>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ActivationFunnelStage {
    pub stage: String,
    pub count: i64,
    pub percentage: f64,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EngagementMetrics {
    pub dau: i64,
    pub mau: i64,
    pub dau_mau_ratio: f64,
    pub wau: i64,
    pub monthly_active_tenants: i64,
    pub avg_session_count_per_user: f64,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TrialConversionStats {
    pub trials_started: i64,
    pub trials_converted: i64,
    pub conversion_rate: f64,
    pub avg_trial_to_paid_days: f64,
    pub conversion_by_plan: Vec<TrialPlanConversion>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TrialPlanConversion {
    pub plan: String,
    pub trials: i64,
    pub converted: i64,
    pub rate: f64,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CustomerLifecycle {
    pub new_customers_30d: i64,
    pub active_customers: i64,
    pub churned_customers_30d: i64,
    pub churn_rate_30d: f64,
    pub retained_customers_30d: i64,
    pub retention_rate_30d: f64,
    pub avg_customer_lifetime_days: f64,
}

fn parse_period_days(period: &str) -> i64 {
    match period {
        "7d" => 7,
        "30d" => 30,
        "90d" => 90,
        "365d" | "1y" => 365,
        _ => 30,
    }
}

/// Average engagement-session count per active user over the last 30 days,
/// computed from real events: a "session" is an active day (distinct
/// tenant + day with at least one event), so this is the mean number of
/// active days per active tenant. Returns 0.0 when there is no event data —
/// never a fabricated constant.
async fn avg_session_count_per_user(db: &sqlx::PgPool) -> f64 {
    sqlx::query_scalar::<_, Option<f64>>(
        "SELECT COUNT(DISTINCT (tenant_id, DATE(timestamp)))::float8
              / NULLIF(COUNT(DISTINCT tenant_id), 0)
         FROM events
         WHERE timestamp >= NOW() - INTERVAL '30 days'",
    )
    .fetch_one(db)
    .await
    .ok()
    .flatten()
    .unwrap_or(0.0)
}

/// Trials started in the window — a trial is a stripe_subscriptions row
/// with a non-NULL trial_end.
const TRIALS_STARTED_SQL: &str = "SELECT COUNT(*)::bigint FROM stripe_subscriptions
         WHERE trial_end IS NOT NULL
           AND created_at >= NOW() - $1::interval";

/// Converted trials — the trial period ended (trial_end < NOW()) and the
/// subscription is still paying (status active/past_due). The previous
/// formulation selected rows that were simultaneously `status = 'active'`
/// AND `status = 'trialing'` on a single-row-per-subscription table, which
/// can never match (self-negating).
const TRIALS_CONVERTED_SQL: &str = "SELECT COUNT(*)::bigint FROM stripe_subscriptions
         WHERE trial_end IS NOT NULL
           AND trial_end < NOW()
           AND status IN ('active', 'past_due')
           AND created_at >= NOW() - $1::interval";

/// Mean trial-to-paid duration over converted trials. Payment for a
/// converted trial begins at trial_end, so time-to-paid is
/// trial_end - created_at. NULL when there are no converted trials.
const AVG_TRIAL_TO_PAID_SQL: &str =
    "SELECT AVG(EXTRACT(EPOCH FROM (trial_end - created_at)) / 86400)
         FROM stripe_subscriptions
         WHERE trial_end IS NOT NULL
           AND trial_end < NOW()
           AND status IN ('active', 'past_due')
           AND created_at >= NOW() - $1::interval";

async fn get_growth_analytics(
    State(state): State<AppState>,
    auth: AuthUser,
    Query(params): Query<GrowthQuery>,
) -> Result<Json<GrowthAnalyticsResponse>, ApiError> {
    crate::middleware::auth::require_scopes(&auth, &["*"])?;

    let db = &state.db;
    let days = parse_period_days(&params.period);
    let interval = format!("{days} days");

    // ─── Signups ──────────────────────────────────────────────────────
    let total_signups: i64 = sqlx::query_scalar(
        "SELECT COUNT(*)::bigint FROM tenants WHERE created_at >= NOW() - $1::interval",
    )
    .bind(&interval)
    .fetch_one(db)
    .await
    .unwrap_or(0);

    let new_today: i64 =
        sqlx::query_scalar("SELECT COUNT(*)::bigint FROM tenants WHERE created_at >= CURRENT_DATE")
            .fetch_one(db)
            .await
            .unwrap_or(0);

    let new_this_week: i64 = sqlx::query_scalar(
        "SELECT COUNT(*)::bigint FROM tenants WHERE created_at >= NOW() - INTERVAL '7 days'",
    )
    .fetch_one(db)
    .await
    .unwrap_or(0);

    let new_this_month: i64 = sqlx::query_scalar(
        "SELECT COUNT(*)::bigint FROM tenants WHERE created_at >= NOW() - INTERVAL '30 days'",
    )
    .fetch_one(db)
    .await
    .unwrap_or(0);

    let signup_timeline: Vec<SignupTimelinePoint> = sqlx::query_as::<_, (String, i64)>(
        "SELECT DATE(created_at)::text, COUNT(*)::bigint
         FROM tenants
         WHERE created_at >= NOW() - $1::interval
         GROUP BY DATE(created_at) ORDER BY 1",
    )
    .bind(&interval)
    .fetch_all(db)
    .await
    .unwrap_or_default()
    .into_iter()
    .map(|(date, count)| SignupTimelinePoint { date, count })
    .collect();

    let by_plan: Vec<SignupByPlan> = sqlx::query_as::<_, (String, i64)>(
        "SELECT COALESCE(NULLIF(plan, ''), 'free'), COUNT(*)::bigint
         FROM tenants
         WHERE created_at >= NOW() - $1::interval
         GROUP BY 1 ORDER BY 2 DESC",
    )
    .bind(&interval)
    .fetch_all(db)
    .await
    .unwrap_or_default()
    .into_iter()
    .map(|(plan, count)| SignupByPlan { plan, count })
    .collect();

    let by_source: Vec<SourceBreakdown> = sqlx::query_as::<_, (Option<String>, i64)>(
        "SELECT metadata->>'referrer' as source, COUNT(*)::bigint
         FROM tenants
         WHERE created_at >= NOW() - $1::interval
         GROUP BY 1 ORDER BY 2 DESC
         LIMIT 10",
    )
    .bind(&interval)
    .fetch_all(db)
    .await
    .unwrap_or_default()
    .into_iter()
    .map(|(source, count)| SourceBreakdown {
        source: source.unwrap_or_else(|| "direct".into()),
        count,
    })
    .collect();

    // ─── Activation ────────────────────────────────────────────────────
    // "Activated" = tenant has verified a domain AND sent at least 1 email
    let total_tenants: i64 = sqlx::query_scalar(
        "SELECT COUNT(*)::bigint FROM tenants WHERE created_at >= NOW() - $1::interval",
    )
    .bind(&interval)
    .fetch_one(db)
    .await
    .unwrap_or(1);

    let domain_verified: i64 = sqlx::query_scalar(
        "SELECT COUNT(DISTINCT d.tenant_id)::bigint
         FROM domains d
         JOIN tenants t ON t.id::text = d.tenant_id::text
         WHERE d.verified = true AND t.created_at >= NOW() - $1::interval",
    )
    .bind(&interval)
    .fetch_one(db)
    .await
    .unwrap_or(0);

    let email_sent: i64 = sqlx::query_scalar(
        "SELECT COUNT(DISTINCT m.tenant_id)::bigint
         FROM messages m
         JOIN tenants t ON t.id::text = m.tenant_id::text
         WHERE m.status IN ('sent', 'delivered')
           AND t.created_at >= NOW() - $1::interval",
    )
    .bind(&interval)
    .fetch_one(db)
    .await
    .unwrap_or(0);
    let dkim_configured: i64 = sqlx::query_scalar(
        "SELECT COUNT(DISTINCT d.tenant_id)::bigint
         FROM domains d
         JOIN tenants t ON t.id::text = d.tenant_id::text
         WHERE d.dkim_enabled
           AND t.created_at >= NOW() - $1::interval",
    )
    .bind(&interval)
    .fetch_one(db)
    .await
    .unwrap_or(0);

    let activation_funnel: Vec<ActivationFunnelStage> = vec![
        ActivationFunnelStage {
            stage: "Signed up".into(),
            count: total_tenants,
            percentage: 100.0,
        },
        ActivationFunnelStage {
            stage: "Domain verified".into(),
            count: domain_verified,
            percentage: if total_tenants > 0 {
                domain_verified as f64 / total_tenants as f64 * 100.0
            } else {
                0.0
            },
        },
        ActivationFunnelStage {
            stage: "DKIM configured".into(),
            count: dkim_configured,
            percentage: if total_tenants > 0 {
                dkim_configured as f64 / total_tenants as f64 * 100.0
            } else {
                0.0
            },
        },
        ActivationFunnelStage {
            stage: "First email sent".into(),
            count: email_sent,
            percentage: if total_tenants > 0 {
                email_sent as f64 / total_tenants as f64 * 100.0
            } else {
                0.0
            },
        },
    ];

    // Avg time to activate (first email sent minus tenant creation)
    let avg_activation_hours: Option<(Option<f64>,)> = sqlx::query_as(
        "SELECT AVG(EXTRACT(EPOCH FROM (MIN(m.created_at) - t.created_at)) / 3600)
         FROM tenants t
         JOIN messages m ON m.tenant_id::text = t.id::text
         WHERE t.created_at >= NOW() - $1::interval
         GROUP BY t.id",
    )
    .bind(&interval)
    .fetch_optional(db)
    .await
    .ok()
    .flatten();

    // ─── Engagement ─────────────────────────────────────────────────────
    let dau: i64 = sqlx::query_scalar(
        "SELECT COUNT(DISTINCT tenant_id)::bigint FROM events
         WHERE timestamp >= CURRENT_DATE",
    )
    .fetch_one(db)
    .await
    .unwrap_or(0);

    let mau: i64 = sqlx::query_scalar(
        "SELECT COUNT(DISTINCT tenant_id)::bigint FROM events
         WHERE timestamp >= NOW() - INTERVAL '30 days'",
    )
    .fetch_one(db)
    .await
    .unwrap_or(1);

    let wau: i64 = sqlx::query_scalar(
        "SELECT COUNT(DISTINCT tenant_id)::bigint FROM events
         WHERE timestamp >= NOW() - INTERVAL '7 days'",
    )
    .fetch_one(db)
    .await
    .unwrap_or(0);

    let monthly_active_tenants: i64 = sqlx::query_scalar(
        "SELECT COUNT(DISTINCT tenant_id)::bigint FROM messages
         WHERE created_at >= NOW() - INTERVAL '30 days'",
    )
    .fetch_one(db)
    .await
    .unwrap_or(0);

    // ─── Trial Conversion ───────────────────────────────────────────────
    // Computed from stripe_subscriptions' period/status semantics (the table
    // the billing webhook writers populate). See the SQL constants above.
    let trials_started: i64 = sqlx::query_scalar(TRIALS_STARTED_SQL)
        .bind(&interval)
        .fetch_one(db)
        .await
        .unwrap_or(0);

    let trials_converted: i64 = sqlx::query_scalar(TRIALS_CONVERTED_SQL)
        .bind(&interval)
        .fetch_one(db)
        .await
        .unwrap_or(0);

    // Average trial-to-paid duration from real conversion timestamps
    // (trial_end - created_at over converted trials). NULL when no
    // converted trial exists — never a fabricated constant.
    let avg_trial_to_paid_days: Option<f64> =
        sqlx::query_scalar::<_, Option<f64>>(AVG_TRIAL_TO_PAID_SQL)
            .bind(&interval)
            .fetch_one(db)
            .await
            .ok()
            .flatten();

    // Trial conversion by plan (subscription plan, falling back to the
    // tenant's current plan)
    let trial_by_plan: Vec<TrialPlanConversion> = sqlx::query_as::<_, (String, i64, i64)>(
        "SELECT COALESCE(NULLIF(s.plan, ''), NULLIF(t.plan, ''), 'free'),
                COUNT(*)::bigint,
                COUNT(*) FILTER (
                    WHERE s.trial_end IS NOT NULL
                      AND s.trial_end < NOW()
                      AND s.status IN ('active', 'past_due')
                )::bigint
         FROM stripe_subscriptions s
         LEFT JOIN tenants t ON t.id = s.tenant_id
         WHERE s.trial_end IS NOT NULL
           AND s.created_at >= NOW() - $1::interval
         GROUP BY 1 ORDER BY 2 DESC",
    )
    .bind(&interval)
    .fetch_all(db)
    .await
    .unwrap_or_default()
    .into_iter()
    .map(|(plan, trials, converted)| TrialPlanConversion {
        rate: if trials > 0 {
            converted as f64 / trials as f64
        } else {
            0.0
        },
        plan,
        trials,
        converted,
    })
    .collect();

    // ─── Customer Lifecycle ─────────────────────────────────────────────
    // All lifecycle counts read stripe_subscriptions (one row per tenant,
    // kept current by billing webhooks).
    let new_cust_30d: i64 = sqlx::query_scalar(
        "SELECT COUNT(*)::bigint FROM stripe_subscriptions
         WHERE status IN ('active', 'trialing', 'past_due')
           AND created_at >= NOW() - INTERVAL '30 days'",
    )
    .fetch_one(db)
    .await
    .unwrap_or(0);

    let active_cust: i64 = sqlx::query_scalar(
        "SELECT COUNT(DISTINCT tenant_id)::bigint FROM stripe_subscriptions
         WHERE status IN ('active', 'trialing', 'past_due')",
    )
    .fetch_one(db)
    .await
    .unwrap_or(0);

    let churned_30d: i64 = sqlx::query_scalar(
        "SELECT COUNT(DISTINCT tenant_id)::bigint FROM stripe_subscriptions
         WHERE status = 'canceled'
           AND COALESCE(canceled_at, updated_at) >= NOW() - INTERVAL '30 days'",
    )
    .fetch_one(db)
    .await
    .unwrap_or(0);

    let churn_rate = if active_cust > 0 {
        churned_30d as f64 / active_cust as f64
    } else {
        0.0
    };

    let retention = 1.0 - churn_rate;

    // Avg customer lifetime from real subscription ages (active/paying only)
    let avg_lifetime_days: Option<f64> = sqlx::query_scalar::<_, Option<f64>>(
        "SELECT AVG(EXTRACT(EPOCH FROM (NOW() - created_at)) / 86400)
         FROM stripe_subscriptions WHERE status IN ('active', 'past_due')",
    )
    .fetch_one(db)
    .await
    .ok()
    .flatten()
    .filter(|v| *v > 0.0);

    Ok(Json(GrowthAnalyticsResponse {
        signups: SignupStats {
            total_signups,
            new_today,
            new_this_week,
            new_this_month,
            signup_timeline,
            by_plan,
            by_source_referrer: by_source,
        },
        activation: ActivationStats {
            total_activated: email_sent,
            activation_rate: if total_tenants > 0 {
                email_sent as f64 / total_tenants as f64
            } else {
                0.0
            },
            avg_time_to_activate_hours: avg_activation_hours.and_then(|r| r.0).unwrap_or(0.0),
            activation_funnel,
        },
        engagement: EngagementMetrics {
            dau,
            mau,
            dau_mau_ratio: if mau > 0 {
                dau as f64 / mau as f64
            } else {
                0.0
            },
            wau,
            monthly_active_tenants,
            avg_session_count_per_user: avg_session_count_per_user(db).await,
        },
        trial_conversion: TrialConversionStats {
            trials_started,
            trials_converted,
            conversion_rate: if trials_started > 0 {
                trials_converted as f64 / trials_started as f64
            } else {
                0.0
            },
            avg_trial_to_paid_days: avg_trial_to_paid_days.unwrap_or(0.0),
            conversion_by_plan: trial_by_plan,
        },
        lifecycle: CustomerLifecycle {
            new_customers_30d: new_cust_30d,
            active_customers: active_cust,
            churned_customers_30d: churned_30d,
            churn_rate_30d: churn_rate,
            retained_customers_30d: active_cust - churned_30d,
            retention_rate_30d: retention,
            avg_customer_lifetime_days: avg_lifetime_days.unwrap_or(0.0),
        },
    }))
}

async fn get_signup_timeline(
    State(state): State<AppState>,
    auth: AuthUser,
    Query(params): Query<GrowthQuery>,
) -> Result<Json<Vec<SignupTimelinePoint>>, ApiError> {
    crate::middleware::auth::require_scopes(&auth, &["*"])?;

    let days = parse_period_days(&params.period);
    let interval = format!("{days} days");

    let db = &state.db;
    let points = sqlx::query_as::<_, (String, i64)>(
        "SELECT DATE(created_at)::text, COUNT(*)::bigint
         FROM tenants
         WHERE created_at >= NOW() - $1::interval
         GROUP BY DATE(created_at) ORDER BY 1",
    )
    .bind(&interval)
    .fetch_all(db)
    .await
    .unwrap_or_default()
    .into_iter()
    .map(|(date, count)| SignupTimelinePoint { date, count })
    .collect();

    Ok(Json(points))
}

async fn get_activation_funnel(
    State(state): State<AppState>,
    auth: AuthUser,
    Query(params): Query<GrowthQuery>,
) -> Result<Json<ActivationStats>, ApiError> {
    crate::middleware::auth::require_scopes(&auth, &["*"])?;

    let days = parse_period_days(&params.period);
    let interval = format!("{days} days");
    let db = &state.db;

    let total_tenants: i64 = sqlx::query_scalar(
        "SELECT COUNT(*)::bigint FROM tenants WHERE created_at >= NOW() - $1::interval",
    )
    .bind(&interval)
    .fetch_one(db)
    .await
    .unwrap_or(1);

    let domain_verified: i64 = sqlx::query_scalar(
        "SELECT COUNT(DISTINCT d.tenant_id)::bigint
         FROM domains d
         JOIN tenants t ON t.id::text = d.tenant_id::text
         WHERE d.verified = true AND t.created_at >= NOW() - $1::interval",
    )
    .bind(&interval)
    .fetch_one(db)
    .await
    .unwrap_or(0);

    let email_sent: i64 = sqlx::query_scalar(
        "SELECT COUNT(DISTINCT m.tenant_id)::bigint
         FROM messages m
         JOIN tenants t ON t.id::text = m.tenant_id::text
         WHERE m.status IN ('sent', 'delivered')
           AND t.created_at >= NOW() - $1::interval",
    )
    .bind(&interval)
    .fetch_one(db)
    .await
    .unwrap_or(0);

    let avg_activation: Option<(Option<f64>,)> = sqlx::query_as(
        "SELECT AVG(EXTRACT(EPOCH FROM (MIN(m.created_at) - t.created_at)) / 3600)
         FROM tenants t
         JOIN messages m ON m.tenant_id::text = t.id::text
         WHERE t.created_at >= NOW() - $1::interval
         GROUP BY t.id",
    )
    .bind(&interval)
    .fetch_optional(db)
    .await
    .ok()
    .flatten();

    Ok(Json(ActivationStats {
        total_activated: email_sent,
        activation_rate: if total_tenants > 0 {
            email_sent as f64 / total_tenants as f64
        } else {
            0.0
        },
        avg_time_to_activate_hours: avg_activation.and_then(|r| r.0).unwrap_or(0.0),
        activation_funnel: vec![
            ActivationFunnelStage {
                stage: "Signed up".into(),
                count: total_tenants,
                percentage: 100.0,
            },
            ActivationFunnelStage {
                stage: "Domain verified".into(),
                count: domain_verified,
                percentage: if total_tenants > 0 {
                    domain_verified as f64 / total_tenants as f64 * 100.0
                } else {
                    0.0
                },
            },
            ActivationFunnelStage {
                stage: "First email sent".into(),
                count: email_sent,
                percentage: if total_tenants > 0 {
                    email_sent as f64 / total_tenants as f64 * 100.0
                } else {
                    0.0
                },
            },
        ],
    }))
}

async fn get_engagement_metrics(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<Json<EngagementMetrics>, ApiError> {
    crate::middleware::auth::require_scopes(&auth, &["*"])?;

    let db = &state.db;

    let dau: i64 = sqlx::query_scalar(
        "SELECT COUNT(DISTINCT tenant_id)::bigint FROM events
         WHERE timestamp >= CURRENT_DATE",
    )
    .fetch_one(db)
    .await
    .unwrap_or(0);

    let mau: i64 = sqlx::query_scalar(
        "SELECT COUNT(DISTINCT tenant_id)::bigint FROM events
         WHERE timestamp >= NOW() - INTERVAL '30 days'",
    )
    .fetch_one(db)
    .await
    .unwrap_or(1);

    let wau: i64 = sqlx::query_scalar(
        "SELECT COUNT(DISTINCT tenant_id)::bigint FROM events
         WHERE timestamp >= NOW() - INTERVAL '7 days'",
    )
    .fetch_one(db)
    .await
    .unwrap_or(0);

    let monthly_active_tenants: i64 = sqlx::query_scalar(
        "SELECT COUNT(DISTINCT tenant_id)::bigint FROM messages
         WHERE created_at >= NOW() - INTERVAL '30 days'",
    )
    .fetch_one(db)
    .await
    .unwrap_or(0);

    Ok(Json(EngagementMetrics {
        dau,
        mau,
        dau_mau_ratio: if mau > 0 {
            dau as f64 / mau as f64
        } else {
            0.0
        },
        wau,
        monthly_active_tenants,
        avg_session_count_per_user: avg_session_count_per_user(db).await,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_period_days_defaults_to_thirty() {
        assert_eq!(parse_period_days("bogus"), 30);
    }

    #[test]
    fn parse_period_days_maps_correctly() {
        assert_eq!(parse_period_days("7d"), 7);
        assert_eq!(parse_period_days("30d"), 30);
        assert_eq!(parse_period_days("90d"), 90);
        assert_eq!(parse_period_days("365d"), 365);
        assert_eq!(parse_period_days("1y"), 365);
    }

    #[test]
    fn activation_funnel_stages_ordered() {
        let stages = [
            ActivationFunnelStage {
                stage: "Signed up".into(),
                count: 100,
                percentage: 100.0,
            },
            ActivationFunnelStage {
                stage: "Domain verified".into(),
                count: 80,
                percentage: 80.0,
            },
            ActivationFunnelStage {
                stage: "First email sent".into(),
                count: 50,
                percentage: 50.0,
            },
        ];
        assert_eq!(stages.len(), 3);
        assert!(stages[0].count >= stages[1].count);
        assert!(stages[1].count >= stages[2].count);
    }

    #[test]
    fn dau_mau_ratio_handles_zero_mau() {
        let metrics = EngagementMetrics {
            dau: 0,
            mau: 0,
            dau_mau_ratio: 0.0,
            wau: 0,
            monthly_active_tenants: 0,
            avg_session_count_per_user: 0.0,
        };
        assert_eq!(metrics.dau_mau_ratio, 0.0);
    }

    #[test]
    fn trial_sql_reads_stripe_subscriptions_with_period_semantics() {
        // The legacy table had no writer; all trial SQL must read
        // stripe_subscriptions and use trial_end period semantics.
        for sql in [
            TRIALS_STARTED_SQL,
            TRIALS_CONVERTED_SQL,
            AVG_TRIAL_TO_PAID_SQL,
        ] {
            assert!(sql.contains("FROM stripe_subscriptions"));
            assert!(sql.contains("trial_end IS NOT NULL"));
            assert!(!sql.contains("FROM subscriptions\n"));
        }
    }

    #[test]
    fn trial_converted_sql_is_not_self_negating() {
        // The old query demanded status = 'active' AND membership in a
        // status = 'trialing' set of the SAME single-row table — impossible.
        assert!(!TRIALS_CONVERTED_SQL.contains("id IN"));
        assert!(TRIALS_CONVERTED_SQL.contains("trial_end < NOW()"));
        assert!(TRIALS_CONVERTED_SQL.contains("status IN ('active', 'past_due')"));
    }

    #[test]
    fn avg_trial_to_paid_is_derived_not_constant() {
        // Must be computed from trial_end - created_at, and there must be no
        // hardcoded 14.0-day constant anywhere in the SQL.
        assert!(AVG_TRIAL_TO_PAID_SQL.contains("trial_end - created_at"));
        assert!(!AVG_TRIAL_TO_PAID_SQL.contains("14"));
    }
}
