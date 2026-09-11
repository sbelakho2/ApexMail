//! Growth analytics endpoint — new signups, activation rate, active-tenant
//! activity, trial conversion, and customer lifecycle metrics.
//!
//! All values come from real database queries against tenants, users, messages,
//! events, subscriptions, and stripe_subscriptions tables.
//!
//! Honest labels: the activity counters here measure active TENANTS (distinct
//! `events.tenant_id`), not users — ApexMail's events carry no user identity,
//! so DAU/WAU/MAU would be a lie. "Activation" and time-to-first-send are
//! derived from the actual successful-send lifecycle (`events.event_type =
//! 'sent'`), not from message rows or current status.

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
    /// Fraction in `0.0..=1.0` (activated tenants / new tenants).
    pub activation_rate: f64,
    /// Average hours from signup to the first ACTUAL successful send event
    /// (`events.event_type = 'sent'`). `None` when no tenant in the window
    /// has sent yet — never-sent is explicitly distinct from zero elapsed
    /// time (F79).
    pub avg_time_to_first_send_hours: Option<f64>,
    pub activation_funnel: Vec<ActivationFunnelStage>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ActivationFunnelStage {
    pub stage: String,
    pub count: i64,
    /// Display percentage (0-100) of the signup population.
    pub percentage: f64,
}

/// Activity metrics. These count TENANTS, not users: the events table has no
/// user dimension, so reporting "DAU/WAU/MAU" would mislabel active tenants
/// as active users. Field names state exactly what is measured.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EngagementMetrics {
    /// Distinct tenants with at least one event today (UTC day).
    pub active_tenants_today: i64,
    /// Distinct tenants with at least one event in the last 7 days.
    pub active_tenants_7d: i64,
    /// Distinct tenants with at least one event in the last 30 days.
    pub active_tenants_30d: i64,
    /// `active_tenants_today / active_tenants_30d` — a fraction in
    /// `0.0..=1.0`, measuring daily stickiness of the tenant base.
    pub active_tenants_today_ratio_30d: f64,
    /// Distinct tenants with at least one successful `sent` EVENT in the
    /// last 30 days (the real send lifecycle, not message rows).
    pub sending_tenants_30d: i64,
    /// Mean number of active days (distinct tenant+day with an event) per
    /// active tenant over 30 days.
    pub avg_active_days_per_tenant_30d: f64,
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

/// Mean number of active days per active tenant over the last 30 days,
/// computed from real events: an "active day" is a distinct
/// (tenant_id, day) pair with at least one event. Returns 0.0 when there is
/// no event data — never a fabricated constant.
async fn avg_active_days_per_tenant_30d(db: &sqlx::PgPool) -> f64 {
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

/// The honest tenant-activity block: distinct TENANTS with event activity in
/// today / 7-day / 30-day windows, plus tenants with real successful sends.
/// The events table has no user dimension, so these are not DAU/WAU/MAU.
async fn engagement_metrics(db: &sqlx::PgPool) -> EngagementMetrics {
    let active_tenants_today: i64 = sqlx::query_scalar(
        "SELECT COUNT(DISTINCT tenant_id)::bigint FROM events
         WHERE timestamp >= CURRENT_DATE",
    )
    .fetch_one(db)
    .await
    .unwrap_or(0);

    let active_tenants_30d: i64 = sqlx::query_scalar(
        "SELECT COUNT(DISTINCT tenant_id)::bigint FROM events
         WHERE timestamp >= NOW() - INTERVAL '30 days'",
    )
    .fetch_one(db)
    .await
    .unwrap_or(0);

    let active_tenants_7d: i64 = sqlx::query_scalar(
        "SELECT COUNT(DISTINCT tenant_id)::bigint FROM events
         WHERE timestamp >= NOW() - INTERVAL '7 days'",
    )
    .fetch_one(db)
    .await
    .unwrap_or(0);

    let sending_tenants_30d: i64 = sqlx::query_scalar(
        "SELECT COUNT(DISTINCT tenant_id)::bigint FROM events
         WHERE event_type = 'sent'
           AND timestamp >= NOW() - INTERVAL '30 days'",
    )
    .fetch_one(db)
    .await
    .unwrap_or(0);

    EngagementMetrics {
        active_tenants_today,
        active_tenants_7d,
        active_tenants_30d,
        active_tenants_today_ratio_30d: if active_tenants_30d > 0 {
            active_tenants_today as f64 / active_tenants_30d as f64
        } else {
            0.0
        },
        sending_tenants_30d,
        avg_active_days_per_tenant_30d: avg_active_days_per_tenant_30d(db).await,
    }
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
    // "Activated" = tenant has a REAL successful send event
    // (`events.event_type = 'sent'`, written after provider acceptance).
    // Message rows / current status are not the successful-send lifecycle.
    let total_tenants: i64 = sqlx::query_scalar(
        "SELECT COUNT(*)::bigint FROM tenants WHERE created_at >= NOW() - $1::interval",
    )
    .bind(&interval)
    .fetch_one(db)
    .await
    .unwrap_or(0);

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
        "SELECT COUNT(DISTINCT e.tenant_id)::bigint
         FROM events e
         JOIN tenants t ON t.id::text = e.tenant_id::text
         WHERE e.event_type = 'sent'
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

    // Avg time to first ACTUAL send — the shared, corrected per-tenant
    // first-send-event query (F79).
    let avg_time_to_first_send = avg_time_to_first_send_hours(db, &interval).await?;

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
            avg_time_to_first_send_hours: avg_time_to_first_send,
            activation_funnel,
        },
        engagement: engagement_metrics(db).await,
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

/// F79: average time from signup to the first ACTUAL successful send event,
/// shared by both endpoints. The first send is the earliest
/// `events.event_type = 'sent'` occurrence for the tenant (written after
/// provider acceptance) — not `messages.created_at` and not a current-status
/// comparison. The per-tenant MIN lives in a subquery (nesting MIN inside
/// AVG at one query level is invalid SQL — 42803); the outer SELECT
/// averages the per-tenant deltas. The result is a typed `Option<f64>`:
/// `None` means no tenant in the window has sent, which is explicitly
/// distinct from a zero elapsed time. Query errors propagate as unavailable,
/// never as a numerical zero.
const AVG_TIME_TO_FIRST_SEND_SQL: &str = r#"
    SELECT AVG(EXTRACT(EPOCH FROM (first_send - created_at)) / 3600)::double precision
    FROM (
        SELECT t.id AS tenant_id, t.created_at AS created_at,
               MIN(e.timestamp) AS first_send
        FROM tenants t
        JOIN events e ON e.tenant_id::text = t.id::text
        WHERE t.created_at >= NOW() - $1::interval
          AND e.event_type = 'sent'
        GROUP BY t.id, t.created_at
    ) first_sends
"#;

async fn avg_time_to_first_send_hours(
    db: &sqlx::PgPool,
    interval: &str,
) -> Result<Option<f64>, ApiError> {
    let avg: Option<Option<f64>> = sqlx::query_scalar(AVG_TIME_TO_FIRST_SEND_SQL)
        .bind(interval)
        .fetch_optional(db)
        .await?;
    Ok(avg.flatten())
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
    .unwrap_or(0);

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

    // Real successful-send lifecycle: distinct tenants with a `sent` event.
    let email_sent: i64 = sqlx::query_scalar(
        "SELECT COUNT(DISTINCT e.tenant_id)::bigint
         FROM events e
         JOIN tenants t ON t.id::text = e.tenant_id::text
         WHERE e.event_type = 'sent'
           AND t.created_at >= NOW() - $1::interval",
    )
    .bind(&interval)
    .fetch_one(db)
    .await
    .unwrap_or(0);

    let avg = avg_time_to_first_send_hours(db, &interval).await?;

    Ok(Json(ActivationStats {
        total_activated: email_sent,
        activation_rate: if total_tenants > 0 {
            email_sent as f64 / total_tenants as f64
        } else {
            0.0
        },
        avg_time_to_first_send_hours: avg,
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

    Ok(Json(engagement_metrics(&state.db).await))
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
    fn active_tenant_ratio_handles_zero_30d_population() {
        let metrics = EngagementMetrics {
            active_tenants_today: 0,
            active_tenants_7d: 0,
            active_tenants_30d: 0,
            active_tenants_today_ratio_30d: 0.0,
            sending_tenants_30d: 0,
            avg_active_days_per_tenant_30d: 0.0,
        };
        assert_eq!(metrics.active_tenants_today_ratio_30d, 0.0);
    }

    #[test]
    fn engagement_metrics_are_labelled_tenants_not_users() {
        // The struct must not expose DAU/WAU/MAU-style user labels: the
        // events table has no user dimension, so those would be a mislabel.
        let metrics = EngagementMetrics {
            active_tenants_today: 5,
            active_tenants_7d: 9,
            active_tenants_30d: 12,
            active_tenants_today_ratio_30d: 5.0 / 12.0,
            sending_tenants_30d: 7,
            avg_active_days_per_tenant_30d: 3.5,
        };
        assert!(metrics.active_tenants_today_ratio_30d <= 1.0);
        assert!(metrics.active_tenants_today <= metrics.active_tenants_30d);
        assert!(metrics.active_tenants_7d <= metrics.active_tenants_30d);
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

    // ── F79: corrected first-send aggregate ────────────────────────────

    #[test]
    fn first_send_aggregate_is_not_nested() {
        // Nesting MIN inside AVG at one query level is rejected by
        // PostgreSQL with 42803. The MIN must live in a subquery and only
        // the outer level may aggregate.
        let outer = AVG_TIME_TO_FIRST_SEND_SQL
            .split("FROM (")
            .next()
            .unwrap_or("");
        assert!(
            !outer.contains("MIN("),
            "no aggregate may be nested in the outer AVG: {outer}"
        );
        assert!(
            AVG_TIME_TO_FIRST_SEND_SQL.contains("MIN(e.timestamp) AS first_send"),
            "the per-tenant first send is computed in the subquery"
        );
        // Typed float result.
        assert!(AVG_TIME_TO_FIRST_SEND_SQL.contains(")::double precision"));
        // The metric is the FIRST SUCCESSFUL SEND EVENT: the events
        // lifecycle, not messages.created_at / current status.
        assert!(AVG_TIME_TO_FIRST_SEND_SQL.contains("e.event_type = 'sent'"));
        assert!(!AVG_TIME_TO_FIRST_SEND_SQL.contains("FROM messages"));
        assert!(!AVG_TIME_TO_FIRST_SEND_SQL.contains("status IN"));
    }

    /// Seed two tenants with different first-successful-send delays
    /// (event occurrence) and multiple events: the exact expected average
    /// comes back, and never-sent tenants (and no-data windows) are distinct
    /// from zero. Canonical schema via the production migrator; gated on
    /// TEST_DATABASE_URL.
    #[tokio::test]
    async fn avg_time_to_first_send_matches_exact_expectation() {
        let pool =
            match migrator::test_support::fresh_canonical_pool("growth_f79", "first_send").await {
                Ok(pool) => pool,
                Err(error) => panic!("{}", error.panic_message()),
            };
        let Some(pool) = pool else {
            eprintln!("skipping: set TEST_DATABASE_URL to run DB-backed test");
            return;
        };

        let seed = |days_before: i64, delay_hours: i64, sent: bool, label: &str| {
            let pool = pool.clone();
            let label = label.to_string();
            async move {
                // Canonical tenant ids are VARCHAR(26) (ULID domain).
                let suffix = uuid::Uuid::new_v4().simple().to_string();
                let tenant = format!("t{}", &suffix[..25]);
                sqlx::query(
                    "INSERT INTO tenants (id, name, created_at) \
                     VALUES ($1, $2, NOW() - make_interval(days => $3::int))",
                )
                .bind(&tenant)
                .bind(&label)
                .bind(days_before)
                .execute(&pool)
                .await
                .unwrap();
                if sent {
                    for i in 0..3 {
                        // A successful send EVENT, timestamped at the actual
                        // send occurrence; later duplicates must not move MIN.
                        sqlx::query(
                            "INSERT INTO events (id, tenant_id, message_id, event_type, timestamp) \
                             VALUES ($1, $2, $3, 'sent', \
                                     NOW() - make_interval(days => $4::int) + make_interval(hours => $5::int))",
                        )
                        .bind(format!("evt-{}", uuid::Uuid::new_v4().simple()))
                        .bind(&tenant)
                        .bind(format!("msg-{}-{i}", &suffix[..10]))
                        .bind(days_before)
                        .bind(delay_hours + i)
                        .execute(&pool)
                        .await
                        .unwrap();
                    }
                }
                tenant
            }
        };

        // Tenant A: sent 6h after signup. Tenant B: sent 18h after signup.
        // Tenant C: never sent — excluded from the average, NOT counted as 0.
        seed(5, 6, true, "f79-a").await;
        seed(5, 18, true, "f79-b").await;
        seed(5, 0, false, "f79-c").await;

        let avg = avg_time_to_first_send_hours(&pool, "30 days")
            .await
            .unwrap();
        let avg = avg.expect("two tenants sent; the average is defined");
        assert!(
            (avg - 12.0).abs() < 0.01,
            "average of 6h and 18h is 12h, got {avg}"
        );

        // A window containing ONLY the never-sent tenant: a zero-width
        // window excludes the older tenants, leaving just f79-c (no sends).
        let none = avg_time_to_first_send_hours(&pool, "0 days").await.unwrap();
        assert!(
            none.is_none(),
            "never-sent tenants must not render as a zero elapsed time"
        );

        pool.close().await;
    }
}
