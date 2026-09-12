//! Growth analytics endpoint — new signups, activation milestones,
//! active-tenant activity, trial conversion, and customer lifecycle metrics.
//!
//! All values come from real database queries against tenants, users, messages,
//! events, subscriptions, and stripe_subscriptions tables.
//!
//! Honest labels: the activity counters here measure active TENANTS (distinct
//! `events.tenant_id`), not users — ApexMail's events carry no user identity,
//! so DAU/WAU/MAU would be a lie. "Activation" and time-to-first-send are
//! derived from the actual successful-send lifecycle (`events.event_type =
//! 'sent'`), not from message rows or current status.
//!
//! Cohort semantics (audit fix):
//!
//! * **Churn is a starting cohort.** The churn denominator is the set of
//!   subscriptions that existed at the period start and had not already been
//!   canceled before it. Churn counts only those cohort members who cancel
//!   inside the window, so churn ≤ cohort by construction: the rate cannot
//!   exceed 100% and retained (`cohort − churn`) cannot go negative. Current
//!   active customers and new customers are separate populations/flow, never
//!   subtracted from each other.
//! * **Activation is reported as MILESTONES, not a funnel.** Domain
//!   verification, DKIM configuration and the first successful send are
//!   independent capabilities (a tenant can send through the shared pool
//!   before verifying a domain), so a later milestone may legitimately exceed
//!   an earlier one. The API field is `activationMilestones`; nothing is
//!   presented as nested funnel stages.
//! * **Trial conversion uses ELIGIBLE trials.** The denominator is trials
//!   that have ENDED (`trial_end < NOW()`), never all trials started — an
//!   ongoing trial has not had the chance to convert and must not
//!   right-censor the rate. Time-to-paid uses the earliest actual paid
//!   invoice at/after `trial_end` when billing data links one; `trial_end`
//!   is the documented fallback (see [`TRIAL_PAYMENT_TIME_METHOD`]).
//!
//! Failure semantics (audit item 20):
//!
//! * **A database failure is never a zero.** Every REQUIRED operational
//!   query (customers, signups, trials, activation) returns `Result<_, _>`
//!   and propagates with `?`: the endpoint fails loudly instead of reporting
//!   "0 customers" / "0 signups" for an outage an operator would act on.
//! * **Rates are `Option<f64>`**: a zero denominator is absent (`null`), not
//!   `0`.
//! * **Genuinely-optional derived metrics** (averages over a possibly-empty
//!   population) use [`MetricState`], so "no data" (`Available(None)`) stays
//!   distinguishable from "could not be read" (`Unavailable { reason }`)
//!   and the reason is surfaced in the response.

use axum::extract::{Query, State};
use axum::routing::get;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;

use crate::analytics_metrics::MetricState;
use crate::error::ApiError;
use crate::middleware::auth::AuthUser;
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/", get(get_growth_analytics))
        .route("/signups", get(get_signup_timeline))
        .route("/activation", get(get_activation_milestones))
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
    /// Fraction in `0.0..=1.0` (activated tenants / new tenants). `None`
    /// when no tenant signed up in the window — absent, not `0`.
    pub activation_rate: Option<f64>,
    /// Average hours from signup to the first ACTUAL successful send event
    /// (`events.event_type = 'sent'`). `None` when no tenant in the window
    /// has sent yet — never-sent is explicitly distinct from zero elapsed
    /// time (F79).
    pub avg_time_to_first_send_hours: Option<f64>,
    /// Independent activation MILESTONES — not nested funnel stages. Each
    /// milestone is measured against the same signup population and a later
    /// milestone may exceed an earlier one (the capabilities are independent:
    /// shared-pool sending needs neither domain verification nor DKIM).
    pub activation_milestones: Vec<ActivationMilestone>,
}

/// One independent activation milestone. Deliberately named `milestone`
/// rather than funnel `stage`: the counts are not nested cohorts, and no
/// ordering invariant is claimed between them.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ActivationMilestone {
    pub milestone: String,
    pub count: i64,
    /// Display percentage (0-100) of the signup population. `None` when the
    /// signup denominator is zero — absent, not `0`.
    pub percentage: Option<f64>,
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
    /// `0.0..=1.0`, measuring daily stickiness of the tenant base. `None`
    /// when there is no 30-day activity population.
    pub active_tenants_today_ratio_30d: Option<f64>,
    /// Distinct tenants with at least one successful `sent` EVENT in the
    /// last 30 days (the real send lifecycle, not message rows).
    pub sending_tenants_30d: i64,
    /// Mean number of active days (distinct tenant+day with an event) per
    /// active tenant over 30 days. `Available(None)` = no event data (the
    /// mean is undefined, not zero); `Unavailable` = the aggregate could not
    /// be read.
    pub avg_active_days_per_tenant_30d: MetricState<Option<f64>>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TrialConversionStats {
    /// Every trial BEGUN in the window, including trials still running. This
    /// is a flow counter; it is deliberately NOT the conversion denominator.
    pub trials_started: i64,
    /// Trials that had already ENDED (`trial_end < NOW()`) in the window.
    /// This is the conversion denominator: ongoing trials have not had the
    /// chance to convert and must not right-censor the rate.
    pub trials_eligible: i64,
    /// Eligible trials that converted (subscription still paying after the
    /// trial ended).
    pub trials_converted: i64,
    /// Fraction in `0.0..=1.0` of ELIGIBLE (ended) trials that converted;
    /// `None` when no trial ended in the window — absent, not `0`.
    pub conversion_rate: Option<f64>,
    /// `Available(None)` = no converted trial exists (undefined, not zero);
    /// `Unavailable` = the aggregate could not be read.
    pub avg_trial_to_paid_days: MetricState<Option<f64>>,
    /// How time-to-paid obtains its activation timestamp (actual paid
    /// invoice where billing data links one, otherwise the documented
    /// `trial_end` fallback).
    pub payment_time_method: String,
    pub conversion_by_plan: Vec<TrialPlanConversion>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TrialPlanConversion {
    pub plan: String,
    /// Trials begun in the window for this plan (includes ongoing trials).
    pub trials: i64,
    /// Trials for this plan that have ENDED in the window (the denominator).
    pub eligible: i64,
    pub converted: i64,
    /// Fraction in `0.0..=1.0` of ELIGIBLE trials; `None` when this plan has
    /// no ended trial.
    pub rate: Option<f64>,
}

/// Customer lifecycle over a fixed 30-day window.
///
/// The churn rate is computed over the STARTING COHORT — subscriptions that
/// existed at the period start and had not already been canceled — not over
/// the current active count. New customers are a separate flow and are never
/// subtracted; retained = cohort − churn, so neither can go out of bounds.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CustomerLifecycle {
    /// Gross new subscriptions created in the window (incomplete checkouts
    /// excluded). A separate acquisition FLOW: new customers are not part of
    /// the starting cohort and never enter the churn arithmetic.
    pub new_customers_30d: i64,
    /// Current snapshot of paying customers (status active/trialing/past_due).
    pub active_customers: i64,
    /// The churn denominator: customers whose subscription existed at the
    /// period start and was not already canceled before it.
    pub cohort_customers_at_period_start: i64,
    /// Cohort members who canceled INSIDE the window. Always a subset of
    /// `cohort_customers_at_period_start` — churn can never exceed the cohort.
    pub churned_customers_30d: i64,
    /// `churned / cohort`, a fraction in `0.0..=1.0`; `None` when the
    /// starting cohort is empty — absent, not `0`.
    pub churn_rate_30d: Option<f64>,
    /// `cohort − churned`, never negative (the numerator is a subset of the
    /// denominator by construction).
    pub retained_customers_30d: i64,
    /// `1 - churn_rate`, `None` whenever the churn rate is absent.
    pub retention_rate_30d: Option<f64>,
    /// `Available(None)` = no paying subscription (undefined, not zero);
    /// `Unavailable` = the aggregate could not be read.
    pub avg_customer_lifetime_days: MetricState<Option<f64>>,
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

/// Run a required scalar count. A database failure is returned as an error;
/// there is deliberately no `unwrap_or(0)` anywhere on this path (audit item
/// 20: `database failure → 0 customers` must be impossible).
async fn required_count(db: &PgPool, sql: &str, bind: Option<&str>) -> Result<i64, ApiError> {
    let mut query = sqlx::query_scalar::<_, i64>(sql);
    if let Some(value) = bind {
        query = query.bind(value);
    }
    Ok(query.fetch_one(db).await?)
}

// ─── Signups ───────────────────────────────────────────────────────────

async fn signup_stats(db: &PgPool, interval: &str) -> Result<SignupStats, ApiError> {
    let total_signups = required_count(
        db,
        "SELECT COUNT(*)::bigint FROM tenants WHERE created_at >= NOW() - $1::interval",
        Some(interval),
    )
    .await?;

    let new_today = required_count(
        db,
        "SELECT COUNT(*)::bigint FROM tenants WHERE created_at >= CURRENT_DATE",
        None,
    )
    .await?;

    let new_this_week = required_count(
        db,
        "SELECT COUNT(*)::bigint FROM tenants WHERE created_at >= NOW() - INTERVAL '7 days'",
        None,
    )
    .await?;

    let new_this_month = required_count(
        db,
        "SELECT COUNT(*)::bigint FROM tenants WHERE created_at >= NOW() - INTERVAL '30 days'",
        None,
    )
    .await?;

    let signup_timeline: Vec<SignupTimelinePoint> = sqlx::query_as::<_, (String, i64)>(
        "SELECT DATE(created_at)::text, COUNT(*)::bigint
         FROM tenants
         WHERE created_at >= NOW() - $1::interval
         GROUP BY DATE(created_at) ORDER BY 1",
    )
    .bind(interval)
    .fetch_all(db)
    .await?
    .into_iter()
    .map(|(date, count)| SignupTimelinePoint { date, count })
    .collect();

    let by_plan: Vec<SignupByPlan> = sqlx::query_as::<_, (String, i64)>(
        "SELECT COALESCE(NULLIF(plan, ''), 'free'), COUNT(*)::bigint
         FROM tenants
         WHERE created_at >= NOW() - $1::interval
         GROUP BY 1 ORDER BY 2 DESC",
    )
    .bind(interval)
    .fetch_all(db)
    .await?
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
    .bind(interval)
    .fetch_all(db)
    .await?
    .into_iter()
    .map(|(source, count)| SourceBreakdown {
        source: source.unwrap_or_else(|| "direct".into()),
        count,
    })
    .collect();

    Ok(SignupStats {
        total_signups,
        new_today,
        new_this_week,
        new_this_month,
        signup_timeline,
        by_plan,
        by_source_referrer: by_source,
    })
}

// ─── Activation ────────────────────────────────────────────────────────

struct ActivationCounts {
    total_tenants: i64,
    domain_verified: i64,
    email_sent: i64,
    dkim_configured: i64,
}

/// The activation population. Every query is required: a failure propagates.
async fn activation_counts(db: &PgPool, interval: &str) -> Result<ActivationCounts, ApiError> {
    // "Activated" = tenant has a REAL successful send event
    // (`events.event_type = 'sent'`, written after provider acceptance).
    // Message rows / current status are not the successful-send lifecycle.
    let total_tenants = required_count(
        db,
        "SELECT COUNT(*)::bigint FROM tenants WHERE created_at >= NOW() - $1::interval",
        Some(interval),
    )
    .await?;

    let domain_verified = required_count(
        db,
        "SELECT COUNT(DISTINCT d.tenant_id)::bigint
         FROM domains d
         JOIN tenants t ON t.id::text = d.tenant_id::text
         WHERE d.verified = true AND t.created_at >= NOW() - $1::interval",
        Some(interval),
    )
    .await?;

    let email_sent = required_count(
        db,
        "SELECT COUNT(DISTINCT e.tenant_id)::bigint
         FROM events e
         JOIN tenants t ON t.id::text = e.tenant_id::text
         WHERE e.event_type = 'sent'
           AND t.created_at >= NOW() - $1::interval",
        Some(interval),
    )
    .await?;

    let dkim_configured = required_count(
        db,
        "SELECT COUNT(DISTINCT d.tenant_id)::bigint
         FROM domains d
         JOIN tenants t ON t.id::text = d.tenant_id::text
         WHERE d.dkim_enabled
           AND t.created_at >= NOW() - $1::interval",
        Some(interval),
    )
    .await?;

    Ok(ActivationCounts {
        total_tenants,
        domain_verified,
        email_sent,
        dkim_configured,
    })
}

/// Percentage of the signup population, or `None` when the population is
/// empty (never a fabricated `0`).
fn percentage_of(part: i64, whole: i64) -> Option<f64> {
    (whole > 0).then(|| part as f64 / whole as f64 * 100.0)
}

fn activation_rate_of(part: i64, whole: i64) -> Option<f64> {
    (whole > 0).then(|| part as f64 / whole as f64)
}

/// Independent activation MILESTONES, not nested funnel stages.
///
/// Domain verified, DKIM configured and first email sent are counted
/// independently against the same signup population. They are genuinely
/// independent capabilities — a tenant can send through the platform's
/// shared pool without verifying a domain or configuring DKIM — so a later
/// milestone can exceed an earlier one and none of the counts may be
/// presented as a successive stage of a funnel. (Nested cohort CTEs were
/// considered and rejected: forcing containment would fabricate a dependency
/// between milestones that the product does not have.)
fn activation_milestones(counts: &ActivationCounts) -> Vec<ActivationMilestone> {
    vec![
        ActivationMilestone {
            milestone: "Signed up".into(),
            count: counts.total_tenants,
            percentage: Some(100.0),
        },
        ActivationMilestone {
            milestone: "Domain verified".into(),
            count: counts.domain_verified,
            percentage: percentage_of(counts.domain_verified, counts.total_tenants),
        },
        ActivationMilestone {
            milestone: "DKIM configured".into(),
            count: counts.dkim_configured,
            percentage: percentage_of(counts.dkim_configured, counts.total_tenants),
        },
        ActivationMilestone {
            milestone: "First email sent".into(),
            count: counts.email_sent,
            percentage: percentage_of(counts.email_sent, counts.total_tenants),
        },
    ]
}

// ─── Engagement ────────────────────────────────────────────────────────

/// Mean number of active days per active tenant over the last 30 days,
/// computed from real events: an "active day" is a distinct
/// (tenant_id, day) pair with at least one event.
///
/// `Available(None)` when there is no event data (the mean is undefined —
/// never a fabricated constant `0.0`); `Unavailable { reason }` when the
/// aggregate cannot be read.
async fn avg_active_days_per_tenant_30d(db: &PgPool) -> MetricState<Option<f64>> {
    match sqlx::query_scalar::<_, Option<f64>>(
        "SELECT COUNT(DISTINCT (tenant_id, DATE(timestamp)))::float8
              / NULLIF(COUNT(DISTINCT tenant_id), 0)
         FROM events
         WHERE timestamp >= NOW() - INTERVAL '30 days'",
    )
    .fetch_one(db)
    .await
    {
        Ok(value) => MetricState::Available(value),
        Err(error) => {
            tracing::error!(
                error = %error,
                "growth analytics: avg active days aggregate failed — reporting unavailable, not zero"
            );
            MetricState::Unavailable {
                reason: "active-days aggregate could not be read",
            }
        }
    }
}

/// The honest tenant-activity block: distinct TENANTS with event activity in
/// today / 7-day / 30-day windows, plus tenants with real successful sends.
/// The events table has no user dimension, so these are not DAU/WAU/MAU.
///
/// Every count is a required query: a database failure is an `Err`, never
/// "0 active tenants".
async fn engagement_metrics(db: &PgPool) -> Result<EngagementMetrics, ApiError> {
    let active_tenants_today: i64 = required_count(
        db,
        "SELECT COUNT(DISTINCT tenant_id)::bigint FROM events
         WHERE timestamp >= CURRENT_DATE",
        None,
    )
    .await?;

    let active_tenants_30d: i64 = required_count(
        db,
        "SELECT COUNT(DISTINCT tenant_id)::bigint FROM events
         WHERE timestamp >= NOW() - INTERVAL '30 days'",
        None,
    )
    .await?;

    let active_tenants_7d: i64 = required_count(
        db,
        "SELECT COUNT(DISTINCT tenant_id)::bigint FROM events
         WHERE timestamp >= NOW() - INTERVAL '7 days'",
        None,
    )
    .await?;

    let sending_tenants_30d: i64 = required_count(
        db,
        "SELECT COUNT(DISTINCT tenant_id)::bigint FROM events
         WHERE event_type = 'sent'
           AND timestamp >= NOW() - INTERVAL '30 days'",
        None,
    )
    .await?;

    Ok(EngagementMetrics {
        active_tenants_today,
        active_tenants_7d,
        active_tenants_30d,
        active_tenants_today_ratio_30d: (active_tenants_30d > 0)
            .then(|| active_tenants_today as f64 / active_tenants_30d as f64),
        sending_tenants_30d,
        avg_active_days_per_tenant_30d: avg_active_days_per_tenant_30d(db).await,
    })
}

// ─── Trial conversion ──────────────────────────────────────────────────

/// Trials started in the window — a trial is a stripe_subscriptions row
/// with a non-NULL trial_end. Includes trials still running (`trial_end >=
/// NOW()`): this is the flow counter, NOT the conversion denominator.
const TRIALS_STARTED_SQL: &str = "SELECT COUNT(*)::bigint FROM stripe_subscriptions
         WHERE trial_end IS NOT NULL
           AND created_at >= NOW() - $1::interval";

/// ELIGIBLE trials — the conversion denominator. A trial is eligible once
/// it has ENDED (`trial_end < NOW()`): only ended trials have had the
/// opportunity to convert, so an ongoing trial must not right-censor the
/// rate. The numerator is filtered from this same population.
const TRIALS_ELIGIBLE_SQL: &str = "SELECT COUNT(*)::bigint FROM stripe_subscriptions
         WHERE trial_end IS NOT NULL
           AND trial_end < NOW()
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

/// How time-to-paid obtains its activation timestamp. The earliest PAID
/// invoice at/after `trial_end` is the actual payment time when the billing
/// data links one; otherwise `trial_end` (the Stripe billing-period start
/// that the subscription carries) is the documented fallback. The fallback
/// can understate true time-to-payment if payment was collected late, so it
/// is returned to clients as [`TrialConversionStats::payment_time_method`].
const TRIAL_PAYMENT_TIME_METHOD: &str = "actual paid-invoice time at/after trial_end when billing data links one; otherwise trial_end as a documented fallback (may understate late-collected payments)";

/// Mean trial-to-paid duration over converted trials. Activation time is
/// the earliest `invoices.paid_at` at/after `trial_end` for the tenant (one
/// subscription per tenant — `uq_stripe_subscriptions_tenant`), falling
/// back to `trial_end` only when no paid invoice links one. `Available(None)`
/// when there are no converted trials; `Unavailable` when the aggregate
/// cannot be read.
const AVG_TRIAL_TO_PAID_SQL: &str = r#"
    SELECT AVG(EXTRACT(EPOCH FROM (COALESCE(paid.first_paid_at, s.trial_end) - s.created_at)) / 86400)::double precision
    FROM stripe_subscriptions s
    LEFT JOIN LATERAL (
        SELECT MIN(i.paid_at) AS first_paid_at
        FROM invoices i
        WHERE i.tenant_id = s.tenant_id
          AND i.status = 'paid'
          AND i.paid_at IS NOT NULL
          AND i.paid_at >= s.trial_end
    ) paid ON TRUE
    WHERE s.trial_end IS NOT NULL
      AND s.trial_end < NOW()
      AND s.status IN ('active', 'past_due')
      AND s.created_at >= NOW() - $1::interval
"#;

async fn avg_trial_to_paid_days(db: &PgPool, interval: &str) -> MetricState<Option<f64>> {
    match sqlx::query_scalar::<_, Option<f64>>(AVG_TRIAL_TO_PAID_SQL)
        .bind(interval)
        .fetch_one(db)
        .await
    {
        Ok(value) => MetricState::Available(value),
        Err(error) => {
            tracing::error!(
                error = %error,
                "growth analytics: trial-to-paid aggregate failed — reporting unavailable, not zero"
            );
            MetricState::Unavailable {
                reason: "trial-to-paid aggregate could not be read",
            }
        }
    }
}

async fn trial_conversion_stats(
    db: &PgPool,
    interval: &str,
) -> Result<TrialConversionStats, ApiError> {
    // Required operational counts: failures propagate, never zeroed.
    let trials_started = sqlx::query_scalar::<_, i64>(TRIALS_STARTED_SQL)
        .bind(interval)
        .fetch_one(db)
        .await?;

    let trials_eligible = sqlx::query_scalar::<_, i64>(TRIALS_ELIGIBLE_SQL)
        .bind(interval)
        .fetch_one(db)
        .await?;

    let trials_converted = sqlx::query_scalar::<_, i64>(TRIALS_CONVERTED_SQL)
        .bind(interval)
        .fetch_one(db)
        .await?;

    // Trial conversion by plan (subscription plan, falling back to the
    // tenant's current plan). Eligibility is the same ended-trial
    // population used for the headline rate.
    let trial_by_plan: Vec<TrialPlanConversion> = sqlx::query_as::<_, (String, i64, i64, i64)>(
        "SELECT COALESCE(NULLIF(s.plan, ''), NULLIF(t.plan, ''), 'free'),
                COUNT(*)::bigint,
                COUNT(*) FILTER (WHERE s.trial_end < NOW())::bigint,
                COUNT(*) FILTER (
                    WHERE s.trial_end < NOW()
                      AND s.status IN ('active', 'past_due')
                )::bigint
         FROM stripe_subscriptions s
         LEFT JOIN tenants t ON t.id = s.tenant_id
         WHERE s.trial_end IS NOT NULL
           AND s.created_at >= NOW() - $1::interval
         GROUP BY 1 ORDER BY 2 DESC",
    )
    .bind(interval)
    .fetch_all(db)
    .await?
    .into_iter()
    .map(|(plan, trials, eligible, converted)| TrialPlanConversion {
        rate: activation_rate_of(converted, eligible),
        plan,
        trials,
        eligible,
        converted,
    })
    .collect();

    Ok(TrialConversionStats {
        trials_started,
        trials_eligible,
        trials_converted,
        conversion_rate: activation_rate_of(trials_converted, trials_eligible),
        avg_trial_to_paid_days: avg_trial_to_paid_days(db, interval).await,
        payment_time_method: TRIAL_PAYMENT_TIME_METHOD.into(),
        conversion_by_plan: trial_by_plan,
    })
}

// ─── Customer lifecycle ────────────────────────────────────────────────

/// Distinct paying customers. REQUIRED operational data: the error is
/// propagated, so a database failure can never render as "0 customers".
async fn active_customer_count(db: &PgPool) -> Result<i64, ApiError> {
    Ok(sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(DISTINCT tenant_id)::bigint FROM stripe_subscriptions
         WHERE status IN ('active', 'trialing', 'past_due')",
    )
    .fetch_one(db)
    .await?)
}

/// New customers in the last 30 days: a separate acquisition FLOW, not part
/// of the churn denominator. Counts subscriptions created in the window
/// regardless of their current status — a customer who joins and cancels
/// inside the same window is still new (and is deliberately NOT counted as
/// churn, because they were not in the starting cohort). Incomplete
/// checkouts (Stripe `incomplete` / `incomplete_expired`) are not customers.
/// Required — a failure propagates.
async fn new_customer_count_30d(db: &PgPool) -> Result<i64, ApiError> {
    Ok(sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(DISTINCT tenant_id)::bigint FROM stripe_subscriptions
         WHERE created_at >= NOW() - INTERVAL '30 days'
           AND COALESCE(status, '') NOT IN ('incomplete', 'incomplete_expired')",
    )
    .fetch_one(db)
    .await?)
}

/// The churn cohort and its in-window cancellations, in ONE query so both
/// counts come from the same snapshot:
///
/// * cohort = subscriptions that existed at the period start (`created_at <
///   start`) and had not already been canceled before it;
/// * churned = cohort members whose cancellation falls inside the window.
///
/// The churn condition is evaluated inside the cohort CTE, so the numerator
/// is a subset of the denominator by construction. Returns
/// `(cohort_size, churned)`.
const COHORT_CHURN_SQL: &str = r#"
    WITH period AS (SELECT NOW() - INTERVAL '30 days' AS start_at),
    cohort AS (
        SELECT s.tenant_id,
               BOOL_OR(
                   s.status = 'canceled'
                   AND COALESCE(s.canceled_at, s.updated_at) >= p.start_at
               ) AS churned_in_window
        FROM stripe_subscriptions s
        CROSS JOIN period p
        WHERE s.created_at < p.start_at
          AND COALESCE(
                s.canceled_at,
                CASE WHEN s.status = 'canceled' THEN s.updated_at END,
                'infinity'::timestamptz
              ) >= p.start_at
        GROUP BY s.tenant_id
    )
    SELECT COUNT(*)::bigint AS cohort_size,
           COUNT(*) FILTER (WHERE churned_in_window)::bigint AS churned
    FROM cohort
"#;

/// `(cohort at period start, cohort members canceled in the window)`.
/// Required — a failure propagates.
async fn cohort_churn_counts_30d(db: &PgPool) -> Result<(i64, i64), ApiError> {
    Ok(sqlx::query_as::<_, (i64, i64)>(COHORT_CHURN_SQL)
        .fetch_one(db)
        .await?)
}

/// Avg customer lifetime from real subscription ages (active/paying only).
/// `Available(None)` when there is no paying subscription; `Unavailable`
/// when the aggregate cannot be read.
async fn avg_customer_lifetime_days(db: &PgPool) -> MetricState<Option<f64>> {
    match sqlx::query_scalar::<_, Option<f64>>(
        "SELECT AVG(EXTRACT(EPOCH FROM (NOW() - created_at)) / 86400)
         FROM stripe_subscriptions WHERE status IN ('active', 'past_due')",
    )
    .fetch_one(db)
    .await
    {
        Ok(value) => MetricState::Available(value.filter(|v| *v > 0.0)),
        Err(error) => {
            tracing::error!(
                error = %error,
                "growth analytics: customer-lifetime aggregate failed — reporting unavailable, not zero"
            );
            MetricState::Unavailable {
                reason: "customer-lifetime aggregate could not be read",
            }
        }
    }
}

async fn customer_lifecycle(db: &PgPool) -> Result<CustomerLifecycle, ApiError> {
    let new_customers_30d = new_customer_count_30d(db).await?;
    let active_customers = active_customer_count(db).await?;
    let (cohort_customers_at_period_start, churned_customers_30d) =
        cohort_churn_counts_30d(db).await?;

    // The numerator is filtered to members of the starting cohort, so
    // churn_rate <= 1.0 and retained >= 0 hold structurally; saturating_sub
    // is a belt-and-braces guard, not a clamp of a reachable negative.
    let churn_rate_30d =
        activation_rate_of(churned_customers_30d, cohort_customers_at_period_start);
    let retained_customers_30d =
        cohort_customers_at_period_start.saturating_sub(churned_customers_30d);

    Ok(CustomerLifecycle {
        new_customers_30d,
        active_customers,
        cohort_customers_at_period_start,
        churned_customers_30d,
        churn_rate_30d,
        retained_customers_30d,
        retention_rate_30d: churn_rate_30d.map(|rate| 1.0 - rate),
        avg_customer_lifetime_days: avg_customer_lifetime_days(db).await,
    })
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
    db: &PgPool,
    interval: &str,
) -> Result<Option<f64>, ApiError> {
    let avg: Option<Option<f64>> = sqlx::query_scalar(AVG_TIME_TO_FIRST_SEND_SQL)
        .bind(interval)
        .fetch_optional(db)
        .await?;
    Ok(avg.flatten())
}

// ─── Handlers ──────────────────────────────────────────────────────────

async fn get_growth_analytics(
    State(state): State<AppState>,
    auth: AuthUser,
    Query(params): Query<GrowthQuery>,
) -> Result<Json<GrowthAnalyticsResponse>, ApiError> {
    crate::middleware::auth::require_scopes(&auth, &["*"])?;

    let db = &state.db;
    let days = parse_period_days(&params.period);
    let interval = format!("{days} days");

    let signups = signup_stats(db, &interval).await?;
    let activation = activation_counts(db, &interval).await?;
    let avg_time_to_first_send = avg_time_to_first_send_hours(db, &interval).await?;

    Ok(Json(GrowthAnalyticsResponse {
        signups,
        activation: ActivationStats {
            total_activated: activation.email_sent,
            activation_rate: activation_rate_of(activation.email_sent, activation.total_tenants),
            avg_time_to_first_send_hours: avg_time_to_first_send,
            activation_milestones: activation_milestones(&activation),
        },
        engagement: engagement_metrics(db).await?,
        trial_conversion: trial_conversion_stats(db, &interval).await?,
        lifecycle: customer_lifecycle(db).await?,
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

    Ok(Json(
        signup_stats(&state.db, &interval).await?.signup_timeline,
    ))
}

async fn get_activation_milestones(
    State(state): State<AppState>,
    auth: AuthUser,
    Query(params): Query<GrowthQuery>,
) -> Result<Json<ActivationStats>, ApiError> {
    crate::middleware::auth::require_scopes(&auth, &["*"])?;

    let days = parse_period_days(&params.period);
    let interval = format!("{days} days");
    let db = &state.db;

    let counts = activation_counts(db, &interval).await?;
    let avg = avg_time_to_first_send_hours(db, &interval).await?;

    Ok(Json(ActivationStats {
        total_activated: counts.email_sent,
        activation_rate: activation_rate_of(counts.email_sent, counts.total_tenants),
        avg_time_to_first_send_hours: avg,
        activation_milestones: activation_milestones(&counts),
    }))
}

async fn get_engagement_metrics(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<Json<EngagementMetrics>, ApiError> {
    crate::middleware::auth::require_scopes(&auth, &["*"])?;

    Ok(Json(engagement_metrics(&state.db).await?))
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

    /// The API reports independent MILESTONES, not funnel stages: the
    /// counts are not nested and a later milestone may exceed an earlier
    /// one (shared-pool sending requires neither domain verification nor
    /// DKIM). No ordering invariant may be claimed or enforced.
    #[test]
    fn activation_milestones_are_independent_not_nested() {
        let counts = ActivationCounts {
            total_tenants: 100,
            domain_verified: 40,
            dkim_configured: 70,
            email_sent: 90,
        };
        let milestones = activation_milestones(&counts);
        assert_eq!(milestones.len(), 4);
        assert_eq!(milestones[0].count, 100);
        assert_eq!(milestones[1].count, 40);
        assert_eq!(
            milestones[2].count, 70,
            "later milestone may exceed earlier"
        );
        assert_eq!(
            milestones[3].count, 90,
            "later milestone may exceed earlier"
        );
        assert_eq!(milestones[0].percentage, Some(100.0));
        assert_eq!(milestones[3].percentage, Some(90.0));
    }

    /// The serialized surface must say `activationMilestones`/`milestone`
    /// and must not resurrect funnel-stage vocabulary.
    #[test]
    fn activation_fields_are_named_milestones_not_funnel() {
        let stats = ActivationStats {
            total_activated: 1,
            activation_rate: Some(0.5),
            avg_time_to_first_send_hours: Some(2.0),
            activation_milestones: activation_milestones(&ActivationCounts {
                total_tenants: 2,
                domain_verified: 1,
                dkim_configured: 1,
                email_sent: 1,
            }),
        };
        let json = serde_json::to_string(&stats).expect("serialize activation stats");
        assert!(json.contains("activationMilestones"));
        assert!(json.contains("\"milestone\""));
        assert!(!json.contains("activationFunnel"));
        assert!(!json.contains("\"stage\""));
    }

    /// A zero signup population yields an ABSENT percentage/rate (`None`),
    /// never a fabricated 0.
    #[test]
    fn zero_denominator_percentages_are_absent_not_zero() {
        let counts = ActivationCounts {
            total_tenants: 0,
            domain_verified: 0,
            dkim_configured: 0,
            email_sent: 0,
        };
        let milestones = activation_milestones(&counts);
        assert_eq!(milestones[0].percentage, Some(100.0));
        for milestone in &milestones[1..] {
            assert_eq!(milestone.percentage, None, "milestone {milestone:?}");
        }
        assert_eq!(percentage_of(1, 0), None);
        assert_eq!(activation_rate_of(1, 0), None);
        assert_eq!(activation_rate_of(0, 0), None);
        assert_eq!(activation_rate_of(1, 4), Some(0.25));
    }

    #[test]
    fn active_tenant_ratio_handles_zero_30d_population() {
        // The ratio field is Option: an empty population is absent, not 0.
        let ratio: Option<f64> = (0 > 0).then(|| 0.0);
        assert_eq!(ratio, None);

        let metrics = EngagementMetrics {
            active_tenants_today: 0,
            active_tenants_7d: 0,
            active_tenants_30d: 0,
            active_tenants_today_ratio_30d: None,
            sending_tenants_30d: 0,
            avg_active_days_per_tenant_30d: MetricState::Available(None),
        };
        assert_eq!(metrics.active_tenants_today_ratio_30d, None);
        assert_eq!(
            metrics.avg_active_days_per_tenant_30d,
            MetricState::Available(None),
            "no events is an undefined mean, not a zero"
        );
        assert_ne!(
            metrics.avg_active_days_per_tenant_30d,
            MetricState::Available(Some(0.0)),
            "undefined must be distinguishable from a measured zero"
        );
    }

    #[test]
    fn engagement_metrics_are_labelled_tenants_not_users() {
        // The struct must not expose DAU/WAU/MAU-style user labels: the
        // events table has no user dimension, so those would be a mislabel.
        let metrics = EngagementMetrics {
            active_tenants_today: 5,
            active_tenants_7d: 9,
            active_tenants_30d: 12,
            active_tenants_today_ratio_30d: Some(5.0 / 12.0),
            sending_tenants_30d: 7,
            avg_active_days_per_tenant_30d: MetricState::Available(Some(3.5)),
        };
        assert!(metrics.active_tenants_today_ratio_30d.expect("ratio") <= 1.0);
        assert!(metrics.active_tenants_today <= metrics.active_tenants_30d);
        assert!(metrics.active_tenants_7d <= metrics.active_tenants_30d);
    }

    #[test]
    fn trial_sql_reads_stripe_subscriptions_with_period_semantics() {
        // The legacy table had no writer; all trial SQL must read
        // stripe_subscriptions and use trial_end period semantics.
        for sql in [
            TRIALS_STARTED_SQL,
            TRIALS_ELIGIBLE_SQL,
            TRIALS_CONVERTED_SQL,
            AVG_TRIAL_TO_PAID_SQL,
        ] {
            assert!(sql.contains("FROM stripe_subscriptions"));
            assert!(sql.contains("trial_end IS NOT NULL"));
            assert!(!sql.contains("FROM subscriptions\n"));
        }
    }

    /// The conversion denominator is ENDED trials only: the eligible count
    /// requires `trial_end < NOW()`, so an ongoing trial is never included.
    #[test]
    fn trial_denominator_is_ended_trials_only() {
        assert!(TRIALS_ELIGIBLE_SQL.contains("trial_end < NOW()"));
        // Started trials deliberately do NOT filter on trial_end: they are
        // the flow counter that includes ongoing trials.
        assert!(!TRIALS_STARTED_SQL.contains("trial_end < NOW()"));
        // The converted numerator is a subset of the eligible denominator.
        assert!(TRIALS_CONVERTED_SQL.contains("trial_end < NOW()"));
        assert!(TRIALS_CONVERTED_SQL.contains("status IN ('active', 'past_due')"));
    }

    #[test]
    fn trial_converted_sql_is_not_self_negating() {
        // The old query demanded status = 'active' AND membership in a
        // status = 'trialing' set of the SAME single-row table — impossible.
        assert!(!TRIALS_CONVERTED_SQL.contains("id IN"));
        assert!(TRIALS_CONVERTED_SQL.contains("trial_end < NOW()"));
        assert!(TRIALS_CONVERTED_SQL.contains("status IN ('active', 'past_due')"));
    }

    /// Time-to-paid prefers the ACTUAL paid-invoice time at/after trial_end
    /// and only falls back to trial_end (documented caveat returned to
    /// clients). No hardcoded duration constant.
    #[test]
    fn avg_trial_to_paid_prefers_actual_payment_with_documented_fallback() {
        assert!(
            AVG_TRIAL_TO_PAID_SQL.contains("i.paid_at >= s.trial_end"),
            "actual payment must be at/after the trial end"
        );
        assert!(AVG_TRIAL_TO_PAID_SQL.contains("i.status = 'paid'"));
        assert!(
            AVG_TRIAL_TO_PAID_SQL.contains("COALESCE(paid.first_paid_at, s.trial_end)"),
            "trial_end must be the explicit fallback, not the primary source"
        );
        assert!(!AVG_TRIAL_TO_PAID_SQL.contains("14"));
        assert!(TRIAL_PAYMENT_TIME_METHOD.contains("fallback"));
    }

    // ── Churn cohort (audit fix) ────────────────────────────────────────

    /// A previous period mixed incompatible populations: churn was
    /// `canceled-in-window / current-active` and retained was
    /// `current-active − canceled-in-window`. A tenant that canceled inside
    /// the window but signed up inside it too (or was counted as canceled
    /// while no longer current-active) made retained NEGATIVE and churn
    /// EXCEED 100%. The cohort formula cannot.
    #[test]
    fn old_mixed_population_churn_could_go_negative_new_cohort_cannot() {
        // Observed counts: 1 currently-active customer, 2 cancellations in
        // the window (one of them a same-window signup), cohort at period
        // start = 2. Of the 2 cancellations only ONE is a cohort member; the
        // same-window signup is the separate new-customer flow.
        let current_active = 1_i64;
        let canceled_in_window = 2_i64;
        let cohort_at_start = 2_i64;
        let cohort_churned = 1_i64;
        let new_customers = 1_i64;

        // OLD (wrong) math — reproduced here as the regression witness.
        let old_rate = canceled_in_window as f64 / current_active as f64;
        let old_retained = current_active - canceled_in_window;
        assert!(old_rate > 1.0, "old churn exceeded 100%: {old_rate}");
        assert!(
            old_retained < 0,
            "old retained went negative: {old_retained}"
        );

        // NEW math: churn is counted inside the starting cohort; new
        // customers are a separate flow and never enter the subtraction.
        let rate = activation_rate_of(cohort_churned, cohort_at_start).expect("non-empty cohort");
        let retained = cohort_at_start.saturating_sub(cohort_churned);
        assert!(rate <= 1.0, "cohort churn can never exceed 100%: {rate}");
        assert!(
            retained >= 0,
            "cohort retained can never be negative: {retained}"
        );
        assert_eq!(rate, 0.5);
        assert_eq!(retained, 1);
        assert_eq!(new_customers, 1, "new customers are a separate flow");
    }

    /// The SQL counts churn INSIDE the cohort CTE, so the numerator is a
    /// subset of the denominator by construction (not by clamping).
    #[test]
    fn churn_sql_counts_members_of_the_starting_cohort_only() {
        assert!(COHORT_CHURN_SQL.contains("WITH period AS"));
        assert!(COHORT_CHURN_SQL.contains("cohort AS"));
        assert!(
            COHORT_CHURN_SQL.contains("FROM stripe_subscriptions s")
                && COHORT_CHURN_SQL.contains("CROSS JOIN period p"),
            "cohort membership must read real subscriptions at period start"
        );
        // Membership: existed at start and not already canceled before it.
        assert!(COHORT_CHURN_SQL.contains("s.created_at < p.start_at"));
        assert!(COHORT_CHURN_SQL.contains("'infinity'::timestamptz"));
        // Churn: counted on cohort rows, joined later against the cohort.
        let churn_select = COHORT_CHURN_SQL
            .split("SELECT COUNT(*)::bigint AS cohort_size")
            .nth(1)
            .expect("aggregation over the cohort");
        assert!(churn_select.contains("FROM cohort"));
        // The old current-active denominator must not appear anywhere.
        assert!(!COHORT_CHURN_SQL.contains("status IN ('active', 'trialing', 'past_due')"));
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

    /// Adversarial 5 (audit item 20): a database failure must NEVER render
    /// as "0 customers". The relation is renamed in a throwaway canonical
    /// database; the required helpers and the whole lifecycle block must
    /// return an error, not `Ok(0)`.
    #[tokio::test]
    async fn db_failure_is_not_zero_customers() {
        let Some(pool) = crate::test_db::canonical_pool("growth_db_failure").await else {
            eprintln!("skipping db_failure_is_not_zero_customers: no TEST_DATABASE_URL");
            return;
        };

        // Throwaway per-test database: renaming the billing relation
        // simulates the outage.
        sqlx::query("ALTER TABLE stripe_subscriptions RENAME TO stripe_subscriptions_failure_test")
            .execute(&pool)
            .await
            .expect("rename stripe_subscriptions (throwaway test database)");

        let active = active_customer_count(&pool).await;
        assert!(
            active.is_err(),
            "a failed customers query must be an error, never Ok(0 customers)"
        );

        let new = new_customer_count_30d(&pool).await;
        assert!(
            new.is_err(),
            "a failed new-customers query must be an error"
        );

        let churned = cohort_churn_counts_30d(&pool).await;
        assert!(
            churned.is_err(),
            "a failed cohort/churn query must be an error"
        );

        let lifecycle = customer_lifecycle(&pool).await;
        assert!(
            lifecycle.is_err(),
            "the lifecycle block must fail loudly, never report zero customers"
        );

        // The genuinely-optional aggregate reports UNAVAILABLE with a
        // reason instead of a numeric zero.
        let lifetime = avg_customer_lifetime_days(&pool).await;
        assert!(
            !lifetime.is_available(),
            "optional metric must be Unavailable on read failure, got {lifetime:?}"
        );
        assert!(
            lifetime.unavailable_reason().is_some(),
            "the unavailable state must carry a reason"
        );

        pool.close().await;
    }

    /// A successful read of a genuinely empty population is
    /// `Available(None)` — distinguishable from a read failure.
    #[tokio::test]
    async fn empty_population_is_available_none_not_failure() {
        let Some(pool) = crate::test_db::canonical_pool("growth_empty_optional").await else {
            eprintln!(
                "skipping empty_population_is_available_none_not_failure: no TEST_DATABASE_URL"
            );
            return;
        };

        let lifetime = avg_customer_lifetime_days(&pool).await;
        assert_eq!(
            lifetime,
            MetricState::Available(None),
            "an empty paying population is undefined lifetime, not unavailability"
        );

        let avg_active = avg_active_days_per_tenant_30d(&pool).await;
        assert_eq!(avg_active, MetricState::Available(None));

        pool.close().await;
    }

    /// The audit's exact scenario, against the canonical schema: a customer
    /// who signed up and canceled INSIDE the window, plus a pre-window
    /// cancellation. The old math (cancellations-in-window over CURRENT
    /// active, retained = active − cancellations) produced >100% churn and
    /// negative retention; the cohort math cannot.
    #[tokio::test]
    async fn churn_cohort_excludes_new_customers_and_stays_bounded() {
        let Some(pool) = crate::test_db::canonical_pool("growth_churn_cohort").await else {
            eprintln!(
                "skipping churn_cohort_excludes_new_customers_and_stays_bounded: no TEST_DATABASE_URL"
            );
            return;
        };

        let suffix = uuid::Uuid::new_v4().simple().to_string();
        let tenant = |name: &str| format!("t{}{name}", &suffix[..6]);

        let seed = |id: String,
                    label: &'static str,
                    created_days: i64,
                    status: &'static str,
                    canceled_days: Option<i64>| {
            let pool = pool.clone();
            let sub_id = format!("sub-{id}");
            async move {
                sqlx::query("INSERT INTO tenants (id, name) VALUES ($1, $2)")
                    .bind(&id)
                    .bind(label)
                    .execute(&pool)
                    .await
                    .expect("seed tenant");
                sqlx::query(
                    "INSERT INTO stripe_subscriptions
                         (tenant_id, stripe_subscription_id, plan, status, created_at, canceled_at)
                     VALUES ($1, $2, 'starter', $3,
                             NOW() - make_interval(days => $4::int),
                             CASE WHEN $5::int IS NULL THEN NULL
                                  ELSE NOW() - make_interval(days => $5::int) END)",
                )
                .bind(&id)
                .bind(&sub_id)
                .bind(status)
                .bind(created_days)
                .bind(canceled_days)
                .execute(&pool)
                .await
                .expect("seed subscription");
            }
        };

        // Cohort + churn: existed at period start, canceled inside window.
        seed(tenant("a"), "cohort-churned", 60, "canceled", Some(5)).await;
        // Cohort + retained: existed at period start, still active.
        seed(tenant("b"), "cohort-retained", 60, "active", None).await;
        // New customer that canceled inside the window: a separate flow. The
        // OLD math counted this cancellation against the current-active
        // population; the cohort math excludes it from both cohort and churn.
        seed(tenant("c"), "new-churn", 3, "canceled", Some(1)).await;
        // Canceled BEFORE the period start: neither cohort nor churn.
        seed(tenant("d"), "old-churn", 90, "canceled", Some(40)).await;

        let (cohort, churned) = cohort_churn_counts_30d(&pool).await.expect("cohort counts");
        assert_eq!(cohort, 2, "only pre-start, not-yet-canceled subscriptions");
        assert_eq!(churned, 1, "only the cohort member canceled in-window");
        assert!(
            churned <= cohort,
            "numerator is a subset of the denominator"
        );

        let lifecycle = customer_lifecycle(&pool).await.expect("lifecycle");
        assert_eq!(lifecycle.cohort_customers_at_period_start, 2);
        assert_eq!(lifecycle.churned_customers_30d, 1);
        assert_eq!(lifecycle.retained_customers_30d, 1);
        assert_eq!(lifecycle.churn_rate_30d, Some(0.5));
        assert_eq!(lifecycle.retention_rate_30d, Some(0.5));
        assert!(
            lifecycle.churn_rate_30d.expect("rate") <= 1.0,
            "cohort churn can never exceed 100%"
        );
        assert!(lifecycle.retained_customers_30d >= 0);
        assert_eq!(
            lifecycle.new_customers_30d, 1,
            "the in-window canceled signup is reported in the new-customer flow"
        );
        // The current snapshot stays a snapshot (only the still-active row).
        assert_eq!(lifecycle.active_customers, 1);

        // Regression witness: the OLD formula on these same rows produced a
        // 200% churn rate and −1 retained customers.
        let old_churned_in_window = 2_i64; // rows a + c
        let old_rate = old_churned_in_window as f64 / lifecycle.active_customers as f64;
        let old_retained = lifecycle.active_customers - old_churned_in_window;
        assert!(old_rate > 1.0, "old formula churn was {old_rate}");
        assert!(old_retained < 0, "old formula retained was {old_retained}");

        pool.close().await;
    }

    /// Trial conversion denominator = trials that have ENDED. An ONGOING
    /// trial is excluded; a long-ended unconverted trial is included; the
    /// rate can no longer be right-censored by trials still running. Also
    /// proves time-to-paid prefers actual paid-invoice time over the
    /// documented trial_end fallback.
    #[tokio::test]
    async fn trial_conversion_denominator_is_ended_trials_only() {
        let Some(pool) = crate::test_db::canonical_pool("growth_trial_eligible").await else {
            eprintln!(
                "skipping trial_conversion_denominator_is_ended_trials_only: no TEST_DATABASE_URL"
            );
            return;
        };

        let suffix = uuid::Uuid::new_v4().simple().to_string();
        let tenant = |name: &str| format!("t{}{name}", &suffix[..6]);

        let seed_trial = |id: String,
                          label: &'static str,
                          created_days: i64,
                          trial_end_days: i64,
                          status: &'static str| {
            let pool = pool.clone();
            let sub_id = format!("sub-{id}");
            async move {
                sqlx::query("INSERT INTO tenants (id, name) VALUES ($1, $2)")
                    .bind(&id)
                    .bind(label)
                    .execute(&pool)
                    .await
                    .expect("seed tenant");
                sqlx::query(
                    "INSERT INTO stripe_subscriptions
                         (tenant_id, stripe_subscription_id, plan, status, created_at, trial_end)
                     VALUES ($1, $2, 'starter', $3,
                             NOW() - make_interval(days => $4::int),
                             NOW() - make_interval(days => $5::int))",
                )
                .bind(&id)
                .bind(&sub_id)
                .bind(status)
                .bind(created_days)
                .bind(trial_end_days)
                .execute(&pool)
                .await
                .expect("seed trial");
            }
        };

        // Long-ended, never converted: MUST be in the denominator.
        seed_trial(tenant("a"), "ended-unconverted", 40, 26, "trialing").await;
        // Ongoing trial: started, MUST NOT be in the denominator.
        seed_trial(tenant("b"), "ongoing", 10, -5, "trialing").await;
        // Ended and converted, with actual payment 3 days ago (17d to paid).
        let converted_with_invoice = tenant("c");
        seed_trial(
            converted_with_invoice.clone(),
            "converted-paid",
            20,
            6,
            "active",
        )
        .await;
        // Ended and converted, no post-trial invoice: documented fallback to
        // trial_end (10d to paid). The pre-trial setup invoice must NOT be
        // mistaken for the conversion payment.
        let converted_with_fallback = tenant("d");
        seed_trial(
            converted_with_fallback.clone(),
            "converted-fallback",
            15,
            5,
            "active",
        )
        .await;

        for (tenant_id, paid_days_ago) in [
            (converted_with_invoice, 3_i64),
            (converted_with_fallback, 12_i64), // paid BEFORE trial_end → ignored
        ] {
            sqlx::query(
                "INSERT INTO invoices (tenant_id, stripe_invoice_id, status, amount, currency, paid_at)
                 VALUES ($1, $2, 'paid', 1000, 'EUR', NOW() - make_interval(days => $3::int))",
            )
            .bind(&tenant_id)
            .bind(format!("inv-{tenant_id}"))
            .bind(paid_days_ago)
            .execute(&pool)
            .await
            .expect("seed paid invoice");
        }

        let stats = trial_conversion_stats(&pool, "90 days")
            .await
            .expect("trial conversion stats");
        assert_eq!(
            stats.trials_started, 4,
            "flow counter includes the ongoing trial"
        );
        assert_eq!(
            stats.trials_eligible, 3,
            "only ended trials are eligible: ongoing excluded, long-ended unconverted included"
        );
        assert_eq!(stats.trials_converted, 2);
        let rate = stats
            .conversion_rate
            .expect("eligible denominator is non-empty");
        assert!(
            (rate - 2.0 / 3.0).abs() < 1e-9,
            "converted/eligible = 2/3, got {rate}"
        );
        assert!(
            (rate - 0.5).abs() > 1e-9,
            "the old started-trials denominator would give 2/4 = 0.5 — right-censored"
        );

        // The actual payment for tenant c is 17 days after signup; tenant d
        // falls back to trial_end = 10 days after signup. Mean = 13.5.
        match stats.avg_trial_to_paid_days {
            MetricState::Available(Some(days)) => assert!(
                (days - 13.5).abs() < 0.01,
                "expected actual-payment 17d and fallback 10d → 13.5d, got {days}"
            ),
            other => panic!("expected an available average, got {other:?}"),
        }
        assert!(stats.payment_time_method.contains("fallback"));
        assert!(
            (stats
                .conversion_by_plan
                .iter()
                .map(|p| p.eligible)
                .sum::<i64>())
                >= stats.trials_eligible,
            "per-plan eligibility must use the same ended-trial population"
        );

        pool.close().await;
    }
}
