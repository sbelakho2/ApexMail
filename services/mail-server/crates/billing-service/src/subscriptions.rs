//! Subscription management – create, get, update plan, cancel.
//!
//! The actual Stripe subscription lifecycle (checkout, portal, and verified
//! webhooks) stays in the billing integration boundary. Public helpers in
//! this module deliberately cannot create, change, or cancel local records
//! because doing so would bypass Stripe as the payment authority.

#[cfg(test)]
use crate::types::UsageSummary;

use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

use crate::types::{BillingInterval, Subscription, SubscriptionStatus};

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Direct local subscription creation is disabled.
///
/// Verified Stripe webhook handling owns subscription persistence. Retaining
/// this public helper as a safe failure prevents future callers from creating
/// an `active` local record without a matching Stripe event.
pub async fn create_subscription(
    _pool: &PgPool,
    _input: CreateSubscriptionInput,
) -> Result<Subscription, SubscriptionError> {
    Err(SubscriptionError::PaymentConfirmationRequired)
}

/// Get the active subscription for a tenant.
pub async fn get_subscription(
    pool: &PgPool,
    tenant_id: &str,
) -> Result<Option<Subscription>, SubscriptionError> {
    let row: Option<SubRow> = sqlx::query_as(
        r#"
        SELECT
            id, tenant_id, plan_name,
            status, billing_interval,
            current_period_start, current_period_end,
            stripe_subscription_id, stripe_customer_id,
            cancel_at_period_end, created_at, updated_at
        FROM subscriptions
        WHERE tenant_id = $1
          AND status IN ('active', 'trialing', 'past_due')
        ORDER BY created_at DESC
        LIMIT 1
        "#,
    )
    .bind(tenant_id)
    .fetch_optional(pool)
    .await
    .map_err(SubscriptionError::Db)?;

    row.map(|r| r.into_subscription()).transpose()
}

/// Direct subscription changes are deliberately blocked. Stripe is the source
/// of payment confirmation, and only verified Stripe webhook processing may
/// update an entitlement-bearing tenant plan.
pub async fn update_plan(
    _pool: &PgPool,
    _tenant_id: &str,
    _new_plan: &str,
) -> Result<(), SubscriptionError> {
    Err(SubscriptionError::PaymentConfirmationRequired)
}

/// Direct local cancellation is disabled; use Stripe’s billing portal and
/// reconcile the verified webhook event instead.
pub async fn cancel_subscription(
    _pool: &PgPool,
    _tenant_id: &str,
) -> Result<(), SubscriptionError> {
    Err(SubscriptionError::PaymentConfirmationRequired)
}

// ---------------------------------------------------------------------------
// Input types
// ---------------------------------------------------------------------------

pub struct CreateSubscriptionInput {
    pub tenant_id: String,
    pub plan_name: String,
    pub billing_interval: BillingInterval,
    pub period_start: DateTime<Utc>,
    pub period_end: DateTime<Utc>,
    pub stripe_subscription_id: Option<String>,
    pub stripe_customer_id: Option<String>,
}

// ---------------------------------------------------------------------------
// Internal
// ---------------------------------------------------------------------------

#[cfg(test)]
fn interval_to_str(i: BillingInterval) -> &'static str {
    match i {
        BillingInterval::Monthly => "monthly",
        BillingInterval::Yearly => "yearly",
    }
}

fn parse_status(s: &str) -> Result<SubscriptionStatus, SubscriptionError> {
    match s {
        "active" => Ok(SubscriptionStatus::Active),
        "past_due" => Ok(SubscriptionStatus::PastDue),
        "canceled" => Ok(SubscriptionStatus::Canceled),
        "trialing" => Ok(SubscriptionStatus::Trialing),
        "paused" => Ok(SubscriptionStatus::Paused),
        "incomplete" => Ok(SubscriptionStatus::Incomplete),
        _ => Err(SubscriptionError::InvalidStatus(s.to_string())),
    }
}

fn parse_interval(s: &str) -> BillingInterval {
    match s {
        "yearly" => BillingInterval::Yearly,
        _ => BillingInterval::Monthly,
    }
}

#[cfg(test)]
fn usage_limit_errors(usage: &UsageSummary, limits: &PlanLimitRow) -> Vec<String> {
    let mut errors = Vec::new();

    if limits.email_limit >= 0 && usage.emails_sent > limits.email_limit {
        errors.push(format!(
            "emails sent this period ({}) exceed the {} plan limit ({})",
            usage.emails_sent, limits.name, limits.email_limit
        ));
    }

    if limits.api_call_limit >= 0 && usage.api_calls > limits.api_call_limit {
        errors.push(format!(
            "API calls this period ({}) exceed the {} plan limit ({})",
            usage.api_calls, limits.name, limits.api_call_limit
        ));
    }

    errors
}

#[derive(sqlx::FromRow)]
struct SubRow {
    id: Uuid,
    tenant_id: String,
    plan_name: String,
    status: String,
    billing_interval: String,
    current_period_start: DateTime<Utc>,
    current_period_end: DateTime<Utc>,
    stripe_subscription_id: Option<String>,
    stripe_customer_id: Option<String>,
    cancel_at_period_end: bool,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

#[cfg(test)]
#[derive(sqlx::FromRow)]
struct PlanLimitRow {
    name: String,
    email_limit: i64,
    api_call_limit: i64,
}

impl SubRow {
    fn into_subscription(self) -> Result<Subscription, SubscriptionError> {
        Ok(Subscription {
            id: self.id,
            tenant_id: self.tenant_id,
            plan_name: self.plan_name,
            status: parse_status(&self.status)?,
            billing_interval: parse_interval(&self.billing_interval),
            current_period_start: self.current_period_start,
            current_period_end: self.current_period_end,
            stripe_subscription_id: self.stripe_subscription_id,
            stripe_customer_id: self.stripe_customer_id,
            cancel_at_period_end: self.cancel_at_period_end,
            created_at: self.created_at,
            updated_at: self.updated_at,
        })
    }
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum SubscriptionError {
    #[error("database error: {0}")]
    Db(#[from] sqlx::Error),
    #[error("usage lookup failed: {0}")]
    Usage(#[from] crate::usage::UsageError),
    #[error("plan not found: {0}")]
    PlanNotFound(String),
    #[error("active subscription not found")]
    NotFound,
    #[error("cannot change to {plan_name}: {reasons:?}")]
    UsageExceedsPlan {
        plan_name: String,
        reasons: Vec<String>,
    },
    #[error("direct plan changes require verified payment confirmation")]
    PaymentConfirmationRequired,
    #[error("invalid subscription status: {0}")]
    InvalidStatus(String),
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use sqlx::postgres::PgPoolOptions;

    #[test]
    fn parse_status_variants() {
        assert_eq!(parse_status("active").unwrap(), SubscriptionStatus::Active);
        assert_eq!(
            parse_status("past_due").unwrap(),
            SubscriptionStatus::PastDue
        );
        assert_eq!(
            parse_status("canceled").unwrap(),
            SubscriptionStatus::Canceled
        );
        assert_eq!(
            parse_status("trialing").unwrap(),
            SubscriptionStatus::Trialing
        );
        assert_eq!(parse_status("paused").unwrap(), SubscriptionStatus::Paused);
        assert_eq!(
            parse_status("incomplete").unwrap(),
            SubscriptionStatus::Incomplete
        );
    }

    #[test]
    fn parse_status_unknown_is_error() {
        let err = parse_status("unknown").unwrap_err();

        assert!(matches!(err, SubscriptionError::InvalidStatus(status) if status == "unknown"));
    }

    #[test]
    fn parse_interval_variants() {
        assert_eq!(parse_interval("monthly"), BillingInterval::Monthly);
        assert_eq!(parse_interval("yearly"), BillingInterval::Yearly);
        assert_eq!(parse_interval("other"), BillingInterval::Monthly);
    }

    #[test]
    fn interval_to_str_roundtrip() {
        assert_eq!(interval_to_str(BillingInterval::Monthly), "monthly");
        assert_eq!(interval_to_str(BillingInterval::Yearly), "yearly");
    }

    #[test]
    fn sub_row_into_subscription() {
        let now = Utc::now();
        let row = SubRow {
            id: Uuid::new_v4(),
            tenant_id: "tenant_01HZY2Q4YQ0L8QW8Q7Q28WKSFJ".into(),
            plan_name: "pro".into(),
            status: "active".into(),
            billing_interval: "monthly".into(),
            current_period_start: now,
            current_period_end: now,
            stripe_subscription_id: Some("sub_123".into()),
            stripe_customer_id: Some("cus_456".into()),
            cancel_at_period_end: false,
            created_at: now,
            updated_at: now,
        };
        let sub = row.into_subscription().unwrap();
        assert_eq!(sub.plan_name, "pro");
        assert_eq!(sub.status, SubscriptionStatus::Active);
        assert_eq!(sub.billing_interval, BillingInterval::Monthly);
    }

    #[test]
    fn sub_row_into_subscription_rejects_invalid_status() {
        let now = Utc::now();
        let row = SubRow {
            id: Uuid::new_v4(),
            tenant_id: "tenant_01HZY2Q4YQ0L8QW8Q7Q28WKSFJ".into(),
            plan_name: "pro".into(),
            status: "corrupted".into(),
            billing_interval: "monthly".into(),
            current_period_start: now,
            current_period_end: now,
            stripe_subscription_id: None,
            stripe_customer_id: None,
            cancel_at_period_end: false,
            created_at: now,
            updated_at: now,
        };

        let err = row.into_subscription().unwrap_err();
        assert!(matches!(err, SubscriptionError::InvalidStatus(status) if status == "corrupted"));
    }

    #[test]
    fn subscription_error_display() {
        let err = SubscriptionError::PlanNotFound("gold".into());
        assert!(err.to_string().contains("gold"));
    }

    #[test]
    fn direct_plan_update_error_requires_payment_confirmation() {
        assert_eq!(
            SubscriptionError::PaymentConfirmationRequired.to_string(),
            "direct plan changes require verified payment confirmation"
        );
    }

    #[tokio::test]
    async fn direct_subscription_mutations_never_touch_the_database() {
        let pool = PgPoolOptions::new()
            .connect_lazy("postgres://unused:unused@127.0.0.1:1/unused")
            .expect("a lazy pool should not connect during construction");
        let now = Utc::now();

        assert!(matches!(
            create_subscription(
                &pool,
                CreateSubscriptionInput {
                    tenant_id: "tenant_123".into(),
                    plan_name: "pro".into(),
                    billing_interval: BillingInterval::Monthly,
                    period_start: now,
                    period_end: now,
                    stripe_subscription_id: Some("sub_123".into()),
                    stripe_customer_id: Some("cus_123".into()),
                },
            )
            .await,
            Err(SubscriptionError::PaymentConfirmationRequired)
        ));
        assert!(matches!(
            update_plan(&pool, "tenant_123", "growth").await,
            Err(SubscriptionError::PaymentConfirmationRequired)
        ));
        assert!(matches!(
            cancel_subscription(&pool, "tenant_123").await,
            Err(SubscriptionError::PaymentConfirmationRequired)
        ));
    }

    #[test]
    fn usage_limit_errors_accepts_usage_within_limits() {
        let usage = UsageSummary {
            tenant_id: "tenant_01HZY2Q4YQ0L8QW8Q7Q28WKSFJ".into(),
            period_start: Utc::now(),
            period_end: Utc::now(),
            emails_sent: 10,
            emails_limit: 100,
            api_calls: 20,
            api_calls_limit: 200,
            percent_used: 10.0,
            metrics: json!({}),
        };
        let limits = PlanLimitRow {
            name: "starter".into(),
            email_limit: 50,
            api_call_limit: 100,
        };

        assert!(usage_limit_errors(&usage, &limits).is_empty());
    }

    #[test]
    fn usage_limit_errors_reports_email_and_api_overages() {
        let usage = UsageSummary {
            tenant_id: "tenant_01HZY2Q4YQ0L8QW8Q7Q28WKSFJ".into(),
            period_start: Utc::now(),
            period_end: Utc::now(),
            emails_sent: 75,
            emails_limit: 100,
            api_calls: 250,
            api_calls_limit: 500,
            percent_used: 75.0,
            metrics: json!({}),
        };
        let limits = PlanLimitRow {
            name: "starter".into(),
            email_limit: 50,
            api_call_limit: 200,
        };

        let errors = usage_limit_errors(&usage, &limits);

        assert_eq!(errors.len(), 2);
        assert!(errors
            .iter()
            .any(|error| error.contains("emails sent this period")));
        assert!(errors
            .iter()
            .any(|error| error.contains("API calls this period")));
    }

    #[test]
    fn usage_limit_errors_allows_unlimited_plan_limits() {
        let usage = UsageSummary {
            tenant_id: "tenant_01HZY2Q4YQ0L8QW8Q7Q28WKSFJ".into(),
            period_start: Utc::now(),
            period_end: Utc::now(),
            emails_sent: 10_000,
            emails_limit: 100,
            api_calls: 20_000,
            api_calls_limit: 500,
            percent_used: 100.0,
            metrics: json!({}),
        };
        let limits = PlanLimitRow {
            name: "enterprise".into(),
            email_limit: -1,
            api_call_limit: -1,
        };

        assert!(usage_limit_errors(&usage, &limits).is_empty());
    }
}
