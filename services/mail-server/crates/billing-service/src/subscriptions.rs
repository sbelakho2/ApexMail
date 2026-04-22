//! Subscription management – create, get, update plan, cancel.
//!
//! The actual Stripe subscription lifecycle (checkout, webhooks) stays in
//! TypeScript. This module manages the local DB record and plan transitions.

use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

use crate::types::{BillingInterval, Subscription, SubscriptionStatus};

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Create a new subscription record.
pub async fn create_subscription(
    pool: &PgPool,
    input: CreateSubscriptionInput,
) -> Result<Subscription, SubscriptionError> {
    let id = Uuid::new_v4();
    let now = Utc::now();

    sqlx::query(
        r#"
        INSERT INTO subscriptions (
            id, tenant_id, plan_name, status, billing_interval,
            current_period_start, current_period_end,
            stripe_subscription_id, stripe_customer_id,
            cancel_at_period_end, created_at, updated_at
        ) VALUES (
            $1, $2, $3, 'active', $4,
            $5, $6,
            $7, $8,
            false, $9, $9
        )
        "#,
    )
    .bind(id)
    .bind(input.tenant_id)
    .bind(&input.plan_name)
    .bind(interval_to_str(input.billing_interval))
    .bind(input.period_start)
    .bind(input.period_end)
    .bind(&input.stripe_subscription_id)
    .bind(&input.stripe_customer_id)
    .bind(now)
    .execute(pool)
    .await
    .map_err(SubscriptionError::Db)?;

    Ok(Subscription {
        id,
        tenant_id: input.tenant_id,
        plan_name: input.plan_name,
        status: SubscriptionStatus::Active,
        billing_interval: input.billing_interval,
        current_period_start: input.period_start,
        current_period_end: input.period_end,
        stripe_subscription_id: input.stripe_subscription_id,
        stripe_customer_id: input.stripe_customer_id,
        cancel_at_period_end: false,
        created_at: now,
        updated_at: now,
    })
}

/// Get the active subscription for a tenant.
pub async fn get_subscription(
    pool: &PgPool,
    tenant_id: Uuid,
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

/// Change the plan on an existing subscription (upgrade / downgrade).
/// Also updates the tenant's `plan` column.
pub async fn update_plan(
    pool: &PgPool,
    tenant_id: Uuid,
    new_plan: &str,
) -> Result<(), SubscriptionError> {
// Verify the plan exists.
    let exists: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM plans WHERE name = $1 AND is_active = true",
    )
    .bind(new_plan)
    .fetch_one(pool)
    .await
    .map_err(SubscriptionError::Db)?;

    if exists.0 == 0 {
        return Err(SubscriptionError::PlanNotFound(new_plan.to_string()));
    }

    let now = Utc::now();

// Wrap both writes in a transaction for atomicity.
    let mut tx = pool.begin().await.map_err(SubscriptionError::Db)?;

// Update only the current visible subscription record.
    let updated_subscription_id: Option<Uuid> = sqlx::query_scalar(
        r#"
        WITH target AS (
            SELECT id
            FROM subscriptions
            WHERE tenant_id = $3
              AND status IN ('active', 'trialing', 'past_due')
            ORDER BY created_at DESC
            LIMIT 1
        )
        UPDATE subscriptions s
        SET plan_name = $1, updated_at = $2
        FROM target
        WHERE s.id = target.id
        RETURNING s.id
        "#,
    )
    .bind(new_plan)
    .bind(now)
    .bind(tenant_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(SubscriptionError::Db)?;

    if updated_subscription_id.is_none() {
        return Err(SubscriptionError::NotFound);
    }

// Update tenant plan column.
    sqlx::query("UPDATE tenants SET plan = $1, updated_at = $2 WHERE id = $3")
        .bind(new_plan)
        .bind(now)
        .bind(tenant_id)
        .execute(&mut *tx)
        .await
        .map_err(SubscriptionError::Db)?;

    tx.commit().await.map_err(SubscriptionError::Db)?;

    Ok(())
}

/// Cancel the subscription (at period end).
pub async fn cancel_subscription(
    pool: &PgPool,
    tenant_id: Uuid,
) -> Result<(), SubscriptionError> {
    let now = Utc::now();

    let affected = sqlx::query(
        r#"
        UPDATE subscriptions
        SET cancel_at_period_end = true, updated_at = $1
        WHERE tenant_id = $2
          AND status IN ('active', 'trialing')
        "#,
    )
    .bind(now)
    .bind(tenant_id)
    .execute(pool)
    .await
    .map_err(SubscriptionError::Db)?
    .rows_affected();

    if affected == 0 {
        return Err(SubscriptionError::NotFound);
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Input types
// ---------------------------------------------------------------------------

pub struct CreateSubscriptionInput {
    pub tenant_id: Uuid,
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

#[derive(sqlx::FromRow)]
struct SubRow {
    id: Uuid,
    tenant_id: Uuid,
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
    #[error("plan not found: {0}")]
    PlanNotFound(String),
    #[error("active subscription not found")]
    NotFound,
    #[error("invalid subscription status: {0}")]
    InvalidStatus(String),
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_status_variants() {
        assert_eq!(parse_status("active").unwrap(), SubscriptionStatus::Active);
        assert_eq!(parse_status("past_due").unwrap(), SubscriptionStatus::PastDue);
        assert_eq!(parse_status("canceled").unwrap(), SubscriptionStatus::Canceled);
        assert_eq!(parse_status("trialing").unwrap(), SubscriptionStatus::Trialing);
        assert_eq!(parse_status("paused").unwrap(), SubscriptionStatus::Paused);
        assert_eq!(parse_status("incomplete").unwrap(), SubscriptionStatus::Incomplete);
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
            tenant_id: Uuid::new_v4(),
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
            tenant_id: Uuid::new_v4(),
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
}
