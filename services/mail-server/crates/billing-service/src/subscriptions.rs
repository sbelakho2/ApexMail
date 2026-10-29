//! Subscription management – create, get, update plan, cancel.
//!
//! NEUTRALITY-DEBT (external audit P0-A): provider decisions here (credential
//! revocation) go through the neutral
//! [`crate::payments::PaymentProvider`] boundary resolved by
//! [`crate::payments::registry::from_env`], and revocation reads/writes the
//! NEUTRAL `payment_credentials` ledger (N-04 retired, audit step 7).
//!
//! N-01/N-03 RESOLVED (beta authority inversion): entitlement reads come
//! from the LOCAL subscription state (the billing-cycle row the webhook
//! writers and the local renewal worker maintain) joined with the tenant's
//! effective plan; the public DTO carries no provider object ids (a legacy
//! contract id survives for reconciliation on the neutral
//! `subscription_payment_bindings` row, keyed by the local subscription id).
//! The physical table name the state lives in is legacy provider-tagged
//! vocabulary; its rename is the owner-gated step-10 table retirement.
//!
//! The payment provider is the payment authority for CHECKOUTS: subscription
//! persistence and plan activation are driven by verified provider webhooks,
//! and direct create/plan changes remain refused. CANCELLATION is different
//! (external audit 15 Oct, H1): ApexMail owns the subscription state, so a
//! customer cancelling from the product is a LOCAL state change,
//! `cancel_at_period_end` stops the next renewal charge and the local
//! renewal worker ends the subscription when the period actually ends. The
//! old refusal pointed customers at a provider hosted billing portal that
//! does not exist, leaving them no way to stop being charged.

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
/// Verified provider webhook handling owns subscription persistence. The
/// input shape keeps no provider object ids (N-01): a subscription is local
/// state, created by the webhook-verified activation only.
pub async fn create_subscription(
    _pool: &PgPool,
    _input: CreateSubscriptionInput,
) -> Result<Subscription, SubscriptionError> {
    Err(SubscriptionError::PaymentConfirmationRequired)
}

/// SQL used by [`get_subscription`] to read the live subscription.
///
/// Fix C, entitlement writers only ever touch the local subscription state +
/// `tenants.plan`; the legacy `subscriptions` table stays empty, so reads
/// resolve against the live subscription row (period bounds live in
/// billing_cycle_start/end) and join tenants for the effective plan name.
///
/// N-03 (beta authority inversion): the LOCAL row is the authority this
/// reader resolves; only the physical table name is provider-tagged legacy
/// vocabulary (owner-gated step-10 rename).
const GET_SUBSCRIPTION_SQL: &str = r#"
        SELECT
            s.id, s.tenant_id,
            COALESCE(t.plan, 'free') AS plan_name,
            s.status, s.billing_interval,
            s.billing_cycle_start AS current_period_start,
            s.billing_cycle_end AS current_period_end,
            s.cancel_at_period_end, s.created_at, s.updated_at
        FROM mollie_subscriptions s
        JOIN tenants t ON t.id = s.tenant_id
        WHERE s.tenant_id = $1
          AND s.status IN ('active', 'trialing', 'past_due')
        ORDER BY s.created_at DESC
        LIMIT 1
        "#;

/// Get the active subscription for a tenant.
pub async fn get_subscription(
    pool: &PgPool,
    tenant_id: &str,
) -> Result<Option<Subscription>, SubscriptionError> {
    let row: Option<SubRow> = sqlx::query_as(GET_SUBSCRIPTION_SQL)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
        .map_err(SubscriptionError::Db)?;

    row.map(|r| r.into_subscription()).transpose()
}

/// Direct subscription changes are deliberately blocked. Mollie is the source
/// of payment confirmation, and only verified Mollie webhook processing may
/// update an entitlement-bearing tenant plan.
pub async fn update_plan(
    _pool: &PgPool,
    _tenant_id: &str,
    _new_plan: &str,
) -> Result<(), SubscriptionError> {
    Err(SubscriptionError::PaymentConfirmationRequired)
}

/// Direct local cancellation, the self-service stop for the next renewal.
///
/// `immediately == false` (the normal case) records `cancel_at_period_end`
/// and keeps access until `billing_cycle_end`; the period-end sweep then
/// marks the subscription canceled and downgrades the tenant. `immediately`
/// ends the subscription and downgrades the tenant now. Idempotent: a repeat
/// keeps the original `canceled_at`.
///
/// The state change is written in one transaction with a chained audit row;
/// no provider call is required because Mollie's Subscription processing model
/// is merchant-initiated (there is no provider-side plan that keeps charging
/// on its own). Every renewal path reads this row, so the next charge stops.
/// Revoke the tenant's Mollie mandate at the provider.
///
/// A local cancellation stops OUR charges, but a live stored credential at
/// the provider is still a standing permission to debit the customer.
/// Revoking it is the only provider-side guarantee, so cancellation calls
/// this and records the result on the neutral `payment_credentials` row
/// (`revoked_at` NULL on an active credential after a canceled subscription
/// is the retry signal for the maintenance sweep; N-04 retired).
///
/// Returns `Ok(false)` when the tenant has no stored mandate or Mollie is not
/// configured (nothing to revoke). Provider failures are returned so the
/// caller can log them without failing the already-committed cancellation.
pub async fn revoke_tenant_mandate_at_provider(
    pool: &PgPool,
    tenant_id: &str,
) -> Result<bool, String> {
    let revoked =
        revoke_tenant_mandates_at_provider(pool, std::slice::from_ref(&tenant_id.to_string()))
            .await?;
    Ok(revoked > 0)
}

/// Batch form: ONE lookup for every tenant, then one provider revoke each.
/// The period-end sweep must not add a per-row SELECT to its set-based path.
///
/// N-04 RETIRED (audit step 7): stored credentials are read from and
/// revocations are stamped back to the NEUTRAL `payment_credentials` table
/// (the legacy `mollie_customers.mandate_revoked_at` mirror has no readers
/// left and is no longer written). The provider call goes through the
/// neutral boundary as before.
pub async fn revoke_tenant_mandates_at_provider(
    pool: &PgPool,
    tenant_ids: &[String],
) -> Result<u64, String> {
    if tenant_ids.is_empty() {
        return Ok(0);
    }
    let stored: Vec<(String, String, String)> = sqlx::query_as(
        r#"
        SELECT DISTINCT ON (pc.tenant_id)
               pc.tenant_id, pc.provider_customer_id, pc.provider_method_id
        FROM payment_credentials pc
        WHERE pc.tenant_id = ANY($1)
          AND pc.state = 'active'
          AND pc.revoked_at IS NULL
        ORDER BY pc.tenant_id, pc.created_at DESC
        "#,
    )
    .bind(tenant_ids)
    .fetch_all(pool)
    .await
    .map_err(|error| format!("Failed to load the tenant payment credentials: {error}"))?;

    let Ok(provider) = crate::payments::registry::from_env() else {
        return Ok(0);
    };
    let mut revoked = 0u64;
    for (tenant_id, customer_id, method_id) in stored {
        provider
            .revoke_saved_method(&customer_id, &method_id)
            .await
            .map_err(|error| {
                format!("Mollie mandate revocation for tenant {tenant_id} failed: {error}")
            })?;
        sqlx::query(
            "UPDATE payment_credentials
                SET state = 'failed', revoked_at = NOW(), updated_at = NOW()
              WHERE provider = $1 AND provider_method_id = $2",
        )
        .bind(provider.provider_name())
        .bind(&method_id)
        .execute(pool)
        .await
        .map_err(|error| format!("Failed to record the credential revocation: {error}"))?;
        revoked += 1;
    }
    Ok(revoked)
}

pub async fn cancel_subscription(
    pool: &PgPool,
    tenant_id: &str,
    immediately: bool,
) -> Result<Subscription, SubscriptionError> {
    let mut tx = pool.begin().await.map_err(SubscriptionError::Db)?;

    // Serialize concurrent cancels for this tenant; only a live subscription
    // can be canceled.
    let row: Option<(Uuid,)> = sqlx::query_as(
        r#"
        SELECT id
        FROM mollie_subscriptions
        WHERE tenant_id = $1
          AND status IN ('active', 'trialing', 'past_due', 'unpaid')
        ORDER BY created_at DESC
        LIMIT 1
        FOR UPDATE
        "#,
    )
    .bind(tenant_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(SubscriptionError::Db)?;
    let Some((subscription_id,)) = row else {
        tx.rollback().await.ok();
        return Err(SubscriptionError::NotFound);
    };

    let now = Utc::now();
    let action = if immediately {
        sqlx::query(
            "UPDATE mollie_subscriptions
                SET status = 'canceled',
                    cancel_at_period_end = false,
                    canceled_at = COALESCE(canceled_at, $2),
                    updated_at = $2
              WHERE id = $1",
        )
        .bind(subscription_id)
        .bind(now)
        .execute(&mut *tx)
        .await
        .map_err(SubscriptionError::Db)?;
        sqlx::query(
            "UPDATE tenants SET plan = 'free', updated_at = $2
              WHERE id = $1 AND plan <> 'free'",
        )
        .bind(tenant_id)
        .bind(now)
        .execute(&mut *tx)
        .await
        .map_err(SubscriptionError::Db)?;
        "billing.subscription_canceled"
    } else {
        sqlx::query(
            "UPDATE mollie_subscriptions
                SET cancel_at_period_end = true,
                    canceled_at = COALESCE(canceled_at, $2),
                    updated_at = $2
              WHERE id = $1",
        )
        .bind(subscription_id)
        .bind(now)
        .execute(&mut *tx)
        .await
        .map_err(SubscriptionError::Db)?;
        "billing.subscription_canceled_at_period_end"
    };

    crate::routes::append_audit_log(
        &mut tx,
        tenant_id,
        action,
        "subscription",
        Some(&subscription_id.to_string()),
        serde_json::json!({
            "immediately": immediately,
            "effectiveAt": if immediately { now.to_rfc3339() } else { "period_end".to_string() },
        }),
        now,
    )
    .await
    .map_err(|error| SubscriptionError::Db(sqlx::Error::Protocol(error)))?;

    tx.commit().await.map_err(SubscriptionError::Db)?;

    // Immediate cancellation revokes the stored credential at the provider
    // (the standing permission to debit the customer). There is no
    // provider-side SUBSCRIPTION to cancel: the local row is the renewal
    // authority, so stopping the local row stops the charges. Revocation is
    // best-effort by design (the local cancel is committed); failures are
    // retried by the maintenance sweep.
    if immediately {
        if let Err(error) = revoke_tenant_mandate_at_provider(pool, tenant_id).await {
            tracing::warn!(
                tenant_id = %tenant_id,
                error = %error,
                "subscription canceled locally but the stored-credential revocation failed; the sweep will retry"
            );
        }
    }

    subscription_by_id(pool, subscription_id).await
}

/// Retry credential revocations for tenants whose subscription ended but
/// whose stored payment credential is still live at the provider
/// (`payment_credentials.revoked_at IS NULL`). Idempotent: the provider
/// call is a DELETE and a successful revoke stamps the neutral row.
pub async fn sweep_pending_mandate_revocations(pool: &PgPool) -> Result<u64, String> {
    let tenants: Vec<String> = sqlx::query_scalar(
        r#"
        SELECT DISTINCT s.tenant_id
        FROM mollie_subscriptions s
        JOIN payment_credentials pc
          ON pc.tenant_id = s.tenant_id
         AND pc.provider_method_id = s.mollie_mandate_id
         AND pc.state = 'active'
         AND pc.revoked_at IS NULL
        WHERE s.status = 'canceled'
          AND s.mollie_mandate_id IS NOT NULL
          AND s.mollie_mandate_id <> ''
        LIMIT 100
        "#,
    )
    .fetch_all(pool)
    .await
    .map_err(|error| format!("Failed to load pending mandate revocations: {error}"))?;

    let mut revoked = 0u64;
    for tenant_id in tenants {
        match revoke_tenant_mandate_at_provider(pool, &tenant_id).await {
            Ok(true) => revoked += 1,
            Ok(false) => {}
            Err(error) => tracing::warn!(
                tenant_id = %tenant_id,
                error = %error,
                "mandate revocation retry failed"
            ),
        }
    }
    Ok(revoked)
}

/// The latest subscription row for a tenant regardless of status (the
/// cancellation response must be able to return a just-canceled row).
const GET_LATEST_SUBSCRIPTION_SQL: &str = r#"
        SELECT
            s.id, s.tenant_id,
            COALESCE(t.plan, 'free') AS plan_name,
            s.status, s.billing_interval,
            s.billing_cycle_start AS current_period_start,
            s.billing_cycle_end AS current_period_end,
            s.cancel_at_period_end, s.created_at, s.updated_at
        FROM mollie_subscriptions s
        JOIN tenants t ON t.id = s.tenant_id
        WHERE s.id = $1
        "#;

async fn subscription_by_id(
    pool: &PgPool,
    subscription_id: Uuid,
) -> Result<Subscription, SubscriptionError> {
    let row: SubRow = sqlx::query_as(GET_LATEST_SUBSCRIPTION_SQL)
        .bind(subscription_id)
        .fetch_one(pool)
        .await
        .map_err(SubscriptionError::Db)?;
    row.into_subscription()
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

    // ------------------------------------------------------------------
    // Fix C, the subscription reader must target the table the Mollie
    // webhook writers actually populate.
    // ------------------------------------------------------------------

    #[test]
    fn get_subscription_reads_mollie_subscriptions_not_legacy_table() {
        assert!(GET_SUBSCRIPTION_SQL.contains("FROM mollie_subscriptions s"));
        assert!(!GET_SUBSCRIPTION_SQL.contains("FROM subscriptions\n"));
        assert!(GET_SUBSCRIPTION_SQL.contains("JOIN tenants t"));
        assert!(GET_SUBSCRIPTION_SQL.contains("s.billing_cycle_start"));
        assert!(GET_SUBSCRIPTION_SQL.contains("s.billing_cycle_end"));
    }

    #[tokio::test]
    async fn direct_creation_and_plan_changes_never_touch_the_database() {
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
                },
            )
            .await,
            Err(SubscriptionError::PaymentConfirmationRequired)
        ));
        assert!(matches!(
            update_plan(&pool, "tenant_123", "growth").await,
            Err(SubscriptionError::PaymentConfirmationRequired)
        ));
        // Cancellation is NOT in this refusal family any more (audit 15 Oct,
        // H1): it is a real local state change covered by the DB-backed test
        // below.
    }

    /// External audit 15 Oct, H1: self-service cancellation stops the next
    /// renewal (period end by default; immediate ends access and downgrades).
    #[tokio::test]
    async fn cancellation_stops_at_period_end_and_immediate_cancellation_downgrades() {
        let Some(env) = crate::test_support::provision("subscriptions_cancel").await else {
            return;
        };
        let suffix = uuid::Uuid::new_v4().simple().to_string();
        let tenant = format!("subcancel-{}", &suffix[..10]);
        crate::test_support::seed_tenant(&env.pool, &tenant, "growth").await;
        sqlx::query(
            "INSERT INTO mollie_subscriptions
                 (tenant_id, mollie_subscription_id, plan, status, billing_cycle_start,
                  billing_cycle_end, mollie_customer_id)
             VALUES ($1, $2, 'growth', 'active', NOW(), NOW() + INTERVAL '30 days', $1)",
        )
        .bind(&tenant)
        .bind(format!("psp_{}", &suffix[..12]))
        .execute(&env.pool)
        .await
        .expect("seed subscription");

        let subscription = cancel_subscription(&env.pool, &tenant, false)
            .await
            .expect("period-end cancellation");
        assert!(subscription.cancel_at_period_end);
        assert_eq!(subscription.status, SubscriptionStatus::Active);
        let (status, cancel_at_period_end, canceled_at): (String, bool, Option<String>) =
            sqlx::query_as(
                "SELECT status, cancel_at_period_end, canceled_at::text
                   FROM mollie_subscriptions WHERE tenant_id = $1",
            )
            .bind(&tenant)
            .fetch_one(&env.pool)
            .await
            .unwrap();
        assert_eq!(status, "active");
        assert!(cancel_at_period_end);
        assert!(canceled_at.is_some());

        // Replay keeps the original instant.
        let again = cancel_subscription(&env.pool, &tenant, false)
            .await
            .expect("idempotent replay");
        assert!(again.cancel_at_period_end);
        let (replay_instant,): (Option<String>,) = sqlx::query_as(
            "SELECT canceled_at::text FROM mollie_subscriptions WHERE tenant_id = $1",
        )
        .bind(&tenant)
        .fetch_one(&env.pool)
        .await
        .unwrap();
        assert_eq!(replay_instant, canceled_at);

        // Immediate cancellation ends it now and downgrades the tenant.
        let immediate = cancel_subscription(&env.pool, &tenant, true)
            .await
            .expect("immediate cancellation");
        assert_eq!(immediate.status, SubscriptionStatus::Canceled);
        let (plan,): (String,) = sqlx::query_as("SELECT plan FROM tenants WHERE id = $1")
            .bind(&tenant)
            .fetch_one(&env.pool)
            .await
            .unwrap();
        assert_eq!(plan, "free");

        // No subscription → NotFound (never a fabricated success).
        assert!(matches!(
            cancel_subscription(&env.pool, "no-such-tenant", false).await,
            Err(SubscriptionError::NotFound)
        ));
        env.finish().await;
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
