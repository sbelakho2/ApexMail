//! Plan billing against Mollie subscriptions.
//!
//! The product's documented model: a paid, VERIFIED checkout activates the
//! plan, the provider mints the mandate, and a Mollie SUBSCRIPTION
//! (`sub_…`) is what grants and renews it. This module owns that lifecycle:
//!
//! * [`activate_from_paid_checkout`] — a settled checkout payment is mapped
//!   back to an active catalog plan ONLY when its amount matches the catalog
//!   for the paid interval/currency; a Mollie subscription is created and its
//!   id is stored; the charge becomes a PAID invoice (VAT extracted from the
//!   gross) with its allocation and statutory postings; the tenant plan
//!   changes in the same transaction as the subscription row.
//! * [`renew_from_paid_subscription`] — a Mollie subscription charge settles
//!   the NEXT period: one paid invoice per payment (idempotent on the payment
//!   id), the cycle advances, the tenant stays active.
//! * [`mark_subscription_payment_failed`] — a failed subscription charge
//!   moves the row to `past_due`; Mollie retries its own charges, so the local
//!   dunning retry path deliberately does not charge these rows.
//! * [`sweep_provider_subscription_state`] — provider state is reconciled
//!   from authenticated fetches: only `active` grants the plan; `canceled`,
//!   `completed`, `suspended` and `pending` resolve the tenant to Free.
//! * [`cancel_provider_subscription`] — cancellation stops Mollie's own
//!   charge generation (`DELETE …/subscriptions/{sub}`) and revokes the
//!   mandate.
//!
//! Every provider call is idempotent-keyed, and every local write is guarded
//! by the moment's authoritative check (payment id, subscription id, period).

use chrono::{DateTime, Months, Utc};
use sqlx::Connection as _;
use sqlx::PgPool;
use uuid::Uuid;

use crate::mollie_client::{CreateSubscription, MollieClient, Money};
use crate::routes::append_audit_log;

/// The self-serve plans a generic checkout may sell.
pub const SELF_SERVE_PLAN_IDS: &[&str] = &["starter", "pro", "growth", "scale"];

pub fn interval_months(interval: &str) -> Option<u32> {
    match interval.trim().to_ascii_lowercase().as_str() {
        "monthly" => Some(1),
        "yearly" | "annual" => Some(12),
        _ => None,
    }
}

/// Mollie subscription interval strings are fixed: `1 month`, `12 months`.
fn mollie_interval(months: u32) -> String {
    if months == 1 {
        "1 month".to_string()
    } else {
        format!("{months} months")
    }
}

/// The catalog amount for a plan/interval/currency, or `None` when the plan is
/// not self-serve billable in that currency.
pub fn catalog_amount_cents(plan_name: &str, interval: &str, currency: &str) -> Option<i64> {
    let plan = platform_catalog::plan_by_name(plan_name)?;
    if !SELF_SERVE_PLAN_IDS.contains(&plan.name) {
        return None;
    }
    let yearly = interval_months(interval)? == 12;
    let usd = currency.trim().eq_ignore_ascii_case("USD");
    let cents = match (usd, yearly) {
        (true, true) => plan.price_yearly_usd_cents,
        (true, false) => plan.price_monthly_usd_cents,
        (false, true) => plan.price_yearly_cents,
        (false, false) => plan.price_monthly_cents,
    };
    (cents > 0).then_some(cents)
}

/// The monthly-normalized catalog price of a plan/interval, in EUR cents
/// (round-half-up yearly math, mirroring the revenue analytics). Used ONLY to
/// classify a plan change in the activation audit: upgrade/downgrade and the
/// expansion/contraction MRR.
fn catalog_monthly_mrr_cents(plan_name: &str, interval: &str) -> i64 {
    let Some(plan) = platform_catalog::plan_by_name(plan_name) else {
        return 0;
    };
    if interval_months(interval) == Some(12) {
        (plan.price_yearly_cents + 6) / 12
    } else {
        plan.price_monthly_cents
    }
}

fn period_end(start: DateTime<Utc>, months: u32) -> Result<DateTime<Utc>, String> {
    start
        .checked_add_months(Months::new(months))
        .ok_or_else(|| "billing period end overflow".to_string())
}

/// What activation decided, for the caller's log line.
#[derive(Debug)]
pub struct ActivationOutcome {
    pub invoice_id: Option<Uuid>,
    pub mollie_subscription_id: Option<String>,
    pub already_active: bool,
}

/// The per-tenant writer lock for billing state transitions.
///
/// Provider calls do NOT participate in the Postgres transaction, so the
/// serialization point must come BEFORE any provider mutation: two verified
/// checkouts for the same tenant arriving together would otherwise both read
/// the old subscription, both create a distinct Mollie `sub_…` (their
/// idempotency keys differ by payment id) and both adopt it — leaving an
/// orphan provider subscription the reconciliation sweep can never discover.
/// The lock is a SESSION advisory lock held on one dedicated connection for
/// the whole operation (provider I/O included); the inner transaction then
/// runs on that same connection, so a transaction-level re-acquire of the
/// same key is re-entrant and cannot self-deadlock.
async fn run_under_tenant_billing_lock<T>(
    pool: &PgPool,
    key: String,
    operation: &'static str,
    f: impl for<'a> FnOnce(
        &'a mut sqlx::PgConnection,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<T, String>> + Send + 'a>,
    >,
) -> Result<T, String> {
    let mut conn = pool
        .acquire()
        .await
        .map_err(|error| format!("{operation}: connection acquire failed: {error}"))?;
    sqlx::query("SELECT pg_advisory_lock(hashtext($1))")
        .bind(&key)
        .execute(&mut *conn)
        .await
        .map_err(|error| format!("{operation}: tenant lock failed: {error}"))?;
    let outcome = f(&mut conn).await;
    // The lock lives on this pooled connection: if the unlock fails, the
    // connection must NOT return to the pool (a later borrower would inherit
    // the lock and deadlock the next activation). Close it instead.
    if let Err(error) = sqlx::query("SELECT pg_advisory_unlock(hashtext($1))")
        .bind(&key)
        .execute(&mut *conn)
        .await
    {
        tracing::error!(
            lock = %key,
            error = %error,
            "tenant billing lock release failed — closing the pooled connection"
        );
        let _ = conn.close().await;
    }
    outcome
}

/// Raise a finance incident, deduplicated per (kind, provider id) while it is
/// still open: an hourly sweep must not file the same finding twice.
pub(crate) async fn raise_billing_incident(
    db: &sqlx::PgPool,
    kind: &'static str,
    severity: &'static str,
    tenant_id: Option<&str>,
    provider_id: Option<&str>,
    detail: serde_json::Value,
) {
    let query = sqlx::query(
        "INSERT INTO finance_incidents (kind, severity, status, tenant_id, mollie_payment_id, detail, created_at) \
         VALUES ($1, $2, 'open', $3, $4, $5, NOW()) \
         ON CONFLICT (kind, mollie_payment_id) WHERE status = 'open' AND mollie_payment_id IS NOT NULL DO NOTHING",
    )
    .bind(kind)
    .bind(severity)
    .bind(tenant_id)
    .bind(provider_id)
    .bind(detail);
    if let Err(error) = query.execute(db).await {
        tracing::error!(kind = %kind, error = %error, "finance incident insert failed");
    }
}

/// Activate a plan from a paid checkout payment.
///
/// The caller has already verified the payment with the provider (the webhook
/// fetched it). The metadata is OUR checkout metadata; the amount is the
/// verified gross charge.
///
/// Ordering (the activation saga, serialized per tenant by the billing lock):
/// 1. read the superseded subscriptions' facts (nothing is mutated yet),
/// 2. create the NEW provider subscription (its idempotency key replays on
///    retry instead of minting a second object),
/// 3. adopt it locally in ONE transaction (row upsert, tenant plan, paid
///    invoice, allocation, postings, audit) — the old subscription is still
///    intact if any step fails, so the customer's billing never lapses,
/// 4. only after the commit, retire the superseded provider subscriptions; a
///    failed retirement raises an incident and the sweep's orphan detection
///    cancels the straggler.
///
/// On an adoption failure the NEW provider subscription is canceled again, so
/// no live provider object can outlive its local adoption.
#[allow(clippy::too_many_arguments)]
pub async fn activate_from_paid_checkout(
    pool: &PgPool,
    payment_id: &str,
    tenant_id: &str,
    plan_name: &str,
    interval: &str,
    currency: &str,
    gross_cents: i64,
    customer_id: Option<&str>,
    mandate_id: Option<&str>,
) -> Result<ActivationOutcome, String> {
    let months = interval_months(interval)
        .ok_or_else(|| format!("unknown billing interval {interval:?}"))?;
    let expected = catalog_amount_cents(plan_name, interval, currency).ok_or_else(|| {
        format!("plan {plan_name:?} is not self-serve billable for {interval} in {currency}")
    })?;
    if gross_cents != expected {
        return Err(format!(
            "checkout payment {payment_id} charged {gross_cents} {currency} but the catalog price for \
             {plan_name} ({interval}) is {expected} — refusing to grant a mismatched entitlement"
        ));
    }
    let (Some(customer_id), Some(mandate_id)) = (customer_id, mandate_id) else {
        // The money moved but no reusable method exists: refund and report.
        // Idempotent on the refund's idempotency key; no local state changes,
        // so it needs no tenant serialization.
        refund_unusable_checkout(pool, payment_id, gross_cents, currency).await?;
        return Ok(ActivationOutcome {
            invoice_id: None,
            mollie_subscription_id: None,
            already_active: false,
        });
    };

    let now = Utc::now();
    let start = now;
    let end = period_end(start, months)?;
    let display_name = platform_catalog::plan_by_name(plan_name)
        .map(|plan| plan.display_name.to_string())
        .unwrap_or_else(|| plan_name.to_string());

    // The locked closure owns its inputs (PgPool is an Arc clone; the small
    // strings are cheap) so the boxed future borrows only the connection.
    let inner_pool = pool.clone();
    let payment_id = payment_id.to_string();
    let tenant_id = tenant_id.to_string();
    let plan_name = plan_name.to_string();
    let interval = interval.to_string();
    let currency = currency.to_string();
    let customer_id = customer_id.to_string();
    let mandate_id = mandate_id.to_string();
    run_under_tenant_billing_lock(
        pool,
        format!("billing_plan_activation:{tenant_id}"),
        "plan activation",
        |conn| {
            Box::pin(async move {
                activate_locked(
                    &inner_pool,
                    conn,
                    &payment_id,
                    &tenant_id,
                    &plan_name,
                    &interval,
                    &currency,
                    gross_cents,
                    &customer_id,
                    &mandate_id,
                    months,
                    start,
                    end,
                    display_name,
                )
                .await
            })
        },
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn activate_locked(
    pool: &PgPool,
    conn: &mut sqlx::PgConnection,
    payment_id: &str,
    tenant_id: &str,
    plan_name: &str,
    interval: &str,
    currency: &str,
    gross_cents: i64,
    customer_id: &str,
    mandate_id: &str,
    months: u32,
    start: DateTime<Utc>,
    end: DateTime<Utc>,
    display_name: String,
) -> Result<ActivationOutcome, String> {
    // Already activated (webhook redelivery): the payment id is the natural
    // idempotency key. Re-checked inside the transaction below.
    if let Some(existing) = sqlx::query_scalar::<_, Uuid>(
        "SELECT id FROM invoices WHERE mollie_payment_id = $1 LIMIT 1",
    )
    .bind(payment_id)
    .fetch_optional(&mut *conn)
    .await
    .map_err(|error| format!("activation idempotency check failed: {error}"))?
    {
        return Ok(ActivationOutcome {
            invoice_id: Some(existing),
            mollie_subscription_id: None,
            already_active: true,
        });
    }

    // The superseded subscriptions are READ here (ids for the post-commit
    // retirement, plan facts for the change analytics) but NOT mutated: the
    // old recurring arrangement must survive until the replacement is durably
    // adopted, or any later failure would leave the customer with NO live
    // subscription at all. The upsert below flips these rows to `canceled`.
    type PreviousSubscription = (String, Option<String>, Option<String>, Option<String>);
    let previous: Vec<PreviousSubscription> = sqlx::query_as(
        "SELECT mollie_subscription_id, mollie_customer_id, plan, billing_interval \
         FROM mollie_subscriptions \
         WHERE tenant_id = $1 AND left(mollie_subscription_id, 4) = 'sub_' \
           AND status IN ('active', 'trialing', 'past_due', 'unpaid') \
         ORDER BY created_at DESC",
    )
    .bind(tenant_id)
    .fetch_all(&mut *conn)
    .await
    .map_err(|error| format!("previous subscription lookup failed: {error}"))?;
    let mut previous_plan: Option<String> = None;
    let mut previous_interval: Option<String> = None;
    let mut previous_mrr_cents: i64 = 0;
    let mut superseded: Vec<(String, String)> = Vec::new();
    for (subscription_id, previous_customer, plan, previous_iv) in previous {
        if previous_plan.is_none() {
            previous_mrr_cents = plan
                .as_deref()
                .zip(previous_iv.as_deref())
                .map(|(plan, interval)| catalog_monthly_mrr_cents(plan, interval))
                .unwrap_or(0);
            previous_plan = plan;
            previous_interval = previous_iv;
        }
        if let Some(previous_customer) = previous_customer.filter(|id| !id.trim().is_empty()) {
            superseded.push((previous_customer, subscription_id));
        }
    }
    let new_mrr_cents = catalog_monthly_mrr_cents(plan_name, interval);

    // Provider object first: its id is required by the (NOT NULL, unique)
    // column, and an idempotency key makes a retried webhook replay the same
    // subscription rather than minting a second one.
    let mollie = MollieClient::from_env().map_err(|error| error.to_string())?;
    let subscription = mollie
        .create_subscription(CreateSubscription {
            customer_id: customer_id.to_string(),
            mandate_id: Some(mandate_id.to_string()),
            amount: Money::new(currency, gross_cents),
            interval: mollie_interval(months),
            description: format!("ApexMail {display_name}"),
            webhook_url: None,
            metadata: serde_json::json!({
                "tenant_id": tenant_id,
                "plan_name": plan_name,
                "interval": interval,
            }),
            start_date: Some(end.format("%Y-%m-%d").to_string()),
            idempotency_key: format!("plan_sub_{tenant_id}_{payment_id}"),
        })
        .await
        .map_err(|error| format!("Mollie subscription creation failed: {error}"))?;
    let provider_id = subscription.id;
    if provider_id.trim().is_empty() {
        return Err("Mollie subscription response carries no id".into());
    }

    // Everything below must succeed together. If it does not, the provider
    // subscription created above is canceled again: a live provider object
    // that charges a customer with no local plan/invoice is worse than a
    // failed webhook (which Mollie retries).
    let db_outcome: Result<ActivationOutcome, String> = async {
        let mut tx = conn
            .begin()
            .await
            .map_err(|error| format!("activation transaction failed: {error}"))?;
        sqlx::query("SELECT pg_advisory_xact_lock(hashtext($1))")
            .bind(format!("billing_plan_activation:{tenant_id}"))
            .execute(&mut *tx)
            .await
            .map_err(|error| format!("activation lock failed: {error}"))?;

        // Re-check inside the lock (a concurrent delivery may have won).
        if let Some(existing) = sqlx::query_scalar::<_, Uuid>(
            "SELECT id FROM invoices WHERE mollie_payment_id = $1 LIMIT 1",
        )
        .bind(payment_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|error| format!("activation idempotency check failed: {error}"))?
        {
            return Ok(ActivationOutcome {
                invoice_id: Some(existing),
                mollie_subscription_id: Some(provider_id.clone()),
                already_active: true,
            });
        }

        sqlx::query(
            r#"
        INSERT INTO mollie_subscriptions (
            id, tenant_id, mollie_subscription_id, plan, status, billing_interval,
            billing_cycle_start, billing_cycle_end, mollie_customer_id, mollie_mandate_id,
            mollie_sequence_type, cancel_at_period_end, canceled_at, created_at, updated_at
        ) VALUES (
            gen_random_uuid(), $1, $2, $3, 'active', $4,
            $5, $6, $7, $8, 'recurring', false, NULL, NOW(), NOW()
        )
        ON CONFLICT (tenant_id) WHERE status = 'active' DO UPDATE SET
            mollie_subscription_id = EXCLUDED.mollie_subscription_id,
            plan = EXCLUDED.plan,
            billing_interval = EXCLUDED.billing_interval,
            billing_cycle_start = EXCLUDED.billing_cycle_start,
            billing_cycle_end = EXCLUDED.billing_cycle_end,
            mollie_customer_id = EXCLUDED.mollie_customer_id,
            mollie_mandate_id = EXCLUDED.mollie_mandate_id,
            mollie_sequence_type = EXCLUDED.mollie_sequence_type,
            cancel_at_period_end = false,
            canceled_at = NULL,
            updated_at = NOW()
        "#,
        )
        .bind(tenant_id)
        .bind(&provider_id)
        .bind(plan_name)
        .bind(interval.trim().to_ascii_lowercase())
        .bind(start)
        .bind(end)
        .bind(customer_id)
        .bind(mandate_id)
        .execute(&mut *tx)
        .await
        .map_err(|error| format!("subscription upsert failed: {error}"))?;

        sqlx::query("UPDATE tenants SET plan = $2, updated_at = NOW() WHERE id = $1")
            .bind(tenant_id)
            .bind(plan_name)
            .execute(&mut *tx)
            .await
            .map_err(|error| format!("tenant plan update failed: {error}"))?;

        let invoice = crate::invoices::create_paid_plan_invoice_in_tx(
            &mut tx,
            tenant_id,
            &display_name,
            interval,
            gross_cents,
            currency,
            payment_id,
            start,
            end,
        )
        .await
        .map_err(|error| format!("plan invoice creation failed: {error}"))?;

        // The settlement allocation and the statutory ledger, in the same
        // transaction as the invoice (idempotent on the operation id).
        let operation_id = format!("mollie:{payment_id}");
        sqlx::query(
            r#"
        INSERT INTO invoice_payment_allocations (
            id, tenant_id, invoice_id, operation_id, source, amount_cents, currency
        ) VALUES (gen_random_uuid(), $1, $2, $3, 'mollie', $4, $5)
        ON CONFLICT (operation_id) DO NOTHING
        "#,
        )
        .bind(tenant_id)
        .bind(invoice.id)
        .bind(&operation_id)
        .bind(gross_cents)
        .bind(currency.trim().to_ascii_uppercase())
        .execute(&mut *tx)
        .await
        .map_err(|error| format!("plan allocation failed: {error}"))?;
        crate::accounting_postings::post_invoice_issued_in(&mut tx, invoice.id).await;
        crate::accounting_postings::post_payment_allocation_in(&mut tx, &operation_id).await;

        append_audit_log(
            &mut tx,
            tenant_id,
            "billing.subscription_activated",
            "subscription",
            Some(&provider_id),
            serde_json::json!({
                "paymentId": payment_id,
                "plan": plan_name,
                "interval": interval,
                "grossCents": gross_cents,
                "currency": currency.trim().to_ascii_uppercase(),
                "periodStart": start.to_rfc3339(),
                "periodEnd": end.to_rfc3339(),
                // Plan-change analytics: the MRR before and after this
                // verified checkout. A zero/absent previous fact means "new
                // subscription".
                "previousPlan": previous_plan,
                "previousInterval": previous_interval,
                "previousMrrCents": previous_mrr_cents,
                "newMrrCents": new_mrr_cents,
            }),
            Utc::now(),
        )
        .await
        .map_err(|error| format!("activation audit failed: {error}"))?;

        tx.commit()
            .await
            .map_err(|error| format!("activation commit failed: {error}"))?;

        Ok(ActivationOutcome {
            invoice_id: Some(invoice.id),
            mollie_subscription_id: Some(provider_id.clone()),
            already_active: false,
        })
    }
    .await;

    // The adoption is durable — NOW the superseded provider subscriptions
    // may stop charging. A failed retirement is an incident (the customer
    // would keep paying the old plan) and the sweep's orphan detection
    // cancels the straggler on its next pass.
    if db_outcome.is_ok() {
        for (previous_customer, previous_subscription) in &superseded {
            if let Err(error) =
                cancel_provider_subscription_object(previous_customer, previous_subscription).await
            {
                tracing::error!(
                    tenant_id = %tenant_id,
                    subscription_id = %previous_subscription,
                    error = %error,
                    "superseded Mollie subscription could not be retired after adoption — \
                     incident raised; the reconciliation sweep cancels it"
                );
                raise_billing_incident(
                    pool,
                    "mollie_superseded_subscription_cancel_failed",
                    "high",
                    Some(tenant_id),
                    Some(previous_subscription),
                    serde_json::json!({
                        "tenantId": tenant_id,
                        "subscriptionId": previous_subscription,
                        "customerId": previous_customer,
                        "error": error,
                    }),
                )
                .await;
            }
        }
    }

    if db_outcome.is_err() {
        if let Err(cancel_error) =
            cancel_provider_subscription_object(customer_id, &provider_id).await
        {
            tracing::error!(
                tenant_id = %tenant_id,
                subscription_id = %provider_id,
                error = %cancel_error,
                "activation failed and the compensating provider cancellation also failed — \
                 a live provider subscription has no local plan; the reconciliation sweep reports it"
            );
        }
    }
    db_outcome
}

/// A paid checkout that produced no mandate cannot recur: refund it in full
/// and record why. Idempotent on the payment id.
async fn refund_unusable_checkout(
    pool: &PgPool,
    payment_id: &str,
    gross_cents: i64,
    currency: &str,
) -> Result<(), String> {
    let mollie = MollieClient::from_env().map_err(|error| error.to_string())?;
    let refund = mollie
        .create_refund(
            payment_id,
            Money::new(currency, gross_cents),
            "Plan activation needs a reusable payment method; refunded automatically",
            &format!("plan_refund_no_mandate_{payment_id}"),
        )
        .await
        .map_err(|error| format!("automatic refund failed for {payment_id}: {error}"))?;
    sqlx::query(
        "INSERT INTO mollie_refunds (id, payment_id, amount_cents, currency, status)
         VALUES ($1, $2, $3, $4, 'created') ON CONFLICT (id) DO NOTHING",
    )
    .bind(&refund.id)
    .bind(payment_id)
    .bind(gross_cents)
    .bind(currency.trim().to_ascii_uppercase())
    .execute(pool)
    .await
    .map_err(|error| format!("refund mapping failed: {error}"))?;
    sqlx::query(
        "INSERT INTO finance_incidents (kind, severity, status, detail, created_at)
         VALUES ('mollie_plan_payment_without_mandate', 'high', 'open', $1, NOW())",
    )
    .bind(serde_json::json!({
        "paymentId": payment_id,
        "amountCents": gross_cents,
        "currency": currency.trim().to_ascii_uppercase(),
        "action": "refunded; the customer must retry with a reusable method",
    }))
    .execute(pool)
    .await
    .map_err(|error| format!("incident write failed: {error}"))?;
    Ok(())
}

/// Settle the NEXT period of a provider subscription from a paid payment.
pub async fn renew_from_paid_subscription(
    pool: &PgPool,
    payment_id: &str,
    provider_subscription_id: &str,
    gross_cents: i64,
    currency: &str,
) -> Result<Option<Uuid>, String> {
    // The tenant/plan/interval live on OUR subscription row: Mollie
    // subscription payments are identified by `subscriptionId`, and trusting
    // payment metadata for them would let a forged body pick the plan.
    let row_meta: Option<(String, Option<String>, Option<String>)> = sqlx::query_as(
        "SELECT tenant_id, plan, billing_interval FROM mollie_subscriptions \
         WHERE mollie_subscription_id = $1",
    )
    .bind(provider_subscription_id)
    .fetch_optional(pool)
    .await
    .map_err(|error| format!("subscription row load failed: {error}"))?;
    let Some((tenant_id, plan, interval)) = row_meta else {
        return Err(format!(
            "subscription payment {payment_id} names unknown provider subscription              {provider_subscription_id}"
        ));
    };
    let plan_name = plan.ok_or_else(|| {
        format!(
            "subscription {provider_subscription_id} carries no local plan — reconciled separately"
        )
    })?;
    let interval = interval.unwrap_or_else(|| "monthly".to_string());
    let months = interval_months(&interval)
        .ok_or_else(|| format!("unknown billing interval {interval:?}"))?;
    let expected = catalog_amount_cents(&plan_name, &interval, currency).ok_or_else(|| {
        format!("plan {plan_name:?} is not self-serve billable for {interval} in {currency}")
    })?;
    if gross_cents != expected {
        return Err(format!(
            "subscription payment {payment_id} charged {gross_cents} {currency} but the catalog \
             price for {plan_name} ({interval}) is {expected}"
        ));
    }
    if let Some(existing) = sqlx::query_scalar::<_, Uuid>(
        "SELECT id FROM invoices WHERE mollie_payment_id = $1 LIMIT 1",
    )
    .bind(payment_id)
    .fetch_optional(pool)
    .await
    .map_err(|error| format!("renewal idempotency check failed: {error}"))?
    {
        return Ok(Some(existing));
    }
    let display_name = platform_catalog::plan_by_name(&plan_name)
        .map(|plan| plan.display_name.to_string())
        .unwrap_or_else(|| plan_name.clone());
    let now = Utc::now();

    // Same per-tenant serialization as activation: two renewal deliveries
    // racing must not double-advance the cycle or double-invoice the period.
    let payment_id = payment_id.to_string();
    let provider_subscription_id = provider_subscription_id.to_string();
    let plan_name = plan_name.clone();
    let tenant_id = tenant_id.clone();
    let interval = interval.to_string();
    let display_name = display_name.to_string();
    let currency = currency.to_string();
    run_under_tenant_billing_lock(
        pool,
        format!("billing_plan_activation:{tenant_id}"),
        "renewal",
        |conn| {
            Box::pin(async move {
                renew_locked(
                    conn,
                    &payment_id,
                    &provider_subscription_id,
                    &tenant_id,
                    &plan_name,
                    &interval,
                    &display_name,
                    &currency,
                    gross_cents,
                    months,
                    now,
                )
                .await
            })
        },
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn renew_locked(
    conn: &mut sqlx::PgConnection,
    payment_id: &str,
    provider_subscription_id: &str,
    tenant_id: &str,
    plan_name: &str,
    interval: &str,
    display_name: &str,
    currency: &str,
    gross_cents: i64,
    months: u32,
    now: DateTime<Utc>,
) -> Result<Option<Uuid>, String> {
    let mut tx = conn
        .begin()
        .await
        .map_err(|error| format!("renewal transaction failed: {error}"))?;
    type LocalSubscriptionCycle = (Uuid, Option<DateTime<Utc>>, Option<DateTime<Utc>>);
    let row: Option<LocalSubscriptionCycle> = sqlx::query_as(
        "SELECT id, billing_cycle_end, billing_cycle_end FROM mollie_subscriptions \
         WHERE mollie_subscription_id = $1 FOR UPDATE",
    )
    .bind(provider_subscription_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|error| format!("subscription row load failed: {error}"))?;
    let Some((row_id, cycle_end, _)) = row else {
        return Err(format!(
            "subscription payment {payment_id} names unknown provider subscription \
             {provider_subscription_id}"
        ));
    };
    // The paid period starts where the last one ended; a stale cycle (missed
    // deliveries) starts from now rather than invoicing history.
    let start = match cycle_end {
        Some(end) if end > now - Months::new(months) => end,
        _ => now,
    };
    let end = period_end(start, months)?;

    let invoice = crate::invoices::create_paid_plan_invoice_in_tx(
        &mut tx,
        tenant_id,
        display_name,
        interval,
        gross_cents,
        currency,
        payment_id,
        start,
        end,
    )
    .await
    .map_err(|error| format!("renewal invoice creation failed: {error}"))?;
    let operation_id = format!("mollie:{payment_id}");
    sqlx::query(
        r#"
        INSERT INTO invoice_payment_allocations (
            id, tenant_id, invoice_id, operation_id, source, amount_cents, currency
        ) VALUES (gen_random_uuid(), $1, $2, $3, 'mollie', $4, $5)
        ON CONFLICT (operation_id) DO NOTHING
        "#,
    )
    .bind(tenant_id)
    .bind(invoice.id)
    .bind(&operation_id)
    .bind(gross_cents)
    .bind(currency.trim().to_ascii_uppercase())
    .execute(&mut *tx)
    .await
    .map_err(|error| format!("renewal allocation failed: {error}"))?;
    crate::accounting_postings::post_invoice_issued_in(&mut tx, invoice.id).await;
    crate::accounting_postings::post_payment_allocation_in(&mut tx, &operation_id).await;

    sqlx::query(
        "UPDATE mollie_subscriptions SET status = 'active', billing_cycle_start = $2, \
                billing_cycle_end = $3, cancel_at_period_end = false, updated_at = NOW() \
         WHERE id = $1",
    )
    .bind(row_id)
    .bind(start)
    .bind(end)
    .execute(&mut *tx)
    .await
    .map_err(|error| format!("subscription cycle advance failed: {error}"))?;

    append_audit_log(
        &mut tx,
        tenant_id,
        "billing.subscription_renewed",
        "subscription",
        Some(provider_subscription_id),
        serde_json::json!({
            "paymentId": payment_id,
            "invoiceId": invoice.id,
            "plan": plan_name,
            "interval": interval,
            "periodStart": start.to_rfc3339(),
            "periodEnd": end.to_rfc3339(),
            "grossCents": gross_cents,
        }),
        now,
    )
    .await
    .map_err(|error| format!("renewal audit failed: {error}"))?;

    tx.commit()
        .await
        .map_err(|error| format!("renewal commit failed: {error}"))?;
    Ok(Some(invoice.id))
}

/// A subscription charge failed: the provider retries its own charges, so the
/// local row moves to `past_due` and the customer is notified; no local
/// mandate charge is attempted (that would double-charge a retried period).
pub async fn mark_subscription_payment_failed(
    pool: &PgPool,
    provider_subscription_id: &str,
    reason: Option<&str>,
    amount_cents: Option<i64>,
) -> Result<(), String> {
    let tenant_id: Option<String> = sqlx::query_scalar(
        "SELECT tenant_id FROM mollie_subscriptions WHERE mollie_subscription_id = $1",
    )
    .bind(provider_subscription_id)
    .fetch_optional(pool)
    .await
    .map_err(|error| format!("subscription lookup failed: {error}"))?;
    let Some(tenant_id) = tenant_id else {
        return Err(format!(
            "subscription payment failure names unknown provider subscription              {provider_subscription_id}"
        ));
    };
    let now = Utc::now();
    let mut tx = pool
        .begin()
        .await
        .map_err(|error| format!("failure transaction failed: {error}"))?;
    sqlx::query(
        "UPDATE mollie_subscriptions SET status = 'past_due', updated_at = NOW() \
         WHERE mollie_subscription_id = $1",
    )
    .bind(provider_subscription_id)
    .execute(&mut *tx)
    .await
    .map_err(|error| format!("subscription past_due update failed: {error}"))?;
    sqlx::query(
        "INSERT INTO notification_queue (id, tenant_id, type, payload, status, created_at)
         VALUES (gen_random_uuid(), $1, 'payment_failed', $2, 'pending', NOW())",
    )
    .bind(&tenant_id)
    .bind(serde_json::json!({
        "amount": amount_cents,
        "reason": reason.unwrap_or("the subscription payment failed"),
        "subscriptionId": provider_subscription_id,
    }))
    .execute(&mut *tx)
    .await
    .map_err(|error| format!("failure notification failed: {error}"))?;
    append_audit_log(
        &mut tx,
        &tenant_id,
        "billing.subscription_payment_failed",
        "subscription",
        Some(provider_subscription_id),
        serde_json::json!({"reason": reason, "amountCents": amount_cents}),
        now,
    )
    .await
    .map_err(|error| format!("failure audit failed: {error}"))?;
    tx.commit()
        .await
        .map_err(|error| format!("failure commit failed: {error}"))?;
    Ok(())
}

/// Stop Mollie's own charge generation for the tenant and revoke the mandate.
///
/// Called on activation (a plan change must cancel the previous subscription)
/// and on cancellation. Idempotent: a missing provider id is a no-op and the
/// DELETE is provider-idempotent.
///
/// The ids are CAPTURED before the local state transition (see
/// `subscriptions::cancel_subscription` and the period-end sweep): a local
/// cancel flips the row to `canceled` first, so a lookup keyed on the live
/// status would find nothing and the provider would keep charging.
pub async fn cancel_provider_subscription_object(
    customer_id: &str,
    subscription_id: &str,
) -> Result<(), String> {
    if !subscription_id.starts_with("sub_") || customer_id.trim().is_empty() {
        // A legacy/local sentinel is not a provider object.
        return Ok(());
    }
    let Ok(mollie) = MollieClient::from_env() else {
        return Ok(());
    };
    match mollie
        .cancel_subscription(customer_id, subscription_id)
        .await
    {
        Ok(()) => Ok(()),
        // The provider already forgot the object: the desired end state.
        Err(crate::mollie_client::MollieError::Rejected { status: 404, .. }) => Ok(()),
        Err(error) => Err(format!(
            "canceling Mollie subscription {subscription_id} failed: {error}"
        )),
    }
}

/// Reconcile local subscription state from the provider.
///
/// Only `active` grants the plan; `canceled`, `completed`, `suspended` and
/// `pending` resolve the tenant to Free. An amount that no longer matches the
/// catalog raises a finance incident and never silently changes entitlement.
pub async fn sweep_provider_subscription_state(pool: &PgPool) -> Result<u64, String> {
    type ProviderSubscriptionRow = (
        Uuid,
        String,
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
    );
    let rows: Vec<ProviderSubscriptionRow> = sqlx::query_as(
        "SELECT id, tenant_id, plan, billing_interval, mollie_subscription_id, \
                    mollie_customer_id, status FROM mollie_subscriptions \
             WHERE left(mollie_subscription_id, 4) = 'sub_' \
               AND status IN ('active', 'trialing', 'past_due', 'unpaid', 'canceled')",
    )
    .fetch_all(pool)
    .await
    .map_err(|error| format!("subscription sweep load failed: {error}"))?;
    let Ok(mollie) = MollieClient::from_env() else {
        return Ok(0);
    };
    let mut reconciled = 0u64;
    for (row_id, tenant_id, plan, interval, subscription_id, customer_id, local_status) in rows {
        let (Some(subscription_id), Some(customer_id)) = (subscription_id, customer_id) else {
            continue;
        };
        let provider = match mollie
            .get_subscription(&customer_id, &subscription_id)
            .await
        {
            Ok(provider) => provider,
            // A canceled local row whose provider object is GONE is converged.
            Err(crate::mollie_client::MollieError::Rejected { status: 404, .. })
                if local_status.as_deref() == Some("canceled") =>
            {
                continue;
            }
            Err(error) => {
                tracing::warn!(subscription_id = %subscription_id, error = %error,
                    "provider subscription fetch failed; local state left unchanged");
                continue;
            }
        };
        // The local cancel is committed before the provider DELETE (so a
        // provider outage can never leave the customer entitled but
        // uncanceled locally). If that DELETE did not land, the provider
        // object is still active and charging — retry it here.
        if local_status.as_deref() == Some("canceled") {
            if provider.status == "active" {
                match cancel_provider_subscription_object(&customer_id, &subscription_id).await {
                    Ok(()) => reconciled += 1,
                    Err(error) => tracing::warn!(
                        subscription_id = %subscription_id,
                        error = %error,
                        "retrying the provider subscription cancellation failed"
                    ),
                }
            }
            continue;
        }
        // An ACTIVE provider subscription charging an amount the catalog does
        // not expect is exactly the subscription that must be checked: the
        // check runs BEFORE the active early-return, is deduplicated per
        // subscription while it stays open, and leaves entitlement untouched
        // (the customer paid; downgrading silently would punish them for the
        // provider-side change). The incident names the subscription so the
        // operator can cancel and re-create it deliberately.
        if let (Some(plan), Some(interval), Some(amount)) = (
            plan.as_deref(),
            interval.as_deref(),
            provider.amount.as_ref(),
        ) {
            if let Some(expected) = catalog_amount_cents(plan, interval, &amount.currency) {
                if expected != amount.cents {
                    raise_billing_incident(
                        pool,
                        "mollie_subscription_amount_drift",
                        "high",
                        Some(&tenant_id),
                        Some(&subscription_id),
                        serde_json::json!({
                            "tenantId": tenant_id,
                            "subscriptionId": subscription_id,
                            "plan": plan,
                            "interval": interval,
                            "expectedCents": expected,
                            "providerCents": amount.cents,
                            "currency": amount.currency,
                        }),
                    )
                    .await;
                }
            }
        }
        if provider.status == "active" {
            // The healthy case — and the ONLY place an orphan can hide: a
            // live provider subscription for this customer that the local
            // table does not reference (e.g. the losing side of a superseded
            // activation whose retirement failed). Enumerate the customer's
            // subscriptions and cancel every active/pending object that is
            // not the locally active one.
            match mollie.list_subscriptions(&customer_id).await {
                Ok(provider_subscriptions) => {
                    for stray in provider_subscriptions {
                        if stray.id == subscription_id {
                            continue;
                        }
                        if stray.status != "active" && stray.status != "pending" {
                            continue;
                        }
                        match cancel_provider_subscription_object(&customer_id, &stray.id).await {
                            Ok(()) => {
                                reconciled += 1;
                                tracing::warn!(
                                    tenant_id = %tenant_id,
                                    orphan = %stray.id,
                                    "canceled an orphan Mollie subscription that was charging \
                                     outside the local state"
                                );
                                raise_billing_incident(
                                    pool,
                                    "mollie_orphan_subscription_canceled",
                                    "high",
                                    Some(&tenant_id),
                                    Some(&stray.id),
                                    serde_json::json!({
                                        "tenantId": tenant_id,
                                        "orphanSubscriptionId": stray.id,
                                        "localSubscriptionId": subscription_id,
                                        "customerId": customer_id,
                                    }),
                                )
                                .await;
                            }
                            Err(error) => {
                                tracing::error!(
                                    tenant_id = %tenant_id,
                                    orphan = %stray.id,
                                    error = %error,
                                    "orphan Mollie subscription cancellation failed — incident raised"
                                );
                                raise_billing_incident(
                                    pool,
                                    "mollie_orphan_subscription_cancel_failed",
                                    "critical",
                                    Some(&tenant_id),
                                    Some(&stray.id),
                                    serde_json::json!({
                                        "tenantId": tenant_id,
                                        "orphanSubscriptionId": stray.id,
                                        "localSubscriptionId": subscription_id,
                                        "customerId": customer_id,
                                        "error": error,
                                    }),
                                )
                                .await;
                            }
                        }
                    }
                }
                // A listing failure must not fail the whole sweep (existing
                // behavior for fetch failures); the next pass retries.
                Err(error) => tracing::warn!(
                    subscription_id = %subscription_id,
                    error = %error,
                    "provider subscription listing failed; orphan detection skipped"
                ),
            }
            continue;
        }
        // Only `active` grants the plan: downgrade this tenant if its plan
        // still comes from this subscription.
        let mut tx = pool
            .begin()
            .await
            .map_err(|error| format!("reconcile transaction failed: {error}"))?;
        sqlx::query(
            "UPDATE mollie_subscriptions SET status = 'canceled', updated_at = NOW() WHERE id = $1",
        )
        .bind(row_id)
        .execute(&mut *tx)
        .await
        .map_err(|error| format!("subscription cancel update failed: {error}"))?;
        if let Some(plan) = plan.as_deref() {
            sqlx::query(
                "UPDATE tenants SET plan = 'free', updated_at = NOW() \
                 WHERE id = $1 AND plan = $2",
            )
            .bind(&tenant_id)
            .bind(plan)
            .execute(&mut *tx)
            .await
            .map_err(|error| format!("tenant downgrade failed: {error}"))?;
        }
        append_audit_log(
            &mut tx,
            &tenant_id,
            "billing.subscription_reconciled_canceled",
            "subscription",
            Some(&subscription_id),
            serde_json::json!({
                "providerStatus": provider.status,
                "localStatusBefore": local_status,
            }),
            Utc::now(),
        )
        .await
        .map_err(|error| format!("reconcile audit failed: {error}"))?;
        tx.commit()
            .await
            .map_err(|error| format!("reconcile commit failed: {error}"))?;
        reconciled += 1;
    }
    Ok(reconciled)
}

/// `true` when the tenant's subscription is provider-managed (Mollie charges
/// it). The local dunning retry path must NOT charge these rows: Mollie
/// retries its own subscription payments.
pub async fn has_provider_subscription(pool: &PgPool, tenant_id: &str) -> Result<bool, String> {
    sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM mollie_subscriptions WHERE tenant_id = $1 \
           AND left(mollie_subscription_id, 4) = 'sub_')",
    )
    .bind(tenant_id)
    .fetch_one(pool)
    .await
    .map_err(|error| format!("provider subscription lookup failed: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Datelike;

    #[test]
    fn intervals_map_to_mollie_strings() {
        assert_eq!(interval_months("monthly"), Some(1));
        assert_eq!(interval_months("yearly"), Some(12));
        assert_eq!(interval_months("annual"), Some(12));
        assert_eq!(interval_months("weekly"), None);
        assert_eq!(mollie_interval(1), "1 month");
        assert_eq!(mollie_interval(12), "12 months");
    }

    #[test]
    fn catalog_amounts_are_the_published_lists() {
        for plan in SELF_SERVE_PLAN_IDS {
            assert!(
                catalog_amount_cents(plan, "monthly", "EUR").is_some(),
                "{plan}"
            );
            assert!(
                catalog_amount_cents(plan, "yearly", "EUR").is_some(),
                "{plan}"
            );
        }
        assert_eq!(catalog_amount_cents("enterprise", "monthly", "EUR"), None);
        assert_eq!(catalog_amount_cents("starter", "weekly", "EUR"), None);
    }

    #[test]
    fn period_end_advances_whole_months() {
        use chrono::TimeZone;
        let start = Utc.with_ymd_and_hms(2026, 1, 31, 12, 0, 0).unwrap();
        let end = period_end(start, 1).unwrap();
        assert_eq!(end.month(), 2);
        let year = period_end(start, 12).unwrap();
        assert_eq!(year.year(), 2027);
    }
}
