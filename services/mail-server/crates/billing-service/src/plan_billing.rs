//! Plan billing: ApexMail owns subscriptions, the PSP only charges.
//!
//! Beta authority inversion (external audit #8, sections 1-3, 11): core
//! subscription renewal does NOT depend on a provider-owned recurring
//! schedule — the provider never decides when the next charge exists. The
//! required shape, implemented by [`renew_due_subscriptions`]:
//!
//! ```text
//!     local current_period_end arrives
//!         → ApexMail renewal worker (the maintenance tick)
//!         → create INV-123 FIRST
//!         → claim payment attempt (attempt N, key payment:{ref}:{N})
//!         → PaymentProvider::charge_saved_method()
//!         → provider payment object
//!         → verify against INV-123 (exact amount — the engine enforces this)
//!         → settle INV-123
//!         → advance local subscription period
//! ```
//!
//! This module owns that lifecycle:
//!
//! * [`activate_from_paid_checkout`], a settled checkout payment is mapped
//!   back to an active catalog plan ONLY when its amount matches the catalog
//!   for the paid interval/currency; the LOCAL subscription row is created
//!   (no provider schedule is minted — renewal is local), the charge becomes
//!   a PAID invoice (VAT extracted from the gross) with its allocation and
//!   statutory postings; the tenant plan changes in the same transaction as
//!   the subscription row.
//! * [`renew_due_subscriptions`], the renewal worker tick: for every active
//!   local subscription at/after its period end it invoices the NEXT period
//!   FIRST, claims the payment attempt through the engine, charges the
//!   stored credential, and on success settles + advances the period.
//!   Dunning: a definitive failure leaves the invoice open and opens the
//!   NEXT immutable attempt on a later tick; after
//!   [`MAX_DUNNING_ATTEMPTS`] the subscription moves to `past_due` (the
//!   crate's existing dunning vocabulary). A subscription flagged
//!   `cancel_at_period_end` is ended with NO invoice and NO charge — the
//!   local flag is the cancellation authority.
//! * [`reconcile_provider_renewal_payment`], the repair-only reconciler for
//!   a provider-initiated renewal payment: it may settle an obligation the
//!   LOCAL scheduler already created, but it never creates an invoice and
//!   never advances a period on its own authority — a provider payment with
//!   no local obligation is a reconciliation incident (typed error + audit
//!   event), and a locally-canceled subscription is never resurrected.
//! * [`mark_subscription_payment_failed`], a failed subscription charge
//!   moves the row to `past_due` and notifies the customer.
//!
//! Every provider call is idempotent-keyed, and every local write is guarded
//! by the moment's authoritative check (payment id, subscription id, period).

use chrono::{DateTime, Months, Utc};
use sqlx::Connection as _;
use sqlx::PgPool;
use uuid::Uuid;

use crate::payments::{PaymentProvider, ProviderError};
use crate::routes::append_audit_log;
use crate::AppState;

/// The self-serve plans a generic checkout may sell.
pub const SELF_SERVE_PLAN_IDS: &[&str] = &["starter", "pro", "growth", "scale"];

/// Dunning policy of the local renewal worker (beta authority inversion):
/// after this many DEFINITIVELY failed renewal attempts the subscription
/// stops retrying and moves to `past_due` (the crate's existing dunning
/// vocabulary, mirrored from `mark_subscription_payment_failed`). The
/// customer keeps the plan until an operator or the period-end sweep acts;
/// cancellation is never automatic. (i32: the column is an INT4.)
pub const MAX_DUNNING_ATTEMPTS: i32 = 3;

/// The cooldown a renewal row observes after an attempt before the next
/// dunning attempt may fire (the attempts themselves are spaced by the
/// maintenance tick; this keeps a failed row from retrying every tick).
const DUNNING_RETRY_COOLDOWN_SQL: &str = "INTERVAL '1 hour'";

pub fn interval_months(interval: &str) -> Option<u32> {
    match interval.trim().to_ascii_lowercase().as_str() {
        "monthly" => Some(1),
        "yearly" | "annual" => Some(12),
        _ => None,
    }
}

/// The interval grammar is provider vocabulary and moved to the Mollie
/// adapter with the inversion; this test-facing alias keeps the existing
/// interval oracle intact.
#[cfg(test)]
fn mollie_interval(months: u32) -> String {
    crate::payments::mollie_provider::interval_string(months)
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
    /// The LOCAL subscription identifier (an ApexMail-owned opaque id; the
    /// provider holds no schedule object for this subscription — renewal is
    /// local).
    pub subscription_id: Option<String>,
    pub already_active: bool,
}

/// The per-tenant writer lock for billing state transitions.
///
/// Provider calls do NOT participate in the Postgres transaction, so the
/// serialization point must come BEFORE any provider mutation: two verified
/// checkouts for the same tenant arriving together would otherwise both read
/// the old subscription and both adopt a replacement, leaving the tenant
/// with two live arrangements. The lock is a SESSION advisory lock held on
/// one dedicated connection for the whole operation (provider I/O
/// included); the inner transaction then runs on that same connection, so a
/// transaction-level re-acquire of the same key is re-entrant and cannot
/// self-deadlock.
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
            "tenant billing lock release failed, closing the pooled connection"
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
/// the superseded subscriptions' facts are read for the change analytics,
/// then everything is adopted in ONE transaction (local subscription row,
/// tenant plan, paid invoice, allocation, postings, stored-credential
/// registration, audit) — the old subscription row is replaced atomically,
/// so the customer's billing never lapses. NO provider object is minted:
/// renewal is local, and the stored method the checkout captured is what the
/// renewal worker charges.
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
             {plan_name} ({interval}) is {expected}, refusing to grant a mismatched entitlement"
        ));
    }
    let (Some(customer_id), Some(mandate_id)) = (customer_id, mandate_id) else {
        // The money moved but no reusable method exists: refund and report.
        // Idempotent on the refund's idempotency key; no local state changes,
        // so it needs no tenant serialization.
        refund_unusable_checkout(pool, payment_id, gross_cents, currency).await?;
        return Ok(ActivationOutcome {
            invoice_id: None,
            subscription_id: None,
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
            subscription_id: None,
            already_active: true,
        });
    }

    // The superseded subscription's facts (plan analytics only — the row
    // itself is replaced atomically by the upsert below, and there is no
    // provider-side arrangement to retire: renewal is local).
    let previous: Option<(Option<String>, Option<String>)> = sqlx::query_as(
        "SELECT s.plan, s.billing_interval \
         FROM mollie_subscriptions s \
         WHERE s.tenant_id = $1 \
           AND s.status IN ('active', 'trialing', 'past_due', 'unpaid') \
           AND s.plan IS NOT NULL \
         ORDER BY s.created_at DESC \
         LIMIT 1",
    )
    .bind(tenant_id)
    .fetch_optional(&mut *conn)
    .await
    .map_err(|error| format!("previous subscription lookup failed: {error}"))?;
    let (previous_plan, previous_interval) = previous.unwrap_or((None, None));
    let previous_mrr_cents = previous_plan
        .as_deref()
        .zip(previous_interval.as_deref())
        .map(|(plan, interval)| catalog_monthly_mrr_cents(plan, interval))
        .unwrap_or(0);
    let new_mrr_cents = catalog_monthly_mrr_cents(plan_name, interval);

    // NEUTRALITY-DEBT (N-05, N-06): the legacy `mollie_*` columns written
    // below and the frozen allocation vocabulary stay byte-stable this
    // round; the owner-gated step 10 renames them onto the neutral ledger.
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
                subscription_id: None,
                already_active: true,
            });
        }

        // The LOCAL subscription identifier: an ApexMail-owned opaque id.
        // The provider holds no schedule object for this subscription —
        // the renewal worker charges the stored method per local period.
        let local_subscription_id = format!("local_{}", Uuid::new_v4().simple());

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
            renewal_attempts = 0,
            renewal_locked_at = NULL,
            cancel_at_period_end = false,
            canceled_at = NULL,
            updated_at = NOW()
        "#,
        )
        .bind(tenant_id)
        .bind(&local_subscription_id)
        .bind(plan_name)
        .bind(interval.trim().to_ascii_lowercase())
        .bind(start)
        .bind(end)
        .bind(customer_id)
        .bind(mandate_id)
        .execute(&mut *tx)
        .await
        .map_err(|error| format!("subscription upsert failed: {error}"))?;

        // The stored payment method the activation captured lands on the
        // NEUTRAL credentials ledger (the charging authority the renewal
        // worker reads). Same transaction: a committed activation always
        // leaves the credential behind.
        let provider = crate::payments::registry::from_env().map_err(|error| error.to_string())?;
        sqlx::query(
            r#"
        INSERT INTO payment_credentials
            (tenant_id, provider, provider_customer_id, provider_method_id, state)
        VALUES ($1, $2, $3, $4, 'active')
        ON CONFLICT (provider, provider_method_id) DO UPDATE SET
            state = 'active',
            revoked_at = NULL,
            provider_customer_id = EXCLUDED.provider_customer_id,
            updated_at = NOW()
        "#,
        )
        .bind(tenant_id)
        .bind(provider.provider_name())
        .bind(customer_id)
        .bind(mandate_id)
        .execute(&mut *tx)
        .await
        .map_err(|error| format!("payment credential write failed: {error}"))?;

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
        // NEUTRALITY-DEBT (N-05): the allocation `source` tag and the
        // `mollie:` operation-id prefix are frozen ledger vocabulary this
        // round; renaming would fork accounting history mid-stream.
        let operation_id = format!("mollie:{payment_id}");
        sqlx::query(
            r#"
        INSERT INTO invoice_payment_allocations (
            id, tenant_id, invoice_id, operation_id, source, amount_cents, currency, provider
        ) VALUES (gen_random_uuid(), $1, $2, $3, 'mollie', $4, $5, 'mollie')
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
            Some(&local_subscription_id),
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
            subscription_id: Some(local_subscription_id),
            already_active: false,
        })
    }
    .await;

    // No provider-side compensation is needed: nothing was created at the
    // provider, so a failed adoption leaves no live provider object behind.
    let _ = pool;
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
    // The refund is a neutral provider operation; the legacy refund mapping
    // row below stays (NEUTRALITY-DEBT N-05, step 10 moves it to
    // payment_provider_refunds).
    let provider = crate::payments::registry::from_env().map_err(|error| error.to_string())?;
    let refund = provider
        .refund(crate::payments::RefundRequest {
            provider_payment_id: payment_id.to_string(),
            amount_minor: gross_cents,
            currency: currency.to_string(),
            description: "Plan activation needs a reusable payment method; refunded automatically"
                .to_string(),
            // NEUTRALITY-DEBT (N-06): the key grammar is frozen operation
            // identity; changing it would mint a second refund on retry.
            idempotency_key: format!("plan_refund_no_mandate_{payment_id}"),
        })
        .await
        .map_err(|error| format!("automatic refund failed for {payment_id}: {error}"))?;
    sqlx::query(
        "INSERT INTO mollie_refunds (id, payment_id, amount_cents, currency, status)
         VALUES ($1, $2, $3, $4, 'created') ON CONFLICT (id) DO NOTHING",
    )
    .bind(&refund.provider_refund_id)
    .bind(payment_id)
    .bind(gross_cents)
    .bind(currency.trim().to_ascii_uppercase())
    .execute(pool)
    .await
    .map_err(|error| format!("refund mapping failed: {error}"))?;
    // Audit step 7: the same refund fact on the neutral refunds ledger.
    sqlx::query(
        r#"
        INSERT INTO payment_provider_refunds
            (provider, provider_refund_id, provider_payment_id, state,
             amount_minor, currency)
        VALUES ($1, $2, $3, 'pending', $4, $5)
        ON CONFLICT (provider, provider_refund_id) DO NOTHING
        "#,
    )
    .bind(provider.provider_name())
    .bind(&refund.provider_refund_id)
    .bind(payment_id)
    .bind(gross_cents)
    .bind(currency.trim().to_ascii_uppercase())
    .execute(pool)
    .await
    .map_err(|error| format!("neutral refund ledger write failed: {error}"))?;
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

// ---------------------------------------------------------------------------
// The local renewal worker (the core deliverable)
// ---------------------------------------------------------------------------

/// The renewal worker tick: renew every LOCAL subscription whose period has
/// ended, resolving the provider through the registry. Installed in the
/// billing maintenance loop (see `maintenance.rs`, the tick that previously
/// ran the provider-state sweep); the one-shot ops entry point is
/// `--renew-subscriptions-only` on the server binary.
///
/// Fails closed without a configured provider: an unconfigured deployment
/// renews nothing (0) instead of charging nothing and erroring the tick.
pub async fn renew_due_subscriptions(state: &AppState) -> Result<u64, String> {
    let Ok(provider) = crate::payments::registry::from_env() else {
        return Ok(0);
    };
    renew_due_subscriptions_with(state, provider, Utc::now()).await
}

/// The renewal core with the provider INJECTED: the maintenance loop runs it
/// with the registry-resolved adapter, the conformance harness and the
/// adversarial tests run it with a scripted double. Same invoice-first,
/// claim-then-charge path either way. The provider rides an [`Arc`] so a
/// renewal tick can hold it across the per-tenant locked closure.
pub async fn renew_due_subscriptions_with(
    state: &AppState,
    provider: std::sync::Arc<dyn PaymentProvider>,
    now: DateTime<Utc>,
) -> Result<u64, String> {
    // The due set: active local subscriptions whose period ended — INCLUDING
    // the ones flagged `cancel_at_period_end` (the worker ends those with no
    // invoice and no charge; conformance arm 18), not mid-attempt (the
    // `renewal_locked_at` gate spaces the dunning retries by one cooldown),
    // not already past the dunning ladder (`past_due` rows left the active
    // set when the ladder exhausted).
    let due: Vec<(String,)> = sqlx::query_as(&format!(
        r#"
        SELECT s.tenant_id
        FROM mollie_subscriptions s
        WHERE s.status = 'active'
          AND s.billing_cycle_end IS NOT NULL
          AND s.billing_cycle_end <= $1
          AND (s.renewal_locked_at IS NULL
               OR s.renewal_locked_at <= $1 - {DUNNING_RETRY_COOLDOWN_SQL})
        ORDER BY s.billing_cycle_end
        LIMIT 100
        "#
    ))
    .bind(now)
    .fetch_all(&state.db)
    .await
    .map_err(|error| format!("renewal due-set load failed: {error}"))?;

    let mut renewed = 0u64;
    for (tenant_id,) in due {
        let inner_pool = state.db.clone();
        let inner_provider = provider.clone();
        let tenant = tenant_id.clone();
        let outcome = run_under_tenant_billing_lock(
            &state.db,
            format!("billing_plan_activation:{tenant_id}"),
            "renewal worker",
            move |conn| {
                Box::pin(async move {
                    renew_subscription_locked(
                        &inner_pool,
                        conn,
                        inner_provider.as_ref(),
                        &tenant,
                        now,
                    )
                    .await
                })
            },
        )
        .await;
        match outcome {
            Ok(true) => renewed += 1,
            Ok(false) => {}
            Err(error) => tracing::warn!(
                tenant_id = %tenant_id,
                error = %error,
                "renewal attempt failed for this tick; the row cools down and the next tick retries"
            ),
        }
    }
    Ok(renewed)
}

/// One tenant's renewal, serialized by the billing lock. `Ok(true)` = the
/// period was renewed (charged, settled and advanced) in this call.
#[allow(clippy::too_many_lines)]
async fn renew_subscription_locked(
    pool: &PgPool,
    conn: &mut sqlx::PgConnection,
    provider: &dyn PaymentProvider,
    tenant_id: &str,
    now: DateTime<Utc>,
) -> Result<bool, String> {
    type DueRow = (
        Uuid,
        Option<String>,
        Option<String>,
        Option<DateTime<Utc>>,
        bool,
        i32,
    );
    // Re-read under the row lock: the cancel flag may have flipped since the
    // due-set snapshot, and only one writer may advance the cycle.
    let Some((row_id, plan, interval, cycle_end, cancel_at_period_end, attempts_i32)) =
        sqlx::query_as::<_, DueRow>(
            "SELECT id, plan, billing_interval, billing_cycle_end, cancel_at_period_end, \
                    renewal_attempts \
             FROM mollie_subscriptions \
             WHERE tenant_id = $1 AND status = 'active' \
             ORDER BY created_at DESC LIMIT 1 \
             FOR UPDATE",
        )
        .bind(tenant_id)
        .fetch_optional(&mut *conn)
        .await
        .map_err(|error| format!("renewal row load failed: {error}"))?
    else {
        return Ok(false);
    };

    // THE LOCAL CANCEL AUTHORITY: a subscription flagged
    // `cancel_at_period_end` is ended at period end with NO new invoice and
    // NO charge (conformance arm 18). Never resurrected by any later
    // provider fact.
    if cancel_at_period_end {
        return end_subscription_at_period_end(conn, row_id, tenant_id)
            .await
            .map(|()| false);
    }

    let Some(plan) = plan else {
        raise_billing_incident(
            pool,
            "renewal_subscription_without_plan",
            "high",
            Some(tenant_id),
            Some(&row_id.to_string()),
            serde_json::json!({
                "tenantId": tenant_id,
                "subscriptionId": row_id,
                "action": "the local row carries no plan; the period was not renewed",
            }),
        )
        .await;
        return Ok(false);
    };
    let interval = interval.unwrap_or_else(|| "monthly".to_string());
    let months = interval_months(&interval)
        .ok_or_else(|| format!("unknown billing interval {interval:?}"))?;
    let display_name = platform_catalog::plan_by_name(&plan)
        .map(|p| p.display_name.to_string())
        .unwrap_or_else(|| plan.clone());

    // The tenant's billing currency is the currency it is actually being
    // invoiced in (the most recent invoice wins); EUR is the catalog
    // default.
    let currency: String = sqlx::query_scalar(
        "SELECT currency FROM invoices WHERE tenant_id = $1 \
         ORDER BY created_at DESC LIMIT 1",
    )
    .bind(tenant_id)
    .fetch_optional(&mut *conn)
    .await
    .map_err(|error| format!("renewal currency lookup failed: {error}"))?
    .unwrap_or_else(|| "EUR".to_string());
    let Some(gross_cents) = catalog_amount_cents(&plan, &interval, &currency) else {
        raise_billing_incident(
            pool,
            "renewal_plan_not_billable",
            "high",
            Some(tenant_id),
            Some(&row_id.to_string()),
            serde_json::json!({
                "tenantId": tenant_id,
                "plan": plan,
                "interval": interval,
                "currency": currency,
                "action": "the catalog has no price for this plan/interval/currency; the period was not renewed",
            }),
        )
        .await;
        return Ok(false);
    };

    // The paid period starts where the last one ended; a stale cycle (the
    // worker was down) starts from now rather than invoicing history.
    let start = match cycle_end {
        Some(end) if end > now - Months::new(months) => end,
        _ => now,
    };
    let end = period_end(start, months)?;

    // INVOICE FIRST (the audit's shape): the obligation exists before any
    // charge. Idempotent on (tenant, open, period_start) — a previous tick
    // that created the invoice but lost the charge claims the SAME invoice.
    let invoice_id: Uuid = match sqlx::query_scalar::<_, Uuid>(
        "SELECT id FROM invoices \
         WHERE tenant_id = $1 AND status IN ('draft', 'pending') AND period_start = $2 \
         ORDER BY created_at DESC LIMIT 1",
    )
    .bind(tenant_id)
    .bind(start)
    .fetch_optional(&mut *conn)
    .await
    .map_err(|error| format!("renewal obligation lookup failed: {error}"))?
    {
        Some(existing) => existing,
        None => {
            let mut tx = conn
                .begin()
                .await
                .map_err(|error| format!("renewal invoice transaction failed: {error}"))?;
            let invoice = crate::invoices::create_open_plan_invoice_in_tx(
                &mut tx,
                tenant_id,
                &display_name,
                &interval,
                gross_cents,
                &currency,
                start,
                end,
            )
            .await
            .map_err(|error| format!("renewal invoice creation failed: {error}"))?;
            crate::accounting_postings::post_invoice_issued_in(&mut tx, invoice.id).await;
            tx.commit()
                .await
                .map_err(|error| format!("renewal invoice commit failed: {error}"))?;
            invoice.id
        }
    };
    let obligation_ref = format!("invoice:{invoice_id}");

    // The charging credential comes from the NEUTRAL credentials ledger.
    // Without one there is nothing to charge: raise the incident and stamp
    // the cooldown — no attempt is claimed, so no provider call happens.
    let Some((customer_id, method_id)) = sqlx::query_as::<_, (String, String)>(
        "SELECT provider_customer_id, provider_method_id FROM payment_credentials \
         WHERE tenant_id = $1 AND state = 'active' AND revoked_at IS NULL \
         ORDER BY created_at DESC LIMIT 1",
    )
    .bind(tenant_id)
    .fetch_optional(pool)
    .await
    .map_err(|error| format!("renewal credential lookup failed: {error}"))?
    else {
        raise_billing_incident(
            pool,
            "renewal_no_payment_method",
            "high",
            Some(tenant_id),
            Some(&row_id.to_string()),
            serde_json::json!({
                "tenantId": tenant_id,
                "subscriptionId": row_id,
                "invoiceId": invoice_id,
                "action": "no active stored payment method; the open invoice waits for dunning",
            }),
        )
        .await;
        stamp_renewal_cooldown(pool, row_id, attempts_i32, tenant_id, &obligation_ref, None)
            .await?;
        return Ok(false);
    };

    // Stamp the in-flight/backoff gate BEFORE claiming: a concurrent tick
    // (and the next dunning retry) skips a stamped row.
    sqlx::query(
        "UPDATE mollie_subscriptions SET renewal_locked_at = $2, updated_at = NOW() WHERE id = $1",
    )
    .bind(row_id)
    .bind(now)
    .execute(pool)
    .await
    .map_err(|error| format!("renewal gate stamp failed: {error}"))?;

    // CLAIM BEFORE CHARGE: the dunning ladder opens attempt N+1 as a NEW
    // immutable row under the shared `payment:{ref}:{N}` key. `None` means
    // an attempt is open/unresolved/succeeded — no second charge.
    let Some((attempt_no, key)) = crate::payments::engine::claim_next_attempt(
        pool,
        provider.provider_name(),
        tenant_id,
        &obligation_ref,
        "renewal",
        gross_cents,
        &currency,
    )
    .await
    .map_err(|error| format!("renewal attempt claim failed: {error}"))?
    else {
        tracing::debug!(
            tenant_id = %tenant_id,
            obligation_ref = %obligation_ref,
            "a payment attempt is already in flight for the renewal obligation"
        );
        return Ok(false);
    };

    let charge = provider
        .charge_saved_method(crate::payments::SavedMethodCharge {
            provider_customer_id: customer_id,
            provider_method_id: method_id,
            amount_minor: gross_cents,
            currency: currency.clone(),
            description: format!("ApexMail {display_name}"),
            metadata: serde_json::json!({
                "tenant_id": tenant_id,
                "plan_name": plan,
                "interval": interval,
                "reference": obligation_ref,
            }),
            idempotency_key: key.clone(),
        })
        .await;

    match charge {
        Ok(payment) => {
            // CONFIRM after charge: the payment id + normalized state land
            // on the claimed row (terminal states close it, immutable).
            crate::payments::engine::confirm_attempt(
                pool,
                provider.provider_name(),
                &key,
                &payment.provider_payment_id,
                payment.state,
            )
            .await
            .map_err(|error| format!("renewal attempt confirm failed: {error}"))?;
            match payment.state {
                crate::payments::PaymentState::Succeeded => {
                    settle_renewal_and_advance(
                        pool,
                        provider.provider_name(),
                        tenant_id,
                        &plan,
                        &interval,
                        row_id,
                        invoice_id,
                        &payment.provider_payment_id,
                        gross_cents,
                        &currency,
                        attempt_no,
                        now,
                    )
                    .await
                }
                // A definitive refusal WITH a provider payment object: the
                // confirm above already closed the claimed row (`failed`/
                // `canceled` is terminal and immutable) — walk the dunning
                // ladder exactly like a pre-mint refusal.
                state @ (crate::payments::PaymentState::Failed
                | crate::payments::PaymentState::Canceled) => {
                    dunning_failure(
                        pool,
                        row_id,
                        tenant_id,
                        &plan,
                        attempts_i32,
                        &obligation_ref,
                        Some(gross_cents),
                        &format!("the provider declined the charge: {state:?}"),
                        now,
                    )
                    .await?;
                    Ok(false)
                }
                // The charge is moving (or parked on the customer): the
                // webhook observation or the repair sweep drives it through
                // verify-then-settle; the next tick's claim is refused while
                // the attempt is open.
                state => {
                    tracing::info!(
                        tenant_id = %tenant_id,
                        obligation_ref = %obligation_ref,
                        state = ?state,
                        "renewal charge accepted but not final; the webhook or repair sweep settles it"
                    );
                    Ok(false)
                }
            }
        }
        // Transport uncertainty: the claim stays open and KEYLESS — the
        // stale-claim reconcile (authenticated provider-side search) either
        // repairs the charge or parks it `unresolved`. Never retried blind.
        Err(error @ ProviderError::Unavailable(_)) => {
            tracing::warn!(
                tenant_id = %tenant_id,
                obligation_ref = %obligation_ref,
                error = %error,
                "renewal charge outcome unknown; the attempt stays open for the repair sweep"
            );
            Ok(false)
        }
        // Definitive refusal (no payment id minted): close the claim failed
        // and walk the dunning ladder.
        Err(error) => {
            crate::payments::engine::fail_claim(pool, provider.provider_name(), &key)
                .await
                .map_err(|e| format!("renewal claim close failed: {e}"))?;
            dunning_failure(
                pool,
                row_id,
                tenant_id,
                &plan,
                attempts_i32,
                &obligation_ref,
                Some(gross_cents),
                &error.to_string(),
                now,
            )
            .await?;
            Ok(false)
        }
    }
}

/// Settle a SUCCESSFUL renewal charge through the engine's
/// observe -> verify -> settle core, then advance the local period.
/// The advance happens ONLY after the obligation is actually paid.
#[allow(clippy::too_many_arguments)]
async fn settle_renewal_and_advance(
    pool: &PgPool,
    provider_name: &str,
    tenant_id: &str,
    plan: &str,
    interval: &str,
    row_id: Uuid,
    invoice_id: Uuid,
    provider_payment_id: &str,
    gross_cents: i64,
    currency: &str,
    attempt_no: i64,
    now: DateTime<Utc>,
) -> Result<bool, String> {
    let observed = crate::payments::engine::ObservedPayment {
        provider: provider_name.to_string(),
        provider_payment_id: provider_payment_id.to_string(),
        state: crate::payments::PaymentState::Succeeded,
        amount_minor: Some(gross_cents),
        currency: Some(currency.to_string()),
        tenant_id: Some(tenant_id.to_string()),
        obligation_ref: Some(format!("invoice:{invoice_id}")),
        purpose: "renewal",
    };
    crate::payments::engine::observe_payment(pool, &observed).await?;
    match crate::payments::engine::verify_against_obligation(pool, &observed).await {
        Ok(verified) => {
            let settled = crate::payments::engine::settle_verified(pool, provider_name, &verified)
                .await
                .map_err(|error| format!("renewal settlement failed: {error}"))?;
            let paid: bool =
                sqlx::query_scalar("SELECT status::text = 'paid' FROM invoices WHERE id = $1")
                    .bind(invoice_id)
                    .fetch_one(pool)
                    .await
                    .map_err(|error| format!("renewal invoice reread failed: {error}"))?;
            if !paid {
                // The engine refused to flip the invoice paid (a replay of a
                // settled fact settles nothing but the invoice IS already
                // paid; a paid=false here means the allocation did not cover
                // the obligation — do not advance on an unpaid obligation).
                if settled {
                    tracing::warn!(
                        tenant_id = %tenant_id,
                        invoice_id = %invoice_id,
                        "renewal settlement landed but the invoice is not paid; the period did not advance"
                    );
                    return Ok(false);
                }
                return Ok(false);
            }
            // Recognition ledger: reflect the settlement (cash-accounting
            // tenants recognise on payment), same as the webhook path.
            if let Err(error) =
                crate::vat_recognition::materialize_invoice_recognition_by_id(pool, invoice_id, now)
                    .await
            {
                tracing::warn!(
                    invoice_id = %invoice_id,
                    error = %error,
                    "failed to materialize VAT recognition after the renewal settlement"
                );
            }
            advance_period(
                pool,
                row_id,
                tenant_id,
                plan,
                interval,
                invoice_id,
                attempt_no,
                gross_cents,
                now,
            )
            .await?;
            Ok(true)
        }
        Err(crate::payments::engine::VerifyError::AmountMismatch {
            payment_id,
            expected_minor,
            actual_minor,
        }) => {
            // NEVER closed failed, never capped: the money may exist. The
            // attempt stays open for human reconciliation.
            tracing::error!(
                tenant_id = %tenant_id,
                payment_id = %payment_id,
                expected_minor,
                actual_minor,
                "RECONCILIATION INCIDENT: the renewal charge amount != the obligation amount; \
                 no entitlement, no settlement — the attempt stays open for manual reconciliation"
            );
            raise_billing_incident(
                pool,
                "renewal_amount_mismatch",
                "critical",
                Some(tenant_id),
                Some(&payment_id),
                serde_json::json!({
                    "tenantId": tenant_id,
                    "paymentId": payment_id,
                    "expectedMinor": expected_minor,
                    "actualMinor": actual_minor,
                }),
            )
            .await;
            Ok(false)
        }
        Err(error) => {
            tracing::warn!(
                tenant_id = %tenant_id,
                invoice_id = %invoice_id,
                error = %error,
                "renewal verification refused; the attempt stays open, no settlement"
            );
            Ok(false)
        }
    }
}

/// Advance the local period after a settled renewal: the cycle moves, the
/// dunning state resets, the renewal is audited.
#[allow(clippy::too_many_arguments)]
async fn advance_period(
    pool: &PgPool,
    row_id: Uuid,
    tenant_id: &str,
    plan: &str,
    interval: &str,
    invoice_id: Uuid,
    attempt_no: i64,
    gross_cents: i64,
    now: DateTime<Utc>,
) -> Result<(), String> {
    let months = interval_months(interval)
        .ok_or_else(|| format!("unknown billing interval {interval:?}"))?;
    type Cycle = (Option<DateTime<Utc>>, Option<DateTime<Utc>>);
    let (cycle_start, cycle_end): Cycle = sqlx::query_as(
        "SELECT billing_cycle_start, billing_cycle_end FROM mollie_subscriptions WHERE id = $1",
    )
    .bind(row_id)
    .fetch_one(pool)
    .await
    .map_err(|error| format!("renewal cycle read failed: {error}"))?;
    // The paid period starts where the last one ended; a stale cycle starts
    // from now rather than invoicing history (the same guard the old
    // webhook-driven renewal applied).
    let start = match cycle_end {
        Some(end) if end > now - Months::new(months) => end,
        _ => now,
    };
    let end = period_end(start, months)?;

    let mut tx = pool
        .begin()
        .await
        .map_err(|error| format!("renewal advance transaction failed: {error}"))?;
    sqlx::query(
        "UPDATE mollie_subscriptions SET status = 'active', billing_cycle_start = $2, \
                billing_cycle_end = $3, renewal_attempts = 0, renewal_locked_at = NULL, \
                updated_at = NOW() \
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
        Some(&row_id.to_string()),
        serde_json::json!({
            "paymentId": null,
            "invoiceId": invoice_id,
            "attemptNo": attempt_no,
            "plan": plan,
            "interval": interval,
            "periodStart": start.to_rfc3339(),
            "periodEnd": end.to_rfc3339(),
            "grossCents": gross_cents,
            "authority": "local_renewal_worker",
            "cycleStartBefore": cycle_start,
            "cycleEndBefore": cycle_end,
        }),
        now,
    )
    .await
    .map_err(|error| format!("renewal audit failed: {error}"))?;

    tx.commit()
        .await
        .map_err(|error| format!("renewal advance commit failed: {error}"))?;
    Ok(())
}

/// End a subscription flagged `cancel_at_period_end` once its period has
/// ended: the LOCAL flag is the cancellation authority. Same state writes
/// and audit vocabulary as the period-end sweep (`status = 'canceled'`, the
/// flag cleared, the tenant downgraded).
async fn end_subscription_at_period_end(
    conn: &mut sqlx::PgConnection,
    row_id: Uuid,
    tenant_id: &str,
) -> Result<(), String> {
    let mut tx = conn
        .begin()
        .await
        .map_err(|error| format!("period-end transaction failed: {error}"))?;
    sqlx::query(
        "UPDATE mollie_subscriptions SET status = 'canceled', cancel_at_period_end = false, \
                renewal_locked_at = NULL, updated_at = NOW() \
         WHERE id = $1 AND cancel_at_period_end",
    )
    .bind(row_id)
    .execute(&mut *tx)
    .await
    .map_err(|error| format!("period-end subscription update failed: {error}"))?;
    sqlx::query(
        "UPDATE tenants SET plan = 'free', updated_at = NOW() \
         WHERE id = $1 AND plan <> 'free'",
    )
    .bind(tenant_id)
    .execute(&mut *tx)
    .await
    .map_err(|error| format!("period-end downgrade failed: {error}"))?;
    append_audit_log(
        &mut tx,
        tenant_id,
        "billing.subscription_ended_at_period_end",
        "subscription",
        Some(&row_id.to_string()),
        serde_json::json!({ "effective": "period_end", "authority": "cancel_at_period_end" }),
        Utc::now(),
    )
    .await
    .map_err(|error| format!("period-end audit failed: {error}"))?;
    tx.commit()
        .await
        .map_err(|error| format!("period-end commit failed: {error}"))?;
    Ok(())
}

/// One definitive renewal failure: the invoice stays OPEN, the dunning
/// counter moves, and the NEXT attempt is a NEW immutable attempt row
/// claimed by a later tick. The subscription is never canceled on failure —
/// after [`MAX_DUNNING_ATTEMPTS`] it moves to `past_due` (the crate's
/// existing dunning vocabulary) and the customer is notified, mirroring
/// `mark_subscription_payment_failed`.
#[allow(clippy::too_many_arguments)]
async fn dunning_failure(
    pool: &PgPool,
    row_id: Uuid,
    tenant_id: &str,
    plan: &str,
    attempts: i32,
    obligation_ref: &str,
    amount_cents: Option<i64>,
    reason: &str,
    now: DateTime<Utc>,
) -> Result<(), String> {
    stamp_renewal_cooldown(
        pool,
        row_id,
        attempts,
        tenant_id,
        obligation_ref,
        amount_cents,
    )
    .await?;
    let new_attempts = attempts + 1;
    if new_attempts >= MAX_DUNNING_ATTEMPTS {
        let mut tx = pool
            .begin()
            .await
            .map_err(|error| format!("dunning transaction failed: {error}"))?;
        sqlx::query(
            "UPDATE mollie_subscriptions SET status = 'past_due', renewal_attempts = $2, \
                    renewal_locked_at = $3, updated_at = NOW() \
             WHERE id = $1",
        )
        .bind(row_id)
        .bind(new_attempts)
        .bind(now)
        .execute(&mut *tx)
        .await
        .map_err(|error| format!("dunning past_due update failed: {error}"))?;
        sqlx::query(
            "INSERT INTO notification_queue (id, tenant_id, type, payload, status, created_at)
             VALUES (gen_random_uuid(), $1, 'payment_failed', $2, 'pending', NOW())",
        )
        .bind(tenant_id)
        .bind(serde_json::json!({
            "amount": amount_cents,
            "reason": "the subscription renewal failed repeatedly; update your payment method",
            "attempts": new_attempts,
        }))
        .execute(&mut *tx)
        .await
        .map_err(|error| format!("dunning notification failed: {error}"))?;
        append_audit_log(
            &mut tx,
            tenant_id,
            "billing.subscription_payment_failed",
            "subscription",
            Some(&row_id.to_string()),
            serde_json::json!({
                "reason": reason,
                "amountCents": amount_cents,
                "attempts": new_attempts,
                "obligationRef": obligation_ref,
                "authority": "local_renewal_worker",
            }),
            now,
        )
        .await
        .map_err(|error| format!("dunning audit failed: {error}"))?;
        tx.commit()
            .await
            .map_err(|error| format!("dunning commit failed: {error}"))?;
        let _ = plan;
        Ok(())
    } else {
        tracing::info!(
            tenant_id = %tenant_id,
            obligation_ref = %obligation_ref,
            attempts = new_attempts,
            reason = %reason,
            "renewal attempt failed; the invoice stays open and the dunning ladder retries on a later tick"
        );
        let mut tx = pool
            .begin()
            .await
            .map_err(|error| format!("dunning transaction failed: {error}"))?;
        append_audit_log(
            &mut tx,
            tenant_id,
            "billing.renewal_attempt_failed",
            "subscription",
            Some(&row_id.to_string()),
            serde_json::json!({
                "reason": reason,
                "amountCents": amount_cents,
                "attempts": new_attempts,
                "obligationRef": obligation_ref,
                "authority": "local_renewal_worker",
            }),
            now,
        )
        .await
        .map_err(|error| format!("dunning audit failed: {error}"))?;
        tx.commit()
            .await
            .map_err(|error| format!("dunning commit failed: {error}"))?;
        Ok(())
    }
}

/// Stamp the cooldown gate + dunning counter WITHOUT the terminal
/// transition (used when no charge attempt could even be claimed: no stored
/// payment method).
async fn stamp_renewal_cooldown(
    pool: &PgPool,
    row_id: Uuid,
    attempts: i32,
    tenant_id: &str,
    obligation_ref: &str,
    amount_cents: Option<i64>,
) -> Result<(), String> {
    sqlx::query(
        "UPDATE mollie_subscriptions SET renewal_attempts = $2, renewal_locked_at = NOW(), \
                updated_at = NOW() WHERE id = $1",
    )
    .bind(row_id)
    .bind(attempts + 1)
    .execute(pool)
    .await
    .map_err(|error| format!("renewal cooldown stamp failed: {error}"))?;
    let _ = (tenant_id, obligation_ref, amount_cents);
    Ok(())
}

// ---------------------------------------------------------------------------
// The repair-only reconciler for provider-initiated renewal payments
// ---------------------------------------------------------------------------

/// Why a provider-initiated renewal payment could not be applied. Every
/// variant is a RECONCILIATION INCIDENT (the provider must never decide
/// when the next charge exists), never a silent drop.
#[derive(Debug, thiserror::Error)]
pub enum RenewalReconciliationError {
    #[error(
        "RECONCILIATION INCIDENT: subscription payment {payment_id} names unknown provider \
         contract {provider_contract_id}; no local subscription is bound to it — the provider \
         must never decide when the next charge exists"
    )]
    UnknownProviderContract {
        payment_id: String,
        provider_contract_id: String,
    },
    #[error(
        "RECONCILIATION INCIDENT: provider renewal payment {payment_id} for tenant {tenant_id} \
         arrived with NO local obligation for the current period; no invoice was created and \
         the period did not advance — the provider must never decide when the next charge exists"
    )]
    NoLocalObligation {
        payment_id: String,
        tenant_id: String,
    },
    #[error("renewal settlement verification refused: {0}")]
    Verify(#[from] crate::payments::engine::VerifyError),
    #[error("renewal reconciliation failed: {0}")]
    Other(String),
}

/// Reconcile a provider-initiated subscription renewal payment (the webhook
/// arm's ONLY renewal path).
///
/// The provider's view is an observation; the LOCAL row is the authority:
///
/// * a local obligation for the current period (the invoice the renewal
///   worker created BEFORE its own charge) is settled through the SAME
///   observe -> verify -> settle engine the repair sweep uses, and a settled
///   active subscription's period advances — nothing else;
/// * NO obligation for the current period, or an unbound provider contract:
///   a typed reconciliation incident (`RenewalReconciliationError`) + a
///   finance incident + an audit row. No invoice is created, no period
///   advances;
/// * a locally-canceled (or otherwise non-active) subscription is NEVER
///   resurrected: the money may settle against an existing obligation, but
///   the status and the cycle are untouched and the reconciliation is
///   audited.
pub async fn reconcile_provider_renewal_payment(
    pool: &PgPool,
    payment_id: &str,
    provider_contract_id: &str,
    gross_cents: i64,
    currency: &str,
) -> Result<Option<Uuid>, RenewalReconciliationError> {
    // Ladder rung 0: this payment ALREADY settled an invoice (a replayed
    // webhook, or the repair sweep beat the notification). Settlement is
    // exactly-once on the operation id: acknowledge the replay with the
    // settled obligation — no contract resolution, no tenant lock, no
    // incident, no second allocation.
    let operation_id = format!("mollie:{}", payment_id.trim());
    if let Some((invoice_id,)) = sqlx::query_as::<_, (Uuid,)>(
        "SELECT i.id FROM invoice_payment_allocations a \
         JOIN invoices i ON i.id = a.invoice_id \
         WHERE a.operation_id = $1 LIMIT 1",
    )
    .bind(&operation_id)
    .fetch_optional(pool)
    .await
    .map_err(|error| RenewalReconciliationError::Other(error.to_string()))?
    {
        return Ok(Some(invoice_id));
    }

    // Resolve the LOCAL subscription: the neutral binding first (the legacy
    // contract id's surviving purpose), then the legacy column (rows bound
    // before the binding table existed).
    type LocalRow = (
        Uuid,
        String,
        Option<String>,
        Option<String>,
        Option<DateTime<Utc>>,
        String,
    );
    let row: Option<LocalRow> = sqlx::query_as(
        "SELECT s.id, s.tenant_id, s.plan, s.billing_interval, s.billing_cycle_end, s.status \
         FROM mollie_subscriptions s \
         LEFT JOIN subscription_payment_bindings b ON b.local_subscription_id = s.id \
              AND b.provider = 'mollie' \
         WHERE b.provider_contract_id = $1 OR s.mollie_subscription_id = $1 \
         ORDER BY (b.id IS NOT NULL) DESC, s.created_at DESC \
         LIMIT 1",
    )
    .bind(provider_contract_id)
    .fetch_optional(pool)
    .await
    .map_err(|error| {
        RenewalReconciliationError::Other(format!(
            "subscription load failed for contract {provider_contract_id}: {error}"
        ))
    })?;

    let Some((row_id, tenant_id, plan, interval, cycle_end, status)) = row else {
        raise_billing_incident(
            pool,
            "provider_renewal_unknown_contract",
            "high",
            None,
            Some(provider_contract_id),
            serde_json::json!({
                "paymentId": payment_id,
                "providerContractId": provider_contract_id,
                "amountMinor": gross_cents,
                "currency": currency,
                "action": "no local subscription is bound to this provider contract; nothing was settled or granted",
            }),
        )
        .await;
        return Err(RenewalReconciliationError::UnknownProviderContract {
            payment_id: payment_id.to_string(),
            provider_contract_id: provider_contract_id.to_string(),
        });
    };

    let inner_pool = pool.clone();
    let payment_id = payment_id.to_string();
    let contract_id = provider_contract_id.to_string();
    let currency = currency.to_string();
    let outcome = run_under_tenant_billing_lock(
        pool,
        format!("billing_plan_activation:{tenant_id}"),
        "provider renewal reconciliation",
        move |conn| {
            Box::pin(async move {
                reconcile_locked(
                    &inner_pool,
                    conn,
                    &payment_id,
                    &contract_id,
                    gross_cents,
                    &currency,
                    row_id,
                    &tenant_id,
                    plan.as_deref(),
                    interval.as_deref(),
                    cycle_end,
                    &status,
                )
                .await
                .map_err(|error| error.to_string())
            })
        },
    )
    .await
    .map_err(RenewalReconciliationError::Other)?;
    Ok(outcome)
}

/// The locked reconciliation core. Returns the settled (or already-settled)
/// invoice id, or a typed incident.
#[allow(clippy::too_many_arguments, clippy::type_complexity)]
async fn reconcile_locked(
    pool: &PgPool,
    conn: &mut sqlx::PgConnection,
    payment_id: &str,
    _contract_id: &str,
    gross_cents: i64,
    currency: &str,
    row_id: Uuid,
    tenant_id: &str,
    plan: Option<&str>,
    interval: Option<&str>,
    cycle_end: Option<DateTime<Utc>>,
    status: &str,
) -> Result<Option<Uuid>, RenewalReconciliationError> {
    // The obligation ladder (the settled-allocation rung already ran in the
    // caller):
    // 1. an attempt row carries the obligation reference (the worker's claim
    //    this payment belongs to);
    // 2. the open renewal invoice the worker created for the CURRENT period
    //    (period_start = the cycle being renewed).
    let obligation_ref: Option<String> = {
        let from_attempt: Option<String> = sqlx::query_scalar(
            "SELECT obligation_ref FROM payment_attempts \
             WHERE provider = 'mollie' AND provider_payment_id = $1 \
               AND obligation_ref IS NOT NULL LIMIT 1",
        )
        .bind(payment_id.trim())
        .fetch_optional(&mut *conn)
        .await
        .map_err(|error| RenewalReconciliationError::Other(error.to_string()))?;
        match from_attempt {
            Some(reference) => Some(reference),
            None => {
                // The open obligation for the CURRENT period only. A
                // provider payment never summons an invoice into existence,
                // and never settles an arbitrary open invoice (an overage or
                // usage invoice has its own charging path).
                sqlx::query_scalar::<_, Uuid>(
                    "SELECT id FROM invoices \
                     WHERE tenant_id = $1 AND status IN ('draft', 'pending') \
                       AND period_start IS NOT DISTINCT FROM $2 \
                     ORDER BY created_at DESC LIMIT 1",
                )
                .bind(tenant_id)
                .bind(cycle_end)
                .fetch_optional(&mut *conn)
                .await
                .map_err(|error| RenewalReconciliationError::Other(error.to_string()))?
                .map(|invoice_id| format!("invoice:{invoice_id}"))
            }
        }
    };

    let Some(obligation_ref) = obligation_ref else {
        raise_billing_incident(
            pool,
            "provider_renewal_no_local_obligation",
            "high",
            Some(tenant_id),
            Some(payment_id),
            serde_json::json!({
                "tenantId": tenant_id,
                "paymentId": payment_id,
                "providerContractId": _contract_id,
                "amountMinor": gross_cents,
                "currency": currency,
                "subscriptionStatus": status,
                "action": "no local obligation exists for the current period; the provider-initiated charge was not applied",
            }),
        )
        .await;
        let mut audit_tx = conn
            .begin()
            .await
            .map_err(|error| RenewalReconciliationError::Other(error.to_string()))?;
        append_audit_log(
            &mut audit_tx,
            tenant_id,
            "billing.provider_renewal_incident",
            "subscription",
            Some(&row_id.to_string()),
            serde_json::json!({
                "paymentId": payment_id,
                "providerContractId": _contract_id,
                "amountMinor": gross_cents,
                "currency": currency,
                "reason": "no_local_obligation",
            }),
            Utc::now(),
        )
        .await
        .map_err(|error| RenewalReconciliationError::Other(error.to_string()))?;
        audit_tx
            .commit()
            .await
            .map_err(|error| RenewalReconciliationError::Other(error.to_string()))?;
        return Err(RenewalReconciliationError::NoLocalObligation {
            payment_id: payment_id.to_string(),
            tenant_id: tenant_id.to_string(),
        });
    };
    // The engine core: observe -> verify (EXACT amount) -> settle. The
    // provider's fact is already the authenticated truth the webhook
    // fetched.
    let observed = crate::payments::engine::ObservedPayment {
        provider: "mollie".to_string(),
        provider_payment_id: payment_id.trim().to_string(),
        state: crate::payments::PaymentState::Succeeded,
        amount_minor: Some(gross_cents),
        currency: Some(currency.to_string()),
        tenant_id: Some(tenant_id.to_string()),
        obligation_ref: Some(obligation_ref.clone()),
        purpose: "webhook",
    };
    crate::payments::engine::observe_payment(pool, &observed)
        .await
        .map_err(RenewalReconciliationError::Other)?;
    let verified = match crate::payments::engine::verify_against_obligation(pool, &observed).await {
        Ok(verified) => verified,
        Err(error @ crate::payments::engine::VerifyError::AmountMismatch { .. }) => {
            tracing::error!(
                tenant_id = %tenant_id,
                payment_id = %payment_id,
                "RECONCILIATION INCIDENT: the provider-initiated renewal charge amount != the \
                 obligation amount; no settlement — the attempt stays open for reconciliation"
            );
            let crate::payments::engine::VerifyError::AmountMismatch { ref payment_id, .. } = error
            else {
                unreachable!("matched arm guarantees AmountMismatch")
            };
            raise_billing_incident(
                pool,
                "provider_renewal_amount_mismatch",
                "critical",
                Some(tenant_id),
                Some(payment_id.as_str()),
                serde_json::json!({
                    "tenantId": tenant_id,
                    "paymentId": payment_id,
                    "error": error.to_string(),
                }),
            )
            .await;
            return Err(RenewalReconciliationError::Verify(error));
        }
        Err(error) => return Err(RenewalReconciliationError::Verify(error)),
    };
    let settled_now = crate::payments::engine::settle_verified(pool, "mollie", &verified)
        .await
        .map_err(RenewalReconciliationError::Other)?;

    let invoice_id = verified.invoice_id;
    if !settled_now {
        // A replay: the obligation was already settled exactly once.
        return Ok(Some(invoice_id));
    }
    if let Err(error) =
        crate::vat_recognition::materialize_invoice_recognition_by_id(pool, invoice_id, Utc::now())
            .await
    {
        tracing::warn!(
            invoice_id = %invoice_id,
            error = %error,
            "failed to materialize VAT recognition after the reconciled renewal settlement"
        );
    }

    // The LOCAL row is the authority: only an ACTIVE subscription's period
    // advances. A canceled (or past_due/paused) subscription is never
    // resurrected by a provider fact — the settlement stands, the state
    // does not move, and the reconciliation is audited.
    if status == "active" {
        let plan = plan.ok_or_else(|| {
            RenewalReconciliationError::Other(format!(
                "active subscription {row_id} carries no plan; the period cannot advance"
            ))
        })?;
        let interval = interval.unwrap_or("monthly");
        advance_period(
            pool,
            row_id,
            tenant_id,
            plan,
            interval,
            invoice_id,
            0,
            gross_cents,
            Utc::now(),
        )
        .await
        .map_err(RenewalReconciliationError::Other)?;
    } else {
        let mut audit_tx = conn
            .begin()
            .await
            .map_err(|error| RenewalReconciliationError::Other(error.to_string()))?;
        append_audit_log(
            &mut audit_tx,
            tenant_id,
            "billing.provider_renewal_reconciled",
            "subscription",
            Some(&row_id.to_string()),
            serde_json::json!({
                "paymentId": payment_id,
                "invoiceId": invoice_id,
                "subscriptionStatus": status,
                "applied": false,
                "reason": "the local subscription is not active; a provider fact never resurrects it",
            }),
            Utc::now(),
        )
        .await
        .map_err(|error| RenewalReconciliationError::Other(error.to_string()))?;
        audit_tx
            .commit()
            .await
            .map_err(|error| RenewalReconciliationError::Other(error.to_string()))?;
    }
    Ok(Some(invoice_id))
}

/// A subscription charge failed: the row moves to `past_due` and the
/// customer is notified; no local mandate charge is attempted for this
/// period (the local renewal worker owns retries, and a `past_due` row has
/// left its active set).
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

    #[test]
    fn dunning_policy_is_three_attempts_and_never_cancellation() {
        assert_eq!(MAX_DUNNING_ATTEMPTS, 3);
    }
}
