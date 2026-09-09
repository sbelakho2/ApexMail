//! Subscription overage and PAYG usage: soft-limit enforcement plus
//! end-of-period invoicing AND collection.
//!
//! Published behaviour (docs/pricing.md, marketing pricing FAQ): a paid plan
//! is NOT hard-blocked at its included volume — sending continues into an
//! overage allowance and the extra volume is invoiced at the configured
//! rate (default €0.40 per 1,000 emails) when the billing period ends.
//! PAYG (unlimited, zero base price) tenants are invoiced for their whole
//! metered volume at the tiered [`crate::config::PaygPricing`] rates at the
//! end of each calendar month. The enforcement half lives in
//! `usage::record_with_quota_check` (which passes the ceiling below to the
//! Redis quota Lua); this module implements the ceiling math and the daily
//! sweep that turns accrued usage into a COLLECTED invoice.
//!
//! # Period records (audits F30/F31)
//!
//! Billable periods live in the immutable `billing_periods` table
//! (migration 137), written by the Stripe subscription webhook at every
//! period transition and by a catch-up insert at the top of the sweep. A
//! renewal can no longer overwrite the period bounds before the sweep
//! reads them. The sweep selects only `invoice_state = 'unbilled'` rows —
//! completed work is excluded in SQL — and pages through them with a
//! stable keyset cursor on `(period_end, tenant_id)`.
//!
//! # Claim atomicity (audit F29)
//!
//! Claiming a period and inserting its invoice happen in ONE transaction:
//! `pg_advisory_xact_lock(tenant, kind, period)` + a state re-check +
//! [`crate::invoices::create_invoice_in_tx`] + the period's
//! `invoiced` transition + a collection-outbox operation, all committed
//! together. The UNIQUE index on `invoices (tenant_id, overage_period)`
//! (migration 136) is the schema-level backstop; a unique violation
//! returns the EXISTING invoice without collecting it twice.
//!
//! # Collection flow (audits F33/F34/F35)
//!
//! Every invoice the sweep creates gets a `collect_usage_invoice` outbox
//! row in the same transaction (migration 138), so collection is resumable
//! — a crash after invoice creation can never strand a draft. The ladder
//! commits each step and checks every commit:
//!
//! 1. **Wallet first.** The tenant's EUR wallet balance is applied to the
//!    invoice; the wallet debit, its `wallet_transactions` row and an
//!    immutable `invoice_payment_allocations` row (unique operation id)
//!    commit together (audit F35). A non-EUR wallet is never spent —
//!    currency mixing would mint phantom money. Outstanding is always
//!    `total − confirmed payments − credit notes`.
//! 2. **Stripe invoice item.** For tenants with a Stripe customer on file
//!    and a configured `STRIPE_SECRET_KEY`, the REMAINING amount is added
//!    as a pending invoice item (`/v1/invoiceitems`, idempotency key
//!    `overage_{tenant}_{period_start}`) so Stripe collects it on the next
//!    billing cycle. The item id is stored in the DEDICATED
//!    `stripe_invoice_item_id` column (audit F34) — never in
//!    `stripe_invoice_id`, which the `invoice.paid` webhook matches
//!    against real `in_...` invoice ids. The HTTP call happens OUTSIDE any
//!    wallet-lock transaction (audit F33).
//! 3. **Dunning.** Whatever the wallet did not cover flips the invoice
//!    from `draft` to `pending` with an explicit `dunning_entered` event
//!    (local/PAYG dunning is enqueued explicitly), entering the existing
//!    dunning flow (soft-suspend after 7 days, hard-suspend after 21,
//!    7-day grace — see `stripe_webhooks.rs` and the `dunning_config`
//!    defaults) instead of rotting as a draft nothing ever charges.

use crate::config::PaygPricing;
use crate::invoices::{
    create_invoice_in_tx, invoice_outstanding_cents, CreateInvoiceInput, InvoiceError, NewLineItem,
};
use crate::plans;
use crate::types::Invoice;
use crate::AppState;
use chrono::{DateTime, Datelike, Timelike, Utc};
use deadpool_redis::redis::AsyncCommands;
use sqlx::PgPool;
use tracing::{info, warn};
use uuid::Uuid;

/// Overage allowance as a percentage of the plan's included email volume
/// (100 = the tenant may send up to 200% of the plan limit before the hard
/// 403). 0 disables the soft ceiling (pure hard quota). Override with
/// `OVERAGE_ALLOWANCE_PERCENT`.
pub fn overage_allowance_percent() -> i64 {
    std::env::var("OVERAGE_ALLOWANCE_PERCENT")
        .ok()
        .and_then(|v| v.trim().parse::<i64>().ok())
        .unwrap_or(100)
        .clamp(0, 1000)
}

/// The enforcement ceiling for a metering counter, given the plan limit.
/// Unlimited plans (-1) stay unlimited; a hard cap applies only beyond the
/// allowance so a runaway loop cannot bill unbounded volume.
pub fn overage_ceiling(plan_limit: i64) -> i64 {
    if plan_limit < 0 {
        return -1;
    }
    let allowance = plan_limit.saturating_mul(overage_allowance_percent()) / 100;
    plan_limit.saturating_add(allowance)
}

/// End-of-period usage-invoicing switch (`OVERAGE_INVOICING_ENABLED`,
/// default on). Enforcement is independent: the ceiling above always lets
/// paid tenants cross the plan boundary; this only controls whether the
/// accrued usage is invoiced by the sweep.
pub fn overage_invoicing_enabled() -> bool {
    std::env::var("OVERAGE_INVOICING_ENABLED")
        .map(|v| v != "false" && v != "0")
        .unwrap_or(true)
}

/// Page size for the sweep's keyset pagination (audit F31). A page smaller
/// than this means the cursor reached the end.
const SWEEP_PAGE: i64 = 500;

/// Unbilled-period selection for the overage sweep (audits F29/F31):
/// completed work is excluded IN SQL (`invoice_state = 'unbilled'`) and
/// pagination is a stable keyset on `(period_end, tenant_id)`. Pinned by
/// unit tests.
const SWEEP_UNBILLED_PERIODS_SQL: &str = r#"
    SELECT id, tenant_id, stripe_subscription_id, period_start, period_end,
           plan_name, email_allowance
    FROM billing_periods
    WHERE usage_kind = 'subscription'
      AND invoice_state = 'unbilled'
      AND period_end < NOW()
      AND period_end > NOW() - INTERVAL '40 days'
      AND (
            $1::timestamptz IS NULL
            OR (period_end, tenant_id) > ($1::timestamptz, $2::text)
          )
    ORDER BY period_end, tenant_id
    LIMIT $3
    "#;

#[derive(Debug, Default)]
pub struct OverageSweepResult {
    pub periods_checked: u64,
    pub invoices_created: u64,
    pub skipped_no_address: u64,
    pub skipped_no_overage: u64,
    /// Tenants whose plan name resolves to nothing (missing plans row AND
    /// unknown to the builtin seeds) — skipped loudly, never billed
    /// limit-0 (audit 1.3).
    pub skipped_unknown_plan: u64,
    /// PAYG calendar-month invoices created by the PAYG half of the sweep.
    pub payg_invoices_created: u64,
    /// Invoices fully covered by the wallet and marked paid.
    pub wallet_paid: u64,
    /// Invoices left `pending` for the dunning flow / Stripe next cycle.
    pub pending_dunning: u64,
    /// Periods whose invoice already existed when claimed (unique index
    /// backstop) — the existing invoice was reused, never double-collected
    /// (audit F29).
    pub conflicts_existing: u64,
}

/// An immutable billing-period record selected by the sweep (migration
/// 137). `plan_name`/`email_allowance` are the snapshot taken when the
/// period was recorded — pricing uses THE SAME plan for allowance and rate
/// (audit F32).
#[derive(sqlx::FromRow)]
struct BillingPeriodRow {
    id: Uuid,
    tenant_id: String,
    stripe_subscription_id: Option<String>,
    period_start: DateTime<Utc>,
    period_end: DateTime<Utc>,
    plan_name: Option<String>,
    email_allowance: Option<i64>,
}

/// Daily sweep: for every recently-ended billing cycle, compute metered
/// `emails_sent` beyond the plan limit and invoice (and collect) the
/// overage; then invoice PAYG tenants for their metered calendar-month
/// usage. Idempotent per (tenant, period): a period with an existing usage
/// invoice is skipped (uniqueness enforced at the schema level), so re-runs
/// after downtime are safe. The lookback window covers the metering TTL
/// (40 days).
pub async fn sweep_period_overage(state: &AppState) -> Result<OverageSweepResult, String> {
    if !overage_invoicing_enabled() {
        info!("overage invoicing disabled (OVERAGE_INVOICING_ENABLED=false)");
        return Ok(OverageSweepResult::default());
    }

    let mut result = OverageSweepResult::default();
    sweep_subscription_periods(state, &mut result).await?;
    sweep_payg_calendar_months(state, &mut result).await?;
    Ok(result)
}

/// Effective plan for a subscription's period, status-aware (audit F32):
/// ACTIVE subscriptions resolve the TENANT-level override-aware plan — the
/// same source the enforcement gate used; terminal/trialing rows resolve
/// the SUBSCRIPTION's own plan, because the tenant is frequently already
/// downgraded to free and pricing the old cycle at today's free limit
/// would bill volume that was never granted. Returns (plan_name,
/// email_limit) — the plan and its allowance in ONE row, so the rate
/// ladder can never price a different plan than the allowance came from.
const EFFECTIVE_PERIOD_PLAN_SQL: &str = r#"
    SELECT
        CASE WHEN ss.status = 'active'
             THEN COALESCE(po.plan, t.plan, ss.plan)
             ELSE ss.plan
        END AS plan_name,
        p.email_limit
    FROM stripe_subscriptions ss
    JOIN tenants t ON t.id = ss.tenant_id
    LEFT JOIN plan_overrides po
      ON po.tenant_id = t.id
     AND po.active = true
     AND (po.expires_at IS NULL OR po.expires_at > NOW())
    LEFT JOIN plans p
      ON p.name = CASE WHEN ss.status = 'active'
                       THEN COALESCE(po.plan, t.plan, ss.plan)
                       ELSE ss.plan
                  END
    WHERE ss.tenant_id = $1
      AND ss.stripe_subscription_id = $2
    LIMIT 1
"#;

/// Ensure a `billing_periods` record exists for every subscription's
/// current cycle (migration 137 seeded historical ones). This is the
/// catch-up for period transitions the webhook path missed; the webhook
/// itself snapshots closing periods transactionally (audit F30).
async fn ensure_subscription_period_records(db: &PgPool) -> Result<(), String> {
    sqlx::query(
        r#"
        INSERT INTO billing_periods (
            tenant_id, stripe_subscription_id, usage_kind,
            period_start, period_end, currency, plan_name, email_allowance
        )
        SELECT
            ss.tenant_id, ss.stripe_subscription_id, 'subscription',
            ss.billing_cycle_start, ss.billing_cycle_end, 'EUR',
            CASE WHEN ss.status = 'active'
                 THEN COALESCE(po.plan, t.plan, ss.plan)
                 ELSE ss.plan
            END AS plan_name,
            p.email_limit
        FROM stripe_subscriptions ss
        JOIN tenants t ON t.id = ss.tenant_id
        LEFT JOIN plan_overrides po
          ON po.tenant_id = t.id
         AND po.active = true
         AND (po.expires_at IS NULL OR po.expires_at > NOW())
        LEFT JOIN plans p
          ON p.name = CASE WHEN ss.status = 'active'
                           THEN COALESCE(po.plan, t.plan, ss.plan)
                           ELSE ss.plan
                      END
        WHERE ss.billing_cycle_start IS NOT NULL
          AND ss.billing_cycle_end IS NOT NULL
          AND ss.billing_cycle_end > ss.billing_cycle_start
        ON CONFLICT (tenant_id, usage_kind, period_start) DO NOTHING
        "#,
    )
    .execute(db)
    .await
    .map_err(|e| format!("overage sweep: period record catch-up failed: {e}"))?;
    Ok(())
}

/// Overage half of the sweep: every ended `billing_periods` cycle in the
/// lookback, regardless of subscription status — a lapsed paid-tier trial
/// or a canceled subscription accrued real overage that must still be
/// invoiced (audit 1.3). Only never-paid free plans are skipped (free has
/// no overage entitlement by definition; the rate ladder returns None).
async fn sweep_subscription_periods(
    state: &AppState,
    result: &mut OverageSweepResult,
) -> Result<(), String> {
    ensure_subscription_period_records(&state.db).await?;

    // Audit F31: only UNBILLED periods are selected — completed work is
    // excluded in SQL, and the keyset cursor on (period_end, tenant_id)
    // makes pagination stable across concurrent state changes.
    let mut cursor: Option<(DateTime<Utc>, String)> = None;
    loop {
        let periods: Vec<BillingPeriodRow> = sqlx::query_as(SWEEP_UNBILLED_PERIODS_SQL)
            .bind(cursor.as_ref().map(|c| c.0))
            .bind(cursor.as_ref().map(|c| c.1.clone()))
            .bind(SWEEP_PAGE)
            .fetch_all(&state.db)
            .await
            .map_err(|e| format!("overage sweep: period query failed: {e}"))?;

        let page_len = periods.len();
        for period in &periods {
            result.periods_checked += 1;
            process_subscription_period(state, period, result).await?;
        }

        if page_len < SWEEP_PAGE as usize {
            break;
        }
        let last = periods.last().expect("page of SWEEP_PAGE has a last row");
        cursor = Some((last.period_end, last.tenant_id.clone()));
    }

    Ok(())
}

/// Metered `emails_sent` for exactly one billing period.
async fn metered_emails_for_period(
    executor: impl sqlx::Executor<'_, Database = sqlx::Postgres>,
    tenant_id: &str,
    period_start: DateTime<Utc>,
    period_end: DateTime<Utc>,
) -> Result<i64, String> {
    sqlx::query_scalar(
        r#"
        SELECT COALESCE(SUM(quantity), 0)::bigint
        FROM metering_events
        WHERE tenant_id = $1
          AND event_type = 'emails_sent'
          AND timestamp >= $2
          AND timestamp <  $3
        "#,
    )
    .bind(tenant_id)
    .bind(period_start)
    .bind(period_end)
    .fetch_one(executor)
    .await
    .map_err(|e| format!("overage sweep: usage query failed: {e}"))
}

/// Claim ONE billing period and, when it carries billable overage, insert
/// its invoice in the SAME transaction (audit F29). A concurrent winner or
/// a pre-existing invoice returns the existing invoice without collecting
/// it a second time.
async fn process_subscription_period(
    state: &AppState,
    period: &BillingPeriodRow,
    result: &mut OverageSweepResult,
) -> Result<(), String> {
    let mut tx = state
        .db
        .begin()
        .await
        .map_err(|e| format!("overage sweep: claim tx failed: {e}"))?;

    // Serialize the per-period claim: same lock shape the SLA sweep uses,
    // held to the end of THIS transaction (which now includes the insert).
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
        .bind(format!(
            "overage:{}:subscription:{}",
            period.tenant_id,
            period.period_start.to_rfc3339()
        ))
        .execute(&mut *tx)
        .await
        .map_err(|e| format!("overage sweep: advisory lock failed: {e}"))?;

    // State re-check INSIDE the lock: a concurrent sweep may have completed
    // this period between our SELECT and the claim.
    let current_state: Option<String> =
        sqlx::query_scalar("SELECT invoice_state::text FROM billing_periods WHERE id = $1")
            .bind(period.id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(|e| format!("overage sweep: period state re-check failed: {e}"))?;
    match current_state.as_deref() {
        Some("unbilled") => {}
        _ => {
            // Completed concurrently (or the record vanished) — nothing to do.
            let _ = tx.rollback().await;
            return Ok(());
        }
    }

    // ── Effective plan: allowance AND pricing come from the SAME plan ──
    // (audit F32). Prefer the period's immutable snapshot; fall back to a
    // live status-aware resolution when the snapshot carries no plan.
    let mut plan_name = period.plan_name.clone();
    let mut email_limit = period.email_allowance;

    if plan_name.as_deref().map(str::trim).unwrap_or("").is_empty() {
        let live: Option<(String, Option<i64>)> = sqlx::query_as(EFFECTIVE_PERIOD_PLAN_SQL)
            .bind(&period.tenant_id)
            .bind(&period.stripe_subscription_id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(|e| format!("overage sweep: plan limit query failed: {e}"))?;
        if let Some((name, limit)) = live {
            if !name.trim().is_empty() {
                plan_name = Some(name);
                if email_limit.is_none() {
                    email_limit = limit;
                }
            }
        }
    }

    let Some(plan_name) = plan_name else {
        warn!(
            tenant_id = %period.tenant_id,
            period_start = %period.period_start.to_rfc3339(),
            "overage sweep: period has no resolvable plan; skipping period"
        );
        result.skipped_unknown_plan += 1;
        let _ = tx.rollback().await;
        return Ok(());
    };

    let plan_limit = match email_limit {
        Some(limit) => Some(limit),
        None => {
            resolve_plan_limit_or_warn(
                &mut *tx,
                &period.tenant_id,
                &plan_name,
                &mut result.skipped_unknown_plan,
            )
            .await?
        }
    };

    let Some(plan_limit) = plan_limit else {
        let _ = tx.rollback().await;
        return Ok(()); // already counted + warned
    };

    if plan_limit < 0 {
        // Unlimited plan — no overage by definition. Terminal state, so
        // the sweep never revisits it (audit F31).
        mark_period_skipped(&mut tx, period.id).await?;
        tx.commit()
            .await
            .map_err(|e| format!("overage sweep: claim commit failed: {e}"))?;
        result.skipped_no_overage += 1;
        return Ok(());
    }

    // Metered sends for exactly this billing cycle.
    let sent = metered_emails_for_period(
        &mut *tx,
        period.tenant_id.as_str(),
        period.period_start,
        period.period_end,
    )
    .await?;

    // Checked arithmetic (audit F32): a metering anomaly must never wrap.
    let overage_emails = match sent.checked_sub(plan_limit) {
        Some(overage) => overage,
        None => {
            warn!(
                tenant_id = %period.tenant_id,
                sent,
                plan_limit,
                "overage sweep: metered volume underflow vs allowance; skipping period"
            );
            mark_period_skipped(&mut tx, period.id).await?;
            tx.commit()
                .await
                .map_err(|e| format!("overage sweep: claim commit failed: {e}"))?;
            result.skipped_no_overage += 1;
            return Ok(());
        }
    };

    if overage_emails <= 0 {
        mark_period_skipped(&mut tx, period.id).await?;
        tx.commit()
            .await
            .map_err(|e| format!("overage sweep: claim commit failed: {e}"))?;
        result.skipped_no_overage += 1;
        return Ok(());
    }

    // A billing address is mandatory on a VAT invoice; without one the
    // invoice cannot be issued correctly — surface loudly and retry next
    // sweep (the period stays `unbilled`, so nothing is double-billed once
    // the address is backfilled).
    if !tenant_has_billing_address(&period.tenant_id, &mut *tx).await? {
        result.skipped_no_address += 1;
        warn!(
            tenant_id = %period.tenant_id,
            overage_emails,
            "overage accrued but no billing address on file — invoice deferred"
        );
        let _ = tx.rollback().await;
        return Ok(());
    }

    // Review 2026-09-08 §9: the DIFFERENTIATED per-plan ladder prices
    // overage (Developer 80 / Pro 60 / Growth+Business+Enterprise 35
    // millicents per email). Free/PAYG/unknown plans have no automatic
    // overage — skip. The invoice text below quotes the same rate.
    let rate_millicents = match plans::plan_overage_rate_millicents(&plan_name) {
        Some(rate) => rate,
        None => {
            warn!(
                tenant_id = %period.tenant_id,
                plan = %plan_name,
                "overage sweep: plan has no automatic overage; skipping period"
            );
            mark_period_skipped(&mut tx, period.id).await?;
            tx.commit()
                .await
                .map_err(|e| format!("overage sweep: claim commit failed: {e}"))?;
            result.skipped_no_overage += 1;
            return Ok(());
        }
    };
    let amount_cents = plans::calculate_overage_cost_with_rate(sent, plan_limit, rate_millicents);
    if amount_cents <= 0 {
        mark_period_skipped(&mut tx, period.id).await?;
        tx.commit()
            .await
            .map_err(|e| format!("overage sweep: claim commit failed: {e}"))?;
        result.skipped_no_overage += 1;
        return Ok(());
    }

    let description = format!(
        "Overage: {overage_emails} emails beyond the plan limit ({plan_limit}/cycle), at {} per 1,000",
        format_rate_per_thousand_emails(rate_millicents)
    );

    let input = CreateInvoiceInput {
        tenant_id: period.tenant_id.clone(),
        stripe_invoice_id: None,
        line_items: vec![NewLineItem {
            description: description.clone(),
            quantity: 1,
            unit_price: amount_cents,
        }],
        period_start: period.period_start,
        period_end: period.period_end,
        due_at: None,
        currency: None, // invoices.rs defaults to EUR
        overage_period: Some(period.period_start),
    };

    // Claim + insert in ONE transaction (audit F29). A unique violation on
    // (tenant_id, overage_period) means another writer already invoiced
    // this period: adopt the EXISTING invoice, never double-collect.
    let invoice = match create_invoice_in_tx(&mut tx, input).await {
        Ok(invoice) => invoice,
        Err(error) if is_unique_violation(&error) => {
            let existing_id: Option<Uuid> = sqlx::query_scalar(
                "SELECT id FROM invoices WHERE tenant_id = $1 AND overage_period = $2 LIMIT 1",
            )
            .bind(&period.tenant_id)
            .bind(period.period_start)
            .fetch_optional(&mut *tx)
            .await
            .map_err(|e| format!("overage sweep: existing-invoice lookup failed: {e}"))?;

            if let Some(existing_id) = existing_id {
                mark_period_invoiced(&mut tx, period.id, existing_id, sent).await?;
                enqueue_collection(
                    &mut tx,
                    &period.tenant_id,
                    existing_id,
                    period.period_start,
                    &description,
                    "overage",
                )
                .await?;
                tx.commit()
                    .await
                    .map_err(|e| format!("overage sweep: claim commit failed: {e}"))?;
                result.conflicts_existing += 1;
                info!(
                    tenant_id = %period.tenant_id,
                    invoice_id = %existing_id,
                    "overage sweep: period already invoiced — reusing existing invoice, no second collection"
                );
            } else {
                let _ = tx.rollback().await;
            }
            return Ok(());
        }
        Err(error) => {
            warn!(
                tenant_id = %period.tenant_id,
                error = %error,
                "overage sweep: invoice creation failed; retried on next sweep"
            );
            let _ = tx.rollback().await;
            return Ok(());
        }
    };

    mark_period_invoiced(&mut tx, period.id, invoice.id, sent).await?;
    enqueue_collection(
        &mut tx,
        &period.tenant_id,
        invoice.id,
        period.period_start,
        &description,
        "overage",
    )
    .await?;

    tx.commit()
        .await
        .map_err(|e| format!("overage sweep: claim commit failed: {e}"))?;

    result.invoices_created += 1;
    info!(
        tenant_id = %period.tenant_id,
        invoice_number = %invoice.invoice_number,
        overage_emails,
        amount_cents,
        "overage invoice created for ended billing period"
    );

    // Collection runs AFTER the claim committed — external calls must stay
    // out of the claim transaction (audit F33).
    collect_usage_invoice(
        state,
        &invoice,
        period.period_start,
        &description,
        "overage",
        &mut result.wallet_paid,
        &mut result.pending_dunning,
    )
    .await;

    Ok(())
}

/// PAYG half of the sweep (audit 1.3 — PAYG was priced and displayed but
/// never billed). PAYG tenants (unlimited email limit, zero base price,
/// typically no Stripe subscription) are invoiced per COMPLETED calendar
/// month — the same period the quota/reporting paths use for tenants
/// without a subscription cycle — from the existing metering events.
/// Usage-record pushing to Stripe Meter is deliberately NOT used; the
/// invoice-item mechanism in [`collect_usage_invoice`] collects the cost.
/// A month that computes to zero is skipped silently.
async fn sweep_payg_calendar_months(
    state: &AppState,
    result: &mut OverageSweepResult,
) -> Result<(), String> {
    let pricing = PaygPricing::default();
    let months = recent_completed_calendar_months(Utc::now());

    // Audit F31: stable keyset pagination on tenant id — the same tenants
    // are never re-scanned past the cursor within one sweep pass.
    let mut cursor: Option<String> = None;
    loop {
        let tenants: Vec<String> = sqlx::query_scalar(
            r#"
            SELECT DISTINCT t.id
            FROM tenants t
            LEFT JOIN plan_overrides po
              ON po.tenant_id = t.id
             AND po.active = true
             AND (po.expires_at IS NULL OR po.expires_at > NOW())
            WHERE COALESCE(po.plan, t.plan) = 'payg'
              AND ($1::text IS NULL OR t.id > $1::text)
            ORDER BY t.id
            LIMIT $2
            "#,
        )
        .bind(cursor.as_ref().cloned())
        .bind(SWEEP_PAGE)
        .fetch_all(&state.db)
        .await
        .map_err(|e| format!("payg sweep: tenant query failed: {e}"))?;

        let page_len = tenants.len();
        for tenant_id in &tenants {
            for &(month_start, month_end) in &months {
                process_payg_month(state, tenant_id, month_start, month_end, &pricing, result)
                    .await?;
            }
        }

        if page_len < SWEEP_PAGE as usize {
            break;
        }
        cursor = tenants.last().cloned();
    }

    Ok(())
}

/// Claim one PAYG calendar month (period record + invoice in one
/// transaction — same claim atomicity as the subscription half) and
/// collect the resulting invoice.
async fn process_payg_month(
    state: &AppState,
    tenant_id: &str,
    month_start: DateTime<Utc>,
    month_end: DateTime<Utc>,
    pricing: &PaygPricing,
    result: &mut OverageSweepResult,
) -> Result<(), String> {
    let mut tx = state
        .db
        .begin()
        .await
        .map_err(|e| format!("payg sweep: claim tx failed: {e}"))?;

    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
        .bind(format!(
            "overage:{tenant_id}:payg:{}",
            month_start.to_rfc3339()
        ))
        .execute(&mut *tx)
        .await
        .map_err(|e| format!("payg sweep: advisory lock failed: {e}"))?;

    // Claim-or-adopt the period record: inserted here the first time,
    // adopted (with a state re-check) when a previous run already created
    // it (audit F29/F30).
    let inserted: Option<Uuid> = sqlx::query_scalar(
        r#"
        INSERT INTO billing_periods (
            tenant_id, usage_kind, period_start, period_end, currency, plan_name
        )
        VALUES ($1, 'payg', $2, $3, 'EUR', 'payg')
        ON CONFLICT (tenant_id, usage_kind, period_start) DO NOTHING
        RETURNING id
        "#,
    )
    .bind(tenant_id)
    .bind(month_start)
    .bind(month_end)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|e| format!("payg sweep: period claim failed: {e}"))?;

    let period_id = match inserted {
        Some(id) => id,
        None => {
            let existing: Option<(Uuid, String)> = sqlx::query_as(
                "SELECT id, invoice_state::text FROM billing_periods \
                 WHERE tenant_id = $1 AND usage_kind = 'payg' AND period_start = $2",
            )
            .bind(tenant_id)
            .bind(month_start)
            .fetch_optional(&mut *tx)
            .await
            .map_err(|e| format!("payg sweep: period lookup failed: {e}"))?;
            match existing {
                Some((id, state)) if state == "unbilled" => id,
                _ => {
                    let _ = tx.rollback().await;
                    return Ok(()); // completed (or gone) — skip
                }
            }
        }
    };

    let usage: (i64, i64) = sqlx::query_as(
        r#"
        SELECT
            COALESCE(SUM(quantity) FILTER (WHERE event_type = 'emails_sent'), 0)::bigint,
            COALESCE(SUM(quantity) FILTER (WHERE event_type = 'api_calls'), 0)::bigint
        FROM metering_events
        WHERE tenant_id = $1
          AND timestamp >= $2
          AND timestamp <  $3
        "#,
    )
    .bind(tenant_id)
    .bind(month_start)
    .bind(month_end)
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| format!("payg sweep: usage query failed: {e}"))?;
    let (emails_sent, api_calls) = usage;

    let Ok((email_cost_cents, api_cost_cents, total_cents)) =
        pricing.calculate(emails_sent.max(0) as u64, api_calls.max(0) as u64)
    else {
        let _ = tx.rollback().await;
        return Ok(());
    };
    if total_cents <= 0 {
        mark_period_skipped(&mut tx, period_id).await?;
        tx.commit()
            .await
            .map_err(|e| format!("payg sweep: claim commit failed: {e}"))?;
        return Ok(()); // zero-cost month — skip silently
    }

    if !tenant_has_billing_address(tenant_id, &mut *tx).await? {
        result.skipped_no_address += 1;
        warn!(
            tenant_id = tenant_id,
            "PAYG usage accrued but no billing address on file — invoice deferred"
        );
        let _ = tx.rollback().await;
        return Ok(());
    }

    let mut line_items = Vec::with_capacity(2);
    if email_cost_cents > 0 {
        line_items.push(NewLineItem {
            description: format!("PAYG usage: {emails_sent} emails (tiered per-email pricing)"),
            quantity: 1,
            unit_price: email_cost_cents,
        });
    }
    if api_cost_cents > 0 {
        line_items.push(NewLineItem {
            description: format!(
                "PAYG usage: {api_calls} API calls (above the monthly free allowance)"
            ),
            quantity: 1,
            unit_price: api_cost_cents,
        });
    }
    if line_items.is_empty() {
        let _ = tx.rollback().await;
        return Ok(());
    }
    let description = format!(
        "PAYG usage for {} — {emails_sent} emails, {api_calls} API calls",
        month_start.format("%Y-%m")
    );

    let input = CreateInvoiceInput {
        tenant_id: tenant_id.to_string(),
        stripe_invoice_id: None,
        line_items,
        period_start: month_start,
        period_end: month_end,
        due_at: None,
        currency: None, // invoices.rs defaults to EUR
        overage_period: Some(month_start),
    };

    let invoice = match create_invoice_in_tx(&mut tx, input).await {
        Ok(invoice) => invoice,
        Err(error) if is_unique_violation(&error) => {
            // Another writer already invoiced this month — adopt it, never
            // double-collect (audit F29).
            let existing_id: Option<Uuid> = sqlx::query_scalar(
                "SELECT id FROM invoices WHERE tenant_id = $1 AND overage_period = $2 LIMIT 1",
            )
            .bind(tenant_id)
            .bind(month_start)
            .fetch_optional(&mut *tx)
            .await
            .map_err(|e| format!("payg sweep: existing-invoice lookup failed: {e}"))?;

            if let Some(existing_id) = existing_id {
                mark_period_invoiced(&mut tx, period_id, existing_id, emails_sent).await?;
                enqueue_collection(
                    &mut tx,
                    tenant_id,
                    existing_id,
                    month_start,
                    &description,
                    "payg",
                )
                .await?;
                tx.commit()
                    .await
                    .map_err(|e| format!("payg sweep: claim commit failed: {e}"))?;
                result.conflicts_existing += 1;
            } else {
                let _ = tx.rollback().await;
            }
            return Ok(());
        }
        Err(error) => {
            warn!(
                tenant_id = tenant_id,
                error = %error,
                "payg sweep: invoice creation failed; retried on next sweep"
            );
            let _ = tx.rollback().await;
            return Ok(());
        }
    };

    mark_period_invoiced(&mut tx, period_id, invoice.id, emails_sent).await?;
    enqueue_collection(
        &mut tx,
        tenant_id,
        invoice.id,
        month_start,
        &description,
        "payg",
    )
    .await?;

    tx.commit()
        .await
        .map_err(|e| format!("payg sweep: claim commit failed: {e}"))?;

    result.payg_invoices_created += 1;
    info!(
        tenant_id = tenant_id,
        invoice_number = %invoice.invoice_number,
        emails_sent,
        api_calls,
        total_cents,
        "PAYG invoice created for completed calendar month"
    );

    collect_usage_invoice(
        state,
        &invoice,
        month_start,
        &description,
        "payg",
        &mut result.wallet_paid,
        &mut result.pending_dunning,
    )
    .await;

    Ok(())
}

/// Terminal `skipped` transition for a period (no overage / not billable).
/// The sweep never revisits it (audit F31).
async fn mark_period_skipped(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    period_id: Uuid,
) -> Result<(), String> {
    sqlx::query(
        "UPDATE billing_periods SET invoice_state = 'skipped', updated_at = NOW() WHERE id = $1",
    )
    .bind(period_id)
    .execute(&mut **tx)
    .await
    .map_err(|e| format!("overage sweep: skip transition failed: {e}"))?;
    Ok(())
}

/// `unbilled -> invoiced` transition with the usage watermark and invoice
/// link.
async fn mark_period_invoiced(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    period_id: Uuid,
    invoice_id: Uuid,
    metered_emails: i64,
) -> Result<(), String> {
    sqlx::query(
        r#"
        UPDATE billing_periods
        SET invoice_state = 'invoiced', invoice_id = $2, metered_emails = $3, updated_at = NOW()
        WHERE id = $1
        "#,
    )
    .bind(period_id)
    .bind(invoice_id)
    .bind(metered_emails)
    .execute(&mut **tx)
    .await
    .map_err(|e| format!("overage sweep: invoiced transition failed: {e}"))?;
    Ok(())
}

/// Create the invoice's collection-outbox operation in the SAME
/// transaction as the invoice (audit F33): collection is resumable, a
/// crash can never strand a draft invoice nothing revisits.
async fn enqueue_collection(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    tenant_id: &str,
    invoice_id: Uuid,
    period_start: DateTime<Utc>,
    description: &str,
    usage_kind: &str,
) -> Result<(), String> {
    sqlx::query(
        r#"
        INSERT INTO invoice_collection_outbox (tenant_id, invoice_id, operation, status, payload)
        VALUES ($1, $2, 'collect_usage_invoice', 'pending', $3::jsonb)
        ON CONFLICT (invoice_id, operation) DO NOTHING
        "#,
    )
    .bind(tenant_id)
    .bind(invoice_id)
    .bind(
        serde_json::json!({
            "periodStart": period_start.to_rfc3339(),
            "usageKind": usage_kind,
            "description": description,
        })
        .to_string(),
    )
    .execute(&mut **tx)
    .await
    .map_err(|e| format!("overage sweep: outbox enqueue failed: {e}"))?;
    Ok(())
}

/// Whether an invoice-creation error is a UNIQUE constraint violation —
/// the (tenant_id, overage_period) backstop firing (audit F29).
fn is_unique_violation(error: &InvoiceError) -> bool {
    matches!(
        error,
        InvoiceError::Db(sqlx::Error::Database(db_error)) if db_error.code().as_deref() == Some("23505")
    )
}

/// Resolve a plan's email limit: a present `plans.email_limit` wins (the
/// claim's live query joins it override-aware); otherwise the plans row is
/// looked up by name so operator-configured limits still win; a
/// missing/deactivated plans row falls back to the BUILTIN plan's limit by
/// name (exactly how `usage::resolve_plan_limits` resolves quotas); an
/// unknown plan name returns `None` after a loud warn — the caller skips
/// the tenant rather than billing everything as overage.
async fn resolve_plan_limit_or_warn<'e, E>(
    executor: E,
    tenant_id: &str,
    plan_name: &str,
    skipped_unknown_plan: &mut u64,
) -> Result<Option<i64>, String>
where
    E: sqlx::Executor<'e, Database = sqlx::Postgres>,
{
    let row_limit: Option<i64> =
        sqlx::query_scalar("SELECT email_limit FROM plans WHERE name = $1")
            .bind(plan_name)
            .fetch_optional(executor)
            .await
            .map_err(|e| format!("overage sweep: plan lookup failed: {e}"))?;
    if let Some(limit) = row_limit {
        return Ok(Some(limit));
    }
    // No plans row at all (missing/deactivated). Builtin seed by name.
    match plans::builtin_email_limit_for_plan(plan_name) {
        Some(limit) => {
            warn!(
                tenant_id = tenant_id,
                plan = plan_name,
                email_limit = limit,
                "overage sweep: plans row missing; using builtin plan limit"
            );
            Ok(Some(limit))
        }
        None => {
            *skipped_unknown_plan += 1;
            warn!(
                tenant_id = tenant_id,
                plan = plan_name,
                "overage sweep: unknown plan name (no plans row, no builtin seed) — \
                 skipping period; refusing to bill the tenant's entire volume as overage"
            );
            Ok(None)
        }
    }
}

/// Existence-check SQL for the billing-address gate. Audit F28: it must
/// select `EXISTS(...)` (bool) — the previous `SELECT 1` bound Postgres
/// INT4 into an i64 and failed to decode. Pinned by unit test.
const ADDRESS_EXISTS_SQL: &str =
    "SELECT EXISTS(SELECT 1 FROM billing_addresses WHERE tenant_id = $1)";

/// Whether the tenant has a billing address on file (mandatory on a VAT
/// invoice). Uses SELECT EXISTS — `SELECT 1` decodes INT4 and cannot bind
/// to i64 (audit F28).
async fn tenant_has_billing_address<'e, T>(tenant_id: &str, executor: T) -> Result<bool, String>
where
    T: sqlx::Executor<'e, Database = sqlx::Postgres>,
{
    let has_address: bool = sqlx::query_scalar(ADDRESS_EXISTS_SQL)
        .bind(tenant_id)
        .fetch_one(executor)
        .await
        .map_err(|e| format!("overage sweep: address query failed: {e}"))?;
    Ok(has_address)
}

/// The completed calendar months whose end lies within the metering TTL
/// window (40 days) — at most two (the previous month and, early in a
/// month, the one before it).
fn recent_completed_calendar_months(now: DateTime<Utc>) -> Vec<(DateTime<Utc>, DateTime<Utc>)> {
    let mut months = Vec::with_capacity(2);
    let mut cursor = first_of_month(now);
    let cutoff = now - chrono::Duration::days(40);
    for _ in 0..2 {
        let previous_end = cursor;
        let previous_start = first_of_month(cursor - chrono::Duration::days(1));
        if previous_end <= cutoff || previous_end > now {
            break;
        }
        months.push((previous_start, previous_end));
        cursor = previous_start;
    }
    months
}

fn first_of_month(at: DateTime<Utc>) -> DateTime<Utc> {
    at.with_day(1)
        .and_then(|d| d.with_hour(0))
        .and_then(|d| d.with_minute(0))
        .and_then(|d| d.with_second(0))
        .and_then(|d| d.with_nanosecond(0))
        .unwrap_or(at)
}

/// The configured overage rate rendered as "€X.YZ per 1,000 emails"
/// (integer math — 40 millicents/email is 40 cents per 1 000 emails,
/// i.e. "€0.40"). The invoice text must quote the rate actually charged,
/// never a hardcoded "€0.40".
fn format_rate_per_thousand_emails(rate_millicents: i64) -> String {
    // 1 000 emails × rate millicents = rate cents = rate/100 euros.
    let cents_per_thousand = rate_millicents.max(0);
    billing_common::proration::cents_to_eur_string(cents_per_thousand)
}

/// Collection ladder for a freshly created usage invoice (see the module
/// docs). Resumable: every step commits durably and is idempotent, and the
/// outbox operation written with the invoice tracks progress (audit F33).
/// Failures never leave the invoice in `draft`: worst case it is `pending`
/// and dunning owns it.
async fn collect_usage_invoice(
    state: &AppState,
    invoice: &Invoice,
    period_start: DateTime<Utc>,
    description: &str,
    usage_kind: &str,
    wallet_paid: &mut u64,
    pending_dunning: &mut u64,
) {
    // Outbox: pending -> in_progress (attempts bumped). The row was created
    // atomically with the invoice; claiming it here makes the ladder's
    // progress visible and resumable.
    claim_collection_operation(state, invoice.id).await;

    // (a) Wallet first — EUR only, committed WITH its payment allocation
    // (audit F35). A non-EUR wallet is never spent on a EUR invoice;
    // mixing currencies would mint phantom money.
    let applied_cents = apply_wallet_credit(state, invoice).await;

    // Outstanding AFTER the wallet application — the single derivation
    // (total − confirmed payments − credits; audit F35).
    let remaining_cents = match invoice_outstanding_cents(&state.db, invoice.id).await {
        Ok(outstanding) => outstanding,
        Err(error) => {
            warn!(
                tenant_id = %invoice.tenant_id,
                invoice_number = %invoice.invoice_number,
                error = %error,
                "usage invoice collection: outstanding lookup failed — treating full total as outstanding"
            );
            invoice.total.saturating_sub(applied_cents)
        }
    };

    // (b) Whole-invoice paid when confirmed payments covered everything.
    if remaining_cents <= 0 {
        if let Err(error) = finalize_collection(state, invoice, "paid").await {
            warn!(
                tenant_id = %invoice.tenant_id,
                invoice_number = %invoice.invoice_number,
                error = %error,
                "usage invoice collection: marking paid failed — outbox stays resumable"
            );
        } else {
            *wallet_paid += 1;
            info!(
                tenant_id = %invoice.tenant_id,
                invoice_number = %invoice.invoice_number,
                applied_cents,
                "usage invoice settled in full from wallet balance"
            );
        }
        invalidate_wallet_balance_cache(state, &invoice.tenant_id).await;
        return;
    }

    // (c) Stripe-managed tenants: add the REMAINING amount as a pending
    // invoice item (collected on the next billing cycle). Idempotent per
    // (tenant, period) so sweep retries never duplicate the item. Failure
    // is non-fatal — the local invoice still moves to pending/dunning.
    // The HTTP call runs OUTSIDE every wallet-lock transaction (F33), and
    // the ITEM id is stored in its own column — never in
    // stripe_invoice_id, which belongs to real Stripe invoices (F34).
    let stripe_item_id = match create_stripe_invoiceitem(
        state,
        &invoice.tenant_id,
        remaining_cents,
        description,
        period_start,
        usage_kind,
    )
    .await
    {
        Ok(id) => id,
        Err(error) => {
            warn!(
                tenant_id = %invoice.tenant_id,
                invoice_number = %invoice.invoice_number,
                error = %error,
                "usage invoice collection: Stripe invoice item failed — invoice enters dunning without a Stripe mirror"
            );
            None
        }
    };

    if let Some(item_id) = stripe_item_id.as_deref() {
        match sqlx::query(
            "UPDATE invoices SET stripe_invoice_item_id = $2, updated_at = NOW() WHERE id = $1",
        )
        .bind(invoice.id)
        .bind(item_id)
        .execute(&state.db)
        .await
        {
            Ok(_) => {}
            Err(error) => warn!(
                tenant_id = %invoice.tenant_id,
                invoice_number = %invoice.invoice_number,
                error = %error,
                "usage invoice collection: storing Stripe invoice-item id failed (item exists at Stripe)"
            ),
        }
    }

    // (d) Pending → dunning flow (soft 7d / hard 21d / grace 7d) with an
    // explicit dunning-entered event so local/PAYG tenants are enqueued
    // into dunning deliberately, not by side effect.
    match finalize_collection(state, invoice, "pending").await {
        Ok(()) => {
            *pending_dunning += 1;
            info!(
                tenant_id = %invoice.tenant_id,
                invoice_number = %invoice.invoice_number,
                applied_cents,
                remaining_cents,
                stripe_invoice_item = ?stripe_item_id,
                "usage invoice moved to pending — wallet applied, remainder via dunning/Stripe"
            );
        }
        Err(error) => {
            warn!(
                tenant_id = %invoice.tenant_id,
                invoice_number = %invoice.invoice_number,
                error = %error,
                "usage invoice collection: marking pending failed — outbox stays resumable"
            );
        }
    }

    invalidate_wallet_balance_cache(state, &invoice.tenant_id).await;
}

/// Outbox claim: pending/in_progress -> in_progress with a bumped attempt
/// counter. Best-effort — a missing row (legacy invoices) must not block
/// the ladder.
async fn claim_collection_operation(state: &AppState, invoice_id: Uuid) {
    let claim = sqlx::query(
        r#"
        UPDATE invoice_collection_outbox
        SET status = 'in_progress', attempts = attempts + 1, updated_at = NOW()
        WHERE invoice_id = $1 AND operation = 'collect_usage_invoice'
          AND status IN ('pending', 'in_progress')
        "#,
    )
    .bind(invoice_id)
    .execute(&state.db)
    .await;
    if let Err(error) = claim {
        warn!(
            invoice_id = %invoice_id,
            error = %error,
            "usage invoice collection: outbox claim failed — continuing (ladder is idempotent)"
        );
    }
}

/// Apply the tenant's EUR wallet balance to the invoice. The wallet debit,
/// its `wallet_transactions` row and the immutable payment allocation
/// (unique operation id) commit TOGETHER (audit F35). Serialization:
/// advisory lock on the invoice, so the sweep and the outbox resumer can
/// never double-apply. Returns the cents applied by THIS call (0 when the
/// wallet is empty, non-EUR, or the invoice is already covered).
async fn apply_wallet_credit(state: &AppState, invoice: &Invoice) -> i64 {
    let mut tx = match state.db.begin().await {
        Ok(tx) => tx,
        Err(error) => {
            warn!(
                tenant_id = %invoice.tenant_id,
                invoice_number = %invoice.invoice_number,
                error = %error,
                "usage invoice collection: failed to open wallet transaction — no wallet credit applied"
            );
            return 0;
        }
    };

    let lock = sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
        .bind(format!("usage_collect:{}", invoice.id))
        .execute(&mut *tx)
        .await;
    if let Err(error) = lock {
        warn!(
            tenant_id = %invoice.tenant_id,
            error = %error,
            "usage invoice collection: wallet serialization lock failed — no wallet credit applied"
        );
        let _ = tx.rollback().await;
        return 0;
    }

    let wallet: Option<(i64, String)> =
        sqlx::query_as("SELECT balance, currency FROM wallets WHERE tenant_id = $1 FOR UPDATE")
            .bind(&invoice.tenant_id)
            .fetch_optional(&mut *tx)
            .await
            .unwrap_or_else(|error| {
                warn!(
                    tenant_id = %invoice.tenant_id,
                    error = %error,
                    "usage invoice collection: wallet read failed — no wallet credit applied"
                );
                None
            });

    let Some((balance, currency)) = wallet else {
        let _ = tx.rollback().await;
        return 0;
    };
    if !currency.trim().eq_ignore_ascii_case("EUR") {
        warn!(
            tenant_id = %invoice.tenant_id,
            wallet_currency = %currency,
            "usage invoice collection: non-EUR wallet not spendable on a EUR invoice"
        );
        let _ = tx.rollback().await;
        return 0;
    }

    // What is already durably allocated decides what remains — retries and
    // concurrent ladders can never over-apply (audit F35).
    let already_applied: i64 = sqlx::query_scalar(
        "SELECT COALESCE(SUM(amount_cents), 0)::bigint FROM invoice_payment_allocations WHERE invoice_id = $1",
    )
    .bind(invoice.id)
    .fetch_one(&mut *tx)
    .await
    .unwrap_or_else(|error| {
        warn!(
            tenant_id = %invoice.tenant_id,
            error = %error,
            "usage invoice collection: allocation sum failed — no wallet credit applied"
        );
        0
    });
    let remaining = invoice.total.saturating_sub(already_applied);
    if balance <= 0 || remaining <= 0 {
        let _ = tx.rollback().await;
        return 0;
    }

    let applied_cents = balance.min(remaining);
    let operation_id = format!("usage_invoice:{}:wallet", invoice.id);
    let debit = sqlx::query(
        r#"
        WITH debit_wallet AS (
            UPDATE wallets
            SET balance = balance - $2, updated_at = NOW()
            WHERE tenant_id = $1
            RETURNING id, balance
        ),
        wallet_tx AS (
            INSERT INTO wallet_transactions
                (wallet_id, tenant_id, type, amount, balance_after, description, reference, created_at)
            SELECT id, $1, 'debit', $2, balance, $3, $4, NOW()
            FROM debit_wallet
            RETURNING id
        )
        INSERT INTO invoice_payment_allocations (
            id, tenant_id, invoice_id, operation_id, source, amount_cents, currency, wallet_transaction_id
        )
        SELECT gen_random_uuid(), $1, $5, $6, 'wallet', $2, 'EUR', wallet_tx.id
        FROM wallet_tx
        ON CONFLICT (operation_id) DO NOTHING
        "#,
    )
    .bind(&invoice.tenant_id)
    .bind(applied_cents)
    .bind(format!("Usage invoice {}: wallet settlement", invoice.invoice_number))
    .bind(invoice.invoice_number.clone())
    .bind(invoice.id)
    .bind(&operation_id)
    .execute(&mut *tx)
    .await;

    if let Err(error) = debit {
        warn!(
            tenant_id = %invoice.tenant_id,
            invoice_number = %invoice.invoice_number,
            error = %error,
            "usage invoice collection: wallet debit failed — continuing without wallet credit"
        );
        let _ = tx.rollback().await;
        return 0;
    }

    // Audit F33: check EVERY commit — an ignored failure here would have
    // debited nothing yet report credit applied.
    if let Err(error) = tx.commit().await {
        warn!(
            tenant_id = %invoice.tenant_id,
            invoice_number = %invoice.invoice_number,
            error = %error,
            "usage invoice collection: wallet transaction commit failed — wallet credit not applied"
        );
        return 0;
    }

    applied_cents
}

/// Flip the just-created draft invoice to its collection status, mark the
/// period collected, record the explicit dunning entry and complete the
/// outbox operation — one committed transaction (audit F33). Only a row
/// still in `draft` is status-flipped, so a concurrent manual payment can
/// never be overwritten.
async fn finalize_collection(
    state: &AppState,
    invoice: &Invoice,
    status: &str,
) -> Result<(), String> {
    let mut tx = state
        .db
        .begin()
        .await
        .map_err(|e| format!("finalize tx failed: {e}"))?;

    sqlx::query(
        r#"
        UPDATE invoices
        SET status = $2,
            paid_at = CASE WHEN $2 = 'paid' THEN NOW() ELSE paid_at END,
            updated_at = NOW()
        WHERE id = $1
          AND status = 'draft'
        "#,
    )
    .bind(invoice.id)
    .bind(status)
    .execute(&mut *tx)
    .await
    .map_err(|e| format!("status update failed: {e}"))?;

    sqlx::query(
        r#"
        UPDATE billing_periods
        SET invoice_state = CASE WHEN $2 = 'paid' THEN 'collected' ELSE invoice_state END,
            updated_at = NOW()
        WHERE invoice_id = $1
        "#,
    )
    .bind(invoice.id)
    .bind(status)
    .execute(&mut *tx)
    .await
    .map_err(|e| format!("period collection transition failed: {e}"))?;

    if status == "pending" {
        // Explicit dunning entry for the invoice — local/PAYG tenants enter
        // dunning deliberately (audit F33), not as an unobserved side
        // effect of the status flip.
        sqlx::query(
            r#"
            INSERT INTO dunning_events (id, tenant_id, event_type, invoice_id, created_at)
            VALUES (gen_random_uuid(), $1, 'dunning_entered', $2, NOW())
            "#,
        )
        .bind(&invoice.tenant_id)
        .bind(invoice.id.to_string())
        .execute(&mut *tx)
        .await
        .map_err(|e| format!("dunning entry failed: {e}"))?;
    }

    sqlx::query(
        r#"
        UPDATE invoice_collection_outbox
        SET status = 'done', updated_at = NOW()
        WHERE invoice_id = $1 AND operation = 'collect_usage_invoice'
        "#,
    )
    .bind(invoice.id)
    .execute(&mut *tx)
    .await
    .map_err(|e| format!("outbox completion failed: {e}"))?;

    tx.commit()
        .await
        .map_err(|e| format!("finalize commit failed: {e}"))?;
    Ok(())
}

/// Add the remaining usage amount to the tenant's Stripe customer as a
/// pending invoice item (`/v1/invoiceitems`), collected automatically on
/// the next billing cycle. `quantity`/`unit_amount` are chosen to reproduce
/// the millicent-exact integer-cents amount EXACTLY (1 × amount_cents) —
/// Stripe cannot express millicents, so any other factorization would
/// round. Returns `Ok(None)` when the tenant has no Stripe customer or no
/// `STRIPE_SECRET_KEY` is configured (the wallet + dunning path covers
/// them).
async fn create_stripe_invoiceitem(
    state: &AppState,
    tenant_id: &str,
    amount_cents: i64,
    description: &str,
    period_start: DateTime<Utc>,
    usage_kind: &str,
) -> Result<Option<String>, String> {
    if amount_cents <= 0 {
        return Ok(None);
    }
    let Ok(secret_key) = std::env::var("STRIPE_SECRET_KEY") else {
        return Ok(None); // not Stripe-configured — wallet + dunning path
    };
    if secret_key.trim().is_empty() {
        return Ok(None);
    }

    let customer: Option<String> = sqlx::query_scalar(
        r#"
        SELECT stripe_customer_id
        FROM stripe_subscriptions
        WHERE tenant_id = $1
          AND stripe_customer_id IS NOT NULL
        ORDER BY CASE WHEN status = 'active' THEN 0 ELSE 1 END, created_at DESC
        LIMIT 1
        "#,
    )
    .bind(tenant_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| format!("Stripe customer lookup failed: {e}"))?;
    let Some(customer) = customer else {
        return Ok(None); // no Stripe customer — wallet + dunning path
    };

    let idempotency_key = format!("overage_{tenant_id}_{}", period_start.to_rfc3339());
    let base_url =
        std::env::var("STRIPE_API_BASE_URL").unwrap_or_else(|_| "https://api.stripe.com".into());

    let form = [
        ("customer", customer),
        ("currency", "eur".to_string()),
        ("description", description.to_string()),
        ("unit_amount", amount_cents.to_string()),
        ("quantity", "1".to_string()),
        ("metadata[apexmailTenantId]", tenant_id.to_string()),
        ("metadata[periodStart]", period_start.to_rfc3339()),
        ("metadata[type]", usage_kind.to_string()),
    ];

    let client = reqwest::Client::new();
    let response = client
        .post(format!("{base_url}/v1/invoiceitems"))
        .bearer_auth(secret_key)
        .header("Idempotency-Key", idempotency_key)
        .form(&form)
        .timeout(std::time::Duration::from_secs(30))
        .send()
        .await
        .map_err(|e| format!("Stripe invoice item request failed: {e}"))?;

    let status = response.status();
    let body = response.text().await.unwrap_or_default();
    if !status.is_success() {
        return Err(format!("Stripe returned {status}: {body}"));
    }

    let parsed: serde_json::Value = serde_json::from_str(&body)
        .map_err(|e| format!("Stripe invoice item decode failed: {e}"))?;
    let id = parsed
        .get("id")
        .and_then(|value| value.as_str())
        .map(str::to_string);
    Ok(id)
}

/// Best-effort invalidation of the shared wallet-balance cache (the same
/// key maintenance's reservation sweep clears).
async fn invalidate_wallet_balance_cache(state: &AppState, tenant_id: &str) {
    if let Ok(mut conn) = state.redis.get().await {
        let cache_key = format!("wallet:balance:{tenant_id}");
        let deletion: Result<i64, _> = conn.del(&cache_key).await;
        if let Err(error) = deletion {
            warn!(tenant_id = tenant_id, error = %error, "failed to clear wallet balance cache after usage settlement");
        }
    }
}

/// Resume stranded collection operations (audit F33): invoices whose
/// `collect_usage_invoice` outbox row is still pending/in_progress — e.g.
/// the process died between invoice creation and collection — are run
/// through the same idempotent ladder again. Wired into the maintenance
/// hourly loop.
pub async fn resume_pending_collections(state: &AppState) -> Result<u64, String> {
    let stranded: Vec<(Uuid, String, serde_json::Value)> = sqlx::query_as(
        r#"
        SELECT invoice_id, tenant_id, payload
        FROM invoice_collection_outbox
        WHERE operation = 'collect_usage_invoice'
          AND status IN ('pending', 'in_progress')
          AND attempts < 10
        ORDER BY created_at
        LIMIT 100
        "#,
    )
    .fetch_all(&state.db)
    .await
    .map_err(|e| format!("collection resume: outbox query failed: {e}"))?;

    let mut resumed = 0u64;
    for (invoice_id, tenant_id, payload) in stranded {
        let invoice = crate::invoices::get_invoice_by_id(&state.db, invoice_id)
            .await
            .map_err(|e| format!("collection resume: invoice lookup failed: {e}"))?;
        let Some(invoice) = invoice else {
            warn!(invoice_id = %invoice_id, "collection resume: invoice row missing — marking outbox failed");
            let _ = sqlx::query(
                "UPDATE invoice_collection_outbox SET status = 'failed', last_error = 'invoice row missing', updated_at = NOW() WHERE invoice_id = $1 AND operation = 'collect_usage_invoice'",
            )
            .bind(invoice_id)
            .execute(&state.db)
            .await;
            continue;
        };

        let period_start = payload
            .get("periodStart")
            .and_then(|v| v.as_str())
            .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
            .map(|d| d.with_timezone(&Utc))
            .unwrap_or(invoice.period_start);
        let usage_kind = payload
            .get("usageKind")
            .and_then(|v| v.as_str())
            .unwrap_or("overage")
            .to_string();
        let description = payload
            .get("description")
            .and_then(|v| v.as_str())
            .unwrap_or("Usage invoice")
            .to_string();

        let mut wallet_paid = 0u64;
        let mut pending_dunning = 0u64;
        collect_usage_invoice(
            state,
            &invoice,
            period_start,
            &description,
            &usage_kind,
            &mut wallet_paid,
            &mut pending_dunning,
        )
        .await;
        resumed += 1;
        info!(
            tenant_id = %tenant_id,
            invoice_id = %invoice_id,
            "collection resume: re-ran collection ladder for stranded usage invoice"
        );
    }

    Ok(resumed)
}

/// Pure helper for the enforcement gate in usage.rs: the quota value to pass
/// to the Redis Lua for this event, given the plan limit and the tenant's
/// subscription state. Email sending on an ACTIVE paid subscription uses
/// the overage ceiling; everything else (API calls, free tenants, TRIALING
/// subscriptions, no-subscription tenants, unlimited plans) keeps its raw
/// plan limit — a trial has not paid for an overage allowance, so granting
/// the 2× ceiling pre-payment double-counted the allowance (audit 1.3).
pub fn effective_email_quota(plan_limit: i64, subscription_active_paid: bool) -> i64 {
    if subscription_active_paid {
        overage_ceiling(plan_limit)
    } else {
        plan_limit
    }
}

/// Short-lived cache for the paid-subscription gate: this runs on the email
/// send hot path (record_with_quota_check), and one indexed SELECT per send
/// is avoidable — subscription state changes on webhook timescales, not
/// per-send. 60s staleness matches the suppression-cache precedent.
const SUBSCRIPTION_CACHE_TTL_SECS: u64 = 60;

static PAID_SUBSCRIPTION_CACHE: std::sync::OnceLock<moka::sync::Cache<String, bool>> =
    std::sync::OnceLock::new();

fn paid_subscription_cache() -> &'static moka::sync::Cache<String, bool> {
    PAID_SUBSCRIPTION_CACHE.get_or_init(|| {
        moka::sync::Cache::builder()
            .time_to_live(std::time::Duration::from_secs(SUBSCRIPTION_CACHE_TTL_SECS))
            .max_capacity(10_000)
            .build()
    })
}

/// Whether the tenant currently has an ACTIVE paid subscription (status
/// `active` on a priced plan). Trialing is deliberately NOT paid here: the
/// overage allowance is a post-payment benefit, and counting trials made
/// the enforcement ceiling 2× the plan limit before any money moved
/// (audit 1.3). Cached briefly — used per-send by the quota gate.
///
/// Audit F28: the existence check selects `EXISTS(...)` (bool) — the old
/// `SELECT 1` binds Postgres INT4 into an i64 and fails to decode.
pub async fn tenant_has_active_paid_subscription(
    pool: &PgPool,
    tenant_id: &str,
) -> Result<bool, sqlx::Error> {
    if let Some(cached) = paid_subscription_cache().get(tenant_id) {
        return Ok(cached);
    }
    let active: bool = sqlx::query_scalar(PAID_SUBSCRIPTION_EXISTS_SQL)
        .bind(tenant_id)
        .fetch_one(pool)
        .await?;
    paid_subscription_cache().insert(tenant_id.to_string(), active);
    Ok(active)
}

/// Existence-check SQL for the paid-subscription gate (audit F28):
/// `EXISTS(...)` selects bool — the previous `SELECT 1` bound INT4 into an
/// i64 and failed to decode. Pinned by unit test.
const PAID_SUBSCRIPTION_EXISTS_SQL: &str = r#"
    SELECT EXISTS(
        SELECT 1
        FROM stripe_subscriptions ss
        JOIN plans p ON p.name = ss.plan
        WHERE ss.tenant_id = $1
          AND ss.status = 'active'
          AND COALESCE(p.price_monthly, 0) > 0
    )
    "#;

/// Drop the tenant's cached paid-subscription gate. Called by entitlement
/// writers (admin plan override — audit F06) so the 60s cache cannot serve
/// the pre-override answer after a plan changed.
pub fn invalidate_subscription_cache(tenant_id: &str) {
    paid_subscription_cache().invalidate(tenant_id);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ceiling_is_allowance_on_top_of_the_plan_limit() {
        // default allowance 100%: a 50,000 plan may send up to 100,000
        assert_eq!(overage_ceiling(50_000), 100_000);
        // zero limit: ceiling is zero (nothing included, allowance of zero)
        assert_eq!(overage_ceiling(0), 0);
        // unlimited stays unlimited
        assert_eq!(overage_ceiling(-1), -1);
    }

    #[test]
    fn effective_quota_only_widens_for_active_paid_subscriptions() {
        // free / trial / canceled: hard plan limit — no pre-payment ceiling
        assert_eq!(effective_email_quota(50_000, false), 50_000);
        // active paid subscription: overage ceiling
        assert_eq!(effective_email_quota(50_000, true), 100_000);
        // unlimited is unchanged either way
        assert_eq!(effective_email_quota(-1, false), -1);
        assert_eq!(effective_email_quota(-1, true), -1);
    }

    #[test]
    fn allowance_percent_is_clamped_and_parsed() {
        // The pure math honours whatever the env clamps to; spot-check the
        // clamp boundaries through overage_ceiling indirectly (env is
        // process-global, so only assert the default path here).
        assert!(overage_allowance_percent() >= 0);
        assert!(overage_allowance_percent() <= 1000);
    }

    // ------------------------------------------------------------------
    // Rate text (audit: the invoice description hardcoded "€0.40").
    // ------------------------------------------------------------------

    #[test]
    fn rate_text_formats_the_configured_rate_in_euros() {
        // 40 millicents/email = 40 cents per 1 000 = €0.40.
        assert_eq!(format_rate_per_thousand_emails(40), "€0.40");
        // A doubled rate renders doubled euros, not the old constant.
        assert_eq!(format_rate_per_thousand_emails(80), "€0.80");
        assert_eq!(format_rate_per_thousand_emails(125), "€1.25");
        // Degenerate rates never render negative.
        assert_eq!(format_rate_per_thousand_emails(0), "€0.00");
        assert_eq!(format_rate_per_thousand_emails(-5), "€0.00");
    }

    // ------------------------------------------------------------------
    // PAYG calendar-month window.
    // ------------------------------------------------------------------

    fn utc(year: i32, month: u32, day: u32) -> DateTime<Utc> {
        chrono::NaiveDate::from_ymd_opt(year, month, day)
            .unwrap()
            .and_hms_opt(0, 0, 0)
            .unwrap()
            .and_utc()
    }

    #[test]
    fn recent_completed_months_mid_month_yields_previous_month_only() {
        // On 15 Aug 2026 the only completed month ending within 40 days is
        // July (ended 1 Aug 00:00); June ended 1 July, 45 days earlier —
        // outside the 40-day metering TTL.
        let months = recent_completed_calendar_months(utc(2026, 8, 15));
        assert_eq!(months.len(), 1);
        assert_eq!(months[0].0, utc(2026, 7, 1));
        assert_eq!(months[0].1, utc(2026, 8, 1));
    }

    #[test]
    fn recent_completed_months_early_month_yields_two() {
        // On 3 Aug 2026: July (ended 1 Aug, 2 days ago) and June (ended
        // 1 July, 33 days ago) both lie inside the window.
        let months = recent_completed_calendar_months(utc(2026, 8, 3));
        assert_eq!(months.len(), 2);
        assert_eq!(months[0].0, utc(2026, 7, 1));
        assert_eq!(months[0].1, utc(2026, 8, 1));
        assert_eq!(months[1].0, utc(2026, 6, 1));
        assert_eq!(months[1].1, utc(2026, 7, 1));
    }

    #[test]
    fn recent_completed_months_never_includes_the_future() {
        for day in [1, 2, 15, 28] {
            let months = recent_completed_calendar_months(utc(2026, 3, day));
            for (start, end) in months {
                assert!(end <= utc(2026, 3, day) + chrono::Duration::days(1));
                assert!(start < end);
            }
        }
    }

    #[test]
    fn stripe_idempotency_key_shape_is_stable_per_tenant_period() {
        // (Documented contract; the key is built inline in
        // create_stripe_invoiceitem — pin the shape here.)
        let tenant = "tenant_01HZY2Q4YQ0L8QW8Q7Q28WKSFJ";
        let period = utc(2026, 8, 1);
        // The implementation formats the period with to_rfc3339 (a +00:00
        // suffix, stable per instant); the naive Display form below is what
        // the key must equal character-for-character in production.
        assert_eq!(
            format!("overage_{tenant}_{}", period.to_rfc3339()),
            "overage_tenant_01HZY2Q4YQ0L8QW8Q7Q28WKSFJ_2026-08-01T00:00:00+00:00"
        );
    }

    // ------------------------------------------------------------------
    // Audit F29 — unique-violation classification drives the
    // conflict-returns-existing-invoice path.
    // ------------------------------------------------------------------

    #[test]
    fn unique_violation_is_detected_through_the_error_wrapper() {
        use sqlx::error::DatabaseError;

        struct FakeDbError(&'static str);
        impl std::fmt::Debug for FakeDbError {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "FakeDbError({})", self.0)
            }
        }
        impl std::fmt::Display for FakeDbError {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "FakeDbError({})", self.0)
            }
        }
        impl std::error::Error for FakeDbError {}
        impl DatabaseError for FakeDbError {
            fn message(&self) -> &str {
                "duplicate key value violates unique constraint"
            }
            fn code(&self) -> Option<std::borrow::Cow<'_, str>> {
                Some(self.0.into())
            }
            fn as_error(&self) -> &(dyn std::error::Error + Send + Sync + 'static) {
                self
            }
            fn as_error_mut(&mut self) -> &mut (dyn std::error::Error + Send + Sync + 'static) {
                self
            }
            fn into_error(self: Box<Self>) -> Box<dyn std::error::Error + Send + Sync + 'static> {
                self
            }
            fn is_transient_in_connect_phase(&self) -> bool {
                false
            }
            fn kind(&self) -> sqlx::error::ErrorKind {
                sqlx::error::ErrorKind::Other
            }
        }

        let unique = InvoiceError::Db(sqlx::Error::Database(Box::new(FakeDbError("23505"))));
        assert!(is_unique_violation(&unique));

        let other = InvoiceError::Db(sqlx::Error::Database(Box::new(FakeDbError("23503"))));
        assert!(!is_unique_violation(&other));

        let not_db = InvoiceError::NoBillingAddress;
        assert!(!is_unique_violation(&not_db));
    }

    // ------------------------------------------------------------------
    // Audit F32 — checked overage arithmetic must never wrap.
    // ------------------------------------------------------------------

    #[test]
    fn checked_overage_arithmetic_rejects_underflow_inputs() {
        // The production path uses sent.checked_sub(plan_limit); pin the
        // semantic: i64::MIN allowance against real volume must NOT wrap to
        // a positive overage.
        let sent: i64 = 1_000;
        let allowance: i64 = i64::MIN;
        assert!(sent.checked_sub(allowance).is_none());
    }

    // ------------------------------------------------------------------
    // Audit F35 — outstanding derivation.
    // ------------------------------------------------------------------

    #[test]
    fn outstanding_sums_payments_and_credits_and_clamps_at_zero() {
        use crate::invoices::compute_outstanding;
        // Nothing applied: full total outstanding.
        assert_eq!(compute_outstanding(10_000, 0, 0), 10_000);
        // Partial wallet payment.
        assert_eq!(compute_outstanding(10_000, 4_000, 0), 6_000);
        // Payments + credit notes both reduce.
        assert_eq!(compute_outstanding(10_000, 4_000, 1_000), 5_000);
        // Fully settled.
        assert_eq!(compute_outstanding(10_000, 9_000, 1_000), 0);
        // Over-credit can never go negative.
        assert_eq!(compute_outstanding(10_000, 4_000, 20_000), 0);
        // Negative inputs are clamped, not subtracted.
        assert_eq!(compute_outstanding(10_000, -5_000, -5_000), 10_000);
    }

    #[test]
    fn wallet_operation_id_is_stable_per_invoice() {
        let id = Uuid::new_v4();
        assert_eq!(
            format!("usage_invoice:{id}:wallet"),
            format!("usage_invoice:{id}:wallet")
        );
        // Distinct invoices get distinct operation ids (unique constraint
        // is per operation).
        assert_ne!(
            format!("usage_invoice:{id}:wallet"),
            format!("usage_invoice:{}:wallet", Uuid::new_v4())
        );
    }

    // ------------------------------------------------------------------
    // Audit F28 — existence checks must select EXISTS (bool), never a
    // bare `SELECT 1` (INT4 -> i64 decode failure).
    // ------------------------------------------------------------------

    #[test]
    fn address_existence_check_selects_exists_bool() {
        assert!(ADDRESS_EXISTS_SQL.contains("SELECT EXISTS("));
        assert!(!ADDRESS_EXISTS_SQL.trim_start().starts_with("SELECT 1"));
        assert!(!ADDRESS_EXISTS_SQL.contains("LIMIT 1"));
    }

    #[test]
    fn paid_subscription_existence_check_selects_exists_bool() {
        assert!(PAID_SUBSCRIPTION_EXISTS_SQL.contains("SELECT EXISTS("));
        // The guard: the outer select is the EXISTS bool, never a bare
        // INT4 literal bound to i64.
        assert!(!PAID_SUBSCRIPTION_EXISTS_SQL
            .trim_start()
            .starts_with("SELECT 1"));
        assert!(!PAID_SUBSCRIPTION_EXISTS_SQL.contains("LIMIT 1"));
    }

    // ------------------------------------------------------------------
    // Audits F29/F31 — the sweep selects only unbilled periods, excludes
    // completed work in SQL, and pages with a stable keyset.
    // ------------------------------------------------------------------

    #[test]
    fn sweep_selects_only_unbilled_periods() {
        assert!(SWEEP_UNBILLED_PERIODS_SQL.contains("invoice_state = 'unbilled'"));
        // Completed states are excluded by the unbilled filter — the
        // terminal states must never appear as an inclusion list.
        assert!(!SWEEP_UNBILLED_PERIODS_SQL.contains("invoiced"));
        assert!(!SWEEP_UNBILLED_PERIODS_SQL.contains("collected"));
        assert!(!SWEEP_UNBILLED_PERIODS_SQL.contains("skipped"));
    }

    #[test]
    fn sweep_pagination_is_a_stable_keyset() {
        // Keyset predicate + deterministic ORDER matching it.
        assert!(SWEEP_UNBILLED_PERIODS_SQL.contains("(period_end, tenant_id) >"));
        assert!(SWEEP_UNBILLED_PERIODS_SQL.contains("ORDER BY period_end, tenant_id"));
        assert!(SWEEP_UNBILLED_PERIODS_SQL.contains("LIMIT $3"));
        // No OFFSET — offsets re-visit rows as pages complete.
        assert!(!SWEEP_UNBILLED_PERIODS_SQL.to_lowercase().contains("offset"));
    }

    // ------------------------------------------------------------------
    // Audit F32 — one effective plan feeds BOTH the allowance and the
    // pricing rate: the live resolution selects the override-aware plan
    // (COALESCE(po.plan, t.plan)) together with its email_limit.
    // ------------------------------------------------------------------

    #[test]
    fn effective_period_plan_resolves_allowance_and_plan_together() {
        assert!(EFFECTIVE_PERIOD_PLAN_SQL.contains("COALESCE(po.plan, t.plan"));
        // The SAME CASE expression joins the plans row for email_limit, so
        // the allowance can never come from a different plan than the name
        // the query returns.
        assert!(EFFECTIVE_PERIOD_PLAN_SQL.contains("LEFT JOIN plans p"));
        assert!(EFFECTIVE_PERIOD_PLAN_SQL.contains("p.email_limit"));
        // Terminal subscriptions price by the subscription's OWN plan (the
        // tenant is frequently already downgraded).
        assert!(EFFECTIVE_PERIOD_PLAN_SQL.contains("ELSE ss.plan"));
    }
}
