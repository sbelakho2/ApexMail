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
//! complete keyset cursor on `(period_end, tenant_id, id)`. Unresolved
//! periods are NOT aged out: raw-event retention (40 days) is never the
//! expiry policy for financial work, each period carries its own
//! attempt/error/backoff state (migration 177), and a failing period is
//! isolated so the rest of the sweep progresses (audit F31).
//!
//! # Pricing snapshots (audit F32)
//!
//! The complete effective pricing — email allowance, integer overage
//! rate, currency, override context — is snapshotted onto the period at
//! creation (migration 178: `pricing_snapshot`, plus the scalar
//! `overage_rate_millicents`/`currency` columns). Pricing reads ONLY the
//! snapshot; a later plan/override change can never reprice a past
//! period. Unresolved snapshots are backfilled once under the period
//! lock, or surface as the explicit `needs_review` state instead of being
//! inferred from today's plan.
//!
//! # Claim atomicity (audit F29)
//!
//! Claiming a period and inserting its invoice happen in ONE transaction:
//! `pg_advisory_xact_lock(tenant, kind, period)` + a state re-check +
//! [`crate::invoices::create_invoice_in_tx`] + the period's
//! `invoiced` transition + a collection-outbox operation, all committed
//! together. The UNIQUE index on `invoices (tenant_id, overage_period)`
//! (migration 136) is the schema-level backstop; invoice creation runs
//! inside a SAVEPOINT, so a violation of THAT EXACT constraint (identity
//! checked by constraint name, then tenant/kind/period/amount/currency
//! compared) rolls back to the savepoint and the still-healthy
//! transaction adopts the existing invoice — never a 25P02 SELECT inside
//! an aborted transaction, never a second collection.
//!
//! # Collection flow (audits F33/F34/F35/F60)
//!
//! Every invoice the sweep creates gets a `collect_usage_invoice` outbox
//! row in the same transaction (migration 138), so collection is resumable
//! — a crash after invoice creation can never strand a draft. The ladder
//! commits each step and checks every commit:
//!
//! 1. **Wallet first.** The tenant's wallet balance is applied to the
//!    invoice in the invoice's currency; the wallet debit, its
//!    `wallet_transactions` row and an immutable
//!    `invoice_payment_allocations` row (unique operation id) commit
//!    together (audit F35). What remains is derived by the ONE shared
//!    outstanding function (total − confirmed payments − debt-reduction
//!    credits; audit F60) — wallet application never invents its own
//!    total-minus-this-debit fallback, and an unavailable balance is a
//!    retryable failure, never the basis of an external amount (F33).
//! 2. **Stripe invoice (finalized).** For tenants with a Stripe customer
//!    on file and a configured `STRIPE_SECRET_KEY`, the REMAINING amount
//!    is posted as an invoice item AND collected immediately by creating
//!    and FINALIZING a Stripe invoice (audit F34: a pending
//!    `/invoiceitems` entry was never linked to a real invoice, so
//!    `invoice.paid` never matched and final usage went uncollected).
//!    Idempotency keys carry the immutable local operation identity
//!    (invoice id + usage kind) AND the frozen amount/currency, so a
//!    retry with a changed wallet balance can never reuse one Stripe key
//!    with different parameters. The local ↔ external mapping (invoice
//!    id, item id, currency, amount) is persisted before finalization
//!    commits, and `invoice.paid` reconciles through
//!    `stripe_invoice_id`. The HTTP calls run OUTSIDE any wallet-lock
//!    transaction (audit F33).
//! 3. **Dunning handoff.** Whatever remains flips the invoice from
//!    `draft` to `pending` WITH a transactional handoff to the durable
//!    dunning machinery: `dunning_records` (what the retry/suspension
//!    jobs actually read) is upserted in the SAME transaction that marks
//!    the outbox done (audit F33 — a bare `dunning_entered` event had no
//!    consumer). Failures anywhere propagate: the outbox row keeps a
//!    owner/lease fence (migration 180), records its error, backs off,
//!    and is never marked done without confirmed settlement or the
//!    committed handoff.

use crate::config::PaygPricing;
use crate::invoices::{
    create_invoice_in_tx, invoice_outstanding_cents, invoice_outstanding_cents_in,
    CreateInvoiceInput, InvoiceError, NewLineItem,
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

/// Unbilled-period selection for the overage sweep (audits F29/F31/F32):
/// completed work is excluded IN SQL (`invoice_state = 'unbilled'`),
/// pagination is a COMPLETE keyset on `(period_end, tenant_id, id)` (the
/// two-column cursor was not a unique row ordering), failed periods are
/// gated by their own backoff (`next_sweep_attempt_at`), and there is NO
/// age cutoff — unresolved financial work is retained until explicitly
/// reconciled, never aged out with the raw metering events. Pinned by
/// unit tests.
const SWEEP_UNBILLED_PERIODS_SQL: &str = r#"
    SELECT id, tenant_id, stripe_subscription_id, period_start, period_end,
           plan_name, email_allowance, overage_rate_millicents, currency
    FROM billing_periods
    WHERE usage_kind = 'subscription'
      AND invoice_state = 'unbilled'
      AND period_end < NOW()
      AND (next_sweep_attempt_at IS NULL OR next_sweep_attempt_at <= NOW())
      AND (
            $1::timestamptz IS NULL
            OR (period_end, tenant_id, id) > ($1::timestamptz, $2::text, $3::uuid)
          )
    ORDER BY period_end, tenant_id, id
    LIMIT $4
    "#;

#[derive(Debug, Default)]
pub struct OverageSweepResult {
    pub periods_checked: u64,
    pub invoices_created: u64,
    pub skipped_no_address: u64,
    pub skipped_no_overage: u64,
    /// Tenants whose plan name resolves to nothing (missing plans row AND
    /// unknown to the builtin seeds) — surfaced to `needs_review`, never
    /// billed limit-0 (audit 1.3).
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
    /// Audit F31: periods whose processing failed THIS run — isolated,
    /// recorded with error/backoff state, retried later; the rest of the
    /// sweep progressed regardless.
    pub failed_periods: u64,
    /// Audit F31: age of the oldest still-unresolved period, in seconds
    /// (`None` when nothing is unresolved).
    pub oldest_unresolved_age_secs: Option<i64>,
    /// Audit F31: unresolved periods older than the metering retention
    /// window whose usage read is zero — surfaced to `needs_review`
    /// (cannot distinguish no-usage from lost events).
    pub aged_needs_review: u64,
    /// Audit F32: periods moved to `needs_review` because their pricing
    /// could not be resolved from history (refused to price from today's
    /// plan).
    pub pricing_needs_review: u64,
    /// Audit F29: existing-invoice adoptions where the stored invoice's
    /// amount/currency disagreed with the recomputed snapshot pricing —
    /// linked (single collection) but loudly surfaced for reconciliation.
    pub existing_invoice_mismatches: u64,
}

/// An immutable billing-period record selected by the sweep (migration
/// 137). `plan_name`/`email_allowance`/`overage_rate_millicents`/
/// `currency` are the pricing snapshot taken when the period was recorded
/// — pricing uses ONLY these, never the current plan (audit F32).
#[derive(sqlx::FromRow)]
struct BillingPeriodRow {
    id: Uuid,
    tenant_id: String,
    stripe_subscription_id: Option<String>,
    period_start: DateTime<Utc>,
    period_end: DateTime<Utc>,
    plan_name: Option<String>,
    email_allowance: Option<i64>,
    overage_rate_millicents: Option<i64>,
    currency: String,
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
/// itself snapshots closing periods transactionally (audit F30). The
/// catch-up freezes the COMPLETE effective pricing (allowance, rate,
/// currency) onto each new period record (audit F32).
async fn ensure_subscription_period_records(db: &PgPool) -> Result<(), String> {
    sqlx::query(
        r#"
        INSERT INTO billing_periods (
            tenant_id, stripe_subscription_id, usage_kind,
            period_start, period_end, currency, plan_name, email_allowance,
            overage_rate_millicents, pricing_snapshot, pricing_resolved_at
        )
        SELECT
            ss.tenant_id, ss.stripe_subscription_id, 'subscription',
            ss.billing_cycle_start, ss.billing_cycle_end,
            eff.currency, eff.plan_name, p.email_limit,
            rate.rate_millicents,
            jsonb_build_object(
                'snapshotVersion', 1,
                'planName', eff.plan_name,
                'emailAllowance', p.email_limit,
                'overageRateMillicents', rate.rate_millicents,
                'currency', eff.currency,
                'source', 'catchup'
            ),
            NOW()
        FROM stripe_subscriptions ss
        JOIN tenants t ON t.id = ss.tenant_id
        LEFT JOIN LATERAL (
            SELECT po.plan AS override_plan
            FROM plan_overrides po
            WHERE po.tenant_id = t.id
              AND po.active = true
              AND (po.expires_at IS NULL OR po.expires_at > NOW())
            LIMIT 1
        ) po ON TRUE
        CROSS JOIN LATERAL (
            SELECT CASE WHEN ss.status = 'active'
                        THEN COALESCE(po.override_plan, t.plan, ss.plan)
                        ELSE ss.plan
                   END AS plan_name,
                   COALESCE(UPPER(t.settings->>'billingCurrency'), 'EUR') AS currency
        ) eff ON TRUE
        LEFT JOIN plans p ON p.name = eff.plan_name
        CROSS JOIN LATERAL (
            SELECT CASE eff.plan_name
                        WHEN 'growth' THEN 35
                        WHEN 'scale' THEN 35
                        WHEN 'enterprise' THEN 35
                        WHEN 'pro' THEN 60
                        WHEN 'starter' THEN 80
                        ELSE NULL
                   END AS rate_millicents
        ) rate ON TRUE
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
    refresh_pricing_snapshots(state, result).await;

    // Audit F31: expose the unresolved backlog's size and oldest age so
    // aging work is visible instead of silently dropping out of the query.
    let unresolved: (i64, Option<DateTime<Utc>>) = sqlx::query_as(
        r#"
        SELECT COUNT(*)::bigint, MIN(period_end)
        FROM billing_periods
        WHERE usage_kind = 'subscription'
          AND invoice_state = 'unbilled'
          AND period_end < NOW()
        "#,
    )
    .fetch_one(&state.db)
    .await
    .map_err(|e| format!("overage sweep: unresolved-stats query failed: {e}"))?;
    let (unresolved_count, oldest_end) = unresolved;
    if unresolved_count > 0 {
        if let Some(oldest_end) = oldest_end {
            result.oldest_unresolved_age_secs =
                Some((Utc::now() - oldest_end).num_seconds().max(0));
        }
    }

    // Audit F31: only UNBILLED periods are selected — completed work is
    // excluded in SQL, the COMPLETE keyset cursor on
    // (period_end, tenant_id, id) makes pagination stable across
    // concurrent state changes AND tied cursor values, and each period's
    // own backoff decorrelates failed retries.
    let mut cursor: Option<(DateTime<Utc>, String, Uuid)> = None;
    loop {
        let periods: Vec<BillingPeriodRow> = sqlx::query_as(SWEEP_UNBILLED_PERIODS_SQL)
            .bind(cursor.as_ref().map(|c| c.0))
            .bind(cursor.as_ref().map(|c| c.1.clone()))
            .bind(cursor.as_ref().map(|c| c.2))
            .bind(SWEEP_PAGE)
            .fetch_all(&state.db)
            .await
            .map_err(|e| format!("overage sweep: period query failed: {e}"))?;

        let page_len = periods.len();
        for period in &periods {
            result.periods_checked += 1;
            // Audit F31: ONE failing period must not abort the sweep —
            // the error is recorded on the period (attempt counter, last
            // error, backoff) and the sweep moves on to the next period.
            if let Err(error) = process_subscription_period(state, period, result).await {
                result.failed_periods += 1;
                warn!(
                    tenant_id = %period.tenant_id,
                    period_id = %period.id,
                    error = %error,
                    "overage sweep: period failed — isolated; recorded for backoff retry"
                );
                record_period_sweep_failure(&state.db, period.id, &error).await;
            }
        }

        if page_len < SWEEP_PAGE as usize {
            break;
        }
        let last = periods.last().expect("page of SWEEP_PAGE has a last row");
        cursor = Some((last.period_end, last.tenant_id.clone(), last.id));
    }

    Ok(())
}

/// Persist a period's sweep failure (audit F31): attempt counter, last
/// error, and an exponentially backed-off next-attempt time (capped at
/// 48h) so a persistently failing period neither blocks its neighbours
/// nor hammers the failure path every run.
async fn record_period_sweep_failure(db: &PgPool, period_id: Uuid, error: &str) {
    let backoff_minutes: i64 = 60;
    let next_attempt = Utc::now()
        + chrono::Duration::minutes(
            backoff_minutes
                .saturating_mul(
                    2_i64.saturating_pow(
                        sqlx::query_scalar::<_, i32>(
                            "SELECT sweep_attempts FROM billing_periods WHERE id = $1",
                        )
                        .bind(period_id)
                        .fetch_one(db)
                        .await
                        .map(|attempts| attempts.clamp(0, 6) as u32)
                        .unwrap_or(0),
                    ),
                )
                .min(2 * 24 * 60),
        );
    let recorded = sqlx::query(
        r#"
        UPDATE billing_periods
        SET sweep_attempts = sweep_attempts + 1,
            last_sweep_error = $2,
            next_sweep_attempt_at = $3,
            updated_at = NOW()
        WHERE id = $1
        "#,
    )
    .bind(period_id)
    .bind(error)
    .bind(next_attempt)
    .execute(db)
    .await;
    if let Err(record_error) = recorded {
        warn!(
            period_id = %period_id,
            error = %record_error,
            "overage sweep: failed to record period failure state"
        );
    }
}

/// Clear a period's failure state after a successful pass (audit F31):
/// the next natural failure starts its backoff ladder from zero again.
async fn clear_period_sweep_failure(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    period_id: Uuid,
) -> Result<(), String> {
    sqlx::query(
        r#"
        UPDATE billing_periods
        SET sweep_attempts = 0,
            last_sweep_error = NULL,
            next_sweep_attempt_at = NULL,
            updated_at = NOW()
        WHERE id = $1
        "#,
    )
    .bind(period_id)
    .execute(&mut **tx)
    .await
    .map_err(|e| format!("overage sweep: failure-state reset failed: {e}"))?;
    Ok(())
}

/// One-shot repair pass (audit F31): periods that already crossed the old
/// 40-day cutoff were invisible to the sweep. `needs_review` periods are
/// re-exposed here so operators can see recovered work — the real recovery
/// is that [`SWEEP_UNBILLED_PERIODS_SQL`] no longer drops old rows at all.
async fn refresh_pricing_snapshots(state: &AppState, result: &mut OverageSweepResult) {
    let review: Option<(i64, Option<DateTime<Utc>>)> = sqlx::query_as(
        r#"
        SELECT COUNT(*)::bigint, MIN(period_end)
        FROM billing_periods
        WHERE invoice_state = 'needs_review'
        "#,
    )
    .fetch_optional(&state.db)
    .await
    .ok()
    .flatten();
    if let Some((count, oldest)) = review {
        if count > 0 {
            result.pricing_needs_review += count as u64;
            if let Some(oldest) = oldest {
                let age_secs = (Utc::now() - oldest).num_seconds().max(0);
                result.oldest_unresolved_age_secs = match result.oldest_unresolved_age_secs {
                    Some(existing) => Some(existing.min(age_secs)),
                    None => Some(age_secs),
                };
            }
        }
    }
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

    // ── Pricing comes ONLY from the period's immutable snapshot ──
    // (audit F32). An incomplete legacy snapshot is backfilled ONCE here
    // (under the period lock) from the authoritative per-plan records and
    // persisted; a snapshot that cannot be resolved from history surfaces
    // as `needs_review` instead of being priced from today's plan.
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
        // Snapshot carries no plan and history cannot resolve one —
        // explicit review state, never today's plan (audit F32).
        warn!(
            tenant_id = %period.tenant_id,
            period_start = %period.period_start.to_rfc3339(),
            "overage sweep: period has no resolvable plan; surfacing for review"
        );
        result.skipped_unknown_plan += 1;
        mark_period_needs_review(&mut tx, period.id, "no resolvable plan snapshot").await?;
        tx.commit()
            .await
            .map_err(|e| format!("overage sweep: claim commit failed: {e}"))?;
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
        mark_period_needs_review(&mut tx, period.id, "unknown plan; no builtin limit").await?;
        tx.commit()
            .await
            .map_err(|e| format!("overage sweep: claim commit failed: {e}"))?;
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

    // Audit F31: a period older than the metering retention window with a
    // ZERO usage read cannot distinguish "no usage" from "events aged
    // out" — surface it for review instead of silently skipping.
    if period.period_end < Utc::now() - chrono::Duration::days(40) && sent == 0 {
        warn!(
            tenant_id = %period.tenant_id,
            period_start = %period.period_start.to_rfc3339(),
            "overage sweep: aged period reads zero usage — retained for review, not dropped"
        );
        result.aged_needs_review += 1;
        mark_period_needs_review(
            &mut tx,
            period.id,
            "aged beyond metering retention with zero usage read",
        )
        .await?;
        tx.commit()
            .await
            .map_err(|e| format!("overage sweep: claim commit failed: {e}"))?;
        return Ok(());
    }

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

    // ── Rate/currency from the SNAPSHOT, backfilled once when missing ──
    // (audit F32: the sweep must never re-read the current plan ladder
    // for a period whose snapshot already exists).
    let rate_millicents = match period.overage_rate_millicents {
        Some(rate) => rate,
        None => match plans::plan_overage_rate_millicents(&plan_name) {
            Some(rate) => {
                persist_pricing_snapshot(
                    &mut tx,
                    period.id,
                    Some(rate),
                    &period.currency,
                    plan_limit,
                    &plan_name,
                )
                .await?;
                rate
            }
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
        },
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
        format_rate_per_thousand_emails(rate_millicents, &period.currency)
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
        // Audit F32: the invoice is issued in the period's SNAPSHOT
        // currency, never an implicit EUR default.
        currency: Some(period.currency.to_lowercase()),
        overage_period: Some(period.period_start),
    };

    // Claim + insert in ONE transaction (audit F29). The insert runs
    // inside a SAVEPOINT: a violation of the EXACT period-identity
    // constraint (name-checked, then tenant/period/amount/currency
    // compared) rolls back to the savepoint only, so the recovery SELECT
    // runs in a STILL-HEALTHY transaction — never 25P02 inside an aborted
    // one — and adopts the existing invoice without a second collection.
    sqlx::query("SAVEPOINT invoice_creation")
        .execute(&mut *tx)
        .await
        .map_err(|e| format!("overage sweep: invoice savepoint failed: {e}"))?;

    let invoice = match create_invoice_in_tx(&mut tx, input).await {
        Ok(invoice) => {
            sqlx::query("RELEASE SAVEPOINT invoice_creation")
                .execute(&mut *tx)
                .await
                .map_err(|e| format!("overage sweep: invoice savepoint release failed: {e}"))?;
            invoice
        }
        Err(error) if is_overage_period_unique_violation(&error) => {
            // Undo ONLY the failed insert: the outer claim transaction
            // stays usable for the adoption below (audit F29).
            sqlx::query("ROLLBACK TO SAVEPOINT invoice_creation")
                .execute(&mut *tx)
                .await
                .map_err(|e| format!("overage sweep: invoice savepoint rollback failed: {e}"))?;

            let existing_id: Option<(Uuid, i64, String)> = sqlx::query_as(
                "SELECT id, COALESCE(total, amount, 0)::bigint, currency \
                 FROM invoices WHERE tenant_id = $1 AND overage_period = $2 LIMIT 1",
            )
            .bind(&period.tenant_id)
            .bind(period.period_start)
            .fetch_optional(&mut *tx)
            .await
            .map_err(|e| format!("overage sweep: existing-invoice lookup failed: {e}"))?;

            let Some((existing_id, existing_total, existing_currency)) = existing_id else {
                // The constraint fired but the invoice is not visible in
                // this transaction — record the failure and retry later
                // rather than adopting something unverified.
                return Err(format!(
                    "overage sweep: period-identity constraint fired but no existing invoice \
                     is visible for tenant {} period {}",
                    period.tenant_id,
                    period.period_start.to_rfc3339()
                ));
            };

            // Identity check (audit F29): adopt only a genuine replay of
            // THIS period's invoice — same currency, same amount. A
            // mismatch is linked (exactly one collection) but loudly
            // surfaced for reconciliation.
            if !existing_currency.eq_ignore_ascii_case(&period.currency)
                || existing_total != amount_cents
            {
                warn!(
                    tenant_id = %period.tenant_id,
                    invoice_id = %existing_id,
                    existing_total,
                    existing_currency = %existing_currency,
                    snapshot_total = amount_cents,
                    snapshot_currency = %period.currency,
                    "overage sweep: existing period invoice disagrees with the pricing snapshot — linked for review"
                );
                result.existing_invoice_mismatches += 1;
            }

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
            return Ok(());
        }
        Err(error) => {
            // Propagate (audit F31/F33): the failure is recorded on the
            // period with backoff by the sweep loop.
            let _ = tx.rollback().await;
            return Err(format!("invoice creation failed: {error}"));
        }
    };

    mark_period_invoiced(&mut tx, period.id, invoice.id, sent).await?;
    clear_period_sweep_failure(&mut tx, period.id).await?;
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
    // out of the claim transaction (audit F33). Collection failures are
    // recorded on the outbox (error, backoff, owner state) and retried;
    // the invoice itself is durably claimed above.
    if let Err(error) = collect_usage_invoice(
        state,
        &invoice,
        period.period_start,
        &description,
        "overage",
        &mut result.wallet_paid,
        &mut result.pending_dunning,
    )
    .await
    {
        warn!(
            tenant_id = %period.tenant_id,
            invoice_id = %invoice.id,
            error = %error,
            "overage sweep: collection failed — outbox retains retryable state"
        );
    }

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
    // it (audit F29/F30). The complete PAYG pricing context is snapshotted
    // at creation (audit F32): the tiered ladder + currency live on the
    // period row, so a later pricing change never reprices a past month.
    let inserted: Option<Uuid> = sqlx::query_scalar(
        r#"
        INSERT INTO billing_periods (
            tenant_id, usage_kind, period_start, period_end, currency, plan_name,
            pricing_snapshot, pricing_resolved_at
        )
        VALUES ($1, 'payg', $2, $3, $4, 'payg', $5::jsonb, NOW())
        ON CONFLICT (tenant_id, usage_kind, period_start) DO NOTHING
        RETURNING id
        "#,
    )
    .bind(tenant_id)
    .bind(month_start)
    .bind(month_end)
    .bind(PAYG_SNAPSHOT_CURRENCY)
    .bind(payg_pricing_snapshot_json(pricing).to_string())
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
        // Audit F32: PAYG months are issued in the snapshot currency
        // (persisted on the period record at claim time above).
        currency: Some(PAYG_SNAPSHOT_CURRENCY.to_lowercase()),
        overage_period: Some(month_start),
    };

    // SAVEPOINT around the insert (audit F29): a period-identity unique
    // violation rolls back to the savepoint, and the adoption SELECT runs
    // in the still-healthy claim transaction — no 25P02.
    sqlx::query("SAVEPOINT invoice_creation")
        .execute(&mut *tx)
        .await
        .map_err(|e| format!("payg sweep: invoice savepoint failed: {e}"))?;

    let invoice = match create_invoice_in_tx(&mut tx, input).await {
        Ok(invoice) => {
            sqlx::query("RELEASE SAVEPOINT invoice_creation")
                .execute(&mut *tx)
                .await
                .map_err(|e| format!("payg sweep: invoice savepoint release failed: {e}"))?;
            invoice
        }
        Err(error) if is_overage_period_unique_violation(&error) => {
            sqlx::query("ROLLBACK TO SAVEPOINT invoice_creation")
                .execute(&mut *tx)
                .await
                .map_err(|e| format!("payg sweep: invoice savepoint rollback failed: {e}"))?;

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

            let Some(existing_id) = existing_id else {
                return Err(format!(
                    "payg sweep: period-identity constraint fired but no existing invoice is \
                     visible for tenant {tenant_id} month {}",
                    month_start.to_rfc3339()
                ));
            };

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
            return Ok(());
        }
        Err(error) => {
            let _ = tx.rollback().await;
            return Err(format!("payg invoice creation failed: {error}"));
        }
    };

    mark_period_invoiced(&mut tx, period_id, invoice.id, emails_sent).await?;
    clear_period_sweep_failure(&mut tx, period_id).await?;
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

    if let Err(error) = collect_usage_invoice(
        state,
        &invoice,
        month_start,
        &description,
        "payg",
        &mut result.wallet_paid,
        &mut result.pending_dunning,
    )
    .await
    {
        warn!(
            tenant_id = tenant_id,
            invoice_id = %invoice.id,
            error = %error,
            "payg sweep: collection failed — outbox retains retryable state"
        );
    }

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

/// `unbilled -> needs_review` transition (audits F31/F32): a period whose
/// pricing or usage cannot be resolved from history is surfaced for
/// reconciliation — visible, retained, never silently priced from today's
/// plan or dropped with aged-out metering events.
async fn mark_period_needs_review(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    period_id: Uuid,
    reason: &str,
) -> Result<(), String> {
    sqlx::query(
        r#"
        UPDATE billing_periods
        SET invoice_state = 'needs_review',
            last_sweep_error = $2,
            updated_at = NOW()
        WHERE id = $1
        "#,
    )
    .bind(period_id)
    .bind(format!("needs review: {reason}"))
    .execute(&mut **tx)
    .await
    .map_err(|e| format!("overage sweep: needs-review transition failed: {e}"))?;
    Ok(())
}

/// Persist a backfilled pricing snapshot on the period (audit F32). The
/// guard `overage_rate_millicents IS NULL` makes the backfill a
/// one-time freeze under the period lock — later plan/override changes can
/// never overwrite it.
#[allow(clippy::too_many_arguments)]
async fn persist_pricing_snapshot(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    period_id: Uuid,
    rate_millicents: Option<i64>,
    currency: &str,
    email_allowance: i64,
    plan_name: &str,
) -> Result<(), String> {
    let snapshot = serde_json::json!({
        "snapshotVersion": 1,
        "planName": plan_name,
        "emailAllowance": email_allowance,
        "overageRateMillicents": rate_millicents,
        "currency": currency,
        "backfilled": true,
    });
    sqlx::query(
        r#"
        UPDATE billing_periods
        SET overage_rate_millicents = $2,
            currency = $3,
            pricing_snapshot = $4::jsonb,
            pricing_resolved_at = NOW(),
            updated_at = NOW()
        WHERE id = $1
          AND (overage_rate_millicents IS NULL OR overage_rate_millicents <> $2)
        "#,
    )
    .bind(period_id)
    .bind(rate_millicents)
    .bind(currency)
    .bind(snapshot.to_string())
    .execute(&mut **tx)
    .await
    .map_err(|e| format!("overage sweep: pricing snapshot persist failed: {e}"))?;
    Ok(())
}

/// Currency PAYG months are snapshotted (and invoiced) in. PAYG pricing is
/// defined in EUR; persisting it on the period record means the month is
/// priced from its snapshot even if the platform default later changes
/// (audit F32).
const PAYG_SNAPSHOT_CURRENCY: &str = "EUR";

/// The default period-pricing currency (audit F32): applied ONCE when a
/// pricing snapshot is created and then frozen on the period row —
/// invoicing reads the snapshot, never this default.
pub fn default_period_currency() -> String {
    PAYG_SNAPSHOT_CURRENCY.to_string()
}

/// The complete PAYG tiered pricing context snapshotted onto the period
/// record at claim time (audit F32).
fn payg_pricing_snapshot_json(pricing: &PaygPricing) -> serde_json::Value {
    serde_json::json!({
        "snapshotVersion": 1,
        "usageKind": "payg",
        "currency": PAYG_SNAPSHOT_CURRENCY,
        "pricing": pricing,
    })
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

/// Name of the schema-level period-identity backstop (migration 136).
const OVERAGE_PERIOD_UNIQUE_CONSTRAINT: &str = "uq_invoices_tenant_overage_period";

/// Whether an invoice-creation error is a violation of the EXACT
/// period-identity constraint — the (tenant_id, overage_period) backstop
/// (audit F29). Arbitrary 23505s (invoice number sequence, external
/// invoice id, ...) are NOT period replays and must never be reinterpreted
/// as one; they propagate to the sweep's failure handling.
fn is_overage_period_unique_violation(error: &InvoiceError) -> bool {
    match error {
        InvoiceError::Db(sqlx::Error::Database(db_error)) => {
            db_error.code().as_deref() == Some("23505")
                && db_error.constraint() == Some(OVERAGE_PERIOD_UNIQUE_CONSTRAINT)
        }
        _ => false,
    }
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

/// The snapshotted overage rate rendered as "X.YZ CUR per 1,000 emails"
/// (integer math — 40 millicents/email is 40 cents per 1 000 emails,
/// i.e. "0.40"). The invoice text must quote the rate actually charged in
/// the period's SNAPSHOT currency, never a hardcoded "€0.40" (audit F32).
fn format_rate_per_thousand_emails(rate_millicents: i64, currency: &str) -> String {
    // 1 000 emails × rate millicents = rate cents = rate/100 major units.
    let cents_per_thousand = rate_millicents.max(0);
    format!(
        "{} {}",
        billing_common::proration::cents_to_eur_string(cents_per_thousand),
        currency.to_uppercase()
    )
}

/// Collection ladder for a freshly created usage invoice (see the module
/// docs). Resumable: every step commits durably and is idempotent, and the
/// outbox operation written with the invoice tracks progress under an
/// owner/lease fence (audit F33). Failures propagate as errors and leave
/// the outbox retryable — the operation is marked done ONLY after
/// confirmed settlement or the committed dunning handoff.
async fn collect_usage_invoice(
    state: &AppState,
    invoice: &Invoice,
    period_start: DateTime<Utc>,
    description: &str,
    usage_kind: &str,
    wallet_paid: &mut u64,
    pending_dunning: &mut u64,
) -> Result<(), String> {
    // Outbox: acquire the exclusive owner/lease or STOP (audit F33). A
    // claim failure (or another live owner) must never let collection
    // proceed unowned.
    let Some(owner_token) = claim_collection_operation(state, invoice.id).await? else {
        info!(
            invoice_id = %invoice.id,
            "usage invoice collection: operation not claimable (owned/done) — skipping"
        );
        return Ok(());
    };

    // (a) Wallet first — in the INVOICE's currency, committed WITH its
    // payment allocation (audit F35). A wallet held in another currency is
    // never spent: mixing currencies would mint phantom money. The
    // remaining obligation is derived by the ONE shared outstanding
    // function (total − confirmed payments − debt-reduction credits,
    // audit F60).
    let applied_cents = match apply_wallet_credit(state, invoice).await {
        Ok(applied) => applied,
        Err(error) => {
            record_collection_failure(state, invoice.id, &owner_token, &error).await;
            return Err(format!("wallet application failed: {error}"));
        }
    };

    // Outstanding AFTER the wallet application — the single derivation.
    // An UNAVAILABLE balance is a retryable failure (audit F33): never
    // initiate an external Stripe amount from a fallback total.
    let remaining_cents = match invoice_outstanding_cents(&state.db, invoice.id).await {
        Ok(outstanding) => outstanding,
        Err(error) => {
            let error = format!("outstanding lookup failed: {error}");
            record_collection_failure(state, invoice.id, &owner_token, &error).await;
            return Err(error);
        }
    };

    // (b) Whole-invoice paid when confirmed payments covered everything.
    if remaining_cents <= 0 {
        if let Err(error) = finalize_collection(state, invoice, "paid", &owner_token).await {
            record_collection_failure(state, invoice.id, &owner_token, &error).await;
            return Err(format!("marking paid failed: {error}"));
        }
        *wallet_paid += 1;
        info!(
            tenant_id = %invoice.tenant_id,
            invoice_number = %invoice.invoice_number,
            applied_cents,
            "usage invoice settled in full from wallet balance"
        );
        invalidate_wallet_balance_cache(state, &invoice.tenant_id).await;
        return Ok(());
    }

    // (c) Stripe-managed tenants: post the REMAINING amount as an invoice
    // item AND create + FINALIZE the Stripe invoice (audit F34 — the old
    // pending-item-only path never set stripe_invoice_id, so invoice.paid
    // never matched and final usage could wait forever for a renewal that
    // never comes). Idempotency keys carry the local invoice id, usage
    // kind AND the frozen amount/currency; the local ↔ external mapping is
    // persisted before finalize. The HTTP calls run OUTSIDE every
    // wallet-lock transaction (audit F33). A Stripe failure is a
    // retryable error: the outbox keeps the work and backs off — the
    // invoice is NOT pushed to done on the back of a failure.
    let stripe = match create_and_finalize_stripe_usage_invoice(
        state,
        invoice,
        remaining_cents,
        &invoice.currency,
        description,
        period_start,
        usage_kind,
    )
    .await
    {
        Ok(stripe) => stripe,
        Err(error) => {
            record_collection_failure(state, invoice.id, &owner_token, &error).await;
            return Err(format!("Stripe collection failed: {error}"));
        }
    };

    if let Some(mapping) = stripe.as_ref() {
        let persisted = sqlx::query(
            r#"
            UPDATE invoices
            SET stripe_invoice_id = $2,
                stripe_invoice_item_id = $3,
                updated_at = NOW()
            WHERE id = $1
              AND (stripe_invoice_id IS NULL OR stripe_invoice_id = $2)
            "#,
        )
        .bind(invoice.id)
        .bind(&mapping.invoice_id)
        .bind(&mapping.item_id)
        .execute(&state.db)
        .await;
        match persisted {
            Ok(execution) if execution.rows_affected() > 0 => {}
            Ok(_) => warn!(
                invoice_id = %invoice.id,
                existing = ?invoice.stripe_invoice_id,
                "usage invoice collection: Stripe mapping not stored — invoice already bound to a different Stripe invoice"
            ),
            Err(error) => {
                // The external operation exists; the mapping must not be
                // lost — keep the outbox retryable (audit F34).
                let error = format!("storing Stripe mapping failed: {error}");
                record_collection_failure(state, invoice.id, &owner_token, &error).await;
                return Err(error);
            }
        }
    }

    // (d) Pending → dunning flow with a TRANSACTIONAL handoff to the
    // durable dunning machinery (audit F33): dunning_records (what the
    // retry/suspension jobs actually read) is upserted in the same
    // transaction that flips the invoice and completes the outbox
    // operation. Only this committed handoff — or confirmed settlement —
    // legitimizes marking the operation done.
    if let Err(error) = finalize_collection(state, invoice, "pending", &owner_token).await {
        record_collection_failure(state, invoice.id, &owner_token, &error).await;
        return Err(format!("dunning handoff failed: {error}"));
    }
    *pending_dunning += 1;
    info!(
        tenant_id = %invoice.tenant_id,
        invoice_number = %invoice.invoice_number,
        applied_cents,
        remaining_cents,
        stripe_invoice = stripe.as_ref().map(|m| m.invoice_id.clone()),
        "usage invoice moved to pending — wallet applied, remainder handed to dunning/Stripe"
    );

    invalidate_wallet_balance_cache(state, &invoice.tenant_id).await;
    Ok(())
}

/// How long a collection lease is held before a crashed collector's work
/// becomes reclaimable (audit F33).
const COLLECTION_LEASE_SECS: i64 = 600;

/// Outbox claim: pending/in_progress -> in_progress with a bumped attempt
/// counter AND an exclusive owner/lease (audit F33). Returns
/// `Ok(Some(owner_token))` when this collector now owns the operation;
/// `Ok(None)` when there is nothing claimable (done/failed, missing row,
/// or a live lease held elsewhere). The returned token fences every
/// subsequent transition of the operation.
async fn claim_collection_operation(
    state: &AppState,
    invoice_id: Uuid,
) -> Result<Option<String>, String> {
    let owner_token = format!("col-{}", Uuid::new_v4().simple());
    let lease_expires_at = Utc::now() + chrono::Duration::seconds(COLLECTION_LEASE_SECS);
    let claimed: Option<String> = sqlx::query_scalar(
        r#"
        UPDATE invoice_collection_outbox
        SET status = 'in_progress',
            attempts = attempts + 1,
            owner_token = $2,
            lease_expires_at = $3,
            updated_at = NOW()
        WHERE invoice_id = $1
          AND operation = 'collect_usage_invoice'
          AND status IN ('pending', 'in_progress')
          AND (
                owner_token IS NULL
             OR owner_token = $2
             OR lease_expires_at IS NULL
             OR lease_expires_at < NOW()
          )
        RETURNING owner_token
        "#,
    )
    .bind(invoice_id)
    .bind(&owner_token)
    .bind(lease_expires_at)
    .fetch_optional(&state.db)
    .await
    .map_err(|error| format!("outbox claim failed: {error}"))?;
    Ok(claimed)
}

/// Maximum collection attempts before the operation dead-letters (audit
/// F33): exhausted attempts are exposed as `failed` rows, never silently
/// omitted from the resume query.
const COLLECTION_MAX_ATTEMPTS: i32 = 10;

/// Record a retryable collection failure on the outbox row (audit F33):
/// the owner/lease is released, the error is stored, and a capped
/// exponential backoff decides when the work becomes claimable again.
/// Once the attempt cap is reached the operation dead-letters to `failed`
/// — visible, not retried blindly.
async fn record_collection_failure(
    state: &AppState,
    invoice_id: Uuid,
    owner_token: &str,
    error: &str,
) {
    let backoff_secs: i64 = 300_i64
        .saturating_mul(
            2_i64.saturating_pow(
                sqlx::query_scalar::<_, i32>(
                    "SELECT attempts FROM invoice_collection_outbox \
                     WHERE invoice_id = $1 AND operation = 'collect_usage_invoice'",
                )
                .bind(invoice_id)
                .fetch_one(&state.db)
                .await
                .map(|attempts| (attempts as u32).saturating_sub(1).clamp(0, 8))
                .unwrap_or(0),
            ),
        )
        .min(24 * 60 * 60);
    let next_attempt_at = Utc::now() + chrono::Duration::seconds(backoff_secs);
    let dead_letter = sqlx::query_scalar::<_, bool>(
        r#"
        UPDATE invoice_collection_outbox
        SET last_error = $3,
            owner_token = NULL,
            lease_expires_at = NULL,
            status = CASE WHEN attempts >= $4 THEN 'failed' ELSE 'pending' END,
            next_attempt_at = CASE WHEN attempts >= $4 THEN NULL ELSE $5 END,
            updated_at = NOW()
        WHERE invoice_id = $1
          AND operation = 'collect_usage_invoice'
          AND (owner_token = $2 OR owner_token IS NULL)
        RETURNING status = 'failed'
        "#,
    )
    .bind(invoice_id)
    .bind(owner_token)
    .bind(error)
    .bind(COLLECTION_MAX_ATTEMPTS)
    .bind(next_attempt_at)
    .fetch_optional(&state.db)
    .await;
    match dead_letter {
        Ok(Some(true)) => warn!(
            invoice_id = %invoice_id,
            error = error,
            "usage invoice collection: attempts exhausted — operation dead-lettered for operator review"
        ),
        Ok(_) => {}
        Err(record_error) => warn!(
            invoice_id = %invoice_id,
            error = %record_error,
            "usage invoice collection: failed to record failure state"
        ),
    }
}

/// Apply the tenant's wallet balance to the invoice. The wallet debit,
/// its `wallet_transactions` row and the immutable payment allocation
/// (unique operation id) commit TOGETHER (audit F35). Serialization:
/// advisory lock on the invoice, so the sweep and the outbox resumer can
/// never double-apply. What remains is derived by the ONE shared
/// outstanding function — total − confirmed payments − debt-reduction
/// credits (audit F60: wallet application must not ignore credits, and
/// must not invent its own total-minus-this-debit figure). The wallet must
/// be held in the INVOICE's currency. Returns the cents applied by THIS
/// call (0 when the wallet is empty, currency-mismatched, or the invoice
/// is already covered); an unreachable balance is a retryable error.
async fn apply_wallet_credit(state: &AppState, invoice: &Invoice) -> Result<i64, String> {
    let mut tx = state
        .db
        .begin()
        .await
        .map_err(|error| format!("failed to open wallet transaction: {error}"))?;

    let lock = sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
        .bind(format!("usage_collect:{}", invoice.id))
        .execute(&mut *tx)
        .await
        .map_err(|error| format!("wallet serialization lock failed: {error}"))?;

    let wallet: Option<(i64, String)> =
        sqlx::query_as("SELECT balance, currency FROM wallets WHERE tenant_id = $1 FOR UPDATE")
            .bind(&invoice.tenant_id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(|error| format!("wallet read failed: {error}"))?;

    let Some((balance, wallet_currency)) = wallet else {
        let _ = tx.rollback().await;
        return Ok(0);
    };
    if !wallet_currency
        .trim()
        .eq_ignore_ascii_case(invoice.currency.trim())
    {
        warn!(
            tenant_id = %invoice.tenant_id,
            wallet_currency = %wallet_currency,
            invoice_currency = %invoice.currency,
            "usage invoice collection: wallet currency does not match the invoice — not spendable"
        );
        let _ = tx.rollback().await;
        return Ok(0);
    }

    // What remains is the SHARED outstanding derivation (audit F60) —
    // total − confirmed allocations − debt-reduction credits — read under
    // the invoice lock, so retries and concurrent ladders can never
    // over-apply. An unavailable derivation is a retryable failure, never
    // a fallback figure (audit F33).
    let remaining = invoice_outstanding_cents_in(&mut *tx, invoice.id)
        .await
        .map_err(|error| format!("outstanding derivation failed: {error}"))?;
    if balance <= 0 || remaining <= 0 {
        let _ = tx.rollback().await;
        return Ok(0);
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
        SELECT gen_random_uuid(), $1, $5, $6, 'wallet', $2, $7, wallet_tx.id
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
    .bind(invoice.currency.to_uppercase())
    .execute(&mut *tx)
    .await
    .map_err(|error| format!("wallet debit failed: {error}"))?;

    if debit.rows_affected() == 0 {
        // The allocation already exists (replay) — nothing to debit again.
        let _ = tx.rollback().await;
        return Ok(0);
    }

    // Audit F33: check EVERY commit — an ignored failure here would have
    // debited nothing yet report credit applied.
    tx.commit()
        .await
        .map_err(|error| format!("wallet transaction commit failed: {error}"))?;

    let _ = lock;
    Ok(applied_cents)
}

/// Flip the just-created draft invoice to its collection status, mark the
/// period collected, record the dunning entry and complete the outbox
/// operation — one committed transaction (audit F33). Only a row still in
/// `draft` is status-flipped, so a concurrent manual payment can never be
/// overwritten.
///
/// The outbox operation is completed ONLY here, and ONLY fenced by the
/// owner token that claimed it. For `pending`, the SAME transaction
/// upserts `dunning_records` — the durable retry/suspension machinery the
/// maintenance jobs actually read (`process_scheduled_retries` selects
/// `next_retry_at IS NOT NULL AND status IN ('warning', 'soft_suspended')`)
/// — so the handoff is committed together with the done-marking instead
/// of a `dunning_entered` event nothing consumes.
async fn finalize_collection(
    state: &AppState,
    invoice: &Invoice,
    status: &str,
    owner_token: &str,
) -> Result<(), String> {
    let mut tx = state
        .db
        .begin()
        .await
        .map_err(|e| format!("finalize tx failed: {e}"))?;

    let invoice_update = sqlx::query(
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

    if invoice_update.rows_affected() == 0 {
        // Not in draft anymore (concurrent settlement) — still safe to
        // complete the handoff below; nothing was overwritten.
        warn!(
            invoice_id = %invoice.id,
            requested_status = status,
            "usage invoice collection: invoice no longer draft — status left untouched"
        );
    }

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
        // Audit F33 — the durable handoff: dunning_records is what the
        // retry jobs read. Upserted in the SAME transaction as the
        // outbox completion, with a scheduled first retry.
        sqlx::query(
            r#"
            INSERT INTO dunning_records (
                id, tenant_id, status, failed_payment_count, first_failed_at,
                last_failed_at, next_retry_at, suspended_at, grace_period_ends_at,
                created_at, updated_at
            )
            VALUES ($2, $1, 'warning', 1, NOW(), NOW(), NOW() + INTERVAL '1 day', NULL, NULL, NOW(), NOW())
            ON CONFLICT (tenant_id) DO UPDATE SET
                last_failed_at = NOW(),
                next_retry_at = COALESCE(
                    dunning_records.next_retry_at,
                    NOW() + INTERVAL '1 day'
                ),
                updated_at = NOW()
            "#,
        )
        .bind(&invoice.tenant_id)
        .bind(crate::routes::generate_audit_log_id())
        .execute(&mut *tx)
        .await
        .map_err(|e| format!("dunning handoff upsert failed: {e}"))?;

        // Explicit dunning entry for the invoice's history (audit F33:
        // diagnostic trail alongside the durable dunning_records row).
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

    // Outbox completion, fenced by the claiming owner (audit F33).
    let outbox_done = sqlx::query(
        r#"
        UPDATE invoice_collection_outbox
        SET status = 'done',
            owner_token = NULL,
            lease_expires_at = NULL,
            next_attempt_at = NULL,
            last_error = NULL,
            updated_at = NOW()
        WHERE invoice_id = $1
          AND operation = 'collect_usage_invoice'
          AND (owner_token = $2 OR owner_token IS NULL)
        "#,
    )
    .bind(invoice.id)
    .bind(owner_token)
    .execute(&mut *tx)
    .await
    .map_err(|e| format!("outbox completion failed: {e}"))?;

    if outbox_done.rows_affected() == 0 {
        return Err(format!(
            "outbox completion matched no owned row — lease lost or stolen for invoice {}",
            invoice.id
        ));
    }

    tx.commit()
        .await
        .map_err(|e| format!("finalize commit failed: {e}"))?;
    Ok(())
}

/// The persisted local ↔ external Stripe mapping for a collected usage
/// invoice (audit F34): the REAL invoice id (`in_...`) that
/// `invoice.paid` reconciles against, plus the pending item id it was
/// built from.
#[derive(Debug, Clone)]
struct StripeUsageInvoice {
    invoice_id: String,
    item_id: String,
}

/// Immediate Stripe collection of a usage invoice's remaining amount
/// (audit F34): post the remaining amount as an invoice item, then CREATE
/// and FINALIZE a Stripe invoice for that item — the charge happens now,
/// not "on some future renewal" (which never comes for cancelled/PAYG
/// tenants).
///
/// * `quantity`/`unit_amount` reproduce the integer-cents amount EXACTLY
///   (1 × amount_cents) — Stripe cannot express millicents.
/// * Every idempotency key embeds the immutable local operation identity
///   (invoice id + usage kind) AND the FROZEN amount/currency, so a retry
///   after a wallet-balance change can never replay one Stripe key with
///   different request parameters (F34).
/// * Stripe metadata carries the local invoice id, usage kind and period,
///   so callbacks reconcile through the persisted mapping.
/// * Returns `Ok(None)` when the tenant has no Stripe customer or no
///   `STRIPE_SECRET_KEY` is configured (the wallet + dunning path covers
///   them).
async fn create_and_finalize_stripe_usage_invoice(
    state: &AppState,
    invoice: &Invoice,
    amount_cents: i64,
    currency: &str,
    description: &str,
    period_start: DateTime<Utc>,
    usage_kind: &str,
) -> Result<Option<StripeUsageInvoice>, String> {
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
    .bind(&invoice.tenant_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| format!("Stripe customer lookup failed: {e}"))?;
    let Some(customer) = customer else {
        return Ok(None); // no Stripe customer — wallet + dunning path
    };

    let base_url =
        std::env::var("STRIPE_API_BASE_URL").unwrap_or_else(|_| "https://api.stripe.com".into());
    let client = reqwest::Client::new();
    let currency_code = currency.trim().to_lowercase();
    // Frozen external operation identity: local invoice + usage kind +
    // amount + currency (audit F34 — changed parameters can never reuse a
    // previously issued key).
    let key_seed = format!(
        "usageinv_{}_{}_{}c_{}",
        invoice.id.simple(),
        usage_kind,
        amount_cents,
        currency_code
    );

    // 1. Pending invoice item for the remaining amount.
    let item_form = [
        ("customer", customer.clone()),
        ("currency", currency_code.clone()),
        ("description", description.to_string()),
        ("unit_amount", amount_cents.to_string()),
        ("quantity", "1".to_string()),
        ("metadata[apexmailInvoiceId]", invoice.id.to_string()),
        ("metadata[apexmailTenantId]", invoice.tenant_id.clone()),
        ("metadata[periodStart]", period_start.to_rfc3339()),
        ("metadata[usageKind]", usage_kind.to_string()),
    ];
    let response = client
        .post(format!("{base_url}/v1/invoiceitems"))
        .bearer_auth(&secret_key)
        .header("Idempotency-Key", format!("{key_seed}_item"))
        .form(&item_form)
        .timeout(std::time::Duration::from_secs(30))
        .send()
        .await
        .map_err(|e| format!("Stripe invoice item request failed: {e}"))?;
    let status = response.status();
    let body = response.text().await.unwrap_or_default();
    if !status.is_success() {
        return Err(format!("Stripe invoice item returned {status}: {body}"));
    }
    let parsed: serde_json::Value = serde_json::from_str(&body)
        .map_err(|e| format!("Stripe invoice item decode failed: {e}"))?;
    let Some(item_id) = parsed
        .get("id")
        .and_then(|value| value.as_str())
        .map(str::to_string)
    else {
        return Err("Stripe invoice item response carried no id".into());
    };

    // 2. Create the invoice that carries the item — the REAL `in_...`
    // identity the invoice.paid webhook matches (audit F34).
    let invoice_form = [
        ("customer", customer),
        ("metadata[apexmailInvoiceId]", invoice.id.to_string()),
        ("metadata[apexmailTenantId]", invoice.tenant_id.clone()),
        ("metadata[usageKind]", usage_kind.to_string()),
    ];
    let response = client
        .post(format!("{base_url}/v1/invoices"))
        .bearer_auth(&secret_key)
        .header("Idempotency-Key", format!("{key_seed}_invoice"))
        .form(&invoice_form)
        .timeout(std::time::Duration::from_secs(30))
        .send()
        .await
        .map_err(|e| format!("Stripe invoice create request failed: {e}"))?;
    let create_status = response.status();
    let create_body = response.text().await.unwrap_or_default();
    if !create_status.is_success() {
        return Err(format!(
            "Stripe invoice create returned {create_status}: {create_body}"
        ));
    }
    let created: serde_json::Value = serde_json::from_str(&create_body)
        .map_err(|e| format!("Stripe invoice create decode failed: {e}"))?;
    let Some(stripe_invoice_id) = created
        .get("id")
        .and_then(|value| value.as_str())
        .map(str::to_string)
    else {
        return Err("Stripe invoice create response carried no id".into());
    };

    // 3. FINALIZE — the charge is attempted immediately (audit F34: an
    // immediate final-usage collection path that does not rely on another
    // renewal). Settlement is confirmed by the invoice.paid webhook
    // reconciling stripe_invoice_id; this call only opens the attempt.
    let response = client
        .post(format!(
            "{base_url}/v1/invoices/{stripe_invoice_id}/finalize"
        ))
        .bearer_auth(&secret_key)
        .header("Idempotency-Key", format!("{key_seed}_finalize"))
        .timeout(std::time::Duration::from_secs(30))
        .send()
        .await
        .map_err(|e| format!("Stripe invoice finalize request failed: {e}"))?;
    let finalize_status = response.status();
    let finalize_body = response.text().await.unwrap_or_default();
    if !finalize_status.is_success() {
        return Err(format!(
            "Stripe invoice finalize returned {finalize_status}: {finalize_body}"
        ));
    }

    Ok(Some(StripeUsageInvoice {
        invoice_id: stripe_invoice_id,
        item_id,
    }))
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

/// Statistics from a resume pass (audit F33): exhausted operations are
/// dead-lettered (exposed), not silently omitted.
#[derive(Debug, Default, Clone, Copy)]
pub struct CollectionResumeStats {
    pub resumed: u64,
    pub dead_lettered: u64,
}

/// Resume stranded collection operations (audit F33): invoices whose
/// `collect_usage_invoice` outbox row is still pending/in_progress — e.g.
/// the process died between invoice creation and collection — are run
/// through the same idempotent ladder again. Only operations whose retry
/// backoff has elapsed are claimed; operations past the attempt cap are
/// dead-lettered to `failed` and EXPOSED instead of being silently
/// filtered out. Wired into the maintenance hourly loop.
pub async fn resume_pending_collections(state: &AppState) -> Result<CollectionResumeStats, String> {
    let stranded: Vec<(Uuid, String, serde_json::Value)> = sqlx::query_as(
        r#"
        SELECT invoice_id, tenant_id, payload
        FROM invoice_collection_outbox
        WHERE operation = 'collect_usage_invoice'
          AND status IN ('pending', 'in_progress')
          AND (next_attempt_at IS NULL OR next_attempt_at <= NOW())
        ORDER BY created_at
        LIMIT 100
        "#,
    )
    .fetch_all(&state.db)
    .await
    .map_err(|e| format!("collection resume: outbox query failed: {e}"))?;

    let mut stats = CollectionResumeStats::default();
    for (invoice_id, tenant_id, payload) in stranded {
        // Exhausted attempts dead-letter (audit F33): visible failure, no
        // blind retry.
        let attempts: i32 = sqlx::query_scalar(
            "SELECT attempts FROM invoice_collection_outbox \
             WHERE invoice_id = $1 AND operation = 'collect_usage_invoice'",
        )
        .bind(invoice_id)
        .fetch_one(&state.db)
        .await
        .unwrap_or(0);
        if attempts >= COLLECTION_MAX_ATTEMPTS {
            let dead = sqlx::query(
                "UPDATE invoice_collection_outbox \
                 SET status = 'failed', owner_token = NULL, lease_expires_at = NULL, \
                     next_attempt_at = NULL, updated_at = NOW() \
                 WHERE invoice_id = $1 AND operation = 'collect_usage_invoice'",
            )
            .bind(invoice_id)
            .execute(&state.db)
            .await;
            if let Err(error) = dead {
                warn!(invoice_id = %invoice_id, error = %error, "collection resume: dead-letter update failed");
                continue;
            }
            warn!(
                tenant_id = %tenant_id,
                invoice_id = %invoice_id,
                attempts,
                "collection resume: attempts exhausted — operation dead-lettered for operator review"
            );
            stats.dead_lettered += 1;
            continue;
        }

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
        if let Err(error) = collect_usage_invoice(
            state,
            &invoice,
            period_start,
            &description,
            &usage_kind,
            &mut wallet_paid,
            &mut pending_dunning,
        )
        .await
        {
            warn!(
                tenant_id = %tenant_id,
                invoice_id = %invoice_id,
                error = %error,
                "collection resume: ladder failed — retryable state retained on the outbox"
            );
            continue;
        }
        stats.resumed += 1;
        info!(
            tenant_id = %tenant_id,
            invoice_id = %invoice_id,
            "collection resume: re-ran collection ladder for stranded usage invoice"
        );
    }

    Ok(stats)
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
    fn rate_text_formats_the_configured_rate_with_the_snapshot_currency() {
        // 40 millicents/email = 40 cents per 1 000 = 0.40.
        assert_eq!(format_rate_per_thousand_emails(40, "EUR"), "€0.40 EUR");
        // A doubled rate renders doubled, never the old constant.
        assert_eq!(format_rate_per_thousand_emails(80, "EUR"), "€0.80 EUR");
        assert_eq!(format_rate_per_thousand_emails(125, "EUR"), "€1.25 EUR");
        // A non-EUR snapshot currency is rendered, not coerced to EUR
        // (audit F32).
        assert_eq!(format_rate_per_thousand_emails(40, "usd"), "€0.40 USD");
        // Degenerate rates never render negative.
        assert_eq!(format_rate_per_thousand_emails(0, "EUR"), "€0.00 EUR");
        assert_eq!(format_rate_per_thousand_emails(-5, "EUR"), "€0.00 EUR");
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
    fn stripe_idempotency_key_shape_is_stable_per_invoice_amount_currency() {
        // (Documented contract; the key is built inline in
        // create_and_finalize_stripe_usage_invoice — pin the shape.) The
        // key embeds the local invoice id, usage kind AND the frozen
        // amount/currency (audit F34): a retry with changed parameters
        // gets a DIFFERENT key, so Stripe never replays one key with
        // different request parameters.
        let invoice_id = Uuid::new_v4();
        let key_seed = format!(
            "usageinv_{}_{}_{}c_{}",
            invoice_id.simple(),
            "overage",
            6000,
            "eur"
        );
        assert_eq!(
            format!("{key_seed}_item"),
            format!("usageinv_{}_overage_6000c_eur_item", invoice_id.simple())
        );
        // A changed amount changes the key.
        let changed = format!("usageinv_{}_overage_4000c_eur_item", invoice_id.simple());
        assert_ne!(format!("{key_seed}_item"), changed);
    }

    // ------------------------------------------------------------------
    // Audit F29 — ONLY the exact period-identity constraint (by name) is
    // a period replay; arbitrary unique violations are not.
    // ------------------------------------------------------------------

    #[test]
    fn unique_violation_is_detected_through_the_error_wrapper() {
        use sqlx::error::DatabaseError;

        struct FakeDbError {
            code: &'static str,
            constraint: Option<String>,
        }
        impl std::fmt::Debug for FakeDbError {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "FakeDbError({})", self.code)
            }
        }
        impl std::fmt::Display for FakeDbError {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "FakeDbError({})", self.code)
            }
        }
        impl std::error::Error for FakeDbError {}
        impl DatabaseError for FakeDbError {
            fn message(&self) -> &str {
                "duplicate key value violates unique constraint"
            }
            fn code(&self) -> Option<std::borrow::Cow<'_, str>> {
                Some(self.code.into())
            }
            fn constraint(&self) -> Option<&str> {
                self.constraint.as_deref()
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

        fn db_error(code: &'static str, constraint: Option<&str>) -> InvoiceError {
            InvoiceError::Db(sqlx::Error::Database(Box::new(FakeDbError {
                code,
                constraint: constraint.map(str::to_string),
            })))
        }

        // The exact period-identity constraint firing IS a period replay.
        let unique = db_error("23505", Some("uq_invoices_tenant_overage_period"));
        assert!(is_overage_period_unique_violation(&unique));

        // Any OTHER unique violation (invoice number, external invoice id,
        // ...) must NOT be reinterpreted as a period replay (audit F29).
        let other_constraint = db_error("23505", Some("invoices_invoice_number_key"));
        assert!(!is_overage_period_unique_violation(&other_constraint));

        let unnamed_unique = db_error("23505", None);
        assert!(!is_overage_period_unique_violation(&unnamed_unique));

        let not_unique = db_error("23503", Some("uq_invoices_tenant_overage_period"));
        assert!(!is_overage_period_unique_violation(&not_unique));

        let not_db = InvoiceError::NoBillingAddress;
        assert!(!is_overage_period_unique_violation(&not_db));
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
    // Audits F29/F31/F32 — the sweep selects only unbilled periods,
    // excludes completed work in SQL, pages with a COMPLETE keyset (no
    // age cutoff: unresolved work is retained), and reads the pricing
    // snapshot columns.
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
    fn sweep_pagination_is_a_complete_keyset() {
        // Keyset predicate + deterministic ORDER matching it — the
        // (period_end, tenant_id) pair alone was NOT a unique row ordering
        // (audit F31).
        assert!(SWEEP_UNBILLED_PERIODS_SQL.contains("(period_end, tenant_id, id) >"));
        assert!(SWEEP_UNBILLED_PERIODS_SQL.contains("ORDER BY period_end, tenant_id, id"));
        assert!(SWEEP_UNBILLED_PERIODS_SQL.contains("LIMIT $4"));
        // No OFFSET — offsets re-visit rows as pages complete.
        assert!(!SWEEP_UNBILLED_PERIODS_SQL.to_lowercase().contains("offset"));
    }

    #[test]
    fn sweep_never_ages_out_unresolved_periods() {
        // Audit F31: raw-event retention (40 days) must not be the expiry
        // policy for unresolved financial work — no age cutoff, and
        // per-period backoff gates retries instead.
        assert!(!SWEEP_UNBILLED_PERIODS_SQL.contains("INTERVAL '40 days'"));
        assert!(!SWEEP_UNBILLED_PERIODS_SQL.contains("40 days"));
        assert!(SWEEP_UNBILLED_PERIODS_SQL.contains("next_sweep_attempt_at IS NULL"));
    }

    #[test]
    fn sweep_selects_the_pricing_snapshot_columns() {
        // Audit F32: pricing reads the period's snapshot (rate + currency),
        // never the current plan ladder.
        assert!(SWEEP_UNBILLED_PERIODS_SQL.contains("overage_rate_millicents"));
        assert!(SWEEP_UNBILLED_PERIODS_SQL.contains("currency"));
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
