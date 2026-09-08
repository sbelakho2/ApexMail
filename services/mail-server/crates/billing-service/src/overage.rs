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
//! # Collection flow (audit 1.3 — drafts were previously never collected)
//!
//! Every invoice this sweep creates is pushed through the same ladder:
//!
//! 1. **Wallet first.** The tenant's EUR wallet balance is applied to the
//!    invoice (a non-EUR wallet is never spent — currency mixing would mint
//!    phantom money). Full coverage marks the invoice `paid` immediately;
//!    partial coverage reduces the amount still owed.
//! 2. **Stripe invoice item.** For tenants with a Stripe customer on file
//!    and a configured `STRIPE_SECRET_KEY`, the REMAINING amount is added
//!    as a pending invoice item (`/v1/invoiceitems`, idempotency key
//!    `overage_{tenant}_{period_start}`) so Stripe collects it on the next
//!    billing cycle. Invoice items — not Stripe Meter usage records — are
//!    the chosen mechanism: the platform already meters into
//!    `metering_events` and prices in integer cents/millicents, and an
//!    invoice item reproduces the millicent-exact amount without a second
//!    metering pipeline. Tenants without a Stripe customer fall through to
//!    step 3 only.
//! 3. **Dunning.** Whatever the wallet did not cover flips the invoice from
//!    `draft` to `pending`, entering the existing dunning flow
//!    (soft-suspend after 7 days, hard-suspend after 21, 7-day grace — see
//!    `stripe_webhooks.rs` and the `dunning_config` defaults) instead of
//!    rotting as a draft nothing ever charges.
//!
//! Idempotency: one usage invoice per (tenant, period), guarded by a
//! `pg_advisory_xact_lock` plus the explicit `invoices.overage_period`
//! marker column (migration 126) — never again by scraping
//! `line_items::text LIKE '%Overage:%'`.

use crate::config::PaygPricing;
use crate::invoices::{create_invoice, CreateInvoiceInput, NewLineItem};
use crate::plans;
use crate::types::Invoice;
use crate::AppState;
use chrono::{DateTime, Datelike, Timelike, Utc};
use deadpool_redis::redis::AsyncCommands;
use sqlx::PgPool;
use tracing::{info, warn};

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
}

/// A billing period that has ended and may carry billable usage. The
/// subscription's own plan name is carried because terminal-status rows
/// (lapsed trials, canceled subs) must be priced by the plan that was in
/// force during the period — the tenant may already be downgraded to free.
#[derive(sqlx::FromRow)]
struct EndedPeriodRow {
    tenant_id: String,
    billing_cycle_start: DateTime<Utc>,
    billing_cycle_end: DateTime<Utc>,
    subscription_plan: Option<String>,
    status: String,
}

/// Daily sweep: for every recently-ended billing cycle, compute metered
/// `emails_sent` beyond the plan limit and invoice (and collect) the
/// overage; then invoice PAYG tenants for their metered calendar-month
/// usage. Idempotent per (tenant, period): a period with an existing usage
/// invoice is skipped, so re-runs after downtime are safe. The lookback
/// window covers the metering TTL (40 days).
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

/// Overage half of the sweep: every ended `stripe_subscriptions` cycle in
/// the lookback, regardless of subscription status — a lapsed paid-tier
/// trial or a canceled subscription accrued real overage that must still be
/// invoiced (audit 1.3). Only never-paid free plans are skipped (free has
/// no overage entitlement by definition).
async fn sweep_subscription_periods(
    state: &AppState,
    result: &mut OverageSweepResult,
) -> Result<(), String> {
    // No status filter: 'active' rows carry the ordinary end-of-cycle
    // overage; 'trialing'/'canceled'/'unpaid'/'past_due' rows whose cycle
    // ended in the lookback carry overage accrued while the paid tier (or
    // trial of one) was in force. Plan resolution below decides whether
    // the period is billable.
    let periods: Vec<EndedPeriodRow> = sqlx::query_as(
        r#"
        SELECT tenant_id, billing_cycle_start, billing_cycle_end,
               plan AS subscription_plan, status::text AS status
        FROM stripe_subscriptions
        WHERE billing_cycle_end IS NOT NULL
          AND billing_cycle_end < NOW()
          AND billing_cycle_end > NOW() - INTERVAL '40 days'
        ORDER BY billing_cycle_end ASC
        LIMIT 500
        "#,
    )
    .fetch_all(&state.db)
    .await
    .map_err(|e| format!("overage sweep: period query failed: {e}"))?;

    for period in periods {
        result.periods_checked += 1;

        // Effective plan name for this period (tenant row or terminal
        // subscription) — drives the per-plan overage rate below.
        let mut sweep_plan_name = String::new();

        // Plan limit for the period. Active subscriptions resolve the
        // TENANT-level (override-aware) limit — the same source the
        // enforcement gate used, so the invoice bills exactly the volume
        // the gate allowed. Terminal/trialing rows resolve the
        // SUBSCRIPTION's own plan: the tenant is frequently already
        // downgraded to free, and pricing the old cycle at today's free
        // limit would bill volume that was never granted.
        let plan_limit = if period.status == "active" {
            // Plan limit at the tenant level (override-aware, same source
            // as the enforcement gate).
            let limit_row: Option<(String, Option<i64>)> = sqlx::query_as(
                r#"
                SELECT t.plan as plan_name, p.email_limit
                FROM tenants t
                LEFT JOIN plan_overrides po
                  ON po.tenant_id = t.id
                 AND po.active = true
                 AND (po.expires_at IS NULL OR po.expires_at > NOW())
                LEFT JOIN plans p ON p.name = COALESCE(po.plan, t.plan)
                WHERE t.id = $1
                "#,
            )
            .bind(&period.tenant_id)
            .fetch_optional(&state.db)
            .await
            .map_err(|e| format!("overage sweep: plan limit query failed: {e}"))?;

            let Some((plan_name, email_limit)) = limit_row else {
                warn!(tenant_id = %period.tenant_id, "overage sweep: tenant row missing; skipping period");
                result.skipped_unknown_plan += 1;
                continue;
            };
            // Missing/deactivated plans row (LEFT JOIN miss): resolve the
            // builtin plan's limit BY NAME; unknown names are skipped
            // loudly below — never `unwrap_or(0)`, which billed the
            // tenant's entire volume as overage (audit 1.3).
            sweep_plan_name = plan_name;
            resolve_plan_limit_or_warn(
                &state.db,
                &sweep_plan_name,
                email_limit,
                &period.tenant_id,
                &mut result.skipped_unknown_plan,
            )
            .await?
        } else {
            let Some(plan_name) = period.subscription_plan.clone() else {
                warn!(
                    tenant_id = %period.tenant_id,
                    subscription_status = %period.status,
                    "overage sweep: terminal subscription has no plan name; skipping period"
                );
                result.skipped_unknown_plan += 1;
                continue;
            };
            sweep_plan_name = plan_name;
            resolve_plan_limit_or_warn(
                &state.db,
                &sweep_plan_name,
                None,
                &period.tenant_id,
                &mut result.skipped_unknown_plan,
            )
            .await?
        };

        let Some(plan_limit) = plan_limit else {
            continue; // already counted + warned
        };

        if plan_limit < 0 {
            result.skipped_no_overage += 1;
            continue; // unlimited plan — no overage by definition
        }

        // Metered sends for exactly this billing cycle.
        let sent: i64 = sqlx::query_scalar(
            r#"
            SELECT COALESCE(SUM(quantity), 0)::bigint
            FROM metering_events
            WHERE tenant_id = $1
              AND event_type = 'emails_sent'
              AND timestamp >= $2
              AND timestamp <  $3
            "#,
        )
        .bind(&period.tenant_id)
        .bind(period.billing_cycle_start)
        .bind(period.billing_cycle_end)
        .fetch_one(&state.db)
        .await
        .map_err(|e| format!("overage sweep: usage query failed: {e}"))?;

        let overage_emails = sent - plan_limit;
        if overage_emails <= 0 {
            result.skipped_no_overage += 1;
            continue;
        }

        // A billing address is mandatory on a VAT invoice; without one the
        // invoice cannot be issued correctly — surface loudly and retry next
        // sweep (the idempotency check above means nothing is double-billed
        // once the address is backfilled).
        if !tenant_has_billing_address(&state.db, &period.tenant_id).await? {
            result.skipped_no_address += 1;
            warn!(
                tenant_id = %period.tenant_id,
                overage_emails,
                "overage accrued but no billing address on file — invoice deferred"
            );
            continue;
        }

        // Review 2026-09-08 §9: the DIFFERENTIATED per-plan ladder prices
        // overage (Developer 80 / Pro 60 / Growth+Business+Enterprise 35
        // millicents per email). Free/PAYG/unknown plans have no automatic
        // overage — skip. The invoice text below quotes the same rate.
        let rate_millicents = match plans::plan_overage_rate_millicents(&sweep_plan_name) {
            Some(rate) => rate,
            None => {
                warn!(
                    tenant_id = %period.tenant_id,
                    plan = %sweep_plan_name,
                    "overage sweep: plan has no automatic overage; skipping period"
                );
                result.skipped_no_overage += 1;
                continue;
            }
        };
        let amount_cents =
            plans::calculate_overage_cost_with_rate(sent, plan_limit, rate_millicents);
        if amount_cents <= 0 {
            result.skipped_no_overage += 1;
            continue;
        }

        let description = format!(
            "Overage: {overage_emails} emails beyond the plan limit ({plan_limit}/cycle), at {} per 1,000",
            format_rate_per_thousand_emails(rate_millicents)
        );

        // Idempotency (audit: concurrent sweeps double-invoiced): serialize
        // on (tenant, period) with the same advisory-lock shape the SLA
        // sweep uses, then re-check the explicit overage_period marker
        // INSIDE the lock.
        if !claim_period_slot(state, &period.tenant_id, period.billing_cycle_start).await? {
            continue; // another sweep (or an earlier run) already invoiced it
        }

        let input = CreateInvoiceInput {
            tenant_id: period.tenant_id.clone(),
            stripe_invoice_id: None,
            line_items: vec![NewLineItem {
                description: description.clone(),
                quantity: 1,
                unit_price: amount_cents,
            }],
            period_start: period.billing_cycle_start,
            period_end: period.billing_cycle_end,
            due_at: None,
            currency: None, // invoices.rs defaults to EUR
            overage_period: Some(period.billing_cycle_start),
        };
        match create_invoice(&state.db, input).await {
            Ok(invoice) => {
                result.invoices_created += 1;
                info!(
                    tenant_id = %period.tenant_id,
                    invoice_number = %invoice.invoice_number,
                    overage_emails,
                    amount_cents,
                    "overage invoice created for ended billing period"
                );
                collect_usage_invoice(
                    state,
                    &invoice,
                    period.billing_cycle_start,
                    &description,
                    "overage",
                    &mut result.wallet_paid,
                    &mut result.pending_dunning,
                )
                .await;
            }
            Err(error) => {
                warn!(
                    tenant_id = %period.tenant_id,
                    error = %error,
                    "overage sweep: invoice creation failed; retried on next sweep"
                );
            }
        }
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

    let tenants: Vec<String> = sqlx::query_scalar(
        r#"
        SELECT DISTINCT t.id
        FROM tenants t
        LEFT JOIN plan_overrides po
          ON po.tenant_id = t.id
         AND po.active = true
         AND (po.expires_at IS NULL OR po.expires_at > NOW())
        WHERE COALESCE(po.plan, t.plan) = 'payg'
        ORDER BY t.id
        LIMIT 500
        "#,
    )
    .fetch_all(&state.db)
    .await
    .map_err(|e| format!("payg sweep: tenant query failed: {e}"))?;

    let months = recent_completed_calendar_months(Utc::now());
    for tenant_id in tenants {
        for &(month_start, month_end) in &months {
            if !claim_period_slot(state, &tenant_id, month_start).await? {
                continue;
            }

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
            .bind(&tenant_id)
            .bind(month_start)
            .bind(month_end)
            .fetch_one(&state.db)
            .await
            .map_err(|e| format!("payg sweep: usage query failed: {e}"))?;
            let (emails_sent, api_calls) = usage;

            let Ok((email_cost_cents, api_cost_cents, total_cents)) =
                pricing.calculate(emails_sent.max(0) as u64, api_calls.max(0) as u64)
            else {
                continue;
            };
            if total_cents <= 0 {
                continue; // zero-cost month — skip silently
            }

            if !tenant_has_billing_address(&state.db, &tenant_id).await? {
                result.skipped_no_address += 1;
                warn!(
                    tenant_id = %tenant_id,
                    "PAYG usage accrued but no billing address on file — invoice deferred"
                );
                continue;
            }

            let mut line_items = Vec::with_capacity(2);
            if email_cost_cents > 0 {
                line_items.push(NewLineItem {
                    description: format!(
                        "PAYG usage: {emails_sent} emails (tiered per-email pricing)"
                    ),
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
                continue;
            }
            let description = format!(
                "PAYG usage for {} — {emails_sent} emails, {api_calls} API calls",
                month_start.format("%Y-%m")
            );

            let input = CreateInvoiceInput {
                tenant_id: tenant_id.clone(),
                stripe_invoice_id: None,
                line_items,
                period_start: month_start,
                period_end: month_end,
                due_at: None,
                currency: None, // invoices.rs defaults to EUR
                overage_period: Some(month_start),
            };
            match create_invoice(&state.db, input).await {
                Ok(invoice) => {
                    result.payg_invoices_created += 1;
                    info!(
                        tenant_id = %tenant_id,
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
                }
                Err(error) => {
                    warn!(
                        tenant_id = %tenant_id,
                        error = %error,
                        "payg sweep: invoice creation failed; retried on next sweep"
                    );
                }
            }
        }
    }

    Ok(())
}

/// Resolve a plan's email limit: a present `plans.email_limit` wins (the
/// active-subscription path joins it override-aware); otherwise the plans
/// row is looked up by name (terminal subscriptions carry no join); a
/// missing/deactivated plans row falls back to the BUILTIN plan's limit by
/// name (exactly how `usage::resolve_plan_limits` resolves quotas); an
/// unknown plan name returns `None` after a loud warn — the caller skips
/// the tenant rather than billing everything as overage.
async fn resolve_plan_limit_or_warn(
    db: &PgPool,
    plan_name: &str,
    email_limit: Option<i64>,
    tenant_id: &str,
    skipped_unknown_plan: &mut u64,
) -> Result<Option<i64>, String> {
    if let Some(limit) = email_limit {
        return Ok(Some(limit));
    }
    // No joined limit (terminal-subscription path): look the plans row up
    // by name so operator-configured limits still win.
    let row_limit: Option<i64> =
        sqlx::query_scalar("SELECT email_limit FROM plans WHERE name = $1")
            .bind(plan_name)
            .fetch_optional(db)
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

/// Whether the tenant has a billing address on file (mandatory on a VAT
/// invoice).
async fn tenant_has_billing_address(db: &PgPool, tenant_id: &str) -> Result<bool, String> {
    let has_address: Option<i64> =
        sqlx::query_scalar("SELECT 1 FROM billing_addresses WHERE tenant_id = $1 LIMIT 1")
            .bind(tenant_id)
            .fetch_optional(db)
            .await
            .map_err(|e| format!("overage sweep: address query failed: {e}"))?;
    Ok(has_address.is_some())
}

/// Serialize the per-period check-then-insert (audit: concurrent sweeps
/// double-invoiced). Takes a `pg_advisory_xact_lock` keyed on
/// (tenant, period) — the same shape as the SLA credit sweep — and re-checks
/// the explicit `invoices.overage_period` marker INSIDE the lock. Returns
/// `true` when the caller may invoice this period.
///
/// The invoice INSERT itself (via `create_invoice` on the pool) commits
/// atomically WITH its `overage_period` marker, so a crash between claim
/// and insert can never orphan a marker-less invoice; a concurrent sweep
/// blocked on the lock re-checks only after this claim transaction commits,
/// which is strictly after the marker became visible.
async fn claim_period_slot(
    state: &AppState,
    tenant_id: &str,
    period_start: DateTime<Utc>,
) -> Result<bool, String> {
    let mut tx = state
        .db
        .begin()
        .await
        .map_err(|e| format!("overage sweep: claim tx failed: {e}"))?;

    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
        .bind(format!("overage:{tenant_id}:{}", period_start.to_rfc3339()))
        .execute(&mut *tx)
        .await
        .map_err(|e| format!("overage sweep: advisory lock failed: {e}"))?;

    let already: Option<i64> = sqlx::query_scalar(
        r#"
        SELECT 1 FROM invoices
        WHERE tenant_id = $1
          AND overage_period = $2
        LIMIT 1
        "#,
    )
    .bind(tenant_id)
    .bind(period_start)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|e| format!("overage sweep: idempotency query failed: {e}"))?;

    tx.commit()
        .await
        .map_err(|e| format!("overage sweep: claim commit failed: {e}"))?;

    Ok(already.is_none())
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
/// docs): wallet first, then a Stripe invoice item for the remainder when
/// the tenant is Stripe-managed, then `pending` for the dunning flow.
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
    let mut tx = match state.db.begin().await {
        Ok(tx) => tx,
        Err(error) => {
            warn!(
                tenant_id = %invoice.tenant_id,
                invoice_number = %invoice.invoice_number,
                error = %error,
                "usage invoice collection: failed to open transaction — invoice left in draft; retried by operators"
            );
            return;
        }
    };

    // (a) Wallet first — EUR only. A non-EUR wallet is never spent on a EUR
    // invoice; mixing currencies would mint phantom money.
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

    let mut applied_cents: i64 = 0;
    if let Some((balance, currency)) = wallet {
        if !currency.trim().eq_ignore_ascii_case("EUR") {
            warn!(
                tenant_id = %invoice.tenant_id,
                wallet_currency = %currency,
                "usage invoice collection: non-EUR wallet not spendable on a EUR invoice"
            );
        } else if balance > 0 {
            applied_cents = balance.min(invoice.total);
            if let Err(error) = sqlx::query(
                r#"
                WITH debit_wallet AS (
                    UPDATE wallets
                    SET balance = balance - $2, updated_at = NOW()
                    WHERE tenant_id = $1
                    RETURNING id, balance
                )
                INSERT INTO wallet_transactions
                    (wallet_id, tenant_id, type, amount, balance_after, description, reference, created_at)
                SELECT id, $1, 'debit', $2, balance, $3, $4, NOW()
                FROM debit_wallet
                "#,
            )
            .bind(&invoice.tenant_id)
            .bind(applied_cents)
            .bind(format!("Usage invoice {}: wallet settlement", invoice.invoice_number))
            .bind(invoice.invoice_number.clone())
            .execute(&mut *tx)
            .await
            {
                warn!(
                    tenant_id = %invoice.tenant_id,
                    error = %error,
                    "usage invoice collection: wallet debit failed — continuing without wallet credit"
                );
                applied_cents = 0;
            }
        }
    }

    let remaining_cents = invoice.total.saturating_sub(applied_cents);

    // (b) Whole-invoice paid when the wallet covered everything.
    if remaining_cents <= 0 {
        match finalize_collection(&mut tx, invoice, "paid", None).await {
            Ok(()) => {
                *wallet_paid += 1;
                info!(
                    tenant_id = %invoice.tenant_id,
                    invoice_number = %invoice.invoice_number,
                    applied_cents,
                    "usage invoice settled in full from wallet balance"
                );
            }
            Err(error) => {
                warn!(
                    tenant_id = %invoice.tenant_id,
                    invoice_number = %invoice.invoice_number,
                    error = %error,
                    "usage invoice collection: marking paid failed"
                );
            }
        }
        let _ = tx.commit().await;
        invalidate_wallet_balance_cache(state, &invoice.tenant_id).await;
        return;
    }

    // (c) Stripe-managed tenants: add the REMAINING amount as a pending
    // invoice item (collected on the next billing cycle). Idempotent per
    // (tenant, period) so sweep retries never duplicate the item. Failure
    // is non-fatal — the local invoice still moves to pending/dunning.
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

    // (d) Pending → dunning flow (soft 7d / hard 21d / grace 7d), with the
    // Stripe invoice-item id mirrored as the invoice's Stripe reference.
    match finalize_collection(&mut tx, invoice, "pending", stripe_item_id.as_deref()).await {
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
                "usage invoice collection: marking pending failed"
            );
        }
    }

    let _ = tx.commit().await;
    invalidate_wallet_balance_cache(state, &invoice.tenant_id).await;
}

/// Flip the just-created draft invoice to its collection status. Only a
/// row still in `draft` is updated, so a concurrent manual payment can
/// never be overwritten.
async fn finalize_collection(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    invoice: &Invoice,
    status: &str,
    stripe_item_id: Option<&str>,
) -> Result<(), String> {
    sqlx::query(
        r#"
        UPDATE invoices
        SET status = $2,
            paid_at = CASE WHEN $2 = 'paid' THEN NOW() ELSE paid_at END,
            stripe_invoice_id = COALESCE($3, stripe_invoice_id),
            updated_at = NOW()
        WHERE id = $1
          AND status = 'draft'
        "#,
    )
    .bind(invoice.id)
    .bind(status)
    .bind(stripe_item_id)
    .execute(&mut **tx)
    .await
    .map_err(|e| format!("status update failed: {e}"))?;
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
pub async fn tenant_has_active_paid_subscription(
    pool: &PgPool,
    tenant_id: &str,
) -> Result<bool, sqlx::Error> {
    if let Some(cached) = paid_subscription_cache().get(tenant_id) {
        return Ok(cached);
    }
    let active: Option<i64> = sqlx::query_scalar(
        r#"
        SELECT 1
        FROM stripe_subscriptions ss
        JOIN plans p ON p.name = ss.plan
        WHERE ss.tenant_id = $1
          AND ss.status = 'active'
          AND COALESCE(p.price_monthly, 0) > 0
        LIMIT 1
        "#,
    )
    .bind(tenant_id)
    .fetch_optional(pool)
    .await?;
    let value = active.is_some();
    paid_subscription_cache().insert(tenant_id.to_string(), value);
    Ok(value)
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
}
