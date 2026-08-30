//! Subscription overage: soft-limit enforcement plus end-of-period invoicing.
//!
//! Published behaviour (docs/pricing.md, marketing pricing FAQ): a paid plan
//! is NOT hard-blocked at its included volume — sending continues into an
//! overage allowance and the extra volume is invoiced at €0.40 per 1,000
//! emails when the billing period ends. The enforcement half lives in
//! `usage::record_with_quota_check` (which passes the ceiling below to the
//! Redis quota Lua); this module implements the ceiling math and the daily
//! sweep that turns accrued overage into an invoice line item.

use crate::invoices::{create_invoice, CreateInvoiceInput, NewLineItem};
use crate::plans;
use crate::AppState;
use chrono::{DateTime, Utc};
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

/// End-of-period overage invoicing switch (`OVERAGE_INVOICING_ENABLED`,
/// default on). Enforcement is independent: the ceiling above always lets
/// paid tenants cross the plan boundary; this only controls whether the
/// accrued overage is invoiced by the sweep.
pub fn overage_invoicing_enabled() -> bool {
    std::env::var("OVERAGE_INVOICING_ENABLED")
        .map(|v| v != "false" && v != "0")
        .unwrap_or(true)
}

/// Overage rate: 40 millicents per email (€0.40 per 1,000). Mirrors
/// `plans::DEFAULT_OVERAGE_RATE_MILLICENTS`.
const OVERAGE_RATE_MILLICENTS: i64 = plans::DEFAULT_OVERAGE_RATE_MILLICENTS;

#[derive(Debug, Default)]
pub struct OverageSweepResult {
    pub periods_checked: u64,
    pub invoices_created: u64,
    pub skipped_no_address: u64,
    pub skipped_no_overage: u64,
}

/// A billing period that has ended and may carry overage.
#[derive(sqlx::FromRow)]
struct EndedPeriodRow {
    tenant_id: String,
    billing_cycle_start: DateTime<Utc>,
    billing_cycle_end: DateTime<Utc>,
}

/// Daily sweep: for every recently-ended billing cycle of an active paid
/// subscription, compute metered `emails_sent` beyond the plan limit and
/// create the overage invoice. Idempotent per (tenant, period): a period
/// with an existing overage invoice is skipped, so re-runs after downtime
/// are safe. The lookback window covers the metering TTL (40 days).
pub async fn sweep_period_overage(state: &AppState) -> Result<OverageSweepResult, String> {
    if !overage_invoicing_enabled() {
        info!("overage invoicing disabled (OVERAGE_INVOICING_ENABLED=false)");
        return Ok(OverageSweepResult::default());
    }

    let mut result = OverageSweepResult::default();
    let periods: Vec<EndedPeriodRow> = sqlx::query_as(
        r#"
        SELECT tenant_id, billing_cycle_start, billing_cycle_end
        FROM stripe_subscriptions
        WHERE status = 'active'
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

        // Idempotency: one overage invoice per tenant per period.
        let already: Option<i64> = sqlx::query_scalar(
            r#"
            SELECT 1 FROM invoices
            WHERE tenant_id = $1
              AND period_start = $2
              AND period_end = $3
              AND line_items::text LIKE '%Overage:%'
            LIMIT 1
            "#,
        )
        .bind(&period.tenant_id)
        .bind(period.billing_cycle_start)
        .bind(period.billing_cycle_end)
        .fetch_optional(&state.db)
        .await
        .map_err(|e| format!("overage sweep: idempotency query failed: {e}"))?;
        if already.is_some() {
            continue;
        }

        // Plan limit at the tenant level (override-aware, same source as the
        // enforcement gate).
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

        let (plan_name, email_limit) = match limit_row {
            Some((plan_name, email_limit)) => (plan_name, email_limit),
            None => {
                warn!(tenant_id = %period.tenant_id, "overage sweep: tenant row missing; skipping period");
                continue;
            }
        };
        let plan_limit = email_limit.unwrap_or(0);
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
        let has_address: Option<i64> =
            sqlx::query_scalar("SELECT 1 FROM billing_addresses WHERE tenant_id = $1 LIMIT 1")
                .bind(&period.tenant_id)
                .fetch_optional(&state.db)
                .await
                .map_err(|e| format!("overage sweep: address query failed: {e}"))?;
        if has_address.is_none() {
            result.skipped_no_address += 1;
            warn!(
                tenant_id = %period.tenant_id,
                overage_emails,
                "overage accrued but no billing address on file — invoice deferred"
            );
            continue;
        }

        let amount_cents =
            plans::calculate_overage_cost_with_rate(sent, plan_limit, OVERAGE_RATE_MILLICENTS);
        if amount_cents <= 0 {
            result.skipped_no_overage += 1;
            continue;
        }

        let input = CreateInvoiceInput {
            tenant_id: period.tenant_id.clone(),
            stripe_invoice_id: None,
            line_items: vec![NewLineItem {
                description: format!(
                    "Overage: {overage_emails} emails beyond the {plan_name} plan limit ({plan_limit}/cycle), at €0.40 per 1,000"
                ),
                quantity: 1,
                unit_price: amount_cents,
            }],
            period_start: period.billing_cycle_start,
            period_end: period.billing_cycle_end,
            due_at: None,
            currency: None, // invoices.rs defaults to EUR
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

    Ok(result)
}

/// Pure helper for the enforcement gate in usage.rs: the quota value to pass
/// to the Redis Lua for this event, given the plan limit and the tenant's
/// subscription state. Email sending on an active paid subscription uses the
/// overage ceiling; everything else (API calls, free/trial/no-subscription
/// tenants, unlimited plans) keeps its raw limit.
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

/// Whether the tenant currently has an active paid subscription (status
/// active/trialing on a priced plan). Cached briefly — used per-send by the
/// quota gate.
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
          AND ss.status IN ('active', 'trialing')
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
        // free / trialing-without-subscription / cancelled: hard plan limit
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
}
