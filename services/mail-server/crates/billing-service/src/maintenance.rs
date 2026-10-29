use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use billing_common::cost_throttle::{
    cost_throttle_key, CostThrottleOverride, COST_THROTTLE_TTL_SECS,
};
use chrono::{DateTime, Datelike, Timelike, Utc};
use redis::AsyncCommands;
use reqwest::Client;
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sqlx::{Connection, FromRow, PgPool, Postgres, QueryBuilder};
use tokio::time::{interval_at, Instant, MissedTickBehavior};
use tracing::{error, info, warn};
use uuid::Uuid;

use crate::routes::append_audit_log;
use crate::usage::build_metering_audit_metadata;
use crate::vat_emta::{EmtaClient, EmtaConfig};
use crate::AppState;

const HOURLY_TASK_INTERVAL: Duration = Duration::from_secs(60 * 60);
const DEDICATED_IP_TASK_INTERVAL: Duration = Duration::from_secs(30);
const METERING_TASK_INTERVAL: Duration = Duration::from_secs(60);
const USAGE_ALERT_TASK_INTERVAL: Duration = Duration::from_secs(5 * 60);
const COST_MARGIN_TASK_INTERVAL: Duration = Duration::from_secs(15 * 60);
const MANDATE_REVOCATION_TASK_INTERVAL: Duration = Duration::from_secs(15 * 60);
/// Audit gate E (step 8): how often open payment attempts are re-fetched
/// from the provider and driven through the verify-then-settle core, so a
/// missed webhook can never strand a paid charge.
const PAYMENT_ATTEMPT_REPAIR_TASK_INTERVAL: Duration = Duration::from_secs(5 * 60);
const DAILY_TASK_INTERVAL: Duration = Duration::from_secs(24 * 60 * 60);
const METERING_SCAN_COUNT: usize = 200;
const METERING_RECOVERY_LIMIT: usize = 10_000;
const METERING_PERIOD_TTL_SECONDS: i64 = 40 * 86_400;
const USAGE_ALERT_COOLDOWN_SECONDS: u64 = 60 * 60;
const COST_MARGIN_WARNING_THRESHOLD: f64 = 20.0;
const COST_MARGIN_CRITICAL_THRESHOLD: f64 = 10.0;
const SLA_AVAILABILITY_TARGET: f64 = 99.9;
const KMD_GENERATION_INTERVAL: Duration = Duration::from_secs(6 * 60 * 60); // Every 6 hours
const INVOICE_ARCHIVE_INTERVAL: Duration = Duration::from_secs(24 * 60 * 60); // Daily
/// `cleanup_outbound_throttle_decisions` retention (migration 066's
/// documented default).
const OUTBOUND_THROTTLE_RETENTION_DAYS: i32 = 90;
/// Derived-usage sweep starts 90 minutes past the hour after startup: late
/// enough for the day to be firmly closed and other daily jobs to settle,
/// soon enough to land before the reconciliation report is read.
const DERIVED_USAGE_SWEEP_INITIAL_DELAY: Duration = Duration::from_secs(90 * 60);

/// Operational override for the periodic-task intervals above. When set,
/// EVERY loop ticks on this many milliseconds instead of its production
/// cadence, so integration tests (and ops smoke-checks) can drive the real
/// spawned loops in milliseconds. Unset keeps the production intervals.
fn task_interval(default: Duration) -> Duration {
    std::env::var("PERIODIC_TASK_INTERVAL_MS")
        .ok()
        .and_then(|value| value.trim().parse::<u64>().ok())
        .map(|ms| Duration::from_millis(ms.max(10)))
        .unwrap_or(default)
}

static DEDICATED_IP_TABLE_MISSING_LOGGED: AtomicBool = AtomicBool::new(false);

/// Run the canonical end-of-period overage + PAYG sweep ONCE against the
/// live database, log the outcome and return it.
///
/// E-SWEEP-TRIGGER (live dogfood 2026-10-08): the scheduled sweep's FIRST
/// tick is the next UTC midnight (`next_day_start`) and no on-demand trigger
/// existed anywhere, so an operator could not close a period without waiting
/// for midnight or running the undeployed billing-service binary by hand.
/// This is the on-demand entrypoint; `bin/server.rs` exposes it as the
/// one-shot `--sweep-overage-only` CLI (the `--reconcile-plans-only` ops
/// pattern), and the nightly loop calls the SAME function, one code path,
/// one behavior.
pub async fn sweep_overage_once(
    state: &AppState,
) -> Result<crate::overage::OverageSweepResult, String> {
    let result = crate::overage::sweep_period_overage(state).await?;
    if result.invoices_created > 0
        || result.payg_invoices_created > 0
        || result.skipped_no_address > 0
        || result.skipped_unknown_plan > 0
    {
        info!(
            periods_checked = result.periods_checked,
            invoices_created = result.invoices_created,
            payg_invoices_created = result.payg_invoices_created,
            wallet_paid = result.wallet_paid,
            pending_dunning = result.pending_dunning,
            deferred_no_address = result.skipped_no_address,
            skipped_unknown_plan = result.skipped_unknown_plan,
            failed_periods = result.failed_periods,
            oldest_unresolved_age_secs = ?result.oldest_unresolved_age_secs,
            aged_needs_review = result.aged_needs_review,
            pricing_needs_review = result.pricing_needs_review,
            "processed period usage invoices"
        );
    } else if result.failed_periods > 0 {
        warn!(
            failed_periods = result.failed_periods,
            oldest_unresolved_age_secs = ?result.oldest_unresolved_age_secs,
            "period overage sweep finished with isolated period failures, recorded with backoff"
        );
    }
    Ok(result)
}

/// The monthly contract product-line sweep (Platform + Mailboxes), wired
/// exactly like [`sweep_overage_once`]: the nightly loop calls the SAME
/// function the one-shot
/// `--sweep-product-lines-only` CLI trigger runs, so an operator can close a
/// contract month on demand and the two paths can never drift. Idempotent
/// per (tenant, line, month), a replay adopts the existing invoice.
pub async fn sweep_product_lines_once(
    state: &AppState,
) -> Result<crate::product_lines::ProductLineSweepResult, String> {
    let result = crate::product_lines::sweep_product_line_months(state).await?;
    if result.invoices_created > 0
        || result.months_already_invoiced > 0
        || result.skipped_no_address > 0
        || result.periods_needs_review > 0
        || result.failed_months > 0
    {
        info!(
            tenants_checked = result.tenants_checked,
            tenant_months_checked = result.tenant_months_checked,
            invoices_created = result.invoices_created,
            periods_invoiced = result.periods_invoiced,
            months_already_invoiced = result.months_already_invoiced,
            periods_already_terminal = result.periods_already_terminal,
            deferred_no_address = result.skipped_no_address,
            periods_needs_review = result.periods_needs_review,
            wallet_paid = result.wallet_paid,
            pending_dunning = result.pending_dunning,
            failed_months = result.failed_months,
            "processed contract product-line invoices"
        );
    }
    Ok(result)
}

/// The US sales-tax nexus sweep (plan WP C2), wired exactly like
/// [`sweep_product_lines_once`]: the nightly loop calls the SAME function the
/// one-shot `--sweep-us-tax-nexus-only` CLI trigger runs. It only TRACKS and
/// ALERTS (once per state per window): registration is an owner/accounting
/// act through the admin surface, and the sweep never charges tax.
pub async fn sweep_us_tax_nexus_once(
    state: &AppState,
) -> Result<crate::us_tax::UsTaxSweepResult, String> {
    let result = crate::us_tax::sweep_us_tax_nexus(state).await?;
    if result.needs_attention() {
        info!(
            states_evaluated = result.states_evaluated,
            states_below = result.states_below,
            states_crossed = result.states_crossed,
            states_registered = result.states_registered,
            states_not_taxable = ?result.states_not_taxable,
            alerts_raised = result.alerts_raised,
            warnings_raised = result.warnings_raised,
            states_warned = result.states_warned,
            without_threshold_data = ?result.states_without_threshold_data,
            invalid_nexus_declarations = ?result.states_invalid_nexus,
            unknown_state_invoices = result.unknown_state_invoices,
            unknown_state_cents = result.unknown_state_cents,
            non_usd_invoices = ?result.non_usd_invoices,
            failed_states = result.failed_states,
            "processed US sales-tax nexus thresholds"
        );
    }
    Ok(result)
}

/// Enforce the documented retention of `outbound_throttle_decisions`
/// (migration 066). A missing table/function is harmless (the SQL function
/// returns 0); any other failure is logged and retried on the next run.
async fn run_throttle_retention(db: &PgPool) {
    match sqlx::query_scalar::<_, i64>("SELECT cleanup_outbound_throttle_decisions($1)")
        .bind(OUTBOUND_THROTTLE_RETENTION_DAYS)
        .fetch_one(db)
        .await
    {
        Ok(deleted) if deleted > 0 => info!(
            deleted,
            retention_days = OUTBOUND_THROTTLE_RETENTION_DAYS,
            "pruned old outbound throttle decisions"
        ),
        Ok(_) => {}
        Err(error) => error!(
            error = %error,
            "failed to prune outbound throttle decisions"
        ),
    }
}

pub fn start_periodic_jobs(state: std::sync::Arc<AppState>) {
    let dedicated_ip_state = state.clone();
    tokio::spawn(async move {
        let client = Client::new();

        match process_dedicated_ip_billing(dedicated_ip_state.as_ref(), &client).await {
            Ok(result) if result.charged > 0 || result.canceled > 0 => {
                info!(
                    charged = result.charged,
                    canceled = result.canceled,
                    "processed dedicated IP billing sync on startup"
                );
            }
            Ok(_) => {}
            Err(error_message) => {
                error!(error = %error_message, "failed to process dedicated IP billing sync on startup");
            }
        }

        let mut interval = interval_at(
            Instant::now() + task_interval(DEDICATED_IP_TASK_INTERVAL),
            task_interval(DEDICATED_IP_TASK_INTERVAL),
        );
        interval.set_missed_tick_behavior(MissedTickBehavior::Skip);

        loop {
            interval.tick().await;

            match process_dedicated_ip_billing(dedicated_ip_state.as_ref(), &client).await {
                Ok(result) if result.charged > 0 || result.canceled > 0 => {
                    info!(
                        charged = result.charged,
                        canceled = result.canceled,
                        "processed dedicated IP billing sync"
                    );
                }
                Ok(_) => {}
                Err(error_message) => {
                    error!(error = %error_message, "failed to process dedicated IP billing sync");
                }
            }
        }
    });

    // Provider subscription state is reconciled from authenticated fetches:
    // only an ACTIVE Mollie subscription grants the plan, and an amount that
    // drifted from the catalog is a finance incident.
    let subscription_state = state.clone();
    tokio::spawn(async move {
        let mut interval = interval_at(
            Instant::now() + task_interval(HOURLY_TASK_INTERVAL),
            task_interval(HOURLY_TASK_INTERVAL),
        );
        interval.set_missed_tick_behavior(MissedTickBehavior::Skip);
        loop {
            interval.tick().await;
            match crate::plan_billing::sweep_provider_subscription_state(&subscription_state.db)
                .await
            {
                Ok(0) => {}
                Ok(reconciled) => info!(reconciled, "reconciled Mollie subscription state"),
                Err(error) => error!(error = %error, "Mollie subscription reconciliation failed"),
            }
        }
    });

    // Provider-side mandate revocation: a canceled account must not remain
    // chargeable at Mollie. The cancel path attempts the DELETE immediately;
    // this sweep retries every tenant whose revocation is still outstanding
    // (the `mandate_revoked_at` NULL marker).
    // Audit gate E (step 8): the generic repair sweep. Every open payment
    // attempt is re-fetched WITH PROVIDER AUTHENTICATION and driven through
    // the SAME observe -> verify -> settle core the webhook uses; a missed
    // webhook settles the obligation on the next pass instead of stranding
    // a paid charge.
    let repair_state = state.clone();
    tokio::spawn(async move {
        let mut interval = interval_at(
            Instant::now() + task_interval(PAYMENT_ATTEMPT_REPAIR_TASK_INTERVAL),
            task_interval(PAYMENT_ATTEMPT_REPAIR_TASK_INTERVAL),
        );
        interval.set_missed_tick_behavior(MissedTickBehavior::Skip);
        loop {
            interval.tick().await;
            match crate::payments::engine::sweep_open_attempts(&repair_state).await {
                Ok(stats) if stats == crate::payments::engine::AttemptSweepStats::default() => {}
                Ok(stats) => info!(
                    examined = stats.examined,
                    settled = stats.settled,
                    closed_failed = stats.closed_failed,
                    "payment attempt repair sweep completed"
                ),
                Err(error) => error!(error = %error, "payment attempt repair sweep failed"),
            }
        }
    });

    let mandate_state = state.clone();
    tokio::spawn(async move {
        let mut interval = interval_at(
            Instant::now() + task_interval(MANDATE_REVOCATION_TASK_INTERVAL),
            task_interval(MANDATE_REVOCATION_TASK_INTERVAL),
        );
        interval.set_missed_tick_behavior(MissedTickBehavior::Skip);
        loop {
            interval.tick().await;
            match crate::subscriptions::sweep_pending_mandate_revocations(&mandate_state.db).await {
                Ok(0) => {}
                Ok(revoked) => info!(revoked, "revoked pending Mollie mandates"),
                Err(error) => error!(error = %error, "mandate revocation sweep failed"),
            }
        }
    });

    let metering_state = state.clone();
    tokio::spawn(async move {
        // Startup drain with monitoring (metrics + alerting)
        let _ = crate::metering_monitor::monitored_drain_pending_events(
            metering_state.as_ref(),
            METERING_RECOVERY_LIMIT,
        )
        .await;

        let mut interval = interval_at(
            Instant::now() + task_interval(METERING_TASK_INTERVAL),
            task_interval(METERING_TASK_INTERVAL),
        );
        interval.set_missed_tick_behavior(MissedTickBehavior::Skip);

        loop {
            interval.tick().await;

            // Monitored drain, records histograms, counters, and
            // triggers consecutive-error alert if threshold is exceeded.
            let _ = crate::metering_monitor::monitored_drain_pending_events(
                metering_state.as_ref(),
                METERING_RECOVERY_LIMIT,
            )
            .await;

            // Stale-event check, updates pending-event gauge and
            // warns if events remain undrained past the age limit.
            crate::metering_monitor::check_stale_pending_events(metering_state.as_ref()).await;
        }
    });

    // F8 (audit): the expired-wallet-reservation sweep was REMOVED here. No
    // production code path ever wrote a `wallet_reservations` row (only test
    // fixtures did) and nothing ever incremented `wallets.reserved`, so the
    // loop could never release anything, it ran every 30 minutes against a
    // table that is structurally always empty for a claim ("funds are held
    // until capture") the product does not implement. The live wallet flow
    // is direct debit/top-up through `wallet_transactions` (see
    // `expire_stale_wallet_credits` below, which IS live); the reservation
    // model was removed with the sweep rather than implying an isolation
    // guarantee no code provides.

    let usage_alert_state = state.clone();
    tokio::spawn(async move {
        let client = Client::new();
        let mut interval = interval_at(
            Instant::now() + task_interval(USAGE_ALERT_TASK_INTERVAL),
            task_interval(USAGE_ALERT_TASK_INTERVAL),
        );
        interval.set_missed_tick_behavior(MissedTickBehavior::Skip);

        loop {
            interval.tick().await;

            match process_usage_alerts(usage_alert_state.as_ref(), &client).await {
                Ok(result) if result.tenants_checked > 0 || result.alerts_triggered > 0 => {
                    info!(
                        tenants_checked = result.tenants_checked,
                        alerts_triggered = result.alerts_triggered,
                        "processed usage alerts"
                    );
                }
                Ok(_) => {}
                Err(error_message) => {
                    error!(error = %error_message, "failed to process usage alerts");
                }
            }
        }
    });

    let cost_margin_state = state.clone();
    tokio::spawn(async move {
        let mut interval = interval_at(
            Instant::now() + task_interval(COST_MARGIN_TASK_INTERVAL),
            task_interval(COST_MARGIN_TASK_INTERVAL),
        );
        interval.set_missed_tick_behavior(MissedTickBehavior::Skip);

        loop {
            interval.tick().await;

            match process_cost_margin_checks(cost_margin_state.as_ref()).await {
                Ok(result) if result.checked > 0 || result.warnings > 0 || result.critical > 0 => {
                    info!(
                        checked = result.checked,
                        warnings = result.warnings,
                        critical = result.critical,
                        "processed tenant cost margin checks"
                    );
                }
                Ok(_) => {}
                Err(error_message) => {
                    error!(error = %error_message, "failed to process tenant cost margin checks");
                }
            }
        }
    });

    let sla_state = state.clone();
    tokio::spawn(async move {
        match process_monthly_sla_credits(sla_state.as_ref()).await {
            Ok(result) if result.tenants_checked > 0 || result.credits_created > 0 => {
                info!(
                    tenants_checked = result.tenants_checked,
                    credits_created = result.credits_created,
                    "processed monthly SLA credits on startup"
                );
            }
            Ok(_) => {}
            Err(error_message) => {
                error!(error = %error_message, "failed to process monthly SLA credits on startup");
            }
        }

        let next_run = next_day_start(Utc::now());
        let initial_delay = (next_run - Utc::now())
            .to_std()
            .unwrap_or(task_interval(DAILY_TASK_INTERVAL));
        let mut interval = interval_at(
            Instant::now() + initial_delay,
            task_interval(DAILY_TASK_INTERVAL),
        );
        interval.set_missed_tick_behavior(MissedTickBehavior::Skip);

        loop {
            interval.tick().await;

            match process_monthly_sla_credits(sla_state.as_ref()).await {
                Ok(result) if result.tenants_checked > 0 || result.credits_created > 0 => {
                    info!(
                        tenants_checked = result.tenants_checked,
                        credits_created = result.credits_created,
                        "processed monthly SLA credits"
                    );
                }
                Ok(_) => {}
                Err(error_message) => {
                    error!(error = %error_message, "failed to process monthly SLA credits");
                }
            }

            // End-of-period overage + PAYG invoicing (idempotent per
            // tenant+period; paid subscriptions may send into an overage
            // allowance, see usage::record_with_quota_check and the
            // overage module). Every created invoice is COLLECTED: wallet
            // first, then Mollie invoice item / dunning (see overage.rs).
            match sweep_overage_once(sla_state.as_ref()).await {
                Ok(_) => {}
                Err(error_message) => {
                    error!(error = %error_message, "failed to sweep period overage");
                }
            }

            // Contract product-line invoices (Platform + Mailboxes),
            // idempotent per (tenant, line, month); one invoice per tenant
            // per month across the lines, collected through the same
            // ladder as the overage sweep (see product_lines.rs).
            match sweep_product_lines_once(sla_state.as_ref()).await {
                Ok(_) => {}
                Err(error_message) => {
                    error!(error = %error_message, "failed to sweep contract product lines");
                }
            }

            // US sales-tax economic-nexus thresholds (plan WP C2): tracks
            // taxable US sales per state and raises ONE operator alert per
            // crossing. Never registers, never charges, registration is an
            // owner/accounting action (see us_tax.rs).
            match sweep_us_tax_nexus_once(sla_state.as_ref()).await {
                Ok(_) => {}
                Err(error_message) => {
                    error!(error = %error_message, "failed to sweep US sales-tax nexus");
                }
            }

            // ToS 6.4 wallet-credit expiry (12 months), see
            // expire_stale_wallet_credits.
            match expire_stale_wallet_credits(sla_state.as_ref()).await {
                Ok(expired) if expired > 0 => {
                    info!(expired, "expired stale wallet credits per ToS 6.4");
                }
                Ok(_) => {}
                Err(error_message) => {
                    error!(error = %error_message, "failed to expire stale wallet credits");
                }
            }
        }
    });

    let grace_state = state.clone();
    tokio::spawn(async move {
        let client = Client::new();
        let mut interval = interval_at(
            Instant::now() + task_interval(HOURLY_TASK_INTERVAL),
            task_interval(HOURLY_TASK_INTERVAL),
        );
        interval.set_missed_tick_behavior(MissedTickBehavior::Skip);

        loop {
            interval.tick().await;

            match process_grace_period_expirations(grace_state.as_ref(), 100).await {
                Ok(result) if result.processed_count > 0 || result.purged_messages_count > 0 => {
                    info!(
                        processed_count = result.processed_count,
                        purged_messages_count = result.purged_messages_count,
                        "processed expired dunning grace periods"
                    );
                }
                Ok(_) => {}
                Err(error_message) => {
                    error!(error = %error_message, "failed to process dunning grace periods");
                }
            }

            match process_scheduled_retries(grace_state.as_ref(), &client).await {
                Ok(result) if result.attempted > 0 => {
                    info!(
                        attempted = result.attempted,
                        succeeded = result.succeeded,
                        "processed scheduled Mollie retries"
                    );
                }
                Ok(_) => {}
                Err(error_message) => {
                    error!(error = %error_message, "failed to process scheduled Mollie retries");
                }
            }

            // Audit F33, resume stranded usage-invoice collection
            // operations (invoice created, collection interrupted): the
            // idempotent ladder re-runs wallet application, the finalized
            // Mollie invoice and the dunning handoff until the outbox row
            // is done. Exhausted attempts dead-letter visibly.
            match crate::overage::resume_pending_collections(grace_state.as_ref()).await {
                Ok(stats) if stats.resumed > 0 || stats.dead_lettered > 0 => {
                    info!(
                        resumed = stats.resumed,
                        dead_lettered = stats.dead_lettered,
                        "resumed stranded usage invoice collections"
                    );
                }
                Ok(_) => {}
                Err(error_message) => {
                    error!(error = %error_message, "failed to resume usage invoice collections");
                }
            }

            // Audit F66, the hourly subscription_change_saga cleanup job was
            // removed: no migration or writer ever created that table (every
            // run failed with 42P01). Subscription-change persistence and
            // recovery are the canonical mollie_webhook_events store
            // (migrations 127/128) plus the deadletter retry ladder, there
            // is no separate saga to clean up.
        }
    });

    // ── Mollie webhook stale-pending reclaim (startup + hourly, Fix G) ──
    let webhook_state = state.clone();
    tokio::spawn(async move {
        match crate::mollie_webhooks::reclaim_stale_pending_webhooks(webhook_state.as_ref()).await {
            Ok(reclaimed) if !reclaimed.is_empty() => {
                info!(
                    count = reclaimed.len(),
                    "reclaimed stale pending mollie webhooks on startup"
                );
            }
            Ok(_) => {}
            Err(error_message) => {
                error!(error = %error_message, "failed to reclaim stale pending mollie webhooks on startup");
            }
        }

        let mut interval = interval_at(
            Instant::now() + task_interval(HOURLY_TASK_INTERVAL),
            task_interval(HOURLY_TASK_INTERVAL),
        );
        interval.set_missed_tick_behavior(MissedTickBehavior::Skip);

        loop {
            interval.tick().await;

            match crate::mollie_webhooks::reclaim_stale_pending_webhooks(webhook_state.as_ref())
                .await
            {
                Ok(reclaimed) if !reclaimed.is_empty() => {
                    info!(
                        count = reclaimed.len(),
                        "reclaimed stale pending mollie webhooks"
                    );
                }
                Ok(_) => {}
                Err(error_message) => {
                    error!(error = %error_message, "failed to reclaim stale pending mollie webhooks");
                }
            }
        }
    });

    // ── KMD VAT return generation (every 6 hours) ──────────────
    let kmd_state = state.clone();
    tokio::spawn(async move {
        let mut interval = interval_at(
            Instant::now() + task_interval(KMD_GENERATION_INTERVAL),
            task_interval(KMD_GENERATION_INTERVAL),
        );
        interval.set_missed_tick_behavior(MissedTickBehavior::Skip);

        // Build EMTA client once (loads config from environment variables).
        // Enabled clients validate mTLS paths immediately; invalid EMTA setup
        // is logged and filing is skipped until configuration is fixed.
        let emta_config = EmtaConfig::from_env();
        let emta_client = match EmtaClient::from_config(emta_config.clone()) {
            Ok(client) => client,
            Err(error) => {
                error!(error = %error, "invalid EMTA configuration; electronic KMD filing disabled");
                EmtaClient::new(
                    EmtaConfig {
                        enabled: false,
                        ..emta_config
                    },
                    reqwest::Client::builder()
                        .timeout(std::time::Duration::from_secs(30))
                        .build()
                        .expect("Client::builder with only timeout should never fail"),
                )
            }
        };

        loop {
            interval.tick().await;

            // F7 (audit): the third-month fallback for cash-accounting
            // (`cash_special`) VAT. `materialize_due_cash_special` used to
            // have no caller while mollie_webhooks.rs claimed "the sweep"
            // handled it, an invoice that stayed unpaid past the third
            // month never materialized its `cash_special_due` recognition
            // entry, so the KMD aggregation silently omitted that output
            // VAT. Run it BEFORE the return generation so the period being
            // filed includes the entries.
            match crate::vat_recognition::materialize_due_cash_special(&kmd_state.db, Utc::now())
                .await
            {
                Ok(materialized) if materialized > 0 => {
                    info!(
                        materialized,
                        "materialized third-month cash-accounting VAT recognition entries"
                    );
                }
                Ok(_) => {}
                Err(error) => {
                    error!(
                        error = %error,
                        "cash-accounting third-month recognition sweep failed"
                    );
                }
            }

            match generate_kmd_if_due(kmd_state.as_ref()).await {
                Ok(results) => {
                    for result in results {
                        info!(
                            tax_year = result.tax_year,
                            tax_month = result.tax_month,
                            invoice_count = result.invoice_count,
                            total_vat_cents = result.total_vat_cents,
                            "KMD VAT return generated for previous month"
                        );

                        // Attempt electronic filing via EMTA (e-MTA) if configured.
                        if emta_client.is_ready() {
                            match attempt_emta_filing(&kmd_state.db, &emta_client, &result).await {
                                Ok(Some(filing)) => {
                                    info!(
                                        tax_year = result.tax_year,
                                        tax_month = result.tax_month,
                                        filing_reference = ?filing.filing_reference,
                                        accepted = filing.accepted,
                                        "KMD VAT return filed with EMTA"
                                    );
                                }
                                Ok(None) => {
                                    info!(
                                        tax_year = result.tax_year,
                                        tax_month = result.tax_month,
                                        "KMD VAT return already filed with EMTA; skipping"
                                    );
                                }
                                Err(e) => {
                                    error!(
                                        error = %e,
                                        tax_year = result.tax_year,
                                        tax_month = result.tax_month,
                                        "EMTA filing failed"
                                    );
                                }
                            }
                        } else {
                            info!("EMTA client not ready (disabled or misconfigured); skipping electronic filing");
                        }
                    }
                }
                Err(error_message) => {
                    error!(error = %error_message, "KMD VAT return generation failed");
                }
            }
        }
    });

    // ── Invoice archival (daily) ──────────────────────────────
    let archive_state = state.clone();
    tokio::spawn(async move {
        // Run once on startup
        match archive_paid_invoices(archive_state.as_ref()).await {
            Ok(n) if n > 0 => info!(archived = n, "archived invoices on startup"),
            Ok(_) => {}
            Err(e) => error!(error = %e, "invoice archival on startup failed"),
        }

        let mut interval = interval_at(
            Instant::now() + task_interval(INVOICE_ARCHIVE_INTERVAL),
            task_interval(INVOICE_ARCHIVE_INTERVAL),
        );
        interval.set_missed_tick_behavior(MissedTickBehavior::Skip);

        loop {
            interval.tick().await;

            match archive_paid_invoices(archive_state.as_ref()).await {
                Ok(n) if n > 0 => info!(archived = n, "archived paid invoices"),
                Ok(_) => {}
                Err(e) => error!(error = %e, "invoice archival failed"),
            }
        }
    });

    // ── Provider throttle audit retention (daily) ──────────────
    // `cleanup_outbound_throttle_decisions` (migration 066) had no caller
    // after the throttle writer returned, so the decision table grew
    // unbounded. The re-wired provider throttle writes deferrals again; this
    // daily sweep enforces its documented 90-day retention. The SQL function
    // itself returns 0 when the table does not exist, so an older schema is
    // harmless.
    let throttle_retention_state = state.clone();
    tokio::spawn(async move {
        // Run once on startup too: a process restarted more often than the
        // daily interval must still enforce retention.
        run_throttle_retention(&throttle_retention_state.db).await;

        let mut interval = interval_at(
            Instant::now() + task_interval(DAILY_TASK_INTERVAL),
            task_interval(DAILY_TASK_INTERVAL),
        );
        interval.set_missed_tick_behavior(MissedTickBehavior::Skip);

        loop {
            interval.tick().await;
            run_throttle_retention(&throttle_retention_state.db).await;
        }
    });

    // ── Month-end closing (daily) ──────────────────────────────
    let close_state = state.clone();
    tokio::spawn(async move {
        // Run once on startup (staggered by 1 hour to let other services initialise)
        let mut interval = interval_at(
            Instant::now() + Duration::from_secs(3600),
            task_interval(DAILY_TASK_INTERVAL),
        );
        interval.set_missed_tick_behavior(MissedTickBehavior::Skip);

        loop {
            interval.tick().await;

            match perform_month_end_closing(close_state.as_ref()).await {
                Ok(true) => info!("Month-end closing completed"),
                Ok(false) => {} // Not yet due or already closed
                Err(e) => error!(error = %e, "Month-end closing failed"),
            }
        }
    });

    // ── Trial-expiry sweep (daily) ──────────────────────────────
    // The ONLY writers of terminal subscription states are verified Mollie
    // webhooks. If the webhook chain dies during a trial→paid transition
    // (deadletter exhausts after 5 retries), a trialing row whose period
    // ended keeps granting the paid entitlement forever. This sweep is the
    // reconciler: any trialing subscription whose cycle ended more than a
    // grace window ago (webhook retries span ~4h) is marked canceled and
    // its tenant downgraded to free, with an audit trail.
    let trial_state = state.clone();
    tokio::spawn(async move {
        let mut interval = interval_at(
            Instant::now() + Duration::from_secs(5400),
            task_interval(DAILY_TASK_INTERVAL),
        );
        interval.set_missed_tick_behavior(MissedTickBehavior::Skip);

        loop {
            interval.tick().await;

            match sweep_expired_trials(trial_state.as_ref()).await {
                Ok(n) if n > 0 => info!(
                    expired_trials = n,
                    "Trial-expiry sweep downgraded stale trials"
                ),
                Ok(_) => {}
                Err(e) => error!(error = %e, "Trial-expiry sweep failed"),
            }

            // External audit 15 Oct, H1: a subscription canceled from the
            // product keeps access until its period end, then this reconciler
            // ends it and downgrades the tenant, the next renewal can never
            // charge a canceled subscription.
            match sweep_canceled_at_period_end(trial_state.as_ref()).await {
                Ok(n) if n > 0 => info!(
                    ended_subscriptions = n,
                    "Canceled-at-period-end sweep ended subscriptions"
                ),
                Ok(_) => {}
                Err(e) => error!(error = %e, "Canceled-at-period-end sweep failed"),
            }
        }
    });

    // ── Derived usage sweep + reconciliation (daily, audit items 1a–2) ──
    // Derives emails_delivered / webhooks_delivered / dedicated_ip_hours /
    // storage_gb_hours / bandwidth_gb for the last closed day from the
    // platform's own tables (idempotent via metering_daily_markers), then
    // writes the reserved-vs-delivered reconciliation report.
    let derived_state = state.clone();
    tokio::spawn(async move {
        let mut interval = interval_at(
            Instant::now() + task_interval(DERIVED_USAGE_SWEEP_INITIAL_DELAY),
            task_interval(DAILY_TASK_INTERVAL),
        );
        interval.set_missed_tick_behavior(MissedTickBehavior::Skip);

        loop {
            interval.tick().await;

            match crate::usage_ingest::sweep_derived_usage(&derived_state.db, Utc::now()).await {
                Ok(result)
                    if result.emails_delivered > 0
                        || result.webhooks_delivered > 0
                        || result.dedicated_ip_hours > 0
                        || result.storage_gb_hours > 0
                        || result.bandwidth_gb > 0 =>
                {
                    info!(
                        day = %result.day,
                        emails_delivered = result.emails_delivered,
                        webhooks_delivered = result.webhooks_delivered,
                        dedicated_ip_hours = result.dedicated_ip_hours,
                        storage_gb_hours = result.storage_gb_hours,
                        bandwidth_gb = result.bandwidth_gb,
                        skipped = ?result.skipped_sources,
                        "recorded derived usage aggregates"
                    );
                }
                Ok(result) if !result.skipped_sources.is_empty() => {
                    warn!(
                        day = %result.day,
                        skipped = ?result.skipped_sources,
                        "derived usage sweep skipped missing source tables"
                    );
                }
                Ok(_) => {}
                Err(error_message) => {
                    error!(error = %error_message, "failed to sweep derived usage aggregates");
                }
            }

            match crate::usage_ingest::reconcile_daily_deliveries(&derived_state.db, Utc::now())
                .await
            {
                Ok(result) if result.reports_written > 0 || result.overage_candidates > 0 => {
                    info!(
                        day = %result.day,
                        tenants_compared = result.tenants_compared,
                        reports_written = result.reports_written,
                        overage_candidates = result.overage_candidates,
                        "wrote delivery reconciliation reports"
                    );
                }
                Ok(_) => {}
                Err(error_message) => {
                    error!(error = %error_message, "failed to reconcile delivered usage");
                }
            }
        }
    });
}

/// Archive paid invoices that are older than 90 days and have a PDF URL set.
async fn archive_paid_invoices(state: &AppState) -> Result<i64, String> {
    let cutoff = Utc::now() - chrono::Duration::days(90);

    // Find paid invoices older than 90 days that have a PDF URL but no archive entry
    let candidates: Vec<(uuid::Uuid, String, String, Option<String>)> = sqlx::query_as(
        r#"
        SELECT i.id, i.tenant_id, i.invoice_number, i.pdf_url
        FROM invoices i
        LEFT JOIN invoice_archives ia ON ia.invoice_id = i.id
        WHERE ia.id IS NULL
          AND i.status = 'paid'
          AND i.paid_at IS NOT NULL
          AND i.paid_at < $1
          AND i.pdf_url IS NOT NULL
        LIMIT 500
        "#,
    )
    .bind(cutoff)
    .fetch_all(&state.db)
    .await
    .map_err(|e| format!("Failed to query invoice archive candidates: {e}"))?;

    let count = candidates.len() as i64;
    if candidates.is_empty() {
        return Ok(0);
    }

    let batch_id = uuid::Uuid::new_v4();

    // P3 item 7, archive the whole batch with ONE multi-row INSERT. The
    // pre-fix loop issued one INSERT per candidate (up to 500 round trips a
    // day) and only logged individual failures; `ON CONFLICT DO NOTHING`
    // keeps the replay idempotence, and the returned duplicate count is the
    // number of rows this run actually archived.
    #[cfg(test)]
    crate::test_support::query_count::bump("archive.db.insert");
    let mut builder = QueryBuilder::<Postgres>::new(
        "INSERT INTO invoice_archives (
            invoice_id, tenant_id, invoice_number, pdf_url, batch_id, archived_at
         ) ",
    );
    builder.push_values(
        &candidates,
        |mut values, (invoice_id, tenant_id, invoice_number, pdf_url)| {
            values
                .push_bind(*invoice_id)
                .push_bind(tenant_id.clone())
                .push_bind(invoice_number.clone())
                .push_bind(pdf_url.clone())
                .push_bind(batch_id)
                .push("NOW()");
        },
    );
    builder.push(" ON CONFLICT (invoice_id) DO NOTHING");
    // Error isolation matches the pre-batch loop: a failing row must not
    // discard its batch-mates. On a batch failure retry each candidate once;
    // a permanently failing row is logged (as before) and the rest archive.
    let archived = match builder.build().execute(&state.db).await {
        Ok(result) => result.rows_affected(),
        Err(error) => {
            warn!(
                error = %error,
                candidates = count,
                "Invoice archive batch failed; retrying rows individually"
            );
            let mut archived = 0u64;
            for (invoice_id, tenant_id, invoice_number, pdf_url) in &candidates {
                match sqlx::query(
                    "INSERT INTO invoice_archives (
                        invoice_id, tenant_id, invoice_number, pdf_url, batch_id, archived_at
                     ) VALUES ($1, $2, $3, $4, $5, NOW())
                     ON CONFLICT (invoice_id) DO NOTHING",
                )
                .bind(invoice_id)
                .bind(tenant_id)
                .bind(invoice_number)
                .bind(pdf_url)
                .bind(batch_id)
                .execute(&state.db)
                .await
                {
                    Ok(result) => archived += result.rows_affected(),
                    Err(row_error) => error!(
                        error = %row_error,
                        invoice_id = %invoice_id,
                        "Failed to archive invoice"
                    ),
                }
            }
            archived
        }
    };

    info!(
        batch_id = %batch_id,
        candidates = count,
        archived,
        "Invoice archival batch completed"
    );

    Ok(i64::try_from(archived).unwrap_or(i64::MAX))
}

/// Perform month-end closing for the previous month.
///
/// Runs daily (via `DAILY_TASK_INTERVAL`), targeting the *previous* calendar
/// month.  On the first run after month-end it will:
///
///  1. Set `closed_at` on every `paid` invoice whose `issued_at` falls in the
///     target period.
///  2. Record a [`month_end_closings`] row with summary statistics.
///  3. Log a system-level audit entry in `billing_audit_log`.
///
/// Returns `Ok(true)` when a closing was actually performed, `Ok(false)` when
/// nothing needed to be done (already closed or no paid invoices).
async fn perform_month_end_closing(state: &AppState) -> Result<bool, String> {
    let now = Utc::now();
    let current_month = now.month();
    let current_year = now.year();

    // Target period = previous calendar month.
    let (target_year, target_month) = if current_month == 1 {
        (current_year - 1, 12u32)
    } else {
        (current_year, current_month - 1)
    };

    // ------------------------------------------------------------------
    // 0.  Serialize concurrent closings (Fix F5): the previous
    //     check-then-insert ran across replicas/restarts, both passed the
    //     NOT-EXISTS check and double-inserted month_end_closings rows (and
    //     raced the invoice UPDATE). Take a pg advisory TRANSACTION lock
    //     keyed on the period and re-check existence INSIDE the lock; no
    //     schema change needed.
    // ------------------------------------------------------------------
    let mut tx = state
        .db
        .begin()
        .await
        .map_err(|e| format!("Failed to begin transaction: {e}"))?;

    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
        .bind(format!("month_end_closing:{target_year}-{target_month:02}"))
        .execute(&mut *tx)
        .await
        .map_err(|e| format!("Failed to acquire month-end closing lock: {e}"))?;

    // ------------------------------------------------------------------
    // 1.  Check if a closing record already exists for this period
    //     (re-checked under the advisory lock).
    // ------------------------------------------------------------------
    // `SELECT 1` is INT4; decoding it as i64 fails with a type mismatch, so
    // the idempotency re-check (and therefore every second daily run) errored
    // after the first closing. Project an explicit bigint.
    let already_closed: bool = sqlx::query_scalar::<_, Option<i64>>(
        "SELECT 1::bigint FROM month_end_closings WHERE tax_year = $1 AND tax_month = $2 LIMIT 1",
    )
    .bind(target_year)
    .bind(target_month as i32)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|e| format!("Failed to check existing month-end closing: {e}"))?
    .is_some();

    if already_closed {
        return Ok(false);
    }

    // ------------------------------------------------------------------
    // 2.  Build period boundaries ([period_start, period_end)).
    // ------------------------------------------------------------------
    // KMD/Tallinn-midnight boundaries (21:00/22:00 UTC on the previous
    // day): the closing record and the KMD VAT return MUST bucket invoices
    // by the same instants, or the 2-3 UTC hours after local midnight land
    // in different tax months between the two reports and the filed numbers
    // never tie out. Reuse the KMD period bounds as the single source of
    // truth (fail loudly on an ambiguous DST midnight rather than guessing).
    let (period_start, period_end) =
        crate::vat_kmd::kmd_period_bounds_utc(target_year, target_month)?;

    // ------------------------------------------------------------------
    // 3.  Count invoices that would be affected (dry-run check).
    // ------------------------------------------------------------------
    let pending_count: i64 = sqlx::query_scalar(
        r#"
        SELECT COUNT(*)::bigint
        FROM invoices
        WHERE issued_at >= $1 AND issued_at < $2
          AND status = 'paid'
          AND closed_at IS NULL
        "#,
    )
    .bind(period_start)
    .bind(period_end)
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| format!("Failed to count pending invoices: {e}"))?;

    if pending_count == 0 {
        // Still record a closing marker so we don't re-check every day.
        let closing_id = Uuid::new_v4();
        sqlx::query(
            r#"
            INSERT INTO month_end_closings
                (id, tax_year, tax_month, total_invoices, total_revenue_cents,
                 total_vat_cents, status)
            VALUES ($1, $2, $3, 0, 0, 0, 'completed')
            "#,
        )
        .bind(closing_id)
        .bind(target_year)
        .bind(target_month as i32)
        .execute(&mut *tx)
        .await
        .map_err(|e| format!("Failed to record empty month-end closing: {e}"))?;

        tx.commit()
            .await
            .map_err(|e| format!("Failed to commit empty month-end closing: {e}"))?;

        info!(
            tax_year = target_year,
            tax_month = target_month,
            "Month-end closing recorded (no paid invoices to close)"
        );
        return Ok(true);
    }

    // ------------------------------------------------------------------
    // 4.  Inside the lock-held transaction from step 0: update invoices +
    //     insert closing record + audit.
    // ------------------------------------------------------------------

    // 4a. Mark all paid invoices in the target period as closed.
    let updated = sqlx::query(
        r#"
        UPDATE invoices
        SET closed_at = NOW()
        WHERE issued_at >= $1 AND issued_at < $2
          AND status = 'paid'
          AND closed_at IS NULL
        "#,
    )
    .bind(period_start)
    .bind(period_end)
    .execute(&mut *tx)
    .await
    .map_err(|e| format!("Failed to close invoices: {e}"))?
    .rows_affected();

    // 4b. Compute summary statistics.
    let summary: (i64, i64, i64) = sqlx::query_as(
        r#"
        SELECT
            COUNT(*)::bigint,
            COALESCE(SUM(total), 0)::bigint,
            COALESCE(SUM(vat_total), 0)::bigint
        FROM invoices
        WHERE issued_at >= $1 AND issued_at < $2
          AND status = 'paid'
          AND closed_at IS NOT NULL
        "#,
    )
    .bind(period_start)
    .bind(period_end)
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| format!("Failed to compute month-end summary: {e}"))?;

    // 4c. Insert the month_end_closings record.
    let closing_id = Uuid::new_v4();
    sqlx::query(
        r#"
        INSERT INTO month_end_closings
            (id, tax_year, tax_month, total_invoices, total_revenue_cents,
             total_vat_cents, status)
        VALUES ($1, $2, $3, $4, $5, $6, 'completed')
        "#,
    )
    .bind(closing_id)
    .bind(target_year)
    .bind(target_month as i32)
    .bind(summary.0)
    .bind(summary.1)
    .bind(summary.2)
    .execute(&mut *tx)
    .await
    .map_err(|e| format!("Failed to insert month-end closing record: {e}"))?;

    // 4d. System-level audit trail (nullable tenant_id for global operations).
    sqlx::query(
        r#"
        INSERT INTO billing_audit_log
            (tenant_id, action, actor_type, details)
        VALUES (NULL, 'month_end_closing', 'system', $1)
        "#,
    )
    .bind(serde_json::json!({
        "tax_year": target_year,
        "tax_month": target_month,
        "closed_invoices": summary.0,
        "total_revenue_cents": summary.1,
        "total_vat_cents": summary.2,
        "closing_id": closing_id.to_string(),
        "rows_updated": updated,
    }))
    .execute(&mut *tx)
    .await
    .map_err(|e| format!("Failed to insert billing audit log: {e}"))?;

    tx.commit()
        .await
        .map_err(|e| format!("Failed to commit month-end closing transaction: {e}"))?;

    info!(
        tax_year = target_year,
        tax_month = target_month,
        closed_invoices = summary.0,
        total_revenue_cents = summary.1,
        total_vat_cents = summary.2,
        rows_updated = updated,
        "Month-end closing completed"
    );

    Ok(true)
}

/// One audit entry handed to [`append_audit_log_batch`]: the exact fields the
/// per-row [`append_audit_log`] writes, prepared in sweep order.
pub(crate) struct BatchedAuditEntry {
    tenant_id: String,
    action: &'static str,
    resource_type: &'static str,
    resource_id: Option<String>,
    metadata: Value,
    timestamp: DateTime<Utc>,
}

/// Append a whole batch of audit entries with a BOUNDED number of statements
/// per sweep (perf audit 2026-10-18, finding 15): ONE chain-head advance and
/// ONE multi-row INSERT, never a transaction round trip per entry.
///
/// Chain/hash semantics are IDENTICAL to N calls to [`append_audit_log`] in
/// input order, batched the way compliance `AuditLogger::log_batch` batches:
/// * the row hash is the canonical 7-segment SHA-256 over
///   `tenant|user|action|resource|resource_id|details|timestamp`, the chain
///   link is NOT part of the row hash, so every hash can be computed before
///   the head is read;
/// * ONE atomic `audit_chain_head` upsert advances the head to the LAST
///   entry's hash and returns the hash it replaced, which entry 0 links to;
///   entries 1..n chain in memory in input order (concurrent appenders
///   serialise on the single head row exactly as before, the batch is one
///   link on the shared chain);
/// * timestamps stay microsecond-truncated (one per entry, in order) and the
///   HMAC signature still covers `previous_hash|hash`.
async fn append_audit_log_batch(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    entries: Vec<BatchedAuditEntry>,
) -> Result<(), String> {
    if entries.is_empty() {
        return Ok(());
    }

    // Row hashes first: the canonical formula never mixes the chain link in,
    // so the whole chain of hashes is computable before we touch the head.
    let mut hashes: Vec<String> = Vec::with_capacity(entries.len());
    for entry in &entries {
        let timestamp = apexmail_lib::audit::truncate_timestamp_to_micros(entry.timestamp);
        let hash_payload = apexmail_lib::audit::audit_hash_payload(
            Some(&entry.tenant_id),
            None, // machine context: user segment EMPTY, never absent
            entry.action,
            entry.resource_type,
            entry.resource_id.as_deref(),
            &entry.metadata,
            timestamp,
        );
        hashes.push(apexmail_lib::audit::audit_row_hash(&hash_payload));
    }

    // ONE atomic head advance for the whole batch: the head becomes the LAST
    // hash and returns the hash it replaced, the link for entry 0.
    let head_hash = hashes.last().cloned().unwrap_or_default();
    let first_previous_hash: Option<String> = sqlx::query_scalar(
        r#"
        INSERT INTO audit_chain_head (chain_id, head_hash, prev_hash, head_seq, updated_at)
        VALUES ('global', $1, NULL, 1, NOW())
        ON CONFLICT (chain_id) DO UPDATE SET
            prev_hash  = audit_chain_head.head_hash,
            head_hash  = EXCLUDED.head_hash,
            head_seq   = audit_chain_head.head_seq + 1,
            updated_at = NOW()
        RETURNING prev_hash
        "#,
    )
    .bind(&head_hash)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|e| format!("Failed to advance audit chain head: {e}"))?
    .flatten();

    // Link the in-memory chain in input order, sign every link, and write
    // ONE multi-row INSERT (same columns, outcome and timestamp/created_at
    // shape the per-row writer uses).
    let signing_key = audit_signing_key();
    let mut previous_hash = first_previous_hash;
    let mut linked: Vec<(String, Option<String>)> = Vec::with_capacity(entries.len());
    for hash in &hashes {
        linked.push((hash.clone(), previous_hash.clone()));
        previous_hash = Some(hash.clone());
    }

    let mut builder = sqlx::QueryBuilder::new(
        r#"
        INSERT INTO audit_logs (
            id, tenant_id, action, resource, resource_id,
            details, outcome, previous_hash, hash, signature, timestamp, created_at
        )
        "#,
    );
    builder.push_values(
        linked.into_iter().zip(entries),
        |mut b, ((hash, previous_hash), entry)| {
            let signature = match apexmail_lib::audit::audit_log_signature(
                previous_hash.as_deref(),
                &hash,
                &signing_key,
            ) {
                Ok(signature) => signature,
                Err(_) => {
                    tracing::error!(
                        "AUDIT_SIGNING_KEY could not be parsed; audit-log signature left empty"
                    );
                    String::new()
                }
            };
            let timestamp = apexmail_lib::audit::truncate_timestamp_to_micros(entry.timestamp);
            b.push_bind(crate::routes::generate_audit_log_id())
                .push_bind(entry.tenant_id.clone())
                .push_bind(entry.action)
                .push_bind(entry.resource_type)
                .push_bind(entry.resource_id)
                .push_bind(entry.metadata)
                .push_bind("success")
                .push_bind(previous_hash)
                .push_bind(hash)
                .push_bind(signature)
                .push_bind(timestamp)
                .push_bind(timestamp);
        },
    );
    builder
        .build()
        .execute(&mut **tx)
        .await
        .map_err(|e| format!("Failed to insert audit log batch: {e}"))?;

    Ok(())
}

/// The HMAC key for audit chain signatures: `AUDIT_SIGNING_KEY` when
/// configured, else the documented development fallback, the same policy
/// `routes::audit_log_signature` applies for per-row appends.
fn audit_signing_key() -> String {
    match std::env::var("AUDIT_SIGNING_KEY") {
        Ok(key) if !key.trim().is_empty() => key,
        _ => {
            tracing::warn!(
                "AUDIT_SIGNING_KEY is not configured, signing with the documented development fallback key"
            );
            "apexmail-audit-fallback-key".to_string()
        }
    }
}

/// Apply subscriptions canceled for period end once the period has actually
/// ended (external audit 15 Oct, H1).
///
/// `subscriptions::cancel_subscription(..., immediately = false)` records the
/// period-end stop and an audit row; this reconciler is what makes the stop
/// durable when the cycle ends: status → canceled, tenant → free, and an
/// audit entry. Idempotent (the `cancel_at_period_end = true` predicate is
/// cleared in the same statement), and the period lock is skipped, so a
/// concurrent maintenance pass cannot double-count.
///
/// Set-based (perf audit 2026-10-18, finding 15): one transaction, ONE
/// `WITH due … FOR UPDATE SKIP LOCKED` statement that performs the
/// subscription transition and the tenant downgrade in bulk, then ONE
/// multi-row audit append, 3 statements per sweep instead of ~3 per row, so
/// a mass-cancellation event no longer holds long per-row write loops on
/// `tenants`/`mollie_subscriptions`. Status values, timestamp columns, the
/// `plan <> 'free'` guard and the audit payload are byte-identical to the
/// per-row loop this replaced.
pub async fn sweep_canceled_at_period_end(state: &AppState) -> Result<u64, String> {
    let mut tx = state
        .db
        .begin()
        .await
        .map_err(|e| format!("Failed to begin canceled-subscription sweep transaction: {e}"))?;

    // Lock the due set, transition the subscriptions and downgrade their
    // tenants in ONE statement; the RETURNING chain yields exactly the rows
    // that were ended (same predicate, same writes as the old per-row loop).
    // The provider ids ride along: they must be captured BEFORE the local
    // status becomes `canceled`, otherwise the provider-side DELETE has no
    // row left to find and Mollie would keep charging a canceled customer.
    let due: Vec<(uuid::Uuid, String, String, Option<String>)> = sqlx::query_as(
        r#"
        WITH due AS (
            SELECT s.id, s.tenant_id, s.mollie_subscription_id, s.mollie_customer_id
            FROM mollie_subscriptions s
            WHERE s.cancel_at_period_end = true
              AND s.status IN ('active', 'trialing', 'past_due', 'unpaid')
              AND s.billing_cycle_end IS NOT NULL
              AND s.billing_cycle_end <= NOW()
            FOR UPDATE SKIP LOCKED
        ),
        ended AS (
            UPDATE mollie_subscriptions s
               SET status = 'canceled',
                   cancel_at_period_end = false,
                   updated_at = NOW()
              FROM due
             WHERE s.id = due.id
            RETURNING s.id
        ),
        downgraded AS (
            UPDATE tenants t
               SET plan = 'free', updated_at = NOW()
              FROM due
             WHERE t.id = due.tenant_id
               AND t.plan <> 'free'
        )
        SELECT due.id, due.tenant_id, due.mollie_subscription_id, due.mollie_customer_id
        FROM due
        JOIN ended ON ended.id = due.id
        ORDER BY due.id
        "#,
    )
    .fetch_all(&mut *tx)
    .await
    .map_err(|e| format!("Failed to end due subscriptions: {e}"))?;

    append_audit_log_batch(
        &mut tx,
        due.iter()
            .map(|(subscription_id, tenant_id, _, _)| BatchedAuditEntry {
                tenant_id: tenant_id.clone(),
                action: "billing.subscription_ended_at_period_end",
                resource_type: "subscription",
                resource_id: Some(subscription_id.to_string()),
                metadata: serde_json::json!({ "effective": "period_end" }),
                timestamp: Utc::now(),
            })
            .collect(),
    )
    .await?;

    tx.commit()
        .await
        .map_err(|e| format!("Failed to commit canceled-subscription sweep: {e}"))?;

    // The provider-side half of the period-end cancellation: stop Mollie's
    // own charge generation and revoke the mandate, using the ids captured
    // before the local transition. A provider failure here is logged; the
    // reconciliation sweep retries any provider object still active for a
    // locally canceled row, and the revocation sweep retries mandates.
    let tenants: Vec<String> = due.iter().map(|(_, tenant, _, _)| tenant.clone()).collect();
    for (_, tenant_id, subscription_id, customer_id) in &due {
        let Some(customer_id) = customer_id.as_deref() else {
            continue;
        };
        if let Err(error) =
            crate::plan_billing::cancel_provider_subscription_object(customer_id, subscription_id)
                .await
        {
            tracing::warn!(tenant_id = %tenant_id, error = %error,
                "period-end cancellation: provider subscription cancellation failed (reconciliation retries it)");
        }
    }
    if let Err(error) =
        crate::subscriptions::revoke_tenant_mandates_at_provider(&state.db, &tenants).await
    {
        tracing::warn!(error = %error,
            "period-end cancellation: mandate revocation failed (sweep will retry)");
    }
    Ok(due.len() as u64)
}

/// Downgrade tenants whose trialing subscription ended without a terminal
/// webhook (see the sweep task comment). Returns the number of tenants
/// downgraded. Idempotent: rows already canceled no longer match.
///
/// Set-based (perf audit 2026-10-18, finding 15): one transaction, ONE
/// statement that cancels every stale trialing subscription and downgrades
/// its tenant, then ONE multi-row audit append, 3 statements per sweep
/// instead of ~3 per stale row. Status values, timestamp columns, the
/// `status = 'trialing'` write guard and the audit payload are byte-identical
/// to the per-row loop this replaced.
async fn sweep_expired_trials(state: &AppState) -> Result<u64, String> {
    // Webhook retries span ~4 hours after the transition; allow 24h before
    // the reconciler acts so a merely-delayed webhook is never raced.
    let mut tx = state
        .db
        .begin()
        .await
        .map_err(|e| format!("Failed to begin trial sweep transaction: {e}"))?;

    let stale: Vec<(String, String)> = sqlx::query_as(
        r#"
        WITH stale AS (
            SELECT DISTINCT s.tenant_id, s.mollie_subscription_id
            FROM mollie_subscriptions s
            JOIN tenants t ON t.id = s.tenant_id AND t.plan <> 'free'
            WHERE s.status = 'trialing'
              AND COALESCE(s.trial_end, s.billing_cycle_end) < NOW() - INTERVAL '24 hours'
        ),
        canceled AS (
            UPDATE mollie_subscriptions s
               SET status = 'canceled', updated_at = NOW()
              FROM stale
             WHERE s.mollie_subscription_id = stale.mollie_subscription_id
               AND s.status = 'trialing'
        ),
        downgraded AS (
            UPDATE tenants t
               SET plan = 'free', updated_at = NOW()
              FROM stale
             WHERE t.id = stale.tenant_id
        )
        SELECT tenant_id, mollie_subscription_id
        FROM stale
        ORDER BY tenant_id
        "#,
    )
    .fetch_all(&mut *tx)
    .await
    .map_err(|e| format!("Failed to cancel stale trials: {e}"))?;

    if stale.is_empty() {
        tx.commit().await.map_err(|e| e.to_string())?;
        return Ok(0);
    }

    append_audit_log_batch(
        &mut tx,
        stale
            .iter()
            .map(|(tenant_id, subscription_id)| BatchedAuditEntry {
                tenant_id: tenant_id.clone(),
                action: "billing.trial_expired_sweep",
                resource_type: "mollie_subscription",
                resource_id: Some(subscription_id.clone()),
                metadata: serde_json::json!({
                    "reason": "trialing subscription period ended without a terminal webhook",
                }),
                timestamp: chrono::Utc::now(),
            })
            .collect(),
    )
    .await
    .map_err(|e| format!("Failed to audit trial sweep: {e}"))?;

    let count = stale.len() as u64;
    tx.commit()
        .await
        .map_err(|e| format!("Failed to commit trial sweep: {e}"))?;
    Ok(count)
}

/// Check if the previous month's KMD return is due (past the 20th)
/// and generate it, plus every missed month since the last generated
/// return, if not present yet (Fix I5: a service outage used to skip
/// months permanently because only the immediately-previous month was
/// ever considered).
async fn generate_kmd_if_due(
    state: &AppState,
) -> Result<Vec<crate::vat_kmd::VatKmdResult>, String> {
    let now = Utc::now();
    let current_day = now.day();
    let current_month = now.month();

    // KMD for previous month is due on the 20th of the current month
    if current_day < 20 {
        return Ok(Vec::new());
    }

    // Determine the target period (previous month)
    let target = if current_month == 1 {
        (now.year() - 1, 12u32)
    } else {
        (now.year(), current_month - 1)
    };

    let generated = crate::vat_kmd::list_generated_kmd_periods(&state.db).await?;
    let missing = kmd_backfill_periods(&generated, target, KMD_BACKFILL_MAX_MONTHS);

    let mut results = Vec::with_capacity(missing.len());
    for (tax_year, tax_month) in missing {
        info!(
            tax_year,
            tax_month, "generating KMD return for missed period"
        );
        results.push(crate::vat_kmd::generate_kmd_return(&state.db, tax_year, tax_month).await?);
    }

    Ok(results)
}

/// Upper bound on how many missed KMD periods a single sweep will backfill
/// (protects a fresh deployment from synthesizing years of empty returns).
const KMD_BACKFILL_MAX_MONTHS: usize = 24;

/// Pure companion of [`generate_kmd_if_due`]: the exact list of periods to
/// generate, i.e. every missing month strictly after the latest generated
/// period through `target` (inclusive). With nothing generated yet, only the
/// target period is produced.
fn kmd_backfill_periods(
    generated: &[(i32, u32)],
    target: (i32, u32),
    cap: usize,
) -> Vec<(i32, u32)> {
    let last = generated.iter().copied().max();
    let from = match last {
        // Already generated at/after the target, nothing to do.
        Some(last) if last >= target => return Vec::new(),
        Some(last) => last,
        None => return vec![target],
    };
    crate::vat_kmd::month_steps(from, target, cap)
}

/// Attempt to file the generated KMD VAT return with the EMTA (e-MTA) API.
///
/// Performs idempotency check, if the KMD return record already has a
/// `filing_reference` and `filed_at` set, the filing is skipped.
///
/// Returns:
/// * `Ok(Some(...))`, filing was attempted and acknowledged.
/// * `Ok(None)`, already filed, skipped.
/// * `Err(...)`, filing failed (HTTP error, parse error, DB error).
async fn attempt_emta_filing(
    db: &sqlx::PgPool,
    emta_client: &EmtaClient,
    kmd: &crate::vat_kmd::VatKmdResult,
) -> Result<Option<crate::vat_emta::EmtaSubmissionResult>, String> {
    use crate::vat_kmd::VatKmdReturn;

    // ── 1. Load the stored KMD return row ──────────────────────────
    let stored = sqlx::query_as::<_, VatKmdReturn>(
        r#"
        SELECT id, tax_year, tax_month, status, breakdown,
               invoice_count, total_taxable_cents, total_vat_cents,
               generated_at, filed_at, filing_reference, filing_error,
               created_at, updated_at
        FROM vat_kmd_returns
        WHERE id = $1
        "#,
    )
    .bind(kmd.kmd_id)
    .fetch_optional(db)
    .await
    .map_err(|e| format!("Failed to query KMD return for EMTA filing: {e}"))?
    .ok_or_else(|| format!("KMD return {} not found in database", kmd.kmd_id))?;

    // ── 2. Idempotency check, skip if already filed ──────────────
    if stored.filed_at.is_some() && stored.filing_reference.is_some() {
        info!(
            kmd_id = %kmd.kmd_id,
            filing_reference = ?stored.filing_reference,
            "KMD return already filed with EMTA; skipping"
        );
        return Ok(None);
    }

    // ── 3. Submit to EMTA ─────────────────────────────────────────
    let filing_result = emta_client
        .submit_kmd_return(kmd, &stored.breakdown, kmd.kmd_id)
        .await
        .map_err(|e| format!("EMTA filing failed: {e}"))?;

    // ── 4. Update the stored record with filing outcome ───────────
    let new_status = if filing_result.accepted {
        "filed"
    } else {
        "failed"
    };
    let filing_error: Option<String> = if filing_result.accepted {
        None
    } else {
        Some(filing_result.status_message.clone())
    };

    sqlx::query(
        r#"
        UPDATE vat_kmd_returns
        SET status = $1,
            filed_at = NOW(),
            filing_reference = $2,
            filing_error = $3,
            updated_at = NOW()
        WHERE id = $4
        "#,
    )
    .bind(new_status)
    .bind(&filing_result.filing_reference)
    .bind(filing_error)
    .bind(kmd.kmd_id)
    .execute(db)
    .await
    .map_err(|e| format!("Failed to update KMD return filing status: {e}"))?;

    info!(
        kmd_id = %kmd.kmd_id,
        accepted = filing_result.accepted,
        filing_reference = ?filing_result.filing_reference,
        "KMD return filing status updated"
    );

    Ok(Some(filing_result))
}

#[derive(Debug)]
struct GracePeriodResult {
    processed_count: i64,
    purged_messages_count: i64,
}

#[derive(Debug)]
struct RetryResult {
    attempted: i64,
    succeeded: i64,
}

#[derive(Debug)]
pub(crate) struct MeteringDrainResult {
    pub(crate) processed_count: i64,
    pub(crate) discarded_count: i64,
}

/// Outcome of one usage-alert sweep. Public because the SAME evaluation the
/// periodic loop runs is exposed to integration tests through
/// [`process_usage_alerts`], a test that re-implemented the sweep would
/// prove nothing about the running path.
#[derive(Debug)]
pub struct UsageAlertSweepResult {
    pub tenants_checked: i64,
    pub alerts_triggered: i64,
}

#[derive(Debug)]
struct CostMarginSweepResult {
    checked: i64,
    warnings: i64,
    critical: i64,
}

#[derive(Debug)]
struct SlaCreditSweepResult {
    tenants_checked: i64,
    credits_created: i64,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PendingMeterEvent {
    id: String,
    tenant_id: String,
    event_type: String,
    quantity: i64,
    timestamp: DateTime<Utc>,
    #[serde(default)]
    metadata: Value,
}

#[derive(Debug, Clone)]
struct PreparedMeterEvent {
    raw_id: String,
    normalized_id: Uuid,
    tenant_id: String,
    event_type: String,
    quantity: i64,
    timestamp: DateTime<Utc>,
    metadata: Value,
}

#[derive(Debug, FromRow)]
struct UsageAlertConfigRow {
    id: Uuid,
    /// Operator-facing rule label (migration 246). NULL on rows created by
    /// the tenant-facing upsert before names existed; the fired incident
    /// falls back to the metric in that case.
    name: Option<String>,
    metric_type: String,
    threshold_percent: i32,
    notification_channel: String,
    /// info | warning | critical (migration 246 CHECK), carried onto the
    /// fired `system_alerts` row.
    severity: String,
}

/// One enabled usage-alert rule together with its tenant, as loaded by the
/// grouped sweep (one query for ALL tenants with rules instead of one query
/// per tenant).
#[derive(Debug, FromRow)]
struct TenantUsageAlertConfigRow {
    tenant_id: String,
    id: Uuid,
    name: Option<String>,
    metric_type: String,
    threshold_percent: i32,
    notification_channel: String,
    severity: String,
}

/// One row of the grouped plan-limits query, `usage.rs`'s
/// `TenantPlanLimitRow` widened with the tenant id (the override-aware
/// `COALESCE(po.plan, t.plan)` resolution lives in the sweep's SQL).
#[derive(Debug, FromRow)]
struct TenantAlertPlanLimitRow {
    tenant_id: String,
    plan_name: String,
    email_limit: Option<i64>,
    api_call_limit: Option<i64>,
    tenant_created_at: Option<DateTime<Utc>>,
}

/// The limit resolution `usage.rs::resolve_plan_limits` applies, mirrored for
/// the grouped usage-alert sweep: DB plan values win, builtin plan defaults
/// fill the gaps, and the free-plan launch allowance only ever WIDENS the
/// free email ceiling during the first 30 days of the tenant's life.
fn resolve_alert_plan_limits(row: &TenantAlertPlanLimitRow) -> (i64, i64) {
    let (fallback_email_limit, fallback_api_call_limit) =
        crate::plans::builtin_quota_limits(Some(&row.plan_name));

    let mut email_limit = row.email_limit.unwrap_or(fallback_email_limit);
    if row.plan_name == "free" {
        let in_launch_window = row
            .tenant_created_at
            .map(|created| {
                Utc::now() - created
                    < chrono::Duration::days(crate::usage::FREE_PLAN_LAUNCH_WINDOW_DAYS)
            })
            .unwrap_or(false); // unknown creation date: never widened
        if in_launch_window {
            email_limit = email_limit.max(crate::usage::FREE_PLAN_LAUNCH_ALLOWANCE);
        }
    }

    (
        email_limit,
        row.api_call_limit.unwrap_or(fallback_api_call_limit),
    )
}

#[derive(Debug, FromRow)]
struct TenantCostSummaryRow {
    storage_cost: i64,
    bandwidth_cost: i64,
    compute_cost: i64,
    dedicated_ip_cost: i64,
    total_cost: i64,
    revenue: i64,
}

/// One tenant's cost summary as loaded by the grouped cost-margin sweep —
/// `TenantCostSummaryRow` keyed by tenant id (the LEFT JOIN keeps tenants
/// with no `tenant_costs` rows, whose COALESCE zeros are Healthy).
#[derive(Debug, FromRow)]
struct TenantGroupedCostSummaryRow {
    tenant_id: String,
    #[sqlx(flatten)]
    summary: TenantCostSummaryRow,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CostMarginStatus {
    Healthy,
    Warning,
    Critical,
}

impl CostMarginStatus {
    fn as_str(self) -> &'static str {
        match self {
            Self::Healthy => "healthy",
            Self::Warning => "warning",
            Self::Critical => "critical",
        }
    }
}

#[derive(Debug, FromRow)]
struct SlaMetricCandidateRow {
    tenant_id: String,
    uptime_percent: f64,
    features: Value,
}

#[derive(Debug)]
struct DedicatedIpSyncResult {
    charged: i64,
    canceled: i64,
}

#[derive(Debug, FromRow)]
struct DedicatedIpPendingRow {
    id: String,
    tenant_id: String,
    ip_address: String,
    mollie_mandate_id: Option<String>,
}

#[derive(Debug, FromRow)]
struct TenantMollieSubscriptionRow {
    /// The Mollie customer that owns the stored mandate.
    mollie_customer_id: Option<String>,
    /// The stored-payment token recurring charges replay; `None` until the
    /// customer re-tokenizes.
    mollie_mandate_id: Option<String>,
}

#[derive(Debug, FromRow)]
struct ExpiredTenantPurgeRow {
    tenant_id: String,
    purged_count: i32,
}

async fn process_grace_period_expirations(
    state: &AppState,
    batch_size: i64,
) -> Result<GracePeriodResult, String> {
    let mut total_processed = 0_i64;
    let mut total_purged = 0_i64;
    let now = Utc::now();

    loop {
        let rows = sqlx::query_as::<_, ExpiredTenantPurgeRow>(
            r#"
            WITH expired_tenants AS (
                SELECT tenant_id FROM dunning_records
                WHERE status = 'hard_suspended'
                  AND grace_period_ends_at IS NOT NULL
                  AND grace_period_ends_at < $1
                ORDER BY grace_period_ends_at ASC
                LIMIT $2
                FOR UPDATE SKIP LOCKED
            ),
            purge_messages AS (
                DELETE FROM messages
                WHERE tenant_id IN (SELECT tenant_id FROM expired_tenants)
                  AND status = 'dunning_queued'
                RETURNING tenant_id
            ),
            purge_counts AS (
                SELECT tenant_id, COUNT(*) AS purged_count
                FROM purge_messages
                GROUP BY tenant_id
            ),
            queue_notifications AS (
                INSERT INTO notification_queue (id, tenant_id, type, payload, status, created_at)
                SELECT gen_random_uuid(), et.tenant_id, 'messages_purged',
                       jsonb_build_object('purgedCount', COALESCE(pc.purged_count, 0)),
                       'pending', NOW()
                FROM expired_tenants et
                LEFT JOIN purge_counts pc ON et.tenant_id = pc.tenant_id
                RETURNING tenant_id
            ),
            update_dunning AS (
                UPDATE dunning_records
                SET grace_period_ends_at = NULL, updated_at = NOW()
                WHERE tenant_id IN (SELECT tenant_id FROM expired_tenants)
                RETURNING tenant_id
            )
            SELECT et.tenant_id, COALESCE(pc.purged_count, 0)::int AS purged_count
            FROM expired_tenants et
            LEFT JOIN purge_counts pc ON et.tenant_id = pc.tenant_id
            "#,
        )
        .bind(now)
        .bind(batch_size)
        .fetch_all(&state.db)
        .await
        .map_err(|error| format!("Failed to process grace-period expirations: {error}"))?;

        let batch_count = i64::try_from(rows.len()).unwrap_or(i64::MAX);
        if batch_count == 0 {
            break;
        }

        let batch_purged: i64 = rows.iter().map(|row| i64::from(row.purged_count)).sum();

        total_processed += batch_count;
        total_purged += batch_purged;

        for row in &rows {
            info!(tenant_id = %row.tenant_id, purged_count = row.purged_count, "purged dunning queued messages after grace period");
        }

        if batch_count < batch_size {
            break;
        }
    }

    Ok(GracePeriodResult {
        processed_count: total_processed,
        purged_messages_count: total_purged,
    })
}

/// Lua script that atomically deletes the pending key and increments the
/// real-time counter, guarded by a counter-guard key to prevent double-
/// counting on re-run after a crash.
///
/// KEYS[1] = counter-guard key (e.g. "meter:guard:<normalized_id>")
/// KEYS[2] = counter key (e.g. "meter:rt:<tenant>:<event_type>:<period>")
/// KEYS[3] = pending key (e.g. "meter:pending:<raw_id>")
/// ARGV[1] = quantity
/// ARGV[2] = counter TTL in seconds
///
/// The counter-guard key ensures that if the Lua script succeeds but the
/// DB insert was already committed, a re-run will NOT double-increment
/// the counter.  The pending key is cleaned up regardless.
const DRAIN_AND_INCR_LUA: &str = r#"
    local guarded = redis.call('SET', KEYS[1], '1', 'EX', ARGV[2], 'NX')
    if guarded then
        redis.call('INCRBY', KEYS[2], ARGV[1])
        redis.call('EXPIRE', KEYS[2], ARGV[2])
    end
    redis.call('DEL', KEYS[3])
    return 1
"#;

/// EVAL commands per pipelined Redis round trip (P2). Each EVAL remains an
/// atomic script invocation; the pipeline only removes the per-event network
/// round trip.
const DRAIN_EVAL_PIPELINE_CHUNK: usize = 500;

#[derive(sqlx::FromRow)]
struct DrainCycleAnchorRow {
    tenant_id: String,
    billing_cycle_start: DateTime<Utc>,
}

/// Memo key for a resolved counter key. The brief's
/// (tenant_id, event_type, year-month) tuple is extended with the SELECTED
/// cycle anchor: two events in the same calendar month can legitimately
/// select different anchors when a subscription starts mid-month, and the
/// key must stay byte-identical to
/// `usage::enforced_counter_key_for_event_type` for each event.
type DrainCounterMemoKey = (String, String, i32, u32, Option<chrono::NaiveDate>);

/// Resolve the enforced counter keys for a whole drain (P2).
///
/// ONE SELECT loads every active/trialing/past-due subscription's
/// `billing_cycle_start` for the drain's distinct tenants; per-event anchor
/// selection (latest start at or before the event timestamp) and the
/// anchored cycle math then run in memory. This mirrors
/// `usage::enforced_counter_key_for_event_type` exactly (the helpers it
/// calls are private to `usage.rs`); the caller's memo collapses repeated
/// (tenant, type, month, anchor) combinations.
async fn drain_counter_keys(
    state: &AppState,
    events: &[PreparedMeterEvent],
) -> Result<Vec<String>, String> {
    let mut tenants: Vec<String> = events
        .iter()
        .map(|event| event.tenant_id.clone())
        .collect::<HashSet<_>>()
        .into_iter()
        .collect();
    tenants.sort();

    #[cfg(test)]
    crate::test_support::query_count::bump("drain.db.counter_keys");
    let rows: Vec<DrainCycleAnchorRow> = sqlx::query_as(
        r#"
        SELECT tenant_id, billing_cycle_start
        FROM mollie_subscriptions
        WHERE tenant_id = ANY($1)
          AND status IN ('active', 'trialing', 'past_due')
          AND billing_cycle_start IS NOT NULL
        ORDER BY tenant_id, billing_cycle_start
        "#,
    )
    .bind(&tenants)
    .fetch_all(&state.db)
    .await
    .map_err(|error| format!("Failed to load drain subscription anchors: {error}"))?;

    let mut anchors: HashMap<String, Vec<DateTime<Utc>>> = HashMap::new();
    for row in rows {
        anchors
            .entry(row.tenant_id)
            .or_default()
            .push(row.billing_cycle_start);
    }

    let mut memo: HashMap<DrainCounterMemoKey, String> = HashMap::new();
    let mut keys = Vec::with_capacity(events.len());
    for event in events {
        let anchor = drain_anchor_for(
            anchors.get(&event.tenant_id).map(Vec::as_slice),
            event.timestamp,
        );
        let memo_key = (
            event.tenant_id.clone(),
            event.event_type.clone(),
            event.timestamp.year(),
            event.timestamp.month(),
            anchor,
        );
        let key = memo
            .entry(memo_key)
            .or_insert_with(|| {
                drain_format_counter_key(
                    &event.tenant_id,
                    &event.event_type,
                    event.timestamp,
                    anchor,
                )
            })
            .clone();
        keys.push(key);
    }
    Ok(keys)
}

/// Latest cycle start at or before `at` (the SELECT's
/// `ORDER BY billing_cycle_start DESC LIMIT 1` in memory).
fn drain_anchor_for(
    starts: Option<&[DateTime<Utc>]>,
    at: DateTime<Utc>,
) -> Option<chrono::NaiveDate> {
    starts?
        .iter()
        .rev()
        .find(|start| **start <= at)
        .map(|start| start.date_naive())
}

/// Exact copy of `usage::most_recent_anchored_cycle` (private there):
/// the most recent anchored cycle start at or before `at`.
fn drain_most_recent_anchored_cycle(
    at: DateTime<Utc>,
    anchor: chrono::NaiveDate,
) -> (i32, u32, DateTime<Utc>) {
    let mut year = at.year();
    let mut month = at.month();
    loop {
        let candidate = drain_anchored_date(year, month, anchor.day());
        let candidate_start = candidate
            .and_hms_opt(0, 0, 0)
            .map(|naive| DateTime::<Utc>::from_naive_utc_and_offset(naive, Utc));
        if let Some(start) = candidate_start {
            if start <= at {
                return (year, month, start);
            }
        }
        if month == 1 {
            month = 12;
            year -= 1;
        } else {
            month -= 1;
        }
    }
}

fn drain_anchored_date(year: i32, month: u32, day: u32) -> chrono::NaiveDate {
    let last_day = {
        let next = if month == 12 {
            chrono::NaiveDate::from_ymd_opt(year + 1, 1, 1)
        } else {
            chrono::NaiveDate::from_ymd_opt(year, month + 1, 1)
        }
        .expect("first of next month is always valid");
        (next - chrono::Duration::days(1)).day()
    };
    chrono::NaiveDate::from_ymd_opt(year, month, day.min(last_day))
        .expect("clamped day is always valid")
}

/// Byte-identical to `usage::enforced_counter_key_for_event_type` (see the
/// Fix F2 note in the drain): cycle-anchored keys for subscription tenants,
/// UTC calendar-month keys otherwise.
fn drain_format_counter_key(
    tenant_id: &str,
    event_type: &str,
    at: DateTime<Utc>,
    anchor: Option<chrono::NaiveDate>,
) -> String {
    match anchor {
        Some(anchor) => {
            let (year, month, _cycle_start) = drain_most_recent_anchored_cycle(at, anchor);
            format!("meter:rt:{tenant_id}:{event_type}:c{year}-{month:02}")
        }
        None => format!(
            "meter:rt:{tenant_id}:{event_type}:{}-{:02}",
            at.year(),
            at.month()
        ),
    }
}

pub(crate) async fn drain_pending_metering_events(
    state: &AppState,
    limit: usize,
) -> Result<MeteringDrainResult, String> {
    let mut conn = state.redis.get().await.map_err(|error| {
        format!("Failed to get Redis connection for metering recovery: {error}")
    })?;

    let pending_keys = scan_metering_pending_keys(&mut conn, limit).await?;
    if pending_keys.is_empty() {
        return Ok(MeteringDrainResult {
            processed_count: 0,
            discarded_count: 0,
        });
    }

    let payloads: Vec<Option<String>> = redis::cmd("MGET")
        .arg(&pending_keys)
        .query_async(&mut conn)
        .await
        .map_err(|error| format!("Failed to load pending metering events from Redis: {error}"))?;

    let mut valid_events = Vec::new();
    let mut cleanup_keys = Vec::new();

    for (key, payload) in pending_keys.iter().zip(payloads) {
        let Some(payload) = payload else {
            cleanup_keys.push(key.clone());
            continue;
        };

        match serde_json::from_str::<PendingMeterEvent>(&payload) {
            Ok(event) => valid_events.push(PreparedMeterEvent {
                raw_id: event.id.clone(),
                normalized_id: normalize_metering_event_id(&event.id),
                tenant_id: event.tenant_id,
                event_type: event.event_type,
                quantity: event.quantity,
                timestamp: event.timestamp,
                metadata: event.metadata,
            }),
            Err(error) => {
                warn!(key = %key, error = %error, "discarding malformed pending metering event");
                cleanup_keys.push(key.clone());
            }
        }
    }

    if valid_events.is_empty() {
        delete_redis_keys(&mut conn, &cleanup_keys)
            .await
            .map_err(|error| {
                format!("Failed to clean malformed pending metering events: {error}")
            })?;

        return Ok(MeteringDrainResult {
            processed_count: 0,
            discarded_count: i64::try_from(cleanup_keys.len()).unwrap_or(i64::MAX),
        });
    }

    // Persist new events to the DB.  ON CONFLICT DO NOTHING makes this safe
    // for re-runs after a crash.
    let inserted_ids = insert_metering_events(state, &valid_events).await?;
    let inserted_id_set: HashSet<Uuid> = inserted_ids.into_iter().collect();

    // Atomically delete the pending key and increment the counter per event,
    // guarded by a per-event guard key to prevent double-counting on re-run.
    let mut cleanup_keys_only = Vec::new();
    for key in &cleanup_keys {
        cleanup_keys_only.push(key.clone());
    }
    // Delete stale cleanup keys (malformed events) in bulk.
    if !cleanup_keys_only.is_empty() {
        delete_redis_keys(&mut conn, &cleanup_keys_only)
            .await
            .map_err(|error| {
                format!("Failed to clean malformed pending metering events: {error}")
            })?;
    }

    // P2, resolve EVERY event's enforced counter key from ONE batched
    // subscription-anchor SELECT plus an in-memory memo keyed by
    // (tenant, event_type, event year-month, selected cycle anchor start).
    // Pre-fix this was one `enforced_counter_key_for_event_type` SELECT per
    // event (up to 10,000 every 60s).
    let counter_keys = drain_counter_keys(state, &valid_events).await?;

    // P2, the EVALs stay one atomic script invocation PER EVENT (the guard
    // semantics are unchanged) but are pipelined in bounded chunks: one
    // network round trip per chunk instead of one per event.
    for (chunk, chunk_keys) in valid_events
        .chunks(DRAIN_EVAL_PIPELINE_CHUNK)
        .zip(counter_keys.chunks(DRAIN_EVAL_PIPELINE_CHUNK))
    {
        let mut pipeline = redis::pipe();
        for (event, counter_key) in chunk.iter().zip(chunk_keys) {
            let guard_key = format!("meter:guard:{}", event.normalized_id);
            let pending_key = format!("meter:pending:{}", event.raw_id);
            // Only increment the counter if this event was newly inserted into
            // the DB.  Events that were already there (re-run after crash) will
            // have their counter guard already set, so the Lua script is a no-op
            // for the counter while still cleaning up the pending key.
            pipeline
                .cmd("EVAL")
                .arg(DRAIN_AND_INCR_LUA)
                .arg(3i64) // number of keys
                .arg(&guard_key)
                .arg(counter_key)
                .arg(&pending_key)
                .arg(event.quantity)
                .arg(METERING_PERIOD_TTL_SECONDS);
        }
        #[cfg(test)]
        crate::test_support::query_count::bump("drain.redis.pipeline");
        let _: Vec<i64> = pipeline.query_async(&mut conn).await.map_err(|error| {
            format!(
                "Failed to drain+incr metering events (chunk starting at {}): {error}",
                chunk[0].raw_id
            )
        })?;
    }

    // Clean up any remaining pending keys that belong to re-inserted events.
    // (The Lua script above already DELETEs the pending key for each event,
    // but this is belt-and-suspenders for events that somehow got missed.)
    let remaining_pending: Vec<String> = valid_events
        .iter()
        .map(|e| format!("meter:pending:{}", e.raw_id))
        .collect();
    if !remaining_pending.is_empty() {
        let _: () = redis::cmd("DEL")
            .arg(&remaining_pending)
            .query_async(&mut conn)
            .await
            .map_err(|error| {
                format!("Failed to clean up remaining pending metering events: {error}")
            })?;
    }

    Ok(MeteringDrainResult {
        processed_count: i64::try_from(inserted_id_set.len()).unwrap_or(i64::MAX),
        discarded_count: i64::try_from(cleanup_keys.len()).unwrap_or(i64::MAX),
    })
}

async fn scan_metering_pending_keys(
    conn: &mut deadpool_redis::Connection,
    limit: usize,
) -> Result<Vec<String>, String> {
    let mut cursor = 0_u64;
    let mut keys = Vec::new();

    loop {
        let (next_cursor, batch): (u64, Vec<String>) = redis::cmd("SCAN")
            .arg(cursor)
            .arg("MATCH")
            .arg("meter:pending:*")
            .arg("COUNT")
            .arg(METERING_SCAN_COUNT)
            .query_async(conn)
            .await
            .map_err(|error| format!("Failed to scan pending metering keys: {error}"))?;

        keys.extend(batch);
        if keys.len() >= limit {
            keys.truncate(limit);
            return Ok(keys);
        }

        cursor = next_cursor;
        if cursor == 0 {
            break;
        }
    }

    Ok(keys)
}

async fn delete_redis_keys(
    conn: &mut deadpool_redis::Connection,
    keys: &[String],
) -> Result<(), redis::RedisError> {
    if keys.is_empty() {
        return Ok(());
    }

    let mut pipeline = redis::pipe();
    for key in keys {
        pipeline.del(key).ignore();
    }
    pipeline.query_async(conn).await
}

async fn insert_metering_events(
    state: &AppState,
    events: &[PreparedMeterEvent],
) -> Result<Vec<Uuid>, String> {
    let mut tx = state
        .db
        .begin()
        .await
        .map_err(|error| format!("Failed to start metering recovery transaction: {error}"))?;
    let mut query_builder = QueryBuilder::<Postgres>::new(
        r#"
        INSERT INTO metering_events (id, tenant_id, event_type, quantity, timestamp, metadata)
        "#,
    );

    query_builder.push_values(events, |mut builder, event| {
        builder
            .push_bind(event.normalized_id)
            .push_bind(&event.tenant_id)
            .push_bind(&event.event_type)
            .push_bind(event.quantity)
            .push_bind(event.timestamp)
            .push_bind(&event.metadata);
    });

    query_builder.push(
        r#"
            -- metering_events is RANGE-partitioned by "timestamp" with
            -- PRIMARY KEY (id, timestamp): the arbiter must include the
            -- partition key or PostgreSQL raises 42P10 and the recovery
            -- drain can never persist anything.
            ON CONFLICT (id, "timestamp") DO NOTHING
            RETURNING id
            "#,
    );

    let inserted_ids = query_builder
        .build_query_scalar::<Uuid>()
        .fetch_all(&mut *tx)
        .await
        .map_err(|error| format!("Failed to persist pending metering events: {error}"))?;

    let inserted_set: HashSet<Uuid> = inserted_ids.iter().copied().collect();
    for event in events
        .iter()
        .filter(|event| inserted_set.contains(&event.normalized_id))
    {
        let mut audit_metadata = build_metering_audit_metadata(
            &event.event_type,
            event.quantity,
            event.timestamp,
            &event.metadata,
        );
        audit_metadata.insert("recovered".into(), json!(true));
        audit_metadata.insert("rawEventId".into(), json!(&event.raw_id));

        append_audit_log(
            &mut tx,
            &event.tenant_id,
            "billing.metering_event_recovered",
            "metering_event",
            Some(&event.normalized_id.to_string()),
            Value::Object(audit_metadata),
            Utc::now(),
        )
        .await
        .map_err(|error| format!("Failed to audit recovered metering event: {error}"))?;
    }

    tx.commit()
        .await
        .map_err(|error| format!("Failed to commit metering recovery transaction: {error}"))?;

    Ok(inserted_ids)
}

fn normalize_metering_event_id(raw_id: &str) -> Uuid {
    if let Ok(id) = Uuid::parse_str(raw_id) {
        return id;
    }

    if let Some((_, suffix)) = raw_id.rsplit_once('_') {
        if let Ok(id) = Uuid::parse_str(suffix) {
            return id;
        }
    }

    let digest = Sha256::digest(raw_id.as_bytes());
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x50;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Uuid::from_bytes(bytes)
}

#[derive(Debug, FromRow)]
struct RetryCandidateRow {
    tenant_id: String,
    /// The Mollie customer that owns the stored mandate.
    mollie_customer_id: Option<String>,
    /// The stored-payment token the recurring charge replays
    /// (`mollie_subscriptions.mollie_mandate_id`); `None`
    /// until the customer re-tokenizes.
    mollie_mandate_id: Option<String>,
}

/// Whether the scheduled auto-pay job may charge tenants' saved Mollie
/// payment methods for open invoices. Default: disabled, auto-charging is
/// financially sensitive and must be opted into explicitly via
/// `AUTO_PAY_OPEN_INVOICES=true` (or `1`).
fn auto_pay_open_invoices_enabled() -> bool {
    std::env::var("AUTO_PAY_OPEN_INVOICES")
        .map(|value| value.trim().eq_ignore_ascii_case("true") || value.trim() == "1")
        .unwrap_or(false)
}

/// Nothing is left to retry for this tenant (no open local invoice, or one
/// already covered): clear the scheduled retry so the dunning sweep stops
/// claiming it.
async fn clear_dunning_retry(state: &AppState, tenant_id: &str) -> Result<(), String> {
    sqlx::query(
        r#"
        UPDATE dunning_records
        SET next_retry_at = NULL, updated_at = NOW()
        WHERE tenant_id = $1
        "#,
    )
    .bind(tenant_id)
    .execute(&state.db)
    .await
    .map(|_| ())
    .map_err(|error| format!("Failed to clear next_retry_at for {tenant_id}: {error}"))
}

/// The earliest PENDING invoice per tenant, for a whole retry batch in ONE
/// query (`DISTINCT ON`, deterministic on `created_at, id`). This replaces
/// the per-dunning-row invoice SELECT (P3 fix 5). Tenant ids without an open
/// invoice have no map entry, exactly the old `fetch_optional` → `None`.
async fn load_open_invoices_for_tenants(
    db: &PgPool,
    tenant_ids: &[String],
) -> Result<HashMap<String, (Uuid, String)>, String> {
    let mut invoices = HashMap::new();
    if tenant_ids.is_empty() {
        return Ok(invoices);
    }
    #[cfg(test)]
    crate::test_support::query_count::bump("dunning.invoice_lookup");
    let rows: Vec<(String, Uuid, String)> = sqlx::query_as(
        r#"
        SELECT DISTINCT ON (tenant_id) tenant_id, id, currency
        FROM invoices
        WHERE tenant_id = ANY($1)
          AND status = 'pending'
        ORDER BY tenant_id, created_at ASC, id ASC
        "#,
    )
    .bind(tenant_ids)
    .fetch_all(db)
    .await
    .map_err(|error| format!("Failed to load the tenants' open invoices: {error}"))?;
    for (tenant_id, invoice_id, currency) in rows {
        invoices.insert(tenant_id, (invoice_id, currency));
    }
    Ok(invoices)
}

async fn process_scheduled_retries(
    state: &AppState,
    client: &Client,
) -> Result<RetryResult, String> {
    // Config gate: charging saved payment methods without an explicit
    // user-initiated flow must be opt-in. When disabled we log + skip so
    // dunning retries remain visible in logs without moving money.
    if !auto_pay_open_invoices_enabled() {
        info!(
            "AUTO_PAY_OPEN_INVOICES disabled, skipping scheduled Mollie auto-pay retries \
             (set AUTO_PAY_OPEN_INVOICES=true to enable)"
        );
        return Ok(RetryResult {
            attempted: 0,
            succeeded: 0,
        });
    }

    let rows = sqlx::query_as::<_, RetryCandidateRow>(
        r#"
        SELECT d.tenant_id, s.mollie_customer_id, s.mollie_mandate_id
        FROM dunning_records d
        JOIN mollie_subscriptions s ON s.tenant_id = d.tenant_id
        WHERE d.next_retry_at IS NOT NULL
          AND d.next_retry_at <= NOW()
          AND d.status IN ('warning', 'soft_suspended')
          AND s.status IN ('past_due', 'unpaid')
          -- External audit 15 Oct, H1: a subscription canceled for period end
          -- must never be charged again, even if a dunning retry is queued.
          AND s.cancel_at_period_end = false
          -- Mollie retries its OWN subscription charges; a local mandate
          -- charge here would collect the same period twice. Provider rows
          -- always carry a `sub_...` id; local-only rows do not.
          AND (s.mollie_subscription_id IS NULL OR left(s.mollie_subscription_id, 4) <> 'sub_')
        ORDER BY d.next_retry_at ASC
        LIMIT 50
        "#,
    )
    .fetch_all(&state.db)
    .await
    .map_err(|error| format!("Failed to load scheduled Mollie retries: {error}"))?;

    let mut attempted = 0_i64;
    let mut succeeded = 0_i64;

    // P3 fix 5, resolve every candidate's open local invoice in ONE query
    // (earliest pending invoice per tenant). The old loop issued one invoice
    // SELECT per due dunning row, so a 50-row batch cost 50 round trips
    // before any provider work. The amount is still DERIVED per invoice
    // below (integer cents via `invoice_outstanding_cents`).
    let candidate_tenants: Vec<String> = rows.iter().map(|row| row.tenant_id.clone()).collect();
    let open_invoices = load_open_invoices_for_tenants(&state.db, &candidate_tenants).await?;

    for row in rows {
        attempted += 1;

        let retry_result: Result<(), String> = async {
            // Mollie has no provider-side invoice objects: the retry charges
            // the tenant's OWN open (pending) local invoice against the
            // stored recurring token. No open invoice → nothing to retry.
            let invoice = open_invoices.get(&row.tenant_id).cloned();

            let Some((invoice_id, currency)) = invoice else {
                clear_dunning_retry(state, &row.tenant_id).await?;
                return Ok(());
            };

            // The amount is DERIVED from the local invoice (total minus
            // confirmed payments minus debt-reduction credits), never a
            // provider object, never a client input.
            let outstanding_cents =
                crate::invoices::invoice_outstanding_cents(&state.db, invoice_id)
                    .await
                    .map_err(|error| format!("Failed to derive the invoice outstanding: {error}"))?;
            if outstanding_cents <= 0 {
                // Fully covered since the retry was scheduled (e.g. wallet):
                // the collection ladder settles it, not this sweep.
                clear_dunning_retry(state, &row.tenant_id).await?;
                return Ok(());
            }

            let Some(stored_payment_method_id) = row
                .mollie_mandate_id
                .as_deref()
                .map(str::trim)
                .filter(|token| !token.is_empty())
            else {
                return Err(
                    "the tenant has no stored Mollie recurring token to charge".to_string()
                );
            };

            let Some(customer_id) = row
                .mollie_customer_id
                .as_deref()
                .map(str::trim)
                .filter(|id| !id.is_empty())
            else {
                return Err(
                    "the tenant has no Mollie customer to charge a stored mandate".to_string()
                );
            };

            let response = mollie_charge_stored_payment_method(
                &state.db,
                client,
                &format!("invoice:{invoice_id}"),
                &row.tenant_id,
                customer_id,
                stored_payment_method_id,
                outstanding_cents,
                &currency,
                // One key per invoice: a retry after a lost response must
                // replay the SAME Mollie charge call, not charge twice.
                &format!("autopay_{}", invoice_id.simple()),
                serde_json::json!({
                    "apexmailInvoiceId": invoice_id.to_string(),
                    "source": "dunning_retry",
                }),
            )
            .await?;

            // Bind the charge's payment id to the local invoice (the webhook
            // settles on `reference = invoice:{id}`); an existing different
            // binding is never overwritten.
            let bound = sqlx::query(
                r#"
                UPDATE invoices
                SET mollie_payment_id = $2, updated_at = NOW()
                WHERE id = $1
                  AND status = 'pending'
                  AND mollie_payment_id IS NULL
                "#,
            )
            .bind(invoice_id)
            .bind(&response.payment_id)
            .execute(&state.db)
            .await
            .map_err(|error| format!("Failed to bind the Mollie payment to the invoice: {error}"))?;
            if bound.rows_affected() == 0 {
                warn!(
                    invoice_id = %invoice_id,
                    "dunning retry charge accepted but the invoice already carries a Mollie binding, left untouched"
                );
            }

            mark_payment_recovered(state, &row.tenant_id, Some(&invoice_id.to_string())).await?;
            Ok(())
        }
        .await;

        match retry_result {
            Ok(()) => {
                succeeded += 1;
            }
            Err(error_message) => {
                warn!(tenant_id = %row.tenant_id, error = %error_message, "scheduled Mollie retry failed");
                if let Err(error) = sqlx::query(
                    r#"
                    UPDATE dunning_records
                    SET next_retry_at = NOW() + INTERVAL '1 day', updated_at = NOW()
                    WHERE tenant_id = $1
                    "#,
                )
                .bind(&row.tenant_id)
                .execute(&state.db)
                .await
                {
                    error!(tenant_id = %row.tenant_id, error = %error, "failed to reschedule dunning retry after Mollie retry failure");
                }
            }
        }
    }

    Ok(RetryResult {
        attempted,
        succeeded,
    })
}

/// One usage-alert sweep across every tenant with at least one enabled rule.
///
/// This is the function the periodic billing loop calls (see
/// [`start_periodic_jobs`]); it is PUBLIC so integration tests can drive the
/// exact running evaluation, seeding a rule through the admin API and
/// observing the fired `system_alerts` row, instead of re-implementing the
/// sweep in test code.
pub async fn process_usage_alerts(
    state: &AppState,
    client: &Client,
) -> Result<UsageAlertSweepResult, String> {
    let period_start = month_start(Utc::now());
    let period_end = next_month_start(period_start);

    // ONE fetch of every enabled rule (perf audit 2026-10-18, finding 17):
    // the tenant list is derived from it instead of a separate DISTINCT
    // query, and the within-tenant order (threshold ASC) is preserved.
    let configs: Vec<TenantUsageAlertConfigRow> = sqlx::query_as(
        r#"
        SELECT tenant_id, id, name, metric_type, threshold_percent, notification_channel, severity
        FROM usage_alert_configs
        WHERE enabled = true
        ORDER BY tenant_id ASC, threshold_percent ASC
        "#,
    )
    .fetch_all(&state.db)
    .await
    .map_err(|error| format!("Failed to load usage alert configs: {error}"))?;

    let tenant_ids: Vec<String> = {
        let mut seen = HashSet::new();
        configs
            .iter()
            .map(|config| config.tenant_id.clone())
            .filter(|tenant_id| seen.insert(tenant_id.clone()))
            .collect()
    };
    if tenant_ids.is_empty() {
        return Ok(UsageAlertSweepResult {
            tenants_checked: 0,
            alerts_triggered: 0,
        });
    }

    // ONE grouped usage aggregate for ALL tenants with rules, never one
    // metering SUM per tenant.
    let usage_rows: Vec<(String, String, i64)> = sqlx::query_as(
        r#"
        SELECT tenant_id, event_type, SUM(quantity)::bigint AS total
        FROM metering_events
        WHERE tenant_id = ANY($1)
          AND timestamp >= $2
          AND timestamp <  $3
        GROUP BY tenant_id, event_type
        "#,
    )
    .bind(&tenant_ids)
    .bind(period_start)
    .bind(period_end)
    .fetch_all(&state.db)
    .await
    .map_err(|error| format!("Failed to load grouped usage summaries: {error}"))?;

    // ONE override-aware plan-limits fetch (mirrors usage.rs's
    // TENANT_PLAN_LIMITS_SQL widened to an IN list).
    let limit_rows: Vec<TenantAlertPlanLimitRow> = sqlx::query_as(
        r#"
        SELECT t.id AS tenant_id,
               COALESCE(po.plan, t.plan) AS plan_name,
               p.email_limit,
               p.api_call_limit,
               t.created_at AS tenant_created_at
        FROM tenants t
        LEFT JOIN plan_overrides po
          ON po.tenant_id = t.id
         AND po.active = true
         AND (po.expires_at IS NULL OR po.expires_at > NOW())
        LEFT JOIN plans p ON p.name = COALESCE(po.plan, t.plan)
        WHERE t.id = ANY($1)
        "#,
    )
    .bind(&tenant_ids)
    .fetch_all(&state.db)
    .await
    .map_err(|error| format!("Failed to load grouped plan limits: {error}"))?;
    let mut limits: HashMap<String, (i64, i64)> = HashMap::new();
    for row in limit_rows {
        // A tenant with several active overrides resolves to one row in the
        // per-tenant query (fetch_optional keeps the first), do the same.
        limits
            .entry(row.tenant_id.clone())
            .or_insert_with(|| resolve_alert_plan_limits(&row));
    }

    // ONE webhook-URL fetch for every tenant with rules.
    let settings_rows: Vec<(String, Value)> = sqlx::query_as(
        r#"
        SELECT id, COALESCE(settings, '{}'::jsonb) AS settings
        FROM tenants
        WHERE id = ANY($1)
        "#,
    )
    .bind(&tenant_ids)
    .fetch_all(&state.db)
    .await
    .map_err(|error| format!("Failed to load grouped tenant settings: {error}"))?;
    let webhook_urls: HashMap<String, Option<String>> = settings_rows
        .into_iter()
        .map(|(tenant_id, settings)| {
            let url = settings
                .get("webhookUrl")
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(str::to_string);
            (tenant_id, url)
        })
        .collect();

    // One pooled Redis connection for the whole sweep; the per-config
    // cooldown check/set semantics are unchanged.
    let mut conn = state
        .redis
        .get()
        .await
        .map_err(|error| format!("Failed to get Redis connection for usage alerts: {error}"))?;

    let mut alerts_triggered = 0_i64;
    // Fold the grouped usage rows once: tenant → (emails_sent, api_calls).
    let mut usage: HashMap<String, (i64, i64)> = HashMap::new();
    for (tenant_id, event_type, total) in usage_rows {
        let entry = usage.entry(tenant_id).or_insert((0, 0));
        match event_type.as_str() {
            "emails_sent" => entry.0 = total,
            "api_calls" => entry.1 = total,
            _ => {}
        }
    }
    let mut index = 0_usize;
    while index < configs.len() {
        let tenant_id = configs[index].tenant_id.clone();
        let end = configs[index..]
            .iter()
            .take_while(|config| config.tenant_id == tenant_id)
            .count()
            + index;

        let (emails_sent, api_calls) = usage.get(&tenant_id).copied().unwrap_or((0, 0));
        let (emails_limit, api_calls_limit) = limits.get(&tenant_id).copied().unwrap_or((0, 0));
        let percent_used = if emails_limit > 0 {
            (emails_sent as f64 / emails_limit as f64) * 100.0
        } else {
            0.0
        };
        let usage_summary = crate::types::UsageSummary {
            tenant_id: tenant_id.clone(),
            period_start,
            period_end,
            emails_sent,
            emails_limit,
            api_calls,
            api_calls_limit,
            percent_used,
            metrics: serde_json::Value::Object(serde_json::Map::new()),
        };
        let webhook_url = webhook_urls.get(&tenant_id).cloned().flatten();

        for config in &configs[index..end] {
            let cooldown_key = format!(
                "alert:cooldown:{tenant_id}:{}:{}",
                config.metric_type, config.threshold_percent
            );
            let in_cooldown: bool = match conn.exists(&cooldown_key).await {
                Ok(exists) => exists,
                Err(error) => {
                    // Same blast radius as the per-tenant sweep: a Redis
                    // failure abandons this tenant's remaining rules for the
                    // cycle and the next tick retries.
                    warn!(tenant_id = %tenant_id, error = %error, "Failed to check usage alert cooldown");
                    break;
                }
            };
            if in_cooldown {
                continue;
            }

            let Some((current_value, limit_value)) =
                resolve_usage_alert_metric(&usage_summary, &config.metric_type)
            else {
                continue;
            };

            let current_percent = if limit_value > 0 {
                (current_value as f64 / limit_value as f64) * 100.0
            } else {
                0.0
            };
            if current_percent < f64::from(config.threshold_percent) {
                continue;
            }

            let config = UsageAlertConfigRow {
                id: config.id,
                name: config.name.clone(),
                metric_type: config.metric_type.clone(),
                threshold_percent: config.threshold_percent,
                notification_channel: config.notification_channel.clone(),
                severity: config.severity.clone(),
            };

            // The condition HOLDS: raise the incident on the control-plane alert
            // rail. This is independent of channel delivery on purpose, the CP
            // /alerts page is a first-class destination, so a rule whose webhook
            // is down or absent still fires where operators look. `delivered`
            // below keeps its exact prior semantics (channel acceptance gates the
            // cooldown and `alerts_triggered`), so a failed webhook still retries.
            record_usage_alert_incident(
                state,
                &tenant_id,
                &config,
                current_value,
                limit_value,
                current_percent,
            )
            .await;

            let delivered = send_usage_alert(
                state,
                client,
                &tenant_id,
                webhook_url.as_deref(),
                &config,
                current_value,
                limit_value,
                current_percent,
            )
            .await;

            if !delivered {
                continue;
            }

            let _: () = conn
                .set_ex(&cooldown_key, "1", USAGE_ALERT_COOLDOWN_SECONDS)
                .await
                .map_err(|error| {
                    format!("Failed to set usage alert cooldown for {tenant_id}: {error}")
                })?;

            sqlx::query(
                r#"
                UPDATE usage_alert_configs
                SET last_triggered_at = NOW()
                WHERE id = $1
                "#,
            )
            .bind(config.id)
            .execute(&state.db)
            .await
            .map_err(|error| {
                format!("Failed to update usage alert trigger time for {tenant_id}: {error}")
            })?;

            alerts_triggered += 1;
        }

        index = end;
    }

    Ok(UsageAlertSweepResult {
        tenants_checked: i64::try_from(tenant_ids.len()).unwrap_or(i64::MAX),
        alerts_triggered,
    })
}

/// Persist a fired usage rule into `system_alerts`, the store the control
/// plane's `/alerts` page, SSE stream, and dashboard risk counts read.
///
/// Idempotent per rule: `source = 'usage_alert'` plus `fingerprint = <rule
/// id>` collide on the unique index migration 108 installed
/// (`(source, fingerprint) WHERE source <> 'system' AND fingerprint IS NOT
/// NULL`), so a rule whose condition keeps holding refreshes its single
/// incident row (message / severity / timestamp) instead of piling up a
/// duplicate every sweep. `acknowledged` is deliberately left untouched: an
/// operator's acknowledgement must not be silently reopened by the next
/// sweep.
async fn record_usage_alert_incident(
    state: &AppState,
    tenant_id: &str,
    config: &UsageAlertConfigRow,
    current_value: i64,
    limit_value: i64,
    current_percent: f64,
) {
    let label = config
        .name
        .as_deref()
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .unwrap_or(config.metric_type.as_str());
    let message = format!(
        "Alert rule \"{label}\" fired: {} at {}% of the plan limit ({} / {}).",
        config.metric_type,
        current_percent.round() as i64,
        current_value,
        limit_value,
    );
    if let Err(error) = sqlx::query(
        r#"
        INSERT INTO system_alerts
            (alert_type, message, severity, component, tenant_id, source, fingerprint)
        VALUES ('usage_alert', $1, $2, 'usage', $3, 'usage_alert', $4)
        ON CONFLICT (source, fingerprint)
            WHERE source <> 'system' AND fingerprint IS NOT NULL
        DO UPDATE SET
            message = EXCLUDED.message,
            severity = EXCLUDED.severity,
            tenant_id = EXCLUDED.tenant_id,
            created_at = NOW()
        "#,
    )
    .bind(&message)
    .bind(&config.severity)
    .bind(tenant_id)
    .bind(config.id.to_string())
    .execute(&state.db)
    .await
    {
        warn!(
            tenant_id = %tenant_id,
            rule_id = %config.id,
            error = %error,
            "failed to record usage alert incident in system_alerts"
        );
    }
}

fn resolve_usage_alert_metric(
    usage_summary: &crate::types::UsageSummary,
    metric_type: &str,
) -> Option<(i64, i64)> {
    match metric_type {
        "emails" => Some((usage_summary.emails_sent, usage_summary.emails_limit)),
        "api_calls" => Some((usage_summary.api_calls, usage_summary.api_calls_limit)),
        _ => None,
    }
}

#[allow(clippy::too_many_arguments)]
async fn send_usage_alert(
    state: &AppState,
    client: &Client,
    tenant_id: &str,
    webhook_url: Option<&str>,
    config: &UsageAlertConfigRow,
    current_value: i64,
    limit_value: i64,
    current_percent: f64,
) -> bool {
    let email_enabled = matches!(config.notification_channel.as_str(), "email" | "both");
    let webhook_enabled =
        matches!(config.notification_channel.as_str(), "webhook" | "both") && webhook_url.is_some();
    if !email_enabled && !webhook_enabled {
        return false;
    }

    let rounded_percent = current_percent.round() as i64;
    let email_payload = json!({
        "type": "usage_alert",
        "metricType": config.metric_type,
        "thresholdPercent": config.threshold_percent,
        "currentPercent": rounded_percent,
        "currentValue": current_value,
        "limitValue": limit_value,
    });

    let webhook_payload = json!({
        "event": "usage.threshold_reached",
        "data": {
            "metricType": config.metric_type,
            "thresholdPercent": config.threshold_percent,
            "currentPercent": rounded_percent,
            "currentValue": current_value,
            "limitValue": limit_value,
        },
        "timestamp": Utc::now().to_rfc3339(),
    });

    let mut delivered = false;

    if email_enabled {
        // Enqueue = accepted for delivery: the api-server's notification-queue
        // drainer (`api_server::routes::notification_drain`, spawned in
        // `bin/server.rs`) is the consumer that hands every pending row to the
        // platform mail pipeline and records retries on the row. Before that
        // drainer existed this INSERT was a silent no-op (dogfood 2026-10-06
        // wave B: 64 pending usage_alert rows, oldest 2 days, attempts=0).
        match sqlx::query(
            r#"
            INSERT INTO notification_queue (id, tenant_id, type, payload, status, created_at)
            VALUES (gen_random_uuid(), $1, 'usage_alert', $2, 'pending', NOW())
            "#,
        )
        .bind(tenant_id)
        .bind(&email_payload)
        .execute(&state.db)
        .await
        {
            Ok(_) => delivered = true,
            Err(error) => {
                warn!(tenant_id = %tenant_id, error = %error, "failed to enqueue usage alert email")
            }
        }
    }

    if let Some(webhook_url) = webhook_url.filter(|_| webhook_enabled) {
        match client.post(webhook_url).json(&webhook_payload).send().await {
            Ok(response) if response.status().is_success() => {
                delivered = true;
            }
            Ok(response) => {
                warn!(
                    tenant_id = %tenant_id,
                    status = %response.status(),
                    webhook_url = %webhook_url,
                    "usage alert webhook returned non-success status"
                );
            }
            Err(error) => {
                warn!(tenant_id = %tenant_id, error = %error, webhook_url = %webhook_url, "failed to send usage alert webhook");
            }
        }
    }

    delivered
}

fn month_start(now: DateTime<Utc>) -> DateTime<Utc> {
    now.with_day(1)
        .and_then(|date| date.with_hour(0))
        .and_then(|date| date.with_minute(0))
        .and_then(|date| date.with_second(0))
        .and_then(|date| date.with_nanosecond(0))
        .unwrap_or(now)
}

fn next_month_start(period_start: DateTime<Utc>) -> DateTime<Utc> {
    let shifted = period_start + chrono::Days::new(32);
    month_start(shifted)
}

fn day_start(now: DateTime<Utc>) -> DateTime<Utc> {
    now.with_hour(0)
        .and_then(|date| date.with_minute(0))
        .and_then(|date| date.with_second(0))
        .and_then(|date| date.with_nanosecond(0))
        .unwrap_or(now)
}

fn next_day_start(now: DateTime<Utc>) -> DateTime<Utc> {
    day_start(now) + chrono::Days::new(1)
}

/// Rows per multi-row INSERT of SLA credits.
///
/// PostgreSQL rejects statements with more than 65,535 bound parameters; the
/// SLA credit insert binds 9 columns per row, so 5,000 rows <= 45,000 binds.
/// A breach month can exceed that row count, so the insert must be chunked.
const SLA_CREDIT_INSERT_CHUNK_ROWS: usize = 5_000;

async fn process_monthly_sla_credits(state: &AppState) -> Result<SlaCreditSweepResult, String> {
    process_monthly_sla_credits_chunked(state, SLA_CREDIT_INSERT_CHUNK_ROWS).await
}

/// [`process_monthly_sla_credits`] with an explicit insert chunk size (tests
/// shrink it to cross the chunk boundary; production uses
/// [`SLA_CREDIT_INSERT_CHUNK_ROWS`]).
async fn process_monthly_sla_credits_chunked(
    state: &AppState,
    insert_chunk_rows: usize,
) -> Result<SlaCreditSweepResult, String> {
    let insert_chunk_rows = insert_chunk_rows.max(1);
    let current_month_start = month_start(Utc::now());
    let period_start = month_start(current_month_start - chrono::Days::new(1));
    let period_month = period_start.date_naive();
    let period_end = current_month_start;

    #[cfg(test)]
    crate::test_support::query_count::bump("sla.db.candidates");
    let candidates = sqlx::query_as::<_, SlaMetricCandidateRow>(
        r#"
        SELECT sm.tenant_id,
               sm.uptime_percent::double precision AS uptime_percent,
               p.features
        FROM sla_metrics sm
        JOIN tenants t ON t.id = sm.tenant_id
        -- Override-aware plan resolution, exactly like plans.rs
        -- get_plan_for_tenant: an active admin plan override (e.g. an
        -- Enterprise override on a Scale-tier tenant row) carries the SLA
        -- entitlement and the credit cap of the OVERRIDING plan, joining
        -- only on t.plan silently dropped the override's SLA features.
        LEFT JOIN plan_overrides po
          ON po.tenant_id = t.id
         AND po.active = true
         AND (po.expires_at IS NULL OR po.expires_at > NOW())
        JOIN plans p ON p.name = COALESCE(po.plan, t.plan)
        WHERE sm.period_month = $1
          AND t.status = 'active'
        ORDER BY sm.tenant_id
        "#,
    )
    .bind(period_month)
    .fetch_all(&state.db)
    .await
    .map_err(|error| format!("Failed to load SLA metric candidates: {error}"))?;

    // P3: the invoice inputs for EVERY candidate are loaded in ONE grouped
    // query. Before this, each breaching candidate issued its own currency
    // lookup (latest paid invoice) and amount SUM, two round trips per row.
    // Only candidates that can actually reach the credit insert need them.
    let invoice_tenants: Vec<String> = candidates
        .iter()
        .filter(|candidate| {
            feature_flag_enabled(&candidate.features, &["slaGuarantee", "sla_guarantee"])
                && candidate.uptime_percent < SLA_AVAILABILITY_TARGET
                && sla_credit_percentage_for_breach(
                    SLA_AVAILABILITY_TARGET - candidate.uptime_percent,
                ) > 0
        })
        .map(|candidate| candidate.tenant_id.clone())
        .collect();

    let mut invoice_stats: HashMap<String, (String, i64)> = HashMap::new();
    if !invoice_tenants.is_empty() {
        #[cfg(test)]
        crate::test_support::query_count::bump("sla.db.invoice_aggregate");
        // Currency = the LATEST paid invoice's currency (the per-row
        // `ORDER BY created_at DESC LIMIT 1`); amount = the sum of that
        // currency's paid invoices in the period. `COALESCE(total, amount)` is
        // the same fallback the per-row SUM used; every value stays BIGINT
        // cents (integer-cent semantics, no f64).
        let rows: Vec<(String, String, i64)> = sqlx::query_as(
            r#"
            WITH eligible AS (
                SELECT tenant_id,
                       UPPER(currency) AS currency,
                       COALESCE(total, amount)::bigint AS amount_cents,
                       created_at
                FROM invoices
                WHERE status = 'paid'
                  AND period_start >= $2
                  AND period_end <= $3
                  AND tenant_id = ANY($1)
            ),
            picked AS (
                SELECT DISTINCT ON (tenant_id) tenant_id, currency
                FROM eligible
                ORDER BY tenant_id, created_at DESC
            ),
            totals AS (
                SELECT tenant_id, currency, SUM(amount_cents)::bigint AS amount_cents
                FROM eligible
                GROUP BY tenant_id, currency
            )
            SELECT p.tenant_id, p.currency, COALESCE(t.amount_cents, 0)::bigint
            FROM picked p
            LEFT JOIN totals t
              ON t.tenant_id = p.tenant_id
             AND t.currency = p.currency
            "#,
        )
        .bind(&invoice_tenants)
        .bind(period_start)
        .bind(period_end)
        .fetch_all(&state.db)
        .await
        .map_err(|error| format!("Failed to load SLA invoice aggregates: {error}"))?;
        invoice_stats.extend(
            rows.into_iter()
                .map(|(tenant_id, currency, amount_cents)| (tenant_id, (currency, amount_cents))),
        );
    }

    // Compute every credit in memory (integer cents only), then persist the
    // whole pass in ONE transaction.
    struct PendingSlaCredit {
        tenant_id: String,
        breach_percent: f64,
        credit_percent: i32,
        credit_amount: i64,
        currency: String,
    }
    let mut pending: Vec<PendingSlaCredit> = Vec::new();

    for candidate in &candidates {
        if !feature_flag_enabled(&candidate.features, &["slaGuarantee", "sla_guarantee"]) {
            continue;
        }

        if candidate.uptime_percent >= SLA_AVAILABILITY_TARGET {
            continue;
        }

        let breach_percent = SLA_AVAILABILITY_TARGET - candidate.uptime_percent;
        let credit_percent = sla_credit_percentage_for_breach(breach_percent);
        if credit_percent == 0 {
            continue;
        }

        // Fix I6, SLA credits are cash-equivalent: base them only on
        // invoices that were actually paid, and credit in the invoice's own
        // currency (mixed-currency totals must never be summed together).
        // Defaults: no paid invoice → EUR, zero cents → no credit.
        let (invoice_currency, invoice_amount_cents) = invoice_stats
            .get(&candidate.tenant_id)
            .cloned()
            .unwrap_or_else(|| ("EUR".into(), 0));

        // Money invariant: integer cents, half-up rounding, no f64 in the
        // computation path (the previous `(cents as f64) * pct/100` drifted
        // for large cent values).
        let credit_amount =
            percent_of_cents_half_up(invoice_amount_cents, i64::from(credit_percent));
        if credit_amount <= 0 {
            continue;
        }

        // Enforce plan-specific SLA credit cap (e.g. Scale = 10 %, Enterprise = 25 %).
        // The `sla_credit_percentage` field in `PlanFeatures` defines the maximum
        // percentage of the monthly invoice that may be credited.
        let cap_percent = candidate
            .features
            .get("slaCreditPercentage")
            .and_then(Value::as_i64)
            .or_else(|| {
                candidate
                    .features
                    .get("sla_credit_percentage")
                    .and_then(Value::as_i64)
            })
            .unwrap_or(100); // default: no cap below 100 %

        let credit_amount = if cap_percent < 100 {
            let max_credit = percent_of_cents_half_up(invoice_amount_cents, cap_percent);
            credit_amount.min(max_credit)
        } else {
            credit_amount
        };
        if credit_amount <= 0 {
            continue;
        }

        pending.push(PendingSlaCredit {
            tenant_id: candidate.tenant_id.clone(),
            breach_percent,
            credit_percent,
            credit_amount,
            currency: invoice_currency,
        });
    }

    let mut credits_created = 0_i64;
    if !pending.is_empty() {
        // Fix F5, the old NOT-EXISTS check-then-insert could double-run
        // across replicas/restarts (sla_credits has no unique constraint on
        // (tenant_id, period_month)). The batch takes the SAME per-(tenant,
        // period) advisory locks, in ONE statement and sorted order (no
        // deadlock between two sweeping replicas), then checks existence and
        // inserts under those locks in ONE transaction.
        let mut tx = state
            .db
            .begin()
            .await
            .map_err(|error| format!("Failed to begin SLA credit batch: {error}"))?;

        let mut lock_keys: Vec<String> = pending
            .iter()
            .map(|credit| {
                format!(
                    "sla_credit:{}:{}-{:02}",
                    credit.tenant_id,
                    period_month.year(),
                    period_month.month()
                )
            })
            .collect();
        lock_keys.sort();
        lock_keys.dedup();
        #[cfg(test)]
        crate::test_support::query_count::bump("sla.db.lock_batch");
        sqlx::query(
            "SELECT pg_advisory_xact_lock(hashtextextended(lock_key, 0))
               FROM (SELECT unnest($1::text[]) AS lock_key ORDER BY 1) AS locks",
        )
        .bind(&lock_keys)
        .execute(&mut *tx)
        .await
        .map_err(|error| format!("Failed to acquire SLA credit locks: {error}"))?;

        let tenant_ids: Vec<String> = pending
            .iter()
            .map(|credit| credit.tenant_id.clone())
            .collect();
        #[cfg(test)]
        crate::test_support::query_count::bump("sla.db.existing_batch");
        let already: Vec<String> = sqlx::query_scalar(
            "SELECT tenant_id FROM sla_credits WHERE period_month = $1 AND tenant_id = ANY($2)",
        )
        .bind(period_month)
        .bind(&tenant_ids)
        .fetch_all(&mut *tx)
        .await
        .map_err(|error| format!("Failed to re-check existing SLA credits: {error}"))?;
        let already: HashSet<String> = already.into_iter().collect();

        let to_insert: Vec<&PendingSlaCredit> = pending
            .iter()
            .filter(|credit| !already.contains(&credit.tenant_id))
            .collect();

        if !to_insert.is_empty() {
            for chunk in to_insert.chunks(insert_chunk_rows) {
                #[cfg(test)]
                crate::test_support::query_count::bump("sla.db.insert_batch");
                let mut builder = QueryBuilder::<Postgres>::new(
                    "INSERT INTO sla_credits (
                        id, tenant_id, period_month, breach_percent, credit_percent,
                        credit_amount, currency, status, created_at
                     ) ",
                );
                builder.push_values(chunk, |mut row, credit| {
                    row.push_bind(Uuid::new_v4())
                        .push_bind(credit.tenant_id.clone())
                        .push_bind(period_month)
                        .push_bind(credit.breach_percent)
                        .push_bind(credit.credit_percent)
                        .push_bind(credit.credit_amount)
                        .push_bind(credit.currency.clone())
                        .push_bind("pending")
                        .push("NOW()");
                });
                let inserted = builder
                    .build()
                    .execute(&mut *tx)
                    .await
                    .map_err(|error| format!("Failed to insert SLA credits: {error}"))?;
                credits_created += i64::try_from(inserted.rows_affected()).unwrap_or(i64::MAX);
            }
        }

        tx.commit()
            .await
            .map_err(|error| format!("Failed to commit SLA credit batch: {error}"))?;
    }

    Ok(SlaCreditSweepResult {
        tenants_checked: i64::try_from(candidates.len()).unwrap_or(i64::MAX),
        credits_created,
    })
}

fn feature_flag_enabled(features: &Value, keys: &[&str]) -> bool {
    keys.iter()
        .any(|key| features.get(*key).and_then(Value::as_bool).unwrap_or(false))
}

/// `percent` of `cents`, rounded half-up, computed in integer arithmetic
/// (i128 intermediate so cent×percent cannot overflow). Used by the SLA
/// credit path, money computation must never route through f64.
pub(crate) fn percent_of_cents_half_up(cents: i64, percent: i64) -> i64 {
    if cents <= 0 || percent <= 0 {
        return 0;
    }
    let numerator = i128::from(cents) * i128::from(percent) + 50;
    i64::try_from(numerator.div_euclid(100)).unwrap_or(i64::MAX)
}

fn sla_credit_percentage_for_breach(breach_percent: f64) -> i32 {
    if breach_percent >= 5.0 {
        100
    } else if breach_percent >= 1.0 {
        50
    } else if breach_percent >= 0.5 {
        25
    } else if breach_percent >= 0.1 {
        10
    } else {
        0
    }
}

async fn process_dedicated_ip_billing(
    state: &AppState,
    client: &Client,
) -> Result<DedicatedIpSyncResult, String> {
    let charged = process_pending_dedicated_ip_charges(state, client).await?;
    let canceled = process_pending_dedicated_ip_cancels(state, client).await?;

    Ok(DedicatedIpSyncResult { charged, canceled })
}

async fn process_pending_dedicated_ip_charges(
    state: &AppState,
    client: &Client,
) -> Result<i64, String> {
    let Some(price_cents) = dedicated_ip_price_cents() else {
        return Ok(0);
    };

    // Fix I7, the FOR UPDATE SKIP LOCKED claim previously ran in
    // autocommit mode, so the row locks were released immediately and two
    // maintenance ticks could double-charge the same IP. The fetch and the
    // per-row processing now share one explicit transaction; each row runs
    // inside a SAVEPOINT so one failure does not roll back the others.
    // Double-charging remains impossible even if the transaction is lost
    // after the Mollie call thanks to the Idempotency-Key.
    let mut tx = state
        .db
        .begin()
        .await
        .map_err(|error| format!("Failed to begin dedicated IP charge transaction: {error}"))?;

    let rows = match sqlx::query_as::<_, DedicatedIpPendingRow>(
        r#"
        SELECT id, tenant_id, ip_address, mollie_mandate_id
        FROM dedicated_ips
        WHERE billing_status = 'pending_charge'
          AND (billing_retry_after IS NULL OR billing_retry_after <= NOW())
        ORDER BY created_at ASC
        LIMIT 50
        FOR UPDATE SKIP LOCKED
        "#,
    )
    .fetch_all(&mut *tx)
    .await
    {
        Ok(rows) => rows,
        Err(error) if is_missing_table_error(&error) => {
            log_missing_dedicated_ip_table_once();
            return Ok(0);
        }
        Err(error) => {
            return Err(format!(
                "Failed to load pending dedicated IP charges: {error}"
            ));
        }
    };

    let mut processed = 0_i64;
    for row in rows {
        let mut savepoint = match (*tx).begin().await {
            Ok(savepoint) => savepoint,
            Err(error) => {
                warn!(ip_id = %row.id, error = %error, "failed to open dedicated IP savepoint");
                continue;
            }
        };

        match charge_dedicated_ip(&mut savepoint, &state.db, client, &row, price_cents).await {
            Ok(()) => {
                if let Err(error) = savepoint.commit().await {
                    warn!(ip_id = %row.id, error = %error, "failed to commit dedicated IP savepoint");
                    continue;
                }
                processed += 1;
            }
            Err(error_message) => {
                if let Err(rollback_error) = savepoint.rollback().await {
                    warn!(ip_id = %row.id, error = %rollback_error, "failed to roll back dedicated IP savepoint");
                }
                // Record the backoff on the outer transaction (outside the
                // rolled-back savepoint) so failed rows are retried later.
                update_dedicated_ip_retry_metadata(&mut tx, &row.id).await;
                warn!(tenant_id = %row.tenant_id, ip_id = %row.id, ip_address = %row.ip_address, error = %error_message, "failed to charge the dedicated IP add-on via Mollie");
            }
        }
    }

    tx.commit()
        .await
        .map_err(|error| format!("Failed to commit dedicated IP charge transaction: {error}"))?;

    Ok(processed)
}

async fn process_pending_dedicated_ip_cancels(
    state: &AppState,
    client: &Client,
) -> Result<i64, String> {
    // Fix I7, same explicit-transaction claim as the charge path.
    let mut tx = state
        .db
        .begin()
        .await
        .map_err(|error| format!("Failed to begin dedicated IP cancel transaction: {error}"))?;

    let rows = match sqlx::query_as::<_, DedicatedIpPendingRow>(
        r#"
        SELECT id, tenant_id, ip_address, mollie_mandate_id
        FROM dedicated_ips
        WHERE billing_status = 'pending_cancel'
        ORDER BY updated_at ASC
        LIMIT 50
        FOR UPDATE SKIP LOCKED
        "#,
    )
    .fetch_all(&mut *tx)
    .await
    {
        Ok(rows) => rows,
        Err(error) if is_missing_table_error(&error) => {
            log_missing_dedicated_ip_table_once();
            return Ok(0);
        }
        Err(error) => {
            return Err(format!(
                "Failed to load pending dedicated IP cancels: {error}"
            ));
        }
    };

    let mut processed = 0_i64;
    for row in rows {
        let mut savepoint = match (*tx).begin().await {
            Ok(savepoint) => savepoint,
            Err(error) => {
                warn!(ip_id = %row.id, error = %error, "failed to open dedicated IP cancel savepoint");
                continue;
            }
        };

        match cancel_dedicated_ip_billing(&mut savepoint, client, &row).await {
            Ok(()) => {
                if let Err(error) = savepoint.commit().await {
                    warn!(ip_id = %row.id, error = %error, "failed to commit dedicated IP cancel savepoint");
                    continue;
                }
                processed += 1;
            }
            Err(error_message) => {
                if let Err(rollback_error) = savepoint.rollback().await {
                    warn!(ip_id = %row.id, error = %rollback_error, "failed to roll back dedicated IP cancel savepoint");
                }
                warn!(tenant_id = %row.tenant_id, ip_id = %row.id, ip_address = %row.ip_address, error = %error_message, "failed to finalize the dedicated IP add-on cancel");
            }
        }
    }

    tx.commit()
        .await
        .map_err(|error| format!("Failed to commit dedicated IP cancel transaction: {error}"))?;

    Ok(processed)
}

/// Charge one dedicated-IP add-on activation via Mollie.
///
/// Mollie has no subscription-item object: the add-on is OUR row and the
/// charge is a recurring `POST /payments` against the tenant subscription's
/// stored token, priced ONLY from `DEDICATED_IP_PRICE_CENTS` (cents), with
/// `reference = dedicated_ip:{dedicated_ips.id}` (the add-on's own identity —
/// there is no local invoice for an add-on activation, and the base
/// subscription id is shared by every add-on of the tenant).
async fn charge_dedicated_ip(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    db: &sqlx::PgPool,
    client: &Client,
    row: &DedicatedIpPendingRow,
    price_cents: i64,
) -> Result<(), String> {
    let subscription = sqlx::query_as::<_, TenantMollieSubscriptionRow>(
        r#"
        SELECT mollie_customer_id, mollie_mandate_id
        FROM mollie_subscriptions
        WHERE tenant_id = $1
          AND status = 'active'
        ORDER BY created_at DESC
        LIMIT 1
        "#,
    )
    .bind(&row.tenant_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|error| format!("Failed to load tenant Mollie subscription: {error}"))?;

    let Some(subscription) = subscription else {
        return Err("No active Mollie subscription for tenant".to_string());
    };
    let Some(stored_payment_method_id) = subscription
        .mollie_mandate_id
        .as_deref()
        .map(str::trim)
        .filter(|token| !token.is_empty())
    else {
        return Err(
            "the tenant's active Mollie subscription carries no stored recurring token".to_string(),
        );
    };

    let Some(customer_id) = subscription
        .mollie_customer_id
        .as_deref()
        .map(str::trim)
        .filter(|id| !id.is_empty())
    else {
        return Err("the tenant's Mollie subscription carries no customer id".to_string());
    };

    let response = mollie_charge_stored_payment_method(
        db,
        client,
        &format!("dedicated_ip:{}", row.id),
        &row.tenant_id,
        customer_id,
        stored_payment_method_id,
        price_cents,
        "EUR",
        // Deterministic per add-on activation, time-independent: a crashed
        // sweep whose transaction is lost REPLAYS this key instead of
        // charging the add-on twice on the retry.
        &dedicated_ip_idempotency_key(&row.id),
        serde_json::json!({
            "apexmailIpId": row.id,
            "apexmailTenantId": row.tenant_id,
            "type": "dedicated_ip_addon",
        }),
    )
    .await?;

    sqlx::query(
        r#"
        UPDATE dedicated_ips
        SET billing_status = 'active',
            mollie_mandate_id = $2,
            billing_started_at = NOW(),
            billing_failure_count = 0,
            billing_retry_after = NULL,
            updated_at = NOW()
        WHERE id = $1
        "#,
    )
    .bind(&row.id)
    // The activation charge's payment id is the add-on's provider-side
    // reference (there is no subscription object to store).
    .bind(response.payment_id)
    .execute(&mut **tx)
    .await
    .map_err(|error| format!("Failed to mark dedicated IP billing active: {error}"))?;

    Ok(())
}

/// Stop billing a dedicated-IP add-on. Mollie has no provider-side
/// subscription-item object to delete and NO automatic future charges for
/// the add-on (each activation is charged by our own sweep), so ending the
/// add-on is a LOCAL transition: the row flips to `canceled` and no further
/// sweep claims it. The recorded activation charge stays untouched.
async fn cancel_dedicated_ip_billing(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    _client: &Client,
    row: &DedicatedIpPendingRow,
) -> Result<(), String> {
    if let Some(provider_reference) = &row.mollie_mandate_id {
        info!(
            ip_id = %row.id,
            provider_reference = %provider_reference,
            "cancel: no provider-side dedicated IP object exists under Mollie, the add-on stops with its local row"
        );
    }

    sqlx::query(
        r#"
        UPDATE dedicated_ips
        SET billing_status = 'canceled',
            billing_ended_at = NOW(),
            billing_retry_after = NULL,
            updated_at = NOW()
        WHERE id = $1
        "#,
    )
    .bind(&row.id)
    .execute(&mut **tx)
    .await
    .map_err(|error| format!("Failed to finalize dedicated IP billing cancel: {error}"))?;

    Ok(())
}

/// The dedicated-IP activation charge's Idempotency-Key: deterministic per
/// add-on and bounded to Mollie's 64-char limit (production ids are 36-char
/// UUIDs, `dedicated_ip_` + 36 = 49; anything longer is folded into a
/// fixed-width digest).
fn dedicated_ip_idempotency_key(ip_id: &str) -> String {
    let key = format!("dedicated_ip_{ip_id}");
    if key.len() <= 64 {
        return key;
    }
    let digest = Sha256::digest(ip_id.as_bytes());
    format!("dedicated_ip_{}", hex::encode(&digest[..24]))
}

/// The dedicated-IP add-on price in CENTS (minor units). The canonical
/// price lives in `platform-catalog` (the plan's rule: prices change only at
/// the source); `DEDICATED_IP_PRICE_CENTS` stays as an explicit operator
/// override. An explicit non-positive override (0 or negative) disables the
/// sweep; a missing/blank/unparseable value falls back to the catalog price
/// (and the unparseable case warns loudly).
fn dedicated_ip_price_cents() -> Option<i64> {
    match std::env::var("DEDICATED_IP_PRICE_CENTS") {
        Ok(raw) => {
            let trimmed = raw.trim();
            if trimmed.is_empty() {
                return Some(platform_catalog::DEDICATED_IP_FIRST_CENTS);
            }
            match trimmed.parse::<i64>() {
                Ok(cents) if cents > 0 => Some(cents),
                Ok(_) => None,
                Err(_) => {
                    tracing::warn!(
                        value = %trimmed,
                        "DEDICATED_IP_PRICE_CENTS is not an integer, falling back to the platform-catalog price"
                    );
                    Some(platform_catalog::DEDICATED_IP_FIRST_CENTS)
                }
            }
        }
        Err(_) => Some(platform_catalog::DEDICATED_IP_FIRST_CENTS),
    }
}

fn is_missing_table_error(error: &sqlx::Error) -> bool {
    error
        .as_database_error()
        .and_then(|db_error| db_error.code())
        .is_some_and(|code| code == "42P01")
}

fn log_missing_dedicated_ip_table_once() {
    if DEDICATED_IP_TABLE_MISSING_LOGGED
        .compare_exchange(false, true, Ordering::Relaxed, Ordering::Relaxed)
        .is_ok()
    {
        warn!(table = "dedicated_ips", "dedicated IP table missing; skipping dedicated IP billing sync until migrations are applied");
    }
}

async fn update_dedicated_ip_retry_metadata(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    ip_id: &str,
) {
    if let Err(error) = sqlx::query(
        r#"
        UPDATE dedicated_ips
        SET billing_failure_count = COALESCE(billing_failure_count, 0) + 1,
            billing_retry_after = NOW() + (
                LEAST(POWER(2, LEAST(COALESCE(billing_failure_count, 0), 5)), 30) || ' minutes'
            )::interval,
            updated_at = NOW()
        WHERE id = $1
        "#,
    )
    .bind(ip_id)
    .execute(&mut **tx)
    .await
    {
        warn!(ip_id = %ip_id, error = %error, "failed to update dedicated IP retry metadata");
    }
}

async fn process_cost_margin_checks(state: &AppState) -> Result<CostMarginSweepResult, String> {
    let period_start = month_start(Utc::now());
    let period_end = next_month_start(period_start);

    // ONE grouped query for the entire fleet (perf audit 2026-10-18,
    // finding 15): every ACTIVE tenant's cost/revenue summary in a single
    // GROUP BY over `tenant_costs`, the old loop paid one full SUM per
    // tenant. The LEFT JOIN keeps zero-activity tenants in the result, so
    // `checked` and their Healthy classification match the per-tenant SUM
    // (COALESCE zeros) exactly.
    let summaries: Vec<TenantGroupedCostSummaryRow> = match sqlx::query_as(
        r#"
        SELECT t.id AS tenant_id,
               COALESCE(SUM(tc.storage_cost), 0)::bigint AS storage_cost,
               COALESCE(SUM(tc.bandwidth_cost), 0)::bigint AS bandwidth_cost,
               COALESCE(SUM(tc.compute_cost), 0)::bigint AS compute_cost,
               COALESCE(SUM(tc.dedicated_ip_cost), 0)::bigint AS dedicated_ip_cost,
               COALESCE(SUM(tc.total_cost), 0)::bigint AS total_cost,
               COALESCE(SUM(tc.revenue), 0)::bigint AS revenue
        FROM tenants t
        LEFT JOIN tenant_costs tc
          ON tc.tenant_id = t.id
         AND tc.recorded_at >= $1
         AND tc.recorded_at < $2
        WHERE t.status = 'active'
        GROUP BY t.id
        ORDER BY t.id
        "#,
    )
    .bind(period_start.date_naive())
    .bind(period_end.date_naive())
    .fetch_all(&state.db)
    .await
    {
        Ok(summaries) => summaries,
        // Degraded mode (fault-injection contract
        // `cost_margin_status_arms_alert_dedup_and_throttle`): a broken
        // `tenant_costs` table must NOT fail the sweep, it degrades to
        // per-tenant isolation, one warn per unreachable tenant.
        Err(error) => {
            warn!(error = %error, "grouped tenant cost summary load failed; falling back to per-tenant cost checks");
            return process_cost_margin_checks_per_tenant(state).await;
        }
    };

    let mut warnings = 0_i64;
    let mut critical = 0_i64;
    let mut healthy: Vec<(String, Option<f64>)> = Vec::new();

    for row in &summaries {
        let tenant_id = &row.tenant_id;
        let summary = &row.summary;
        // The decision logic is the per-tenant rule (see
        // `evaluate_tenant_cost_margin`); only the DB SUM is grouped away.
        // Tenants whose margin actually breaches pay the full per-tenant
        // alert/throttle path, those are the rare rows the sweep exists
        // for. Healthy tenants get their throttle cleared and status cached
        // through ONE pipelined Redis round trip for the whole batch
        // instead of two round trips per tenant.
        if summary.total_cost == 0 && summary.revenue == 0 {
            healthy.push((tenant_id.clone(), None));
            continue;
        }
        let margin_percent = if summary.revenue > 0 {
            ((summary.revenue - summary.total_cost) as f64 / summary.revenue as f64) * 100.0
        } else {
            0.0
        };
        if margin_percent < COST_MARGIN_CRITICAL_THRESHOLD
            || margin_percent < COST_MARGIN_WARNING_THRESHOLD
        {
            match evaluate_tenant_cost_margin(state, tenant_id, summary).await {
                Ok(CostMarginStatus::Warning) => warnings += 1,
                Ok(CostMarginStatus::Critical) => critical += 1,
                Ok(CostMarginStatus::Healthy) => {}
                Err(error_message) => {
                    warn!(tenant_id = %tenant_id, error = %error_message, "failed to evaluate tenant cost margin");
                }
            }
        } else {
            healthy.push((tenant_id.clone(), Some(margin_percent)));
        }
    }

    cache_healthy_cost_margins_batch(state, &healthy).await;

    Ok(CostMarginSweepResult {
        checked: i64::try_from(summaries.len()).unwrap_or(i64::MAX),
        warnings,
        critical,
    })
}

/// The healthy tail of the cost-margin sweep in ONE Redis round trip: clear
/// each tenant's (stale) cost throttle and cache its evaluated status, the
/// exact writes `clear_cost_throttling` + `cache_cost_margin_status` perform
/// per tenant, pipelined. A throttle that actually existed (a recovery) still
/// gets its per-tenant audit event, in tenant order, exactly as before.
async fn cache_healthy_cost_margins_batch(state: &AppState, healthy: &[(String, Option<f64>)]) {
    if healthy.is_empty() {
        return;
    }
    let mut conn = match state.redis.get().await {
        Ok(conn) => conn,
        Err(error) => {
            warn!(count = healthy.len(), error = %error, "failed to get Redis connection for cost margin sweep");
            return;
        }
    };

    let mut pipeline = redis::pipe();
    for (tenant_id, margin_percent) in healthy {
        // Per-tenant DEL then SETEX, the exact command order the per-row
        // clear/cache used, and the order the results come back in.
        pipeline.del(cost_throttle_key(tenant_id));
        let payload = json!({
            "status": CostMarginStatus::Healthy.as_str(),
            "margin": margin_percent,
            "checkedAt": Utc::now().to_rfc3339(),
        })
        .to_string();
        pipeline.set_ex(format!("cost:status:{tenant_id}"), payload, 60 * 60);
    }
    let results: Vec<(usize, ())> = match pipeline.query_async(&mut conn).await {
        Ok(results) => results,
        Err(error) => {
            warn!(count = healthy.len(), error = %error, "failed to refresh healthy cost margins in Redis");
            return;
        }
    };

    for ((tenant_id, _), (deleted, _)) in healthy.iter().zip(results) {
        if deleted > 0 {
            info!(tenant_id = %tenant_id, "cleared cost-protection rate limit");
            record_cost_throttle_audit(
                state,
                tenant_id,
                "billing.cost_throttle.cleared",
                json!({ "reason": "margin_recovered" }),
            )
            .await;
        }
    }
}

/// The pre-batching shape, kept as the DEGRADED path: when the grouped
/// summary cannot be loaded (e.g. `tenant_costs` missing during a migration
/// window), the sweep falls back to one query per active tenant so a broken
/// table isolates per-tenant failures instead of failing the whole fleet —
/// exactly the semantics the batching replaced.
async fn process_cost_margin_checks_per_tenant(
    state: &AppState,
) -> Result<CostMarginSweepResult, String> {
    let tenant_ids: Vec<String> = sqlx::query_scalar(
        r#"
        SELECT id
        FROM tenants
        WHERE status = 'active'
        ORDER BY id
        "#,
    )
    .fetch_all(&state.db)
    .await
    .map_err(|error| format!("Failed to load active tenants for cost checks: {error}"))?;

    let mut warnings = 0_i64;
    let mut critical = 0_i64;

    for tenant_id in &tenant_ids {
        match check_tenant_cost_margin(state, tenant_id).await {
            Ok(CostMarginStatus::Warning) => warnings += 1,
            Ok(CostMarginStatus::Critical) => critical += 1,
            Ok(CostMarginStatus::Healthy) => {}
            Err(error_message) => {
                warn!(tenant_id = %tenant_id, error = %error_message, "failed to evaluate tenant cost margin");
            }
        }
    }

    Ok(CostMarginSweepResult {
        checked: i64::try_from(tenant_ids.len()).unwrap_or(i64::MAX),
        warnings,
        critical,
    })
}

/// Per-tenant loader + decision: the degraded path above and the direct
/// recovery/parity checks the test-suite drives run through the same decision
/// the batched sweep runs. The decision half is `evaluate_tenant_cost_margin`.
async fn check_tenant_cost_margin(
    state: &AppState,
    tenant_id: &str,
) -> Result<CostMarginStatus, String> {
    let period_start = month_start(Utc::now());
    let period_end = next_month_start(period_start);

    let summary = sqlx::query_as::<_, TenantCostSummaryRow>(
        r#"
        SELECT
            COALESCE(SUM(storage_cost), 0)::bigint AS storage_cost,
            COALESCE(SUM(bandwidth_cost), 0)::bigint AS bandwidth_cost,
            COALESCE(SUM(compute_cost), 0)::bigint AS compute_cost,
            COALESCE(SUM(dedicated_ip_cost), 0)::bigint AS dedicated_ip_cost,
            COALESCE(SUM(total_cost), 0)::bigint AS total_cost,
            COALESCE(SUM(revenue), 0)::bigint AS revenue
        FROM tenant_costs
        WHERE tenant_id = $1
          AND recorded_at >= $2
          AND recorded_at < $3
        "#,
    )
    .bind(tenant_id)
    .bind(period_start.date_naive())
    .bind(period_end.date_naive())
    .fetch_one(&state.db)
    .await
    .map_err(|error| format!("Failed to load tenant cost summary for {tenant_id}: {error}"))?;

    evaluate_tenant_cost_margin(state, tenant_id, &summary).await
}

/// The per-tenant cost-margin decision, unchanged from the original
/// `check_tenant_cost_margin` body: zero activity is Healthy, else the margin
/// percent classifies Critical (< 10%) / Warning (< 20%) / Healthy, with the
/// alert, throttle and cache side effects below. The grouped sweep calls this
/// ONLY for breaching tenants; their summaries come from the grouped query.
async fn evaluate_tenant_cost_margin(
    state: &AppState,
    tenant_id: &str,
    summary: &TenantCostSummaryRow,
) -> Result<CostMarginStatus, String> {
    if summary.total_cost == 0 && summary.revenue == 0 {
        clear_cost_throttling(state, tenant_id).await;
        cache_cost_margin_status(state, tenant_id, CostMarginStatus::Healthy, None).await;
        return Ok(CostMarginStatus::Healthy);
    }

    let margin_percent = if summary.revenue > 0 {
        ((summary.revenue - summary.total_cost) as f64 / summary.revenue as f64) * 100.0
    } else {
        0.0
    };

    let status = if margin_percent < COST_MARGIN_CRITICAL_THRESHOLD {
        let alert_type = if margin_percent < 0.0 {
            "negative_margin"
        } else {
            "low_margin"
        };
        create_cost_margin_alert(
            state,
            tenant_id,
            alert_type,
            COST_MARGIN_CRITICAL_THRESHOLD,
            margin_percent,
            summary,
        )
        .await?;
        apply_cost_throttling(state, tenant_id, margin_percent).await;
        CostMarginStatus::Critical
    } else if margin_percent < COST_MARGIN_WARNING_THRESHOLD {
        create_cost_margin_alert(
            state,
            tenant_id,
            "low_margin",
            COST_MARGIN_WARNING_THRESHOLD,
            margin_percent,
            summary,
        )
        .await?;
        CostMarginStatus::Warning
    } else {
        CostMarginStatus::Healthy
    };

    if status != CostMarginStatus::Critical {
        clear_cost_throttling(state, tenant_id).await;
    }

    cache_cost_margin_status(state, tenant_id, status, Some(margin_percent)).await;
    Ok(status)
}

async fn create_cost_margin_alert(
    state: &AppState,
    tenant_id: &str,
    alert_type: &str,
    threshold: f64,
    margin_percent: f64,
    summary: &TenantCostSummaryRow,
) -> Result<(), String> {
    let details = json!({
        "threshold": threshold,
        "actual": margin_percent,
        "costs": {
            "storage": summary.storage_cost,
            "bandwidth": summary.bandwidth_cost,
            "compute": summary.compute_cost,
            "dedicatedIp": summary.dedicated_ip_cost,
            "total": summary.total_cost,
        },
        "revenue": summary.revenue,
    });

    sqlx::query(
        r#"
        WITH existing_alert AS (
            SELECT id
            FROM cost_alerts
            WHERE tenant_id = $1
              AND alert_type = $2
              AND resolved_at IS NULL
            LIMIT 1
        ),
        insert_alert AS (
            INSERT INTO cost_alerts (id, tenant_id, alert_type, margin_percent, details, created_at)
            SELECT gen_random_uuid(), $1, $2, $3, $4, NOW()
            WHERE NOT EXISTS (SELECT 1 FROM existing_alert)
            RETURNING id
        )
        INSERT INTO notification_queue (id, tenant_id, type, payload, status, created_at)
        SELECT gen_random_uuid(), $1, 'cost_alert', $4, 'pending', NOW()
        WHERE EXISTS (SELECT 1 FROM insert_alert)
        "#,
    )
    .bind(tenant_id)
    .bind(alert_type)
    .bind(margin_percent)
    .bind(&details)
    .execute(&state.db)
    .await
    .map_err(|error| format!("Failed to create cost alert for {tenant_id}: {error}"))?;

    Ok(())
}

/// Activate the shared API cost-throttle contract. The API derives the actual
/// cap from each tenant's current plan at request time, so this remains valid
/// if its rate-limit window or the tenant's plan changes.
async fn apply_cost_throttling(state: &AppState, tenant_id: &str, margin_percent: f64) {
    let override_ = CostThrottleOverride::critical_low_margin();
    let key = cost_throttle_key(tenant_id);

    match state.redis.get().await {
        Ok(mut conn) => {
            let already_active: bool = match conn.exists(&key).await {
                Ok(active) => active,
                Err(error) => {
                    warn!(tenant_id = %tenant_id, error = %error, "failed to inspect existing cost throttle state");
                    return;
                }
            };
            let payload = match serde_json::to_string(&override_) {
                Ok(payload) => payload,
                Err(error) => {
                    warn!(tenant_id = %tenant_id, error = %error, "failed to serialize cost throttle override");
                    return;
                }
            };

            let mut pipeline = redis::pipe();
            pipeline
                .set_ex(&key, payload, COST_THROTTLE_TTL_SECS)
                .ignore()
                // Remove the legacy keys written by the old no-op feature so
                // future operators cannot mistake them for active controls.
                .del(format!("cost:throttle:{tenant_id}"))
                .ignore()
                .del(format!("rate:limit:{tenant_id}:throttled"))
                .ignore();

            if let Err(error) = pipeline.query_async::<()>(&mut conn).await {
                warn!(tenant_id = %tenant_id, error = %error, "failed to persist cost throttling state");
                return;
            }

            if !already_active {
                info!(
                    tenant_id = %tenant_id,
                    margin_percent,
                    cap_percent = override_.cap_percent,
                    "activated cost-protection rate limit"
                );
                record_cost_throttle_audit(
                    state,
                    tenant_id,
                    "billing.cost_throttle.applied",
                    json!({
                        "reason": "low_margin",
                        "marginPercent": margin_percent,
                        "capPercent": override_.cap_percent,
                        "ttlSeconds": COST_THROTTLE_TTL_SECS,
                    }),
                )
                .await;
            }
        }
        Err(error) => {
            warn!(tenant_id = %tenant_id, error = %error, "failed to get Redis connection for cost throttling");
        }
    }
}

/// Remove a no-longer-required cost throttle once a tenant recovers above the
/// critical margin threshold. This prevents an arbitrary 24-hour penalty after
/// recovery while retaining a durable audit event for the state transition.
async fn clear_cost_throttling(state: &AppState, tenant_id: &str) {
    let key = cost_throttle_key(tenant_id);
    match state.redis.get().await {
        Ok(mut conn) => match conn.del::<_, usize>(&key).await {
            Ok(0) => {}
            Ok(_) => {
                info!(tenant_id = %tenant_id, "cleared cost-protection rate limit");
                record_cost_throttle_audit(
                    state,
                    tenant_id,
                    "billing.cost_throttle.cleared",
                    json!({ "reason": "margin_recovered" }),
                )
                .await;
            }
            Err(error) => {
                warn!(tenant_id = %tenant_id, error = %error, "failed to clear cost throttling state");
            }
        },
        Err(error) => {
            warn!(tenant_id = %tenant_id, error = %error, "failed to get Redis connection for cost throttle cleanup");
        }
    }
}

async fn record_cost_throttle_audit(
    state: &AppState,
    tenant_id: &str,
    action: &str,
    metadata: Value,
) {
    let mut transaction = match state.db.begin().await {
        Ok(transaction) => transaction,
        Err(error) => {
            warn!(tenant_id = %tenant_id, error = %error, "failed to start cost-throttle audit transaction");
            return;
        }
    };

    if let Err(error) = append_audit_log(
        &mut transaction,
        tenant_id,
        action,
        "tenant_rate_limit",
        Some(tenant_id),
        metadata,
        Utc::now(),
    )
    .await
    {
        warn!(tenant_id = %tenant_id, error = %error, "failed to append cost-throttle audit event");
        return;
    }

    if let Err(error) = transaction.commit().await {
        warn!(tenant_id = %tenant_id, error = %error, "failed to commit cost-throttle audit event");
    }
}

async fn cache_cost_margin_status(
    state: &AppState,
    tenant_id: &str,
    status: CostMarginStatus,
    margin_percent: Option<f64>,
) {
    match state.redis.get().await {
        Ok(mut conn) => {
            let payload = json!({
                "status": status.as_str(),
                "margin": margin_percent,
                "checkedAt": Utc::now().to_rfc3339(),
            })
            .to_string();
            let cache_result: Result<(), redis::RedisError> = conn
                .set_ex(format!("cost:status:{tenant_id}"), payload, 60 * 60)
                .await;
            if let Err(error) = cache_result {
                warn!(tenant_id = %tenant_id, error = %error, "failed to cache cost margin status");
            }
        }
        Err(error) => {
            warn!(tenant_id = %tenant_id, error = %error, "failed to get Redis connection for cost status cache");
        }
    }
}

/// ToS 6.4, "Credits expire after 12 months unless otherwise stated."
/// The published policy previously had NO enforcement mechanism, so wallet
/// balances sat forever. This sweep expires UNCONSUMED credits older than
/// 12 months: under the FIFO convention (debits consume the oldest credit
/// first, matching how every settlement path spends the wallet) the
/// expire-eligible amount for a tenant is
/// `max(credits_older_than_12mo − all_debits, 0)`, capped at the current
/// balance. The expiry is a normal debit with its own ledger row and an
/// audit event, and it is self-limiting: yesterday's expiry debit counts
/// as consumption in tomorrow's computation. Runs daily.
async fn expire_stale_wallet_credits(state: &AppState) -> Result<u64, String> {
    let candidates: Vec<(String, i64)> = sqlx::query_as(
        r#"
        WITH candidate_wallets AS (
            SELECT tenant_id, balance
            FROM wallets
            WHERE balance > 0
            ORDER BY updated_at ASC
            LIMIT 500
        ),
        ledger AS (
            SELECT wt.tenant_id,
                   COALESCE(SUM(amount) FILTER (
                       WHERE wt.type = 'credit'
                         AND wt.created_at < NOW() - INTERVAL '12 months'
                   ), 0)::bigint AS stale_credits,
                   COALESCE(SUM(amount) FILTER (WHERE wt.type = 'debit'), 0)::bigint AS total_debits
            FROM wallet_transactions wt
            JOIN candidate_wallets cw ON cw.tenant_id = wt.tenant_id
            GROUP BY wt.tenant_id
        )
        SELECT cw.tenant_id,
               LEAST(cw.balance, GREATEST(l.stale_credits - l.total_debits, 0))::bigint AS expire_amount
        FROM candidate_wallets cw
        JOIN ledger l ON l.tenant_id = cw.tenant_id
        WHERE GREATEST(l.stale_credits - l.total_debits, 0) > 0
        "#,
    )
    .fetch_all(&state.db)
    .await
    .map_err(|error| format!("Failed to load stale wallet credits: {error}"))?;

    let mut expired_count = 0_u64;
    for (tenant_id, expire_amount) in candidates {
        if expire_amount <= 0 {
            continue;
        }

        let mut tx = state.db.begin().await.map_err(|error| {
            format!("Failed to begin wallet credit expiry tx for {tenant_id}: {error}")
        })?;

        let debited = sqlx::query(
            r#"
            WITH debit_wallet AS (
                UPDATE wallets
                SET balance = balance - $2, updated_at = NOW()
                WHERE tenant_id = $1 AND balance >= $2
                RETURNING id, balance
            )
            INSERT INTO wallet_transactions
                (wallet_id, tenant_id, type, amount, balance_after, description, reference, created_at)
            SELECT id, $1, 'debit', $2, balance, $3, 'wallet_credit_expiry', NOW()
            FROM debit_wallet
            "#,
        )
        .bind(&tenant_id)
        .bind(expire_amount)
        .bind("Expired credit, 12-month wallet credit policy (ToS 6.4)")
        .execute(&mut *tx)
        .await
        .map_err(|error| {
            format!("Failed to expire stale wallet credit for {tenant_id}: {error}")
        })?
        .rows_affected();

        if debited == 0 {
            // Balance moved between the candidate scan and the debit, skip
            // rather than force-below zero.
            let _ = tx.rollback().await;
            continue;
        }

        if let Err(error) = append_audit_log(
            &mut tx,
            &tenant_id,
            "billing.wallet_credit_expired",
            "wallet",
            Some(&tenant_id),
            serde_json::json!({
                "expiredAmount": expire_amount,
                "policy": "credits expire 12 months after grant (ToS 6.4)",
            }),
            Utc::now(),
        )
        .await
        {
            let _ = tx.rollback().await;
            return Err(format!(
                "Failed to audit wallet credit expiry for {tenant_id}: {error}"
            ));
        }

        tx.commit().await.map_err(|error| {
            format!("Failed to commit wallet credit expiry for {tenant_id}: {error}")
        })?;

        info!(
            tenant_id = %tenant_id,
            expired_amount = expire_amount,
            "expired unconsumed wallet credits older than 12 months (ToS 6.4)"
        );
        expired_count += 1;

        if let Ok(mut conn) = state.redis.get().await {
            let key = format!("wallet:balance:{tenant_id}");
            let deletion: Result<i64, _> = conn.del(&key).await;
            if let Err(error) = deletion {
                warn!(tenant_id = %tenant_id, error = %error, "failed to clear wallet balance cache after credit expiry");
            }
        }
    }

    Ok(expired_count)
}

/// Fix F4/F09, record a payment recovery and restore access according to
/// the INDEPENDENT restriction model.
///
/// `invoice_id` scopes the recovery to that invoice's failure history: the
/// tenant-level reset only happens when the tenant's most recent
/// `payment_failed` event belongs to the settled invoice, a DIFFERENT
/// invoice that is still failing keeps the tenant in dunning. The
/// `payment_recovered` dunning event is always written (with the invoice
/// id) so the settled invoice's history is complete either way. `None`
/// restores the legacy unscoped blanket reset (used when no invoice
/// context is available).
///
/// Audit F09, restrictions are represented independently
/// (billing/administrative/verification/abuse, migration 181) and this
/// recovery clears ONLY the billing restriction. Tenant state and
/// queued-message eligibility are then recomputed IN THE SAME TRANSACTION
/// from every remaining hold:
///
/// * a tenant still `pending` verification stays pending;
/// * an active administrative/verification restriction keeps the tenant
///   restricted (recovery cannot clear what it did not impose);
/// * an open/investigating/confirmed abuse report keeps the hold;
/// * only a suspension ATTRIBUTABLE to billing (an active billing
///   restriction existed and was just cleared) reactivates the tenant.
pub(crate) async fn mark_payment_recovered(
    state: &AppState,
    tenant_id: &str,
    invoice_id: Option<&str>,
) -> Result<(), String> {
    let (reset_allowed, billing_cleared, dunning_reset, _reactivated, _released): (
        bool,
        i64,
        i64,
        i64,
        i64,
    ) = sqlx::query_as(
        r#"
        WITH latest_failure AS (
            SELECT invoice_id
            FROM dunning_events
            WHERE tenant_id = $1
              AND event_type = 'payment_failed'
            ORDER BY created_at DESC
            LIMIT 1
        ),
        reset_allowed AS (
            SELECT (
                $2::text IS NULL
                OR NOT EXISTS (
                    SELECT 1
                    FROM latest_failure
                    WHERE invoice_id IS NOT NULL
                      AND invoice_id <> $2::text
                )
            ) AS allowed
        ),
        -- Audit F09: clear ONLY the billing restriction. Administrative,
        -- verification and abuse restrictions survive recovery untouched.
        cleared_billing AS (
            UPDATE tenant_restrictions
            SET cleared_at = NOW(),
                cleared_by = 'payment_recovery',
                cleared_reason = 'confirmed payment recovery'
            WHERE tenant_id = $1
              AND kind = 'billing'
              AND cleared_at IS NULL
              AND (SELECT allowed FROM reset_allowed)
            RETURNING id
        ),
        update_dunning AS (
            UPDATE dunning_records
            SET status = 'healthy',
                failed_payment_count = 0,
                first_failed_at = NULL,
                last_failed_at = NULL,
                next_retry_at = NULL,
                suspended_at = NULL,
                grace_period_ends_at = NULL,
                updated_at = NOW()
            WHERE tenant_id = $1
              AND (SELECT allowed FROM reset_allowed)
            RETURNING tenant_id
        ),
        log_recovery AS (
            INSERT INTO dunning_events (id, tenant_id, event_type, invoice_id, created_at)
            VALUES (gen_random_uuid(), $1, 'payment_recovered', $2, NOW())
            RETURNING tenant_id
        ),
        -- Audit F09: recompute effective state from the REMAINING holds in
        -- the SAME transaction. `pending` verification is preserved; an
        -- active non-billing restriction or an open abuse report blocks
        -- reactivation; only a billing-attributed suspension reactivates.
        reactivate_tenant AS (
            UPDATE tenants
            SET status = 'active', updated_at = NOW()
            WHERE id = $1
              AND (SELECT allowed FROM reset_allowed)
              AND tenants.status <> 'pending'
              AND EXISTS (SELECT 1 FROM cleared_billing)
              AND NOT EXISTS (
                SELECT 1
                FROM tenant_restrictions tr
                WHERE tr.tenant_id = $1
                  AND tr.cleared_at IS NULL
                  AND tr.kind <> 'billing'
              )
              AND NOT EXISTS (
                SELECT 1
                FROM abuse_reports ar
                WHERE ar.tenant_id = $1
                  AND ar.status IN ('open', 'investigating', 'confirmed')
              )
            RETURNING id
        ),
        -- Queued-message eligibility recomputed under the same holds.
        release_messages AS (
            UPDATE messages
            SET status = 'queued', updated_at = NOW()
            WHERE tenant_id = $1
              AND status = 'dunning_queued'
              AND (SELECT allowed FROM reset_allowed)
              AND NOT EXISTS (
                SELECT 1
                FROM tenant_restrictions tr
                WHERE tr.tenant_id = $1
                  AND tr.cleared_at IS NULL
                  AND tr.kind <> 'billing'
              )
              AND NOT EXISTS (
                SELECT 1
                FROM abuse_reports ar
                WHERE ar.tenant_id = $1
                  AND ar.status IN ('open', 'investigating', 'confirmed')
              )
            RETURNING id
        )
        SELECT (SELECT allowed FROM reset_allowed),
               (SELECT COUNT(*)::bigint FROM cleared_billing),
               (SELECT COUNT(*)::bigint FROM update_dunning),
               (SELECT COUNT(*)::bigint FROM reactivate_tenant),
               (SELECT COUNT(*)::bigint FROM release_messages)
        "#,
    )
    .bind(tenant_id)
    .bind(invoice_id)
    .fetch_one(&state.db)
    .await
    .map_err(|error| format!("Failed to mark payment recovered for {tenant_id}: {error}"))?;

    if !reset_allowed {
        // The settled invoice recovered, but the tenant's latest failure is
        // for a different invoice that is still unpaid, keep dunning,
        // suspension and the queued-message hold exactly as they are.
        info!(
            tenant_id = %tenant_id,
            invoice_id = ?invoice_id,
            "payment recovered for one invoice; dunning kept active, a different invoice is still failing"
        );
        return Ok(());
    }

    if billing_cleared == 0 {
        // Audit F09: nothing billing-attributed was holding this tenant —
        // any remaining suspension belongs to another cause and is left
        // untouched (an unattributable suspension is never auto-cleared).
        info!(
            tenant_id = %tenant_id,
            invoice_id = ?invoice_id,
            dunning_reset,
            "payment recovered; no billing restriction was active, administrative/verification/abuse holds left untouched"
        );
    }

    if let Ok(mut conn) = state.redis.get().await {
        let cache_key = format!("dunning:status:{tenant_id}");
        let delete_result: Result<i64, _> = conn.del(&cache_key).await;
        if let Err(error) = delete_result {
            warn!(tenant_id = %tenant_id, error = %error, "failed to clear cached dunning status");
        }
    }

    Ok(())
}

/// The manual admin dunning reset (audit F09): the SAME restriction-aware
/// rule as [`mark_payment_recovered`], clear only the billing hold, then
/// recompute tenant state and queued-message eligibility in one
/// transaction, with the admin actor recorded on the clearance. Exposed
/// so the api-server admin route and the billing-service recovery path
/// share one contract (no divergent abuse predicates).
pub async fn admin_reset_dunning_restriction_aware(
    db: &sqlx::PgPool,
    redis: &deadpool_redis::Pool,
    tenant_id: &str,
    admin_actor: &str,
    reason: &str,
) -> Result<(), String> {
    let (billing_cleared, _dunning_reset, _reactivated, released): (i64, i64, i64, i64) =
        sqlx::query_as(
            r#"
            WITH cleared_billing AS (
                UPDATE tenant_restrictions
                SET cleared_at = NOW(),
                    cleared_by = $2,
                    cleared_reason = $3
                WHERE tenant_id = $1
                  AND kind = 'billing'
                  AND cleared_at IS NULL
                RETURNING id
            ),
            update_dunning AS (
                UPDATE dunning_records
                SET status = 'healthy',
                    failed_payment_count = 0,
                    first_failed_at = NULL,
                    last_failed_at = NULL,
                    next_retry_at = NULL,
                    suspended_at = NULL,
                    grace_period_ends_at = NULL,
                    updated_at = NOW()
                WHERE tenant_id = $1
                RETURNING tenant_id
            ),
            log_recovery AS (
                INSERT INTO dunning_events (id, tenant_id, event_type, created_at)
                VALUES (gen_random_uuid(), $1, 'payment_recovered', NOW())
                RETURNING tenant_id
            ),
            reactivate_tenant AS (
                UPDATE tenants
                SET status = 'active', updated_at = NOW()
                WHERE id = $1
                  AND tenants.status <> 'pending'
                  AND EXISTS (SELECT 1 FROM cleared_billing)
                  AND NOT EXISTS (
                    SELECT 1
                    FROM tenant_restrictions tr
                    WHERE tr.tenant_id = $1
                      AND tr.cleared_at IS NULL
                      AND tr.kind <> 'billing'
                  )
                  AND NOT EXISTS (
                    SELECT 1
                    FROM abuse_reports ar
                    WHERE ar.tenant_id = $1
                      AND ar.status IN ('open', 'investigating', 'confirmed')
                  )
                RETURNING id
            ),
            release_messages AS (
                UPDATE messages
                SET status = 'queued', updated_at = NOW()
                WHERE tenant_id = $1
                  AND status = 'dunning_queued'
                  AND NOT EXISTS (
                    SELECT 1
                    FROM tenant_restrictions tr
                    WHERE tr.tenant_id = $1
                      AND tr.cleared_at IS NULL
                      AND tr.kind <> 'billing'
                  )
                  AND NOT EXISTS (
                    SELECT 1
                    FROM abuse_reports ar
                    WHERE ar.tenant_id = $1
                      AND ar.status IN ('open', 'investigating', 'confirmed')
                  )
                RETURNING id
            )
            SELECT (SELECT COUNT(*)::bigint FROM cleared_billing),
                   (SELECT COUNT(*)::bigint FROM update_dunning),
                   (SELECT COUNT(*)::bigint FROM reactivate_tenant),
                   (SELECT COUNT(*)::bigint FROM release_messages)
            "#,
        )
        .bind(tenant_id)
        .bind(admin_actor)
        .bind(format!("admin dunning reset: {reason}"))
        .fetch_one(db)
        .await
        .map_err(|error| format!("Failed to reset dunning for {tenant_id}: {error}"))?;

    if billing_cleared == 0 {
        info!(
            tenant_id = tenant_id,
            "admin dunning reset: no billing restriction was active, other holds left untouched"
        );
    }
    if released > 0 {
        info!(
            tenant_id = tenant_id,
            released, "released queued messages after admin dunning reset"
        );
    }

    if let Ok(mut conn) = redis.get().await {
        let cache_key = format!("dunning:status:{tenant_id}");
        let delete_result: Result<i64, _> = conn.del(&cache_key).await;
        if let Err(error) = delete_result {
            warn!(tenant_id = tenant_id, error = %error, "failed to clear cached dunning status");
        }
    }

    Ok(())
}

// Abuse-report lifecycle writers (audit F09). `abuse_reports.status` is a
// constrained lifecycle (migration 133: open -> investigating ->
// confirmed | dismissed | resolved). These are the canonical writers —
// payment recovery (`mark_payment_recovered`) and the admin dunning reset
// keep their billing holds DISTINCT from the abuse hold: clearing a
// billing hold releases sending only when no open/investigating/confirmed
// abuse report remains.

/// Record a new abuse report in the `open` state (the cautious default:
/// holds reactivation until reviewed).
pub async fn record_abuse_report(
    state: &AppState,
    tenant_id: &str,
    report_type: &str,
    source: Option<&str>,
    details: serde_json::Value,
) -> Result<Uuid, String> {
    let id: Uuid = sqlx::query_scalar(
        r#"
        INSERT INTO abuse_reports (tenant_id, report_type, source, details, status)
        VALUES ($1, $2, $3, $4::jsonb, 'open')
        RETURNING id
        "#,
    )
    .bind(tenant_id)
    .bind(report_type)
    .bind(source)
    .bind(details.to_string())
    .fetch_one(&state.db)
    .await
    .map_err(|error| format!("Failed to record abuse report: {error}"))?;
    info!(tenant_id = tenant_id, report_id = %id, report_type, "abuse report recorded (open)");
    Ok(id)
}

/// Whether an OPEN abuse hold exists for the tenant, the state that must
/// block sending-release and reactivation regardless of billing health.
pub async fn tenant_has_open_abuse_hold(state: &AppState, tenant_id: &str) -> Result<bool, String> {
    let open: bool = sqlx::query_scalar(
        r#"
        SELECT EXISTS(
            SELECT 1 FROM abuse_reports
            WHERE tenant_id = $1
              AND status IN ('open', 'investigating', 'confirmed')
        )
        "#,
    )
    .bind(tenant_id)
    .fetch_one(&state.db)
    .await
    .map_err(|error| format!("Failed to check abuse hold: {error}"))?;
    Ok(open)
}

// ---------------------------------------------------------------------------
// Audited state transitions (audit F09): a CHECK of allowed labels is not
// transition authorization. These are the canonical, audit-logged writers
// for abuse review/resolution and for administrative restrictions; the
// recovery paths above consume their state but never bypass them.
// ---------------------------------------------------------------------------

/// Allowed abuse-report transitions (open -> investigating ->
/// confirmed | dismissed | resolved; confirmed may still be resolved after
/// remediation; dismissed/resolved are terminal for a NEW review cycle).
fn abuse_transition_allowed(from: &str, to: &str) -> bool {
    matches!(
        (from, to),
        ("open", "investigating")
            | ("open", "dismissed")
            | ("open", "resolved")
            | ("investigating", "confirmed")
            | ("investigating", "dismissed")
            | ("investigating", "resolved")
            | ("confirmed", "resolved")
    )
}

/// Advance an abuse report through an AUTHORIZED, audited transition. The
/// reviewer identity is recorded (`reviewed_by`/`reviewed_at`), evidence
/// that distinguishes a genuine resolution from the legacy blanket
/// resolves migration 182 re-opened.
pub async fn review_abuse_report(
    db: &sqlx::PgPool,
    report_id: Uuid,
    to_status: &str,
    reviewer: &str,
    notes: &str,
) -> Result<(), String> {
    let mut tx = db
        .begin()
        .await
        .map_err(|error| format!("Failed to begin abuse review transaction: {error}"))?;
    let current: Option<String> =
        sqlx::query_scalar("SELECT status::text FROM abuse_reports WHERE id = $1 FOR UPDATE")
            .bind(report_id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(|error| format!("Failed to load abuse report: {error}"))?;
    let Some(from) = current else {
        return Err(format!("Abuse report {report_id} not found"));
    };
    if !abuse_transition_allowed(&from, to_status) {
        return Err(format!(
            "Unauthorized abuse report transition: {from} -> {to_status}"
        ));
    }
    sqlx::query(
        r#"
        UPDATE abuse_reports
        SET status = $2,
            reviewed_at = NOW(),
            reviewed_by = $3,
            resolved_at = CASE WHEN $2 IN ('resolved', 'dismissed') THEN NOW() ELSE NULL END
        WHERE id = $1
        "#,
    )
    .bind(report_id)
    .bind(to_status)
    .bind(reviewer)
    .execute(&mut *tx)
    .await
    .map_err(|error| format!("Failed to update abuse report: {error}"))?;

    // The abuse restriction mirrors the report lifecycle: an active report
    // imposes the restriction; a terminal dismissed/resolved one clears it.
    let tenant_id: String = sqlx::query_scalar("SELECT tenant_id FROM abuse_reports WHERE id = $1")
        .bind(report_id)
        .fetch_one(&mut *tx)
        .await
        .map_err(|error| format!("Failed to load abuse report tenant: {error}"))?;
    if to_status == "dismissed" || to_status == "resolved" {
        sqlx::query(
            r#"
            UPDATE tenant_restrictions
            SET cleared_at = NOW(), cleared_by = $2, cleared_reason = $3
            WHERE tenant_id = $1 AND kind = 'abuse' AND cleared_at IS NULL
            "#,
        )
        .bind(&tenant_id)
        .bind(reviewer)
        .bind(format!("abuse report {report_id} {to_status}: {notes}"))
        .execute(&mut *tx)
        .await
        .map_err(|error| format!("Failed to clear abuse restriction: {error}"))?;
    } else {
        sqlx::query(
            r#"
            INSERT INTO tenant_restrictions (tenant_id, kind, reason, actor_type, actor_id)
            VALUES ($1, 'abuse', $2, 'admin', $3)
            ON CONFLICT (tenant_id, kind) WHERE cleared_at IS NULL DO NOTHING
            "#,
        )
        .bind(&tenant_id)
        .bind(format!("abuse report {report_id} {to_status}"))
        .bind(reviewer)
        .execute(&mut *tx)
        .await
        .map_err(|error| format!("Failed to impose abuse restriction: {error}"))?;
    }

    append_audit_log(
        &mut tx,
        &tenant_id,
        "billing.abuse_report_transition",
        "abuse_report",
        Some(&report_id.to_string()),
        serde_json::json!({
            "fromStatus": from,
            "toStatus": to_status,
            "reviewer": reviewer,
            "notes": notes,
        }),
        Utc::now(),
    )
    .await
    .map_err(|error| format!("Failed to append abuse audit log: {error}"))?;

    tx.commit()
        .await
        .map_err(|error| format!("Failed to commit abuse review: {error}"))?;
    Ok(())
}

/// Impose an administrative restriction on a tenant (audit F09): recorded
/// independently with actor/reason, so payment recovery and dunning resets
/// can never clear it, only the symmetric [`clear_tenant_restriction`].
pub async fn impose_tenant_restriction(
    db: &sqlx::PgPool,
    tenant_id: &str,
    kind: &str,
    reason: &str,
    actor_type: &str,
    actor_id: Option<&str>,
) -> Result<(), String> {
    sqlx::query(
        r#"
        INSERT INTO tenant_restrictions (tenant_id, kind, reason, actor_type, actor_id)
        VALUES ($1, $2, $3, $4, $5)
        ON CONFLICT (tenant_id, kind) WHERE cleared_at IS NULL
        DO UPDATE SET reason = EXCLUDED.reason, actor_type = EXCLUDED.actor_type,
                      actor_id = EXCLUDED.actor_id
        "#,
    )
    .bind(tenant_id)
    .bind(kind)
    .bind(reason)
    .bind(actor_type)
    .bind(actor_id)
    .execute(db)
    .await
    .map_err(|error| format!("Failed to impose tenant restriction: {error}"))?;
    Ok(())
}

/// Clear one specific restriction by kind (audit F09), the ONLY writer
/// that lifts administrative/verification/abuse restrictions, with the
/// clearing actor and reason recorded.
pub async fn clear_tenant_restriction(
    db: &sqlx::PgPool,
    tenant_id: &str,
    kind: &str,
    cleared_by: &str,
    cleared_reason: &str,
) -> Result<bool, String> {
    let cleared = sqlx::query(
        r#"
        UPDATE tenant_restrictions
        SET cleared_at = NOW(), cleared_by = $3, cleared_reason = $4
        WHERE tenant_id = $1 AND kind = $2 AND cleared_at IS NULL
        "#,
    )
    .bind(tenant_id)
    .bind(kind)
    .bind(cleared_by)
    .bind(cleared_reason)
    .execute(db)
    .await
    .map_err(|error| format!("Failed to clear tenant restriction: {error}"))?;
    Ok(cleared.rows_affected() > 0)
}

/// Resolve an abuse report (terminal) through the audited transition
/// above, releases the abuse restriction in the same transaction.
pub async fn resolve_abuse_report(
    db: &sqlx::PgPool,
    report_id: Uuid,
    reviewed_by: &str,
    notes: &str,
) -> Result<(), String> {
    review_abuse_report(db, report_id, "resolved", reviewed_by, notes).await
}

/// One Mollie recurring charge against a STORED mandate.
///
/// A repeat payment is `POST /payments` with `sequenceType: "recurring"`,
/// the Mollie customer and the mandate, NOT a subscription object (the add-on
/// is OUR row, and the mandate is shared by every add-on of the tenant).
/// Amounts travel as decimal strings, the key as a Bearer token, and a
/// deterministic `Idempotency-Key` makes a retried call replay instead of
/// double-charging.
///
/// The returned [`MollieCharge`] carries the payment id. A
/// `failed`/`canceled`/`expired` status is an `Err`; `paid` and the async
/// states (`open`, `pending`, `authorized`) are accepted, the webhook
/// settles the final outcome.
///
/// Charge the tenant's stored payment method for one reference (auto-pay
/// retry, dedicated-IP add-on) through the NEUTRAL payment boundary and the
/// execution ledger (audit step 7; N-11 RETIRED).
///
/// * The provider call goes through `registry::from_env()` +
///   `charge_saved_method`; no wire client is constructed here.
/// * CLAIM BEFORE CHARGE: the attempt row is claimed under the frozen
///   idempotency key BEFORE the provider call. A concurrent tick, or a
///   previous attempt whose response was LOST (timeout after a successful
///   charge), refuses the claim and NO second charge is opened.
/// * CONFIRM AFTER CHARGE: the provider payment id and normalized state
///   land on the claim; a transport failure leaves the claim open and
///   keyless for the webhook/repair sweep to link and settle.
#[allow(clippy::too_many_arguments)]
async fn mollie_charge_stored_payment_method(
    db: &sqlx::PgPool,
    _client: &Client,
    reference: &str,
    tenant_id: &str,
    customer_id: &str,
    mandate_id: &str,
    amount_cents: i64,
    currency: &str,
    idempotency_key: &str,
    metadata: serde_json::Value,
) -> Result<MollieCharge, String> {
    use crate::payments::SavedMethodCharge;

    let provider = crate::payments::registry::from_env().map_err(|error| error.to_string())?;
    let provider_name = provider.provider_name();

    // The obligation reference is the caller's (invoice:{id} /
    // dedicated_ip:{id}); the attempts ledger links provider callbacks to
    // open claims by it.
    let claimed = crate::payments::engine::claim_attempt(
        db,
        provider_name,
        idempotency_key,
        tenant_id,
        reference,
        "autopay",
        amount_cents,
        currency,
    )
    .await
    .map_err(|error| format!("payment attempt claim failed ({reference}): {error}"))?;
    if !claimed {
        // Exactly one attempt per operation per tick: an open claim (maybe
        // keyless after a lost response) means a charge may already be
        // moving; refuse rather than double-charge.
        return Err(format!(
            "a payment attempt for {reference} is unresolved or already succeeded, \
             no second charge"
        ));
    }

    let mut metadata = metadata;
    if let Some(object) = metadata.as_object_mut() {
        object.insert(
            "reference".into(),
            serde_json::Value::String(reference.to_string()),
        );
        object.insert(
            "tenant_id".into(),
            serde_json::Value::String(tenant_id.to_string()),
        );
    }
    // A recurring charge is API-initiated: no browser redirect exists.
    let charge = provider
        .charge_saved_method(SavedMethodCharge {
            provider_customer_id: customer_id.to_string(),
            provider_method_id: mandate_id.to_string(),
            amount_minor: amount_cents,
            currency: currency.to_string(),
            description: format!("ApexMail {reference}"),
            metadata,
            idempotency_key: idempotency_key.to_string(),
        })
        .await;

    let link = match charge {
        Ok(link) => link,
        Err(error @ crate::payments::ProviderError::Unavailable(_)) => {
            // Timeout after a (possibly successful) provider charge: the
            // claim stays open and keyless; the webhook links the payment id
            // by reference and the repair sweep settles it. Surface the
            // ambiguity as an error so the caller's retry ladder backs off
            // instead of treating the charge as opened.
            return Err(format!(
                "Mollie charge outcome unknown ({reference}): {error}; the attempt stays open, \
                 the webhook or repair sweep will settle it"
            ));
        }
        Err(error) => {
            let _ = crate::payments::engine::fail_claim(db, provider_name, idempotency_key).await;
            return Err(format!("Mollie charge failed ({reference}): {error}"));
        }
    };

    // CONFIRM: the payment id and normalized state land on the claim.
    crate::payments::engine::confirm_attempt(
        db,
        provider_name,
        idempotency_key,
        &link.provider_payment_id,
        link.state,
    )
    .await
    .map_err(|error| format!("payment attempt confirm failed ({reference}): {error}"))?;

    // The accepted outcome states cover exactly the pre-inversion wire
    // statuses (open/pending/authorized/paid); anything else is a refusal
    // and the claim is closed failed so a later tick may retry.
    match link.state {
        crate::payments::PaymentState::Succeeded
        | crate::payments::PaymentState::Pending
        | crate::payments::PaymentState::Processing => Ok(MollieCharge {
            payment_id: link.provider_payment_id,
        }),
        other => {
            let _ = crate::payments::engine::fail_claim(db, provider_name, idempotency_key).await;
            Err(format!(
                "Mollie declined the charge ({reference}): state {other:?}"
            ))
        }
    }
}

/// The accepted recurring-charge outcome.
#[derive(Debug, Clone)]
struct MollieCharge {
    payment_id: String,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ------------------------------------------------------------------
    // Audit F09, authorized abuse-report transitions: a CHECK of allowed
    // labels alone is not transition authorization.
    // ------------------------------------------------------------------

    #[test]
    fn abuse_lifecycle_follows_only_forward_transitions() {
        assert!(abuse_transition_allowed("open", "investigating"));
        assert!(abuse_transition_allowed("investigating", "confirmed"));
        // A confirmed report can still be resolved after remediation.
        assert!(abuse_transition_allowed("confirmed", "resolved"));
        // Early dismissals terminate the report.
        assert!(abuse_transition_allowed("open", "dismissed"));
        assert!(abuse_transition_allowed("investigating", "dismissed"));
        assert!(abuse_transition_allowed("investigating", "resolved"));
        assert!(abuse_transition_allowed("open", "resolved"));
    }

    #[test]
    fn abuse_transitions_reject_reopening_and_skipping() {
        // Terminal states never reopen...
        assert!(!abuse_transition_allowed("resolved", "open"));
        assert!(!abuse_transition_allowed("dismissed", "investigating"));
        // ...investigation cannot be skipped to confirmed...
        assert!(!abuse_transition_allowed("open", "confirmed"));
        // ...and resolved reports cannot be re-resolved or re-confirmed.
        assert!(!abuse_transition_allowed("resolved", "resolved"));
        assert!(!abuse_transition_allowed("resolved", "confirmed"));
        assert!(!abuse_transition_allowed("confirmed", "investigating"));
    }

    // ------------------------------------------------------------------
    // Fix I5, KMD backfill covers every missed month.
    // ------------------------------------------------------------------

    #[test]
    fn kmd_backfill_fills_three_month_gap() {
        // Last generated: 2026-03. Target: 2026-06 → April, May, June.
        let periods = kmd_backfill_periods(&[(2026, 3)], (2026, 6), 24);
        assert_eq!(periods, vec![(2026, 4), (2026, 5), (2026, 6)]);
    }

    #[test]
    fn kmd_backfill_with_no_history_generates_only_target() {
        let periods = kmd_backfill_periods(&[], (2026, 6), 24);
        assert_eq!(periods, vec![(2026, 6)]);
    }

    #[test]
    fn kmd_backfill_is_noop_when_target_already_generated() {
        assert!(kmd_backfill_periods(&[(2026, 6)], (2026, 6), 24).is_empty());
        // Future-dated returns also block regeneration.
        assert!(kmd_backfill_periods(&[(2026, 8)], (2026, 6), 24).is_empty());
    }

    #[test]
    fn kmd_backfill_wraps_year_boundary() {
        let periods = kmd_backfill_periods(&[(2026, 11)], (2027, 2), 24);
        assert_eq!(periods, vec![(2026, 12), (2027, 1), (2027, 2)]);
    }

    #[test]
    fn kmd_backfill_is_bounded() {
        assert_eq!(kmd_backfill_periods(&[(2024, 1)], (2026, 12), 5).len(), 5);
    }

    /// F7: the third-month cash-accounting fallback is SCHEDULED in the
    /// periodic KMD job (it previously had no caller while mollie_webhooks
    /// claimed "the sweep" handled it) and it runs BEFORE the return
    /// generation, so the `cash_special_due` output VAT is included in the
    /// period being filed. This pins the production source (test code is
    /// excluded from the scanned slice).
    #[test]
    fn cash_accounting_third_month_sweep_is_scheduled_before_kmd_generation() {
        let source = include_str!("maintenance.rs");
        let production = source
            .split("#[cfg(test)]")
            .next()
            .expect("production section present");
        let scheduled = production
            .split("pub fn start_periodic_jobs")
            .nth(1)
            .expect("start_periodic_jobs present");
        let sweep = scheduled
            .find("materialize_due_cash_special")
            .expect("the periodic job registry must schedule the cash-accounting fallback sweep");
        let generation = scheduled
            .find("generate_kmd_if_due")
            .expect("the periodic job registry calls the KMD generation");
        assert!(
            sweep < generation,
            "the third-month fallback must materialize BEFORE the KMD aggregation"
        );
    }

    // ------------------------------------------------------------------
    // Fix I6, SLA credit percentage ladder.
    // ------------------------------------------------------------------

    #[test]
    fn sla_credit_percentage_ladder() {
        assert_eq!(sla_credit_percentage_for_breach(5.0), 100);
        assert_eq!(sla_credit_percentage_for_breach(1.0), 50);
        assert_eq!(sla_credit_percentage_for_breach(0.5), 25);
        assert_eq!(sla_credit_percentage_for_breach(0.1), 10);
        assert_eq!(sla_credit_percentage_for_breach(0.05), 0);
    }

    /// E-SWEEP-TRIGGER pin: the binary must expose the one-shot
    /// `--sweep-overage-only` trigger and route it through the SAME
    /// [`sweep_overage_once`] the nightly loop calls, one code path, one
    /// behavior (a second sweep implementation could drift from the
    /// scheduled one).
    #[test]
    fn the_on_demand_sweep_trigger_is_wired_to_the_canonical_sweep() {
        let binary = include_str!("bin/server.rs");
        assert!(
            binary.contains("sweep_overage_only"),
            "bin/server.rs must expose the --sweep-overage-only one-shot trigger"
        );
        assert!(
            binary.contains("maintenance::sweep_overage_once"),
            "the trigger must run the canonical sweep_overage_once, not a copy"
        );
        let production = include_str!("maintenance.rs")
            .split("#[cfg(test)]")
            .next()
            .expect("production section present");
        let scheduled = production
            .split("pub fn start_periodic_jobs")
            .nth(1)
            .expect("start_periodic_jobs present");
        assert!(
            scheduled.contains("sweep_overage_once(sla_state.as_ref())"),
            "the nightly loop must call the same sweep_overage_once the CLI does"
        );
    }

    /// The same one-code-path pin for the contract product-line sweep: the
    /// binary must expose `--sweep-product-lines-only` and the nightly loop
    /// must call the very same `sweep_product_lines_once`.
    #[test]
    fn the_product_line_sweep_trigger_is_wired_to_the_canonical_sweep() {
        let binary = include_str!("bin/server.rs");
        assert!(
            binary.contains("sweep_product_lines_only"),
            "bin/server.rs must expose the --sweep-product-lines-only one-shot trigger"
        );
        assert!(
            binary.contains("maintenance::sweep_product_lines_once"),
            "the trigger must run the canonical sweep_product_lines_once, not a copy"
        );
        let production = include_str!("maintenance.rs")
            .split("#[cfg(test)]")
            .next()
            .expect("production section present");
        let scheduled = production
            .split("pub fn start_periodic_jobs")
            .nth(1)
            .expect("start_periodic_jobs present");
        assert!(
            scheduled.contains("sweep_product_lines_once(sla_state.as_ref())"),
            "the nightly loop must call the same sweep_product_lines_once the CLI does"
        );
    }
}

// ---------------------------------------------------------------------------
// Adversarial coverage tests (DB + Redis backed) for the maintenance sweeps.
//
// These call the PRIVATE sweep functions directly, the periodic-job
// wrappers spawn loops and sleep, which is neither deterministic nor fast.
// Every test provisions its own canonical database clone; `TEST_DATABASE_URL`
// unset means soft-skip.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod coverage_adversarial {
    use super::*;
    use crate::config::BillingConfig;
    use chrono::TimeZone;
    use deadpool_redis::Runtime;
    use sqlx::postgres::PgPoolOptions;
    use std::sync::Arc;

    struct Env {
        state: Arc<AppState>,
        pool: sqlx::PgPool,
        redis: deadpool_redis::Pool,
        db_name: String,
        admin_url: String,
    }

    impl Env {
        /// Schema-level fault injection in this test's PRIVATE database
        /// clone: rename a table so queries against it fail (42P01).
        async fn break_table(&self, table: &str) {
            sqlx::query(&format!("ALTER TABLE {table} RENAME TO {table}_broken"))
                .execute(&self.pool)
                .await
                .expect("break table");
        }

        async fn restore_table(&self, table: &str) {
            let _ = sqlx::query(&format!("ALTER TABLE {table}_broken RENAME TO {table}"))
                .execute(&self.pool)
                .await;
        }

        async fn finish(self) {
            self.pool.close().await;
            // Bounded retry: under parallel load the admin connect can time
            // out once; failing the TEST over teardown contention reports a
            // regression where there is none (the namespaced leftover DB is
            // dropped by the next run of the same test).
            let mut admin = None;
            for attempt in 0..3 {
                match PgPoolOptions::new()
                    .max_connections(1)
                    .acquire_timeout(Duration::from_secs(10))
                    .connect(&self.admin_url)
                    .await
                {
                    Ok(pool) => {
                        admin = Some(pool);
                        break;
                    }
                    Err(error) if attempt == 2 => {
                        eprintln!(
                            "teardown of {} gave up after 3 attempts: {error}",
                            self.db_name
                        );
                    }
                    Err(_) => tokio::time::sleep(Duration::from_secs(1)).await,
                }
            }
            let Some(admin) = admin else { return };
            let _ = sqlx::query(&format!(
                r#"DROP DATABASE IF EXISTS "{}" WITH (FORCE)"#,
                self.db_name
            ))
            .execute(&admin)
            .await;
            admin.close().await;
        }
    }

    async fn provision(test_name: &str) -> Option<Env> {
        crate::test_support::assert_soft_skip_allowed("TEST_DATABASE_URL");
        let url = std::env::var("TEST_DATABASE_URL")
            .ok()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())?;
        let (server_part, db_part) = url.rsplit_once('/').expect("db segment");
        let db_only = db_part.split('?').next().unwrap_or(db_part);
        let mut digest: u64 = 0xcbf2_9ce4_8422_2325;
        for byte in test_name.bytes() {
            digest ^= u64::from(byte);
            digest = digest.wrapping_mul(0x0000_0100_0000_01b3);
        }
        let db_name = format!("{db_only}_mtcov_{:08x}", digest & 0xffff_ffff);

        let admin_url = std::env::var("TEST_DATABASE_ADMIN_URL")
            .ok()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| format!("{server_part}/postgres"));
        let admin = PgPoolOptions::new()
            .max_connections(1)
            .acquire_timeout(Duration::from_secs(30))
            .connect(&admin_url)
            .await
            .expect("admin connect");

        let migrations_dir =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../migrations");
        let mut count = 0_usize;
        let mut newest = 0_i64;
        for entry in std::fs::read_dir(&migrations_dir).expect("migrations dir") {
            let name = entry
                .expect("entry")
                .file_name()
                .to_string_lossy()
                .to_string();
            if let Some(prefix) = name.split('_').next() {
                if let Ok(version) = prefix.parse::<i64>() {
                    count += 1;
                    newest = newest.max(version);
                }
            }
        }
        let template: Option<String> = sqlx::query_scalar(
            "SELECT datname FROM pg_database WHERE datname LIKE $1 ORDER BY datname DESC LIMIT 1",
        )
        .bind(format!("apexmail_canonical_tpl_{count}_{newest}_%"))
        .fetch_optional(&admin)
        .await
        .expect("template lookup");
        let template = template.expect("canonical template database must exist");

        sqlx::query(&format!(
            r#"DROP DATABASE IF EXISTS "{}" WITH (FORCE)"#,
            db_name
        ))
        .execute(&admin)
        .await
        .expect("drop test db");
        {
            // Serialize template clones process-wide and retry the transient
            // 55006 (a concurrent cloner's internal session on the template).
            let _clone_guard = crate::test_support::CLONE_LOCK.lock().await;
            let mut last_error = None;
            for _ in 0..5 {
                match sqlx::query(&format!(
                    r#"CREATE DATABASE "{}" TEMPLATE "{}""#,
                    db_name, template
                ))
                .execute(&admin)
                .await
                {
                    Ok(_) => {
                        last_error = None;
                        break;
                    }
                    Err(error) => {
                        last_error = Some(error);
                        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                    }
                }
            }
            if let Some(error) = last_error {
                panic!("clone test db: {error}");
            }
        }
        admin.close().await;

        let database_url = format!("{server_part}/{db_name}");
        let pool = PgPoolOptions::new()
            .max_connections(4)
            .acquire_timeout(Duration::from_secs(10))
            .connect(&database_url)
            .await
            .expect("connect test db");
        let redis_url = std::env::var("TEST_REDIS_URL")
            .ok()
            .filter(|value| !value.trim().is_empty())
            .expect("TEST_REDIS_URL must be set");
        let redis = deadpool_redis::Config::from_url(redis_url)
            .create_pool(Some(Runtime::Tokio1))
            .expect("redis pool");
        let config = BillingConfig {
            database_url,
            redis_url: "redis://127.0.0.1:6379".to_string(),
            service_auth_token: "coverage".to_string(),
            mollie_api_key: "whsec_coverage".to_string(),
            ..BillingConfig::default()
        };
        let state = AppState::new(pool.clone(), redis.clone(), config);
        Some(Env {
            state,
            pool,
            redis,
            db_name,
            admin_url,
        })
    }

    /// Cross-process serialization for tests that touch the SHARED Redis
    /// pending-metering keyspace: a drain consumes every `meter:pending:*`
    /// key it can see, including another test process's, so two drains
    /// racing make each other's counts wrong. A session-level advisory lock
    /// on the admin database; released when the pool drops.
    async fn metering_keys_guard(admin_url: &str) -> sqlx::PgPool {
        crate::test_support::redis_keys_guard(admin_url, "metering").await
    }

    macro_rules! env_test {
        ($name:ident, |$e:ident| $body:block) => {
            #[tokio::test]
            async fn $name() {
                if let Some(owned) = provision(stringify!($name)).await {
                    let $e = &owned;
                    $body
                    owned.finish().await;
                }
            }
        };
    }

    use crate::types::MeterEventType;
    use crate::usage::record_usage;
    use billing_common::cost_throttle::cost_throttle_key;

    // ---------------- seeding / redis helpers ----------------

    async fn seed_tenant(env: &Env, tenant_id: &str, plan: &str, status: &str) {
        sqlx::query(
            "INSERT INTO tenants (id, name, plan, status) VALUES ($1, $2, $3, $4)
             ON CONFLICT (id) DO UPDATE SET plan = EXCLUDED.plan, status = EXCLUDED.status",
        )
        .bind(tenant_id)
        .bind(format!("Coverage {tenant_id}"))
        .bind(plan)
        .bind(status)
        .execute(&env.pool)
        .await
        .expect("seed tenant");
    }

    async fn seed_plan(env: &Env, name: &str, limit: i64, features: Value) {
        sqlx::query(
            "INSERT INTO plans (id, name, display_name, price_cents, email_limit, api_call_limit, features)
             VALUES ($1, $2, $2, 0, $3, 100000, $4)
             ON CONFLICT (name) DO UPDATE SET email_limit = EXCLUDED.email_limit, features = EXCLUDED.features",
        )
        .bind(format!("plan_{name}"))
        .bind(name)
        .bind(limit)
        .bind(features)
        .execute(&env.pool)
        .await
        .expect("seed plan");
    }

    async fn redis_del(env: &Env, key: &str) {
        let mut conn = env.redis.get().await.expect("redis");
        let _: () = redis::cmd("DEL")
            .arg(key)
            .query_async(&mut conn)
            .await
            .expect("redis del");
    }

    async fn redis_exists(env: &Env, key: &str) -> bool {
        let mut conn = env.redis.get().await.expect("redis");
        let exists: bool = conn.exists(key).await.expect("redis exists");
        exists
    }

    // ---------------- scripted local HTTP mock ----------------

    #[derive(Clone, Debug)]
    struct RecordedCall {
        method: String,
        path: String,
        headers: std::collections::HashMap<String, String>,
        body: String,
    }

    #[derive(Clone, Default)]
    struct Mock {
        responses: Arc<std::sync::Mutex<std::collections::HashMap<String, (u16, String)>>>,
        calls: Arc<std::sync::Mutex<Vec<RecordedCall>>>,
        /// Per-path call counters for the `{seq}` placeholder (see
        /// mock_handler): sequential posts to one route can return
        /// DISTINCT payment ids, the way a real provider does.
        seq: Arc<std::sync::Mutex<std::collections::HashMap<String, u64>>>,
    }

    impl Mock {
        fn route(&self, path: &str, status: u16, body: impl Into<String>) {
            self.responses
                .lock()
                .expect("lock")
                .insert(path.to_string(), (status, body.into()));
        }

        fn call_count(&self, path: &str) -> usize {
            self.calls
                .lock()
                .expect("lock")
                .iter()
                .filter(|recorded| recorded.path == path)
                .count()
        }

        fn last_call(&self, path: &str) -> Option<RecordedCall> {
            self.calls
                .lock()
                .expect("lock")
                .iter()
                .rev()
                .find(|recorded| recorded.path == path)
                .cloned()
        }
    }

    async fn mock_handler(
        axum::extract::State(mock): axum::extract::State<Mock>,
        request: axum::http::Request<axum::body::Body>,
    ) -> axum::response::Response {
        use axum::response::IntoResponse;
        let method = request.method().to_string();
        let path = request.uri().path().to_string();
        let headers = request
            .headers()
            .iter()
            .map(|(name, value)| {
                (
                    name.as_str().to_string(),
                    value.to_str().unwrap_or_default().to_string(),
                )
            })
            .collect();
        let body = axum::body::to_bytes(request.into_body(), usize::MAX)
            .await
            .unwrap_or_default();
        let (status, response_body) = mock
            .responses
            .lock()
            .expect("lock")
            .get(&path)
            .cloned()
            .unwrap_or_else(|| (404, "{}".to_string()));
        let seq = {
            let mut counters = mock.seq.lock().expect("lock");
            let counter = counters.entry(path.clone()).or_insert(0);
            *counter += 1;
            *counter
        };
        let response_body = response_body.replace("{seq}", &seq.to_string());
        mock.calls.lock().expect("lock").push(RecordedCall {
            method,
            path,
            headers,
            body: String::from_utf8_lossy(&body).to_string(),
        });
        (
            axum::http::StatusCode::from_u16(status).expect("status"),
            [(axum::http::header::CONTENT_TYPE, "application/json")],
            response_body,
        )
            .into_response()
    }

    async fn spawn_mock(mock: Mock) -> String {
        let app = axum::Router::new().fallback(mock_handler).with_state(mock);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind mock");
        let addr = listener.local_addr().expect("addr");
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        format!("http://{addr}")
    }

    /// Serializes tests that mutate process-global environment variables.
    /// Async-aware so the guard may be held across await points.
    static ENV_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    /// The metering drain scans the process-shared Redis namespace
    /// (`meter:pending:*`), so any two drain tests running concurrently
    /// would consume each other's fixture events. Serialize them.
    static METER_DRAIN_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    // ---------------- metering drain ----------------

    env_test!(
        metering_drain_recovers_valid_and_discards_malformed,
        |env| {
            let _drain_guard = METER_DRAIN_LOCK.lock().await;
            let _metering_guard = metering_keys_guard(&env.admin_url).await;
            let tenant = "mtcov_drain";
            seed_tenant(env, tenant, "free", "active").await;
            redis_del(env, "meter:pending:raw-1").await;
            redis_del(env, "meter:pending:raw-2").await;
            redis_del(
                env,
                &format!("meter:guard:{}", normalize_metering_event_id("raw-1")),
            )
            .await;

            let valid = format!(
                r#"{{"id":"raw-1","tenantId":"{tenant}","eventType":"api_calls","quantity":7,"timestamp":"{}"}}"#,
                Utc::now().to_rfc3339()
            );
            let mut conn = env.redis.get().await.expect("redis");
            let _: () = redis::cmd("SET")
                .arg("meter:pending:raw-1")
                .arg(&valid)
                .query_async(&mut conn)
                .await
                .expect("set pending");
            let _: () = redis::cmd("SET")
                .arg("meter:pending:raw-2")
                .arg("not json at all")
                .query_async(&mut conn)
                .await
                .expect("set malformed");

            let result = drain_pending_metering_events(&env.state, 100)
                .await
                .expect("drain");
            // The drain walks the WHOLE Redis keyspace, so its counters move
            // for a sibling test's events too when the suite runs in parallel.
            // Assert on THIS test's events: the malformed one left the pending
            // set without being persisted, the valid one was recovered once.
            assert!(result.processed_count >= 1, "{result:?}");
            assert!(
                !redis_exists(env, "meter:pending:raw-2").await,
                "a malformed event must be discarded from the pending set"
            );

            let (quantity, event_type): (i64, String) = sqlx::query_as(
                "SELECT quantity, event_type FROM metering_events WHERE tenant_id = $1",
            )
            .bind(tenant)
            .fetch_one(&env.pool)
            .await
            .expect("metering row");
            assert_eq!(quantity, 7);
            assert_eq!(event_type, "api_calls");
            let audits: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM audit_logs WHERE tenant_id = $1
             AND action = 'billing.metering_event_recovered'",
            )
            .bind(tenant)
            .fetch_one(&env.pool)
            .await
            .expect("count audits");
            assert_eq!(audits, 1);
            assert!(!redis_exists(env, "meter:pending:raw-1").await);
            assert!(!redis_exists(env, "meter:pending:raw-2").await);

            // Re-running is a clean no-op FOR THIS TEST'S EVENTS: the drain's
            // counters are global (they cover a sibling test's pending keys
            // too when the suite runs in parallel), so the replay is asserted
            // through this tenant's row count and pending keys instead.
            drain_pending_metering_events(&env.state, 100)
                .await
                .expect("replay");
            let rows: i64 =
                sqlx::query_scalar("SELECT COUNT(*) FROM metering_events WHERE tenant_id = $1")
                    .bind(tenant)
                    .fetch_one(&env.pool)
                    .await
                    .expect("count rows");
            assert_eq!(rows, 1, "replay must not double-insert");
        }
    );

    // ---------------- invoice archival ----------------

    async fn seed_invoice_row(
        env: &Env,
        id: Uuid,
        tenant: &str,
        status: &str,
        issued_at: DateTime<Utc>,
        paid_at: Option<DateTime<Utc>>,
        pdf_url: Option<&str>,
    ) {
        sqlx::query(
            "INSERT INTO invoices (id, tenant_id, amount, currency, status, invoice_number,
                                   subtotal, vat_total, total, issued_at, paid_at, pdf_url,
                                   due_at, period_start, period_end, created_at, updated_at)
             VALUES ($1, $2, 100, 'EUR', $3, $4, 100, 0, 100, $5, $6, $7,
                     $5, $5, $5, $5, $5)",
        )
        .bind(id)
        .bind(tenant)
        .bind(status)
        .bind(format!("MTCOV-{}", id.simple()))
        .bind(issued_at)
        .bind(paid_at)
        .bind(pdf_url)
        .execute(&env.pool)
        .await
        .expect("seed invoice");
    }

    env_test!(
        archive_paid_invoices_respects_window_and_is_idempotent,
        |env| {
            let tenant = "mtcov_archive";
            seed_tenant(env, tenant, "free", "active").await;
            let now = Utc::now();
            let old = now - chrono::Duration::days(120);

            let archivable = Uuid::new_v4();
            let no_pdf = Uuid::new_v4();
            let recent = Uuid::new_v4();
            let unpaid = Uuid::new_v4();
            seed_invoice_row(
                env,
                archivable,
                tenant,
                "paid",
                old,
                Some(old),
                Some("https://pdf/1"),
            )
            .await;
            seed_invoice_row(env, no_pdf, tenant, "paid", old, Some(old), None).await;
            seed_invoice_row(
                env,
                recent,
                tenant,
                "paid",
                now - chrono::Duration::days(5),
                Some(now),
                Some("https://pdf/2"),
            )
            .await;
            seed_invoice_row(
                env,
                unpaid,
                tenant,
                "pending",
                old,
                None,
                Some("https://pdf/3"),
            )
            .await;

            assert_eq!(archive_paid_invoices(&env.state).await.expect("archive"), 1);
            assert_eq!(archive_paid_invoices(&env.state).await.expect("replay"), 0);
            let archived: Vec<Uuid> = sqlx::query_scalar("SELECT invoice_id FROM invoice_archives")
                .fetch_all(&env.pool)
                .await
                .expect("archives");
            assert_eq!(archived, vec![archivable]);
        }
    );

    env_test!(archive_paid_invoices_empty_table_is_zero, |env| {
        assert_eq!(
            archive_paid_invoices(&env.state)
                .await
                .expect("empty archive"),
            0
        );
    });

    // P3 item 7, invoice archival was one INSERT per candidate (up to 500 a
    // day). The whole batch is now ONE multi-row INSERT; the counter proves
    // three invoices cost one statement, not three.
    env_test!(archive_paid_invoices_is_one_statement_per_batch, |env| {
        use crate::test_support::query_count;

        let tenant = "mtcov_archive_batch";
        seed_tenant(env, tenant, "free", "active").await;
        let old = Utc::now() - chrono::Duration::days(120);
        for _ in 0..3 {
            seed_invoice_row(
                env,
                Uuid::new_v4(),
                tenant,
                "paid",
                old,
                Some(old),
                Some("https://pdf/batch"),
            )
            .await;
        }

        query_count::reset();
        let archived = archive_paid_invoices(&env.state).await.expect("archive");
        assert_eq!(archived, 3);
        assert_eq!(
            query_count::count("archive.db.insert"),
            1,
            "one multi-row INSERT for the whole batch"
        );

        query_count::reset();
        assert_eq!(
            archive_paid_invoices(&env.state)
                .await
                .expect("archive replay"),
            0
        );
        assert_eq!(
            query_count::count("archive.db.insert"),
            0,
            "nothing left to archive issues no INSERT"
        );
    });

    // Regression guard for the batch-error path: one poisoned archive row
    // must not discard its batch-mates. The batch INSERT aborts on the
    // trigger, the per-row fallback archives the two healthy invoices and
    // logs the failing one, the pre-fallback code returned Err and archived
    // ZERO.
    env_test!(archive_paid_invoices_isolates_a_poisoned_row, |env| {
        let tenant = "mtcov_archive_poison";
        seed_tenant(env, tenant, "free", "active").await;
        let old = Utc::now() - chrono::Duration::days(120);
        let ids: Vec<Uuid> = (0..3).map(|_| Uuid::new_v4()).collect();
        for id in &ids {
            seed_invoice_row(
                env,
                *id,
                tenant,
                "paid",
                old,
                Some(old),
                Some("https://pdf/poison"),
            )
            .await;
        }
        // The seeded invoice_number is `MTCOV-<uuid simple>` (identifier-safe:
        // ASCII hex + dash only, so embedding it in DDL cannot inject).
        let poison_number = format!("MTCOV-{}", ids[1].simple());
        sqlx::query(&format!(
            "CREATE FUNCTION test_poison_invoice_archive() RETURNS trigger AS $$ \
             BEGIN \
                 IF NEW.invoice_number = '{poison_number}' THEN \
                     RAISE EXCEPTION 'poisoned invoice archive row'; \
                 END IF; \
                 RETURN NEW; \
             END $$ LANGUAGE plpgsql"
        ))
        .execute(&env.pool)
        .await
        .expect("trigger function");
        sqlx::query(
            "CREATE TRIGGER test_poison_invoice_archive BEFORE INSERT ON invoice_archives \
             FOR EACH ROW EXECUTE FUNCTION test_poison_invoice_archive()",
        )
        .execute(&env.pool)
        .await
        .expect("trigger");

        let archived = archive_paid_invoices(&env.state).await.expect("archive");
        assert_eq!(archived, 2, "the two healthy invoices are archived");
        let rows: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM invoice_archives")
            .fetch_one(&env.pool)
            .await
            .expect("archive count");
        assert_eq!(rows, 2);
    });

    // ---------------- month-end closing ----------------

    env_test!(
        month_end_closing_marks_only_previous_month_paid_and_is_idempotent,
        |env| {
            let tenant = "mtcov_close";
            seed_tenant(env, tenant, "free", "active").await;
            let now = Utc::now();
            let this_month = now
                .date_naive()
                .with_day(1)
                .expect("first")
                .and_hms_opt(0, 0, 0)
                .expect("midnight")
                .and_utc();
            let last_month = this_month - chrono::Months::new(1);
            let mid_last_month = last_month + chrono::Duration::days(10);
            let three_months_ago = this_month - chrono::Months::new(3);

            let target_paid = Uuid::new_v4();
            let target_unpaid = Uuid::new_v4();
            let outside = Uuid::new_v4();
            seed_invoice_row(
                env,
                target_paid,
                tenant,
                "paid",
                mid_last_month,
                Some(mid_last_month),
                None,
            )
            .await;
            seed_invoice_row(
                env,
                target_unpaid,
                tenant,
                "pending",
                mid_last_month,
                None,
                None,
            )
            .await;
            seed_invoice_row(
                env,
                outside,
                tenant,
                "paid",
                three_months_ago,
                Some(three_months_ago),
                None,
            )
            .await;

            assert!(perform_month_end_closing(&env.state)
                .await
                .expect("closing"));
            assert!(!perform_month_end_closing(&env.state).await.expect("replay"));

            let closed: Vec<(Uuid, Option<DateTime<Utc>>)> =
                sqlx::query_as("SELECT id, closed_at FROM invoices ORDER BY id")
                    .fetch_all(&env.pool)
                    .await
                    .expect("invoices");
            for (id, closed_at) in closed {
                if id == target_paid {
                    assert!(closed_at.is_some(), "target paid invoice closed");
                } else {
                    assert!(
                        closed_at.is_none(),
                        "invoice {id} outside the window untouched"
                    );
                }
            }
            let closings: (i64, i64, i64) = sqlx::query_as(
                "SELECT COUNT(*)::bigint, COALESCE(SUM(total_invoices),0)::bigint,
                    COALESCE(SUM(total_revenue_cents),0)::bigint
             FROM month_end_closings",
            )
            .fetch_one(&env.pool)
            .await
            .expect("closings");
            assert_eq!(closings, (1, 1, 100));
        }
    );

    // ---------------- expired trials ----------------

    env_test!(
        expired_trials_sweep_downgrades_only_stale_paid_plan_trials,
        |env| {
            let stale = "mtcov_trial_stale";
            let fresh = "mtcov_trial_fresh";
            let free = "mtcov_trial_free";
            for tenant in [stale, fresh, free] {
                seed_tenant(env, tenant, "growth", "active").await;
            }
            sqlx::query("UPDATE tenants SET plan = 'free' WHERE id = $1")
                .bind(free)
                .execute(&env.pool)
                .await
                .expect("downgrade free tenant");
            let now = Utc::now();
            for (tenant, sub, trial_end) in [
                (stale, "sub_trial_stale", now - chrono::Duration::hours(48)),
                (fresh, "sub_trial_fresh", now - chrono::Duration::hours(1)),
                (free, "sub_trial_free", now - chrono::Duration::hours(48)),
            ] {
                sqlx::query(
                    "INSERT INTO mollie_subscriptions
                     (tenant_id, mollie_subscription_id, plan, status, trial_end,
                      billing_cycle_start, billing_cycle_end)
                 VALUES ($1, $2, 'growth', 'trialing', $3, $4, $5)",
                )
                .bind(tenant)
                .bind(sub)
                .bind(trial_end)
                .bind(now - chrono::Duration::days(14))
                .bind(now + chrono::Duration::days(16))
                .execute(&env.pool)
                .await
                .expect("seed trial");
            }

            assert_eq!(
                sweep_expired_trials(&env.state).await.expect("trial sweep"),
                1
            );
            assert_eq!(sweep_expired_trials(&env.state).await.expect("replay"), 0);
            let (plan, status): (String, String) = sqlx::query_as(
                "SELECT t.plan, s.status FROM tenants t
                            JOIN mollie_subscriptions s ON s.tenant_id = t.id WHERE t.id = $1",
            )
            .bind(stale)
            .fetch_one(&env.pool)
            .await
            .expect("stale tenant");
            assert_eq!(plan, "free");
            assert_eq!(status, "canceled");
            let fresh_status: String =
                sqlx::query_scalar("SELECT status FROM mollie_subscriptions WHERE tenant_id = $1")
                    .bind(fresh)
                    .fetch_one(&env.pool)
                    .await
                    .expect("fresh status");
            assert_eq!(fresh_status, "trialing", "a recent trial is never raced");
        }
    );

    // ---------------- wallet credit expiry ----------------

    env_test!(
        wallet_credit_expiry_respects_fifo_and_never_goes_negative,
        |env| {
            let expiring = "mtcov_credit_expire";
            let covered = "mtcov_credit_covered";
            for tenant in [expiring, covered] {
                seed_tenant(env, tenant, "free", "active").await;
            }

            // 100 stale credit, no debits → the full 100 expires.
            let wallet_a = Uuid::new_v4();
            sqlx::query("INSERT INTO wallets (id, tenant_id, balance, currency) VALUES ($1, $2, 100, 'EUR')")
            .bind(wallet_a)
            .bind(expiring)
            .execute(&env.pool)
            .await
            .expect("wallet a");
            sqlx::query(
            "INSERT INTO wallet_transactions (wallet_id, tenant_id, type, amount, balance_after, description, created_at)
             VALUES ($1, $2, 'credit', 100, 100, 'stale grant', NOW() - INTERVAL '13 months')",
        )
        .bind(wallet_a)
        .bind(expiring)
        .execute(&env.pool)
        .await
        .expect("credit a");

            // 100 stale credit but 150 debits → nothing expires (FIFO consumed).
            let wallet_b = Uuid::new_v4();
            sqlx::query("INSERT INTO wallets (id, tenant_id, balance, currency) VALUES ($1, $2, 200, 'EUR')")
            .bind(wallet_b)
            .bind(covered)
            .execute(&env.pool)
            .await
            .expect("wallet b");
            sqlx::query(
            "INSERT INTO wallet_transactions (wallet_id, tenant_id, type, amount, balance_after, description, created_at)
             VALUES ($1, $2, 'credit', 100, 100, 'stale grant', NOW() - INTERVAL '13 months'),
                    ($1, $2, 'credit', 250, 350, 'recent grant', NOW() - INTERVAL '1 month'),
                    ($1, $2, 'debit', 150, 200, 'spend', NOW() - INTERVAL '2 months')",
        )
        .bind(wallet_b)
        .bind(covered)
        .execute(&env.pool)
        .await
        .expect("ledger b");

            assert_eq!(
                expire_stale_wallet_credits(&env.state)
                    .await
                    .expect("expire"),
                1
            );
            assert_eq!(
                expire_stale_wallet_credits(&env.state)
                    .await
                    .expect("replay"),
                0,
                "the expiry debit counts as consumption on the next run"
            );
            let balance_a: i64 =
                sqlx::query_scalar("SELECT balance FROM wallets WHERE tenant_id = $1")
                    .bind(expiring)
                    .fetch_one(&env.pool)
                    .await
                    .expect("balance a");
            assert_eq!(balance_a, 0);
            let balance_b: i64 =
                sqlx::query_scalar("SELECT balance FROM wallets WHERE tenant_id = $1")
                    .bind(covered)
                    .fetch_one(&env.pool)
                    .await
                    .expect("balance b");
            assert_eq!(balance_b, 200, "covered credits never expire");
            let expiry_rows: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM wallet_transactions WHERE tenant_id = $1 AND reference = 'wallet_credit_expiry'",
        )
        .bind(expiring)
        .fetch_one(&env.pool)
        .await
        .expect("expiry rows");
            assert_eq!(expiry_rows, 1);
            let audits: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM audit_logs WHERE tenant_id = $1 AND action = 'billing.wallet_credit_expired'",
        )
        .bind(expiring)
        .fetch_one(&env.pool)
        .await
        .expect("audit rows");
            assert_eq!(audits, 1);
        }
    );

    // ---------------- payment recovery / restrictions ----------------

    async fn seed_billing_hold(env: &Env, tenant: &str, invoice: &str) {
        sqlx::query(
            "INSERT INTO tenant_restrictions (tenant_id, kind, reason, actor_type)
             VALUES ($1, 'billing', 'failed payment', 'system')",
        )
        .bind(tenant)
        .execute(&env.pool)
        .await
        .expect("restriction");
        sqlx::query(
            "INSERT INTO dunning_records (id, tenant_id, invoice_id, status, next_retry_at, failed_payment_count)
             VALUES ($1, $2, $3, 'warning', NOW(), 1)",
        )
        .bind(format!("dun_{}", &tenant[..tenant.len().min(20)]))
        .bind(tenant)
        .bind(invoice)
        .execute(&env.pool)
        .await
        .expect("dunning record");
        sqlx::query(
            "INSERT INTO dunning_events (tenant_id, invoice_id, event_type) VALUES ($1, $2, 'payment_failed')",
        )
        .bind(tenant)
        .bind(invoice)
        .execute(&env.pool)
        .await
        .expect("dunning event");
        sqlx::query(
            "INSERT INTO messages (tenant_id, from_email, to_emails, status)
             VALUES ($1, 'a@b.c', '[]'::jsonb, 'dunning_queued')",
        )
        .bind(tenant)
        .execute(&env.pool)
        .await
        .expect("queued message");
    }

    env_test!(
        payment_recovery_clears_only_billing_hold_for_the_settled_invoice,
        |env| {
            let tenant = "mtcov_recovery";
            seed_tenant(env, tenant, "free", "suspended").await;
            seed_billing_hold(env, tenant, "in_A").await;

            mark_payment_recovered(&env.state, tenant, Some("in_A"))
                .await
                .expect("recovery");
            let (status, retry): (String, Option<DateTime<Utc>>) = sqlx::query_as(
                "SELECT status, next_retry_at FROM dunning_records WHERE tenant_id = $1",
            )
            .bind(tenant)
            .fetch_one(&env.pool)
            .await
            .expect("dunning");
            assert_eq!(status, "healthy");
            assert!(retry.is_none());
            let tenant_status: String =
                sqlx::query_scalar("SELECT status FROM tenants WHERE id = $1")
                    .bind(tenant)
                    .fetch_one(&env.pool)
                    .await
                    .expect("tenant");
            assert_eq!(tenant_status, "active");
            let cleared: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM tenant_restrictions WHERE tenant_id = $1 AND cleared_at IS NOT NULL",
        )
        .bind(tenant)
        .fetch_one(&env.pool)
        .await
        .expect("cleared");
            assert_eq!(cleared, 1);
            let queued: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM messages WHERE tenant_id = $1 AND status = 'queued'",
            )
            .bind(tenant)
            .fetch_one(&env.pool)
            .await
            .expect("messages");
            assert_eq!(queued, 1, "queued mail is released on recovery");
            let recovered_events: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM dunning_events WHERE tenant_id = $1 AND event_type = 'payment_recovered'",
        )
        .bind(tenant)
        .fetch_one(&env.pool)
        .await
        .expect("recovery event");
            assert_eq!(recovered_events, 1);
        }
    );

    env_test!(
        payment_recovery_for_a_different_invoice_keeps_dunning,
        |env| {
            let tenant = "mtcov_recovery_scope";
            seed_tenant(env, tenant, "free", "suspended").await;
            seed_billing_hold(env, tenant, "in_current").await;

            mark_payment_recovered(&env.state, tenant, Some("in_other"))
                .await
                .expect("scoped recovery");
            let (status, retry): (String, Option<DateTime<Utc>>) = sqlx::query_as(
                "SELECT status, next_retry_at FROM dunning_records WHERE tenant_id = $1",
            )
            .bind(tenant)
            .fetch_one(&env.pool)
            .await
            .expect("dunning");
            assert_eq!(status, "warning", "another failing invoice keeps dunning");
            assert!(retry.is_some());
            let tenant_status: String =
                sqlx::query_scalar("SELECT status FROM tenants WHERE id = $1")
                    .bind(tenant)
                    .fetch_one(&env.pool)
                    .await
                    .expect("tenant");
            assert_eq!(tenant_status, "suspended");
            let queued: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM messages WHERE tenant_id = $1 AND status = 'dunning_queued'",
            )
            .bind(tenant)
            .fetch_one(&env.pool)
            .await
            .expect("messages");
            assert_eq!(queued, 1, "mail stays held");
        }
    );

    env_test!(
        payment_recovery_never_clears_administrative_or_abuse_holds,
        |env| {
            let tenant = "mtcov_recovery_admin";
            seed_tenant(env, tenant, "free", "suspended").await;
            seed_billing_hold(env, tenant, "in_A").await;
            sqlx::query(
                "INSERT INTO tenant_restrictions (tenant_id, kind, reason, actor_type)
             VALUES ($1, 'administrative', 'fraud review', 'admin')",
            )
            .bind(tenant)
            .execute(&env.pool)
            .await
            .expect("admin restriction");

            mark_payment_recovered(&env.state, tenant, Some("in_A"))
                .await
                .expect("recovery");
            let tenant_status: String =
                sqlx::query_scalar("SELECT status FROM tenants WHERE id = $1")
                    .bind(tenant)
                    .fetch_one(&env.pool)
                    .await
                    .expect("tenant");
            assert_eq!(
                tenant_status, "suspended",
                "an administrative hold must survive payment recovery"
            );
            let queued: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM messages WHERE tenant_id = $1 AND status = 'dunning_queued'",
            )
            .bind(tenant)
            .fetch_one(&env.pool)
            .await
            .expect("messages");
            assert_eq!(queued, 1, "mail is not released while a hold remains");
            let billing_cleared: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM tenant_restrictions WHERE tenant_id = $1 AND kind = 'billing' AND cleared_at IS NOT NULL",
        )
        .bind(tenant)
        .fetch_one(&env.pool)
        .await
        .expect("billing cleared");
            assert_eq!(billing_cleared, 1, "the billing hold itself was cleared");
        }
    );

    // ---------------- SLA credits ----------------

    env_test!(
        sla_credits_use_integer_half_up_and_are_created_once,
        |env| {
            let tenant = "mtcov_sla";
            seed_tenant(env, tenant, "slacov", "active").await;
            seed_plan(
                env,
                "slacov",
                100_000,
                json!({"slaGuarantee": true, "slaCreditPercentage": 50}),
            )
            .await;
            let now = Utc::now();
            let this_month = now
                .date_naive()
                .with_day(1)
                .expect("first")
                .and_hms_opt(0, 0, 0)
                .expect("midnight")
                .and_utc();
            let last_month = this_month - chrono::Months::new(1);
            let period_date = last_month.date_naive();
            sqlx::query(
                "INSERT INTO sla_metrics (tenant_id, period_month, uptime_percent)
             VALUES ($1, $2, 98.5000)",
            )
            .bind(tenant)
            .bind(period_date)
            .execute(&env.pool)
            .await
            .expect("sla metric");
            let invoice = Uuid::new_v4();
            seed_invoice_row(
                env,
                invoice,
                tenant,
                "paid",
                last_month + chrono::Duration::days(5),
                Some(last_month + chrono::Duration::days(6)),
                None,
            )
            .await;
            sqlx::query(
                "UPDATE invoices SET total = 10000, subtotal = 10000, amount = 10000 WHERE id = $1",
            )
            .bind(invoice)
            .execute(&env.pool)
            .await
            .expect("invoice total");

            let first = process_monthly_sla_credits(&env.state).await.expect("sla");
            assert_eq!(first.credits_created, 1, "{first:?}");
            let replay = process_monthly_sla_credits(&env.state)
                .await
                .expect("sla replay");
            assert_eq!(replay.credits_created, 0);

            // 1.5% breach → 50% of a 10 000-cent invoice = 5 000, capped at the
            // plan's 50% SLA cap (also 5 000).
            let (credit_amount, credit_percent, currency, status): (i32, f64, String, String) =
                sqlx::query_as(
                    "SELECT credit_amount, credit_percent::double precision, currency, status
                 FROM sla_credits WHERE tenant_id = $1",
                )
                .bind(tenant)
                .fetch_one(&env.pool)
                .await
                .expect("sla credit");
            assert_eq!(credit_amount, 5_000);
            assert_eq!(credit_percent, 50.0);
            assert_eq!(currency, "EUR");
            assert_eq!(status, "pending");
        }
    );

    // P3 fix 1, the SLA sweep must not scale its DB round trips with the
    // number of breaching candidates. Before the fix each candidate cost two
    // invoice reads plus its own advisory lock + existence check + insert
    // (≈5 statements/row). The batched pass loads every candidate's invoice
    // aggregate in ONE query and persists all credits in ONE locked
    // transaction. The test compares the statement counters of a 1-candidate
    // pass with a 3-candidate pass: they must be identical, and the insert
    // must be one statement. (Thread-local counters: isolated from the other
    // tests running in this binary.)
    env_test!(
        sla_sweep_statement_count_is_constant_in_candidate_count,
        |env| {
            use crate::test_support::query_count;

            let now = Utc::now();
            let this_month = now
                .date_naive()
                .with_day(1)
                .expect("first")
                .and_hms_opt(0, 0, 0)
                .expect("midnight")
                .and_utc();
            let last_month = this_month - chrono::Months::new(1);
            let period_date = last_month.date_naive();
            seed_plan(
                env,
                "slabatch",
                100_000,
                json!({"slaGuarantee": true, "slaCreditPercentage": 100}),
            )
            .await;

            async fn seed_candidate(
                env: &Env,
                tenant: &str,
                total_cents: i64,
                last_month: DateTime<Utc>,
                period_date: chrono::NaiveDate,
            ) {
                seed_tenant(env, tenant, "slabatch", "active").await;
                sqlx::query(
                    "INSERT INTO sla_metrics (tenant_id, period_month, uptime_percent)
                 VALUES ($1, $2, 98.5000)",
                )
                .bind(tenant)
                .bind(period_date)
                .execute(&env.pool)
                .await
                .expect("sla metric");
                let invoice = Uuid::new_v4();
                seed_invoice_row(
                    env,
                    invoice,
                    tenant,
                    "paid",
                    last_month + chrono::Duration::days(5),
                    Some(last_month + chrono::Duration::days(6)),
                    None,
                )
                .await;
                sqlx::query(
                    "UPDATE invoices SET total = $2, subtotal = $2, amount = $2 WHERE id = $1",
                )
                .bind(invoice)
                .bind(total_cents)
                .execute(&env.pool)
                .await
                .expect("invoice total");
            }

            seed_candidate(env, "mtcov_slabatch_a", 10_000, last_month, period_date).await;
            query_count::reset();
            let one = process_monthly_sla_credits(&env.state)
                .await
                .expect("one-candidate sweep");
            assert_eq!(one.credits_created, 1, "{one:?}");
            let one_counts = (
                query_count::count("sla.db.candidates"),
                query_count::count("sla.db.invoice_aggregate"),
                query_count::count("sla.db.lock_batch"),
                query_count::count("sla.db.existing_batch"),
                query_count::count("sla.db.insert_batch"),
            );
            assert_eq!(one_counts, (1, 1, 1, 1, 1), "one row = five statements");

            // Two more candidates: the SAME five statements, not fifteen.
            seed_candidate(env, "mtcov_slabatch_b", 20_000, last_month, period_date).await;
            seed_candidate(env, "mtcov_slabatch_c", 30_000, last_month, period_date).await;
            query_count::reset();
            let three = process_monthly_sla_credits(&env.state)
                .await
                .expect("three-candidate sweep");
            assert_eq!(
                three.credits_created, 2,
                "the first row is already credited"
            );
            let three_counts = (
                query_count::count("sla.db.candidates"),
                query_count::count("sla.db.invoice_aggregate"),
                query_count::count("sla.db.lock_batch"),
                query_count::count("sla.db.existing_batch"),
                query_count::count("sla.db.insert_batch"),
            );
            assert_eq!(
                three_counts, one_counts,
                "statement count must be constant in the candidate count"
            );

            // Integer cents and per-invoice currency survive the batching:
            // 1.5% breach → 50% credit, no cap.
            let rows: Vec<(String, i32, String)> = sqlx::query_as(
                "SELECT tenant_id, credit_amount, currency FROM sla_credits
              WHERE tenant_id LIKE 'mtcov_slabatch_%' ORDER BY tenant_id",
            )
            .fetch_all(&env.pool)
            .await
            .expect("sla credits");
            assert_eq!(
                rows,
                vec![
                    ("mtcov_slabatch_a".to_string(), 5_000, "EUR".to_string()),
                    ("mtcov_slabatch_b".to_string(), 10_000, "EUR".to_string()),
                    ("mtcov_slabatch_c".to_string(), 15_000, "EUR".to_string()),
                ],
                "half-up integer cents: 50% of the paid invoice total"
            );

            // Replay: nothing new, same read/lock/check shape.
            query_count::reset();
            let replay = process_monthly_sla_credits(&env.state)
                .await
                .expect("replay");
            assert_eq!(replay.credits_created, 0);
            assert_eq!(query_count::count("sla.db.candidates"), 1);
            assert_eq!(query_count::count("sla.db.invoice_aggregate"), 1);
            assert_eq!(query_count::count("sla.db.lock_batch"), 1);
            assert_eq!(query_count::count("sla.db.existing_batch"), 1);
            assert_eq!(
                query_count::count("sla.db.insert_batch"),
                0,
                "an idempotent replay issues no insert"
            );
        }
    );

    // F-audit P2 (PostgreSQL 65,535-parameter ceiling): the SLA credit INSERT
    // must chunk an oversized candidate set. The chunk size is shrunk here
    // (production uses the pinned 5,000-row constant) so a 5-candidate sweep
    // crosses the boundary: 5 rows / 2 per statement = 3 INSERTs, with every
    // credit persisted and the replay still idempotent.
    //
    // Fail-before: the unbounded single `push_values` issues exactly ONE
    // insert statement for all 5 candidates.
    env_test!(
        sla_credit_insert_chunks_above_the_parameter_boundary,
        |env| {
            use crate::test_support::query_count;

            let now = Utc::now();
            let this_month = now
                .date_naive()
                .with_day(1)
                .expect("first")
                .and_hms_opt(0, 0, 0)
                .expect("midnight")
                .and_utc();
            let last_month = this_month - chrono::Months::new(1);
            let period_date = last_month.date_naive();
            seed_plan(
                env,
                "slachunk",
                100_000,
                json!({"slaGuarantee": true, "slaCreditPercentage": 100}),
            )
            .await;

            for index in 0..5 {
                let tenant = format!("mtcov_slachunk_{index}");
                seed_tenant(env, &tenant, "slachunk", "active").await;
                sqlx::query(
                    "INSERT INTO sla_metrics (tenant_id, period_month, uptime_percent)
                     VALUES ($1, $2, 98.5000)",
                )
                .bind(&tenant)
                .bind(period_date)
                .execute(&env.pool)
                .await
                .expect("sla metric");
                let invoice = Uuid::new_v4();
                seed_invoice_row(
                    env,
                    invoice,
                    &tenant,
                    "paid",
                    last_month + chrono::Duration::days(5),
                    Some(last_month + chrono::Duration::days(6)),
                    None,
                )
                .await;
                sqlx::query(
                    "UPDATE invoices SET total = 10000, subtotal = 10000, amount = 10000 WHERE id = $1",
                )
                .bind(invoice)
                .execute(&env.pool)
                .await
                .expect("invoice total");
            }

            query_count::reset();
            let sweep = process_monthly_sla_credits_chunked(&env.state, 2)
                .await
                .expect("chunked sla sweep");
            assert_eq!(sweep.credits_created, 5, "all five credits created");
            assert_eq!(
                query_count::count("sla.db.insert_batch"),
                3,
                "5 rows at 2 per chunk = 3 SLA credit INSERTs"
            );

            let persisted: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM sla_credits WHERE tenant_id LIKE 'mtcov_slachunk_%'",
            )
            .fetch_one(&env.pool)
            .await
            .expect("sla credit count");
            assert_eq!(persisted, 5, "every credit persists across chunks");

            // The chunked replay still creates nothing new.
            let replay = process_monthly_sla_credits_chunked(&env.state, 2)
                .await
                .expect("chunked replay");
            assert_eq!(replay.credits_created, 0);

            // The production chunk size stays inside the bind ceiling (9
            // binds per SLA credit row).
            const {
                assert!(SLA_CREDIT_INSERT_CHUNK_ROWS * 9 <= 65_535);
            }
        }
    );

    // ---------------- cost margin + throttling ----------------

    env_test!(cost_margin_alerts_and_throttle_lifecycle, |env| {
        let tenant = "mtcov_margin";
        seed_tenant(env, tenant, "free", "active").await;
        let key = billing_common::cost_throttle::cost_throttle_key(tenant);
        redis_del(env, &key).await;
        let today = Utc::now().date_naive();
        sqlx::query(
            "INSERT INTO tenant_costs (tenant_id, recorded_at, total_cost, revenue)
             VALUES ($1, $2, 100, 10)",
        )
        .bind(tenant)
        .bind(today)
        .execute(&env.pool)
        .await
        .expect("critical costs");

        let sweep = process_cost_margin_checks(&env.state)
            .await
            .expect("margin");
        assert!(sweep.critical >= 1, "{sweep:?}");
        assert!(redis_exists(env, &key).await, "throttle key must be set");
        let alerts: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM cost_alerts WHERE tenant_id = $1 AND resolved_at IS NULL",
        )
        .bind(tenant)
        .fetch_one(&env.pool)
        .await
        .expect("alerts");
        assert_eq!(alerts, 1);
        let queued: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM notification_queue WHERE tenant_id = $1 AND type = 'cost_alert'",
        )
        .bind(tenant)
        .fetch_one(&env.pool)
        .await
        .expect("notifications");
        assert_eq!(queued, 1);
        // Re-running must not duplicate the open alert or its notification.
        let replay = process_cost_margin_checks(&env.state)
            .await
            .expect("margin replay");
        assert!(replay.critical >= 1);
        let alerts: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM cost_alerts WHERE tenant_id = $1 AND resolved_at IS NULL",
        )
        .bind(tenant)
        .fetch_one(&env.pool)
        .await
        .expect("alerts after replay");
        assert_eq!(alerts, 1, "open alert is not duplicated");
        let queued: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM notification_queue WHERE tenant_id = $1 AND type = 'cost_alert'",
        )
        .bind(tenant)
        .fetch_one(&env.pool)
        .await
        .expect("notifications after replay");
        assert_eq!(queued, 1, "notification is not duplicated");

        // The tenant recovers: costs drop and the throttle is cleared.
        sqlx::query("UPDATE tenant_costs SET total_cost = 10, revenue = 100 WHERE tenant_id = $1")
            .bind(tenant)
            .execute(&env.pool)
            .await
            .expect("recover costs");
        let recovered = process_cost_margin_checks(&env.state)
            .await
            .expect("recovered");
        assert!(recovered.critical == 0, "{recovered:?}");
        assert!(
            !redis_exists(env, &key).await,
            "throttle clears on recovery"
        );
        let audits: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM audit_logs WHERE tenant_id = $1
             AND action IN ('billing.cost_throttle.applied', 'billing.cost_throttle.cleared')",
        )
        .bind(tenant)
        .fetch_one(&env.pool)
        .await
        .expect("throttle audits");
        assert!(audits >= 2, "both transitions are audited: {audits}");
    });

    // ---------------- usage alerts ----------------

    env_test!(usage_alerts_trigger_once_then_respect_cooldown, |env| {
        let tenant = "mtcov_alert";
        seed_tenant(env, tenant, "alertcov", "active").await;
        seed_plan(env, "alertcov", 1_000, json!({})).await;
        let mock = Mock::default();
        mock.route("/hook", 200, "{}");
        let base = spawn_mock(mock.clone()).await;
        sqlx::query("UPDATE tenants SET settings = $2::jsonb WHERE id = $1")
            .bind(tenant)
            .bind(json!({"webhookUrl": format!("{base}/hook")}).to_string())
            .execute(&env.pool)
            .await
            .expect("tenant webhook");
        sqlx::query(
            "INSERT INTO usage_alert_configs (tenant_id, metric_type, threshold_percent, notification_channel)
             VALUES ($1, 'emails', 50, 'webhook'),
                    ($1, 'unknown_metric', 1, 'webhook')",
        )
        .bind(tenant)
        .execute(&env.pool)
        .await
        .expect("alert configs");
        sqlx::query(
            "INSERT INTO metering_events (id, tenant_id, event_type, quantity, timestamp)
             VALUES (gen_random_uuid(), $1, 'emails_sent', 600, NOW())",
        )
        .bind(tenant)
        .execute(&env.pool)
        .await
        .expect("usage");

        redis_del(env, &format!("alert:cooldown:{tenant}:emails:50")).await;
        let client = Client::new();
        let first = process_usage_alerts(&env.state, &client)
            .await
            .expect("alerts");
        assert_eq!(first.tenants_checked, 1);
        assert_eq!(first.alerts_triggered, 1, "{first:?}");
        assert_eq!(
            mock.call_count("/hook"),
            1,
            "webhook delivered once (alerts_triggered={})",
            first.alerts_triggered
        );
        let last_triggered: Option<DateTime<Utc>> = sqlx::query_scalar(
            "SELECT last_triggered_at FROM usage_alert_configs
             WHERE tenant_id = $1 AND metric_type = 'emails'",
        )
        .bind(tenant)
        .fetch_one(&env.pool)
        .await
        .expect("last triggered");
        assert!(last_triggered.is_some());

        let second = process_usage_alerts(&env.state, &client)
            .await
            .expect("alerts replay");
        assert_eq!(second.alerts_triggered, 0, "cooldown suppresses duplicates");
        assert_eq!(mock.call_count("/hook"), 1);
    });

    // The rules surface's core promise: a rule in the evaluated store fires
    // through the RUNNING sweep into `system_alerts` (the store the CP
    // /alerts page reads), carrying the rule's name, severity, and tenant —
    // and a still-holding rule refreshes ONE incident row, never a pile.
    env_test!(usage_alert_rule_fires_into_system_alerts, |env| {
        let tenant = "mtcov_rule_fire";
        seed_tenant(env, tenant, "rulefire", "active").await;
        seed_plan(env, "rulefire", 1_000, json!({})).await;
        let rule_id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO usage_alert_configs
                 (id, tenant_id, name, metric_type, threshold_percent,
                  notification_channel, severity)
             VALUES ($1, $2, 'Emails near plan limit', 'emails', 50, 'email', 'critical')",
        )
        .bind(rule_id)
        .bind(tenant)
        .execute(&env.pool)
        .await
        .expect("rule");
        sqlx::query(
            "INSERT INTO metering_events (id, tenant_id, event_type, quantity, timestamp)
             VALUES (gen_random_uuid(), $1, 'emails_sent', 600, NOW())",
        )
        .bind(tenant)
        .execute(&env.pool)
        .await
        .expect("usage");
        // The cooldown key is shared Redis and may survive a prior run.
        redis_del(env, &format!("alert:cooldown:{tenant}:emails:50")).await;

        let client = Client::new();
        let first = process_usage_alerts(&env.state, &client)
            .await
            .expect("sweep");
        assert_eq!(first.alerts_triggered, 1, "{first:?}");

        let (severity, message, recorded_tenant): (String, String, String) = sqlx::query_as(
            "SELECT severity, message, COALESCE(tenant_id, '')
             FROM system_alerts
             WHERE source = 'usage_alert' AND fingerprint = $1",
        )
        .bind(rule_id.to_string())
        .fetch_one(&env.pool)
        .await
        .expect("the fired rule must land in system_alerts");
        assert_eq!(severity, "critical");
        assert!(
            message.contains("Emails near plan limit"),
            "the rule's name must ride the incident message: {message}"
        );
        assert!(message.contains("600 / 1000"), "message: {message}");
        assert_eq!(recorded_tenant, tenant);

        // A second sweep (condition still holds, cooldown active) must not
        // duplicate the incident: one rule = one open control-plane incident.
        let second = process_usage_alerts(&env.state, &client)
            .await
            .expect("sweep replay");
        assert_eq!(second.alerts_triggered, 0);
        let incidents: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM system_alerts
             WHERE source = 'usage_alert' AND fingerprint = $1",
        )
        .bind(rule_id.to_string())
        .fetch_one(&env.pool)
        .await
        .expect("incident count");
        assert_eq!(incidents, 1, "one rule, one incident row");
    });

    // A rule whose condition does NOT hold must leave `system_alerts`
    // alone, firing on a sweep where usage is below the threshold would
    // make the console lie about the tenant's state.
    env_test!(usage_alert_rule_below_threshold_never_fires, |env| {
        let tenant = "mtcov_rule_quiet";
        seed_tenant(env, tenant, "rulequiet", "active").await;
        seed_plan(env, "rulequiet", 1_000, json!({})).await;
        sqlx::query(
            "INSERT INTO usage_alert_configs
                 (tenant_id, name, metric_type, threshold_percent,
                  notification_channel, severity)
             VALUES ($1, 'Should stay quiet', 'emails', 80, 'email', 'warning')",
        )
        .bind(tenant)
        .execute(&env.pool)
        .await
        .expect("rule");
        sqlx::query(
            "INSERT INTO metering_events (id, tenant_id, event_type, quantity, timestamp)
             VALUES (gen_random_uuid(), $1, 'emails_sent', 100, NOW())",
        )
        .bind(tenant)
        .execute(&env.pool)
        .await
        .expect("usage");

        let client = Client::new();
        let sweep = process_usage_alerts(&env.state, &client)
            .await
            .expect("sweep");
        assert_eq!(sweep.alerts_triggered, 0, "{sweep:?}");
        let incidents: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM system_alerts WHERE tenant_id = $1 AND source = 'usage_alert'",
        )
        .bind(tenant)
        .fetch_one(&env.pool)
        .await
        .expect("incident count");
        assert_eq!(incidents, 0, "10% usage must not fire an 80% rule");
    });

    env_test!(
        usage_alerts_skip_when_no_webhook_and_threshold_not_met,
        |env| {
            let tenant = "mtcov_alert_none";
            seed_tenant(env, tenant, "alertcov2", "active").await;
            seed_plan(env, "alertcov2", 1_000, json!({})).await;
            sqlx::query(
            "INSERT INTO usage_alert_configs (tenant_id, metric_type, threshold_percent, notification_channel)
             VALUES ($1, 'emails', 50, 'webhook'),
                    ($1, 'api_calls', 99, 'email')",
        )
        .bind(tenant)
        .execute(&env.pool)
        .await
        .expect("alert configs");
            // 10% usage: the 50% threshold is not met; the 99% config has no
            // email channel failure (email just enqueues), so nothing triggers.
            sqlx::query(
                "INSERT INTO metering_events (id, tenant_id, event_type, quantity, timestamp)
             VALUES (gen_random_uuid(), $1, 'emails_sent', 100, NOW())",
            )
            .bind(tenant)
            .execute(&env.pool)
            .await
            .expect("usage");
            let client = Client::new();
            let result = process_usage_alerts(&env.state, &client)
                .await
                .expect("alerts");
            assert_eq!(result.alerts_triggered, 0, "{result:?}");
        }
    );

    // ---------------- dedicated IP billing (mock Mollie) ----------------

    #[tokio::test]
    async fn dedicated_ip_charge_and_cancel_use_mocked_mollie() {
        let Some(env) = provision("dedicated_ip_charge_and_cancel").await else {
            return;
        };
        let mock = Mock::default();
        // Mollie has no subscription-item object: an add-on activation is ONE
        // recurring `POST /v2/payments` against the tenant's stored mandate.
        mock.route(
            "/v2/payments",
            200,
            r#"{"id":"tr_dip_cov","status":"paid","_links":{"checkout":{"href":"https://www.mollie.com/checkout/select-method/dip"}}}"#,
        );
        let base = spawn_mock(mock.clone()).await;

        let guard = ENV_LOCK.lock().await;
        let previous = (
            std::env::var("MOLLIE_API_KEY").ok(),
            std::env::var("MOLLIE_API_BASE_URL").ok(),
            std::env::var("MOLLIE_PROFILE_ID").ok(),
            std::env::var("DEDICATED_IP_PRICE_CENTS").ok(),
        );
        std::env::set_var("MOLLIE_API_KEY", "mollie-test-key-fixture");
        std::env::set_var("MOLLIE_API_BASE_URL", format!("{base}/v2"));
        std::env::set_var("MOLLIE_PROFILE_ID", "ApexMailTestECOM");
        // The add-on price is CENTS (minor units), never a provider price id.
        std::env::set_var("DEDICATED_IP_PRICE_CENTS", "500");

        let tenant = "mtcov_dip";
        seed_tenant(&env, tenant, "growth", "active").await;
        sqlx::query(
            "INSERT INTO mollie_subscriptions
                 (tenant_id, mollie_subscription_id, plan, status, billing_cycle_start,
                  billing_cycle_end, mollie_customer_id,
                  mollie_mandate_id)
             VALUES ($1, 'psp_dip_sub', 'growth', 'active', NOW(), NOW() + INTERVAL '30 days',
                     $1, 'tok_dip_cov')",
        )
        .bind(tenant)
        .execute(&env.pool)
        .await
        .expect("subscription");
        sqlx::query(
            "INSERT INTO dedicated_ips (id, tenant_id, ip_address, status, billing_status)
             VALUES ('cov_dip_charge', $1, '203.0.113.201', 'active', 'pending_charge'),
                    ('cov_dip_cancel', $1, '203.0.113.202', 'active', 'pending_cancel')",
        )
        .bind(tenant)
        .execute(&env.pool)
        .await
        .expect("dedicated ips");

        let client = Client::new();
        let result = process_dedicated_ip_billing(&env.state, &client)
            .await
            .expect("dip billing");
        assert_eq!(result.charged, 1, "one charge processed");
        assert_eq!(result.canceled, 1, "one cancel processed");
        // The activation charge's Mollie payment id becomes the add-on's
        // provider-side reference.
        let (charge_status, provider_ref): (String, Option<String>) = sqlx::query_as(
            "SELECT billing_status, mollie_mandate_id FROM dedicated_ips WHERE id = 'cov_dip_charge'",
        )
        .fetch_one(&env.pool)
        .await
        .expect("charged ip");
        assert_eq!(charge_status, "active");
        assert_eq!(provider_ref.as_deref(), Some("tr_dip_cov"));
        let cancel_status: String = sqlx::query_scalar(
            "SELECT billing_status FROM dedicated_ips WHERE id = 'cov_dip_cancel'",
        )
        .fetch_one(&env.pool)
        .await
        .expect("canceled ip");
        assert_eq!(cancel_status, "canceled", "cancel is a local transition");

        // The single payment call carries the Mollie contract: Bearer auth,
        // deterministic Idempotency-Key, decimal amount, sequenceType
        // recurring with customer+mandate, and our reference in metadata.
        assert_eq!(
            mock.call_count("/v2/payments"),
            1,
            "cancels make no HTTP call"
        );
        let call = mock.last_call("/v2/payments").expect("charge call");
        assert_eq!(call.method, "POST");
        assert_eq!(
            call.headers.get("authorization").map(String::as_str),
            Some("Bearer mollie-test-key-fixture"),
            "the secret key authenticates the charge"
        );
        assert_eq!(
            call.headers.get("idempotency-key").map(String::as_str),
            Some("dedicated_ip_cov_dip_charge"),
            "the add-on's own identity is the deterministic key"
        );
        let body: serde_json::Value = serde_json::from_str(&call.body).expect("payment body JSON");
        assert_eq!(
            body["amount"],
            serde_json::json!({"currency": "EUR", "value": "5.00"}),
            "Mollie amounts travel as decimal strings, never minor units"
        );
        assert_eq!(
            body["sequenceType"],
            serde_json::json!("recurring"),
            "the add-on is charged against the stored mandate"
        );
        assert_eq!(body["customerId"], serde_json::json!(tenant));
        assert_eq!(body["mandateId"], serde_json::json!("tok_dip_cov"));
        assert_eq!(
            body["metadata"]["reference"],
            serde_json::json!("dedicated_ip:cov_dip_charge")
        );
        assert_eq!(
            body["metadata"]["type"],
            serde_json::json!("dedicated_ip_addon")
        );

        // Failure isolation: a pending charge with NO active subscription
        // records retry metadata instead of aborting the sweep.
        sqlx::query(
            "INSERT INTO dedicated_ips (id, tenant_id, ip_address, status, billing_status)
             VALUES ('cov_dip_orphan', $1, '203.0.113.203', 'active', 'pending_charge')",
        )
        .bind(tenant)
        .execute(&env.pool)
        .await
        .expect("orphan ip");
        sqlx::query("UPDATE mollie_subscriptions SET status = 'canceled' WHERE tenant_id = $1")
            .bind(tenant)
            .execute(&env.pool)
            .await
            .expect("cancel subscription");
        let failed = process_dedicated_ip_billing(&env.state, &client)
            .await
            .expect("failure isolation");
        assert_eq!(failed.charged, 0);
        let (failure_count, retry_after, billing): (i32, Option<DateTime<Utc>>, String) =
            sqlx::query_as(
                "SELECT billing_failure_count, billing_retry_after, billing_status
                 FROM dedicated_ips WHERE id = 'cov_dip_orphan'",
            )
            .fetch_one(&env.pool)
            .await
            .expect("orphan state");
        assert_eq!(failure_count, 1);
        assert!(retry_after.is_some(), "backoff recorded for retry");
        assert_eq!(
            billing, "pending_charge",
            "still pending, never silently dropped"
        );
        assert_eq!(
            mock.call_count("/v2/payments"),
            1,
            "a tokenless/subscriptionless charge never reaches the provider"
        );

        match previous {
            (Some(key), Some(url), Some(merchant), Some(price)) => {
                std::env::set_var("MOLLIE_API_KEY", key);
                std::env::set_var("MOLLIE_API_BASE_URL", url);
                std::env::set_var("MOLLIE_PROFILE_ID", merchant);
                std::env::set_var("DEDICATED_IP_PRICE_CENTS", price);
            }
            _ => {
                std::env::remove_var("MOLLIE_API_KEY");
                std::env::remove_var("MOLLIE_API_BASE_URL");
                std::env::remove_var("MOLLIE_PROFILE_ID");
                std::env::remove_var("DEDICATED_IP_PRICE_CENTS");
            }
        }
        drop(guard);
        env.finish().await;
    }

    // ---------------- scheduled retries (mock Mollie) ----------------

    #[tokio::test]
    async fn scheduled_retries_pay_the_open_invoice_once() {
        let Some(env) = provision("scheduled_retries_pay").await else {
            return;
        };
        let mock = Mock::default();
        // Mollie has no provider-side invoice objects: the retry charges the
        // tenant's OWN open (pending) LOCAL invoice with ONE recurring
        // `POST /v2/payments` against the stored mandate.
        mock.route(
            "/v2/payments",
            200,
            r#"{"id":"tr_retry_pay","status":"paid","_links":{"checkout":{"href":"https://www.mollie.com/checkout/select-method/retry"}}}"#,
        );
        let base = spawn_mock(mock.clone()).await;

        let guard = ENV_LOCK.lock().await;
        let previous = (
            std::env::var("AUTO_PAY_OPEN_INVOICES").ok(),
            std::env::var("MOLLIE_API_KEY").ok(),
            std::env::var("MOLLIE_API_BASE_URL").ok(),
            std::env::var("MOLLIE_PROFILE_ID").ok(),
        );
        std::env::set_var("AUTO_PAY_OPEN_INVOICES", "true");
        std::env::set_var("MOLLIE_API_KEY", "mollie-test-key-fixture");
        std::env::set_var("MOLLIE_API_BASE_URL", format!("{base}/v2"));
        std::env::set_var("MOLLIE_PROFILE_ID", "ApexMailTestECOM");

        let tenant = "mtcov_retry";
        seed_tenant(&env, tenant, "growth", "active").await;
        sqlx::query(
            "INSERT INTO dunning_records (id, tenant_id, status, next_retry_at, failed_payment_count)
             VALUES ('dun_cov_retry', $1, 'warning', NOW() - INTERVAL '1 hour', 1)",
        )
        .bind(tenant)
        .execute(&env.pool)
        .await
        .expect("dunning");
        sqlx::query(
            "INSERT INTO mollie_subscriptions
                 (tenant_id, mollie_subscription_id, plan, status, billing_cycle_start,
                  billing_cycle_end, mollie_customer_id,
                  mollie_mandate_id)
             VALUES ($1, '', 'growth', 'past_due', NOW(),
                     NOW() + INTERVAL '30 days', $1, 'tok_retry')",
        )
        .bind(tenant)
        .execute(&env.pool)
        .await
        .expect("subscription");
        // The open LOCAL invoice the retry must collect (amount derived from
        // its own outstanding remainder, never a provider object).
        let invoice_id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO invoices (id, tenant_id, amount, currency, status, invoice_number,
                                   subtotal, vat_total, total, issued_at, due_at,
                                   period_start, period_end, created_at, updated_at)
             VALUES ($1, $2, 4900, 'EUR', 'pending', $3, 4900, 0, 4900,
                     NOW(), NOW(), NOW(), NOW(), NOW(), NOW())",
        )
        .bind(invoice_id)
        .bind(tenant)
        .bind(format!("MTCOV-{}", invoice_id.simple()))
        .execute(&env.pool)
        .await
        .expect("open invoice");

        let client = Client::new();
        let result = process_scheduled_retries(&env.state, &client)
            .await
            .expect("retries");
        assert_eq!(result.attempted, 1);
        assert_eq!(result.succeeded, 1);
        assert_eq!(
            mock.call_count("/v2/payments"),
            1,
            "the open invoice is paid exactly once"
        );
        let call = mock.last_call("/v2/payments").expect("retry payment call");
        assert_eq!(call.method, "POST");
        assert_eq!(
            call.headers.get("authorization").map(String::as_str),
            Some("Bearer mollie-test-key-fixture")
        );
        assert_eq!(
            call.headers.get("idempotency-key").map(String::as_str),
            Some(format!("autopay_{}", invoice_id.simple()).as_str()),
            "one key per invoice: a lost response replays the same charge"
        );
        let body: serde_json::Value = serde_json::from_str(&call.body).expect("payment body JSON");
        assert_eq!(
            body["amount"],
            serde_json::json!({"currency": "EUR", "value": "49.00"}),
            "the amount is the local invoice's total as a decimal string"
        );
        assert_eq!(body["sequenceType"], serde_json::json!("recurring"));
        assert_eq!(body["customerId"], serde_json::json!(tenant));
        assert_eq!(body["mandateId"], serde_json::json!("tok_retry"));
        assert_eq!(
            body["metadata"]["reference"],
            serde_json::json!(format!("invoice:{invoice_id}"))
        );
        assert_eq!(body["metadata"]["tenant_id"], serde_json::json!(tenant));
        // The charge's payment id is bound to the local invoice for the
        // webhook to settle on `metadata.reference = invoice:{id}`.
        let (status, bound): (String, Option<String>) =
            sqlx::query_as("SELECT status, mollie_payment_id FROM invoices WHERE id = $1")
                .bind(invoice_id)
                .fetch_one(&env.pool)
                .await
                .expect("invoice");
        assert_eq!(status, "pending");
        assert_eq!(bound.as_deref(), Some("tr_retry_pay"));
        let status: String =
            sqlx::query_scalar("SELECT status FROM dunning_records WHERE tenant_id = $1")
                .bind(tenant)
                .fetch_one(&env.pool)
                .await
                .expect("dunning status");
        assert_eq!(status, "healthy", "recovery reset the dunning record");

        match previous {
            (Some(auto), Some(key), Some(url), Some(merchant)) => {
                std::env::set_var("AUTO_PAY_OPEN_INVOICES", auto);
                std::env::set_var("MOLLIE_API_KEY", key);
                std::env::set_var("MOLLIE_API_BASE_URL", url);
                std::env::set_var("MOLLIE_PROFILE_ID", merchant);
            }
            _ => {
                std::env::remove_var("AUTO_PAY_OPEN_INVOICES");
                std::env::remove_var("MOLLIE_API_KEY");
                std::env::remove_var("MOLLIE_API_BASE_URL");
                std::env::remove_var("MOLLIE_PROFILE_ID");
            }
        }
        drop(guard);
        env.finish().await;
    }

    #[tokio::test]
    async fn auto_pay_disabled_is_the_default_and_moves_no_money() {
        let Some(env) = provision("auto_pay_disabled").await else {
            return;
        };
        let guard = ENV_LOCK.lock().await;
        std::env::remove_var("AUTO_PAY_OPEN_INVOICES");
        let tenant = "mtcov_retry_off";
        seed_tenant(&env, tenant, "growth", "active").await;
        sqlx::query(
            "INSERT INTO dunning_records (id, tenant_id, status, next_retry_at, failed_payment_count)
             VALUES ('dun_cov_off', $1, 'warning', NOW() - INTERVAL '1 hour', 1)",
        )
        .bind(tenant)
        .execute(&env.pool)
        .await
        .expect("dunning");
        let client = Client::new();
        let result = process_scheduled_retries(&env.state, &client)
            .await
            .expect("retries");
        assert_eq!(result.attempted, 0, "auto-pay is opt-in");
        assert_eq!(result.succeeded, 0);
        drop(guard);
        env.finish().await;
    }

    // ---------------- pure boundary helpers ----------------

    #[test]
    fn percent_of_cents_half_up_boundaries() {
        assert_eq!(percent_of_cents_half_up(0, 50), 0);
        assert_eq!(percent_of_cents_half_up(-5, 50), 0);
        assert_eq!(percent_of_cents_half_up(100, 0), 0);
        assert_eq!(percent_of_cents_half_up(100, -1), 0);
        // 1 cent × 50% = 0.5 → half-up to 1 (never silently truncate).
        assert_eq!(percent_of_cents_half_up(1, 50), 1);
        assert_eq!(percent_of_cents_half_up(1, 49), 0);
        assert_eq!(percent_of_cents_half_up(1, 40), 0);
        assert_eq!(percent_of_cents_half_up(10_000, 25), 2_500);
        // Saturates instead of overflowing.
        assert_eq!(percent_of_cents_half_up(i64::MAX, 100), i64::MAX);
    }

    #[test]
    fn maintenance_time_boundaries_are_stable() {
        let dec31 = Utc.with_ymd_and_hms(2026, 12, 31, 23, 59, 59).unwrap();
        assert_eq!(
            next_month_start(month_start(dec31)),
            Utc.with_ymd_and_hms(2027, 1, 1, 0, 0, 0).unwrap()
        );
        let jan31 = Utc.with_ymd_and_hms(2027, 1, 31, 12, 0, 0).unwrap();
        assert_eq!(
            next_month_start(month_start(jan31)),
            Utc.with_ymd_and_hms(2027, 2, 1, 0, 0, 0).unwrap()
        );
        // Leap February: 2028-02-29's next month starts in March.
        let leap_day = Utc.with_ymd_and_hms(2028, 2, 29, 8, 0, 0).unwrap();
        assert_eq!(
            next_month_start(month_start(leap_day)),
            Utc.with_ymd_and_hms(2028, 3, 1, 0, 0, 0).unwrap()
        );
        let dst_end = Utc.with_ymd_and_hms(2026, 3, 29, 23, 30, 0).unwrap();
        assert_eq!(
            next_day_start(dst_end),
            Utc.with_ymd_and_hms(2026, 3, 30, 0, 0, 0).unwrap()
        );
        assert_eq!(
            day_start(dst_end),
            Utc.with_ymd_and_hms(2026, 3, 29, 0, 0, 0).unwrap()
        );
    }

    // ---------------- grace-period purges ----------------

    async fn seed_message(env: &Env, tenant: &str, status: &str) -> Uuid {
        sqlx::query_scalar(
            "INSERT INTO messages (tenant_id, from_email, to_emails, status)
             VALUES ($1, 'a@b.c', '[]'::jsonb, $2) RETURNING id",
        )
        .bind(tenant)
        .bind(status)
        .fetch_one(&env.pool)
        .await
        .expect("seed message")
    }

    env_test!(
        grace_period_expirations_purge_only_expired_hard_suspensions,
        |env| {
            let expired = "mtcov_grace_expired";
            let future = "mtcov_grace_future";
            let no_grace = "mtcov_grace_none";
            let soft = "mtcov_grace_soft";
            for tenant in [expired, future, no_grace, soft] {
                seed_tenant(env, tenant, "free", "suspended").await;
            }
            let now = Utc::now();
            sqlx::query(
                "INSERT INTO dunning_records
                     (id, tenant_id, status, grace_period_ends_at, failed_payment_count)
                 VALUES ('dun_grace_exp', $1, 'hard_suspended', $2, 3),
                        ('dun_grace_fut', $3, 'hard_suspended', $4, 3),
                        ('dun_grace_non', $5, 'hard_suspended', NULL, 3),
                        ('dun_grace_soft', $6, 'soft_suspended', $2, 3)",
            )
            .bind(expired)
            .bind(now - chrono::Duration::hours(1))
            .bind(future)
            .bind(now + chrono::Duration::hours(1))
            .bind(no_grace)
            .bind(soft)
            .execute(&env.pool)
            .await
            .expect("dunning records");

            // Only `dunning_queued` mail of the EXPIRED tenant may be purged.
            let purge_a = seed_message(env, expired, "dunning_queued").await;
            let purge_b = seed_message(env, expired, "dunning_queued").await;
            let keep_queued = seed_message(env, expired, "queued").await;
            let keep_sent = seed_message(env, expired, "sent").await;
            let future_msg = seed_message(env, future, "dunning_queued").await;
            let no_grace_msg = seed_message(env, no_grace, "dunning_queued").await;
            let soft_msg = seed_message(env, soft, "dunning_queued").await;

            let result = process_grace_period_expirations(&env.state, 100)
                .await
                .expect("grace sweep");
            assert_eq!(result.processed_count, 1, "only the expired tenant acts");
            assert_eq!(result.purged_messages_count, 2, "only dunning_queued mail");

            let surviving: Vec<Uuid> = sqlx::query_scalar("SELECT id FROM messages ORDER BY id")
                .fetch_all(&env.pool)
                .await
                .expect("surviving messages");
            for kept in [keep_queued, keep_sent, future_msg, no_grace_msg, soft_msg] {
                assert!(surviving.contains(&kept), "{kept} must not be purged");
            }
            assert!(!surviving.contains(&purge_a) && !surviving.contains(&purge_b));

            // The expired tenant's grace window is closed exactly once.
            let grace: Option<DateTime<Utc>> = sqlx::query_scalar(
                "SELECT grace_period_ends_at FROM dunning_records WHERE tenant_id = $1",
            )
            .bind(expired)
            .fetch_one(&env.pool)
            .await
            .expect("grace state");
            assert!(grace.is_none());
            for tenant in [future, no_grace] {
                let other: Option<DateTime<Utc>> = sqlx::query_scalar(
                    "SELECT grace_period_ends_at FROM dunning_records WHERE tenant_id = $1",
                )
                .bind(tenant)
                .fetch_one(&env.pool)
                .await
                .expect("other grace state");
                if tenant == no_grace {
                    assert!(other.is_none());
                } else {
                    assert!(other.is_some(), "future grace window untouched");
                }
            }

            let (notification_count, purged_count): (i64, i64) = sqlx::query_as(
                "SELECT COUNT(*)::bigint, COALESCE(MAX((payload->>'purgedCount')::bigint), 0)
                 FROM notification_queue WHERE tenant_id = $1 AND type = 'messages_purged'",
            )
            .bind(expired)
            .fetch_one(&env.pool)
            .await
            .expect("notification");
            assert_eq!((notification_count, purged_count), (1, 2));

            // Replay: the grace window is already closed, so nothing repeats.
            let replay = process_grace_period_expirations(&env.state, 100)
                .await
                .expect("grace replay");
            assert_eq!(replay.processed_count, 0);
            assert_eq!(replay.purged_messages_count, 0);
            let notifications_after: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM notification_queue WHERE tenant_id = $1 AND type = 'messages_purged'",
            )
            .bind(expired)
            .fetch_one(&env.pool)
            .await
            .expect("notification replay");
            assert_eq!(notifications_after, 1, "no duplicate notification");
        }
    );

    env_test!(
        grace_period_expirations_page_through_every_expired_tenant,
        |env| {
            let now = Utc::now();
            let mut tenants = Vec::new();
            for index in 0..3 {
                let tenant = format!("mtcov_grace_page_{index}");
                seed_tenant(env, &tenant, "free", "suspended").await;
                sqlx::query(
                    "INSERT INTO dunning_records
                         (id, tenant_id, status, grace_period_ends_at, failed_payment_count)
                     VALUES ($1, $2, 'hard_suspended', $3, 1)",
                )
                .bind(format!("dun_grace_page_{index}"))
                .bind(&tenant)
                .bind(now - chrono::Duration::minutes(10 + index))
                .execute(&env.pool)
                .await
                .expect("dunning row");
                seed_message(env, &tenant, "dunning_queued").await;
                tenants.push(tenant);
            }

            // batch_size = 1 forces the keyset loop to page one tenant at a
            // time; every expired tenant must still be processed.
            let sweep = process_grace_period_expirations(&env.state, 1)
                .await
                .expect("paged grace sweep");
            assert_eq!(sweep.processed_count, 3);
            assert_eq!(sweep.purged_messages_count, 3);
            for tenant in &tenants {
                let grace: Option<DateTime<Utc>> = sqlx::query_scalar(
                    "SELECT grace_period_ends_at FROM dunning_records WHERE tenant_id = $1",
                )
                .bind(tenant)
                .fetch_one(&env.pool)
                .await
                .expect("grace state");
                assert!(grace.is_none(), "{tenant} was processed");
            }
        }
    );

    // ---------------- metering drain idempotency ----------------

    env_test!(metering_drain_replay_never_double_counts, |env| {
        let _drain_guard = METER_DRAIN_LOCK.lock().await;
        let _metering_guard = metering_keys_guard(&env.admin_url).await;
        crate::test_support::clear_pending_metering_keys(&env.redis).await;
        let tenant = "mtcov_drain_replay";
        seed_tenant(env, tenant, "free", "active").await;
        let raw_id = "mtcov-replay-raw-1";
        let payload = format!(
            r#"{{"id":"{raw_id}","tenantId":"{tenant}","eventType":"api_calls","quantity":5,"timestamp":"{}"}}"#,
            Utc::now().to_rfc3339()
        );
        let pending_key = format!("meter:pending:{raw_id}");
        let guard_key = format!("meter:guard:{}", normalize_metering_event_id(raw_id));
        let counter_key = crate::usage::enforced_counter_key_for_event_type(
            &env.pool,
            tenant,
            "api_calls",
            Utc::now(),
        )
        .await;
        redis_del(env, &pending_key).await;
        redis_del(env, &guard_key).await;
        redis_del(env, &counter_key).await;

        let mut conn = env.redis.get().await.expect("redis");
        let _: () = redis::cmd("SET")
            .arg(&pending_key)
            .arg(&payload)
            .query_async(&mut conn)
            .await
            .expect("set pending");
        drop(conn);

        let first = drain_pending_metering_events(&env.state, 100)
            .await
            .expect("drain");
        // The drain scans the WHOLE Redis keyspace for pending metering
        // events, so its global `processed_count` also moves for a sibling
        // test's event when the suite runs in parallel, asserting on it made
        // this test order-dependent. Assert on THIS event: it left the pending
        // set, it was persisted once, and the enforced counter moved by it.
        assert!(first.processed_count >= 1, "{first:?}");
        assert!(!redis_exists(env, &pending_key).await);
        assert_eq!(redis_i64(env, &counter_key).await, 5);
        let first_rows: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM metering_events WHERE tenant_id = $1")
                .bind(tenant)
                .fetch_one(&env.pool)
                .await
                .expect("rows");
        assert_eq!(first_rows, 1, "the first pass persists the event once");

        // The same raw event is redelivered (crash before the client could
        // observe the ack): the DB row and the enforced counter must both
        // stay exactly once.
        let mut conn = env.redis.get().await.expect("redis");
        let _: () = redis::cmd("SET")
            .arg(&pending_key)
            .arg(&payload)
            .query_async(&mut conn)
            .await
            .expect("re-set pending");
        drop(conn);

        drain_pending_metering_events(&env.state, 100)
            .await
            .expect("drain replay");
        // The replay must not move THIS tenant's counter or add a row, a
        // global `processed_count == 0` would only hold if no sibling test
        // had a pending event.
        assert_eq!(
            redis_i64(env, &counter_key).await,
            5,
            "never double-counted"
        );
        let rows: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM metering_events WHERE tenant_id = $1")
                .bind(tenant)
                .fetch_one(&env.pool)
                .await
                .expect("rows");
        assert_eq!(rows, 1, "exactly-once accounting");
        assert!(!redis_exists(env, &pending_key).await);
    });

    // P2 metering recovery drain, the pre-fix loop issued ONE
    // `enforced_counter_key_for_event_type` SELECT per event and ONE Redis
    // EVAL round trip per event. The fix memoizes the key per
    // (tenant, event_type, event month) and loads every tenant's cycle
    // anchors in ONE batched SELECT, so 100 events cost one lookup no matter
    // how many distinct tenants they span.
    //
    // Fail-before: 100 events -> `drain.db.counter_keys` == 100,
    // `drain.redis.pipeline` == 0.
    env_test!(
        metering_drain_counter_key_lookup_is_constant_in_distinct_tenants,
        |env| {
            use crate::test_support::query_count;

            let _drain_guard = METER_DRAIN_LOCK.lock().await;
            let _metering_guard = metering_keys_guard(&env.admin_url).await;
            crate::test_support::clear_pending_metering_keys(&env.redis).await;

            let now = Utc::now();
            let events: Vec<(String, &'static str, String, i64)> = (0..100)
                .map(|index| {
                    // 100 DISTINCT tenants, two event types, varying quantities.
                    let tenant = format!("w6drainq{index:03}");
                    let event_type = if index % 2 == 0 {
                        "api_calls"
                    } else {
                        "emails_sent"
                    };
                    let raw_id = format!("w6drainq-raw-{index}");
                    let quantity = i64::from((index % 5) + 1);
                    (tenant, event_type, raw_id, quantity)
                })
                .collect();

            let mut conn = env.redis.get().await.expect("redis");
            let mut expected: Vec<(String, i64)> = Vec::with_capacity(events.len());
            for (tenant, event_type, raw_id, quantity) in &events {
                let guard_key = format!("meter:guard:{}", normalize_metering_event_id(raw_id));
                let counter_key = crate::usage::enforced_counter_key_for_event_type(
                    &env.pool, tenant, event_type, now,
                )
                .await;
                let pending_key = format!("meter:pending:{raw_id}");
                // Deterministic prior state: clear the 40-day guard/counter
                // keys so a re-run of this test drains and increments again.
                let _: () = redis::cmd("DEL")
                    .arg(&guard_key)
                    .arg(&counter_key)
                    .arg(&pending_key)
                    .query_async(&mut conn)
                    .await
                    .expect("clear prior keys");
                let payload = serde_json::json!({
                    "id": raw_id,
                    "tenantId": tenant,
                    "eventType": event_type,
                    "quantity": quantity,
                    "timestamp": now.to_rfc3339(),
                    "metadata": {},
                });
                let _: () = redis::cmd("SET")
                    .arg(&pending_key)
                    .arg(payload.to_string())
                    .query_async(&mut conn)
                    .await
                    .expect("seed pending");
                expected.push((counter_key, *quantity));
            }
            drop(conn);

            query_count::reset();
            let result = drain_pending_metering_events(&env.state, 100)
                .await
                .expect("batched drain");
            assert!(result.processed_count >= 100, "{result:?}");
            assert_eq!(
                query_count::count("drain.db.counter_keys"),
                1,
                "ONE counter-key lookup for the whole drain, not one per event/tenant"
            );
            assert_eq!(
                query_count::count("drain.redis.eval"),
                0,
                "no serial EVAL round trips (the EVALs are pipelined)"
            );
            assert_eq!(
                query_count::count("drain.redis.pipeline"),
                1,
                "100 pipelined EVALs fit one chunk"
            );

            for (counter_key, quantity) in expected {
                assert_eq!(
                    redis_i64(env, &counter_key).await,
                    quantity,
                    "counter {counter_key} moved by exactly its event quantity"
                );
            }
        }
    );

    // P2 metering recovery drain, pipelined EVALs must produce exactly the
    // counter values the serial path produced, including for a
    // billing-cycle-anchored tenant (whose key is `c`-prefixed and differs
    // from the UTC calendar-month key).
    env_test!(
        metering_drain_pipelined_counters_match_serial_expected_values,
        |env| {
            use crate::test_support::query_count;

            let _drain_guard = METER_DRAIN_LOCK.lock().await;
            let _metering_guard = metering_keys_guard(&env.admin_url).await;
            crate::test_support::clear_pending_metering_keys(&env.redis).await;

            let now = Utc::now();
            let mut events: Vec<(String, &'static str, String, i64)> = Vec::new();
            for tenant_index in 0..10 {
                let tenant = format!("w6drainp{tenant_index:02}");
                if tenant_index == 0 {
                    // Cycle-anchored tenant: the counter key is
                    // `...:c<year>-<month>` (cycle start), not the calendar
                    // month key a tenant without a subscription uses.
                    sqlx::query(
                        "INSERT INTO mollie_subscriptions
                         (tenant_id, mollie_subscription_id, plan, status,
                          billing_cycle_start, billing_cycle_end)
                         VALUES ($1, $2, 'growth', 'active', $3, $4)",
                    )
                    .bind(&tenant)
                    .bind("w6drainp-sub-0")
                    .bind(now - chrono::Duration::days(20))
                    .bind(now + chrono::Duration::days(20))
                    .execute(&env.pool)
                    .await
                    .expect("seed cycle-anchored subscription");
                }
                for event_index in 0..10 {
                    let event_type = if event_index % 2 == 0 {
                        "api_calls"
                    } else {
                        "emails_sent"
                    };
                    let raw_id = format!("w6drainp-{tenant_index}-{event_index}");
                    let quantity = i64::from(((tenant_index + event_index) % 4) + 1);
                    events.push((tenant.clone(), event_type, raw_id, quantity));
                }
            }

            let mut conn = env.redis.get().await.expect("redis");
            let mut expected: HashMap<String, i64> = HashMap::new();
            for (tenant, event_type, raw_id, quantity) in &events {
                let guard_key = format!("meter:guard:{}", normalize_metering_event_id(raw_id));
                let counter_key = crate::usage::enforced_counter_key_for_event_type(
                    &env.pool, tenant, event_type, now,
                )
                .await;
                let pending_key = format!("meter:pending:{raw_id}");
                let _: () = redis::cmd("DEL")
                    .arg(&guard_key)
                    .arg(&counter_key)
                    .arg(&pending_key)
                    .query_async(&mut conn)
                    .await
                    .expect("clear prior keys");
                let payload = serde_json::json!({
                    "id": raw_id,
                    "tenantId": tenant,
                    "eventType": event_type,
                    "quantity": quantity,
                    "timestamp": now.to_rfc3339(),
                    "metadata": {},
                });
                let _: () = redis::cmd("SET")
                    .arg(&pending_key)
                    .arg(payload.to_string())
                    .query_async(&mut conn)
                    .await
                    .expect("seed pending");
                *expected.entry(counter_key).or_default() += quantity;
            }
            drop(conn);

            query_count::reset();
            let result = drain_pending_metering_events(&env.state, 100)
                .await
                .expect("pipelined drain");
            assert!(result.processed_count >= 100, "{result:?}");
            assert_eq!(query_count::count("drain.redis.eval"), 0);
            assert_eq!(
                query_count::count("drain.redis.pipeline"),
                1,
                "100 EVALs are one pipeline round trip"
            );

            for (counter_key, quantity) in expected {
                assert_eq!(
                    redis_i64(env, &counter_key).await,
                    quantity,
                    "pipelined counter {counter_key} matches the serial sum"
                );
            }
        }
    );

    async fn redis_i64(env: &Env, key: &str) -> i64 {
        let mut conn = env.redis.get().await.expect("redis");
        redis::cmd("GET")
            .arg(key)
            .query_async::<Option<i64>>(&mut conn)
            .await
            .expect("redis get")
            .unwrap_or(0)
    }

    #[test]
    fn normalize_metering_event_id_is_stable_and_uuid_aware() {
        let uuid = Uuid::new_v4();
        assert_eq!(normalize_metering_event_id(&uuid.to_string()), uuid);
        assert_eq!(
            normalize_metering_event_id(&format!("evt_{uuid}")),
            uuid,
            "a trailing UUID suffix is authoritative"
        );
        let hashed = normalize_metering_event_id("not-a-uuid");
        assert_eq!(
            hashed,
            normalize_metering_event_id("not-a-uuid"),
            "hash fallback is deterministic"
        );
        assert_ne!(hashed, normalize_metering_event_id("not-a-uuid-2"));
        // Shaped as a v5-style UUID (version nibble + variant bits).
        assert_eq!(hashed.get_version_num(), 5);
        assert_eq!(hashed.as_bytes()[8] & 0xc0, 0x80);
    }

    // ---------------- EMTA filing ----------------

    fn emta_test_client(base: &str) -> EmtaClient {
        EmtaClient::new(
            EmtaConfig {
                api_base_url: base.to_string(),
                client_cert_path: "unused-cert.pem".to_string(),
                client_key_path: "unused-key.pem".to_string(),
                company_registry_code: "12345678".to_string(),
                enabled: true,
            },
            Client::new(),
        )
    }

    env_test!(emta_filing_is_idempotent_and_records_acceptance, |env| {
        let mock = Mock::default();
        mock.route(
            "/api/v1/kmd/submit",
            200,
            "<xrd:accepted>true</xrd:accepted><xrd:filingReference>REF-COV-1</xrd:filingReference>",
        );
        let base = spawn_mock(mock.clone()).await;
        let client = emta_test_client(&base);

        let kmd = crate::vat_kmd::generate_kmd_return(&env.pool, 2026, 1)
            .await
            .expect("generate kmd");
        let filing = attempt_emta_filing(&env.pool, &client, &kmd)
            .await
            .expect("filing")
            .expect("first attempt submits");
        assert!(filing.accepted);
        assert_eq!(filing.filing_reference.as_deref(), Some("REF-COV-1"));
        assert_eq!(mock.call_count("/api/v1/kmd/submit"), 1);

        let (status, reference, error): (String, Option<String>, Option<String>) = sqlx::query_as(
            "SELECT status, filing_reference, filing_error FROM vat_kmd_returns WHERE id = $1",
        )
        .bind(kmd.kmd_id)
        .fetch_one(&env.pool)
        .await
        .expect("kmd row");
        assert_eq!(status, "filed");
        assert_eq!(reference.as_deref(), Some("REF-COV-1"));
        assert!(error.is_none());

        // Replay: an already-filed return is never re-submitted.
        let replay = attempt_emta_filing(&env.pool, &client, &kmd)
            .await
            .expect("replay");
        assert!(replay.is_none());
        assert_eq!(
            mock.call_count("/api/v1/kmd/submit"),
            1,
            "no duplicate submission"
        );

        // A rejected acknowledgment is recorded as `failed` with the reason.
        mock.route(
            "/api/v1/kmd/submit",
            200,
            "<accepted>false</accepted><statusMessage>Period rejected</statusMessage>",
        );
        let rejected = crate::vat_kmd::generate_kmd_return(&env.pool, 2026, 2)
            .await
            .expect("generate rejected kmd");
        let rejected_result = attempt_emta_filing(&env.pool, &client, &rejected)
            .await
            .expect("rejected filing")
            .expect("attempted");
        assert!(!rejected_result.accepted);
        let (status, error): (String, Option<String>) =
            sqlx::query_as("SELECT status, filing_error FROM vat_kmd_returns WHERE id = $1")
                .bind(rejected.kmd_id)
                .fetch_one(&env.pool)
                .await
                .expect("rejected row");
        assert_eq!(status, "failed");
        assert_eq!(error.as_deref(), Some("Period rejected"));
    });

    env_test!(emta_filing_http_failure_leaves_the_return_draft, |env| {
        let mock = Mock::default();
        mock.route("/api/v1/kmd/submit", 500, "upstream exploded");
        let base = spawn_mock(mock.clone()).await;
        let client = emta_test_client(&base);

        let kmd = crate::vat_kmd::generate_kmd_return(&env.pool, 2026, 3)
            .await
            .expect("generate kmd");
        let error = attempt_emta_filing(&env.pool, &client, &kmd)
            .await
            .expect_err("5xx must surface as an error");
        assert!(error.contains("EMTA"), "{error}");
        let (status, filed_at): (String, Option<DateTime<Utc>>) =
            sqlx::query_as("SELECT status, filed_at FROM vat_kmd_returns WHERE id = $1")
                .bind(kmd.kmd_id)
                .fetch_one(&env.pool)
                .await
                .expect("kmd row");
        assert_eq!(status, "draft", "a failed filing is never marked filed");
        assert!(filed_at.is_none());

        // An unknown KMD id is refused before any HTTP call.
        let ghost = crate::vat_kmd::VatKmdResult {
            tax_year: 2026,
            tax_month: 4,
            invoice_count: 0,
            tenant_count: 0,
            total_taxable_cents: 0,
            total_vat_cents: 0,
            rates: Vec::new(),
            excluded_other_currency: Vec::new(),
            kmd_id: Uuid::new_v4(),
        };
        let missing = attempt_emta_filing(&env.pool, &client, &ghost)
            .await
            .expect_err("unknown KMD id");
        assert!(missing.contains("not found"), "{missing}");
    });

    // ---------------- usage alert channels ----------------

    env_test!(
        usage_alert_email_channel_enqueues_once_per_cooldown,
        |env| {
            let tenant = "mtcov_alert_mail";
            seed_tenant(env, tenant, "alertmail", "active").await;
            seed_plan(env, "alertmail", 1_000, json!({})).await;
            sqlx::query(
            "INSERT INTO usage_alert_configs (tenant_id, metric_type, threshold_percent, notification_channel)
             VALUES ($1, 'emails', 50, 'email')",
        )
        .bind(tenant)
        .execute(&env.pool)
        .await
        .expect("alert config");
            sqlx::query(
                "INSERT INTO metering_events (id, tenant_id, event_type, quantity, timestamp)
             VALUES (gen_random_uuid(), $1, 'emails_sent', 600, NOW())",
            )
            .bind(tenant)
            .execute(&env.pool)
            .await
            .expect("usage");
            redis_del(env, &format!("alert:cooldown:{tenant}:emails:50")).await;

            let client = Client::new();
            let first = process_usage_alerts(&env.state, &client)
                .await
                .expect("alerts");
            assert_eq!(first.alerts_triggered, 1, "{first:?}");
            let (queued, percent): (i64, i64) = sqlx::query_as(
                "SELECT COUNT(*)::bigint, COALESCE(MAX((payload->>'currentPercent')::bigint), -1)
             FROM notification_queue WHERE tenant_id = $1 AND type = 'usage_alert'",
            )
            .bind(tenant)
            .fetch_one(&env.pool)
            .await
            .expect("notification");
            assert_eq!((queued, percent), (1, 60));

            let replay = process_usage_alerts(&env.state, &client)
                .await
                .expect("replay");
            assert_eq!(replay.alerts_triggered, 0, "cooldown holds for an hour");
            let queued_after: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM notification_queue WHERE tenant_id = $1 AND type = 'usage_alert'",
        )
        .bind(tenant)
        .fetch_one(&env.pool)
        .await
        .expect("notification replay");
            assert_eq!(queued_after, 1);
        }
    );

    // ---------------- scheduled Mollie retries ----------------

    async fn seed_retry_candidate(env: &Env, tenant: &str, dunning_status: &str, sub_status: &str) {
        seed_tenant(env, tenant, "growth", "active").await;
        sqlx::query(
            "INSERT INTO dunning_records (id, tenant_id, status, next_retry_at, failed_payment_count)
             VALUES ($1, $2, $3, NOW() - INTERVAL '1 hour', 1)",
        )
        .bind(format!("dun_{}", &tenant[..tenant.len().min(20)]))
        .bind(tenant)
        .bind(dunning_status)
        .execute(&env.pool)
        .await
        .expect("dunning");
        sqlx::query(
            "INSERT INTO mollie_subscriptions
                 (tenant_id, mollie_subscription_id, plan, status, billing_cycle_start,
                  billing_cycle_end, mollie_customer_id)
             -- local_<tenant> = a LOCAL-only subscription row (no Mollie
             -- subscription): the legacy/operator shape the mandate retry
             -- charges. Provider rows always carry a `sub_...` id.
             VALUES ($1, $2, 'growth', $3, NOW(), NOW() + INTERVAL '30 days', $1)",
        )
        .bind(tenant)
        .bind(format!("local_{}", &tenant[..tenant.len().min(20)]))
        .bind(sub_status)
        .execute(&env.pool)
        .await
        .expect("subscription");
    }

    // External audit 15 Oct, H1: a subscription canceled for period end must
    // never be charged by the dunning/auto-pay sweep, even when a retry is
    // queued and an invoice is open.
    env_test!(scheduled_retries_skip_canceled_at_period_end, |env| {
        let mock = Mock::default();
        mock.route(
            "/v2/payments",
            200,
            r#"{"id":"tr_should_not_happen","status":"paid"}"#,
        );
        let base = spawn_mock(mock.clone()).await;
        let guard = ENV_LOCK.lock().await;
        let previous = (
            std::env::var("AUTO_PAY_OPEN_INVOICES").ok(),
            std::env::var("MOLLIE_API_KEY").ok(),
            std::env::var("MOLLIE_API_BASE_URL").ok(),
            std::env::var("MOLLIE_PROFILE_ID").ok(),
        );
        std::env::set_var("AUTO_PAY_OPEN_INVOICES", "true");
        std::env::set_var("MOLLIE_API_KEY", "mollie-test-key-fixture");
        std::env::set_var("MOLLIE_API_BASE_URL", format!("{base}/v2"));
        std::env::set_var("MOLLIE_PROFILE_ID", "ApexMailTestECOM");

        let tenant = "mtcov_retry_canceled";
        seed_retry_candidate(env, tenant, "warning", "past_due").await;
        sqlx::query(
            "UPDATE mollie_subscriptions
                SET cancel_at_period_end = true,
                    canceled_at = NOW(),
                    mollie_mandate_id = 'tok_retry_canceled'
              WHERE tenant_id = $1",
        )
        .bind(tenant)
        .execute(&env.pool)
        .await
        .expect("canceled subscription");
        let invoice_id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO invoices (id, tenant_id, amount, currency, status, invoice_number,
                                   subtotal, vat_total, total, issued_at, due_at,
                                   period_start, period_end, created_at, updated_at)
             VALUES ($1, $2, 2500, 'EUR', 'pending', $3, 2500, 0, 2500,
                     NOW(), NOW(), NOW(), NOW(), NOW(), NOW())",
        )
        .bind(invoice_id)
        .bind(tenant)
        .bind(format!("MTCOV-{}", invoice_id.simple()))
        .execute(&env.pool)
        .await
        .expect("open invoice");

        let result = process_scheduled_retries(&env.state, &Client::new())
            .await
            .expect("retries");
        assert_eq!(
            result.attempted, 0,
            "a canceled subscription is never retried"
        );
        assert_eq!(
            mock.call_count("/v2/payments"),
            0,
            "no provider charge may be attempted after cancellation"
        );

        match previous {
            (Some(v), _, _, _) => std::env::set_var("AUTO_PAY_OPEN_INVOICES", v),
            _ => std::env::remove_var("AUTO_PAY_OPEN_INVOICES"),
        }
        drop(guard);
    });

    // External audit 15 Oct, H1: the period-end reconciler ends a canceled
    // subscription once its cycle has actually ended and downgrades the
    // tenant; a future period end is untouched and a replay is a no-op.
    env_test!(
        canceled_at_period_end_sweep_ends_due_and_is_idempotent,
        |env| {
            let now_tenant = "mtcov_cancel_now";
            let future_tenant = "mtcov_cancel_future";
            seed_tenant(env, now_tenant, "growth", "active").await;
            seed_tenant(env, future_tenant, "growth", "active").await;
            for (tenant, due) in [(now_tenant, true), (future_tenant, false)] {
                sqlx::query(
                    "INSERT INTO mollie_subscriptions
                     (tenant_id, mollie_subscription_id, plan, status,
                      billing_cycle_start, billing_cycle_end,
                      cancel_at_period_end, canceled_at, mollie_customer_id)
                 VALUES ($1, $2, 'growth', 'active',
                         NOW() - INTERVAL '30 days',
                         CASE WHEN $3 THEN NOW() - INTERVAL '1 hour'
                              ELSE NOW() + INTERVAL '10 days' END,
                         true, NOW(), $1)",
                )
                .bind(tenant)
                .bind(format!("psp_{tenant}"))
                .bind(due)
                .execute(&env.pool)
                .await
                .expect("canceled subscription");
            }

            let ended = sweep_canceled_at_period_end(&env.state)
                .await
                .expect("sweep");
            assert_eq!(ended, 1, "only the ended cycle is reconciled");
            let (status, cancel_at_period_end): (String, bool) = sqlx::query_as(
                "SELECT status, cancel_at_period_end FROM mollie_subscriptions WHERE tenant_id = $1",
            )
            .bind(now_tenant)
            .fetch_one(&env.pool)
            .await
            .unwrap();
            assert_eq!(status, "canceled");
            assert!(!cancel_at_period_end);
            let (plan,): (String,) = sqlx::query_as("SELECT plan FROM tenants WHERE id = $1")
                .bind(now_tenant)
                .fetch_one(&env.pool)
                .await
                .unwrap();
            assert_eq!(plan, "free");
            let audits: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM audit_logs
              WHERE tenant_id = $1 AND action = 'billing.subscription_ended_at_period_end'",
            )
            .bind(now_tenant)
            .fetch_one(&env.pool)
            .await
            .unwrap();
            assert_eq!(audits, 1, "the ending is audit-chained");

            let future_status: String =
                sqlx::query_scalar("SELECT status FROM mollie_subscriptions WHERE tenant_id = $1")
                    .bind(future_tenant)
                    .fetch_one(&env.pool)
                    .await
                    .unwrap();
            assert_eq!(future_status, "active", "a future period end is untouched");
            assert_eq!(
                sweep_canceled_at_period_end(&env.state)
                    .await
                    .expect("replay"),
                0,
                "replay is a no-op"
            );
        }
    );

    env_test!(scheduled_retries_reschedule_after_mollie_failure, |env| {
        let mock = Mock::default();
        mock.route("/v2/payments", 500, "mollie down");
        let base = spawn_mock(mock.clone()).await;
        let guard = ENV_LOCK.lock().await;
        let previous = (
            std::env::var("AUTO_PAY_OPEN_INVOICES").ok(),
            std::env::var("MOLLIE_API_KEY").ok(),
            std::env::var("MOLLIE_API_BASE_URL").ok(),
            std::env::var("MOLLIE_PROFILE_ID").ok(),
        );
        std::env::set_var("AUTO_PAY_OPEN_INVOICES", "true");
        std::env::set_var("MOLLIE_API_KEY", "mollie-test-key-fixture");
        std::env::set_var("MOLLIE_API_BASE_URL", format!("{base}/v2"));
        std::env::set_var("MOLLIE_PROFILE_ID", "ApexMailTestECOM");

        let tenant = "mtcov_retry_fail";
        seed_retry_candidate(env, tenant, "warning", "past_due").await;
        // The retry only reaches Mollie when the tenant HAS an open local
        // invoice to collect; seed one so the provider failure is the thing
        // under test (not the nothing-to-collect early exit).
        sqlx::query(
            "UPDATE mollie_subscriptions SET mollie_mandate_id = 'tok_retry_fail'
             WHERE tenant_id = $1",
        )
        .bind(tenant)
        .execute(&env.pool)
        .await
        .expect("stored token");
        let invoice_id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO invoices (id, tenant_id, amount, currency, status, invoice_number,
                                   subtotal, vat_total, total, issued_at, due_at,
                                   period_start, period_end, created_at, updated_at)
             VALUES ($1, $2, 2500, 'EUR', 'pending', $3, 2500, 0, 2500,
                     NOW(), NOW(), NOW(), NOW(), NOW(), NOW())",
        )
        .bind(invoice_id)
        .bind(tenant)
        .bind(format!("MTCOV-{}", invoice_id.simple()))
        .execute(&env.pool)
        .await
        .expect("open invoice");
        let client = Client::new();
        let result = process_scheduled_retries(&env.state, &client)
            .await
            .expect("retries");
        assert_eq!(result.attempted, 1);
        assert_eq!(result.succeeded, 0, "a 5xx never counts as paid");
        let (status, retry): (String, Option<DateTime<Utc>>) = sqlx::query_as(
            "SELECT status, next_retry_at FROM dunning_records WHERE tenant_id = $1",
        )
        .bind(tenant)
        .fetch_one(&env.pool)
        .await
        .expect("dunning");
        assert_eq!(status, "warning", "dunning is not reset on failure");
        let retry = retry.expect("retry rescheduled");
        assert!(
            retry > Utc::now() + chrono::Duration::hours(23),
            "failure backs off a full day"
        );
        assert_eq!(
            mock.call_count("/v2/payments"),
            1,
            "the failed charge is attempted exactly once and never replayed blindly"
        );
        let (invoice_status, bound): (String, Option<String>) =
            sqlx::query_as("SELECT status, mollie_payment_id FROM invoices WHERE id = $1")
                .bind(invoice_id)
                .fetch_one(&env.pool)
                .await
                .expect("invoice");
        assert_eq!(invoice_status, "pending");
        assert!(
            bound.is_none(),
            "a failed charge binds no Mollie payment id to the invoice"
        );

        match previous {
            (Some(auto), Some(key), Some(url), Some(merchant)) => {
                std::env::set_var("AUTO_PAY_OPEN_INVOICES", auto);
                std::env::set_var("MOLLIE_API_KEY", key);
                std::env::set_var("MOLLIE_API_BASE_URL", url);
                std::env::set_var("MOLLIE_PROFILE_ID", merchant);
            }
            _ => {
                std::env::remove_var("AUTO_PAY_OPEN_INVOICES");
                std::env::remove_var("MOLLIE_API_KEY");
                std::env::remove_var("MOLLIE_API_BASE_URL");
                std::env::remove_var("MOLLIE_PROFILE_ID");
            }
        }
        drop(guard);
    });

    env_test!(
        scheduled_retries_clear_retry_when_no_open_invoice_exists,
        |env| {
            let mock = Mock::default();
            let base = spawn_mock(mock.clone()).await;
            let guard = ENV_LOCK.lock().await;
            let previous = (
                std::env::var("AUTO_PAY_OPEN_INVOICES").ok(),
                std::env::var("MOLLIE_API_KEY").ok(),
                std::env::var("MOLLIE_API_BASE_URL").ok(),
                std::env::var("MOLLIE_PROFILE_ID").ok(),
            );
            std::env::set_var("AUTO_PAY_OPEN_INVOICES", "1");
            std::env::set_var("MOLLIE_API_KEY", "mollie-test-key-fixture");
            std::env::set_var("MOLLIE_API_BASE_URL", format!("{base}/v2"));
            std::env::set_var("MOLLIE_PROFILE_ID", "ApexMailTestECOM");

            let tenant = "mtcov_retry_empty";
            seed_retry_candidate(env, tenant, "soft_suspended", "unpaid").await;
            // Not a candidate: healthy dunning and an ineligible subscription.
            let other = "mtcov_retry_notcand";
            seed_retry_candidate(env, other, "healthy", "past_due").await;
            sqlx::query("UPDATE dunning_records SET next_retry_at = NULL WHERE tenant_id = $1")
                .bind(other)
                .execute(&env.pool)
                .await
                .expect("clear retry");

            let client = Client::new();
            let result = process_scheduled_retries(&env.state, &client)
                .await
                .expect("retries");
            assert_eq!(result.attempted, 1, "only the due candidate is attempted");
            assert_eq!(result.succeeded, 1);
            let retry: Option<DateTime<Utc>> = sqlx::query_scalar(
                "SELECT next_retry_at FROM dunning_records WHERE tenant_id = $1",
            )
            .bind(tenant)
            .fetch_one(&env.pool)
            .await
            .expect("dunning");
            assert!(retry.is_none(), "nothing to collect: retry cleared");
            assert_eq!(
                mock.call_count("/v2/payments"),
                0,
                "no open LOCAL invoice exists, so the provider is never called"
            );

            match previous {
                (Some(auto), Some(key), Some(url), Some(merchant)) => {
                    std::env::set_var("AUTO_PAY_OPEN_INVOICES", auto);
                    std::env::set_var("MOLLIE_API_KEY", key);
                    std::env::set_var("MOLLIE_API_BASE_URL", url);
                    std::env::set_var("MOLLIE_PROFILE_ID", merchant);
                }
                _ => {
                    std::env::remove_var("AUTO_PAY_OPEN_INVOICES");
                    std::env::remove_var("MOLLIE_API_KEY");
                    std::env::remove_var("MOLLIE_API_BASE_URL");
                    std::env::remove_var("MOLLIE_PROFILE_ID");
                }
            }
            drop(guard);
        }
    );

    // P3 fix 5, one batched open-invoice lookup for the whole dunning
    // batch, not one SELECT per due dunning row. Three candidates with no
    // open invoice must cost exactly ONE lookup query (the pre-fix loop
    // issued three) and must still clear every retry.
    env_test!(
        scheduled_retries_lookup_open_invoices_once_per_batch,
        |env| {
            use crate::test_support::query_count;

            let guard = ENV_LOCK.lock().await;
            let previous = std::env::var("AUTO_PAY_OPEN_INVOICES").ok();
            std::env::set_var("AUTO_PAY_OPEN_INVOICES", "1");

            let tenants = [
                "mtcov_retry_batch_a",
                "mtcov_retry_batch_b",
                "mtcov_retry_batch_c",
            ];
            for tenant in tenants {
                seed_retry_candidate(env, tenant, "warning", "past_due").await;
            }

            query_count::reset();
            let result = process_scheduled_retries(&env.state, &Client::new())
                .await
                .expect("retry batch");
            assert_eq!(result.attempted, 3);
            assert_eq!(result.succeeded, 3);
            assert_eq!(
                query_count::count("dunning.invoice_lookup"),
                1,
                "one DISTINCT ON lookup must serve every due dunning row"
            );

            let still_due: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM dunning_records
              WHERE tenant_id = ANY($1) AND next_retry_at IS NOT NULL",
            )
            .bind(&tenants[..])
            .fetch_one(&env.pool)
            .await
            .expect("dunning state");
            assert_eq!(
                still_due, 0,
                "no open invoice: every candidate's retry is cleared"
            );

            match previous {
                Some(auto) => std::env::set_var("AUTO_PAY_OPEN_INVOICES", auto),
                None => std::env::remove_var("AUTO_PAY_OPEN_INVOICES"),
            }
            drop(guard);
        }
    );

    // ---------------- dedicated IP edge paths ----------------
    async fn seed_dedicated_ip(
        env: &Env,
        ip_id: &str,
        tenant: &str,
        address: &str,
        billing_status: &str,
        item: Option<&str>,
    ) {
        sqlx::query(
            "INSERT INTO dedicated_ips (id, tenant_id, ip_address, status, billing_status,
                                        mollie_mandate_id)
             VALUES ($1, $2, $3, 'active', $4, $5)",
        )
        .bind(ip_id)
        .bind(tenant)
        .bind(address)
        .bind(billing_status)
        .bind(item)
        .execute(&env.pool)
        .await
        .expect("dedicated ip");
    }

    env_test!(
        dedicated_ip_charge_without_price_cents_moves_nothing,
        |env| {
            let guard = ENV_LOCK.lock().await;
            let previous = std::env::var("DEDICATED_IP_PRICE_CENTS").ok();

            let tenant = "mtcov_dip_noprice";
            seed_tenant(env, tenant, "growth", "active").await;
            seed_dedicated_ip(
                env,
                "cov_dip_noprice",
                tenant,
                "203.0.113.251",
                "pending_charge",
                None,
            )
            .await;
            let client = Client::new();
            // The canonical price lives in platform-catalog (prices change
            // only at the source). A missing, blank or non-numeric override
            // therefore falls back to the catalog price, the sweep MOVES —
            // while an explicit non-positive override (0 / negative) is the
            // operator's disable switch and moves nothing.
            for price in [None, Some(""), Some("   "), Some("abc")] {
                match price {
                    Some(value) => std::env::set_var("DEDICATED_IP_PRICE_CENTS", value),
                    None => std::env::remove_var("DEDICATED_IP_PRICE_CENTS"),
                }
                // No stored token on the seeded subscription: the sweep runs
                // at the catalog price and reports the charge as a failure
                // (never a silent no-op), assert it is no longer disabled.
                let result = process_dedicated_ip_billing(&env.state, &client)
                    .await
                    .expect("dip billing");
                assert_eq!(result.canceled, 0, "price {price:?}");
            }
            for price in [Some("0"), Some("-5")] {
                if let Some(value) = price {
                    std::env::set_var("DEDICATED_IP_PRICE_CENTS", value);
                }
                let result = process_dedicated_ip_billing(&env.state, &client)
                    .await
                    .expect("dip billing");
                assert_eq!(
                    (result.charged, result.canceled),
                    (0, 0),
                    "explicit non-positive override disables the sweep: {price:?}"
                );
            }
            std::env::remove_var("DEDICATED_IP_PRICE_CENTS");
            let (billing, failures): (String, i32) = sqlx::query_as(
                "SELECT billing_status, COALESCE(billing_failure_count, 0)
             FROM dedicated_ips WHERE id = 'cov_dip_noprice'",
            )
            .fetch_one(&env.pool)
            .await
            .expect("ip state");
            // The row never moves to provisioned (no charge could be made
            // without a stored token), but with the catalog price as the
            // default the sweep is no longer a SILENT no-op: every enabled
            // attempt records its failure visibly.
            assert_eq!(billing.as_str(), "pending_charge");
            assert!(
                failures >= 1,
                "enabled sweeps must record their failures, got {failures}"
            );

            match previous {
                Some(price) => std::env::set_var("DEDICATED_IP_PRICE_CENTS", price),
                None => std::env::remove_var("DEDICATED_IP_PRICE_CENTS"),
            }
            drop(guard);
        }
    );

    env_test!(dedicated_ip_cancel_finalizes_locally_without_http, |env| {
        let mock = Mock::default();
        let base = spawn_mock(mock.clone()).await;
        let guard = ENV_LOCK.lock().await;
        let previous = (
            std::env::var("MOLLIE_API_KEY").ok(),
            std::env::var("MOLLIE_API_BASE_URL").ok(),
            std::env::var("DEDICATED_IP_PRICE_CENTS").ok(),
        );
        std::env::set_var("MOLLIE_API_KEY", "mollie-test-key-fixture");
        std::env::set_var("MOLLIE_API_BASE_URL", format!("{base}/v2"));
        std::env::set_var("DEDICATED_IP_PRICE_CENTS", "500");

        let tenant = "mtcov_dip_cancel";
        seed_tenant(env, tenant, "growth", "active").await;
        // Mollie has no provider-side subscription-item object AND no
        // automatic future charges for the add-on (each activation is
        // charged by our own sweep), so a cancel is a LOCAL transition:
        // with or without a stale stored reference, no HTTP is ever made.
        seed_dedicated_ip(
            env,
            "cov_dip_cancel_none",
            tenant,
            "203.0.113.252",
            "pending_cancel",
            None,
        )
        .await;
        seed_dedicated_ip(
            env,
            "cov_dip_cancel_gone",
            tenant,
            "203.0.113.253",
            "pending_cancel",
            Some("si_gone"),
        )
        .await;
        let client = Client::new();
        let canceled = process_pending_dedicated_ip_cancels(&env.state, &client)
            .await
            .expect("cancels");
        assert_eq!(canceled, 2, "both rows finalize locally");
        let rows: Vec<(String, String, Option<DateTime<Utc>>)> = sqlx::query_as(
            "SELECT id, billing_status, billing_ended_at FROM dedicated_ips
             WHERE id LIKE 'cov_dip_cancel_%' ORDER BY id",
        )
        .fetch_all(&env.pool)
        .await
        .expect("ip states");
        assert_eq!(
            rows.iter()
                .map(|(id, status, ended)| (id.as_str(), status.as_str(), ended.is_some()))
                .collect::<Vec<_>>(),
            vec![
                ("cov_dip_cancel_gone", "canceled", true),
                ("cov_dip_cancel_none", "canceled", true),
            ],
            "cancel is timestamped and never wedges on a stale provider reference"
        );
        assert_eq!(
            mock.call_count("/v2/payments"),
            0,
            "no HTTP to the payments endpoint"
        );

        match previous {
            (Some(key), Some(url), Some(price)) => {
                std::env::set_var("MOLLIE_API_KEY", key);
                std::env::set_var("MOLLIE_API_BASE_URL", url);
                std::env::set_var("DEDICATED_IP_PRICE_CENTS", price);
            }
            _ => {
                std::env::remove_var("MOLLIE_API_KEY");
                std::env::remove_var("MOLLIE_API_BASE_URL");
                std::env::remove_var("DEDICATED_IP_PRICE_CENTS");
            }
        }
        drop(guard);
    });

    env_test!(dedicated_ip_missing_table_is_a_clean_noop, |env| {
        let guard = ENV_LOCK.lock().await;
        let previous = std::env::var("DEDICATED_IP_PRICE_CENTS").ok();
        // A VALID cents price: with the sweep disabled the missing table
        // would never be queried and the test would pass for the wrong
        // reason.
        std::env::set_var("DEDICATED_IP_PRICE_CENTS", "500");
        sqlx::query("DROP TABLE IF EXISTS dedicated_ips CASCADE")
            .execute(&env.pool)
            .await
            .expect("drop table");

        let client = Client::new();
        let result = process_dedicated_ip_billing(&env.state, &client)
            .await
            .expect("missing table must not error the sweep");
        assert_eq!((result.charged, result.canceled), (0, 0));

        match previous {
            Some(price) => std::env::set_var("DEDICATED_IP_PRICE_CENTS", price),
            None => std::env::remove_var("DEDICATED_IP_PRICE_CENTS"),
        }
        drop(guard);
    });

    // ---------------- SLA credits: override plans + caps + currency ----------------

    env_test!(
        sla_credits_use_override_plan_and_cap_in_invoice_currency,
        |env| {
            let overridden = "mtcov_sla_override";
            let unentitled = "mtcov_sla_unentitled";
            seed_tenant(env, overridden, "sla_base", "active").await;
            seed_tenant(env, unentitled, "sla_base", "active").await;
            seed_plan(env, "sla_base", 100_000, json!({})).await;
            seed_plan(
                env,
                "sla_capped",
                100_000,
                json!({"slaGuarantee": true, "slaCreditPercentage": 10}),
            )
            .await;
            sqlx::query(
                "INSERT INTO plan_overrides (tenant_id, plan, active)
                 VALUES ($1, 'sla_capped', true)",
            )
            .bind(overridden)
            .execute(&env.pool)
            .await
            .expect("override");

            let now = Utc::now();
            let this_month = now
                .date_naive()
                .with_day(1)
                .expect("first")
                .and_hms_opt(0, 0, 0)
                .expect("midnight")
                .and_utc();
            let last_month = this_month - chrono::Months::new(1);
            let period_date = last_month.date_naive();
            for tenant in [overridden, unentitled] {
                sqlx::query(
                    "INSERT INTO sla_metrics (tenant_id, period_month, uptime_percent)
                     VALUES ($1, $2, 97.0000)",
                )
                .bind(tenant)
                .bind(period_date)
                .execute(&env.pool)
                .await
                .expect("sla metric");
            }
            // Only the overridden tenant has a paid invoice: the base tenant
            // is not entitled, so it must never receive a credit.
            let invoice = Uuid::new_v4();
            seed_invoice_row(
                env,
                invoice,
                overridden,
                "paid",
                last_month + chrono::Duration::days(5),
                Some(last_month + chrono::Duration::days(6)),
                None,
            )
            .await;
            sqlx::query(
                "UPDATE invoices SET total = 10000, subtotal = 10000, amount = 10000,
                    currency = 'USD', period_start = $2, period_end = $3 WHERE id = $1",
            )
            .bind(invoice)
            .bind(last_month)
            .bind(this_month)
            .execute(&env.pool)
            .await
            .expect("invoice totals");

            let sweep = process_monthly_sla_credits(&env.state)
                .await
                .expect("sla sweep");
            assert_eq!(sweep.tenants_checked, 2, "both candidates were evaluated");
            assert_eq!(sweep.credits_created, 1, "only the entitled tenant");
            let (amount, percent, currency): (i32, f64, String) = sqlx::query_as(
                "SELECT credit_amount, credit_percent::double precision, currency
                 FROM sla_credits WHERE tenant_id = $1",
            )
            .bind(overridden)
            .fetch_one(&env.pool)
            .await
            .expect("credit");
            assert_eq!(amount, 1_000, "50% breach credit capped at the plan's 10%");
            assert_eq!(percent, 50.0);
            assert_eq!(currency, "USD", "credited in the invoice's own currency");
            let unentitled_credits: i64 =
                sqlx::query_scalar("SELECT COUNT(*) FROM sla_credits WHERE tenant_id = $1")
                    .bind(unentitled)
                    .fetch_one(&env.pool)
                    .await
                    .expect("unentitled credits");
            assert_eq!(unentitled_credits, 0);
        }
    );

    // ---------------- abuse report transitions ----------------

    env_test!(
        abuse_review_rejects_unknown_and_illegal_and_mirrors_restrictions,
        |env| {
            let tenant = "mtcov_abuse_review";
            seed_tenant(env, tenant, "free", "active").await;

            let missing = review_abuse_report(&env.pool, Uuid::new_v4(), "resolved", "adm", "")
                .await
                .expect_err("unknown report");
            assert!(missing.contains("not found"), "{missing}");

            let report: Uuid = sqlx::query_scalar(
                "INSERT INTO abuse_reports (tenant_id, report_type, status)
                 VALUES ($1, 'spam', 'open') RETURNING id",
            )
            .bind(tenant)
            .fetch_one(&env.pool)
            .await
            .expect("report");

            let illegal = review_abuse_report(&env.pool, report, "confirmed", "adm", "")
                .await
                .expect_err("open -> confirmed is not authorized");
            assert!(illegal.contains("Unauthorized"), "{illegal}");

            review_abuse_report(&env.pool, report, "investigating", "adm", "looking")
                .await
                .expect("open -> investigating");
            let active: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM tenant_restrictions
                 WHERE tenant_id = $1 AND kind = 'abuse' AND cleared_at IS NULL",
            )
            .bind(tenant)
            .fetch_one(&env.pool)
            .await
            .expect("restriction");
            assert_eq!(active, 1, "an active report imposes the abuse hold");
            assert!(tenant_has_open_abuse_hold(&env.state, tenant)
                .await
                .expect("hold check"));

            review_abuse_report(&env.pool, report, "confirmed", "adm", "confirmed")
                .await
                .expect("investigating -> confirmed");
            review_abuse_report(&env.pool, report, "resolved", "adm", "fixed")
                .await
                .expect("confirmed -> resolved");
            let (status, resolved_at, cleared): (String, Option<DateTime<Utc>>, i64) =
                sqlx::query_as(
                    "SELECT r.status, r.resolved_at,
                            (SELECT COUNT(*) FROM tenant_restrictions tr
                             WHERE tr.tenant_id = r.tenant_id AND tr.kind = 'abuse'
                               AND tr.cleared_at IS NOT NULL)
                     FROM abuse_reports r WHERE r.id = $1",
                )
                .bind(report)
                .fetch_one(&env.pool)
                .await
                .expect("report state");
            assert_eq!(status, "resolved");
            assert!(resolved_at.is_some());
            assert_eq!(cleared, 1, "resolution releases the abuse hold");
            assert!(!tenant_has_open_abuse_hold(&env.state, tenant)
                .await
                .expect("hold check"));
            let audits: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM audit_logs WHERE tenant_id = $1
                 AND action = 'billing.abuse_report_transition'",
            )
            .bind(tenant)
            .fetch_one(&env.pool)
            .await
            .expect("audits");
            assert_eq!(audits, 3, "every transition is audited");
        }
    );

    env_test!(mark_payment_recovered_unscoped_resets_the_hold, |env| {
        let tenant = "mtcov_recovery_all";
        seed_tenant(env, tenant, "free", "suspended").await;
        seed_billing_hold(env, tenant, "in_all").await;

        mark_payment_recovered(&env.state, tenant, None)
            .await
            .expect("unscoped recovery");
        let tenant_status: String = sqlx::query_scalar("SELECT status FROM tenants WHERE id = $1")
            .bind(tenant)
            .fetch_one(&env.pool)
            .await
            .expect("tenant");
        assert_eq!(tenant_status, "active");
        let queued: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM messages WHERE tenant_id = $1 AND status = 'queued'",
        )
        .bind(tenant)
        .fetch_one(&env.pool)
        .await
        .expect("messages");
        assert_eq!(queued, 1, "mail is released");
        let dunning: String =
            sqlx::query_scalar("SELECT status FROM dunning_records WHERE tenant_id = $1")
                .bind(tenant)
                .fetch_one(&env.pool)
                .await
                .expect("dunning");
        assert_eq!(dunning, "healthy");
    });

    env_test!(cost_margin_warning_does_not_throttle, |env| {
        let tenant = "mtcov_margin_warn";
        seed_tenant(env, tenant, "free", "active").await;
        let key = billing_common::cost_throttle::cost_throttle_key(tenant);
        redis_del(env, &key).await;
        let today = Utc::now().date_naive();
        sqlx::query(
            "INSERT INTO tenant_costs (tenant_id, recorded_at, total_cost, revenue)
             VALUES ($1, $2, 85, 100)",
        )
        .bind(tenant)
        .bind(today)
        .execute(&env.pool)
        .await
        .expect("warning-band costs");

        let status = check_tenant_cost_margin(&env.state, tenant)
            .await
            .expect("margin");
        assert_eq!(status, CostMarginStatus::Warning);
        assert!(
            !redis_exists(env, &key).await,
            "a warning never rate-limits a tenant"
        );
        let alert_type: String = sqlx::query_scalar(
            "SELECT alert_type FROM cost_alerts
             WHERE tenant_id = $1 AND resolved_at IS NULL ORDER BY created_at DESC LIMIT 1",
        )
        .bind(tenant)
        .fetch_one(&env.pool)
        .await
        .expect("alert");
        assert_eq!(alert_type, "low_margin");

        // Recovery (healthy band) clears nothing that was never set.
        sqlx::query("UPDATE tenant_costs SET total_cost = 10, revenue = 100 WHERE tenant_id = $1")
            .bind(tenant)
            .execute(&env.pool)
            .await
            .expect("recover");
        let status = check_tenant_cost_margin(&env.state, tenant)
            .await
            .expect("margin");
        assert_eq!(status, CostMarginStatus::Healthy);
    });

    // ===================================================================
    // Deep adversarial additions: the scheduler's startup sweeps and tick
    // loops (virtual clock), month-end closing, trial reconciliation,
    // dunning grace expiry, wallet conservation, restriction-aware recovery
    // and the cost-margin throttle, each pinned to exactly-once semantics.
    // ===================================================================

    async fn seed_tenant_plan(env: &Env, tenant: &str, plan: &str, status: &str) {
        sqlx::query(
            "INSERT INTO tenants (id, name, plan, status) VALUES ($1, $2, $3, $4)
             ON CONFLICT (id) DO UPDATE SET plan = EXCLUDED.plan, status = EXCLUDED.status",
        )
        .bind(tenant)
        .bind(format!("Maint {tenant}"))
        .bind(plan)
        .bind(status)
        .execute(&env.pool)
        .await
        .expect("seed tenant");
    }

    async fn seed_dunning(env: &Env, tenant: &str, status: &str, grace: Option<DateTime<Utc>>) {
        sqlx::query(
            "INSERT INTO dunning_records (id, tenant_id, status, failed_payment_count, grace_period_ends_at)
             VALUES ($2, $1, $3, 2, $4)
             ON CONFLICT (tenant_id) DO UPDATE SET status = EXCLUDED.status,
                 grace_period_ends_at = EXCLUDED.grace_period_ends_at",
        )
        .bind(tenant)
        // dunning_records.id is VARCHAR(26): the tenant-prefixed id
        // overflowed it (22001). ON CONFLICT (tenant_id) keys the row, so a
        // short unique id is enough.
        .bind(format!("dun{}", &uuid::Uuid::new_v4().simple().to_string()[..22]))
        .bind(status)
        .bind(grace)
        .execute(&env.pool)
        .await
        .expect("seed dunning");
    }

    // ---------------- scheduler: startup + virtual-clock ticks ----------------

    #[tokio::test]
    async fn periodic_jobs_run_their_startup_sweeps_and_log_results() {
        let Some(env) = provision("periodic_startup").await else {
            return;
        };
        let _metering_guard = metering_keys_guard(&env.admin_url).await;
        crate::test_support::ensure_trace_subscriber();

        // Seed data so the startup arms of archive / reclaim / grace produce
        // RESULT logs, not just empty sweeps.
        seed_tenant_plan(&env, "mtcov_start", "growth", "active").await;
        sqlx::query(
            "INSERT INTO invoices (id, tenant_id, invoice_number, status, amount, currency,
                                   subtotal, vat_total, total, pdf_url, issued_at, paid_at,
                                   due_at, period_start, period_end)
             VALUES (gen_random_uuid(), 'mtcov_start', 'MTCOV-1', 'paid', 1000, 'eur', 1000, 0, 1000,
                     'https://pdf.example/mtcov', NOW() - INTERVAL '120 days',
                     NOW() - INTERVAL '120 days', NOW() - INTERVAL '90 days',
                     NOW() - INTERVAL '120 days', NOW() - INTERVAL '90 days')",
        )
        .execute(&env.pool)
        .await
        .expect("archivable invoice");
        sqlx::query(
            "INSERT INTO mollie_webhook_events (id, mollie_event_id, event_type, status, updated_at)
             VALUES (gen_random_uuid(), 'evt_mtcov_stale', 'invoice.paid', 'pending',
                     NOW() - INTERVAL '20 minutes')",
        )
        .execute(&env.pool)
        .await
        .expect("stale webhook");

        start_periodic_jobs(env.state.clone());
        // The startup sweeps run immediately; interval ticks are >= 30s away
        // and never fire within this bounded, real-time window. Under a full
        // workspace parallel run 40ms is far too short for the sweeps to
        // reach a freshly-provisioned database, poll to a bounded deadline
        // instead of sleeping a fixed instant.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        let archived = loop {
            let archived: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM invoice_archives")
                .fetch_one(&env.pool)
                .await
                .expect("archives");
            if archived >= 1 || std::time::Instant::now() > deadline {
                break archived;
            }
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        };
        assert_eq!(
            archived, 1,
            "startup archival archived the old paid invoice"
        );
        // The sweep arms run sequentially inside the startup task (archive →
        // reclaim → …): observing the archive row does not yet mean the
        // reclaim arm has run. Poll it to a bounded deadline like the archive
        // above instead of racing the next arm with a single query.
        let reclaim_deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        let reclaimed: String = loop {
            let status: String = sqlx::query_scalar(
                "SELECT status FROM mollie_webhook_events WHERE mollie_event_id = 'evt_mtcov_stale'",
            )
            .fetch_one(&env.pool)
            .await
            .expect("reclaimed");
            if status == "received" || std::time::Instant::now() > reclaim_deadline {
                break status;
            }
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        };
        assert_eq!(
            reclaimed, "received",
            "startup reclaim reset the stale claim"
        );
        env.finish().await;
    }

    #[tokio::test]
    async fn periodic_jobs_startup_error_arms_are_logged_not_fatal() {
        let Some(env) = provision("periodic_startup_faults").await else {
            return;
        };
        crate::test_support::ensure_trace_subscriber();
        // A VALID cents price: without it the dedicated-IP sweep returns
        // before touching the table and its error arm would stay cold.
        let previous_price = std::env::var("DEDICATED_IP_PRICE_CENTS").ok();
        std::env::set_var("DEDICATED_IP_PRICE_CENTS", "500");
        // Break the tables the startup sweeps read: every Err arm must be an
        // error! log, never a panic or an aborted task.
        env.break_table("invoices").await;
        env.break_table("mollie_webhook_events").await;
        env.break_table("dedicated_ips").await;
        start_periodic_jobs(env.state.clone());
        tokio::time::sleep(std::time::Duration::from_millis(40)).await;
        env.restore_table("invoices").await;
        env.restore_table("mollie_webhook_events").await;
        env.restore_table("dedicated_ips").await;
        match previous_price {
            Some(value) => std::env::set_var("DEDICATED_IP_PRICE_CENTS", value),
            None => std::env::remove_var("DEDICATED_IP_PRICE_CENTS"),
        }
        env.finish().await;
    }

    #[tokio::test]
    async fn periodic_jobs_tick_every_loop_under_a_virtual_clock() {
        let Some(env) = provision("periodic_ticks").await else {
            return;
        };
        let _metering_guard = metering_keys_guard(&env.admin_url).await;
        crate::test_support::ensure_trace_subscriber();
        seed_tenant_plan(&env, "mtcov_tick", "growth", "active").await;
        // All real I/O (provisioning) happened on the running clock; now
        // freeze time and let the scheduler's timers fast-forward through a
        // virtual day so EVERY loop ticks at least once.
        tokio::time::pause();
        start_periodic_jobs(env.state.clone());
        let virtual_day = tokio::time::sleep(std::time::Duration::from_secs(26 * 3600));
        // Bound the virtual fast-forward with REAL time: auto-advance makes
        // this finish in milliseconds; a hang fails loudly instead.
        let _ = tokio::time::timeout(std::time::Duration::from_secs(60), virtual_day).await;
        env.finish().await;
    }

    // ---------------- month-end closing ----------------

    env_test!(month_end_closing_is_exactly_once_per_period, |env| {
        seed_tenant_plan(env, "mtcov_close", "growth", "active").await;
        // One paid invoice in the CURRENT month: the closing targets the
        // PREVIOUS month, so the first run records an EMPTY closing marker.
        sqlx::query(
            "INSERT INTO invoices (id, tenant_id, invoice_number, status, amount, currency,
                                   subtotal, vat_total, total, issued_at, due_at,
                                   period_start, period_end)
             VALUES (gen_random_uuid(), 'mtcov_close', 'MTCOV-2', 'paid', 10000, 'eur',
                     8000, 2000, 10000, NOW(), NOW() + INTERVAL '30 days', NOW(), NOW())",
        )
        .execute(&env.pool)
        .await
        .expect("current-month invoice");

        let ran = perform_month_end_closing(&env.state)
            .await
            .expect("closing");
        assert!(ran, "an empty period still records its closing marker");
        // total_invoices is INTEGER (INT4) on the canonical schema, sqlx
        // does not coerce it to i64.
        let (total, status): (i32, String) = sqlx::query_as(
            "SELECT total_invoices, status FROM month_end_closings ORDER BY created_at DESC LIMIT 1",
        )
        .fetch_one(&env.pool)
        .await
        .expect("closing row");
        assert_eq!(total, 0);
        assert_eq!(status, "completed");
        // Idempotent: the second run in the same period is a no-op.
        let ran = perform_month_end_closing(&env.state)
            .await
            .expect("closing");
        assert!(!ran, "a closed period never closes twice");
        let closings: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM month_end_closings")
            .fetch_one(&env.pool)
            .await
            .expect("count");
        assert_eq!(closings, 1, "exactly one closing row per period");

        // A paid invoice in the PREVIOUS month is closed with exact totals.
        sqlx::query(
            "INSERT INTO invoices (id, tenant_id, invoice_number, status, amount, currency,
                                   subtotal, vat_total, total, issued_at, due_at,
                                   period_start, period_end)
             VALUES (gen_random_uuid(), 'mtcov_close', 'MTCOV-3', 'paid', 12400, 'eur',
                     10000, 2400, 12400, NOW() - INTERVAL '1 month', NOW(), NOW(), NOW())",
        )
        .execute(&env.pool)
        .await
        .expect("last-month invoice");
        // Drop the marker so the closing re-runs for the populated period.
        sqlx::query("DELETE FROM month_end_closings")
            .execute(&env.pool)
            .await
            .expect("reset");
        let ran = perform_month_end_closing(&env.state)
            .await
            .expect("closing");
        assert!(ran);
        // The canonical invoices columns are subtotal/vat_total/total (the
        // *_cents names live on month_end_closings).
        let (closed_at_set, revenue, vat): (bool, i64, i64) = sqlx::query_as(
            "SELECT closed_at IS NOT NULL, total, vat_total
             FROM invoices WHERE invoice_number = 'MTCOV-3'",
        )
        .fetch_one(&env.pool)
        .await
        .expect("invoice");
        assert!(closed_at_set, "the paid invoice is closed");
        assert_eq!(revenue, 12400);
        assert_eq!(vat, 2400);
        let audit: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM billing_audit_log WHERE action = 'month_end_closing'",
        )
        .fetch_one(&env.pool)
        .await
        .expect("audit");
        assert_eq!(audit, 1, "the closing writes a system audit entry");
    });

    env_test!(month_end_closing_fault_arms_fail_honestly, |env| {
        seed_tenant_plan(env, "mtcov_closefault", "growth", "active").await;
        env.break_table("month_end_closings").await;
        let error = perform_month_end_closing(&env.state)
            .await
            .expect_err("broken closing table");
        assert!(
            error.contains("Failed to check existing month-end closing"),
            "honest failure: {error}"
        );
        env.restore_table("month_end_closings").await;
    });

    // ---------------- trial reconciliation ----------------

    env_test!(trial_sweep_downgrades_only_stale_trials, |env| {
        seed_tenant_plan(env, "mtcov_trial_stale", "growth", "active").await;
        seed_tenant_plan(env, "mtcov_trial_fresh", "growth", "active").await;
        // Real timestamps: the bound value reaches $3::timestamptz as a
        // parameter, so SQL text like "NOW() - INTERVAL ..." is rejected
        // (22007) instead of being evaluated.
        for (tenant, sub, trial_end) in [
            (
                "mtcov_trial_stale",
                "sub_mtcov_stale",
                chrono::Utc::now() - chrono::Duration::days(3),
            ),
            (
                "mtcov_trial_fresh",
                "sub_mtcov_fresh",
                chrono::Utc::now() + chrono::Duration::days(10),
            ),
        ] {
            sqlx::query(
                "INSERT INTO mollie_subscriptions
                     (tenant_id, mollie_subscription_id, plan, status, billing_cycle_start,
                      billing_cycle_end, trial_end, mollie_customer_id)
                 VALUES ($1, $2, 'growth', 'trialing', NOW() - INTERVAL '20 days',
                         NOW() - INTERVAL '2 days', $3::timestamptz, $1)",
            )
            .bind(tenant)
            .bind(sub)
            .bind(trial_end)
            .execute(&env.pool)
            .await
            .expect("trial row");
        }

        let swept = sweep_expired_trials(&env.state).await.expect("sweep");
        assert_eq!(swept, 1, "only the stale trial is downgraded");
        let (stale_status, stale_plan): (String, String) = sqlx::query_as(
            "SELECT (SELECT status FROM mollie_subscriptions WHERE mollie_subscription_id = 'sub_mtcov_stale'),
                    (SELECT plan FROM tenants WHERE id = 'mtcov_trial_stale')",
        )
        .fetch_one(&env.pool)
        .await
        .expect("stale");
        assert_eq!(stale_status, "canceled");
        assert_eq!(stale_plan, "free", "entitlement drops with the stale trial");
        let fresh_plan: String =
            sqlx::query_scalar("SELECT plan FROM tenants WHERE id = 'mtcov_trial_fresh'")
                .fetch_one(&env.pool)
                .await
                .expect("fresh");
        assert_eq!(fresh_plan, "growth", "a live trial is never raced");
        let audit: i64 = sqlx::query_scalar(
            // These sweeps audit through the canonical compliance audit_logs chain
            // (append_audit_log), not the billing-local log.
            "SELECT COUNT(*) FROM audit_logs WHERE action = 'billing.trial_expired_sweep'",
        )
        .fetch_one(&env.pool)
        .await
        .expect("audit");
        assert_eq!(audit, 1, "the downgrade is audited");
        // Idempotent: a second sweep finds nothing.
        let swept = sweep_expired_trials(&env.state).await.expect("sweep");
        assert_eq!(swept, 0);
    });

    env_test!(empty_trial_sweep_commits_cleanly, |env| {
        let swept = sweep_expired_trials(&env.state).await.expect("sweep");
        assert_eq!(swept, 0, "an empty sweep is a committed no-op");
    });

    // ---------------- dunning grace expiry ----------------

    env_test!(grace_expiry_purges_queues_and_notifies_once, |env| {
        for tenant in ["mtcov_grace_a", "mtcov_grace_b"] {
            seed_tenant_plan(env, tenant, "growth", "suspended").await;
            seed_dunning(
                env,
                tenant,
                "hard_suspended",
                Some(Utc::now() - chrono::Duration::days(2)),
            )
            .await;
            sqlx::query(
                "INSERT INTO messages (id, tenant_id, from_email, to_emails, status, created_at, updated_at)
                 VALUES (gen_random_uuid(), $1, 'billing@apexmail.test', '[\"tenant@example.test\"]'::jsonb, 'dunning_queued', NOW(), NOW())",
            )
            .bind(tenant)
            .execute(&env.pool)
            .await
            .expect("queued message");
        }

        // Batch size 1 forces the loop through TWO full iterations.
        let result = process_grace_period_expirations(&env.state, 1)
            .await
            .expect("grace sweep");
        assert_eq!(result.processed_count, 2);
        assert_eq!(
            result.purged_messages_count, 2,
            "queued messages are purged"
        );
        let notifications: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM notification_queue WHERE type = 'messages_purged'",
        )
        .fetch_one(&env.pool)
        .await
        .expect("notifications");
        assert_eq!(notifications, 2, "each tenant is notified exactly once");
        let messages_left: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM messages WHERE status = 'dunning_queued'")
                .fetch_one(&env.pool)
                .await
                .expect("messages");
        assert_eq!(messages_left, 0);
        let grace_left: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM dunning_records WHERE grace_period_ends_at IS NOT NULL",
        )
        .fetch_one(&env.pool)
        .await
        .expect("grace");
        assert_eq!(grace_left, 0, "the expired grace window is cleared");

        // Idempotent: nothing matches a second sweep.
        let result = process_grace_period_expirations(&env.state, 100)
            .await
            .expect("grace sweep");
        assert_eq!(result.processed_count, 0);
    });

    // ---------------- wallet conservation ----------------

    async fn seed_wallet(env: &Env, tenant: &str, balance: i64, reserved: i64) -> uuid::Uuid {
        seed_tenant_plan(env, tenant, "growth", "active").await;
        let id: uuid::Uuid = sqlx::query_scalar(
            "INSERT INTO wallets (tenant_id, balance, reserved) VALUES ($1, $2, $3) RETURNING id",
        )
        .bind(tenant)
        .bind(balance)
        .bind(reserved)
        .fetch_one(&env.pool)
        .await
        .expect("wallet");
        sqlx::query(
            "INSERT INTO wallet_transactions (wallet_id, tenant_id, type, amount, balance_after, description)
             VALUES ($1, $2, 'credit', $3, $4, 'seed credit')",
        )
        .bind(id)
        .bind(tenant)
        .bind(balance)
        .bind(balance)
        .execute(&env.pool)
        .await
        .expect("credit row");
        id
    }

    env_test!(stale_credits_expire_once_under_the_fifo_cap, |env| {
        let tenant = "mtcov_expiry";
        // A 13-month-old credit of 3000, a fresh credit of 2000: only the
        // stale, unconsumed part may expire.
        let wallet = seed_wallet(env, tenant, 5000, 0).await;
        sqlx::query(
            "INSERT INTO wallet_transactions (wallet_id, tenant_id, type, amount, balance_after, description, created_at)
             VALUES ($1, $2, 'credit', 3000, 3000, 'old credit', NOW() - INTERVAL '13 months')",
        )
        .bind(wallet)
        .bind(tenant)
        .execute(&env.pool)
        .await
        .expect("old credit");

        let expired = expire_stale_wallet_credits(&env.state)
            .await
            .expect("expiry");
        assert_eq!(expired, 1);
        let (balance, expiry_rows): (i64, i64) = sqlx::query_as(
            "SELECT (SELECT balance FROM wallets WHERE tenant_id = $1),
                    (SELECT COUNT(*) FROM wallet_transactions
                     WHERE tenant_id = $1 AND reference = 'wallet_credit_expiry')",
        )
        .bind(tenant)
        .fetch_one(&env.pool)
        .await
        .expect("wallet");
        assert_eq!(balance, 2000, "only the stale credit expired");
        assert_eq!(expiry_rows, 1, "the expiry is a single ledger debit");
        let audit: i64 = sqlx::query_scalar(
            // These sweeps audit through the canonical compliance audit_logs chain
            // (append_audit_log), not the billing-local log.
            "SELECT COUNT(*) FROM audit_logs WHERE action = 'billing.wallet_credit_expired'",
        )
        .fetch_one(&env.pool)
        .await
        .expect("audit");
        assert_eq!(audit, 1);

        // Self-limiting: the expiry debit counts as consumption.
        let expired = expire_stale_wallet_credits(&env.state)
            .await
            .expect("expiry");
        assert_eq!(expired, 0, "the sweep never expires the same credit twice");
    });

    // ---------------- restriction-aware recovery ----------------

    env_test!(payment_recovery_scopes_to_the_settled_invoice, |env| {
        let tenant = "mtcov_recover";
        seed_tenant_plan(env, tenant, "growth", "suspended").await;
        seed_dunning(env, tenant, "hard_suspended", None).await;
        sqlx::query(
            "INSERT INTO tenant_restrictions (tenant_id, kind, reason, actor_type)
             VALUES ($1, 'billing', 'dunning hard suspension', 'system')",
        )
        .bind(tenant)
        .execute(&env.pool)
        .await
        .expect("billing hold");
        // The latest failure belongs to a DIFFERENT invoice.
        sqlx::query(
            "INSERT INTO dunning_events (id, tenant_id, event_type, invoice_id, created_at)
             VALUES (gen_random_uuid(), $1, 'payment_failed', 'in_other', NOW())",
        )
        .bind(tenant)
        .execute(&env.pool)
        .await
        .expect("failure event");

        mark_payment_recovered(&env.state, tenant, Some("in_settled"))
            .await
            .expect("scoped recovery");
        let (status, hold_cleared): (String, bool) = sqlx::query_as(
            "SELECT (SELECT status FROM dunning_records WHERE tenant_id = $1),
                    (SELECT cleared_at IS NOT NULL FROM tenant_restrictions
                     WHERE tenant_id = $1 AND kind = 'billing')",
        )
        .bind(tenant)
        .fetch_one(&env.pool)
        .await
        .expect("state");
        assert_eq!(
            status, "hard_suspended",
            "Fix F4: a different failing invoice keeps dunning"
        );
        assert!(!hold_cleared, "the billing hold survives a scoped refusal");
        let recovered: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM dunning_events WHERE tenant_id = $1 AND event_type = 'payment_recovered'",
        )
        .bind(tenant)
        .fetch_one(&env.pool)
        .await
        .expect("events");
        assert_eq!(
            recovered, 1,
            "the settled invoice's recovery is still logged"
        );

        // Recovering the invoice that ACTUALLY failed resets everything.
        mark_payment_recovered(&env.state, tenant, Some("in_other"))
            .await
            .expect("full recovery");
        let (status, tenant_status): (String, String) = sqlx::query_as(
            "SELECT (SELECT status FROM dunning_records WHERE tenant_id = $1),
                    (SELECT status FROM tenants WHERE id = $1)",
        )
        .bind(tenant)
        .fetch_one(&env.pool)
        .await
        .expect("state");
        assert_eq!(status, "healthy");
        assert_eq!(tenant_status, "active", "the billing suspension is lifted");
    });

    env_test!(payment_recovery_never_touches_non_billing_holds, |env| {
        let tenant = "mtcov_recover_admin";
        seed_tenant_plan(env, tenant, "growth", "suspended").await;
        seed_dunning(env, tenant, "soft_suspended", None).await;
        for kind in ["billing", "administrative"] {
            sqlx::query(
                "INSERT INTO tenant_restrictions (tenant_id, kind, reason, actor_type)
                     VALUES ($1, $2, 'hold', 'system')",
            )
            .bind(tenant)
            .bind(kind)
            .execute(&env.pool)
            .await
            .expect("hold");
        }

        admin_reset_dunning_restriction_aware(
            &env.pool,
            &env.redis,
            tenant,
            "admin-cov",
            "manual reset",
        )
        .await
        .expect("admin reset");
        let cleared: Vec<(String,)> = sqlx::query_as(
                "SELECT kind FROM tenant_restrictions WHERE tenant_id = $1 AND cleared_at IS NULL ORDER BY kind",
            )
            .bind(tenant)
            .fetch_all(&env.pool)
            .await
            .expect("holds");
        let kinds: Vec<String> = cleared.into_iter().map(|row| row.0).collect();
        assert_eq!(
            kinds,
            vec!["administrative".to_string()],
            "only the billing hold clears"
        );
        let status: String =
            sqlx::query_scalar("SELECT status FROM dunning_records WHERE tenant_id = $1")
                .bind(tenant)
                .fetch_one(&env.pool)
                .await
                .expect("dunning");
        assert_eq!(status, "healthy");
    });

    // ---------------- abuse lifecycle ----------------

    #[test]
    fn abuse_transitions_are_gated() {
        assert!(abuse_transition_allowed("open", "investigating"));
        assert!(abuse_transition_allowed("investigating", "confirmed"));
        assert!(abuse_transition_allowed("investigating", "dismissed"));
        assert!(abuse_transition_allowed("confirmed", "resolved"));
        // dismissed/resolved are TERMINAL for the review cycle (the matrix's
        // documented contract): a dismissed report is not abuse, so
        // "resolving" it later would double-count a resolution.
        assert!(!abuse_transition_allowed("dismissed", "resolved"));
        assert!(
            !abuse_transition_allowed("open", "confirmed"),
            "no trial-by-default"
        );
        assert!(
            !abuse_transition_allowed("resolved", "open"),
            "terminal stays terminal"
        );
        assert!(
            !abuse_transition_allowed("confirmed", "dismissed"),
            "confirmed abuse is resolved, not dismissed"
        );
    }

    env_test!(abuse_report_blocks_recovery_until_resolved, |env| {
        let tenant = "mtcov_abuse";
        seed_tenant_plan(env, tenant, "growth", "suspended").await;
        seed_dunning(env, tenant, "hard_suspended", None).await;
        sqlx::query(
            "INSERT INTO tenant_restrictions (tenant_id, kind, reason, actor_type)
             VALUES ($1, 'billing', 'dunning hard suspension', 'system')",
        )
        .bind(tenant)
        .execute(&env.pool)
        .await
        .expect("billing hold");

        let blocked = tenant_has_open_abuse_hold(&env.state, tenant)
            .await
            .expect("hold check");
        assert!(!blocked, "no report yet: no abuse hold");

        let report_id = record_abuse_report(
            &env.state,
            tenant,
            "spam",
            Some("cov-admin"),
            serde_json::json!({}),
        )
        .await
        .expect("record report");
        let blocked = tenant_has_open_abuse_hold(&env.state, tenant)
            .await
            .expect("hold check");
        assert!(blocked, "an open report holds the tenant");

        // While the abuse report is open, payment recovery clears billing but
        // must NOT reactivate the tenant.
        mark_payment_recovered(&env.state, tenant, None)
            .await
            .expect("recovery");
        let tenant_status: String = sqlx::query_scalar("SELECT status FROM tenants WHERE id = $1")
            .bind(tenant)
            .fetch_one(&env.pool)
            .await
            .expect("status");
        assert_eq!(
            tenant_status, "suspended",
            "an open abuse report blocks reactivation"
        );

        // Dismissing the report releases the hold; resolving it does too.
        review_abuse_report(&env.pool, report_id, "dismissed", "cov-admin", "handled")
            .await
            .expect("dismiss");
        let blocked = tenant_has_open_abuse_hold(&env.state, tenant)
            .await
            .expect("hold check");
        assert!(!blocked, "a dismissed report no longer holds");
    });

    env_test!(restrictions_impose_and_clear_independently, |env| {
        let tenant = "mtcov_restrict";
        seed_tenant_plan(env, tenant, "growth", "active").await;
        impose_tenant_restriction(
            &env.pool,
            tenant,
            "verification",
            "cov reason",
            "system",
            None,
        )
        .await
        .expect("impose");
        let active: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM tenant_restrictions
                 WHERE tenant_id = $1 AND kind = 'verification' AND cleared_at IS NULL",
        )
        .bind(tenant)
        .fetch_one(&env.pool)
        .await
        .expect("count");
        assert_eq!(active, 1);
        let cleared =
            clear_tenant_restriction(&env.pool, tenant, "verification", "cov-admin", "done")
                .await
                .expect("clear");
        assert!(cleared, "the restriction existed and was cleared");
        let active: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM tenant_restrictions
                 WHERE tenant_id = $1 AND kind = 'verification' AND cleared_at IS NULL",
        )
        .bind(tenant)
        .fetch_one(&env.pool)
        .await
        .expect("count");
        assert_eq!(active, 0, "the restriction is cleared, not deleted");
    });

    // ---------------- cost margin + throttling ----------------

    async fn seed_cost_row(env: &Env, tenant: &str, revenue: i64, cost: i64) {
        seed_tenant_plan(env, tenant, "growth", "active").await;
        sqlx::query(
            "INSERT INTO tenant_costs
                 (tenant_id, recorded_at, storage_cost, bandwidth_cost, compute_cost,
                  dedicated_ip_cost, total_cost, revenue)
             VALUES ($1, NOW(), 0, 0, 0, 0, $2, $3)",
        )
        .bind(tenant)
        .bind(cost)
        .bind(revenue)
        .execute(&env.pool)
        .await
        .expect("cost row");
    }

    env_test!(cost_margin_throttles_critical_and_recovers, |env| {
        let healthy = "mtcov_cost_healthy";
        let critical = "mtcov_cost_critical";
        let warning = "mtcov_cost_warning";
        seed_cost_row(env, healthy, 10_000, 1_000).await; // 90% margin
        seed_cost_row(env, warning, 10_000, 8_500).await; // 15% margin
        seed_cost_row(env, critical, 1_000, 2_000).await; // -100% margin

        let result = process_cost_margin_checks(&env.state)
            .await
            .expect("checks");
        // The canonical chain seeds the platform `system` tenant (migration
        // 072): the sweep checks every ACTIVE tenant, so 4 are checked while
        // only the three above carry cost rows.
        assert_eq!(result.checked, 4);
        assert_eq!(result.warnings, 1);
        assert_eq!(result.critical, 1);

        // The critical tenant is throttled; the others are not.
        let mut conn = env.redis.get().await.expect("redis");
        let throttled: bool = redis::cmd("EXISTS")
            .arg(cost_throttle_key(critical))
            .query_async(&mut conn)
            .await
            .expect("exists");
        assert!(throttled, "a critical margin activates the cost throttle");
        let healthy_throttled: bool = redis::cmd("EXISTS")
            .arg(cost_throttle_key(healthy))
            .query_async(&mut conn)
            .await
            .expect("exists");
        assert!(!healthy_throttled, "a healthy margin never throttles");
        // The status cache key is `cost:status:{tenant}` (see
        // cache_cost_margin_status).
        let cached: Option<String> = redis::cmd("GET")
            .arg(format!("cost:status:{healthy}"))
            .query_async(&mut conn)
            .await
            .expect("cache");
        assert!(cached.is_some(), "the evaluated status is cached");

        // Recovery: a fresh month with no costs clears the throttle.
        sqlx::query("DELETE FROM tenant_costs WHERE tenant_id = $1")
            .bind(critical)
            .execute(&env.pool)
            .await
            .expect("clear costs");
        sqlx::query("DELETE FROM cost_alerts WHERE tenant_id = $1")
            .bind(critical)
            .execute(&env.pool)
            .await
            .expect("clear alerts");
        let status = check_tenant_cost_margin(&env.state, critical)
            .await
            .expect("check");
        assert_eq!(status, CostMarginStatus::Healthy);
        let throttled: bool = redis::cmd("EXISTS")
            .arg(cost_throttle_key(critical))
            .query_async(&mut conn)
            .await
            .expect("exists");
        assert!(!throttled, "recovery releases the throttle");
    });

    env_test!(cost_alerts_deduplicate_while_open, |env| {
        let tenant = "mtcov_cost_dedupe";
        seed_cost_row(env, tenant, 1_000, 5_000).await; // deeply negative margin
        process_cost_margin_checks(&env.state)
            .await
            .expect("checks");
        process_cost_margin_checks(&env.state)
            .await
            .expect("checks");
        let alerts: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM cost_alerts WHERE tenant_id = $1 AND alert_type = 'negative_margin'",
        )
        .bind(tenant)
        .fetch_one(&env.pool)
        .await
        .expect("alerts");
        assert_eq!(alerts, 1, "an open alert is never duplicated");
    });

    // ---------------- sweep statement-count regressions ----------------
    // Perf audit 2026-10-18 (findings 15 + 17): the subscription sweeps,
    // the usage-alert sweep and the cost-margin sweep used to pay per-row
    // statements. The captures below (the worker crate's `log_statements`
    // pattern) pin the batched shapes; the behavior-parity tests next to
    // them pin identical rows/statuses/audit payloads.

    /// Thread-local SQL capture for the batching regression tests (the pool
    /// is rebuilt with `log_statements(Debug)`), mirroring the worker
    /// crate's capture in `worker-processors::campaigns`.
    /// One fetched `audit_logs` row: (tenant_id, resource, resource_id,
    /// details, previous_hash, hash, signature, timestamp).
    type FetchedAuditRow = (
        String,
        String,
        Option<String>,
        Value,
        Option<String>,
        String,
        String,
        DateTime<Utc>,
    );

    #[derive(Clone, Default)]
    struct SweepSqlCapture {
        statements: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
    }

    impl SweepSqlCapture {
        fn statements(&self) -> Vec<String> {
            self.statements.lock().unwrap().clone()
        }

        fn count_starting_with(&self, prefix: &str) -> usize {
            self.statements()
                .iter()
                .filter(|statement| statement.trim_start().starts_with(prefix))
                .count()
        }

        fn print(&self, label: &str) {
            eprintln!("sql capture [{label}]");
            for statement in self.statements() {
                eprintln!("  {statement:?}");
            }
        }
    }

    struct SqlCaptureLayer(SweepSqlCapture);

    impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for SqlCaptureLayer {
        fn on_event(
            &self,
            event: &tracing::Event<'_>,
            _context: tracing_subscriber::layer::Context<'_, S>,
        ) {
            if event.metadata().target() != "sqlx::query" {
                return;
            }
            struct SummaryVisitor<'a>(&'a mut Option<String>);
            impl tracing::field::Visit for SummaryVisitor<'_> {
                fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
                    if field.name() == "summary" {
                        *self.0 = Some(value.to_string());
                    }
                }
                fn record_debug(
                    &mut self,
                    field: &tracing::field::Field,
                    value: &dyn std::fmt::Debug,
                ) {
                    if field.name() == "summary" {
                        *self.0 = Some(format!("{value:?}"));
                    }
                }
            }
            let mut summary = None;
            event.record(&mut SummaryVisitor(&mut summary));
            if let Some(summary) = summary {
                self.0.statements.lock().unwrap().push(summary);
            }
        }
    }

    fn capture_sweep_sql() -> (SweepSqlCapture, tracing::subscriber::DefaultGuard) {
        use tracing_subscriber::layer::SubscriberExt;
        let capture = SweepSqlCapture::default();
        let subscriber = tracing_subscriber::registry().with(SqlCaptureLayer(capture.clone()));
        (capture, tracing::subscriber::set_default(subscriber))
    }

    /// A second AppState over the SAME database whose pool logs every
    /// statement, so the capture sees exactly what the sweep issues.
    async fn logging_pool_state(env: &Env) -> Arc<AppState> {
        use sqlx::ConnectOptions;
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(2)
            .test_before_acquire(false)
            .connect_with(
                (*env.pool.connect_options())
                    .clone()
                    .log_statements(tracing::log::LevelFilter::Debug),
            )
            .await
            .expect("logging pool over the coverage database");
        AppState::new(
            pool,
            env.redis.clone(),
            crate::config::BillingConfig::default(),
        )
    }

    /// Seed a subscription shaped like `subscriptions::cancel_subscription`
    /// leaves behind for a period-end stop (`cancel_at_period_end = true`).
    async fn seed_period_end_subscription(env: &Env, tenant: &str, due: bool, status: &str) {
        sqlx::query(
            "INSERT INTO mollie_subscriptions
                 (tenant_id, mollie_subscription_id, plan, status,
                  billing_cycle_start, billing_cycle_end,
                  cancel_at_period_end, canceled_at, mollie_customer_id)
             VALUES ($1, $2, 'growth', $4,
                     NOW() - INTERVAL '30 days',
                     CASE WHEN $3 THEN NOW() - INTERVAL '1 hour'
                          ELSE NOW() + INTERVAL '10 days' END,
                     true, NOW(), $1)",
        )
        .bind(tenant)
        .bind(format!("psp_{tenant}"))
        .bind(due)
        .bind(status)
        .execute(&env.pool)
        .await
        .expect("seed canceled subscription");
    }

    env_test!(
        sweep_canceled_at_period_end_is_set_based_with_identical_rows,
        |env| {
            let due_a = "mtcov_cset_due_a";
            let due_b = "mtcov_cset_due_b";
            let future = "mtcov_cset_future";
            for tenant in [due_a, due_b, future] {
                seed_tenant(env, tenant, "growth", "active").await;
            }
            seed_period_end_subscription(env, due_a, true, "active").await;
            seed_period_end_subscription(env, due_b, true, "past_due").await;
            seed_period_end_subscription(env, future, false, "active").await;

            let guard = ENV_LOCK.lock().await;
            let previous_key = std::env::var("AUDIT_SIGNING_KEY").ok();
            std::env::set_var("AUDIT_SIGNING_KEY", "cset-audit-key-0123456789abcdef");
            let signing_key = "cset-audit-key-0123456789abcdef".to_string();

            let head_before: Option<i64> = sqlx::query_scalar(
                "SELECT head_seq FROM audit_chain_head WHERE chain_id = 'global'",
            )
            .fetch_optional(&env.pool)
            .await
            .expect("chain head before");

            let state = logging_pool_state(env).await;
            let (capture, capture_guard) = capture_sweep_sql();
            let ended = sweep_canceled_at_period_end(state.as_ref())
                .await
                .expect("sweep");
            drop(capture_guard);
            capture.print("sweep_canceled_at_period_end");

            // SET-BASED: one CTE statement performs BOTH writes, and the
            // whole audit append costs ONE head advance + ONE multi-row
            // INSERT, regardless of how many subscriptions are due.
            assert_eq!(
                capture.count_starting_with("WITH due AS"),
                1,
                "the lock+transition+downgrade must be ONE statement: {:?}",
                capture.statements()
            );
            assert_eq!(
                capture.count_starting_with("UPDATE mollie_subscriptions"),
                0,
                "no per-row subscription updates: {:?}",
                capture.statements()
            );
            assert_eq!(
                capture.count_starting_with("UPDATE tenants"),
                0,
                "no per-row tenant downgrades: {:?}",
                capture.statements()
            );
            // The provider-side cancellation must use handles captured by the
            // SAME statement that flips the status: a post-commit lookup keyed
            // on the live status would find nothing (the row is already
            // `canceled`) and Mollie would keep charging. So the CTE carries
            // the provider ids and NO subscription lookup may run at all.
            let cte = capture
                .statements()
                .into_iter()
                .find(|statement| statement.starts_with("WITH due AS"))
                .unwrap_or_default();
            assert!(!cte.is_empty(), "the due statement must run");
            // The capture truncates SQL text, so the handle contract is pinned
            // on the source of the ONE sweep function.
            let source =
                std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/maintenance.rs"))
                    .expect("maintenance source");
            let start = source
                .find("pub async fn sweep_canceled_at_period_end")
                .expect("sweep function");
            let body = &source[start..(start + 4_000).min(source.len())];
            assert!(
                body.contains("due.mollie_subscription_id")
                    && body.contains("due.mollie_customer_id"),
                "the due statement must capture the provider handles"
            );
            assert_eq!(
                capture.count_starting_with("SELECT tenant_id, mollie_subscription_id"),
                0,
                "no post-commit provider-subscription lookup: {:?}",
                capture.statements()
            );
            // The batch mandate lookup reads the NEUTRAL payment_credentials
            // ledger (billing-neutrality step 7; pc = payment_credentials).
            assert_eq!(
                capture.count_starting_with("SELECT DISTINCT ON (pc.tenant_id)"),
                1,
                "ONE batch credential lookup: {:?}",
                capture.statements()
            );
            assert_eq!(
                capture.count_starting_with("SELECT"),
                1,
                "only the batch mandate lookup may SELECT: {:?}",
                capture.statements()
            );
            assert_eq!(
                capture.count_starting_with("SELECT * FROM mollie_subscriptions"),
                0,
                "no separate due-list SELECT: {:?}",
                capture.statements()
            );
            assert_eq!(
                capture.count_starting_with("INSERT INTO audit_chain_head"),
                1,
                "ONE chain-head advance per batch"
            );
            assert_eq!(
                capture.count_starting_with("INSERT INTO audit_logs"),
                1,
                "ONE multi-row audit insert per batch"
            );
            assert!(
                capture.statements().len() <= 6,
                "the whole sweep must stay at ~5 statements (BEGIN + CTE + audit batch + COMMIT): {:?}",
                capture.statements()
            );

            // BEHAVIOR PARITY: same statuses, flags, plan, audit payloads.
            assert_eq!(ended, 2, "both due subscriptions end");
            for tenant in [due_a, due_b] {
                let (status, cancel_at_period_end): (String, bool) = sqlx::query_as(
                    "SELECT status, cancel_at_period_end FROM mollie_subscriptions
                     WHERE tenant_id = $1",
                )
                .bind(tenant)
                .fetch_one(&env.pool)
                .await
                .expect("subscription after sweep");
                assert_eq!(status, "canceled");
                assert!(!cancel_at_period_end);
                let (plan,): (String,) = sqlx::query_as("SELECT plan FROM tenants WHERE id = $1")
                    .bind(tenant)
                    .fetch_one(&env.pool)
                    .await
                    .expect("tenant after sweep");
                assert_eq!(plan, "free");
            }
            let future_status: String =
                sqlx::query_scalar("SELECT status FROM mollie_subscriptions WHERE tenant_id = $1")
                    .bind(future)
                    .fetch_one(&env.pool)
                    .await
                    .expect("future status");
            assert_eq!(future_status, "active", "a future period end is untouched");
            let (future_plan,): (String,) =
                sqlx::query_as("SELECT plan FROM tenants WHERE id = $1")
                    .bind(future)
                    .fetch_one(&env.pool)
                    .await
                    .expect("future tenant plan");
            assert_eq!(future_plan, "growth");

            // Audit rows: one per ended subscription, exact payload fields,
            // byte-re-derivable hashes and signed links, exactly what the
            // per-row append produced (resource_id is the subscription's
            // internal id, as in the original loop).
            let subscriptions: Vec<(uuid::Uuid, String)> = sqlx::query_as(
                "SELECT id, tenant_id FROM mollie_subscriptions
                 WHERE tenant_id IN ($1, $2) AND status = 'canceled'",
            )
            .bind(due_a)
            .bind(due_b)
            .fetch_all(&env.pool)
            .await
            .expect("ended subscriptions");
            let expected_audits: std::collections::HashSet<(String, String)> = subscriptions
                .iter()
                .map(|(id, tenant)| (tenant.clone(), id.to_string()))
                .collect();
            let audits: Vec<FetchedAuditRow> = sqlx::query_as(
                "SELECT tenant_id, resource, resource_id, details, previous_hash, hash,
                        signature, timestamp
                 FROM audit_logs
                 WHERE action = 'billing.subscription_ended_at_period_end'",
            )
            .fetch_all(&env.pool)
            .await
            .expect("audit rows");
            assert_eq!(audits.len(), 2, "one audit row per ended subscription");
            let audited_set: std::collections::HashSet<(String, String)> = audits
                .iter()
                .map(|(tenant_id, _, resource_id, ..)| {
                    (tenant_id.clone(), resource_id.clone().expect("resource id"))
                })
                .collect();
            assert_eq!(
                audited_set, expected_audits,
                "each ended subscription gets its own tenant-attributed audit row"
            );
            for (
                tenant_id,
                resource,
                resource_id,
                details,
                previous_hash,
                hash,
                signature,
                timestamp,
            ) in &audits
            {
                assert_eq!(resource, "subscription");
                assert_eq!(
                    details,
                    &serde_json::json!({ "effective": "period_end" }),
                    "the audit payload is unchanged"
                );
                let recomputed = apexmail_lib::audit::audit_hash(
                    Some(tenant_id),
                    None,
                    "billing.subscription_ended_at_period_end",
                    resource,
                    resource_id.as_deref(),
                    details,
                    *timestamp,
                );
                assert_eq!(&recomputed, hash, "the row hash re-derives byte-exactly");
                let expected_signature = apexmail_lib::audit::audit_log_signature(
                    previous_hash.as_deref(),
                    hash,
                    &signing_key,
                )
                .expect("signs");
                assert_eq!(&expected_signature, signature, "the link is signed");
            }

            // The batch chains in due order and advances the shared head
            // exactly once (one link per batch, like compliance log_batch).
            // Row order in the SELECT is unspecified: the row the OTHER row
            // links to was written first.
            let first_index = if audits[1].4.as_deref() == Some(audits[0].5.as_str()) {
                0
            } else {
                1
            };
            let second_index = 1 - first_index;
            let head_hash_after: Option<String> = sqlx::query_scalar(
                "SELECT head_hash FROM audit_chain_head WHERE chain_id = 'global'",
            )
            .fetch_optional(&env.pool)
            .await
            .expect("chain head after");
            let head_seq_after: i64 = sqlx::query_scalar(
                "SELECT head_seq FROM audit_chain_head WHERE chain_id = 'global'",
            )
            .fetch_one(&env.pool)
            .await
            .expect("chain seq after");
            assert_eq!(
                head_hash_after.as_deref(),
                Some(audits[second_index].5.as_str()),
                "the batch's LAST row is the new chain head"
            );
            assert_eq!(
                audits[second_index].4.as_deref(),
                Some(audits[first_index].5.as_str()),
                "entry 1 links entry 0, in-memory chain, input order"
            );
            assert_eq!(
                head_seq_after,
                head_before.unwrap_or(0) + 1,
                "one batch = one head-seq advance"
            );

            // Idempotent replay: nothing matches, nothing is written.
            let (capture_replay, replay_guard) = capture_sweep_sql();
            let replay = sweep_canceled_at_period_end(state.as_ref())
                .await
                .expect("replay");
            drop(replay_guard);
            assert_eq!(replay, 0, "replay is a no-op");
            assert_eq!(
                capture_replay.count_starting_with("INSERT INTO audit_logs"),
                0,
                "an empty sweep writes no audit rows"
            );

            match previous_key {
                Some(value) => std::env::set_var("AUDIT_SIGNING_KEY", value),
                None => std::env::remove_var("AUDIT_SIGNING_KEY"),
            }
            drop(guard);
        }
    );

    env_test!(
        sweep_expired_trials_is_set_based_with_identical_rows,
        |env| {
            let stale_a = "mtcov_tset_stale_a";
            let stale_b = "mtcov_tset_stale_b";
            let fresh = "mtcov_tset_fresh";
            let free = "mtcov_tset_free";
            for tenant in [stale_a, stale_b, fresh] {
                seed_tenant(env, tenant, "growth", "active").await;
            }
            seed_tenant(env, free, "free", "active").await;
            let now = Utc::now();
            for (tenant, sub, trial_end) in [
                (
                    stale_a,
                    "psp_trial_stale_a",
                    now - chrono::Duration::hours(48),
                ),
                (
                    stale_b,
                    "psp_trial_stale_b",
                    now - chrono::Duration::hours(30),
                ),
                (fresh, "psp_trial_fresh", now - chrono::Duration::hours(1)),
                (free, "psp_trial_free", now - chrono::Duration::hours(48)),
            ] {
                sqlx::query(
                    "INSERT INTO mollie_subscriptions
                         (tenant_id, mollie_subscription_id, plan, status, trial_end,
                          billing_cycle_start, billing_cycle_end)
                     VALUES ($1, $2, 'growth', 'trialing', $3, $4, $5)",
                )
                .bind(tenant)
                .bind(sub)
                .bind(trial_end)
                .bind(now - chrono::Duration::days(14))
                .bind(now + chrono::Duration::days(16))
                .execute(&env.pool)
                .await
                .expect("seed trial");
            }

            let guard = ENV_LOCK.lock().await;
            let previous_key = std::env::var("AUDIT_SIGNING_KEY").ok();
            std::env::set_var("AUDIT_SIGNING_KEY", "tset-audit-key-0123456789abcdef");
            let signing_key = "tset-audit-key-0123456789abcdef".to_string();

            let state = logging_pool_state(env).await;
            let (capture, capture_guard) = capture_sweep_sql();
            let swept = sweep_expired_trials(state.as_ref()).await.expect("sweep");
            drop(capture_guard);
            capture.print("sweep_expired_trials");

            // SET-BASED: one CTE statement cancels every stale trialing
            // subscription and downgrades its tenant; ONE audit batch.
            assert_eq!(
                capture.count_starting_with("WITH stale AS"),
                1,
                "the stale detection + cancel + downgrade must be ONE statement: {:?}",
                capture.statements()
            );
            assert_eq!(
                capture.count_starting_with("UPDATE mollie_subscriptions"),
                0,
                "no per-row subscription cancellations: {:?}",
                capture.statements()
            );
            assert_eq!(
                capture.count_starting_with("UPDATE tenants"),
                0,
                "no per-row tenant downgrades: {:?}",
                capture.statements()
            );
            assert_eq!(
                capture.count_starting_with("SELECT"),
                0,
                "no separate stale-list SELECT: {:?}",
                capture.statements()
            );
            assert_eq!(
                capture.count_starting_with("INSERT INTO audit_chain_head"),
                1,
                "ONE chain-head advance per batch"
            );
            assert_eq!(
                capture.count_starting_with("INSERT INTO audit_logs"),
                1,
                "ONE multi-row audit insert per batch"
            );

            // BEHAVIOR PARITY: same rows and statuses as the per-row sweep.
            assert_eq!(swept, 2, "both stale trials downgrade");
            for tenant in [stale_a, stale_b] {
                let (plan, status): (String, String) = sqlx::query_as(
                    "SELECT t.plan, s.status FROM tenants t
                     JOIN mollie_subscriptions s ON s.tenant_id = t.id WHERE t.id = $1",
                )
                .bind(tenant)
                .fetch_one(&env.pool)
                .await
                .expect("stale tenant after sweep");
                assert_eq!(plan, "free");
                assert_eq!(status, "canceled");
            }
            let fresh_status: String =
                sqlx::query_scalar("SELECT status FROM mollie_subscriptions WHERE tenant_id = $1")
                    .bind(fresh)
                    .fetch_one(&env.pool)
                    .await
                    .expect("fresh status");
            assert_eq!(fresh_status, "trialing", "a recent trial is never raced");
            let free_status: String =
                sqlx::query_scalar("SELECT status FROM mollie_subscriptions WHERE tenant_id = $1")
                    .bind(free)
                    .fetch_one(&env.pool)
                    .await
                    .expect("free tenant status");
            assert_eq!(
                free_status, "trialing",
                "a free-plan tenant is not the sweep's business"
            );

            // Audit rows: one per downgraded tenant, exact payload fields.
            let audits: Vec<(String, String, Option<String>, Value)> = sqlx::query_as(
                "SELECT tenant_id, resource, resource_id, details
                 FROM audit_logs
                 WHERE action = 'billing.trial_expired_sweep'
                 ORDER BY tenant_id",
            )
            .fetch_all(&env.pool)
            .await
            .expect("audit rows");
            assert_eq!(audits.len(), 2, "one audit row per downgraded tenant");
            for (index, (tenant_id, resource, resource_id, details)) in audits.iter().enumerate() {
                assert_eq!(resource, "mollie_subscription");
                let expected_sub = if index == 0 {
                    "psp_trial_stale_a"
                } else {
                    "psp_trial_stale_b"
                };
                assert_eq!(resource_id.as_deref(), Some(expected_sub));
                assert_eq!(
                    tenant_id.as_str(),
                    if index == 0 { stale_a } else { stale_b }
                );
                assert_eq!(
                    details,
                    &serde_json::json!({
                        "reason": "trialing subscription period ended without a terminal webhook",
                    }),
                    "the audit payload is unchanged"
                );
            }

            // The chain still verifies: re-derive and check the links.
            let chain: Vec<(Option<String>, String, String)> = sqlx::query_as(
                "SELECT previous_hash, hash, signature FROM audit_logs
                 WHERE action = 'billing.trial_expired_sweep'
                 ORDER BY tenant_id",
            )
            .fetch_all(&env.pool)
            .await
            .expect("chain rows");
            for (previous_hash, hash, signature) in &chain {
                let expected_signature = apexmail_lib::audit::audit_log_signature(
                    previous_hash.as_deref(),
                    hash,
                    &signing_key,
                )
                .expect("signs");
                assert_eq!(&expected_signature, signature, "the link is signed");
            }

            // Idempotent replay.
            let replay = sweep_expired_trials(state.as_ref()).await.expect("replay");
            assert_eq!(replay, 0, "replay is a no-op");

            match previous_key {
                Some(value) => std::env::set_var("AUDIT_SIGNING_KEY", value),
                None => std::env::remove_var("AUDIT_SIGNING_KEY"),
            }
            drop(guard);
        }
    );

    env_test!(
        cost_margin_sweep_is_grouped_with_identical_decisions,
        |env| {
            // Same shape as cost_margin_throttles_critical_and_recovers plus
            // a zero-activity tenant: the sweep must classify identically
            // while paying ONE grouped query for the whole fleet.
            let healthy = "mtcov_gcost_healthy";
            let warning = "mtcov_gcost_warning";
            let critical = "mtcov_gcost_critical";
            let inactive = "mtcov_gcost_inactive";
            seed_cost_row(env, healthy, 10_000, 1_000).await; // 90% margin
            seed_cost_row(env, warning, 10_000, 8_500).await; // 15% margin
            seed_cost_row(env, critical, 1_000, 2_000).await; // -100% margin
            seed_tenant(env, inactive, "growth", "active").await;

            let state = logging_pool_state(env).await;
            let (capture, capture_guard) = capture_sweep_sql();
            let result = process_cost_margin_checks(state.as_ref())
                .await
                .expect("checks");
            drop(capture_guard);
            capture.print("process_cost_margin_checks");

            // SET-BASED: ONE grouped summary query, NO per-tenant SUM and NO
            // separate active-tenant list; only breaching tenants pay the
            // per-tenant alert path (2 here).
            assert_eq!(
                capture.count_starting_with("SELECT t.id AS tenant_id"),
                1,
                "one GROUP BY query for the whole fleet: {:?}",
                capture.statements()
            );
            assert_eq!(
                capture.count_starting_with("SELECT COALESCE(SUM(storage_cost)"),
                0,
                "no per-tenant cost SUM may remain: {:?}",
                capture.statements()
            );
            assert_eq!(
                capture.count_starting_with("SELECT id FROM tenants WHERE status"),
                0,
                "no separate active-tenant list query: {:?}",
                capture.statements()
            );
            assert_eq!(
                capture.count_starting_with("WITH existing_alert AS"),
                2,
                "exactly the breaching tenants pay an alert statement"
            );

            // BEHAVIOR PARITY: identical counts, throttle and cache writes.
            // The canonical chain seeds the platform `system` tenant, so 5
            // active tenants are checked.
            assert_eq!(result.checked, 5);
            assert_eq!(result.warnings, 1);
            assert_eq!(result.critical, 1);
            let mut conn = env.redis.get().await.expect("redis");
            let throttled: bool = redis::cmd("EXISTS")
                .arg(cost_throttle_key(critical))
                .query_async(&mut conn)
                .await
                .expect("exists");
            assert!(throttled, "a critical margin still activates the throttle");
            let healthy_throttled: bool = redis::cmd("EXISTS")
                .arg(cost_throttle_key(healthy))
                .query_async(&mut conn)
                .await
                .expect("exists");
            assert!(!healthy_throttled, "a healthy margin never throttles");
            let inactive_throttled: bool = redis::cmd("EXISTS")
                .arg(cost_throttle_key(inactive))
                .query_async(&mut conn)
                .await
                .expect("exists");
            assert!(!inactive_throttled, "zero activity never throttles");
            for tenant in [healthy, inactive] {
                let cached: Option<String> = redis::cmd("GET")
                    .arg(format!("cost:status:{tenant}"))
                    .query_async(&mut conn)
                    .await
                    .expect("cache");
                assert!(
                    cached.is_some(),
                    "healthy tenants still get their evaluated status cached"
                );
            }
            let cached_healthy: String = redis::cmd("GET")
                .arg(format!("cost:status:{healthy}"))
                .query_async(&mut conn)
                .await
                .expect("cache");
            let cached: Value = serde_json::from_str(&cached_healthy).expect("cache json");
            assert_eq!(cached["status"], "healthy");
            assert!(
                (cached["margin"].as_f64().expect("margin") - 90.0).abs() < 1e-9,
                "the healthy margin value rides the cache: {cached}"
            );
            let alerts: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM cost_alerts")
                .fetch_one(&env.pool)
                .await
                .expect("alerts");
            assert_eq!(alerts, 2, "warning + critical open one alert each");

            // RECOVERY through the batched healthy path: a pre-existing
            // throttle on a now-healthy tenant is cleared and audited.
            {
                let mut seed_conn = env.redis.get().await.expect("redis");
                let _: () = redis::pipe()
                    .set_ex(cost_throttle_key(healthy), "{}", 60)
                    .ignore()
                    .query_async(&mut seed_conn)
                    .await
                    .expect("seed throttle");
            }
            let result = process_cost_margin_checks(&env.state)
                .await
                .expect("recovery sweep");
            assert_eq!(result.critical, 1);
            let still_throttled: bool = redis::cmd("EXISTS")
                .arg(cost_throttle_key(healthy))
                .query_async(&mut conn)
                .await
                .expect("exists");
            assert!(!still_throttled, "the stale throttle is cleared");
            let clear_audits: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM audit_logs
                 WHERE tenant_id = $1 AND action = 'billing.cost_throttle.cleared'",
            )
            .bind(healthy)
            .fetch_one(&env.pool)
            .await
            .expect("clear audits");
            assert_eq!(
                clear_audits, 1,
                "an actual throttle clear keeps its per-tenant audit event"
            );
        }
    );

    env_test!(
        usage_alert_sweep_is_grouped_with_identical_behavior,
        |env| {
            // Two tenants with rules (one breaching rule each) prove the
            // grouped evaluation fires the same rows the per-tenant sweep
            // did, including the cooldown that gates the second sweep.
            let tenant_a = "mtcov_galert_a";
            let tenant_b = "mtcov_galert_b";
            for tenant in [tenant_a, tenant_b] {
                seed_tenant(env, tenant, "growth", "active").await;
            }
            sqlx::query(
                "INSERT INTO plans (id, name, display_name, price_cents, email_limit, api_call_limit)
                 VALUES ('plan_galert_a', 'mtcov_galert_plan_a', 'x', 0, 10, 1000),
                        ('plan_galert_b', 'mtcov_galert_plan_b', 'x', 0, 20, 1000)
                 ON CONFLICT (name) DO UPDATE SET email_limit = EXCLUDED.email_limit",
            )
            .execute(&env.pool)
            .await
            .expect("plans");
            sqlx::query("UPDATE tenants SET plan = 'mtcov_galert_plan_a' WHERE id = $1")
                .bind(tenant_a)
                .execute(&env.pool)
                .await
                .expect("plan a");
            sqlx::query("UPDATE tenants SET plan = 'mtcov_galert_plan_b' WHERE id = $1")
                .bind(tenant_b)
                .execute(&env.pool)
                .await
                .expect("plan b");
            // tenant A: one rule, 80% of 10 = 8 used → fires.
            // tenant B: rules at 40% and 80% of 20 = 10 used → only 40 fires.
            sqlx::query(
                "INSERT INTO usage_alert_configs
                     (tenant_id, metric_type, threshold_percent, notification_channel, enabled)
                 VALUES ($1, 'emails', 80, 'email', true),
                        ($2, 'emails', 40, 'email', true),
                        ($2, 'emails', 80, 'email', true)",
            )
            .bind(tenant_a)
            .bind(tenant_b)
            .execute(&env.pool)
            .await
            .expect("alert configs");
            sqlx::query(
                "INSERT INTO metering_events (id, tenant_id, event_type, quantity, timestamp)
                 VALUES (gen_random_uuid(), $1, 'emails_sent', 8, NOW()),
                        (gen_random_uuid(), $2, 'emails_sent', 10, NOW())",
            )
            .bind(tenant_a)
            .bind(tenant_b)
            .execute(&env.pool)
            .await
            .expect("usage");

            // The cooldown keys live in the SHARED test Redis and survive a
            // failed prior run: clear them first.
            {
                let mut conn = env.redis.get().await.expect("redis");
                let _: () = redis::pipe()
                    .del(format!("alert:cooldown:{tenant_a}:emails:80"))
                    .ignore()
                    .del(format!("alert:cooldown:{tenant_b}:emails:40"))
                    .ignore()
                    .del(format!("alert:cooldown:{tenant_b}:emails:80"))
                    .ignore()
                    .query_async(&mut conn)
                    .await
                    .expect("clear stale cooldowns");
            }

            let state = logging_pool_state(env).await;
            let client = Client::new();
            let (capture, capture_guard) = capture_sweep_sql();
            let first = process_usage_alerts(state.as_ref(), &client)
                .await
                .expect("sweep");
            drop(capture_guard);
            capture.print("process_usage_alerts");

            // SET-BASED: one configs fetch, ONE grouped usage aggregate, one
            // plan-limits fetch, one webhook-URL fetch, for BOTH tenants.
            assert_eq!(
                capture.count_starting_with("SELECT tenant_id, id,"),
                1,
                "one configs fetch for all rules: {:?}",
                capture.statements()
            );
            assert_eq!(
                capture.count_starting_with("SELECT DISTINCT tenant_id"),
                0,
                "no separate tenant-list query: {:?}",
                capture.statements()
            );
            assert_eq!(
                capture.count_starting_with("SELECT tenant_id, event_type"),
                1,
                "ONE grouped usage query for all tenants with rules: {:?}",
                capture.statements()
            );
            assert_eq!(
                capture.count_starting_with("SELECT event_type"),
                0,
                "no per-tenant metering SUM may remain: {:?}",
                capture.statements()
            );
            assert_eq!(
                capture.count_starting_with("SELECT t.id AS tenant_id"),
                1,
                "one plan-limits fetch (IN list): {:?}",
                capture.statements()
            );
            assert_eq!(
                capture.count_starting_with("SELECT id, COALESCE(settings"),
                1,
                "one webhook-URL fetch (IN list): {:?}",
                capture.statements()
            );

            // BEHAVIOR PARITY: same fired rules, incidents, queue rows,
            // cooldowns and last_triggered stamps.
            assert_eq!(first.tenants_checked, 2);
            assert_eq!(first.alerts_triggered, 2, "A's 80% and B's 40% fire");
            let queued_a: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM notification_queue WHERE tenant_id = $1 AND type = 'usage_alert'",
            )
            .bind(tenant_a)
            .fetch_one(&env.pool)
            .await
            .expect("queue a");
            assert_eq!(queued_a, 1);
            let queued_b: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM notification_queue WHERE tenant_id = $1 AND type = 'usage_alert'",
            )
            .bind(tenant_b)
            .fetch_one(&env.pool)
            .await
            .expect("queue b");
            assert_eq!(queued_b, 1);
            let incidents: Vec<(Option<String>, String, String)> = sqlx::query_as(
                "SELECT tenant_id, severity, message FROM system_alerts
                 WHERE source = 'usage_alert' ORDER BY fingerprint",
            )
            .fetch_all(&env.pool)
            .await
            .expect("incidents");
            assert_eq!(incidents.len(), 2, "one incident per fired rule");
            let triggered: Vec<(i32,)> = sqlx::query_as(
                "SELECT threshold_percent FROM usage_alert_configs
                 WHERE last_triggered_at IS NOT NULL ORDER BY tenant_id, threshold_percent",
            )
            .fetch_all(&env.pool)
            .await
            .expect("triggered");
            assert_eq!(
                triggered,
                vec![(80,), (40,)],
                "only the fired rules are stamped"
            );
            let mut conn = env.redis.get().await.expect("redis");
            let cooldown_a: bool = conn
                .exists(format!("alert:cooldown:{tenant_a}:emails:80"))
                .await
                .expect("cooldown a");
            assert!(cooldown_a, "the delivered rule enters cooldown");
            let cooldown_b80: bool = conn
                .exists(format!("alert:cooldown:{tenant_b}:emails:80"))
                .await
                .expect("cooldown b80");
            assert!(
                !cooldown_b80,
                "a rule below its threshold never enters cooldown"
            );

            // The second sweep finds every fired rule in cooldown: the
            // per-config cooldown semantics are unchanged.
            let second = process_usage_alerts(&env.state, &client)
                .await
                .expect("second sweep");
            assert_eq!(
                second.alerts_triggered, 0,
                "cooldown suppresses the same rule in the next sweep"
            );
            let queued_after: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM notification_queue WHERE type = 'usage_alert'",
            )
            .fetch_one(&env.pool)
            .await
            .expect("queue total");
            assert_eq!(queued_after, 2, "no additional queue rows");
        }
    );

    // ---------------- KMD backfill ----------------

    #[test]
    fn kmd_backfill_covers_missed_periods_within_the_cap() {
        // Nothing generated: only the target period.
        assert_eq!(kmd_backfill_periods(&[], (2026, 8), 24), vec![(2026, 8)]);
        // Gap: every missing month after the latest generated period.
        assert_eq!(
            kmd_backfill_periods(&[(2026, 5)], (2026, 8), 24),
            vec![(2026, 6), (2026, 7), (2026, 8)]
        );
        // Already at/after the target: nothing to do.
        assert_eq!(
            kmd_backfill_periods(&[(2026, 8)], (2026, 8), 24),
            Vec::<(i32, u32)>::new()
        );
        assert_eq!(
            kmd_backfill_periods(&[(2026, 9)], (2026, 8), 24),
            Vec::<(i32, u32)>::new()
        );
        // The cap protects a fresh deployment from years of empty returns.
        assert_eq!(kmd_backfill_periods(&[(2020, 1)], (2026, 8), 24).len(), 24);
        // Year rollover walks correctly.
        assert_eq!(
            kmd_backfill_periods(&[(2025, 12)], (2026, 2), 24),
            vec![(2026, 1), (2026, 2)]
        );
    }

    env_test!(usage_alert_sweep_cooldown_fires_once, |env| {
        let tenant = "mtcov_alert";
        seed_tenant_plan(env, tenant, "growth", "active").await;
        // Plan with a 10-email limit; usage at 100% of it.
        sqlx::query(
            "INSERT INTO plans (id, name, display_name, price_cents, email_limit, api_call_limit)
             VALUES ('plan_mtcov_alert', 'mtcov_alert_plan', 'x', 0, 10, 10)
             ON CONFLICT (name) DO UPDATE SET email_limit = EXCLUDED.email_limit",
        )
        .execute(&env.pool)
        .await
        .expect("plan");
        sqlx::query("UPDATE tenants SET plan = 'mtcov_alert_plan' WHERE id = $1")
            .bind(tenant)
            .execute(&env.pool)
            .await
            .expect("plan");
        sqlx::query(
            "INSERT INTO usage_alert_configs
                 (tenant_id, metric_type, threshold_percent, notification_channel, enabled)
             VALUES ($1, 'emails', 80, 'email', true)",
        )
        .bind(tenant)
        .execute(&env.pool)
        .await
        .expect("alert config");
        for _ in 0..10 {
            record_usage(
                &env.pool,
                &env.redis,
                tenant,
                MeterEventType::EmailsSent,
                1,
                None,
                None,
            )
            .await
            .expect("usage");
        }

        // The cooldown key lives in the SHARED test Redis and survives a
        // failed prior run (its TTL outlives the test): clear it so the
        // first sweep is judged on this run's data alone. The cooldown's
        // once-per-window behaviour is asserted by the SECOND sweep below.
        {
            let mut conn = env.redis.get().await.expect("redis");
            let _: () = redis::cmd("DEL")
                .arg("alert:cooldown:mtcov_alert:emails:80")
                .query_async(&mut conn)
                .await
                .expect("clear stale cooldown");
        }
        let client = Client::new();
        let first = process_usage_alerts(&env.state, &client)
            .await
            .expect("sweep");
        assert_eq!(first.tenants_checked, 1);
        assert_eq!(first.alerts_triggered, 1, "the threshold fires");
        let queued: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM notification_queue WHERE tenant_id = $1 AND type = 'usage_alert'",
        )
        .bind(tenant)
        .fetch_one(&env.pool)
        .await
        .expect("queue");
        assert_eq!(queued, 1);

        // The cooldown suppresses a second alert within the hour.
        let second = process_usage_alerts(&env.state, &client)
            .await
            .expect("sweep");
        assert_eq!(
            second.alerts_triggered, 0,
            "the cooldown fires at most once per period"
        );
        let queued: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM notification_queue WHERE tenant_id = $1 AND type = 'usage_alert'",
        )
        .bind(tenant)
        .fetch_one(&env.pool)
        .await
        .expect("queue");
        assert_eq!(queued, 1, "no duplicate notification");
    });

    env_test!(metering_drain_recovers_pending_events_exactly_once, |env| {
        let _metering_guard = metering_keys_guard(&env.admin_url).await;
        crate::test_support::clear_pending_metering_keys(&env.redis).await;
        let tenant = "mtcov_drain";
        seed_tenant_plan(env, tenant, "growth", "active").await;
        let raw_id = "evt_mtcov_drain_0001";
        let event_id = normalize_metering_event_id(raw_id);
        // The pending-event wire format is camelCase (PendingMeterEvent's
        // rename_all): snake_case fields deserialize as missing and the
        // event is discarded as malformed.
        let payload = serde_json::json!({
            "id": raw_id,
            "tenantId": tenant,
            "eventType": "email_sent",
            "quantity": 3,
            "timestamp": Utc::now().to_rfc3339(),
            "metadata": {},
        });
        let mut conn = env.redis.get().await.expect("redis");
        let _: () = redis::cmd("SET")
            .arg(format!("meter:pending:{raw_id}"))
            .arg(payload.to_string())
            .query_async(&mut conn)
            .await
            .expect("pending event");
        // A corrupt sibling is discarded, not recovered.
        let _: () = redis::cmd("SET")
            .arg("meter:pending:evt_mtcov_corrupt")
            .arg("not json")
            .query_async(&mut conn)
            .await
            .expect("corrupt pending");
        drop(conn);

        let result = drain_pending_metering_events(&env.state, 100)
            .await
            .expect("drain");
        assert_eq!(result.processed_count, 1);
        assert_eq!(result.discarded_count, 1);
        let stored: i64 = sqlx::query_scalar("SELECT quantity FROM metering_events WHERE id = $1")
            .bind(event_id)
            .fetch_one(&env.pool)
            .await
            .expect("event");
        assert_eq!(stored, 3);
        // Recovered events are audited into the CANONICAL compliance
        // audit_logs table (insert_audit_log), not a billing-local log.
        let audit: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM audit_logs WHERE action = 'billing.metering_event_recovered'",
        )
        .fetch_one(&env.pool)
        .await
        .expect("audit");
        assert_eq!(audit, 1, "the recovery is audited");
        let keys_left: i64 = redis::cmd("KEYS")
            .arg("meter:pending:evt_mtcov_*")
            .query_async::<Vec<String>>(&mut env.redis.get().await.expect("redis"))
            .await
            .map(|keys| keys.len() as i64)
            .expect("keys");
        assert_eq!(keys_left, 0, "both pending keys are cleaned up");

        // Replay: the DB conflict makes the counter guard a no-op, the event
        // is never double-counted.
        let mut conn = env.redis.get().await.expect("redis");
        let _: () = redis::cmd("SET")
            .arg(format!("meter:pending:{raw_id}"))
            .arg(payload.to_string())
            .query_async(&mut conn)
            .await
            .expect("re-queue");
        drop(conn);
        let result = drain_pending_metering_events(&env.state, 100)
            .await
            .expect("drain");
        assert_eq!(
            result.processed_count, 0,
            "a recovered event never re-inserts"
        );
        let rows: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM metering_events WHERE id = $1")
            .bind(event_id)
            .fetch_one(&env.pool)
            .await
            .expect("count");
        assert_eq!(rows, 1);
    });

    // ── spawned periodic-loop bodies driven at real short intervals ────
    //
    // start_periodic_jobs spawns one interval loop per task. The production
    // cadences (minutes..hours) are overridden through
    // PERIODIC_TASK_INTERVAL_MS, so every spawned loop really ticks, and
    // really runs its task bodies, against a private database clone within
    // milliseconds, no virtual clock and no long sleeps.

    #[tokio::test(flavor = "current_thread")]
    async fn periodic_job_loops_run_every_task_at_overridden_intervals() {
        let Some(owned) = provision("periodic_ok_intervals").await else {
            eprintln!("skipping: TEST_DATABASE_URL unset");
            return;
        };
        std::env::set_var("PERIODIC_TASK_INTERVAL_MS", "15");
        start_periodic_jobs(owned.state.clone());

        // Let every loop tick several times at the 15 ms cadence.
        for _ in 0..8 {
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        std::env::remove_var("PERIODIC_TASK_INTERVAL_MS");

        // The runtime survived every task body.
        let ready: i32 = sqlx::query_scalar("SELECT 1")
            .fetch_one(&owned.pool)
            .await
            .expect("database still reachable");
        assert_eq!(ready, 1);

        // Stop before the private clone is dropped (the loops keep
        // erroring harmlessly in the background until the runtime drops).
        owned.finish().await;
    }

    #[tokio::test(flavor = "current_thread")]
    async fn periodic_job_loops_report_errors_when_the_database_is_gone() {
        let state = crate::test_support::state_with_broken_db();
        std::env::set_var("PERIODIC_TASK_INTERVAL_MS", "15");
        start_periodic_jobs(state);
        for _ in 0..8 {
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        std::env::remove_var("PERIODIC_TASK_INTERVAL_MS");
    }

    // ── W6C adversarial coverage: loop-tick RESULT arms + fault arms ────
    //
    // The pre-existing tick test proves the loops RUN at overridden
    // intervals; the arms that fire only when a tick actually PRODUCES
    // work (charged>0, released>0, resumed>0, reclaimed>0, reports>0, …)
    // stayed cold. This driver seeds real work for every loop so each
    // result arm is reachable, and asserts the observable DB effects.

    #[tokio::test(flavor = "current_thread")]
    async fn periodic_job_tick_loops_produce_real_results() {
        let Some(owned) = provision("periodic_tick_results").await else {
            eprintln!("skipping: TEST_DATABASE_URL unset");
            return;
        };
        let _metering_guard = metering_keys_guard(&owned.admin_url).await;
        crate::test_support::ensure_trace_subscriber();

        let mock = Mock::default();
        // Dedicated-IP activation: ONE recurring `POST /v2/payments` per
        // add-on against the tenant's stored mandate.
        // {seq} makes each POST return a DISTINCT payment id (a real provider
        // never answers two payments with one id, and the attempts ledger's
        // unique (provider, provider_payment_id) key enforces exactly that).
        mock.route(
            "/v2/payments",
            200,
            r#"{"id":"tr_w6c_drv_{seq}","status":"paid"}"#,
        );
        let base = spawn_mock(mock.clone()).await;

        let _env_guard = ENV_LOCK.lock().await;
        let previous_env = (
            std::env::var("PERIODIC_TASK_INTERVAL_MS").ok(),
            std::env::var("DEDICATED_IP_PRICE_CENTS").ok(),
            std::env::var("MOLLIE_API_KEY").ok(),
            std::env::var("MOLLIE_API_BASE_URL").ok(),
            std::env::var("MOLLIE_PROFILE_ID").ok(),
            std::env::var("AUTO_PAY_OPEN_INVOICES").ok(),
        );
        std::env::set_var("PERIODIC_TASK_INTERVAL_MS", "10");
        // Cents, not a provider price id.
        std::env::set_var("DEDICATED_IP_PRICE_CENTS", "500");
        std::env::set_var("MOLLIE_API_KEY", "mollie-test-key-fixture");
        std::env::set_var("MOLLIE_API_BASE_URL", format!("{base}/v2"));
        std::env::set_var("MOLLIE_PROFILE_ID", "ApexMailTestECOM");
        std::env::set_var("AUTO_PAY_OPEN_INVOICES", "true");

        let env = &owned;

        // ── dedicated IP: two pending charges (one for the startup sweep,
        // one for a tick) on a tenant with an ACTIVE subscription carrying
        // the stored recurring token the charge replays.
        seed_tenant_plan(env, "w6cdrv_ip", "growth", "active").await;
        sqlx::query(
            "INSERT INTO mollie_subscriptions
                 (tenant_id, mollie_subscription_id, plan, status, billing_cycle_start,
                  billing_cycle_end, mollie_customer_id,
                  mollie_mandate_id)
             VALUES ('w6cdrv_ip', 'psp_w6cdrv_ip', 'growth', 'active', NOW(),
                     NOW() + INTERVAL '30 days', 'w6cdrv_ip', 'tok_w6cdrv')",
        )
        .execute(&env.pool)
        .await
        .expect("ip subscription");
        for suffix in ["a", "b"] {
            sqlx::query(
                "INSERT INTO dedicated_ips (id, tenant_id, ip_address, billing_status)
                 VALUES ($1, 'w6cdrv_ip', $2, 'pending_charge')",
            )
            .bind(format!("w6cdrv-ip-{suffix}"))
            .bind(format!("192.0.2.{suffix}"))
            .execute(&env.pool)
            .await
            .expect("pending charge ip");
        }

        // ── usage alerts: one enabled config makes tenants_checked > 0.
        seed_tenant_plan(env, "w6cdrv_alert", "growth", "active").await;
        sqlx::query(
            "INSERT INTO usage_alert_configs (tenant_id, metric_type, threshold_percent,
                                              notification_channel, enabled)
             VALUES ('w6cdrv_alert', 'emails', 50, 'email', true)",
        )
        .execute(&env.pool)
        .await
        .expect("alert config");

        // ── dunning grace expiry: a hard-suspended tenant past its grace
        // window with queued messages to purge.
        seed_tenant_plan(env, "w6cdrv_grace", "growth", "suspended").await;
        seed_dunning(
            env,
            "w6cdrv_grace",
            "hard_suspended",
            Some(Utc::now() - chrono::Duration::hours(2)),
        )
        .await;
        sqlx::query(
            r#"INSERT INTO messages (id, tenant_id, to_addresses, status, from_email, to_emails,
                                   open_count, click_count, unsubscribe_count, message_category,
                                   created_at, updated_at)
             VALUES (gen_random_uuid(), 'w6cdrv_grace', ARRAY['victim@example.test'],
                     'dunning_queued', 'no-reply@apexmail.test', '["victim@example.test"]'::jsonb,
                     0, 0, 0, 'transactional', NOW(), NOW())"#,
        )
        .execute(&env.pool)
        .await
        .expect("queued message");

        // ── scheduled auto-pay: warning dunning due NOW on a past_due
        // subscription; NO open local invoice exists, so the sweep clears
        // the retry without ever calling the provider.
        seed_tenant_plan(env, "w6cdrv_pay", "growth", "active").await;
        sqlx::query(
            "INSERT INTO mollie_subscriptions
                 (tenant_id, mollie_subscription_id, plan, status, billing_cycle_start,
                  billing_cycle_end, mollie_customer_id)
             VALUES ('w6cdrv_pay', 'psp_w6cdrv_pay', 'growth', 'past_due', NOW(),
                     NOW() + INTERVAL '30 days', 'w6cdrv_pay')",
        )
        .execute(&env.pool)
        .await
        .expect("past due subscription");
        seed_dunning(env, "w6cdrv_pay", "warning", None).await;
        sqlx::query(
            "UPDATE dunning_records SET next_retry_at = NOW() - INTERVAL '1 minute'
             WHERE tenant_id = 'w6cdrv_pay'",
        )
        .execute(&env.pool)
        .await
        .expect("due retry");

        // ── stranded collection resume: a wallet fully covers a draft
        // usage invoice, so the resumed ladder settles it.
        seed_tenant_plan(env, "w6cdrv_resume", "growth", "active").await;
        sqlx::query("INSERT INTO wallets (tenant_id, balance, currency) VALUES ('w6cdrv_resume', 10000, 'EUR')")
            .execute(&env.pool)
            .await
            .expect("resume wallet");
        let resume_invoice = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO invoices (id, tenant_id, amount, currency, status, invoice_number,
                                   subtotal, vat_total, total, issued_at, due_at,
                                   period_start, period_end, created_at, updated_at)
             VALUES ($1, 'w6cdrv_resume', 5000, 'EUR', 'draft', $2, 5000, 0, 5000,
                     NOW(), NOW(), NOW() - INTERVAL '35 days', NOW() - INTERVAL '5 days',
                     NOW(), NOW())",
        )
        .bind(resume_invoice)
        .bind(format!("W6CDRV-{}", resume_invoice.simple()))
        .execute(&env.pool)
        .await
        .expect("resume invoice");
        sqlx::query(
            "INSERT INTO invoice_collection_outbox
                 (tenant_id, invoice_id, operation, status, payload)
             VALUES ('w6cdrv_resume', $1, 'collect_usage_invoice', 'pending', '{}'::jsonb)",
        )
        .bind(resume_invoice)
        .execute(&env.pool)
        .await
        .expect("resume outbox");

        // ── derived usage: a delivered email yesterday plus a
        // reserved-vs-delivered gap to reconcile.
        seed_tenant_plan(env, "w6cdrv_derived", "growth", "active").await;
        sqlx::query(
            "INSERT INTO email_queue (id, tenant_id, from_address, to_addresses, subject, status,
                                      attempts, max_attempts, created_at, updated_at, priority,
                                      attempt, message_category, sent_at)
             VALUES (gen_random_uuid(), 'w6cdrv_derived', 'no-reply@apexmail.test',
                     ARRAY['buyer@example.test'], 'w6c derived', 'sent', 1, 3,
                     NOW() - INTERVAL '2 days', NOW() - INTERVAL '1 day', 5, 1, 'transactional',
                     NOW() - INTERVAL '1 day')",
        )
        .execute(&env.pool)
        .await
        .expect("sent email");
        for (event_type, quantity) in [("emails_sent", 10), ("emails_delivered", 4)] {
            sqlx::query(
                "INSERT INTO metering_events (id, tenant_id, event_type, quantity, timestamp)
                 VALUES (gen_random_uuid(), 'w6cdrv_derived', $1, $2,
                         NOW() - INTERVAL '1 day')",
            )
            .bind(event_type)
            .bind(quantity)
            .execute(&env.pool)
            .await
            .expect("metering gap");
        }

        // ── webhook reclaim: one stale pending webhook for the STARTUP
        // sweep; a second is inserted after startup ran so a TICK reclaims
        // it (the tick arm cannot be reached by pre-seeded rows alone).
        for event in ["evt_w6cdrv_startup", "evt_w6cdrv_tick"] {
            sqlx::query(
                "INSERT INTO mollie_webhook_events (id, mollie_event_id, event_type, status,
                                                    updated_at)
                 VALUES (gen_random_uuid(), $1, 'invoice.paid', 'pending',
                         NOW() - INTERVAL '1 hour')",
            )
            .bind(event)
            .execute(&env.pool)
            .await
            .expect("stale webhook");
        }

        start_periodic_jobs(owned.state.clone());
        // Let the startup sweeps finish before adding tick-only work: the
        // startup sweeps consume everything seeded above, so the TICK arms
        // of the loops only fire for work that appears afterwards.
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        sqlx::query(
            "INSERT INTO mollie_webhook_events (id, mollie_event_id, event_type, status,
                                                updated_at)
             VALUES (gen_random_uuid(), 'evt_w6cdrv_tick2', 'invoice.paid', 'pending',
                     NOW() - INTERVAL '1 hour')",
        )
        .execute(&env.pool)
        .await
        .expect("tick-only stale webhook");
        sqlx::query(
            "INSERT INTO dedicated_ips (id, tenant_id, ip_address, billing_status)
             VALUES ('w6cdrv-ip-c', 'w6cdrv_ip', '192.0.2.3', 'pending_charge')",
        )
        .execute(&env.pool)
        .await
        .expect("tick-only pending charge");

        // All loops poll on 10 ms cadences; give the assertions a bounded
        // deadline instead of fixed sleeps. Each poll loop below fails the
        // test when its deadline passes without the loop's effect landing —
        // a silent loop is a broken loop.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
        macro_rules! poll_until {
            ($deadline:expr, $query:expr, $ready:expr, $what:literal) => {{
                let mut satisfied = false;
                while std::time::Instant::now() < $deadline {
                    let row = sqlx::query_scalar::<_, i64>($query)
                        .fetch_one(&env.pool)
                        .await
                        .expect("poll probe");
                    if $ready(row) {
                        satisfied = true;
                        break;
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                }
                assert!(
                    satisfied,
                    "periodic loop never produced its effect: {}",
                    $what
                );
            }};
        }

        // Dedicated IPs: ALL pending charges were charged to active —
        // one charged by the startup sweep, the rest by ticks.
        poll_until!(
            deadline,
            "SELECT COUNT(*) FROM dedicated_ips
             WHERE id IN ('w6cdrv-ip-a', 'w6cdrv-ip-b', 'w6cdrv-ip-c')
               AND billing_status = 'active'",
            |count| count == 3,
            "all dedicated IPs charged (startup + tick)"
        );

        // Dunning grace: queued messages purged and the grace window cleared.
        poll_until!(
            deadline,
            "SELECT (SELECT COUNT(*) FROM messages
                      WHERE tenant_id = 'w6cdrv_grace' AND status = 'dunning_queued')
                   + (SELECT COUNT(*) FROM dunning_records
                      WHERE tenant_id = 'w6cdrv_grace' AND grace_period_ends_at IS NOT NULL)",
            |count| count == 0,
            "grace expiry purged messages and cleared the window"
        );
        let notified: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM notification_queue
             WHERE tenant_id = 'w6cdrv_grace' AND type = 'messages_purged'",
        )
        .fetch_one(&env.pool)
        .await
        .expect("notification");
        assert_eq!(notified, 1, "exactly one purge notification was queued");

        // Scheduled auto-pay: the due retry found no open LOCAL invoice and
        // cleared the next retry, never rescheduled blindly.
        poll_until!(
            deadline,
            "SELECT COUNT(*) FROM dunning_records
             WHERE tenant_id = 'w6cdrv_pay' AND next_retry_at IS NULL",
            |count| count == 1,
            "auto-pay cleared the retry after finding no open invoice"
        );

        // Resume ladder: the stranded usage invoice was settled exactly once.
        poll_until!(
            deadline,
            "SELECT COUNT(*) FROM invoices i
             JOIN invoice_collection_outbox o ON o.invoice_id = i.id
             WHERE i.tenant_id = 'w6cdrv_resume' AND i.status = 'paid' AND o.status = 'done'",
            |count| count == 1,
            "stranded usage invoice resumed to paid"
        );
        let (balance, debits, allocations): (i64, i64, i64) = sqlx::query_as(
            "SELECT (SELECT balance FROM wallets WHERE tenant_id = 'w6cdrv_resume'),
                    (SELECT COUNT(*) FROM wallet_transactions
                     WHERE tenant_id = 'w6cdrv_resume' AND type = 'debit'),
                    (SELECT COUNT(*) FROM invoice_payment_allocations WHERE invoice_id = $1)",
        )
        .bind(resume_invoice)
        .fetch_one(&env.pool)
        .await
        .expect("resume settlement detail");
        assert_eq!((balance, debits, allocations), (5000, 1, 1));

        // Webhook reclaim: the startup row AND the tick-only row were both
        // reclaimed to 'received'.
        poll_until!(
            deadline,
            "SELECT COUNT(*) FROM mollie_webhook_events
             WHERE mollie_event_id IN ('evt_w6cdrv_startup', 'evt_w6cdrv_tick', 'evt_w6cdrv_tick2')
               AND status = 'received'",
            |count| count == 3,
            "all stale webhooks reclaimed (startup + tick)"
        );

        // Derived usage: yesterday's delivered email recorded a marker, and
        // the reserved-vs-delivered gap produced a reconciliation report.
        poll_until!(
            deadline,
            "SELECT COUNT(*) FROM metering_daily_markers",
            |count| count >= 1,
            "derived usage marker recorded"
        );
        poll_until!(
            deadline,
            "SELECT COUNT(*) FROM billing_reconciliation_reports",
            |count| count >= 1,
            "delivery reconciliation report written"
        );

        // KMD: the loop generates the previous month's VAT return only ON OR
        // AFTER the 20th (the real-time gate in `generate_kmd_if_due`), so
        // the expectation follows the same calendar, generated past the
        // due day, deliberately absent before it. (A fixed "one row must
        // appear" assertion silently failed on the 1st–19th of every month.)
        let kmd_due = Utc::now().day() >= 20;
        poll_until!(
            deadline,
            "SELECT COUNT(*) FROM vat_kmd_returns",
            |count| if kmd_due { count >= 1 } else { count == 0 },
            "KMD VAT return honours the 20th-of-the-month due gate"
        );

        // The loops keep running on the runtime until it drops; restore the
        // process-global environment before other work observes it.
        let (interval, price, secret, api_base, merchant, auto_pay) = previous_env;
        match interval {
            Some(value) => std::env::set_var("PERIODIC_TASK_INTERVAL_MS", value),
            None => std::env::remove_var("PERIODIC_TASK_INTERVAL_MS"),
        }
        match price {
            Some(value) => std::env::set_var("DEDICATED_IP_PRICE_CENTS", value),
            None => std::env::remove_var("DEDICATED_IP_PRICE_CENTS"),
        }
        match secret {
            Some(value) => std::env::set_var("MOLLIE_API_KEY", value),
            None => std::env::remove_var("MOLLIE_API_KEY"),
        }
        match api_base {
            Some(value) => std::env::set_var("MOLLIE_API_BASE_URL", value),
            None => std::env::remove_var("MOLLIE_API_BASE_URL"),
        }
        match merchant {
            Some(value) => std::env::set_var("MOLLIE_PROFILE_ID", value),
            None => std::env::remove_var("MOLLIE_PROFILE_ID"),
        }
        match auto_pay {
            Some(value) => std::env::set_var("AUTO_PAY_OPEN_INVOICES", value),
            None => std::env::remove_var("AUTO_PAY_OPEN_INVOICES"),
        }
        drop(_env_guard);

        owned.finish().await;
    }
    // ── metering drain fault arms ───────────────────────────────────────

    env_test!(metering_drain_discards_malformed_and_fails_loudly, |env| {
        let _drain_guard = METER_DRAIN_LOCK.lock().await;
        let _metering_guard = metering_keys_guard(&env.admin_url).await;
        crate::test_support::clear_pending_metering_keys(&env.redis).await;

        // This test owns the `w6c-` prefix inside the pending keyspace:
        // clear leftovers from previous runs first (the drain consumes the
        // whole namespace it can see).
        {
            let mut conn = env.redis.get().await.expect("redis");
            let stale: Vec<String> = redis::cmd("KEYS")
                .arg("meter:pending:w6c-*")
                .query_async(&mut conn)
                .await
                .expect("scan stale");
            if !stale.is_empty() {
                let _: () = redis::cmd("DEL")
                    .arg(&stale)
                    .query_async(&mut conn)
                    .await
                    .expect("clear stale");
            }
        }

        let mut conn = env.redis.get().await.expect("redis");
        // Two malformed payloads: the drain discards them WITHOUT touching
        // the database and reports the count.
        for raw in ["w6c-bad-1", "w6c-bad-2"] {
            let _: () = redis::cmd("SET")
                .arg(format!("meter:pending:{raw}"))
                .arg("this is not json")
                .query_async(&mut conn)
                .await
                .expect("seed malformed");
        }
        drop(conn);
        let result = drain_pending_metering_events(&env.state, 100)
            .await
            .expect("malformed payloads are not an error");
        assert_eq!(
            (result.processed_count, result.discarded_count),
            (0, 2),
            "both malformed payloads discarded"
        );
        let mut conn = env.redis.get().await.expect("redis");
        let left: Vec<String> = redis::cmd("KEYS")
            .arg("meter:pending:w6c-bad-*")
            .query_async(&mut conn)
            .await
            .expect("keys");
        assert!(left.is_empty(), "discarded keys are cleaned up");

        // A COUNTER key of the WRONG Redis type makes INCRBY raise
        // WRONGTYPE: the counter script fails and the drain must surface the
        // error LOUDLY. (A wrong-type GUARD key would NOT fail: SET NX on an
        // existing wrong-type key degrades to a nil reply inside Lua.) The
        // DB insert commits first, so the event is persisted exactly once
        // and the pending key survives for the next attempt.
        let raw_id = "w6c-wrongtype-1";
        let event_at = Utc::now();
        let counter_key = crate::usage::enforced_counter_key_for_event_type(
            &env.pool,
            "w6cdrv_wrongtype",
            "emails_sent",
            event_at,
        )
        .await;
        let payload = serde_json::json!({
            "id": raw_id,
            "tenantId": "w6cdrv_wrongtype",
            "eventType": "emails_sent",
            "quantity": 3,
            "timestamp": event_at.to_rfc3339(),
            "metadata": {},
        });
        seed_tenant_plan(env, "w6cdrv_wrongtype", "growth", "active").await;
        // Deterministic Redis state: a previous run's guard key (40-day TTL)
        // would make SET NX silently skip the increment instead of tripping
        // the wrong-type error.
        let guard_key = format!("meter:guard:{}", normalize_metering_event_id(raw_id));
        let _: () = redis::cmd("DEL")
            .arg(&guard_key)
            .arg(&counter_key)
            .arg(format!("meter:pending:{raw_id}"))
            .query_async(&mut conn)
            .await
            .expect("clear prior keys");
        let _: () = redis::cmd("RPUSH")
            .arg(&counter_key)
            .arg("not-a-scalar")
            .query_async(&mut conn)
            .await
            .expect("wrongtype counter");
        let _: () = redis::cmd("SET")
            .arg(format!("meter:pending:{raw_id}"))
            .arg(payload.to_string())
            .query_async(&mut conn)
            .await
            .expect("seed event");
        drop(conn);
        let error = drain_pending_metering_events(&env.state, 100)
            .await
            .expect_err("a WRONGTYPE counter key must fail the drain");
        assert!(
            error.contains("drain+incr"),
            "the failure names the counter step: {error}"
        );
        let persisted: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM metering_events WHERE tenant_id = 'w6cdrv_wrongtype'",
        )
        .fetch_one(&env.pool)
        .await
        .expect("events");
        assert_eq!(
            persisted, 1,
            "the DB insert committed before the script ran"
        );
        let mut conn = env.redis.get().await.expect("redis");
        let counter_kind: String = redis::cmd("TYPE")
            .arg(&counter_key)
            .query_async(&mut conn)
            .await
            .expect("counter type");
        assert_eq!(
            counter_kind, "list",
            "the counter was never INCRBY'd through the wrong type"
        );
        let pending_left: bool = conn
            .exists(format!("meter:pending:{raw_id}"))
            .await
            .expect("pending key");
        assert!(
            pending_left,
            "the script aborted before DEL: the pending key survives for the next retry"
        );
    });

    env_test!(
        delete_redis_keys_with_an_empty_list_is_a_clean_noop,
        |env| {
            let mut conn = env.redis.get().await.expect("redis");
            delete_redis_keys(&mut conn, &[])
                .await
                .expect("empty key list is a no-op");
        }
    );

    // ── SLA credit edges ────────────────────────────────────────────────

    env_test!(sla_credit_edges_are_explicit_and_capped, |env| {
        let this_month = month_start(Utc::now());
        let last_month = month_start(this_month - chrono::Days::new(1));
        let mid_last_month = last_month + chrono::Duration::days(10);

        // (tenant/plan, uptime % as exact decimal text, plan features) —
        // uptime stays in EXACT decimal text end-to-end (numeric column, no
        // binary floating point anywhere near the money computation).
        let cases: [(&str, &str, Value); 6] = [
            ("w6csla_noflag", "90.0", serde_json::json!({})),
            (
                "w6csla_good",
                "99.95",
                serde_json::json!({"slaGuarantee": true}),
            ),
            (
                "w6csla_tiny",
                "99.85",
                serde_json::json!({"slaGuarantee": true}),
            ),
            (
                "w6csla_capped",
                "95.0",
                serde_json::json!({"slaGuarantee": true, "slaCreditPercentage": 10}),
            ),
            (
                "w6csla_noinv",
                "90.0",
                serde_json::json!({"slaGuarantee": true}),
            ),
            (
                "w6csla_already",
                "90.0",
                serde_json::json!({"slaGuarantee": true}),
            ),
        ];
        for (tenant, uptime, features) in &cases {
            seed_plan(env, tenant, 1000, features.clone()).await;
            seed_tenant_plan(env, tenant, tenant, "active").await;
            sqlx::query(
                "INSERT INTO sla_metrics (tenant_id, period_month, uptime_percent)
                 VALUES ($1, $2, $3::numeric)",
            )
            .bind(tenant)
            .bind(last_month)
            .bind(uptime)
            .execute(&env.pool)
            .await
            .expect("sla metric");
        }

        // Paid invoices inside the credited period. The capped tenant holds
        // an older EUR invoice and a LATER USD one: the credit follows the
        // LATEST invoice's currency and sums only that currency.
        for (tenant, currency, total, created_at) in [
            ("w6csla_capped", "EUR", 10_000_i64, mid_last_month),
            (
                "w6csla_capped",
                "USD",
                400_000_i64,
                mid_last_month + chrono::Duration::days(5),
            ),
            ("w6csla_already", "EUR", 10_000_i64, mid_last_month),
        ] {
            let id = Uuid::new_v4();
            sqlx::query(
                "INSERT INTO invoices (id, tenant_id, amount, currency, status, invoice_number,
                                       subtotal, vat_total, total, issued_at, paid_at, due_at,
                                       period_start, period_end, created_at, updated_at)
                 VALUES ($1, $2, $3, $4, 'paid', $5, $3, 0, $3, $6, $6, $6, $7, $8, $9, $9)",
            )
            .bind(id)
            .bind(tenant)
            .bind(total)
            .bind(currency)
            .bind(format!("W6CSLA-{}", id.simple()))
            .bind(mid_last_month)
            .bind(last_month)
            .bind(this_month)
            .bind(created_at)
            .execute(&env.pool)
            .await
            .expect("paid invoice");
        }

        // The already-credited tenant keeps its existing credit: no second
        // row even though the breach qualifies again.
        sqlx::query(
            "INSERT INTO sla_credits (id, tenant_id, period_month, breach_percent,
                                      credit_percent, credit_amount, currency, status)
             VALUES (gen_random_uuid(), 'w6csla_already', $1, 9.9, 100, 10000, 'EUR', 'pending')",
        )
        .bind(last_month)
        .execute(&env.pool)
        .await
        .expect("pre-existing credit");

        let result = process_monthly_sla_credits(&env.state)
            .await
            .expect("sla sweep");
        assert_eq!(result.tenants_checked, 6, "{result:?}");
        assert_eq!(
            result.credits_created, 1,
            "only the capped tenant qualifies: {result:?}"
        );

        let credit: (i32, String, i32) = sqlx::query_as(
            "SELECT credit_amount::int, currency, credit_percent::int FROM sla_credits
             WHERE tenant_id = 'w6csla_capped'",
        )
        .fetch_one(&env.pool)
        .await
        .expect("capped credit");
        // Breach 4.9 % → 50 % credit; the plan cap of 10 % of the USD total
        // (40 000 c) wins over 50 % (200 000 c).
        assert_eq!(credit, (40_000, "USD".to_string(), 50));

        let total_rows: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM sla_credits")
            .fetch_one(&env.pool)
            .await
            .expect("rows");
        assert_eq!(total_rows, 2, "no double credit, no credit for the others");

        // Replaying the sweep is a no-op (per-period lock + re-check).
        let replay = process_monthly_sla_credits(&env.state)
            .await
            .expect("sla replay");
        assert_eq!(replay.credits_created, 0);
    });

    // ── dedicated-IP cancel fault arms ──────────────────────────────────

    env_test!(dedicated_ip_cancel_is_local_and_never_calls_mollie, |env| {
        let mock = Mock::default();
        let base = spawn_mock(mock.clone()).await;

        let guard = ENV_LOCK.lock().await;
        let previous = (
            std::env::var("MOLLIE_API_KEY").ok(),
            std::env::var("MOLLIE_API_BASE_URL").ok(),
            std::env::var("DEDICATED_IP_PRICE_CENTS").ok(),
        );
        std::env::set_var("MOLLIE_API_KEY", "mollie-test-key-fixture");
        std::env::set_var("MOLLIE_API_BASE_URL", format!("{base}/v2"));
        std::env::set_var("DEDICATED_IP_PRICE_CENTS", "500");

        // Under Mollie there is no provider-side subscription-item object to
        // delete and no automatic future add-on charges: ending the add-on
        // is a LOCAL transition for every row, stale stored references
        // included (they are activation payment ids now, not deletable
        // items). The old two-step failure matrix (500 rolls back, 404
        // succeeds) pinned a pre-cutover mechanic with no Mollie analog.
        seed_tenant_plan(env, "w6cdip_cancel", "growth", "active").await;
        sqlx::query(
            "INSERT INTO dedicated_ips (id, tenant_id, ip_address, status, billing_status,
                                        mollie_mandate_id)
             VALUES ('w6cdip-dead', 'w6cdip_cancel', '192.0.2.51', 'active', 'pending_cancel', 'psp_dead'),
                    ('w6cdip-gone', 'w6cdip_cancel', '192.0.2.52', 'active', 'pending_cancel', 'psp_gone')",
        )
        .execute(&env.pool)
        .await
        .expect("pending cancels");

        let client = Client::new();
        let canceled = process_pending_dedicated_ip_cancels(&env.state, &client)
            .await
            .expect("cancel sweep");
        assert_eq!(canceled, 2, "every pending cancel finalizes locally");
        let statuses: Vec<(String, String)> = sqlx::query_as(
            "SELECT id, billing_status FROM dedicated_ips WHERE id LIKE 'w6cdip-%' ORDER BY id",
        )
        .fetch_all(&env.pool)
        .await
        .expect("statuses");
        assert_eq!(
            statuses,
            vec![
                ("w6cdip-dead".to_string(), "canceled".to_string()),
                ("w6cdip-gone".to_string(), "canceled".to_string()),
            ],
            "no provider call exists to succeed or fail: both rows finalize"
        );
        assert_eq!(
            mock.call_count("/v2/payments"),
            0,
            "cancelling an add-on never moves money"
        );

        match previous {
            (Some(a), Some(b), Some(c)) => {
                std::env::set_var("MOLLIE_API_KEY", a);
                std::env::set_var("MOLLIE_API_BASE_URL", b);
                std::env::set_var("DEDICATED_IP_PRICE_CENTS", c);
            }
            _ => {
                std::env::remove_var("MOLLIE_API_KEY");
                std::env::remove_var("MOLLIE_API_BASE_URL");
                std::env::remove_var("DEDICATED_IP_PRICE_CENTS");
            }
        }
        drop(guard);
    });

    // ── cost margin status arms ─────────────────────────────────────────

    env_test!(cost_margin_status_arms_alert_dedup_and_throttle, |env| {
        let tenant_zero = "w6cm_zero";
        let tenant_warn = "w6cm_warn";
        let tenant_crit = "w6cm_crit";
        let tenant_ok = "w6cm_ok";
        for tenant in [tenant_zero, tenant_warn, tenant_crit, tenant_ok] {
            seed_tenant_plan(env, tenant, "growth", "active").await;
        }
        let recorded = month_start(Utc::now()).date_naive();
        for (tenant, total, revenue) in [
            (tenant_warn, 850_i64, 1_000_i64),
            (tenant_crit, 500_i64, 100_i64),
            (tenant_ok, 100_i64, 1_000_i64),
        ] {
            sqlx::query(
                "INSERT INTO tenant_costs (tenant_id, recorded_at, total_cost, revenue)
                 VALUES ($1, $2, $3, $4)",
            )
            .bind(tenant)
            .bind(recorded)
            .bind(total)
            .bind(revenue)
            .execute(&env.pool)
            .await
            .expect("tenant costs");
        }

        // Zero activity: healthy, nothing alert-worthy.
        assert!(matches!(
            check_tenant_cost_margin(&env.state, tenant_zero).await,
            Ok(CostMarginStatus::Healthy)
        ));
        // 5 % margin: warning, alert raised, throttle NOT applied.
        assert!(matches!(
            check_tenant_cost_margin(&env.state, tenant_warn).await,
            Ok(CostMarginStatus::Warning)
        ));
        // Negative margin: critical, alert raised AND throttle applied.
        assert!(matches!(
            check_tenant_cost_margin(&env.state, tenant_crit).await,
            Ok(CostMarginStatus::Critical)
        ));
        // 90 % margin: healthy.
        assert!(matches!(
            check_tenant_cost_margin(&env.state, tenant_ok).await,
            Ok(CostMarginStatus::Healthy)
        ));

        let alerts: Vec<(String, String)> = sqlx::query_as(
            "SELECT tenant_id, alert_type FROM cost_alerts WHERE resolved_at IS NULL
             ORDER BY tenant_id",
        )
        .fetch_all(&env.pool)
        .await
        .expect("alerts");
        assert_eq!(
            alerts,
            vec![
                (tenant_crit.to_string(), "negative_margin".to_string()),
                (tenant_warn.to_string(), "low_margin".to_string()),
            ]
        );
        let crit_throttled = redis_exists(env, &cost_throttle_key(tenant_crit)).await;
        assert!(crit_throttled, "the critical tenant is throttled");
        let warn_throttled = redis_exists(env, &cost_throttle_key(tenant_warn)).await;
        assert!(!warn_throttled, "a warning never throttles");

        // Re-running the critical tenant deduplicates the open alert.
        assert!(matches!(
            check_tenant_cost_margin(&env.state, tenant_crit).await,
            Ok(CostMarginStatus::Critical)
        ));
        let crit_alerts: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM cost_alerts WHERE tenant_id = $1 AND alert_type = 'negative_margin'",
        )
        .bind(tenant_crit)
        .fetch_one(&env.pool)
        .await
        .expect("alert count");
        assert_eq!(crit_alerts, 1, "open alerts deduplicate");

        // Recovery clears the throttle and audits the transition.
        clear_cost_throttling(&env.state, tenant_crit).await;
        assert!(!redis_exists(env, &cost_throttle_key(tenant_crit)).await);
        let cleared: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM audit_logs
             WHERE tenant_id = $1 AND action = 'billing.cost_throttle.cleared'",
        )
        .bind(tenant_crit)
        .fetch_one(&env.pool)
        .await
        .expect("audit");
        assert_eq!(cleared, 1);

        // A broken cost table isolates per-tenant failures: the sweep
        // reports the checked set (every active tenant in the clone,
        // including template seeds) but asserts no statuses.
        let active_tenants: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM tenants WHERE status = 'active'")
                .fetch_one(&env.pool)
                .await
                .expect("tenant count");
        env.break_table("tenant_costs").await;
        let result = process_cost_margin_checks(&env.state).await.expect("sweep");
        env.restore_table("tenant_costs").await;
        assert_eq!(result.checked, active_tenants);
        assert_eq!((result.warnings, result.critical), (0, 0));
    });

    // ── wallet-credit expiry audit fault ────────────────────────────────

    env_test!(wallet_credit_expiry_audit_failure_rolls_back, |env| {
        let tenant = "w6cexp_audit";
        seed_tenant_plan(env, tenant, "growth", "active").await;
        sqlx::query("INSERT INTO wallets (tenant_id, balance, currency) VALUES ($1, 500, 'EUR')")
            .bind(tenant)
            .execute(&env.pool)
            .await
            .expect("wallet");
        sqlx::query(
            "INSERT INTO wallet_transactions
                 (wallet_id, tenant_id, type, amount, balance_after, description, reference, created_at)
             SELECT id, tenant_id, 'credit', 500, 500, 'aged grant', 'w6c-exp',
                    NOW() - INTERVAL '13 months'
             FROM wallets WHERE tenant_id = $1",
        )
        .bind(tenant)
        .execute(&env.pool)
        .await
        .expect("aged credit");

        // With the audit trail unwritable the expiry must FAIL WHOLE: the
        // balance is untouched and no debit exists (money never moves
        // without its ledger + audit entry).
        env.break_table("audit_logs").await;
        let error = expire_stale_wallet_credits(&env.state)
            .await
            .expect_err("audit failure must abort the expiry");
        env.restore_table("audit_logs").await;
        assert!(
            error.contains("Failed to audit wallet credit expiry"),
            "{error}"
        );
        let balance: i64 = sqlx::query_scalar("SELECT balance FROM wallets WHERE tenant_id = $1")
            .bind(tenant)
            .fetch_one(&env.pool)
            .await
            .expect("wallet");
        assert_eq!(balance, 500, "the credit survived the failed expiry");

        // With auditing healthy the same credit expires exactly once.
        let expired = expire_stale_wallet_credits(&env.state)
            .await
            .expect("expiry");
        assert_eq!(expired, 1);
        let balance: i64 = sqlx::query_scalar("SELECT balance FROM wallets WHERE tenant_id = $1")
            .bind(tenant)
            .fetch_one(&env.pool)
            .await
            .expect("wallet");
        assert_eq!(balance, 0);
        let debits: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM wallet_transactions WHERE tenant_id = $1 AND type = 'debit'",
        )
        .bind(tenant)
        .fetch_one(&env.pool)
        .await
        .expect("debits");
        assert_eq!(debits, 1);
        assert_eq!(
            expire_stale_wallet_credits(&env.state)
                .await
                .expect("replay"),
            0,
            "yesterday's expiry debit counts as consumption"
        );
    });

    // ── restriction-aware admin reset ───────────────────────────────────

    env_test!(
        admin_reset_reports_missing_holds_and_releases_messages,
        |env| {
            let tenant = "w6cadmin_reset";
            seed_tenant_plan(env, tenant, "growth", "active").await;
            seed_dunning(env, tenant, "warning", None).await;
            seed_message(env, tenant, "dunning_queued").await;
            seed_message(env, tenant, "dunning_queued").await;

            // No billing restriction exists: the reset still resets dunning and
            // releases the queued messages, and must not pretend a hold cleared.
            admin_reset_dunning_restriction_aware(
                &env.pool,
                &env.redis,
                tenant,
                "admin-w6c",
                "w6c coverage reset",
            )
            .await
            .expect("admin reset");
            let (status, holds, queued): (String, i64, i64) = sqlx::query_as(
                "SELECT (SELECT status FROM dunning_records WHERE tenant_id = $1),
                    (SELECT COUNT(*) FROM tenant_restrictions
                     WHERE tenant_id = $1 AND kind = 'billing' AND cleared_at IS NOT NULL),
                    (SELECT COUNT(*) FROM messages WHERE tenant_id = $1 AND status = 'queued')",
            )
            .bind(tenant)
            .fetch_one(&env.pool)
            .await
            .expect("state");
            assert_eq!(status, "healthy");
            assert_eq!(holds, 0, "no hold existed to clear");
            assert_eq!(queued, 2, "queued messages released");

            // A replay stays clean.
            admin_reset_dunning_restriction_aware(
                &env.pool,
                &env.redis,
                tenant,
                "admin-w6c",
                "w6c replay",
            )
            .await
            .expect("admin reset replay");
        }
    );

    // ── month-end closing audit fault ───────────────────────────────────

    env_test!(
        month_end_closing_audit_failure_rolls_everything_back,
        |env| {
            let tenant = "w6cmclose_audit";
            seed_tenant_plan(env, tenant, "growth", "active").await;
            let this_month = month_start(Utc::now());
            let mid_last_month =
                month_start(this_month - chrono::Days::new(1)) + chrono::Duration::days(10);
            let invoice = Uuid::new_v4();
            seed_invoice_row(
                env,
                invoice,
                tenant,
                "paid",
                mid_last_month,
                Some(mid_last_month),
                None,
            )
            .await;

            env.break_table("billing_audit_log").await;
            let error = perform_month_end_closing(&env.state)
                .await
                .expect_err("a broken audit trail must abort the closing");
            env.restore_table("billing_audit_log").await;
            assert!(
                error.contains("Failed to insert billing audit log"),
                "{error}"
            );
            // The whole transaction rolled back: nothing closed, nothing recorded.
            let (closed, closings): (i64, i64) = sqlx::query_as(
                "SELECT (SELECT COUNT(*) FROM invoices WHERE id = $1 AND closed_at IS NOT NULL),
                    (SELECT COUNT(*) FROM month_end_closings)",
            )
            .bind(invoice)
            .fetch_one(&env.pool)
            .await
            .expect("rollback state");
            assert_eq!((closed, closings), (0, 0));

            // With the audit trail healthy the closing completes exactly once.
            assert!(perform_month_end_closing(&env.state)
                .await
                .expect("closing"));
            assert!(!perform_month_end_closing(&env.state).await.expect("replay"));
            let closed: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM invoices WHERE id = $1 AND closed_at IS NOT NULL",
            )
            .bind(invoice)
            .fetch_one(&env.pool)
            .await
            .expect("closed");
            assert_eq!(closed, 1);
        }
    );

    // ── usage-alert webhook failure arm ─────────────────────────────────

    env_test!(
        usage_alert_webhook_failure_delivers_nothing_and_retries,
        |env| {
            let tenant = "w6calert_fail";
            // This test owns `alert:cooldown:{tenant}:*` in the shared Redis:
            // a cooldown set by a previous run (1 h TTL) must not suppress the
            // first delivery attempt.
            {
                let mut conn = env.redis.get().await.expect("redis");
                let stale: Vec<String> = redis::cmd("KEYS")
                    .arg(format!("alert:cooldown:{tenant}:*"))
                    .query_async(&mut conn)
                    .await
                    .expect("scan cooldowns");
                if !stale.is_empty() {
                    let _: () = redis::cmd("DEL")
                        .arg(&stale)
                        .query_async(&mut conn)
                        .await
                        .expect("clear cooldowns");
                }
            }
            seed_tenant_plan(env, tenant, "growth", "active").await;
            seed_plan(env, "w6calert_plan", 100, json!({})).await;
            sqlx::query("UPDATE tenants SET plan = 'w6calert_plan' WHERE id = $1")
                .bind(tenant)
                .execute(&env.pool)
                .await
                .expect("switch plan");
            let mock = Mock::default();
            mock.route("/hook", 500, "webhook down");
            let base = spawn_mock(mock.clone()).await;
            sqlx::query("UPDATE tenants SET settings = $2::jsonb WHERE id = $1")
                .bind(tenant)
                .bind(json!({"webhookUrl": format!("{base}/hook")}).to_string())
                .execute(&env.pool)
                .await
                .expect("tenant webhook");
            sqlx::query(
                "INSERT INTO usage_alert_configs (tenant_id, metric_type, threshold_percent,
                                              notification_channel)
             VALUES ($1, 'emails', 50, 'webhook')",
            )
            .bind(tenant)
            .execute(&env.pool)
            .await
            .expect("alert config");
            sqlx::query(
                "INSERT INTO metering_events (id, tenant_id, event_type, quantity, timestamp)
             VALUES (gen_random_uuid(), $1, 'emails_sent', 80, NOW())",
            )
            .bind(tenant)
            .execute(&env.pool)
            .await
            .expect("usage");

            let client = Client::new();
            // Webhook down: nothing delivered, NO cooldown set, the next pass
            // must retry.
            let first = process_usage_alerts(&env.state, &client)
                .await
                .expect("alerts");
            assert_eq!(first.alerts_triggered, 0, "{first:?}");
            assert_eq!(mock.call_count("/hook"), 1, "the webhook was attempted");
            assert!(
                !redis_exists(env, &format!("alert:cooldown:{tenant}:emails:50")).await,
                "a failed delivery never sets the cooldown"
            );
            let last_triggered: Option<DateTime<Utc>> = sqlx::query_scalar(
                "SELECT last_triggered_at FROM usage_alert_configs WHERE tenant_id = $1",
            )
            .bind(tenant)
            .fetch_one(&env.pool)
            .await
            .expect("last triggered");
            assert!(last_triggered.is_none());

            // Webhook recovers: the SAME threshold fires on the next pass.
            mock.route("/hook", 200, "{}");
            let second = process_usage_alerts(&env.state, &client)
                .await
                .expect("alerts");
            assert_eq!(second.alerts_triggered, 1, "{second:?}");
            assert!(
                redis_exists(env, &format!("alert:cooldown:{tenant}:emails:50")).await,
                "a delivered alert sets the cooldown"
            );
            let third = process_usage_alerts(&env.state, &client)
                .await
                .expect("alerts");
            assert_eq!(third.alerts_triggered, 0, "cooldown suppresses the replay");
        }
    );
}
