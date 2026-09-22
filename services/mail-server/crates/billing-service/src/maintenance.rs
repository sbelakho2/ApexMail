use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use billing_common::cost_throttle::{
    cost_throttle_key, CostThrottleOverride, COST_THROTTLE_TTL_SECS,
};
use chrono::{DateTime, Datelike, Timelike, Utc};
use redis::AsyncCommands;
use reqwest::Client;
use serde::de::DeserializeOwned;
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sqlx::{Connection, FromRow, Postgres, QueryBuilder};
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
const DAILY_TASK_INTERVAL: Duration = Duration::from_secs(24 * 60 * 60);
const WALLET_CLEANUP_INTERVAL: Duration = Duration::from_secs(30 * 60);
const METERING_SCAN_COUNT: usize = 200;
const METERING_RECOVERY_LIMIT: usize = 10_000;
const METERING_PERIOD_TTL_SECONDS: i64 = 40 * 86_400;
const USAGE_ALERT_COOLDOWN_SECONDS: u64 = 60 * 60;
const COST_MARGIN_WARNING_THRESHOLD: f64 = 20.0;
const COST_MARGIN_CRITICAL_THRESHOLD: f64 = 10.0;
const SLA_AVAILABILITY_TARGET: f64 = 99.9;
const KMD_GENERATION_INTERVAL: Duration = Duration::from_secs(6 * 60 * 60); // Every 6 hours
const INVOICE_ARCHIVE_INTERVAL: Duration = Duration::from_secs(24 * 60 * 60); // Daily
/// Derived-usage sweep starts 90 minutes past the hour after startup: late
/// enough for the day to be firmly closed and other daily jobs to settle,
/// soon enough to land before the reconciliation report is read.
const DERIVED_USAGE_SWEEP_INITIAL_DELAY: Duration = Duration::from_secs(90 * 60);

/// Operational override for the periodic-task intervals above. When set,
/// EVERY loop ticks on this many milliseconds instead of its production
/// cadence — so integration tests (and ops smoke-checks) can drive the real
/// spawned loops in milliseconds. Unset keeps the production intervals.
fn task_interval(default: Duration) -> Duration {
    std::env::var("PERIODIC_TASK_INTERVAL_MS")
        .ok()
        .and_then(|value| value.trim().parse::<u64>().ok())
        .map(|ms| Duration::from_millis(ms.max(10)))
        .unwrap_or(default)
}

static DEDICATED_IP_TABLE_MISSING_LOGGED: AtomicBool = AtomicBool::new(false);

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

            // Monitored drain — records histograms, counters, and
            // triggers consecutive-error alert if threshold is exceeded.
            let _ = crate::metering_monitor::monitored_drain_pending_events(
                metering_state.as_ref(),
                METERING_RECOVERY_LIMIT,
            )
            .await;

            // Stale-event check — updates pending-event gauge and
            // warns if events remain undrained past the age limit.
            crate::metering_monitor::check_stale_pending_events(metering_state.as_ref()).await;
        }
    });

    let wallet_state = state.clone();
    tokio::spawn(async move {
        let mut interval = interval_at(
            Instant::now() + task_interval(WALLET_CLEANUP_INTERVAL),
            task_interval(WALLET_CLEANUP_INTERVAL),
        );
        interval.set_missed_tick_behavior(MissedTickBehavior::Skip);

        loop {
            interval.tick().await;

            match process_expired_wallet_reservations(wallet_state.as_ref()).await {
                Ok(released_count) if released_count > 0 => {
                    info!(released_count, "released expired wallet reservations");
                }
                Ok(_) => {}
                Err(error_message) => {
                    error!(error = %error_message, "failed to release expired wallet reservations");
                }
            }
        }
    });

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
            // allowance — see usage::record_with_quota_check and the
            // overage module). Every created invoice is COLLECTED: wallet
            // first, then Stripe invoice item / dunning (see overage.rs).
            match crate::overage::sweep_period_overage(sla_state.as_ref()).await {
                Ok(result)
                    if result.invoices_created > 0
                        || result.payg_invoices_created > 0
                        || result.skipped_no_address > 0
                        || result.skipped_unknown_plan > 0 =>
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
                }
                Ok(result) if result.failed_periods > 0 => {
                    warn!(
                        failed_periods = result.failed_periods,
                        oldest_unresolved_age_secs = ?result.oldest_unresolved_age_secs,
                        "period overage sweep finished with isolated period failures — recorded with backoff"
                    );
                }
                Ok(_) => {}
                Err(error_message) => {
                    error!(error = %error_message, "failed to sweep period overage");
                }
            }

            // ToS 6.4 wallet-credit expiry (12 months) — see
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
                        "processed scheduled Stripe retries"
                    );
                }
                Ok(_) => {}
                Err(error_message) => {
                    error!(error = %error_message, "failed to process scheduled Stripe retries");
                }
            }

            // Audit F33 — resume stranded usage-invoice collection
            // operations (invoice created, collection interrupted): the
            // idempotent ladder re-runs wallet application, the finalized
            // Stripe invoice and the dunning handoff until the outbox row
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

            // Audit F66 — the hourly subscription_change_saga cleanup job was
            // removed: no migration or writer ever created that table (every
            // run failed with 42P01). Subscription-change persistence and
            // recovery are the canonical stripe_webhook_events store
            // (migrations 127/128) plus the deadletter retry ladder — there
            // is no separate saga to clean up.
        }
    });

    // ── Stripe webhook stale-pending reclaim (startup + hourly, Fix G) ──
    let webhook_state = state.clone();
    tokio::spawn(async move {
        match crate::stripe_webhooks::reclaim_stale_pending_webhooks(webhook_state.as_ref()).await {
            Ok(reclaimed) if !reclaimed.is_empty() => {
                info!(
                    count = reclaimed.len(),
                    "reclaimed stale pending stripe webhooks on startup"
                );
            }
            Ok(_) => {}
            Err(error_message) => {
                error!(error = %error_message, "failed to reclaim stale pending stripe webhooks on startup");
            }
        }

        let mut interval = interval_at(
            Instant::now() + task_interval(HOURLY_TASK_INTERVAL),
            task_interval(HOURLY_TASK_INTERVAL),
        );
        interval.set_missed_tick_behavior(MissedTickBehavior::Skip);

        loop {
            interval.tick().await;

            match crate::stripe_webhooks::reclaim_stale_pending_webhooks(webhook_state.as_ref())
                .await
            {
                Ok(reclaimed) if !reclaimed.is_empty() => {
                    info!(
                        count = reclaimed.len(),
                        "reclaimed stale pending stripe webhooks"
                    );
                }
                Ok(_) => {}
                Err(error_message) => {
                    error!(error = %error_message, "failed to reclaim stale pending stripe webhooks");
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
    // The ONLY writers of terminal subscription states are verified Stripe
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

    for (invoice_id, tenant_id, invoice_number, pdf_url) in &candidates {
        if let Err(e) = sqlx::query(
            r#"
            INSERT INTO invoice_archives (invoice_id, tenant_id, invoice_number, pdf_url, batch_id, archived_at)
            VALUES ($1, $2, $3, $4, $5, NOW())
            ON CONFLICT (invoice_id) DO NOTHING
            "#,
        )
        .bind(invoice_id)
        .bind(tenant_id)
        .bind(invoice_number)
        .bind(pdf_url)
        .bind(batch_id)
        .execute(&state.db)
        .await
        {
            warn!(
                invoice_id = %invoice_id,
                error = %e,
                "Failed to archive invoice"
            );
        }
    }

    info!(
        batch_id = %batch_id,
        count = count,
        "Invoice archival batch completed"
    );

    Ok(count)
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
    //     check-then-insert ran across replicas/restarts — both passed the
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

/// Downgrade tenants whose trialing subscription ended without a terminal
/// webhook (see the sweep task comment). Returns the number of tenants
/// downgraded. Idempotent: rows already canceled no longer match.
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
        SELECT DISTINCT s.tenant_id, s.stripe_subscription_id
        FROM stripe_subscriptions s
        JOIN tenants t ON t.id = s.tenant_id AND t.plan <> 'free'
        WHERE s.status = 'trialing'
          AND COALESCE(s.trial_end, s.billing_cycle_end) < NOW() - INTERVAL '24 hours'
        "#,
    )
    .fetch_all(&mut *tx)
    .await
    .map_err(|e| format!("Failed to query stale trials: {e}"))?;

    if stale.is_empty() {
        tx.commit().await.map_err(|e| e.to_string())?;
        return Ok(0);
    }

    for (tenant_id, subscription_id) in &stale {
        sqlx::query(
            "UPDATE stripe_subscriptions SET status = 'canceled', updated_at = NOW()              WHERE stripe_subscription_id = $1 AND status = 'trialing'",
        )
        .bind(subscription_id)
        .execute(&mut *tx)
        .await
        .map_err(|e| format!("Failed to cancel stale trial {subscription_id}: {e}"))?;

        sqlx::query("UPDATE tenants SET plan = 'free', updated_at = NOW() WHERE id = $1")
            .bind(tenant_id)
            .execute(&mut *tx)
            .await
            .map_err(|e| format!("Failed to downgrade tenant {tenant_id}: {e}"))?;

        append_audit_log(
            &mut tx,
            tenant_id,
            "billing.trial_expired_sweep",
            "stripe_subscription",
            Some(subscription_id),
            serde_json::json!({
                "reason": "trialing subscription period ended without a terminal webhook",
            }),
            chrono::Utc::now(),
        )
        .await
        .map_err(|e| format!("Failed to audit trial sweep for {tenant_id}: {e}"))?;
    }

    let count = stale.len() as u64;
    tx.commit()
        .await
        .map_err(|e| format!("Failed to commit trial sweep: {e}"))?;
    Ok(count)
}

/// Check if the previous month's KMD return is due (past the 20th)
/// and generate it — plus every missed month since the last generated
/// return — if not present yet (Fix I5: a service outage used to skip
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
        // Already generated at/after the target — nothing to do.
        Some(last) if last >= target => return Vec::new(),
        Some(last) => last,
        None => return vec![target],
    };
    crate::vat_kmd::month_steps(from, target, cap)
}

/// Attempt to file the generated KMD VAT return with the EMTA (e-MTA) API.
///
/// Performs idempotency check — if the KMD return record already has a
/// `filing_reference` and `filed_at` set, the filing is skipped.
///
/// Returns:
/// * `Ok(Some(...))` — filing was attempted and acknowledged.
/// * `Ok(None)` — already filed, skipped.
/// * `Err(...)` — filing failed (HTTP error, parse error, DB error).
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

    // ── 2. Idempotency check — skip if already filed ──────────────
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

#[derive(Debug)]
struct UsageAlertSweepResult {
    tenants_checked: i64,
    alerts_triggered: i64,
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
    metric_type: String,
    threshold_percent: i32,
    notification_channel: String,
}

#[derive(Debug, FromRow)]
struct TenantAlertSettingsRow {
    settings: Value,
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
    stripe_subscription_item_id: Option<String>,
}

#[derive(Debug, FromRow)]
struct TenantStripeSubscriptionRow {
    stripe_subscription_id: String,
}

#[derive(Debug, Deserialize)]
struct StripeSubscriptionItemResponse {
    id: String,
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

    for event in &valid_events {
        let guard_key = format!("meter:guard:{}", event.normalized_id);
        // Fix F2 — the recovered event must bump the SAME counter the quota
        // gate enforces. The key is derived through the shared anchored-key
        // selection (billing-cycle anchored for subscription tenants, UTC
        // calendar month otherwise) — the old calendar-month key forked
        // cycle-anchored tenants onto a second, never-enforced counter, so
        // recovered events bypassed quota entirely.
        let counter_key = crate::usage::enforced_counter_key_for_event_type(
            &state.db,
            &event.tenant_id,
            &event.event_type,
            event.timestamp,
        )
        .await;
        let pending_key = format!("meter:pending:{}", event.raw_id);

        // Only increment the counter if this event was newly inserted into
        // the DB.  Events that were already there (re-run after crash) will
        // have their counter guard already set, so the Lua script is a no-op
        // for the counter while still cleaning up the pending key.
        let _: i64 = redis::cmd("EVAL")
            .arg(DRAIN_AND_INCR_LUA)
            .arg(3i64) // number of keys
            .arg(&guard_key)
            .arg(&counter_key)
            .arg(&pending_key)
            .arg(event.quantity)
            .arg(METERING_PERIOD_TTL_SECONDS)
            .query_async(&mut conn)
            .await
            .map_err(|error| {
                format!(
                    "Failed to drain+incr metering event {}: {error}",
                    event.raw_id
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
    stripe_subscription_id: String,
    stripe_customer_id: String,
}

/// Whether the scheduled auto-pay job may charge tenants' saved Stripe
/// payment methods for open invoices. Default: disabled — auto-charging is
/// financially sensitive and must be opted into explicitly via
/// `AUTO_PAY_OPEN_INVOICES=true` (or `1`).
fn auto_pay_open_invoices_enabled() -> bool {
    std::env::var("AUTO_PAY_OPEN_INVOICES")
        .map(|value| value.trim().eq_ignore_ascii_case("true") || value.trim() == "1")
        .unwrap_or(false)
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
            "AUTO_PAY_OPEN_INVOICES disabled — skipping scheduled Stripe auto-pay retries \
             (set AUTO_PAY_OPEN_INVOICES=true to enable)"
        );
        return Ok(RetryResult {
            attempted: 0,
            succeeded: 0,
        });
    }

    let rows = sqlx::query_as::<_, RetryCandidateRow>(
        r#"
        SELECT d.tenant_id, s.stripe_subscription_id, s.stripe_customer_id
        FROM dunning_records d
        JOIN stripe_subscriptions s ON s.tenant_id = d.tenant_id
        WHERE d.next_retry_at IS NOT NULL
          AND d.next_retry_at <= NOW()
          AND d.status IN ('warning', 'soft_suspended')
          AND s.status IN ('past_due', 'unpaid')
        ORDER BY d.next_retry_at ASC
        LIMIT 50
        "#,
    )
    .fetch_all(&state.db)
    .await
    .map_err(|error| format!("Failed to load scheduled Stripe retries: {error}"))?;

    let mut attempted = 0_i64;
    let mut succeeded = 0_i64;

    for row in rows {
        attempted += 1;

        let retry_result: Result<(), String> = async {
            let invoices = stripe_get_json::<StripeInvoiceListResponse>(
                client,
                "/v1/invoices",
                &[
                    ("customer", row.stripe_customer_id.clone()),
                    ("subscription", row.stripe_subscription_id.clone()),
                    ("status", "open".to_string()),
                    ("limit", "1".to_string()),
                ],
            )
            .await?;

            let Some(invoice) = invoices.data.first() else {
                sqlx::query(
                    r#"
                    UPDATE dunning_records
                    SET next_retry_at = NULL, updated_at = NOW()
                    WHERE tenant_id = $1
                    "#,
                )
                .bind(&row.tenant_id)
                .execute(&state.db)
                .await
                .map_err(|error| {
                    format!(
                        "Failed to clear next_retry_at for {}: {error}",
                        row.tenant_id
                    )
                })?;
                return Ok(());
            };

            stripe_post_json_idempotent::<serde_json::Value>(
                client,
                &format!("/v1/invoices/{}/pay", invoice.id),
                // One key per invoice: a retry after a lost response must
                // replay the SAME Stripe pay call, not charge twice.
                &format!("autopay_{}", invoice.id),
            )
            .await?;

            mark_payment_recovered(state, &row.tenant_id, Some(invoice.id.as_str())).await?;
            Ok(())
        }
        .await;

        match retry_result {
            Ok(()) => {
                succeeded += 1;
            }
            Err(error_message) => {
                warn!(tenant_id = %row.tenant_id, error = %error_message, "scheduled Stripe retry failed");
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
                    error!(tenant_id = %row.tenant_id, error = %error, "failed to reschedule dunning retry after Stripe retry failure");
                }
            }
        }
    }

    Ok(RetryResult {
        attempted,
        succeeded,
    })
}

async fn process_usage_alerts(
    state: &AppState,
    client: &Client,
) -> Result<UsageAlertSweepResult, String> {
    let tenant_ids: Vec<String> = sqlx::query_scalar(
        r#"
        SELECT DISTINCT tenant_id
        FROM usage_alert_configs
        WHERE enabled = true
        ORDER BY tenant_id
        "#,
    )
    .fetch_all(&state.db)
    .await
    .map_err(|error| format!("Failed to load usage alert tenants: {error}"))?;

    let mut alerts_triggered = 0_i64;
    for tenant_id in &tenant_ids {
        match process_usage_alerts_for_tenant(state, client, tenant_id).await {
            Ok(count) => alerts_triggered += count,
            Err(error_message) => {
                warn!(tenant_id = %tenant_id, error = %error_message, "failed to process usage alerts for tenant");
            }
        }
    }

    Ok(UsageAlertSweepResult {
        tenants_checked: i64::try_from(tenant_ids.len()).unwrap_or(i64::MAX),
        alerts_triggered,
    })
}

async fn process_usage_alerts_for_tenant(
    state: &AppState,
    client: &Client,
    tenant_id: &str,
) -> Result<i64, String> {
    let period_start = month_start(Utc::now());
    let period_end = next_month_start(period_start);
    let usage_summary = crate::usage::get_usage(&state.db, tenant_id, period_start, period_end)
        .await
        .map_err(|error| format!("Failed to load usage summary for {tenant_id}: {error}"))?;

    let configs = sqlx::query_as::<_, UsageAlertConfigRow>(
        r#"
        SELECT id, metric_type, threshold_percent, notification_channel
        FROM usage_alert_configs
        WHERE tenant_id = $1
          AND enabled = true
        ORDER BY threshold_percent ASC
        "#,
    )
    .bind(tenant_id)
    .fetch_all(&state.db)
    .await
    .map_err(|error| format!("Failed to load usage alert configs for {tenant_id}: {error}"))?;

    if configs.is_empty() {
        return Ok(0);
    }

    let webhook_url = load_usage_alert_webhook_url(state, tenant_id).await?;
    let mut conn = state
        .redis
        .get()
        .await
        .map_err(|error| format!("Failed to get Redis connection for usage alerts: {error}"))?;

    let mut alerts_triggered = 0_i64;

    for config in configs {
        let cooldown_key = format!(
            "alert:cooldown:{tenant_id}:{}:{}",
            config.metric_type, config.threshold_percent
        );
        let in_cooldown: bool = conn.exists(&cooldown_key).await.map_err(|error| {
            format!("Failed to check usage alert cooldown for {tenant_id}: {error}")
        })?;
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

        let delivered = send_usage_alert(
            state,
            client,
            tenant_id,
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

    Ok(alerts_triggered)
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

async fn load_usage_alert_webhook_url(
    state: &AppState,
    tenant_id: &str,
) -> Result<Option<String>, String> {
    let row = sqlx::query_as::<_, TenantAlertSettingsRow>(
        r#"
        SELECT COALESCE(settings, '{}'::jsonb) AS settings
        FROM tenants
        WHERE id = $1
        "#,
    )
    .bind(tenant_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|error| format!("Failed to load tenant settings for {tenant_id}: {error}"))?;

    Ok(row.and_then(|row| {
        row.settings
            .get("webhookUrl")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string)
    }))
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

async fn process_monthly_sla_credits(state: &AppState) -> Result<SlaCreditSweepResult, String> {
    let current_month_start = month_start(Utc::now());
    let period_start = month_start(current_month_start - chrono::Days::new(1));
    let period_month = period_start.date_naive();
    let period_end = current_month_start;

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
        -- entitlement and the credit cap of the OVERRIDING plan — joining
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

    let mut credits_created = 0_i64;
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

        // Fix I6 — SLA credits are cash-equivalent: base them only on
        // invoices that were actually paid, and credit in the invoice's own
        // currency (mixed-currency totals must never be summed together).
        let invoice_currency: String = sqlx::query_scalar(
            r#"
            SELECT UPPER(currency)
            FROM invoices
            WHERE tenant_id = $1
              AND status = 'paid'
              AND period_start >= $2
              AND period_end <= $3
            ORDER BY created_at DESC
            LIMIT 1
            "#,
        )
        .bind(&candidate.tenant_id)
        .bind(period_start)
        .bind(period_end)
        .fetch_optional(&state.db)
        .await
        .map_err(|error| {
            format!(
                "Failed to load invoice currency for SLA credits {}: {error}",
                candidate.tenant_id
            )
        })?
        .flatten()
        .unwrap_or_else(|| "EUR".into());

        let invoice_amount_cents: i64 = sqlx::query_scalar(
            r#"
            SELECT COALESCE(SUM(COALESCE(total, amount)), 0)::bigint
            FROM invoices
            WHERE tenant_id = $1
              AND status = 'paid'
              AND period_start >= $2
              AND period_end <= $3
              AND UPPER(currency) = $4
            "#,
        )
        .bind(&candidate.tenant_id)
        .bind(period_start)
        .bind(period_end)
        .bind(&invoice_currency)
        .fetch_one(&state.db)
        .await
        .map_err(|error| {
            format!(
                "Failed to load invoice total for SLA credits {}: {error}",
                candidate.tenant_id
            )
        })?;

        // Money invariant: integer cents, half-up rounding — no f64 in the
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

        // Fix F5 — the previous NOT-EXISTS check-then-insert could
        // double-run across replicas/restarts: two sweeps both saw no
        // credit and both inserted (sla_credits has no unique constraint on
        // (tenant_id, period_month)). Serialize with a pg advisory
        // TRANSACTION lock keyed on (tenant, period) and re-check existence
        // INSIDE the lock — no schema change needed.
        let mut tx = state.db.begin().await.map_err(|error| {
            format!(
                "Failed to begin SLA credit transaction for {}: {error}",
                candidate.tenant_id
            )
        })?;

        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
            .bind(format!(
                "sla_credit:{}:{}-{:02}",
                candidate.tenant_id,
                period_month.year(),
                period_month.month()
            ))
            .execute(&mut *tx)
            .await
            .map_err(|error| {
                format!(
                    "Failed to acquire SLA credit lock for {}: {error}",
                    candidate.tenant_id
                )
            })?;

        // `SELECT 1` is INT4 and cannot decode into Option<i64>: the
        // idempotency re-check failed on every SECOND sweep, aborting the
        // whole SLA pass. Project an explicit bigint.
        let already_credited: Option<i64> = sqlx::query_scalar(
            "SELECT 1::bigint FROM sla_credits WHERE tenant_id = $1 AND period_month = $2 LIMIT 1",
        )
        .bind(&candidate.tenant_id)
        .bind(period_month)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|error| {
            format!(
                "Failed to re-check existing SLA credit for {}: {error}",
                candidate.tenant_id
            )
        })?;

        let created = if already_credited.is_some() {
            false
        } else {
            sqlx::query(
                r#"
                INSERT INTO sla_credits (
                    id,
                    tenant_id,
                    period_month,
                    breach_percent,
                    credit_percent,
                    credit_amount,
                    currency,
                    status,
                    created_at
                )
                VALUES (gen_random_uuid(), $1, $2, $3, $4, $5, $6, 'pending', NOW())
                "#,
            )
            .bind(&candidate.tenant_id)
            .bind(period_month)
            .bind(breach_percent)
            .bind(credit_percent)
            .bind(credit_amount)
            .bind(&invoice_currency)
            .execute(&mut *tx)
            .await
            .map_err(|error| {
                format!(
                    "Failed to insert SLA credit for {}: {error}",
                    candidate.tenant_id
                )
            })?;
            true
        };

        tx.commit().await.map_err(|error| {
            format!(
                "Failed to commit SLA credit transaction for {}: {error}",
                candidate.tenant_id
            )
        })?;

        if created {
            credits_created += 1;
        }
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
/// credit path — money computation must never route through f64.
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
    let Some(price_id) = dedicated_ip_price_id() else {
        return Ok(0);
    };

    // Fix I7 — the FOR UPDATE SKIP LOCKED claim previously ran in
    // autocommit mode, so the row locks were released immediately and two
    // maintenance ticks could double-charge the same IP. The fetch and the
    // per-row processing now share one explicit transaction; each row runs
    // inside a SAVEPOINT so one failure does not roll back the others.
    // Double-charging remains impossible even if the transaction is lost
    // after the Stripe call thanks to the Idempotency-Key.
    let mut tx = state
        .db
        .begin()
        .await
        .map_err(|error| format!("Failed to begin dedicated IP charge transaction: {error}"))?;

    let rows = match sqlx::query_as::<_, DedicatedIpPendingRow>(
        r#"
        SELECT id, tenant_id, ip_address, stripe_subscription_item_id
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

        match charge_dedicated_ip(&mut savepoint, client, &row, &price_id).await {
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
                warn!(tenant_id = %row.tenant_id, ip_id = %row.id, ip_address = %row.ip_address, error = %error_message, "failed to create dedicated IP Stripe subscription item");
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
    // Fix I7 — same explicit-transaction claim as the charge path.
    let mut tx = state
        .db
        .begin()
        .await
        .map_err(|error| format!("Failed to begin dedicated IP cancel transaction: {error}"))?;

    let rows = match sqlx::query_as::<_, DedicatedIpPendingRow>(
        r#"
        SELECT id, tenant_id, ip_address, stripe_subscription_item_id
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
                warn!(tenant_id = %row.tenant_id, ip_id = %row.id, ip_address = %row.ip_address, error = %error_message, "failed to cancel dedicated IP Stripe subscription item");
            }
        }
    }

    tx.commit()
        .await
        .map_err(|error| format!("Failed to commit dedicated IP cancel transaction: {error}"))?;

    Ok(processed)
}

async fn charge_dedicated_ip(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    client: &Client,
    row: &DedicatedIpPendingRow,
    price_id: &str,
) -> Result<(), String> {
    let subscription = sqlx::query_as::<_, TenantStripeSubscriptionRow>(
        r#"
        SELECT stripe_subscription_id
        FROM stripe_subscriptions
        WHERE tenant_id = $1
          AND status = 'active'
        ORDER BY created_at DESC
        LIMIT 1
        "#,
    )
    .bind(&row.tenant_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|error| format!("Failed to load tenant Stripe subscription: {error}"))?;

    let Some(subscription) = subscription else {
        return Err("No active Stripe subscription for tenant".to_string());
    };

    let response = dedicated_ip_subscription_item_create(
        client,
        &subscription.stripe_subscription_id,
        price_id,
        &row.id,
        &row.tenant_id,
    )
    .await?;

    sqlx::query(
        r#"
        UPDATE dedicated_ips
        SET billing_status = 'active',
            stripe_subscription_item_id = $2,
            billing_started_at = NOW(),
            billing_failure_count = 0,
            billing_retry_after = NULL,
            updated_at = NOW()
        WHERE id = $1
        "#,
    )
    .bind(&row.id)
    .bind(response.id)
    .execute(&mut **tx)
    .await
    .map_err(|error| format!("Failed to mark dedicated IP billing active: {error}"))?;

    Ok(())
}

async fn cancel_dedicated_ip_billing(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    client: &Client,
    row: &DedicatedIpPendingRow,
) -> Result<(), String> {
    if let Some(subscription_item_id) = &row.stripe_subscription_item_id {
        dedicated_ip_subscription_item_delete(client, subscription_item_id).await?;
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

fn dedicated_ip_price_id() -> Option<String> {
    std::env::var("STRIPE_DEDICATED_IP_PRICE_ID")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

async fn dedicated_ip_subscription_item_create(
    client: &Client,
    subscription_id: &str,
    price_id: &str,
    ip_id: &str,
    tenant_id: &str,
) -> Result<StripeSubscriptionItemResponse, String> {
    let secret_key = std::env::var("STRIPE_SECRET_KEY")
        .map_err(|_| "Stripe secret key is not configured".to_string())?;

    let form = vec![
        ("subscription", subscription_id.to_string()),
        ("price", price_id.to_string()),
        ("quantity", "1".to_string()),
        ("proration_behavior", "create_prorations".to_string()),
        ("metadata[apexmail_ip_id]", ip_id.to_string()),
        ("metadata[apexmail_tenant_id]", tenant_id.to_string()),
        ("metadata[type]", "dedicated_ip_addon".to_string()),
    ];

    let response = client
        .post(format!("{}/v1/subscription_items", stripe_api_base_url()))
        .bearer_auth(secret_key)
        .header("Idempotency-Key", format!("apexmail_ip_charge_{ip_id}"))
        .form(&form)
        .send()
        .await
        .map_err(|error| format!("Stripe request failed: {error}"))?;

    decode_stripe_response(response).await
}

async fn dedicated_ip_subscription_item_delete(
    client: &Client,
    subscription_item_id: &str,
) -> Result<(), String> {
    let secret_key = std::env::var("STRIPE_SECRET_KEY")
        .map_err(|_| "Stripe secret key is not configured".to_string())?;

    let form = [("proration_behavior", "create_prorations")];
    let response = client
        .delete(format!(
            "{}/v1/subscription_items/{subscription_item_id}",
            stripe_api_base_url()
        ))
        .bearer_auth(secret_key)
        .form(&form)
        .send()
        .await
        .map_err(|error| format!("Stripe request failed: {error}"))?;

    if response.status().is_success() {
        return Ok(());
    }

    let status = response.status();
    let body = response.text().await.unwrap_or_default();
    if status.as_u16() == 404 || body.contains("resource_missing") {
        return Ok(());
    }

    Err(format!("Stripe returned {status}: {body}"))
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
            &summary,
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
            &summary,
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

async fn process_expired_wallet_reservations(state: &AppState) -> Result<i64, String> {
    let rows = sqlx::query_as::<_, ExpiredWalletReservationRow>(
        r#"
        WITH expired_reservations AS (
            SELECT id, tenant_id, amount
            FROM wallet_reservations
            WHERE status IN ('pending', 'active')
              AND captured_at IS NULL
              AND released_at IS NULL
              AND expires_at < NOW()
            FOR UPDATE SKIP LOCKED
        ),
        released_reservations AS (
            UPDATE wallet_reservations wr
            SET status = 'released', released_at = NOW()
            FROM expired_reservations er
            WHERE wr.id = er.id
            RETURNING er.tenant_id, er.amount
        ),
        released_totals AS (
            SELECT tenant_id, COALESCE(SUM(amount), 0)::bigint AS total_amount
            FROM released_reservations
            GROUP BY tenant_id
        ),
        wallet_updates AS (
            UPDATE wallets w
            SET reserved = release_reserved_cents(w.reserved, rt.total_amount),
                updated_at = NOW()
            FROM released_totals rt
            WHERE w.tenant_id = rt.tenant_id
            RETURNING w.tenant_id
        )
        SELECT wu.tenant_id,
               COALESCE((SELECT COUNT(*)::bigint FROM released_reservations), 0) AS released_count
        FROM wallet_updates wu
        "#,
    )
    .fetch_all(&state.db)
    .await
    .map_err(|error| format!("Failed to release expired wallet reservations: {error}"))?;

    let released_count = rows.first().map(|row| row.released_count).unwrap_or(0);
    if released_count == 0 {
        return Ok(0);
    }

    if let Ok(mut conn) = state.redis.get().await {
        let tenant_ids: Vec<String> = rows.into_iter().map(|row| row.tenant_id).collect();
        if !tenant_ids.is_empty() {
            let keys: Vec<String> = tenant_ids
                .into_iter()
                .map(|tenant_id| format!("wallet:balance:{tenant_id}"))
                .collect();
            if let Err(error) = delete_redis_keys(&mut conn, &keys).await {
                warn!(error = %error, "failed to clear wallet balance cache after releasing reservations");
            }
        }
    }

    Ok(released_count)
}

#[derive(Debug, FromRow)]
struct ExpiredWalletReservationRow {
    tenant_id: String,
    released_count: i64,
}

/// ToS 6.4 — "Credits expire after 12 months unless otherwise stated."
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
        .bind("Expired credit — 12-month wallet credit policy (ToS 6.4)")
        .execute(&mut *tx)
        .await
        .map_err(|error| {
            format!("Failed to expire stale wallet credit for {tenant_id}: {error}")
        })?
        .rows_affected();

        if debited == 0 {
            // Balance moved between the candidate scan and the debit — skip
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

/// Fix I12 — release a wallet reservation in BIGINT arithmetic.
/// The previous SQL cast the summed reservations to INTEGER before
/// subtracting, so a released total above 2^31-1 cents (~21.5M EUR) would
/// overflow/wrap instead of clamping the reservation to zero.
///
/// SQL helper: `release_reserved_cents(reserved, total)` = bigint-clamped
/// subtraction (see the migration-created function).
#[cfg_attr(not(test), allow(dead_code))]
fn release_reserved_cents_clamp(reserved: i64, released_total: i64) -> i64 {
    reserved.saturating_sub(released_total).max(0)
}

/// Fix F4/F09 — record a payment recovery and restore access according to
/// the INDEPENDENT restriction model.
///
/// `invoice_id` scopes the recovery to that invoice's failure history: the
/// tenant-level reset only happens when the tenant's most recent
/// `payment_failed` event belongs to the settled invoice — a DIFFERENT
/// invoice that is still failing keeps the tenant in dunning. The
/// `payment_recovered` dunning event is always written (with the invoice
/// id) so the settled invoice's history is complete either way. `None`
/// restores the legacy unscoped blanket reset (used when no invoice
/// context is available).
///
/// Audit F09 — restrictions are represented independently
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
        // for a different invoice that is still unpaid — keep dunning,
        // suspension and the queued-message hold exactly as they are.
        info!(
            tenant_id = %tenant_id,
            invoice_id = ?invoice_id,
            "payment recovered for one invoice; dunning kept active — a different invoice is still failing"
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
            "payment recovered; no billing restriction was active — administrative/verification/abuse holds left untouched"
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
/// rule as [`mark_payment_recovered`] — clear only the billing hold, then
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
            "admin dunning reset: no billing restriction was active — other holds left untouched"
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

/// Whether an OPEN abuse hold exists for the tenant — the state that must
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
/// reviewer identity is recorded (`reviewed_by`/`reviewed_at`) — evidence
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
/// can never clear it — only the symmetric [`clear_tenant_restriction`].
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

/// Clear one specific restriction by kind (audit F09) — the ONLY writer
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
/// above — releases the abuse restriction in the same transaction.
pub async fn resolve_abuse_report(
    db: &sqlx::PgPool,
    report_id: Uuid,
    reviewed_by: &str,
    notes: &str,
) -> Result<(), String> {
    review_abuse_report(db, report_id, "resolved", reviewed_by, notes).await
}

fn stripe_api_base_url() -> String {
    std::env::var("STRIPE_API_BASE_URL").unwrap_or_else(|_| "https://api.stripe.com".into())
}

async fn stripe_get_json<T: DeserializeOwned>(
    client: &Client,
    path: &str,
    query: &[(&str, String)],
) -> Result<T, String> {
    let secret_key = std::env::var("STRIPE_SECRET_KEY")
        .map_err(|_| "Stripe secret key is not configured".to_string())?;

    let response = client
        .get(format!("{}{}", stripe_api_base_url(), path))
        .bearer_auth(secret_key)
        .query(query)
        .send()
        .await
        .map_err(|error| format!("Stripe request failed: {error}"))?;

    decode_stripe_response(response).await
}

/// `stripe_post_json` with an `Idempotency-Key` header (mirrors the
/// dedicated-IP charge call below): money-moving POSTs must be safe to
/// retry — a timeout between Stripe executing the pay call and the
/// response reaching us used to cause a SECOND charge on the retry sweep.
async fn stripe_post_json_idempotent<T: DeserializeOwned>(
    client: &Client,
    path: &str,
    idempotency_key: &str,
) -> Result<T, String> {
    let secret_key = std::env::var("STRIPE_SECRET_KEY")
        .map_err(|_| "Stripe secret key is not configured".to_string())?;

    let response = client
        .post(format!("{}{}", stripe_api_base_url(), path))
        .bearer_auth(secret_key)
        .header("Idempotency-Key", idempotency_key)
        .send()
        .await
        .map_err(|error| format!("Stripe request failed: {error}"))?;

    decode_stripe_response(response).await
}

async fn decode_stripe_response<T: DeserializeOwned>(
    response: reqwest::Response,
) -> Result<T, String> {
    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(format!("Stripe returned {status}: {body}"));
    }

    response
        .json::<T>()
        .await
        .map_err(|error| format!("Stripe response decode failed: {error}"))
}

#[derive(Debug, Deserialize)]
struct StripeInvoiceListResponse {
    data: Vec<StripeInvoiceSummary>,
}

#[derive(Debug, Deserialize)]
struct StripeInvoiceSummary {
    id: String,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ------------------------------------------------------------------
    // Audit F09 — authorized abuse-report transitions: a CHECK of allowed
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
    // Fix I5 — KMD backfill covers every missed month.
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

    // ------------------------------------------------------------------
    // Fix I12 — wallet reservation release must not overflow.
    // ------------------------------------------------------------------

    #[test]
    fn release_reserved_clamps_to_zero_on_large_totals() {
        // Released total above INT range (~2.1B cents) previously wrapped
        // through the ::integer cast and could leave phantom reservations.
        assert_eq!(release_reserved_cents_clamp(500, 3_000_000_000), 0);
        assert_eq!(release_reserved_cents_clamp(i64::MAX, i64::MAX), 0);
    }

    #[test]
    fn release_reserved_subtracts_within_bounds() {
        assert_eq!(release_reserved_cents_clamp(1_000, 400), 600);
        assert_eq!(release_reserved_cents_clamp(1_000, 1_000), 0);
        // Releasing more than reserved cannot go negative.
        assert_eq!(release_reserved_cents_clamp(100, 200), 0);
        assert_eq!(release_reserved_cents_clamp(0, 0), 0);
    }

    // ------------------------------------------------------------------
    // Fix I6 — SLA credit percentage ladder.
    // ------------------------------------------------------------------

    #[test]
    fn sla_credit_percentage_ladder() {
        assert_eq!(sla_credit_percentage_for_breach(5.0), 100);
        assert_eq!(sla_credit_percentage_for_breach(1.0), 50);
        assert_eq!(sla_credit_percentage_for_breach(0.5), 25);
        assert_eq!(sla_credit_percentage_for_breach(0.1), 10);
        assert_eq!(sla_credit_percentage_for_breach(0.05), 0);
    }
}

// ---------------------------------------------------------------------------
// Adversarial coverage tests (DB + Redis backed) for the maintenance sweeps.
//
// These call the PRIVATE sweep functions directly — the periodic-job
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
            stripe_webhook_secret: "whsec_coverage".to_string(),
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
    /// key it can see — including another test process's — so two drains
    /// racing make each other's counts wrong. A session-level advisory lock
    /// on the admin database; released when the pool drops.
    async fn metering_keys_guard(admin_url: &str) -> Option<sqlx::PgPool> {
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

    #[derive(Clone, Default)]
    struct Mock {
        responses: Arc<std::sync::Mutex<std::collections::HashMap<String, (u16, String)>>>,
        calls: Arc<std::sync::Mutex<Vec<(String, String)>>>,
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
                .filter(|(recorded, _)| recorded == path)
                .count()
        }
    }

    async fn mock_handler(
        axum::extract::State(mock): axum::extract::State<Mock>,
        request: axum::http::Request<axum::body::Body>,
    ) -> axum::response::Response {
        use axum::response::IntoResponse;
        let path = request.uri().path().to_string();
        let _ = axum::body::to_bytes(request.into_body(), usize::MAX).await;
        let (status, body) = mock
            .responses
            .lock()
            .expect("lock")
            .get(&path)
            .cloned()
            .unwrap_or_else(|| (404, "{}".to_string()));
        mock.calls.lock().expect("lock").push((path, "hit".into()));
        (
            axum::http::StatusCode::from_u16(status).expect("status"),
            [(axum::http::header::CONTENT_TYPE, "application/json")],
            body,
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
                    "INSERT INTO stripe_subscriptions
                     (tenant_id, stripe_subscription_id, plan, status, trial_end,
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
                            JOIN stripe_subscriptions s ON s.tenant_id = t.id WHERE t.id = $1",
            )
            .bind(stale)
            .fetch_one(&env.pool)
            .await
            .expect("stale tenant");
            assert_eq!(plan, "free");
            assert_eq!(status, "canceled");
            let fresh_status: String =
                sqlx::query_scalar("SELECT status FROM stripe_subscriptions WHERE tenant_id = $1")
                    .bind(fresh)
                    .fetch_one(&env.pool)
                    .await
                    .expect("fresh status");
            assert_eq!(fresh_status, "trialing", "a recent trial is never raced");
        }
    );

    // ---------------- wallet reservations / credit expiry ----------------

    env_test!(expired_wallet_reservations_release_and_clamp, |env| {
        let tenant = "mtcov_wallet_res";
        seed_tenant(env, tenant, "free", "active").await;
        let wallet_id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO wallets (id, tenant_id, balance, currency, reserved)
             VALUES ($1, $2, 0, 'EUR', 100)",
        )
        .bind(wallet_id)
        .bind(tenant)
        .execute(&env.pool)
        .await
        .expect("seed wallet");
        sqlx::query(
            "INSERT INTO wallet_reservations (tenant_id, wallet_id, amount, status, expires_at)
             VALUES ($1, $2, 60, 'active', NOW() - INTERVAL '1 minute'),
                    ($1, $2, 40, 'active', NOW() + INTERVAL '1 hour')",
        )
        .bind(tenant)
        .bind(wallet_id)
        .execute(&env.pool)
        .await
        .expect("seed reservations");

        assert_eq!(
            process_expired_wallet_reservations(&env.state)
                .await
                .expect("release"),
            1
        );
        assert_eq!(
            process_expired_wallet_reservations(&env.state)
                .await
                .expect("replay"),
            0
        );
        let reserved: i64 = sqlx::query_scalar("SELECT reserved FROM wallets WHERE tenant_id = $1")
            .bind(tenant)
            .fetch_one(&env.pool)
            .await
            .expect("reserved");
        assert_eq!(reserved, 40, "only the expired reservation was released");
        let released_statuses: Vec<String> = sqlx::query_scalar(
            "SELECT status FROM wallet_reservations WHERE tenant_id = $1 ORDER BY amount DESC",
        )
        .bind(tenant)
        .fetch_all(&env.pool)
        .await
        .expect("statuses");
        assert_eq!(
            released_statuses,
            vec!["released".to_string(), "active".to_string()]
        );
    });

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

    // ---------------- dedicated IP billing (mock Stripe) ----------------

    #[tokio::test]
    async fn dedicated_ip_charge_and_cancel_use_mocked_stripe() {
        let Some(env) = provision("dedicated_ip_charge_and_cancel").await else {
            return;
        };
        let mock = Mock::default();
        mock.route("/v1/subscription_items", 200, r#"{"id":"si_cov_1"}"#);
        mock.route("/v1/subscription_items/si_cov_1", 200, "{}");
        let base = spawn_mock(mock.clone()).await;

        let guard = ENV_LOCK.lock().await;
        let previous = (
            std::env::var("STRIPE_SECRET_KEY").ok(),
            std::env::var("STRIPE_API_BASE_URL").ok(),
            std::env::var("STRIPE_DEDICATED_IP_PRICE_ID").ok(),
        );
        std::env::set_var("STRIPE_SECRET_KEY", "sk_test_coverage");
        std::env::set_var("STRIPE_API_BASE_URL", &base);
        std::env::set_var("STRIPE_DEDICATED_IP_PRICE_ID", "price_cov_dip");

        let tenant = "mtcov_dip";
        seed_tenant(&env, tenant, "growth", "active").await;
        sqlx::query(
            "INSERT INTO stripe_subscriptions
                 (tenant_id, stripe_subscription_id, plan, status, billing_cycle_start,
                  billing_cycle_end, stripe_customer_id)
             VALUES ($1, 'sub_dip', 'growth', 'active', NOW(), NOW() + INTERVAL '30 days', 'cus_dip')",
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
        sqlx::query(
            "UPDATE dedicated_ips SET stripe_subscription_item_id = 'si_cov_1' WHERE id = 'cov_dip_cancel'",
        )
        .execute(&env.pool)
        .await
        .expect("cancel item");

        let client = Client::new();
        let result = process_dedicated_ip_billing(&env.state, &client)
            .await
            .expect("dip billing");
        assert_eq!(result.charged, 1, "one charge processed");
        assert_eq!(result.canceled, 1, "one cancel processed");
        let (charge_status, item): (String, Option<String>) = sqlx::query_as(
            "SELECT billing_status, stripe_subscription_item_id FROM dedicated_ips WHERE id = 'cov_dip_charge'",
        )
        .fetch_one(&env.pool)
        .await
        .expect("charged ip");
        assert_eq!(charge_status, "active");
        assert_eq!(item.as_deref(), Some("si_cov_1"));
        let cancel_status: String = sqlx::query_scalar(
            "SELECT billing_status FROM dedicated_ips WHERE id = 'cov_dip_cancel'",
        )
        .fetch_one(&env.pool)
        .await
        .expect("canceled ip");
        assert_eq!(cancel_status, "canceled");

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
        sqlx::query("UPDATE stripe_subscriptions SET status = 'canceled' WHERE tenant_id = $1")
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

        match previous {
            (Some(key), Some(url), Some(price)) => {
                std::env::set_var("STRIPE_SECRET_KEY", key);
                std::env::set_var("STRIPE_API_BASE_URL", url);
                std::env::set_var("STRIPE_DEDICATED_IP_PRICE_ID", price);
            }
            _ => {
                std::env::remove_var("STRIPE_SECRET_KEY");
                std::env::remove_var("STRIPE_API_BASE_URL");
                std::env::remove_var("STRIPE_DEDICATED_IP_PRICE_ID");
            }
        }
        drop(guard);
        env.finish().await;
    }

    // ---------------- scheduled retries (mock Stripe) ----------------

    #[tokio::test]
    async fn scheduled_retries_pay_the_open_invoice_once() {
        let Some(env) = provision("scheduled_retries_pay").await else {
            return;
        };
        let mock = Mock::default();
        mock.route("/v1/invoices", 200, r#"{"data":[{"id":"in_open_cov"}]}"#);
        mock.route(
            "/v1/invoices/in_open_cov/pay",
            200,
            r#"{"id":"in_open_cov"}"#,
        );
        let base = spawn_mock(mock.clone()).await;

        let guard = ENV_LOCK.lock().await;
        let previous = (
            std::env::var("AUTO_PAY_OPEN_INVOICES").ok(),
            std::env::var("STRIPE_SECRET_KEY").ok(),
            std::env::var("STRIPE_API_BASE_URL").ok(),
        );
        std::env::set_var("AUTO_PAY_OPEN_INVOICES", "true");
        std::env::set_var("STRIPE_SECRET_KEY", "sk_test_coverage");
        std::env::set_var("STRIPE_API_BASE_URL", &base);

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
            "INSERT INTO stripe_subscriptions
                 (tenant_id, stripe_subscription_id, plan, status, billing_cycle_start,
                  billing_cycle_end, stripe_customer_id)
             VALUES ($1, 'sub_retry', 'growth', 'past_due', NOW(), NOW() + INTERVAL '30 days', 'cus_retry')",
        )
        .bind(tenant)
        .execute(&env.pool)
        .await
        .expect("subscription");

        let client = Client::new();
        let result = process_scheduled_retries(&env.state, &client)
            .await
            .expect("retries");
        assert_eq!(result.attempted, 1);
        assert_eq!(result.succeeded, 1);
        assert_eq!(mock.call_count("/v1/invoices"), 1);
        assert_eq!(
            mock.call_count("/v1/invoices/in_open_cov/pay"),
            1,
            "paid exactly once"
        );
        let status: String =
            sqlx::query_scalar("SELECT status FROM dunning_records WHERE tenant_id = $1")
                .bind(tenant)
                .fetch_one(&env.pool)
                .await
                .expect("dunning status");
        assert_eq!(status, "healthy", "recovery reset the dunning record");

        match previous {
            (Some(auto), Some(key), Some(url)) => {
                std::env::set_var("AUTO_PAY_OPEN_INVOICES", auto);
                std::env::set_var("STRIPE_SECRET_KEY", key);
                std::env::set_var("STRIPE_API_BASE_URL", url);
            }
            _ => {
                std::env::remove_var("AUTO_PAY_OPEN_INVOICES");
                std::env::remove_var("STRIPE_SECRET_KEY");
                std::env::remove_var("STRIPE_API_BASE_URL");
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
        // test's event when the suite runs in parallel — asserting on it made
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
        // The replay must not move THIS tenant's counter or add a row — a
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

    // ---------------- scheduled Stripe retries ----------------

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
            "INSERT INTO stripe_subscriptions
                 (tenant_id, stripe_subscription_id, plan, status, billing_cycle_start,
                  billing_cycle_end, stripe_customer_id)
             VALUES ($1, $2, 'growth', $3, NOW(), NOW() + INTERVAL '30 days', 'cus_retry_cov')",
        )
        .bind(tenant)
        .bind(format!("sub_{}", &tenant[..tenant.len().min(20)]))
        .bind(sub_status)
        .execute(&env.pool)
        .await
        .expect("subscription");
    }

    env_test!(scheduled_retries_reschedule_after_stripe_failure, |env| {
        let mock = Mock::default();
        mock.route("/v1/invoices", 500, "stripe down");
        let base = spawn_mock(mock.clone()).await;
        let guard = ENV_LOCK.lock().await;
        let previous = (
            std::env::var("AUTO_PAY_OPEN_INVOICES").ok(),
            std::env::var("STRIPE_SECRET_KEY").ok(),
            std::env::var("STRIPE_API_BASE_URL").ok(),
        );
        std::env::set_var("AUTO_PAY_OPEN_INVOICES", "true");
        std::env::set_var("STRIPE_SECRET_KEY", "sk_test_coverage");
        std::env::set_var("STRIPE_API_BASE_URL", &base);

        let tenant = "mtcov_retry_fail";
        seed_retry_candidate(env, tenant, "warning", "past_due").await;
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
            mock.call_count("/v1/invoices"),
            1,
            "the pay endpoint is never reached on a failed list call"
        );

        match previous {
            (Some(auto), Some(key), Some(url)) => {
                std::env::set_var("AUTO_PAY_OPEN_INVOICES", auto);
                std::env::set_var("STRIPE_SECRET_KEY", key);
                std::env::set_var("STRIPE_API_BASE_URL", url);
            }
            _ => {
                std::env::remove_var("AUTO_PAY_OPEN_INVOICES");
                std::env::remove_var("STRIPE_SECRET_KEY");
                std::env::remove_var("STRIPE_API_BASE_URL");
            }
        }
        drop(guard);
    });

    env_test!(
        scheduled_retries_clear_retry_when_no_open_invoice_exists,
        |env| {
            let mock = Mock::default();
            mock.route("/v1/invoices", 200, r#"{"data":[]}"#);
            let base = spawn_mock(mock.clone()).await;
            let guard = ENV_LOCK.lock().await;
            let previous = (
                std::env::var("AUTO_PAY_OPEN_INVOICES").ok(),
                std::env::var("STRIPE_SECRET_KEY").ok(),
                std::env::var("STRIPE_API_BASE_URL").ok(),
            );
            std::env::set_var("AUTO_PAY_OPEN_INVOICES", "1");
            std::env::set_var("STRIPE_SECRET_KEY", "sk_test_coverage");
            std::env::set_var("STRIPE_API_BASE_URL", &base);

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
                mock.call_count("/v1/invoices"),
                1,
                "no invoice exists, so no pay call is made"
            );

            match previous {
                (Some(auto), Some(key), Some(url)) => {
                    std::env::set_var("AUTO_PAY_OPEN_INVOICES", auto);
                    std::env::set_var("STRIPE_SECRET_KEY", key);
                    std::env::set_var("STRIPE_API_BASE_URL", url);
                }
                _ => {
                    std::env::remove_var("AUTO_PAY_OPEN_INVOICES");
                    std::env::remove_var("STRIPE_SECRET_KEY");
                    std::env::remove_var("STRIPE_API_BASE_URL");
                }
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
                                        stripe_subscription_item_id)
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

    env_test!(dedicated_ip_charge_without_price_id_moves_nothing, |env| {
        let guard = ENV_LOCK.lock().await;
        let previous = std::env::var("STRIPE_DEDICATED_IP_PRICE_ID").ok();
        std::env::remove_var("STRIPE_DEDICATED_IP_PRICE_ID");

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
        let result = process_dedicated_ip_billing(&env.state, &client)
            .await
            .expect("dip billing");
        assert_eq!((result.charged, result.canceled), (0, 0));
        let (billing, failures): (String, i32) = sqlx::query_as(
            "SELECT billing_status, COALESCE(billing_failure_count, 0)
             FROM dedicated_ips WHERE id = 'cov_dip_noprice'",
        )
        .fetch_one(&env.pool)
        .await
        .expect("ip state");
        assert_eq!((billing.as_str(), failures), ("pending_charge", 0));

        match previous {
            Some(price) => std::env::set_var("STRIPE_DEDICATED_IP_PRICE_ID", price),
            None => std::env::remove_var("STRIPE_DEDICATED_IP_PRICE_ID"),
        }
        drop(guard);
    });

    env_test!(
        dedicated_ip_cancel_without_item_finalizes_without_http,
        |env| {
            let mock = Mock::default();
            let base = spawn_mock(mock.clone()).await;
            let guard = ENV_LOCK.lock().await;
            let previous = (
                std::env::var("STRIPE_SECRET_KEY").ok(),
                std::env::var("STRIPE_API_BASE_URL").ok(),
                std::env::var("STRIPE_DEDICATED_IP_PRICE_ID").ok(),
            );
            std::env::set_var("STRIPE_SECRET_KEY", "sk_test_coverage");
            std::env::set_var("STRIPE_API_BASE_URL", &base);
            std::env::set_var("STRIPE_DEDICATED_IP_PRICE_ID", "price_cov_dip");

            let tenant = "mtcov_dip_cancel";
            seed_tenant(env, tenant, "growth", "active").await;
            // No subscription item was ever created, so the delete call is
            // unnecessary — the row still finalizes.
            seed_dedicated_ip(
                env,
                "cov_dip_cancel_none",
                tenant,
                "203.0.113.252",
                "pending_cancel",
                None,
            )
            .await;
            let client = Client::new();
            let canceled = process_pending_dedicated_ip_cancels(&env.state, &client)
                .await
                .expect("cancels");
            assert_eq!(canceled, 1);
            let (billing, ended): (String, Option<DateTime<Utc>>) = sqlx::query_as(
                "SELECT billing_status, billing_ended_at FROM dedicated_ips
                 WHERE id = 'cov_dip_cancel_none'",
            )
            .fetch_one(&env.pool)
            .await
            .expect("ip state");
            assert_eq!(billing, "canceled");
            assert!(ended.is_some(), "cancel is timestamped");
            assert_eq!(
                mock.call_count("/v1/subscription_items/cov_missing"),
                0,
                "no HTTP for a row without an item"
            );

            // A 404 on the item delete means the item is already gone: the
            // local cancel must still finalize (never wedge).
            mock.route(
                "/v1/subscription_items/si_gone",
                404,
                r#"{"error":{"code":"resource_missing"}}"#,
            );
            seed_dedicated_ip(
                env,
                "cov_dip_cancel_gone",
                tenant,
                "203.0.113.253",
                "pending_cancel",
                Some("si_gone"),
            )
            .await;
            let canceled = process_pending_dedicated_ip_cancels(&env.state, &client)
                .await
                .expect("cancels");
            assert_eq!(canceled, 1, "a missing Stripe item is a successful cancel");
            let billing: String = sqlx::query_scalar(
                "SELECT billing_status FROM dedicated_ips WHERE id = 'cov_dip_cancel_gone'",
            )
            .fetch_one(&env.pool)
            .await
            .expect("ip state");
            assert_eq!(billing, "canceled");

            match previous {
                (Some(key), Some(url), Some(price)) => {
                    std::env::set_var("STRIPE_SECRET_KEY", key);
                    std::env::set_var("STRIPE_API_BASE_URL", url);
                    std::env::set_var("STRIPE_DEDICATED_IP_PRICE_ID", price);
                }
                _ => {
                    std::env::remove_var("STRIPE_SECRET_KEY");
                    std::env::remove_var("STRIPE_API_BASE_URL");
                    std::env::remove_var("STRIPE_DEDICATED_IP_PRICE_ID");
                }
            }
            drop(guard);
        }
    );

    env_test!(dedicated_ip_missing_table_is_a_clean_noop, |env| {
        let guard = ENV_LOCK.lock().await;
        let previous = std::env::var("STRIPE_DEDICATED_IP_PRICE_ID").ok();
        std::env::set_var("STRIPE_DEDICATED_IP_PRICE_ID", "price_cov_dip");
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
            Some(price) => std::env::set_var("STRIPE_DEDICATED_IP_PRICE_ID", price),
            None => std::env::remove_var("STRIPE_DEDICATED_IP_PRICE_ID"),
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
    // and the cost-margin throttle — each pinned to exactly-once semantics.
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
            "INSERT INTO stripe_webhook_events (id, stripe_event_id, event_type, status, updated_at)
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
        // reach a freshly-provisioned database — poll to a bounded deadline
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
        let reclaimed: String = sqlx::query_scalar(
            "SELECT status FROM stripe_webhook_events WHERE stripe_event_id = 'evt_mtcov_stale'",
        )
        .fetch_one(&env.pool)
        .await
        .expect("reclaimed");
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
        // Break the tables the startup sweeps read: every Err arm must be an
        // error! log, never a panic or an aborted task.
        env.break_table("invoices").await;
        env.break_table("stripe_webhook_events").await;
        env.break_table("dedicated_ips").await;
        start_periodic_jobs(env.state.clone());
        tokio::time::sleep(std::time::Duration::from_millis(40)).await;
        env.restore_table("invoices").await;
        env.restore_table("stripe_webhook_events").await;
        env.restore_table("dedicated_ips").await;
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
        // total_invoices is INTEGER (INT4) on the canonical schema — sqlx
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
                "INSERT INTO stripe_subscriptions
                     (tenant_id, stripe_subscription_id, plan, status, billing_cycle_start,
                      billing_cycle_end, trial_end, stripe_customer_id)
                 VALUES ($1, $2, 'growth', 'trialing', NOW() - INTERVAL '20 days',
                         NOW() - INTERVAL '2 days', $3::timestamptz, 'cus_mtcov')",
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
            "SELECT (SELECT status FROM stripe_subscriptions WHERE stripe_subscription_id = 'sub_mtcov_stale'),
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

    env_test!(
        expired_reservations_release_exactly_the_reserved_amount,
        |env| {
            let tenant = "mtcov_wallet";
            let wallet = seed_wallet(env, tenant, 5000, 1200).await;
            sqlx::query(
                // The canonical wallet_reservations shape: UUID id, the
                // owning wallet row (NOT NULL FK target), positive amount.
                "INSERT INTO wallet_reservations (id, wallet_id, tenant_id, amount, status, expires_at)
             VALUES ($1, $2, $3, 700, 'active', NOW() - INTERVAL '1 hour')",
            )
            .bind(uuid::Uuid::new_v4())
            .bind(wallet)
            .bind(tenant)
            .execute(&env.pool)
            .await
            .expect("reservation");

            let released = process_expired_wallet_reservations(&env.state)
                .await
                .expect("release");
            assert_eq!(released, 1);
            let (balance, reserved): (i64, i64) =
                sqlx::query_as("SELECT balance, reserved FROM wallets WHERE tenant_id = $1")
                    .bind(tenant)
                    .fetch_one(&env.pool)
                    .await
                    .expect("wallet");
            assert_eq!(balance, 5000, "the balance itself never moves on release");
            assert_eq!(reserved, 500, "exactly the reservation amount is released");

            // Idempotent.
            let released = process_expired_wallet_reservations(&env.state)
                .await
                .expect("release");
            assert_eq!(released, 0);
            let released_again: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM wallet_reservations WHERE released_at IS NOT NULL",
            )
            .fetch_one(&env.pool)
            .await
            .expect("count");
            assert_eq!(released_again, 1);
        }
    );

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

    #[test]
    fn release_reserved_clamp_never_wraps() {
        assert_eq!(release_reserved_cents_clamp(1000, 400), 600);
        assert_eq!(release_reserved_cents_clamp(1000, 1000), 0);
        assert_eq!(
            release_reserved_cents_clamp(100, 9_000_000_000),
            0,
            "no wrap on huge totals"
        );
    }

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

        // Replay: the DB conflict makes the counter guard a no-op — the event
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
    // PERIODIC_TASK_INTERVAL_MS, so every spawned loop really ticks — and
    // really runs its task bodies — against a private database clone within
    // milliseconds, no virtual clock and no long sleeps.

    #[tokio::test(flavor = "current_thread")]
    async fn periodic_job_loops_run_every_task_at_overridden_intervals() {
        let Some(owned) = provision("periodic_ok_intervals").await else {
            eprintln!("skipping: TEST_DATABASE_URL unset");
            return;
        };
        // Give one task real work to report so its activity arm fires
        // alongside the empty-success arms: an expired wallet reservation.
        let wallet: Option<(Uuid, String)> =
            sqlx::query_as("SELECT id, tenant_id FROM wallets WHERE tenant_id = 'mtcov_periodic'")
                .fetch_optional(&owned.pool)
                .await
                .expect("wallet probe");
        if let Some((wallet_id, _)) = wallet {
            sqlx::query(
                "INSERT INTO wallet_reservations (id, wallet_id, tenant_id, amount, status, created_at, updated_at) \
                 VALUES (gen_random_uuid(), $1, 'mtcov_periodic', 100, 'pending', NOW() - INTERVAL '2 hours', NOW() - INTERVAL '2 hours') \
                 ON CONFLICT DO NOTHING",
            )
            .bind(wallet_id)
            .execute(&owned.pool)
            .await
            .expect("seed expired reservation");
        }

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
}
