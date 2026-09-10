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
            Instant::now() + DEDICATED_IP_TASK_INTERVAL,
            DEDICATED_IP_TASK_INTERVAL,
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
            Instant::now() + METERING_TASK_INTERVAL,
            METERING_TASK_INTERVAL,
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
            Instant::now() + WALLET_CLEANUP_INTERVAL,
            WALLET_CLEANUP_INTERVAL,
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
            Instant::now() + USAGE_ALERT_TASK_INTERVAL,
            USAGE_ALERT_TASK_INTERVAL,
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
            Instant::now() + COST_MARGIN_TASK_INTERVAL,
            COST_MARGIN_TASK_INTERVAL,
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
            .unwrap_or(DAILY_TASK_INTERVAL);
        let mut interval = interval_at(Instant::now() + initial_delay, DAILY_TASK_INTERVAL);
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
        let mut interval = interval_at(Instant::now() + HOURLY_TASK_INTERVAL, HOURLY_TASK_INTERVAL);
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

        let mut interval = interval_at(Instant::now() + HOURLY_TASK_INTERVAL, HOURLY_TASK_INTERVAL);
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
            Instant::now() + KMD_GENERATION_INTERVAL,
            KMD_GENERATION_INTERVAL,
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
            Instant::now() + INVOICE_ARCHIVE_INTERVAL,
            INVOICE_ARCHIVE_INTERVAL,
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
            DAILY_TASK_INTERVAL,
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
            DAILY_TASK_INTERVAL,
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
            Instant::now() + DERIVED_USAGE_SWEEP_INITIAL_DELAY,
            DAILY_TASK_INTERVAL,
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
    let already_closed: bool = sqlx::query_scalar::<_, Option<i64>>(
        "SELECT 1 FROM month_end_closings WHERE tax_year = $1 AND tax_month = $2 LIMIT 1",
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
            ON CONFLICT (id) DO NOTHING
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

        let already_credited: Option<i64> = sqlx::query_scalar(
            "SELECT 1 FROM sla_credits WHERE tenant_id = $1 AND period_month = $2 LIMIT 1",
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
