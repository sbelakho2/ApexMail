//! Campaign dispatch scheduler — the background job that keeps active
//! campaigns flowing through the platform pipeline.
//!
//! Runs in `bin/server.rs` as a spawned task with graceful shutdown:
//!
//! * every `SALES_DISPATCH_INTERVAL_SECS` (default 30) with ±20% jitter,
//! * for every active campaign: one bounded batch (`SALES_DISPATCH_BATCH_SIZE`)
//!   of due recipients through [`ProductionCampaignDispatcher`],
//! * concurrency-bounded across campaigns (semaphore,
//!   `SALES_DISPATCH_CONCURRENCY`),
//! * quota exhaustion pauses the campaign with an error state
//!   (`sales_campaigns.last_error`) — never a silent partial send,
//! * transient batch failures (DB hiccup, billing unavailable) leave the
//!   campaign active; the same batch is retried on the next tick. Retries
//!   are idempotent: the (campaign, recipient) idempotency key makes a
//!   double-send impossible even after a crash between ledger write and
//!   enqueue,
//! * a campaign with no due AND no cap-pending recipients left transitions
//!   to completed (frequency-capped recipients keep it active until the
//!   7-day cap window passes — audit E),
//! * after each batch, opens/clicks stats are reconciled from the
//!   platform `messages` counters maintained by the tracking service.

use std::sync::Arc;

use sqlx::PgPool;
use uuid::Uuid;

use crate::campaigns::{CampaignEmailDispatcher, CampaignManager, RecipientFunnel};
use crate::dispatcher::ProductionCampaignDispatcher;
use crate::types::SalesError;

/// Completion gate (audit E): an empty due batch finishes the campaign ONLY
/// when no recipient is still awaiting the frequency-cap window. A
/// capped-only campaign must stay active — the 7-day window (fix I-2
/// CAN-SPAM) eventually makes those recipients due again, and completing
/// early would strand them forever.
pub fn campaign_is_finished(funnel: &RecipientFunnel) -> bool {
    funnel.due == 0 && funnel.frequency_capped == 0
}

/// Which campaigns to process in one tick.
async fn active_campaigns(db: &PgPool, limit: i64) -> Result<Vec<(Uuid, String, String)>, SalesError> {
    let rows: Vec<(Uuid, String, String)> = sqlx::query_as(
        "SELECT id, tenant_id, template_id FROM sales_campaigns \
         WHERE status = 'active' \
         ORDER BY created_at ASC \
         LIMIT $1",
    )
    .bind(limit)
    .fetch_all(db)
    .await
    .map_err(|e| SalesError::Database(e.to_string()))?;
    Ok(rows)
}

/// Process one active campaign for one tick. Returns the number of
/// recipients enqueued.
pub async fn process_campaign(
    manager: &CampaignManager,
    dispatcher: &Arc<ProductionCampaignDispatcher>,
    batch_size: usize,
    campaign_id: Uuid,
    tenant_id: &str,
    template_id: &str,
) -> Result<usize, SalesError> {
    let recipients = manager.due_recipients(tenant_id, campaign_id, batch_size as i64).await?;

    if recipients.is_empty() {
        // Nothing due right now. Two very different causes (audit E):
        // * every recipient is sent/suppressed → the campaign is DONE;
        // * recipients remain but are frequency-capped (7-day window) → the
        //   campaign must STAY active so later ticks dispatch them once the
        //   cap window passes. Completing here stranded them forever.
        let funnel = manager
            .recipient_funnel_counts(tenant_id, campaign_id)
            .await?;
        if !campaign_is_finished(&funnel) {
            tracing::info!(
                tenant_id = %tenant_id,
                campaign_id = %campaign_id,
                capped_pending = funnel.frequency_capped,
                "campaign stays active — recipients await the frequency-cap window"
            );
            return Ok(0);
        }
        manager.complete_campaign(campaign_id).await?;
        tracing::info!(
            tenant_id = %tenant_id,
            campaign_id = %campaign_id,
            "campaign completed — no due or cap-pending recipients remain"
        );
        return Ok(0);
    }

    let enqueued = dispatcher
        .dispatch(tenant_id, campaign_id, template_id, &recipients)
        .await;

    match enqueued {
        Ok(n) => {
            // Fold tracking-service open/click counters back into the
            // campaign columns. Non-fatal: a stats blip must not stop sends.
            if let Err(e) = manager.reconcile_campaign_stats(campaign_id).await {
                tracing::warn!(
                    error = %e,
                    campaign_id = %campaign_id,
                    "campaign stats reconciliation failed (non-fatal)"
                );
            }
            Ok(n)
        }
        Err(SalesError::QuotaExhausted(_)) => {
            // Pauses WITH an error state — operators see why. Recipients
            // dispatched before exhaustion are ledger-stamped; the rest
            // resume if the campaign is restarted after quota resets.
            manager
                .pause_with_error(campaign_id, "email quota exhausted")
                .await?;
            tracing::warn!(
                tenant_id = %tenant_id,
                campaign_id = %campaign_id,
                "campaign paused: email quota exhausted"
            );
            metrics::counter!("sales_campaign_paused_total", "reason" => "quota_exhausted")
                .increment(1);
            Err(SalesError::QuotaExhausted(tenant_id.to_string()))
        }
        Err(e) => {
            // Transient failure: campaign stays active; the batch is retried
            // idempotently on the next tick.
            tracing::error!(
                error = %e,
                tenant_id = %tenant_id,
                campaign_id = %campaign_id,
                "campaign dispatch batch failed — will retry on next tick"
            );
            metrics::counter!("sales_campaign_dispatch_errors_total").increment(1);
            Err(e)
        }
    }
}

/// One scheduler tick: dispatch one bounded batch for every active campaign,
/// concurrency-bounded across campaigns.
pub async fn tick(
    manager: &CampaignManager,
    dispatcher: &Arc<ProductionCampaignDispatcher>,
    batch_size: usize,
    concurrency: usize,
) -> Vec<Result<usize, SalesError>> {
    let campaigns = match active_campaigns(manager.db(), 500).await {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(error = %e, "dispatch tick: failed to list active campaigns");
            return vec![Err(e)];
        }
    };

    let semaphore = Arc::new(tokio::sync::Semaphore::new(concurrency.max(1)));
    let mut handles = Vec::with_capacity(campaigns.len());

    for (campaign_id, tenant_id, template_id) in campaigns {
        let permit = semaphore.clone().acquire_owned().await;
        let manager = manager.clone();
        let dispatcher = dispatcher.clone();
        handles.push(tokio::spawn(async move {
            let _permit = permit;
            process_campaign(&manager, &dispatcher, batch_size, campaign_id, &tenant_id, &template_id)
                .await
        }));
    }

    let mut results = Vec::with_capacity(handles.len());
    for handle in handles {
        match handle.await {
            Ok(result) => results.push(result),
            Err(join_err) => {
                tracing::error!(error = %join_err, "dispatch tick: campaign task panicked");
                results.push(Err(SalesError::Internal(anyhow::anyhow!(
                    "campaign dispatch task failed: {join_err}"
                ))));
            }
        }
    }
    results
}

/// Run the scheduler loop until `shutdown` resolves. Jittered interval
/// avoids thundering herds when multiple replicas restart together.
pub async fn run(
    manager: CampaignManager,
    dispatcher: Arc<ProductionCampaignDispatcher>,
    interval_secs: u64,
    batch_size: usize,
    concurrency: usize,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
) {
    let base = std::time::Duration::from_secs(interval_secs.max(1));
    let mut shutdown = Box::pin(shutdown);
    tracing::info!(
        interval_secs = interval_secs,
        batch_size = batch_size,
        concurrency = concurrency,
        "campaign dispatch scheduler started"
    );

    loop {
        // ±20% jitter on the interval.
        let jitter_ms = rand_jitter_ms(base);
        let sleep = tokio::time::sleep(base + std::time::Duration::from_millis(jitter_ms));

        tokio::select! {
            _ = &mut shutdown => {
                tracing::info!("campaign dispatch scheduler stopping");
                return;
            }
            _ = sleep => {}
        }

        let results = tick(&manager, &dispatcher, batch_size, concurrency).await;
        let total_enqueued: usize = results.iter().map(|r| r.as_ref().unwrap_or(&0)).sum();
        if total_enqueued > 0 || results.iter().any(|r| r.is_err()) {
            tracing::info!(
                campaigns = results.len(),
                enqueued = total_enqueued,
                errors = results.iter().filter(|r| r.is_err()).count(),
                "dispatch tick complete"
            );
        }
    }
}

/// Deterministic-ish jitter derived from the clock — no extra RNG dep.
fn rand_jitter_ms(base: std::time::Duration) -> u64 {
    let ms = base.as_millis() as u64;
    let factor = (std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos() as u64)
        .unwrap_or(0))
        % 100;
    (ms / 5) * factor / 100 // up to +20%
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jitter_stays_within_twenty_percent() {
        let base = std::time::Duration::from_secs(30);
        for _ in 0..200 {
            let j = rand_jitter_ms(base);
            assert!(j <= 6_000, "jitter {j}ms exceeds 20% of 30s");
        }
    }

    fn funnel(due: i64, capped: i64) -> RecipientFunnel {
        RecipientFunnel {
            total: due + capped,
            already_sent: 0,
            suppressed_local: 0,
            suppressed_platform: 0,
            frequency_capped: capped,
            due,
        }
    }

    /// E: the funnel gate — a capped-only campaign is NOT finished, so the
    /// scheduler keeps it active until the cap window passes; a fully
    /// drained campaign (or one whose remainder is suppressed/sent)
    /// completes.
    #[test]
    fn completion_requires_no_due_and_no_capped_recipients() {
        // Fully drained → finished.
        assert!(campaign_is_finished(&funnel(0, 0)));
        // Suppressed/sent remainders funnel to zero due/capped → finished.
        assert!(campaign_is_finished(&RecipientFunnel {
            total: 5,
            already_sent: 3,
            suppressed_local: 1,
            suppressed_platform: 1,
            ..funnel(0, 0)
        }));
        // Capped-only → NOT finished: the 7-day window will make them due.
        assert!(
            !campaign_is_finished(&funnel(0, 4)),
            "capped-only campaign must stay active"
        );
        // Due recipients exist → not finished (sanity; the scheduler only
        // consults the gate on an empty batch).
        assert!(!campaign_is_finished(&funnel(2, 0)));
    }

    /// E (integration, local Postgres): a capped-only campaign stays active
    /// across scheduler ticks; once the cap window passes (simulated by
    /// back-dating the recipients' last sends beyond 7 days) the recipients
    /// become due again and the campaign then completes. Requires the
    /// sales-autopilot schema (`initialize_schema`).
    #[ignore = "requires local PostgreSQL with the sales-autopilot schema"]
    #[tokio::test]
    async fn capped_only_campaign_stays_active_until_cap_window_passes() {
        let db = sqlx::postgres::PgPoolOptions::new()
            .max_connections(2)
            .connect(&std::env::var("TEST_DATABASE_URL").unwrap_or_else(|_| {
                "postgres://apexmail:apexmail@localhost:5432/apexmail".to_string()
            }))
            .await
            .unwrap();
        crate::routes::initialize_schema(&db).await.unwrap();

        let manager = CampaignManager::new(10, db.clone());
        let campaign = manager
            .create_campaign(
                "sched-e-test".into(),
                "capped".into(),
                "t".into(),
                "all".into(),
            )
            .await
            .unwrap();
        manager
            .add_recipients(
                "sched-e-test",
                campaign.id,
                vec!["capped@example.com".into()],
            )
            .await
            .unwrap();

        // Make the recipient capped: the weekly cap is
        // RECIPIENT_FREQUENCY_CAP_WEEKLY (3) sends within 7 days, and each
        // campaign contributes at most ONE ledger row per recipient (PK
        // campaign_id+email) — so three filler campaigns with a recent send
        // put the recipient at the cap.
        let mut filler_ids = Vec::new();
        for n in 0..3 {
            let filler = manager
                .create_campaign(
                    "sched-e-test".into(),
                    format!("filler-{n}"),
                    "t".into(),
                    "all".into(),
                )
                .await
                .unwrap();
            manager
                .add_recipients("sched-e-test", filler.id, vec!["capped@example.com".into()])
                .await
                .unwrap();
            sqlx::query(
                "UPDATE sales_campaign_recipients SET sent_at = NOW() - INTERVAL '1 hour' \
                 WHERE campaign_id = $1",
            )
            .bind(filler.id)
            .execute(&db)
            .await
            .unwrap();
            filler_ids.push(filler.id);
        }
        // The campaign under test starts unsent (only the cap signals from
        // the filler sends above remain).
        sqlx::query(
            "UPDATE sales_campaign_recipients SET sent_at = NULL WHERE campaign_id = $1",
        )
        .bind(campaign.id)
        .execute(&db)
        .await
        .unwrap();
        sqlx::query("UPDATE sales_campaigns SET status = 'active' WHERE id = $1")
            .bind(campaign.id)
            .execute(&db)
            .await
            .unwrap();

        // Tick with the cap in force: the funnel must show capped=1 → the
        // gate keeps the campaign active even though nothing is due.
        let funnel = manager
            .recipient_funnel_counts("sched-e-test", campaign.id)
            .await
            .unwrap();
        assert_eq!(funnel.due, 0, "recipient is capped, not due");
        assert_eq!(funnel.frequency_capped, 1);
        assert!(
            !campaign_is_finished(&funnel),
            "capped-only campaign must not complete"
        );

        // Back-date every send past the 7-day window: the recipient becomes
        // due again, so after a (hypothetical) dispatch drain the gate opens.
        for filler_id in &filler_ids {
            sqlx::query(
                "UPDATE sales_campaign_recipients SET sent_at = NOW() - INTERVAL '8 days' \
                 WHERE campaign_id = $1",
            )
            .bind(filler_id)
            .execute(&db)
            .await
            .unwrap();
        }
        let funnel = manager
            .recipient_funnel_counts("sched-e-test", campaign.id)
            .await
            .unwrap();
        assert_eq!(funnel.due, 1, "cap window passed — recipient is due again");
        assert_eq!(funnel.frequency_capped, 0);
        assert!(!campaign_is_finished(&funnel), "due recipient blocks completion");

        // Drain it: now the campaign is genuinely finished.
        sqlx::query(
            "UPDATE sales_campaign_recipients SET sent_at = NOW() WHERE campaign_id = $1",
        )
        .bind(campaign.id)
        .execute(&db)
        .await
        .unwrap();
        let funnel = manager
            .recipient_funnel_counts("sched-e-test", campaign.id)
            .await
            .unwrap();
        assert_eq!(funnel.due, 0);
        assert_eq!(funnel.frequency_capped, 0);
        assert!(campaign_is_finished(&funnel));

        // Cleanup.
        for campaign_id in std::iter::once(campaign.id).chain(filler_ids) {
            sqlx::query("DELETE FROM sales_campaigns WHERE id = $1")
                .bind(campaign_id)
                .execute(&db)
                .await
                .unwrap();
        }
    }
}
