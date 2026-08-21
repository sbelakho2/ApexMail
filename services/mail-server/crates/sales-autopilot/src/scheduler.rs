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
//! * a campaign with no due recipients left transitions to completed,
//! * after each batch, opens/clicks stats are reconciled from the
//!   platform `messages` counters maintained by the tracking service.

use std::sync::Arc;

use sqlx::PgPool;
use uuid::Uuid;

use crate::campaigns::{CampaignEmailDispatcher, CampaignManager};
use crate::dispatcher::ProductionCampaignDispatcher;
use crate::types::SalesError;

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
        // Nothing due (all sent / suppressed / capped): finish the campaign.
        manager.complete_campaign(campaign_id).await?;
        tracing::info!(
            tenant_id = %tenant_id,
            campaign_id = %campaign_id,
            "campaign completed — no due recipients remain"
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
}
