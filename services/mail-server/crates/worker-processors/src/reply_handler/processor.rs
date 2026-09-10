//! Reply handler processor implementation.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use chrono::Utc;
use sqlx::PgPool;
use tokio::sync::Notify;
use tokio::time::sleep;
use tracing::{debug, error, info, warn};

use super::classifier::classify;
use super::types::{ActionType, ClassificationResult, InboundMessage, ReplyClassification};
use crate::common::{ProcessorError, ProcessorResult, ReplyHandlerConfig};

/// Age at which a reply-handler claim is considered stale and may be
/// reclaimed by any worker. Mirrors the analytics processor's 10-minute
/// stale-claim window (see `AnalyticsProcessor::fetch_events`).
pub const CLAIM_STALENESS: &str = "10 minutes";

/// Claim query for inbound replies (F2:timestamped claim).
///
/// The claim is `processing = true, processing_at = NOW()`; rows whose
/// claim is older than [`CLAIM_STALENESS`] are reclaimed, so a worker that
/// died between claiming and finishing can no longer strand a message in
/// `processing = true` forever (the previous bare boolean had no expiry).
/// The `{claim_staleness}` placeholder is substituted with the interval
/// built from [`CLAIM_STALENESS`] at fetch time.
const FETCH_MESSAGES_SQL: &str = r#"
            UPDATE inbound_messages
            SET processing = true, processing_at = NOW()
            WHERE id IN (
                SELECT id
                FROM inbound_messages
                WHERE processed_at IS NULL
                  AND (
                      processing = false
                      OR processing_at < NOW() - {claim_staleness}
                  )
                ORDER BY received_at ASC
                LIMIT $1
                FOR UPDATE SKIP LOCKED
            )
            RETURNING
                id, tenant_id as "tenantId", lead_id as "leadId",
                from_email as "fromEmail", to_email as "toEmail",
                COALESCE(subject, '') as subject,
                -- O-16.5: Truncate body fields at the SQL level to enforce max_reply_size
                LEFT(body_text, $2::int) as "bodyText",
                LEFT(body_html, $2::int) as "bodyHtml",
                headers, received_at as "receivedAt",
                processed_at as "processedAt", classification,
                message_id_header as "messageIdHeader"
        "#;

/// The stale-claim reclaim bound as a SQL interval expression, derived
/// from [`CLAIM_STALENESS`] so the two can never drift.
fn claim_staleness_interval() -> String {
    format!("interval '{CLAIM_STALENESS}'")
}

/// Completion write (F2): clears the claim fully — `processing_at = NULL`
/// next to `processing = false`, mirroring the analytics processor's
/// `reset_processing`.
const MARK_PROCESSED_SQL: &str = r#"
            UPDATE inbound_messages
            SET processed_at = NOW(),
                processing = false,
                processing_at = NULL,
                classification = $1,
                classification_confidence = $2,
                suggested_action = $3,
                action_taken = $4
            WHERE id = $5
        "#;

/// Reset a stale/failed claim (F2): release the row for immediate re-claim
/// instead of waiting out [`CLAIM_STALENESS`].
const RESET_CLAIM_SQL: &str = r#"
            UPDATE inbound_messages
            SET processing = false, processing_at = NULL
            WHERE id = $1 AND processing = true
        "#;

/// Reply handler processor.
pub struct ReplyHandler {
    db: PgPool,
    config: ReplyHandlerConfig,
    /// F67: durable reply-analytics handoff (canonical reply_events model,
    /// migration 159). Committed with inbound acceptance in
    /// process_message_inner — an analytics failure fails the message so the
    /// claim resets and the handoff retries idempotently.
    reply_analytics: analytics::reply_tracking::ReplyTrackingService,
    is_running: AtomicBool,
    active_jobs: AtomicUsize,
    shutdown_notify: Arc<Notify>,
}

impl ReplyHandler {
    /// Create a new reply handler.
    pub fn new(db: PgPool, config: ReplyHandlerConfig) -> Self {
        Self {
            reply_analytics: analytics::reply_tracking::ReplyTrackingService::new(db.clone()),
            db,
            config,
            is_running: AtomicBool::new(false),
            active_jobs: AtomicUsize::new(0),
            shutdown_notify: Arc::new(Notify::new()),
        }
    }

    /// Ensure the timestamped-claim column exists (F2).
    ///
    /// `inbound_messages` historically carried only the bare `processing`
    /// boolean (no expiry). The timestamped claim needs `processing_at`,
    /// which the migration chain only added to `analytics_queue`. Schema
    /// changes are owned by SQL migrations, but the claim cannot be made
    /// expirable without the column, so — exactly like migration 088's own
    /// guarded reconciliation ALTERs — the column is added idempotently
    /// (`IF NOT EXISTS`) at startup. On an already-migrated database this
    /// is a no-op.
    async fn ensure_timestamped_claim_column(&self) -> ProcessorResult<()> {
        sqlx::query(
            "ALTER TABLE inbound_messages ADD COLUMN IF NOT EXISTS processing_at TIMESTAMPTZ",
        )
        .execute(&self.db)
        .await?;
        Ok(())
    }

    /// Start the processor.
    pub async fn start(self: Arc<Self>) -> ProcessorResult<()> {
        info!(
            concurrency = self.config.base.concurrency,
            "Starting reply handler"
        );

        self.ensure_timestamped_claim_column().await?;

        self.is_running.store(true, Ordering::SeqCst);
        self.poll_loop().await;

        Ok(())
    }

    /// Stop the processor gracefully.
    pub async fn stop(&self) -> ProcessorResult<()> {
        info!("Stopping reply handler");
        self.is_running.store(false, Ordering::SeqCst);
        self.shutdown_notify.notify_waiters();

        // Wait for active jobs
        let max_wait = Duration::from_secs(30);
        let start = Instant::now();

        while self.active_jobs.load(Ordering::SeqCst) > 0 && start.elapsed() < max_wait {
            sleep(Duration::from_millis(100)).await;
        }

        info!("Reply handler stopped");
        Ok(())
    }

    /// Main poll loop.
    async fn poll_loop(&self) {
        while self.is_running.load(Ordering::SeqCst) {
            // Check capacity
            let available = self
                .config
                .base
                .concurrency
                .saturating_sub(self.active_jobs.load(Ordering::SeqCst));
            if available == 0 {
                sleep(Duration::from_millis(100)).await;
                continue;
            }

            match self.fetch_messages(available).await {
                Ok(messages) if messages.is_empty() => {
                    tokio::select! {
                        _ = sleep(self.config.base.poll_interval) => {}
                        _ = self.shutdown_notify.notified() => break,
                    }
                }
                Ok(messages) => {
                    for msg in messages {
                        let msg_id = msg.id.clone();
                        if let Err(e) = self.process_message(msg).await {
                            error!(msg_id = %msg_id, error = %e, "Failed to process message");
                            // F2:release the claim immediately so the row is
                            // retried on the next poll instead of waiting out
                            // the staleness window (mirrors the analytics
                            // processor's reset_processing).
                            if let Err(reset_err) = self.reset_claim(&msg_id).await {
                                error!(
                                    msg_id = %msg_id,
                                    error = %reset_err,
                                    "Failed to reset processing claim; the stale-claim reclaim in fetch_messages will recover it"
                                );
                            }
                        }
                    }
                    sleep(Duration::from_millis(100)).await;
                }
                Err(e) => {
                    error!(error = %e, "Failed to fetch messages");
                    sleep(self.config.base.poll_interval).await;
                }
            }
        }
    }

    /// Fetch unprocessed inbound messages (O-16.5: with size truncation).
    ///
    /// F2:the claim is TIMESTAMPED (`processing_at = NOW()`), and rows
    /// whose claim is older than [`CLAIM_STALENESS`] are reclaimed —
    /// mirroring the analytics processor's stale-claim pattern — so a
    /// crashed worker can no longer strand a reply in `processing = true`
    /// forever.
    async fn fetch_messages(&self, limit: usize) -> ProcessorResult<Vec<InboundMessage>> {
        let claim_sql =
            FETCH_MESSAGES_SQL.replace("{claim_staleness}", &claim_staleness_interval());
        let messages = sqlx::query_as::<_, InboundMessage>(&claim_sql)
            .bind(limit as i64)
            .bind(self.config.max_reply_size as i64)
            .fetch_all(&self.db)
            .await?;

        Ok(messages)
    }

    /// F2:release a claim on a message whose processing failed, so the next
    /// poll retries it immediately (no need to wait out the staleness
    /// window).
    async fn reset_claim(&self, msg_id: &str) -> ProcessorResult<()> {
        sqlx::query(RESET_CLAIM_SQL)
            .bind(msg_id)
            .execute(&self.db)
            .await?;
        Ok(())
    }

    /// Process a single inbound message.
    async fn process_message(&self, msg: InboundMessage) -> ProcessorResult<()> {
        self.active_jobs.fetch_add(1, Ordering::SeqCst);
        let start = Instant::now();

        let result = self.process_message_inner(&msg).await;

        self.active_jobs.fetch_sub(1, Ordering::SeqCst);

        let duration = start.elapsed();
        debug!(
            msg_id = %msg.id,
            duration_ms = duration.as_millis(),
            "Message processed"
        );

        result
    }

    async fn process_message_inner(&self, msg: &InboundMessage) -> ProcessorResult<()> {
        // Get text content (O-16.5: already truncated at SQL level in fetch_messages)
        let body = msg.body_text.as_deref().unwrap_or("");

        // Classify the reply
        let classification = classify(&msg.subject, body);

        debug!(
            msg_id = %msg.id,
            classification = ?classification.classification,
            confidence = classification.confidence,
            "Classified reply"
        );

        // O-16.6: Gate auto-execute behind config flag + confidence threshold.
        // Previously, `auto_execute` from the classification result was followed
        // unconditionally. Now it respects the admin-configured policy:
        // - `auto_suppress` must be enabled in config
        // - confidence must meet the configured threshold
        let can_auto_execute = self.config.auto_suppress
            && classification.confidence >= self.config.auto_suppress_confidence_threshold;

        let action_taken = if classification.suggested_action.auto_execute && can_auto_execute {
            debug!(
                msg_id = %msg.id,
                action = ?classification.suggested_action.action,
                confidence = classification.confidence,
                "Auto-executing reply action"
            );
            self.execute_action(msg, &classification).await?
        } else if classification.suggested_action.auto_execute && !can_auto_execute {
            info!(
                msg_id = %msg.id,
                action = ?classification.suggested_action.action,
                confidence = classification.confidence,
                auto_suppress = self.config.auto_suppress,
                "Reply action blocked by policy — would auto-execute but config disallows it"
            );
            None
        } else {
            None
        };

        // F67: commit the durable reply-analytics handoff WITH inbound
        // acceptance — before the row is marked processed. A failure here
        // fails the whole message (claim reset → retry), and the handoff is
        // idempotent through restarts (tenant-qualified message identity),
        // so a retry after a crash between the two writes collapses to one
        // reply event. Messages without a tenant are skipped: analytics is
        // tenant-scoped.
        if let Some(tenant_id) = msg.tenant_id.as_deref() {
            let in_reply_to = msg.in_reply_to();
            let handoff = analytics::reply_tracking::InboundReplyHandoff {
                inbound_id: &msg.id,
                tenant_id,
                message_id_header: msg.message_id_header.as_deref(),
                in_reply_to: in_reply_to.as_deref(),
                from_email: &msg.from_email,
                subject: &msg.subject,
                body,
                headers: msg.analytics_headers(),
                received_at: msg.received_at,
            };
            self.reply_analytics
                .process_inbound_reply(&handoff)
                .await
                .map_err(|e| {
                    ProcessorError::Internal(anyhow::anyhow!(
                        "reply analytics handoff failed for {}: {e}",
                        msg.id
                    ))
                })?;
        }

        // Update the message record
        sqlx::query(MARK_PROCESSED_SQL)
            .bind(classification.classification.as_str())
            .bind(classification.confidence)
            .bind(serde_json::to_value(&classification.suggested_action)?)
            .bind(&action_taken)
            .bind(&msg.id)
            .execute(&self.db)
            .await?;

        // If there's a lead, update lead status
        if let Some(ref lead_id) = msg.lead_id {
            self.update_lead_status(lead_id, &classification).await?;
        }

        Ok(())
    }

    /// Execute the suggested action.
    async fn execute_action(
        &self,
        msg: &InboundMessage,
        classification: &ClassificationResult,
    ) -> ProcessorResult<Option<String>> {
        match classification.suggested_action.action {
            ActionType::Snooze => {
                let days = classification
                    .suggested_action
                    .parameters
                    .get("duration_days")
                    .and_then(|v| v.as_i64())
                    .unwrap_or(7);

                if let Some(ref lead_id) = msg.lead_id {
                    let snooze_until = Utc::now() + chrono::Duration::days(days);
                    sqlx::query(
                        "UPDATE sales_leads SET snoozed_until = $1, status = 'snoozed' WHERE id = $2",
                    )
                    .bind(snooze_until)
                    .bind(lead_id)
                    .execute(&self.db)
                    .await?;
                }

                Ok(Some(format!("snoozed_for_{}_days", days)))
            }
            ActionType::Suppress => {
                // Add to suppressions (needs a tenant; rows from unknown
                // tenants are skipped so the NOT NULL FK is never violated).
                let Some(ref tenant_id) = msg.tenant_id else {
                    warn!(msg_id = %msg.id, "Suppress action skipped — inbound message has no tenant_id");
                    return Ok(Some("skipped_no_tenant".to_string()));
                };
                sqlx::query(
                    r#"
                    INSERT INTO suppressions (id, tenant_id, email, reason, created_at)
                    VALUES ($1, $2, $3, $4, NOW())
                    ON CONFLICT (tenant_id, email) DO NOTHING
                    "#,
                )
                // suppressions.id is VARCHAR(26), so use a short random
                // suffix ("sup_" + 18 hex chars = 22 chars).
                .bind(format!(
                    "sup_{}",
                    &uuid::Uuid::new_v4().simple().to_string()[..18]
                ))
                .bind(tenant_id)
                .bind(&msg.from_email)
                .bind("not_interested")
                .execute(&self.db)
                .await?;

                Ok(Some("suppressed".to_string()))
            }
            ActionType::Unsubscribe => {
                let Some(ref tenant_id) = msg.tenant_id else {
                    warn!(msg_id = %msg.id, "Unsubscribe action skipped — inbound message has no tenant_id");
                    return Ok(Some("skipped_no_tenant".to_string()));
                };
                // Add to suppressions with unsubscribe reason
                sqlx::query(
                    r#"
                    INSERT INTO suppressions (id, tenant_id, email, reason, created_at)
                    VALUES ($1, $2, $3, 'unsubscribe', NOW())
                    ON CONFLICT (tenant_id, email) DO UPDATE SET reason = 'unsubscribe'
                    "#,
                )
                .bind(format!(
                    "sup_{}",
                    &uuid::Uuid::new_v4().simple().to_string()[..18]
                ))
                .bind(tenant_id)
                .bind(&msg.from_email)
                .execute(&self.db)
                .await?;

                Ok(Some("unsubscribed".to_string()))
            }
            ActionType::FlagSales => {
                if let Some(ref lead_id) = msg.lead_id {
                    sqlx::query(
                        "UPDATE sales_leads SET status = 'interested', priority = 'high', updated_at = NOW() WHERE id = $1",
                    )
                    .bind(lead_id)
                    .execute(&self.db)
                    .await?;
                }

                Ok(Some("flagged_for_sales".to_string()))
            }
            ActionType::Escalate => {
                // Log escalation (would typically create a task or notification)
                warn!(
                    msg_id = %msg.id,
                    from = %msg.from_email,
                    classification = ?classification.classification,
                    "Message escalated for review"
                );

                Ok(Some("escalated".to_string()))
            }
            ActionType::Ignore => Ok(Some("ignored".to_string())),
            _ => Ok(None),
        }
    }

    /// Update lead status based on classification.
    async fn update_lead_status(
        &self,
        lead_id: &str,
        classification: &ClassificationResult,
    ) -> ProcessorResult<()> {
        let new_status = match classification.classification {
            ReplyClassification::Interested
            | ReplyClassification::TellMeMore
            | ReplyClassification::PositiveIntent => "interested",
            ReplyClassification::NotInterested => "lost",
            ReplyClassification::MeetingRequest => "demo_requested",
            ReplyClassification::OutOfOffice => "snoozed",
            ReplyClassification::WrongPerson => "wrong_contact",
            ReplyClassification::Unsubscribe => "unsubscribed",
            ReplyClassification::Complaint => "complaint",
            _ => return Ok(()), // Don't update for unknown/other
        };

        sqlx::query(
            "UPDATE sales_leads SET status = $1, last_reply_at = NOW(), updated_at = NOW() WHERE id = $2",
        )
        .bind(new_status)
        .bind(lead_id)
        .execute(&self.db)
        .await?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // F2:the claim must be timestamped AND expirable. These pin the SQL
    // shape (same technique as queue-provider's provider.rs tests) so the
    // stale-claim reclaim cannot silently regress.
    #[test]
    fn claim_is_timestamped() {
        assert!(
            FETCH_MESSAGES_SQL.contains("SET processing = true, processing_at = NOW()"),
            "the claim must stamp processing_at"
        );
    }

    #[test]
    fn stale_claims_are_reclaimed() {
        assert!(
            FETCH_MESSAGES_SQL.contains("processing = false")
                && FETCH_MESSAGES_SQL.contains("OR processing_at < NOW()"),
            "fetch must reclaim rows whose claim expired, not filter on the bare boolean"
        );
        assert_eq!(CLAIM_STALENESS, "10 minutes");
        // The template substitutes the interval from CLAIM_STALENESS, so
        // the window can never drift from the documented constant.
        assert!(FETCH_MESSAGES_SQL.contains("{claim_staleness}"));
        let interval = claim_staleness_interval();
        assert_eq!(interval, "interval '10 minutes'");
        assert!(
            FETCH_MESSAGES_SQL
                .replace("{claim_staleness}", &interval)
                .contains("processing_at < NOW() - interval '10 minutes'"),
            "the substituted reclaim window must match CLAIM_STALENESS"
        );
    }

    #[test]
    fn unclaimed_rows_are_still_eligible() {
        // New rows (never claimed) must remain fetchable: the OR arm covers
        // processing = false rows regardless of processing_at.
        assert!(FETCH_MESSAGES_SQL.contains("WHERE processed_at IS NULL"));
        assert!(FETCH_MESSAGES_SQL.contains("FOR UPDATE SKIP LOCKED"));
    }

    #[test]
    fn completion_and_reset_clear_the_claim_fully() {
        assert!(
            MARK_PROCESSED_SQL.contains("processing = false")
                && MARK_PROCESSED_SQL.contains("processing_at = NULL"),
            "completion must clear the timestamped claim"
        );
        assert!(
            RESET_CLAIM_SQL.contains("SET processing = false, processing_at = NULL"),
            "reset must release the claim for immediate re-claim"
        );
    }

    // ── F67: durable reply-analytics handoff ───────────────────────────

    /// The fetch must surface the stable provider/inbound event identity
    /// (Message-ID header) to the analytics adapter.
    #[test]
    fn fetch_selects_the_message_id_header() {
        assert!(
            FETCH_MESSAGES_SQL.contains("message_id_header as \"messageIdHeader\""),
            "the analytics handoff needs the inbound Message-ID"
        );
    }

    /// Ingest a real inbound fixture through the production entry point,
    /// retry it, and restart before consumption: exactly one reply event
    /// appears and metrics update only for its tenant. DB-backed (unit test
    /// so the private processing path is reachable); gated on
    /// TEST_DATABASE_URL via the canonical migrator fixture.
    #[tokio::test]
    async fn inbound_reply_ingests_exactly_one_analytics_event_under_retry() {
        let pool = match migrator::test_support::fresh_canonical_pool("worker_f67", "reply_handoff")
            .await
        {
            Ok(pool) => pool,
            Err(error) => panic!("{}", error.panic_message()),
        };
        let Some(pool) = pool else {
            eprintln!("skipping: set TEST_DATABASE_URL to run DB-backed test");
            return;
        };

        // The inbound fixture: tenant-scoped, with canonical headers.
        sqlx::query(
            r#"
            INSERT INTO inbound_messages
                (id, tenant_id, from_email, to_email, subject, body_text,
                 headers, message_id_header, received_at)
            VALUES
                ('inb_f67_1', 'tenant_f67', 'replier@example.com', 'sales@apex.example',
                 'Re: proposal', 'Thanks, this looks great — one question: when can we start?',
                 '{"message-id": "<repl-1@example.com>", "in-reply-to": "<orig-1@apex.example>",
                   "auto-submitted": "auto-generated"}'::jsonb,
                 '<repl-1@example.com>', NOW() - INTERVAL '1 minute')
            "#,
        )
        .execute(&pool)
        .await
        .expect("seed inbound fixture");

        let handler = ReplyHandler::new(pool.clone(), ReplyHandlerConfig::default());
        // start() ensures the timestamped-claim column at startup; the test
        // drives the fetch/process path directly so it does the same.
        handler
            .ensure_timestamped_claim_column()
            .await
            .expect("ensure claim column");

        // Claim + process through the production entry point.
        let messages = handler.fetch_messages(10).await.expect("fetch");
        assert_eq!(messages.len(), 1);
        assert_eq!(
            messages[0].message_id_header.as_deref(),
            Some("<repl-1@example.com>")
        );
        let msg = messages.into_iter().next().unwrap();
        handler
            .process_message(msg)
            .await
            .expect("process commits the analytics handoff");

        // Exactly one durable reply event, derived from the Message-ID.
        let (count, tenant, recipient): (i64, String, String) =
            sqlx::query_as("SELECT COUNT(*), MAX(tenant_id), MAX(recipient) FROM reply_events")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(count, 1);
        assert_eq!(tenant, "tenant_f67");
        assert_eq!(recipient, "replier@example.com");
        let (message_id, is_auto, in_reply_to): (String, bool, String) =
            sqlx::query_as("SELECT message_id, is_auto_reply, in_reply_to FROM reply_events")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(message_id, "<repl-1@example.com>");
        assert_eq!(in_reply_to, "<orig-1@apex.example>");
        assert!(
            is_auto,
            "auto-submitted header must drive auto-reply detection"
        );

        // The inbound row is accepted (processed).
        let processed: Option<chrono::DateTime<chrono::Utc>> =
            sqlx::query_scalar("SELECT processed_at FROM inbound_messages WHERE id = 'inb_f67_1'")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert!(
            processed.is_some(),
            "handoff committed WITH inbound acceptance"
        );

        // Restart + retry: nothing left to process, still one event.
        let restarted = ReplyHandler::new(pool.clone(), ReplyHandlerConfig::default());
        let leftover = restarted
            .fetch_messages(10)
            .await
            .expect("fetch after restart");
        assert!(leftover.is_empty(), "accepted rows never re-process");

        // Idempotency through the analytics path itself: replaying the same
        // handoff (the crash-between-writes case) collapses to one event.
        let analytics = analytics::reply_tracking::ReplyTrackingService::new(pool.clone());
        let headers = std::collections::HashMap::from([(
            "auto-submitted".to_string(),
            "auto-generated".to_string(),
        )]);
        let handoff = analytics::reply_tracking::InboundReplyHandoff {
            inbound_id: "inb_f67_1",
            tenant_id: "tenant_f67",
            message_id_header: Some("<repl-1@example.com>"),
            in_reply_to: Some("<orig-1@apex.example>"),
            from_email: "replier@example.com",
            subject: "Re: proposal",
            body: "Thanks, this looks great — one question: when can we start?",
            headers,
            received_at: chrono::Utc::now(),
        };
        analytics
            .process_inbound_reply(&handoff)
            .await
            .expect("replayed handoff");
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM reply_events")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(count, 1, "replay must not add a second event");

        // Metrics update only for the owning tenant.
        let metrics = analytics
            .get_metrics("tenant_f67", 7)
            .await
            .expect("metrics");
        assert_eq!(metrics.total_replies, 1);
        let other = analytics
            .get_metrics("tenant_other", 7)
            .await
            .expect("metrics for another tenant");
        assert_eq!(other.total_replies, 0);

        // Readiness/lag + explicit no-events state.
        let status = analytics.status().await;
        assert!(status.schema_ready);
        assert_eq!(status.pending_inbound, 0);
        assert!(status.has_events);
        assert!(status.latest_reply_at.is_some());

        pool.close().await;
    }
}
