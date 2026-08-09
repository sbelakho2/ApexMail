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
use crate::common::{ProcessorResult, ReplyHandlerConfig};

/// Reply handler processor.
pub struct ReplyHandler {
    db: PgPool,
    config: ReplyHandlerConfig,
    is_running: AtomicBool,
    active_jobs: AtomicUsize,
    shutdown_notify: Arc<Notify>,
}

impl ReplyHandler {
    /// Create a new reply handler.
    pub fn new(db: PgPool, config: ReplyHandlerConfig) -> Self {
        Self {
            db,
            config,
            is_running: AtomicBool::new(false),
            active_jobs: AtomicUsize::new(0),
            shutdown_notify: Arc::new(Notify::new()),
        }
    }

    /// Start the processor.
    pub async fn start(self: Arc<Self>) -> ProcessorResult<()> {
        info!(
            concurrency = self.config.base.concurrency,
            "Starting reply handler"
        );

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
                        if let Err(e) = self.process_message(msg).await {
                            error!(error = %e, "Failed to process message");
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
    async fn fetch_messages(&self, limit: usize) -> ProcessorResult<Vec<InboundMessage>> {
        let messages = sqlx::query_as::<_, InboundMessage>(
            r#"
            UPDATE inbound_messages
            SET processing = true
            WHERE id IN (
                SELECT id
                FROM inbound_messages
                WHERE processed_at IS NULL AND processing = false
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
                processed_at as "processedAt", classification
            "#,
        )
        .bind(limit as i64)
        .bind(self.config.max_reply_size as i64)
        .fetch_all(&self.db)
        .await?;

        Ok(messages)
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

        // Update the message record
        sqlx::query(
            r#"
            UPDATE inbound_messages
            SET processed_at = NOW(),
                processing = false,
                classification = $1,
                classification_confidence = $2,
                suggested_action = $3,
                action_taken = $4
            WHERE id = $5
            "#,
        )
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
                .bind(format!("sup_{}", &uuid::Uuid::new_v4().simple().to_string()[..18]))
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
                .bind(format!("sup_{}", &uuid::Uuid::new_v4().simple().to_string()[..18]))
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
