//! Reply handler processor implementation.
//!
//! # Reply → enrollment lock (§21)
//!
//! Every inbound human reply must transactionally lock the enrollment it
//! belongs to, so a scheduled follow-up cannot race out.
//!
//! This crate deliberately does NOT depend on `sales-autopilot` (the worker
//! image only needs the canonical tables; pulling the control-plane crate in
//! would drag its routes/dispatcher/AXUM surface along). Therefore the
//! equivalent of `sales_autopilot::enrollments::lock_on_reply` is performed
//! here directly against the canonical tables, in ONE transaction:
//!
//! 1. `sales_enrollments.has_human_reply = TRUE` and the state move from the
//!    [`super::policy`] mapping (same mapping as `lock_on_reply`);
//! 2. `sales_unsubscribes` UPSERT for `unsubscribe`/`complaint`/`bounce_hard`;
//! 3. `sales_contact_points` invalidation for `bounce_hard`;
//! 4. cancellation of queued/leased/executing `sales_actions` for the
//!    enrollment AND for its step executions (the canonical enqueue path keys
//!    `send_step` actions on `step_execution` entities, so cancelling only
//!    enrollment-keyed rows would leave the next send claimable);
//! 5. a sender-health penalty signal (`sales_outcomes` complaint row, plus a
//!    best-effort `sales_sender_health.complaints` increment when the sending
//!    identity can be resolved);
//! 6. for out-of-office: reschedule rather than cancel — queued work is
//!    pushed to at least the stated return date + 1 day (or the default wait).
//!
//! If the product later adds the `sales-autopilot` dependency, this function
//! should call `lock_on_reply` instead; the mapping and the DB effects are
//! intentionally identical so that swap is behaviour-preserving.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use chrono::Utc;
use sqlx::{PgPool, Postgres, Transaction};
use tokio::sync::Notify;
use tokio::time::sleep;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

use super::ai::{classifier_from_config, ReplyClassifier};
use super::classifier::classify_full;
use super::deterministic;
use super::policy::{self, PolicyDecision, PolicyInput};
use super::types::{ClassifierKind, Evidence, InboundMessage, ReplyDisposition, ReplyInput};
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

/// Resolve the enrollment behind an inbound reply.
///
/// Resolution is canonical-only: the candidate addresses (`from_email`, plus
/// the DSN `Final-Recipient` / `X-Failed-Recipients` for a bounce, whose own
/// `From:` is MAILER-DAEMON rather than the prospect) matched against
/// `sales_contact_points.normalized_value` (`channel = 'email'`). Candidate
/// order wins first (the `From:` address is the sender), then unsuppressed
/// over suppressed, then highest confidence and newest.
///
/// The former transitional fallback — `inbound_messages.lead_id` →
/// `sales_leads.contact_id` — was DELETED (audit item 17). Its removal
/// condition was "no `sales_leads` row resolves a reply the canonical lookup
/// would not": every path in this workspace that inserts into
/// `inbound_messages` (mta migration 088 shape, ai_drafts, the reply
/// handler's own tests) leaves `lead_id` NULL, and the bridge columns on
/// `sales_leads` are no longer a resolution input, so the fallback was
/// dead code that could only ever resurrect a legacy identity.
///
/// Live enrollments win over terminal ones so a re-delivered reply resolves
/// to the same row it locked the first time instead of an older completed
/// enrollment.
const RESOLVE_ENROLLMENT_SQL: &str = r#"
            WITH canonical_contact AS (
                SELECT cp.contact_id
                FROM sales_contact_points cp
                WHERE cp.tenant_id = $1 AND cp.channel = 'email'
                  AND lower(cp.normalized_value) = ANY($2)
                ORDER BY array_position($2::text[], lower(cp.normalized_value)) NULLS LAST,
                         (cp.suppressed_at IS NULL) DESC,
                         cp.confidence DESC,
                         cp.created_at DESC
                LIMIT 1
            )
            SELECT e.id, e.contact_id, e.contact_point_id, e.account_id, e.state
            FROM sales_enrollments e, canonical_contact t
            WHERE e.tenant_id = $1
              AND e.contact_id = t.contact_id
            ORDER BY CASE
                         WHEN e.state IN ('completed', 'failed', 'suppressed') THEN 1
                         ELSE 0
                     END,
                     e.updated_at DESC, e.id
            LIMIT 1
        "#;

/// Cancel every claimable action for one enrollment. Two entity keys are
/// covered on purpose: `enrollment`-keyed rows (operator/enrollment actions)
/// and `step_execution`-keyed rows (the canonical `start_outreach` send path
/// keys `send_step` on the step execution).
const CANCEL_ENROLLMENT_ACTIONS_SQL: &str = r#"
            UPDATE sales_actions
            SET state = 'cancelled',
                last_error = $3,
                lease_owner = NULL,
                lease_expires_at = NULL,
                completed_at = NOW()
            WHERE tenant_id = $1
              AND state IN ('queued', 'leased', 'executing')
              AND (
                  (entity_type = 'enrollment' AND entity_id = $2)
                  OR (entity_type = 'step_execution' AND entity_id IN (
                      SELECT id FROM sales_step_executions
                      WHERE tenant_id = $1 AND enrollment_id = $2
                  ))
              )
        "#;

/// Cancel the enrollment's not-yet-sent step executions (the action rows above
/// reference them; cancelling both keeps the queue and the ledger consistent).
const CANCEL_ENROLLMENT_STEPS_SQL: &str = r#"
            UPDATE sales_step_executions
            SET state = 'cancelled', skip_reason = $3, updated_at = NOW()
            WHERE tenant_id = $1 AND enrollment_id = $2
              AND state IN ('scheduled', 'queued')
        "#;

/// Push the enrollment's queued work to at least `$3` (out-of-office resume).
const RESCHEDULE_ENROLLMENT_ACTIONS_SQL: &str = r#"
            UPDATE sales_actions
            SET due_at = GREATEST(due_at, $3), last_error = $4
            WHERE tenant_id = $1
              AND state IN ('queued', 'leased', 'executing')
              AND (
                  (entity_type = 'enrollment' AND entity_id = $2)
                  OR (entity_type = 'step_execution' AND entity_id IN (
                      SELECT id FROM sales_step_executions
                      WHERE tenant_id = $1 AND enrollment_id = $2
                  ))
              )
        "#;

const RESCHEDULE_ENROLLMENT_STEPS_SQL: &str = r#"
            UPDATE sales_step_executions
            SET scheduled_for = GREATEST(COALESCE(scheduled_for, $3), $3),
                updated_at = NOW()
            WHERE tenant_id = $1 AND enrollment_id = $2
              AND state IN ('scheduled', 'queued')
        "#;

/// Idempotency lookup for classification rows: the same
/// (tenant, inbound message, classifier, disposition) is one audit row.
const CLASSIFICATION_DEDUPE_SQL: &str = r#"
            SELECT id
            FROM sales_reply_classifications
            WHERE tenant_id = $1
              AND inbound_message_id = $2
              AND classifier = $3
              AND disposition = $4
              AND operator_correction IS NULL
            ORDER BY created_at ASC
            LIMIT 1
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
    /// The semantic classifier (HTTP AI service, or the never-guessing static
    /// fallback). Deterministic parsing always runs before this.
    classifier: Arc<dyn ReplyClassifier>,
    is_running: AtomicBool,
    active_jobs: AtomicUsize,
    shutdown_notify: Arc<Notify>,
}

impl ReplyHandler {
    /// Create a new reply handler.
    pub fn new(db: PgPool, config: ReplyHandlerConfig) -> Self {
        let classifier = classifier_from_config(&config);
        Self::with_classifier(db, config, classifier)
    }

    /// Create a reply handler with an explicit classifier (tests, embedding,
    /// and operators who supply their own provider).
    pub fn with_classifier(
        db: PgPool,
        config: ReplyHandlerConfig,
        classifier: Arc<dyn ReplyClassifier>,
    ) -> Self {
        Self {
            reply_analytics: analytics::reply_tracking::ReplyTrackingService::new(db.clone()),
            db,
            config,
            classifier,
            is_running: AtomicBool::new(false),
            active_jobs: AtomicUsize::new(0),
            shutdown_notify: Arc::new(Notify::new()),
        }
    }

    /// The classifier this handler uses (test/observability accessor).
    pub fn classifier_name(&self) -> &'static str {
        self.classifier.name()
    }

    /// Start the processor.
    ///
    /// `inbound_messages.processing_at` (used by the timestamped claim in
    /// [`FETCH_MESSAGES_SQL`]) is schema-owned: migration 203 creates the
    /// column and its partial stale-claim index. The worker runs DML only —
    /// no runtime schema reconciliation — so a deployment that skipped a
    /// migration fails its first query loudly instead of silently repairing
    /// the schema with privileges the service role does not need.
    pub async fn start(self: Arc<Self>) -> ProcessorResult<()> {
        info!(
            concurrency = self.config.base.concurrency,
            classifier = self.classifier.name(),
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

    /// Resolve the enrollment behind an inbound message (see
    /// [`RESOLVE_ENROLLMENT_SQL`] for the exact link).
    async fn resolve_enrollment(
        &self,
        msg: &InboundMessage,
    ) -> ProcessorResult<Option<ResolvedEnrollment>> {
        let Some(tenant_id) = msg.tenant_id.as_deref() else {
            return Ok(None);
        };
        let addresses = reply_recipient_candidates(msg);
        if addresses.is_empty() {
            return Ok(None);
        }
        let row: Option<ResolvedEnrollmentRow> = sqlx::query_as(RESOLVE_ENROLLMENT_SQL)
            .bind(tenant_id)
            .bind(&addresses)
            .fetch_optional(&self.db)
            .await?;
        Ok(row.map(ResolvedEnrollment::from))
    }

    /// The transactional reply lock. See the module docs for why this is
    /// direct SQL rather than `sales_autopilot::enrollments::lock_on_reply`.
    async fn lock_enrollment(
        &self,
        msg: &InboundMessage,
        decision: &PolicyDecision,
        resolved: &ResolvedEnrollment,
    ) -> ProcessorResult<LockOutcome> {
        let Some(tenant_id) = msg.tenant_id.as_deref() else {
            return Ok(LockOutcome::default());
        };

        let mut tx: Transaction<'_, Postgres> = self.db.begin().await?;
        let mut outcome = LockOutcome {
            enrollment_id: Some(resolved.enrollment_id),
            ..LockOutcome::default()
        };

        // 1. has_human_reply + state, in the same transaction as everything
        //    else. The committed flag is the authoritative race gate: the
        //    sequence worker re-reads it before sending.
        let updated = sqlx::query(
            "UPDATE sales_enrollments \
             SET has_human_reply = $3, state = $4, updated_at = NOW(), \
                 completed_at = CASE \
                     WHEN $4 IN ('completed', 'suppressed') THEN NOW() \
                     ELSE completed_at \
                 END \
             WHERE id = $1 AND tenant_id = $2",
        )
        .bind(resolved.enrollment_id)
        .bind(tenant_id)
        .bind(decision.has_human_reply)
        .bind(decision.enrollment_state.as_str())
        .execute(&mut *tx)
        .await?
        .rows_affected();
        if updated == 0 {
            // The enrollment disappeared between resolution and the lock.
            // Nothing was written; release the transaction.
            tx.rollback().await?;
            return Ok(LockOutcome::default());
        }

        // 2. Permanent suppression: sales-side fast path + platform mirror.
        if decision.suppress_endpoint {
            let email: Option<String> = sqlx::query_scalar(
                "SELECT COALESCE( \
                     (SELECT cp.value FROM sales_contact_points cp \
                      WHERE cp.id = $2 AND cp.tenant_id = $1), \
                     (SELECT cp.value FROM sales_contact_points cp \
                      WHERE cp.contact_id = $3 AND cp.tenant_id = $1 AND cp.channel = 'email' \
                      ORDER BY (cp.suppressed_at IS NULL) DESC, cp.created_at DESC \
                      LIMIT 1), \
                     $4 \
                 )",
            )
            .bind(tenant_id)
            .bind(resolved.contact_point_id)
            .bind(resolved.contact_id)
            .bind(&msg.from_email)
            .fetch_one(&mut *tx)
            .await?;

            if let Some(email) = email.filter(|email| !email.trim().is_empty()) {
                sqlx::query(
                    "INSERT INTO sales_unsubscribes (tenant_id, email) \
                     VALUES ($1, lower($2)) \
                     ON CONFLICT (tenant_id, email) DO NOTHING",
                )
                .bind(tenant_id)
                .bind(&email)
                .execute(&mut *tx)
                .await?;
                outcome.unsubscribed = true;

                let platform_reason = match decision.suppression_reason {
                    Some("complaint") => "complaint",
                    Some("bounce_hard") => "bounce",
                    _ => "unsubscribe",
                };
                sqlx::query(
                    "INSERT INTO suppressions (id, tenant_id, email, reason, source, created_at) \
                     VALUES ($1, $2, lower($3), $4, 'reply_handler', NOW()) \
                     ON CONFLICT (tenant_id, email) DO UPDATE \
                         SET reason = EXCLUDED.reason, updated_at = NOW()",
                )
                .bind(format!(
                    "sup_{}",
                    &Uuid::new_v4().simple().to_string()[..18]
                ))
                .bind(tenant_id)
                .bind(&email)
                .bind(platform_reason)
                .execute(&mut *tx)
                .await?;
            }
        }

        // 3. A hard bounce invalidates (and suppresses) the contact point.
        if decision.invalidate_contact_point {
            let affected = sqlx::query(
                "UPDATE sales_contact_points \
                 SET verification = 'invalid', \
                     suppressed_at = COALESCE(suppressed_at, NOW()), \
                     updated_at = NOW() \
                 WHERE tenant_id = $1 \
                   AND id = COALESCE($2::uuid, ( \
                       SELECT cp.id FROM sales_contact_points cp \
                       WHERE cp.tenant_id = $1 AND cp.contact_id = $3 AND cp.channel = 'email' \
                         AND cp.normalized_value = lower($4) \
                       ORDER BY (cp.suppressed_at IS NULL) DESC, cp.created_at DESC \
                       LIMIT 1))",
            )
            .bind(tenant_id)
            .bind(resolved.contact_point_id)
            .bind(resolved.contact_id)
            .bind(&msg.from_email)
            .execute(&mut *tx)
            .await?
            .rows_affected();
            outcome.contact_point_invalidated = affected > 0;
        }

        // 4. Queued work: cancel (every disposition except OOO/soft bounce) or
        //    reschedule (OOO).
        if decision.cancel_queued {
            let cancel_reason = format!(
                "sequence locked by '{}' reply",
                decision.disposition.as_str()
            );
            outcome.cancelled_actions = sqlx::query(CANCEL_ENROLLMENT_ACTIONS_SQL)
                .bind(tenant_id)
                .bind(resolved.enrollment_id)
                .bind(&cancel_reason)
                .execute(&mut *tx)
                .await?
                .rows_affected();
            outcome.cancelled_step_executions = sqlx::query(CANCEL_ENROLLMENT_STEPS_SQL)
                .bind(tenant_id)
                .bind(resolved.enrollment_id)
                .bind(&cancel_reason)
                .execute(&mut *tx)
                .await?
                .rows_affected();
        }
        if let Some(reschedule) = decision.reschedule {
            let why = format!("rescheduled by '{}' reply", decision.disposition.as_str());
            let moved = sqlx::query(RESCHEDULE_ENROLLMENT_ACTIONS_SQL)
                .bind(tenant_id)
                .bind(resolved.enrollment_id)
                .bind(reschedule.resume_at)
                .bind(&why)
                .execute(&mut *tx)
                .await?
                .rows_affected();
            let moved_steps = sqlx::query(RESCHEDULE_ENROLLMENT_STEPS_SQL)
                .bind(tenant_id)
                .bind(resolved.enrollment_id)
                .bind(reschedule.resume_at)
                .execute(&mut *tx)
                .await?
                .rows_affected();
            outcome.rescheduled = moved > 0 || moved_steps > 0;
        }

        // 5. Complaint: sender-health penalty signal. The canonical outcome
        //    ladder is the durable signal; the sender-lifecycle counter is a
        //    best-effort attribution when the sending identity is resolvable.
        if decision.sender_health_penalty {
            let inserted = sqlx::query(
                "INSERT INTO sales_outcomes \
                     (id, tenant_id, account_id, contact_id, enrollment_id, \
                      discovery_source, offer, outcome, value_eur, occurred_at) \
                 SELECT gen_random_uuid(), $1, $2, $3, $4, NULL, NULL, 'complaint', 0, NOW() \
                 WHERE NOT EXISTS ( \
                     SELECT 1 FROM sales_outcomes \
                     WHERE tenant_id = $1 AND enrollment_id = $4 AND outcome = 'complaint' \
                       AND occurred_at > NOW() - INTERVAL '1 day')",
            )
            .bind(tenant_id)
            .bind(resolved.account_id)
            .bind(resolved.contact_id)
            .bind(resolved.enrollment_id)
            .execute(&mut *tx)
            .await?
            .rows_affected();
            outcome.complaint_signal_recorded = inserted > 0;

            let penalized = sqlx::query(
                "UPDATE sales_sender_health h \
                 SET complaints = h.complaints + 1, updated_at = NOW() \
                 FROM sales_sender_identities si \
                 WHERE h.tenant_id = $1 AND si.tenant_id = $1 \
                   AND h.sender_identity_id = si.id \
                   AND si.id = ( \
                       SELECT si2.id \
                       FROM sales_step_executions se \
                       JOIN messages m ON m.id = se.message_id \
                                      AND m.tenant_id::text = se.tenant_id \
                       JOIN sales_sender_identities si2 \
                            ON lower(si2.from_email) = lower(m.from_address) \
                           AND si2.tenant_id = se.tenant_id \
                       WHERE se.tenant_id = $1 AND se.enrollment_id = $2 \
                         AND se.message_id IS NOT NULL \
                       ORDER BY se.executed_at DESC NULLS LAST, se.id DESC \
                       LIMIT 1 \
                   )",
            )
            .bind(tenant_id)
            .bind(resolved.enrollment_id)
            .execute(&mut *tx)
            .await?
            .rows_affected();
            outcome.sender_health_penalized = penalized > 0;
        }

        tx.commit().await?;

        info!(
            msg_id = %msg.id,
            enrollment = %resolved.enrollment_id,
            previous_state = %resolved.state,
            disposition = decision.disposition.as_str(),
            state = decision.enrollment_state.as_str(),
            cancelled_actions = outcome.cancelled_actions,
            cancelled_steps = outcome.cancelled_step_executions,
            unsubscribed = outcome.unsubscribed,
            invalidated = outcome.contact_point_invalidated,
            rescheduled = outcome.rescheduled,
            "sequence locked by inbound reply"
        );

        Ok(outcome)
    }

    async fn process_message_inner(&self, msg: &InboundMessage) -> ProcessorResult<()> {
        // Classify through the three layers: deterministic first, then the AI
        // layer (which never guesses on outage).
        let input: ReplyInput = msg.reply_input();
        let outcome = classify_full(self.classifier.as_ref(), &input).await;
        let decision = policy::decide(
            PolicyInput::new(outcome.disposition, outcome.result.confidence)
                .with_return_date(outcome.return_date),
            Utc::now(),
        );

        debug!(
            msg_id = %msg.id,
            disposition = decision.disposition.as_str(),
            observed = decision.observed_disposition.as_str(),
            classifier = outcome.classifier.as_str(),
            confidence = decision.confidence,
            evidence = ?outcome.evidence,
            "Classified reply"
        );

        // §21: lock the enrollment (has_human_reply, state, suppression,
        // queue cancellation / OOO rescheduling) in ONE transaction.
        let resolved = self.resolve_enrollment(msg).await?;
        let lock_outcome = match &resolved {
            Some(enrollment) => self.lock_enrollment(msg, &decision, enrollment).await?,
            None => LockOutcome::default(),
        };

        // Persist the full classification record. The actual action is known
        // now (it was just executed transactionally), so the suggested/actual
        // pair lands in one row. Operator corrections are separate rows via
        // `record_operator_correction` / `record_action_outcome`.
        let actual_action = lock_outcome.describe(&decision);
        let record = ClassificationRecord {
            tenant_id: msg.tenant_id.clone().unwrap_or_default(),
            enrollment_id: resolved.as_ref().map(|r| r.enrollment_id),
            contact_id: resolved.as_ref().map(|r| r.contact_id),
            contact_point_id: resolved.as_ref().and_then(|r| r.contact_point_id),
            inbound_message_id: Some(msg.id.clone()),
            disposition: decision.disposition,
            confidence: decision.confidence,
            classifier: outcome.classifier,
            reasoning: outcome.result.reasoning.clone(),
            model_version: outcome.model_version.clone(),
            prompt_version: outcome.prompt_version.clone(),
            evidence: outcome.evidence.clone(),
            suggested_action: Some(decision.suggested_action.to_string()),
            actual_action: Some(actual_action.clone()),
            operator_correction: None,
        };
        let classification_id = persist_classification(&self.db, &record).await?;
        debug!(
            msg_id = %msg.id,
            classification_id = %classification_id,
            actual_action = %actual_action,
            "reply classification persisted"
        );

        // O-16.6: the legacy platform action path stays gated behind config.
        // The enrollment lock above is the canonical, compliance-required
        // effect and is not config-gated; this gate only covers the legacy
        // suppressions/lead-status actions.
        let can_auto_execute = self.config.auto_suppress
            && decision.auto_execute
            && decision.confidence >= self.config.auto_suppress_confidence_threshold;

        let mut action_taken: Option<String> = if resolved.is_some() {
            Some(actual_action)
        } else {
            None
        };
        if can_auto_execute {
            debug!(
                msg_id = %msg.id,
                action = ?outcome.result.suggested_action.action,
                confidence = decision.confidence,
                "Auto-executing reply action"
            );
            if let Some(legacy) = self.execute_action(msg, &outcome.result).await? {
                action_taken = Some(match action_taken {
                    Some(existing) => format!("{existing};{legacy}"),
                    None => legacy,
                });
            }
        } else if outcome.result.suggested_action.auto_execute {
            info!(
                msg_id = %msg.id,
                action = ?outcome.result.suggested_action.action,
                confidence = decision.confidence,
                auto_suppress = self.config.auto_suppress,
                "Reply action blocked by policy — would auto-execute but config disallows it"
            );
        }

        // F67: commit the durable reply-analytics handoff WITH inbound
        // acceptance — before the row is marked processed. A failure here
        // fails the whole message (claim reset → retry), and the handoff is
        // idempotent through restarts (tenant-qualified message identity),
        // so a retry after a crash between the two writes collapses to one
        // reply event. Messages without a tenant are skipped: analytics is
        // tenant-scoped.
        if let Some(tenant_id) = msg.tenant_id.as_deref() {
            let in_reply_to = msg.in_reply_to();
            let body = msg.body_text.as_deref().unwrap_or("");
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
            .bind(outcome.result.classification.as_str())
            .bind(outcome.result.confidence)
            .bind(serde_json::to_value(&outcome.result.suggested_action)?)
            .bind(&action_taken)
            .bind(&msg.id)
            .execute(&self.db)
            .await?;

        // Audit item 17: the former `sales_leads.status` write here is gone.
        // The reply's visible outcome is already canonical — `lock_enrollment`
        // set `sales_enrollments.state` / `has_human_reply` and (for
        // suppression) the contact point — and the CP read derives status
        // from exactly those fields. Any `sales_leads.status` write would be
        // pure divergence: no read path renders that column any more.

        Ok(())
    }

    /// Execute the suggested legacy action.
    async fn execute_action(
        &self,
        msg: &InboundMessage,
        classification: &super::types::ClassificationResult,
    ) -> ProcessorResult<Option<String>> {
        match classification.suggested_action.action {
            super::types::ActionType::Snooze => {
                // The canonical effect (reschedule the enrollment's queued
                // actions/steps, set the enrollment state) is applied by
                // `lock_enrollment` in the same transaction as the reply
                // lock. The former legacy lead-column writes here were
                // removed in audit item 17: nothing reads those columns any
                // more.
                let days = classification
                    .suggested_action
                    .parameters
                    .get("duration_days")
                    .and_then(|v| v.as_i64())
                    .unwrap_or(7);

                Ok(Some(format!("snoozed_for_{}_days", days)))
            }
            super::types::ActionType::Suppress => {
                // Add to suppressions (needs a tenant; rows from unknown
                // tenants are skipped so the NOT NULL FK is never violated).
                let Some(ref tenant_id) = msg.tenant_id else {
                    warn!(msg_id = %msg.id, "Suppress action skipped — inbound message has no tenant_id");
                    return Ok(Some("skipped_no_tenant".to_string()));
                };
                let reason = classification
                    .suggested_action
                    .parameters
                    .get("reason")
                    .and_then(|value| value.as_str())
                    .unwrap_or("not_interested");
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
                .bind(reason)
                .execute(&self.db)
                .await?;

                Ok(Some("suppressed".to_string()))
            }
            super::types::ActionType::Unsubscribe => {
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
            super::types::ActionType::FlagSales => {
                // The `sales_leads.status` / `priority` write that used to
                // live here was removed in audit item 17: the columns are
                // write-only (no reader in the workspace), and the reply's
                // canonical record — the enrollment lock and the persisted
                // classification — already carries the flag.
                Ok(Some("flagged_for_sales".to_string()))
            }
            super::types::ActionType::Escalate => {
                // Log escalation (would typically create a task or notification)
                warn!(
                    msg_id = %msg.id,
                    from = %msg.from_email,
                    classification = ?classification.classification,
                    "Message escalated for review"
                );

                Ok(Some("escalated".to_string()))
            }
            super::types::ActionType::Ignore => Ok(Some("ignored".to_string())),
            _ => Ok(None),
        }
    }
}

// ---------------------------------------------------------------------------
// Enrollment resolution / lock types
// ---------------------------------------------------------------------------

/// Candidate recipient addresses used to link a reply to a contact point.
///
/// The `From:` address comes first; a bounce DSN additionally names the
/// original recipient in `Final-Recipient` (body) and `X-Failed-Recipients`
/// (header), because the DSN's own `From:` is MAILER-DAEMON rather than the
/// prospect.
fn reply_recipient_candidates(msg: &InboundMessage) -> Vec<String> {
    let mut candidates: Vec<String> = Vec::new();

    fn push(candidates: &mut Vec<String>, value: &str) {
        let value = value
            .trim()
            .trim_matches(|c| c == '<' || c == '>')
            .trim()
            .to_ascii_lowercase();
        if value.contains('@')
            && !value.contains(char::is_whitespace)
            && !candidates.contains(&value)
        {
            candidates.push(value);
        }
    }

    push(&mut candidates, &msg.from_email);
    if let Some(body) = msg.body_text.as_deref() {
        if let Some(recipient) = deterministic::dsn_final_recipient(body) {
            push(&mut candidates, &recipient);
        }
    }
    if let Some(header) = msg.header("x-failed-recipients") {
        for recipient in header.split(',').take(16) {
            push(&mut candidates, recipient);
        }
    }
    candidates
}

/// A resolved enrollment behind an inbound reply.
#[derive(Debug, Clone)]
pub struct ResolvedEnrollment {
    pub enrollment_id: Uuid,
    pub contact_id: Uuid,
    pub contact_point_id: Option<Uuid>,
    pub account_id: Option<Uuid>,
    pub state: String,
}

#[derive(sqlx::FromRow)]
struct ResolvedEnrollmentRow {
    id: Uuid,
    contact_id: Uuid,
    contact_point_id: Option<Uuid>,
    account_id: Option<Uuid>,
    state: String,
}

impl From<ResolvedEnrollmentRow> for ResolvedEnrollment {
    fn from(row: ResolvedEnrollmentRow) -> Self {
        Self {
            enrollment_id: row.id,
            contact_id: row.contact_id,
            contact_point_id: row.contact_point_id,
            account_id: row.account_id,
            state: row.state,
        }
    }
}

/// What the transactional lock actually did, for the persisted
/// `actual_action` and for tests.
#[derive(Debug, Clone, Default)]
pub struct LockOutcome {
    pub enrollment_id: Option<Uuid>,
    pub cancelled_actions: u64,
    pub cancelled_step_executions: u64,
    pub unsubscribed: bool,
    pub contact_point_invalidated: bool,
    pub rescheduled: bool,
    pub complaint_signal_recorded: bool,
    pub sender_health_penalized: bool,
}

impl LockOutcome {
    /// A stable, human-readable description persisted as `actual_action`.
    pub fn describe(&self, decision: &PolicyDecision) -> String {
        let mut parts: Vec<String> = Vec::new();
        match self.enrollment_id {
            Some(_) => parts.push(format!(
                "enrollment_locked:{}",
                decision.enrollment_state.as_str()
            )),
            None => parts.push("no_enrollment".to_string()),
        }
        if self.cancelled_actions > 0 {
            parts.push(format!("cancelled_actions:{}", self.cancelled_actions));
        }
        if self.cancelled_step_executions > 0 {
            parts.push(format!(
                "cancelled_step_executions:{}",
                self.cancelled_step_executions
            ));
        }
        if self.unsubscribed {
            parts.push("unsubscribed".to_string());
        }
        if self.contact_point_invalidated {
            parts.push("contact_point_invalidated".to_string());
        }
        if self.rescheduled {
            parts.push("rescheduled".to_string());
        }
        if self.complaint_signal_recorded {
            parts.push("sender_health_penalty".to_string());
        }
        parts.join(";")
    }
}

// ---------------------------------------------------------------------------
// Classification persistence (§20)
// ---------------------------------------------------------------------------

/// One row for `sales_reply_classifications`.
#[derive(Debug, Clone)]
pub struct ClassificationRecord {
    pub tenant_id: String,
    pub enrollment_id: Option<Uuid>,
    pub contact_id: Option<Uuid>,
    pub contact_point_id: Option<Uuid>,
    pub inbound_message_id: Option<String>,
    pub disposition: ReplyDisposition,
    pub confidence: f64,
    pub classifier: ClassifierKind,
    pub reasoning: String,
    pub model_version: Option<String>,
    pub prompt_version: Option<String>,
    pub evidence: Vec<Evidence>,
    pub suggested_action: Option<String>,
    pub actual_action: Option<String>,
    pub operator_correction: Option<String>,
}

/// Persist one classification row, idempotently.
///
/// `sales_reply_classifications` has no unique constraint on
/// `inbound_message_id` (it is an append-only audit ledger), so idempotency
/// is enforced here: an exact repeat — same tenant, inbound message,
/// classifier and disposition — returns the existing row instead of
/// inserting a second one. A *different* disposition for the same message is
/// a legitimate new audit row (reclassification); an operator correction is
/// recorded through [`record_operator_correction`] and always inserts.
pub async fn persist_classification(
    db: &PgPool,
    record: &ClassificationRecord,
) -> Result<Uuid, sqlx::Error> {
    if let Some(inbound_message_id) = record.inbound_message_id.as_deref() {
        if record.operator_correction.is_none() && record.classifier != ClassifierKind::Operator {
            let existing: Option<Uuid> = sqlx::query_scalar(CLASSIFICATION_DEDUPE_SQL)
                .bind(&record.tenant_id)
                .bind(inbound_message_id)
                .bind(record.classifier.as_str())
                .bind(record.disposition.as_str())
                .fetch_optional(db)
                .await?;
            if let Some(existing) = existing {
                return Ok(existing);
            }
        }
    }

    let id = Uuid::new_v4();
    let evidence = serde_json::to_value(&record.evidence)
        .unwrap_or_else(|_| serde_json::Value::Array(Vec::new()));
    sqlx::query(
        "INSERT INTO sales_reply_classifications \
             (id, tenant_id, enrollment_id, contact_id, contact_point_id, \
              inbound_message_id, disposition, confidence, classifier, reasoning, \
              model_version, prompt_version, evidence, suggested_action, actual_action, \
              operator_correction, created_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, NOW())",
    )
    .bind(id)
    .bind(&record.tenant_id)
    .bind(record.enrollment_id)
    .bind(record.contact_id)
    .bind(record.contact_point_id)
    .bind(record.inbound_message_id.as_deref())
    .bind(record.disposition.as_str())
    .bind(record.confidence)
    .bind(record.classifier.as_str())
    .bind(&record.reasoning)
    .bind(record.model_version.as_deref())
    .bind(record.prompt_version.as_deref())
    .bind(&evidence)
    .bind(record.suggested_action.as_deref())
    .bind(record.actual_action.as_deref())
    .bind(record.operator_correction.as_deref())
    .execute(db)
    .await?;
    Ok(id)
}

/// Record the result of an operator (or downstream process) acting on a
/// classification as a first-class row.
///
/// * `actual_action == suggested_action` — the suggestion was confirmed; the
///   existing row's `actual_action` is stamped and no row is added.
/// * different — a NEW row is inserted with `classifier = 'operator'`,
///   `operator_correction = "suggested '<x>', actual '<y>'"`, carrying the
///   original disposition/model/evidence. Corrections are therefore
///   training/evaluation examples (the partial index on
///   `operator_correction` surfaces exactly them) instead of overwriting the
///   machine verdict.
///
/// Returns the new correction row's id, or `None` when the suggestion was
/// confirmed / the classification does not exist.
pub async fn record_action_outcome(
    db: &PgPool,
    tenant_id: &str,
    classification_id: Uuid,
    actual_action: &str,
) -> Result<Option<Uuid>, sqlx::Error> {
    #[derive(sqlx::FromRow)]
    struct Row {
        disposition: String,
        confidence: f64,
        reasoning: Option<String>,
        model_version: Option<String>,
        prompt_version: Option<String>,
        evidence: serde_json::Value,
        suggested_action: Option<String>,
        enrollment_id: Option<Uuid>,
        contact_id: Option<Uuid>,
        contact_point_id: Option<Uuid>,
        inbound_message_id: Option<String>,
    }

    let row: Option<Row> = sqlx::query_as(
        "SELECT disposition, confidence, reasoning, model_version, prompt_version, \
                evidence, suggested_action, enrollment_id, contact_id, contact_point_id, \
                inbound_message_id \
         FROM sales_reply_classifications \
         WHERE id = $1 AND tenant_id = $2",
    )
    .bind(classification_id)
    .bind(tenant_id)
    .fetch_optional(db)
    .await?;

    let Some(row) = row else {
        return Ok(None);
    };

    if row.suggested_action.as_deref() == Some(actual_action) {
        sqlx::query(
            "UPDATE sales_reply_classifications SET actual_action = $2 \
             WHERE id = $1 AND tenant_id = $3",
        )
        .bind(classification_id)
        .bind(actual_action)
        .bind(tenant_id)
        .execute(db)
        .await?;
        return Ok(None);
    }

    let correction = format!(
        "suggested '{}', actual '{}'",
        row.suggested_action.as_deref().unwrap_or("none"),
        actual_action
    );
    let disposition: ReplyDisposition =
        row.disposition.parse().unwrap_or(ReplyDisposition::Unknown);
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO sales_reply_classifications \
             (id, tenant_id, enrollment_id, contact_id, contact_point_id, inbound_message_id, \
              disposition, confidence, classifier, reasoning, model_version, prompt_version, \
              evidence, suggested_action, actual_action, operator_correction, created_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'operator', $9, $10, $11, $12, $13, $14, $15, NOW())",
    )
    .bind(id)
    .bind(tenant_id)
    .bind(row.enrollment_id)
    .bind(row.contact_id)
    .bind(row.contact_point_id)
    .bind(row.inbound_message_id.as_deref())
    .bind(disposition.as_str())
    .bind(row.confidence)
    .bind(row.reasoning.as_deref())
    .bind(row.model_version.as_deref())
    .bind(row.prompt_version.as_deref())
    .bind(&row.evidence)
    .bind(row.suggested_action.as_deref())
    .bind(actual_action)
    .bind(&correction)
    .execute(db)
    .await?;
    Ok(Some(id))
}

/// Record an operator correction of a machine classification as a new
/// `classifier = 'operator'` row, so it becomes a training/evaluation
/// example (the partial index on `operator_correction` surfaces these rows to
/// the CP).
#[allow(clippy::too_many_arguments)]
pub async fn record_operator_correction(
    db: &PgPool,
    tenant_id: &str,
    inbound_message_id: &str,
    original_disposition: ReplyDisposition,
    corrected_disposition: ReplyDisposition,
    corrected_confidence: f64,
    reasoning: &str,
) -> Result<Uuid, sqlx::Error> {
    let id = Uuid::new_v4();
    let correction = original_disposition.corrects(corrected_disposition);
    sqlx::query(
        "INSERT INTO sales_reply_classifications \
             (id, tenant_id, inbound_message_id, disposition, confidence, classifier, reasoning, \
              suggested_action, actual_action, operator_correction, evidence, created_at) \
         VALUES ($1, $2, $3, $4, $5, 'operator', $6, $7, $8, $9, '[]'::jsonb, NOW())",
    )
    .bind(id)
    .bind(tenant_id)
    .bind(inbound_message_id)
    .bind(corrected_disposition.as_str())
    .bind(corrected_confidence.clamp(0.0, 1.0))
    .bind(reasoning)
    .bind(original_disposition.as_str())
    .bind(corrected_disposition.as_str())
    .bind(&correction)
    .execute(db)
    .await?;
    Ok(id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reply_handler::ai::ClassifyError;
    use async_trait::async_trait;

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

    /// Item 23: the reply worker must run DML only. `processing_at` and
    /// `idx_inbound_messages_processing_stale` are owned by migration 203,
    /// and a service role without DDL privileges must be able to start and
    /// process. A source scan (the same technique as the SQL-shape tests
    /// above) keeps the last runtime schema statement from creeping back:
    /// the needles are assembled at runtime so this test's own source text
    /// is not what the scan finds.
    #[test]
    fn reply_handler_issues_no_runtime_schema_ddl() {
        let source = include_str!("processor.rs");
        for needle in [
            concat!("ALTER", " TABLE"),
            concat!("CREATE", " TABLE"),
            concat!("DROP", " TABLE"),
            concat!("CREATE", " INDEX"),
            concat!("DROP", " INDEX"),
        ] {
            assert!(
                !source.contains(needle),
                "runtime schema statement {needle:?} must not appear in the reply handler; \
                 schema is owned by the migration chain"
            );
        }
    }

    // ── §21: the lock SQL shape ──────────────────────────────────────

    /// Audit item 17: resolution is canonical-ONLY. The previous version of
    /// this test asserted the canonical-first ordering plus the transitional
    /// `lead_contact` fallback; the fallback is gone, so the assertions now
    /// guard its absence (do not weaken: the old ordering assertions became
    /// a stronger "no bridge identity in the resolver at all").
    #[test]
    fn resolution_is_canonical_only_and_never_reads_the_lead_bridge() {
        assert!(
            RESOLVE_ENROLLMENT_SQL.contains("sales_contact_points")
                && RESOLVE_ENROLLMENT_SQL.contains("lower(cp.normalized_value) = ANY($2)"),
            "the email link must match any candidate address (from_email or DSN recipient)"
        );
        assert!(
            !RESOLVE_ENROLLMENT_SQL.contains("sales_leads"),
            "the resolver must not read the sales_leads bridge"
        );
        assert!(
            !RESOLVE_ENROLLMENT_SQL.contains("lead_contact")
                && !RESOLVE_ENROLLMENT_SQL.contains("COALESCE"),
            "the deleted bridge fallback (and its COALESCE) must not return"
        );
        assert!(
            RESOLVE_ENROLLMENT_SQL.contains("'completed', 'failed', 'suppressed'"),
            "live enrollments must sort before terminal ones"
        );
    }

    /// The reply handler must not write the legacy `sales_leads` columns at
    /// all (item 17). This is a source scan so a reintroduced write fails
    /// loudly without needing a database. Only the production half of the
    /// file is scanned — the tests below legitimately seed/delete bridge rows.
    #[test]
    fn reply_handler_writes_no_legacy_sales_leads_state() {
        let source = include_str!("processor.rs");
        let production = source
            .split("#[cfg(test)]")
            .next()
            .expect("processor.rs has a test module");
        for fragment in [
            ["UPDATE sales_leads", "SET"].join(" "),
            ["INSERT INTO", "sales_leads"].join(" "),
            ["DELETE FROM", "sales_leads"].join(" "),
            ["snoozed", "until"].join("_"),
            ["last_reply", "at"].join("_"),
        ] {
            assert!(
                !production.contains(&fragment),
                "reply handler must not write legacy lead state (`{fragment}` found)"
            );
        }
    }

    #[test]
    fn cancellation_covers_both_action_entity_keys() {
        assert!(CANCEL_ENROLLMENT_ACTIONS_SQL.contains("entity_type = 'enrollment'"));
        assert!(
            CANCEL_ENROLLMENT_ACTIONS_SQL.contains("entity_type = 'step_execution'"),
            "the canonical send path keys send_step on step executions"
        );
        assert!(
            CANCEL_ENROLLMENT_ACTIONS_SQL.contains("state IN ('queued', 'leased', 'executing')")
        );
        assert!(CANCEL_ENROLLMENT_ACTIONS_SQL.contains("state = 'cancelled'"));
        assert!(CANCEL_ENROLLMENT_STEPS_SQL.contains("state = 'cancelled'"));
    }

    #[test]
    fn ooo_reschedule_pushes_work_forward_instead_of_cancelling() {
        assert!(RESCHEDULE_ENROLLMENT_ACTIONS_SQL.contains("GREATEST(due_at, $3)"));
        assert!(RESCHEDULE_ENROLLMENT_ACTIONS_SQL
            .contains("state IN ('queued', 'leased', 'executing')"));
        assert!(
            RESCHEDULE_ENROLLMENT_STEPS_SQL.contains("GREATEST(COALESCE(scheduled_for, $3), $3)")
        );
        assert!(
            !RESCHEDULE_ENROLLMENT_ACTIONS_SQL.contains("'cancelled'"),
            "OOO must never cancel"
        );
    }

    #[test]
    fn classification_dedupe_is_tenant_and_message_scoped() {
        assert!(CLASSIFICATION_DEDUPE_SQL.contains("tenant_id = $1"));
        assert!(CLASSIFICATION_DEDUPE_SQL.contains("inbound_message_id = $2"));
        assert!(CLASSIFICATION_DEDUPE_SQL.contains("classifier = $3"));
        assert!(CLASSIFICATION_DEDUPE_SQL.contains("disposition = $4"));
        assert!(CLASSIFICATION_DEDUPE_SQL.contains("operator_correction IS NULL"));
    }

    #[test]
    fn lock_outcome_description_names_every_effect() {
        let decision = policy::decide(
            PolicyInput::new(ReplyDisposition::Complaint, 0.99),
            Utc::now(),
        );
        let outcome = LockOutcome {
            enrollment_id: Some(Uuid::new_v4()),
            cancelled_actions: 2,
            cancelled_step_executions: 1,
            unsubscribed: true,
            contact_point_invalidated: false,
            rescheduled: false,
            complaint_signal_recorded: true,
            sender_health_penalized: false,
        };
        let description = outcome.describe(&decision);
        assert!(description.contains("enrollment_locked:suppressed"));
        assert!(description.contains("cancelled_actions:2"));
        assert!(description.contains("cancelled_step_executions:1"));
        assert!(description.contains("unsubscribed"));
        assert!(description.contains("sender_health_penalty"));

        let none = LockOutcome::default();
        assert_eq!(none.describe(&decision), "no_enrollment");
    }

    // F67: durable reply-analytics handoff.
    //
    // Ingest a real inbound fixture through the production entry point,
    // retry it, and restart before consumption: exactly one reply event
    // appears and metrics update only for its tenant. DB-backed (unit test
    // so the private processing path is reachable); gated on
    // TEST_DATABASE_URL via the canonical migrator fixture.
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
        // `processing_at` is migration-owned (203), so the test drives the
        // fetch/process path directly with no schema setup.

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

        // The classification is persisted in the canonical table too.
        let (disposition, classifier, suggested): (String, String, Option<String>) = sqlx::query_as(
            "SELECT disposition, classifier, suggested_action FROM sales_reply_classifications \
             WHERE tenant_id = 'tenant_f67'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(disposition, "ooo");
        assert_eq!(classifier, "deterministic");
        assert_eq!(suggested.as_deref(), Some("reschedule_after_ooo"));

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

    // =======================================================================
    // Item 17: canonical-first identity resolution
    // =======================================================================

    /// Inbound identity resolves through `sales_contact_points` ONLY; the
    /// `sales_leads` bridge is not a resolution input at all (item 17).
    ///
    /// Proved adversarially in three legs: the legacy bridge row points at a
    /// DIFFERENT contact (B) with its own live enrollment; (1) the resolver
    /// returns the sender's canonical contact A, (2) the bridge row is
    /// deleted and resolution still succeeds, (3) the inbound message's
    /// legacy `lead_id` is rewritten to a nonexistent lead and resolution
    /// STILL returns A — proving the deleted fallback is not load-bearing
    /// even in its last reachable shape.
    ///
    /// DB-backed via the canonical migrator fixture (soft-skips without
    /// `TEST_DATABASE_URL`, like the F67 handoff test above).
    #[tokio::test]
    async fn reply_identity_resolves_canonically_without_the_lead_bridge() {
        let pool =
            match migrator::test_support::fresh_canonical_pool("worker_item17", "reply_canonical")
                .await
            {
                Ok(pool) => pool,
                Err(error) => panic!("{}", error.panic_message()),
            };
        let Some(pool) = pool else {
            eprintln!("skipping: set TEST_DATABASE_URL to run DB-backed test");
            return;
        };

        let suffix = &Uuid::new_v4().simple().to_string()[..12];
        let tenant = format!("item17{suffix}");
        let account_id = Uuid::new_v4();
        let contact_a = Uuid::new_v4();
        let point_a = Uuid::new_v4();
        let contact_b = Uuid::new_v4();
        let point_b = Uuid::new_v4();
        let sequence_id = Uuid::new_v4();
        let version_id = Uuid::new_v4();
        let enrollment_a = Uuid::new_v4();
        let enrollment_b = Uuid::new_v4();
        let email_a = format!("canonical-{suffix}@example.com");
        let email_b = format!("bridge-{suffix}@example.com");
        // `inbound_messages.lead_id` is VARCHAR(26) (migration 088:98).
        let lead_id = format!("lead{suffix}");
        let inbound_id = format!("inb{}", &Uuid::new_v4().simple().to_string()[..18]);

        sqlx::query(
            "INSERT INTO sales_accounts (id, tenant_id, company, domain) \
             VALUES ($1, $2, 'Item17 Co', $3)",
        )
        .bind(account_id)
        .bind(&tenant)
        .bind(format!("{suffix}.example"))
        .execute(&pool)
        .await
        .expect("seed account");
        for (contact_id, point_id, email) in [
            (contact_a, point_a, &email_a),
            (contact_b, point_b, &email_b),
        ] {
            sqlx::query(
                "INSERT INTO sales_contacts (id, tenant_id, account_id, full_name) \
                 VALUES ($1, $2, $3, 'Item17 Contact')",
            )
            .bind(contact_id)
            .bind(&tenant)
            .bind(account_id)
            .execute(&pool)
            .await
            .expect("seed contact");
            sqlx::query(
                "INSERT INTO sales_contact_points \
                     (id, tenant_id, contact_id, channel, value, normalized_value, verification) \
                 VALUES ($1, $2, $3, 'email', $4, lower($4), 'valid')",
            )
            .bind(point_id)
            .bind(&tenant)
            .bind(contact_id)
            .bind(email)
            .execute(&pool)
            .await
            .expect("seed contact point");
        }
        sqlx::query(
            "INSERT INTO sales_sequences (id, tenant_id, name, status) \
             VALUES ($1, $2, 'Item17 Sequence', 'active')",
        )
        .bind(sequence_id)
        .bind(&tenant)
        .execute(&pool)
        .await
        .expect("seed sequence");
        sqlx::query(
            "INSERT INTO sales_sequence_versions \
                 (id, tenant_id, sequence_id, version, status, locale, approved_by, approved_at) \
             VALUES ($1, $2, $3, 1, 'active', 'en', 'item17', NOW())",
        )
        .bind(version_id)
        .bind(&tenant)
        .bind(sequence_id)
        .execute(&pool)
        .await
        .expect("seed version");
        for (enrollment_id, contact_id, point_id) in [
            (enrollment_a, contact_a, point_a),
            (enrollment_b, contact_b, point_b),
        ] {
            sqlx::query(
                "INSERT INTO sales_enrollments \
                     (id, tenant_id, sequence_version_id, account_id, contact_id, \
                      contact_point_id, state, current_step_index) \
                 VALUES ($1, $2, $3, $4, $5, $6, 'active', 0)",
            )
            .bind(enrollment_id)
            .bind(&tenant)
            .bind(version_id)
            .bind(account_id)
            .bind(contact_id)
            .bind(point_id)
            .execute(&pool)
            .await
            .expect("seed enrollment");
        }
        // The transitional bridge points at contact B, NOT at the sender's
        // canonical contact A: canonical-first must ignore it.
        sqlx::query(
            "INSERT INTO sales_leads \
                 (id, tenant_id, company_name, domain, contact_email, status, account_id, contact_id) \
             VALUES ($1, $2, 'Item17 Co', $3, $4, 'new', $5, $6)",
        )
        .bind(&lead_id)
        .bind(&tenant)
        .bind(format!("{suffix}.example"))
        .bind(&email_b)
        .bind(account_id)
        .bind(contact_b)
        .execute(&pool)
        .await
        .expect("seed bridge lead");
        sqlx::query(
            "INSERT INTO inbound_messages \
                 (id, tenant_id, lead_id, from_email, to_email, subject, body_text, \
                  headers, received_at) \
             VALUES ($1, $2, $3, $4, 'sales@apex.example', 'Re: item17', 'hello there', \
                     '{}'::jsonb, NOW() - INTERVAL '1 minute')",
        )
        .bind(&inbound_id)
        .bind(&tenant)
        .bind(&lead_id)
        .bind(&email_a)
        .execute(&pool)
        .await
        .expect("seed inbound");

        let handler = ReplyHandler::new(pool.clone(), ReplyHandlerConfig::default());
        let msg = fetch_message_by_id(&handler, &inbound_id)
            .await
            .expect("claim the inbound reply");
        assert_eq!(msg.lead_id.as_deref(), Some(lead_id.as_str()));

        let resolved = handler
            .resolve_enrollment(&msg)
            .await
            .expect("resolve")
            .expect("the canonical contact point must resolve");
        assert_eq!(
            resolved.contact_id, contact_a,
            "the sender's contact point must win over the lead bridge (which points at B)"
        );
        assert_eq!(resolved.enrollment_id, enrollment_a);

        // Remove the bridge row entirely: canonical resolution must not need
        // the fallback.
        sqlx::query("DELETE FROM sales_leads WHERE id = $1")
            .bind(&lead_id)
            .execute(&pool)
            .await
            .expect("delete the bridge lead");
        let resolved_without_bridge = handler
            .resolve_enrollment(&msg)
            .await
            .expect("resolve without the bridge")
            .expect("resolution must still succeed with no sales_leads row at all");
        assert_eq!(resolved_without_bridge.contact_id, contact_a);
        assert_eq!(resolved_without_bridge.enrollment_id, enrollment_a);

        // Last reachable shape of the deleted fallback: `lead_id` points at a
        // lead that does not exist. The resolver must still return the
        // canonical contact (a resolver that consulted `lead_id` at all would
        // fail to resolve here).
        sqlx::query("UPDATE inbound_messages SET lead_id = $1 WHERE id = $2")
            .bind("missing_lead_17")
            .bind(&inbound_id)
            .execute(&pool)
            .await
            .expect("rewrite lead_id to a nonexistent lead");
        let resolved_after_bogus_lead = handler
            .resolve_enrollment(&msg)
            .await
            .expect("resolve after bogus lead_id")
            .expect("resolution must ignore inbound_messages.lead_id entirely");
        assert_eq!(resolved_after_bogus_lead.contact_id, contact_a);
        assert_eq!(resolved_after_bogus_lead.enrollment_id, enrollment_a);

        pool.close().await;
    }

    // =======================================================================
    // Live-database tests (§20/§21 adversarial set). Ignored by default;
    // run with `TEST_DATABASE_URL=… cargo test -p worker-processors --lib
    // -- --ignored`. The base URL defaults to the local Postgres when the
    // variable is unset; an unreachable default soft-skips, a configured but
    // broken URL fails (repo F01 convention).
    // =======================================================================

    fn live_base_url() -> (String, bool) {
        match std::env::var("TEST_DATABASE_URL")
            .ok()
            .filter(|value| !value.trim().is_empty())
        {
            Some(url) => (url, false),
            None => (
                "postgresql://apexmail:apexmail@localhost:5432/apexmail".to_string(),
                true,
            ),
        }
    }

    async fn live_pool(test_name: &str) -> Option<PgPool> {
        let (base, defaulted) = live_base_url();
        let db_name = format!("apexmail_worker_{test_name}");
        match migrator::test_support::fresh_canonical_db(&base, &db_name).await {
            Ok(Some(pool)) => Some(pool),
            Ok(None) => None,
            Err(error) if defaulted && matches!(error.stage(), "admin-connect" | "db-connect") => {
                eprintln!("skipping {test_name}: local PostgreSQL at {base} unreachable ({error})");
                None
            }
            Err(error) => panic!("{}", error.panic_message()),
        }
    }

    /// A scripted AI classifier: lets a live test force one disposition
    /// through the non-deterministic path.
    struct ScriptedClassifier {
        disposition: ReplyDisposition,
        confidence: f64,
        fail: bool,
    }

    #[async_trait]
    impl ReplyClassifier for ScriptedClassifier {
        async fn classify(
            &self,
            _input: &ReplyInput,
        ) -> Result<super::super::types::AiClassification, ClassifyError> {
            if self.fail {
                return Err(ClassifyError::Transport("scripted outage".to_string()));
            }
            Ok(super::super::types::AiClassification {
                disposition: self.disposition,
                confidence: self.confidence,
                reasoning: "scripted classification".to_string(),
                model_version: Some("scripted-v1".to_string()),
                prompt_version: Some("test".to_string()),
                evidence: vec![Evidence::new("token", "scripted", "test")],
            })
        }
        fn name(&self) -> &'static str {
            "scripted"
        }
    }

    fn scripted_handler(
        pool: PgPool,
        disposition: ReplyDisposition,
        confidence: f64,
    ) -> ReplyHandler {
        ReplyHandler::with_classifier(
            pool,
            ReplyHandlerConfig::default(),
            Arc::new(ScriptedClassifier {
                disposition,
                confidence,
                fail: false,
            }),
        )
    }

    struct LiveFixture {
        enrollment_id: Uuid,
        step_execution_id: Uuid,
        action_step_id: Uuid,
        action_enrollment_id: Uuid,
        contact_point_id: Uuid,
        email: String,
    }

    /// Seed the canonical tables for one reply scenario. No cleanup: each
    /// ignored test provisions its own freshly-cloned database.
    async fn seed_live_fixture(pool: &PgPool, tenant: &str) -> LiveFixture {
        let account_id = Uuid::new_v4();
        let contact_id = Uuid::new_v4();
        let contact_point_id = Uuid::new_v4();
        let sequence_id = Uuid::new_v4();
        let version_id = Uuid::new_v4();
        let step_id = Uuid::new_v4();
        let enrollment_id = Uuid::new_v4();
        let step_execution_id = Uuid::new_v4();
        let email = format!(
            "prospect-{}@example.com",
            &Uuid::new_v4().simple().to_string()[..8]
        );

        sqlx::query(
            "INSERT INTO tenants (id, name, slug, plan, status) \
             VALUES ($1, 'Reply Test', $2, 'free', 'active')",
        )
        .bind(tenant)
        .bind(format!("reply-test-{tenant}"))
        .execute(pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO sales_accounts (id, tenant_id, company, domain) \
             VALUES ($1, $2, 'Fixture Co', $3)",
        )
        .bind(account_id)
        .bind(tenant)
        .bind(format!("{account_id}.example"))
        .execute(pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO sales_contacts (id, tenant_id, account_id, full_name) \
             VALUES ($1, $2, $3, 'Fixture Prospect')",
        )
        .bind(contact_id)
        .bind(tenant)
        .bind(account_id)
        .execute(pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO sales_contact_points \
                 (id, tenant_id, contact_id, channel, value, normalized_value, verification) \
             VALUES ($1, $2, $3, 'email', $4, lower($4), 'valid')",
        )
        .bind(contact_point_id)
        .bind(tenant)
        .bind(contact_id)
        .bind(&email)
        .execute(pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO sales_sequences (id, tenant_id, name, status) \
             VALUES ($1, $2, 'Fixture Sequence', 'active')",
        )
        .bind(sequence_id)
        .bind(tenant)
        .execute(pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO sales_sequence_versions \
                 (id, tenant_id, sequence_id, version, status, locale, approved_by, approved_at) \
             VALUES ($1, $2, $3, 1, 'active', 'en', 'fixture', NOW())",
        )
        .bind(version_id)
        .bind(tenant)
        .bind(sequence_id)
        .execute(pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO sales_sequence_steps \
                 (id, tenant_id, version_id, step_index, kind, min_delay_secs, max_delay_secs) \
             VALUES ($1, $2, $3, 0, 'email', 0, 0)",
        )
        .bind(step_id)
        .bind(tenant)
        .bind(version_id)
        .execute(pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO sales_enrollments \
                 (id, tenant_id, sequence_version_id, account_id, contact_id, contact_point_id, \
                  state, current_step_index) \
             VALUES ($1, $2, $3, $4, $5, $6, 'active', 0)",
        )
        .bind(enrollment_id)
        .bind(tenant)
        .bind(version_id)
        .bind(account_id)
        .bind(contact_id)
        .bind(contact_point_id)
        .execute(pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO sales_step_executions \
                 (id, tenant_id, enrollment_id, sequence_version_id, sequence_step_id, step_index, \
                  attempt_kind, variant, state, idempotency_key, scheduled_for) \
             VALUES ($1, $2, $3, $4, $5, 0, 'primary', 'default', 'scheduled', $6, NOW())",
        )
        .bind(step_execution_id)
        .bind(tenant)
        .bind(enrollment_id)
        .bind(version_id)
        .bind(step_id)
        .bind(format!("fixture-step:{step_execution_id}"))
        .execute(pool)
        .await
        .unwrap();
        // The production enqueue shape: send_step keyed on the step execution.
        let action_step_id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO sales_actions \
                 (id, tenant_id, action_type, entity_type, entity_id, due_at, priority, state, \
                  idempotency_key, payload) \
             VALUES ($1, $2, 'send_step', 'step_execution', $3, NOW(), 100, 'queued', $4, '{}')",
        )
        .bind(action_step_id)
        .bind(tenant)
        .bind(step_execution_id)
        .bind(format!("fixture-action-step:{step_execution_id}"))
        .execute(pool)
        .await
        .unwrap();
        // A second action keyed on the enrollment itself, to prove both
        // entity keys are cancelled.
        let action_enrollment_id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO sales_actions \
                 (id, tenant_id, action_type, entity_type, entity_id, due_at, priority, state, \
                  idempotency_key, payload) \
             VALUES ($1, $2, 'send_step', 'enrollment', $3, NOW(), 100, 'queued', $4, '{}')",
        )
        .bind(action_enrollment_id)
        .bind(tenant)
        .bind(enrollment_id)
        .bind(format!("fixture-action-enrollment:{enrollment_id}"))
        .execute(pool)
        .await
        .unwrap();

        LiveFixture {
            enrollment_id,
            step_execution_id,
            action_step_id,
            action_enrollment_id,
            contact_point_id,
            email,
        }
    }

    async fn seed_inbound(
        pool: &PgPool,
        id: &str,
        tenant: &str,
        from_email: &str,
        subject: &str,
        body: &str,
        headers: serde_json::Value,
    ) {
        sqlx::query(
            "INSERT INTO inbound_messages \
                 (id, tenant_id, from_email, to_email, subject, body_text, headers, received_at) \
             VALUES ($1, $2, $3, 'sales@apex.example', $4, $5, $6, NOW() - INTERVAL '1 minute')",
        )
        .bind(id)
        .bind(tenant)
        .bind(from_email)
        .bind(subject)
        .bind(body)
        .bind(headers)
        .execute(pool)
        .await
        .unwrap();
    }

    async fn fetch_message_by_id(
        handler: &ReplyHandler,
        msg_id: &str,
    ) -> ProcessorResult<InboundMessage> {
        // `inbound_messages.processing_at` is migration-owned (203); the
        // worker issues no schema statements.
        let messages = handler.fetch_messages(10).await?;
        messages
            .into_iter()
            .find(|message| message.id == msg_id)
            .ok_or_else(|| {
                ProcessorError::Internal(anyhow::anyhow!(
                    "inbound message {msg_id} was not claimable"
                ))
            })
    }

    async fn process_message_by_id(handler: &ReplyHandler, msg_id: &str) -> ProcessorResult<()> {
        let msg = fetch_message_by_id(handler, msg_id).await?;
        handler.process_message(msg).await
    }

    async fn enrollment_state(pool: &PgPool, id: Uuid) -> (String, bool) {
        sqlx::query_as("SELECT state, has_human_reply FROM sales_enrollments WHERE id = $1")
            .bind(id)
            .fetch_one(pool)
            .await
            .unwrap()
    }

    async fn action_state(pool: &PgPool, id: Uuid) -> String {
        sqlx::query_scalar("SELECT state FROM sales_actions WHERE id = $1")
            .bind(id)
            .fetch_one(pool)
            .await
            .unwrap()
    }

    /// §21 RELEASE GATE: a reply racing a queued send cancels the action, and
    /// the committed `has_human_reply` flag is set, so the next scheduled
    /// touch cannot race out.
    #[ignore = "requires PostgreSQL (TEST_DATABASE_URL; defaults to local Postgres)"]
    #[tokio::test]
    async fn live_reply_racing_a_queued_send_is_cancelled() {
        let Some(pool) = live_pool("reply_race").await else {
            return;
        };
        let tenant = format!("ten{}", &Uuid::new_v4().simple().to_string()[..20]);
        let fixture = seed_live_fixture(&pool, &tenant).await;
        seed_inbound(
            &pool,
            &format!("inb{}", &Uuid::new_v4().simple().to_string()[..20]),
            &tenant,
            &fixture.email,
            "Re: proposal",
            "Thanks for the note. Fine, let's keep it short.",
            serde_json::json!({}),
        )
        .await;

        // A human reply through the semantic layer (no deterministic match).
        let handler = scripted_handler(pool.clone(), ReplyDisposition::Positive, 0.95);
        let inbound_id: String =
            sqlx::query_scalar("SELECT id FROM inbound_messages WHERE tenant_id = $1")
                .bind(&tenant)
                .fetch_one(&pool)
                .await
                .unwrap();
        let msg = fetch_message_by_id(&handler, &inbound_id)
            .await
            .expect("claim the inbound reply");
        handler
            .process_message(msg.clone())
            .await
            .expect("processing the reply");

        // The queued send — however it was keyed — is no longer claimable.
        for action_id in [fixture.action_step_id, fixture.action_enrollment_id] {
            assert_eq!(
                action_state(&pool, action_id).await,
                "cancelled",
                "queued follow-up {action_id} must be cancelled by the reply lock"
            );
        }
        let claimable: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM sales_actions \
             WHERE tenant_id = $1 AND state IN ('queued', 'leased', 'executing')",
        )
        .bind(&tenant)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(claimable, 0, "nothing may remain claimable");

        let (state, has_human_reply) = enrollment_state(&pool, fixture.enrollment_id).await;
        assert_eq!(state, "replied");
        assert!(has_human_reply, "the committed race gate must be set");

        let step_state: String =
            sqlx::query_scalar("SELECT state FROM sales_step_executions WHERE id = $1")
                .bind(fixture.step_execution_id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(step_state, "cancelled");

        // The full classification record with suggested/actual pair.
        let (disposition, classifier, suggested, actual): (
            String,
            String,
            Option<String>,
            Option<String>,
        ) = sqlx::query_as(
            "SELECT disposition, classifier, suggested_action, actual_action \
             FROM sales_reply_classifications WHERE tenant_id = $1",
        )
        .bind(&tenant)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(disposition, "positive");
        assert_eq!(classifier, "ai");
        assert_eq!(suggested.as_deref(), Some("route_high_intent"));
        assert!(actual
            .unwrap_or_default()
            .contains("enrollment_locked:replied"));

        // §10 idempotency: re-processing the same logical message (the
        // crash-between-writes retry) adds nothing.
        handler
            .process_message(msg)
            .await
            .expect("re-processing the same message is idempotent");
        let rows: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM sales_reply_classifications WHERE tenant_id = $1",
        )
        .bind(&tenant)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(rows, 1, "exact repeats collapse to one audit row");

        pool.close().await;
    }

    /// Table-driven live test for every disposition's durable effects.
    #[ignore = "requires PostgreSQL (TEST_DATABASE_URL; defaults to local Postgres)"]
    #[tokio::test]
    async fn live_disposition_effects_match_the_policy_table() {
        let Some(pool) = live_pool("reply_effects").await else {
            return;
        };

        // (disposition, confidence, expected state, expect unsubscribe,
        //  expect contact-point invalidation, expect complaint outcome)
        let cases = [
            (
                ReplyDisposition::Unsubscribe,
                0.99,
                "suppressed",
                true,
                false,
                false,
            ),
            (
                ReplyDisposition::Complaint,
                0.99,
                "suppressed",
                true,
                false,
                true,
            ),
            (
                ReplyDisposition::BounceHard,
                0.99,
                "suppressed",
                true,
                true,
                false,
            ),
            (
                ReplyDisposition::BounceSoft,
                0.99,
                "waiting",
                false,
                false,
                false,
            ),
            (
                ReplyDisposition::OutOfOffice,
                0.99,
                "waiting",
                false,
                false,
                false,
            ),
            (
                ReplyDisposition::Positive,
                0.99,
                "replied",
                false,
                false,
                false,
            ),
            (
                ReplyDisposition::MeetingRequest,
                0.99,
                "replied",
                false,
                false,
                false,
            ),
            (
                ReplyDisposition::NotInterested,
                0.99,
                "completed",
                false,
                false,
                false,
            ),
            (
                ReplyDisposition::Unknown,
                0.99,
                "paused",
                false,
                false,
                false,
            ),
            // Low confidence must behave exactly like Unknown.
            (
                ReplyDisposition::Unsubscribe,
                0.2,
                "paused",
                false,
                false,
                false,
            ),
        ];

        for (
            index,
            (disposition, confidence, expected_state, expect_unsub, expect_inval, expect_penalty),
        ) in cases.into_iter().enumerate()
        {
            let tenant = format!("ten{}", &Uuid::new_v4().simple().to_string()[..20]);
            let fixture = seed_live_fixture(&pool, &tenant).await;
            let msg_id = format!("inb{}", &Uuid::new_v4().simple().to_string()[..20]);
            seed_inbound(
                &pool,
                &msg_id,
                &tenant,
                &fixture.email,
                "Re: proposal",
                "Fine, thanks.",
                serde_json::json!({}),
            )
            .await;

            let handler = scripted_handler(pool.clone(), disposition, confidence);
            process_message_by_id(&handler, &msg_id)
                .await
                .unwrap_or_else(|error| panic!("case {index} ({disposition:?}): {error}"));

            let (state, has_human_reply) = enrollment_state(&pool, fixture.enrollment_id).await;
            assert_eq!(
                state, expected_state,
                "case {index}: state for {disposition:?} at {confidence}"
            );
            assert_eq!(
                has_human_reply,
                disposition.stops_normal_sequence(),
                "case {index}: has_human_reply for {disposition:?} at {confidence}"
            );

            let unsubscribes: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM sales_unsubscribes \
                 WHERE tenant_id = $1 AND email = lower($2)",
            )
            .bind(&tenant)
            .bind(&fixture.email)
            .fetch_one(&pool)
            .await
            .unwrap();
            assert_eq!(
                unsubscribes,
                i64::from(expect_unsub),
                "case {index}: unsubscribe for {disposition:?} at {confidence}"
            );

            let (verification, suppressed): (String, bool) = sqlx::query_as(
                "SELECT verification, suppressed_at IS NOT NULL \
                 FROM sales_contact_points WHERE id = $1",
            )
            .bind(fixture.contact_point_id)
            .fetch_one(&pool)
            .await
            .unwrap();
            assert_eq!(
                verification,
                if expect_inval { "invalid" } else { "valid" },
                "case {index}: contact-point verification for {disposition:?}"
            );
            assert_eq!(
                suppressed, expect_inval,
                "case {index}: contact-point suppression for {disposition:?}"
            );

            let complaint_outcomes: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM sales_outcomes \
                 WHERE tenant_id = $1 AND outcome = 'complaint'",
            )
            .bind(&tenant)
            .fetch_one(&pool)
            .await
            .unwrap();
            assert_eq!(
                complaint_outcomes,
                i64::from(expect_penalty),
                "case {index}: sender-health penalty signal for {disposition:?} at {confidence}"
            );

            // OOO/soft bounce keep queued work; every other disposition
            // cancels it. Low-confidence Unknown cancels too.
            let cancelled = action_state(&pool, fixture.action_step_id).await == "cancelled";
            let should_cancel = disposition != ReplyDisposition::OutOfOffice
                && disposition != ReplyDisposition::BounceSoft
                || confidence < super::super::policy::MIN_AUTO_ACTION_CONFIDENCE;
            assert_eq!(
                cancelled, should_cancel,
                "case {index}: cancellation for {disposition:?} at {confidence}"
            );

            if disposition == ReplyDisposition::OutOfOffice {
                let due_at: chrono::DateTime<chrono::Utc> =
                    sqlx::query_scalar("SELECT due_at FROM sales_actions WHERE id = $1")
                        .bind(fixture.action_step_id)
                        .fetch_one(&pool)
                        .await
                        .unwrap();
                assert!(
                    due_at > Utc::now() + chrono::Duration::days(6),
                    "OOO must reschedule the queued send past the default wait"
                );
            }

            // §9: an unsubscribe suppresses but is never reported as a
            // complaint; a complaint is.
            if disposition == ReplyDisposition::Unsubscribe && confidence >= 0.7 {
                let platform_reason: String = sqlx::query_scalar(
                    "SELECT reason FROM suppressions WHERE tenant_id = $1 AND lower(email) = lower($2)",
                )
                .bind(&tenant)
                .bind(&fixture.email)
                .fetch_one(&pool)
                .await
                .unwrap();
                assert_eq!(platform_reason, "unsubscribe");
                assert_ne!(platform_reason, "complaint");
            }
            if disposition == ReplyDisposition::Complaint {
                let platform_reason: String = sqlx::query_scalar(
                    "SELECT reason FROM suppressions WHERE tenant_id = $1 AND lower(email) = lower($2)",
                )
                .bind(&tenant)
                .bind(&fixture.email)
                .fetch_one(&pool)
                .await
                .unwrap();
                assert_eq!(platform_reason, "complaint");

                let actual: String = sqlx::query_scalar(
                    "SELECT actual_action FROM sales_reply_classifications \
                     WHERE tenant_id = $1 AND classifier = 'ai'",
                )
                .bind(&tenant)
                .fetch_one(&pool)
                .await
                .unwrap();
                assert!(
                    actual.contains("sender_health_penalty"),
                    "the complaint's actual action must name the penalty: {actual}"
                );
            }
        }

        pool.close().await;
    }

    /// §10 idempotency + the operator-correction helper: an exact repeat is
    /// one row; a changed action is a first-class `operator` correction row.
    #[ignore = "requires PostgreSQL (TEST_DATABASE_URL; defaults to local Postgres)"]
    #[tokio::test]
    async fn live_repeat_classification_and_operator_correction_are_first_class() {
        let Some(pool) = live_pool("reply_correction").await else {
            return;
        };
        let tenant = format!("ten{}", &Uuid::new_v4().simple().to_string()[..20]);
        let fixture = seed_live_fixture(&pool, &tenant).await;
        let msg_id = format!("inb{}", &Uuid::new_v4().simple().to_string()[..20]);
        seed_inbound(
            &pool,
            &msg_id,
            &tenant,
            &fixture.email,
            "Re: proposal",
            "Fine, thanks.",
            serde_json::json!({}),
        )
        .await;

        let handler = scripted_handler(pool.clone(), ReplyDisposition::Unsubscribe, 0.99);
        let msg = fetch_message_by_id(&handler, &msg_id).await.unwrap();
        handler.process_message(msg.clone()).await.unwrap();

        let rows: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM sales_reply_classifications WHERE tenant_id = $1",
        )
        .bind(&tenant)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(rows, 1);
        let unsubscribes: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM sales_unsubscribes WHERE tenant_id = $1")
                .bind(&tenant)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(unsubscribes, 1);

        // Re-processing the same logical message (retry) must not create a
        // second suppression row or a second classification row.
        handler.process_message(msg).await.unwrap();
        let rows: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM sales_reply_classifications WHERE tenant_id = $1",
        )
        .bind(&tenant)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(rows, 1, "repeat classification is deduplicated");
        let unsubscribes: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM sales_unsubscribes WHERE tenant_id = $1")
                .bind(&tenant)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(unsubscribes, 1, "repeat suppression is idempotent");

        // An operator changes the action: the correction is a NEW row with
        // classifier='operator' and operator_correction set (the CP's partial
        // index surfaces exactly these).
        let classification_id: Uuid = sqlx::query_scalar(
            "SELECT id FROM sales_reply_classifications \
             WHERE tenant_id = $1 AND classifier = 'ai'",
        )
        .bind(&tenant)
        .fetch_one(&pool)
        .await
        .unwrap();
        let correction_id =
            record_action_outcome(&pool, &tenant, classification_id, "route_to_human_review")
                .await
                .unwrap()
                .expect("a changed action is a first-class correction row");

        let (classifier, disposition, correction, suggested, actual): (
            String,
            String,
            Option<String>,
            Option<String>,
            Option<String>,
        ) = sqlx::query_as(
            "SELECT classifier, disposition, operator_correction, suggested_action, actual_action \
             FROM sales_reply_classifications WHERE id = $1",
        )
        .bind(correction_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(classifier, "operator");
        assert_eq!(disposition, "unsubscribe");
        assert!(correction.unwrap_or_default().contains("actual"));
        assert_eq!(suggested.as_deref(), Some("suppress_endpoint"));
        assert_eq!(actual.as_deref(), Some("route_to_human_review"));

        // Confirming the suggestion does not add a row.
        let mut confirmed = None;
        for candidate in [classification_id] {
            confirmed = record_action_outcome(&pool, &tenant, candidate, "suppress_endpoint")
                .await
                .unwrap();
        }
        assert!(
            confirmed.is_none(),
            "a confirmation is not a correction row"
        );

        let operator_rows: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM sales_reply_classifications \
             WHERE tenant_id = $1 AND operator_correction IS NOT NULL",
        )
        .bind(&tenant)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(operator_rows, 1);

        // A direct operator correction of the disposition also inserts.
        let corrected_id = record_operator_correction(
            &pool,
            &tenant,
            &msg_id,
            ReplyDisposition::Unsubscribe,
            ReplyDisposition::NotInterested,
            1.0,
            "operator: it was a soft no, not an unsubscribe",
        )
        .await
        .unwrap();
        let corrected: (String, String, Option<String>) = sqlx::query_as(
            "SELECT classifier, disposition, operator_correction \
             FROM sales_reply_classifications WHERE id = $1",
        )
        .bind(corrected_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(corrected.0, "operator");
        assert_eq!(corrected.1, "not_interested");
        assert!(corrected.2.unwrap_or_default().contains("unsubscribe"));

        pool.close().await;
    }

    /// §8/§6/§4 live: deterministic DSN and OOO paths through the real
    /// processor (headers win, OOO does not cancel, hard bounce invalidates).
    #[ignore = "requires PostgreSQL (TEST_DATABASE_URL; defaults to local Postgres)"]
    #[tokio::test]
    async fn live_deterministic_dsn_and_ooo_paths() {
        let Some(pool) = live_pool("reply_deterministic").await else {
            return;
        };

        // Hard bounce: DSN body + 5xx status.
        let tenant = format!("ten{}", &Uuid::new_v4().simple().to_string()[..20]);
        let fixture = seed_live_fixture(&pool, &tenant).await;
        let msg_id = format!("inb{}", &Uuid::new_v4().simple().to_string()[..20]);
        let dsn_body = format!(
            "Reporting-MTA: dns; mx.example.com\n\n\
             Final-Recipient: rfc822; {}\n\
             Action: failed\nStatus: 5.1.1",
            fixture.email
        );
        seed_inbound(
            &pool,
            &msg_id,
            &tenant,
            "MAILER-DAEMON@mx.example.com",
            "Undelivered Mail Returned to Sender",
            &dsn_body,
            serde_json::json!({
                "content-type": "multipart/report; report-type=delivery-status"
            }),
        )
        .await;
        let handler = ReplyHandler::new(pool.clone(), ReplyHandlerConfig::default());
        process_message_by_id(&handler, &msg_id).await.unwrap();

        let (verification, suppressed): (String, bool) = sqlx::query_as(
            "SELECT verification, suppressed_at IS NOT NULL \
             FROM sales_contact_points WHERE id = $1",
        )
        .bind(fixture.contact_point_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(verification, "invalid");
        assert!(suppressed);
        let (state, flag): (String, bool) = enrollment_state(&pool, fixture.enrollment_id).await;
        assert_eq!(state, "suppressed");
        assert!(flag);

        // OOO: Auto-Submitted header + a stated return date. The sequence
        // must NOT be cancelled; the queued send is pushed past the date.
        let tenant = format!("ten{}", &Uuid::new_v4().simple().to_string()[..20]);
        let fixture = seed_live_fixture(&pool, &tenant).await;
        let msg_id = format!("inb{}", &Uuid::new_v4().simple().to_string()[..20]);
        seed_inbound(
            &pool,
            &msg_id,
            &tenant,
            &fixture.email,
            "Automatic reply: Re: proposal",
            "I am out of the office and will return on 2026-12-01.",
            serde_json::json!({"auto-submitted": "auto-replied"}),
        )
        .await;
        process_message_by_id(&handler, &msg_id).await.unwrap();

        let (state, flag) = enrollment_state(&pool, fixture.enrollment_id).await;
        assert_eq!(state, "waiting");
        assert!(!flag, "an OOO autoreply is not a human reply");
        let (action_state_value, due_at): (String, chrono::DateTime<chrono::Utc>) =
            sqlx::query_as("SELECT state, due_at FROM sales_actions WHERE id = $1")
                .bind(fixture.action_step_id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(action_state_value, "queued", "OOO keeps the queued send");
        assert!(
            due_at
                >= chrono::DateTime::parse_from_rfc3339("2026-12-02T09:00:00Z")
                    .unwrap()
                    .with_timezone(&Utc),
            "the queued send must move after the stated return date, got {due_at}"
        );

        // Soft bounce does not invalidate or suppress.
        let tenant = format!("ten{}", &Uuid::new_v4().simple().to_string()[..20]);
        let fixture = seed_live_fixture(&pool, &tenant).await;
        let msg_id = format!("inb{}", &Uuid::new_v4().simple().to_string()[..20]);
        let soft_body = format!(
            "Final-Recipient: rfc822; {}\nAction: delayed\nStatus: 4.4.1",
            fixture.email
        );
        seed_inbound(
            &pool,
            &msg_id,
            &tenant,
            "MAILER-DAEMON@mx.example.com",
            "Delayed delivery",
            &soft_body,
            serde_json::json!({"content-type": "multipart/report; report-type=delivery-status"}),
        )
        .await;
        process_message_by_id(&handler, &msg_id).await.unwrap();
        let (verification, suppressed): (String, bool) = sqlx::query_as(
            "SELECT verification, suppressed_at IS NOT NULL \
             FROM sales_contact_points WHERE id = $1",
        )
        .bind(fixture.contact_point_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(verification, "valid", "a soft bounce must not invalidate");
        assert!(!suppressed);
        let unsubscribes: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM sales_unsubscribes WHERE tenant_id = $1")
                .bind(&tenant)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(unsubscribes, 0);

        pool.close().await;
    }
}
