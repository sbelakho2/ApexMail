//! Durable action queue.
//!
//! The previous "autopilot" was an in-process `tokio::spawn` loop: work lived
//! in a `JoinHandle`, so a deploy or crash silently lost or duplicated it, and
//! only one process could ever make progress.
//!
//! `sales_actions` is a lease-based queue instead. Claims use
//! `FOR UPDATE SKIP LOCKED` so any number of workers run concurrently without
//! blocking each other, and a lease means a worker that dies mid-action is
//! recovered by lease expiry rather than losing the work. Every action carries
//! a unique `idempotency_key`, so replaying an action can never produce a
//! second external effect.

use chrono::{DateTime, Duration as ChronoDuration, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{PgPool, Postgres, Transaction};
use std::sync::Arc;
use uuid::Uuid;

use crate::types::SalesError;

/// Action kinds the engine can enqueue. Stored as text in
/// `sales_actions.action_type` so a new kind is a code change, not a migration.
pub mod action_type {
    /// Generate and send one sequence step for an enrollment.
    pub const SEND_STEP: &str = "send_step";
    /// Enrich an account or contact (waterfall).
    pub const ENRICH: &str = "enrich";
    /// Verify a contact point (email verification).
    pub const VERIFY_CONTACT_POINT: &str = "verify_contact_point";
    /// Gather evidence / research a company.
    pub const RESEARCH: &str = "research";
    /// Re-evaluate an account after new evidence arrives.
    pub const RESCORE: &str = "rescore";
    /// Run discovery for a tenant.
    pub const DISCOVER: &str = "discover";
    /// Poll a provider signal source.
    pub const POLL_SIGNALS: &str = "poll_signals";
    /// Hand work to a human operator.
    pub const OPERATOR_TASK: &str = "operator_task";
    /// Book or reschedule a meeting.
    pub const BOOK_MEETING: &str = "book_meeting";
}

/// Entity kinds an action can point at.
pub mod entity_type {
    pub const ACCOUNT: &str = "account";
    pub const CONTACT: &str = "contact";
    pub const ENROLLMENT: &str = "enrollment";
    pub const STEP_EXECUTION: &str = "step_execution";
    pub const JOB: &str = "job";
    pub const DECISION: &str = "decision";
}

/// Default lease duration. Long enough for an SMTP-side enqueue, short enough
/// that a crashed worker's work is picked up promptly.
pub const DEFAULT_LEASE_SECS: i64 = 120;

/// One row of the queue.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SalesAction {
    pub id: Uuid,
    pub tenant_id: String,
    pub action_type: String,
    pub entity_type: String,
    pub entity_id: Uuid,
    pub due_at: DateTime<Utc>,
    pub priority: i16,
    pub state: String,
    pub attempt: i32,
    pub max_attempts: i32,
    pub lease_owner: Option<String>,
    pub lease_expires_at: Option<DateTime<Utc>>,
    pub idempotency_key: String,
    pub payload: serde_json::Value,
    pub decision_id: Option<Uuid>,
    pub last_error: Option<String>,
    pub created_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
}

/// A claimed action, together with the lease the worker must present when it
/// completes or fails the action.
#[derive(Debug, Clone)]
pub struct LeasedAction {
    pub action: SalesAction,
    pub lease_owner: String,
}

impl LeasedAction {
    pub fn id(&self) -> Uuid {
        self.action.id
    }

    pub fn tenant_id(&self) -> &str {
        &self.action.tenant_id
    }

    pub fn action_type(&self) -> &str {
        &self.action.action_type
    }

    pub fn payload(&self) -> &serde_json::Value {
        &self.action.payload
    }
}

/// The outcome a worker reports for a claimed action.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ActionOutcome {
    /// Finished; the action is done and will not be retried.
    Succeeded,
    /// Failed but may be retried (transient). The action returns to `queued`
    /// with a backoff until `max_attempts`, then becomes `dead_letter`.
    Retry(String),
    /// Failed permanently. Goes straight to `dead_letter`.
    DeadLetter(String),
}

/// Queue operations. Stateless — every call takes the pool.
#[derive(Debug, Clone)]
pub struct ActionQueue {
    db: PgPool,
    /// Identifies this worker in `lease_owner`. Two processes must not share
    /// one owner string, or lease verification cannot tell them apart.
    worker_id: String,
}

impl ActionQueue {
    pub fn new(db: PgPool, worker_id: impl Into<String>) -> Self {
        Self {
            db,
            worker_id: worker_id.into(),
        }
    }

    pub fn worker_id(&self) -> &str {
        &self.worker_id
    }

    /// Enqueue an action, or return the existing row when the idempotency key
    /// is already present.
    ///
    /// Idempotent by construction: `ON CONFLICT (idempotency_key) DO NOTHING`
    /// plus a re-select means a retried enqueue returns the same action id and
    /// never creates a second unit of work.
    #[allow(clippy::too_many_arguments)]
    pub async fn enqueue(
        &self,
        tenant_id: &str,
        action_type: &str,
        entity_type: &str,
        entity_id: Uuid,
        idempotency_key: &str,
        payload: serde_json::Value,
        due_at: DateTime<Utc>,
        priority: i16,
        decision_id: Option<Uuid>,
    ) -> Result<SalesAction, SalesError> {
        // A due_at in the past is "immediately due", which is what callers mean.
        let due_at = due_at.max(Utc::now() - ChronoDuration::seconds(1));

        let inserted: Option<SalesAction> = sqlx::query_as::<_, SalesActionRow>(
            "INSERT INTO sales_actions ( \
                 id, tenant_id, action_type, entity_type, entity_id, due_at, priority, \
                 state, attempt, max_attempts, idempotency_key, payload, decision_id, created_at \
             ) VALUES (gen_random_uuid(), $1, $2, $3, $4, $5, $6, 'queued', 0, 5, $7, $8, $9, NOW()) \
             ON CONFLICT (idempotency_key) DO NOTHING \
             RETURNING *",
        )
        .bind(tenant_id)
        .bind(action_type)
        .bind(entity_type)
        .bind(entity_id)
        .bind(due_at)
        .bind(priority)
        .bind(idempotency_key)
        .bind(&payload)
        .bind(decision_id)
        .fetch_optional(&self.db)
        .await
        .map_err(|e| SalesError::Database(e.to_string()))?
        .map(Into::into);

        if let Some(action) = inserted {
            return Ok(action);
        }

        // Conflict: the same logical work already exists.
        let existing: SalesAction = sqlx::query_as::<_, SalesActionRow>(
            "SELECT * FROM sales_actions WHERE idempotency_key = $1",
        )
        .bind(idempotency_key)
        .fetch_one(&self.db)
        .await
        .map_err(|e| SalesError::Database(e.to_string()))?
        .into();
        Ok(existing)
    }

    /// Enqueue using an open transaction, so the unit of work and its trigger
    /// commit atomically.
    #[allow(clippy::too_many_arguments)]
    pub async fn enqueue_tx(
        tx: &mut Transaction<'_, Postgres>,
        tenant_id: &str,
        action_type: &str,
        entity_type: &str,
        entity_id: Uuid,
        idempotency_key: &str,
        payload: serde_json::Value,
        due_at: DateTime<Utc>,
        priority: i16,
        decision_id: Option<Uuid>,
    ) -> Result<Uuid, SalesError> {
        let id: Option<Uuid> = sqlx::query_scalar(
            "INSERT INTO sales_actions ( \
                 id, tenant_id, action_type, entity_type, entity_id, due_at, priority, \
                 state, attempt, max_attempts, idempotency_key, payload, decision_id, created_at \
             ) VALUES (gen_random_uuid(), $1, $2, $3, $4, $5, $6, 'queued', 0, 5, $7, $8, $9, NOW()) \
             ON CONFLICT (idempotency_key) DO NOTHING \
             RETURNING id",
        )
        .bind(tenant_id)
        .bind(action_type)
        .bind(entity_type)
        .bind(entity_id)
        .bind(due_at)
        .bind(priority)
        .bind(idempotency_key)
        .bind(&payload)
        .bind(decision_id)
        .fetch_optional(&mut **tx)
        .await
        .map_err(|e| SalesError::Database(e.to_string()))?;

        match id {
            Some(id) => Ok(id),
            None => sqlx::query_scalar("SELECT id FROM sales_actions WHERE idempotency_key = $1")
                .bind(idempotency_key)
                .fetch_one(&mut **tx)
                .await
                .map_err(|e| SalesError::Database(e.to_string())),
        }
    }

    /// Claim up to `limit` due actions for this worker.
    ///
    /// The claim is a single statement: the sub-select takes row locks with
    /// `FOR UPDATE SKIP LOCKED` so concurrent workers never contend, and the
    /// outer `UPDATE ... RETURNING` stamps the lease atomically. Two workers
    /// can therefore never claim the same action.
    ///
    /// Actions whose lease has expired are also reclaimable — that is the
    /// crash-recovery path. `attempt` is incremented at claim time so a
    /// repeatedly crashing worker eventually dead-letters instead of looping.
    pub async fn claim(
        &self,
        limit: i64,
        lease_secs: i64,
    ) -> Result<Vec<LeasedAction>, SalesError> {
        let lease_secs = lease_secs.max(1);
        let rows: Vec<SalesActionRow> = sqlx::query_as::<_, SalesActionRow>(
            "UPDATE sales_actions a \
             SET state = 'leased', \
                 lease_owner = $1, \
                 lease_expires_at = NOW() + make_interval(secs => $2::double precision), \
                 attempt = a.attempt + 1 \
             FROM ( \
                 SELECT id FROM sales_actions \
                 WHERE state = 'queued' AND due_at <= NOW() \
                 ORDER BY priority DESC, due_at ASC \
                 FOR UPDATE SKIP LOCKED \
                 LIMIT $3 \
             ) AS claimable \
             WHERE a.id = claimable.id \
             RETURNING a.*",
        )
        .bind(&self.worker_id)
        .bind(lease_secs as f64)
        .bind(limit)
        .fetch_all(&self.db)
        .await
        .map_err(|e| SalesError::Database(e.to_string()))?;

        Ok(rows
            .into_iter()
            .map(|row| LeasedAction {
                action: row.into(),
                lease_owner: self.worker_id.clone(),
            })
            .collect())
    }

    /// Refresh a lease while a long action is still running. Returns false if
    /// the lease was lost (reclaimed by another worker), in which case the
    /// caller must stop and not produce an external effect.
    pub async fn extend_lease(&self, action_id: Uuid, lease_secs: i64) -> Result<bool, SalesError> {
        let affected = sqlx::query(
            "UPDATE sales_actions \
             SET lease_expires_at = NOW() + make_interval(secs => $1::double precision) \
             WHERE id = $2 AND lease_owner = $3 AND state IN ('leased', 'executing')",
        )
        .bind(lease_secs.max(1) as f64)
        .bind(action_id)
        .bind(&self.worker_id)
        .execute(&self.db)
        .await
        .map_err(|e| SalesError::Database(e.to_string()))?
        .rows_affected();
        Ok(affected == 1)
    }

    /// Report the outcome of a claimed action.
    ///
    /// Lease-checked: only the worker holding the lease may complete it, so a
    /// worker that lost its lease cannot overwrite the state written by the
    /// worker that recovered the action.
    pub async fn finish(
        &self,
        action_id: Uuid,
        outcome: ActionOutcome,
    ) -> Result<bool, SalesError> {
        let (state, last_error, requeue): (&str, Option<&str>, bool) = match &outcome {
            ActionOutcome::Succeeded => ("succeeded", None, false),
            ActionOutcome::Retry(error) => ("queued", Some(error.as_str()), true),
            ActionOutcome::DeadLetter(error) => ("dead_letter", Some(error.as_str()), false),
        };

        if !requeue {
            let affected = sqlx::query(
                "UPDATE sales_actions \
                 SET state = $1, last_error = $2, lease_owner = NULL, lease_expires_at = NULL, \
                     completed_at = NOW() \
                 WHERE id = $3 AND lease_owner = $4 AND state IN ('leased', 'executing')",
            )
            .bind(state)
            .bind(last_error)
            .bind(action_id)
            .bind(&self.worker_id)
            .execute(&self.db)
            .await
            .map_err(|e| SalesError::Database(e.to_string()))?
            .rows_affected();
            return Ok(affected == 1);
        }

        // Retry: exponential backoff, and dead-letter once attempts are spent.
        // The attempt guard lives in SQL so two workers cannot both decide.
        let affected = sqlx::query(
            "UPDATE sales_actions \
             SET state = CASE WHEN attempt >= max_attempts THEN 'dead_letter' ELSE 'queued' END, \
                 last_error = $1, \
                 due_at = NOW() + make_interval(secs => LEAST(3600, 15 * POWER(2, attempt))::double precision), \
                 lease_owner = NULL, \
                 lease_expires_at = NULL, \
                 completed_at = CASE WHEN attempt >= max_attempts THEN NOW() ELSE NULL END \
             WHERE id = $2 AND lease_owner = $3 AND state IN ('leased', 'executing')",
        )
        .bind(last_error)
        .bind(action_id)
        .bind(&self.worker_id)
        .execute(&self.db)
        .await
        .map_err(|e| SalesError::Database(e.to_string()))?
        .rows_affected();
        Ok(affected == 1)
    }

    /// Requeue an action for immediate replay (operator-driven, from the CP).
    ///
    /// Clears the lease and resets the attempt counter so a dead-lettered
    /// action gets a full budget again. Returns false when the action does not
    /// exist for this tenant.
    pub async fn replay(&self, tenant_id: &str, action_id: Uuid) -> Result<bool, SalesError> {
        let affected = sqlx::query(
            "UPDATE sales_actions \
             SET state = 'queued', attempt = 0, due_at = NOW(), \
                 lease_owner = NULL, lease_expires_at = NULL, \
                 last_error = NULL, completed_at = NULL \
             WHERE id = $1 AND tenant_id = $2 \
               AND state IN ('failed', 'dead_letter', 'cancelled', 'succeeded')",
        )
        .bind(action_id)
        .bind(tenant_id)
        .execute(&self.db)
        .await
        .map_err(|e| SalesError::Database(e.to_string()))?
        .rows_affected();
        Ok(affected == 1)
    }

    /// Cancel every queued/leased action for an entity. Used when a human
    /// reply must stop a sequence immediately.
    pub async fn cancel_for_entity(
        &self,
        tenant_id: &str,
        entity_type: &str,
        entity_id: Uuid,
        reason: &str,
    ) -> Result<u64, SalesError> {
        let affected = sqlx::query(
            "UPDATE sales_actions \
             SET state = 'cancelled', last_error = $4, \
                 lease_owner = NULL, lease_expires_at = NULL, completed_at = NOW() \
             WHERE tenant_id = $1 AND entity_type = $2 AND entity_id = $3 \
               AND state IN ('queued', 'leased', 'executing')",
        )
        .bind(tenant_id)
        .bind(entity_type)
        .bind(entity_id)
        .bind(reason)
        .execute(&self.db)
        .await
        .map_err(|e| SalesError::Database(e.to_string()))?
        .rows_affected();
        Ok(affected)
    }

    /// Counts by state, for the CP control surface.
    pub async fn stats(&self, tenant_id: &str) -> Result<serde_json::Value, SalesError> {
        let rows: Vec<(String, i64)> = sqlx::query_as(
            "SELECT state, COUNT(*)::bigint FROM sales_actions \
             WHERE tenant_id = $1 GROUP BY state ORDER BY state",
        )
        .bind(tenant_id)
        .fetch_all(&self.db)
        .await
        .map_err(|e| SalesError::Database(e.to_string()))?;

        let mut by_state = serde_json::Map::new();
        let mut total = 0i64;
        for (state, count) in rows {
            total += count;
            by_state.insert(state, serde_json::json!(count));
        }

        let due_now: i64 = sqlx::query_scalar(
            "SELECT COUNT(*)::bigint FROM sales_actions \
             WHERE tenant_id = $1 AND state = 'queued' AND due_at <= NOW()",
        )
        .bind(tenant_id)
        .fetch_one(&self.db)
        .await
        .map_err(|e| SalesError::Database(e.to_string()))?;

        let dead_lettered: i64 = sqlx::query_scalar(
            "SELECT COUNT(*)::bigint FROM sales_actions \
             WHERE tenant_id = $1 AND state = 'dead_letter'",
        )
        .bind(tenant_id)
        .fetch_one(&self.db)
        .await
        .map_err(|e| SalesError::Database(e.to_string()))?;

        Ok(serde_json::json!({
            "total": total,
            "dueNow": due_now,
            "deadLettered": dead_lettered,
            "byState": by_state,
        }))
    }
}

/// Return actions whose lease expired to the queue, so a worker that died
/// mid-action is recovered instead of stranding the work in `leased`.
///
/// Actions that have already spent their attempt budget are dead-lettered
/// rather than requeued, which bounds the retry loop for a permanently
/// crashing handler.
///
/// Returns the number of rows moved (requeued + dead-lettered).
pub async fn requeue_expired_leases(db: &PgPool) -> Result<u64, SalesError> {
    let affected = sqlx::query(
        "UPDATE sales_actions \
         SET state = CASE WHEN attempt >= max_attempts THEN 'dead_letter' ELSE 'queued' END, \
             lease_owner = NULL, \
             lease_expires_at = NULL, \
             completed_at = CASE WHEN attempt >= max_attempts THEN NOW() ELSE NULL END, \
             last_error = COALESCE(last_error, 'lease expired — worker did not complete the action') \
         WHERE state IN ('leased', 'executing') \
           AND lease_expires_at IS NOT NULL \
           AND lease_expires_at < NOW()",
    )
    .execute(db)
    .await
    .map_err(|e| SalesError::Database(e.to_string()))?
    .rows_affected();
    Ok(affected)
}

/// Handles one claimed action.
///
/// Implementations must be idempotent: the queue guarantees at-least-once
/// delivery (a lease can expire after the handler produced its effect but
/// before it reported success), so a handler that sends mail must derive its
/// own idempotency key from the action rather than assuming a single run.
#[async_trait::async_trait]
pub trait ActionHandler: Send + Sync {
    async fn handle(&self, action: &LeasedAction) -> ActionOutcome;
}

/// A handler that dead-letters everything, naming the action type it could
/// not handle.
///
/// Used when a deployment has no handler registered. It is deliberately loud:
/// silently dropping work would look like an idle queue.
#[derive(Debug, Default)]
pub struct UnhandledActionHandler;

#[async_trait::async_trait]
impl ActionHandler for UnhandledActionHandler {
    async fn handle(&self, action: &LeasedAction) -> ActionOutcome {
        ActionOutcome::DeadLetter(format!(
            "no handler registered for action type '{}' (entity {} {})",
            action.action_type(),
            action.action.entity_type,
            action.action.entity_id
        ))
    }
}

/// One worker tick: recover expired leases, claim a batch, run each action,
/// report the outcome. Returns the number of actions processed.
///
/// Claims are sequential within a tick so a single worker cannot stampede the
/// database, but any number of processes can run this concurrently — the
/// `FOR UPDATE SKIP LOCKED` claim is what makes that safe.
pub async fn tick(
    queue: &ActionQueue,
    handler: &dyn ActionHandler,
    batch: i64,
    lease_secs: i64,
) -> Result<usize, SalesError> {
    let recovered = requeue_expired_leases(queue.db()).await?;
    if recovered > 0 {
        tracing::warn!(
            recovered,
            "sales action queue recovered work from expired leases"
        );
        metrics::counter!("sales_actions_lease_recovered_total").increment(recovered);
    }

    let claimed = queue.claim(batch, lease_secs).await?;
    let processed = claimed.len();

    for action in claimed {
        let started = std::time::Instant::now();
        let outcome = handler.handle(&action).await;

        // A handler that lost its lease must not write a result over the
        // worker that recovered the action.
        let reported = queue.finish(action.id(), outcome.clone()).await?;
        if !reported {
            tracing::warn!(
                action_id = %action.id(),
                "sales action result dropped: lease was lost (another worker recovered it)"
            );
            metrics::counter!("sales_actions_lease_lost_total").increment(1);
            continue;
        }

        let label = match &outcome {
            ActionOutcome::Succeeded => "succeeded",
            ActionOutcome::Retry(_) => "retry",
            ActionOutcome::DeadLetter(_) => "dead_letter",
        };
        metrics::counter!("sales_actions_completed_total", "outcome" => label).increment(1);
        metrics::histogram!("sales_action_duration_seconds", "action_type" => action.action.action_type.clone())
            .record(started.elapsed().as_secs_f64());

        if let ActionOutcome::DeadLetter(error) = &outcome {
            tracing::error!(
                action_id = %action.id(),
                action_type = %action.action_type(),
                error = %error,
                "sales action dead-lettered — operator intervention required"
            );
        }
    }

    Ok(processed)
}

/// Run the action worker until `shutdown` resolves.
pub async fn run(
    queue: ActionQueue,
    handler: Arc<dyn ActionHandler>,
    interval_secs: u64,
    batch: i64,
    lease_secs: i64,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
) {
    let base = std::time::Duration::from_secs(interval_secs.max(1));
    let mut shutdown = Box::pin(shutdown);
    tracing::info!(
        worker_id = queue.worker_id(),
        interval_secs = interval_secs,
        batch = batch,
        "sales action worker started"
    );

    loop {
        // Small jitter so multiple replicas do not all wake together.
        let jitter = std::time::Duration::from_millis(
            (std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| u64::from(d.subsec_millis()))
                .unwrap_or(0))
                % (base.as_millis().max(1) as u64 / 5 + 1),
        );

        tokio::select! {
            _ = &mut shutdown => {
                tracing::info!("sales action worker stopping");
                return;
            }
            _ = tokio::time::sleep(base + jitter) => {}
        }

        match tick(&queue, handler.as_ref(), batch, lease_secs).await {
            Ok(0) => {}
            Ok(processed) => {
                tracing::debug!(processed, "sales action tick complete");
            }
            Err(error) => {
                tracing::error!(error = %error, "sales action tick failed — will retry");
                metrics::counter!("sales_action_tick_errors_total").increment(1);
            }
        }
    }
}

impl ActionQueue {
    /// The pool this queue runs against (used by the worker tick).
    pub fn db(&self) -> &PgPool {
        &self.db
    }
}

/// Raw row mapping. Kept private so the column list has exactly one home.
#[derive(sqlx::FromRow)]
struct SalesActionRow {
    id: Uuid,
    tenant_id: String,
    action_type: String,
    entity_type: String,
    entity_id: Uuid,
    due_at: DateTime<Utc>,
    priority: i16,
    state: String,
    attempt: i32,
    max_attempts: i32,
    lease_owner: Option<String>,
    lease_expires_at: Option<DateTime<Utc>>,
    idempotency_key: String,
    payload: serde_json::Value,
    decision_id: Option<Uuid>,
    last_error: Option<String>,
    created_at: DateTime<Utc>,
    completed_at: Option<DateTime<Utc>>,
}

impl From<SalesActionRow> for SalesAction {
    fn from(row: SalesActionRow) -> Self {
        Self {
            id: row.id,
            tenant_id: row.tenant_id,
            action_type: row.action_type,
            entity_type: row.entity_type,
            entity_id: row.entity_id,
            due_at: row.due_at,
            priority: row.priority,
            state: row.state,
            attempt: row.attempt,
            max_attempts: row.max_attempts,
            lease_owner: row.lease_owner,
            lease_expires_at: row.lease_expires_at,
            idempotency_key: row.idempotency_key,
            payload: row.payload,
            decision_id: row.decision_id,
            last_error: row.last_error,
            created_at: row.created_at,
            completed_at: row.completed_at,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn action_type_constants_are_distinct() {
        let all = [
            action_type::SEND_STEP,
            action_type::ENRICH,
            action_type::VERIFY_CONTACT_POINT,
            action_type::RESEARCH,
            action_type::RESCORE,
            action_type::DISCOVER,
            action_type::POLL_SIGNALS,
            action_type::OPERATOR_TASK,
            action_type::BOOK_MEETING,
        ];
        let mut sorted = all.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), all.len(), "action types must be unique");
    }

    #[test]
    fn retry_error_carries_the_reason() {
        let outcome = ActionOutcome::Retry("smtp timeout".into());
        match outcome {
            ActionOutcome::Retry(reason) => assert_eq!(reason, "smtp timeout"),
            _ => panic!("expected Retry"),
        }
    }

    /// Live-DB proof that the durable queue actually serialises claims: two
    /// workers racing for one action must each get disjoint sets, and the
    /// total claimed must never exceed what was enqueued.
    #[ignore = "requires local PostgreSQL with the canonical sales schema"]
    #[tokio::test]
    async fn concurrent_workers_never_claim_the_same_action() {
        // Provisioned canonically (never the ambient TEST_DATABASE_URL, which
        // may be a legacy database whose schema this crate's guard refuses).
        let Some(pool) = crate::test_db::canonical_test_pool("concurrent_claims").await else {
            return;
        };

        let tenant = crate::test_db::unique_test_tenant("claim");
        let queue_a = ActionQueue::new(pool.clone(), format!("worker-a-{tenant}"));
        let queue_b = ActionQueue::new(pool.clone(), format!("worker-b-{tenant}"));

        let mut enqueued = Vec::new();
        for n in 0..20 {
            let action = queue_a
                .enqueue(
                    &tenant,
                    action_type::RESCORE,
                    entity_type::ACCOUNT,
                    Uuid::new_v4(),
                    &format!("claim-test:{tenant}:{n}"),
                    serde_json::json!({ "n": n }),
                    Utc::now() - ChronoDuration::seconds(1),
                    100,
                    None,
                )
                .await
                .unwrap();
            enqueued.push(action.id);
        }

        let (a, b) = tokio::join!(
            queue_a.claim(20, DEFAULT_LEASE_SECS),
            queue_b.claim(20, DEFAULT_LEASE_SECS)
        );
        let mut claimed: Vec<Uuid> = a
            .unwrap()
            .into_iter()
            .chain(b.unwrap())
            .map(|leased| leased.id())
            .collect();

        assert_eq!(
            claimed.len(),
            20,
            "two workers racing must claim the 20 enqueued actions exactly once each"
        );
        claimed.sort_unstable();
        claimed.dedup();
        assert_eq!(claimed.len(), 20, "an action was claimed twice");

        // Cleanup.
        sqlx::query("DELETE FROM sales_actions WHERE tenant_id = $1")
            .bind(&tenant)
            .execute(&pool)
            .await
            .unwrap();
    }

    /// Live-DB proof of the crash-recovery path: an action leased but never
    /// finished becomes claimable again once its lease expires.
    #[ignore = "requires local PostgreSQL with the canonical sales schema"]
    #[tokio::test]
    async fn expired_lease_is_recovered_by_another_worker() {
        let Some(pool) = crate::test_db::canonical_test_pool("lease_recovery").await else {
            return;
        };

        let tenant = crate::test_db::unique_test_tenant("lease");
        let queue_a = ActionQueue::new(pool.clone(), "worker-a");
        let queue_b = ActionQueue::new(pool.clone(), "worker-b");

        let action = queue_a
            .enqueue(
                &tenant,
                action_type::ENRICH,
                entity_type::ACCOUNT,
                Uuid::new_v4(),
                &format!("lease-test:{tenant}"),
                serde_json::json!({}),
                Utc::now() - ChronoDuration::seconds(1),
                100,
                None,
            )
            .await
            .unwrap();

        // Worker A claims, then "dies" without finishing.
        //
        // The queue is deliberately global (one worker serves every tenant), so
        // a claim may also return unrelated rows from other tests sharing this
        // database — assert on membership of OUR action, not on a count.
        let claimed = queue_a.claim(50, DEFAULT_LEASE_SECS).await.unwrap();
        let mine = claimed
            .iter()
            .find(|leased| leased.id() == action.id)
            .expect("worker A must claim the action it enqueued");
        assert_eq!(mine.action.attempt, 1, "first claim increments to 1");

        // Worker B cannot claim it while the lease is live.
        let other = queue_b.claim(50, DEFAULT_LEASE_SECS).await.unwrap();
        assert!(
            !other.iter().any(|leased| leased.id() == action.id),
            "a live lease must not be claimable by another worker"
        );

        // Simulate the worker dying: expire the lease directly.
        sqlx::query(
            "UPDATE sales_actions SET lease_expires_at = NOW() - INTERVAL '1 second' WHERE id = $1",
        )
        .bind(action.id)
        .execute(&pool)
        .await
        .unwrap();

        // The sweeper returns the stranded work to the queue…
        let requeued = requeue_expired_leases(&pool).await.unwrap();
        assert!(requeued >= 1);

        // …and worker B recovers it.
        let recovered = queue_b.claim(50, DEFAULT_LEASE_SECS).await.unwrap();
        let recovered_action = recovered
            .iter()
            .find(|leased| leased.id() == action.id)
            .expect("an expired lease must be recoverable by another worker");
        assert_eq!(
            recovered_action.action.attempt, 2,
            "recovery increments the attempt counter"
        );

        sqlx::query("DELETE FROM sales_actions WHERE tenant_id = $1")
            .bind(&tenant)
            .execute(&pool)
            .await
            .unwrap();
    }
}
