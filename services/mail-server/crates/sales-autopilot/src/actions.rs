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
use tokio::sync::{oneshot, OwnedSemaphorePermit, Semaphore};
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
///
/// `lease_token` identifies THIS claim, not just this worker: two claims by
/// the same `lease_owner` carry different tokens, so a worker whose action was
/// recovered by another process cannot complete it with a stale fence.
#[derive(Debug, Clone)]
pub struct LeasedAction {
    pub action: SalesAction,
    pub lease_owner: String,
    pub lease_token: Uuid,
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

    /// The full fence every worker-side mutation of this action must present.
    pub fn fence(&self) -> ActionFence {
        ActionFence {
            action_id: self.action.id,
            lease_owner: self.lease_owner.clone(),
            lease_token: self.lease_token,
        }
    }
}

/// Per-claim proof of ownership: action id + owner + the token issued by
/// [`ActionQueue::claim`].
///
/// Every worker-side mutation (`extend_lease`, `finish`, `attach_decision`)
/// matches on all three, plus a live `lease_expires_at` and
/// `state = 'executing'`. The owner string alone is not enough: two claims by
/// one worker (or two containers sharing a PID) are indistinguishable without
/// the token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActionFence {
    pub action_id: Uuid,
    pub lease_owner: String,
    pub lease_token: Uuid,
}

impl ActionFence {
    /// Pure mirror of the SQL predicate used by every fenced mutation, so the
    /// rule is unit-testable without a database. Keep in sync with the
    /// `WHERE id = ... AND lease_owner = ... AND lease_token = ... AND
    /// lease_expires_at > NOW() AND state = 'executing'` clauses below.
    pub fn authorizes(
        &self,
        stored_owner: Option<&str>,
        stored_token: Option<Uuid>,
        stored_expires_at: Option<DateTime<Utc>>,
        stored_state: &str,
        now: DateTime<Utc>,
    ) -> bool {
        stored_owner == Some(self.lease_owner.as_str())
            && stored_token == Some(self.lease_token)
            && stored_state == "executing"
            && stored_expires_at
                .map(|expires| expires > now)
                .unwrap_or(false)
    }
}

/// Verify a worker still holds a live lease on an action, taking a
/// `FOR SHARE` lock on the row for the caller's transaction.
///
/// Returns false when the lease was recovered by another worker, in which
/// case the caller MUST abort without producing an external effect.
pub async fn verify_fence_in_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    fence: &ActionFence,
) -> Result<bool, SalesError> {
    let row: Option<i32> = sqlx::query_scalar(
        "SELECT 1 FROM sales_actions \
         WHERE id = $1 AND lease_owner = $2 AND lease_token = $3 \
           AND lease_expires_at > NOW() AND state = 'executing' \
         FOR SHARE",
    )
    .bind(fence.action_id)
    .bind(&fence.lease_owner)
    .bind(fence.lease_token)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|e| SalesError::Database(e.to_string()))?;
    Ok(row.is_some())
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
    /// The handler's gates require a human before this work may run. The
    /// action parks in `awaiting_approval` — not complete, not failed, and
    /// not claimable until `control::review_decision` releases it.
    AwaitApproval,
}

/// The queue state a non-retry outcome maps to. Pure so the `AwaitApproval`
/// contract (work parks for a human instead of completing or dying) is
/// unit-testable without a database.
///
/// `Retry` maps to `queued` here as its default target; the real retry path
/// additionally dead-letters once the attempt budget is spent, which is
/// decided in SQL.
fn outcome_state(outcome: &ActionOutcome) -> &'static str {
    match outcome {
        ActionOutcome::Succeeded => "succeeded",
        ActionOutcome::Retry(_) => "queued",
        ActionOutcome::DeadLetter(_) => "dead_letter",
        ActionOutcome::AwaitApproval => "awaiting_approval",
    }
}

/// States an operator replay may touch.
///
/// `awaiting_approval` is deliberately absent: releasing approval-gated work
/// is `control::review_decision`'s job, and letting replay touch it would be
/// a second path around the approval gate. Binding this slice into the SQL
/// keeps the rule in one place instead of duplicating the list as a literal.
const REPLAYABLE_STATES: [&str; 2] = ["failed", "dead_letter"];

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

        // Conflict: the same logical work already exists. `sales_actions`'s
        // unique index on `idempotency_key` is GLOBAL, so the conflict may
        // belong to another tenant. Re-selecting by key alone would hand that
        // tenant's row (payload, entity, decision) across the isolation
        // boundary; matching the tenant too fails closed instead.
        let existing: Option<SalesAction> = sqlx::query_as::<_, SalesActionRow>(
            "SELECT * FROM sales_actions WHERE idempotency_key = $1 AND tenant_id = $2",
        )
        .bind(idempotency_key)
        .bind(tenant_id)
        .fetch_optional(&self.db)
        .await
        .map_err(|e| SalesError::Database(e.to_string()))?
        .map(Into::into);
        existing.ok_or_else(|| {
            SalesError::InvalidInput(format!(
                "idempotency key '{idempotency_key}' is already used by another tenant"
            ))
        })
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
            None => {
                // Same global-key caveat as `enqueue`: scope the re-select to
                // the requesting tenant so a collision cannot return (and let
                // the caller mutate) another tenant's action.
                let existing: Option<Uuid> = sqlx::query_scalar(
                    "SELECT id FROM sales_actions WHERE idempotency_key = $1 AND tenant_id = $2",
                )
                .bind(idempotency_key)
                .bind(tenant_id)
                .fetch_optional(&mut **tx)
                .await
                .map_err(|e| SalesError::Database(e.to_string()))?;
                existing.ok_or_else(|| {
                    SalesError::InvalidInput(format!(
                        "idempotency key '{idempotency_key}' is already used by another tenant"
                    ))
                })
            }
        }
    }

    /// Claim up to `limit` due actions for this worker.
    ///
    /// The claim is a single statement: the sub-select takes row locks with
    /// `FOR UPDATE SKIP LOCKED` so concurrent workers never contend, and the
    /// outer `UPDATE ... RETURNING` stamps the lease atomically. Two workers
    /// can therefore never claim the same action.
    ///
    /// Each row gets its OWN `lease_token` (`gen_random_uuid()` in the UPDATE,
    /// never a shared bind), so two claims by the same worker are individually
    /// fenced. The claimed state is `executing`: the claim IS the start of
    /// execution, and a lease is valid only while that state holds.
    ///
    /// Actions whose lease has expired are also reclaimable — that is the
    /// crash-recovery path (see [`requeue_expired_leases`]). `attempt` is
    /// incremented at claim time so a repeatedly crashing worker eventually
    /// dead-letters instead of looping.
    pub async fn claim(
        &self,
        limit: i64,
        lease_secs: i64,
    ) -> Result<Vec<LeasedAction>, SalesError> {
        self.claim_filtered(limit, lease_secs, None).await
    }

    /// Claim due actions, optionally restricted to specific ids.
    ///
    /// `claim` deliberately takes ANY due work: one worker drains every tenant,
    /// and that is what makes a pool of replicas efficient. This variant exists
    /// for the caller that already knows which work it wants, in which case
    /// taking unrelated rows is wrong rather than merely wasteful:
    ///
    ///   * a targeted recovery of one stuck action;
    ///   * a test that must not race and be raced by unrelated rows sharing the
    ///     same database (the reason the queue tests previously had to run
    ///     serialized — a test using the global claim would steal another
    ///     test's action, and be stolen from).
    ///
    /// It is the SAME statement as `claim` with one extra predicate, so the
    /// state/lease/token semantics cannot drift between the two paths.
    pub async fn claim_filtered(
        &self,
        limit: i64,
        lease_secs: i64,
        only: Option<&[Uuid]>,
    ) -> Result<Vec<LeasedAction>, SalesError> {
        let lease_secs = lease_secs.max(1);
        let rows: Vec<SalesActionRow> = sqlx::query_as::<_, SalesActionRow>(
            "WITH claimable AS ( \
                 SELECT id FROM sales_actions \
                 WHERE state = 'queued' AND due_at <= NOW() \
                   AND ($4::uuid[] IS NULL OR id = ANY($4)) \
                 ORDER BY priority DESC, due_at ASC \
                 FOR UPDATE SKIP LOCKED \
                 LIMIT $3 \
             ) \
             UPDATE sales_actions a \
             SET state = 'executing', \
                 lease_owner = $1, \
                 lease_token = gen_random_uuid(), \
                 lease_expires_at = NOW() + make_interval(secs => $2::double precision), \
                 attempt = a.attempt + 1 \
             FROM claimable \
             WHERE a.id = claimable.id \
             RETURNING a.*",
        )
        .bind(&self.worker_id)
        .bind(lease_secs as f64)
        .bind(limit)
        .bind(only)
        .fetch_all(&self.db)
        .await
        .map_err(|e| SalesError::Database(e.to_string()))?;

        Ok(rows
            .into_iter()
            .map(|row| {
                // The claim always stamps a token; a nil fallback would only
                // be reachable on a corrupted row, and fails closed because no
                // fence ever matches nil.
                let lease_token = row.lease_token.unwrap_or_default();
                LeasedAction {
                    action: row.into(),
                    lease_owner: self.worker_id.clone(),
                    lease_token,
                }
            })
            .collect())
    }

    /// Refresh a lease while a long action is still running. Returns false if
    /// the lease was lost (reclaimed by another worker), in which case the
    /// caller must stop and not produce an external effect.
    ///
    /// Fenced on the full [`ActionFence`]: owner AND per-claim token AND a
    /// live expiry AND `state = 'executing'`.
    pub async fn extend_lease(
        &self,
        fence: &ActionFence,
        lease_secs: i64,
    ) -> Result<bool, SalesError> {
        let affected = sqlx::query(
            "UPDATE sales_actions \
             SET lease_expires_at = NOW() + make_interval(secs => $1::double precision) \
             WHERE id = $2 AND lease_owner = $3 AND lease_token = $4 \
               AND lease_expires_at > NOW() AND state = 'executing'",
        )
        .bind(lease_secs.max(1) as f64)
        .bind(fence.action_id)
        .bind(&fence.lease_owner)
        .bind(fence.lease_token)
        .execute(&self.db)
        .await
        .map_err(|e| SalesError::Database(e.to_string()))?
        .rows_affected();
        Ok(affected == 1)
    }

    /// Report the outcome of a claimed action.
    ///
    /// Fenced: only the worker holding THIS claim (owner + token + live
    /// lease + `executing`) may complete it, so a worker whose action was
    /// recovered by another process cannot overwrite the recovered worker's
    /// state. Returns false when the fence is stale.
    ///
    /// `AwaitApproval` parks the action in `awaiting_approval` with no lease
    /// and `completed_at = NULL`: it is not complete, and it must not be
    /// counted as succeeded or dead-lettered. Only an operator review
    /// (`control::review_decision`) releases it.
    pub async fn finish(
        &self,
        fence: &ActionFence,
        outcome: ActionOutcome,
    ) -> Result<bool, SalesError> {
        if let ActionOutcome::Retry(error) = &outcome {
            // Retry: exponential backoff, and dead-letter once attempts are
            // spent. The attempt guard lives in SQL so two workers cannot both
            // decide.
            let affected = sqlx::query(
                "UPDATE sales_actions \
                 SET state = CASE WHEN attempt >= max_attempts THEN 'dead_letter' ELSE 'queued' END, \
                     last_error = $1, \
                     due_at = NOW() + make_interval(secs => LEAST(3600, 15 * POWER(2, attempt))::double precision), \
                     lease_owner = NULL, \
                     lease_token = NULL, \
                     lease_expires_at = NULL, \
                     completed_at = CASE WHEN attempt >= max_attempts THEN NOW() ELSE NULL END \
                 WHERE id = $2 AND lease_owner = $3 AND lease_token = $4 \
                   AND lease_expires_at > NOW() AND state = 'executing'",
            )
            .bind(error)
            .bind(fence.action_id)
            .bind(&fence.lease_owner)
            .bind(fence.lease_token)
            .execute(&self.db)
            .await
            .map_err(|e| SalesError::Database(e.to_string()))?
            .rows_affected();
            return Ok(affected == 1);
        }

        let state = outcome_state(&outcome);
        let last_error = match &outcome {
            ActionOutcome::DeadLetter(error) => Some(error.as_str()),
            _ => None,
        };
        // `AwaitApproval` is the same fenced write as a terminal outcome, but
        // it keeps `completed_at` NULL and drops the error text: the work is
        // parked for a human, not done and not failed.
        let awaiting_approval = outcome == ActionOutcome::AwaitApproval;
        let affected = sqlx::query(
            "UPDATE sales_actions \
             SET state = $1, last_error = $2, lease_owner = NULL, lease_token = NULL, \
                 lease_expires_at = NULL, \
                 completed_at = CASE WHEN $5 THEN NULL ELSE NOW() END \
             WHERE id = $3 AND lease_owner = $4 AND lease_token = $6 \
               AND lease_expires_at > NOW() AND state = 'executing'",
        )
        .bind(state)
        .bind(last_error)
        .bind(fence.action_id)
        .bind(&fence.lease_owner)
        .bind(awaiting_approval)
        .bind(fence.lease_token)
        .execute(&self.db)
        .await
        .map_err(|e| SalesError::Database(e.to_string()))?
        .rows_affected();
        Ok(affected == 1)
    }

    /// Attach the Decision Packet to an action, fenced by the caller's lease.
    ///
    /// Returns false if the fence is stale: a worker whose lease was recovered
    /// must not re-point the action at a different decision, and the recovered
    /// worker owns whatever it writes.
    pub async fn attach_decision(
        &self,
        fence: &ActionFence,
        decision_id: Uuid,
    ) -> Result<bool, SalesError> {
        let affected = sqlx::query(
            "UPDATE sales_actions \
             SET decision_id = $1 \
             WHERE id = $2 AND lease_owner = $3 AND lease_token = $4 \
               AND lease_expires_at > NOW() AND state = 'executing'",
        )
        .bind(decision_id)
        .bind(fence.action_id)
        .bind(&fence.lease_owner)
        .bind(fence.lease_token)
        .execute(&self.db)
        .await
        .map_err(|e| SalesError::Database(e.to_string()))?
        .rows_affected();
        Ok(affected == 1)
    }

    /// Requeue an action for immediate replay (operator-driven, from the CP).
    ///
    /// OPERATOR PATH — deliberately NOT fenced: no worker lease is held by the
    /// caller, so requiring a token would make replay impossible. The action
    /// must be terminal (`failed`/`dead_letter`, see [`REPLAYABLE_STATES`]);
    /// `awaiting_approval` is refused because releasing approval-gated work is
    /// `control::review_decision`'s job, and replaying it would be a second
    /// path around the approval gate.
    ///
    /// Clears any stale lease and resets the attempt counter so a dead-lettered
    /// action gets a full budget again. Returns false when the action does not
    /// exist for this tenant or is not replayable.
    pub async fn replay(&self, tenant_id: &str, action_id: Uuid) -> Result<bool, SalesError> {
        let affected = sqlx::query(
            "UPDATE sales_actions \
             SET state = 'queued', attempt = 0, due_at = NOW(), \
                 lease_owner = NULL, lease_token = NULL, lease_expires_at = NULL, \
                 last_error = NULL, completed_at = NULL \
             WHERE id = $1 AND tenant_id = $2 \
               AND state = ANY($3)",
        )
        .bind(action_id)
        .bind(tenant_id)
        .bind(&REPLAYABLE_STATES[..])
        .execute(&self.db)
        .await
        .map_err(|e| SalesError::Database(e.to_string()))?
        .rows_affected();
        Ok(affected == 1)
    }

    /// Cancel every queued/leased action for an entity. Used when a human
    /// reply must stop a sequence immediately.
    ///
    /// OPERATOR/SYSTEM PATH — deliberately NOT fenced: this is a stop signal
    /// that must win over any lease, so it clears the lease (including the
    /// token) instead of presenting one. A worker whose action is cancelled
    /// underneath it then fails its own fenced `finish` and drops the result,
    /// which is exactly the intent.
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
                 lease_owner = NULL, lease_token = NULL, lease_expires_at = NULL, \
                 completed_at = NOW() \
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
/// Both `leased` and `executing` are swept deliberately: post-201 claims land
/// directly in `executing` (the claim IS the start of execution), but a
/// database that still carries pre-201 rows may hold work in the old `leased`
/// state, and those rows must remain recoverable until the queue has drained.
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
             lease_token = NULL, \
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

/// How often an in-flight action's lease is extended: one third of the lease,
/// clamped to at least one second so a zero/one-second lease cannot produce a
/// zero-length interval (which would busy-loop the heartbeat).
fn heartbeat_interval(lease_secs: i64) -> std::time::Duration {
    std::time::Duration::from_secs(lease_secs.max(1).saturating_div(3).max(1) as u64)
}

/// Execute one claimed action under its lease.
///
/// Owned so it can be spawned: the tick hands each claimed action to the
/// runtime immediately and keeps claiming only up to the free slots, so
/// actions run in parallel instead of one at a time.
///
/// Cancellation: a heartbeat task extends the lease every
/// [`heartbeat_interval`]. When `extend_lease` returns false the lease was
/// recovered by another worker; the heartbeat fires a oneshot and the
/// `tokio::select!` below drops the handler future. That drop is the
/// cooperative stop signal the existing `ActionHandler` interface supports,
/// and it is the EARLIER of the two lease-lost signals — the later one is
/// `finish` returning false, which guarantees no result is written over the
/// recovering worker. A handler dropped mid-effect is safe because the queue
/// contract already requires idempotent handlers (`idempotency_key`).
async fn execute_claimed(
    queue: ActionQueue,
    handler: Arc<dyn ActionHandler>,
    action: LeasedAction,
    lease_secs: i64,
    _permit: OwnedSemaphorePermit,
) {
    let started = std::time::Instant::now();
    let fence = action.fence();

    let (lost_tx, mut lost_rx) = oneshot::channel::<()>();
    let heartbeat_queue = queue.clone();
    let heartbeat_fence = fence.clone();
    let heartbeat = tokio::spawn(async move {
        loop {
            tokio::time::sleep(heartbeat_interval(lease_secs)).await;
            match heartbeat_queue
                .extend_lease(&heartbeat_fence, lease_secs)
                .await
            {
                Ok(true) => {}
                Ok(false) => {
                    // Lease lost: stop the handler and stop beating.
                    let _ = lost_tx.send(());
                    return;
                }
                Err(error) => {
                    // A transient database error is not proof the lease is
                    // gone; keep beating and let the final fenced write decide.
                    tracing::warn!(
                        action_id = %heartbeat_fence.action_id,
                        error = %error,
                        "sales action lease heartbeat failed; will retry"
                    );
                }
            }
        }
    });

    // The handler runs concurrently with the heartbeat; whichever finishes
    // first wins. On lease loss the handler future is dropped (cancelled).
    let outcome = tokio::select! {
        outcome = handler.handle(&action) => Some(outcome),
        _ = &mut lost_rx => None,
    };
    heartbeat.abort();

    let Some(outcome) = outcome else {
        tracing::warn!(
            action_id = %action.id(),
            "sales action abandoned mid-flight: lease was lost (another worker recovered it)"
        );
        metrics::counter!("sales_actions_lease_lost_total").increment(1);
        return;
    };

    match queue.finish(&fence, outcome.clone()).await {
        Ok(true) => {}
        Ok(false) => {
            // The write is fenced, so a false here proves the lease was lost
            // after (or while) the handler ran. The result is deliberately
            // dropped rather than written over the recovering worker.
            tracing::warn!(
                action_id = %action.id(),
                "sales action result dropped: lease was lost (another worker recovered it)"
            );
            metrics::counter!("sales_actions_lease_lost_total").increment(1);
            return;
        }
        Err(error) => {
            tracing::error!(
                action_id = %action.id(),
                error = %error,
                "sales action outcome could not be recorded"
            );
            return;
        }
    }

    let label = match &outcome {
        ActionOutcome::Succeeded => "succeeded",
        ActionOutcome::Retry(_) => "retry",
        ActionOutcome::DeadLetter(_) => "dead_letter",
        ActionOutcome::AwaitApproval => "awaiting_approval",
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

/// One worker tick: recover expired leases, claim at most the number of
/// currently free execution slots, and spawn each claimed action so they run
/// in parallel. Returns the number of actions claimed (handed to handlers) in
/// this tick.
///
/// The semaphore is sized to the worker's concurrency and held by each
/// in-flight action, so a later tick claims only the slots that are actually
/// free — the worker never has more than `concurrency` actions in flight, and
/// the stale-lease window of a batch pre-lease is gone. Any number of
/// processes can run this concurrently; `FOR UPDATE SKIP LOCKED` makes the
/// claims safe.
pub async fn tick(
    queue: &ActionQueue,
    handler: &Arc<dyn ActionHandler>,
    semaphore: &Arc<Semaphore>,
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

    let permits = semaphore.available_permits().max(1);
    let claimed = queue.claim(permits as i64, lease_secs).await?;
    let claimed_count = claimed.len();

    for action in claimed {
        // The claim was sized to the free permits, so this normally resolves
        // immediately; awaiting covers a concurrent tick racing for the same
        // slot. A closed semaphore (teardown) requeues the action instead of
        // stranding it in this process's hands.
        let permit = match semaphore.clone().acquire_owned().await {
            Ok(permit) => permit,
            Err(_) => {
                let _ = queue
                    .finish(
                        &action.fence(),
                        ActionOutcome::Retry("worker semaphore closed before execution".into()),
                    )
                    .await;
                continue;
            }
        };
        // Detached on purpose: the permit bounds in-flight work, the tick
        // returns so the next tick can top up free slots, and lease expiry
        // recovers anything interrupted by a hard process exit.
        let _join = tokio::spawn(execute_claimed(
            queue.clone(),
            handler.clone(),
            action,
            lease_secs,
            permit,
        ));
    }

    Ok(claimed_count)
}

/// Run the action worker until `shutdown` resolves.
///
/// `concurrency` is the maximum number of actions in flight simultaneously.
/// Shutdown stops new claims; actions already in flight are not forcibly
/// awaited — a hard exit is recovered by lease expiry, and handlers are
/// idempotent by contract.
pub async fn run(
    queue: ActionQueue,
    handler: Arc<dyn ActionHandler>,
    interval_secs: u64,
    concurrency: i64,
    lease_secs: i64,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
) {
    let base = std::time::Duration::from_secs(interval_secs.max(1));
    let concurrency = concurrency.max(1);
    let semaphore = Arc::new(Semaphore::new(concurrency as usize));
    let mut shutdown = Box::pin(shutdown);
    tracing::info!(
        worker_id = queue.worker_id(),
        interval_secs = interval_secs,
        concurrency = concurrency,
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

        match tick(&queue, &handler, &semaphore, lease_secs).await {
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
    lease_token: Option<Uuid>,
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

    /// `sales_actions` row read back after [`ActionQueue::finish`] parks an
    /// action awaiting approval.
    #[derive(sqlx::FromRow)]
    struct ParkedActionRow {
        state: String,
        lease_owner: Option<String>,
        lease_token: Option<Uuid>,
        lease_expires_at: Option<DateTime<Utc>>,
        completed_at: Option<DateTime<Utc>>,
    }

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
            queue_a.claim_filtered(20, DEFAULT_LEASE_SECS, Some(&enqueued)),
            queue_b.claim_filtered(20, DEFAULT_LEASE_SECS, Some(&enqueued))
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
        // Every claim here is scoped to the action under test. The production
        // claim is deliberately global (one worker drains every tenant), so an
        // unscoped claim in a test would take — and be raced by — unrelated rows
        // sharing this database.
        let claimed = queue_a
            .claim_filtered(50, DEFAULT_LEASE_SECS, Some(&[action.id]))
            .await
            .unwrap();
        let mine = claimed
            .iter()
            .find(|leased| leased.id() == action.id)
            .expect("worker A must claim the action it enqueued");
        assert_eq!(mine.action.attempt, 1, "first claim increments to 1");

        // Worker B cannot claim it while the lease is live.
        let other = queue_b
            .claim_filtered(50, DEFAULT_LEASE_SECS, Some(&[action.id]))
            .await
            .unwrap();
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

        // The sweeper returns the stranded work to the queue.
        //
        // The sweep is deployment-global, so a concurrent test sharing this
        // database may already have recovered our action before this call —
        // assert on OUR action's resulting state rather than on the global
        // count, which is a property of the whole database, not of this test.
        requeue_expired_leases(&pool).await.unwrap();
        let requeued_state: String =
            sqlx::query_scalar("SELECT state FROM sales_actions WHERE id = $1")
                .bind(action.id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(
            requeued_state, "queued",
            "an expired lease must return the action to the queue"
        );

        // …and worker B recovers it. The claim may be skipped once by a
        // concurrent test's deployment-global sweep still holding the row
        // lock (`FOR UPDATE SKIP LOCKED`), so retry briefly — the property
        // asserted (the survivor recovers the row, attempt incremented) is
        // unchanged.
        let mut recovered = Vec::new();
        for _ in 0..20 {
            recovered = queue_b
                .claim_filtered(50, DEFAULT_LEASE_SECS, Some(&[action.id]))
                .await
                .unwrap();
            if recovered.iter().any(|leased| leased.id() == action.id) {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
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

    // -----------------------------------------------------------------------
    // Lease-token fences
    // -----------------------------------------------------------------------

    fn sample_action(id: Uuid) -> SalesAction {
        SalesAction {
            id,
            tenant_id: "tenant-fence".into(),
            action_type: action_type::RESCORE.into(),
            entity_type: entity_type::ACCOUNT.into(),
            entity_id: Uuid::new_v4(),
            due_at: Utc::now(),
            priority: 100,
            state: "executing".into(),
            attempt: 1,
            max_attempts: 5,
            lease_owner: Some("worker-a".into()),
            lease_expires_at: Some(Utc::now() + ChronoDuration::seconds(30)),
            idempotency_key: format!("fence:{id}"),
            payload: serde_json::json!({}),
            decision_id: None,
            last_error: None,
            created_at: Utc::now(),
            completed_at: None,
        }
    }

    #[test]
    fn leased_action_fence_carries_action_id_owner_and_token() {
        let id = Uuid::new_v4();
        let token = Uuid::new_v4();
        let leased = LeasedAction {
            action: sample_action(id),
            lease_owner: "worker-a".into(),
            lease_token: token,
        };
        let fence = leased.fence();
        assert_eq!(fence.action_id, id);
        assert_eq!(fence.lease_owner, "worker-a");
        assert_eq!(fence.lease_token, token);
    }

    /// The pure mirror of the SQL fence predicate: owner AND token AND live
    /// expiry AND `executing`. Each conjunct is individually load-bearing.
    #[test]
    fn fence_authorizes_only_the_matching_live_lease() {
        let now = Utc::now();
        let token = Uuid::new_v4();
        let fence = ActionFence {
            action_id: Uuid::new_v4(),
            lease_owner: "worker-a".into(),
            lease_token: token,
        };
        let live = Some(now + ChronoDuration::seconds(30));

        assert!(fence.authorizes(Some("worker-a"), Some(token), live, "executing", now));

        // A second claim by the SAME worker has a different token: the first
        // claim must no longer be able to write.
        assert!(
            !fence.authorizes(
                Some("worker-a"),
                Some(Uuid::new_v4()),
                live,
                "executing",
                now
            ),
            "a same-worker claim with a different token must not be authorized"
        );
        assert!(
            !fence.authorizes(Some("worker-b"), Some(token), live, "executing", now),
            "a different owner must not be authorized"
        );
        assert!(
            !fence.authorizes(
                Some("worker-a"),
                Some(token),
                Some(now - ChronoDuration::seconds(1)),
                "executing",
                now
            ),
            "an expired lease must not be authorized"
        );
        assert!(
            !fence.authorizes(
                Some("worker-a"),
                Some(token),
                live,
                "awaiting_approval",
                now
            ),
            "only an executing action can be mutated by its worker"
        );
        assert!(
            !fence.authorizes(None, None, None, "queued", now),
            "a row without a lease must never match"
        );
    }

    // -----------------------------------------------------------------------
    // Outcome mapping and operator replay guard
    // -----------------------------------------------------------------------

    #[test]
    fn await_approval_parks_work_instead_of_completing_or_failing() {
        assert_eq!(
            outcome_state(&ActionOutcome::AwaitApproval),
            "awaiting_approval"
        );
        assert_ne!(
            outcome_state(&ActionOutcome::AwaitApproval),
            "succeeded",
            "approval is not completion"
        );
        assert_ne!(
            outcome_state(&ActionOutcome::AwaitApproval),
            "dead_letter",
            "approval is not failure"
        );
        assert_eq!(outcome_state(&ActionOutcome::Succeeded), "succeeded");
        assert_eq!(
            outcome_state(&ActionOutcome::DeadLetter("boom".into())),
            "dead_letter"
        );
    }

    #[test]
    fn replay_never_targets_awaiting_approval() {
        assert!(REPLAYABLE_STATES.contains(&"failed"));
        assert!(REPLAYABLE_STATES.contains(&"dead_letter"));
        assert!(
            !REPLAYABLE_STATES.contains(&"awaiting_approval"),
            "replaying approval-gated work would bypass the approval gate"
        );
        assert!(!REPLAYABLE_STATES.contains(&"queued"));
        assert!(!REPLAYABLE_STATES.contains(&"executing"));
        assert!(!REPLAYABLE_STATES.contains(&"succeeded"));
    }

    #[test]
    fn heartbeat_interval_is_clamped_to_at_least_one_second() {
        use std::time::Duration;
        // A zero/one-second lease must not produce a zero-length interval.
        assert_eq!(heartbeat_interval(0), Duration::from_secs(1));
        assert_eq!(heartbeat_interval(1), Duration::from_secs(1));
        assert_eq!(heartbeat_interval(2), Duration::from_secs(1));
        assert_eq!(heartbeat_interval(3), Duration::from_secs(1));
        assert_eq!(heartbeat_interval(120), Duration::from_secs(40));
        assert_eq!(heartbeat_interval(150), Duration::from_secs(50));
    }

    // -----------------------------------------------------------------------
    // Live-DB proofs
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn claim_issues_a_distinct_token_per_row() {
        let Some(pool) = crate::test_db::canonical_test_pool("claim_tokens").await else {
            return;
        };
        let tenant = crate::test_db::unique_test_tenant("tokens");
        let queue = ActionQueue::new(pool.clone(), format!("worker-{tenant}"));

        let mut ours = Vec::new();
        for n in 0..6 {
            let action = queue
                .enqueue(
                    &tenant,
                    action_type::RESCORE,
                    entity_type::ACCOUNT,
                    Uuid::new_v4(),
                    &format!("token-test:{tenant}:{n}"),
                    serde_json::json!({ "n": n }),
                    Utc::now() - ChronoDuration::seconds(1),
                    100,
                    None,
                )
                .await
                .unwrap();
            ours.push(action.id);
        }

        // Two claims by the same worker, scoped to the six actions this test
        // enqueued: the production claim is global, so an unscoped claim would
        // take unrelated rows and a concurrent test would take these.
        let first = queue
            .claim_filtered(3, DEFAULT_LEASE_SECS, Some(&ours))
            .await
            .unwrap();
        let second = queue
            .claim_filtered(3, DEFAULT_LEASE_SECS, Some(&ours))
            .await
            .unwrap();
        let leased: Vec<&LeasedAction> = first.iter().chain(second.iter()).collect();
        assert_eq!(leased.len(), 6, "all six enqueued actions must be claimed");

        let mut tokens: Vec<Uuid> = leased.iter().map(|a| a.lease_token).collect();
        tokens.sort_unstable();
        tokens.dedup();
        assert_eq!(
            tokens.len(),
            6,
            "every claimed row must carry its own lease token"
        );
        assert!(
            tokens.iter().all(|token| !token.is_nil()),
            "claim must always issue a real token"
        );
        let owners: Vec<&str> = leased.iter().map(|a| a.lease_owner.as_str()).collect();
        assert!(
            owners.iter().all(|owner| *owner == queue.worker_id()),
            "the same worker claims all rows but with distinct tokens"
        );

        sqlx::query("DELETE FROM sales_actions WHERE tenant_id = $1")
            .bind(&tenant)
            .execute(&pool)
            .await
            .unwrap();
    }

    /// The defect this test exists for: a worker whose action was recovered by
    /// another process must not be able to complete it (or mutate it at all)
    /// with its stale owner string. Only the recovering worker's token works.
    #[tokio::test]
    async fn stale_token_cannot_finish_an_action_another_worker_recovered() {
        let Some(pool) = crate::test_db::canonical_test_pool("stale_fence").await else {
            return;
        };
        let tenant = crate::test_db::unique_test_tenant("stale");
        let queue_a = ActionQueue::new(pool.clone(), format!("worker-a-{tenant}"));
        let queue_b = ActionQueue::new(pool.clone(), format!("worker-b-{tenant}"));

        let action = queue_a
            .enqueue(
                &tenant,
                action_type::ENRICH,
                entity_type::ACCOUNT,
                Uuid::new_v4(),
                &format!("stale-test:{tenant}"),
                serde_json::json!({}),
                Utc::now() - ChronoDuration::seconds(1),
                100,
                None,
            )
            .await
            .unwrap();

        let first = queue_a
            .claim_filtered(50, DEFAULT_LEASE_SECS, Some(&[action.id]))
            .await
            .unwrap()
            .into_iter()
            .find(|leased| leased.id() == action.id)
            .expect("worker A must claim its own action");
        assert!(
            queue_a
                .extend_lease(&first.fence(), DEFAULT_LEASE_SECS)
                .await
                .unwrap(),
            "a live fence extends its lease"
        );

        // Worker A "dies": the lease expires and the sweeper recovers the row.
        sqlx::query(
            "UPDATE sales_actions SET lease_expires_at = NOW() - INTERVAL '1 second' WHERE id = $1",
        )
        .bind(action.id)
        .execute(&pool)
        .await
        .unwrap();
        requeue_expired_leases(&pool).await.unwrap();

        let recovered = queue_b
            .claim_filtered(50, DEFAULT_LEASE_SECS, Some(&[action.id]))
            .await
            .unwrap()
            .into_iter()
            .find(|leased| leased.id() == action.id)
            .expect("worker B must recover the expired action");
        assert_ne!(
            first.lease_token, recovered.lease_token,
            "recovery must issue a new per-claim token"
        );

        // Every mutation with the stale fence is refused…
        assert!(
            !queue_a
                .extend_lease(&first.fence(), DEFAULT_LEASE_SECS)
                .await
                .unwrap(),
            "a stale token must not extend the recovered lease"
        );
        assert!(
            !queue_a
                .attach_decision(&first.fence(), Uuid::new_v4())
                .await
                .unwrap(),
            "a stale token must not attach a decision"
        );
        assert!(
            !queue_a
                .finish(&first.fence(), ActionOutcome::Succeeded)
                .await
                .unwrap(),
            "a stale token must not complete the recovered action"
        );

        let (state, owner, token): (String, Option<String>, Option<Uuid>) = sqlx::query_as(
            "SELECT state, lease_owner, lease_token FROM sales_actions WHERE id = $1",
        )
        .bind(action.id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(state, "executing", "the stale finish must not land");
        assert_eq!(owner.as_deref(), Some(queue_b.worker_id()));
        assert_eq!(token, Some(recovered.lease_token));

        // …while the recovering worker's fence still works.
        assert!(queue_b
            .finish(&recovered.fence(), ActionOutcome::Succeeded)
            .await
            .unwrap());
        let state: String = sqlx::query_scalar("SELECT state FROM sales_actions WHERE id = $1")
            .bind(action.id)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(state, "succeeded");

        sqlx::query("DELETE FROM sales_actions WHERE tenant_id = $1")
            .bind(&tenant)
            .execute(&pool)
            .await
            .unwrap();
    }

    /// The `FOR SHARE` fence check the dispatcher runs inside its send
    /// transaction: a live claim passes, a forged token does not.
    #[tokio::test]
    async fn verify_fence_in_tx_accepts_only_the_live_claim() {
        let Some(pool) = crate::test_db::canonical_test_pool("verify_fence").await else {
            return;
        };
        let tenant = crate::test_db::unique_test_tenant("verify");
        let queue = ActionQueue::new(pool.clone(), format!("worker-{tenant}"));

        let action = queue
            .enqueue(
                &tenant,
                action_type::RESCORE,
                entity_type::ACCOUNT,
                Uuid::new_v4(),
                &format!("verify-test:{tenant}"),
                serde_json::json!({}),
                Utc::now() - ChronoDuration::seconds(1),
                100,
                None,
            )
            .await
            .unwrap();
        let leased = queue
            .claim_filtered(50, DEFAULT_LEASE_SECS, Some(&[action.id]))
            .await
            .unwrap()
            .into_iter()
            .find(|leased| leased.id() == action.id)
            .expect("the action must be claimable");

        let mut tx = pool.begin().await.unwrap();
        assert!(
            verify_fence_in_tx(&mut tx, &leased.fence()).await.unwrap(),
            "the live claim must verify"
        );
        let forged = ActionFence {
            action_id: leased.id(),
            lease_owner: leased.lease_owner.clone(),
            lease_token: Uuid::new_v4(),
        };
        assert!(
            !verify_fence_in_tx(&mut tx, &forged).await.unwrap(),
            "a same-owner forged token must not verify"
        );
        tx.rollback().await.unwrap();

        sqlx::query("DELETE FROM sales_actions WHERE tenant_id = $1")
            .bind(&tenant)
            .execute(&pool)
            .await
            .unwrap();
    }

    /// AwaitApproval is a parked state, not a completion: the action keeps no
    /// lease, has no `completed_at`, cannot be re-claimed, and — critically —
    /// operator replay refuses it.
    #[tokio::test]
    async fn finish_await_approval_parks_the_action_and_replay_refuses_it() {
        let Some(pool) = crate::test_db::canonical_test_pool("await_approval").await else {
            return;
        };
        let tenant = crate::test_db::unique_test_tenant("await");
        let queue = ActionQueue::new(pool.clone(), format!("worker-{tenant}"));

        let action = queue
            .enqueue(
                &tenant,
                action_type::OPERATOR_TASK,
                entity_type::ACCOUNT,
                Uuid::new_v4(),
                &format!("await-test:{tenant}"),
                serde_json::json!({}),
                Utc::now() - ChronoDuration::seconds(1),
                100,
                None,
            )
            .await
            .unwrap();
        let leased = queue
            .claim_filtered(50, DEFAULT_LEASE_SECS, Some(&[action.id]))
            .await
            .unwrap()
            .into_iter()
            .find(|leased| leased.id() == action.id)
            .expect("the action must be claimable");
        assert!(queue
            .finish(&leased.fence(), ActionOutcome::AwaitApproval)
            .await
            .unwrap());

        let row: ParkedActionRow = sqlx::query_as(
            "SELECT state, lease_owner, lease_token, lease_expires_at, completed_at \
             FROM sales_actions WHERE id = $1",
        )
        .bind(action.id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(row.state, "awaiting_approval");
        assert_eq!(
            row.lease_owner, None,
            "a parked action holds no lease owner"
        );
        assert_eq!(
            row.lease_token, None,
            "a parked action holds no lease token"
        );
        assert_eq!(row.lease_expires_at, None);
        assert_eq!(
            row.completed_at, None,
            "waiting for a human is not completion"
        );

        // Not claimable while parked.
        let again = queue
            .claim_filtered(50, DEFAULT_LEASE_SECS, Some(&[action.id]))
            .await
            .unwrap();
        assert!(
            !again.iter().any(|leased| leased.id() == action.id),
            "awaiting_approval must not be claimable by the normal queue path"
        );

        // Replay is an escape hatch for failed/dead-lettered work only.
        assert!(
            !queue.replay(&tenant, action.id).await.unwrap(),
            "replaying approval-gated work would bypass the approval gate"
        );
        let state: String = sqlx::query_scalar("SELECT state FROM sales_actions WHERE id = $1")
            .bind(action.id)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(state, "awaiting_approval");

        sqlx::query("DELETE FROM sales_actions WHERE tenant_id = $1")
            .bind(&tenant)
            .execute(&pool)
            .await
            .unwrap();
    }

    // -----------------------------------------------------------------------
    // Adversarial live-DB proofs (run by default; soft-skip only when the
    // canonical test database is unconfigured).
    // -----------------------------------------------------------------------

    /// A handler that always reports the same outcome, for exercising the
    /// queue's finish paths through a real worker queue.
    struct FixedHandler(ActionOutcome);

    #[async_trait::async_trait]
    impl ActionHandler for FixedHandler {
        async fn handle(&self, _action: &LeasedAction) -> ActionOutcome {
            self.0.clone()
        }
    }

    async fn live_pool(test_name: &str) -> Option<PgPool> {
        crate::test_db::canonical_test_pool(test_name).await
    }

    /// Enqueueing the same logical work twice is idempotent *within* a tenant.
    /// Across tenants the shared global unique index means the second tenant
    /// must NOT be handed the first tenant's row: that would leak another
    /// tenant's action (payload, entity, decision) across the isolation
    /// boundary. The enqueue must refuse instead.
    #[tokio::test]
    async fn enqueue_never_hands_another_tenants_action_across_tenants() {
        let Some(pool) = live_pool("actions_enqueue_tenant_isolation").await else {
            return;
        };
        let tenant_a = crate::test_db::unique_test_tenant("act-iso-a");
        let tenant_b = crate::test_db::unique_test_tenant("act-iso-b");
        let queue_a = ActionQueue::new(pool.clone(), format!("worker-a-{tenant_a}"));
        let queue_b = ActionQueue::new(pool.clone(), format!("worker-b-{tenant_b}"));
        let key = format!("cross-tenant:{}", Uuid::new_v4());

        let first = queue_a
            .enqueue(
                &tenant_a,
                action_type::RESCORE,
                entity_type::ACCOUNT,
                Uuid::new_v4(),
                &key,
                serde_json::json!({ "private": "tenant-a" }),
                Utc::now(),
                100,
                None,
            )
            .await
            .expect("tenant A enqueues");
        assert_eq!(first.tenant_id, tenant_a);

        // Same tenant, same key: the same row comes back, no duplicate.
        let replay = queue_a
            .enqueue(
                &tenant_a,
                action_type::RESCORE,
                entity_type::ACCOUNT,
                first.entity_id,
                &key,
                serde_json::json!({ "private": "tenant-a" }),
                Utc::now(),
                100,
                None,
            )
            .await
            .expect("same-tenant replay is idempotent");
        assert_eq!(replay.id, first.id, "same-tenant replay must reuse the row");

        // Another tenant presenting the same key must not receive tenant A's
        // action. Refusing is the only fail-closed outcome.
        let cross = queue_b
            .enqueue(
                &tenant_b,
                action_type::RESCORE,
                entity_type::ACCOUNT,
                Uuid::new_v4(),
                &key,
                serde_json::json!({ "private": "tenant-b" }),
                Utc::now(),
                100,
                None,
            )
            .await;
        match cross {
            Ok(action) => panic!(
                "tenant B received {}'s action {} across the isolation boundary",
                action.tenant_id, action.id
            ),
            Err(error) => {
                let message = error.to_string();
                assert!(
                    message.contains("idempotency key"),
                    "the refusal must name the idempotency key: {message}"
                );
            }
        }

        // And no row was created for tenant B.
        let b_rows: i64 =
            sqlx::query_scalar("SELECT COUNT(*)::bigint FROM sales_actions WHERE tenant_id = $1")
                .bind(&tenant_b)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(b_rows, 0, "tenant B must have no action row");

        sqlx::query("DELETE FROM sales_actions WHERE tenant_id = $1")
            .bind(&tenant_a)
            .execute(&pool)
            .await
            .unwrap();
    }

    /// `enqueue_tx` has the same isolation contract as `enqueue`: a
    /// cross-tenant key collision aborts the transaction instead of returning
    /// (and letting the caller mutate) another tenant's action.
    #[tokio::test]
    async fn enqueue_tx_refuses_a_cross_tenant_key_collision() {
        let Some(pool) = live_pool("actions_enqueue_tx_tenant_isolation").await else {
            return;
        };
        let tenant_a = crate::test_db::unique_test_tenant("act-tx-a");
        let tenant_b = crate::test_db::unique_test_tenant("act-tx-b");
        let queue_a = ActionQueue::new(pool.clone(), format!("worker-a-{tenant_a}"));
        let key = format!("cross-tenant-tx:{}", Uuid::new_v4());

        queue_a
            .enqueue(
                &tenant_a,
                action_type::ENRICH,
                entity_type::ACCOUNT,
                Uuid::new_v4(),
                &key,
                serde_json::json!({}),
                Utc::now(),
                100,
                None,
            )
            .await
            .expect("tenant A enqueues");

        let mut tx = pool.begin().await.unwrap();
        let result = ActionQueue::enqueue_tx(
            &mut tx,
            &tenant_b,
            action_type::ENRICH,
            entity_type::ACCOUNT,
            Uuid::new_v4(),
            &key,
            serde_json::json!({}),
            Utc::now(),
            100,
            None,
        )
        .await;
        assert!(
            result.is_err(),
            "enqueue_tx must refuse another tenant's key: {result:?}"
        );
        tx.rollback().await.unwrap();

        sqlx::query("DELETE FROM sales_actions WHERE tenant_id = $1")
            .bind(&tenant_a)
            .execute(&pool)
            .await
            .unwrap();
    }

    /// Claim ordering and the limit are load-bearing: highest priority first,
    /// then earliest due time, and never more rows than asked for.
    #[tokio::test]
    async fn claim_is_priority_then_due_ordered_and_bounded() {
        let Some(pool) = live_pool("actions_claim_order").await else {
            return;
        };
        let tenant = crate::test_db::unique_test_tenant("act-order");
        let queue = ActionQueue::new(pool.clone(), format!("worker-{tenant}"));

        let low = queue
            .enqueue(
                &tenant,
                action_type::RESCORE,
                entity_type::ACCOUNT,
                Uuid::new_v4(),
                &format!("order-low:{tenant}"),
                serde_json::json!({}),
                Utc::now() - ChronoDuration::seconds(1),
                1,
                None,
            )
            .await
            .unwrap();
        let high = queue
            .enqueue(
                &tenant,
                action_type::RESCORE,
                entity_type::ACCOUNT,
                Uuid::new_v4(),
                &format!("order-high:{tenant}"),
                serde_json::json!({}),
                Utc::now() - ChronoDuration::seconds(1),
                100,
                None,
            )
            .await
            .unwrap();
        let mid = queue
            .enqueue(
                &tenant,
                action_type::RESCORE,
                entity_type::ACCOUNT,
                Uuid::new_v4(),
                &format!("order-mid:{tenant}"),
                serde_json::json!({}),
                Utc::now() - ChronoDuration::seconds(1),
                50,
                None,
            )
            .await
            .unwrap();

        let ids = [low.id, high.id, mid.id];
        let claimed = queue
            .claim_filtered(2, DEFAULT_LEASE_SECS, Some(&ids))
            .await
            .unwrap();
        assert_eq!(claimed.len(), 2, "the limit must bound the claim");
        // The ordering selects WHICH rows are claimed (the two highest
        // priorities); `RETURNING` does not promise their order, so assert on
        // the selected set.
        let mut selected: Vec<Uuid> = claimed.iter().map(|leased| leased.id()).collect();
        selected.sort_unstable();
        let mut expected = vec![high.id, mid.id];
        expected.sort_unstable();
        assert_eq!(selected, expected, "the two highest priorities are claimed");
        assert!(
            !claimed.iter().any(|leased| leased.id() == low.id),
            "the unbounded row stays queued"
        );

        // A claim is not repeatable while the lease is live: the second claim
        // takes only the still-queued low-priority row, never the executing
        // two.
        let again = queue
            .claim_filtered(2, DEFAULT_LEASE_SECS, Some(&ids))
            .await
            .unwrap();
        assert_eq!(again.len(), 1, "only the unclaimed row remains: {again:?}");
        assert_eq!(again[0].id(), low.id);
        assert!(
            !again
                .iter()
                .any(|leased| leased.id() == high.id || leased.id() == mid.id),
            "executing actions must not be claimable: {again:?}"
        );
        assert_eq!(claimed[0].action.attempt, 1);
        assert_eq!(
            claimed[0].action.state, "executing",
            "the claim and the start of execution are one statement"
        );

        sqlx::query("DELETE FROM sales_actions WHERE tenant_id = $1")
            .bind(&tenant)
            .execute(&pool)
            .await
            .unwrap();
    }

    /// A retryable failure returns the action to the queue with a backoff, and
    /// the attempt budget is enforced in SQL: once spent, the retry becomes a
    /// dead letter with `completed_at` set — never an infinite retry loop.
    #[tokio::test]
    async fn retry_backs_off_and_dead_letters_when_the_budget_is_spent() {
        let Some(pool) = live_pool("actions_retry_budget").await else {
            return;
        };
        let tenant = crate::test_db::unique_test_tenant("act-retry");
        let queue = ActionQueue::new(pool.clone(), format!("worker-{tenant}"));
        let action = queue
            .enqueue(
                &tenant,
                action_type::RESCORE,
                entity_type::ACCOUNT,
                Uuid::new_v4(),
                &format!("retry:{tenant}"),
                serde_json::json!({}),
                Utc::now() - ChronoDuration::seconds(1),
                100,
                None,
            )
            .await
            .unwrap();

        let leased = queue
            .claim_filtered(1, DEFAULT_LEASE_SECS, Some(&[action.id]))
            .await
            .unwrap()
            .into_iter()
            .next()
            .expect("claim");
        assert!(queue
            .finish(&leased.fence(), ActionOutcome::Retry("smtp timeout".into()))
            .await
            .unwrap());

        #[derive(sqlx::FromRow)]
        struct RetryRow {
            state: String,
            attempt: i32,
            last_error: Option<String>,
            due_at: DateTime<Utc>,
            lease_owner: Option<String>,
            lease_token: Option<Uuid>,
            lease_expires_at: Option<DateTime<Utc>>,
            completed_at: Option<DateTime<Utc>>,
        }
        let row: RetryRow = sqlx::query_as(
            "SELECT state, attempt, last_error, due_at, lease_owner, lease_token, \
                    lease_expires_at, completed_at \
             FROM sales_actions WHERE id = $1",
        )
        .bind(action.id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(row.state, "queued", "a bounded failure is retryable");
        assert_eq!(row.attempt, 1);
        assert_eq!(row.last_error.as_deref(), Some("smtp timeout"));
        assert!(row.due_at > Utc::now(), "the retry is backed off");
        assert_eq!(row.lease_owner, None, "the lease is released");
        assert_eq!(row.lease_token, None);
        assert_eq!(row.lease_expires_at, None);
        assert_eq!(row.completed_at, None, "a retry is not completion");

        // Spend the attempt budget, then let the same retry statement decide.
        sqlx::query(
            "UPDATE sales_actions SET attempt = max_attempts, due_at = NOW() WHERE id = $1",
        )
        .bind(action.id)
        .execute(&pool)
        .await
        .unwrap();
        let leased = queue
            .claim_filtered(1, DEFAULT_LEASE_SECS, Some(&[action.id]))
            .await
            .unwrap()
            .into_iter()
            .next()
            .expect("re-claim after backoff");
        assert_eq!(leased.action.attempt, 6, "claiming increments the attempt");
        assert!(queue
            .finish(
                &leased.fence(),
                ActionOutcome::Retry("still failing".into())
            )
            .await
            .unwrap());

        let row: RetryRow = sqlx::query_as(
            "SELECT state, attempt, last_error, due_at, lease_owner, lease_token, \
                    lease_expires_at, completed_at \
             FROM sales_actions WHERE id = $1",
        )
        .bind(action.id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(row.state, "dead_letter", "a spent budget dead-letters");
        assert!(row.completed_at.is_some(), "a dead letter is terminal");
        assert_eq!(row.last_error.as_deref(), Some("still failing"));

        // A dead letter is not claimable.
        let again = queue
            .claim_filtered(1, DEFAULT_LEASE_SECS, Some(&[action.id]))
            .await
            .unwrap();
        assert!(
            again.is_empty(),
            "dead-lettered work must not be re-claimed"
        );

        sqlx::query("DELETE FROM sales_actions WHERE tenant_id = $1")
            .bind(&tenant)
            .execute(&pool)
            .await
            .unwrap();
    }

    /// Cancelling for an entity is a stop signal that must beat a live lease:
    /// the executing row is cancelled, its lease cleared, and a stale worker's
    /// fenced finish can no longer land.
    #[tokio::test]
    async fn cancel_for_entity_stops_queued_and_executing_work() {
        let Some(pool) = live_pool("actions_cancel_entity").await else {
            return;
        };
        let tenant = crate::test_db::unique_test_tenant("act-cancel");
        let queue = ActionQueue::new(pool.clone(), format!("worker-{tenant}"));
        let entity_id = Uuid::new_v4();

        let queued = queue
            .enqueue(
                &tenant,
                action_type::SEND_STEP,
                entity_type::STEP_EXECUTION,
                entity_id,
                &format!("cancel-queued:{tenant}"),
                serde_json::json!({}),
                Utc::now() - ChronoDuration::seconds(1),
                100,
                None,
            )
            .await
            .unwrap();
        let other_entity = queue
            .enqueue(
                &tenant,
                action_type::SEND_STEP,
                entity_type::STEP_EXECUTION,
                Uuid::new_v4(),
                &format!("cancel-other:{tenant}"),
                serde_json::json!({}),
                Utc::now() - ChronoDuration::seconds(1),
                100,
                None,
            )
            .await
            .unwrap();
        let to_cancel_executing = queue
            .enqueue(
                &tenant,
                action_type::SEND_STEP,
                entity_type::STEP_EXECUTION,
                entity_id,
                &format!("cancel-executing:{tenant}"),
                serde_json::json!({}),
                Utc::now() - ChronoDuration::seconds(1),
                100,
                None,
            )
            .await
            .unwrap();

        let leased = queue
            .claim_filtered(1, DEFAULT_LEASE_SECS, Some(&[to_cancel_executing.id]))
            .await
            .unwrap()
            .into_iter()
            .next()
            .expect("claim the executing one");

        let cancelled = queue
            .cancel_for_entity(
                &tenant,
                entity_type::STEP_EXECUTION,
                entity_id,
                "human reply arrived",
            )
            .await
            .unwrap();
        assert_eq!(cancelled, 2, "both the queued and executing rows stop");

        let states: Vec<(Uuid, String, Option<String>)> = sqlx::query_as(
            "SELECT id, state, last_error FROM sales_actions \
             WHERE tenant_id = $1 ORDER BY idempotency_key",
        )
        .bind(&tenant)
        .fetch_all(&pool)
        .await
        .unwrap();
        for (id, state, last_error) in &states {
            if *id == other_entity.id {
                assert_eq!(state, "queued", "an unrelated entity is untouched");
            } else {
                assert_eq!(state, "cancelled", "row {id} must be cancelled");
                assert_eq!(last_error.as_deref(), Some("human reply arrived"));
            }
        }
        assert!(!states.is_empty());

        // The cancelled worker's stale fence must not be able to complete it.
        assert!(
            !queue
                .finish(&leased.fence(), ActionOutcome::Succeeded)
                .await
                .unwrap(),
            "a cancelled action must refuse its worker's finish"
        );
        // And the queued row is gone from the claimable set.
        let claimable = queue
            .claim_filtered(
                10,
                DEFAULT_LEASE_SECS,
                Some(&[queued.id, to_cancel_executing.id]),
            )
            .await
            .unwrap();
        assert!(
            claimable.is_empty(),
            "cancelled work must never be claimed: {claimable:?}"
        );

        sqlx::query("DELETE FROM sales_actions WHERE tenant_id = $1")
            .bind(&tenant)
            .execute(&pool)
            .await
            .unwrap();
    }

    /// Operator replay is the recovery hatch for dead letters: it clears the
    /// stale error/lease, resets the attempt budget, and makes the action
    /// claimable again. It must never touch a live or terminal-success row.
    #[tokio::test]
    async fn replay_recovers_a_dead_letter_and_resets_its_budget() {
        let Some(pool) = live_pool("actions_replay_dead_letter").await else {
            return;
        };
        let tenant = crate::test_db::unique_test_tenant("act-replay");
        let queue = ActionQueue::new(pool.clone(), format!("worker-{tenant}"));
        let action = queue
            .enqueue(
                &tenant,
                action_type::RESCORE,
                entity_type::ACCOUNT,
                Uuid::new_v4(),
                &format!("replay:{tenant}"),
                serde_json::json!({}),
                Utc::now() - ChronoDuration::seconds(1),
                100,
                None,
            )
            .await
            .unwrap();
        sqlx::query(
            "UPDATE sales_actions SET state = 'dead_letter', attempt = max_attempts, \
                    last_error = 'poison', completed_at = NOW(), due_at = NOW() + interval '1 hour' \
             WHERE id = $1",
        )
        .bind(action.id)
        .execute(&pool)
        .await
        .unwrap();

        assert!(
            queue.replay(&tenant, action.id).await.unwrap(),
            "a dead letter is replayable"
        );
        let (state, attempt, last_error, completed_at, due_at): (
            String,
            i32,
            Option<String>,
            Option<DateTime<Utc>>,
            DateTime<Utc>,
        ) = sqlx::query_as(
            "SELECT state, attempt, last_error, completed_at, due_at FROM sales_actions WHERE id = $1",
        )
        .bind(action.id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(state, "queued");
        assert_eq!(attempt, 0, "replay grants a fresh attempt budget");
        assert_eq!(last_error, None);
        assert_eq!(completed_at, None);
        assert!(due_at <= Utc::now(), "replay is immediately due");

        // Replay is scoped to the owning tenant.
        let other_tenant = crate::test_db::unique_test_tenant("act-replay-other");
        assert!(
            !queue.replay(&other_tenant, action.id).await.unwrap(),
            "another tenant must not replay this action"
        );

        // Succeed it; now replay must refuse (success is terminal).
        let leased = queue
            .claim_filtered(1, DEFAULT_LEASE_SECS, Some(&[action.id]))
            .await
            .unwrap()
            .into_iter()
            .next()
            .unwrap();
        assert!(queue
            .finish(&leased.fence(), ActionOutcome::Succeeded)
            .await
            .unwrap());
        assert!(
            !queue.replay(&tenant, action.id).await.unwrap(),
            "a succeeded action is not replayable"
        );

        sqlx::query("DELETE FROM sales_actions WHERE tenant_id = $1")
            .bind(&tenant)
            .execute(&pool)
            .await
            .unwrap();
    }

    /// `stats` is the CP's view of the queue: per-state counts, due-now and
    /// dead-letter totals, all scoped to one tenant.
    #[tokio::test]
    async fn stats_counts_states_due_work_and_dead_letters_per_tenant() {
        let Some(pool) = live_pool("actions_stats").await else {
            return;
        };
        let tenant = crate::test_db::unique_test_tenant("act-stats");
        let other = crate::test_db::unique_test_tenant("act-stats-other");
        let queue = ActionQueue::new(pool.clone(), format!("worker-{tenant}"));

        queue
            .enqueue(
                &tenant,
                action_type::RESCORE,
                entity_type::ACCOUNT,
                Uuid::new_v4(),
                &format!("stats-due:{tenant}"),
                serde_json::json!({}),
                Utc::now() - ChronoDuration::seconds(1),
                100,
                None,
            )
            .await
            .unwrap();
        queue
            .enqueue(
                &tenant,
                action_type::RESCORE,
                entity_type::ACCOUNT,
                Uuid::new_v4(),
                &format!("stats-future:{tenant}"),
                serde_json::json!({}),
                Utc::now() + ChronoDuration::hours(4),
                100,
                None,
            )
            .await
            .unwrap();
        let dead = queue
            .enqueue(
                &tenant,
                action_type::RESCORE,
                entity_type::ACCOUNT,
                Uuid::new_v4(),
                &format!("stats-dead:{tenant}"),
                serde_json::json!({}),
                Utc::now(),
                100,
                None,
            )
            .await
            .unwrap();
        sqlx::query("UPDATE sales_actions SET state = 'dead_letter' WHERE id = $1")
            .bind(dead.id)
            .execute(&pool)
            .await
            .unwrap();
        // Another tenant's due work must not be counted.
        let other_queue = ActionQueue::new(pool.clone(), format!("worker-{other}"));
        other_queue
            .enqueue(
                &other,
                action_type::RESCORE,
                entity_type::ACCOUNT,
                Uuid::new_v4(),
                &format!("stats-other:{other}"),
                serde_json::json!({}),
                Utc::now() - ChronoDuration::seconds(1),
                100,
                None,
            )
            .await
            .unwrap();

        let stats = queue.stats(&tenant).await.unwrap();
        assert_eq!(stats["total"], 3);
        assert_eq!(stats["dueNow"], 1, "only the past-due queued row counts");
        assert_eq!(stats["deadLettered"], 1);
        assert_eq!(stats["byState"]["queued"], 2);
        assert_eq!(stats["byState"]["dead_letter"], 1);
        assert!(
            stats["byState"].get("succeeded").is_none(),
            "absent states must not be fabricated: {stats}"
        );

        sqlx::query("DELETE FROM sales_actions WHERE tenant_id = ANY($1)")
            .bind(vec![tenant.clone(), other.clone()])
            .execute(&pool)
            .await
            .unwrap();
    }

    /// A deployment without a registered handler must dead-letter loudly with
    /// the action type in the reason — never drop the work silently.
    #[tokio::test]
    async fn unhandled_handler_dead_letters_with_the_action_type_named() {
        let leased = LeasedAction {
            action: sample_action(Uuid::new_v4()),
            lease_owner: "worker-a".into(),
            lease_token: Uuid::new_v4(),
        };
        let outcome = UnhandledActionHandler.handle(&leased).await;
        match outcome {
            ActionOutcome::DeadLetter(reason) => {
                assert!(reason.contains(action_type::RESCORE), "{reason}");
                assert!(reason.contains("account"), "{reason}");
            }
            other => panic!("an unhandled action must dead-letter: {other:?}"),
        }
    }

    /// The expired-lease sweeper dead-letters work whose attempt budget is
    /// already spent instead of looping forever.
    #[tokio::test]
    async fn expired_lease_with_a_spent_budget_is_dead_lettered_not_requeued() {
        let Some(pool) = live_pool("actions_expired_budget").await else {
            return;
        };
        let tenant = crate::test_db::unique_test_tenant("act-expired");
        let queue = ActionQueue::new(pool.clone(), format!("worker-{tenant}"));
        let action = queue
            .enqueue(
                &tenant,
                action_type::RESCORE,
                entity_type::ACCOUNT,
                Uuid::new_v4(),
                &format!("expired:{tenant}"),
                serde_json::json!({}),
                Utc::now() - ChronoDuration::seconds(1),
                100,
                None,
            )
            .await
            .unwrap();
        // A crashed worker at the end of its budget.
        sqlx::query(
            "UPDATE sales_actions SET state = 'executing', attempt = max_attempts, \
                    lease_owner = 'crashed', lease_token = gen_random_uuid(), \
                    lease_expires_at = NOW() - interval '1 second' \
             WHERE id = $1",
        )
        .bind(action.id)
        .execute(&pool)
        .await
        .unwrap();

        // The sweep is deployment-global; assert on OUR row's result.
        requeue_expired_leases(&pool).await.unwrap();
        let (state, completed): (String, Option<DateTime<Utc>>) =
            sqlx::query_as("SELECT state, completed_at FROM sales_actions WHERE id = $1")
                .bind(action.id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(
            state, "dead_letter",
            "a spent budget must dead-letter rather than cycle"
        );
        assert!(completed.is_some());

        sqlx::query("DELETE FROM sales_actions WHERE tenant_id = $1")
            .bind(&tenant)
            .execute(&pool)
            .await
            .unwrap();
    }

    /// Two workers racing for ONE action: exactly one wins, and the loser's
    /// every mutation (extend/finish/attach) is refused by the fence. A
    /// crashed winner's work is then recoverable by the survivor.
    #[tokio::test]
    async fn one_winner_per_claim_and_a_stale_token_cannot_write() {
        let Some(pool) = live_pool("actions_single_winner").await else {
            return;
        };
        let tenant = crate::test_db::unique_test_tenant("act-winner");
        let queue_a = ActionQueue::new(pool.clone(), format!("worker-a-{tenant}"));
        let queue_b = ActionQueue::new(pool.clone(), format!("worker-b-{tenant}"));
        let action = queue_a
            .enqueue(
                &tenant,
                action_type::RESCORE,
                entity_type::ACCOUNT,
                Uuid::new_v4(),
                &format!("winner:{tenant}"),
                serde_json::json!({}),
                Utc::now() - ChronoDuration::seconds(1),
                100,
                None,
            )
            .await
            .unwrap();
        let ids = [action.id];

        let (a, b) = tokio::join!(
            queue_a.claim_filtered(1, DEFAULT_LEASE_SECS, Some(&ids)),
            queue_b.claim_filtered(1, DEFAULT_LEASE_SECS, Some(&ids))
        );
        let a = a.unwrap();
        let b = b.unwrap();
        let total = a.len() + b.len();
        assert_eq!(total, 1, "exactly one worker may claim the action");
        let (winner, winner_queue, loser_queue) = if a.is_empty() {
            (b.into_iter().next().unwrap(), queue_b, queue_a)
        } else {
            (a.into_iter().next().unwrap(), queue_a, queue_b)
        };
        assert_eq!(winner.id(), action.id);
        assert!(!winner.lease_token.is_nil());

        // The loser cannot write with a forged token, and the winner's own
        // (unissued) token guess cannot either.
        let forged = ActionFence {
            action_id: action.id,
            lease_owner: winner.lease_owner.clone(),
            lease_token: Uuid::new_v4(),
        };
        assert!(!loser_queue
            .extend_lease(&forged, DEFAULT_LEASE_SECS)
            .await
            .unwrap());
        assert!(!loser_queue
            .finish(&forged, ActionOutcome::Succeeded)
            .await
            .unwrap());
        assert!(!loser_queue
            .attach_decision(&forged, Uuid::new_v4())
            .await
            .unwrap());
        let state: String = sqlx::query_scalar("SELECT state FROM sales_actions WHERE id = $1")
            .bind(action.id)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(state, "executing", "no stale write landed");

        // The winner crashes: expire the lease, sweep, and the survivor picks
        // the work up with a NEW token while the old one stays dead.
        sqlx::query(
            "UPDATE sales_actions SET lease_expires_at = NOW() - INTERVAL '1 second' WHERE id = $1",
        )
        .bind(action.id)
        .execute(&pool)
        .await
        .unwrap();
        requeue_expired_leases(&pool).await.unwrap();
        let recovered = loser_queue
            .claim_filtered(1, DEFAULT_LEASE_SECS, Some(&ids))
            .await
            .unwrap()
            .into_iter()
            .next()
            .expect("a crashed worker's action must be recoverable");
        assert_eq!(recovered.action.attempt, 2);
        assert!(!winner_queue
            .finish(&winner.fence(), ActionOutcome::Succeeded)
            .await
            .unwrap());
        assert!(loser_queue
            .finish(&recovered.fence(), ActionOutcome::Succeeded)
            .await
            .unwrap());
        let state: String = sqlx::query_scalar("SELECT state FROM sales_actions WHERE id = $1")
            .bind(action.id)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(state, "succeeded");

        sqlx::query("DELETE FROM sales_actions WHERE tenant_id = $1")
            .bind(&tenant)
            .execute(&pool)
            .await
            .unwrap();
    }

    /// `run` claims nothing before its first interval and stops promptly when
    /// shutdown resolves — the worker loop's contract.
    #[tokio::test]
    async fn run_worker_stops_on_shutdown_without_claiming() {
        let Some(pool) = live_pool("actions_run_shutdown").await else {
            return;
        };
        let tenant = crate::test_db::unique_test_tenant("act-run");
        let queue = ActionQueue::new(pool.clone(), format!("worker-{tenant}"));
        let handler: Arc<dyn ActionHandler> = Arc::new(FixedHandler(ActionOutcome::Succeeded));

        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        let worker = tokio::spawn(run(
            queue.clone(),
            handler,
            60,
            1,
            DEFAULT_LEASE_SECS,
            async move {
                let _ = rx.await;
            },
        ));
        // Shutdown before one interval elapses: the worker must exit promptly.
        tx.send(()).unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(2), worker)
            .await
            .expect("the worker must stop on shutdown")
            .expect("the worker task must not panic");

        // Nothing was claimable, so the tenant's queue is still empty.
        let stats = queue.stats(&tenant).await.unwrap();
        assert_eq!(stats["total"], 0);
    }
}
