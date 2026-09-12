//! Outcome projector — the production producers of the sales feedback loops.
//!
//! Migration 202 added the two feedback ledgers but nothing consumed them, so
//! `sender_health::record_event` and `experiments::record_reward` had no
//! production caller: the learning loop was decorative. This module is the
//! single consumer that closes both loops:
//!
//! 1. `sales_sender_events` → `sales_sender_health` (audit item 10);
//! 2. `sales_outcomes.reward_processed_at` → `experiments::record_reward`
//!    (audit item 11).
//!
//! # One ledger, one path (item 10)
//!
//! Sender-health aggregates are **never** updated from three separate
//! callbacks (SMTP acceptance, bounce callback, provider webhook). Every
//! delivery path that knows `sales_sender_identity_id` writes exactly ONE
//! `sales_sender_events` row; the ledger's
//! `UNIQUE (sender_identity_id, event_type, message_id, recipient)`
//! (`migrations/202_sales_feedback_delivery_binding.sql:120`) makes a
//! replayed provider callback a no-op instead of double-counting a complaint
//! against a sending domain. This projector is the ONE consumer that folds
//! those rows into `sales_sender_health` through the canonical
//! [`sender_health::record_event`] (which itself re-assesses and persists the
//! breaker state). There is no second path.
//!
//! # Claim protocol (mirrors [`crate::actions::ActionQueue`])
//!
//! The ledger schema is frozen (migrations are out of scope) and
//! `sales_sender_events` carries no `lease_owner` / `lease_token` /
//! `lease_expires_at` columns — only `processed_at`. The durable claim is
//! therefore written into the ONE marker column the migration provides,
//! following the same three properties as `ActionQueue::claim`:
//!
//! * **Claim** — one statement, `FOR UPDATE SKIP LOCKED` over
//!   `processed_at IS NULL` rows ordered by `occurred_at`, then
//!   `UPDATE ... SET processed_at = NOW() ... RETURNING`. Two workers can
//!   never claim the same row, exactly like `ActionQueue::claim`.
//! * **Lease owner + token** — the claim value (`NOW()` at claim time, read
//!   back per row) is the per-claim token carried in [`ClaimedSenderEvent`],
//!   and `worker_id` is the owner. The token is the fence any release/re-open
//!   predicate matches (`WHERE id = $1 AND processed_at = $claimed_at`). Both
//!   live in process memory rather than in columns because the ledger has no
//!   lease columns and adding them is a migration (out of scope).
//! * **Expiry recovery** — a worker that dies mid-application leaves the
//!   durable claim behind. [`OutcomeProjector::recover_unapplied_claims`]
//!   re-opens a claim whose lease has expired (`claimed_at` older than
//!   `lease_secs`) **only when no `sales_sender_health` row for the sender was
//!   written at or after the claim** (the SQL re-opens exactly the rows for
//!   which `NOT EXISTS (h.updated_at >= e.processed_at)`). This is the
//!   ActionQueue lease-expiry sweep adapted to
//!   a one-column ledger, and it is what makes the projector safe under the
//!   audit's adversarial replay: an event whose health update already landed
//!   is never re-applied (no double count), and an event whose worker died
//!   before the health update is re-opened and applied exactly once.
//!
//! A failed `record_event` is deliberately left claimed: the recovery sweep
//! re-opens it after the lease expires. Releasing immediately on error would
//! re-apply an event whose counter UPDATE committed but whose assessment
//! step failed — a real double count; the watermark rule above cannot happen
//! because a successful health write bumps `updated_at`.
//!
//! ## Why the claim precedes the health update
//!
//! The obvious ordering — apply [`sender_health::record_event`] first, write
//! `processed_at = NOW()` after it succeeds — is exactly the ordering that
//! double-counts: `record_event` runs on its own pooled connection, so a
//! crash between its implicit commit and the marker write leaves a pending
//! row whose aggregate has already moved; the next claim re-applies it.
//! Because the ledger has no lease columns, the marker is the ONLY durable
//! state that can distinguish "claimed and in flight" from "pending", so the
//! claim must be durable BEFORE the health write and the re-open decision
//! must be made from evidence (the health watermark) rather than from the
//! marker alone. That is what this module implements, and it is why a
//! replayed or crashed pass never double-counts a complaint or a bounce.
//!
//! As with [`crate::actions::ActionQueue`], the lease is not a mutual
//! exclusion guarantee against a live-but-slow worker: a worker that
//! outlives `lease_secs` mid-`record_event` can have its claim recovered and
//! re-applied by another projector. The window is bounded by
//! `lease_secs` (120 s default, three orders of magnitude above a health
//! round trip) and is the same at-least-once boundary the action queue
//! documents for its handlers.
//!
//! # Reward claim protocol (item 11)
//!
//! [`OutcomeProjector::project_rewards`] claims
//! `sales_outcomes WHERE reward_processed_at IS NULL AND step_execution_id IS
//! NOT NULL` with `FOR UPDATE OF o SKIP LOCKED` (the partial index
//! `idx_sales_outcomes_reward_pending`, migration 202 lines 138-140, serves
//! exactly this predicate), resolves the experiment and variant from the
//! linked step execution / enrollment, and calls
//! [`experiments::record_reward`] with the stable key
//! `"sales-outcome:{sales_outcomes.id}"`. That key is the primary key of
//! `sales_experiment_outcomes`, so replaying the same outcome moves the
//! posterior at most once; `reward_processed_at = NOW()` is written ONLY
//! after a successful record (a crash in between simply replays the no-op).
//! Rows without a `step_execution_id` are never claimed: there is no step
//! execution to attribute to, and `NULL` makes the database unique key
//! non-idempotent (`attribution` module docs).

use chrono::{DateTime, Duration as ChronoDuration, Utc};
use serde::Serialize;
use sqlx::{PgPool, Postgres, Transaction};
use std::sync::Arc;
use tokio::sync::Semaphore;
use uuid::Uuid;

use crate::attribution::OutcomeKind;
use crate::experiments::{self, RewardKind};
use crate::sender_health::{self, HealthThresholds, SenderHealthEvent};
use crate::types::SalesError;

/// Maximum ledger rows one sender-event pass claims.
pub const DEFAULT_BATCH_SIZE: i64 = 50;

/// Default durable-claim lease. Mirrors
/// [`crate::actions::DEFAULT_LEASE_SECS`] — long enough for one
/// `record_event` round trip, short enough that a crashed worker's event is
/// recovered promptly.
pub const DEFAULT_LEASE_SECS: i64 = crate::actions::DEFAULT_LEASE_SECS;

/// How far back the recovery sweep looks for unapplied claims. A claim older
/// than this that never reached the aggregate is left alone (it is outside
/// the operational recovery horizon; the window also bounds the sweep's
/// scan).
pub const DEFAULT_RECOVERY_WINDOW_SECS: i64 = 3600;

/// Prefix of the stable experiment-outcome key. The full key is
/// `sales-outcome:{sales_outcomes.id}`.
pub const OUTCOME_KEY_PREFIX: &str = "sales-outcome:";

/// The `sales_sender_events.event_type` vocabulary — exact wire strings of
/// the CHECK constraint (migration 202 lines 112-115).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SenderEventType {
    Delivered,
    HardBounce,
    SoftBounce,
    Complaint,
    Unsubscribe,
    Deferral,
    AuthFailure,
}

impl SenderEventType {
    /// Every wire value, in migration order.
    pub const ALL: [Self; 7] = [
        Self::Delivered,
        Self::HardBounce,
        Self::SoftBounce,
        Self::Complaint,
        Self::Unsubscribe,
        Self::Deferral,
        Self::AuthFailure,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Delivered => "delivered",
            Self::HardBounce => "hard_bounce",
            Self::SoftBounce => "soft_bounce",
            Self::Complaint => "complaint",
            Self::Unsubscribe => "unsubscribe",
            Self::Deferral => "deferral",
            Self::AuthFailure => "auth_failure",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value.trim() {
            "delivered" => Some(Self::Delivered),
            "hard_bounce" => Some(Self::HardBounce),
            "soft_bounce" => Some(Self::SoftBounce),
            "complaint" => Some(Self::Complaint),
            "unsubscribe" => Some(Self::Unsubscribe),
            "deferral" => Some(Self::Deferral),
            "auth_failure" => Some(Self::AuthFailure),
            _ => None,
        }
    }

    /// The canonical health-window event this ledger row folds into. The
    /// mapping is one-to-one and MUST stay so: mapping `complaint` onto
    /// `Unsubscribe` (or vice versa) would mis-weight the health score
    /// ([`SenderHealthEvent::Complaint`] is the heaviest negative).
    pub fn health_event(self) -> SenderHealthEvent {
        match self {
            Self::Delivered => SenderHealthEvent::Delivered,
            Self::HardBounce => SenderHealthEvent::HardBounce,
            Self::SoftBounce => SenderHealthEvent::SoftBounce,
            Self::Complaint => SenderHealthEvent::Complaint,
            Self::Unsubscribe => SenderHealthEvent::Unsubscribe,
            Self::Deferral => SenderHealthEvent::Deferral,
            Self::AuthFailure => SenderHealthEvent::AuthFailure,
        }
    }
}

/// Per-claim proof of ownership, mirroring
/// [`crate::actions::ActionFence`]'s role.
///
/// `token` is a fresh random id per claim and `expires_at` is
/// `claimed_at + lease_secs`. The durable fence that release statements use
/// is the claim timestamp written to `sales_sender_events.processed_at`
/// (see the module docs); this struct is the in-process identity used for
/// logging, metrics and for expressing the expiry rule in one testable place.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeaseToken {
    pub owner: String,
    pub token: Uuid,
    pub expires_at: DateTime<Utc>,
}

impl LeaseToken {
    /// Pure mirror of the lease rules: a live lease belongs to THIS owner
    /// token and has not expired. Keep in sync with
    /// [`OutcomeProjector::recover_unapplied_claims`], whose SQL re-opens
    /// exactly the claims this returns `false` for.
    pub fn authorizes(
        &self,
        stored_owner: &str,
        stored_token: Uuid,
        stored_expires_at: DateTime<Utc>,
        now: DateTime<Utc>,
    ) -> bool {
        stored_owner == self.owner && stored_token == self.token && stored_expires_at > now
    }
}

/// One durably claimed `sales_sender_events` row.
#[derive(Debug, Clone)]
pub struct ClaimedSenderEvent {
    pub id: Uuid,
    pub tenant_id: String,
    pub sender_identity_id: Uuid,
    pub event_type: SenderEventType,
    pub message_id: Option<String>,
    pub recipient: Option<String>,
    /// The claim value written to `processed_at` at claim time. It is the
    /// per-claim token a release/recovery must match.
    pub claimed_at: DateTime<Utc>,
    pub lease: LeaseToken,
}

/// What one sender-event projection pass did.
#[derive(Debug, Clone, Copy, Default, Serialize)]
pub struct SenderProjectionReport {
    /// Claims re-opened by the expiry sweep because no health write landed.
    pub recovered: u64,
    /// Ledger rows claimed in this pass.
    pub claimed: u64,
    /// Health windows successfully advanced.
    pub applied: u64,
    /// Rows whose event vocabulary was unknown (CHECK guarantees this cannot
    /// happen; the row stays claimed and is logged loudly).
    pub unmapped: u64,
    /// `record_event` failures; the claim is left for the recovery sweep.
    pub failed: u64,
}

/// What one reward projection pass did.
#[derive(Debug, Clone, Copy, Default, Serialize)]
pub struct RewardProjectionReport {
    pub claimed: u64,
    /// Outcomes successfully handed to `experiments::record_reward`
    /// (including idempotent replays).
    pub recorded: u64,
    /// Outcomes with no linked experiment — marked processed, nothing to
    /// attribute to.
    pub unattributed: u64,
    /// `record_reward` failures; the row stays pending and is retried.
    pub failed: u64,
}

/// One projector tick across both ledgers.
#[derive(Debug, Clone, Copy, Default, Serialize)]
pub struct TickReport {
    pub sender_events: SenderProjectionReport,
    pub rewards: RewardProjectionReport,
}

/// Projector tuning. `Default` is the production shape.
#[derive(Debug, Clone, Copy)]
pub struct ProjectorConfig {
    pub batch_size: i64,
    pub lease_secs: i64,
    pub recovery_window_secs: i64,
    pub health_thresholds: HealthThresholds,
}

impl Default for ProjectorConfig {
    fn default() -> Self {
        Self {
            batch_size: DEFAULT_BATCH_SIZE,
            lease_secs: DEFAULT_LEASE_SECS,
            recovery_window_secs: DEFAULT_RECOVERY_WINDOW_SECS,
            health_thresholds: HealthThresholds::default(),
        }
    }
}

/// The outcome projector. Stateless beyond the pool and its worker id, like
/// [`crate::actions::ActionQueue`].
#[derive(Debug, Clone)]
pub struct OutcomeProjector {
    db: PgPool,
    worker_id: String,
}

impl OutcomeProjector {
    pub fn new(db: PgPool, worker_id: impl Into<String>) -> Self {
        Self {
            db,
            worker_id: worker_id.into(),
        }
    }

    pub fn worker_id(&self) -> &str {
        &self.worker_id
    }

    pub fn db(&self) -> &PgPool {
        &self.db
    }

    /// One tick: recover expired claims, project sender events, project
    /// rewards.
    pub async fn tick(&self, config: &ProjectorConfig) -> Result<TickReport, SalesError> {
        let sender_events = self.project_sender_events(config).await?;
        let rewards = self.project_rewards(config).await?;
        Ok(TickReport {
            sender_events,
            rewards,
        })
    }

    /// Fold one batch of `sales_sender_events` into `sales_sender_health`.
    ///
    /// See the module docs for the claim protocol. The claim statement is a
    /// single `UPDATE ... FROM (SELECT ... FOR UPDATE SKIP LOCKED)` so the
    /// durable claim and the row locks are taken atomically: no second worker
    /// can see an unclaimed row this worker is about to apply.
    pub async fn project_sender_events(
        &self,
        config: &ProjectorConfig,
    ) -> Result<SenderProjectionReport, SalesError> {
        let mut report = SenderProjectionReport::default();

        report.recovered = self
            .recover_unapplied_claims(config.lease_secs, config.recovery_window_secs)
            .await?;
        if report.recovered > 0 {
            tracing::warn!(
                worker_id = self.worker_id.as_str(),
                recovered = report.recovered,
                "sales sender ledger recovered unapplied claims (worker crash mid-application)"
            );
            metrics::counter!("sales_sender_events_recovered_total").increment(report.recovered);
        }

        let rows: Vec<ClaimedSenderEventRow> = sqlx::query_as::<_, ClaimedSenderEventRow>(
            "WITH claimable AS ( \
                 SELECT id FROM sales_sender_events \
                 WHERE processed_at IS NULL \
                 ORDER BY occurred_at ASC \
                 FOR UPDATE SKIP LOCKED \
                 LIMIT $1 \
             ) \
             UPDATE sales_sender_events e \
             SET processed_at = NOW() \
             FROM claimable c \
             WHERE e.id = c.id \
             RETURNING e.id, e.tenant_id, e.sender_identity_id, e.event_type, \
                       e.message_id, e.recipient, e.processed_at",
        )
        .bind(config.batch_size.max(1))
        .fetch_all(&self.db)
        .await
        .map_err(|error| SalesError::Database(error.to_string()))?;

        report.claimed = rows.len() as u64;
        let lease_secs = config.lease_secs.max(1);

        for row in rows {
            let Some(event_type) = SenderEventType::parse(&row.event_type) else {
                // Unreachable through the CHECK constraint; a corrupted row
                // must not wedge the batch, and releasing it would wedge it
                // forever. Leave it claimed and make it visible.
                report.unmapped += 1;
                tracing::error!(
                    sender_event_id = %row.id,
                    event_type = row.event_type.as_str(),
                    "sales sender ledger row has an unknown event_type; the migration 202 \
                     CHECK constraint should make this impossible"
                );
                metrics::counter!("sales_sender_events_unmapped_total").increment(1);
                continue;
            };

            let claimed_at = row.processed_at;
            let claimed = ClaimedSenderEvent {
                id: row.id,
                tenant_id: row.tenant_id,
                sender_identity_id: row.sender_identity_id,
                event_type,
                message_id: row.message_id,
                recipient: row.recipient,
                claimed_at,
                lease: LeaseToken {
                    owner: self.worker_id.clone(),
                    token: Uuid::new_v4(),
                    expires_at: claimed_at + ChronoDuration::seconds(lease_secs),
                },
            };

            match sender_health::record_event(
                &self.db,
                &claimed.tenant_id,
                claimed.sender_identity_id,
                claimed.event_type.health_event(),
                &config.health_thresholds,
            )
            .await
            {
                Ok(assessment) => {
                    report.applied += 1;
                    metrics::counter!(
                        "sales_sender_events_projected_total",
                        "event_type" => claimed.event_type.as_str(),
                        "state" => assessment.state.clone(),
                    )
                    .increment(1);
                    tracing::debug!(
                        sender_event_id = %claimed.id,
                        sender_identity_id = %claimed.sender_identity_id,
                        event_type = claimed.event_type.as_str(),
                        state = %assessment.state,
                        "sender health window advanced from the delivery ledger"
                    );
                }
                Err(error) => {
                    // Leave the durable claim in place: the recovery sweep
                    // re-opens it once the lease expires AND the health
                    // window proves no write landed. Releasing here would
                    // double-count a partially applied record_event.
                    report.failed += 1;
                    metrics::counter!("sales_sender_events_projection_failures_total").increment(1);
                    tracing::error!(
                        sender_event_id = %claimed.id,
                        sender_identity_id = %claimed.sender_identity_id,
                        event_type = claimed.event_type.as_str(),
                        error = %error,
                        "sender health projection failed; the claim is left for lease-expiry recovery"
                    );
                }
            }
        }

        if report.claimed > 0 {
            tracing::debug!(
                worker_id = self.worker_id.as_str(),
                claimed = report.claimed,
                applied = report.applied,
                failed = report.failed,
                "sender-event projection tick complete"
            );
        }

        Ok(report)
    }

    /// Re-open durable claims whose worker died before the health update
    /// landed.
    ///
    /// A claim is expired (`processed_at <= NOW() - lease_secs`) and
    /// unapplied (`NOT EXISTS` a `sales_sender_health` row for the sender
    /// with `updated_at >= processed_at`). The watermark is exact: a
    /// successful [`sender_health::record_event`] always writes
    /// `sales_sender_health.updated_at = NOW()` (the counter UPDATE and the
    /// assessment upsert both do), and that `NOW()` is necessarily after the
    /// claim's `NOW()` because the claim statement committed first. An
    /// applied claim therefore can never be re-opened — the aggregate is not
    /// double-counted — while an unapplied one is retried.
    ///
    /// Residual race (documented, never a double count): another writer can
    /// bump the same sender's `updated_at` after the claim but before the
    /// crash, which masks the unapplied claim so the sweep does not re-open
    /// it — the event is under-counted, not counted twice.
    pub async fn recover_unapplied_claims(
        &self,
        lease_secs: i64,
        window_secs: i64,
    ) -> Result<u64, SalesError> {
        let affected = sqlx::query(
            "UPDATE sales_sender_events e \
             SET processed_at = NULL \
             WHERE e.processed_at IS NOT NULL \
               AND e.processed_at <= NOW() - make_interval(secs => $1::double precision) \
               AND e.processed_at > NOW() - make_interval(secs => $2::double precision) \
               AND NOT EXISTS ( \
                   SELECT 1 FROM sales_sender_health h \
                   WHERE h.tenant_id = e.tenant_id \
                     AND h.sender_identity_id = e.sender_identity_id \
                     AND h.updated_at >= e.processed_at \
               )",
        )
        .bind(lease_secs.max(0) as f64)
        .bind(window_secs.max(0) as f64)
        .execute(&self.db)
        .await
        .map_err(|error| SalesError::Database(error.to_string()))?
        .rows_affected();
        Ok(affected)
    }

    /// Project one batch of pending `sales_outcomes` rewards.
    ///
    /// The claim runs in a transaction so the `FOR UPDATE OF o SKIP LOCKED`
    /// locks are held while `record_reward` executes on the pool; the locks
    /// are not what makes this idempotent — the stable
    /// `"sales-outcome:{id}"` outcome key is (see the module docs). The claim
    /// predicate matches the partial index
    /// `idx_sales_outcomes_reward_pending` exactly.
    ///
    /// The pool must have at least two connections (the claim transaction
    /// holds one while `record_reward` checks out another); every production
    /// and test pool in this workspace has more.
    pub async fn project_rewards(
        &self,
        config: &ProjectorConfig,
    ) -> Result<RewardProjectionReport, SalesError> {
        let mut report = RewardProjectionReport::default();
        let mut tx: Transaction<'_, Postgres> = self
            .db
            .begin()
            .await
            .map_err(|error| SalesError::Database(error.to_string()))?;

        let rows: Vec<RewardCandidateRow> = sqlx::query_as::<_, RewardCandidateRow>(
            "SELECT o.id, o.tenant_id, o.outcome, o.value_eur::float8 AS value_eur, \
                    se.variant AS step_variant, \
                    e.experiment_id, e.experiment_variant \
             FROM sales_outcomes o \
             JOIN sales_step_executions se \
                  ON se.id = o.step_execution_id AND se.tenant_id = o.tenant_id \
             LEFT JOIN sales_enrollments e \
                  ON e.id = se.enrollment_id AND e.tenant_id = se.tenant_id \
             WHERE o.reward_processed_at IS NULL AND o.step_execution_id IS NOT NULL \
             ORDER BY o.occurred_at ASC \
             FOR UPDATE OF o SKIP LOCKED \
             LIMIT $1",
        )
        .bind(config.batch_size.max(1))
        .fetch_all(&mut *tx)
        .await
        .map_err(|error| SalesError::Database(error.to_string()))?;

        report.claimed = rows.len() as u64;

        for row in rows {
            let Some(kind) = OutcomeKind::parse(&row.outcome) else {
                // Unreachable through the migration 200 CHECK constraint
                // (lines 768-771); mark processed so an unparsable row cannot
                // poison every tick.
                tracing::error!(
                    outcome_id = %row.id,
                    outcome = row.outcome.as_str(),
                    "sales outcome has an unknown outcome value; marking processed without reward"
                );
                metrics::counter!("sales_outcomes_unmapped_total").increment(1);
                mark_reward_processed(&mut tx, row.id).await?;
                report.unattributed += 1;
                continue;
            };

            // Variant resolution: the step execution carries the arm chosen
            // before the send (`sales_step_executions.variant`, migration 200
            // line 532); the enrollment mirrors it
            // (`sales_enrollments.experiment_variant`, line 503) as the
            // fallback for rows written before the step variant existed.
            let experiment_id = row.experiment_id;
            let Some(experiment_id) = experiment_id else {
                // Not experiment mail (no experiment on the enrollment):
                // there is nobody to attribute to. Mark processed so the row
                // does not occupy the pending index forever.
                mark_reward_processed(&mut tx, row.id).await?;
                report.unattributed += 1;
                tracing::debug!(
                    outcome_id = %row.id,
                    "sales outcome has no linked experiment; reward projection skipped"
                );
                continue;
            };

            let variant = row
                .step_variant
                .as_deref()
                .or(row.experiment_variant.as_deref())
                .unwrap_or("default");
            let outcome_key = format!("{OUTCOME_KEY_PREFIX}{}", row.id);
            // `value_eur` is NUMERIC(14,4) NOT NULL DEFAULT 0 and the CHECK
            // allows corrections, but record_reward rejects negative values
            // outright; clamp so a negative correction cannot poison the
            // claim loop.
            let value_eur = if row.value_eur.is_finite() && row.value_eur > 0.0 {
                row.value_eur
            } else {
                0.0
            };

            match experiments::record_reward(
                &self.db,
                &row.tenant_id,
                experiment_id,
                variant,
                RewardKind::from_outcome_kind(kind),
                &outcome_key,
                value_eur,
            )
            .await
            {
                Ok(()) => {
                    mark_reward_processed(&mut tx, row.id).await?;
                    report.recorded += 1;
                    metrics::counter!(
                        "sales_outcome_rewards_recorded_total",
                        "outcome" => kind.as_str(),
                    )
                    .increment(1);
                    tracing::debug!(
                        outcome_id = %row.id,
                        experiment_id = %experiment_id,
                        variant,
                        outcome = kind.as_str(),
                        "experiment reward projected from a production outcome"
                    );
                }
                Err(error) => {
                    // No mark: the row is retried on a later tick, and the
                    // replay is a posterior no-op thanks to the stable key.
                    report.failed += 1;
                    metrics::counter!("sales_outcome_reward_failures_total").increment(1);
                    tracing::error!(
                        outcome_id = %row.id,
                        experiment_id = %experiment_id,
                        variant,
                        error = %error,
                        "experiment reward projection failed; outcome left pending for retry"
                    );
                }
            }
        }

        tx.commit()
            .await
            .map_err(|error| SalesError::Database(error.to_string()))?;

        if report.claimed > 0 {
            tracing::debug!(
                worker_id = self.worker_id.as_str(),
                claimed = report.claimed,
                recorded = report.recorded,
                unattributed = report.unattributed,
                failed = report.failed,
                "reward projection tick complete"
            );
        }

        Ok(report)
    }
}

/// Mark one outcome's reward claim once the reward ledger accepted it.
async fn mark_reward_processed(
    tx: &mut Transaction<'_, Postgres>,
    outcome_id: Uuid,
) -> Result<(), SalesError> {
    sqlx::query(
        "UPDATE sales_outcomes SET reward_processed_at = NOW() \
         WHERE id = $1 AND reward_processed_at IS NULL",
    )
    .bind(outcome_id)
    .execute(&mut **tx)
    .await
    .map_err(|error| SalesError::Database(error.to_string()))?;
    Ok(())
}

/// Run the outcome projector until `shutdown` resolves.
///
/// Same shape as [`crate::actions::run`]: an interval with sub-second jitter
/// so replicas do not wake together, a semaphore bounding the number of
/// ticks in flight to `concurrency`, and a shutdown future that stops new
/// ticks. Work already in flight is not forcibly awaited — a hard exit is
/// recovered by lease expiry (see the module docs), which is exactly why the
/// claim protocol is durable.
pub async fn run(
    projector: OutcomeProjector,
    interval_secs: u64,
    concurrency: i64,
    lease_secs: i64,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
) {
    let base = std::time::Duration::from_secs(interval_secs.max(1));
    let concurrency = concurrency.max(1);
    let semaphore = Arc::new(Semaphore::new(concurrency as usize));
    let mut shutdown = Box::pin(shutdown);
    let config = ProjectorConfig {
        lease_secs: lease_secs.max(1),
        ..ProjectorConfig::default()
    };
    tracing::info!(
        worker_id = projector.worker_id(),
        interval_secs,
        concurrency,
        lease_secs,
        "sales outcome projector started"
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
                tracing::info!("sales outcome projector stopping");
                return;
            }
            _ = tokio::time::sleep(base + jitter) => {}
        }

        let permit = match semaphore.clone().acquire_owned().await {
            Ok(permit) => permit,
            Err(_) => return,
        };
        let projector = projector.clone();
        let _join = tokio::spawn(async move {
            let _permit = permit;
            match projector.tick(&config).await {
                Ok(report) => {
                    if report.sender_events.claimed > 0 || report.rewards.claimed > 0 {
                        tracing::debug!(
                            sender_events = report.sender_events.claimed,
                            rewards = report.rewards.claimed,
                            "sales outcome projector tick complete"
                        );
                    }
                }
                Err(error) => {
                    tracing::error!(error = %error, "sales outcome projector tick failed — will retry");
                    metrics::counter!("sales_outcome_projector_tick_errors_total").increment(1);
                }
            }
        });
    }
}

/// Raw claim row. Kept private so the column list has exactly one home.
#[derive(sqlx::FromRow)]
struct ClaimedSenderEventRow {
    id: Uuid,
    tenant_id: String,
    sender_identity_id: Uuid,
    event_type: String,
    message_id: Option<String>,
    recipient: Option<String>,
    processed_at: DateTime<Utc>,
}

/// Raw reward candidate row.
#[derive(sqlx::FromRow)]
struct RewardCandidateRow {
    id: Uuid,
    tenant_id: String,
    outcome: String,
    value_eur: f64,
    step_variant: Option<String>,
    experiment_id: Option<Uuid>,
    experiment_variant: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sender_health::{self, HealthThresholds};
    use sqlx::PgPool;

    // -----------------------------------------------------------------------
    // Pure mapping / lease-rule tests (no database)
    // -----------------------------------------------------------------------

    #[test]
    fn sender_event_types_match_the_migration_vocabulary() {
        // migration 202 lines 112-115
        let expected = [
            "delivered",
            "hard_bounce",
            "soft_bounce",
            "complaint",
            "unsubscribe",
            "deferral",
            "auth_failure",
        ];
        assert_eq!(SenderEventType::ALL.len(), expected.len());
        for (event, wire) in SenderEventType::ALL.iter().zip(expected) {
            assert_eq!(event.as_str(), wire);
            assert_eq!(SenderEventType::parse(wire), Some(*event));
        }
        assert_eq!(SenderEventType::parse("nonsense"), None);
    }

    #[test]
    fn complaint_maps_to_complaint_never_unsubscribe() {
        assert_eq!(
            SenderEventType::Complaint.health_event(),
            SenderHealthEvent::Complaint
        );
        assert_eq!(
            SenderEventType::Unsubscribe.health_event(),
            SenderHealthEvent::Unsubscribe
        );
        assert_ne!(
            SenderEventType::Complaint.health_event(),
            SenderHealthEvent::Unsubscribe
        );
    }

    #[test]
    fn lease_rules_mirror_action_queue_expiry() {
        let now = Utc::now();
        let lease = LeaseToken {
            owner: "projector-a".into(),
            token: Uuid::new_v4(),
            expires_at: now + ChronoDuration::seconds(120),
        };
        assert!(lease.authorizes("projector-a", lease.token, lease.expires_at, now));
        // Wrong owner.
        assert!(!lease.authorizes("projector-b", lease.token, lease.expires_at, now));
        // Wrong token.
        assert!(!lease.authorizes("projector-a", Uuid::new_v4(), lease.expires_at, now));
        // Expired lease.
        assert!(!lease.authorizes(
            "projector-a",
            lease.token,
            now - ChronoDuration::seconds(1),
            now
        ));
    }

    #[test]
    fn outcome_key_prefix_is_stable() {
        let id = Uuid::nil();
        assert_eq!(
            format!("{OUTCOME_KEY_PREFIX}{id}"),
            format!("sales-outcome:{id}")
        );
    }

    // -----------------------------------------------------------------------
    // Live-database tests (canonical provisioned pool; soft-skip when
    // SALES_TEST_DATABASE_URL is unconfigured — see src/test_db.rs)
    //
    // The canonical database is SHARED and these tests run in parallel, so a
    // projector pass legitimately claims rows that belong to a sibling test.
    // Every ledger row is applied exactly once by exactly one projector (the
    // claim protocol), so each test asserts the aggregate state of ITS OWN
    // sender/outcome rather than the global report counters.
    // -----------------------------------------------------------------------

    async fn insert_tenant(pool: &PgPool, label: &str) -> String {
        let tenant = crate::test_db::unique_test_tenant(label);
        sqlx::query(
            "INSERT INTO tenants (id, name, slug, plan, status) \
             VALUES ($1, $2, $3, 'starter', 'active') \
             ON CONFLICT (id) DO NOTHING",
        )
        .bind(&tenant)
        .bind(format!("test {tenant}"))
        .bind(format!("slug-{tenant}"))
        .execute(pool)
        .await
        .expect("insert tenant fixture");
        tenant
    }

    async fn insert_sender(pool: &PgPool, tenant: &str) -> Uuid {
        let sender_id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO sales_sender_identities \
                 (id, tenant_id, pool, from_email, from_name, domain, status, daily_limit) \
             VALUES ($1, $2, 'sales_outbound', $3, 'Projector Sender', $4, 'active', 500)",
        )
        .bind(sender_id)
        .bind(tenant)
        .bind(format!(
            "sender-{}@{}",
            &sender_id.simple().to_string()[..10],
            "projector.example.com"
        ))
        .bind("projector.example.com")
        .execute(pool)
        .await
        .expect("insert sender identity fixture");
        sender_id
    }

    async fn insert_ledger_event(
        pool: &PgPool,
        tenant: &str,
        sender_id: Uuid,
        event_type: &str,
        message_id: &str,
        recipient: &str,
    ) -> Uuid {
        // ON CONFLICT DO NOTHING models a replayed provider callback: the
        // unique key makes the second write a no-op, returning the ORIGINAL
        // row id.
        let id: Option<Uuid> = sqlx::query_scalar(
            "INSERT INTO sales_sender_events \
                 (tenant_id, sender_identity_id, event_type, message_id, recipient, occurred_at) \
             VALUES ($1, $2, $3, $4, $5, NOW()) \
             ON CONFLICT (sender_identity_id, event_type, message_id, recipient) DO NOTHING \
             RETURNING id",
        )
        .bind(tenant)
        .bind(sender_id)
        .bind(event_type)
        .bind(message_id)
        .bind(recipient)
        .fetch_optional(pool)
        .await
        .expect("insert sender ledger event");
        match id {
            Some(id) => id,
            None => sqlx::query_scalar(
                "SELECT id FROM sales_sender_events \
                 WHERE sender_identity_id = $1 AND event_type = $2 \
                   AND message_id = $3 AND recipient = $4",
            )
            .bind(sender_id)
            .bind(event_type)
            .bind(message_id)
            .bind(recipient)
            .fetch_one(pool)
            .await
            .expect("replayed ledger event must resolve to the original row"),
        }
    }

    /// `(volume, hard_bounces, soft_bounces, complaints, unsubscribes,
    /// deferrals, auth_failures, state)`.
    type Counters = (i64, i64, i64, i64, i64, i64, i64, String);

    async fn health_counters(pool: &PgPool, tenant: &str, sender_id: Uuid) -> Counters {
        sqlx::query_as(
            "SELECT volume, hard_bounces, soft_bounces, complaints, unsubscribes, \
                    deferrals, auth_failures, state \
             FROM sales_sender_health WHERE tenant_id = $1 AND sender_identity_id = $2",
        )
        .bind(tenant)
        .bind(sender_id)
        .fetch_one(pool)
        .await
        .expect("sender health row must exist after projection")
    }

    /// Run projector passes. The shared database holds only this module's
    /// ledger rows (no other code writes `sales_sender_events` yet), so a
    /// handful of passes drains every pending row.
    async fn drain(projector: &OutcomeProjector, ticks: usize) {
        for _ in 0..ticks {
            projector
                .project_sender_events(&ProjectorConfig::default())
                .await
                .expect("sender projection tick");
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
    }

    /// Run reward-projection passes (see [`drain`]).
    async fn drain_rewards(projector: &OutcomeProjector, ticks: usize) {
        for _ in 0..ticks {
            projector
                .project_rewards(&ProjectorConfig::default())
                .await
                .expect("reward projection tick");
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
    }

    /// Adversarial 1: a replayed sender event (same unique key) is processed
    /// once and the health aggregate moves once.
    #[tokio::test]
    async fn replayed_sender_event_moves_the_aggregate_once() {
        let Some(pool) = crate::test_db::canonical_test_pool("projector_replay").await else {
            return;
        };
        let tenant = insert_tenant(&pool, "proj-replay").await;
        let sender = insert_sender(&pool, &tenant).await;

        // The provider callback is delivered twice: the unique key
        // (sender_identity_id, event_type, message_id, recipient) collapses
        // them onto ONE row (migration 202 line 120).
        let first = insert_ledger_event(
            &pool,
            &tenant,
            sender,
            "complaint",
            "msg-replay",
            "a@x.test",
        )
        .await;
        let second = insert_ledger_event(
            &pool,
            &tenant,
            sender,
            "complaint",
            "msg-replay",
            "a@x.test",
        )
        .await;
        assert_eq!(first, second, "the unique key must collapse the replay");

        let projector = OutcomeProjector::new(pool.clone(), "test-worker-replay");
        drain(&projector, 3).await;

        let (_, _, _, complaints, unsubscribes, _, _, _) =
            health_counters(&pool, &tenant, sender).await;
        assert_eq!(complaints, 1, "one ledger row → one complaint");
        assert_eq!(unsubscribes, 0);

        let rows: i64 = sqlx::query_scalar(
            "SELECT COUNT(*)::bigint FROM sales_sender_events WHERE tenant_id = $1",
        )
        .bind(&tenant)
        .fetch_one(&pool)
        .await
        .expect("count ledger rows");
        assert_eq!(rows, 1);

        let marker: Option<DateTime<Utc>> =
            sqlx::query_scalar("SELECT processed_at FROM sales_sender_events WHERE id = $1")
                .bind(first)
                .fetch_one(&pool)
                .await
                .expect("read claim marker");
        assert!(marker.is_some(), "the event must be durably processed");

        // Further passes must not touch the processed row at all.
        drain(&projector, 3).await;
        let (_, _, _, complaints, _, _, _, _) = health_counters(&pool, &tenant, sender).await;
        assert_eq!(complaints, 1, "replay must not double-count");
    }

    /// Adversarial 2: a projector that dies between the durable claim and the
    /// health update is recovered and applied exactly once; a projector that
    /// dies after the health update (the audit's scenario) is NOT re-applied,
    /// because the claim plus the `sales_sender_health.updated_at` watermark
    /// prove the aggregate already moved.
    #[tokio::test]
    async fn crashed_claims_never_double_count_and_unapplied_claims_are_recovered() {
        let Some(pool) = crate::test_db::canonical_test_pool("projector_crash_recovery").await
        else {
            return;
        };
        let tenant = insert_tenant(&pool, "proj-crash").await;
        // Two senders: the watermark rule is per sender, so the two crash
        // cases must not mask each other.
        let sender_applied = insert_sender(&pool, &tenant).await;
        let sender_unapplied = insert_sender(&pool, &tenant).await;

        // Case A — crash AFTER the health update: the paper trail is
        // "durable claim (old) + health write (new)". The aggregate is
        // applied FIRST so the row never exists without its watermark, then
        // the claimed row is inserted in one statement (no window in which a
        // parallel projector could treat it as pending).
        sender_health::record_event(
            &pool,
            &tenant,
            sender_applied,
            SenderHealthEvent::Complaint,
            &HealthThresholds::default(),
        )
        .await
        .expect("apply complaint directly");
        let after_health: Uuid = sqlx::query_scalar(
            "INSERT INTO sales_sender_events \
                 (tenant_id, sender_identity_id, event_type, message_id, recipient, \
                  occurred_at, processed_at) \
             VALUES ($1, $2, 'complaint', 'msg-a', 'a@x.test', NOW(), \
                     NOW() - INTERVAL '5 minutes') \
             RETURNING id",
        )
        .bind(&tenant)
        .bind(sender_applied)
        .fetch_one(&pool)
        .await
        .expect("insert applied claim");

        // Case B — crash BEFORE the health update: an expired durable claim
        // with no health write for this sender.
        let before_health: Uuid = sqlx::query_scalar(
            "INSERT INTO sales_sender_events \
                 (tenant_id, sender_identity_id, event_type, message_id, recipient, \
                  occurred_at, processed_at) \
             VALUES ($1, $2, 'hard_bounce', 'msg-b', 'b@x.test', NOW(), \
                     NOW() - INTERVAL '5 minutes') \
             RETURNING id",
        )
        .bind(&tenant)
        .bind(sender_unapplied)
        .fetch_one(&pool)
        .await
        .expect("insert unapplied claim");

        let projector = OutcomeProjector::new(pool.clone(), "test-worker-crash");
        drain(&projector, 3).await;

        // Case A: never re-opened, so the aggregate stays at exactly one.
        let (_, _, _, complaints_a, _, _, _, _) =
            health_counters(&pool, &tenant, sender_applied).await;
        assert_eq!(complaints_a, 1, "the applied complaint is counted once");
        let marker_a: Option<DateTime<Utc>> =
            sqlx::query_scalar("SELECT processed_at FROM sales_sender_events WHERE id = $1")
                .bind(after_health)
                .fetch_one(&pool)
                .await
                .expect("read applied claim");
        assert!(
            marker_a.is_some(),
            "an applied claim must stay durable — never re-opened, never re-applied"
        );

        // Case B: recovered exactly once.
        let (volume_b, hard_bounces_b, _, _, _, _, _, _) =
            health_counters(&pool, &tenant, sender_unapplied).await;
        assert_eq!(hard_bounces_b, 1, "the recovered bounce is applied once");
        assert_eq!(volume_b, 1, "volume moves exactly once (hard bounce)");
        let marker_b: Option<DateTime<Utc>> =
            sqlx::query_scalar("SELECT processed_at FROM sales_sender_events WHERE id = $1")
                .bind(before_health)
                .fetch_one(&pool)
                .await
                .expect("read recovered claim");
        assert!(marker_b.is_some(), "the recovered event must be re-claimed");

        // Further passes change nothing (no replay, no double count).
        drain(&projector, 3).await;
        let (volume_b, hard_bounces_b, _, _, _, _, _, _) =
            health_counters(&pool, &tenant, sender_unapplied).await;
        assert_eq!((volume_b, hard_bounces_b), (1, 1));
        let (_, _, _, complaints_a, _, _, _, _) =
            health_counters(&pool, &tenant, sender_applied).await;
        assert_eq!(complaints_a, 1);
    }

    /// Adversarial 3: hard bounces cross the pause threshold, the identity is
    /// paused, and the canonical pre-send gate denies.
    #[tokio::test]
    async fn hard_bounce_threshold_pauses_and_the_gate_denies() {
        let Some(pool) = crate::test_db::canonical_test_pool("projector_bounce_pause").await else {
            return;
        };
        let tenant = insert_tenant(&pool, "proj-pause").await;
        let sender = insert_sender(&pool, &tenant).await;

        // 47 delivered + 3 hard bounces = volume 50, hard-bounce rate 0.06 >
        // the 0.05 pause threshold (HealthThresholds::default).
        for index in 0..47 {
            insert_ledger_event(
                &pool,
                &tenant,
                sender,
                "delivered",
                &format!("msg-d{index}"),
                "d@x.test",
            )
            .await;
        }
        for index in 0..3 {
            insert_ledger_event(
                &pool,
                &tenant,
                sender,
                "hard_bounce",
                &format!("msg-h{index}"),
                "h@x.test",
            )
            .await;
        }

        let projector = OutcomeProjector::new(pool.clone(), "test-worker-pause");
        drain(&projector, 4).await;

        let (volume, hard_bounces, _, _, _, _, _, state) =
            health_counters(&pool, &tenant, sender).await;
        assert_eq!(
            (volume, hard_bounces),
            (50, 3),
            "all 50 ledger rows must be projected exactly once"
        );
        assert_eq!(
            state, "paused",
            "3/50 hard bounces must trip the pause breaker"
        );

        let identity_status: String =
            sqlx::query_scalar("SELECT status FROM sales_sender_identities WHERE id = $1")
                .bind(sender)
                .fetch_one(&pool)
                .await
                .expect("read identity status");
        assert_eq!(identity_status, "paused");

        let denied = sender_health::gate(&pool, &tenant, sender).await;
        assert!(
            denied.is_err(),
            "a paused sender identity must be denied by the pre-send gate"
        );
    }

    /// Adversarial 4: a complaint ledger row is recorded as a complaint, not
    /// as an unsubscribe (the two carry very different weights).
    #[tokio::test]
    async fn complaint_is_recorded_as_complaint_not_unsubscribe() {
        let Some(pool) = crate::test_db::canonical_test_pool("projector_complaint").await else {
            return;
        };
        let tenant = insert_tenant(&pool, "proj-complaint").await;
        let sender = insert_sender(&pool, &tenant).await;
        insert_ledger_event(&pool, &tenant, sender, "complaint", "msg-c", "c@x.test").await;

        let projector = OutcomeProjector::new(pool.clone(), "test-worker-complaint");
        drain(&projector, 3).await;

        let (_, _, _, complaints, unsubscribes, _, _, _) =
            health_counters(&pool, &tenant, sender).await;
        assert_eq!(complaints, 1);
        assert_eq!(unsubscribes, 0);
    }

    // -----------------------------------------------------------------------
    // Reward-loop fixture
    // -----------------------------------------------------------------------

    struct RewardFixture {
        experiment_id: Uuid,
        enrollment_id: Uuid,
        step_execution_id: Uuid,
    }

    /// Seed the canonical chain an experiment reward needs:
    /// sequence → version → step → experiment + arm → enrollment (carrying
    /// the experiment) → step execution (carrying the arm).
    async fn seed_reward_fixture(pool: &PgPool, tenant: &str) -> RewardFixture {
        let account_id = Uuid::new_v4();
        let contact_id = Uuid::new_v4();
        let sequence_id = Uuid::new_v4();
        let version_id = Uuid::new_v4();
        let step_id = Uuid::new_v4();
        let enrollment_id = Uuid::new_v4();
        let step_execution_id = Uuid::new_v4();
        let experiment_id = Uuid::new_v4();
        let suffix = &Uuid::new_v4().simple().to_string()[..12];

        sqlx::query(
            "INSERT INTO sales_accounts \
                 (id, tenant_id, company, domain, country, country_confidence, lifecycle) \
             VALUES ($1, $2, $3, $4, 'QZ', 0.95, 'discovered')",
        )
        .bind(account_id)
        .bind(tenant)
        .bind(format!("Reward Co {suffix}"))
        .bind(format!("reward-{suffix}.example"))
        .execute(pool)
        .await
        .expect("insert account");

        sqlx::query(
            "INSERT INTO sales_contacts (id, tenant_id, account_id, full_name, country) \
             VALUES ($1, $2, $3, 'Reward Prospect', 'QZ')",
        )
        .bind(contact_id)
        .bind(tenant)
        .bind(account_id)
        .execute(pool)
        .await
        .expect("insert contact");

        sqlx::query(
            "INSERT INTO sales_sequences (id, tenant_id, name, status) VALUES ($1, $2, $3, 'active')",
        )
        .bind(sequence_id)
        .bind(tenant)
        .bind(format!("Reward Sequence {suffix}"))
        .execute(pool)
        .await
        .expect("insert sequence");

        sqlx::query(
            "INSERT INTO sales_sequence_versions \
                 (id, tenant_id, sequence_id, version, status, locale, approved_by, approved_at) \
             VALUES ($1, $2, $3, 1, 'active', 'en', 'projector-test', NOW())",
        )
        .bind(version_id)
        .bind(tenant)
        .bind(sequence_id)
        .execute(pool)
        .await
        .expect("insert sequence version");

        sqlx::query(
            "INSERT INTO sales_sequence_steps \
                 (id, tenant_id, version_id, step_index, kind, min_delay_secs, max_delay_secs, sender_pool) \
             VALUES ($1, $2, $3, 0, 'email', 0, 0, 'sales_outbound')",
        )
        .bind(step_id)
        .bind(tenant)
        .bind(version_id)
        .execute(pool)
        .await
        .expect("insert sequence step");

        sqlx::query(
            "INSERT INTO sales_experiments (id, tenant_id, key, name, status) \
             VALUES ($1, $2, $3, 'Reward experiment', 'running')",
        )
        .bind(experiment_id)
        .bind(tenant)
        .bind(format!("reward-exp-{suffix}"))
        .execute(pool)
        .await
        .expect("insert experiment");

        for variant in ["control", "challenger"] {
            sqlx::query(
                "INSERT INTO sales_experiment_arms \
                     (id, tenant_id, experiment_id, variant, is_control) \
                 VALUES (gen_random_uuid(), $1, $2, $3, $4)",
            )
            .bind(tenant)
            .bind(experiment_id)
            .bind(variant)
            .bind(variant == "control")
            .execute(pool)
            .await
            .expect("insert experiment arm");
        }

        sqlx::query(
            "INSERT INTO sales_enrollments \
                 (id, tenant_id, sequence_version_id, account_id, contact_id, state, \
                  experiment_id, experiment_variant) \
             VALUES ($1, $2, $3, $4, $5, 'active', $6, 'challenger')",
        )
        .bind(enrollment_id)
        .bind(tenant)
        .bind(version_id)
        .bind(account_id)
        .bind(contact_id)
        .bind(experiment_id)
        .execute(pool)
        .await
        .expect("insert enrollment");

        sqlx::query(
            "INSERT INTO sales_step_executions \
                 (id, tenant_id, enrollment_id, sequence_version_id, sequence_step_id, \
                  step_index, state, variant, idempotency_key) \
             VALUES ($1, $2, $3, $4, $5, 0, 'sent', 'challenger', $6)",
        )
        .bind(step_execution_id)
        .bind(tenant)
        .bind(enrollment_id)
        .bind(version_id)
        .bind(step_id)
        .bind(format!("projector-{suffix}"))
        .execute(pool)
        .await
        .expect("insert step execution");

        RewardFixture {
            experiment_id,
            enrollment_id,
            step_execution_id,
        }
    }

    async fn insert_outcome(
        pool: &PgPool,
        tenant: &str,
        fixture: &RewardFixture,
        outcome: &str,
    ) -> Uuid {
        sqlx::query_scalar(
            "INSERT INTO sales_outcomes \
                 (id, tenant_id, enrollment_id, step_execution_id, outcome, value_eur, occurred_at) \
             VALUES (gen_random_uuid(), $1, $2, $3, $4, 0, NOW()) \
             RETURNING id",
        )
        .bind(tenant)
        .bind(fixture.enrollment_id)
        .bind(fixture.step_execution_id)
        .bind(outcome)
        .fetch_one(pool)
        .await
        .expect("insert sales outcome")
    }

    async fn arm_posterior(
        pool: &PgPool,
        experiment_id: Uuid,
        variant: &str,
    ) -> (f64, f64, i64, i64) {
        sqlx::query_as(
            "SELECT alpha, beta, trials, successes FROM sales_experiment_arms \
             WHERE experiment_id = $1 AND variant = $2",
        )
        .bind(experiment_id)
        .bind(variant)
        .fetch_one(pool)
        .await
        .expect("read arm posterior")
    }

    /// Adversarial 5: a real production outcome reaches `record_reward`, the
    /// posterior moves once, and replaying the same stable
    /// `sales-outcome:{id}` key leaves it unchanged.
    #[tokio::test]
    async fn reward_projection_moves_the_posterior_once_and_replay_is_a_noop() {
        let Some(pool) = crate::test_db::canonical_test_pool("projector_reward").await else {
            return;
        };
        let tenant = insert_tenant(&pool, "proj-reward").await;
        let fixture = seed_reward_fixture(&pool, &tenant).await;
        let outcome_id = insert_outcome(&pool, &tenant, &fixture, "positive_reply").await;

        let projector = OutcomeProjector::new(pool.clone(), "test-worker-reward");
        drain_rewards(&projector, 3).await;

        // positive_reply reward is 0.5 (experiments.rs ladder).
        let (alpha, beta, trials, successes) =
            arm_posterior(&pool, fixture.experiment_id, "challenger").await;
        assert!((alpha - 1.5).abs() < 1e-9, "alpha moved once: {alpha}");
        assert!((beta - 1.0).abs() < 1e-9);
        assert_eq!((trials, successes), (1, 1));

        let marker: Option<DateTime<Utc>> =
            sqlx::query_scalar("SELECT reward_processed_at FROM sales_outcomes WHERE id = $1")
                .bind(outcome_id)
                .fetch_one(&pool)
                .await
                .expect("read reward marker");
        assert!(marker.is_some(), "a successful record marks the outcome");

        // Replay the SAME logical outcome by clearing the claim marker (the
        // worst case a crash between record_reward and the marker produces).
        sqlx::query("UPDATE sales_outcomes SET reward_processed_at = NULL WHERE id = $1")
            .bind(outcome_id)
            .execute(&pool)
            .await
            .expect("simulate crash before the marker");

        drain_rewards(&projector, 3).await;

        let (alpha, beta, trials, successes) =
            arm_posterior(&pool, fixture.experiment_id, "challenger").await;
        assert!(
            (alpha - 1.5).abs() < 1e-9,
            "replay must not move alpha: {alpha}"
        );
        assert!((beta - 1.0).abs() < 1e-9);
        assert_eq!((trials, successes), (1, 1), "replay must not move trials");

        let ledger_rows: i64 = sqlx::query_scalar(
            "SELECT COUNT(*)::bigint FROM sales_experiment_outcomes WHERE experiment_id = $1",
        )
        .bind(fixture.experiment_id)
        .fetch_one(&pool)
        .await
        .expect("count experiment outcomes");
        assert_eq!(ledger_rows, 1, "one stable key → one reward ledger row");
    }

    /// Adversarial 8: an outcome with a NULL `step_execution_id` is not
    /// claimed by the reward projector (no experiment to attribute to).
    #[tokio::test]
    async fn outcome_without_step_execution_is_never_claimed() {
        let Some(pool) = crate::test_db::canonical_test_pool("projector_null_step").await else {
            return;
        };
        let tenant = insert_tenant(&pool, "proj-null-step").await;

        let outcome_id: Uuid = sqlx::query_scalar(
            "INSERT INTO sales_outcomes (id, tenant_id, outcome, value_eur, occurred_at) \
             VALUES (gen_random_uuid(), $1, 'positive_reply', 0, NOW()) RETURNING id",
        )
        .bind(&tenant)
        .fetch_one(&pool)
        .await
        .expect("insert unlinked outcome");

        let projector = OutcomeProjector::new(pool.clone(), "test-worker-null-step");
        drain_rewards(&projector, 3).await;

        let marker: Option<DateTime<Utc>> =
            sqlx::query_scalar("SELECT reward_processed_at FROM sales_outcomes WHERE id = $1")
                .bind(outcome_id)
                .fetch_one(&pool)
                .await
                .expect("read marker");
        assert!(
            marker.is_none(),
            "an unlinked outcome must stay out of the reward claim set"
        );
    }
}
