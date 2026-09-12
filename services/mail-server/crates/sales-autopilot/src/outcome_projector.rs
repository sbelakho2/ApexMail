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
//! `sales_sender_events` carries no `lease_owner` / `lease_token` /
//! `lease_expires_at` columns — only `processed_at`. The durable claim is
//! therefore written into that one column, following the same three
//! properties as `ActionQueue::claim`:
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
//!   lease columns.
//! * **Expiry recovery** — a worker that dies mid-application leaves the
//!   durable claim behind. [`OutcomeProjector::recover_unapplied_claims`]
//!   re-opens a claim whose lease has expired (`claimed_at` older than
//!   `lease_secs`) **only when the per-event applied marker for THIS event is
//!   absent** (`NOT EXISTS (SELECT 1 FROM sales_sender_health_applied m WHERE
//!   m.event_id = e.id)`), so an event whose aggregate update committed is
//!   never re-applied while an unapplied one is retried.
//!
//! ## Per-event applied marker (migration 205)
//!
//! [`OutcomeProjector::apply_claimed_event`] applies an event as ONE
//! transaction:
//!
//! ```text
//! BEGIN;
//!   INSERT INTO sales_sender_health_applied (event_id) VALUES ($event)
//!     ON CONFLICT (event_id) DO NOTHING RETURNING event_id;
//!   -- only when the INSERT returned a row:
//!   <counter update + reassessment of sales_sender_health>;
//! COMMIT;
//! ```
//!
//! The marker's primary key makes application idempotent: re-claiming an
//! event that already has a marker hits `ON CONFLICT DO NOTHING`, returns no
//! row, and moves no aggregate. Because the marker and the aggregate commit
//! atomically, "the marker exists" is exactly equivalent to "this event's
//! counters are in the aggregate" — no inference from any sender-wide
//! watermark is needed or allowed. The previous implementation used
//! `sales_sender_health.updated_at >= processed_at` as the proof, which
//! **permanently undercounted** a crashed claim whenever a different event
//! for the same sender happened to bump `updated_at` after the claim: the
//! sweep concluded the crashed event had been applied. That heuristic and
//! its comment are gone.
//!
//! A failed [`sender_health::record_event_tx`] rolls the marker back with the
//! aggregate, and the claim is deliberately left in place: the recovery sweep
//! re-opens it after the lease expires (marker absent) and it is applied
//! exactly once. Releasing immediately on error is unnecessary now that the
//! whole application is atomic.
//!
//! ## Why the claim precedes the aggregate update
//!
//! The claim is durable BEFORE the aggregate transaction so that a crash at
//! any point leaves either (a) an unclaimed pending row, or (b) a claimed row
//! with no marker — both of which are recoverable — and never a row whose
//! aggregate moved without the ledger saying so. Recovery no longer needs to
//! guess from the aggregate: it asks the marker.
//!
//! Unlike the old watermark scheme, the marker also closes the
//! live-but-slow-worker window: if a worker outlives `lease_secs` mid-apply,
//! its claim can be recovered and re-applied, but the second transaction's
//! marker INSERT conflicts with the first's (waiting for it to commit or
//! roll back), so the aggregate moves exactly once. The lease bounds how
//! quickly a crashed claim is retried, not whether a retry can double-count.
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
    /// Claims whose per-event applied marker already existed: the aggregate
    /// already contains the event, so nothing moved (idempotent re-claim).
    pub already_applied: u64,
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

            match self
                .apply_claimed_event(&claimed, &config.health_thresholds)
                .await
            {
                Ok(Some(assessment)) => {
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
                Ok(None) => {
                    // The per-event marker already existed: the aggregate
                    // already contains this event. Move nothing.
                    report.already_applied += 1;
                    metrics::counter!("sales_sender_events_already_applied_total").increment(1);
                    tracing::debug!(
                        sender_event_id = %claimed.id,
                        sender_identity_id = %claimed.sender_identity_id,
                        "sender event already has an applied marker; re-claim is a no-op"
                    );
                }
                Err(error) => {
                    // Marker + aggregate rolled back together, so the claim
                    // is left in place and the recovery sweep re-opens it
                    // once the lease expires (the marker is absent).
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

    /// Apply one claimed event: insert its per-event applied marker and fold
    /// the event into `sales_sender_health` in ONE transaction.
    ///
    /// Returns `Ok(Some(assessment))` when this call moved the aggregate,
    /// `Ok(None)` when a marker for this event already existed (idempotent
    /// re-claim: the aggregate already contains the event and is not touched
    /// again). On error the transaction rolls back, leaving neither marker
    /// nor aggregate movement, so lease-expiry recovery can retry safely.
    async fn apply_claimed_event(
        &self,
        claimed: &ClaimedSenderEvent,
        thresholds: &HealthThresholds,
    ) -> Result<Option<sender_health::HealthAssessment>, SalesError> {
        let mut tx = self
            .db
            .begin()
            .await
            .map_err(|error| SalesError::Database(error.to_string()))?;

        // The marker INSERT is the idempotency gate: its primary key makes a
        // second application of the same event conflict, and
        // `ON CONFLICT DO NOTHING` then returns no row. A concurrent
        // transaction that inserted the same key blocks here until it
        // commits or rolls back, so the aggregate below runs at most once
        // even if two workers apply the same event concurrently.
        let inserted: Option<Uuid> = sqlx::query_scalar(
            "INSERT INTO sales_sender_health_applied (event_id) VALUES ($1) \
             ON CONFLICT (event_id) DO NOTHING \
             RETURNING event_id",
        )
        .bind(claimed.id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|error| SalesError::Database(error.to_string()))?;

        if inserted.is_none() {
            tx.commit()
                .await
                .map_err(|error| SalesError::Database(error.to_string()))?;
            return Ok(None);
        }

        let assessment = sender_health::record_event_tx(
            &mut tx,
            &claimed.tenant_id,
            claimed.sender_identity_id,
            claimed.event_type.health_event(),
            thresholds,
        )
        .await?;

        tx.commit()
            .await
            .map_err(|error| SalesError::Database(error.to_string()))?;
        Ok(Some(assessment))
    }

    /// Re-open durable claims whose worker died before the application
    /// transaction committed.
    ///
    /// A claim is expired (`processed_at <= NOW() - lease_secs`) and
    /// unapplied when the per-event applied marker for THIS event is absent
    /// (`NOT EXISTS (SELECT 1 FROM sales_sender_health_applied m WHERE
    /// m.event_id = e.id)`). Marker presence is the only evidence consulted:
    /// the marker and the aggregate counter commit atomically, so an applied
    /// claim can never be re-opened (no double count) and an unapplied one is
    /// always retried (no undercount). The previous sender-wide
    /// `sales_sender_health.updated_at` watermark is deliberately gone — a
    /// different event for the same sender bumping `updated_at` used to mask
    /// a crashed claim permanently.
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
                   SELECT 1 FROM sales_sender_health_applied m \
                   WHERE m.event_id = e.id \
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
    use crate::sender_health;
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
    /// application transaction is recovered and applied exactly once; a
    /// projector that dies after the transaction committed is NOT re-applied,
    /// because the per-event applied marker proves THIS event moved the
    /// aggregate.
    #[tokio::test]
    async fn crashed_claims_never_double_count_and_unapplied_claims_are_recovered() {
        let Some(pool) = crate::test_db::canonical_test_pool("projector_crash_recovery").await
        else {
            return;
        };
        let tenant = insert_tenant(&pool, "proj-crash").await;
        let sender_applied = insert_sender(&pool, &tenant).await;
        let sender_unapplied = insert_sender(&pool, &tenant).await;

        // Case A — crash AFTER the application transaction committed: the
        // paper trail is "durable claim + marker + aggregate". Produce it
        // through the REAL projector (marker and aggregate commit together),
        // then age the claim to model a worker that died after commit.
        let after_commit = insert_ledger_event(
            &pool,
            &tenant,
            sender_applied,
            "complaint",
            "msg-a",
            "a@x.test",
        )
        .await;
        let projector = OutcomeProjector::new(pool.clone(), "test-worker-crash");
        drain(&projector, 4).await;
        let applied_marker: i64 = sqlx::query_scalar(
            "SELECT COUNT(*)::bigint FROM sales_sender_health_applied WHERE event_id = $1",
        )
        .bind(after_commit)
        .fetch_one(&pool)
        .await
        .expect("count applied markers");
        assert_eq!(applied_marker, 1, "the applied event must carry a marker");
        sqlx::query(
            "UPDATE sales_sender_events SET processed_at = NOW() - INTERVAL '5 minutes' \
             WHERE id = $1",
        )
        .bind(after_commit)
        .execute(&pool)
        .await
        .expect("age the applied claim past the lease");

        // Case B — crash BEFORE the application transaction committed: an
        // expired durable claim with no marker and no aggregate movement.
        let before_commit: Uuid = sqlx::query_scalar(
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

        drain(&projector, 3).await;

        // Case A: the marker keeps the applied claim closed — no re-open, no
        // re-application, aggregate stays at exactly one.
        let (_, _, _, complaints_a, _, _, _, _) =
            health_counters(&pool, &tenant, sender_applied).await;
        assert_eq!(complaints_a, 1, "the applied complaint is counted once");
        let remarker_a: i64 = sqlx::query_scalar(
            "SELECT COUNT(*)::bigint FROM sales_sender_health_applied WHERE event_id = $1",
        )
        .bind(after_commit)
        .fetch_one(&pool)
        .await
        .expect("count applied markers");
        assert_eq!(remarker_a, 1, "an applied marker must stay singular");

        // Case B: recovered exactly once, and its marker is written.
        let (volume_b, hard_bounces_b, _, _, _, _, _, _) =
            health_counters(&pool, &tenant, sender_unapplied).await;
        assert_eq!(hard_bounces_b, 1, "the recovered bounce is applied once");
        assert_eq!(volume_b, 1, "volume moves exactly once (hard bounce)");
        let marker_b: i64 = sqlx::query_scalar(
            "SELECT COUNT(*)::bigint FROM sales_sender_health_applied WHERE event_id = $1",
        )
        .bind(before_commit)
        .fetch_one(&pool)
        .await
        .expect("count recovered markers");
        assert_eq!(marker_b, 1, "the recovered event must be marked applied");

        // Further passes change nothing (no replay, no double count).
        drain(&projector, 3).await;
        let (volume_b, hard_bounces_b, _, _, _, _, _, _) =
            health_counters(&pool, &tenant, sender_unapplied).await;
        assert_eq!((volume_b, hard_bounces_b), (1, 1));
        let (_, _, _, complaints_a, _, _, _, _) =
            health_counters(&pool, &tenant, sender_applied).await;
        assert_eq!(complaints_a, 1);
    }

    /// The exact residual race the old `updated_at` watermark lost: event A
    /// is applied for a sender (bumping the sender-wide `updated_at`), a
    /// second event B for the SAME sender is claimed by a worker that crashes
    /// before its application transaction commits, and the recovery sweep
    /// runs. The old heuristic compared B's claim against the sender-wide
    /// `updated_at` written by A and concluded B was applied — permanently
    /// undercounting B. The per-event marker answers for B alone, so B is
    /// recovered and applied; neither event undercounts.
    #[tokio::test]
    async fn same_sender_crash_does_not_undercount_behind_another_event() {
        let Some(pool) = crate::test_db::canonical_test_pool("projector_same_sender_race").await
        else {
            return;
        };
        let tenant = insert_tenant(&pool, "proj-race").await;
        let sender = insert_sender(&pool, &tenant).await;

        // Event A: applied through the real projector. This bumps
        // `sales_sender_health.updated_at` to "now".
        insert_ledger_event(&pool, &tenant, sender, "complaint", "msg-a", "a@x.test").await;
        let projector = OutcomeProjector::new(pool.clone(), "test-worker-race");
        drain(&projector, 4).await;

        // Event B arrives for the SAME sender and is claimed, but its worker
        // dies before the application transaction commits: an expired claim
        // with no marker. Its claim predates A's `updated_at` bump, which is
        // exactly what made the old sweep blind to it.
        let event_b: Uuid = sqlx::query_scalar(
            "INSERT INTO sales_sender_events \
                 (tenant_id, sender_identity_id, event_type, message_id, recipient, \
                  occurred_at, processed_at) \
             VALUES ($1, $2, 'hard_bounce', 'msg-b', 'b@x.test', NOW(), \
                     NOW() - INTERVAL '5 minutes') \
             RETURNING id",
        )
        .bind(&tenant)
        .bind(sender)
        .fetch_one(&pool)
        .await
        .expect("insert crashed claim");

        // The sweep must recover B on the marker's evidence alone. The old
        // watermark rule returned 0 here (A's health write was newer than
        // B's claim), silently undercounting the bounce forever.
        // The recovery sweep is global (the canonical test database is shared
        // by parallel tests), so the counter is only a liveness check; the
        // exact proof is B's own claim being re-opened.
        let recovered = projector
            .recover_unapplied_claims(DEFAULT_LEASE_SECS, DEFAULT_RECOVERY_WINDOW_SECS)
            .await
            .expect("recovery sweep");
        assert!(recovered >= 1, "the sweep must re-open the crashed claim");
        let reopened: bool = sqlx::query_scalar(
            "SELECT processed_at IS NULL FROM sales_sender_events WHERE id = $1",
        )
        .bind(event_b)
        .fetch_one(&pool)
        .await
        .expect("read B's claim");
        assert!(
            reopened,
            "the crashed claim for the same sender must be re-opened even though \
             another event wrote the aggregate after it"
        );

        // Apply the recovered event, then prove both events are counted once.
        // Volume counts sends: the hard bounce adds 1, the complaint adds 0
        // (it is an event about a send, not a send) — the undercount this test
        // guards would show as complaints = 0.
        drain(&projector, 3).await;
        let (volume, hard_bounces, _, complaints, _, _, _, _) =
            health_counters(&pool, &tenant, sender).await;
        assert_eq!(
            (volume, complaints, hard_bounces),
            (1, 1, 1),
            "neither the applied complaint nor the recovered bounce may undercount"
        );

        // Both events carry exactly one marker.
        let markers: i64 = sqlx::query_scalar(
            "SELECT COUNT(*)::bigint FROM sales_sender_health_applied m \
             JOIN sales_sender_events e ON e.id = m.event_id \
             WHERE e.sender_identity_id = $1",
        )
        .bind(sender)
        .fetch_one(&pool)
        .await
        .expect("count markers");
        assert_eq!(markers, 2);

        // Re-claiming an event that already has a marker is a no-op that
        // moves no aggregate and writes no second marker.
        sqlx::query("UPDATE sales_sender_events SET processed_at = NULL WHERE id = $1")
            .bind(event_b)
            .execute(&pool)
            .await
            .expect("force a re-claim of the marked event");
        drain(&projector, 3).await;
        let reclaimed: Option<DateTime<Utc>> =
            sqlx::query_scalar("SELECT processed_at FROM sales_sender_events WHERE id = $1")
                .bind(event_b)
                .fetch_one(&pool)
                .await
                .expect("read B's re-claim");
        assert!(
            reclaimed.is_some(),
            "the marked event must be re-claimed (and the application no-op)"
        );
        let (volume, hard_bounces, _, complaints, _, _, _, _) =
            health_counters(&pool, &tenant, sender).await;
        assert_eq!(
            (volume, complaints, hard_bounces),
            (1, 1, 1),
            "a re-claim of a marked event must not move the aggregate"
        );
        let markers: i64 = sqlx::query_scalar(
            "SELECT COUNT(*)::bigint FROM sales_sender_health_applied WHERE event_id = $1",
        )
        .bind(event_b)
        .fetch_one(&pool)
        .await
        .expect("count markers");
        assert_eq!(markers, 1, "the marker must remain singular");
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
