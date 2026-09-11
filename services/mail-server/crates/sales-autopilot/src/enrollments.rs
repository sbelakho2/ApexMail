//! Enrollment commands and the reply-driven sequence lock.
//!
//! This is the write side of the sequence model:
//!
//! * [`start_outreach`] — the control plane's outreach command. It resolves
//!   the sequence to an approved ACTIVE version, evaluates every per-contact
//!   gate (existence, email, suppression, legal policy, verification,
//!   duplicate enrollment), and atomically enrolls each accepted contact and
//!   enqueues its first step execution. Rejections are never silent: the
//!   response reports the exact reason key for every rejected contact.
//! * [`list_enrollments`] — the read model the CP campaigns page renders.
//! * [`set_enrollment_state`] — pause/resume/cancel of one enrollment's
//!   queued work.
//! * [`lock_on_reply`] — the release gate behind "100% of human replies
//!   prevent subsequent normal sequence sends". A reply transactionally sets
//!   `has_human_reply`, moves the enrollment off the normal path, and then
//!   cancels queued work.

use std::collections::{BTreeMap, HashMap, HashSet};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;

use crate::actions::{action_type, entity_type, ActionQueue};
use crate::sequences::{load_active_version, sales_step_idempotency_key, schedule_delay_secs};
use crate::types::{EnrollmentState, ReplyDisposition, SalesError};

/// The exact rejection-reason vocabulary the CP renders. These strings are an
/// API contract; do not rename them without changing the CP.
pub mod rejection_reason {
    /// No such contact in this tenant.
    pub const NOT_FOUND: &str = "not_found";
    /// The contact's email address is unsubscribed/suppressed (sales fast
    /// path, contact-point suppression, or the platform suppression list).
    pub const SUPPRESSED: &str = "suppressed";
    /// A recorded legal-policy decision denies this contact, or the selected
    /// policy is `prohibited`.
    pub const LEGAL_POLICY: &str = "legal_policy";
    /// The email contact point is not verified good (`valid` or `risky`).
    pub const UNVERIFIED_CONTACT: &str = "unverified_contact";
    /// A live enrollment already exists for (tenant, version, contact).
    pub const ALREADY_ENROLLED: &str = "already_enrolled";
    /// The contact has no email contact point.
    pub const NO_EMAIL: &str = "no_email";
}

/// Maximum number of contacts accepted in one outreach command.
pub const MAX_OUTREACH_CONTACTS: usize = 100;

/// Default step-execution variant when no experiment allocates one yet.
const DEFAULT_VARIANT: &str = "default";

/// Priority of a first-step action in `sales_actions`.
const FIRST_STEP_ACTION_PRIORITY: i16 = 100;

/// The CP's outreach command. `sequence_id` and `contact_ids` are the
/// canonical identifiers — NOT lead ids + a free-text template name.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct StartOutreachRequest {
    pub sequence_id: Uuid,
    pub contact_ids: Vec<Uuid>,
    pub autonomy_policy_id: Uuid,
    pub experiment_id: Option<Uuid>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StartOutreachResponse {
    pub enrollment_batch_id: Uuid,
    pub accepted: usize,
    pub rejected: usize,
    /// Reason key -> count, for the contacts that were rejected.
    pub rejection_reasons: BTreeMap<String, usize>,
}

/// One row for the CP campaign/enrollment list.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EnrollmentSummary {
    pub id: Uuid,
    pub sequence_name: String,
    pub sequence_version: i32,
    pub contact_name: String,
    pub contact_email: Option<String>,
    pub account_company: Option<String>,
    pub state: String,
    pub current_step_index: i32,
    pub enrolled_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Enroll contacts into a sequence, evaluating every gate per contact and
/// enqueuing the first step action for each accepted enrollment.
///
/// # Gates and precedence
///
/// Each contact is evaluated once, in this order, and rejected with the first
/// matching reason key:
///
/// 1. `not_found` — no such contact in this tenant.
/// 2. `no_email` — no `sales_contact_points` row with `channel = 'email'`.
/// 3. `suppressed` — the chosen address is in `sales_unsubscribes`, the
///    contact point has `suppressed_at` set, or the address is in the platform
///    `suppressions` table (all compared tenant + lower(email)).
/// 4. `legal_policy` — the latest recorded
///    `sales_contact_policy_decisions` row for the contact is `prohibited` or
///    `approval_required` (or an unrecognised value — fail closed), or no
///    decision is recorded and the selected policy is `prohibited`.
/// 5. `unverified_contact` — the email point's `verification` is neither
///    `valid` nor `risky`. `unknown` is therefore rejected too. `risky` is
///    accepted (reachable but lower confidence) and counted as accepted.
/// 6. `already_enrolled` — a `sales_enrollments` row for (tenant, version,
///    contact) exists in a state other than
///    `completed`/`failed`/`suppressed`. Those terminal states may be
///    re-enrolled; the upsert resets the row.
///
/// # Validation (whole request)
///
/// * `contact_ids` must hold 1..=100 entries; duplicates are de-duplicated
///   (first occurrence wins) so each contact is processed and counted once.
/// * `sequence_id` must resolve to an approved ACTIVE version (see
///   [`load_active_version`]); otherwise the call fails.
/// * `autonomy_policy_id` must resolve to an approved, in-date
///   `sales_jurisdiction_policies` row for the email channel; otherwise
///   [`SalesError::PolicyDenied`] names it. An unapproved policy is never a
///   usable basis for outreach. An `approval_required` policy is accepted:
///   the authenticated operator's explicit command with an approved in-date
///   policy is the approval for this batch.
///
/// # Atomicity and idempotency
///
/// Writes happen in ONE transaction per accepted contact: the enrollment
/// insert (with `ON CONFLICT ... DO UPDATE` for terminal states), the first
/// step execution (`ON CONFLICT (idempotency_key) DO NOTHING`), and the queue
/// action (`ActionQueue::enqueue_tx`, idempotent on its key). A database
/// failure while enrolling one contact rolls that contact back and returns an
/// error; contacts already committed stay enrolled, and re-running the
/// command is a no-op for them (`already_enrolled`). Re-running with the same
/// contacts therefore creates no duplicate enrollments and no duplicate
/// actions. `enrollment_batch_id` is written into every action payload so the
/// CP can correlate a run.
pub async fn start_outreach(
    db: &PgPool,
    queue: &ActionQueue,
    tenant_id: &str,
    request: &StartOutreachRequest,
) -> Result<StartOutreachResponse, SalesError> {
    if request.contact_ids.is_empty() || request.contact_ids.len() > MAX_OUTREACH_CONTACTS {
        return Err(SalesError::InvalidInput(format!(
            "contact_ids must contain between 1 and {MAX_OUTREACH_CONTACTS} contacts (got {})",
            request.contact_ids.len()
        )));
    }

    let enrollment_batch_id = Uuid::new_v4();
    let contact_ids = dedup_preserving_order(&request.contact_ids);

    // The sequence itself must be schedulable before any contact work starts.
    let version = load_active_version(db, tenant_id, request.sequence_id).await?;
    let first_step = version.steps.first().ok_or_else(|| {
        SalesError::ServiceUnavailable(format!(
            "sequence {} active version {} has no steps — nothing to enroll",
            request.sequence_id, version.version
        ))
    })?;

    // The legal basis for the whole batch must be an approved, in-date policy.
    let policy_row: Option<PolicyRow> = sqlx::query_as(
        "SELECT channel, decision, approved_by, approved_at, valid_from, valid_until \
         FROM sales_jurisdiction_policies \
         WHERE id = $1",
    )
    .bind(request.autonomy_policy_id)
    .fetch_optional(db)
    .await
    .map_err(|e| SalesError::Database(e.to_string()))?;
    let policy_prohibited =
        policy_verdict(policy_row.as_ref(), request.autonomy_policy_id, Utc::now())?;

    // ---------------------------------------------------------------------
    // Bulk gate inputs (one round trip each, never per contact).
    // ---------------------------------------------------------------------
    let contacts: HashMap<Uuid, ContactRow> = sqlx::query_as::<_, ContactRow>(
        "SELECT id, account_id, full_name \
         FROM sales_contacts \
         WHERE tenant_id = $1 AND id = ANY($2)",
    )
    .bind(tenant_id)
    .bind(&contact_ids)
    .fetch_all(db)
    .await
    .map_err(|e| SalesError::Database(e.to_string()))?
    .into_iter()
    .map(|contact| (contact.id, contact))
    .collect();

    // One email point per contact: prefer a non-suppressed point, then the
    // most recently created one. `DISTINCT ON` keeps this a single query.
    let email_points: HashMap<Uuid, EmailPointRow> = sqlx::query_as::<_, EmailPointRow>(
        "SELECT DISTINCT ON (contact_id) contact_id, id, value, normalized_value, \
                verification, suppressed_at \
         FROM sales_contact_points \
         WHERE tenant_id = $1 AND contact_id = ANY($2) AND channel = 'email' \
         ORDER BY contact_id, (suppressed_at IS NULL) DESC, created_at DESC",
    )
    .bind(tenant_id)
    .bind(&contact_ids)
    .fetch_all(db)
    .await
    .map_err(|e| SalesError::Database(e.to_string()))?
    .into_iter()
    .map(|point| (point.contact_id, point))
    .collect();

    let emails: Vec<String> = email_points
        .values()
        .map(|point| point.normalized_value.to_ascii_lowercase())
        .collect();
    let mut suppressed_addresses: HashSet<String> = HashSet::new();
    if !emails.is_empty() {
        let unsubscribed: Vec<String> = sqlx::query_scalar(
            "SELECT lower(email) FROM sales_unsubscribes \
             WHERE tenant_id = $1 AND lower(email) = ANY($2)",
        )
        .bind(tenant_id)
        .bind(&emails)
        .fetch_all(db)
        .await
        .map_err(|e| SalesError::Database(e.to_string()))?;
        suppressed_addresses.extend(unsubscribed);

        let platform_suppressed: Vec<String> = sqlx::query_scalar(
            "SELECT lower(email) FROM suppressions \
             WHERE tenant_id = $1 AND lower(email) = ANY($2)",
        )
        .bind(tenant_id)
        .bind(&emails)
        .fetch_all(db)
        .await
        .map_err(|e| SalesError::Database(e.to_string()))?;
        suppressed_addresses.extend(platform_suppressed);
    }

    let enrollment_states: HashMap<Uuid, String> = sqlx::query_as::<_, (Uuid, String)>(
        "SELECT contact_id, state FROM sales_enrollments \
         WHERE tenant_id = $1 AND sequence_version_id = $2 AND contact_id = ANY($3)",
    )
    .bind(tenant_id)
    .bind(version.version_id)
    .bind(&contact_ids)
    .fetch_all(db)
    .await
    .map_err(|e| SalesError::Database(e.to_string()))?
    .into_iter()
    .collect();

    let legal_decisions: HashMap<Uuid, String> = sqlx::query_as::<_, (Uuid, String)>(
        "SELECT DISTINCT ON (contact_id) contact_id, decision \
         FROM sales_contact_policy_decisions \
         WHERE tenant_id = $1 AND contact_id = ANY($2) \
         ORDER BY contact_id, created_at DESC",
    )
    .bind(tenant_id)
    .bind(&contact_ids)
    .fetch_all(db)
    .await
    .map_err(|e| SalesError::Database(e.to_string()))?
    .into_iter()
    .collect();

    // ---------------------------------------------------------------------
    // Per-contact gates and enrollment.
    // ---------------------------------------------------------------------
    let mut accepted = 0usize;
    let mut rejected = 0usize;
    let mut rejection_reasons: BTreeMap<String, usize> = BTreeMap::new();

    for contact_id in contact_ids {
        let contact = contacts.get(&contact_id);
        let point = email_points.get(&contact_id);
        let already_enrolled = enrollment_states
            .get(&contact_id)
            .is_some_and(|state| enrollment_is_live(state));
        let address_suppressed = point
            .map(|point| {
                suppressed_addresses.contains(&point.normalized_value.to_ascii_lowercase())
            })
            .unwrap_or(false);
        let legal_denied = match legal_decisions.get(&contact_id).map(String::as_str) {
            Some("allowed") => false,
            // prohibited, approval_required, or an unknown value: fail closed.
            Some(_) => true,
            None => policy_prohibited,
        };

        if let Some(reason) = evaluate_contact_gates(ContactGateInput {
            contact_found: contact.is_some(),
            email: point.map(|point| EmailGate {
                verification: point.verification.as_str(),
                suppressed: point.suppressed_at.is_some(),
            }),
            address_suppressed,
            legal_denied,
            already_enrolled,
        }) {
            *rejection_reasons.entry(reason.to_string()).or_insert(0) += 1;
            rejected += 1;
            continue;
        }

        // The gates guaranteed both are present.
        let Some(contact) = contact else {
            return Err(SalesError::Internal(anyhow::anyhow!(
                "contact {contact_id} disappeared between gate evaluation and enrollment"
            )));
        };
        let Some(point) = point else {
            return Err(SalesError::Internal(anyhow::anyhow!(
                "email point for contact {contact_id} disappeared between gate evaluation and enrollment"
            )));
        };

        // ONE transaction per contact: enrollment + first step execution +
        // queued action commit together, so a failure on this contact cannot
        // corrupt another contact's already-committed enrollment.
        let mut tx = db
            .begin()
            .await
            .map_err(|e| SalesError::Database(e.to_string()))?;

        // A first `wait` step means no send is pending: the enrollment waits.
        let enrollment_state = if first_step.kind == "wait" {
            EnrollmentState::Waiting
        } else {
            EnrollmentState::Active
        };

        let inserted: Option<Uuid> = sqlx::query_scalar(
            "INSERT INTO sales_enrollments ( \
                 id, tenant_id, sequence_version_id, account_id, contact_id, contact_point_id, \
                 state, current_step_index, experiment_id, has_human_reply, enrolled_at, updated_at \
             ) VALUES ($1, $2, $3, $4, $5, $6, $7, 0, $8, FALSE, NOW(), NOW()) \
             ON CONFLICT (tenant_id, sequence_version_id, contact_id) DO UPDATE \
                SET state = EXCLUDED.state, \
                    current_step_index = EXCLUDED.current_step_index, \
                    account_id = EXCLUDED.account_id, \
                    contact_point_id = EXCLUDED.contact_point_id, \
                    experiment_id = EXCLUDED.experiment_id, \
                    has_human_reply = FALSE, \
                    decision_id = NULL, \
                    enrolled_at = NOW(), \
                    updated_at = NOW(), \
                    completed_at = NULL \
              WHERE sales_enrollments.state IN ('completed', 'failed', 'suppressed') \
             RETURNING id",
        )
        .bind(Uuid::new_v4())
        .bind(tenant_id)
        .bind(version.version_id)
        .bind(contact.account_id)
        .bind(contact_id)
        .bind(point.id)
        .bind(enrollment_state.as_str())
        .bind(request.experiment_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| SalesError::Database(e.to_string()))?;

        let Some(enrollment_id) = inserted else {
            // Lost a race with a concurrent outreach call: a live enrollment
            // exists. Nothing was written; report it like the pre-check would.
            let _ = tx.rollback().await;
            *rejection_reasons
                .entry(rejection_reason::ALREADY_ENROLLED.to_string())
                .or_insert(0) += 1;
            rejected += 1;
            continue;
        };

        let attempt_kind = attempt_kind_for_step_kind(&first_step.kind);
        let idempotency_key = sales_step_idempotency_key(
            enrollment_id,
            version.version_id,
            first_step.id,
            attempt_kind,
            DEFAULT_VARIANT,
        );
        let delay_secs = schedule_delay_secs(first_step, &idempotency_key);

        let inserted: Option<(Uuid, Option<DateTime<Utc>>)> = sqlx::query_as(
            "INSERT INTO sales_step_executions ( \
                 id, tenant_id, enrollment_id, sequence_version_id, sequence_step_id, step_index, \
                 attempt_kind, variant, state, idempotency_key, scheduled_for, attempt, \
                 created_at, updated_at \
             ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'scheduled', $9, \
                       NOW() + make_interval(secs => $10::double precision), 0, NOW(), NOW()) \
             ON CONFLICT (idempotency_key) DO NOTHING \
             RETURNING id, scheduled_for",
        )
        .bind(Uuid::new_v4())
        .bind(tenant_id)
        .bind(enrollment_id)
        .bind(version.version_id)
        .bind(first_step.id)
        .bind(first_step.step_index)
        .bind(attempt_kind)
        .bind(DEFAULT_VARIANT)
        .bind(&idempotency_key)
        .bind(delay_secs as f64)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| SalesError::Database(e.to_string()))?;

        let (step_execution_id, scheduled_for) = match inserted {
            Some(row) => row,
            None => sqlx::query_as(
                "SELECT id, scheduled_for FROM sales_step_executions \
                 WHERE idempotency_key = $1",
            )
            .bind(&idempotency_key)
            .fetch_one(&mut *tx)
            .await
            .map_err(|e| SalesError::Database(e.to_string()))?,
        };
        let due_at = scheduled_for.unwrap_or_else(Utc::now);

        let action_id = ActionQueue::enqueue_tx(
            &mut tx,
            tenant_id,
            action_type::SEND_STEP,
            entity_type::STEP_EXECUTION,
            step_execution_id,
            &format!("sa-send:{step_execution_id}"),
            serde_json::json!({
                "enrollmentBatchId": enrollment_batch_id,
                "enrollmentId": enrollment_id,
                "sequenceId": version.sequence_id,
                "sequenceVersionId": version.version_id,
                "stepExecutionId": step_execution_id,
                "stepIndex": first_step.step_index,
            }),
            due_at,
            FIRST_STEP_ACTION_PRIORITY,
            None,
        )
        .await?;

        tx.commit()
            .await
            .map_err(|e| SalesError::Database(e.to_string()))?;

        tracing::debug!(
            worker = queue.worker_id(),
            tenant = tenant_id,
            enrollment = %enrollment_id,
            action = %action_id,
            batch = %enrollment_batch_id,
            "first sequence step enqueued"
        );
        accepted += 1;
    }

    Ok(StartOutreachResponse {
        enrollment_batch_id,
        accepted,
        rejected,
        rejection_reasons,
    })
}

/// The read model the CP campaigns page renders.
pub async fn list_enrollments(
    db: &PgPool,
    tenant_id: &str,
    limit: i64,
    offset: i64,
) -> Result<Vec<EnrollmentSummary>, SalesError> {
    let limit = limit.clamp(0, 1000);
    let offset = offset.max(0);

    let rows: Vec<EnrollmentSummaryRow> = sqlx::query_as(
        "SELECT e.id, s.name AS sequence_name, v.version AS sequence_version, \
                c.full_name AS contact_name, \
                COALESCE( \
                    cp.value, \
                    (SELECT p.value FROM sales_contact_points p \
                     WHERE p.contact_id = c.id AND p.channel = 'email' \
                     ORDER BY (p.suppressed_at IS NULL) DESC, p.created_at DESC \
                     LIMIT 1) \
                ) AS contact_email, \
                a.company AS account_company, \
                e.state, e.current_step_index, e.enrolled_at, e.updated_at \
         FROM sales_enrollments e \
         JOIN sales_sequence_versions v ON v.id = e.sequence_version_id \
         JOIN sales_sequences s ON s.id = v.sequence_id \
         JOIN sales_contacts c ON c.id = e.contact_id \
         LEFT JOIN sales_accounts a ON a.id = e.account_id \
         LEFT JOIN sales_contact_points cp ON cp.id = e.contact_point_id \
         WHERE e.tenant_id = $1 \
         ORDER BY e.enrolled_at DESC, e.id \
         LIMIT $2 OFFSET $3",
    )
    .bind(tenant_id)
    .bind(limit)
    .bind(offset)
    .fetch_all(db)
    .await
    .map_err(|e| SalesError::Database(e.to_string()))?;

    Ok(rows.into_iter().map(EnrollmentSummary::from).collect())
}

/// Pause / resume / cancel one enrollment's queued work.
///
/// The enrollment state is updated first; when the target state stops the
/// normal path (`Pending`, `Paused`, `Replied`, `MeetingBooked`, `Completed`,
/// `Suppressed`, `Failed`) every queued/leased action for the enrollment is
/// cancelled through [`ActionQueue::cancel_for_entity`], so pausing genuinely
/// stops the next touch. `Active` and `Waiting` keep queued work: `Waiting` is
/// the normal OOO/soft-bounce pause and the sequence resumes later.
///
/// Returns `false` when no enrollment with that id exists for the tenant.
/// Resuming from a cancelled state does not resurrect cancelled actions; an
/// operator replays them from the queue if they are still wanted.
pub async fn set_enrollment_state(
    db: &PgPool,
    queue: &ActionQueue,
    tenant_id: &str,
    enrollment_id: Uuid,
    state: EnrollmentState,
) -> Result<bool, SalesError> {
    let affected = sqlx::query(
        "UPDATE sales_enrollments \
         SET state = $3, updated_at = NOW(), \
             completed_at = CASE \
                 WHEN $3 IN ('completed', 'failed', 'suppressed') THEN NOW() \
                 ELSE NULL \
             END \
         WHERE id = $1 AND tenant_id = $2",
    )
    .bind(enrollment_id)
    .bind(tenant_id)
    .bind(state.as_str())
    .execute(db)
    .await
    .map_err(|e| SalesError::Database(e.to_string()))?
    .rows_affected();

    if affected == 0 {
        return Ok(false);
    }

    if cancels_queued_work(state) {
        queue
            .cancel_for_entity(
                tenant_id,
                entity_type::ENROLLMENT,
                enrollment_id,
                &format!("enrollment moved to '{state}'"),
            )
            .await?;
    }

    Ok(true)
}

/// Record that an inbound reply arrived and lock the enrollment so no
/// scheduled follow-up can race out.
///
/// The enrollment update (state + `has_human_reply`) and the unsubscribe
/// upsert happen in ONE transaction; the queue cancellation follows the
/// commit via [`ActionQueue::cancel_for_entity`]. The committed
/// `has_human_reply` flag is the authoritative gate — the dispatcher's send
/// path must check it — because the cancellation of an already-leased action
/// cannot be made to race with the send inside the enrollment transaction
/// without bypassing the queue API.
///
/// Disposition mapping (also see `reply_lock_plan`):
///
/// | Disposition | State | Queued work | Unsubscribe |
/// |---|---|---|---|
/// | `Unsubscribe`, `Complaint`, `BounceHard` | `suppressed` | cancelled | upserted |
/// | `Positive`, `MeetingRequest`, `Question`, `Referral` | `replied` | cancelled | — |
/// | `NotInterested` | `completed` | cancelled | — |
/// | `OutOfOffice`, `BounceSoft` | `waiting` | kept (resumes later) | — |
/// | `Unknown` | `paused` | cancelled | — |
///
/// `has_human_reply` is set for every disposition except `OutOfOffice` and
/// `BounceSoft` (`ReplyDisposition::stops_normal_sequence`): a soft bounce or
/// an out-of-office autoreply must not permanently block the sequence, every
/// other inbound signal must.
pub async fn lock_on_reply(
    db: &PgPool,
    queue: &ActionQueue,
    tenant_id: &str,
    enrollment_id: Uuid,
    disposition: ReplyDisposition,
) -> Result<(), SalesError> {
    let plan = reply_lock_plan(disposition);

    let mut tx = db
        .begin()
        .await
        .map_err(|e| SalesError::Database(e.to_string()))?;

    let updated: Option<(Uuid, Option<Uuid>)> = sqlx::query_as(
        "UPDATE sales_enrollments \
         SET has_human_reply = $3, state = $4, updated_at = NOW(), \
             completed_at = CASE \
                 WHEN $4 IN ('completed', 'suppressed') THEN NOW() \
                 ELSE completed_at \
             END \
         WHERE id = $1 AND tenant_id = $2 \
         RETURNING contact_id, contact_point_id",
    )
    .bind(enrollment_id)
    .bind(tenant_id)
    .bind(plan.has_human_reply)
    .bind(plan.state.as_str())
    .fetch_optional(&mut *tx)
    .await
    .map_err(|e| SalesError::Database(e.to_string()))?;

    let Some((contact_id, contact_point_id)) = updated else {
        let _ = tx.rollback().await;
        return Err(SalesError::InvalidInput(format!(
            "enrollment {enrollment_id} not found for tenant {tenant_id}"
        )));
    };

    if plan.suppress_endpoint {
        let email: Option<String> = sqlx::query_scalar(
            "SELECT COALESCE( \
                 (SELECT cp.value FROM sales_contact_points cp WHERE cp.id = $1), \
                 (SELECT p.value FROM sales_contact_points p \
                  WHERE p.contact_id = $2 AND p.channel = 'email' \
                  ORDER BY (p.suppressed_at IS NULL) DESC, p.created_at DESC \
                  LIMIT 1) \
             )",
        )
        .bind(contact_point_id)
        .bind(contact_id)
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| SalesError::Database(e.to_string()))?;

        match email {
            Some(email) => {
                sqlx::query(
                    "INSERT INTO sales_unsubscribes (tenant_id, email) \
                     VALUES ($1, lower($2)) \
                     ON CONFLICT (tenant_id, email) DO NOTHING",
                )
                .bind(tenant_id)
                .bind(&email)
                .execute(&mut *tx)
                .await
                .map_err(|e| SalesError::Database(e.to_string()))?;
            }
            None => {
                tracing::warn!(
                    tenant = tenant_id,
                    enrollment = %enrollment_id,
                    contact = %contact_id,
                    "suppression disposition recorded but no email contact point exists to unsubscribe"
                );
            }
        }
    }

    tx.commit()
        .await
        .map_err(|e| SalesError::Database(e.to_string()))?;

    if plan.cancel_queued {
        let cancelled = queue
            .cancel_for_entity(
                tenant_id,
                entity_type::ENROLLMENT,
                enrollment_id,
                &format!("sequence locked by '{}' reply", disposition.as_str()),
            )
            .await?;
        tracing::info!(
            tenant = tenant_id,
            enrollment = %enrollment_id,
            disposition = disposition.as_str(),
            state = plan.state.as_str(),
            cancelled_actions = cancelled,
            "sequence locked by reply"
        );
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Pure gate / mapping helpers
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy)]
struct EmailGate<'a> {
    /// `sales_contact_points.verification`.
    verification: &'a str,
    /// `sales_contact_points.suppressed_at IS NOT NULL`.
    suppressed: bool,
}

/// Everything the per-contact gates need, reduced to plain values so the
/// precedence is unit-testable.
#[derive(Debug, Clone, Copy)]
struct ContactGateInput<'a> {
    contact_found: bool,
    email: Option<EmailGate<'a>>,
    address_suppressed: bool,
    legal_denied: bool,
    already_enrolled: bool,
}

/// Evaluate the per-contact gates in contract precedence. `None` = accepted,
/// `Some(key)` = the exact rejection reason key.
fn evaluate_contact_gates(input: ContactGateInput<'_>) -> Option<&'static str> {
    if !input.contact_found {
        return Some(rejection_reason::NOT_FOUND);
    }
    let Some(email) = input.email else {
        return Some(rejection_reason::NO_EMAIL);
    };
    if email.suppressed || input.address_suppressed {
        return Some(rejection_reason::SUPPRESSED);
    }
    if input.legal_denied {
        return Some(rejection_reason::LEGAL_POLICY);
    }
    // Accept `valid` and `risky`; reject `unverified`, `invalid` and anything
    // unrecognised (including `unknown`), because a send needs a good address.
    if !matches!(email.verification, "valid" | "risky") {
        return Some(rejection_reason::UNVERIFIED_CONTACT);
    }
    if input.already_enrolled {
        return Some(rejection_reason::ALREADY_ENROLLED);
    }
    None
}

/// Is an enrollment row in a state that blocks a new enrollment?
///
/// Terminal states may be re-enrolled; everything else is `already_enrolled`.
fn enrollment_is_live(state: &str) -> bool {
    !matches!(state, "completed" | "failed" | "suppressed")
}

/// Does moving to this state stop the normal path and therefore cancel
/// queued/leased actions for the enrollment?
fn cancels_queued_work(state: EnrollmentState) -> bool {
    // `Active` runs and `Waiting` resumes later (OOO / soft bounce); every
    // other state stops the next touch.
    !matches!(state, EnrollmentState::Active | EnrollmentState::Waiting)
}

/// The step-execution attempt kind for a step kind. `primary` is the default
/// unit of work; meeting invitations and nurture touches keep their own
/// attempt kind so their idempotency identities differ from a normal email.
fn attempt_kind_for_step_kind(kind: &str) -> &'static str {
    match kind {
        "meeting_invite" => "meeting_invite",
        "nurture" => "nurture",
        _ => "primary",
    }
}

/// How one reply disposition locks the enrollment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ReplyLockPlan {
    state: EnrollmentState,
    cancel_queued: bool,
    suppress_endpoint: bool,
    has_human_reply: bool,
}

/// The disposition-to-lock mapping. See [`lock_on_reply`] for the table.
fn reply_lock_plan(disposition: ReplyDisposition) -> ReplyLockPlan {
    let has_human_reply = disposition.stops_normal_sequence();
    match disposition {
        ReplyDisposition::Unsubscribe
        | ReplyDisposition::Complaint
        | ReplyDisposition::BounceHard => ReplyLockPlan {
            state: EnrollmentState::Suppressed,
            cancel_queued: true,
            suppress_endpoint: true,
            has_human_reply,
        },
        ReplyDisposition::Positive
        | ReplyDisposition::MeetingRequest
        | ReplyDisposition::Question
        | ReplyDisposition::Referral => ReplyLockPlan {
            state: EnrollmentState::Replied,
            cancel_queued: true,
            suppress_endpoint: false,
            has_human_reply,
        },
        ReplyDisposition::NotInterested => ReplyLockPlan {
            state: EnrollmentState::Completed,
            cancel_queued: true,
            suppress_endpoint: false,
            has_human_reply,
        },
        ReplyDisposition::OutOfOffice | ReplyDisposition::BounceSoft => ReplyLockPlan {
            state: EnrollmentState::Waiting,
            cancel_queued: false,
            suppress_endpoint: false,
            has_human_reply,
        },
        ReplyDisposition::Unknown => ReplyLockPlan {
            state: EnrollmentState::Paused,
            cancel_queued: true,
            suppress_endpoint: false,
            has_human_reply,
        },
    }
}

/// De-duplicate contact ids, keeping the first occurrence order.
fn dedup_preserving_order(ids: &[Uuid]) -> Vec<Uuid> {
    let mut seen: HashSet<Uuid> = HashSet::with_capacity(ids.len());
    let mut unique: Vec<Uuid> = Vec::with_capacity(ids.len());
    for &id in ids {
        if seen.insert(id) {
            unique.push(id);
        }
    }
    unique
}

/// The resolved `sales_jurisdiction_policies` row (global, not tenant-scoped).
#[derive(sqlx::FromRow)]
struct PolicyRow {
    channel: String,
    decision: String,
    approved_by: Option<String>,
    approved_at: Option<DateTime<Utc>>,
    valid_from: DateTime<Utc>,
    valid_until: Option<DateTime<Utc>>,
}

/// Validate the selected autonomy policy as a legal basis for outreach.
///
/// Returns `Ok(true)` when the policy's decision is `prohibited` (the caller
/// then rejects each contact with `legal_policy`), `Ok(false)` when outreach
/// may proceed. Any reason the policy is not a valid basis — missing,
/// unapproved, out of date, wrong channel, unknown decision — is
/// [`SalesError::PolicyDenied`] naming the policy.
fn policy_verdict(
    row: Option<&PolicyRow>,
    policy_id: Uuid,
    now: DateTime<Utc>,
) -> Result<bool, SalesError> {
    let Some(policy) = row else {
        return Err(SalesError::PolicyDenied(format!(
            "autonomy policy {policy_id} does not exist"
        )));
    };
    if policy.channel != "email" {
        return Err(SalesError::PolicyDenied(format!(
            "autonomy policy {policy_id} governs channel '{}', not email outreach",
            policy.channel
        )));
    }
    if policy.approved_by.is_none() || policy.approved_at.is_none() {
        return Err(SalesError::PolicyDenied(format!(
            "autonomy policy {policy_id} is not approved: an unapproved policy cannot be the \
             basis for outreach"
        )));
    }
    if policy.valid_from > now {
        return Err(SalesError::PolicyDenied(format!(
            "autonomy policy {policy_id} is not in effect until {}",
            policy.valid_from
        )));
    }
    if let Some(valid_until) = policy.valid_until {
        if valid_until <= now {
            return Err(SalesError::PolicyDenied(format!(
                "autonomy policy {policy_id} expired at {valid_until}"
            )));
        }
    }
    match policy.decision.as_str() {
        "prohibited" => Ok(true),
        // An approved, in-date `approval_required` policy is usable: the
        // authenticated operator's explicit outreach command is the approval
        // for this batch. Per-contact recorded decisions still override.
        "allowed" | "approval_required" => Ok(false),
        other => Err(SalesError::PolicyDenied(format!(
            "autonomy policy {policy_id} has unknown decision '{other}' — refusing to guess"
        ))),
    }
}

// ---------------------------------------------------------------------------
// Row types
// ---------------------------------------------------------------------------

#[derive(sqlx::FromRow)]
struct ContactRow {
    id: Uuid,
    account_id: Option<Uuid>,
    #[allow(dead_code)]
    full_name: String,
}

#[derive(sqlx::FromRow)]
struct EmailPointRow {
    contact_id: Uuid,
    id: Uuid,
    #[allow(dead_code)]
    value: String,
    normalized_value: String,
    verification: String,
    suppressed_at: Option<DateTime<Utc>>,
}

#[derive(sqlx::FromRow)]
struct EnrollmentSummaryRow {
    id: Uuid,
    sequence_name: String,
    sequence_version: i32,
    contact_name: String,
    contact_email: Option<String>,
    account_company: Option<String>,
    state: String,
    current_step_index: i32,
    enrolled_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

impl From<EnrollmentSummaryRow> for EnrollmentSummary {
    fn from(row: EnrollmentSummaryRow) -> Self {
        Self {
            id: row.id,
            sequence_name: row.sequence_name,
            sequence_version: row.sequence_version,
            contact_name: row.contact_name,
            contact_email: row.contact_email,
            account_company: row.account_company,
            state: row.state,
            current_step_index: row.current_step_index,
            enrolled_at: row.enrolled_at,
            updated_at: row.updated_at,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // Request/response contract
    // -----------------------------------------------------------------------

    #[test]
    fn start_outreach_request_is_camel_case_and_strict() {
        let json = r#"{
            "sequenceId": "11111111-1111-1111-1111-111111111111",
            "contactIds": ["22222222-2222-2222-2222-222222222222"],
            "autonomyPolicyId": "33333333-3333-3333-3333-333333333333",
            "experimentId": null
        }"#;
        let request: StartOutreachRequest = serde_json::from_str(json).unwrap();
        assert_eq!(
            request.sequence_id,
            Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap()
        );
        assert_eq!(request.contact_ids.len(), 1);
        assert!(request.experiment_id.is_none());

        // Unknown fields are rejected (deny_unknown_fields).
        let with_extra = r#"{
            "sequenceId": "11111111-1111-1111-1111-111111111111",
            "contactIds": ["22222222-2222-2222-2222-222222222222"],
            "autonomyPolicyId": "33333333-3333-3333-3333-333333333333",
            "leadIds": ["44444444-4444-4444-4444-444444444444"]
        }"#;
        assert!(serde_json::from_str::<StartOutreachRequest>(with_extra).is_err());
    }

    #[test]
    fn start_outreach_response_serializes_camel_case() {
        let mut rejection_reasons = BTreeMap::new();
        rejection_reasons.insert(rejection_reason::NO_EMAIL.to_string(), 2usize);
        let response = StartOutreachResponse {
            enrollment_batch_id: Uuid::parse_str("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa").unwrap(),
            accepted: 3,
            rejected: 2,
            rejection_reasons,
        };
        let json = serde_json::to_value(&response).unwrap();
        assert_eq!(json["accepted"], 3);
        assert_eq!(json["rejected"], 2);
        assert_eq!(json["rejectionReasons"]["no_email"], 2);
        assert_eq!(
            json["enrollmentBatchId"],
            "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
        );
        // The CP reads exactly these keys.
        assert!(json.get("enrollmentBatchId").is_some());
        assert!(json.get("rejectionReasons").is_some());
    }

    #[test]
    fn rejection_reason_keys_match_the_api_contract() {
        assert_eq!(rejection_reason::NOT_FOUND, "not_found");
        assert_eq!(rejection_reason::SUPPRESSED, "suppressed");
        assert_eq!(rejection_reason::LEGAL_POLICY, "legal_policy");
        assert_eq!(rejection_reason::UNVERIFIED_CONTACT, "unverified_contact");
        assert_eq!(rejection_reason::ALREADY_ENROLLED, "already_enrolled");
        assert_eq!(rejection_reason::NO_EMAIL, "no_email");
    }

    // -----------------------------------------------------------------------
    // De-duplication
    // -----------------------------------------------------------------------

    #[test]
    fn dedup_preserving_order_keeps_first_occurrence_order() {
        let a = Uuid::from_u128(1);
        let b = Uuid::from_u128(2);
        let c = Uuid::from_u128(3);
        assert_eq!(dedup_preserving_order(&[b, a, b, c, a]), vec![b, a, c]);
        assert!(dedup_preserving_order(&[]).is_empty());
    }

    // -----------------------------------------------------------------------
    // Per-contact gate precedence
    // -----------------------------------------------------------------------

    fn gate_input<'a>(
        contact_found: bool,
        verification: Option<&'a str>,
        suppressed: bool,
        address_suppressed: bool,
        legal_denied: bool,
        already_enrolled: bool,
    ) -> ContactGateInput<'a> {
        ContactGateInput {
            contact_found,
            email: verification.map(|verification| EmailGate {
                verification,
                suppressed,
            }),
            address_suppressed,
            legal_denied,
            already_enrolled,
        }
    }

    #[test]
    fn gate_not_found_wins_over_everything() {
        assert_eq!(
            evaluate_contact_gates(gate_input(false, None, true, true, true, true)),
            Some(rejection_reason::NOT_FOUND)
        );
    }

    #[test]
    fn gate_no_email_wins_after_not_found() {
        assert_eq!(
            evaluate_contact_gates(gate_input(true, None, false, true, true, true)),
            Some(rejection_reason::NO_EMAIL)
        );
    }

    #[test]
    fn gate_suppressed_wins_over_legal_and_verification() {
        assert_eq!(
            evaluate_contact_gates(gate_input(true, Some("invalid"), true, false, true, true)),
            Some(rejection_reason::SUPPRESSED)
        );
        // Suppression can also come from the unsubscribe/platform tables.
        assert_eq!(
            evaluate_contact_gates(gate_input(true, Some("valid"), false, true, false, false)),
            Some(rejection_reason::SUPPRESSED)
        );
    }

    #[test]
    fn gate_legal_policy_wins_over_verification() {
        assert_eq!(
            evaluate_contact_gates(gate_input(
                true,
                Some("unverified"),
                false,
                false,
                true,
                false
            )),
            Some(rejection_reason::LEGAL_POLICY)
        );
    }

    #[test]
    fn gate_unverified_rejects_unverified_invalid_and_unknown() {
        for verification in ["unverified", "invalid", "unknown", "weird"] {
            assert_eq!(
                evaluate_contact_gates(gate_input(
                    true,
                    Some(verification),
                    false,
                    false,
                    false,
                    false
                )),
                Some(rejection_reason::UNVERIFIED_CONTACT),
                "verification '{verification}' must be rejected"
            );
        }
    }

    #[test]
    fn gate_accepts_valid_and_risky_verification() {
        for verification in ["valid", "risky"] {
            assert_eq!(
                evaluate_contact_gates(gate_input(
                    true,
                    Some(verification),
                    false,
                    false,
                    false,
                    false
                )),
                None,
                "verification '{verification}' must be accepted"
            );
        }
    }

    #[test]
    fn gate_already_enrolled_only_after_quality_gates() {
        assert_eq!(
            evaluate_contact_gates(gate_input(true, Some("valid"), false, false, false, true)),
            Some(rejection_reason::ALREADY_ENROLLED)
        );
        // A fully clean contact is accepted.
        assert_eq!(
            evaluate_contact_gates(gate_input(true, Some("risky"), false, false, false, false)),
            None
        );
    }

    #[test]
    fn enrollment_is_live_excludes_only_terminal_states() {
        for terminal in ["completed", "failed", "suppressed"] {
            assert!(
                !enrollment_is_live(terminal),
                "{terminal} may be re-enrolled"
            );
        }
        for live in [
            "pending",
            "active",
            "waiting",
            "paused",
            "replied",
            "meeting_booked",
        ] {
            assert!(enrollment_is_live(live), "{live} blocks a new enrollment");
        }
    }

    // -----------------------------------------------------------------------
    // Reply lock mapping
    // -----------------------------------------------------------------------

    #[test]
    fn reply_lock_plan_matches_the_contract() {
        let cases: [(ReplyDisposition, EnrollmentState, bool, bool, bool); 11] = [
            // Unsubscribe|Complaint|BounceHard -> suppressed + unsubscribe
            (
                ReplyDisposition::Unsubscribe,
                EnrollmentState::Suppressed,
                true,
                true,
                true,
            ),
            (
                ReplyDisposition::Complaint,
                EnrollmentState::Suppressed,
                true,
                true,
                true,
            ),
            (
                ReplyDisposition::BounceHard,
                EnrollmentState::Suppressed,
                true,
                true,
                true,
            ),
            // Positive|MeetingRequest|Question|Referral -> replied
            (
                ReplyDisposition::Positive,
                EnrollmentState::Replied,
                true,
                false,
                true,
            ),
            (
                ReplyDisposition::MeetingRequest,
                EnrollmentState::Replied,
                true,
                false,
                true,
            ),
            (
                ReplyDisposition::Question,
                EnrollmentState::Replied,
                true,
                false,
                true,
            ),
            (
                ReplyDisposition::Referral,
                EnrollmentState::Replied,
                true,
                false,
                true,
            ),
            // NotInterested -> completed
            (
                ReplyDisposition::NotInterested,
                EnrollmentState::Completed,
                true,
                false,
                true,
            ),
            // OutOfOffice|BounceSoft -> waiting, no cancellation
            (
                ReplyDisposition::OutOfOffice,
                EnrollmentState::Waiting,
                false,
                false,
                false,
            ),
            (
                ReplyDisposition::BounceSoft,
                EnrollmentState::Waiting,
                false,
                false,
                false,
            ),
            // Unknown -> paused (stop next outbound pending classification)
            (
                ReplyDisposition::Unknown,
                EnrollmentState::Paused,
                true,
                false,
                true,
            ),
        ];
        for (disposition, state, cancel_queued, suppress_endpoint, has_human_reply) in cases {
            let plan = reply_lock_plan(disposition);
            assert_eq!(plan.state, state, "state for {disposition:?}");
            assert_eq!(
                plan.cancel_queued, cancel_queued,
                "cancel for {disposition:?}"
            );
            assert_eq!(
                plan.suppress_endpoint, suppress_endpoint,
                "suppress for {disposition:?}"
            );
            assert_eq!(
                plan.has_human_reply, has_human_reply,
                "has_human_reply for {disposition:?}"
            );
        }
    }

    #[test]
    fn ooo_and_soft_bounce_resume_the_sequence() {
        for disposition in [ReplyDisposition::OutOfOffice, ReplyDisposition::BounceSoft] {
            let plan = reply_lock_plan(disposition);
            assert_eq!(plan.state, EnrollmentState::Waiting);
            assert!(!plan.cancel_queued);
            assert!(!plan.has_human_reply);
            assert!(!plan.suppress_endpoint);
        }
    }

    // -----------------------------------------------------------------------
    // State transitions
    // -----------------------------------------------------------------------

    #[test]
    fn only_active_and_waiting_keep_queued_work() {
        assert!(!cancels_queued_work(EnrollmentState::Active));
        assert!(!cancels_queued_work(EnrollmentState::Waiting));
        for state in [
            EnrollmentState::Pending,
            EnrollmentState::Paused,
            EnrollmentState::Replied,
            EnrollmentState::MeetingBooked,
            EnrollmentState::Completed,
            EnrollmentState::Suppressed,
            EnrollmentState::Failed,
        ] {
            assert!(
                cancels_queued_work(state),
                "{state} must cancel queued actions"
            );
        }
    }

    #[test]
    fn attempt_kind_mapping_keeps_special_kinds_distinct() {
        assert_eq!(attempt_kind_for_step_kind("email"), "primary");
        assert_eq!(attempt_kind_for_step_kind("wait"), "primary");
        assert_eq!(
            attempt_kind_for_step_kind("meeting_invite"),
            "meeting_invite"
        );
        assert_eq!(attempt_kind_for_step_kind("nurture"), "nurture");
    }

    // -----------------------------------------------------------------------
    // Policy validation
    // -----------------------------------------------------------------------

    fn policy_row(decision: &str) -> PolicyRow {
        PolicyRow {
            channel: "email".into(),
            decision: decision.into(),
            approved_by: Some("counsel".into()),
            approved_at: Some(Utc::now() - chrono::Duration::days(1)),
            valid_from: Utc::now() - chrono::Duration::days(1),
            valid_until: None,
        }
    }

    #[test]
    fn policy_missing_is_denied() {
        let now = Utc::now();
        let err = policy_verdict(None, Uuid::new_v4(), now).unwrap_err();
        assert!(matches!(err, SalesError::PolicyDenied(_)));
        assert!(err.to_string().contains("does not exist"));
    }

    #[test]
    fn policy_unapproved_is_denied() {
        let now = Utc::now();
        let mut row = policy_row("allowed");
        row.approved_by = None;
        let err = policy_verdict(Some(&row), Uuid::new_v4(), now).unwrap_err();
        assert!(matches!(err, SalesError::PolicyDenied(_)));
        assert!(err.to_string().contains("not approved"));

        let mut row = policy_row("allowed");
        row.approved_at = None;
        let err = policy_verdict(Some(&row), Uuid::new_v4(), now).unwrap_err();
        assert!(err.to_string().contains("not approved"));
    }

    #[test]
    fn policy_out_of_date_is_denied() {
        let now = Utc::now();
        let mut row = policy_row("allowed");
        row.valid_from = now + chrono::Duration::days(1);
        assert!(policy_verdict(Some(&row), Uuid::new_v4(), now).is_err());

        let mut row = policy_row("allowed");
        row.valid_until = Some(now - chrono::Duration::seconds(1));
        let err = policy_verdict(Some(&row), Uuid::new_v4(), now).unwrap_err();
        assert!(err.to_string().contains("expired"));
    }

    #[test]
    fn policy_wrong_channel_is_denied() {
        let now = Utc::now();
        let mut row = policy_row("allowed");
        row.channel = "phone".into();
        let err = policy_verdict(Some(&row), Uuid::new_v4(), now).unwrap_err();
        assert!(err.to_string().contains("phone"));
    }

    #[test]
    fn policy_prohibited_is_reported_but_not_a_request_error() {
        let now = Utc::now();
        assert_eq!(
            policy_verdict(Some(&policy_row("prohibited")), Uuid::new_v4(), now).unwrap(),
            true
        );
        assert_eq!(
            policy_verdict(Some(&policy_row("allowed")), Uuid::new_v4(), now).unwrap(),
            false
        );
        // approval_required is usable by an explicit operator command.
        assert_eq!(
            policy_verdict(Some(&policy_row("approval_required")), Uuid::new_v4(), now).unwrap(),
            false
        );
    }

    #[test]
    fn policy_unknown_decision_fails_closed() {
        let now = Utc::now();
        let err = policy_verdict(Some(&policy_row("maybe")), Uuid::new_v4(), now).unwrap_err();
        assert!(matches!(err, SalesError::PolicyDenied(_)));
        assert!(err.to_string().contains("maybe"));
    }

    // -----------------------------------------------------------------------
    // Live-database tests (ignored by default)
    // -----------------------------------------------------------------------

    struct Fixture {
        account_id: Uuid,
        contact_id: Uuid,
        contact_point_id: Uuid,
        contact_email: String,
        sequence_id: Uuid,
        version_id: Uuid,
        #[allow(dead_code)]
        step_id: Uuid,
        policy_id: Uuid,
    }

    /// Canonically provisioned pool for the enrollment live tests.
    ///
    /// Deliberately NOT `TEST_DATABASE_URL`: that may name a legacy database
    /// whose schema the crate's guard refuses, and a test that only passes
    /// against a hand-migrated database is not testing the deployed schema.
    async fn live_pool(test_name: &str) -> Option<PgPool> {
        crate::test_db::canonical_test_pool(test_name).await
    }

    async fn seed_fixture(pool: &PgPool, tenant: &str) -> Fixture {
        let account_id = Uuid::new_v4();
        let contact_id = Uuid::new_v4();
        let contact_point_id = Uuid::new_v4();
        let sequence_id = Uuid::new_v4();
        let version_id = Uuid::new_v4();
        let step_id = Uuid::new_v4();
        let policy_id = Uuid::new_v4();
        let contact_email = format!("prospect-{contact_id}@example.com");

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
        .bind(&contact_email)
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
            "INSERT INTO sales_jurisdiction_policies \
                 (id, jurisdiction, channel, contact_type, decision, basis, version, \
                  approved_by, approved_at) \
             VALUES ($1, $2, 'email', 'b2b_professional', 'allowed', 'consent', 1, \
                     'fixture', NOW())",
        )
        .bind(policy_id)
        .bind(format!("TEST-{policy_id}"))
        .execute(pool)
        .await
        .unwrap();

        Fixture {
            account_id,
            contact_id,
            contact_point_id,
            contact_email,
            sequence_id,
            version_id,
            step_id,
            policy_id,
        }
    }

    async fn cleanup_fixture(pool: &PgPool, tenant: &str, policy_id: Uuid) {
        for statement in [
            "DELETE FROM sales_actions WHERE tenant_id = $1",
            "DELETE FROM sales_step_executions WHERE tenant_id = $1",
            "DELETE FROM sales_enrollments WHERE tenant_id = $1",
            "DELETE FROM sales_unsubscribes WHERE tenant_id = $1",
            "DELETE FROM sales_sequence_steps WHERE tenant_id = $1",
            "DELETE FROM sales_sequence_versions WHERE tenant_id = $1",
            "DELETE FROM sales_sequences WHERE tenant_id = $1",
            "DELETE FROM sales_contact_points WHERE tenant_id = $1",
            "DELETE FROM sales_contacts WHERE tenant_id = $1",
            "DELETE FROM sales_accounts WHERE tenant_id = $1",
        ] {
            sqlx::query(statement)
                .bind(tenant)
                .execute(pool)
                .await
                .unwrap();
        }
        sqlx::query("DELETE FROM sales_jurisdiction_policies WHERE id = $1")
            .bind(policy_id)
            .execute(pool)
            .await
            .unwrap();
    }

    #[ignore = "requires local PostgreSQL with the canonical sales schema"]
    #[tokio::test]
    async fn start_outreach_rerun_reports_already_enrolled_without_duplicates() {
        let Some(pool) = live_pool("outreach_rerun").await else {
            return;
        };
        let tenant = crate::test_db::unique_test_tenant("outreach");
        let fixture = seed_fixture(&pool, &tenant).await;
        let queue = ActionQueue::new(pool.clone(), format!("test-worker-{tenant}"));
        let request = StartOutreachRequest {
            sequence_id: fixture.sequence_id,
            contact_ids: vec![fixture.contact_id],
            autonomy_policy_id: fixture.policy_id,
            experiment_id: None,
        };

        let first = start_outreach(&pool, &queue, &tenant, &request)
            .await
            .unwrap();
        assert_eq!(first.accepted, 1);
        assert_eq!(first.rejected, 0);
        assert!(first.rejection_reasons.is_empty());

        // A re-run must be a no-op that reports already_enrolled.
        let second = start_outreach(&pool, &queue, &tenant, &request)
            .await
            .unwrap();
        assert_eq!(second.accepted, 0);
        assert_eq!(second.rejected, 1);
        assert_eq!(
            second
                .rejection_reasons
                .get(rejection_reason::ALREADY_ENROLLED),
            Some(&1)
        );

        let enrollments: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM sales_enrollments WHERE tenant_id = $1")
                .bind(&tenant)
                .fetch_one(&pool)
                .await
                .unwrap();
        let executions: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM sales_step_executions WHERE tenant_id = $1")
                .bind(&tenant)
                .fetch_one(&pool)
                .await
                .unwrap();
        let actions: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM sales_actions WHERE tenant_id = $1")
                .bind(&tenant)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(enrollments, 1, "no duplicate enrollment");
        assert_eq!(executions, 1, "no duplicate step execution");
        assert_eq!(actions, 1, "no duplicate queued action");

        cleanup_fixture(&pool, &tenant, fixture.policy_id).await;
    }

    #[ignore = "requires local PostgreSQL with the canonical sales schema"]
    #[tokio::test]
    async fn lock_on_reply_cancels_queued_actions_and_stops_the_sequence() {
        let Some(pool) = live_pool("reply_lock").await else {
            return;
        };
        let tenant = crate::test_db::unique_test_tenant("reply");
        let fixture = seed_fixture(&pool, &tenant).await;
        let queue = ActionQueue::new(pool.clone(), format!("test-worker-{tenant}"));

        let enrollment_id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO sales_enrollments \
                 (id, tenant_id, sequence_version_id, account_id, contact_id, contact_point_id, \
                  state, current_step_index) \
             VALUES ($1, $2, $3, $4, $5, $6, 'active', 0)",
        )
        .bind(enrollment_id)
        .bind(&tenant)
        .bind(fixture.version_id)
        .bind(fixture.account_id)
        .bind(fixture.contact_id)
        .bind(fixture.contact_point_id)
        .execute(&pool)
        .await
        .unwrap();

        let action = queue
            .enqueue(
                &tenant,
                action_type::SEND_STEP,
                entity_type::ENROLLMENT,
                enrollment_id,
                &format!("reply-test-send:{enrollment_id}"),
                serde_json::json!({}),
                Utc::now(),
                100,
                None,
            )
            .await
            .unwrap();

        lock_on_reply(
            &pool,
            &queue,
            &tenant,
            enrollment_id,
            ReplyDisposition::Positive,
        )
        .await
        .unwrap();

        let (state, has_human_reply): (String, bool) =
            sqlx::query_as("SELECT state, has_human_reply FROM sales_enrollments WHERE id = $1")
                .bind(enrollment_id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(state, "replied");
        assert!(has_human_reply, "the reply lock must be recorded");

        let action_state: String =
            sqlx::query_scalar("SELECT state FROM sales_actions WHERE id = $1")
                .bind(action.id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(
            action_state, "cancelled",
            "a queued follow-up must be cancelled by the reply lock"
        );

        // A permanent suppression disposition upserts the sales unsubscribe
        // fast path in the same enrollment lock.
        lock_on_reply(
            &pool,
            &queue,
            &tenant,
            enrollment_id,
            ReplyDisposition::Unsubscribe,
        )
        .await
        .unwrap();
        let unsubscribed: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM sales_unsubscribes \
             WHERE tenant_id = $1 AND email = lower($2)",
        )
        .bind(&tenant)
        .bind(&fixture.contact_email)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(unsubscribed, 1, "unsubscribe must be recorded");

        let final_state: String =
            sqlx::query_scalar("SELECT state FROM sales_enrollments WHERE id = $1")
                .bind(enrollment_id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(final_state, "suppressed");

        cleanup_fixture(&pool, &tenant, fixture.policy_id).await;
    }
}
