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
use crate::decision_engine::ContactPolicyInputOwned;
use crate::sequences::{load_active_version, sales_step_idempotency_key, schedule_delay_secs};
use crate::types::{ContactDecision, EnrollmentState, ReplyDisposition, SalesError};

/// The exact rejection-reason vocabulary the CP renders. These strings are an
/// API contract; do not rename them without changing the CP.
pub mod rejection_reason {
    /// No such contact in this tenant.
    pub const NOT_FOUND: &str = "not_found";
    /// The contact's email address is unsubscribed/suppressed (sales fast
    /// path, contact-point suppression, or the platform suppression list).
    pub const SUPPRESSED: &str = "suppressed";
    /// The policy resolved from the CURRENT canonical store for this contact
    /// is `prohibited`. A past `sales_contact_policy_decisions` row is never
    /// consulted: only the live policy can prohibit.
    pub const LEGAL_POLICY: &str = "legal_policy";
    /// The request's `autonomy_policy_id` is not the policy the canonical
    /// store currently resolves for this contact. The caller states what it
    /// believes applies but cannot force a stale policy; re-resolve the policy
    /// and retry. NOT used when no authoritative policy exists at all (the
    /// fail-closed `ApprovalRequired` default is not a "different" policy).
    pub const STALE_POLICY: &str = "stale_policy";
    /// The email contact point is not verified good (`valid` or `risky`).
    pub const UNVERIFIED_CONTACT: &str = "unverified_contact";
    /// A live enrollment already exists for (tenant, version, contact).
    pub const ALREADY_ENROLLED: &str = "already_enrolled";
    /// The contact has no email contact point.
    pub const NO_EMAIL: &str = "no_email";
    /// Account-level contact coordination refused this contact: the account is
    /// at its `max_active_contacts` cap, is a non-multi-thread tier, has a
    /// higher-priority persona active, is inside a negative-reply cooldown, or
    /// has a strong objection. The operator-readable verdict detail is logged;
    /// the response carries this key only.
    pub const ACCOUNT_COORDINATION: &str = "account_coordination";
    /// The account's weekly touch budget is exhausted (reservations + realised
    /// outcomes). The contact was not enrolled.
    pub const ACCOUNT_BUDGET: &str = "account_budget";
    /// Reserved wire key for "no account relation", kept because the CP
    /// renders the vocabulary. It is NOT produced by `start_outreach`: an
    /// account-less contact (a legacy campaign recipient with
    /// `account_id = NULL`) has no account-level rules or budget to apply, so
    /// coordination and the touch reservation simply do not run for it.
    pub const NO_ACCOUNT: &str = "no_account";
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
    /// DEPRECATED, advisory-only: the policy the caller BELIEVES applies to
    /// this batch. Omit it (the new contract) and the machine resolves the
    /// current policy independently PER CONTACT from the canonical
    /// `sales_jurisdiction_policies` store. This is the only correct mode for
    /// a batch spanning several jurisdictions: a single batch-level id cannot
    /// be the policy for recipients in different countries.
    ///
    /// Kept deserializable for one rolling-deploy release (the CP still sends
    /// it), and deliberately NOT silently ignored: when present, a value that
    /// is not the policy the store resolves for a contact is still rejected
    /// with `stale_policy`. A value that matches the resolved policy is
    /// accepted. There is nothing to be stale against when no authoritative
    /// policy exists, so the resolved fail-closed verdict stands alone.
    #[serde(default)]
    pub autonomy_policy_id: Option<Uuid>,
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
/// 4. `legal_policy` — the policy resolved from the CURRENT canonical
///    `sales_jurisdiction_policies` store for this contact (jurisdiction from
///    the account's country/confidence with the contact's country as
///    fallback, contact type, channel) is `prohibited`. A historical
///    `sales_contact_policy_decisions` row is never read as permission.
/// 5. `stale_policy` — the resolved policy is not `prohibited`, the request
///    supplied a (deprecated, optional) `autonomy_policy_id`, and that id is
///    not the policy row the store resolved FOR THIS CONTACT. The caller's id
///    is advisory; the machine resolves what applies. An omitted id skips this
///    check entirely — which is what makes a mixed-jurisdiction batch work:
///    every contact is resolved against its own current policy.
/// 6. `unverified_contact` — the email point's `verification` is neither
///    `valid` nor `risky`. `unknown` is therefore rejected too. `risky` is
///    accepted (reachable but lower confidence) and counted as accepted.
/// 7. `already_enrolled` — a `sales_enrollments` row for (tenant, version,
///    contact) exists in a state other than
///    `completed`/`failed`/`suppressed`. Those terminal states may be
///    re-enrolled; the upsert resets the row.
/// 8. `account_coordination` — inside the per-contact transaction, with the
///    `sales_accounts` row locked `FOR UPDATE`, the account-level contact
///    coordination rules refuse the contact: the `max_active_contacts` cap is
///    reached, the account tier does not permit multi-threading, a
///    higher-priority persona is active, the account is inside the
///    negative-reply cooldown, or a strong objection/disqualified lifecycle
///    stops the account. `max_active_contacts`, persona ordering, cooldown,
///    strong-objection stop and multi-threading all hold under concurrency
///    because the account lock serialises the decision with the enrollment
///    insert. Referral promotion (R6) has no live-path input yet: no canonical
///    column marks a contact as referred (see `account_coordination`).
/// 9. `account_budget` — the account's weekly touch budget
///    (`sales_account_touch_reservations` + realised outcomes) is exhausted;
///    `decision_engine::reserve_account_touch_tx` refused the reservation for
///    this enrollment's logical send unit.
///
/// Rules 8 and 9 apply only to contacts with an account relation. A legacy
/// campaign recipient that migrates with `sales_contacts.account_id = NULL`
/// has no account-level rules and no weekly budget to charge, so it skips
/// them and is admitted by the per-contact gates alone. (`no_account` remains
/// a rendered wire key but is not produced by this command.)
///
/// # `ApprovalRequired` is planned, not rejected (audit item 9)
///
/// An `ApprovalRequired` verdict is NOT a rejection. The enrollment is
/// accepted and planned; the first external action will come back as
/// `AwaitApproval` from the decision engine (and `revalidate_execution`
/// re-evaluates the policy under the current store immediately before the
/// send). The enrollment-time verdict is never a capability token: it is
/// advisory input to sequence planning only. Only `Prohibited` rejects a
/// contact outright. Do not attempt to enforce the approval here.
///
/// # Validation (whole request)
///
/// * `contact_ids` must hold 1..=100 entries; duplicates are de-duplicated
///   (first occurrence wins) so each contact is processed and counted once.
/// * `sequence_id` must resolve to an approved ACTIVE version (see
///   [`load_active_version`]); otherwise the call fails.
/// * `autonomy_policy_id` is deprecated and optional. When omitted, the
///   machine resolves the current policy independently per contact — the
///   required behavior for a batch spanning jurisdictions. When supplied
///   (rolling-deploy compatibility), it is verified per contact against the
///   resolved verdict (`stale_policy` on mismatch); it is never the
///   authorization itself, the canonical store decides.
///
/// # Atomicity and idempotency
///
/// Writes happen in ONE transaction per accepted contact: the account
/// coordination decision (holding the account row lock), the enrollment insert
/// (with `ON CONFLICT ... DO UPDATE` for terminal states), the weekly-budget
/// reservation for the logical send unit, the first step execution
/// (`ON CONFLICT (idempotency_key) DO NOTHING`), and the queue action
/// (`ActionQueue::enqueue_tx`, idempotent on its key). A database failure
/// while enrolling one contact rolls that contact back and returns an error;
/// contacts already committed stay enrolled, and re-running the command is a
/// no-op for them (`already_enrolled`). Re-running with the same contacts
/// therefore creates no duplicate enrollments and no duplicate actions.
/// `enrollment_batch_id` is written into every action payload so the CP can
/// correlate a run.
///
/// The touch reservation is the atomic counter in
/// `sales_account_touch_reservations` (keyed by the same logical send unit the
/// action queue uses, `sa-send:{step_execution_id}`); it runs for every
/// accepted contact that has an account relation. If anything after it in
/// the transaction fails — the step-execution insert, the action enqueue, or
/// the commit itself — the transaction rolls back and the reservation row
/// disappears with it, so a refused enrollment never consumes weekly budget
/// (`transaction_rollback_releases_touch_and_sender_reservations` asserts
/// this). A successful commit leaves the reservation live; it is settled when
/// the send happens and released on a pre-send refusal by the worker path
/// (migration 206's lifecycle).
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

    // ---------------------------------------------------------------------
    // Bulk gate inputs (one round trip each, never per contact). The legal
    // policy is NOT bulk-fetched from history: it is evaluated per contact
    // from the current canonical store below.
    // ---------------------------------------------------------------------
    // The recipient-country facts mirror the worker's `build_policy_input`:
    // `COALESCE(account.country, contact.country)` with the account's
    // confidence (a missing confidence is 0, which fails closed to UNKNOWN).
    let contacts: HashMap<Uuid, ContactRow> = sqlx::query_as::<_, ContactRow>(
        "SELECT c.id, c.account_id, c.full_name, \
                COALESCE(a.country, c.country) AS recipient_country, \
                COALESCE(a.country_confidence, 0)::float4 AS country_confidence, \
                COALESCE(a.lifecycle = 'customer', FALSE) AS has_existing_relationship \
         FROM sales_contacts c \
         LEFT JOIN sales_accounts a ON a.id = c.account_id \
         WHERE c.tenant_id = $1 AND c.id = ANY($2)",
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

        // Cheap, policy-independent gates reject first, so a contact that can
        // never be enrolled does not cost a policy evaluation.
        let cheap_gate = evaluate_pre_policy_gates(
            contact.is_some(),
            point.map(|point| EmailGate {
                suppressed: point.suppressed_at.is_some(),
            }),
            address_suppressed,
        );
        if let Some(reason) = cheap_gate {
            *rejection_reasons.entry(reason.to_string()).or_insert(0) += 1;
            rejected += 1;
            continue;
        }

        // The gates above guaranteed both are present.
        let (Some(contact), Some(point)) = (contact, point) else {
            return Err(SalesError::Internal(anyhow::anyhow!(
                "contact {contact_id} passed the existence and email gates without a row"
            )));
        };

        // Legal hard gate, re-evaluated for THIS contact from the current
        // canonical policy store. The input is recipient FACTS (mirroring the
        // worker's `build_policy_input`), never a stored verdict.
        let verdict = evaluate_contact_policy(db, tenant_id, contact, point).await?;
        let gate = policy_gate(
            verdict.decision,
            verdict.policy_id,
            request.autonomy_policy_id,
        );
        let legal_reason = match gate {
            PolicyGate::Prohibited => Some(rejection_reason::LEGAL_POLICY),
            PolicyGate::StalePolicy => Some(rejection_reason::STALE_POLICY),
            PolicyGate::Proceed => None,
        };
        if let Some(reason) = legal_reason
            .or_else(|| evaluate_post_policy_gates(point.verification.as_str(), already_enrolled))
        {
            *rejection_reasons.entry(reason.to_string()).or_insert(0) += 1;
            rejected += 1;
            continue;
        }

        // A contact without an account relation (a legacy campaign recipient
        // migrates with `account_id = NULL`) has no account-level rules or
        // budget to apply: the §38 gate has no subject. Such a contact is
        // still admitted only by the per-contact gates above; it simply
        // consumes no account slot.
        let account_id = contact.account_id;

        // ONE transaction per contact: enrollment + first step execution +
        // queued action commit together, so a failure on this contact cannot
        // corrupt another contact's already-committed enrollment.
        let mut tx = db
            .begin()
            .await
            .map_err(|e| SalesError::Database(e.to_string()))?;

        // §38 account coordination: with the account row locked `FOR UPDATE`,
        // evaluate every account-level rule before any enrollment write. The
        // lock stays in this transaction for the enrollment insert and the
        // touch reservation below, so `max_active_contacts` cannot be exceeded
        // by a concurrent request for the same account. A refusal is a
        // database-independent verdict: roll back (nothing was written), count
        // the documented reason key and move to the next contact — never a
        // hard error.
        if let Some(account_id) = account_id {
            let verdict = crate::account_coordination::request_contact_slot_locked_in_tx(
                &mut tx,
                tenant_id,
                account_id,
                contact_id,
                Utc::now(),
                false,
            )
            .await?;
            if let Some(reason) = verdict.block_reason() {
                let _ = tx.rollback().await;
                tracing::info!(
                    tenant = tenant_id,
                    account = %account_id,
                    contact = %contact_id,
                    reason = %reason,
                    "account coordination refused the contact"
                );
                *rejection_reasons
                    .entry(rejection_reason::ACCOUNT_COORDINATION.to_string())
                    .or_insert(0) += 1;
                rejected += 1;
                continue;
            }
        }

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

        let step_execution_id = Uuid::new_v4();
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
        .bind(step_execution_id)
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

        // Reserve the account's weekly touch slot in this SAME transaction and
        // under the same account lock, keyed by the logical send unit the
        // action queue uses (`sa-send:{step_execution_id}`), so the weekly
        // budget can never be double-spent by two concurrent enrollments. The
        // reservation is the decision, not a pre-check: a `false` verdict
        // means the budget is spent. Rolling back also removes the enrollment
        // and step-execution inserts above, so a budget-refused contact
        // consumes nothing. A contact without an account relation has no
        // budget to reserve and skips this step.
        let logical_send = format!("sa-send:{step_execution_id}");
        if let Some(account_id) = account_id {
            let touch_reserved = crate::decision_engine::reserve_account_touch_tx(
                &mut tx,
                tenant_id,
                account_id,
                &logical_send,
            )
            .await?;
            if !touch_reserved {
                let _ = tx.rollback().await;
                tracing::info!(
                    tenant = tenant_id,
                    account = %account_id,
                    contact = %contact_id,
                    logical_send = %logical_send,
                    "account weekly touch budget exhausted; rejecting the contact"
                );
                *rejection_reasons
                    .entry(rejection_reason::ACCOUNT_BUDGET.to_string())
                    .or_insert(0) += 1;
                rejected += 1;
                continue;
            }
        }

        let action_id = ActionQueue::enqueue_tx(
            &mut tx,
            tenant_id,
            action_type::SEND_STEP,
            entity_type::STEP_EXECUTION,
            step_execution_id,
            &logical_send,
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
struct EmailGate {
    /// `sales_contact_points.suppressed_at IS NOT NULL`.
    suppressed: bool,
}

/// Gates evaluated BEFORE the legal-policy evaluation, so a contact that can
/// never be enrolled does not cost a policy lookup. `None` = the contact may
/// proceed to the legal gate, `Some(key)` = the exact rejection reason key.
fn evaluate_pre_policy_gates(
    contact_found: bool,
    email: Option<EmailGate>,
    address_suppressed: bool,
) -> Option<&'static str> {
    if !contact_found {
        return Some(rejection_reason::NOT_FOUND);
    }
    let Some(email) = email else {
        return Some(rejection_reason::NO_EMAIL);
    };
    if email.suppressed || address_suppressed {
        return Some(rejection_reason::SUPPRESSED);
    }
    None
}

/// Gates evaluated AFTER the legal-policy verdict. `None` = accepted.
///
/// Address sendability is [`crate::decision_engine::email_point_is_sendable`],
/// the single definition shared with the live worker and approval
/// revalidation (accept `valid`/`risky`; reject `unverified`, `invalid` and
/// everything unrecognised, including `unknown`). Keeping one definition is
/// deliberate: a second copy is a second thing to keep in sync.
fn evaluate_post_policy_gates(verification: &str, already_enrolled: bool) -> Option<&'static str> {
    if !crate::decision_engine::email_point_is_sendable(verification) {
        return Some(rejection_reason::UNVERIFIED_CONTACT);
    }
    if already_enrolled {
        return Some(rejection_reason::ALREADY_ENROLLED);
    }
    None
}

/// What the per-contact legal gate concluded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PolicyGate {
    /// The current policy allows contact, or merely requires approval. The
    /// enrollment may be planned; an `ApprovalRequired` verdict becomes
    /// `AwaitApproval` at the first external action (decision engine), never
    /// an enrollment rejection.
    Proceed,
    /// The current policy prohibits contacting this person.
    Prohibited,
    /// The request supplied an `autonomy_policy_id` that is not the policy the
    /// store resolves for this contact. Never produced when the field is
    /// omitted.
    StalePolicy,
}

/// Map the resolved verdict plus the caller's believed policy id to a gate
/// result.
///
/// * `Prohibited` always prohibits — a caller naming the prohibiting policy
///   does not make the contact contactable, and a caller naming another
///   policy does not soften it.
/// * When an authoritative policy resolved (`Some(id)`) AND the request
///   supplied a believed id, the two must be exactly equal or the belief is
///   stale. An omitted believed id (the new contract) is not stale: the
///   machine's own resolution is authoritative.
/// * When NO authoritative policy exists (`policy_id == None`), the verdict is
///   the fail-closed `ApprovalRequired`; there is nothing for the caller's id
///   to be "stale" against, so the enrollment proceeds on the resolved
///   verdict alone.
fn policy_gate(
    decision: ContactDecision,
    resolved_policy_id: Option<Uuid>,
    requested_policy_id: Option<Uuid>,
) -> PolicyGate {
    match decision {
        ContactDecision::Prohibited => PolicyGate::Prohibited,
        ContactDecision::Allowed | ContactDecision::ApprovalRequired => {
            match (resolved_policy_id, requested_policy_id) {
                // The request carried a belief AND an authoritative policy
                // resolved: they must agree.
                (Some(resolved), Some(requested)) if resolved != requested => {
                    PolicyGate::StalePolicy
                }
                // No belief supplied (the new contract) or no authoritative
                // policy to compare against: the resolved verdict stands.
                _ => PolicyGate::Proceed,
            }
        }
    }
}

/// Evaluate the legal hard gate for one contact from CURRENT canonical facts.
///
/// The input mirrors the worker's `build_policy_input`: account country with
/// the contact country as fallback, the account's country confidence, the
/// canonical professional contact type, the chosen email contact point, the
/// canonical sequence source, and the account-lifecycle relationship fact.
/// Consent evidence is loaded from `sales_consent_evidence` (active row
/// newest by `collected_at`; a withdrawn row becomes
/// `consent_status = "withdrawn"`). Subscriber type has no canonical source,
/// so it fails closed to Unknown — inferring legal personality from the B2B
/// persona is forbidden — and the §103¹(2) similar-product/collection-opt-out
/// facts have no canonical source either, so they stay at the fail-closed
/// value exactly like the send path.
async fn evaluate_contact_policy(
    db: &PgPool,
    tenant_id: &str,
    contact: &ContactRow,
    point: &EmailPointRow,
) -> Result<crate::legal_policy::ContactPolicyVerdict, SalesError> {
    let consent =
        crate::legal_policy::load_consent_state(db, tenant_id, contact.id, Some(point.id)).await?;
    let input = ContactPolicyInputOwned {
        account_id: contact.account_id,
        contact_id: Some(contact.id),
        contact_point_id: Some(point.id),
        recipient_country: contact.recipient_country.clone(),
        country_confidence: contact.country_confidence,
        contact_type: "b2b_professional".to_string(),
        channel: "email".to_string(),
        source: Some("sequence".to_string()),
        purpose: Some("outbound_sales".to_string()),
        has_existing_relationship: contact.has_existing_relationship,
        consent_status: consent.status().map(str::to_string),
        soft_opt_in: false,
        legitimate_interest_assessed: true,
        // No verified subscriber-type source exists yet; Unknown fails closed
        // (do not infer the legal person from a work email).
        subscriber_type: crate::legal_policy::SubscriberType::Unknown,
        consent_evidence_id: consent.evidence_id(),
        // Account lifecycle is the canonical relationship fact; it is not a
        // per-recipient purchase record.
        existing_customer: contact.has_existing_relationship,
        // No canonical offer-to-purchase mapping exists yet.
        similar_product_basis: false,
        // No canonical collection-time opt-out record exists yet.
        collection_opt_out_offered_at: None,
    };
    crate::legal_policy::evaluate(db, &input.as_borrowed(tenant_id)).await
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

// ---------------------------------------------------------------------------
// Row types
// ---------------------------------------------------------------------------

#[derive(sqlx::FromRow)]
struct ContactRow {
    id: Uuid,
    account_id: Option<Uuid>,
    #[allow(dead_code)]
    full_name: String,
    /// `COALESCE(account.country, contact.country)` — the recipient country
    /// the policy engine resolves.
    recipient_country: Option<String>,
    /// `COALESCE(account.country_confidence, 0)`: a missing confidence fails
    /// closed to the UNKNOWN jurisdiction.
    country_confidence: f32,
    /// `account.lifecycle = 'customer'` — the relationship fact the policy
    /// engine consumes (same as the worker's `build_policy_input`).
    has_existing_relationship: bool,
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
        assert_eq!(
            request.autonomy_policy_id,
            Some(Uuid::parse_str("33333333-3333-3333-3333-333333333333").unwrap()),
            "a legacy payload still deserializes (rolling deploy)"
        );
        assert!(request.experiment_id.is_none());

        // The new contract omits autonomyPolicyId entirely: the machine
        // resolves the current policy per contact.
        let without_policy = r#"{
            "sequenceId": "11111111-1111-1111-1111-111111111111",
            "contactIds": ["22222222-2222-2222-2222-222222222222"]
        }"#;
        let request: StartOutreachRequest = serde_json::from_str(without_policy).unwrap();
        assert!(
            request.autonomy_policy_id.is_none(),
            "an omitted autonomyPolicyId must mean 'machine resolves per contact'"
        );

        // Unknown fields are rejected (deny_unknown_fields).
        let with_extra = r#"{
            "sequenceId": "11111111-1111-1111-1111-111111111111",
            "contactIds": ["22222222-2222-2222-2222-222222222222"],
            "autonomyPolicyId": "33333333-3333-3333-3333-333333333333",
            "leadIds": ["44444444-4444-4444-4444-444444444444"]
        }"#;
        assert!(serde_json::from_str::<StartOutreachRequest>(with_extra).is_err());
    }

    /// The deprecated `autonomy_policy_id` is not silently ignored: a value
    /// that contradicts the per-contact resolution is still `stale_policy`,
    /// while an omitted value accepts the machine's own resolution.
    #[test]
    fn omitted_autonomy_policy_id_is_not_stale_but_a_mismatch_still_is() {
        let resolved = Uuid::new_v4();
        let other = Uuid::new_v4();
        // Prohibited always prohibits, regardless of the belief.
        assert_eq!(
            policy_gate(ContactDecision::Prohibited, Some(resolved), None),
            PolicyGate::Prohibited
        );
        // Omitted belief: the resolved verdict stands.
        assert_eq!(
            policy_gate(ContactDecision::Allowed, Some(resolved), None),
            PolicyGate::Proceed
        );
        // No authoritative policy to compare against: omitted or supplied
        // belief both proceed on the fail-closed verdict.
        assert_eq!(
            policy_gate(ContactDecision::ApprovalRequired, None, Some(other)),
            PolicyGate::Proceed
        );
        // A supplied belief that disagrees is rejected, never ignored.
        assert_eq!(
            policy_gate(ContactDecision::Allowed, Some(resolved), Some(other)),
            PolicyGate::StalePolicy
        );
        // A supplied belief that agrees proceeds.
        assert_eq!(
            policy_gate(ContactDecision::Allowed, Some(resolved), Some(resolved)),
            PolicyGate::Proceed
        );
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
        assert_eq!(rejection_reason::STALE_POLICY, "stale_policy");
        assert_eq!(rejection_reason::UNVERIFIED_CONTACT, "unverified_contact");
        assert_eq!(rejection_reason::ALREADY_ENROLLED, "already_enrolled");
        assert_eq!(rejection_reason::NO_EMAIL, "no_email");
        // Added with the §38 production gate: the CP renders these keys.
        assert_eq!(
            rejection_reason::ACCOUNT_COORDINATION,
            "account_coordination"
        );
        assert_eq!(rejection_reason::ACCOUNT_BUDGET, "account_budget");
        assert_eq!(rejection_reason::NO_ACCOUNT, "no_account");
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

    fn pre_gate(
        contact_found: bool,
        has_email: bool,
        suppressed: bool,
        address_suppressed: bool,
    ) -> Option<&'static str> {
        evaluate_pre_policy_gates(
            contact_found,
            has_email.then_some(EmailGate { suppressed }),
            address_suppressed,
        )
    }

    #[test]
    fn gate_not_found_wins_over_everything() {
        assert_eq!(
            pre_gate(false, false, true, true),
            Some(rejection_reason::NOT_FOUND)
        );
    }

    #[test]
    fn gate_no_email_wins_after_not_found() {
        assert_eq!(
            pre_gate(true, false, false, true),
            Some(rejection_reason::NO_EMAIL)
        );
    }

    #[test]
    fn gate_suppressed_wins_over_legal_and_verification() {
        assert_eq!(
            pre_gate(true, true, true, false),
            Some(rejection_reason::SUPPRESSED)
        );
        // Suppression can also come from the unsubscribe/platform tables.
        assert_eq!(
            pre_gate(true, true, false, true),
            Some(rejection_reason::SUPPRESSED)
        );
    }

    #[test]
    fn illegal_policy_rejection_precedes_verification_and_duplicate_gates() {
        // The caller computes the legal reason first; a prohibited contact is
        // rejected with `legal_policy` even when its address is unverified and
        // an enrollment already exists.
        let legal_reason = Some(rejection_reason::LEGAL_POLICY)
            .or_else(|| evaluate_post_policy_gates("unverified", true));
        assert_eq!(legal_reason, Some(rejection_reason::LEGAL_POLICY));
    }

    #[test]
    fn gate_unverified_rejects_unverified_invalid_and_unknown() {
        for verification in ["unverified", "invalid", "unknown", "weird"] {
            assert_eq!(
                evaluate_post_policy_gates(verification, false),
                Some(rejection_reason::UNVERIFIED_CONTACT),
                "verification '{verification}' must be rejected"
            );
        }
    }

    #[test]
    fn gate_accepts_valid_and_risky_verification() {
        for verification in ["valid", "risky"] {
            assert_eq!(
                evaluate_post_policy_gates(verification, false),
                None,
                "verification '{verification}' must be accepted"
            );
        }
    }

    #[test]
    fn gate_already_enrolled_only_after_quality_gates() {
        assert_eq!(
            evaluate_post_policy_gates("valid", true),
            Some(rejection_reason::ALREADY_ENROLLED)
        );
        // A fully clean contact is accepted.
        assert_eq!(evaluate_post_policy_gates("risky", false), None);
    }

    // -----------------------------------------------------------------------
    // Current-policy gate (audit item 8)
    // -----------------------------------------------------------------------

    #[test]
    fn policy_gate_prohibited_rejects_regardless_of_requested_policy() {
        let resolved = Uuid::new_v4();
        for requested in [resolved, Uuid::new_v4()] {
            assert_eq!(
                policy_gate(ContactDecision::Prohibited, Some(resolved), Some(requested)),
                PolicyGate::Prohibited,
                "a prohibited verdict is absolute"
            );
        }
        // Even the fail-closed no-policy case cannot produce Prohibited here;
        // Prohibited always comes from a real policy row.
        assert_eq!(
            policy_gate(ContactDecision::Prohibited, None, Some(Uuid::new_v4())),
            PolicyGate::Prohibited
        );
    }

    #[test]
    fn policy_gate_requested_policy_must_match_the_resolved_policy() {
        let resolved = Uuid::new_v4();
        assert_eq!(
            policy_gate(ContactDecision::Allowed, Some(resolved), Some(resolved)),
            PolicyGate::Proceed
        );
        assert_eq!(
            policy_gate(
                ContactDecision::ApprovalRequired,
                Some(resolved),
                Some(resolved)
            ),
            PolicyGate::Proceed,
            "ApprovalRequired is planned, not rejected (audit item 9)"
        );
        let other = Uuid::new_v4();
        assert_eq!(
            policy_gate(ContactDecision::Allowed, Some(resolved), Some(other)),
            PolicyGate::StalePolicy
        );
        assert_eq!(
            policy_gate(
                ContactDecision::ApprovalRequired,
                Some(resolved),
                Some(other)
            ),
            PolicyGate::StalePolicy
        );
    }

    #[test]
    fn policy_gate_without_authoritative_policy_proceeds_on_the_verdict() {
        // No policy row resolved (unlisted jurisdiction / unapproved row):
        // the fail-closed ApprovalRequired default is not a policy the caller
        // can be "stale" against. An omitted request id also proceeds on the
        // resolved verdict (the new contract).
        assert_eq!(
            policy_gate(
                ContactDecision::ApprovalRequired,
                None,
                Some(Uuid::new_v4())
            ),
            PolicyGate::Proceed
        );
        assert_eq!(
            policy_gate(ContactDecision::ApprovalRequired, None, None),
            PolicyGate::Proceed
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
    // Live-database tests
    //
    // These follow the crate's canonical bootstrap (`test_db::canonical_test_pool`)
    // and SOFT-SKIP when no test database is configured, so they run for real
    // wherever `SALES_TEST_DATABASE_URL` points at the canonical schema.
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
        /// The `allowed`/`legitimate_interest` policy the fixture seeded for
        /// the contact's jurisdiction, when it seeded one.
        policy_id: Option<Uuid>,
        jurisdiction: String,
    }

    /// Canonically provisioned pool for the enrollment live tests.
    ///
    /// Deliberately NOT `TEST_DATABASE_URL`: that may name a legacy database
    /// whose schema the crate's guard refuses, and a test that only passes
    /// against a hand-migrated database is not testing the deployed schema.
    async fn live_pool(test_name: &str) -> Option<PgPool> {
        crate::test_db::canonical_test_pool(test_name).await
    }

    /// Pick an unused two-letter jurisdiction code that resolves to itself
    /// (not EU/EEA, whose seeded row would apply instead).
    ///
    /// The canonical database is shared across tests and runs, so the code
    /// must not collide with another policy row; the fixture deletes its own
    /// row afterwards, and an unused code makes any leftover from a crashed
    /// run harmless.
    /// Seed a working enrollment fixture.
    ///
    /// `policy`: when `Some((decision, basis))`, an approved in-date policy
    /// row for the contact's jurisdiction/channel/type is created and its id
    /// returned; when `None`, the jurisdiction has NO policy at all (the
    /// fail-closed `ApprovalRequired` case).
    async fn seed_fixture_with(
        pool: &PgPool,
        tenant: &str,
        policy: Option<(&str, &str)>,
    ) -> Fixture {
        let account_id = Uuid::new_v4();
        let contact_id = Uuid::new_v4();
        let contact_point_id = Uuid::new_v4();
        let sequence_id = Uuid::new_v4();
        let version_id = Uuid::new_v4();
        let step_id = Uuid::new_v4();

        // Resolve the policy FIRST and use the jurisdiction it actually landed
        // under as the recipient's country. The policy insert is race-tolerant
        // (the 2-letter fixture namespace is shared across parallel test
        // processes), so the code it returns is the authoritative one — writing
        // a country chosen beforehand could leave the row without a policy.
        let (policy_id, jurisdiction) = match policy {
            Some((decision, basis)) => {
                let (code, id) = crate::test_db::insert_unique_jurisdiction_policy_returning_id(
                    pool, decision, basis,
                )
                .await;
                (Some(id), code)
            }
            // The fail-closed case needs a jurisdiction guaranteed to have no
            // policy, which a randomly chosen free code cannot promise.
            None => (
                None,
                crate::test_db::ensure_no_policy_jurisdiction(pool).await,
            ),
        };

        let contact_email = format!("prospect-{contact_id}@example.com");

        sqlx::query(
            "INSERT INTO sales_accounts (id, tenant_id, company, domain, country, country_confidence) \
             VALUES ($1, $2, 'Fixture Co', $3, $4, 0.95)",
        )
        .bind(account_id)
        .bind(tenant)
        .bind(format!("{account_id}.example"))
        .bind(&jurisdiction)
        .execute(pool)
        .await
        .unwrap();

        sqlx::query(
            "INSERT INTO sales_contacts (id, tenant_id, account_id, full_name, country) \
             VALUES ($1, $2, $3, 'Fixture Prospect', $4)",
        )
        .bind(contact_id)
        .bind(tenant)
        .bind(account_id)
        .bind(&jurisdiction)
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

        Fixture {
            account_id,
            contact_id,
            contact_point_id,
            contact_email,
            sequence_id,
            version_id,
            step_id,
            policy_id,
            jurisdiction,
        }
    }

    /// The pre-audit happy path: an allowed `legitimate_interest` policy.
    async fn seed_fixture(pool: &PgPool, tenant: &str) -> Fixture {
        seed_fixture_with(pool, tenant, Some(("allowed", "legitimate_interest"))).await
    }

    async fn cleanup_fixture(pool: &PgPool, tenant: &str, policy_id: Option<Uuid>) {
        for statement in [
            "DELETE FROM sales_reply_classifications WHERE tenant_id = $1",
            "DELETE FROM sales_account_touch_reservations WHERE tenant_id = $1",
            "DELETE FROM sales_contact_policy_decisions WHERE tenant_id = $1",
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
        if let Some(policy_id) = policy_id {
            sqlx::query("DELETE FROM sales_jurisdiction_policies WHERE id = $1")
                .bind(policy_id)
                .execute(pool)
                .await
                .unwrap();
        }
    }

    /// A historical `sales_contact_policy_decisions` row saying `allowed` must
    /// NOT rescue a contact whose CURRENT policy is `prohibited`. This is the
    /// exact defect audit item 8 deletes.
    #[tokio::test]
    async fn historical_allowed_decision_does_not_rescue_a_prohibited_contact() {
        let Some(pool) = live_pool("historical_policy").await else {
            return;
        };
        let tenant = crate::test_db::unique_test_tenant("historical");
        let fixture =
            seed_fixture_with(&pool, &tenant, Some(("prohibited", "not_permitted"))).await;
        let queue = ActionQueue::new(pool.clone(), format!("test-worker-{tenant}"));

        // The stale audit history: the contact was once (wrongly) allowed.
        sqlx::query(
            "INSERT INTO sales_contact_policy_decisions \
                 (id, tenant_id, account_id, contact_id, contact_point_id, jurisdiction, \
                  decision, basis, reason, inputs) \
             VALUES (gen_random_uuid(), $1, $2, $3, $4, $5, 'allowed', 'consent', \
                     'historical row from before the policy was tightened', '{}'::jsonb)",
        )
        .bind(&tenant)
        .bind(fixture.account_id)
        .bind(fixture.contact_id)
        .bind(fixture.contact_point_id)
        .bind(&fixture.jurisdiction)
        .execute(&pool)
        .await
        .unwrap();

        let response = start_outreach(
            &pool,
            &queue,
            &tenant,
            &StartOutreachRequest {
                sequence_id: fixture.sequence_id,
                contact_ids: vec![fixture.contact_id],
                autonomy_policy_id: Some(fixture.policy_id.unwrap_or_else(Uuid::new_v4)),
                experiment_id: None,
            },
        )
        .await
        .unwrap();

        assert_eq!(response.accepted, 0, "the current policy prohibits");
        assert_eq!(response.rejected, 1);
        assert_eq!(
            response
                .rejection_reasons
                .get(rejection_reason::LEGAL_POLICY),
            Some(&1),
            "reasons: {:?}",
            response.rejection_reasons
        );
        let enrollments: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM sales_enrollments WHERE tenant_id = $1")
                .bind(&tenant)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(enrollments, 0, "no enrollment for a prohibited contact");

        cleanup_fixture(&pool, &tenant, fixture.policy_id).await;
    }

    /// A contact in a jurisdiction with no policy at all resolves to the
    /// fail-closed `ApprovalRequired` (never `Allowed`) and is accepted but
    /// gated — not rejected (audit item 9).
    #[tokio::test]
    async fn no_policy_anywhere_is_planned_under_approval_required() {
        let Some(pool) = live_pool("no_policy").await else {
            return;
        };
        let tenant = crate::test_db::unique_test_tenant("nopolicy");
        let fixture = seed_fixture_with(&pool, &tenant, None).await;
        let queue = ActionQueue::new(pool.clone(), format!("test-worker-{tenant}"));

        // The caller may believe any policy applies; with no authoritative row
        // there is nothing to be stale against, so the verdict stands alone.
        let response = start_outreach(
            &pool,
            &queue,
            &tenant,
            &StartOutreachRequest {
                sequence_id: fixture.sequence_id,
                contact_ids: vec![fixture.contact_id],
                autonomy_policy_id: Some(Uuid::new_v4()),
                experiment_id: None,
            },
        )
        .await
        .unwrap();

        assert_eq!(response.accepted, 1, "ApprovalRequired is planned");
        assert_eq!(response.rejected, 0);

        // The first action is queued; the decision engine will return
        // `AwaitApproval` for it (revalidate_execution re-evaluates the
        // policy under the current store immediately before any send).
        let actions: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM sales_actions WHERE tenant_id = $1")
                .bind(&tenant)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(
            actions, 1,
            "the enrollment must be planned, not silently dropped"
        );

        cleanup_fixture(&pool, &tenant, fixture.policy_id).await;
    }

    /// `autonomy_policy_id` naming a DIFFERENT policy than the resolved one is
    /// `stale_policy`; naming the resolved one is accepted. The same contact
    /// proves both halves.
    #[tokio::test]
    async fn autonomy_policy_id_must_match_the_resolved_policy() {
        let Some(pool) = live_pool("stale_policy").await else {
            return;
        };
        let tenant = crate::test_db::unique_test_tenant("stale");
        let fixture = seed_fixture(&pool, &tenant).await;
        let queue = ActionQueue::new(pool.clone(), format!("test-worker-{tenant}"));
        let resolved_policy_id = fixture.policy_id.expect("fixture seeds a policy");

        // A second, unrelated but real policy the caller might mistakenly name.
        // Inserted through the race-tolerant helper rather than a probe plus a
        // plain INSERT: the 2-letter namespace is shared across parallel test
        // processes, so the probe can lose the code between check and insert.
        let (_other_jurisdiction, other_policy_id) =
            crate::test_db::insert_unique_jurisdiction_policy_returning_id(
                &pool,
                "allowed",
                "legitimate_interest",
            )
            .await;

        let stale = start_outreach(
            &pool,
            &queue,
            &tenant,
            &StartOutreachRequest {
                sequence_id: fixture.sequence_id,
                contact_ids: vec![fixture.contact_id],
                autonomy_policy_id: Some(other_policy_id),
                experiment_id: None,
            },
        )
        .await
        .unwrap();
        assert_eq!(stale.accepted, 0);
        assert_eq!(
            stale.rejection_reasons.get(rejection_reason::STALE_POLICY),
            Some(&1),
            "reasons: {:?}",
            stale.rejection_reasons
        );

        // The caller cannot force the unrelated policy. The new contract
        // omits the field entirely: the machine's own resolution is accepted
        // and there is no stale comparison to lose.
        let accepted = start_outreach(
            &pool,
            &queue,
            &tenant,
            &StartOutreachRequest {
                sequence_id: fixture.sequence_id,
                contact_ids: vec![fixture.contact_id],
                autonomy_policy_id: None,
                experiment_id: None,
            },
        )
        .await
        .unwrap();
        assert_eq!(
            accepted.accepted, 1,
            "an omitted policy id accepts the machine's own resolution: {:?}",
            accepted.rejection_reasons
        );
        assert_eq!(accepted.rejected, 0);
        assert!(!accepted
            .rejection_reasons
            .contains_key(rejection_reason::STALE_POLICY));

        // Naming the resolved policy explicitly is also accepted — the contact
        // is simply already enrolled by the call above.
        let named = start_outreach(
            &pool,
            &queue,
            &tenant,
            &StartOutreachRequest {
                sequence_id: fixture.sequence_id,
                contact_ids: vec![fixture.contact_id],
                autonomy_policy_id: Some(resolved_policy_id),
                experiment_id: None,
            },
        )
        .await
        .unwrap();
        assert_eq!(named.accepted, 0);
        assert_eq!(
            named
                .rejection_reasons
                .get(rejection_reason::ALREADY_ENROLLED),
            Some(&1),
            "naming the resolved policy must not be stale: {:?}",
            named.rejection_reasons
        );

        cleanup_fixture(&pool, &tenant, fixture.policy_id).await;
        sqlx::query("DELETE FROM sales_jurisdiction_policies WHERE id = $1")
            .bind(other_policy_id)
            .execute(&pool)
            .await
            .unwrap();
    }

    /// An `approval_required` current policy is accepted (planned) even when
    /// the caller names it — item 9's enrollment-side contract.
    #[tokio::test]
    async fn approval_required_policy_is_accepted_and_gated_at_execution() {
        let Some(pool) = live_pool("approval_required_planned").await else {
            return;
        };
        let tenant = crate::test_db::unique_test_tenant("approval");
        let fixture = seed_fixture_with(
            &pool,
            &tenant,
            Some(("approval_required", "legitimate_interest")),
        )
        .await;
        let queue = ActionQueue::new(pool.clone(), format!("test-worker-{tenant}"));

        let response = start_outreach(
            &pool,
            &queue,
            &tenant,
            &StartOutreachRequest {
                sequence_id: fixture.sequence_id,
                contact_ids: vec![fixture.contact_id],
                autonomy_policy_id: Some(fixture.policy_id.expect("fixture seeds a policy")),
                experiment_id: None,
            },
        )
        .await
        .unwrap();
        assert_eq!(response.accepted, 1);
        assert_eq!(response.rejected, 0);

        cleanup_fixture(&pool, &tenant, fixture.policy_id).await;
    }

    /// `Prohibited` is rejected with `legal_policy`, even if the caller names
    /// the prohibiting policy as its "applicable" policy.
    #[tokio::test]
    async fn prohibited_current_policy_rejects_with_legal_policy() {
        let Some(pool) = live_pool("prohibited").await else {
            return;
        };
        let tenant = crate::test_db::unique_test_tenant("prohibited");
        let fixture =
            seed_fixture_with(&pool, &tenant, Some(("prohibited", "not_permitted"))).await;
        let queue = ActionQueue::new(pool.clone(), format!("test-worker-{tenant}"));

        let response = start_outreach(
            &pool,
            &queue,
            &tenant,
            &StartOutreachRequest {
                sequence_id: fixture.sequence_id,
                contact_ids: vec![fixture.contact_id],
                autonomy_policy_id: Some(fixture.policy_id.expect("fixture seeds a policy")),
                experiment_id: None,
            },
        )
        .await
        .unwrap();
        assert_eq!(response.accepted, 0);
        assert_eq!(
            response
                .rejection_reasons
                .get(rejection_reason::LEGAL_POLICY),
            Some(&1)
        );

        cleanup_fixture(&pool, &tenant, fixture.policy_id).await;
    }

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
            autonomy_policy_id: Some(fixture.policy_id.expect("fixture seeds a policy")),
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

    // -----------------------------------------------------------------------
    // §38 coordination + weekly budget on the live enrollment path
    // -----------------------------------------------------------------------

    /// A multi-contact account fixture for the coordination/budget tests.
    struct OutreachFixture {
        account_id: Uuid,
        sequence_id: Uuid,
        policy_id: Uuid,
        contact_ids: Vec<Uuid>,
    }

    /// Seed one account with `contacts` contacts (all `valid` emails), an
    /// approved `allowed`/`legitimate_interest` policy, and an active sequence.
    async fn seed_outreach_fixture(
        pool: &PgPool,
        tenant: &str,
        contacts: usize,
        max_active_contacts: i16,
        multi_thread_allowed: bool,
        cooldown_hours: i32,
    ) -> OutreachFixture {
        let (jurisdiction, policy_id) =
            crate::test_db::insert_unique_jurisdiction_policy_returning_id(
                pool,
                "allowed",
                "legitimate_interest",
            )
            .await;

        let account_id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO sales_accounts \
                 (id, tenant_id, company, domain, country, country_confidence, \
                  max_active_contacts, multi_thread_allowed, negative_reply_cooldown_hours) \
             VALUES ($1, $2, 'Coordination Co', $3, $4, 0.95, $5, $6, $7)",
        )
        .bind(account_id)
        .bind(tenant)
        .bind(format!("{account_id}.example"))
        .bind(&jurisdiction)
        .bind(max_active_contacts)
        .bind(multi_thread_allowed)
        .bind(cooldown_hours)
        .execute(pool)
        .await
        .unwrap();

        let mut contact_ids = Vec::with_capacity(contacts);
        for _ in 0..contacts {
            let contact_id = Uuid::new_v4();
            sqlx::query(
                "INSERT INTO sales_contacts (id, tenant_id, account_id, full_name, country) \
                 VALUES ($1, $2, $3, 'Coordination Prospect', $4)",
            )
            .bind(contact_id)
            .bind(tenant)
            .bind(account_id)
            .bind(&jurisdiction)
            .execute(pool)
            .await
            .unwrap();
            sqlx::query(
                "INSERT INTO sales_contact_points \
                     (id, tenant_id, contact_id, channel, value, normalized_value, verification) \
                 VALUES ($1, $2, $3, 'email', $4, lower($4), 'valid')",
            )
            .bind(Uuid::new_v4())
            .bind(tenant)
            .bind(contact_id)
            .bind(format!("prospect-{contact_id}@example.com"))
            .execute(pool)
            .await
            .unwrap();
            contact_ids.push(contact_id);
        }

        let sequence_id = Uuid::new_v4();
        let version_id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO sales_sequences (id, tenant_id, name, status) \
             VALUES ($1, $2, 'Coordination Sequence', 'active')",
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
        .bind(Uuid::new_v4())
        .bind(tenant)
        .bind(version_id)
        .execute(pool)
        .await
        .unwrap();

        OutreachFixture {
            account_id,
            sequence_id,
            policy_id,
            contact_ids,
        }
    }

    async fn insert_active_enrollment(
        pool: &PgPool,
        tenant: &str,
        account_id: Uuid,
        sequence_id: Uuid,
        contact_id: Uuid,
    ) -> Uuid {
        let version_id: Uuid = sqlx::query_scalar(
            "SELECT id FROM sales_sequence_versions WHERE sequence_id = $1 AND tenant_id = $2",
        )
        .bind(sequence_id)
        .bind(tenant)
        .fetch_one(pool)
        .await
        .unwrap();
        let enrollment_id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO sales_enrollments \
                 (id, tenant_id, sequence_version_id, account_id, contact_id, state) \
             VALUES ($1, $2, $3, $4, $5, 'active')",
        )
        .bind(enrollment_id)
        .bind(tenant)
        .bind(version_id)
        .bind(account_id)
        .bind(contact_id)
        .execute(pool)
        .await
        .unwrap();
        enrollment_id
    }

    async fn account_persona(pool: &PgPool, tenant: &str, contact_id: Uuid, persona: &str) {
        sqlx::query("UPDATE sales_contacts SET persona = $3 WHERE id = $1 AND tenant_id = $2")
            .bind(contact_id)
            .bind(tenant)
            .bind(persona)
            .execute(pool)
            .await
            .unwrap();
    }

    async fn insert_reply_classification(
        pool: &PgPool,
        tenant: &str,
        enrollment_id: Uuid,
        contact_id: Uuid,
        disposition: &str,
    ) {
        sqlx::query(
            "INSERT INTO sales_reply_classifications \
                 (id, tenant_id, enrollment_id, contact_id, disposition, classifier) \
             VALUES (gen_random_uuid(), $1, $2, $3, $4, 'deterministic')",
        )
        .bind(tenant)
        .bind(enrollment_id)
        .bind(contact_id)
        .bind(disposition)
        .execute(pool)
        .await
        .unwrap();
    }

    /// An accepted enrollment reserves exactly one weekly touch slot, keyed by
    /// the same logical send unit the action queue uses.
    #[tokio::test]
    async fn accepted_enrollment_reserves_the_account_touch_slot() {
        let Some(pool) = live_pool("touch_reservation").await else {
            return;
        };
        let tenant = crate::test_db::unique_test_tenant("touch");
        let fixture = seed_outreach_fixture(&pool, &tenant, 1, 2, false, 0).await;
        let queue = ActionQueue::new(pool.clone(), format!("test-worker-{tenant}"));

        let response = start_outreach(
            &pool,
            &queue,
            &tenant,
            &StartOutreachRequest {
                sequence_id: fixture.sequence_id,
                contact_ids: vec![fixture.contact_ids[0]],
                autonomy_policy_id: Some(fixture.policy_id),
                experiment_id: None,
            },
        )
        .await
        .unwrap();
        assert_eq!(response.accepted, 1, "{:?}", response.rejection_reasons);
        assert_eq!(response.rejected, 0);

        let reservations: Vec<(String, String)> = sqlx::query_as(
            "SELECT logical_send, state FROM sales_account_touch_reservations \
             WHERE account_id = $1 AND tenant_id = $2",
        )
        .bind(fixture.account_id)
        .bind(&tenant)
        .fetch_all(&pool)
        .await
        .unwrap();
        assert_eq!(reservations.len(), 1, "exactly one touch slot reserved");
        let (logical_send, state) = &reservations[0];
        assert_eq!(state, "reserved", "the slot must be live until the send");
        assert!(
            logical_send.starts_with("sa-send:"),
            "the logical send unit is the queue key: {logical_send}"
        );

        let action_key: String =
            sqlx::query_scalar("SELECT idempotency_key FROM sales_actions WHERE tenant_id = $1")
                .bind(&tenant)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(
            &action_key, logical_send,
            "the reservation and the queued action must share one logical send unit"
        );

        cleanup_fixture(&pool, &tenant, Some(fixture.policy_id)).await;
    }

    /// Budget = 1 (14 of the 15 weekly slots pre-consumed) with 16 concurrent
    /// enrollment attempts for the same account: exactly one is accepted and
    /// the other fifteen are rejected with `account_budget`. The reservation
    /// is the decision, so the account lock serialises the attempts.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn budget_of_one_admits_exactly_one_of_sixteen_concurrent_enrollments() {
        let Some(pool) = live_pool("budget_race").await else {
            return;
        };
        let tenant = crate::test_db::unique_test_tenant("budgetrace");
        // max_active_contacts = 3 keeps the weekly budget at
        // max(15, 3 * 5) = 15 while allowing several concurrent threads.
        let fixture = seed_outreach_fixture(&pool, &tenant, 16, 3, true, 0).await;

        // Consume fourteen slots, leaving exactly one. `settled` rows count the
        // same as live reservations (migration 206: reservations + outcomes).
        for index in 0..14 {
            sqlx::query(
                "INSERT INTO sales_account_touch_reservations \
                     (account_id, logical_send, tenant_id, state) \
                 VALUES ($1, $2, $3, 'reserved')",
            )
            .bind(fixture.account_id)
            .bind(format!("preconsumed-{index}"))
            .bind(&tenant)
            .execute(&pool)
            .await
            .unwrap();
        }

        let mut handles = Vec::new();
        for contact_id in &fixture.contact_ids {
            let pool = pool.clone();
            let tenant = tenant.clone();
            let sequence_id = fixture.sequence_id;
            let policy_id = fixture.policy_id;
            let contact_id = *contact_id;
            handles.push(tokio::spawn(async move {
                let queue = ActionQueue::new(pool.clone(), format!("budget-race-{contact_id}"));
                start_outreach(
                    &pool,
                    &queue,
                    &tenant,
                    &StartOutreachRequest {
                        sequence_id,
                        contact_ids: vec![contact_id],
                        autonomy_policy_id: Some(policy_id),
                        experiment_id: None,
                    },
                )
                .await
            }));
        }

        let results = futures::future::join_all(handles).await;
        let mut accepted = 0usize;
        let mut rejected = 0usize;
        let mut budget_rejections = 0usize;
        for result in results {
            let response = result
                .expect("enrollment task must not panic")
                .expect("the command itself must succeed");
            assert!(
                response
                    .rejection_reasons
                    .keys()
                    .all(|key| key.as_str() == rejection_reason::ACCOUNT_BUDGET),
                "every rejection must be the budget reason: {:?}",
                response.rejection_reasons
            );
            accepted += response.accepted;
            rejected += response.rejected;
            budget_rejections += response
                .rejection_reasons
                .get(rejection_reason::ACCOUNT_BUDGET)
                .copied()
                .unwrap_or(0);
        }
        assert_eq!(accepted, 1, "exactly one attempt may take the last slot");
        assert_eq!(rejected, 15, "every other attempt must be refused");
        assert_eq!(budget_rejections, 15);

        let reservations: i64 = sqlx::query_scalar(
            "SELECT COUNT(*)::bigint FROM sales_account_touch_reservations \
             WHERE account_id = $1 AND tenant_id = $2",
        )
        .bind(fixture.account_id)
        .bind(&tenant)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(reservations, 15, "14 pre-consumed + 1 admitted");
        let enrollments: i64 = sqlx::query_scalar(
            "SELECT COUNT(*)::bigint FROM sales_enrollments WHERE tenant_id = $1",
        )
        .bind(&tenant)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(enrollments, 1, "budget-refused contacts must not enroll");

        cleanup_fixture(&pool, &tenant, Some(fixture.policy_id)).await;
    }

    /// The contact cap is a live gate: with `max_active_contacts = 2` and
    /// three active contacts, a fourth is refused on the enrollment path with
    /// the documented reason key, and the operator-readable verdict names the
    /// cap.
    #[tokio::test]
    async fn contact_cap_denies_the_fourth_contact_on_the_enrollment_path() {
        let Some(pool) = live_pool("coordination_cap").await else {
            return;
        };
        let tenant = crate::test_db::unique_test_tenant("coordcap");
        let fixture = seed_outreach_fixture(&pool, &tenant, 4, 2, true, 0).await;
        for contact_id in &fixture.contact_ids[..3] {
            insert_active_enrollment(
                &pool,
                &tenant,
                fixture.account_id,
                fixture.sequence_id,
                *contact_id,
            )
            .await;
        }

        let fourth = fixture.contact_ids[3];
        let queue = ActionQueue::new(pool.clone(), format!("test-worker-{tenant}"));
        let response = start_outreach(
            &pool,
            &queue,
            &tenant,
            &StartOutreachRequest {
                sequence_id: fixture.sequence_id,
                contact_ids: vec![fourth],
                autonomy_policy_id: Some(fixture.policy_id),
                experiment_id: None,
            },
        )
        .await
        .unwrap();
        assert_eq!(response.accepted, 0);
        assert_eq!(response.rejected, 1);
        assert_eq!(
            response
                .rejection_reasons
                .get(rejection_reason::ACCOUNT_COORDINATION),
            Some(&1),
            "the denial must be visible in the response: {:?}",
            response.rejection_reasons
        );

        // The verdict itself is operator-readable ("cap reached (3 of 2 ...)").
        let mut tx = pool.begin().await.unwrap();
        let verdict = crate::account_coordination::request_contact_slot_locked_in_tx(
            &mut tx,
            &tenant,
            fixture.account_id,
            fourth,
            Utc::now(),
            false,
        )
        .await
        .unwrap();
        match verdict {
            crate::account_coordination::CoordinationVerdict::Denied(reason) => {
                assert!(reason.contains("cap"), "reason must name the cap: {reason}");
            }
            other => panic!("expected Denied, got {other:?}"),
        }
        tx.rollback().await.unwrap();

        let enrollments: i64 = sqlx::query_scalar(
            "SELECT COUNT(*)::bigint FROM sales_enrollments WHERE tenant_id = $1",
        )
        .bind(&tenant)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(enrollments, 3, "the denied contact must not enroll");

        cleanup_fixture(&pool, &tenant, Some(fixture.policy_id)).await;
    }

    /// A referral is allowed past the cap only at a multi-threading tier; at a
    /// single-thread tier the same request is refused. Exercises the live
    /// database path (the function the enrollment command calls), not the pure
    /// decision function alone.
    #[tokio::test]
    async fn referral_promotion_is_enforced_by_the_live_database_path() {
        let Some(pool) = live_pool("referral_promotion").await else {
            return;
        };
        let tenant = crate::test_db::unique_test_tenant("referral");
        let fixture = seed_outreach_fixture(&pool, &tenant, 2, 1, true, 0).await;
        insert_active_enrollment(
            &pool,
            &tenant,
            fixture.account_id,
            fixture.sequence_id,
            fixture.contact_ids[0],
        )
        .await;
        let referred = fixture.contact_ids[1];

        // multi_thread_allowed = true: the referral passes the cap.
        let mut tx = pool.begin().await.unwrap();
        let verdict = crate::account_coordination::request_contact_slot_locked_in_tx(
            &mut tx,
            &tenant,
            fixture.account_id,
            referred,
            Utc::now(),
            true,
        )
        .await
        .unwrap();
        assert!(
            verdict.is_allowed(),
            "a referral at a multi-threading tier must pass the cap, got {verdict:?}"
        );
        tx.rollback().await.unwrap();

        // multi_thread_allowed = false: the same referral is refused.
        sqlx::query("UPDATE sales_accounts SET multi_thread_allowed = FALSE WHERE id = $1")
            .bind(fixture.account_id)
            .execute(&pool)
            .await
            .unwrap();
        let mut tx = pool.begin().await.unwrap();
        let verdict = crate::account_coordination::request_contact_slot_locked_in_tx(
            &mut tx,
            &tenant,
            fixture.account_id,
            referred,
            Utc::now(),
            true,
        )
        .await
        .unwrap();
        match verdict {
            crate::account_coordination::CoordinationVerdict::Denied(reason) => {
                assert!(
                    reason.contains("multi-threading"),
                    "reason must name the tier rule: {reason}"
                );
            }
            other => panic!("expected Denied, got {other:?}"),
        }
        tx.rollback().await.unwrap();

        cleanup_fixture(&pool, &tenant, Some(fixture.policy_id)).await;
    }

    /// Persona ordering, negative-reply cooldown and the strong-objection stop
    /// are all evaluated from live state by the path `start_outreach` uses.
    #[tokio::test]
    async fn persona_cooldown_and_strong_objection_hold_on_the_live_path() {
        let Some(pool) = live_pool("coordination_rules_live").await else {
            return;
        };
        let tenant = crate::test_db::unique_test_tenant("coordrules");
        let fixture = seed_outreach_fixture(&pool, &tenant, 3, 3, true, 24).await;
        account_persona(&pool, &tenant, fixture.contact_ids[0], "CEO").await;
        account_persona(&pool, &tenant, fixture.contact_ids[1], "Engineer").await;
        account_persona(&pool, &tenant, fixture.contact_ids[2], "CEO").await;
        let incumbent = insert_active_enrollment(
            &pool,
            &tenant,
            fixture.account_id,
            fixture.sequence_id,
            fixture.contact_ids[0],
        )
        .await;

        // R3: an individual contributor cannot displace the active CEO.
        let queue = ActionQueue::new(pool.clone(), format!("test-worker-{tenant}"));
        let persona_response = start_outreach(
            &pool,
            &queue,
            &tenant,
            &StartOutreachRequest {
                sequence_id: fixture.sequence_id,
                contact_ids: vec![fixture.contact_ids[1]],
                autonomy_policy_id: Some(fixture.policy_id),
                experiment_id: None,
            },
        )
        .await
        .unwrap();
        assert_eq!(
            persona_response
                .rejection_reasons
                .get(rejection_reason::ACCOUNT_COORDINATION),
            Some(&1),
            "persona ordering must reject: {:?}",
            persona_response.rejection_reasons
        );

        // R2: a negative reply starts the cooldown; a same-rank CEO is deferred.
        insert_reply_classification(
            &pool,
            &tenant,
            incumbent,
            fixture.contact_ids[0],
            "not_interested",
        )
        .await;
        let cooldown_response = start_outreach(
            &pool,
            &queue,
            &tenant,
            &StartOutreachRequest {
                sequence_id: fixture.sequence_id,
                contact_ids: vec![fixture.contact_ids[2]],
                autonomy_policy_id: Some(fixture.policy_id),
                experiment_id: None,
            },
        )
        .await
        .unwrap();
        assert_eq!(
            cooldown_response
                .rejection_reasons
                .get(rejection_reason::ACCOUNT_COORDINATION),
            Some(&1),
            "the cooldown must reject: {:?}",
            cooldown_response.rejection_reasons
        );
        let verdict = crate::account_coordination::request_contact_slot(
            &pool,
            &tenant,
            fixture.account_id,
            fixture.contact_ids[2],
            Utc::now(),
        )
        .await
        .unwrap();
        assert!(
            matches!(
                verdict,
                crate::account_coordination::CoordinationVerdict::Deferred { .. }
            ),
            "expected Deferred, got {verdict:?}"
        );

        // R1: a strong objection stops the account even with a free persona.
        insert_reply_classification(
            &pool,
            &tenant,
            incumbent,
            fixture.contact_ids[0],
            "unsubscribe",
        )
        .await;
        let verdict = crate::account_coordination::request_contact_slot(
            &pool,
            &tenant,
            fixture.account_id,
            fixture.contact_ids[2],
            Utc::now(),
        )
        .await
        .unwrap();
        match verdict {
            crate::account_coordination::CoordinationVerdict::Denied(reason) => {
                assert!(reason.contains("strong objection"), "reason: {reason}");
            }
            other => panic!("expected Denied, got {other:?}"),
        }

        cleanup_fixture(&pool, &tenant, Some(fixture.policy_id)).await;
    }

    /// A transaction that rolls back releases BOTH reservations it made: the
    /// account touch slot and the sender daily capacity. This is the guarantee
    /// that a failed enrollment consumes neither the weekly budget nor a
    /// sender's day.
    #[ignore = "live Postgres: set SALES_TEST_DATABASE_URL"]
    #[tokio::test]
    async fn transaction_rollback_releases_touch_and_sender_reservations() {
        let Some(pool) = live_pool("reservation_rollback").await else {
            return;
        };
        let tenant = crate::test_db::unique_test_tenant("rollback");
        let fixture = seed_outreach_fixture(&pool, &tenant, 1, 2, true, 0).await;

        let sender_id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO sales_sender_identities \
                 (id, tenant_id, pool, from_email, from_name, domain, status, daily_limit) \
             VALUES ($1, $2, 'sales_outbound', $3, 'Fixture Sender', 'fixture.example', \
                     'active', 5)",
        )
        .bind(sender_id)
        .bind(&tenant)
        .bind(format!("rollback-{sender_id}@fixture.example"))
        .execute(&pool)
        .await
        .unwrap();
        let usage_day = crate::sender_pool::utc_usage_day(Utc::now());

        let mut tx = pool.begin().await.unwrap();
        // The live-path account lock, as start_outreach takes it.
        sqlx::query("SELECT id FROM sales_accounts WHERE id = $1 AND tenant_id = $2 FOR UPDATE")
            .bind(fixture.account_id)
            .bind(&tenant)
            .fetch_one(&mut *tx)
            .await
            .unwrap();
        let touch_reserved = crate::decision_engine::reserve_account_touch_tx(
            &mut tx,
            &tenant,
            fixture.account_id,
            "sa-send:rollback-fixture",
        )
        .await
        .unwrap();
        assert!(touch_reserved, "the account has budget for one touch");
        let capacity_reserved = crate::sender_pool::reserve_sender_capacity_in_tx(
            &mut tx,
            sender_id,
            usage_day,
            Some(5),
        )
        .await
        .unwrap();
        assert!(capacity_reserved);

        // Both are visible inside the transaction...
        let touch_inside: i64 = sqlx::query_scalar(
            "SELECT COUNT(*)::bigint FROM sales_account_touch_reservations \
             WHERE account_id = $1 AND tenant_id = $2",
        )
        .bind(fixture.account_id)
        .bind(&tenant)
        .fetch_one(&mut *tx)
        .await
        .unwrap();
        assert_eq!(touch_inside, 1);
        let sent_inside: i32 = sqlx::query_scalar(
            "SELECT sent FROM sales_sender_daily_usage \
             WHERE sender_identity_id = $1 AND usage_day = $2",
        )
        .bind(sender_id)
        .bind(usage_day)
        .fetch_one(&mut *tx)
        .await
        .unwrap();
        assert_eq!(sent_inside, 1);

        // ...and both are gone after the rollback.
        tx.rollback().await.unwrap();
        let touches_after: i64 = sqlx::query_scalar(
            "SELECT COUNT(*)::bigint FROM sales_account_touch_reservations \
             WHERE account_id = $1 AND tenant_id = $2",
        )
        .bind(fixture.account_id)
        .bind(&tenant)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(
            touches_after, 0,
            "a rolled-back enrollment must not consume the weekly budget"
        );
        let usage_rows: i64 = sqlx::query_scalar(
            "SELECT COUNT(*)::bigint FROM sales_sender_daily_usage \
             WHERE sender_identity_id = $1",
        )
        .bind(sender_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(
            usage_rows, 0,
            "a rolled-back transaction must release the sender capacity reservation"
        );

        sqlx::query("DELETE FROM sales_sender_identities WHERE id = $1")
            .bind(sender_id)
            .execute(&pool)
            .await
            .unwrap();
        cleanup_fixture(&pool, &tenant, Some(fixture.policy_id)).await;
    }
}
