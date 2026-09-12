//! The central decision gate and the Decision Packet.
//!
//! Every automated external action must go through [`decide`]. It evaluates
//! each hard constraint in a fixed order, records **every** failure reason,
//! persists exactly one `sales_decisions` row (including denials and shadowed
//! decisions) carrying the enforcement verdict, the selected sender reference
//! and the operator-review state, and returns the enforcement verdict.
//!
//! Approval is never a bypass: immediately before an external effect is
//! produced, [`revalidate_execution`] re-runs every hard gate for an existing
//! decision, so an unsubscribe, a human reply, a legal-policy change or a
//! newly quarantined sender still stops a send that was decided (or approved)
//! earlier.
//!
//! Release gates this module implements:
//!
//! * **100% of external sales messages map to a `sales_decision`.** Every
//!   sales route — the live sequence worker included — builds its send through
//!   [`decide`] instead of an inline copy of the gates; the decision id is
//!   attached to the queued action and the packet stores the enforcement
//!   verdict the worker acts on.
//! * **Legal-policy denial is impossible to bypass through another sales
//!   route.** Every external decision re-evaluates the legal policy from the
//!   current canonical store — a verdict supplied by a caller is never
//!   trusted — and a missing input fails closed; the resolved policy uuid is
//!   stored on the packet, and [`revalidate_execution`] repeats the evaluation
//!   before the send.
//! * **An approval cannot resurrect a gate that changed.** An operator
//!   approval is permission to proceed, not an indefinite capability token:
//!   [`revalidate_execution`] re-runs every hard gate immediately before the
//!   external effect, so an approval recorded minutes ago does not defeat an
//!   unsubscribe, a human reply, a legal-policy change or a newly quarantined
//!   sender.
//! * **100% of human replies prevent subsequent normal sequence sends.** A
//!   `sales_enrollments.has_human_reply` row denies the next touch even when
//!   the action row was already queued.
//! * **The global kill switch prevents new outbound actions immediately while
//!   preserving data and inbound reply processing.** `decide` records and
//!   denies; nothing is deleted, and read/inbound paths remain untouched.
//!
//! Gate order (all reasons are kept, not just the first):
//!
//! 1. global kill switch
//! 2. autonomy mode `disabled`
//! 3. suppression (`sales_unsubscribes` ∪ platform `suppressions`)
//! 4. contact point verification not sendable (only `valid`/`risky` pass;
//!    see [`email_point_is_sendable`])
//! 5. legal policy, re-evaluated from the current canonical store:
//!    `prohibited` denies; `approval_required` forces a human; no policy input
//!    at all fails closed
//! 6. enrollment already has a human reply
//! 7. sender-health gate
//! 8. per-account weekly frequency budget (a reservation, not a check)
//! 9. contact point `suppressed_at`
//!
//! The autonomy state is loaded inline from `sales_autonomy_state` (the
//! `crate::autonomy` module is written in parallel); no row fails closed to
//! `disabled`.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{PgConnection, PgPool, Postgres, Transaction};
use uuid::Uuid;

use crate::legal_policy::{self, ContactPolicyInput, SubscriberType};
use crate::sender_health;
use crate::types::{
    AutonomyMode, AutonomyState, ContactDecision, DecisionAction, Enforcement, JurisdictionPolicy,
    OpportunityScore, SalesError,
};

/// Default weekly per-account touch budget when the account has no explicit
/// policy. Rationale: automation must never independently hammer one company.
/// An account's own budget is `max(DEFAULT_WEEKLY_ACCOUNT_BUDGET,
/// max_active_contacts * WEEKLY_BUDGET_PER_ACTIVE_CONTACT)` so multi-threaded
/// accounts get proportionally more room.
pub const DEFAULT_WEEKLY_ACCOUNT_BUDGET: i64 = 15;

/// Additional weekly touches granted per active contact slot on an account.
pub const WEEKLY_BUDGET_PER_ACTIVE_CONTACT: i64 = 5;

impl Enforcement {
    /// The wire string persisted in `sales_decisions.enforcement`. These four
    /// values are exactly the ones accepted by the migration-201 CHECK
    /// constraint `chk_sales_decisions_enforcement`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Execute => "execute",
            Self::AwaitApproval => "await_approval",
            Self::Shadowed => "shadowed",
            Self::Denied => "denied",
        }
    }

    /// Parse a persisted enforcement value. An unknown value is `None` so the
    /// caller can fail closed instead of guessing a verdict the worker's match
    /// arms do not handle.
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "execute" => Some(Self::Execute),
            "await_approval" => Some(Self::AwaitApproval),
            "shadowed" => Some(Self::Shadowed),
            "denied" => Some(Self::Denied),
            _ => None,
        }
    }
}

/// The `sales_decisions.review_status` value a verdict requires.
///
/// Only a verdict that awaits a human goes into the operator queue; a denied,
/// shadowed or executing verdict requires no review (marking those `pending`
/// would flood the queue with decisions that need no human).
pub fn review_status_for(enforcement: Enforcement) -> Option<&'static str> {
    match enforcement {
        Enforcement::AwaitApproval => Some("pending"),
        Enforcement::Denied | Enforcement::Shadowed | Enforcement::Execute => Some("not_required"),
    }
}

/// Is this contact-point verification state sendable?
///
/// The single definition used by enrollment, the live worker and approval
/// revalidation: `verification IN ('valid', 'risky')`. `unknown`, `unverified`
/// and `invalid` are all refused, so a contact point that regresses from
/// `valid` to any other state is stopped by every gate that consults this
/// function rather than only by the literal `invalid` case.
pub fn email_point_is_sendable(verification: &str) -> bool {
    matches!(verification, "valid" | "risky")
}

/// Everything one decision needs. Built by callers from the canonical tables.
#[derive(Debug, Clone)]
pub struct DecisionContext {
    pub tenant_id: String,
    pub account_id: Option<Uuid>,
    pub contact_id: Option<Uuid>,
    pub contact_point_id: Option<Uuid>,
    pub enrollment_id: Option<Uuid>,
    pub action: DecisionAction,
    pub score: OpportunityScore,
    pub expected_value_eur: f64,
    pub confidence: f32,
    pub evidence_ids: Vec<Uuid>,
    pub selected_offer: Option<String>,
    pub selected_sequence: Option<String>,
    pub selected_variant: Option<String>,
    pub selected_sender: Option<Uuid>,
    pub model_version: Option<String>,
    /// Owned form of the legal-policy input. Required for external sends;
    /// when absent an external action fails closed.
    pub policy: Option<ContactPolicyInputOwned>,
    pub rationale: String,
    pub execute_after: Option<DateTime<Utc>>,
}

/// Owned counterpart of [`ContactPolicyInput`], so a [`DecisionContext`] can
/// be built, queued and moved without lifetime plumbing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContactPolicyInputOwned {
    pub account_id: Option<Uuid>,
    pub contact_id: Option<Uuid>,
    pub contact_point_id: Option<Uuid>,
    pub recipient_country: Option<String>,
    pub country_confidence: f32,
    pub contact_type: String,
    pub channel: String,
    pub source: Option<String>,
    pub purpose: Option<String>,
    pub has_existing_relationship: bool,
    pub consent_status: Option<String>,
    pub soft_opt_in: bool,
    pub legitimate_interest_assessed: bool,
    /// Authoritative subscriber classification (§103¹). `#[serde(default)]`
    /// so a decision packet recorded before this field existed deserializes
    /// to the fail-closed `Unknown` instead of becoming unreadable.
    #[serde(default)]
    pub subscriber_type: SubscriberType,
    /// Active `sales_consent_evidence` row evidencing consent.
    #[serde(default)]
    pub consent_evidence_id: Option<Uuid>,
    #[serde(default)]
    pub existing_customer: bool,
    #[serde(default)]
    pub similar_product_basis: bool,
    #[serde(default)]
    pub collection_opt_out_offered_at: Option<DateTime<Utc>>,
}

impl ContactPolicyInputOwned {
    /// Borrow this owned input for [`legal_policy::evaluate`].
    pub fn as_borrowed<'a>(&'a self, tenant_id: &'a str) -> ContactPolicyInput<'a> {
        ContactPolicyInput {
            tenant_id,
            account_id: self.account_id,
            contact_id: self.contact_id,
            contact_point_id: self.contact_point_id,
            recipient_country: self.recipient_country.clone(),
            country_confidence: self.country_confidence,
            contact_type: &self.contact_type,
            channel: &self.channel,
            source: self.source.as_deref(),
            purpose: self.purpose.as_deref(),
            has_existing_relationship: self.has_existing_relationship,
            consent_status: self.consent_status.as_deref(),
            soft_opt_in: self.soft_opt_in,
            legitimate_interest_assessed: self.legitimate_interest_assessed,
            subscriber_type: self.subscriber_type,
            consent_evidence_id: self.consent_evidence_id,
            existing_customer: self.existing_customer,
            similar_product_basis: self.similar_product_basis,
            collection_opt_out_offered_at: self.collection_opt_out_offered_at,
        }
    }
}

/// What the gate decided, plus the id of the persisted Decision Packet.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecisionOutcome {
    pub decision_id: Uuid,
    pub enforcement: Enforcement,
    pub block_reasons: Vec<String>,
}

/// Combine gate failures, the autonomy mode and the legal verdict into the
/// enforcement decision. Pure, so every combination is unit-testable.
///
/// Any failure denies. With no failures: `AutonomousGuarded` executes only
/// when the legal gate is `Allowed` (an `ApprovalRequired` legal verdict
/// forces a human even in autonomous mode); `Assisted`/`ApprovalRequired`
/// await approval; `Shadow` records but blocks; `Disabled` denies.
pub fn combine(failures: &[String], mode: AutonomyMode, legal: ContactDecision) -> Enforcement {
    if !failures.is_empty() {
        return Enforcement::Denied;
    }
    match mode {
        AutonomyMode::Disabled => Enforcement::Denied,
        AutonomyMode::Shadow => Enforcement::Shadowed,
        AutonomyMode::Assisted | AutonomyMode::ApprovalRequired => Enforcement::AwaitApproval,
        AutonomyMode::AutonomousGuarded => match legal {
            ContactDecision::Allowed => Enforcement::Execute,
            // A legal approval requirement outranks autonomous mode.
            ContactDecision::ApprovalRequired => Enforcement::AwaitApproval,
            // Prohibited should already be a failure; deny defensively.
            ContactDecision::Prohibited => Enforcement::Denied,
        },
    }
}

async fn load_autonomy_state(db: &PgPool, tenant_id: &str) -> Result<AutonomyState, SalesError> {
    let row: Option<(String, bool)> =
        sqlx::query_as("SELECT mode, kill_switch FROM sales_autonomy_state WHERE tenant_id = $1")
            .bind(tenant_id)
            .fetch_optional(db)
            .await
            .map_err(|e| SalesError::Database(e.to_string()))?;

    Ok(match row {
        Some((mode, kill_switch)) => AutonomyState {
            tenant_id: tenant_id.to_string(),
            mode: AutonomyMode::parse(&mode),
            kill_switch,
            rules: serde_json::json!({}),
            last_action: None,
            last_action_at: None,
        },
        // No row means autonomy was never granted for this tenant: fail
        // closed to disabled rather than assuming a permissive default.
        None => AutonomyState {
            tenant_id: tenant_id.to_string(),
            ..AutonomyState::default()
        },
    })
}

/// Evaluate every hard constraint, persist the Decision Packet, and return
/// the enforcement verdict. EVERY automated external action must go through
/// this.
///
/// Persists exactly one `sales_decisions` row even when the action is denied
/// or shadowed, so the machine stays explainable and replayable. Execute
/// requests (external sends) under an engaged kill switch additionally return
/// [`SalesError::KillSwitchEngaged`] after the packet is written.
pub async fn decide(db: &PgPool, ctx: DecisionContext) -> Result<DecisionOutcome, SalesError> {
    let tenant_id = ctx.tenant_id.as_str();
    let autonomy = load_autonomy_state(db, tenant_id).await?;
    let external = ctx.action.is_external_send();

    let mut failures: Vec<String> = Vec::new();

    // Gate 1 — global kill switch. Immediate stop for NEW outbound actions;
    // data and inbound processing are untouched.
    if autonomy.kill_switch {
        failures.push(
            "global_kill_switch: outbound halted by operator; no new external action may start"
                .to_string(),
        );
    }

    // Gate 2 — autonomy disabled. Fail closed for tenants that never granted
    // autonomy.
    if autonomy.mode == AutonomyMode::Disabled {
        failures.push(
            "autonomy_disabled: tenant autonomy mode is 'disabled'; no automated action"
                .to_string(),
        );
    }

    // Gates 3, 4 and 9 — suppression status and contact-point verification.
    // Only possible when the decision carries a contact point; the address is
    // an attribute of the point, never a field on the decision.
    if let Some(contact_point_id) = ctx.contact_point_id {
        let point: Option<(String, String, String, Option<DateTime<Utc>>)> = sqlx::query_as(
            "SELECT channel, normalized_value, verification, suppressed_at \
             FROM sales_contact_points \
             WHERE id = $1 AND tenant_id = $2",
        )
        .bind(contact_point_id)
        .bind(tenant_id)
        .fetch_optional(db)
        .await
        .map_err(|e| SalesError::Database(e.to_string()))?;

        match point {
            None => failures.push(format!(
                "contact_point_not_found: contact point {contact_point_id} does not exist \
                 for this tenant; fail closed"
            )),
            Some((channel, value, verification, suppressed_at)) => {
                if channel != "email" {
                    failures.push(format!(
                        "contact_point_channel_not_email: contact point channel is '{channel}'; \
                         the sales gate only sends email"
                    ));
                } else {
                    // Gate 3 — suppression (both the sales fast path and the
                    // platform-wide authority).
                    if check_suppression(db, tenant_id, &value).await? {
                        failures.push(format!(
                            "suppressed: {value} is on the unsubscribe/suppression list"
                        ));
                    }
                }

                // Gate 4 — only a sendable address may ever be contacted.
                // The rule is the one canonical definition shared with
                // enrollment and approval revalidation:
                // `verification IN ('valid', 'risky')`.
                if !email_point_is_sendable(&verification) {
                    failures.push(format!(
                        "contact_point_not_sendable: verification is '{verification}' for \
                         contact point {contact_point_id}; only 'valid' or 'risky' may be \
                         contacted"
                    ));
                }

                // Gate 9 — the point itself was suppressed.
                if suppressed_at.is_some() {
                    failures.push(format!(
                        "contact_point_suppressed: contact point {contact_point_id} has \
                         suppressed_at set"
                    ));
                }
            }
        }
    }

    // Gate 5 — legal policy. The context carries recipient FACTS (jurisdiction,
    // contact type, consent state), never a verdict or an authorization: the
    // verdict is re-evaluated from the current canonical store on every call,
    // so a policy that changed since the caller assembled the context is
    // honoured. No inputs at all means the gate cannot be evaluated, which
    // fails closed instead of silently skipping the gate.
    let (legal_decision, policy_id): (ContactDecision, Option<String>) = match ctx.policy.clone() {
        Some(mut owned) => {
            if owned.account_id.is_none() {
                owned.account_id = ctx.account_id;
            }
            if owned.contact_id.is_none() {
                owned.contact_id = ctx.contact_id;
            }
            if owned.contact_point_id.is_none() {
                owned.contact_point_id = ctx.contact_point_id;
            }
            let input = owned.as_borrowed(tenant_id);
            let verdict = legal_policy::evaluate(db, &input).await?;
            // Audit trail: every evaluated contact attempt is recorded.
            legal_policy::record(db, tenant_id, &input, &verdict).await?;

            match verdict.decision {
                ContactDecision::Prohibited => {
                    failures.push(format!("legal_policy_prohibited: {}", verdict.reason))
                }
                // ApprovalRequired is not a failure: it forces AwaitApproval via
                // `combine` even in autonomous mode.
                ContactDecision::ApprovalRequired | ContactDecision::Allowed => {}
            }

            (verdict.decision, verdict.policy_id.map(|id| id.to_string()))
        }
        None => {
            failures.push(
                "legal_policy_input_missing: no legal-policy input on the context; the \
                 legal gate cannot be evaluated and fails closed"
                    .to_string(),
            );
            (ContactDecision::ApprovalRequired, None)
        }
    };

    // Gate 6 — a human reply must prevent the next touch racing out.
    if let Some(enrollment_id) = ctx.enrollment_id {
        if check_enrollment_replied(db, enrollment_id).await? {
            failures.push(format!(
                "human_reply: enrollment {enrollment_id} has a human reply; \
                 subsequent sequence sends are blocked"
            ));
        }
    }

    // Gate 7 — sender health (only when a sender was resolved; resolution is
    // upstream and a missing sender is handled by the dispatcher).
    if let Some(sender_identity_id) = ctx.selected_sender {
        if let Err(err) = sender_health::gate(db, tenant_id, sender_identity_id).await {
            failures.push(format!("sender_health_denied: {err}"));
        }
    }

    // Gate 8 — per-account weekly frequency budget.
    if let Some(account_id) = ctx.account_id {
        if !check_frequency_budget(db, tenant_id, account_id).await? {
            failures.push(format!(
                "account_frequency_budget_exhausted: account {account_id} reached its \
                 weekly touch budget"
            ));
        }
    }

    let enforcement = combine(&failures, autonomy.mode, legal_decision);
    let blocked = enforcement == Enforcement::Denied;
    // A verdict that awaits a human becomes the operator's queue item; every
    // other verdict is recorded as requiring no review.
    let review_status = review_status_for(enforcement);

    // Persist the Decision Packet — ALWAYS, including denials and shadowed
    // decisions. The decision id is what makes the machine explainable. The
    // enforcement verdict, the sender reference and the review status make the
    // packet the execution contract the worker acts on; the deprecated TEXT
    // `selected_sender` column is deliberately not written any more.
    let block_reasons = serde_json::json!(failures);
    let confidence = ctx.confidence.clamp(0.0, 1.0) as f64;
    let score_total = ctx.score.total as f64;

    let decision_id: Uuid = sqlx::query_scalar(
        "INSERT INTO sales_decisions ( \
             id, tenant_id, account_id, contact_id, action, expected_value_eur, \
             confidence, score_total, selected_offer, selected_sequence, \
             selected_variant, selected_sender_id, evidence_ids, policy_id, \
             model_version, autonomy_mode, rationale, blocked, block_reasons, \
             execute_after, enforcement, review_status, created_at \
         ) VALUES ( \
             gen_random_uuid(), $1, $2, $3, $4, \
             LEAST(GREATEST($5::double precision, -1000000000), 1000000000)::numeric(14, 4), \
             LEAST(GREATEST($6::double precision, 0), 1), \
             $7::double precision, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, NOW() \
         ) RETURNING id",
    )
    .bind(tenant_id)
    .bind(ctx.account_id)
    .bind(ctx.contact_id)
    .bind(ctx.action.as_str())
    .bind(ctx.expected_value_eur)
    .bind(confidence)
    .bind(score_total)
    .bind(ctx.selected_offer.as_deref())
    .bind(ctx.selected_sequence.as_deref())
    .bind(ctx.selected_variant.as_deref())
    .bind(ctx.selected_sender)
    .bind(&ctx.evidence_ids)
    .bind(policy_id.as_deref())
    .bind(ctx.model_version.as_deref())
    .bind(autonomy.mode.as_str())
    .bind(&ctx.rationale)
    .bind(blocked)
    .bind(&block_reasons)
    .bind(ctx.execute_after)
    .bind(enforcement.as_str())
    .bind(review_status)
    .fetch_one(db)
    .await
    .map_err(|e| SalesError::Database(e.to_string()))?;

    if blocked {
        tracing::warn!(
            tenant_id,
            decision_id = %decision_id,
            action = ctx.action.as_str(),
            reasons = ?failures,
            "sales decision denied by hard gate"
        );
    }

    // Execute requests under a kill switch surface the stop as an error, not
    // just a blocked packet, so the caller cannot mistake it for a normal
    // approval wait.
    if autonomy.kill_switch && external {
        return Err(SalesError::KillSwitchEngaged);
    }

    Ok(DecisionOutcome {
        decision_id,
        enforcement,
        block_reasons: failures,
    })
}

/// The verdict of re-checking every hard gate immediately before an external
/// effect is produced.
#[derive(Debug, Clone)]
pub struct ExecutionRevalidation {
    pub allowed: bool,
    pub reasons: Vec<String>,
    /// The gates that were re-read, for the audit trail.
    pub checked: Vec<&'static str>,
}

/// Gate names reported in [`ExecutionRevalidation::checked`], in the order
/// [`revalidate_execution`] evaluates them.
const GATE_KILL_SWITCH: &str = "global_kill_switch";
const GATE_AUTONOMY_MODE: &str = "autonomy_mode";
const GATE_SUPPRESSION: &str = "suppression";
const GATE_CONTACT_POINT_SUPPRESSED: &str = "contact_point_suppressed";
const GATE_ADDRESS_VERIFICATION: &str = "address_verification";
const GATE_HUMAN_REPLY: &str = "human_reply";
const GATE_SENDER_HEALTH: &str = "sender_health";
const GATE_FREQUENCY_BUDGET: &str = "frequency_budget";
const GATE_LEGAL_POLICY: &str = "legal_policy";

/// The result for an action with no external effect: nothing was re-checked
/// and nothing needs to be. Documented reason: there is no external effect to
/// protect, so the send gates do not apply.
fn internal_action_revalidation() -> ExecutionRevalidation {
    ExecutionRevalidation {
        allowed: true,
        reasons: Vec::new(),
        checked: Vec::new(),
    }
}

/// Does a persisted `sales_decisions.action` value produce an external effect
/// (a message to a human)? Unknown values fail closed: they are treated as
/// external sends and must pass every gate.
fn action_is_external(action: &str) -> bool {
    match action.trim().to_ascii_lowercase().as_str() {
        "do_nothing" | "wait" | "collect_evidence" | "enrich" | "verify_email"
        | "research_company" | "operator_task" | "nurture" | "stop_permanently" => false,
        // contact | follow_up | change_angle | ask_for_referral | book_meeting
        // and anything unrecognised.
        _ => true,
    }
}

/// Map a freshly evaluated legal verdict — plus the decision's recorded review
/// state — to a revalidation failure. Pure, so every combination is
/// unit-tested.
///
/// `Prohibited` always fails. `ApprovalRequired` fails unless a human has
/// approved the decision (`review_status = 'approved'`): the human requirement
/// must be satisfied *under the current policy*, and a policy that moved to
/// approval-required after the decision may not ride on an old autonomous
/// verdict. `Allowed` never fails.
fn legal_revalidation_failure(
    verdict: ContactDecision,
    verdict_reason: &str,
    review_status: Option<&str>,
) -> Option<String> {
    match verdict {
        ContactDecision::Allowed => None,
        ContactDecision::Prohibited => Some(format!("legal_policy_prohibited: {verdict_reason}")),
        ContactDecision::ApprovalRequired if review_status == Some("approved") => None,
        ContactDecision::ApprovalRequired => Some(format!(
            "legal_policy_approval_required: {verdict_reason}; the decision's review_status is \
             '{}' — a human must approve under the current policy before this can execute",
            review_status.unwrap_or("none")
        )),
    }
}

/// The columns [`revalidate_execution`] needs from the Decision Packet.
///
/// `contact_point_id` and `enrollment_id` are deliberately resolved through
/// their canonical carriers: `sales_decisions` has neither column (migration
/// 200 creates the packet without them; migration 201 adds only enforcement,
/// sender, and review columns).
#[derive(sqlx::FromRow)]
struct ExecutionDecisionRow {
    tenant_id: String,
    account_id: Option<Uuid>,
    contact_id: Option<Uuid>,
    action: String,
    selected_sender_id: Option<Uuid>,
    review_status: Option<String>,
}

/// The gate-relevant state of the enrollment a decision belongs to.
#[derive(sqlx::FromRow)]
struct EnrollmentGateRow {
    contact_point_id: Option<Uuid>,
    has_human_reply: bool,
}

/// Resolve the enrollment a decision belongs to, through the canonical
/// carriers in priority order: the queued action for the decision, the step
/// execution that carries the decision id, an enrollment created from the
/// decision, then the contact's newest enrollment as a last resort (so a
/// missing link cannot silently skip the human-reply gate).
///
/// Connection-scoped so it can run inside [`revalidate_execution_tx`]'s
/// transaction.
async fn resolve_enrollment_conn(
    conn: &mut PgConnection,
    tenant_id: &str,
    decision_id: Uuid,
    contact_id: Option<Uuid>,
) -> Result<Option<EnrollmentGateRow>, SalesError> {
    let linked: Option<Uuid> = sqlx::query_scalar(
        "SELECT entity_id FROM sales_actions \
         WHERE tenant_id = $1 AND decision_id = $2 AND entity_type = 'enrollment' \
         ORDER BY created_at DESC LIMIT 1",
    )
    .bind(tenant_id)
    .bind(decision_id)
    .fetch_optional(&mut *conn)
    .await
    .map_err(|e| SalesError::Database(e.to_string()))?;

    let linked = match linked {
        Some(id) => Some(id),
        None => sqlx::query_scalar(
            "SELECT enrollment_id FROM sales_step_executions \
                 WHERE decision_id = $1 ORDER BY created_at DESC LIMIT 1",
        )
        .bind(decision_id)
        .fetch_optional(&mut *conn)
        .await
        .map_err(|e| SalesError::Database(e.to_string()))?,
    };

    let linked = match linked {
        Some(id) => Some(id),
        None => sqlx::query_scalar(
            "SELECT id FROM sales_enrollments \
                 WHERE tenant_id = $1 AND decision_id = $2 \
                 ORDER BY enrolled_at DESC LIMIT 1",
        )
        .bind(tenant_id)
        .bind(decision_id)
        .fetch_optional(&mut *conn)
        .await
        .map_err(|e| SalesError::Database(e.to_string()))?,
    };

    if let Some(enrollment_id) = linked {
        return sqlx::query_as(
            "SELECT contact_point_id, has_human_reply FROM sales_enrollments \
             WHERE id = $1 AND tenant_id = $2",
        )
        .bind(enrollment_id)
        .bind(tenant_id)
        .fetch_optional(&mut *conn)
        .await
        .map_err(|e| SalesError::Database(e.to_string()));
    }

    let Some(contact_id) = contact_id else {
        return Ok(None);
    };
    sqlx::query_as(
        "SELECT contact_point_id, has_human_reply FROM sales_enrollments \
         WHERE tenant_id = $1 AND contact_id = $2 \
         ORDER BY enrolled_at DESC LIMIT 1",
    )
    .bind(tenant_id)
    .bind(contact_id)
    .fetch_optional(&mut *conn)
    .await
    .map_err(|e| SalesError::Database(e.to_string()))
}

/// The legal-policy evaluation recorded for a contact point (or, when the
/// point is unknown, for the contact) at decision time.
///
/// Only the `inputs` are used: they are recipient FACTS. The verdict itself is
/// deliberately ignored and re-derived by [`revalidate_execution`], so a stale
/// policy decision can never be replayed as an indefinite capability.
async fn latest_policy_audit_conn(
    conn: &mut PgConnection,
    tenant_id: &str,
    contact_id: Option<Uuid>,
    contact_point_id: Option<Uuid>,
) -> Result<Option<(Option<Uuid>, serde_json::Value)>, SalesError> {
    if let Some(point_id) = contact_point_id {
        return sqlx::query_as(
            "SELECT contact_point_id, inputs FROM sales_contact_policy_decisions \
             WHERE tenant_id = $1 AND contact_point_id = $2 \
             ORDER BY created_at DESC LIMIT 1",
        )
        .bind(tenant_id)
        .bind(point_id)
        .fetch_optional(&mut *conn)
        .await
        .map_err(|e| SalesError::Database(e.to_string()));
    }

    let Some(contact_id) = contact_id else {
        return Ok(None);
    };
    sqlx::query_as(
        "SELECT contact_point_id, inputs FROM sales_contact_policy_decisions \
         WHERE tenant_id = $1 AND contact_id = $2 \
         ORDER BY created_at DESC LIMIT 1",
    )
    .bind(tenant_id)
    .bind(contact_id)
    .fetch_optional(&mut *conn)
    .await
    .map_err(|e| SalesError::Database(e.to_string()))
}

/// The contact's newest email contact point, used only when neither the
/// enrollment link nor the policy audit row identifies one.
async fn newest_email_contact_point_conn(
    conn: &mut PgConnection,
    tenant_id: &str,
    contact_id: Option<Uuid>,
) -> Result<Option<Uuid>, SalesError> {
    let Some(contact_id) = contact_id else {
        return Ok(None);
    };
    sqlx::query_scalar(
        "SELECT id FROM sales_contact_points \
         WHERE tenant_id = $1 AND contact_id = $2 AND channel = 'email' \
         ORDER BY created_at DESC LIMIT 1",
    )
    .bind(tenant_id)
    .bind(contact_id)
    .fetch_optional(&mut *conn)
    .await
    .map_err(|e| SalesError::Database(e.to_string()))
}

/// Re-run every hard gate for a decision that already exists.
///
/// An operator approval is permission to proceed, not permission to bypass a
/// gate that changed since the decision was made: an approval from five
/// minutes ago must not defeat an unsubscribe, a human reply, a legal-policy
/// change or a newly quarantined sender.
///
/// Used by the worker immediately before the external enqueue, and by the
/// approval path in `control.rs`.
///
/// Gates are re-read in this order, and **every** failure is recorded (the
/// check does not stop at the first): global kill switch; autonomy mode still
/// permits execution; suppression on the contact point's current email (both
/// `sales_unsubscribes` and platform `suppressions`); the contact point's
/// `suppressed_at`; its current address verification, through the one
/// canonical rule [`email_point_is_sendable`] (`valid`/`risky` only); the
/// enrollment's `has_human_reply`; the selected sender's current health; the
/// account's weekly touch budget — now an atomic **reservation**, not a
/// count-and-compare; the current legal policy (re-evaluated from the
/// canonical store, never replayed from the packet).
///
/// Admission and the reservation are one transaction. [`revalidate_execution`]
/// opens its own transaction; [`revalidate_execution_tx`] runs the identical
/// gates inside a caller's transaction so a review's decision lock,
/// revalidation, linked-action transition and terminal status are atomic.
///
/// Reservation policy: the logical send unit is
/// `sa-send:{step_execution_id}` (falling back to `decision:{decision_id}`),
/// so re-validating the same send never consumes a second slot; a
/// revalidation that ultimately refuses the send releases the slot it just
/// reserved, in the same transaction. A caller that admits a touch and then
/// does not send it must call [`settle_account_touch_tx`] with
/// `settled = false`; the send's own transaction settles it with `true`.
///
/// `allowed` is true only when no gate failed. A missing decision is
/// [`SalesError::InvalidInput`]. Internal actions (not
/// [`DecisionAction::is_external_send`]) short-circuit to `allowed: true` with
/// `checked: []` — there is no external effect to protect.
/// Re-open the decision and all its gates in one transaction. This is the
/// safe wrapper for callers that do not already hold one; the approval path
/// uses [`revalidate_execution_tx`] so its decision lock, revalidation,
/// linked-action transition and terminal review status are a single atomic
/// unit.
pub async fn revalidate_execution(
    db: &PgPool,
    decision_id: Uuid,
) -> Result<ExecutionRevalidation, SalesError> {
    let mut tx = db.begin().await.map_err(db_error)?;
    let result = revalidate_execution_conn(tx.as_mut(), decision_id).await;
    match result {
        Ok(revalidation) => {
            tx.commit().await.map_err(db_error)?;
            Ok(revalidation)
        }
        Err(error) => {
            let _ = tx.rollback().await;
            Err(error)
        }
    }
}

/// Transaction-scoped revalidation. Same gate set as
/// [`revalidate_execution`], but evaluated on the caller's connection so the
/// review transition (decision lock, revalidation, linked-action transition,
/// terminal `review_status`) can be atomic.
///
/// The frequency-budget gate is an atomic reservation taken inside this
/// transaction (see [`reserve_account_touch_tx`]); if any gate ultimately
/// refuses the send, the slot is released before this function returns.
pub async fn revalidate_execution_tx(
    tx: &mut Transaction<'_, Postgres>,
    decision_id: Uuid,
) -> Result<ExecutionRevalidation, SalesError> {
    revalidate_execution_conn(tx.as_mut(), decision_id).await
}

async fn revalidate_execution_conn(
    conn: &mut PgConnection,
    decision_id: Uuid,
) -> Result<ExecutionRevalidation, SalesError> {
    let decision: Option<ExecutionDecisionRow> = sqlx::query_as(
        "SELECT tenant_id, account_id, contact_id, action, selected_sender_id, \
                review_status \
         FROM sales_decisions \
         WHERE id = $1",
    )
    .bind(decision_id)
    .fetch_optional(&mut *conn)
    .await
    .map_err(db_error)?;

    let Some(decision) = decision else {
        return Err(SalesError::InvalidInput(format!(
            "revalidate_execution: no sales_decisions row with id {decision_id}"
        )));
    };

    // Internal actions have no external effect to protect.
    if !action_is_external(&decision.action) {
        return Ok(internal_action_revalidation());
    }

    let mut reasons: Vec<String> = Vec::new();
    let mut checked: Vec<&'static str> = Vec::new();
    let tenant_id = decision.tenant_id.as_str();

    // Gates 1 and 2 — the autonomy state as it is NOW. The kill switch stops
    // new outbound actions immediately, and a mode that blocks all execution
    // (`disabled`/`shadow`) must not be bypassed by replaying an old decision.
    let autonomy = load_autonomy_state_conn(conn, tenant_id).await?;
    checked.push(GATE_KILL_SWITCH);
    if autonomy.kill_switch {
        reasons.push(
            "global_kill_switch: outbound halted by operator; no external action may start"
                .to_string(),
        );
    }
    checked.push(GATE_AUTONOMY_MODE);
    if autonomy.mode.blocks_all_execution() {
        reasons.push(format!(
            "autonomy_mode_blocks_execution: tenant autonomy mode is '{}'; execution is not \
             permitted",
            autonomy.mode.as_str()
        ));
    }

    // Resolve the enrollment and the contact point this decision was made for.
    let enrollment =
        resolve_enrollment_conn(conn, tenant_id, decision_id, decision.contact_id).await?;
    let enrollment_point = enrollment.as_ref().and_then(|e| e.contact_point_id);
    let mut policy_audit = match enrollment_point {
        Some(point_id) => {
            latest_policy_audit_conn(conn, tenant_id, decision.contact_id, Some(point_id)).await?
        }
        None => None,
    };
    if policy_audit.is_none() {
        policy_audit = latest_policy_audit_conn(conn, tenant_id, decision.contact_id, None).await?;
    }
    let contact_point_id =
        match enrollment_point.or_else(|| policy_audit.as_ref().and_then(|(point, _)| *point)) {
            Some(point_id) => Some(point_id),
            None => newest_email_contact_point_conn(conn, tenant_id, decision.contact_id).await?,
        };

    // Gates 3-5 — the contact point's current suppression status, its own
    // suppressed flag, and its current verification.
    match contact_point_id {
        None => reasons.push(format!(
            "contact_point_not_found: decision {decision_id} has no resolvable email contact \
             point; the suppression and verification gates cannot be evaluated — fail closed"
        )),
        Some(point_id) => {
            let point: Option<(String, String, String, Option<DateTime<Utc>>)> = sqlx::query_as(
                "SELECT channel, normalized_value, verification, suppressed_at \
                 FROM sales_contact_points \
                 WHERE id = $1 AND tenant_id = $2",
            )
            .bind(point_id)
            .bind(tenant_id)
            .fetch_optional(&mut *conn)
            .await
            .map_err(db_error)?;

            match point {
                None => reasons.push(format!(
                    "contact_point_not_found: contact point {point_id} does not exist for this \
                     tenant; fail closed"
                )),
                Some((channel, value, verification, suppressed_at)) => {
                    // Gate 3 — both suppression authorities, on the address as
                    // it is NOW, not as it was at decision time.
                    if channel != "email" {
                        reasons.push(format!(
                            "contact_point_channel_not_email: contact point channel is \
                             '{channel}'; the sales gate only sends email"
                        ));
                    } else {
                        checked.push(GATE_SUPPRESSION);
                        if check_suppression_conn(conn, tenant_id, &value).await? {
                            reasons.push(format!(
                                "suppressed: {value} is on the unsubscribe/suppression list"
                            ));
                        }
                    }

                    // Gate 4 — the point itself was suppressed after the
                    // decision.
                    checked.push(GATE_CONTACT_POINT_SUPPRESSED);
                    if suppressed_at.is_some() {
                        reasons.push(format!(
                            "contact_point_suppressed: contact point {point_id} has \
                             suppressed_at set"
                        ));
                    }

                    // Gate 5 — an address that is not sendable NOW must never
                    // be contacted. The rule is the one canonical definition
                    // shared with enrollment and the live worker
                    // ([`email_point_is_sendable`]): only `valid`/`risky` pass,
                    // so a regression from `valid` to `unverified`/`unknown`
                    // stops the send just as `invalid` does.
                    checked.push(GATE_ADDRESS_VERIFICATION);
                    if !email_point_is_sendable(&verification) {
                        reasons.push(format!(
                            "contact_point_not_sendable: verification is '{verification}' for \
                             contact point {point_id}; only 'valid' or 'risky' may be contacted"
                        ));
                    }
                }
            }
        }
    }

    // Gate 6 — a human reply that arrived after the decision stops the send.
    if let Some(enrollment) = enrollment.as_ref() {
        checked.push(GATE_HUMAN_REPLY);
        if enrollment.has_human_reply {
            reasons.push(format!(
                "human_reply: the enrollment for decision {decision_id} has a human reply; \
                 subsequent sequence sends are blocked"
            ));
        }
    }

    // Gate 7 — the selected sender's current health, on this connection.
    if let Some(sender_identity_id) = decision.selected_sender_id {
        checked.push(GATE_SENDER_HEALTH);
        if let Err(err) = sender_health_gate_conn(conn, tenant_id, sender_identity_id).await {
            reasons.push(format!("sender_health_denied: {err}"));
        }
    }

    // Gate 8 — the account's weekly touch budget as an atomic RESERVATION.
    // The count and the insert happen on this connection while the account
    // row is locked below (`SELECT ... FOR UPDATE`), so two concurrent
    // workers cannot both take the last slot the way a bare `count < budget`
    // check allowed. Idempotent per logical send: re-validating the same send
    // never consumes a second slot.
    let mut reserved: Option<(Uuid, String)> = None;
    if let Some(account_id) = decision.account_id {
        checked.push(GATE_FREQUENCY_BUDGET);
        let logical_send = logical_send_for_decision_conn(conn, decision_id).await?;
        if reserve_account_touch_conn(conn, tenant_id, account_id, &logical_send).await? {
            reserved = Some((account_id, logical_send));
        } else {
            reasons.push(format!(
                "account_frequency_budget_exhausted: account {account_id} reached its weekly \
                 touch budget"
            ));
        }
    }

    // Gate 9 — the legal policy as it stands NOW. The recorded inputs are
    // recipient facts; the verdict is re-derived from the current canonical
    // store (on this connection), never replayed from the decision's
    // policy_id.
    checked.push(GATE_LEGAL_POLICY);
    match policy_audit {
        None => reasons.push(
            "legal_policy_input_missing: no recorded legal-policy inputs for this decision; the \
             legal gate cannot be re-evaluated and fails closed"
                .to_string(),
        ),
        Some((_, inputs)) => match serde_json::from_value::<ContactPolicyInputOwned>(inputs) {
            Err(err) => reasons.push(format!(
                "legal_policy_input_unreadable: recorded legal-policy inputs cannot be \
                 deserialized ({err}); fail closed"
            )),
            Ok(mut owned) => {
                if owned.account_id.is_none() {
                    owned.account_id = decision.account_id;
                }
                if owned.contact_id.is_none() {
                    owned.contact_id = decision.contact_id;
                }
                if owned.contact_point_id.is_none() {
                    owned.contact_point_id = contact_point_id;
                }
                let input = owned.as_borrowed(tenant_id);
                let verdict = evaluate_legal_policy_conn(conn, &input).await?;
                if let Some(reason) = legal_revalidation_failure(
                    verdict.decision,
                    &verdict.reason,
                    decision.review_status.as_deref(),
                ) {
                    reasons.push(reason);
                }
            }
        },
    }

    // A refusal must not leak the slot it just reserved: release the
    // reservation in this same transaction when any gate failed. This is the
    // documented policy — a reservation whose send is refused is released;
    // one that sends is settled (see [`settle_account_touch_tx`]).
    if !reasons.is_empty() {
        if let Some((account_id, logical_send)) = reserved.as_ref() {
            settle_account_touch_conn(conn, tenant_id, *account_id, logical_send, false).await?;
        }
    }

    let allowed = reasons.is_empty();
    Ok(ExecutionRevalidation {
        allowed,
        reasons,
        checked,
    })
}

/// [`load_autonomy_state`] on an explicit connection, so it can run inside
/// [`revalidate_execution_tx`]'s transaction.
async fn load_autonomy_state_conn(
    conn: &mut PgConnection,
    tenant_id: &str,
) -> Result<AutonomyState, SalesError> {
    let row: Option<(String, bool)> =
        sqlx::query_as("SELECT mode, kill_switch FROM sales_autonomy_state WHERE tenant_id = $1")
            .bind(tenant_id)
            .fetch_optional(&mut *conn)
            .await
            .map_err(db_error)?;

    Ok(match row {
        Some((mode, kill_switch)) => AutonomyState {
            tenant_id: tenant_id.to_string(),
            mode: AutonomyMode::parse(&mode),
            kill_switch,
            rules: serde_json::json!({}),
            last_action: None,
            last_action_at: None,
        },
        // No row means autonomy was never granted for this tenant: fail
        // closed to disabled rather than assuming a permissive default.
        None => AutonomyState {
            tenant_id: tenant_id.to_string(),
            ..AutonomyState::default()
        },
    })
}

/// Sender-health gate on an explicit connection.
///
/// Mirrors [`sender_health::gate`] with the module's default thresholds (the
/// canonical thresholds stay in `sender_health.rs`; only the executor
/// differs) so the check can run inside the caller's transaction.
async fn sender_health_gate_conn(
    conn: &mut PgConnection,
    tenant_id: &str,
    sender_identity_id: Uuid,
) -> Result<(), SalesError> {
    let thresholds = sender_health::HealthThresholds::default();
    let row: Option<(String, f64)> = sqlx::query_as(
        "SELECT state, health_score FROM sales_sender_health \
         WHERE tenant_id = $1 AND sender_identity_id = $2",
    )
    .bind(tenant_id)
    .bind(sender_identity_id)
    .fetch_optional(&mut *conn)
    .await
    .map_err(db_error)?;

    let Some((state, health_score)) = row else {
        return Err(SalesError::PolicyDenied(format!(
            "sender identity {sender_identity_id} has never been health-assessed; \
             fail closed until it is"
        )));
    };

    if matches!(state.as_str(), "quarantined" | "paused") {
        return Err(SalesError::PolicyDenied(format!(
            "sender identity {sender_identity_id} is {state}; sending is blocked"
        )));
    }

    if health_score < thresholds.min_health_to_send {
        return Err(SalesError::PolicyDenied(format!(
            "sender identity {sender_identity_id} health {health_score:.3} is below \
             the minimum {:.3}",
            thresholds.min_health_to_send
        )));
    }

    Ok(())
}

/// [`check_suppression`] on an explicit connection.
async fn check_suppression_conn(
    conn: &mut PgConnection,
    tenant_id: &str,
    email: &str,
) -> Result<bool, SalesError> {
    let suppressed: bool = sqlx::query_scalar(
        "SELECT EXISTS ( \
             SELECT 1 FROM sales_unsubscribes \
             WHERE tenant_id = $1 AND lower(email) = lower($2) \
         ) OR EXISTS ( \
             SELECT 1 FROM suppressions \
             WHERE tenant_id = $1 AND lower(email) = lower($2) \
         )",
    )
    .bind(tenant_id)
    .bind(email)
    .fetch_one(&mut *conn)
    .await
    .map_err(db_error)?;
    Ok(suppressed)
}

/// The legal-policy row shape [`evaluate_legal_policy_conn`] reads. It mirrors
/// the private `PolicyRow` in `legal_policy.rs`; the decision logic itself is
/// never duplicated — the public pure helpers
/// ([`legal_policy::resolve_jurisdiction`], [`legal_policy::policy_is_authoritative`],
/// [`legal_policy::decide_with_state`]) are called with this row.
#[derive(sqlx::FromRow)]
struct TxPolicyRow {
    id: Uuid,
    jurisdiction: String,
    channel: String,
    contact_type: String,
    decision: String,
    basis: String,
    required_disclosure: serde_json::Value,
    version: i32,
    approved_by: Option<String>,
    approved_at: Option<DateTime<Utc>>,
    valid_from: DateTime<Utc>,
    valid_until: Option<DateTime<Utc>>,
}

/// Map a persisted `sales_jurisdiction_policies.decision` value. Mirrors the
/// private parser in `legal_policy.rs`: unknown values fail closed to
/// `ApprovalRequired`.
fn tx_parse_contact_decision(raw: &str) -> ContactDecision {
    match raw.trim().to_ascii_lowercase().as_str() {
        "allowed" => ContactDecision::Allowed,
        "prohibited" => ContactDecision::Prohibited,
        _ => ContactDecision::ApprovalRequired,
    }
}

/// [`legal_policy::evaluate`] on an explicit connection.
///
/// Same two queries and the same public pure decision function, so the
/// verdict is identical to the pool version; only the executor differs. This
/// is what lets the legal gate run inside the review transaction.
async fn evaluate_legal_policy_conn(
    conn: &mut PgConnection,
    input: &ContactPolicyInput<'_>,
) -> Result<legal_policy::ContactPolicyVerdict, SalesError> {
    let jurisdiction = legal_policy::resolve_jurisdiction(
        input.recipient_country.as_deref(),
        input.country_confidence,
    );
    let contact_type = legal_policy::normalize_contact_type(input.contact_type);
    let channel = legal_policy::normalize_channel(input.channel);

    // Highest version for the exact triple, regardless of approval/validity:
    // an unapproved or expired top version must not silently delegate to an
    // older row — it falls through to the unknown default instead.
    let row: Option<TxPolicyRow> = sqlx::query_as(
        "SELECT id, jurisdiction, channel, contact_type, decision, basis, \
                required_disclosure, version, approved_by, approved_at, \
                valid_from, valid_until \
         FROM sales_jurisdiction_policies \
         WHERE jurisdiction = $1 AND channel = $2 AND contact_type = $3 \
         ORDER BY version DESC \
         LIMIT 1",
    )
    .bind(&jurisdiction)
    .bind(channel)
    .bind(contact_type)
    .fetch_optional(&mut *conn)
    .await
    .map_err(db_error)?;

    let now = Utc::now();
    let policy = row.and_then(|row| {
        let authoritative = legal_policy::policy_is_authoritative(
            row.approved_by.as_deref(),
            row.approved_at,
            row.valid_from,
            row.valid_until,
            now,
        );
        authoritative.then(|| JurisdictionPolicy {
            id: row.id,
            jurisdiction: row.jurisdiction,
            channel: row.channel,
            contact_type: row.contact_type,
            decision: tx_parse_contact_decision(&row.decision),
            basis: row.basis,
            required_disclosure: row.required_disclosure,
            version: row.version,
        })
    });

    // Distinguish "jurisdiction is listed but this channel is not configured"
    // from "jurisdiction is entirely unlisted" for the operator-facing reason.
    let channel_configured = if policy.is_some() {
        true
    } else {
        sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS ( \
                 SELECT 1 FROM sales_jurisdiction_policies \
                 WHERE jurisdiction = $1 AND contact_type = $2 \
                   AND approved_by IS NOT NULL AND approved_at IS NOT NULL \
                   AND valid_from <= NOW() \
                   AND (valid_until IS NULL OR valid_until > NOW()) \
             )",
        )
        .bind(&jurisdiction)
        .bind(contact_type)
        .fetch_one(&mut *conn)
        .await
        .map_err(db_error)?
    };

    Ok(legal_policy::decide_with_state(
        policy.as_ref(),
        channel_configured,
        input,
    ))
}

// ---------------------------------------------------------------------------
// Account touch budget: admission as a reservation
// ---------------------------------------------------------------------------

/// Realised touches for an account over the rolling 7-day window, counted as
/// distinct logical sends (one `sales_outcomes` row per step execution at
/// most). `open`/`click` are deliberately excluded as weak, machine-generatable
/// signals; every other outcome is a send that reached a terminal fate — the
/// same set the budget check has always counted.
async fn count_realised_touches_conn(
    conn: &mut PgConnection,
    tenant_id: &str,
    account_id: Uuid,
) -> Result<i64, SalesError> {
    sqlx::query_scalar(
        "SELECT COUNT(DISTINCT COALESCE(step_execution_id::text, id::text))::bigint \
         FROM sales_outcomes \
         WHERE tenant_id = $1 AND account_id = $2 \
           AND occurred_at >= NOW() - INTERVAL '7 days' \
           AND outcome IN ('delivered', 'reply', 'positive_reply', 'meeting_booked', \
                           'meeting_attended', 'trial', 'paid_subscription', \
                           'retained_mrr', 'bounce', 'complaint', 'unsubscribe')",
    )
    .bind(tenant_id)
    .bind(account_id)
    .fetch_one(&mut *conn)
    .await
    .map_err(db_error)
}

/// Live (not yet settled or released) reservations for an account.
async fn count_live_reservations_conn(
    conn: &mut PgConnection,
    account_id: Uuid,
) -> Result<i64, SalesError> {
    sqlx::query_scalar(
        "SELECT COUNT(*)::bigint FROM sales_account_touch_reservations \
         WHERE account_id = $1 AND state = 'reserved'",
    )
    .bind(account_id)
    .fetch_one(&mut *conn)
    .await
    .map_err(db_error)
}

/// Account weekly touch budget: `max(DEFAULT_WEEKLY_ACCOUNT_BUDGET,
/// max_active_contacts * WEEKLY_BUDGET_PER_ACTIVE_CONTACT)`. A missing account
/// row uses the default.
fn weekly_budget_for(max_active_contacts: Option<i16>) -> i64 {
    max_active_contacts
        .map(|n| DEFAULT_WEEKLY_ACCOUNT_BUDGET.max(i64::from(n) * WEEKLY_BUDGET_PER_ACTIVE_CONTACT))
        .unwrap_or(DEFAULT_WEEKLY_ACCOUNT_BUDGET)
}

/// Lock the account row and read its weekly budget.
///
/// `SELECT ... FOR UPDATE` is the serialisation point: a caller that already
/// holds the lock (for a multi-step admission decision) simply re-selects in
/// the same transaction; a caller that does not acquires it here. Either way
/// the budget count and the reservation insert that follow cannot interleave
/// with another worker's admission for the same account.
async fn lock_account_budget_conn(
    conn: &mut PgConnection,
    tenant_id: &str,
    account_id: Uuid,
) -> Result<i64, SalesError> {
    let max_active_contacts: Option<i16> = sqlx::query_scalar(
        "SELECT max_active_contacts FROM sales_accounts \
         WHERE id = $1 AND tenant_id = $2 FOR UPDATE",
    )
    .bind(account_id)
    .bind(tenant_id)
    .fetch_optional(&mut *conn)
    .await
    .map_err(db_error)?;

    max_active_contacts
        .map(|n| weekly_budget_for(Some(n)))
        .ok_or_else(|| {
            SalesError::InvalidInput(format!(
                "reserve_account_touch_tx: account {account_id} does not exist for tenant \
             {tenant_id}; refusing to admit a touch against an unknown account"
            ))
        })
}

/// Reserve one touch slot for an account.
///
/// MUST run inside a transaction that holds (or acquires) the
/// `sales_accounts` row lock; this function acquires it itself with
/// `SELECT ... FOR UPDATE`, so the count of reservations plus realised
/// outcomes and the insert cannot race. Returns `Ok(false)` when the budget
/// is exhausted — a refusal, not an error. An unknown account is an error
/// (fail closed, never a silent refusal).
///
/// Idempotent per `(account_id, logical_send)`: an existing `reserved` or
/// `settled` row returns `Ok(true)` without consuming another slot, and a
/// `released` row may be re-reserved when budget allows.
pub async fn reserve_account_touch_tx(
    tx: &mut Transaction<'_, Postgres>,
    tenant_id: &str,
    account_id: Uuid,
    logical_send: &str,
) -> Result<bool, SalesError> {
    reserve_account_touch_conn(tx.as_mut(), tenant_id, account_id, logical_send).await
}

async fn reserve_account_touch_conn(
    conn: &mut PgConnection,
    tenant_id: &str,
    account_id: Uuid,
    logical_send: &str,
) -> Result<bool, SalesError> {
    let budget = lock_account_budget_conn(conn, tenant_id, account_id).await?;
    reserve_account_touch_with_budget_conn(conn, tenant_id, account_id, logical_send, budget).await
}

/// [`reserve_account_touch_conn`] with an explicit budget, for tests that
/// need a budget the account formula can never produce (the formula's floor
/// is [`DEFAULT_WEEKLY_ACCOUNT_BUDGET`]). The caller must already hold the
/// account row lock.
async fn reserve_account_touch_with_budget_conn(
    conn: &mut PgConnection,
    tenant_id: &str,
    account_id: Uuid,
    logical_send: &str,
    budget: i64,
) -> Result<bool, SalesError> {
    // Idempotency: this logical send already holds (or consumed) its slot.
    let existing: Option<String> = sqlx::query_scalar(
        "SELECT state FROM sales_account_touch_reservations \
         WHERE account_id = $1 AND logical_send = $2",
    )
    .bind(account_id)
    .bind(logical_send)
    .fetch_optional(&mut *conn)
    .await
    .map_err(db_error)?;

    if matches!(existing.as_deref(), Some("reserved") | Some("settled")) {
        return Ok(true);
    }

    // The budget is `live reservations + realised outcomes in the window`.
    let live = count_live_reservations_conn(conn, account_id).await?;
    let realised = count_realised_touches_conn(conn, tenant_id, account_id).await?;
    if live + realised >= budget {
        return Ok(false);
    }

    // Fresh admission, or re-admission of a released logical send. The unique
    // key `(account_id, logical_send)` is the second line of defence: even if
    // two reservations raced, the logical send could consume only one slot.
    sqlx::query(
        "INSERT INTO sales_account_touch_reservations \
             (account_id, logical_send, tenant_id, state) \
         VALUES ($1, $2, $3, 'reserved') \
         ON CONFLICT (account_id, logical_send) DO UPDATE \
             SET state = 'reserved', reserved_at = NOW(), settled_at = NULL \
             WHERE sales_account_touch_reservations.state = 'released'",
    )
    .bind(account_id)
    .bind(logical_send)
    .bind(tenant_id)
    .execute(&mut *conn)
    .await
    .map_err(db_error)?;

    Ok(true)
}

/// Settle or release a reservation once the send's fate is known.
///
/// `settled = true` keeps the slot consumed (the send happened; its outcome
/// becomes the durable touch record). `settled = false` releases the slot
/// (the touch was refused or will never happen). Only a live `reserved` row
/// transitions, so repeated calls — and a call after the other transition —
/// are a safe no-op.
pub async fn settle_account_touch_tx(
    tx: &mut Transaction<'_, Postgres>,
    tenant_id: &str,
    account_id: Uuid,
    logical_send: &str,
    settled: bool,
) -> Result<(), SalesError> {
    settle_account_touch_conn(tx.as_mut(), tenant_id, account_id, logical_send, settled).await
}

async fn settle_account_touch_conn(
    conn: &mut PgConnection,
    tenant_id: &str,
    account_id: Uuid,
    logical_send: &str,
    settled: bool,
) -> Result<(), SalesError> {
    sqlx::query(
        "UPDATE sales_account_touch_reservations \
         SET state = CASE WHEN $4 THEN 'settled' ELSE 'released' END, settled_at = NOW() \
         WHERE account_id = $1 AND logical_send = $2 AND tenant_id = $3 AND state = 'reserved'",
    )
    .bind(account_id)
    .bind(logical_send)
    .bind(tenant_id)
    .bind(settled)
    .execute(&mut *conn)
    .await
    .map_err(db_error)?;
    Ok(())
}

/// The stable logical send unit for a decision: the queue's idempotency key
/// for its send step execution (`sa-send:{step_execution_id}`, the same unit
/// migration 205 keys the delivery ledger by), or `decision:{decision_id}`
/// when no step execution is linked.
async fn logical_send_for_decision_conn(
    conn: &mut PgConnection,
    decision_id: Uuid,
) -> Result<String, SalesError> {
    let step_execution_id: Option<Uuid> = sqlx::query_scalar(
        "SELECT id FROM sales_step_executions \
         WHERE decision_id = $1 ORDER BY created_at DESC LIMIT 1",
    )
    .bind(decision_id)
    .fetch_optional(&mut *conn)
    .await
    .map_err(db_error)?;

    Ok(match step_execution_id {
        Some(id) => format!("sa-send:{id}"),
        None => format!("decision:{decision_id}"),
    })
}

/// Release the live touch reservation a decision's logical send may hold.
///
/// Used by the review transition when a decision is rejected (or an approval
/// is refused): the touch will never happen, so its slot must not stay
/// consumed. A missing reservation is a no-op.
pub(crate) async fn release_decision_touch_tx(
    tx: &mut Transaction<'_, Postgres>,
    tenant_id: &str,
    decision_id: Uuid,
) -> Result<(), SalesError> {
    let account_id: Option<Option<Uuid>> = sqlx::query_scalar(
        "SELECT account_id FROM sales_decisions WHERE id = $1 AND tenant_id = $2",
    )
    .bind(decision_id)
    .bind(tenant_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(db_error)?;

    let Some(Some(account_id)) = account_id else {
        return Ok(());
    };
    let logical_send = logical_send_for_decision_conn(tx.as_mut(), decision_id).await?;
    settle_account_touch_conn(tx.as_mut(), tenant_id, account_id, &logical_send, false).await
}

/// Map a SQL error into the crate error type.
fn db_error(error: sqlx::Error) -> SalesError {
    SalesError::Database(error.to_string())
}

/// Is this address on either suppression authority?
pub async fn check_suppression(
    db: &PgPool,
    tenant_id: &str,
    email: &str,
) -> Result<bool, SalesError> {
    let suppressed: bool = sqlx::query_scalar(
        "SELECT EXISTS ( \
             SELECT 1 FROM sales_unsubscribes \
             WHERE tenant_id = $1 AND lower(email) = lower($2) \
         ) OR EXISTS ( \
             SELECT 1 FROM suppressions \
             WHERE tenant_id = $1 AND lower(email) = lower($2) \
         )",
    )
    .bind(tenant_id)
    .bind(email)
    .fetch_one(db)
    .await
    .map_err(|e| SalesError::Database(e.to_string()))?;
    Ok(suppressed)
}

/// Has a human already replied to this enrollment? A missing row answers
/// `false` (there is no recorded human reply).
pub async fn check_enrollment_replied(
    db: &PgPool,
    enrollment_id: Uuid,
) -> Result<bool, SalesError> {
    let replied: Option<bool> =
        sqlx::query_scalar("SELECT has_human_reply FROM sales_enrollments WHERE id = $1")
            .bind(enrollment_id)
            .fetch_optional(db)
            .await
            .map_err(|e| SalesError::Database(e.to_string()))?;
    Ok(replied.unwrap_or(false))
}

/// Account weekly touch budget: `max(DEFAULT_WEEKLY_ACCOUNT_BUDGET,
/// max_active_contacts * WEEKLY_BUDGET_PER_ACTIVE_CONTACT)`. A missing account
/// row uses the default.
async fn account_weekly_budget(
    db: &PgPool,
    tenant_id: &str,
    account_id: Uuid,
) -> Result<i64, SalesError> {
    let max_active_contacts: Option<i16> = sqlx::query_scalar(
        "SELECT max_active_contacts FROM sales_accounts WHERE id = $1 AND tenant_id = $2",
    )
    .bind(account_id)
    .bind(tenant_id)
    .fetch_optional(db)
    .await
    .map_err(db_error)?;

    Ok(weekly_budget_for(max_active_contacts))
}

/// Does the account still have weekly budget for another touch?
///
/// Counts the account's live reservations (`state = 'reserved'`) plus its
/// realised touches over the rolling 7-day window and compares against the
/// account budget. This is the early, read-only pre-gate used by [`decide`];
/// the authoritative admission is the atomic reservation inside
/// [`revalidate_execution_tx`], which serialises the same count and the insert
/// under the account row lock.
pub async fn check_frequency_budget(
    db: &PgPool,
    tenant_id: &str,
    account_id: Uuid,
) -> Result<bool, SalesError> {
    let budget = account_weekly_budget(db, tenant_id, account_id).await?;
    let mut conn = db.acquire().await.map_err(db_error)?;
    let live = count_live_reservations_conn(&mut conn, account_id).await?;
    let realised = count_realised_touches_conn(&mut conn, tenant_id, account_id).await?;
    Ok(live + realised < budget)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn failure() -> Vec<String> {
        vec!["suppressed: someone opted out".to_string()]
    }

    #[test]
    fn any_failure_denies_regardless_of_mode_or_legal_verdict() {
        for mode in AutonomyMode::all() {
            assert_eq!(
                combine(&failure(), mode, ContactDecision::Allowed),
                Enforcement::Denied,
                "mode {mode} must not execute with failures"
            );
        }
    }

    #[test]
    fn autonomous_guarded_with_all_gates_passed_executes() {
        assert_eq!(
            combine(
                &[],
                AutonomyMode::AutonomousGuarded,
                ContactDecision::Allowed
            ),
            Enforcement::Execute
        );
    }

    #[test]
    fn legal_approval_required_forces_a_human_even_in_autonomous_mode() {
        assert_eq!(
            combine(
                &[],
                AutonomyMode::AutonomousGuarded,
                ContactDecision::ApprovalRequired
            ),
            Enforcement::AwaitApproval
        );
    }

    #[test]
    fn legal_prohibited_denies_even_without_recorded_failures() {
        assert_eq!(
            combine(
                &[],
                AutonomyMode::AutonomousGuarded,
                ContactDecision::Prohibited
            ),
            Enforcement::Denied
        );
    }

    #[test]
    fn assisted_and_approval_required_modes_await_approval() {
        for mode in [AutonomyMode::Assisted, AutonomyMode::ApprovalRequired] {
            assert_eq!(
                combine(&[], mode, ContactDecision::Allowed),
                Enforcement::AwaitApproval
            );
        }
    }

    #[test]
    fn shadow_mode_shadows_clean_decisions() {
        assert_eq!(
            combine(&[], AutonomyMode::Shadow, ContactDecision::Allowed),
            Enforcement::Shadowed
        );
    }

    #[test]
    fn disabled_mode_denies_clean_decisions() {
        assert_eq!(
            combine(&[], AutonomyMode::Disabled, ContactDecision::Allowed),
            Enforcement::Denied
        );
    }

    #[test]
    fn weekly_budget_default_is_documented() {
        assert_eq!(DEFAULT_WEEKLY_ACCOUNT_BUDGET, 15);
        assert_eq!(WEEKLY_BUDGET_PER_ACTIVE_CONTACT, 5);
    }

    #[test]
    fn address_rule_accepts_only_valid_and_risky() {
        for sendable in ["valid", "risky"] {
            assert!(
                email_point_is_sendable(sendable),
                "'{sendable}' must be sendable"
            );
        }
        // The adversarial states: `unknown`/`unverified` are regressions too,
        // not only the literal `invalid`.
        for refused in [
            "unverified",
            "unknown",
            "invalid",
            "",
            "VALID",
            "Risky",
            "valid ",
        ] {
            assert!(
                !email_point_is_sendable(refused),
                "'{refused}' must not be sendable"
            );
        }
    }

    #[test]
    fn weekly_budget_uses_the_larger_of_default_and_per_contact_room() {
        assert_eq!(weekly_budget_for(None), DEFAULT_WEEKLY_ACCOUNT_BUDGET);
        assert_eq!(weekly_budget_for(Some(1)), DEFAULT_WEEKLY_ACCOUNT_BUDGET);
        assert_eq!(weekly_budget_for(Some(3)), DEFAULT_WEEKLY_ACCOUNT_BUDGET);
        assert_eq!(
            weekly_budget_for(Some(4)),
            4 * WEEKLY_BUDGET_PER_ACTIVE_CONTACT
        );
        assert_eq!(
            weekly_budget_for(Some(10)),
            10 * WEEKLY_BUDGET_PER_ACTIVE_CONTACT
        );
    }

    #[test]
    fn owned_policy_input_borrows_correctly() {
        let evidence_id = Uuid::new_v4();
        let owned = ContactPolicyInputOwned {
            account_id: None,
            contact_id: None,
            contact_point_id: None,
            recipient_country: Some("EE".into()),
            country_confidence: 0.9,
            contact_type: "b2b_professional".into(),
            channel: "email".into(),
            source: Some("public_registry".into()),
            purpose: Some("sales_outreach".into()),
            has_existing_relationship: false,
            consent_status: Some("granted".into()),
            soft_opt_in: false,
            legitimate_interest_assessed: true,
            subscriber_type: SubscriberType::NaturalPerson,
            consent_evidence_id: Some(evidence_id),
            existing_customer: false,
            similar_product_basis: false,
            collection_opt_out_offered_at: None,
        };
        let borrowed = owned.as_borrowed("tenant-a");
        assert_eq!(borrowed.tenant_id, "tenant-a");
        assert_eq!(borrowed.recipient_country.as_deref(), Some("EE"));
        assert_eq!(borrowed.contact_type, "b2b_professional");
        assert_eq!(borrowed.channel, "email");
        assert_eq!(borrowed.consent_status, Some("granted"));
        // The §103¹ inputs survive the owned→borrowed conversion.
        assert_eq!(borrowed.subscriber_type, SubscriberType::NaturalPerson);
        assert_eq!(borrowed.consent_evidence_id, Some(evidence_id));
        assert!(!borrowed.existing_customer);
        assert!(!borrowed.similar_product_basis);
        assert!(borrowed.collection_opt_out_offered_at.is_none());
        assert_eq!(
            legal_policy::resolve_jurisdiction(
                borrowed.recipient_country.as_deref(),
                borrowed.country_confidence
            ),
            legal_policy::EU_POLICY_KEY
        );
    }

    #[test]
    fn policy_input_serialization_carries_the_section_1031_inputs() {
        // These are the fields `legal_policy::record` writes into
        // `sales_contact_policy_decisions.inputs` (JSONB), so the audit trail
        // shows exactly which §103¹ facts the verdict was derived from.
        let evidence_id = Uuid::new_v4();
        let collected_at = Utc::now();
        let owned = ContactPolicyInputOwned {
            account_id: None,
            contact_id: Some(Uuid::new_v4()),
            contact_point_id: None,
            recipient_country: Some("EE".into()),
            country_confidence: 0.9,
            contact_type: "b2c".into(),
            channel: "email".into(),
            source: Some("form:newsletter".into()),
            purpose: Some("outbound_sales".into()),
            has_existing_relationship: true,
            consent_status: Some("granted".into()),
            soft_opt_in: true,
            legitimate_interest_assessed: false,
            subscriber_type: SubscriberType::NaturalPerson,
            consent_evidence_id: Some(evidence_id),
            existing_customer: true,
            similar_product_basis: true,
            collection_opt_out_offered_at: Some(collected_at),
        };

        let json = serde_json::to_value(&owned).expect("policy input serializes");
        assert_eq!(json["subscriber_type"], "natural_person");
        assert_eq!(json["consent_evidence_id"], evidence_id.to_string());
        assert_eq!(json["existing_customer"], true);
        assert_eq!(json["similar_product_basis"], true);
        let collected_round_trip: DateTime<Utc> =
            serde_json::from_value(json["collection_opt_out_offered_at"].clone())
                .expect("the collection opt-out timestamp round-trips");
        assert_eq!(collected_round_trip, collected_at);
        assert_eq!(json["purpose"], "outbound_sales");
        assert_eq!(json["jurisdiction"], serde_json::Value::Null);
        // No separate `jurisdiction` key exists: the resolved jurisdiction is
        // derived from `recipient_country` + `country_confidence`, exactly as
        // `legal_policy::evaluate` does.
    }

    #[test]
    fn owned_policy_input_deserializes_legacy_packets_to_fail_closed_defaults() {
        // A Decision Packet recorded before the §103¹ fields existed must not
        // become unreadable at revalidation time; it deserializes to the
        // fail-closed defaults instead.
        let legacy = serde_json::json!({
            "account_id": null,
            "contact_id": null,
            "contact_point_id": null,
            "recipient_country": "EE",
            "country_confidence": 0.9,
            "contact_type": "b2b_professional",
            "channel": "email",
            "source": "public_registry",
            "purpose": "sales_outreach",
            "has_existing_relationship": false,
            "consent_status": null,
            "soft_opt_in": true,
            "legitimate_interest_assessed": true
        });
        let owned: ContactPolicyInputOwned =
            serde_json::from_value(legacy).expect("legacy packet must deserialize");
        assert_eq!(owned.subscriber_type, SubscriberType::Unknown);
        assert_eq!(owned.consent_evidence_id, None);
        assert!(!owned.existing_customer);
        assert!(!owned.similar_product_basis);
        assert_eq!(owned.collection_opt_out_offered_at, None);

        // And the fail-closed default means the legacy packet can never be
        // executed autonomously off an old soft-opt-in boolean.
        let borrowed = owned.as_borrowed("tenant-a");
        let policy = JurisdictionPolicy {
            id: Uuid::new_v4(),
            jurisdiction: legal_policy::EU_POLICY_KEY.into(),
            channel: "email".into(),
            contact_type: "b2b_professional".into(),
            decision: ContactDecision::Allowed,
            basis: "soft_opt_in".into(),
            required_disclosure: serde_json::json!({}),
            version: 1,
        };
        assert_ne!(
            legal_policy::decide_with_state(Some(&policy), true, &borrowed).decision,
            ContactDecision::Allowed
        );
    }

    #[test]
    fn enforcement_wire_strings_match_the_201_check_constraint() {
        // Exactly the four values `chk_sales_decisions_enforcement` allows.
        assert_eq!(Enforcement::Execute.as_str(), "execute");
        assert_eq!(Enforcement::Denied.as_str(), "denied");
        assert_eq!(Enforcement::Shadowed.as_str(), "shadowed");
        assert_eq!(Enforcement::AwaitApproval.as_str(), "await_approval");
    }

    #[test]
    fn enforcement_parse_inverts_as_str_and_rejects_unknown_values() {
        for enforcement in [
            Enforcement::Execute,
            Enforcement::Denied,
            Enforcement::Shadowed,
            Enforcement::AwaitApproval,
        ] {
            assert_eq!(Enforcement::parse(enforcement.as_str()), Some(enforcement));
        }
        assert_eq!(
            Enforcement::parse(" AWAIT_APPROVAL "),
            Some(Enforcement::AwaitApproval)
        );
        assert_eq!(Enforcement::parse("maybe"), None);
        assert_eq!(Enforcement::parse(""), None);
    }

    #[test]
    fn review_status_is_pending_only_for_await_approval() {
        assert_eq!(
            review_status_for(Enforcement::AwaitApproval),
            Some("pending")
        );
        assert_eq!(review_status_for(Enforcement::Denied), Some("not_required"));
        assert_eq!(
            review_status_for(Enforcement::Shadowed),
            Some("not_required")
        );
        assert_eq!(
            review_status_for(Enforcement::Execute),
            Some("not_required")
        );
    }

    #[test]
    fn only_external_actions_need_execution_revalidation() {
        let internal = [
            DecisionAction::DoNothing,
            DecisionAction::Wait,
            DecisionAction::CollectEvidence,
            DecisionAction::Enrich,
            DecisionAction::VerifyEmail,
            DecisionAction::ResearchCompany,
            DecisionAction::OperatorTask,
            DecisionAction::Nurture,
            DecisionAction::StopPermanently,
        ];
        for action in internal {
            assert!(!action.is_external_send(), "{action} must be internal");
            assert!(!action_is_external(action.as_str()));
        }
        let external = [
            DecisionAction::Contact,
            DecisionAction::FollowUp,
            DecisionAction::ChangeAngle,
            DecisionAction::AskForReferral,
            DecisionAction::BookMeeting,
        ];
        for action in external {
            assert!(action.is_external_send(), "{action} must be external");
            assert!(action_is_external(action.as_str()));
        }
        // Unknown/forward-compatible action names fail closed.
        assert!(action_is_external("future_action"));
        assert!(action_is_external(""));
    }

    #[test]
    fn internal_action_short_circuit_is_clean() {
        let result = internal_action_revalidation();
        assert!(result.allowed);
        assert!(result.reasons.is_empty());
        assert!(result.checked.is_empty());
    }

    #[test]
    fn legal_revalidation_matrix() {
        // Prohibited denies regardless of any recorded review state.
        for review in [
            None,
            Some("pending"),
            Some("approved"),
            Some("rejected"),
            Some("not_required"),
        ] {
            let failure =
                legal_revalidation_failure(ContactDecision::Prohibited, "policy prohibits", review);
            assert!(
                failure.is_some_and(|reason| reason.starts_with("legal_policy_prohibited")),
                "review {review:?} must not rescue a prohibited verdict"
            );
        }

        // ApprovalRequired needs a human approval CURRENT for this policy.
        for review in [
            None,
            Some("pending"),
            Some("rejected"),
            Some("not_required"),
        ] {
            assert!(
                legal_revalidation_failure(
                    ContactDecision::ApprovalRequired,
                    "unknown jurisdiction",
                    review
                )
                .is_some_and(|reason| reason.starts_with("legal_policy_approval_required")),
                "review {review:?} is not an approval"
            );
        }
        assert!(legal_revalidation_failure(
            ContactDecision::ApprovalRequired,
            "unknown jurisdiction",
            Some("approved")
        )
        .is_none());

        // Allowed never fails.
        assert!(
            legal_revalidation_failure(ContactDecision::Allowed, "legitimate interest", None)
                .is_none()
        );
    }

    // -----------------------------------------------------------------------
    // Live-database tests (ignored by default)
    // -----------------------------------------------------------------------

    /// A complete, cleanly executable send fixture on the canonically
    /// provisioned test database.
    struct SendFixture {
        tenant: String,
        account_id: Uuid,
        contact_id: Uuid,
        contact_point_id: Uuid,
        enrollment_id: Uuid,
        step_execution_id: Uuid,
        sender_id: Uuid,
        policy_id: Uuid,
        jurisdiction: String,
        email: String,
    }

    impl SendFixture {
        fn policy_input(&self) -> ContactPolicyInputOwned {
            ContactPolicyInputOwned {
                account_id: Some(self.account_id),
                contact_id: Some(self.contact_id),
                contact_point_id: Some(self.contact_point_id),
                recipient_country: Some(self.jurisdiction.clone()),
                country_confidence: 0.95,
                contact_type: "b2b_professional".into(),
                channel: "email".into(),
                source: Some("public_registry".into()),
                purpose: Some("sales_outreach".into()),
                has_existing_relationship: false,
                consent_status: None,
                soft_opt_in: false,
                legitimate_interest_assessed: true,
                // The fixture declares the legal-person classification
                // explicitly; the production loader passes Unknown because no
                // canonical source exists yet.
                subscriber_type: SubscriberType::LegalPerson,
                consent_evidence_id: None,
                existing_customer: false,
                similar_product_basis: false,
                collection_opt_out_offered_at: None,
            }
        }
    }

    /// Canonically provisioned pool (never a raw `TEST_DATABASE_URL`).
    async fn live_pool(test_name: &str) -> Option<PgPool> {
        crate::test_db::canonical_test_pool(test_name).await
    }

    /// A 2-letter jurisdiction code unique enough that its policy row cannot
    /// collide with another test or a previous run on the shared database.
    fn unique_jurisdiction() -> String {
        let bytes = *Uuid::new_v4().as_bytes();
        format!(
            "{}{}",
            (b'A' + (bytes[0] % 26)) as char,
            (b'A' + (bytes[1] % 26)) as char
        )
    }

    async fn seed_send_fixture(
        pool: &PgPool,
        tenant: &str,
        policy_decision: &str,
        policy_basis: &str,
    ) -> SendFixture {
        let account_id = Uuid::new_v4();
        let contact_id = Uuid::new_v4();
        let contact_point_id = Uuid::new_v4();
        let sequence_id = Uuid::new_v4();
        let version_id = Uuid::new_v4();
        let step_id = Uuid::new_v4();
        let enrollment_id = Uuid::new_v4();
        let step_execution_id = Uuid::new_v4();
        let sender_id = Uuid::new_v4();
        // The policy row's id is generated by the shared race-safe helper, and
        // the code it actually used is what the fixture must key on.
        let jurisdiction = unique_jurisdiction();
        let email = format!("prospect-{contact_id}@example.com");

        sqlx::query(
            "INSERT INTO sales_accounts (id, tenant_id, company, domain, max_active_contacts) \
             VALUES ($1, $2, 'Revalidation Co', $3, 2)",
        )
        .bind(account_id)
        .bind(tenant)
        .bind(format!("{account_id}.example"))
        .execute(pool)
        .await
        .expect("insert sales_accounts");

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
        .expect("insert sales_contacts");

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
        .expect("insert sales_contact_points");

        sqlx::query(
            "INSERT INTO sales_sequences (id, tenant_id, name, status) \
             VALUES ($1, $2, 'Revalidation Sequence', 'active')",
        )
        .bind(sequence_id)
        .bind(tenant)
        .execute(pool)
        .await
        .expect("insert sales_sequences");

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
        .expect("insert sales_sequence_versions");

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
        .expect("insert sales_sequence_steps");

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
        .expect("insert sales_enrollments");

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
        .bind(format!("reval-{step_execution_id}"))
        .execute(pool)
        .await
        .expect("insert sales_step_executions");

        sqlx::query(
            "INSERT INTO sales_sender_identities \
                 (id, tenant_id, pool, from_email, from_name, domain, status, daily_limit) \
             VALUES ($1, $2, 'sales_outbound', $3, 'Fixture Sender', 'example.com', 'active', 200)",
        )
        .bind(sender_id)
        .bind(tenant)
        .bind(format!("sender-{sender_id}@example.com"))
        .execute(pool)
        .await
        .expect("insert sales_sender_identities");

        sqlx::query(
            "INSERT INTO sales_sender_health \
                 (id, tenant_id, sender_identity_id, health_score, state) \
             VALUES (gen_random_uuid(), $1, $2, 0.99, 'healthy')",
        )
        .bind(tenant)
        .bind(sender_id)
        .execute(pool)
        .await
        .expect("insert sales_sender_health");

        sqlx::query(
            "INSERT INTO sales_autonomy_state (tenant_id, mode) \
             VALUES ($1, 'autonomous_guarded')",
        )
        .bind(tenant)
        .execute(pool)
        .await
        .expect("insert sales_autonomy_state");

        // Race-safe: the 2-letter fixture namespace is small and shared across
        // parallel test processes, so the policy is inserted optimistically and
        // the code actually taken is the one the fixture must then use.
        let jurisdiction =
            crate::test_db::insert_unique_jurisdiction_policy(pool, policy_decision, policy_basis)
                .await;
        let policy_id: uuid::Uuid = sqlx::query_scalar(
            "SELECT id FROM sales_jurisdiction_policies WHERE jurisdiction = $1",
        )
        .bind(&jurisdiction)
        .fetch_one(pool)
        .await
        .expect("the inserted policy must be readable");

        SendFixture {
            tenant: tenant.to_string(),
            account_id,
            contact_id,
            contact_point_id,
            enrollment_id,
            step_execution_id,
            sender_id,
            policy_id,
            jurisdiction,
            email,
        }
    }

    fn send_context(fixture: &SendFixture, policy: ContactPolicyInputOwned) -> DecisionContext {
        DecisionContext {
            tenant_id: fixture.tenant.clone(),
            account_id: Some(fixture.account_id),
            contact_id: Some(fixture.contact_id),
            contact_point_id: Some(fixture.contact_point_id),
            enrollment_id: None,
            action: DecisionAction::FollowUp,
            score: OpportunityScore::default(),
            expected_value_eur: 250.0,
            confidence: 0.9,
            evidence_ids: Vec::new(),
            selected_offer: None,
            selected_sequence: None,
            selected_variant: None,
            selected_sender: None,
            model_version: Some("test".into()),
            policy: Some(policy),
            rationale: "live-DB revalidation fixture".into(),
            execute_after: None,
        }
    }

    /// Attach the decision to the step execution, the canonical carrier the
    /// live worker populates.
    async fn link_decision_to_step_execution(
        pool: &PgPool,
        decision_id: Uuid,
        step_execution_id: Uuid,
    ) {
        sqlx::query("UPDATE sales_step_executions SET decision_id = $1 WHERE id = $2")
            .bind(decision_id)
            .bind(step_execution_id)
            .execute(pool)
            .await
            .expect("link decision to step execution");
    }

    #[ignore = "requires local PostgreSQL with the canonical sales schema"]
    #[tokio::test]
    async fn revalidation_denies_a_contact_suppressed_after_the_decision() {
        let Some(pool) =
            live_pool("decision_engine::tests::revalidation_denies_suppressed_after_decision")
                .await
        else {
            return;
        };
        let tenant = crate::test_db::unique_test_tenant("reval-suppress");
        let fixture = seed_send_fixture(&pool, &tenant, "allowed", "legitimate_interest").await;

        let outcome = decide(&pool, send_context(&fixture, fixture.policy_input()))
            .await
            .unwrap();
        assert_eq!(
            outcome.enforcement,
            Enforcement::Execute,
            "fixture must start executable: {:?}",
            outcome.block_reasons
        );

        // The recipient unsubscribes AFTER the decision was made (and would
        // have been approved).
        sqlx::query("INSERT INTO sales_unsubscribes (tenant_id, email) VALUES ($1, $2)")
            .bind(&tenant)
            .bind(&fixture.email)
            .execute(&pool)
            .await
            .unwrap();

        let revalidation = revalidate_execution(&pool, outcome.decision_id)
            .await
            .unwrap();
        assert!(
            !revalidation.allowed,
            "an unsubscribe must defeat the old decision"
        );
        assert!(
            revalidation
                .reasons
                .iter()
                .any(|reason| reason.starts_with("suppressed:")),
            "reasons: {:?}",
            revalidation.reasons
        );
        assert!(revalidation.checked.contains(&GATE_SUPPRESSION));
    }

    #[ignore = "requires local PostgreSQL with the canonical sales schema"]
    #[tokio::test]
    async fn revalidation_denies_a_human_reply_that_arrived_after_the_decision() {
        let Some(pool) =
            live_pool("decision_engine::tests::revalidation_denies_human_reply_after_decision")
                .await
        else {
            return;
        };
        let tenant = crate::test_db::unique_test_tenant("reval-reply");
        let fixture = seed_send_fixture(&pool, &tenant, "allowed", "legitimate_interest").await;
        let outcome = decide(&pool, send_context(&fixture, fixture.policy_input()))
            .await
            .unwrap();
        assert_eq!(
            outcome.enforcement,
            Enforcement::Execute,
            "fixture must start executable: {:?}",
            outcome.block_reasons
        );
        link_decision_to_step_execution(&pool, outcome.decision_id, fixture.step_execution_id)
            .await;

        sqlx::query("UPDATE sales_enrollments SET has_human_reply = TRUE WHERE id = $1")
            .bind(fixture.enrollment_id)
            .execute(&pool)
            .await
            .unwrap();

        let revalidation = revalidate_execution(&pool, outcome.decision_id)
            .await
            .unwrap();
        assert!(
            !revalidation.allowed,
            "a human reply must defeat the old decision"
        );
        assert!(
            revalidation
                .reasons
                .iter()
                .any(|reason| reason.starts_with("human_reply:")),
            "reasons: {:?}",
            revalidation.reasons
        );
        assert!(revalidation.checked.contains(&GATE_HUMAN_REPLY));
    }

    #[ignore = "requires local PostgreSQL with the canonical sales schema"]
    #[tokio::test]
    async fn prohibited_policy_denies_even_under_autonomous_guarded() {
        let Some(pool) =
            live_pool("decision_engine::tests::prohibited_policy_denies_autonomous_guarded").await
        else {
            return;
        };
        let tenant = crate::test_db::unique_test_tenant("reval-prohibited");
        let fixture = seed_send_fixture(&pool, &tenant, "prohibited", "not_permitted").await;
        let outcome = decide(&pool, send_context(&fixture, fixture.policy_input()))
            .await
            .unwrap();
        assert_eq!(outcome.enforcement, Enforcement::Denied);
        assert!(
            outcome
                .block_reasons
                .iter()
                .any(|reason| reason.starts_with("legal_policy_prohibited")),
            "reasons: {:?}",
            outcome.block_reasons
        );

        // A policy that flips to prohibited after an allowed decision also
        // defeats the old decision at revalidation time.
        let allowed_tenant = crate::test_db::unique_test_tenant("reval-flip");
        let allowed =
            seed_send_fixture(&pool, &allowed_tenant, "allowed", "legitimate_interest").await;
        let first = decide(&pool, send_context(&allowed, allowed.policy_input()))
            .await
            .unwrap();
        assert_eq!(first.enforcement, Enforcement::Execute);

        sqlx::query(
            "UPDATE sales_jurisdiction_policies \
             SET decision = 'prohibited', basis = 'not_permitted' WHERE id = $1",
        )
        .bind(allowed.policy_id)
        .execute(&pool)
        .await
        .unwrap();

        let revalidation = revalidate_execution(&pool, first.decision_id)
            .await
            .unwrap();
        assert!(!revalidation.allowed);
        assert!(
            revalidation
                .reasons
                .iter()
                .any(|reason| reason.starts_with("legal_policy_prohibited")),
            "reasons: {:?}",
            revalidation.reasons
        );
    }

    #[ignore = "requires local PostgreSQL with the canonical sales schema"]
    #[tokio::test]
    async fn checked_names_every_gate_that_was_re_read() {
        let Some(pool) = live_pool("decision_engine::tests::checked_names_every_gate").await else {
            return;
        };
        let tenant = crate::test_db::unique_test_tenant("reval-checked");
        let fixture = seed_send_fixture(&pool, &tenant, "allowed", "legitimate_interest").await;
        let outcome = {
            // The live worker resolves and stores the sender before the packet
            // is written; the fixture must too so the sender gate is evaluated.
            let mut ctx = send_context(&fixture, fixture.policy_input());
            ctx.selected_sender = Some(fixture.sender_id);
            decide(&pool, ctx).await.unwrap()
        };
        assert_eq!(
            outcome.enforcement,
            Enforcement::Execute,
            "fixture must start executable: {:?}",
            outcome.block_reasons
        );
        link_decision_to_step_execution(&pool, outcome.decision_id, fixture.step_execution_id)
            .await;

        let revalidation = revalidate_execution(&pool, outcome.decision_id)
            .await
            .unwrap();
        assert!(
            revalidation.allowed,
            "clean fixture must revalidate: {:?}",
            revalidation.reasons
        );
        assert_eq!(
            revalidation.checked,
            vec![
                GATE_KILL_SWITCH,
                GATE_AUTONOMY_MODE,
                GATE_SUPPRESSION,
                GATE_CONTACT_POINT_SUPPRESSED,
                GATE_ADDRESS_VERIFICATION,
                GATE_HUMAN_REPLY,
                GATE_SENDER_HEALTH,
                GATE_FREQUENCY_BUDGET,
                GATE_LEGAL_POLICY,
            ]
        );
    }

    #[ignore = "requires local PostgreSQL with the canonical sales schema"]
    #[tokio::test]
    async fn revalidation_of_a_missing_decision_is_an_error() {
        let Some(pool) = live_pool("decision_engine::tests::missing_decision").await else {
            return;
        };
        let missing = Uuid::new_v4();
        let err = revalidate_execution(&pool, missing).await.unwrap_err();
        assert!(
            matches!(err, SalesError::InvalidInput(_)),
            "unexpected error: {err}"
        );
        assert!(err.to_string().contains(&missing.to_string()));
    }

    /// The adversarial address case: the point was `valid` when the decision
    /// was made and regresses to `unverified` before approval. The weaker
    /// "reject only literal `invalid`" rule let this through; the canonical
    /// rule (`email_point_is_sendable`) refuses it.
    #[ignore = "requires local PostgreSQL with the canonical sales schema"]
    #[tokio::test]
    async fn revalidation_refuses_a_contact_that_regressed_from_valid_to_unverified() {
        let Some(pool) = live_pool("decision_engine::tests::revalidation_refuses_unverified").await
        else {
            return;
        };
        let tenant = crate::test_db::unique_test_tenant("reval-regress");
        let fixture = seed_send_fixture(&pool, &tenant, "allowed", "legitimate_interest").await;
        let outcome = decide(&pool, send_context(&fixture, fixture.policy_input()))
            .await
            .unwrap();
        assert_eq!(
            outcome.enforcement,
            Enforcement::Execute,
            "fixture must start executable: {:?}",
            outcome.block_reasons
        );
        link_decision_to_step_execution(&pool, outcome.decision_id, fixture.step_execution_id)
            .await;

        // The provider re-checks the address after the decision: `valid` →
        // `unverified` (not `invalid`).
        sqlx::query("UPDATE sales_contact_points SET verification = 'unverified' WHERE id = $1")
            .bind(fixture.contact_point_id)
            .execute(&pool)
            .await
            .unwrap();

        let revalidation = revalidate_execution(&pool, outcome.decision_id)
            .await
            .unwrap();
        assert!(
            !revalidation.allowed,
            "an unverified address must be refused, not just an invalid one"
        );
        assert!(
            revalidation
                .reasons
                .iter()
                .any(|reason| reason.starts_with("contact_point_not_sendable")),
            "reasons: {:?}",
            revalidation.reasons
        );
        assert!(revalidation.checked.contains(&GATE_ADDRESS_VERIFICATION));
    }

    /// Budget = 1, 16 concurrent workers: the atomic reservation admits exactly
    /// one. The old count-and-compare gate let every worker see the same
    /// remaining slot.
    ///
    /// The budget is injected as 1 because the production formula floors at
    /// [`DEFAULT_WEEKLY_ACCOUNT_BUDGET`]; the account row lock held by each
    /// worker is the real serialisation point, so the test exercises the same
    /// code path the formula-driven budget does.
    #[ignore = "requires local PostgreSQL with the canonical sales schema"]
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_budget_of_one_admits_exactly_one_of_sixteen_concurrent_workers() {
        let Some(pool) = live_pool("decision_engine::tests::budget_race").await else {
            return;
        };
        let tenant = crate::test_db::unique_test_tenant("budget-race");
        let account_id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO sales_accounts (id, tenant_id, company, domain, max_active_contacts) \
             VALUES ($1, $2, 'Budget Race Co', $3, 1)",
        )
        .bind(account_id)
        .bind(&tenant)
        .bind(format!("{account_id}.example"))
        .execute(&pool)
        .await
        .expect("insert sales_accounts");

        let mut handles = Vec::new();
        for worker in 0..16u32 {
            let pool = pool.clone();
            let tenant = tenant.clone();
            handles.push(tokio::spawn(async move {
                let mut tx = pool.begin().await.expect("begin");
                // Acquire the account row lock first, exactly as the admission
                // contract requires; the count and insert then cannot race.
                lock_account_budget_conn(&mut tx, &tenant, account_id)
                    .await
                    .expect("lock account");
                let admitted = reserve_account_touch_with_budget_conn(
                    &mut tx,
                    &tenant,
                    account_id,
                    &format!("sa-send:budget-race-{worker}"),
                    1,
                )
                .await
                .expect("reserve");
                tx.commit().await.expect("commit");
                admitted
            }));
        }

        let mut admitted = 0usize;
        for handle in handles {
            if handle.await.expect("join") {
                admitted += 1;
            }
        }
        assert_eq!(
            admitted, 1,
            "exactly one of 16 concurrent workers may take the last slot"
        );

        let live: i64 = sqlx::query_scalar(
            "SELECT COUNT(*)::bigint FROM sales_account_touch_reservations \
             WHERE account_id = $1 AND state = 'reserved'",
        )
        .bind(account_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        let total: i64 = sqlx::query_scalar(
            "SELECT COUNT(*)::bigint FROM sales_account_touch_reservations WHERE account_id = $1",
        )
        .bind(account_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(live, 1);
        assert_eq!(total, 1, "refusals must not leave reservation rows behind");

        // The account row is the FK parent; deleting it cascades the reservations.
        sqlx::query("DELETE FROM sales_accounts WHERE id = $1")
            .bind(account_id)
            .execute(&pool)
            .await
            .ok();
    }

    /// A reservation is consumed once per logical send and can be released
    /// when the send never happens.
    #[ignore = "requires local PostgreSQL with the canonical sales schema"]
    #[tokio::test]
    async fn revalidation_reserves_once_per_logical_send_and_release_frees_the_slot() {
        let Some(pool) = live_pool("decision_engine::tests::reservation_lifecycle").await else {
            return;
        };
        let tenant = crate::test_db::unique_test_tenant("reserve-life");
        let fixture = seed_send_fixture(&pool, &tenant, "allowed", "legitimate_interest").await;
        let outcome = decide(&pool, send_context(&fixture, fixture.policy_input()))
            .await
            .unwrap();
        assert_eq!(outcome.enforcement, Enforcement::Execute);
        link_decision_to_step_execution(&pool, outcome.decision_id, fixture.step_execution_id)
            .await;

        let first = revalidate_execution(&pool, outcome.decision_id)
            .await
            .unwrap();
        assert!(
            first.allowed,
            "clean send must revalidate: {:?}",
            first.reasons
        );

        let expected_key = format!("sa-send:{}", fixture.step_execution_id);
        let (state, logical_send): (String, String) = sqlx::query_as(
            "SELECT state, logical_send FROM sales_account_touch_reservations \
             WHERE account_id = $1",
        )
        .bind(fixture.account_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(state, "reserved");
        assert_eq!(logical_send, expected_key);

        // Re-validating the same logical send is idempotent: one row, still
        // admitted, no second slot consumed.
        let again = revalidate_execution(&pool, outcome.decision_id)
            .await
            .unwrap();
        assert!(again.allowed, "{:?}", again.reasons);
        let rows: i64 = sqlx::query_scalar(
            "SELECT COUNT(*)::bigint FROM sales_account_touch_reservations \
             WHERE account_id = $1",
        )
        .bind(fixture.account_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(rows, 1);

        // A pre-send refusal releases the slot...
        let mut tx = pool.begin().await.unwrap();
        settle_account_touch_tx(&mut tx, &tenant, fixture.account_id, &expected_key, false)
            .await
            .unwrap();
        tx.commit().await.unwrap();
        let state: String = sqlx::query_scalar(
            "SELECT state FROM sales_account_touch_reservations WHERE account_id = $1",
        )
        .bind(fixture.account_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(state, "released");

        // ... and a released logical send may be admitted again.
        let third = revalidate_execution(&pool, outcome.decision_id)
            .await
            .unwrap();
        assert!(third.allowed, "{:?}", third.reasons);
        let (state, rows): (String, i64) = sqlx::query_as(
            "SELECT MIN(state), COUNT(*)::bigint FROM sales_account_touch_reservations \
             WHERE account_id = $1",
        )
        .bind(fixture.account_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(state, "reserved");
        assert_eq!(rows, 1);
    }
}
