//! Decisive attacker handling: the additive post-policy decision stage of
//! the marks plane (change.md 3.3.3).
//!
//! The stage runs after [`crate::policy::RiskPolicy::decide_with_hysteresis`]
//! and only when a marks reader is wired into the engine; the plain
//! decision path of an unwired engine is byte-identical to before. Three
//! rules, in order:
//!
//! 1. A mark on one of the requesting identity's own dimensions (session,
//!    principal, agent or the ASN bucket) escalates the chosen action to
//!    at least the ladder's maximum challenge rung (Argon64). StepUp and
//!    Deny keep their rank. A saturated argon backend re-escalates the
//!    rung to the interactive step-up exactly like the policy's own
//!    capacity check.
//! 2. A mark combined with corroborating attacker evidence on the same
//!    request denies for the remaining mark TTL. Corroborating evidence
//!    means bad-proof, replay or malformed traffic at the policy's
//!    corroboration floor, or decoy evidence. The deny holds while
//!    `now < last_ms + mark_ttl_ms`, and the decision's retry hint
//!    carries the saturated remainder.
//! 3. A mark on the login target the request presents (a login attempt
//!    against an attacked account) maps to StepUp and nothing stronger.
//!    Target evidence never escalates the requesting identity's own
//!    dimensions beyond the interactive step-up, so a victim can always
//!    finish logging in.
//!
//! Victim-protection invariant (property-tested): when only target-side
//! evidence fires, the final action equals the plain action or StepUp,
//! never Argon64 and never Deny.
//!
//! A mark outside its TTL window is inert: the stage treats it as absent
//! for both the rung and the deny rule, the belt to the store's own key
//! expiry for stores without one.
//!
//! Quarantine selection (change.md 1.3 and 3.3.4, see
//! [`crate::quarantine`]): when `quarantine_spam_marks` is true (the
//! engine's decision-plane posture) and every in-TTL own mark is the
//! server-confirmed spam kind with no corroboration and no target mark,
//! a plain Allow decision quarantines instead of escalating: the action
//! stays Allow (wire identical to allow end to end, same rung and
//! pricing), the decision carries the quarantine disposition and the
//! spam_mark_quarantine reason. A spam mark never runs the Argon64
//! floor: above the Allow band the plain action stands (severity wins)
//! with the ordinary marked_identity reason, and the deny, target and
//! non-spam-mark rules keep their precedence over quarantine. The
//! legacy corpus (attacker-denial-vectors.json) pins rules 1 to 3 with
//! the selection off; the quarantine corpus (quarantine-vectors.json)
//! pins the selection and its precedence with it on.

use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::Arc;

use crate::action::RiskAction;
use crate::asn::AsnDataset;
use crate::outcomes::{MarkDimension, MarkRecord, OutcomeMarksStore};
use crate::policy::RiskReason;
use crate::resources::ResourcePressure;
use crate::signals::SignalVector;
use crate::RiskDecision;
use crate::RiskError;

/// The whole-window default: the store's 90-day mark TTL in milliseconds.
pub const DEFAULT_MARK_TTL_MS: u64 = crate::redis::DEFAULT_MARK_TTL_SECS * 1000;

/// The corroborating-evidence floor of the policy's own hard overrides
/// (`bad_proof >= 300`, `replay >= 300`, `malformed >= 300`). The stage
/// corroborates a mark with the identical threshold, so the two cores
/// and the policy never disagree about what counts as attacker
/// evidence.
pub const CORROBORATION_FLOOR: u16 = 300;

/// The D3.5 target-attack threshold: a target whose live failure count
/// reaches this many spread failures is under attack, and the next
/// login claiming it sees the interactive step-up (never a lockout).
pub const TARGET_ATTACK_THRESHOLD: u32 = 5;

/// The scope failure-ratio pressure floor for first-attempt login
/// escalation: at/above this `global_pressure` signal (or global level
/// [`SCOPE_PRESSURE_LEVEL`]) every login escalates to the interactive
/// step-up, not only the attacked target's.
pub const SCOPE_PRESSURE_FLOOR: u16 = 300;

/// The global hysteresis level at which scope pressure escalates
/// first-attempt logins (the ratchet's first rung already means the
/// scope failure ratio is running hot).
pub const SCOPE_PRESSURE_LEVEL: u8 = 1;

/// Below this argon capacity the strongest rung re-escalates to StepUp
/// (the policy's own capacity check, applied to the mark rung too).
const ARGON_CAPACITY_FLOOR: u16 = 300;

/// The marks view of one request: the marks found on the requesting
/// identity's own dimensions plus, when the request presents a login
/// target, the mark on that target dimension.
///
/// The view is a resolved value: whatever produced it (the reader, a
/// test, the simulator) has already decided which dimensions the request
/// addresses. [`MarksView::read`] builds it from any marks store.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MarksView {
    own: Vec<(MarkDimension, MarkRecord)>,
    target: Option<MarkRecord>,
    /// First-attempt prevention evidence (P0-1): a valid credential on
    /// its first attempt, with no marks anywhere. Default neutral.
    first_attempt: FirstAttemptEvidence,
}

impl MarksView {
    /// The view from already-resolved marks: own entries keep the given
    /// dimension order.
    pub fn from_parts(own: Vec<(MarkDimension, MarkRecord)>, target: Option<MarkRecord>) -> Self {
        MarksView {
            own,
            target,
            first_attempt: FirstAttemptEvidence::zero(),
        }
    }

    /// Replaces the target entry with a reader-derived record: the shape
    /// a deployment compiles from the target-failure signal of the
    /// evidence plane when no target mark was written to the store.
    pub fn with_target(mut self, target: Option<MarkRecord>) -> Self {
        self.target = target;
        self
    }

    /// Attaches the first-attempt prevention evidence (P0-1).
    pub fn with_first_attempt(mut self, evidence: FirstAttemptEvidence) -> Self {
        self.first_attempt = evidence;
        self
    }

    /// The attached first-attempt evidence (neutral when none).
    pub fn first_attempt(&self) -> &FirstAttemptEvidence {
        &self.first_attempt
    }

    /// Reads the view from a marks store: one lookup per own dimension
    /// (absent marks simply drop out) plus the target lookup when the
    /// request presents a target pseudonym. The target record is the
    /// written mark when one exists; otherwise it is compiled from the
    /// live engine state (the target-failure counter the outcome bridge
    /// maintains): a count at or above [`TARGET_ATTACK_THRESHOLD`]
    /// produces the `targetUnderAttack` record the stage maps to exactly
    /// the interactive step-up. Callers never inject this record — the
    /// engine's own failure state is the sole source.
    ///
    /// # Errors
    ///
    /// [`RiskError::Store`] when any lookup fails; the caller treats an
    /// unreadable view fail-closed via [`apply_unreadable`].
    pub fn read(
        store: &dyn OutcomeMarksStore,
        own: &[(MarkDimension, String)],
        target: Option<&str>,
    ) -> Result<MarksView, RiskError> {
        let mut marks = Vec::new();
        for (dimension, id) in own {
            if let Some(record) = store.read_mark(dimension.key(), id)? {
                marks.push((*dimension, record));
            }
        }
        let target = match target {
            None => None,
            Some(id) => match store.read_mark(MarkDimension::Target.key(), id)? {
                Some(record) => Some(record),
                None => {
                    let state = store.read_target_state(id)?;
                    (state.fails >= TARGET_ATTACK_THRESHOLD).then(|| MarkRecord {
                        kind: "targetUnderAttack".to_string(),
                        last_kind: "targetUnderAttack".to_string(),
                        count: state.fails as i64,
                        first_ms: state.first_ms,
                        last_ms: state.last_ms,
                    })
                }
            },
        };
        Ok(MarksView {
            own: marks,
            target,
            first_attempt: FirstAttemptEvidence::zero(),
        })
    }

    /// The own-dimension marks still inside their TTL window.
    pub fn own_in_ttl(&self, now_ms: u64, ttl_ms: u64) -> Vec<&(MarkDimension, MarkRecord)> {
        self.own
            .iter()
            .filter(|(_, record)| in_ttl(record, now_ms, ttl_ms))
            .collect()
    }

    /// The freshest own-dimension mark inside its TTL window (the one
    /// backing the longest remaining deny window), or `None`.
    pub fn freshest_own_in_ttl(&self, now_ms: u64, ttl_ms: u64) -> Option<&MarkRecord> {
        self.own_in_ttl(now_ms, ttl_ms)
            .into_iter()
            .map(|(_, record)| record)
            .max_by_key(|record| record.last_ms)
    }

    /// The target mark when it is still inside its TTL window.
    pub fn target_in_ttl(&self, now_ms: u64, ttl_ms: u64) -> Option<&MarkRecord> {
        self.target
            .as_ref()
            .filter(|record| in_ttl(record, now_ms, ttl_ms))
    }

    /// True when at least one own dimension carries an in-TTL mark.
    pub fn own_marked(&self, now_ms: u64, ttl_ms: u64) -> bool {
        self.freshest_own_in_ttl(now_ms, ttl_ms).is_some()
    }
}

/// A mark is live while `now < last_ms + ttl` (strict, matching the deny
/// window). A negative `last_ms` (a corrupt record) is expired, never a
/// zero-epoch live mark.
fn in_ttl(record: &MarkRecord, now_ms: u64, ttl_ms: u64) -> bool {
    match u64::try_from(record.last_ms) {
        Ok(last) => now_ms < last.saturating_add(ttl_ms),
        Err(_) => false,
    }
}

/// The request identity picture the engine hands a marks reader: the
/// scope, the source address and the session and principal pseudonyms
/// the engine derived. The reader's implementation adds the dimensions
/// only the deployment resolves (the agent name, the ASN bucket, the
/// login target of the form being submitted).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MarksRequest {
    pub scope: u32,
    pub source_ip: IpAddr,
    /// The session pseudonym (32 hex chars), or `None` without a session.
    pub session: Option<String>,
    /// The principal pseudonym (32 hex chars), or `None` when the request
    /// is unauthenticated.
    pub principal: Option<String>,
}

/// The first-attempt prevention evidence (D3.5 P0-1): the signals that
/// must stop a valid stolen credential on its very first attempt, before
/// any failure has accumulated anywhere. Each flag is independent
/// evidence for the interactive step-up (never a deny — the legitimate
/// owner must always be able to finish the login):
///
/// - `novel_network`: the principal has never been seen from this
///   network bucket (/64 or IPv4) and the account has no prior trusted
///   network, so the login cannot be vouched for by any network history.
/// - `breached_credential`: the presented credential is known-breached
///   (caller-supplied corpus verdict — same step-up-worthy shape as
///   honeypot evidence).
/// - `scope_pressure`: the scope failure-ratio pressure is running at or
///   above [`SCOPE_PRESSURE_FLOOR`] / [`SCOPE_PRESSURE_LEVEL`], so every
///   first-attempt login escalates — not only the attacked target's.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FirstAttemptEvidence {
    pub novel_network: bool,
    pub breached_credential: bool,
    pub scope_pressure: bool,
}

impl FirstAttemptEvidence {
    /// Neutral: no first-attempt evidence at all.
    pub fn zero() -> FirstAttemptEvidence {
        FirstAttemptEvidence::default()
    }

    /// True when any first-attempt prevention signal fired.
    pub fn requires_step_up(&self) -> bool {
        self.novel_network || self.breached_credential || self.scope_pressure
    }
}

/// The marks reader seam of the engine wiring: given the identity picture
/// the engine derived, answer the marks view of the request and the TTL
/// window the stage must honor (the reader's store may carry a custom
/// mark TTL).
///
/// The default implementation over a marks store is
/// [`StoreMarksReader`]; deployments that resolve the agent, ASN or
/// target dimensions supply their own.
pub trait MarksReader: Send + Sync {
    /// The marks view of one request.
    ///
    /// # Errors
    ///
    /// [`RiskError::Store`] when the underlying marks surface fails; the
    /// engine then applies [`apply_unreadable`] fail-closed.
    fn request_marks(&self, request: &MarksRequest) -> Result<MarksView, RiskError>;

    /// The mark TTL window (ms) the stage honors for this reader's store.
    fn mark_ttl_ms(&self) -> u64;
}

/// The store-backed default reader: the session and principal marks of
/// the engine-derived pseudonyms, plus the agent mark for a configured
/// agent name and the ASN bucket mark when a dataset is attached. It
/// resolves no target: a login form's target enters through a reader
/// that sees the submitted identifier.
#[derive(Clone)]
pub struct StoreMarksReader {
    store: Arc<dyn OutcomeMarksStore + Send + Sync>,
    agent: Option<String>,
    asn: Option<Arc<AsnDataset>>,
    mark_ttl_ms: u64,
}

impl StoreMarksReader {
    /// Reads the session and principal marks (and any configured extras)
    /// from `store`.
    pub fn new(store: Arc<dyn OutcomeMarksStore + Send + Sync>) -> StoreMarksReader {
        StoreMarksReader {
            store,
            agent: None,
            asn: None,
            mark_ttl_ms: DEFAULT_MARK_TTL_MS,
        }
    }

    /// Addresses the agent dimension under the configured agent name.
    pub fn with_agent(mut self, agent: &str) -> StoreMarksReader {
        self.agent = Some(agent.to_string());
        self
    }

    /// Addresses the ASN dimension with the bucket id the dataset
    /// resolves for the request's source address.
    pub fn with_asn_dataset(mut self, asn: Arc<AsnDataset>) -> StoreMarksReader {
        self.asn = Some(asn);
        self
    }

    /// Overrides the TTL window the stage honors.
    pub fn with_mark_ttl_ms(mut self, mark_ttl_ms: u64) -> StoreMarksReader {
        self.mark_ttl_ms = mark_ttl_ms;
        self
    }
}

impl MarksReader for StoreMarksReader {
    fn request_marks(&self, request: &MarksRequest) -> Result<MarksView, RiskError> {
        let mut own: Vec<(MarkDimension, String)> = Vec::new();
        if let Some(session) = &request.session {
            own.push((MarkDimension::Session, session.clone()));
        }
        if let Some(principal) = &request.principal {
            own.push((MarkDimension::Principal, principal.clone()));
        }
        if let Some(agent) = &self.agent {
            own.push((MarkDimension::Agent, agent.clone()));
        }
        if let Some(dataset) = &self.asn {
            own.push((MarkDimension::Asn, dataset.bucket_id(request.source_ip)));
        }
        MarksView::read(self.store.as_ref(), &own, None)
    }

    fn mark_ttl_ms(&self) -> u64 {
        self.mark_ttl_ms
    }
}

/// True when the request's own evidence corroborates a mark: bad-proof,
/// replay or malformed traffic at the policy's corroboration floor, or
/// any decoy evidence (a honeypot event kind or the v2 context's
/// honeypot flag, supplied by the caller as `decoy_evidence`).
pub fn corroborated(s: &SignalVector, decoy_evidence: bool) -> bool {
    s.bad_proof >= CORROBORATION_FLOOR
        || s.malformed >= CORROBORATION_FLOOR
        || s.replay >= CORROBORATION_FLOOR
        || decoy_evidence
}

/// The decisive stage: combines the plain decision with the request's
/// marks view. Pure; the plain decision's score, band, policy version,
/// model revision, global level and decision id pass through untouched.
///
/// Stage reasons prepend exactly like the policy's hard overrides, then
/// deduplicate and cap at 4. `quarantine_spam_marks` arms the
/// quarantine selection (the engine's decision-plane posture); false
/// keeps the legacy rules exactly, the posture the shared
/// attacker-denial corpus pins.
#[allow(clippy::too_many_arguments)]
pub fn apply(
    plain: RiskDecision,
    view: &MarksView,
    corroborated: bool,
    now_ms: u64,
    mark_ttl_ms: u64,
    resources: &ResourcePressure,
    quarantine_spam_marks: bool,
) -> RiskDecision {
    let mut decision = plain;
    let mut stage_reasons: Vec<RiskReason> = Vec::new();
    let mut quarantined = false;

    // Rule 1 and 2: the requesting identity's own marks.
    if let Some(mark) = view.freshest_own_in_ttl(now_ms, mark_ttl_ms) {
        if corroborated {
            decision.action = RiskAction::Deny;
            let deadline = u64::try_from(mark.last_ms).unwrap_or(0) + mark_ttl_ms;
            // in_ttl guaranteed deadline > now, so the subtraction cannot
            // underflow; the u32 wire field saturates like the cooldown.
            decision.retry_after_ms = Some((deadline - now_ms).min(u32::MAX as u64) as u32);
            stage_reasons.push(RiskReason::CorroboratedAbuse);
        } else if quarantine_spam_marks
            && decision.action == RiskAction::Allow
            && crate::quarantine::selects(view, false, now_ms, mark_ttl_ms)
        {
            // The quarantine disposition: server-confirmed spam, clean
            // request, plain Allow. The action stays Allow (never a rung
            // change, never a capacity re-escalation), so the issued
            // challenge is wire-identical to allow.
            quarantined = true;
            stage_reasons.push(RiskReason::SpamMarkQuarantine);
        } else {
            stage_reasons.push(RiskReason::MarkedIdentity);
            // The Argon64 floor belongs to the non-spam marks: a
            // spam-only identity is the quarantine plane's subject, so
            // above the Allow band its plain action stands (severity
            // wins) and the stage adds no rung of its own.
            let floor_applies =
                !quarantine_spam_marks || !crate::quarantine::spam_only(view, now_ms, mark_ttl_ms);
            if floor_applies && decision.action.rank() < RiskAction::Argon64.rank() {
                decision.action = RiskAction::Argon64;
                if resources.argon_capacity < ARGON_CAPACITY_FLOOR {
                    decision.action = RiskAction::StepUp;
                    stage_reasons.push(RiskReason::CapacityPressure);
                }
            }
        }
    }

    // Rule 3: the presented target. The guard is the victim protection:
    // target evidence tops out at StepUp, so an attacked account's owner
    // can always finish the interactive login. The step-up outranks the
    // quarantine disposition, so a target mark drops it.
    if view.target_in_ttl(now_ms, mark_ttl_ms).is_some() {
        quarantined = false;
        if decision.action.rank() < RiskAction::StepUp.rank() {
            decision.action = RiskAction::StepUp;
        }
        stage_reasons.push(RiskReason::TargetUnderAttack);
    }

    // Rule 4: first-attempt prevention (P0-1). A valid credential on its
    // very first attempt carries no marks and no target history, so rules
    // 1-3 stay silent — exactly the D3.5 hole. Any of the three signals
    // (novel network with no prior trusted network, a known-breached
    // credential, or scope failure-ratio pressure at/above the floor)
    // forces the interactive step-up before any session credit, and tops
    // out at StepUp like target evidence: the legitimate owner must
    // always be able to finish the login (never Deny, never a rung).
    if view.first_attempt.requires_step_up() {
        quarantined = false;
        if decision.action.rank() < RiskAction::StepUp.rank() {
            decision.action = RiskAction::StepUp;
        }
        if view.first_attempt.novel_network {
            stage_reasons.push(RiskReason::NovelNetwork);
        }
        if view.first_attempt.breached_credential {
            stage_reasons.push(RiskReason::BreachedCredential);
        }
        if view.first_attempt.scope_pressure {
            stage_reasons.push(RiskReason::GlobalAttack);
        }
    }

    merge_stage_reasons(&mut decision, stage_reasons);
    decision.quarantined = quarantined;
    decision
}

/// The fail-closed fallback for an unreadable marks surface: the request
/// is treated as a marked identity with an unknown window, so the action
/// floors at the maximum challenge rung (capacity-aware) but no deny is
/// fabricated from evidence that could not be read.
pub fn apply_unreadable(
    plain: RiskDecision,
    now_ms: u64,
    resources: &ResourcePressure,
) -> RiskDecision {
    let marked = MarkRecord {
        kind: "unreadable".to_string(),
        last_kind: "unreadable".to_string(),
        count: 1,
        first_ms: now_ms as i64,
        last_ms: now_ms as i64,
    };
    let view = MarksView::from_parts(vec![(MarkDimension::Session, marked)], None);
    // The unreadable picture never quarantines: its synthetic mark is
    // not the spam kind, so the fail-closed floor applies.
    apply(plain, &view, false, now_ms, 1, resources, false)
}

/// Prepends the stage reasons to the decision's reasons, deduplicates
/// and caps at 4 (the policy's own assembly order).
fn merge_stage_reasons(decision: &mut RiskDecision, stage_reasons: Vec<RiskReason>) {
    if stage_reasons.is_empty() {
        return;
    }
    let mut reasons = stage_reasons;
    reasons.extend(decision.reasons_vec());
    let mut seen = HashSet::new();
    reasons.retain(|reason| seen.insert(*reason));
    reasons.truncate(4);
    let mut out = [None; 4];
    for (slot, reason) in out.iter_mut().zip(reasons) {
        *slot = Some(reason);
    }
    decision.reasons = out;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::outcomes::MarkDimension;
    use crate::policy::RiskPolicy;
    use crate::resources::ResourcePressure;
    use crate::signals::SignalVector;
    use serde_json::json;
    use std::collections::HashMap;
    use std::sync::Mutex;

    const T0: u64 = 1_700_000_000_000;
    const TTL: u64 = 7_776_000_000;
    const SESSION: &str = "c7b3e1f9a5d24708b6e0c8a2f4d69123";
    const TARGET: &str = "5e2a9b4c1d7f38e6a0b5c9d2e4f6a813";

    fn mark(kind: &str, last_ms: i64) -> MarkRecord {
        MarkRecord {
            kind: kind.to_string(),
            last_kind: kind.to_string(),
            count: 1,
            first_ms: last_ms,
            last_ms,
        }
    }

    fn policy() -> RiskPolicy {
        RiskPolicy::from_config(
            3,
            &json!({
                "version": 3,
                "weights": {
                    "source_fast": 190, "source_slow": 110, "subnet_fast": 80,
                    "issue_debt": 150, "bad_proof": 220, "malformed": 260,
                    "replay": 320, "action_failure": 120, "scope_switch": 60,
                    "global_pressure": 170, "network_risk": 100,
                    "trust_credit": 130, "principal_credit": 100
                },
                "scopes": {
                    "1": { "base_risk": 100, "minimum": "allow", "post_solve_check": true, "degraded": "sha20" }
                },
                "global_floors": { "0": "allow", "1": "sha16", "2": "sha18", "3": "sha20", "4": "sha20" }
            }),
        )
        .expect("config parses")
    }

    fn healthy() -> ResourcePressure {
        ResourcePressure::default()
    }

    fn plain(score: u16) -> RiskDecision {
        policy().decide(1, score, &SignalVector::zero(), &healthy(), 0, T0, 0)
    }

    fn session_view(last_ms: i64) -> MarksView {
        MarksView::from_parts(
            vec![(MarkDimension::Session, mark("accountBanned", last_ms))],
            None,
        )
    }

    fn target_view() -> MarksView {
        MarksView::from_parts(vec![], Some(mark("accountBanned", T0 as i64)))
    }

    #[test]
    fn unmarked_view_keeps_the_plain_decision() {
        let plain = plain(500);
        let out = apply(
            plain.clone(),
            &MarksView::default(),
            true,
            T0,
            TTL,
            &healthy(),
            false,
        );
        assert_eq!(out.action, RiskAction::Sha20);
        assert_eq!(out.reasons, plain.reasons);
        assert_eq!(out.retry_after_ms, None);
    }

    #[test]
    fn marked_identity_escalates_to_the_maximum_rung() {
        for score in [0u16, 100, 500, 700] {
            let out = apply(
                plain(score),
                &session_view(T0 as i64),
                false,
                T0,
                TTL,
                &healthy(),
                false,
            );
            assert_eq!(out.action, RiskAction::Argon64, "score {score}");
            assert!(out.has_reason(RiskReason::MarkedIdentity));
            assert_eq!(out.retry_after_ms, None);
        }
    }

    #[test]
    fn marked_identity_never_downgrades_step_up_or_deny() {
        let step = apply(
            plain(950),
            &session_view(T0 as i64),
            false,
            T0,
            TTL,
            &healthy(),
            false,
        );
        assert_eq!(step.action, RiskAction::StepUp);
        let deny = apply(
            plain(980),
            &session_view(T0 as i64),
            false,
            T0,
            TTL,
            &healthy(),
            false,
        );
        assert_eq!(deny.action, RiskAction::Deny);
        assert!(deny.has_reason(RiskReason::MarkedIdentity));
    }

    #[test]
    fn marked_identity_respects_argon_capacity() {
        let saturated = ResourcePressure {
            argon_capacity: 299,
            ..Default::default()
        };
        let out = apply(
            plain(100),
            &session_view(T0 as i64),
            false,
            T0,
            TTL,
            &saturated,
            false,
        );
        assert_eq!(out.action, RiskAction::StepUp);
        assert!(out.has_reason(RiskReason::MarkedIdentity));
        assert!(out.has_reason(RiskReason::CapacityPressure));
    }

    #[test]
    fn corroborated_mark_denies_for_the_remaining_ttl() {
        let signals = SignalVector {
            bad_proof: 400,
            ..Default::default()
        };
        let base = policy().decide(1, 100, &signals, &healthy(), 0, T0, 0);
        let out = apply(
            base,
            &session_view(T0 as i64),
            true,
            T0 + 1_000,
            TTL,
            &healthy(),
            false,
        );
        assert_eq!(out.action, RiskAction::Deny);
        assert!(out.has_reason(RiskReason::CorroboratedAbuse));
        // 90 days minus one second exceeds the u32 wire field: saturated.
        assert_eq!(out.retry_after_ms, Some(u32::MAX));

        // A near-expired mark leaves a short, exact retry hint.
        let now = T0 + TTL - 5_000;
        let out = apply(
            plain(100),
            &session_view(T0 as i64),
            true,
            now,
            TTL,
            &healthy(),
            false,
        );
        assert_eq!(out.action, RiskAction::Deny);
        assert_eq!(out.retry_after_ms, Some(5_000));
    }

    #[test]
    fn corroborated_evidence_without_a_mark_stays_plain() {
        let signals = SignalVector {
            replay: 700,
            ..Default::default()
        };
        let base = policy().decide(1, 100, &signals, &healthy(), 0, T0, 0);
        let out = apply(
            base.clone(),
            &MarksView::default(),
            true,
            T0,
            TTL,
            &healthy(),
            false,
        );
        assert_eq!(out.action, base.action);
        assert!(!out.has_reason(RiskReason::CorroboratedAbuse));
    }

    #[test]
    fn expired_mark_is_inert() {
        let now = T0 + TTL;
        let out = apply(
            plain(500),
            &session_view(T0 as i64),
            true,
            now,
            TTL,
            &healthy(),
            false,
        );
        assert_eq!(out.action, RiskAction::Sha20);
        assert!(!out.has_reason(RiskReason::MarkedIdentity));
        // A corrupt negative timestamp never reads as a live mark.
        let corrupt = apply(
            plain(500),
            &session_view(-1),
            true,
            now,
            TTL,
            &healthy(),
            false,
        );
        assert_eq!(corrupt.action, RiskAction::Sha20);
    }

    #[test]
    fn attacked_target_maps_a_claimant_to_step_up_only() {
        let out = apply(
            plain(100),
            &target_view(),
            false,
            T0,
            TTL,
            &healthy(),
            false,
        );
        assert_eq!(out.action, RiskAction::StepUp);
        assert!(out.has_reason(RiskReason::TargetUnderAttack));
        // Even a plain Argon64 band tops out at StepUp for the victim.
        let out = apply(
            plain(700),
            &target_view(),
            false,
            T0,
            TTL,
            &healthy(),
            false,
        );
        assert_eq!(out.action, RiskAction::StepUp);
        // A different claimant presents no target: the plain action stands.
        let out = apply(
            plain(100),
            &MarksView::default(),
            false,
            T0,
            TTL,
            &healthy(),
            false,
        );
        assert_eq!(out.action, RiskAction::Allow);
    }

    #[test]
    fn own_mark_deny_wins_over_the_target_step_up() {
        let view = MarksView::from_parts(
            vec![(MarkDimension::Session, mark("fraudConfirmed", T0 as i64))],
            Some(mark("accountBanned", T0 as i64)),
        );
        let out = apply(plain(100), &view, true, T0, TTL, &healthy(), false);
        assert_eq!(out.action, RiskAction::Deny);
        assert!(out.has_reason(RiskReason::CorroboratedAbuse));
        assert!(out.has_reason(RiskReason::TargetUnderAttack));
    }

    #[test]
    fn freshest_mark_backs_the_deny_window() {
        let view = MarksView::from_parts(
            vec![
                (MarkDimension::Session, mark("spamReported", T0 as i64)),
                (
                    MarkDimension::Asn,
                    mark("accountBanned", (T0 + 60_000) as i64),
                ),
            ],
            None,
        );
        let out = apply(plain(100), &view, true, T0 + 61_000, TTL, &healthy(), false);
        assert_eq!(out.action, RiskAction::Deny);
        // The ASN mark written a minute later owns the window.
        assert_eq!(out.retry_after_ms, Some(u32::MAX));
    }

    /// The victim-protection property: with only target-side evidence,
    /// the final action equals the plain action or StepUp, and the score,
    /// band and policy metadata pass through untouched.
    #[test]
    fn target_only_evidence_never_escalates_past_step_up() {
        let p = policy();
        for scope in [1u32] {
            for score in (0..=1000u16).step_by(25) {
                for level in 0..=4u8 {
                    let base = p.decide(
                        scope,
                        score,
                        &SignalVector::zero(),
                        &healthy(),
                        level,
                        T0,
                        0,
                    );
                    let out = apply(
                        base.clone(),
                        &target_view(),
                        true,
                        T0,
                        TTL,
                        &healthy(),
                        false,
                    );
                    assert!(
                        out.action == base.action || out.action == RiskAction::StepUp,
                        "scope {scope} score {score} level {level}: {:?} -> {:?}",
                        base.action,
                        out.action
                    );
                    assert_eq!(out.score, base.score);
                    assert_eq!(out.band, base.band);
                    assert_eq!(out.retry_after_ms, None);
                }
            }
        }
    }

    /// The marked-identity property: an in-TTL own mark on any dimension
    /// floors the action at the maximum rung or denies outright.
    #[test]
    fn own_mark_never_stays_below_the_maximum_rung() {
        let p = policy();
        for dimension in [
            MarkDimension::Principal,
            MarkDimension::Session,
            MarkDimension::Agent,
            MarkDimension::Asn,
        ] {
            for score in (0..=1000u16).step_by(50) {
                let base = p.decide(1, score, &SignalVector::zero(), &healthy(), 0, T0, 0);
                let view =
                    MarksView::from_parts(vec![(dimension, mark("spamReported", T0 as i64))], None);
                let out = apply(base, &view, false, T0, TTL, &healthy(), false);
                assert!(
                    out.action.rank() >= RiskAction::Argon64.rank(),
                    "{dimension:?} score {score}: {:?}",
                    out.action
                );
            }
        }
    }

    #[test]
    fn unreadable_marks_floor_fail_closed_without_fabricating_a_deny() {
        let out = apply_unreadable(plain(100), T0, &healthy());
        assert_eq!(out.action, RiskAction::Argon64);
        assert!(out.has_reason(RiskReason::MarkedIdentity));
        assert_eq!(out.retry_after_ms, None);
        let saturated = ResourcePressure {
            argon_capacity: 0,
            ..Default::default()
        };
        let out = apply_unreadable(plain(100), T0, &saturated);
        assert_eq!(out.action, RiskAction::StepUp);
        // A plain Deny stays a Deny even when the surface is unreadable.
        let out = apply_unreadable(plain(980), T0, &healthy());
        assert_eq!(out.action, RiskAction::Deny);
    }

    #[test]
    fn corroboration_floor_matches_the_policy_thresholds() {
        let below = SignalVector {
            bad_proof: 299,
            malformed: 299,
            replay: 299,
            ..Default::default()
        };
        assert!(!corroborated(&below, false));
        for field in [
            SignalVector {
                bad_proof: 300,
                ..Default::default()
            },
            SignalVector {
                malformed: 300,
                ..Default::default()
            },
            SignalVector {
                replay: 300,
                ..Default::default()
            },
        ] {
            assert!(corroborated(&field, false));
        }
        assert!(corroborated(&SignalVector::zero(), true));
    }

    /// The in-memory marks store twin of the PHP stub: reads and writes
    /// keyed by dimension and identifier, with the marks.lua write
    /// semantics (max-severity kind, separate latest kind, event-id
    /// idempotency).
    #[derive(Default)]
    struct MapStore {
        marks: Mutex<HashMap<(String, String), MarkRecord>>,
        seen_events: Mutex<std::collections::HashSet<String>>,
    }

    impl OutcomeMarksStore for MapStore {
        fn mark_key(&self, dimension: &str, id: &str) -> Result<String, RiskError> {
            Ok(format!("mark:{{kiwi:test}}:{dimension}:{id}"))
        }
        fn write_mark(
            &self,
            dimension: &str,
            id: &str,
            kind: &str,
            now_ms: u64,
            event_id: &str,
        ) -> Result<i64, RiskError> {
            if !event_id.is_empty()
                && !self
                    .seen_events
                    .lock()
                    .unwrap()
                    .insert(format!("{dimension}:{id}:{event_id}"))
            {
                let marks = self.marks.lock().unwrap();
                return Ok(marks
                    .get(&(dimension.to_string(), id.to_string()))
                    .map(|m| m.count)
                    .unwrap_or(0));
            }
            let mut marks = self.marks.lock().unwrap();
            let entry = marks
                .entry((dimension.to_string(), id.to_string()))
                .or_insert(MarkRecord {
                    kind: kind.to_string(),
                    last_kind: kind.to_string(),
                    count: 0,
                    first_ms: now_ms as i64,
                    last_ms: now_ms as i64,
                });
            if crate::outcomes::mark_kind_severity(kind)
                > crate::outcomes::mark_kind_severity(&entry.kind)
            {
                entry.kind = kind.to_string();
            }
            entry.last_kind = kind.to_string();
            entry.count += 1;
            entry.last_ms = now_ms as i64;
            Ok(entry.count)
        }
        fn read_mark(&self, dimension: &str, id: &str) -> Result<Option<MarkRecord>, RiskError> {
            Ok(self
                .marks
                .lock()
                .unwrap()
                .get(&(dimension.to_string(), id.to_string()))
                .cloned())
        }
        fn forget_marks(&self, dimension: &str, id: &str) -> Result<u32, RiskError> {
            Ok(self
                .marks
                .lock()
                .unwrap()
                .remove(&(dimension.to_string(), id.to_string()))
                .map_or(0, |_| 1))
        }
    }

    #[test]
    fn read_drops_absent_dimensions_and_resolves_the_target() {
        let store = MapStore::default();
        store
            .write_mark("session", SESSION, "accountBanned", T0, "")
            .unwrap();
        store
            .write_mark("target", TARGET, "fraudConfirmed", T0, "")
            .unwrap();
        let view = MarksView::read(
            &store,
            &[
                (MarkDimension::Session, SESSION.to_string()),
                (
                    MarkDimension::Principal,
                    "9f1c4a7e2b8d63f05a1e9c4d7b2e6f18".to_string(),
                ),
                (MarkDimension::Asn, "a64496".to_string()),
            ],
            Some(TARGET),
        )
        .unwrap();
        assert_eq!(view.own.len(), 1);
        assert_eq!(view.own[0].0, MarkDimension::Session);
        assert!(view.target.is_some());
        assert!(view.own_marked(T0, TTL));
        // A different claimant presents a different target: no target mark.
        let other = MarksView::read(&store, &[], Some("0f1e2d3c4b5a69788796a5b4c3d2e1f0")).unwrap();
        assert!(other.target.is_none());
    }

    #[test]
    fn store_reader_addresses_session_principal_agent_and_asn() {
        let store = Arc::new(MapStore::default());
        store
            .write_mark("session", SESSION, "accountBanned", T0, "")
            .unwrap();
        store
            .write_mark("asn", "a64496", "fraudConfirmed", T0, "")
            .unwrap();
        let mut reader = StoreMarksReader::new(store).with_agent("backfill-bot");
        reader = reader.with_mark_ttl_ms(60_000);
        assert_eq!(reader.mark_ttl_ms(), 60_000);
        let request = MarksRequest {
            scope: 1,
            source_ip: "192.0.2.10".parse().unwrap(),
            session: Some(SESSION.to_string()),
            principal: None,
        };
        let view = reader.request_marks(&request).unwrap();
        // No dataset attached: the ASN dimension is absent, the agent is
        // unmarked, so exactly the session mark resolves.
        assert_eq!(view.own.len(), 1);
        assert_eq!(view.own[0].0, MarkDimension::Session);
        assert!(view.target.is_none());
    }

    /// The shared attacker-denial vectors (protocol/risk-v1/
    /// attacker-denial-vectors.json): both cores must resolve every
    /// vector to the identical action, retry hint and ordered reason
    /// list. The attacker-vectors path variable overrides the file
    /// location.
    #[test]
    fn attacker_denial_vectors_match_exactly() {
        let path = std::env::var("RISK_ATTACKER_VECTORS_PATH").unwrap_or_else(|_| {
            concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../protocol/risk-v1/attacker-denial-vectors.json"
            )
            .to_string()
        });
        let raw = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("attacker-denial vectors not readable at {path}: {e}"));
        let vectors: serde_json::Value = serde_json::from_str(&raw).expect("vectors parse");
        assert_eq!(vectors["version"], 1);
        let policy = RiskPolicy::from_config(3, &vectors["policy"]).expect("policy parses");
        let ttl = vectors["mark_ttl_ms"].as_u64().expect("ttl");

        let seen = vectors["vectors"].as_array().expect("vectors array");
        assert!(!seen.is_empty());
        for vector in seen {
            let why = vector["why"].as_str().unwrap_or("vector");
            // Sparse signal objects default their missing fields to zero,
            // exactly like the PHP SignalVector::fromArray reader.
            let mut signals_value = serde_json::json!({
                "source_fast": 0, "source_slow": 0, "subnet_fast": 0,
                "issue_debt": 0, "bad_proof": 0, "malformed": 0,
                "replay": 0, "action_failure": 0, "scope_switch": 0,
                "global_pressure": 0, "network_risk": 0,
                "trust_credit": 0, "principal_credit": 0
            });
            if let Some(fields) = vector["signals"].as_object() {
                for (field, value) in fields {
                    signals_value[field] = value.clone();
                }
            }
            let signals: SignalVector =
                serde_json::from_value(signals_value).expect("signals parse");
            let resources = ResourcePressure {
                argon_capacity: vector["argon_capacity"].as_u64().expect("argon") as u16,
                issuance_capacity: vector["issuance_capacity"].as_u64().expect("issuance") as u16,
            };
            let plain = policy.decide(
                vector["scope"].as_u64().expect("scope") as u32,
                vector["score"].as_u64().expect("score") as u16,
                &signals,
                &resources,
                vector["global_level"].as_u64().expect("level") as u8,
                vector["now_ms"].as_u64().expect("now"),
                0,
            );
            let mut own = Vec::new();
            for (dimension, record) in vector["own_marks"].as_object().expect("own marks object") {
                let dimension = MarkDimension::from_key(dimension).expect("known dimension");
                own.push((dimension, record_from_json(record)));
            }
            let target = vector
                .get("target_mark")
                .filter(|record| !record.is_null())
                .map(record_from_json);
            let view = MarksView::from_parts(own, target);
            let out = apply(
                plain,
                &view,
                vector["corroborated"].as_bool().expect("corroborated flag"),
                vector["now_ms"].as_u64().expect("now"),
                ttl,
                &resources,
                // The legacy corpus pins the stage with the quarantine
                // selection off; the quarantine corpus pins it on.
                false,
            );
            assert_eq!(
                vector["expected_action"].as_str().expect("action"),
                out.action.as_str(),
                "action mismatch: {why}"
            );
            let expected_retry = match vector.get("expected_retry_after_ms") {
                None | Some(serde_json::Value::Null) => None,
                Some(v) => Some(v.as_u64().expect("retry") as u32),
            };
            assert_eq!(expected_retry, out.retry_after_ms, "retry mismatch: {why}");
            let expected_reasons: Vec<&str> = vector["expected_reasons"]
                .as_array()
                .expect("reasons")
                .iter()
                .map(|r| r.as_str().expect("reason"))
                .collect();
            let actual: Vec<&str> = out.reasons.iter().flatten().map(|r| r.as_str()).collect();
            assert_eq!(expected_reasons, actual, "reasons mismatch: {why}");
        }
    }

    fn record_from_json(record: &serde_json::Value) -> MarkRecord {
        let kind = record["kind"].as_str().expect("kind").to_string();
        MarkRecord {
            last_kind: record
                .get("last_kind")
                .and_then(|v| v.as_str())
                .unwrap_or(&kind)
                .to_string(),
            kind,
            count: record["count"].as_i64().expect("count"),
            first_ms: record["first_ms"].as_i64().expect("first"),
            last_ms: record["last_ms"].as_i64().expect("last"),
        }
    }
}
