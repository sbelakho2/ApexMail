//! Reply policy — layer 3 of 3, the ONLY place that decides what happens next.
//!
//! A classification is an observation; this module turns it into an action.
//! It is a pure function ([`decide`]) so the entire table is unit-testable
//! without a database, and the processor persists exactly what it returns.
//!
//! # The table
//!
//! | Disposition | Enrollment state | Queued work | Other effects |
//! |---|---|---|---|
//! | `Unsubscribe` | `suppressed` | cancelled | permanent suppression |
//! | `Complaint` | `suppressed` | cancelled | permanent suppression + sender-health penalty |
//! | `BounceHard` | `suppressed` | cancelled | permanent suppression + contact point invalidated |
//! | `OutOfOffice` | `waiting` | KEPT (rescheduled) | resume after the stated return date, else default wait |
//! | `BounceSoft` | `waiting` | KEPT | resume after the soft-bounce window |
//! | `Positive`, `MeetingRequest`, `Question`, `Referral` | `replied` | cancelled | route to the high-intent workflow |
//! | `NotInterested` | `completed` | cancelled | stop (no unsubscribe upsert) |
//! | `Unknown` | `paused` | cancelled | stop the next outbound touch pending classification |
//!
//! `has_human_reply` is set for every disposition whose
//! [`ReplyDisposition::stops_normal_sequence`] is true — i.e. everything
//! except `OutOfOffice` and `BounceSoft`.

use chrono::{DateTime, Duration, Utc};

use super::deterministic::ooo_resume_at;
use super::types::{ActionType, ReplyDisposition, SuggestedAction, Urgency};

/// Minimum confidence for a classification to auto-act.
///
/// Below this threshold the policy downgrades the disposition to `Unknown`:
/// the next outbound touch is stopped pending classification, but NO
/// irreversible action (suppression, contact-point invalidation,
/// sender-health penalty) is taken. A wrong suppression is customer-visible
/// and hard to undo; stopping a send is not. This is deliberately independent
/// from the operator-configured `auto_suppress_confidence_threshold`, which
/// can only make auto-execution stricter, never looser.
pub const MIN_AUTO_ACTION_CONFIDENCE: f64 = 0.7;

/// Default resume delay for an out-of-office reply with no parseable return
/// date (also the policy's stated default wait).
pub const DEFAULT_OOO_WAIT_DAYS: i64 = 7;

/// The enrollment states from the canonical `sales_enrollments.state` CHECK.
/// Mirrored here for the same reason [`ReplyDisposition`] is mirrored: the
/// worker does not depend on `sales-autopilot`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnrollmentState {
    Pending,
    Active,
    Waiting,
    Paused,
    Replied,
    MeetingBooked,
    Completed,
    Suppressed,
    Failed,
}

impl EnrollmentState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Active => "active",
            Self::Waiting => "waiting",
            Self::Paused => "paused",
            Self::Replied => "replied",
            Self::MeetingBooked => "meeting_booked",
            Self::Completed => "completed",
            Self::Suppressed => "suppressed",
            Self::Failed => "failed",
        }
    }
}

/// When to resume an enrollment (OOO / soft bounce).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReschedulePlan {
    /// Durable queue rows for the enrollment must be due no earlier than this.
    pub resume_at: DateTime<Utc>,
    /// Short machine-readable reason persisted with the classification.
    pub reason: &'static str,
}

/// Why a classification was downgraded (for the persisted reasoning).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DowngradeReason {
    /// Confidence was below [`MIN_AUTO_ACTION_CONFIDENCE`].
    BelowConfidenceThreshold,
    /// The confidence value was not a usable number (NaN/infinite).
    InvalidConfidence,
}

impl DowngradeReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::BelowConfidenceThreshold => "confidence below MIN_AUTO_ACTION_CONFIDENCE",
            Self::InvalidConfidence => "non-finite confidence",
        }
    }
}

/// Everything the policy needs from a classification.
#[derive(Debug, Clone, Copy)]
pub struct PolicyInput {
    pub disposition: ReplyDisposition,
    pub confidence: f64,
    /// Parsed OOO return date, when the deterministic layer found one.
    pub return_date: Option<DateTime<Utc>>,
}

impl PolicyInput {
    pub fn new(disposition: ReplyDisposition, confidence: f64) -> Self {
        Self {
            disposition,
            confidence,
            return_date: None,
        }
    }

    pub fn with_return_date(mut self, return_date: Option<DateTime<Utc>>) -> Self {
        self.return_date = return_date;
        self
    }
}

/// The complete action plan. The processor executes exactly these flags in
/// one transaction plus (after commit) the queue cancellation.
#[derive(Debug, Clone)]
pub struct PolicyDecision {
    /// The disposition the policy actually acted on (after any downgrade).
    pub disposition: ReplyDisposition,
    /// The classification's original disposition (before any downgrade).
    pub observed_disposition: ReplyDisposition,
    /// The observed confidence.
    pub confidence: f64,
    /// Set when confidence was below [`MIN_AUTO_ACTION_CONFIDENCE`].
    pub downgraded: Option<DowngradeReason>,
    /// Target `sales_enrollments.state`.
    pub enrollment_state: EnrollmentState,
    /// Cancel queued/leased/executing `sales_actions` for the enrollment and
    /// cancel its scheduled step executions.
    pub cancel_queued: bool,
    /// Set `sales_enrollments.has_human_reply`.
    pub has_human_reply: bool,
    /// UPSERT `sales_unsubscribes` (and the platform suppression mirror).
    pub suppress_endpoint: bool,
    /// `unsubscribe`, `complaint`, or `bounce_hard` — the suppression reason.
    pub suppression_reason: Option<&'static str>,
    /// Mark the contact point `invalid` and suppressed.
    pub invalidate_contact_point: bool,
    /// Record a sender-health penalty (complaint outcomes).
    pub sender_health_penalty: bool,
    /// Reschedule rather than cancel (OOO / soft bounce).
    pub reschedule: Option<ReschedulePlan>,
    /// Route to the high-intent workflow (human follow-up).
    pub route_high_intent: bool,
    /// Stop the next outbound touch pending classification.
    pub stop_next_touch_pending_classification: bool,
    /// Stable suggested-action name persisted to
    /// `sales_reply_classifications.suggested_action`.
    pub suggested_action: &'static str,
    /// Legacy-shaped action for `inbound_messages.suggested_action` and the
    /// existing `execute_action` path.
    pub legacy_action: SuggestedAction,
    /// Whether the suggested action may execute without operator review.
    pub auto_execute: bool,
}

/// Decide what a classification does. The ONLY policy entry point.
///
/// `now` is a parameter so tests can pin OOO rescheduling.
pub fn decide(input: PolicyInput, now: DateTime<Utc>) -> PolicyDecision {
    let confidence_usable = input.confidence.is_finite();
    let confidence = if confidence_usable {
        input.confidence.clamp(0.0, 1.0)
    } else {
        0.0
    };

    // Low-confidence gate: downgrade BEFORE any disposition-specific effect.
    if !confidence_usable || confidence < MIN_AUTO_ACTION_CONFIDENCE {
        let reason = if confidence_usable {
            DowngradeReason::BelowConfidenceThreshold
        } else {
            DowngradeReason::InvalidConfidence
        };
        let mut decision = base_decision(ReplyDisposition::Unknown, confidence);
        decision.observed_disposition = input.disposition;
        decision.downgraded = Some(reason);
        return decision;
    }

    let mut decision = base_decision(input.disposition, confidence);
    if input.disposition == ReplyDisposition::OutOfOffice {
        let resume_at = ooo_resume_at(input.return_date, now);
        let days = (resume_at - now).num_days().max(1);
        decision.reschedule = Some(ReschedulePlan {
            resume_at,
            reason: if input.return_date.is_some() {
                "after stated return date"
            } else {
                "default out-of-office wait"
            },
        });
        decision.legacy_action = snooze_action(days, resume_at);
    }
    decision
}

/// The disposition table itself. Confidence has already been validated.
fn base_decision(disposition: ReplyDisposition, confidence: f64) -> PolicyDecision {
    let has_human_reply = disposition.stops_normal_sequence();
    let suppress_endpoint = disposition.requires_unsubscribe_upsert();

    let (
        enrollment_state,
        cancel_queued,
        invalidate_contact_point,
        sender_health_penalty,
        route_high_intent,
        stop_pending,
        suppression_reason,
        suggested_action,
        legacy_action,
        auto_execute,
    ) = match disposition {
        ReplyDisposition::Unsubscribe => (
            EnrollmentState::Suppressed,
            true,
            false,
            false,
            false,
            false,
            Some("unsubscribe"),
            "suppress_endpoint",
            unsubscribe_action(),
            true,
        ),
        ReplyDisposition::Complaint => (
            EnrollmentState::Suppressed,
            true,
            false,
            true,
            false,
            false,
            Some("complaint"),
            "suppress_endpoint_and_penalize_sender_health",
            complaint_action(),
            true,
        ),
        ReplyDisposition::BounceHard => (
            EnrollmentState::Suppressed,
            true,
            true,
            false,
            false,
            false,
            Some("bounce_hard"),
            "invalidate_contact_point",
            hard_bounce_action(),
            true,
        ),
        ReplyDisposition::OutOfOffice => (
            EnrollmentState::Waiting,
            false,
            false,
            false,
            false,
            false,
            None,
            "reschedule_after_ooo",
            snooze_action(DEFAULT_OOO_WAIT_DAYS, Utc::now()),
            true,
        ),
        ReplyDisposition::BounceSoft => (
            EnrollmentState::Waiting,
            false,
            false,
            false,
            false,
            false,
            None,
            "resume_after_soft_bounce_window",
            snooze_action(1, Utc::now() + Duration::days(1)),
            true,
        ),
        ReplyDisposition::Positive | ReplyDisposition::Question | ReplyDisposition::Referral => (
            EnrollmentState::Replied,
            true,
            false,
            false,
            true,
            false,
            None,
            "route_high_intent",
            high_intent_action(),
            true,
        ),
        ReplyDisposition::MeetingRequest => (
            EnrollmentState::Replied,
            true,
            false,
            false,
            true,
            false,
            None,
            "route_high_intent_meeting",
            meeting_action(),
            true,
        ),
        ReplyDisposition::NotInterested => (
            EnrollmentState::Completed,
            true,
            false,
            false,
            false,
            false,
            None,
            "suppress_after_confirmation",
            not_interested_action(),
            // A "no" that only stops the sequence is safe automatically; a
            // permanent suppression from a heuristically-read "no" is not.
            false,
        ),
        ReplyDisposition::Unknown => (
            EnrollmentState::Paused,
            true,
            false,
            false,
            false,
            true,
            None,
            "stop_next_touch_pending_classification",
            stop_pending_action(),
            true,
        ),
    };

    PolicyDecision {
        disposition,
        observed_disposition: disposition,
        confidence,
        downgraded: None,
        enrollment_state,
        cancel_queued,
        has_human_reply,
        suppress_endpoint,
        suppression_reason,
        invalidate_contact_point,
        sender_health_penalty,
        reschedule: None,
        route_high_intent,
        stop_next_touch_pending_classification: stop_pending,
        suggested_action,
        legacy_action,
        auto_execute,
    }
}

// ---------------------------------------------------------------------------
// Legacy SuggestedAction constructors (keep `inbound_messages.suggested_action`
// and the existing execute_action path working)
// ---------------------------------------------------------------------------

fn unsubscribe_action() -> SuggestedAction {
    SuggestedAction {
        action: ActionType::Unsubscribe,
        parameters: serde_json::json!({ "reason": "unsubscribe" }),
        auto_execute: true,
        priority: Urgency::High,
    }
}

fn complaint_action() -> SuggestedAction {
    SuggestedAction {
        action: ActionType::Escalate,
        parameters: serde_json::json!({
            "reason": "complaint",
            "sender_health_penalty": true
        }),
        auto_execute: true,
        priority: Urgency::High,
    }
}

fn hard_bounce_action() -> SuggestedAction {
    SuggestedAction {
        action: ActionType::Suppress,
        parameters: serde_json::json!({
            "reason": "bounce_hard",
            "invalidate_contact_point": true
        }),
        auto_execute: true,
        priority: Urgency::High,
    }
}

fn snooze_action(days: i64, resume_at: DateTime<Utc>) -> SuggestedAction {
    SuggestedAction {
        action: ActionType::Snooze,
        parameters: serde_json::json!({
            "duration_days": days.max(1),
            "resume_at": resume_at.to_rfc3339()
        }),
        auto_execute: true,
        priority: Urgency::Low,
    }
}

fn high_intent_action() -> SuggestedAction {
    SuggestedAction {
        action: ActionType::FlagSales,
        parameters: serde_json::json!({ "flag": "high_intent", "priority": "high" }),
        auto_execute: true,
        priority: Urgency::High,
    }
}

fn meeting_action() -> SuggestedAction {
    SuggestedAction {
        action: ActionType::ScheduleDemo,
        parameters: serde_json::json!({ "priority": "high" }),
        auto_execute: true,
        priority: Urgency::High,
    }
}

fn not_interested_action() -> SuggestedAction {
    SuggestedAction {
        action: ActionType::Suppress,
        parameters: serde_json::json!({ "reason": "not_interested" }),
        auto_execute: false,
        priority: Urgency::Medium,
    }
}

fn stop_pending_action() -> SuggestedAction {
    SuggestedAction {
        action: ActionType::Ignore,
        parameters: serde_json::json!({ "reason": "stop_next_touch_pending_classification" }),
        auto_execute: true,
        priority: Urgency::Low,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The documented table, one row per disposition. Kept as data so the
    /// test and a reviewer can diff it against the module doc.
    struct Expected {
        disposition: ReplyDisposition,
        state: EnrollmentState,
        cancel: bool,
        has_human_reply: bool,
        suppress: bool,
        invalidate: bool,
        penalty: bool,
        route: bool,
        stop_pending: bool,
    }

    const TABLE: [Expected; 11] = [
        Expected {
            disposition: ReplyDisposition::Unsubscribe,
            state: EnrollmentState::Suppressed,
            cancel: true,
            has_human_reply: true,
            suppress: true,
            invalidate: false,
            penalty: false,
            route: false,
            stop_pending: false,
        },
        Expected {
            disposition: ReplyDisposition::Complaint,
            state: EnrollmentState::Suppressed,
            cancel: true,
            has_human_reply: true,
            suppress: true,
            invalidate: false,
            penalty: true,
            route: false,
            stop_pending: false,
        },
        Expected {
            disposition: ReplyDisposition::BounceHard,
            state: EnrollmentState::Suppressed,
            cancel: true,
            has_human_reply: true,
            suppress: true,
            invalidate: true,
            penalty: false,
            route: false,
            stop_pending: false,
        },
        Expected {
            disposition: ReplyDisposition::OutOfOffice,
            state: EnrollmentState::Waiting,
            cancel: false,
            has_human_reply: false,
            suppress: false,
            invalidate: false,
            penalty: false,
            route: false,
            stop_pending: false,
        },
        Expected {
            disposition: ReplyDisposition::BounceSoft,
            state: EnrollmentState::Waiting,
            cancel: false,
            has_human_reply: false,
            suppress: false,
            invalidate: false,
            penalty: false,
            route: false,
            stop_pending: false,
        },
        Expected {
            disposition: ReplyDisposition::Positive,
            state: EnrollmentState::Replied,
            cancel: true,
            has_human_reply: true,
            suppress: false,
            invalidate: false,
            penalty: false,
            route: true,
            stop_pending: false,
        },
        Expected {
            disposition: ReplyDisposition::MeetingRequest,
            state: EnrollmentState::Replied,
            cancel: true,
            has_human_reply: true,
            suppress: false,
            invalidate: false,
            penalty: false,
            route: true,
            stop_pending: false,
        },
        Expected {
            disposition: ReplyDisposition::Question,
            state: EnrollmentState::Replied,
            cancel: true,
            has_human_reply: true,
            suppress: false,
            invalidate: false,
            penalty: false,
            route: true,
            stop_pending: false,
        },
        Expected {
            disposition: ReplyDisposition::Referral,
            state: EnrollmentState::Replied,
            cancel: true,
            has_human_reply: true,
            suppress: false,
            invalidate: false,
            penalty: false,
            route: true,
            stop_pending: false,
        },
        Expected {
            disposition: ReplyDisposition::NotInterested,
            state: EnrollmentState::Completed,
            cancel: true,
            has_human_reply: true,
            suppress: false,
            invalidate: false,
            penalty: false,
            route: false,
            stop_pending: false,
        },
        Expected {
            disposition: ReplyDisposition::Unknown,
            state: EnrollmentState::Paused,
            cancel: true,
            has_human_reply: true,
            suppress: false,
            invalidate: false,
            penalty: false,
            route: false,
            stop_pending: true,
        },
    ];

    fn confident(disposition: ReplyDisposition) -> PolicyDecision {
        decide(PolicyInput::new(disposition, 0.99), Utc::now())
    }

    #[test]
    fn every_disposition_maps_to_the_documented_action() {
        assert_eq!(TABLE.len(), ReplyDisposition::ALL.len());
        for expected in TABLE {
            let decision = confident(expected.disposition);
            let label = expected.disposition.as_str();
            assert_eq!(decision.disposition, expected.disposition, "{label}");
            assert_eq!(decision.enrollment_state, expected.state, "state {label}");
            assert_eq!(decision.cancel_queued, expected.cancel, "cancel {label}");
            assert_eq!(
                decision.has_human_reply, expected.has_human_reply,
                "has_human_reply {label}"
            );
            assert_eq!(
                decision.suppress_endpoint, expected.suppress,
                "suppress {label}"
            );
            assert_eq!(
                decision.invalidate_contact_point, expected.invalidate,
                "invalidate {label}"
            );
            assert_eq!(
                decision.sender_health_penalty, expected.penalty,
                "penalty {label}"
            );
            assert_eq!(decision.route_high_intent, expected.route, "route {label}");
            assert_eq!(
                decision.stop_next_touch_pending_classification, expected.stop_pending,
                "stop_pending {label}"
            );
            assert!(
                decision.downgraded.is_none(),
                "no downgrade at 0.99 {label}"
            );
        }
    }

    #[test]
    fn suppression_reasons_are_exact() {
        assert_eq!(
            confident(ReplyDisposition::Unsubscribe).suppression_reason,
            Some("unsubscribe")
        );
        assert_eq!(
            confident(ReplyDisposition::Complaint).suppression_reason,
            Some("complaint")
        );
        assert_eq!(
            confident(ReplyDisposition::BounceHard).suppression_reason,
            Some("bounce_hard")
        );
        assert_eq!(
            confident(ReplyDisposition::NotInterested).suppression_reason,
            None,
            "not_interested stops the sequence but does not upsert an unsubscribe"
        );
    }

    #[test]
    fn ooo_does_not_cancel_while_every_other_human_disposition_does() {
        for disposition in ReplyDisposition::ALL {
            let decision = confident(disposition);
            let expected_cancel = disposition != ReplyDisposition::OutOfOffice
                && disposition != ReplyDisposition::BounceSoft;
            assert_eq!(
                decision.cancel_queued,
                expected_cancel,
                "cancel for {}",
                disposition.as_str()
            );
            assert_eq!(
                decision.has_human_reply,
                disposition.stops_normal_sequence(),
                "has_human_reply for {}",
                disposition.as_str()
            );
        }
        // The exception is pinned twice, deliberately.
        let ooo = confident(ReplyDisposition::OutOfOffice);
        assert!(!ooo.cancel_queued);
        assert!(ooo.reschedule.is_some());
    }

    #[test]
    fn low_confidence_downgrades_to_unknown_and_never_auto_acts() {
        for disposition in [
            ReplyDisposition::Positive,
            ReplyDisposition::MeetingRequest,
            ReplyDisposition::Unsubscribe,
            ReplyDisposition::Complaint,
            ReplyDisposition::BounceHard,
            ReplyDisposition::NotInterested,
        ] {
            let decision = decide(PolicyInput::new(disposition, 0.3), Utc::now());
            assert_eq!(
                decision.disposition,
                ReplyDisposition::Unknown,
                "{} must downgrade",
                disposition.as_str()
            );
            assert_eq!(
                decision.observed_disposition, disposition,
                "the observed disposition is preserved for the audit row"
            );
            assert_eq!(
                decision.downgraded,
                Some(DowngradeReason::BelowConfidenceThreshold)
            );
            assert_eq!(decision.enrollment_state, EnrollmentState::Paused);
            assert!(decision.cancel_queued);
            assert!(decision.has_human_reply);
            assert!(decision.stop_next_touch_pending_classification);
            assert!(!decision.suppress_endpoint, "no suppression from low conf");
            assert!(!decision.invalidate_contact_point);
            assert!(!decision.sender_health_penalty);
            assert!(!decision.route_high_intent);
        }
    }

    #[test]
    fn threshold_is_inclusive_and_documented() {
        assert!((0.0..1.0).contains(&MIN_AUTO_ACTION_CONFIDENCE));
        let at_threshold = decide(
            PolicyInput::new(ReplyDisposition::Unsubscribe, MIN_AUTO_ACTION_CONFIDENCE),
            Utc::now(),
        );
        assert_eq!(at_threshold.disposition, ReplyDisposition::Unsubscribe);
        let below = decide(
            PolicyInput::new(
                ReplyDisposition::Unsubscribe,
                MIN_AUTO_ACTION_CONFIDENCE - 0.01,
            ),
            Utc::now(),
        );
        assert_eq!(below.disposition, ReplyDisposition::Unknown);
    }

    #[test]
    fn nan_and_infinite_confidence_downgrade() {
        for value in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
            let decision = decide(
                PolicyInput::new(ReplyDisposition::Positive, value),
                Utc::now(),
            );
            assert_eq!(decision.disposition, ReplyDisposition::Unknown);
            assert_eq!(
                decision.downgraded,
                Some(DowngradeReason::InvalidConfidence)
            );
            assert_eq!(decision.confidence, 0.0);
        }
    }

    #[test]
    fn complaint_penalizes_sender_health_but_unsubscribe_does_not() {
        let complaint = confident(ReplyDisposition::Complaint);
        assert!(complaint.sender_health_penalty);
        assert!(complaint.suppress_endpoint);

        let unsubscribe = confident(ReplyDisposition::Unsubscribe);
        assert!(unsubscribe.suppress_endpoint);
        assert!(
            !unsubscribe.sender_health_penalty,
            "an unsubscribe is not a complaint and must not be reported as one"
        );
        assert_eq!(unsubscribe.suppression_reason, Some("unsubscribe"));
        assert_ne!(unsubscribe.suppression_reason, Some("complaint"));
    }

    #[test]
    fn hard_bounce_invalidates_the_contact_point_and_soft_bounce_does_not() {
        let hard = confident(ReplyDisposition::BounceHard);
        assert!(hard.invalidate_contact_point);
        assert!(hard.suppress_endpoint);
        assert_eq!(hard.suppression_reason, Some("bounce_hard"));

        let soft = confident(ReplyDisposition::BounceSoft);
        assert!(!soft.invalidate_contact_point);
        assert!(!soft.suppress_endpoint);
        assert_eq!(soft.enrollment_state, EnrollmentState::Waiting);
    }

    #[test]
    fn ooo_reschedules_after_the_stated_return_date() {
        let now = Utc::now();
        let stated = now + Duration::days(3);
        let decision = decide(
            PolicyInput::new(ReplyDisposition::OutOfOffice, 1.0).with_return_date(Some(stated)),
            now,
        );
        let reschedule = decision.reschedule.expect("OOO must reschedule");
        assert!(
            reschedule.resume_at > stated,
            "resume strictly after the stated return"
        );
        assert_eq!(reschedule.reason, "after stated return date");

        // No stated date -> the default wait.
        let decision = decide(PolicyInput::new(ReplyDisposition::OutOfOffice, 1.0), now);
        let reschedule = decision.reschedule.expect("default reschedule");
        assert_eq!(
            reschedule.resume_at,
            now + Duration::days(DEFAULT_OOO_WAIT_DAYS)
        );
        assert_eq!(reschedule.reason, "default out-of-office wait");
    }

    #[test]
    fn positive_categories_route_to_high_intent_and_stop_the_sequence() {
        for disposition in [
            ReplyDisposition::Positive,
            ReplyDisposition::MeetingRequest,
            ReplyDisposition::Question,
            ReplyDisposition::Referral,
        ] {
            let decision = confident(disposition);
            assert!(decision.route_high_intent);
            assert!(decision.cancel_queued);
            assert_eq!(decision.enrollment_state, EnrollmentState::Replied);
        }
    }

    #[test]
    fn not_interested_stops_without_permanent_suppression() {
        let decision = confident(ReplyDisposition::NotInterested);
        assert_eq!(decision.enrollment_state, EnrollmentState::Completed);
        assert!(decision.cancel_queued);
        assert!(decision.has_human_reply);
        assert!(!decision.suppress_endpoint);
        assert!(
            !decision.auto_execute,
            "suppression needs operator confirmation"
        );
        assert!(!decision.legacy_action.auto_execute);
    }

    #[test]
    fn unknown_stops_the_next_touch_pending_classification() {
        let decision = confident(ReplyDisposition::Unknown);
        assert_eq!(decision.enrollment_state, EnrollmentState::Paused);
        assert!(decision.cancel_queued);
        assert!(decision.has_human_reply);
        assert!(decision.stop_next_touch_pending_classification);
        assert!(!decision.suppress_endpoint);
    }

    #[test]
    fn suggested_action_names_are_stable_and_distinct_per_disposition() {
        // Positive/Question/Referral share the high-intent route by design;
        // every other disposition names its own action.
        let expected = [
            (ReplyDisposition::Unsubscribe, "suppress_endpoint"),
            (
                ReplyDisposition::Complaint,
                "suppress_endpoint_and_penalize_sender_health",
            ),
            (ReplyDisposition::BounceHard, "invalidate_contact_point"),
            (ReplyDisposition::OutOfOffice, "reschedule_after_ooo"),
            (
                ReplyDisposition::BounceSoft,
                "resume_after_soft_bounce_window",
            ),
            (ReplyDisposition::Positive, "route_high_intent"),
            (
                ReplyDisposition::MeetingRequest,
                "route_high_intent_meeting",
            ),
            (ReplyDisposition::Question, "route_high_intent"),
            (ReplyDisposition::Referral, "route_high_intent"),
            (
                ReplyDisposition::NotInterested,
                "suppress_after_confirmation",
            ),
            (
                ReplyDisposition::Unknown,
                "stop_next_touch_pending_classification",
            ),
        ];
        for (disposition, name) in expected {
            assert_eq!(
                confident(disposition).suggested_action,
                name,
                "suggested action for {}",
                disposition.as_str()
            );
        }
    }

    #[test]
    fn every_decision_has_a_legacy_action_for_the_existing_path() {
        for disposition in ReplyDisposition::ALL {
            let decision = confident(disposition);
            assert!(!decision.legacy_action.parameters.is_null());
        }
    }
}
