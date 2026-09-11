//! Reply handler — inbound email classification and sequence locking.
//!
//! The classifier is split into three honest layers:
//!
//! - [`deterministic`] — header/syntax-proven cases only, with exact evidence;
//! - [`ai`] — provider-agnostic semantic classification with a never-guessing
//!   fallback on outage;
//! - [`policy`] — the single decision table turning a classification into an
//!   enrollment state, suppression, rescheduling and queue cancellation.
//!
//! [`processor`] wires those layers to the `inbound_messages` claim loop and
//! to the canonical sales tables (`sales_enrollments`, `sales_actions`,
//! `sales_unsubscribes`, `sales_reply_classifications`).

pub mod ai;
mod classifier;
pub mod deterministic;
pub mod policy;
mod processor;
mod types;

pub use ai::{
    classifier_from_config, classify_or_fallback, ClassifyError, HttpReplyClassifier,
    ReplyClassifier, StaticFallbackClassifier, AI_OUTAGE_REASON_PREFIX, AI_PROMPT_VERSION,
};
pub use classifier::{classify, classify_full, CLASSIFIER_INPUT_CAP};
pub use deterministic::{
    classify as classify_deterministic, DeterministicVerdict, DEFAULT_OOO_WAIT_DAYS,
    MAX_CLASSIFIER_INPUT_BYTES, OOO_HEADER_NAMES, OOO_SUBJECT_TOKENS, STOP_REQUEST_TOKENS,
};
pub use policy::{
    decide as decide_policy, DowngradeReason, EnrollmentState, PolicyDecision, PolicyInput,
    ReschedulePlan, MIN_AUTO_ACTION_CONFIDENCE,
};
pub use processor::{
    persist_classification, record_action_outcome, record_operator_correction,
    ClassificationRecord, ReplyHandler,
};
pub use types::{
    ActionType, AiClassification, ClassificationOutcome, ClassificationResult, ClassifierKind,
    Evidence, ExtractedData, InboundMessage, ProcessedReply, ReplyClassification, ReplyDisposition,
    ReplyInput, Sentiment, SuggestedAction, Urgency,
};
