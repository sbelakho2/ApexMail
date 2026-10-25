//! WP F9 — reply risk classes and the promotion gate that lets a LOW class
//! send without human approval.
//!
//! The operating model is one line: *autonomy moves only through the promotion
//! gates in WP F12*. This module is that gate for the reply pipeline, plus the
//! deterministic classifier that names the classes it can promote.
//!
//! # The pipeline this gate sits in
//!
//! ```text
//! mailbot drafts (inbound_messages.ai_response, pending_approval = true)
//!   → api-server /v1/admin/ai/drafts review queue (human approval)
//!   → approve_draft_core: atomic claim → consent gate → priority-100 enqueue
//!     → actor-attributed audit in the same transaction
//! ```
//!
//! WP F9 adds exactly one new arrow: an enabled `(tenant, reply_class)` gate
//! row lets the auto-send sweep release a draft of that class through the SAME
//! claim → consent → enqueue → audit path, attributed to the automation, with
//! the class, the grounding evidence and the gate row on its audit record.
//!
//! # The classifier (table-driven, deterministic, fail closed)
//!
//! Inputs — all read from the pending draft row plus owner flags; nothing is
//! model-inferred:
//!
//! | Input | Source |
//! |---|---|
//! | `draft_text` | `inbound_messages.ai_response` |
//! | `intent_class` | `inbound_messages.classification` — the 11-value disposition taxonomy of `sales_reply_classifications` (migration 200), the SAME vocabulary the reply worker persists; no parallel taxonomy is invented |
//! | `intent_confidence` | `inbound_messages.classification_confidence`, gated at the worker's own `MIN_AUTO_ACTION_CONFIDENCE` (0.7) |
//! | `suggestion` | `inbound_messages.suggested_action` JSONB (`objection_class`, `draft_prompt_version`, `first_touch`/`sequence_step`) |
//! | KB grounding | the draft text scanned against the SHARED canonical knowledge base (`sales_knowledge`): restricted-capability claims via `validate_claim`, numeric claims via the KB's own number grounding, and citation markers |
//! | owner flags | recipient flagged as a contract-tier decision-maker — the tenant's autonomy rules (`sales_autonomy_state.rules -> reply_autosend_flagged_recipients`, see [`FLAGGED_RECIPIENTS_RULE_KEY`]); first-touch-of-a-new-sequence marker (`first_touch` / `sequence_step = 1`) |
//!
//! Decision table — the FIRST rule that fires wins, and the order is the
//! safety order (structure, then flags, then content, then the intent map):
//!
//! | # | Condition | Verdict |
//! |---|---|---|
//! | 1 | draft text empty | HIGH `empty_draft` |
//! | 2 | intent class missing / not one of the canonical 11 | HIGH `missing_intent_class` / `unknown_intent_class` |
//! | 3 | confidence missing, non-finite or < 0.7 | HIGH `low_confidence` |
//! | 4 | `first_touch` / `sequence_step = 1` marker | HIGH `first_message_of_new_sequence` |
//! | 5 | recipient owner-flagged as a contract-tier decision-maker | HIGH `flagged_decision_maker` |
//! | 6 | `objection_class` in {price, trust, authority} | HIGH `objection_class_not_low_risk` |
//! | 7 | a claim names a restricted capability the KB does not back | HIGH `unbacked_claim` |
//! | 8 | a numeric claim no external-copy fact carries | HIGH `unbacked_claim` |
//! | 9 | the draft carries `[n]` citation markers with no grounding evidence | HIGH `unbacked_claim` |
//! | 10 | pricing/commitment language anywhere | HIGH `pricing_or_commitment` |
//! | 11 | legal/contract/DPA/SLA language anywhere | HIGH `legal_or_contract` |
//! | 12 | security/infrastructure language anywhere | HIGH `security_or_infrastructure` |
//! | 13 | intent `meeting_request` | LOW `scheduling` |
//! | 14 | intent `question`, no factual claim | LOW `clarification` |
//! | 15 | intent `question`, factual claims (all KB-grounded) | LOW `documentation` |
//! | 16 | intent `ooo` | LOW `acknowledgement` |
//! | 17 | intent `unsubscribe` | LOW `opt_out_confirmation` |
//! | 18 | every other intent (`positive`, `referral`, `not_interested`, `complaint`, `bounce_hard`, `bounce_soft`, `unknown`) | HIGH `disposition_not_low_risk` |
//!
//! "The KB backs it" is the KB's own machinery, not a new heuristic:
//! [`sales_knowledge::SalesKnowledgeBase::validate_claim`] must not report an
//! unbacked restricted capability, and every number in a factual sentence must
//! appear in some external-copy-allowed fact (the same "no figures the fact
//! does not carry" rule the KB applies to SLA claims). A rule that cannot
//! evaluate (no KB, no intent class, no confidence) fails closed to HIGH.
//!
//! # The gate
//!
//! [`evaluate_for_send`] is re-run INSIDE the auto-send transaction, against
//! the same connection that will enqueue the reply, immediately before the
//! commit. It requires ALL of:
//!
//! 1. an enabled [`ReplyAutosendGrant`] row for `(tenant, class)`;
//! 2. live evidence: ≥ the row's `evidence_required_approvals` approvals of
//!    that class inside the window, and ZERO complaints/opt-outs in the
//!    window (derived by [`APPROVED_CLASS_COUNT_SQL`] /
//!    [`COMPLAINT_OR_OPTOUT_COUNT_SQL`] from the canonical records);
//! 3. the routed tenant's `sales_autonomy_state.mode` is `autonomous_guarded`
//!    and its `kill_switch` is disengaged.
//!
//! Any failure returns `allowed = false` with the reasons; the caller must
//! leave the draft pending for human approval. Enablement itself
//! ([`enable`]) requires a live owner-scope actor ([`OwnerActor::verify`] —
//! the same `users.role = 'owner'` test the control plane's structural gate
//! runs, re-read inside the gate function so no agent path can bypass the
//! route layer) and refuses to switch on a class whose evidence is not
//! satisfied at that instant.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgConnection;

use crate::types::{AutonomyMode, SalesError};

// ---------------------------------------------------------------------------
// Constants — the bars the gate is pinned to
// ---------------------------------------------------------------------------

/// The worker's own auto-action confidence gate (reply_handler/policy.rs):
/// nothing irreversible happens below 0.7, and auto-sending a reply without a
/// human is at least as irreversible as the actions that constant guards.
/// Kept numerically equal on purpose; the drift is pinned by a test here and
/// by the constant's own suite there.
pub const MIN_REPLY_CONFIDENCE: f64 = 0.7;

/// Default number of approved-and-sent replies a class needs before an owner
/// may enable it. The table's CHECK forbids anything below
/// [`MIN_REQUIRED_APPROVALS`].
pub const DEFAULT_REQUIRED_APPROVALS: i64 = 20;

/// Default evidence window, in days.
pub const DEFAULT_EVIDENCE_WINDOW_DAYS: i64 = 30;

/// The floor for `evidence_required_approvals` (mirrors migration 259's CHECK).
pub const MIN_REQUIRED_APPROVALS: i64 = 10;

/// The evidence window bounds (mirrors migration 259's CHECK).
pub const MIN_EVIDENCE_WINDOW_DAYS: i64 = 7;
pub const MAX_EVIDENCE_WINDOW_DAYS: i64 = 90;

/// The audit action a real approval writes (api-server's AI-draft approval).
/// The evidence query reads THIS action's rows — a counter update is not
/// evidence; a recorded approval is.
pub const APPROVED_AUDIT_ACTION: &str = "control_plane.ai_draft.approved";

/// Approved-and-sent replies of one class for one routed tenant, inside the
/// window. `$1` = routed tenant, `$2` = reply class, `$3` = window days.
///
/// `COUNT(DISTINCT resource_id)` de-duplicates a draft's audit rows: a draft
/// can only be claimed once, so one approval row per draft is the invariant —
/// the DISTINCT makes a duplicated row (a backup replay, a hand-inserted
/// copy) count once, never twice.
pub const APPROVED_CLASS_COUNT_SQL: &str = r#"
    SELECT COUNT(DISTINCT resource_id)::bigint
    FROM audit_logs
    WHERE action = 'control_plane.ai_draft.approved'
      AND details->>'routedTenantId' = $1
      AND details->>'replyClass' = $2
      AND created_at >= NOW() - make_interval(days => $3::int)
"#;

/// Complaints/opt-outs recorded for the tenant inside the window: the
/// canonical reply-classification rows (migration 200) the reply worker
/// writes. Zero tolerance — a single complaint or unsubscribe in the window
/// closes every class for that tenant.
pub const COMPLAINT_OR_OPTOUT_COUNT_SQL: &str = r#"
    SELECT COUNT(*)::bigint
    FROM sales_reply_classifications
    WHERE tenant_id = $1
      AND disposition IN ('complaint', 'unsubscribe')
      AND created_at >= NOW() - make_interval(days => $2::int)
"#;

/// The AI-transparency disclosure every autonomous outbound message carries
/// (invariant I11). Both autonomous writers render it into the body — the
/// reply auto-send path (api-server) and the sequence worker — so no
/// unattended send leaves the platform without saying how it was produced and
/// how to reach a human.
pub const AUTO_SEND_AI_DISCLOSURE: &str = "This message was drafted automatically by \
     the ApexMail AI assistant and checked against the ApexMail knowledge base before \
     sending. Reply to reach a human at support@apexmail.ee.";

/// The auto-send audit action (api-server writes it inside the send
/// transaction).
pub const AUTO_SENT_AUDIT_ACTION: &str = "control_plane.ai_draft.auto_sent";

// ---------------------------------------------------------------------------
// The risk taxonomy
// ---------------------------------------------------------------------------

/// The low-risk reply classes — the enablement unit of the promotion gate.
///
/// These are the classes the owner may promote one at a time, each with its
/// own evidence bar. The names are the canonical strings persisted in
/// `reply_autosend_grants.reply_class` and on every audit row.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LowRiskClass {
    /// Acknowledgement of an automatic/away message (`ooo`).
    Acknowledgement,
    /// Scheduling / availability answer (`meeting_request`).
    Scheduling,
    /// Neutral clarification with no factual product claim (`question`).
    Clarification,
    /// Factual product answer the knowledge base backs (`question` with
    /// KB-grounded claims).
    Documentation,
    /// Opt-out confirmation (`unsubscribe`).
    OptOutConfirmation,
}

impl LowRiskClass {
    pub const ALL: [LowRiskClass; 5] = [
        Self::Acknowledgement,
        Self::Scheduling,
        Self::Clarification,
        Self::Documentation,
        Self::OptOutConfirmation,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Acknowledgement => "acknowledgement",
            Self::Scheduling => "scheduling",
            Self::Clarification => "clarification",
            Self::Documentation => "documentation",
            Self::OptOutConfirmation => "opt_out_confirmation",
        }
    }

    /// Parse the persisted string. Unknown values are `None` — a caller must
    /// fail closed, never guess a class.
    pub fn parse(value: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|class| class.as_str() == value.trim())
    }
}

impl std::fmt::Display for LowRiskClass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Why a draft is HIGH risk. Every variant is a fail-closed outcome: the
/// draft takes the human approval path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HighRiskReason {
    /// No draft text to evaluate.
    EmptyDraft,
    /// The row carries no intent class.
    MissingIntentClass,
    /// The intent class is not one of the canonical 11 dispositions.
    UnknownIntentClass,
    /// Confidence missing, non-finite or below [`MIN_REPLY_CONFIDENCE`].
    LowConfidence,
    /// The draft would start a new sequence (first-touch marker present).
    FirstMessageOfNewSequence,
    /// The recipient is an owner-flagged contract-tier decision-maker.
    FlaggedDecisionMaker,
    /// The objection sub-class (`price`, `trust`, `authority`) is not
    /// low-risk by construction.
    ObjectionClassNotLowRisk,
    /// The knowledge base does not back a claim (restricted capability,
    /// ungrounded figure, or citation markers with no grounding evidence).
    UnbackedClaim,
    /// Pricing / commitment language.
    PricingOrCommitment,
    /// Legal / contract / DPA / SLA language.
    LegalOrContract,
    /// Security / infrastructure language.
    SecurityOrInfrastructure,
    /// The intent class maps to no LOW class.
    DispositionNotLowRisk,
}

impl HighRiskReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::EmptyDraft => "empty_draft",
            Self::MissingIntentClass => "missing_intent_class",
            Self::UnknownIntentClass => "unknown_intent_class",
            Self::LowConfidence => "low_confidence",
            Self::FirstMessageOfNewSequence => "first_message_of_new_sequence",
            Self::FlaggedDecisionMaker => "flagged_decision_maker",
            Self::ObjectionClassNotLowRisk => "objection_class_not_low_risk",
            Self::UnbackedClaim => "unbacked_claim",
            Self::PricingOrCommitment => "pricing_or_commitment",
            Self::LegalOrContract => "legal_or_contract",
            Self::SecurityOrInfrastructure => "security_or_infrastructure",
            Self::DispositionNotLowRisk => "disposition_not_low_risk",
        }
    }
}

impl std::fmt::Display for HighRiskReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The risk verdict for one draft.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReplyRisk {
    Low(LowRiskClass),
    High(HighRiskReason),
}

impl ReplyRisk {
    pub fn low_class(self) -> Option<LowRiskClass> {
        match self {
            Self::Low(class) => Some(class),
            Self::High(_) => None,
        }
    }

    pub fn is_low(self) -> bool {
        matches!(self, Self::Low(_))
    }

    /// The persisted string: the class for LOW, `high:<reason>` for HIGH.
    /// This is what rides `audit_logs.details->>'replyClass'`, so a HIGH
    /// verdict is never mistaken for a promotable class by the evidence query.
    pub fn as_str(self) -> String {
        match self {
            Self::Low(class) => class.as_str().to_string(),
            Self::High(reason) => format!("high:{}", reason.as_str()),
        }
    }
}

/// Everything the classifier may look at. Built from the pending draft row by
/// the caller; the classifier itself touches no I/O.
#[derive(Debug, Clone, Copy, Default)]
pub struct DraftRiskInput<'a> {
    /// `inbound_messages.ai_response`.
    pub draft_text: &'a str,
    /// `inbound_messages.classification` — the canonical disposition taxonomy.
    pub intent_class: Option<&'a str>,
    /// `inbound_messages.classification_confidence`.
    pub intent_confidence: Option<f64>,
    /// `inbound_messages.suggested_action`.
    pub suggestion: Option<&'a serde_json::Value>,
    /// Owner-flagged contract-tier decision-maker (recipient property).
    pub recipient_owner_flagged: bool,
    /// Set when the draft is marked as the first touch of a NEW sequence
    /// (cold outreach), never for a reply to an inbound message.
    pub first_message_of_new_sequence: bool,
}

/// One knowledge-base check the classifier performed, for the audit record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GroundingCheck {
    /// `restricted_capability`, `ungrounded_number` or `citation_marker`.
    pub kind: String,
    /// The offending sentence/text (trimmed, bounded).
    pub text: String,
    /// The KB's own reason when it names one.
    pub reason: String,
}

/// The deterministic verdict.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplyRiskVerdict {
    pub risk: ReplyRisk,
    /// Grounding failures the KB reported (empty when the draft is grounded).
    pub grounding_failures: Vec<GroundingCheck>,
    /// Whether the draft text carried any factual claim sentence at all.
    pub has_factual_claims: bool,
}

impl ReplyRiskVerdict {
    /// The persisted class string (see [`ReplyRisk::as_str`]).
    pub fn class_string(&self) -> String {
        self.risk.as_str()
    }
}

// ---------------------------------------------------------------------------
// The deterministic classifier
// ---------------------------------------------------------------------------

/// The canonical disposition vocabulary, byte-for-byte
/// `sales_reply_classifications.disposition` (migration 200). Declared here as
/// a list of strings, not a second enum: the wire/persisted authority is the
/// DB CHECK constraint and the worker's mirror.
pub const CANONICAL_DISPOSITIONS: [&str; 11] = [
    "positive",
    "meeting_request",
    "question",
    "referral",
    "not_interested",
    "unsubscribe",
    "complaint",
    "ooo",
    "bounce_hard",
    "bounce_soft",
    "unknown",
];

/// Objection sub-classes that disqualify a class by construction: a reply
/// shaped around pricing, trust or authority is not a low-risk class.
const NON_LOW_RISK_OBJECTION_CLASSES: [&str; 3] = ["price", "trust", "authority"];

/// Pricing / commitment language. Substring match on the lowercased draft,
/// deliberately over-inclusive: a false positive sends the draft to a human,
/// which is the safe direction.
const PRICING_MARKERS: [&str; 18] = [
    "price",
    "pricing",
    "cost per",
    "costs ",
    "€",
    "usd",
    "per month",
    "per seat",
    "per user",
    "discount",
    "quote you",
    "invoice",
    "billing",
    "refund",
    "commitment",
    "guarantee",
    "budget",
    "contract value",
];

/// Legal / contract / DPA / SLA language.
const LEGAL_MARKERS: [&str; 14] = [
    "dpa",
    "data processing agreement",
    "contract",
    "terms of service",
    "terms and conditions",
    "sla",
    "service level agreement",
    "liability",
    "indemnif",
    "warrant",
    "subprocessor",
    "sub-processor",
    "lawful basis",
    "legal advice",
];

/// Security / infrastructure language.
const SECURITY_MARKERS: [&str; 20] = [
    "soc 2",
    "soc2",
    "iso 27001",
    "iso27001",
    "penetration test",
    "encryption",
    "encrypted",
    "zero-knowledge",
    "security posture",
    "our security",
    "data residency",
    "data center",
    "datacenter",
    "hosting",
    "infrastructure",
    "uptime",
    "redundan",
    "failover",
    "subprocessor list",
    "audit log",
];

/// Assertion markers that make a sentence a factual claim about the product or
/// the platform (and therefore subject to the KB grounding checks). Kept
/// tight on purpose: scheduling logistics ("does 10:00 Thursday work?") carry
/// no marker and are not claims.
const FACTUAL_ASSERTION_MARKERS: [&str; 16] = [
    "we support",
    "we provide",
    "we offer",
    "we include",
    "we can",
    "we send",
    "we handle",
    "supports ",
    "provides ",
    "includes ",
    "offers ",
    "our platform",
    "our service",
    "our system",
    "up to ",
    "per day",
];

/// Deterministic sentence split (`.`, `!`, `?`, newline), trimmed, empties
/// dropped. No NLP.
fn sentences(text: &str) -> Vec<&str> {
    text.split(|c| ['.', '!', '?', '\n'].contains(&c))
        .map(str::trim)
        .filter(|sentence| !sentence.is_empty())
        .collect()
}

/// Does the sentence assert a factual claim about the product?
fn is_factual_claim(sentence_lower: &str) -> bool {
    FACTUAL_ASSERTION_MARKERS
        .iter()
        .any(|marker| sentence_lower.contains(marker))
}

/// Decimal numbers, normalized exactly like `sales-knowledge`'s grounding
/// check (digits and dots; `%` and thousands separators fall away).
fn numbers(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut current = String::new();
    for ch in text.chars() {
        if ch.is_ascii_digit() || (ch == '.' && !current.is_empty()) {
            current.push(ch);
        } else if !current.is_empty() {
            out.push(current.trim_matches('.').to_string());
            current.clear();
        }
    }
    if !current.is_empty() {
        out.push(current.trim_matches('.').to_string());
    }
    out.retain(|n| !n.is_empty());
    out
}

/// `[n]`-style citation markers: `[` + digits + `]`.
fn has_citation_markers(text: &str) -> bool {
    let bytes = text.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'[' {
            let mut cursor = index + 1;
            let mut digits = 0;
            while cursor < bytes.len() && bytes[cursor].is_ascii_digit() {
                cursor += 1;
                digits += 1;
            }
            if digits > 0 && cursor < bytes.len() && bytes[cursor] == b']' {
                return true;
            }
        }
        index += 1;
    }
    false
}

/// The canonical knowledge base, built once per process (a pure function of
/// the repository's canonical artifacts).
fn knowledge_base() -> &'static sales_knowledge::SalesKnowledgeBase {
    static KB: std::sync::OnceLock<sales_knowledge::SalesKnowledgeBase> =
        std::sync::OnceLock::new();
    KB.get_or_init(sales_knowledge::SalesKnowledgeBase::canonical)
}

/// Every decimal number any external-copy-allowed fact carries. A numeric
/// claim is grounded only when its figures appear here.
fn kb_numbers() -> std::collections::BTreeSet<String> {
    static NUMBERS: std::sync::OnceLock<std::collections::BTreeSet<String>> =
        std::sync::OnceLock::new();
    NUMBERS
        .get_or_init(|| {
            let facts = knowledge_base().external_copy_facts();
            facts.iter().flat_map(|fact| numbers(&fact.claim)).collect()
        })
        .clone()
}

/// Scan the draft text against the canonical knowledge base. Deterministic:
/// same text in, same checks out.
fn scan_grounding(draft_text: &str) -> (Vec<GroundingCheck>, bool) {
    let kb = knowledge_base();
    let grounded_numbers = kb_numbers();
    let mut failures = Vec::new();
    let mut has_factual_claims = false;

    for sentence in sentences(draft_text) {
        let lower = sentence.to_lowercase();
        if !is_factual_claim(&lower) {
            continue;
        }
        has_factual_claims = true;

        // 1. Restricted capabilities (SSO / SLA terms / migration /
        //    certifications) go through the SHARED validator.
        if let sales_knowledge::ClaimVerdict::Unsupported { capability, reason } =
            kb.validate_claim(sentence)
        {
            failures.push(GroundingCheck {
                kind: "restricted_capability".into(),
                text: bounded(sentence),
                reason: format!("{capability}: {reason}"),
            });
        }

        // 2. Figures the KB does not carry.
        for number in numbers(sentence) {
            if !grounded_numbers.contains(&number) {
                failures.push(GroundingCheck {
                    kind: "ungrounded_number".into(),
                    text: bounded(sentence),
                    reason: format!("the knowledge base carries no fact with the figure {number}"),
                });
            }
        }
    }

    // 3. Citation markers with no grounding evidence: the mailbot's draft
    //    surface performs no retrieval, so a `[n]` marker is unsupported by
    //    construction (`retrieval_unavailable`).
    if has_citation_markers(draft_text) {
        failures.push(GroundingCheck {
            kind: "citation_marker".into(),
            text: bounded(draft_text),
            reason: "the draft cites [n] sources but the grounding surface performed no \
                     retrieval; citations cannot be resolved"
                .into(),
        });
    }

    (failures, has_factual_claims)
}

/// Bound the text kept on the audit/verdict record.
fn bounded(text: &str) -> String {
    const MAX: usize = 240;
    let trimmed = text.trim();
    if trimmed.chars().count() <= MAX {
        return trimmed.to_string();
    }
    let mut out: String = trimmed.chars().take(MAX).collect();
    out.push('…');
    out
}

/// The classifier. Deterministic on its inputs; every missing/unreadable input
/// fails closed to HIGH.
pub fn classify_draft(input: &DraftRiskInput<'_>) -> ReplyRiskVerdict {
    let (grounding_failures, has_factual_claims) = scan_grounding(input.draft_text);

    let verdict = |risk: ReplyRisk| ReplyRiskVerdict {
        risk,
        grounding_failures: grounding_failures.clone(),
        has_factual_claims,
    };
    let high = |reason: HighRiskReason| verdict(ReplyRisk::High(reason));

    // 1. Structure.
    if input.draft_text.trim().is_empty() {
        return high(HighRiskReason::EmptyDraft);
    }

    // 2. The intent class must be one of the canonical dispositions.
    let Some(intent) = input.intent_class.map(str::trim).filter(|s| !s.is_empty()) else {
        return high(HighRiskReason::MissingIntentClass);
    };
    let intent = intent.to_ascii_lowercase();
    if !CANONICAL_DISPOSITIONS.contains(&intent.as_str()) {
        return high(HighRiskReason::UnknownIntentClass);
    }

    // 3. Confidence: the worker's own 0.7 auto-action gate.
    let confidence = input.intent_confidence.unwrap_or(f64::NAN);
    if !confidence.is_finite() || confidence < MIN_REPLY_CONFIDENCE {
        return high(HighRiskReason::LowConfidence);
    }

    // 4. A draft that starts a new sequence is never auto-sent.
    if input.first_message_of_new_sequence {
        return high(HighRiskReason::FirstMessageOfNewSequence);
    }

    // 5. Owner-flagged contract-tier decision-makers are never auto-sent.
    if input.recipient_owner_flagged {
        return high(HighRiskReason::FlaggedDecisionMaker);
    }

    // 6. Objection sub-classes that are not low-risk by construction.
    if let Some(objection) = input
        .suggestion
        .and_then(|suggestion| suggestion.get("objection_class"))
        .and_then(|value| value.as_str())
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        if NON_LOW_RISK_OBJECTION_CLASSES.contains(&objection.to_ascii_lowercase().as_str()) {
            return high(HighRiskReason::ObjectionClassNotLowRisk);
        }
    }

    // 7-9. Knowledge-base grounding.
    if !grounding_failures.is_empty() {
        return high(HighRiskReason::UnbackedClaim);
    }

    // 10-12. Topic language — a commitment is HIGH whatever the KB says.
    let lower = input.draft_text.to_lowercase();
    if PRICING_MARKERS.iter().any(|marker| lower.contains(marker)) {
        return high(HighRiskReason::PricingOrCommitment);
    }
    if LEGAL_MARKERS.iter().any(|marker| lower.contains(marker)) {
        return high(HighRiskReason::LegalOrContract);
    }
    if SECURITY_MARKERS.iter().any(|marker| lower.contains(marker)) {
        return high(HighRiskReason::SecurityOrInfrastructure);
    }

    // 13-18. The intent map.
    let class = match intent.as_str() {
        "meeting_request" => LowRiskClass::Scheduling,
        "question" => {
            if has_factual_claims {
                LowRiskClass::Documentation
            } else {
                LowRiskClass::Clarification
            }
        }
        "ooo" => LowRiskClass::Acknowledgement,
        "unsubscribe" => LowRiskClass::OptOutConfirmation,
        // positive, referral, not_interested, complaint, bounce_hard,
        // bounce_soft, unknown.
        _ => return high(HighRiskReason::DispositionNotLowRisk),
    };
    verdict(ReplyRisk::Low(class))
}

/// Derive the `first_message_of_new_sequence` flag from the draft's
/// `suggested_action`. The reply pipeline answers an inbound message, so the
/// flag is never set for it; a row carrying an explicit first-touch marker
/// (a new-sequence draft) is HIGH by construction.
pub fn first_touch_marker(suggestion: Option<&serde_json::Value>) -> bool {
    let Some(suggestion) = suggestion else {
        return false;
    };
    let first_touch = suggestion
        .get("first_touch")
        .and_then(|value| value.as_bool())
        .unwrap_or(false);
    let sequence_step_is_one = suggestion
        .get("sequence_step")
        .and_then(|value| value.as_i64())
        .map(|step| step == 1)
        .unwrap_or(false);
    first_touch || sequence_step_is_one
}

// ---------------------------------------------------------------------------
// The promotion gate
// ---------------------------------------------------------------------------

/// Live evidence for one `(tenant, reply class)`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceReport {
    pub tenant_id: String,
    pub reply_class: String,
    /// Approved-and-sent replies of the class inside the window.
    pub approved_and_sent: i64,
    /// Complaints/opt-outs recorded inside the window (zero tolerance).
    pub complaints_or_optouts: i64,
    pub required_approvals: i64,
    pub window_days: i64,
    /// `approved_and_sent >= required_approvals && complaints_or_optouts == 0`.
    pub satisfied: bool,
}

impl EvidenceReport {
    /// The fail-closed default for an unconfigured class: the evidence bar
    /// with zero counted approvals.
    pub fn unconfigured(tenant_id: &str, class: LowRiskClass) -> Self {
        Self {
            tenant_id: tenant_id.to_string(),
            reply_class: class.as_str().to_string(),
            approved_and_sent: 0,
            complaints_or_optouts: 0,
            required_approvals: DEFAULT_REQUIRED_APPROVALS,
            window_days: DEFAULT_EVIDENCE_WINDOW_DAYS,
            satisfied: false,
        }
    }
}

/// Compute the live evidence report. `required`/`window_days` are the grant's
/// bars (defaults for an unconfigured class).
pub async fn evidence_report(
    conn: &mut PgConnection,
    tenant_id: &str,
    class: LowRiskClass,
    required: i64,
    window_days: i64,
) -> Result<EvidenceReport, SalesError> {
    let approved_and_sent: i64 = sqlx::query_scalar(APPROVED_CLASS_COUNT_SQL)
        .bind(tenant_id)
        .bind(class.as_str())
        .bind(window_days as i32)
        .fetch_one(&mut *conn)
        .await
        .map_err(|e| SalesError::Database(e.to_string()))?;

    let complaints_or_optouts: i64 = sqlx::query_scalar(COMPLAINT_OR_OPTOUT_COUNT_SQL)
        .bind(tenant_id)
        .bind(window_days as i32)
        .fetch_one(&mut *conn)
        .await
        .map_err(|e| SalesError::Database(e.to_string()))?;

    Ok(EvidenceReport {
        tenant_id: tenant_id.to_string(),
        reply_class: class.as_str().to_string(),
        approved_and_sent,
        complaints_or_optouts,
        required_approvals: required,
        window_days,
        satisfied: approved_and_sent >= required && complaints_or_optouts == 0,
    })
}

/// One `(tenant, reply class)` promotion row.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplyAutosendGrant {
    pub tenant_id: String,
    pub reply_class: LowRiskClass,
    pub enabled: bool,
    pub enabled_by: Option<String>,
    pub enabled_at: Option<DateTime<Utc>>,
    pub evidence_required_approvals: i64,
    pub evidence_window_days: i64,
    pub evidence_snapshot: serde_json::Value,
    pub disabled_by: Option<String>,
    pub disabled_at: Option<DateTime<Utc>>,
    pub updated_at: DateTime<Utc>,
}

#[derive(sqlx::FromRow)]
struct GrantRow {
    tenant_id: String,
    reply_class: String,
    enabled: bool,
    enabled_by: Option<String>,
    enabled_at: Option<DateTime<Utc>>,
    evidence_required_approvals: i32,
    evidence_window_days: i32,
    evidence_snapshot: serde_json::Value,
    disabled_by: Option<String>,
    disabled_at: Option<DateTime<Utc>>,
    updated_at: DateTime<Utc>,
}

impl GrantRow {
    /// A row whose `reply_class` is not in the canonical set is unreadable
    /// (fail closed: the caller treats it as no grant at all).
    fn into_grant(self) -> Option<ReplyAutosendGrant> {
        let class = LowRiskClass::parse(&self.reply_class)?;
        Some(ReplyAutosendGrant {
            tenant_id: self.tenant_id,
            reply_class: class,
            enabled: self.enabled,
            enabled_by: self.enabled_by,
            enabled_at: self.enabled_at,
            evidence_required_approvals: i64::from(self.evidence_required_approvals),
            evidence_window_days: i64::from(self.evidence_window_days),
            evidence_snapshot: self.evidence_snapshot,
            disabled_by: self.disabled_by,
            disabled_at: self.disabled_at,
            updated_at: self.updated_at,
        })
    }
}

const SELECT_GRANT_SQL: &str = r#"
    SELECT tenant_id, reply_class, enabled, enabled_by, enabled_at,
           evidence_required_approvals, evidence_window_days, evidence_snapshot,
           disabled_by, disabled_at, updated_at
    FROM reply_autosend_grants
    WHERE tenant_id = $1 AND reply_class = $2
"#;

/// Load one grant row. `None` = no row = OFF (the fail-closed default state).
pub async fn load_grant(
    conn: &mut PgConnection,
    tenant_id: &str,
    class: LowRiskClass,
) -> Result<Option<ReplyAutosendGrant>, SalesError> {
    let row: Option<GrantRow> = sqlx::query_as(SELECT_GRANT_SQL)
        .bind(tenant_id)
        .bind(class.as_str())
        .fetch_optional(&mut *conn)
        .await
        .map_err(|e| SalesError::Database(e.to_string()))?;
    Ok(row.and_then(GrantRow::into_grant))
}

/// Every grant row for a tenant, plus (for each canonical class) the live
/// evidence report — the promotion status the owner reads before deciding.
pub async fn promotion_status(
    conn: &mut PgConnection,
    tenant_id: &str,
) -> Result<Vec<(ReplyAutosendGrant, EvidenceReport)>, SalesError> {
    let mut out = Vec::new();
    for class in LowRiskClass::ALL {
        let grant = load_grant(&mut *conn, tenant_id, class).await?;
        let (required, window_days) = grant
            .as_ref()
            .map(|row| (row.evidence_required_approvals, row.evidence_window_days))
            .unwrap_or((DEFAULT_REQUIRED_APPROVALS, DEFAULT_EVIDENCE_WINDOW_DAYS));
        let evidence = evidence_report(&mut *conn, tenant_id, class, required, window_days).await?;
        match grant {
            // A class with no row still reports its (unsatisfied) evidence, so
            // the owner sees the bar before creating the row.
            Some(row) => out.push((row, evidence)),
            None => out.push((
                ReplyAutosendGrant {
                    tenant_id: tenant_id.to_string(),
                    reply_class: class,
                    enabled: false,
                    enabled_by: None,
                    enabled_at: None,
                    evidence_required_approvals: required,
                    evidence_window_days: window_days,
                    evidence_snapshot: serde_json::json!({}),
                    disabled_by: None,
                    disabled_at: None,
                    updated_at: Utc::now(),
                },
                evidence,
            )),
        }
    }
    Ok(out)
}

/// An owner-scope actor. Constructible ONLY through [`OwnerActor::verify`],
/// which re-reads the live role from `users` inside the caller's transaction —
/// the same test the control plane's structural owner gate
/// (`middleware::sales_owner`) runs, so a caller that reaches this function by
/// any other path (an agent, a machine credential, a direct DB session) is
/// refused there and cannot manufacture the token to get here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnerActor {
    /// The platform owner's user id (audit attribution).
    pub user_id: String,
}

const OWNER_ROLE_SQL: &str = r#"
    SELECT u.role
    FROM users u
    WHERE u.id = $1::uuid
      AND (u.tenant_id = 'system'
           OR EXISTS (SELECT 1 FROM tenants t WHERE t.id = u.tenant_id AND t.slug = 'system'))
    LIMIT 1
"#;

impl OwnerActor {
    /// Verify a live platform owner. Unknown user, non-system tenant, wrong
    /// role, or a storage failure all fail closed.
    pub async fn verify(conn: &mut PgConnection, user_id: &str) -> Result<OwnerActor, SalesError> {
        let role: Option<String> = sqlx::query_scalar(OWNER_ROLE_SQL)
            .bind(user_id)
            .fetch_optional(&mut *conn)
            .await
            .map_err(|e| SalesError::Database(e.to_string()))?
            .flatten();
        match role.as_deref() {
            Some("owner") => Ok(OwnerActor {
                user_id: user_id.to_string(),
            }),
            _ => Err(SalesError::Unauthorized(
                "autonomy is promoted by the platform owner only".into(),
            )),
        }
    }
}

/// Enable a class for a tenant. Requires the owner actor AND satisfied
/// evidence at this instant; the evidence report is captured on the row.
pub async fn enable(
    conn: &mut PgConnection,
    tenant_id: &str,
    class: LowRiskClass,
    actor: &OwnerActor,
    required_approvals: i64,
    window_days: i64,
) -> Result<EvidenceReport, SalesError> {
    if tenant_id.trim().is_empty() {
        return Err(SalesError::InvalidInput("tenant_id is required".into()));
    }
    if !(MIN_REQUIRED_APPROVALS..=1_000).contains(&required_approvals) {
        return Err(SalesError::InvalidInput(format!(
            "required_approvals must be between {MIN_REQUIRED_APPROVALS} and 1000"
        )));
    }
    if !(MIN_EVIDENCE_WINDOW_DAYS..=MAX_EVIDENCE_WINDOW_DAYS).contains(&window_days) {
        return Err(SalesError::InvalidInput(format!(
            "window_days must be between {MIN_EVIDENCE_WINDOW_DAYS} and \
             {MAX_EVIDENCE_WINDOW_DAYS}"
        )));
    }

    // The evidence is DERIVED here, under the caller's transaction: a class
    // cannot be switched on by writing a row, only by having the recorded
    // approvals that satisfy the bar.
    let evidence = evidence_report(
        &mut *conn,
        tenant_id,
        class,
        required_approvals,
        window_days,
    )
    .await?;
    if !evidence.satisfied {
        return Err(SalesError::InvalidInput(format!(
            "evidence not satisfied for {tenant_id}/{class}: \
             {}/{} approved-and-sent in the last {} days, {} complaint(s)/opt-out(s) \
             (need >= {} approvals and exactly 0 complaints/opt-outs)",
            evidence.approved_and_sent,
            evidence.required_approvals,
            evidence.window_days,
            evidence.complaints_or_optouts,
            evidence.required_approvals
        )));
    }

    let snapshot = serde_json::to_value(&evidence)
        .map_err(|e| SalesError::InvalidInput(format!("evidence snapshot: {e}")))?;

    let updated = sqlx::query(
        "INSERT INTO reply_autosend_grants \
             (tenant_id, reply_class, enabled, enabled_by, enabled_at, \
              evidence_required_approvals, evidence_window_days, evidence_snapshot, \
              disabled_by, disabled_at, updated_at) \
         VALUES ($1, $2, TRUE, $3, NOW(), $4, $5, $6::jsonb, NULL, NULL, NOW()) \
         ON CONFLICT (tenant_id, reply_class) DO UPDATE SET \
             enabled = TRUE, \
             enabled_by = $3, \
             enabled_at = NOW(), \
             evidence_required_approvals = $4, \
             evidence_window_days = $5, \
             evidence_snapshot = $6::jsonb, \
             disabled_by = NULL, \
             disabled_at = NULL, \
             updated_at = NOW()",
    )
    .bind(tenant_id)
    .bind(class.as_str())
    .bind(&actor.user_id)
    .bind(required_approvals as i32)
    .bind(window_days as i32)
    .bind(&snapshot)
    .execute(&mut *conn)
    .await
    .map_err(|e| SalesError::Database(e.to_string()))?;
    debug_assert_eq!(updated.rows_affected(), 1);

    Ok(evidence)
}

/// Revoke a class for a tenant (the per-class kill switch). The row is kept —
/// the evidence snapshot stays on record — and `enabled` goes back to FALSE.
/// Idempotent: revoking a class that was never enabled reports `false` (no row
/// changed), never an error.
pub async fn revoke(
    conn: &mut PgConnection,
    tenant_id: &str,
    class: LowRiskClass,
    actor: &OwnerActor,
) -> Result<bool, SalesError> {
    let result = sqlx::query(
        "UPDATE reply_autosend_grants \
         SET enabled = FALSE, disabled_by = $3, disabled_at = NOW(), updated_at = NOW() \
         WHERE tenant_id = $1 AND reply_class = $2 AND enabled",
    )
    .bind(tenant_id)
    .bind(class.as_str())
    .bind(&actor.user_id)
    .execute(&mut *conn)
    .await
    .map_err(|e| SalesError::Database(e.to_string()))?;
    Ok(result.rows_affected() == 1)
}

/// The send-time verdict.
#[derive(Debug, Clone)]
pub struct GateVerdict {
    pub tenant_id: String,
    pub reply_class: LowRiskClass,
    /// TRUE only when the class may send without a human right now.
    pub allowed: bool,
    /// Every failing condition, in check order (empty when allowed).
    pub reasons: Vec<String>,
    /// The live evidence report (recomputed on every call).
    pub evidence: EvidenceReport,
    /// The enabled instant of the grant row, when one is enabled.
    pub enabled_at: Option<DateTime<Utc>>,
    /// The owner actor on the grant row, when one is enabled.
    pub enabled_by: Option<String>,
    pub autonomy_mode: AutonomyMode,
    pub kill_switch: bool,
}

/// Does the class have an enabled grant row right now, without evaluating the
/// evidence/autonomy rings? Used by the sweep's cheap candidate filter.
pub const CLASS_ENABLED_FOR_TENANT_SQL: &str = r#"
    SELECT EXISTS (
        SELECT 1 FROM reply_autosend_grants
        WHERE tenant_id = $1 AND reply_class = $2 AND enabled
    )
"#;

const AUTONOMY_STATE_SQL: &str =
    "SELECT mode, kill_switch FROM sales_autonomy_state WHERE tenant_id = $1";

/// The owner-managed list of recipients whose drafts are HIGH by construction
/// ("anything addressed to a named contract-tier decision-maker the owner
/// flagged"): an array of addresses under the tenant's autonomy rules,
/// `sales_autonomy_state.rules -> 'reply_autosend_flagged_recipients'`.
///
/// The rules JSONB is the autonomy state's own operator-policy column (the
/// same one [`crate::autonomy::set_rules`] writes) — the owner-scope place a
/// per-tenant policy belongs. The repository has no separate flagged-recipient
/// registry or owner UI for it, so the rule is enforced wherever the data
/// exists and an absent key means "nothing flagged"; the classifier treats a
/// match as HIGH either way.
pub const FLAGGED_RECIPIENTS_RULE_KEY: &str = "reply_autosend_flagged_recipients";

const AUTONOMY_RULES_SQL: &str = "SELECT rules FROM sales_autonomy_state WHERE tenant_id = $1";

/// The owner-flagged recipients for a tenant (lowercased). A missing row or
/// absent/!array key yields none — never an error, never a guess.
pub async fn flagged_recipients(
    conn: &mut PgConnection,
    tenant_id: &str,
) -> Result<Vec<String>, SalesError> {
    let rules: Option<serde_json::Value> = sqlx::query_scalar(AUTONOMY_RULES_SQL)
        .bind(tenant_id)
        .fetch_optional(&mut *conn)
        .await
        .map_err(|e| SalesError::Database(e.to_string()))?;
    let Some(rules) = rules else {
        return Ok(Vec::new());
    };
    Ok(rules
        .get(FLAGGED_RECIPIENTS_RULE_KEY)
        .and_then(|value| value.as_array())
        .map(|entries| {
            entries
                .iter()
                .filter_map(|entry| entry.as_str())
                .map(|entry| entry.trim().to_lowercase())
                .filter(|entry| !entry.is_empty())
                .collect()
        })
        .unwrap_or_default())
}

/// Is this recipient owner-flagged as a contract-tier decision-maker?
pub fn recipient_is_flagged(flagged: &[String], recipient: &str) -> bool {
    let recipient = recipient.trim().to_lowercase();
    !recipient.is_empty() && flagged.iter().any(|entry| entry == &recipient)
}

/// Evaluate the full gate INSIDE the caller's transaction, immediately before
/// the send commits. Fail closed: any missing row, unreadable value, lapsed
/// evidence or engaged kill switch yields `allowed = false` with the reasons.
pub async fn evaluate_for_send(
    conn: &mut PgConnection,
    tenant_id: &str,
    class: LowRiskClass,
) -> Result<GateVerdict, SalesError> {
    let mut reasons = Vec::new();

    // Ring 1 — the per-class promotion row (default OFF: no row = no grant).
    let grant = load_grant(&mut *conn, tenant_id, class).await?;
    let (required, window_days) = grant
        .as_ref()
        .map(|row| (row.evidence_required_approvals, row.evidence_window_days))
        .unwrap_or((DEFAULT_REQUIRED_APPROVALS, DEFAULT_EVIDENCE_WINDOW_DAYS));
    match &grant {
        Some(row) if row.enabled => {}
        Some(_) => reasons.push(format!(
            "grant_disabled: {tenant_id}/{class} is switched off (revoked); human approval required"
        )),
        None => reasons.push(format!(
            "grant_missing: no promotion row for {tenant_id}/{class}; autonomy is off by default"
        )),
    }

    // Ring 2 — the evidence, re-derived now (never the stored snapshot).
    let evidence = evidence_report(&mut *conn, tenant_id, class, required, window_days).await?;
    if !evidence.satisfied {
        reasons.push(format!(
            "evidence_lapsed: {}/{} approved-and-sent in the last {} days, \
             {} complaint(s)/opt-out(s)",
            evidence.approved_and_sent,
            evidence.required_approvals,
            evidence.window_days,
            evidence.complaints_or_optouts
        ));
    }

    // Ring 3 — the tenant's autonomy state (the F12 outer gate): the routed
    // tenant must have granted autonomous execution and its kill switch must
    // be disengaged. A missing row is `disabled`, the fail-closed default.
    let state: Option<(String, bool)> = sqlx::query_as(AUTONOMY_STATE_SQL)
        .bind(tenant_id)
        .fetch_optional(&mut *conn)
        .await
        .map_err(|e| SalesError::Database(e.to_string()))?;
    let (autonomy_mode, kill_switch) = match state {
        Some((mode, kill_switch)) => (AutonomyMode::parse(&mode), kill_switch),
        None => (AutonomyMode::Disabled, false),
    };
    if kill_switch {
        reasons.push(
            "kill_switch_engaged: outbound halted by the operator; the class reverts to approval"
                .into(),
        );
    }
    if !autonomy_mode.may_execute_autonomously() {
        reasons.push(format!(
            "autonomy_not_granted: tenant mode is '{autonomy_mode}'; only 'autonomous_guarded' \
             permits autonomous execution"
        ));
    } else {
        // Ring 4 — invariant I22: the MODE grants execution; an active,
        // OWNER-APPROVED policy pack covering this tenant AND the action kind
        // (with budget left) is the AUTHORITY. Fail-closed: no pack, wrong
        // action coverage or exhausted caps refuse here.
        let verdict =
            crate::policy_packs::evaluate(&mut *conn, tenant_id, "reply_autosend").await?;
        if !verdict.allowed {
            reasons.extend(verdict.reasons);
        }
    }

    Ok(GateVerdict {
        tenant_id: tenant_id.to_string(),
        reply_class: class,
        allowed: reasons.is_empty(),
        reasons,
        evidence,
        enabled_at: grant.as_ref().and_then(|row| row.enabled_at),
        enabled_by: grant.as_ref().and_then(|row| row.enabled_by.clone()),
        autonomy_mode,
        kill_switch,
    })
}

/// Database-backed gate tests.
///
/// The approval rows these tests seed are the EXACT rows the api-server
/// approval path writes (`audit_logs`, action
/// `control_plane.ai_draft.approved`, `details.routedTenantId` +
/// `details.replyClass`). api-server's own suite drives the real approval
/// endpoint end to end and proves the same query counts those approvals; here
/// the point is that the query counts ONLY them: a wrong action, a missing
/// class, a class from another tenant, or a row outside the window all count
/// zero, and no counter column exists to set instead.
#[cfg(test)]
mod gate_db_tests {
    use super::*;
    use crate::test_db::{canonical_test_pool, unique_test_tenant};
    use sqlx::PgPool;

    /// Seed N approval audit rows for (tenant, class) aged `age_days`.
    async fn seed_approvals(
        pool: &PgPool,
        tenant: &str,
        class: LowRiskClass,
        count: i64,
        age_days: i64,
    ) {
        for index in 0..count {
            sqlx::query(
                "INSERT INTO audit_logs (id, tenant_id, user_id, action, resource, resource_id, \
                     details, outcome, timestamp, created_at, hash, signature) \
                 VALUES ($1, 'system', NULL, 'control_plane.ai_draft.approved', 'ai_draft', $2, \
                     jsonb_build_object('routedTenantId', $3::text, 'replyClass', $4::text), \
                     'success', NOW() - make_interval(days => $5::int), \
                     NOW() - make_interval(days => $5::int), '', '')",
            )
            .bind(format!("audit_f9_{tenant}_{index}_{age_days}"))
            .bind(format!("inb_f9{index:016}"))
            .bind(tenant)
            .bind(class.as_str())
            .bind(age_days as i32)
            .execute(pool)
            .await
            .expect("seed approval audit row");
        }
    }

    async fn seed_tenant(pool: &PgPool, tenant: &str, mode: &str, kill_switch: bool) {
        sqlx::query(
            "INSERT INTO sales_autonomy_state (tenant_id, mode, kill_switch) VALUES ($1, $2, $3) \
             ON CONFLICT (tenant_id) DO UPDATE SET mode = $2, kill_switch = $3, updated_at = NOW()",
        )
        .bind(tenant)
        .bind(mode)
        .bind(kill_switch)
        .execute(pool)
        .await
        .expect("seed autonomy state");
    }

    /// Invariant I22 — the pack ring. Grant + evidence + autonomy all pass,
    /// but the AUTHORITY is the pack: missing, wrong-action, expired and
    /// exhausted packs all refuse; a covering pack with budget allows.
    #[tokio::test]
    async fn autonomous_send_requires_an_active_owner_approved_policy_pack() {
        let Some(pool) = canonical_test_pool("f9_policy_pack").await else {
            return;
        };
        let tenant = unique_test_tenant("f9pack");
        let class = LowRiskClass::Scheduling;

        // The pack table has a real FK to tenants — the tenant must exist.
        sqlx::query(
            "INSERT INTO tenants (id, name, plan, status) \
             VALUES ($1, $2, 'free', 'active') ON CONFLICT (id) DO NOTHING",
        )
        .bind(&tenant)
        .bind(format!("I22 {tenant}"))
        .execute(&pool)
        .await
        .expect("seed tenant");

        // Seed everything EXCEPT the pack: grant row + evidence + autonomy.
        sqlx::query(
            "INSERT INTO sales_autonomy_state (tenant_id, mode, kill_switch) \
             VALUES ($1, 'autonomous_guarded', FALSE) \
             ON CONFLICT (tenant_id) DO UPDATE SET mode = 'autonomous_guarded', kill_switch = FALSE",
        )
        .bind(&tenant)
        .execute(&pool)
        .await
        .expect("seed autonomy");
        sqlx::query(
            "INSERT INTO reply_autosend_grants (tenant_id, reply_class, enabled, \
                enabled_by, enabled_at, evidence_required_approvals, evidence_window_days) \
             VALUES ($1, $2, TRUE, 'test-operator', NOW(), 10, 30) \
             ON CONFLICT (tenant_id, reply_class) DO UPDATE SET enabled = TRUE, \
                enabled_by = EXCLUDED.enabled_by, enabled_at = EXCLUDED.enabled_at, \
                evidence_required_approvals = 10, evidence_window_days = 30",
        )
        .bind(&tenant)
        .bind(class.as_str())
        .execute(&pool)
        .await
        .expect("seed grant");
        // Real approvals satisfy the evidence ring (floor: 10 in 30 days).
        seed_approvals(&pool, &tenant, class, 10, 1).await;

        let mut conn = pool.acquire().await.expect("acquire");

        // No pack: refused with the typed reason (fail closed).
        let verdict = evaluate_for_send(&mut conn, &tenant, class)
            .await
            .expect("evaluate without a pack");
        assert!(!verdict.allowed);
        assert!(
            verdict
                .reasons
                .iter()
                .any(|r| r.contains("policy_pack_missing")),
            "{:?}",
            verdict.reasons
        );

        // A pack that does not cover the action kind: still refused.
        crate::policy_packs::approve(
            &pool,
            &tenant,
            "research-only",
            &["research".to_string()],
            100,
            1000,
            "audit-operator",
        )
        .await
        .expect("approve research-only pack");
        let verdict = evaluate_for_send(&mut conn, &tenant, class)
            .await
            .expect("evaluate with a non-covering pack");
        assert!(!verdict.allowed);
        assert!(
            verdict
                .reasons
                .iter()
                .any(|r| r.contains("policy_pack_action_not_covered")),
            "{:?}",
            verdict.reasons
        );

        // An EXPIRED covering pack: refused.
        sqlx::query("DELETE FROM sales_policy_packs WHERE tenant_id = $1")
            .bind(&tenant)
            .execute(&pool)
            .await
            .expect("clear packs");
        crate::policy_packs::approve(
            &pool,
            &tenant,
            "expired-pack",
            &["reply_autosend".to_string()],
            100,
            1000,
            "audit-operator",
        )
        .await
        .expect("approve expired pack");
        sqlx::query("UPDATE sales_policy_packs SET expires_at = NOW() - INTERVAL '1 day' WHERE tenant_id = $1")
            .bind(&tenant)
            .execute(&pool)
            .await
            .expect("expire pack");
        let verdict = evaluate_for_send(&mut conn, &tenant, class)
            .await
            .expect("evaluate with an expired pack");
        assert!(!verdict.allowed);
        assert!(
            verdict
                .reasons
                .iter()
                .any(|r| r.contains("policy_pack_missing")),
            "an expired pack must fail closed: {:?}",
            verdict.reasons
        );

        // A covering, active, owner-approved pack: allowed.
        sqlx::query("DELETE FROM sales_policy_packs WHERE tenant_id = $1")
            .bind(&tenant)
            .execute(&pool)
            .await
            .expect("clear packs");
        crate::policy_packs::approve(
            &pool,
            &tenant,
            "reply-pack",
            &["reply_autosend".to_string(), "sequence_send".to_string()],
            100,
            1000,
            "audit-operator",
        )
        .await
        .expect("approve covering pack");
        let verdict = evaluate_for_send(&mut conn, &tenant, class)
            .await
            .expect("evaluate with the covering pack");
        assert!(
            verdict.allowed,
            "a covering pack authorizes the send: {:?}",
            verdict.reasons
        );

        // Budget: cap the pack at zero remaining (2 today, cap 2) and the
        // same gate refuses with the cap reason.
        sqlx::query("UPDATE sales_policy_packs SET daily_message_cap = 2 WHERE tenant_id = $1")
            .bind(&tenant)
            .execute(&pool)
            .await
            .expect("set cap");
        // Seed the REAL production ledger rows: the auto-send path writes
        // `control_plane.ai_draft.auto_sent` under the system tenant with the
        // routed tenant in details.tenantId (ai_drafts.rs auto-send txn).
        for i in 0..2 {
            sqlx::query(
                "INSERT INTO audit_logs (id, tenant_id, user_id, action, resource, resource_id, \
                     details, outcome, timestamp, created_at, hash, signature) \
                 VALUES ($1, 'system', NULL, 'control_plane.ai_draft.auto_sent', 'ai_draft', $3, \
                     jsonb_build_object('tenantId', $2::text, 'replyClass', 'scheduling'), \
                     'success', NOW(), NOW(), '', '')",
            )
            .bind(format!("pack_budget_{tenant}_{i}"))
            .bind(&tenant)
            .bind(format!("inb_pack_{tenant}_{i}"))
            .execute(&pool)
            .await
            .expect("seed autonomous send audit");
        }
        let verdict = evaluate_for_send(&mut conn, &tenant, class)
            .await
            .expect("evaluate with an exhausted cap");
        assert!(!verdict.allowed);
        assert!(
            verdict
                .reasons
                .iter()
                .any(|r| r.contains("policy_pack_daily_cap_reached")),
            "{:?}",
            verdict.reasons
        );

        sqlx::query(
            "DELETE FROM audit_logs WHERE action = 'control_plane.ai_draft.auto_sent' \
             AND details->>'tenantId' = $1",
        )
        .bind(&tenant)
        .execute(&pool)
        .await
        .expect("cleanup audits");
        sqlx::query("DELETE FROM sales_policy_packs WHERE tenant_id = $1")
            .bind(&tenant)
            .execute(&pool)
            .await
            .expect("cleanup packs");
    }

    /// Seed a live user in the system tenant with the given role.
    async fn seed_user(pool: &PgPool, email: &str, role: &str) -> String {
        sqlx::query(
            "INSERT INTO tenants (id, name, plan, status, created_at, updated_at) \
             VALUES ('system', 'System', 'free', 'active', NOW(), NOW()) \
             ON CONFLICT (id) DO NOTHING",
        )
        .execute(pool)
        .await
        .expect("seed system tenant");
        let id = uuid::Uuid::new_v4().to_string();
        sqlx::query(
            "INSERT INTO users (id, tenant_id, email, name, role, status, password_hash, email_verified) \
             VALUES ($1::uuid, 'system', $2, 'F9 Actor', $3, 'active', 'x', true) \
             ON CONFLICT (email) DO UPDATE SET role = EXCLUDED.role, id = EXCLUDED.id",
        )
        .bind(&id)
        .bind(email)
        .bind(role)
        .execute(pool)
        .await
        .expect("seed user");
        sqlx::query_scalar::<_, uuid::Uuid>("SELECT id FROM users WHERE email = $1")
            .bind(email)
            .fetch_one(pool)
            .await
            .expect("user id")
            .to_string()
    }

    /// The (tenant, class) state is OFF with no row, and only real recorded
    /// approvals satisfy the evidence — wrong action, missing/foreign class,
    /// and out-of-window rows all count zero.
    #[tokio::test]
    async fn default_off_and_evidence_is_only_real_recorded_approvals() {
        let Some(pool) = canonical_test_pool("f9_default_off").await else {
            return;
        };
        let tenant = unique_test_tenant("f9off");
        let class = LowRiskClass::Scheduling;
        let mut conn = pool.acquire().await.expect("acquire");

        // No row, no autonomy state: OFF, fail closed.
        let verdict = evaluate_for_send(&mut conn, &tenant, class)
            .await
            .expect("evaluate without a row");
        assert!(!verdict.allowed);
        assert!(
            verdict.reasons.iter().any(|r| r.contains("grant_missing")),
            "{:?}",
            verdict.reasons
        );
        assert_eq!(verdict.autonomy_mode, AutonomyMode::Disabled);

        // Rows that LOOK like evidence but are not the recorded approval shape.
        for (action, routed, reply_class, age_days) in [
            (
                "control_plane.ai_draft.auto_sent",
                tenant.as_str(),
                "scheduling",
                0,
            ),
            (APPROVED_AUDIT_ACTION, "someone-else", "scheduling", 0),
            (APPROVED_AUDIT_ACTION, tenant.as_str(), "clarification", 0),
            (APPROVED_AUDIT_ACTION, tenant.as_str(), "scheduling", 40),
        ] {
            sqlx::query(
                "INSERT INTO audit_logs (id, tenant_id, action, resource, resource_id, details, \
                     outcome, timestamp, created_at, hash, signature) \
                 VALUES ($1, 'system', $2, 'ai_draft', $3, \
                     jsonb_build_object('routedTenantId', $4::text, 'replyClass', $5::text), \
                     'success', NOW() - make_interval(days => $6::int), \
                     NOW() - make_interval(days => $6::int), '', '')",
            )
            .bind(format!("audit_f9_noise_{action}_{age_days}"))
            .bind(action)
            .bind(format!("inb_noise{age_days}"))
            .bind(routed)
            .bind(reply_class)
            .bind(age_days)
            .execute(&pool)
            .await
            .expect("seed non-matching row");
        }
        let evidence = evidence_report(
            &mut conn,
            &tenant,
            class,
            DEFAULT_REQUIRED_APPROVALS,
            DEFAULT_EVIDENCE_WINDOW_DAYS,
        )
        .await
        .expect("evidence");
        assert_eq!(
            evidence.approved_and_sent, 0,
            "only the canonical approval shape may count: {evidence:?}"
        );
        assert!(!evidence.satisfied);

        // Ten matching in-window approvals: the count follows the records.
        seed_approvals(&pool, &tenant, class, 10, 1).await;
        let evidence = evidence_report(&mut conn, &tenant, class, 10, 30)
            .await
            .expect("evidence");
        assert_eq!(evidence.approved_and_sent, 10, "{evidence:?}");
        assert!(evidence.satisfied, "{evidence:?}");

        // A complaint in the window flips satisfied to false even with ample
        // approvals: zero tolerance.
        sqlx::query(
            "INSERT INTO sales_reply_classifications \
                 (id, tenant_id, disposition, confidence, classifier) \
             VALUES ($1::uuid, $2, 'complaint', 0.9, 'deterministic')",
        )
        .bind(uuid::Uuid::new_v4().to_string())
        .bind(&tenant)
        .execute(&pool)
        .await
        .expect("seed complaint");
        let evidence = evidence_report(&mut conn, &tenant, class, 10, 30)
            .await
            .expect("evidence");
        assert_eq!(evidence.complaints_or_optouts, 1, "{evidence:?}");
        assert!(!evidence.satisfied, "{evidence:?}");
    }

    /// Enablement is owner-scope only, refuses unsatisfied evidence, refuses a
    /// class whose approvals it does not have, and refuses out-of-bounds bars.
    #[tokio::test]
    async fn enable_requires_the_owner_and_satisfied_evidence() {
        let Some(pool) = canonical_test_pool("f9_enable").await else {
            return;
        };
        let tenant = unique_test_tenant("f9en");
        let class = LowRiskClass::Scheduling;
        let admin = seed_user(&pool, "f9-admin@apexmail.test", "admin").await;
        let owner = seed_user(&pool, "f9-owner@apexmail.test", "owner").await;
        let mut conn = pool.acquire().await.expect("acquire");

        // A live admin — however privileged — is not the owner.
        let refused = OwnerActor::verify(&mut conn, &admin).await;
        assert!(
            matches!(refused, Err(SalesError::Unauthorized(_))),
            "a non-owner must not become an OwnerActor: {refused:?}"
        );
        // An unknown id fails closed too.
        assert!(
            OwnerActor::verify(&mut conn, &uuid::Uuid::new_v4().to_string())
                .await
                .is_err()
        );
        let owner_actor = OwnerActor::verify(&mut conn, &owner)
            .await
            .expect("the live owner verifies");

        // No evidence: refused with the numbers.
        let refused = enable(
            &mut conn,
            &tenant,
            class,
            &owner_actor,
            MIN_REQUIRED_APPROVALS,
            30,
        )
        .await;
        match refused {
            Err(SalesError::InvalidInput(message)) => {
                assert!(message.contains("evidence not satisfied"), "{message}")
            }
            other => panic!("expected an evidence refusal, got {other:?}"),
        }

        // Evidence for the wrong class does not enable this one.
        seed_approvals(&pool, &tenant, LowRiskClass::Clarification, 10, 1).await;
        assert!(enable(
            &mut conn,
            &tenant,
            class,
            &owner_actor,
            MIN_REQUIRED_APPROVALS,
            30
        )
        .await
        .is_err());

        // Out-of-bounds bars are refused before any evidence is read.
        seed_approvals(&pool, &tenant, class, 10, 1).await;
        for (required, window) in [(1_i64, 30_i64), (10, 120), (10, 1), (0, 30)] {
            let refused = enable(&mut conn, &tenant, class, &owner_actor, required, window).await;
            assert!(
                matches!(refused, Err(SalesError::InvalidInput(_))),
                "bars ({required}, {window}) must be refused: {refused:?}"
            );
        }

        // The honest path: evidence satisfied + owner → enabled, with the
        // evidence captured on the row and the owner attributed.
        let report = enable(&mut conn, &tenant, class, &owner_actor, 10, 30)
            .await
            .expect("enable with evidence");
        assert!(report.satisfied);
        let row = load_grant(&mut conn, &tenant, class)
            .await
            .expect("load grant")
            .expect("grant row exists");
        assert!(row.enabled);
        assert_eq!(row.enabled_by.as_deref(), Some(owner.as_str()));
        assert_eq!(row.evidence_snapshot["approved_and_sent"], 10);

        // Per-class isolation: the other classes stay off.
        for other in LowRiskClass::ALL.into_iter().filter(|c| *c != class) {
            assert!(
                load_grant(&mut conn, &tenant, other)
                    .await
                    .expect("load other")
                    .is_none(),
                "{other} must stay OFF"
            );
        }
    }

    /// The three rings at send time: grant off/absent, evidence lapse, and the
    /// tenant's mode/kill switch all revert the class to human approval.
    #[tokio::test]
    async fn send_time_recheck_reverts_to_approval_on_every_lapse() {
        let Some(pool) = canonical_test_pool("f9_send_time").await else {
            return;
        };
        let tenant = unique_test_tenant("f9st");
        let class = LowRiskClass::Scheduling;
        let owner = seed_user(&pool, "f9-owner2@apexmail.test", "owner").await;
        let mut conn = pool.acquire().await.expect("acquire");
        let owner_actor = OwnerActor::verify(&mut conn, &owner).await.expect("owner");

        seed_tenant(&pool, &tenant, "autonomous_guarded", false).await;
        seed_approvals(&pool, &tenant, class, 10, 1).await;
        enable(&mut conn, &tenant, class, &owner_actor, 10, 30)
            .await
            .expect("enable");
        // Ring 4 (invariant I22): the covering owner-approved pack this send
        // needs. The recheck below flips OTHER rings; the pack stays valid so
        // each assert names exactly the ring under test.
        sqlx::query(
            "INSERT INTO tenants (id, name, plan, status) VALUES ($1, $2, 'free', 'active') \
             ON CONFLICT (id) DO NOTHING",
        )
        .bind(&tenant)
        .bind(format!("I22 {tenant}"))
        .execute(&pool)
        .await
        .expect("seed tenant for the pack");
        crate::policy_packs::approve(
            &pool,
            &tenant,
            "gate-pack",
            &["reply_autosend".to_string()],
            1_000,
            10_000,
            "gate-owner",
        )
        .await
        .expect("approve pack");

        // All four rings satisfied: allowed.
        let verdict = evaluate_for_send(&mut conn, &tenant, class)
            .await
            .expect("evaluate");
        assert!(verdict.allowed, "{:?}", verdict.reasons);
        assert_eq!(verdict.autonomy_mode, AutonomyMode::AutonomousGuarded);

        // Ring 3a: the kill switch. Re-checked at send time, immediate.
        seed_tenant(&pool, &tenant, "autonomous_guarded", true).await;
        let verdict = evaluate_for_send(&mut conn, &tenant, class)
            .await
            .expect("evaluate");
        assert!(!verdict.allowed);
        assert!(verdict.reasons.iter().any(|r| r.contains("kill_switch")));
        seed_tenant(&pool, &tenant, "autonomous_guarded", false).await;

        // Ring 3b: the tenant's mode reverts (autonomy not granted).
        seed_tenant(&pool, &tenant, "shadow", false).await;
        let verdict = evaluate_for_send(&mut conn, &tenant, class)
            .await
            .expect("evaluate");
        assert!(!verdict.allowed);
        assert!(verdict
            .reasons
            .iter()
            .any(|r| r.contains("autonomy_not_granted")));

        // Ring 3c: the row disappears entirely (a tenant with no state row).
        sqlx::query("DELETE FROM sales_autonomy_state WHERE tenant_id = $1")
            .bind(&tenant)
            .execute(&pool)
            .await
            .expect("delete autonomy state");
        let verdict = evaluate_for_send(&mut conn, &tenant, class)
            .await
            .expect("evaluate");
        assert!(!verdict.allowed);
        assert_eq!(verdict.autonomy_mode, AutonomyMode::Disabled);
        seed_tenant(&pool, &tenant, "autonomous_guarded", false).await;

        // Ring 2: evidence lapses when the approvals fall out of the window.
        // 20-day-old approvals satisfy a 30-day window…
        sqlx::query("DELETE FROM audit_logs WHERE details->>'routedTenantId' = $1")
            .bind(&tenant)
            .execute(&pool)
            .await
            .expect("clear approval rows");
        seed_approvals(&pool, &tenant, class, 10, 20).await;
        let verdict = evaluate_for_send(&mut conn, &tenant, class)
            .await
            .expect("evaluate");
        assert!(verdict.allowed, "{:?}", verdict.reasons);
        // …and lapse the moment the owner tightens the window to 7 days.
        sqlx::query(
            "UPDATE reply_autosend_grants SET evidence_window_days = 7, updated_at = NOW() \
             WHERE tenant_id = $1 AND reply_class = $2",
        )
        .bind(&tenant)
        .bind(class.as_str())
        .execute(&pool)
        .await
        .expect("tighten window");
        let verdict = evaluate_for_send(&mut conn, &tenant, class)
            .await
            .expect("evaluate");
        assert!(!verdict.allowed, "{:?}", verdict.reasons);
        assert!(
            verdict
                .reasons
                .iter()
                .any(|r| r.contains("evidence_lapsed")),
            "{:?}",
            verdict.reasons
        );
        sqlx::query(
            "UPDATE reply_autosend_grants SET evidence_window_days = 30, updated_at = NOW() \
             WHERE tenant_id = $1 AND reply_class = $2",
        )
        .bind(&tenant)
        .bind(class.as_str())
        .execute(&pool)
        .await
        .expect("restore window");
        let verdict = evaluate_for_send(&mut conn, &tenant, class)
            .await
            .expect("evaluate");
        assert!(verdict.allowed, "{:?}", verdict.reasons);

        // Ring 1: revocation (the per-class kill switch) keeps the row but
        // turns the class off immediately.
        assert!(revoke(&mut conn, &tenant, class, &owner_actor)
            .await
            .expect("revoke"));
        let verdict = evaluate_for_send(&mut conn, &tenant, class)
            .await
            .expect("evaluate");
        assert!(!verdict.allowed);
        assert!(verdict.reasons.iter().any(|r| r.contains("grant_disabled")));
        // Revoking again is a no-op, never an error.
        assert!(!revoke(&mut conn, &tenant, class, &owner_actor)
            .await
            .expect("revoke twice"));

        // Re-enabling requires the evidence to hold again at that instant:
        // empty the window, then re-earn it.
        sqlx::query("DELETE FROM audit_logs WHERE details->>'routedTenantId' = $1")
            .bind(&tenant)
            .execute(&pool)
            .await
            .expect("clear approval rows");
        let refused = enable(&mut conn, &tenant, class, &owner_actor, 10, 30).await;
        assert!(
            matches!(refused, Err(SalesError::InvalidInput(_))),
            "a re-enable without evidence must be refused: {refused:?}"
        );
        seed_approvals(&pool, &tenant, class, 10, 1).await;
        enable(&mut conn, &tenant, class, &owner_actor, 10, 30)
            .await
            .expect("re-enable once the evidence is earned again");
        let verdict = evaluate_for_send(&mut conn, &tenant, class)
            .await
            .expect("evaluate");
        assert!(verdict.allowed, "{:?}", verdict.reasons);
    }

    /// The grant table's own constraints: a (tenant, class) is the unit, an
    /// enabled row must carry its owner attribution, and the bars have floors.
    #[tokio::test]
    async fn grant_constraints_pin_the_promotion_unit() {
        let Some(pool) = canonical_test_pool("f9_constraints").await else {
            return;
        };
        let tenant = unique_test_tenant("f9con");

        // An enabled row without attribution is unrepresentable.
        let unr = sqlx::query(
            "INSERT INTO reply_autosend_grants (tenant_id, reply_class, enabled) \
             VALUES ($1, 'scheduling', TRUE)",
        )
        .bind(&tenant)
        .execute(&pool)
        .await;
        assert!(unr.is_err(), "enabled without enabled_by must be refused");

        // Unknown classes and sub-floor bars are refused by the CHECKs.
        for sql in [
            "INSERT INTO reply_autosend_grants (tenant_id, reply_class, enabled) \
                 VALUES ($1, 'autonomous_full', FALSE)",
            "INSERT INTO reply_autosend_grants \
                 (tenant_id, reply_class, enabled, evidence_required_approvals) \
                 VALUES ($1, 'scheduling', FALSE, 1)",
            "INSERT INTO reply_autosend_grants \
                 (tenant_id, reply_class, enabled, evidence_window_days) \
                 VALUES ($1, 'scheduling', FALSE, 365)",
        ] {
            let refused = sqlx::query(sql).bind(&tenant).execute(&pool).await;
            assert!(refused.is_err(), "must be refused by the CHECK: {sql}");
        }

        // A hand-edited disabled row is still not a grant: evaluate fails.
        sqlx::query(
            "INSERT INTO reply_autosend_grants (tenant_id, reply_class, enabled) \
             VALUES ($1, 'scheduling', FALSE)",
        )
        .bind(&tenant)
        .execute(&pool)
        .await
        .expect("disabled row inserts");
        let mut conn = pool.acquire().await.expect("acquire");
        let verdict = evaluate_for_send(&mut conn, &tenant, LowRiskClass::Scheduling)
            .await
            .expect("evaluate");
        assert!(!verdict.allowed);
        assert!(verdict.reasons.iter().any(|r| r.contains("grant_disabled")));
    }

    /// The owner-flagged contract-tier decision-maker list is read from the
    /// tenant's autonomy rules, matched case-insensitively, and absent/!array
    /// values mean "nothing flagged" (never an error).
    #[tokio::test]
    async fn flagged_recipients_come_from_the_owner_managed_rules() {
        let Some(pool) = canonical_test_pool("f9_flags").await else {
            return;
        };
        let tenant = unique_test_tenant("f9flag");
        let mut conn = pool.acquire().await.expect("acquire");

        // No row at all: nothing flagged, no error.
        assert_eq!(
            flagged_recipients(&mut conn, &tenant).await.expect("read"),
            Vec::<String>::new()
        );

        seed_tenant(&pool, &tenant, "autonomous_guarded", false).await;
        // A row with no flags key.
        assert_eq!(
            flagged_recipients(&mut conn, &tenant).await.expect("read"),
            Vec::<String>::new()
        );

        // The owner flags two decision-makers (mixed case / whitespace).
        sqlx::query(
            "UPDATE sales_autonomy_state SET rules = jsonb_build_object($2, \
                 jsonb_build_array(' CEO@BigCorp.example ', 'cto@other.example')) \
             WHERE tenant_id = $1",
        )
        .bind(&tenant)
        .bind(FLAGGED_RECIPIENTS_RULE_KEY)
        .execute(&pool)
        .await
        .expect("set rules");

        let flagged = flagged_recipients(&mut conn, &tenant).await.expect("read");
        assert_eq!(
            flagged,
            vec![
                "ceo@bigcorp.example".to_string(),
                "cto@other.example".to_string()
            ]
        );
        assert!(recipient_is_flagged(&flagged, "Ceo@BigCorp.example"));
        assert!(recipient_is_flagged(&flagged, " cto@other.example "));
        assert!(!recipient_is_flagged(&flagged, "someone@else.example"));
        assert!(!recipient_is_flagged(&flagged, ""));

        // A malformed (non-array) value fails closed to "nothing flagged"
        // rather than erroring the sweep.
        sqlx::query(
            "UPDATE sales_autonomy_state SET rules = jsonb_build_object($2, 42) \
             WHERE tenant_id = $1",
        )
        .bind(&tenant)
        .bind(FLAGGED_RECIPIENTS_RULE_KEY)
        .execute(&pool)
        .await
        .expect("set malformed rules");
        assert_eq!(
            flagged_recipients(&mut conn, &tenant).await.expect("read"),
            Vec::<String>::new()
        );
    }

    /// A hand-written "satisfied" snapshot — the closest thing to a forgeable
    /// counter the schema allows — does not open the gate: the send-time check
    /// recomputes the evidence from the canonical records and ignores the
    /// snapshot. Same for an enabled row whose attribution is faked by a
    /// direct UPDATE that bypasses [`enable`]: the live evidence still has to
    /// hold.
    #[tokio::test]
    async fn a_forged_evidence_snapshot_never_opens_the_gate() {
        let Some(pool) = canonical_test_pool("f9_forged").await else {
            return;
        };
        let tenant = unique_test_tenant("f9forge");
        let class = LowRiskClass::Scheduling;
        seed_tenant(&pool, &tenant, "autonomous_guarded", false).await;

        // A forged row: enabled, attributed, with a fabricated evidence report
        // that claims 999 approvals and zero complaints.
        sqlx::query(
            "INSERT INTO reply_autosend_grants \
                 (tenant_id, reply_class, enabled, enabled_by, enabled_at, \
                  evidence_required_approvals, evidence_window_days, evidence_snapshot) \
             VALUES ($1, 'scheduling', TRUE, 'forged-actor', NOW(), 10, 30, \
                     '{\"approved_and_sent\": 999, \"complaints_or_optouts\": 0, \
                       \"required_approvals\": 10, \"window_days\": 30, \"satisfied\": true}'::jsonb)",
        )
        .bind(&tenant)
        .execute(&pool)
        .await
        .expect("forged row inserts (the CHECKs cannot see JSON)");

        let mut conn = pool.acquire().await.expect("acquire");
        let verdict = evaluate_for_send(&mut conn, &tenant, class)
            .await
            .expect("evaluate");
        assert!(
            !verdict.allowed,
            "a fabricated snapshot must not authorise a send: {:?}",
            verdict.reasons
        );
        assert!(
            verdict
                .reasons
                .iter()
                .any(|r| r.contains("evidence_lapsed")),
            "{:?}",
            verdict.reasons
        );
        assert_eq!(
            verdict.evidence.approved_and_sent, 0,
            "the live evidence is derived, never read from the snapshot"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input<'a>(draft: &'a str, intent: &'a str) -> DraftRiskInput<'a> {
        DraftRiskInput {
            draft_text: draft,
            intent_class: Some(intent),
            intent_confidence: Some(0.95),
            suggestion: None,
            recipient_owner_flagged: false,
            first_message_of_new_sequence: false,
        }
    }

    // ── The classifier table ─────────────────────────────────────────

    #[test]
    fn low_classes_are_reachable_for_their_intents() {
        let cases = [
            (
                "Thanks for the note — I will review it and get back to you.",
                "ooo",
                LowRiskClass::Acknowledgement,
            ),
            (
                "Thursday 10:00 works for us — shall I send an invite?",
                "meeting_request",
                LowRiskClass::Scheduling,
            ),
            (
                "Happy to clarify: which part of the question should I expand on?",
                "question",
                LowRiskClass::Clarification,
            ),
            (
                "Done — you have been unsubscribed and will not receive further messages.",
                "unsubscribe",
                LowRiskClass::OptOutConfirmation,
            ),
        ];
        for (draft, intent, expected) in cases {
            let verdict = classify_draft(&input(draft, intent));
            assert_eq!(
                verdict.risk,
                ReplyRisk::Low(expected),
                "draft {draft:?} intent {intent} must classify LOW {expected}"
            );
        }
    }

    #[test]
    fn every_canonical_disposition_maps_to_an_explicit_verdict() {
        // The intent map must cover the whole taxonomy: no disposition may
        // fall through to a permissive default.
        let expected_high = [
            "positive",
            "referral",
            "not_interested",
            "complaint",
            "bounce_hard",
            "bounce_soft",
            "unknown",
        ];
        for disposition in CANONICAL_DISPOSITIONS {
            let verdict = classify_draft(&input("Thanks for the note.", disposition));
            if expected_high.contains(&disposition) {
                assert_eq!(
                    verdict.risk,
                    ReplyRisk::High(HighRiskReason::DispositionNotLowRisk),
                    "{disposition} must be HIGH"
                );
            } else {
                assert!(verdict.risk.is_low(), "{disposition} must be LOW");
            }
        }
    }

    #[test]
    fn pricing_legal_and_security_language_is_high_even_when_grounded() {
        for (draft, expected) in [
            (
                "Our plan pricing starts per month — shall I book a call?",
                HighRiskReason::PricingOrCommitment,
            ),
            (
                "We can sign the DPA next week once legal reviews it.",
                HighRiskReason::LegalOrContract,
            ),
            (
                "The platform handles encryption at rest for every tenant.",
                HighRiskReason::SecurityOrInfrastructure,
            ),
        ] {
            let verdict = classify_draft(&input(draft, "question"));
            assert_eq!(
                verdict.risk,
                ReplyRisk::High(expected),
                "draft {draft:?} must be HIGH {expected}"
            );
        }
    }

    #[test]
    fn unbacked_claims_fail_closed() {
        // A restricted capability (SSO) with no verified external-copy fact.
        let verdict = classify_draft(&input(
            "We support SSO for enterprise accounts.",
            "question",
        ));
        assert_eq!(verdict.risk, ReplyRisk::High(HighRiskReason::UnbackedClaim));
        assert!(verdict
            .grounding_failures
            .iter()
            .any(|check| check.kind == "restricted_capability"));

        // A figure no external-copy fact carries.
        let verdict = classify_draft(&input(
            "We handle up to 900000 messages per day on one node.",
            "question",
        ));
        assert_eq!(verdict.risk, ReplyRisk::High(HighRiskReason::UnbackedClaim));
        assert!(verdict
            .grounding_failures
            .iter()
            .any(|check| check.kind == "ungrounded_number"));

        // Citation markers with no retrieval behind them.
        let verdict = classify_draft(&input(
            "Yes, that is documented in our public API docs [1].",
            "question",
        ));
        assert_eq!(verdict.risk, ReplyRisk::High(HighRiskReason::UnbackedClaim));
        assert!(verdict
            .grounding_failures
            .iter()
            .any(|check| check.kind == "citation_marker"));
    }

    #[test]
    fn grounded_factual_question_is_the_documentation_class() {
        // A KB-backed factual sentence: the REST sending API fact
        // (verified, external-copy-allowed, its figures carried by itself).
        let kb = knowledge_base();
        let fact = kb
            .external_copy_facts()
            .into_iter()
            .find(|fact| fact.id == "KB-FEAT-REST-SENDING")
            .expect("the canonical KB carries KB-FEAT-REST-SENDING");
        let sentence = fact.claim.clone();
        assert!(
            is_factual_claim(&sentence.to_lowercase()),
            "the fixture fact must be assertion-shaped: {sentence}"
        );
        let verdict = classify_draft(&input(&sentence, "question"));
        assert_eq!(verdict.grounding_failures, vec![], "{verdict:?}");
        assert!(verdict.has_factual_claims, "{verdict:?}");
        assert_eq!(
            verdict.risk,
            ReplyRisk::Low(LowRiskClass::Documentation),
            "{verdict:?}"
        );
    }

    #[test]
    fn structural_failures_are_high_in_safety_order() {
        // Empty draft.
        let verdict = classify_draft(&input("   ", "question"));
        assert_eq!(verdict.risk, ReplyRisk::High(HighRiskReason::EmptyDraft));

        // Missing intent class.
        let mut risk_input = input("Happy to help.", "question");
        risk_input.intent_class = None;
        assert_eq!(
            classify_draft(&risk_input).risk,
            ReplyRisk::High(HighRiskReason::MissingIntentClass)
        );

        // Unknown intent class (not one of the canonical 11).
        let verdict = classify_draft(&input("Happy to help.", "maybe_interested"));
        assert_eq!(
            verdict.risk,
            ReplyRisk::High(HighRiskReason::UnknownIntentClass)
        );

        // Confidence below the worker's 0.7 gate, non-finite, and missing.
        for confidence in [Some(0.69), Some(f64::NAN), Some(f64::INFINITY), None] {
            let mut risk_input = input("Thanks — noted.", "ooo");
            risk_input.intent_confidence = confidence;
            assert_eq!(
                classify_draft(&risk_input).risk,
                ReplyRisk::High(HighRiskReason::LowConfidence),
                "confidence {confidence:?} must fail closed"
            );
        }
    }

    #[test]
    fn owner_flags_and_first_touch_are_high() {
        let mut risk_input = input("Thanks — noted.", "ooo");
        risk_input.recipient_owner_flagged = true;
        assert_eq!(
            classify_draft(&risk_input).risk,
            ReplyRisk::High(HighRiskReason::FlaggedDecisionMaker)
        );

        let mut risk_input = input("Hello — introducing ourselves.", "question");
        risk_input.first_message_of_new_sequence = true;
        assert_eq!(
            classify_draft(&risk_input).risk,
            ReplyRisk::High(HighRiskReason::FirstMessageOfNewSequence)
        );

        // The marker derives deterministically from suggested_action.
        assert!(first_touch_marker(Some(&serde_json::json!({
            "first_touch": true
        }))));
        assert!(first_touch_marker(Some(&serde_json::json!({
            "sequence_step": 1
        }))));
        assert!(!first_touch_marker(Some(&serde_json::json!({
            "sequence_step": 2
        }))));
        assert!(!first_touch_marker(None));
    }

    #[test]
    fn objection_subclasses_that_are_not_low_risk_are_high() {
        for objection in ["price", "trust", "authority"] {
            let mut risk_input = input("Thanks for the note.", "question");
            let suggestion = serde_json::json!({ "objection_class": objection });
            risk_input.suggestion = Some(&suggestion);
            assert_eq!(
                classify_draft(&risk_input).risk,
                ReplyRisk::High(HighRiskReason::ObjectionClassNotLowRisk),
                "objection {objection} must be HIGH"
            );
        }
        // `timing`/`need` do not disqualify by themselves.
        let suggestion = serde_json::json!({ "objection_class": "timing" });
        let mut risk_input = input("Thanks for the note.", "question");
        risk_input.suggestion = Some(&suggestion);
        assert!(classify_draft(&risk_input).risk.is_low());
    }

    #[test]
    fn classification_is_deterministic() {
        let risk_input = input("Thursday 10:00 works for us.", "meeting_request");
        let first = classify_draft(&risk_input);
        for _ in 0..8 {
            assert_eq!(classify_draft(&risk_input), first);
        }
    }

    #[test]
    fn the_confidence_gate_matches_the_worker_constant() {
        // The worker's own gate is 0.7 (reply_handler/policy.rs
        // MIN_AUTO_ACTION_CONFIDENCE). This crate cannot depend on
        // worker-processors, so the value is mirrored and pinned here; a
        // change there must change this constant in the same wave.
        assert_eq!(MIN_REPLY_CONFIDENCE, 0.7);
        let mut risk_input = input("Thanks — noted.", "ooo");
        risk_input.intent_confidence = Some(MIN_REPLY_CONFIDENCE);
        assert!(classify_draft(&risk_input).risk.is_low());
        risk_input.intent_confidence = Some(MIN_REPLY_CONFIDENCE - f64::EPSILON);
        assert_eq!(
            classify_draft(&risk_input).risk,
            ReplyRisk::High(HighRiskReason::LowConfidence)
        );
    }

    #[test]
    fn class_strings_round_trip_and_high_is_never_a_class() {
        for class in LowRiskClass::ALL {
            assert_eq!(LowRiskClass::parse(class.as_str()), Some(class));
            assert_eq!(ReplyRisk::Low(class).as_str(), class.as_str());
        }
        assert_eq!(LowRiskClass::parse("autonomous_full"), None);
        assert_eq!(LowRiskClass::parse(""), None);
        assert_eq!(
            ReplyRisk::High(HighRiskReason::UnbackedClaim).as_str(),
            "high:unbacked_claim"
        );
        // A HIGH verdict can never be parsed back into a promotable class.
        assert_eq!(
            LowRiskClass::parse(&ReplyRisk::High(HighRiskReason::LowConfidence).as_str()),
            None
        );
    }

    // ── The evidence SQL is pinned ───────────────────────────────────

    #[test]
    fn evidence_is_derived_from_recorded_approvals_never_a_counter() {
        // The approval evidence query must read the audit record of real
        // approvals, keyed by class and routed tenant, inside the window.
        for fragment in [
            "FROM audit_logs",
            "action = 'control_plane.ai_draft.approved'",
            "details->>'routedTenantId' = $1",
            "details->>'replyClass' = $2",
            "created_at >= NOW() - make_interval(days => $3::int)",
            "COUNT(DISTINCT resource_id)",
        ] {
            assert!(
                APPROVED_CLASS_COUNT_SQL.contains(fragment),
                "approval evidence SQL must contain `{fragment}`: {APPROVED_CLASS_COUNT_SQL}"
            );
        }
        // Complaints/opt-outs come from the canonical classification rows.
        for fragment in [
            "FROM sales_reply_classifications",
            "disposition IN ('complaint', 'unsubscribe')",
            "created_at >= NOW() - make_interval(days => $2::int)",
        ] {
            assert!(
                COMPLAINT_OR_OPTOUT_COUNT_SQL.contains(fragment),
                "complaint evidence SQL must contain `{fragment}`"
            );
        }
        // The grant table itself must carry no counter the evidence query
        // could read instead (the snapshot is a record, not the authority).
        for forbidden in ["approved_count", "counter", "seed_evidence"] {
            assert!(
                !APPROVED_CLASS_COUNT_SQL.contains(forbidden)
                    && !SELECT_GRANT_SQL.contains(forbidden)
                    && !COMPLAINT_OR_OPTOUT_COUNT_SQL.contains(forbidden),
                "no forgeable counter may exist in the gate SQL: {forbidden}"
            );
        }
    }
}
