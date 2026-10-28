//! Inbound purpose, risk and delivery-class taxonomy with the deterministic
//! policy table that maps them (fourth external audit, Tier-1 item 6, and the
//! P0 release-semantics finding).
//!
//! # Why this module exists
//!
//! The fourth external audit found the top Mailbot product defect: the
//! draft-approval/release path treated "an approved AI reply" as a
//! MARKETING-class send and enforced the MARKETING consent gate before
//! releasing it. That is wrong semantics: a reply to an inbound customer
//! message (a support question, a billing issue, a security report, a
//! cancellation, a DPA inquiry) is SERVICE correspondence within an existing
//! conversation. The recipient emailed first; marketing consent is not the
//! gate that applies. Suppression, bounce/complaint suppression, the kill
//! switch, autonomy mode/policy packs, the human-approval requirement and the
//! frequency/promotion evidence gates all still apply exactly as before.
//!
//! This module is the vocabulary and the POLICY that make the send class a
//! typed, deterministic decision instead of a column default:
//!
//! * [`InboundPurpose`], WHY the sender wrote (17 values, the audit's
//!   vocabulary);
//! * [`RiskLevel`], how sensitive the conversation is;
//! * [`DeliveryClass`], which send-admission regime applies (service,
//!   transactional, marketing, or none: do not respond);
//! * [`policy_for`], the DETERMINISTIC purpose -> (delivery class, autonomy
//!   requirement) table, per the audit's policy table;
//! * [`reply_class_for_ai_draft`], the explicit release class of an approved
//!   AI reply: SERVICE, never the queue schema default;
//! * [`classify_all`], the multi-label classifier over the inbound subject +
//!   body + stored headers. Every matched purpose contributes its policy row;
//!   the effective risk is the MAXIMUM over the matched rows and the
//!   effective autonomy requirement is the STRICTEST. Adding a label can only
//!   escalate the decision, never relax it. [`classify`] is a thin
//!   single-label wrapper for callers that only need the primary purpose.
//!   The deterministic layer is the policy AUTHORITY: a future model may
//!   refine the purpose labels WITHIN these policy bounds (it may never widen
//!   a class beyond what the table grants).
//!
//! # Multi-label reduction (fifth external audit)
//!
//! The first classifier was single-label, first-match-wins. Real mail
//! compounds intents ("billing + cancellation + complaint", "security + legal
//! + refund"), and a first-match rule can hide the heavier intent behind the
//! lighter one. [`classify_all`] therefore returns ALL matched purposes in
//! priority order, with `primary` (the first/strongest hit) kept for the
//! audit record and the effective `risk`/`autonomy` reduced over the full
//! set. The reduction is monotone by construction: [`RiskLevel::max`] and
//! [`AutonomyRequirement::strictest`] only ever move upward, so adding a
//! label cannot lower the risk or relax the autonomy requirement. A
//! no-reply purpose anywhere in the set (automated or spam) makes the whole
//! decision no-reply.
//!
//! # Automated detection requires machine evidence (fifth external audit)
//!
//! Autoresponders and DSNs are identified primarily by MACHINE-MAIL
//! EVIDENCE in the stored headers: `Auto-Submitted` (RFC 3834),
//! `Precedence: bulk|junk|list`, `X-Autoreply`/`X-Autorespond`/
//! `X-Autoresponder`/`Auto-Reply`, a null (`<>`) `Return-Path`, and the
//! DSN `Content-Type: multipart/report; report-type=delivery-status`.
//! Prose alone is NOT evidence: a customer writing "we have a delivery
//! failure and the address was not found, can you help?" is a deliverability
//! conversation, not machine mail. Body phrases that used to trigger
//! `automated` are now deliverability vocabulary. The only text-only
//! evidence kept is the small subject-line template set
//! (`rules::AUTOMATED_SUBJECT_PREFIXES`); the module documents there why an
//! exact machine prefix on the SUBJECT line is structural rather than free
//! prose.
//!
//! # Relationship to the 11-value sales disposition taxonomy
//!
//! The reply worker persists `inbound_messages.classification` from the
//! canonical 11-value disposition vocabulary
//! (`sales_reply_classifications`, migration 200, mirrored by
//! [`crate::reply_autosend::CANONICAL_DISPOSITIONS`]). That vocabulary stays
//! EXACTLY as it is: it answers "what should the reply DO" (meeting_request,
//! unsubscribe, complaint, ...) and drives sales analytics and the reply
//! auto-send promotion classes. This module's purpose taxonomy is
//! ORTHOGONAL: it answers "why did the sender write", and it governs the
//! delivery class and the autonomy requirement of the release. The release
//! decision reads BOTH: the disposition drives the promotion classifier
//! ([`crate::reply_autosend::classify_draft`], unchanged), the purpose
//! drives the delivery class and the autonomous-release veto
//! ([`reply_release_decision`]). Neither vocabulary replaces the other, and
//! no parallel copy of the 11-value list exists here.
//!
//! # The policy table (as code)
//!
//! | Purpose | Delivery class | Autonomy requirement | Default risk |
//! |---|---|---|---|
//! | technical_support | service | promotion gate (autosend capable) | low |
//! | deliverability | service | promotion gate (autosend capable) | low |
//! | dns_auth | service | promotion gate (autosend capable) | low |
//! | sales | service | promotion gate (see note) | low |
//! | other | service | human review | medium |
//! | billing | service | human review | medium |
//! | invoice | service | human review | medium |
//! | privacy | service | human review (mandatory) | medium |
//! | refund | service | human review (dispute) | high |
//! | cancellation | service | human review (dispute) | high |
//! | account_security | service | human review (security sensitivity) | high |
//! | legal | service | human review (mandatory) | high |
//! | procurement | service | human review | medium |
//! | partnership | service | human review | low |
//! | abuse | service | no autonomous response | high |
//! | automated | none | no autonomous response | low |
//! | spam | none | no autonomous response | low |
//!
//! Notes the audit table carries in prose, made explicit here:
//!
//! * "DNS/API support -> service, potentially autosend": the promotion gate
//!   ([`crate::reply_autosend`]) remains the ONLY autonomy path; the purpose
//!   layer can only ever TIGHTEN it ([`reply_release_decision`]).
//! * "Sales -> policy-dependent": outbound prospecting is the sequence
//!   dispatcher's regime (marketing category, its own consent path) and is
//!   NOT this taxonomy's concern. An inbound sales inquiry answered within an
//!   existing conversation is service correspondence like every other reply.
//! * "GDPR/privacy + legal notice -> service/legal, mandatory review": the
//!   [`DeliveryClass`] vocabulary has no separate legal class (the audit's
//!   enum is service/transactional/marketing/none), so these collapse to
//!   service with a mandatory human review.
//! * "OOO/bounce -> none": an autoresponder or a delivery status notification
//!   has no human reader; the reply decision for it is NO REPLY
//!   ([`DeliveryClass::None`]).
//! * "Other" is the classifier's uncertainty state, not a judgement that the
//!   message is harmless. The audit's original table let `other` ride the
//!   promotion gate at low risk, which made an unproven classifier's silence
//!   an autonomy grant. Fifth external audit reversed that: `other` is
//!   service/medium/HUMAN REVIEW. Uncertainty must never keep autonomy; the
//!   promotion gate can only be reached when the classifier positively
//!   places the message in a known, autosend-capable purpose.

use serde::{Deserialize, Serialize};

use apexmail_lib::email_headers::message_category;

// ---------------------------------------------------------------------------
// The vocabulary
// ---------------------------------------------------------------------------

/// WHY the sender wrote. The audit's inbound purpose vocabulary. The persisted
/// string rides the audit record (`details.inboundPurpose`); unknown text
/// classifies as [`InboundPurpose::Other`], never fails.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InboundPurpose {
    /// Product/API usage help ("the API key returns 401").
    TechnicalSupport,
    /// Delivery problems of the customer's own mail ("campaigns land in spam").
    Deliverability,
    /// DNS/authentication setup ("SPF fails alignment", DKIM, DMARC, MX).
    DnsAuth,
    /// Account billing questions ("update my card", "payment failed").
    Billing,
    /// Invoice copies, VAT/tax details, charge questions.
    Invoice,
    /// Money-back demands and charge disputes.
    Refund,
    /// Account/subscription cancellation and non-renewal notices.
    Cancellation,
    /// Login/security incidents and phishing reports ("hacked", "suspicious
    /// login", "verify your account" lures).
    AccountSecurity,
    /// GDPR/DPA/DSAR and other data-protection requests.
    Privacy,
    /// Legal notices, lawyer involvement, contract disputes.
    Legal,
    /// Unsubscribe demands, abuse reports, hostile escalations.
    Abuse,
    /// Vendor onboarding, security questionnaires, purchase orders, RFPs.
    Procurement,
    /// Commercial interest in the product ("pricing", "demo", "trial").
    Sales,
    /// Partner/reseller/affiliate collaboration proposals.
    Partnership,
    /// Machine-generated mail: out-of-office autoresponders and delivery
    /// status notifications. There is no human reader; the reply decision is
    /// NO REPLY.
    Automated,
    /// Unsolicited bulk mail. No reply.
    Spam,
    /// Anything the first-pass classifier cannot place.
    Other,
}

impl InboundPurpose {
    pub const ALL: [InboundPurpose; 17] = [
        Self::TechnicalSupport,
        Self::Deliverability,
        Self::DnsAuth,
        Self::Billing,
        Self::Invoice,
        Self::Refund,
        Self::Cancellation,
        Self::AccountSecurity,
        Self::Privacy,
        Self::Legal,
        Self::Abuse,
        Self::Procurement,
        Self::Sales,
        Self::Partnership,
        Self::Automated,
        Self::Spam,
        Self::Other,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::TechnicalSupport => "technical_support",
            Self::Deliverability => "deliverability",
            Self::DnsAuth => "dns_auth",
            Self::Billing => "billing",
            Self::Invoice => "invoice",
            Self::Refund => "refund",
            Self::Cancellation => "cancellation",
            Self::AccountSecurity => "account_security",
            Self::Privacy => "privacy",
            Self::Legal => "legal",
            Self::Abuse => "abuse",
            Self::Procurement => "procurement",
            Self::Sales => "sales",
            Self::Partnership => "partnership",
            Self::Automated => "automated",
            Self::Spam => "spam",
            Self::Other => "other",
        }
    }

    /// Parse the persisted string. Unknown values are `None`; a caller must
    /// never guess a purpose it did not classify.
    pub fn parse(value: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|purpose| purpose.as_str() == value.trim())
    }
}

impl std::fmt::Display for InboundPurpose {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// How sensitive the conversation is. The purpose policy carries the default;
/// HIGH always means "no autonomous release".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskLevel {
    Low,
    Medium,
    High,
}

impl RiskLevel {
    pub const ALL: [RiskLevel; 3] = [Self::Low, Self::Medium, Self::High];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
        }
    }

    /// Ordering rank: LOW < MEDIUM < HIGH. Used by the multi-label reduction,
    /// which takes the MAXIMUM over the matched purposes.
    fn severity(self) -> u8 {
        match self {
            Self::Low => 0,
            Self::Medium => 1,
            Self::High => 2,
        }
    }

    /// The higher of two risks. Monotone: `a.max(b)` is never below `a`.
    #[must_use]
    pub fn max(self, other: Self) -> Self {
        if other.severity() > self.severity() {
            other
        } else {
            self
        }
    }
}

impl std::fmt::Display for RiskLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Which send-admission regime applies to a message.
///
/// Service and transactional are preference-exempt correspondence
/// (`message_category::PREFERENCE_EXEMPT`): the MARKETING consent requirement
/// does not gate them. Suppression (tenant list and platform bounce/complaint
/// stores) applies to EVERY class without exception. Marketing is the bulk
/// commercial class whose recipients each need an active consent record.
/// [`DeliveryClass::None`] means no message is sent at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeliveryClass {
    /// Correspondence within an existing conversation (a reply to an inbound
    /// message) and platform notices.
    Service,
    /// Operational mail the recipient triggered (receipts, password resets).
    Transactional,
    /// Bulk commercial mail, marketing-consent gated.
    Marketing,
    /// No message is sent (autoresponders, delivery status notifications,
    /// spam).
    None,
}

impl DeliveryClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Service => "service",
            Self::Transactional => "transactional",
            Self::Marketing => "marketing",
            Self::None => "none",
        }
    }

    /// The `messages.message_category` / `email_queue.message_category` value
    /// this class writes, EXPLICITLY (never the schema default). `None` for
    /// [`DeliveryClass::None`]: there is no queue row to write.
    pub fn message_category(self) -> Option<&'static str> {
        match self {
            Self::Service => Some(message_category::SERVICE),
            Self::Transactional => Some(message_category::TRANSACTIONAL),
            Self::Marketing => Some(message_category::MARKETING),
            Self::None => None,
        }
    }

    /// True only for the classes the MARKETING consent gate governs. Service
    /// and transactional correspondence is preference-exempt; suppression
    /// still applies to every class.
    pub fn requires_marketing_consent(self) -> bool {
        self == Self::Marketing
    }
}

impl std::fmt::Display for DeliveryClass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The autonomy requirement the audit's policy table assigns a purpose.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AutonomyRequirement {
    /// The purpose layer adds no constraint of its own: the reply auto-send
    /// promotion gate ([`crate::reply_autosend`]) decides as before. The gate
    /// is never loosened by this layer, only reinforced.
    PromotionGate,
    /// A human must review; the autonomous sweep never releases, whatever the
    /// promotion gate's evidence says.
    HumanReview,
    /// No autonomous response; only a human decision can release.
    NoAutonomousResponse,
}

impl AutonomyRequirement {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PromotionGate => "promotion_gate",
            Self::HumanReview => "human_review",
            Self::NoAutonomousResponse => "no_autonomous_response",
        }
    }

    /// Ordering rank: promotion gate < human review < no autonomous
    /// response. Used by the multi-label reduction, which takes the
    /// STRICTEST over the matched purposes.
    fn strictness(self) -> u8 {
        match self {
            Self::PromotionGate => 0,
            Self::HumanReview => 1,
            Self::NoAutonomousResponse => 2,
        }
    }

    /// The stricter of two requirements. Monotone: `a.strictest(b)` is never
    /// looser than `a`.
    #[must_use]
    pub fn strictest(self, other: Self) -> Self {
        if other.strictness() > self.strictness() {
            other
        } else {
            self
        }
    }
}

impl std::fmt::Display for AutonomyRequirement {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One purpose's row in the deterministic policy table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PurposePolicy {
    /// The delivery class replies to this purpose are sent under.
    pub delivery_class: DeliveryClass,
    /// The autonomy requirement beyond the existing promotion gate.
    pub autonomy: AutonomyRequirement,
    /// The classification risk this purpose implies.
    pub default_risk: RiskLevel,
}

/// The POLICY TABLE, one row per purpose, total over [`InboundPurpose::ALL`].
/// Deterministic and deliberate: this function is the authority a future
/// model refines WITHIN, never around.
pub fn policy_for(purpose: InboundPurpose) -> PurposePolicy {
    use AutonomyRequirement::{HumanReview, NoAutonomousResponse, PromotionGate};
    use DeliveryClass::{None, Service};
    use RiskLevel::{High, Low, Medium};
    match purpose {
        InboundPurpose::TechnicalSupport => PurposePolicy {
            delivery_class: Service,
            autonomy: PromotionGate,
            default_risk: Low,
        },
        InboundPurpose::Deliverability => PurposePolicy {
            delivery_class: Service,
            autonomy: PromotionGate,
            default_risk: Low,
        },
        InboundPurpose::DnsAuth => PurposePolicy {
            delivery_class: Service,
            autonomy: PromotionGate,
            default_risk: Low,
        },
        InboundPurpose::Sales => PurposePolicy {
            delivery_class: Service,
            autonomy: PromotionGate,
            default_risk: Low,
        },
        InboundPurpose::Other => PurposePolicy {
            delivery_class: Service,
            autonomy: HumanReview,
            default_risk: Medium,
        },
        InboundPurpose::Billing => PurposePolicy {
            delivery_class: Service,
            autonomy: HumanReview,
            default_risk: Medium,
        },
        InboundPurpose::Invoice => PurposePolicy {
            delivery_class: Service,
            autonomy: HumanReview,
            default_risk: Medium,
        },
        InboundPurpose::Privacy => PurposePolicy {
            delivery_class: Service,
            autonomy: HumanReview,
            default_risk: Medium,
        },
        InboundPurpose::Refund => PurposePolicy {
            delivery_class: Service,
            autonomy: HumanReview,
            default_risk: High,
        },
        InboundPurpose::Cancellation => PurposePolicy {
            delivery_class: Service,
            autonomy: HumanReview,
            default_risk: High,
        },
        InboundPurpose::AccountSecurity => PurposePolicy {
            delivery_class: Service,
            autonomy: HumanReview,
            default_risk: High,
        },
        InboundPurpose::Legal => PurposePolicy {
            delivery_class: Service,
            autonomy: HumanReview,
            default_risk: High,
        },
        InboundPurpose::Procurement => PurposePolicy {
            delivery_class: Service,
            autonomy: HumanReview,
            default_risk: Medium,
        },
        InboundPurpose::Partnership => PurposePolicy {
            delivery_class: Service,
            autonomy: HumanReview,
            default_risk: Low,
        },
        InboundPurpose::Abuse => PurposePolicy {
            delivery_class: Service,
            autonomy: NoAutonomousResponse,
            default_risk: High,
        },
        InboundPurpose::Automated => PurposePolicy {
            delivery_class: None,
            autonomy: NoAutonomousResponse,
            default_risk: Low,
        },
        InboundPurpose::Spam => PurposePolicy {
            delivery_class: None,
            autonomy: NoAutonomousResponse,
            default_risk: Low,
        },
    }
}

// ---------------------------------------------------------------------------
// The release class of an approved AI reply (the P0 fix)
// ---------------------------------------------------------------------------

/// The delivery class of an APPROVED AI REPLY draft.
///
/// Fourth external audit, P0: a reply to an inbound customer message is
/// SERVICE correspondence within an existing conversation (the recipient
/// emailed first). The release path used to classify it MARKETING (in fact it
/// inherited the `email_queue.message_category` schema default) and enforced
/// the marketing consent gate, refusing to deliver answers to support,
/// billing, security or privacy questions from recipients who never opted in
/// to marketing. The class is therefore EXPLICIT here and typed: the release
/// points call this function instead of deriving a category from a schema
/// default. Suppression (tenant and platform bounce/complaint stores) still
/// applies, as does every other safety gate (approval requirement, kill
/// switch, autonomy mode, policy packs, promotion evidence).
pub fn reply_class_for_ai_draft() -> DeliveryClass {
    DeliveryClass::Service
}

// ---------------------------------------------------------------------------
// The deterministic first-pass classifier
// ---------------------------------------------------------------------------

/// The multi-label classification verdict (fifth external audit).
///
/// `purposes` is every matched purpose in priority order, deduplicated;
/// `primary` is the first/strongest hit (what the audit record's
/// `inboundPurpose` carries); `risk` and `autonomy` are the EFFECTIVE values
/// reduced over every matched purpose's [`policy_for`] row (MAX risk,
/// STRICTEST autonomy). The reduction is monotone: adding a purpose can only
/// escalate these fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Classification {
    /// Every matched purpose, in priority order, no duplicates.
    pub purposes: Vec<InboundPurpose>,
    /// Effective risk: the maximum over the matched purposes' policy risk.
    pub risk: RiskLevel,
    /// Effective autonomy: the strictest over the matched purposes.
    pub autonomy: AutonomyRequirement,
    /// The first/strongest matched purpose (the audit record's label).
    pub primary: InboundPurpose,
}

impl Classification {
    /// Reduce a non-empty purpose set through the policy table. The
    /// constructor keeps the monotonicity invariant in ONE place: risk is
    /// the max, autonomy the strictest, and an empty set is the classifier's
    /// uncertainty state ([`InboundPurpose::Other`], never "no constraint").
    fn from_purposes(purposes: Vec<InboundPurpose>) -> Self {
        let purposes = if purposes.is_empty() {
            vec![InboundPurpose::Other]
        } else {
            purposes
        };
        let primary = purposes[0];
        let mut risk = RiskLevel::Low;
        let mut autonomy = AutonomyRequirement::PromotionGate;
        for purpose in &purposes {
            let policy = policy_for(*purpose);
            risk = risk.max(policy.default_risk);
            autonomy = autonomy.strictest(policy.autonomy);
        }
        Self {
            purposes,
            risk,
            autonomy,
            primary,
        }
    }
}

/// Keyword/phrase rules, checked in a documented priority order. EVERY
/// matching rule contributes a label (multi-label, fifth external audit);
/// the order only decides which hit is `primary`, never whether a later hit
/// is dropped. Order IS policy: an autoresponder mentioning "support" still
/// has `automated` as its primary label, and a legal threat wrapped in an
/// unsubscribe demand carries BOTH labels, so the reduction takes the safer
/// risk/autonomy either way.
///
/// Substring match over the lowercased subject + body. Deliberately
/// over-inclusive toward review: a false positive sends the draft to a human,
/// which is the safe direction, and never changes the delivery class away
/// from service for a reply.
///
/// The deterministic layer is the policy AUTHORITY (see the module doc): a
/// future model may refine the purpose labels within [`policy_for`]'s bounds.
mod rules {
    /// Subject-line templates that identify a machine-generated autoresponder
    /// WITHOUT any header evidence. These are matched against the SUBJECT
    /// line only, as an exact prefix (case-insensitive), never as a body
    /// substring. Why this is structural enough: the dominant autoresponder
    /// implementations emit these prefixes verbatim at the start of the
    /// subject ("Automatic reply:" from Exchange/Outlook, "Auto-Reply:" and
    /// "Out of Office:" from other gateways); a human writing to support
    /// would have to impersonate the exact machine shape. The failure mode is
    /// also bounded: `automated` means "the AI does not reply", the message
    /// still reaches a human, so the worst case is a human answering a
    /// customer, never a customer being answered by a machine.
    pub const AUTOMATED_SUBJECT_PREFIXES: [&str; 7] = [
        "automatic reply:",
        "auto-reply:",
        "auto reply:",
        "autoreply:",
        "automated response:",
        "out of office:",
        "out-of-office:",
    ];

    /// Unsolicited bulk mail. No reply.
    pub const SPAM: [&str; 12] = [
        "viagra",
        "casino",
        "lottery",
        "you have won",
        "claim your prize",
        "crypto giveaway",
        "forex signals",
        "make money fast",
        "seo services",
        "backlinks",
        "cheap followers",
        "this is not spam",
    ];

    /// Unsubscribe demands and abuse reports. The worker's suppression path
    /// (recording the disposition, adding the address to the suppression
    /// stores) is upstream of this taxonomy and UNCHANGED; the policy effect
    /// here is that the autonomous sweep never answers these.
    pub const ABUSE: [&str; 15] = [
        "unsubscribe",
        "opt out",
        "opt-out",
        "remove me",
        "take me off",
        "remove my email",
        "remove my address",
        "stop sending",
        "stop emailing",
        "do not email",
        "do not contact",
        "never contact",
        "cease all communication",
        "report you as spam",
        "reporting this as abuse",
    ];

    /// Legal notices and lawyer involvement. Mandatory review.
    pub const LEGAL: [&str; 12] = [
        "lawsuit",
        "legal action",
        "attorney",
        "lawyer",
        "small claims",
        "court order",
        "subpoena",
        "legal notice",
        "cease and desist",
        "litigation",
        "breach of contract",
        "without prejudice",
    ];

    /// Money-back demands and charge disputes.
    pub const REFUND: [&str; 6] = [
        "refund",
        "money back",
        "chargeback",
        "charge back",
        "dispute the charge",
        "reverse the charge",
    ];

    /// Cancellation and non-renewal notices.
    pub const CANCELLATION: [&str; 12] = [
        "cancel my account",
        "cancel our account",
        "cancel my subscription",
        "cancel our subscription",
        "cancel my plan",
        "terminate my account",
        "terminate our account",
        "close my account",
        "close our account",
        "delete my account",
        "not renewing",
        "do not want to renew",
    ];

    /// Phishing lures and security incidents. Security sensitivity.
    pub const ACCOUNT_SECURITY: [&str; 24] = [
        "verify your account",
        "confirm your identity",
        "verify your identity",
        "account has been suspended",
        "account will be suspended",
        "unusual sign-in",
        "unusual login",
        "suspicious login",
        "login attempt from",
        "sign-in attempt from",
        "we detected a new login",
        "hacked",
        "compromised",
        "phishing",
        "someone accessed",
        "unauthorized access",
        "unauthorised access",
        "security incident",
        "data breach",
        "locked out",
        "cannot log in",
        "can't log in",
        "cannot sign in",
        "can't sign in",
    ];

    /// Vendor onboarding and procurement paperwork.
    pub const PROCUREMENT: [&str; 12] = [
        "procurement",
        "purchase order",
        "po number",
        "vendor onboarding",
        "vendor form",
        "vendor profile",
        "supplier form",
        "security questionnaire",
        "w-9",
        "w9 form",
        "request for proposal",
        "rfp",
    ];

    /// GDPR/DPA/data-protection requests. Mandatory review.
    pub const PRIVACY: [&str; 14] = [
        "gdpr",
        "dpa",
        "data processing agreement",
        "data processing addendum",
        "personal data",
        "right to erasure",
        "right to be forgotten",
        "right to access",
        "data subject",
        "dsar",
        "ccpa",
        "data protection officer",
        "delete my data",
        "erase my data",
    ];

    /// DNS and email-authentication setup.
    pub const DNS_AUTH: [&str; 14] = [
        "spf",
        "dkim",
        "dmarc",
        "mx record",
        "mx records",
        "dns record",
        "dns records",
        "txt record",
        "cname",
        "nameserver",
        "dns setup",
        "dns configuration",
        "domain verification",
        "verify my domain",
    ];

    /// Delivery problems of the customer's own mail. Includes the DSN /
    /// bounce vocabulary that the first classifier treated as automated-mail
    /// evidence: without machine-mail headers those words are a customer
    /// describing a delivery problem (fifth external audit), so they now
    /// classify as deliverability, never `automated`.
    pub const DELIVERABILITY: [&str; 23] = [
        "spam folder",
        "junk folder",
        "promotions tab",
        "inbox placement",
        "deliverability",
        "landing in spam",
        "goes to spam",
        "going to spam",
        "marked as spam",
        "bounce rate",
        "bounces",
        "bounced",
        "blacklist",
        "undeliverable",
        "delivery status notification",
        "delivery failure",
        "delivery has failed",
        "delivery failed",
        "returned mail",
        "mailer-daemon",
        "mail delivery subsystem",
        "could not be delivered",
        "address not found",
    ];

    /// Invoice copies, VAT/tax details, charge questions.
    pub const INVOICE: [&str; 7] = [
        "invoice",
        "receipt",
        "charged twice",
        "double charged",
        "billed twice",
        "vat number",
        "vat id",
    ];

    /// Account billing questions.
    pub const BILLING: [&str; 10] = [
        "billing",
        "payment failed",
        "payment method",
        "update my card",
        "update our card",
        "credit card",
        "declined",
        "overcharged",
        "subscription",
        "plan renewal",
    ];

    /// Partner/reseller proposals.
    pub const PARTNERSHIP: [&str; 10] = [
        "partnership",
        "partner program",
        "become a partner",
        "reseller",
        "affiliate",
        "co-marketing",
        "joint webinar",
        "sponsorship",
        "collaborate",
        "cross-promotion",
    ];

    /// Commercial interest in the product.
    pub const SALES: [&str; 15] = [
        "demo",
        "pricing",
        "quote",
        "how much",
        "cost",
        "free trial",
        "trial account",
        "sign up",
        "get started",
        "purchase",
        "ready to buy",
        "upgrade my plan",
        "upgrade our plan",
        "enterprise plan",
        "discount",
    ];

    /// Product/API usage help. Checked late on purpose: anything here that
    /// slipped past the more specific rules is still support; unmatched text
    /// falls back to [`super::InboundPurpose::Other`], which requires human
    /// review (uncertainty never keeps autonomy).
    pub const TECHNICAL_SUPPORT: [&str; 16] = [
        "api key",
        "apikey",
        "api token",
        "not working",
        "doesn't work",
        "does not work",
        "stopped working",
        "error",
        "bug",
        "broken",
        "webhook",
        "integration",
        "timeout",
        "timed out",
        "how do i",
        "how can i",
    ];
}

/// The rule order for the text rules. EVERY match contributes a label; the
/// order only determines which hit is `primary` (see the `rules` module doc
/// and the module doc's priority discussion). `automated` is not a text rule:
/// it is decided by machine-mail evidence (see [`classify_all`]).
const RULE_ORDER: [(InboundPurpose, &[&str]); 15] = [
    (InboundPurpose::Spam, &rules::SPAM),
    (InboundPurpose::Abuse, &rules::ABUSE),
    (InboundPurpose::Legal, &rules::LEGAL),
    (InboundPurpose::Refund, &rules::REFUND),
    (InboundPurpose::Cancellation, &rules::CANCELLATION),
    (InboundPurpose::AccountSecurity, &rules::ACCOUNT_SECURITY),
    (InboundPurpose::Procurement, &rules::PROCUREMENT),
    (InboundPurpose::Privacy, &rules::PRIVACY),
    (InboundPurpose::DnsAuth, &rules::DNS_AUTH),
    (InboundPurpose::Deliverability, &rules::DELIVERABILITY),
    (InboundPurpose::Invoice, &rules::INVOICE),
    (InboundPurpose::Billing, &rules::BILLING),
    (InboundPurpose::Partnership, &rules::PARTNERSHIP),
    (InboundPurpose::Sales, &rules::SALES),
    (InboundPurpose::TechnicalSupport, &rules::TECHNICAL_SUPPORT),
];

/// Read one stored header case-insensitively (the MTA mirror writes lowercase
/// names into the JSONB object, but fixtures and other writers may not).
/// Repeated headers were joined with ", " by the mirror; an array value is
/// joined the same way for robustness. Non-string scalars are ignored.
fn header_value(headers: Option<&serde_json::Value>, name: &str) -> Option<String> {
    let object = headers?.as_object()?;
    let (_, value) = object
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case(name))?;
    match value {
        serde_json::Value::String(text) => Some(text.clone()),
        serde_json::Value::Array(items) => {
            let joined = items
                .iter()
                .filter_map(serde_json::Value::as_str)
                .collect::<Vec<_>>()
                .join(", ");
            (!joined.is_empty()).then_some(joined)
        }
        _ => None,
    }
}

/// A DSN content type: `multipart/report` whose `report-type` parameter is
/// `delivery-status` (RFC 3462/3464). Parameters may be quoted.
fn is_dsn_content_type(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    let mut parts = lower.split(';');
    if parts.next().unwrap_or("").trim() != "multipart/report" {
        return false;
    }
    parts.any(|parameter| {
        parameter
            .trim()
            .strip_prefix("report-type=")
            .map(|value| value.trim().trim_matches('"') == "delivery-status")
            .unwrap_or(false)
    })
}

/// The null sender a DSN carries (`Return-Path: <>`). The mirror excludes
/// Return-Path today, so this only fires if a writer stores it; it is
/// defensive, never required.
fn is_null_sender(value: &str) -> bool {
    let trimmed = value.trim();
    trimmed.is_empty() || trimmed == "<>"
}

/// Deterministic machine-mail evidence from the stored headers. This is the
/// PRIMARY automated-mail signal (fifth external audit): prose alone is never
/// enough. Returns the evidence kind for documentation/debugging.
fn machine_mail_evidence(headers: Option<&serde_json::Value>) -> Option<&'static str> {
    if let Some(value) = header_value(headers, "auto-submitted") {
        // RFC 3834: the parameter list may follow the keyword
        // (`auto-replied; owner-email=...`); `no` is a human message.
        let token = value
            .split(';')
            .next()
            .unwrap_or("")
            .trim()
            .to_ascii_lowercase();
        if matches!(
            token.as_str(),
            "auto-generated" | "auto-replied" | "auto-notified"
        ) {
            return Some("auto_submitted");
        }
    }
    if let Some(value) = header_value(headers, "precedence") {
        let token = value
            .split([',', ';'])
            .next()
            .unwrap_or("")
            .trim()
            .to_ascii_lowercase();
        if matches!(token.as_str(), "bulk" | "junk" | "list") {
            return Some("precedence");
        }
    }
    for name in [
        "x-autoreply",
        "x-autorespond",
        "x-autoresponder",
        "auto-reply",
    ] {
        if header_value(headers, name).is_some_and(|value| !value.trim().is_empty()) {
            return Some("autoreply_header");
        }
    }
    if header_value(headers, "return-path").is_some_and(|value| is_null_sender(&value)) {
        return Some("null_return_path");
    }
    if header_value(headers, "content-type").is_some_and(|value| is_dsn_content_type(&value)) {
        return Some("dsn_content_type");
    }
    None
}

/// An exact, documented machine template at the START of the subject line.
/// See [`rules::AUTOMATED_SUBJECT_PREFIXES`] for why this text is structural.
fn has_automated_subject_prefix(lower_subject: &str) -> bool {
    let subject = lower_subject.trim_start();
    rules::AUTOMATED_SUBJECT_PREFIXES
        .iter()
        .any(|prefix| subject.starts_with(prefix))
}

/// The multi-label classifier over the inbound subject, body, and stored
/// headers. Same input in, same [`Classification`] out; no I/O, no model.
///
/// `automated` is added only on machine-mail evidence (a header signal or the
/// subject-line template set), never on body prose. Every text rule that
/// matches contributes its purpose, so compound intents ("billing +
/// cancellation") keep both labels and the effective risk/autonomy escalate
/// to the strictest of them. Unmatched text classifies as
/// [`InboundPurpose::Other`] (service/medium/HUMAN REVIEW: uncertainty never
/// keeps autonomy).
///
/// `headers` is the stored `inbound_messages.headers` JSONB object: header
/// name -> value, as the MTA mirror writes it. `None` (no stored headers) is
/// exactly the no-header path.
pub fn classify_all(
    subject: &str,
    body: &str,
    headers: Option<&serde_json::Value>,
) -> Classification {
    let lower_subject = subject.trim().to_lowercase();
    let lower_body = body.trim().to_lowercase();
    let combined = format!("{lower_subject}\n{lower_body}");

    let mut purposes = Vec::new();
    if machine_mail_evidence(headers).is_some() || has_automated_subject_prefix(&lower_subject) {
        purposes.push(InboundPurpose::Automated);
    }
    for (purpose, markers) in RULE_ORDER {
        if markers.iter().any(|marker| combined.contains(marker)) && !purposes.contains(&purpose) {
            purposes.push(purpose);
        }
    }
    Classification::from_purposes(purposes)
}

/// Thin single-label wrapper for callers that only need the primary purpose
/// and the effective risk. It is exactly [`classify_all`] with no stored
/// headers; release decisions must consume [`classify_all`] directly so the
/// full label set and its stricter reduction are never dropped.
pub fn classify(subject: &str, body: &str) -> (InboundPurpose, RiskLevel) {
    let classification = classify_all(subject, body, None);
    (classification.primary, classification.risk)
}

// ---------------------------------------------------------------------------
// The release decision: Classification -> DeliveryClass + autonomy
// ---------------------------------------------------------------------------

/// The reply-handling decision the release points consume, derived from a
/// multi-label [`Classification`] through the policy table. This is what
/// replaced the everything-is-marketing default: the delivery class is a
/// typed table lookup, and the autonomous sweep can only ever be TIGHTENED
/// by it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReplyReleaseDecision {
    /// The send class of the approved AI reply. Always
    /// [`reply_class_for_ai_draft`] (service): the reply is correspondence
    /// within an existing conversation whatever its topic. The purpose layer
    /// governs WHO may release, never the marketing consent regime.
    pub delivery_class: DeliveryClass,
    /// The purpose policy's autonomy requirement.
    pub autonomy: AutonomyRequirement,
    /// Whether the AUTONOMOUS sweep may release this reply through the
    /// promotion gate. False when the purpose policy requires human review,
    /// forbids autonomous response, implies no reply at all, or the
    /// classification risk is high. A false value HOLDS the draft for human
    /// approval; it never weakens any existing gate.
    pub sweep_may_release: bool,
    /// The policy reason the sweep may not release (empty when it may).
    pub hold_reason: &'static str,
}

/// Derive the release decision from a multi-label classification.
/// Deterministic. The decision consumes the EFFECTIVE risk and autonomy
/// (reduced over every matched purpose), and a no-reply purpose anywhere in
/// the set (automated, spam) makes the whole decision no-reply: adding labels
/// can only tighten this answer.
pub fn reply_release_decision(classification: &Classification) -> ReplyReleaseDecision {
    let no_reply = classification
        .purposes
        .iter()
        .any(|purpose| policy_for(*purpose).delivery_class == DeliveryClass::None);
    let (sweep_may_release, hold_reason) = if no_reply {
        (false, "purpose_policy_no_reply")
    } else {
        match classification.autonomy {
            AutonomyRequirement::NoAutonomousResponse => {
                (false, "purpose_policy_no_autonomous_response")
            }
            AutonomyRequirement::HumanReview => (false, "purpose_policy_human_review"),
            AutonomyRequirement::PromotionGate if classification.risk == RiskLevel::High => {
                (false, "purpose_policy_high_risk")
            }
            AutonomyRequirement::PromotionGate => (true, ""),
        }
    };
    ReplyReleaseDecision {
        delivery_class: reply_class_for_ai_draft(),
        autonomy: classification.autonomy,
        sweep_may_release,
        hold_reason,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn decision_for(purpose: InboundPurpose) -> ReplyReleaseDecision {
        reply_release_decision(&Classification::from_purposes(vec![purpose]))
    }

    /// The audit's representative inbound texts, table-driven.
    #[test]
    fn table_driven_classification_matches_the_audit_examples() {
        let cases: [(&str, &str, InboundPurpose, RiskLevel, bool); 9] = [
            (
                "API key broken",
                "The REST API key returns 401 on every call since this morning, \
                 can you check the account?",
                InboundPurpose::TechnicalSupport,
                RiskLevel::Low,
                true,
            ),
            (
                "our campaigns land in spam",
                "Everything we send is bouncing and goes to the junk folder \
                 since last week.",
                InboundPurpose::Deliverability,
                RiskLevel::Low,
                true,
            ),
            (
                "SPF fails alignment",
                "Our SPF record and DKIM selector look right in the DNS records \
                 but DMARC still fails.",
                InboundPurpose::DnsAuth,
                RiskLevel::Low,
                true,
            ),
            (
                "Refund my invoice",
                "I want a refund for the June invoice, please process it today.",
                InboundPurpose::Refund,
                RiskLevel::High,
                false,
            ),
            (
                "DPA request",
                "Please send your data processing agreement, we are completing \
                 our GDPR assessment.",
                InboundPurpose::Privacy,
                RiskLevel::Medium,
                false,
            ),
            (
                "Automatic reply: Out of office",
                "I am out of office until Monday with limited access to email.",
                InboundPurpose::Automated,
                RiskLevel::Low,
                false,
            ),
            (
                "Remove me",
                "Unsubscribe me from everything, take me off all your lists.",
                InboundPurpose::Abuse,
                RiskLevel::High,
                false,
            ),
            (
                "Verify your account now",
                "Unusual login detected, click the link to avoid having your \
                 account suspended.",
                InboundPurpose::AccountSecurity,
                RiskLevel::High,
                false,
            ),
            (
                "Interested in the product",
                "We are a team of 40, what is the pricing and can we book a demo?",
                InboundPurpose::Sales,
                RiskLevel::Low,
                true,
            ),
        ];
        for (subject, body, purpose, risk, sweep) in cases {
            let classification = classify_all(subject, body, None);
            assert_eq!(
                classification.primary, purpose,
                "subject {subject:?} must classify {purpose} as its primary label, got {:?}",
                classification.purposes
            );
            assert!(
                classification.purposes.contains(&purpose),
                "subject {subject:?} must carry {purpose}, got {:?}",
                classification.purposes
            );
            assert_eq!(
                classification.risk, risk,
                "subject {subject:?} must carry effective risk {risk}, got {:?}",
                classification.purposes
            );
            let decision = reply_release_decision(&classification);
            assert_eq!(
                decision.sweep_may_release, sweep,
                "subject {subject:?}: wrong sweep decision {:?}",
                decision
            );
        }
    }

    /// The policy table rows the audit states explicitly.
    #[test]
    fn policy_table_rows_match_the_audit_table() {
        // DNS/API support: service, autosend capable.
        let support = policy_for(InboundPurpose::TechnicalSupport);
        assert_eq!(support.delivery_class, DeliveryClass::Service);
        assert_eq!(support.autonomy, AutonomyRequirement::PromotionGate);

        // Invoice explanation: service, review.
        let invoice = policy_for(InboundPurpose::Invoice);
        assert_eq!(invoice.delivery_class, DeliveryClass::Service);
        assert_eq!(invoice.autonomy, AutonomyRequirement::HumanReview);

        // Refund/cancellation dispute: service, human review.
        for purpose in [InboundPurpose::Refund, InboundPurpose::Cancellation] {
            let policy = policy_for(purpose);
            assert_eq!(policy.delivery_class, DeliveryClass::Service);
            assert_eq!(policy.autonomy, AutonomyRequirement::HumanReview);
        }

        // GDPR/privacy and legal notice: service, mandatory review.
        for purpose in [InboundPurpose::Privacy, InboundPurpose::Legal] {
            let policy = policy_for(purpose);
            assert_eq!(policy.delivery_class, DeliveryClass::Service);
            assert_eq!(policy.autonomy, AutonomyRequirement::HumanReview);
        }

        // Phishing/abuse: security sensitivity, no autonomous response. Abuse
        // carries the strict no-autonomous-response requirement outright;
        // account_security requires human review, and both hold the draft for
        // a human either way.
        for purpose in [InboundPurpose::Abuse, InboundPurpose::AccountSecurity] {
            assert!(
                !decision_for(purpose).sweep_may_release,
                "{purpose} must not auto-send"
            );
        }
        assert_eq!(
            policy_for(InboundPurpose::Abuse).autonomy,
            AutonomyRequirement::NoAutonomousResponse
        );
        assert_eq!(
            policy_for(InboundPurpose::AccountSecurity).autonomy,
            AutonomyRequirement::HumanReview
        );

        // Fifth external audit, the reversal: `other` is uncertainty, and
        // uncertainty must never keep autonomy. It is service/medium/HUMAN
        // REVIEW (the audit's original low-risk promotion-gate row let an
        // unproven classifier's silence grant autonomy).
        let other = policy_for(InboundPurpose::Other);
        assert_eq!(other.delivery_class, DeliveryClass::Service);
        assert_eq!(other.default_risk, RiskLevel::Medium);
        assert_eq!(other.autonomy, AutonomyRequirement::HumanReview);
        let other_decision = decision_for(InboundPurpose::Other);
        assert!(!other_decision.sweep_may_release);
        assert_eq!(other_decision.hold_reason, "purpose_policy_human_review");

        // OOO/bounce and spam: no reply at all.
        for purpose in [InboundPurpose::Automated, InboundPurpose::Spam] {
            let policy = policy_for(purpose);
            assert_eq!(policy.delivery_class, DeliveryClass::None);
            assert!(!decision_for(purpose).sweep_may_release);
        }
    }

    /// The anti-recurrence invariant this module exists for: NO inbound
    /// purpose's policy ever maps to the marketing delivery class. The
    /// marketing class is the outbound campaign/sequence regime, never the
    /// default for a reply to an inbound message.
    #[test]
    fn no_inbound_purpose_maps_to_marketing() {
        for purpose in InboundPurpose::ALL {
            let policy = policy_for(purpose);
            assert_ne!(
                policy.delivery_class,
                DeliveryClass::Marketing,
                "purpose {purpose} must never default to the marketing class"
            );
            assert!(
                policy.delivery_class == DeliveryClass::Service
                    || policy.delivery_class == DeliveryClass::None,
                "purpose {purpose} carries an unexpected class {policy:?}"
            );
            let decision = decision_for(purpose);
            assert_eq!(
                decision.delivery_class,
                reply_class_for_ai_draft(),
                "an approved reply is always service correspondence, whatever the purpose"
            );
        }
    }

    /// The release class of an approved AI reply is SERVICE, explicitly: the
    /// marketing-consent requirement does not gate it, the queue category is
    /// the preference-exempt service value, and suppression still applies
    /// (that part lives in the admission gate, which probes the suppression
    /// stores for every class).
    #[test]
    fn approved_ai_replies_release_as_service_mail() {
        let class = reply_class_for_ai_draft();
        assert_eq!(class, DeliveryClass::Service);
        assert_eq!(class.as_str(), "service");
        assert_eq!(class.message_category(), Some("service"));
        assert!(!class.requires_marketing_consent());
        // The queue category the class writes is preference-exempt, the exact
        // property the marketing consent gate keys on.
        assert!(
            apexmail_lib::email_headers::message_category::is_preference_exempt(
                class.message_category().expect("service has a category")
            )
        );
    }

    /// Delivery-class to queue-category mapping and the consent regime.
    #[test]
    fn delivery_class_category_mapping_is_explicit() {
        assert_eq!(
            DeliveryClass::Transactional.message_category(),
            Some("transactional")
        );
        assert!(!DeliveryClass::Transactional.requires_marketing_consent());
        assert_eq!(
            DeliveryClass::Marketing.message_category(),
            Some("marketing")
        );
        assert!(DeliveryClass::Marketing.requires_marketing_consent());
        assert_eq!(DeliveryClass::None.message_category(), None);
        assert_eq!(DeliveryClass::None.as_str(), "none");
        // The categories are the server-owned canonical strings.
        for class in [
            DeliveryClass::Service,
            DeliveryClass::Transactional,
            DeliveryClass::Marketing,
        ] {
            let category = class.message_category().expect("sendable class");
            assert_eq!(
                apexmail_lib::email_headers::message_category::validate(category).as_deref(),
                Some(category)
            );
        }
    }

    /// The vocabulary round-trips through its persisted strings, the policy
    /// table is total over the enum, and classification is deterministic.
    #[test]
    fn vocabulary_round_trips_and_the_table_is_total() {
        for purpose in InboundPurpose::ALL {
            assert_eq!(InboundPurpose::parse(purpose.as_str()), Some(purpose));
            let _ = policy_for(purpose);
        }
        assert_eq!(InboundPurpose::parse("autosend"), None);
        assert_eq!(InboundPurpose::parse(""), None);
        for risk in RiskLevel::ALL {
            assert_eq!(risk.as_str(), risk.to_string());
        }
        assert_eq!(DeliveryClass::None.to_string(), "none");

        let classification = classify_all("Thursday works", "Shall I send the invite?", None);
        for _ in 0..8 {
            assert_eq!(
                classify_all("Thursday works", "Shall I send the invite?", None),
                classification
            );
        }
        // The thin wrapper carries the primary label and effective risk.
        assert_eq!(
            classify("Thursday works", "Shall I send the invite?"),
            (classification.primary, classification.risk)
        );
    }

    /// Rule-order pins: a customer quoting a DSN phrase is deliverability,
    /// not automated; an autoresponder's subject template stays the primary
    /// label; a legal threat wrapped in an unsubscribe demand carries BOTH
    /// labels and takes the strictest autonomy; ordinary text falls back to
    /// other (service/medium/HUMAN REVIEW).
    #[test]
    fn rule_order_is_pinned() {
        // A customer asking about their own bounces: NOT an autoresponder.
        let classification = classify_all(
            "why do my emails bounce",
            "Our sends to gmail bounces with no DSN we can find.",
            None,
        );
        assert_eq!(classification.primary, InboundPurpose::Deliverability);
        assert!(!classification.purposes.contains(&InboundPurpose::Automated));

        // An autoresponder that mentions the support address: still
        // automated (the subject template is structural evidence).
        let classification = classify_all(
            "Automatic reply: out of office",
            "I am away. For urgent matters contact support@.example.",
            None,
        );
        assert_eq!(classification.primary, InboundPurpose::Automated);
        assert!(!reply_release_decision(&classification).sweep_may_release);

        // An unsubscribe demand wrapped around a threat: both abuse and
        // legal are labels; abuse is primary (rule order) and the effective
        // autonomy is the strictest (no autonomous response), suppression
        // path upstream unchanged.
        let classification = classify_all(
            "unsubscribe and delete everything",
            "If you ever email me again I will see you in court with my lawyer.",
            None,
        );
        assert_eq!(classification.primary, InboundPurpose::Abuse);
        assert!(classification.purposes.contains(&InboundPurpose::Legal));
        assert_eq!(classification.risk, RiskLevel::High);
        assert_eq!(
            classification.autonomy,
            AutonomyRequirement::NoAutonomousResponse
        );
        assert!(!reply_release_decision(&classification).sweep_may_release);

        // A real DSN is automated only with machine-mail evidence. WITHOUT
        // headers the same text is a delivery-problem description, never
        // machine mail (fifth external audit).
        let dsn_headers = json!({
            "auto-submitted": "auto-generated",
            "content-type": "multipart/report; report-type=delivery-status",
        });
        let classification = classify_all(
            "Delivery Status Notification",
            "This message could not be delivered to the recipient address.",
            Some(&dsn_headers),
        );
        assert_eq!(classification.primary, InboundPurpose::Automated);
        assert!(!reply_release_decision(&classification).sweep_may_release);
        let headerless = classify_all(
            "Delivery Status Notification",
            "This message could not be delivered to the recipient address.",
            None,
        );
        assert!(!headerless.purposes.contains(&InboundPurpose::Automated));
        assert!(headerless
            .purposes
            .contains(&InboundPurpose::Deliverability));

        // Unmatched text: other, medium risk, human review. Uncertainty never
        // keeps autonomy.
        let classification = classify_all("Re: notes", "Thanks for the context, noted.", None);
        assert_eq!(classification.purposes, vec![InboundPurpose::Other]);
        assert_eq!(classification.risk, RiskLevel::Medium);
        assert_eq!(classification.autonomy, AutonomyRequirement::HumanReview);
        assert!(!reply_release_decision(&classification).sweep_may_release);
    }

    /// Fifth external audit: compound intents keep every matched label and the
    /// reduction takes the strictest policy. Single-purpose rows are
    /// unchanged.
    #[test]
    fn compound_intents_take_the_strictest_policy() {
        // billing + cancellation: both service, cancellation is the high-risk
        // human-review label.
        let billing_cancellation = classify_all(
            "Cancel my subscription and fix the billing",
            "Please cancel my subscription today, the billing is also wrong.",
            None,
        );
        assert!(billing_cancellation
            .purposes
            .contains(&InboundPurpose::Billing));
        assert!(billing_cancellation
            .purposes
            .contains(&InboundPurpose::Cancellation));
        assert_eq!(
            billing_cancellation.primary,
            InboundPurpose::Cancellation,
            "cancellation precedes billing in the documented rule order"
        );
        assert_eq!(billing_cancellation.risk, RiskLevel::High);
        assert_eq!(
            billing_cancellation.autonomy,
            AutonomyRequirement::HumanReview
        );
        assert!(!reply_release_decision(&billing_cancellation).sweep_may_release);

        // security + legal: high risk under either label.
        let security_legal = classify_all(
            "Hacked account and lawyer involved",
            "Our account was compromised and the attorney will file a lawsuit.",
            None,
        );
        assert!(security_legal
            .purposes
            .contains(&InboundPurpose::AccountSecurity));
        assert!(security_legal.purposes.contains(&InboundPurpose::Legal));
        assert_eq!(security_legal.risk, RiskLevel::High);
        assert_eq!(security_legal.autonomy, AutonomyRequirement::HumanReview);
        assert!(!reply_release_decision(&security_legal).sweep_may_release);

        // technical + procurement: the procurement label alone turns an
        // autosend-capable support question into human review (medium risk).
        let technical_procurement = classify_all(
            "Security questionnaire and API integration",
            "Our procurement team needs the vendor form; the integration stopped working.",
            None,
        );
        assert!(technical_procurement
            .purposes
            .contains(&InboundPurpose::TechnicalSupport));
        assert!(technical_procurement
            .purposes
            .contains(&InboundPurpose::Procurement));
        assert_eq!(
            technical_procurement.primary,
            InboundPurpose::Procurement,
            "procurement precedes technical support in the documented rule order"
        );
        assert_eq!(technical_procurement.risk, RiskLevel::Medium);
        assert_eq!(
            technical_procurement.autonomy,
            AutonomyRequirement::HumanReview
        );
        assert!(!reply_release_decision(&technical_procurement).sweep_may_release);

        // Single-purpose rows keep their policy exactly.
        let support = classify_all("API key broken", "the integration stopped working.", None);
        assert_eq!(support.purposes, vec![InboundPurpose::TechnicalSupport]);
        assert_eq!(support.risk, RiskLevel::Low);
        assert_eq!(support.autonomy, AutonomyRequirement::PromotionGate);
        let support_decision = reply_release_decision(&support);
        assert!(support_decision.sweep_may_release);
        assert_eq!(support_decision.hold_reason, "");
    }

    /// Reduction monotonicity (property): adding a label can only escalate
    /// risk and autonomy, never relax them, and never changes the primary
    /// label (the first/strongest hit).
    #[test]
    fn adding_labels_never_lowers_risk_or_autonomy() {
        let risk_rank = |risk: RiskLevel| risk.severity();
        let autonomy_rank = |autonomy: AutonomyRequirement| autonomy.strictness();

        for base in InboundPurpose::ALL {
            let single = Classification::from_purposes(vec![base]);
            for extra in InboundPurpose::ALL {
                let pair = Classification::from_purposes(vec![base, extra]);
                assert!(
                    risk_rank(pair.risk) >= risk_rank(single.risk),
                    "adding {extra} to {base} lowered the risk: {} -> {}",
                    single.risk,
                    pair.risk
                );
                assert!(
                    autonomy_rank(pair.autonomy) >= autonomy_rank(single.autonomy),
                    "adding {extra} to {base} relaxed autonomy: {} -> {}",
                    single.autonomy,
                    pair.autonomy
                );
                assert_eq!(pair.primary, base, "the first label stays primary");

                for third in InboundPurpose::ALL {
                    let triple = Classification::from_purposes(vec![base, extra, third]);
                    assert!(
                        risk_rank(triple.risk) >= risk_rank(pair.risk),
                        "adding {third} to {base}+{extra} lowered the risk"
                    );
                    assert!(
                        autonomy_rank(triple.autonomy) >= autonomy_rank(pair.autonomy),
                        "adding {third} to {base}+{extra} relaxed autonomy"
                    );
                }
            }
        }

        // The empty set is the classifier's uncertainty state, never an
        // autonomy grant.
        let empty = Classification::from_purposes(Vec::new());
        assert_eq!(empty.purposes, vec![InboundPurpose::Other]);
        assert_eq!(empty.risk, RiskLevel::Medium);
        assert_eq!(empty.autonomy, AutonomyRequirement::HumanReview);
    }

    /// Fifth external audit: automated mail requires MACHINE evidence, never
    /// prose. The audit's customer counterexample must stay a real
    /// deliverability conversation.
    #[test]
    fn customer_delivery_prose_without_headers_is_not_automated() {
        let classification = classify_all(
            "We have a delivery failure",
            "we have a delivery failure and the address was not found, can you help?",
            None,
        );
        assert!(!classification.purposes.contains(&InboundPurpose::Automated));
        assert!(
            classification
                .purposes
                .contains(&InboundPurpose::Deliverability),
            "the customer's delivery problem must classify deliverability, got {:?}",
            classification.purposes
        );
        assert_eq!(classification.primary, InboundPurpose::Deliverability);
        assert_eq!(classification.risk, RiskLevel::Low);
        assert_eq!(classification.autonomy, AutonomyRequirement::PromotionGate);
        assert!(reply_release_decision(&classification).sweep_may_release);
    }

    /// A real DSN carries the structural headers: automated and no reply.
    #[test]
    fn real_dsn_headers_classify_as_automated_and_no_reply() {
        let dsn_headers = json!({
            "auto-submitted": "auto-generated",
            "content-type": "multipart/report; report-type=delivery-status; boundary=\"x\"",
            "return-path": "<>",
        });
        let classification = classify_all(
            "Delivery Status Notification",
            "This message could not be delivered to the recipient address.",
            Some(&dsn_headers),
        );
        assert_eq!(classification.primary, InboundPurpose::Automated);
        assert!(classification.purposes.contains(&InboundPurpose::Automated));
        let decision = reply_release_decision(&classification);
        assert!(!decision.sweep_may_release);
        assert_eq!(decision.hold_reason, "purpose_policy_no_reply");
        assert_eq!(
            policy_for(InboundPurpose::Automated).delivery_class,
            DeliveryClass::None
        );
    }

    /// Each structural machine-mail signal is sufficient on its own.
    #[test]
    fn structural_header_signals_each_classify_as_automated() {
        for headers in [
            json!({"auto-submitted": "auto-generated"}),
            json!({"auto-submitted": "auto-replied"}),
            json!({"auto-submitted": "auto-notified"}),
            json!({"auto-submitted": "auto-replied; owner-email=\"owner@example.com\""}),
            json!({"precedence": "bulk"}),
            json!({"precedence": "junk"}),
            json!({"precedence": "list"}),
            json!({"x-autoreply": "yes"}),
            json!({"x-autorespond": "yes"}),
            json!({"x-autoresponder": "yes"}),
            json!({"auto-reply": "yes"}),
            json!({"return-path": "<>"}),
            json!({"content-type": "multipart/report; report-type=\"delivery-status\""}),
            // The MTA mirror writes lowercase names, but the lookup is
            // case-insensitive for the fixture/other-writer path.
            json!({"Auto-Submitted": "auto-generated"}),
        ] {
            let classification = classify_all(
                "Re: project update",
                "Sounds good, talk tomorrow.",
                Some(&headers),
            );
            assert!(
                classification.purposes.contains(&InboundPurpose::Automated),
                "headers {headers} must classify automated, got {:?}",
                classification.purposes
            );
            assert_eq!(
                classification.primary,
                InboundPurpose::Automated,
                "headers {headers}"
            );
        }
    }

    /// Values that are NOT machine-mail evidence, including the RFC 3834
    /// `no` value and non-DSN report types.
    #[test]
    fn non_machine_header_values_are_not_automated_evidence() {
        for headers in [
            json!({"auto-submitted": "no"}),
            json!({"precedence": "first-class"}),
            json!({"content-type": "multipart/report; report-type=disposition-notification"}),
            json!({"content-type": "text/plain; charset=utf-8"}),
            json!({"return-path": "<customer@example.com>"}),
            json!({}),
        ] {
            let classification = classify_all(
                "Re: project update",
                "Sounds good, talk tomorrow.",
                Some(&headers),
            );
            assert!(
                !classification.purposes.contains(&InboundPurpose::Automated),
                "headers {headers} must not classify automated, got {:?}",
                classification.purposes
            );
        }
    }

    /// The documented subject-line template set is the ONLY text-only
    /// automated evidence: exact prefix on the subject, never body prose and
    /// never a mid-subject occurrence.
    #[test]
    fn subject_line_templates_are_the_only_textual_automated_evidence() {
        for subject in [
            "Automatic reply: away",
            "Auto-Reply: away",
            "Auto Reply: away",
            "Out of Office: away",
            "out-of-office: away",
            "Automated response: away",
        ] {
            let classification = classify_all(subject, "I am away until Monday.", None);
            assert_eq!(
                classification.primary,
                InboundPurpose::Automated,
                "subject {subject:?} is a documented machine template"
            );
        }
        // Body prose alone is not evidence.
        let classification = classify_all(
            "Re: notes",
            "Automatic reply: the system sent this yesterday.",
            None,
        );
        assert!(!classification.purposes.contains(&InboundPurpose::Automated));
        // A mid-subject occurrence is not a template prefix.
        let classification =
            classify_all("Re: Automatic reply: away", "I am away until Monday.", None);
        assert!(!classification.purposes.contains(&InboundPurpose::Automated));
    }

    /// Missing headers (`None`), an empty JSON object, and a JSON null all
    /// behave like the no-header path.
    #[test]
    fn missing_headers_behave_like_the_no_header_path() {
        let no_headers = classify_all("Why do my emails bounce?", "our sends bounce", None);
        let empty_headers = classify_all(
            "Why do my emails bounce?",
            "our sends bounce",
            Some(&json!({})),
        );
        let null_headers = classify_all(
            "Why do my emails bounce?",
            "our sends bounce",
            Some(&serde_json::Value::Null),
        );
        assert_eq!(no_headers, empty_headers);
        assert_eq!(no_headers, null_headers);
        assert_eq!(
            classify("Why do my emails bounce?", "our sends bounce"),
            (no_headers.primary, no_headers.risk)
        );
    }
}
