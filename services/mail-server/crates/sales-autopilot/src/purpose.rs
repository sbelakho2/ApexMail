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
//! * [`classify`], a first-pass keyword/phrase classifier over the inbound
//!   subject + body. The deterministic layer is the policy AUTHORITY: a
//!   future model may refine the purpose label WITHIN these policy bounds
//!   (it may never widen a class beyond what the table grants).
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
//! | other | service | promotion gate | low |
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
            autonomy: PromotionGate,
            default_risk: Low,
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

/// The classification verdict: purpose plus the policy's risk for it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InboundClassification {
    pub purpose: InboundPurpose,
    pub risk: RiskLevel,
}

/// Keyword/phrase rules, checked in a documented priority order, first match
/// wins. Order IS policy: an autoresponder mentioning "support" is still
/// automated; a legal threat wrapped in an unsubscribe demand takes the
/// safer autonomy requirement either way.
///
/// Substring match over the lowercased subject + body. Deliberately
/// over-inclusive toward review: a false positive sends the draft to a human,
/// which is the safe direction, and never changes the delivery class away
/// from service for a reply.
///
/// The deterministic layer is the policy AUTHORITY (see the module doc): a
/// future model may refine the purpose label within [`policy_for`]'s bounds.
mod rules {
    /// Out-of-office autoresponders and delivery status notifications. No
    /// human reader, no reply. Precise DSN phrases only: a customer asking
    /// "why do my emails bounce" must reach the deliverability rule.
    pub const AUTOMATED: [&str; 21] = [
        "out of office",
        "out-of-office",
        "automatic reply",
        "auto-reply",
        "autoreply",
        "automated response",
        "away from the office",
        "on vacation",
        "on annual leave",
        "on parental leave",
        "on maternity leave",
        "on sick leave",
        "undeliverable",
        "delivery status notification",
        "delivery failure",
        "delivery has failed",
        "returned mail",
        "mailer-daemon",
        "mail delivery subsystem",
        "could not be delivered",
        "address not found",
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

    /// Delivery problems of the customer's own mail.
    pub const DELIVERABILITY: [&str; 13] = [
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
    /// slipped past the more specific rules is still support, and the
    /// fallback ([`super::InboundPurpose::Other`]) carries the same policy.
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

/// The rule order. First match wins; the order is documented policy (see the
/// `rules` module doc and the module doc's priority discussion).
const RULE_ORDER: [(InboundPurpose, &[&str]); 16] = [
    (InboundPurpose::Automated, &rules::AUTOMATED),
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

/// The deterministic first-pass classifier over the inbound subject and body.
/// Same text in, same classification out; no I/O, no model. Unmatched text
/// classifies as [`InboundPurpose::Other`] with the policy's default risk.
pub fn classify(subject: &str, body: &str) -> InboundClassification {
    let combined = format!(
        "{}\n{}",
        subject.trim().to_lowercase(),
        body.trim().to_lowercase()
    );
    let purpose = RULE_ORDER
        .into_iter()
        .find(|(_, markers)| markers.iter().any(|marker| combined.contains(marker)))
        .map(|(purpose, _)| purpose)
        .unwrap_or(InboundPurpose::Other);
    let risk = policy_for(purpose).default_risk;
    InboundClassification { purpose, risk }
}

// ---------------------------------------------------------------------------
// The release decision: (purpose, risk) -> DeliveryClass + autonomy
// ---------------------------------------------------------------------------

/// The reply-handling decision the release points consume, derived from
/// (purpose, risk) through the policy table. This is what replaced the
/// everything-is-marketing default: the delivery class is a typed table
/// lookup, and the autonomous sweep can only ever be TIGHTENED by it.
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

/// Derive the release decision from a classification. Deterministic.
pub fn reply_release_decision(classification: &InboundClassification) -> ReplyReleaseDecision {
    let policy = policy_for(classification.purpose);
    let (sweep_may_release, hold_reason) = if policy.delivery_class == DeliveryClass::None {
        (false, "purpose_policy_no_reply")
    } else {
        match policy.autonomy {
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
        autonomy: policy.autonomy,
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
                "Out of office",
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
            let classification = classify(subject, body);
            assert_eq!(
                classification.purpose, purpose,
                "subject {subject:?} must classify {purpose}, got {}",
                classification.purpose
            );
            assert_eq!(
                classification.risk, risk,
                "subject {subject:?} must carry risk {risk}"
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
            let policy = policy_for(purpose);
            let decision = reply_release_decision(&InboundClassification {
                purpose,
                risk: policy.default_risk,
            });
            assert!(!decision.sweep_may_release, "{purpose} must not auto-send");
        }
        assert_eq!(
            policy_for(InboundPurpose::Abuse).autonomy,
            AutonomyRequirement::NoAutonomousResponse
        );
        assert_eq!(
            policy_for(InboundPurpose::AccountSecurity).autonomy,
            AutonomyRequirement::HumanReview
        );

        // OOO/bounce and spam: no reply at all.
        for purpose in [InboundPurpose::Automated, InboundPurpose::Spam] {
            let policy = policy_for(purpose);
            assert_eq!(policy.delivery_class, DeliveryClass::None);
            assert!(
                !reply_release_decision(&InboundClassification {
                    purpose,
                    risk: RiskLevel::Low,
                })
                .sweep_may_release
            );
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
            let decision = reply_release_decision(&InboundClassification {
                purpose,
                risk: policy.default_risk,
            });
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

        let classification = classify("Thursday works", "Shall I send the invite?");
        for _ in 0..8 {
            assert_eq!(
                classify("Thursday works", "Shall I send the invite?"),
                classification
            );
        }
    }

    /// Rule-order pins: a customer quoting a DSN phrase is deliverability,
    /// not automated; an autoresponder mentioning support stays automated; a
    /// legal threat wrapped in an unsubscribe demand takes the abuse rule
    /// (no autonomous response either way); ordinary text falls back to
    /// other with the service class.
    #[test]
    fn rule_order_is_pinned() {
        // A customer asking about their own bounces: NOT an autoresponder.
        let classification = classify(
            "why do my emails bounce",
            "Our sends to gmail bounces with no DSN we can find.",
        );
        assert_eq!(classification.purpose, InboundPurpose::Deliverability);

        // An autoresponder that mentions the support address: still automated.
        let classification = classify(
            "Automatic reply: out of office",
            "I am away. For urgent matters contact support@.example.",
        );
        assert_eq!(classification.purpose, InboundPurpose::Automated);
        assert!(!reply_release_decision(&classification).sweep_may_release);

        // An unsubscribe demand wrapped around a threat: abuse (the safe
        // autonomy outcome), suppression path upstream unchanged.
        let classification = classify(
            "unsubscribe and delete everything",
            "If you ever email me again I will see you in court with my lawyer.",
        );
        assert_eq!(classification.purpose, InboundPurpose::Abuse);
        assert!(!reply_release_decision(&classification).sweep_may_release);

        // A real DSN: automated, no reply.
        let classification = classify(
            "Delivery Status Notification",
            "This message could not be delivered to the recipient address.",
        );
        assert_eq!(classification.purpose, InboundPurpose::Automated);

        // Unmatched text: other, service class, promotion gate.
        let classification = classify("Re: notes", "Thanks for the context, noted.");
        assert_eq!(classification.purpose, InboundPurpose::Other);
        assert!(reply_release_decision(&classification).sweep_may_release);
    }
}
