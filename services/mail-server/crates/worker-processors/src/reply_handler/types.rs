//! Types for reply handler.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;

/// Reply classification categories.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReplyClassification {
    OutOfOffice,
    NotInterested,
    Interested,
    TellMeMore,
    WrongPerson,
    Referral,
    Unsubscribe,
    Bounce,
    PositiveIntent,
    MeetingRequest,
    Question,
    Complaint,
    Spam,
    Unknown,
}

impl ReplyClassification {
    /// Convert to string.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::OutOfOffice => "out_of_office",
            Self::NotInterested => "not_interested",
            Self::Interested => "interested",
            Self::TellMeMore => "tell_me_more",
            Self::WrongPerson => "wrong_person",
            Self::Referral => "referral",
            Self::Unsubscribe => "unsubscribe",
            Self::Bounce => "bounce",
            Self::PositiveIntent => "positive_intent",
            Self::MeetingRequest => "meeting_request",
            Self::Question => "question",
            Self::Complaint => "complaint",
            Self::Spam => "spam",
            Self::Unknown => "unknown",
        }
    }
}

impl std::str::FromStr for ReplyClassification {
    type Err = std::convert::Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s.to_lowercase().as_str() {
            "out_of_office" | "ooo" => Self::OutOfOffice,
            "not_interested" => Self::NotInterested,
            "interested" => Self::Interested,
            "tell_me_more" => Self::TellMeMore,
            "wrong_person" => Self::WrongPerson,
            "referral" => Self::Referral,
            "unsubscribe" => Self::Unsubscribe,
            "bounce" => Self::Bounce,
            "positive_intent" => Self::PositiveIntent,
            "meeting_request" => Self::MeetingRequest,
            "question" => Self::Question,
            "complaint" => Self::Complaint,
            "spam" => Self::Spam,
            _ => Self::Unknown,
        })
    }
}

impl std::fmt::Display for ReplyClassification {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// Canonical reply intelligence vocabulary (§20/§21 unification)
// ---------------------------------------------------------------------------

/// Canonical inbound reply disposition — the 11-variant vocabulary of
/// `sales_reply_classifications.disposition` (migration 200) and
/// `sales_autopilot::types::ReplyDisposition`.
///
/// This crate deliberately MIRRORS that vocabulary instead of depending on
/// `sales-autopilot`: the worker process only needs the string contract (the
/// DB CHECK constraint is the shared authority), and worker-processors must
/// not grow a dependency on the control-plane crate for it. The `as_str`
/// values are byte-for-byte the canonical strings; a drift here fails the
/// database CHECK constraint rather than corrupting data.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReplyDisposition {
    Positive,
    MeetingRequest,
    Question,
    Referral,
    NotInterested,
    Unsubscribe,
    Complaint,
    OutOfOffice,
    BounceHard,
    BounceSoft,
    Unknown,
}

impl ReplyDisposition {
    /// The canonical `sales_reply_classifications.disposition` string.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Positive => "positive",
            Self::MeetingRequest => "meeting_request",
            Self::Question => "question",
            Self::Referral => "referral",
            Self::NotInterested => "not_interested",
            Self::Unsubscribe => "unsubscribe",
            Self::Complaint => "complaint",
            Self::OutOfOffice => "ooo",
            Self::BounceHard => "bounce_hard",
            Self::BounceSoft => "bounce_soft",
            Self::Unknown => "unknown",
        }
    }

    /// Every variant, in the canonical order. Useful for table-driven tests
    /// and for the AI request's `taxonomy` field.
    pub const ALL: [ReplyDisposition; 11] = [
        Self::Positive,
        Self::MeetingRequest,
        Self::Question,
        Self::Referral,
        Self::NotInterested,
        Self::Unsubscribe,
        Self::Complaint,
        Self::OutOfOffice,
        Self::BounceHard,
        Self::BounceSoft,
        Self::Unknown,
    ];

    /// Must any human reply of this kind stop the normal sequence?
    ///
    /// Mirrors `sales_autopilot::types::ReplyDisposition::stops_normal_sequence`:
    /// every disposition except a pure out-of-office autoreply / soft bounce is
    /// a signal the scheduled follow-up must not race.
    pub fn stops_normal_sequence(self) -> bool {
        !matches!(self, Self::OutOfOffice | Self::BounceSoft)
    }

    /// Does the sales side treat this disposition as permanent suppression
    /// (the enrollment lock upserts `sales_unsubscribes`)?
    pub fn is_permanent_suppression(self) -> bool {
        matches!(
            self,
            Self::Unsubscribe | Self::Complaint | Self::BounceHard | Self::NotInterested
        )
    }

    /// Does the enrollment lock UPSERT `sales_unsubscribes` for this
    /// disposition? This mirrors `sales_autopilot::enrollments::lock_on_reply`
    /// exactly: `NotInterested` is a permanent suppression domain concept but
    /// does NOT write the unsubscribe fast path.
    pub fn requires_unsubscribe_upsert(self) -> bool {
        matches!(self, Self::Unsubscribe | Self::Complaint | Self::BounceHard)
    }

    /// Human-readable note for the persisted `operator_correction` column.
    pub fn corrects(self, corrected: ReplyDisposition) -> String {
        format!(
            "operator corrected '{}' -> '{}'",
            self.as_str(),
            corrected.as_str()
        )
    }
}

impl std::str::FromStr for ReplyDisposition {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s.trim().to_ascii_lowercase().as_str() {
            "positive" => Self::Positive,
            "meeting_request" => Self::MeetingRequest,
            "question" => Self::Question,
            "referral" => Self::Referral,
            "not_interested" => Self::NotInterested,
            "unsubscribe" => Self::Unsubscribe,
            "complaint" => Self::Complaint,
            "ooo" | "out_of_office" => Self::OutOfOffice,
            "bounce_hard" => Self::BounceHard,
            "bounce_soft" => Self::BounceSoft,
            "unknown" => Self::Unknown,
            other => return Err(format!("unknown reply disposition '{other}'")),
        })
    }
}

impl std::fmt::Display for ReplyDisposition {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl From<ReplyDisposition> for ReplyClassification {
    /// Legacy-vocabulary projection for the existing `inbound_messages`
    /// columns and the public `classify()` API.
    fn from(disposition: ReplyDisposition) -> Self {
        match disposition {
            ReplyDisposition::Positive => Self::PositiveIntent,
            ReplyDisposition::MeetingRequest => Self::MeetingRequest,
            ReplyDisposition::Question => Self::Question,
            ReplyDisposition::Referral => Self::Referral,
            ReplyDisposition::NotInterested => Self::NotInterested,
            ReplyDisposition::Unsubscribe => Self::Unsubscribe,
            ReplyDisposition::Complaint => Self::Complaint,
            ReplyDisposition::OutOfOffice => Self::OutOfOffice,
            ReplyDisposition::BounceHard | ReplyDisposition::BounceSoft => Self::Bounce,
            ReplyDisposition::Unknown => Self::Unknown,
        }
    }
}

/// Which layer produced a classification. The canonical
/// `sales_reply_classifications.classifier` vocabulary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClassifierKind {
    Deterministic,
    Ai,
    Operator,
}

impl ClassifierKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Deterministic => "deterministic",
            Self::Ai => "ai",
            Self::Operator => "operator",
        }
    }
}

/// One auditable fact behind a classification.
///
/// A deterministic verdict MUST carry the exact header name + value or the
/// exact matched token, so an operator can replay the decision without the
/// original message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Evidence {
    /// `header`, `dsn`, `subject`, or `token`.
    pub kind: String,
    /// The header name / pattern group / token list name.
    pub key: String,
    /// The exact observed value.
    pub value: String,
}

impl Evidence {
    pub fn new(kind: impl Into<String>, key: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            kind: kind.into(),
            key: key.into(),
            value: value.into(),
        }
    }

    /// Exact header evidence: `header: <name> = <value>`.
    pub fn header(name: &str, value: &str) -> Self {
        Self::new("header", name.to_ascii_lowercase(), value)
    }

    /// Exact token evidence.
    pub fn token(token: &str) -> Self {
        Self::new("token", "stop_request", token)
    }

    /// DSN syntax evidence (e.g. `Status: 5.1.1`).
    pub fn dsn(key: &str, value: &str) -> Self {
        Self::new("dsn", key, value)
    }
}

/// The message as the classifier layers consume it.
///
/// Constructed from an [`InboundMessage`] by the processor, but usable
/// standalone (tests, replay tooling). Header lookup is case-insensitive;
/// header values are stored as strings and non-string JSON header values are
/// ignored rather than coerced.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ReplyInput {
    pub subject: String,
    pub body: String,
    /// Lowercased header name -> raw value.
    pub headers: BTreeMap<String, String>,
}

impl ReplyInput {
    pub fn new(subject: impl Into<String>, body: impl Into<String>) -> Self {
        Self {
            subject: subject.into(),
            body: body.into(),
            headers: BTreeMap::new(),
        }
    }

    /// Build from raw bytes, lossily converting invalid UTF-8.
    ///
    /// Hostile input (a body that is not valid UTF-8) must degrade to
    /// replacement characters, never panic or abort classification.
    pub fn from_bytes(subject: &[u8], body: &[u8]) -> Self {
        Self::new(
            String::from_utf8_lossy(subject).into_owned(),
            String::from_utf8_lossy(body).into_owned(),
        )
    }

    pub fn with_header(mut self, name: &str, value: &str) -> Self {
        self.headers
            .insert(name.to_ascii_lowercase(), value.to_string());
        self
    }

    /// Attach headers from the canonical inbound `headers` JSONB object.
    /// Non-object values and non-string values are ignored.
    pub fn with_headers_json(mut self, headers: Option<&serde_json::Value>) -> Self {
        if let Some(serde_json::Value::Object(map)) = headers {
            for (name, value) in map {
                if let Some(value) = value.as_str() {
                    self.headers
                        .insert(name.to_ascii_lowercase(), value.to_string());
                }
            }
        }
        self
    }

    /// Case-insensitive header lookup.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .get(&name.to_ascii_lowercase())
            .map(String::as_str)
    }
}

/// A semantic classification produced by any [`crate::reply_handler::ai::ReplyClassifier`]
/// implementation. Every field is persisted to
/// `sales_reply_classifications` (`disposition`, `confidence`, `reasoning`,
/// `model_version`, `prompt_version`, `evidence`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiClassification {
    pub disposition: ReplyDisposition,
    pub confidence: f64,
    pub reasoning: String,
    pub model_version: Option<String>,
    pub prompt_version: Option<String>,
    pub evidence: Vec<Evidence>,
}

impl AiClassification {
    /// The conservative "no verified interpretation" result. Used when no AI
    /// is configured or the AI call failed: NEVER guess a category.
    pub fn unknown_outage(reason: impl Into<String>) -> Self {
        Self {
            disposition: ReplyDisposition::Unknown,
            confidence: 0.0,
            reasoning: reason.into(),
            model_version: None,
            prompt_version: None,
            evidence: Vec::new(),
        }
    }

    pub fn is_positive_category(&self) -> bool {
        matches!(
            self.disposition,
            ReplyDisposition::Positive
                | ReplyDisposition::MeetingRequest
                | ReplyDisposition::Question
                | ReplyDisposition::Referral
        )
    }
}

/// The complete classification outcome: the canonical disposition plus the
/// legacy-shaped [`ClassificationResult`] the existing callers consume.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClassificationOutcome {
    /// Canonical disposition (the `sales_reply_classifications` vocabulary).
    pub disposition: ReplyDisposition,
    /// Which layer decided.
    pub classifier: ClassifierKind,
    /// Legacy result (`classification`, confidence, extracted data, action).
    pub result: ClassificationResult,
    /// Auditable evidence behind the verdict.
    pub evidence: Vec<Evidence>,
    /// AI model identity, when the AI layer decided.
    pub model_version: Option<String>,
    /// Prompt identity, when the AI layer decided.
    pub prompt_version: Option<String>,
    /// For `ooo`: the parsed return date, when present.
    pub return_date: Option<DateTime<Utc>>,
    /// Set when the policy downgraded the observed disposition (low
    /// confidence / non-finite confidence) to `Unknown`.
    pub downgraded_from: Option<ReplyDisposition>,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[derive(Default)]
pub enum Sentiment {
    Positive,
    Negative,
    #[default]
    Neutral,
}

/// Urgency level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[derive(Default)]
pub enum Urgency {
    High,
    #[default]
    Medium,
    Low,
}

/// Action type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionType {
    Snooze,
    Suppress,
    FlagSales,
    ScheduleDemo,
    RequestReferral,
    Unsubscribe,
    Ignore,
    Escalate,
    AutoReply,
}

/// Extracted data from reply content.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ExtractedData {
    /// Return date for OOO.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub return_date: Option<DateTime<Utc>>,
    /// Referred contact for wrong person.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub referred_contact: Option<String>,
    /// Whether this is a meeting request.
    pub meeting_request: bool,
    /// Detected sentiment.
    pub sentiment: Sentiment,
    /// Urgency level.
    pub urgency: Urgency,
}

/// Suggested action based on classification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuggestedAction {
    pub action: ActionType,
    pub parameters: serde_json::Value,
    pub auto_execute: bool,
    pub priority: Urgency,
}

impl Default for SuggestedAction {
    fn default() -> Self {
        Self {
            action: ActionType::Ignore,
            parameters: serde_json::Value::Object(Default::default()),
            auto_execute: false,
            priority: Urgency::Low,
        }
    }
}

/// Full classification result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClassificationResult {
    pub classification: ReplyClassification,
    pub confidence: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sub_type: Option<String>,
    pub extracted_data: ExtractedData,
    pub suggested_action: SuggestedAction,
    pub reasoning: String,
}

/// Inbound message from the queue.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct InboundMessage {
    pub id: String,
    #[sqlx(rename = "tenantId")]
    pub tenant_id: Option<String>,
    #[sqlx(rename = "leadId")]
    pub lead_id: Option<String>,
    #[sqlx(rename = "fromEmail")]
    pub from_email: String,
    #[sqlx(rename = "toEmail")]
    pub to_email: String,
    pub subject: String,
    #[sqlx(rename = "bodyText")]
    pub body_text: Option<String>,
    #[sqlx(rename = "bodyHtml")]
    pub body_html: Option<String>,
    pub headers: Option<serde_json::Value>,
    /// F67: the inbound reply's RFC 5322 Message-ID — the stable
    /// provider/inbound event identity for the analytics handoff.
    #[sqlx(rename = "messageIdHeader")]
    pub message_id_header: Option<String>,
    #[sqlx(rename = "receivedAt")]
    pub received_at: DateTime<Utc>,
    #[sqlx(rename = "processedAt")]
    pub processed_at: Option<DateTime<Utc>>,
    pub classification: Option<String>,
}

impl InboundMessage {
    /// F67: header lookup with case-insensitive names (the canonical
    /// headers JSONB uses arbitrary casing; auto-reply detection keys on
    /// lowercase canonical header names).
    pub fn header(&self, name: &str) -> Option<String> {
        let target = name.to_ascii_lowercase();
        self.headers
            .as_ref()?
            .as_object()?
            .iter()
            .find_map(|(k, v)| {
                if k.to_ascii_lowercase() == target {
                    v.as_str().map(str::to_string)
                } else {
                    None
                }
            })
    }

    /// F67: the headers auto-reply detection inspects, as a lowercase map.
    pub fn analytics_headers(&self) -> std::collections::HashMap<String, String> {
        let mut selected = std::collections::HashMap::new();
        for name in [
            "auto-submitted",
            "x-auto-response-suppress",
            "precedence",
            "x-auto-reply",
        ] {
            if let Some(value) = self.header(name) {
                selected.insert(name.to_string(), value);
            }
        }
        selected
    }

    /// F67: In-Reply-To from the canonical headers JSON (there is no
    /// dedicated column on inbound_messages).
    pub fn in_reply_to(&self) -> Option<String> {
        self.header("in-reply-to")
    }
}

impl InboundMessage {
    /// Build the classifier input from this row. Prefers `body_text` and
    /// falls back to `body_html` so an HTML-only reply is still classified.
    pub fn reply_input(&self) -> ReplyInput {
        let body = self
            .body_text
            .as_deref()
            .filter(|body| !body.trim().is_empty())
            .or(self.body_html.as_deref())
            .unwrap_or("");
        ReplyInput::new(self.subject.clone(), body).with_headers_json(self.headers.as_ref())
    }
}

/// Processed reply result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessedReply {
    pub inbound_message_id: String,
    pub lead_id: Option<String>,
    pub tenant_id: String,
    pub from_email: String,
    pub subject: String,
    pub body_preview: String,
    pub classification: ClassificationResult,
    pub action_taken: Option<String>,
    pub processed_at: DateTime<Utc>,
}
