//! Types for reply handler.

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

/// Sentiment analysis result.
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
    #[sqlx(rename = "receivedAt")]
    pub received_at: DateTime<Utc>,
    #[sqlx(rename = "processedAt")]
    pub processed_at: Option<DateTime<Utc>>,
    pub classification: Option<String>,
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
