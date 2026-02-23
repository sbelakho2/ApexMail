use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Enums
// ---------------------------------------------------------------------------

/// Status of a lead as it progresses through the sales funnel.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LeadStatus {
    New,
    Contacted,
    Qualified,
    Converted,
    Lost,
}

impl std::fmt::Display for LeadStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::New => write!(f, "new"),
            Self::Contacted => write!(f, "contacted"),
            Self::Qualified => write!(f, "qualified"),
            Self::Converted => write!(f, "converted"),
            Self::Lost => write!(f, "lost"),
        }
    }
}

/// Status of a drip/outreach campaign.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CampaignStatus {
    Draft,
    Active,
    Paused,
    Completed,
}

impl std::fmt::Display for CampaignStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Draft => write!(f, "draft"),
            Self::Active => write!(f, "active"),
            Self::Paused => write!(f, "paused"),
            Self::Completed => write!(f, "completed"),
        }
    }
}

/// Category of an inbound inbox message.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MessageCategory {
    Lead,
    Customer,
    Support,
    Spam,
    Other,
}

// ---------------------------------------------------------------------------
// Core domain structs
// ---------------------------------------------------------------------------

/// A sales lead tracked in the CRM.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Lead {
    pub id: Uuid,
    pub email: String,
    pub name: String,
    pub company: String,
    pub title: String,
    /// Lead score 0–100, calculated from engagement + firmographics.
    pub score: u8,
    /// Where this lead was acquired (e.g. "product_hunt", "manual").
    pub source: String,
    pub status: LeadStatus,
    pub created_at: DateTime<Utc>,
}

/// An enriched company record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Company {
    pub id: Uuid,
    pub name: String,
    pub domain: String,
    pub industry: String,
    /// A human-readable employee band such as "50-200".
    pub size: String,
    /// e.g. "$1M-$10M"
    pub revenue_range: String,
    pub enriched_at: DateTime<Utc>,
}

/// An outreach campaign.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Campaign {
    pub id: Uuid,
    pub name: String,
    pub template_id: String,
    /// Audience filter description (e.g. JSON filter).
    pub audience: String,
    pub status: CampaignStatus,
    pub sent: u64,
    pub opened: u64,
    pub clicked: u64,
    pub created_at: DateTime<Utc>,
}

/// A calendar event (demo / follow-up).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CalendarEvent {
    pub id: Uuid,
    pub title: String,
    pub attendees: Vec<String>,
    pub start_at: DateTime<Utc>,
    pub end_at: DateTime<Utc>,
    pub meeting_link: Option<String>,
}

/// A message in the monitored sales inbox.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InboxMessage {
    pub id: Uuid,
    pub from: String,
    pub subject: String,
    pub received_at: DateTime<Utc>,
    pub category: MessageCategory,
    pub replied: bool,
}

/// A tracked ad click for ROI attribution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdClick {
    pub id: Uuid,
    pub campaign_id: Uuid,
    pub source: String,
    pub cost: f64,
    pub converted: bool,
}

// ---------------------------------------------------------------------------
// Error
// ---------------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum SalesError {
    #[error("lead not found: {0}")]
    LeadNotFound(Uuid),

    #[error("campaign not found: {0}")]
    CampaignNotFound(Uuid),

    #[error("event not found: {0}")]
    EventNotFound(Uuid),

    #[error("invalid input: {0}")]
    InvalidInput(String),

    #[error("enrichment failed: {0}")]
    EnrichmentFailed(String),

    #[error("max campaigns reached ({0})")]
    MaxCampaignsReached(usize),

    #[error("time slot unavailable")]
    SlotUnavailable,

    #[error(transparent)]
    Internal(#[from] anyhow::Error),
}

// Convenience: allow axum handlers to return SalesError as a 4xx/5xx.
impl axum::response::IntoResponse for SalesError {
    fn into_response(self) -> axum::response::Response {
        use axum::http::StatusCode;
        let (status, msg) = match &self {
            SalesError::LeadNotFound(_) | SalesError::CampaignNotFound(_) | SalesError::EventNotFound(_) => {
                (StatusCode::NOT_FOUND, self.to_string())
            }
            SalesError::InvalidInput(_) | SalesError::MaxCampaignsReached(_) | SalesError::SlotUnavailable => {
                (StatusCode::BAD_REQUEST, self.to_string())
            }
            SalesError::EnrichmentFailed(_) => (StatusCode::BAD_GATEWAY, self.to_string()),
            SalesError::Internal(_) => (StatusCode::INTERNAL_SERVER_ERROR, "internal error".into()),
        };
        (status, axum::Json(serde_json::json!({ "error": msg }))).into_response()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lead_status_display() {
        assert_eq!(LeadStatus::New.to_string(), "new");
        assert_eq!(LeadStatus::Contacted.to_string(), "contacted");
        assert_eq!(LeadStatus::Qualified.to_string(), "qualified");
        assert_eq!(LeadStatus::Converted.to_string(), "converted");
        assert_eq!(LeadStatus::Lost.to_string(), "lost");
    }

    #[test]
    fn test_campaign_status_serde_roundtrip() {
        for status in [CampaignStatus::Draft, CampaignStatus::Active, CampaignStatus::Paused, CampaignStatus::Completed] {
            let json = serde_json::to_string(&status).unwrap();
            let parsed: CampaignStatus = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed, status);
        }
    }

    #[test]
    fn test_lead_serialization() {
        let lead = Lead {
            id: Uuid::nil(),
            email: "alice@example.com".into(),
            name: "Alice".into(),
            company: "Acme".into(),
            title: "CTO".into(),
            score: 85,
            source: "product_hunt".into(),
            status: LeadStatus::New,
            created_at: Utc::now(),
        };
        let json = serde_json::to_value(&lead).unwrap();
        assert_eq!(json["email"], "alice@example.com");
        assert_eq!(json["score"], 85);
        assert_eq!(json["status"], "new");
    }

    #[test]
    fn test_sales_error_display() {
        let id = Uuid::nil();
        let err = SalesError::LeadNotFound(id);
        assert!(err.to_string().contains("lead not found"));
        let err2 = SalesError::InvalidInput("bad email".into());
        assert!(err2.to_string().contains("bad email"));
    }

    #[test]
    fn test_message_category_serde() {
        let cats = [
            MessageCategory::Lead,
            MessageCategory::Customer,
            MessageCategory::Support,
            MessageCategory::Spam,
            MessageCategory::Other,
        ];
        for cat in cats {
            let json = serde_json::to_string(&cat).unwrap();
            let parsed: MessageCategory = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed, cat);
        }
    }
}
