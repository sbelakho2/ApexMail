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

    #[error("database error: {0}")]
    Database(String),

    #[error("max campaigns reached ({0})")]
    MaxCampaignsReached(usize),

    #[error("time slot unavailable")]
    SlotUnavailable,

    #[error(transparent)]
    Internal(#[from] anyhow::Error),
}

// Convenience:allow axum handlers to return SalesError as a 4xx/5xx.
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
            SalesError::Database(_) | SalesError::Internal(_) => (StatusCode::INTERNAL_SERVER_ERROR, "internal error".into()),
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
    fn test_database_error_display() {
        let err = SalesError::Database("connection refused".into());
        assert!(err.to_string().contains("database error"));
        assert!(err.to_string().contains("connection refused"));
    }

    #[test]
    fn test_all_error_variants_display() {
        let id = Uuid::nil();
        let errors: Vec<SalesError> = vec![
            SalesError::LeadNotFound(id),
            SalesError::CampaignNotFound(id),
            SalesError::EventNotFound(id),
            SalesError::InvalidInput("bad".into()),
            SalesError::EnrichmentFailed("timeout".into()),
            SalesError::Database("pg error".into()),
            SalesError::MaxCampaignsReached(10),
            SalesError::SlotUnavailable,
        ];
        for err in &errors {
            let msg = err.to_string();
            assert!(!msg.is_empty(), "Error display should not be empty: {:?}", err);
        }
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

// -----------------------------------------------------------------------
// Additional comprehensive tests
// -----------------------------------------------------------------------

    #[test]
    fn lead_status_all_variants_round_trip() {
        for status in [
            LeadStatus::New,
            LeadStatus::Contacted,
            LeadStatus::Qualified,
            LeadStatus::Converted,
            LeadStatus::Lost,
        ] {
            let json = serde_json::to_string(&status).unwrap();
            let parsed: LeadStatus = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed, status);
// Display matches serde name
            let display = status.to_string();
            assert!(json.contains(&display));
        }
    }

    #[test]
    fn lead_status_display_values() {
        assert_eq!(LeadStatus::New.to_string(), "new");
        assert_eq!(LeadStatus::Contacted.to_string(), "contacted");
        assert_eq!(LeadStatus::Qualified.to_string(), "qualified");
        assert_eq!(LeadStatus::Converted.to_string(), "converted");
        assert_eq!(LeadStatus::Lost.to_string(), "lost");
    }

    #[test]
    fn campaign_status_display_values() {
        assert_eq!(CampaignStatus::Draft.to_string(), "draft");
        assert_eq!(CampaignStatus::Active.to_string(), "active");
        assert_eq!(CampaignStatus::Paused.to_string(), "paused");
        assert_eq!(CampaignStatus::Completed.to_string(), "completed");
    }

    #[test]
    fn lead_score_boundary() {
        let lead = Lead {
            id: Uuid::nil(),
            email: "x@x.com".into(),
            name: "X".into(),
            company: "".into(),
            title: "".into(),
            score: 0,
            source: "".into(),
            status: LeadStatus::New,
            created_at: Utc::now(),
        };
        assert_eq!(lead.score, 0);
        
        let lead_max = Lead { score: 100, ..lead.clone() };
        assert_eq!(lead_max.score, 100);
        
// u8 can hold 255 but semantically score is 0-100
        let lead_over = Lead { score: 255, ..lead };
        let json = serde_json::to_value(&lead_over).unwrap();
        assert_eq!(json["score"], 255);
    }

    #[test]
    fn lead_clone() {
        let lead = Lead {
            id: Uuid::new_v4(),
            email: "test@test.com".into(),
            name: "Test".into(),
            company: "TestCo".into(),
            title: "Dev".into(),
            score: 50,
            source: "web".into(),
            status: LeadStatus::Qualified,
            created_at: Utc::now(),
        };
        let cloned = lead.clone();
        assert_eq!(lead.id, cloned.id);
        assert_eq!(lead.email, cloned.email);
        assert_eq!(lead.status, cloned.status);
    }

    #[test]
    fn company_serde_roundtrip() {
        let company = Company {
            id: Uuid::new_v4(),
            name: "Acme".into(),
            domain: "acme.com".into(),
            industry: "tech".into(),
            size: "50-200".into(),
            revenue_range: "$1M-$10M".into(),
            enriched_at: Utc::now(),
        };
        let json = serde_json::to_string(&company).unwrap();
        let parsed: Company = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.name, "Acme");
        assert_eq!(parsed.domain, "acme.com");
    }

    #[test]
    fn campaign_serde_roundtrip() {
        let campaign = Campaign {
            id: Uuid::new_v4(),
            name: "Launch".into(),
            template_id: "tpl-1".into(),
            audience: "{}".into(),
            status: CampaignStatus::Active,
            sent: 1000,
            opened: 450,
            clicked: 120,
            created_at: Utc::now(),
        };
        let json = serde_json::to_string(&campaign).unwrap();
        let parsed: Campaign = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.name, "Launch");
        assert_eq!(parsed.status, CampaignStatus::Active);
        assert_eq!(parsed.sent, 1000);
    }

    #[test]
    fn calendar_event_with_and_without_meeting_link() {
        let with_link = CalendarEvent {
            id: Uuid::new_v4(),
            title: "Demo".into(),
            attendees: vec!["a@a.com".into()],
            start_at: Utc::now(),
            end_at: Utc::now(),
            meeting_link: Some("https://meet.example.com/abc".into()),
        };
        let json = serde_json::to_value(&with_link).unwrap();
        assert!(json["meeting_link"].is_string());

        let without_link = CalendarEvent {
            meeting_link: None,
            ..with_link
        };
        let json = serde_json::to_value(&without_link).unwrap();
        assert!(json["meeting_link"].is_null());
    }

    #[test]
    fn ad_click_serde() {
        let click = AdClick {
            id: Uuid::new_v4(),
            campaign_id: Uuid::new_v4(),
            source: "google".into(),
            cost: 1.50,
            converted: true,
        };
        let json = serde_json::to_string(&click).unwrap();
        let parsed: AdClick = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.source, "google");
        assert!(parsed.converted);
        assert!((parsed.cost - 1.50).abs() < f64::EPSILON);
    }

    #[test]
    fn inbox_message_serde() {
        let msg = InboxMessage {
            id: Uuid::new_v4(),
            from: "sender@test.com".into(),
            subject: "Hello".into(),
            received_at: Utc::now(),
            category: MessageCategory::Lead,
            replied: false,
        };
        let json = serde_json::to_string(&msg).unwrap();
        let parsed: InboxMessage = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.from, "sender@test.com");
        assert!(!parsed.replied);
    }
}
