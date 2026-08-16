use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Enums
// ---------------------------------------------------------------------------

/// Status of a lead as it progresses through the sales funnel.
///
/// `Snoozed` and `Interested` are written by the reply-handling workers
/// (e.g. out-of-office replies snooze a lead, positive replies mark it
/// interested) and must round-trip through the database.
///
/// `Unknown` is used when reading a status value that this service does
/// not recognise; the original value is preserved so it round-trips
/// instead of being silently coerced to `New`.
///
/// Note: not `Copy` because `Unknown` carries a `String`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LeadStatus {
    New,
    Contacted,
    Qualified,
    Converted,
    Lost,
    Snoozed,
    Interested,
    Unknown(String),
}

impl std::fmt::Display for LeadStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::New => write!(f, "new"),
            Self::Contacted => write!(f, "contacted"),
            Self::Qualified => write!(f, "qualified"),
            Self::Converted => write!(f, "converted"),
            Self::Lost => write!(f, "lost"),
            Self::Snoozed => write!(f, "snoozed"),
            Self::Interested => write!(f, "interested"),
            // Preserve the original value so Display round-trips with parse.
            Self::Unknown(raw) => write!(f, "{raw}"),
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

impl std::fmt::Display for MessageCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Lead => write!(f, "lead"),
            Self::Customer => write!(f, "customer"),
            Self::Support => write!(f, "support"),
            Self::Spam => write!(f, "spam"),
            Self::Other => write!(f, "other"),
        }
    }
}

impl MessageCategory {
    /// Parse a message category from its snake_case string representation.
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Self {
        match s {
            "lead" => Self::Lead,
            "customer" => Self::Customer,
            "support" => Self::Support,
            "spam" => Self::Spam,
            _ => Self::Other,
        }
    }
}

// ---------------------------------------------------------------------------
// Core domain structs
// ---------------------------------------------------------------------------

/// A sales lead tracked in the CRM.
///
/// The id is a `String` because leads are created by several services with
/// different identifier formats (UUID here, `lead_<timestamp>` in api-server,
/// nanoid/ULID elsewhere); the storage column is TEXT.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Lead {
    pub id: String,
    pub tenant_id: String,
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
    pub tenant_id: String,
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
    pub tenant_id: String,
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
    pub tenant_id: String,
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

/// A tracked conversion attributed to a specific campaign and lead (SALES-03).
///
/// Ties a lead's conversion event back to the campaign that drove it,
/// enabling ROI analysis and attribution reporting.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Conversion {
    pub id: Uuid,
    pub tenant_id: String,
    pub campaign_id: Uuid,
    pub lead_id: Uuid,
    /// Revenue attributed to this conversion (e.g., deal value in USD).
    pub revenue: f64,
    /// Description of the conversion event (e.g., "signed contract", "demo booked").
    pub description: String,
    pub converted_at: DateTime<Utc>,
}

// ---------------------------------------------------------------------------
// Conversion tracking types (SALES-03)
// ---------------------------------------------------------------------------

/// Request body for recording a conversion.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateConversionBody {
    pub campaign_id: Uuid,
    pub lead_id: Uuid,
    #[serde(default)]
    pub revenue: f64,
    #[serde(default)]
    pub description: String,
}

// ---------------------------------------------------------------------------
// Error
// ---------------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SalesError {
    #[error("lead not found: {0}")]
    LeadNotFound(String),

    #[error("lead already exists for tenant: {0}")]
    LeadAlreadyExists(String),

    #[error("campaign not found: {0}")]
    CampaignNotFound(Uuid),

    #[error("event not found: {0}")]
    EventNotFound(Uuid),

    #[error("inbox message not found: {0}")]
    MessageNotFound(Uuid),

    #[error("conversion not found: {0}")]
    ConversionNotFound(Uuid),

    #[error("invalid input: {0}")]
    InvalidInput(String),

    #[error("enrichment failed: {0}")]
    EnrichmentFailed(String),

    #[error("rate limited: {0}")]
    RateLimited(String),

    #[error("database error: {0}")]
    Database(String),

    #[error("max campaigns reached ({0})")]
    MaxCampaignsReached(usize),

    #[error("time slot unavailable")]
    SlotUnavailable,

    #[error("unauthorized: {0}")]
    Unauthorized(String),

    #[error(transparent)]
    Internal(#[from] anyhow::Error),
}

// Convenience:allow axum handlers to return SalesError as a 4xx/5xx.
impl axum::response::IntoResponse for SalesError {
    fn into_response(self) -> axum::response::Response {
        use axum::http::StatusCode;
        let (status, msg) = match &self {
            SalesError::LeadNotFound(_) => (StatusCode::NOT_FOUND, self.to_string()),
            SalesError::LeadAlreadyExists(_) => (StatusCode::CONFLICT, self.to_string()),
            SalesError::CampaignNotFound(_)
            | SalesError::EventNotFound(_)
            | SalesError::MessageNotFound(_)
            | SalesError::ConversionNotFound(_) => (StatusCode::NOT_FOUND, self.to_string()),
            SalesError::InvalidInput(_)
            | SalesError::MaxCampaignsReached(_)
            | SalesError::SlotUnavailable => (StatusCode::BAD_REQUEST, self.to_string()),
            SalesError::EnrichmentFailed(_) => (StatusCode::BAD_GATEWAY, self.to_string()),
            SalesError::RateLimited(_) => (StatusCode::TOO_MANY_REQUESTS, self.to_string()),
            SalesError::Unauthorized(_) => (StatusCode::FORBIDDEN, self.to_string()),
            SalesError::Database(_) | SalesError::Internal(_) => {
                (StatusCode::INTERNAL_SERVER_ERROR, "internal error".into())
            }
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
        assert_eq!(LeadStatus::Snoozed.to_string(), "snoozed");
        assert_eq!(LeadStatus::Interested.to_string(), "interested");
        assert_eq!(
            LeadStatus::Unknown("custom_status".into()).to_string(),
            "custom_status"
        );
    }

    #[test]
    fn test_campaign_status_serde_roundtrip() {
        for status in [
            CampaignStatus::Draft,
            CampaignStatus::Active,
            CampaignStatus::Paused,
            CampaignStatus::Completed,
        ] {
            let json = serde_json::to_string(&status).unwrap();
            let parsed: CampaignStatus = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed, status);
        }
    }

    #[test]
    fn test_lead_serialization() {
        let lead = Lead {
            id: "06b6b0e0-8c7f-4a1e-9d3a-2f0d5c9b1e64".into(),
            tenant_id: "tenant-a".into(),
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
        assert_eq!(json["id"], "06b6b0e0-8c7f-4a1e-9d3a-2f0d5c9b1e64");
        assert_eq!(json["email"], "alice@example.com");
        assert_eq!(json["score"], 85);
        assert_eq!(json["status"], "new");
    }

    #[test]
    fn test_lead_serialization_preserves_non_uuid_id() {
        // Leads created by other services use non-UUID id formats (nanoid,
        // ULID, "lead_<ts>"); they must survive a serde round-trip intact.
        let lead = Lead {
            id: "lead_1739612345678".into(),
            tenant_id: "system".into(),
            email: "x@example.com".into(),
            name: "X".into(),
            company: "".into(),
            title: "".into(),
            score: 5,
            source: "contact_form".into(),
            status: LeadStatus::New,
            created_at: Utc::now(),
        };
        let json = serde_json::to_string(&lead).unwrap();
        let parsed: Lead = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.id, "lead_1739612345678");
    }

    #[test]
    fn test_sales_error_display() {
        let err = SalesError::LeadNotFound("missing".into());
        assert!(err.to_string().contains("lead not found"));
        let err2 = SalesError::InvalidInput("bad email".into());
        assert!(err2.to_string().contains("bad email"));
        let err3 = SalesError::LeadAlreadyExists("alice@acme.com".into());
        assert!(err3.to_string().contains("lead already exists"));
    }

    #[test]
    fn test_database_error_display() {
        let err = SalesError::Database("connection refused".into());
        assert!(err.to_string().contains("database error"));
        assert!(err.to_string().contains("connection refused"));
    }

    #[test]
    fn test_all_error_variants_display() {
        let errors: Vec<SalesError> = vec![
            SalesError::LeadNotFound("id".into()),
            SalesError::LeadAlreadyExists("alice@acme.com".into()),
            SalesError::CampaignNotFound(Uuid::nil()),
            SalesError::EventNotFound(Uuid::nil()),
            SalesError::MessageNotFound(Uuid::nil()),
            SalesError::InvalidInput("bad".into()),
            SalesError::EnrichmentFailed("timeout".into()),
            SalesError::RateLimited("too many requests".into()),
            SalesError::Database("pg error".into()),
            SalesError::MaxCampaignsReached(10),
            SalesError::SlotUnavailable,
        ];
        for err in &errors {
            let msg = err.to_string();
            assert!(
                !msg.is_empty(),
                "Error display should not be empty: {:?}",
                err
            );
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
            LeadStatus::Snoozed,
            LeadStatus::Interested,
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
        assert_eq!(LeadStatus::Snoozed.to_string(), "snoozed");
        assert_eq!(LeadStatus::Interested.to_string(), "interested");
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
            id: "lead-1".into(),
            tenant_id: "tenant-a".into(),
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

        let lead_max = Lead {
            score: 100,
            ..lead.clone()
        };
        assert_eq!(lead_max.score, 100);

        // u8 can hold 255 but semantically score is 0-100
        let lead_over = Lead { score: 255, ..lead };
        let json = serde_json::to_value(&lead_over).unwrap();
        assert_eq!(json["score"], 255);
    }

    #[test]
    fn lead_clone() {
        let lead = Lead {
            id: Uuid::new_v4().to_string(),
            tenant_id: "tenant-a".into(),
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
            tenant_id: "tenant-a".into(),
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
        assert_eq!(parsed.tenant_id, "tenant-a");
        assert_eq!(parsed.name, "Launch");
        assert_eq!(parsed.status, CampaignStatus::Active);
        assert_eq!(parsed.sent, 1000);
    }

    #[test]
    fn calendar_event_with_and_without_meeting_link() {
        let with_link = CalendarEvent {
            id: Uuid::new_v4(),
            tenant_id: "tenant-a".into(),
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
            tenant_id: "tenant-1".into(),
            from: "sender@test.com".into(),
            subject: "Hello".into(),
            received_at: Utc::now(),
            category: MessageCategory::Lead,
            replied: false,
        };
        let json = serde_json::to_string(&msg).unwrap();
        let parsed: InboxMessage = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.from, "sender@test.com");
        assert_eq!(parsed.tenant_id, "tenant-1");
        assert!(!parsed.replied);
    }
}
