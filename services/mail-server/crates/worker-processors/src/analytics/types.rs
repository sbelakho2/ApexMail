//! Types for the analytics processor.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;

/// An analytics event from the queue.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct AnalyticsEvent {
    pub id: String,
    #[sqlx(rename = "tenant_id")]
    pub tenant_id: String,
    #[sqlx(rename = "event_type")]
    pub event_type: String,
    #[sqlx(rename = "message_id")]
    pub message_id: Option<String>,
    #[sqlx(rename = "domain_id")]
    pub domain_id: Option<String>,
    #[sqlx(rename = "campaign_id")]
    pub campaign_id: Option<String>,
    #[sqlx(rename = "recipient_email")]
    pub recipient_email: Option<String>,
    pub metadata: Option<serde_json::Value>,
    pub timestamp: DateTime<Utc>,
}

/// Aggregated statistics for a time period.
#[derive(Debug, Clone, Default)]
pub struct AggregatedStats {
    pub tenant_id: String,
    pub domain_id: Option<String>,
    pub campaign_id: Option<String>,
    pub period_start: DateTime<Utc>,
    pub period_end: DateTime<Utc>,
    pub sent: i64,
    pub delivered: i64,
    pub opened: i64,
    pub clicked: i64,
    pub bounced: i64,
    pub unsubscribed: i64,
    pub complained: i64,
    pub failed: i64,
}

impl AggregatedStats {
    /// Create new stats for a tenant and period.
    pub fn new(
        tenant_id: String,
        domain_id: Option<String>,
        campaign_id: Option<String>,
        period_start: DateTime<Utc>,
        period_end: DateTime<Utc>,
    ) -> Self {
        Self {
            tenant_id,
            domain_id,
            campaign_id,
            period_start,
            period_end,
            ..Default::default()
        }
    }

    /// Increment the appropriate counter based on event type.
    pub fn increment(&mut self, event_type: &str) {
        match event_type {
            "sent" => self.sent += 1,
            "delivered" => self.delivered += 1,
            "opened" => self.opened += 1,
            "clicked" => self.clicked += 1,
            "bounced" => self.bounced += 1,
            "unsubscribed" => self.unsubscribed += 1,
            "complained" => self.complained += 1,
            "failed" => self.failed += 1,
            _ => {} // Ignore unknown event types
        }
    }
}

/// Event type enumeration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EventType {
    Sent,
    Delivered,
    Opened,
    Clicked,
    Bounced,
    Unsubscribed,
    Complained,
    Failed,
}

impl EventType {
    /// Parse from string.
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "sent" => Some(Self::Sent),
            "delivered" => Some(Self::Delivered),
            "opened" => Some(Self::Opened),
            "clicked" => Some(Self::Clicked),
            "bounced" => Some(Self::Bounced),
            "unsubscribed" => Some(Self::Unsubscribed),
            "complained" => Some(Self::Complained),
            "failed" => Some(Self::Failed),
            _ => None,
        }
    }

    /// Convert to string.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Sent => "sent",
            Self::Delivered => "delivered",
            Self::Opened => "opened",
            Self::Clicked => "clicked",
            Self::Bounced => "bounced",
            Self::Unsubscribed => "unsubscribed",
            Self::Complained => "complained",
            Self::Failed => "failed",
        }
    }
}
