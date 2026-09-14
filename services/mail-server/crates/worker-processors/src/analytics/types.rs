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
    pub recipient: Option<String>,
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
        match event_type.parse::<EventType>() {
            Ok(EventType::Sent) => self.sent += 1,
            Ok(EventType::Delivered) => self.delivered += 1,
            Ok(EventType::Opened) => self.opened += 1,
            Ok(EventType::Clicked) => self.clicked += 1,
            Ok(EventType::Bounced) => self.bounced += 1,
            Ok(EventType::Unsubscribed) => self.unsubscribed += 1,
            Ok(EventType::Complained) => self.complained += 1,
            Ok(EventType::Failed) => self.failed += 1,
            Err(_) => {}
        }
    }

    /// Merge another period-aligned stats entry into this one (counter-wise
    /// addition). Used when restoring an aggregation buffer after a failed
    /// flush that raced with new events landing under the same keys.
    pub fn merge_from(&mut self, other: AggregatedStats) {
        self.sent += other.sent;
        self.delivered += other.delivered;
        self.opened += other.opened;
        self.clicked += other.clicked;
        self.bounced += other.bounced;
        self.unsubscribed += other.unsubscribed;
        self.complained += other.complained;
        self.failed += other.failed;
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

impl std::str::FromStr for EventType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "sent" => Ok(Self::Sent),
            "delivered" => Ok(Self::Delivered),
            "opened" => Ok(Self::Opened),
            "clicked" => Ok(Self::Clicked),
            "bounced" => Ok(Self::Bounced),
            "unsubscribed" => Ok(Self::Unsubscribed),
            "complained" => Ok(Self::Complained),
            "failed" => Ok(Self::Failed),
            _ => Err(format!("Unknown event type: {}", s)),
        }
    }
}

impl std::fmt::Display for EventType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_type_round_trips_every_variant_and_rejects_garbage() {
        let variants = [
            ("sent", EventType::Sent),
            ("delivered", EventType::Delivered),
            ("opened", EventType::Opened),
            ("clicked", EventType::Clicked),
            ("bounced", EventType::Bounced),
            ("unsubscribed", EventType::Unsubscribed),
            ("complained", EventType::Complained),
            ("failed", EventType::Failed),
        ];
        for (name, expected) in variants {
            assert_eq!(name.parse::<EventType>(), Ok(expected), "parse {name}");
            assert_eq!(expected.as_str(), name);
            assert_eq!(expected.to_string(), name);
        }
        assert!(
            "SENT".parse::<EventType>().is_err(),
            "the wire grammar is lower-case only"
        );
        let error = "bogus".parse::<EventType>().expect_err("refused");
        assert!(error.contains("bogus"), "error: {error}");
    }

    #[test]
    fn aggregation_increments_every_wire_event_type_once() {
        let start = Utc::now();
        let end = start + chrono::Duration::hours(1);
        let mut stats = AggregatedStats::new(
            "tenant-1".to_string(),
            Some("dom-1".to_string()),
            Some("camp-1".to_string()),
            start,
            end,
        );
        assert_eq!(stats.tenant_id, "tenant-1");
        assert_eq!(stats.domain_id.as_deref(), Some("dom-1"));
        assert_eq!(stats.campaign_id.as_deref(), Some("camp-1"));
        assert_eq!(stats.period_start, start);
        assert_eq!(stats.period_end, end);

        for event in [
            "sent",
            "delivered",
            "opened",
            "clicked",
            "bounced",
            "unsubscribed",
            "complained",
            "failed",
        ] {
            stats.increment(event);
        }
        assert_eq!(stats.sent, 1);
        assert_eq!(stats.delivered, 1);
        assert_eq!(stats.opened, 1);
        assert_eq!(stats.clicked, 1);
        assert_eq!(stats.bounced, 1);
        assert_eq!(stats.unsubscribed, 1);
        assert_eq!(stats.complained, 1);
        assert_eq!(stats.failed, 1);

        // Unknown event types are ignored (forward compatibility), while a
        // case-mismatched one is not silently folded in.
        stats.increment("not-a-real-event");
        stats.increment("Sent");
        assert_eq!(stats.sent, 1);
        assert_eq!(stats.failed, 1);
    }

    #[test]
    fn merge_from_adds_every_counter() {
        let mut base = AggregatedStats::default();
        let delta = AggregatedStats {
            sent: 1,
            delivered: 2,
            opened: 3,
            clicked: 4,
            bounced: 5,
            unsubscribed: 6,
            complained: 7,
            failed: 8,
            ..Default::default()
        };
        base.merge_from(delta);
        assert_eq!(
            (
                base.sent,
                base.delivered,
                base.opened,
                base.clicked,
                base.bounced,
                base.unsubscribed,
                base.complained,
                base.failed
            ),
            (1, 2, 3, 4, 5, 6, 7, 8)
        );
        // Merging again keeps the counters additive (restored buffers).
        base.merge_from(base.clone());
        assert_eq!(base.failed, 16);
    }
}
