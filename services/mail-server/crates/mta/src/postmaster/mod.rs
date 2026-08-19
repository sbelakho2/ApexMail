//! Sender reputation tracking — Google Postmaster Tools v1 and Microsoft SNDS.
//!
//! Persists raw daily snapshots, computes a normalised reputation score band
//! per (scope, identity), and emits events when a domain or IP transitions
//! between bands so downstream alerting and worker-processors throttling can
//! respond.
//!
//! ## Modules
//! * [`google`] — Postmaster Tools v1 client (OAuth2 + traffic-stats).
//! * [`snds`] — Microsoft Smart Network Data Services client (CSV ingest).
//! * [`aggregator`] — Recomputes `postmaster_reputation_summary` and emits
//!   `postmaster_reputation_events` on band transitions.
//! * [`scheduler`] — Periodic poller (fires every `interval_secs`).
//!
//! Schema lives in migration `040_postmaster_reputation.sql`.

pub mod aggregator;
pub mod google;
pub mod scheduler;
pub mod snds;

use chrono::{DateTime, NaiveDate, Utc};
use serde::{Deserialize, Serialize};

/// Three-tier reputation band used by aggregation, alerting, and throttling.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ReputationBand {
    Green,
    Amber,
    Red,
}

impl ReputationBand {
    pub fn from_score(score: i32) -> Self {
        match score {
            i if i >= 70 => Self::Green,
            i if i >= 40 => Self::Amber,
            _ => Self::Red,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Green => "green",
            Self::Amber => "amber",
            Self::Red => "red",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "green" => Some(Self::Green),
            "amber" => Some(Self::Amber),
            "red" => Some(Self::Red),
            _ => None,
        }
    }

    /// Suggested throttle percentage (0 = full speed, 100 = full pause).
    pub fn suggested_throttle_pct(self) -> i32 {
        match self {
            Self::Green => 0,
            Self::Amber => 50,
            Self::Red => 90,
        }
    }
}

/// One Google Postmaster Tools daily traffic stat row, persisted to DB.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GoogleReputation {
    pub domain: String,
    pub observed_at: NaiveDate,
    pub domain_reputation: Option<String>,
    pub ip_reputation: serde_json::Value,
    pub user_reported_spam_ratio: Option<f64>,
    pub spammy_feedback_loops: Option<serde_json::Value>,
    pub spf_success_ratio: Option<f64>,
    pub dkim_success_ratio: Option<f64>,
    pub dmarc_success_ratio: Option<f64>,
    pub inbound_encryption_ratio: Option<f64>,
    pub outbound_encryption_ratio: Option<f64>,
    pub delivery_errors: serde_json::Value,
    pub raw: serde_json::Value,
}

/// One Microsoft SNDS daily IP record, persisted to DB.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SndsRecord {
    pub ip: std::net::IpAddr,
    pub observed_at: NaiveDate,
    pub activity_start: Option<DateTime<Utc>>,
    pub activity_end: Option<DateTime<Utc>>,
    pub rcpt_commands: i64,
    pub data_commands: i64,
    pub message_recipients: i64,
    pub filter_result: Option<String>,
    pub complaint_rate: Option<f64>,
    pub trap_hits: i64,
    pub sample_helo: Option<String>,
    pub sample_from: Option<String>,
    pub raw: serde_json::Value,
}

/// Aggregated reputation summary for one (scope, identity, provider).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReputationSummary {
    pub scope: String,
    pub identity: String,
    pub provider: String,
    pub reputation_score: i32,
    pub band: ReputationBand,
    pub factors: Vec<String>,
    pub suggested_throttle_pct: i32,
    pub window_days: i32,
    pub computed_at: DateTime<Utc>,
}

/// Reputation event emitted on band transitions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReputationEvent {
    pub tenant_id: Option<String>,
    pub scope: String,
    pub identity: String,
    pub provider: String,
    pub severity: String,
    pub event_type: String,
    pub from_band: Option<String>,
    pub to_band: Option<String>,
    pub payload: serde_json::Value,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn band_score_thresholds() {
        assert_eq!(ReputationBand::from_score(100), ReputationBand::Green);
        assert_eq!(ReputationBand::from_score(70), ReputationBand::Green);
        assert_eq!(ReputationBand::from_score(69), ReputationBand::Amber);
        assert_eq!(ReputationBand::from_score(40), ReputationBand::Amber);
        assert_eq!(ReputationBand::from_score(39), ReputationBand::Red);
        assert_eq!(ReputationBand::from_score(0), ReputationBand::Red);
    }

    #[test]
    fn band_throttle() {
        assert_eq!(ReputationBand::Green.suggested_throttle_pct(), 0);
        assert_eq!(ReputationBand::Amber.suggested_throttle_pct(), 50);
        assert_eq!(ReputationBand::Red.suggested_throttle_pct(), 90);
    }

    #[test]
    fn band_round_trip() {
        for b in [
            ReputationBand::Green,
            ReputationBand::Amber,
            ReputationBand::Red,
        ] {
            assert_eq!(ReputationBand::parse(b.as_str()), Some(b));
        }
        assert_eq!(ReputationBand::parse("nope"), None);
    }
}
