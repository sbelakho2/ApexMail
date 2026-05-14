//! Threat intelligence configuration

use serde::{Deserialize, Serialize};

/// Configuration for threat intelligence
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ThreatIntelConfig {
    /// Default TTL for blocklist entries in seconds (default:86400 = 24h)
    pub default_ttl_secs: u64,

    /// Maximum entries in IP blocklist (default:1_000_000)
    pub max_ip_entries: usize,

    /// Maximum entries in domain blocklist (default:500_000)
    pub max_domain_entries: usize,

    /// Score threshold for blocking (default:7.0)
    pub block_threshold: f64,

    /// Score threshold for flagging (default:4.0)
    pub flag_threshold: f64,

    /// Weight for IP reputation in composite score
    pub weight_ip: f64,

    /// Weight for domain reputation in composite score
    pub weight_domain: f64,

    /// Whether to auto-expire entries past TTL
    pub enable_ttl_expiration: bool,

    /// Feed source configurations
    pub feeds: Vec<FeedSource>,

    /// Minimum trust required for a feed to be eligible for hard block decisions
    pub min_feed_trust_score: f64,

    /// When the total number of IP + domain entries exceeds this fraction of
    /// the configured maximums, trigger an immediate TTL purge instead of
    /// waiting for the next scheduled purge cycle (default:0.9 = 90%).
    pub purge_pressure_threshold: f64,
}

/// Feed enforcement mode.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum FeedEnforcementMode {
    /// Feed contributes to scoring, but can only produce FLAG outcomes.
    Monitor,
    /// Feed contributes fully and may produce BLOCK outcomes.
    Enforce,
}

/// A threat intelligence feed source
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeedSource {
    /// Human-readable name
    pub name: String,
    /// Feed URL
    pub url: String,
    /// Feed format
    pub format: FeedFormat,
    /// Refresh interval in seconds
    pub refresh_interval_secs: u64,
    /// Whether this feed is enabled
    pub enabled: bool,
    /// Feed trust score (0.0-10.0)
    pub trust_score: f64,
    /// Whether matches from this feed are monitor-only or enforceable
    pub enforcement_mode: FeedEnforcementMode,
}

/// Supported feed formats
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum FeedFormat {
    /// Spamhaus DROP format (CIDR ; SBL-ID)
    SpamhausDrop,
    /// Plain text, one IP/CIDR per line (comments start with #)
    PlainText,
    /// CSV with IP in first column
    CsvIp,
    /// JSON array of objects with "ip" field
    JsonIp,
    /// Plain text domain list
    DomainList,
}

impl Default for ThreatIntelConfig {
    fn default() -> Self {
        Self {
            default_ttl_secs: 86400,
            max_ip_entries: 1_000_000,
            max_domain_entries: 500_000,
            block_threshold: 7.0,
            flag_threshold: 4.0,
            weight_ip: 1.0,
            weight_domain: 1.0,
            enable_ttl_expiration: true,
            min_feed_trust_score: 6.0,
            purge_pressure_threshold: 0.9,
            feeds: vec![
                FeedSource {
                    name: "Spamhaus DROP".into(),
                    url: "https://www.spamhaus.org/drop/drop.txt".into(),
                    format: FeedFormat::SpamhausDrop,
                    refresh_interval_secs: 3600,
                    enabled: true,
                    trust_score: 9.5,
                    enforcement_mode: FeedEnforcementMode::Enforce,
                },
                FeedSource {
                    name: "Spamhaus EDROP".into(),
                    url: "https://www.spamhaus.org/drop/edrop.txt".into(),
                    format: FeedFormat::SpamhausDrop,
                    refresh_interval_secs: 3600,
                    enabled: true,
                    trust_score: 9.5,
                    enforcement_mode: FeedEnforcementMode::Enforce,
                },
                FeedSource {
                    name: "Spamhaus DBL".into(),
                    url: "https://www.spamhaus.org/drop/dbl.txt".into(),
                    format: FeedFormat::DomainList,
                    refresh_interval_secs: 3600,
                    enabled: true,
                    trust_score: 9.0,
                    enforcement_mode: FeedEnforcementMode::Enforce,
                },
                FeedSource {
                    name: "abuse.ch URLhaus".into(),
                    url: "https://urlhaus.abuse.ch/downloads/text/".into(),
                    format: FeedFormat::PlainText,
                    refresh_interval_secs: 900,
                    enabled: true,
                    trust_score: 8.0,
                    enforcement_mode: FeedEnforcementMode::Enforce,
                },
                FeedSource {
                    name: "abuse.ch ThreatFox IOCs".into(),
                    url: "https://threatfox.abuse.ch/downloads/hostfile/".into(),
                    format: FeedFormat::PlainText,
                    refresh_interval_secs: 1800,
                    enabled: true,
                    trust_score: 7.5,
                    enforcement_mode: FeedEnforcementMode::Monitor,
                },
            ],
        }
    }
}
