//! Threat intelligence configuration

use serde::{Deserialize, Serialize};

/// Configuration for threat intelligence
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatIntelConfig {
    /// Default TTL for blocklist entries in seconds (default: 86400 = 24h)
    pub default_ttl_secs: u64,

    /// Maximum entries in IP blocklist (default: 1_000_000)
    pub max_ip_entries: usize,

    /// Maximum entries in domain blocklist (default: 500_000)
    pub max_domain_entries: usize,

    /// Score threshold for blocking (default: 7.0)
    pub block_threshold: f64,

    /// Score threshold for flagging (default: 4.0)
    pub flag_threshold: f64,

    /// Weight for IP reputation in composite score
    pub weight_ip: f64,

    /// Weight for domain reputation in composite score
    pub weight_domain: f64,

    /// Whether to auto-expire entries past TTL
    pub enable_ttl_expiration: bool,

    /// Feed source configurations
    pub feeds: Vec<FeedSource>,
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
            feeds: vec![
                FeedSource {
                    name: "Spamhaus DROP".into(),
                    url: "https://www.spamhaus.org/drop/drop.txt".into(),
                    format: FeedFormat::SpamhausDrop,
                    refresh_interval_secs: 3600,
                    enabled: true,
                },
                FeedSource {
                    name: "Spamhaus EDROP".into(),
                    url: "https://www.spamhaus.org/drop/edrop.txt".into(),
                    format: FeedFormat::SpamhausDrop,
                    refresh_interval_secs: 3600,
                    enabled: true,
                },
            ],
        }
    }
}
