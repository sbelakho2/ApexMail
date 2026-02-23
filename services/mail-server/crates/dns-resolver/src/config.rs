//! DNS resolver configuration.

use serde::{Deserialize, Serialize};
use std::time::Duration;

/// DNS resolver configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsConfig {
    /// Cache TTL in seconds. Default: 300 (5 minutes).
    pub cache_ttl_secs: u64,
    /// Maximum cache entries. Default: 10,000.
    pub max_cache_entries: u64,
    /// Negative cache TTL (for NXDOMAIN). Default: 60.
    pub negative_ttl_secs: u64,
    /// Query timeout in milliseconds. Default: 5,000.
    pub query_timeout_ms: u64,
    /// Number of retry attempts. Default: 2.
    pub retries: u32,
    /// Whether to use TCP fallback. Default: true.
    pub tcp_fallback: bool,
    /// Custom nameservers. Empty = system defaults.
    pub nameservers: Vec<String>,
}

impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            cache_ttl_secs: 300,
            max_cache_entries: 10_000,
            negative_ttl_secs: 60,
            query_timeout_ms: 5_000,
            retries: 2,
            tcp_fallback: true,
            nameservers: Vec::new(),
        }
    }
}

impl DnsConfig {
    pub fn cache_ttl(&self) -> Duration {
        Duration::from_secs(self.cache_ttl_secs)
    }

    pub fn negative_ttl(&self) -> Duration {
        Duration::from_secs(self.negative_ttl_secs)
    }

    pub fn query_timeout(&self) -> Duration {
        Duration::from_millis(self.query_timeout_ms)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let cfg = DnsConfig::default();
        assert_eq!(cfg.cache_ttl_secs, 300);
        assert_eq!(cfg.max_cache_entries, 10_000);
        assert_eq!(cfg.retries, 2);
        assert!(cfg.tcp_fallback);
        assert!(cfg.nameservers.is_empty());
    }

    #[test]
    fn test_durations() {
        let cfg = DnsConfig::default();
        assert_eq!(cfg.cache_ttl(), Duration::from_secs(300));
        assert_eq!(cfg.negative_ttl(), Duration::from_secs(60));
        assert_eq!(cfg.query_timeout(), Duration::from_millis(5000));
    }

    #[test]
    fn test_serialization() {
        let cfg = DnsConfig::default();
        let json = serde_json::to_string(&cfg).unwrap();
        let parsed: DnsConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.cache_ttl_secs, 300);
    }
}
