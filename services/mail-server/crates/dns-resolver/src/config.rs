//! DNS resolver configuration.

use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Maximum TTL ceiling in seconds (24 hours = 86400).
/// Any TTL exceeding this value is capped to this ceiling to prevent
/// stale records from being served indefinitely (MI-005).
pub const DNS_MAX_TTL_CEILING_SECS: u64 = 86_400;

/// DNS resolver configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsConfig {
    /// Cache TTL in seconds. Default:300 (5 minutes).
    /// This is the *configured* TTL; the effective cache TTL is capped
    /// at [`DNS_MAX_TTL_CEILING_SECS`] (24h) to prevent stale records.
    pub cache_ttl_secs: u64,
    /// Maximum cache entries. Default:10,000.
    pub max_cache_entries: u64,
    /// Negative cache TTL (for NXDOMAIN). Default:60.
    pub negative_ttl_secs: u64,
    /// Query timeout in milliseconds. Default:5,000.
    pub query_timeout_ms: u64,
    /// Number of retry attempts. Default:2.
    pub retries: u32,
    /// Whether to use TCP fallback. Default:true.
    pub tcp_fallback: bool,
    /// Custom nameservers. Empty = system defaults.
    pub nameservers: Vec<String>,
    /// Maximum TTL ceiling in seconds (default: 86400 = 24h).
    /// Prevents stale DNS records from being served indefinitely.
    pub max_ttl_ceiling_secs: u64,
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
            max_ttl_ceiling_secs: DNS_MAX_TTL_CEILING_SECS,
        }
    }
}

impl DnsConfig {
    pub fn validate(&self) -> Result<(), String> {
        if self.cache_ttl_secs == 0 {
            return Err("cache_ttl_secs must be > 0".into());
        }
        if self.max_cache_entries == 0 {
            return Err("max_cache_entries must be > 0".into());
        }
        if self.negative_ttl_secs == 0 {
            return Err("negative_ttl_secs must be > 0".into());
        }
        if self.query_timeout_ms == 0 {
            return Err("query_timeout_ms must be > 0".into());
        }
        if self.max_ttl_ceiling_secs < 60 {
            return Err("max_ttl_ceiling_secs must be at least 60".into());
        }
        Ok(())
    }

    /// Returns the effective cache TTL, capped at the configured ceiling.
    pub fn cache_ttl(&self) -> Duration {
        let ttl = self.cache_ttl_secs.min(self.max_ttl_ceiling_secs);
        Duration::from_secs(ttl)
    }

    /// Returns the effective negative TTL, capped at the configured ceiling.
    pub fn negative_ttl(&self) -> Duration {
        let ttl = self.negative_ttl_secs.min(self.max_ttl_ceiling_secs);
        Duration::from_secs(ttl)
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
        assert_eq!(cfg.max_ttl_ceiling_secs, DNS_MAX_TTL_CEILING_SECS);
    }

    #[test]
    fn test_durations() {
        let cfg = DnsConfig::default();
        assert_eq!(cfg.cache_ttl(), Duration::from_secs(300));
        assert_eq!(cfg.negative_ttl(), Duration::from_secs(60));
        assert_eq!(cfg.query_timeout(), Duration::from_millis(5000));
    }

    #[test]
    fn test_ttl_capped_at_ceiling() {
        let cfg = DnsConfig {
            cache_ttl_secs: 200_000, // well over 24h
            max_ttl_ceiling_secs: 86_400,
            ..Default::default()
        };
        // Should be capped to ceiling
        assert_eq!(cfg.cache_ttl(), Duration::from_secs(86_400));
    }

    #[test]
    fn test_ttl_under_ceiling_not_capped() {
        let cfg = DnsConfig {
            cache_ttl_secs: 300,
            max_ttl_ceiling_secs: 86_400,
            ..Default::default()
        };
        assert_eq!(cfg.cache_ttl(), Duration::from_secs(300));
    }

    #[test]
    fn test_negative_ttl_capped() {
        let cfg = DnsConfig {
            negative_ttl_secs: 200_000,
            max_ttl_ceiling_secs: 86_400,
            ..Default::default()
        };
        assert_eq!(cfg.negative_ttl(), Duration::from_secs(86_400));
    }

    #[test]
    fn test_validate_rejects_low_ceiling() {
        let cfg = DnsConfig {
            max_ttl_ceiling_secs: 30,
            ..Default::default()
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn test_serialization() {
        let cfg = DnsConfig::default();
        let json = serde_json::to_string(&cfg).unwrap();
        let parsed: DnsConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.cache_ttl_secs, 300);
        assert_eq!(parsed.max_ttl_ceiling_secs, DNS_MAX_TTL_CEILING_SECS);
    }
}
