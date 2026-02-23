//! Rate limiter configuration types.

use serde::{Deserialize, Serialize};
use std::num::NonZeroU32;
use std::time::Duration;

/// Configuration for a governor-based rate limiter.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitConfig {
    /// Maximum sustained requests per second.
    pub requests_per_second: NonZeroU32,
    /// Burst capacity (tokens available immediately). Defaults to `requests_per_second`.
    pub burst_size: Option<NonZeroU32>,
    /// Optional jitter range applied to retry-after. Reduces thundering herd.
    pub jitter_ms: Option<u64>,
}

impl RateLimitConfig {
    pub fn new(rps: u32) -> Self {
        Self {
            requests_per_second: NonZeroU32::new(rps).expect("rps must be > 0"),
            burst_size: None,
            jitter_ms: None,
        }
    }

    pub fn with_burst(mut self, burst: u32) -> Self {
        self.burst_size = Some(NonZeroU32::new(burst).expect("burst must be > 0"));
        self
    }

    pub fn with_jitter(mut self, jitter_ms: u64) -> Self {
        self.jitter_ms = Some(jitter_ms);
        self
    }

    pub fn effective_burst(&self) -> NonZeroU32 {
        self.burst_size.unwrap_or(self.requests_per_second)
    }

    pub fn jitter_duration(&self) -> Option<Duration> {
        self.jitter_ms.map(Duration::from_millis)
    }
}

/// Configuration for a sliding window counter.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlidingWindowConfig {
    /// Window duration in milliseconds.
    pub window_ms: u64,
    /// Maximum number of events allowed in the window.
    pub max_events: u64,
    /// Key prefix for namespacing (optional).
    pub key_prefix: Option<String>,
}

impl SlidingWindowConfig {
    pub fn new(window: Duration, max_events: u64) -> Self {
        Self {
            window_ms: window.as_millis() as u64,
            max_events,
            key_prefix: None,
        }
    }

    pub fn per_minute(max_events: u64) -> Self {
        Self::new(Duration::from_secs(60), max_events)
    }

    pub fn per_hour(max_events: u64) -> Self {
        Self::new(Duration::from_secs(3600), max_events)
    }
}

/// Configuration for keyed (multi-tenant) rate limiter.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyedConfig {
    /// Config per key.
    pub per_key: RateLimitConfig,
    /// Maximum number of keys to track. Old keys evicted on overflow.
    pub max_keys: usize,
    /// Cleanup interval for expired entries.
    pub cleanup_interval_secs: u64,
}

impl Default for KeyedConfig {
    fn default() -> Self {
        Self {
            per_key: RateLimitConfig::new(100),
            max_keys: 10_000,
            cleanup_interval_secs: 60,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rate_limit_config_builder() {
        let cfg = RateLimitConfig::new(50).with_burst(200).with_jitter(100);
        assert_eq!(cfg.requests_per_second.get(), 50);
        assert_eq!(cfg.effective_burst().get(), 200);
        assert_eq!(cfg.jitter_duration(), Some(Duration::from_millis(100)));
    }

    #[test]
    fn test_rate_limit_config_defaults() {
        let cfg = RateLimitConfig::new(100);
        assert_eq!(cfg.effective_burst().get(), 100);
        assert!(cfg.jitter_duration().is_none());
    }

    #[test]
    fn test_sliding_window_per_minute() {
        let cfg = SlidingWindowConfig::per_minute(1000);
        assert_eq!(cfg.window_ms, 60_000);
        assert_eq!(cfg.max_events, 1000);
    }

    #[test]
    fn test_sliding_window_per_hour() {
        let cfg = SlidingWindowConfig::per_hour(5000);
        assert_eq!(cfg.window_ms, 3_600_000);
        assert_eq!(cfg.max_events, 5000);
    }

    #[test]
    fn test_keyed_config_default() {
        let cfg = KeyedConfig::default();
        assert_eq!(cfg.per_key.requests_per_second.get(), 100);
        assert_eq!(cfg.max_keys, 10_000);
    }

    #[test]
    fn test_config_serialization() {
        let cfg = RateLimitConfig::new(50).with_burst(200);
        let json = serde_json::to_string(&cfg).unwrap();
        let parsed: RateLimitConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.requests_per_second.get(), 50);
        assert_eq!(parsed.effective_burst().get(), 200);
    }
}
