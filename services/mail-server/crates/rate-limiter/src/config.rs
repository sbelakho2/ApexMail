//! Rate limiter configuration types.
//!
//! All values can be overridden via environment variables at runtime:
//!
//! | Variable | Default | Description |
//! |----------|---------|-------------|
//! | `RATE_LIMITER_RPS` | `100` | Default requests per second |
//! | `RATE_LIMITER_BURST` | `(same as RPS)` | Burst capacity |
//! | `RATE_LIMITER_JITTER_MS` | (none) | Jitter in ms for retry-after |
//! | `RATE_LIMITER_MAX_KEYS` | `10000` | Max tracked tenant keys |
//! | `RATE_LIMITER_CLEANUP_SECS` | `60` | Stale key eviction interval |
//! | `RATE_LIMITER_SLIDING_WINDOW_MS` | `60000` | Sliding window duration |
//! | `RATE_LIMITER_SLIDING_MAX_EVENTS` | `1000` | Max events per window |
//! | `RATE_LIMIT_BACKEND` | `in_memory` | Backend selection (`in_memory` / `redis`) |
//! | `RATE_LIMIT_REDIS_URL` | (none) | Redis connection URL (required for `redis` backend) |
//! | `RATE_LIMIT_REDIS_KEY_PREFIX` | `ratelimit:` | Key prefix for Redis keys |

use serde::{Deserialize, Serialize};
use std::env;
use std::num::NonZeroU32;
use std::time::Duration;

/// Which backend to use for rate limiting.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum RateLimitBackend {
    /// In-memory rate limiting (per-pod, no distributed state).
    #[default]
    InMemory,
    /// Redis-backed distributed rate limiting (shared across all pods).
    Redis,
}

/// Configuration for a governor-based rate limiter.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RateLimitConfig {
    /// Maximum sustained requests per second.
    pub requests_per_second: NonZeroU32,
    /// Burst capacity (tokens available immediately). Defaults to `requests_per_second`.
    pub burst_size: Option<NonZeroU32>,
    /// Optional jitter range applied to retry-after. Reduces thundering herd.
    pub jitter_ms: Option<u64>,
    /// Backend selection (in-memory or Redis).
    #[serde(default)]
    pub backend: RateLimitBackend,
    /// Redis connection URL (required if `backend` is `Redis`).
    pub redis_url: Option<String>,
    /// Key prefix for Redis keys. Default: `"ratelimit:"`.
    #[serde(default = "default_redis_key_prefix")]
    pub redis_key_prefix: String,
}

fn default_redis_key_prefix() -> String {
    "ratelimit:".to_string()
}

fn nonzero_or_min(value: u32) -> NonZeroU32 {
    NonZeroU32::new(value).unwrap_or(NonZeroU32::MIN)
}

impl RateLimitConfig {
    pub fn new(rps: u32) -> Self {
        Self {
            requests_per_second: nonzero_or_min(rps),
            burst_size: None,
            jitter_ms: None,
            backend: RateLimitBackend::default(),
            redis_url: None,
            redis_key_prefix: default_redis_key_prefix(),
        }
    }

    pub fn with_burst(mut self, burst: u32) -> Self {
        self.burst_size = Some(nonzero_or_min(burst));
        self
    }

    pub fn with_jitter(mut self, jitter_ms: u64) -> Self {
        self.jitter_ms = Some(jitter_ms);
        self
    }

    /// Select a backend for this configuration.
    pub fn with_backend(mut self, backend: RateLimitBackend) -> Self {
        self.backend = backend;
        self
    }

    /// Set the Redis connection URL.
    pub fn with_redis_url(mut self, url: &str) -> Self {
        self.redis_url = Some(url.to_string());
        self
    }

    /// Set the Redis key prefix.
    pub fn with_redis_key_prefix(mut self, prefix: &str) -> Self {
        self.redis_key_prefix = prefix.to_string();
        self
    }

    /// Build a `RateLimitConfig` from environment variables prefixed with
    /// `RATE_LIMITER_`. Falls back to defaults when vars are unset.
    ///
    /// | Variable | Default |
    /// |----------|---------|
    /// | `RATE_LIMITER_RPS` | `100` |
    /// | `RATE_LIMITER_BURST` | (same as RPS) |
    /// | `RATE_LIMITER_JITTER_MS` | (none) |
    /// | `RATE_LIMIT_BACKEND` | `in_memory` |
    /// | `RATE_LIMIT_REDIS_URL` | (none) |
    /// | `RATE_LIMIT_REDIS_KEY_PREFIX` | `ratelimit:` |
    pub fn from_env() -> Self {
        let rps = env::var("RATE_LIMITER_RPS")
            .ok()
            .and_then(|v| v.parse::<u32>().ok())
            .unwrap_or(100);

        let burst = env::var("RATE_LIMITER_BURST")
            .ok()
            .and_then(|v| v.parse::<u32>().ok());

        let jitter_ms = env::var("RATE_LIMITER_JITTER_MS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok());

        let backend = env::var("RATE_LIMIT_BACKEND")
            .ok()
            .map(|v| match v.to_lowercase().as_str() {
                "redis" => RateLimitBackend::Redis,
                _ => RateLimitBackend::InMemory,
            })
            .unwrap_or_default();

        let redis_url = env::var("RATE_LIMIT_REDIS_URL").ok();

        let redis_key_prefix =
            env::var("RATE_LIMIT_REDIS_KEY_PREFIX").unwrap_or_else(|_| default_redis_key_prefix());

        let mut cfg = Self {
            requests_per_second: nonzero_or_min(rps),
            burst_size: burst.map(nonzero_or_min),
            jitter_ms,
            backend,
            redis_url,
            redis_key_prefix,
        };
        if let Some(j) = jitter_ms {
            cfg = cfg.with_jitter(j);
        }
        cfg
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
#[serde(deny_unknown_fields)]
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

    /// Build a `SlidingWindowConfig` from environment variables.
    ///
    /// | Variable | Default |
    /// |----------|---------|
    /// | `RATE_LIMITER_SLIDING_WINDOW_MS` | `60000` |
    /// | `RATE_LIMITER_SLIDING_MAX_EVENTS` | `1000` |
    pub fn from_env() -> Self {
        let window_ms = env::var("RATE_LIMITER_SLIDING_WINDOW_MS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(60_000);

        let max_events = env::var("RATE_LIMITER_SLIDING_MAX_EVENTS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(1_000);

        Self {
            window_ms,
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
#[serde(deny_unknown_fields)]
pub struct KeyedConfig {
    /// Config per key.
    pub per_key: RateLimitConfig,
    /// Maximum number of keys to track. Old keys evicted on overflow.
    pub max_keys: usize,
    /// Cleanup interval for expired entries.
    pub cleanup_interval_secs: u64,
    /// Cooldown during which a key that was LRU-evicted re-enters with an
    /// EMPTY burst budget (prevents budget-reset abuse via key rotation).
    /// Zero uses the crate default (60s).
    #[serde(default)]
    pub eviction_tombstone_ttl_secs: u64,
}

impl Default for KeyedConfig {
    fn default() -> Self {
        Self {
            per_key: RateLimitConfig::new(100),
            max_keys: 10_000,
            cleanup_interval_secs: 60,
            eviction_tombstone_ttl_secs: 60,
        }
    }
}

impl KeyedConfig {
    /// Effective tombstone cooldown (default 60s when unset/zero).
    pub fn effective_tombstone_ttl(&self) -> std::time::Duration {
        if self.eviction_tombstone_ttl_secs == 0 {
            std::time::Duration::from_secs(60)
        } else {
            std::time::Duration::from_secs(self.eviction_tombstone_ttl_secs)
        }
    }
}

impl KeyedConfig {
    /// Build a `KeyedConfig` from environment variables.
    /// Uses `RateLimitConfig::from_env()` for the per-key settings.
    ///
    /// | Variable | Default |
    /// |----------|---------|
    /// | `RATE_LIMITER_MAX_KEYS` | `10000` |
    /// | `RATE_LIMITER_CLEANUP_SECS` | `60` |
    /// | `RATE_LIMITER_TOMBSTONE_TTL_SECS` | `60` |
    pub fn from_env() -> Self {
        let max_keys = env::var("RATE_LIMITER_MAX_KEYS")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(10_000);

        let cleanup_interval_secs = env::var("RATE_LIMITER_CLEANUP_SECS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(60);

        let eviction_tombstone_ttl_secs = env::var("RATE_LIMITER_TOMBSTONE_TTL_SECS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(60);

        Self {
            per_key: RateLimitConfig::from_env(),
            max_keys,
            cleanup_interval_secs,
            eviction_tombstone_ttl_secs,
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
        assert_eq!(cfg.backend, RateLimitBackend::InMemory);
        assert_eq!(cfg.redis_key_prefix, "ratelimit:");
        assert!(cfg.redis_url.is_none());
    }

    #[test]
    fn test_backend_in_memory_default() {
        assert_eq!(RateLimitBackend::default(), RateLimitBackend::InMemory);
    }

    #[test]
    fn test_backend_serialization() {
        let in_memory = serde_json::to_string(&RateLimitBackend::InMemory).unwrap();
        assert_eq!(in_memory, "\"in_memory\"");

        let redis = serde_json::to_string(&RateLimitBackend::Redis).unwrap();
        assert_eq!(redis, "\"redis\"");
    }

    #[test]
    fn test_backend_deserialization() {
        let in_memory: RateLimitBackend = serde_json::from_str("\"in_memory\"").unwrap();
        assert_eq!(in_memory, RateLimitBackend::InMemory);

        let redis: RateLimitBackend = serde_json::from_str("\"redis\"").unwrap();
        assert_eq!(redis, RateLimitBackend::Redis);
    }

    #[test]
    fn test_config_with_backend() {
        let cfg = RateLimitConfig::new(50)
            .with_backend(RateLimitBackend::Redis)
            .with_redis_url("redis://localhost:6379")
            .with_redis_key_prefix("myprefix:");

        assert_eq!(cfg.backend, RateLimitBackend::Redis);
        assert_eq!(cfg.redis_url, Some("redis://localhost:6379".to_string()));
        assert_eq!(cfg.redis_key_prefix, "myprefix:");
    }

    #[test]
    fn test_config_serialization_with_redis() {
        let cfg = RateLimitConfig::new(50)
            .with_burst(200)
            .with_backend(RateLimitBackend::Redis)
            .with_redis_url("redis://redis:6379");

        let json = serde_json::to_string(&cfg).unwrap();
        let parsed: RateLimitConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.requests_per_second.get(), 50);
        assert_eq!(parsed.effective_burst().get(), 200);
        assert_eq!(parsed.backend, RateLimitBackend::Redis);
        assert_eq!(parsed.redis_url, Some("redis://redis:6379".to_string()));
        assert_eq!(parsed.redis_key_prefix, "ratelimit:");
    }

    /// Serializes all env-var-dependent tests to prevent race conditions
    /// from concurrent `std::env::set_var` calls.
    static ENV_TEST_MUTEX: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// Helper to run a closure with temporary environment variables.
    fn with_env_vars<K, V>(vars: &[(K, V)], f: impl FnOnce())
    where
        K: AsRef<std::ffi::OsStr>,
        V: AsRef<std::ffi::OsStr>,
    {
        let _guard = ENV_TEST_MUTEX.lock().unwrap();

        // Save original values
        let originals: Vec<(String, Option<String>)> = vars
            .iter()
            .map(|(k, _)| {
                let key = k.as_ref().to_str().unwrap().to_string();
                let orig = std::env::var(&key).ok();
                (key, orig)
            })
            .collect();

        // Set the temporary values
        for (k, v) in vars {
            std::env::set_var(k, v);
        }

        f();

        // Restore original values
        for (key, orig) in &originals {
            match orig {
                Some(val) => std::env::set_var(key, val),
                None => std::env::remove_var(key),
            }
        }
    }

    #[test]
    fn test_config_from_env_redis_backend() {
        with_env_vars(
            &[
                ("RATE_LIMIT_BACKEND", "redis"),
                ("RATE_LIMIT_REDIS_URL", "redis://myredis:6379"),
                ("RATE_LIMIT_REDIS_KEY_PREFIX", "test:"),
            ],
            || {
                let cfg = RateLimitConfig::from_env();
                assert_eq!(cfg.backend, RateLimitBackend::Redis);
                assert_eq!(cfg.redis_url, Some("redis://myredis:6379".to_string()));
                assert_eq!(cfg.redis_key_prefix, "test:");
            },
        );
    }

    #[test]
    fn test_config_from_env_in_memory_default() {
        with_env_vars(&[("RATE_LIMIT_BACKEND", "in_memory")], || {
            let cfg = RateLimitConfig::from_env();
            assert_eq!(cfg.backend, RateLimitBackend::InMemory);
            assert!(cfg.redis_url.is_none());
            assert_eq!(cfg.redis_key_prefix, "ratelimit:");
        });
    }

    #[test]
    fn test_config_from_env_redis_fallback_to_in_memory() {
        with_env_vars(&[("RATE_LIMIT_BACKEND", "unknown_value")], || {
            let cfg = RateLimitConfig::from_env();
            assert_eq!(
                cfg.backend,
                RateLimitBackend::InMemory,
                "Unknown backend should default to InMemory"
            );
        });
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

    #[test]
    fn config_deserialization_rejects_unknown_fields() {
        let error =
            serde_json::from_str::<RateLimitConfig>(r#"{"requests_per_second":50,"unused":true}"#)
                .unwrap_err();
        assert!(error.to_string().contains("unknown field"));
    }
}
