//! Keyed (multi-tenant) rate limiter with per-key governors and eviction.
//!
//! Suitable for API rate limiting where each tenant / API key needs
//! independent limits. Uses DashMap for lock-free concurrent access.

use dashmap::DashMap;
use governor::{
    clock::DefaultClock,
    state::{InMemoryState, NotKeyed},
    Quota, RateLimiter,
};
use std::num::NonZeroU32;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tracing::debug;

use crate::config::{KeyedConfig, RateLimitConfig};
use crate::types::Decision;

/// Multi-tenant rate limiter that creates per-key governor instances.
pub struct KeyedRateLimiter {
    limiters: Arc<DashMap<String, Arc<RateLimiter<NotKeyed, InMemoryState, DefaultClock>>>>,
    config: RateLimitConfig,
    max_keys: usize,
    total_checks: AtomicU64,
    total_denied: AtomicU64,
}

impl KeyedRateLimiter {
/// Create a new keyed rate limiter.
    pub fn new(config: KeyedConfig) -> Self {
        Self {
            limiters: Arc::new(DashMap::with_capacity(1024)),
            config: config.per_key,
            max_keys: config.max_keys,
            total_checks: AtomicU64::new(0),
            total_denied: AtomicU64::new(0),
        }
    }

/// Create with simple per-key config.
    pub fn from_params(rps: u32, burst: u32, max_keys: usize) -> Self {
        Self {
            limiters: Arc::new(DashMap::with_capacity(1024)),
            config: RateLimitConfig::new(rps).with_burst(burst),
            max_keys,
            total_checks: AtomicU64::new(0),
            total_denied: AtomicU64::new(0),
        }
    }

/// Check rate limit for a specific key.
    pub fn check(&self, key: &str) -> Decision {
        self.total_checks.fetch_add(1, Ordering::Relaxed);

        let limiter = self.get_or_create(key);
        match limiter.check() {
            Ok(()) => Decision::Allowed {
                remaining: self.config.effective_burst().get() as u64,
            },
            Err(not_until) => {
                self.total_denied.fetch_add(1, Ordering::Relaxed);
                let wait = not_until.wait_time_from(DefaultClock::default().now());
                debug!(key, wait_ms = wait.as_millis(), "Keyed rate limit exceeded");
                Decision::Denied { retry_after: wait }
            }
        }
    }

/// Check rate limit for `n` requests for a key (batch).
    pub fn check_n(&self, key: &str, n: u32) -> Decision {
        self.total_checks.fetch_add(1, Ordering::Relaxed);
        let Some(n_nz) = NonZeroU32::new(n) else {
            return Decision::Allowed {
                remaining: self.config.effective_burst().get() as u64,
            };
        };

        let limiter = self.get_or_create(key);
        match limiter.check_n(n_nz) {
            Ok(Ok(())) => Decision::Allowed {
                remaining: self.config.effective_burst().get() as u64,
            },
            _ => {
                self.total_denied.fetch_add(1, Ordering::Relaxed);
                Decision::Denied {
                    retry_after: Duration::from_millis(100),
                }
            }
        }
    }

/// Remove a specific key's rate limiter (e.g. on key deletion).
    pub fn remove(&self, key: &str) {
        self.limiters.remove(key);
    }

/// Number of tracked keys.
    pub fn key_count(&self) -> usize {
        self.limiters.len()
    }

/// Total check count.
    pub fn total_checks(&self) -> u64 {
        self.total_checks.load(Ordering::Relaxed)
    }

/// Total denied count.
    pub fn total_denied(&self) -> u64 {
        self.total_denied.load(Ordering::Relaxed)
    }

/// Clear all tracked keys.
    pub fn clear(&self) {
        self.limiters.clear();
    }

/// Evict keys to stay within max_keys. Simple strategy:remove random entries.
    fn maybe_evict(&self) {
        if self.limiters.len() <= self.max_keys {
            return;
        }

        let to_remove = self.limiters.len() - self.max_keys + (self.max_keys / 10);
        let keys_to_remove: Vec<String> = self
            .limiters
            .iter()
            .take(to_remove)
            .map(|e| e.key().clone())
            .collect();

        for key in keys_to_remove {
            self.limiters.remove(&key);
        }

        debug!(
            removed = to_remove,
            remaining = self.limiters.len(),
            "Evicted rate limiter keys"
        );
    }

// #219:Use entry.or_insert_with to avoid TOCTOU and unnecessary limiter creation
    fn get_or_create(
        &self,
        key: &str,
    ) -> Arc<RateLimiter<NotKeyed, InMemoryState, DefaultClock>> {
// Use entry API to avoid race condition between get and insert
        let limiter = self.limiters
            .entry(key.to_string())
            .or_insert_with(|| {
                let burst = self.config.effective_burst();
                let quota = Quota::per_second(self.config.requests_per_second).allow_burst(burst);
                Arc::new(RateLimiter::direct(quota))
            })
            .value()
            .clone();

// Check if we need to evict
        self.maybe_evict();

        limiter
    }
}

// Need this for governor::clock
use governor::clock::Clock;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keyed_allows_different_keys() {
        let limiter = KeyedRateLimiter::from_params(10, 5, 1000);
        assert!(limiter.check("key_a").is_allowed());
        assert!(limiter.check("key_b").is_allowed());
    }

    #[test]
    fn test_keyed_independent_limits() {
        let limiter = KeyedRateLimiter::from_params(1, 1, 1000);
        assert!(limiter.check("key_a").is_allowed());
// key_a exhausted but key_b should still work
        assert!(limiter.check("key_b").is_allowed());
// key_a should be denied
        assert!(limiter.check("key_a").is_denied());
    }

    #[test]
    fn test_keyed_tracks_count() {
        let limiter = KeyedRateLimiter::from_params(10, 5, 1000);
        limiter.check("key_a");
        limiter.check("key_b");
        limiter.check("key_c");
        assert_eq!(limiter.key_count(), 3);
    }

    #[test]
    fn test_keyed_remove() {
        let limiter = KeyedRateLimiter::from_params(10, 5, 1000);
        limiter.check("key_a");
        limiter.check("key_b");
        assert_eq!(limiter.key_count(), 2);
        limiter.remove("key_a");
        assert_eq!(limiter.key_count(), 1);
    }

    #[test]
    fn test_keyed_clear() {
        let limiter = KeyedRateLimiter::from_params(10, 5, 1000);
        for i in 0..10 {
            limiter.check(&format!("key_{i}"));
        }
        limiter.clear();
        assert_eq!(limiter.key_count(), 0);
    }

    #[test]
    fn test_keyed_eviction() {
        let limiter = KeyedRateLimiter::from_params(10, 5, 5);
        for i in 0..10 {
            limiter.check(&format!("key_{i}"));
        }
// Should have evicted some keys
        assert!(limiter.key_count() <= 6);
    }

    #[test]
    fn test_keyed_metrics() {
        let limiter = KeyedRateLimiter::from_params(1, 1, 1000);
        limiter.check("key_a");
        limiter.check("key_a"); // likely denied
        assert_eq!(limiter.total_checks(), 2);
        assert!(limiter.total_denied() >= 1);
    }

    #[test]
    fn test_keyed_check_n() {
        let limiter = KeyedRateLimiter::from_params(10, 5, 1000);
        assert!(limiter.check_n("key_a", 3).is_allowed());
        assert!(limiter.check_n("key_a", 0).is_allowed()); // 0 always allowed
    }

    #[test]
    fn test_keyed_from_config() {
        let config = KeyedConfig {
            per_key: RateLimitConfig::new(50).with_burst(100),
            max_keys: 5000,
            cleanup_interval_secs: 30,
        };
        let limiter = KeyedRateLimiter::new(config);
        assert_eq!(limiter.key_count(), 0);
        assert!(limiter.check("test").is_allowed());
    }
}
