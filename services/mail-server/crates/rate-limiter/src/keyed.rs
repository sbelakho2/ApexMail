//! Keyed (multi-tenant) rate limiter with per-key governors and LRU eviction.
//!
//! Suitable for API rate limiting where each tenant / API key needs
//! independent limits. Uses `moka::sync::Cache` for concurrent access
//! with built-in TinyLFU (LRU-approximating) eviction.

use governor::{
    clock::DefaultClock,
    state::{InMemoryState, NotKeyed},
    Quota, RateLimiter,
};
use moka::sync::Cache;
use std::num::NonZeroU32;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tracing::debug;

use crate::config::{KeyedConfig, RateLimitConfig};
use crate::types::Decision;

/// Default tombstone cooldown: a key evicted from the LRU cache re-enters
/// with an EMPTY budget for this long after eviction.
pub const DEFAULT_EVICTION_TOMBSTONE_TTL: Duration = Duration::from_secs(60);

/// Multi-tenant rate limiter that creates per-key governor instances.
///
/// Eviction strategy: LRU (Least Recently Used) via `moka`'s built-in
/// TinyLFU eviction policy, which evicts the least recently used entry
/// when the cache exceeds `max_capacity`.
///
/// Budget-reset protection (fix J): without extra state, an evicted key
/// would be re-created with a FULL burst budget on its next request,
/// letting a client rotate `max_keys` distinct keys to get a fresh burst
/// each time. Evicted keys are therefore remembered in a TTL tombstone
/// cache and re-enter with a drained limiter (empty budget, refilling at
/// the steady rate) until the tombstone expires.
pub struct KeyedRateLimiter {
    limiters: Cache<String, Arc<RateLimiter<NotKeyed, InMemoryState, DefaultClock>>>,
    /// Recently-created keys, TTL-bounded. A cache miss for a key that is
    /// still present here means the key was LRU-evicted (not new) — the
    /// re-created limiter starts empty (tombstone penalty).
    seen_keys: Cache<String, ()>,
    tombstone_ttl: Duration,
    config: RateLimitConfig,
    /// Tracks the number of entries. Incremented on insertion, decremented
    /// on explicit removal/clear. Moka's background LRU eviction is not
    /// reflected here (TinyLFU eviction runs asynchronously), so this
    /// represents an upper bound on actual cached entries.
    key_count: AtomicI64,
    total_checks: AtomicU64,
    total_denied: AtomicU64,
}

impl KeyedRateLimiter {
    /// Create a new keyed rate limiter.
    pub fn new(config: KeyedConfig) -> Self {
        Self {
            limiters: Cache::builder()
                .max_capacity(config.max_keys as u64)
                .build(),
            seen_keys: Cache::builder()
                .max_capacity(config.max_keys as u64)
                .time_to_live(config.effective_tombstone_ttl())
                .build(),
            tombstone_ttl: config.effective_tombstone_ttl(),
            config: config.per_key,
            key_count: AtomicI64::new(0),
            total_checks: AtomicU64::new(0),
            total_denied: AtomicU64::new(0),
        }
    }

    /// Create with simple per-key config.
    pub fn from_params(rps: u32, burst: u32, max_keys: usize) -> Self {
        Self::from_params_with_ttl(rps, burst, max_keys, DEFAULT_EVICTION_TOMBSTONE_TTL)
    }

    /// Create with simple per-key config and a custom eviction-tombstone
    /// cooldown (useful for tests and tuning).
    pub fn from_params_with_ttl(
        rps: u32,
        burst: u32,
        max_keys: usize,
        tombstone_ttl: Duration,
    ) -> Self {
        Self {
            limiters: Cache::builder().max_capacity(max_keys as u64).build(),
            seen_keys: Cache::builder()
                .max_capacity(max_keys as u64)
                .time_to_live(tombstone_ttl)
                .build(),
            tombstone_ttl,
            config: RateLimitConfig::new(rps).with_burst(burst),
            key_count: AtomicI64::new(0),
            total_checks: AtomicU64::new(0),
            total_denied: AtomicU64::new(0),
        }
    }

    /// Force moka's asynchronous eviction/maintenance tasks to run.
    /// Useful for deterministic tests of eviction behavior.
    pub fn run_maintenance(&self) {
        self.limiters.run_pending_tasks();
        self.seen_keys.run_pending_tasks();
    }

    /// Check rate limit for a specific key.
    pub fn check(&self, key: &str) -> Decision {
        self.total_checks.fetch_add(1, Ordering::Relaxed);

        let limiter = self.get_or_create(key);
        match limiter.check() {
            Ok(()) => {
                metrics::counter!("rate_limiter_requests_total", "strategy" => "keyed", "decision" => "allowed").increment(1);
                Decision::Allowed {
                    remaining: self.config.effective_burst().get() as u64,
                }
            }
            Err(not_until) => {
                self.total_denied.fetch_add(1, Ordering::Relaxed);
                metrics::counter!("rate_limiter_requests_total", "strategy" => "keyed", "decision" => "denied").increment(1);
                metrics::counter!("rate_limiter_blocked_total", "strategy" => "keyed").increment(1);
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
            Ok(Ok(())) => {
                metrics::counter!("rate_limiter_requests_total", "strategy" => "keyed_batch", "decision" => "allowed").increment(n as u64);
                Decision::Allowed {
                    remaining: self.config.effective_burst().get() as u64,
                }
            }
            // n can never fit in the burst: wait = time to accumulate n tokens
            Err(_insufficient) => {
                self.total_denied.fetch_add(1, Ordering::Relaxed);
                metrics::counter!("rate_limiter_requests_total", "strategy" => "keyed_batch", "decision" => "denied").increment(n as u64);
                metrics::counter!("rate_limiter_blocked_total", "strategy" => "keyed_batch")
                    .increment(1);
                Decision::Denied {
                    retry_after: batch_wait_time(n, self.config.requests_per_second.get()),
                }
            }
            // Not enough tokens right now: wait from limiter state
            Ok(Err(not_until)) => {
                self.total_denied.fetch_add(1, Ordering::Relaxed);
                metrics::counter!("rate_limiter_requests_total", "strategy" => "keyed_batch", "decision" => "denied").increment(n as u64);
                metrics::counter!("rate_limiter_blocked_total", "strategy" => "keyed_batch")
                    .increment(1);
                Decision::Denied {
                    retry_after: not_until.wait_time_from(DefaultClock::default().now()),
                }
            }
        }
    }

    /// Remove a specific key's rate limiter (e.g. on key deletion).
    /// Administrative removal also clears the tombstone so the key is not
    /// penalized if it legitimately returns.
    pub fn remove(&self, key: &str) {
        self.limiters.invalidate(key);
        self.seen_keys.invalidate(key);
        self.key_count.fetch_sub(1, Ordering::Relaxed);
    }

    /// Number of tracked keys.
    pub fn key_count(&self) -> usize {
        self.key_count.load(Ordering::Relaxed).max(0) as usize
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
        self.limiters.invalidate_all();
        self.seen_keys.invalidate_all();
        self.key_count.store(0, Ordering::Relaxed);
    }

    /// Atomic get-or-create with built-in LRU eviction handled by moka.
    /// When the cache exceeds `max_capacity`, moka evicts the least recently
    /// used entry before inserting the new one.
    ///
    /// Fix J: if the key was previously created but is no longer in the
    /// cache (LRU eviction) and its tombstone is still fresh, the
    /// re-created limiter starts EMPTY (all burst tokens drained) instead
    /// of handing the client a full fresh budget. Without this, rotating
    /// `max_keys` distinct keys granted a full burst on every revisit.
    fn get_or_create(&self, key: &str) -> Arc<RateLimiter<NotKeyed, InMemoryState, DefaultClock>> {
        // Use get (non-creating) first to check if the key exists.
        // This avoids unnecessary key_count increments for existing keys.
        if let Some(limiter) = self.limiters.get(key) {
            return limiter.clone();
        }

        // Key not in the limiter cache. If we saw it recently (tombstone
        // alive) it was LRU-evicted, not new → apply the re-entry penalty.
        let was_evicted_recently = self.seen_keys.get(key).is_some();
        if was_evicted_recently {
            debug!(
                key,
                tombstone_ttl_ms = self.tombstone_ttl.as_millis() as u64,
                "Evicted key re-entering: starting with empty burst budget"
            );
        }

        // Key not found — create a new limiter and try to insert.
        let burst = self.config.effective_burst();
        let quota = Quota::per_second(self.config.requests_per_second).allow_burst(burst);
        let new_limiter = Arc::new(RateLimiter::direct(quota));
        if was_evicted_recently {
            // Drain the full burst: `check` consumes one token per allowed
            // call and never consumes future refill, so exactly `burst`
            // calls empty the bucket. It then refills at the steady rate.
            for _ in 0..burst.get() {
                let _ = new_limiter.check();
            }
        }

        // Use get_with to atomically insert if still absent, or return
        // existing value if another thread inserted concurrently.
        let limiter = self.limiters.get_with(key.to_string(), || {
            self.key_count.fetch_add(1, Ordering::Relaxed);
            new_limiter
        });
        // (Re)record the key so a later eviction is detectable. Re-inserting
        // also refreshes the TTL for live keys.
        self.seen_keys.insert(key.to_string(), ());
        limiter
    }
}

// Need this for governor::clock
use governor::clock::Clock;

/// Time to accumulate `n` tokens at `rps` (rounded up, min 1ms).
fn batch_wait_time(n: u32, rps: u32) -> Duration {
    let nanos = (u64::from(n) * 1_000_000_000) / u64::from(rps.max(1));
    Duration::from_nanos(nanos.max(1_000_000))
}

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
        // moka evicts entries asynchronously via an internal maintenance
        // thread (TinyLFU policy), so the manual key_count is an upper
        // bound — it tracks inserts and explicit removes, not async evictions.
        // The real eviction behavior is verified in test_lru_eviction_evicts_oldest
        // which checks that the LRU entry is re-created fresh on next access.
        assert!(
            limiter.key_count() <= 10,
            "Key count should not exceed total inserts"
        );
        // At least some entries should persist close to max_capacity
        assert!(
            limiter.key_count() >= 5,
            "At least 5 entries should remain near max_capacity"
        );
    }

    // NOTE: `test_lru_eviction_evicts_oldest` was replaced — it asserted
    // the vulnerable behavior that an evicted key is "re-created fresh
    // (full burst available)", which let clients rotate keys to reset
    // their budgets. Evicted keys now re-enter with an empty budget for
    // the tombstone cooldown.
    //
    // (moka's TinyLFU admission makes *which* key gets evicted
    // non-deterministic at tiny capacities, so eviction is simulated
    // deterministically via the internal cache where needed.)

    #[test]
    fn test_lru_eviction_reentry_gets_empty_budget() {
        // 1 rps, burst 5. Simulate an LRU eviction of key_a by dropping it
        // from the limiter cache (as moka would) — the tombstone in
        // seen_keys must force an empty restart budget.
        let limiter = KeyedRateLimiter::from_params(1, 5, 1000);

        assert!(limiter.check("key_a").is_allowed()); // 4 tokens left
        // Simulate eviction (NOT an administrative remove — tombstone stays)
        limiter.limiters.invalidate("key_a");
        limiter.run_maintenance();

        // key_a re-enters: tombstone alive → limiter starts empty → denied.
        let decision = limiter.check("key_a");
        assert!(
            decision.is_denied(),
            "evicted key must NOT receive a full fresh burst (fix J), got {:?}",
            decision
        );
    }

    #[test]
    fn test_key_rotation_cannot_reset_budgets() {
        // Adversarial: rotate 4× max_keys distinct keys. Every rotated-out
        // key that re-enters while its tombstone is alive must start with
        // an EMPTY budget — key rotation cannot buy fresh bursts.
        let max_keys = 64;
        let limiter = KeyedRateLimiter::from_params(1, 3, max_keys);

        for i in 0..(max_keys * 4) {
            limiter.check(&format!("attacker-key-{i}"));
        }
        limiter.run_maintenance();

        // Keys no longer in the limiter cache must have been tombstoned:
        // re-entering them is denied, not granted a fresh burst.
        let mut evicted_and_denied = 0usize;
        let mut evicted = 0usize;
        for i in 0..(max_keys * 4) {
            let key = format!("attacker-key-{i}");
            let in_cache = limiter.limiters.get(&key).is_some();
            let tombstoned = limiter.seen_keys.get(&key).is_some();
            if !in_cache && tombstoned {
                evicted += 1;
                assert!(
                    limiter.check(&key).is_denied(),
                    "evicted key {key} must re-enter with an empty budget"
                );
                evicted_and_denied += 1;
            }
        }
        assert!(evicted > 0, "rotation must have evicted some keys");
        assert_eq!(evicted, evicted_and_denied);
    }

    #[test]
    fn test_tombstone_expires_after_ttl() {
        // With a very short tombstone TTL, re-entry after expiry gets a
        // fresh budget again (10 rps refills the drained limiter quickly).
        let limiter =
            KeyedRateLimiter::from_params_with_ttl(10, 5, 1000, Duration::from_millis(40));

        limiter.check("key_a");
        limiter.limiters.invalidate("key_a"); // simulate eviction
        limiter.run_maintenance();
        assert!(
            limiter.check("key_a").is_denied(),
            "tombstone alive: re-entry starts empty"
        );

        // After the TTL (and some token refill time): budget available again
        std::thread::sleep(Duration::from_millis(300));
        limiter.run_maintenance();
        assert!(
            limiter.check("key_a").is_allowed(),
            "after tombstone expiry the key gets a fresh budget"
        );
    }

    #[test]
    fn test_explicit_remove_does_not_tombstone() {
        // Administrative removal clears the tombstone: a legitimately
        // deleted key returning starts fresh.
        let limiter = KeyedRateLimiter::from_params(1, 5, 1000);
        limiter.check("key_a");
        limiter.remove("key_a");
        limiter.run_maintenance();
        assert!(
            limiter.check("key_a").is_allowed(),
            "explicitly removed key re-enters fresh (no tombstone penalty)"
        );
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
            eviction_tombstone_ttl_secs: 60,
        };
        let limiter = KeyedRateLimiter::new(config);
        assert_eq!(limiter.key_count(), 0);
        assert!(limiter.check("test").is_allowed());
    }
}
