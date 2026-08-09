//! Redis-backed distributed rate limiter using sorted sets and Lua scripting.
//!
//! Provides a sliding window rate limiter that shares state across all pods
//! via Redis. Falls back to in-memory governor-based limiting when Redis
//! is unreachable, with automatic recovery when Redis comes back online.
//!
//! ## Architecture
//!
//! ```text
//! ┌──────────────┐     ┌───────────────────┐     ┌─────────────┐
//! │  check() /   │ ──▶ │  RedisLimiter      │ ──▶ │  Redis       │
//! │  check_n()   │     │  (Lua script)      │     │  (SortedSet) │
//! └──────────────┘     └───────────────────┘     └─────────────┘
//!                             │  fallback
//!                             ▼
//!                      ┌──────────────┐
//!                      │ GovernorLimiter│
//!                      │ (in-memory)   │
//!                      └──────────────┘
//! ```
//!
//! ## Lua Script (Sliding Window)
//!
//! The script uses Redis Sorted Sets to track request timestamps within a
//! sliding time window. Expired entries are removed on each check via
//! `ZREMRANGEBYSCORE`, and the current count is compared against the limit.

#![cfg(feature = "redis")]

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use tracing::{debug, warn};

use crate::config::RateLimitConfig;
use crate::governor_limiter::GovernorLimiter;
use crate::types::Decision;

/// Interval at which fallback warning logs are emitted (debounce).
const FALLBACK_WARN_INTERVAL: Duration = Duration::from_secs(60);

/// Default sliding window size in seconds.
const DEFAULT_WINDOW_SECS: u64 = 1;

/// Redis-backed distributed rate limiter with automatic in-memory fallback.
///
/// Uses a Lua script with Redis Sorted Sets for atomic sliding window
/// rate limiting that is consistent across all application pods.
pub struct RedisLimiter {
    /// Redis connection manager, wrapped for `&mut self` access.
    cm: Option<Arc<Mutex<redis::aio::ConnectionManager>>>,
    /// Key prefix for Redis keys (e.g., `"ratelimit:"`).
    key_prefix: String,
    /// Sliding window size in seconds.
    window_secs: u64,
    /// Maximum requests allowed per window.
    max_requests: u64,
    /// In-memory fallback limiter used when Redis is unreachable.
    fallback: GovernorLimiter,
    /// Whether we are currently operating in fallback mode.
    in_fallback: AtomicBool,
    /// Timestamp of the last fallback warning (debounce).
    last_warn: Mutex<tokio::time::Instant>,
}

impl RedisLimiter {
    /// Create a new Redis-backed rate limiter.
    ///
    /// The limiter uses `RateLimitConfig` for rate parameters:
    /// - `requests_per_second` → window size of 1 second
    /// - `effective_burst()` → max requests per window
    pub fn new(config: &RateLimitConfig, cm: redis::aio::ConnectionManager) -> Self {
        Self {
            cm: Some(Arc::new(Mutex::new(cm))),
            key_prefix: "ratelimit:".to_string(),
            window_secs: DEFAULT_WINDOW_SECS,
            max_requests: config.effective_burst().get() as u64,
            fallback: GovernorLimiter::new(config),
            in_fallback: AtomicBool::new(false),
            last_warn: Mutex::new(tokio::time::Instant::now()),
        }
    }

    /// Create a new Redis-backed rate limiter with a custom key prefix.
    pub fn with_prefix(mut self, prefix: &str) -> Self {
        self.key_prefix = prefix.to_string();
        self
    }

    /// Create a new Redis-backed rate limiter with custom window parameters.
    pub fn with_window(mut self, window_secs: u64) -> Self {
        self.window_secs = window_secs;
        self
    }

    /// Create a limiter that only uses the in-memory fallback (for testing
    /// or configurations where Redis is intentionally unavailable).
    pub fn fallback_only(config: &RateLimitConfig) -> Self {
        Self {
            cm: None,
            key_prefix: "ratelimit:".to_string(),
            window_secs: DEFAULT_WINDOW_SECS,
            max_requests: config.effective_burst().get() as u64,
            fallback: GovernorLimiter::new(config),
            in_fallback: AtomicBool::new(true),
            last_warn: Mutex::new(tokio::time::Instant::now()),
        }
    }

    /// Create a limiter for testing with a raw Redis connection.
    ///
    /// This bypasses `ConnectionManager` and allows direct injection of
    /// a connection for test isolation.
    #[cfg(feature = "redis")]
    pub fn with_connection(
        config: &RateLimitConfig,
        conn: redis::aio::ConnectionManager,
        key_prefix: &str,
        window_secs: u64,
    ) -> Self {
        Self {
            cm: Some(Arc::new(Mutex::new(conn))),
            key_prefix: key_prefix.to_string(),
            window_secs,
            max_requests: config.effective_burst().get() as u64,
            fallback: GovernorLimiter::new(config),
            in_fallback: AtomicBool::new(false),
            last_warn: Mutex::new(tokio::time::Instant::now()),
        }
    }

    /// Check if a single request is allowed and increment the counter.
    ///
    /// Optionally scoped to a `tenant_id` to prevent key collisions between tenants.
    /// When `tenant_id` is `None`, falls back to the `"default"` key.
    pub async fn check(&self) -> Decision {
        self.check_n(1).await
    }

    /// Check if `n` requests are allowed and increment the counter.
    ///
    /// Optionally scoped to a `tenant_id` to prevent key collisions between tenants.
    /// When `tenant_id` is `None`, falls back to the `"default"` key.
    pub async fn check_n(&self, n: u32) -> Decision {
        self.check_n_for_tenant(None, n).await
    }

    /// Check if `n` requests are allowed for a specific tenant and increment the counter.
    ///
    /// Scopes the rate limit key by `tenant_id` to prevent cross-tenant key collisions.
    pub async fn check_n_for_tenant(&self, tenant_id: Option<&str>, n: u32) -> Decision {
        let key_scope = tenant_id.unwrap_or("default");
        if self.cm.is_none() {
            return self.fallback.check_n(n);
        }

        let key = format!("{}{}", self.key_prefix, key_scope);
        match self.eval_script(&key, n).await {
            Ok(decision) => {
                // If we were in fallback mode and this succeeded, we've recovered
                if self.in_fallback.swap(false, Ordering::Relaxed) {
                    warn!("Redis rate limiter recovered, switching back from fallback");
                }
                decision
            }
            Err(err) => {
                debug!(%err, "Redis rate limiter error, falling back to in-memory");
                self.enter_fallback().await;
                self.fallback.check_n(n)
            }
        }
    }

    /// Read-only check without consuming capacity.
    ///
    /// Uses `ZCOUNT` instead of the Lua script to avoid modifying the
    /// sorted set. This is useful for health checks or monitoring.
    ///
    /// Optionally scoped to a `tenant_id` to prevent key collisions between tenants.
    pub async fn peek(&self) -> Decision {
        self.peek_for_tenant(None).await
    }

    /// Read-only check without consuming capacity, scoped to a specific tenant.
    ///
    /// Uses `ZCOUNT` instead of the Lua script to avoid modifying the
    /// sorted set. This is useful for health checks or monitoring.
    pub async fn peek_for_tenant(&self, tenant_id: Option<&str>) -> Decision {
        let key_scope = tenant_id.unwrap_or("default");
        let cm = match &self.cm {
            Some(cm) => cm,
            // RS-054: When Redis is unavailable, fail-open (allow) instead of
            // consuming tokens from the in-memory fallback, which causes over-limiting.
            // Peek is read-only and should not modify state.
            None => {
                warn!(
                    "Redis unavailable during peek — allowing request (fail-open) to avoid over-limiting"
                );
                return Decision::Allowed {
                    remaining: self.max_requests,
                };
            }
        };

        let key = format!("{}{}", self.key_prefix, key_scope);
        let mut cm_guard = cm.lock().await;

        let now = unix_epoch_secs();
        let window_start = now.saturating_sub(self.window_secs);

        match redis::cmd("ZCOUNT")
            .arg(&key)
            .arg(window_start)
            .arg("+inf")
            .query_async::<u64>(&mut *cm_guard)
            .await
        {
            Ok(count) => {
                // If we were in fallback mode, we've recovered
                if self.in_fallback.swap(false, Ordering::Relaxed) {
                    warn!("Redis rate limiter recovered, switching back from fallback");
                }

                if count >= self.max_requests {
                    Decision::Denied {
                        retry_after: Duration::from_secs(1),
                    }
                } else {
                    Decision::Allowed {
                        remaining: self.max_requests.saturating_sub(count),
                    }
                }
            }
            Err(err) => {
                debug!(%err, "Redis peek error, falling back to in-memory");
                self.enter_fallback().await;
                self.fallback.check_n(1)
            }
        }
    }

    /// Reset the rate limiter state by deleting the Redis key.
    ///
    /// Optionally scoped to a `tenant_id` to reset per-tenant state.
    pub async fn reset(&self) -> Result<(), redis::RedisError> {
        self.reset_for_tenant(None).await
    }

    /// Reset the rate limiter state for a specific tenant.
    pub async fn reset_for_tenant(&self, tenant_id: Option<&str>) -> Result<(), redis::RedisError> {
        let key_scope = tenant_id.unwrap_or("default");
        match &self.cm {
            Some(cm) => {
                let key = format!("{}{}", self.key_prefix, key_scope);
                let mut cm_guard = cm.lock().await;
                redis::cmd("DEL")
                    .arg(&key)
                    .query_async::<()>(&mut *cm_guard)
                    .await?;
                Ok(())
            }
            None => Ok(()),
        }
    }

    /// Returns `true` if the limiter is currently in fallback mode.
    pub fn is_in_fallback(&self) -> bool {
        self.in_fallback.load(Ordering::Relaxed)
    }

    /// Enter fallback mode with debounced warning logging.
    async fn enter_fallback(&self) {
        if !self.in_fallback.swap(true, Ordering::Relaxed) {
            let mut last_warn = self.last_warn.lock().await;
            let now = tokio::time::Instant::now();
            if now.duration_since(*last_warn) >= FALLBACK_WARN_INTERVAL {
                warn!(
                    "Redis unreachable, falling back to in-memory rate limiter \
                     (next warning suppressed for {}s)",
                    FALLBACK_WARN_INTERVAL.as_secs()
                );
                *last_warn = now;
            }
        }
    }

    /// Evaluate the Lua sliding window script against Redis.
    async fn eval_script(&self, key: &str, cost: u32) -> Result<Decision, redis::RedisError> {
        let mut cm_guard = self
            .cm
            .as_ref()
            .expect("invariant: eval_script only called when cm is Some")
            .lock()
            .await;

        let now = unix_epoch_secs();

        // Lua script for atomic sliding window rate limiting.
        // Uses sorted sets with timestamp scores to track requests within
        // a sliding time window.
        let script = redis::Script::new(
            r#"
            local window = tonumber(ARGV[1])
            local max_requests = tonumber(ARGV[2])
            local now = tonumber(ARGV[3])
            local cost = tonumber(ARGV[4])
            local window_start = now - window

            -- Remove expired entries outside the current window
            redis.call('ZREMRANGEBYSCORE', KEYS[1], 0, window_start)

            -- Count current entries in the window
            local current = redis.call('ZCARD', KEYS[1])

            if current + cost > max_requests then
                -- Denied: get the oldest entry's timestamp for retry-after calc
                local oldest = redis.call('ZRANGE', KEYS[1], 0, 0, 'WITHSCORES')
                local retry_after = 0
                if oldest[2] then
                    retry_after = window - (now - tonumber(oldest[2]))
                end
                return {0, retry_after, current}
            end

            -- Allowed: add one member per unit of cost so ZCARD always equals
            -- the real request count.  TIME gives microsecond precision; the
            -- per-script loop index disambiguates members added within the
            -- same TIME snapshot (a batch of cost>1 must create cost members).
            local time_arr = redis.call('TIME')
            local member_base = now .. ':' .. time_arr[1] .. '.' .. time_arr[2]
            for i = 1, cost do
                redis.call('ZADD', KEYS[1], now, member_base .. ':' .. i)
            end
            redis.call('EXPIRE', KEYS[1], window)

            return {1, 0, current + cost}
            "#,
        );

        let result: Vec<i64> = script
            .key(key)
            .arg(self.window_secs as i64)
            .arg(self.max_requests as i64)
            .arg(now as i64)
            .arg(cost as i64)
            .invoke_async(&mut *cm_guard)
            .await?;

        let allowed = result.first().copied().unwrap_or(0) == 1;
        let retry_after_secs = result.get(1).copied().unwrap_or(0) as u64;
        let used = result.get(2).copied().unwrap_or(0) as u64;

        if allowed {
            metrics::counter!(
                "rate_limiter_requests_total",
                "strategy" => "redis",
                "decision" => "allowed"
            )
            .increment(cost as u64);
            Ok(Decision::Allowed {
                remaining: self.max_requests.saturating_sub(used),
            })
        } else {
            metrics::counter!(
                "rate_limiter_requests_total",
                "strategy" => "redis",
                "decision" => "denied"
            )
            .increment(cost as u64);
            metrics::counter!("rate_limiter_blocked_total", "strategy" => "redis").increment(1);
            Ok(Decision::Denied {
                retry_after: Duration::from_secs(retry_after_secs.max(1)),
            })
        }
    }
}

/// Get the current Unix epoch time in seconds.
fn unix_epoch_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

impl std::fmt::Debug for RedisLimiter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RedisLimiter")
            .field("key_prefix", &self.key_prefix)
            .field("window_secs", &self.window_secs)
            .field("max_requests", &self.max_requests)
            .field("in_fallback", &self.in_fallback.load(Ordering::Relaxed))
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::RateLimitConfig;

    // ── In-memory fallback tests (no Redis required) ──────────────

    #[tokio::test]
    async fn test_fallback_allows_within_limit() {
        let config = RateLimitConfig::new(10).with_burst(5);
        let limiter = RedisLimiter::fallback_only(&config);

        for _ in 0..5 {
            let decision = limiter.check().await;
            assert!(decision.is_allowed(), "Expected allowed within burst");
        }
    }

    #[tokio::test]
    async fn test_fallback_denies_after_limit() {
        let config = RateLimitConfig::new(1).with_burst(1);
        let limiter = RedisLimiter::fallback_only(&config);

        assert!(limiter.check().await.is_allowed());
        let decision = limiter.check().await;
        assert!(
            decision.is_denied(),
            "Expected denied after burst exhausted"
        );
    }

    #[tokio::test]
    async fn test_fallback_check_n() {
        let config = RateLimitConfig::new(10).with_burst(5);
        let limiter = RedisLimiter::fallback_only(&config);

        // First check_n(3) consumes 3 of 5 burst tokens
        assert!(limiter.check_n(3).await.is_allowed());
        // Second check_n(3) tries to consume 3, but only 2 remain → denied
        assert!(limiter.check_n(3).await.is_denied());
        // check_n with cost=0 should always be allowed
        assert!(limiter.check_n(0).await.is_allowed());
    }

    #[tokio::test]
    async fn test_fallback_peek() {
        let config = RateLimitConfig::new(10).with_burst(5);
        let limiter = RedisLimiter::fallback_only(&config);

        // Peek should always go to fallback, which treats peek same as check_n(1)
        // for the in-memory case
        let decision = limiter.peek().await;
        // In fallback-only mode, peek uses fallback.check_n(1)
        // With burst=5, first call should be allowed
        assert!(decision.is_allowed());
    }

    #[tokio::test]
    async fn test_fallback_reset() {
        let config = RateLimitConfig::new(1).with_burst(1);
        let limiter = RedisLimiter::fallback_only(&config);

        // Reset should not error even without Redis
        assert!(limiter.reset().await.is_ok());
    }

    #[tokio::test]
    async fn test_fallback_is_in_fallback() {
        let config = RateLimitConfig::new(10);
        let limiter = RedisLimiter::fallback_only(&config);

        assert!(limiter.is_in_fallback());
    }

    #[tokio::test]
    async fn test_fallback_with_custom_window() {
        let config = RateLimitConfig::new(100);
        let limiter = RedisLimiter::fallback_only(&config)
            .with_prefix("custom:")
            .with_window(60);

        let decision = limiter.check().await;
        assert!(decision.is_allowed());
    }

    // ── Integration tests (require a running Redis instance) ──────
    // These tests are skipped by default. Run with:
    //   cargo test -p rate-limiter --features redis -- --ignored
    // and ensure a Redis server is available at the configured URL.

    /// Helper to connect to Redis for integration tests.
    async fn test_redis_connection() -> Option<redis::aio::ConnectionManager> {
        let url = std::env::var("REDIS_TEST_URL")
            .unwrap_or_else(|_| "redis://127.0.0.1:6379".to_string());

        let client = redis::Client::open(url.as_str()).ok()?;
        match redis::aio::ConnectionManager::new(client).await {
            Ok(cm) => {
                // Verify connectivity with a simple PING
                let mut cm_clone = cm.clone();
                let pong: Result<String, _> = redis::cmd("PING").query_async(&mut cm_clone).await;
                if pong.map_or(false, |v| v == "PONG") {
                    Some(cm)
                } else {
                    None
                }
            }
            Err(_) => None,
        }
    }

    /// Integration test: basic allow/deny behavior with Redis.
    ///
    /// Verifies that requests within the limit are allowed and requests
    /// exceeding the limit are denied.
    #[ignore]
    #[tokio::test]
    async fn test_redis_basic_allow_deny() {
        let cm = test_redis_connection()
            .await
            .expect("Redis not available. Start Redis or set REDIS_TEST_URL");
        let config = RateLimitConfig::new(100).with_burst(3);
        let limiter = RedisLimiter::with_connection(&config, cm, "test:basic:", 1);

        // Clean slate
        limiter.reset().await.unwrap();

        // First 3 should be allowed (burst = 3)
        for i in 0..3 {
            let decision = limiter.check().await;
            assert!(
                decision.is_allowed(),
                "Request {} should be allowed (burst)",
                i + 1
            );
        }

        // 4th should be denied (burst exhausted)
        let decision = limiter.check().await;
        assert!(decision.is_denied(), "4th request should be denied");

        // Verify peek reads current state without modifying it
        let peek_decision = limiter.peek().await;
        assert!(
            peek_decision.is_denied(),
            "Peek should reflect current state"
        );

        limiter.reset().await.unwrap();
    }

    /// Integration test: window expiry.
    ///
    /// Verifies that requests outside the current window don't count
    /// against the limit. Uses a 1-second window.
    #[ignore]
    #[tokio::test]
    async fn test_redis_window_expiry() {
        let cm = test_redis_connection()
            .await
            .expect("Redis not available. Start Redis or set REDIS_TEST_URL");
        let config = RateLimitConfig::new(100).with_burst(2);
        let limiter = RedisLimiter::with_connection(&config, cm, "test:window:", 1);

        limiter.reset().await.unwrap();

        // Consume both tokens
        assert!(limiter.check().await.is_allowed());
        assert!(limiter.check().await.is_allowed());
        assert!(limiter.check().await.is_denied());

        // Wait for window to expire
        tokio::time::sleep(Duration::from_secs(1)).await;

        // Should be allowed again (window slid)
        let decision = limiter.check().await;
        assert!(decision.is_allowed(), "Window should have expired");

        limiter.reset().await.unwrap();
    }

    /// Integration test: multiple keys are independent.
    #[ignore]
    #[tokio::test]
    async fn test_redis_multiple_keys_independent() {
        let cm = test_redis_connection()
            .await
            .expect("Redis not available. Start Redis or set REDIS_TEST_URL");
        let config = RateLimitConfig::new(100).with_burst(2);

        // Two limiters with different key prefixes
        let limiter_a = RedisLimiter::with_connection(&config, cm.clone(), "test:keys:a:", 10);
        let limiter_b = RedisLimiter::with_connection(&config, cm, "test:keys:b:", 10);

        limiter_a.reset().await.unwrap();
        limiter_b.reset().await.unwrap();

        // Exhaust limiter A
        assert!(limiter_a.check().await.is_allowed());
        assert!(limiter_a.check().await.is_allowed());
        assert!(limiter_a.check().await.is_denied());

        // Limiter B should still be fresh
        assert!(
            limiter_b.check().await.is_allowed(),
            "Independent key B should be allowed"
        );
        assert!(
            limiter_b.check().await.is_allowed(),
            "Independent key B should be allowed"
        );

        limiter_a.reset().await.unwrap();
        limiter_b.reset().await.unwrap();
    }

    /// Integration test: state survives pod restart.
    ///
    /// Simulates a pod restart by creating a new `RedisLimiter` with a
    /// fresh connection and verifying that existing rate limit state
    /// is carried over.
    #[ignore]
    #[tokio::test]
    async fn test_redis_state_survives_restart() {
        let cm = test_redis_connection()
            .await
            .expect("Redis not available. Start Redis or set REDIS_TEST_URL");
        let config = RateLimitConfig::new(100).with_burst(3);

        // "Pod 1" — add requests
        let limiter1 = RedisLimiter::with_connection(&config, cm.clone(), "test:restart:", 60);
        limiter1.reset().await.unwrap();

        assert!(limiter1.check().await.is_allowed());
        assert!(limiter1.check().await.is_allowed());
        assert!(limiter1.check().await.is_allowed());

        // "Pod 2" (new connection, same key prefix) — old state should persist
        let limiter2 = RedisLimiter::with_connection(&config, cm, "test:restart:", 60);
        let decision = limiter2.check().await;
        assert!(
            decision.is_denied(),
            "State should survive 'restart' — expected denied, got {:?}",
            decision
        );

        // Peek should also show the same state
        let peek = limiter2.peek().await;
        assert!(
            peek.is_denied(),
            "Peek after restart should show full state"
        );

        limiter2.reset().await.unwrap();
    }

    /// Integration test: check_n with batch cost.
    #[ignore]
    #[tokio::test]
    async fn test_redis_check_n() {
        let cm = test_redis_connection()
            .await
            .expect("Redis not available. Start Redis or set REDIS_TEST_URL");
        let config = RateLimitConfig::new(100).with_burst(5);
        let limiter = RedisLimiter::with_connection(&config, cm, "test:batchn:", 10);

        limiter.reset().await.unwrap();

        // Batch of 3 should be allowed
        assert!(limiter.check_n(3).await.is_allowed());

        // Batch of 3 more should be denied (3 + 3 > 5)
        assert!(limiter.check_n(3).await.is_denied());

        // Batch of 2 should be allowed (3 + 2 = 5)
        assert!(limiter.check_n(2).await.is_allowed());

        // Now at limit
        assert!(limiter.check().await.is_denied());

        limiter.reset().await.unwrap();
    }
}
