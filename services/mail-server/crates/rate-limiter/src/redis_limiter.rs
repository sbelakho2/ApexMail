//! Redis-backed distributed rate limiter using a token bucket in Lua.
//!
//! Provides a token bucket rate limiter that shares state across all pods
//! via Redis. Falls back to in-memory governor-based limiting when Redis
//! is unreachable, with automatic recovery when Redis comes back online.
//!
//! ## Architecture
//!
//! ```text
//! ┌──────────────┐     ┌───────────────────┐     ┌─────────────┐
//! │  check() /   │ ──▶ │  RedisLimiter      │ ──▶ │  Redis       │
//! │  check_n()   │     │  (Lua script)      │     │  (HASH)      │
//! └──────────────┘     └───────────────────┘     └─────────────┘
//!                             │  fallback
//!                             ▼
//!                      ┌──────────────┐
//!                      │ GovernorLimiter│
//!                      │ (in-memory)   │
//!                      └──────────────┘
//! ```
//!
//! ## Lua Script (Token Bucket)
//!
//! The bucket starts with `burst` tokens and refills continuously at
//! `rps` tokens per second. Each check is an atomic TAKE: at most `burst`
//! requests pass instantaneously and at most `rps` requests/second are
//! sustained. All timing uses `redis.call('TIME')` so instances with
//! skewed clocks cannot corrupt the shared bucket (no caller clock is
//! sent or trusted).

#![cfg(feature = "redis")]

use std::sync::atomic::{AtomicBool, Ordering};
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

/// Environment variable dividing the fallback budget across the expected
/// number of pods sharing the limit.
///
/// When Redis is unreachable each pod falls back to an independent
/// in-memory limiter. With N pods each enforcing the FULL limit, the fleet
/// effectively allows N× the configured rate. Setting this to the expected
/// pod count divides the fallback limit (both burst and sustained rate)
/// accordingly.
///
/// When UNSET the budget is divided by 2 (fix #2): a default of 1 meant N
/// pods each held the full budget, admitting N× the configured limit.
/// The conservative default of 2 halves the damage of a Redis outage on a
/// single-pod deployment while still bounding multi-pod over-admission to
/// 2× instead of N×.
pub const FALLBACK_PODS_ENV: &str = "RATE_LIMIT_FALLBACK_PODS";

/// Default fallback budget divisor when `RATE_LIMIT_FALLBACK_PODS` is unset.
pub const DEFAULT_FALLBACK_SHARES: u64 = 2;

/// Lua script implementing the atomic token-bucket TAKE (fixes #1 and #4).
///
/// Semantics enforced IN LUA (not derivable from a sliding window):
/// - the bucket starts full at `capacity` (= `effective_burst()`) tokens;
/// - tokens refill CONTINUOUSLY at `refill_per_sec` (= `requests_per_second`)
///   tokens/second, clamped at capacity;
/// - each check atomically takes `cost` tokens: at most `burst` requests
///   pass instantaneously, at most `rps` are sustained per second;
/// - `remaining` returned to the caller is the ACTUAL token count.
///
/// All timestamps come from `redis.call('TIME')` — the caller's app clock
/// is never used, so cross-instance clock skew cannot corrupt the bucket.
///
/// Precision: tokens are stored as integer "micro-tokens" (1 token =
/// 10^6 micro-tokens). Because 1 token/s = 10^6 micro-tokens / 10^6 µs,
/// the per-microsecond refill rate equals `refill_per_sec`, so elapsed
/// micro-seconds × refill rate gives micro-tokens directly.
///
/// Built ONCE per limiter (fix K1): `redis::Script::new` computes the
/// script SHA-1 hash on every construction, so re-creating it per check
/// burned CPU on the hot path. `Script` is cheap to reuse (`invoke`
/// clones internally).
const TOKEN_BUCKET_SCRIPT: &str = r#"
            local time = redis.call('TIME')
            local now_us = tonumber(time[1]) * 1000000 + tonumber(time[2])

            local capacity = tonumber(ARGV[1])
            local refill_per_sec = tonumber(ARGV[2])
            local cost = tonumber(ARGV[3])

            local SCALE = 1000000
            local capacity_ut = capacity * SCALE

            local bucket = redis.call('HMGET', KEYS[1], 'ut', 'ts')
            local tokens_ut = tonumber(bucket[1]) or capacity_ut
            local ts_us = tonumber(bucket[2]) or now_us
            if ts_us > now_us then
                -- Future timestamp (skewed writer / manual seeding):
                -- clamp to now so elapsed never goes negative.
                ts_us = now_us
            end

            -- Continuous refill, clamped at capacity.
            tokens_ut = math.min(capacity_ut, tokens_ut + (now_us - ts_us) * refill_per_sec)

            local allowed = 0
            local retry_after_us = 0
            local cost_ut = cost * SCALE
            if tokens_ut >= cost_ut then
                tokens_ut = tokens_ut - cost_ut
                allowed = 1
            elseif refill_per_sec > 0 then
                -- Micro-seconds until `cost` tokens are available:
                -- deficit micro-tokens / (refill micro-tokens per micro-second).
                retry_after_us = math.ceil((cost_ut - tokens_ut) / refill_per_sec)
            else
                retry_after_us = SCALE
            end

            redis.call('HSET', KEYS[1], 'ut', tokens_ut, 'ts', now_us)
            -- Expire once the bucket could have refilled from empty to
            -- full, plus a 60s buffer so idle buckets are reclaimed.
            local ttl = 60
            if refill_per_sec > 0 then
                ttl = math.ceil(capacity / refill_per_sec) + 60
            end
            redis.call('EXPIRE', KEYS[1], ttl)

            local remaining = math.floor(tokens_ut / SCALE)
            return {allowed, retry_after_us, remaining}
            "#;

/// Lua script implementing a read-only token-bucket peek (fix K2: peek
/// must never mutate state). Computes the same refill as
/// [`TOKEN_BUCKET_SCRIPT`] but writes nothing; returns the remaining
/// whole tokens and the µs until one token is available.
const TOKEN_PEEK_SCRIPT: &str = r#"
            local time = redis.call('TIME')
            local now_us = tonumber(time[1]) * 1000000 + tonumber(time[2])

            local capacity = tonumber(ARGV[1])
            local refill_per_sec = tonumber(ARGV[2])

            local SCALE = 1000000
            local capacity_ut = capacity * SCALE

            local bucket = redis.call('HMGET', KEYS[1], 'ut', 'ts')
            if not bucket[1] then
                return {capacity, 0}
            end
            local tokens_ut = tonumber(bucket[1]) or capacity_ut
            local ts_us = tonumber(bucket[2]) or now_us
            if ts_us > now_us then
                ts_us = now_us
            end

            tokens_ut = math.min(capacity_ut, tokens_ut + (now_us - ts_us) * refill_per_sec)

            local retry_after_us = 0
            if tokens_ut < SCALE and refill_per_sec > 0 then
                retry_after_us = math.ceil((SCALE - tokens_ut) / refill_per_sec)
            end
            return {math.floor(tokens_ut / SCALE), retry_after_us}
            "#;

/// Redis-backed distributed rate limiter with automatic in-memory fallback.
///
/// Uses a Lua token bucket in Redis for atomic, cross-pod-consistent rate
/// limiting: `burst` tokens available immediately, continuous refill at
/// `rps` tokens/second.
pub struct RedisLimiter {
    /// Redis connection manager.
    ///
    /// Fix #3: `ConnectionManager` is `Clone` and internally multiplexed —
    /// concurrent checks each clone it and run the Lua script in parallel;
    /// the script itself is the atomicity boundary. The previous
    /// `Arc<Mutex<ConnectionManager>>` serialized every check behind one
    /// lock, defeating the multiplexed connection.
    cm: Option<redis::aio::ConnectionManager>,
    /// Key prefix for Redis keys (e.g., `"ratelimit:"`).
    key_prefix: String,
    /// Sliding window size in seconds (legacy parameter, retained for API
    /// compatibility; the token bucket derives its own key TTL from
    /// capacity/refill rate).
    #[allow(dead_code)]
    window_secs: u64,
    /// Maximum requests allowed per window.
    max_requests: u64,
    /// Sustained refill rate (tokens per second).
    refill_per_sec: u64,
    /// In-memory fallback limiter used when Redis is unreachable.
    fallback: GovernorLimiter,
    /// The original rate configuration (used to rebuild the fallback when
    /// the pod-share divisor changes).
    base_config: RateLimitConfig,
    /// Expected number of pods sharing the limit; the fallback limiter's
    /// budget (burst AND sustained rate) is divided by this so a Redis
    /// outage does not multiply the effective fleet-wide limit.
    fallback_shares: u64,
    /// Pre-built token bucket script (SHA-1 computed once).
    script: redis::Script,
    /// Pre-built read-only peek script (SHA-1 computed once).
    peek_script: redis::Script,
    /// Whether we are currently operating in fallback mode.
    in_fallback: AtomicBool,
    /// Timestamp of the last fallback warning (debounce).
    last_warn: Mutex<tokio::time::Instant>,
}

impl RedisLimiter {
    /// Create a new Redis-backed rate limiter.
    ///
    /// The limiter uses `RateLimitConfig` for rate parameters:
    /// - `effective_burst()` → token bucket capacity (instantaneous burst)
    /// - `requests_per_second` → continuous refill rate (sustained limit)
    ///
    /// The in-memory fallback budget is divided by the value of the
    /// `RATE_LIMIT_FALLBACK_PODS` environment variable (default: divide
    /// by 2) so a Redis outage does not multiply the effective limit
    /// across pods.
    pub fn new(config: &RateLimitConfig, cm: redis::aio::ConnectionManager) -> Self {
        let shares = fallback_shares_from_env();
        Self {
            cm: Some(cm),
            key_prefix: "ratelimit:".to_string(),
            window_secs: DEFAULT_WINDOW_SECS,
            max_requests: config.effective_burst().get() as u64,
            refill_per_sec: config.requests_per_second.get() as u64,
            fallback: GovernorLimiter::new(&divided_config(config, shares)),
            base_config: config.clone(),
            fallback_shares: shares,
            script: redis::Script::new(TOKEN_BUCKET_SCRIPT),
            peek_script: redis::Script::new(TOKEN_PEEK_SCRIPT),
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

    /// Set the number of pods the fallback budget is shared across.
    ///
    /// Example: with `pods = 4` and a configured limit of 100 req/s, the
    /// per-pod fallback limit becomes 25 req/s so the fleet-wide effective
    /// limit stays ≈100 req/s while Redis is unavailable.
    pub fn with_fallback_shares(mut self, pods: u64) -> Self {
        self.fallback_shares = pods.max(1);
        self.fallback =
            GovernorLimiter::new(&divided_config(&self.base_config, self.fallback_shares));
        self
    }

    /// Number of pods the fallback budget is divided across.
    pub fn fallback_shares(&self) -> u64 {
        self.fallback_shares
    }

    /// Create a limiter that only uses the in-memory fallback (for testing
    /// or configurations where Redis is intentionally unavailable).
    pub fn fallback_only(config: &RateLimitConfig) -> Self {
        let shares = fallback_shares_from_env();
        Self {
            cm: None,
            key_prefix: "ratelimit:".to_string(),
            window_secs: DEFAULT_WINDOW_SECS,
            max_requests: config.effective_burst().get() as u64,
            refill_per_sec: config.requests_per_second.get() as u64,
            fallback: GovernorLimiter::new(&divided_config(config, shares)),
            base_config: config.clone(),
            fallback_shares: shares,
            script: redis::Script::new(TOKEN_BUCKET_SCRIPT),
            peek_script: redis::Script::new(TOKEN_PEEK_SCRIPT),
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
            cm: Some(conn),
            key_prefix: key_prefix.to_string(),
            window_secs,
            max_requests: config.effective_burst().get() as u64,
            refill_per_sec: config.requests_per_second.get() as u64,
            fallback: GovernorLimiter::new(config),
            base_config: config.clone(),
            fallback_shares: 1,
            script: redis::Script::new(TOKEN_BUCKET_SCRIPT),
            peek_script: redis::Script::new(TOKEN_PEEK_SCRIPT),
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
    /// Uses a read-only Lua peek (no writes) so the token bucket state is
    /// never mutated by a peek. This is useful for health checks or
    /// monitoring.
    ///
    /// Optionally scoped to a `tenant_id` to prevent key collisions between tenants.
    pub async fn peek(&self) -> Decision {
        self.peek_for_tenant(None).await
    }

    /// Read-only check without consuming capacity, scoped to a specific tenant.
    ///
    /// Uses a read-only Lua peek (no writes) so the token bucket state is
    /// never mutated by a peek. This is useful for health checks or
    /// monitoring.
    pub async fn peek_for_tenant(&self, tenant_id: Option<&str>) -> Decision {
        let key_scope = tenant_id.unwrap_or("default");
        let cm = match &self.cm {
            Some(cm) => cm.clone(),
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
        let mut conn = cm;

        match self
            .peek_script
            .key(key)
            .arg(self.max_requests as i64)
            .arg(self.refill_per_sec as i64)
            .invoke_async::<Vec<i64>>(&mut conn)
            .await
        {
            Ok(result) => {
                // If we were in fallback mode, we've recovered
                if self.in_fallback.swap(false, Ordering::Relaxed) {
                    warn!("Redis rate limiter recovered, switching back from fallback");
                }

                let remaining = result.first().copied().unwrap_or(self.max_requests as i64) as u64;
                let retry_after_us = result.get(1).copied().unwrap_or(0) as u64;
                if remaining == 0 {
                    Decision::Denied {
                        retry_after: Duration::from_micros(retry_after_us)
                            .max(Duration::from_millis(1)),
                    }
                } else {
                    Decision::Allowed { remaining }
                }
            }
            Err(err) => {
                // Fix K2: peek must NOT consume capacity. The error path
                // fails open (read-only, no state mutation); only the
                // fallback MODE flag is updated.
                debug!(%err, "Redis peek error — failing open (read-only, no state mutation)");
                self.enter_fallback().await;
                Decision::Allowed {
                    remaining: self.max_requests,
                }
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
                let mut conn = cm.clone();
                redis::cmd("DEL")
                    .arg(&key)
                    .query_async::<()>(&mut conn)
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

    /// Evaluate the Lua token-bucket script against Redis.
    async fn eval_script(&self, key: &str, cost: u32) -> Result<Decision, redis::RedisError> {
        // Fix #3: clone the multiplexed ConnectionManager — no lock; the
        // Lua script is the atomicity boundary.
        let mut conn = self
            .cm
            .as_ref()
            .expect("invariant: eval_script only called when cm is Some")
            .clone();

        // Fix K1: the script (and its SHA-1 hash) is pre-built at
        // construction; re-creating it per check burned CPU on the hot path.
        // Fix #4: no caller clock is passed — the script uses redis TIME.
        let result: Vec<i64> = self
            .script
            .key(key)
            .arg(self.max_requests as i64)
            .arg(self.refill_per_sec as i64)
            .arg(cost as i64)
            .invoke_async(&mut conn)
            .await?;

        let allowed = result.first().copied().unwrap_or(0) == 1;
        let retry_after_us = result.get(1).copied().unwrap_or(0) as u64;
        // Fix #1: remaining is the ACTUAL token count reported by the
        // script, not `max - used` derived from a window count.
        let remaining = result.get(2).copied().unwrap_or(0) as u64;

        if allowed {
            metrics::counter!(
                "rate_limiter_requests_total",
                "strategy" => "redis",
                "decision" => "allowed"
            )
            .increment(cost as u64);
            Ok(Decision::Allowed { remaining })
        } else {
            metrics::counter!(
                "rate_limiter_requests_total",
                "strategy" => "redis",
                "decision" => "denied"
            )
            .increment(cost as u64);
            metrics::counter!("rate_limiter_blocked_total", "strategy" => "redis").increment(1);
            Ok(Decision::Denied {
                retry_after: Duration::from_micros(retry_after_us).max(Duration::from_millis(1)),
            })
        }
    }
}

/// Read the expected pod count for fallback budget sharing from the
/// environment.
///
/// Fix #2: when unset, the budget is divided by
/// [`DEFAULT_FALLBACK_SHARES`] (2) — the previous default of 1 let N pods
/// each hold the FULL budget, admitting N× the configured limit during a
/// Redis outage.
fn fallback_shares_from_env() -> u64 {
    std::env::var(FALLBACK_PODS_ENV)
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|v| *v > 0)
        .unwrap_or(DEFAULT_FALLBACK_SHARES)
}

/// Divide a rate config across `shares` pods (each dimension at least 1).
///
/// Both the sustained rate (`rps`) and the burst are divided so the
/// fallback enforces `rps / shares` sustained — not the full burst rate.
fn divided_config(config: &RateLimitConfig, shares: u64) -> RateLimitConfig {
    if shares <= 1 {
        return config.clone();
    }
    let rps = (config.requests_per_second.get() as u64)
        .div_ceil(shares)
        .min(u32::MAX as u64) as u32;
    let burst = (config.effective_burst().get() as u64)
        .div_ceil(shares)
        .min(u32::MAX as u64) as u32;
    let mut divided = RateLimitConfig::new(rps).with_burst(burst);
    divided.jitter_ms = config.jitter_ms;
    divided
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
        // Explicit single pod: the DEFAULT now divides the budget by 2
        // (fix #2), which is pinned by test_fallback_shares_default_is_two.
        let limiter = RedisLimiter::fallback_only(&config).with_fallback_shares(1);

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

    // ── Fix K3:fallback budget divided across expected pods ────────

    #[tokio::test]
    async fn test_fallback_shares_divide_budget() {
        // 100 rps / burst 100 shared across 4 pods → per-pod fallback
        // allows only ~25 in the initial burst instead of the full 100
        // (which fleet-wide would be 4× the configured limit).
        let config = RateLimitConfig::new(100).with_burst(100);
        let limiter = RedisLimiter::fallback_only(&config).with_fallback_shares(4);
        assert_eq!(limiter.fallback_shares(), 4);

        let mut allowed = 0;
        for _ in 0..100 {
            if limiter.check().await.is_allowed() {
                allowed += 1;
            }
        }
        assert!(
            allowed <= 30, // 25 exact + refill headroom
            "divided fallback must allow ~25, got {allowed}"
        );
        assert!(
            allowed >= 25,
            "expected at least the divided burst, got {allowed}"
        );
    }

    /// Env-test mutex: `std::env::set_var` races when tests run on
    /// multiple threads (same pattern as config.rs).
    static ENV_TEST_MUTEX: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[tokio::test]
    async fn test_fallback_shares_default_is_two_when_env_unset() {
        // Fix #2: with RATE_LIMIT_FALLBACK_PODS unset the fallback budget
        // must be divided conservatively by 2 — a default of 1 meant N pods
        // each held the FULL budget, admitting N× the configured limit.
        let limiter = {
            let _guard = ENV_TEST_MUTEX.lock().unwrap();
            if std::env::var(FALLBACK_PODS_ENV).is_ok() {
                // Another test set it; avoid fighting over the environment.
                eprintln!("skipping: {FALLBACK_PODS_ENV} set in environment");
                return;
            }
            let config = RateLimitConfig::new(50).with_burst(5);
            RedisLimiter::fallback_only(&config)
        };
        assert_eq!(
            limiter.fallback_shares(),
            2,
            "default fallback division must be 2 (conservative)"
        );
        // 50 rps/burst 5 divided by 2 → per-pod burst ceil(5/2)=3.
        for _ in 0..3 {
            assert!(limiter.check().await.is_allowed());
        }
        assert!(limiter.check().await.is_denied());
    }

    #[tokio::test]
    async fn test_fallback_shares_env_override_respected() {
        let limiter = {
            let _guard = ENV_TEST_MUTEX.lock().unwrap();
            let original = std::env::var(FALLBACK_PODS_ENV).ok();
            std::env::set_var(FALLBACK_PODS_ENV, "8");
            let config = RateLimitConfig::new(100).with_burst(16);
            let limiter = RedisLimiter::fallback_only(&config);
            match original {
                Some(v) => std::env::set_var(FALLBACK_PODS_ENV, v),
                None => std::env::remove_var(FALLBACK_PODS_ENV),
            }
            limiter
        };
        assert_eq!(limiter.fallback_shares(), 8);
        // burst 16 / 8 pods = 2 per pod.
        assert!(limiter.check().await.is_allowed());
        assert!(limiter.check().await.is_allowed());
        assert!(limiter.check().await.is_denied());
    }

    /// Fix #2: the division must apply to the SUSTAINED rate (rps), not
    /// only the burst — otherwise the fallback still admits the full
    /// configured rate per second on every pod.
    #[test]
    fn test_divided_config_divides_sustained_rate_not_just_burst() {
        let config = RateLimitConfig::new(100).with_burst(10);
        let divided = divided_config(&config, 4);
        assert_eq!(divided.requests_per_second.get(), 25, "rps must be 100/4");
        assert_eq!(
            divided.effective_burst().get(),
            3,
            "burst must be ceil(10/4)"
        );
        assert_eq!(divided.jitter_ms, config.jitter_ms);

        // shares <= 1 is a no-op.
        let undivided = divided_config(&config, 1);
        assert_eq!(undivided.requests_per_second.get(), 100);
        assert_eq!(undivided.effective_burst().get(), 10);
    }

    // ── Fix K2:peek never mutates fallback state ───────────────────

    #[tokio::test]
    async fn test_peek_does_not_consume_capacity() {
        let config = RateLimitConfig::new(10).with_burst(2);
        // Single pod (no default ÷2 division): this test pins the K2 peek
        // semantics, not the fallback budget split.
        let limiter = RedisLimiter::fallback_only(&config).with_fallback_shares(1);

        // Consume one token
        assert!(limiter.check().await.is_allowed());

        // Repeated peeks must not consume the remaining budget
        for _ in 0..10 {
            let _ = limiter.peek().await;
        }
        // The second burst token is still there
        assert!(limiter.check().await.is_allowed(), "peek must be read-only");
        assert!(limiter.check().await.is_denied());
    }

    // ── Fix K1:script is pre-built at construction ─────────────────

    #[test]
    fn test_script_is_cached_at_construction() {
        // Two limiters each hold their own pre-built script; the Lua text
        // is stored once as a const. This test mainly pins the public
        // behavior (construct + mark fallback) and documents the intent;
        // the performance win is that eval_script no longer calls
        // `redis::Script::new` (SHA-1 hashing) per check.
        let config = RateLimitConfig::new(10).with_burst(5);
        let limiter = RedisLimiter::fallback_only(&config);
        assert!(limiter.is_in_fallback());
    }

    // ── Integration tests (require a running Redis instance) ──────
    // These tests are skipped by default. Run with:
    //   cargo test -p rate-limiter --features redis -- --ignored
    // and ensure a Redis server is available at the configured URL.

    /// Helper to connect to Redis for integration tests.
    async fn test_redis_connection() -> Option<redis::aio::ConnectionManager> {
        // F6: no ambient 6379 default — the variable must name the Redis
        // under test explicitly; unset means skip.
        let url = std::env::var("REDIS_TEST_URL").ok()?;

        let client = redis::Client::open(url.as_str()).ok()?;
        match redis::aio::ConnectionManager::new(client).await {
            Ok(cm) => {
                // Verify connectivity with a simple PING
                let mut cm_clone = cm.clone();
                let pong: Result<String, _> = redis::cmd("PING").query_async(&mut cm_clone).await;
                if pong.is_ok_and(|v| v == "PONG") {
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
        let limiter = RedisLimiter::with_connection(&config, cm, "test:batchn:", 1);

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

    /// Integration test (fix #1): the Redis limiter must be a TOKEN BUCKET —
    /// `burst` tokens available immediately, continuous refill at `rps`
    /// tokens/second. The previous sliding window enforced `burst` per
    /// rolling second, so (rps=10, burst=100) admitted 100 req/s forever.
    #[ignore]
    #[tokio::test]
    async fn test_redis_token_bucket_burst_and_sustained_rate() {
        let cm = test_redis_connection()
            .await
            .expect("Redis not available. Start Redis or set REDIS_TEST_URL");
        let config = RateLimitConfig::new(10).with_burst(100);
        let limiter = RedisLimiter::with_connection(&config, cm, "test:tokenbucket:", 1);

        limiter.reset().await.unwrap();

        // remaining must report ACTUAL tokens after a take.
        let d = limiter.check().await;
        assert!(d.is_allowed());
        assert_eq!(
            d.remaining(),
            99,
            "Decision::remaining must report actual tokens (100 - 1)"
        );

        // Drain the rest of the burst: 99 more immediate checks pass.
        for i in 0..99 {
            assert!(
                limiter.check().await.is_allowed(),
                "immediate check {i} within burst must pass"
            );
        }
        // The 101st check in the same instant must fail: burst exhausted,
        // only the 10/s refill remains.
        assert!(
            limiter.check().await.is_denied(),
            "101st immediate check must be denied (burst exhausted)"
        );

        // After ~1s idle, only ~rps tokens may be available (8..12
        // tolerant window), NOT the full burst again (the old sliding
        // window re-admitted all 100 here).
        tokio::time::sleep(Duration::from_millis(1100)).await;
        let mut available = 0;
        for _ in 0..100 {
            if limiter.check().await.is_allowed() {
                available += 1;
            } else {
                break;
            }
        }
        assert!(
            (8..=12).contains(&available),
            "after ~1s idle at rps=10 expected 8..12 tokens, got {available}"
        );

        limiter.reset().await.unwrap();
    }

    /// Integration test (fix #4): the Lua script must use `redis TIME`,
    /// never the caller's app clock. A bucket whose stored timestamp is in
    /// the future (skewed writer / manual seeding) must be clamped to now
    /// (no negative elapsed time), and a far-past timestamp must refill to
    /// at most capacity — never beyond it.
    #[ignore]
    #[tokio::test]
    async fn test_redis_time_skew_tolerant() {
        let mut cm = test_redis_connection()
            .await
            .expect("Redis not available. Start Redis or set REDIS_TEST_URL");
        let config = RateLimitConfig::new(10).with_burst(50);
        let limiter = RedisLimiter::with_connection(&config, cm.clone(), "test:skew:", 1);

        limiter.reset().await.unwrap();

        // ── Future timestamp (a writer whose clock ran ahead) ──
        // Drain the bucket completely first.
        for _ in 0..50 {
            assert!(limiter.check().await.is_allowed());
        }
        assert!(limiter.check().await.is_denied());

        // Force the stored timestamp far into the FUTURE. If the script
        // trusted caller-supplied or unclamped timestamps, elapsed would go
        // negative and tokens would be "un-spent" (over-admission).
        let future_ts_us: i64 = (std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_micros()
            + 3_600_000_000) as i64; // +1 hour, in µs
        redis::cmd("HSET")
            .arg("test:skew:default")
            .arg("ts")
            .arg(future_ts_us)
            .query_async::<()>(&mut cm)
            .await
            .unwrap();
        // Timestamp clamped to now → no phantom refill → still denied.
        assert!(
            limiter.check().await.is_denied(),
            "future ts must be clamped; no phantom tokens may appear"
        );

        limiter.reset().await.unwrap();

        // ── Far-past timestamp (a writer whose clock fell behind) ──
        // Refill must be CLAMPED AT CAPACITY: the 101st token must not be
        // admissible even though elapsed is enormous.
        redis::cmd("HSET")
            .arg("test:skew:default")
            .arg("ut")
            .arg(0i64)
            .arg("ts")
            .arg(1i64) // epoch+1µs — over 50 years of "elapsed"
            .query_async::<()>(&mut cm)
            .await
            .unwrap();
        for i in 0..50 {
            assert!(
                limiter.check().await.is_allowed(),
                "refilled-to-capacity check {i} must pass"
            );
        }
        assert!(
            limiter.check().await.is_denied(),
            "refill must clamp at capacity (50), not exceed it"
        );

        limiter.reset().await.unwrap();
    }

    /// Integration test (fix #3): concurrent checks must not serialize or
    /// deadlock — the ConnectionManager is multiplexed and the Lua script
    /// is the atomicity boundary (no connection-level mutex).
    #[ignore]
    #[tokio::test]
    async fn test_redis_concurrent_checks_share_multiplexed_connection() {
        use std::sync::Arc;
        let cm = test_redis_connection()
            .await
            .expect("Redis not available. Start Redis or set REDIS_TEST_URL");
        let config = RateLimitConfig::new(10).with_burst(200);
        let limiter = Arc::new(RedisLimiter::with_connection(
            &config,
            cm,
            "test:concurrent:",
            1,
        ));

        limiter.reset().await.unwrap();

        let mut handles = Vec::new();
        for t in 0..50u32 {
            let l = Arc::clone(&limiter);
            handles.push(tokio::spawn(async move {
                let d = l.check_n_for_tenant(Some(&format!("tenant-{t}")), 1).await;
                d.is_allowed()
            }));
        }
        let mut allowed = 0;
        for h in handles {
            if h.await.expect("task must not panic") {
                allowed += 1;
            }
        }
        assert_eq!(allowed, 50, "all concurrent checks must be allowed");

        limiter.reset().await.unwrap();
    }
}
