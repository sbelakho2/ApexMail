//! Rate limiting:sliding window, token bucket, quota enforcement.

use chrono::{Duration, Utc};
use deadpool_redis::Pool as RedisPool;
use redis::AsyncCommands;
use std::sync::OnceLock;
use tracing::info;

use crate::config::QuotaConfig;
use crate::types::*;

// ── Rate Limit Service ─────────────────────────────────────

// Fix (rate-limiter K1 pattern): `redis::Script::new` computes the
// script's SHA-1 on every construction. These were previously rebuilt on
// EVERY request, burning CPU on the hot path. `Script::invoke` only needs
// `&self` (it clones internally), so a `&'static Script` behind a
// `OnceLock` is safe to share across requests.

/// Sliding-window check script (atomic prune + count + conditional add).
static SLIDING_WINDOW_SCRIPT: OnceLock<redis::Script> = OnceLock::new();

fn sliding_window_script() -> &'static redis::Script {
    SLIDING_WINDOW_SCRIPT.get_or_init(|| {
        redis::Script::new(
            r#"
            local key = KEYS[1]
            local now = tonumber(ARGV[1])
            local windowStart = tonumber(ARGV[2])
            local maxRequests = tonumber(ARGV[3])
            local member = ARGV[4]
            local windowMs = tonumber(ARGV[5])

            redis.call('ZREMRANGEBYSCORE', key, '-inf', windowStart)
            local count = tonumber(redis.call('ZCARD', key))
            if count >= maxRequests then
                redis.call('PEXPIRE', key, windowMs)
                return {0, count}
            end

            redis.call('ZADD', key, now, member)
            redis.call('PEXPIRE', key, windowMs)
            return {1, count + 1}
        "#,
        )
    })
}

/// Token-bucket check script (atomic refill + take).
///
/// The key TTL is derived from the ACTUAL refill math: a bucket refills
/// from empty to full in `capacity / refill_rate` refill intervals, i.e.
/// `(capacity / refill_rate) * refill_interval_ms` milliseconds (plus a
/// 1s buffer). The previous hard-coded `refillInterval * capacity + 1000`
/// was dimensionally wrong (ms × tokens) whenever `refill_rate != 1`.
static TOKEN_BUCKET_SCRIPT: OnceLock<redis::Script> = OnceLock::new();

fn token_bucket_script() -> &'static redis::Script {
    TOKEN_BUCKET_SCRIPT.get_or_init(|| {
        redis::Script::new(
            r#"
            local key = KEYS[1]
            local capacity = tonumber(ARGV[1])
            local refillRate = tonumber(ARGV[2])
            local refillInterval = tonumber(ARGV[3])
            local requested = tonumber(ARGV[4])
            local now = tonumber(ARGV[5])

            local data = redis.call('HMGET', key, 'tokens', 'lastRefill')
            local tokens = tonumber(data[1]) or capacity
            local lastRefill = tonumber(data[2]) or now

            local elapsed = now - lastRefill
            local refills = math.floor(elapsed / refillInterval)
            if refills > 0 then
                tokens = math.min(capacity, tokens + refills * refillRate)
                lastRefill = lastRefill + refills * refillInterval
            end

            local allowed = 0
            if tokens >= requested then
                tokens = tokens - requested
                allowed = 1
            end

            redis.call('HMSET', key, 'tokens', tokens, 'lastRefill', lastRefill)
            -- TTL from the real refill math (see TOKEN_BUCKET_SCRIPT docs).
            local ttlMs = 61000
            if refillRate > 0 then
                ttlMs = math.ceil((capacity / refillRate) * refillInterval) + 1000
            end
            redis.call('PEXPIRE', key, ttlMs)

            return {allowed, math.floor(tokens), lastRefill}
        "#,
        )
    })
}

/// Resource-limit check script (atomic increment-under-limit).
static RESOURCE_LIMIT_SCRIPT: OnceLock<redis::Script> = OnceLock::new();

fn resource_limit_script() -> &'static redis::Script {
    RESOURCE_LIMIT_SCRIPT.get_or_init(|| {
        redis::Script::new(
            r#"
            local key = KEYS[1]
            local increment = tonumber(ARGV[1])
            local limit = tonumber(ARGV[2])

            if increment < 0 then
                increment = 0
            end

            local current = tonumber(redis.call('GET', key) or '0')
            local projected = current + increment

            if projected > limit then
                return {0, current}
            end

            if increment > 0 then
                current = tonumber(redis.call('INCRBY', key, increment))
            end

            return {1, current}
        "#,
        )
    })
}

pub struct RateLimitService {
    redis: RedisPool,
}

impl RateLimitService {
    pub fn new(redis: RedisPool) -> Self {
        Self { redis }
    }

    /// Sliding-window rate limit using Redis sorted sets.
    pub async fn check_rate_limit(
        &self,
        key: &str,
        config: &RateLimitConfig,
    ) -> anyhow::Result<RateLimitResult> {
        let prefix = config.key_prefix.as_deref().unwrap_or("ratelimit");
        let redis_key = format!("{}:{}", prefix, key);
        let now = Utc::now();
        let window_start = now - Duration::milliseconds(config.window_ms);
        let now_ms = now.timestamp_millis();
        let window_start_ms = window_start.timestamp_millis();
        let member = format!("{}:{}", now_ms, uuid::Uuid::new_v4());

        let mut conn = self.redis.get().await?;

        let result: Vec<i64> = sliding_window_script()
            .key(&redis_key)
            .arg(now_ms)
            .arg(window_start_ms)
            .arg(config.max_requests)
            .arg(&member)
            .arg(config.window_ms)
            .invoke_async(&mut *conn)
            .await?;

        let allowed = result.first().copied().unwrap_or(0) == 1;
        let count = result.get(1).copied().unwrap_or(0);
        let reset_at = now + Duration::milliseconds(config.window_ms);

        let remaining = (config.max_requests - count).max(0);
        let retry_after = if allowed {
            None
        } else {
            Some(config.window_ms / 1000)
        };

        Ok(RateLimitResult {
            allowed,
            remaining,
            reset_at,
            retry_after,
            limit: config.max_requests,
        })
    }

    /// Token bucket using a Lua script for atomicity.
    pub async fn check_token_bucket(
        &self,
        key: &str,
        config: &TokenBucketConfig,
        tokens_requested: i64,
    ) -> anyhow::Result<RateLimitResult> {
        let redis_key = format!("tokenbucket:{}", key);
        let now = Utc::now();
        let now_ms = now.timestamp_millis();

        let mut conn = self.redis.get().await?;

        // Pass refill_rate as f64 (previously truncated via `as i64`, so
        // fractional refill rates collapsed to 0 = bucket never refilled).
        let result: Vec<i64> = token_bucket_script()
            .key(&redis_key)
            .arg(config.capacity)
            .arg(config.refill_rate)
            .arg(config.refill_interval_ms)
            .arg(tokens_requested)
            .arg(now_ms)
            .invoke_async(&mut *conn)
            .await?;

        let allowed = result.first().copied().unwrap_or(0) == 1;
        let remaining = result.get(1).copied().unwrap_or(0);
        let next_refill_ms = config.refill_interval_ms;

        let retry_after = if allowed {
            None
        } else {
            Some(next_refill_ms / 1000)
        };

        Ok(RateLimitResult {
            allowed,
            remaining,
            reset_at: now + Duration::milliseconds(next_refill_ms),
            retry_after,
            limit: config.capacity,
        })
    }

    /// Check workspace quota for a specific metric.
    pub async fn check_workspace_quota(
        &self,
        workspace_id: &str,
        metric: &str,
        quota: &QuotaConfig,
        increment: i64,
    ) -> anyhow::Result<RateLimitResult> {
        match metric {
            "api_requests_per_minute" => {
                let config = RateLimitConfig {
                    window_ms: 60_000,
                    max_requests: quota.api_requests_per_minute,
                    burst_limit: Some(quota.api_requests_per_minute / 10),
                    key_prefix: Some("workspace:api".into()),
                };
                self.check_rate_limit(&format!("{}:api", workspace_id), &config)
                    .await
            }
            "emails_per_month" => {
                let config = RateLimitConfig {
                    window_ms: 30 * 24 * 60 * 60 * 1000, // 30 days
                    max_requests: quota.emails_per_month,
                    burst_limit: None,
                    key_prefix: Some("workspace:email".into()),
                };
                self.check_rate_limit(&format!("{}:email", workspace_id), &config)
                    .await
            }
            "webhooks_per_month" => {
                let config = RateLimitConfig {
                    window_ms: 30 * 24 * 60 * 60 * 1000,
                    max_requests: quota.webhooks_per_month,
                    burst_limit: None,
                    key_prefix: Some("workspace:webhook".into()),
                };
                self.check_rate_limit(&format!("{}:webhook", workspace_id), &config)
                    .await
            }
            "contacts" | "templates" | "domains" | "storage_bytes" => {
                self.check_resource_limit(workspace_id, metric, get_limit(quota, metric), increment)
                    .await
            }
            _ => anyhow::bail!("Unknown quota metric: {}", metric),
        }
    }

    /// Read-only rate limit status.
    pub async fn get_rate_limit_status(
        &self,
        key: &str,
        config: &RateLimitConfig,
    ) -> anyhow::Result<RateLimitResult> {
        let prefix = config.key_prefix.as_deref().unwrap_or("ratelimit");
        let redis_key = format!("{}:{}", prefix, key);
        let now = Utc::now();
        let window_start = now - Duration::milliseconds(config.window_ms);
        let window_start_ms = window_start.timestamp_millis() as f64;

        let mut conn = self.redis.get().await?;

        // Remove expired entries and count
        let _: () = conn
            .zrembyscore(&redis_key, "-inf", window_start_ms)
            .await?;
        let count: i64 = conn.zcard(&redis_key).await?;

        let remaining = (config.max_requests - count).max(0);
        let reset_at = now + Duration::milliseconds(config.window_ms);

        Ok(RateLimitResult {
            allowed: count < config.max_requests,
            remaining,
            reset_at,
            retry_after: None,
            limit: config.max_requests,
        })
    }

    /// Reset a rate limit key.
    pub async fn reset_rate_limit(
        &self,
        key: &str,
        key_prefix: Option<&str>,
    ) -> anyhow::Result<()> {
        let prefix = key_prefix.unwrap_or("ratelimit");
        let redis_key = format!("{}:{}", prefix, key);
        let mut conn = self.redis.get().await?;
        let _: () = conn.del(&redis_key).await?;
        info!(key = redis_key, "Rate limit reset");
        Ok(())
    }

    /// Get rate limit configs for a workspace based on quota.
    pub fn get_workspace_rate_limit_configs(
        quota: &QuotaConfig,
    ) -> std::collections::HashMap<String, RateLimitConfig> {
        let mut configs = std::collections::HashMap::new();
        configs.insert(
            "api".into(),
            RateLimitConfig {
                window_ms: 60_000,
                max_requests: quota.api_requests_per_minute,
                burst_limit: Some(quota.api_requests_per_minute / 10),
                key_prefix: Some("workspace:api".into()),
            },
        );
        configs.insert(
            "email".into(),
            RateLimitConfig {
                window_ms: 30 * 24 * 60 * 60 * 1000,
                max_requests: quota.emails_per_month,
                burst_limit: None,
                key_prefix: Some("workspace:email".into()),
            },
        );
        configs.insert(
            "webhook".into(),
            RateLimitConfig {
                window_ms: 30 * 24 * 60 * 60 * 1000,
                max_requests: quota.webhooks_per_month,
                burst_limit: None,
                key_prefix: Some("workspace:webhook".into()),
            },
        );
        configs
    }

    // ── Resource Limits (non-time-based) ───────────────────

    async fn check_resource_limit(
        &self,
        workspace_id: &str,
        metric: &str,
        limit: i64,
        increment: i64,
    ) -> anyhow::Result<RateLimitResult> {
        let redis_key = format!("workspace:{}:resource:{}", workspace_id, metric);
        let mut conn = self.redis.get().await?;

        let result: Vec<i64> = resource_limit_script()
            .key(&redis_key)
            .arg(increment)
            .arg(limit)
            .invoke_async(&mut *conn)
            .await?;

        let allowed = result.first().copied().unwrap_or(0) == 1;
        let current = result.get(1).copied().unwrap_or(0);

        Ok(RateLimitResult {
            allowed,
            remaining: (limit - current).max(0),
            reset_at: Utc::now(), // N/A for resource limits
            retry_after: None,
            limit,
        })
    }

    /// Increment a resource counter.
    pub async fn increment_resource_count(
        &self,
        workspace_id: &str,
        metric: &str,
        amount: i64,
    ) -> anyhow::Result<i64> {
        let redis_key = format!("workspace:{}:resource:{}", workspace_id, metric);
        let mut conn = self.redis.get().await?;
        let new_val: i64 = conn.incr(&redis_key, amount).await?;
        Ok(new_val)
    }

    /// Decrement a resource counter (floor at 0).
    pub async fn decrement_resource_count(
        &self,
        workspace_id: &str,
        metric: &str,
        amount: i64,
    ) -> anyhow::Result<i64> {
        let redis_key = format!("workspace:{}:resource:{}", workspace_id, metric);
        let mut conn = self.redis.get().await?;
        let current: Option<i64> = conn.get(&redis_key).await?;
        let current = current.unwrap_or(0);
        let new_val = (current - amount).max(0);
        let _: () = conn.set(&redis_key, new_val).await?;
        Ok(new_val)
    }

    /// Set a resource count directly.
    pub async fn set_resource_count(
        &self,
        workspace_id: &str,
        metric: &str,
        count: i64,
    ) -> anyhow::Result<()> {
        let redis_key = format!("workspace:{}:resource:{}", workspace_id, metric);
        let mut conn = self.redis.get().await?;
        let _: () = conn.set(&redis_key, count).await?;
        Ok(())
    }
}

fn get_limit(quota: &QuotaConfig, metric: &str) -> i64 {
    match metric {
        "contacts" => quota.contacts_limit,
        "templates" => quota.templates_limit,
        "domains" => quota.domains_limit,
        "storage_bytes" => quota.storage_bytes,
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_limit() {
        let q = QuotaConfig::default();
        assert_eq!(get_limit(&q, "contacts"), 10_000);
        assert_eq!(get_limit(&q, "templates"), 100);
        assert_eq!(get_limit(&q, "domains"), 5);
        assert_eq!(get_limit(&q, "storage_bytes"), 1_073_741_824);
        assert_eq!(get_limit(&q, "unknown"), 0);
    }

    #[test]
    fn test_workspace_rate_limit_configs() {
        let q = QuotaConfig::default();
        let configs = RateLimitService::get_workspace_rate_limit_configs(&q);
        assert_eq!(configs.len(), 3);
        assert!(configs.contains_key("api"));
        assert!(configs.contains_key("email"));
        assert!(configs.contains_key("webhook"));

        let api = &configs["api"];
        assert_eq!(api.window_ms, 60_000);
        assert_eq!(api.max_requests, 100);
        assert_eq!(api.burst_limit, Some(10));
    }

    #[test]
    fn test_rate_limit_config_defaults() {
        let q = QuotaConfig {
            api_requests_per_minute: 200,
            emails_per_month: 100_000,
            webhooks_per_month: 20_000,
            ..QuotaConfig::default()
        };
        let configs = RateLimitService::get_workspace_rate_limit_configs(&q);
        assert_eq!(configs["api"].max_requests, 200);
        assert_eq!(configs["api"].burst_limit, Some(20));
        assert_eq!(configs["email"].max_requests, 100_000);
    }

    // ── Fix:Lua scripts cached in OnceLock (no per-call SHA-1) ─────

    #[test]
    fn test_lua_scripts_cached_and_shared() {
        // `redis::Script::new` computes the SHA-1 per construction; the
        // scripts must be cached so repeated requests reuse one instance.
        assert!(std::ptr::eq(
            sliding_window_script(),
            sliding_window_script()
        ));
        assert!(std::ptr::eq(token_bucket_script(), token_bucket_script()));
        assert!(std::ptr::eq(
            resource_limit_script(),
            resource_limit_script()
        ));
        // And each script is a distinct object.
        assert!(!std::ptr::eq(
            sliding_window_script() as *const _,
            token_bucket_script() as *const _
        ));
    }

    /// Expected token-bucket key TTL derived from the refill math:
    /// refilling from empty to full takes `capacity / refill_rate`
    /// intervals of `refill_interval_ms` ms, plus a 1s buffer.
    fn expected_bucket_ttl_ms(config: &TokenBucketConfig) -> i64 {
        ((config.capacity as f64 / config.refill_rate) as i64) * config.refill_interval_ms + 1000
    }

    /// Integration test (gated on REDIS_TEST_URL — no ambient default):
    /// pins that the token bucket key TTL follows the refill math
    /// `(capacity / refill_rate) * refill_interval_ms + 1000` and NOT the
    /// dimensionally wrong `refill_interval_ms * capacity + 1000`.
    #[tokio::test]
    async fn test_token_bucket_ttl_derived_from_refill_math() {
        let Ok(url) = std::env::var("REDIS_TEST_URL") else {
            eprintln!("skipping: REDIS_TEST_URL not set");
            return;
        };
        let pool = deadpool_redis::Config::from_url(url)
            .create_pool(None)
            .expect("valid pool config");
        let service = RateLimitService::new(pool);

        // capacity 10, 2 tokens per 500ms interval → full refill in
        // (10/2)*500 = 2500ms → TTL ≈ 3500ms. The OLD buggy formula gave
        // 500*10+1000 = 6000ms.
        let config = TokenBucketConfig {
            capacity: 10,
            refill_rate: 2.0,
            refill_interval_ms: 500,
        };
        let key = "ttl-pin-test";
        let redis_key = format!("tokenbucket:{key}");

        let mut conn = service.redis.get().await.expect("redis conn");
        let _: () = conn.del(&redis_key).await.expect("clean slate");

        let result = service
            .check_token_bucket(key, &config, 1)
            .await
            .expect("bucket check");
        assert!(result.allowed);

        let ttl_ms: i64 = conn.pttl(&redis_key).await.expect("PTTL after check");
        let expected = expected_bucket_ttl_ms(&config);
        assert_eq!(expected, 3500, "sanity: expected TTL is 3500ms");
        // Redis TTLs tick down; allow a small margin for elapsed time.
        assert!(
            (3300..=3500).contains(&ttl_ms),
            "TTL must follow refill math (~3500ms), got {ttl_ms}ms"
        );

        let _: () = conn.del(&redis_key).await.expect("cleanup");
    }
}
