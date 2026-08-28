//! Redis-backed cache utilities.

use deadpool_redis::{redis::AsyncCommands, Pool as RedisPool};
use serde::{de::DeserializeOwned, Serialize};
use std::time::Duration;

/// Get a cached JSON value from Redis.
pub async fn cache_get<T: DeserializeOwned>(redis: &RedisPool, key: &str) -> Option<T> {
    let mut conn = redis.get().await.ok()?;
    let raw: Option<String> = conn.get(key).await.ok()?;
    raw.and_then(|s| serde_json::from_str(&s).ok())
}

/// Set a JSON value in Redis with TTL.
pub async fn cache_set<T: Serialize>(
    redis: &RedisPool,
    key: &str,
    value: &T,
    ttl: Duration,
) -> Result<(), anyhow::Error> {
    let json = serde_json::to_string(value)?;
    let mut conn = redis.get().await?;
    let _: () = conn.set_ex(key, &json, ttl.as_secs()).await?;
    Ok(())
}

/// Delete a cache key.
pub async fn cache_del(redis: &RedisPool, key: &str) -> Result<(), anyhow::Error> {
    let mut conn = redis.get().await?;
    let _: () = conn.del(key).await?;
    Ok(())
}

/// Atomic increment with expiry (for rate limiting counters).
/// #218:Uses Lua script for atomic INCR + conditional EXPIRE
///
/// The EXPIRE is applied when the counter is first created (INCR == 1)
/// AND when the key exists without a TTL (TTL == -1): a pre-existing
/// no-TTL key would otherwise become a PERMANENT counter (permanent
/// lockouts / key leak) after a single increment.
pub async fn cache_incr_with_ttl(
    redis: &RedisPool,
    key: &str,
    ttl_secs: u64,
) -> Result<i64, anyhow::Error> {
    let mut conn = redis.get().await?;
    // Atomic Lua script:INCR, then EXPIRE if first increment (count == 1)
    // or if the key currently has no TTL at all (-1).
    let script = redis::Script::new(
        r#"
        local count = redis.call('INCR', KEYS[1])
        local ttl = redis.call('TTL', KEYS[1])
        if count == 1 or ttl == -1 then
            redis.call('EXPIRE', KEYS[1], ARGV[1])
        end
        return count
        "#,
    );
    let count: i64 = script
        .key(key)
        .arg(ttl_secs)
        .invoke_async(&mut *conn)
        .await?;
    Ok(count)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cache_key_format() {
        let key = format!("apexmail:cache:{}:{}", "tenant_123", "messages");
        assert_eq!(key, "apexmail:cache:tenant_123:messages");
    }

    #[test]
    fn test_ttl_duration() {
        let ttl = Duration::from_secs(3600);
        assert_eq!(ttl.as_secs(), 3600);
    }

    /// Helper: build a deadpool pool from `REDIS_TEST_URL` (no ambient
    /// default; unset means skip), mirroring the rate-limiter convention.
    async fn test_pool() -> Option<RedisPool> {
        let url = std::env::var("REDIS_TEST_URL").ok()?;
        deadpool_redis::Config::from_url(url).create_pool(None).ok()
    }

    /// Fix #6 (fail-first): a PRE-EXISTING key with NO TTL must not become
    /// a PERMANENT counter. `cache_incr_with_ttl` used to apply EXPIRE only
    /// when INCR returned 1, so incrementing an already-present no-TTL key
    /// (e.g. created by a plain SET/INCR elsewhere) left it live forever —
    /// permanent lockouts and a slow leak of counter keys.
    #[tokio::test]
    async fn test_incr_with_ttl_sets_ttl_on_preexisting_persistent_key() {
        let Some(pool) = test_pool().await else {
            eprintln!("skipping: REDIS_TEST_URL not set");
            return;
        };
        let key = "apexmail:cache:test:incr-persistent";

        // Seed a counter WITHOUT a TTL, as another code path might.
        {
            let mut conn = pool.get().await.expect("conn");
            let _: () = redis::cmd("SET")
                .arg(key)
                .arg(5i64)
                .query_async(&mut conn)
                .await
                .expect("seed");
        }

        let count = cache_incr_with_ttl(&pool, key, 60).await.expect("incr");
        assert_eq!(count, 6, "pre-existing value 5 + 1");

        let ttl: i64 = {
            let mut conn = pool.get().await.expect("conn");
            redis::cmd("TTL")
                .arg(key)
                .query_async(&mut conn)
                .await
                .expect("ttl")
        };
        assert!(
            ttl > 0,
            "pre-existing no-TTL key must gain a TTL (got {ttl}; -1 = permanent)"
        );
        assert!(ttl <= 60, "TTL must be the requested 60s window, got {ttl}");

        cache_del(&pool, key).await.expect("cleanup");
    }

    /// The original behavior (fresh key gets TTL on INCR==1) must keep
    /// working.
    #[tokio::test]
    async fn test_incr_with_ttl_fresh_key_still_gets_ttl() {
        let Some(pool) = test_pool().await else {
            eprintln!("skipping: REDIS_TEST_URL not set");
            return;
        };
        let key = "apexmail:cache:test:incr-fresh";

        let count = cache_incr_with_ttl(&pool, key, 60).await.expect("incr");
        assert_eq!(count, 1, "fresh key starts at 1");

        let ttl: i64 = {
            let mut conn = pool.get().await.expect("conn");
            redis::cmd("TTL")
                .arg(key)
                .query_async(&mut conn)
                .await
                .expect("ttl")
        };
        assert!(
            (0..=60).contains(&ttl),
            "fresh key TTL in (0,60], got {ttl}"
        );

        cache_del(&pool, key).await.expect("cleanup");
    }
}
