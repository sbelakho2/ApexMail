//! Redis-backed cache utilities.

use deadpool_redis::{Pool as RedisPool, redis::AsyncCommands};
use serde::{Serialize, de::DeserializeOwned};
use std::time::Duration;

/// Get a cached JSON value from Redis.
pub async fn cache_get<T: DeserializeOwned>(
    redis: &RedisPool,
    key: &str,
) -> Option<T> {
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
pub async fn cache_del(
    redis: &RedisPool,
    key: &str,
) -> Result<(), anyhow::Error> {
    let mut conn = redis.get().await?;
    let _: () = conn.del(key).await?;
    Ok(())
}

/// Atomic increment with expiry (for rate limiting counters).
pub async fn cache_incr_with_ttl(
    redis: &RedisPool,
    key: &str,
    ttl_secs: u64,
) -> Result<i64, anyhow::Error> {
    let mut conn = redis.get().await?;
    let count: i64 = conn.incr(key, 1i64).await?;
    if count == 1 {
        let _: () = conn.expire(key, ttl_secs as i64).await?;
    }
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
}
