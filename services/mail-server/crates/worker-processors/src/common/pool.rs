//! Database and Redis pool management.

use deadpool_redis::{Config as RedisConfig, Pool as DeadpoolRedis, Runtime};
use sqlx::postgres::{PgConnectOptions, PgPool, PgPoolOptions};
use std::time::Duration;

use super::error::{ProcessorError, ProcessorResult};

/// PostgreSQL connection pool wrapper.
pub type DbPool = PgPool;

/// Redis connection pool wrapper.
pub type RedisPool = DeadpoolRedis;

/// Create a PostgreSQL connection pool.
///
/// PERF-116: Acquire timeout increased to 60s (from 30s) to prevent premature
/// timeouts under heavy load. Statement caching (capacity 100) is enabled to
/// avoid re-preparation roundtrips for repeated queries.
pub async fn create_db_pool(database_url: &str, max_connections: u32) -> ProcessorResult<DbPool> {
    let connect_opts = database_url
        .parse::<PgConnectOptions>()?
        .statement_cache_capacity(100);
    let pool = PgPoolOptions::new()
        .max_connections(max_connections)
        .acquire_timeout(Duration::from_secs(60))
        .idle_timeout(Duration::from_secs(600))
        .connect_with(connect_opts)
        .await?;
    Ok(pool)
}

/// Create a Redis connection pool.
/// PP-002: Pool-level timeouts set to prevent indefinite stalls on Redis outage.
/// `create_timeout` limits TCP connect to Redis; `wait_timeout` limits acquire
/// from the pool.
pub fn create_redis_pool(redis_url: &str, max_size: usize) -> ProcessorResult<RedisPool> {
    let cfg = RedisConfig::from_url(redis_url);
    let pool = cfg
        .builder()
        .map_err(|e| ProcessorError::Config(format!("redis config error: {e}")))?
        .max_size(max_size)
        .runtime(Runtime::Tokio1)
        .create_timeout(Some(Duration::from_secs(10)))
        .wait_timeout(Some(Duration::from_secs(5)))
        .build()
        .map_err(|e| ProcessorError::Config(format!("redis pool error: {e}")))?;
    Ok(pool)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn db_pool_rejects_unparseable_urls_without_connecting() {
        let error = create_db_pool("not a database url", 1)
            .await
            .expect_err("garbage must be a configuration error");
        assert!(
            matches!(error, ProcessorError::Database(_)),
            "got {error:?}"
        );
    }

    #[tokio::test]
    async fn db_pool_connects_to_the_configured_database() {
        let Some(url) = std::env::var("TEST_DATABASE_URL")
            .ok()
            .filter(|url| !url.trim().is_empty())
        else {
            return;
        };
        let pool = create_db_pool(&url, 2).await.unwrap_or_else(|error| {
            panic!(
                "configured TEST_DATABASE_URL is unusable ({error}); \
                     this is an infrastructure failure, not a skip"
            )
        });
        let one: i32 = sqlx::query_scalar("SELECT 1")
            .fetch_one(&pool)
            .await
            .expect("the pool must serve queries with statement caching enabled");
        assert_eq!(one, 1);
        pool.close().await;
    }

    #[test]
    fn redis_pool_builds_lazily_from_a_url() {
        let url = std::env::var("TEST_REDIS_URL")
            .ok()
            .filter(|v| !v.trim().is_empty())
            .unwrap_or_else(|| "redis://127.0.0.1:6379".to_string());
        let pool = create_redis_pool(&url, 2).expect("a valid URL must build a pool");
        assert_eq!(pool.status().max_size, 2);
    }
}
