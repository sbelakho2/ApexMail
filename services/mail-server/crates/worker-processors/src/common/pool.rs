//! Database and Redis pool management.

use deadpool_redis::{Config as RedisConfig, Pool as DeadpoolRedis, Runtime};
use sqlx::postgres::{PgPool, PgPoolOptions};
use std::time::Duration;

use super::error::{ProcessorError, ProcessorResult};

/// PostgreSQL connection pool wrapper.
pub type DbPool = PgPool;

/// Redis connection pool wrapper.
pub type RedisPool = DeadpoolRedis;

/// Create a PostgreSQL connection pool.
pub async fn create_db_pool(database_url: &str, max_connections: u32) -> ProcessorResult<DbPool> {
    let pool = PgPoolOptions::new()
        .max_connections(max_connections)
        .acquire_timeout(Duration::from_secs(30))
        .idle_timeout(Duration::from_secs(600))
        .connect(database_url)
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
