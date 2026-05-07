//! PostgreSQL connection pool management.
//!
//! PP-001: All pools are configured with `acquire_timeout` to prevent indefinite
//! stalls on database outage. The utility function [`with_query_timeout`] wraps
//! any future with a per-query timeout for critical query paths.
//!
//! # TLS (O-18.1)
//!
//! Production connections should use TLS. Configure via `PGSSLMODE` environment
//! variable or by calling [`PgPoolOptions::ssl_mode`] before calling
//! [`create_pool`]. For example:
//!
//! ```ignore
//! use sqlx::postgres::PgConnectOptions;
//! use sqlx::ConnectOptions;
//!
//! let opts = PgConnectOptions::new()
//!     .host("db.example.com")
//!     .port(5432)
//!     .database("apexmail")
//!     .ssl_mode(sqlx::postgres::PgSslMode::Require);
//! let pool = PgPoolOptions::new()
//!     .max_connections(10)
//!     .connect_with(opts)
//!     .await?;
//! ```

use sqlx::postgres::{PgPool, PgPoolOptions};
use std::future::Future;
use std::time::Duration;
use tracing::info;

/// Default per-query timeout applied by [`with_query_timeout`].
pub const QUERY_TIMEOUT: Duration = Duration::from_secs(30);

/// Type alias for the database pool.
pub type DatabasePool = PgPool;

/// Wrap a query future with a timeout so the caller cannot stall indefinitely.
///
/// PP-001: Use this for critical query paths (e.g., message dispatch, auth lookups)
/// to cap the maximum wall-clock time a single query may take.
///
/// # Example
///
/// ```ignore
/// use pool::with_query_timeout;
/// let rows = with_query_timeout(query.fetch_all(&db)).await??;
/// ```
pub async fn with_query_timeout<F, T>(fut: F) -> Result<T, tokio::time::error::Elapsed>
where
    F: Future<Output = T>,
{
    tokio::time::timeout(QUERY_TIMEOUT, fut).await
}

/// DI-009: Read-after-write consistency. This pool connects to a single PostgreSQL
/// primary, so committed writes are immediately visible under READ COMMITTED isolation.
/// If read replicas are introduced in the future, split this into a write pool (primary)
/// and a read pool (replicas) and route critical reads (e.g., get_account_quota,
/// list_messages after expunge) to the write pool to avoid stale reads.
///
/// Create a connection pool from a database URL.
pub async fn create_pool(
    database_url: &str,
    max_connections: u32,
) -> Result<DatabasePool, sqlx::Error> {
    let pool = PgPoolOptions::new()
        .max_connections(max_connections)
        .min_connections(2)
        // DI-010 / PP-001: Prevent connection pool exhaustion and indefinite stalls
        .acquire_timeout(Duration::from_secs(10))
        // DI-010: Validate connections before handing them out to detect stale connections
        .test_before_acquire(true)
        .idle_timeout(Duration::from_secs(300))
        .max_lifetime(Duration::from_secs(1800))
        .connect(database_url)
        .await?;

    info!(max_connections, "Database connection pool created");
    Ok(pool)
}

/// Create a pool from individual config params.
pub async fn create_pool_from_config(
    host: &str,
    port: u16,
    name: &str,
    user: &str,
    password: &str,
    max_connections: u32,
) -> Result<DatabasePool, sqlx::Error> {
    // #210:URL-encode user and password to handle special characters safely
    let encoded_user = urlencoding::encode(user);
    let encoded_password = urlencoding::encode(password);
    let url = format!(
        "postgres://{}:{}@{}:{}/{}",
        encoded_user, encoded_password, host, port, name
    );
    create_pool(&url, max_connections).await
}

/// DI-010: Create a pool with full configuration for environments requiring
/// tighter control over connection lifecycle.
#[allow(dead_code)]
pub async fn create_pool_with_config(
    database_url: &str,
    max_connections: u32,
    min_connections: u32,
    acquire_timeout_secs: u64,
    idle_timeout_secs: u64,
    max_lifetime_secs: u64,
) -> Result<DatabasePool, sqlx::Error> {
    let pool = PgPoolOptions::new()
        .max_connections(max_connections)
        .min_connections(min_connections)
        .acquire_timeout(Duration::from_secs(acquire_timeout_secs))
        .test_before_acquire(true)
        .idle_timeout(Duration::from_secs(idle_timeout_secs))
        .max_lifetime(Duration::from_secs(max_lifetime_secs))
        .connect(database_url)
        .await?;

    info!(
        max_connections,
        min_connections,
        acquire_timeout_secs,
        "Database connection pool created with custom config"
    );
    Ok(pool)
}

/// Create a lazy pool that doesn't connect until first use.
pub fn create_lazy_pool(database_url: &str) -> Result<DatabasePool, sqlx::Error> {
    PgPool::connect_lazy(database_url)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_lazy_pool_creation() {
        let pool = create_lazy_pool("postgres://localhost/test");
        assert!(pool.is_ok());
    }

    #[test]
    fn test_database_url_format() {
        let url = format!(
            "postgres://{}:{}@{}:{}/{}",
            "user", "pass", "localhost", 5432, "apexmail"
        );
        assert_eq!(url, "postgres://user:pass@localhost:5432/apexmail");
    }
}
