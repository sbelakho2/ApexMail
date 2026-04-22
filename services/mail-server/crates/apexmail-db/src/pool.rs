//! PostgreSQL connection pool management.

use sqlx::postgres::{PgPool, PgPoolOptions};
use std::time::Duration;
use tracing::info;

/// Type alias for the database pool.
pub type DatabasePool = PgPool;

/// Create a connection pool from a database URL.
pub async fn create_pool(database_url: &str, max_connections: u32) -> Result<DatabasePool, sqlx::Error> {
    let pool = PgPoolOptions::new()
        .max_connections(max_connections)
        .min_connections(2)
        .acquire_timeout(Duration::from_secs(10))
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
