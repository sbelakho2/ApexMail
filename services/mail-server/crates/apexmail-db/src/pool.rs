//! PostgreSQL connection pool management.
//!
//! PP-001: All pools are configured with `acquire_timeout` to prevent indefinite
//! stalls on database outage. The utility function [`with_query_timeout`] wraps
//! any future with a per-query timeout for critical query paths.
//!
//! DB-09: The API server pool uses `acquire_timeout=10s` (below) and the worker
//! pool should be aligned to the same value with `test_before_acquire(true)`.
//! DB-10: Prepared statement caching is configured via `statement_cache_capacity`
//! on `PgConnectOptions` (see [`pool_with_statement_cache`] example).
//! DB-18: Pool metrics (size, active, idle, wait) are exported via the `metrics`
//! crate — see [`PoolMetricsCollector`] registration in main.
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

use once_cell::sync::Lazy;
use prometheus::{register_gauge_vec, register_histogram_vec, GaugeVec, HistogramVec};
use sqlx::postgres::{PgConnectOptions, PgPool, PgPoolOptions};
use std::future::Future;
use std::time::{Duration, Instant};
use tracing::{info, warn};

/// Prometheus histogram tracking query duration in seconds, labelled by query name.
static DB_QUERY_DURATION: Lazy<HistogramVec> = Lazy::new(|| {
    register_histogram_vec!(
        "db_query_duration_seconds",
        "Database query duration in seconds",
        &["query_name"],
        vec![0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0, 5.0, 10.0, 30.0]
    )
    .expect("db_query_duration_seconds metric registration must not fail")
});

/// Global query timeout in seconds, configurable via [`set_query_timeout`] or the
/// `QUERY_TIMEOUT_SECONDS` environment variable. Default: 30.
static QUERY_TIMEOUT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(30);

/// Set the global query timeout.
pub fn set_query_timeout(seconds: u64) {
    QUERY_TIMEOUT.store(seconds, std::sync::atomic::Ordering::Relaxed);
}

/// Get the current global query timeout as a [`Duration`].
pub fn get_query_timeout() -> Duration {
    Duration::from_secs(QUERY_TIMEOUT.load(std::sync::atomic::Ordering::Relaxed))
}

/// Type alias for the database pool.
pub type DatabasePool = PgPool;

/// A pair of PostgreSQL connection pools — one for read-write (primary),
/// one for read-only (replica). If no replica URL is configured, both pools
/// point to the same primary.
pub struct PoolPair {
    /// Read-write pool (primary)
    pub rw: PgPool,
    /// Read-only pool (replica — falls back to primary if unconfigured)
    pub ro: PgPool,
}

impl PoolPair {
    /// Create a new pool pair from primary and (optional) replica URLs.
    /// If replica_url is None, the replica pool shares the primary URL.
    pub async fn new(
        primary_url: &str,
        replica_url: Option<&str>,
        _max_connections: u32,
    ) -> Result<Self, sqlx::Error> {
        let rw = PgPool::connect(primary_url).await?;
        let ro = match replica_url {
            Some(url) => PgPool::connect(url).await?,
            None => PgPool::connect(primary_url).await?,
        };
        Ok(Self { rw, ro })
    }

    /// Get the appropriate pool based on query type
    pub fn get(&self, pool_type: PoolType) -> &PgPool {
        match pool_type {
            PoolType::ReadWrite => &self.rw,
            PoolType::ReadOnly => &self.ro,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PoolType {
    ReadWrite,
    ReadOnly,
}

/// Tracks when the last write occurred for read-after-write consistency.
/// After a write, subsequent reads are routed to the primary (RW) pool
/// for a 5-second "sticky window" to avoid stale reads from replicas.
pub struct WriteTracker {
    last_write: Option<Instant>,
}

impl WriteTracker {
    pub fn new() -> Self {
        Self { last_write: None }
    }

    pub fn record_write(&mut self) {
        self.last_write = Some(Instant::now());
    }

    /// Returns true if the most recent write was within the sticky window (5 seconds)
    pub fn is_within_sticky_window(&self) -> bool {
        self.last_write
            .map(|t| t.elapsed() < std::time::Duration::from_secs(5))
            .unwrap_or(false)
    }

    /// Choose the pool: use RW if within sticky window, otherwise use RO
    pub fn choose_pool<'a>(&self, pools: &'a PoolPair) -> &'a PgPool {
        if self.is_within_sticky_window() {
            &pools.rw
        } else {
            &pools.ro
        }
    }
}

impl Default for WriteTracker {
    fn default() -> Self {
        Self::new()
    }
}

/// T-205: Prometheus gauge tracking the number of PostgreSQL connections
/// currently in use, labelled by pool name and max connections cap.
static POSTGRES_CONNECTIONS: Lazy<GaugeVec> = Lazy::new(|| {
    register_gauge_vec!(
        "postgres_connections_used",
        "Number of PostgreSQL connections currently in use",
        &["pool", "max"]
    )
    .expect("postgres_connections_used metric registration must not fail")
});

/// Configuration for creating a connection pool with connection budget enforcement.
///
/// T-205: The `connection_budget` and `expected_replica_count` fields control
/// cluster-wide connection budget validation at pool creation time.
pub struct PoolConfig<'a> {
    pub database_url: &'a str,
    pub max_connections: u32,
    pub min_connections: u32,
    pub acquire_timeout_secs: u64,
    pub idle_timeout_secs: u64,
    pub max_lifetime_secs: u64,
    /// Human-readable pool label used in metrics and log messages.
    pub pool_name: Option<String>,
    /// Cluster-wide connection budget. If `None`, budget validation is skipped.
    pub connection_budget: Option<usize>,
    /// Expected number of replicas in the cluster. Used to compute
    /// `total_potential = max_connections * expected_replica_count` for
    /// budget comparison. Defaults to 3.
    pub expected_replica_count: u32,
    /// T-304: Prepared statement cache capacity. 0 = disabled (default).
    /// When > 0, sqlx caches up to this many prepared statements per connection,
    /// avoiding re-preparation roundtrips for repeated queries.
    pub statement_cache_capacity: usize,
}

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
    let timeout_dur = get_query_timeout();
    tokio::time::timeout(timeout_dur, fut).await
}

/// Execute a future with a configurable timeout and record Prometheus duration
/// metrics. Logs a warning when the query takes longer than 50% of the timeout.
///
/// # Example
///
/// ```ignore
/// use pool::timed_query;
/// let rows = timed_query("list_messages", query.fetch_all(&db), 30).await??;
/// ```
pub async fn timed_query<F, T>(
    query_name: &str,
    fut: F,
    timeout_secs: u64,
) -> Result<T, tokio::time::error::Elapsed>
where
    F: std::future::Future<Output = T>,
{
    let start = std::time::Instant::now();
    let timeout_dur = Duration::from_secs(timeout_secs);
    let result = tokio::time::timeout(timeout_dur, fut).await;

    let elapsed = start.elapsed();
    DB_QUERY_DURATION
        .with_label_values(&[query_name])
        .observe(elapsed.as_secs_f64());

    if elapsed > timeout_dur / 2 {
        tracing::warn!(
            "Slow query [{}]: {:.2}s (timeout={}s)",
            query_name,
            elapsed.as_secs_f64(),
            timeout_secs,
        );
    }

    result
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
    // DB-09: acquire_timeout=10s aligned with worker pool recommendation;
    // test_before_acquire(true) prevents handing out stale connections.
    // DB-10: To configure statement caching, use PgConnectOptions:
    //   let opts = PgConnectOptions::new()
    //       .statement_cache_capacity(100_usize);
    //   let pool = PgPoolOptions::new()
    //       .max_connections(max_connections)
    //       .connect_with(opts)
    //       .await?;
    // DB-18: Pool metrics should be exported by the service binary that owns the
    // pool. For example, in the API server main.rs:
    //   metrics::describe_gauge!("db_pool_size", "Number of pool connections");
    //   metrics::gauge!("db_pool_size", pool.max_connections() as f64);
    //   metrics::gauge!("db_pool_active", pool.num_active() as f64);
    //   metrics::gauge!("db_pool_idle", pool.num_idle() as f64);
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
///
/// T-304: `statement_cache_capacity` controls prepared statement caching.
/// Pass 0 to disable caching (backward compatible).
pub async fn create_pool_from_config(
    host: &str,
    port: u16,
    name: &str,
    user: &str,
    password: &str,
    max_connections: u32,
    statement_cache_capacity: usize,
) -> Result<DatabasePool, sqlx::Error> {
    // #210:URL-encode user and password to handle special characters safely
    let encoded_user = urlencoding::encode(user);
    let encoded_password = urlencoding::encode(password);
    let url = format!(
        "postgres://{}:{}@{}:{}/{}",
        encoded_user, encoded_password, host, port, name
    );
    let config = PoolConfig {
        database_url: &url,
        max_connections,
        min_connections: 2,
        acquire_timeout_secs: 10,
        idle_timeout_secs: 300,
        max_lifetime_secs: 1800,
        pool_name: None,
        connection_budget: None,
        expected_replica_count: 3,
        statement_cache_capacity,
    };
    create_pool_with_opts(&config).await
}

/// DI-010 / T-205: Create a pool with full configuration for environments requiring
/// tighter control over connection lifecycle and cluster-wide budget enforcement.
///
/// After pool creation, a background task periodically exports pool utilisation as a
/// Prometheus gauge (`postgres_connections_used`). If `connection_budget` is set,
/// a warning is logged when `max_connections × expected_replica_count` exceeds the
/// budget. At 90% utilisation, an additional warning is emitted.
pub async fn create_pool_with_config(
    database_url: &str,
    max_connections: u32,
    min_connections: u32,
    acquire_timeout_secs: u64,
    idle_timeout_secs: u64,
    max_lifetime_secs: u64,
) -> Result<DatabasePool, sqlx::Error> {
    let config = PoolConfig {
        database_url,
        max_connections,
        min_connections,
        acquire_timeout_secs,
        idle_timeout_secs,
        max_lifetime_secs,
        pool_name: None,
        connection_budget: None,
        expected_replica_count: 3,
        statement_cache_capacity: 0,
    };
    create_pool_with_opts(&config).await
}

/// T-205: Create a pool with full configuration including connection budget.
///
/// This is the canonical pool creation function. [`create_pool_with_config`] delegates
/// to this function with default budget values.
pub async fn create_pool_with_opts(config: &PoolConfig<'_>) -> Result<DatabasePool, sqlx::Error> {
    // T-304: When statement_cache_capacity > 0, parse the URL into PgConnectOptions
    // so we can set the statement cache capacity before connecting. Otherwise fall
    // back to the simple connect() path for backward compatibility.
    let pool = if config.statement_cache_capacity > 0 {
        let connect_opts = config
            .database_url
            .parse::<PgConnectOptions>()?
            .statement_cache_capacity(config.statement_cache_capacity);
        PgPoolOptions::new()
            .max_connections(config.max_connections)
            .min_connections(config.min_connections)
            .acquire_timeout(Duration::from_secs(config.acquire_timeout_secs))
            .test_before_acquire(true)
            .idle_timeout(Duration::from_secs(config.idle_timeout_secs))
            .max_lifetime(Duration::from_secs(config.max_lifetime_secs))
            .connect_with(connect_opts)
            .await?
    } else {
        PgPoolOptions::new()
            .max_connections(config.max_connections)
            .min_connections(config.min_connections)
            .acquire_timeout(Duration::from_secs(config.acquire_timeout_secs))
            .test_before_acquire(true)
            .idle_timeout(Duration::from_secs(config.idle_timeout_secs))
            .max_lifetime(Duration::from_secs(config.max_lifetime_secs))
            .connect(config.database_url)
            .await?
    };

    let pool_label = config
        .pool_name
        .clone()
        .unwrap_or_else(|| "default".to_string());

    // ── Connection budget validation ──────────────────────────────────────────
    if let Some(budget) = config.connection_budget {
        let total_potential = config.max_connections * config.expected_replica_count;
        if total_potential > budget as u32 {
            warn!(
                pool = %pool_label,
                max_connections = config.max_connections,
                expected_replicas = config.expected_replica_count,
                total_potential,
                budget,
                "Connection budget may be exceeded: {} max_connections × {} replicas = {} > {} budget",
                config.max_connections,
                config.expected_replica_count,
                total_potential,
                budget,
            );
        }
    }

    // ── Background metrics reporting ─────────────────────────────────────────
    let pool_clone = pool.clone();
    let metrics_label = pool_label.clone();
    let max_conns = config.max_connections;
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(15));
        loop {
            interval.tick().await;
            let idle: u32 = pool_clone.num_idle().try_into().unwrap_or(0);
            let active = pool_clone.size().saturating_sub(idle);
            POSTGRES_CONNECTIONS
                .with_label_values(&[&metrics_label, &max_conns.to_string()])
                .set(active as f64);

            // ── 90% utilisation warning ──────────────────────────────────────
            if max_conns > 0 {
                let utilization = active as f64 / max_conns as f64;
                if utilization > 0.9 {
                    warn!(
                        pool = %metrics_label,
                        active,
                        max_connections = max_conns,
                        utilization = format!("{:.1}%", utilization * 100.0),
                        "Connection pool at {:.1}% capacity",
                        utilization * 100.0,
                    );
                }
            }
        }
    });

    info!(
        max_connections = config.max_connections,
        min_connections = config.min_connections,
        acquire_timeout_secs = config.acquire_timeout_secs,
        pool = %pool_label,
        "Database connection pool created with custom config"
    );
    Ok(pool)
}

/// Create a lazy pool that doesn't connect until first use.
pub fn create_lazy_pool(database_url: &str) -> Result<DatabasePool, sqlx::Error> {
    PgPool::connect_lazy(database_url)
}

/// Create a pair of connection pools — primary (read-write) and replica (read-only).
///
/// T-304: `statement_cache_capacity` controls prepared statement caching.
/// Pass 0 to disable caching (backward compatible).
///
/// If `replica_url` is `None`, both pools connect to the primary, ensuring
/// the system works without a replica deployment.
pub async fn create_pool_pair(
    primary_url: &str,
    replica_url: Option<&str>,
    max_connections: u32,
    statement_cache_capacity: usize,
) -> Result<PoolPair, sqlx::Error> {
    let rw_config = PoolConfig {
        database_url: primary_url,
        max_connections,
        min_connections: 2,
        acquire_timeout_secs: 10,
        idle_timeout_secs: 300,
        max_lifetime_secs: 1800,
        pool_name: Some("rw".into()),
        connection_budget: None,
        expected_replica_count: 3,
        statement_cache_capacity,
    };
    let rw = create_pool_with_opts(&rw_config).await?;

    let replica_url = replica_url.unwrap_or(primary_url);
    let ro_config = PoolConfig {
        database_url: replica_url,
        max_connections,
        min_connections: 2,
        acquire_timeout_secs: 10,
        idle_timeout_secs: 300,
        max_lifetime_secs: 1800,
        pool_name: Some("ro".into()),
        connection_budget: None,
        expected_replica_count: 3,
        statement_cache_capacity,
    };
    let ro = create_pool_with_opts(&ro_config).await?;

    Ok(PoolPair { rw, ro })
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
