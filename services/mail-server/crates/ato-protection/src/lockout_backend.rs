//! Lockout backend abstraction — pluggable storage for lockout state
//!
//! Provides a [`LockoutBackend`] trait so that lockout events can be stored
//! in-memory (default) or in an external shared store (e.g., Redis) for
//! multi-node consistency.
//!
//! ## Usage
//!
//! ```rust,no_run
//! use ato_protection::lockout_backend::{InMemoryLockoutBackend, LockoutBackend};
//!
//! let backend = InMemoryLockoutBackend::new();
//! backend.record_lockout("user123", 86400);
//! let count = backend.recent_lockouts("user123", 86400);
//! assert_eq!(count, 1);
//! ```

use chrono::{DateTime, Utc};
use dashmap::DashMap;
use std::sync::Arc;
use std::sync::OnceLock;

/// Trait for storing and querying lockout events.
/// Implementations must be `Send + Sync` for use in async contexts.
/// # Contract
/// - `record_lockout` stores a lockout timestamp for the given user.
/// - `recent_lockouts` returns the count of lockout events within
/// `window_secs` seconds.
/// - `clear` removes all lockout events for a user (e.g., after admin unlock).
pub trait LockoutBackend: Send + Sync {
    /// Record a lockout event for `user_id` with the given TTL window.
    fn record_lockout(&self, user_id: &str, window_secs: u64);

    /// Count lockout events for `user_id` within the last `window_secs`.
    fn recent_lockouts(&self, user_id: &str, window_secs: u64) -> u32;

    /// Clear all lockout events for `user_id`.
    fn clear(&self, user_id: &str);
}

// ─── In-Memory Backend ───────────────────────────────────────────────────────

type LockoutRegistry = Arc<DashMap<String, Vec<DateTime<Utc>>>>;

fn global_lockout_registry() -> LockoutRegistry {
    static GLOBAL: OnceLock<LockoutRegistry> = OnceLock::new();
    GLOBAL.get_or_init(|| Arc::new(DashMap::new())).clone()
}

/// Process-local in-memory lockout backend.
/// Optionally shares state across all instances in the same process via a
/// global `OnceLock` registry (controlled by `use_global`).
/// **Limitation:** State is lost on process restart and is not visible to
/// other nodes. For multi-node deployments, use [`RedisLockoutBackend`].
pub struct InMemoryLockoutBackend {
    store: LockoutRegistry,
}

impl InMemoryLockoutBackend {
    /// Create a new instance with a process-global shared store.
    pub fn new() -> Self {
        Self {
            store: global_lockout_registry(),
        }
    }

    /// Create a new instance with an isolated store (e.g., for tests).
    pub fn isolated() -> Self {
        Self {
            store: Arc::new(DashMap::new()),
        }
    }
}

impl Default for InMemoryLockoutBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl LockoutBackend for InMemoryLockoutBackend {
    fn record_lockout(&self, user_id: &str, window_secs: u64) {
        let cutoff = Utc::now() - chrono::Duration::seconds(window_secs as i64);
        let mut entries = self.store.entry(user_id.to_string()).or_default();
        entries.retain(|t| *t > cutoff);
        entries.push(Utc::now());
    }

    fn recent_lockouts(&self, user_id: &str, window_secs: u64) -> u32 {
        let cutoff = Utc::now() - chrono::Duration::seconds(window_secs as i64);
        self.store
            .get(user_id)
            .map(|entries| entries.iter().filter(|t| **t > cutoff).count() as u32)
            .unwrap_or(0)
    }

    fn clear(&self, user_id: &str) {
        self.store.remove(user_id);
    }
}

// ─── Redis Backend ───────────────────────────────────────────────────────────

/// Whether the `redis-lockout` feature is compiled in.
/// Use this to check at runtime if Redis lockout operations will actually work.
pub const REDIS_LOCKOUT_AVAILABLE: bool = cfg!(feature = "redis-lockout");

/// Timeout applied when OPENING a Redis connection (audit F8). Without it a
/// hung Redis accept queue blocked the synchronous `evaluate()` hot path
/// indefinitely.
#[cfg(feature = "redis-lockout")]
const REDIS_CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);

/// Per-socket read/write timeout applied to every command on a cached
/// connection (audit F8): bounds each query so `evaluate()` cannot stall on
/// a dead-but-open connection.
#[cfg(feature = "redis-lockout")]
const REDIS_IO_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);

/// Redis-backed lockout backend for multi-node deployments.
/// Stores lockout events as sorted-set members keyed by
/// `ato:lockout:{user_id}` with score = Unix timestamp.
/// **Requires the `redis-lockout` feature flag** which brings in the `redis`
/// crate dependency. Without it, this struct is available but all operations
/// are no-ops that log errors.
/// ## Configuration
/// ```rust,no_run
/// use ato_protection::lockout_backend::RedisLockoutBackend;
/// let backend = RedisLockoutBackend::new("redis://127.0.0.1:6379".into());
/// ```
/// ## Known limitations
/// - **Blocking I/O**:Redis calls currently use synchronous I/O on the calling
///   thread, so every operation is bounded by explicit connect and socket
///   timeouts (see [`REDIS_CONNECT_TIMEOUT`] / [`REDIS_IO_TIMEOUT`], audit F8).
///   On timeout or I/O error the operation short-circuits to the same result
///   as the in-memory fallback (`recent_lockouts` → 0, writes → no-op), which
///   keeps `evaluate()` latency bounded instead of blocking the hot path on a
///   hung Redis. NOTE: because the [`LockoutBackend`] trait is synchronous,
///   the blocking call still occupies the calling thread for up to the
///   timeout; fully async behavior requires an async trait method or wrapping
///   each call in `tokio::task::spawn_blocking` at the call site.
/// Error returned when a Redis lockout backend cannot be constructed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LockoutBackendError {
    /// The configured Redis URL could not be parsed.
    InvalidUrl(String),
}

impl std::fmt::Display for LockoutBackendError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LockoutBackendError::InvalidUrl(url) => {
                write!(f, "invalid Redis URL for RedisLockoutBackend: {url}")
            }
        }
    }
}

impl std::error::Error for LockoutBackendError {}

/// Redis-backed lockout backend (see module docs above).
pub struct RedisLockoutBackend {
    /// Redis connection URL (e.g., `redis://127.0.0.1:6379`)
    url: String,
    /// Key prefix for lockout sorted sets (used by the Redis backend impl).
    #[cfg(feature = "redis-lockout")]
    key_prefix: String,
    /// Redis client (None when the URL is invalid or the feature is off —
    /// operations then log-and-degrade instead of panicking).
    #[cfg(feature = "redis-lockout")]
    client: Option<redis::Client>,
    /// Persistent cached connection. Reused across calls instead of opening
    /// a fresh TCP connection per operation; dropped (forcing reconnect) on
    /// any I/O error.
    #[cfg(feature = "redis-lockout")]
    conn: std::sync::Mutex<Option<redis::Connection>>,
    /// Construction error, surfaced via `construction_error()` instead of
    /// a panic (typed error — see [`LockoutBackendError`]).
    #[cfg(feature = "redis-lockout")]
    init_error: Option<LockoutBackendError>,
}

impl RedisLockoutBackend {
    /// Create a new Redis lockout backend.
    /// Invalid URLs no longer panic — the backend is created in a degraded
    /// state and the error is reported via [`Self::construction_error`].
    pub fn new(url: String) -> Self {
        Self::with_prefix(url, "ato:lockout:".into())
    }

    /// Create with a custom key prefix.
    pub fn with_prefix(url: String, prefix: String) -> Self {
        #[cfg(feature = "redis-lockout")]
        let client = match redis::Client::open(url.as_str()) {
            Ok(c) => Some(c),
            Err(e) => {
                tracing::error!(
                    redis_url = %url,
                    error = %e,
                    "RedisLockoutBackend: invalid Redis URL — backend degraded to no-op"
                );
                None
            }
        };

        // `prefix` is only consumed by the Redis backend impl; without the
        // feature we discard it explicitly to keep the constructor uniform.
        #[cfg(not(feature = "redis-lockout"))]
        let _ = prefix;

        #[cfg(feature = "redis-lockout")]
        {
            let init_error = client
                .is_none()
                .then(|| LockoutBackendError::InvalidUrl(url.clone()));
            Self {
                url,
                key_prefix: prefix,
                client,
                conn: std::sync::Mutex::new(None),
                init_error,
            }
        }
        #[cfg(not(feature = "redis-lockout"))]
        {
            Self { url }
        }
    }

    /// The construction error, if the Redis URL was invalid.
    #[cfg(feature = "redis-lockout")]
    pub fn construction_error(&self) -> Option<&LockoutBackendError> {
        self.init_error.as_ref()
    }

    #[cfg(feature = "redis-lockout")]
    fn key(&self, user_id: &str) -> String {
        format!("{}{}", self.key_prefix, user_id)
    }

    /// Run `f` with a persistent connection, reconnecting once on failure.
    /// The connection is cached between calls — previously every lockout
    /// operation opened a brand-new TCP connection to Redis.
    ///
    /// Audit F8: connects with an explicit timeout and stamps per-socket
    /// read/write timeouts on the connection, so a hung Redis can no longer
    /// block the synchronous hot path. Any timeout/I-O error short-circuits
    /// to `None`, which the callers translate to the in-memory-fallback
    /// result (`recent_lockouts` → 0, writes → no-op).
    #[cfg(feature = "redis-lockout")]
    fn with_conn<T>(
        &self,
        op: &str,
        f: impl FnOnce(&mut redis::Connection) -> Result<T, redis::RedisError>,
    ) -> Option<T> {
        let client = self.client.as_ref()?;
        let mut guard = match self.conn.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        if guard.is_none() {
            // Bounded connect (audit F8).
            match client.get_connection_with_timeout(REDIS_CONNECT_TIMEOUT) {
                Ok(mut c) => {
                    // Bound each subsequent query on this socket as well.
                    if c.set_read_timeout(Some(REDIS_IO_TIMEOUT)).is_err()
                        || c.set_write_timeout(Some(REDIS_IO_TIMEOUT)).is_err()
                    {
                        tracing::error!(
                            redis_url = %self.url,
                            op = op,
                            "RedisLockoutBackend: could not set socket timeouts — reconnecting without cache"
                        );
                    }
                    *guard = Some(c);
                }
                Err(e) => {
                    tracing::error!(
                        redis_url = %self.url,
                        op = op,
                        error = %e,
                        "RedisLockoutBackend: connect failed (timeout: {:?})",
                        REDIS_CONNECT_TIMEOUT
                    );
                    return None;
                }
            }
        }
        let Some(conn) = guard.as_mut() else {
            return None;
        };
        match f(conn) {
            Ok(v) => Some(v),
            Err(e) => {
                // Drop the (probably broken or timed-out) connection so the
                // next call reconnects; the caller falls back to the
                // in-memory result, keeping evaluate() bounded.
                *guard = None;
                tracing::error!(
                    redis_url = %self.url,
                    op = op,
                    error = %e,
                    "RedisLockoutBackend: command failed or timed out — connection recycled, falling back to in-memory behavior"
                );
                None
            }
        }
    }

    /// Get the configured Redis URL.
    pub fn url(&self) -> &str {
        &self.url
    }
}

#[cfg(feature = "redis-lockout")]
impl LockoutBackend for RedisLockoutBackend {
    fn record_lockout(&self, user_id: &str, window_secs: u64) {
        let key = self.key(user_id);
        let now = Utc::now().timestamp() as f64;
        let cutoff = now - window_secs as f64;
        let member = uuid::Uuid::new_v4().to_string();

        self.with_conn("record_lockout", |conn| {
            // Remove entries older than the window
            let _: Result<(), redis::RedisError> = redis::cmd("ZREMRANGEBYSCORE")
                .arg(&key)
                .arg("-inf")
                .arg(cutoff)
                .query(conn);
            // Add the new lockout event
            let _: Result<(), redis::RedisError> = redis::cmd("ZADD")
                .arg(&key)
                .arg(now)
                .arg(&member)
                .query(conn);
            // Set TTL on the key
            redis::cmd("EXPIRE")
                .arg(&key)
                .arg(window_secs)
                .query::<()>(conn)
        });
    }

    fn recent_lockouts(&self, user_id: &str, window_secs: u64) -> u32 {
        let key = self.key(user_id);
        let cutoff = (Utc::now().timestamp() - window_secs as i64) as f64;

        self.with_conn("recent_lockouts", |conn| {
            redis::cmd("ZCOUNT")
                .arg(&key)
                .arg(cutoff)
                .arg("+inf")
                .query::<u32>(conn)
        })
        .unwrap_or(0)
    }

    fn clear(&self, user_id: &str) {
        let key = self.key(user_id);
        self.with_conn("clear", |conn| {
            redis::cmd("DEL").arg(&key).query::<()>(conn)
        });
    }
}

/// Without the `redis-lockout` feature, all operations are no-ops.
/// This allows code to reference `RedisLockoutBackend` unconditionally
/// while only gaining actual Redis functionality when the feature is enabled.
#[cfg(not(feature = "redis-lockout"))]
impl LockoutBackend for RedisLockoutBackend {
    fn record_lockout(&self, user_id: &str, _window_secs: u64) {
        tracing::error!(
            user_id = %user_id,
            redis_url = %self.url,
            "RedisLockoutBackend: record_lockout called but redis-lockout feature is not enabled — ATO protection is DISABLED"
        );
    }

    fn recent_lockouts(&self, user_id: &str, _window_secs: u64) -> u32 {
        tracing::error!(
            user_id = %user_id,
            redis_url = %self.url,
            "RedisLockoutBackend: recent_lockouts called but redis-lockout feature is not enabled — ATO protection is DISABLED"
        );
        0
    }

    fn clear(&self, user_id: &str) {
        tracing::error!(
            user_id = %user_id,
            redis_url = %self.url,
            "RedisLockoutBackend: clear called but redis-lockout feature is not enabled — ATO protection is DISABLED"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_in_memory_record_and_count() {
        let backend = InMemoryLockoutBackend::isolated();
        assert_eq!(backend.recent_lockouts("user1", 3600), 0);

        backend.record_lockout("user1", 3600);
        assert_eq!(backend.recent_lockouts("user1", 3600), 1);

        backend.record_lockout("user1", 3600);
        backend.record_lockout("user1", 3600);
        assert_eq!(backend.recent_lockouts("user1", 3600), 3);
    }

    #[test]
    fn test_in_memory_clear() {
        let backend = InMemoryLockoutBackend::isolated();
        backend.record_lockout("user1", 3600);
        backend.record_lockout("user1", 3600);
        assert_eq!(backend.recent_lockouts("user1", 3600), 2);

        backend.clear("user1");
        assert_eq!(backend.recent_lockouts("user1", 3600), 0);
    }

    #[test]
    fn test_in_memory_isolation() {
        let backend_a = InMemoryLockoutBackend::isolated();
        let backend_b = InMemoryLockoutBackend::isolated();

        backend_a.record_lockout("user1", 3600);
        assert_eq!(backend_a.recent_lockouts("user1", 3600), 1);
        assert_eq!(backend_b.recent_lockouts("user1", 3600), 0);
    }

    #[test]
    fn test_redis_backend_noop() {
        let backend = RedisLockoutBackend::new("redis://localhost:6379".into());
        backend.record_lockout("user1", 3600);
        assert_eq!(backend.recent_lockouts("user1", 3600), 0);
        backend.clear("user1"); // Should not panic
    }

    #[test]
    fn test_in_memory_different_users() {
        let backend = InMemoryLockoutBackend::isolated();
        backend.record_lockout("alice", 3600);
        backend.record_lockout("alice", 3600);
        backend.record_lockout("bob", 3600);

        assert_eq!(backend.recent_lockouts("alice", 3600), 2);
        assert_eq!(backend.recent_lockouts("bob", 3600), 1);
        assert_eq!(backend.recent_lockouts("charlie", 3600), 0);
    }

    #[test]
    fn test_invalid_redis_url_does_not_panic() {
        // The constructor previously `.expect()`-ed on invalid URLs — a
        // misconfigured env var could panic the whole process at startup.
        let backend = RedisLockoutBackend::new("not a valid redis url %%%".into());
        // Degraded, not panicked; contract still honors the trait.
        backend.record_lockout("user", 60);
        assert_eq!(backend.recent_lockouts("user", 60), 0);
        backend.clear("user");
        assert_eq!(backend.url(), "not a valid redis url %%%");
    }
}
