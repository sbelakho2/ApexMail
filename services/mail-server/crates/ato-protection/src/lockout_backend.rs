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
/// thread. For high-throughput deployments, wrap in `tokio::task::spawn_blocking`.
pub struct RedisLockoutBackend {
    /// Redis connection URL (e.g., `redis://127.0.0.1:6379`)
    url: String,
    /// Key prefix for lockout sorted sets (used by the Redis backend impl).
    #[cfg(feature = "redis-lockout")]
    key_prefix: String,
    /// Redis client (only present when `redis-lockout` feature is enabled)
    #[cfg(feature = "redis-lockout")]
    client: redis::Client,
}

impl RedisLockoutBackend {
    /// Create a new Redis lockout backend.
    pub fn new(url: String) -> Self {
        #[cfg(feature = "redis-lockout")]
        let client =
            redis::Client::open(url.as_str()).expect("Invalid Redis URL for RedisLockoutBackend");

        Self {
            url,
            #[cfg(feature = "redis-lockout")]
            key_prefix: "ato:lockout:".into(),
            #[cfg(feature = "redis-lockout")]
            client,
        }
    }

    /// Create with a custom key prefix.
    pub fn with_prefix(url: String, prefix: String) -> Self {
        #[cfg(feature = "redis-lockout")]
        let client =
            redis::Client::open(url.as_str()).expect("Invalid Redis URL for RedisLockoutBackend");

        // `prefix` is only consumed by the Redis backend impl; without the
        // feature we discard it explicitly to keep the constructor uniform.
        #[cfg(not(feature = "redis-lockout"))]
        let _ = prefix;

        Self {
            url,
            #[cfg(feature = "redis-lockout")]
            key_prefix: prefix,
            #[cfg(feature = "redis-lockout")]
            client,
        }
    }

    #[cfg(feature = "redis-lockout")]
    fn key(&self, user_id: &str) -> String {
        format!("{}{}", self.key_prefix, user_id)
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

        match self.client.get_connection() {
            Ok(mut conn) => {
                // Remove entries older than the window
                let _: Result<(), _> = redis::cmd("ZREMRANGEBYSCORE")
                    .arg(&key)
                    .arg("-inf")
                    .arg(cutoff)
                    .query(&mut conn);

                // Add the new lockout event
                let _: Result<(), _> = redis::cmd("ZADD")
                    .arg(&key)
                    .arg(now)
                    .arg(&member)
                    .query(&mut conn);

                // Set TTL on the key
                let _: Result<(), _> = redis::cmd("EXPIRE")
                    .arg(&key)
                    .arg(window_secs)
                    .query(&mut conn);
            }
            Err(e) => {
                tracing::error!(
                    user_id = %user_id,
                    redis_url = %self.url,
                    error = %e,
                    "RedisLockoutBackend: failed to get Redis connection for record_lockout"
                );
            }
        }
    }

    fn recent_lockouts(&self, user_id: &str, window_secs: u64) -> u32 {
        let key = self.key(user_id);
        let cutoff = (Utc::now().timestamp() - window_secs as i64) as f64;

        match self.client.get_connection() {
            Ok(mut conn) => {
                match redis::cmd("ZCOUNT")
                    .arg(&key)
                    .arg(cutoff)
                    .arg("+inf")
                    .query::<u32>(&mut conn)
                {
                    Ok(count) => count,
                    Err(e) => {
                        tracing::error!(
                            user_id = %user_id,
                            redis_url = %self.url,
                            error = %e,
                            "RedisLockoutBackend: ZCOUNT failed for recent_lockouts"
                        );
                        0
                    }
                }
            }
            Err(e) => {
                tracing::error!(
                    user_id = %user_id,
                    redis_url = %self.url,
                    error = %e,
                    "RedisLockoutBackend: failed to get Redis connection for recent_lockouts"
                );
                0
            }
        }
    }

    fn clear(&self, user_id: &str) {
        let key = self.key(user_id);

        match self.client.get_connection() {
            Ok(mut conn) => {
                let _: Result<(), _> = redis::cmd("DEL").arg(&key).query(&mut conn);
            }
            Err(e) => {
                tracing::error!(
                    user_id = %user_id,
                    redis_url = %self.url,
                    error = %e,
                    "RedisLockoutBackend: failed to get Redis connection for clear"
                );
            }
        }
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
}
