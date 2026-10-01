//! SM10 F4 — data-plane STONITH fencing machinery.
//!
//! The failover coordinator (`crate::failover`) PLACES fence keys in Redis,
//! but until now the only consumer of those keys was the HA service's own
//! HTTP guard — api-server, worker and mta kept writing through a fenced
//! node. This module is the pub helper those data-plane crates consume to
//! enforce the fence where the writes actually happen.
//!
//! # Redis key layout (single source of truth)
//!
//! | Key                 | Value | TTL    | Meaning                                |
//! |---------------------|-------|--------|----------------------------------------|
//! | `ha:fenced:{node}`  | `"1"` | 3600 s | present ⇒ `{node}` is FENCED: it must |
//! |                     |       |        | refuse every mutating operation        |
//!
//! The key is written by the failover coordinator (and the operator fence
//! routes); data-plane services only ever READ it. The primary-claim keys
//! (`ha:primary:{node}`) and the failover lock (`ha:failover:lock`) are
//! owned by [`crate::failover`] and must not be touched from the data plane.
//!
//! # Integration contract for api-server / worker / mta
//!
//! 1. At startup, build one checker per process and share it:
//!    ```ignore
//!    let checker = ha::fence::FenceChecker::new(
//!        ha::fence::RedisFenceStore::from_config(&config)?,
//!        config.multi_region.node_id.clone(),
//!    );
//!    ```
//! 2. Before accepting ANY mutating operation (HTTP write, claim
//!    completion, SMTP acceptance), call
//!    [`FenceChecker::ensure_not_fenced`]:
//!    - `Ok(())` → the node is PROVEN not fenced — serve the write;
//!    - `Err(FenceError::Fenced)` → the node's fence key is present —
//!      refuse the write (HTTP 503 / reject the job);
//!    - `Err(FenceError::Unreadable(_))` → the fence authority could not be
//!      read — FAIL CLOSED and refuse the write (a node that cannot prove
//!      it is not fenced must not write to the primary).
//! 3. Latency & bounded staleness: a fresh not-fenced verdict is cached
//!    locally for [`DEFAULT_NEGATIVE_CACHE_TTL`] so the common path costs
//!    zero Redis round-trips. Consequence: a node may keep accepting writes
//!    for AT MOST that TTL after being fenced (the fence is then observed
//!    on the next authority read). A `Fenced` verdict is never cached, and
//!    an unreadable authority always refuses, cache or not. Tune the window
//!    with [`FenceChecker::with_negative_cache_ttl`].
//!
//! The HA service's own guard (`routes::fence_guard`) deliberately does NOT
//! use the cached checker — the control plane must observe fence state
//! live; the negative cache exists for hot data-plane write paths.

use std::future::Future;
use std::pin::Pin;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Redis key prefix of the node fence keys. `ha:fenced:{node}` with value
/// `"1"` and a 3600 s TTL.
pub const FENCE_KEY_PREFIX: &str = "ha:fenced:";
/// TTL the coordinator places on fence keys (mirrors
/// `FailoverService::fence_node`).
pub const FENCE_TTL_SECS: u64 = 3600;
/// Default freshness window of the local NEGATIVE ("not fenced") cache.
///
/// This bounds both the Redis load (≤ 1 GET per window) and the fence
/// staleness (a fenced node may serve writes for at most this long after
/// the key is placed).
pub const DEFAULT_NEGATIVE_CACHE_TTL: Duration = Duration::from_secs(5);

/// The fence key for a node — the exact layout every fence consumer agrees on.
pub fn fence_key(node: &str) -> String {
    format!("{FENCE_KEY_PREFIX}{node}")
}

/// Outcome of a fence check. Both variants mean "refuse the write" — the
/// distinction is diagnostic only (fenced vs. cannot-prove-not-fenced).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FenceError {
    /// The node's fence key is present in the fence authority.
    Fenced,
    /// The fence authority could not be read (Redis unreachable/error) —
    /// the node cannot PROVE it is not fenced, so writes are refused.
    Unreadable(String),
}

impl std::fmt::Display for FenceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Fenced => write!(f, "node is fenced — writes refused"),
            Self::Unreadable(e) => write!(
                f,
                "fence status unreadable ({e}) — failing closed, writes refused"
            ),
        }
    }
}

impl std::error::Error for FenceError {}

/// The fence authority abstraction. `RedisFenceStore` is the production
/// implementation; tests substitute in-memory mocks through this seam.
pub trait FenceStore: Send + Sync {
    /// Look the node's fence key up in the fence authority.
    /// `Ok(true)` = fenced, `Ok(false)` = not fenced, `Err` = unreadable —
    /// callers must fail CLOSED on `Err`.
    fn is_fenced<'a>(
        &'a self,
        node: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<bool, String>> + Send + 'a>>;
}

/// Production fence authority: the `ha:fenced:{node}` keys in Redis.
#[derive(Clone)]
pub struct RedisFenceStore {
    client: redis::Client,
}

impl RedisFenceStore {
    /// Build from a `redis://` URL (e.g. `Config::redis` `url()`).
    pub fn from_url(url: &str) -> Result<Self, String> {
        let client = redis::Client::open(url).map_err(|e| e.to_string())?;
        Ok(Self { client })
    }

    /// Build from the HA service config (reads `REDIS_HOST`/`REDIS_PORT`/
    /// `REDIS_PASSWORD`/`REDIS_DB` via [`crate::config::RedisConfig::url`]).
    pub fn from_config(config: &crate::config::Config) -> Result<Self, String> {
        Self::from_url(config.redis.url().as_str())
    }
}

impl FenceStore for RedisFenceStore {
    fn is_fenced<'a>(
        &'a self,
        node: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<bool, String>> + Send + 'a>> {
        Box::pin(async move {
            let mut conn = self
                .client
                .get_multiplexed_async_connection()
                .await
                .map_err(|e| format!("connect to fence authority: {e}"))?;
            let value: Option<String> = redis::cmd("GET")
                .arg(fence_key(node))
                .query_async(&mut conn)
                .await
                .map_err(|e| format!("read {}: {e}", fence_key(node)))?;
            Ok(value.is_some())
        })
    }
}

/// Freshness timestamp of the last PROVEN "not fenced" verdict. A `Fenced`
/// verdict is never cached — refusals are always backed by the authority.
struct NegativeCache(Mutex<Option<Instant>>);

impl NegativeCache {
    fn get(&self) -> Option<Instant> {
        // A poisoned cache is treated as a miss: the cache is an
        // optimization, the authority is Redis.
        *self
            .0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn set(&self, until: Option<Instant>) {
        // Same tolerance: poisoning must never take down the write path.
        if let Ok(mut guard) = self.0.lock() {
            *guard = until;
        }
    }
}

/// Data-plane fence gate (SM10 F4). Wraps a [`FenceStore`] with a short-TTL
/// NEGATIVE cache so hot write paths can afford a fence check per operation.
///
/// Semantics (see the module docs for the full contract):
/// - a fresh not-fenced verdict short-circuits the authority read;
/// - `Fenced` is never cached and clears the cache;
/// - an unreadable authority ALWAYS fails closed, cache or not.
pub struct FenceChecker<S: FenceStore> {
    store: S,
    node_id: String,
    negative_cache_ttl: Duration,
    not_fenced_until: NegativeCache,
}

impl<S: FenceStore> FenceChecker<S> {
    /// Checker with the default negative-cache TTL.
    pub fn new(store: S, node_id: impl Into<String>) -> Self {
        Self::with_negative_cache_ttl(store, node_id, DEFAULT_NEGATIVE_CACHE_TTL)
    }

    /// Checker with an explicit negative-cache TTL (smaller = tighter fence
    /// observation, more Redis reads).
    pub fn with_negative_cache_ttl(
        store: S,
        node_id: impl Into<String>,
        negative_cache_ttl: Duration,
    ) -> Self {
        Self {
            store,
            node_id: node_id.into(),
            negative_cache_ttl,
            not_fenced_until: NegativeCache(Mutex::new(None)),
        }
    }

    /// The node this checker vouches for.
    pub fn node_id(&self) -> &str {
        &self.node_id
    }

    /// Drop any cached verdict (e.g. after an operator fences this node and
    /// the process must notice immediately).
    pub fn clear_cache(&self) {
        self.not_fenced_until.set(None);
    }

    /// The gate: `Ok(())` only when this node is PROVEN not fenced (via the
    /// authority or a fresh negative-cache entry). Any other outcome is an
    /// `Err` — refuse the write.
    pub async fn ensure_not_fenced(&self) -> Result<(), FenceError> {
        if let Some(until) = self.not_fenced_until.get() {
            if Instant::now() < until {
                return Ok(());
            }
        }
        match self.store.is_fenced(&self.node_id).await {
            Ok(false) => {
                self.not_fenced_until
                    .set(Some(Instant::now() + self.negative_cache_ttl));
                Ok(())
            }
            Ok(true) => {
                self.not_fenced_until.set(None);
                Err(FenceError::Fenced)
            }
            Err(e) => Err(FenceError::Unreadable(e)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn test_runtime() -> &'static tokio::runtime::Runtime {
        use std::sync::OnceLock;
        static RT: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
        RT.get_or_init(|| {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
        })
    }

    /// In-memory fence authority (the trait seam): per-node verdicts that
    /// tests flip between NotFenced / Fenced / Unreadable. Clones SHARE the
    /// verdict map (the checker and the test handle must observe the same
    /// authority).
    #[derive(Clone, Default)]
    struct MockFenceStore(std::sync::Arc<std::sync::Mutex<HashMap<String, Result<bool, String>>>>);

    impl MockFenceStore {
        fn new() -> Self {
            Self(Default::default())
        }
        fn set(&self, node: &str, verdict: Result<bool, String>) {
            self.0
                .lock()
                .expect("mock fence store lock")
                .insert(node.to_string(), verdict);
        }
    }

    impl FenceStore for MockFenceStore {
        fn is_fenced<'a>(
            &'a self,
            node: &'a str,
        ) -> Pin<Box<dyn Future<Output = Result<bool, String>> + Send + 'a>> {
            Box::pin(async move {
                self.0
                    .lock()
                    .expect("mock fence store lock")
                    .get(node)
                    .cloned()
                    .unwrap_or(Ok(false))
            })
        }
    }

    #[test]
    fn test_fence_key_layout() {
        assert_eq!(fence_key("node-a"), "ha:fenced:node-a");
        assert_eq!(FENCE_KEY_PREFIX, "ha:fenced:");
    }

    #[test]
    fn test_negative_cache_hits_until_ttl_expires() {
        test_runtime().block_on(async {
            let store = MockFenceStore::new();
            let checker = FenceChecker::with_negative_cache_ttl(
                store.clone(),
                "node-a",
                Duration::from_millis(150),
            );

            // Not fenced: first check consults the mock and caches the verdict.
            assert!(checker.ensure_not_fenced().await.is_ok());

            // The node becomes fenced — the cached verdict still holds for
            // the (bounded) TTL window.
            store.0.lock().unwrap().insert("node-a".into(), Ok(true));
            assert!(
                checker.ensure_not_fenced().await.is_ok(),
                "fresh negative cache must serve without consulting the authority"
            );

            // After the TTL the authority is consulted and the fence seen.
            tokio::time::sleep(Duration::from_millis(250)).await;
            assert_eq!(
                checker.ensure_not_fenced().await,
                Err(FenceError::Fenced),
                "expired cache must expose the fence"
            );
        });
    }

    #[test]
    fn test_fenced_verdict_is_never_cached_and_clears_the_cache() {
        test_runtime().block_on(async {
            let store = MockFenceStore::new();
            store.set("node-a", Ok(true));
            let checker = FenceChecker::new(store.clone(), "node-a");

            assert_eq!(
                checker.ensure_not_fenced().await,
                Err(FenceError::Fenced),
                "fenced node must be refused on the very first check"
            );
            assert_eq!(
                checker.ensure_not_fenced().await,
                Err(FenceError::Fenced),
                "a Fenced verdict must not be cached into an acceptance"
            );

            // Operator unfences: the next authority read recovers the node.
            store.set("node-a", Ok(false));
            assert!(checker.ensure_not_fenced().await.is_ok());
        });
    }

    #[test]
    fn test_unreadable_authority_fails_closed_even_with_stale_cache() {
        test_runtime().block_on(async {
            let store = MockFenceStore::new();
            let checker = FenceChecker::with_negative_cache_ttl(
                store.clone(),
                "node-a",
                Duration::from_millis(100),
            );

            // Proven not-fenced once (cache populated)…
            assert!(checker.ensure_not_fenced().await.is_ok());
            // …then the authority becomes unreadable and the cache expires:
            // the node can no longer PROVE it is not fenced → fail CLOSED.
            store.set("node-a", Err("redis down".into()));
            tokio::time::sleep(Duration::from_millis(200)).await;
            assert_eq!(
                checker.ensure_not_fenced().await,
                Err(FenceError::Unreadable("redis down".into())),
                "unreadable fence status must refuse writes (fail closed)"
            );
        });
    }

    #[test]
    fn test_clear_cache_forces_authority_re_read() {
        test_runtime().block_on(async {
            let store = MockFenceStore::new();
            let checker = FenceChecker::new(store.clone(), "node-a");
            assert!(checker.ensure_not_fenced().await.is_ok());

            store.set("node-a", Ok(true));
            checker.clear_cache();
            assert_eq!(
                checker.ensure_not_fenced().await,
                Err(FenceError::Fenced),
                "clear_cache must surface an already-placed fence immediately"
            );
        });
    }

    #[test]
    fn test_fence_error_display() {
        assert_eq!(
            FenceError::Fenced.to_string(),
            "node is fenced — writes refused"
        );
        let unreadable = FenceError::Unreadable("boom".into()).to_string();
        assert!(unreadable.contains("failing closed"));
        assert!(unreadable.contains("boom"));
    }

    // ── Live-Redis store check (crate's ephemeral redis-server pattern) ──

    #[test]
    fn test_redis_store_reads_the_real_fence_key() {
        let Some(redis) = spawn_test_redis() else {
            eprintln!("skipping: redis-server not available");
            return;
        };
        test_runtime().block_on(async move {
            let store = RedisFenceStore::from_url(&format!("redis://127.0.0.1:{}", redis.port))
                .expect("valid redis url");
            let checker = FenceChecker::new(store, "node-x");

            // No key → proven not fenced.
            assert!(checker.ensure_not_fenced().await.is_ok());

            // Place the EXACT production key ( FailoverService::fence_node layout).
            redis_set(redis.port, &fence_key("node-x"), "1").await;
            assert_eq!(
                checker.clear_cache_then_check().await,
                Err(FenceError::Fenced),
                "the production fence key must be seen by the data-plane checker"
            );

            // TTL was placed by the coordinator — the checker is read-only.
            let ttl: i64 = redis::cmd("TTL")
                .arg(fence_key("node-x"))
                .query_async(
                    &mut redis::Client::open(format!("redis://127.0.0.1:{}", redis.port).as_str())
                        .unwrap()
                        .get_multiplexed_async_connection()
                        .await
                        .unwrap(),
                )
                .await
                .unwrap();
            assert!(ttl > 0, "fence key must carry a TTL");
        });
    }

    impl<S: FenceStore> FenceChecker<S> {
        /// Test helper: bypass the negative cache for one check.
        async fn clear_cache_then_check(&self) -> Result<(), FenceError> {
            self.clear_cache();
            self.ensure_not_fenced().await
        }
    }

    /// Ephemeral throwaway `redis-server` on a random port (same pattern as
    /// `failover.rs` tests). Returns None when no binary is available.
    struct TestRedis {
        port: u16,
        child: std::process::Child,
    }
    impl Drop for TestRedis {
        fn drop(&mut self) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }

    fn spawn_test_redis() -> Option<TestRedis> {
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).ok()?;
        let port = listener.local_addr().ok()?.port();
        drop(listener);
        let mut child = std::process::Command::new("redis-server")
            .args([
                "--port",
                &port.to_string(),
                "--save",
                "",
                "--appendonly",
                "no",
                "--daemonize",
                "no",
            ])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .ok()?;
        let url = format!("redis://127.0.0.1:{port}");
        for _ in 0..50 {
            if let Ok(client) = redis::Client::open(url.as_str()) {
                if let Ok(mut conn) = client.get_connection() {
                    if redis::cmd("PING")
                        .query::<String>(&mut conn)
                        .map(|r| r == "PONG")
                        .unwrap_or(false)
                    {
                        return Some(TestRedis { port, child });
                    }
                }
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        let _ = child.kill();
        let _ = child.wait();
        None
    }

    /// Place a fence key exactly like the coordinator does
    /// (`FailoverService::fence_node`: value "1" + `FENCE_TTL_SECS` expiry).
    async fn redis_set(port: u16, key: &str, value: &str) {
        let mut conn = redis::Client::open(format!("redis://127.0.0.1:{port}").as_str())
            .unwrap()
            .get_multiplexed_async_connection()
            .await
            .unwrap();
        let _: () = redis::cmd("SET")
            .arg(key)
            .arg(value)
            .arg("EX")
            .arg(FENCE_TTL_SECS)
            .query_async(&mut conn)
            .await
            .unwrap();
    }
}
