//! Shared authentication lockout tracking and timing-equalisation helpers.
//!
//! Both the submission server (port 587) and the inbound server's
//! implicit-TLS AUTH path (port 465) authenticate against the same
//! `users` table. This module gives both servers identical
//! brute-force lockout semantics (per-IP + per-account) and a dummy
//! password verification so that unknown-account lookups take the same
//! time as real-account lookups (user-enumeration side channel).
//!
//! ## Durability
//!
//! Failure counters live in TWO layers:
//!
//! 1. an always-on in-process cache (the pre-existing behaviour —
//!    protects a single replica even when Redis is down), and
//! 2. an optional durable store (Redis via `deadpool-redis`, wired in
//!    `with_redis`) that makes lockouts **survive restarts** and apply
//!    uniformly across **all replicas** behind the same Redis.
//!
//! `is_locked` returns true if EITHER layer is over threshold, so a Redis
//! outage only ever weakens cross-replica aggregation, never the local
//! protection. Durable keys carry a TTL equal to the lockout window, so
//! counters decay exactly like the in-memory ones.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use moka::sync::Cache;

/// Maximum failed attempts for one (IP, account) pair before further
/// attempts from that pair are rejected with a lockout response.
pub const MAX_AUTH_FAILURES_PER_ACCOUNT: u32 = 5;

/// Maximum failed attempts from a single IP across all accounts before
/// that IP is locked out. Deliberately higher than the per-account
/// threshold so one compromised account behind a NAT cannot lock out
/// every other user sharing the IP.
pub const MAX_AUTH_FAILURES_PER_IP: u32 = 20;

/// How long failure counters are retained. The cache TTL is the lockout
/// window: once an entry expires the counters reset and legitimate
/// users can authenticate again.
const FAILURE_WINDOW: Duration = Duration::from_secs(300);

/// Outcome of an authentication attempt, so callers can distinguish a
/// plain wrong-credentials failure from an active brute-force lockout.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthError {
    /// Credentials were rejected (or the account is disabled).
    Failed,
    /// Too many recent failures; the attempt was rejected without
    /// spending any password-verification time.
    LockedOut,
}

/// Durable counter store backing the lockout tracker (Redis in
/// production, an injectable in-memory implementation in tests).
#[async_trait::async_trait]
pub trait FailStore: Send + Sync {
    /// Increment `key` by one and (re)set its TTL to `ttl`.
    async fn incr(&self, key: &str, ttl: Duration) -> anyhow::Result<i64>;
    /// Current value of `key` (0 when absent).
    async fn get(&self, key: &str) -> anyhow::Result<i64>;
    /// Remove `key`.
    async fn del(&self, key: &str) -> anyhow::Result<()>;
}

/// Redis-backed [`FailStore`]. Keys are namespaced under the given
/// prefix and expire with the lockout window.
struct RedisFailStore {
    pool: deadpool_redis::Pool,
    prefix: String,
}

#[async_trait::async_trait]
impl FailStore for RedisFailStore {
    async fn incr(&self, key: &str, ttl: Duration) -> anyhow::Result<i64> {
        let mut conn = self.pool.get().await?;
        let full = format!("{}{key}", self.prefix);
        let value: i64 = redis::cmd("INCR")
            .arg(&full)
            .query_async(&mut *conn)
            .await?;
        let expire: i64 = redis::cmd("EXPIRE")
            .arg(&full)
            .arg(ttl.as_secs() as i64)
            .query_async(&mut *conn)
            .await?;
        let _ = expire;
        Ok(value)
    }

    async fn get(&self, key: &str) -> anyhow::Result<i64> {
        let mut conn = self.pool.get().await?;
        let value: i64 = redis::cmd("GET")
            .arg(format!("{}{key}", self.prefix))
            .query_async(&mut *conn)
            .await?;
        Ok(value)
    }

    async fn del(&self, key: &str) -> anyhow::Result<()> {
        let mut conn = self.pool.get().await?;
        let deleted: i64 = redis::cmd("DEL")
            .arg(format!("{}{key}", self.prefix))
            .query_async(&mut *conn)
            .await?;
        let _ = deleted;
        Ok(())
    }
}

/// Injectable in-memory [`FailStore`] with TTL semantics — used by tests
/// to prove restart/replica persistence of lockout state deterministically
/// (no live Redis required).
pub struct SharedMemoryFailStore {
    counters: Mutex<HashMap<String, (i64, Instant)>>,
}

impl SharedMemoryFailStore {
    pub fn new() -> Self {
        Self {
            counters: Mutex::new(HashMap::new()),
        }
    }

    fn sweep(&self) {
        // Drop expired entries so the map cannot grow without bound.
        self.counters
            .lock()
            .unwrap()
            .retain(|_, (_, expiry)| *expiry > Instant::now());
    }
}

impl Default for SharedMemoryFailStore {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl FailStore for SharedMemoryFailStore {
    async fn incr(&self, key: &str, ttl: Duration) -> anyhow::Result<i64> {
        self.sweep();
        let mut counters = self.counters.lock().unwrap();
        let entry = counters
            .entry(key.to_string())
            .or_insert((0, Instant::now() + ttl));
        entry.0 += 1;
        entry.1 = Instant::now() + ttl; // each failure refreshes the window
        Ok(entry.0)
    }

    async fn get(&self, key: &str) -> anyhow::Result<i64> {
        self.sweep();
        Ok(self
            .counters
            .lock()
            .unwrap()
            .get(key)
            .filter(|(_, expiry)| *expiry > Instant::now())
            .map(|(value, _)| *value)
            .unwrap_or(0))
    }

    async fn del(&self, key: &str) -> anyhow::Result<()> {
        self.counters.lock().unwrap().remove(key);
        Ok(())
    }
}

/// Tracks failed authentication attempts per (IP, account) and per IP.
///
/// - Per-account key `(ip, account)`: an attacker rotating through many
///   accounts from one IP accumulates against each account separately,
///   and one account's failures never lock out a different account.
/// - Per-IP key `ip`: a distributed attack across many accounts from a
///   single IP (e.g. a botnet behind one NAT) is still bounded.
///
/// When constructed with [`AuthFailTracker::with_redis`] the counters are
/// mirrored into Redis so a restart (fresh process = empty caches) or
/// another replica behind the same Redis still sees the failures.
pub struct AuthFailTracker {
    per_account: Cache<(IpAddr, String), u32>,
    per_ip: Cache<IpAddr, u32>,
    store: Option<std::sync::Arc<dyn FailStore>>,
}

impl Default for AuthFailTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl AuthFailTracker {
    pub fn new() -> Self {
        Self {
            per_account: Cache::builder()
                .max_capacity(50_000)
                .time_to_live(FAILURE_WINDOW)
                .build(),
            per_ip: Cache::builder()
                .max_capacity(50_000)
                .time_to_live(FAILURE_WINDOW)
                .build(),
            store: None,
        }
    }

    /// Redis-backed tracker: lockout counters survive restarts and are
    /// shared across every replica using the same Redis.
    pub fn with_redis(pool: deadpool_redis::Pool) -> Self {
        Self::with_redis_prefix(pool, "mta:authfail:")
    }

    /// Prefix-variant of [`AuthFailTracker::with_redis`] (test isolation).
    pub fn with_redis_prefix(pool: deadpool_redis::Pool, prefix: &str) -> Self {
        let mut tracker = Self::new();
        tracker.store = Some(std::sync::Arc::new(RedisFailStore {
            pool,
            prefix: prefix.to_string(),
        }));
        tracker
    }

    /// Injectable durable store for deterministic restart/replica tests.
    pub fn with_store(store: std::sync::Arc<dyn FailStore>) -> Self {
        let mut tracker = Self::new();
        tracker.store = Some(store);
        tracker
    }

    fn account_key(ip: IpAddr, account: &str) -> String {
        format!("acct:{ip}|{account}")
    }

    fn ip_key(ip: IpAddr) -> String {
        format!("ip:{ip}")
    }

    /// Whether further attempts from `ip` for `account` should be
    /// rejected without verifying credentials.
    ///
    /// Locked if EITHER the local cache or the durable store is over a
    /// threshold: a Redis outage can therefore only make the check more
    /// permissive w.r.t. other replicas, never less protective than the
    /// original in-memory behaviour.
    pub async fn is_locked(&self, ip: IpAddr, account: &str) -> bool {
        let account = normalize_account(account);
        let memory_locked = self.per_ip.get(&ip).unwrap_or(0) >= MAX_AUTH_FAILURES_PER_IP
            || self.per_account.get(&(ip, account.clone())).unwrap_or(0)
                >= MAX_AUTH_FAILURES_PER_ACCOUNT;
        if memory_locked {
            return true;
        }
        let Some(store) = self.store.as_ref() else {
            return false;
        };
        for key in [Self::ip_key(ip), Self::account_key(ip, &account)] {
            match store.get(&key).await {
                // ip: keys threshold at MAX_AUTH_FAILURES_PER_IP, acct:
                // keys at MAX_AUTH_FAILURES_PER_ACCOUNT — check both
                // thresholds against both readings; only the matching
                // key can realistically reach the other bound.
                Ok(count) => {
                    let over = if key.starts_with("ip:") {
                        count >= MAX_AUTH_FAILURES_PER_IP as i64
                    } else {
                        count >= MAX_AUTH_FAILURES_PER_ACCOUNT as i64
                    };
                    if over {
                        return true;
                    }
                }
                Err(error) => {
                    // Durable layer unavailable: fall back to the local
                    // cache verdict (already computed above).
                    tracing::debug!(
                        error = %error,
                        "lockout store unavailable; using in-memory counters only"
                    );
                    return memory_locked;
                }
            }
        }
        false
    }

    /// Record one failed attempt (wrong password, disabled account, or
    /// unknown account) against both the per-account and per-IP keys.
    pub async fn record_failure(&self, ip: IpAddr, account: &str) {
        let account = normalize_account(account);
        self.per_ip
            .insert(ip, 1 + self.per_ip.get(&ip).unwrap_or(0));
        self.per_account.insert(
            (ip, account.clone()),
            1 + self.per_account.get(&(ip, account.clone())).unwrap_or(0),
        );
        if let Some(store) = self.store.as_ref() {
            for key in [Self::ip_key(ip), Self::account_key(ip, &account)] {
                if let Err(error) = store.incr(&key, FAILURE_WINDOW).await {
                    tracing::debug!(
                        error = %error,
                        "failed to persist auth-failure counter to durable store"
                    );
                }
            }
        }
    }

    /// Clear both counters after a successful authentication.
    pub async fn reset(&self, ip: IpAddr, account: &str) {
        let account = normalize_account(account);
        self.per_ip.remove(&ip);
        self.per_account.remove(&(ip, account.clone()));
        if let Some(store) = self.store.as_ref() {
            for key in [Self::ip_key(ip), Self::account_key(ip, &account)] {
                if let Err(error) = store.del(&key).await {
                    tracing::debug!(
                        error = %error,
                        "failed to clear auth-failure counter in durable store"
                    );
                }
            }
        }
    }
}

fn normalize_account(account: &str) -> String {
    account.to_lowercase()
}

/// OWASP-parameter Argon2id hash (m=19456, t=2, p=1) of a random
/// password. It never matches any real credentials; it exists so the
/// server can spend real verification time on unknown accounts.
const DUMMY_PASSWORD_HASH: &str = "$argon2id$v=19$m=19456,t=2,p=1$6KmAIGYKaSBl9ASEUmLo9w$TnUkbLd7Q5pk3BfTXwLOaU6A5wYH6YaBGo9sjWvgvIE";

/// Spend the same password-verification time as a real account lookup,
/// then report failure. Returns `false` unconditionally so an unknown
/// account is indistinguishable (by response time) from a real account
/// presented with a wrong password.
pub fn verify_against_dummy(password: &str) -> bool {
    let _ = apexmail_lib::crypto::verify_password(password, DUMMY_PASSWORD_HASH);
    false
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::{Duration, Instant};

    use super::{
        normalize_account, verify_against_dummy, AuthError, AuthFailTracker, FailStore,
        SharedMemoryFailStore, MAX_AUTH_FAILURES_PER_ACCOUNT, MAX_AUTH_FAILURES_PER_IP,
    };

    fn ip(octet: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, octet))
    }

    #[test]
    fn test_not_locked_below_threshold() {
        let tracker = AuthFailTracker::new();
        for _ in 0..MAX_AUTH_FAILURES_PER_ACCOUNT - 1 {
            tokio::runtime::Builder::new_current_thread()
                .build()
                .unwrap()
                .block_on(tracker.record_failure(ip(1), "alice@example.com"));
        }
        tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap()
            .block_on(async {
                assert!(!tracker.is_locked(ip(1), "alice@example.com").await);
            });
    }

    #[tokio::test]
    async fn test_locked_after_five_failures() {
        let tracker = AuthFailTracker::new();
        for _ in 0..MAX_AUTH_FAILURES_PER_ACCOUNT {
            tracker.record_failure(ip(1), "alice@example.com").await;
        }
        assert!(tracker.is_locked(ip(1), "alice@example.com").await);
    }

    #[tokio::test]
    async fn test_success_resets_counters() {
        let tracker = AuthFailTracker::new();
        for _ in 0..MAX_AUTH_FAILURES_PER_ACCOUNT {
            tracker.record_failure(ip(1), "alice@example.com").await;
        }
        assert!(tracker.is_locked(ip(1), "alice@example.com").await);
        tracker.reset(ip(1), "alice@example.com").await;
        assert!(!tracker.is_locked(ip(1), "alice@example.com").await);
    }

    #[tokio::test]
    async fn test_wrong_password_for_account_b_does_not_lock_account_a() {
        let tracker = AuthFailTracker::new();
        for _ in 0..MAX_AUTH_FAILURES_PER_ACCOUNT {
            tracker.record_failure(ip(1), "bob@example.com").await;
        }
        assert!(!tracker.is_locked(ip(1), "alice@example.com").await);
    }

    #[tokio::test]
    async fn test_failures_from_ip_x_do_not_lock_ip_y() {
        let tracker = AuthFailTracker::new();
        for _ in 0..MAX_AUTH_FAILURES_PER_ACCOUNT {
            tracker.record_failure(ip(1), "alice@example.com").await;
        }
        assert!(!tracker.is_locked(ip(2), "alice@example.com").await);
    }

    #[tokio::test]
    async fn test_unknown_account_attempts_count_toward_lockout() {
        // An unknown email is recorded under its attempted address, so it
        // can never be used to bypass the lockout.
        let tracker = AuthFailTracker::new();
        for _ in 0..MAX_AUTH_FAILURES_PER_ACCOUNT {
            tracker.record_failure(ip(1), "ghost@example.com").await;
        }
        assert!(tracker.is_locked(ip(1), "ghost@example.com").await);
    }

    #[tokio::test]
    async fn test_account_insensitive_to_case() {
        let tracker = AuthFailTracker::new();
        for _ in 0..MAX_AUTH_FAILURES_PER_ACCOUNT {
            tracker.record_failure(ip(1), "Alice@Example.COM").await;
        }
        assert!(tracker.is_locked(ip(1), "alice@example.com").await);
    }

    #[tokio::test]
    async fn test_verify_against_dummy_returns_false() {
        assert!(!verify_against_dummy("any-password"));
    }

    #[tokio::test]
    async fn test_verify_against_dummy_spends_real_verification_time() {
        // The dummy verify must actually run the Argon2id verification
        // (same parameters as real password hashes), otherwise the
        // unknown-user fast path would leak account existence through
        // response time.
        let start = Instant::now();
        verify_against_dummy("wrong-password");
        let elapsed = start.elapsed();
        assert!(
            elapsed >= Duration::from_millis(1),
            "dummy verify returned in {elapsed:?}; it must run a real Argon2id verification"
        );
    }

    #[tokio::test]
    async fn test_auth_error_variants_distinguishable() {
        assert_ne!(AuthError::Failed, AuthError::LockedOut);
    }

    // ── durable (restart/replica-safe) lockout semantics ───────────────────

    #[tokio::test]
    async fn lockout_survives_process_restart_via_durable_store() {
        // "Restart": drop the first tracker (its in-memory caches die with
        // it) and build a fresh one on the SAME durable store. The
        // recorded failures must still block authentication.
        let store = std::sync::Arc::new(SharedMemoryFailStore::new());
        let first = AuthFailTracker::with_store(store.clone());
        for _ in 0..MAX_AUTH_FAILURES_PER_ACCOUNT {
            first.record_failure(ip(7), "alice@example.com").await;
        }
        assert!(first.is_locked(ip(7), "alice@example.com").await);
        drop(first); // process "restart"

        let second = AuthFailTracker::with_store(store);
        assert!(
            second.is_locked(ip(7), "alice@example.com").await,
            "lockout state must survive a restart via the durable store"
        );
    }

    #[tokio::test]
    async fn lockout_is_shared_across_replicas_via_durable_store() {
        // Two live "replicas" over one store: failures seen by replica A
        // are immediately visible to replica B even though their
        // in-memory caches are independent.
        let store = std::sync::Arc::new(SharedMemoryFailStore::new());
        let replica_a = AuthFailTracker::with_store(store.clone());
        let replica_b = AuthFailTracker::with_store(store);
        for _ in 0..MAX_AUTH_FAILURES_PER_ACCOUNT {
            replica_a.record_failure(ip(8), "bob@example.com").await;
        }
        assert!(replica_b.is_locked(ip(8), "bob@example.com").await);
    }

    #[tokio::test]
    async fn durable_reset_clears_the_lockout_for_other_replicas() {
        let store = std::sync::Arc::new(SharedMemoryFailStore::new());
        let replica_a = AuthFailTracker::with_store(store.clone());
        let replica_b = AuthFailTracker::with_store(store);
        for _ in 0..MAX_AUTH_FAILURES_PER_ACCOUNT {
            replica_a.record_failure(ip(9), "carol@example.com").await;
        }
        assert!(replica_b.is_locked(ip(9), "carol@example.com").await);
        // A successful auth on replica A clears the durable counters, so
        // replica B no longer blocks the pair either.
        replica_a.reset(ip(9), "carol@example.com").await;
        assert!(!replica_b.is_locked(ip(9), "carol@example.com").await);
    }

    #[tokio::test]
    async fn per_ip_threshold_enforced_through_durable_store() {
        // 20 failures across DIFFERENT accounts from one IP lock the IP
        // (not any single account) — verified through a fresh tracker
        // sharing the durable store, i.e. after a "restart".
        let store = std::sync::Arc::new(SharedMemoryFailStore::new());
        let writer = AuthFailTracker::with_store(store.clone());
        for i in 0..MAX_AUTH_FAILURES_PER_IP {
            writer
                .record_failure(ip(10), &format!("user{i}@example.com"))
                .await;
        }
        let reader = AuthFailTracker::with_store(store);
        assert!(reader.is_locked(ip(10), "fresh-account@example.com").await);
        // ...but a different IP is unaffected.
        assert!(!reader.is_locked(ip(11), "fresh-account@example.com").await);
    }

    #[tokio::test]
    async fn memory_layer_still_blocks_when_durable_store_is_down() {
        // A failing store must never weaken the in-process protection:
        // local failures still lock locally.
        struct BrokenStore;
        #[async_trait::async_trait]
        impl FailStore for BrokenStore {
            async fn incr(&self, _: &str, _: Duration) -> anyhow::Result<i64> {
                anyhow::bail!("store down")
            }
            async fn get(&self, _: &str) -> anyhow::Result<i64> {
                anyhow::bail!("store down")
            }
            async fn del(&self, _: &str) -> anyhow::Result<()> {
                anyhow::bail!("store down")
            }
        }
        let tracker = AuthFailTracker::with_store(std::sync::Arc::new(BrokenStore));
        for _ in 0..MAX_AUTH_FAILURES_PER_ACCOUNT {
            tracker.record_failure(ip(12), "dave@example.com").await;
        }
        assert!(tracker.is_locked(ip(12), "dave@example.com").await);
    }

    #[tokio::test]
    async fn live_redis_lockout_round_trip() {
        // Optional integration check against a real Redis (skipped when
        // unreachable, so CI without Redis stays green). Started via
        // `redis-server` locally it proves the Redis code path end-to-end.
        // F6: no ambient 6379 default — the variable must name the Redis
        // under test explicitly; unset means skip.
        let Ok(url) = std::env::var("REDIS_TEST_URL") else {
            eprintln!("skipping: REDIS_TEST_URL not set");
            return;
        };
        let pool = match deadpool_redis::Config::from_url(&url)
            .create_pool(Some(deadpool_redis::Runtime::Tokio1))
        {
            Ok(pool) => pool,
            Err(_) => {
                eprintln!("skipping: cannot build pool for {url}");
                return;
            }
        };
        let probe = pool.get().await;
        if probe.is_err() {
            eprintln!("skipping: no live Redis at {url}");
            return;
        }
        drop(probe);

        let prefix = format!("test:authfail:{}:", uuid::Uuid::new_v4());
        let first = AuthFailTracker::with_redis_prefix(pool.clone(), &prefix);
        for _ in 0..MAX_AUTH_FAILURES_PER_ACCOUNT {
            first.record_failure(ip(20), "alice@example.com").await;
        }
        // "Restart": a brand-new tracker (empty caches) over the same Redis.
        let second = AuthFailTracker::with_redis_prefix(pool, &prefix);
        assert!(
            second.is_locked(ip(20), "alice@example.com").await,
            "lockout must be read back from live Redis after restart"
        );
        // Cleanup + reset semantics against live Redis.
        second.reset(ip(20), "alice@example.com").await;
        assert!(!second.is_locked(ip(20), "alice@example.com").await);
    }

    #[test]
    fn normalize_account_lowercases() {
        assert_eq!(normalize_account("Alice@Example.COM"), "alice@example.com");
    }
}
