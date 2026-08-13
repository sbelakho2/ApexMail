//! Redis-backed production verification with ONE-SHOT concurrency semantics.
//!
//! [`RedisChallengeStore`] persists [`ChallengeRecord`]s as the language-
//! neutral JSON schema shared with the PHP core (`packages/kiwicaptcha-php`)
//! — the same 18 keys `ChallengeRecord::toArray()` emits — under the key
//! `{prefix}{nonce}` with an EX TTL of `expires_at - now + ttl_margin_secs`
//! (min 1 s, exactly like the PHP `RedisStorage` plus the audit #22/#23 TTL
//! margin). A PHP service and a Rust service can read each other's records
//! from the same Redis instance.
//!
//! [`ProductionVerifier`] implements the PHP verifier's check order with
//! atomic single-use enforced by Redis GETDEL:
//!
//! ```text
//! token decode → store.find(nonce) PEEK (GET) → cheap validation (structure,
//! v1 gate, signature, TTL, scope, IP binding, server-measured min duration) →
//! optional Argon admission gate → store.consume(nonce) (GETDEL) → TOCTOU
//! re-validation of the CONSUMED record → derive hash (once) → leading-zero check
//! ```
//!
//! # One-shot semantics (why exactly one derive per nonce)
//!
//! The cheap phase and the Argon admission gate run against the PEEKED
//! record and never consume: a malformed/expired/mismatched challenge or a
//! gate rejection leaves the record in the store, so the client can retry.
//! Consumption happens exactly once, immediately before hash derivation, via
//! Redis `GETDEL`, which atomically returns AND deletes the key. Under
//! concurrency exactly one caller can ever observe the record: two racing
//! `verify()` calls on the same token yield one [`VerifyOutcome::Valid`] and
//! one [`VerifyOutcome::Invalid(VerifyError::RecordNotFound)`] — the loser
//! never reaches hash derivation, so each nonce drives AT MOST one expensive
//! Argon2id/SHA-256 computation no matter how many requests race for it.
//! This is the distributed bound the caller-managed attempt counter in
//! [`crate::verify::verify_solution`] cannot provide: that counter lives on
//! a per-process record copy, while GETDEL fuses load-and-remove in the
//! store itself (Redis 6.2+, same as PHP's `rawCommand('GETDEL', ...)`).
//!
//! A wrong counter reaches the proof phase and therefore burns the record —
//! replaying any consumed token always fails with `RecordNotFound`. The
//! TOCTOU re-validation after `consume()` makes a swapped/racing record fail
//! closed: the consumed instance must carry the exact challenge that was
//! peeked and must pass the full cheap phase again.
//!
//! # Error semantics (find/consume failures)
//!
//! Storage failures are mapped onto two distinct rejections, never blurred
//! into `RecordNotFound`:
//!
//! - [`VerifyError::StorageUnavailable`] — the PEEK (`find()`) or its pool
//!   checkout failed (unreachable backend, failed connect, read/write
//!   timeout). A GET never consumes, so the challenge is PRESUMED INTACT:
//!   the client may retry it once the store recovers.
//! - [`VerifyError::ConsumeIndeterminate`] — the atomic consume (`GETDEL`)
//!   failed with an uncertain I/O error (e.g. the reply timed out). The
//!   challenge MAY or MAY NOT have been consumed: GETDEL is atomic on the
//!   server, so the record is gone if the command landed and intact if it
//!   never arrived. The verifier NEVER retries the GETDEL automatically —
//!   see the no-retry rule below. The caller should treat the token as
//!   unknown (e.g. re-issue) rather than replay it.
//!
//! `Ok(None)` from `find()`/`consume()` stays [`VerifyError::RecordNotFound`]
//! — a genuinely absent key (never issued, expired away, or already consumed
//! by a concurrent winner).
//!
//! # The GETDEL no-retry rule
//!
//! On an uncertain `consume()` failure the pooled connection is POISONED and
//! r2d2 evicts it (never returned to the idle pool): the GETDEL reply may
//! still be in flight on that socket, and reusing the connection could
//! desync the RESP stream. The failure is reported as
//! [`VerifyError::ConsumeIndeterminate`] and the GETDEL is NEVER
//! automatically retried — a blind retry could burn a record that the
//! original attempt did consume.
//!
//! # Telemetry parity note
//!
//! Telemetry enforcement is a PHP / high-level-integration feature (Privacy
//! Strict disables telemetry anyway). The Rust production API deliberately
//! does not enforce telemetry — this is the documented parity boundary.

use crate::challenge::{
    binding_tag, hash_ip, now_epoch_micros, payload_from_record, verify_signature,
    verify_signature_v2, ChallengeRecord, PoWAlgorithm,
};
use crate::token::SolutionToken;
use crate::verify::{
    ct_eq, derive_hash, leading_zero_bits, signature_from_challenge, validate_record, VerifyError,
    VerifyOutcome, SKEW_TOLERANCE_US,
};
use redis::ConnectionLike;

use std::fmt;
use std::time::Duration;

/// Default number of pooled Redis connections.
pub const DEFAULT_POOL_SIZE: usize = 4;

/// TCP connect timeout for every pooled connection.
///
/// Applied at connect time via `redis::Client::get_connection_with_timeout`.
/// 500 ms is tight enough that a dead backend degrades to
/// [`VerifyError::StorageUnavailable`] quickly, while comfortably covering
/// local/co-located Redis (sub-millisecond connects).
pub const CONNECT_TIMEOUT: Duration = Duration::from_millis(500);

/// Read timeout applied to every pooled connection (per-command).
///
/// A hung Redis degrades to [`VerifyError::StorageUnavailable`] /
/// [`VerifyError::ConsumeIndeterminate`] within this bound instead of
/// blocking a request forever.
pub const READ_TIMEOUT: Duration = Duration::from_secs(1);

/// Write timeout applied to every pooled connection (per-command).
pub const WRITE_TIMEOUT: Duration = Duration::from_secs(1);

/// Maximum time `pool.get()` waits for a free slot (the r2d2 builder's
/// `connection_timeout`). Bounds checkout stalls when every slot is busy
/// with a hung command, and bounds the dead-backend case: `pool.get()`
/// returns this long after the first failed connect.
pub const POOL_CHECKOUT_TIMEOUT: Duration = Duration::from_secs(1);

/// The r2d2 connection manager: opens a real `redis::Connection` per pooled
/// slot with the crate's timeouts applied at connect time, and reports
/// poisoned connections as broken so r2d2 evicts them instead of reusing
/// them (see the module docs — GETDEL no-retry rule).
struct StoreConnectionManager {
    client: redis::Client,
}

/// A pooled Redis connection. `poisoned` is set on any command-level
/// failure: the connection may be protocol-desynced (e.g. a GETDEL whose
/// reply timed out — the reply could still be in flight on the socket), so
/// r2d2 must evict it on return.
struct ManagedConnection {
    inner: redis::Connection,
    poisoned: bool,
}

impl ManagedConnection {
    /// Mark the connection as unusable: r2d2's `has_broken` will evict it
    /// on return instead of returning it to the idle pool.
    fn poison(&mut self) {
        self.poisoned = true;
    }
}

impl redis::ConnectionLike for ManagedConnection {
    fn req_packed_command(&mut self, cmd: &[u8]) -> redis::RedisResult<redis::Value> {
        self.inner.req_packed_command(cmd)
    }

    fn req_packed_commands(
        &mut self,
        cmd: &[u8],
        offset: usize,
        count: usize,
    ) -> redis::RedisResult<Vec<redis::Value>> {
        self.inner.req_packed_commands(cmd, offset, count)
    }

    fn get_db(&self) -> i64 {
        self.inner.get_db()
    }

    fn check_connection(&mut self) -> bool {
        self.inner.check_connection()
    }

    fn is_open(&self) -> bool {
        self.inner.is_open()
    }
}

impl r2d2::ManageConnection for StoreConnectionManager {
    type Connection = ManagedConnection;
    type Error = redis::RedisError;

    fn connect(&self) -> Result<ManagedConnection, redis::RedisError> {
        let inner = self.client.get_connection_with_timeout(CONNECT_TIMEOUT)?;
        inner.set_read_timeout(Some(READ_TIMEOUT))?;
        inner.set_write_timeout(Some(WRITE_TIMEOUT))?;
        Ok(ManagedConnection {
            inner,
            poisoned: false,
        })
    }

    fn is_valid(&self, conn: &mut ManagedConnection) -> Result<(), redis::RedisError> {
        if conn.inner.check_connection() {
            Ok(())
        } else {
            Err(redis::RedisError::from((
                redis::ErrorKind::IoError,
                "pooled connection failed validation (PING)",
            )))
        }
    }

    fn has_broken(&self, conn: &mut ManagedConnection) -> bool {
        conn.poisoned || !conn.inner.is_open()
    }
}

/// Redis-backed challenge store with atomic single-use semantics.
///
/// Records are stored as JSON at `{prefix}{nonce}` with an EX TTL of
/// `expires_at - now` (min 1 s) — byte-compatible with the PHP core's
/// `RedisStorage` (same key layout, same JSON schema, same TTL rule), so
/// records written by one side verify on the other.
///
/// `consume()` uses Redis GETDEL (Redis 6.2+): load and delete are fused,
/// so two concurrent consumers can never both win the record. `find()`
/// peeks with a plain GET — the non-consuming read the verify flow runs
/// before the atomic consume.
///
/// Connections come from a REAL r2d2 connection pool (default size
/// [`DEFAULT_POOL_SIZE`], see [`RedisChallengeStore::with_pool_size`]):
/// each operation checks out a pooled `redis::Connection` instead of
/// opening a fresh one, so concurrent verifies still genuinely race the
/// GETDEL in Redis (each pooled connection has its own socket) without
/// per-request connection churn. Connections are opened lazily on first
/// use and reused; a connection that failed mid-command is poisoned and
/// evicted by r2d2 (see the module docs — the GETDEL no-retry rule).
pub struct RedisChallengeStore {
    pool: r2d2::Pool<StoreConnectionManager>,
    prefix: String,
    /// Number of replicas the SET must be acknowledged by (Redis WAIT)
    /// before `store()` returns (audit #22/#23). 0 = fire-and-forget.
    wait_replicas: u32,
    /// Timeout (ms) for the Redis WAIT after the SET.
    wait_timeout_ms: u64,
    /// Extra seconds added to the EX TTL (`expires_at - now + margin`,
    /// min 1 s) so a challenge survives replica lag / clock skew (audit #23).
    ttl_margin_secs: i64,
}

impl RedisChallengeStore {
    /// Build a store for the given Redis client and key prefix (the PHP core
    /// default prefix is `"kiwicaptcha:"`), with the default pool size
    /// [`DEFAULT_POOL_SIZE`].
    pub fn new(client: redis::Client, prefix: impl Into<String>) -> Self {
        RedisChallengeStore::with_pool_size(client, prefix, DEFAULT_POOL_SIZE)
    }

    /// Build a store with an explicit connection pool size (>= 1).
    ///
    /// # Panics
    ///
    /// Panics if `pool_size` is 0.
    pub fn with_pool_size(
        client: redis::Client,
        prefix: impl Into<String>,
        pool_size: usize,
    ) -> Self {
        assert!(pool_size >= 1, "pool_size must be >= 1");
        let manager = StoreConnectionManager { client };
        // No min_idle and build_unchecked: connections are opened lazily on
        // first use, so building a store never touches the network. The
        // checkout wait is bounded by POOL_CHECKOUT_TIMEOUT; the r2d2
        // defaults for idle_timeout/max_lifetime (10/30 min) and
        // test_on_check_out (PING on checkout) apply, so desynced or stale
        // idle connections are reaped/revalidated by the pool itself.
        let pool = r2d2::Pool::builder()
            .max_size(pool_size as u32)
            .connection_timeout(POOL_CHECKOUT_TIMEOUT)
            .build_unchecked(manager);
        RedisChallengeStore {
            pool,
            prefix: prefix.into(),
            wait_replicas: 0,
            wait_timeout_ms: 0,
            ttl_margin_secs: 0,
        }
    }

    /// Require the stored record to be acknowledged by `wait_replicas`
    /// replicas before `store()` returns: after the SET, a Redis `WAIT
    /// replicas timeout_ms` is issued (audit #22/#23 — replica durability
    /// so a promotion cannot lose a freshly issued challenge). `0` disables
    /// the wait. With no replicas configured, WAIT returns immediately with
    /// 0 acknowledged replicas.
    pub fn with_wait(mut self, wait_replicas: u32, timeout_ms: u64) -> Self {
        self.wait_replicas = wait_replicas;
        self.wait_timeout_ms = timeout_ms;
        self
    }

    /// Add `ttl_margin_secs` seconds to the stored record's EX TTL:
    /// `ttl = max(1, expires_at - now + margin)` (audit #23). A positive
    /// margin keeps the record readable past `expires_at` by replica lag or
    /// clock skew; the verifier's own TTL check still rejects it at
    /// `expires_at`, so the margin never extends the challenge's real
    /// lifetime. 0 = PHP `RedisStorage` parity.
    pub fn with_ttl_margin(mut self, ttl_margin_secs: i64) -> Self {
        self.ttl_margin_secs = ttl_margin_secs;
        self
    }

    /// The configured replica-wait requirement `(replicas, timeout_ms)`.
    pub fn wait_config(&self) -> (u32, u64) {
        (self.wait_replicas, self.wait_timeout_ms)
    }

    /// The configured TTL margin in seconds.
    pub fn ttl_margin_secs(&self) -> i64 {
        self.ttl_margin_secs
    }

    /// The configured connection pool size.
    pub fn pool_size(&self) -> usize {
        self.pool.max_size() as usize
    }

    /// Diagnostic observability: `(total connections, idle connections)`
    /// currently managed by the pool. Exposed for operations and tests; not
    /// part of the stable API surface.
    #[doc(hidden)]
    pub fn debug_pool_state(&self) -> (u32, u32) {
        let state = self.pool.state();
        (state.connections, state.idle_connections)
    }

    /// Check out a pooled connection, applying the crate's timeouts (set at
    /// connect time by the manager). A checkout failure is mapped to a
    /// `redis::RedisError` — the pool's `connection_timeout` bounds the wait.
    fn checkout(&self) -> redis::RedisResult<r2d2::PooledConnection<StoreConnectionManager>> {
        self.pool.get().map_err(|e| {
            redis::RedisError::from((
                redis::ErrorKind::IoError,
                "r2d2 pool checkout failed",
                e.to_string(),
            ))
        })
    }

    /// Run one command on a checked-out connection. Any command-level error
    /// POISONS the connection (its protocol state may be desynced — see the
    /// module docs' GETDEL no-retry rule), then propagates the error.
    fn run_command<T>(
        conn: &mut r2d2::PooledConnection<StoreConnectionManager>,
        f: impl FnOnce(&mut ManagedConnection) -> redis::RedisResult<T>,
    ) -> redis::RedisResult<T> {
        match f(conn) {
            Ok(v) => Ok(v),
            Err(e) => {
                conn.poison();
                Err(e)
            }
        }
    }

    /// Persist a record with `EX ttl = max(1, expires_at - now +
    /// ttl_margin_secs)` — the PHP `RedisStorage::store()` rule plus the
    /// audit #23 TTL margin. An already-expired record is stored with a
    /// 1-second lifetime (it will fail the verifier's TTL check if fetched
    /// in time, and vanish otherwise).
    ///
    /// When [`RedisChallengeStore::with_wait`] configured a replica wait,
    /// a Redis `WAIT replicas timeout_ms` is issued AFTER the SET: the
    /// record is only acknowledged once the requested replica count has it
    /// (or the timeout elapsed), so a promotion cannot lose a freshly
    /// issued challenge. WAIT blocks up to its timeout before replying
    /// (with 0 replicas it blocks the full timeout and returns 0), so the
    /// connection's read timeout is temporarily raised to
    /// `timeout_ms + 500 ms` headroom around the WAIT and restored to
    /// [`READ_TIMEOUT`] afterwards. An I/O failure propagates like any
    /// other command error (the SET may already have landed — retrying the
    /// store overwrites the record, which is safe).
    pub fn store(&self, record: &ChallengeRecord) -> redis::RedisResult<()> {
        let key = format!("{}{}", self.prefix, record.nonce);
        // Infallible for this struct: every field is a String or an integer
        // (no non-finite floats), so serde_json::to_string cannot fail.
        let value = serde_json::to_string(record)
            .expect("ChallengeRecord JSON serialization is infallible");
        let now_unix = now_epoch_micros() / 1_000_000;
        let ttl = (record.expires_at as i64)
            .saturating_sub(now_unix as i64)
            .saturating_add(self.ttl_margin_secs)
            .max(1) as u64;
        let wait_replicas = self.wait_replicas;
        let wait_timeout_ms = self.wait_timeout_ms;
        let mut conn = self.checkout()?;
        Self::run_command(&mut conn, |c| {
            redis::cmd("SET")
                .arg(key)
                .arg(value)
                .arg("EX")
                .arg(ttl)
                .query::<()>(c)?;
            if wait_replicas > 0 {
                // Replica wait (audit #22/#23): WAIT returns the number of
                // replicas that acknowledged the write (>= 0; 0 when no
                // replicas are configured). Headroom so the WAIT reply can
                // never race the pool's read timeout.
                c.inner.set_read_timeout(Some(Duration::from_millis(
                    wait_timeout_ms.saturating_add(500),
                )))?;
                let wait = redis::cmd("WAIT")
                    .arg(wait_replicas)
                    .arg(wait_timeout_ms)
                    .query::<i64>(c);
                // Restore the bounded read timeout even when WAIT failed.
                let restore = c.inner.set_read_timeout(Some(READ_TIMEOUT));
                wait?;
                restore?;
            }
            Ok(())
        })
    }

    /// Load a record WITHOUT consuming it — the peek of the verify flow
    /// (Redis GET).
    ///
    /// Returns `None` when the key is absent, when the stored value is not
    /// valid JSON, or when it does not map onto a [`ChallengeRecord`] — a
    /// corrupt key must never blow up the verify path (mirrors the PHP
    /// `RedisStorage::decode()`). An `Err` is a genuine storage failure
    /// (unreachable backend, timeout) — the verify flow maps it to
    /// [`VerifyError::StorageUnavailable`], never `RecordNotFound`.
    pub fn find(&self, nonce: &str) -> redis::RedisResult<Option<ChallengeRecord>> {
        let key = format!("{}{}", self.prefix, nonce);
        let mut conn = self.checkout()?;
        let raw = Self::run_command(&mut conn, |c| {
            redis::cmd("GET").arg(key).query::<Option<String>>(c)
        })?;
        Ok(raw.and_then(|json| serde_json::from_str(&json).ok()))
    }

    /// Atomically return-and-delete the record for `nonce`.
    ///
    /// Returns `None` when the key is absent, when the stored value is not
    /// valid JSON, or when it does not map onto a [`ChallengeRecord`] — a
    /// corrupt key must never blow up the verify path (mirrors the PHP
    /// `RedisStorage::decode()`). `Ok(None)` also means the record is
    /// already consumed: a replay can never win.
    ///
    /// An `Err` is an UNCERTAIN failure: the GETDEL may or may not have
    /// executed on the server. The connection is poisoned and evicted; the
    /// caller must NOT retry the GETDEL blindly — see the module docs'
    /// no-retry rule.
    pub fn consume(&self, nonce: &str) -> redis::RedisResult<Option<ChallengeRecord>> {
        let key = format!("{}{}", self.prefix, nonce);
        let mut conn = self.checkout()?;
        let raw = Self::run_command(&mut conn, |c| {
            redis::cmd("GETDEL").arg(key).query::<Option<String>>(c)
        })?;
        Ok(raw.and_then(|json| serde_json::from_str(&json).ok()))
    }

    /// Best-effort cleanup of a terminal cheap-failure record. Deletion is
    /// NOT security-critical once the challenge has been rejected, and a
    /// storage error must never turn a cheap invalid submission into an
    /// infrastructure failure — the typed outcome already decided stands.
    /// Failures are swallowed (the record expires via its TTL anyway).
    pub fn best_effort_delete(&self, nonce: &str) {
        let key = format!("{}{}", self.prefix, nonce);
        let Ok(mut conn) = self.checkout() else {
            return;
        };
        let _ = redis::cmd("DEL").arg(key).query::<()>(&mut conn);
    }
}

impl fmt::Debug for RedisChallengeStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RedisChallengeStore")
            .field("prefix", &self.prefix)
            .field("pool_size", &self.pool_size())
            .finish_non_exhaustive()
    }
}

/// Admission control for memory-hard (Argon2id) verifications: a real
/// lease lifecycle instead of a bare predicate.
///
/// Mirrors the PHP `VerificationAdmissionGate` acquire/hold/release
/// semantics: [`ArgonAdmissionGate::acquire`] hands out a [`ArgonLease`]
/// that is released by `Drop` — exactly one `acquire` corresponds to
/// exactly one release. The lease is held across the atomic GETDEL and
/// the single hash derivation in [`ProductionVerifier::verify`], then
/// released when it drops (PHP's acquire/hold/release-in-finally).
///
/// `Ok(None)` rejects the verification with
/// [`VerifyError::CapacityExceeded`]; `Err(_)` rejects with
/// [`VerifyError::AdmissionUnavailable`]. Both happen BEFORE any hash is
/// derived and never consume the record. Only Argon2id records are gated
/// (SHA-256 records are cheap to verify and never gated), matching the
/// PHP verifier.
pub trait ArgonAdmissionGate: Send + Sync {
    /// Try to acquire a capacity lease for one verification of `record`.
    ///
    /// - `Ok(Some(lease))` — capacity granted; the caller holds `lease`
    ///   through the consume + derive and `Drop` performs the release.
    /// - `Ok(None)` — capacity unavailable (`CapacityExceeded`).
    /// - `Err(AdmissionError::Unavailable)` — the gate backend itself is
    ///   unavailable (`AdmissionUnavailable`).
    ///
    /// Must not consume the record: `record` is the peeked (non-consumed)
    /// copy and a rejection leaves it in the store for a retry.
    fn acquire(
        &self,
        record: &ChallengeRecord,
    ) -> Result<Option<Box<dyn ArgonLease>>, AdmissionError>;
}

/// A held admission lease: capacity reserved for exactly one verification.
///
/// The lease is released by `Drop` — one `acquire` corresponds to exactly
/// one release, mirroring the PHP acquire/hold/release-in-finally
/// semantics. Implementors must release their capacity slot in `Drop`.
pub trait ArgonLease: Send {}

/// Why an admission gate could not grant a lease.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdmissionError {
    /// The gate's capacity backend is unavailable.
    Unavailable,
}

/// Production verifier: the PHP core's one-shot flow, backed by
/// [`RedisChallengeStore`] for distributed single-use.
///
/// See the module docs for the check order, the one-shot semantics, the
/// storage error semantics, and the GETDEL no-retry rule.
pub struct ProductionVerifier {
    store: RedisChallengeStore,
    secret_key: String,
    argon_gate: Option<Box<dyn ArgonAdmissionGate>>,
    accept_legacy_v1: bool,
    expected_region: Option<String>,
}

impl ProductionVerifier {
    /// Build a verifier with no Argon admission gate, no legacy-v1
    /// acceptance, and no expected region (all mirror the PHP defaults).
    pub fn new(store: RedisChallengeStore, secret_key: impl Into<String>) -> Self {
        ProductionVerifier {
            store,
            secret_key: secret_key.into(),
            argon_gate: None,
            accept_legacy_v1: false,
            expected_region: None,
        }
    }

    /// Add an Argon2id admission gate (default: none). `acquire` returning
    /// `Ok(None)` rejects with [`VerifyError::CapacityExceeded`]; returning
    /// `Err(_)` rejects with [`VerifyError::AdmissionUnavailable`] — both
    /// before any hash derivation, without consuming the record.
    pub fn with_argon_gate(mut self, gate: impl ArgonAdmissionGate + 'static) -> Self {
        self.argon_gate = Some(Box::new(gate));
        self
    }

    /// The backing store — lets the caller persist issued records under the
    /// same key prefix this verifier consumes from.
    pub fn store(&self) -> &RedisChallengeStore {
        &self.store
    }

    /// Accept protocol-v1 (legacy) challenges during an explicit migration
    /// window. Off by default, exactly like the PHP verifier.
    pub fn with_accept_legacy_v1(mut self, accept: bool) -> Self {
        self.accept_legacy_v1 = accept;
        self
    }

    /// Require every verified challenge to have been issued for this region
    /// (audit #22): a record with a different region — or with no region at
    /// all — is rejected with [`VerifyError::WrongRegion`]. Use
    /// [`ProductionVerifier::without_expected_region`] to clear.
    pub fn with_expected_region(mut self, region: impl Into<String>) -> Self {
        self.expected_region = Some(region.into());
        self
    }

    /// Disable the region expectation (the default).
    pub fn without_expected_region(mut self) -> Self {
        self.expected_region = None;
        self
    }

    /// The configured expected region, if any.
    pub fn expected_region(&self) -> Option<&str> {
        self.expected_region.as_deref()
    }

    /// Verify a client-submitted solution token against the store.
    ///
    /// - `token` — the raw `kiwi__token` value (`base64` of
    ///   `nonce.counter.duration_ms.telemetry`).
    /// - `scope` — the expected auth flow; a record issued for a different
    ///   scope is rejected with [`VerifyError::WrongScope`].
    /// - `client_ip` — the caller's IP, checked against the record's
    ///   nonce-bound binding tag (a record with an empty tag skips the
    ///   check). A `binding_tag` computation failure on an unparsable IP
    ///   rejects as [`VerifyError::IpMismatch`].
    /// - `now_ns` — server receipt time in EPOCH MICROSECONDS (the unit
    ///   shared with the PHP core), used with the record's `issued_at_ns`
    ///   for the server-measured minimum-duration check.
    ///
    /// Flow: decode → PEEK (GET) → cheap validation → Argon admission gate
    /// (acquire → RAII lease) → atomic CONSUME (GETDEL) → TOCTOU
    /// re-validation of the consumed record → single derive → leading-zero
    /// check → lease released by Drop. Terminal cheap failures (malformed
    /// record, unsupported protocol, bad signature, expired, wrong scope,
    /// IP mismatch, TooFast) CONSUME the record via a best-effort DEL,
    /// matching the PHP core's one-shot cheap-failure semantics; capacity /
    /// admission-backend / storage failures never consume. The expensive
    /// proof is burned exactly once, at the GETDEL, so at most one hash
    /// derivation ever runs per nonce (concurrent losers see
    /// `RecordNotFound`).
    ///
    /// Storage failure semantics (see the module docs): a `find()` /
    /// checkout failure rejects with [`VerifyError::StorageUnavailable`]
    /// (the challenge is presumed intact — retryable once the store
    /// recovers); a `consume()` failure rejects with
    /// [`VerifyError::ConsumeIndeterminate`] and the GETDEL is NEVER
    /// retried automatically (the challenge may or may not have been
    /// consumed). `Ok(None)` from either stays
    /// [`VerifyError::RecordNotFound`] — a genuinely absent key.
    pub fn verify(&self, token: &str, scope: &str, client_ip: &str, now_ns: u64) -> VerifyOutcome {
        // 1. Token decode. The counter is bounded here too: the decoder
        //    rejects counter >= SOLVER_MAX_HASHES (VerifyError::CounterTooLarge
        //    territory) with MalformedToken — mirroring the PHP flow.
        let token = match SolutionToken::decode(token) {
            Ok(token) => token,
            Err(_) => return VerifyOutcome::Invalid(VerifyError::MalformedToken),
        };

        // 2. PEEK (non-consuming GET). None → RecordNotFound — the record
        //    was never issued, was already consumed, or expired away. A
        //    storage failure (unreachable backend, timeout) →
        //    StorageUnavailable: the challenge was never touched by the
        //    GET, so it is presumed intact and retryable.
        let peek = match self.store.find(&token.nonce) {
            Ok(Some(record)) => record,
            Ok(None) => return VerifyOutcome::Invalid(VerifyError::RecordNotFound),
            Err(_) => return VerifyOutcome::Invalid(VerifyError::StorageUnavailable),
        };

        // 3. Cheap validation on the PEEKED record. Per the shared
        //    cross-language consumption table (PHP mirrors this), terminal
        //    cheap failures CONSUME the record: malformed stored record,
        //    unsupported protocol, bad signature, expired, wrong scope, IP
        //    mismatch and TooFast all burn the challenge (best-effort DEL —
        //    a cleanup error never overrides the typed outcome), matching
        //    PHP's one-shot cheap-failure semantics. NOT consumed:
        //    missing IP/context (Rust requires the IP), Argon capacity
        //    exhausted, admission backend unavailable, storage unavailable
        //    (presumed intact) and ConsumeIndeterminate (GETDEL never
        //    retried). The expensive proof itself is burned by the GETDEL.
        if let Err(e) = self.check_cheap(&peek, scope, client_ip, now_ns) {
            self.store.best_effort_delete(&token.nonce);
            return VerifyOutcome::Invalid(e);
        }

        // 4. Argon2id admission gate (optional): capacity control before the
        //    memory-hard hash. Only Argon2id records are gated, matching PHP.
        //    acquire() hands out an RAII LEASE: exactly one acquire
        //    corresponds to exactly one release (Drop). The lease binding
        //    stays ALIVE through the atomic GETDEL, the TOCTOU re-check and
        //    the single derivation below, and is released by Drop when
        //    `_lease` goes out of scope — mirroring the PHP
        //    acquire/hold/release-in-finally semantics. Both the `Ok(None)`
        //    (CapacityExceeded) and `Err(_)` (AdmissionUnavailable) paths
        //    return WITHOUT consuming — the record stays for a retry.
        let _lease: Option<Box<dyn ArgonLease>> = if peek.algorithm == PoWAlgorithm::Argon2id {
            match &self.argon_gate {
                Some(gate) => match gate.acquire(&peek) {
                    Ok(Some(lease)) => Some(lease),
                    Ok(None) => return VerifyOutcome::Invalid(VerifyError::CapacityExceeded),
                    Err(_) => return VerifyOutcome::Invalid(VerifyError::AdmissionUnavailable),
                },
                None => None,
            }
        } else {
            None
        };

        // 5. Atomic CONSUME (GETDEL). The one-shot bound: exactly one caller
        //    observes the record, so exactly one derive can ever happen per
        //    nonce. None here means a concurrent verifier won the GETDEL
        //    first (or the key vanished between peek and consume). An
        //    uncertain I/O failure → ConsumeIndeterminate: the challenge may
        //    or may not have been consumed — the GETDEL is NEVER retried.
        let record = match self.store.consume(&token.nonce) {
            Ok(Some(record)) => record,
            Ok(None) => return VerifyOutcome::Invalid(VerifyError::RecordNotFound),
            Err(_) => return VerifyOutcome::Invalid(VerifyError::ConsumeIndeterminate),
        };

        // 6. TOCTOU re-validation of the CONSUMED record: it must carry the
        //    exact challenge that was peeked (constant-time string compare,
        //    like the PHP hash_equals) and must pass the full cheap phase
        //    again — a swapped/racing record fails closed instead of being
        //    verified against bytes that were never validated.
        if !ct_eq(record.challenge.as_bytes(), peek.challenge.as_bytes()) {
            return VerifyOutcome::Invalid(VerifyError::MalformedRecord);
        }
        if let Err(e) = self.check_cheap(&record, scope, client_ip, now_ns) {
            return VerifyOutcome::Invalid(e);
        }

        // 7. Single derive + leading-zero check.
        let hash = match derive_hash(&record, token.counter) {
            Ok(hash) => hash,
            Err(e) => return VerifyOutcome::Invalid(e),
        };
        if leading_zero_bits(&hash) >= record.target_bits {
            // The outcome carries the consumed canonical nonce (jti — audit
            // #37) so callers can correlate the result with the storage key
            // and downstream result tokens.
            VerifyOutcome::Valid {
                nonce: record.nonce,
            }
        } else {
            VerifyOutcome::Invalid(VerifyError::InsufficientWork)
        }
    }

    /// The cheap validation phase: structural validation, the protocol-v1
    /// gate, the signature re-check, TTL, scope, IP binding, and the
    /// server-measured minimum duration — the checks PHP runs against the
    /// peeked record before the Argon admission gate. Run against the
    /// PEEKED record and re-run against the CONSUMED record (TOCTOU guard).
    fn check_cheap(
        &self,
        record: &ChallengeRecord,
        scope: &str,
        client_ip: &str,
        now_ns: u64,
    ) -> Result<(), VerifyError> {
        // 3a. Cheap structural validation BEFORE any crypto or timing work.
        validate_record(record)?;

        // 3b. Protocol version gate: v1 (legacy) only during an explicit
        //     migration window.
        if record.protocol_version == 1 && !self.accept_legacy_v1 {
            return Err(VerifyError::MalformedRecord);
        }

        // 3c. Signature re-check over the protocol-appropriate canonical
        //     input.
        let sig = signature_from_challenge(record);
        let sig_ok = match record.protocol_version {
            1 => verify_signature(&payload_from_record(record), sig, &self.secret_key),
            _ => verify_signature_v2(record, sig, &self.secret_key),
        };
        match sig_ok {
            Ok(true) => {}
            _ => return Err(VerifyError::BadSignature),
        }

        // 3c2. Hard Argon2id parameter ceilings (audit #32) — AFTER the
        //      signature is authenticated, BEFORE any Params::new/allocation.
        if record.algorithm == PoWAlgorithm::Argon2id {
            crate::verify::check_argon2_ceilings(record)?;
        }

        // 3d. TTL (server clock, like the PHP `time()`).
        let now_unix = now_epoch_micros() / 1_000_000;
        if now_unix >= record.expires_at {
            return Err(VerifyError::Expired);
        }

        // 3e. Scope: prevent cross-scope replay.
        if record.scope != scope {
            return Err(VerifyError::WrongScope);
        }

        // 3e2. Region (audit #22): a region-expecting deployment fails
        //      closed on challenges issued for another region — or for no
        //      region at all.
        if let Some(expected) = self.expected_region.as_deref() {
            if record.region.as_deref() != Some(expected) {
                return Err(VerifyError::WrongRegion);
            }
        }

        // 3f. IP binding. The stored record is authoritative: an EMPTY
        //     binding tag means binding is disabled; a non-empty tag means
        //     the challenge IS bound, so a mismatch fails closed
        //     (IpMismatch).
        if !record.binding_tag.is_empty() {
            let expected = match record.protocol_version {
                1 => hash_ip(client_ip, &self.secret_key),
                _ => match binding_tag(&record.nonce, client_ip, &self.secret_key) {
                    Ok(tag) => tag,
                    Err(_) => return Err(VerifyError::IpMismatch),
                },
            };
            if !ct_eq(record.binding_tag.as_bytes(), expected.as_bytes()) {
                return Err(VerifyError::IpMismatch);
            }
        }

        // 3g. Minimum duration, SERVER-measured: the floor is `now_ns` vs
        //     the record's `issued_at_ns` (both epoch microseconds), never
        //     the forgeable client-reported duration. A record without
        //     `issued_at_ns` is malformed (no legacy fallback).
        if record.issued_at_ns == 0 {
            return Err(VerifyError::MalformedRecord);
        }
        if record.min_duration_ms > 0 {
            if now_ns >= record.issued_at_ns {
                if now_ns - record.issued_at_ns < record.min_duration_ms.saturating_mul(1_000) {
                    return Err(VerifyError::TooFast);
                }
            } else if record.issued_at_ns - now_ns > SKEW_TOLERANCE_US {
                return Err(VerifyError::TooFast);
            }
        }

        Ok(())
    }
}
