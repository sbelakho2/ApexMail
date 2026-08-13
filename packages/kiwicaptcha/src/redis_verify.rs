//! Redis-backed production verification with ONE-SHOT concurrency semantics.
//!
//! [`RedisChallengeStore`] persists [`ChallengeRecord`]s as the language-
//! neutral JSON schema shared with the PHP core (`packages/kiwicaptcha-php`)
//! — the same 21 keys `ChallengeRecord::toArray()` emits — under the key
//! `{prefix}{nonce}` with an EX TTL of `expires_at - now + ttl_margin_secs`
//! (min 1 s, exactly like the PHP `RedisStorage` plus the audit #22/#23 TTL
//! margin). A PHP service and a Rust service can read each other's records
//! from the same Redis instance.
//!
//! # Consumed-state transition (audit #74)
//!
//! `consume()` is a Lua TRANSITION, not a GETDEL: the pending record is
//! KEPT in the store with a storage-level runtime field `state =
//! "consumed"` (plus the committed outcome `consumed_result`), so a
//! concurrent loser — or a later replay — observes the consumed record and
//! returns the WINNER'S COMMITTED OUTCOME instead of RecordNotFound and
//! instead of re-deriving. The winner derives exactly once and commits its
//! outcome with [`RedisChallengeStore::commit_result`] (best-effort).
//! A loser that finds the record consumed but NOT yet committed (crash
//! between transition and commit) gets
//! [`VerifyError::ConsumeIndeterminate`].
//!
//! [`ProductionVerifier`] implements the PHP verifier's check order with
//! atomic single-use enforced by the consumed-state transition:
//!
//! ```text
//! token decode → store.find(nonce) PEEK (GET) → cheap validation (structure,
//! v1 gate, signature, TTL incl. the future-time bound, scope, region,
//! policy epoch, issuer, IP binding, server-measured min duration) →
//! optional Argon admission gate → store.consume(nonce) (Lua transition) →
//! first=false → return the stored outcome (or ConsumeIndeterminate) →
//! TOCTOU re-validation of the consumed record → derive hash (once) →
//! FINAL re-validation with a fresh clock read + current expectations →
//! leading-zero check → best-effort commit_result
//! ```
//!
//! # One-shot semantics (why exactly one derive per nonce)
//!
//! The cheap phase and the Argon admission gate run against the PEEKED
//! record and never consume: a malformed/expired/mismatched challenge or a
//! gate rejection leaves the record in the store, so the client can retry.
//! Consumption happens exactly once, immediately before hash derivation,
//! via the atomic Lua transition (pending → consumed). Under concurrency
//! exactly one caller can ever win the transition: two racing `verify()`
//! calls on the same token yield one [`VerifyOutcome::Valid`] (the winner,
//! which derives) and one SAME outcome returned from the stored result (or
//! [`VerifyError::ConsumeIndeterminate`] if it races before the commit) —
//! the loser never reaches hash derivation, so each nonce drives AT MOST one
//! expensive Argon2id/SHA-256 computation no matter how many requests race
//! for it. This is the distributed bound the caller-managed attempt counter
//! in [`crate::verify::verify_solution`] cannot provide: that counter lives
//! on a per-process record copy, while the Lua transition fuses
//! load-and-mark-consumed in the store itself.
//!
//! A wrong counter reaches the proof phase, commits `valid = false` and
//! therefore burns the record — replaying the token returns the stored
//! `InsufficientWork` outcome. The TOCTOU re-validation after `consume()`
//! makes a swapped/racing record fail closed: the consumed instance must
//! carry the exact challenge that was peeked and must pass the full cheap
//! phase again.
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
//! - [`VerifyError::ConsumeIndeterminate`] — the atomic consume failed with
//!   an uncertain I/O error (e.g. the reply timed out), or the record was
//!   already consumed without a committed outcome (crash between the
//!   transition and the outcome commit). The verifier NEVER retries the
//!   consume automatically — see the no-retry rule below. The caller should
//!   treat the token as unknown (e.g. re-issue) rather than replay it.
//!
//! `Ok(None)` from `find()`/`consume()` stays [`VerifyError::RecordNotFound`]
//! — a genuinely absent key (never issued, expired away).
//!
//! # The no-retry rule
//!
//! On an uncertain `consume()` failure the pooled connection is POISONED and
//! r2d2 evicts it (never returned to the idle pool): the reply may still be
//! in flight on that socket, and reusing the connection could desync the
//! RESP stream. The failure is reported as
//! [`VerifyError::ConsumeIndeterminate`] and the consume is NEVER
//! automatically retried — a blind retry could corrupt a record that the
//! original attempt did transition.
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
    ct_eq, derive_hash, final_revalidate, leading_zero_bits, signature_from_challenge,
    validate_record, VerifyError, VerifyOutcome, SKEW_TOLERANCE_US,
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

/// One Lua script for the consumed-state TRANSITION (audit #74): atomically
/// marks a pending record consumed (KEEPING it — the storage-level `state`
/// field is added), or observes the already-consumed record.
///
/// Returns (as a RESP array):
/// - missing key → `false` (Lua nil → RESP null → [`VerifyError::RecordNotFound`]);
/// - `[record_json, 1]` — this caller won the transition (first);
/// - `[record_json, 0]` — already consumed by a concurrent caller (the
///   record_json carries `state` and, once committed, `consumed_result`).
///
/// The record's original TTL is preserved on the re-SET so the challenge
/// still expires on schedule.
///
/// The `state` field is appended as a RAW STRING splice — the record's own
/// JSON bytes are NEVER re-encoded. Re-encoding through `cjson.encode`
/// would rewrite large integers (`issued_at_ns` ~1.7e15) in scientific
/// notation, which the strict cross-language parsers reject. PHP mirrors
/// this script byte-for-byte.
const CONSUME_TRANSITION_LUA: &str = r#"
local v = redis.call('GET', KEYS[1])
if not v then return false end
local d = cjson.decode(v)
if type(d) ~= 'table' or d[1] ~= nil then return false end
if d.state == 'consumed' then
    return {v, 0}
end
if string.sub(v, -1) ~= '}' then return false end
local ttl = redis.call('TTL', KEYS[1])
if ttl < 1 then ttl = 1 end
redis.call('SET', KEYS[1], string.sub(v, 1, -2) .. ',"state":"consumed"}', 'EX', ttl)
return {v, 1}
"#;

/// One Lua script for the best-effort outcome commit (audit #74): stores
/// `consumed_result = {valid, binding}` exactly once, only when the record
/// is already `consumed` and carries no result yet. Returns 1 when stored,
/// 0 otherwise. Like [`CONSUME_TRANSITION_LUA`], the record's JSON bytes
/// are kept untouched — only the small result object is freshly encoded
/// (bools + a short string, immune to the cjson large-integer issue).
const COMMIT_RESULT_LUA: &str = r#"
local v = redis.call('GET', KEYS[1])
if not v then return 0 end
local d = cjson.decode(v)
if type(d) ~= 'table' or d[1] ~= nil then return 0 end
if d.state ~= 'consumed' then return 0 end
if d.consumed_result ~= nil then return 0 end
if string.sub(v, -1) ~= '}' then return 0 end
local result
if ARGV[2] ~= '' then
    result = cjson.encode({valid = ARGV[1] == '1', binding = ARGV[2]})
else
    result = cjson.encode({valid = ARGV[1] == '1'})
end
local ttl = redis.call('TTL', KEYS[1])
if ttl < 1 then ttl = 1 end
redis.call('SET', KEYS[1], string.sub(v, 1, -2) .. ',"consumed_result":' .. result .. '}', 'EX', ttl)
return 1
"#;

/// The result of the consumed-state transition (audit #74).
#[derive(Debug, Clone)]
pub struct ConsumeResult {
    /// The consumed record (the value as stored — the runtime `state` /
    /// `consumed_result` fields are stripped).
    pub record: ChallengeRecord,
    /// `true` when THIS caller performed the pending → consumed transition
    /// and owns the single derivation; `false` when the record was already
    /// consumed by a concurrent caller (see `stored_result`).
    pub first: bool,
    /// The outcome a previous consumer committed, when one exists. Only
    /// meaningful when `first == false`.
    pub stored_result: Option<StoredConsumedResult>,
}

/// A committed verification outcome, persisted at the STORAGE layer (audit
/// #74) so a concurrent or retried consumer returns the SAME outcome
/// without re-deriving. This is storage-level runtime state — it is never
/// part of the [`ChallengeRecord`] wire schema.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct StoredConsumedResult {
    /// Whether the proof met the difficulty target.
    pub valid: bool,
    /// The record's application-supplied transaction binding at commit time.
    pub binding: Option<String>,
}

/// A stored value decoded at the storage layer: the [`ChallengeRecord`]
/// plus the optional committed outcome (audit #74). The `state` field is
/// stripped from the JSON by [`decode_stored`] (it must never leak into the
/// strict record parse); the transition flag comes from the Lua reply.
struct StoredChallenge {
    record: ChallengeRecord,
    consumed_result: Option<StoredConsumedResult>,
}

/// Decode a stored value that MAY carry the storage-level runtime fields
/// `state` / `consumed_result`. The runtime fields are stripped BEFORE the
/// strict [`ChallengeRecord`] parse, so `deny_unknown_fields` stays
/// effective: any other foreign key makes the whole value undecodable.
/// Returns `None` on any parse failure — a corrupt key must never blow up
/// the verify path (mirrors the PHP `RedisStorage::decode()`).
fn decode_stored(raw: &str) -> Option<StoredChallenge> {
    let mut value: serde_json::Value = serde_json::from_str(raw).ok()?;
    let consumed_result = value
        .get("consumed_result")
        .and_then(|v| serde_json::from_value(v.clone()).ok());
    let obj = value.as_object_mut()?;
    obj.remove("state");
    obj.remove("consumed_result");
    let record: ChallengeRecord = serde_json::from_value(value).ok()?;
    Some(StoredChallenge {
        record,
        consumed_result,
    })
}

/// Parse the RESP reply of [`CONSUME_TRANSITION_LUA`] into a
/// [`ConsumeResult`]: `nil` → `None` (missing key); `[raw, 1|0]` → the
/// consumed record with the `first` flag. The stored outcome is taken from
/// the returned JSON itself, so `first == false` carries the winner's
/// committed result when one exists.
fn parse_consume(value: redis::Value) -> Option<ConsumeResult> {
    let (raw, first) = match value {
        redis::Value::Nil => return None,
        redis::Value::Array(items) if items.len() == 2 => {
            let raw = match &items[0] {
                redis::Value::BulkString(bytes) => String::from_utf8_lossy(bytes).into_owned(),
                _ => return None,
            };
            let first = matches!(&items[1], redis::Value::Int(1));
            (raw, first)
        }
        _ => return None,
    };
    let stored = decode_stored(&raw)?;
    Some(ConsumeResult {
        record: stored.record,
        first,
        stored_result: if first { None } else { stored.consumed_result },
    })
}
/// Redis-backed challenge store with atomic single-use semantics.
///
/// Records are stored as JSON at `{prefix}{nonce}` with an EX TTL of
/// `expires_at - now` (min 1 s) — byte-compatible with the PHP core's
/// `RedisStorage` (same key layout, same JSON schema, same TTL rule), so
/// records written by one side verify on the other.
///
/// `consume()` is a Lua TRANSITION (audit #74): the pending record is kept
/// with a storage-level `state = "consumed"` field so a concurrent loser
/// returns the winner's committed outcome instead of re-deriving.
/// `find()` peeks with a plain GET — the non-consuming read the verify flow
/// runs before the atomic consume.
///
/// Connections come from a REAL r2d2 connection pool (default size
/// [`DEFAULT_POOL_SIZE`], see [`RedisChallengeStore::with_pool_size`]):
/// each operation checks out a pooled `redis::Connection` instead of
/// opening a fresh one, so concurrent verifies still genuinely race the
/// transition in Redis (each pooled connection has its own socket) without
/// per-request connection churn. Connections are opened lazily on first
/// use and reused; a connection that failed mid-command is poisoned and
/// evicted by r2d2 (see the module docs — the no-retry rule).
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
        Ok(raw.and_then(|json| decode_stored(&json).map(|s| s.record)))
    }

    /// Atomically transition the record for `nonce` from `pending` to
    /// `consumed` — the one-shot bound of the verify flow (audit #74).
    ///
    /// ONE Lua script on the server:
    /// - `pending` → the record is KEPT with `state = "consumed"` and
    ///   `{record, first = true}` is returned — the caller owns the single
    ///   derivation and must commit its outcome with [`Self::commit_result`].
    /// - `consumed` → `{record, first = false}` is returned; the caller must
    ///   return the record's COMMITTED outcome (or
    ///   [`VerifyError::ConsumeIndeterminate`] when no outcome was committed
    ///   yet — the previous consumer crashed between transition and commit).
    /// - missing → `Ok(None)` (RecordNotFound).
    ///
    /// The `state` / `consumed_result` JSON fields are STORAGE-LEVEL runtime
    /// state only — the [`ChallengeRecord`] wire schema itself is unchanged,
    /// and the record fields parse strictly (`deny_unknown_fields` still
    /// applies to anything that is not `state`/`consumed_result`).
    ///
    /// An `Err` is an UNCERTAIN failure: the transition may or may not have
    /// executed on the server. The connection is poisoned and evicted; the
    /// caller must NOT retry the consume blindly — see the module docs'
    /// no-retry rule.
    pub fn consume(&self, nonce: &str) -> redis::RedisResult<Option<ConsumeResult>> {
        let key = format!("{}{}", self.prefix, nonce);
        let mut conn = self.checkout()?;
        let value = Self::run_command(&mut conn, |c| {
            redis::Script::new(CONSUME_TRANSITION_LUA)
                .key(key)
                .invoke::<redis::Value>(c)
        })?;
        Ok(parse_consume(value))
    }

    /// Best-effort persistence of the proof outcome for an already-consumed
    /// record (audit #74): ONE Lua script stores `{valid, binding}` exactly
    /// once, and only while the record is in the `consumed` state with no
    /// result yet.
    ///
    /// Returns `Ok(true)` when the result was stored, `Ok(false)` when a
    /// result already exists or the record is missing / not consumed,
    /// `Err(_)` on a storage failure. CALLERS MUST IGNORE THE RESULT: the
    /// commit is best-effort — a storage failure must never change the
    /// verification outcome (the record expires via its TTL anyway).
    pub fn commit_result(
        &self,
        nonce: &str,
        valid: bool,
        binding: Option<&str>,
    ) -> redis::RedisResult<bool> {
        let key = format!("{}{}", self.prefix, nonce);
        let mut conn = self.checkout()?;
        let stored = Self::run_command(&mut conn, |c| {
            redis::Script::new(COMMIT_RESULT_LUA)
                .key(key)
                .arg(if valid { "1" } else { "0" })
                .arg(binding.unwrap_or(""))
                .invoke::<i64>(c)
        })?;
        Ok(stored == 1)
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
    expected_policy_version: Option<u32>,
    expected_issuer: Option<String>,
    /// Clock override (the PHP Verifier's `$now` closure equivalent):
    /// returns the current Unix time in seconds used by the TTL checks and
    /// the post-derive final re-validation. Defaults to the real clock.
    now_unix: fn() -> u64,
}

fn real_now_unix() -> u64 {
    now_epoch_micros() / 1_000_000
}

impl ProductionVerifier {
    /// Build a verifier with no Argon admission gate, no legacy-v1
    /// acceptance, and no expected region / policy epoch / issuer (all
    /// mirror the PHP defaults).
    pub fn new(store: RedisChallengeStore, secret_key: impl Into<String>) -> Self {
        ProductionVerifier {
            store,
            secret_key: secret_key.into(),
            argon_gate: None,
            accept_legacy_v1: false,
            expected_region: None,
            expected_policy_version: None,
            expected_issuer: None,
            now_unix: real_now_unix,
        }
    }

    /// Override the verifier's clock: `f` returns the current Unix time in
    /// seconds used by the TTL checks and the post-derive final
    /// re-validation (audit #59). Mirrors the PHP Verifier's `$now` clock
    /// override; the default is the real clock.
    #[doc(hidden)]
    pub fn with_now_fn(mut self, f: fn() -> u64) -> Self {
        self.now_unix = f;
        self
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

    /// Require every verified challenge to have been issued under the
    /// CURRENT security-policy epoch (audit #42): a record with a different
    /// `policy_version` is rejected with [`VerifyError::WrongPolicyVersion`]
    /// — outstanding challenges die immediately on policy revocation
    /// (origin/action-policy changes, emergency revocation, compromised
    /// tenant). Use [`ProductionVerifier::without_expected_policy_version`]
    /// to clear.
    pub fn with_expected_policy_version(mut self, version: u32) -> Self {
        self.expected_policy_version = Some(version);
        self
    }

    /// Disable the policy-epoch expectation (the default).
    pub fn without_expected_policy_version(mut self) -> Self {
        self.expected_policy_version = None;
        self
    }

    /// The configured expected policy epoch, if any.
    pub fn expected_policy_version(&self) -> Option<u32> {
        self.expected_policy_version
    }

    /// Require every verified challenge to have been issued by this issuer
    /// (audit #67): a record with a different issuer — or with no issuer at
    /// all — is rejected with [`VerifyError::WrongIssuer`] (fail closed,
    /// like the region expectation). Use
    /// [`ProductionVerifier::without_expected_issuer`] to clear.
    pub fn with_expected_issuer(mut self, issuer: impl Into<String>) -> Self {
        self.expected_issuer = Some(issuer.into());
        self
    }

    /// Disable the issuer expectation (the default).
    pub fn without_expected_issuer(mut self) -> Self {
        self.expected_issuer = None;
        self
    }

    /// The configured expected issuer, if any.
    pub fn expected_issuer(&self) -> Option<&str> {
        self.expected_issuer.as_deref()
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

        // 5. Atomic CONSUME (the pending → consumed TRANSITION, audit #74).
        //    The one-shot bound: exactly one caller wins the transition and
        //    derives; a concurrent loser observes `first == false` and
        //    returns the WINNER'S COMMITTED OUTCOME (Valid/InsufficientWork)
        //    WITHOUT re-deriving — or ConsumeIndeterminate when the winner
        //    crashed between the transition and the outcome commit. An
        //    uncertain I/O failure → ConsumeIndeterminate: the transition
        //    may or may not have executed — the consume is NEVER retried.
        let consumed = match self.store.consume(&token.nonce) {
            Ok(Some(consumed)) => consumed,
            Ok(None) => return VerifyOutcome::Invalid(VerifyError::RecordNotFound),
            Err(_) => return VerifyOutcome::Invalid(VerifyError::ConsumeIndeterminate),
        };
        if !consumed.first {
            return match consumed.stored_result {
                Some(result) => {
                    if result.valid {
                        VerifyOutcome::Valid {
                            nonce: consumed.record.nonce,
                            request_binding: result.binding,
                        }
                    } else {
                        VerifyOutcome::Invalid(VerifyError::InsufficientWork)
                    }
                }
                None => VerifyOutcome::Invalid(VerifyError::ConsumeIndeterminate),
            };
        }
        let record = consumed.record;

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

        // 7. Single derive.
        let hash = match derive_hash(&record, token.counter) {
            Ok(hash) => hash,
            Err(e) => return VerifyOutcome::Invalid(e),
        };

        // 7b. POST-DERIVE FINAL re-validation (audit #59): re-read the
        //     CURRENT server time and the current expectations — the
        //     challenge may have expired DURING the expensive derivation,
        //     or the policy epoch / region / issuer expectations may have
        //     changed while the hash was computing. A failure here is
        //     terminal: the record is already consumed, no outcome is
        //     committed, and a concurrent loser sees ConsumeIndeterminate
        //     (honest — the stored result only ever IS a proof verdict).
        if let Err(e) = final_revalidate(
            &record,
            (self.now_unix)(),
            self.expected_region.as_deref(),
            self.expected_policy_version,
            self.expected_issuer.as_deref(),
        ) {
            return VerifyOutcome::Invalid(e);
        }

        // 8. Leading-zero check + best-effort outcome commit (audit #74):
        //    the winner stores the proof verdict so concurrent/retried
        //    consumers return the SAME outcome without re-deriving. The
        //    commit is best-effort — a storage failure must never change
        //    the outcome.
        if leading_zero_bits(&hash) >= record.target_bits {
            let outcome = VerifyOutcome::Valid {
                nonce: record.nonce.clone(),
                request_binding: record.request_binding.clone(),
            };
            let _ = self
                .store
                .commit_result(&token.nonce, true, record.request_binding.as_deref());
            outcome
        } else {
            let _ =
                self.store
                    .commit_result(&token.nonce, false, record.request_binding.as_deref());
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

        // 3d. TTL (server clock, like the PHP `time()`). The challenge is
        //     invalid outside its validity window [issued_at, expires_at):
        //     expired once now reaches expires_at, and (audit #76) a
        //     future-issued challenge is a time-domain anomaly when its
        //     issued_at is more than MAX_CLOCK_SKEW_SECS ahead of the
        //     verifier clock.
        let now_unix = (self.now_unix)();
        if now_unix >= record.expires_at {
            return Err(VerifyError::Expired);
        }
        if record.issued_at > now_unix.saturating_add(crate::challenge::MAX_CLOCK_SKEW_SECS) {
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

        // 3e3. Security-policy epoch (audit #42): the policy that authorized
        //      this challenge must still be in force.
        if let Some(expected) = self.expected_policy_version {
            if record.policy_version != expected {
                return Err(VerifyError::WrongPolicyVersion);
            }
        }

        // 3e4. Issuer identity (audit #67): an issuer-expecting deployment
        //      rejects challenges issued by another issuer — or by no
        //      issuer at all (fail closed).
        if let Some(expected) = self.expected_issuer.as_deref() {
            if record.issuer.as_deref() != Some(expected) {
                return Err(VerifyError::WrongIssuer);
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::challenge::{issue_challenge, BindingMode};
    use crate::verify::solve_for_test;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    const SECRET: &str = "0123456789abcdef0123456789abcdef";
    const IP: &str = "198.51.100.7";

    fn redis_url() -> Option<String> {
        match std::env::var("RISK_REDIS_URL") {
            Ok(url) => Some(url),
            Err(_) => {
                eprintln!("RISK_REDIS_URL unset — Redis integration test skipped");
                None
            }
        }
    }

    fn now_unix() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    fn now_micros() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_micros() as u64
    }

    fn sha_config(target_bits: u32) -> crate::challenge::ChallengeConfig {
        crate::challenge::ChallengeConfig {
            secret_key: SECRET.into(),
            algorithm: PoWAlgorithm::Sha256,
            m_kib: 0,
            t: 1,
            p: 1,
            target_bits,
            argon2_target_bits: target_bits,
            ttl_secs: 120,
            min_duration_ms: None,
            auto_tune: false,
            auto_tune_min_bits: 8,
            auto_tune_max_bits: 20,
            binding_mode: BindingMode::Bound,
            region: None,
            issuer: None,
            policy_version: 1,
        }
    }

    fn encode_token(nonce: &str, counter: u64) -> String {
        crate::token::SolutionToken {
            nonce: nonce.into(),
            counter,
            duration_ms: 5000,
            telemetry: serde_json::json!({}),
        }
        .encode()
    }

    /// Deterministic fake clock for the final-revalidation race: returns
    /// `BASE` for the first two reads (the cheap phase's peek + the
    /// post-consume TOCTOU re-check) and `BASE + 1` afterwards — simulating
    /// the wall clock ADVANCING PAST expires_at while the proof derives.
    /// The verifier's clock reads are exactly: cheap(peek), cheap(recheck),
    /// final gate — so the first two see `BASE` and the final gate sees
    /// `BASE + 1`.
    static FAKE_NOW_BASE: AtomicU64 = AtomicU64::new(0);
    static FAKE_NOW_CALLS: AtomicU64 = AtomicU64::new(0);

    fn fake_now() -> u64 {
        let call = FAKE_NOW_CALLS.fetch_add(1, Ordering::SeqCst);
        let base = FAKE_NOW_BASE.load(Ordering::SeqCst);
        if call >= 2 {
            base + 1
        } else {
            base
        }
    }

    #[test]
    fn expired_during_derivation_is_rejected_by_the_final_revalidation() {
        // Audit #59 at the production boundary: the challenge expires WHILE
        // the proof derives. The cheap phase (peek + post-consume re-check)
        // passes at time BASE; the FINAL re-validation RE-READS the clock
        // (the race) and sees BASE + 1 ≥ expires_at → Expired, even though
        // the record was already consumed. Fully deterministic — the
        // verifier's clock is injected (the PHP `$now` override equivalent),
        // so the test never depends on wall-clock timing.
        let Some(url) = redis_url() else { return };
        let prefix = format!("kiwitest:derive-race:{}:", std::process::id());

        let base = now_unix();
        FAKE_NOW_BASE.store(base, Ordering::SeqCst);
        let config = crate::challenge::ChallengeConfig {
            ttl_secs: 1, // expires_at = base + 1
            ..sha_config(4)
        };
        let issued = issue_challenge(&config, "login", IP, base, now_micros(), 0, None).unwrap();
        let counter = solve_for_test(&issued.record).expect("4-bit sha solves");
        let issued_at_ns = issued.record.issued_at_ns;

        let store = RedisChallengeStore::new(redis::Client::open(url).unwrap(), prefix.clone());
        store.store(&issued.record).unwrap();
        let verifier = ProductionVerifier::new(store, SECRET).with_now_fn(fake_now);

        let token = encode_token(&issued.record.nonce, counter);
        FAKE_NOW_CALLS.store(0, Ordering::SeqCst);
        assert_eq!(
            verifier.verify(&token, "login", IP, issued_at_ns + 1_000_000),
            VerifyOutcome::Invalid(VerifyError::Expired),
            "the final re-validation re-reads the clock: expired during the derive → Expired"
        );

        // The gate failure is terminal and commits NO outcome: a replay sees
        // the consumed record without a stored result → ConsumeIndeterminate
        // (deterministic — pins the no-commit-on-gate-failure semantics).
        FAKE_NOW_CALLS.store(0, Ordering::SeqCst);
        assert_eq!(
            verifier.verify(&token, "login", IP, issued_at_ns + 1_000_000),
            VerifyOutcome::Invalid(VerifyError::ConsumeIndeterminate)
        );
    }
}
