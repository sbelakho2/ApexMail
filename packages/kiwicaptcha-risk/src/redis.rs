//! Redis-backed risk state store running the canonical risk-v1 Lua script.
//!
//! The script is the shared cross-language asset, embedded verbatim from
//! this package's `resources/risk-v1.lua` (a copy of
//! `<repo-root>/protocol/risk-v1/risk-v1.lua`) and executed via
//! `redis::Script` (evalsha with an automatic noscript fallback inside
//! `ScriptInvocation::invoke`, sha cached in the store's `Script`).
//!
//! All keys carry the hash tag `{kiwi:<namespace>}` so the script is
//! Cluster safe. Source/subnet keys are epoch-scoped: the observation
//! carries three per-epoch pseudonyms (prev/current/next) and each key
//! uses the pseudonym HMAC'd with its own epoch. The Lua's `network_risk`
//! slot (always 0) is overridden with the observation's classifier-derived
//! network risk; `principal_credit` is parsed from reply slot 12 and
//! `is_duplicate` from slot 15.
//!
//! Connections: a small round-robin pool of `pool_size` lazy connections
//! (default 4), each configured with the fail-fast timeouts below.
//! Timeouts: the sync `redis` crate has no `ConnectionConfig`/response
//! timeout (that is the async API); the equivalent sync settings are
//! `Client::get_connection_with_timeout` (connection, 75 ms) and
//! `Connection::set_read_timeout`/`set_write_timeout` (command, 10 ms).
//!
//! Broken connections are evicted, never reused (the same policy the
//! sister crate's `redis_verify` pool applies — see its no-retry rule):
//! any invocation/command error evicts the slot (the connection is
//! dropped, so the next acquire on that slot reconnects), because a
//! timed-out or failed reply may still be in flight on the socket and
//! reusing the connection could desync the Redis reply stream — the next
//! assessment would silently parse shifted values into the risk
//! [`SignalVector`]. A pooled slot whose socket is no longer open (a
//! Redis restart, an idle TCP reset) is detected on acquire via the
//! cheap `is_open` check and replaced the same way, so a backend restart
//! heals per slot on the next use instead of leaving every slot broken
//! until process restart.

use std::sync::atomic::{AtomicU64, AtomicU8, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use crate::event::RiskObservation;
use crate::namespace::{deployment_namespace, NamespaceVersion};
use crate::signals::SignalVector;
use crate::store::{
    AssessV2Reply, Observed, OutcomeRegistration, RiskStateStore, RiskStoreError,
    SessionContextTagStore, SessionTlsTagStore,
};
use ::redis as redis_crate;
use ::redis::ConnectionLike as _;

/// The canonical risk-v1 state script, embedded verbatim from this
/// package's resources directory (kept in sync with the shared protocol
/// asset `protocol/risk-v1/risk-v1.lua`).
pub const SCRIPT: &str = include_str!("../resources/risk-v1.lua");

/// The canonical outcome-ledger scripts (shared verbatim with PHP
/// `protocol/risk-v1/outcome_*.lua`): the always-on, calibration-
/// independent ledger. With calibration disabled the store registers a
/// pending ledger entry per decision and flips it exactly once on
/// confirmation; with calibration enabled the register_decision/confirm/
/// correction scripts do the same inside the calibration namespace.
pub const OUTCOME_REGISTER_LUA: &str = include_str!("../resources/outcome_register.lua");
pub const OUTCOME_CONFIRM_LUA: &str = include_str!("../resources/outcome_confirm.lua");
pub const OUTCOME_CORRECT_LUA: &str = include_str!("../resources/outcome_correct.lua");

/// The consolidated risk-v2 assessment script (shared verbatim with PHP):
/// one atomic invocation that runs the full risk-v1 observation, records
/// the session's first-seen client-context + trusted-edge TLS tags and
/// (when requested) registers the decision's pending outcome-ledger
/// entry, returning the signal vector, the recorded tag values and the
/// registration status.
pub const ASSESS_V2_LUA: &str = include_str!("../resources/assess_v2.lua");

/// The canonical long-memory outcome-mark script (shared verbatim with
/// PHP `protocol/risk-v1/marks.lua`): one atomic mark write — the kind,
/// the count increment, the first/last timestamps and the refreshed
/// whole-key TTL land in a single invocation.
pub const MARKS_LUA: &str = include_str!("../resources/marks.lua");

/// The canonical target-failure state script (shared verbatim with PHP
/// `protocol/risk-v1/target_failure.lua`): the leaky-bucket failure
/// counter and the source/asn spread HLLs of the target dimension.
pub const TARGET_FAILURE_LUA: &str = include_str!("../resources/target_failure.lua");

/// The canonical context-bound session-trust script (shared verbatim
/// with PHP `protocol/risk-v1/trust.lua`): one atomic bucket-record
/// read, credit or decay — the decay anchor, the clamped fixed-point
/// trust, the first/last timestamps and the refreshed whole-key TTL
/// (the session dimension TTL) land in a single invocation.
pub const TRUST_LUA: &str = include_str!("../resources/trust.lua");

/// The mark dimensions of the long-memory outcomes surface: the four
/// identity dimensions the typed handles carry plus the asn dimension
/// the network-aware callers address. Shared verbatim with the PHP
/// mirror and the cross-language vectors.
pub const MARK_DIMENSIONS: [&str; 5] = ["principal", "target", "session", "agent", "asn"];

/// Default lifetime of a long-memory mark: 90 days (7776000 s).
pub const DEFAULT_MARK_TTL_SECS: u64 = 7_776_000;

/// The largest accepted mark kind length in bytes (the outcome name).
pub const MAX_MARK_KIND_BYTES: usize = 64;

/// Default raw saturations in Lua argv order:
/// src_fast, src_slow, issue, bad, mal, rep, action, switch, global,
/// trust, principal.
pub const DEFAULT_SATURATIONS: [u32; 11] = [
    8000, 100000, 6000, 4000, 3000, 2000, 6000, 10000, 70000, 10000, 10000,
];

/// Default outcome-ledger TTL (seconds): the pending/L/A ledger entries
/// expire after 24 h (configurable via
/// [`RedisRiskStateStore::with_options`]).
pub const DEFAULT_OUTCOME_TTL_SECS: u64 = 86_400;

/// The largest accepted TTL in seconds: 10 years. The bound keeps every
/// accepted TTL inside the Redis expire range on every deployment (the
/// Lua scripts validate the same ceiling as the last line of defense)
/// while a fatter window cannot persist risk state for longer than the
/// deployment's own retention contract.
pub const MAX_TTL_SECS: u64 = 315_360_000;

/// Default number of pooled Redis connections.
pub const DEFAULT_POOL_SIZE: usize = 4;

/// Redis-backed [`RiskStateStore`].
pub struct RedisRiskStateStore {
    client: redis_crate::Client,
    /// The encoded namespace inside the `{kiwi:<ns>}` hash tag, derived
    /// from `raw_namespace` through the shared deployment derivation.
    namespace: String,
    /// The raw configured deployment discriminator: kept so the namespace
    /// version can be switched explicitly after construction, and so the
    /// encoded value is never mistaken for the deployment identity.
    raw_namespace: String,
    /// The key-version contract the encoded namespace was derived under.
    namespace_version: NamespaceVersion,
    /// The pre-built hash-tag prefix `{kiwi:<ns>}` shared by every key the
    /// store touches: computed once at construction, so the per-assessment
    /// key construction prefixes it instead of re-interpolating the
    /// namespace, and the cluster-safety check compares the prefix (a
    /// shared prefix implies a shared cluster slot) instead of recomputing
    /// CRC-16 over each key's tag.
    key_tag: String,
    state_ttl_secs: u64,
    dedupe_ttl_secs: u64,
    target_ttl_secs: u64,
    hysteresis_ms: u64,
    session_ttl_secs: u64,
    principal_ttl_secs: u64,
    outcome_ttl_secs: u64,
    mark_ttl_secs: u64,
    saturations: [u32; 11],
    /// Shared, immutable script handles: the Lua sources are ~18-25 KB, so
    /// the per-assessment hot path borrows them through the `Arc` instead
    /// of cloning the full source `String` (and recomputing nothing — the
    /// SHA-1 cache digest inside `redis::Script` is computed once, at
    /// construction).
    script: Arc<redis_crate::Script>,
    assess_v2_script: Arc<redis_crate::Script>,
    outcome_register_script: Arc<redis_crate::Script>,
    outcome_confirm_script: Arc<redis_crate::Script>,
    outcome_correct_script: Arc<redis_crate::Script>,
    marks_script: Arc<redis_crate::Script>,
    target_failure_script: Arc<redis_crate::Script>,
    trust_script: Arc<redis_crate::Script>,
    pool: ConnectionPool,
    connection_timeout_ms: u64,
    command_timeout_ms: u64,
    last_global_level: AtomicU8,
    last_cooldown_until_ms: AtomicU64,
}

/// Lazy round-robin pool of sync connections. Crate-internal so the
/// sharded keyspace store (Plane 7) can run one pool per slot-group
/// endpoint with the same eviction semantics.
pub(crate) struct ConnectionPool {
    slots: Vec<Mutex<Option<redis_crate::Connection>>>,
    next: AtomicUsize,
    connection_timeout_ms: u64,
    command_timeout_ms: u64,
}

impl ConnectionPool {
    pub(crate) fn new(
        pool_size: usize,
        connection_timeout_ms: u64,
        command_timeout_ms: u64,
    ) -> ConnectionPool {
        assert!(pool_size >= 1, "pool_size must be >= 1");
        ConnectionPool {
            slots: (0..pool_size).map(|_| Mutex::new(None)).collect(),
            connection_timeout_ms,
            command_timeout_ms,
            next: AtomicUsize::new(0),
        }
    }

    /// Picks the next slot round-robin and lazily opens (and timeouts-
    /// configures) its connection. A slot whose pooled connection is no
    /// longer open (a Redis restart, an idle TCP reset — the cheap
    /// `is_open` socket check, no round trip) is evicted here and replaced
    /// by a fresh connection, so a backend restart heals per slot on the
    /// next use instead of leaving the pool broken until process restart.
    pub(crate) fn acquire(
        &self,
        client: &redis_crate::Client,
    ) -> Result<MutexGuard<'_, Option<redis_crate::Connection>>, RiskStoreError> {
        // Round-robin start position, then prefer the first slot that is
        // not currently checked out: a batch holds its slot for the whole
        // pipelined exchange, so strict round-robin would serialize
        // concurrent callers behind one slot while others sit idle. When
        // every slot is checked out, block on the start slot (fair
        // queuing, identical semantics to the plain round-robin).
        let start = self.next.fetch_add(1, Ordering::Relaxed) % self.slots.len();
        let mut guard: Option<MutexGuard<'_, Option<redis_crate::Connection>>> = None;
        for offset in 0..self.slots.len() {
            let idx = (start + offset) % self.slots.len();
            if let Ok(checked_out) = self.slots[idx].try_lock() {
                guard = Some(checked_out);
                break;
            }
        }
        let mut guard = match guard {
            Some(guard) => guard,
            None => self.slots[start].lock().unwrap_or_else(|p| p.into_inner()),
        };
        if guard.as_ref().is_some_and(|conn| !conn.is_open()) {
            *guard = None;
        }
        if guard.is_none() {
            let conn = client
                .get_connection_with_timeout(Duration::from_millis(self.connection_timeout_ms))
                .map_err(map_redis_error)?;
            conn.set_read_timeout(Some(Duration::from_millis(self.command_timeout_ms)))
                .map_err(map_redis_error)?;
            conn.set_write_timeout(Some(Duration::from_millis(self.command_timeout_ms)))
                .map_err(map_redis_error)?;
            *guard = Some(conn);
        }
        Ok(guard)
    }

    /// The number of slots currently holding a live (not evicted)
    /// connection. Diagnostic observability for operations and tests; not
    /// part of the stable API surface.
    #[doc(hidden)]
    pub fn live_connections(&self) -> usize {
        self.slots
            .iter()
            .filter(|slot| slot.lock().unwrap_or_else(|p| p.into_inner()).is_some())
            .count()
    }

    /// Runs one unit of Redis work on the next slot's connection. Any
    /// command-level failure evicts the slot (the connection is dropped out
    /// of it) before the error is mapped and propagated, so the next
    /// acquire on that slot reconnects: a timed-out or failed reply may
    /// still be in flight on the socket, and reusing the connection could
    /// desync the Redis reply stream — the next assessment would silently
    /// parse shifted values into the risk signal vector (the same
    /// no-retry/poison rule the sister crate's `redis_verify` pool
    /// documents; there it is r2d2's `has_broken`, here it is eviction on
    /// error because this pool owns its slots directly).
    pub(crate) fn with_connection<T>(
        &self,
        client: &redis_crate::Client,
        f: impl FnOnce(&mut redis_crate::Connection) -> redis_crate::RedisResult<T>,
    ) -> Result<T, RiskStoreError> {
        let mut guard = self.acquire(client)?;
        let result = match guard.as_mut() {
            Some(conn) => f(conn),
            None => {
                return Err(RiskStoreError::BackendUnavailable(
                    "connection vanished".to_string(),
                ))
            }
        };
        match result {
            Ok(v) => Ok(v),
            Err(e) => {
                *guard = None;
                Err(map_redis_error(e))
            }
        }
    }
}

impl RedisRiskStateStore {
    /// Connection timeout used for establishing the TCP connection. The
    /// 75 ms default tolerates TLS, managed and cross-AZ handshakes while
    /// staying fail-fast.
    pub const CONNECTION_TIMEOUT_MS: u64 = 75;
    /// Command (read/write) timeout applied to the socket. The tight 10 ms
    /// default keeps one wedged socket from wedging the assessment path.
    pub const COMMAND_TIMEOUT_MS: u64 = 10;

    /// Builds a store with the contract defaults (namespace `d`,
    /// 1800 s state TTL, 60 s dedupe TTL, 60 s hysteresis, 1800 s session
    /// TTL, 86400 s principal TTL, 86400 s outcome-ledger TTL, default
    /// saturations, pool size 4).
    ///
    /// `namespace` is the RAW configured discriminator: the store derives
    /// the encoded `{kiwi:<ns>}` tag through the shared deployment
    /// derivation ([`crate::namespace::deployment_namespace`]) with the
    /// legacy key version, the historical key shape. A deployment that
    /// migrates to the digest version switches explicitly through
    /// [`RedisRiskStateStore::with_namespace_version`].
    ///
    /// # Panics
    ///
    /// Panics if the namespace is empty or contains `{`/`}` (the hash tag
    /// would be malformed), mirroring the PHP constructor's
    /// `InvalidArgumentException`.
    pub fn new(client: redis_crate::Client, namespace: &str) -> RedisRiskStateStore {
        RedisRiskStateStore::new_with_namespace_version(client, namespace, NamespaceVersion::Legacy)
    }

    /// Builds a store with an explicit namespace key version (the raw
    /// namespace is still the configured discriminator, never an encoded
    /// value).
    ///
    /// # Panics
    ///
    /// Panics if the namespace is empty or contains `{`/`}`.
    pub fn new_with_namespace_version(
        client: redis_crate::Client,
        namespace: &str,
        namespace_version: NamespaceVersion,
    ) -> RedisRiskStateStore {
        assert!(
            !namespace.is_empty() && !namespace.contains(['{', '}']),
            "Risk namespace must be non-empty and free of braces"
        );
        let encoded = deployment_namespace(namespace, namespace_version);
        RedisRiskStateStore {
            client,
            key_tag: format!("{{kiwi:{encoded}}}"),
            namespace: encoded,
            raw_namespace: namespace.to_string(),
            namespace_version,
            state_ttl_secs: 1800,
            dedupe_ttl_secs: 60,
            target_ttl_secs: 86_400,
            hysteresis_ms: 60_000,
            session_ttl_secs: 1800,
            principal_ttl_secs: 86_400,
            outcome_ttl_secs: DEFAULT_OUTCOME_TTL_SECS,
            mark_ttl_secs: DEFAULT_MARK_TTL_SECS,
            saturations: DEFAULT_SATURATIONS,
            script: Arc::new(redis_crate::Script::new(SCRIPT)),
            assess_v2_script: Arc::new(redis_crate::Script::new(ASSESS_V2_LUA)),
            outcome_register_script: Arc::new(redis_crate::Script::new(OUTCOME_REGISTER_LUA)),
            outcome_confirm_script: Arc::new(redis_crate::Script::new(OUTCOME_CONFIRM_LUA)),
            outcome_correct_script: Arc::new(redis_crate::Script::new(OUTCOME_CORRECT_LUA)),
            marks_script: Arc::new(redis_crate::Script::new(MARKS_LUA)),
            target_failure_script: Arc::new(redis_crate::Script::new(TARGET_FAILURE_LUA)),
            trust_script: Arc::new(redis_crate::Script::new(TRUST_LUA)),
            pool: ConnectionPool::new(
                DEFAULT_POOL_SIZE,
                Self::CONNECTION_TIMEOUT_MS,
                Self::COMMAND_TIMEOUT_MS,
            ),
            connection_timeout_ms: Self::CONNECTION_TIMEOUT_MS,
            command_timeout_ms: Self::COMMAND_TIMEOUT_MS,
            last_global_level: AtomicU8::new(0),
            last_cooldown_until_ms: AtomicU64::new(0),
        }
    }

    /// Builds a store with explicit knobs (`outcome_ttl_secs` is the
    /// always-on outcome-ledger lifetime, default 86400 s).
    ///
    /// # Panics
    ///
    /// Panics if the namespace is empty or contains `{`/`}`.
    #[allow(clippy::too_many_arguments)]
    pub fn with_options(
        client: redis_crate::Client,
        namespace: &str,
        state_ttl_secs: u64,
        dedupe_ttl_secs: u64,
        hysteresis_ms: u64,
        session_ttl_secs: u64,
        principal_ttl_secs: u64,
        outcome_ttl_secs: u64,
        saturations: [u32; 11],
    ) -> RedisRiskStateStore {
        // The configuration invariants live at the lowest public API
        // boundary, not only in the Symfony bundle: a standalone caller
        // must never be able to build a store that writes a persistent
        // risk hash (TTL 0), an invalid `SET ... EX 0`, an
        // immediately-deleted record, or nonsensical epoch/hysteresis
        // behaviour. The bundle's tree gives the friendlier first error;
        // this constructor is the security validation every caller gets,
        // with the identical bounds as the PHP store. TTLs also carry the
        // 10-year upper bound: a fatter expire value is not representable
        // on every Redis deployment and would abort the script after its
        // first write.
        for (knob, value) in [
            ("state_ttl_secs", state_ttl_secs),
            ("dedupe_ttl_secs", dedupe_ttl_secs),
            ("session_ttl_secs", session_ttl_secs),
            ("principal_ttl_secs", principal_ttl_secs),
            ("outcome_ttl_secs", outcome_ttl_secs),
        ] {
            assert!(
                (1..=MAX_TTL_SECS).contains(&value),
                "{knob} must be within 1..={MAX_TTL_SECS} (got {value}): a non-positive TTL would write persistent or immediately-expired risk state and a huge one is rejected by Redis at request time"
            );
        }
        assert!(
            hysteresis_ms >= 1,
            "hysteresis_ms must be >= 1 (got {hysteresis_ms}): a non-positive hysteresis window would write persistent or immediately-expired risk state"
        );
        assert!(
            saturations.iter().all(|saturation| *saturation >= 1),
            "saturations must all be positive integers"
        );
        let mut store = RedisRiskStateStore::new(client, namespace);
        store.state_ttl_secs = state_ttl_secs;
        store.dedupe_ttl_secs = dedupe_ttl_secs;
        store.hysteresis_ms = hysteresis_ms;
        store.session_ttl_secs = session_ttl_secs;
        store.principal_ttl_secs = principal_ttl_secs;
        store.outcome_ttl_secs = outcome_ttl_secs;
        store.saturations = saturations;
        store
    }

    /// Override the connection/command timeouts: the
    /// production defaults (75 ms connect, 10 ms command) stay in place;
    /// tests exercising long real-time sequences use
    /// generous timeouts so CI scheduling jitter can never produce a
    /// spurious `Timeout` — the tight-timeout behavior is a production
    /// tuning knob, not a test oracle.
    pub fn with_io_timeouts(mut self, connection_timeout_ms: u64, command_timeout_ms: u64) -> Self {
        self.connection_timeout_ms = connection_timeout_ms;
        self.command_timeout_ms = command_timeout_ms;
        self.pool = ConnectionPool::new(
            self.pool.slots.len(),
            connection_timeout_ms,
            command_timeout_ms,
        );
        self
    }

    /// Overrides the long-memory mark TTL (default
    /// [`DEFAULT_MARK_TTL_SECS`], 90 days): every mark write re-arms the
    /// whole-key TTL to this window.
    ///
    /// # Panics
    ///
    /// Panics when the TTL falls outside `1..=MAX_TTL_SECS` — the same
    /// bound every other store TTL carries (a persistent or
    /// immediately-expired mark is never admissible).
    pub fn with_mark_ttl_secs(mut self, mark_ttl_secs: u64) -> Self {
        assert!(
            (1..=MAX_TTL_SECS).contains(&mark_ttl_secs),
            "mark_ttl_secs must be within 1..={MAX_TTL_SECS} (got {mark_ttl_secs})"
        );
        self.mark_ttl_secs = mark_ttl_secs;
        self
    }

    /// Builds a store with an explicit connection pool size (>= 1).
    ///
    /// # Panics
    ///
    /// Panics if the namespace is empty or contains `{`/`}`, or if
    /// `pool_size` is 0.
    pub fn with_pool_size(
        client: redis_crate::Client,
        namespace: &str,
        pool_size: usize,
    ) -> RedisRiskStateStore {
        let mut store = RedisRiskStateStore::new(client, namespace);
        store.pool = ConnectionPool::new(
            pool_size,
            store.connection_timeout_ms,
            store.command_timeout_ms,
        );
        store
    }

    /// The encoded deployment namespace inside the `{kiwi:<ns>}` hash
    /// tag (the derived value, never the raw configured discriminator).
    pub fn namespace(&self) -> &str {
        &self.namespace
    }

    /// The raw configured deployment discriminator this store was built
    /// from.
    pub fn raw_namespace(&self) -> &str {
        &self.raw_namespace
    }

    /// The key-version contract the encoded namespace was derived under.
    pub fn namespace_version(&self) -> NamespaceVersion {
        self.namespace_version
    }

    /// Re-derive every key from the raw namespace under an explicit key
    /// version: switching an existing deployment to
    /// [`NamespaceVersion::Digest`] changes its key space, so the caller
    /// performs this deliberately as a migration.
    pub fn with_namespace_version(mut self, namespace_version: NamespaceVersion) -> Self {
        let encoded = deployment_namespace(&self.raw_namespace, namespace_version);
        self.key_tag = format!("{{kiwi:{encoded}}}");
        self.namespace = encoded;
        self.namespace_version = namespace_version;
        self
    }

    /// The configured connection pool size.
    pub fn pool_size(&self) -> usize {
        self.pool.slots.len()
    }

    /// The number of pool slots currently holding a live (not evicted)
    /// connection. Diagnostic observability for operations and tests (a
    /// slot evicted after a failed invocation is reconnected lazily on its
    /// next acquire); not part of the stable API surface.
    #[doc(hidden)]
    pub fn live_pool_connections(&self) -> usize {
        self.pool.live_connections()
    }

    /// The full key set for one observation, in the Lua keys order.
    ///
    /// Source keys use the observation's epoch-scoped pseudonyms:
    /// `src:<source_epoch>:<source_id>`,
    /// `src:<source_epoch-1>:<source_id_prev>`,
    /// `src:<source_epoch+1>:<source_id_next>` (same for `net`). All keys
    /// share the `{kiwi:<namespace>}` hash tag so the script is Cluster
    /// safe. `session_id`/`principal_id` are hex-encoded; `None` maps to
    /// the contract's all-zero placeholder. Public so tests (and tooling)
    /// can build and inspect the exact key layout.
    ///
    /// `namespace` is the RAW configured discriminator and
    /// `namespace_version` selects the derivation: the returned keys are
    /// exactly the keys the store built with the same pair produces.
    #[allow(clippy::too_many_arguments)]
    pub fn keys_for(
        namespace: &str,
        namespace_version: NamespaceVersion,
        source_epoch: i64,
        source_id_prev: &str,
        source_id: &str,
        source_id_next: &str,
        subnet_epoch: i64,
        subnet_id_prev: &str,
        subnet_id: &str,
        subnet_id_next: &str,
        session_id: Option<&[u8]>,
        principal_id: Option<&[u8]>,
        event_id: &str,
    ) -> Vec<String> {
        let tag = format!(
            "{{kiwi:{}}}",
            deployment_namespace(namespace, namespace_version)
        );
        let session_id = session_id
            .map(hex::encode)
            .unwrap_or_else(|| "0".repeat(32));
        let principal_id = principal_id
            .map(hex::encode)
            .unwrap_or_else(|| "0".repeat(32));

        // The ±1 epoch neighbours fold onto the boundary instead of
        // overflowing: an epoch at the i64 edge is astronomically outside
        // any real clock window, and the PHP mirror's offsetEpoch applies
        // the identical clamp, so the key grammar never carries a wrapped
        // value (debug overflow panics, release silently names another
        // epoch).
        vec![
            format!("{tag}:risk:src:{source_epoch}:{source_id}"),
            format!(
                "{tag}:risk:src:{}:{source_id_prev}",
                source_epoch.saturating_sub(1)
            ),
            format!(
                "{tag}:risk:src:{}:{source_id_next}",
                source_epoch.saturating_add(1)
            ),
            format!("{tag}:risk:net:{subnet_epoch}:{subnet_id}"),
            format!(
                "{tag}:risk:net:{}:{subnet_id_prev}",
                subnet_epoch.saturating_sub(1)
            ),
            format!(
                "{tag}:risk:net:{}:{subnet_id_next}",
                subnet_epoch.saturating_add(1)
            ),
            format!("{tag}:risk:session:{session_id}"),
            format!("{tag}:risk:principal:{principal_id}"),
            format!("{tag}:risk:global"),
            format!("{tag}:risk:dedupe:{event_id}"),
        ]
    }

    /// Validates the observation's key material at the store boundary —
    /// the mirror of the PHP `RiskObservation` constructor's rejection
    /// conditions: the six epoch-scoped source/subnet pseudonyms are
    /// 32-char lowercase hex, the event_id is 32- or 64-char lowercase
    /// hex (the canonical fresh/HMAC ids the engines produce), and the
    /// network risk stays within the 0..1000 contract band. Malformed
    /// input fails closed before any Redis call.
    pub(crate) fn validate_observation(o: &RiskObservation) -> Result<(), RiskStoreError> {
        for id in [
            &o.source_id_prev,
            &o.source_id,
            &o.source_id_next,
            &o.subnet_id_prev,
            &o.subnet_id,
            &o.subnet_id_next,
        ] {
            if !is_lower_hex(id, 32) {
                return Err(RiskStoreError::ScriptError(
                    "source/subnet pseudonyms must be 16-byte hex".to_string(),
                ));
            }
        }
        if !(is_lower_hex(&o.event_id, 32) || is_lower_hex(&o.event_id, 64)) {
            return Err(RiskStoreError::ScriptError(
                "event_id must be 16 random bytes in hex or a normalized 32-byte sha256 in hex"
                    .to_string(),
            ));
        }
        if o.network_risk > 1000 {
            return Err(RiskStoreError::ScriptError(
                "network_risk must be within 0..1000".to_string(),
            ));
        }
        Ok(())
    }

    /// Whether a caller-supplied identifier is safe as a Redis key
    /// component: non-empty, free of control characters (including the C1
    /// and U+2028/U+2029 separators the PHP regex names) and of the `:`/`}`
    /// structure bytes. Mirrors PHP
    /// `RedisRiskStateStore::assertKeySafeIdentifier`, which guards the
    /// store's decision ids; the calibration store's receipt/ledger keys
    /// enforce the same rule so every decision-id key path agrees.
    pub(crate) fn valid_key_component(value: &str) -> bool {
        !value.is_empty()
            && !value
                .chars()
                .any(|c| c.is_control() || matches!(c, ':' | '}' | '\u{2028}' | '\u{2029}'))
    }

    /// Cheap per-assessment key-family check: every key must carry either
    /// the store's shared hash-tag prefix (a shared prefix implies a
    /// shared cluster slot — the tag's slot is fixed at construction, so
    /// the per-key CRC-16 recomputation is unnecessary) or the target
    /// family tag `{kiwi:<ns>:target:<hex2>}` (the target failure hash
    /// and its spread HLLs ride their own slot so a stuffing storm never
    /// hammers the shared primary).
    fn check_key_tag(&self, keys: &[String]) -> Result<(), RiskStoreError> {
        let target_family = format!("{{kiwi:{}:target:", self.namespace);
        for key in keys {
            if !key.starts_with(&self.key_tag) && !key.starts_with(&target_family) {
                return Err(RiskStoreError::ScriptError(format!(
                    "key {key} does not carry the {{kiwi:{}}} hash tag or the target family",
                    self.namespace
                )));
            }
        }
        Ok(())
    }

    /// The ten risk-v1 observation keys for `o`, in the Lua keys order,
    /// built on the cached hash-tag prefix.
    fn observation_keys(&self, o: &RiskObservation) -> Vec<String> {
        let tag = &self.key_tag;
        let session_id = o
            .session_id
            .map(hex::encode)
            .unwrap_or_else(|| "0".repeat(32));
        let principal_id = o
            .principal_id
            .map(hex::encode)
            .unwrap_or_else(|| "0".repeat(32));
        // The same boundary fold as keys_for(): a deserialized
        // observation can carry any i64, and the ±1 neighbours must never
        // overflow (the PHP mirror clamps via offsetEpoch).
        vec![
            format!("{}:risk:src:{}:{}", tag, o.source_epoch, o.source_id),
            format!(
                "{}:risk:src:{}:{}",
                tag,
                o.source_epoch.saturating_sub(1),
                o.source_id_prev
            ),
            format!(
                "{}:risk:src:{}:{}",
                tag,
                o.source_epoch.saturating_add(1),
                o.source_id_next
            ),
            format!("{}:risk:net:{}:{}", tag, o.subnet_epoch, o.subnet_id),
            format!(
                "{}:risk:net:{}:{}",
                tag,
                o.subnet_epoch.saturating_sub(1),
                o.subnet_id_prev
            ),
            format!(
                "{}:risk:net:{}:{}",
                tag,
                o.subnet_epoch.saturating_add(1),
                o.subnet_id_next
            ),
            format!("{tag}:risk:session:{session_id}"),
            format!("{tag}:risk:principal:{principal_id}"),
            format!("{tag}:risk:global"),
            format!("{tag}:risk:dedupe:{}", o.event_id),
        ]
    }

    /// Applies the observation and returns the full script reply
    /// (vector + global level + cooldown deadline + dedupe verdict).
    pub fn observe_full(&self, o: &RiskObservation) -> Result<Observed, RiskStoreError> {
        Self::validate_observation(o)?;
        let keys = self.observation_keys(o);
        self.check_key_tag(&keys)?;

        // The full 22-value argv contract, in order. Integers are pushed
        // typed (the redis crate serializes them as their decimal strings,
        // byte-identical to the previous per-arg `to_string()` while
        // avoiding the per-assessment argv `String` churn).
        let mut invocation = self.script.prepare_invoke();
        for key in &keys {
            invocation.key(key.as_str());
        }
        invocation.arg(o.event.as_u8());
        invocation.arg(o.scope);
        invocation.arg(o.now_ms);
        invocation.arg(o.event_id.as_str());
        invocation.arg(self.dedupe_ttl_secs);
        invocation.arg(self.state_ttl_secs);
        invocation.arg(self.hysteresis_ms);
        for s in self.saturations {
            invocation.arg(s);
        }
        invocation.arg(if o.session_id.is_some() { 1u8 } else { 0u8 });
        invocation.arg(if o.principal_id.is_some() { 1u8 } else { 0u8 });
        invocation.arg(self.session_ttl_secs);
        invocation.arg(self.principal_ttl_secs);

        // A failed invocation evicts the pool slot (see
        // ConnectionPool::with_connection).
        let reply: Vec<i64> = self
            .pool
            .with_connection(&self.client, |conn| invocation.invoke(conn))?;

        if reply.len() < 16 {
            return Err(RiskStoreError::ScriptError(format!(
                "risk script returned an unexpected payload ({} values)",
                reply.len()
            )));
        }

        // Clamped slot decode: the typed `Vec<i64>` above already rejected
        // malformed slot types, so only integers reach these clamps. The
        // script guarantees the bands, and a shifted integer reply must
        // never widen them — a raw i64 -> u16 cast would wrap.
        let global_level = clamp_level(reply[13]);
        let cooldown_until_ms = clamp_cooldown(reply[14]);
        let is_duplicate = reply[15] != 0;
        self.last_global_level
            .store(global_level, Ordering::Relaxed);
        self.last_cooldown_until_ms
            .store(cooldown_until_ms, Ordering::Relaxed);

        Ok(Observed {
            vector: SignalVector {
                source_fast: clamp_signal(reply[0]),
                source_slow: clamp_signal(reply[1]),
                subnet_fast: clamp_signal(reply[2]),
                issue_debt: clamp_signal(reply[3]),
                bad_proof: clamp_signal(reply[4]),
                malformed: clamp_signal(reply[5]),
                replay: clamp_signal(reply[6]),
                action_failure: clamp_signal(reply[7]),
                scope_switch: clamp_signal(reply[8]),
                global_pressure: clamp_signal(reply[9]),
                network_risk: o.network_risk,
                trust_credit: clamp_signal(reply[11]),
                principal_credit: clamp_signal(reply[12]),
            },
            global_level,
            cooldown_until_ms,
            is_duplicate,
        })
    }

    /// The consolidated risk-v2 assessment: one atomic script call that
    /// runs the full v1 observation with the exact risk-v1 semantics,
    /// records the session's first-seen client-context + trusted-edge TLS
    /// tags (SET NX, first write wins, session TTL) and, when
    /// `registration` is given, registers the decision's pending
    /// outcome-ledger entry (SET NX EX under the store's outcome TTL) —
    /// returning the signal vector, the recorded tag values and the
    /// registration status. An established risk-v2 session therefore
    /// costs ONE script call instead of the separate SET NX / GET tag
    /// round trips and the separate outcome registration.
    ///
    /// `context_tag` / `tls_tag` are the presented tags of the current
    /// request (`None` = none presented; the corresponding record is
    /// untouched and its existing value is reported as `None`). The
    /// records use the exact keys and TTL of
    /// [`SessionContextTagStore::session_first_context_tag`] /
    /// [`SessionTlsTagStore::session_first_tls_tag`], so the two surfaces
    /// are interchangeable. The ledger registration mirrors
    /// [`RiskStateStore::register_outcome`] byte-for-byte (the score is
    /// computed inside the script from the exact base risk and weights
    /// the engine scores with). All keys share the hash tag — Cluster
    /// safe.
    pub fn assess_v2_full(
        &self,
        o: &RiskObservation,
        context_tag: Option<&str>,
        tls_tag: Option<&str>,
        registration: Option<&OutcomeRegistration>,
    ) -> Result<AssessV2Reply, RiskStoreError> {
        Self::validate_observation(o)?;

        let mut keys = self.observation_keys(o);
        let session_hex = o
            .session_id
            .map(hex::encode)
            .unwrap_or_else(|| "0".repeat(32));
        keys.push(format!("{}:risk:ctx:{session_hex}", self.key_tag));
        keys.push(format!("{}:risk:tls:{session_hex}", self.key_tag));
        // Stable KEYS positions 13..16: the ledger slot always exists
        // (the Lua indexes it unconditionally when ARGV[25] is set) and
        // the three target slots always exist (touched only when
        // has_target = 1). A missing registration uses a dummy ledger
        // key in the same hash tag; a missing target uses dummy target
        // keys so the slot map never shifts.
        match registration {
            Some(reg) => keys.push(self.outcome_ledger_key(&reg.decision_id)),
            None => keys.push(format!("{}:risk:ledger:unused", self.key_tag)),
        }
        match registration.and_then(|reg| reg.target_id.as_deref()) {
            Some(target_id) => keys.extend(self.target_state_keys(target_id)),
            None => {
                keys.push(format!("{}:risk:tgt:unused", self.key_tag));
                keys.push(format!("{}:risk:tgt:src:unused", self.key_tag));
                keys.push(format!("{}:risk:tgt:asn:unused", self.key_tag));
            }
        }
        self.check_key_tag(&keys)?;

        // The full argv contract: the 22 v1 values + the two presented
        // tags + the 23 registration values (ARGV[25..47]). Integers are
        // pushed typed (decimal serialization byte-identical to the
        // previous per-arg `to_string()`, without the argv `String` churn).
        let mut invocation = self.assess_v2_script.prepare_invoke();
        for key in &keys {
            invocation.key(key.as_str());
        }
        invocation.arg(o.event.as_u8());
        invocation.arg(o.scope);
        invocation.arg(o.now_ms);
        invocation.arg(o.event_id.as_str());
        invocation.arg(self.dedupe_ttl_secs);
        invocation.arg(self.state_ttl_secs);
        invocation.arg(self.hysteresis_ms);
        for s in self.saturations {
            invocation.arg(s);
        }
        invocation.arg(if o.session_id.is_some() { 1u8 } else { 0u8 });
        invocation.arg(if o.principal_id.is_some() { 1u8 } else { 0u8 });
        invocation.arg(self.session_ttl_secs);
        invocation.arg(self.principal_ttl_secs);
        invocation.arg(context_tag.unwrap_or(""));
        invocation.arg(tls_tag.unwrap_or(""));
        match registration {
            Some(reg) => {
                invocation.arg(reg.decision_id.as_str());
                invocation.arg(reg.decision_hour);
                invocation.arg(self.outcome_ttl_secs);
                invocation.arg(o.network_risk);
                invocation.arg(if reg.global_pressure_enabled {
                    1u8
                } else {
                    0u8
                });
                invocation.arg(reg.base_risk);
                invocation.arg(if reg.honeypot_hit { 1u8 } else { 0u8 });
                let w = &reg.v1_weights;
                for weight in [
                    w.source_fast,
                    w.source_slow,
                    w.subnet_fast,
                    w.issue_debt,
                    w.bad_proof,
                    w.malformed,
                    w.replay,
                    w.action_failure,
                    w.scope_switch,
                    w.global_pressure,
                    w.network_risk,
                    w.trust_credit,
                    w.principal_credit,
                ] {
                    invocation.arg(weight);
                }
                let w2 = &reg.v2_weights;
                for weight in [w2.honeypot, w2.session_inconsistency, w2.tls] {
                    invocation.arg(weight);
                }
                // Target dimension (KEYS[14..16]) and the two additive
                // target score weights (ARGV[52..53]).
                if reg.target_id.is_some() {
                    invocation.arg(1u8);
                } else {
                    invocation.arg(0u8);
                }
                invocation.arg("");
                invocation.arg("");
                invocation.arg(self.target_ttl_secs);
                invocation.arg(w2.target_failure_pressure);
                invocation.arg(w2.target_spread);
            }
            None => {
                invocation.arg("");
                for _ in 0..22 {
                    invocation.arg(0u16);
                }
                invocation.arg(0u8);
                invocation.arg("");
                invocation.arg("");
                invocation.arg(self.target_ttl_secs);
                invocation.arg(0u16);
                invocation.arg(0u16);
            }
        }

        let reply: Vec<redis_crate::Value> = self
            .pool
            .with_connection(&self.client, |conn| invocation.invoke(conn))?;

        if reply.len() < 22 {
            return Err(RiskStoreError::ScriptError(format!(
                "risk script returned an unexpected payload ({} values)",
                reply.len()
            )));
        }

        // The tag slots are strings or absent by contract. Any other reply
        // type is a malformed/shifted reply: fail closed instead of
        // silently decoding it as "no recorded tag" (the same fail-closed
        // rule every other slot follows).
        let value_string = |v: &redis_crate::Value| -> Result<String, RiskStoreError> {
            match v {
                redis_crate::Value::BulkString(b) => Ok(String::from_utf8_lossy(b).into_owned()),
                redis_crate::Value::Nil => Ok(String::new()),
                _ => Err(RiskStoreError::ScriptError(
                    "risk script returned a non-string tag slot".to_string(),
                )),
            }
        };

        // Clamped slot decode: only decoded integer slots reach these
        // clamps, because a malformed slot type already failed closed
        // above. The script guarantees the bands, and a shifted integer
        // reply must never widen them — a raw i64 -> u16 cast would wrap.
        let global_level = clamp_level(value_i64(&reply[13])?);
        let cooldown_until_ms = clamp_cooldown(value_i64(&reply[14])?);
        let is_duplicate = value_i64(&reply[15])? != 0;
        self.last_global_level
            .store(global_level, Ordering::Relaxed);
        self.last_cooldown_until_ms
            .store(cooldown_until_ms, Ordering::Relaxed);

        let existing_context_tag = value_string(&reply[16])?;
        let existing_tls_tag = value_string(&reply[17])?;
        let registration_status = value_i64(&reply[18])? != 0;

        Ok(AssessV2Reply {
            observed: Observed {
                vector: SignalVector {
                    source_fast: clamp_signal(value_i64(&reply[0])?),
                    source_slow: clamp_signal(value_i64(&reply[1])?),
                    subnet_fast: clamp_signal(value_i64(&reply[2])?),
                    issue_debt: clamp_signal(value_i64(&reply[3])?),
                    bad_proof: clamp_signal(value_i64(&reply[4])?),
                    malformed: clamp_signal(value_i64(&reply[5])?),
                    replay: clamp_signal(value_i64(&reply[6])?),
                    action_failure: clamp_signal(value_i64(&reply[7])?),
                    scope_switch: clamp_signal(value_i64(&reply[8])?),
                    global_pressure: clamp_signal(value_i64(&reply[9])?),
                    network_risk: o.network_risk,
                    trust_credit: clamp_signal(value_i64(&reply[11])?),
                    principal_credit: clamp_signal(value_i64(&reply[12])?),
                },
                global_level,
                cooldown_until_ms,
                is_duplicate,
            },
            existing_context_tag: (!existing_context_tag.is_empty())
                .then_some(existing_context_tag),
            existing_tls_tag: (!existing_tls_tag.is_empty()).then_some(existing_tls_tag),
            registration_status,
            target_failures: value_i64(&reply[19])?.max(0) as u32,
            target_spread_sources: value_i64(&reply[20])?.max(0) as u32,
            target_spread_asns: value_i64(&reply[21])?.max(0) as u32,
        })
    }

    /// The outcome-ledger key for one decision — the same canonical key
    /// the calibration scripts use (`{kiwi:<ns>}:outcome:<decision_id>`),
    /// so the always-on ledger is one key layout whether calibration is
    /// enabled or disabled. Public so tests (and tooling) can inspect the
    /// ledger entries.
    pub fn outcome_ledger_key(&self, decision_id: &str) -> String {
        format!("{{kiwi:{}}}:outcome:{decision_id}", self.namespace)
    }

    /// The target-dimension state keys of one target pseudonym: the
    /// failure hash plus the source/asn spread HLLs, on the target id's
    /// own family slot (`{kiwi:<ns>:target:<hex2>}`) — byte-identical
    /// with the keys assess_v2.lua maintains (KEYS[14..16]) and the
    /// PHP `RedisRiskStateStore::targetStateKeys`. A stuffing storm
    /// against one target then hits that target's slot, never the
    /// shared `{kiwi:<ns>}` primary.
    fn target_state_keys(&self, target_id: &str) -> [String; 3] {
        crate::keyspace::target_state_keys(&self.namespace, target_id)
    }

    /// One target_failure.lua op, returning {fails, spread}.
    fn run_target_op(
        &self,
        op: &str,
        target_id: &str,
        source: &str,
        asn: &str,
    ) -> Result<crate::store::TargetState, RiskStoreError> {
        if !Self::valid_key_component(target_id) {
            return Err(RiskStoreError::InvalidIdentifier(format!(
                "target_id is not a safe Redis key component (got 0x{})",
                hex::encode(target_id)
            )));
        }
        let keys = self.target_state_keys(target_id);
        // The target dimension's window is the principal retention (the
        // 24h default change.md assigns it); a dedicated knob would
        // only duplicate that contract.
        let ttl: i64 = self.principal_ttl_secs.try_into().unwrap_or(i64::MAX);
        let mut invocation = self.target_failure_script.prepare_invoke();
        for key in &keys {
            invocation.key(key.as_str());
        }
        invocation.arg(op);
        invocation.arg(source);
        invocation.arg(asn);
        invocation.arg(ttl);
        let reply: Vec<i64> = self
            .pool
            .with_connection(&self.client, |conn| invocation.invoke(conn))?;
        if reply.len() < 5 {
            return Err(RiskStoreError::ScriptError(format!(
                "target_failure script returned {} values",
                reply.len()
            )));
        }
        Ok(crate::store::TargetState {
            fails: reply[0].clamp(0, i64::from(u32::MAX)) as u32,
            spread_sources: reply[1].clamp(0, i64::from(u32::MAX)) as u32,
            spread_asns: reply[2].clamp(0, i64::from(u32::MAX)) as u32,
            first_ms: reply[3],
            last_ms: reply[4],
        })
    }

    /// The long-memory mark key of one dimension and identifier:
    /// `mark:{kiwi:<ns>}:<dim>:<id>`. The hash tag keeps every mark in
    /// the risk keyspace's cluster slot; the dimension is one of the
    /// five contract dimensions and the identifier follows the shared
    /// key-safety rule.
    ///
    /// # Errors
    ///
    /// [`RiskStoreError::InvalidIdentifier`] when the dimension is
    /// unknown or the identifier is not a safe key component.
    pub fn mark_key(&self, dimension: &str, id: &str) -> Result<String, RiskStoreError> {
        if !MARK_DIMENSIONS.contains(&dimension) {
            return Err(RiskStoreError::InvalidIdentifier(format!(
                "mark dimension must be one of {} (got {dimension})",
                MARK_DIMENSIONS.join("|")
            )));
        }
        if !Self::valid_key_component(id) {
            return Err(RiskStoreError::InvalidIdentifier(format!(
                "id is not a safe Redis key component (got 0x{})",
                hex::encode(id)
            )));
        }
        Ok(format!("mark:{{kiwi:{}}}:{dimension}:{id}", self.namespace))
    }

    /// Writes one long-memory mark atomically through the canonical
    /// marks.lua: the max-severity kind, the latest kind, the count
    /// increment, the first/last timestamps and the refreshed whole-key
    /// TTL land in one script call. The clock is the server's TIME; the
    /// `now_ms` argument is kept for wire compatibility and ignored.
    /// `event_id` dedupes the write (`''` disables dedupe): a retried
    /// report returns the count unchanged. The dedupe marker carries
    /// the script's retry-horizon TTL (24 h), not the mark's long TTL —
    /// one marker key per event id must not pin the keyspace for the
    /// whole mark life.
    ///
    /// # Errors
    ///
    /// [`RiskStoreError::InvalidIdentifier`] on an invalid dimension,
    /// identifier or kind; backend errors on Redis failures.
    pub fn write_mark(
        &self,
        dimension: &str,
        id: &str,
        kind: &str,
        now_ms: u64,
        event_id: &str,
    ) -> Result<i64, RiskStoreError> {
        let key = self.mark_key(dimension, id)?;
        if kind.is_empty() || kind.len() > MAX_MARK_KIND_BYTES {
            return Err(RiskStoreError::InvalidIdentifier(format!(
                "kind must be a non-empty value of at most {MAX_MARK_KIND_BYTES} bytes"
            )));
        }
        let ttl_ms: i64 = (self.mark_ttl_secs * 1000).try_into().unwrap_or(i64::MAX);
        let mut invocation = self.marks_script.prepare_invoke();
        invocation.key(key.as_str());
        if event_id.is_empty() {
            // The script's KEYS[2] is the dedupe marker: with dedupe
            // disabled the marker is the mark key itself (never read on
            // this path, never written beyond the marker slot).
            invocation.key(key.as_str());
        } else {
            // The marker is scoped to this mark (dimension + id), so a
            // reused event id on another dimension can never suppress a
            // different mark (cross-dimension transplant / suppression).
            // The event id itself must be a safe key component: it is
            // interpolated into a Redis key.
            if !Self::valid_key_component(event_id) {
                return Err(RiskStoreError::InvalidIdentifier(format!(
                    "event_id is not a safe Redis key component (got 0x{})",
                    hex::encode(event_id)
                )));
            }
            invocation.key(format!("{key}:dd:{event_id}"));
        }
        invocation.arg(kind);
        invocation.arg(now_ms);
        invocation.arg(ttl_ms);
        invocation.arg(event_id);
        let count: i64 = self
            .pool
            .with_connection(&self.client, |conn| invocation.invoke(conn))?;
        Ok(count)
    }

    /// The current mark of one dimension and identifier: the hash fields
    /// kind (max severity), last_kind, count, first_ms and last_ms, or
    /// `None` when no mark exists. A corrupt or truncated hash fails
    /// closed instead of decoding as a zeroed mark. A hash written by a
    /// pre-severity writer has no `last_kind`; its `kind` was the latest
    /// write, so it doubles as the latest.
    ///
    /// # Errors
    ///
    /// [`RiskStoreError::InvalidIdentifier`] on an invalid dimension or
    /// identifier; backend errors on Redis failures.
    pub fn read_mark(
        &self,
        dimension: &str,
        id: &str,
    ) -> Result<Option<crate::outcomes::MarkRecord>, RiskStoreError> {
        let key = self.mark_key(dimension, id)?;
        let fields: Vec<(String, String)> = self.pool.with_connection(&self.client, |conn| {
            use ::redis::Commands;
            conn.hgetall(&key)
        })?;
        if fields.is_empty() {
            return Ok(None);
        }
        let mut kind: Option<String> = None;
        let mut last_kind: Option<String> = None;
        let mut count: Option<i64> = None;
        let mut first_ms: Option<i64> = None;
        let mut last_ms: Option<i64> = None;
        for (field, value) in fields {
            match field.as_str() {
                "kind" => kind = Some(value),
                "last_kind" => last_kind = Some(value),
                "count" => count = value.parse().ok(),
                "first_ms" => first_ms = value.parse().ok(),
                "last_ms" => last_ms = value.parse().ok(),
                _ => {}
            }
        }
        let kind = kind.ok_or_else(|| {
            RiskStoreError::ScriptError("risk mark hash is missing its kind field".to_string())
        })?;
        let mark = crate::outcomes::MarkRecord {
            last_kind: last_kind.unwrap_or_else(|| kind.clone()),
            kind,
            count: count.ok_or_else(|| {
                RiskStoreError::ScriptError("risk mark hash is missing its count field".to_string())
            })?,
            first_ms: first_ms.ok_or_else(|| {
                RiskStoreError::ScriptError(
                    "risk mark hash is missing its first_ms field".to_string(),
                )
            })?,
            last_ms: last_ms.ok_or_else(|| {
                RiskStoreError::ScriptError(
                    "risk mark hash is missing its last_ms field".to_string(),
                )
            })?,
        };
        Ok(Some(mark))
    }

    /// Removes the mark of one dimension and identifier and returns the
    /// number of keys removed (0 or 1): the erasure path of the outcomes
    /// plane, built from the exact key with no scan.
    ///
    /// # Errors
    ///
    /// [`RiskStoreError::InvalidIdentifier`] on an invalid dimension or
    /// identifier; backend errors on Redis failures.
    pub fn forget_marks(&self, dimension: &str, id: &str) -> Result<u32, RiskStoreError> {
        let key = self.mark_key(dimension, id)?;
        let removed: i64 = self.pool.with_connection(&self.client, |conn| {
            use ::redis::Commands;
            conn.del(&key)
        })?;
        Ok(removed.max(0) as u32)
    }

    /// The context-bound trust record key of one session and ASN bucket:
    /// `trust:{kiwi:<ns>}:<session>:<bucket>`. The hash tag keeps every
    /// bucket record in the risk keyspace's cluster slot; the session is
    /// the 32-char lowercase hex pseudonym and the bucket follows the
    /// shared bucket-id grammar (`crate::asn::is_valid_bucket_id`).
    ///
    /// # Errors
    ///
    /// [`RiskStoreError::InvalidIdentifier`] when the session id is not
    /// 32-char lowercase hex or the bucket id is not canonical.
    pub fn bucket_trust_key(
        &self,
        session_id: &str,
        bucket: &str,
    ) -> Result<String, RiskStoreError> {
        if !is_lower_hex(session_id, 32) {
            return Err(RiskStoreError::InvalidIdentifier(
                "session_id must be a 16-byte hex pseudonym".to_string(),
            ));
        }
        if !crate::asn::is_valid_bucket_id(bucket) {
            return Err(RiskStoreError::InvalidIdentifier(format!(
                "bucket must be a canonical bucket id (a<asn>, u4/<prefix> or u6/<8hex>; got {bucket})"
            )));
        }
        Ok(format!(
            "trust:{{kiwi:{}}}:{session_id}:{bucket}",
            self.namespace
        ))
    }

    /// Runs one trust.lua op (`read`, `credit` or `decay`) on the
    /// session's bucket record and returns the record's post-op raw
    /// trust. The record TTL is the store's session TTL (the trust
    /// dimension stays aligned with the session dimension).
    ///
    /// # Errors
    ///
    /// [`RiskStoreError::InvalidIdentifier`] on an invalid session id,
    /// bucket id or delta; backend errors on Redis failures.
    fn apply_bucket_trust(
        &self,
        session_id: &str,
        bucket: &str,
        op: &str,
        delta: u32,
    ) -> Result<u32, RiskStoreError> {
        let key = self.bucket_trust_key(session_id, bucket)?;
        if delta > 100_000 {
            return Err(RiskStoreError::InvalidIdentifier(format!(
                "delta must be within 0..=100000 (got {delta})"
            )));
        }
        let ttl_ms: i64 = (self.session_ttl_secs * 1000)
            .try_into()
            .unwrap_or(i64::MAX);
        let mut invocation = self.trust_script.prepare_invoke();
        invocation.key(key.as_str());
        invocation.arg(op);
        invocation.arg(delta);
        invocation.arg(ttl_ms);
        let raw: i64 = self
            .pool
            .with_connection(&self.client, |conn| invocation.invoke(conn))?;
        Ok(raw.max(0) as u32)
    }

    /// The decayed bucket-local trust of one session and bucket (0 when
    /// no record): a pure read through the canonical `trust.lua`, never
    /// mutating the record, so a foreign presentation cannot reduce home
    /// credit.
    ///
    /// # Errors
    ///
    /// [`RiskStoreError::InvalidIdentifier`] on an invalid session or
    /// bucket id; backend errors on Redis failures.
    pub fn read_bucket_trust(&self, session_id: &str, bucket: &str) -> Result<u32, RiskStoreError> {
        self.apply_bucket_trust(session_id, bucket, "read", 0)
    }

    /// Credits the session's bucket record atomically (clamped at the
    /// fixed-point ceiling, whole-key TTL refreshed) and returns the
    /// record's new raw trust.
    ///
    /// # Errors
    ///
    /// [`RiskStoreError::InvalidIdentifier`] on an invalid session id,
    /// bucket id or delta; backend errors on Redis failures.
    pub fn credit_bucket_trust(
        &self,
        session_id: &str,
        bucket: &str,
        delta: u32,
    ) -> Result<u32, RiskStoreError> {
        self.apply_bucket_trust(session_id, bucket, "credit", delta)
    }

    /// Decays the session's bucket record atomically and returns the
    /// record's new raw trust.
    ///
    /// # Errors
    ///
    /// [`RiskStoreError::InvalidIdentifier`] on an invalid session id,
    /// bucket id or delta; backend errors on Redis failures.
    pub fn decay_bucket_trust(
        &self,
        session_id: &str,
        bucket: &str,
        delta: u32,
    ) -> Result<u32, RiskStoreError> {
        self.apply_bucket_trust(session_id, bucket, "decay", delta)
    }

    /// CRC-16/xmodem (poly 0x1021, init 0): `"123456789"` -> `0x31C3`,
    /// and `slot("foo") = crc16("foo") & 0x3FFF = 12182` per the Redis
    /// Cluster docs.
    pub fn crc16(data: &[u8]) -> u16 {
        let mut crc: u16 = 0;
        for byte in data {
            crc ^= (*byte as u16) << 8;
            for _ in 0..8 {
                if crc & 0x8000 != 0 {
                    crc = (crc << 1) ^ 0x1021;
                } else {
                    crc <<= 1;
                }
            }
        }
        crc
    }

    /// Asserts every key hashes to the same Redis Cluster slot (all must
    /// share the `{kiwi:<ns>}` hash tag).
    pub fn assert_same_slot(keys: &[String]) -> Result<(), RiskStoreError> {
        let mut slot: Option<u16> = None;
        for key in keys {
            let open = key
                .find('{')
                .ok_or_else(|| RiskStoreError::ScriptError(format!("key {key} has no hash tag")))?;
            let relative_close = key[open + 1..].find('}').ok_or_else(|| {
                RiskStoreError::ScriptError(format!("key {key} has no closing hash tag"))
            })?;
            let close = open + 1 + relative_close;
            let tag = &key[open + 1..close];
            let s = Self::crc16(tag.as_bytes()) & 0x3FFF;
            match slot {
                None => slot = Some(s),
                Some(prev) if prev != s => {
                    return Err(RiskStoreError::ScriptError(format!(
                        "key {key} slots to {s}, expected {prev}"
                    )));
                }
                _ => {}
            }
        }
        Ok(())
    }
}

/// True when `s` is exactly `len` lowercase hex characters (`[0-9a-f]`,
/// the PHP `^[0-9a-f]{len}$` pseudonym/id contract).
fn is_lower_hex(s: &str, len: usize) -> bool {
    s.len() == len
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Decodes one integer slot of the consolidated script reply. The contract
/// types slots 0..15 and 18 as integers; only the tag slots 16 and 17 are
/// strings, and they never pass through this decoder. A malformed or
/// shifted reply fails closed with the script error instead of decoding
/// as 0. Int, a parseable bulk string and a parseable simple string stay
/// accepted, matching the typed `Vec<i64>` reply decoder
/// [`RedisRiskStateStore::observe_full`] uses; every other reply type
/// (Nil, an array, a map, a boolean, a non-numeric string) is refused.
pub(crate) fn value_i64(v: &redis_crate::Value) -> Result<i64, RiskStoreError> {
    match v {
        redis_crate::Value::Int(i) => Ok(*i),
        redis_crate::Value::BulkString(b) => std::str::from_utf8(b)
            .ok()
            .and_then(|s| s.parse().ok())
            .ok_or_else(|| {
                RiskStoreError::ScriptError(
                    "risk script returned a non-integer signal slot".to_string(),
                )
            }),
        redis_crate::Value::SimpleString(s) => s.parse().map_err(|_| {
            RiskStoreError::ScriptError(
                "risk script returned a non-integer signal slot".to_string(),
            )
        }),
        _ => Err(RiskStoreError::ScriptError(
            "risk script returned a non-integer signal slot".to_string(),
        )),
    }
}

/// Clamps a raw i64 signal slot to the 0..1000 band (the script guarantees
/// the band; a tampered or shifted reply must never widen it — the raw
/// `as u16` cast would wrap).
fn clamp_signal(v: i64) -> u16 {
    v.clamp(0, 1000) as u16
}

/// Clamps the raw global-level slot to 0..4.
fn clamp_level(v: i64) -> u8 {
    v.clamp(0, 4) as u8
}

/// Clamps the raw cooldown slot to a non-negative epoch-ms value.
fn clamp_cooldown(v: i64) -> u64 {
    v.max(0) as u64
}

pub(crate) fn map_redis_error(e: redis_crate::RedisError) -> RiskStoreError {
    match e.kind() {
        redis_crate::ErrorKind::IoError => {
            let message = e.to_string();
            // redis 0.27 has no distinct Timeout kind for sync connections;
            // socket timeouts surface as IoError with a platform message.
            if message.contains("timed out")
                || message.contains("Resource temporarily unavailable")
                || message.contains("Operation now in progress")
            {
                RiskStoreError::Timeout(message)
            } else {
                RiskStoreError::BackendUnavailable(message)
            }
        }
        redis_crate::ErrorKind::ResponseError | redis_crate::ErrorKind::ExecAbortError => {
            RiskStoreError::ScriptError(e.to_string())
        }
        _ => RiskStoreError::BackendUnavailable(e.to_string()),
    }
}

impl RiskStateStore for RedisRiskStateStore {
    fn observe(&self, o: &RiskObservation) -> Result<Observed, RiskStoreError> {
        self.observe_full(o)
    }

    fn assess_v2(
        &self,
        o: &RiskObservation,
        context_tag: Option<&str>,
        tls_tag: Option<&str>,
        registration: Option<&OutcomeRegistration>,
    ) -> Result<Option<AssessV2Reply>, RiskStoreError> {
        self.assess_v2_full(o, context_tag, tls_tag, registration)
            .map(Some)
    }

    fn register_outcome(
        &self,
        decision_id: &str,
        scope: u32,
        decision_hour: i64,
        score: u32,
    ) -> Result<bool, RiskStoreError> {
        // outcome_register.lua: SET NX EX a pending ledger entry
        // {"o":"P","scope","hour","score","w":1}. Returns 1 when created,
        // 0 when the decision_id is already registered.
        if !Self::valid_key_component(decision_id) {
            return Err(RiskStoreError::InvalidIdentifier(format!(
                "decision_id is not a safe Redis key component (got 0x{})",
                hex::encode(decision_id)
            )));
        }
        let key = self.outcome_ledger_key(decision_id);
        let mut invocation = self.outcome_register_script.prepare_invoke();
        invocation.key(key.as_str());
        invocation.arg(scope.to_string());
        invocation.arg(decision_hour.to_string());
        invocation.arg(score.to_string());
        invocation.arg(self.outcome_ttl_secs.to_string());
        let created: i64 = self
            .pool
            .with_connection(&self.client, |conn| invocation.invoke(conn))?;
        Ok(created != 0)
    }

    fn confirm_outcome(&self, decision_id: &str, legitimate: bool) -> Result<u8, RiskStoreError> {
        // outcome_confirm.lua: pending -> L/A exactly once.
        if !Self::valid_key_component(decision_id) {
            return Err(RiskStoreError::InvalidIdentifier(format!(
                "decision_id is not a safe Redis key component (got 0x{})",
                hex::encode(decision_id)
            )));
        }
        let key = self.outcome_ledger_key(decision_id);
        let mut invocation = self.outcome_confirm_script.prepare_invoke();
        invocation.key(key.as_str());
        invocation.arg(if legitimate { "L" } else { "A" });
        invocation.arg(self.outcome_ttl_secs.to_string());
        let status: i64 = self
            .pool
            .with_connection(&self.client, |conn| invocation.invoke(conn))?;
        Ok(status as u8)
    }

    fn correct_outcome(&self, decision_id: &str, legitimate: bool) -> Result<bool, RiskStoreError> {
        // outcome_correct.lua: flip L <-> A (no-op when the ledger already
        // carries the target outcome).
        if !Self::valid_key_component(decision_id) {
            return Err(RiskStoreError::InvalidIdentifier(format!(
                "decision_id is not a safe Redis key component (got 0x{})",
                hex::encode(decision_id)
            )));
        }
        let key = self.outcome_ledger_key(decision_id);
        let mut invocation = self.outcome_correct_script.prepare_invoke();
        invocation.key(key.as_str());
        invocation.arg(if legitimate { "L" } else { "A" });
        invocation.arg(self.outcome_ttl_secs.to_string());
        let applied: i64 = self
            .pool
            .with_connection(&self.client, |conn| invocation.invoke(conn))?;
        Ok(applied != 0)
    }

    fn register_target_failure(
        &self,
        target_id: &str,
        source: &str,
        asn: &str,
    ) -> Result<crate::store::TargetState, RiskStoreError> {
        self.run_target_op("fail", target_id, source, asn)
    }

    fn clear_target_failures(&self, target_id: &str) -> Result<(), RiskStoreError> {
        self.run_target_op("clear", target_id, "", "")?;
        Ok(())
    }

    fn read_target_state(&self, target_id: &str) -> Result<crate::store::TargetState, RiskStoreError> {
        self.run_target_op("read", target_id, "", "")
    }

    fn last_global_level(&self) -> u8 {
        self.last_global_level.load(Ordering::Relaxed)
    }

    fn last_cooldown_until_ms(&self) -> u64 {
        self.last_cooldown_until_ms.load(Ordering::Relaxed)
    }
}

/// The risk-v2 session client-context capability: records the first tag a
/// session ever presents (SET NX, first write wins) under the session TTL.
impl SessionContextTagStore for RedisRiskStateStore {
    /// The risk-v2 session client-context record
    /// (`{kiwi:<ns>}:risk:ctx:<session-pseudonym-hex>`): SET NX with the
    /// session TTL (first write wins = the first tag the session ever
    /// presented), then return the recorded tag. The record is keyed by the
    /// session pseudonym only — the raw cookie value never appears in
    /// Redis — and shares the hash tag with the risk-v1 state keys, so it
    /// is Cluster safe.
    fn session_first_context_tag(
        &self,
        session_id: &[u8; 16],
        tag: &str,
    ) -> Result<Option<String>, RiskStoreError> {
        let key = format!(
            "{{kiwi:{}}}:risk:ctx:{}",
            self.namespace,
            hex::encode(session_id)
        );
        self.session_first_tag_record(&key, tag)
    }
}

/// The risk-v2 session trusted-edge TLS capability: records the first
/// coarse TLS classification a session ever presents (SET NX, first write
/// wins) under the session TTL.
impl SessionTlsTagStore for RedisRiskStateStore {
    /// The risk-v2 session trusted-edge TLS record
    /// (`{kiwi:<ns>}:risk:tls:<session-pseudonym-hex>`): SET NX with the
    /// session TTL (first write wins = the first coarse, server-attested
    /// TLS classification the session ever presented), then return the
    /// recorded tag. Mirrors the `session_first_context_tag` machinery
    /// exactly under its own key: keyed by the session pseudonym only —
    /// the raw cookie value never appears in Redis — and sharing the hash
    /// tag with the risk-v1 state keys, so it is Cluster safe.
    fn session_first_tls_tag(
        &self,
        session_id: &[u8; 16],
        tag: &str,
    ) -> Result<Option<String>, RiskStoreError> {
        let key = format!(
            "{{kiwi:{}}}:risk:tls:{}",
            self.namespace,
            hex::encode(session_id)
        );
        self.session_first_tag_record(&key, tag)
    }
}

impl RedisRiskStateStore {
    /// The shared body of the two first-seen session tag records (context /
    /// TLS): SET NX with the session TTL (first write wins), then EXPIRE on
    /// the fresh record or GET the existing one. Runs as ONE unit of pool
    /// work, so any command failure evicts the slot exactly like a failed
    /// script invocation (a desynced reply stream must never serve the next
    /// assessment).
    fn session_first_tag_record(
        &self,
        key: &str,
        tag: &str,
    ) -> Result<Option<String>, RiskStoreError> {
        use ::redis::Commands;
        // ONE command: `SET key tag NX EX ttl`. The previous SET NX plus
        // a separate EXPIRE could be interrupted between the two (process
        // death, connection drop, command timeout), leaving a first-seen
        // session record with NO TTL at all — permanently retained
        // evidence. With the atomic form the lifetime is established by
        // the write itself, so no interruption can produce a persistent
        // key. The TTL is validated positive by the constructor.
        let ttl: i64 = self.session_ttl_secs.try_into().unwrap_or(i64::MAX);
        let created_key = key.to_string();
        let existing_key = key.to_string();
        let tag = tag.to_string();
        self.pool.with_connection(&self.client, |conn| {
            let set: Option<String> = ::redis::cmd("SET")
                .arg(created_key)
                .arg(tag.as_str())
                .arg("NX")
                .arg("EX")
                .arg(ttl)
                .query(conn)?;
            if set.is_some() {
                return Ok(Some(tag.clone()));
            }
            let stored: Option<String> = conn.get(existing_key)?;
            Ok(stored)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::action::RiskAction;
    use crate::event::RiskEventKind;
    use rand::RngCore;
    use redis::Commands;

    const T0: u64 = 1_700_000_000_000;

    fn redis_url() -> Option<String> {
        match std::env::var("RISK_REDIS_URL") {
            Ok(url) if !url.is_empty() => Some(normalize_redis_url(&url)),
            _ => None,
        }
    }

    /// redis-rs parses `redis://` (and `rediss://`), not predis-style
    /// `tcp://` URLs; normalize so both work.
    fn normalize_redis_url(url: &str) -> String {
        if let Some(rest) = url.strip_prefix("tcp://") {
            format!("redis://{rest}")
        } else {
            url.to_string()
        }
    }

    fn client() -> redis_crate::Client {
        redis_crate::Client::open(redis_url().expect("RISK_REDIS_URL set")).expect("url parses")
    }

    fn unique_namespace(prefix: &str) -> String {
        let mut suffix = [0u8; 4];
        rand::thread_rng().fill_bytes(&mut suffix);
        format!("{prefix}{}", hex::encode(suffix))
    }

    fn store(hysteresis_ms: u64, suffix: &str) -> RedisRiskStateStore {
        RedisRiskStateStore::with_options(
            client(),
            &unique_namespace(suffix),
            1800,
            60,
            hysteresis_ms,
            1800,
            86_400,
            DEFAULT_OUTCOME_TTL_SECS,
            DEFAULT_SATURATIONS,
        )
        // Relaxed test timeouts — the production 10 ms
        // command timeout is a fail-fast tuning knob, not a test oracle;
        // under CI scheduling load it produced spurious Timeout flakes in
        // the sequential-storm tests.
        .with_io_timeouts(2_000, 2_000)
    }

    fn epoch_ids(source: &str) -> (i64, String, String, String) {
        let epoch = ((T0 / 1000) / 900) as i64;
        // 32-char lowercase-hex pseudonyms per epoch (the store boundary
        // validates the exact contract shape).
        let id = |suffix: &str| {
            let mut base = source.to_string();
            while base.len() < 30 {
                base.push('0');
            }
            format!("{base}{suffix}")
        };
        (epoch, id("00"), id("11"), id("22"))
    }

    fn observation(event_id: &str, scope: u32, now_ms: u64, network_risk: u16) -> RiskObservation {
        let (src_epoch, src_prev, src_cur, src_next) = epoch_ids("aa");
        let (net_epoch, net_prev, net_cur, net_next) = epoch_ids("bb");
        RiskObservation {
            event: RiskEventKind::PreIssue,
            scope,
            source_epoch: src_epoch,
            source_id_prev: src_prev,
            source_id: src_cur,
            source_id_next: src_next,
            subnet_epoch: net_epoch,
            subnet_id_prev: net_prev,
            subnet_id: net_cur,
            subnet_id_next: net_next,
            session_id: None,
            principal_id: None,
            event_id: event_id.to_string(),
            network_risk,
            now_ms,
        }
    }

    fn event_id(n: u64) -> String {
        let mut out = [0u8; 16];
        out[..8].copy_from_slice(&n.to_be_bytes());
        hex::encode(out)
    }

    #[test]
    fn crc16_vectors() {
        // Redis docs: CRC16("123456789") = 0x31C3; slot of "foo" = 12182.
        assert_eq!(RedisRiskStateStore::crc16(b"123456789"), 0x31C3);
        assert_eq!(RedisRiskStateStore::crc16(b"foo") & 0x3FFF, 12_182);
        assert_eq!(RedisRiskStateStore::crc16(b""), 0);
    }

    #[test]
    fn assert_same_slot_contract_key_set() {
        let tag = format!("{{kiwi:{}}}", unique_namespace("slot"));
        let (src_epoch, src_prev, src_cur, src_next) = epoch_ids("a");
        let (net_epoch, net_prev, net_cur, net_next) = epoch_ids("b");
        let keys = vec![
            format!("{tag}:risk:src:{src_epoch}:{src_cur}"),
            format!("{tag}:risk:src:{}:{src_prev}", src_epoch - 1),
            format!("{tag}:risk:src:{}:{src_next}", src_epoch + 1),
            format!("{tag}:risk:net:{net_epoch}:{net_cur}"),
            format!("{tag}:risk:net:{}:{net_prev}", net_epoch - 1),
            format!("{tag}:risk:net:{}:{net_next}", net_epoch + 1),
            format!("{tag}:risk:session:{}", "0".repeat(32)),
            format!("{tag}:risk:principal:{}", "0".repeat(32)),
            format!("{tag}:risk:global"),
            format!("{tag}:risk:dedupe:{}", "c".repeat(32)),
        ];
        assert!(RedisRiskStateStore::assert_same_slot(&keys).is_ok());

        let mut broken = keys;
        broken[0] = broken[0].replace(&tag, &format!("{{kiwi:{}}}", unique_namespace("other")));
        assert!(RedisRiskStateStore::assert_same_slot(&broken).is_err());

        let no_tag = vec!["risk:global".to_string()];
        assert!(RedisRiskStateStore::assert_same_slot(&no_tag).is_err());
    }

    // ── Hermetic pool-eviction tests (no Redis URL needed) ──

    /// A failed invocation evicts its pool slot: the connection is dropped
    /// (never returned to the slot), and the next acquire on that slot
    /// opens a fresh TCP connection. A miniature endpoint accepts a
    /// connection, swallows the first command bytes and then closes the
    /// socket without replying — the in-flight invocation fails with an
    /// I/O error, exactly the "reply timed out / backend died mid-command"
    /// shape that would desync the reply stream if the connection were
    /// reused. Hermetic: no Redis URL needed.
    #[test]
    fn failed_invocation_evicts_the_pool_slot() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let accepted = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let server_accepted = std::sync::Arc::clone(&accepted);
        std::thread::spawn(move || {
            use std::io::Read;
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { continue };
                server_accepted.fetch_add(1, Ordering::SeqCst);
                // Swallow whatever command the client sends, then close
                // with no reply (dropping the stream sends the FIN).
                let mut buf = [0u8; 512];
                let _ = stream.read(&mut buf);
            }
        });

        let url = format!("redis://127.0.0.1:{port}/");
        let client = redis_crate::Client::open(url).expect("fake endpoint URL parses");
        // pool_size 1: a single slot, so round-robin cannot mask the
        // eviction with a different slot. Relaxed timeouts for CI jitter.
        let store =
            RedisRiskStateStore::with_pool_size(client, "evict", 1).with_io_timeouts(2_000, 2_000);
        let obs = observation(&event_id(1), 0, T0, 0);

        assert!(
            store.observe(&obs).is_err(),
            "the abruptly closed reply must fail the invocation"
        );
        assert_eq!(
            store.live_pool_connections(),
            0,
            "the slot whose invocation failed must be evicted (None), never reused"
        );
        assert_eq!(accepted.load(Ordering::SeqCst), 1);

        // The evicted slot reconnects on its next acquire: a second TCP
        // connection is accepted by the endpoint. Without eviction the
        // stale (closed-socket) connection would sit in the slot and the
        // next invocation would fail on it without any new connection.
        assert!(store.observe(&obs).is_err());
        assert_eq!(
            accepted.load(Ordering::SeqCst),
            2,
            "the next acquire on the evicted slot must have reconnected"
        );
        assert_eq!(store.live_pool_connections(), 0);
    }

    // ── Hermetic input-validation tests (no Redis URL needed) ──

    /// A client pointing at a guaranteed-refused port (a listener is bound
    /// and dropped): the store constructor is lazy, and any real command
    /// fails fast with a connection error.
    fn dead_port_client() -> redis_crate::Client {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        redis_crate::Client::open(format!("redis://127.0.0.1:{port}/")).unwrap()
    }

    #[test]
    #[should_panic(expected = "Risk namespace must be non-empty and free of braces")]
    fn empty_namespace_is_rejected_at_construction() {
        let _ = RedisRiskStateStore::new(dead_port_client(), "");
    }

    #[test]
    #[should_panic(expected = "Risk namespace must be non-empty and free of braces")]
    fn open_brace_namespace_is_rejected_at_construction() {
        let _ = RedisRiskStateStore::new(dead_port_client(), "ns{");
    }

    #[test]
    #[should_panic(expected = "Risk namespace must be non-empty and free of braces")]
    fn close_brace_namespace_is_rejected_at_construction() {
        let _ = RedisRiskStateStore::new(dead_port_client(), "ns}");
    }

    #[test]
    fn malformed_observations_are_rejected_at_the_store_boundary() {
        let store = RedisRiskStateStore::new(dead_port_client(), "validate");
        let expect_reject = |o: &RiskObservation| {
            let err = store.observe(o).unwrap_err();
            assert!(
                matches!(err, RiskStoreError::ScriptError(_)),
                "malformed observation must fail closed with the script error (got {err:?})"
            );
        };

        // Short pseudonym.
        let mut o = observation(&event_id(1), 0, T0, 0);
        o.source_id = "aa00".to_string();
        expect_reject(&o);
        // Uppercase hex is outside the contract.
        let mut o = observation(&event_id(1), 0, T0, 0);
        o.subnet_id_next = "A".repeat(32);
        expect_reject(&o);
        // Non-hex characters.
        let mut o = observation(&event_id(1), 0, T0, 0);
        o.source_id_prev = format!("z{}", "0".repeat(31));
        expect_reject(&o);
        // Event id: empty, wrong length, non-hex — the 32-or-64 lowercase
        // hex contract (PHP mirrors these exactly).
        let mut o = observation(&event_id(1), 0, T0, 0);
        o.event_id = String::new();
        expect_reject(&o);
        let mut o = observation(&event_id(1), 0, T0, 0);
        o.event_id = "0".repeat(31);
        expect_reject(&o);
        let mut o = observation(&event_id(1), 0, T0, 0);
        o.event_id = format!("g{}", "0".repeat(63));
        expect_reject(&o);
        // Network risk outside the 0..1000 band.
        let o = observation(&event_id(1), 0, T0, 1001);
        expect_reject(&o);

        // The consolidated surface validates identically.
        let mut o = observation(&event_id(1), 0, T0, 0);
        o.source_id = "aa00".to_string();
        assert!(matches!(
            store.assess_v2_full(&o, None, None, None),
            Err(RiskStoreError::ScriptError(_))
        ));

        // A valid observation passes validation and reaches the backend
        // (the dead port fails with a connection error, NOT a validation
        // error).
        let o = observation(&event_id(1), 0, T0, 0);
        assert!(matches!(
            store.observe(&o),
            Err(RiskStoreError::BackendUnavailable(_))
        ));
    }

    /// A miniature fake Redis endpoint that answers every complete command
    /// with one fixed RESP payload: the reply-fidelity harness. The
    /// listener lives inside the spawned thread, so the port stays bound
    /// for the test's duration.
    fn serve_fixed_reply(payload: String) -> u16 {
        // The bytes consumed by the first complete RESP array in
        // `acc` (a `*N` header followed by N complete bulk strings),
        // or 0 while the frame is still partial.
        fn complete_resp_array(acc: &[u8]) -> usize {
            if acc.first() != Some(&b'*') {
                return 0;
            }
            let Some(header_end) = acc.windows(2).position(|w| w == b"\r\n") else {
                return 0;
            };
            let Some(count) = std::str::from_utf8(&acc[1..header_end])
                .ok()
                .and_then(|h| h.trim().parse::<usize>().ok())
            else {
                return acc.len();
            };
            let mut pos = header_end + 2;
            for _ in 0..count {
                // A frame that stops short of its next bulk header
                // is incomplete until more bytes arrive.
                if acc.get(pos) != Some(&b'$') {
                    return 0;
                }
                let Some(len_end) = acc[pos..].windows(2).position(|w| w == b"\r\n") else {
                    return 0;
                };
                let Some(len) = std::str::from_utf8(&acc[pos + 1..pos + len_end])
                    .ok()
                    .and_then(|l| l.trim().parse::<usize>().ok())
                else {
                    return acc.len();
                };
                pos += len_end + 2 + len + 2;
                if pos > acc.len() {
                    return 0;
                }
            }
            pos
        }
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            use std::io::{Read, Write};
            use std::time::Duration;
            // One handler thread per connection: a client that
            // reconnects (the pool evicts and re-acquires after a
            // failed reply) never waits behind a prior connection's
            // reply cycle.
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { continue };
                let payload = payload.clone();
                std::thread::spawn(move || {
                    // Every read is bounded so the reply loop always
                    // re-checks its deadline instead of blocking past
                    // it on a quiet client. One payload per complete
                    // RESP frame keeps the pipelined setup commands
                    // and the script call each paired with a reply.
                    let _ = stream.set_read_timeout(Some(Duration::from_millis(25)));
                    let _ = stream.set_write_timeout(Some(Duration::from_millis(25)));
                    let mut buf = [0u8; 4096];
                    let mut acc: Vec<u8> = Vec::new();
                    let idle = std::time::Instant::now() + Duration::from_millis(2_000);
                    while std::time::Instant::now() < idle {
                        match stream.read(&mut buf) {
                            Ok(0) => break,
                            Ok(n) => acc.extend_from_slice(&buf[..n]),
                            Err(_) => continue,
                        }
                        while let consumed_at @ 1.. = complete_resp_array(&acc) {
                            acc.drain(..consumed_at);
                            let _ = stream.write_all(payload.as_bytes());
                            let _ = stream.flush();
                        }
                    }
                });
            }
        });
        port
    }

    /// Builds one fixed RESP reply with `slots` elements, each rendered by
    /// `slot`: the malformed-reply tests substitute single slots without
    /// hand-counting the payload.
    fn fixed_reply(slots: usize, slot: impl Fn(usize) -> &'static str) -> String {
        let mut reply = format!("*{slots}\r\n");
        for i in 0..slots {
            reply.push_str(slot(i));
        }
        reply
    }

    /// A store on a fresh fake endpoint serving `payload`.
    fn fake_store(payload: String, namespace: &str) -> RedisRiskStateStore {
        let port = serve_fixed_reply(payload);
        let client = redis_crate::Client::open(format!("redis://127.0.0.1:{port}/")).unwrap();
        RedisRiskStateStore::with_pool_size(client, namespace, 1).with_io_timeouts(2_000, 2_000)
    }

    /// The clamp contract: the script reply's integer slots are out of
    /// band (negative / >1000 / level 9 / negative cooldown) — the store
    /// must clamp every decoded slot to the contract bands instead of
    /// wrapping the raw i64 casts.
    #[test]
    fn reply_slots_are_clamped_to_the_contract_bands() {
        // Serves the fixed RESP payload once per complete command: the
        // client pipelines its connection-setup commands ahead of the
        // script call, so the frame count (not the byte count) decides
        // the reply count.
        // observe_full: the 16-slot tampered reply.
        let reply = b"*16\r\n:70000\r\n:-5\r\n:1000\r\n:0\r\n:0\r\n:0\r\n:0\r\n:0\r\n:0\r\n:0\r\n:0\r\n:65541\r\n:0\r\n:9\r\n:-7\r\n:2\r\n".to_vec();
        let store = fake_store(String::from_utf8(reply).unwrap(), "clamp");
        let observed = store
            .observe(&observation(&event_id(1), 0, T0, 0))
            .expect("the tampered reply must still parse");
        assert_eq!(observed.vector.source_fast, 1000, "70000 clamps to 1000");
        assert_eq!(observed.vector.source_slow, 0, "-5 clamps to 0");
        assert_eq!(observed.vector.subnet_fast, 1000);
        assert_eq!(observed.vector.trust_credit, 1000, "65541 clamps to 1000");
        assert_eq!(observed.global_level, 4, "level 9 clamps to 4");
        assert_eq!(observed.cooldown_until_ms, 0, "-7 clamps to 0");
        assert!(observed.is_duplicate);

        // assess_v2_full: the same clamps in the 19-slot consolidated
        // reply (slots 16..18 are the tag/registration strings).
        let reply = b"*22\r\n:70000\r\n:-5\r\n:1000\r\n:0\r\n:0\r\n:0\r\n:0\r\n:0\r\n:0\r\n:0\r\n:0\r\n:65541\r\n:0\r\n:9\r\n:-7\r\n:2\r\n$2\r\naa\r\n$0\r\n\r\n:0\r\n:0\r\n:0\r\n:0\r\n".to_vec();
        let store = fake_store(String::from_utf8(reply).unwrap(), "clampv2");
        let reply = store
            .assess_v2_full(&observation(&event_id(1), 0, T0, 0), None, None, None)
            .expect("the tampered consolidated reply must still parse");
        assert_eq!(reply.observed.vector.source_fast, 1000);
        assert_eq!(reply.observed.vector.source_slow, 0);
        assert_eq!(reply.observed.vector.trust_credit, 1000);
        assert_eq!(reply.observed.global_level, 4);
        assert_eq!(reply.observed.cooldown_until_ms, 0);
        assert_eq!(reply.existing_context_tag.as_deref(), Some("aa"));
        assert_eq!(reply.existing_tls_tag, None);
        assert!(!reply.registration_status);
    }

    // ── Hermetic reply-fidelity tests (no Redis URL needed) ──

    /// The integer-slot decoder accepts Int and numeric bulk/simple-string
    /// replies and rejects every other reply type with the script error,
    /// the same fail-closed shape the typed decode in `observe_full` gives.
    #[test]
    fn integer_slot_decoder_rejects_non_integer_reply_types() {
        use redis_crate::Value;
        assert_eq!(value_i64(&Value::Int(7)).unwrap(), 7);
        assert_eq!(value_i64(&Value::BulkString(b"42".to_vec())).unwrap(), 42);
        assert_eq!(
            value_i64(&Value::SimpleString("43".to_string())).unwrap(),
            43
        );
        for unexpected in [
            Value::Nil,
            Value::Array(vec![Value::Int(1)]),
            Value::BulkString(b"abc".to_vec()),
            Value::SimpleString("abc".to_string()),
            Value::Boolean(true),
        ] {
            assert!(
                matches!(value_i64(&unexpected), Err(RiskStoreError::ScriptError(_))),
                "expected the script error for {unexpected:?}"
            );
        }
    }

    /// A malformed or shifted integer slot must fail the consolidated
    /// assessment closed with the script error, never decode as 0: a Nil,
    /// an array, and a non-numeric bulk string each fail. The tag slots 16
    /// and 17 stay the only slots that accept Nil or a string.
    #[test]
    fn assess_v2_full_fails_closed_on_malformed_integer_slots() {
        let observation = observation(&event_id(1), 0, T0, 0);
        let cases: [(&str, usize, &str, &str); 3] = [
            ("nil", 0, "$-1\r\n", "a Nil signal slot"),
            ("arr", 12, "*1\r\n:5\r\n", "an array signal slot"),
            (
                "str",
                11,
                "$3\r\nabc\r\n",
                "a non-numeric string signal slot",
            ),
        ];
        for (namespace, malformed_slot, malformed_reply, label) in cases {
            let reply = fixed_reply(22, |i| {
                if i == malformed_slot {
                    malformed_reply
                } else if i == 16 {
                    "$2\r\naa\r\n"
                } else if i == 17 {
                    "$0\r\n\r\n"
                } else {
                    ":0\r\n"
                }
            });
            let store = fake_store(reply, namespace);
            let err = store
                .assess_v2_full(&observation, None, None, None)
                .expect_err("the malformed reply must fail closed");
            assert!(
                matches!(err, RiskStoreError::ScriptError(_)),
                "{label} must fail closed with the script error (got {err:?})"
            );
        }
    }

    /// The tag slots 16 and 17 accept Nil or a string: a Nil tag decodes
    /// as no recorded tag, a string tag decodes as the recorded value.
    #[test]
    fn assess_v2_full_tag_slots_accept_nil_and_strings() {
        let observation = observation(&event_id(1), 0, T0, 0);
        let reply = fixed_reply(22, |i| match i {
            16 => "$-1\r\n",
            17 => "$2\r\nbb\r\n",
            _ => ":0\r\n",
        });
        let store = fake_store(reply, "tagnil");
        let reply = store
            .assess_v2_full(&observation, None, None, None)
            .expect("Nil and string tags must decode");
        assert_eq!(reply.existing_context_tag, None, "a Nil tag means none");
        assert_eq!(reply.existing_tls_tag.as_deref(), Some("bb"));

        let reply = fixed_reply(22, |i| match i {
            16 => "$2\r\naa\r\n",
            17 => "$-1\r\n",
            _ => ":0\r\n",
        });
        let store = fake_store(reply, "tagnil2");
        let reply = store
            .assess_v2_full(&observation, None, None, None)
            .expect("a string and a Nil tag must decode");
        assert_eq!(reply.existing_context_tag.as_deref(), Some("aa"));
        assert_eq!(reply.existing_tls_tag, None);
    }

    /// Tag slots 16 and 17 are strings-or-Nil only: a shifted non-string
    /// reply (an integer or an array in a tag slot) fails closed instead
    /// of silently decoding as "no recorded tag".
    #[test]
    fn assess_v2_full_fails_closed_on_non_string_tag_slots() {
        let observation = observation(&event_id(1), 0, T0, 0);
        for (namespace, tag_slot, malformed_reply, label) in [
            ("tagint", 16, ":5\r\n", "an integer context tag"),
            ("tagarr", 17, "*1\r\n:5\r\n", "an array TLS tag"),
        ] {
            let reply = fixed_reply(22, |i| {
                if i == tag_slot {
                    malformed_reply
                } else if i == 16 || i == 17 {
                    "$0\r\n\r\n"
                } else {
                    ":0\r\n"
                }
            });
            let store = fake_store(reply, namespace);
            let err = store
                .assess_v2_full(&observation, None, None, None)
                .expect_err("a non-string tag slot must fail closed");
            assert!(
                matches!(err, RiskStoreError::ScriptError(_)),
                "{label} must fail closed with the script error (got {err:?})"
            );
        }
    }

    /// observe_full decodes into a typed vector, so the same malformed Nil
    /// slot fails closed there too.
    #[test]
    fn observe_full_fails_closed_on_a_malformed_integer_slot() {
        let reply = fixed_reply(16, |i| if i == 0 { "$-1\r\n" } else { ":0\r\n" });
        let store = fake_store(reply, "obsnil");
        assert!(store.observe(&observation(&event_id(1), 0, T0, 0)).is_err());
    }

    /// The connect default tolerates a TLS, managed or cross-AZ handshake,
    /// the command timeout stays tight, and the calibration store shares
    /// both values. The builder overrides both knobs.
    #[test]
    fn io_timeout_defaults_and_builder() {
        assert_eq!(RedisRiskStateStore::CONNECTION_TIMEOUT_MS, 75);
        assert_eq!(RedisRiskStateStore::COMMAND_TIMEOUT_MS, 10);
        assert_eq!(
            crate::calibration::RedisCalibrationStore::CONNECTION_TIMEOUT_MS,
            RedisRiskStateStore::CONNECTION_TIMEOUT_MS,
            "the calibration store shares the state store's connect default"
        );
        assert_eq!(
            crate::calibration::RedisCalibrationStore::COMMAND_TIMEOUT_MS,
            RedisRiskStateStore::COMMAND_TIMEOUT_MS,
            "the calibration store shares the state store's command default"
        );

        let store = RedisRiskStateStore::new(dead_port_client(), "timeouts");
        assert_eq!(store.connection_timeout_ms, 75);
        assert_eq!(store.command_timeout_ms, 10);
        assert_eq!(store.pool.connection_timeout_ms, 75);
        assert_eq!(store.pool.command_timeout_ms, 10);

        let tuned = store.with_io_timeouts(120, 15);
        assert_eq!(tuned.connection_timeout_ms, 120);
        assert_eq!(tuned.command_timeout_ms, 15);
        assert_eq!(tuned.pool.connection_timeout_ms, 120);
        assert_eq!(tuned.pool.command_timeout_ms, 15);
    }

    // ── Redis-backed tests (skipped unless the Redis test URL is set) ──

    #[test]
    fn single_event() {
        let Some(_url) = redis_url() else {
            eprintln!("skipping Redis test: RISK_REDIS_URL not set");
            return;
        };
        let store = store(60_000, "single");
        let observed = store.observe(&observation(&event_id(1), 0, T0, 0)).unwrap();
        let vector = observed.vector;
        assert_eq!(vector.source_fast, 125); // 1000*1000/8000
        assert_eq!(vector.source_slow, 10); // 1000*1000/100000
        assert_eq!(vector.subnet_fast, 125);
        assert_eq!(vector.issue_debt, 0);
        assert_eq!(vector.global_pressure, 28); // 2000*1000/70000
        assert_eq!(vector.network_risk, 0); // classifier side-channel override
        assert_eq!(vector.principal_credit, 0); // no principal state yet
        assert!(!observed.is_duplicate);
        assert_eq!(store.last_global_level(), 0);
    }

    #[test]
    fn duplicate_event_id_single_increment() {
        let Some(_url) = redis_url() else {
            eprintln!("skipping Redis test: RISK_REDIS_URL not set");
            return;
        };
        let store = store(60_000, "dup");
        let id = event_id(7);

        let first = store.observe(&observation(&id, 0, T0, 0)).unwrap();
        assert_eq!(first.vector.source_fast, 125);
        assert!(!first.is_duplicate);

        // Same event_id again: duplicate no-op, current signals returned.
        // The channels leak by real elapsed time (rf 250/s, rs 20/s), so
        // sequential calls can floor one unit lower on a slow runner.
        let duplicate = store.observe(&observation(&id, 0, T0, 0)).unwrap();
        assert!(duplicate.is_duplicate);
        assert!(
            (100..=125).contains(&duplicate.vector.source_fast),
            "a duplicate must not increment (got {})",
            duplicate.vector.source_fast
        );
        assert!(
            (8..=10).contains(&duplicate.vector.source_slow),
            "a duplicate must not increment (got {})",
            duplicate.vector.source_slow
        );

        // A distinct event must observe the state from a single increment
        // (two events, minus the small real-elapsed decay).
        let third = store.observe(&observation(&event_id(8), 0, T0, 0)).unwrap();
        assert!(!third.is_duplicate);
        assert!(
            (200..=250).contains(&third.vector.source_fast),
            "exactly two increments (got {})",
            third.vector.source_fast
        );
        assert!(
            (18..=20).contains(&third.vector.source_slow),
            "exactly two increments (got {})",
            third.vector.source_slow
        );
    }

    #[test]
    fn network_risk_override_slot() {
        let Some(_url) = redis_url() else {
            eprintln!("skipping Redis test: RISK_REDIS_URL not set");
            return;
        };
        let store = store(60_000, "nrisk");
        let observed = store
            .observe(&observation(&event_id(3), 0, T0, 600))
            .unwrap();
        assert_eq!(observed.vector.network_risk, 600);
        assert_eq!(observed.vector.principal_credit, 0);
    }

    /// The risk-v2 session client-context record: SET NX first-write-wins
    /// with the session TTL — the first tag a session presents is recorded
    /// and returned forever, a later different tag still yields the first
    /// one (the engine derives the inconsistency signal from that).
    #[test]
    fn session_first_context_tag_records_the_first_tag_with_the_session_ttl() {
        let Some(_url) = redis_url() else {
            eprintln!("skipping Redis test: RISK_REDIS_URL not set");
            return;
        };
        let store = store(60_000, "firsttag");
        let session_id = [0x5au8; 16];

        // First tag-bearing request: the tag is recorded and returned.
        let first = store.session_first_context_tag(&session_id, "aa").unwrap();
        assert_eq!(first.as_deref(), Some("aa"));

        // Same tag again: the recorded first tag is returned unchanged.
        let again = store.session_first_context_tag(&session_id, "aa").unwrap();
        assert_eq!(again.as_deref(), Some("aa"));

        // A different tag: the first tag wins (the inconsistency signal
        // derives from this comparison).
        let changed = store.session_first_context_tag(&session_id, "bb").unwrap();
        assert_eq!(
            changed.as_deref(),
            Some("aa"),
            "the first-seen tag must win"
        );

        // The record carries the session TTL (1800 s), like the risk-v1
        // session state hash.
        let key = format!(
            "{{kiwi:{}}}:risk:ctx:{}",
            store.namespace(),
            hex::encode(session_id)
        );
        let mut conn = client().get_connection().expect("connection");
        let ttl: i64 = ::redis::Commands::ttl(&mut conn, key.as_str()).unwrap();
        assert!(
            (1..=1800).contains(&ttl),
            "the record must expire with the session TTL (got {ttl})"
        );

        // A different session has its own record.
        let other = [0x2bu8; 16];
        let other_first = store.session_first_context_tag(&other, "zz").unwrap();
        assert_eq!(other_first.as_deref(), Some("zz"));
    }

    /// The risk-v2 session trusted-edge TLS record: SET NX first-write-wins
    /// with the session TTL — the first coarse TLS classification a session
    /// presents is recorded and returned forever, a later different tag
    /// still yields the first one (the engine derives the tls_inconsistency
    /// signal from that). Mirrors the session_first_context_tag machinery
    /// exactly under its own key.
    #[test]
    fn session_first_tls_tag_records_the_first_tag_with_the_session_ttl() {
        let Some(_url) = redis_url() else {
            eprintln!("skipping Redis test: RISK_REDIS_URL not set");
            return;
        };
        let store = store(60_000, "firsttls");
        let session_id = [0x7cu8; 16];

        // First TLS tag-bearing request: the tag is recorded and returned.
        let first = store
            .session_first_tls_tag(&session_id, "tls13|http2")
            .unwrap();
        assert_eq!(first.as_deref(), Some("tls13|http2"));

        // Same tag again: the recorded first tag is returned unchanged.
        let again = store
            .session_first_tls_tag(&session_id, "tls13|http2")
            .unwrap();
        assert_eq!(again.as_deref(), Some("tls13|http2"));

        // A different tag: the first tag wins (the tls_inconsistency signal
        // derives from this comparison).
        let changed = store
            .session_first_tls_tag(&session_id, "tls12|http1")
            .unwrap();
        assert_eq!(
            changed.as_deref(),
            Some("tls13|http2"),
            "the first-seen TLS tag must win"
        );

        // The record carries the session TTL (1800 s), like the risk-v1
        // session state hash.
        let key = format!(
            "{{kiwi:{}}}:risk:tls:{}",
            store.namespace(),
            hex::encode(session_id)
        );
        let mut conn = client().get_connection().expect("connection");
        let ttl: i64 = ::redis::Commands::ttl(&mut conn, key.as_str()).unwrap();
        assert!(
            (1..=1800).contains(&ttl),
            "the record must expire with the session TTL (got {ttl})"
        );

        // A different session has its own record.
        let other = [0x8du8; 16];
        let other_first = store.session_first_tls_tag(&other, "tls13|h3").unwrap();
        assert_eq!(other_first.as_deref(), Some("tls13|h3"));
    }

    #[test]
    fn hundred_sequential_events_saturate() {
        let Some(_url) = redis_url() else {
            eprintln!("skipping Redis test: RISK_REDIS_URL not set");
            return;
        };
        let store = store(60_000, "sat");
        let mut vector = SignalVector::zero();
        for i in 0..100u64 {
            vector = store
                .observe(&observation(&event_id(i), 0, T0, 0))
                .unwrap()
                .vector;
        }
        assert_eq!(vector.source_fast, 1000);
        // source_slow leaks at 20/s against 100_000 raw: the sequential
        // storm decays a few raw units of real elapsed time, so the floor
        // can sit at 999; anything below 990 would mean lost increments.
        assert!(
            (990..=1000).contains(&vector.source_slow),
            "no increments may be lost (got {})",
            vector.source_slow
        );
        assert_eq!(vector.subnet_fast, 1000);
        assert_eq!(vector.global_pressure, 1000);
        assert_eq!(store.last_global_level(), 4);
    }

    #[test]
    fn global_hysteresis() {
        let Some(_url) = redis_url() else {
            eprintln!("skipping Redis test: RISK_REDIS_URL not set");
            return;
        };
        let mut conn = client().get_connection().expect("connection");
        let t: Vec<i64> = redis::cmd("TIME").query(&mut conn).expect("TIME");
        let t0 = (t[0] * 1000 + t[1] / 1000) as u64;

        // Normalized global thresholds: L1 >= 300, L2 >= 550, L3 >= 750,
        // L4 >= 900 (raw gp scaled by sat_global 70000). Each PreIssue adds
        // 2000 raw (rf 1000 + rs 1000): 20 events -> gp 40000 -> 571 (L2);
        // 32 events -> gp 64000 -> 914 (L4). Leak: rf 250/s, rs 20/s. The
        // rate-limit clock is Redis time, so the cooldown deadline is
        // asserted against the real clock, not an injected one.
        let big = store(60_000, "big");
        for i in 1..=20u64 {
            big.observe(&observation(&event_id(i), 2, T0, 0)).unwrap();
        }
        assert_eq!(big.last_global_level(), 2, "20 events must reach level 2");
        for i in 21..=32u64 {
            big.observe(&observation(&event_id(i), 2, T0, 0)).unwrap();
        }
        assert_eq!(big.last_global_level(), 4, "32 events must reach level 4");
        let cool = big.last_cooldown_until_ms();
        assert!(
            cool > t0 + 60_000 && cool <= t0 + 65_000,
            "the 60 s cooldown must be armed at the ratchet time + 60000 (got {cool}, t0 {t0})"
        );

        // The drop after the hysteresis window needs a real ~2.1 s sleep
        // (the script derives its clock from Redis time): a short window of
        // 2 s and a saturation that makes 5 events reach L4 (10000 raw ->
        // 909). RiskDenied probes add NO pressure, so the decay is pure.
        let mut sats = DEFAULT_SATURATIONS;
        sats[8] = 11_000; // sat_global (argv[16])
        let tiny = RedisRiskStateStore::with_options(
            client(),
            &unique_namespace("tiny"),
            1800,
            60,
            2000,
            1800,
            86_400,
            DEFAULT_OUTCOME_TTL_SECS,
            sats,
        );
        for i in 1..=5u64 {
            tiny.observe(&observation(&event_id(i), 2, T0, 0)).unwrap();
        }
        let settle = |id: u64| {
            let mut o = observation(&event_id(id), 2, T0, 0);
            o.event = RiskEventKind::RiskDenied;
            o
        };
        tiny.observe(&settle(90)).unwrap();
        assert_eq!(tiny.last_global_level(), 4);
        let cool = tiny.last_cooldown_until_ms();
        assert!(
            cool > t0 + 2_000 && cool <= t0 + 7_000,
            "the 2 s cooldown must be armed at the ratchet time + 2000"
        );

        // Inside the window (+1 s): gp 10000 - ~270 = ~9730 -> 884 — below
        // the L4 enter (900), still above the L4 exit (850) — the hold
        // applies and the deadline is untouched.
        std::thread::sleep(Duration::from_millis(1000));
        tiny.observe(&settle(90)).unwrap();
        assert_eq!(
            tiny.last_global_level(),
            4,
            "level holds inside the 2 s window"
        );
        assert_eq!(
            tiny.last_cooldown_until_ms(),
            cool,
            "the hold keeps the deadline"
        );

        // After the window (+~2.1 s more, ~3.1 s total): gp 10000 - ~840 =
        // ~9160 -> 833 < the L4 exit 850 and now >= cool -> the level drops
        // to the target (L3) and the hold closes.
        std::thread::sleep(Duration::from_millis(2100));
        tiny.observe(&settle(90)).unwrap();
        assert_eq!(
            tiny.last_global_level(),
            3,
            "level must drop to the target after the hysteresis window"
        );
        assert_eq!(tiny.last_cooldown_until_ms(), 0);
    }

    #[test]
    fn outcome_ledger_lifecycle_is_always_on() {
        let Some(_url) = redis_url() else {
            eprintln!("skipping Redis test: RISK_REDIS_URL not set");
            return;
        };
        let store = store(60_000, "ledger");
        let hour = (T0 / 3_600_000) as i64;

        // Unknown decision: confirm/correct are no-ops.
        assert_eq!(store.confirm_outcome("led-unknown", true).unwrap(), 0);
        assert!(!store.correct_outcome("led-unknown", false).unwrap());

        // Register: pending ledger created once.
        assert!(store.register_outcome("led-1", 7, hour, 900).unwrap());
        assert!(
            !store.register_outcome("led-1", 7, hour, 900).unwrap(),
            "a duplicate registration must not overwrite the ledger"
        );
        let mut conn = client().get_connection().expect("connection");
        let key = store.outcome_ledger_key("led-1");
        let raw: String = conn.get(&key).expect("get");
        let value: serde_json::Value = serde_json::from_str(&raw).expect("json");
        assert_eq!(value["o"], "P");
        assert_eq!(value["scope"], 7);
        assert_eq!(value["hour"], hour);
        assert_eq!(value["score"], 900);
        let ttl: i64 = redis::cmd("TTL").arg(&key).query(&mut conn).expect("ttl");
        assert!(
            (1..=86_400).contains(&ttl),
            "the ledger TTL is the outcome TTL (got {ttl})"
        );

        // First confirmation flips to A; the retry is a no-op.
        assert_eq!(store.confirm_outcome("led-1", false).unwrap(), 1);
        assert_eq!(store.confirm_outcome("led-1", false).unwrap(), 0);
        let raw: String = conn.get(&key).expect("get");
        let value: serde_json::Value = serde_json::from_str(&raw).expect("json");
        assert_eq!(value["o"], "A");

        // Correction flips A -> L once; the repeat (already L) is a no-op.
        assert!(store.correct_outcome("led-1", true).unwrap());
        assert!(!store.correct_outcome("led-1", true).unwrap());
        let raw: String = conn.get(&key).expect("get");
        let value: serde_json::Value = serde_json::from_str(&raw).expect("json");
        assert_eq!(value["o"], "L");

        // A pending entry is never corrected directly: confirmation is
        // the only transition out of pending (a direct P flip would skip
        // the confirmation and its reputation event). The refusal must
        // leave the ledger untouched.
        assert!(store.register_outcome("led-2", 7, hour, 100).unwrap());
        assert!(!store.correct_outcome("led-2", false).unwrap());
        let raw: String = conn.get(store.outcome_ledger_key("led-2")).expect("get");
        let value: serde_json::Value = serde_json::from_str(&raw).expect("json");
        assert_eq!(value["o"], "P");

        // After a real confirmation the correction applies, and the
        // original TTL is preserved (SET ... KEEPTTL, never re-extended).
        assert_eq!(store.confirm_outcome("led-2", true).unwrap(), 1);
        let ttl_before: i64 = redis::cmd("TTL")
            .arg(store.outcome_ledger_key("led-2"))
            .query(&mut conn)
            .expect("ttl");
        assert!(store.correct_outcome("led-2", false).unwrap());
        let ttl_after: i64 = redis::cmd("TTL")
            .arg(store.outcome_ledger_key("led-2"))
            .query(&mut conn)
            .expect("ttl");
        let raw: String = conn.get(store.outcome_ledger_key("led-2")).expect("get");
        let value: serde_json::Value = serde_json::from_str(&raw).expect("json");
        assert_eq!(value["o"], "A");
        assert!(
            ttl_after <= ttl_before && ttl_before - ttl_after <= 2,
            "KEEPTTL must preserve the ledger TTL (before {ttl_before}, after {ttl_after})"
        );
    }

    #[test]
    fn assess_v2_registers_ledger_tags_and_returns_status() {
        let Some(_url) = redis_url() else {
            eprintln!("skipping Redis test: RISK_REDIS_URL not set");
            return;
        };
        let store = store(60_000, "v2assess");
        let session = [0x9c; 16];
        let mut o = observation(&event_id(5), 1, T0, 600);
        o.session_id = Some(session);
        let registration = OutcomeRegistration {
            decision_id: "dec-cons-1".to_string(),
            decision_hour: 472_222,
            base_risk: 100,
            global_pressure_enabled: true,
            honeypot_hit: false,
            v1_weights: crate::score::RiskWeights::default(),
            v2_weights: crate::score::RiskV2Weights::default(),
            target_id: None,
        };

        let reply = store
            .assess_v2_full(&o, Some("aa"), Some("tls13|http2"), Some(&registration))
            .expect("consolidated assessment");
        assert!(
            reply.registration_status,
            "the pending ledger entry must be created"
        );
        assert_eq!(reply.existing_context_tag.as_deref(), Some("aa"));
        assert_eq!(reply.existing_tls_tag.as_deref(), Some("tls13|http2"));
        assert_eq!(
            reply.observed.vector.source_fast, 125,
            "the v1 observation must run identically"
        );

        // The ledger mirrors register_outcome byte-for-byte: the script
        // computes the exact decision score from the signals, weights and
        // base risk (100 + weighted 125,190 + weighted 10,110 +
        // weighted 125,80 + weighted 28,170 + weighted 600,100 = 198).
        let mut conn = client().get_connection().expect("connection");
        let key = store.outcome_ledger_key("dec-cons-1");
        let raw: String = conn.get(&key).expect("get");
        let value: serde_json::Value = serde_json::from_str(&raw).expect("json");
        assert_eq!(value["o"], "P");
        assert_eq!(value["scope"], 1);
        assert_eq!(value["hour"], 472_222);
        assert_eq!(value["score"], 198);
        assert_eq!(value["w"], 1);

        // A retried decision_id is refused (SET NX).
        let retry = store
            .assess_v2_full(&o, Some("aa"), Some("tls13|http2"), Some(&registration))
            .expect("retry");
        assert!(
            !retry.registration_status,
            "a duplicate decision_id must not overwrite the ledger"
        );
        assert_eq!(retry.existing_context_tag.as_deref(), Some("aa"));
        assert_eq!(retry.existing_tls_tag.as_deref(), Some("tls13|http2"));

        // Changed tags on an established session return the first tags.
        let mut o2 = observation(&event_id(6), 1, T0, 600);
        o2.session_id = Some(session);
        let reply2 = store
            .assess_v2_full(
                &o2,
                Some("bb"),
                Some("tls12|http1"),
                Some(&OutcomeRegistration {
                    decision_id: "dec-cons-2".to_string(),
                    ..registration.clone()
                }),
            )
            .expect("changed tags");
        assert_eq!(
            reply2.existing_context_tag.as_deref(),
            Some("aa"),
            "the first context tag is the baseline"
        );
        assert_eq!(
            reply2.existing_tls_tag.as_deref(),
            Some("tls13|http2"),
            "the first TLS tag is the baseline"
        );
        assert!(reply2.registration_status);

        // The tag records carry the session TTL, exactly like the
        // individual session_first_* record surfaces.
        let session_hex = hex::encode(session);
        let ctx_ttl: i64 = redis::cmd("TTL")
            .arg(format!(
                "{{kiwi:{}}}:risk:ctx:{session_hex}",
                store.namespace()
            ))
            .query(&mut conn)
            .expect("ttl");
        let tls_ttl: i64 = redis::cmd("TTL")
            .arg(format!(
                "{{kiwi:{}}}:risk:tls:{session_hex}",
                store.namespace()
            ))
            .query(&mut conn)
            .expect("ttl");
        assert!((1..=1800).contains(&ctx_ttl));
        assert!((1..=1800).contains(&tls_ttl));
    }

    #[test]
    fn assess_v2_without_registration_skips_the_ledger() {
        let Some(_url) = redis_url() else {
            eprintln!("skipping Redis test: RISK_REDIS_URL not set");
            return;
        };
        let store = store(60_000, "v2assessnr");
        let mut o = observation(&event_id(7), 1, T0, 0);
        o.session_id = Some([0x2f; 16]);
        let reply = store
            .assess_v2_full(&o, Some("aa"), Some("tls13|http2"), None)
            .expect("consolidated assessment");
        assert!(
            !reply.registration_status,
            "without a registration payload no ledger entry is created"
        );
        assert_eq!(
            reply.existing_context_tag.as_deref(),
            Some("aa"),
            "the tag records still apply"
        );
        assert_eq!(reply.observed.vector.source_fast, 125);
        let mut conn = client().get_connection().expect("connection");
        let raw: Option<String> = conn
            .get(store.outcome_ledger_key("dec-missing"))
            .expect("get");
        assert!(raw.is_none());
    }

    #[test]
    fn namespace_accessor() {
        let Some(_url) = redis_url() else {
            eprintln!("skipping Redis test: RISK_REDIS_URL not set");
            return;
        };
        let ns = unique_namespace("deploy");
        let store = RedisRiskStateStore::new(client(), &ns);
        assert_eq!(store.namespace(), ns);
    }

    #[test]
    fn saturations_are_configurable() {
        let Some(_url) = redis_url() else {
            eprintln!("skipping Redis test: RISK_REDIS_URL not set");
            return;
        };
        // Half saturation: 1000 raw -> normalize(1000, 4000) = 250.
        let mut sats = DEFAULT_SATURATIONS;
        sats[0] = 4000;
        let store = RedisRiskStateStore::with_options(
            client(),
            &unique_namespace("sats"),
            1800,
            60,
            60_000,
            1800,
            86_400,
            DEFAULT_OUTCOME_TTL_SECS,
            sats,
        );
        let observed = store.observe(&observation(&event_id(1), 0, T0, 0)).unwrap();
        assert_eq!(observed.vector.source_fast, 250);
    }

    #[test]
    fn principal_credit_is_real() {
        let Some(_url) = redis_url() else {
            eprintln!("skipping Redis test: RISK_REDIS_URL not set");
            return;
        };
        // A principal with AuthenticationSuccess (event 10) builds trust:
        // principal state trust +2000 -> normalize(2000, 10000) = 200.
        let store = store(60_000, "prin");
        let mut o = observation(&event_id(1), 0, T0, 0);
        o.event = RiskEventKind::AuthenticationSuccess;
        o.principal_id = Some([0xEE; 16]);
        let observed = store.observe(&o).unwrap();
        assert_eq!(observed.vector.principal_credit, 200);

        // Without a principal the channel stays zero.
        let mut o2 = observation(&event_id(2), 0, T0, 0);
        o2.event = RiskEventKind::AuthenticationSuccess;
        let observed2 = store.observe(&o2).unwrap();
        assert_eq!(observed2.vector.principal_credit, 0);
    }

    #[test]
    fn epoch_boundary_burst_sums_across_pseudonyms() {
        let Some(_url) = redis_url() else {
            eprintln!("skipping Redis test: RISK_REDIS_URL not set");
            return;
        };
        // Saturations far above the burst so the SUM is visible: 20 * 1000
        // raw -> normalize(20000, 10_000_000) = 2 (a max3 over the two
        // halves would have read 1).
        let mut sats = DEFAULT_SATURATIONS;
        sats[0] = 10_000_000; // src_fast
        sats[1] = 10_000_000; // src_slow
        let store = RedisRiskStateStore::with_options(
            client(),
            &unique_namespace("sum3"),
            1800,
            60,
            60_000,
            1800,
            86_400,
            DEFAULT_OUTCOME_TTL_SECS,
            sats,
        );
        let (epoch, _prev, _cur, next) = epoch_ids("aa");
        // Half 1: 10 events on the current-epoch pseudonym.
        for i in 0..10u64 {
            store.observe(&observation(&event_id(i), 0, T0, 0)).unwrap();
        }
        // Half 2: 10 events one epoch later, whose current pseudonym is the
        // probe's NEXT-epoch boundary key.
        for i in 10..20u64 {
            let mut o = observation(&event_id(i), 0, T0, 0);
            o.source_epoch = epoch + 1;
            o.source_id = next.clone();
            store.observe(&o).unwrap();
        }
        // The probe (current pseudonym, epoch E) reads prev (0) + current
        // (10 events) + next (10 events): the split burst sums to 20 events
        // (20000 raw) instead of maxing to one half.
        let vector = store
            .observe(&observation(&event_id(100), 0, T0, 0))
            .unwrap()
            .vector;
        assert_eq!(vector.source_fast, 2, "sum3 across the rotated epochs");
        assert_eq!(vector.source_slow, 2, "sum3 across the rotated epochs");
    }

    #[test]
    fn principal_reputation_raises_bad_proof_but_not_trust_credit() {
        let Some(_url) = redis_url() else {
            eprintln!("skipping Redis test: RISK_REDIS_URL not set");
            return;
        };
        // Distinct saturations so the principal's higher bad/mal pressure
        // shows through the max4 dimension (source ConfirmedAbuse adds
        // 5000/2500; the principal adds 6000/3000).
        let mut sats = DEFAULT_SATURATIONS;
        sats[3] = 60_000; // bad
        sats[4] = 60_000; // mal
        let store = RedisRiskStateStore::with_options(
            client(),
            &unique_namespace("prinneg"),
            1800,
            60,
            60_000,
            1800,
            86_400,
            DEFAULT_OUTCOME_TTL_SECS,
            sats,
        );

        // ConfirmedAbuse with a principal: bad_proof/malformed take the
        // principal dimension (max over source/session/principal), and no
        // trust exists anywhere.
        let mut o = observation(&event_id(1), 0, T0, 0);
        o.event = RiskEventKind::ConfirmedAbuse;
        o.principal_id = Some([0xEE; 16]);
        let with_principal = store.observe(&o).unwrap().vector;
        assert_eq!(with_principal.bad_proof, 100); // max(src 5000, prin 6000) -> 6000 -> 100
        assert_eq!(with_principal.malformed, 50); // max(src 2500, prin 3000) -> 3000 -> 50
        assert_eq!(with_principal.trust_credit, 0);
        assert_eq!(with_principal.principal_credit, 0);

        // Control without a principal (fresh source pseudonym): only the
        // source's own 5000/2500 remain.
        let mut o2 = observation(&event_id(2), 0, T0, 0);
        o2.event = RiskEventKind::ConfirmedAbuse;
        o2.source_id = hex::encode([0x11; 16]);
        let without = store.observe(&o2).unwrap().vector;
        assert_eq!(without.bad_proof, 83); // 5000 * 1000 / 60000
        assert_eq!(without.malformed, 41); // 2500 * 1000 / 60000

        // trust_credit never includes principal trust (source+session only)
        // while principal_credit is the principal's own trust: the two
        // channels are disjoint (no double subtraction).
        let mut a = observation(&event_id(3), 0, T0, 0);
        a.event = RiskEventKind::AuthenticationSuccess;
        a.principal_id = Some([0xEE; 16]);
        let va = store.observe(&a).unwrap().vector;
        let mut b = observation(&event_id(4), 0, T0, 0);
        b.event = RiskEventKind::AuthenticationSuccess;
        b.source_id = hex::encode([0x22; 16]);
        let vb = store.observe(&b).unwrap().vector;
        assert_eq!(va.principal_credit, 200); // prin trust 2000 / 10000
        assert_eq!(vb.principal_credit, 0);
        assert_eq!(va.trust_credit, 150); // source trust 1500 / 10000
        assert_eq!(vb.trust_credit, 150);
        assert_eq!(
            va.trust_credit, vb.trust_credit,
            "principal trust must not leak into trust_credit"
        );
    }

    #[test]
    fn pool_size_round_robin() {
        let Some(_url) = redis_url() else {
            eprintln!("skipping Redis test: RISK_REDIS_URL not set");
            return;
        };
        let store = RedisRiskStateStore::with_pool_size(client(), &unique_namespace("pool"), 2);
        assert_eq!(store.pool_size(), 2);
        // 10 observations round-robin over the 2-slot pool: all must work.
        for i in 0..10u64 {
            let observed = store.observe(&observation(&event_id(i), 0, T0, 0)).unwrap();
            assert!(!observed.is_duplicate);
        }
        assert_eq!(store.last_global_level(), 0);
    }

    /// The shared cross-language store-configuration vectors
    /// (protocol/risk-v1/fixtures.json -> invalid_store_configuration):
    /// every vector must be rejected by `with_options` (panic), exactly
    /// as the PHP `RedisRiskStateStore` constructor throws for the same
    /// vector. The negative-TTL vector is skipped here because the Rust
    /// knobs are unsigned and cannot represent it; the PHP suite covers
    /// it.
    #[test]
    fn shared_invalid_store_configuration_vectors_are_rejected() {
        let raw = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../protocol/risk-v1/fixtures.json"
        ))
        .expect("the shared fixtures must load");
        let fixtures: serde_json::Value = serde_json::from_str(&raw).expect("valid json");
        let section = fixtures
            .get("invalid_store_configuration")
            .expect("the shared invalid-configuration vectors must exist");
        let defaults = &section["defaults"];
        let default = |key: &str| defaults[key].as_u64().expect("a default");

        for vector in section["vectors"].as_array().expect("vectors") {
            let knob = vector["knob"].as_str().expect("knob");
            let value = vector["value"].as_i64().expect("value");
            if value < 0 {
                continue; // unsigned in Rust; the PHP suite covers the negative vector
            }
            let mut state = default("state_ttl_secs");
            let mut dedupe = default("dedupe_ttl_secs");
            let mut hysteresis = default("hysteresis_ms");
            let mut session = default("session_ttl_secs");
            let mut principal = default("principal_ttl_secs");
            let mut outcome = default("outcome_ttl_secs");
            let mut saturations = DEFAULT_SATURATIONS;
            match knob {
                "state_ttl_secs" => state = value as u64,
                "dedupe_ttl_secs" => dedupe = value as u64,
                "hysteresis_ms" => hysteresis = value as u64,
                "session_ttl_secs" => session = value as u64,
                "principal_ttl_secs" => principal = value as u64,
                "outcome_ttl_secs" => outcome = value as u64,
                "saturation_0" => saturations[0] = value as u32,
                other => panic!("unknown vector knob {other}"),
            }
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                RedisRiskStateStore::with_options(
                    client(),
                    &unique_namespace("inv"),
                    state,
                    dedupe,
                    hysteresis,
                    session,
                    principal,
                    outcome,
                    saturations,
                );
            }));
            assert!(
                result.is_err(),
                "the invalid configuration vector {} ({knob}={value}) must be rejected",
                vector["name"]
            );
        }
    }

    #[test]
    fn policy_decision_round_trip_uses_action_module() {
        // Guards the redis module's dependency surface only.
        assert_eq!(RiskAction::Sha20.rank(), 3);
    }
}
