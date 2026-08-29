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
//! `Client::get_connection_with_timeout` (connection, 5 ms) and
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

/// Default number of pooled Redis connections.
pub const DEFAULT_POOL_SIZE: usize = 4;

/// Redis-backed [`RiskStateStore`].
pub struct RedisRiskStateStore {
    client: redis_crate::Client,
    namespace: String,
    state_ttl_secs: u64,
    dedupe_ttl_secs: u64,
    hysteresis_ms: u64,
    session_ttl_secs: u64,
    principal_ttl_secs: u64,
    outcome_ttl_secs: u64,
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
    pool: ConnectionPool,
    connection_timeout_ms: u64,
    command_timeout_ms: u64,
    last_global_level: AtomicU8,
    last_cooldown_until_ms: AtomicU64,
}

/// Lazy round-robin pool of sync connections.
struct ConnectionPool {
    slots: Vec<Mutex<Option<redis_crate::Connection>>>,
    next: AtomicUsize,
    connection_timeout_ms: u64,
    command_timeout_ms: u64,
}

impl ConnectionPool {
    fn new(
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
    fn acquire(
        &self,
        client: &redis_crate::Client,
    ) -> Result<MutexGuard<'_, Option<redis_crate::Connection>>, RiskStoreError> {
        let idx = self.next.fetch_add(1, Ordering::Relaxed) % self.slots.len();
        let mut guard = self.slots[idx].lock().unwrap_or_else(|p| p.into_inner());
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
    fn with_connection<T>(
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
    /// Connection timeout used for establishing the TCP connection.
    pub const CONNECTION_TIMEOUT_MS: u64 = 5;
    /// Command (read/write) timeout applied to the socket.
    pub const COMMAND_TIMEOUT_MS: u64 = 10;

    /// Builds a store with the contract defaults (namespace `d`,
    /// 1800 s state TTL, 60 s dedupe TTL, 60 s hysteresis, 1800 s session
    /// TTL, 86400 s principal TTL, 86400 s outcome-ledger TTL, default
    /// saturations, pool size 4).
    ///
    /// # Panics
    ///
    /// Panics if the namespace is empty or contains `{`/`}` (the hash tag
    /// would be malformed), mirroring the PHP constructor's
    /// `InvalidArgumentException`.
    pub fn new(client: redis_crate::Client, namespace: &str) -> RedisRiskStateStore {
        RedisRiskStateStore {
            client,
            namespace: namespace.to_string(),
            state_ttl_secs: 1800,
            dedupe_ttl_secs: 60,
            hysteresis_ms: 60_000,
            session_ttl_secs: 1800,
            principal_ttl_secs: 86_400,
            outcome_ttl_secs: DEFAULT_OUTCOME_TTL_SECS,
            saturations: DEFAULT_SATURATIONS,
            script: Arc::new(redis_crate::Script::new(SCRIPT)),
            assess_v2_script: Arc::new(redis_crate::Script::new(ASSESS_V2_LUA)),
            outcome_register_script: Arc::new(redis_crate::Script::new(OUTCOME_REGISTER_LUA)),
            outcome_confirm_script: Arc::new(redis_crate::Script::new(OUTCOME_CONFIRM_LUA)),
            outcome_correct_script: Arc::new(redis_crate::Script::new(OUTCOME_CORRECT_LUA)),
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
    /// production fail-fast consts (5 ms / 10 ms) stay the defaults; tests
    /// exercising long real-time sequences (storms, TTL expiry) use
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

    /// The deployment namespace inside the `{kiwi:<ns>}` hash tag.
    pub fn namespace(&self) -> &str {
        &self.namespace
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
    #[allow(clippy::too_many_arguments)]
    pub fn keys_for(
        namespace: &str,
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
        let tag = format!("{{kiwi:{namespace}}}");
        let session_id = session_id
            .map(hex::encode)
            .unwrap_or_else(|| "0".repeat(32));
        let principal_id = principal_id
            .map(hex::encode)
            .unwrap_or_else(|| "0".repeat(32));

        vec![
            format!("{tag}:risk:src:{source_epoch}:{source_id}"),
            format!("{tag}:risk:src:{}:{source_id_prev}", source_epoch - 1),
            format!("{tag}:risk:src:{}:{source_id_next}", source_epoch + 1),
            format!("{tag}:risk:net:{subnet_epoch}:{subnet_id}"),
            format!("{tag}:risk:net:{}:{subnet_id_prev}", subnet_epoch - 1),
            format!("{tag}:risk:net:{}:{subnet_id_next}", subnet_epoch + 1),
            format!("{tag}:risk:session:{session_id}"),
            format!("{tag}:risk:principal:{principal_id}"),
            format!("{tag}:risk:global"),
            format!("{tag}:risk:dedupe:{event_id}"),
        ]
    }

    /// Applies the observation and returns the full script reply
    /// (vector + global level + cooldown deadline + dedupe verdict).
    pub fn observe_full(&self, o: &RiskObservation) -> Result<Observed, RiskStoreError> {
        let now_ms = o.now_ms;

        let keys = Self::keys_for(
            &self.namespace,
            o.source_epoch,
            &o.source_id_prev,
            &o.source_id,
            &o.source_id_next,
            o.subnet_epoch,
            &o.subnet_id_prev,
            &o.subnet_id,
            &o.subnet_id_next,
            o.session_id.as_ref().map(|v| v.as_slice()),
            o.principal_id.as_ref().map(|v| v.as_slice()),
            &o.event_id,
        );
        Self::assert_same_slot(&keys)?;

        // The full 22-value argv contract, in order.
        let mut args: Vec<String> = Vec::with_capacity(22);
        args.push(o.event.as_u8().to_string());
        args.push(o.scope.to_string());
        args.push(now_ms.to_string());
        args.push(o.event_id.clone());
        args.push(self.dedupe_ttl_secs.to_string());
        args.push(self.state_ttl_secs.to_string());
        args.push(self.hysteresis_ms.to_string());
        args.extend(self.saturations.iter().map(|s| s.to_string()));
        args.push((if o.session_id.is_some() { "1" } else { "0" }).to_string());
        args.push((if o.principal_id.is_some() { "1" } else { "0" }).to_string());
        args.push(self.session_ttl_secs.to_string());
        args.push(self.principal_ttl_secs.to_string());

        // The script handle is borrowed through the Arc (no per-assessment
        // source clone); the invocation is configured with this call's keys
        // and argv, then run on the next pool slot. A failed invocation
        // evicts the slot (see ConnectionPool::with_connection).
        let mut invocation = self.script.prepare_invoke();
        for key in &keys {
            invocation.key(key.as_str());
        }
        for arg in &args {
            invocation.arg(arg.as_str());
        }

        let reply: Vec<i64> = self
            .pool
            .with_connection(&self.client, |conn| invocation.invoke(conn))?;

        if reply.len() < 16 {
            return Err(RiskStoreError::ScriptError(format!(
                "risk script returned an unexpected payload ({} values)",
                reply.len()
            )));
        }

        let global_level = reply[13] as u8;
        let cooldown_until_ms = reply[14] as u64;
        let is_duplicate = reply[15] != 0;
        self.last_global_level
            .store(global_level, Ordering::Relaxed);
        self.last_cooldown_until_ms
            .store(cooldown_until_ms, Ordering::Relaxed);

        Ok(Observed {
            vector: SignalVector {
                source_fast: reply[0] as u16,
                source_slow: reply[1] as u16,
                subnet_fast: reply[2] as u16,
                issue_debt: reply[3] as u16,
                bad_proof: reply[4] as u16,
                malformed: reply[5] as u16,
                replay: reply[6] as u16,
                action_failure: reply[7] as u16,
                scope_switch: reply[8] as u16,
                global_pressure: reply[9] as u16,
                network_risk: o.network_risk,
                trust_credit: reply[11] as u16,
                principal_credit: reply[12] as u16,
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
        let now_ms = o.now_ms;

        let mut keys = Self::keys_for(
            &self.namespace,
            o.source_epoch,
            &o.source_id_prev,
            &o.source_id,
            &o.source_id_next,
            o.subnet_epoch,
            &o.subnet_id_prev,
            &o.subnet_id,
            &o.subnet_id_next,
            o.session_id.as_ref().map(|v| v.as_slice()),
            o.principal_id.as_ref().map(|v| v.as_slice()),
            &o.event_id,
        );
        let session_hex = o
            .session_id
            .map(hex::encode)
            .unwrap_or_else(|| "0".repeat(32));
        keys.push(format!(
            "{{kiwi:{}}}:risk:ctx:{session_hex}",
            self.namespace
        ));
        keys.push(format!(
            "{{kiwi:{}}}:risk:tls:{session_hex}",
            self.namespace
        ));
        if let Some(reg) = registration {
            keys.push(self.outcome_ledger_key(&reg.decision_id));
        }
        Self::assert_same_slot(&keys)?;

        // The full argv contract: the 22 v1 values + the two presented
        // tags + the 23 registration values (ARGV[25..47]).
        let mut args: Vec<String> = Vec::with_capacity(47);
        args.push(o.event.as_u8().to_string());
        args.push(o.scope.to_string());
        args.push(now_ms.to_string());
        args.push(o.event_id.clone());
        args.push(self.dedupe_ttl_secs.to_string());
        args.push(self.state_ttl_secs.to_string());
        args.push(self.hysteresis_ms.to_string());
        args.extend(self.saturations.iter().map(|s| s.to_string()));
        args.push((if o.session_id.is_some() { "1" } else { "0" }).to_string());
        args.push((if o.principal_id.is_some() { "1" } else { "0" }).to_string());
        args.push(self.session_ttl_secs.to_string());
        args.push(self.principal_ttl_secs.to_string());
        args.push(context_tag.unwrap_or("").to_string());
        args.push(tls_tag.unwrap_or("").to_string());
        match registration {
            Some(reg) => {
                args.push(reg.decision_id.clone());
                args.push(reg.decision_hour.to_string());
                args.push(self.outcome_ttl_secs.to_string());
                args.push(o.network_risk.to_string());
                args.push(
                    (if reg.global_pressure_enabled {
                        "1"
                    } else {
                        "0"
                    })
                    .to_string(),
                );
                args.push(reg.base_risk.to_string());
                args.push((if reg.honeypot_hit { "1" } else { "0" }).to_string());
                let w = &reg.v1_weights;
                args.extend(
                    [
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
                    ]
                    .iter()
                    .map(u16::to_string),
                );
                let w2 = &reg.v2_weights;
                args.extend(
                    [w2.honeypot, w2.session_inconsistency, w2.tls]
                        .iter()
                        .map(u16::to_string),
                );
            }
            None => {
                args.push(String::new());
                args.extend((0..22).map(|_| "0".to_string()));
            }
        }

        let mut invocation = self.assess_v2_script.prepare_invoke();
        for key in &keys {
            invocation.key(key.as_str());
        }
        for arg in &args {
            invocation.arg(arg.as_str());
        }

        let reply: Vec<redis_crate::Value> = self
            .pool
            .with_connection(&self.client, |conn| invocation.invoke(conn))?;

        if reply.len() < 19 {
            return Err(RiskStoreError::ScriptError(format!(
                "risk script returned an unexpected payload ({} values)",
                reply.len()
            )));
        }

        let value_i64 = |v: &redis_crate::Value| -> i64 {
            match v {
                redis_crate::Value::Int(i) => *i,
                redis_crate::Value::BulkString(b) => std::str::from_utf8(b)
                    .ok()
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(0),
                _ => 0,
            }
        };
        let value_string = |v: &redis_crate::Value| -> String {
            match v {
                redis_crate::Value::BulkString(b) => String::from_utf8_lossy(b).into_owned(),
                redis_crate::Value::Int(i) => i.to_string(),
                _ => String::new(),
            }
        };

        let global_level = value_i64(&reply[13]) as u8;
        let cooldown_until_ms = value_i64(&reply[14]) as u64;
        let is_duplicate = value_i64(&reply[15]) != 0;
        self.last_global_level
            .store(global_level, Ordering::Relaxed);
        self.last_cooldown_until_ms
            .store(cooldown_until_ms, Ordering::Relaxed);

        let existing_context_tag = value_string(&reply[16]);
        let existing_tls_tag = value_string(&reply[17]);
        let registration_status = value_i64(&reply[18]) != 0;

        Ok(AssessV2Reply {
            observed: Observed {
                vector: SignalVector {
                    source_fast: value_i64(&reply[0]) as u16,
                    source_slow: value_i64(&reply[1]) as u16,
                    subnet_fast: value_i64(&reply[2]) as u16,
                    issue_debt: value_i64(&reply[3]) as u16,
                    bad_proof: value_i64(&reply[4]) as u16,
                    malformed: value_i64(&reply[5]) as u16,
                    replay: value_i64(&reply[6]) as u16,
                    action_failure: value_i64(&reply[7]) as u16,
                    scope_switch: value_i64(&reply[8]) as u16,
                    global_pressure: value_i64(&reply[9]) as u16,
                    network_risk: o.network_risk,
                    trust_credit: value_i64(&reply[11]) as u16,
                    principal_credit: value_i64(&reply[12]) as u16,
                },
                global_level,
                cooldown_until_ms,
                is_duplicate,
            },
            existing_context_tag: (!existing_context_tag.is_empty())
                .then_some(existing_context_tag),
            existing_tls_tag: (!existing_tls_tag.is_empty()).then_some(existing_tls_tag),
            registration_status,
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

fn map_redis_error(e: redis_crate::RedisError) -> RiskStoreError {
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
        let ttl: i64 = self.session_ttl_secs.try_into().unwrap_or(i64::MAX);
        let created_key = key.to_string();
        let existing_key = key.to_string();
        let tag = tag.to_string();
        self.pool.with_connection(&self.client, |conn| {
            let created: bool = conn.set_nx(created_key.clone(), tag.as_str())?;
            if created {
                conn.expire::<_, ()>(created_key, ttl)?;
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
        (
            epoch,
            format!("{source}00"),
            format!("{source}11"),
            format!("{source}22"),
        )
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

        // A pending entry can be corrected too (never confirmed yet).
        assert!(store.register_outcome("led-2", 7, hour, 100).unwrap());
        assert!(store.correct_outcome("led-2", false).unwrap());
        let raw: String = conn.get(store.outcome_ledger_key("led-2")).expect("get");
        let value: serde_json::Value = serde_json::from_str(&raw).expect("json");
        assert_eq!(value["o"], "A");
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

    #[test]
    fn policy_decision_round_trip_uses_action_module() {
        // Guards the redis module's dependency surface only.
        assert_eq!(RiskAction::Sha20.rank(), 3);
    }
}
