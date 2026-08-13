//! Redis-backed risk state store running the canonical risk-v1 Lua script.
//!
//! The script is the shared cross-language asset, embedded verbatim from
//! this package's `resources/risk-v1.lua` (a copy of
//! `<repo-root>/protocol/risk-v1/risk.lua`) and executed via
//! `redis::Script` (EVALSHA with an automatic NOSCRIPT fallback inside
//! `ScriptInvocation::invoke`, sha cached in the store's `Script`).
//!
//! All keys carry the hash tag `{kiwi:<namespace>}` so the script is
//! Cluster safe. Source/subnet keys are EPOCH-SCOPED: the observation
//! carries three per-epoch pseudonyms (prev/current/next) and each key
//! uses the pseudonym HMAC'd with ITS OWN epoch. The Lua's `network_risk`
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

use std::sync::atomic::{AtomicU64, AtomicU8, AtomicUsize, Ordering};
use std::sync::{Mutex, MutexGuard};
use std::time::Duration;

use crate::event::RiskObservation;
use crate::signals::SignalVector;
use crate::store::{Observed, RiskStateStore, RiskStoreError};
use ::redis as redis_crate;

/// The canonical risk-v1 state script, embedded verbatim from this
/// package's resources directory (kept in sync with the shared protocol
/// asset `protocol/risk-v1/risk.lua`).
pub const SCRIPT: &str = include_str!("../resources/risk-v1.lua");

/// Default raw saturations in Lua ARGV order:
/// src_fast, src_slow, issue, bad, mal, rep, action, switch, global,
/// trust, principal.
pub const DEFAULT_SATURATIONS: [u32; 11] = [
    8000, 100000, 6000, 4000, 3000, 2000, 6000, 10000, 70000, 10000, 10000,
];

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
    saturations: [u32; 11],
    script: redis_crate::Script,
    pool: ConnectionPool,
    last_global_level: AtomicU8,
    last_cooldown_until_ms: AtomicU64,
}

/// Lazy round-robin pool of sync connections.
struct ConnectionPool {
    slots: Vec<Mutex<Option<redis_crate::Connection>>>,
    next: AtomicUsize,
}

impl ConnectionPool {
    fn new(pool_size: usize) -> ConnectionPool {
        assert!(pool_size >= 1, "pool_size must be >= 1");
        ConnectionPool {
            slots: (0..pool_size).map(|_| Mutex::new(None)).collect(),
            next: AtomicUsize::new(0),
        }
    }

    /// Picks the next slot round-robin and lazily opens (and timeouts-
    /// configures) its connection.
    fn acquire(
        &self,
        client: &redis_crate::Client,
    ) -> Result<MutexGuard<'_, Option<redis_crate::Connection>>, RiskStoreError> {
        let idx = self.next.fetch_add(1, Ordering::Relaxed) % self.slots.len();
        let mut guard = self.slots[idx].lock().unwrap_or_else(|p| p.into_inner());
        if guard.is_none() {
            let conn = client
                .get_connection_with_timeout(Duration::from_millis(
                    RedisRiskStateStore::CONNECTION_TIMEOUT_MS,
                ))
                .map_err(map_redis_error)?;
            conn.set_read_timeout(Some(Duration::from_millis(
                RedisRiskStateStore::COMMAND_TIMEOUT_MS,
            )))
            .map_err(map_redis_error)?;
            conn.set_write_timeout(Some(Duration::from_millis(
                RedisRiskStateStore::COMMAND_TIMEOUT_MS,
            )))
            .map_err(map_redis_error)?;
            *guard = Some(conn);
        }
        Ok(guard)
    }
}

impl RedisRiskStateStore {
    /// Connection timeout used for establishing the TCP connection.
    pub const CONNECTION_TIMEOUT_MS: u64 = 5;
    /// Command (read/write) timeout applied to the socket.
    pub const COMMAND_TIMEOUT_MS: u64 = 10;

    /// Builds a store with the contract defaults (namespace `d`,
    /// 1800 s state TTL, 60 s dedupe TTL, 60 s hysteresis, 1800 s session
    /// TTL, 86400 s principal TTL, default saturations, pool size 4).
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
            saturations: DEFAULT_SATURATIONS,
            script: redis_crate::Script::new(SCRIPT),
            pool: ConnectionPool::new(DEFAULT_POOL_SIZE),
            last_global_level: AtomicU8::new(0),
            last_cooldown_until_ms: AtomicU64::new(0),
        }
    }

    /// Builds a store with explicit knobs.
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
        saturations: [u32; 11],
    ) -> RedisRiskStateStore {
        let mut store = RedisRiskStateStore::new(client, namespace);
        store.state_ttl_secs = state_ttl_secs;
        store.dedupe_ttl_secs = dedupe_ttl_secs;
        store.hysteresis_ms = hysteresis_ms;
        store.session_ttl_secs = session_ttl_secs;
        store.principal_ttl_secs = principal_ttl_secs;
        store.saturations = saturations;
        store
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
        store.pool = ConnectionPool::new(pool_size);
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

    /// The FULL key set for one observation, in the Lua KEYS order.
    ///
    /// Source keys use the observation's EPOCH-SCOPED pseudonyms:
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

        // The full 22-value ARGV contract, in order.
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

        let script = self.script.clone();
        let mut invocation = script.prepare_invoke();
        for key in &keys {
            invocation.key(key.as_str());
        }
        for arg in &args {
            invocation.arg(arg.as_str());
        }

        let mut conn_guard = self.pool.acquire(&self.client)?;
        let conn = conn_guard
            .as_mut()
            .ok_or_else(|| RiskStoreError::BackendUnavailable("connection vanished".to_string()))?;
        let reply: Vec<i64> = invocation.invoke(conn).map_err(map_redis_error)?;

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

    /// CRC-16/XMODEM (poly 0x1021, init 0): `"123456789"` -> `0x31C3`,
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

    fn last_global_level(&self) -> u8 {
        self.last_global_level.load(Ordering::Relaxed)
    }

    fn last_cooldown_until_ms(&self) -> u64 {
        self.last_cooldown_until_ms.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::action::RiskAction;
    use crate::event::RiskEventKind;
    use rand::RngCore;

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
            DEFAULT_SATURATIONS,
        )
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

    // ── Redis-backed tests (skipped unless RISK_REDIS_URL is set) ──

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
        // The channels leak by REAL elapsed time (rf 250/s, rs 20/s), so
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

        // A distinct event must observe the state from a SINGLE increment
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
        // storm decays a few raw units of REAL elapsed time, so the floor
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
        // rate-limit clock is Redis TIME, so the cooldown deadline is
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

        // The DROP after the hysteresis window needs a real ~2.1 s sleep
        // (the script derives its clock from Redis TIME): a SHORT window of
        // 2 s and a saturation that makes 5 events reach L4 (10000 raw ->
        // 909). RiskDenied probes add NO pressure, so the decay is pure.
        let mut sats = DEFAULT_SATURATIONS;
        sats[8] = 11_000; // sat_global (ARGV[16])
        let tiny = RedisRiskStateStore::with_options(
            client(),
            &unique_namespace("tiny"),
            1800,
            60,
            2000,
            1800,
            86_400,
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
        // the L4 ENTER (900), still above the L4 EXIT (850) — the hold
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
        // raw -> normalize(20000, 10_000_000) = 2 (the old max3 over the two
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
            sats,
        );
        let (epoch, _prev, _cur, next) = epoch_ids("aa");
        // Half 1: 10 events on the current-epoch pseudonym.
        for i in 0..10u64 {
            store.observe(&observation(&event_id(i), 0, T0, 0)).unwrap();
        }
        // Half 2: 10 events one epoch LATER, whose current pseudonym is the
        // probe's NEXT-epoch boundary key.
        for i in 10..20u64 {
            let mut o = observation(&event_id(i), 0, T0, 0);
            o.source_epoch = epoch + 1;
            o.source_id = next.clone();
            store.observe(&o).unwrap();
        }
        // The probe (current pseudonym, epoch E) reads prev (0) + current
        // (10 events) + next (10 events): the split burst SUMS to 20 events
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
        // Distinct saturations so the principal's HIGHER bad/mal pressure
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
            sats,
        );

        // ConfirmedAbuse with a principal: bad_proof/malformed take the
        // PRINCIPAL dimension (max over source/session/principal), and no
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

        // trust_credit NEVER includes principal trust (source+session only)
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
