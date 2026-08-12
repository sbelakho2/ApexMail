//! Redis-backed risk state store running the canonical risk-v1 Lua script.
//!
//! The script is the shared cross-language asset at
//! `<repo-root>/protocol/risk-v1/risk.lua`, embedded verbatim and executed
//! via `redis::Script` (EVALSHA with an automatic NOSCRIPT fallback inside
//! `ScriptInvocation::invoke`).
//!
//! All keys carry the hash tag `{kiwi:<namespace>}` so the script is
//! Cluster safe. The Lua's `network_risk` slot (always 0) is overridden
//! with the observation's classifier-derived network risk;
//! `principal_credit` (0, reserved) is passed through.
//!
//! Timeouts: the sync `redis` crate has no `ConnectionConfig`/response
//! timeout (that is the async API); the equivalent sync settings are
//! `Client::get_connection_with_timeout` (connection, 5 ms) and
//! `Connection::set_read_timeout`/`set_write_timeout` (command, 10 ms),
//! applied on the first connection and documented here as best-effort
//! fail-fast values.

use std::sync::atomic::{AtomicU64, AtomicU8, Ordering};
use std::sync::Mutex;
use std::time::Duration;

use crate::event::RiskObservation;
use crate::signals::SignalVector;
use crate::store::{RiskStateStore, RiskStoreError};
use ::redis as redis_crate;

/// The canonical risk-v1 state script, embedded verbatim from the shared
/// protocol directory (repo root `protocol/risk-v1/risk.lua`).
pub const SCRIPT: &str = include_str!("../../../protocol/risk-v1/risk.lua");

/// Default raw saturations in Lua ARGV order:
/// src_fast, src_slow, issue, bad, mal, rep, action, switch, global, trust.
pub const DEFAULT_SATURATIONS: [u32; 10] = [
    8000, 100000, 6000, 4000, 3000, 2000, 6000, 10000, 70000, 10000,
];

/// The full reply of one script run: the signal vector plus the global
/// pressure level and cooldown deadline tracked by the script.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Observed {
    pub vector: SignalVector,
    pub global_level: u8,
    pub cooldown_until_ms: u64,
}

/// Redis-backed [`RiskStateStore`].
pub struct RedisRiskStateStore {
    client: redis_crate::Client,
    namespace: String,
    source_epoch_secs: u64,
    subnet_epoch_secs: u64,
    state_ttl_secs: u64,
    dedupe_ttl_secs: u64,
    hysteresis_ms: u64,
    saturations: [u32; 10],
    script: redis::Script,
    conn: Mutex<Option<redis_crate::Connection>>,
    last_global_level: AtomicU8,
    last_cooldown_until_ms: AtomicU64,
}

impl RedisRiskStateStore {
    /// Connection timeout used for establishing the TCP connection.
    pub const CONNECTION_TIMEOUT_MS: u64 = 5;
    /// Command (read/write) timeout applied to the socket.
    pub const COMMAND_TIMEOUT_MS: u64 = 10;

    /// Builds a store with the contract defaults (namespace `d`,
    /// 900 s epochs, 1800 s state TTL, 60 s dedupe TTL, 60 s hysteresis).
    ///
    /// # Panics
    ///
    /// Panics if the namespace is empty or contains `{`/`}` (the hash tag
    /// would be malformed), mirroring the PHP constructor's
    /// `InvalidArgumentException`.
    pub fn new(client: redis_crate::Client, namespace: &str) -> RedisRiskStateStore {
        assert!(
            !namespace.is_empty() && !namespace.contains(['{', '}']),
            "Risk namespace must be non-empty and free of braces"
        );
        RedisRiskStateStore {
            client,
            namespace: namespace.to_string(),
            source_epoch_secs: 900,
            subnet_epoch_secs: 900,
            state_ttl_secs: 1800,
            dedupe_ttl_secs: 60,
            hysteresis_ms: 60_000,
            saturations: DEFAULT_SATURATIONS,
            script: redis_crate::Script::new(SCRIPT),
            conn: Mutex::new(None),
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
        source_epoch_secs: u64,
        subnet_epoch_secs: u64,
        state_ttl_secs: u64,
        dedupe_ttl_secs: u64,
        hysteresis_ms: u64,
        saturations: [u32; 10],
    ) -> RedisRiskStateStore {
        let mut store = RedisRiskStateStore::new(client, namespace);
        store.source_epoch_secs = source_epoch_secs;
        store.subnet_epoch_secs = subnet_epoch_secs;
        store.state_ttl_secs = state_ttl_secs;
        store.dedupe_ttl_secs = dedupe_ttl_secs;
        store.hysteresis_ms = hysteresis_ms;
        store.saturations = saturations;
        store
    }

    /// The deployment namespace inside the `{kiwi:<ns>}` hash tag.
    pub fn namespace(&self) -> &str {
        &self.namespace
    }

    /// The FULL key set for one observation, in the Lua KEYS order
    /// (source ±1, subnet ±1, session, principal, global, dedupe).
    ///
    /// All keys share the `{kiwi:<namespace>}` hash tag so the script is
    /// Cluster safe. `session_id`/`principal_id` are hex-encoded;
    /// `None` maps to the contract's all-zero placeholder. Public so tests
    /// (and tooling) can build and inspect the exact key layout.
    #[allow(clippy::too_many_arguments)]
    pub fn keys_for(
        namespace: &str,
        src_epoch: u64,
        net_epoch: u64,
        source_id: &[u8],
        subnet_id: &[u8],
        session_id: Option<&[u8]>,
        principal_id: Option<&[u8]>,
        event_id: &[u8],
    ) -> Vec<String> {
        let tag = format!("{{kiwi:{namespace}}}");
        let source_id = hex::encode(source_id);
        let subnet_id = hex::encode(subnet_id);
        let session_id = session_id
            .map(hex::encode)
            .unwrap_or_else(|| "0".repeat(32));
        let principal_id = principal_id
            .map(hex::encode)
            .unwrap_or_else(|| "0".repeat(32));
        let event_id = hex::encode(event_id);

        vec![
            format!("{tag}:risk:src:{src_epoch}:{source_id}"),
            format!("{tag}:risk:src:{}:{source_id}", src_epoch - 1),
            format!("{tag}:risk:src:{}:{source_id}", src_epoch + 1),
            format!("{tag}:risk:net:{net_epoch}:{subnet_id}"),
            format!("{tag}:risk:net:{}:{subnet_id}", net_epoch - 1),
            format!("{tag}:risk:net:{}:{subnet_id}", net_epoch + 1),
            format!("{tag}:risk:session:{session_id}"),
            format!("{tag}:risk:principal:{principal_id}"),
            format!("{tag}:risk:global"),
            format!("{tag}:risk:dedupe:{event_id}"),
        ]
    }

    /// Applies the observation and returns the full script reply
    /// (vector + global level + cooldown deadline).
    pub fn observe_full(&self, o: &RiskObservation) -> Result<Observed, RiskStoreError> {
        let now_ms = o.now_ms;
        let now_secs = now_ms / 1000;
        let src_epoch = now_secs / self.source_epoch_secs;
        let net_epoch = now_secs / self.subnet_epoch_secs;

        let keys = Self::keys_for(
            &self.namespace,
            src_epoch,
            net_epoch,
            &o.source_id,
            &o.subnet_id,
            o.session_id.as_ref().map(|v| v.as_slice()),
            o.principal_id.as_ref().map(|v| v.as_slice()),
            &o.event_id,
        );
        Self::assert_same_slot(&keys)?;

        let args: Vec<String> = vec![
            o.event.as_u8().to_string(),
            o.scope.to_string(),
            now_ms.to_string(),
            hex::encode(o.event_id),
            self.dedupe_ttl_secs.to_string(),
            self.state_ttl_secs.to_string(),
            self.hysteresis_ms.to_string(),
            self.saturations[0].to_string(),
            self.saturations[1].to_string(),
            self.saturations[2].to_string(),
            self.saturations[3].to_string(),
            self.saturations[4].to_string(),
            self.saturations[5].to_string(),
            self.saturations[6].to_string(),
            self.saturations[7].to_string(),
            self.saturations[8].to_string(),
            self.saturations[9].to_string(),
        ];

        let script = self.script.clone();
        let mut invocation = script.prepare_invoke();
        for key in &keys {
            invocation.key(key.as_str());
        }
        for arg in &args {
            invocation.arg(arg.as_str());
        }

        let mut conn_guard = self.connection()?;
        let conn = conn_guard
            .as_mut()
            .ok_or_else(|| RiskStoreError::BackendUnavailable("connection vanished".to_string()))?;
        let reply: Vec<i64> = invocation.invoke(conn).map_err(map_redis_error)?;

        if reply.len() == 1 && reply[0] == -1 {
            return Err(RiskStoreError::DuplicateEvent);
        }
        if reply.len() < 15 {
            return Err(RiskStoreError::ScriptError(format!(
                "risk script returned an unexpected payload ({} values)",
                reply.len()
            )));
        }

        let global_level = reply[13] as u8;
        let cooldown_until_ms = reply[14] as u64;
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
                principal_credit: 0,
            },
            global_level,
            cooldown_until_ms,
        })
    }

    /// Lazily opens (and timeouts-configured) the single sync connection.
    fn connection(
        &self,
    ) -> Result<std::sync::MutexGuard<'_, Option<redis_crate::Connection>>, RiskStoreError> {
        let mut guard = self.conn.lock().unwrap_or_else(|p| p.into_inner());
        if guard.is_none() {
            let conn = self
                .client
                .get_connection_with_timeout(Duration::from_millis(Self::CONNECTION_TIMEOUT_MS))
                .map_err(map_redis_error)?;
            conn.set_read_timeout(Some(Duration::from_millis(Self::COMMAND_TIMEOUT_MS)))
                .map_err(map_redis_error)?;
            conn.set_write_timeout(Some(Duration::from_millis(Self::COMMAND_TIMEOUT_MS)))
                .map_err(map_redis_error)?;
            *guard = Some(conn);
        }
        Ok(guard)
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
    fn observe(&self, o: &RiskObservation) -> Result<SignalVector, RiskStoreError> {
        Ok(self.observe_full(o)?.vector)
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
            900,
            900,
            1800,
            60,
            hysteresis_ms,
            DEFAULT_SATURATIONS,
        )
    }

    fn observation(
        event_id: &[u8; 16],
        scope: u16,
        now_ms: u64,
        network_risk: u16,
    ) -> RiskObservation {
        RiskObservation {
            event: RiskEventKind::PreIssue,
            scope,
            source_id: [0xAA; 16],
            subnet_id: [0xBB; 16],
            session_id: None,
            principal_id: None,
            event_id: *event_id,
            network_risk,
            now_ms,
        }
    }

    fn event_id(n: u64) -> [u8; 16] {
        let mut out = [0u8; 16];
        out[..8].copy_from_slice(&n.to_be_bytes());
        out
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
        let epoch = (T0 / 1000) / 900;
        let source = "a".repeat(32);
        let subnet = "b".repeat(32);
        let keys = vec![
            format!("{tag}:risk:src:{epoch}:{source}"),
            format!("{tag}:risk:src:{}:{source}", epoch - 1),
            format!("{tag}:risk:src:{}:{source}", epoch + 1),
            format!("{tag}:risk:net:{epoch}:{subnet}"),
            format!("{tag}:risk:net:{}:{subnet}", epoch - 1),
            format!("{tag}:risk:net:{}:{subnet}", epoch + 1),
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
        let vector = store.observe(&observation(&event_id(1), 0, T0, 0)).unwrap();
        assert_eq!(vector.source_fast, 125); // 1000*1000/8000
        assert_eq!(vector.source_slow, 10); // 1000*1000/100000
        assert_eq!(vector.subnet_fast, 125);
        assert_eq!(vector.issue_debt, 0);
        assert_eq!(vector.global_pressure, 28); // 2000*1000/70000
        assert_eq!(vector.network_risk, 0); // classifier side-channel override
        assert_eq!(vector.principal_credit, 0); // reserved
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
        assert_eq!(first.source_fast, 125);

        // Same event_id again: duplicate, state untouched.
        let duplicate = store.observe(&observation(&id, 0, T0, 0));
        assert_eq!(duplicate.unwrap_err(), RiskStoreError::DuplicateEvent);

        // A distinct event must observe the state from a SINGLE increment.
        let third = store.observe(&observation(&event_id(8), 0, T0, 0)).unwrap();
        assert_eq!(third.source_fast, 250);
        assert_eq!(third.source_slow, 20);
    }

    #[test]
    fn network_risk_override_slot() {
        let Some(_url) = redis_url() else {
            eprintln!("skipping Redis test: RISK_REDIS_URL not set");
            return;
        };
        let store = store(60_000, "nrisk");
        let vector = store
            .observe(&observation(&event_id(3), 0, T0, 600))
            .unwrap();
        assert_eq!(vector.network_risk, 600);
        assert_eq!(vector.principal_credit, 0);
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
            vector = store.observe(&observation(&event_id(i), 0, T0, 0)).unwrap();
        }
        assert_eq!(vector.source_fast, 1000);
        assert_eq!(vector.source_slow, 1000);
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

        // Normalized global thresholds: L1 >= 300, L2 >= 550, L3 >= 750,
        // L4 >= 900 (raw gp scaled by sat_global 70000). Each PreIssue adds
        // 2000 raw (rf 1000 + rs 1000): 20 events -> gp 40000 -> 571 (L2);
        // 32 events -> gp 64000 -> 914 (L4). Leak: rf 250/s, rs 20/s.
        let big = store(60_000, "big");
        for i in 1..=20u64 {
            big.observe(&observation(&event_id(i), 2, T0, 0)).unwrap();
        }
        assert_eq!(big.last_global_level(), 2, "20 events must reach level 2");
        for i in 21..=32u64 {
            big.observe(&observation(&event_id(i), 2, T0, 0)).unwrap();
        }
        assert_eq!(big.last_global_level(), 4, "32 events must reach level 4");
        assert_eq!(big.last_cooldown_until_ms(), T0 + 60_000);

        // t0+61s: rf 32000 - 15250 = 16750; rs 32000 - 1220 = 30780;
        // gp 49530 -> 707 -> target L2 (< L4). The window has passed, so the
        // level drops to the target (hysteresis hold expired).
        big.observe(&observation(&event_id(33), 2, T0 + 61_000, 0))
            .unwrap();
        assert_eq!(
            big.last_global_level(),
            2,
            "level must drop to the target after the hysteresis window"
        );
        assert_eq!(big.last_cooldown_until_ms(), 0);

        // A 50 ms window leaves as soon as the window passes.
        let tiny = store(50, "tiny");
        for i in 1..=32u64 {
            tiny.observe(&observation(&event_id(i), 2, T0, 0)).unwrap();
        }
        assert_eq!(tiny.last_global_level(), 4);
        // After 100ms the pressure decays below the L4 exit threshold (850):
        // rf 32000 - 25 = 31975; rs 32000 - 2 = 31998 -> gp 63973 -> 913 —
        // still >= 900, so the level stays 4 until the window passes.
        tiny.observe(&observation(&event_id(33), 2, T0 + 100, 0))
            .unwrap();
        assert_eq!(
            tiny.last_global_level(),
            4,
            "level holds inside the 50ms window"
        );
        // The cooldown was armed by the FIRST event's ratchet (T0+50) and
        // only re-arms on a level RISE — at level 4 with the target still 4
        // the arm stays at its first value.
        assert_eq!(tiny.last_cooldown_until_ms(), T0 + 50);
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
            900,
            900,
            1800,
            60,
            60_000,
            sats,
        );
        let vector = store.observe(&observation(&event_id(1), 0, T0, 0)).unwrap();
        assert_eq!(vector.source_fast, 250);
    }

    #[test]
    fn policy_decision_round_trip_uses_action_module() {
        // Guards the redis module's dependency surface only.
        assert_eq!(RiskAction::Sha20.rank(), 3);
    }
}
