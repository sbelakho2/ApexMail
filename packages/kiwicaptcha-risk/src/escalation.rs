//! Decoy escalation (change.md 3.2.2): the additive post-marks
//! decision stage that raises a session's price by one rung for the
//! escalation window after a confirmed decoy hit, plus the reader seam
//! the engine wires the stage through. The evidence stage composes
//! right after it, so the two raises stack before the pricing stage.
//!
//! An escalation, never a block: the raise caps at the interactive
//! step-up, so a Deny never deepens and the strongest outcome stays the
//! step-up. The window is carried by the store record's TTL (the
//! canonical decoy_escalation.lua writes a 10-minute record); the stage
//! itself is a pure one-rung raise over whatever the pipeline has
//! already composed.
//!
//! The gate is part of the contract, not a deployment afterthought: the
//! canonical script (protocol/risk-v1/decoy_escalation.lua, embedded
//! here as [`DECOY_ESCALATION_LUA`]) refuses the record op unless the
//! caller passes the autofill-qualification gate as open, and the gate
//! is open only when the qualification matrix
//! (tests/browser/qualification/autofill-matrix.json) passes every
//! required surface. Until then the write path writes nothing, so a
//! password manager can never trip the escalation on a real user.

use std::net::IpAddr;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::action::RiskAction;
use crate::policy::RiskReason;
use crate::store::RiskStoreError;
use crate::RiskDecision;

/// The canonical decoy-escalation script (byte-identical across the
/// three shipped copies: protocol/risk-v1/, this package's resources/
/// and the PHP package's resources/).
pub const DECOY_ESCALATION_LUA: &str = include_str!("../resources/decoy_escalation.lua");

/// The escalation window: 10 minutes in milliseconds (the record TTL
/// the canonical script is invoked with).
pub const ESCALATION_TTL_MS: u64 = 600_000;

/// The reader seam of the engine wiring (the marks-reader precedent):
/// answers whether the session's decoy escalation is live. An
/// unreadable surface degrades to not-live: the stage is a temporary
/// price raise, so a backend miss must never escalate anyone.
pub trait DecoyEscalationReader: Send + Sync {
    /// True when the session carries a live escalation record. `None`
    /// session (no session dimension on the request) answers false.
    fn escalation_live(&self, session: Option<&str>) -> bool;
}

/// The Redis-backed decoy-escalation store: the Rust mirror of the PHP
/// `DecoyEscalationStore`, running the canonical [`DECOY_ESCALATION_LUA`]
/// over the same key grammar (`decoy_esc:{namespace}:{session}`) and the
/// same hash record (`count`, `first_ms`, `last_ms` with a whole-key
/// TTL). It implements [`DecoyEscalationReader`], so an engine is wired
/// through [`crate::RiskEngine::with_decoy_escalation`].
///
/// Build it from an existing state store with
/// [`crate::redis::RedisRiskStateStore::decoy_escalation_reader`], which
/// shares the store's Redis client and encoded deployment namespace, so
/// the reader and the risk state live in one keyspace.
///
/// The write is gated exactly like the PHP store: `gate_open` is the
/// autofill-qualification decision, and a closed gate makes the script
/// refuse the record (and write nothing) before any mutation. A caller
/// that evaluates the qualification matrix per request constructs the
/// reader with the current decision.
pub struct RedisDecoyEscalationStore {
    client: ::redis::Client,
    /// The encoded deployment namespace (the same value the state store
    /// interpolates inside its keys).
    namespace: String,
    ttl_ms: u64,
    gate_open: bool,
    script: ::redis::Script,
}

impl RedisDecoyEscalationStore {
    /// Builds the reader over one Redis client and an already-encoded
    /// deployment namespace. Prefer
    /// [`crate::redis::RedisRiskStateStore::decoy_escalation_reader`] so
    /// the namespace derivation stays in one place.
    pub fn new(
        client: ::redis::Client,
        namespace: impl Into<String>,
        gate_open: bool,
    ) -> Result<Self, String> {
        let namespace = namespace.into();
        if namespace.is_empty() || namespace.contains(['{', '}', ':']) {
            return Err(
                "the decoy escalation namespace must be non-empty and free of '{', '}' and ':'"
                    .to_string(),
            );
        }
        Ok(RedisDecoyEscalationStore {
            client,
            namespace,
            ttl_ms: ESCALATION_TTL_MS,
            gate_open,
            script: ::redis::Script::new(DECOY_ESCALATION_LUA),
        })
    }

    /// Overrides the escalation window (the record's TTL). The script
    /// enforces the positive-integer bound.
    pub fn with_ttl_ms(mut self, ttl_ms: u64) -> Result<Self, String> {
        if ttl_ms < 1 {
            return Err("the decoy escalation TTL must be at least one millisecond".to_string());
        }
        self.ttl_ms = ttl_ms;
        Ok(self)
    }

    fn key(&self, session: &str) -> Result<String, RiskStoreError> {
        if session.is_empty() || session.contains(['{', '}', ':']) {
            return Err(RiskStoreError::InvalidIdentifier(
                "the session identifier must be a non-empty safe key component".to_string(),
            ));
        }
        Ok(format!("decoy_esc:{}:{}", self.namespace, session))
    }

    fn connection(&self) -> Result<::redis::Connection, RiskStoreError> {
        // Bounded liveness first: the setup pipeline has no reply bound
        // after TCP connect, so a silent acceptor would park this path.
        kiwicaptcha::redis_verify::probe_connection_info(self.client.get_connection_info())
            .map_err(|e| {
                RiskStoreError::BackendUnavailable(format!(
                    "redis probe before escalation connect: {e}"
                ))
            })?;
        let conn = self
            .client
            .get_connection_with_timeout(std::time::Duration::from_millis(
                crate::redis::RedisRiskStateStore::CONNECTION_TIMEOUT_MS,
            ))
            .map_err(crate::redis::map_redis_error)?;
        conn.set_read_timeout(Some(std::time::Duration::from_millis(
            crate::redis::RedisRiskStateStore::COMMAND_TIMEOUT_MS,
        )))
        .map_err(crate::redis::map_redis_error)?;
        conn.set_write_timeout(Some(std::time::Duration::from_millis(
            crate::redis::RedisRiskStateStore::COMMAND_TIMEOUT_MS,
        )))
        .map_err(crate::redis::map_redis_error)?;
        Ok(conn)
    }

    /// Records one server-confirmed decoy hit for `session` and returns
    /// the record's hit count (0 when the qualification gate is closed:
    /// the script refuses the write before touching the key).
    pub fn record_confirmed_hit(&self, session: &str, now_ms: u64) -> Result<i64, RiskStoreError> {
        let key = self.key(session)?;
        let mut conn = self.connection()?;
        self.script
            .key(key)
            .arg("record")
            .arg("1")
            .arg(if self.gate_open { "1" } else { "0" })
            .arg(now_ms)
            .arg(self.ttl_ms)
            .invoke::<i64>(&mut conn)
            .map_err(crate::redis::map_redis_error)
    }

    /// True when `session` carries a live escalation record at `now_ms`
    /// (inside the window and before the key's TTL). The explicit clock
    /// keeps the check deterministic for tests and callers with a
    /// server-authoritative time source.
    pub fn is_live_at(&self, session: &str, now_ms: u64) -> Result<bool, RiskStoreError> {
        let key = self.key(session)?;
        let mut conn = self.connection()?;
        let live: i64 = self
            .script
            .key(key)
            .arg("read")
            .arg("0")
            .arg("0")
            .arg(now_ms)
            .arg(self.ttl_ms)
            .invoke(&mut conn)
            .map_err(crate::redis::map_redis_error)?;
        Ok(live == 1)
    }
}

impl DecoyEscalationReader for RedisDecoyEscalationStore {
    fn escalation_live(&self, session: Option<&str>) -> bool {
        let Some(session) = session.filter(|s| !s.is_empty()) else {
            return false;
        };
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        // A backend miss never escalates anyone (the stage is a
        // temporary price raise; the PHP mirror degrades identically).
        self.is_live_at(session, now_ms).unwrap_or(false)
    }
}

/// The request identity picture the engine hands the reader (the same
/// shape the marks and pricing readers receive).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecoyEscalationRequest {
    pub scope: u32,
    pub source_ip: IpAddr,
    /// The session pseudonym (32 hex chars), or `None` without a session.
    pub session: Option<String>,
}

/// The decoy-escalation stage: raises the composed action by exactly
/// one ladder rung, capped at the interactive step-up. Pure; the score,
/// band, policy version, model revision, global level and decision id
/// pass through untouched. The stage reason prepends exactly like the
/// policy's hard overrides, then deduplicates and caps at 4.
pub fn apply(plain: RiskDecision, live: bool) -> RiskDecision {
    if !live {
        return plain;
    }
    let mut decision = plain;
    let next_rank = decision.action.rank() + 1;
    let next = if next_rank >= RiskAction::Deny.rank() {
        RiskAction::StepUp
    } else {
        rung_at_rank(next_rank)
    };
    if next.rank() <= decision.action.rank() {
        return decision;
    }
    decision.action = next;
    let mut reasons = vec![RiskReason::DecoyEscalation];
    reasons.extend(decision.reasons_vec());
    let mut seen = std::collections::HashSet::new();
    reasons.retain(|reason| seen.insert(*reason));
    reasons.truncate(4);
    let mut out = [None; 4];
    for (slot, reason) in out.iter_mut().zip(reasons) {
        *slot = Some(reason);
    }
    decision.reasons = out;
    decision
}

/// The ladder rung at a rank (the inverse of [`RiskAction::rank`] for
/// the raise path; the rank always comes from a real rung).
fn rung_at_rank(rank: u8) -> RiskAction {
    match rank {
        0 => RiskAction::Allow,
        1 => RiskAction::Sha16,
        2 => RiskAction::Sha18,
        3 => RiskAction::Sha20,
        4 => RiskAction::Argon16,
        5 => RiskAction::Argon32,
        6 => RiskAction::Argon64,
        7 => RiskAction::Rsw,
        8 => RiskAction::StepUp,
        _ => RiskAction::Deny,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::RiskPolicy;
    use crate::resources::ResourcePressure;
    use crate::signals::SignalVector;
    use serde_json::json;

    const T0: u64 = 1_700_000_000_000;

    fn policy() -> RiskPolicy {
        RiskPolicy::from_config(
            3,
            &json!({
                "version": 3,
                "weights": {
                    "source_fast": 190, "source_slow": 110, "subnet_fast": 80,
                    "issue_debt": 150, "bad_proof": 220, "malformed": 260,
                    "replay": 320, "action_failure": 120, "scope_switch": 60,
                    "global_pressure": 170, "network_risk": 100,
                    "trust_credit": 130, "principal_credit": 100
                },
                "scopes": {
                    "1": { "base_risk": 100, "minimum": "allow", "post_solve_check": true, "degraded": "sha20" }
                },
                "global_floors": { "0": "allow", "1": "sha16", "2": "sha18", "3": "sha20", "4": "sha20" }
            }),
        )
        .expect("config parses")
    }

    fn plain(score: u16) -> RiskDecision {
        policy().decide(
            1,
            score,
            &SignalVector::zero(),
            &ResourcePressure::default(),
            0,
            T0,
            0,
        )
    }

    #[test]
    fn embedded_script_is_the_canonical_copy() {
        // The resources copy must stay byte-identical to the protocol
        // asset (the same parity the other Lua scripts keep).
        let canonical = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../protocol/risk-v1/decoy_escalation.lua"
        );
        let raw = std::fs::read_to_string(canonical).expect("protocol copy readable");
        assert_eq!(raw, DECOY_ESCALATION_LUA);
    }

    #[test]
    fn not_live_passes_through() {
        let base = plain(500);
        let out = apply(base.clone(), false);
        assert_eq!(out.action, base.action);
        assert_eq!(out.reasons, base.reasons);
    }

    #[test]
    fn live_raises_exactly_one_rung() {
        let out = apply(plain(100), true);
        assert_eq!(out.action, RiskAction::Sha16);
        assert!(out.has_reason(RiskReason::DecoyEscalation));
        let out = apply(plain(500), true);
        assert_eq!(out.action, RiskAction::Argon16);
        let out = apply(plain(900), true);
        assert_eq!(out.action, RiskAction::Rsw);
        let out = apply(plain(940), true);
        assert_eq!(out.action, RiskAction::StepUp);
    }

    #[test]
    fn escalation_never_blocks() {
        // StepUp stays StepUp and Deny never deepens: the raise caps at
        // the interactive step-up.
        let out = apply(plain(965), true);
        assert_eq!(out.action, RiskAction::StepUp);
        let deny = plain(990);
        let out = apply(deny.clone(), true);
        assert_eq!(out.action, RiskAction::Deny);
        assert_eq!(out.reasons, deny.reasons);
    }

    #[test]
    fn stage_fields_pass_through() {
        let base = plain(500);
        let out = apply(base.clone(), true);
        assert_eq!(out.score, base.score);
        assert_eq!(out.band, base.band);
        assert_eq!(out.policy_version, base.policy_version);
        assert_eq!(out.model_revision, base.model_revision);
        assert_eq!(out.global_level, base.global_level);
        assert_eq!(out.decision_id, base.decision_id);
    }

    #[test]
    fn ttl_constant_is_the_ten_minute_window() {
        assert_eq!(ESCALATION_TTL_MS, 600_000);
    }

    #[test]
    fn the_php_copy_is_byte_identical_too() {
        // The PHP package ships its own resources copy; the Rust reader
        // executes the embedded script against the same PHP key grammar,
        // so a divergence in either copy would silently split the two
        // languages' escalation state.
        let php = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../kiwicaptcha-risk-php/resources/decoy_escalation.lua"
        );
        let raw = std::fs::read_to_string(php).expect("PHP resources copy readable");
        assert_eq!(raw, DECOY_ESCALATION_LUA);
    }

    fn redis_url() -> Option<String> {
        match std::env::var("RISK_REDIS_URL") {
            Ok(url) if !url.is_empty() => Some(if let Some(rest) = url.strip_prefix("tcp://") {
                format!("redis://{rest}")
            } else {
                url
            }),
            _ => {
                eprintln!("skipping Redis decoy-escalation test: RISK_REDIS_URL not set");
                None
            }
        }
    }

    fn unique_namespace(label: &str) -> String {
        let mut suffix = [0u8; 4];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut suffix);
        format!("{label}{}", hex::encode(suffix))
    }

    #[test]
    fn redis_reader_records_reads_and_expires_like_the_canonical_script() {
        let Some(url) = redis_url() else { return };
        let client = ::redis::Client::open(url.clone()).expect("url parses");
        let namespace = unique_namespace("dectest");
        let session = "a1b2c3d4e5f60718293a4b5c6d7e8f90";
        let reader = RedisDecoyEscalationStore::new(client.clone(), namespace.clone(), true)
            .expect("reader builds");

        // A confirmed hit records and increments the count.
        assert_eq!(reader.record_confirmed_hit(session, T0).expect("record"), 1);
        assert_eq!(
            reader
                .record_confirmed_hit(session, T0 + 1)
                .expect("record"),
            2
        );

        // The record is live inside the window and dead at its boundary
        // (the script's explicit window check anchored on the last hit,
        // independent of key TTL).
        assert!(reader.is_live_at(session, T0 + 2).expect("read"));
        assert!(!reader
            .is_live_at(session, T0 + 1 + ESCALATION_TTL_MS)
            .expect("read"));

        // The trait degrades unknown/missing sessions to not-live.
        assert!(!reader.escalation_live(None));
        assert!(!reader.escalation_live(Some("")));
        assert!(!reader.escalation_live(Some("not-a-session:with-colon")));
        assert!(!reader.escalation_live(Some("f".repeat(32).as_str())));

        // A closed qualification gate refuses the write before any
        // mutation: the key never exists, so no reader can escalate.
        let closed_ns = unique_namespace("decclosed");
        let closed = RedisDecoyEscalationStore::new(client.clone(), closed_ns.clone(), false)
            .expect("reader builds");
        assert_eq!(closed.record_confirmed_hit(session, T0).expect("record"), 0);
        assert!(!closed.is_live_at(session, T0 + 1).expect("read"));

        let mut conn = client.get_connection().expect("connection");
        let _: () = ::redis::cmd("DEL")
            .arg(format!("decoy_esc:{namespace}:{session}"))
            .arg(format!("decoy_esc:{closed_ns}:{session}"))
            .query(&mut conn)
            .expect("cleanup");
    }

    #[test]
    fn redis_reader_rejects_unsafe_key_components() {
        let client = ::redis::Client::open("redis://127.0.0.1:1").expect("url parses lazily");
        assert!(RedisDecoyEscalationStore::new(client.clone(), "bad:ns", true).is_err());
        assert!(RedisDecoyEscalationStore::new(client.clone(), "", true).is_err());
        let reader = RedisDecoyEscalationStore::new(client, "ns1", true).expect("reader builds");
        let error = match reader.with_ttl_ms(0) {
            Ok(_) => panic!("a zero TTL is refused"),
            Err(error) => error,
        };
        assert!(error.contains("at least one millisecond"));
    }
}
