//! Risk state store: atomically applies an observation and returns the
//! resulting signal vector.

use thiserror::Error;

use crate::event::RiskEventKind;
use crate::signals::SignalVector;

/// Raised when the risk state backend cannot serve an assessment; the
/// engine treats this as a circuit-breaker failure and degrades.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum RiskStoreError {
    #[error("risk state backend unavailable: {0}")]
    BackendUnavailable(String),
    #[error("risk script error: {0}")]
    ScriptError(String),
    #[error("risk state backend timeout: {0}")]
    Timeout(String),
}

/// The full reply of one store application: the signal vector plus the
/// global pressure level, cooldown deadline and dedupe verdict tracked by
/// the backend.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Observed {
    pub vector: SignalVector,
    pub global_level: u8,
    pub cooldown_until_ms: u64,
    /// True when the event_id was already applied: the state was NOT
    /// mutated and the returned signals are the current ones (there is no
    /// duplicate error in risk-v1 semantics).
    pub is_duplicate: bool,
}

/// Risk state store: applies an observation (event_id dedupe) and returns
/// the current signal vector.
///
/// A duplicate event_id is a documented no-op: the state is untouched and
/// the current signals are returned with `is_duplicate = true`.
pub trait RiskStateStore {
    /// Applies the observation and returns the resulting [`Observed`].
    ///
    /// # Errors
    ///
    /// - backend errors (`BackendUnavailable`, `ScriptError`, `Timeout`).
    fn observe(&self, o: &crate::event::RiskObservation) -> Result<Observed, RiskStoreError>;

    /// Registers a pending outcome-ledger entry for one decision
    /// (`outcome_register.lua`). The outcome ledger is always on and
    /// independent of calibration: with calibration disabled the engine
    /// books the ledger here at decision time, so
    /// ConfirmedLegitimate/ConfirmedAbuse work identically with or without
    /// calibration. `decision_hour` is `now_ms / 3_600_000` (the decision's
    /// hour; the ledger carries it for decision-time bucketing and
    /// correction key derivation).
    ///
    /// Returns `Ok(false)` when the decision_id is already registered
    /// (SET NX: a retried decision can never overwrite its ledger entry).
    ///
    /// # Errors
    ///
    /// - backend errors (`BackendUnavailable`, `ScriptError`, `Timeout`).
    fn register_outcome(
        &self,
        decision_id: &str,
        scope: u32,
        decision_hour: i64,
        score: u32,
    ) -> Result<bool, RiskStoreError>;

    /// Confirms a decision's ledger entry exactly once
    /// (`outcome_confirm.lua`): pending -> L/A. Returns `1` for the first
    /// confirmation (reputation eligible), `0` when the decision is
    /// unknown/already confirmed.
    ///
    /// # Errors
    ///
    /// - backend errors (`BackendUnavailable`, `ScriptError`, `Timeout`).
    fn confirm_outcome(&self, decision_id: &str, legitimate: bool) -> Result<u8, RiskStoreError>;

    /// Corrects a decision's ledger entry (`outcome_correct.lua`): flips
    /// L <-> A (authoritative for future events; ephemeral reputation
    /// decays naturally — no synthetic identities). Returns `Ok(true)`
    /// when the ledger was flipped, `Ok(false)` when the decision is
    /// unknown or already carries the target outcome.
    ///
    /// # Errors
    ///
    /// - backend errors (`BackendUnavailable`, `ScriptError`, `Timeout`).
    fn correct_outcome(&self, decision_id: &str, legitimate: bool) -> Result<bool, RiskStoreError>;

    /// Last observed global pressure level (0..4) reported by the backend
    /// during the most recent successful assessment. Stores without the
    /// probe return 0.
    fn last_global_level(&self) -> u8 {
        0
    }

    /// Cooldown deadline (epoch ms) from the most recent assessment, or 0
    /// when none is active.
    fn last_cooldown_until_ms(&self) -> u64 {
        0
    }
}

/// Optional risk-v2 capability: records the session's first-seen
/// client-context tag and returns the recorded tag.
///
/// Kept out of the [`RiskStateStore`] trait so existing v1 implementations
/// compile unchanged. The default implementation reports no record
/// surface — `Ok(None)` — so a store without the capability degrades the
/// session-consistency signal to neutral (consistent), exactly the
/// backend-miss semantics.
///
/// Opt-in: the capability traits are optional — a third-party store
/// implementing only [`RiskStateStore`] opts in by adding the two empty
/// impls (`impl SessionContextTagStore for MyStore {}` and
/// `impl SessionTlsTagStore for MyStore {}`); the default methods then
/// provide the neutral v2 signals (no record surface -> "consistent").
/// The built-in Redis store ([`crate::redis::RedisRiskStateStore`])
/// implements the real record surfaces.
pub trait SessionContextTagStore {
    /// The risk-v2 session client-context record: records `tag` as the
    /// session's first-seen client-context tag (SET NX, first write wins)
    /// and returns the recorded tag — `Some(first)` when a record exists,
    /// `None` when the store has no record surface.
    ///
    /// The record is keyed by the session's HMAC pseudonym (never the raw
    /// cookie value) and expires with the same TTL as the risk-v1 session
    /// state. The engine derives the `session_consistency` signal by
    /// comparing the current request's tag against the returned first tag;
    /// `Ok(None)` / `Err` degrade to "consistent" (neutral), never breaking
    /// an assessment.
    fn session_first_context_tag(
        &self,
        _session_id: &[u8; 16],
        _tag: &str,
    ) -> Result<Option<String>, RiskStoreError> {
        Ok(None)
    }
}

/// Optional risk-v2 capability: records the session's first-seen
/// trusted-edge TLS classification tag and returns the recorded tag.
///
/// Kept out of the [`RiskStateStore`] trait so existing v1 implementations
/// compile unchanged. The default implementation reports no record
/// surface — `Ok(None)` — so a store without the capability degrades the
/// tls-inconsistency signal to neutral (consistent), exactly the
/// backend-miss semantics.
///
/// Opt-in: the capability traits are optional — a third-party store
/// implementing only [`RiskStateStore`] opts in by adding the two empty
/// impls (`impl SessionContextTagStore for MyStore {}` and
/// `impl SessionTlsTagStore for MyStore {}`); the default methods then
/// provide the neutral v2 signals (no record surface -> "consistent").
/// The built-in Redis store ([`crate::redis::RedisRiskStateStore`])
/// implements the real record surfaces.
pub trait SessionTlsTagStore {
    /// The risk-v2 session trusted-edge TLS record: records `tag` as the
    /// session's first-seen TLS classification tag (SET NX, first write
    /// wins) and returns the recorded tag — the first coarse, server-
    /// attested TLS classification (e.g. "tls13|http2", supplied only by
    /// trusted proxy/CDN infrastructure) the session ever presented, or
    /// `Ok(None)` when the store has no record surface.
    ///
    /// The record is keyed by the session's HMAC pseudonym (never the raw
    /// cookie value) and expires with the same TTL as the risk-v1 session
    /// state. The engine derives the `tls_inconsistency` signal by
    /// comparing the current request's tag against the returned first tag;
    /// `Ok(None)` / `Err` degrade to "consistent" (neutral), never breaking
    /// an assessment. Only the ephemeral classification is stored — never
    /// a raw fingerprint database.
    fn session_first_tls_tag(
        &self,
        _session_id: &[u8; 16],
        _tag: &str,
    ) -> Result<Option<String>, RiskStoreError> {
        Ok(None)
    }
}

/// Convenience wrapper for recording events without building an
/// [`crate::event::RiskObservation`] by hand.
pub trait RiskStateStoreExt: RiskStateStore {
    /// Records an event with the given epoch-scoped pseudonyms and a fresh
    /// caller-supplied event_id, returning the resulting [`Observed`].
    #[allow(clippy::too_many_arguments)]
    fn record_event(
        &self,
        event: RiskEventKind,
        scope: u32,
        source_epoch: i64,
        source_id_prev: &str,
        source_id: &str,
        source_id_next: &str,
        subnet_epoch: i64,
        subnet_id_prev: &str,
        subnet_id: &str,
        subnet_id_next: &str,
        event_id: &str,
        now_ms: u64,
    ) -> Result<Observed, RiskStoreError> {
        let observation = crate::event::RiskObservation {
            event,
            scope,
            source_epoch,
            source_id_prev: source_id_prev.to_string(),
            source_id: source_id.to_string(),
            source_id_next: source_id_next.to_string(),
            subnet_epoch,
            subnet_id_prev: subnet_id_prev.to_string(),
            subnet_id: subnet_id.to_string(),
            subnet_id_next: subnet_id_next.to_string(),
            session_id: None,
            principal_id: None,
            event_id: event_id.to_string(),
            network_risk: 0,
            now_ms,
        };
        self.observe(&observation)
    }
}

impl<T: RiskStateStore + ?Sized> RiskStateStoreExt for T {}
