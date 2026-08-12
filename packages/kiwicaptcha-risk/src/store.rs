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
    #[error("duplicate event_id")]
    DuplicateEvent,
    #[error("risk script error: {0}")]
    ScriptError(String),
    #[error("risk state backend timeout: {0}")]
    Timeout(String),
}

/// Risk state store: applies an observation exactly once (event_id dedupe)
/// and returns the current signal vector.
///
/// A duplicate event_id is a documented no-op that surfaces as
/// [`RiskStoreError::DuplicateEvent`]; the engine's degraded path is NOT
/// triggered for it by the store itself.
pub trait RiskStateStore {
    /// Applies the observation and returns the resulting [`SignalVector`].
    ///
    /// # Errors
    ///
    /// - [`RiskStoreError::DuplicateEvent`] when the event_id was already
    ///   applied (the state is untouched).
    /// - backend errors (`BackendUnavailable`, `ScriptError`, `Timeout`).
    fn observe(&self, o: &crate::event::RiskObservation) -> Result<SignalVector, RiskStoreError>;

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

/// Convenience wrapper for recording events without building an
/// [`crate::event::RiskObservation`] by hand.
pub trait RiskStateStoreExt: RiskStateStore {
    /// Records an event with the given pseudonym ids and a fresh caller-
    /// supplied event_id, returning the resulting vector.
    fn record_event(
        &self,
        event: RiskEventKind,
        scope: u16,
        source_id: [u8; 16],
        subnet_id: [u8; 16],
        event_id: [u8; 16],
        now_ms: u64,
    ) -> Result<SignalVector, RiskStoreError> {
        let observation = crate::event::RiskObservation {
            event,
            scope,
            source_id,
            subnet_id,
            session_id: None,
            principal_id: None,
            event_id,
            network_risk: 0,
            now_ms,
        };
        self.observe(&observation)
    }
}

impl<T: RiskStateStore + ?Sized> RiskStateStoreExt for T {}
