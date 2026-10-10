//! Typed outcomes API and the long-memory mark surface: the eight
//! application-reported outcomes, the sealed handle set that addresses
//! their subjects, and the one versioned mapping table that resolves
//! every outcome onto the existing risk-v1 event channels, the
//! always-on outcome ledger and the marks.
//!
//! The trust polarity lives in the table and is enforced by property
//! tests: only the server-confirmed trust outcomes may subtract risk,
//! exactly the abuse outcomes write long-memory marks, and the two
//! classes are disjoint. The authentication pair maps onto the existing
//! authentication feedback channels only (no marks). The cross-language
//! vectors (`protocol/risk-v1/outcomes-vectors.json`) pin this crate and
//! the PHP mirror to the same table contents.

use crate::context::RiskContext;
use crate::event::RiskEventKind;
use crate::network::NetworkClassifier;
use crate::redis::RedisRiskStateStore;
use crate::store::{RiskStateStore, RiskStoreError, SessionContextTagStore, SessionTlsTagStore};
use crate::{EventReceipt, RiskEngine, RiskError};

/// The version of the outcome mapping table. Must rise whenever a row
/// changes meaning; the shared vectors pin both cores to one version.
pub const OUTCOME_MAP_VERSION: u32 = 1;

/// The typed outcome vocabulary: the eight application-reported
/// outcomes. The serde wire names are the contract names shared with
/// the PHP mirror and the cross-language vectors.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Outcome {
    ConfirmedLegitimate,
    StepUpCompleted,
    AuthenticationSuccess,
    AuthenticationFailure,
    SpamReported,
    Chargeback,
    AccountBanned,
    FraudConfirmed,
}

impl Outcome {
    /// All eight outcomes, in vocabulary order.
    pub const ALL: [Outcome; 8] = [
        Outcome::ConfirmedLegitimate,
        Outcome::StepUpCompleted,
        Outcome::AuthenticationSuccess,
        Outcome::AuthenticationFailure,
        Outcome::SpamReported,
        Outcome::Chargeback,
        Outcome::AccountBanned,
        Outcome::FraudConfirmed,
    ];

    /// The contract wire name (`confirmedLegitimate` and siblings).
    pub fn wire_name(self) -> &'static str {
        match self {
            Outcome::ConfirmedLegitimate => "confirmedLegitimate",
            Outcome::StepUpCompleted => "stepUpCompleted",
            Outcome::AuthenticationSuccess => "authenticationSuccess",
            Outcome::AuthenticationFailure => "authenticationFailure",
            Outcome::SpamReported => "spamReported",
            Outcome::Chargeback => "chargeback",
            Outcome::AccountBanned => "accountBanned",
            Outcome::FraudConfirmed => "fraudConfirmed",
        }
    }

    /// Resolves a wire name; `None` for unknown names so callers on the
    /// report boundary can reject them fail-closed.
    pub fn from_wire_name(name: &str) -> Option<Outcome> {
        Outcome::ALL.iter().copied().find(|o| o.wire_name() == name)
    }
}

/// The long-memory mark dimensions: the four identity dimensions the
/// typed handles carry plus the asn dimension the network-aware callers
/// address through the store surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MarkDimension {
    Principal,
    Target,
    Session,
    Agent,
    Asn,
}

impl MarkDimension {
    /// The key segment inside a mark key.
    pub fn key(self) -> &'static str {
        match self {
            MarkDimension::Principal => "principal",
            MarkDimension::Target => "target",
            MarkDimension::Session => "session",
            MarkDimension::Agent => "agent",
            MarkDimension::Asn => "asn",
        }
    }

    /// Resolves a key segment; `None` for unknown segments.
    pub fn from_key(key: &str) -> Option<MarkDimension> {
        match key {
            "principal" => Some(MarkDimension::Principal),
            "target" => Some(MarkDimension::Target),
            "session" => Some(MarkDimension::Session),
            "agent" => Some(MarkDimension::Agent),
            "asn" => Some(MarkDimension::Asn),
            _ => None,
        }
    }
}

/// The sealed handle dimensions of the typed outcomes API: the six ways
/// an application can address the subject of an outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HandleDimension {
    Nonce,
    DecisionId,
    Principal,
    Target,
    Session,
    Agent,
}

impl HandleDimension {
    /// All six dimensions, in table order.
    pub const ALL: [HandleDimension; 6] = [
        HandleDimension::Nonce,
        HandleDimension::DecisionId,
        HandleDimension::Principal,
        HandleDimension::Target,
        HandleDimension::Session,
        HandleDimension::Agent,
    ];

    /// The wire name of the dimension (the vectors' `dimension` field).
    pub fn wire_name(self) -> &'static str {
        match self {
            HandleDimension::Nonce => "nonce",
            HandleDimension::DecisionId => "decisionId",
            HandleDimension::Principal => "principal",
            HandleDimension::Target => "target",
            HandleDimension::Session => "session",
            HandleDimension::Agent => "agent",
        }
    }

    /// Resolves a wire name; `None` for unknown names.
    pub fn from_wire_name(name: &str) -> Option<HandleDimension> {
        HandleDimension::ALL
            .iter()
            .copied()
            .find(|d| d.wire_name() == name)
    }

    /// True for the two ledger dimensions (the outcome-ledger path).
    pub fn is_ledger(self) -> bool {
        matches!(self, HandleDimension::Nonce | HandleDimension::DecisionId)
    }

    /// True for the four identity dimensions (feedback + marks).
    pub fn is_identity(self) -> bool {
        !self.is_ledger()
    }

    /// The mark dimension the handle addresses, or `None` for the
    /// ledger dimensions (a ledger handle names no mark).
    pub fn mark_dimension(self) -> Option<MarkDimension> {
        match self {
            HandleDimension::Principal => Some(MarkDimension::Principal),
            HandleDimension::Target => Some(MarkDimension::Target),
            HandleDimension::Session => Some(MarkDimension::Session),
            HandleDimension::Agent => Some(MarkDimension::Agent),
            HandleDimension::Nonce | HandleDimension::DecisionId => None,
        }
    }
}

/// One subject address of a typed outcome report: a dimension plus the
/// identifier value the caller addresses it by.
///
/// The identity dimensions carry the subject's pseudonym, never the raw
/// identifier: principal, target and session values must already be the
/// 128-bit lowercase-hex pseudonyms the identity factory derives. A
/// raw-looking value is rejected at construction, fail-closed, so a raw
/// identifier can never reach a long-memory mark key. Agent carries the
/// configured agent name and the ledger dimensions carry the
/// caller-tracked nonce or decision id; both follow the shared
/// key-safety rule of the store's ledger keys.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutcomeHandle {
    pub dimension: HandleDimension,
    pub id: String,
}

impl OutcomeHandle {
    fn new(dimension: HandleDimension, id: &str) -> Result<OutcomeHandle, RiskError> {
        let rule = if matches!(
            dimension,
            HandleDimension::Principal | HandleDimension::Target | HandleDimension::Session
        ) {
            Self::is_pseudonym
        } else {
            Self::is_key_safe
        };
        if !rule(id) {
            return Err(RiskError::InvalidOutcomeHandle(format!(
                "{} handle carries an inadmissible identifier value (got 0x{})",
                dimension.wire_name(),
                hex::encode(id)
            )));
        }
        Ok(OutcomeHandle {
            dimension,
            id: id.to_string(),
        })
    }

    /// A challenge-nonce handle (the ledger dimension for nonce-keyed
    /// pending entries).
    pub fn nonce(nonce: &str) -> Result<OutcomeHandle, RiskError> {
        Self::new(HandleDimension::Nonce, nonce)
    }

    /// A decision-id handle (the always-on outcome ledger's key).
    pub fn decision_id(decision_id: &str) -> Result<OutcomeHandle, RiskError> {
        Self::new(HandleDimension::DecisionId, decision_id)
    }

    /// A principal handle carrying the principal pseudonym.
    pub fn principal(pseudonym: &str) -> Result<OutcomeHandle, RiskError> {
        Self::new(HandleDimension::Principal, pseudonym)
    }

    /// A target handle carrying the target pseudonym.
    pub fn target(pseudonym: &str) -> Result<OutcomeHandle, RiskError> {
        Self::new(HandleDimension::Target, pseudonym)
    }

    /// A session handle carrying the session pseudonym.
    pub fn session(pseudonym: &str) -> Result<OutcomeHandle, RiskError> {
        Self::new(HandleDimension::Session, pseudonym)
    }

    /// An agent handle carrying the configured agent name.
    pub fn agent(agent_id: &str) -> Result<OutcomeHandle, RiskError> {
        Self::new(HandleDimension::Agent, agent_id)
    }

    /// The pseudonym rule: exactly 32 lowercase hex chars, the 128-bit
    /// HMAC pseudonym byte shape shared by both cores.
    fn is_pseudonym(value: &str) -> bool {
        value.len() == 32
            && value
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    }

    /// The ledger/agent rule: the shared key-safety contract of the
    /// store's ledger keys (byte-identical with the PHP mirror).
    fn is_key_safe(value: &str) -> bool {
        RedisRiskStateStore::valid_key_component(value)
    }
}

/// One row of the versioned outcome mapping table: how a single outcome
/// resolves onto the existing surfaces. The row is total — every
/// outcome has exactly one channel event, one ledger action, one mark
/// behavior and one polarity class.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OutcomeMapping {
    pub outcome: Outcome,
    /// The existing risk-v1 event the outcome books on the feedback path.
    pub channel: RiskEventKind,
    /// `None` = no ledger semantics; `Some(true)` confirms L;
    /// `Some(false)` confirms A.
    pub ledger_legitimate: Option<bool>,
    /// Whether the outcome writes a long-memory abuse mark on identity
    /// handles.
    pub writes_abuse_mark: bool,
    /// Whether the outcome is a server-side assertion (raw client input
    /// can never produce it directly).
    pub server_confirmed: bool,
    /// Whether any path of the outcome may lower risk (the trust
    /// polarity).
    pub may_subtract_risk: bool,
    /// The handle dimensions the outcome can be reported with.
    pub accepted_handles: &'static [HandleDimension],
}

impl OutcomeMapping {
    /// True when the outcome can be reported on this dimension.
    pub fn accepts(self, dimension: HandleDimension) -> bool {
        self.accepted_handles.contains(&dimension)
    }

    /// The mark kind the outcome writes on identity handles: the
    /// outcome's own wire name when the mapping carries an abuse mark.
    pub fn mark_kind(self) -> Option<&'static str> {
        self.writes_abuse_mark.then(|| self.outcome.wire_name())
    }

    /// True when the outcome has a ledger action (a nonce or decision id
    /// can confirm it through the always-on outcome ledger).
    pub fn has_ledger_action(self) -> bool {
        self.ledger_legitimate.is_some()
    }
}

const LEDGER_DIMENSIONS: [HandleDimension; 2] =
    [HandleDimension::Nonce, HandleDimension::DecisionId];

const IDENTITY_DIMENSIONS: [HandleDimension; 4] = [
    HandleDimension::Principal,
    HandleDimension::Target,
    HandleDimension::Session,
    HandleDimension::Agent,
];

const EVERY_DIMENSION: [HandleDimension; 6] = [
    HandleDimension::Nonce,
    HandleDimension::DecisionId,
    HandleDimension::Principal,
    HandleDimension::Target,
    HandleDimension::Session,
    HandleDimension::Agent,
];

/// The one versioned outcome mapping table. There is exactly one table —
/// the public enum vocabulary, the engine's feedback channels and the
/// mark behavior can never diverge into a second mapping.
pub fn mapping(outcome: Outcome) -> OutcomeMapping {
    match outcome {
        Outcome::ConfirmedLegitimate => OutcomeMapping {
            outcome,
            channel: RiskEventKind::ConfirmedLegitimate,
            ledger_legitimate: Some(true),
            writes_abuse_mark: false,
            server_confirmed: true,
            may_subtract_risk: true,
            accepted_handles: &EVERY_DIMENSION,
        },
        Outcome::StepUpCompleted => OutcomeMapping {
            outcome,
            channel: RiskEventKind::ProtectedActionSuccess,
            ledger_legitimate: None,
            writes_abuse_mark: false,
            server_confirmed: true,
            may_subtract_risk: true,
            accepted_handles: &IDENTITY_DIMENSIONS,
        },
        Outcome::AuthenticationSuccess => OutcomeMapping {
            outcome,
            channel: RiskEventKind::AuthenticationSuccess,
            ledger_legitimate: None,
            writes_abuse_mark: false,
            server_confirmed: true,
            may_subtract_risk: true,
            accepted_handles: &IDENTITY_DIMENSIONS,
        },
        Outcome::AuthenticationFailure => OutcomeMapping {
            outcome,
            channel: RiskEventKind::AuthenticationFailure,
            ledger_legitimate: None,
            writes_abuse_mark: false,
            server_confirmed: false,
            may_subtract_risk: false,
            accepted_handles: &IDENTITY_DIMENSIONS,
        },
        Outcome::SpamReported => OutcomeMapping {
            outcome,
            channel: RiskEventKind::ProtectedActionFailure,
            ledger_legitimate: None,
            writes_abuse_mark: true,
            server_confirmed: true,
            may_subtract_risk: false,
            accepted_handles: &IDENTITY_DIMENSIONS,
        },
        Outcome::Chargeback => OutcomeMapping {
            outcome,
            channel: RiskEventKind::ConfirmedAbuse,
            ledger_legitimate: Some(false),
            writes_abuse_mark: true,
            server_confirmed: true,
            may_subtract_risk: false,
            accepted_handles: &EVERY_DIMENSION,
        },
        Outcome::AccountBanned => OutcomeMapping {
            outcome,
            channel: RiskEventKind::ConfirmedAbuse,
            ledger_legitimate: Some(false),
            writes_abuse_mark: true,
            server_confirmed: true,
            may_subtract_risk: false,
            accepted_handles: &EVERY_DIMENSION,
        },
        Outcome::FraudConfirmed => OutcomeMapping {
            outcome,
            channel: RiskEventKind::ConfirmedAbuse,
            ledger_legitimate: Some(false),
            writes_abuse_mark: true,
            server_confirmed: true,
            may_subtract_risk: false,
            accepted_handles: &EVERY_DIMENSION,
        },
    }
}

/// Every row, in vocabulary order (the completeness oracle of the
/// property tests and the vector readers).
pub fn all_mappings() -> [OutcomeMapping; 8] {
    Outcome::ALL.map(mapping)
}

/// The ledger dimensions in table order (nonce before decision id).
pub fn ledger_dimensions() -> [HandleDimension; 2] {
    LEDGER_DIMENSIONS
}

/// The identity dimensions in table order.
pub fn identity_dimensions() -> [HandleDimension; 4] {
    IDENTITY_DIMENSIONS
}

/// The current content of one written mark: the hash fields kind,
/// last_kind, count, first_ms and last_ms.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MarkRecord {
    /// The maximum-severity outcome name ever written onto the mark: a
    /// mild report after a chargeback can never downgrade it (severity
    /// order: spamReported < accountBanned < fraudConfirmed < chargeback;
    /// unknown kinds rank lowest and never displace an earned kind).
    pub kind: String,
    /// The most recent outcome name written onto the mark (the write's
    /// own kind, always).
    pub last_kind: String,
    /// The total writes onto the mark (monotone; only the erasure path
    /// removes a mark).
    pub count: i64,
    /// The first write's timestamp (epoch ms).
    pub first_ms: i64,
    /// The most recent write's timestamp (epoch ms).
    pub last_ms: i64,
}

/// The frozen mark-kind severity ranks (mirrors marks.lua): unknown kinds
/// rank 0 so they record `last_kind` but never displace an earned
/// higher-severity kind.
pub fn mark_kind_severity(kind: &str) -> u8 {
    match kind {
        "spamReported" => 1,
        "accountBanned" => 2,
        "fraudConfirmed" => 3,
        "chargeback" => 4,
        _ => 0,
    }
}

/// The receipt of one typed outcome report: what the report actually did
/// on each surface it touched.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutcomeReceipt {
    pub outcome: Outcome,
    pub handle_dimension: HandleDimension,
    /// The accepted-outcome status of the ledger path (1 or 2 = the
    /// first confirmation, 0 = nothing consumed); stays 0 on the
    /// identity path.
    pub status: u8,
    /// True when the mapped feedback event was booked.
    pub channel_booked: bool,
    /// The number of long-memory marks written by this report.
    pub marks_written: u32,
    /// The mark's total count field after the write.
    pub mark_count: i64,
    /// The deduped feedback event id when a channel was booked.
    pub event_id: Option<String>,
}

/// The long-memory mark surface of the outcomes plane. The Redis store
/// implements it with the canonical marks.lua script; the trait keeps
/// the typed facade testable against any marks-capable store.
pub trait OutcomeMarksStore {
    /// The exact mark key of one dimension key segment and identifier.
    fn mark_key(&self, dimension: &str, id: &str) -> Result<String, RiskError>;
    /// Writes one mark atomically and returns the mark's new total
    /// count. `event_id` dedupes the write (empty disables dedupe): a
    /// retried report with the same id returns the count unchanged and
    /// never increments it again.
    fn write_mark(
        &self,
        dimension: &str,
        id: &str,
        kind: &str,
        now_ms: u64,
        event_id: &str,
    ) -> Result<i64, RiskError>;
    /// The current mark, or `None` when no mark exists.
    fn read_mark(&self, dimension: &str, id: &str) -> Result<Option<MarkRecord>, RiskError>;
    /// Removes the mark and returns the number of keys removed.
    fn forget_marks(&self, dimension: &str, id: &str) -> Result<u32, RiskError>;
    /// The live target-dimension failure state of one target (the
    /// engine-stored failure counter and spread). Stores without the
    /// capability answer the neutral state.
    fn read_target_state(&self, _target_id: &str) -> Result<crate::store::TargetState, RiskError> {
        Ok(crate::store::TargetState::default())
    }
}

fn store_err(e: RiskStoreError) -> RiskError {
    RiskError::Store(e.to_string())
}

impl OutcomeMarksStore for RedisRiskStateStore {
    fn mark_key(&self, dimension: &str, id: &str) -> Result<String, RiskError> {
        RedisRiskStateStore::mark_key(self, dimension, id).map_err(store_err)
    }

    fn write_mark(
        &self,
        dimension: &str,
        id: &str,
        kind: &str,
        now_ms: u64,
        event_id: &str,
    ) -> Result<i64, RiskError> {
        RedisRiskStateStore::write_mark(self, dimension, id, kind, now_ms, event_id)
            .map_err(store_err)
    }

    fn read_mark(&self, dimension: &str, id: &str) -> Result<Option<MarkRecord>, RiskError> {
        RedisRiskStateStore::read_mark(self, dimension, id).map_err(store_err)
    }

    fn forget_marks(&self, dimension: &str, id: &str) -> Result<u32, RiskError> {
        RedisRiskStateStore::forget_marks(self, dimension, id).map_err(store_err)
    }

    fn read_target_state(&self, target_id: &str) -> Result<crate::store::TargetState, RiskError> {
        RiskStateStore::read_target_state(self, target_id).map_err(store_err)
    }
}

/// The typed outcomes facade: reports the eight application outcomes and
/// serves the erasure path, resolving every report through the one
/// versioned mapping table onto the existing engine surfaces.
///
/// A ledger handle (nonce or decision id) drives the always-on
/// outcome-ledger confirmation; the mapping's ledger row (L for
/// confirmedLegitimate, A for the confirmed-abuse outcomes) decides the
/// flip. An identity handle drives the existing feedback channel the
/// mapping names and writes the long-memory mark when the mapping
/// carries one; the session and principal pseudonyms of the handle ride
/// the observation directly, so the report addresses exactly the
/// identity the caller named.
///
/// A report context is optional: deferred outcomes (a chargeback
/// webhook, a ban decision) have no request to observe, so they settle
/// the ledger and the marks and leave the short-memory feedback
/// channels alone. When a context is given, the mapped reputation event
/// is booked with the caller's idempotency key, deduped by the engine's
/// event id.
pub struct KiwiOutcomes<'a, S, N>
where
    S: RiskStateStore + SessionContextTagStore + SessionTlsTagStore,
    N: NetworkClassifier,
{
    engine: &'a RiskEngine<S, N>,
    marks: &'a dyn OutcomeMarksStore,
}

impl<'a, S, N> KiwiOutcomes<'a, S, N>
where
    S: RiskStateStore + SessionContextTagStore + SessionTlsTagStore,
    N: NetworkClassifier,
{
    /// Builds the facade over one engine and one marks-capable store.
    pub fn new(engine: &'a RiskEngine<S, N>, marks: &'a dyn OutcomeMarksStore) -> Self {
        KiwiOutcomes { engine, marks }
    }

    /// Reports one typed outcome for one handle.
    ///
    /// # Errors
    ///
    /// [`RiskError::InvalidOutcomeHandle`] when the mapping accepts no
    /// such handle dimension for the outcome; [`RiskError::Store`] when
    /// a mark write or a ledger confirmation fails (a failed mark must
    /// surface, never silently drop).
    pub fn report(
        &self,
        outcome: Outcome,
        handle: &OutcomeHandle,
        idempotency_key: Option<String>,
        context: Option<RiskContext<'_>>,
    ) -> Result<OutcomeReceipt, RiskError> {
        let map = mapping(outcome);
        if !map.accepts(handle.dimension) {
            return Err(RiskError::InvalidOutcomeHandle(format!(
                "outcome {} cannot be reported on a {} handle",
                outcome.wire_name(),
                handle.dimension.wire_name()
            )));
        }

        let mut status = 0u8;
        let mut channel_booked = false;
        let mut marks_written = 0u32;
        let mut mark_count = 0i64;
        let mut event_id: Option<String> = None;

        if handle.dimension.is_ledger() {
            let legitimate = map.ledger_legitimate == Some(true);
            status = self.engine.confirm_outcome(&handle.id, legitimate, None)?;
            // Reputation authorization: statuses 1 and 2 always; status
            // 3 (a capped label) only for abuse outcomes — a capped
            // trust label must never mint unlimited reputation credit
            // (status 4 is the v2 confirm's trust cap and never
            // authorizes).
            let authorize =
                matches!(status, 1 | 2) || (status == 3 && !legitimate);
            if authorize {
                if let Some(ctx) = context {
                    let receipt: EventReceipt = self.engine.record_outcome_feedback(
                        map.channel,
                        ctx,
                        idempotency_key,
                        None,
                        None,
                    )?;
                    event_id = Some(receipt.event_id);
                    channel_booked = true;
                }
            }
        } else {
            // The outcome-bridge write path of target-account
            // protection: an authentication failure reported against a
            // target registers the failure in the engine's target state
            // (the leaky counter + spread HLLs assess_v2.lua maintains);
            // a completed step-up clears the counter so a legitimate
            // user is not stepped up twice. The clear is gated on a
            // non-empty idempotency key: only the step-up completion
            // credit path (which always derives one from the consumed
            // challenge) may reset a target's failure counter. Failures
            // are stored by the engine, never injected by callers.
            if handle.dimension == HandleDimension::Target {
                match outcome {
                    Outcome::AuthenticationFailure => {
                        let (source, asn) = self
                            .engine
                            .target_spread_elements(&handle.id, context.as_ref());
                        self.engine
                            .register_target_failure(&handle.id, &source, &asn)?;
                    }
                    Outcome::StepUpCompleted
                        if idempotency_key
                            .as_deref()
                            .map(|k| !k.is_empty())
                            .unwrap_or(false) =>
                    {
                        self.engine.clear_target_failures(&handle.id)?;
                    }
                    _ => {}
                }
            }
            if let Some(kind) = map.mark_kind() {
                // The mark write dedupes on the report's own event id
                // (the same one the feedback channel books), so a
                // retried report never double-counts the mark. No
                // context and no idempotency key draws a fresh id per
                // call (dedupe effectively disabled).
                let mark_event_id = self.engine.derive_outcome_event_id(
                    idempotency_key.as_deref(),
                    context.as_ref().map(|ctx| ctx.scope).unwrap_or(0),
                    map.channel,
                )?;
                // An empty id disables mark dedupe (no marker key): only
                // a caller-supplied idempotency key can make a report
                // idempotent.
                mark_count = self.marks.write_mark(
                    handle
                        .dimension
                        .mark_dimension()
                        .map(|d| d.key())
                        .unwrap_or(""),
                    &handle.id,
                    kind,
                    crate::now_ms(),
                    &mark_event_id,
                )?;
                marks_written = 1;
            }
            if let Some(ctx) = context {
                let session_pseudonym =
                    (handle.dimension == HandleDimension::Session).then_some(handle.id.as_str());
                let principal_pseudonym =
                    (handle.dimension == HandleDimension::Principal).then_some(handle.id.as_str());
                let receipt = self.engine.record_outcome_feedback(
                    map.channel,
                    ctx,
                    idempotency_key,
                    session_pseudonym,
                    principal_pseudonym,
                )?;
                event_id = Some(receipt.event_id);
                channel_booked = true;
            }
        }

        Ok(OutcomeReceipt {
            outcome,
            handle_dimension: handle.dimension,
            status,
            channel_booked,
            marks_written,
            mark_count,
            event_id,
        })
    }

    /// Removes the long-memory marks of the handle's dimensions and
    /// returns the number of marks removed. Constructed from the exact
    /// keys, scan-free; a ledger handle names no mark and answers 0.
    ///
    /// # Errors
    ///
    /// [`RiskError::Store`] when the state backend fails.
    pub fn forget(&self, handle: &OutcomeHandle) -> Result<u32, RiskError> {
        match handle.dimension.mark_dimension() {
            None => Ok(0),
            Some(dimension) => self.marks.forget_marks(dimension.key(), &handle.id),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::RiskObservation;
    use crate::network::{CidrNetworkClassifier, NetworkFlags};
    use crate::resources::ResourcePressure;
    use crate::signals::SignalVector;
    use crate::store::Observed;
    use crate::store::TargetState;
    use serde_json::json;
    use std::collections::HashMap;
    use std::sync::Mutex;

    const PRINCIPAL: &str = "9f1c4a7e2b8d63f05a1e9c4d7b2e6f18";
    const SESSION: &str = "c7b3e1f9a5d24708b6e0c8a2f4d69123";
    const TARGET: &str = "5e2a9b4c1d7f38e6a0b5c9d2e4f6a813";
    const DECISION: &str = "d4e5f60718293a4b5c6d7e8f90a1b2c3";

    /// The trust trio: the only outcomes whose paths may lower risk.
    const TRUST_OUTCOMES: [Outcome; 3] = [
        Outcome::ConfirmedLegitimate,
        Outcome::StepUpCompleted,
        Outcome::AuthenticationSuccess,
    ];

    /// The abuse quartet: the only outcomes that write long-memory marks.
    const MARK_OUTCOMES: [Outcome; 4] = [
        Outcome::SpamReported,
        Outcome::Chargeback,
        Outcome::AccountBanned,
        Outcome::FraudConfirmed,
    ];

    /// In-memory marks + ledger + observation store: the unit-test twin
    /// of the PHP RiskStateStoreStub. Cloning shares the state (every
    /// field is an Arc), so the engine owns one clone while the test
    /// inspects through another.
    #[derive(Default, Clone)]
    struct StubStore {
        observed: std::sync::Arc<Mutex<Vec<RiskObservation>>>,
        ledger: std::sync::Arc<Mutex<HashMap<String, Option<bool>>>>,
        marks: std::sync::Arc<Mutex<HashMap<String, MarkRecord>>>,
        seen_mark_events: std::sync::Arc<Mutex<std::collections::HashSet<String>>>,
        target_spread: std::sync::Arc<Mutex<HashMap<String, std::collections::HashSet<String>>>>,
    }

    impl StubStore {
        fn confirm(&self, decision_id: &str, legitimate: bool) -> u8 {
            let mut ledger = self.ledger.lock().unwrap();
            match ledger.get(decision_id) {
                Some(None) => {
                    ledger.insert(decision_id.to_string(), Some(legitimate));
                    1
                }
                _ => 0,
            }
        }

        fn last_observation(&self) -> RiskObservation {
            self.observed
                .lock()
                .unwrap()
                .last()
                .cloned()
                .expect("an observation was booked")
        }
    }

    impl RiskStateStore for StubStore {
        fn observe(&self, o: &RiskObservation) -> Result<Observed, RiskStoreError> {
            self.observed.lock().unwrap().push(o.clone());
            Ok(Observed {
                vector: SignalVector::zero(),
                global_level: 0,
                cooldown_until_ms: 0,
                is_duplicate: false,
            })
        }

        fn register_outcome(
            &self,
            decision_id: &str,
            _scope: u32,
            _decision_hour: i64,
            _score: u32,
        ) -> Result<bool, RiskStoreError> {
            let mut ledger = self.ledger.lock().unwrap();
            if ledger.contains_key(decision_id) {
                return Ok(false);
            }
            ledger.insert(decision_id.to_string(), None);
            Ok(true)
        }

        fn confirm_outcome(
            &self,
            decision_id: &str,
            legitimate: bool,
        ) -> Result<u8, RiskStoreError> {
            Ok(self.confirm(decision_id, legitimate))
        }

        fn correct_outcome(
            &self,
            decision_id: &str,
            legitimate: bool,
        ) -> Result<bool, RiskStoreError> {
            let mut ledger = self.ledger.lock().unwrap();
            match ledger.get_mut(decision_id) {
                Some(current) if *current != Some(legitimate) => {
                    *current = Some(legitimate);
                    Ok(true)
                }
                _ => Ok(false),
            }
        }

        fn register_target_failure(
            &self,
            target_id: &str,
            source: &str,
            asn: &str,
        ) -> Result<TargetState, RiskStoreError> {
            let mut guard = self.target_spread.lock().unwrap();
            let set = guard.entry(target_id.to_string()).or_default();
            if !source.is_empty() {
                set.insert(format!("src:{source}"));
            }
            if !asn.is_empty() {
                set.insert(format!("asn:{asn}"));
            }
            let spread_sources = set.iter().filter(|e| e.starts_with("src:")).count() as u32;
            let spread_asns = set.iter().filter(|e| e.starts_with("asn:")).count() as u32;
            Ok(TargetState {
                fails: 1,
                first_ms: 0,
                last_ms: 0,
                spread_sources,
                spread_asns,
            })
        }

        fn read_target_state(&self, target_id: &str) -> Result<TargetState, RiskStoreError> {
            let set = self.target_spread.lock().unwrap();
            let set = set.get(target_id);
            let spread_sources = set
                .map(|s| s.iter().filter(|e| e.starts_with("src:")).count() as u32)
                .unwrap_or(0);
            let spread_asns = set
                .map(|s| s.iter().filter(|e| e.starts_with("asn:")).count() as u32)
                .unwrap_or(0);
            Ok(TargetState {
                fails: 0,
                first_ms: 0,
                last_ms: 0,
                spread_sources,
                spread_asns,
            })
        }
    }

    impl SessionContextTagStore for StubStore {}
    impl SessionTlsTagStore for StubStore {}

    impl OutcomeMarksStore for StubStore {
        fn mark_key(&self, dimension: &str, id: &str) -> Result<String, RiskError> {
            Ok(format!("mark:{{kiwi:test}}:{dimension}:{id}"))
        }

        fn write_mark(
            &self,
            dimension: &str,
            id: &str,
            kind: &str,
            now_ms: u64,
            event_id: &str,
        ) -> Result<i64, RiskError> {
            if !event_id.is_empty()
                && !self
                    .seen_mark_events
                    .lock()
                    .unwrap()
                    .insert(format!("{dimension}:{id}:{event_id}"))
            {
                return Ok(self
                    .marks
                    .lock()
                    .unwrap()
                    .get(&format!("{dimension}:{id}"))
                    .map(|m| m.count)
                    .unwrap_or(0));
            }
            let mut marks = self.marks.lock().unwrap();
            let key = format!("{dimension}:{id}");
            let entry = marks.entry(key).or_insert(MarkRecord {
                kind: kind.to_string(),
                last_kind: kind.to_string(),
                count: 0,
                first_ms: now_ms as i64,
                last_ms: now_ms as i64,
            });
            if mark_kind_severity(kind) > mark_kind_severity(&entry.kind) {
                entry.kind = kind.to_string();
            }
            entry.last_kind = kind.to_string();
            entry.count += 1;
            entry.last_ms = now_ms as i64;
            Ok(entry.count)
        }

        fn read_mark(&self, dimension: &str, id: &str) -> Result<Option<MarkRecord>, RiskError> {
            Ok(self
                .marks
                .lock()
                .unwrap()
                .get(&format!("{dimension}:{id}"))
                .cloned())
        }

        fn forget_marks(&self, dimension: &str, id: &str) -> Result<u32, RiskError> {
            Ok(self
                .marks
                .lock()
                .unwrap()
                .remove(&format!("{dimension}:{id}"))
                .map_or(0, |_| 1))
        }
    }

    fn classifier() -> CidrNetworkClassifier {
        CidrNetworkClassifier::from_entries(vec![])
    }

    fn engine(store: StubStore) -> RiskEngine<StubStore, CidrNetworkClassifier> {
        RiskEngine::new(
            store,
            classifier(),
            std::sync::Arc::new(
                crate::policy::RiskPolicy::from_config(
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
                .expect("config parses"),
            ),
            crate::keys::RiskKeys::from_master(&[0x42; 32]),
        )
    }

    fn context() -> RiskContext<'static> {
        RiskContext::new(
            1,
            "198.51.100.7".parse().unwrap(),
            None,
            None,
            RiskEventKind::PreIssue,
            NetworkFlags::default(),
            ResourcePressure::default(),
        )
    }

    fn build_handle(dimension: &str, id: &str) -> Result<OutcomeHandle, RiskError> {
        match HandleDimension::from_wire_name(dimension) {
            Some(HandleDimension::Nonce) => OutcomeHandle::nonce(id),
            Some(HandleDimension::DecisionId) => OutcomeHandle::decision_id(id),
            Some(HandleDimension::Principal) => OutcomeHandle::principal(id),
            Some(HandleDimension::Target) => OutcomeHandle::target(id),
            Some(HandleDimension::Session) => OutcomeHandle::session(id),
            Some(HandleDimension::Agent) => OutcomeHandle::agent(id),
            None => Err(RiskError::InvalidOutcomeHandle(format!(
                "unknown dimension {dimension}"
            ))),
        }
    }

    #[test]
    fn mapping_table_is_complete_and_total() {
        let rows = all_mappings();
        assert_eq!(rows.len(), Outcome::ALL.len());
        for (i, row) in rows.iter().enumerate() {
            assert_eq!(
                row.outcome,
                Outcome::ALL[i],
                "one row per outcome, in order"
            );
            assert_eq!(
                mapping(row.outcome),
                *row,
                "the lookup answers the same row"
            );
            assert!(!row.accepted_handles.is_empty());
        }
        assert_eq!(OUTCOME_MAP_VERSION, 1);
        assert_eq!(ledger_dimensions().len(), 2);
        assert_eq!(identity_dimensions().len(), 4);
    }

    #[test]
    fn every_outcome_maps_to_exactly_one_channel_and_mark_behavior() {
        let mut channels: Vec<u8> = Vec::new();
        for row in all_mappings() {
            channels.push(row.channel.as_u8());
            assert_eq!(
                row.mark_kind(),
                row.writes_abuse_mark.then(|| row.outcome.wire_name())
            );
            for dimension in ledger_dimensions() {
                assert_eq!(
                    row.accepts(dimension),
                    row.has_ledger_action(),
                    "{} must accept a ledger handle exactly when it carries a ledger action",
                    row.outcome.wire_name()
                );
            }
            for dimension in identity_dimensions() {
                assert!(
                    row.accepts(dimension),
                    "{} must accept every identity handle",
                    row.outcome.wire_name()
                );
            }
        }
        channels.sort_unstable();
        channels.dedup();
        assert_eq!(channels, vec![8, 9, 10, 11, 12, 13]);
    }

    #[test]
    fn polarity_properties() {
        for row in all_mappings() {
            let name = row.outcome.wire_name();
            if row.may_subtract_risk || row.writes_abuse_mark {
                assert!(row.server_confirmed, "{name} must be server-confirmed");
            }
            if !row.server_confirmed {
                assert!(!row.may_subtract_risk, "{name} may never subtract risk");
                assert!(!row.writes_abuse_mark, "{name} may never write a mark");
            }
            assert!(
                !(row.may_subtract_risk && row.writes_abuse_mark),
                "{name} may not both subtract risk and write an abuse mark"
            );
            if TRUST_OUTCOMES.contains(&row.outcome) {
                assert!(row.may_subtract_risk, "{name} is a trust outcome");
            } else {
                assert!(!row.may_subtract_risk, "{name} must never subtract risk");
            }
            if MARK_OUTCOMES.contains(&row.outcome) {
                assert!(row.writes_abuse_mark, "{name} writes a long-memory mark");
            } else {
                assert!(
                    !row.writes_abuse_mark,
                    "{name} must never write an abuse mark"
                );
            }
            // The channel polarity: trust rows map only onto the trust
            // channels (8, 10, 12); every other row maps only onto the
            // pressure channels (9, 11, 13).
            if row.may_subtract_risk {
                assert!(
                    [8, 10, 12].contains(&row.channel.as_u8()),
                    "{name} trust channel"
                );
            } else {
                assert!(
                    [9, 11, 13].contains(&row.channel.as_u8()),
                    "{name} add-only channel"
                );
            }
        }
        let not_confirmed: Vec<&str> = all_mappings()
            .iter()
            .filter(|row| !row.server_confirmed)
            .map(|row| row.outcome.wire_name())
            .collect();
        assert_eq!(not_confirmed, vec!["authenticationFailure"]);
        assert_eq!(
            mapping(Outcome::AuthenticationSuccess).channel,
            RiskEventKind::AuthenticationSuccess
        );
        assert_eq!(
            mapping(Outcome::AuthenticationFailure).channel,
            RiskEventKind::AuthenticationFailure
        );
    }

    #[test]
    fn raw_identity_handles_are_rejected() {
        assert!(OutcomeHandle::principal("user@example.com").is_err());
        assert!(OutcomeHandle::target("acct-2024-11").is_err());
        assert!(OutcomeHandle::session("short").is_err());
        assert!(OutcomeHandle::session(SESSION.to_uppercase().as_str()).is_err());
        assert!(OutcomeHandle::agent("agent:two").is_err());
        assert!(OutcomeHandle::nonce("").is_err());
        assert!(OutcomeHandle::principal(PRINCIPAL).is_ok());
        assert!(OutcomeHandle::session(SESSION).is_ok());
        assert!(OutcomeHandle::agent("backfill-bot").is_ok());
        assert!(OutcomeHandle::decision_id(DECISION).is_ok());
        // The wire names resolve both ways.
        assert_eq!(
            Outcome::from_wire_name("chargeback"),
            Some(Outcome::Chargeback)
        );
        assert_eq!(Outcome::from_wire_name("unknownOutcome"), None);
        assert_eq!(
            HandleDimension::from_wire_name("decisionId"),
            Some(HandleDimension::DecisionId)
        );
        assert_eq!(MarkDimension::from_key("asn"), Some(MarkDimension::Asn));
        assert_eq!(MarkDimension::from_key("nope"), None);
    }

    #[test]
    fn report_ledger_handle_confirms_the_ledger() {
        let store = StubStore::default();
        store.register_outcome(DECISION, 1, 0, 420).unwrap();
        let engine = engine(store.clone());
        let outcomes = KiwiOutcomes::new(&engine, &store);

        let receipt = outcomes
            .report(
                Outcome::Chargeback,
                &OutcomeHandle::decision_id(DECISION).unwrap(),
                None,
                None,
            )
            .unwrap();
        assert_eq!(receipt.status, 1);
        assert!(!receipt.channel_booked);
        assert_eq!(receipt.marks_written, 0);
        assert!(
            store.observed.lock().unwrap().is_empty(),
            "a contextless ledger report books no feedback event"
        );

        let retry = outcomes
            .report(
                Outcome::Chargeback,
                &OutcomeHandle::decision_id(DECISION).unwrap(),
                None,
                None,
            )
            .unwrap();
        assert_eq!(retry.status, 0, "the retry consumes nothing");
        assert_eq!(
            *store.ledger.lock().unwrap().get(DECISION).unwrap(),
            Some(false)
        );
    }

    #[test]
    fn report_identity_handle_writes_the_mark_and_books_the_channel() {
        let store = StubStore::default();
        let engine = engine(store.clone());
        let outcomes = KiwiOutcomes::new(&engine, &store);

        let receipt = outcomes
            .report(
                Outcome::SpamReported,
                &OutcomeHandle::principal(PRINCIPAL).unwrap(),
                Some("idem-1".to_string()),
                Some(context()),
            )
            .unwrap();
        assert_eq!(receipt.status, 0);
        assert!(receipt.channel_booked);
        assert_eq!(receipt.marks_written, 1);
        assert_eq!(receipt.mark_count, 1);
        let mark = store.read_mark("principal", PRINCIPAL).unwrap().unwrap();
        assert_eq!(mark.kind, "spamReported");
        let observation = store.last_observation();
        assert_eq!(observation.event, RiskEventKind::ProtectedActionFailure);
        // The handle's pseudonym rides the observation verbatim.
        assert_eq!(
            observation.principal_id,
            Some(hex::decode(PRINCIPAL).unwrap()[..16].try_into().unwrap())
        );

        // A contextless deferred report writes the mark only, and the
        // count accumulates with the newest kind on top.
        let receipt = outcomes
            .report(
                Outcome::AccountBanned,
                &OutcomeHandle::principal(PRINCIPAL).unwrap(),
                None,
                None,
            )
            .unwrap();
        assert!(!receipt.channel_booked);
        assert_eq!(receipt.mark_count, 2);
        let mark = store.read_mark("principal", PRINCIPAL).unwrap().unwrap();
        assert_eq!(mark.kind, "accountBanned");
        assert_eq!(mark.count, 2);
    }

    #[test]
    fn session_handle_rides_the_session_slot() {
        let store = StubStore::default();
        let engine = engine(store.clone());
        let outcomes = KiwiOutcomes::new(&engine, &store);

        outcomes
            .report(
                Outcome::AuthenticationFailure,
                &OutcomeHandle::session(SESSION).unwrap(),
                None,
                Some(context()),
            )
            .unwrap();
        let observation = store.last_observation();
        assert_eq!(observation.event, RiskEventKind::AuthenticationFailure);
        assert_eq!(
            observation.session_id,
            Some(hex::decode(SESSION).unwrap()[..16].try_into().unwrap())
        );
        assert!(
            store.read_mark("session", SESSION).unwrap().is_none(),
            "authenticationFailure writes no mark"
        );
    }

    #[test]
    fn target_failures_from_distinct_asns_spread() {
        let store = StubStore::default();
        let engine = engine(store.clone()).with_asn_dataset(std::sync::Arc::new(
            crate::asn::AsnDataset::open(
                std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join("../../protocol/asn/sample-asn.tsv"),
            )
            .expect("sample dataset opens"),
        ));
        let outcomes = KiwiOutcomes::new(&engine, &store);

        // 192.0.2.0/24 is AS64496 and 203.0.113.0/27 is AS64500 in the
        // shared sample dataset: two failures from those origins must
        // contribute two distinct asn spread elements.
        for ip in ["192.0.2.7", "203.0.113.9"] {
            let ctx = RiskContext::new(
                1,
                ip.parse().unwrap(),
                None,
                None,
                RiskEventKind::AuthenticationFailure,
                NetworkFlags::default(),
                ResourcePressure::default(),
            );
            outcomes
                .report(
                    Outcome::AuthenticationFailure,
                    &OutcomeHandle::target(TARGET).unwrap(),
                    None,
                    Some(ctx),
                )
                .unwrap();
        }

        let state = RiskStateStore::read_target_state(&store, TARGET).unwrap();
        assert!(
            state.spread_asns >= 2,
            "two distinct ASNs must spread at least 2 (got {})",
            state.spread_asns
        );
        let spread = store.target_spread.lock().unwrap();
        let elements = spread.get(TARGET).expect("spread recorded");
        assert_eq!(
            elements.iter().filter(|e| e.starts_with("asn:")).count(),
            2,
            "got {elements:?}"
        );
    }

    #[test]
    fn report_rejects_unmapped_handle_dimensions() {
        let store = StubStore::default();
        let engine = engine(store.clone());
        let outcomes = KiwiOutcomes::new(&engine, &store);
        for (outcome, handle) in [
            (
                Outcome::StepUpCompleted,
                OutcomeHandle::decision_id(DECISION).unwrap(),
            ),
            (
                Outcome::AuthenticationSuccess,
                OutcomeHandle::nonce("0f1e2d3c4b5a69788796a5b4c3d2e1f0").unwrap(),
            ),
            (
                Outcome::SpamReported,
                OutcomeHandle::decision_id(DECISION).unwrap(),
            ),
            (
                Outcome::AuthenticationFailure,
                OutcomeHandle::nonce("0f1e2d3c4b5a69788796a5b4c3d2e1f0").unwrap(),
            ),
        ] {
            let err = outcomes.report(outcome, &handle, None, None).unwrap_err();
            assert!(
                matches!(err, RiskError::InvalidOutcomeHandle(_)),
                "{} must reject a {} handle (got {err:?})",
                outcome.wire_name(),
                handle.dimension.wire_name()
            );
        }
    }

    #[test]
    fn forget_removes_marks_and_counts() {
        let store = StubStore::default();
        let engine = engine(store.clone());
        let outcomes = KiwiOutcomes::new(&engine, &store);

        outcomes
            .report(
                Outcome::FraudConfirmed,
                &OutcomeHandle::target(TARGET).unwrap(),
                None,
                None,
            )
            .unwrap();
        outcomes
            .report(
                Outcome::Chargeback,
                &OutcomeHandle::principal(PRINCIPAL).unwrap(),
                None,
                None,
            )
            .unwrap();

        assert_eq!(
            outcomes
                .forget(&OutcomeHandle::target(TARGET).unwrap())
                .unwrap(),
            1
        );
        assert!(store.read_mark("target", TARGET).unwrap().is_none());
        assert!(
            store.read_mark("principal", PRINCIPAL).unwrap().is_some(),
            "other dimensions stay"
        );
        assert_eq!(
            outcomes
                .forget(&OutcomeHandle::target(TARGET).unwrap())
                .unwrap(),
            0
        );
        assert_eq!(
            outcomes
                .forget(&OutcomeHandle::decision_id(DECISION).unwrap())
                .unwrap(),
            0
        );
    }

    #[test]
    fn outcome_vectors_match_exactly() {
        let path = std::env::var("RISK_OUTCOMES_VECTORS_PATH").unwrap_or_else(|_| {
            concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../protocol/risk-v1/outcomes-vectors.json"
            )
            .to_string()
        });
        let raw = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("outcome vectors file not readable at {path}: {e}"));
        let vectors: serde_json::Value = serde_json::from_str(&raw).expect("vectors parse");
        assert_eq!(vectors["version"], OUTCOME_MAP_VERSION);

        // The key-building surface: the store constructor is lazy, so a
        // client pointed at a dead port never connects for mark_key.
        let client = ::redis::Client::open("redis://127.0.0.1:1/").unwrap();
        let store = RedisRiskStateStore::new(client, vectors["namespace"].as_str().unwrap());

        let mut seen: Vec<&str> = Vec::new();
        for vector in vectors["vectors"].as_array().expect("vectors array") {
            let outcome = Outcome::from_wire_name(vector["outcome"].as_str().unwrap())
                .expect("known outcome wire name");
            seen.push(outcome.wire_name());
            let dimension = vector["handle"]["dimension"].as_str().unwrap();
            let id = vector["handle"]["id"].as_str().unwrap();

            if vector["accepted"].as_bool() == Some(false) {
                if vector.get("reject").and_then(|r| r.as_str()) == Some("identifier") {
                    assert!(
                        build_handle(dimension, id).is_err(),
                        "{dimension} must reject {id}"
                    );
                } else {
                    let handle = build_handle(dimension, id).unwrap();
                    assert!(
                        !mapping(outcome).accepts(handle.dimension),
                        "{} must reject a {dimension} handle",
                        outcome.wire_name()
                    );
                }
                continue;
            }

            let handle = build_handle(dimension, id).unwrap();
            let map = mapping(outcome);
            assert!(map.accepts(handle.dimension));
            assert_eq!(vector["channel_value"], json!(map.channel.as_u8()));
            assert_eq!(vector["writes_abuse_mark"], json!(map.writes_abuse_mark));
            assert_eq!(vector["server_confirmed"], json!(map.server_confirmed));
            assert_eq!(vector["may_subtract_risk"], json!(map.may_subtract_risk));
            assert_eq!(vector["mark_kind"].as_str(), map.mark_kind());
            let expected_ledger = vector["ledger_action"].as_str();
            let actual_ledger = map
                .ledger_legitimate
                .map(|legitimate| if legitimate { "L" } else { "A" });
            assert_eq!(expected_ledger, actual_ledger);

            if let Some(expected) = vector["mark_key"].as_str() {
                let dimension_key = handle
                    .dimension
                    .mark_dimension()
                    .map(|d| d.key())
                    .unwrap_or_default();
                assert_eq!(
                    RedisRiskStateStore::mark_key(&store, dimension_key, &handle.id).unwrap(),
                    expected
                );
            }
        }

        seen.sort_unstable();
        seen.dedup();
        let mut expected: Vec<&str> = Outcome::ALL.iter().map(|o| o.wire_name()).collect();
        expected.sort_unstable();
        assert_eq!(
            seen, expected,
            "the vectors must cover the whole vocabulary"
        );

        for row in vectors["store_marks"]
            .as_array()
            .expect("store marks array")
        {
            assert_eq!(
                RedisRiskStateStore::mark_key(
                    &store,
                    row["dimension"].as_str().unwrap(),
                    row["id"].as_str().unwrap()
                )
                .unwrap(),
                row["key"].as_str().unwrap()
            );
        }
    }

    // ── Real-Redis marks tests, gated on the Redis URL variable ──

    const T0: u64 = 1_700_000_000_000;

    fn redis_url() -> Option<String> {
        match std::env::var("RISK_REDIS_URL") {
            Ok(url) if !url.is_empty() => Some(
                url.strip_prefix("tcp://")
                    .map(|rest| format!("redis://{rest}"))
                    .unwrap_or(url),
            ),
            _ => None,
        }
    }

    fn unique_namespace(prefix: &str) -> String {
        let mut suffix = [0u8; 4];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut suffix);
        format!("{prefix}{}", hex::encode(suffix))
    }

    fn redis_store(mark_ttl_secs: Option<u64>) -> Option<RedisRiskStateStore> {
        let url = redis_url()?;
        let client = ::redis::Client::open(url).expect("url parses");
        let mut store = RedisRiskStateStore::new(client, &unique_namespace("outcomes"))
            .with_io_timeouts(2_000, 2_000);
        if let Some(ttl) = mark_ttl_secs {
            store = store.with_mark_ttl_secs(ttl);
        }
        Some(store)
    }

    fn hex32(seed: char) -> String {
        std::iter::repeat_n(seed, 32).collect()
    }

    fn raw_observation(event: RiskEventKind, event_id: &str, now_ms: u64) -> RiskObservation {
        RiskObservation {
            event,
            scope: 1,
            source_epoch: ((now_ms / 1000) / 900) as i64,
            source_id_prev: hex32('a'),
            source_id: hex32('a'),
            source_id_next: hex32('a'),
            subnet_epoch: ((now_ms / 1000) / 900) as i64,
            subnet_id_prev: hex32('b'),
            subnet_id: hex32('b'),
            subnet_id_next: hex32('b'),
            session_id: None,
            principal_id: None,
            event_id: event_id.to_string(),
            network_risk: 0,
            now_ms,
        }
    }

    #[test]
    fn mark_write_carries_count_first_last_and_the_ninety_day_ttl() {
        let Some(store) = redis_store(None) else {
            eprintln!("skipping: RISK_REDIS_URL not set");
            return;
        };
        let key = store.mark_key("principal", PRINCIPAL).unwrap();

        assert_eq!(
            store
                .write_mark("principal", PRINCIPAL, "spamReported", T0, "")
                .unwrap(),
            1
        );
        assert_eq!(
            store
                .write_mark("principal", PRINCIPAL, "chargeback", T0 + 5_000, "")
                .unwrap(),
            2
        );
        let mark = store.read_mark("principal", PRINCIPAL).unwrap().unwrap();
        assert_eq!(mark.kind, "chargeback", "max-severity kind is kept");
        assert_eq!(mark.last_kind, "chargeback");
        assert_eq!(mark.count, 2);
        // The mark clock is the server's TIME (marks.lua ignores the
        // caller timestamp), so the stamps are wall-clock, not T0.
        let now = crate::now_ms() as i64;
        assert!(mark.first_ms > now - 60_000 && mark.first_ms <= now + 1_000);
        assert!(mark.last_ms >= mark.first_ms && mark.last_ms <= now + 1_000);
        let pttl: i64 = {
            use ::redis::Commands;
            let mut conn = store_pool_connection(&store);
            conn.pttl(&key).unwrap()
        };
        assert!(pttl > crate::redis::DEFAULT_MARK_TTL_SECS as i64 * 1000 - 10_000);
        assert!(pttl <= crate::redis::DEFAULT_MARK_TTL_SECS as i64 * 1000);

        use ::redis::Commands;
        let mut conn = store_pool_connection(&store);
        let removed: i64 = conn.del(&key).unwrap();
        assert_eq!(removed, 1);
        assert!(store.read_mark("principal", PRINCIPAL).unwrap().is_none());
        assert_eq!(
            store.forget_marks("principal", PRINCIPAL).unwrap(),
            0,
            "a second forget is a no-op"
        );
    }

    #[test]
    fn mark_severity_never_downgrades_and_the_latest_is_kept_separately() {
        let Some(store) = redis_store(None) else {
            eprintln!("skipping: RISK_REDIS_URL not set");
            return;
        };
        store
            .write_mark("principal", PRINCIPAL, "chargeback", T0, "")
            .unwrap();
        store
            .write_mark("principal", PRINCIPAL, "spamReported", T0 + 1_000, "")
            .unwrap();
        let mark = store.read_mark("principal", PRINCIPAL).unwrap().unwrap();
        assert_eq!(mark.kind, "chargeback", "a mild report never downgrades");
        assert_eq!(mark.last_kind, "spamReported", "latest is kept separately");
        assert_eq!(mark.count, 2);
        store.forget_marks("principal", PRINCIPAL).unwrap();
    }

    #[test]
    fn mark_writes_dedupe_by_event_id() {
        let Some(store) = redis_store(None) else {
            eprintln!("skipping: RISK_REDIS_URL not set");
            return;
        };
        let event = "cafe".repeat(16);
        assert_eq!(
            store
                .write_mark("session", SESSION, "accountBanned", T0, &event)
                .unwrap(),
            1
        );
        assert_eq!(
            store
                .write_mark("session", SESSION, "accountBanned", T0 + 5, &event)
                .unwrap(),
            1,
            "a retried report must not double-count"
        );
        assert_eq!(
            store
                .write_mark("session", SESSION, "accountBanned", T0 + 5, &"beef".repeat(16))
                .unwrap(),
            2
        );
        assert_eq!(
            store.read_mark("session", SESSION).unwrap().unwrap().count,
            2
        );
        store.forget_marks("session", SESSION).unwrap();
        let _: i64 = {
            use ::redis::Commands;
            let mut conn = store_pool_connection(&store);
            conn.del(format!(
                "mark:{{kiwi:{}}}:dd:{event}",
                store.namespace()
            ))
            .unwrap()
        };
    }

    #[test]
    fn every_write_refreshes_the_whole_key_ttl() {
        let Some(store) = redis_store(Some(6)) else {
            eprintln!("skipping: RISK_REDIS_URL not set");
            return;
        };
        let key = store.mark_key("session", SESSION).unwrap();
        use ::redis::Commands;
        let mut conn = store_pool_connection(&store);

        store
            .write_mark("session", SESSION, "accountBanned", T0, "")
            .unwrap();
        std::thread::sleep(std::time::Duration::from_secs(2));
        let decayed: i64 = conn.pttl(&key).unwrap();
        assert!(
            decayed <= 4_000,
            "the mark window must measurably decay first"
        );

        store
            .write_mark("session", SESSION, "fraudConfirmed", T0, "")
            .unwrap();
        let refreshed: i64 = conn.pttl(&key).unwrap();
        assert!(
            refreshed > decayed + 1_000,
            "the second write must re-arm the full mark TTL"
        );

        let removed: i64 = conn.del(&key).unwrap();
        assert_eq!(removed, 1);
    }

    #[test]
    fn report_resolves_the_ledger_mark_and_channel_over_real_surfaces() {
        let Some(url) = redis_url() else {
            eprintln!("skipping: RISK_REDIS_URL not set");
            return;
        };
        let client = ::redis::Client::open(url).unwrap();
        let namespace = unique_namespace("outcomes");
        let engine_store =
            RedisRiskStateStore::new(client.clone(), &namespace).with_io_timeouts(2_000, 2_000);
        // The marks store shares the namespace, so both stores address
        // the same keys: the engine owns one, the facade borrows the
        // other (the engine's store is not reachable from outside).
        let store = RedisRiskStateStore::new(client, &namespace).with_io_timeouts(2_000, 2_000);
        let decision_id = hex::encode(rand::random::<[u8; 16]>());
        let ledger_key = format!(
            "{{kiwi:{}}}:outcome:{decision_id}",
            engine_store.namespace()
        );
        let mark_key = store.mark_key("principal", PRINCIPAL).unwrap();

        let engine = RiskEngine::new(
            engine_store,
            classifier(),
            std::sync::Arc::new(
                crate::policy::RiskPolicy::from_config(
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
                .expect("config parses"),
            ),
            crate::keys::RiskKeys::from_master(&[0x42; 32]),
        );
        let outcomes = KiwiOutcomes::new(&engine, &store);
        use ::redis::Commands;
        let mut conn = store_pool_connection(&store);

        assert!(store.register_outcome(&decision_id, 1, 0, 420).unwrap());
        let receipt = outcomes
            .report(
                Outcome::Chargeback,
                &OutcomeHandle::decision_id(&decision_id).unwrap(),
                None,
                None,
            )
            .unwrap();
        assert_eq!(receipt.status, 1);
        assert_eq!(
            receipt.marks_written, 0,
            "a ledger handle names no mark dimension"
        );
        let ledger: String = conn.get(&ledger_key).unwrap();
        assert!(ledger.contains("\"o\":\"A\""));

        let receipt = outcomes
            .report(
                Outcome::SpamReported,
                &OutcomeHandle::principal(PRINCIPAL).unwrap(),
                Some("idem-rust-1".to_string()),
                Some(context()),
            )
            .unwrap();
        assert_eq!(receipt.marks_written, 1);
        assert!(receipt.channel_booked);
        let mark = store.read_mark("principal", PRINCIPAL).unwrap().unwrap();
        assert_eq!(mark.kind, "spamReported");

        // The trust trio never writes an abuse mark.
        outcomes
            .report(
                Outcome::ConfirmedLegitimate,
                &OutcomeHandle::principal(PRINCIPAL).unwrap(),
                None,
                Some(context()),
            )
            .unwrap();
        assert_eq!(
            store
                .read_mark("principal", PRINCIPAL)
                .unwrap()
                .unwrap()
                .kind,
            "spamReported",
            "trust outcomes never touch marks"
        );

        assert_eq!(
            outcomes
                .forget(&OutcomeHandle::principal(PRINCIPAL).unwrap())
                .unwrap(),
            1
        );
        assert!(store.read_mark("principal", PRINCIPAL).unwrap().is_none());

        let _: i64 = conn.del(&ledger_key).unwrap();
        let _: i64 = conn.del(&mark_key).unwrap();
    }

    /// The state-level polarity proof: after attacker evidence is seeded
    /// at T0, applying any mapped outcome event at the same timestamp
    /// leaves every attacker channel undamaged, and trust credit flows
    /// only through the mapped trust channels. Decay is pinned to zero
    /// by the shared timestamp, so any decrease would be the event
    /// itself subtracting attacker risk.
    #[test]
    fn no_outcome_event_ever_lowers_attacker_added_risk() {
        let Some(store) = redis_store(None) else {
            eprintln!("skipping: RISK_REDIS_URL not set");
            return;
        };
        for row in all_mappings() {
            let mut seeded = None;
            for seed in [RiskEventKind::InvalidProof, RiskEventKind::ReplayAttempt] {
                let reply = store
                    .observe_full(&raw_observation(
                        seed,
                        &hex::encode(rand::random::<[u8; 16]>()),
                        T0,
                    ))
                    .unwrap();
                seeded = Some(reply.vector);
            }
            let seeded = seeded.unwrap();
            let after = store
                .observe_full(&raw_observation(
                    row.channel,
                    &hex::encode(rand::random::<[u8; 16]>()),
                    T0,
                ))
                .unwrap()
                .vector;

            for (name, before, current) in [
                ("bad_proof", seeded.bad_proof, after.bad_proof),
                ("malformed", seeded.malformed, after.malformed),
                ("replay", seeded.replay, after.replay),
                (
                    "action_failure",
                    seeded.action_failure,
                    after.action_failure,
                ),
            ] {
                assert!(
                    current >= before,
                    "{} (channel {}) must never lower the attacker channel {}",
                    row.outcome.wire_name(),
                    row.channel.as_u8(),
                    name
                );
            }
            if row.may_subtract_risk {
                assert!(
                    after.trust_credit > seeded.trust_credit,
                    "{} grants trust through its mapped channel",
                    row.outcome.wire_name()
                );
            } else {
                assert!(
                    after.trust_credit == seeded.trust_credit,
                    "{} (channel {}) must never grant source trust",
                    row.outcome.wire_name(),
                    row.channel.as_u8()
                );
            }
        }

        // Cleanup: the polarity loop shares one namespace, so the ten
        // epoch keys it wrote are removed once at the end.
        let epoch = ((T0 / 1000) / 900) as i64;
        for key in RedisRiskStateStore::keys_for(
            store.raw_namespace(),
            store.namespace_version(),
            epoch,
            &hex32('a'),
            &hex32('a'),
            &hex32('a'),
            epoch,
            &hex32('b'),
            &hex32('b'),
            &hex32('b'),
            None,
            None,
            "cleanup",
        ) {
            use ::redis::Commands;
            let mut conn = store_pool_connection(&store);
            let _: i64 = conn.del(key).unwrap();
        }
    }

    /// Opens a direct connection to the store's Redis (the store's pool
    /// is private; the test only needs plain commands for assertions
    /// and cleanup).
    fn store_pool_connection(_store: &RedisRiskStateStore) -> ::redis::Connection {
        ::redis::Client::open(redis_url().unwrap())
            .unwrap()
            .get_connection()
            .unwrap()
    }
}
