//! Inputs of one risk assessment.

use std::net::IpAddr;

use crate::event::RiskEventKind;
use crate::network::NetworkFlags;
use crate::resources::ResourcePressure;

/// Inputs of one risk assessment.
pub struct RiskContext<'a> {
    pub scope: u32,
    pub source_ip: IpAddr,
    /// Raw session cookie value (pseudonymized before storage).
    pub session_id: Option<&'a [u8]>,
    /// Application principal id bytes (pseudonymized before storage).
    pub principal_id: Option<&'a [u8]>,
    pub event: RiskEventKind,
    pub network_flags: NetworkFlags,
    pub resources: ResourcePressure,
}

impl<'a> RiskContext<'a> {
    /// Convenience constructor for tests and simple call sites.
    pub fn new(
        scope: u32,
        source_ip: IpAddr,
        session_id: Option<&'a [u8]>,
        principal_id: Option<&'a [u8]>,
        event: RiskEventKind,
        network_flags: NetworkFlags,
        resources: ResourcePressure,
    ) -> RiskContext<'a> {
        RiskContext {
            scope,
            source_ip,
            session_id,
            principal_id,
            event,
            network_flags,
            resources,
        }
    }
}

/// The ADDITIVE risk-v2 context surface: probabilistic evidence that feeds
/// the scorer but is NEVER a security gate and NEVER mutates the risk-v1
/// state contract.
///
/// - `honeypot_hit`: true when ANY honeypot/decoy evidence fired
///   ([`RiskEventKind::is_honeypot`] kinds, or a decoy marker observed by
///   the caller). The engine maps it to the bounded `honeypot` signal.
/// - `client_context_tag`: the ephemeral coarse capability tag of the
///   current request (bounded, keyed to deployment + short epoch + session —
///   never a stable device identifier). The engine compares it against the
///   tag recorded for this session's FIRST tag-bearing request.
/// - `client_context_consistent`: COMPUTED by the engine from the session's
///   first-seen tag record (the risk-v2 session record, same TTL as the
///   risk-v1 session state); callers pass the default and the derivation
///   overwrites it.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RiskV2Context {
    pub honeypot_hit: bool,
    pub client_context_tag: Option<String>,
    pub client_context_consistent: bool,
}

impl RiskV2Context {
    /// True when the context carries NO risk-v2 evidence at all.
    pub fn is_empty(&self) -> bool {
        !self.honeypot_hit && self.client_context_tag.is_none()
    }
}
