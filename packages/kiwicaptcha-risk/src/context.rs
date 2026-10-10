//! Inputs of one risk assessment.

use std::net::IpAddr;

use crate::event::RiskEventKind;
use crate::network::NetworkFlags;
use crate::resources::ResourcePressure;

/// Inputs of one risk assessment.
pub struct RiskContext<'a> {
    pub scope: u32,
    pub source_ip: IpAddr,
    /// The decoded 16-byte session cookie value (pseudonymized before
    /// storage): the browser carries the cookie as 32 lowercase hex chars,
    /// the caller decodes them. The typed array makes a wrong-length
    /// cookie a compile-time error instead of a runtime panic.
    pub session_id: Option<&'a [u8; 16]>,
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
        session_id: Option<&'a [u8; 16]>,
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

/// The additive risk-v2 context surface: probabilistic evidence that feeds
/// the scorer but is never a security gate and never mutates the risk-v1
/// state contract.
///
/// - `honeypot_hit`: true when ANY honeypot/decoy evidence fired
///   ([`RiskEventKind::is_honeypot`] kinds, or a decoy marker observed by
///   the caller). The engine maps it to the bounded `honeypot` signal.
/// - `client_context_tag`: the ephemeral coarse capability tag of the
///   current request (bounded to [`MAX_CONTEXT_TAG_BYTES`] = 64 bytes,
///   keyed to deployment + session — never a stable device identifier,
///   stable for the session's whole lifetime). The engine compares it
///   against the tag recorded for this session's first tag-bearing
///   request; a longer tag rejects the assessment input (never a silent
///   truncation, which would split one session's identity across tag
///   records).
/// - `tls_tag`: the coarse, server-attested TLS classification tag
///   supplied by trusted reverse-proxy/CDN infrastructure (e.g.
///   "tls13|http2") — never a raw fingerprint database. The engine records
///   only the ephemeral classification as the session's first-seen tag and
///   compares the current request's tag against it; values over 64 chars
///   are treated as absent by the consuming engine (bounded). The PHP
///   mirror names the field `tlsTag`.
/// - `telemetry_payload`: the raw telemetry-v1 payload text from the
///   solution token (the published schema lives at
///   protocol/telemetry-v1/payload.json). The engine parses it per the
///   schema; a rejected or over-bound payload is the neutral-unknown
///   state, never a negative signal. The PHP mirror names the field
///   `telemetryPayload`.
/// - `solve_ms` and `solve_rung`: the solved challenge's client-reported
///   duration and issued rung key (the client-performance difficulty
///   key). They ride together or not at all; a half-present pair rejects
///   the assessment input. The PHP mirror names them `solveMs` and
///   `solveRung`.
/// - `breached_credential`: true when the caller's breached-password
///   check reports the presented credential as known-breached (the
///   D3.5 local corpus verdict). Step-up-worthy evidence in the same
///   shape as `honeypot_hit`: it forces the interactive step-up before
///   any session credit and never a deny on its own. The PHP mirror
///   names the field `breachedCredential`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RiskV2Context {
    pub honeypot_hit: bool,
    pub client_context_tag: Option<String>,
    pub tls_tag: Option<String>,
    pub telemetry_payload: Option<String>,
    pub solve_ms: Option<u64>,
    pub solve_rung: Option<String>,
    pub breached_credential: bool,
}

/// The contract bound on the risk-v2 session tag strings (bytes), shared
/// with PHP: `assess_v2.lua` rejects longer tags as the last line of
/// defense, and the engines reject the assessment input up front.
pub const MAX_CONTEXT_TAG_BYTES: usize = 64;

/// The contract bound on the telemetry payload string (bytes), shared
/// with PHP: an over-bound payload rejects the assessment input up
/// front, mirroring the tag bound.
pub const MAX_TELEMETRY_PAYLOAD_BYTES: usize = crate::evidence::MAX_PAYLOAD_BYTES;

impl RiskV2Context {
    /// True when the context carries NO risk-v2 evidence at all.
    pub fn is_empty(&self) -> bool {
        !self.honeypot_hit
            && self.client_context_tag.is_none()
            && self.tls_tag.is_none()
            && self.telemetry_payload.is_none()
            && self.solve_ms.is_none()
            && self.solve_rung.is_none()
            && !self.breached_credential
    }

    /// The solve facts as the tuple the evidence stage consumes, or
    /// `None` when absent. A half-present pair never reaches this
    /// method on the engine paths (the validation rejects it first).
    pub fn solve_facts(&self) -> Option<(u64, &str)> {
        match (self.solve_ms, self.solve_rung.as_deref()) {
            (Some(ms), Some(rung)) => Some((ms, rung)),
            _ => None,
        }
    }
}
