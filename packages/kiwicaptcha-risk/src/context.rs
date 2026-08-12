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
