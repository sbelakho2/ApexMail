//! Delivery-route resolution: SES shared pool vs a dedicated source IP.
//!
//! ## Routing rule (non-negotiable)
//!
//! | Warmup-IP selection for the send | Route |
//! |----------------------------------|-------|
//! | A warming `dedicated_ips` row is selected (`Domain::warmup_ip`) | [`DeliveryRoute::Dedicated`] — the relay MTA must bind its recipient-facing socket to that IP |
//! | None | [`DeliveryRoute::SesShared`] — AWS SES shared IP pool |
//!
//! There is **no** per-tenant preference toggle: the presence of a selected
//! dedicated IP is the sole determinant. A tenant with dedicated IPs still
//! sends every unit through the dedicated route; a tenant without one rides
//! the shared pool. The processor derives the route per send from the same
//! warmup-IP identity its admission gate keys on, so the admission decision
//! and the network path cannot disagree.
//!
//! ## Why this module no longer contains a transport
//!
//! Route resolution used to live here behind a SECOND `EmailTransport`
//! trait (with a `bind_ip` `TransportConfig`, a `send_raw_email` path and a
//! DB-backed `TransportRouter` cache) that the running processor never
//! called. Two transport abstractions existed and only one was live — so
//! warmup admission could reserve capacity on an IP nothing actually sent
//! from (release-blocker 15). The duplicate trait, its send path, its cache
//! and its wrapper were deleted. The single active contract is
//! `email::transport::EmailTransport::send(&PreparedEmail, &DeliveryRoute)
//! -> ProcessorResult<DeliveryReceipt>`.
//!
//! What remains is a pure mapping from a resolved route to the transport
//! kind that can honour it: no database, no cache, no second send path.

use super::types::DeliveryRoute;

/// Which backend a resolved [`DeliveryRoute`] is bound to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportKind {
    /// AWS SES shared IP pool — no dedicated source IP to bind.
    SesShared,
    /// Self-hosted relay MTA carrying a dedicated source IP.
    Dedicated,
}

impl std::fmt::Display for TransportKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TransportKind::SesShared => write!(f, "ses-shared"),
            TransportKind::Dedicated => write!(f, "dedicated"),
        }
    }
}

/// The transport kind a resolved route requires. Pure, total, and the only
/// routing decision left in this module.
pub fn transport_kind_for(route: &DeliveryRoute) -> TransportKind {
    match route {
        DeliveryRoute::SesShared => TransportKind::SesShared,
        DeliveryRoute::Dedicated { .. } => TransportKind::Dedicated,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transport_kind_follows_the_resolved_route() {
        assert_eq!(
            transport_kind_for(&DeliveryRoute::SesShared),
            TransportKind::SesShared
        );
        assert_eq!(
            transport_kind_for(&DeliveryRoute::Dedicated {
                dedicated_ip_id: "dip-1".into(),
                source_ip: "203.0.113.9".parse().expect("valid test IP"),
            }),
            TransportKind::Dedicated
        );
        assert_eq!(TransportKind::SesShared.to_string(), "ses-shared");
        assert_eq!(TransportKind::Dedicated.to_string(), "dedicated");
    }
}
