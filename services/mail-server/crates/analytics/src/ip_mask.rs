//! GDPR IP masking for the analytics persistence path.
//!
//! Client IP addresses are personal data (GDPR Art. 4(1)); the analytics
//! stores keep events for up to 730 days (Postgres hot store, ClickHouse
//! OLAP, cold JSONL). Every IP is therefore truncated AT INGEST, at the
//! point where the event is persisted:
//!
//! - IPv4 → /24 (last octet zeroed):`203.0.113.178` → `203.0.113.0`
//! - IPv6 → /48 (host bits zeroed):`2001:db8:a:b:c:d:e:f` → `2001:db8:a::`
//!
//! The truncated form keeps network-level geo/ISP analytics working while
//! no longer identifying an individual subscriber. Full client IPs remain
//! ONLY in transient, never-persisted paths (rate limiting, the Redis WAL
//! between flushes, SSE Pub/Sub fan-out).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Mask a client IP for persistence:IPv4 → /24, IPv6 → /48.
///
/// IPv4-mapped IPv6 addresses (`::ffff:203.0.113.7`) are normalised to the
/// embedded IPv4 form first, so they mask as IPv4 instead of collapsing to
/// `::`. Values that do not parse as an IP address are returned unchanged —
/// they carry no address semantics to truncate.
pub fn mask_ip(ip: &str) -> String {
    match ip.parse::<IpAddr>() {
        Ok(IpAddr::V4(v4)) => mask_v4(v4.octets()).to_string(),
        Ok(IpAddr::V6(v6)) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                // IPv4-mapped — mask the embedded IPv4 address.
                mask_v4(v4.octets()).to_string()
            } else {
                mask_v6(v6.segments()).to_string()
            }
        }
        Err(_) => ip.to_string(),
    }
}

/// [`mask_ip`] over the optional `ip_address` column shape used by event
/// rows (`None` stays `None`).
pub fn mask_ip_opt(ip: Option<&str>) -> Option<String> {
    ip.map(mask_ip)
}

/// Zero the host octets of an IPv4 address (→ /24 network).
fn mask_v4(o: [u8; 4]) -> Ipv4Addr {
    Ipv4Addr::new(o[0], o[1], o[2], 0)
}

/// Zero the host bits of an IPv6 address (→ /48 network).
fn mask_v6(s: [u16; 8]) -> Ipv6Addr {
    Ipv6Addr::new(s[0], s[1], s[2], 0, 0, 0, 0, 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipv4_last_octet_is_zeroed() {
        assert_eq!(mask_ip("203.0.113.178"), "203.0.113.0");
        assert_eq!(mask_ip("192.168.1.255"), "192.168.1.0");
        assert_eq!(mask_ip("10.0.0.1"), "10.0.0.0");
    }

    #[test]
    fn ipv4_network_prefix_is_preserved() {
        // Only the LAST octet changes; the /24 prefix survives.
        assert_eq!(&mask_ip("198.51.100.9")[..10], "198.51.100");
    }

    #[test]
    fn ipv6_host_bits_are_zeroed_to_48() {
        assert_eq!(mask_ip("2001:db8:a:b:c:d:e:f"), "2001:db8:a::");
        assert_eq!(
            mask_ip("2001:0db8:0001:0002:0003:0004:0005:0006"),
            "2001:db8:1::"
        );
        // Already-masked input is idempotent.
        assert_eq!(mask_ip("2001:db8:a::"), "2001:db8:a::");
    }

    #[test]
    fn ipv4_mapped_ipv6_masks_as_ipv4() {
        assert_eq!(mask_ip("::ffff:203.0.113.7"), "203.0.113.0");
    }

    #[test]
    fn masking_is_idempotent_for_ipv4() {
        let once = mask_ip("203.0.113.178");
        assert_eq!(mask_ip(&once), once);
    }

    #[test]
    fn non_ip_values_pass_through_unchanged() {
        assert_eq!(mask_ip(""), "");
        assert_eq!(mask_ip("unknown"), "unknown");
        assert_eq!(mask_ip("not-an-ip"), "not-an-ip");
    }

    #[test]
    fn optional_variant_preserves_none() {
        assert_eq!(mask_ip_opt(None), None);
        assert_eq!(mask_ip_opt(Some("203.0.113.9")), Some("203.0.113.0".into()));
    }
}
