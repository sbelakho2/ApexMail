use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub fn is_localhost(host: &str) -> bool {
    let normalized = normalize_host(host);
    matches!(normalized.as_str(), "localhost" | "127.0.0.1" | "::1")
}

pub fn is_private_or_reserved_host(host: &str) -> bool {
    let normalized = normalize_host(host);

    if matches!(
        normalized.as_str(),
        "localhost" | "127.0.0.1" | "::1" | "0.0.0.0"
    ) {
        return true;
    }

    if let Ok(ip) = normalized.parse::<IpAddr>() {
        return is_private_or_reserved_ip(ip);
    }

    // These TLD/suffix patterns are NEVER legitimate for outbound HTTP
    // in an email platform — they are reserved for mDNS, split-horizon DNS,
    // or cloud-metadata endpoints. The primary SSRF defence is IP-range-based
    // (is_private_or_reserved_ip below). This hostname check is a fast-path
    // pre-filter to avoid unnecessary DNS resolution for well-known internal
    // naming conventions.
    normalized.ends_with(".local")
        || normalized.ends_with(".internal")
        || normalized.ends_with(".corp")
        || normalized == "metadata.google.internal"
}

pub fn is_private_or_reserved_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_private_or_reserved_ipv4(v4),
        IpAddr::V6(v6) => is_private_or_reserved_ipv6(v6),
    }
}

fn normalize_host(host: &str) -> String {
    host.trim()
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_ascii_lowercase()
}

fn is_private_or_reserved_ipv4(ip: Ipv4Addr) -> bool {
    let octets = ip.octets();

    ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_broadcast()
        || ip.is_documentation()
        || ip.is_unspecified()
        || (octets[0] == 100 && (octets[1] & 0xC0) == 64)
        || (octets[0] == 198 && (octets[1] == 18 || octets[1] == 19))
        // 240.0.0.0/4 (reserved for future use) and 192.0.0.0/24 (IETF
        // protocol assignments, incl. 192.0.0.8/32 NAT64 IPv4-translatable
        // and 192.0.0.9/32 MDT): neither range is ever a legitimate outbound
        // HTTP target, and both sit outside the std-net predicate family.
        || (octets[0] & 0xF0) == 0xF0
        || (octets[0] == 192 && octets[1] == 0 && octets[2] == 0)
}

fn is_private_or_reserved_ipv6(ip: Ipv6Addr) -> bool {
    // IPv4-mapped (::ffff:a.b.c.d): normalize FIRST so the embedded v4
    // address is judged by the full IPv4 range set. Without this, a mapped
    // address such as ::ffff:169.254.169.254 matches none of the v6
    // predicates below and bypasses the SSRF gate (the cloud-metadata
    // endpoint is reachable over a v6 socket via its mapped form).
    if let Some(v4) = ip.to_ipv4_mapped() {
        return is_private_or_reserved_ipv4(v4);
    }
    ip.is_loopback() || ip.is_unspecified() || ip.is_unique_local() || ip.is_unicast_link_local()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn localhost_detection_handles_ipv4_and_ipv6_forms() {
        assert!(is_localhost("localhost"));
        assert!(is_localhost("127.0.0.1"));
        assert!(is_localhost("::1"));
        assert!(is_localhost("[::1]"));
        assert!(!is_localhost("example.com"));
    }

    #[test]
    fn blocks_private_and_reserved_ipv4_ranges() {
        for ip in [
            "10.0.0.1",
            "172.16.0.1",
            "192.168.1.10",
            "169.254.169.254",
            "100.64.0.1",
            "198.18.0.1",
            "203.0.113.5",
        ] {
            assert!(
                is_private_or_reserved_ip(ip.parse().unwrap()),
                "{ip} should be blocked"
            );
        }
    }

    #[test]
    fn blocks_private_and_reserved_ipv6_ranges() {
        for ip in ["::1", "::", "fe80::1", "fd00::1"] {
            assert!(
                is_private_or_reserved_ip(ip.parse().unwrap()),
                "{ip} should be blocked"
            );
        }
        assert!(!is_private_or_reserved_ip(
            "2001:4860:4860::8888".parse().unwrap()
        ));
    }

    #[test]
    fn blocks_ipv4_mapped_ipv6_forms_of_private_ranges() {
        // The mapped form of every private/reserved v4 range must be judged
        // by its embedded v4 address, not by the (global-looking) v6 wrapper.
        for ip in [
            "::ffff:10.0.0.1",
            "::ffff:172.16.0.1",
            "::ffff:192.168.1.10",
            "::ffff:169.254.169.254",
            "::ffff:127.0.0.1",
            "::ffff:100.64.0.1",
            "::ffff:203.0.113.5",
        ] {
            assert!(
                is_private_or_reserved_ip(ip.parse().unwrap()),
                "{ip} should be blocked"
            );
        }
        // A mapped PUBLIC address stays allowed.
        assert!(!is_private_or_reserved_ip(
            "::ffff:8.8.8.8".parse().unwrap()
        ));
    }

    #[test]
    fn blocks_reserved_ipv4_special_ranges() {
        // 240.0.0.0/4 and 192.0.0.0/24 are reserved and must never be
        // fetched, while public space stays allowed.
        for ip in ["240.0.0.1", "255.255.255.254", "192.0.0.9"] {
            assert!(
                is_private_or_reserved_ip(ip.parse().unwrap()),
                "{ip} should be blocked"
            );
        }
        assert!(!is_private_or_reserved_ip("8.8.4.4".parse().unwrap()));
    }

    #[test]
    fn blocks_internal_hostnames() {
        for host in [
            "localhost",
            "0.0.0.0",
            "metadata.google.internal",
            "service.internal",
            "printer.local",
            "office.corp",
        ] {
            assert!(
                is_private_or_reserved_host(host),
                "{host} should be blocked"
            );
        }

        assert!(!is_private_or_reserved_host("api.apexmail.ee"));
    }
}
