//! Ephemeral identity derivation, byte-identical with the risk-v1 contract.
//!
//! - `canonical_ip`: family byte `0x04`/`0x06` + packed bytes; IPv4-mapped
//!   IPv6 (`::ffff:a.b.c.d`) is normalized to the 4-byte IPv4 form.
//! - `pseudonym`: first 16 bytes of
//!   `HMAC-SHA256(key, "kiwi-risk-id-v1\0" || context || "\0" ||
//!    epoch.to_be_bytes() || material)` (epoch big-endian 8 bytes).
//! - `masked_network`: family byte + prefix-masked bytes (IPv4 /24, IPv6
//!   /56 by default).

use std::net::IpAddr;

use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// Canonical IP form: family byte (`0x04`/`0x06`) + packed bytes.
///
/// IPv4-mapped IPv6 addresses normalize to the 4-byte IPv4 form.
pub fn canonical_ip(ip: IpAddr) -> Vec<u8> {
    match ip {
        IpAddr::V4(v4) => {
            let mut out = Vec::with_capacity(5);
            out.push(0x04);
            out.extend_from_slice(&v4.octets());
            out
        }
        IpAddr::V6(v6) => {
            let octets = v6.octets();
            let mapped =
                octets[..10].iter().all(|b| *b == 0) && octets[10] == 0xff && octets[11] == 0xff;
            let mut out = Vec::with_capacity(17);
            if mapped {
                out.push(0x04);
                out.extend_from_slice(&octets[12..]);
            } else {
                out.push(0x06);
                out.extend_from_slice(&octets);
            }
            out
        }
    }
}

/// 128-bit ephemeral pseudonym: the first 16 bytes of the HMAC-SHA256
/// described in the contract. The epoch is encoded as an 8-byte big-endian
/// unsigned integer.
pub fn pseudonym(key: &[u8], context: &[u8], epoch: u64, material: &[u8]) -> [u8; 16] {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(b"kiwi-risk-id-v1\0");
    mac.update(context);
    mac.update(b"\0");
    mac.update(&epoch.to_be_bytes());
    mac.update(material);
    let digest = mac.finalize().into_bytes();
    let mut out = [0u8; 16];
    out.copy_from_slice(&digest[..16]);
    out
}

/// Family byte + prefix-masked bytes (IPv4 default /24, IPv6 default /56).
///
/// The returned vector is in the same canonical form as [`canonical_ip`]
/// (family byte first, then the masked packed bytes).
pub fn masked_network(ip: IpAddr, ipv4_prefix: u8, ipv6_prefix: u8) -> Vec<u8> {
    let canonical = canonical_ip(ip);
    let family = canonical[0];
    let bytes = &canonical[1..];
    let prefix = if family == 0x04 {
        ipv4_prefix
    } else {
        ipv6_prefix
    };
    let max_bits = (bytes.len() * 8) as u8;
    assert!(
        prefix <= max_bits,
        "prefix must be within 0..{max_bits} (got {prefix})"
    );

    let mut out = Vec::with_capacity(bytes.len() + 1);
    out.push(family);
    let mut remaining = prefix;
    for byte in bytes {
        if remaining >= 8 {
            out.push(*byte);
            remaining -= 8;
        } else if remaining > 0 {
            out.push(byte & (0xFFu8 << (8 - remaining)));
            remaining = 0;
        } else {
            out.push(0);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn canonical_ip_v4() {
        let ip: IpAddr = Ipv4Addr::new(203, 0, 113, 27).into();
        assert_eq!(canonical_ip(ip), vec![0x04, 203, 0, 113, 27]);
    }

    #[test]
    fn canonical_ip_v6() {
        let ip: IpAddr = "2001:db8::1".parse().unwrap();
        let expected: Vec<u8> = std::iter::once(0x06)
            .chain(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1).octets())
            .collect();
        assert_eq!(canonical_ip(ip), expected);
    }

    #[test]
    fn canonical_ip_v4_mapped_v6_normalizes_to_v4() {
        let ip: IpAddr = "::ffff:203.0.113.27".parse().unwrap();
        assert_eq!(canonical_ip(ip), vec![0x04, 203, 0, 113, 27]);
    }

    #[test]
    fn pseudonym_is_deterministic() {
        let key = [0x42u8; 32];
        let a = pseudonym(&key, b"src", 7, b"material");
        let b = pseudonym(&key, b"src", 7, b"material");
        assert_eq!(a, b);
        assert_eq!(a.len(), 16);
    }

    #[test]
    fn pseudonym_epochs_are_separated() {
        let key = [0x42u8; 32];
        let a = pseudonym(&key, b"src", 7, b"material");
        let b = pseudonym(&key, b"src", 8, b"material");
        assert_ne!(a, b);
    }

    #[test]
    fn pseudonym_contexts_are_separated() {
        let key = [0x42u8; 32];
        let a = pseudonym(&key, b"src", 7, b"material");
        let b = pseudonym(&key, b"net", 7, b"material");
        assert_ne!(a, b);
    }

    #[test]
    fn pseudonym_matches_contract_shape() {
        // HMAC-SHA256(key=0x42*32, "kiwi-risk-id-v1\0src\0" || epoch(7) || material)
        // prefix must be 16 bytes of the full digest.
        let key = [0x42u8; 32];
        let mut mac = HmacSha256::new_from_slice(&key).unwrap();
        mac.update(b"kiwi-risk-id-v1\0src\0");
        mac.update(&7u64.to_be_bytes());
        mac.update(b"material");
        let digest = mac.finalize().into_bytes();
        let p = pseudonym(&key, b"src", 7, b"material");
        assert_eq!(p, digest[..16]);
    }

    #[test]
    fn mask_ipv4_default_prefix() {
        let ip: IpAddr = Ipv4Addr::new(203, 0, 113, 27).into();
        assert_eq!(masked_network(ip, 24, 56), vec![0x04, 203, 0, 113, 0]);
    }

    #[test]
    fn mask_ipv4_custom_prefix() {
        let ip: IpAddr = Ipv4Addr::new(203, 0, 113, 27).into();
        // /16 keeps the first two bytes.
        assert_eq!(masked_network(ip, 16, 56), vec![0x04, 203, 0, 0, 0]);
        // /32 keeps everything.
        assert_eq!(masked_network(ip, 32, 56), vec![0x04, 203, 0, 113, 27]);
        // /0 zeroes everything.
        assert_eq!(masked_network(ip, 0, 56), vec![0x04, 0, 0, 0, 0]);
    }

    #[test]
    fn mask_ipv6_default_prefix() {
        let ip: IpAddr = "2001:db8:abcd:1234:5678:9abc:def0:1234".parse().unwrap();
        let masked = masked_network(ip, 24, 56);
        assert_eq!(masked.len(), 17);
        assert_eq!(masked[0], 0x06);
        let octets = match ip {
            IpAddr::V6(v6) => v6.octets(),
            _ => unreachable!(),
        };
        // /56 keeps the first 7 bytes exactly, zeroes the rest.
        assert_eq!(&masked[1..8], &octets[..7]);
        assert!(masked[8..].iter().all(|b| *b == 0));
    }

    #[test]
    fn mask_ipv6_custom_prefix() {
        let ip: IpAddr = "2001:db8:abcd:1234::1".parse().unwrap();
        let masked = masked_network(ip, 24, 64);
        assert_eq!(masked[0], 0x06);
        let octets = match ip {
            IpAddr::V6(v6) => v6.octets(),
            _ => unreachable!(),
        };
        assert_eq!(&masked[1..9], &octets[..8]);
        assert!(masked[9..].iter().all(|b| *b == 0));
    }
}
