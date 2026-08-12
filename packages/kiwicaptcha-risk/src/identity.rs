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

use crate::keys::RiskKeys;

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
/// unsigned integer (the two's-complement reinterpretation of a negative
/// `i64` epoch, matching PHP's `pack('J', $epoch)`).
pub fn pseudonym(key: &[u8], context: &[u8], epoch: i64, material: &[u8]) -> [u8; 16] {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(b"kiwi-risk-id-v1\0");
    mac.update(context);
    mac.update(b"\0");
    mac.update(&(epoch as u64).to_be_bytes());
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

/// Derives the epoch-scoped source/subnet pseudonyms and the stable
/// session/principal pseudonyms, mirroring the PHP `RiskIdentityFactory`.
///
/// Every epoch key MUST use the pseudonym HMAC'd with ITS OWN epoch: the
/// engine builds prev/current/next ids at `floor(now/900)-1`,
/// `floor(now/900)`, `floor(now/900)+1` and the store addresses
/// `src:<epoch>:<id>`, `src:<epoch-1>:<id_prev>`, `src:<epoch+1>:<id_next>`
/// (same for `net`).
#[derive(Debug, Clone)]
pub struct RiskIdentityFactory {
    keys: RiskKeys,
    source_epoch_secs: i64,
    subnet_epoch_secs: i64,
    ipv4_prefix: u8,
    ipv6_prefix: u8,
}

impl RiskIdentityFactory {
    /// Contract defaults: 900 s epochs, /24 IPv4 and /56 IPv6 masks.
    pub fn new(keys: RiskKeys) -> RiskIdentityFactory {
        RiskIdentityFactory {
            keys,
            source_epoch_secs: 900,
            subnet_epoch_secs: 900,
            ipv4_prefix: 24,
            ipv6_prefix: 56,
        }
    }

    /// Builds a factory with explicit epoch windows (tests and alternate
    /// deployments); the network masks stay at the contract defaults.
    pub fn with_epochs(
        keys: RiskKeys,
        source_epoch_secs: i64,
        subnet_epoch_secs: i64,
    ) -> RiskIdentityFactory {
        let mut factory = RiskIdentityFactory::new(keys);
        factory.source_epoch_secs = source_epoch_secs;
        factory.subnet_epoch_secs = subnet_epoch_secs;
        factory
    }

    /// Source pseudonym (hex) for the current epoch at `now_secs`.
    pub fn source_id(&self, ip: IpAddr, now_secs: i64) -> String {
        self.source_id_for_epoch(ip, now_secs / self.source_epoch_secs)
    }

    /// Subnet pseudonym (hex) for the current epoch at `now_secs`.
    pub fn subnet_id(&self, ip: IpAddr, now_secs: i64) -> String {
        self.subnet_id_for_epoch(ip, now_secs / self.subnet_epoch_secs)
    }

    /// Source pseudonym (hex) for an EXPLICIT epoch: context `b"src"`,
    /// material = family byte + packed IP.
    pub fn source_id_for_epoch(&self, ip: IpAddr, epoch: i64) -> String {
        hex::encode(pseudonym(
            &self.keys.source,
            b"src",
            epoch,
            &canonical_ip(ip),
        ))
    }

    /// Subnet pseudonym (hex) for an EXPLICIT epoch: context `b"net"`,
    /// material = masked network (/24 IPv4, /56 IPv6).
    pub fn subnet_id_for_epoch(&self, ip: IpAddr, epoch: i64) -> String {
        hex::encode(pseudonym(
            &self.keys.subnet,
            b"net",
            epoch,
            &masked_network(ip, self.ipv4_prefix, self.ipv6_prefix),
        ))
    }

    /// Session pseudonym (context `b"sess"`, no epoch): 16 raw bytes.
    pub fn session_id(&self, raw: &[u8]) -> [u8; 16] {
        pseudonym(&self.keys.session, b"sess", 0, raw)
    }

    /// Principal pseudonym (context `b"prin"`, no epoch): 16 raw bytes.
    pub fn principal_id(&self, raw: &[u8]) -> [u8; 16] {
        pseudonym(&self.keys.principal, b"prin", 0, raw)
    }
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

    #[test]
    fn factory_ids_are_epoch_scoped_hex() {
        let keys = RiskKeys::from_master(&[0x42; 32]);
        let factory = RiskIdentityFactory::new(keys.clone());
        let ip: IpAddr = "203.0.113.27".parse().unwrap();

        let cur = factory.source_id_for_epoch(ip, 7);
        assert_eq!(cur.len(), 32);
        assert!(cur.chars().all(|c| c.is_ascii_hexdigit()));
        // The explicit-epoch construction must equal the canonical HMAC.
        assert_eq!(
            cur,
            hex::encode(pseudonym(&keys.source, b"src", 7, &canonical_ip(ip)))
        );
        // Each epoch gets its own pseudonym: prev/current/next all differ.
        let prev = factory.source_id_for_epoch(ip, 6);
        let next = factory.source_id_for_epoch(ip, 8);
        assert_ne!(cur, prev);
        assert_ne!(cur, next);
        assert_ne!(prev, next);

        let net_cur = factory.subnet_id_for_epoch(ip, 7);
        assert_eq!(
            net_cur,
            hex::encode(pseudonym(
                &keys.subnet,
                b"net",
                7,
                &masked_network(ip, 24, 56)
            ))
        );
        // Source and subnet contexts never collide.
        assert_ne!(cur, net_cur);

        // Current-epoch convenience matches the explicit form.
        assert_eq!(factory.source_id(ip, 7 * 900 + 42), cur);
        assert_eq!(factory.subnet_id(ip, 7 * 900 + 42), net_cur);

        // Session/principal are epoch-free raw pseudonyms.
        assert_eq!(
            factory.session_id(b"raw"),
            pseudonym(&keys.session, b"sess", 0, b"raw")
        );
        assert_eq!(
            factory.principal_id(b"raw"),
            pseudonym(&keys.principal, b"prin", 0, b"raw")
        );
    }

    #[test]
    fn factory_with_epochs_changes_windows() {
        let keys = RiskKeys::from_master(&[0x42; 32]);
        let factory = RiskIdentityFactory::with_epochs(keys, 60, 120);
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        // now_secs 125: source epoch 125/60 = 2, subnet epoch 125/120 = 1.
        assert_eq!(
            factory.source_id(ip, 125),
            factory.source_id_for_epoch(ip, 2)
        );
        assert_eq!(
            factory.subnet_id(ip, 125),
            factory.subnet_id_for_epoch(ip, 1)
        );
    }
}
