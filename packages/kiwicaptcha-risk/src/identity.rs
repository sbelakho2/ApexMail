//! Ephemeral identity derivation, byte-identical with the risk-v1 contract.
//!
//! - `canonical_ip`: family byte `0x04`/`0x06` + packed bytes; IPv4-mapped
//!   IPv6 (`::ffff:a.b.c.d`) and the deprecated IPv4-compatible `0::/96`
//!   form (`::a.b.c.d`, excluding `::` and `::1`) are normalized to the
//!   4-byte IPv4 form.
//! - `pseudonym`: first 16 bytes of
//!   `HMAC-SHA256(key, "kiwi-risk-id-v1\0" || context || "\0" ||
//!    epoch.to_be_bytes() || material)` (epoch big-endian 8 bytes).
//! - `masked_network`: family byte + prefix-masked bytes (IPv4 /24, IPv6
//!   /56 by default).

use std::net::IpAddr;

use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::keys::RiskKeys;
use crate::RiskError;

type HmacSha256 = Hmac<Sha256>;

/// The ASN dimension's rotation window in seconds (six hours), per the
/// risk-v2 identity contract file `protocol/risk-v2/identity.json`.
pub const ASN_EPOCH_SECS: i64 = 21_600;

/// Canonical IP form: family byte (`0x04`/`0x06`) + packed bytes.
///
/// IPv4-mapped IPv6 addresses normalize to the 4-byte IPv4 form, and so
/// do the deprecated IPv4-compatible ones (`::a.b.c.d`), except the
/// unspecified `::` and the loopback `::1`.
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
            let low = u32::from_be_bytes([octets[12], octets[13], octets[14], octets[15]]);
            let compatible = octets[..12].iter().all(|b| *b == 0) && low != 0 && low != 1;
            let mut out = Vec::with_capacity(17);
            if mapped || compatible {
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
/// # Rotation
///
/// Only the source and subnet pseudonyms rotate with their epochs:
/// source epochs follow `source_epoch_secs` (default 900 s) and subnet
/// epochs `subnet_epoch_secs`. Session pseudonyms are stable for the
/// lifetime of the session cookie or its record TTL, and principal
/// pseudonyms for the principal TTL (`principal_ttl_s`, default 24 h).
/// There is no per-request rotation for either stable identity.
///
/// # Rotation
///
/// Only the source and subnet pseudonyms rotate with their epochs:
/// source epochs follow `source_epoch_secs` (default 900 s) and subnet
/// epochs `subnet_epoch_secs`. Session pseudonyms are stable for the
/// lifetime of the session cookie or its record TTL, and principal
/// pseudonyms for the principal TTL (`principal_ttl_s`, default 24 h).
/// There is no per-request rotation for either stable identity.
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
    ///
    /// # Errors
    ///
    /// [`RiskError::InvalidTiming`] when either window is below one
    /// second: a zero window divides by zero in `source_id`/`subnet_id`.
    pub fn with_epochs(
        keys: RiskKeys,
        source_epoch_secs: i64,
        subnet_epoch_secs: i64,
    ) -> Result<RiskIdentityFactory, RiskError> {
        if source_epoch_secs < 1 {
            return Err(RiskError::InvalidTiming(
                "source_epoch_secs",
                source_epoch_secs.max(0) as u64,
            ));
        }
        if subnet_epoch_secs < 1 {
            return Err(RiskError::InvalidTiming(
                "subnet_epoch_secs",
                subnet_epoch_secs.max(0) as u64,
            ));
        }
        let mut factory = RiskIdentityFactory::new(keys);
        factory.source_epoch_secs = source_epoch_secs;
        factory.subnet_epoch_secs = subnet_epoch_secs;
        Ok(factory)
    }

    /// Source pseudonym (hex) for the current epoch at `now_secs`,
    /// with floor division so negative times never alias the epoch-0
    /// bucket.
    pub fn source_id(&self, ip: IpAddr, now_secs: i64) -> String {
        self.source_id_for_epoch(ip, now_secs.div_euclid(self.source_epoch_secs))
    }

    /// Subnet pseudonym (hex) for the current epoch at `now_secs`,
    /// with floor division so negative times never alias the epoch-0
    /// bucket.
    pub fn subnet_id(&self, ip: IpAddr, now_secs: i64) -> String {
        self.subnet_id_for_epoch(ip, now_secs.div_euclid(self.subnet_epoch_secs))
    }

    /// Source pseudonym (hex) for an explicit epoch: context `b"src"`,
    /// material = the shared source identity, `masked_network(ip, 32,
    /// 64)` — the full IPv4 address, or the IPv6 /64. A host controls at
    /// least a /64, so a /128-keyed source would let it rotate addresses
    /// for a fresh pseudonym on every request; the /64 matches the PHP
    /// `RiskIdentityFactory::sourceId()` and every server-side source
    /// budget (`Issuer::canonicalSourceFamily`).
    pub fn source_id_for_epoch(&self, ip: IpAddr, epoch: i64) -> String {
        hex::encode(pseudonym(
            &self.keys.source,
            b"src",
            epoch,
            &masked_network(ip, 32, 64),
        ))
    }

    /// Subnet pseudonym (hex) for an explicit epoch: context `b"net"`,
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
    ///
    /// The material is the decoded 16-byte session cookie value: the
    /// browser carries the cookie as 32 lowercase hex chars and the caller
    /// decodes them before this call, matching the PHP derivation.
    pub fn session_id(&self, raw: &[u8; 16]) -> [u8; 16] {
        pseudonym(&self.keys.session, b"sess", 0, raw)
    }

    /// Principal pseudonym (context `b"prin"`, no epoch): 16 raw bytes.
    pub fn principal_id(&self, raw: &[u8]) -> [u8; 16] {
        pseudonym(&self.keys.principal, b"prin", 0, raw)
    }

    /// ASN pseudonym (hex) for the epoch covering `now_secs`: context
    /// `b"asn"`, material = the ASN bucket id string, keyed by the
    /// subnet HKDF key. The context string and the six-hour rotation
    /// window are declared by the risk-v2 identity contract file
    /// (`protocol/risk-v2/identity.json`), which is their source of
    /// truth; the derivation itself mirrors the source/subnet epoch
    /// pattern above (floor division, epoch big-endian in the HMAC
    /// slot). The bucket id comes from the free ASN dataset and never
    /// identifies a single host.
    pub fn asn_id(&self, bucket: &str, now_secs: i64) -> String {
        hex::encode(pseudonym(
            &self.keys.subnet,
            b"asn",
            now_secs.div_euclid(ASN_EPOCH_SECS),
            bucket.as_bytes(),
        ))
    }

    /// Agent pseudonym (raw 16 bytes): context `b"agent"`, no epoch,
    /// keyed by the principal HKDF key. The material is the configured
    /// verified-agent key id, a deployment identifier with no per-user
    /// cardinality. The context string and the key assignment are
    /// declared by the risk-v2 identity contract file, which is their
    /// source of truth.
    pub fn agent_id(&self, agent_key_id: &str) -> [u8; 16] {
        pseudonym(&self.keys.principal, b"agent", 0, agent_key_id.as_bytes())
    }

    /// Target pseudonym: the full 32-byte HMAC-SHA256 (64 lowercase hex
    /// chars) over a normalized target identifier. The message mirrors
    /// the shared pseudonym framing with context `b"tgt"` and the target
    /// pipeline version in the epoch slot (`"kiwi-risk-id-v1\0tgt\0" ||
    /// version.to_be_bytes() || normalized`), keyed by the master-derived
    /// target key. Unlike the 16-byte identity pseudonyms this digest is
    /// kept whole: the target dimension is keyed by the full digest, and
    /// the version stamp means a pipeline change can never collide with
    /// pseudonyms derived under an earlier pipeline. The caller passes
    /// only the output of [`crate::target::normalize_target`] forward;
    /// the normalized value itself never leaves this boundary.
    pub fn target_id(&self, normalized: &str) -> String {
        crate::target::target_id(&self.keys, normalized)
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
    fn canonical_ip_v4_compatible_v6_normalizes_to_v4_except_unspecified_and_loopback() {
        let compat: IpAddr = "::203.0.113.27".parse().unwrap();
        assert_eq!(canonical_ip(compat), vec![0x04, 203, 0, 113, 27]);

        let mut unspecified = vec![0u8; 17];
        unspecified[0] = 0x06;
        assert_eq!(canonical_ip("::".parse().unwrap()), unspecified);

        let mut loopback = vec![0u8; 17];
        loopback[0] = 0x06;
        loopback[16] = 1;
        assert_eq!(canonical_ip("::1".parse().unwrap()), loopback);
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
        // HMAC-SHA256 over key=0x42*32 and "kiwi-risk-id-v1\0src\0" || epoch(7) || material
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
        let session_raw = [0x5au8; 16];
        assert_eq!(
            factory.session_id(&session_raw),
            pseudonym(&keys.session, b"sess", 0, &session_raw)
        );
        assert_eq!(
            factory.principal_id(b"raw"),
            pseudonym(&keys.principal, b"prin", 0, b"raw")
        );
    }

    #[test]
    fn with_epochs_rejects_zero_windows() {
        let keys = RiskKeys::from_master(&[0x42; 32]);
        assert!(matches!(
            RiskIdentityFactory::with_epochs(keys.clone(), 0, 900),
            Err(RiskError::InvalidTiming("source_epoch_secs", 0))
        ));
        assert!(matches!(
            RiskIdentityFactory::with_epochs(keys, 900, 0),
            Err(RiskError::InvalidTiming("subnet_epoch_secs", 0))
        ));
    }

    #[test]
    fn factory_with_epochs_changes_windows() {
        let keys = RiskKeys::from_master(&[0x42; 32]);
        let factory = RiskIdentityFactory::with_epochs(keys, 60, 120).unwrap();
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

    #[test]
    fn golden_identity_vectors_match_the_shared_fixture() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../protocol/risk-v1/fixtures.json"
        );
        let doc: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
        let vectors = &doc["identity_vectors"];
        let master = vectors["master_key"].as_str().unwrap().as_bytes();
        let factory = RiskIdentityFactory::new(RiskKeys::from_master(master));

        // The session vector pins the representation contract: the HMAC
        // binds the decoded 16 bytes, never the ASCII hex representation.
        let cookie_hex = vectors["session"]["cookie_hex"].as_str().unwrap();
        let raw = hex::decode(cookie_hex).unwrap();
        assert_eq!(
            vectors["session"]["cookie_raw_hex"].as_str().unwrap(),
            cookie_hex,
            "the fixture states both representations of the same 16 bytes"
        );
        assert_eq!(
            hex::encode(factory.session_id((&raw[..]).try_into().unwrap())),
            vectors["session"]["expected_session_id"].as_str().unwrap()
        );

        let principal = vectors["principal"]["material_utf8"].as_str().unwrap();
        assert_eq!(
            hex::encode(factory.principal_id(principal.as_bytes())),
            vectors["principal"]["expected_id"].as_str().unwrap()
        );

        let ip: IpAddr = vectors["source"]["ip"].as_str().unwrap().parse().unwrap();
        let epoch = vectors["source"]["epoch"].as_i64().unwrap();
        assert_eq!(
            factory.source_id_for_epoch(ip, epoch),
            vectors["source"]["expected_id"].as_str().unwrap()
        );
        let net_ip: IpAddr = vectors["subnet"]["ip"].as_str().unwrap().parse().unwrap();
        let net_epoch = vectors["subnet"]["epoch"].as_i64().unwrap();
        assert_eq!(
            factory.subnet_id_for_epoch(net_ip, net_epoch),
            vectors["subnet"]["expected_id"].as_str().unwrap()
        );

        // The IPv6 source is masked to its /64: two hosts in one /64
        // share the source pseudonym, a different /64 does not.
        let v6 = &vectors["source_ipv6"];
        let v6_epoch = v6["epoch"].as_i64().unwrap();
        let v6_ip: IpAddr = v6["ip"].as_str().unwrap().parse().unwrap();
        let sibling: IpAddr = v6["sibling_ip"].as_str().unwrap().parse().unwrap();
        let other: IpAddr = v6["other_ip"].as_str().unwrap().parse().unwrap();
        assert_eq!(
            factory.source_id_for_epoch(v6_ip, v6_epoch),
            v6["expected_id"].as_str().unwrap()
        );
        assert_eq!(
            factory.source_id_for_epoch(v6_ip, v6_epoch),
            factory.source_id_for_epoch(sibling, v6_epoch),
            "a /64 sibling must share the source pseudonym"
        );
        assert_eq!(
            factory.source_id_for_epoch(other, v6_epoch),
            v6["expected_other_id"].as_str().unwrap(),
            "a different /64 must derive a different source pseudonym"
        );
    }
}
