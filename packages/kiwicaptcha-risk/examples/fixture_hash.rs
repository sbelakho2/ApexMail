//! Prints the sha256 of the cross-language risk-v1 protocol parity blob.
//!
//! The blob order is fixed and mirrored byte-for-byte by the PHP side
//! (`packages/kiwicaptcha-risk-php/tools/fixture_hash.php`); CI's
//! risk-parity job compares the two hashes:
//!
//!   1. every fixtures.json case's big-endian u16 contract score;
//!   2. the five hkdf-sha256 identity keys of identity_vectors.master_key
//!      in source, subnet, session, principal, event order (32 raw bytes
//!      each);
//!   3. canonical IP bytes and masked networks for the fixed probe list
//!      (IPv4, IPv6, IPv4-mapped IPv6 normalized to IPv4);
//!   4. the identity_vectors derivations as raw 16-byte pseudonyms:
//!      session (from the decoded cookie bytes), principal, source and
//!      subnet (at the fixture epochs);
//!   5. every namespace_vectors derived namespace (utf-8 bytes).
//!
//! Steps 2-5 make this a real protocol parity hash: HKDF keys, canonical
//! IP encoding, IPv4-mapped normalization, subnet masking, the ephemeral
//! pseudonyms and the deployment namespace are all compared across the
//! two implementations, not only the score vector.

use kiwicaptcha_risk::identity::{canonical_ip, masked_network, RiskIdentityFactory};
use kiwicaptcha_risk::keys::RiskKeys;
use kiwicaptcha_risk::namespace::{deployment_namespace, NamespaceVersion};
use kiwicaptcha_risk::score::{score, RiskWeights};
use kiwicaptcha_risk::signals::SignalVector;
use sha2::{Digest, Sha256};
use std::net::IpAddr;

/// The canonical probe list: IPv4, IPv6 and an IPv4-mapped IPv6 that must
/// normalize to its 4-byte IPv4 form on both sides.
const PROBE_IPS: [&str; 4] = [
    "203.0.113.27",
    "192.0.2.1",
    "2001:db8:abcd:12ff:ffff:ffff:ffff:ffff",
    "::ffff:203.0.113.27",
];

fn main() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../protocol/risk-v1/fixtures.json"
    );
    let raw = std::fs::read_to_string(path).expect("fixtures.json must exist at the repo root");
    let fixtures: serde_json::Value = serde_json::from_str(&raw).expect("fixtures.json must parse");
    assert_eq!(fixtures["protocol"], "risk-v1");

    let mut blob: Vec<u8> = Vec::new();

    // 1. Contract scores over the shared signal fixtures.
    let weights: RiskWeights =
        serde_json::from_value(fixtures["weights"].clone()).expect("weights decode");
    let base = fixtures["base_risk"].as_u64().expect("base_risk") as u16;
    for case in fixtures["fixtures"].as_array().expect("fixtures array") {
        let vector: SignalVector =
            serde_json::from_value(case["signals"].clone()).expect("signals decode");
        blob.extend_from_slice(&score(base, &vector, &weights).to_be_bytes());
    }

    // 2. HKDF identity keys from the shared master.
    let identity = &fixtures["identity_vectors"];
    let master = identity["master_key"].as_str().expect("master_key");
    let keys = RiskKeys::from_master(master.as_bytes());
    for key in [
        &keys.source,
        &keys.subnet,
        &keys.session,
        &keys.principal,
        &keys.event,
    ] {
        blob.extend_from_slice(key);
    }

    // 3. Canonical IP encodings and masked networks.
    let factory = RiskIdentityFactory::new(keys);
    for probe in PROBE_IPS {
        let ip: IpAddr = probe.parse().expect("probe IP parses");
        blob.extend_from_slice(&canonical_ip(ip));
        blob.extend_from_slice(&masked_network(ip, 24, 56));
    }

    // 4. The identity golden vectors as raw pseudonym bytes.
    let cookie = identity["session"]["cookie_hex"]
        .as_str()
        .expect("cookie_hex");
    let cookie_raw: [u8; 16] = hex::decode(cookie)
        .expect("cookie hex")
        .try_into()
        .expect("16 bytes");
    blob.extend_from_slice(&factory.session_id(&cookie_raw));
    let principal = identity["principal"]["material_utf8"]
        .as_str()
        .expect("material_utf8");
    blob.extend_from_slice(&factory.principal_id(principal.as_bytes()));
    let source_ip: IpAddr = identity["source"]["ip"].as_str().unwrap().parse().unwrap();
    let source_epoch = identity["source"]["epoch"].as_i64().unwrap();
    blob.extend_from_slice(
        hex::decode(factory.source_id(source_ip, source_epoch * 900))
            .unwrap()
            .as_slice(),
    );
    let subnet_ip: IpAddr = identity["subnet"]["ip"].as_str().unwrap().parse().unwrap();
    let subnet_epoch = identity["subnet"]["epoch"].as_i64().unwrap();
    blob.extend_from_slice(
        hex::decode(factory.subnet_id(subnet_ip, subnet_epoch * 900))
            .unwrap()
            .as_slice(),
    );
    // The IPv6 source /64 vectors: expected, same-/64 sibling and a
    // different /64. Hashing all three pins the masking rule (not only
    // one derived value) across the two implementations.
    let v6 = &identity["source_ipv6"];
    let v6_epoch = v6["epoch"].as_i64().unwrap() * 900;
    for key in ["ip", "sibling_ip", "other_ip"] {
        let ip: IpAddr = v6[key].as_str().unwrap().parse().unwrap();
        blob.extend_from_slice(
            hex::decode(factory.source_id(ip, v6_epoch))
                .unwrap()
                .as_slice(),
        );
    }

    // 5. Deployment namespace derivations from the shared vectors.
    for vector in fixtures["namespace_vectors"]
        .as_array()
        .expect("namespace_vectors")
    {
        let raw_ns = vector["raw"].as_str().expect("raw namespace");
        let version = NamespaceVersion::from_u8(vector["version"].as_u64().unwrap() as u8)
            .expect("known namespace version");
        blob.extend_from_slice(deployment_namespace(raw_ns, version).as_bytes());
    }

    println!("{}", hex::encode(Sha256::digest(&blob)));
}
