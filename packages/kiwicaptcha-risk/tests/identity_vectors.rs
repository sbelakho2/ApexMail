//! The risk-v2 identity contract and the shared cross-language vector
//! corpus (change.md 3.1.1).
//!
//! Two enforced surfaces. First, the contract file
//! `protocol/risk-v2/identity.json`: this test re-derives every
//! dimension straight from the file's declared context string, epoch
//! policy, key assignment and granularity, and must reproduce the
//! vector the crate computes, so the file is the machine-checked
//! source of truth rather than documentation. Second, the corpus
//! `protocol/risk-v2/identity-fixtures.json`: the identical vectors the
//! PHP mirror asserts in its reader test, byte for byte, null for
//! null.
//!
//! `RISK_IDENTITY_VECTORS_PATH` overrides the corpus location, and
//! `RISK_ASN_DATASET_PATH` the dataset it resolves through (the same
//! overrides the ASN vector lane uses).

use std::net::IpAddr;

use kiwicaptcha_risk::asn::AsnDataset;
use kiwicaptcha_risk::identity::{masked_network, pseudonym, RiskIdentityFactory, ASN_EPOCH_SECS};
use kiwicaptcha_risk::identity_vector::{IdentityVector, IdentityVectorInput, DIMENSIONS};
use kiwicaptcha_risk::keys::RiskKeys;
use kiwicaptcha_risk::RiskTimingConfig;

fn contract_path() -> String {
    std::env::var("RISK_IDENTITY_CONTRACT_PATH").unwrap_or_else(|_| {
        format!(
            "{}/../../protocol/risk-v2/identity.json",
            env!("CARGO_MANIFEST_DIR")
        )
    })
}

fn vectors_path() -> String {
    std::env::var("RISK_IDENTITY_VECTORS_PATH").unwrap_or_else(|_| {
        format!(
            "{}/../../protocol/risk-v2/identity-fixtures.json",
            env!("CARGO_MANIFEST_DIR")
        )
    })
}

fn dataset_path() -> std::path::PathBuf {
    if let Ok(path) = std::env::var("RISK_ASN_DATASET_PATH") {
        return std::path::PathBuf::from(path);
    }
    std::path::Path::new(&vectors_path())
        .parent()
        .expect("the corpus lives in a directory")
        .join("../asn/sample-asn.tsv")
}

fn read_json(path: &str) -> serde_json::Value {
    let bytes = std::fs::read(path).unwrap_or_else(|e| panic!("cannot read {path}: {e}"));
    serde_json::from_slice(&bytes).unwrap_or_else(|e| panic!("cannot parse {path}: {e}"))
}

fn key_for_hkdf_info<'a>(keys: &'a RiskKeys, info: &str) -> &'a [u8; 32] {
    match info {
        "source" => &keys.source,
        "subnet" => &keys.subnet,
        "session" => &keys.session,
        "principal" => &keys.principal,
        "target" => &keys.target,
        other => panic!("unknown hkdf_info in the contract: {other}"),
    }
}

/// The per-dimension epoch the contract file declares for `now`:
/// floor(now / window) for a rotated dimension, the constant 0 for a
/// fixed one (the target dimension's slot carries its pipeline
/// version, handled by the full-digest derivation below).
fn contract_epoch(policy: &serde_json::Value, now: i64) -> i64 {
    match policy["mode"].as_str().expect("epoch mode is a string") {
        "rotated" => now.div_euclid(policy["window_secs"].as_i64().expect("window_secs")),
        "fixed" => 0,
        other => panic!("unknown epoch mode in the contract: {other}"),
    }
}

/// The request-side inputs of one corpus vector, bundled so the
/// re-derivation below stays a three-argument helper.
struct CaseInput<'a> {
    ip: IpAddr,
    bucket: String,
    cookie: Option<[u8; 16]>,
    principal: Option<&'a [u8]>,
    agent: Option<&'a str>,
    normalized_target: Option<&'a str>,
    now: i64,
}

/// Re-derives one dimension exactly as the contract file declares it,
/// through the shared pseudonym primitive rather than the factory
/// methods under test.
fn contract_derivation(
    contract: &serde_json::Value,
    dimension: &str,
    keys: &RiskKeys,
    case: &CaseInput<'_>,
) -> Option<String> {
    let spec = &contract["dimensions"][dimension];
    let context = spec["hmac_context"].as_str().expect("context").as_bytes();
    let info = spec["hkdf_info"].as_str().expect("hkdf_info");
    let key = key_for_hkdf_info(keys, info);
    let material: Vec<u8> = match dimension {
        "source" => masked_network(case.ip, 32, 64),
        "subnet" => {
            let g = &spec["granularity"];
            masked_network(
                case.ip,
                g["ipv4_prefix"].as_u64().expect("v4 prefix") as u8,
                g["ipv6_prefix"].as_u64().expect("v6 prefix") as u8,
            )
        }
        "asn" => case.bucket.as_bytes().to_vec(),
        "session" => case.cookie?.to_vec(),
        "principal" => case.principal?.to_vec(),
        "agent" => case.agent?.as_bytes().to_vec(),
        "target" => {
            let value = case.normalized_target.filter(|t| !t.is_empty())?;
            // The contract's fixed target slot carries the pipeline
            // version, and the digest stays whole at 32 bytes.
            let version = kiwicaptcha_risk::target::TARGET_PIPELINE_VERSION;
            use hmac::Mac;
            let mut mac = <hmac::Hmac<sha2::Sha256>>::new_from_slice(key)
                .expect("HMAC accepts any key length");
            mac.update(b"kiwi-risk-id-v1\0");
            mac.update(context);
            mac.update(b"\0");
            mac.update(&version.to_be_bytes());
            mac.update(value.as_bytes());
            return Some(hex::encode(mac.finalize().into_bytes()));
        }
        other => panic!("unknown dimension in the contract: {other}"),
    };
    let epoch = contract_epoch(&spec["epoch_policy"], case.now);
    Some(hex::encode(pseudonym(key, context, epoch, &material)))
}

#[test]
fn contract_file_declares_the_seven_dimensions_in_order() {
    let contract = read_json(&contract_path());
    assert_eq!(contract["contract"], "kiwicaptcha.identity-v2/1");
    let order: Vec<&str> = contract["dimension_order"]
        .as_array()
        .expect("dimension_order is a list")
        .iter()
        .map(|v| v.as_str().expect("a name"))
        .collect();
    assert_eq!(order, DIMENSIONS.to_vec());
    for name in &order {
        let spec = &contract["dimensions"][name];
        assert!(
            spec["hmac_context"].is_string(),
            "{name} declares a context"
        );
        assert!(spec["hkdf_info"].is_string(), "{name} declares a key");
        assert!(
            spec["granularity"].is_object(),
            "{name} declares granularity"
        );
        assert!(
            spec["epoch_policy"].is_object(),
            "{name} declares an epoch policy"
        );
        assert!(spec["ttl_secs"].is_object() || spec["ttl_secs"].is_null());
        assert!(
            spec["cardinality_bound"].is_u64(),
            "{name} declares a cardinality bound"
        );
        assert_eq!(
            spec["output_bytes"].as_u64().unwrap(),
            if *name == "target" { 32 } else { 16 },
            "{name} declares its pseudonym length"
        );
    }
    // The rotated windows and fixed TTLs the engines carry by default
    // are the contract's, read from the timing configuration rather
    // than a second literal.
    let timing = RiskTimingConfig::default();
    let dims = &contract["dimensions"];
    assert_eq!(
        dims["source"]["epoch_policy"]["window_secs"],
        timing.source_epoch_secs()
    );
    assert_eq!(
        dims["subnet"]["epoch_policy"]["window_secs"],
        timing.subnet_epoch_secs()
    );
    assert_eq!(
        dims["asn"]["epoch_policy"]["window_secs"],
        ASN_EPOCH_SECS as u64
    );
    assert_eq!(
        dims["source"]["ttl_secs"]["fast"],
        timing.session_ttl_secs()
    );
    assert_eq!(
        dims["session"]["ttl_secs"]["fast"],
        timing.session_ttl_secs()
    );
    assert_eq!(
        dims["principal"]["ttl_secs"]["fast"],
        timing.principal_ttl_secs()
    );
}

#[test]
fn the_contract_file_reproduces_every_derived_dimension() {
    let contract = read_json(&contract_path());
    let corpus = read_json(&vectors_path());
    let master = corpus["master_key"]
        .as_str()
        .expect("master key")
        .as_bytes();
    let keys = RiskKeys::from_master(master);
    let factory = RiskIdentityFactory::new(keys.clone());
    let dataset = AsnDataset::open(dataset_path()).expect("the sample dataset opens");

    let mut checked = 0;
    for vector in corpus["vectors"].as_array().expect("a vector list") {
        let ip: IpAddr = vector["client_ip"]
            .as_str()
            .expect("an ip")
            .parse()
            .unwrap();
        let now = vector["now_unix_secs"].as_i64().expect("a time");
        let cookie: Option<[u8; 16]> = vector["session_cookie_hex"].as_str().map(|hex| {
            let raw = hex::decode(hex).expect("hex cookie");
            raw.try_into().expect("16 cookie bytes")
        });
        let principal = vector["principal_id"].as_str().map(str::as_bytes);
        let agent = vector["agent_key_id"].as_str();
        let normalized = vector["target_normalized"].as_str();
        let descriptor = IdentityVectorInput {
            client_ip: ip,
            session_cookie: cookie.as_ref(),
            principal_id: principal,
            agent_key_id: agent,
            target_normalized: normalized,
            asn_dataset: &dataset,
            now_unix_secs: now,
        };
        let derived = IdentityVector::derive(&descriptor, &factory);
        let case = CaseInput {
            ip,
            bucket: dataset.bucket_id(ip),
            cookie,
            principal,
            agent,
            normalized_target: normalized,
            now,
        };
        for name in DIMENSIONS {
            let expected_from_contract = contract_derivation(&contract, name, &keys, &case);
            assert_eq!(
                derived.dimension(name),
                expected_from_contract.as_deref(),
                "vector {} dimension {} diverges from the contract file",
                vector["name"],
                name,
            );
            checked += 1;
        }
    }
    assert!(
        checked >= 12 * 7,
        "the corpus carries {checked} dimension checks"
    );
}

#[test]
fn shared_vectors_reproduce_byte_identically() {
    let corpus = read_json(&vectors_path());
    let dataset_info = AsnDataset::open(dataset_path())
        .expect("the sample dataset opens")
        .dataset_info();
    assert_eq!(
        corpus["asn_dataset"]["sha256"], dataset_info.sha256,
        "the corpus pins the dataset digest it was generated from"
    );
    let master = corpus["master_key"]
        .as_str()
        .expect("master key")
        .as_bytes();
    let factory = RiskIdentityFactory::new(RiskKeys::from_master(master));

    let mut by_name = std::collections::HashMap::new();
    for vector in corpus["vectors"].as_array().expect("a vector list") {
        let name = vector["name"].as_str().expect("a name").to_string();
        let ip: IpAddr = vector["client_ip"]
            .as_str()
            .expect("an ip")
            .parse()
            .unwrap();
        let cookie: Option<[u8; 16]> = vector["session_cookie_hex"].as_str().map(|hex| {
            hex::decode(hex)
                .expect("hex cookie")
                .try_into()
                .expect("16 cookie bytes")
        });
        // The target dimension rides the versioned normalization
        // pipeline: the corpus's raw value must normalize to the
        // corpus's normalized value before the pseudonym is derived.
        let normalized = vector["target_raw"].as_str().map(|raw| {
            let normalized = kiwicaptcha_risk::target::normalize_target(raw);
            assert_eq!(
                Some(normalized.as_str()),
                vector["target_normalized"].as_str(),
                "vector {name}: the normalization pipeline diverges from the corpus"
            );
            normalized
        });
        let descriptor = IdentityVectorInput {
            client_ip: ip,
            session_cookie: cookie.as_ref(),
            principal_id: vector["principal_id"].as_str().map(str::as_bytes),
            agent_key_id: vector["agent_key_id"].as_str(),
            target_normalized: normalized.as_deref(),
            asn_dataset: &AsnDataset::open(dataset_path()).expect("the sample dataset opens"),
            now_unix_secs: vector["now_unix_secs"].as_i64().expect("a time"),
        };
        let derived = IdentityVector::derive(&descriptor, &factory);
        let expected = &vector["expected"];
        for dimension in DIMENSIONS {
            assert_eq!(
                derived.dimension(dimension),
                expected[dimension].as_str(),
                "vector {name} dimension {dimension} diverges from the shared corpus"
            );
        }
        // The resolved bucket is part of the corpus: the derivation
        // and the stated bucket can never drift apart.
        assert_eq!(
            descriptor.asn_dataset.bucket_id(ip),
            vector["expected_asn_bucket"].as_str().expect("a bucket")
        );
        by_name.insert(name, derived);
    }

    // The mapped and compatible v6 spellings derive the identical
    // vectors to their plain v4 counterparts, and a sibling host in
    // the same /64 shares source, subnet and asn.
    let canonical = &by_name["canonical_ipv4_all_dimensions"];
    assert_eq!(by_name["v4_mapped_v6_spelling"], *canonical);
    assert_eq!(
        by_name["v4_compatible_spelling"],
        by_name["boundary_epoch_zero"]
    );
    let ipv6 = &by_name["plain_ipv6_unicode_target"];
    let sibling = &by_name["v6_sibling_same_64"];
    assert_eq!(sibling.source(), ipv6.source());
    assert_eq!(sibling.subnet(), ipv6.subnet());
    assert_eq!(sibling.asn(), ipv6.asn());
    // Epoch 0 covers the whole first window, epoch 1 differs on the
    // rotated dimensions and the fixed ones stay put.
    let zero = &by_name["boundary_epoch_zero"];
    assert_eq!(by_name["boundary_epoch_zero_late_in_window"], *zero);
    let one = &by_name["boundary_epoch_one"];
    assert_ne!(one.source(), zero.source());
    assert_ne!(one.subnet(), zero.subnet());
    assert_eq!(one.asn(), zero.asn(), "900 s stays inside the asn window");
    assert_eq!(one.session(), zero.session());
    assert_eq!(one.principal(), zero.principal());
}
