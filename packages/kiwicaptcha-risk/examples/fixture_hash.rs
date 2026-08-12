//! Prints the sha256 of the concatenated big-endian u16 fixture scores
//! (protocol/risk-v1/fixtures.json, base_risk 100, contract weights).
//!
//! The PHP side (`packages/kiwicaptcha-risk-php/tools/fixture_hash.php`)
//! prints the identical hash; CI's risk-parity job compares the two.

use kiwicaptcha_risk::score::{score, RiskWeights};
use kiwicaptcha_risk::signals::SignalVector;
use sha2::{Digest, Sha256};

fn main() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../protocol/risk-v1/fixtures.json"
    );
    let raw = std::fs::read_to_string(path).expect("fixtures.json must exist at the repo root");
    let fixtures: serde_json::Value = serde_json::from_str(&raw).expect("fixtures.json must parse");
    assert_eq!(fixtures["protocol"], "risk-v1");

    let weights: RiskWeights =
        serde_json::from_value(fixtures["weights"].clone()).expect("weights decode");
    let base = fixtures["base_risk"].as_u64().expect("base_risk") as u16;

    let mut blob = Vec::with_capacity(fixtures["fixtures"].as_array().map_or(0, |f| f.len() * 2));
    for case in fixtures["fixtures"].as_array().expect("fixtures array") {
        let vector: SignalVector =
            serde_json::from_value(case["signals"].clone()).expect("signals decode");
        blob.extend_from_slice(&score(base, &vector, &weights).to_be_bytes());
    }

    println!("{}", hex::encode(Sha256::digest(&blob)));
}
