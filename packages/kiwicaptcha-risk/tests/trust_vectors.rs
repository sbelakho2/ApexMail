//! Shared context-bound-trust vectors (protocol/risk-v1/
//! trust-vectors.json): every row pins the bucket id its IP resolves to
//! and the credit decision the policy derives from the recorded raw
//! trust; the PHP mirror (`tests/TrustVectorsTest.php`) derives the
//! identical outputs. `RISK_TRUST_VECTORS_PATH` overrides the corpus
//! location and `RISK_ASN_DATASET_PATH` the sample dataset.

use std::net::IpAddr;

use kiwicaptcha_risk::asn::{AsnDataset, BUCKET_ID_VERSION};
use kiwicaptcha_risk::trust::{bucket_trust_credit, BUCKET_TRUST_SATURATION};

fn vectors_path() -> String {
    std::env::var("RISK_TRUST_VECTORS_PATH")
        .ok()
        .filter(|p| !p.is_empty())
        .unwrap_or_else(|| {
            concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../protocol/risk-v1/trust-vectors.json"
            )
            .to_string()
        })
}

fn corpus() -> serde_json::Value {
    let raw = std::fs::read_to_string(vectors_path())
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", vectors_path()));
    serde_json::from_str(&raw).expect("valid json")
}

fn dataset(vectors: &serde_json::Value) -> AsnDataset {
    if let Some(path) = std::env::var("RISK_ASN_DATASET_PATH")
        .ok()
        .filter(|p| !p.is_empty())
    {
        return AsnDataset::open(path).expect("the sample dataset opens");
    }
    let relative = vectors["dataset_path"].as_str().expect("dataset_path");
    let root = std::path::Path::new(&vectors_path())
        .parent()
        .and_then(|p| p.parent())
        .and_then(|p| p.parent())
        .expect("the corpus sits three levels under the root")
        .to_path_buf();
    AsnDataset::open(root.join(relative)).expect("the sample dataset opens")
}

#[test]
fn shared_trust_vectors_match_php() {
    let doc = corpus();
    assert_eq!(doc["protocol"], "risk-v1");
    assert_eq!(
        doc["bucket_id_version"].as_u64().unwrap(),
        BUCKET_ID_VERSION,
        "the corpus was generated under a different bucket grammar"
    );
    assert_eq!(
        doc["trust_saturation"].as_u64().unwrap(),
        BUCKET_TRUST_SATURATION as u64
    );
    let resolver = dataset(&doc);
    let vectors = doc["vectors"].as_array().expect("vectors array");
    assert!(vectors.len() >= 10, "the vector families must stay rich");
    for vector in vectors {
        let note = vector["note"].as_str().expect("note");
        let ip: IpAddr = vector["ip"].as_str().expect("ip").parse().unwrap();
        let expected_bucket = vector["expected_bucket"].as_str().expect("expected_bucket");
        assert_eq!(
            resolver.bucket_id(ip),
            expected_bucket,
            "vector {note:?} must resolve its bucket"
        );
        let raw = vector["raw_trust"].as_u64().map(|v| v as u32);
        let decision = bucket_trust_credit(expected_bucket, raw);
        assert_eq!(
            decision.credit as u64,
            vector["expected_credit"].as_u64().unwrap(),
            "vector {note:?} credit"
        );
        assert_eq!(
            decision.is_home,
            vector["expected_is_home"].as_bool().unwrap(),
            "vector {note:?} home verdict"
        );
        // Cross-bucket isolation: the same raw trust in a foreign bucket
        // is invisible from the home bucket and vice versa.
        if let Some(raw_value) = raw {
            let foreign = bucket_trust_credit("u4/1", None);
            assert_eq!(foreign.credit, 0, "an absent foreign bucket earns nothing");
            let home_again = bucket_trust_credit(expected_bucket, Some(raw_value));
            assert_eq!(
                home_again, decision,
                "the home decision is reproducible and never decays on a foreign read"
            );
        }
    }
}
