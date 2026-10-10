//! Shared ASN-resolution vectors (protocol/risk-v1/asn-vectors.json):
//! every query IP runs through the dataset loader under the recorded
//! sample digest; the PHP mirror (`tests/AsnVectorsTest.php`) resolves
//! the identical bucket ids. The corpus pins the listed resolutions
//! (every row shape), the gap fallbacks (v4 /16, v6 /32), the
//! v4-mapped/v4-compatible normalizations and the malformed-row
//! accounting. Pure — no Redis. `RISK_ASN_VECTORS_PATH` overrides the
//! corpus location and `RISK_ASN_DATASET_PATH` the sample dataset.

use std::net::IpAddr;

use kiwicaptcha_risk::asn::{
    is_valid_bucket_id, AsnDataset, AsnError, BUCKET_ID_VERSION, DATASET_FORMAT_VERSION,
};

fn vectors_path() -> String {
    std::env::var("RISK_ASN_VECTORS_PATH")
        .ok()
        .filter(|p| !p.is_empty())
        .unwrap_or_else(|| {
            concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../protocol/risk-v1/asn-vectors.json"
            )
            .to_string()
        })
}

fn dataset_path(vectors: &serde_json::Value) -> String {
    std::env::var("RISK_ASN_DATASET_PATH")
        .ok()
        .filter(|p| !p.is_empty())
        .unwrap_or_else(|| {
            let relative = vectors["dataset_path"].as_str().expect("dataset_path");
            // The corpus lives at <root>/protocol/risk-v1; the dataset
            // path is root-relative.
            let corpus = std::path::Path::new(&vectors_path())
                .parent()
                .and_then(|p| p.parent())
                .and_then(|p| p.parent())
                .expect("the corpus sits three levels under the root")
                .to_path_buf();
            corpus.join(relative).display().to_string()
        })
}

fn corpus() -> serde_json::Value {
    let raw = std::fs::read_to_string(vectors_path())
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", vectors_path()));
    serde_json::from_str(&raw).expect("valid json")
}

#[test]
fn shared_asn_vectors_match_php() {
    let doc = corpus();
    assert_eq!(doc["protocol"], "risk-v1");
    assert_eq!(
        doc["dataset_format_version"].as_u64().unwrap(),
        DATASET_FORMAT_VERSION,
        "the corpus was generated under a different format version"
    );
    assert_eq!(
        doc["bucket_id_version"].as_u64().unwrap(),
        BUCKET_ID_VERSION,
        "the corpus was generated under a different bucket grammar"
    );
    let dataset = AsnDataset::open(dataset_path(&doc)).expect("the sample dataset opens");

    // The corpus pins the exact bytes the resolutions were generated
    // from: a drifted fixture fails here instead of silently passing.
    let info = dataset.dataset_info();
    assert_eq!(info.sha256, doc["dataset_sha256"].as_str().unwrap());
    assert_eq!(info.byte_len, doc["dataset_byte_len"].as_u64().unwrap());
    assert_eq!(
        info.valid_rows as u64,
        doc["expected_valid_rows"].as_u64().unwrap()
    );
    assert_eq!(
        info.malformed_rows as u64,
        doc["expected_malformed_rows"].as_u64().unwrap()
    );

    let vectors = doc["vectors"].as_array().expect("vectors array");
    assert!(vectors.len() >= 20, "the vector families must stay rich");
    for vector in vectors {
        let note = vector["note"].as_str().expect("note");
        let ip: IpAddr = vector["ip"].as_str().expect("ip").parse().unwrap();
        let expected = vector["expected_bucket"].as_str().expect("expected_bucket");
        assert!(
            is_valid_bucket_id(expected),
            "vector {note:?} pins a non-canonical bucket id"
        );
        let lookup = dataset.lookup(ip);
        assert_eq!(lookup.bucket, expected, "vector {note:?}");
        if let Some(expected_asn) = expected.strip_prefix('a') {
            let expected_asn: u32 = expected_asn.parse().unwrap();
            assert_eq!(lookup.asn, Some(expected_asn), "vector {note:?} asn");
        } else {
            assert_eq!(lookup.asn, None, "vector {note:?} must resolve no ASN");
        }
        // Deterministic: a repeated lookup is the identical resolution.
        assert_eq!(dataset.lookup(ip), lookup, "vector {note:?} repeats");
    }

    // The mapped-form family resolves identically to its IPv4 twin.
    let bucket_of = |ip: &str| dataset.bucket_id(ip.parse::<IpAddr>().unwrap());
    assert_eq!(bucket_of("::ffff:203.0.113.7"), bucket_of("203.0.113.7"));
    assert_eq!(bucket_of("::192.0.2.44"), bucket_of("192.0.2.44"));

    // The gap families: two unlisted v4 addresses share a bucket exactly
    // in their /16, two unlisted v6 addresses in their /32.
    assert_eq!(bucket_of("203.0.113.150"), bucket_of("203.0.113.199"));
    assert_ne!(bucket_of("203.0.113.150"), bucket_of("203.1.113.1"));
    assert_eq!(bucket_of("2001:db8:3::1"), bucket_of("2001:db8:5::1"));
    assert_ne!(bucket_of("2001:db8:3::1"), bucket_of("2600::1"));
}

#[test]
fn a_torn_reload_never_replaces_the_serving_table_for_the_corpus_shapes() {
    // The reload contract over a copy of the corpus dataset: a digest
    // mismatch, an all-malformed file and a missing file each leave the
    // last good table serving; a verified reload swaps it.
    let doc = corpus();
    let original = std::fs::read(dataset_path(&doc)).expect("dataset bytes");
    let tmp = std::env::temp_dir().join(format!("kiwi-asn-vec-reload-{}.tsv", std::process::id()));
    std::fs::write(&tmp, &original).unwrap();
    let dataset = AsnDataset::open(&tmp).expect("copy opens");
    let ip: IpAddr = "203.0.113.7".parse().unwrap();
    let good = dataset.lookup(ip).bucket;

    let other = String::from_utf8_lossy(&original).replace("64500\tfr", "64511\tfr");
    std::fs::write(&tmp, other.as_bytes()).unwrap();
    let stale_digest = dataset.dataset_info().sha256;
    assert!(matches!(
        dataset.reload(Some(&stale_digest)),
        Err(AsnError::DigestMismatch { .. })
    ));
    assert_eq!(dataset.lookup(ip).bucket, good);

    dataset.reload(None).expect("the edited copy reloads");
    assert_eq!(dataset.lookup(ip).bucket, "a64511");

    std::fs::write(&tmp, "not-an-ip\tgarbage\trows\n").unwrap();
    assert!(matches!(dataset.reload(None), Err(AsnError::Empty { .. })));
    assert_eq!(
        dataset.lookup(ip).bucket,
        "a64511",
        "the old table keeps serving"
    );
    let _ = std::fs::remove_file(&tmp);
}
