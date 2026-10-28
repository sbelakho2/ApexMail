//! The shared challenge-signature corpus against the Rust verifier.
//!
//! The fixture is expanded by the PHP generator and read byte-for-byte
//! by every hosted SDK suite. Each row carries a stored v2 record, the
//! presented challenge, the verifier secret and tenant, and the
//! reference verdict.

use std::fs;

use kiwicaptcha::challenge::{verify_signature_v2_with_tenant, ChallengeRecord};
use serde_json::Value;

fn signature_from_challenge(challenge: &str) -> &str {
    challenge.rsplit_once('.').map(|(_, sig)| sig).unwrap_or("")
}

#[test]
fn every_signature_corpus_row_has_the_reference_verdict() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/wire-signature-corpus.json"
    );
    let document: Value =
        serde_json::from_str(&fs::read_to_string(path).expect("signature corpus fixture"))
            .expect("signature corpus JSON");
    let rows = document["vectors"].as_array().expect("vectors");
    assert!(rows.len() >= 40, "the signature corpus must stay broad");
    for row in rows {
        let id = row["id"].as_str().expect("id");
        let record: ChallengeRecord =
            serde_json::from_value(row["record"].clone()).expect("record parses");
        let challenge = row["challenge"].as_str().expect("challenge");
        assert_eq!(
            record.challenge, challenge,
            "{id}: the record carries the row challenge"
        );
        let secret = row["verify_secret"].as_str().expect("secret");
        let tenant = row["verify_tenant"].as_str();
        let signature = signature_from_challenge(challenge);
        let verified = verify_signature_v2_with_tenant(&record, signature, secret, tenant)
            .unwrap_or_else(|e| panic!("{id}: signature verification errored: {e}"));
        let expected = row["expect"].as_str().expect("expect") == "accept";
        assert_eq!(verified, expected, "{id}");
    }
}
