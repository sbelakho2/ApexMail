//! Differential malicious-record parsing: the shared corpus must be
//! rejected by the Rust public reconstruction boundary.
//!
//! The corpus lives at protocol/risk-v1/fuzz-corpus.json (deterministic
//! seed 0x5EED0001, 1000 mutations of a base record that is itself not
//! structurally canonical: its `prefix` is not the `challenge|salt|`
//! binding and its scope carries a separator outside the identifier
//! alphabet). `ChallengeRecord`'s `Deserialize` now applies
//! `record_is_structurally_valid` — the same one-call structural
//! authority the Redis storage decoder and the verifier consult — so
//! the public interchange type can never surface a record the verifier
//! would reject as malformed. The pinned acceptance is therefore zero:
//! every corpus record violates the structural contract at the public
//! boundary, exactly like the PHP `fromArray()` reconstruction boundary
//! rejects the records whose structural invariants it enforces.

#[test]
fn malicious_corpus_acceptance_is_pinned() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../protocol/risk-v1/fuzz-corpus.json"
    );
    let corpus: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let records = corpus.as_array().unwrap();
    let mut accepted = 0usize;
    let mut rejected = 0usize;
    for r in records {
        let s = serde_json::to_string(r).unwrap();
        match serde_json::from_str::<kiwicaptcha::ChallengeRecord>(&s) {
            Ok(_) => accepted += 1,
            Err(_) => rejected += 1,
        }
    }
    assert_eq!(
        accepted, 0,
        "the public reconstruction boundary applies the structural contract: no corpus record may decode"
    );
    assert_eq!(rejected, 1000);
}
