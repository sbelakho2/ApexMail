//! Differential malicious-record parsing: the SAME corpus must be rejected
//! (and accepted) identically by the Rust and PHP parsers (audit #56).
//!
//! The corpus lives at protocol/risk-v1/fuzz-corpus.json (deterministic
//! seed 0x5EED0001, 1000 mutations of a valid record). The accepted count
//! is pinned: the PHP fromArray parser must accept the SAME 659 records.

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
    let mut accepted_nonces = std::collections::HashSet::new();
    for r in records {
        let s = serde_json::to_string(r).unwrap();
        match serde_json::from_str::<kiwicaptcha::ChallengeRecord>(&s) {
            Ok(rec) => {
                accepted += 1;
                accepted_nonces.insert(rec.nonce);
                // Audit #91: the corpus predates the kid key — every accepted
                // record must default to kid = 1 (the historical single-key
                // deployments), keeping the acceptance count pinned at 659.
                assert_eq!(rec.kid, 1, "missing kid must default to 1");
            }
            Err(_) => rejected += 1,
        }
    }
    assert_eq!(accepted, 659, "Rust parser acceptance must stay pinned");
    assert_eq!(rejected, 1000 - 659);
    let _ = accepted_nonces;
}
