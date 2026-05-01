//! Fuzz tests for cryptographic functions in apexmail-lib.

use apexmail_lib::crypto::{create_hmac_signature, create_hmac_signature_base64};
use apexmail_lib::id::{
    generate_api_key, generate_id, generate_request_id, generate_webhook_secret,
};
use fuzz_tests::*;

#[test]
fn fuzz_hmac_deterministic() {
    // Same key + message must always produce the same signature.
    for _ in 0..1_000 {
        let key = random_bytes(rand::random::<usize>() % 128 + 1);
        let msg = random_bytes(rand::random::<usize>() % 512);
        let sig1 = create_hmac_signature(&key, &msg);
        let sig2 = create_hmac_signature(&key, &msg);
        assert_eq!(sig1, sig2, "HMAC must be deterministic");

        // Also check base64 variant
        let sig_b1 = create_hmac_signature_base64(&key, &msg);
        let sig_b2 = create_hmac_signature_base64(&key, &msg);
        assert_eq!(sig_b1, sig_b2, "HMAC base64 must be deterministic");
    }
}

#[test]
fn fuzz_hmac_different_keys() {
    // Different keys must produce different outputs (with overwhelming probability).
    let msg = b"constant message for testing";
    let mut distinct_sigs = std::collections::HashSet::new();
    for _ in 0..1_000 {
        let key = random_bytes(32);
        let sig = create_hmac_signature(&key, msg);
        distinct_sigs.insert(sig);
    }
    // With 1000 random 256-bit keys, collision probability is negligible.
    assert!(
        distinct_sigs.len() >= 990,
        "Expected nearly all distinct signatures, got {}/1000",
        distinct_sigs.len()
    );
}

#[test]
fn fuzz_id_always_prefixed() {
    // 1,000 generated IDs must always start with the expected prefix.
    let prefixes = ["msg", "ev", "usr", "org", "inv", "wh", "", "test_prefix"];
    for prefix in &prefixes {
        for _ in 0..125 {
            let len = rand::random::<usize>() % 32 + 8;
            let id = generate_id(prefix, len);
            if prefix.is_empty() {
                // No prefix — no underscore
                assert!(
                    !id.starts_with('_'),
                    "Empty prefix should not produce leading underscore: {id}"
                );
                assert_eq!(id.len(), len);
            } else {
                let expected_prefix = format!("{prefix}_");
                assert!(
                    id.starts_with(&expected_prefix),
                    "ID {id} should start with {expected_prefix}"
                );
            }
        }
    }

    // Also check specific generators
    for _ in 0..100 {
        let api_key = generate_api_key(false);
        assert!(api_key.starts_with("am_live_"), "API key: {api_key}");

        let test_key = generate_api_key(true);
        assert!(test_key.starts_with("am_test_"), "Test key: {test_key}");

        let req_id = generate_request_id();
        assert!(req_id.starts_with("req_"), "Request ID: {req_id}");

        let wh_secret = generate_webhook_secret();
        assert!(
            wh_secret.starts_with("whsec_"),
            "Webhook secret: {wh_secret}"
        );
    }
}

#[test]
fn fuzz_id_never_empty() {
    for _ in 0..1_000 {
        let len = rand::random::<usize>() % 64 + 1;
        let id = generate_id("x", len);
        assert!(!id.is_empty(), "ID must never be empty");
        assert!(id.len() >= 2, "ID must have at least prefix + 1 char");
    }
    // Even with length 1
    let id = generate_id("", 1);
    assert!(!id.is_empty());
}
