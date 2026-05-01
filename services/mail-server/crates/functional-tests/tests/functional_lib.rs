//! Functional tests for apexmail-lib:crypto, IDs, validation, time, error codes.

use std::collections::HashSet;
use std::time::Duration;

// ── Crypto ─────────────────────────────────────────────────────

#[test]
fn hmac_known_vector_deterministic() {
    let sig1 = apexmail_lib::crypto::create_hmac_signature(b"secret", b"hello world");
    let sig2 = apexmail_lib::crypto::create_hmac_signature(b"secret", b"hello world");
    assert_eq!(sig1, sig2, "HMAC must be deterministic");
    assert_eq!(sig1.len(), 64, "hex-encoded SHA-256 is 64 chars");
}

#[test]
fn hmac_different_keys_differ() {
    let a = apexmail_lib::crypto::create_hmac_signature(b"key-a", b"data");
    let b = apexmail_lib::crypto::create_hmac_signature(b"key-b", b"data");
    assert_ne!(a, b);
}

#[test]
fn password_hash_roundtrip() {
    let hash = apexmail_lib::crypto::hash_password("s3cret!").unwrap();
    assert!(hash.starts_with("$argon2"), "should be argon2 hash");
    assert!(apexmail_lib::crypto::verify_password("s3cret!", &hash).unwrap());
    assert!(!apexmail_lib::crypto::verify_password("wrong", &hash).unwrap());
}

#[test]
fn password_hash_unique_salts() {
    let h1 = apexmail_lib::crypto::hash_password("test").unwrap();
    let h2 = apexmail_lib::crypto::hash_password("test").unwrap();
    assert_ne!(h1, h2, "different salts should yield different hashes");
}

#[test]
fn timing_safe_compare_correctness() {
    assert!(apexmail_lib::crypto::timing_safe_compare("abc", "abc"));
    assert!(!apexmail_lib::crypto::timing_safe_compare("abc", "abd"));
    assert!(!apexmail_lib::crypto::timing_safe_compare("abc", "abcd"));
    assert!(apexmail_lib::crypto::timing_safe_compare("", ""));
}

#[test]
fn hash_api_key_deterministic_and_unique() {
    let h1 = apexmail_lib::crypto::hash_api_key("am_live_abc");
    let h2 = apexmail_lib::crypto::hash_api_key("am_live_abc");
    let h3 = apexmail_lib::crypto::hash_api_key("am_live_xyz");
    assert_eq!(h1, h2);
    assert_ne!(h1, h3);
    assert_eq!(h1.len(), 64);
}

// ── ID generation ──────────────────────────────────────────────

#[test]
fn generate_1000_unique_ids() {
    let ids: HashSet<String> = (0..1000)
        .map(|_| apexmail_lib::id::generate_id("msg", 20))
        .collect();
    assert_eq!(ids.len(), 1000, "all 1000 IDs must be unique");
}

#[test]
fn api_key_prefixes() {
    let live = apexmail_lib::id::generate_api_key(false);
    let test = apexmail_lib::id::generate_api_key(true);
    assert!(live.starts_with("am_live_"));
    assert!(test.starts_with("am_test_"));
}

// ── Validation edge cases ──────────────────────────────────────

#[test]
fn validate_email_edge_cases() {
    // Valid
    assert!(apexmail_lib::validation::is_valid_email("user@example.com"));
    assert!(apexmail_lib::validation::is_valid_email("a@b.cc"));
    assert!(apexmail_lib::validation::is_valid_email(
        "test+tag@sub.domain.co.uk"
    ));
    // Invalid
    assert!(!apexmail_lib::validation::is_valid_email(""));
    assert!(!apexmail_lib::validation::is_valid_email("noatsign"));
    assert!(!apexmail_lib::validation::is_valid_email("@no-local.com"));
    // Very long (> 320 chars)
    let long_local = "a".repeat(310);
    let long_email = format!("{}@example.com", long_local);
    assert!(!apexmail_lib::validation::is_valid_email(&long_email));
}

#[test]
fn null_byte_detection_and_sanitization() {
    assert!(!apexmail_lib::validation::has_null_bytes("clean"));
    assert!(apexmail_lib::validation::has_null_bytes("has\0null"));
    assert!(!apexmail_lib::validation::has_null_bytes("has\\u0000null"));
    assert_eq!(apexmail_lib::validation::sanitize_string("he\0lo"), "helo");
}

// ── Time parsing ───────────────────────────────────────────────

#[test]
fn parse_valid_durations() {
    assert_eq!(
        apexmail_lib::time::parse_duration("24h").unwrap(),
        Duration::from_secs(86400)
    );
    assert_eq!(
        apexmail_lib::time::parse_duration("30m").unwrap(),
        Duration::from_secs(1800)
    );
    assert_eq!(
        apexmail_lib::time::parse_duration("7d").unwrap(),
        Duration::from_secs(604800)
    );
    assert_eq!(
        apexmail_lib::time::parse_duration("60s").unwrap(),
        Duration::from_secs(60)
    );
}

#[test]
fn parse_invalid_durations() {
    assert!(apexmail_lib::time::parse_duration("abc").is_err());
    assert!(apexmail_lib::time::parse_duration("").is_err());
    assert!(apexmail_lib::time::parse_duration("10x").is_err());
}

// ── Error codes ────────────────────────────────────────────────

#[test]
fn error_code_http_status_mapping_all_variants() {
    use apexmail_lib::ErrorCode;
    let mappings: Vec<(ErrorCode, u16)> = vec![
        (ErrorCode::Unauthorized, 401),
        (ErrorCode::Forbidden, 403),
        (ErrorCode::TokenExpired, 401),
        (ErrorCode::TokenBlacklisted, 401),
        (ErrorCode::InvalidApiKey, 401),
        (ErrorCode::InsufficientScopes, 403),
        (ErrorCode::ValidationError, 400),
        (ErrorCode::InvalidInput, 400),
        (ErrorCode::PayloadTooLarge, 413),
        (ErrorCode::NullByteDetected, 400),
        (ErrorCode::RateLimitExceeded, 429),
        (ErrorCode::NotFound, 404),
        (ErrorCode::Conflict, 409),
        (ErrorCode::Gone, 410),
        (ErrorCode::InternalError, 500),
        (ErrorCode::ServiceUnavailable, 503),
        (ErrorCode::RequestTimeout, 408),
        (ErrorCode::GatewayTimeout, 504),
        (ErrorCode::DomainNotVerified, 422),
        (ErrorCode::SuppressionExists, 409),
        (ErrorCode::WebhookDeliveryFailed, 503),
        (ErrorCode::QuotaExceeded, 429),
        (ErrorCode::InvalidTemplate, 400),
        (ErrorCode::MessageCancelled, 410),
        (ErrorCode::IdempotencyConflict, 409),
    ];
    for (code, expected) in mappings {
        assert_eq!(
            code.http_status(),
            expected,
            "{code}: expected {expected}, got {}",
            code.http_status()
        );
    }
}

#[test]
fn error_code_display_roundtrip() {
    assert_eq!(
        apexmail_lib::ErrorCode::Unauthorized.to_string(),
        "UNAUTHORIZED"
    );
    assert_eq!(
        apexmail_lib::ErrorCode::RateLimitExceeded.to_string(),
        "RATE_LIMIT_EXCEEDED"
    );
    assert_eq!(
        apexmail_lib::ErrorCode::IdempotencyConflict.to_string(),
        "IDEMPOTENCY_CONFLICT"
    );
}
