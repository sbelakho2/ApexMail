//! CI cross-language harness: loads a PHP-ISSUED record (KC_PHP_RECORD env),
//! solves it with the Rust solver, and verifies it with verify_solution.
//! Skips (returns) when the env var is unset so local `cargo test` stays
//! hermetic.

use kiwicaptcha::verify::{
    solve_for_test, verify_solution, VerifyContext, VerifyError, VerifyOutcome,
};

#[test]
fn rust_verifies_php_issued_record() {
    let Ok(path) = std::env::var("KC_PHP_RECORD") else {
        eprintln!("KC_PHP_RECORD unset — cross-language test skipped");
        return;
    };
    let json = std::fs::read_to_string(&path).expect("KC_PHP_RECORD file");
    let record: kiwicaptcha::ChallengeRecord =
        serde_json::from_str(&json).expect("PHP JSON must deserialize into the Rust record");
    assert_eq!(record.protocol_version, 2);
    assert_eq!(record.scope, "login");

    let counter = solve_for_test(&record).expect("Rust solver finds a counter");
    let mut rec = record;
    let now_ns = rec.issued_at_ns + 1_000_000;
    let mut ctx = VerifyContext {
        record: &mut rec,
        secret_key: "0123456789abcdef0123456789abcdef",
        counter,
        duration_ms: 5000,
        now_unix: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
        now_ns,
        min_duration_ms: 0,
        expected_scope: Some("login"),
        expected_region: None,
        expected_issuer: None,
        expected_policy_version: None,
        client_ip: Some("198.51.100.7"),
        telemetry: None,
        enforce_telemetry: false,
        max_attempts: 0,
        accept_legacy_v1: false,
    };
    assert!(
        matches!(verify_solution(&mut ctx), VerifyOutcome::Valid { .. }),
        "Rust must accept a PHP-issued challenge"
    );

    // Cross-language binding: a wrong IP must be rejected.
    let mut rec2 = rec.clone();
    let mut ctx2 = VerifyContext {
        record: &mut rec2,
        secret_key: "0123456789abcdef0123456789abcdef",
        counter,
        duration_ms: 5000,
        now_unix: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
        now_ns,
        min_duration_ms: 0,
        expected_scope: Some("login"),
        expected_region: None,
        expected_issuer: None,
        expected_policy_version: None,
        client_ip: Some("9.9.9.9"),
        telemetry: None,
        enforce_telemetry: false,
        max_attempts: 0,
        accept_legacy_v1: false,
    };
    assert_eq!(
        verify_solution(&mut ctx2),
        VerifyOutcome::Invalid(VerifyError::IpMismatch)
    );
    println!("RUST_VERIFIES_PHP: OK (counter={counter})");
}

#[test]
fn rust_issues_record_for_php() {
    // Reverse direction: Rust issues a record (KC_RUST_ALGO=sha256|argon2id),
    // writes the language-neutral JSON to KC_RUST_RECORD for the PHP job to
    // solve + verify. Skips when the env var is unset.
    let Ok(path) = std::env::var("KC_RUST_RECORD") else {
        eprintln!("KC_RUST_RECORD unset — reverse cross-language test skipped");
        return;
    };
    let algo_name = std::env::var("KC_RUST_ALGO").unwrap_or_else(|_| "sha256".to_string());
    let (algorithm, m_kib, t, p, target_bits, argon2_target_bits) = if algo_name == "argon2id" {
        (
            kiwicaptcha::challenge::PoWAlgorithm::Argon2id,
            64u32,
            3u32,
            1u32,
            4u32,
            4u32,
        )
    } else {
        (
            kiwicaptcha::challenge::PoWAlgorithm::Sha256,
            0u32,
            1u32,
            1u32,
            8u32,
            8u32,
        )
    };
    let config = kiwicaptcha::challenge::ChallengeConfig {
        secret_key: "0123456789abcdef0123456789abcdef".into(),
        algorithm,
        m_kib,
        t,
        p,
        target_bits,
        argon2_target_bits,
        ttl_secs: 120,
        min_duration_ms: None,
        auto_tune: false,
        auto_tune_min_bits: 8,
        auto_tune_max_bits: 20,
        binding_mode: kiwicaptcha::challenge::BindingMode::Bound,
        region: None,
        issuer: None,
        policy_version: 1,
    };
    let now_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let now_ns = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_micros() as u64;
    let issued = kiwicaptcha::challenge::issue_challenge(
        &config,
        "login",
        "198.51.100.7",
        now_unix,
        now_ns,
        0,
        None,
    )
    .expect("issue");
    std::fs::write(
        &path,
        serde_json::to_string(&issued.record).expect("serialize"),
    )
    .expect("write");
    println!("RUST_ISSUED {}", algo_name);
}
