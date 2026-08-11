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
        now_unix: 1_700_000_100,
        now_ns,
        min_duration_ms: 0,
        expected_scope: Some("login"),
        client_ip: Some("198.51.100.7"),
        telemetry: None,
        enforce_telemetry: false,
        max_attempts: 0,
    };
    assert_eq!(
        verify_solution(&mut ctx),
        VerifyOutcome::Valid,
        "Rust must accept a PHP-issued challenge"
    );

    // Cross-language binding: a wrong IP must be rejected.
    let mut rec2 = rec.clone();
    let mut ctx2 = VerifyContext {
        record: &mut rec2,
        secret_key: "0123456789abcdef0123456789abcdef",
        counter,
        duration_ms: 5000,
        now_unix: 1_700_000_100,
        now_ns,
        min_duration_ms: 0,
        expected_scope: Some("login"),
        client_ip: Some("9.9.9.9"),
        telemetry: None,
        enforce_telemetry: false,
        max_attempts: 0,
    };
    assert_eq!(
        verify_solution(&mut ctx2),
        VerifyOutcome::Invalid(VerifyError::IpMismatch)
    );
    println!("RUST_VERIFIES_PHP: OK (counter={counter})");
}
