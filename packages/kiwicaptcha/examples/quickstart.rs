//! The whole quick-start (issue, solve, verify) as one executable example.
//! CI runs it with `cargo test -p kiwicaptcha --example quickstart` and the
//! run below asserts the journey ends in `VerifyOutcome::Valid`.
//!
//! The outline mirrors the crate documentation: the server issues a signed
//! proof-of-work challenge, the client solves it, and the server verifies
//! the submission against the stored record. The client side here uses
//! `solve_for_test`, the documented test and dev-bypass solver, so the
//! example stays hermetic: a browser widget performs this step in
//! production.
//!
//! Storage is intentionally left out. A real deployment persists
//! `issued.record` under `kcaptcha:{nonce}` and consumes it on success;
//! see the crate documentation for the Redis adapter and the
//! single-use semantics.

use std::time::{SystemTime, UNIX_EPOCH};

use kiwicaptcha::{
    issue_challenge, solve_for_test, verify_solution, BindingMode, ChallengeConfig, PoWAlgorithm,
    RequestBindingExpectation, SolutionToken, VerifyContext, VerifyOutcome,
};

/// The server's HMAC secret. Generate a real one at deploy time, for
/// example with `openssl rand -hex 32`.
const SECRET: &str = "replace-with-a-random-32-byte-secret-value";

/// One challenge journey against one simulated client address: the
/// server issues, the client solves and submits, the server verifies.
fn journey() {
    let client_ip = "203.0.113.7";

    // 1. The server configures the difficulty profile and issues the
    //    challenge. SHA-256 at 18 bits is the documented default.
    let config = ChallengeConfig {
        secret_key: SECRET.to_string(),
        algorithm: PoWAlgorithm::Sha256,
        m_kib: 0,
        t: 1,
        p: 1,
        target_bits: 18,
        argon2_target_bits: 4,
        ttl_secs: 120,
        // The example has no client latency between issue and submit, so
        // the server-side minimum duration floor is disabled with `Some(0)`.
        // A real deployment keeps `None` and the difficulty-derived floor.
        min_duration_ms: Some(0),
        auto_tune: false,
        auto_tune_min_bits: 10,
        auto_tune_max_bits: 20,
        binding_mode: BindingMode::Bound,
        policy_version: 1,
        region: None,
        issuer: None,
        kid: 1,
        execution_key: None,
        rsw_modulus_n: None,
        rsw_lambda: None,
        rsw_t: 0,
        tenant: None,
    };

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock after the epoch");
    let now_unix = now.as_secs();
    let now_micros = now.as_micros() as u64;

    let issued = issue_challenge(&config, "login", client_ip, now_unix, now_micros, 0, None)
        .expect("issuance with a valid config");
    // Persist issued.record under kcaptcha:{nonce} and send issued.challenge
    // to the client as JSON. This example holds the record in memory.
    let nonce = issued.challenge.nonce.clone();

    // 2. The client solves the challenge and submits the solution token.
    //    `solve_for_test` is the test and dev-bypass surface; the browser
    //    widget performs this step in production.
    let counter = solve_for_test(&issued.record).expect("the solver finds a counter");
    let token = SolutionToken {
        nonce: nonce.clone(),
        counter,
        duration_ms: 5_000,
        telemetry: serde_json::json!({}),
        execution_digest: None,
        execution_trace: None,
        rsw_proof: None,
    };
    let wire = token.encode();

    // 3. The server decodes the submission, looks the record up, and
    //    verifies. Verification performs attempt accounting on the record,
    //    so the caller persists it back on failure and consumes it on
    //    success.
    let decoded = SolutionToken::decode(&wire).expect("the wire token decodes");
    assert_eq!(decoded.nonce, nonce, "the token names the issued nonce");

    let receipt = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock after the epoch");
    let mut record = issued.record;
    let mut ctx = VerifyContext {
        record: &mut record,
        secret_key: SECRET,
        tenant: None,
        secrets_by_kid: None,
        revoked_kids: None,
        counter: decoded.counter,
        duration_ms: decoded.duration_ms,
        // The safe default: the verifier reads the real system clock itself,
        // twice, so a challenge that expires mid-derive is detected.
        now_unix: None,
        now_ns: receipt.as_micros() as u64,
        min_duration_ms: 0,
        expected_scope: Some("login"),
        expected_request_binding: RequestBindingExpectation::Unenforced,
        expected_region: None,
        expected_issuer: None,
        expected_policy_version: None,
        policy_version_floor: None,
        client_ip: Some(client_ip),
        execution_digest: None,
        execution_trace: None,
        telemetry: Some(&decoded.telemetry),
        enforce_telemetry: false,
        max_attempts: 10,
        accept_legacy_v1: false,
        rsw_proof: None,
        rsw_modulus_n: None,
        rsw_lambda: None,
        rsw_keyring: None,
    };

    match verify_solution(&mut ctx) {
        VerifyOutcome::Valid {
            nonce: consumed, ..
        } => {
            // Consume the challenge atomically here (the Redis pending to
            // consumed transition), then allow the protected action.
            assert_eq!(consumed, nonce, "the valid outcome carries the jti");
            println!("quickstart: challenge {} verified", consumed);
        }
        VerifyOutcome::Invalid(reason) => {
            panic!("the quickstart journey must verify: {:?}", reason);
        }
    }
}

fn main() {
    journey();
}

/// The CI hook: `cargo test -p kiwicaptcha --example quickstart` runs
/// this and fails the lane when the journey stops ending in Valid.
#[test]
fn the_quickstart_journey_verifies() {
    journey();
}
