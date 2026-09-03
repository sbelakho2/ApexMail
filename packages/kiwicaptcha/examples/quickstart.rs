//! End-to-end quick-start mirroring the project's quick-start docs:
//! issue a low-difficulty challenge → construct a solution → verify it →
//! assert `VerifyOutcome::Valid`. CI runs this example (`cargo test
//! --example quickstart`), so the documented flow is proven to work, not
//! merely to compile. It is the single source of truth for the quick-start
//! snippets — change the API here and the docs together.
//!
//! Run with: `cargo run --example quickstart` (or `cargo test --example
//! quickstart` — the test wrapper asserts the exact `Valid` outcome).

use kiwicaptcha::{
    issue_challenge, now_epoch_micros, solve_for_test, verify_solution, BindingMode,
    ChallengeConfig, PoWAlgorithm, RequestBindingExpectation, SolutionToken, VerifyContext,
    VerifyOutcome,
};

/// The complete current `ChallengeConfig`: there is NO
/// `Default` — every field is explicit so a copied quick-start cannot
/// silently drop a security-relevant knob.
fn config() -> ChallengeConfig {
    ChallengeConfig {
        secret_key: "0123456789abcdef0123456789abcdef".to_string(), // >= 16 bytes
        algorithm: PoWAlgorithm::Sha256,
        m_kib: 0, // SHA-256: the memory-hard parameters are unused
        t: 1,
        p: 1,
        target_bits: 8, // low difficulty so the example solves instantly
        argon2_target_bits: 8,
        ttl_secs: 120,
        min_duration_ms: Some(0), // disable the timing floor for the example
        auto_tune: false,
        auto_tune_min_bits: 8,
        auto_tune_max_bits: 8,
        binding_mode: BindingMode::Bound, // nonce-bound IP binding (relay mitigation)
        policy_version: 1,                // the security-policy epoch
        region: None,                     // Some("eu") for region-bound deployments
        issuer: None,                     // Some("auth-gateway") to pin the issuer
        kid: 1,                           // single-key deployment
        execution_key: None,              // ExecutionChallengeV1 off (no key)
        rsw_modulus_n: None,
        rsw_lambda: None,
        rsw_t: kiwicaptcha::challenge::DEFAULT_RSW_T,
    }
}

fn quickstart() -> Result<(), String> {
    let config = config();
    let now_ns = now_epoch_micros(); // epoch microseconds (shared with PHP)
    let now_unix = (now_ns / 1_000_000) as u64;

    // 1. Issue: sign a challenge bound to the client IP.
    let issued = issue_challenge(
        &config,
        "login",
        "203.0.113.7", // canonical client IP (per the deployment's trusted proxies)
        now_unix,
        now_ns,
        0,    // active solver count (auto-tune input; disabled above)
        None, // request_binding: the application transaction binding (None = none)
    )
    .map_err(|e| format!("issuance failed: {e}"))?;

    // 2. Solve (what the browser widget does): brute-force a counter that
    //    meets the difficulty, then pack the solution token.
    let counter =
        solve_for_test(&issued.record).ok_or("no counter met the difficulty (too high?)")?;
    let token = SolutionToken {
        nonce: issued.challenge.nonce.clone(),
        counter,
        duration_ms: 1,
        telemetry: serde_json::json!({}), // telemetry is OFF by default -> empty object
        execution_digest: None,
        execution_trace: None,
        rsw_proof: None,
    };
    let raw = token.encode();
    let decoded = SolutionToken::decode(&raw).map_err(|e| format!("token decode failed: {e}"))?;

    // 3. Verify: single-key deployment — secrets_by_kid/revoked_kids are
    //    None (an empty map would reject kid 1 as unknown); telemetry
    //    enforcement is OFF because the default widget sends none.
    let mut record = issued.record;
    let mut ctx = VerifyContext {
        record: &mut record,
        secret_key: &config.secret_key,
        secrets_by_kid: None, // None = single-key path (kid 1 verified)
        revoked_kids: None,   // None = no compromise-revoked keys
        counter: decoded.counter,
        duration_ms: decoded.duration_ms,
        // The safe default: no injected clock — the verifier reads the
        // real system clock itself, twice (receipt + post-derive), so a
        // challenge that expired during the derivation is detected.
        now_unix: None,
        now_ns,
        min_duration_ms: 0, // floor is max(ctx, record.min_duration_ms); 0 = record only
        expected_scope: Some("login"),
        expected_request_binding: RequestBindingExpectation::Unenforced,
        expected_region: None,
        expected_issuer: None,
        expected_policy_version: Some(1),
        client_ip: Some("203.0.113.7"), // must match the issuance IP (Bound mode)
        execution_digest: None,
        execution_trace: None,
        telemetry: Some(&decoded.telemetry),
        enforce_telemetry: false, // default widget sends no telemetry — never reject on it
        accept_legacy_v1: false,  // v2 is the only issued format
        rsw_proof: None,
        rsw_modulus_n: None,
        rsw_lambda: None,
        max_attempts: 10,
    };

    match verify_solution(&mut ctx) {
        VerifyOutcome::Valid { nonce, .. } => {
            println!("valid solution for {nonce}");
            Ok(())
        }
        VerifyOutcome::Invalid(reason) => Err(format!("verification failed: {reason}")),
    }
}

fn main() {
    match quickstart() {
        Ok(()) => println!("quickstart: OK"),
        Err(e) => {
            eprintln!("quickstart: FAILED — {e}");
            std::process::exit(1);
        }
    }
}

#[test]
fn quickstart_reaches_verify_outcome_valid() {
    // CI asserts behavior, not just syntax.
    quickstart().expect("the documented quick-start must end in VerifyOutcome::Valid");
}
