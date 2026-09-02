//! Protocol-v3/v4 two-phase rollout invariants, Rust side.
//!
//! The mixed-fleet contract: a decoy-armed (protocol v3) record issued
//! by the current generation verifies through the current verifier,
//! whose acceptance set is {1, 2, 3, 4}, while the same record is
//! rejected as MalformedRecord by a simulated parent-revision verifier
//! whose acceptance set is {1, 2} — the exact old-binary behavior the
//! rollout protects against. The v4 execution phase extends the
//! contract: an execution-armed (protocol v4) record verifies through
//! the current verifier and is rejected by both older generations
//! ({1, 2} and {1, 2, 3}). The symmetric invariant: an unarmed v2
//! record verifies through every generation, so a mixed fleet serving
//! v2 traffic never breaks a solve.
//!
//! The parent-revision simulation is the version-acceptance predicate
//! with an explicit max protocol ([`accepts_with_max`]): a binary whose
//! max protocol is `max` accepts exactly 1..=max and fails closed as
//! MalformedRecord outside the set, before any further structural
//! check, exactly like the parent revision's `validate_record` gate.
//! Every other check is byte-identical across the revision boundary, so
//! the accepted versions delegate to the current `validate_record`.

use kiwicaptcha::challenge::{
    issue_challenge_with_decoy, issue_challenge_with_execution, BindingMode, ChallengeConfig,
    PoWAlgorithm,
};
use kiwicaptcha::verify::{
    solve_for_test, validate_record, verify_solution, RequestBindingExpectation, VerifyContext,
    VerifyError, VerifyOutcome,
};

/// The shared signing secret (kid 1), identical to the PHP fixtures.
const SECRET: &str = "0123456789abcdef0123456789abcdef";

/// The fixed fixture clock (Unix seconds), shared by issuance and
/// verification so the TTL checks never see a future-issued or
/// prematurely expired record.
const NOW_UNIX: u64 = 1_800_000_000;

/// The fixture receipt instant in epoch microseconds, just after
/// issuance.
const NOW_NS: u64 = 1_800_000_000_000_000;

/// The parent-revision version-acceptance predicate with an explicit
/// max: a binary whose max protocol is `max` accepts exactly 1..=max.
/// Protocol 3 is outside {1, 2}, which is the whole point of the
/// rollout gate.
fn accepts_with_max(record: &kiwicaptcha::ChallengeRecord, max: u8) -> Result<(), VerifyError> {
    if !(1..=max).contains(&record.protocol_version) {
        return Err(VerifyError::MalformedRecord);
    }
    validate_record(record)
}

fn sha256_config() -> ChallengeConfig {
    ChallengeConfig {
        secret_key: SECRET.into(),
        kid: 1,
        execution_key: None,
        algorithm: PoWAlgorithm::Sha256,
        m_kib: 0,
        t: 1,
        p: 1,
        target_bits: 8,
        argon2_target_bits: 8,
        ttl_secs: 120,
        min_duration_ms: None,
        auto_tune: false,
        auto_tune_min_bits: 8,
        auto_tune_max_bits: 20,
        binding_mode: BindingMode::Bound,
        region: None,
        issuer: None,
        policy_version: 1,
    }
}

#[allow(clippy::too_many_arguments)]
fn verify_ctx<'a>(
    record: &'a mut kiwicaptcha::ChallengeRecord,
    counter: u64,
    now_unix: &'a mut dyn FnMut() -> u64,
    now_ns: u64,
) -> VerifyContext<'a> {
    VerifyContext {
        record,
        secret_key: SECRET,
        secrets_by_kid: None,
        revoked_kids: None,
        counter,
        duration_ms: 5000,
        now_unix: Some(now_unix),
        now_ns,
        min_duration_ms: 0,
        expected_scope: Some("login"),
        expected_request_binding: RequestBindingExpectation::Unenforced,
        expected_region: None,
        expected_issuer: None,
        expected_policy_version: None,
        client_ip: Some("198.51.100.7"),
        execution_digest: None,
        execution_trace: None,
        telemetry: None,
        enforce_telemetry: false,
        max_attempts: 0,
        accept_legacy_v1: false,
    }
}

#[test]
fn v3_armed_record_verifies_current_and_fails_v2_only() {
    // Issue a decoy-armed (protocol v3) record through the current
    // generation's issuance.
    let issued = issue_challenge_with_decoy(
        &sha256_config(),
        "login",
        "198.51.100.7",
        NOW_UNIX,
        NOW_NS,
        0,
        None,
        true,
    )
    .expect("v3 issuance");
    assert_eq!(issued.record.protocol_version, 3);
    assert!(
        issued.record.decoy_field.is_some(),
        "an armed issuance writes the authenticated decoy segment"
    );

    // The current generation's structural gate accepts the v3 record.
    assert_eq!(
        validate_record(&issued.record),
        Ok(()),
        "the current verifier's acceptance set includes protocol 3"
    );

    // The parent-revision gate: max protocol 2 rejects the same record
    // as MalformedRecord; max protocol 3 (the new generation) accepts
    // it.
    assert_eq!(
        accepts_with_max(&issued.record, 2),
        Err(VerifyError::MalformedRecord),
        "a parent-revision verifier must reject a v3 record as MalformedRecord"
    );
    assert!(
        accepts_with_max(&issued.record, 3).is_ok(),
        "the new generation accepts v3 (its own max protocol)"
    );

    // The full verification path on the current verifier: solve the
    // record and verify it end to end.
    let counter = solve_for_test(&issued.record).expect("solver finds a counter");
    let mut rec = issued.record.clone();
    let mut clock = || NOW_UNIX;
    let mut ctx = verify_ctx(&mut rec, counter, &mut clock, NOW_NS + 1_000_000);
    assert!(
        matches!(verify_solution(&mut ctx), VerifyOutcome::Valid { .. }),
        "the current verifier must accept its own v3 record end to end"
    );
}

#[test]
fn v2_unarmed_record_verifies_through_both_generations() {
    // The symmetric mixed-fleet invariant: unarmed v2 emission solves
    // and verifies through the current verifier AND the simulated
    // parent-revision verifier, so a rolling fleet serving v2 traffic
    // never breaks a solve while the rollout is in progress.
    let issued = issue_challenge_with_decoy(
        &sha256_config(),
        "login",
        "198.51.100.7",
        NOW_UNIX,
        NOW_NS,
        0,
        None,
        false,
    )
    .expect("v2 issuance");
    assert_eq!(issued.record.protocol_version, 2);
    assert_eq!(
        accepts_with_max(&issued.record, 2),
        Ok(()),
        "the parent-revision gate accepts v2 (its unarmed canonical)"
    );

    let counter = solve_for_test(&issued.record).expect("solver finds a counter");
    let mut rec = issued.record.clone();
    let mut clock = || NOW_UNIX;
    let mut ctx = verify_ctx(&mut rec, counter, &mut clock, NOW_NS + 1_000_000);
    assert!(
        matches!(verify_solution(&mut ctx), VerifyOutcome::Valid { .. }),
        "the current verifier must accept the v2 record"
    );

    // The parent-revision full path is the same verify over the same
    // record: the version gate passed above, and every other check is
    // byte-identical across the revision boundary.
    assert_eq!(
        accepts_with_max(&issued.record, 2),
        Ok(()),
        "a parent-revision verifier must keep serving v2 traffic"
    );
}

#[test]
fn v4_execution_armed_record_verifies_current_and_fails_both_older_generations() {
    // The v4 execution phase of the rollout contract: a
    // protocol v4 record (execution-armed, decoy included) verifies
    // through the current verifier, whose acceptance set is
    // {1, 2, 3, 4}; the same record is rejected as MalformedRecord by
    // the v2-only simulator AND by the v3-only simulator — the exact
    // old-binary behavior the v4 floor protects against.
    let mut cfg = sha256_config();
    cfg.execution_key = Some(SECRET.into());
    let issued = issue_challenge_with_execution(
        &cfg,
        "login",
        "198.51.100.7",
        NOW_UNIX,
        NOW_NS,
        0,
        None,
        true,
        Some("login-action"),
        Some(1),
        true,
    )
    .expect("v4 issuance");
    assert_eq!(issued.record.protocol_version, 4);
    assert!(
        issued.record.decoy_field.is_some(),
        "the v4 record carries the decoy segment"
    );
    assert_eq!(issued.record.execution_version, Some(1));
    assert_eq!(
        kiwicaptcha::challenge::execution_commitment(
            issued.record.execution_program.as_deref().unwrap()
        ),
        issued.record.execution_commitment.as_deref().unwrap(),
        "the signed commitment mirrors the stored program"
    );

    assert_eq!(
        validate_record(&issued.record),
        Ok(()),
        "the current verifier's acceptance set includes protocol 4"
    );
    assert_eq!(
        accepts_with_max(&issued.record, 2),
        Err(VerifyError::MalformedRecord),
        "a v2-only verifier must reject a v4 record as MalformedRecord"
    );
    assert_eq!(
        accepts_with_max(&issued.record, 3),
        Err(VerifyError::MalformedRecord),
        "a v3-only verifier must reject a v4 record as MalformedRecord"
    );
    assert!(
        accepts_with_max(&issued.record, 4).is_ok(),
        "the current generation accepts v4 (its own max protocol)"
    );

    // The full verification path on the current verifier: solve the
    // record and verify it end to end with the recomputed execution
    // digest.
    let program = issued.record.execution_program.as_deref().unwrap();
    let decoded = kiwicaptcha::execution::decode(program).expect("program parses");
    let trace = kiwicaptcha::execution::executed_trace_for(&decoded);
    let trace_b64: String = kiwicaptcha_verify_base64(&trace);
    let digest =
        kiwicaptcha::execution::expected_digest_over_trace(program, &issued.record.nonce, &trace)
            .expect("digest");
    let counter = solve_for_test(&issued.record).expect("solver finds a counter");
    let mut rec = issued.record.clone();
    let mut clock = || NOW_UNIX;
    let mut ctx = verify_ctx(&mut rec, counter, &mut clock, NOW_NS + 1_000_000);
    ctx.execution_digest = Some(&digest);
    ctx.execution_trace = Some(&trace_b64);
    assert!(
        matches!(verify_solution(&mut ctx), VerifyOutcome::Valid { .. }),
        "the current verifier must accept its own v4 record end to end"
    );
}

#[test]
fn acceptance_predicate_pins_the_set_boundaries() {
    // The acceptance-predicate boundary matrix: the set is exactly
    // 1..=max. Protocol 0 (unknown) fails everywhere; a bare protocol-4
    // record without the execution triplet fails the current grammar
    // (the commitment is mandatory on v4) AND the v3-only acceptance
    // set; the current generation's own max is 4.
    let mut record = kiwicaptcha::ChallengeRecord {
        nonce: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".into(),
        scope: "login".into(),
        binding_tag: String::new(),
        issued_at: NOW_UNIX,
        expires_at: NOW_UNIX + 120,
        algorithm: PoWAlgorithm::Sha256,
        m_kib: 0,
        t: 1,
        p: 1,
        target_bits: 8,
        salt: "c2FsdA==".into(),
        prefix: "challenge|".into(),
        challenge: "challenge".into(),
        min_duration_ms: 0,
        issued_at_ns: NOW_NS,
        attempts_used: 0,
        protocol_version: 0,
        region: None,
        policy_version: 1,
        request_binding: None,
        issuer: None,
        hostname: None,
        decoy_field: None,
        execution_program: None,
        execution_version: None,
        execution_commitment: None,
        kid: 1,
    };
    for version in [0u8, 4u8] {
        record.protocol_version = version;
        assert_eq!(
            accepts_with_max(&record, 3),
            Err(VerifyError::MalformedRecord),
            "protocol version {version} must fail closed as MalformedRecord against a v3-only binary"
        );
        assert_eq!(
            validate_record(&record),
            Err(VerifyError::MalformedRecord),
            "protocol version {version} fails the current grammar too (4 without the execution triplet is malformed)"
        );
    }
    record.protocol_version = 3;
    assert_eq!(
        accepts_with_max(&record, 2),
        Err(VerifyError::MalformedRecord),
        "protocol 3 is outside the parent revision's acceptance set"
    );
    assert_eq!(
        validate_record(&record),
        Err(VerifyError::MalformedRecord),
        "a decoyless v3 record fails the current grammar (the decoy is mandatory on v3)"
    );
}

fn kiwicaptcha_verify_base64(trace: &str) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .encode(trace.as_bytes())
        .replace('+', "-")
        .replace('/', "_")
        .trim_end_matches('=')
        .to_string()
}
