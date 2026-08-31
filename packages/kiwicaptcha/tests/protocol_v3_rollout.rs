//! Protocol-v3 two-phase rollout invariants, Rust side.
//!
//! The mixed-fleet contract: a decoy-armed (protocol v3) record issued
//! by the current generation verifies through the current verifier,
//! whose acceptance set is {1, 2, 3}, while the same record is rejected
//! as MalformedRecord by a simulated parent-revision verifier whose
//! acceptance set is {1, 2} — the exact old-binary behavior the rollout
//! protects against. The symmetric invariant: an unarmed v2 record
//! verifies through both generations, so a mixed fleet serving v2
//! traffic never breaks a solve.
//!
//! The parent-revision simulation is the version-acceptance predicate
//! with an explicit max protocol ([`accepts_with_max`]): a binary whose
//! max protocol is `max` accepts exactly 1..=max and fails closed as
//! MalformedRecord outside the set, before any further structural
//! check, exactly like the parent revision's `validate_record` gate.
//! Every other check is byte-identical across the revision boundary, so
//! the accepted versions delegate to the current `validate_record`.

use kiwicaptcha::challenge::{
    issue_challenge_with_decoy, BindingMode, ChallengeConfig, PoWAlgorithm,
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
fn acceptance_predicate_pins_the_set_boundaries() {
    // The acceptance-predicate boundary matrix: the set is exactly
    // 1..=max. Protocol 0 (unknown), 3 against a max of 2 (the
    // parent-revision rejection) and 4 (beyond the current generation's
    // own max) are all MalformedRecord; the current generation's own
    // max is 3.
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
        kid: 1,
    };
    for version in [0u8, 4u8] {
        record.protocol_version = version;
        assert_eq!(
            accepts_with_max(&record, 3),
            Err(VerifyError::MalformedRecord),
            "protocol version {version} must fail closed as MalformedRecord"
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
