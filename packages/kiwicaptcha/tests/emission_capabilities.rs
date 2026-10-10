//! The protocol-v5 emission-capability matrix: the ceiling is a real
//! authority over every protocol extension, not a hint. Arming beyond it
//! fails issuance explicitly; no writer ever emits a protocol version
//! above the confirmed ceiling; a ceiling below the base protocol is
//! rejected at construction; and the rsw modulus identity is the one
//! documented fallback (it degrades to the identityless base shape below
//! the feature version).

use kiwicaptcha::challenge::{
    issue_challenge_with_capabilities, issue_challenge_with_decoy_capabilities,
    issue_challenge_with_execution_capabilities, BindingMode, ChallengeConfig,
    EmissionCapabilities, EmissionCapabilityError, PoWAlgorithm, SignError, BASE_PROTOCOL_VERSION,
    DECOY_PROTOCOL_VERSION, EXECUTION_PROTOCOL_VERSION, RSW_IDENTITY_PROTOCOL_VERSION,
};
use kiwicaptcha::rsw::fixtures::{LAMBDA_B64, MODULUS_N_B64};
use kiwicaptcha::verify::{
    verify_solution, RequestBindingExpectation, VerifyContext, VerifyOutcome,
};

const SECRET: &str = "0123456789abcdef0123456789abcdef";
const NOW_UNIX: u64 = 1_800_000_000;
const NOW_NS: u64 = NOW_UNIX * 1_000_000;

fn caps(value: u8) -> EmissionCapabilities {
    EmissionCapabilities::confirmed(value).expect("the test ceilings are valid")
}

fn base_config() -> ChallengeConfig {
    ChallengeConfig {
        secret_key: SECRET.into(),
        kid: 1,
        execution_key: Some("execution-key-32-bytes-0123456789ab".into()),
        rsw_modulus_n: None,
        rsw_lambda: None,
        rsw_t: kiwicaptcha::challenge::MIN_RSW_T,
        tenant: None,
        algorithm: PoWAlgorithm::Sha256,
        m_kib: 0,
        t: 1,
        p: 1,
        target_bits: 8,
        argon2_target_bits: 8,
        ttl_secs: 120,
        min_duration_ms: Some(0),
        auto_tune: false,
        auto_tune_min_bits: 8,
        auto_tune_max_bits: 20,
        binding_mode: BindingMode::Bound,
        region: None,
        issuer: None,
        policy_version: 1,
    }
}

fn rsw_config() -> ChallengeConfig {
    ChallengeConfig {
        rsw_modulus_n: Some(MODULUS_N_B64.into()),
        rsw_lambda: Some(LAMBDA_B64.into()),
        algorithm: PoWAlgorithm::Rsw,
        ..base_config()
    }
}

#[test]
fn ceilings_below_the_base_protocol_are_rejected() {
    for value in [0u8, 1] {
        assert_eq!(
            EmissionCapabilities::confirmed(value),
            Err(EmissionCapabilityError::BelowBase)
        );
    }
    assert!(EmissionCapabilities::confirmed(BASE_PROTOCOL_VERSION).is_ok());
}

#[test]
fn the_default_capability_is_capability_free() {
    let default = EmissionCapabilities::default();
    assert_eq!(default.max_protocol_version(), BASE_PROTOCOL_VERSION);
    assert!(default.admits_base());
    assert!(!default.admits_decoy());
    assert!(!default.admits_execution());
    assert!(!default.admits_rsw_identity());
    assert!(caps(DECOY_PROTOCOL_VERSION).admits_decoy());
    assert!(!caps(DECOY_PROTOCOL_VERSION).admits_execution());
    assert!(caps(EXECUTION_PROTOCOL_VERSION).admits_execution());
    assert!(!caps(EXECUTION_PROTOCOL_VERSION).admits_rsw_identity());
    assert!(caps(RSW_IDENTITY_PROTOCOL_VERSION).admits_rsw_identity());
}

#[test]
fn arming_beyond_the_confirmed_ceiling_fails_explicitly() {
    // Decoy armed below version 3.
    assert!(matches!(
        issue_challenge_with_decoy_capabilities(
            caps(BASE_PROTOCOL_VERSION),
            &base_config(),
            "login",
            "198.51.100.7",
            NOW_UNIX,
            NOW_NS,
            0,
            None,
            true,
        ),
        Err(SignError::EmissionCapabilityExceeded)
    ));
    // Execution armed below version 4.
    assert!(matches!(
        issue_challenge_with_execution_capabilities(
            caps(DECOY_PROTOCOL_VERSION),
            &base_config(),
            "login",
            "198.51.100.7",
            NOW_UNIX,
            NOW_NS,
            0,
            None,
            true,
            Some("login-action"),
            Some(1),
            false,
        ),
        Err(SignError::EmissionCapabilityExceeded)
    ));
    // Decoy + execution at version 4 is admitted and emits v4.
    let composed = issue_challenge_with_execution_capabilities(
        caps(EXECUTION_PROTOCOL_VERSION),
        &base_config(),
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
    .expect("the composed arms fit the confirmed ceiling");
    assert_eq!(composed.record.protocol_version, EXECUTION_PROTOCOL_VERSION);
}

#[test]
fn no_emission_ever_exceeds_the_confirmed_ceiling() {
    let config = base_config();
    for ceiling in [2u8, 3, 4, 5] {
        let plain = issue_challenge_with_capabilities(
            caps(ceiling),
            &config,
            "login",
            "198.51.100.7",
            NOW_UNIX,
            NOW_NS,
            0,
            None,
        )
        .expect("plain issuance fits every ceiling");
        assert_eq!(plain.record.protocol_version, BASE_PROTOCOL_VERSION);
        assert!(plain.record.protocol_version <= ceiling);

        match issue_challenge_with_decoy_capabilities(
            caps(ceiling),
            &config,
            "login",
            "198.51.100.7",
            NOW_UNIX,
            NOW_NS,
            0,
            None,
            true,
        ) {
            Ok(decoy) => {
                assert!(
                    ceiling >= DECOY_PROTOCOL_VERSION,
                    "ceiling {ceiling} admitted the decoy"
                );
                assert_eq!(decoy.record.protocol_version, DECOY_PROTOCOL_VERSION);
                assert!(decoy.record.protocol_version <= ceiling);
            }
            Err(err) => {
                assert!(matches!(err, SignError::EmissionCapabilityExceeded));
                assert!(
                    ceiling < DECOY_PROTOCOL_VERSION,
                    "ceiling {ceiling} refused the decoy"
                );
            }
        }

        match issue_challenge_with_execution_capabilities(
            caps(ceiling),
            &config,
            "login",
            "198.51.100.7",
            NOW_UNIX,
            NOW_NS,
            0,
            None,
            true,
            Some("login-action"),
            Some(1),
            false,
        ) {
            Ok(execution) => {
                assert!(
                    ceiling >= EXECUTION_PROTOCOL_VERSION,
                    "ceiling {ceiling} admitted the execution"
                );
                assert_eq!(
                    execution.record.protocol_version,
                    EXECUTION_PROTOCOL_VERSION
                );
                assert!(execution.record.protocol_version <= ceiling);
            }
            Err(err) => {
                assert!(matches!(err, SignError::EmissionCapabilityExceeded));
                assert!(
                    ceiling < EXECUTION_PROTOCOL_VERSION,
                    "ceiling {ceiling} refused the execution"
                );
            }
        }
    }
}

#[test]
fn the_rsw_identity_is_the_one_documented_fallback() {
    let config = rsw_config();
    for ceiling in [BASE_PROTOCOL_VERSION, EXECUTION_PROTOCOL_VERSION] {
        let issued = issue_challenge_with_capabilities(
            caps(ceiling),
            &config,
            "login",
            "198.51.100.7",
            NOW_UNIX,
            NOW_NS,
            0,
            None,
        )
        .expect("rsw issuance falls back, never fails");
        assert_eq!(issued.record.protocol_version, BASE_PROTOCOL_VERSION);
        assert_eq!(issued.record.rsw_modulus_sha256, None);
    }
    for ceiling in [RSW_IDENTITY_PROTOCOL_VERSION, 6] {
        let issued = issue_challenge_with_capabilities(
            caps(ceiling),
            &config,
            "login",
            "198.51.100.7",
            NOW_UNIX,
            NOW_NS,
            0,
            None,
        )
        .expect("rsw issuance");
        assert_eq!(
            issued.record.protocol_version,
            RSW_IDENTITY_PROTOCOL_VERSION
        );
        assert_eq!(
            issued.record.rsw_modulus_sha256.as_deref(),
            Some(
                kiwicaptcha::rsw::modulus_fingerprint_hex(MODULUS_N_B64)
                    .expect("the fixture modulus is canonical")
                    .as_str()
            )
        );
    }
}

#[test]
fn a_capped_rsw_record_still_verifies_through_the_reader_path() {
    // The fallback is not a broken challenge: a pre-v5 reader accepts the
    // identityless base shape and the sequential proof verifies.
    let config = rsw_config();
    let issued = issue_challenge_with_capabilities(
        caps(EXECUTION_PROTOCOL_VERSION),
        &config,
        "login",
        "198.51.100.7",
        NOW_UNIX,
        NOW_NS,
        0,
        None,
    )
    .expect("rsw issuance");
    let proof = kiwicaptcha::rsw::fixtures::sequential_proof(
        &issued.record.prefix,
        &issued.record.nonce,
        issued.record.t as u64,
    );
    let mut record = issued.record;
    let outcome = verify_solution(&mut VerifyContext {
        record: &mut record,
        secret_key: SECRET,
        tenant: None,
        secrets_by_kid: None,
        revoked_kids: None,
        counter: 0,
        duration_ms: 5000,
        now_unix: Some(&mut || NOW_UNIX + 1),
        now_ns: NOW_NS + 1_000_000,
        min_duration_ms: 0,
        expected_scope: Some("login"),
        expected_request_binding: RequestBindingExpectation::Unenforced,
        expected_region: None,
        expected_issuer: None,
        expected_policy_version: None,
        policy_version_floor: None,
        client_ip: Some("198.51.100.7"),
        execution_digest: None,
        execution_trace: None,
        telemetry: None,
        enforce_telemetry: false,
        max_attempts: 0,
        accept_legacy_v1: false,
        rsw_proof: Some(&proof),
        rsw_modulus_n: Some(MODULUS_N_B64),
        rsw_lambda: Some(LAMBDA_B64),
        rsw_keyring: None,
    });
    assert!(matches!(outcome, VerifyOutcome::Valid { .. }));
}
