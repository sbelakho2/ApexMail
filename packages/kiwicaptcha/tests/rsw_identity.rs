//! The one canonical rsw modulus identity and the identity-selection
//! rules of the rotation keyring, asserted against the shared
//! cross-language fixture (protocol/rsw-identity-v1/fixtures.json): the
//! exact 64 hex characters the rsw-keygen, the PHP core and this crate
//! must all produce from the same modulus, plus A->A acceptance, A->B
//! rejection, rotated A historical with B active, unknown-identity
//! rejection, the legacy base64-text alias window, and the explicit
//! negative: a B proof computed for an A-bound record must never pass.

use kiwicaptcha::challenge::{
    issue_challenge_with_capabilities, BindingMode, ChallengeConfig, PoWAlgorithm,
};
use kiwicaptcha::rsw::{
    legacy_base64_text_fingerprint_hex, modulus_fingerprint_hex, resolve_rsw_trapdoor, RswKeyring,
    RswKeyringError, RswResolutionError, RswTrapdoor,
};
use kiwicaptcha::verify::{
    verify_solution, RequestBindingExpectation, VerifyContext, VerifyError, VerifyOutcome,
};

const SECRET: &str = "0123456789abcdef0123456789abcdef";
const NOW_UNIX: u64 = 1_800_000_000;
const NOW_NS: u64 = NOW_UNIX * 1_000_000;

fn fixture() -> serde_json::Value {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../protocol/rsw-identity-v1/fixtures.json"
    );
    let raw = std::fs::read_to_string(path).expect("the shared rsw identity fixture exists");
    serde_json::from_str(&raw).expect("the fixture is JSON")
}

fn s<'a>(fixture: &'a serde_json::Value, path: &[&str]) -> &'a str {
    let mut value = fixture;
    for key in path {
        value = value.get(*key).expect("fixture path");
    }
    value.as_str().expect("fixture string")
}

fn rsw_config(modulus_b64: &str, lambda_b64: &str) -> ChallengeConfig {
    ChallengeConfig {
        secret_key: SECRET.into(),
        kid: 1,
        execution_key: None,
        rsw_modulus_n: Some(modulus_b64.into()),
        rsw_lambda: Some(lambda_b64.into()),
        rsw_t: kiwicaptcha::challenge::MIN_RSW_T,
        tenant: None,
        algorithm: PoWAlgorithm::Rsw,
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

fn issued(modulus_b64: &str, lambda_b64: &str) -> kiwicaptcha::challenge::Issued {
    // These interop cases test the identity-bearing generation, so the
    // capability ceiling is confirmed explicitly (the plain
    // issue_challenge default is the capability-free legacy shape).
    issue_challenge_with_capabilities(
        kiwicaptcha::challenge::EmissionCapabilities::confirmed(
            kiwicaptcha::challenge::RSW_IDENTITY_PROTOCOL_VERSION,
        )
        .expect("the confirmed ceiling is at least the base protocol"),
        &rsw_config(modulus_b64, lambda_b64),
        "login",
        "198.51.100.7",
        NOW_UNIX,
        NOW_NS,
        0,
        None,
    )
    .expect("rsw issuance")
}

/// Verify one record with the given active pair / keyring / proof.
fn verify(
    record: &mut kiwicaptcha::ChallengeRecord,
    proof: &str,
    active: Option<(&str, &str)>,
    keyring: Option<&RswKeyring>,
) -> VerifyOutcome {
    verify_solution(&mut VerifyContext {
        record,
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
        rsw_proof: Some(proof),
        rsw_modulus_n: active.map(|(modulus, _)| modulus),
        rsw_lambda: active.map(|(_, lambda)| lambda),
        rsw_keyring: keyring,
    })
}

#[test]
fn the_three_components_agree_on_the_canonical_fingerprint() {
    let fixture = fixture();
    let modulus = s(&fixture, &["modulus_n_b64"]);
    let canonical = s(&fixture, &["rsw_modulus_n_sha256"]);
    let legacy = s(&fixture, &["legacy_base64_text_sha256"]);

    assert_eq!(
        modulus,
        kiwicaptcha::rsw::fixtures::MODULUS_N_B64,
        "the fixture and the suite share one modulus"
    );
    assert_eq!(
        modulus_fingerprint_hex(modulus).unwrap(),
        canonical,
        "the Rust canonical fingerprint equals the keygen rsw_modulus_n_sha256"
    );
    assert_eq!(
        legacy_base64_text_fingerprint_hex(modulus),
        legacy,
        "the legacy alias is the historical base64-text rule"
    );
    assert_ne!(
        canonical, legacy,
        "the canonical identity and the legacy alias are distinct"
    );
    assert!(
        modulus_fingerprint_hex("not base64!").is_err(),
        "a non-canonical modulus mints no identity"
    );
}

#[test]
fn an_invalid_keyring_entry_is_refused_at_configuration() {
    // The shadowing hazard: active A is valid, but a historical keyring
    // entry carries A with a bad lambda. Configuring it must fail, not
    // turn valid A challenges into UnsupportedRswParams — once insert()
    // validates the full pair, the invalid entry cannot exist and the
    // resolver can never shadow the active pair with it.
    let fixture = fixture();
    let modulus = s(&fixture, &["modulus_n_b64"]);
    let lambda = s(&fixture, &["lambda_b64"]);
    let identity = s(&fixture, &["rsw_modulus_n_sha256"]);

    let mut ring = RswKeyring::new();
    assert_eq!(
        ring.insert(identity, modulus, "not-a-lambda!"),
        Err(RswKeyringError::InvalidTrapdoor),
        "a pair that fails trapdoor validation is refused"
    );
    assert!(
        ring.is_empty(),
        "the refused entry was never stored, so it cannot shadow the active pair"
    );
    assert_eq!(
        ring.insert(&"f".repeat(64), modulus, lambda),
        Err(RswKeyringError::MismatchedIdentity)
    );
    assert_eq!(
        ring.insert("not-an-identity", "not-base64!", lambda),
        Err(RswKeyringError::InvalidModulus),
        "the modulus is canonical-decoded before anything else"
    );

    // A valid entry inserts, and the resolver still selects the active
    // pair for the active identity.
    ring.insert(identity, modulus, lambda)
        .expect("the valid pair inserts");
    let resolved = resolve_rsw_trapdoor(Some((modulus, lambda)), Some(&ring), Some(identity), 5);
    assert!(resolved.expect("resolution succeeds").is_some());
}

#[test]
fn the_keyring_registers_both_identity_forms_and_refuses_mismatches() {
    let fixture = fixture();
    let modulus = s(&fixture, &["modulus_n_b64"]);
    let lambda = kiwicaptcha::rsw::fixtures::LAMBDA_B64;
    let canonical = s(&fixture, &["rsw_modulus_n_sha256"]);
    let legacy = s(&fixture, &["legacy_base64_text_sha256"]);

    // The migration mode OFF (the default): only the canonical identity
    // form is accepted and registered.
    let mut keyring = RswKeyring::new();
    assert_eq!(
        keyring.insert(legacy, modulus, lambda),
        Err(RswKeyringError::MismatchedIdentity),
        "a legacy-alias key is refused while the migration mode is off"
    );
    keyring
        .insert(canonical, modulus, lambda)
        .expect("the canonical identity is accepted");
    assert_eq!(keyring.len(), 1, "only the canonical form is registered");
    assert!(keyring.lookup(canonical).is_some());
    assert!(keyring.lookup(legacy).is_none());

    // The migration mode ON: both identity forms are accepted and
    // registered, as documented for the bounded drain.
    for identity in [canonical, legacy] {
        let mut ring = RswKeyring::new().with_legacy_aliases(true);
        ring.insert(identity, modulus, lambda)
            .expect("both identity forms are accepted in the migration mode");
        assert_eq!(ring.len(), 2, "both computed forms are registered");
        assert!(ring.lookup(canonical).is_some());
        assert!(ring.lookup(legacy).is_some());
    }
    let mut keyring = RswKeyring::new();
    assert!(
        keyring.insert(&"f".repeat(64), modulus, lambda).is_err(),
        "a mismatched identity is refused"
    );
    assert_eq!(
        resolve_rsw_trapdoor(
            Some((
                s(&fixture, &["secondary", "modulus_n_b64"]),
                s(&fixture, &["secondary", "lambda_b64"])
            )),
            Some(&keyring),
            Some(canonical),
            5,
        )
        .map(|t| t.is_some())
        .unwrap_err(),
        RswResolutionError::UnknownIdentity,
        "an empty keyring leaves the identity unknown"
    );
}

#[test]
fn identity_selection_is_exact_and_never_falls_through() {
    let fixture = fixture();
    let modulus_a = s(&fixture, &["modulus_n_b64"]);
    let lambda_a = s(&fixture, &["lambda_b64"]);
    let modulus_b = s(&fixture, &["secondary", "modulus_n_b64"]);
    let lambda_b = s(&fixture, &["secondary", "lambda_b64"]);
    let identity_a = s(&fixture, &["rsw_modulus_n_sha256"]);
    let legacy_a = s(&fixture, &["legacy_base64_text_sha256"]);

    let mut keyring_a = RswKeyring::new();
    keyring_a.insert(identity_a, modulus_a, lambda_a).unwrap();

    // A -> A acceptance.
    let mut record = issued(modulus_a, lambda_a).record;
    assert_eq!(record.protocol_version, 5);
    assert_eq!(record.rsw_modulus_sha256.as_deref(), Some(identity_a));
    let proof = kiwicaptcha::rsw::fixtures::sequential_proof(
        &record.prefix,
        &record.nonce,
        record.t as u64,
    );
    assert!(matches!(
        verify(
            &mut record,
            &proof,
            Some((modulus_a, lambda_a)),
            Some(&keyring_a)
        ),
        VerifyOutcome::Valid { .. }
    ));

    // A -> B rejection (unknown identity, never the active pair).
    let mut record = issued(modulus_a, lambda_a).record;
    let proof = kiwicaptcha::rsw::fixtures::sequential_proof(
        &record.prefix,
        &record.nonce,
        record.t as u64,
    );
    assert_eq!(
        verify(
            &mut record,
            &proof,
            Some((modulus_b, lambda_b)),
            Some(&RswKeyring::new())
        ),
        VerifyOutcome::Invalid(VerifyError::UnsupportedRswParams)
    );

    // Rotated A historical, B active: the keyring resolves the record.
    let mut record = issued(modulus_a, lambda_a).record;
    let proof = kiwicaptcha::rsw::fixtures::sequential_proof(
        &record.prefix,
        &record.nonce,
        record.t as u64,
    );
    assert!(matches!(
        verify(
            &mut record,
            &proof,
            Some((modulus_b, lambda_b)),
            Some(&keyring_a)
        ),
        VerifyOutcome::Valid { .. }
    ));

    // The legacy alias resolves only a pre-v5 identity. The v5 record
    // always carries the canonical identity; a v5 record whose identity
    // is the legacy alias is refused by the resolver.
    assert_eq!(
        resolve_rsw_trapdoor(
            Some((modulus_a, lambda_a)),
            Some(&keyring_a),
            Some(legacy_a),
            5
        )
        .map(|t| t.is_some())
        .unwrap_err(),
        RswResolutionError::UnknownIdentity
    );
    // ... and the alias does NOT resolve a protocol-2 record either while
    // the migration mode is off (default): the temporary grammar is
    // removable, so a drained deployment refuses it fail-closed.
    assert_eq!(
        resolve_rsw_trapdoor(
            Some((modulus_a, lambda_a)),
            Some(&keyring_a),
            Some(legacy_a),
            2
        )
        .map(|t| t.is_some())
        .unwrap_err(),
        RswResolutionError::UnknownIdentity,
        "the migration mode is off by default"
    );
    // ... while the same alias resolves a protocol-2 record once the
    // bounded migration window is explicitly enabled.
    let migration = RswKeyring::new().with_legacy_aliases(true);
    assert!(resolve_rsw_trapdoor(
        Some((modulus_a, lambda_a)),
        Some(&migration),
        Some(legacy_a),
        2
    )
    .unwrap()
    .is_some());

    // A v5 record without the identity is refused (identity required).
    assert_eq!(
        resolve_rsw_trapdoor(Some((modulus_a, lambda_a)), Some(&keyring_a), None, 5).unwrap_err(),
        RswResolutionError::IdentityRequired
    );
    // ... while a pre-v5 identityless record uses the explicit legacy
    // active-pair behavior.
    assert!(
        resolve_rsw_trapdoor(Some((modulus_a, lambda_a)), Some(&keyring_a), None, 2)
            .unwrap()
            .is_some()
    );
}

#[test]
fn a_b_proof_computed_for_an_a_bound_record_never_passes() {
    let fixture = fixture();
    let modulus_a = s(&fixture, &["modulus_n_b64"]);
    let lambda_a = s(&fixture, &["lambda_b64"]);
    let modulus_b = s(&fixture, &["secondary", "modulus_n_b64"]);
    let lambda_b = s(&fixture, &["secondary", "lambda_b64"]);
    let identity_a = s(&fixture, &["rsw_modulus_n_sha256"]);

    let mut keyring_a = RswKeyring::new();
    keyring_a.insert(identity_a, modulus_a, lambda_a).unwrap();
    let trapdoor_b =
        RswTrapdoor::validated(modulus_b, lambda_b).expect("the secondary pair validates");

    // The attacker holds an A-bound record and the public modulus B:
    // they compute the sequential squarings under B and submit that
    // final value.
    let mut record = issued(modulus_a, lambda_a).record;
    assert_eq!(record.rsw_modulus_sha256.as_deref(), Some(identity_a));
    let b_proof = trapdoor_b.expected_proof_hex(&record.prefix, &record.nonce, record.t as u64);

    // A verifier configured with B as its active pair refuses: the
    // authenticated identity A does not resolve under B.
    assert_eq!(
        verify(
            &mut record,
            &b_proof,
            Some((modulus_b, lambda_b)),
            Some(&RswKeyring::new())
        ),
        VerifyOutcome::Invalid(VerifyError::UnsupportedRswParams)
    );

    // Even a verifier that owns A (through the keyring) must not accept
    // the B proof: the proof is checked under A and fails.
    assert_eq!(
        verify(
            &mut record,
            &b_proof,
            Some((modulus_b, lambda_b)),
            Some(&keyring_a)
        ),
        VerifyOutcome::Invalid(VerifyError::InsufficientWork)
    );

    // Control: the correct A proof passes.
    let mut record = issued(modulus_a, lambda_a).record;
    let a_proof = kiwicaptcha::rsw::fixtures::sequential_proof(
        &record.prefix,
        &record.nonce,
        record.t as u64,
    );
    assert!(matches!(
        verify(&mut record, &a_proof, Some((modulus_a, lambda_a)), None),
        VerifyOutcome::Valid { .. }
    ));
}
