//! The no-panic invariant under attacker-controlled
//! input.
//!
//! ~5000 deterministic random byte mutations of a valid solution token and a
//! valid record JSON (seeded — reproducible): every public parse path
//! (`SolutionToken::decode`, `ChallengeRecord` deserialization,
//! `validate_record`, `verify_solution`) must return `Ok`/`Err` — a panic is
//! a test failure.
//!
//! Kept fast by construction: the seed record is SHA-256, and a mutation can
//! only preserve the v2 signature by hitting the unsigned record fields
//! (`issued_at_ns` / `attempts_used`) — so `verify_solution` never derives a
//! memory-hard hash inside the loop (a mutated `algorithm`/parameter breaks
//! the signature before derivation, and the Argon ceilings are validated
//! pre-signature anyway).

use kiwicaptcha::challenge::{
    issue_challenge, BindingMode, ChallengeConfig, ChallengeRecord, PoWAlgorithm,
};
use kiwicaptcha::token::SolutionToken;
use kiwicaptcha::verify::{
    validate_record, verify_solution, RequestBindingExpectation, VerifyContext,
};
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

const SECRET: &str = "0123456789abcdef0123456789abcdef";
const IP: &str = "198.51.100.7";
const NOW_UNIX: u64 = 1_700_000_000;
const NOW_NS: u64 = 1_700_000_000_000_000;

fn sha_config(target_bits: u32) -> ChallengeConfig {
    ChallengeConfig {
        secret_key: SECRET.into(),
        kid: 1,
        execution_key: None,
        algorithm: PoWAlgorithm::Sha256,
        m_kib: 0,
        t: 1,
        p: 1,
        target_bits,
        argon2_target_bits: target_bits,
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

#[test]
fn byte_mutations_never_panic_on_any_parse_path() {
    let mut rng = StdRng::seed_from_u64(0x5EED_00D1_0115);

    let issued = issue_challenge(&sha_config(4), "login", IP, NOW_UNIX, NOW_NS, 0, None).unwrap();
    let token = SolutionToken {
        nonce: issued.record.nonce.clone(),
        counter: 1,
        duration_ms: 5000,
        telemetry: serde_json::json!({"v": 2, "mode": "full", "wd": false, "me": 1, "ke": 2}),
        execution_digest: None,
        execution_trace: None,
    }
    .encode()
    .into_bytes();
    let record_json = serde_json::to_string(&issued.record).unwrap().into_bytes();

    let mut token_mutations = 0usize;
    let mut record_mutations = 0usize;

    for _ in 0..2500 {
        // ── Token mutation: flip one random byte to a random value. ──────
        let mut mutated = token.clone();
        let idx = rng.gen_range(0..mutated.len());
        mutated[idx] = rng.gen::<u8>();
        let s = String::from_utf8_lossy(&mutated);
        let _ = SolutionToken::decode(&s); // must return Ok/Err, never panic
        token_mutations += 1;

        // ── Record mutation: flip one random byte to a random value. ────
        let mut mutated = record_json.clone();
        let idx = rng.gen_range(0..mutated.len());
        mutated[idx] = rng.gen::<u8>();
        let s = String::from_utf8_lossy(&mutated);
        if let Ok(record) = serde_json::from_str::<ChallengeRecord>(&s) {
            // A parsed record must survive the structural validator…
            let _ = validate_record(&record);
            // …and the full verification path (attempt accounting, cheap
            // phase, signature, TTL, binding, derivation, re-validation).
            let mut rec = record;
            let mut ctx = VerifyContext {
                record: &mut rec,
                secret_key: SECRET,
                secrets_by_kid: None,
                revoked_kids: None,
                counter: 1,
                duration_ms: 5000,
                now_unix: Some(&mut || NOW_UNIX + 1),
                now_ns: NOW_NS + 1_000_000,
                min_duration_ms: 0,
                expected_scope: None,
                expected_request_binding: RequestBindingExpectation::Unenforced,
                expected_region: None,
                expected_issuer: None,
                expected_policy_version: None,
                client_ip: Some(IP),
                execution_digest: None,
                execution_trace: None,
                telemetry: None,
                enforce_telemetry: false,
                max_attempts: 0,
                accept_legacy_v1: false,
            };
            let _ = verify_solution(&mut ctx); // must return an outcome, never panic
        }
        record_mutations += 1;
    }

    assert_eq!(token_mutations, 2500, "every token mutation was exercised");
    assert_eq!(
        record_mutations, 2500,
        "every record mutation was exercised"
    );
}
