//! Redis-backed production verifier integration tests.
//!
//! Gated two ways:
//! - The whole file compiles only with `--features redis`.
//! - Every test that touches Redis skips (returns) unless `RISK_REDIS_URL`
//!   is set — the same env-gated pattern as `tests/cross_language.rs` — so
//!   local `cargo test --features redis` stays hermetic. The pure-JSON
//!   cross-language key-parity test runs without Redis.

#![cfg(feature = "redis")]

use std::collections::BTreeSet;
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

use kiwicaptcha::challenge::{
    issue_challenge, BindingMode, ChallengeConfig, ChallengeRecord, PoWAlgorithm,
};
use kiwicaptcha::redis_verify::{ProductionVerifier, RedisChallengeStore};
use kiwicaptcha::token::SolutionToken;
use kiwicaptcha::verify::{solve_for_test, VerifyError, VerifyOutcome};

const SECRET: &str = "0123456789abcdef0123456789abcdef";
const IP: &str = "198.51.100.7";

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn now_micros() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_micros() as u64
}

/// Test prefix unique per process so concurrent test binaries never collide.
fn prefix(label: &str) -> String {
    format!("kiwitest:{}:{label}:", std::process::id())
}

fn redis_url() -> Option<String> {
    match std::env::var("RISK_REDIS_URL") {
        Ok(url) => Some(url),
        Err(_) => {
            eprintln!("RISK_REDIS_URL unset — Redis integration tests skipped");
            None
        }
    }
}

fn sha_config(target_bits: u32) -> ChallengeConfig {
    ChallengeConfig {
        secret_key: SECRET.into(),
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
    }
}

fn argon_config(target_bits: u32) -> ChallengeConfig {
    ChallengeConfig {
        secret_key: SECRET.into(),
        algorithm: PoWAlgorithm::Argon2id,
        m_kib: 128,
        t: 3,
        p: 1,
        target_bits,
        argon2_target_bits: target_bits,
        ttl_secs: 120,
        min_duration_ms: None,
        auto_tune: false,
        auto_tune_min_bits: 8,
        auto_tune_max_bits: 20,
        binding_mode: BindingMode::Bound,
    }
}

fn store_for(url: &str, prefix: &str) -> RedisChallengeStore {
    RedisChallengeStore::new(redis::Client::open(url).unwrap(), prefix.to_string())
}

fn verifier_for(url: &str, prefix: &str) -> ProductionVerifier {
    ProductionVerifier::new(store_for(url, prefix), SECRET)
}

fn encode_token(nonce: &str, counter: u64) -> String {
    SolutionToken {
        nonce: nonce.into(),
        counter,
        duration_ms: 5000,
        telemetry: serde_json::json!({}),
    }
    .encode()
}

/// Verify with a receipt time 1 s after issuance — safely above every
/// derived minimum-duration floor (SHA 5 ms, Argon2id 50 ms).
fn verify_at(verifier: &ProductionVerifier, token: &str, issued_at_ns: u64) -> VerifyOutcome {
    verifier.verify(token, "login", IP, issued_at_ns + 1_000_000)
}

#[test]
fn valid_solution_verifies_and_wire_format_is_language_neutral() {
    let Some(url) = redis_url() else { return };
    let prefix = prefix("valid");
    let issued = issue_challenge(&sha_config(4), "login", IP, now_unix(), now_micros(), 0).unwrap();
    let counter = solve_for_test(&issued.record).expect("4-bit sha solves");

    let store = store_for(&url, &prefix);
    store.store(&issued.record).unwrap();

    // The stored value must round-trip byte-exactly through the same JSON
    // schema a PHP RedisStorage would read/write.
    let key = format!("{prefix}{}", issued.record.nonce);
    let mut conn = redis::Client::open(url.clone())
        .unwrap()
        .get_connection()
        .unwrap();
    let raw: String = redis::cmd("GET").arg(&key).query(&mut conn).unwrap();
    assert_eq!(
        serde_json::to_string(&issued.record).unwrap(),
        raw,
        "stored wire format must be the canonical ChallengeRecord JSON"
    );
    let decoded: ChallengeRecord = serde_json::from_str(&raw).unwrap();
    assert_eq!(decoded.nonce, issued.record.nonce);
    assert_eq!(decoded.protocol_version, 2);

    // EX TTL is expires_at - now (bounded by the issued 120 s lifetime).
    let ttl: i64 = redis::cmd("TTL").arg(&key).query(&mut conn).unwrap();
    assert!(
        (1..=120).contains(&ttl),
        "TTL must be expires_at - now, got {ttl}"
    );

    let verifier = verifier_for(&url, &prefix);
    assert_eq!(
        verify_at(
            &verifier,
            &encode_token(&issued.record.nonce, counter),
            issued.record.issued_at_ns
        ),
        VerifyOutcome::Valid
    );
}

#[test]
fn two_concurrent_verifies_exactly_one_wins() {
    let Some(url) = redis_url() else { return };
    let prefix = prefix("race");
    let issued = issue_challenge(&sha_config(4), "login", IP, now_unix(), now_micros(), 0).unwrap();
    let counter = solve_for_test(&issued.record).expect("4-bit sha solves");
    let token = encode_token(&issued.record.nonce, counter);
    let issued_at_ns = issued.record.issued_at_ns;

    let verifier = Arc::new(verifier_for(&url, &prefix));
    verifier.store().store(&issued.record).unwrap();

    // Two threads race the same token; GETDEL means exactly one of them can
    // ever observe the record — the loser must fail before any derive.
    let barrier = Arc::new(Barrier::new(3));
    let mut handles = Vec::new();
    for _ in 0..2 {
        let verifier = Arc::clone(&verifier);
        let barrier = Arc::clone(&barrier);
        let token = token.clone();
        handles.push(thread::spawn(move || {
            barrier.wait();
            verifier.verify(&token, "login", IP, issued_at_ns + 1_000_000)
        }));
    }
    barrier.wait();

    let mut valid = 0;
    let mut not_found = 0;
    for handle in handles {
        match handle.join().unwrap() {
            VerifyOutcome::Valid => valid += 1,
            VerifyOutcome::Invalid(VerifyError::RecordNotFound) => not_found += 1,
            other => panic!("unexpected concurrent outcome: {other:?}"),
        }
    }
    assert_eq!(
        (valid, not_found),
        (1, 1),
        "exactly one concurrent verify may derive; the other must see the consumed record"
    );
}

#[test]
fn replay_after_valid_verify_is_record_not_found() {
    let Some(url) = redis_url() else { return };
    let prefix = prefix("replay");
    let issued = issue_challenge(&sha_config(4), "login", IP, now_unix(), now_micros(), 0).unwrap();
    let counter = solve_for_test(&issued.record).expect("4-bit sha solves");
    let token = encode_token(&issued.record.nonce, counter);
    let issued_at_ns = issued.record.issued_at_ns;

    let verifier = verifier_for(&url, &prefix);
    verifier.store().store(&issued.record).unwrap();

    assert_eq!(
        verify_at(&verifier, &token, issued_at_ns),
        VerifyOutcome::Valid
    );
    assert_eq!(
        verify_at(&verifier, &token, issued_at_ns),
        VerifyOutcome::Invalid(VerifyError::RecordNotFound),
        "a consumed token can never verify twice"
    );
}

#[test]
fn wrong_counter_is_insufficient_work_and_burns_the_record() {
    let Some(url) = redis_url() else { return };
    let prefix = prefix("wrong-counter");
    let issued = issue_challenge(&sha_config(4), "login", IP, now_unix(), now_micros(), 0).unwrap();
    let valid = solve_for_test(&issued.record).expect("4-bit sha solves");
    let wrong = if valid == 0 { 1 } else { 0 };
    let issued_at_ns = issued.record.issued_at_ns;

    let verifier = verifier_for(&url, &prefix);
    verifier.store().store(&issued.record).unwrap();

    // Wrong counter: the one-shot model consumes the record, so the attempt
    // bound is per-nonce (GETDEL), not a caller-managed counter.
    assert_eq!(
        verify_at(
            &verifier,
            &encode_token(&issued.record.nonce, wrong),
            issued_at_ns
        ),
        VerifyOutcome::Invalid(VerifyError::InsufficientWork)
    );
    assert_eq!(
        verify_at(
            &verifier,
            &encode_token(&issued.record.nonce, valid),
            issued_at_ns
        ),
        VerifyOutcome::Invalid(VerifyError::RecordNotFound),
        "a wrong counter must burn the challenge"
    );
}

#[test]
fn expired_record_returns_expired() {
    let Some(url) = redis_url() else { return };
    // Issue with a past wall-clock via the issuer's now_unix knob:
    // expires_at lands 1 s in the past, so the verifier's TTL check must
    // fire. Redis EX TTLs a past-expiry record at 1 s, so on the rare
    // occasion the GETDEL misses the window (RecordNotFound), retry with a
    // fresh challenge.
    for attempt in 0..3 {
        let prefix = prefix(&format!("expired-{attempt}"));
        let issued = issue_challenge(
            &sha_config(4),
            "login",
            IP,
            now_unix().saturating_sub(121),
            now_micros(),
            0,
        )
        .unwrap();
        let counter = solve_for_test(&issued.record).expect("4-bit sha solves");
        let token = encode_token(&issued.record.nonce, counter);

        let verifier = verifier_for(&url, &prefix);
        verifier.store().store(&issued.record).unwrap();
        match verifier.verify(&token, "login", IP, now_micros()) {
            VerifyOutcome::Invalid(VerifyError::Expired) => return,
            VerifyOutcome::Invalid(VerifyError::RecordNotFound) => continue,
            other => panic!("expired record gave unexpected outcome: {other:?}"),
        }
    }
    panic!("expired record never observed before its 1 s Redis TTL");
}

#[test]
fn tampered_record_signature_is_rejected() {
    let Some(url) = redis_url() else { return };
    let prefix = prefix("tamper");
    let issued = issue_challenge(&sha_config(4), "login", IP, now_unix(), now_micros(), 0).unwrap();
    let counter = solve_for_test(&issued.record).expect("4-bit sha solves");

    // Tamper the stored record: append to the embedded signature and keep
    // the prefix structurally consistent (challenge|salt|), so the record
    // passes structural validation and fails specifically at the HMAC
    // re-check — the same corruption a PHP RedisStorage would serve back.
    let mut record = issued.record;
    record.challenge.push_str("00");
    record.prefix = format!("{}|{}|", record.challenge, record.salt);

    let verifier = verifier_for(&url, &prefix);
    verifier.store().store(&record).unwrap();
    assert_eq!(
        verify_at(
            &verifier,
            &encode_token(&record.nonce, counter),
            record.issued_at_ns
        ),
        VerifyOutcome::Invalid(VerifyError::BadSignature)
    );
}

#[test]
fn gate_rejection_does_not_consume_the_record() {
    let Some(url) = redis_url() else { return };
    let prefix = prefix("gate-noconsume");
    let issued =
        issue_challenge(&argon_config(4), "login", IP, now_unix(), now_micros(), 0).unwrap();
    let counter = solve_for_test(&issued.record).expect("4-bit argon solves");
    let token = encode_token(&issued.record.nonce, counter);
    let issued_at_ns = issued.record.issued_at_ns;

    // Gate refuses capacity: CapacityExceeded, no derivation, NO consume.
    let rejecting = verifier_for(&url, &prefix).with_argon_gate(|_| false);
    rejecting.store().store(&issued.record).unwrap();
    assert_eq!(
        verify_at(&rejecting, &token, issued_at_ns),
        VerifyOutcome::Invalid(VerifyError::CapacityExceeded)
    );

    // The record survives the gate rejection: a second verify with an
    // accepting gate still derives and succeeds.
    let accepting = verifier_for(&url, &prefix).with_argon_gate(|_| true);
    assert_eq!(
        verify_at(&accepting, &token, issued_at_ns),
        VerifyOutcome::Valid,
        "a gate rejection must not burn the record"
    );
}

#[test]
fn cheap_validation_failure_does_not_consume_the_record() {
    let Some(url) = redis_url() else { return };
    let prefix = prefix("cheap-noconsume");
    let issued = issue_challenge(&sha_config(4), "login", IP, now_unix(), now_micros(), 0).unwrap();
    let counter = solve_for_test(&issued.record).expect("4-bit sha solves");
    let issued_at_ns = issued.record.issued_at_ns;

    // Corrupt the stored record's embedded signature while keeping the
    // structure consistent (prefix = challenge|salt|), so the cheap phase
    // fails specifically at the HMAC re-check — the same corruption a PHP
    // RedisStorage would serve back.
    let mut tampered = issued.record.clone();
    tampered.challenge.push_str("00");
    tampered.prefix = format!("{}|{}|", tampered.challenge, tampered.salt);

    let verifier = verifier_for(&url, &prefix);
    verifier.store().store(&tampered).unwrap();
    let token = encode_token(&tampered.nonce, counter);
    assert_eq!(
        verify_at(&verifier, &token, issued_at_ns),
        VerifyOutcome::Invalid(VerifyError::BadSignature)
    );

    // The record must survive the cheap rejection: the key is still present
    // and still fails the same way (never RecordNotFound).
    assert!(
        verifier.store().find(&tampered.nonce).unwrap().is_some(),
        "a cheap-validation failure must not consume the record"
    );
    assert_eq!(
        verify_at(&verifier, &token, issued_at_ns),
        VerifyOutcome::Invalid(VerifyError::BadSignature)
    );

    // And the pristine record under the same nonce still verifies.
    verifier.store().store(&issued.record).unwrap();
    assert_eq!(
        verify_at(
            &verifier,
            &encode_token(&issued.record.nonce, counter),
            issued_at_ns
        ),
        VerifyOutcome::Valid
    );
}

#[test]
fn argon_gate_rejects_before_derivation_and_accepts_when_clear() {
    let Some(url) = redis_url() else { return };
    let prefix = prefix("argon-gate");

    // Gate refuses capacity: CapacityExceeded, no hash derivation.
    let issued =
        issue_challenge(&argon_config(4), "login", IP, now_unix(), now_micros(), 0).unwrap();
    let counter = solve_for_test(&issued.record).expect("4-bit argon solves");
    let issued_at_ns = issued.record.issued_at_ns;
    let rejecting = verifier_for(&url, &prefix).with_argon_gate(|_| false);
    rejecting.store().store(&issued.record).unwrap();
    assert_eq!(
        verify_at(
            &rejecting,
            &encode_token(&issued.record.nonce, counter),
            issued_at_ns
        ),
        VerifyOutcome::Invalid(VerifyError::CapacityExceeded)
    );

    // Gate grants capacity: the record derives once and verifies.
    let issued =
        issue_challenge(&argon_config(4), "login", IP, now_unix(), now_micros(), 0).unwrap();
    let counter = solve_for_test(&issued.record).expect("4-bit argon solves");
    let issued_at_ns = issued.record.issued_at_ns;
    let accepting = verifier_for(&url, &prefix).with_argon_gate(|_| true);
    accepting.store().store(&issued.record).unwrap();
    assert_eq!(
        verify_at(
            &accepting,
            &encode_token(&issued.record.nonce, counter),
            issued_at_ns
        ),
        VerifyOutcome::Valid
    );
}

#[test]
fn record_json_keys_match_php_cross_language_format() {
    // The 17 keys PHP ChallengeRecord::toArray() emits for v2 records — the
    // exact key set a PHP RedisStorage writes and fromArray() reads. No
    // Redis needed: pure language-neutral schema parity.
    const PHP_KEYS: [&str; 17] = [
        "nonce",
        "scope",
        "binding_tag",
        "issued_at",
        "expires_at",
        "algorithm",
        "m_kib",
        "t",
        "p",
        "target_bits",
        "salt",
        "prefix",
        "challenge",
        "min_duration_ms",
        "issued_at_ns",
        "attempts_used",
        "protocol_version",
    ];

    let issued = issue_challenge(&sha_config(4), "login", IP, now_unix(), now_micros(), 0).unwrap();
    let value = serde_json::to_value(&issued.record).unwrap();
    let keys: BTreeSet<&str> = value
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    let expected: BTreeSet<&str> = PHP_KEYS.iter().copied().collect();
    assert_eq!(
        keys, expected,
        "Rust-serialized record must carry exactly the PHP toArray() keys"
    );
    assert_eq!(value["algorithm"], "sha256");

    // Reverse direction: a PHP-toArray()-shaped object (same keys, including
    // attempts_used and protocol_version) must deserialize into the Rust
    // record — the shape RedisChallengeStore::consume parses.
    let php_written = serde_json::json!({
        "nonce": issued.record.nonce,
        "scope": issued.record.scope,
        "binding_tag": issued.record.binding_tag,
        "issued_at": issued.record.issued_at,
        "expires_at": issued.record.expires_at,
        "algorithm": "sha256",
        "m_kib": issued.record.m_kib,
        "t": issued.record.t,
        "p": issued.record.p,
        "target_bits": issued.record.target_bits,
        "salt": issued.record.salt,
        "prefix": issued.record.prefix,
        "challenge": issued.record.challenge,
        "min_duration_ms": issued.record.min_duration_ms,
        "issued_at_ns": issued.record.issued_at_ns,
        "attempts_used": 0,
        "protocol_version": 2,
    });
    let decoded: ChallengeRecord = serde_json::from_value(php_written).unwrap();
    assert_eq!(decoded.nonce, issued.record.nonce);
    assert_eq!(decoded.binding_tag, issued.record.binding_tag);
    assert_eq!(decoded.algorithm, PoWAlgorithm::Sha256);
    assert_eq!(decoded.protocol_version, 2);
    assert_eq!(decoded.expires_at, issued.record.expires_at);
}
