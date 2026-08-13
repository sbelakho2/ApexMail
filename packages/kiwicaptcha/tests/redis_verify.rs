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
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

use kiwicaptcha::challenge::{
    issue_challenge, BindingMode, ChallengeConfig, ChallengeRecord, PoWAlgorithm,
};
use kiwicaptcha::redis_verify::{
    AdmissionError, ArgonAdmissionGate, ArgonLease, ProductionVerifier, RedisChallengeStore,
    DEFAULT_POOL_SIZE,
};
use kiwicaptcha::token::SolutionToken;
use kiwicaptcha::verify::{solve_for_test, VerifyError, VerifyOutcome};

/// Gate that flatly grants (`true`) or refuses (`false`) capacity — the
/// trait-based replacement for the old closure gates.
#[derive(Clone, Copy)]
struct BoolGate(bool);

struct UnitLease;

impl ArgonLease for UnitLease {}

impl ArgonAdmissionGate for BoolGate {
    fn acquire(
        &self,
        _record: &ChallengeRecord,
    ) -> Result<Option<Box<dyn ArgonLease>>, AdmissionError> {
        if self.0 {
            Ok(Some(Box::new(UnitLease)))
        } else {
            Ok(None)
        }
    }
}

/// Gate + RAII lease pair that counts acquires, in-flight leases, and
/// releases — proves one acquire corresponds to exactly one Drop.
struct CountingGate {
    active: Arc<AtomicUsize>,
    acquired: Arc<AtomicUsize>,
    released: Arc<AtomicUsize>,
    accept: bool,
}

struct CountingLease {
    active: Arc<AtomicUsize>,
    released: Arc<AtomicUsize>,
}

impl ArgonLease for CountingLease {}

impl Drop for CountingLease {
    fn drop(&mut self) {
        self.active.fetch_sub(1, Ordering::SeqCst);
        self.released.fetch_add(1, Ordering::SeqCst);
    }
}

impl ArgonAdmissionGate for CountingGate {
    fn acquire(
        &self,
        _record: &ChallengeRecord,
    ) -> Result<Option<Box<dyn ArgonLease>>, AdmissionError> {
        if !self.accept {
            return Ok(None);
        }
        self.acquired.fetch_add(1, Ordering::SeqCst);
        self.active.fetch_add(1, Ordering::SeqCst);
        Ok(Some(Box::new(CountingLease {
            active: Arc::clone(&self.active),
            released: Arc::clone(&self.released),
        })))
    }
}

/// Gate whose capacity backend is unavailable.
struct UnavailableGate;

impl ArgonAdmissionGate for UnavailableGate {
    fn acquire(
        &self,
        _record: &ChallengeRecord,
    ) -> Result<Option<Box<dyn ArgonLease>>, AdmissionError> {
        Err(AdmissionError::Unavailable)
    }
}

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

/// Minimal RESP2 command parser for the fake-Redis test server: returns the
/// command's argument strings and the number of bytes consumed, or `None`
/// while the buffer holds only a partial command.
fn parse_resp_command(buf: &[u8]) -> Option<(Vec<String>, usize)> {
    fn split_crlf(buf: &[u8]) -> Option<(&[u8], &[u8])> {
        let i = buf.windows(2).position(|w| w == b"\r\n")?;
        Some((&buf[..i], &buf[i + 2..]))
    }
    let rest = buf.strip_prefix(b"*")?;
    let (nline, mut rest) = split_crlf(rest)?;
    let count: usize = std::str::from_utf8(nline).ok()?.parse().ok()?;
    let mut args = Vec::with_capacity(count);
    for _ in 0..count {
        let rest2 = rest.strip_prefix(b"$")?;
        let (llen, rest3) = split_crlf(rest2)?;
        let len: usize = std::str::from_utf8(llen).ok()?.parse().ok()?;
        if rest3.len() < len + 2 {
            return None;
        }
        args.push(String::from_utf8_lossy(&rest3[..len]).into_owned());
        rest = &rest3[len + 2..];
    }
    let consumed = buf.len() - rest.len();
    Some((args, consumed))
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
    let rejecting = verifier_for(&url, &prefix).with_argon_gate(BoolGate(false));
    rejecting.store().store(&issued.record).unwrap();
    assert_eq!(
        verify_at(&rejecting, &token, issued_at_ns),
        VerifyOutcome::Invalid(VerifyError::CapacityExceeded)
    );

    // The record survives the gate rejection: a second verify with an
    // accepting gate still derives and succeeds.
    let accepting = verifier_for(&url, &prefix).with_argon_gate(BoolGate(true));
    assert_eq!(
        verify_at(&accepting, &token, issued_at_ns),
        VerifyOutcome::Valid,
        "a gate rejection must not burn the record"
    );
}

#[test]
fn cheap_validation_failure_consumes_the_record() {
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

    // Round-7 cross-language table: terminal cheap failures CONSUME the
    // record (best-effort DEL), matching the PHP core — a retry with the
    // correct token now sees RecordNotFound.
    let good_token = encode_token(&issued.record.nonce, counter);
    assert_eq!(
        verify_at(&verifier, &good_token, issued_at_ns),
        VerifyOutcome::Invalid(VerifyError::RecordNotFound),
        "the tampered record must have been consumed by the cheap failure"
    );

    assert_eq!(
        verify_at(&verifier, &token, issued_at_ns),
        VerifyOutcome::Invalid(VerifyError::RecordNotFound),
        "the consumed record stays consumed"
    );

    // And a pristine record under the same nonce still verifies.
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
    let rejecting = verifier_for(&url, &prefix).with_argon_gate(BoolGate(false));
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
    let accepting = verifier_for(&url, &prefix).with_argon_gate(BoolGate(true));
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
fn argon_lease_is_held_during_verify_and_released_by_drop() {
    let Some(url) = redis_url() else { return };
    let prefix = prefix("lease-hold");
    let issued =
        issue_challenge(&argon_config(4), "login", IP, now_unix(), now_micros(), 0).unwrap();
    let counter = solve_for_test(&issued.record).expect("4-bit argon solves");
    let token = encode_token(&issued.record.nonce, counter);
    let issued_at_ns = issued.record.issued_at_ns;

    let active = Arc::new(AtomicUsize::new(0));
    let acquired = Arc::new(AtomicUsize::new(0));
    let released = Arc::new(AtomicUsize::new(0));
    let gate = CountingGate {
        active: Arc::clone(&active),
        acquired: Arc::clone(&acquired),
        released: Arc::clone(&released),
        accept: true,
    };
    let verifier = Arc::new(verifier_for(&url, &prefix).with_argon_gate(gate));
    verifier.store().store(&issued.record).unwrap();

    // Verify on a worker thread so the main thread can OBSERVE the lease in
    // flight: it must be held (count == 1) across the atomic GETDEL and the
    // Argon2id derivation, i.e. DURING the verify call.
    let worker = Arc::clone(&verifier);
    let worker_token = token.clone();
    let handle =
        thread::spawn(move || worker.verify(&worker_token, "login", IP, issued_at_ns + 1_000_000));

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
    let mut seen_in_flight = false;
    while std::time::Instant::now() < deadline {
        if active.load(Ordering::SeqCst) == 1 {
            seen_in_flight = true;
            break;
        }
        thread::sleep(std::time::Duration::from_micros(100));
    }
    assert!(
        seen_in_flight,
        "the lease (count 1) must be held while verify() runs"
    );
    assert_eq!(
        handle.join().unwrap(),
        VerifyOutcome::Valid,
        "a granted lease must let the verification succeed"
    );
    assert_eq!(acquired.load(Ordering::SeqCst), 1, "exactly one acquire");
    assert_eq!(
        active.load(Ordering::SeqCst),
        0,
        "after verify returns, Drop must have released the lease"
    );
    assert_eq!(released.load(Ordering::SeqCst), 1, "exactly one release");
}

#[test]
fn gate_ok_none_is_capacity_exceeded_and_does_not_consume() {
    let Some(url) = redis_url() else { return };
    let prefix = prefix("gate-ok-none");
    let issued =
        issue_challenge(&argon_config(4), "login", IP, now_unix(), now_micros(), 0).unwrap();
    let counter = solve_for_test(&issued.record).expect("4-bit argon solves");
    let token = encode_token(&issued.record.nonce, counter);
    let issued_at_ns = issued.record.issued_at_ns;

    // acquire -> Ok(None): CapacityExceeded, no lease handed out, NO consume.
    let active = Arc::new(AtomicUsize::new(0));
    let acquired = Arc::new(AtomicUsize::new(0));
    let released = Arc::new(AtomicUsize::new(0));
    let rejecting = verifier_for(&url, &prefix).with_argon_gate(CountingGate {
        active: Arc::clone(&active),
        acquired: Arc::clone(&acquired),
        released: Arc::clone(&released),
        accept: false,
    });
    rejecting.store().store(&issued.record).unwrap();
    assert_eq!(
        verify_at(&rejecting, &token, issued_at_ns),
        VerifyOutcome::Invalid(VerifyError::CapacityExceeded)
    );
    assert_eq!(
        acquired.load(Ordering::SeqCst),
        0,
        "Ok(None) must not acquire"
    );
    assert_eq!(active.load(Ordering::SeqCst), 0, "no lease must be held");
    assert_eq!(released.load(Ordering::SeqCst), 0, "nothing to release");

    // The record survives: a second verify with a granting gate succeeds.
    let accepting = verifier_for(&url, &prefix).with_argon_gate(BoolGate(true));
    assert_eq!(
        verify_at(&accepting, &token, issued_at_ns),
        VerifyOutcome::Valid,
        "an Ok(None) rejection must not burn the record"
    );
}

#[test]
fn gate_error_is_admission_unavailable_and_does_not_consume() {
    let Some(url) = redis_url() else { return };
    let prefix = prefix("gate-unavailable");
    let issued =
        issue_challenge(&argon_config(4), "login", IP, now_unix(), now_micros(), 0).unwrap();
    let counter = solve_for_test(&issued.record).expect("4-bit argon solves");
    let token = encode_token(&issued.record.nonce, counter);
    let issued_at_ns = issued.record.issued_at_ns;

    // acquire -> Err(AdmissionError::Unavailable): AdmissionUnavailable, no
    // consume — the client can retry once the gate backend recovers.
    let rejecting = verifier_for(&url, &prefix).with_argon_gate(UnavailableGate);
    rejecting.store().store(&issued.record).unwrap();
    assert_eq!(
        verify_at(&rejecting, &token, issued_at_ns),
        VerifyOutcome::Invalid(VerifyError::AdmissionUnavailable)
    );

    // The record survives: a second verify with a healthy gate succeeds.
    let accepting = verifier_for(&url, &prefix).with_argon_gate(BoolGate(true));
    assert_eq!(
        verify_at(&accepting, &token, issued_at_ns),
        VerifyOutcome::Valid,
        "an AdmissionUnavailable rejection must not burn the record"
    );
}

#[test]
fn sha256_records_are_never_gated() {
    let Some(url) = redis_url() else { return };
    let prefix = prefix("sha-ungated");
    let issued = issue_challenge(&sha_config(4), "login", IP, now_unix(), now_micros(), 0).unwrap();
    let counter = solve_for_test(&issued.record).expect("4-bit sha solves");
    let token = encode_token(&issued.record.nonce, counter);
    let issued_at_ns = issued.record.issued_at_ns;

    // A gate that always errors: SHA-256 records are cheap and must never
    // consult it (matching the PHP verifier), so the verify still succeeds.
    let verifier = verifier_for(&url, &prefix).with_argon_gate(UnavailableGate);
    verifier.store().store(&issued.record).unwrap();
    assert_eq!(
        verify_at(&verifier, &token, issued_at_ns),
        VerifyOutcome::Valid,
        "SHA-256 records must skip the Argon admission gate"
    );
}

#[test]
fn connection_pool_reuses_connections_round_robin() {
    let Some(url) = redis_url() else { return };
    let prefix = prefix("pool");
    let issued = issue_challenge(&sha_config(4), "login", IP, now_unix(), now_micros(), 0).unwrap();
    let counter = solve_for_test(&issued.record).expect("4-bit sha solves");
    let token = encode_token(&issued.record.nonce, counter);
    let issued_at_ns = issued.record.issued_at_ns;

    // Default pool size is DEFAULT_POOL_SIZE; with_pool_size overrides it.
    assert_eq!(store_for(&url, &prefix).pool_size(), DEFAULT_POOL_SIZE);
    assert_eq!(
        RedisChallengeStore::with_pool_size(
            redis::Client::open(url.clone()).unwrap(),
            prefix.clone(),
            2
        )
        .pool_size(),
        2
    );

    // Many operations over a tiny pool: every slot is lazily opened, reused
    // round-robin, and the one-shot semantics are unaffected.
    let verifier = ProductionVerifier::new(
        RedisChallengeStore::with_pool_size(
            redis::Client::open(url.clone()).unwrap(),
            prefix.clone(),
            2,
        ),
        SECRET,
    );
    for _ in 0..8 {
        verifier.store().store(&issued.record).unwrap();
        assert_eq!(
            verify_at(&verifier, &token, issued_at_ns),
            VerifyOutcome::Valid
        );
        verifier.store().consume(&issued.record.nonce).unwrap();
    }
}

#[test]
fn pool_reuses_the_same_slots_across_operations() {
    let Some(url) = redis_url() else { return };
    let prefix = prefix("pool-reuse");
    let issued = issue_challenge(&sha_config(4), "login", IP, now_unix(), now_micros(), 0).unwrap();
    let counter = solve_for_test(&issued.record).expect("4-bit sha solves");
    let issued_at_ns = issued.record.issued_at_ns;

    let store = RedisChallengeStore::with_pool_size(
        redis::Client::open(url.clone()).unwrap(),
        prefix.clone(),
        2,
    );
    // 48 operations over a 2-slot pool: the SAME two slots must serve every
    // operation (lazy open on first use, reuse afterwards) — a pool that
    // recreated connections per operation would show more than 2 total
    // connections.
    for _ in 0..16 {
        store.store(&issued.record).unwrap();
        let peeked = store
            .find(&issued.record.nonce)
            .unwrap()
            .expect("stored record peeks");
        assert_eq!(peeked.challenge, issued.record.challenge);
        let consumed = store
            .consume(&issued.record.nonce)
            .unwrap()
            .expect("stored record consumes");
        assert_eq!(consumed.challenge, issued.record.challenge);
    }
    let (conns, idle) = store.debug_pool_state();
    assert_eq!(
        conns, 2,
        "48 operations must never open more than the configured 2 connections"
    );
    assert_eq!(
        idle, 2,
        "both slots must be returned to the pool between operations"
    );

    // One-shot semantics still hold end-to-end on the reused slots.
    store.store(&issued.record).unwrap();
    let verifier = ProductionVerifier::new(store, SECRET);
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
fn unreachable_store_maps_find_error_to_storage_unavailable() {
    // Bind a listener and drop it so the port is guaranteed closed: pool
    // connects fail fast with ECONNREFUSED and the checkout returns after
    // the bounded POOL_CHECKOUT_TIMEOUT. No RISK_REDIS_URL needed — this
    // test is hermetic.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);

    let issued = issue_challenge(&sha_config(4), "login", IP, now_unix(), now_micros(), 0).unwrap();
    let verifier = verifier_for(&format!("redis://127.0.0.1:{port}/"), &prefix("dead"));
    assert_eq!(
        verifier.verify(
            &encode_token(&issued.record.nonce, 0),
            "login",
            IP,
            now_micros()
        ),
        VerifyOutcome::Invalid(VerifyError::StorageUnavailable),
        "a find()/checkout failure must map to StorageUnavailable (the challenge is presumed intact), never RecordNotFound"
    );
}

#[test]
fn hung_getdel_maps_consume_error_to_consume_indeterminate() {
    let issued = issue_challenge(&sha_config(4), "login", IP, now_unix(), now_micros(), 0).unwrap();
    let counter = solve_for_test(&issued.record).expect("4-bit sha solves");
    let record_json = serde_json::to_string(&issued.record).unwrap();
    let nonce = issued.record.nonce.clone();
    let issued_at_ns = issued.record.issued_at_ns;

    // A miniature RESP2 server: answers the PEEK (GET) with the stored
    // record's JSON so the verifier's cheap phase succeeds, and then NEVER
    // replies to GETDEL — the client's read timeout fires and consume()
    // must map to ConsumeIndeterminate. Hermetic: no RISK_REDIS_URL needed.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        use std::io::{Read, Write};
        let (mut stream, _) = listener.accept().expect("store connects");
        let mut buf = Vec::new();
        let mut tmp = [0u8; 4096];
        loop {
            match stream.read(&mut tmp) {
                Ok(0) => return,
                Ok(n) => {
                    buf.extend_from_slice(&tmp[..n]);
                    while let Some((args, consumed)) = parse_resp_command(&buf) {
                        buf.drain(..consumed);
                        match args[0].as_str() {
                            // Hold the connection open WITHOUT a reply: the
                            // client hits its 1 s read timeout.
                            "GETDEL" => loop {
                                std::thread::sleep(std::time::Duration::from_secs(1));
                            },
                            "GET" => {
                                let reply =
                                    format!("${}\r\n{}\r\n", record_json.len(), record_json);
                                stream.write_all(reply.as_bytes()).unwrap();
                            }
                            _ => {
                                stream.write_all(b"+OK\r\n").unwrap();
                            }
                        }
                    }
                }
                Err(_) => return,
            }
        }
    });

    let verifier = verifier_for(&format!("redis://127.0.0.1:{port}/"), &prefix("hung"));
    assert_eq!(
        verify_at(&verifier, &encode_token(&nonce, counter), issued_at_ns),
        VerifyOutcome::Invalid(VerifyError::ConsumeIndeterminate),
        "an uncertain GETDEL failure must map to ConsumeIndeterminate, never RecordNotFound"
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
