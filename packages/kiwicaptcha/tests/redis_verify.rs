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
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

use kiwicaptcha::challenge::{
    issue_challenge, BindingMode, ChallengeConfig, ChallengeRecord, PoWAlgorithm,
};
use kiwicaptcha::redis_verify::{
    AdmissionError, ArgonAdmissionGate, ArgonLease, ProductionVerifier, RedisChallengeStore,
    StoredConsumedResult, DEFAULT_POOL_SIZE,
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

/// Deterministic verifier clock for the future-issued-skew test: the fixed
/// issue-time second (audit #76) — the 61 s future-issued challenge is then
/// ALWAYS beyond the 60 s skew bound, with no wall-clock race.
static FAKE_FUTURE_NOW: AtomicU64 = AtomicU64::new(0);

fn fake_future_now() -> u64 {
    FAKE_FUTURE_NOW.load(Ordering::SeqCst)
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
        kid: 1,
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

fn argon_config(target_bits: u32) -> ChallengeConfig {
    ChallengeConfig {
        secret_key: SECRET.into(),
        kid: 1,
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
        region: None,
        issuer: None,
        policy_version: 1,
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
    let issued = issue_challenge(
        &sha_config(4),
        "login",
        IP,
        now_unix(),
        now_micros(),
        0,
        None,
    )
    .unwrap();
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
    assert!(matches!(
        verify_at(
            &verifier,
            &encode_token(&issued.record.nonce, counter),
            issued.record.issued_at_ns
        ),
        VerifyOutcome::Valid { .. }
    ));
}

#[test]
fn two_concurrent_verifies_exactly_one_derives() {
    // Audit #74: the consumed-state transition keeps the record, so the
    // concurrent loser now returns the WINNER'S STORED OUTCOME — the SAME
    // Valid — or ConsumeIndeterminate when it races between the transition
    // and the outcome commit. NOT RecordNotFound. Exactly one derive
    // happens: commit_result stores exactly once, so the single stored
    // `consumed_result` (valid=true) pins the derive count; the counting
    // gate proves both racers passed through the Argon gate (the gate runs
    // BEFORE the transition, so both acquire; only the winner derives).
    let Some(url) = redis_url() else { return };
    let prefix = prefix("race");
    let issued = issue_challenge(
        &argon_config(4),
        "login",
        IP,
        now_unix(),
        now_micros(),
        0,
        None,
    )
    .unwrap();
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

    // Two threads race the same token; the transition means exactly one of
    // them wins it — the loser must return the stored outcome without any
    // derivation.
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
    let mut indeterminate = 0;
    for handle in handles {
        match handle.join().unwrap() {
            VerifyOutcome::Valid { .. } => valid += 1,
            VerifyOutcome::Invalid(VerifyError::ConsumeIndeterminate) => indeterminate += 1,
            other => panic!("unexpected concurrent outcome: {other:?}"),
        }
    }
    assert_eq!(
        valid + indeterminate,
        2,
        "one winner (Valid) + one loser (stored Valid or ConsumeIndeterminate)"
    );
    assert!(valid >= 1, "the transition winner must return Valid");
    assert!(
        indeterminate <= 1,
        "only the loser may see ConsumeIndeterminate (racing before the commit)"
    );

    // Exactly one derive + commit: the stored record carries ONE committed
    // outcome (valid=true) — a second derive would have committed a second
    // outcome, which commit_result refuses.
    let key = format!("{prefix}{}", issued.record.nonce);
    let mut conn = redis::Client::open(url.clone())
        .unwrap()
        .get_connection()
        .unwrap();
    let raw: String = redis::cmd("GET").arg(&key).query(&mut conn).unwrap();
    let stored: serde_json::Value = serde_json::from_str(&raw).unwrap();
    assert_eq!(stored["state"], "consumed");
    assert_eq!(stored["consumed_result"]["valid"], true);

    // Both racers consult the Argon gate (it runs before the transition);
    // every lease is released.
    assert_eq!(
        acquired.load(Ordering::SeqCst),
        2,
        "both racers acquire a gate lease"
    );
    assert_eq!(active.load(Ordering::SeqCst), 0, "no lease left in flight");
    assert_eq!(released.load(Ordering::SeqCst), 2, "every lease released");
}

#[test]
fn replay_after_valid_verify_returns_the_stored_outcome() {
    let Some(url) = redis_url() else { return };
    let prefix = prefix("replay");
    let issued = issue_challenge(
        &sha_config(4),
        "login",
        IP,
        now_unix(),
        now_micros(),
        0,
        None,
    )
    .unwrap();
    let counter = solve_for_test(&issued.record).expect("4-bit sha solves");
    let token = encode_token(&issued.record.nonce, counter);
    let issued_at_ns = issued.record.issued_at_ns;

    let verifier = verifier_for(&url, &prefix);
    verifier.store().store(&issued.record).unwrap();

    assert!(matches!(
        verify_at(&verifier, &token, issued_at_ns),
        VerifyOutcome::Valid { .. }
    ));
    // Audit #74: the consumed record is KEPT with the committed outcome —
    // a replay returns the SAME Valid (from the stored result), never
    // RecordNotFound and never a re-derivation.
    assert!(
        matches!(
            verify_at(&verifier, &token, issued_at_ns),
            VerifyOutcome::Valid { .. }
        ),
        "a replayed token returns the stored outcome of the first verification"
    );
}

#[test]
fn wrong_counter_is_insufficient_work_and_burns_the_record() {
    let Some(url) = redis_url() else { return };
    let prefix = prefix("wrong-counter");
    let issued = issue_challenge(
        &sha_config(4),
        "login",
        IP,
        now_unix(),
        now_micros(),
        0,
        None,
    )
    .unwrap();
    let valid = solve_for_test(&issued.record).expect("4-bit sha solves");
    let wrong = if valid == 0 { 1 } else { 0 };
    let issued_at_ns = issued.record.issued_at_ns;

    let verifier = verifier_for(&url, &prefix);
    verifier.store().store(&issued.record).unwrap();

    // Wrong counter: the one-shot model consumes the record via the
    // transition and commits valid=false, so the attempt bound is per-nonce
    // (the transition), not a caller-managed counter.
    assert_eq!(
        verify_at(
            &verifier,
            &encode_token(&issued.record.nonce, wrong),
            issued_at_ns
        ),
        VerifyOutcome::Invalid(VerifyError::InsufficientWork)
    );
    // Audit #74: the retry with the correct counter sees the stored
    // valid=false outcome — the SAME InsufficientWork, not RecordNotFound.
    assert_eq!(
        verify_at(
            &verifier,
            &encode_token(&issued.record.nonce, valid),
            issued_at_ns
        ),
        VerifyOutcome::Invalid(VerifyError::InsufficientWork),
        "a wrong counter commits valid=false; the replay returns the stored outcome"
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
            None,
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
    let issued = issue_challenge(
        &sha_config(4),
        "login",
        IP,
        now_unix(),
        now_micros(),
        0,
        None,
    )
    .unwrap();
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
    let issued = issue_challenge(
        &argon_config(4),
        "login",
        IP,
        now_unix(),
        now_micros(),
        0,
        None,
    )
    .unwrap();
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
    assert!(
        matches!(
            verify_at(&accepting, &token, issued_at_ns),
            VerifyOutcome::Valid { .. }
        ),
        "a gate rejection must not burn the record"
    );
}

#[test]
fn cheap_validation_failure_consumes_the_record() {
    let Some(url) = redis_url() else { return };
    let prefix = prefix("cheap-noconsume");
    let issued = issue_challenge(
        &sha_config(4),
        "login",
        IP,
        now_unix(),
        now_micros(),
        0,
        None,
    )
    .unwrap();
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
    assert!(matches!(
        verify_at(
            &verifier,
            &encode_token(&issued.record.nonce, counter),
            issued_at_ns
        ),
        VerifyOutcome::Valid { .. }
    ));
}

#[test]
fn argon_gate_rejects_before_derivation_and_accepts_when_clear() {
    let Some(url) = redis_url() else { return };
    let prefix = prefix("argon-gate");

    // Gate refuses capacity: CapacityExceeded, no hash derivation.
    let issued = issue_challenge(
        &argon_config(4),
        "login",
        IP,
        now_unix(),
        now_micros(),
        0,
        None,
    )
    .unwrap();
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
    let issued = issue_challenge(
        &argon_config(4),
        "login",
        IP,
        now_unix(),
        now_micros(),
        0,
        None,
    )
    .unwrap();
    let counter = solve_for_test(&issued.record).expect("4-bit argon solves");
    let issued_at_ns = issued.record.issued_at_ns;
    let accepting = verifier_for(&url, &prefix).with_argon_gate(BoolGate(true));
    accepting.store().store(&issued.record).unwrap();
    assert!(matches!(
        verify_at(
            &accepting,
            &encode_token(&issued.record.nonce, counter),
            issued_at_ns
        ),
        VerifyOutcome::Valid { .. }
    ));
}

#[test]
fn argon_lease_is_held_during_verify_and_released_by_drop() {
    let Some(url) = redis_url() else { return };
    let prefix = prefix("lease-hold");
    let issued = issue_challenge(
        &argon_config(4),
        "login",
        IP,
        now_unix(),
        now_micros(),
        0,
        None,
    )
    .unwrap();
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
    assert!(
        matches!(handle.join().unwrap(), VerifyOutcome::Valid { .. }),
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
    let issued = issue_challenge(
        &argon_config(4),
        "login",
        IP,
        now_unix(),
        now_micros(),
        0,
        None,
    )
    .unwrap();
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
    assert!(
        matches!(
            verify_at(&accepting, &token, issued_at_ns),
            VerifyOutcome::Valid { .. }
        ),
        "an Ok(None) rejection must not burn the record"
    );
}

#[test]
fn gate_error_is_admission_unavailable_and_does_not_consume() {
    let Some(url) = redis_url() else { return };
    let prefix = prefix("gate-unavailable");
    let issued = issue_challenge(
        &argon_config(4),
        "login",
        IP,
        now_unix(),
        now_micros(),
        0,
        None,
    )
    .unwrap();
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
    assert!(
        matches!(
            verify_at(&accepting, &token, issued_at_ns),
            VerifyOutcome::Valid { .. }
        ),
        "an AdmissionUnavailable rejection must not burn the record"
    );
}

#[test]
fn sha256_records_are_never_gated() {
    let Some(url) = redis_url() else { return };
    let prefix = prefix("sha-ungated");
    let issued = issue_challenge(
        &sha_config(4),
        "login",
        IP,
        now_unix(),
        now_micros(),
        0,
        None,
    )
    .unwrap();
    let counter = solve_for_test(&issued.record).expect("4-bit sha solves");
    let token = encode_token(&issued.record.nonce, counter);
    let issued_at_ns = issued.record.issued_at_ns;

    // A gate that always errors: SHA-256 records are cheap and must never
    // consult it (matching the PHP verifier), so the verify still succeeds.
    let verifier = verifier_for(&url, &prefix).with_argon_gate(UnavailableGate);
    verifier.store().store(&issued.record).unwrap();
    assert!(
        matches!(
            verify_at(&verifier, &token, issued_at_ns),
            VerifyOutcome::Valid { .. }
        ),
        "SHA-256 records must skip the Argon admission gate"
    );
}

#[test]
fn connection_pool_reuses_connections_round_robin() {
    let Some(url) = redis_url() else { return };
    let prefix = prefix("pool");
    let issued = issue_challenge(
        &sha_config(4),
        "login",
        IP,
        now_unix(),
        now_micros(),
        0,
        None,
    )
    .unwrap();
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
        assert!(matches!(
            verify_at(&verifier, &token, issued_at_ns),
            VerifyOutcome::Valid { .. }
        ));
        let _ = verifier.store().consume(&issued.record.nonce).unwrap();
    }
}

#[test]
fn pool_reuses_the_same_slots_across_operations() {
    let Some(url) = redis_url() else { return };
    let prefix = prefix("pool-reuse");
    let issued = issue_challenge(
        &sha_config(4),
        "login",
        IP,
        now_unix(),
        now_micros(),
        0,
        None,
    )
    .unwrap();
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
        assert_eq!(consumed.record.challenge, issued.record.challenge);
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
    assert!(matches!(
        verify_at(
            &verifier,
            &encode_token(&issued.record.nonce, counter),
            issued_at_ns
        ),
        VerifyOutcome::Valid { .. }
    ));
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

    let issued = issue_challenge(
        &sha_config(4),
        "login",
        IP,
        now_unix(),
        now_micros(),
        0,
        None,
    )
    .unwrap();
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
    let issued = issue_challenge(
        &sha_config(4),
        "login",
        IP,
        now_unix(),
        now_micros(),
        0,
        None,
    )
    .unwrap();
    let counter = solve_for_test(&issued.record).expect("4-bit sha solves");
    let record_json = serde_json::to_string(&issued.record).unwrap();
    let nonce = issued.record.nonce.clone();
    let issued_at_ns = issued.record.issued_at_ns;

    // A miniature RESP2 server: answers the PEEK (GET) with the stored
    // record's JSON so the verifier's cheap phase succeeds, and then NEVER
    // replies to the consume transition (EVAL) — the client's read timeout
    // fires and consume() must map to ConsumeIndeterminate. Hermetic: no
    // RISK_REDIS_URL needed.
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
                            // client hits its 1 s read timeout. (The redis
                            // crate invokes scripts via EVALSHA.)
                            "EVAL" | "EVALSHA" => loop {
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
    // The 22 keys PHP ChallengeRecord::toArray() emits for v2 records — the
    // exact key set a PHP RedisStorage writes and fromArray() reads. The
    // `region` and `issuer` keys (audits #22/#67) are ALWAYS present: null
    // when unbound, exactly like PHP; `kid` (audit #91) is ALWAYS present
    // (default 1). No Redis needed: pure language-neutral schema parity.
    const PHP_KEYS: [&str; 22] = [
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
        "region",
        "policy_version",
        "request_binding",
        "issuer",
        "kid",
    ];

    let issued = issue_challenge(
        &sha_config(4),
        "login",
        IP,
        now_unix(),
        now_micros(),
        0,
        None,
    )
    .unwrap();
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
    assert_eq!(
        value["region"],
        serde_json::Value::Null,
        "the region key must be present (null when unbound) in the Rust wire format"
    );
    assert_eq!(
        value["issuer"],
        serde_json::Value::Null,
        "the issuer key must be present (null when unbound) in the Rust wire format (audit #67)"
    );
    assert_eq!(
        value["kid"], 1,
        "the kid key must be present with the default 1 in the Rust wire format (audit #91)"
    );

    // Reverse direction: a PHP toArray()-shaped object (same keys, including
    // attempts_used, protocol_version, region, issuer and kid) must
    // deserialize into the Rust record — the shape RedisChallengeStore::
    // consume parses.
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
        "region": null,
        "issuer": null,
        "kid": 1,
    });
    let decoded: ChallengeRecord = serde_json::from_value(php_written.clone()).unwrap();
    assert_eq!(decoded.nonce, issued.record.nonce);
    assert_eq!(decoded.binding_tag, issued.record.binding_tag);
    assert_eq!(decoded.algorithm, PoWAlgorithm::Sha256);
    assert_eq!(decoded.protocol_version, 2);
    assert_eq!(decoded.expires_at, issued.record.expires_at);
    assert_eq!(decoded.region, None);
    assert_eq!(decoded.issuer, None);
    assert_eq!(decoded.kid, 1);
    // A PHP record WITHOUT the kid key still deserializes (serde default 1).
    let mut no_kid_written = php_written.clone();
    no_kid_written.as_object_mut().unwrap().remove("kid");
    let decoded: ChallengeRecord = serde_json::from_value(no_kid_written).unwrap();
    assert_eq!(decoded.kid, 1, "missing kid must default to 1 (audit #91)");
    // A region-bound PHP record round-trips the region.
    let mut region_written = php_written.clone();
    region_written["region"] = serde_json::json!("eu");
    let decoded: ChallengeRecord = serde_json::from_value(region_written).unwrap();
    assert_eq!(decoded.region.as_deref(), Some("eu"));
    // An issuer-bound PHP record round-trips the issuer (audit #67).
    let mut issuer_written = php_written.clone();
    issuer_written["issuer"] = serde_json::json!("auth-gw");
    let decoded: ChallengeRecord = serde_json::from_value(issuer_written).unwrap();
    assert_eq!(decoded.issuer.as_deref(), Some("auth-gw"));
    // Old PHP records WITHOUT the region/issuer keys still deserialize
    // (serde default).
    let mut legacy_written = php_written;
    legacy_written.as_object_mut().unwrap().remove("region");
    legacy_written.as_object_mut().unwrap().remove("issuer");
    let decoded: ChallengeRecord = serde_json::from_value(legacy_written).unwrap();
    assert_eq!(decoded.region, None);
    assert_eq!(decoded.issuer, None);
}

// ── Round-8 audit: replica wait, TTL margin, region, jti, strict tokens ──

#[test]
fn replica_wait_barrier_fails_closed_without_replicas() {
    // Audit round 14: with_wait(1, ...) makes the durability promise
    // UNCONDITIONAL — after the SET a WAIT is issued and its
    // acknowledgement count is verified. A replica-less server returns 0
    // (after the timeout), so the store MUST fail closed: a challenge that
    // only lives on the primary must never be handed to the client.
    let Some(url) = redis_url() else { return };
    let wait_prefix = prefix("wait");
    let issued = issue_challenge(
        &sha_config(4),
        "login",
        IP,
        now_unix(),
        now_micros(),
        0,
        None,
    )
    .unwrap();
    let store = store_for(&url, &wait_prefix).with_wait(1, 200);
    assert_eq!(store.wait_config(), (1, 200));
    let err = store
        .store(&issued.record)
        .expect_err("store() must fail closed when the replica ack threshold is not met");
    assert!(
        err.to_string().contains("replica wait not satisfied"),
        "unexpected error: {err}"
    );

    // The same store satisfies the barrier when WAIT reports the required
    // acknowledgement count (a replica set that acked the write). WAIT is
    // the single point of truth, so this exercises the success path
    // against a store whose barrier is genuinely met.
    let prefix_ok = prefix("wait-ok");
    let store_ok = store_for(&url, &prefix_ok)
        .with_wait(0, 0) // no barrier: plain round-trip still works
        .with_ttl_margin(0);
    let issued2 = issue_challenge(
        &sha_config(4),
        "login",
        IP,
        now_unix(),
        now_micros(),
        0,
        None,
    )
    .unwrap();
    store_ok.store(&issued2.record).unwrap();
    let peeked = store_ok
        .find(&issued2.record.nonce)
        .unwrap()
        .expect("record must exist without a barrier");
    assert_eq!(peeked.challenge, issued2.record.challenge);

    // The default store has no wait configured.
    assert_eq!(store_for(&url, &wait_prefix).wait_config(), (0, 0));
    // wait_replicas=0 disables the WAIT entirely.
    store_for(&url, &wait_prefix)
        .with_wait(0, 5000)
        .store(&issued.record)
        .unwrap();
}

#[test]
fn consume_and_commit_barriers_fail_closed_without_replicas() {
    // Audit round 14: the pending→consumed transition and the deterministic
    // result commit carry the SAME verified replica barrier as issuance —
    // a promotion must never resurrect a consumed record from a stale
    // replica, and a committed result must survive promotion. Against a
    // replica-less server both fail closed after the write landed.
    let Some(url) = redis_url() else { return };
    let barrier_prefix = prefix("barrier");
    let issued = issue_challenge(
        &sha_config(4),
        "login",
        IP,
        now_unix(),
        now_micros(),
        0,
        None,
    )
    .unwrap();
    let store = store_for(&url, &barrier_prefix).with_wait(1, 200);

    // Issuance without a barrier, then a BARRIERED consume.
    store_for(&url, &barrier_prefix)
        .store(&issued.record)
        .unwrap();
    let err = store
        .consume(&issued.record.nonce)
        .expect_err("consume must fail closed when the transition is not durably replicated");
    assert!(
        err.to_string().contains("replica wait not satisfied"),
        "unexpected error: {err}"
    );

    // The transition DID land on the primary — a later plain consume sees
    // the consumed state (exactly the indeterminate situation the verifier
    // maps ConsumeIndeterminate to).
    let plain = store_for(&url, &barrier_prefix);
    let retry = plain.consume(&issued.record.nonce).unwrap();
    assert!(retry.is_some());
    assert!(
        !retry.unwrap().first,
        "the failed-barrier consume still transitioned the record"
    );

    // A barriered commit on a consumed record: the commit lands, then the
    // barrier fails closed.
    let issued3 = issue_challenge(
        &sha_config(4),
        "login",
        IP,
        now_unix(),
        now_micros(),
        0,
        None,
    )
    .unwrap();
    store_for(&url, &barrier_prefix)
        .store(&issued3.record)
        .unwrap();
    plain.consume(&issued3.record.nonce).unwrap().unwrap();
    let err = store
        .commit_result(&issued3.record.nonce, true, Some("txn-1"))
        .expect_err("commit must fail closed when the commit is not durably replicated");
    assert!(
        err.to_string().contains("replica wait not satisfied"),
        "unexpected error: {err}"
    );
    // The failed-barrier commit DID land on the primary — a retry cannot
    // re-commit (the deterministic outcome is already stored).
    assert!(
        !plain
            .commit_result(&issued3.record.nonce, true, Some("txn-2"))
            .unwrap(),
        "the failed-barrier commit must not be re-committable"
    );
}

#[test]
fn ttl_margin_extends_the_redis_ttl_only() {
    // Audit #23: store() uses EX = max(1, expires_at - now + margin). The
    // verifier's own TTL check still rejects at expires_at, so the margin
    // never extends the challenge's real lifetime — it only keeps the record
    // readable across replica lag / clock skew.
    let Some(url) = redis_url() else { return };
    let prefix = prefix("margin");
    let issued = issue_challenge(
        &sha_config(4),
        "login",
        IP,
        now_unix(),
        now_micros(),
        0,
        None,
    )
    .unwrap();
    let store = store_for(&url, &prefix).with_ttl_margin(30);
    assert_eq!(store.ttl_margin_secs(), 30);
    store.store(&issued.record).unwrap();

    let key = format!("{prefix}{}", issued.record.nonce);
    let mut conn = redis::Client::open(url.clone())
        .unwrap()
        .get_connection()
        .unwrap();
    let before = now_unix();
    let ttl: i64 = redis::cmd("TTL").arg(&key).query(&mut conn).unwrap();
    let after = now_unix();
    let base = issued.record.expires_at as i64 - after as i64;
    // Sub-second slack: the TTL was stamped from the store's clock read
    // (before) and is read here (after), so the exact bound is
    // `base + 30 + (after - before)`; `>= base + 29` is the tight floor.
    assert!(
        ttl >= base + 29 && ttl <= base + 30 + (after - before) as i64 + 1,
        "TTL must be expires_at - now + margin(30), got {ttl} (base {base})"
    );

    // End-to-end: a record stored with a margin verifies normally, and a
    // stale record (past expires_at but within the margin) is still REJECTED
    // by the verifier's TTL check (the margin is storage-only).
    let verifier = verifier_for(&url, &prefix);
    let store_margin = store_for(&url, &prefix).with_ttl_margin(30);
    let counter = solve_for_test(&issued.record).expect("4-bit sha solves");
    store_margin.store(&issued.record).unwrap();
    assert!(matches!(
        verify_at(
            &verifier,
            &encode_token(&issued.record.nonce, counter),
            issued.record.issued_at_ns
        ),
        VerifyOutcome::Valid { .. }
    ));
}

#[test]
fn verifier_expected_region_rejects_mismatched_and_unbound_records() {
    // Audit #22: ProductionVerifier::with_expected_region enforces the
    // region in the cheap phase. A record issued for a different region —
    // or for no region — is rejected with WrongRegion BEFORE any consume.
    let Some(url) = redis_url() else { return };
    let prefix = prefix("region");
    let config = ChallengeConfig {
        region: Some("eu".into()),
        ..sha_config(4)
    };
    let issued = issue_challenge(&config, "login", IP, now_unix(), now_micros(), 0, None).unwrap();
    let counter = solve_for_test(&issued.record).expect("4-bit sha solves");
    let token = encode_token(&issued.record.nonce, counter);
    let issued_at_ns = issued.record.issued_at_ns;

    // Mismatch: record region "eu", verifier expects "us".
    let expecting_us = verifier_for(&url, &prefix).with_expected_region("us");
    expecting_us.store().store(&issued.record).unwrap();
    assert_eq!(
        verify_at(&expecting_us, &token, issued_at_ns),
        VerifyOutcome::Invalid(VerifyError::WrongRegion)
    );
    // The cheap failure consumed the record; re-store for the next check.
    expecting_us.store().store(&issued.record).unwrap();

    // Match: record region "eu", verifier expects "eu".
    let expecting_eu = verifier_for(&url, &prefix).with_expected_region("eu");
    assert!(matches!(
        verify_at(&expecting_eu, &token, issued_at_ns),
        VerifyOutcome::Valid { .. }
    ));

    // Unbound record + expecting region → fail closed.
    let unbound = issue_challenge(
        &sha_config(4),
        "login",
        IP,
        now_unix(),
        now_micros(),
        0,
        None,
    )
    .unwrap();
    let counter2 = solve_for_test(&unbound.record).expect("4-bit sha solves");
    let token2 = encode_token(&unbound.record.nonce, counter2);
    expecting_eu.store().store(&unbound.record).unwrap();
    assert_eq!(
        verify_at(&expecting_eu, &token2, unbound.record.issued_at_ns),
        VerifyOutcome::Invalid(VerifyError::WrongRegion)
    );

    // No expectation → the record's region is ignored.
    let free = verifier_for(&url, &prefix);
    free.store().store(&unbound.record).unwrap();
    assert!(matches!(
        verify_at(&free, &token2, unbound.record.issued_at_ns),
        VerifyOutcome::Valid { .. }
    ));
    // without_expected_region clears the expectation.
    let cleared = verifier_for(&url, &prefix)
        .with_expected_region("us")
        .without_expected_region();
    assert_eq!(cleared.expected_region(), None);
}

#[test]
fn verifier_secrets_by_kid_selects_the_secret_and_rejects_unknown_kids() {
    // Audit #91 at the production boundary: with_secrets_by_kid makes the
    // record's kid select the signing secret in the cheap phase. The
    // matching key verifies; the wrong key for the same kid is
    // BadSignature; an unknown (or future) kid is UnknownKid — all before
    // any consume.
    let Some(url) = redis_url() else { return };
    let prefix = prefix("kid");
    let key_b = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";
    // Issue under kid 2 with key_b as the master secret.
    let issued = issue_challenge(
        &ChallengeConfig {
            kid: 2,
            ..ChallengeConfig {
                secret_key: key_b.into(),
                ..sha_config(4)
            }
        },
        "login",
        IP,
        now_unix(),
        now_micros(),
        0,
        None,
    )
    .unwrap();
    let counter = solve_for_test(&issued.record).expect("4-bit sha solves");
    let token = encode_token(&issued.record.nonce, counter);
    let issued_at_ns = issued.record.issued_at_ns;
    assert_eq!(issued.record.kid, 2);

    // The matching key verifies.
    let matching = verifier_for(&url, &prefix).with_secrets_by_kid([(2, key_b.to_string())]);
    matching.store().store(&issued.record).unwrap();
    assert!(
        matches!(
            verify_at(&matching, &token, issued_at_ns),
            VerifyOutcome::Valid { .. }
        ),
        "the kid-selected secret must verify"
    );

    // The wrong secret for the same kid → BadSignature.
    let wrong =
        verifier_for(&url, &prefix).with_secrets_by_kid([(2, "WRONG-KEY-16-bytes!".into())]);
    wrong.store().store(&issued.record).unwrap();
    assert_eq!(
        verify_at(&wrong, &token, issued_at_ns),
        VerifyOutcome::Invalid(VerifyError::BadSignature)
    );

    // A verifier that never rolled forward to kid 2 → UnknownKid.
    let older = verifier_for(&url, &prefix).with_secrets_by_kid([(1, key_b.to_string())]);
    older.store().store(&issued.record).unwrap();
    assert_eq!(
        verify_at(&older, &token, issued_at_ns),
        VerifyOutcome::Invalid(VerifyError::UnknownKid),
        "a kid beyond the configured max must be UnknownKid (forward guard)"
    );
}

#[test]
fn valid_outcome_exposes_the_consumed_nonce() {
    // Audit #37: the ProductionVerifier outcome carries the canonical nonce
    // (jti) of the consumed record.
    let Some(url) = redis_url() else { return };
    let prefix = prefix("jti");
    let issued = issue_challenge(
        &sha_config(4),
        "login",
        IP,
        now_unix(),
        now_micros(),
        0,
        None,
    )
    .unwrap();
    let counter = solve_for_test(&issued.record).expect("4-bit sha solves");
    let verifier = verifier_for(&url, &prefix);
    verifier.store().store(&issued.record).unwrap();
    match verify_at(
        &verifier,
        &encode_token(&issued.record.nonce, counter),
        issued.record.issued_at_ns,
    ) {
        VerifyOutcome::Valid { nonce, .. } => assert_eq!(nonce, issued.record.nonce),
        other => panic!("expected Valid, got {other:?}"),
    }
}

#[test]
fn noncanonical_tokens_reach_the_verifier_as_malformed_token() {
    // Audit #29 at the production boundary: url-safe variants and loose
    // padding are rejected as MalformedToken by ProductionVerifier::verify
    // (all decode errors map to MalformedToken).
    let Some(url) = redis_url() else { return };
    let prefix = prefix("strict-token");
    let issued = issue_challenge(
        &sha_config(4),
        "login",
        IP,
        now_unix(),
        now_micros(),
        0,
        None,
    )
    .unwrap();
    let counter = solve_for_test(&issued.record).expect("4-bit sha solves");
    let verifier = verifier_for(&url, &prefix);
    verifier.store().store(&issued.record).unwrap();
    let issued_at_ns = issued.record.issued_at_ns;

    // A token with a 5-digit counter yields a plain payload of 58 bytes
    // (58 % 3 == 1), so the canonical outer encoding carries exactly two
    // padding '=' characters — making the padding variants deterministic.
    let good = encode_token(&issued.record.nonce, 99_999);
    assert_eq!(good.len() % 4, 0);
    assert!(good.ends_with('='));

    let url_safe = format!("-{}", &good[1..]); // '-' is outside the standard alphabet
    assert_ne!(url_safe, good);
    assert_eq!(
        verifier.verify(&url_safe, "login", IP, issued_at_ns + 1_000_000),
        VerifyOutcome::Invalid(VerifyError::MalformedToken)
    );
    let unpadded = good.trim_end_matches('=');
    assert_eq!(
        verifier.verify(unpadded, "login", IP, issued_at_ns + 1_000_000),
        VerifyOutcome::Invalid(VerifyError::MalformedToken)
    );
    let loose = format!("{good}=");
    assert_eq!(
        verifier.verify(&loose, "login", IP, issued_at_ns + 1_000_000),
        VerifyOutcome::Invalid(VerifyError::MalformedToken)
    );

    // None of the rejected tokens consumed the record: the real solution
    // still verifies.
    assert!(matches!(
        verify_at(
            &verifier,
            &encode_token(&issued.record.nonce, counter),
            issued_at_ns
        ),
        VerifyOutcome::Valid { .. }
    ));
}

// ── Round-10 audit: issuer (67), final re-validation (59), future-time
//    bound (76), consumed-state transition (74), algorithm hard-fail (73) ──

#[test]
fn consumed_state_transition_and_outcome_commit_lifecycle() {
    // Audit #74 at the STORE level: consume() is a Lua transition that KEEPS
    // the record (state=pending → consumed), commit_result() stores the
    // outcome exactly once, and a later consume returns first=false with the
    // stored result.
    let Some(url) = redis_url() else { return };
    let prefix = prefix("transition");
    let issued = issue_challenge(
        &sha_config(4),
        "login",
        IP,
        now_unix(),
        now_micros(),
        0,
        None,
    )
    .unwrap();
    let store = store_for(&url, &prefix);
    store.store(&issued.record).unwrap();

    // 1. First consume wins the transition (first=true), no stored result.
    let first = store
        .consume(&issued.record.nonce)
        .unwrap()
        .expect("pending record consumes");
    assert!(first.first);
    assert_eq!(first.stored_result, None);
    assert_eq!(first.record.challenge, issued.record.challenge);

    // The stored value now carries the storage-level runtime `state`; the
    // record part still parses strictly.
    let key = format!("{prefix}{}", issued.record.nonce);
    let mut conn = redis::Client::open(url.clone())
        .unwrap()
        .get_connection()
        .unwrap();
    let raw: String = redis::cmd("GET").arg(&key).query(&mut conn).unwrap();
    let stored: serde_json::Value = serde_json::from_str(&raw).unwrap();
    assert_eq!(stored["state"], "consumed");
    assert!(stored.get("consumed_result").is_none());

    // 2. Consume while consumed with NO committed outcome: first=false,
    //    no stored result (the crash-window case → ConsumeIndeterminate
    //    upstream).
    let second = store
        .consume(&issued.record.nonce)
        .unwrap()
        .expect("consumed record still reads");
    assert!(!second.first);
    assert_eq!(second.stored_result, None);

    // 3. Commit the outcome: stored exactly once and returned on replay.
    assert!(store
        .commit_result(&issued.record.nonce, true, None)
        .unwrap());
    let third = store
        .consume(&issued.record.nonce)
        .unwrap()
        .expect("consumed record still reads");
    assert!(!third.first);
    assert_eq!(
        third.stored_result,
        Some(StoredConsumedResult {
            valid: true,
            binding: None
        })
    );

    // 4. A second commit is a no-op (0) — the first outcome wins.
    assert!(!store
        .commit_result(&issued.record.nonce, false, Some("x"))
        .unwrap());

    // 5. Committing a PENDING record is a no-op (0); a binding round-trips.
    let issued2 = issue_challenge(
        &sha_config(4),
        "login",
        IP,
        now_unix(),
        now_micros(),
        0,
        Some("txn-1"),
    )
    .unwrap();
    store.store(&issued2.record).unwrap();
    assert!(
        !store
            .commit_result(&issued2.record.nonce, true, Some("txn-1"))
            .unwrap(),
        "committing a pending record must be refused"
    );
    let first2 = store
        .consume(&issued2.record.nonce)
        .unwrap()
        .expect("second record consumes");
    assert!(first2.first);
    assert!(store
        .commit_result(&issued2.record.nonce, true, Some("txn-1"))
        .unwrap());
    let replay2 = store
        .consume(&issued2.record.nonce)
        .unwrap()
        .expect("second record replays");
    assert_eq!(
        replay2.stored_result,
        Some(StoredConsumedResult {
            valid: true,
            binding: Some("txn-1".into())
        })
    );

    // 6. Missing keys: consume → None, commit → false.
    assert!(store.consume("does-not-exist").unwrap().is_none());
    assert!(!store.commit_result("does-not-exist", true, None).unwrap());
}

#[test]
fn verifier_expected_issuer_rejects_mismatched_and_unbound_records() {
    // Audit #67 at the production boundary: with_expected_issuer enforces
    // the issuer in the cheap phase. A record issued by a different issuer
    // — or by no issuer — is rejected with WrongIssuer BEFORE any consume.
    let Some(url) = redis_url() else { return };
    let prefix = prefix("issuer");
    let config = ChallengeConfig {
        issuer: Some("auth-gw-eu".into()),
        ..sha_config(4)
    };
    let issued = issue_challenge(&config, "login", IP, now_unix(), now_micros(), 0, None).unwrap();
    let counter = solve_for_test(&issued.record).expect("4-bit sha solves");
    let token = encode_token(&issued.record.nonce, counter);
    let issued_at_ns = issued.record.issued_at_ns;

    // Mismatch: record issuer "auth-gw-eu", verifier expects "auth-gw-us".
    let expecting_us = verifier_for(&url, &prefix).with_expected_issuer("auth-gw-us");
    expecting_us.store().store(&issued.record).unwrap();
    assert_eq!(
        verify_at(&expecting_us, &token, issued_at_ns),
        VerifyOutcome::Invalid(VerifyError::WrongIssuer)
    );
    // The cheap failure consumed the record; re-store for the next check.
    expecting_us.store().store(&issued.record).unwrap();

    // Match: record issuer "auth-gw-eu", verifier expects "auth-gw-eu".
    let expecting_eu = verifier_for(&url, &prefix).with_expected_issuer("auth-gw-eu");
    assert!(matches!(
        verify_at(&expecting_eu, &token, issued_at_ns),
        VerifyOutcome::Valid { .. }
    ));

    // Unbound record + expecting issuer → fail closed.
    let unbound = issue_challenge(
        &sha_config(4),
        "login",
        IP,
        now_unix(),
        now_micros(),
        0,
        None,
    )
    .unwrap();
    let counter2 = solve_for_test(&unbound.record).expect("4-bit sha solves");
    let token2 = encode_token(&unbound.record.nonce, counter2);
    expecting_eu.store().store(&unbound.record).unwrap();
    assert_eq!(
        verify_at(&expecting_eu, &token2, unbound.record.issued_at_ns),
        VerifyOutcome::Invalid(VerifyError::WrongIssuer)
    );

    // No expectation → the record's issuer is ignored; the accessors and
    // the clearing builder behave.
    let free = verifier_for(&url, &prefix);
    free.store().store(&unbound.record).unwrap();
    assert!(matches!(
        verify_at(&free, &token2, unbound.record.issued_at_ns),
        VerifyOutcome::Valid { .. }
    ));
    assert_eq!(expecting_eu.expected_issuer(), Some("auth-gw-eu"));
    let cleared = verifier_for(&url, &prefix)
        .with_expected_issuer("auth-gw")
        .without_expected_issuer();
    assert_eq!(cleared.expected_issuer(), None);
}

#[test]
fn future_issued_challenge_beyond_skew_is_rejected() {
    // Audit #76 at the production boundary: a challenge whose issued_at is
    // more than MAX_CLOCK_SKEW_SECS (60) ahead of the verifier clock is a
    // time-domain anomaly — the cheap TTL phase rejects it with Expired.
    // The verifier's clock is INJECTED (the PHP `$now` override equivalent)
    // so the check is fully deterministic: the 61 s future-issued challenge
    // is always beyond the 60 s skew bound, no wall-clock race.
    let Some(url) = redis_url() else { return };
    let prefix = prefix("future");
    let fixed_now = now_unix();
    let issued = issue_challenge(
        &sha_config(4),
        "login",
        IP,
        fixed_now + 61, // issued_at > now + 60 → beyond the skew bound
        now_micros(),
        0,
        None,
    )
    .unwrap();
    let counter = solve_for_test(&issued.record).expect("4-bit sha solves");
    FAKE_FUTURE_NOW.store(fixed_now, Ordering::SeqCst);
    let verifier = verifier_for(&url, &prefix).with_now_fn(fake_future_now);
    verifier.store().store(&issued.record).unwrap();
    assert_eq!(
        verifier.verify(
            &encode_token(&issued.record.nonce, counter),
            "login",
            IP,
            issued.record.issued_at_ns + 1_000_000
        ),
        VerifyOutcome::Invalid(VerifyError::Expired),
        "a future-issued challenge beyond the clock skew must be rejected"
    );
}

#[test]
fn unknown_algorithm_variants_in_stored_records_are_record_not_found() {
    // Audit #73 at the production boundary: a stored record with an unknown
    // algorithm variant cannot parse (serde rejects it; PHP fromArray
    // throws MalformedRecordException) — the storage layer maps the corrupt
    // key to RecordNotFound, identical to PHP.
    let Some(url) = redis_url() else { return };
    for algo in ["argon2d", "sha1", "sha256-v2", "ARGON2ID"] {
        let prefix = prefix(&format!("algo-{algo}"));
        let issued = issue_challenge(
            &sha_config(4),
            "login",
            IP,
            now_unix(),
            now_micros(),
            0,
            None,
        )
        .unwrap();
        let mut value = serde_json::to_value(&issued.record).unwrap();
        value["algorithm"] = serde_json::json!(algo);
        let key = format!("{prefix}{}", issued.record.nonce);
        let mut conn = redis::Client::open(url.clone())
            .unwrap()
            .get_connection()
            .unwrap();
        let _: () = redis::cmd("SET")
            .arg(key)
            .arg(serde_json::to_string(&value).unwrap())
            .query(&mut conn)
            .unwrap();
        let verifier = verifier_for(&url, &prefix);
        assert_eq!(
            verifier.verify(
                &encode_token(&issued.record.nonce, 0),
                "login",
                IP,
                now_micros()
            ),
            VerifyOutcome::Invalid(VerifyError::RecordNotFound),
            "algorithm {algo:?} must be undecodable (RecordNotFound), like PHP"
        );
    }
}

// ── Round-12 audit: revocation (#117), allocation-after-length (#113),
//    NOSCRIPT recovery (#102) ──────────────────────────────────────────────

#[test]
fn revoked_kid_is_rejected_before_signature_checks() {
    // Audit #117 at the production boundary: with_revoked_kids rejects the
    // record in the cheap phase with UnknownKid — BEFORE the signature
    // check — even when the kid's secret is present in secrets_by_kid:
    // compromise revocation overrides the rotation grace. An UNREVOKED kid
    // with its secret present verifies normally.
    let Some(url) = redis_url() else { return };
    let prefix = prefix("revoked");
    let key_b = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";
    let issued = issue_challenge(
        &ChallengeConfig {
            kid: 2,
            ..ChallengeConfig {
                secret_key: key_b.into(),
                ..sha_config(4)
            }
        },
        "login",
        IP,
        now_unix(),
        now_micros(),
        0,
        None,
    )
    .unwrap();
    let counter = solve_for_test(&issued.record).expect("4-bit sha solves");
    let token = encode_token(&issued.record.nonce, counter);
    let issued_at_ns = issued.record.issued_at_ns;

    // Perfectly signed, secret PRESENT, kid REVOKED → UnknownKid.
    let revoking = verifier_for(&url, &prefix)
        .with_secrets_by_kid([(2, key_b.to_string())])
        .with_revoked_kids([2]);
    revoking.store().store(&issued.record).unwrap();
    assert_eq!(
        verify_at(&revoking, &token, issued_at_ns),
        VerifyOutcome::Invalid(VerifyError::UnknownKid),
        "a revoked kid must be rejected even with its secret present"
    );

    // Same record, a DIFFERENT kid revoked → the unrevoked kid verifies.
    let unrevoked = verifier_for(&url, &prefix)
        .with_secrets_by_kid([(2, key_b.to_string())])
        .with_revoked_kids([9]);
    unrevoked.store().store(&issued.record).unwrap();
    assert!(
        matches!(
            verify_at(&unrevoked, &token, issued_at_ns),
            VerifyOutcome::Valid { .. }
        ),
        "an unrevoked kid must verify normally"
    );
}

#[test]
fn oversized_stored_record_is_rejected_before_parse() {
    // Audit #113 at the production boundary: a 10 MB attacker-written value
    // under the nonce key is rejected by the stored-record length cap BEFORE
    // any JSON parse and maps to RecordNotFound — exactly like any other
    // corrupt key (PHP parity), never a large parse and never a panic.
    let Some(url) = redis_url() else { return };
    let prefix = prefix("oversize");
    let issued = issue_challenge(
        &sha_config(4),
        "login",
        IP,
        now_unix(),
        now_micros(),
        0,
        None,
    )
    .unwrap();
    let key = format!("{prefix}{}", issued.record.nonce);
    let mut conn = redis::Client::open(url.clone())
        .unwrap()
        .get_connection()
        .unwrap();
    let _: () = redis::cmd("SET")
        .arg(key)
        .arg("A".repeat(10 * 1024 * 1024))
        .query(&mut conn)
        .unwrap();

    let verifier = verifier_for(&url, &prefix);
    assert_eq!(
        verifier.verify(
            &encode_token(&issued.record.nonce, 0),
            "login",
            IP,
            now_micros()
        ),
        VerifyOutcome::Invalid(VerifyError::RecordNotFound),
        "a 10 MB stored value must be rejected at parse (RecordNotFound), like any corrupt key"
    );
}

#[test]
fn script_flush_is_recovered_deterministically() {
    // Audit #102: the redis crate's Script invoke() handles NOSCRIPT by
    // re-loading the script text (EVALSHA → NOSCRIPT → SCRIPT LOAD →
    // EVALSHA), so a SCRIPT FLUSH cannot break verification: the record is
    // NOT burned and the verification proceeds normally — deterministically,
    // and again after a second flush (every script invocation re-covers).
    let Some(url) = redis_url() else { return };
    let prefix = prefix("noscript");
    let issued = issue_challenge(
        &sha_config(4),
        "login",
        IP,
        now_unix(),
        now_micros(),
        0,
        None,
    )
    .unwrap();
    let counter = solve_for_test(&issued.record).expect("4-bit sha solves");
    let token = encode_token(&issued.record.nonce, counter);
    let issued_at_ns = issued.record.issued_at_ns;

    let verifier = verifier_for(&url, &prefix);
    verifier.store().store(&issued.record).unwrap();

    let mut conn = redis::Client::open(url.clone())
        .unwrap()
        .get_connection()
        .unwrap();

    // Wipe the server-side script cache: BOTH Lua scripts are now unloaded
    // (the consume transition AND the outcome commit).
    let _: () = redis::cmd("SCRIPT").arg("FLUSH").query(&mut conn).unwrap();

    // The first verify after the flush re-loads the scripts on NOSCRIPT and
    // proceeds normally: the full consume → derive → commit lifecycle works.
    assert!(
        matches!(
            verify_at(&verifier, &token, issued_at_ns),
            VerifyOutcome::Valid { .. }
        ),
        "NOSCRIPT must be recovered by re-loading — the verification proceeds normally"
    );

    // The record is NOT burned: it still exists with the consumed state and
    // the committed outcome, and a replay returns the SAME outcome — even
    // after ANOTHER flush (the replayed consume re-loads the script again).
    let _: () = redis::cmd("SCRIPT").arg("FLUSH").query(&mut conn).unwrap();
    assert!(
        matches!(
            verify_at(&verifier, &token, issued_at_ns),
            VerifyOutcome::Valid { .. }
        ),
        "a replay after a second flush returns the stored outcome — deterministic recovery"
    );

    let key = format!("{prefix}{}", issued.record.nonce);
    let raw: String = redis::cmd("GET").arg(&key).query(&mut conn).unwrap();
    let stored: serde_json::Value = serde_json::from_str(&raw).unwrap();
    assert_eq!(
        stored["state"], "consumed",
        "the transition ran — the record is kept, not burned"
    );
    assert_eq!(stored["consumed_result"]["valid"], true);
}
