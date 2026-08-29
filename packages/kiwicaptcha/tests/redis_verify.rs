//! Redis-backed production verifier integration tests.
//!
//! Gated two ways:
//! - The whole file compiles only with `--features redis`.
//! - Every test that touches Redis skips (returns) unless the Redis URL
//!   env var is set — the same env-gated pattern as `tests/cross_language.rs` — so
//!   local `cargo test --features redis` stays hermetic. The pure-JSON
//!   cross-language key-parity test runs without Redis.

#![cfg(feature = "redis")]

use std::collections::BTreeSet;
use std::sync::atomic::{AtomicI64, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Barrier, Mutex};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

use kiwicaptcha::challenge::{
    issue_challenge, BindingMode, ChallengeConfig, ChallengeRecord, PoWAlgorithm,
};
use kiwicaptcha::redis_verify::{
    AdmissionError, ArgonAdmissionGate, ArgonLease, CancelResult, DeleteIfPending,
    ProductionVerifier, RedisChallengeStore, StoredConsumedResult, DEFAULT_POOL_SIZE,
};
use kiwicaptcha::token::SolutionToken;
use kiwicaptcha::verify::{solve_for_test, RequestBindingExpectation, VerifyError, VerifyOutcome};

/// Gate that flatly grants (`true`) or refuses (`false`) capacity — the
/// trait-based admission-gate contract.
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

/// Gate and lease pair that counts acquires, in-flight leases, and
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

/// The racer variant of the counting gate: counts acquires and leases
/// like [`CountingGate`], and additionally synchronizes every acquire on
/// a barrier. With the runtime-state gate in front of admission, two
/// racers must both pass their state reads before either may consume:
/// the barrier inside `acquire` forces both racers to reach the gate
/// before any lease is granted, so the Pending race is deterministic
/// (both racers read Pending, both acquire, exactly one derives).
struct RacerGate {
    barrier: Arc<Barrier>,
    active: Arc<AtomicUsize>,
    acquired: Arc<AtomicUsize>,
    released: Arc<AtomicUsize>,
}

struct RacerLease {
    active: Arc<AtomicUsize>,
    released: Arc<AtomicUsize>,
}

impl ArgonLease for RacerLease {}

impl Drop for RacerLease {
    fn drop(&mut self) {
        self.active.fetch_sub(1, Ordering::SeqCst);
        self.released.fetch_add(1, Ordering::SeqCst);
    }
}

impl ArgonAdmissionGate for RacerGate {
    fn acquire(
        &self,
        _record: &ChallengeRecord,
    ) -> Result<Option<Box<dyn ArgonLease>>, AdmissionError> {
        self.acquired.fetch_add(1, Ordering::SeqCst);
        self.active.fetch_add(1, Ordering::SeqCst);
        self.barrier.wait();
        Ok(Some(Box::new(RacerLease {
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
/// issue-time second — the 61 s future-issued challenge is then
/// always beyond the 60 s skew bound, with no wall-clock race.
static FAKE_FUTURE_NOW: AtomicU64 = AtomicU64::new(0);

fn fake_future_now() -> u64 {
    FAKE_FUTURE_NOW.load(Ordering::SeqCst)
}

/// Deterministic verifier clock for the consumed-evidence test: a fixed
/// time far past the challenge's signed expiry, so the cheap TTL check
/// deterministically fails while the retained record is still readable.
static FAKE_EVIDENCE_NOW: AtomicU64 = AtomicU64::new(0);

fn fake_evidence_now() -> u64 {
    FAKE_EVIDENCE_NOW.load(Ordering::SeqCst)
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

/// Minimal Redis-protocol command parser for the fake-Redis test server:
/// returns the command's argument strings and the number of bytes consumed,
/// or `None` while the buffer holds only a partial command.
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

/// Verify with a receipt time 1 s after issuance and the full contract
/// inputs (operation identity + expected request binding).
fn verify_with(
    verifier: &ProductionVerifier,
    token: &str,
    issued_at_ns: u64,
    operation_identity: Option<&str>,
    expected_request_binding: RequestBindingExpectation<'_>,
) -> VerifyOutcome {
    verifier.verify(
        token,
        "login",
        IP,
        issued_at_ns + 1_000_000,
        operation_identity,
        expected_request_binding,
    )
}

/// Verify with a receipt time 1 s after issuance — safely above every
/// derived minimum-duration floor (SHA 5 ms, Argon2id 50 ms) — and no
/// operation identity / expected binding (the native-caller default).
fn verify_at(verifier: &ProductionVerifier, token: &str, issued_at_ns: u64) -> VerifyOutcome {
    verify_with(
        verifier,
        token,
        issued_at_ns,
        None,
        RequestBindingExpectation::Unenforced,
    )
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
    // The stored JSON carries the shared runtime envelope (state marker +
    // consumed_result + operation_identity) on top of the canonical record
    // — exactly like the PHP store's format; the canonical fields must
    // equal the record's serialization once the runtime fields are
    // stripped.
    let mut canonical: serde_json::Value = serde_json::from_str(&raw).unwrap();
    for field in ["state", "consumed_result", "operation_identity"] {
        canonical
            .as_object_mut()
            .expect("stored JSON must be an object")
            .remove(field);
    }
    assert_eq!(
        serde_json::to_value(&issued.record).unwrap(),
        canonical,
        "stored wire format must be the canonical ChallengeRecord JSON plus the runtime envelope"
    );
    let decoded: ChallengeRecord = serde_json::from_value(canonical.clone()).unwrap();
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
fn php_written_record_with_non_null_operation_identity_parses_and_strips() {
    // A PHP-written record whose identity-aware consume spliced
    // `"operation_identity":"<hex>"` into the runtime envelope must parse
    // and strip cleanly: the canonical record never sees the runtime
    // field, find() and consume() both work, and the identity survives
    // untouched in the stored value.
    let Some(url) = redis_url() else { return };
    let prefix = prefix("php-opid");
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

    let mut value = serde_json::to_string(&issued.record).unwrap();
    value.truncate(value.len() - 1);
    // The envelope exactly as the PHP identity-aware consume writes it
    // (hex identity — the bounded Siteverify fingerprint shape).
    value.push_str(
        ",\"state\":\"consumed\",\"consumed_result\":{\"valid\":true,\"binding\":null},\
         \"operation_identity\":\"deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef\"}",
    );
    let key = format!("{prefix}{}", issued.record.nonce);
    let mut conn = redis::Client::open(url.clone())
        .unwrap()
        .get_connection()
        .unwrap();
    let _: () = redis::cmd("SET")
        .arg(&key)
        .arg(&value)
        .query(&mut conn)
        .unwrap();

    let store = store_for(&url, &prefix);
    // The strict parse strips the runtime fields (including the non-null
    // operation_identity) — the canonical record comes back intact.
    let found = store
        .find(&issued.record.nonce)
        .expect("find must not fail on a PHP-style record")
        .expect("the PHP-style record must be found");
    assert_eq!(found.nonce, issued.record.nonce);
    assert_eq!(found.issued_at_ns, issued.record.issued_at_ns);

    // The consume observes the already-consumed state (no transition) and
    // the stored committed result rides back.
    let consumed = store
        .consume(&issued.record.nonce)
        .expect("consume must not fail on a PHP-style record")
        .expect("the PHP-style record must be found");
    assert!(
        !consumed.first,
        "the PHP-written record is already consumed"
    );
    let stored = consumed
        .stored_result
        .expect("the PHP-committed result must ride back");
    assert!(stored.valid);
    assert_eq!(
        consumed.operation_identity.as_deref(),
        Some("deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"),
        "the PHP-recorded identity must ride back on the consumed result"
    );

    // The identity marker is preserved byte-exactly in the stored value
    // (the Rust reader only ever strips it, never rewrites it).
    let raw: String = redis::cmd("GET").arg(&key).query(&mut conn).unwrap();
    assert!(
        raw.contains("\"operation_identity\":\"deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef\""),
        "the stored PHP-written identity must survive untouched"
    );
}

#[test]
fn two_concurrent_verifies_exactly_one_derives() {
    // The consumed-state transition keeps the record, so the
    // concurrent loser (a no-identity native caller) resolves the retained
    // state through the identity gate: AlreadyConsumed once the winner's
    // valid outcome is committed — never a second Valid, never
    // RecordNotFound — or ConsumeIndeterminate when it races between the
    // transition and the outcome commit. Exactly one derive
    // happens: commit_result stores exactly once, so the single stored
    // `consumed_result` (valid=true) pins the derive count; the barrier
    // gate proves both racers passed through the Argon gate (the runtime-
    // state read and the gate run before the transition, so both racers
    // read Pending and both acquire; only the winner derives).
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
    // The in-gate barrier has the two racing threads as its only
    // participants: each verify must pass its runtime-state read and
    // reach the gate before either may consume, so the Pending race is
    // deterministic (both racers read Pending, both acquire, exactly one
    // derives).
    let gate = RacerGate {
        barrier: Arc::new(Barrier::new(2)),
        active: Arc::clone(&active),
        acquired: Arc::clone(&acquired),
        released: Arc::clone(&released),
    };
    let verifier = Arc::new(verifier_for(&url, &prefix).with_argon_gate(gate));
    verifier.store().store(&issued.record).unwrap();

    // Two threads race the same token; the transition means exactly one of
    // them wins it — the loser must resolve the retained state through the
    // identity gate without any derivation.
    let barrier = Arc::new(Barrier::new(3));
    let mut handles = Vec::new();
    for _ in 0..2 {
        let verifier = Arc::clone(&verifier);
        let barrier = Arc::clone(&barrier);
        let token = token.clone();
        handles.push(thread::spawn(move || {
            barrier.wait();
            verifier.verify(
                &token,
                "login",
                IP,
                issued_at_ns + 1_000_000,
                None,
                RequestBindingExpectation::Unenforced,
            )
        }));
    }
    barrier.wait();

    let mut valid = 0;
    let mut indeterminate = 0;
    let mut already_consumed = 0;
    for handle in handles {
        match handle.join().unwrap() {
            VerifyOutcome::Valid { .. } => valid += 1,
            VerifyOutcome::Invalid(VerifyError::ConsumeIndeterminate) => indeterminate += 1,
            VerifyOutcome::Invalid(VerifyError::AlreadyConsumed) => already_consumed += 1,
            other => panic!("unexpected concurrent outcome: {other:?}"),
        }
    }
    assert_eq!(
        valid + indeterminate + already_consumed,
        2,
        "one winner (Valid) + one identity-gated loser (AlreadyConsumed or ConsumeIndeterminate)"
    );
    assert_eq!(valid, 1, "exactly the transition winner returns Valid");
    assert!(
        indeterminate <= 1,
        "only the loser may see ConsumeIndeterminate (racing before the commit)"
    );
    assert!(
        already_consumed <= 1,
        "only the loser may see AlreadyConsumed (racing after the commit)"
    );
    assert_eq!(
        indeterminate + already_consumed,
        1,
        "the loser resolves the retained state through the identity gate: AlreadyConsumed when the winner's outcome is committed, ConsumeIndeterminate when it races before the commit"
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
fn cancelled_argon_record_never_acquires_an_admission_slot() {
    // Round-94 audit: a cancelled Argon record is terminal, so verify()
    // reads the runtime state after the cheap phase and before the
    // admission gate: RecordNotFound with zero acquires. An attacker who
    // cancels a challenge once cannot then flood syntactically valid
    // tokens (any bounded counter passes the cheap phase) to capture and
    // release scarce admission slots and starve legitimate memory-hard
    // verifications. The malformed-signature variant fails the cheap
    // phase itself, also with zero acquires.
    let Some(url) = redis_url() else { return };
    let prefix = prefix("cancel-admission");
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
    let arbitrary = encode_token(&issued.record.nonce, 0);
    let issued_at_ns = issued.record.issued_at_ns;

    let store = store_for(&url, &prefix);
    store.store(&issued.record).unwrap();
    assert_eq!(
        store.cancel(&issued.record.nonce).unwrap(),
        Some(CancelResult::CancelledNow),
        "the pending record flips to cancelled"
    );

    let gate = CountingGate {
        active: Arc::new(AtomicUsize::new(0)),
        acquired: Arc::new(AtomicUsize::new(0)),
        released: Arc::new(AtomicUsize::new(0)),
        accept: true,
    };
    let acquired = gate.acquired.clone();
    let verifier = verifier_for(&url, &prefix).with_argon_gate(gate);

    assert_eq!(
        verify_at(&verifier, &token, issued_at_ns),
        VerifyOutcome::Invalid(VerifyError::RecordNotFound),
        "a solved token for a cancelled record fails closed without admission"
    );
    assert_eq!(
        verify_at(&verifier, &arbitrary, issued_at_ns),
        VerifyOutcome::Invalid(VerifyError::RecordNotFound),
        "an arbitrary bounded counter for the same cancelled record also returns without admission"
    );
    assert_eq!(
        acquired.load(Ordering::SeqCst),
        0,
        "a cancelled record must never acquire an admission slot"
    );

    // The malformed-signature variant: the cheap phase fails it
    // (BadSignature) before the state gate, also with zero acquires.
    let tampered = issue_challenge(
        &argon_config(4),
        "login",
        IP,
        now_unix(),
        now_micros(),
        0,
        None,
    )
    .unwrap();
    let mut record = tampered.record.clone();
    record.challenge.push_str("00");
    record.prefix = format!("{}|{}|", record.challenge, record.salt);
    let malformed = encode_token(&record.nonce, counter);
    store.store(&record).unwrap();
    assert_eq!(
        store.cancel(&record.nonce).unwrap(),
        Some(CancelResult::CancelledNow),
        "the malformed-signature record is cancelled too"
    );
    assert_eq!(
        verify_at(&verifier, &malformed, tampered.record.issued_at_ns),
        VerifyOutcome::Invalid(VerifyError::BadSignature),
        "the malformed-signature token fails the cheap phase"
    );
    assert_eq!(
        acquired.load(Ordering::SeqCst),
        0,
        "the malformed-signature variant must never acquire either"
    );
}

#[test]
fn consumed_argon_record_with_matching_identity_replays_without_admission() {
    // Round-94 audit: an already-consumed Argon record resolves through
    // the identity gate from the runtime-state read, before the
    // admission gate: a same-operation replay returns the retained
    // stored outcome with zero acquires.
    let Some(url) = redis_url() else { return };
    let prefix = prefix("consumed-replay-admission");
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
    let identity = "logical-op-consumed-admission";
    let counter = solve_for_test(&issued.record).expect("4-bit argon solves");
    let token = encode_token(&issued.record.nonce, counter);
    let issued_at_ns = issued.record.issued_at_ns;

    let store = store_for(&url, &prefix);
    store.store(&issued.record).unwrap();
    assert!(
        store
            .consume_with_operation_identity(&issued.record.nonce, Some(identity))
            .unwrap()
            .expect("the pending record consumes")
            .first
    );
    store
        .commit_result(
            &issued.record.nonce,
            true,
            issued.record.request_binding.as_deref(),
        )
        .unwrap();

    let gate = CountingGate {
        active: Arc::new(AtomicUsize::new(0)),
        acquired: Arc::new(AtomicUsize::new(0)),
        released: Arc::new(AtomicUsize::new(0)),
        accept: true,
    };
    let acquired = gate.acquired.clone();
    let verifier = verifier_for(&url, &prefix).with_argon_gate(gate);

    let outcome = verify_with(
        &verifier,
        &token,
        issued_at_ns,
        Some(identity),
        RequestBindingExpectation::Unenforced,
    );
    assert!(
        matches!(
            outcome,
            VerifyOutcome::Valid {
                from_stored_result: true,
                ..
            }
        ),
        "the same-operation replay returns the retained stored success: {outcome:?}"
    );
    assert_eq!(
        acquired.load(Ordering::SeqCst),
        0,
        "a consumed record must never acquire an admission slot"
    );
}

#[test]
fn consumed_argon_record_with_wrong_or_null_identity_is_already_consumed_without_admission() {
    // Round-94 audit: the wrong-identity and no-identity replays of an
    // already-consumed Argon record resolve as AlreadyConsumed from the
    // runtime-state read, with zero acquires — one solved token never
    // funds a second operation and never captures admission capacity.
    let Some(url) = redis_url() else { return };
    let prefix = prefix("consumed-identity-admission");
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
    let identity = "logical-op-consumed-identity";
    let counter = solve_for_test(&issued.record).expect("4-bit argon solves");
    let token = encode_token(&issued.record.nonce, counter);
    let issued_at_ns = issued.record.issued_at_ns;

    let store = store_for(&url, &prefix);
    store.store(&issued.record).unwrap();
    assert!(
        store
            .consume_with_operation_identity(&issued.record.nonce, Some(identity))
            .unwrap()
            .expect("the pending record consumes")
            .first
    );
    store
        .commit_result(
            &issued.record.nonce,
            true,
            issued.record.request_binding.as_deref(),
        )
        .unwrap();

    let gate = CountingGate {
        active: Arc::new(AtomicUsize::new(0)),
        acquired: Arc::new(AtomicUsize::new(0)),
        released: Arc::new(AtomicUsize::new(0)),
        accept: true,
    };
    let acquired = gate.acquired.clone();
    let verifier = verifier_for(&url, &prefix).with_argon_gate(gate);

    assert_eq!(
        verify_with(
            &verifier,
            &token,
            issued_at_ns,
            Some("logical-op-someone-else"),
            RequestBindingExpectation::Unenforced
        ),
        VerifyOutcome::Invalid(VerifyError::AlreadyConsumed),
        "a wrong operation identity on the consumed record is AlreadyConsumed"
    );
    assert_eq!(
        verify_at(&verifier, &token, issued_at_ns),
        VerifyOutcome::Invalid(VerifyError::AlreadyConsumed),
        "a no-identity replay of the consumed record is AlreadyConsumed"
    );
    assert_eq!(
        acquired.load(Ordering::SeqCst),
        0,
        "the refused replays must never acquire an admission slot"
    );
}

#[test]
fn replay_after_valid_verify_is_identity_gated() {
    // The identity gate on the retained stored success: an exact
    // operation-identity retry is the idempotent retained Valid (marked
    // from_stored_result=true); a no-identity replay is
    // AlreadyConsumed — one solved token can never fund a second
    // operation. Never RecordNotFound, never a re-derivation.
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

    // Identity-bearing first verification → fresh Valid.
    assert_eq!(
        verify_with(
            &verifier,
            &token,
            issued_at_ns,
            Some("op-replay"),
            RequestBindingExpectation::Unenforced
        ),
        VerifyOutcome::Valid {
            nonce: issued.record.nonce.clone(),
            request_binding: None,
            from_stored_result: false,
        }
    );
    // The consumed record is kept with the committed outcome — an exact
    // identity retry returns the same Valid from the stored result,
    // distinguishable from a fresh success.
    assert_eq!(
        verify_with(
            &verifier,
            &token,
            issued_at_ns,
            Some("op-replay"),
            RequestBindingExpectation::Unenforced
        ),
        VerifyOutcome::Valid {
            nonce: issued.record.nonce.clone(),
            request_binding: None,
            from_stored_result: true,
        },
        "the exact identity retry is the retained Valid"
    );
    // A no-identity replay is refused: the retained success never replays
    // for a caller that cannot prove the recording operation identity.
    assert_eq!(
        verify_at(&verifier, &token, issued_at_ns),
        VerifyOutcome::Invalid(VerifyError::AlreadyConsumed),
        "a no-identity replay of a stored-valid record is AlreadyConsumed"
    );
}

#[test]
fn replay_outcomes_follow_the_operation_identity_gate() {
    // The full cross-language replay matrix: an identity-bearing first
    // verification records the identity atomically with the consume; an
    // exact retry is the idempotent retained Valid; a different identity —
    // or no identity — is AlreadyConsumed; a no-identity first
    // verification succeeds fresh but its replay is AlreadyConsumed; the
    // deterministic invalid outcome replays without any identity.
    let Some(url) = redis_url() else { return };
    let prefix = prefix("matrix");
    let verifier = verifier_for(&url, &prefix);

    // T + A first → fresh Valid (from_stored_result=false).
    let issued_a = issue_challenge(
        &sha_config(4),
        "login",
        IP,
        now_unix(),
        now_micros(),
        0,
        None,
    )
    .unwrap();
    let counter_a = solve_for_test(&issued_a.record).expect("4-bit sha solves");
    let token_a = encode_token(&issued_a.record.nonce, counter_a);
    verifier.store().store(&issued_a.record).unwrap();
    assert_eq!(
        verify_with(
            &verifier,
            &token_a,
            issued_a.record.issued_at_ns,
            Some("op-a"),
            RequestBindingExpectation::Unenforced
        ),
        VerifyOutcome::Valid {
            nonce: issued_a.record.nonce.clone(),
            request_binding: None,
            from_stored_result: false,
        },
        "T + A first: fresh Valid"
    );

    // T + A exact retry → the retained Valid (from_stored_result=true).
    assert_eq!(
        verify_with(
            &verifier,
            &token_a,
            issued_a.record.issued_at_ns,
            Some("op-a"),
            RequestBindingExpectation::Unenforced
        ),
        VerifyOutcome::Valid {
            nonce: issued_a.record.nonce.clone(),
            request_binding: None,
            from_stored_result: true,
        },
        "T + A exact retry: the retained Valid"
    );

    // T + B → AlreadyConsumed (the retained success belongs to op-a).
    assert_eq!(
        verify_with(
            &verifier,
            &token_a,
            issued_a.record.issued_at_ns,
            Some("op-b"),
            RequestBindingExpectation::Unenforced
        ),
        VerifyOutcome::Invalid(VerifyError::AlreadyConsumed),
        "T + B: a different identity is AlreadyConsumed"
    );

    // T + None first → fresh Valid; T + None second → AlreadyConsumed.
    let issued_none = issue_challenge(
        &sha_config(4),
        "login",
        IP,
        now_unix(),
        now_micros(),
        0,
        None,
    )
    .unwrap();
    let counter_none = solve_for_test(&issued_none.record).expect("4-bit sha solves");
    let token_none = encode_token(&issued_none.record.nonce, counter_none);
    verifier.store().store(&issued_none.record).unwrap();
    assert_eq!(
        verify_at(&verifier, &token_none, issued_none.record.issued_at_ns),
        VerifyOutcome::Valid {
            nonce: issued_none.record.nonce.clone(),
            request_binding: None,
            from_stored_result: false,
        },
        "T + None first: fresh Valid"
    );
    assert_eq!(
        verify_at(&verifier, &token_none, issued_none.record.issued_at_ns),
        VerifyOutcome::Invalid(VerifyError::AlreadyConsumed),
        "T + None second: a no-identity replay never receives the stored success"
    );

    // Wrong proof first → InsufficientWork (committed valid=false); the
    // same nonce later → the deterministic invalid, identity-free.
    let issued_wrong = issue_challenge(
        &sha_config(4),
        "login",
        IP,
        now_unix(),
        now_micros(),
        0,
        None,
    )
    .unwrap();
    let valid_counter = solve_for_test(&issued_wrong.record).expect("4-bit sha solves");
    let wrong_counter = if valid_counter == 0 { 1 } else { 0 };
    verifier.store().store(&issued_wrong.record).unwrap();
    assert_eq!(
        verify_with(
            &verifier,
            &encode_token(&issued_wrong.record.nonce, wrong_counter),
            issued_wrong.record.issued_at_ns,
            Some("op-wrong"),
            RequestBindingExpectation::Unenforced
        ),
        VerifyOutcome::Invalid(VerifyError::InsufficientWork),
        "wrong proof first: InsufficientWork"
    );
    assert_eq!(
        verify_with(
            &verifier,
            &encode_token(&issued_wrong.record.nonce, valid_counter),
            issued_wrong.record.issued_at_ns,
            None,
            RequestBindingExpectation::Unenforced
        ),
        VerifyOutcome::Invalid(VerifyError::InsufficientWork),
        "the same nonce later: the deterministic invalid outcome replays without an identity"
    );
}

#[test]
fn expected_request_binding_is_enforced_in_the_cheap_phase() {
    // The expected-request-binding contract: a matching binding verifies;
    // a differing binding — or a record without one when one is expected —
    // is RequestBindingMismatch, and the pending record is consumed by the
    // cheap failure; None (the default) leaves the binding unenforced.
    let Some(url) = redis_url() else { return };
    let prefix = prefix("binding");
    let issued = issue_challenge(
        &sha_config(4),
        "login",
        IP,
        now_unix(),
        now_micros(),
        0,
        Some("txn-1"),
    )
    .unwrap();
    let counter = solve_for_test(&issued.record).expect("4-bit sha solves");
    let token = encode_token(&issued.record.nonce, counter);
    let issued_at_ns = issued.record.issued_at_ns;
    let verifier = verifier_for(&url, &prefix);

    // Match: the record's signed binding equals the expectation.
    verifier.store().store(&issued.record).unwrap();
    assert_eq!(
        verify_with(
            &verifier,
            &token,
            issued_at_ns,
            None,
            RequestBindingExpectation::Exact(Some("txn-1"))
        ),
        VerifyOutcome::Valid {
            nonce: issued.record.nonce.clone(),
            request_binding: Some("txn-1".into()),
            from_stored_result: false,
        },
        "a matching expected binding verifies"
    );

    // Mismatch: a different expected binding is RequestBindingMismatch.
    let issued_mismatch = issue_challenge(
        &sha_config(4),
        "login",
        IP,
        now_unix(),
        now_micros(),
        0,
        Some("txn-1"),
    )
    .unwrap();
    let counter_mismatch = solve_for_test(&issued_mismatch.record).expect("4-bit sha solves");
    let token_mismatch = encode_token(&issued_mismatch.record.nonce, counter_mismatch);
    verifier.store().store(&issued_mismatch.record).unwrap();
    assert_eq!(
        verify_with(
            &verifier,
            &token_mismatch,
            issued_mismatch.record.issued_at_ns,
            None,
            RequestBindingExpectation::Exact(Some("txn-2"))
        ),
        VerifyOutcome::Invalid(VerifyError::RequestBindingMismatch),
        "a differing expected binding is RequestBindingMismatch"
    );
    // The cheap failure consumed the pending record (one-shot semantics).
    assert_eq!(
        verify_with(
            &verifier,
            &token_mismatch,
            issued_mismatch.record.issued_at_ns,
            None,
            RequestBindingExpectation::Exact(Some("txn-1"))
        ),
        VerifyOutcome::Invalid(VerifyError::RecordNotFound),
        "the binding-mismatch cheap failure consumed the pending record"
    );

    // No binding on the record when one is expected → fail closed.
    let issued_unbound = issue_challenge(
        &sha_config(4),
        "login",
        IP,
        now_unix(),
        now_micros(),
        0,
        None,
    )
    .unwrap();
    let counter_unbound = solve_for_test(&issued_unbound.record).expect("4-bit sha solves");
    let token_unbound = encode_token(&issued_unbound.record.nonce, counter_unbound);
    verifier.store().store(&issued_unbound.record).unwrap();
    assert_eq!(
        verify_with(
            &verifier,
            &token_unbound,
            issued_unbound.record.issued_at_ns,
            None,
            RequestBindingExpectation::Exact(Some("txn-1"))
        ),
        VerifyOutcome::Invalid(VerifyError::RequestBindingMismatch),
        "a record without a binding fails closed when one is expected"
    );

    // None → the binding is not enforced (merely returned).
    let issued_none = issue_challenge(
        &sha_config(4),
        "login",
        IP,
        now_unix(),
        now_micros(),
        0,
        Some("txn-1"),
    )
    .unwrap();
    let counter_none = solve_for_test(&issued_none.record).expect("4-bit sha solves");
    let token_none = encode_token(&issued_none.record.nonce, counter_none);
    verifier.store().store(&issued_none.record).unwrap();
    assert_eq!(
        verify_with(
            &verifier,
            &token_none,
            issued_none.record.issued_at_ns,
            None,
            RequestBindingExpectation::Unenforced
        ),
        VerifyOutcome::Valid {
            nonce: issued_none.record.nonce.clone(),
            request_binding: Some("txn-1".into()),
            from_stored_result: false,
        },
        "None disables the expected-binding check"
    );
}

#[test]
fn consumed_evidence_survives_a_cheap_failure_past_expiry() {
    // The crash-recovery evidence contract: a consumed record with a
    // committed outcome is the retained proof of the original verdict. A
    // cheap-phase failure on a replay (here: the signed expiry passed) must
    // NOT delete it — the delete is gated on the consumed state, so the
    // evidence survives to its retention TTL and the replay resolves
    // through the identity-gated consumed branch.
    let Some(url) = redis_url() else { return };
    let prefix = prefix("evidence");
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

    // Consume + commit with an operation identity (the Siteverify-shaped
    // transition: identity recorded atomically with the state flip).
    let store = store_for(&url, &prefix);
    store.store(&issued.record).unwrap();
    let consumed = store
        .consume_with_operation_identity(&issued.record.nonce, Some("op-evidence"))
        .unwrap()
        .expect("pending record consumes");
    assert!(consumed.first);
    assert_eq!(
        consumed.operation_identity.as_deref(),
        Some("op-evidence"),
        "the winner's own identity rides back on the transition result"
    );
    store
        .commit_result(&issued.record.nonce, true, None)
        .unwrap();

    // Advance the verifier clock past the signed expiry: the cheap TTL
    // check fails, but the record is consumed — the failure routes to the
    // identity-gated consumed branch instead of deleting the evidence.
    FAKE_EVIDENCE_NOW.store(now_unix() + 300, Ordering::SeqCst);
    let verifier = verifier_for(&url, &prefix).with_now_fn(fake_evidence_now);
    assert_eq!(
        verify_with(
            &verifier,
            &token,
            issued_at_ns,
            Some("op-evidence"),
            RequestBindingExpectation::Unenforced
        ),
        VerifyOutcome::Valid {
            nonce: issued.record.nonce.clone(),
            request_binding: None,
            from_stored_result: true,
        },
        "the identity replay past expiry resolves the retained Valid"
    );
    assert_eq!(
        verify_at(&verifier, &token, issued_at_ns),
        VerifyOutcome::Invalid(VerifyError::AlreadyConsumed),
        "a no-identity replay of the expired consumed record is AlreadyConsumed"
    );

    // The record still exists — the recovery evidence survived the cheap
    // failure, intact with its committed outcome and identity.
    let key = format!("{prefix}{}", issued.record.nonce);
    let mut conn = redis::Client::open(url.clone())
        .unwrap()
        .get_connection()
        .unwrap();
    let raw: String = redis::cmd("GET").arg(&key).query(&mut conn).unwrap();
    let stored: serde_json::Value = serde_json::from_str(&raw).unwrap();
    assert_eq!(stored["state"], "consumed");
    assert_eq!(stored["consumed_result"]["valid"], true);
    assert_eq!(
        stored["operation_identity"],
        serde_json::json!("op-evidence"),
        "the identity marker survives untouched"
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
    // The retry with the correct counter sees the stored
    // valid=false outcome — the same InsufficientWork, not RecordNotFound.
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
    // occasion the record expires before the verifier reads it
    // (RecordNotFound), retry with a fresh challenge.
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
        match verifier.verify(
            &token,
            "login",
            IP,
            now_micros(),
            None,
            RequestBindingExpectation::Unenforced,
        ) {
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

    // Cross-language table: terminal cheap failures consume the
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

    // Verify on a worker thread so the main thread can observe the lease in
    // flight: it must be held (count == 1) across the atomic consume
    // transition and the Argon2id derivation, i.e. during the verify call.
    let worker = Arc::clone(&verifier);
    let worker_token = token.clone();
    let handle = thread::spawn(move || {
        worker.verify(
            &worker_token,
            "login",
            IP,
            issued_at_ns + 1_000_000,
            None,
            RequestBindingExpectation::Unenforced,
        )
    });

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

    // Default pool size is the crate default; with_pool_size overrides it.
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
    // 48 operations over a 2-slot pool: the same two slots must serve every
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
    // connects fail fast with a connection-refused error and the checkout
    // returns after the bounded pool checkout timeout. No Redis URL needed
    // — this test is hermetic.
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
            now_micros(),
            None,
            RequestBindingExpectation::Unenforced
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

    // A miniature Redis-protocol server: answers the peek (GET) with the
    // stored record's JSON so the verifier's cheap phase succeeds, and then
    // never replies to the consume transition script — the client's read
    // timeout fires and consume() must map to ConsumeIndeterminate.
    // Hermetic: no Redis URL needed.
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
                            // Hold the connection open without a reply: the
                            // client hits its 1 s read timeout. (The redis
                            // crate invokes scripts by sha.)
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
    // The keys PHP ChallengeRecord::toArray() emits for v2 records — the
    // exact key set a PHP RedisStorage writes and fromArray() reads. The
    // `region` and `issuer` keys are always present: null
    // when unbound, exactly like PHP; `kid` is always present
    // (default 1). No Redis needed: pure language-neutral schema parity.
    const PHP_KEYS: [&str; 23] = [
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
        "hostname",
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
        "the issuer key must be present (null when unbound) in the Rust wire format"
    );
    assert_eq!(
        value["kid"], 1,
        "the kid key must be present with the default 1 in the Rust wire format"
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
    // A PHP record without the kid key still deserializes (serde default 1).
    let mut no_kid_written = php_written.clone();
    no_kid_written.as_object_mut().unwrap().remove("kid");
    let decoded: ChallengeRecord = serde_json::from_value(no_kid_written).unwrap();
    assert_eq!(decoded.kid, 1, "missing kid must default to 1");
    // A region-bound PHP record round-trips the region.
    let mut region_written = php_written.clone();
    region_written["region"] = serde_json::json!("eu");
    let decoded: ChallengeRecord = serde_json::from_value(region_written).unwrap();
    assert_eq!(decoded.region.as_deref(), Some("eu"));
    // An issuer-bound PHP record round-trips the issuer.
    let mut issuer_written = php_written.clone();
    issuer_written["issuer"] = serde_json::json!("auth-gw");
    let decoded: ChallengeRecord = serde_json::from_value(issuer_written).unwrap();
    assert_eq!(decoded.issuer.as_deref(), Some("auth-gw"));
    // Old PHP records without the region/issuer keys still deserialize
    // (serde default).
    let mut legacy_written = php_written;
    legacy_written.as_object_mut().unwrap().remove("region");
    legacy_written.as_object_mut().unwrap().remove("issuer");
    let decoded: ChallengeRecord = serde_json::from_value(legacy_written).unwrap();
    assert_eq!(decoded.region, None);
    assert_eq!(decoded.issuer, None);
}

// ── replica wait, TTL margin, region, jti, strict tokens ──

#[test]
fn replica_wait_barrier_fails_closed_without_replicas() {
    // with_wait(1, ...) makes the durability promise
    // unconditional — after the SET a replica wait is issued and its
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

    // The same store satisfies the barrier when the wait reports the
    // required acknowledgement count (a replica set that acked the write).
    // The wait count is the single point of truth, so this exercises the
    // success path against a store whose barrier is genuinely met.
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
    // wait_replicas=0 disables the wait entirely.
    store_for(&url, &wait_prefix)
        .with_wait(0, 5000)
        .store(&issued.record)
        .unwrap();
}

#[test]
fn consume_and_commit_barriers_fail_closed_without_replicas() {
    // The pending→consumed transition and the deterministic
    // result commit carry the same verified replica barrier as issuance —
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

    // Issuance without a barrier, then a barriered consume.
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
fn delete_if_pending_issues_the_verified_wait_only_on_deleted_pending() {
    // A miniature Redis-protocol server records every issued command and
    // answers the delete-if-pending Lua with the tri-state replies keyed
    // on the nonce, so the WAIT barrier placement is observable: exactly
    // the deleted-pending transition with wait_replicas > 0 issues WAIT
    // (carrying the configured replica count and timeout, with the acked
    // count verified against the threshold); missing, consumed and
    // wait_replicas == 0 never wait — those outcomes leave the record
    // untouched, so there is no durability barrier to satisfy. The same
    // server then violates the acknowledgement (fewer acked than
    // configured), and the delete path fails closed with the same
    // durability failure the other transitions use. Hermetic: no Redis
    // URL needed.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();

    // The stored value a consumed record carries: the record JSON plus
    // the runtime envelope, exactly as consume() writes it.
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
    let mut consumed_json = serde_json::to_string(&issued.record).unwrap();
    consumed_json.truncate(consumed_json.len() - 1);
    consumed_json
        .push_str(",\"state\":\"consumed\",\"consumed_result\":null,\"operation_identity\":null}");

    let commands: Arc<Mutex<Vec<Vec<String>>>> = Arc::new(Mutex::new(Vec::new()));
    // -1 = echo the requested replica count (the wait is satisfied);
    // >= 0 = the ack count to reply (0 violates any configured barrier).
    let wait_acks = Arc::new(AtomicI64::new(-1));
    let server_commands = Arc::clone(&commands);
    let server_acks = Arc::clone(&wait_acks);
    std::thread::spawn(move || {
        use std::io::{Read, Write};
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let server_commands = Arc::clone(&server_commands);
            let server_acks = Arc::clone(&server_acks);
            let consumed_json = consumed_json.clone();
            std::thread::spawn(move || {
                let mut buf = Vec::new();
                let mut tmp = [0u8; 4096];
                // The redis crate invokes scripts by sha: the first
                // sha-addressed invocation misses (no-script), the load
                // command registers the script, and the retried
                // invocation is answered with the scripted Lua reply.
                let mut script_loaded = false;
                loop {
                    match stream.read(&mut tmp) {
                        Ok(0) => return,
                        Ok(n) => {
                            buf.extend_from_slice(&tmp[..n]);
                            while let Some((args, consumed)) = parse_resp_command(&buf) {
                                buf.drain(..consumed);
                                server_commands.lock().unwrap().push(args.clone());
                                let reply = match args[0].as_str() {
                                    "PING" => "+PONG\r\n".to_string(),
                                    "EVALSHA" if !script_loaded => {
                                        "-NOSCRIPT No matching script. Use EVAL.\r\n".to_string()
                                    }
                                    "EVALSHA" => {
                                        let key = args.get(3).map(String::as_str).unwrap_or("");
                                        if key.ends_with("-pending") {
                                            "*1\r\n$15\r\ndeleted-pending\r\n".to_string()
                                        } else if key.ends_with("-consumed") {
                                            format!(
                                                "*2\r\n$8\r\nconsumed\r\n${}\r\n{}\r\n",
                                                consumed_json.len(),
                                                consumed_json
                                            )
                                        } else {
                                            "*1\r\n$7\r\nmissing\r\n".to_string()
                                        }
                                    }
                                    "SCRIPT" => {
                                        script_loaded = true;
                                        "+OK\r\n".to_string()
                                    }
                                    "WAIT" => {
                                        let acks = server_acks.load(Ordering::SeqCst);
                                        let n = if acks >= 0 {
                                            acks.to_string()
                                        } else {
                                            args.get(1)
                                                .map(String::as_str)
                                                .unwrap_or("0")
                                                .to_string()
                                        };
                                        format!(":{n}\r\n")
                                    }
                                    _ => "+OK\r\n".to_string(),
                                };
                                stream.write_all(reply.as_bytes()).unwrap();
                            }
                        }
                        Err(_) => return,
                    }
                }
            });
        }
    });

    let url = format!("redis://127.0.0.1:{port}/");
    let barriered = store_for(&url, &prefix("delpend-wait")).with_wait(2, 1000);
    // deleted-pending: the transition mutated the store, so WAIT is
    // issued and the satisfied acknowledgement is accepted.
    assert!(matches!(
        barriered.delete_if_pending("nonce-a-pending").unwrap(),
        DeleteIfPending::DeletedPending
    ));
    // missing and consumed: no mutation, so no wait (a wait here would
    // hang the configured timeout and then fail closed on a 0 ack).
    assert!(matches!(
        barriered.delete_if_pending("nonce-b-missing").unwrap(),
        DeleteIfPending::Missing
    ));
    assert!(matches!(
        barriered.delete_if_pending("nonce-c-consumed").unwrap(),
        DeleteIfPending::Consumed(_)
    ));
    // wait_replicas == 0 disables the barrier even on the deletion.
    let unbarriered = store_for(&url, &prefix("delpend-nowait"));
    assert!(matches!(
        unbarriered.delete_if_pending("nonce-d-pending").unwrap(),
        DeleteIfPending::DeletedPending
    ));

    // A violated acknowledgement (fewer than wait_replicas) fails closed
    // on the delete path with the same durability failure as consume and
    // commit: the delete happened but its durability is unconfirmed.
    wait_acks.store(0, Ordering::SeqCst);
    let barriered2 = store_for(&url, &prefix("delpend-wait2")).with_wait(2, 1000);
    let err = barriered2
        .delete_if_pending("nonce-e-pending")
        .expect_err("a violated replica-wait barrier must fail closed on the delete path");
    assert!(
        err.to_string().contains("replica wait not satisfied"),
        "unexpected error: {err}"
    );

    let recorded = commands.lock().unwrap().clone();
    let waits: Vec<&Vec<String>> = recorded.iter().filter(|args| args[0] == "WAIT").collect();
    assert_eq!(
        waits.len(),
        2,
        "WAIT must be issued exactly on the deleted-pending transitions with wait_replicas > 0 (one satisfied, one violated); full command log: {recorded:?}"
    );
    for wait in &waits {
        assert_eq!(wait[1], "2", "WAIT must carry the configured replica count");
        assert_eq!(wait[2], "1000", "WAIT must carry the configured timeout");
    }
}

#[test]
fn delete_if_pending_barrier_fails_closed_without_replicas() {
    // The delete-if-pending cleanup carries the same verified replica
    // barrier as issuance / consume / commit — a promotion must never
    // resurrect a burned pending challenge from a stale replica. Against
    // a replica-less server the DEL lands on the primary, then the wait
    // reports 0 acks and the call fails closed: the cleanup happened but
    // its durability is unconfirmed. The no-mutation outcomes (missing,
    // consumed) and wait_replicas == 0 never wait and succeed normally.
    let Some(url) = redis_url() else { return };
    let barrier_prefix = prefix("delpend-barrier");
    let store = store_for(&url, &barrier_prefix).with_wait(1, 200);

    // Pending -> deleted with a violated barrier: the DEL executed on the
    // primary before the wait failed.
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
    store_for(&url, &barrier_prefix)
        .store(&issued.record)
        .unwrap();
    let err = store
        .delete_if_pending(&issued.record.nonce)
        .expect_err("delete_if_pending must fail closed when the DEL is not durably replicated");
    assert!(
        err.to_string().contains("replica wait not satisfied"),
        "unexpected error: {err}"
    );
    let key = format!("{barrier_prefix}{}", issued.record.nonce);
    let mut conn = redis::Client::open(url.clone())
        .unwrap()
        .get_connection()
        .unwrap();
    let raw: Option<String> = redis::cmd("GET").arg(&key).query(&mut conn).unwrap();
    assert!(
        raw.is_none(),
        "the failed-barrier delete still executed the DEL on the primary"
    );

    // Missing: no mutation, no wait — the call succeeds even though the
    // configured barrier could never be satisfied on this server.
    assert!(matches!(
        store.delete_if_pending("never-stored-nonce").unwrap(),
        DeleteIfPending::Missing
    ));

    // Consumed: no mutation, no wait — the retained evidence survives.
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
    store_for(&url, &barrier_prefix)
        .store(&issued2.record)
        .unwrap();
    let consumed = store_for(&url, &barrier_prefix)
        .consume(&issued2.record.nonce)
        .unwrap()
        .expect("pending record consumes");
    assert!(consumed.first);
    assert!(matches!(
        store.delete_if_pending(&issued2.record.nonce).unwrap(),
        DeleteIfPending::Consumed(_)
    ));

    // wait_replicas == 0 disables the barrier entirely: the pending
    // record is deleted without any wait.
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
    assert!(matches!(
        store_for(&url, &barrier_prefix)
            .delete_if_pending(&issued3.record.nonce)
            .unwrap(),
        DeleteIfPending::DeletedPending
    ));
}

#[test]
fn consume_issues_the_verified_wait_only_on_the_fresh_transition() {
    // A miniature Redis-protocol server records every issued command and
    // answers the consume-transition Lua with the tri-state replies keyed
    // on the nonce, so the WAIT barrier placement is observable: exactly
    // the fresh pending→consumed transition with wait_replicas > 0 issues
    // WAIT (carrying the configured replica count and timeout, with the
    // acked count verified against the threshold); a consumed-before
    // replay, a missing key and wait_replicas == 0 never wait — those
    // outcomes leave the stored value untouched, so there is no durability
    // barrier to satisfy. The same server then violates the
    // acknowledgement (fewer acked than configured), and the fresh
    // transition fails closed with the same durability failure the other
    // transitions use. Hermetic: no Redis URL needed.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();

    // The stored value a consumed record carries: the record JSON plus
    // the runtime envelope, exactly as consume() writes it.
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
    let mut consumed_json = serde_json::to_string(&issued.record).unwrap();
    consumed_json.truncate(consumed_json.len() - 1);
    consumed_json
        .push_str(",\"state\":\"consumed\",\"consumed_result\":null,\"operation_identity\":null}");

    let commands: Arc<Mutex<Vec<Vec<String>>>> = Arc::new(Mutex::new(Vec::new()));
    // -1 = echo the requested replica count (the wait is satisfied);
    // >= 0 = the ack count to reply (0 violates any configured barrier).
    let wait_acks = Arc::new(AtomicI64::new(-1));
    let server_commands = Arc::clone(&commands);
    let server_acks = Arc::clone(&wait_acks);
    std::thread::spawn(move || {
        use std::io::{Read, Write};
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let server_commands = Arc::clone(&server_commands);
            let server_acks = Arc::clone(&server_acks);
            let consumed_json = consumed_json.clone();
            std::thread::spawn(move || {
                let mut buf = Vec::new();
                let mut tmp = [0u8; 4096];
                // The redis crate invokes scripts by sha: the first
                // sha-addressed invocation misses (no-script), the load
                // command registers the script, and the retried
                // invocation is answered with the scripted Lua reply.
                let mut script_loaded = false;
                loop {
                    match stream.read(&mut tmp) {
                        Ok(0) => return,
                        Ok(n) => {
                            buf.extend_from_slice(&tmp[..n]);
                            while let Some((args, consumed)) = parse_resp_command(&buf) {
                                buf.drain(..consumed);
                                server_commands.lock().unwrap().push(args.clone());
                                let reply = match args[0].as_str() {
                                    "PING" => "+PONG\r\n".to_string(),
                                    "EVALSHA" if !script_loaded => {
                                        "-NOSCRIPT No matching script. Use EVAL.\r\n".to_string()
                                    }
                                    "EVALSHA" => {
                                        let key = args.get(3).map(String::as_str).unwrap_or("");
                                        if key.ends_with("-pending") {
                                            format!(
                                                "*2\r\n${}\r\n{}\r\n:1\r\n",
                                                consumed_json.len(),
                                                consumed_json
                                            )
                                        } else if key.ends_with("-consumed") {
                                            format!(
                                                "*2\r\n${}\r\n{}\r\n:0\r\n",
                                                consumed_json.len(),
                                                consumed_json
                                            )
                                        } else {
                                            "$-1\r\n".to_string()
                                        }
                                    }
                                    "SCRIPT" => {
                                        script_loaded = true;
                                        "+OK\r\n".to_string()
                                    }
                                    "WAIT" => {
                                        let acks = server_acks.load(Ordering::SeqCst);
                                        let n = if acks >= 0 {
                                            acks.to_string()
                                        } else {
                                            args.get(1)
                                                .map(String::as_str)
                                                .unwrap_or("0")
                                                .to_string()
                                        };
                                        format!(":{n}\r\n")
                                    }
                                    _ => "+OK\r\n".to_string(),
                                };
                                stream.write_all(reply.as_bytes()).unwrap();
                            }
                        }
                        Err(_) => return,
                    }
                }
            });
        }
    });

    let url = format!("redis://127.0.0.1:{port}/");
    let barriered = store_for(&url, &prefix("consume-wait")).with_wait(2, 1000);
    // Fresh pending→consumed: the transition mutated the store, so WAIT is
    // issued and the satisfied acknowledgement is accepted.
    let fresh = barriered
        .consume_with_operation_identity("nonce-a-pending", Some("op-a"))
        .unwrap()
        .expect("the fresh transition wins");
    assert!(fresh.first);
    // Consumed-before replay: no mutation, so no wait (a wait here would
    // hang the configured timeout and then fail closed on a 0 ack).
    let replay = barriered
        .consume("nonce-b-consumed")
        .unwrap()
        .expect("the consumed-before replay reads the retained record");
    assert!(!replay.first);
    // Missing: no mutation, no wait.
    assert!(barriered.consume("nonce-c-missing").unwrap().is_none());
    // wait_replicas == 0 disables the barrier even on the fresh transition.
    let unbarriered = store_for(&url, &prefix("consume-nowait"));
    assert!(
        unbarriered
            .consume("nonce-d-pending")
            .unwrap()
            .expect("the unbarriered fresh transition wins")
            .first
    );

    // A violated acknowledgement (fewer than wait_replicas) fails closed
    // on the fresh-transition path with the same durability failure as
    // commit and delete: the transition happened but its durability is
    // unconfirmed.
    wait_acks.store(0, Ordering::SeqCst);
    let barriered2 = store_for(&url, &prefix("consume-wait2")).with_wait(2, 1000);
    let err = barriered2
        .consume("nonce-e-pending")
        .expect_err("a violated replica-wait barrier must fail closed on the fresh transition");
    assert!(
        err.to_string().contains("replica wait not satisfied"),
        "unexpected error: {err}"
    );

    let recorded = commands.lock().unwrap().clone();
    let waits: Vec<&Vec<String>> = recorded.iter().filter(|args| args[0] == "WAIT").collect();
    assert_eq!(
        waits.len(),
        2,
        "WAIT must be issued exactly on the fresh transitions with wait_replicas > 0 (one satisfied, one violated); full command log: {recorded:?}"
    );
    for wait in &waits {
        assert_eq!(wait[1], "2", "WAIT must carry the configured replica count");
        assert_eq!(wait[2], "1000", "WAIT must carry the configured timeout");
    }
}

#[test]
fn cancel_issues_the_verified_wait_only_on_the_fresh_transition() {
    // A miniature Redis-protocol server records every issued command and
    // answers the cancel-transition Lua with the state replies keyed on
    // the nonce, so the WAIT barrier placement is observable: exactly the
    // fresh pending→cancelled flip with wait_replicas > 0 issues WAIT
    // (carrying the configured replica count and timeout, with the acked
    // count verified against the threshold); an already-cancelled replay,
    // a consumed record, a missing key and wait_replicas == 0 never wait —
    // those outcomes leave the stored value untouched, so there is no
    // durability barrier to satisfy. The same server then violates the
    // acknowledgement (fewer acked than configured), and the fresh flip
    // fails closed with the same durability failure the other transitions
    // use. Hermetic: no Redis URL needed.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();

    let commands: Arc<Mutex<Vec<Vec<String>>>> = Arc::new(Mutex::new(Vec::new()));
    // -1 = echo the requested replica count (the wait is satisfied);
    // >= 0 = the ack count to reply (0 violates any configured barrier).
    let wait_acks = Arc::new(AtomicI64::new(-1));
    let server_commands = Arc::clone(&commands);
    let server_acks = Arc::clone(&wait_acks);
    std::thread::spawn(move || {
        use std::io::{Read, Write};
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let server_commands = Arc::clone(&server_commands);
            let server_acks = Arc::clone(&server_acks);
            std::thread::spawn(move || {
                let mut buf = Vec::new();
                let mut tmp = [0u8; 4096];
                // The redis crate invokes scripts by sha: the first
                // sha-addressed invocation misses (no-script), the load
                // command registers the script, and the retried
                // invocation is answered with the scripted Lua reply.
                let mut script_loaded = false;
                loop {
                    match stream.read(&mut tmp) {
                        Ok(0) => return,
                        Ok(n) => {
                            buf.extend_from_slice(&tmp[..n]);
                            while let Some((args, consumed)) = parse_resp_command(&buf) {
                                buf.drain(..consumed);
                                server_commands.lock().unwrap().push(args.clone());
                                let reply = match args[0].as_str() {
                                    "PING" => "+PONG\r\n".to_string(),
                                    "EVALSHA" if !script_loaded => {
                                        "-NOSCRIPT No matching script. Use EVAL.\r\n".to_string()
                                    }
                                    "EVALSHA" => {
                                        let key = args.get(3).map(String::as_str).unwrap_or("");
                                        if key.ends_with("-pending") {
                                            "*1\r\n$13\r\ncancelled-now\r\n".to_string()
                                        } else if key.ends_with("-cancelled") {
                                            "*1\r\n$9\r\ncancelled\r\n".to_string()
                                        } else if key.ends_with("-consumed") {
                                            "*1\r\n$8\r\nconsumed\r\n".to_string()
                                        } else {
                                            "$-1\r\n".to_string()
                                        }
                                    }
                                    "SCRIPT" => {
                                        script_loaded = true;
                                        "+OK\r\n".to_string()
                                    }
                                    "WAIT" => {
                                        let acks = server_acks.load(Ordering::SeqCst);
                                        let n = if acks >= 0 {
                                            acks.to_string()
                                        } else {
                                            args.get(1)
                                                .map(String::as_str)
                                                .unwrap_or("0")
                                                .to_string()
                                        };
                                        format!(":{n}\r\n")
                                    }
                                    _ => "+OK\r\n".to_string(),
                                };
                                stream.write_all(reply.as_bytes()).unwrap();
                            }
                        }
                        Err(_) => return,
                    }
                }
            });
        }
    });

    let url = format!("redis://127.0.0.1:{port}/");
    let barriered = store_for(&url, &prefix("cancel-wait")).with_wait(2, 1000);
    // Fresh pending→cancelled: the flip mutated the store, so WAIT is
    // issued and the satisfied acknowledgement is accepted.
    assert_eq!(
        barriered.cancel("nonce-a-pending").unwrap(),
        Some(CancelResult::CancelledNow)
    );
    // Already-cancelled replay: no mutation, so no wait (a wait here would
    // hang the configured timeout and then fail closed on a 0 ack).
    assert_eq!(
        barriered.cancel("nonce-b-cancelled").unwrap(),
        Some(CancelResult::Cancelled)
    );
    // Consumed: no mutation, no wait.
    assert_eq!(
        barriered.cancel("nonce-c-consumed").unwrap(),
        Some(CancelResult::Consumed)
    );
    // Missing: no mutation, no wait.
    assert!(barriered.cancel("nonce-d-missing").unwrap().is_none());
    // wait_replicas == 0 disables the barrier even on the fresh flip.
    let unbarriered = store_for(&url, &prefix("cancel-nowait"));
    assert_eq!(
        unbarriered.cancel("nonce-e-pending").unwrap(),
        Some(CancelResult::CancelledNow)
    );

    // A violated acknowledgement (fewer than wait_replicas) fails closed
    // on the fresh-flip path with the same durability failure as consume
    // and delete: the flip happened but its durability is unconfirmed.
    wait_acks.store(0, Ordering::SeqCst);
    let barriered2 = store_for(&url, &prefix("cancel-wait2")).with_wait(2, 1000);
    let err = barriered2
        .cancel("nonce-f-pending")
        .expect_err("a violated replica-wait barrier must fail closed on the fresh cancellation");
    assert!(
        err.to_string().contains("replica wait not satisfied"),
        "unexpected error: {err}"
    );

    let recorded = commands.lock().unwrap().clone();
    let waits: Vec<&Vec<String>> = recorded.iter().filter(|args| args[0] == "WAIT").collect();
    assert_eq!(
        waits.len(),
        2,
        "WAIT must be issued exactly on the fresh cancellations with wait_replicas > 0 (one satisfied, one violated); full command log: {recorded:?}"
    );
    for wait in &waits {
        assert_eq!(wait[1], "2", "WAIT must carry the configured replica count");
        assert_eq!(wait[2], "1000", "WAIT must carry the configured timeout");
    }
}

#[test]
fn php_written_cancelled_envelope_reads_as_dead_in_rust() {
    // The reader tolerance: a record whose envelope carries the cancelled
    // marker exactly as the PHP core's cancel transition writes it (the
    // same `"state":"cancelled"` splice, bytes untouched) must behave
    // equivalently on the Rust side — unconsumable, never recoverable,
    // never eagerly deleted, and verification of a genuine solution fails
    // closed as RecordNotFound.
    let Some(url) = redis_url() else { return };
    let prefix = prefix("php-cancelled");
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

    let mut value = serde_json::to_string(&issued.record).unwrap();
    value.truncate(value.len() - 1);
    // The envelope exactly as the PHP cancel Lua splice writes it.
    value
        .push_str(",\"state\":\"cancelled\",\"consumed_result\":null,\"operation_identity\":null}");
    let key = format!("{prefix}{}", issued.record.nonce);
    let mut conn = redis::Client::open(url.clone())
        .unwrap()
        .get_connection()
        .unwrap();
    let _: () = redis::cmd("SET")
        .arg(&key)
        .arg(&value)
        .query(&mut conn)
        .unwrap();

    let store = store_for(&url, &prefix);
    // The state-agnostic peek still reads the retained record (exactly
    // like PHP find()).
    let found = store
        .find(&issued.record.nonce)
        .unwrap()
        .expect("the cancelled record is retained until its TTL");
    assert_eq!(found.nonce, issued.record.nonce);

    // Unconsumable: the consume transition reports it as missing.
    assert!(
        store.consume(&issued.record.nonce).unwrap().is_none(),
        "a PHP-cancelled record is never consumable in Rust"
    );
    // Never recoverable: the consumed-state read never surfaces it.
    assert!(store
        .consumed_state(&issued.record.nonce)
        .unwrap()
        .is_none());
    // Never eagerly deleted: the cleanup keeps the dead record.
    assert!(matches!(
        store.delete_if_pending(&issued.record.nonce).unwrap(),
        DeleteIfPending::Cancelled
    ));
    let raw: String = redis::cmd("GET").arg(&key).query(&mut conn).unwrap();
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&raw).unwrap()["state"],
        "cancelled",
        "the cleanup never deletes a cancelled record"
    );
    // Already-cancelled cancellation is idempotent.
    assert_eq!(
        store.cancel(&issued.record.nonce).unwrap(),
        Some(CancelResult::Cancelled)
    );

    // Never verifiable: a genuine solution fails closed as RecordNotFound.
    let verifier = verifier_for(&url, &prefix);
    assert_eq!(
        verify_at(
            &verifier,
            &encode_token(&issued.record.nonce, counter),
            issued.record.issued_at_ns
        ),
        VerifyOutcome::Invalid(VerifyError::RecordNotFound),
        "a valid token for a PHP-cancelled record fails closed as RecordNotFound"
    );
}

#[test]
fn consumed_before_replay_never_waits_without_replicas() {
    // The consumed-before replay performs no write and therefore no
    // barrier: against a replica-less server with a configured wait, the
    // fresh pending→consumed transition still fails closed (the consumed
    // state must reach the configured replica count before the winner may
    // act on it), but the replay of the already-consumed record — and a
    // missing key — succeed without any wait. A replica outage can never
    // turn an idempotent retry into a failure, and the retained record
    // survives.
    let Some(url) = redis_url() else { return };
    let barrier_prefix = prefix("consume-replay");
    let store = store_for(&url, &barrier_prefix).with_wait(1, 200);

    // Fresh pending→consumed with a violated barrier: the transition
    // executed on the primary, then the wait reported 0 acks and the call
    // failed closed — the consumed state's durability is unconfirmed.
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
    store_for(&url, &barrier_prefix)
        .store(&issued.record)
        .unwrap();
    let err = store.consume(&issued.record.nonce).expect_err(
        "the fresh transition must fail closed when the consumed state is not durably replicated",
    );
    assert!(
        err.to_string().contains("replica wait not satisfied"),
        "unexpected error: {err}"
    );
    // The transition DID land on the primary: the retained consumed
    // record is the replay evidence.
    let key = format!("{barrier_prefix}{}", issued.record.nonce);
    let mut conn = redis::Client::open(url.clone())
        .unwrap()
        .get_connection()
        .unwrap();
    let raw: String = redis::cmd("GET").arg(&key).query(&mut conn).unwrap();
    let stored: serde_json::Value = serde_json::from_str(&raw).unwrap();
    assert_eq!(stored["state"], "consumed");

    // The consumed-before replay performs NO write, so it never waits:
    // it succeeds even though this replica-less server could never
    // satisfy the configured barrier — a replica outage cannot turn the
    // idempotent retry into a failure, and the retained record survives.
    let replay = store
        .consume(&issued.record.nonce)
        .unwrap()
        .expect("the consumed-before replay reads the retained record");
    assert!(!replay.first);
    let replay_identity = store
        .consume_with_operation_identity(&issued.record.nonce, Some("op-replay"))
        .unwrap()
        .expect("the identity-aware replay reads the retained record");
    assert!(!replay_identity.first);

    // Missing: no write, no wait — the call succeeds even though the
    // configured barrier could never be satisfied on this server.
    assert!(store.consume("never-stored-nonce").unwrap().is_none());

    // wait_replicas == 0 disables the barrier entirely: a fresh pending
    // record consumes without any wait.
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
    store_for(&url, &barrier_prefix)
        .store(&issued2.record)
        .unwrap();
    assert!(
        store_for(&url, &barrier_prefix)
            .consume(&issued2.record.nonce)
            .unwrap()
            .expect("a fresh pending record consumes without a barrier")
            .first
    );
}

#[test]
fn ttl_margin_extends_the_redis_ttl_only() {
    // store() uses EX = max(1, expires_at - now + margin). The
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
    // stale record (past expires_at but within the margin) is still rejected
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
    // ProductionVerifier::with_expected_region enforces the
    // region in the cheap phase. A record issued for a different region —
    // or for no region — is rejected with WrongRegion before any consume.
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
    // At the production boundary: with_secrets_by_kid makes the
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
    // The ProductionVerifier outcome carries the canonical nonce
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
    // At the production boundary: url-safe variants and loose
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
        verifier.verify(
            &url_safe,
            "login",
            IP,
            issued_at_ns + 1_000_000,
            None,
            RequestBindingExpectation::Unenforced
        ),
        VerifyOutcome::Invalid(VerifyError::MalformedToken)
    );
    let unpadded = good.trim_end_matches('=');
    assert_eq!(
        verifier.verify(
            unpadded,
            "login",
            IP,
            issued_at_ns + 1_000_000,
            None,
            RequestBindingExpectation::Unenforced
        ),
        VerifyOutcome::Invalid(VerifyError::MalformedToken)
    );
    let loose = format!("{good}=");
    assert_eq!(
        verifier.verify(
            &loose,
            "login",
            IP,
            issued_at_ns + 1_000_000,
            None,
            RequestBindingExpectation::Unenforced
        ),
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

// ── issuer, final re-validation, future-time bound, consumed-state
//    transition, algorithm hard-fail ──

#[test]
fn consumed_state_transition_and_outcome_commit_lifecycle() {
    // At the store level: consume() is a Lua transition that keeps
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
    assert_eq!(stored["consumed_result"], serde_json::Value::Null);

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

    // 5. Committing a pending record is a no-op (0); a binding round-trips.
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
    // At the production boundary: with_expected_issuer enforces
    // the issuer in the cheap phase. A record issued by a different issuer
    // — or by no issuer — is rejected with WrongIssuer before any consume.
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
    // At the production boundary: a challenge whose issued_at is
    // more than the clock-skew bound (60 s) ahead of the verifier clock is
    // a time-domain anomaly — the cheap TTL phase rejects it with Expired.
    // The verifier's clock is injected (the PHP `$now` override equivalent)
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
            issued.record.issued_at_ns + 1_000_000,
            None,
            RequestBindingExpectation::Unenforced
        ),
        VerifyOutcome::Invalid(VerifyError::Expired),
        "a future-issued challenge beyond the clock skew must be rejected"
    );
}

#[test]
fn unknown_algorithm_variants_in_stored_records_are_record_not_found() {
    // At the production boundary: a stored record with an unknown
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
                now_micros(),
                None,
                RequestBindingExpectation::Unenforced
            ),
            VerifyOutcome::Invalid(VerifyError::RecordNotFound),
            "algorithm {algo:?} must be undecodable (RecordNotFound), like PHP"
        );
    }
}

// ── revocation, allocation-after-length, no-script recovery ──

#[test]
fn revoked_kid_is_rejected_before_signature_checks() {
    // At the production boundary: with_revoked_kids rejects the
    // record in the cheap phase with UnknownKid — before the signature
    // check — even when the kid's secret is present in secrets_by_kid:
    // compromise revocation overrides the rotation grace. An unrevoked kid
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

    // Perfectly signed, secret present, kid revoked → UnknownKid.
    let revoking = verifier_for(&url, &prefix)
        .with_secrets_by_kid([(2, key_b.to_string())])
        .with_revoked_kids([2]);
    revoking.store().store(&issued.record).unwrap();
    assert_eq!(
        verify_at(&revoking, &token, issued_at_ns),
        VerifyOutcome::Invalid(VerifyError::UnknownKid),
        "a revoked kid must be rejected even with its secret present"
    );

    // Same record, a different kid revoked → the unrevoked kid verifies.
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
    // At the production boundary: a 10 MB attacker-written value
    // under the nonce key is rejected by the stored-record length cap before
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
            now_micros(),
            None,
            RequestBindingExpectation::Unenforced
        ),
        VerifyOutcome::Invalid(VerifyError::RecordNotFound),
        "a 10 MB stored value must be rejected at parse (RecordNotFound), like any corrupt key"
    );
}

#[test]
fn script_flush_is_recovered_deterministically() {
    // The redis crate's Script invoke() handles a no-script error by
    // re-loading the script text (invoke → no-script → load → invoke), so
    // a script-cache flush cannot break verification: the record is
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

    // Wipe the server-side script cache: both Lua scripts are now unloaded
    // (the consume transition AND the outcome commit).
    let _: () = redis::cmd("SCRIPT").arg("FLUSH").query(&mut conn).unwrap();

    // The first verify after the flush re-loads the scripts on a no-script
    // error and proceeds normally: the full consume → derive → commit
    // lifecycle works.
    assert!(
        matches!(
            verify_at(&verifier, &token, issued_at_ns),
            VerifyOutcome::Valid { .. }
        ),
        "NOSCRIPT must be recovered by re-loading — the verification proceeds normally"
    );

    // The record is NOT burned: it still exists with the consumed state and
    // the committed outcome, and a replay resolves through the identity
    // gate — even after another flush (the replayed consume re-loads the
    // script again, finds the retained consumed state, and the no-identity
    // caller is refused with AlreadyConsumed, never RecordNotFound).
    let _: () = redis::cmd("SCRIPT").arg("FLUSH").query(&mut conn).unwrap();
    assert_eq!(
        verify_at(&verifier, &token, issued_at_ns),
        VerifyOutcome::Invalid(VerifyError::AlreadyConsumed),
        "a replay after a second flush re-loads the consume script and resolves through the identity gate"
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

#[test]
fn security_failures_win_on_matching_identity_replay_and_keep_the_evidence() {
    // The parallel security-failure replay matrix: every hard security
    // verdict — wrong scope, a changed expected request binding, a wrong
    // region, a wrong issuer, a revoked kid — wins on a matching-identity
    // replay of a consumed record (the identity-gated replay exemption
    // never overrides it), and the consumed record survives with its
    // committed valid result and the recorded operation identity intact.
    let Some(url) = redis_url() else { return };

    // (label, replay-verifier factory, replay call) — each scenario gets
    // a freshly issued + solved challenge consumed under op-x, then the
    // replay presents the same identity with a failing expectation.
    type MakeVerifier = fn(&str, &str) -> ProductionVerifier;
    type ReplayCall = fn(&ProductionVerifier, &str, u64) -> VerifyOutcome;
    let scenarios: [(&str, MakeVerifier, ReplayCall); 5] = [
        (
            "wrong scope",
            |url, prefix| verifier_for(url, prefix),
            |v, token, issued_at_ns| {
                v.verify(
                    token,
                    "signup",
                    IP,
                    issued_at_ns + 1_000_000,
                    Some("op-x"),
                    RequestBindingExpectation::Unenforced,
                )
            },
        ),
        (
            "changed expected request binding",
            |url, prefix| verifier_for(url, prefix),
            |v, token, issued_at_ns| {
                v.verify(
                    token,
                    "login",
                    IP,
                    issued_at_ns + 1_000_000,
                    Some("op-x"),
                    RequestBindingExpectation::Exact(Some("txn-OTHER")),
                )
            },
        ),
        (
            "wrong region",
            |url, prefix| verifier_for(url, prefix).with_expected_region("eu"),
            |v, token, issued_at_ns| {
                v.verify(
                    token,
                    "login",
                    IP,
                    issued_at_ns + 1_000_000,
                    Some("op-x"),
                    RequestBindingExpectation::Unenforced,
                )
            },
        ),
        (
            "wrong issuer",
            |url, prefix| verifier_for(url, prefix).with_expected_issuer("prod"),
            |v, token, issued_at_ns| {
                v.verify(
                    token,
                    "login",
                    IP,
                    issued_at_ns + 1_000_000,
                    Some("op-x"),
                    RequestBindingExpectation::Unenforced,
                )
            },
        ),
        (
            "revoked kid",
            |url, prefix| verifier_for(url, prefix).with_revoked_kids([1]),
            |v, token, issued_at_ns| {
                v.verify(
                    token,
                    "login",
                    IP,
                    issued_at_ns + 1_000_000,
                    Some("op-x"),
                    RequestBindingExpectation::Unenforced,
                )
            },
        ),
    ];

    for (label, make_verifier, replay_call) in scenarios {
        let prefix = prefix("secfail");
        let issued = issue_challenge(
            &sha_config(4),
            "login",
            IP,
            now_unix(),
            now_micros(),
            0,
            Some("txn-123"),
        )
        .unwrap();
        let counter = solve_for_test(&issued.record).expect("4-bit sha solves");
        let token = encode_token(&issued.record.nonce, counter);
        let issued_at_ns = issued.record.issued_at_ns;

        let verifier = verifier_for(&url, &prefix);
        verifier.store().store(&issued.record).unwrap();
        assert!(
            matches!(
                verify_with(
                    &verifier,
                    &token,
                    issued_at_ns,
                    Some("op-x"),
                    RequestBindingExpectation::Exact(Some("txn-123"))
                ),
                VerifyOutcome::Valid { .. }
            ),
            "{label}: setup — the bound fresh verification succeeds"
        );

        let replay_verifier = make_verifier(&url, &prefix);
        let outcome = replay_call(&replay_verifier, &token, issued_at_ns);
        let expected = match label {
            "wrong scope" => VerifyError::WrongScope,
            "changed expected request binding" => VerifyError::RequestBindingMismatch,
            "wrong region" => VerifyError::WrongRegion,
            "wrong issuer" => VerifyError::WrongIssuer,
            _ => VerifyError::UnknownKid,
        };
        assert_eq!(
            outcome,
            VerifyOutcome::Invalid(expected),
            "{label}: the security failure wins over the matching-identity replay"
        );

        // The consumed evidence survives the refusal: the record is kept
        // (never deleted), still consumed, with the committed valid
        // result and the recorded operation identity intact.
        let key = format!("{prefix}{}", issued.record.nonce);
        let mut conn = redis::Client::open(url.clone())
            .unwrap()
            .get_connection()
            .unwrap();
        let raw: Option<String> = redis::cmd("GET").arg(&key).query(&mut conn).unwrap();
        let stored: serde_json::Value = serde_json::from_str(
            &raw.expect("the consumed record is never deleted by a hard security failure"),
        )
        .unwrap();
        assert_eq!(
            stored["state"], "consumed",
            "{label}: the record stays consumed"
        );
        assert_eq!(
            stored["consumed_result"]["valid"], true,
            "{label}: the committed valid result survives"
        );
        assert_eq!(
            stored["operation_identity"], "op-x",
            "{label}: the recorded operation identity survives"
        );
    }
}

#[test]
fn exempt_timing_failures_still_resolve_through_the_identity_gate() {
    // The exempt counterparts: expiry and the IP mismatch describe the
    // original redemption's circumstances, so a matching-identity replay
    // resolves through the consumed branch despite them (the stored
    // success replays), and the record survives.
    let Some(url) = redis_url() else { return };

    for (label, changed_ip, advance_secs) in [("expiry", false, 600u64), ("ip mismatch", true, 0)] {
        let prefix = prefix("exempt");
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
        assert!(
            matches!(
                verify_with(
                    &verifier,
                    &token,
                    issued_at_ns,
                    Some("op-e"),
                    RequestBindingExpectation::Unenforced
                ),
                VerifyOutcome::Valid { .. }
            ),
            "{label}: setup — the fresh verification succeeds"
        );

        // Expiry: the TTL window (120 s) has passed at the replay
        // receipt. IP mismatch: the same receipt, another address.
        let receipt = issued_at_ns + advance_secs * 1_000_000_000 + 1_000_000;
        let replay_ip = if changed_ip { "203.0.113.9" } else { IP };
        assert!(
            matches!(
                verifier.verify(
                    &token,
                    "login",
                    replay_ip,
                    receipt,
                    Some("op-e"),
                    RequestBindingExpectation::Unenforced
                ),
                VerifyOutcome::Valid {
                    from_stored_result: true,
                    ..
                }
            ),
            "{label}: the identity-proven replay resolves through the consumed branch"
        );

        let key = format!("{prefix}{}", issued.record.nonce);
        let mut conn = redis::Client::open(url.clone())
            .unwrap()
            .get_connection()
            .unwrap();
        let raw: String = redis::cmd("GET").arg(&key).query(&mut conn).unwrap();
        let stored: serde_json::Value = serde_json::from_str(&raw).unwrap();
        assert_eq!(stored["state"], "consumed", "{label}: the record survives");
        assert_eq!(stored["consumed_result"]["valid"], true);
    }
}

#[test]
fn delete_if_pending_is_the_atomic_tri_state() {
    // The fused cleanup transition: a pending record is deleted
    // atomically, a consumed record is kept untouched and its retained
    // state rides back, a missing key reports missing.
    let Some(url) = redis_url() else { return };
    let prefix = prefix("delpend");
    let store = store_for(&url, &prefix);
    let mut conn = redis::Client::open(url.clone())
        .unwrap()
        .get_connection()
        .unwrap();

    // missing (a nonce that was never stored)
    assert!(matches!(
        store.delete_if_pending("never-stored-nonce").unwrap(),
        DeleteIfPending::Missing
    ));

    // pending -> deleted, key gone
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
    store.store(&issued.record).unwrap();
    let key = format!("{prefix}{}", issued.record.nonce);
    assert!(matches!(
        store.delete_if_pending(&issued.record.nonce).unwrap(),
        DeleteIfPending::DeletedPending
    ));
    let raw: Option<String> = redis::cmd("GET").arg(&key).query(&mut conn).unwrap();
    assert!(raw.is_none(), "the pending record is deleted");

    // consumed -> kept, retained state returned
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
    store.store(&issued.record).unwrap();
    let key = format!("{prefix}{}", issued.record.nonce);
    let consumed = store
        .consume_with_operation_identity(&issued.record.nonce, Some("op-d"))
        .unwrap()
        .expect("the transition wins");
    assert!(consumed.first);
    store
        .commit_result(&issued.record.nonce, true, Some("txn"))
        .unwrap();
    match store.delete_if_pending(&issued.record.nonce).unwrap() {
        DeleteIfPending::Consumed(state) => {
            assert!(state.stored_result.expect("committed").valid);
            assert_eq!(state.operation_identity.as_deref(), Some("op-d"));
        }
        other => panic!("consumed record must be kept, got {other:?}"),
    }
    let raw: String = redis::cmd("GET").arg(&key).query(&mut conn).unwrap();
    let stored: serde_json::Value = serde_json::from_str(&raw).unwrap();
    assert_eq!(stored["state"], "consumed", "the consumed record survives");
}

#[test]
fn delete_if_pending_race_never_erases_committed_evidence() {
    // The check-then-delete window the fused transition closes, run as a real barrier
    // race in the audit's shape: thread A (the cheap-failing verifier)
    // pauses right before its cleanup while thread B consumes + commits
    // Valid; A then resumes. The barrier enforces B's ordering, and the
    // stagger after B's completion varies the gap (0..400 µs) so the
    // cleanup races the commit's visibility at different distances.
    // Whatever the gap, A must observe the consumed state and refuse
    // the delete — the committed evidence is never erased.
    let Some(url) = redis_url() else { return };

    let staggers = [0u64, 1, 50, 400];
    for run in 0..20u32 {
        let i = run % staggers.len() as u32;
        let stagger = staggers[i as usize];
        let prefix = prefix("delpend-race");
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
        let nonce = issued.record.nonce.clone();
        let key = format!("{prefix}{nonce}");
        let store = store_for(&url, &prefix);
        store.store(&issued.record).unwrap();
        drop(store);

        let barrier = Arc::new(Barrier::new(2));
        let b_done = Arc::new(AtomicU64::new(0));
        let b = {
            let url = url.clone();
            let prefix = prefix.clone();
            let barrier = Arc::clone(&barrier);
            let done = Arc::clone(&b_done);
            let nonce = nonce.clone();
            thread::spawn(move || {
                barrier.wait();
                let store = store_for(&url, &prefix);
                let consumed = store
                    .consume_with_operation_identity(&nonce, Some("op-race"))
                    .unwrap()
                    .expect("B wins the transition (it completes before A resumes)");
                assert!(consumed.first);
                assert!(store.commit_result(&nonce, true, Some("txn")).unwrap());
                done.store(1, Ordering::SeqCst);
            })
        };
        let a = {
            let url = url.clone();
            let prefix = prefix.clone();
            let barrier = Arc::clone(&barrier);
            let done = Arc::clone(&b_done);
            let nonce = nonce.clone();
            thread::spawn(move || {
                // A has cheap-failed and pauses at the barrier; it
                // resumes only once B's consume + commit landed, with a
                // varied stagger shrinking the gap to the commit.
                barrier.wait();
                while done.load(Ordering::SeqCst) == 0 {
                    thread::yield_now();
                }
                if stagger > 0 {
                    thread::sleep(std::time::Duration::from_micros(stagger));
                }
                let store = store_for(&url, &prefix);
                store.delete_if_pending(&nonce).unwrap()
            })
        };

        b.join().unwrap();
        match a.join().unwrap() {
            DeleteIfPending::Consumed(state) => {
                if let Some(result) = state.stored_result {
                    assert!(
                        result.valid,
                        "run {run}: an observed committed result is the valid outcome"
                    );
                }
                assert_eq!(
                    state.operation_identity.as_deref(),
                    Some("op-race"),
                    "run {run}: the recorded identity is intact"
                );
            }
            other => panic!("run {run}: committed evidence erased, got {other:?}"),
        }

        let mut conn = redis::Client::open(url.clone())
            .unwrap()
            .get_connection()
            .unwrap();
        let raw: String = redis::cmd("GET").arg(&key).query(&mut conn).unwrap();
        let stored: serde_json::Value = serde_json::from_str(&raw).unwrap();
        assert_eq!(stored["state"], "consumed", "run {run}: the record is kept");
        assert_eq!(stored["consumed_result"]["valid"], true);
        assert_eq!(stored["operation_identity"], "op-race");
        let _: () = redis::cmd("DEL").arg(&key).query(&mut conn).unwrap();
    }
}

/// Deterministic verifier clock for the compositional replay-precedence
/// tests: a fixed mutable second, so the expiry cases never race the
/// wall clock.
static FAKE_REPLAY_NOW: AtomicU64 = AtomicU64::new(0);

fn fake_replay_now() -> u64 {
    FAKE_REPLAY_NOW.load(Ordering::SeqCst)
}

/// One consumed record with a committed valid outcome and a recorded
/// operation identity — the retained evidence a replay resolves against.
/// Returns (nonce, token, issued_at_ns).
fn consumed_committed_record(
    url: &str,
    prefix: &str,
    min_duration_ms: u64,
) -> (String, String, u64) {
    let mut config = sha_config(4);
    if min_duration_ms > 0 {
        config.min_duration_ms = Some(min_duration_ms);
    }
    let issued = issue_challenge(
        &config,
        "login",
        IP,
        now_unix(),
        now_micros(),
        0,
        Some("txn-123"),
    )
    .unwrap();
    let counter = solve_for_test(&issued.record).expect("4-bit sha solves");
    let token = encode_token(&issued.record.nonce, counter);
    let issued_at_ns = issued.record.issued_at_ns;

    let store = store_for(url, prefix);
    store.store(&issued.record).unwrap();
    let consumed = store
        .consume_with_operation_identity(&issued.record.nonce, Some("op-replay"))
        .unwrap()
        .expect("pending record consumes");
    assert!(consumed.first);
    store
        .commit_result(&issued.record.nonce, true, None)
        .unwrap();

    (issued.record.nonce.clone(), token, issued_at_ns)
}

/// Asserts the retained-evidence contract after a hard-wins replay: the
/// record still exists, is consumed, its committed valid result and its
/// recorded operation identity are intact.
fn assert_replay_evidence_intact(url: &str, prefix: &str, nonce: &str) {
    let key = format!("{prefix}{nonce}");
    let mut conn = redis::Client::open(url.to_string())
        .unwrap()
        .get_connection()
        .unwrap();
    let raw: Option<String> = redis::cmd("GET").arg(&key).query(&mut conn).unwrap();
    let raw = raw.expect("the consumed record is NEVER deleted by the hard verdict");
    let stored: serde_json::Value = serde_json::from_str(&raw).unwrap();
    assert_eq!(stored["state"], "consumed", "the record is still consumed");
    assert_eq!(
        stored["consumed_result"]["valid"], true,
        "the committed valid result survives intact"
    );
    assert_eq!(
        stored["operation_identity"], "op-replay",
        "the recorded operation identity survives intact"
    );
}

#[test]
fn exempt_cheap_failure_never_masks_a_hard_verdict_on_a_consumed_replay() {
    // Compositional replay precedence: a replay of a consumed record that
    // fails an exempt circumstance (the expiry, the IP binding) may never
    // replay the stored success around a hard verdict that also applies
    // to the same request. The cheap phase returns the first failing
    // check only and the expiry sits early in the order, so every
    // hard invariant below it must be re-evaluated before the exempt
    // failure may route into the identity-gated consumed branch. The
    // IP binding sits before the minimum-duration floor, so the floor is
    // re-evaluated too. (The production verifier takes a required
    // client IP, so the missing-IP exemption has no Rust matrix entry;
    // telemetry is not gated in this verifier either.)
    let Some(url) = redis_url() else { return };

    struct Case {
        label: &'static str,
        // (scope, client_ip, expected_request_binding) for the replay call
        scope: &'static str,
        client_ip: &'static str,
        expected_request_binding: RequestBindingExpectation<'static>,
        // now offset for the replay receipt: None = +1s, Some(s) = +s
        receipt_offset_s: u64,
        expiry_clock: bool,
        region: Option<&'static str>,
        policy_version: Option<u32>,
        issuer: Option<&'static str>,
        min_duration_ms: u64,
        expected: VerifyError,
    }

    let cases = [
        // The expiry masks every hard invariant below it in check order.
        Case {
            label: "expired + wrong scope",
            scope: "signup",
            client_ip: IP,
            expected_request_binding: RequestBindingExpectation::Unenforced,
            receipt_offset_s: 1,
            expiry_clock: true,
            region: None,
            policy_version: None,
            issuer: None,
            min_duration_ms: 0,
            expected: VerifyError::WrongScope,
        },
        Case {
            label: "expired + request binding mismatch",
            scope: "login",
            client_ip: IP,
            expected_request_binding: RequestBindingExpectation::Exact(Some("txn-OTHER")),
            receipt_offset_s: 1,
            expiry_clock: true,
            region: None,
            policy_version: None,
            issuer: None,
            min_duration_ms: 0,
            expected: VerifyError::RequestBindingMismatch,
        },
        Case {
            label: "expired + wrong region",
            scope: "login",
            client_ip: IP,
            expected_request_binding: RequestBindingExpectation::Exact(Some("txn-123")),
            receipt_offset_s: 1,
            expiry_clock: true,
            region: Some("eu"),
            policy_version: None,
            issuer: None,
            min_duration_ms: 0,
            expected: VerifyError::WrongRegion,
        },
        Case {
            label: "expired + wrong policy epoch",
            scope: "login",
            client_ip: IP,
            expected_request_binding: RequestBindingExpectation::Exact(Some("txn-123")),
            receipt_offset_s: 1,
            expiry_clock: true,
            region: None,
            policy_version: Some(2),
            issuer: None,
            min_duration_ms: 0,
            expected: VerifyError::WrongPolicyVersion,
        },
        Case {
            label: "expired + wrong issuer",
            scope: "login",
            client_ip: IP,
            expected_request_binding: RequestBindingExpectation::Exact(Some("txn-123")),
            receipt_offset_s: 1,
            expiry_clock: true,
            region: None,
            policy_version: None,
            issuer: Some("prod"),
            min_duration_ms: 0,
            expected: VerifyError::WrongIssuer,
        },
        // The IP binding masks the minimum-duration floor (checked after it).
        Case {
            label: "ip mismatch + minimum-duration floor",
            scope: "login",
            client_ip: "203.0.113.9",
            expected_request_binding: RequestBindingExpectation::Exact(Some("txn-123")),
            receipt_offset_s: 1,
            expiry_clock: false,
            region: None,
            policy_version: None,
            issuer: None,
            min_duration_ms: 110_000,
            expected: VerifyError::TooFast,
        },
        // Region precedes the IP binding in check order: the pin that the
        // hard verdict earlier in the order keeps winning outright.
        Case {
            label: "ip mismatch behind wrong region (order pin)",
            scope: "login",
            client_ip: "203.0.113.9",
            expected_request_binding: RequestBindingExpectation::Exact(Some("txn-123")),
            receipt_offset_s: 1,
            expiry_clock: false,
            region: Some("eu"),
            policy_version: None,
            issuer: None,
            min_duration_ms: 0,
            expected: VerifyError::WrongRegion,
        },
    ];

    for case in cases {
        let prefix = prefix("replay-precedence");
        let (nonce, token, issued_at_ns) =
            consumed_committed_record(&url, &prefix, case.min_duration_ms);

        let receipt_ns = issued_at_ns + case.receipt_offset_s * 1_000_000;
        let verifier = if case.expiry_clock {
            FAKE_REPLAY_NOW.store(now_unix() + 300, Ordering::SeqCst);
            verifier_for(&url, &prefix).with_now_fn(fake_replay_now)
        } else {
            verifier_for(&url, &prefix)
        };
        let verifier = match case.region {
            Some(region) => verifier.with_expected_region(region),
            None => verifier,
        };
        let verifier = match case.policy_version {
            Some(version) => verifier.with_expected_policy_version(version),
            None => verifier,
        };
        let verifier = match case.issuer {
            Some(issuer) => verifier.with_expected_issuer(issuer),
            None => verifier,
        };

        let outcome = verifier.verify(
            &token,
            case.scope,
            case.client_ip,
            receipt_ns,
            Some("op-replay"),
            case.expected_request_binding,
        );
        assert_eq!(
            outcome,
            VerifyOutcome::Invalid(case.expected),
            "{}: the hard verdict must win over the exempt circumstance",
            case.label
        );
        assert_replay_evidence_intact(&url, &prefix, &nonce);
    }
}

#[test]
fn exempt_circumstance_alone_still_replays_the_stored_success() {
    // The balance: a retry failing only the exempt circumstance, with the
    // exact matching operation identity, still replays the committed
    // success — the idempotent-retry contract must not regress.
    let Some(url) = redis_url() else { return };

    for (label, client_ip) in [("expired alone", IP), ("ip mismatch alone", "203.0.113.9")] {
        let expired = label.starts_with("expired");
        let prefix = prefix("replay-exempt-alone");
        let (nonce, token, issued_at_ns) = consumed_committed_record(&url, &prefix, 0);

        let verifier = if expired {
            FAKE_REPLAY_NOW.store(now_unix() + 300, Ordering::SeqCst);
            verifier_for(&url, &prefix).with_now_fn(fake_replay_now)
        } else {
            verifier_for(&url, &prefix)
        };
        assert_eq!(
            verifier.verify(
                &token,
                "login",
                client_ip,
                issued_at_ns + 1_000_000,
                Some("op-replay"),
                RequestBindingExpectation::Exact(Some("txn-123")),
            ),
            VerifyOutcome::Valid {
                nonce: nonce.clone(),
                request_binding: None,
                from_stored_result: true,
            },
            "{label}: the identity-proven retry replays the stored success"
        );
        assert_replay_evidence_intact(&url, &prefix, &nonce);
    }
}

#[test]
fn fresh_challenges_keep_the_first_error_precedence() {
    // The replay-security re-evaluation exists only on the consumed
    // branch: a fresh (pending) challenge keeps the documented first-error
    // order — an expired token still reports Expired even when a hard
    // invariant would also fail.
    let Some(url) = redis_url() else { return };
    let prefix = prefix("fresh-precedence");
    let issued = issue_challenge(
        &sha_config(4),
        "login",
        IP,
        now_unix(),
        now_micros(),
        0,
        Some("txn-123"),
    )
    .unwrap();
    let counter = solve_for_test(&issued.record).expect("4-bit sha solves");
    let token = encode_token(&issued.record.nonce, counter);
    let issued_at_ns = issued.record.issued_at_ns;
    store_for(&url, &prefix).store(&issued.record).unwrap();

    FAKE_REPLAY_NOW.store(now_unix() + 300, Ordering::SeqCst);
    let verifier = verifier_for(&url, &prefix)
        .with_now_fn(fake_replay_now)
        .with_expected_region("eu")
        .with_expected_policy_version(2)
        .with_expected_issuer("prod");
    assert_eq!(
        verifier.verify(
            &token,
            "signup",
            IP,
            issued_at_ns + 1_000_000,
            Some("op-replay"),
            RequestBindingExpectation::Exact(Some("txn-OTHER")),
        ),
        VerifyOutcome::Invalid(VerifyError::Expired),
        "the fresh path keeps the first-error precedence: Expired wins"
    );
}
#[test]
fn resume_rejects_an_emergency_revoked_key() {
    // The recovery is never a weaker verification mode: an
    // emergency-revoked kid rejects the resume exactly like a fresh
    // verification (the full cheap phase reruns the revoked/future
    // key guard before any derivation).
    let Some(url) = redis_url() else { return };
    let prefix = format!("kiwitest:resume-revoked:{}:", std::process::id());
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
    let identity = "logical-op-resume-revoked";
    let token = encode_token(
        &issued.record.nonce,
        solve_for_test(&issued.record).expect("4-bit sha solves"),
    );
    let issued_at_ns = issued.record.issued_at_ns;

    let store = RedisChallengeStore::new(redis::Client::open(url.clone()).unwrap(), prefix.clone());
    store.store(&issued.record).unwrap();
    assert!(store
        .consume_with_operation_identity(&issued.record.nonce, Some(identity))
        .unwrap()
        .is_some());

    let verifier = ProductionVerifier::new(
        RedisChallengeStore::new(redis::Client::open(url.clone()).unwrap(), prefix.clone()),
        SECRET,
    )
    .with_revoked_kids([issued.record.kid]);
    let outcome = verifier.resume_consumed_operation(
        &token,
        identity,
        "login",
        IP,
        issued_at_ns + 1_000_000,
        RequestBindingExpectation::Unenforced,
    );
    assert!(
        matches!(outcome, VerifyOutcome::Invalid(VerifyError::UnknownKid)),
        "an emergency-revoked key rejects the recovery: {outcome:?}"
    );
}

#[test]
fn resume_rejects_a_bumped_policy_epoch() {
    // A policy-epoch bump between the consume and the retry rejects
    // the recovery exactly like a fresh verification (the deployment
    // expectations rerun inside the cheap phase).
    let Some(url) = redis_url() else { return };
    let prefix = format!("kiwitest:resume-policy:{}:", std::process::id());
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
    let identity = "logical-op-resume-policy";
    let token = encode_token(
        &issued.record.nonce,
        solve_for_test(&issued.record).expect("4-bit sha solves"),
    );
    let issued_at_ns = issued.record.issued_at_ns;

    let store = RedisChallengeStore::new(redis::Client::open(url.clone()).unwrap(), prefix.clone());
    store.store(&issued.record).unwrap();
    assert!(store
        .consume_with_operation_identity(&issued.record.nonce, Some(identity))
        .unwrap()
        .is_some());

    let verifier = ProductionVerifier::new(
        RedisChallengeStore::new(redis::Client::open(url.clone()).unwrap(), prefix.clone()),
        SECRET,
    )
    .with_expected_policy_version(issued.record.policy_version + 1);
    let outcome = verifier.resume_consumed_operation(
        &token,
        identity,
        "login",
        IP,
        issued_at_ns + 1_000_000,
        RequestBindingExpectation::Unenforced,
    );
    assert!(
        matches!(
            outcome,
            VerifyOutcome::Invalid(VerifyError::WrongPolicyVersion)
        ),
        "a bumped policy epoch rejects the recovery: {outcome:?}"
    );
}

#[test]
fn resume_resolves_an_already_completed_record_without_redriving() {
    // Stored result first: an already-completed consumed record
    // resolves through the identity-gated, replication-fenced
    // stored-result path — the recovery never re-derives a committed
    // outcome, and the Argon admission gate is never touched.
    let Some(url) = redis_url() else { return };
    let prefix = format!("kiwitest:resume-completed:{}:", std::process::id());
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
    let identity = "logical-op-resume-completed";
    let token = encode_token(
        &issued.record.nonce,
        solve_for_test(&issued.record).expect("4-bit sha solves"),
    );
    let issued_at_ns = issued.record.issued_at_ns;

    let store = RedisChallengeStore::new(redis::Client::open(url.clone()).unwrap(), prefix.clone());
    store.store(&issued.record).unwrap();
    assert!(store
        .consume_with_operation_identity(&issued.record.nonce, Some(identity))
        .unwrap()
        .is_some());
    store
        .commit_result(
            &issued.record.nonce,
            true,
            issued.record.request_binding.as_deref(),
        )
        .unwrap();

    let gate = CountingGate {
        active: Arc::new(AtomicUsize::new(0)),
        acquired: Arc::new(AtomicUsize::new(0)),
        released: Arc::new(AtomicUsize::new(0)),
        accept: true,
    };
    let acquired = gate.acquired.clone();
    let outcome = ProductionVerifier::new(
        RedisChallengeStore::new(redis::Client::open(url.clone()).unwrap(), prefix.clone()),
        SECRET,
    )
    .with_argon_gate(gate)
    .resume_consumed_operation(
        &token,
        identity,
        "login",
        IP,
        issued_at_ns + 1_000_000,
        RequestBindingExpectation::Unenforced,
    );
    assert!(
        matches!(
            outcome,
            VerifyOutcome::Valid {
                from_stored_result: true,
                ..
            }
        ),
        "the completed record resolves through the stored-result path: {outcome:?}"
    );
    assert_eq!(
        acquired.load(Ordering::SeqCst),
        0,
        "no re-derivation: the Argon admission gate is never touched for a completed record"
    );
}

#[test]
fn resume_applies_the_argon_admission_gate() {
    // The recovery must not bypass the memory-hard verification
    // protections: a refused capacity lease answers
    // CapacityExceeded, never a re-derived Valid.
    let Some(url) = redis_url() else { return };
    let prefix = format!("kiwitest:resume-gate:{}:", std::process::id());
    let issued = issue_challenge(
        &argon_config(2),
        "login",
        IP,
        now_unix(),
        now_micros(),
        0,
        None,
    )
    .unwrap();
    let identity = "logical-op-resume-gate";
    let counter = solve_for_test(&issued.record).expect("2-bit argon solves");
    let token = encode_token(&issued.record.nonce, counter);
    let issued_at_ns = issued.record.issued_at_ns;

    let store = RedisChallengeStore::new(redis::Client::open(url.clone()).unwrap(), prefix.clone());
    store.store(&issued.record).unwrap();
    assert!(store
        .consume_with_operation_identity(&issued.record.nonce, Some(identity))
        .unwrap()
        .is_some());

    let verifier = ProductionVerifier::new(
        RedisChallengeStore::new(redis::Client::open(url.clone()).unwrap(), prefix.clone()),
        SECRET,
    )
    .with_argon_gate(BoolGate(false));
    let outcome = verifier.resume_consumed_operation(
        &token,
        identity,
        "login",
        IP,
        issued_at_ns + 1_000_000,
        RequestBindingExpectation::Unenforced,
    );
    assert!(
        matches!(
            outcome,
            VerifyOutcome::Invalid(VerifyError::CapacityExceeded)
        ),
        "a refused capacity lease answers CapacityExceeded: {outcome:?}"
    );
}

#[test]
fn resume_derivation_is_serialized_by_the_atomic_claim() {
    // The atomic re-derivation claim: exactly one concurrent
    // same-operation recovery derives. The first resume acquires the
    // claim + the admission lease and commits; the second resume
    // resolves the committed outcome through the stored-result path
    // and never re-acquires the Argon capacity.
    let Some(url) = redis_url() else { return };
    let prefix = format!("kiwitest:resume-serialized:{}:", std::process::id());
    let issued = issue_challenge(
        &argon_config(2),
        "login",
        IP,
        now_unix(),
        now_micros(),
        0,
        None,
    )
    .unwrap();
    let identity = "logical-op-resume-serialized";
    let counter = solve_for_test(&issued.record).expect("2-bit argon solves");
    let token = encode_token(&issued.record.nonce, counter);
    let issued_at_ns = issued.record.issued_at_ns;

    let store = RedisChallengeStore::new(redis::Client::open(url.clone()).unwrap(), prefix.clone());
    store.store(&issued.record).unwrap();
    assert!(store
        .consume_with_operation_identity(&issued.record.nonce, Some(identity))
        .unwrap()
        .is_some());

    let gate = CountingGate {
        active: Arc::new(AtomicUsize::new(0)),
        acquired: Arc::new(AtomicUsize::new(0)),
        released: Arc::new(AtomicUsize::new(0)),
        accept: true,
    };
    let acquired = gate.acquired.clone();
    let verifier = ProductionVerifier::new(
        RedisChallengeStore::new(redis::Client::open(url.clone()).unwrap(), prefix.clone()),
        SECRET,
    )
    .with_argon_gate(gate);

    let first = verifier.resume_consumed_operation(
        &token,
        identity,
        "login",
        IP,
        issued_at_ns + 1_000_000,
        RequestBindingExpectation::Unenforced,
    );
    assert!(
        matches!(first, VerifyOutcome::Valid { .. }),
        "the first resume derives and commits: {first:?}"
    );

    let second = verifier.resume_consumed_operation(
        &token,
        identity,
        "login",
        IP,
        issued_at_ns + 1_000_000,
        RequestBindingExpectation::Unenforced,
    );
    assert!(
        matches!(
            second,
            VerifyOutcome::Valid {
                from_stored_result: true,
                ..
            }
        ),
        "the second resume resolves the committed outcome without re-deriving: {second:?}"
    );
    assert_eq!(
            acquired.load(Ordering::SeqCst),
            1,
            "exactly one Argon acquisition across both resumes — the claim serialized the re-derivation"
        );
}

#[test]
fn resume_loser_with_a_pre_held_claim_never_acquires_argon_capacity() {
    // Round-93 audit: the claim comes first, before the Argon admission
    // gate. A second recovery racing an already-held claim must lose at
    // the claim and answer ConsumeIndeterminate (the resultless reread)
    // while never acquiring an Argon capacity slot; only after the
    // first recovery releases the claim does a resume acquire exactly
    // one admission slot.
    let Some(url) = redis_url() else { return };
    let prefix = format!("kiwitest:resume-preheld:{}:", std::process::id());
    let issued = issue_challenge(
        &argon_config(2),
        "login",
        IP,
        now_unix(),
        now_micros(),
        0,
        None,
    )
    .unwrap();
    let identity = "logical-op-resume-preheld";
    let counter = solve_for_test(&issued.record).expect("2-bit argon solves");
    let token = encode_token(&issued.record.nonce, counter);
    let issued_at_ns = issued.record.issued_at_ns;

    let store = RedisChallengeStore::new(redis::Client::open(url.clone()).unwrap(), prefix.clone());
    store.store(&issued.record).unwrap();
    assert!(store
        .consume_with_operation_identity(&issued.record.nonce, Some(identity))
        .unwrap()
        .is_some());

    // Owner A pre-holds the recovery claim: the full resume path below
    // runs as a claim loser (owner B).
    let owner_a = store
        .claim_resume_derivation(&issued.record.nonce, 60)
        .expect("owner A must claim the resultless record")
        .expect("the pre-held claim is taken");

    let gate = CountingGate {
        active: Arc::new(AtomicUsize::new(0)),
        acquired: Arc::new(AtomicUsize::new(0)),
        released: Arc::new(AtomicUsize::new(0)),
        accept: true,
    };
    let acquired = gate.acquired.clone();
    let verifier = ProductionVerifier::new(
        RedisChallengeStore::new(redis::Client::open(url.clone()).unwrap(), prefix.clone()),
        SECRET,
    )
    .with_argon_gate(gate);

    let losing = verifier.resume_consumed_operation(
        &token,
        identity,
        "login",
        IP,
        issued_at_ns + 1_000_000,
        RequestBindingExpectation::Unenforced,
    );
    assert!(
        matches!(
            losing,
            VerifyOutcome::Invalid(VerifyError::ConsumeIndeterminate)
        ),
        "the claim loser with a resultless reread is ConsumeIndeterminate: {losing:?}"
    );
    assert_eq!(
        acquired.load(Ordering::SeqCst),
        0,
        "the losing recovery must never acquire an Argon admission slot"
    );

    // Owner A releases the claim: the next full resume wins the claim,
    // acquires exactly one admission slot, derives and commits.
    assert!(
        store
            .release_resume_derivation(&issued.record.nonce, &owner_a)
            .expect("the release must run"),
        "owner A must release the pre-held claim"
    );
    let winning = verifier.resume_consumed_operation(
        &token,
        identity,
        "login",
        IP,
        issued_at_ns + 1_000_000,
        RequestBindingExpectation::Unenforced,
    );
    assert!(
        matches!(winning, VerifyOutcome::Valid { .. }),
        "after the release the resume derives and commits: {winning:?}"
    );
    assert_eq!(
        acquired.load(Ordering::SeqCst),
        1,
        "the winner acquires exactly one Argon slot"
    );
}
#[test]
fn resume_releases_the_claim_on_an_early_return() {
    // The RAII guard: an early return (here the pre-derive expiry
    // gate) releases the derivation claim, so the lock never blocks a
    // later retry: a fresh claim can be acquired immediately.
    let Some(url) = redis_url() else { return };
    let prefix = format!("kiwitest:resume-release:{}:", std::process::id());
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
    let identity = "logical-op-resume-release";
    let token = encode_token(
        &issued.record.nonce,
        solve_for_test(&issued.record).expect("4-bit sha solves"),
    );
    let issued_at_ns = issued.record.issued_at_ns;

    let store = RedisChallengeStore::new(redis::Client::open(url.clone()).unwrap(), prefix.clone());
    store.store(&issued.record).unwrap();
    assert!(store
        .consume_with_operation_identity(&issued.record.nonce, Some(identity))
        .unwrap()
        .is_some());

    // A clock far past the signed expiry: the receipt gate returns
    // Expired after the claim was taken, so the guard must release it.
    fn far_future() -> u64 {
        now_unix() + 200
    }
    let verifier = ProductionVerifier::new(
        RedisChallengeStore::new(redis::Client::open(url.clone()).unwrap(), prefix.clone()),
        SECRET,
    )
    .with_now_fn(far_future);
    let outcome = verifier.resume_consumed_operation(
        &token,
        identity,
        "login",
        IP,
        issued_at_ns + 1_000_000,
        RequestBindingExpectation::Unenforced,
    );
    assert!(
        matches!(outcome, VerifyOutcome::Invalid(VerifyError::Expired)),
        "the past-expiry resume is Expired: {outcome:?}"
    );

    // The early return released the claim: a fresh claim succeeds.
    assert!(
        store
            .claim_resume_derivation(&issued.record.nonce, 60)
            .unwrap()
            .is_some(),
        "the RAII guard must release the claim on the early return"
    );
}
#[test]
fn resume_commit_wait_shortfall_never_returns_valid() {
    // The audit's failover sequence: the recovery's commit lands but
    // its verified WAIT shortfalls (standalone Redis acks nothing).
    // The recovered success was NOT proven durable, so the resume
    // must fail closed (the fence on the reread shortfalls too ->
    // StorageUnavailable), never return Valid — a stale-replica
    // promotion must not resurrect the challenge.
    let Some(url) = redis_url() else { return };
    let prefix = format!("kiwitest:resume-waitfail:{}:", std::process::id());
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
    let identity = "logical-op-resume-waitfail";
    let token = encode_token(
        &issued.record.nonce,
        solve_for_test(&issued.record).expect("4-bit sha solves"),
    );
    let issued_at_ns = issued.record.issued_at_ns;

    let plain = RedisChallengeStore::new(redis::Client::open(url.clone()).unwrap(), prefix.clone());
    plain.store(&issued.record).unwrap();
    assert!(plain
        .consume_with_operation_identity(&issued.record.nonce, Some(identity))
        .unwrap()
        .is_some());

    // The accepting verifier requires one acknowledged replica: the
    // commit WAIT returns 0 acked.
    let hardened =
        RedisChallengeStore::new(redis::Client::open(url.clone()).unwrap(), prefix.clone())
            .with_wait(1, 100);
    let verifier = ProductionVerifier::new(hardened, SECRET);
    let outcome = verifier.resume_consumed_operation(
        &token,
        identity,
        "login",
        IP,
        issued_at_ns + 1_000_000,
        RequestBindingExpectation::Unenforced,
    );
    assert!(
        !matches!(outcome, VerifyOutcome::Valid { .. }),
        "a recovery whose commit WAIT shortfalled must never return Valid: {outcome:?}"
    );
    assert!(
            matches!(
                outcome,
                VerifyOutcome::Invalid(VerifyError::StorageUnavailable)
                    | VerifyOutcome::Invalid(VerifyError::ConsumeIndeterminate)
            ),
            "the failed barrier fails closed (fence shortfall -> StorageUnavailable, or the reread stays indeterminate): {outcome:?}"
        );
}

#[test]
fn resume_committed_result_fast_path_rejects_a_changed_context() {
    // The supplied security context is never a dead parameter on the
    // already-completed fast path: a changed scope or transaction
    // binding rejects the stored Valid exactly like a fresh
    // verification.
    let Some(url) = redis_url() else { return };
    let prefix = format!("kiwitest:resume-ctx:{}:", std::process::id());
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
    let identity = "logical-op-resume-ctx";
    let token = encode_token(
        &issued.record.nonce,
        solve_for_test(&issued.record).expect("4-bit sha solves"),
    );
    let issued_at_ns = issued.record.issued_at_ns;

    let store = RedisChallengeStore::new(redis::Client::open(url.clone()).unwrap(), prefix.clone());
    store.store(&issued.record).unwrap();
    assert!(store
        .consume_with_operation_identity(&issued.record.nonce, Some(identity))
        .unwrap()
        .is_some());
    store
        .commit_result(
            &issued.record.nonce,
            true,
            issued.record.request_binding.as_deref(),
        )
        .unwrap();

    let verifier = ProductionVerifier::new(
        RedisChallengeStore::new(redis::Client::open(url.clone()).unwrap(), prefix.clone()),
        SECRET,
    );
    // The changed scope: rejected even though the operation identity
    // matches and a Valid is retained.
    let wrong_scope = verifier.resume_consumed_operation(
        &token,
        identity,
        "payment",
        IP,
        issued_at_ns + 1_000_000,
        RequestBindingExpectation::Unenforced,
    );
    assert!(
        matches!(wrong_scope, VerifyOutcome::Invalid(VerifyError::WrongScope)),
        "a changed scope cannot consume the retained Valid: {wrong_scope:?}"
    );
    // The changed transaction binding: rejected under the exact
    // expectation.
    let wrong_binding = verifier.resume_consumed_operation(
        &token,
        identity,
        "login",
        IP,
        issued_at_ns + 1_000_000,
        RequestBindingExpectation::Exact(Some("txn-other")),
    );
    assert!(
        matches!(
            wrong_binding,
            VerifyOutcome::Invalid(VerifyError::RequestBindingMismatch)
        ),
        "a changed transaction binding cannot consume the retained Valid: {wrong_binding:?}"
    );
    // The correct context still resolves the stored success.
    let ok = verifier.resume_consumed_operation(
        &token,
        identity,
        "login",
        IP,
        issued_at_ns + 1_000_000,
        RequestBindingExpectation::Unenforced,
    );
    assert!(
        matches!(
            ok,
            VerifyOutcome::Valid {
                from_stored_result: true,
                ..
            }
        ),
        "the correct context resolves the retained Valid: {ok:?}"
    );
}

#[test]
fn resume_commit_requires_current_claim_ownership() {
    // The claim is a fencing precondition: a commit whose caller no
    // longer holds the claim is refused before any write, so a stale
    // owner whose claim expired mid-derive can never mutate the
    // record (the audit's stale-vs-new-owner scenario).
    let Some(url) = redis_url() else { return };
    let prefix = format!("kiwitest:resume-owner:{}:", std::process::id());
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
    let identity = "logical-op-resume-owner";

    let store = RedisChallengeStore::new(redis::Client::open(url.clone()).unwrap(), prefix.clone());
    store.store(&issued.record).unwrap();
    assert!(store
        .consume_with_operation_identity(&issued.record.nonce, Some(identity))
        .unwrap()
        .is_some());

    // The real owner holds the claim, embedded in the record envelope.
    let owner = store
        .claim_resume_derivation(&issued.record.nonce, 60)
        .unwrap()
        .expect("the fresh claim is taken");
    const FOREIGN_OWNER: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    assert_ne!(owner, FOREIGN_OWNER, "the foreign token differs");

    // The stale owner's commit is refused before any write. The stale
    // token must still be well-formed (32 lowercase hex chars): the
    // storage boundary rejects a malformed owner before the script, so
    // the fence refusal is proven with a valid-shape foreign token.
    let committed = store
        .commit_result_clearing_claim(&issued.record.nonce, true, None, FOREIGN_OWNER)
        .unwrap();
    assert!(!committed, "the stale owner's commit must be refused");
    let state = store.consumed_state(&issued.record.nonce).unwrap().unwrap();
    assert!(
        state.stored_result.is_none(),
        "the refused commit performed no write"
    );
    assert!(
        state.record.nonce == issued.record.nonce,
        "the record stays resultless"
    );

    // The current owner's commit lands and clears the claim.
    let committed = store
        .commit_result_clearing_claim(&issued.record.nonce, true, None, &owner)
        .unwrap();
    assert!(committed, "the current owner's commit lands");
    let mut conn = redis::Client::open(url.clone()).unwrap();
    let raw: Option<String> = redis::cmd("GET")
        .arg(format!("{}{}", prefix, issued.record.nonce))
        .query(&mut conn)
        .unwrap();
    let raw = raw.expect("the record is still retained");
    assert!(
        !raw.contains("resume_owner"),
        "the current owner's commit clears the claim from the envelope"
    );
}
