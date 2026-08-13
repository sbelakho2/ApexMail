//! Redis-backed production verification with ONE-SHOT concurrency semantics.
//!
//! [`RedisChallengeStore`] persists [`ChallengeRecord`]s as the language-
//! neutral JSON schema shared with the PHP core (`packages/kiwicaptcha-php`)
//! — the same 17 keys `ChallengeRecord::toArray()` emits — under the key
//! `{prefix}{nonce}` with an EX TTL of `expires_at - now` (min 1 s, exactly
//! like the PHP `RedisStorage`). A PHP service and a Rust service can read
//! each other's records from the same Redis instance.
//!
//! [`ProductionVerifier`] implements the PHP verifier's check order with
//! atomic single-use enforced by Redis GETDEL:
//!
//! ```text
//! token decode → store.find(nonce) PEEK (GET) → cheap validation (structure,
//! v1 gate, signature, TTL, scope, IP binding, server-measured min duration) →
//! optional Argon admission gate → store.consume(nonce) (GETDEL) → TOCTOU
//! re-validation of the CONSUMED record → derive hash (once) → leading-zero check
//! ```
//!
//! # One-shot semantics (why exactly one derive per nonce)
//!
//! The cheap phase and the Argon admission gate run against the PEEKED
//! record and never consume: a malformed/expired/mismatched challenge or a
//! gate rejection leaves the record in the store, so the client can retry.
//! Consumption happens exactly once, immediately before hash derivation, via
//! Redis `GETDEL`, which atomically returns AND deletes the key. Under
//! concurrency exactly one caller can ever observe the record: two racing
//! `verify()` calls on the same token yield one [`VerifyOutcome::Valid`] and
//! one [`VerifyOutcome::Invalid(VerifyError::RecordNotFound)`] — the loser
//! never reaches hash derivation, so each nonce drives AT MOST one expensive
//! Argon2id/SHA-256 computation no matter how many requests race for it.
//! This is the distributed bound the caller-managed attempt counter in
//! [`crate::verify::verify_solution`] cannot provide: that counter lives on
//! a per-process record copy, while GETDEL fuses load-and-remove in the
//! store itself (Redis 6.2+, same as PHP's `rawCommand('GETDEL', ...)`).
//!
//! A wrong counter reaches the proof phase and therefore burns the record —
//! replaying any consumed token always fails with `RecordNotFound`. The
//! TOCTOU re-validation after `consume()` makes a swapped/racing record fail
//! closed: the consumed instance must carry the exact challenge that was
//! peeked and must pass the full cheap phase again.
//!
//! A Redis failure inside `find()` or `consume()` fails closed as
//! `RecordNotFound` — never `Valid`.

use crate::challenge::{
    binding_tag, hash_ip, now_epoch_micros, payload_from_record, verify_signature,
    verify_signature_v2, ChallengeRecord, PoWAlgorithm,
};
use crate::token::SolutionToken;
use crate::verify::{
    ct_eq, derive_hash, leading_zero_bits, signature_from_challenge, validate_record, VerifyError,
    VerifyOutcome, SKEW_TOLERANCE_US,
};

/// Redis-backed challenge store with atomic single-use semantics.
///
/// Records are stored as JSON at `{prefix}{nonce}` with an EX TTL of
/// `expires_at - now` (min 1 s) — byte-compatible with the PHP core's
/// `RedisStorage` (same key layout, same JSON schema, same TTL rule), so
/// records written by one side verify on the other.
///
/// `consume()` uses Redis GETDEL (Redis 6.2+): load and delete are fused,
/// so two concurrent consumers can never both win the record. `find()`
/// peeks with a plain GET — the non-consuming read the verify flow runs
/// before the atomic consume.
#[derive(Debug, Clone)]
pub struct RedisChallengeStore {
    client: redis::Client,
    prefix: String,
}

impl RedisChallengeStore {
    /// Build a store for the given Redis client and key prefix (the PHP core
    /// default prefix is `"kiwicaptcha:"`).
    ///
    /// A fresh connection is opened per operation (`redis::Client` is
    /// thread-safe; a `Connection` is not), so concurrent verifies genuinely
    /// race the GETDEL in Redis rather than serializing on a shared socket.
    pub fn new(client: redis::Client, prefix: impl Into<String>) -> Self {
        RedisChallengeStore {
            client,
            prefix: prefix.into(),
        }
    }

    /// Persist a record with `EX ttl = max(1, expires_at - now)` — the exact
    /// TTL rule of the PHP `RedisStorage::store()`. An already-expired record
    /// is stored with a 1-second lifetime (it will fail the verifier's TTL
    /// check if fetched in time, and vanish otherwise).
    pub fn store(&self, record: &ChallengeRecord) -> redis::RedisResult<()> {
        let key = format!("{}{}", self.prefix, record.nonce);
        // Infallible for this struct: every field is a String or an integer
        // (no non-finite floats), so serde_json::to_string cannot fail.
        let value = serde_json::to_string(record)
            .expect("ChallengeRecord JSON serialization is infallible");
        let now_unix = now_epoch_micros() / 1_000_000;
        let ttl = record.expires_at.saturating_sub(now_unix).max(1);
        let mut conn = self.client.get_connection()?;
        redis::cmd("SET")
            .arg(key)
            .arg(value)
            .arg("EX")
            .arg(ttl)
            .query::<()>(&mut conn)
    }

    /// Load a record WITHOUT consuming it — the peek of the verify flow
    /// (Redis GET).
    ///
    /// Returns `None` when the key is absent, when the stored value is not
    /// valid JSON, or when it does not map onto a [`ChallengeRecord`] — a
    /// corrupt key must never blow up the verify path (mirrors the PHP
    /// `RedisStorage::decode()`).
    pub fn find(&self, nonce: &str) -> redis::RedisResult<Option<ChallengeRecord>> {
        let key = format!("{}{}", self.prefix, nonce);
        let mut conn = self.client.get_connection()?;
        let raw: Option<String> = redis::cmd("GET").arg(key).query(&mut conn)?;
        Ok(raw.and_then(|json| serde_json::from_str(&json).ok()))
    }

    /// Atomically return-and-delete the record for `nonce`.
    ///
    /// Returns `None` when the key is absent, when the stored value is not
    /// valid JSON, or when it does not map onto a [`ChallengeRecord`] — a
    /// corrupt key must never blow up the verify path (mirrors the PHP
    /// `RedisStorage::decode()`). `Ok(None)` also means the record is
    /// already consumed: a replay can never win.
    pub fn consume(&self, nonce: &str) -> redis::RedisResult<Option<ChallengeRecord>> {
        let key = format!("{}{}", self.prefix, nonce);
        let mut conn = self.client.get_connection()?;
        let raw: Option<String> = redis::cmd("GETDEL").arg(key).query(&mut conn)?;
        Ok(raw.and_then(|json| serde_json::from_str(&json).ok()))
    }
}

/// Admission-control closure for memory-hard (Argon2id) verifications.
///
/// Mirrors the PHP `VerificationAdmissionGate` concept minimally: `false`
/// rejects the verification with [`VerifyError::CapacityExceeded`] before
/// any hash is derived. Only applies to Argon2id records (SHA-256 records
/// are cheap to verify and never gated), matching the PHP verifier.
pub type ArgonAdmissionGate = Box<dyn Fn(&ChallengeRecord) -> bool + Send + Sync>;

/// Production verifier: the PHP core's one-shot flow, backed by
/// [`RedisChallengeStore`] for distributed single-use.
///
/// See the module docs for the check order and the one-shot semantics.
pub struct ProductionVerifier {
    store: RedisChallengeStore,
    secret_key: String,
    argon_gate: Option<ArgonAdmissionGate>,
    accept_legacy_v1: bool,
}

impl ProductionVerifier {
    /// Build a verifier with no Argon admission gate and no legacy-v1
    /// acceptance (both mirror the PHP defaults).
    pub fn new(store: RedisChallengeStore, secret_key: impl Into<String>) -> Self {
        ProductionVerifier {
            store,
            secret_key: secret_key.into(),
            argon_gate: None,
            accept_legacy_v1: false,
        }
    }

    /// Add an Argon2id admission gate (default: none). `false` → reject with
    /// [`VerifyError::CapacityExceeded`] before any hash derivation.
    pub fn with_argon_gate(
        mut self,
        gate: impl Fn(&ChallengeRecord) -> bool + Send + Sync + 'static,
    ) -> Self {
        self.argon_gate = Some(Box::new(gate));
        self
    }

    /// The backing store — lets the caller persist issued records under the
    /// same key prefix this verifier consumes from.
    pub fn store(&self) -> &RedisChallengeStore {
        &self.store
    }

    /// Accept protocol-v1 (legacy) challenges during an explicit migration
    /// window. Off by default, exactly like the PHP verifier.
    pub fn with_accept_legacy_v1(mut self, accept: bool) -> Self {
        self.accept_legacy_v1 = accept;
        self
    }

    /// Verify a client-submitted solution token against the store.
    ///
    /// - `token` — the raw `kiwi__token` value (`base64` of
    ///   `nonce.counter.duration_ms.telemetry`).
    /// - `scope` — the expected auth flow; a record issued for a different
    ///   scope is rejected with [`VerifyError::WrongScope`].
    /// - `client_ip` — the caller's IP, checked against the record's
    ///   nonce-bound binding tag (a record with an empty tag skips the
    ///   check). A `binding_tag` computation failure on an unparsable IP
    ///   rejects as [`VerifyError::IpMismatch`].
    /// - `now_ns` — server receipt time in EPOCH MICROSECONDS (the unit
    ///   shared with the PHP core), used with the record's `issued_at_ns`
    ///   for the server-measured minimum-duration check.
    ///
    /// Flow: decode → PEEK (GET) → cheap validation → Argon admission gate →
    /// atomic CONSUME (GETDEL) → TOCTOU re-validation of the consumed record
    /// → single derive → leading-zero check. The cheap checks and the gate
    /// never consume, so a malformed/expired/mismatched token or a capacity
    /// rejection leaves the record in place for a retry; the record is
    /// burned exactly once, at the GETDEL, so at most one hash derivation
    /// ever runs per nonce (concurrent losers see `RecordNotFound`).
    pub fn verify(&self, token: &str, scope: &str, client_ip: &str, now_ns: u64) -> VerifyOutcome {
        // 1. Token decode. The counter is bounded here too: the decoder
        //    rejects counter >= SOLVER_MAX_HASHES (VerifyError::CounterTooLarge
        //    territory) with MalformedToken — mirroring the PHP flow.
        let token = match SolutionToken::decode(token) {
            Ok(token) => token,
            Err(_) => return VerifyOutcome::Invalid(VerifyError::MalformedToken),
        };

        // 2. PEEK (non-consuming GET). None → RecordNotFound — the record
        //    was never issued, was already consumed, or expired away. A
        //    Redis error fails closed (never Valid).
        let peek = match self.store.find(&token.nonce) {
            Ok(Some(record)) => record,
            Ok(None) | Err(_) => return VerifyOutcome::Invalid(VerifyError::RecordNotFound),
        };

        // 3. Cheap validation on the PEEKED record — a failure returns the
        //    outcome WITHOUT consuming, so a malformed/expired/mismatched
        //    record is rejected cheaply and stays in the store (the client
        //    can retry with a fresh proof; a corrupt record can never drive
        //    an expensive derivation).
        if let Err(e) = self.check_cheap(&peek, scope, client_ip, now_ns) {
            return VerifyOutcome::Invalid(e);
        }

        // 4. Argon2id admission gate (optional): capacity control before the
        //    memory-hard hash. Only Argon2id records are gated, matching PHP.
        //    A rejection returns CapacityExceeded WITHOUT consuming — the
        //    record stays and the client can retry once capacity frees up.
        if peek.algorithm == PoWAlgorithm::Argon2id {
            if let Some(gate) = &self.argon_gate {
                if !gate(&peek) {
                    return VerifyOutcome::Invalid(VerifyError::CapacityExceeded);
                }
            }
        }

        // 5. Atomic CONSUME (GETDEL). The one-shot bound: exactly one caller
        //    observes the record, so exactly one derive can ever happen per
        //    nonce. None here means a concurrent verifier won the GETDEL
        //    first (or the key vanished between peek and consume).
        let record = match self.store.consume(&token.nonce) {
            Ok(Some(record)) => record,
            Ok(None) | Err(_) => return VerifyOutcome::Invalid(VerifyError::RecordNotFound),
        };

        // 6. TOCTOU re-validation of the CONSUMED record: it must carry the
        //    exact challenge that was peeked (constant-time string compare,
        //    like the PHP hash_equals) and must pass the full cheap phase
        //    again — a swapped/racing record fails closed instead of being
        //    verified against bytes that were never validated.
        if !ct_eq(record.challenge.as_bytes(), peek.challenge.as_bytes()) {
            return VerifyOutcome::Invalid(VerifyError::MalformedRecord);
        }
        if let Err(e) = self.check_cheap(&record, scope, client_ip, now_ns) {
            return VerifyOutcome::Invalid(e);
        }

        // 7. Single derive + leading-zero check.
        let hash = match derive_hash(&record, token.counter) {
            Ok(hash) => hash,
            Err(e) => return VerifyOutcome::Invalid(e),
        };
        if leading_zero_bits(&hash) >= record.target_bits {
            VerifyOutcome::Valid
        } else {
            VerifyOutcome::Invalid(VerifyError::InsufficientWork)
        }
    }

    /// The cheap validation phase: structural validation, the protocol-v1
    /// gate, the signature re-check, TTL, scope, IP binding, and the
    /// server-measured minimum duration — the checks PHP runs against the
    /// peeked record before the Argon admission gate. Run against the
    /// PEEKED record and re-run against the CONSUMED record (TOCTOU guard).
    fn check_cheap(
        &self,
        record: &ChallengeRecord,
        scope: &str,
        client_ip: &str,
        now_ns: u64,
    ) -> Result<(), VerifyError> {
        // 3a. Cheap structural validation BEFORE any crypto or timing work.
        validate_record(record)?;

        // 3b. Protocol version gate: v1 (legacy) only during an explicit
        //     migration window.
        if record.protocol_version == 1 && !self.accept_legacy_v1 {
            return Err(VerifyError::MalformedRecord);
        }

        // 3c. Signature re-check over the protocol-appropriate canonical
        //     input.
        let sig = signature_from_challenge(record);
        let sig_ok = match record.protocol_version {
            1 => verify_signature(&payload_from_record(record), sig, &self.secret_key),
            _ => verify_signature_v2(record, sig, &self.secret_key),
        };
        match sig_ok {
            Ok(true) => {}
            _ => return Err(VerifyError::BadSignature),
        }

        // 3d. TTL (server clock, like the PHP `time()`).
        let now_unix = now_epoch_micros() / 1_000_000;
        if now_unix >= record.expires_at {
            return Err(VerifyError::Expired);
        }

        // 3e. Scope: prevent cross-scope replay.
        if record.scope != scope {
            return Err(VerifyError::WrongScope);
        }

        // 3f. IP binding. The stored record is authoritative: an EMPTY
        //     binding tag means binding is disabled; a non-empty tag means
        //     the challenge IS bound, so a mismatch fails closed
        //     (IpMismatch).
        if !record.binding_tag.is_empty() {
            let expected = match record.protocol_version {
                1 => hash_ip(client_ip, &self.secret_key),
                _ => match binding_tag(&record.nonce, client_ip, &self.secret_key) {
                    Ok(tag) => tag,
                    Err(_) => return Err(VerifyError::IpMismatch),
                },
            };
            if !ct_eq(record.binding_tag.as_bytes(), expected.as_bytes()) {
                return Err(VerifyError::IpMismatch);
            }
        }

        // 3g. Minimum duration, SERVER-measured: the floor is `now_ns` vs
        //     the record's `issued_at_ns` (both epoch microseconds), never
        //     the forgeable client-reported duration. A record without
        //     `issued_at_ns` is malformed (no legacy fallback).
        if record.issued_at_ns == 0 {
            return Err(VerifyError::MalformedRecord);
        }
        if record.min_duration_ms > 0 {
            if now_ns >= record.issued_at_ns {
                if now_ns - record.issued_at_ns < record.min_duration_ms.saturating_mul(1_000) {
                    return Err(VerifyError::TooFast);
                }
            } else if record.issued_at_ns - now_ns > SKEW_TOLERANCE_US {
                return Err(VerifyError::TooFast);
            }
        }

        Ok(())
    }
}
