//! Proof-of-work verification for KiwiCaptcha.
//!
//! Given a stored [`ChallengeRecord`] and a client-submitted counter, this
//! module re-derives the hash (SHA-256 over the record's prefix, counter,
//! and salt, or Argon2id per the record's algorithm) and checks that the
//! raw output has at least `target_bits` leading zero bits.
//!
//! Because the computation is driven by the record's explicit algorithm and
//! difficulty, the verifier always performs exactly the work the issuer
//! configured — the client cannot downgrade difficulty or switch modes.

use argon2::{Algorithm, Argon2, Params, Version};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};

use crate::challenge::{
    binding_tag_for_tenant, hash_ip, payload_from_record, verify_signature,
    verify_signature_v2_with_tenant, ChallengeRecord, PoWAlgorithm,
};
use crate::rsw::RswTrapdoor;

/// Clock-skew tolerance (microseconds) for the server-side minimum-duration
/// check. When the issuer host's clock is ahead of the verifier host
/// (`now_ns < issued_at_ns`), the apparent "elapsed" time is negative; a skew
/// within this bound (5 s) skips the floor heuristic, a larger skew is a
/// clock anomaly and the solution is rejected with [`VerifyError::TooFast`].
pub const SKEW_TOLERANCE_US: u64 = 5_000_000;

/// Compute the hash for the given record + counter.
///
/// The computation is driven by the challenge's explicit [`PoWAlgorithm`],
/// never by a numeric heuristic:
/// 1. [`PoWAlgorithm::Sha256`] — `SHA-256(prefix || counter || salt)`
/// 2. [`PoWAlgorithm::Argon2id`] — `Argon2id(prefix || counter, salt)` with
///    the record's m_kib/t/p parameters.
///
/// An rsw record derives no hash: the proof is the client's final
/// value, checked through the trapdoor by the verification paths
/// instead, so this helper is never called for one.
pub(crate) fn derive_hash(record: &ChallengeRecord, counter: u64) -> Result<[u8; 32], VerifyError> {
    let salt = B64
        .decode(&record.salt)
        .map_err(|_| VerifyError::MalformedRecord)?;

    match record.algorithm {
        PoWAlgorithm::Argon2id => {
            // Reject implausible parameters up front: the verifier must never
            // run a memory-hard computation with impossible parameters — the
            // hard ceilings plus the Argon2 minimum
            // `m_kib >= 8 * p`. The minimum (m_kib >= 8 * p) is enforced at
            // issuance too. A parameter violation is
            // UnsupportedArgon2Params, the PHP core's twin: the record may
            // be properly signed, but this verifier refuses to represent
            // the computation.
            if record.m_kib < 8 * record.p || check_argon2_ceilings(record).is_err() {
                return Err(VerifyError::UnsupportedArgon2Params);
            }
            // Protocol unit: m_kib is in kibibytes (65536 = 64 MiB); the
            // argon2 crate's Params::new takes the same 1 KiB blocks.
            let params = Params::new(record.m_kib, record.t, record.p, Some(32))
                .map_err(|_| VerifyError::UnsupportedArgon2Params)?;
            let hasher = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
            let password = format!("{}{}", record.prefix, counter);
            let mut output = [0u8; 32];
            hasher
                .hash_password_into(password.as_bytes(), &salt, &mut output)
                .map_err(|_| VerifyError::UnsupportedArgon2Params)?;
            Ok(output)
        }
        PoWAlgorithm::Sha256 => {
            let input = format!("{}{}", record.prefix, counter);
            let mut hasher = Sha256::new();
            hasher.update(input.as_bytes());
            hasher.update(&salt);
            let result = hasher.finalize();
            let mut out = [0u8; 32];
            out.copy_from_slice(&result);
            Ok(out)
        }
        // Never reached: the rsw verification paths check the presented
        // final value through the trapdoor instead of deriving a hash.
        PoWAlgorithm::Rsw => Err(VerifyError::MalformedRecord),
    }
}

/// Count the number of leading zero bits in a byte slice (big-endian bit order).
pub(crate) fn leading_zero_bits(hash: &[u8]) -> u32 {
    let mut count = 0u32;
    for &byte in hash {
        if byte == 0 {
            count += 8;
        } else {
            count += byte.leading_zeros();
            break;
        }
    }
    count
}

/// The context for verifying a single solution.
/// The explicit request-binding enforcement policy, mirroring the PHP
/// `RequestBindingExpectation`: `Exact` requires Option-equality between
/// the record's signed `request_binding` and the authoritative
/// transaction binding (null == explicitly unbound, a string == the same
/// bound transaction); `Unenforced` disables the check.
#[derive(Debug, Clone, Copy)]
pub enum RequestBindingExpectation<'a> {
    Unenforced,
    Exact(Option<&'a str>),
}

/// Constant-time byte equality (the request binding is compared without
/// early exit; the bindings are transaction identifiers, the constant-time
/// property is defense-in-depth).
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// The ONE shared request-binding check used by every binding enforcement
/// site (the generic verify_solution, the production Redis verifier's
/// cheap phase, replay gate, post-consume revalidation and resume path):
/// exact Option-equality, compared in constant time when both sides carry
/// a string.
pub(crate) fn check_request_binding(
    record_binding: Option<&str>,
    expectation: RequestBindingExpectation<'_>,
) -> Result<(), VerifyError> {
    match expectation {
        RequestBindingExpectation::Unenforced => Ok(()),
        RequestBindingExpectation::Exact(expected) => match (record_binding, expected) {
            (None, None) => Ok(()),
            (Some(actual), Some(expected))
                if constant_time_eq(actual.as_bytes(), expected.as_bytes()) =>
            {
                Ok(())
            }
            _ => Err(VerifyError::RequestBindingMismatch),
        },
    }
}

pub struct VerifyContext<'a> {
    /// The stored challenge record (looked up from storage by nonce). Passed
    /// as `&mut` because verification performs attempt accounting on the
    /// record's `attempts_used` counter — the caller persists the mutated
    /// record back to storage (on failure paths) or consumes it (on success).
    pub record: &'a mut ChallengeRecord,
    /// The HMAC secret key (to re-verify the challenge signature).
    pub secret_key: &'a str,
    /// The tenant id the purpose keys derive under (validated like
    /// `region`: 1..=64 bytes of the narrow identifier alphabet, see
    /// [`crate::keys::DerivedKeys`]). A record issued under tenant `t1`
    /// verifies only under `Some("t1")` — a different tenant and the
    /// global (`None`) keys reject the signature and the IP binding.
    /// `None` (the default) derives the global purpose keys,
    /// byte-identical to the tenant-free verification.
    pub tenant: Option<&'a str>,
    /// Optional per-key-id secrets: `kid → master secret`. When
    /// present, the record's `kid` selects the secret for the signature (and
    /// IP-binding) checks — the secret rotation map. An unknown kid — or a
    /// kid beyond the map's newest configured id (the forward/rollback guard:
    /// future-keyed challenges must never verify on older nodes, even if the
    /// key were somehow known) — rejects with
    /// [`VerifyError::UnknownKid`]. When `None`, `secret_key` is used
    /// unconditionally (the single-key path).
    pub secrets_by_kid: Option<&'a HashMap<u32, String>>,
    /// Compromise-revoked key ids: `kid → revoked` — e.g. a key
    /// that leaked. A record whose `kid` is in this set is rejected with
    /// [`VerifyError::UnknownKid`] immediately, before the signature check,
    /// even when the secret is present: compromise revocation overrides the
    /// rotation grace (a revoked key may legitimately remain in
    /// `secrets_by_kid` while the deployment retires it, but its challenges
    /// must never verify). When `None`, no kid is revoked.
    pub revoked_kids: Option<&'a HashSet<u32>>,
    /// The client's claimed counter.
    pub counter: u64,
    /// The client's reported solve duration in milliseconds. This value is
    /// client-controlled and therefore forgeable — it is NOT used to enforce
    /// the minimum duration (that is measured server-side via
    /// `issued_at_ns`/`now_ns`); it is only fed to the telemetry scorer.
    pub duration_ms: u64,
    /// The optional injectable server clock provider (Unix seconds).
    /// `None`, the safe default, makes the verifier read the real system
    /// clock itself, twice: once at receipt (the TTL checks) and once
    /// after the expensive derivation (the final re-validation), so a
    /// challenge that expired while the proof was deriving is always
    /// detected. Injection (`Some`) exists only for deterministic
    /// testing and specialized applications: a caller-supplied constant
    /// closure would silently defeat the mid-derive expiry check, so the
    /// default must not require the caller to remember to supply a live
    /// clock.
    pub now_unix: Option<&'a mut dyn FnMut() -> u64>,
    /// The server's receipt time in epoch microseconds — the same unit as the
    /// record's `issued_at_ns` (the field names keep the `_ns`
    /// suffix; the unit is microseconds, shared with PHP). Together they
    /// provide a server-measured elapsed time, used to enforce the minimum
    /// solve duration. A forged client `duration_ms` can never satisfy this
    /// check.
    pub now_ns: u64,
    /// The minimum acceptable solve duration in milliseconds. The floor is a
    /// timing-anomaly heuristic: PoW is probabilistic (a valid solution can
    /// occur at counter 0) and a fast bot can wait before submitting, so the
    /// floor only rejects solves that arrive (per the server clock) faster
    /// than the theoretical minimum — a heuristic, never a proof of human
    /// behavior, and the client-reported duration is never trusted. The
    /// effective floor is `max(min_duration_ms, record.min_duration_ms)`;
    /// 0 disables the check.
    pub min_duration_ms: u64,
    /// Expected auth scope. If [`Some`], the solution is rejected if the
    /// challenge was issued for a different scope (prevents cross-scope replay).
    pub expected_scope: Option<&'a str>,
    /// The request-binding enforcement policy. [`RequestBindingExpectation::Exact`]
    /// requires Option-equality with the authoritative transaction binding
    /// (a bound record under a different or explicitly-unbound transaction
    /// is rejected with [`VerifyError::RequestBindingMismatch`], and an
    /// explicitly unbound record under a bound transaction is rejected
    /// too); [`RequestBindingExpectation::Unenforced`] disables the check.
    pub expected_request_binding: RequestBindingExpectation<'a>,
    /// Expected region. If [`Some`], the solution is rejected with
    /// [`VerifyError::WrongRegion`] when the stored record was issued for a
    /// different region — or for no region at all (a region-expecting
    /// deployment fails closed on region-unbound challenges). When `None`,
    /// the record's region is not checked.
    pub expected_region: Option<&'a str>,
    /// Expected issuer identity. If [`Some`], the solution is
    /// rejected with [`VerifyError::WrongIssuer`] when the stored record was
    /// issued by a different issuer — or by no issuer at all (fail closed,
    /// like the region expectation). When `None`, the record's issuer is not
    /// checked.
    pub expected_issuer: Option<&'a str>,
    /// The current security-policy epoch. When set, a record whose
    /// `policy_version` differs is rejected with
    /// [`VerifyError::WrongPolicyVersion`] — outstanding challenges die
    /// immediately on policy revocation.
    pub expected_policy_version: Option<u32>,
    /// The rollout-window floor for [`VerifyContext::expected_policy_version`]:
    /// during a declared N → N+1 policy rollout a mixed fleet legitimately
    /// redeems challenges issued under either epoch, so a floor of N with an
    /// expected version of N+1 accepts `floor <= policy_version <= expected`
    /// — strict equality otherwise (the default, `None`). A floor greater
    /// than the expected version accepts nothing (fail closed). Ignored when
    /// no expected version is set.
    pub policy_version_floor: Option<u32>,
    /// The current client's IP address. In v2 the binding is the
    /// nonce-bound HMAC tag: verification recomputes the tag from the
    /// challenge nonce + canonical client IP under the derived purpose key
    /// and rejects a mismatch with [`VerifyError::IpMismatch`]. The nonce-
    /// bound tag is the current binding model (v1 records use the legacy
    /// `hash_ip`). When `None` and the
    /// record's binding tag is non-empty, the solution is rejected with
    /// [`VerifyError::MissingClientIp`] — a bound challenge requires its IP.
    /// Only records with an empty binding tag (`BindingMode::None`) verify
    /// without an IP.
    pub client_ip: Option<&'a str>,
    /// The execution digest the solution token presents for an
    /// ExecutionChallengeV1-armed record (64 lowercase hex characters);
    /// `None` on the unarmed token shape. When the record carries an
    /// execution program, the presented digest must equal the expected
    /// digest recomputed from the stored program (constant-time
    /// compare) — a missing or mismatched digest is the deterministic
    /// [`VerifyError::ExecutionMismatch`]. An unarmed record runs no
    /// execution check (byte-identical legacy behavior).
    pub execution_digest: Option<&'a str>,
    /// ExecutionChallengeV2 executed trace (base64url) submitted with the
    /// digest so the server can verify the browser-observed entries;
    /// `None` on the unarmed token shape.
    pub execution_trace: Option<&'a str>,
    /// Browser/environment telemetry gathered by the widget (client-controlled
    /// and forgeable — treated strictly as a supplementary signal).
    pub telemetry: Option<&'a serde_json::Value>,
    /// When `true`, telemetry is scored and the solution is rejected with
    /// [`VerifyError::BotDetected`] when the client appears automated
    /// (including when no telemetry was submitted at all — a custom client
    /// does not send telemetry). When `false`, telemetry is ignored for
    /// enforcement (score-only logging is performed by `score_telemetry`
    /// callers). Default off: telemetry must never be the security boundary.
    pub enforce_telemetry: bool,
    /// Accept protocol-v1 (legacy) challenges. v2 has been the issuance
    /// format for longer than the maximum challenge lifetime (300 s), so no
    /// legitimate v1 record can still exist — v1 is rejected by default.
    /// Set this only during a coordinated migration window.
    pub accept_legacy_v1: bool,
    /// Maximum number of verification attempts against this record
    /// (`record.attempts_used`). 0 = unlimited. Attempts are counted on every
    /// verification call (correct or not), bounding the server-side cost of
    /// wrong candidates — particularly memory-hard Argon2id verifications.
    pub max_attempts: u32,
    /// The rsw final value the solution token presents for an
    /// rsw record (512 lowercase hex); `None` on every other token
    /// shape. When the record's algorithm is rsw, the presented value
    /// must equal the trapdoor expectation (constant-time compare) — a
    /// missing or mismatched value is the deterministic
    /// [`VerifyError::InsufficientWork`].
    pub rsw_proof: Option<&'a str>,
    /// The verifier's configured rsw modulus n (canonical standard
    /// base64 of the 2048-bit composite, generated with the shipped
    /// tools/rsw-keygen binary). Together with `rsw_lambda` it forms
    /// the time-lock trapdoor; a signed rsw record then verifies
    /// through it. When both are `None` (the default), an rsw record is
    /// authentic but unsupported
    /// ([`VerifyError::UnsupportedRswParams`]).
    pub rsw_modulus_n: Option<&'a str>,
    /// The verifier's configured rsw secret lambda = lcm(p-1, q-1)
    /// (canonical standard base64). It is the secret trapdoor: never
    /// persist it beside client material. Never stored on the record
    /// and never sent to the client.
    pub rsw_lambda: Option<&'a str>,
    /// The rsw trapdoor rotation keyring (see
    /// [`crate::rsw::RswKeyring`]): historical pairs indexed by their
    /// authenticated modulus identity. A record whose authenticated
    /// `rsw_modulus_sha256` is not the active pair resolves through
    /// this keyring, so a rotated/mixed-node outstanding challenge
    /// still verifies. `None` = only the active pair resolves. The
    /// selection is exact and never falls through to an arbitrary
    /// active pair: an unknown identity fails closed with
    /// [`VerifyError::UnsupportedRswParams`].
    pub rsw_keyring: Option<&'a crate::rsw::RswKeyring>,
}

/// Outcome of a verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyOutcome {
    /// The solution is valid. The challenge must now be consumed
    /// (atomically — the consumed-state transition) so it can never be used twice.
    /// Carries the consumed challenge's canonical nonce (the jti — the
    /// single-use token identifier), so callers can correlate the outcome
    /// with the storage key and any downstream result token without
    /// re-decoding the solution.
    Valid {
        /// The consumed challenge's canonical base64 nonce (the jti).
        nonce: String,
        /// The application-supplied transaction binding: the host application
        /// generated this nonce and must present
        /// it again on the final protected POST — correlating the captcha
        /// result with the exact application transaction.
        request_binding: Option<String>,
        /// `true` when this success is the retained committed outcome of an
        /// earlier verification of the same nonce, replayed idempotently for
        /// the logical operation that recorded it (the identity gate);
        /// `false` for a fresh derivation. Callers that treat a
        /// [`VerifyOutcome::Valid`] as authorization can therefore
        /// distinguish a new proof from a retained-state replay.
        from_stored_result: bool,
        /// The server-measured solve duration in milliseconds: the span
        /// between the record's server-written issuance clock
        /// (`issued_at_ns`, epoch microseconds; server-side metadata
        /// outside the challenge HMAC, authenticated by the record's
        /// `server_mac`) and this verification's
        /// receipt instant —
        /// unforgeable behavioral evidence the risk layer can consume as a
        /// graded signal. The client-reported token `duration_ms` is
        /// forgeable and is never consulted; only server-written
        /// timestamps feed this value. Mirrors the PHP
        /// `VerifyOutcome::solveDurationMs()`: `None` when no duration
        /// was measurable — a record without an issuance clock
        /// (`issued_at_ns == 0`), or a receipt preceding issuance within
        /// the verifier's clock-skew tolerance, where the elapsed time
        /// cannot be measured reliably (the same skew semantics as the
        /// minimum-duration floor) — and always `None` on non-valid
        /// outcomes. A stored-success replay
        /// (`from_stored_result == true`) also reports `None`: its
        /// receipt measures the retry, not the original solve, and a
        /// confidently incorrect value is worse than none. Purely
        /// additive.
        solve_duration_ms: Option<u64>,
    },
    /// The solution is invalid; the reason explains why.
    Invalid(VerifyError),
}

impl VerifyOutcome {
    /// The consumed canonical nonce (jti) when the outcome is valid, else
    /// `None`.
    pub fn nonce(&self) -> Option<&str> {
        match self {
            VerifyOutcome::Valid { nonce, .. } => Some(nonce),
            VerifyOutcome::Invalid(_) => None,
        }
    }

    /// The record's application-supplied transaction binding when the
    /// outcome is valid.
    pub fn request_binding(&self) -> Option<&str> {
        match self {
            VerifyOutcome::Valid {
                request_binding, ..
            } => request_binding.as_deref(),
            VerifyOutcome::Invalid(_) => None,
        }
    }

    /// The server-measured solve duration in milliseconds when the
    /// outcome is valid AND a duration was measurable, else `None`.
    ///
    /// The value is the gap between the record's `issued_at_ns` and the
    /// verification receipt instant — unforgeable behavioral evidence
    /// (the client-reported token duration never feeds it). `None` on
    /// every non-valid outcome, for a record whose issuance clock is
    /// unknown, for a receipt that precedes issuance within the
    /// verifier's clock-skew tolerance — exactly the semantics of the
    /// minimum-duration floor — and always for a stored-success replay
    /// (`from_stored_result == true`), whose receipt measures the retry,
    /// not the original solve (the cross-language spec, shared with PHP).
    pub fn solve_duration_ms(&self) -> Option<u64> {
        match self {
            VerifyOutcome::Valid {
                solve_duration_ms, ..
            } => *solve_duration_ms,
            VerifyOutcome::Invalid(_) => None,
        }
    }
}

/// Reasons a solution can be rejected.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum VerifyError {
    #[error("challenge signature is invalid")]
    BadSignature,
    #[error("challenge has expired")]
    Expired,
    #[error("solution arrived faster than the theoretical minimum (server-measured)")]
    TooFast,
    #[error("challenge was issued to a different client IP")]
    IpMismatch,
    #[error("challenge is IP-bound but no client IP was supplied")]
    MissingClientIp,
    #[error("submitted counter exceeds the solver maximum")]
    CounterTooLarge,
    #[error("challenge was issued for a different scope")]
    WrongScope,
    /// The caller pinned the challenge to an expected application
    /// transaction binding (`request_binding`), but the record's signed
    /// binding differs — or the record carries no binding at all (an
    /// unbound challenge satisfies no binding-pinned redemption; fail
    /// closed). The comparison is constant-time.
    #[error("challenge is bound to a different application transaction (request_binding)")]
    RequestBindingMismatch,
    #[error("challenge was issued for a different region")]
    WrongRegion,
    /// The stored record was issued under a different issuer identity than
    /// the verifier's configured expected issuer — or under no
    /// issuer at all (an issuer-expecting deployment fails closed on
    /// issuer-unbound challenges).
    #[error("challenge was issued by a different issuer")]
    WrongIssuer,
    /// The stored record was issued under a different security-policy epoch
    /// than the verifier's configured current version — the policy that
    /// authorized the challenge (origin/action rules, difficulty floors,
    /// revocation) is no longer in force, so the challenge is invalid.
    #[error("challenge was issued under a different security-policy epoch")]
    WrongPolicyVersion,
    /// The record's key id (`kid`) is unknown to this verifier —
    /// either absent from its `secrets_by_kid` map, or newer than the
    /// newest configured key (the forward/rollback guard: a challenge keyed
    /// with a future kid must never verify on an older node, even if the
    /// key were somehow known). The deployment must roll forward its key
    /// set (or the challenge is foreign) before this record can verify.
    #[error("challenge was issued with an unknown key id (kid)")]
    UnknownKid,
    #[error("too many verification attempts against this challenge")]
    TooManyAttempts,
    #[error("proof-of-work hash does not meet the difficulty target")]
    InsufficientWork,
    #[error("stored challenge record is malformed")]
    MalformedRecord,
    /// The record is authentic (its signature verifies) but its signed
    /// Argon2id parameters violate the hard process ceilings — the
    /// memory-hard computation must never run, let alone allocate, for
    /// parameters outside these bounds. The PHP core's exact twin
    /// (`unsupported_argon2_params`): a signed record violating the
    /// ceilings came from a foreign or corrupt issuer holding a key, so
    /// it is distinguished from a malformed record.
    #[error("Argon2id parameters exceed the supported process ceilings")]
    UnsupportedArgon2Params,
    /// The record is authentic (its signature verifies) but this
    /// verifier cannot check it: the deployment holds no rsw trapdoor
    /// (the modulus/lambda pair is unconfigured), or the record's
    /// signed sequential cost T sits outside the supported range
    /// (10,000..=300,000). The PHP core's exact twin
    /// (`unsupported_rsw_params`): the record really came from an
    /// issuer holding the trapdoor; this verifier simply cannot
    /// represent the computation.
    #[error("the rsw challenge cannot be verified (no configured trapdoor, or the signed sequential cost is outside the supported bounds)")]
    UnsupportedRswParams,
    #[error("automated or headless client detected via telemetry")]
    BotDetected,
    #[error("solution token is malformed or undecodable")]
    MalformedToken,
    #[error("challenge record not found (already consumed, expired, or never issued)")]
    RecordNotFound,
    /// The challenge store (e.g. Redis) could not be reached for the
    /// non-consuming peek: unreachable backend, failed connect, or a
    /// read/write timeout. The challenge was never touched, so it is
    /// presumed intact and can be retried once the store recovers. Never
    /// returned for a genuinely absent key — that is
    /// [`VerifyError::RecordNotFound`].
    #[error("challenge store unavailable — the challenge is presumed intact and can be retried once the store recovers")]
    StorageUnavailable,
    /// The atomic consume (the pending→consumed transition) failed with
    /// an uncertain I/O error — the challenge may or may not have been
    /// consumed on the server. The verifier MUST NOT retry the consume
    /// automatically (the reply may still be in flight and the record may
    /// already be burned; a blind retry can corrupt the record the first
    /// attempt did transition). What a caller may do depends on its
    /// idempotency contract, see the consume no-retry rule in
    /// `redis_verify`: an idempotent caller that recorded an operation
    /// identity and key may re-present the same token, because a
    /// completed consume replays its retained result and an unexecuted
    /// one is still redeemable; a caller without that identity must treat
    /// the token as unknown (re-issue) rather than replay it.
    #[error("challenge consumption is indeterminate (storage I/O failure) — the challenge may or may not have been consumed; do not blindly retry this token")]
    ConsumeIndeterminate,
    /// The challenge was already consumed by an earlier verification, and
    /// its retained success is not idempotently replayable for this
    /// caller: no operation identity was supplied, the record carries
    /// none, or the supplied identity does not match the recorded one
    /// (constant-time compare). A solved token can never fund a second
    /// operation.
    #[error("challenge already consumed — its retained success is not replayable for this caller")]
    AlreadyConsumed,
    #[error("verification capacity exceeded — try again shortly")]
    CapacityExceeded,
    #[error("admission gate unavailable — try again shortly")]
    AdmissionUnavailable,
    /// The record carries an armed ExecutionChallengeV1 program, but the
    /// presented execution digest does not match the expected digest
    /// recomputed from the stored program, a constant-time compare, or
    /// no digest was presented at all. A hard verdict (never
    /// replay-exempt), and never the sole acceptance boundary: the PoW
    /// proof and the record state machinery still gate. The expected
    /// digest is a pure function of (program, nonce), so the verifier
    /// needs no secret; a substituted program changes both the digest
    /// key and the expected trace, and a digest from another challenge
    /// fails on the nonce-bound context.
    #[error("execution digest does not match the expected program trace of the challenge")]
    ExecutionMismatch,
}

impl VerifyError {
    /// The stable machine-readable wire code for this failure, matching
    /// the PHP SDK's `VerifyError::value` vocabulary case-for-case
    /// (`bad_signature`, `expired`, ...): every PHP code has a Rust twin
    /// carrying the identical wire code. Metrics, alerting and retry
    /// branching must key on these codes — never on the human `Display`
    /// prose. The one documented name-mapping divergence: the Rust
    /// variant `BotDetected` carries PHP's `telemetry_rejected` code
    /// (the same failure class — the variant name is Rust-idiomatic,
    /// the wire code is shared). The one Rust-only code is
    /// `counter_too_large` (this core rejects oversized counters
    /// outright; the PHP decoder maps them to `malformed_token`). The
    /// cross-language drift gate lives in
    /// `tools/verify-error-code-parity.sh`, which parses the PHP enum
    /// and this mapping directly.
    pub fn code(&self) -> &'static str {
        match self {
            Self::BadSignature => "bad_signature",
            Self::Expired => "expired",
            Self::TooFast => "too_fast",
            Self::IpMismatch => "ip_mismatch",
            Self::MissingClientIp => "missing_client_ip",
            Self::CounterTooLarge => "counter_too_large",
            Self::WrongScope => "wrong_scope",
            Self::RequestBindingMismatch => "request_binding_mismatch",
            Self::WrongRegion => "wrong_region",
            Self::WrongIssuer => "wrong_issuer",
            Self::WrongPolicyVersion => "wrong_policy_version",
            Self::UnknownKid => "unknown_kid",
            Self::TooManyAttempts => "too_many_attempts",
            Self::InsufficientWork => "insufficient_work",
            Self::MalformedRecord => "malformed_record",
            Self::UnsupportedArgon2Params => "unsupported_argon2_params",
            Self::UnsupportedRswParams => "unsupported_rsw_params",
            // PHP's `telemetry_rejected` — the same failure class: the
            // client-side telemetry evidence rejected this client. The
            // variant name is Rust-idiomatic; the wire code is shared.
            Self::BotDetected => "telemetry_rejected",
            Self::MalformedToken => "malformed_token",
            Self::RecordNotFound => "record_not_found",
            Self::StorageUnavailable => "storage_unavailable",
            Self::ConsumeIndeterminate => "consume_indeterminate",
            Self::AlreadyConsumed => "already_consumed",
            Self::CapacityExceeded => "capacity_exceeded",
            Self::AdmissionUnavailable => "admission_unavailable",
            Self::ExecutionMismatch => "execution_mismatch",
        }
    }

    /// Whether this failure is exempt from the one-shot policy on a
    /// consumed record: the failure describes the original redemption's
    /// circumstances (the signed expiry, the network binding, the
    /// missing client IP, the client-side telemetry evidence) rather
    /// than this request's authorization, so a consumed record whose
    /// retained committed success is replayed by the proven operation
    /// may resolve through the consumed branch despite it.
    ///
    /// The exemption is deliberately narrow. Every security verdict —
    /// wrong scope, request-binding mismatch, policy epoch, region,
    /// issuer, kid revocation/resolution, signature, record shape, the
    /// execution binding, the unsupported protocol/profile, and the
    /// receipt-timing floor —
    /// stands even when the operation identity matches: the stored
    /// success never replays around it (the record is kept intact and
    /// the failure is returned).
    pub fn is_replay_exempt(&self) -> bool {
        matches!(
            self,
            VerifyError::Expired
                | VerifyError::IpMismatch
                | VerifyError::MissingClientIp
                | VerifyError::BotDetected
        )
    }
}

/// Structural validation of a stored [`ChallengeRecord`].
///
/// Runs as the first check of [`verify_solution`] (after attempt accounting),
/// before any hash is derived, so a malformed or attacker-crafted record can
/// never drive an expensive verification:
/// - `scope` 1..=128 bytes of `[A-Za-z0-9._:-]`;
/// - `issuer` / `region` / `request_binding`, when set, match the same
///   narrow alphabet with the length caps (issuer 128, request_binding 128,
///   region 64);
/// - `nonce` decodes as base64 to exactly 32 bytes (44-char pre-bound before
///   decode);
/// - `salt` decodes as base64 to exactly 16 bytes (24-char pre-bound before
///   decode);
/// - `expires_at > issued_at` and the lifetime stays within the protocol
///   TTL cap;
/// - `prefix` is exactly `challenge|salt|`;
/// - `target_bits` within the explicit difficulty bounds for both algorithms
///   (the Argon2id issuance ceiling stays stricter at the solver's argon2
///   target-bits cap, exactly like the t=7..=16 verifier-vs-issuer split);
/// - the protocol-vs-decoy-vs-execution grammar: v2 => no decoy, v3 =>
///   decoy present, v2/v3 => no execution, v4 => execution present (the
///   exact armed/unarmed equivalence: signed commitment absent <=> stored
///   program absent, present <=> present, `execution_version` within the
///   canonical register 1..=MAX_EXECUTION_VERSION, commitment exactly 64
///   lowercase hex, and SHA256(stored program) == the signed commitment,
///   constant-time).
///
/// Argon2id memory/time/parallelism are deliberately NOT bounded here —
/// the absolute process ceilings apply to the signed parameters after
/// signature authentication (see [`check_argon2_ceilings`]), exactly like
/// the PHP core's structural validator: a validly signed out-of-range
/// record is [`VerifyError::UnsupportedArgon2Params`] rather than
/// [`VerifyError::MalformedRecord`], while an unsigned foreign record
/// fails the signature check instead. The allocation safety is unchanged:
/// the ceilings are re-enforced at every computation site
/// ([`derive_hash`] re-checks before any `Params::new`).
///
/// Returns [`VerifyError::MalformedRecord`] on any violation.
pub fn validate_record(record: &ChallengeRecord) -> Result<(), VerifyError> {
    // Protocol version is part of the wire contract: 1 (legacy, migration
    // window), 2 (unarmed), 3 (decoy-capable) and 4 (execution-capable)
    // exist — anything else is a corrupt/foreign record. The
    // protocol-vs-decoy-vs-execution grammar is explicit and total: the
    // tagged `d=` segment is a protocol v3/v4 canonical extension, so
    // a v2 record carrying a `decoy_field` is rejected here (the v2
    // canonical never includes the segment and such a record cannot have
    // been signed by a conforming issuer — an armed issuance writes
    // protocol v3), and a v3 record without a decoy is rejected too: the
    // decoy is mandatory on v3, so a signed v2 record with its stored
    // version flipped to 3 can never verify (the canonical shape itself
    // authenticates the protocol capability). The execution segments are
    // a v4 canonical extension: a v2/v3 record carrying any execution
    // field is rejected, and a v4 record without the execution triplet
    // (program + version + commitment) is rejected too, so a signed v2/v3
    // record with its stored version flipped to 4 keeps the plain
    // canonical bytes and is refused here. v1 and v2 accept a null decoy
    // and a null execution triplet; v3 requires a present decoy; v4
    // requires the execution triplet.
    if !(1..=crate::challenge::MAX_PROTOCOL_VERSION).contains(&record.protocol_version) {
        return Err(VerifyError::MalformedRecord);
    }
    // The record-metadata MAC, when present, has the exact wire shape
    // (64 lowercase hex) — the PHP ChallengeRecord boundary twin.
    if let Some(tag) = record.server_mac.as_deref() {
        if !crate::challenge::is_server_state_mac_shape(tag) {
            return Err(VerifyError::MalformedRecord);
        }
    }
    // The protocol-vs-extension grammar is the one shared table (the
    // stored-record decoder applies the same matrix at its boundary),
    // so the verifier and the decoder can never disagree about which
    // records are structurally valid.
    if !crate::challenge::protocol_extension_grammar_ok(
        record.protocol_version,
        record.decoy_field.is_some(),
        record.execution_program.is_some(),
        record.rsw_modulus_sha256.is_some(),
    ) {
        return Err(VerifyError::MalformedRecord);
    }
    // The authenticated rsw modulus identity: when present it must be 64
    // lowercase hex and may only ride an rsw record (the stored-record
    // decoder enforces the same on the persisted path; this closes the
    // hand-rolled-record surface). The grammar above guarantees a v5
    // record always carries it and a v2..=4 record's identity is the
    // pre-v5 legacy shape.
    if let Some(identity) = record.rsw_modulus_sha256.as_deref() {
        if record.algorithm != PoWAlgorithm::Rsw
            || identity.len() != 64
            || !identity
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(VerifyError::MalformedRecord);
        }
    }
    let execution_present = record.execution_program.is_some();
    // The exact armed/unarmed equivalence contract: the
    // signed commitment is the exact mirror of the stored program.
    // A hand-rolled record that carries a program without the commitment
    // triplet, a commitment without the program, or a program whose hash
    // does not match the signed commitment is a corrupt or foreign
    // record — stripping, substituting or injecting a program always
    // invalidates the challenge. The commitment compare is constant-time
    // (ct_eq).
    // The record's `execution_version` register is the canonical
    // execution-version set 1..=MAX_EXECUTION_VERSION — the exact set the
    // PHP record/verifier gate accepts, so a PHP-issued armed record at
    // the current maximum verifies here — anything else is corrupt or
    // foreign.
    if execution_present {
        if !record
            .execution_version
            .is_some_and(|v| (1..=crate::execution::MAX_EXECUTION_VERSION).contains(&v))
            || record.execution_commitment.is_none()
        {
            return Err(VerifyError::MalformedRecord);
        }
        let commitment = record.execution_commitment.as_deref().unwrap_or("");
        if commitment.len() != 64
            || !commitment
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(VerifyError::MalformedRecord);
        }
        let expected = crate::challenge::execution_commitment(
            record.execution_program.as_deref().unwrap_or(""),
        );
        if !ct_eq(expected.as_bytes(), commitment.as_bytes()) {
            return Err(VerifyError::MalformedRecord);
        }
    } else if record.execution_version.is_some() || record.execution_commitment.is_some() {
        return Err(VerifyError::MalformedRecord);
    }
    if !crate::challenge::valid_identifier(&record.scope, 128) {
        return Err(VerifyError::MalformedRecord);
    }
    // The same narrow identifier alphabet applies to the optional
    // identifiers — a non-conforming value (Unicode, spaces, empty string)
    // is a malformed record.
    if let Some(issuer) = record.issuer.as_deref() {
        if !crate::challenge::valid_identifier(issuer, 128) {
            return Err(VerifyError::MalformedRecord);
        }
    }
    if let Some(region) = record.region.as_deref() {
        if !crate::challenge::valid_identifier(region, 64) {
            return Err(VerifyError::MalformedRecord);
        }
    }
    if let Some(binding) = record.request_binding.as_deref() {
        if !crate::challenge::valid_identifier(binding, 128) {
            return Err(VerifyError::MalformedRecord);
        }
    }
    // The decoy (honeypot) field name is an authenticated protocol v3
    // canonical field: when present it must match the exact shape the
    // issuer mints and the widget driver renders — 1..=64 bytes of
    // `[A-Za-z0-9_-]` (no `.`, `:` or `|`, so the canonical segment
    // structure can never be altered by a stored value). A non-conforming
    // name is a corrupt or foreign record.
    if let Some(decoy) = record.decoy_field.as_deref() {
        if !crate::challenge::valid_decoy_field_name(decoy) {
            return Err(VerifyError::MalformedRecord);
        }
    }
    // The server-side hostname metadata is validated on read — a label of at
    // most 4096 bytes with no whitespace/control characters, or None. It is
    // NOT part of the signed security payload, so this is interoperability
    // rigor, not a verification boundary.
    if let Some(hostname) = record.hostname.as_deref() {
        if hostname.is_empty()
            || hostname.len() > 4096
            || hostname.bytes().any(|b| b <= 0x20 || b == 0x7f)
        {
            return Err(VerifyError::MalformedRecord);
        }
    }
    // Exact-length pre-bounds before any base64 decode — the
    // nonce is the 44-char base64 of 32 bytes and the salt the 24-char
    // base64 of 16 bytes. An oversized (attacker-written) value is rejected
    // as malformed without allocating a decode buffer for it.
    if record.nonce.len() != 44 || record.salt.len() != 24 {
        return Err(VerifyError::MalformedRecord);
    }
    match B64.decode(&record.nonce) {
        Ok(bytes) if bytes.len() == 32 => {}
        _ => return Err(VerifyError::MalformedRecord),
    }
    match B64.decode(&record.salt) {
        Ok(bytes) if bytes.len() == 16 => {}
        _ => return Err(VerifyError::MalformedRecord),
    }
    if record.expires_at <= record.issued_at {
        return Err(VerifyError::MalformedRecord);
    }
    if record.expires_at - record.issued_at > crate::challenge::MAX_TTL_SECS {
        return Err(VerifyError::MalformedRecord);
    }
    if record.prefix != format!("{}|{}|", record.challenge, record.salt) {
        return Err(VerifyError::MalformedRecord);
    }
    // The difficulty bounds are explicit constants, applied to
    // both algorithms — 0 would accept a trivially-solvable challenge and
    // anything above the solver ceiling can never be produced by a widget.
    use crate::challenge::{MAX_DIFFICULTY, MIN_DIFFICULTY};
    if record.target_bits < MIN_DIFFICULTY || record.target_bits > MAX_DIFFICULTY {
        return Err(VerifyError::MalformedRecord);
    }
    Ok(())
}

/// Validate the hard Argon2id parameter ceilings.
///
/// Checks `m_kib`/`t`/`p` against the hard Argon2id parameter ceilings —
/// the verifier must never run (or allocate for) a memory-hard computation
/// with parameters outside these bounds, even when the record is properly
/// signed.
///
/// Returns [`VerifyError::UnsupportedArgon2Params`] when any parameter is
/// out of range — the PHP core's twin code for the same condition (a
/// signed record violating the process ceilings is authentic but
/// unsupported, not malformed). Called after signature authentication in
/// [`verify_solution`] and the production verifier, and re-checked at the
/// computation site in [`derive_hash`], so no allocation can happen for
/// an out-of-bounds parameter set.
pub(crate) fn check_argon2_ceilings(record: &ChallengeRecord) -> Result<(), VerifyError> {
    use crate::challenge::{
        MAX_ARGON_MEMORY_KIB, MAX_ARGON_TIME, MAX_PARALLELISM, MIN_ARGON_MEMORY_KIB,
        MIN_ARGON_TIME, MIN_PARALLELISM,
    };
    if record.m_kib < MIN_ARGON_MEMORY_KIB
        || record.m_kib > MAX_ARGON_MEMORY_KIB
        || record.t < MIN_ARGON_TIME
        || record.t > MAX_ARGON_TIME
        || record.p < MIN_PARALLELISM
        || record.p > MAX_PARALLELISM
    {
        return Err(VerifyError::UnsupportedArgon2Params);
    }
    Ok(())
}

/// The rsw process bound: a signed rsw record's sequential cost T,
/// carried in the time-cost slot, must sit within the issuance range
/// (10,000..=300,000). The verifier-side trapdoor check costs one
/// modular exponentiation regardless of T, so the bound keeps the
/// signed parameter space canonical rather than capping server work.
/// Returns [`VerifyError::UnsupportedRswParams`] for an out-of-range
/// signed record, the authentic-but-unsupported Argon2id ceiling
/// split, and succeeds for every non-rsw record. Mirrors the
/// PHP `Verifier::rswParamsOk`.
pub(crate) fn check_rsw_params(record: &ChallengeRecord) -> Result<(), VerifyError> {
    use crate::challenge::{MAX_RSW_T, MIN_RSW_T};
    if record.algorithm != PoWAlgorithm::Rsw {
        return Ok(());
    }
    if record.t < MIN_RSW_T || record.t > MAX_RSW_T {
        return Err(VerifyError::UnsupportedRswParams);
    }
    Ok(())
}

/// The per-algorithm proof verdict of a presented token against a
/// record. SHA-256 and Argon2id re-derive the hash and compare the
/// leading zero bits; an rsw record compares the presented final value
/// (the optional final token segment) against the trapdoor expectation
/// in constant time over the fixed 512-hex wire form. The proof
/// vocabulary is algorithm-total: an rsw record demands counter 0 AND a
/// presented final value (any other token shape is InsufficientWork),
/// and a non-rsw record rejects a presented rsw final value outright.
/// `trapdoor` is the verifier's configured rsw pair, `None` when the
/// deployment does not verify rsw records (an rsw record then yields
/// [`VerifyError::UnsupportedRswParams`], the authentic-but-unsupported
/// semantics the PHP core mirrors). Returns
/// [`VerifyError::UnsupportedArgon2Params`] for an Argon2id parameter
/// set the verifier refuses to represent.
pub(crate) fn proof_is_valid(
    record: &ChallengeRecord,
    counter: u64,
    rsw_proof: Option<&str>,
    trapdoor: Option<&RswTrapdoor>,
) -> Result<bool, VerifyError> {
    match record.algorithm {
        PoWAlgorithm::Rsw => {
            let Some(trapdoor) = trapdoor else {
                return Err(VerifyError::UnsupportedRswParams);
            };
            // The rsw composition invariant: an rsw record's solution
            // must carry counter 0 (a time-lock proof has no search
            // counter) AND a non-null rsw final value — any other token
            // shape is rejected outright, never compared.
            if counter != 0 {
                return Ok(false);
            }
            let Some(proof) = rsw_proof else {
                return Ok(false);
            };
            let expected =
                trapdoor.expected_proof_hex(&record.prefix, &record.nonce, record.t as u64);
            Ok(ct_eq(expected.as_bytes(), proof.as_bytes()))
        }
        PoWAlgorithm::Sha256 | PoWAlgorithm::Argon2id => {
            // The mirror invariant for every non-rsw algorithm: an rsw
            // final value is rsw evidence only, so a sha256/argon2id
            // record presented with a token carrying one is rejected
            // outright — the hash is never derived for it.
            if rsw_proof.is_some() {
                return Ok(false);
            }
            let hash = derive_hash(record, counter)?;
            Ok(leading_zero_bits(&hash) >= record.target_bits)
        }
    }
}

/// Verify a solution against its stored challenge record.
///
/// This performs the full server-side check:
/// 1. Attempt accounting: `record.attempts_used` is incremented; when it
///    exceeds `max_attempts` (and `max_attempts > 0`) the solution is
///    rejected with [`VerifyError::TooManyAttempts`]. The caller persists the
///    mutated record on failure, or consumes it on success (single-use).
/// 2. Structural record validation ([`validate_record`]) — a cheap phase that
///    runs before any hash is derived, so malformed or attacker-crafted
///    records can never drive expensive verification work.
/// 3. Re-verify the HMAC signature over the protocol-appropriate canonical
///    input (v1 for `protocol_version == 1` records, v2 otherwise; v2
///    signatures use the `HKDF`-derived challenge key). When
///    `secrets_by_kid` is configured, the record's `kid` selects the secret:
///    an unknown — or future — kid rejects with
///    [`VerifyError::UnknownKid`] before any signature work. A revoked kid
///    (`revoked_kids`) rejects with [`VerifyError::UnknownKid`]
///    even earlier, before the signature check, even when its secret is
///    present: compromise revocation overrides the rotation grace.
/// 4. Hard Argon2id parameter ceilings — after signature
///    authentication, before any `Params::new`/allocation.
/// 5. Check the TTL (defends against stale challenges).
/// 6. Check the scope (prevents cross-scope replay) →
///    [`VerifyError::WrongScope`], then the application transaction
///    binding, then the IP binding — the PHP `cheapPhaseCheck` precedence
///    (shape → TTL → scope+request binding → IP binding → deployment
///    expectations → floor), so a record failing several invariants
///    reports the same error code in both languages.
/// 7. Check the IP binding: for v2 records, recompute the nonce-bound
///    `binding_tag` from `client_ip` + record nonce + secret and compare in
///    constant time; for v1 records, compare the legacy `hash_ip`. An empty
///    `binding_tag` skips the check. A `None` `client_ip` with a non-empty
///    tag fails closed with [`VerifyError::MissingClientIp`] — only records
///    issued with `BindingMode::None` (empty tag) verify without an IP.
/// 8. Check the region (when `expected_region` is set) →
///    [`VerifyError::WrongRegion`], the security-policy epoch and the
///    issuer (the deployment expectations, after the IP binding).
/// 9. Check the minimum duration with the server clock, honoring the
///    clock-skew tolerance. The client-reported
///    duration is forgeable and is never trusted for this check. Records
///    without `issued_at_ns` are malformed (there is no client-duration
///    fallback).
/// 10. Optional telemetry scoring (when `enforce_telemetry` is set).
/// 11. Re-derive the SHA-256/Argon2id hash and check leading zero bits (the
///     actual PoW). The valid outcome's `nonce` field carries the consumed
///     canonical nonce (jti).
///
/// Read the verifier's clock. An injected closure wins when one is
/// supplied (deterministic tests, specialized applications); otherwise
/// the real system clock in Unix seconds is used — the safe default
/// that makes the mid-derive expiry check real for every integration
/// that does not deliberately inject a clock.
fn read_clock(ctx: &mut VerifyContext<'_>) -> u64 {
    match &mut ctx.now_unix {
        Some(clock) => clock(),
        None => real_now_unix(),
    }
}

/// The real system clock in Unix seconds. A failed clock read keeps the
/// fail-closed value 0 and warns: every expiry check treats 0 as
/// long-expired, so a broken clock rejects challenges instead of
/// accepting stale ones.
pub(crate) fn real_now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or_else(|_| {
            tracing::warn!(
                "KiwiCaptcha: system clock read failed — verification clock falls back to 0"
            );
            0
        })
}

/// The server-measured solve duration of a verified record, in
/// milliseconds: the span between the record's high-resolution
/// issuance timestamp (`issued_at_ns`, epoch microseconds written by
/// the issuing host) and this verification's receipt instant — the
/// same single receipt the server-measured minimum-duration floor
/// reads, never a second clock read. Carried on every valid outcome
/// as unforgeable behavioral evidence for the risk layer — the
/// client-reported token duration is forgeable and never consulted.
/// The PHP `measurableSolveDurationMs()` mirror.
///
/// The skew-tolerance semantics mirror the minimum-duration floor
/// exactly: a receipt that precedes issuance is unmeasurable (within
/// the tolerance the two hosts' clocks are unsynced, so the elapsed
/// time cannot be measured reliably — `None`; beyond the tolerance
/// the record is rejected as `TooFast` and never reaches a valid
/// outcome). A record whose issuance clock is unknown
/// (`issued_at_ns == 0`) or unauthenticated (no `server_mac`; the MAC
/// itself is verified with the signature) is equally unmeasurable.
/// Sub-millisecond spans floor toward zero.
pub(crate) fn measurable_solve_duration_ms(
    record: &ChallengeRecord,
    receipt_ns: u64,
) -> Option<u64> {
    if record.server_mac.is_none() || record.issued_at_ns == 0 || receipt_ns < record.issued_at_ns {
        return None;
    }
    Some((receipt_ns - record.issued_at_ns) / 1_000)
}

/// The ExecutionChallengeV1 binding (hard), shared verbatim by
/// [`verify_solution`] and the Redis-backed production verifier (see
/// `crate::redis_verify`): an armed record demands a presented execution
/// digest that matches the expected digest recomputed from the stored
/// program and the presented trace; a missing or mismatched digest is
/// the deterministic [`VerifyError::ExecutionMismatch`]. An unarmed
/// record (no stored program, no signed commitment) demands no
/// evidence: a presented digest or trace is stray execution evidence
/// and is rejected with the deterministic
/// [`VerifyError::ExecutionMismatch`] — never silently ignored, because
/// the signed canonical carries no commitment, so no digest can be
/// legitimate for it. The expected digest is a pure function of
/// (program, nonce): the program embeds the scope/action/version
/// context and the trace is deterministic, so the verifier needs no
/// secret to recompute it. The comparison is constant-time (ct_eq).
pub(crate) fn check_execution_binding(
    record: &ChallengeRecord,
    execution_digest: Option<&str>,
    execution_trace: Option<&str>,
) -> Result<(), VerifyError> {
    match record.execution_program.as_deref() {
        Some(program) => match (execution_digest, execution_trace) {
            (None, _) | (_, None) => Err(VerifyError::ExecutionMismatch),
            (Some(presented), Some(trace_b64)) => {
                // The trace travels on the wire as base64url, unpadded
                // (the driver's format); translate back to canonical
                // standard base64 (re-pad) before the strict decode.
                let standard: String = trace_b64
                    .chars()
                    .map(|c| match c {
                        '-' => '+',
                        '_' => '/',
                        c => c,
                    })
                    .collect();
                let padded = format!("{}{}", standard, "=".repeat((4 - standard.len() % 4) % 4));
                let trace = match B64.decode(padded) {
                    Ok(bytes)
                        if {
                            let out: String = B64
                                .encode(&bytes)
                                .replace('+', "-")
                                .replace('/', "_")
                                .trim_end_matches('=')
                                .to_string();
                            out == *trace_b64
                        } =>
                    {
                        String::from_utf8(bytes).ok()
                    }
                    _ => None,
                };
                // The program decodes exactly once: the trace walk and
                // the digest computation below share the parsed program.
                let Some(trace) = trace else {
                    return Err(VerifyError::ExecutionMismatch);
                };
                let Some(decoded) = crate::execution::decode(program) else {
                    return Err(VerifyError::ExecutionMismatch);
                };
                let Some(verified) =
                    crate::execution::verify_executed_trace_decoded(&decoded, &trace)
                else {
                    return Err(VerifyError::ExecutionMismatch);
                };
                let Some(expected) = crate::execution::expected_digest_over_trace_decoded(
                    program,
                    &decoded,
                    &record.nonce,
                    &verified,
                ) else {
                    // The record's program failed the parse
                    // (validate_record already rejects this shape;
                    // defense in depth).
                    return Err(VerifyError::MalformedRecord);
                };
                if !ct_eq(expected.as_bytes(), presented.as_bytes()) {
                    return Err(VerifyError::ExecutionMismatch);
                }
                Ok(())
            }
        },
        // Stray execution evidence: a digest presented for a record
        // whose signed canonical carries NO commitment is deterministic
        // invalid, never silently ignored.
        None => {
            if execution_digest.is_some() || execution_trace.is_some() {
                return Err(VerifyError::ExecutionMismatch);
            }
            Ok(())
        }
    }
}

/// One verification call's execution-evidence memo: the armed-record
/// check (program decode, trace walk, digest) is a pure function of
/// the stored program, the record nonce and the presented evidence, so
/// the post-consume re-check of the same inputs reuses the first
/// verdict instead of re-deriving it. The entry is keyed by the full
/// input tuple — any change is a miss and re-derives — and the cache
/// lives for a single verification, never across calls (a later
/// verification of the same record re-derives from scratch).
#[cfg(feature = "redis")] // the production verifier (redis_verify) is the sole consumer
#[derive(Default)]
pub(crate) struct ExecutionEvidenceCache {
    entry: Option<ExecutionEvidenceEntry>,
}

#[cfg(feature = "redis")]
struct ExecutionEvidenceEntry {
    program: String,
    nonce: String,
    digest: Option<String>,
    trace: Option<String>,
    verdict: Result<(), VerifyError>,
}

/// The cached [`check_execution_binding`]: an armed record consults the
/// single-entry memo first; an unarmed record (the cheap majority)
/// bypasses the cache entirely.
#[cfg(feature = "redis")] // the production verifier (redis_verify) is the sole consumer
pub(crate) fn check_execution_binding_cached(
    record: &ChallengeRecord,
    execution_digest: Option<&str>,
    execution_trace: Option<&str>,
    cache: &mut ExecutionEvidenceCache,
) -> Result<(), VerifyError> {
    let Some(program) = record.execution_program.as_deref() else {
        return check_execution_binding(record, execution_digest, execution_trace);
    };
    if let Some(entry) = &cache.entry {
        if entry.program == program
            && entry.nonce == record.nonce
            && entry.digest.as_deref() == execution_digest
            && entry.trace.as_deref() == execution_trace
        {
            return entry.verdict.clone();
        }
    }
    let verdict = check_execution_binding(record, execution_digest, execution_trace);
    cache.entry = Some(ExecutionEvidenceEntry {
        program: program.to_string(),
        nonce: record.nonce.clone(),
        digest: execution_digest.map(str::to_string),
        trace: execution_trace.map(str::to_string),
        verdict: verdict.clone(),
    });
    verdict
}

pub fn verify_solution(ctx: &mut VerifyContext<'_>) -> VerifyOutcome {
    // 0. Attempt accounting — counted on every verification call, correct or
    //    not, so a wrong-candidate loop cannot burn unbounded server-side
    //    computation (especially memory-hard Argon2id hashing).
    ctx.record.attempts_used = ctx.record.attempts_used.saturating_add(1);
    if ctx.max_attempts > 0 && ctx.record.attempts_used > ctx.max_attempts {
        return VerifyOutcome::Invalid(VerifyError::TooManyAttempts);
    }

    // 0b. Cheap structural validation first — before any signature work or
    //     hash derivation (XII): a malformed record can never drive an
    //     expensive verification.
    if let Err(e) = validate_record(ctx.record) {
        return VerifyOutcome::Invalid(e);
    }

    // 0c. Counter bound: the official solvers never search beyond the
    //     solver cap; a larger counter is not a legitimate solution and
    //     must not reach hash derivation (deterministic rejection).
    if ctx.counter >= crate::challenge::SOLVER_MAX_HASHES {
        return VerifyOutcome::Invalid(VerifyError::CounterTooLarge);
    }

    // 1. Protocol version gate: v1 (legacy, less comprehensively signed) is
    //    only accepted during an explicit migration window — v2 has been the
    //    issuance format longer than the maximum challenge lifetime, so any
    //    surviving v1 record is stale or foreign.
    if ctx.record.protocol_version == 1 && !ctx.accept_legacy_v1 {
        return VerifyOutcome::Invalid(VerifyError::MalformedRecord);
    }

    // 1a. Key-rotation resolution: when a `secrets_by_kid` map
    //     is configured, the record's kid selects the signing secret. An
    //     unknown kid — or a kid newer than the map's newest id (the
    //     forward/rollback guard: future-keyed challenges must never verify
    //     on older nodes, even if the key were somehow known) — is rejected
    //     with UnknownKid before any signature work.
    //     Compromise revocation is checked first: a revoked kid is
    //     rejected immediately, before the signature check, even when its
    //     secret is still present in `secrets_by_kid` (or the single-key
    //     path): revocation overrides the rotation grace.
    if let Some(revoked) = ctx.revoked_kids {
        if revoked.contains(&ctx.record.kid) {
            return VerifyOutcome::Invalid(VerifyError::UnknownKid);
        }
    }
    let secret: &str = match ctx.secrets_by_kid {
        Some(secrets) => {
            let max_kid = secrets.keys().max().copied().unwrap_or(0);
            if ctx.record.kid > max_kid {
                return VerifyOutcome::Invalid(VerifyError::UnknownKid);
            }
            match secrets.get(&ctx.record.kid) {
                Some(secret) => secret.as_str(),
                None => return VerifyOutcome::Invalid(VerifyError::UnknownKid),
            }
        }
        None => ctx.secret_key,
    };

    // 1b. Signature re-check over the protocol-appropriate canonical input.
    let sig = signature_from_challenge(ctx.record);
    let sig_ok = match ctx.record.protocol_version {
        // Legacy v1 records: `nonce|scope|ip_hash|issued_at` (the binding
        // field carried the legacy hash_ip). Verified for the migration
        // window (max TTL) alongside v2.
        1 => verify_signature(&payload_from_record(ctx.record), sig, secret),
        _ => verify_signature_v2_with_tenant(ctx.record, sig, secret, ctx.tenant),
    };
    match sig_ok {
        Ok(true) => {}
        Ok(false) => return VerifyOutcome::Invalid(VerifyError::BadSignature),
        Err(_) => return VerifyOutcome::Invalid(VerifyError::BadSignature),
    }
    // 1b'. The record-metadata MAC: when the signed canonical commits
    //      the m=1 marker, a valid `server_mac` is required and verified
    //      regardless of the timing floor. A present MAC always verifies.
    //      A rewritten issuance clock or hostname is a forged record
    //      (BadSignature), exactly like the PHP verifier.
    let signed_mac = crate::challenge::signed_canonical_commits_record_meta(&ctx.record.challenge);
    if signed_mac && ctx.record.server_mac.is_none() {
        return VerifyOutcome::Invalid(VerifyError::BadSignature);
    }
    if ctx.record.server_mac.is_some()
        && !crate::challenge::verify_record_meta(
            &crate::keys::DerivedKeys::from_master(secret, ctx.tenant),
            ctx.record,
        )
    {
        return VerifyOutcome::Invalid(VerifyError::BadSignature);
    }

    // 1b''. Hard Argon2id parameter ceilings — validated after the
    //     signature has been authenticated and before any Params::new or
    //     memory allocation: even a properly signed record must never drive
    //     an out-of-bounds memory-hard computation.
    if ctx.record.algorithm == PoWAlgorithm::Argon2id {
        if let Err(e) = check_argon2_ceilings(ctx.record) {
            return VerifyOutcome::Invalid(e);
        }
    }
    // 1c. The rsw process bound — the same authentic-but-unsupported
    //     split: a signed rsw record whose sequential cost T sits outside
    //     the issuance range is refused before any trapdoor work.
    if ctx.record.algorithm == PoWAlgorithm::Rsw {
        if let Err(e) = check_rsw_params(ctx.record) {
            return VerifyOutcome::Invalid(e);
        }
    }

    // 2. TTL. The challenge is invalid outside its validity window
    //    [issued_at, expires_at): expired once now reaches expires_at, and
    //    a future-issued challenge is a time-domain anomaly
    //    when its issued_at is more than the clock-skew bound ahead of the
    //    verifier clock — the issuer and verifier clocks are broken. The
    //    first clock read happens here (the receipt time); the clock is
    //    read again after the derivation for the final re-validation, so
    //    a challenge that expires mid-derive is detected. With no
    //    injected clock (the safe default) the verifier reads the real
    //    system clock.
    let receipt_now = read_clock(ctx);
    if receipt_now >= ctx.record.expires_at {
        return VerifyOutcome::Invalid(VerifyError::Expired);
    }
    if ctx.record.issued_at > receipt_now.saturating_add(crate::challenge::MAX_CLOCK_SKEW_SECS) {
        return VerifyOutcome::Invalid(VerifyError::Expired);
    }

    // 2b. Scope validation: reject if the challenge was issued for a different
    //     auth flow (e.g. a login challenge used on /signup).
    if let Some(expected) = ctx.expected_scope {
        if ctx.record.scope != expected {
            return VerifyOutcome::Invalid(VerifyError::WrongScope);
        }
    }

    // 2b. Application transaction binding (exact Option-equality via the
    //     shared helper).
    if let Err(e) = check_request_binding(
        ctx.record.request_binding.as_deref(),
        ctx.expected_request_binding,
    ) {
        return VerifyOutcome::Invalid(e);
    }

    // 2c. IP binding: the challenge was issued to a client IP; a different
    //     submission IP means the token was relayed. Enforced here (not just
    //     at the route layer) so the secure behavior cannot be forgotten.
    //     The stored record is authoritative: an empty binding tag means
    //     binding is disabled (BindingMode::None) and the check is skipped; a
    //     non-empty tag means the challenge is bound, so a missing client IP
    //     fails closed (MissingClientIp) instead of silently skipping the
    //     check. Checked before the region/policy/issuer expectations, the
    //     PHP cheapPhaseCheck precedence (shape → TTL → scope+request
    //     binding → IP binding → deployment expectations → floor), so a
    //     record failing several invariants reports the same error code in
    //     both languages.
    if !ctx.record.binding_tag.is_empty() {
        let Some(client_ip) = ctx.client_ip else {
            return VerifyOutcome::Invalid(VerifyError::MissingClientIp);
        };
        let expected = match ctx.record.protocol_version {
            1 => hash_ip(client_ip, secret),
            _ => match binding_tag_for_tenant(&ctx.record.nonce, client_ip, secret, ctx.tenant) {
                Ok(tag) => tag,
                Err(_) => return VerifyOutcome::Invalid(VerifyError::IpMismatch),
            },
        };
        if !ct_eq(ctx.record.binding_tag.as_bytes(), expected.as_bytes()) {
            return VerifyOutcome::Invalid(VerifyError::IpMismatch);
        }
    }

    // 2d. Region validation: a deployment that expects a region
    //     rejects challenges issued for a different region — or for no region
    //     at all (fail closed).
    if let Some(expected) = ctx.expected_region {
        if ctx.record.region.as_deref() != Some(expected) {
            return VerifyOutcome::Invalid(VerifyError::WrongRegion);
        }
    }

    // 7b. Security-policy epoch: the policy that authorized this challenge
    //     must still be in force (or, during a declared rollout window, be
    //     one of the two in-flight epochs — see [`policy_version_accepted`]).
    if !policy_version_accepted(
        ctx.record.policy_version,
        ctx.expected_policy_version,
        ctx.policy_version_floor,
    ) {
        return VerifyOutcome::Invalid(VerifyError::WrongPolicyVersion);
    }

    // 7c. Issuer identity: a verifier that expects a specific
    //     issuer rejects challenges issued by another issuer — or by no
    //     issuer at all (fail closed, like the region expectation).
    if let Some(expected) = ctx.expected_issuer {
        if ctx.record.issuer.as_deref() != Some(expected) {
            return VerifyOutcome::Invalid(VerifyError::WrongIssuer);
        }
    }

    // 7d. The ExecutionChallengeV1 binding (hard): an armed record
    //     demands a presented execution digest that matches the expected
    //     digest recomputed from the stored program; a missing or
    //     mismatched digest is the deterministic ExecutionMismatch. An
    //     unarmed record (no stored program, no signed commitment)
    //     demands no digest: a presented digest is stray execution
    //     evidence and is rejected with the deterministic
    //     ExecutionMismatch — never silently ignored, because the signed
    //     canonical carries no commitment, so no digest can be
    //     legitimate for it. The expected digest is a pure function of
    //     (program, nonce): the program embeds the scope/action/version
    //     context and the trace is deterministic, so the verifier needs
    //     no secret to recompute it. The comparison is constant-time
    //     (ct_eq). The shared [`check_execution_binding`] carries the
    //     exact same semantics on the Redis-backed production path.
    if let Err(e) = check_execution_binding(ctx.record, ctx.execution_digest, ctx.execution_trace) {
        return VerifyOutcome::Invalid(e);
    }

    // 3. Minimum duration — server-measured. The client-reported duration_ms
    //    is forgeable and is deliberately not trusted for enforcement. The
    //    floor is a timing-anomaly heuristic: a fast bot can wait before
    //    submitting, so it only rejects solves that arrive faster than the
    //    theoretical minimum. Records without a high-resolution issuance
    //    timestamp are malformed — there is no client-duration fallback. This
    //    is enforced unconditionally (even when the timing floor is disabled)
    //    to match the PHP verifier exactly.
    if ctx.record.issued_at_ns == 0 {
        return VerifyOutcome::Invalid(VerifyError::MalformedRecord);
    }
    let floor = ctx.min_duration_ms.max(ctx.record.min_duration_ms);
    if floor > 0 && ctx.record.server_mac.is_none() {
        // The issuance clock is unauthenticated (no record-metadata
        // MAC): a storage writer could have backdated it, so the floor
        // cannot be evaluated and fails closed.
        return VerifyOutcome::Invalid(VerifyError::MalformedRecord);
    }
    if floor > 0 {
        if ctx.now_ns >= ctx.record.issued_at_ns {
            // High-resolution path: elapsed time between issuance and receipt,
            // both observed by the server clock. Both `now_ns` and
            // `issued_at_ns` are epoch microseconds (the names keep the `_ns`
            // suffix), so the ms floor is compared in the
            // same unit: ms -> µs (× 1_000).
            let elapsed_us = ctx.now_ns - ctx.record.issued_at_ns;
            if elapsed_us < floor.saturating_mul(1_000) {
                return VerifyOutcome::Invalid(VerifyError::TooFast);
            }
        } else {
            // Issuer host ahead of verifier host: apparent elapsed time is
            // negative. A skew within the tolerance bound is a clock anomaly
            // we tolerate (skip the floor heuristic — the negative elapsed
            // time carries no timing signal); a larger skew means the clocks
            // are broken and the timing guarantee is void.
            let skew = ctx.record.issued_at_ns - ctx.now_ns;
            if skew > SKEW_TOLERANCE_US {
                return VerifyOutcome::Invalid(VerifyError::TooFast);
            }
        }
    }

    // 4. Optional telemetry scoring. Strict mode also rejects clients that
    //    submit NO telemetry (a custom non-browser solver does not send it)
    //    or an empty telemetry payload (the PHP widget emits `{}` when no
    //    telemetry was collected).
    if ctx.enforce_telemetry {
        match ctx.telemetry {
            Some(telemetry)
                if telemetry.is_null()
                    || telemetry_is_empty(telemetry)
                    || score_telemetry(telemetry, ctx.duration_ms) =>
            {
                return VerifyOutcome::Invalid(VerifyError::BotDetected);
            }
            Some(_) => {}
            None => {
                return VerifyOutcome::Invalid(VerifyError::BotDetected);
            }
        }
    }

    // 5. Re-derive and check the proof. The rsw record derives no hash:
    //    the presented final value is compared against the trapdoor
    //    expectation (constant-time over the fixed 512-hex wire form).
    //    The trapdoor is selected by the record's authenticated modulus
    //    identity — the rotation keyring first, then the active pair —
    //    through the one resolver both this generic path and the
    //    production verifier use: the legacy base64-text alias resolves
    //    a pre-v5 identity only, a v5 identity resolves its canonical
    //    fingerprint exactly, and an identity in neither fails closed
    //    with UnsupportedRswParams (never an arbitrary active pair).
    //    The process-wide validated-pair memo keeps the expensive
    //    primality tests once per configured pair; every later
    //    verification of the same pair is a cache hit.
    let trapdoor = match crate::rsw::resolve_rsw_trapdoor(
        match (ctx.rsw_modulus_n, ctx.rsw_lambda) {
            (Some(modulus), Some(lambda)) => Some((modulus, lambda)),
            _ => None,
        },
        ctx.rsw_keyring,
        ctx.record.rsw_modulus_sha256.as_deref(),
        ctx.record.protocol_version,
    ) {
        Ok(trapdoor) => trapdoor,
        Err(_) => return VerifyOutcome::Invalid(VerifyError::UnsupportedRswParams),
    };
    let valid = match proof_is_valid(ctx.record, ctx.counter, ctx.rsw_proof, trapdoor.as_deref()) {
        Ok(valid) => valid,
        Err(e) => return VerifyOutcome::Invalid(e),
    };

    // 5b. Final re-validation: the expensive derivation may have
    //     taken long enough that the challenge expired during it. The
    //     clock is read again here, after the derivation (the second
    //     invocation of the injectable clock, never the receipt
    //     snapshot): a challenge that expired mid-derive is Expired even
    //     though the record is already consumed. The policy epoch,
    //     region and issuer are re-validated against the verifier's
    //     currently applied expectation snapshot (they are not
    //     dynamically re-resolved mid-verification; the security-epoch
    //     design bounds revocation latency through its short cache).
    let final_now = read_clock(ctx);
    if let Err(e) = final_revalidate(
        ctx.record,
        final_now,
        ctx.expected_region,
        ctx.expected_policy_version,
        ctx.policy_version_floor,
        ctx.expected_issuer,
    ) {
        return VerifyOutcome::Invalid(e);
    }

    if valid {
        // The outcome carries the consumed canonical nonce (jti) so callers
        // can correlate the result without re-decoding the solution. The
        // server-measured solve duration is computed from the same receipt
        // instant the minimum-duration floor read above (`ctx.now_ns`),
        // never a second clock read.
        VerifyOutcome::Valid {
            nonce: ctx.record.nonce.clone(),
            request_binding: ctx.record.request_binding.clone(),
            from_stored_result: false,
            solve_duration_ms: measurable_solve_duration_ms(ctx.record, ctx.now_ns),
        }
    } else {
        VerifyOutcome::Invalid(VerifyError::InsufficientWork)
    }
}

/// The policy-epoch acceptance predicate, shared by the cheap-phase gate,
/// [`final_revalidate`] and the production verifier's deployment check.
///
/// With no expected version every record passes (the check is disabled).
/// With an expected version `e` and no floor the check is the strict
/// equality `record == e` — outstanding challenges die immediately on
/// policy revocation. During a declared rollout window the operator sets a
/// floor `f < e`: a mixed N/N+1 fleet then redeems challenges issued under
/// either epoch, `f <= record <= e`. A floor `f > e` is an empty interval
/// and accepts nothing (fail closed, never fail open on a misconfiguration).
pub(crate) fn policy_version_accepted(
    record: u32,
    expected: Option<u32>,
    floor: Option<u32>,
) -> bool {
    match expected {
        None => true,
        Some(e) => match floor {
            None => record == e,
            Some(f) => f <= record && record <= e,
        },
    }
}

/// Post-derive final re-validation: re-check the challenge's
/// validity with the current server time and the current verifier
/// expectations, after the (potentially long) proof derivation succeeded but
/// before the outcome is declared valid.
///
/// A challenge can expire during the expensive derivation — the cheap TTL
/// check ran before the hash was computed — and the verifier's current
/// expectations (security-policy epoch, region, issuer) can change while the
/// proof is being derived. This gate is therefore re-run as the last step of
/// [`verify_solution`] and of the production verifier (whose final step
/// passes a fresh clock read — the real race — see `redis_verify`).
///
/// Checks, in order:
/// - `now_unix >= expires_at` → [`VerifyError::Expired`];
/// - expected region mismatch → [`VerifyError::WrongRegion`];
/// - expected policy epoch mismatch (outside a declared rollout window;
///   see [`policy_version_accepted`]) → [`VerifyError::WrongPolicyVersion`];
/// - expected issuer mismatch → [`VerifyError::WrongIssuer`].
pub(crate) fn final_revalidate(
    record: &ChallengeRecord,
    now_unix: u64,
    expected_region: Option<&str>,
    expected_policy_version: Option<u32>,
    policy_version_floor: Option<u32>,
    expected_issuer: Option<&str>,
) -> Result<(), VerifyError> {
    if now_unix >= record.expires_at {
        return Err(VerifyError::Expired);
    }
    if let Some(expected) = expected_region {
        if record.region.as_deref() != Some(expected) {
            return Err(VerifyError::WrongRegion);
        }
    }
    if !policy_version_accepted(
        record.policy_version,
        expected_policy_version,
        policy_version_floor,
    ) {
        return Err(VerifyError::WrongPolicyVersion);
    }
    if let Some(expected) = expected_issuer {
        if record.issuer.as_deref() != Some(expected) {
            return Err(VerifyError::WrongIssuer);
        }
    }
    Ok(())
}

/// Constant-time byte comparison (equal-length inputs; both operands here are
/// fixed-length hex digests).
pub(crate) fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Extract the embedded signature from the stored challenge string.
///
/// The challenge is `base64(payload).signature` (the base64 payload contains no
/// dots, so `rsplit_once('.')` reliably isolates the hex HMAC signature).
pub(crate) fn signature_from_challenge(record: &ChallengeRecord) -> &str {
    record
        .challenge
        .rsplit_once('.')
        .map(|(_, sig)| sig)
        .unwrap_or("")
}

/// Convenience: produce a *valid* counter for a record (used by tests and by a
/// server-side solver for the dev-bypass path). This brute-forces until the
/// difficulty target is met.
///
/// Test/dev-bypass surface only: it performs the solve the client is
/// supposed to perform, so it must never sit on a production admission
/// path — production verifies client-presented counters and never
/// mints its own proof.
pub fn solve_for_test(record: &ChallengeRecord) -> Option<u64> {
    // Capped at the real solver's search space: a counter at or above the
    // solver cap is rejected by verify_solution (CounterTooLarge), so the
    // test solver must never produce one. At 20 bits a legit solver finds
    // no counter within the cap with p ≈ 0.85% — callers that need a
    // guaranteed solve should use a lower difficulty.
    for counter in 0..crate::challenge::SOLVER_MAX_HASHES {
        if let Ok(hash) = derive_hash(record, counter) {
            if leading_zero_bits(&hash) >= record.target_bits {
                return Some(counter);
            }
        }
    }
    None
}

/// SHA-256 helper used by the telemetry risk scorer (kept here to centralize
/// hashing deps).
pub fn sha256_hex(input: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    hex::encode(hasher.finalize())
}

/// True when a telemetry payload carries no signal at all: the empty object
/// the PHP widget emits for no telemetry, an empty array, or JSON `null`.
/// Non-object values (e.g. a number or string) are NOT treated as empty —
/// they are malformed rather than absent, and the scorer handles them.
fn telemetry_is_empty(telemetry: &serde_json::Value) -> bool {
    telemetry
        .as_object()
        .map(|o| o.is_empty())
        .unwrap_or_else(|| telemetry.as_array().map(|a| a.is_empty()).unwrap_or(false))
}

/// Score telemetry data for bot detection. Returns `true` if the client
/// appears to be automated/headless and should be rejected.
///
/// Hard rejection signals:
/// - `webdriver` flag is set (Chrome DevTools Protocol / Selenium).
/// - Solve takes >300s total: well beyond any expected solve (the
///   highest shipped profile is 20 target bits — ~1.05M expected
///   hashes, seconds even on a slow device) while still allowing very
///   slow hardware. There is deliberately NO "long solve with zero
///   interaction" rule: the widget auto-solves and its listeners sit on
///   the widget itself, so a real user on a slow device, or on an
///   Argon2id profile, produces no events and must not be rejected.
/// - A full synthetic event stream with near-zero timing variance
///   (see the entropy check below).
///
/// The historical hc/dm/pl soft signals are gone: the widget never sends
/// those fields, so they fired for every legitimate user.
pub fn score_telemetry(telemetry: &serde_json::Value, duration_ms: u64) -> bool {
    let wd = telemetry
        .get("wd")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    if wd {
        return true;
    }

    // Hard rejection signals:
    // 1. Solve takes >300s total (well beyond expected — a generous bound
    //    that allows for very slow devices). There is deliberately NO
    //    "long solve with zero interaction" rule: the widget auto-solves
    //    and its listeners sit only on the widget, so a real user on a
    //    slow device (or on an Argon2id profile) has no reason to
    //    interact and would be misclassified as a bot.
    if duration_ms > 300_000 {
        tracing::warn!(duration_ms, "KiwiCaptcha: bot suspected — solve took >300s");
        return true;
    }

    // 2. Entropy check: if there are interactions, check for timing variance.
    //    Bots often simulate events with perfectly uniform intervals.
    //
    //    This check is deliberately conservative:
    //    - It only considers *discrete* events (the widget records pointerdown,
    //      non-repeat keydown, and click — never coalesced mousemove, wheel
    //      scrolling, or OS key auto-repeat), so a uniform interval across 24+ discrete
    //      human events is not something a person can produce. The widget
    //      records up to 32 timings, so this 24-event floor is reachable.
    //    - The coefficient of variation must be near zero (< 2%) AND the mean
    //      interval must be ≥ 8 ms, so a burst of sub-frame events (which can
    //      round to identical millisecond timestamps) is never misclassified.
    if let Some(et) = telemetry.get("et").and_then(|v| v.as_array()) {
        if et.len() >= 24 {
            let mut diffs = Vec::with_capacity(et.len() - 1);
            for i in 1..et.len() {
                if let (Some(t1), Some(t0)) = (et[i].as_u64(), et[i - 1].as_u64()) {
                    if t1 >= t0 {
                        diffs.push(t1 - t0);
                    }
                }
            }

            if diffs.len() >= 23 {
                let mut sum: u64 = 0;
                for &d in &diffs {
                    sum += d;
                }
                let mean = sum as f64 / diffs.len() as f64;
                if mean >= 8.0 {
                    let variance: f64 = diffs
                        .iter()
                        .map(|&d| {
                            let diff = d as f64 - mean;
                            diff * diff
                        })
                        .sum::<f64>()
                        / diffs.len() as f64;
                    let cv = variance.sqrt() / mean;
                    if cv < 0.02 {
                        tracing::warn!(
                            cv,
                            mean,
                            n = diffs.len(),
                            "KiwiCaptcha: bot suspected — near-zero timing variance in discrete events"
                        );
                        return true;
                    }
                }
            }
        }
    }

    // The historical hc/dm/pl soft signals are gone: the widget never
    // sends those fields (they would fire for every legitimate user),
    // and this function returns true only for a real rejection.
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::challenge::{
        binding_tag, hash_ip, issue_challenge, BindingMode, ChallengeConfig, PoWAlgorithm,
        SignError,
    };

    #[test]
    fn error_codes_are_unique_machine_readable_snake_case() {
        // The wire-code register hygiene: every variant's code() is
        // non-empty snake_case and unique across the enum. The
        // cross-language drift gate — every PHP VerifyError code has a
        // Rust twin — is NOT a handwritten list here (a stale list
        // passes vacuously); it is enforced by
        // tools/verify-error-code-parity.sh, which parses the PHP enum's
        // case values and this code() mapping directly in CI.
        let variants = [
            VerifyError::BadSignature,
            VerifyError::Expired,
            VerifyError::TooFast,
            VerifyError::IpMismatch,
            VerifyError::MissingClientIp,
            VerifyError::CounterTooLarge,
            VerifyError::WrongScope,
            VerifyError::RequestBindingMismatch,
            VerifyError::WrongRegion,
            VerifyError::WrongIssuer,
            VerifyError::WrongPolicyVersion,
            VerifyError::UnknownKid,
            VerifyError::TooManyAttempts,
            VerifyError::InsufficientWork,
            VerifyError::MalformedRecord,
            VerifyError::UnsupportedArgon2Params,
            VerifyError::UnsupportedRswParams,
            VerifyError::BotDetected,
            VerifyError::MalformedToken,
            VerifyError::RecordNotFound,
            VerifyError::StorageUnavailable,
            VerifyError::ConsumeIndeterminate,
            VerifyError::AlreadyConsumed,
            VerifyError::CapacityExceeded,
            VerifyError::AdmissionUnavailable,
            VerifyError::ExecutionMismatch,
        ];
        assert_eq!(
            variants.len(),
            26,
            "the table must cover EVERY VerifyError variant"
        );
        let codes: Vec<&str> = variants.iter().map(|v| v.code()).collect();
        for code in &codes {
            assert!(
                !code.is_empty()
                    && code
                        .chars()
                        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_'),
                "code {code} is not machine-readable snake_case"
            );
        }
        let mut unique = codes.clone();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(unique.len(), codes.len(), "codes must be unique");
        // The harmonized Argon2 divergence: a signed record violating the
        // process ceilings reports the PHP twin wire code, not
        // malformed_record.
        assert_eq!(
            VerifyError::UnsupportedArgon2Params.code(),
            "unsupported_argon2_params"
        );
        // The documented name-mapping divergence: the Rust-idiomatic
        // BotDetected variant carries PHP's telemetry_rejected wire code.
        assert_eq!(VerifyError::BotDetected.code(), "telemetry_rejected");
    }

    const NOW_UNIX: u64 = 1_000_000;
    // Epoch microseconds (1_700_000_000_000_000 µs ≈ 2023-11-14 UTC) — the
    // unit shared with PHP; field names keep the `_ns` suffix.
    const NOW_NS: u64 = 1_700_000_000_000_000;

    fn make_record(target_bits: u32) -> ChallengeRecord {
        make_record_at(target_bits, NOW_UNIX, NOW_NS)
    }

    fn make_record_at(target_bits: u32, now_unix: u64, now_ns: u64) -> ChallengeRecord {
        let config = ChallengeConfig {
            secret_key: "test-key-32-bytes-0123456789abcd".into(),
            kid: 1,
            execution_key: None,
            rsw_modulus_n: None,
            rsw_lambda: None,
            rsw_t: crate::challenge::DEFAULT_RSW_T,
            tenant: None,
            algorithm: PoWAlgorithm::Sha256,
            m_kib: 100,
            t: 1,
            p: 1,
            target_bits,
            argon2_target_bits: 8,
            ttl_secs: 120,
            min_duration_ms: None,
            auto_tune: false,
            auto_tune_min_bits: 8,
            auto_tune_max_bits: 24,
            binding_mode: BindingMode::Bound,
            region: None,
            issuer: None,

            policy_version: 1,
        };
        let issued =
            issue_challenge(&config, "login", "1.2.3.4", now_unix, now_ns, 0, None).unwrap();
        issued.record
    }

    fn make_argon2_record(target_bits: u32, m_kib: u32) -> ChallengeRecord {
        let config = ChallengeConfig {
            rsw_modulus_n: None,
            rsw_lambda: None,
            rsw_t: crate::challenge::DEFAULT_RSW_T,
            tenant: None,
            secret_key: "test-key-32-bytes-0123456789abcd".into(),
            kid: 1,
            execution_key: None,
            algorithm: PoWAlgorithm::Argon2id,
            m_kib,
            t: 3, // libsodium-representable (t >= 3, p == 1) — issuance rejects t < 3
            p: 1,
            target_bits,
            argon2_target_bits: target_bits,
            ttl_secs: 120,
            min_duration_ms: None,
            auto_tune: false,
            auto_tune_min_bits: 8,
            auto_tune_max_bits: 24,
            binding_mode: BindingMode::Bound,
            region: None,
            issuer: None,

            policy_version: 1,
        };
        let issued =
            issue_challenge(&config, "login", "1.2.3.4", NOW_UNIX, NOW_NS, 0, None).unwrap();
        issued.record
    }

    fn verify(record: &mut ChallengeRecord, counter: u64, duration_ms: u64) -> VerifyOutcome {
        let mut ctx = VerifyContext {
            record,
            secret_key: "test-key-32-bytes-0123456789abcd",
            tenant: None,
            secrets_by_kid: None,
            revoked_kids: None,
            counter,
            duration_ms,
            now_unix: Some(&mut || NOW_UNIX + 1),
            now_ns: NOW_NS + 5_000_000, // 5 s after issuance
            min_duration_ms: 0,
            expected_scope: None,
            expected_request_binding: RequestBindingExpectation::Unenforced,
            expected_region: None,
            expected_issuer: None,
            expected_policy_version: None,
            policy_version_floor: None,
            client_ip: Some("1.2.3.4"),
            rsw_proof: None,
            rsw_modulus_n: None,
            rsw_lambda: None,
            rsw_keyring: None,
            execution_digest: None,
            execution_trace: None,
            telemetry: None,
            enforce_telemetry: false,
            max_attempts: 0,
            accept_legacy_v1: false,
        };
        verify_solution(&mut ctx)
    }

    /// Re-sign a mutated Argon2id record so its parameters are covered by a
    /// valid v2 signature — the ceiling checks must fire on
    /// properly signed records, not on signature failures.
    fn resign_v2(record: &mut ChallengeRecord, secret: &str) {
        resign_v2_tenant(record, secret, None);
    }

    fn resign_v2_tenant(record: &mut ChallengeRecord, secret: &str, tenant: Option<&str>) {
        // The production order: a placeholder MAC commits the m=1 marker
        // before signing, then the real tag is sealed over the signed
        // challenge. A record without a MAC signs without the marker.
        let had_mac = record.server_mac.is_some();
        record.server_mac = if had_mac { Some(String::new()) } else { None };
        let canonical = super::super::challenge::canonical_signing_input_v2(record);
        let sig = super::super::challenge::sign_canonical_v2(&canonical, secret, tenant).unwrap();
        let challenge = format!("{}.{}", B64.encode(canonical.as_bytes()), sig);
        record.challenge = challenge.clone();
        record.prefix = format!("{challenge}|{}|", record.salt);
        if had_mac {
            // The server-state MAC authenticates the unsigned server-side
            // fields (issued_at_ns, hostname) against the exact challenge
            // string: a re-sign changes the challenge, so the MAC must be
            // re-sealed exactly as the production issuer seals it after
            // signing.
            record.server_mac = Some(super::super::challenge::record_meta_mac(
                &super::super::keys::DerivedKeys::from_master(secret, tenant),
                &record.challenge,
                record.issued_at_ns,
                record.hostname.as_deref(),
            ));
        }
    }

    // ── tenant-scoped verification ─────────────────────────────────────

    /// The cross-language tenant vector inputs: tenant id `t1` under the
    /// shared reference master (the tenant-root construction pinned by
    /// the keys suite).
    const TENANT_MASTER: &str = "0123456789abcdef0123456789abcdef";

    fn tenant_record(tenant: Option<&str>) -> ChallengeRecord {
        let config = ChallengeConfig {
            secret_key: TENANT_MASTER.into(),
            kid: 1,
            execution_key: None,
            rsw_modulus_n: None,
            rsw_lambda: None,
            rsw_t: crate::challenge::DEFAULT_RSW_T,
            tenant: tenant.map(str::to_string),
            algorithm: PoWAlgorithm::Sha256,
            m_kib: 0,
            t: 1,
            p: 1,
            target_bits: 4,
            argon2_target_bits: 4,
            ttl_secs: 120,
            min_duration_ms: None,
            auto_tune: false,
            auto_tune_min_bits: 8,
            auto_tune_max_bits: 24,
            binding_mode: BindingMode::Bound,
            region: None,
            issuer: None,
            policy_version: 1,
        };
        issue_challenge(&config, "login", "1.2.3.4", NOW_UNIX, NOW_NS, 0, None)
            .unwrap()
            .record
    }

    fn verify_tenant(
        record: &mut ChallengeRecord,
        counter: u64,
        tenant: Option<&str>,
    ) -> VerifyOutcome {
        let mut ctx = VerifyContext {
            record,
            secret_key: TENANT_MASTER,
            tenant,
            secrets_by_kid: None,
            revoked_kids: None,
            counter,
            duration_ms: 5000,
            now_unix: Some(&mut || NOW_UNIX + 1),
            now_ns: NOW_NS + 5_000_000,
            min_duration_ms: 0,
            expected_scope: None,
            expected_request_binding: RequestBindingExpectation::Unenforced,
            expected_region: None,
            expected_issuer: None,
            expected_policy_version: None,
            policy_version_floor: None,
            client_ip: Some("1.2.3.4"),
            rsw_proof: None,
            rsw_modulus_n: None,
            rsw_lambda: None,
            rsw_keyring: None,
            execution_digest: None,
            execution_trace: None,
            telemetry: None,
            enforce_telemetry: false,
            max_attempts: 0,
            accept_legacy_v1: false,
        };
        verify_solution(&mut ctx)
    }

    #[test]
    fn tenant_round_trip_and_cross_tenant_negatives() {
        // The t1-issued record verifies under tenant t1 and fails under
        // t2 and under the global keys — the cross-tenant record is a
        // BadSignature before any proof work.
        let mut t1 = tenant_record(Some("t1"));
        let counter = solve_for_test(&t1).expect("4-bit sha solves");
        assert!(
            matches!(
                verify_tenant(&mut t1, counter, Some("t1")),
                VerifyOutcome::Valid { .. }
            ),
            "the t1 record round-trips under the t1 context"
        );
        let mut cross = tenant_record(Some("t1"));
        assert_eq!(
            verify_tenant(&mut cross, counter, Some("t2")),
            VerifyOutcome::Invalid(VerifyError::BadSignature),
            "a t2 context rejects the t1 record"
        );
        let mut global_ctx = tenant_record(Some("t1"));
        assert_eq!(
            verify_tenant(&mut global_ctx, counter, None),
            VerifyOutcome::Invalid(VerifyError::BadSignature),
            "the global context rejects the t1 record"
        );
        // The None context keeps accepting None-issued records.
        let mut unscoped = tenant_record(None);
        let unscoped_counter = solve_for_test(&unscoped).expect("4-bit sha solves");
        assert!(matches!(
            verify_tenant(&mut unscoped, unscoped_counter, None),
            VerifyOutcome::Valid { .. }
        ));
    }

    #[test]
    #[cfg(feature = "redis")]
    fn the_execution_evidence_cache_serves_identical_inputs_and_rederives_on_change() {
        // The per-verification memo: identical inputs return the first
        // verdict, and any changed input (the presented digest) is a
        // miss that re-derives and returns its own verdict.
        let config = ChallengeConfig {
            secret_key: "test-key-32-bytes-0123456789abcd".into(),
            kid: 1,
            rsw_modulus_n: None,
            rsw_lambda: None,
            rsw_t: crate::challenge::DEFAULT_RSW_T,
            tenant: None,
            execution_key: Some("test-key-32-bytes-0123456789abcd".into()),
            algorithm: PoWAlgorithm::Sha256,
            m_kib: 0,
            t: 1,
            p: 1,
            target_bits: 4,
            argon2_target_bits: 4,
            ttl_secs: 120,
            min_duration_ms: None,
            auto_tune: false,
            auto_tune_min_bits: 8,
            auto_tune_max_bits: 24,
            binding_mode: BindingMode::Bound,
            region: None,
            issuer: None,
            policy_version: 1,
        };
        let issued = crate::challenge::issue_challenge_with_execution(
            &config,
            "login",
            "1.2.3.4",
            NOW_UNIX,
            NOW_NS,
            0,
            None,
            true,
            Some("verify-action"),
            Some(1),
            false,
        )
        .unwrap();
        let program = issued.record.execution_program.as_deref().unwrap();
        let decoded = crate::execution::decode(program).expect("the issued program parses");
        let trace = crate::execution::fixtures::executed_trace_for(&decoded);
        let trace_b64: String = B64
            .encode(trace.as_bytes())
            .replace('+', "-")
            .replace('/', "_")
            .trim_end_matches('=')
            .to_string();
        let digest =
            crate::execution::expected_digest_over_trace(program, &issued.record.nonce, &trace)
                .expect("the digest over the executed trace");

        let mut cache = ExecutionEvidenceCache::default();
        assert_eq!(
            check_execution_binding_cached(
                &issued.record,
                Some(&digest),
                Some(&trace_b64),
                &mut cache
            ),
            Ok(())
        );
        assert_eq!(
            check_execution_binding_cached(
                &issued.record,
                Some(&digest),
                Some(&trace_b64),
                &mut cache
            ),
            Ok(()),
            "identical inputs return the memoized verdict"
        );
        let wrong_digest = "f".repeat(64);
        assert_eq!(
            check_execution_binding_cached(
                &issued.record,
                Some(&wrong_digest),
                Some(&trace_b64),
                &mut cache
            ),
            Err(VerifyError::ExecutionMismatch),
            "a changed input is a miss and re-derives its own verdict"
        );
        // An unarmed record bypasses the memo entirely.
        let unarmed = make_record(4);
        let mut fresh = ExecutionEvidenceCache::default();
        assert_eq!(
            check_execution_binding_cached(&unarmed, None, None, &mut fresh),
            Ok(())
        );
    }

    #[test]
    fn generic_path_follows_the_php_ip_before_deployment_precedence() {
        // The generic verifier's first-error order mirrors the PHP
        // cheapPhaseCheck: shape → TTL → scope + request binding → IP
        // binding → region/policy/issuer → floor. A record failing both
        // the IP binding and a deployment expectation reports the IP
        // error, exactly like the PHP core (cross-language error-code
        // parity for multi-failure records).
        for (label, client_ip, expected) in [
            (
                "missing ip beats wrong region",
                None,
                VerifyError::MissingClientIp,
            ),
            (
                "ip mismatch beats wrong region",
                Some("9.9.9.9"),
                VerifyError::IpMismatch,
            ),
        ] {
            let mut record = make_record(8);
            let counter = solve_for_test(&record).expect("8-bit sha solves");
            let mut ctx = VerifyContext {
                record: &mut record,
                secret_key: "test-key-32-bytes-0123456789abcd",
                tenant: None,
                secrets_by_kid: None,
                revoked_kids: None,
                counter,
                duration_ms: 5000,
                now_unix: Some(&mut || NOW_UNIX + 1),
                now_ns: NOW_NS + 5_000_000,
                min_duration_ms: 0,
                expected_scope: None,
                expected_request_binding: RequestBindingExpectation::Unenforced,
                expected_region: Some("eu"), // the record is region-unbound → WrongRegion would fire later
                rsw_proof: None,
                rsw_modulus_n: None,
                rsw_lambda: None,
                rsw_keyring: None,
                expected_issuer: Some("prod"),
                expected_policy_version: Some(2),
                policy_version_floor: None,
                client_ip,
                execution_digest: None,
                execution_trace: None,
                telemetry: None,
                enforce_telemetry: false,
                max_attempts: 0,
                accept_legacy_v1: false,
            };
            assert_eq!(
                verify_solution(&mut ctx),
                VerifyOutcome::Invalid(expected),
                "{label}: the IP binding precedes the deployment expectations"
            );
        }
    }

    #[test]
    fn request_binding_expectation_golden_vectors() {
        // The exact Option-equality matrix (the protocol parity gate's
        // Rust half): bound A / exact A pass; bound A / exact B mismatch;
        // bound A / exact null mismatch; unbound / exact null pass;
        // unbound / exact A mismatch; bound A / unenforced pass.
        let cases: [(&str, RequestBindingExpectation, bool); 6] = [
            (
                "txn-A",
                RequestBindingExpectation::Exact(Some("txn-A")),
                true,
            ),
            (
                "txn-A",
                RequestBindingExpectation::Exact(Some("txn-B")),
                false,
            ),
            ("txn-A", RequestBindingExpectation::Exact(None), false),
            ("", RequestBindingExpectation::Exact(None), true),
            ("", RequestBindingExpectation::Exact(Some("txn-A")), false),
            ("txn-A", RequestBindingExpectation::Unenforced, true),
        ];
        for (binding, expectation, should_pass) in cases {
            let record_binding = if binding.is_empty() {
                None
            } else {
                Some(binding)
            };
            let ok = check_request_binding(record_binding, expectation).is_ok();
            assert_eq!(
                ok, should_pass,
                "binding={binding:?} expectation={expectation:?}"
            );
        }
    }

    #[test]
    fn exactly_the_timing_failures_are_replay_exempt() {
        // The exemption is the narrow set of failures that describe the
        // original redemption's circumstances rather than this request's
        // authorization (expiry, the IP binding, the missing client IP,
        // the client-side telemetry evidence). Everything else is a
        // security verdict that must stand even when the operation
        // identity matches a consumed record's committed success.
        let exempt = [
            VerifyError::Expired,
            VerifyError::IpMismatch,
            VerifyError::MissingClientIp,
            VerifyError::BotDetected,
        ];
        let all = [
            VerifyError::BadSignature,
            VerifyError::Expired,
            VerifyError::TooFast,
            VerifyError::IpMismatch,
            VerifyError::MissingClientIp,
            VerifyError::CounterTooLarge,
            VerifyError::WrongScope,
            VerifyError::RequestBindingMismatch,
            VerifyError::WrongRegion,
            VerifyError::WrongIssuer,
            VerifyError::WrongPolicyVersion,
            VerifyError::UnknownKid,
            VerifyError::TooManyAttempts,
            VerifyError::InsufficientWork,
            VerifyError::MalformedRecord,
            VerifyError::UnsupportedArgon2Params,
            VerifyError::BotDetected,
            VerifyError::MalformedToken,
            VerifyError::RecordNotFound,
            VerifyError::StorageUnavailable,
            VerifyError::ConsumeIndeterminate,
            VerifyError::AlreadyConsumed,
            VerifyError::CapacityExceeded,
            VerifyError::AdmissionUnavailable,
        ];
        for e in all {
            assert_eq!(
                exempt.contains(&e),
                e.is_replay_exempt(),
                "{e:?} replay-exempt classification must match the exempt set"
            );
        }
    }

    #[test]
    fn valid_solution_is_accepted() {
        let mut record = make_record(8); // 8 bits — fast solve
        let counter = solve_for_test(&record).expect("solver finds a counter");
        assert!(matches!(
            verify(&mut record, counter, 5000),
            VerifyOutcome::Valid { .. }
        ));
    }

    #[test]
    fn argon2_solution_is_accepted() {
        let mut record = make_argon2_record(4, 128); // low bits, small memory for tests
        let counter = solve_for_test(&record).expect("solver finds an argon2 counter");
        assert!(matches!(
            verify(&mut record, counter, 5000),
            VerifyOutcome::Valid { .. }
        ));
    }

    #[test]
    fn argon2_issuance_rejects_invalid_memory_params() {
        // m_kib < 8 * p must fail at issuance, not at verification time.
        let config = ChallengeConfig {
            secret_key: "test-key-32-bytes-0123456789abcd".into(),
            kid: 1,
            execution_key: None,
            rsw_modulus_n: None,
            rsw_lambda: None,
            rsw_t: crate::challenge::DEFAULT_RSW_T,
            tenant: None,
            algorithm: PoWAlgorithm::Argon2id,
            m_kib: 4,
            t: 3,
            p: 1,
            target_bits: 4,
            argon2_target_bits: 4,
            ttl_secs: 120,
            min_duration_ms: None,
            auto_tune: false,
            auto_tune_min_bits: 8,
            auto_tune_max_bits: 24,
            binding_mode: BindingMode::Bound,
            region: None,
            issuer: None,

            policy_version: 1,
        };
        assert!(issue_challenge(&config, "login", "1.2.3.4", NOW_UNIX, NOW_NS, 0, None).is_err());
    }

    #[test]
    fn argon2_issuance_rejects_libsodium_unrepresentable_t() {
        // PHP/libsodium cannot represent Argon2id with t < 3 — issuance must
        // reject it so cross-language verification can never silently fail.
        for t in [0u32, 1, 2] {
            let config = ChallengeConfig {
                secret_key: "test-key-32-bytes-0123456789abcd".into(),
                kid: 1,
                execution_key: None,
                rsw_modulus_n: None,
                rsw_lambda: None,
                rsw_t: crate::challenge::DEFAULT_RSW_T,
                tenant: None,
                algorithm: PoWAlgorithm::Argon2id,
                m_kib: 128,
                t,
                p: 1,
                target_bits: 4,
                argon2_target_bits: 4,
                ttl_secs: 120,
                min_duration_ms: None,
                auto_tune: false,
                auto_tune_min_bits: 8,
                auto_tune_max_bits: 24,
                binding_mode: BindingMode::Bound,
                region: None,
                issuer: None,

                policy_version: 1,
            };
            assert!(
                issue_challenge(&config, "login", "1.2.3.4", NOW_UNIX, NOW_NS, 0, None).is_err(),
                "Argon2id t={t} must be rejected at issuance"
            );
        }
    }

    #[test]
    fn issuance_rejects_min_duration_at_or_above_ttl() {
        // A floor >= ttl*1000 makes every submission either TooFast or
        // Expired — no acceptable submission time exists (verification
        // checks expiry before the floor).
        let base = ChallengeConfig {
            secret_key: "test-key-32-bytes-0123456789abcd".into(),
            kid: 1,
            execution_key: None,
            rsw_modulus_n: None,
            rsw_lambda: None,
            rsw_t: crate::challenge::DEFAULT_RSW_T,
            tenant: None,
            algorithm: PoWAlgorithm::Sha256,
            m_kib: 0,
            t: 1,
            p: 1,
            target_bits: 8,
            argon2_target_bits: 8,
            ttl_secs: 10,
            min_duration_ms: None,
            auto_tune: false,
            auto_tune_min_bits: 8,
            auto_tune_max_bits: 24,
            binding_mode: BindingMode::Bound,
            region: None,
            issuer: None,

            policy_version: 1,
        };
        for ms in [10_000u64, 20_000, 100_000] {
            let mut cfg = base.clone();
            cfg.min_duration_ms = Some(ms);
            assert!(
                issue_challenge(&cfg, "login", "1.2.3.4", NOW_UNIX, NOW_NS, 0, None).is_err(),
                "min_duration_ms={ms} with ttl 10s must be rejected"
            );
        }
        let mut ok = base.clone();
        ok.min_duration_ms = Some(9_999);
        assert!(issue_challenge(&ok, "login", "1.2.3.4", NOW_UNIX, NOW_NS, 0, None).is_ok());
    }

    #[test]
    fn issuance_rejects_ttl_outside_protocol_range() {
        // The verifier's validate_record rejects lifetimes above the protocol
        // TTL cap (300) and TTL 0 is meaningless — issuance must refuse to
        // mint a record it would later declare malformed.
        let base = ChallengeConfig {
            secret_key: "test-key-32-bytes-0123456789abcd".into(),
            kid: 1,
            execution_key: None,
            rsw_modulus_n: None,
            rsw_lambda: None,
            rsw_t: crate::challenge::DEFAULT_RSW_T,
            tenant: None,
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
            auto_tune_max_bits: 24,
            binding_mode: BindingMode::Bound,
            region: None,
            issuer: None,

            policy_version: 1,
        };
        for ttl in [0u64, 301, 60_000] {
            let mut cfg = base.clone();
            cfg.ttl_secs = ttl;
            assert!(
                issue_challenge(&cfg, "login", "1.2.3.4", NOW_UNIX, NOW_NS, 0, None).is_err(),
                "ttl={ttl} must be rejected at issuance"
            );
        }
        let mut ok = base.clone();
        ok.ttl_secs = 300;
        assert!(issue_challenge(&ok, "login", "1.2.3.4", NOW_UNIX, NOW_NS, 0, None).is_ok());
    }

    #[test]
    fn issuance_rejects_argon_t_above_protocol_ceiling() {
        // The verifier's structural ceiling for t is 16, so t=7 is
        // structurally acceptable — but issuance refuses t above 6, the
        // browser-solver ceiling (PHP Config already does; Rust must match).
        let config = ChallengeConfig {
            secret_key: "test-key-32-bytes-0123456789abcd".into(),
            kid: 1,
            execution_key: None,
            rsw_modulus_n: None,
            rsw_lambda: None,
            rsw_t: crate::challenge::DEFAULT_RSW_T,
            tenant: None,
            algorithm: PoWAlgorithm::Argon2id,
            m_kib: 128,
            t: 7,
            p: 1,
            target_bits: 4,
            argon2_target_bits: 4,
            ttl_secs: 120,
            min_duration_ms: None,
            auto_tune: false,
            auto_tune_min_bits: 8,
            auto_tune_max_bits: 24,
            binding_mode: BindingMode::Bound,
            region: None,
            issuer: None,

            policy_version: 1,
        };
        assert!(
            issue_challenge(&config, "login", "1.2.3.4", NOW_UNIX, NOW_NS, 0, None).is_err(),
            "Argon2id t=7 must be rejected at issuance"
        );
    }

    #[test]
    fn argon2_issuance_rejects_libsodium_unrepresentable_p() {
        let config = ChallengeConfig {
            secret_key: "test-key-32-bytes-0123456789abcd".into(),
            kid: 1,
            execution_key: None,
            rsw_modulus_n: None,
            rsw_lambda: None,
            rsw_t: crate::challenge::DEFAULT_RSW_T,
            tenant: None,
            algorithm: PoWAlgorithm::Argon2id,
            m_kib: 128,
            t: 3,
            p: 2,
            target_bits: 4,
            argon2_target_bits: 4,
            ttl_secs: 120,
            min_duration_ms: None,
            auto_tune: false,
            auto_tune_min_bits: 8,
            auto_tune_max_bits: 24,
            binding_mode: BindingMode::Bound,
            region: None,
            issuer: None,

            policy_version: 1,
        };
        assert!(issue_challenge(&config, "login", "1.2.3.4", NOW_UNIX, NOW_NS, 0, None).is_err());
    }

    #[test]
    fn argon2_issuance_rejects_memory_above_solver_ceiling() {
        // The verifier already rejects records above the argon2 solver memory
        // ceiling (64 MiB — the wasm heap cap); issuance must never mint one.
        let config = ChallengeConfig {
            secret_key: "test-key-32-bytes-0123456789abcd".into(),
            kid: 1,
            execution_key: None,
            rsw_modulus_n: None,
            rsw_lambda: None,
            rsw_t: crate::challenge::DEFAULT_RSW_T,
            tenant: None,
            algorithm: PoWAlgorithm::Argon2id,
            m_kib: crate::challenge::SOLVER_MAX_ARGON2_M_KIB + 1,
            t: 3,
            p: 1,
            target_bits: 4,
            argon2_target_bits: 4,
            ttl_secs: 120,
            min_duration_ms: None,
            auto_tune: false,
            auto_tune_min_bits: 8,
            auto_tune_max_bits: 24,
            binding_mode: BindingMode::Bound,
            region: None,
            issuer: None,

            policy_version: 1,
        };
        assert!(
            matches!(
                issue_challenge(&config, "login", "1.2.3.4", NOW_UNIX, NOW_NS, 0, None),
                Err(SignError::InvalidArgon2Params)
            ),
            "m_kib above the 64 MiB ceiling must be rejected at issuance"
        );
        // The ceiling itself is accepted.
        let at_ceiling = ChallengeConfig {
            m_kib: crate::challenge::SOLVER_MAX_ARGON2_M_KIB,
            ..config
        };
        assert!(
            issue_challenge(&at_ceiling, "login", "1.2.3.4", NOW_UNIX, NOW_NS, 0, None).is_ok()
        );
    }

    #[test]
    fn argon2_issuance_validates_target_bits_range() {
        // argon2_target_bits must be within the argon2 solver target range:
        // 0 would silently clamp to a degenerate difficulty and 11 exceeds
        // the solver ceiling — both must fail at issuance.
        for bits in [0u32, 11] {
            let config = ChallengeConfig {
                rsw_modulus_n: None,
                rsw_lambda: None,
                rsw_t: crate::challenge::DEFAULT_RSW_T,
                tenant: None,
                secret_key: "test-key-32-bytes-0123456789abcd".into(),
                kid: 1,
                execution_key: None,
                algorithm: PoWAlgorithm::Argon2id,
                m_kib: 128,
                t: 3,
                p: 1,
                target_bits: 4,
                argon2_target_bits: bits,
                ttl_secs: 120,
                min_duration_ms: None,
                auto_tune: false,
                auto_tune_min_bits: 8,
                auto_tune_max_bits: 24,
                binding_mode: BindingMode::Bound,
                region: None,
                issuer: None,

                policy_version: 1,
            };
            assert!(
                matches!(
                    issue_challenge(&config, "login", "1.2.3.4", NOW_UNIX, NOW_NS, 0, None),
                    Err(SignError::InvalidArgon2Params)
                ),
                "argon2_target_bits={bits} must be rejected at issuance"
            );
        }
        // The maximum is accepted.
        let max_bits = ChallengeConfig {
            secret_key: "test-key-32-bytes-0123456789abcd".into(),
            kid: 1,
            execution_key: None,
            rsw_modulus_n: None,
            rsw_lambda: None,
            rsw_t: crate::challenge::DEFAULT_RSW_T,
            tenant: None,
            algorithm: PoWAlgorithm::Argon2id,
            m_kib: 128,
            t: 3,
            p: 1,
            target_bits: 4,
            argon2_target_bits: crate::challenge::SOLVER_MAX_ARGON2_TARGET_BITS,
            ttl_secs: 120,
            min_duration_ms: None,
            auto_tune: false,
            auto_tune_min_bits: 8,
            auto_tune_max_bits: 24,
            binding_mode: BindingMode::Bound,
            region: None,
            issuer: None,

            policy_version: 1,
        };
        assert!(issue_challenge(&max_bits, "login", "1.2.3.4", NOW_UNIX, NOW_NS, 0, None).is_ok());
    }

    #[test]
    fn protocol_version_one_with_a_decoy_is_malformed() {
        // The legacy v1 canonical signs neither extension segment, so a
        // stored v1 record carrying a decoy holds semantics the
        // signature never authenticated: the grammar matrix rejects the
        // combination structurally, before any signature work.
        let mut record = make_record(8);
        record.protocol_version = 1;
        record.decoy_field = Some("company_website".to_string());
        let counter = solve_for_test(&record).unwrap();
        assert_eq!(
            verify(&mut record, counter, 5000),
            VerifyOutcome::Invalid(VerifyError::MalformedRecord)
        );
    }

    #[test]
    fn protocol_version_one_with_the_execution_triplet_is_malformed() {
        // The same invariant on the execution side: a v1 record carrying
        // the execution extension is malformed (the legacy canonical
        // never signs the commitment), rejected before any work.
        let mut record = make_record(8);
        record.protocol_version = 1;
        record.execution_program = Some("AAAA".to_string());
        record.execution_version = Some(1);
        record.execution_commitment = Some("a".repeat(64));
        let counter = solve_for_test(&record).unwrap();
        assert_eq!(
            verify(&mut record, counter, 5000),
            VerifyOutcome::Invalid(VerifyError::MalformedRecord)
        );
    }

    #[test]
    fn protocol_version_three_without_a_decoy_is_malformed() {
        // Protocol v3 is the decoy-capable canonical and the decoy is
        // mandatory on v3: a signed v2 record re-versioned to 3 (the
        // stored-version-flip forgery — the same canonical bytes, the
        // same valid signature) must be rejected as malformed, before
        // any signature work. The canonical shape itself authenticates
        // the protocol capability: v3 without a decoy cannot come from a
        // conforming issuer.
        let mut record = make_record(8);
        record.protocol_version = 3;
        let counter = solve_for_test(&record).unwrap();
        assert_eq!(
            verify(&mut record, counter, 5000),
            VerifyOutcome::Invalid(VerifyError::MalformedRecord)
        );
    }

    #[test]
    fn protocol_version_two_with_a_decoy_is_rejected_explicitly() {
        // The protocol-vs-decoy grammar: the tagged `d=` segment is a
        // protocol v3 canonical extension, so a v2 record carrying a
        // decoy is malformed — the v2 canonical never includes the
        // segment, and such a record cannot have been signed by a
        // conforming issuer (an armed issuance writes protocol v3). The
        // rejection is explicit, before any signature work.
        let mut record = make_record(8);
        record.decoy_field = Some("company_website".to_string());
        let counter = solve_for_test(&record).unwrap();
        assert_eq!(
            verify(&mut record, counter, 5000),
            VerifyOutcome::Invalid(VerifyError::MalformedRecord)
        );
    }

    #[test]
    fn protocol_version_three_with_a_decoy_verifies_when_signed() {
        // An armed v3 record (decoy segment in the canonical) verifies
        // end to end: the signature covers the extended input and the
        // validator accepts version 3 with a present decoy.
        let mut record = make_record(8);
        record.protocol_version = 3;
        record.decoy_field = Some("company_website".to_string());
        resign_v2(&mut record, "test-key-32-bytes-0123456789abcd");
        let counter = solve_for_test(&record).unwrap();
        assert!(matches!(
            verify(&mut record, counter, 5000),
            VerifyOutcome::Valid { .. }
        ));
    }

    #[test]
    fn protocol_version_four_without_the_execution_triplet_is_malformed() {
        // Protocol v4 is the execution-capable canonical and the
        // execution commitment is mandatory on v4: a signed v2/v3 record
        // re-versioned to 4 (the stored-version-flip forgery — the same
        // canonical bytes, the same valid signature) must be rejected as
        // malformed, before any signature work. The canonical shape
        // itself authenticates the protocol capability: v4 without the
        // execution triplet cannot come from a conforming issuer.
        let mut record = make_record(8);
        record.protocol_version = 4;
        let counter = solve_for_test(&record).unwrap();
        let outcome = verify(&mut record, counter, 5000);
        assert_eq!(
            outcome,
            VerifyOutcome::Invalid(VerifyError::MalformedRecord)
        );
    }

    #[test]
    fn protocol_version_two_or_three_with_execution_is_malformed() {
        // The protocol-vs-execution grammar: the
        // `|execution_version|execution_commitment` segments are a
        // protocol v4 canonical extension, so a v2 or v3 record carrying
        // any execution field is malformed — the v2/v3 canonical never
        // includes the segments, and such a record cannot have been
        // signed by a conforming issuer (an execution-armed issuance
        // writes protocol v4). The rejection is explicit, before any
        // signature work.
        for version in [2u8, 3u8] {
            let mut record = make_record(8);
            record.protocol_version = version;
            if version == 3 {
                record.decoy_field = Some("company_website".to_string());
            }
            record.execution_program = Some(
                crate::execution::generate(
                    b"0123456789abcdef0123456789abcdef",
                    &record.nonce,
                    "login",
                    "login-action",
                    1,
                )
                .unwrap(),
            );
            let counter = solve_for_test(&record).unwrap();
            assert_eq!(
                verify(&mut record, counter, 5000),
                VerifyOutcome::Invalid(VerifyError::MalformedRecord)
            );
        }
    }

    #[test]
    fn protocol_version_four_with_a_tampered_commitment_is_malformed() {
        // The exact armed/unarmed equivalence: a stored program whose
        // hash does not match the signed commitment is rejected before
        // any execution work — substituting the program after signing
        // always invalidates the challenge.
        let mut record = make_record(8);
        record.protocol_version = 4;
        let program = crate::execution::generate(
            b"0123456789abcdef0123456789abcdef",
            &record.nonce,
            "login",
            "login-action",
            1,
        )
        .unwrap();
        record.execution_program = Some(program);
        record.execution_version = Some(1);
        // The commitment does not match the stored program's hash.
        record.execution_commitment = Some("0".repeat(64));
        resign_v2(&mut record, "test-key-32-bytes-0123456789abcd");
        let counter = solve_for_test(&record).unwrap();
        let outcome = verify(&mut record, counter, 5000);
        assert_eq!(
            outcome,
            VerifyOutcome::Invalid(VerifyError::MalformedRecord)
        );
    }

    #[test]
    fn wrong_counter_is_rejected() {
        let mut record = make_record(8);
        // Find a valid counter, then a counter that provably does not
        // meet the target (the alternate small counter can also solve it,
        // which made the earlier `if valid == 0 { 1 } else { 0 }` guess
        // flaky).
        let valid = solve_for_test(&record).unwrap();
        let bad = (0u64..)
            .find(|counter| {
                *counter != valid
                    && derive_hash(&record, *counter)
                        .is_ok_and(|hash| leading_zero_bits(&hash) < record.target_bits)
            })
            .expect("a non-solving counter exists");
        assert_eq!(
            verify(&mut record, bad, 5000),
            VerifyOutcome::Invalid(VerifyError::InsufficientWork)
        );
    }

    #[test]
    fn expired_challenge_is_rejected() {
        let mut record = make_record(8);
        let counter = solve_for_test(&record).unwrap();
        let mut ctx = VerifyContext {
            record: &mut record,
            secret_key: "test-key-32-bytes-0123456789abcd",
            tenant: None,
            secrets_by_kid: None,
            revoked_kids: None,
            counter,
            duration_ms: 5000,
            now_unix: Some(&mut || NOW_UNIX + 121), // past TTL
            now_ns: NOW_NS,
            min_duration_ms: 0,
            expected_scope: None,
            expected_request_binding: RequestBindingExpectation::Unenforced,
            client_ip: Some("1.2.3.4"),
            execution_digest: None,
            execution_trace: None,
            expected_region: None,
            expected_issuer: None,
            expected_policy_version: None,
            policy_version_floor: None,
            telemetry: None,
            enforce_telemetry: false,
            max_attempts: 0,
            rsw_proof: None,
            rsw_modulus_n: None,
            rsw_lambda: None,
            rsw_keyring: None,
            accept_legacy_v1: false,
        };
        assert_eq!(
            verify_solution(&mut ctx),
            VerifyOutcome::Invalid(VerifyError::Expired)
        );
    }

    #[test]
    fn too_fast_solution_is_rejected_server_side() {
        // The floor is enforced with the server clock (now_ns - issued_at_ns),
        // not the forgeable client duration_ms. Here the client claims a
        // long duration but the server measures a sub-floor elapsed time.
        // Deterministic setup: an 8-bit record (solve guaranteed below the
        // 5M counter cap) with an explicit 60 s ctx floor.
        let mut record = make_record(8);
        let counter = solve_for_test(&record).unwrap();
        let mut ctx = VerifyContext {
            record: &mut record,
            secret_key: "test-key-32-bytes-0123456789abcd",
            tenant: None,
            secrets_by_kid: None,
            revoked_kids: None,
            counter,
            duration_ms: 60_000, // client forges a 60 s solve — must NOT help
            now_unix: Some(&mut || NOW_UNIX + 1),
            now_ns: NOW_NS + 1_000_000, // 1 s elapsed < 60 s floor
            min_duration_ms: 60_000,
            expected_scope: None,
            expected_request_binding: RequestBindingExpectation::Unenforced,
            client_ip: Some("1.2.3.4"),
            execution_digest: None,
            execution_trace: None,
            expected_region: None,
            expected_issuer: None,
            expected_policy_version: None,
            policy_version_floor: None,
            rsw_proof: None,
            rsw_modulus_n: None,
            rsw_lambda: None,
            rsw_keyring: None,
            telemetry: None,
            enforce_telemetry: false,
            max_attempts: 0,
            accept_legacy_v1: false,
        };
        assert_eq!(
            verify_solution(&mut ctx),
            VerifyOutcome::Invalid(VerifyError::TooFast)
        );
    }

    #[test]
    fn server_measured_duration_cannot_be_bypassed_with_forged_client_duration() {
        // An adversarial client submits duration_ms=5000; the server measures
        // sub-millisecond elapsed time. The client's claim must be ignored.
        // Deterministic setup: 8-bit record (solve guaranteed below the 5M
        // counter cap) + explicit 60 s floor.
        let mut record = make_record(8);
        let counter = solve_for_test(&record).unwrap();
        // Elapsed: 0 µs (immediately after issuance) — impossibly fast.
        let mut ctx = VerifyContext {
            record: &mut record,
            secret_key: "test-key-32-bytes-0123456789abcd",
            tenant: None,
            secrets_by_kid: None,
            revoked_kids: None,
            counter,
            duration_ms: 5000, // forged
            now_unix: Some(&mut || NOW_UNIX),
            now_ns: NOW_NS, // same µs as issuance
            min_duration_ms: 0,
            expected_scope: None,
            expected_request_binding: RequestBindingExpectation::Unenforced,
            client_ip: Some("1.2.3.4"),
            execution_digest: None,
            execution_trace: None,
            expected_region: None,
            expected_issuer: None,
            expected_policy_version: None,
            policy_version_floor: None,
            telemetry: None,
            enforce_telemetry: false,
            max_attempts: 0,
            accept_legacy_v1: false,
            rsw_proof: None,
            rsw_modulus_n: None,
            rsw_lambda: None,
            rsw_keyring: None,
        };
        assert_eq!(
            verify_solution(&mut ctx),
            VerifyOutcome::Invalid(VerifyError::TooFast)
        );
    }

    #[test]
    fn issued_min_duration_is_floor_for_derived_difficulty() {
        // The floor is derived at issuance from the algorithm + difficulty:
        // it is always positive, scales with difficulty, and Argon2id
        // (memory-hard) floors are far above SHA-256 floors at equal bits.
        let low = make_record(10);
        let high = make_record(20);
        assert!(low.min_duration_ms > 0);
        assert!(high.min_duration_ms >= low.min_duration_ms);
        let argon = make_argon2_record(10, 128);
        assert!(argon.min_duration_ms > low.min_duration_ms);
    }

    #[test]
    fn bad_secret_key_rejects() {
        let mut record = make_record(8);
        let counter = solve_for_test(&record).unwrap();
        let mut ctx = VerifyContext {
            record: &mut record,
            secret_key: "WRONG-KEY-32-bytes-0123456789abc",
            tenant: None,
            secrets_by_kid: None,
            revoked_kids: None,
            counter,
            duration_ms: 5000,
            now_unix: Some(&mut || NOW_UNIX + 1),
            now_ns: NOW_NS + 5_000_000,
            min_duration_ms: 0,
            rsw_proof: None,
            rsw_modulus_n: None,
            rsw_lambda: None,
            rsw_keyring: None,
            expected_scope: None,
            expected_request_binding: RequestBindingExpectation::Unenforced,
            client_ip: Some("1.2.3.4"),
            execution_digest: None,
            execution_trace: None,
            expected_region: None,
            expected_issuer: None,
            expected_policy_version: None,
            policy_version_floor: None,
            telemetry: None,
            enforce_telemetry: false,
            max_attempts: 0,
            accept_legacy_v1: false,
        };
        assert_eq!(
            verify_solution(&mut ctx),
            VerifyOutcome::Invalid(VerifyError::BadSignature)
        );
    }

    #[test]
    fn short_secret_key_rejects_as_bad_signature() {
        // A secret below the 32-byte minimum can never have signed a valid
        // challenge — verification must fail closed (BadSignature), and the
        // attempt is still accounted on the record.
        let mut record = make_record(8);
        let counter = solve_for_test(&record).unwrap();
        let mut ctx = VerifyContext {
            record: &mut record,
            secret_key: "x", // 1 byte — below the hard minimum
            tenant: None,
            secrets_by_kid: None,
            revoked_kids: None,
            counter,
            duration_ms: 5000,
            rsw_proof: None,
            rsw_modulus_n: None,
            rsw_lambda: None,
            rsw_keyring: None,
            now_unix: Some(&mut || NOW_UNIX + 1),
            now_ns: NOW_NS + 5_000_000,
            min_duration_ms: 0,
            expected_scope: None,
            expected_request_binding: RequestBindingExpectation::Unenforced,
            client_ip: Some("1.2.3.4"),
            execution_digest: None,
            execution_trace: None,
            expected_region: None,
            expected_issuer: None,
            expected_policy_version: None,
            policy_version_floor: None,
            telemetry: None,
            enforce_telemetry: false,
            max_attempts: 0,
            accept_legacy_v1: false,
        };
        assert_eq!(
            verify_solution(&mut ctx),
            VerifyOutcome::Invalid(VerifyError::BadSignature)
        );
        assert_eq!(record.attempts_used, 1, "attempt must still be counted");
    }

    #[test]
    fn ip_mismatch_is_rejected_at_core_level() {
        // IP binding must be enforced by the core verifier itself, not left
        // to the route layer.
        let mut record = make_record(8);
        let counter = solve_for_test(&record).unwrap();
        let mut ctx = VerifyContext {
            record: &mut record,
            secret_key: "test-key-32-bytes-0123456789abcd",
            tenant: None,
            secrets_by_kid: None,
            revoked_kids: None,
            counter,
            duration_ms: 5000,
            now_unix: Some(&mut || NOW_UNIX + 1),
            now_ns: NOW_NS + 5_000_000,
            min_duration_ms: 0,
            expected_scope: None,
            expected_request_binding: RequestBindingExpectation::Unenforced,
            client_ip: Some("9.9.9.9"), // different from issuance IP 1.2.3.4
            execution_digest: None,
            execution_trace: None,
            expected_region: None,
            expected_issuer: None,
            expected_policy_version: None,
            policy_version_floor: None,
            telemetry: None,
            enforce_telemetry: false,
            max_attempts: 0,
            accept_legacy_v1: false,
            rsw_proof: None,
            rsw_modulus_n: None,
            rsw_lambda: None,
            rsw_keyring: None,
        };
        assert_eq!(
            verify_solution(&mut ctx),
            VerifyOutcome::Invalid(VerifyError::IpMismatch)
        );
    }

    #[test]
    fn bound_record_without_client_ip_fails_closed() {
        // A non-empty binding tag means the challenge IS bound — omitting
        // the client IP must fail with MissingClientIp, not silently skip
        // the check (the caller must provide the IP it passed to issuance).
        let mut record = make_record(8);
        let counter = solve_for_test(&record).unwrap();
        let mut ctx = VerifyContext {
            record: &mut record,
            secret_key: "test-key-32-bytes-0123456789abcd",
            tenant: None,
            secrets_by_kid: None,
            revoked_kids: None,
            counter,
            duration_ms: 5000,
            now_unix: Some(&mut || NOW_UNIX + 1),
            now_ns: NOW_NS + 5_000_000,
            min_duration_ms: 0,
            expected_scope: None,
            expected_request_binding: RequestBindingExpectation::Unenforced,
            client_ip: None,
            execution_digest: None,
            execution_trace: None,
            expected_region: None,
            expected_issuer: None,
            expected_policy_version: None,
            policy_version_floor: None,
            telemetry: None,
            enforce_telemetry: false,
            max_attempts: 0,
            accept_legacy_v1: false,
            rsw_proof: None,
            rsw_modulus_n: None,
            rsw_lambda: None,
            rsw_keyring: None,
        };
        assert_eq!(
            verify_solution(&mut ctx),
            VerifyOutcome::Invalid(VerifyError::MissingClientIp)
        );

        // A record with an empty binding tag (BindingMode::None) still
        // verifies without an IP — binding is genuinely disabled. Issued
        // properly so the v2 signature (which covers the tag) stays valid.
        let config = ChallengeConfig {
            secret_key: "test-key-32-bytes-0123456789abcd".into(),
            kid: 1,
            execution_key: None,
            rsw_modulus_n: None,
            rsw_lambda: None,
            rsw_t: crate::challenge::DEFAULT_RSW_T,
            tenant: None,
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
            auto_tune_max_bits: 24,
            binding_mode: BindingMode::None,
            region: None,
            issuer: None,

            policy_version: 1,
        };
        let issued =
            issue_challenge(&config, "login", "1.2.3.4", NOW_UNIX, NOW_NS, 0, None).unwrap();
        let mut unbound = issued.record;
        let counter2 = solve_for_test(&unbound).unwrap();
        let mut ctx2 = VerifyContext {
            record: &mut unbound,
            secret_key: "test-key-32-bytes-0123456789abcd",
            tenant: None,
            secrets_by_kid: None,
            rsw_proof: None,
            rsw_modulus_n: None,
            rsw_lambda: None,
            rsw_keyring: None,
            revoked_kids: None,
            counter: counter2,
            duration_ms: 5000,
            now_unix: Some(&mut || NOW_UNIX + 1),
            now_ns: NOW_NS + 5_000_000,
            min_duration_ms: 0,
            expected_scope: None,
            expected_request_binding: RequestBindingExpectation::Unenforced,
            client_ip: Some("1.2.3.4"),
            execution_digest: None,
            execution_trace: None,

            expected_region: None,
            expected_issuer: None,
            expected_policy_version: None,
            policy_version_floor: None,
            telemetry: None,
            enforce_telemetry: false,
            max_attempts: 0,
            accept_legacy_v1: false,
        };
        assert!(matches!(
            verify_solution(&mut ctx2),
            VerifyOutcome::Valid { .. }
        ));
    }

    #[test]
    fn attempt_cap_counts_every_verification() {
        let mut record = make_record(8);
        let counter = solve_for_test(&record).unwrap();
        // First call (even a wrong counter) consumes the single attempt.
        let wrong = if counter == 0 { 1 } else { 0 };
        let mut ctx = VerifyContext {
            record: &mut record,
            secret_key: "test-key-32-bytes-0123456789abcd",
            tenant: None,
            secrets_by_kid: None,
            revoked_kids: None,
            counter: wrong,
            duration_ms: 5000,
            now_unix: Some(&mut || NOW_UNIX + 1),
            now_ns: NOW_NS + 5_000_000,
            min_duration_ms: 0,
            expected_scope: None,
            expected_request_binding: RequestBindingExpectation::Unenforced,
            client_ip: Some("1.2.3.4"),
            execution_digest: None,
            execution_trace: None,
            expected_region: None,
            expected_issuer: None,
            expected_policy_version: None,
            policy_version_floor: None,
            telemetry: None,
            enforce_telemetry: false,
            max_attempts: 1,
            accept_legacy_v1: false,
            rsw_proof: None,
            rsw_modulus_n: None,
            rsw_lambda: None,
            rsw_keyring: None,
        };
        assert_eq!(
            verify_solution(&mut ctx),
            VerifyOutcome::Invalid(VerifyError::InsufficientWork)
        );
        // Second call — the correct counter, but the attempt budget is gone.
        let mut ctx2 = VerifyContext {
            record: &mut record,
            secret_key: "test-key-32-bytes-0123456789abcd",
            tenant: None,
            secrets_by_kid: None,
            revoked_kids: None,
            counter,
            duration_ms: 5000,
            now_unix: Some(&mut || NOW_UNIX + 1),
            now_ns: NOW_NS + 5_000_000,
            min_duration_ms: 0,
            expected_scope: None,
            expected_request_binding: RequestBindingExpectation::Unenforced,
            client_ip: Some("1.2.3.4"),
            execution_digest: None,
            execution_trace: None,
            expected_region: None,
            expected_issuer: None,
            expected_policy_version: None,
            policy_version_floor: None,
            telemetry: None,
            enforce_telemetry: false,
            max_attempts: 1,
            accept_legacy_v1: false,
            rsw_proof: None,
            rsw_modulus_n: None,
            rsw_lambda: None,
            rsw_keyring: None,
        };
        assert_eq!(
            verify_solution(&mut ctx2),
            VerifyOutcome::Invalid(VerifyError::TooManyAttempts)
        );
    }

    #[test]
    fn attempts_are_persisted_on_the_record() {
        // The caller persists `record.attempts_used` back to storage; a fresh
        // verification against the same stored record must observe the count.
        let mut record = make_record(8);
        let counter = solve_for_test(&record).unwrap();
        let wrong = if counter == 0 { 1 } else { 0 };
        let mut ctx = VerifyContext {
            record: &mut record,
            secret_key: "test-key-32-bytes-0123456789abcd",
            tenant: None,
            secrets_by_kid: None,
            revoked_kids: None,
            counter: wrong,
            duration_ms: 5000,
            now_unix: Some(&mut || NOW_UNIX + 1),
            now_ns: NOW_NS + 5_000_000,
            min_duration_ms: 0,
            expected_scope: None,
            expected_request_binding: RequestBindingExpectation::Unenforced,
            client_ip: Some("1.2.3.4"),
            execution_digest: None,
            execution_trace: None,
            expected_region: None,
            expected_issuer: None,
            expected_policy_version: None,
            policy_version_floor: None,
            telemetry: None,
            enforce_telemetry: false,
            max_attempts: 3,
            accept_legacy_v1: false,
            rsw_proof: None,
            rsw_modulus_n: None,
            rsw_lambda: None,
            rsw_keyring: None,
        };
        verify_solution(&mut ctx); // wrong counter
        let attempts = record.attempts_used;
        assert_eq!(attempts, 1);
        let mut ctx2 = VerifyContext {
            record: &mut record,
            rsw_proof: None,
            rsw_modulus_n: None,
            rsw_lambda: None,
            rsw_keyring: None,
            secret_key: "test-key-32-bytes-0123456789abcd",
            tenant: None,
            secrets_by_kid: None,
            revoked_kids: None,
            counter,
            duration_ms: 5000,
            now_unix: Some(&mut || NOW_UNIX + 1),
            now_ns: NOW_NS + 5_000_000,
            min_duration_ms: 0,
            expected_scope: None,
            expected_request_binding: RequestBindingExpectation::Unenforced,
            client_ip: Some("1.2.3.4"),
            execution_digest: None,
            execution_trace: None,
            expected_region: None,
            expected_issuer: None,
            expected_policy_version: None,
            policy_version_floor: None,
            telemetry: None,
            enforce_telemetry: false,
            max_attempts: 3,
            accept_legacy_v1: false,
        };
        assert!(matches!(
            verify_solution(&mut ctx2),
            VerifyOutcome::Valid { .. }
        ));
        assert_eq!(record.attempts_used, 2);
    }

    #[test]
    fn telemetry_enforced_when_requested() {
        use serde_json::json;
        let mut record = make_record(8);
        let counter = solve_for_test(&record).unwrap();

        // webdriver=true with enforcement → rejected.
        let mut ctx = VerifyContext {
            record: &mut record,
            secret_key: "test-key-32-bytes-0123456789abcd",
            tenant: None,
            secrets_by_kid: None,
            revoked_kids: None,
            counter,
            duration_ms: 5000,
            now_unix: Some(&mut || NOW_UNIX + 1),
            now_ns: NOW_NS + 5_000_000,
            min_duration_ms: 0,
            expected_scope: None,
            expected_request_binding: RequestBindingExpectation::Unenforced,
            client_ip: Some("1.2.3.4"),
            execution_digest: None,
            execution_trace: None,
            expected_region: None,
            expected_issuer: None,
            expected_policy_version: None,
            policy_version_floor: None,
            telemetry: Some(&json!({"wd": true})),
            enforce_telemetry: true,
            max_attempts: 0,
            accept_legacy_v1: false,
            rsw_proof: None,
            rsw_modulus_n: None,
            rsw_lambda: None,
            rsw_keyring: None,
        };
        assert_eq!(
            verify_solution(&mut ctx),
            VerifyOutcome::Invalid(VerifyError::BotDetected)
        );
    }

    #[test]
    fn telemetry_enforcement_rejects_absent_telemetry() {
        // A custom non-browser client submits no telemetry at all — in strict
        // mode that is itself a bot signal.
        let mut record = make_record(8);
        let counter = solve_for_test(&record).unwrap();
        let mut ctx = VerifyContext {
            record: &mut record,
            secret_key: "test-key-32-bytes-0123456789abcd",
            tenant: None,
            secrets_by_kid: None,
            revoked_kids: None,
            counter,
            duration_ms: 5000,
            now_unix: Some(&mut || NOW_UNIX + 1),
            now_ns: NOW_NS + 5_000_000,
            min_duration_ms: 0,
            expected_scope: None,
            expected_request_binding: RequestBindingExpectation::Unenforced,
            client_ip: Some("1.2.3.4"),
            execution_digest: None,
            execution_trace: None,
            expected_region: None,
            expected_issuer: None,
            expected_policy_version: None,
            policy_version_floor: None,
            telemetry: None,
            enforce_telemetry: true,
            max_attempts: 0,
            accept_legacy_v1: false,
            rsw_proof: None,
            rsw_modulus_n: None,
            rsw_lambda: None,
            rsw_keyring: None,
        };
        assert_eq!(
            verify_solution(&mut ctx),
            VerifyOutcome::Invalid(VerifyError::BotDetected)
        );
    }

    #[test]
    fn telemetry_enforcement_rejects_empty_object() {
        // The PHP widget emits `{}` when no telemetry was collected — in
        // strict mode an empty payload is the same as no payload: a bot
        // signal. (An empty object must not score as benign.)
        use serde_json::json;
        let mut record = make_record(8);
        let counter = solve_for_test(&record).unwrap();
        let mut ctx = VerifyContext {
            record: &mut record,
            secret_key: "test-key-32-bytes-0123456789abcd",
            tenant: None,
            secrets_by_kid: None,
            revoked_kids: None,
            counter,
            duration_ms: 5000,
            now_unix: Some(&mut || NOW_UNIX + 1),
            now_ns: NOW_NS + 5_000_000,
            min_duration_ms: 0,
            expected_scope: None,
            expected_request_binding: RequestBindingExpectation::Unenforced,
            client_ip: Some("1.2.3.4"),
            execution_digest: None,
            execution_trace: None,
            expected_region: None,
            expected_issuer: None,
            expected_policy_version: None,
            policy_version_floor: None,
            telemetry: Some(&json!({})),
            enforce_telemetry: true,
            rsw_proof: None,
            rsw_modulus_n: None,
            rsw_lambda: None,
            rsw_keyring: None,
            max_attempts: 0,
            accept_legacy_v1: false,
        };
        assert_eq!(
            verify_solution(&mut ctx),
            VerifyOutcome::Invalid(VerifyError::BotDetected)
        );
        // An empty array is equally empty.
        let mut ctx_array = VerifyContext {
            accept_legacy_v1: false,
            rsw_proof: None,
            rsw_modulus_n: None,
            rsw_lambda: None,
            rsw_keyring: None,
            record: &mut record,
            secret_key: "test-key-32-bytes-0123456789abcd",
            tenant: None,
            secrets_by_kid: None,
            revoked_kids: None,
            counter,
            duration_ms: 5000,
            now_unix: Some(&mut || NOW_UNIX + 1),
            now_ns: NOW_NS + 5_000_000,
            min_duration_ms: 0,
            expected_scope: None,
            expected_request_binding: RequestBindingExpectation::Unenforced,
            client_ip: Some("1.2.3.4"),
            execution_digest: None,
            execution_trace: None,
            expected_region: None,
            expected_issuer: None,
            expected_policy_version: None,
            policy_version_floor: None,
            telemetry: Some(&json!([])),
            enforce_telemetry: true,
            max_attempts: 0,
        };
        assert_eq!(
            verify_solution(&mut ctx_array),
            VerifyOutcome::Invalid(VerifyError::BotDetected)
        );
    }

    #[test]
    fn telemetry_enforcement_rejects_null() {
        // JSON null carries no telemetry signal — treated like an empty
        // payload in strict mode.
        use serde_json::json;
        let mut record = make_record(8);
        let counter = solve_for_test(&record).unwrap();
        let mut ctx = VerifyContext {
            record: &mut record,
            secret_key: "test-key-32-bytes-0123456789abcd",
            tenant: None,
            secrets_by_kid: None,
            revoked_kids: None,
            counter,
            duration_ms: 5000,
            now_unix: Some(&mut || NOW_UNIX + 1),
            now_ns: NOW_NS + 5_000_000,
            min_duration_ms: 0,
            expected_scope: None,
            expected_request_binding: RequestBindingExpectation::Unenforced,
            client_ip: Some("1.2.3.4"),
            execution_digest: None,
            execution_trace: None,
            expected_region: None,
            expected_issuer: None,
            expected_policy_version: None,
            policy_version_floor: None,
            telemetry: Some(&json!(null)),
            enforce_telemetry: true,
            max_attempts: 0,
            accept_legacy_v1: false,
            rsw_proof: None,
            rsw_modulus_n: None,
            rsw_lambda: None,
            rsw_keyring: None,
        };
        assert_eq!(
            verify_solution(&mut ctx),
            VerifyOutcome::Invalid(VerifyError::BotDetected)
        );
    }

    #[test]
    fn telemetry_enforcement_accepts_benign_telemetry() {
        // A non-empty, non-webdriver payload passes strict mode: the empty-
        // payload check must not reject real widget telemetry.
        use serde_json::json;
        let mut record = make_record(8);
        let counter = solve_for_test(&record).unwrap();
        let mut ctx = VerifyContext {
            record: &mut record,
            secret_key: "test-key-32-bytes-0123456789abcd",
            tenant: None,
            secrets_by_kid: None,
            revoked_kids: None,
            counter,
            duration_ms: 5000,
            now_unix: Some(&mut || NOW_UNIX + 1),
            now_ns: NOW_NS + 5_000_000,
            min_duration_ms: 0,
            expected_scope: None,
            expected_request_binding: RequestBindingExpectation::Unenforced,
            client_ip: Some("1.2.3.4"),
            execution_digest: None,
            execution_trace: None,
            expected_region: None,
            expected_issuer: None,
            expected_policy_version: None,
            policy_version_floor: None,
            telemetry: Some(&json!({
                "wd": false, "hc": 8, "dm": 8, "me": 5, "ke": 2, "et": []
            })),
            enforce_telemetry: true,
            max_attempts: 0,
            accept_legacy_v1: false,
            rsw_proof: None,
            rsw_modulus_n: None,
            rsw_lambda: None,
            rsw_keyring: None,
        };
        assert!(matches!(
            verify_solution(&mut ctx),
            VerifyOutcome::Valid { .. }
        ));
    }

    #[test]
    fn telemetry_ignored_when_not_enforced() {
        use serde_json::json;
        let mut record = make_record(8);
        let counter = solve_for_test(&record).unwrap();
        let mut ctx = VerifyContext {
            record: &mut record,
            secret_key: "test-key-32-bytes-0123456789abcd",
            tenant: None,
            secrets_by_kid: None,
            revoked_kids: None,
            counter,
            duration_ms: 5000,
            now_unix: Some(&mut || NOW_UNIX + 1),
            now_ns: NOW_NS + 5_000_000,
            min_duration_ms: 0,
            expected_scope: None,
            expected_request_binding: RequestBindingExpectation::Unenforced,
            client_ip: Some("1.2.3.4"),
            execution_digest: None,
            execution_trace: None,
            expected_region: None,
            expected_issuer: None,
            expected_policy_version: None,
            policy_version_floor: None,
            telemetry: Some(&json!({"wd": true})),
            enforce_telemetry: false,
            max_attempts: 0,
            accept_legacy_v1: false,
            rsw_proof: None,
            rsw_modulus_n: None,
            rsw_lambda: None,
            rsw_keyring: None,
        };
        assert!(matches!(
            verify_solution(&mut ctx),
            VerifyOutcome::Valid { .. }
        ));
    }

    #[test]
    fn records_without_issued_at_ns_are_malformed() {
        // Records without a high-resolution issuance timestamp (issued_at_ns
        // == 0) are rejected as MalformedRecord — there is no client-duration
        // fallback: the floor can only be enforced with a
        // server-measured elapsed time. The record is issued with ns=0 so
        // its server-state MAC is valid: the malformed gate is what
        // refuses it, not the MAC.
        let mut record = make_record_at(8, NOW_UNIX, 0);
        let counter = solve_for_test(&record).unwrap();
        let mut ctx = VerifyContext {
            record: &mut record,
            secret_key: "test-key-32-bytes-0123456789abcd",
            tenant: None,
            secrets_by_kid: None,
            revoked_kids: None,
            counter,
            duration_ms: 60_000, // a forged long client duration must NOT resurrect the legacy path
            now_unix: Some(&mut || NOW_UNIX + 1),
            now_ns: NOW_NS + 10_000_000,
            min_duration_ms: 0,
            expected_scope: None,
            expected_request_binding: RequestBindingExpectation::Unenforced,
            client_ip: Some("1.2.3.4"),
            execution_digest: None,
            execution_trace: None,
            expected_region: None,
            expected_issuer: None,
            expected_policy_version: None,
            policy_version_floor: None,
            telemetry: None,
            enforce_telemetry: false,
            max_attempts: 0,
            accept_legacy_v1: false,
            rsw_proof: None,
            rsw_modulus_n: None,
            rsw_lambda: None,
            rsw_keyring: None,
        };
        assert_eq!(
            verify_solution(&mut ctx),
            VerifyOutcome::Invalid(VerifyError::MalformedRecord)
        );

        // Rewriting the issuance clock of a properly issued record
        // without re-sealing the server-state MAC is the fraud the MAC
        // exists to catch: it fails closed as a signature error, never as
        // a merely malformed record.
        let mut rewritten = make_record(8);
        rewritten.issued_at_ns = 0;
        let counter = solve_for_test(&rewritten).unwrap();
        let mut rewritten_ctx = VerifyContext {
            record: &mut rewritten,
            secret_key: "test-key-32-bytes-0123456789abcd",
            tenant: None,
            secrets_by_kid: None,
            revoked_kids: None,
            counter,
            duration_ms: 60_000,
            now_unix: Some(&mut || NOW_UNIX + 1),
            now_ns: NOW_NS + 10_000_000,
            min_duration_ms: 0,
            expected_scope: None,
            expected_request_binding: RequestBindingExpectation::Unenforced,
            client_ip: Some("1.2.3.4"),
            execution_digest: None,
            execution_trace: None,
            expected_region: None,
            expected_issuer: None,
            expected_policy_version: None,
            policy_version_floor: None,
            telemetry: None,
            enforce_telemetry: false,
            max_attempts: 0,
            accept_legacy_v1: false,
            rsw_proof: None,
            rsw_modulus_n: None,
            rsw_lambda: None,
            rsw_keyring: None,
        };
        assert_eq!(
            verify_solution(&mut rewritten_ctx),
            VerifyOutcome::Invalid(VerifyError::BadSignature),
            "a rewritten issuance clock must fail the server-state MAC"
        );
    }

    #[test]
    fn clock_skew_within_tolerance_skips_the_floor() {
        // Issuer host ahead of verifier host by 1 s (within the 5 s skew
        // tolerance): the floor heuristic is skipped and a correct PoW
        // passes.
        let mut record = make_record(8);
        let counter = solve_for_test(&record).unwrap();
        assert!(record.min_duration_ms > 0, "record floor must be positive");
        let mut ctx = VerifyContext {
            record: &mut record,
            secret_key: "test-key-32-bytes-0123456789abcd",
            tenant: None,
            secrets_by_kid: None,
            revoked_kids: None,
            counter,
            duration_ms: 5000,
            now_unix: Some(&mut || NOW_UNIX + 1),
            now_ns: NOW_NS.saturating_sub(1_000_000), // 1 s skew, issuer ahead
            min_duration_ms: 0,
            expected_scope: None,
            expected_request_binding: RequestBindingExpectation::Unenforced,
            client_ip: Some("1.2.3.4"),
            execution_digest: None,
            execution_trace: None,
            expected_region: None,
            expected_issuer: None,
            expected_policy_version: None,
            policy_version_floor: None,
            telemetry: None,
            enforce_telemetry: false,
            max_attempts: 0,
            accept_legacy_v1: false,
            rsw_proof: None,
            rsw_modulus_n: None,
            rsw_lambda: None,
            rsw_keyring: None,
        };
        assert!(matches!(
            verify_solution(&mut ctx),
            VerifyOutcome::Valid { .. }
        ));
    }

    #[test]
    fn clock_skew_beyond_tolerance_is_rejected() {
        // Issuer host ahead by 6 s (beyond the 5 s skew tolerance): clocks
        // are broken — the timing guarantee is void and the solution is
        // rejected.
        let mut record = make_record(8);
        let counter = solve_for_test(&record).unwrap();
        let mut ctx = VerifyContext {
            record: &mut record,
            secret_key: "test-key-32-bytes-0123456789abcd",
            tenant: None,
            secrets_by_kid: None,
            revoked_kids: None,
            counter,
            duration_ms: 5000,
            now_unix: Some(&mut || NOW_UNIX + 1),
            now_ns: NOW_NS.saturating_sub(6_000_000), // 6 s skew
            min_duration_ms: 0,
            expected_scope: None,
            expected_request_binding: RequestBindingExpectation::Unenforced,
            client_ip: Some("1.2.3.4"),
            execution_digest: None,
            execution_trace: None,
            expected_region: None,
            expected_issuer: None,
            expected_policy_version: None,
            policy_version_floor: None,
            telemetry: None,
            enforce_telemetry: false,
            max_attempts: 0,
            accept_legacy_v1: false,
            rsw_proof: None,
            rsw_modulus_n: None,
            rsw_lambda: None,
            rsw_keyring: None,
        };
        assert_eq!(
            verify_solution(&mut ctx),
            VerifyOutcome::Invalid(VerifyError::TooFast)
        );
    }

    #[test]
    fn leading_zero_bits_counts_correctly() {
        assert_eq!(leading_zero_bits(&[0u8, 0xFF]), 8);
        assert_eq!(leading_zero_bits(&[0u8, 0x0F]), 12);
        assert_eq!(leading_zero_bits(&[0x00, 0x00, 0x01]), 23);
        assert_eq!(leading_zero_bits(&[0xFF]), 0);
        assert_eq!(leading_zero_bits(&[]), 0);
    }

    #[test]
    fn telemetry_bot_detection_works() {
        use serde_json::json;

        // Normal user: irregular discrete-event timings (jittered pointerdowns)
        let t1 = json!({
            "wd": false,
            "me": 50,
            "ke": 10,
            "et": [100, 187, 296, 412, 531, 640, 772, 881, 990, 1107, 1221, 1330, 1449, 1561, 1670, 1788, 1899, 2012, 2124, 2233, 2348, 2461, 2577, 2688, 2801, 2913]
        });
        assert!(!score_telemetry(&t1, 5000));

        // Webdriver rejection
        let t2 = json!({"wd": true});
        assert!(score_telemetry(&t2, 5000));

        // Too slow rejection
        assert!(score_telemetry(&t1, 301_000));

        // A long solve with zero interaction is NOT rejected: the widget
        // auto-solves with widget-local listeners, so a slow device or an
        // Argon2id profile legitimately produces no events.
        let t3 = json!({"wd": false, "me": 0, "ke": 0});
        assert!(!score_telemetry(&t3, 31_000));
        assert!(!score_telemetry(&t3, 299_000));

        // Bot simulation rejection: 24+ discrete events at perfectly uniform
        // intervals (CV ~ 0, mean >= 8ms).
        let uniform: Vec<u64> = (0..30).map(|i| 100 + i * 100).collect();
        let t4 = json!({
            "wd": false,
            "me": 20,
            "ke": 0,
            "et": uniform
        });
        assert!(score_telemetry(&t4, 5000));

        // Human-like jittered timing must NOT be rejected even with many events.
        let jittered: Vec<u64> = (0..30).map(|i| i * 97 + (i * 7 % 13)).collect();
        let t5 = json!({
            "wd": false,
            "me": 20,
            "ke": 0,
            "et": jittered
        });
        assert!(!score_telemetry(&t5, 5000));

        // Sub-frame events (1-2ms diffs) must NOT be rejected: coalesced events
        // can round to identical millisecond timestamps.
        let subframe: Vec<u64> = (0..30).map(|i| i * 2).collect();
        let t6 = json!({
            "wd": false,
            "me": 20,
            "ke": 0,
            "et": subframe
        });
        assert!(!score_telemetry(&t6, 5000));

        // Sparse human events (mean interval > 8ms, high variance) pass.
        let sparse: Vec<u64> = (0..30).map(|i| i * 143 + (i * 11 % 37)).collect();
        let t7 = json!({
            "wd": false,
            "me": 20,
            "ke": 0,
            "et": sparse
        });
        assert!(!score_telemetry(&t7, 5000));
    }

    // ── Aggressive bot-detection suite ────────────────────────────────────

    #[test]
    fn telemetry_rejects_precise_keyboard_autorepeat_patterns() {
        // A headless solver that "types" with exact 30ms OS auto-repeat timing.
        use serde_json::json;
        let uniform_30ms: Vec<u64> = (0..30).map(|i| 100 + i * 30).collect();
        let t = json!({
            "wd": false, "me": 0, "ke": 30, "et": uniform_30ms
        });
        assert!(
            score_telemetry(&t, 4000),
            "uniform 30ms discrete events must be rejected"
        );
    }

    #[test]
    fn telemetry_rejects_exact_60hz_pointer_timestamps() {
        // Mouse-move replay at exactly 16.67ms (display refresh) with zero jitter.
        use serde_json::json;
        let uniform_16ms: Vec<u64> = (0..30).map(|i| 500 + i * 17).collect();
        let t = json!({
            "wd": false, "me": 30, "ke": 0, "et": uniform_16ms
        });
        assert!(
            score_telemetry(&t, 4000),
            "exact 16-17ms discrete intervals must be rejected"
        );
    }

    #[test]
    fn telemetry_accepts_human_jitter_at_many_scales() {
        use serde_json::json;
        // Human click intervals vary 5-30%; none of these should reject.
        let cases: Vec<Vec<u64>> = vec![
            (0..30).map(|i| i * 87 + (i * i % 23)).collect(), // fast typist
            (0..30).map(|i| i * 145 + (i * 3 % 31)).collect(), // slow reader
            (0..30).map(|i| i * 64 + (i * 7 % 11)).collect(), // burst clicking
            (0..30).map(|i| i * 203 + (i % 5) * 17).collect(), // sparse + jitter
        ];
        for (i, et) in cases.iter().enumerate() {
            let t = json!({ "wd": false, "me": 20, "ke": 5, "et": et });
            assert!(
                !score_telemetry(&t, 5000),
                "human-like timing case {i} must not be rejected"
            );
        }
    }

    #[test]
    fn challenge_expiring_during_the_derivation_is_rejected_by_the_post_derive_clock() {
        // The verifier reads the injectable clock twice, itself: once
        // at receipt (the cheap-phase TTL) and once after derive_hash
        // (the final re-validation). A caller-precomputed timestamp
        // could not detect a challenge that expired while the proof was
        // deriving, so the closure answers the first call (receipt)
        // inside the window and the second call (post-derive) past
        // expiry — the exact race the closure-time field could not express.
        let mut record = make_record(8);
        let counter = solve_for_test(&record).unwrap();
        let expires_at = record.expires_at;
        let mut clock_calls = 0;
        let mut ctx = VerifyContext {
            record: &mut record,
            secret_key: "test-key-32-bytes-0123456789abcd",
            tenant: None,
            secrets_by_kid: None,
            revoked_kids: None,
            counter,
            duration_ms: 5000,
            now_unix: Some(&mut || {
                clock_calls += 1;
                if clock_calls == 1 {
                    expires_at - 1
                } else {
                    expires_at + 1
                }
            }),
            now_ns: NOW_NS + 5_000_000,
            min_duration_ms: 0,
            expected_scope: None,
            expected_request_binding: RequestBindingExpectation::Unenforced,
            expected_region: None,
            expected_issuer: None,
            expected_policy_version: None,
            policy_version_floor: None,
            client_ip: Some("1.2.3.4"),
            execution_digest: None,
            execution_trace: None,
            telemetry: None,
            enforce_telemetry: false,
            max_attempts: 0,
            accept_legacy_v1: false,
            rsw_proof: None,
            rsw_modulus_n: None,
            rsw_lambda: None,
            rsw_keyring: None,
        };
        assert_eq!(
            verify_solution(&mut ctx),
            VerifyOutcome::Invalid(VerifyError::Expired),
            "a challenge that expired during the expensive derivation must be Expired"
        );
        assert_eq!(
            clock_calls, 2,
            "the verifier must read the clock twice: receipt + post-derive"
        );

        // A steady clock inside the window verifies.
        let mut record2 = make_record(8);
        let counter2 = solve_for_test(&record2).unwrap();
        let mut ctx2 = VerifyContext {
            record: &mut record2,
            secret_key: "test-key-32-bytes-0123456789abcd",
            tenant: None,
            secrets_by_kid: None,
            revoked_kids: None,
            counter: counter2,
            duration_ms: 5000,
            now_unix: Some(&mut || expires_at - 10),
            now_ns: NOW_NS + 5_000_000,
            min_duration_ms: 0,
            expected_scope: None,
            expected_request_binding: RequestBindingExpectation::Unenforced,
            expected_region: None,
            expected_issuer: None,
            expected_policy_version: None,
            policy_version_floor: None,
            client_ip: Some("1.2.3.4"),
            execution_digest: None,
            execution_trace: None,
            telemetry: None,
            enforce_telemetry: false,
            max_attempts: 0,
            accept_legacy_v1: false,
            rsw_proof: None,
            rsw_modulus_n: None,
            rsw_lambda: None,
            rsw_keyring: None,
        };
        assert!(matches!(
            verify_solution(&mut ctx2),
            VerifyOutcome::Valid { .. }
        ));
    }

    #[test]
    fn the_safe_default_clock_is_the_real_system_clock() {
        // No injected clock (the documented integration default): the
        // verifier reads the real system clock itself, so a freshly
        // issued challenge verifies (the TTL + the post-derive checks
        // both use the live clock, not a caller snapshot). The record is
        // issued at the real clock; make_record's fixed test epoch
        // would look future-dated to the live clock.
        let now = real_now_unix();
        let now_ns = crate::challenge::now_epoch_micros();
        let mut record = make_record_at(8, now, now_ns);
        let counter = solve_for_test(&record).unwrap();
        let mut ctx = VerifyContext {
            record: &mut record,
            secret_key: "test-key-32-bytes-0123456789abcd",
            tenant: None,
            secrets_by_kid: None,
            revoked_kids: None,
            counter,
            duration_ms: 5000,
            now_unix: None,
            now_ns: now_ns + 5_000_000,
            min_duration_ms: 0,
            expected_scope: None,
            expected_request_binding: RequestBindingExpectation::Unenforced,
            expected_region: None,
            expected_issuer: None,
            expected_policy_version: None,
            policy_version_floor: None,
            client_ip: Some("1.2.3.4"),
            execution_digest: None,
            execution_trace: None,
            telemetry: None,
            enforce_telemetry: false,
            max_attempts: 0,
            accept_legacy_v1: false,
            rsw_proof: None,
            rsw_modulus_n: None,
            rsw_lambda: None,
            rsw_keyring: None,
        };
        assert!(
            matches!(verify_solution(&mut ctx), VerifyOutcome::Valid { .. }),
            "the None default reads the live system clock and verifies a fresh challenge"
        );
    }

    #[test]
    fn telemetry_rejects_webdriver_combined_with_normal_timing() {
        // A bot that fakes human timing but leaves webdriver=true.
        use serde_json::json;
        let jittered: Vec<u64> = (0..30).map(|i| i * 97 + (i * 7 % 13)).collect();
        let t = json!({ "wd": true, "me": 20, "ke": 0, "et": jittered });
        assert!(score_telemetry(&t, 5000));
    }

    #[test]
    fn telemetry_does_not_reject_long_auto_solve_without_interaction() {
        use serde_json::json;
        let t = json!({ "wd": false, "me": 0, "ke": 0, "et": [] });
        // The widget auto-solves and listens only on the widget: no
        // interaction is the ordinary case, not a bot signal.
        assert!(!score_telemetry(&t, 31_000));
        assert!(!score_telemetry(&t, 299_000));
        assert!(!score_telemetry(&t, 4000));
        // The absolute solve bound still rejects.
        assert!(score_telemetry(&t, 301_000));
    }

    #[test]
    fn telemetry_accepts_mobile_touch_users() {
        // Mobile users have no mouse/keyboard events — pointer/touch events
        // feed `me`, so a slow mobile solve with touch interaction must pass.
        use serde_json::json;
        let jittered: Vec<u64> = (0..30).map(|i| i * 122 + (i * 5 % 19)).collect();
        let t = json!({ "wd": false, "me": 12, "ke": 0, "et": jittered });
        assert!(!score_telemetry(&t, 25_000));
    }

    #[test]
    fn telemetry_ignores_sparse_or_absent_event_timings() {
        use serde_json::json;
        // Fewer than 24 events: entropy check must not fire.
        let few: Vec<u64> = (0..10).map(|i| 100 + i * 100).collect();
        let t = json!({ "wd": false, "me": 5, "ke": 0, "et": few });
        assert!(!score_telemetry(&t, 5000));
        // No events at all.
        let none = json!({ "wd": false, "me": 0, "ke": 0, "et": [] });
        assert!(!score_telemetry(&none, 5000));
    }

    // ── Aggressive verification suite ─────────────────────────────────────

    #[test]
    fn verify_rejects_counter_beyond_solver_cap() {
        // The solver caps at 5M hashes; verify_solution must reject
        // larger counters deterministically (a huge counter is not a
        // legitimate solution and must never reach hash derivation).
        let mut record = make_record(4);
        let huge = crate::challenge::SOLVER_MAX_HASHES + 1;
        let outcome = verify(&mut record, huge, 5000);
        assert_eq!(
            outcome,
            VerifyOutcome::Invalid(VerifyError::CounterTooLarge)
        );

        // The cap value itself is also rejected: the official decoder
        // rejects counter >= the solver cap (20,000,000; the JS solver
        // searches 0..19,999,999), so the direct verifier must match the
        // protocol contract.
        let mut record2 = make_record(4);
        let outcome = verify(&mut record2, crate::challenge::SOLVER_MAX_HASHES, 5000);
        assert_eq!(
            outcome,
            VerifyOutcome::Invalid(VerifyError::CounterTooLarge)
        );
    }

    #[test]
    fn verify_rejects_tampered_challenge_string() {
        let mut record = make_record(8);
        let counter = solve_for_test(&record).unwrap();
        // Tamper with the stored challenge string (simulates a client that
        // modified the signed payload). The record is structurally malformed
        // (prefix no longer matches challenge|salt|), so the cheap
        // validate_record phase rejects it first.
        record.challenge.push_str("00");
        assert_eq!(
            verify(&mut record, counter, 5000),
            VerifyOutcome::Invalid(VerifyError::MalformedRecord)
        );
    }

    #[test]
    fn verify_rejects_wrong_scope() {
        let mut record = make_record(8);
        let counter = solve_for_test(&record).unwrap();
        let mut ctx = VerifyContext {
            record: &mut record,
            secret_key: "test-key-32-bytes-0123456789abcd",
            tenant: None,
            secrets_by_kid: None,
            revoked_kids: None,
            counter,
            duration_ms: 5000,
            now_unix: Some(&mut || 1_000_001),
            now_ns: NOW_NS + 5_000_000,
            min_duration_ms: 0,
            expected_scope: Some("signup"),
            expected_request_binding: RequestBindingExpectation::Unenforced,
            client_ip: Some("1.2.3.4"),
            execution_digest: None,
            execution_trace: None,
            expected_region: None,
            expected_issuer: None,
            expected_policy_version: None,
            policy_version_floor: None,
            telemetry: None,
            enforce_telemetry: false,
            max_attempts: 0,
            accept_legacy_v1: false,
            rsw_proof: None,
            rsw_modulus_n: None,
            rsw_lambda: None,
            rsw_keyring: None,
        };
        assert_eq!(
            verify_solution(&mut ctx),
            VerifyOutcome::Invalid(VerifyError::WrongScope)
        );
    }

    #[test]
    fn verify_rejects_expired_exactly_at_ttl_boundary() {
        let mut record = make_record(8);
        let counter = solve_for_test(&record).unwrap();
        let expires_at = record.expires_at;
        let mut ctx = VerifyContext {
            record: &mut record,
            secret_key: "test-key-32-bytes-0123456789abcd",
            tenant: None,
            secrets_by_kid: None,
            revoked_kids: None,
            counter,
            duration_ms: 5000,
            now_unix: Some(&mut || expires_at), // exactly at expiry
            now_ns: NOW_NS + 5_000_000,
            min_duration_ms: 0,
            expected_scope: None,
            expected_request_binding: RequestBindingExpectation::Unenforced,
            client_ip: Some("1.2.3.4"),
            execution_digest: None,
            execution_trace: None,
            expected_region: None,
            expected_issuer: None,
            expected_policy_version: None,
            policy_version_floor: None,
            telemetry: None,
            enforce_telemetry: false,
            max_attempts: 0,
            accept_legacy_v1: false,
            rsw_proof: None,
            rsw_modulus_n: None,
            rsw_lambda: None,
            rsw_keyring: None,
        };
        assert_eq!(
            verify_solution(&mut ctx),
            VerifyOutcome::Invalid(VerifyError::Expired)
        );
    }

    #[test]
    fn verify_accepts_exactly_at_ttl_boundary_minus_one() {
        let mut record = make_record(8);
        let counter = solve_for_test(&record).unwrap();
        let expires_at = record.expires_at;
        let mut ctx = VerifyContext {
            record: &mut record,
            secret_key: "test-key-32-bytes-0123456789abcd",
            tenant: None,
            secrets_by_kid: None,
            revoked_kids: None,
            counter,
            duration_ms: 5000,
            now_unix: Some(&mut || expires_at - 1),
            now_ns: NOW_NS + 5_000_000,
            min_duration_ms: 0,
            expected_scope: None,
            expected_request_binding: RequestBindingExpectation::Unenforced,
            client_ip: Some("1.2.3.4"),
            execution_digest: None,
            execution_trace: None,
            expected_region: None,
            expected_issuer: None,
            expected_policy_version: None,
            policy_version_floor: None,
            telemetry: None,
            enforce_telemetry: false,
            max_attempts: 0,
            accept_legacy_v1: false,
            rsw_proof: None,
            rsw_modulus_n: None,
            rsw_lambda: None,
            rsw_keyring: None,
        };
        assert!(matches!(
            verify_solution(&mut ctx),
            VerifyOutcome::Valid { .. }
        ));
    }

    #[test]
    fn verify_rejects_wrong_ip_binding_at_verify_level() {
        // IP binding is enforced in the api-server route (auth.rs), but the
        // record stores the ip_hash — ensure the hash function is stable and
        // distinct for different IPs.
        let h1 = hash_ip("1.2.3.4", "salt");
        let h2 = hash_ip("1.2.3.5", "salt");
        let h3 = hash_ip("1.2.3.4", "salt");
        assert_ne!(h1, h2, "different IPs must hash differently");
        assert_eq!(h1, h3, "same IP must hash identically");
        assert_eq!(h1.len(), 64, "sha256 hex output");
    }

    #[test]
    fn verify_argon2_mode_rejects_wrong_algorithm_hash() {
        // A challenge issued as Argon2id must NOT accept a SHA-256 solution
        // counter and vice versa — the algorithm is part of the contract.
        let sha_record = make_record(8);
        let mut argon_record = make_argon2_record(8, 128);
        let sha_counter = solve_for_test(&sha_record).unwrap();

        // Deterministic core assertion: the two algorithms derive different
        // hashes for the same counter (the algorithm is part of the input).
        let sha_hash = derive_hash(&sha_record, sha_counter).unwrap();
        let argon_hash = derive_hash(&argon_record, sha_counter).unwrap();
        assert_ne!(
            sha_hash, argon_hash,
            "SHA-256 and Argon2id must derive different hashes for the same counter"
        );

        // Outcome assertion with a PROVABLY-failing counter: at 8 bits a
        // random counter meets the target with p=1/256 (a flake seen in
        // CI), so search upward until the Argon hash provably misses.
        let target = argon_record.target_bits;
        let mut wrong = sha_counter;
        while derive_hash(&argon_record, wrong)
            .map(|h| leading_zero_bits(&h) >= target)
            .unwrap_or(true)
        {
            wrong = wrong.wrapping_add(1);
        }
        assert_eq!(
            verify(&mut argon_record, wrong, 5000),
            VerifyOutcome::Invalid(VerifyError::InsufficientWork)
        );
    }

    #[test]
    fn verify_argon2_memory_ceiling_rejects_absurd_params() {
        // m_kib above the browser-solvable ceiling must be rejected up front,
        // not run (a memory-hard hash with 4 TiB would OOM the server).
        // Solve with sane params first (fast), then verify against the
        // absurd-params record — properly signed, so the ceiling check is
        // what fires: UnsupportedArgon2Params, the PHP core's twin code,
        // before any hashing.
        let sane = make_argon2_record(4, 128);
        let counter = solve_for_test(&sane).unwrap();
        let mut absurd = sane.clone();
        absurd.m_kib = crate::challenge::SOLVER_MAX_ARGON2_M_KIB + 1;
        resign_v2(&mut absurd, "test-key-32-bytes-0123456789abcd");
        assert_eq!(
            verify(&mut absurd, counter, 5000),
            VerifyOutcome::Invalid(VerifyError::UnsupportedArgon2Params)
        );
    }

    #[test]
    fn verify_duration_floor_is_per_challenge() {
        // The record's own floor is authoritative when ctx.min_duration_ms
        // is 0. Deterministic setup: 8-bit record (solve guaranteed below
        // the 5M solver cap); its issued SHA-256 floor is 5 ms.
        let mut record = make_record(8);
        let counter = solve_for_test(&record).unwrap();
        assert_eq!(record.min_duration_ms, 5);
        let mut ctx = VerifyContext {
            record: &mut record,
            secret_key: "test-key-32-bytes-0123456789abcd",
            tenant: None,
            secrets_by_kid: None,
            revoked_kids: None,
            counter,
            duration_ms: 5000,
            now_unix: Some(&mut || NOW_UNIX + 1),
            now_ns: NOW_NS + 6_000, // 6 ms elapsed > 5 ms floor (µs)
            min_duration_ms: 0,
            expected_scope: None,
            expected_request_binding: RequestBindingExpectation::Unenforced,
            client_ip: Some("1.2.3.4"),
            execution_digest: None,
            execution_trace: None,
            expected_region: None,
            expected_issuer: None,
            expected_policy_version: None,
            policy_version_floor: None,
            telemetry: None,
            enforce_telemetry: false,
            max_attempts: 0,
            accept_legacy_v1: false,
            rsw_proof: None,
            rsw_modulus_n: None,
            rsw_lambda: None,
            rsw_keyring: None,
        };
        assert!(matches!(
            verify_solution(&mut ctx),
            VerifyOutcome::Valid { .. }
        ));
        let mut ctx_fast = VerifyContext {
            record: &mut record,
            secret_key: "test-key-32-bytes-0123456789abcd",
            tenant: None,
            secrets_by_kid: None,
            revoked_kids: None,
            counter,
            duration_ms: 60_000, // forged long client duration must NOT help
            now_unix: Some(&mut || NOW_UNIX + 1),
            now_ns: NOW_NS + 4_999, // 4.999 ms elapsed < 5 ms floor (µs)
            min_duration_ms: 0,
            expected_scope: None,
            expected_request_binding: RequestBindingExpectation::Unenforced,
            client_ip: Some("1.2.3.4"),
            execution_digest: None,
            execution_trace: None,
            expected_region: None,
            expected_issuer: None,
            expected_policy_version: None,
            policy_version_floor: None,
            telemetry: None,
            enforce_telemetry: false,
            max_attempts: 0,
            accept_legacy_v1: false,
            rsw_proof: None,
            rsw_modulus_n: None,
            rsw_lambda: None,
            rsw_keyring: None,
        };
        assert_eq!(
            verify_solution(&mut ctx_fast),
            VerifyOutcome::Invalid(VerifyError::TooFast)
        );
    }

    #[test]
    fn verify_accepts_full_difficulty_range() {
        // Every difficulty from 1 to the solver cap must issue and verify.
        // (0 is rejected at issuance with InvalidDifficulty.) The solver
        // search is capped at the real solver's hash limit:
        // at 20 bits no counter exists within the cap with p ≈ 0.85% — that
        // is the documented "Exhausted" outcome, so the test asserts Valid
        // when a counter exists and accepts cap-exhaustion at 20 bits only.
        for bits in [1u32, 4, 8, 12, 16, 20] {
            let mut record = make_record(bits);
            match solve_for_test(&record) {
                Some(counter) => {
                    let outcome = verify(&mut record, counter, 5000);
                    assert!(
                        matches!(outcome, VerifyOutcome::Valid { .. }),
                        "difficulty {bits} bits must verify"
                    );
                }
                None => {
                    assert!(
                        bits >= 20,
                        "sub-20-bit difficulties must always find a counter within the solver cap"
                    );
                }
            }
        }
    }

    #[test]
    fn sha256_hex_matches_reference() {
        // RFC 6234 test vector for SHA-256("abc").
        assert_eq!(
            sha256_hex("abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    // ── validate_record, binding_tag, protocol v1/v2 ────────────────────

    #[test]
    fn validate_record_rejects_malformed_records() {
        let mut bad_nonce = make_record(8);
        bad_nonce.nonce = B64.encode([0u8; 4]); // decodes to 4 bytes, not 32
        assert_eq!(
            validate_record(&bad_nonce),
            Err(VerifyError::MalformedRecord)
        );

        let mut bad_salt = make_record(8);
        bad_salt.salt = B64.encode([0u8; 4]); // decodes to 4 bytes, not 16
        assert_eq!(
            validate_record(&bad_salt),
            Err(VerifyError::MalformedRecord)
        );

        let mut bad_prefix = make_record(8);
        bad_prefix.prefix.push('x'); // no longer exactly challenge|salt|
        assert_eq!(
            validate_record(&bad_prefix),
            Err(VerifyError::MalformedRecord)
        );

        let mut bad_ttl = make_record(8);
        bad_ttl.expires_at = bad_ttl.issued_at + 301; // beyond the TTL cap
        assert_eq!(validate_record(&bad_ttl), Err(VerifyError::MalformedRecord));

        let mut bad_scope = make_record(8);
        bad_scope.scope = "login|admin".into(); // contains the separator
        assert_eq!(
            validate_record(&bad_scope),
            Err(VerifyError::MalformedRecord)
        );

        let mut sha_zero = make_record(8);
        sha_zero.target_bits = 0; // SHA difficulty must be 1..=20
        assert_eq!(
            validate_record(&sha_zero),
            Err(VerifyError::MalformedRecord)
        );

        // Argon2id parameters are deliberately NOT structurally bounded —
        // the hard ceilings apply to the signed parameters after
        // signature authentication (the PHP core's structural validator
        // has the same split), so an out-of-range value passes structural
        // validation and is rejected later as UnsupportedArgon2Params by
        // check_argon2_ceilings at the post-signature and computation
        // sites.
        let mut argon_bad_t = make_argon2_record(4, 128);
        argon_bad_t.t = 32; // above the t ceiling (16)
        assert_eq!(validate_record(&argon_bad_t), Ok(()));
        assert_eq!(
            check_argon2_ceilings(&argon_bad_t),
            Err(VerifyError::UnsupportedArgon2Params)
        );

        let mut argon_bad_m = make_argon2_record(4, 128);
        argon_bad_m.m_kib = 65_537; // above the 64 MiB ceiling
        assert_eq!(validate_record(&argon_bad_m), Ok(()));
        assert_eq!(
            check_argon2_ceilings(&argon_bad_m),
            Err(VerifyError::UnsupportedArgon2Params)
        );

        let mut argon_low_m = make_argon2_record(4, 128);
        argon_low_m.m_kib = 1; // below the 8 KiB hard floor
        assert_eq!(validate_record(&argon_low_m), Ok(()));
        assert_eq!(
            check_argon2_ceilings(&argon_low_m),
            Err(VerifyError::UnsupportedArgon2Params)
        );

        let mut argon_low_t = make_argon2_record(4, 128);
        argon_low_t.t = 2; // below the t minimum (3)
        assert_eq!(validate_record(&argon_low_t), Ok(()));
        assert_eq!(
            check_argon2_ceilings(&argon_low_t),
            Err(VerifyError::UnsupportedArgon2Params)
        );

        let mut argon_bad_p = make_argon2_record(4, 128);
        argon_bad_p.p = 5; // above the parallelism ceiling (4)
        assert_eq!(validate_record(&argon_bad_p), Ok(()));
        assert_eq!(
            check_argon2_ceilings(&argon_bad_p),
            Err(VerifyError::UnsupportedArgon2Params)
        );

        // A well-formed record passes.
        assert_eq!(validate_record(&make_record(8)), Ok(()));
        assert_eq!(validate_record(&make_argon2_record(4, 128)), Ok(()));
        assert_eq!(check_argon2_ceilings(&make_argon2_record(4, 128)), Ok(()));
    }

    #[test]
    fn sha_zero_target_bits_rejected_at_issuance() {
        let config = ChallengeConfig {
            secret_key: "0123456789abcdef0123456789abcdef".into(),
            kid: 1,
            execution_key: None,
            rsw_modulus_n: None,
            rsw_lambda: None,
            rsw_t: crate::challenge::DEFAULT_RSW_T,
            tenant: None,
            algorithm: PoWAlgorithm::Sha256,
            m_kib: 0,
            t: 1,
            p: 1,
            target_bits: 0,
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
        };
        assert!(
            matches!(
                issue_challenge(&config, "login", "1.2.3.4", NOW_UNIX, NOW_NS, 0, None),
                Err(SignError::InvalidDifficulty)
            ),
            "SHA target_bits 0 must be rejected at issuance with InvalidDifficulty"
        );
    }

    #[test]
    fn binding_tag_is_nonce_bound() {
        let secret = "0123456789abcdef0123456789abcdef";
        let a = binding_tag("nonce-a", "192.168.1.5", secret).unwrap();
        let b = binding_tag("nonce-b", "192.168.1.5", secret).unwrap();
        assert_ne!(a, b, "same IP, different nonce → different tag");
        let c = binding_tag("nonce-a", "192.168.1.6", secret).unwrap();
        assert_ne!(a, c, "same nonce, different IP → different tag");
        // Deterministic for identical inputs.
        assert_eq!(binding_tag("nonce-a", "192.168.1.5", secret).unwrap(), a);
        // Unknown key → rejected before hashing.
        assert!(matches!(
            binding_tag("n", "1.2.3.4", "short"),
            Err(SignError::KeyTooShort)
        ));
    }

    #[test]
    fn binding_tag_canonicalizes_ipv4_mapped_and_parses_families() {
        let secret = "0123456789abcdef0123456789abcdef";
        // IPv4-mapped IPv6 normalizes to 4-byte IPv4.
        assert_eq!(
            binding_tag("n", "::ffff:192.168.1.5", secret).unwrap(),
            binding_tag("n", "192.168.1.5", secret).unwrap()
        );
        // A real IPv6 address is distinct from its IPv4-mapped form.
        assert_ne!(
            binding_tag("n", "::ffff:192.168.1.5", secret).unwrap(),
            binding_tag("n", "2001:db8::1", secret).unwrap()
        );
        // Tags are 64 hex chars (32-byte HMAC-SHA256).
        assert_eq!(binding_tag("n", "192.168.1.5", secret).unwrap().len(), 64);
        assert_eq!(binding_tag("n", "2001:db8::1", secret).unwrap().len(), 64);
        // Unparsable IP → InvalidIp.
        assert!(matches!(
            binding_tag("n", "not-an-ip", secret),
            Err(SignError::InvalidIp)
        ));
    }

    #[test]
    fn empty_binding_tag_skips_binding_check() {
        // A record with an empty binding_tag (BindingMode::None) verifies
        // even though the submitting IP differs from the issuance IP.
        let issued = issue_challenge(
            &ChallengeConfig {
                secret_key: "test-key-32-bytes-0123456789abcd".into(),
                kid: 1,
                execution_key: None,
                rsw_modulus_n: None,
                rsw_lambda: None,
                rsw_t: crate::challenge::DEFAULT_RSW_T,
                tenant: None,
                algorithm: PoWAlgorithm::Sha256,
                m_kib: 100,
                t: 1,
                p: 1,
                target_bits: 8,
                argon2_target_bits: 8,
                ttl_secs: 120,
                min_duration_ms: None,
                auto_tune: false,
                auto_tune_min_bits: 8,
                auto_tune_max_bits: 20,
                binding_mode: BindingMode::None,
                region: None,
                issuer: None,

                policy_version: 1,
            },
            "login",
            "1.2.3.4",
            NOW_UNIX,
            NOW_NS,
            0,
            None,
        )
        .unwrap();
        assert!(issued.record.binding_tag.is_empty());
        let counter = solve_for_test(&issued.record).unwrap();
        let mut ctx = VerifyContext {
            record: &mut issued.record.clone(),
            secret_key: "test-key-32-bytes-0123456789abcd",
            tenant: None,
            secrets_by_kid: None,
            revoked_kids: None,
            counter,
            duration_ms: 5000,
            now_unix: Some(&mut || NOW_UNIX + 1),
            now_ns: NOW_NS + 5_000_000,
            min_duration_ms: 0,
            expected_scope: None,
            expected_request_binding: RequestBindingExpectation::Unenforced,
            rsw_proof: None,
            rsw_modulus_n: None,
            rsw_lambda: None,
            rsw_keyring: None,
            client_ip: Some("1.2.3.4"),
            execution_digest: None,
            execution_trace: None,
            expected_region: None,
            expected_issuer: None,
            expected_policy_version: None,
            policy_version_floor: None,
            telemetry: None,
            enforce_telemetry: false,
            max_attempts: 0,
            accept_legacy_v1: false,
        };
        assert!(matches!(
            verify_solution(&mut ctx),
            VerifyOutcome::Valid { .. }
        ));
    }

    #[test]
    fn v2_binding_mismatch_is_rejected() {
        let mut record = make_record(8);
        let counter = solve_for_test(&record).unwrap();
        let mut ctx = VerifyContext {
            record: &mut record,
            secret_key: "test-key-32-bytes-0123456789abcd",
            tenant: None,
            secrets_by_kid: None,
            revoked_kids: None,
            counter,
            duration_ms: 5000,
            now_unix: Some(&mut || NOW_UNIX + 1),
            now_ns: NOW_NS + 5_000_000,
            min_duration_ms: 0,
            expected_scope: None,
            expected_request_binding: RequestBindingExpectation::Unenforced,
            rsw_proof: None,
            rsw_modulus_n: None,
            rsw_lambda: None,
            rsw_keyring: None,
            client_ip: Some("9.9.9.9"), // different from issuance IP 1.2.3.4
            execution_digest: None,
            execution_trace: None,
            expected_region: None,
            expected_issuer: None,
            expected_policy_version: None,
            policy_version_floor: None,
            telemetry: None,
            enforce_telemetry: false,
            max_attempts: 0,
            accept_legacy_v1: false,
        };
        assert_eq!(
            verify_solution(&mut ctx),
            VerifyOutcome::Invalid(VerifyError::IpMismatch)
        );
    }

    // ── region binding, argon ceilings, jti exposure ────────────────────

    #[test]
    fn region_mismatch_is_rejected_with_wrong_region() {
        // The record's region is deployment metadata carried on the JSON
        // record. It IS signed into the v2 canonical payload (the line
        // below re-signs it with the region set) — the record itself is
        // server-side authoritative, and the client-visible challenge
        // carries the region only inside the signed canonical payload. A
        // verifier configured with an expected region rejects challenges
        // issued for another region.
        let mut record = make_record(8);
        record.region = Some("eu".into());
        resign_v2(&mut record, "test-key-32-bytes-0123456789abcd"); // region is signed into the canonical payload
        let counter = solve_for_test(&record).unwrap();
        let mut ctx = VerifyContext {
            record: &mut record,
            secret_key: "test-key-32-bytes-0123456789abcd",
            tenant: None,
            secrets_by_kid: None,
            revoked_kids: None,
            counter,
            duration_ms: 5000,
            now_unix: Some(&mut || NOW_UNIX + 1),
            now_ns: NOW_NS + 5_000_000,
            min_duration_ms: 0,
            expected_scope: None,
            expected_request_binding: RequestBindingExpectation::Unenforced,
            expected_region: Some("us"),
            expected_issuer: None,
            expected_policy_version: None,
            policy_version_floor: None,
            client_ip: Some("1.2.3.4"),
            execution_digest: None,
            execution_trace: None,
            telemetry: None,
            enforce_telemetry: false,
            max_attempts: 0,
            accept_legacy_v1: false,
            rsw_proof: None,
            rsw_modulus_n: None,
            rsw_lambda: None,
            rsw_keyring: None,
        };
        assert_eq!(
            verify_solution(&mut ctx),
            VerifyOutcome::Invalid(VerifyError::WrongRegion)
        );
    }

    #[test]
    fn region_expected_but_record_unbound_fails_closed() {
        // A deployment that expects a region fails closed on region-unbound
        // challenges (record.region == None).
        let mut record = make_record(8);
        assert_eq!(record.region, None);
        let counter = solve_for_test(&record).unwrap();
        let mut ctx = VerifyContext {
            record: &mut record,
            secret_key: "test-key-32-bytes-0123456789abcd",
            tenant: None,
            secrets_by_kid: None,
            revoked_kids: None,
            counter,
            duration_ms: 5000,
            now_unix: Some(&mut || NOW_UNIX + 1),
            now_ns: NOW_NS + 5_000_000,
            min_duration_ms: 0,
            expected_scope: None,
            expected_request_binding: RequestBindingExpectation::Unenforced,
            expected_region: Some("us"),
            expected_issuer: None,
            expected_policy_version: None,
            policy_version_floor: None,
            client_ip: Some("1.2.3.4"),
            execution_digest: None,
            execution_trace: None,
            telemetry: None,
            enforce_telemetry: false,
            max_attempts: 0,
            accept_legacy_v1: false,
            rsw_proof: None,
            rsw_modulus_n: None,
            rsw_lambda: None,
            rsw_keyring: None,
        };
        assert_eq!(
            verify_solution(&mut ctx),
            VerifyOutcome::Invalid(VerifyError::WrongRegion)
        );
    }

    #[test]
    fn matching_region_verifies_and_unmatched_expectation_never_fires() {
        let mut record = make_record(8);
        record.region = Some("us".into());
        resign_v2(&mut record, "test-key-32-bytes-0123456789abcd"); // region is signed into the canonical payload
        let counter = solve_for_test(&record).unwrap();

        let mut ctx_match = VerifyContext {
            record: &mut record,
            secret_key: "test-key-32-bytes-0123456789abcd",
            tenant: None,
            secrets_by_kid: None,
            revoked_kids: None,
            counter,
            duration_ms: 5000,
            now_unix: Some(&mut || NOW_UNIX + 1),
            now_ns: NOW_NS + 5_000_000,
            min_duration_ms: 0,
            expected_scope: None,
            expected_request_binding: RequestBindingExpectation::Unenforced,
            expected_region: Some("us"),
            expected_issuer: None,
            expected_policy_version: None,
            policy_version_floor: None,
            client_ip: Some("1.2.3.4"),
            execution_digest: None,
            execution_trace: None,
            telemetry: None,
            enforce_telemetry: false,
            max_attempts: 0,
            accept_legacy_v1: false,
            rsw_proof: None,
            rsw_modulus_n: None,
            rsw_lambda: None,
            rsw_keyring: None,
        };
        assert!(matches!(
            verify_solution(&mut ctx_match),
            VerifyOutcome::Valid { .. }
        ));

        // No expected region → the record's region is ignored entirely.
        let mut ctx_none = VerifyContext {
            record: &mut record,
            secret_key: "test-key-32-bytes-0123456789abcd",
            tenant: None,
            rsw_proof: None,
            rsw_modulus_n: None,
            rsw_lambda: None,
            rsw_keyring: None,
            secrets_by_kid: None,
            revoked_kids: None,
            counter,
            duration_ms: 5000,
            now_unix: Some(&mut || NOW_UNIX + 1),
            now_ns: NOW_NS + 5_000_000,
            min_duration_ms: 0,
            expected_scope: None,
            expected_request_binding: RequestBindingExpectation::Unenforced,
            expected_region: None,
            expected_issuer: None,
            expected_policy_version: None,
            policy_version_floor: None,
            client_ip: Some("1.2.3.4"),
            execution_digest: None,
            execution_trace: None,
            telemetry: None,
            enforce_telemetry: false,
            max_attempts: 0,
            accept_legacy_v1: false,
        };
        assert!(matches!(
            verify_solution(&mut ctx_none),
            VerifyOutcome::Valid { .. }
        ));
    }

    // ── issuer identity ─────────────────────────────────────────────────

    #[test]
    fn issuer_mismatch_is_rejected_with_wrong_issuer() {
        // The record's issuer is signed deployment metadata (final canonical
        // field). A verifier configured with an expected issuer rejects
        // challenges issued by another issuer.
        let mut record = make_record(8);
        record.issuer = Some("auth-gw-eu".into());
        resign_v2(&mut record, "test-key-32-bytes-0123456789abcd"); // issuer is signed into the v2 canonical payload
        let counter = solve_for_test(&record).unwrap();
        let mut ctx = VerifyContext {
            record: &mut record,
            secret_key: "test-key-32-bytes-0123456789abcd",
            tenant: None,
            secrets_by_kid: None,
            revoked_kids: None,
            counter,
            duration_ms: 5000,
            now_unix: Some(&mut || NOW_UNIX + 1),
            now_ns: NOW_NS + 5_000_000,
            min_duration_ms: 0,
            expected_scope: None,
            expected_request_binding: RequestBindingExpectation::Unenforced,
            expected_region: None,
            expected_issuer: Some("auth-gw-us"),
            expected_policy_version: None,
            policy_version_floor: None,
            client_ip: Some("1.2.3.4"),
            execution_digest: None,
            execution_trace: None,
            telemetry: None,
            enforce_telemetry: false,
            max_attempts: 0,
            accept_legacy_v1: false,
            rsw_proof: None,
            rsw_modulus_n: None,
            rsw_lambda: None,
            rsw_keyring: None,
        };
        assert_eq!(
            verify_solution(&mut ctx),
            VerifyOutcome::Invalid(VerifyError::WrongIssuer)
        );
    }

    #[test]
    fn issuer_expected_but_record_unbound_fails_closed() {
        // A deployment that expects an issuer fails closed on issuer-unbound
        // challenges (record.issuer == None), exactly like the region
        // expectation.
        let mut record = make_record(8);
        assert_eq!(record.issuer, None);
        let counter = solve_for_test(&record).unwrap();
        let mut ctx = VerifyContext {
            record: &mut record,
            secret_key: "test-key-32-bytes-0123456789abcd",
            tenant: None,
            secrets_by_kid: None,
            revoked_kids: None,
            counter,
            duration_ms: 5000,
            now_unix: Some(&mut || NOW_UNIX + 1),
            now_ns: NOW_NS + 5_000_000,
            min_duration_ms: 0,
            expected_scope: None,
            expected_request_binding: RequestBindingExpectation::Unenforced,
            expected_region: None,
            expected_issuer: Some("auth-gw"),
            expected_policy_version: None,
            policy_version_floor: None,
            client_ip: Some("1.2.3.4"),
            execution_digest: None,
            execution_trace: None,
            telemetry: None,
            enforce_telemetry: false,
            max_attempts: 0,
            accept_legacy_v1: false,
            rsw_proof: None,
            rsw_modulus_n: None,
            rsw_lambda: None,
            rsw_keyring: None,
        };
        assert_eq!(
            verify_solution(&mut ctx),
            VerifyOutcome::Invalid(VerifyError::WrongIssuer)
        );
    }

    #[test]
    fn matching_issuer_verifies_and_no_expectation_never_fires() {
        let mut record = make_record(8);
        record.issuer = Some("auth-gw".into());
        resign_v2(&mut record, "test-key-32-bytes-0123456789abcd"); // issuer is signed into the v2 canonical payload
        let counter = solve_for_test(&record).unwrap();

        let mut ctx_match = VerifyContext {
            record: &mut record,
            secret_key: "test-key-32-bytes-0123456789abcd",
            tenant: None,
            secrets_by_kid: None,
            revoked_kids: None,
            counter,
            duration_ms: 5000,
            now_unix: Some(&mut || NOW_UNIX + 1),
            now_ns: NOW_NS + 5_000_000,
            min_duration_ms: 0,
            expected_scope: None,
            expected_request_binding: RequestBindingExpectation::Unenforced,
            expected_region: None,
            expected_issuer: Some("auth-gw"),
            expected_policy_version: None,
            policy_version_floor: None,
            client_ip: Some("1.2.3.4"),
            execution_digest: None,
            execution_trace: None,
            telemetry: None,
            enforce_telemetry: false,
            max_attempts: 0,
            accept_legacy_v1: false,
            rsw_proof: None,
            rsw_modulus_n: None,
            rsw_lambda: None,
            rsw_keyring: None,
        };
        assert!(matches!(
            verify_solution(&mut ctx_match),
            VerifyOutcome::Valid { .. }
        ));

        // No expected issuer → the record's issuer is ignored entirely.
        let mut ctx_none = VerifyContext {
            record: &mut record,
            secret_key: "test-key-32-bytes-0123456789abcd",
            tenant: None,
            secrets_by_kid: None,
            revoked_kids: None,
            counter,
            duration_ms: 5000,
            now_unix: Some(&mut || NOW_UNIX + 1),
            now_ns: NOW_NS + 5_000_000,
            min_duration_ms: 0,
            expected_scope: None,
            expected_request_binding: RequestBindingExpectation::Unenforced,
            expected_region: None,
            expected_issuer: None,
            expected_policy_version: None,
            policy_version_floor: None,
            client_ip: Some("1.2.3.4"),
            execution_digest: None,
            execution_trace: None,
            telemetry: None,
            enforce_telemetry: false,
            max_attempts: 0,
            accept_legacy_v1: false,
            rsw_proof: None,
            rsw_modulus_n: None,
            rsw_lambda: None,
            rsw_keyring: None,
        };
        assert!(matches!(
            verify_solution(&mut ctx_none),
            VerifyOutcome::Valid { .. }
        ));
    }

    #[test]
    fn v2_fixture_with_issuer_set_verifies() {
        // The issuer is the field before the final kid: a
        // fixture record with an issuer set re-signs and verifies — the
        // byte-exact anchor the PHP side pins too.
        let mut record = fixture_record(2);
        record.issuer = Some("auth-gw".into());
        resign_v2(&mut record, FIXTURE_SECRET);
        assert!(matches!(
            verify_fixture(&mut record, false),
            VerifyOutcome::Valid { .. }
        ));
    }

    // ── key rotation ───────────────────────────────────────────────────

    /// Issue a SHA-256 record under `kid` with the given master secret.
    fn make_record_with_kid(target_bits: u32, kid: u32, secret: &str) -> ChallengeRecord {
        let config = ChallengeConfig {
            secret_key: secret.into(),
            algorithm: PoWAlgorithm::Sha256,
            m_kib: 0,
            t: 1,
            p: 1,
            target_bits,
            argon2_target_bits: 8,
            ttl_secs: 120,
            min_duration_ms: None,
            auto_tune: false,
            auto_tune_min_bits: 8,
            auto_tune_max_bits: 24,
            binding_mode: BindingMode::Bound,
            region: None,
            issuer: None,
            policy_version: 1,
            kid,
            execution_key: None,
            rsw_modulus_n: None,
            rsw_lambda: None,
            rsw_t: crate::challenge::DEFAULT_RSW_T,
            tenant: None,
        };
        issue_challenge(&config, "login", "1.2.3.4", NOW_UNIX, NOW_NS, 0, None)
            .unwrap()
            .record
    }

    #[test]
    fn kid_selects_the_secret_for_signature_and_binding() {
        // With `secrets_by_kid` configured, the record's kid
        // selects the signing secret — a challenge issued under kid 2 with
        // secret B verifies only against B, never against the other keys.
        let key_b = "0123456789abcdef0123456789abcdef";
        let mut record = make_record_with_kid(8, 2, key_b);
        assert_eq!(
            record.kid, 2,
            "the config kid must be stamped on the record"
        );
        let counter = solve_for_test(&record).unwrap();

        // The matching key verifies.
        let mut secrets: HashMap<u32, String> = HashMap::new();
        secrets.insert(2, key_b.to_string());
        let mut ctx = VerifyContext {
            record: &mut record,
            secret_key: "WRONG-KEY-32-bytes-0123456789abc",
            tenant: None,
            secrets_by_kid: Some(&secrets),
            revoked_kids: None,
            counter,
            duration_ms: 5000,
            now_unix: Some(&mut || NOW_UNIX + 1),
            now_ns: NOW_NS + 5_000_000,
            min_duration_ms: 0,
            expected_scope: None,
            expected_request_binding: RequestBindingExpectation::Unenforced,
            expected_region: None,
            expected_issuer: None,
            expected_policy_version: None,
            policy_version_floor: None,
            client_ip: Some("1.2.3.4"),
            execution_digest: None,
            execution_trace: None,
            telemetry: None,
            enforce_telemetry: false,
            max_attempts: 0,
            accept_legacy_v1: false,
            rsw_proof: None,
            rsw_modulus_n: None,
            rsw_lambda: None,
            rsw_keyring: None,
        };
        assert!(
            matches!(verify_solution(&mut ctx), VerifyOutcome::Valid { .. }),
            "the kid-selected secret must verify the signature AND the binding tag"
        );

        // The same kid with a different secret → BadSignature (the secret
        // selection is real, not cosmetic).
        let mut wrong: HashMap<u32, String> = HashMap::new();
        wrong.insert(2, "WRONG-KEY-32-bytes-0123456789abc".to_string());
        let mut ctx_wrong = VerifyContext {
            record: &mut record,
            secret_key: "WRONG-KEY-32-bytes-0123456789abc",
            tenant: None,
            secrets_by_kid: Some(&wrong),
            revoked_kids: None,
            counter,
            duration_ms: 5000,
            now_unix: Some(&mut || NOW_UNIX + 1),
            now_ns: NOW_NS + 5_000_000,
            min_duration_ms: 0,
            expected_scope: None,
            expected_request_binding: RequestBindingExpectation::Unenforced,
            expected_region: None,
            expected_issuer: None,
            expected_policy_version: None,
            policy_version_floor: None,
            client_ip: Some("1.2.3.4"),
            execution_digest: None,
            execution_trace: None,
            telemetry: None,
            enforce_telemetry: false,
            max_attempts: 0,
            accept_legacy_v1: false,
            rsw_proof: None,
            rsw_modulus_n: None,
            rsw_lambda: None,
            rsw_keyring: None,
        };
        assert_eq!(
            verify_solution(&mut ctx_wrong),
            VerifyOutcome::Invalid(VerifyError::BadSignature)
        );

        // No map → the single secret_key path applies unconditionally.
        let mut ctx_plain = VerifyContext {
            record: &mut record,
            secret_key: key_b,
            tenant: None,
            secrets_by_kid: None,
            revoked_kids: None,
            counter,
            duration_ms: 5000,
            now_unix: Some(&mut || NOW_UNIX + 1),
            now_ns: NOW_NS + 5_000_000,
            min_duration_ms: 0,
            expected_scope: None,
            expected_request_binding: RequestBindingExpectation::Unenforced,
            expected_region: None,
            expected_issuer: None,
            expected_policy_version: None,
            policy_version_floor: None,
            client_ip: Some("1.2.3.4"),
            execution_digest: None,
            execution_trace: None,
            telemetry: None,
            enforce_telemetry: false,
            max_attempts: 0,
            accept_legacy_v1: false,
            rsw_proof: None,
            rsw_modulus_n: None,
            rsw_lambda: None,
            rsw_keyring: None,
        };
        assert!(matches!(
            verify_solution(&mut ctx_plain),
            VerifyOutcome::Valid { .. }
        ));
    }

    #[test]
    fn unknown_kid_is_rejected_with_unknown_kid() {
        // A record whose kid is absent from the verifier's key
        // map is rejected with UnknownKid — before any signature work (the
        // correct signature for a different kid can never rescue it).
        let key_a = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let mut record = make_record_with_kid(8, 1, key_a);
        let counter = solve_for_test(&record).unwrap();

        // The map holds only kid 2 — kid 1 is unknown to this verifier.
        let mut secrets: HashMap<u32, String> = HashMap::new();
        secrets.insert(2, "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB".to_string());
        let mut ctx = VerifyContext {
            record: &mut record,
            secret_key: key_a, // the correct key — must NOT rescue the record
            tenant: None,
            secrets_by_kid: Some(&secrets),
            revoked_kids: None,
            counter,
            duration_ms: 5000,
            now_unix: Some(&mut || NOW_UNIX + 1),
            now_ns: NOW_NS + 5_000_000,
            min_duration_ms: 0,
            expected_scope: None,
            expected_request_binding: RequestBindingExpectation::Unenforced,
            expected_region: None,
            expected_issuer: None,
            expected_policy_version: None,
            policy_version_floor: None,
            client_ip: Some("1.2.3.4"),
            execution_digest: None,
            execution_trace: None,
            telemetry: None,
            enforce_telemetry: false,
            max_attempts: 0,
            accept_legacy_v1: false,
            rsw_proof: None,
            rsw_modulus_n: None,
            rsw_lambda: None,
            rsw_keyring: None,
        };
        assert_eq!(
            verify_solution(&mut ctx),
            VerifyOutcome::Invalid(VerifyError::UnknownKid)
        );
        // An empty map rejects every kid (max configured = 0).
        let empty: HashMap<u32, String> = HashMap::new();
        let mut ctx_empty = VerifyContext {
            record: &mut record,
            secret_key: key_a,
            tenant: None,
            secrets_by_kid: Some(&empty),
            revoked_kids: None,
            counter,
            duration_ms: 5000,
            now_unix: Some(&mut || NOW_UNIX + 1),
            now_ns: NOW_NS + 5_000_000,
            min_duration_ms: 0,
            expected_scope: None,
            expected_request_binding: RequestBindingExpectation::Unenforced,
            expected_region: None,
            expected_issuer: None,
            expected_policy_version: None,
            policy_version_floor: None,
            client_ip: Some("1.2.3.4"),
            execution_digest: None,
            execution_trace: None,
            telemetry: None,
            enforce_telemetry: false,
            max_attempts: 0,
            accept_legacy_v1: false,
            rsw_proof: None,
            rsw_modulus_n: None,
            rsw_lambda: None,
            rsw_keyring: None,
        };
        assert_eq!(
            verify_solution(&mut ctx_empty),
            VerifyOutcome::Invalid(VerifyError::UnknownKid)
        );
    }

    #[test]
    fn future_kid_is_rejected_by_the_forward_guard() {
        // The forward/rollback guard: a record keyed with a kid newer
        // than the verifier's newest configured kid must never verify on an
        // older node — UnknownKid fires even though the record is otherwise
        // perfectly signed and the node has simply not rolled forward yet.
        let key = "0123456789abcdef0123456789abcdef";
        let mut record = make_record_with_kid(8, 3, key);
        let counter = solve_for_test(&record).unwrap();

        // This node has rolled forward only to kid 2 — a kid-3 record from a
        // future deployment must be rejected.
        let mut secrets: HashMap<u32, String> = HashMap::new();
        secrets.insert(1, key.to_string());
        secrets.insert(2, key.to_string());
        let mut ctx = VerifyContext {
            record: &mut record,
            secret_key: key,
            tenant: None,
            secrets_by_kid: Some(&secrets),
            revoked_kids: None,
            counter,
            duration_ms: 5000,
            now_unix: Some(&mut || NOW_UNIX + 1),
            now_ns: NOW_NS + 5_000_000,
            min_duration_ms: 0,
            expected_scope: None,
            expected_request_binding: RequestBindingExpectation::Unenforced,
            expected_region: None,
            expected_issuer: None,
            expected_policy_version: None,
            policy_version_floor: None,
            client_ip: Some("1.2.3.4"),
            execution_digest: None,
            execution_trace: None,
            telemetry: None,
            enforce_telemetry: false,
            max_attempts: 0,
            accept_legacy_v1: false,
            rsw_proof: None,
            rsw_modulus_n: None,
            rsw_lambda: None,
            rsw_keyring: None,
        };
        assert_eq!(
            verify_solution(&mut ctx),
            VerifyOutcome::Invalid(VerifyError::UnknownKid),
            "kid 3 > the configured max kid (2) must be rejected on an older node"
        );

        // The guard's boundary: a record AT the newest configured kid
        // verifies once the key is known.
        let mut record2 = make_record_with_kid(8, 2, key);
        let counter2 = solve_for_test(&record2).unwrap();
        let mut ctx_boundary = VerifyContext {
            record: &mut record2,
            secret_key: key,
            tenant: None,
            secrets_by_kid: Some(&secrets),
            revoked_kids: None,
            counter: counter2,
            duration_ms: 5000,
            now_unix: Some(&mut || NOW_UNIX + 1),
            now_ns: NOW_NS + 5_000_000,
            min_duration_ms: 0,
            expected_scope: None,
            expected_request_binding: RequestBindingExpectation::Unenforced,
            expected_region: None,
            expected_issuer: None,
            expected_policy_version: None,
            policy_version_floor: None,
            client_ip: Some("1.2.3.4"),
            execution_digest: None,
            execution_trace: None,
            telemetry: None,
            enforce_telemetry: false,
            max_attempts: 0,
            accept_legacy_v1: false,
            rsw_proof: None,
            rsw_modulus_n: None,
            rsw_lambda: None,
            rsw_keyring: None,
        };
        assert!(matches!(
            verify_solution(&mut ctx_boundary),
            VerifyOutcome::Valid { .. }
        ));

        // Rolling the node forward to kid 3 makes the same record verify —
        // the guard is about the node's newest configured kid, not the
        // record's.
        let mut rolled_forward: HashMap<u32, String> = secrets.clone();
        rolled_forward.insert(3, key.to_string());
        let mut ctx_rolled = VerifyContext {
            record: &mut record,
            secret_key: key,
            tenant: None,
            secrets_by_kid: Some(&rolled_forward),
            revoked_kids: None,
            counter,
            duration_ms: 5000,
            now_unix: Some(&mut || NOW_UNIX + 1),
            now_ns: NOW_NS + 5_000_000,
            min_duration_ms: 0,
            expected_scope: None,
            expected_request_binding: RequestBindingExpectation::Unenforced,
            expected_region: None,
            expected_issuer: None,
            expected_policy_version: None,
            policy_version_floor: None,
            client_ip: Some("1.2.3.4"),
            execution_digest: None,
            execution_trace: None,
            telemetry: None,
            enforce_telemetry: false,
            max_attempts: 0,
            accept_legacy_v1: false,
            rsw_proof: None,
            rsw_modulus_n: None,
            rsw_lambda: None,
            rsw_keyring: None,
        };
        assert!(matches!(
            verify_solution(&mut ctx_rolled),
            VerifyOutcome::Valid { .. }
        ));
    }

    // ── compromise revocation overrides rotation grace ─────────────────

    #[test]
    fn revoked_kid_is_rejected_even_when_the_secret_is_present() {
        // A revoked kid is rejected with UnknownKid immediately,
        // before the signature check, even though the record is perfectly
        // signed and the verifier still holds its secret: compromise
        // revocation overrides the rotation grace (a leaked key stays in
        // secrets_by_kid while the deployment retires it, but its challenges
        // must never verify).
        let key = "0123456789abcdef0123456789abcdef";
        let mut record = make_record_with_kid(8, 2, key);
        let counter = solve_for_test(&record).unwrap();

        // The secret IS present — the revocation must still fire.
        let mut secrets: HashMap<u32, String> = HashMap::new();
        secrets.insert(2, key.to_string());
        let mut revoked: HashSet<u32> = HashSet::new();
        revoked.insert(2);
        let mut ctx = VerifyContext {
            record: &mut record,
            secret_key: key,
            tenant: None,
            secrets_by_kid: Some(&secrets),
            revoked_kids: Some(&revoked),
            counter,
            duration_ms: 5000,
            now_unix: Some(&mut || NOW_UNIX + 1),
            now_ns: NOW_NS + 5_000_000,
            min_duration_ms: 0,
            expected_scope: None,
            expected_request_binding: RequestBindingExpectation::Unenforced,
            expected_region: None,
            expected_issuer: None,
            expected_policy_version: None,
            policy_version_floor: None,
            client_ip: Some("1.2.3.4"),
            execution_digest: None,
            execution_trace: None,
            telemetry: None,
            enforce_telemetry: false,
            max_attempts: 0,
            accept_legacy_v1: false,
            rsw_proof: None,
            rsw_modulus_n: None,
            rsw_lambda: None,
            rsw_keyring: None,
        };
        assert_eq!(
            verify_solution(&mut ctx),
            VerifyOutcome::Invalid(VerifyError::UnknownKid),
            "a revoked kid must be rejected before the signature check, secret present or not"
        );

        // Revocation also applies on the single-key path (no secrets_by_kid).
        let mut ctx_plain = VerifyContext {
            record: &mut record,
            secret_key: key,
            tenant: None,
            secrets_by_kid: None,
            revoked_kids: Some(&revoked),
            counter,
            duration_ms: 5000,
            now_unix: Some(&mut || NOW_UNIX + 1),
            now_ns: NOW_NS + 5_000_000,
            min_duration_ms: 0,
            expected_scope: None,
            expected_request_binding: RequestBindingExpectation::Unenforced,
            expected_region: None,
            expected_issuer: None,
            expected_policy_version: None,
            policy_version_floor: None,
            client_ip: Some("1.2.3.4"),
            execution_digest: None,
            execution_trace: None,
            telemetry: None,
            enforce_telemetry: false,
            max_attempts: 0,
            accept_legacy_v1: false,
            rsw_proof: None,
            rsw_modulus_n: None,
            rsw_lambda: None,
            rsw_keyring: None,
        };
        assert_eq!(
            verify_solution(&mut ctx_plain),
            VerifyOutcome::Invalid(VerifyError::UnknownKid),
            "revocation applies on the plain single-key path too"
        );
    }

    #[test]
    fn unrevoked_kid_verifies_normally() {
        // Revocation is an exact-kid set — a record whose kid is
        // NOT in the revoked set verifies normally even when other kids are
        // revoked.
        let key = "0123456789abcdef0123456789abcdef";
        let mut record = make_record_with_kid(8, 2, key);
        let counter = solve_for_test(&record).unwrap();

        let mut secrets: HashMap<u32, String> = HashMap::new();
        secrets.insert(2, key.to_string());
        let mut revoked: HashSet<u32> = HashSet::new();
        revoked.insert(1);
        revoked.insert(9); // a different kid is revoked — not this one
        let mut ctx = VerifyContext {
            record: &mut record,
            secret_key: key,
            tenant: None,
            secrets_by_kid: Some(&secrets),
            revoked_kids: Some(&revoked),
            counter,
            duration_ms: 5000,
            now_unix: Some(&mut || NOW_UNIX + 1),
            now_ns: NOW_NS + 5_000_000,
            min_duration_ms: 0,
            expected_scope: None,
            expected_request_binding: RequestBindingExpectation::Unenforced,
            expected_region: None,
            expected_issuer: None,
            expected_policy_version: None,
            policy_version_floor: None,
            client_ip: Some("1.2.3.4"),
            execution_digest: None,
            execution_trace: None,
            telemetry: None,
            enforce_telemetry: false,
            max_attempts: 0,
            accept_legacy_v1: false,
            rsw_proof: None,
            rsw_modulus_n: None,
            rsw_lambda: None,
            rsw_keyring: None,
        };
        assert!(
            matches!(verify_solution(&mut ctx), VerifyOutcome::Valid { .. }),
            "an unrevoked kid with its secret present must verify normally"
        );
    }

    #[test]
    fn tampering_with_kid_breaks_the_v2_signature() {
        // The kid is the final signed canonical field: swapping it must
        // invalidate the signature (a kid-1 challenge cannot be replayed as
        // kid-2).
        let key = "0123456789abcdef0123456789abcdef";
        let record = make_record_with_kid(8, 1, key);
        let signature = record
            .challenge
            .rsplit_once('.')
            .map(|(_, sig)| sig)
            .unwrap()
            .to_string();
        let mut tampered = record.clone();
        tampered.kid = 2;
        assert!(
            !crate::challenge::verify_signature_v2(&tampered, &signature, key).unwrap(),
            "kid is signed — tampering with it must break the signature"
        );
    }

    // ── explicit difficulty bounds ─────────────────────────────────────
    #[test]
    fn validate_record_enforces_the_explicit_difficulty_bounds() {
        // The difficulty bounds 1 and 20 apply to both algorithms — 0, 21,
        // 256 and 65535 are rejected, 1 and 20 accepted.
        use crate::challenge::{MAX_DIFFICULTY, MIN_DIFFICULTY};
        assert_eq!(MIN_DIFFICULTY, 1);
        assert_eq!(MAX_DIFFICULTY, 20);
        for bad in [0u32, 21, 256, 65_535] {
            let mut sha = make_record(8);
            sha.target_bits = bad;
            assert_eq!(
                validate_record(&sha),
                Err(VerifyError::MalformedRecord),
                "sha target_bits={bad} must be rejected"
            );
            let mut argon = make_argon2_record(4, 128);
            argon.target_bits = bad;
            assert_eq!(
                validate_record(&argon),
                Err(VerifyError::MalformedRecord),
                "argon2 target_bits={bad} must be rejected"
            );
        }
        for good in [1u32, 20] {
            let mut sha = make_record(8);
            sha.target_bits = good;
            assert_eq!(
                validate_record(&sha),
                Ok(()),
                "sha target_bits={good} must be accepted"
            );
            let mut argon = make_argon2_record(4, 128);
            argon.target_bits = good;
            assert_eq!(
                validate_record(&argon),
                Ok(()),
                "argon2 target_bits={good} must be accepted (verifier bound; issuance stays stricter)"
            );
        }
    }

    #[test]
    fn difficulty_bounds_reject_before_any_hash_computation() {
        // The ceiling-test pattern: solve with a sane record, then verify
        // against an out-of-bounds-difficulty record with the valid counter —
        // MalformedRecord must fire in validate_record (pre-hash), never
        // reach derive_hash. A hash-based path would accept the valid
        // counter; only the pre-hash gate can reject it.
        for bad in [0u32, 21, 256, 65_535] {
            let mut sha = make_record(8);
            let counter = solve_for_test(&sha).unwrap();
            sha.target_bits = bad;
            assert_eq!(
                verify(&mut sha, counter, 5000),
                VerifyOutcome::Invalid(VerifyError::MalformedRecord),
                "sha target_bits={bad} must be rejected before hashing"
            );
            let mut argon = make_argon2_record(4, 128);
            let counter = solve_for_test(&argon).unwrap();
            argon.target_bits = bad;
            assert_eq!(
                verify(&mut argon, counter, 5000),
                VerifyOutcome::Invalid(VerifyError::MalformedRecord),
                "argon2 target_bits={bad} must be rejected before hashing"
            );
        }
    }

    // ── allocation-after-length pre-bounds ─────────────────────────────

    #[test]
    fn validate_record_rejects_oversized_nonce_and_salt_before_decode() {
        // The exact-length pre-bounds (nonce 44 chars, salt
        // 24 chars) fire before any base64 decode — a megabyte salt/nonce
        // string is rejected as MalformedRecord without allocating a decode
        // buffer. Also verified end-to-end: validate_record is the first
        // check of verify_solution, so an oversized field never reaches
        // derive_hash's decode.
        for mutate in ["salt", "nonce"] {
            let mut record = make_record(8);
            let huge = "A".repeat(1_000_000);
            match mutate {
                "salt" => record.salt = huge,
                _ => record.nonce = huge,
            }
            assert_eq!(
                validate_record(&record),
                Err(VerifyError::MalformedRecord),
                "a 1 MB {mutate} must be rejected before any decode"
            );
            let counter = solve_for_test(&make_record(8)).unwrap();
            let mut record = make_record(8);
            match mutate {
                "salt" => record.salt = "A".repeat(1_000_000),
                _ => record.nonce = "A".repeat(1_000_000),
            }
            assert_eq!(
                verify(&mut record, counter, 5000),
                VerifyOutcome::Invalid(VerifyError::MalformedRecord),
                "a 1 MB {mutate} must never reach hash derivation"
            );
        }
    }

    // ── narrow identifier alphabet ─────────────────────────────────────
    #[test]
    fn validate_record_rejects_non_conforming_identifiers() {
        // scope, issuer, region and request_binding must match
        // [A-Za-z0-9._:-]+ — Unicode, spaces and the empty string are
        // malformed records.
        let mut unicode_scope = make_record(8);
        unicode_scope.scope = "логин".into();
        assert_eq!(
            validate_record(&unicode_scope),
            Err(VerifyError::MalformedRecord),
            "Unicode scope must be rejected"
        );

        let mut space_scope = make_record(8);
        space_scope.scope = "log in".into();
        assert_eq!(
            validate_record(&space_scope),
            Err(VerifyError::MalformedRecord),
            "scope with a space must be rejected"
        );

        let mut empty_issuer = make_record(8);
        empty_issuer.issuer = Some(String::new());
        assert_eq!(
            validate_record(&empty_issuer),
            Err(VerifyError::MalformedRecord),
            "an empty issuer string must be rejected (None is the only unbound form)"
        );

        let mut unicode_issuer = make_record(8);
        unicode_issuer.issuer = Some("auth-gw-ü".into());
        assert_eq!(
            validate_record(&unicode_issuer),
            Err(VerifyError::MalformedRecord),
            "Unicode issuer must be rejected"
        );

        let mut space_region = make_record(8);
        space_region.region = Some("eu west".into());
        assert_eq!(
            validate_record(&space_region),
            Err(VerifyError::MalformedRecord),
            "region with a space must be rejected"
        );

        let mut unicode_binding = make_record(8);
        unicode_binding.request_binding = Some("交易".into());
        assert_eq!(
            validate_record(&unicode_binding),
            Err(VerifyError::MalformedRecord),
            "Unicode request_binding must be rejected"
        );

        let mut long_region = make_record(8);
        long_region.region = Some("r".repeat(65));
        assert_eq!(
            validate_record(&long_region),
            Err(VerifyError::MalformedRecord),
            "region above 64 bytes must be rejected"
        );

        // The boundary values and the allowed alphabet pass.
        let mut ok_region = make_record(8);
        ok_region.region = Some("r".repeat(64));
        assert_eq!(validate_record(&ok_region), Ok(()));
        let mut ok = make_record(8);
        ok.issuer = Some("auth-gw:eu-1._a".into());
        ok.region = Some("eu-west-1".into());
        ok.request_binding = Some("req_1:abc.de-2".into());
        assert_eq!(validate_record(&ok), Ok(()));
    }

    // ── future-time bound ─────────────────────────────────────────────

    #[test]
    fn future_issued_challenge_beyond_skew_is_rejected() {
        // A challenge issued more than the clock-skew bound (60 s) in the
        // future relative to the verifier clock is a time-domain anomaly —
        // the TTL check rejects it. Mutating issued_at invalidates the
        // signature, so re-sign first.
        let mut record = make_record(8);
        record.issued_at = NOW_UNIX + 62; // > now + 60 → anomaly
        record.expires_at = record.issued_at + 120;
        resign_v2(&mut record, "test-key-32-bytes-0123456789abcd");
        let counter = solve_for_test(&record).unwrap();
        let mut ctx = VerifyContext {
            record: &mut record,
            secret_key: "test-key-32-bytes-0123456789abcd",
            tenant: None,
            secrets_by_kid: None,
            revoked_kids: None,
            counter,
            duration_ms: 5000,
            now_unix: Some(&mut || NOW_UNIX + 1), // issued_at > now + 60 → invalid
            now_ns: NOW_NS + 5_000_000,
            min_duration_ms: 0,
            expected_scope: None,
            expected_request_binding: RequestBindingExpectation::Unenforced,
            expected_region: None,
            expected_issuer: None,
            expected_policy_version: None,
            policy_version_floor: None,
            client_ip: Some("1.2.3.4"),
            execution_digest: None,
            execution_trace: None,
            telemetry: None,
            enforce_telemetry: false,
            max_attempts: 0,
            accept_legacy_v1: false,
            rsw_proof: None,
            rsw_modulus_n: None,
            rsw_lambda: None,
            rsw_keyring: None,
        };
        assert_eq!(
            verify_solution(&mut ctx),
            VerifyOutcome::Invalid(VerifyError::Expired)
        );

        // Exactly AT the skew bound is still acceptable (issued_at ==
        // now + 60): the boundary is inclusive.
        let mut record = make_record(8);
        record.issued_at = NOW_UNIX + 61; // == now + 60
        record.expires_at = record.issued_at + 120;
        resign_v2(&mut record, "test-key-32-bytes-0123456789abcd");
        let counter = solve_for_test(&record).unwrap();
        let mut ctx = VerifyContext {
            record: &mut record,
            secret_key: "test-key-32-bytes-0123456789abcd",
            tenant: None,
            secrets_by_kid: None,
            revoked_kids: None,
            counter,
            duration_ms: 5000,
            now_unix: Some(&mut || NOW_UNIX + 1),
            now_ns: NOW_NS + 5_000_000,
            min_duration_ms: 0,
            expected_scope: None,
            expected_request_binding: RequestBindingExpectation::Unenforced,
            expected_region: None,
            expected_issuer: None,
            expected_policy_version: None,
            policy_version_floor: None,
            client_ip: Some("1.2.3.4"),
            execution_digest: None,
            execution_trace: None,
            telemetry: None,
            enforce_telemetry: false,
            max_attempts: 0,
            accept_legacy_v1: false,
            rsw_proof: None,
            rsw_modulus_n: None,
            rsw_lambda: None,
            rsw_keyring: None,
        };
        assert!(matches!(
            verify_solution(&mut ctx),
            VerifyOutcome::Valid { .. }
        ));
    }

    // ── post-derive final re-validation ───────────────────────────────

    #[test]
    fn final_revalidation_race_expired_during_derive() {
        // The expensive derivation may straddle expires_at: the cheap TTL
        // check passes, the hash derives, and by the final re-check the
        // current server time has advanced past expiry. The final gate must
        // reject — deterministically simulated with an advanced now_unix.
        let mut record = make_record(8);
        let counter = solve_for_test(&record).unwrap();
        let cheap_now = record.expires_at - 1;

        // Cheap phase + derive + final re-check all pass just before expiry.
        let mut ctx = VerifyContext {
            record: &mut record,
            secret_key: "test-key-32-bytes-0123456789abcd",
            tenant: None,
            secrets_by_kid: None,
            revoked_kids: None,
            counter,
            duration_ms: 5000,
            now_unix: Some(&mut || cheap_now),
            now_ns: NOW_NS + 5_000_000,
            min_duration_ms: 0,
            expected_scope: None,
            expected_request_binding: RequestBindingExpectation::Unenforced,
            expected_region: None,
            expected_issuer: None,
            expected_policy_version: None,
            policy_version_floor: None,
            client_ip: Some("1.2.3.4"),
            execution_digest: None,
            execution_trace: None,
            telemetry: None,
            enforce_telemetry: false,
            max_attempts: 0,
            accept_legacy_v1: false,
            rsw_proof: None,
            rsw_modulus_n: None,
            rsw_lambda: None,
            rsw_keyring: None,
        };
        assert!(matches!(
            verify_solution(&mut ctx),
            VerifyOutcome::Valid { .. }
        ));

        // The final re-check with the advanced clock: the gate fires at the
        // exact expiry boundary (the ProductionVerifier re-reads the real
        // clock at this step — see tests/redis_verify.rs).
        assert_eq!(
            final_revalidate(&record, cheap_now, None, None, None, None),
            Ok(())
        );
        assert_eq!(
            final_revalidate(&record, record.expires_at, None, None, None, None),
            Err(VerifyError::Expired)
        );
        assert_eq!(
            final_revalidate(&record, record.expires_at + 5, None, None, None, None),
            Err(VerifyError::Expired)
        );
    }

    #[test]
    fn final_revalidation_rejects_changed_expectations() {
        // Expectations (policy epoch, region, issuer) can change while the
        // proof is deriving: the final gate re-checks them all against the
        // current configuration.
        let mut record = make_record(8);
        let counter = solve_for_test(&record).unwrap();
        let now_unix = NOW_UNIX + 1;
        let mut ctx = VerifyContext {
            record: &mut record,
            secret_key: "test-key-32-bytes-0123456789abcd",
            tenant: None,
            secrets_by_kid: None,
            revoked_kids: None,
            counter,
            duration_ms: 5000,
            now_unix: Some(&mut || now_unix),
            now_ns: NOW_NS + 5_000_000,
            min_duration_ms: 0,
            expected_scope: None,
            expected_request_binding: RequestBindingExpectation::Unenforced,
            expected_region: None,
            expected_issuer: None,
            expected_policy_version: None,
            policy_version_floor: None,
            client_ip: Some("1.2.3.4"),
            execution_digest: None,
            execution_trace: None,
            telemetry: None,
            enforce_telemetry: false,
            max_attempts: 0,
            accept_legacy_v1: false,
            rsw_proof: None,
            rsw_modulus_n: None,
            rsw_lambda: None,
            rsw_keyring: None,
        };
        assert!(matches!(
            verify_solution(&mut ctx),
            VerifyOutcome::Valid { .. }
        ));

        // Each expectation re-checked at the final step fails closed when it
        // no longer matches the record.
        assert_eq!(
            final_revalidate(&record, now_unix, None, Some(2), None, None),
            Err(VerifyError::WrongPolicyVersion),
            "policy version changed between cheap and final → rejected"
        );
        assert_eq!(
            final_revalidate(&record, now_unix, Some("us"), None, None, None),
            Err(VerifyError::WrongRegion),
            "region expectation changed between cheap and final → rejected"
        );
        assert_eq!(
            final_revalidate(&record, now_unix, None, None, None, Some("auth-gw")),
            Err(VerifyError::WrongIssuer),
            "issuer expectation changed between cheap and final → rejected"
        );
        // A declared rollout window (floor 1, expected 2) redeems the record's
        // epoch 1 at the final gate too — the window is not a cheap-phase-only
        // relaxation.
        assert_eq!(
            final_revalidate(&record, now_unix, None, Some(2), Some(1), None),
            Ok(()),
            "inside a rollout window the floor epoch redeems at the final gate"
        );
        // The matching configuration passes.
        assert_eq!(
            final_revalidate(&record, now_unix, None, None, None, None),
            Ok(())
        );
    }

    #[test]
    fn policy_version_acceptance_window_matrix() {
        // The rollout-window predicate's truth table: strict equality by
        // default, floor <= record <= expected inside a declared window,
        // an inverted window (floor > expected) accepts nothing (fail
        // closed), and no expectation disables the check entirely.
        for (record, expected, floor, accepted) in [
            // Strict equality — no declared rollout window.
            (2u32, Some(2u32), None, true),
            (1, Some(2), None, false),
            (3, Some(2), None, false),
            // Declared rollout window [1, 2]: a mixed N/N+1 fleet redeems.
            (1, Some(2), Some(1), true),
            (2, Some(2), Some(1), true),
            (0, Some(2), Some(1), false),
            (3, Some(2), Some(1), false),
            // A degenerate one-epoch window is strict equality again.
            (2, Some(2), Some(2), true),
            (1, Some(2), Some(2), false),
            // An inverted window accepts nothing — never fail open on a
            // misconfiguration.
            (1, Some(1), Some(2), false),
            (2, Some(1), Some(2), false),
            // No expectation disables the epoch check (floor is moot).
            (0, None, None, true),
            (99, None, Some(1), true),
        ] {
            assert_eq!(
                policy_version_accepted(record, expected, floor),
                accepted,
                "record {record}, expected {expected:?}, floor {floor:?}"
            );
        }
    }

    #[test]
    fn policy_rollout_window_redeems_a_mixed_fleet_cross_epoch() {
        // Done-when: inside a declared N/N+1 rollout window an outstanding
        // challenge issued under the floor epoch redeems on a node already
        // expecting N+1 — the cheap-phase gate AND the post-derive final
        // re-validation both use the window predicate; outside a window a
        // wrong epoch is still rejected (strict equality).
        let make = |policy_version: u32| {
            let mut config = ChallengeConfig {
                secret_key: "test-key-32-bytes-0123456789abcd".into(),
                kid: 1,
                execution_key: None,
                rsw_modulus_n: None,
                rsw_lambda: None,
                rsw_t: crate::challenge::DEFAULT_RSW_T,
                tenant: None,
                algorithm: PoWAlgorithm::Sha256,
                m_kib: 100,
                t: 1,
                p: 1,
                target_bits: 8,
                argon2_target_bits: 8,
                ttl_secs: 120,
                min_duration_ms: None,
                auto_tune: false,
                auto_tune_min_bits: 8,
                auto_tune_max_bits: 24,
                binding_mode: BindingMode::Bound,
                region: None,
                issuer: None,
                policy_version,
            };
            let _ = &mut config;
            issue_challenge(&config, "login", "1.2.3.4", NOW_UNIX, NOW_NS, 0, None)
                .unwrap()
                .record
        };
        for (record_version, expected, floor, should_verify) in [
            // Rollout window [1, 2]: both fleet epochs redeem.
            (1u32, Some(2u32), Some(1u32), true),
            (2, Some(2), Some(1), true),
            // Outside the window's bounds: rejected.
            (0, Some(2), Some(1), false),
            (3, Some(2), Some(1), false),
            // No declared window: strict equality only.
            (1, Some(2), None, false),
            (2, Some(2), None, true),
            // A degenerate one-epoch window is strict equality again.
            (2, Some(2), Some(2), true),
            (1, Some(2), Some(2), false),
            // An inverted window accepts nothing.
            (2, Some(1), Some(2), false),
        ] {
            let mut record = make(record_version);
            let counter = solve_for_test(&record).unwrap();
            let mut ctx = VerifyContext {
                record: &mut record,
                secret_key: "test-key-32-bytes-0123456789abcd",
                tenant: None,
                secrets_by_kid: None,
                revoked_kids: None,
                counter,
                duration_ms: 5000,
                now_unix: Some(&mut || NOW_UNIX + 1),
                now_ns: NOW_NS + 5_000_000,
                min_duration_ms: 0,
                expected_scope: None,
                expected_request_binding: RequestBindingExpectation::Unenforced,
                expected_region: None,
                expected_issuer: None,
                expected_policy_version: expected,
                policy_version_floor: floor,
                client_ip: Some("1.2.3.4"),
                execution_digest: None,
                execution_trace: None,
                telemetry: None,
                enforce_telemetry: false,
                max_attempts: 0,
                accept_legacy_v1: false,
                rsw_proof: None,
                rsw_modulus_n: None,
                rsw_lambda: None,
                rsw_keyring: None,
            };
            let label = format!("record {record_version}, expected {expected:?}, floor {floor:?}");
            if should_verify {
                assert!(
                    matches!(verify_solution(&mut ctx), VerifyOutcome::Valid { .. }),
                    "{label}: inside the rollout window the epoch must redeem (cheap + final gates)"
                );
            } else {
                assert_eq!(
                    verify_solution(&mut ctx),
                    VerifyOutcome::Invalid(VerifyError::WrongPolicyVersion),
                    "{label}: outside the acceptance window the epoch must be rejected"
                );
            }
        }
        // The final gate applies the same window bounds on its own: below
        // the floor epoch the window rejects there too.
        let mut record = make(0);
        let _ = &mut record;
        assert_eq!(
            final_revalidate(&record, NOW_UNIX + 1, None, Some(2), Some(1), None),
            Err(VerifyError::WrongPolicyVersion),
            "below the floor epoch the final gate rejects inside the window"
        );
    }

    #[test]
    fn unknown_algorithm_variants_are_rejected_at_parse_time() {
        // serde rejects unknown PoWAlgorithm variants exactly like
        // PHP's fromArray throws MalformedRecordException — "argon2d",
        // "sha1", "sha256-v2" and "argon2id" are all parse errors, and the
        // storage layer maps a corrupt key to RecordNotFound (PHP parity).
        let record = make_record(8);
        for algo in ["argon2d", "sha1", "sha256-v2", "ARGON2ID"] {
            let mut value = serde_json::to_value(&record).unwrap();
            value["algorithm"] = serde_json::json!(algo);
            assert!(
                serde_json::from_value::<ChallengeRecord>(value).is_err(),
                "algorithm {algo:?} must be rejected at parse time"
            );
        }
    }

    #[test]
    fn valid_outcome_exposes_the_consumed_nonce_jti() {
        // The VerifyOutcome must carry the canonical nonce so
        // callers can correlate the result without re-decoding the token.
        let mut record = make_record(8);
        let counter = solve_for_test(&record).unwrap();
        let expected_nonce = record.nonce.clone();
        let outcome = verify(&mut record, counter, 5000);
        assert_eq!(outcome.nonce(), Some(expected_nonce.as_str()));
        assert_eq!(
            outcome,
            VerifyOutcome::Valid {
                nonce: expected_nonce,
                request_binding: None,
                from_stored_result: false,
                // The verify() helper's receipt is NOW_NS + 5 s: the
                // server-measured span to that same receipt instant.
                solve_duration_ms: Some(5000),
            }
        );
        let invalid = VerifyOutcome::Invalid(VerifyError::Expired);
        assert_eq!(invalid.nonce(), None);
    }

    #[test]
    fn valid_outcome_carries_the_server_measured_solve_duration() {
        // The server-measured span between the record's issued_at_ns and
        // the verification receipt instant. The client-reported
        // duration_ms, 5000 in the verify() helper, is forgeable and must
        // never leak into the outcome.
        let mut record = make_record(8);
        let counter = solve_for_test(&record).expect("8-bit sha solves");
        let outcome = verify(&mut record, counter, 5000);
        match outcome {
            VerifyOutcome::Valid {
                solve_duration_ms, ..
            } => assert_eq!(
                solve_duration_ms,
                Some(5000),
                "the outcome carries the server-measured span (NOW_NS + 5 s), never the client-reported 5000 ms claim"
            ),
            other => panic!("expected a valid outcome, got {other:?}"),
        }
        // Sub-millisecond precision floors toward zero (the PHP
        // intdiv semantics): 1234.567 ms -> 1234.
        let mut ctx = VerifyContext {
            record: &mut record,
            secret_key: "test-key-32-bytes-0123456789abcd",
            tenant: None,
            secrets_by_kid: None,
            revoked_kids: None,
            counter,
            duration_ms: 5000,
            now_unix: Some(&mut || NOW_UNIX + 1),
            now_ns: NOW_NS + 1_234_567,
            min_duration_ms: 0,
            expected_scope: None,
            expected_request_binding: RequestBindingExpectation::Unenforced,
            expected_region: None,
            expected_issuer: None,
            expected_policy_version: None,
            policy_version_floor: None,
            client_ip: Some("1.2.3.4"),
            execution_digest: None,
            execution_trace: None,
            telemetry: None,
            enforce_telemetry: false,
            max_attempts: 0,
            accept_legacy_v1: false,
            rsw_proof: None,
            rsw_modulus_n: None,
            rsw_lambda: None,
            rsw_keyring: None,
        };
        match verify_solution(&mut ctx) {
            VerifyOutcome::Valid {
                solve_duration_ms, ..
            } => assert_eq!(solve_duration_ms, Some(1234)),
            other => panic!("expected a valid outcome, got {other:?}"),
        }
    }

    #[test]
    fn receipt_preceding_issuance_within_the_skew_tolerance_is_unmeasurable() {
        // A receipt 2 s before issuance: within the 5 s skew tolerance the
        // two hosts' clocks are unsynced, so the elapsed time cannot be
        // measured reliably — the floor check is skipped (the proof still
        // verifies) and the exposed duration is null, exactly the PHP
        // semantics.
        let mut record = make_record(8);
        let counter = solve_for_test(&record).expect("8-bit sha solves");
        let mut ctx = VerifyContext {
            record: &mut record,
            secret_key: "test-key-32-bytes-0123456789abcd",
            tenant: None,
            secrets_by_kid: None,
            revoked_kids: None,
            counter,
            duration_ms: 5000,
            now_unix: Some(&mut || NOW_UNIX + 1),
            now_ns: NOW_NS.saturating_sub(2_000_000),
            min_duration_ms: 0,
            expected_scope: None,
            expected_request_binding: RequestBindingExpectation::Unenforced,
            expected_region: None,
            expected_issuer: None,
            expected_policy_version: None,
            policy_version_floor: None,
            client_ip: Some("1.2.3.4"),
            execution_digest: None,
            execution_trace: None,
            telemetry: None,
            enforce_telemetry: false,
            max_attempts: 0,
            accept_legacy_v1: false,
            rsw_proof: None,
            rsw_modulus_n: None,
            rsw_lambda: None,
            rsw_keyring: None,
        };
        match verify_solution(&mut ctx) {
            VerifyOutcome::Valid {
                solve_duration_ms, ..
            } => assert_eq!(
                solve_duration_ms, None,
                "a receipt preceding issuance within the skew tolerance is unmeasurable"
            ),
            other => panic!("the skew window keeps the verification valid, got {other:?}"),
        }
    }

    #[test]
    fn one_receipt_instant_feeds_both_the_floor_and_the_duration() {
        // The single-receipt-instant property: the exposed duration is
        // computed from the same now_ns the minimum-duration floor reads
        // (never a second clock read). A solve at exactly the floor
        // boundary passes the floor and exposes that exact boundary as
        // its duration — a second, later read would report a larger span.
        let mut record = make_record(8);
        record.min_duration_ms = 5000;
        resign_v2(&mut record, "test-key-32-bytes-0123456789abcd");
        let counter = solve_for_test(&record).expect("8-bit sha solves");
        let mut ctx = VerifyContext {
            record: &mut record,
            secret_key: "test-key-32-bytes-0123456789abcd",
            tenant: None,
            secrets_by_kid: None,
            revoked_kids: None,
            counter,
            duration_ms: 5000,
            now_unix: Some(&mut || NOW_UNIX + 1),
            now_ns: NOW_NS + 5_000_000, // exactly 5000 ms of elapsed time
            min_duration_ms: 0,
            expected_scope: None,
            expected_request_binding: RequestBindingExpectation::Unenforced,
            expected_region: None,
            expected_issuer: None,
            expected_policy_version: None,
            policy_version_floor: None,
            client_ip: Some("1.2.3.4"),
            execution_digest: None,
            execution_trace: None,
            telemetry: None,
            enforce_telemetry: false,
            max_attempts: 0,
            accept_legacy_v1: false,
            rsw_proof: None,
            rsw_modulus_n: None,
            rsw_lambda: None,
            rsw_keyring: None,
        };
        match verify_solution(&mut ctx) {
            VerifyOutcome::Valid {
                solve_duration_ms, ..
            } => assert_eq!(
                solve_duration_ms,
                Some(5000),
                "the same receipt instant that passes the floor is the measured duration"
            ),
            other => panic!("the floor boundary must verify, got {other:?}"),
        }
    }

    #[test]
    fn unmeasurable_duration_helpers_and_non_valid_outcomes_are_null() {
        // The measurableSolveDurationMs mirror: a record without an
        // issuance clock (issued_at_ns == 0) is unmeasurable, and a
        // receipt preceding issuance is unmeasurable; the PHP intdiv
        // semantics floor sub-millisecond spans.
        let mut record = make_record(8);
        record.issued_at_ns = 0;
        assert_eq!(measurable_solve_duration_ms(&record, NOW_NS), None);
        record.issued_at_ns = NOW_NS;
        assert_eq!(
            measurable_solve_duration_ms(&record, NOW_NS + 1_234_567),
            Some(1234),
            "sub-millisecond precision floors toward zero (PHP intdiv)"
        );
        assert_eq!(
            measurable_solve_duration_ms(&record, NOW_NS - 1),
            None,
            "a receipt preceding issuance is unmeasurable"
        );
        // Non-valid outcomes never carry a duration (purely additive).
        assert_eq!(
            VerifyOutcome::Invalid(VerifyError::Expired).solve_duration_ms(),
            None
        );
        assert_eq!(
            VerifyOutcome::Invalid(VerifyError::TooFast).solve_duration_ms(),
            None
        );
    }

    #[test]
    fn signed_argon2_records_outside_hard_ceilings_are_rejected() {
        // Signed records (valid v2 signatures over the mutated
        // parameters) with out-of-range m_kib/t are rejected with
        // UnsupportedArgon2Params — the PHP core's twin code for an
        // authentic record whose signed parameters violate the hard
        // process ceilings — before any Params::new/allocation.
        use crate::challenge::{MAX_ARGON_MEMORY_KIB, MAX_ARGON_TIME};
        for (field, value) in [
            ("m_kib", 1u32),                     // below the memory minimum
            ("m_kib", MAX_ARGON_MEMORY_KIB + 1), // 131072, above the ceiling
            ("t", 1u32),                         // below the time minimum
            ("t", MAX_ARGON_TIME + 1),           // 32, above the ceiling
        ] {
            let mut record = make_argon2_record(4, 128);
            match field {
                "m_kib" => record.m_kib = value,
                "t" => record.t = value,
                _ => unreachable!(),
            }
            resign_v2(&mut record, "test-key-32-bytes-0123456789abcd");
            assert_eq!(
                verify(&mut record, 0, 5000),
                VerifyOutcome::Invalid(VerifyError::UnsupportedArgon2Params),
                "{field}={value} must be rejected by the hard ceilings"
            );
        }
    }

    #[test]
    fn signed_argon2_record_at_the_pinned_parallelism_verifies() {
        // The parallelism space is pinned to p == 1 (the libsodium-backed
        // PHP verifier has no p parameter and refuses anything else), so
        // the floor/ceiling pair is 1/1 and the shipped profile verifies.
        let mut record = make_argon2_record(4, 64);
        record.p = 1;
        record.m_kib = 64;
        resign_v2(&mut record, "test-key-32-bytes-0123456789abcd");
        assert_eq!(crate::challenge::MIN_PARALLELISM, 1);
        assert_eq!(crate::challenge::MAX_PARALLELISM, 1);
        let counter = solve_for_test(&record).expect("argon solve finds a counter");
        assert!(
            matches!(
                verify(&mut record, counter, 5000),
                VerifyOutcome::Valid { .. }
            ),
            "the pinned p=1 profile must verify"
        );
    }

    #[test]
    fn signed_argon2_record_above_the_pinned_parallelism_is_rejected() {
        // A signed p >= 2 record is authentic but unsupported: Rust and
        // PHP must agree that it is never derivable.
        for p in [2u32, 4, 5] {
            let mut record = make_argon2_record(4, 128);
            record.p = p;
            resign_v2(&mut record, "test-key-32-bytes-0123456789abcd");
            assert_eq!(
                verify(&mut record, 0, 5000),
                VerifyOutcome::Invalid(VerifyError::UnsupportedArgon2Params),
                "p={p} must be refused"
            );
        }
    }

    #[test]
    fn validate_record_accepts_parameters_within_the_hard_ceilings() {
        // t=7..=16 and p=2..=4 are within the verifier's hard ceilings even
        // though issuance never mints them (issuance stays stricter).
        let mut record = make_argon2_record(4, 128);
        record.t = 16;
        record.p = 4;
        record.m_kib = 64;
        assert_eq!(validate_record(&record), Ok(()));
    }

    // ── Shared fixture vectors (byte-exact; PHP mirrors these) ─────────
    // secret = "0123456789abcdef0123456789abcdef"
    // nonce  = base64("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef")  (32 ASCII bytes)
    // salt   = base64("1234567890abcdef")  (16 ASCII bytes)
    // scope = "login"; issued_at = 1700000000; expires_at = 1700000120;
    // min_duration_ms = 0; Sha256: target_bits = 8, m_kib = 0, t = 1, p = 1;
    // ip = "192.168.1.5"; protocol_version = 2 (v1 vector below);
    // region/request_binding/issuer all unset, kid = 1 → the canonical ends
    // `|0||1|||1` (issuer is the penultimate field, empty when
    // unset; kid is the final field, 1 when unset).
    const FIXTURE_SECRET: &str = "0123456789abcdef0123456789abcdef";
    const FIXTURE_NONCE: &str = "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVphYmNkZWY=";
    const FIXTURE_SALT: &str = "MTIzNDU2Nzg5MGFiY2RlZg==";
    const FIXTURE_BINDING_TAG: &str =
        "5b105424fe3a5cfa3afdccda95f734c9e66ee703e8b8d426a07cfe1cb9c8954f";
    const FIXTURE_CANONICAL_V2: &str = "v4|2|QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVphYmNkZWY=|login|5b105424fe3a5cfa3afdccda95f734c9e66ee703e8b8d426a07cfe1cb9c8954f|1700000000|1700000120|sha256|0|1|1|8|MTIzNDU2Nzg5MGFiY2RlZg==|0||1|||1";
    const FIXTURE_CHALLENGE_V2: &str = "djR8MnxRVUpEUkVWR1IwaEpTa3RNVFU1UFVGRlNVMVJWVmxkWVdWcGhZbU5rWldZPXxsb2dpbnw1YjEwNTQyNGZlM2E1Y2ZhM2FmZGNjZGE5NWY3MzRjOWU2NmVlNzAzZThiOGQ0MjZhMDdjZmUxY2I5Yzg5NTRmfDE3MDAwMDAwMDB8MTcwMDAwMDEyMHxzaGEyNTZ8MHwxfDF8OHxNVEl6TkRVMk56ZzVNR0ZpWTJSbFpnPT18MHx8MXx8fDE=.b4f93cd65ffa1184b72854237382c225fb8fe195f6657682a8aa4e542759500f";
    // The signed record-metadata MAC vector: the same base canonical plus
    // the m=1 marker, and the server-state MAC the issuer seals over it.
    const FIXTURE_CANONICAL_V2_MAC: &str = "v4|2|QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVphYmNkZWY=|login|5b105424fe3a5cfa3afdccda95f734c9e66ee703e8b8d426a07cfe1cb9c8954f|1700000000|1700000120|sha256|0|1|1|8|MTIzNDU2Nzg5MGFiY2RlZg==|0||1|||1|m=1";
    const FIXTURE_CHALLENGE_V2_MAC: &str = "djR8MnxRVUpEUkVWR1IwaEpTa3RNVFU1UFVGRlNVMVJWVmxkWVdWcGhZbU5rWldZPXxsb2dpbnw1YjEwNTQyNGZlM2E1Y2ZhM2FmZGNjZGE5NWY3MzRjOWU2NmVlNzAzZThiOGQ0MjZhMDdjZmUxY2I5Yzg5NTRmfDE3MDAwMDAwMDB8MTcwMDAwMDEyMHxzaGEyNTZ8MHwxfDF8OHxNVEl6TkRVMk56ZzVNR0ZpWTJSbFpnPT18MHx8MXx8fDF8bT0x.faac3b0327610efab95b2595f12ba6cccfd5d414a6130b5c869fb15cb36bdbfb";
    const FIXTURE_SERVER_MAC: &str =
        "e78e7182608185bf8fa24b46bedc2816b99224c5e6a57fd301f42a97f646a7b6";
    const FIXTURE_LEGACY_IP_HASH: &str =
        "5fdd75a9ee78cf4ebabff4683f396b04e13d969578a6e14483c38eb7668fbaaf";
    const FIXTURE_CANONICAL_V1: &str = "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVphYmNkZWY=|login|5fdd75a9ee78cf4ebabff4683f396b04e13d969578a6e14483c38eb7668fbaaf|1700000000";
    const FIXTURE_CHALLENGE_V1: &str = "UVVKRFJFVkdSMGhKU2t0TVRVNVBVRkZTVTFSVlZsZFlXVnBoWW1Oa1pXWT18bG9naW58NWZkZDc1YTllZTc4Y2Y0ZWJhYmZmNDY4M2YzOTZiMDRlMTNkOTY5NTc4YTZlMTQ0ODNjMzhlYjc2NjhmYmFhZnwxNzAwMDAwMDAw.85a180c2c39a90cda8505b9693b43860594ec63bb33d87104cd4f0aa26b8827b";
    const FIXTURE_NOW_NS: u64 = 1_700_000_000_000_000;

    fn fixture_record(protocol_version: u8) -> ChallengeRecord {
        let (binding, challenge) = if protocol_version == 1 {
            (
                FIXTURE_LEGACY_IP_HASH.to_string(),
                FIXTURE_CHALLENGE_V1.to_string(),
            )
        } else {
            (
                FIXTURE_BINDING_TAG.to_string(),
                FIXTURE_CHALLENGE_V2.to_string(),
            )
        };
        let prefix = format!("{challenge}|{FIXTURE_SALT}|");
        ChallengeRecord {
            nonce: FIXTURE_NONCE.into(),
            scope: "login".into(),
            binding_tag: binding,
            issued_at: 1_700_000_000,
            expires_at: 1_700_000_120,
            algorithm: PoWAlgorithm::Sha256,
            m_kib: 0,
            t: 1,
            p: 1,
            target_bits: 8,
            salt: FIXTURE_SALT.into(),
            prefix,
            challenge,
            min_duration_ms: 0,
            issued_at_ns: FIXTURE_NOW_NS,
            attempts_used: 0,
            protocol_version,
            region: None,
            policy_version: 1,
            request_binding: None,
            issuer: None,
            kid: 1,
            execution_program: None,
            execution_version: None,
            execution_commitment: None,
            hostname: None,
            decoy_field: None,
            rsw_modulus_sha256: None,
            server_mac: None,
        }
    }

    fn verify_fixture(record: &mut ChallengeRecord, accept_legacy_v1: bool) -> VerifyOutcome {
        let counter = solve_for_test(record).expect("fixture counter found");
        let mut ctx = VerifyContext {
            record,
            secret_key: FIXTURE_SECRET,
            tenant: None,
            secrets_by_kid: None,
            rsw_proof: None,
            rsw_modulus_n: None,
            rsw_lambda: None,
            rsw_keyring: None,
            revoked_kids: None,
            counter,
            duration_ms: 5000,
            now_unix: Some(&mut || 1_700_000_100), // before expires_at 1_700_000_120
            now_ns: FIXTURE_NOW_NS + 5_000_000,
            min_duration_ms: 0,
            expected_scope: None,
            expected_request_binding: RequestBindingExpectation::Unenforced,
            client_ip: Some("192.168.1.5"),
            execution_digest: None,
            execution_trace: None,
            expected_region: None,
            expected_issuer: None,
            expected_policy_version: None,
            policy_version_floor: None,
            telemetry: None,
            enforce_telemetry: false,
            max_attempts: 0,
            accept_legacy_v1,
        };
        verify_solution(&mut ctx)
    }

    #[test]
    fn binding_tag_matches_the_shared_fixture() {
        // Locks the exact v2 binding tag from the shared fixture vector.
        assert_eq!(
            binding_tag(FIXTURE_NONCE, "192.168.1.5", FIXTURE_SECRET).unwrap(),
            FIXTURE_BINDING_TAG
        );
        // Legacy binding (v1) is the hash_ip(secret||ip) value.
        assert_eq!(
            hash_ip("192.168.1.5", FIXTURE_SECRET),
            FIXTURE_LEGACY_IP_HASH
        );
    }

    #[test]
    fn v2_fixture_record_verifies() {
        let mut record = fixture_record(2);
        assert_eq!(record.challenge, FIXTURE_CHALLENGE_V2);
        // The challenge's base64 half is byte-exactly the v2 canonical.
        let b64 = FIXTURE_CHALLENGE_V2.split('.').next().unwrap();
        assert_eq!(B64.decode(b64).unwrap(), FIXTURE_CANONICAL_V2.as_bytes());
        // No MAC at issue means no signed marker, and the floorless
        // record stays verifiable: the documented floorless path.
        assert!(record.server_mac.is_none());
        assert!(!crate::challenge::signed_canonical_commits_record_meta(
            &record.challenge
        ));
        assert!(
            matches!(
                verify_fixture(&mut record, false),
                VerifyOutcome::Valid { .. }
            ),
            "v2 shared fixture vector must verify with client_ip 192.168.1.5"
        );
    }

    #[test]
    fn v1_fixture_record_rejected_by_default() {
        // The v1 migration window is closed by default: v2 has been the
        // issuance format longer than the maximum challenge lifetime, so no
        // legitimate v1 record can still exist.
        let mut record = fixture_record(1);
        assert_eq!(
            verify_fixture(&mut record, false),
            VerifyOutcome::Invalid(VerifyError::MalformedRecord),
            "v1 must be rejected unless accept_legacy_v1 is set"
        );
    }

    #[test]
    fn v1_fixture_record_still_verifies_with_migration_flag() {
        // protocol_version 1 + legacy canonical + legacy ip_hash binding —
        // verifiable only during an explicit migration window.
        let mut record = fixture_record(1);
        assert_eq!(record.challenge, FIXTURE_CHALLENGE_V1);
        let b64 = FIXTURE_CHALLENGE_V1.split('.').next().unwrap();
        assert_eq!(B64.decode(b64).unwrap(), FIXTURE_CANONICAL_V1.as_bytes());
        assert!(
            matches!(
                verify_fixture(&mut record, true),
                VerifyOutcome::Valid { .. }
            ),
            "v1 shared fixture vector must verify with the migration flag"
        );
    }

    #[test]
    fn v2_fixture_record_with_signed_mac_verifies_and_refuses_tampering() {
        // The signed m=1 vector: the canonical carries the marker and the
        // record carries the server-state MAC over the exact challenge.
        let mut record = fixture_record(2);
        record.challenge = FIXTURE_CHALLENGE_V2_MAC.into();
        record.prefix = format!("{}|{FIXTURE_SALT}|", record.challenge);
        record.server_mac = Some(FIXTURE_SERVER_MAC.into());
        let b64 = FIXTURE_CHALLENGE_V2_MAC.split('.').next().unwrap();
        assert_eq!(
            B64.decode(b64).unwrap(),
            FIXTURE_CANONICAL_V2_MAC.as_bytes()
        );
        assert!(crate::challenge::signed_canonical_commits_record_meta(
            &record.challenge
        ));
        assert!(!crate::challenge::signed_canonical_commits_record_meta(
            FIXTURE_CHALLENGE_V2
        ));
        let mut signed = record.clone();
        assert!(
            matches!(
                verify_fixture(&mut signed, false),
                VerifyOutcome::Valid { .. }
            ),
            "the signed m=1 fixture must verify"
        );

        // Stripping the MAC leaves the signed marker without its tag:
        // the required-MAC gate refuses the record.
        let mut stripped = record.clone();
        stripped.server_mac = None;
        assert_eq!(
            verify_fixture(&mut stripped, false),
            VerifyOutcome::Invalid(VerifyError::BadSignature)
        );

        // Rewriting the sealed clock keeps the marker and breaks the MAC.
        let mut backdated = record.clone();
        backdated.issued_at_ns -= 1;
        assert_eq!(
            verify_fixture(&mut backdated, false),
            VerifyOutcome::Invalid(VerifyError::BadSignature)
        );

        // A no-marker record with a foreign MAC fails the MAC check.
        let mut forged = fixture_record(2);
        forged.server_mac = Some(FIXTURE_SERVER_MAC.into());
        assert_eq!(
            verify_fixture(&mut forged, false),
            VerifyOutcome::Invalid(VerifyError::BadSignature)
        );
    }

    #[test]
    fn record_meta_marker_parser_rejects_malformed_challenges() {
        // The marker parser is total: no dot, invalid base64, a non-v4
        // revision and a canonical without the trailing marker all read
        // as uncovered, so only a signed v4 marker can demand a MAC.
        assert!(!crate::challenge::signed_canonical_commits_record_meta(
            "no-dot"
        ));
        assert!(!crate::challenge::signed_canonical_commits_record_meta(
            "!!!.###"
        ));
        assert!(!crate::challenge::signed_canonical_commits_record_meta(
            &format!("{}.00", B64.encode(b"v3|1|...|m=1"))
        ));
        assert!(!crate::challenge::signed_canonical_commits_record_meta(
            &format!("{}.00", B64.encode(b"v4|1|..."))
        ));
        assert!(crate::challenge::signed_canonical_commits_record_meta(
            &format!("{}.00", B64.encode(b"v4|1|...|m=1"))
        ));
    }

    #[test]
    fn v2_fixture_rejects_wrong_scope_with_wrong_scope_error() {
        let mut record = fixture_record(2);
        let counter = solve_for_test(&record).unwrap();
        let mut ctx = VerifyContext {
            record: &mut record,
            secret_key: FIXTURE_SECRET,
            tenant: None,
            secrets_by_kid: None,
            revoked_kids: None,
            counter,
            duration_ms: 5000,
            now_unix: Some(&mut || 1_700_000_100),
            now_ns: FIXTURE_NOW_NS + 5_000_000,
            min_duration_ms: 0,
            expected_scope: Some("signup"),
            expected_request_binding: RequestBindingExpectation::Unenforced,
            client_ip: Some("1.2.3.4"),
            execution_digest: None,
            execution_trace: None,
            expected_region: None,
            expected_issuer: None,
            expected_policy_version: None,
            policy_version_floor: None,
            telemetry: None,
            enforce_telemetry: false,
            max_attempts: 0,
            accept_legacy_v1: false,
            rsw_proof: None,
            rsw_modulus_n: None,
            rsw_lambda: None,
            rsw_keyring: None,
        };
        assert_eq!(
            verify_solution(&mut ctx),
            VerifyOutcome::Invalid(VerifyError::WrongScope)
        );
    }

    #[test]
    fn legacy_v1_record_roundtrips_through_json() {
        // Stored legacy records use the "ip_hash" JSON key — the serde alias
        // must read them into binding_tag; protocol_version defaults to 1.
        let json = serde_json::json!({
            "nonce": FIXTURE_NONCE,
            "scope": "login",
            "ip_hash": FIXTURE_LEGACY_IP_HASH,
            "issued_at": 1_700_000_000,
            "expires_at": 1_700_000_120,
            "algorithm": "sha256",
            "m_kib": 0,
            "t": 1,
            "p": 1,
            "target_bits": 8,
            "salt": FIXTURE_SALT,
            "prefix": format!("{}|{}|", FIXTURE_CHALLENGE_V1, FIXTURE_SALT),
            "challenge": FIXTURE_CHALLENGE_V1,
            "min_duration_ms": 0,
            "issued_at_ns": FIXTURE_NOW_NS,
        });
        let mut decoded: ChallengeRecord = serde_json::from_value(json).unwrap();
        assert_eq!(decoded.binding_tag, FIXTURE_LEGACY_IP_HASH);
        assert_eq!(decoded.protocol_version, 1);
        assert_eq!(decoded.challenge, FIXTURE_CHALLENGE_V1);
        assert!(
            matches!(
                verify_fixture(&mut decoded, true),
                VerifyOutcome::Valid { .. }
            ),
            "v1 record read via the ip_hash alias must verify with the migration flag"
        );
    }
    // ── rsw (sequential time-lock) verification ───────────────────────

    fn make_rsw_record(t: u32) -> ChallengeRecord {
        let mut config = crate::challenge::ChallengeConfig {
            secret_key: "test-key-32-bytes-0123456789abcd".into(),
            kid: 1,
            execution_key: None,
            rsw_modulus_n: Some(crate::rsw::fixtures::MODULUS_N_B64.into()),
            rsw_lambda: Some(crate::rsw::fixtures::LAMBDA_B64.into()),
            rsw_t: t,
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
        };
        if t == 0 {
            // A signed out-of-range record: keep a canonical range T for
            // the issuance, then re-sign with the out-of-range slot.
            config.rsw_t = crate::challenge::MIN_RSW_T;
        }
        let issued = crate::challenge::issue_challenge(
            &config, "login", "1.2.3.4", NOW_UNIX, NOW_NS, 0, None,
        )
        .unwrap();
        let mut record = issued.record;
        if t == 0 {
            record.t = 0;
            resign_v2(&mut record, "test-key-32-bytes-0123456789abcd");
        }
        record
    }

    /// Verify a record against a presented rsw proof through the shared
    /// `verify_solution` flow.
    fn verify_rsw(
        record: &mut ChallengeRecord,
        proof: Option<&str>,
        trapdoor: bool,
    ) -> VerifyOutcome {
        let mut ctx = VerifyContext {
            record,
            secret_key: "test-key-32-bytes-0123456789abcd",
            tenant: None,
            secrets_by_kid: None,
            revoked_kids: None,
            counter: 0,
            duration_ms: 5000,
            now_unix: Some(&mut || NOW_UNIX + 1),
            now_ns: NOW_NS + 5_000_000,
            min_duration_ms: 0,
            expected_scope: Some("login"),
            expected_request_binding: RequestBindingExpectation::Unenforced,
            expected_region: None,
            expected_issuer: None,
            expected_policy_version: None,
            policy_version_floor: None,
            client_ip: Some("1.2.3.4"),
            rsw_proof: proof,
            rsw_modulus_n: trapdoor.then_some(crate::rsw::fixtures::MODULUS_N_B64),
            rsw_lambda: trapdoor.then_some(crate::rsw::fixtures::LAMBDA_B64),
            rsw_keyring: None,
            execution_digest: None,
            execution_trace: None,
            telemetry: None,
            enforce_telemetry: false,
            max_attempts: 0,
            accept_legacy_v1: false,
        };
        verify_solution(&mut ctx)
    }

    #[test]
    fn rsw_sequential_solve_round_trip_verifies() {
        let mut record = make_rsw_record(crate::challenge::MIN_RSW_T);
        let proof =
            crate::rsw::fixtures::sequential_proof(&record.prefix, &record.nonce, record.t as u64);
        assert!(
            matches!(
                verify_rsw(&mut record, Some(&proof), true),
                VerifyOutcome::Valid { .. }
            ),
            "the sequential solve must verify through the trapdoor"
        );
    }

    #[test]
    fn rsw_wrong_or_missing_proof_is_insufficient_work() {
        let mut record = make_rsw_record(crate::challenge::MIN_RSW_T);
        let proof =
            crate::rsw::fixtures::sequential_proof(&record.prefix, &record.nonce, record.t as u64);
        let mut wrong = proof.clone();
        wrong.replace_range(0..1, if &proof[0..1] == "0" { "1" } else { "0" });
        assert_eq!(
            verify_rsw(&mut record, Some(&wrong), true),
            VerifyOutcome::Invalid(VerifyError::InsufficientWork)
        );
        let mut record2 = make_rsw_record(crate::challenge::MIN_RSW_T);
        assert_eq!(
            verify_rsw(&mut record2, None, true),
            VerifyOutcome::Invalid(VerifyError::InsufficientWork),
            "a missing proof segment is a wrong proof"
        );
    }

    #[test]
    fn rsw_proof_of_another_challenge_is_insufficient_work() {
        let mut record_a = make_rsw_record(crate::challenge::MIN_RSW_T);
        let record_b = make_rsw_record(crate::challenge::MIN_RSW_T);
        let proof_of_b = crate::rsw::fixtures::sequential_proof(
            &record_b.prefix,
            &record_b.nonce,
            record_b.t as u64,
        );
        assert_eq!(
            verify_rsw(&mut record_a, Some(&proof_of_b), true),
            VerifyOutcome::Invalid(VerifyError::InsufficientWork)
        );
    }

    #[test]
    fn rsw_without_a_configured_trapdoor_is_unsupported() {
        let mut record = make_rsw_record(crate::challenge::MIN_RSW_T);
        let proof =
            crate::rsw::fixtures::sequential_proof(&record.prefix, &record.nonce, record.t as u64);
        assert_eq!(
            verify_rsw(&mut record, Some(&proof), false),
            VerifyOutcome::Invalid(VerifyError::UnsupportedRswParams)
        );
    }

    #[test]
    fn rsw_signed_record_outside_the_t_ceiling_is_unsupported() {
        // A zero time-cost slot is inside the u32 space but far outside
        // the issuance range 10,000..=300,000: the cheap-phase process
        // bound refuses the authentic record before any trapdoor work.
        let mut record = make_rsw_record(0);
        let proof =
            crate::rsw::fixtures::sequential_proof(&record.prefix, &record.nonce, record.t as u64);
        assert_eq!(
            verify_rsw(&mut record, Some(&proof), true),
            VerifyOutcome::Invalid(VerifyError::UnsupportedRswParams)
        );
    }

    #[test]
    fn rsw_trapdoor_expectation_equals_sequential_squaring() {
        let rsw = crate::rsw::RswTrapdoor::new(
            crate::rsw::fixtures::MODULUS_N_B64,
            crate::rsw::fixtures::LAMBDA_B64,
        )
        .unwrap();
        for t in [1u64, 2, 7, 10_000] {
            let record = make_rsw_record(crate::challenge::MIN_RSW_T);
            let sequential =
                crate::rsw::fixtures::sequential_proof(&record.prefix, &record.nonce, t);
            let expected = rsw.expected_proof_hex(&record.prefix, &record.nonce, t);
            assert_eq!(
                expected, sequential,
                "the trapdoor shortcut must equal {t} squarings"
            );
        }
    }

    // ── the rsw + execution composition and the algorithm-total proof
    //    vocabulary (the token matrix's verifier rows) ──────────────────

    /// An rsw record armed with the ExecutionChallengeV1 dimension
    /// (protocol v4, algorithm rsw): the issuance shape whose solution
    /// token carries the digest:trace evidence AND the rsw final value.
    fn make_rsw_execution_record() -> ChallengeRecord {
        let config = ChallengeConfig {
            secret_key: "test-key-32-bytes-0123456789abcd".into(),
            kid: 1,
            execution_key: Some("0123456789abcdef0123456789abcdef".into()),
            rsw_modulus_n: Some(crate::rsw::fixtures::MODULUS_N_B64.into()),
            rsw_lambda: Some(crate::rsw::fixtures::LAMBDA_B64.into()),
            rsw_t: crate::challenge::MIN_RSW_T,
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
        };
        // The composition confirms the v5 ceiling explicitly: the
        // capability-free default would emit the identityless shape.
        crate::challenge::issue_challenge_with_execution_capabilities(
            crate::challenge::EmissionCapabilities::confirmed(
                crate::challenge::RSW_IDENTITY_PROTOCOL_VERSION,
            )
            .expect("the confirmed ceiling is at least the base protocol"),
            &config,
            "login",
            "1.2.3.4",
            NOW_UNIX,
            NOW_NS,
            0,
            None,
            true,
            Some("login-action"),
            Some(1),
            false,
        )
        .expect("the rsw + execution issuance must succeed")
        .record
    }

    /// The real execution evidence of an armed record, built exactly
    /// like the interpreter: the executed trace of the stored program
    /// and the digest over it, with the trace in its base64url wire
    /// form.
    fn execution_evidence(record: &ChallengeRecord) -> (String, String) {
        use base64::Engine;
        let program = record
            .execution_program
            .as_deref()
            .expect("the armed record carries the program");
        let decoded = crate::execution::decode(program).expect("the issued program parses");
        let trace = crate::execution::fixtures::executed_trace_for(&decoded);
        let trace_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(trace.as_bytes());
        let digest = crate::execution::expected_digest_over_trace(program, &record.nonce, &trace)
            .expect("the digest over the executed trace computes");
        (digest, trace_b64)
    }

    /// Verify through the full `verify_solution` flow with full control
    /// of every token field, the rsw + execution composition row
    /// helper.
    #[allow(clippy::too_many_arguments)]
    fn verify_composed(
        record: &mut ChallengeRecord,
        counter: u64,
        proof: Option<&str>,
        digest: Option<&str>,
        trace_b64: Option<&str>,
    ) -> VerifyOutcome {
        let mut ctx = VerifyContext {
            record,
            secret_key: "test-key-32-bytes-0123456789abcd",
            tenant: None,
            secrets_by_kid: None,
            revoked_kids: None,
            counter,
            duration_ms: 5000,
            now_unix: Some(&mut || NOW_UNIX + 1),
            now_ns: NOW_NS + 5_000_000,
            min_duration_ms: 0,
            expected_scope: Some("login"),
            expected_request_binding: RequestBindingExpectation::Unenforced,
            expected_region: None,
            expected_issuer: None,
            expected_policy_version: None,
            policy_version_floor: None,
            client_ip: Some("1.2.3.4"),
            rsw_proof: proof,
            rsw_modulus_n: Some(crate::rsw::fixtures::MODULUS_N_B64),
            rsw_lambda: Some(crate::rsw::fixtures::LAMBDA_B64),
            rsw_keyring: None,
            execution_digest: digest,
            execution_trace: trace_b64,
            telemetry: None,
            enforce_telemetry: false,
            max_attempts: 0,
            accept_legacy_v1: false,
        };
        verify_solution(&mut ctx)
    }

    #[test]
    fn rsw_and_execution_compose_end_to_end() {
        // The positive composition: an rsw + execution armed record is
        // solved with the real digest:trace evidence AND the sequential
        // final value, and the full token round-trips the wire decode
        // (the fifth and sixth segments) and verifies. This is the
        // acceptance the mutually-exclusive decoder used to break.
        let mut record = make_rsw_execution_record();
        assert_eq!(record.protocol_version, 5);
        let proof =
            crate::rsw::fixtures::sequential_proof(&record.prefix, &record.nonce, record.t as u64);
        let (digest, trace_b64) = execution_evidence(&record);

        let wire = crate::token::SolutionToken {
            nonce: record.nonce.clone(),
            counter: 0,
            duration_ms: 5000,
            telemetry: serde_json::json!({}),
            execution_digest: Some(digest.clone()),
            execution_trace: Some(trace_b64.clone()),
            rsw_proof: Some(proof.clone()),
        }
        .encode();
        let decoded = crate::token::SolutionToken::decode(&wire)
            .expect("the composed token must decode on one wire");
        assert_eq!(decoded.rsw_proof.as_deref(), Some(proof.as_str()));
        assert_eq!(decoded.execution_digest.as_deref(), Some(digest.as_str()));
        assert_eq!(decoded.execution_trace.as_deref(), Some(trace_b64.as_str()));

        assert!(
            matches!(
                verify_composed(
                    &mut record,
                    0,
                    Some(&proof),
                    Some(&digest),
                    Some(&trace_b64)
                ),
                VerifyOutcome::Valid { .. }
            ),
            "the rsw + execution composition must verify end to end"
        );
    }

    #[test]
    fn rsw_record_with_a_nonzero_counter_is_insufficient_work() {
        // The verifier matrix row: an rsw record demands counter 0 —
        // even a cryptographically correct final value under a nonzero
        // counter is rejected outright, never compared.
        let mut record = make_rsw_record(crate::challenge::MIN_RSW_T);
        let proof =
            crate::rsw::fixtures::sequential_proof(&record.prefix, &record.nonce, record.t as u64);
        assert_eq!(
            verify_composed(&mut record, 1, Some(&proof), None, None),
            VerifyOutcome::Invalid(VerifyError::InsufficientWork),
            "an rsw token with a nonzero counter must be rejected"
        );
        // The composition shape: the correct execution evidence does not
        // excuse a nonzero counter either.
        let mut composed = make_rsw_execution_record();
        let proof = crate::rsw::fixtures::sequential_proof(
            &composed.prefix,
            &composed.nonce,
            composed.t as u64,
        );
        let (digest, trace_b64) = execution_evidence(&composed);
        assert_eq!(
            verify_composed(
                &mut composed,
                7,
                Some(&proof),
                Some(&digest),
                Some(&trace_b64)
            ),
            VerifyOutcome::Invalid(VerifyError::InsufficientWork),
            "an rsw + execution token with a nonzero counter must be rejected"
        );
    }

    #[test]
    fn sha_and_argon_records_reject_a_presented_rsw_proof() {
        // The verifier matrix rows: a 512-hex rsw final value is rsw
        // evidence only, so a sha256/argon2id record presented with one
        // is rejected outright — with the winning hash counter, so the
        // rejection can only be the proof-vocabulary gate, never the
        // difficulty check.
        let mut sha = make_record(8);
        let sha_counter = solve_for_test(&sha).expect("the sha challenge solves");
        assert!(
            matches!(
                verify_composed(&mut sha, sha_counter, Some(&"a".repeat(512)), None, None),
                VerifyOutcome::Invalid(VerifyError::InsufficientWork)
            ),
            "a sha256 record must reject a presented rsw proof"
        );

        let mut argon = make_argon2_record(4, 64);
        let argon_counter = solve_for_test(&argon).expect("the argon challenge solves");
        assert!(
            matches!(
                verify_composed(
                    &mut argon,
                    argon_counter,
                    Some(&"a".repeat(512)),
                    None,
                    None
                ),
                VerifyOutcome::Invalid(VerifyError::InsufficientWork)
            ),
            "an argon2id record must reject a presented rsw proof"
        );
    }
}
