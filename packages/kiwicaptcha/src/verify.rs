//! Proof-of-work verification for KiwiCaptcha.
//!
//! Given a stored [`ChallengeRecord`] and a client-submitted counter, this
//! module re-derives the hash (`SHA-256(prefix || counter || salt)` or
//! `Argon2id(prefix || counter, salt)` per the record's algorithm) and checks
//! that the raw output has at least `target_bits` leading zero bits.
//!
//! Because the computation is driven by the record's explicit algorithm and
//! difficulty, the verifier always performs exactly the work the issuer
//! configured — the client cannot downgrade difficulty or switch modes.

use argon2::{Algorithm, Argon2, Params, Version};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};

use crate::challenge::{
    binding_tag, hash_ip, payload_from_record, verify_signature, verify_signature_v2,
    ChallengeRecord, PoWAlgorithm,
};

/// Clock-skew tolerance (microseconds) for the server-side minimum-duration
/// check. When the issuer host's clock is AHEAD of the verifier host
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
            // issuance too.
            if record.m_kib < 8 * record.p || check_argon2_ceilings(record).is_err() {
                return Err(VerifyError::MalformedRecord);
            }
            // Protocol unit: m_kib is KIBIBYTES (65536 = 64 MiB); the
            // argon2 crate's Params::new takes the same 1 KiB blocks.
            let params = Params::new(record.m_kib, record.t, record.p, Some(32))
                .map_err(|_| VerifyError::MalformedRecord)?;
            let hasher = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
            let password = format!("{}{}", record.prefix, counter);
            let mut output = [0u8; 32];
            hasher
                .hash_password_into(password.as_bytes(), &salt, &mut output)
                .map_err(|_| VerifyError::InsufficientWork)?;
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
pub struct VerifyContext<'a> {
    /// The stored challenge record (looked up from storage by nonce). Passed
    /// as `&mut` because verification performs attempt accounting on the
    /// record's `attempts_used` counter — the caller persists the mutated
    /// record back to storage (on failure paths) or consumes it (on success).
    pub record: &'a mut ChallengeRecord,
    /// The HMAC secret key (to re-verify the challenge signature).
    pub secret_key: &'a str,
    /// Optional per-key-id secrets: `kid → master secret`. When
    /// present, the record's `kid` selects the secret for the signature (and
    /// IP-binding) checks — the secret rotation map. An unknown kid — or a
    /// kid beyond the map's NEWEST configured id (the forward/rollback guard:
    /// future-keyed challenges must never verify on older nodes, even if the
    /// key were somehow known) — rejects with
    /// [`VerifyError::UnknownKid`]. When `None`, `secret_key` is used
    /// unconditionally (the single-key path).
    pub secrets_by_kid: Option<&'a HashMap<u32, String>>,
    /// Compromise-revoked key ids: `kid → revoked` — e.g. a key
    /// that leaked. A record whose `kid` is in this set is rejected with
    /// [`VerifyError::UnknownKid`] IMMEDIATELY — before the signature check —
    /// even when the secret is present: compromise revocation OVERRIDES the
    /// rotation grace (a revoked key may legitimately remain in
    /// `secrets_by_kid` while the deployment retires it, but its challenges
    /// must never verify). When `None`, no kid is revoked.
    pub revoked_kids: Option<&'a HashSet<u32>>,
    /// The client's claimed counter.
    pub counter: u64,
    /// The client's reported solve duration in milliseconds. This value is
    /// CLIENT-CONTROLLED and therefore forgeable — it is NOT used to enforce
    /// the minimum duration (that is measured server-side via
    /// `issued_at_ns`/`now_ns`); it is only fed to the telemetry scorer.
    pub duration_ms: u64,
    /// The current Unix timestamp in seconds (for the TTL check).
    pub now_unix: u64,
    /// The server's receipt time in EPOCH MICROSECONDS — the same unit as the
    /// record's `issued_at_ns` (the field names keep the `_ns`
    /// suffix; the unit is microseconds, shared with PHP). Together they
    /// provide a server-measured elapsed time, used to enforce the minimum
    /// solve duration. A forged client `duration_ms` can never satisfy this
    /// check.
    pub now_ns: u64,
    /// The minimum acceptable solve duration in milliseconds. The floor is a
    /// timing-anomaly heuristic: PoW is probabilistic (a valid solution can
    /// occur at counter 0) and a fast bot can wait before submitting, so the
    /// floor only rejects solves that ARRIVE (per the server clock) faster
    /// than the theoretical minimum — a heuristic, never a proof of human
    /// behavior, and the client-reported duration is never trusted. The
    /// effective floor is `max(min_duration_ms, record.min_duration_ms)`;
    /// 0 disables the check.
    pub min_duration_ms: u64,
    /// Expected auth scope. If [`Some`], the solution is rejected if the
    /// challenge was issued for a different scope (prevents cross-scope replay).
    pub expected_scope: Option<&'a str>,
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
    /// The CURRENT security-policy epoch. When set, a record whose
    /// `policy_version` differs is rejected with
    /// [`VerifyError::WrongPolicyVersion`] — outstanding challenges die
    /// immediately on policy revocation.
    pub expected_policy_version: Option<u32>,
    /// The current client's IP address. In v2 the binding is the
    /// NONCE-BOUND HMAC tag: verification recomputes the tag from the
    /// challenge nonce + canonical client IP under the derived purpose key
    /// and rejects a mismatch with [`VerifyError::IpMismatch`]. The nonce-
    /// bound tag is the current binding model (v1 records use the legacy
    /// `hash_ip`). When `None` and the
    /// record's binding tag is NON-EMPTY, the solution is rejected with
    /// [`VerifyError::MissingClientIp`] — a bound challenge requires its IP.
    /// Only records with an empty binding tag (`BindingMode::None`) verify
    /// without an IP.
    pub client_ip: Option<&'a str>,
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
    /// Set this ONLY during a coordinated migration window.
    pub accept_legacy_v1: bool,
    /// Maximum number of verification attempts against this record
    /// (`record.attempts_used`). 0 = unlimited. Attempts are counted on every
    /// verification call (correct or not), bounding the server-side cost of
    /// wrong candidates — particularly memory-hard Argon2id verifications.
    pub max_attempts: u32,
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
        /// it again on the final protected POST — correlating the CAPTCHA
        /// result with the exact application transaction.
        request_binding: Option<String>,
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
    #[error("challenge was issued for a different region")]
    WrongRegion,
    /// The stored record was issued under a DIFFERENT issuer identity than
    /// the verifier's configured expected issuer — or under no
    /// issuer at all (an issuer-expecting deployment fails closed on
    /// issuer-unbound challenges).
    #[error("challenge was issued by a different issuer")]
    WrongIssuer,
    /// The stored record was issued under a DIFFERENT security-policy epoch
    /// than the verifier's configured current version — the policy that
    /// authorized the challenge (origin/action rules, difficulty floors,
    /// revocation) is no longer in force, so the challenge is invalid.
    #[error("challenge was issued under a different security-policy epoch")]
    WrongPolicyVersion,
    /// The record's key id (`kid`) is unknown to this verifier —
    /// either absent from its `secrets_by_kid` map, or NEWER than the
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
    /// an uncertain I/O error —
    /// the challenge may or may not have been consumed on the server. The
    /// consumer MUST NOT retry the consume automatically (the record may
    /// already be burned); treat the token as unknown instead of replaying
    /// it. See the consume no-retry rule in `redis_verify`.
    #[error("challenge consumption is indeterminate (storage I/O failure) — the challenge may or may not have been consumed; do not blindly retry this token")]
    ConsumeIndeterminate,
    #[error("verification capacity exceeded — try again shortly")]
    CapacityExceeded,
    #[error("admission gate unavailable — try again shortly")]
    AdmissionUnavailable,
}

/// Comprehensive structural validation of a stored [`ChallengeRecord`].
///
/// Runs as the FIRST check of [`verify_solution`] (after attempt accounting),
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
/// - `expires_at > issued_at` and `expires_at - issued_at <= MAX_TTL_SECS`;
/// - `prefix` is exactly `challenge|salt|`;
/// - `target_bits` 1..=MAX_DIFFICULTY for BOTH algorithms (the
///   Argon2id issuance ceiling stays stricter at
///   [`SOLVER_MAX_ARGON2_TARGET_BITS`], exactly like the t=7..=16
///   verifier-vs-issuer split);
/// - Argon2id: the hard parameter ceilings: `m_kib` 8..=65536,
///   `t` 3..=16, `p` 1..=4.
///
/// Returns [`VerifyError::MalformedRecord`] on any violation.
pub fn validate_record(record: &ChallengeRecord) -> Result<(), VerifyError> {
    // Protocol version is part of the wire contract: only 1 (legacy,
    // migration window) and 2 (current) exist — anything else is a
    // corrupt/foreign record.
    if record.protocol_version != 1 && record.protocol_version != 2 {
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
    // Exact-length pre-bounds BEFORE any base64 decode — the
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
    // BOTH algorithms — 0 would accept a trivially-solvable challenge and
    // anything above the solver ceiling can never be produced by a widget.
    use crate::challenge::{MAX_DIFFICULTY, MIN_DIFFICULTY};
    if record.target_bits < MIN_DIFFICULTY || record.target_bits > MAX_DIFFICULTY {
        return Err(VerifyError::MalformedRecord);
    }
    match record.algorithm {
        PoWAlgorithm::Sha256 => {}
        PoWAlgorithm::Argon2id => {
            check_argon2_ceilings(record)?;
        }
    }
    Ok(())
}

/// Validate the hard Argon2id parameter ceilings.
///
/// Checks `m_kib`/`t`/`p` against [`crate::challenge::MIN_ARGON_MEMORY_KIB`],
/// [`crate::challenge::MAX_ARGON_MEMORY_KIB`], [`crate::challenge::MIN_ARGON_TIME`],
/// [`crate::challenge::MAX_ARGON_TIME`], [`crate::challenge::MIN_PARALLELISM`],
/// [`crate::challenge::MAX_PARALLELISM`] — the verifier must never run (or
/// allocate for) a memory-hard computation with parameters outside these
/// bounds, even when the record is properly signed.
///
/// Returns [`VerifyError::MalformedRecord`] when any parameter is out of
/// range. Called by [`validate_record`] (the cheap pre-signature gate) AND
/// explicitly AFTER signature authentication in [`verify_solution`] and the
/// production verifier, so a signed record is validated against the ceilings
/// again immediately before any allocation happens.
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
        return Err(VerifyError::MalformedRecord);
    }
    Ok(())
}

/// Verify a solution against its stored challenge record.
///
/// This performs the full server-side check:
/// 1. Attempt accounting: `record.attempts_used` is incremented; when it
///    exceeds `max_attempts` (and `max_attempts > 0`) the solution is
///    rejected with [`VerifyError::TooManyAttempts`]. The caller persists the
///    mutated record on failure, or consumes it on success (single-use).
/// 2. Structural record validation ([`validate_record`]) — a cheap phase that
///    runs BEFORE any hash is derived, so malformed or attacker-crafted
///    records can never drive expensive verification work.
/// 3. Re-verify the HMAC signature over the protocol-appropriate canonical
///    input (v1 for `protocol_version == 1` records, v2 otherwise; v2
///    signatures use the HKDF-derived challenge key). When
///    `secrets_by_kid` is configured, the record's `kid` selects the secret:
///    an unknown — or future — kid rejects with
///    [`VerifyError::UnknownKid`] before any signature work. A REVOKED kid
///    (`revoked_kids`) rejects with [`VerifyError::UnknownKid`]
///    even earlier, before the signature check, even when its secret is
///    present: compromise revocation overrides the rotation grace.
/// 4. Hard Argon2id parameter ceilings — after signature
///    authentication, before any `Params::new`/allocation.
/// 5. Check the TTL (defends against stale challenges).
/// 6. Check the scope (prevents cross-scope replay) →
///    [`VerifyError::WrongScope`].
/// 7. Check the region (when `expected_region` is set) →
///    [`VerifyError::WrongRegion`].
/// 8. Check the IP binding: for v2 records, recompute the nonce-bound
///    `binding_tag` from `client_ip` + record nonce + secret and compare in
///    constant time; for v1 records, compare the legacy `hash_ip`. An empty
///    `binding_tag` skips the check. A `None` `client_ip` with a NON-EMPTY
///    tag fails closed with [`VerifyError::MissingClientIp`] — only records
///    issued with `BindingMode::None` (empty tag) verify without an IP.
/// 9. Check the minimum duration with the SERVER clock (see
///    [`SKEW_TOLERANCE_US`] for the clock-skew policy). The client-reported
///    duration is forgeable and is never trusted for this check. Records
///    without `issued_at_ns` are malformed (there is no client-duration
///    fallback).
/// 10. Optional telemetry scoring (when `enforce_telemetry` is set).
/// 11. Re-derive the SHA-256/Argon2id hash and check leading zero bits (the
///     actual PoW). The valid outcome's `nonce` field carries the consumed
///     canonical nonce (jti).
pub fn verify_solution(ctx: &mut VerifyContext<'_>) -> VerifyOutcome {
    // 0. Attempt accounting — counted on EVERY verification call, correct or
    //    not, so a wrong-candidate loop cannot burn unbounded server-side
    //    computation (especially memory-hard Argon2id hashing).
    ctx.record.attempts_used = ctx.record.attempts_used.saturating_add(1);
    if ctx.max_attempts > 0 && ctx.record.attempts_used > ctx.max_attempts {
        return VerifyOutcome::Invalid(VerifyError::TooManyAttempts);
    }

    // 0b. Cheap structural validation FIRST — before any signature work or
    //     hash derivation (XII): a malformed record can never drive an
    //     expensive verification.
    if let Err(e) = validate_record(ctx.record) {
        return VerifyOutcome::Invalid(e);
    }

    // 0c. Counter bound: the official solvers never search beyond
    //     SOLVER_MAX_HASHES; a larger counter is not a legitimate solution
    //     and must not reach hash derivation (deterministic rejection).
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
    //     unknown kid — or a kid NEWER than the map's newest id (the
    //     forward/rollback guard: future-keyed challenges must never verify
    //     on older nodes, even if the key were somehow known) — is rejected
    //     with UnknownKid BEFORE any signature work.
    //     Compromise revocation is checked FIRST: a REVOKED kid is
    //     rejected immediately — before the signature check — even when its
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
        _ => verify_signature_v2(ctx.record, sig, secret),
    };
    match sig_ok {
        Ok(true) => {}
        Ok(false) => return VerifyOutcome::Invalid(VerifyError::BadSignature),
        Err(_) => return VerifyOutcome::Invalid(VerifyError::BadSignature),
    }

    // 1c. Hard Argon2id parameter ceilings — validated AFTER the
    //     signature has been authenticated and BEFORE any Params::new or
    //     memory allocation: even a properly signed record must never drive
    //     an out-of-bounds memory-hard computation.
    if ctx.record.algorithm == PoWAlgorithm::Argon2id {
        if let Err(e) = check_argon2_ceilings(ctx.record) {
            return VerifyOutcome::Invalid(e);
        }
    }

    // 2. TTL. The challenge is invalid outside its validity window
    //    [issued_at, expires_at): expired once now reaches expires_at, and
    //    a future-issued challenge is a time-domain anomaly
    //    when its issued_at is more than MAX_CLOCK_SKEW_SECS ahead of the
    //    verifier clock — the issuer and verifier clocks are broken.
    if ctx.now_unix >= ctx.record.expires_at {
        return VerifyOutcome::Invalid(VerifyError::Expired);
    }
    if ctx.record.issued_at
        > ctx
            .now_unix
            .saturating_add(crate::challenge::MAX_CLOCK_SKEW_SECS)
    {
        return VerifyOutcome::Invalid(VerifyError::Expired);
    }

    // 2b. Scope validation: reject if the challenge was issued for a different
    //     auth flow (e.g. a login challenge used on /signup).
    if let Some(expected) = ctx.expected_scope {
        if ctx.record.scope != expected {
            return VerifyOutcome::Invalid(VerifyError::WrongScope);
        }
    }

    // 2c. Region validation: a deployment that expects a region
    //     rejects challenges issued for a different region — or for no region
    //     at all (fail closed).
    if let Some(expected) = ctx.expected_region {
        if ctx.record.region.as_deref() != Some(expected) {
            return VerifyOutcome::Invalid(VerifyError::WrongRegion);
        }
    }

    // 7b. Security-policy epoch: the policy that authorized this challenge
    //     must still be in force.
    if let Some(expected) = ctx.expected_policy_version {
        if ctx.record.policy_version != expected {
            return VerifyOutcome::Invalid(VerifyError::WrongPolicyVersion);
        }
    }

    // 7c. Issuer identity: a verifier that expects a specific
    //     issuer rejects challenges issued by another issuer — or by no
    //     issuer at all (fail closed, like the region expectation).
    if let Some(expected) = ctx.expected_issuer {
        if ctx.record.issuer.as_deref() != Some(expected) {
            return VerifyOutcome::Invalid(VerifyError::WrongIssuer);
        }
    }

    // 2c. IP binding: the challenge was issued to a client IP; a different
    //     submission IP means the token was relayed. Enforced here (not just
    //     at the route layer) so the secure behavior cannot be forgotten.
    //     The stored record is AUTHORITATIVE: an empty binding tag means
    //     binding is disabled (BindingMode::None) and the check is skipped; a
    //     NON-EMPTY tag means the challenge IS bound, so a missing client IP
    //     fails closed (MissingClientIp) instead of silently skipping the
    //     check.
    if !ctx.record.binding_tag.is_empty() {
        let Some(client_ip) = ctx.client_ip else {
            return VerifyOutcome::Invalid(VerifyError::MissingClientIp);
        };
        let expected = match ctx.record.protocol_version {
            1 => hash_ip(client_ip, secret),
            _ => match binding_tag(&ctx.record.nonce, client_ip, secret) {
                Ok(tag) => tag,
                Err(_) => return VerifyOutcome::Invalid(VerifyError::IpMismatch),
            },
        };
        if !ct_eq(ctx.record.binding_tag.as_bytes(), expected.as_bytes()) {
            return VerifyOutcome::Invalid(VerifyError::IpMismatch);
        }
    }

    // 3. Minimum duration — SERVER-MEASURED. The client-reported duration_ms
    //    is forgeable and is deliberately not trusted for enforcement. The
    //    floor is a timing-anomaly heuristic: a fast bot can wait before
    //    submitting, so it only rejects solves that ARRIVE faster than the
    //    theoretical minimum. Records without a high-resolution issuance
    //    timestamp are malformed — there is no client-duration fallback. This
    //    is enforced UNCONDITIONALLY (even when the timing floor is disabled)
    //    to match the PHP verifier exactly.
    if ctx.record.issued_at_ns == 0 {
        return VerifyOutcome::Invalid(VerifyError::MalformedRecord);
    }
    let floor = ctx.min_duration_ms.max(ctx.record.min_duration_ms);
    if floor > 0 {
        if ctx.now_ns >= ctx.record.issued_at_ns {
            // High-resolution path: elapsed time between issuance and receipt,
            // both observed by the server clock. Both `now_ns` and
            // `issued_at_ns` are EPOCH MICROSECONDS (the names keep the `_ns`
            // suffix), so the ms floor is compared in the
            // same unit: ms -> µs (× 1_000).
            let elapsed_us = ctx.now_ns - ctx.record.issued_at_ns;
            if elapsed_us < floor.saturating_mul(1_000) {
                return VerifyOutcome::Invalid(VerifyError::TooFast);
            }
        } else {
            // Issuer host ahead of verifier host: apparent elapsed time is
            // negative. A skew within SKEW_TOLERANCE_US is a clock anomaly we
            // tolerate (skip the floor heuristic — the negative elapsed time
            // carries no timing signal); a larger skew means the clocks are
            // broken and the timing guarantee is void.
            let skew = ctx.record.issued_at_ns - ctx.now_ns;
            if skew > SKEW_TOLERANCE_US {
                return VerifyOutcome::Invalid(VerifyError::TooFast);
            }
        }
    }

    // 4. Optional telemetry scoring. Strict mode also rejects clients that
    //    submit NO telemetry (a custom non-browser solver does not send it)
    //    or an EMPTY telemetry payload (the PHP widget emits `{}` when no
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

    // 5. Re-derive and check leading zero bits.
    let hash = match derive_hash(ctx.record, ctx.counter) {
        Ok(h) => h,
        Err(e) => return VerifyOutcome::Invalid(e),
    };

    // 5b. FINAL re-validation: the expensive derivation may have
    //     taken long enough that the challenge expired DURING it — or the
    //     verifier's current expectations (policy epoch, region, issuer) may
    //     have changed while the hash was computing. Re-check the CURRENT
    //     server time (ctx.now_unix) and the current expectations BEFORE the
    //     outcome is declared valid: a challenge that expired mid-derive is
    //     Expired even though the record is already consumed.
    if let Err(e) = final_revalidate(
        ctx.record,
        ctx.now_unix,
        ctx.expected_region,
        ctx.expected_policy_version,
        ctx.expected_issuer,
    ) {
        return VerifyOutcome::Invalid(e);
    }

    if leading_zero_bits(&hash) >= ctx.record.target_bits {
        // The outcome carries the consumed canonical nonce (jti) so callers
        // can correlate the result without re-decoding the solution.
        VerifyOutcome::Valid {
            nonce: ctx.record.nonce.clone(),
            request_binding: ctx.record.request_binding.clone(),
        }
    } else {
        VerifyOutcome::Invalid(VerifyError::InsufficientWork)
    }
}

/// POST-DERIVE final re-validation: re-check the challenge's
/// validity with the CURRENT server time and the CURRENT verifier
/// expectations, AFTER the (potentially long) proof derivation succeeded but
/// BEFORE the outcome is declared valid.
///
/// A challenge can expire DURING the expensive derivation — the cheap TTL
/// check ran before the hash was computed — and the verifier's current
/// expectations (security-policy epoch, region, issuer) can change while the
/// proof is being derived. This gate is therefore re-run as the LAST step of
/// [`verify_solution`] and of the production verifier (whose final step
/// passes a FRESH clock read — the real race — see `redis_verify`).
///
/// Checks, in order:
/// - `now_unix >= expires_at` → [`VerifyError::Expired`];
/// - expected region mismatch → [`VerifyError::WrongRegion`];
/// - expected policy epoch mismatch → [`VerifyError::WrongPolicyVersion`];
/// - expected issuer mismatch → [`VerifyError::WrongIssuer`].
pub(crate) fn final_revalidate(
    record: &ChallengeRecord,
    now_unix: u64,
    expected_region: Option<&str>,
    expected_policy_version: Option<u32>,
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
    if let Some(expected) = expected_policy_version {
        if record.policy_version != expected {
            return Err(VerifyError::WrongPolicyVersion);
        }
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
pub fn solve_for_test(record: &ChallengeRecord) -> Option<u64> {
    // Capped at the real solver's search space: a counter >= SOLVER_MAX_HASHES
    // is rejected by verify_solution (CounterTooLarge), so the test solver
    // must never produce one. At 20 bits a legit solver finds no counter
    // within the cap with p ≈ 0.85% — callers that need a guaranteed solve
    // should use a lower difficulty.
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
    let result = hasher.finalize();
    result.iter().map(|b| format!("{b:02x}")).collect()
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
/// - Solve completes in >30s with zero mouse/key events (headless solver).
/// - Solve takes >300s total (well beyond the ~30s expected for targetBits=14).
///
/// Soft signals (logged but NOT rejected):
/// - `hardwareConcurrency=0` AND `deviceMemory=0` (likely headless browser).
/// - `plugins.length=0` AND `hardwareConcurrency=0` (likely headless).
pub fn score_telemetry(telemetry: &serde_json::Value, duration_ms: u64) -> bool {
    let wd = telemetry
        .get("wd")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    if wd {
        return true;
    }

    let me = telemetry.get("me").and_then(|v| v.as_u64()).unwrap_or(0);
    let ke = telemetry.get("ke").and_then(|v| v.as_u64()).unwrap_or(0);
    let hc = telemetry.get("hc").and_then(|v| v.as_u64()).unwrap_or(0);
    let dm = telemetry.get("dm").and_then(|v| v.as_u64()).unwrap_or(0);
    let pl = telemetry.get("pl").and_then(|v| v.as_u64()).unwrap_or(0);

    // Hard rejection signals:
    // 1. Solve completes in >30s with zero mouse/key events (headless solver).
    if duration_ms > 30_000 && me == 0 && ke == 0 {
        tracing::warn!(
            duration_ms,
            me,
            ke,
            "KiwiCaptcha: bot suspected — solve took >30s with zero interaction"
        );
        return true;
    }

    // 2. Solve takes >300s total (well beyond expected — a generous bound
    //    that allows for very slow devices).
    if duration_ms > 300_000 {
        tracing::warn!(duration_ms, "KiwiCaptcha: bot suspected — solve took >300s");
        return true;
    }

    // 3. Entropy check: if there are interactions, check for timing variance.
    //    Bots often simulate events with perfectly uniform intervals.
    //
    //    This check is deliberately conservative:
    //    - It only considers *discrete* events (the widget records pointerdown,
    //      non-repeat keydown, wheel, and click — never coalesced mousemove or
    //      OS key auto-repeat), so a uniform interval across 24+ discrete
    //      human events is not something a person can produce.
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

    // Soft signals (logged but NOT rejected):
    if hc == 0 && dm == 0 {
        tracing::info!(
            hc,
            dm,
            "KiwiCaptcha: possible headless client (hc=0, dm=0) — soft signal, not rejected"
        );
    }

    if hc == 0 && pl == 0 {
        tracing::info!(
            hc,
            pl,
            "KiwiCaptcha: possible headless client (hc=0, pl=0) — soft signal, not rejected"
        );
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::challenge::{
        binding_tag, hash_ip, issue_challenge, BindingMode, ChallengeConfig, PoWAlgorithm,
        SignError,
    };

    const NOW_UNIX: u64 = 1_000_000;
    // EPOCH MICROSECONDS (1_700_000_000_000_000 µs ≈ 2023-11-14 UTC) — the
    // unit shared with PHP; field names keep the `_ns` suffix.
    const NOW_NS: u64 = 1_700_000_000_000_000;

    fn make_record(target_bits: u32) -> ChallengeRecord {
        let config = ChallengeConfig {
            secret_key: "test-key-16-bytes!".into(),
            kid: 1,
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
            issue_challenge(&config, "login", "1.2.3.4", NOW_UNIX, NOW_NS, 0, None).unwrap();
        issued.record
    }

    fn make_argon2_record(target_bits: u32, m_kib: u32) -> ChallengeRecord {
        let config = ChallengeConfig {
            secret_key: "test-key-16-bytes!".into(),
            kid: 1,
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
            secret_key: "test-key-16-bytes!",
            secrets_by_kid: None,
            revoked_kids: None,
            counter,
            duration_ms,
            now_unix: NOW_UNIX + 1,
            now_ns: NOW_NS + 5_000_000, // 5 s after issuance
            min_duration_ms: 0,
            expected_scope: None,
            expected_region: None,
            expected_issuer: None,
            expected_policy_version: None,
            client_ip: Some("1.2.3.4"),
            telemetry: None,
            enforce_telemetry: false,
            max_attempts: 0,
            accept_legacy_v1: false,
        };
        verify_solution(&mut ctx)
    }

    /// Re-sign a mutated Argon2id record so its parameters are covered by a
    /// VALID v2 signature — the ceiling checks must fire on
    /// properly signed records, not on signature failures.
    fn resign_v2(record: &mut ChallengeRecord, secret: &str) {
        let canonical = super::super::challenge::canonical_signing_input_v2(record);
        let sig = super::super::challenge::sign_canonical_v2(&canonical, secret).unwrap();
        let challenge = format!("{}.{}", B64.encode(canonical.as_bytes()), sig);
        record.challenge = challenge.clone();
        record.prefix = format!("{challenge}|{}|", record.salt);
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
            secret_key: "test-key-16-bytes!".into(),
            kid: 1,
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
                secret_key: "test-key-16-bytes!".into(),
                kid: 1,
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
            secret_key: "test-key-16-bytes!".into(),
            kid: 1,
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
        // The verifier's validate_record rejects lifetimes > MAX_TTL_SECS
        // (300) and TTL 0 is meaningless — issuance must refuse to mint a
        // record it would later declare malformed.
        let base = ChallengeConfig {
            secret_key: "test-key-16-bytes!".into(),
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
        // The verifier declares t > MAX_ARGON_T (6) malformed — issuance
        // must refuse it (PHP Config already does; Rust must match).
        let config = ChallengeConfig {
            secret_key: "test-key-16-bytes!".into(),
            kid: 1,
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
            secret_key: "test-key-16-bytes!".into(),
            kid: 1,
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
        // The verifier already rejects records above SOLVER_MAX_ARGON2_M_KIB
        // (64 MiB — the wasm heap ceiling); issuance must never mint one.
        let config = ChallengeConfig {
            secret_key: "test-key-16-bytes!".into(),
            kid: 1,
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
        // argon2_target_bits must be 1..=SOLVER_MAX_ARGON2_TARGET_BITS: 0
        // would silently clamp to a degenerate difficulty and 11 exceeds the
        // solver ceiling — both must fail at issuance.
        for bits in [0u32, 11] {
            let config = ChallengeConfig {
                secret_key: "test-key-16-bytes!".into(),
                kid: 1,
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
            secret_key: "test-key-16-bytes!".into(),
            kid: 1,
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
    fn protocol_version_three_is_malformed() {
        // Only protocol versions 1 (legacy migration) and 2 (current) exist
        // in the wire contract — anything else is a corrupt/foreign record.
        let mut record = make_record(8);
        record.protocol_version = 3;
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
        // Find a valid counter, then use a different one.
        let valid = solve_for_test(&record).unwrap();
        let bad = if valid == 0 { 1 } else { 0 };
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
            secret_key: "test-key-16-bytes!",
            secrets_by_kid: None,
            revoked_kids: None,
            counter,
            duration_ms: 5000,
            now_unix: NOW_UNIX + 121, // past TTL
            now_ns: NOW_NS,
            min_duration_ms: 0,
            expected_scope: None,
            client_ip: Some("1.2.3.4"),
            expected_region: None,
            expected_issuer: None,
            expected_policy_version: None,
            telemetry: None,
            enforce_telemetry: false,
            max_attempts: 0,
            accept_legacy_v1: false,
        };
        assert_eq!(
            verify_solution(&mut ctx),
            VerifyOutcome::Invalid(VerifyError::Expired)
        );
    }

    #[test]
    fn too_fast_solution_is_rejected_server_side() {
        // The floor is enforced with the SERVER clock (now_ns - issued_at_ns),
        // NOT the forgeable client duration_ms. Here the client CLAIMS a long
        // duration but the server measures a sub-floor elapsed time.
        // Deterministic setup: an 8-bit record (solve guaranteed below the
        // 5M counter cap) with an EXPLICIT 60 s ctx floor.
        let mut record = make_record(8);
        let counter = solve_for_test(&record).unwrap();
        let mut ctx = VerifyContext {
            record: &mut record,
            secret_key: "test-key-16-bytes!",
            secrets_by_kid: None,
            revoked_kids: None,
            counter,
            duration_ms: 60_000, // client forges a 60 s solve — must NOT help
            now_unix: NOW_UNIX + 1,
            now_ns: NOW_NS + 1_000_000, // 1 s elapsed < 60 s floor
            min_duration_ms: 60_000,
            expected_scope: None,
            client_ip: Some("1.2.3.4"),
            expected_region: None,
            expected_issuer: None,
            expected_policy_version: None,
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
            secret_key: "test-key-16-bytes!",
            secrets_by_kid: None,
            revoked_kids: None,
            counter,
            duration_ms: 5000, // forged
            now_unix: NOW_UNIX,
            now_ns: NOW_NS, // same µs as issuance
            min_duration_ms: 0,
            expected_scope: None,
            client_ip: Some("1.2.3.4"),
            expected_region: None,
            expected_issuer: None,
            expected_policy_version: None,
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
            secret_key: "WRONG-KEY-16-bytes!",
            secrets_by_kid: None,
            revoked_kids: None,
            counter,
            duration_ms: 5000,
            now_unix: NOW_UNIX + 1,
            now_ns: NOW_NS + 5_000_000,
            min_duration_ms: 0,
            expected_scope: None,
            client_ip: Some("1.2.3.4"),
            expected_region: None,
            expected_issuer: None,
            expected_policy_version: None,
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
        // A secret below the 16-byte minimum can never have signed a valid
        // challenge — verification must fail closed (BadSignature), and the
        // attempt is still accounted on the record.
        let mut record = make_record(8);
        let counter = solve_for_test(&record).unwrap();
        let mut ctx = VerifyContext {
            record: &mut record,
            secret_key: "x", // 1 byte — below the hard minimum
            secrets_by_kid: None,
            revoked_kids: None,
            counter,
            duration_ms: 5000,
            now_unix: NOW_UNIX + 1,
            now_ns: NOW_NS + 5_000_000,
            min_duration_ms: 0,
            expected_scope: None,
            client_ip: Some("1.2.3.4"),
            expected_region: None,
            expected_issuer: None,
            expected_policy_version: None,
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
        // The review's point 6: IP binding must be enforced by the core
        // verifier itself, not left to the route layer.
        let mut record = make_record(8);
        let counter = solve_for_test(&record).unwrap();
        let mut ctx = VerifyContext {
            record: &mut record,
            secret_key: "test-key-16-bytes!",
            secrets_by_kid: None,
            revoked_kids: None,
            counter,
            duration_ms: 5000,
            now_unix: NOW_UNIX + 1,
            now_ns: NOW_NS + 5_000_000,
            min_duration_ms: 0,
            expected_scope: None,
            client_ip: Some("9.9.9.9"), // different from issuance IP 1.2.3.4
            expected_region: None,
            expected_issuer: None,
            expected_policy_version: None,
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

    #[test]
    fn bound_record_without_client_ip_fails_closed() {
        // A non-empty binding tag means the challenge IS bound — omitting
        // the client IP must fail with MissingClientIp, not silently skip
        // the check (the caller must provide the IP it passed to issuance).
        let mut record = make_record(8);
        let counter = solve_for_test(&record).unwrap();
        let mut ctx = VerifyContext {
            record: &mut record,
            secret_key: "test-key-16-bytes!",
            secrets_by_kid: None,
            revoked_kids: None,
            counter,
            duration_ms: 5000,
            now_unix: NOW_UNIX + 1,
            now_ns: NOW_NS + 5_000_000,
            min_duration_ms: 0,
            expected_scope: None,
            client_ip: None,
            expected_region: None,
            expected_issuer: None,
            expected_policy_version: None,
            telemetry: None,
            enforce_telemetry: false,
            max_attempts: 0,
            accept_legacy_v1: false,
        };
        assert_eq!(
            verify_solution(&mut ctx),
            VerifyOutcome::Invalid(VerifyError::MissingClientIp)
        );

        // A record with an EMPTY binding tag (BindingMode::None) still
        // verifies without an IP — binding is genuinely disabled. Issued
        // properly so the v2 signature (which covers the tag) stays valid.
        let config = ChallengeConfig {
            secret_key: "test-key-16-bytes!".into(),
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
            secret_key: "test-key-16-bytes!",
            secrets_by_kid: None,
            revoked_kids: None,
            counter: counter2,
            duration_ms: 5000,
            now_unix: NOW_UNIX + 1,
            now_ns: NOW_NS + 5_000_000,
            min_duration_ms: 0,
            expected_scope: None,
            client_ip: Some("1.2.3.4"),

            expected_region: None,
            expected_issuer: None,
            expected_policy_version: None,
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
        // First call (even a WRONG counter) consumes the single attempt.
        let wrong = if counter == 0 { 1 } else { 0 };
        let mut ctx = VerifyContext {
            record: &mut record,
            secret_key: "test-key-16-bytes!",
            secrets_by_kid: None,
            revoked_kids: None,
            counter: wrong,
            duration_ms: 5000,
            now_unix: NOW_UNIX + 1,
            now_ns: NOW_NS + 5_000_000,
            min_duration_ms: 0,
            expected_scope: None,
            client_ip: Some("1.2.3.4"),
            expected_region: None,
            expected_issuer: None,
            expected_policy_version: None,
            telemetry: None,
            enforce_telemetry: false,
            max_attempts: 1,
            accept_legacy_v1: false,
        };
        assert_eq!(
            verify_solution(&mut ctx),
            VerifyOutcome::Invalid(VerifyError::InsufficientWork)
        );
        // Second call — the correct counter, but the attempt budget is gone.
        let mut ctx2 = VerifyContext {
            record: &mut record,
            secret_key: "test-key-16-bytes!",
            secrets_by_kid: None,
            revoked_kids: None,
            counter,
            duration_ms: 5000,
            now_unix: NOW_UNIX + 1,
            now_ns: NOW_NS + 5_000_000,
            min_duration_ms: 0,
            expected_scope: None,
            client_ip: Some("1.2.3.4"),
            expected_region: None,
            expected_issuer: None,
            expected_policy_version: None,
            telemetry: None,
            enforce_telemetry: false,
            max_attempts: 1,
            accept_legacy_v1: false,
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
            secret_key: "test-key-16-bytes!",
            secrets_by_kid: None,
            revoked_kids: None,
            counter: wrong,
            duration_ms: 5000,
            now_unix: NOW_UNIX + 1,
            now_ns: NOW_NS + 5_000_000,
            min_duration_ms: 0,
            expected_scope: None,
            client_ip: Some("1.2.3.4"),
            expected_region: None,
            expected_issuer: None,
            expected_policy_version: None,
            telemetry: None,
            enforce_telemetry: false,
            max_attempts: 3,
            accept_legacy_v1: false,
        };
        verify_solution(&mut ctx); // wrong counter
        let attempts = record.attempts_used;
        assert_eq!(attempts, 1);
        let mut ctx2 = VerifyContext {
            record: &mut record,
            secret_key: "test-key-16-bytes!",
            secrets_by_kid: None,
            revoked_kids: None,
            counter,
            duration_ms: 5000,
            now_unix: NOW_UNIX + 1,
            now_ns: NOW_NS + 5_000_000,
            min_duration_ms: 0,
            expected_scope: None,
            client_ip: Some("1.2.3.4"),
            expected_region: None,
            expected_issuer: None,
            expected_policy_version: None,
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
            secret_key: "test-key-16-bytes!",
            secrets_by_kid: None,
            revoked_kids: None,
            counter,
            duration_ms: 5000,
            now_unix: NOW_UNIX + 1,
            now_ns: NOW_NS + 5_000_000,
            min_duration_ms: 0,
            expected_scope: None,
            client_ip: Some("1.2.3.4"),
            expected_region: None,
            expected_issuer: None,
            expected_policy_version: None,
            telemetry: Some(&json!({"wd": true})),
            enforce_telemetry: true,
            max_attempts: 0,
            accept_legacy_v1: false,
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
            secret_key: "test-key-16-bytes!",
            secrets_by_kid: None,
            revoked_kids: None,
            counter,
            duration_ms: 5000,
            now_unix: NOW_UNIX + 1,
            now_ns: NOW_NS + 5_000_000,
            min_duration_ms: 0,
            expected_scope: None,
            client_ip: Some("1.2.3.4"),
            expected_region: None,
            expected_issuer: None,
            expected_policy_version: None,
            telemetry: None,
            enforce_telemetry: true,
            max_attempts: 0,
            accept_legacy_v1: false,
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
            secret_key: "test-key-16-bytes!",
            secrets_by_kid: None,
            revoked_kids: None,
            counter,
            duration_ms: 5000,
            now_unix: NOW_UNIX + 1,
            now_ns: NOW_NS + 5_000_000,
            min_duration_ms: 0,
            expected_scope: None,
            client_ip: Some("1.2.3.4"),
            expected_region: None,
            expected_issuer: None,
            expected_policy_version: None,
            telemetry: Some(&json!({})),
            enforce_telemetry: true,
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
            record: &mut record,
            secret_key: "test-key-16-bytes!",
            secrets_by_kid: None,
            revoked_kids: None,
            counter,
            duration_ms: 5000,
            now_unix: NOW_UNIX + 1,
            now_ns: NOW_NS + 5_000_000,
            min_duration_ms: 0,
            expected_scope: None,
            client_ip: Some("1.2.3.4"),
            expected_region: None,
            expected_issuer: None,
            expected_policy_version: None,
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
            secret_key: "test-key-16-bytes!",
            secrets_by_kid: None,
            revoked_kids: None,
            counter,
            duration_ms: 5000,
            now_unix: NOW_UNIX + 1,
            now_ns: NOW_NS + 5_000_000,
            min_duration_ms: 0,
            expected_scope: None,
            client_ip: Some("1.2.3.4"),
            expected_region: None,
            expected_issuer: None,
            expected_policy_version: None,
            telemetry: Some(&json!(null)),
            enforce_telemetry: true,
            max_attempts: 0,
            accept_legacy_v1: false,
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
            secret_key: "test-key-16-bytes!",
            secrets_by_kid: None,
            revoked_kids: None,
            counter,
            duration_ms: 5000,
            now_unix: NOW_UNIX + 1,
            now_ns: NOW_NS + 5_000_000,
            min_duration_ms: 0,
            expected_scope: None,
            client_ip: Some("1.2.3.4"),
            expected_region: None,
            expected_issuer: None,
            expected_policy_version: None,
            telemetry: Some(&json!({
                "wd": false, "hc": 8, "dm": 8, "me": 5, "ke": 2, "et": []
            })),
            enforce_telemetry: true,
            max_attempts: 0,
            accept_legacy_v1: false,
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
            secret_key: "test-key-16-bytes!",
            secrets_by_kid: None,
            revoked_kids: None,
            counter,
            duration_ms: 5000,
            now_unix: NOW_UNIX + 1,
            now_ns: NOW_NS + 5_000_000,
            min_duration_ms: 0,
            expected_scope: None,
            client_ip: Some("1.2.3.4"),
            expected_region: None,
            expected_issuer: None,
            expected_policy_version: None,
            telemetry: Some(&json!({"wd": true})),
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
    fn records_without_issued_at_ns_are_malformed() {
        // Records without a high-resolution issuance timestamp (issued_at_ns
        // == 0) are rejected as MalformedRecord — there is no client-duration
        // fallback: the floor can only be enforced with a
        // server-measured elapsed time.
        let mut record = make_record(8);
        record.issued_at_ns = 0;
        let counter = solve_for_test(&record).unwrap();
        let mut ctx = VerifyContext {
            record: &mut record,
            secret_key: "test-key-16-bytes!",
            secrets_by_kid: None,
            revoked_kids: None,
            counter,
            duration_ms: 60_000, // a forged long client duration must NOT resurrect the legacy path
            now_unix: NOW_UNIX + 1,
            now_ns: NOW_NS + 10_000_000,
            min_duration_ms: 0,
            expected_scope: None,
            client_ip: Some("1.2.3.4"),
            expected_region: None,
            expected_issuer: None,
            expected_policy_version: None,
            telemetry: None,
            enforce_telemetry: false,
            max_attempts: 0,
            accept_legacy_v1: false,
        };
        assert_eq!(
            verify_solution(&mut ctx),
            VerifyOutcome::Invalid(VerifyError::MalformedRecord)
        );
    }

    #[test]
    fn clock_skew_within_tolerance_skips_the_floor() {
        // Issuer host ahead of verifier host by 1 s (within the 5 s
        // SKEW_TOLERANCE_US): the floor heuristic is skipped and a correct
        // PoW passes.
        let mut record = make_record(8);
        let counter = solve_for_test(&record).unwrap();
        assert!(record.min_duration_ms > 0, "record floor must be positive");
        let mut ctx = VerifyContext {
            record: &mut record,
            secret_key: "test-key-16-bytes!",
            secrets_by_kid: None,
            revoked_kids: None,
            counter,
            duration_ms: 5000,
            now_unix: NOW_UNIX + 1,
            now_ns: NOW_NS.saturating_sub(1_000_000), // 1 s skew, issuer ahead
            min_duration_ms: 0,
            expected_scope: None,
            client_ip: Some("1.2.3.4"),
            expected_region: None,
            expected_issuer: None,
            expected_policy_version: None,
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
    fn clock_skew_beyond_tolerance_is_rejected() {
        // Issuer host ahead by 6 s (> SKEW_TOLERANCE_US): clocks are broken —
        // the timing guarantee is void and the solution is rejected.
        let mut record = make_record(8);
        let counter = solve_for_test(&record).unwrap();
        let mut ctx = VerifyContext {
            record: &mut record,
            secret_key: "test-key-16-bytes!",
            secrets_by_kid: None,
            revoked_kids: None,
            counter,
            duration_ms: 5000,
            now_unix: NOW_UNIX + 1,
            now_ns: NOW_NS.saturating_sub(6_000_000), // 6 s skew
            min_duration_ms: 0,
            expected_scope: None,
            client_ip: Some("1.2.3.4"),
            expected_region: None,
            expected_issuer: None,
            expected_policy_version: None,
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

        // Zero interaction long solve rejection
        let t3 = json!({"wd": false, "me": 0, "ke": 0});
        assert!(score_telemetry(&t3, 31_000));

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
    fn telemetry_rejects_webdriver_combined_with_normal_timing() {
        // A bot that fakes human timing but leaves webdriver=true.
        use serde_json::json;
        let jittered: Vec<u64> = (0..30).map(|i| i * 97 + (i * 7 % 13)).collect();
        let t = json!({ "wd": true, "me": 20, "ke": 0, "et": jittered });
        assert!(score_telemetry(&t, 5000));
    }

    #[test]
    fn telemetry_rejects_long_headless_solve_without_interaction() {
        use serde_json::json;
        let t = json!({ "wd": false, "me": 0, "ke": 0, "et": [] });
        assert!(score_telemetry(&t, 31_000));
        assert!(score_telemetry(&t, 301_000));
        // A normal-duration solve with no interaction is fine (users may not
        // touch the page while it auto-solves).
        assert!(!score_telemetry(&t, 4000));
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
        // The solver caps at MAX_SHA_HASHES (5M); verify_solution must reject
        // larger counters deterministically (a huge counter is not a
        // legitimate solution and must never reach hash derivation).
        let mut record = make_record(4);
        let huge = crate::challenge::SOLVER_MAX_HASHES + 1;
        let outcome = verify(&mut record, huge, 5000);
        assert_eq!(
            outcome,
            VerifyOutcome::Invalid(VerifyError::CounterTooLarge)
        );

        // EXACTLY at the cap is also rejected: the official decoder rejects
        // counter >= 5,000,000 (the JS solver searches 0..4,999,999), so the
        // direct verifier must match (protocol parity).
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
            secret_key: "test-key-16-bytes!",
            secrets_by_kid: None,
            revoked_kids: None,
            counter,
            duration_ms: 5000,
            now_unix: 1_000_001,
            now_ns: NOW_NS + 5_000_000,
            min_duration_ms: 0,
            expected_scope: Some("signup"),
            client_ip: Some("1.2.3.4"),
            expected_region: None,
            expected_issuer: None,
            expected_policy_version: None,
            telemetry: None,
            enforce_telemetry: false,
            max_attempts: 0,
            accept_legacy_v1: false,
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
            secret_key: "test-key-16-bytes!",
            secrets_by_kid: None,
            revoked_kids: None,
            counter,
            duration_ms: 5000,
            now_unix: expires_at, // exactly at expiry
            now_ns: NOW_NS + 5_000_000,
            min_duration_ms: 0,
            expected_scope: None,
            client_ip: Some("1.2.3.4"),
            expected_region: None,
            expected_issuer: None,
            expected_policy_version: None,
            telemetry: None,
            enforce_telemetry: false,
            max_attempts: 0,
            accept_legacy_v1: false,
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
            secret_key: "test-key-16-bytes!",
            secrets_by_kid: None,
            revoked_kids: None,
            counter,
            duration_ms: 5000,
            now_unix: expires_at - 1,
            now_ns: NOW_NS + 5_000_000,
            min_duration_ms: 0,
            expected_scope: None,
            client_ip: Some("1.2.3.4"),
            expected_region: None,
            expected_issuer: None,
            expected_policy_version: None,
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

        // Deterministic core assertion: the two algorithms derive DIFFERENT
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
        // absurd-params record: MalformedRecord must fire before hashing.
        let sane = make_argon2_record(4, 128);
        let counter = solve_for_test(&sane).unwrap();
        let mut absurd = sane.clone();
        absurd.m_kib = crate::challenge::SOLVER_MAX_ARGON2_M_KIB + 1;
        assert_eq!(
            verify(&mut absurd, counter, 5000),
            VerifyOutcome::Invalid(VerifyError::MalformedRecord)
        );
    }

    #[test]
    fn verify_duration_floor_is_per_challenge() {
        // The record's own floor is authoritative when ctx.min_duration_ms is 0.
        // Deterministic setup: 8-bit record (solve guaranteed below the 5M
        // solver cap); its issued SHA-256 floor is max(ceil(256/5e9*1000), 5)
        // = 5 ms.
        let mut record = make_record(8);
        let counter = solve_for_test(&record).unwrap();
        assert_eq!(record.min_duration_ms, 5);
        let mut ctx = VerifyContext {
            record: &mut record,
            secret_key: "test-key-16-bytes!",
            secrets_by_kid: None,
            revoked_kids: None,
            counter,
            duration_ms: 5000,
            now_unix: NOW_UNIX + 1,
            now_ns: NOW_NS + 6_000, // 6 ms elapsed > 5 ms floor (µs)
            min_duration_ms: 0,
            expected_scope: None,
            client_ip: Some("1.2.3.4"),
            expected_region: None,
            expected_issuer: None,
            expected_policy_version: None,
            telemetry: None,
            enforce_telemetry: false,
            max_attempts: 0,
            accept_legacy_v1: false,
        };
        assert!(matches!(
            verify_solution(&mut ctx),
            VerifyOutcome::Valid { .. }
        ));
        let mut ctx_fast = VerifyContext {
            record: &mut record,
            secret_key: "test-key-16-bytes!",
            secrets_by_kid: None,
            revoked_kids: None,
            counter,
            duration_ms: 60_000, // forged long client duration must NOT help
            now_unix: NOW_UNIX + 1,
            now_ns: NOW_NS + 4_999, // 4.999 ms elapsed < 5 ms floor (µs)
            min_duration_ms: 0,
            expected_scope: None,
            client_ip: Some("1.2.3.4"),
            expected_region: None,
            expected_issuer: None,
            expected_policy_version: None,
            telemetry: None,
            enforce_telemetry: false,
            max_attempts: 0,
            accept_legacy_v1: false,
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
        // search is capped at SOLVER_MAX_HASHES (the real solver contract):
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
        bad_ttl.expires_at = bad_ttl.issued_at + 301; // > MAX_TTL_SECS
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

        let mut argon_bad_t = make_argon2_record(4, 128);
        argon_bad_t.t = 32; // above MAX_ARGON_TIME (16)
        assert_eq!(
            validate_record(&argon_bad_t),
            Err(VerifyError::MalformedRecord)
        );

        let mut argon_bad_m = make_argon2_record(4, 128);
        argon_bad_m.m_kib = 65_537; // above the 64 MiB ceiling
        assert_eq!(
            validate_record(&argon_bad_m),
            Err(VerifyError::MalformedRecord)
        );

        let mut argon_low_m = make_argon2_record(4, 128);
        argon_low_m.m_kib = 1; // below the 8 KiB hard floor
        assert_eq!(
            validate_record(&argon_low_m),
            Err(VerifyError::MalformedRecord)
        );

        let mut argon_low_t = make_argon2_record(4, 128);
        argon_low_t.t = 2; // below MIN_ARGON_TIME (3)
        assert_eq!(
            validate_record(&argon_low_t),
            Err(VerifyError::MalformedRecord)
        );

        let mut argon_bad_p = make_argon2_record(4, 128);
        argon_bad_p.p = 5; // above MAX_PARALLELISM (4)
        assert_eq!(
            validate_record(&argon_bad_p),
            Err(VerifyError::MalformedRecord)
        );

        // A well-formed record passes.
        assert_eq!(validate_record(&make_record(8)), Ok(()));
        assert_eq!(validate_record(&make_argon2_record(4, 128)), Ok(()));
    }

    #[test]
    fn sha_zero_target_bits_rejected_at_issuance() {
        let config = ChallengeConfig {
            secret_key: "0123456789abcdef0123456789abcdef".into(),
            kid: 1,
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
                secret_key: "test-key-16-bytes!".into(),
                kid: 1,
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
            secret_key: "test-key-16-bytes!",
            secrets_by_kid: None,
            revoked_kids: None,
            counter,
            duration_ms: 5000,
            now_unix: NOW_UNIX + 1,
            now_ns: NOW_NS + 5_000_000,
            min_duration_ms: 0,
            expected_scope: None,
            client_ip: Some("1.2.3.4"),
            expected_region: None,
            expected_issuer: None,
            expected_policy_version: None,
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
            secret_key: "test-key-16-bytes!",
            secrets_by_kid: None,
            revoked_kids: None,
            counter,
            duration_ms: 5000,
            now_unix: NOW_UNIX + 1,
            now_ns: NOW_NS + 5_000_000,
            min_duration_ms: 0,
            expected_scope: None,
            client_ip: Some("9.9.9.9"), // different from issuance IP 1.2.3.4
            expected_region: None,
            expected_issuer: None,
            expected_policy_version: None,
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
        resign_v2(&mut record, "test-key-16-bytes!"); // region is signed into the canonical payload
        let counter = solve_for_test(&record).unwrap();
        let mut ctx = VerifyContext {
            record: &mut record,
            secret_key: "test-key-16-bytes!",
            secrets_by_kid: None,
            revoked_kids: None,
            counter,
            duration_ms: 5000,
            now_unix: NOW_UNIX + 1,
            now_ns: NOW_NS + 5_000_000,
            min_duration_ms: 0,
            expected_scope: None,
            expected_region: Some("us"),
            expected_issuer: None,
            expected_policy_version: None,
            client_ip: Some("1.2.3.4"),
            telemetry: None,
            enforce_telemetry: false,
            max_attempts: 0,
            accept_legacy_v1: false,
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
            secret_key: "test-key-16-bytes!",
            secrets_by_kid: None,
            revoked_kids: None,
            counter,
            duration_ms: 5000,
            now_unix: NOW_UNIX + 1,
            now_ns: NOW_NS + 5_000_000,
            min_duration_ms: 0,
            expected_scope: None,
            expected_region: Some("us"),
            expected_issuer: None,
            expected_policy_version: None,
            client_ip: Some("1.2.3.4"),
            telemetry: None,
            enforce_telemetry: false,
            max_attempts: 0,
            accept_legacy_v1: false,
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
        resign_v2(&mut record, "test-key-16-bytes!"); // region is signed into the canonical payload
        let counter = solve_for_test(&record).unwrap();

        let mut ctx_match = VerifyContext {
            record: &mut record,
            secret_key: "test-key-16-bytes!",
            secrets_by_kid: None,
            revoked_kids: None,
            counter,
            duration_ms: 5000,
            now_unix: NOW_UNIX + 1,
            now_ns: NOW_NS + 5_000_000,
            min_duration_ms: 0,
            expected_scope: None,
            expected_region: Some("us"),
            expected_issuer: None,
            expected_policy_version: None,
            client_ip: Some("1.2.3.4"),
            telemetry: None,
            enforce_telemetry: false,
            max_attempts: 0,
            accept_legacy_v1: false,
        };
        assert!(matches!(
            verify_solution(&mut ctx_match),
            VerifyOutcome::Valid { .. }
        ));

        // No expected region → the record's region is ignored entirely.
        let mut ctx_none = VerifyContext {
            record: &mut record,
            secret_key: "test-key-16-bytes!",
            secrets_by_kid: None,
            revoked_kids: None,
            counter,
            duration_ms: 5000,
            now_unix: NOW_UNIX + 1,
            now_ns: NOW_NS + 5_000_000,
            min_duration_ms: 0,
            expected_scope: None,
            expected_region: None,
            expected_issuer: None,
            expected_policy_version: None,
            client_ip: Some("1.2.3.4"),
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
        resign_v2(&mut record, "test-key-16-bytes!"); // issuer is signed into the v2 canonical payload
        let counter = solve_for_test(&record).unwrap();
        let mut ctx = VerifyContext {
            record: &mut record,
            secret_key: "test-key-16-bytes!",
            secrets_by_kid: None,
            revoked_kids: None,
            counter,
            duration_ms: 5000,
            now_unix: NOW_UNIX + 1,
            now_ns: NOW_NS + 5_000_000,
            min_duration_ms: 0,
            expected_scope: None,
            expected_region: None,
            expected_issuer: Some("auth-gw-us"),
            expected_policy_version: None,
            client_ip: Some("1.2.3.4"),
            telemetry: None,
            enforce_telemetry: false,
            max_attempts: 0,
            accept_legacy_v1: false,
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
            secret_key: "test-key-16-bytes!",
            secrets_by_kid: None,
            revoked_kids: None,
            counter,
            duration_ms: 5000,
            now_unix: NOW_UNIX + 1,
            now_ns: NOW_NS + 5_000_000,
            min_duration_ms: 0,
            expected_scope: None,
            expected_region: None,
            expected_issuer: Some("auth-gw"),
            expected_policy_version: None,
            client_ip: Some("1.2.3.4"),
            telemetry: None,
            enforce_telemetry: false,
            max_attempts: 0,
            accept_legacy_v1: false,
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
        resign_v2(&mut record, "test-key-16-bytes!"); // issuer is signed into the v2 canonical payload
        let counter = solve_for_test(&record).unwrap();

        let mut ctx_match = VerifyContext {
            record: &mut record,
            secret_key: "test-key-16-bytes!",
            secrets_by_kid: None,
            revoked_kids: None,
            counter,
            duration_ms: 5000,
            now_unix: NOW_UNIX + 1,
            now_ns: NOW_NS + 5_000_000,
            min_duration_ms: 0,
            expected_scope: None,
            expected_region: None,
            expected_issuer: Some("auth-gw"),
            expected_policy_version: None,
            client_ip: Some("1.2.3.4"),
            telemetry: None,
            enforce_telemetry: false,
            max_attempts: 0,
            accept_legacy_v1: false,
        };
        assert!(matches!(
            verify_solution(&mut ctx_match),
            VerifyOutcome::Valid { .. }
        ));

        // No expected issuer → the record's issuer is ignored entirely.
        let mut ctx_none = VerifyContext {
            record: &mut record,
            secret_key: "test-key-16-bytes!",
            secrets_by_kid: None,
            revoked_kids: None,
            counter,
            duration_ms: 5000,
            now_unix: NOW_UNIX + 1,
            now_ns: NOW_NS + 5_000_000,
            min_duration_ms: 0,
            expected_scope: None,
            expected_region: None,
            expected_issuer: None,
            expected_policy_version: None,
            client_ip: Some("1.2.3.4"),
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

    #[test]
    fn v2_fixture_with_issuer_set_verifies() {
        // The issuer is the field before the FINAL kid: a
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
        };
        issue_challenge(&config, "login", "1.2.3.4", NOW_UNIX, NOW_NS, 0, None)
            .unwrap()
            .record
    }

    #[test]
    fn kid_selects_the_secret_for_signature_and_binding() {
        // With `secrets_by_kid` configured, the record's kid
        // selects the signing secret — a challenge issued under kid 2 with
        // secret B verifies ONLY against B, never against the other keys.
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
            secret_key: "WRONG-KEY-16-bytes!",
            secrets_by_kid: Some(&secrets),
            revoked_kids: None,
            counter,
            duration_ms: 5000,
            now_unix: NOW_UNIX + 1,
            now_ns: NOW_NS + 5_000_000,
            min_duration_ms: 0,
            expected_scope: None,
            expected_region: None,
            expected_issuer: None,
            expected_policy_version: None,
            client_ip: Some("1.2.3.4"),
            telemetry: None,
            enforce_telemetry: false,
            max_attempts: 0,
            accept_legacy_v1: false,
        };
        assert!(
            matches!(verify_solution(&mut ctx), VerifyOutcome::Valid { .. }),
            "the kid-selected secret must verify the signature AND the binding tag"
        );

        // The same kid with a DIFFERENT secret → BadSignature (the secret
        // selection is real, not cosmetic).
        let mut wrong: HashMap<u32, String> = HashMap::new();
        wrong.insert(2, "WRONG-KEY-16-bytes!".to_string());
        let mut ctx_wrong = VerifyContext {
            record: &mut record,
            secret_key: "WRONG-KEY-16-bytes!",
            secrets_by_kid: Some(&wrong),
            revoked_kids: None,
            counter,
            duration_ms: 5000,
            now_unix: NOW_UNIX + 1,
            now_ns: NOW_NS + 5_000_000,
            min_duration_ms: 0,
            expected_scope: None,
            expected_region: None,
            expected_issuer: None,
            expected_policy_version: None,
            client_ip: Some("1.2.3.4"),
            telemetry: None,
            enforce_telemetry: false,
            max_attempts: 0,
            accept_legacy_v1: false,
        };
        assert_eq!(
            verify_solution(&mut ctx_wrong),
            VerifyOutcome::Invalid(VerifyError::BadSignature)
        );

        // No map → the single secret_key path applies unconditionally.
        let mut ctx_plain = VerifyContext {
            record: &mut record,
            secret_key: key_b,
            secrets_by_kid: None,
            revoked_kids: None,
            counter,
            duration_ms: 5000,
            now_unix: NOW_UNIX + 1,
            now_ns: NOW_NS + 5_000_000,
            min_duration_ms: 0,
            expected_scope: None,
            expected_region: None,
            expected_issuer: None,
            expected_policy_version: None,
            client_ip: Some("1.2.3.4"),
            telemetry: None,
            enforce_telemetry: false,
            max_attempts: 0,
            accept_legacy_v1: false,
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
        // correct signature for a DIFFERENT kid can never rescue it).
        let key_a = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let mut record = make_record_with_kid(8, 1, key_a);
        let counter = solve_for_test(&record).unwrap();

        // The map holds ONLY kid 2 — kid 1 is unknown to this verifier.
        let mut secrets: HashMap<u32, String> = HashMap::new();
        secrets.insert(2, "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB".to_string());
        let mut ctx = VerifyContext {
            record: &mut record,
            secret_key: key_a, // the correct key — must NOT rescue the record
            secrets_by_kid: Some(&secrets),
            revoked_kids: None,
            counter,
            duration_ms: 5000,
            now_unix: NOW_UNIX + 1,
            now_ns: NOW_NS + 5_000_000,
            min_duration_ms: 0,
            expected_scope: None,
            expected_region: None,
            expected_issuer: None,
            expected_policy_version: None,
            client_ip: Some("1.2.3.4"),
            telemetry: None,
            enforce_telemetry: false,
            max_attempts: 0,
            accept_legacy_v1: false,
        };
        assert_eq!(
            verify_solution(&mut ctx),
            VerifyOutcome::Invalid(VerifyError::UnknownKid)
        );
        // An EMPTY map rejects every kid (max configured = 0).
        let empty: HashMap<u32, String> = HashMap::new();
        let mut ctx_empty = VerifyContext {
            record: &mut record,
            secret_key: key_a,
            secrets_by_kid: Some(&empty),
            revoked_kids: None,
            counter,
            duration_ms: 5000,
            now_unix: NOW_UNIX + 1,
            now_ns: NOW_NS + 5_000_000,
            min_duration_ms: 0,
            expected_scope: None,
            expected_region: None,
            expected_issuer: None,
            expected_policy_version: None,
            client_ip: Some("1.2.3.4"),
            telemetry: None,
            enforce_telemetry: false,
            max_attempts: 0,
            accept_legacy_v1: false,
        };
        assert_eq!(
            verify_solution(&mut ctx_empty),
            VerifyOutcome::Invalid(VerifyError::UnknownKid)
        );
    }

    #[test]
    fn future_kid_is_rejected_by_the_forward_guard() {
        // The forward/rollback guard: a record keyed with a kid NEWER
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
            secrets_by_kid: Some(&secrets),
            revoked_kids: None,
            counter,
            duration_ms: 5000,
            now_unix: NOW_UNIX + 1,
            now_ns: NOW_NS + 5_000_000,
            min_duration_ms: 0,
            expected_scope: None,
            expected_region: None,
            expected_issuer: None,
            expected_policy_version: None,
            client_ip: Some("1.2.3.4"),
            telemetry: None,
            enforce_telemetry: false,
            max_attempts: 0,
            accept_legacy_v1: false,
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
            secrets_by_kid: Some(&secrets),
            revoked_kids: None,
            counter: counter2,
            duration_ms: 5000,
            now_unix: NOW_UNIX + 1,
            now_ns: NOW_NS + 5_000_000,
            min_duration_ms: 0,
            expected_scope: None,
            expected_region: None,
            expected_issuer: None,
            expected_policy_version: None,
            client_ip: Some("1.2.3.4"),
            telemetry: None,
            enforce_telemetry: false,
            max_attempts: 0,
            accept_legacy_v1: false,
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
            secrets_by_kid: Some(&rolled_forward),
            revoked_kids: None,
            counter,
            duration_ms: 5000,
            now_unix: NOW_UNIX + 1,
            now_ns: NOW_NS + 5_000_000,
            min_duration_ms: 0,
            expected_scope: None,
            expected_region: None,
            expected_issuer: None,
            expected_policy_version: None,
            client_ip: Some("1.2.3.4"),
            telemetry: None,
            enforce_telemetry: false,
            max_attempts: 0,
            accept_legacy_v1: false,
        };
        assert!(matches!(
            verify_solution(&mut ctx_rolled),
            VerifyOutcome::Valid { .. }
        ));
    }

    // ── compromise revocation overrides rotation grace ─────────────────

    #[test]
    fn revoked_kid_is_rejected_even_when_the_secret_is_present() {
        // A REVOKED kid is rejected with UnknownKid IMMEDIATELY —
        // before the signature check — even though the record is perfectly
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
            secrets_by_kid: Some(&secrets),
            revoked_kids: Some(&revoked),
            counter,
            duration_ms: 5000,
            now_unix: NOW_UNIX + 1,
            now_ns: NOW_NS + 5_000_000,
            min_duration_ms: 0,
            expected_scope: None,
            expected_region: None,
            expected_issuer: None,
            expected_policy_version: None,
            client_ip: Some("1.2.3.4"),
            telemetry: None,
            enforce_telemetry: false,
            max_attempts: 0,
            accept_legacy_v1: false,
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
            secrets_by_kid: None,
            revoked_kids: Some(&revoked),
            counter,
            duration_ms: 5000,
            now_unix: NOW_UNIX + 1,
            now_ns: NOW_NS + 5_000_000,
            min_duration_ms: 0,
            expected_scope: None,
            expected_region: None,
            expected_issuer: None,
            expected_policy_version: None,
            client_ip: Some("1.2.3.4"),
            telemetry: None,
            enforce_telemetry: false,
            max_attempts: 0,
            accept_legacy_v1: false,
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
            secrets_by_kid: Some(&secrets),
            revoked_kids: Some(&revoked),
            counter,
            duration_ms: 5000,
            now_unix: NOW_UNIX + 1,
            now_ns: NOW_NS + 5_000_000,
            min_duration_ms: 0,
            expected_scope: None,
            expected_region: None,
            expected_issuer: None,
            expected_policy_version: None,
            client_ip: Some("1.2.3.4"),
            telemetry: None,
            enforce_telemetry: false,
            max_attempts: 0,
            accept_legacy_v1: false,
        };
        assert!(
            matches!(verify_solution(&mut ctx), VerifyOutcome::Valid { .. }),
            "an unrevoked kid with its secret present must verify normally"
        );
    }

    #[test]
    fn tampering_with_kid_breaks_the_v2_signature() {
        // The kid is the FINAL signed canonical field: swapping it must
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
        // MIN_DIFFICULTY = 1 and MAX_DIFFICULTY = 20 apply to BOTH
        // algorithms — 0, 21, 256 and 65535 are rejected, 1 and 20 accepted.
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
        // The ceiling-test pattern: solve with a SANE record, then verify
        // against an out-of-bounds-difficulty record with the VALID counter —
        // MalformedRecord must fire in validate_record (pre-hash), never
        // reach derive_hash. A hash-based path would ACCEPT the valid
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
        // 24 chars) fire BEFORE any base64 decode — a megabyte salt/nonce
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
        // A challenge issued more than MAX_CLOCK_SKEW_SECS (60) in the
        // future relative to the verifier clock is a time-domain anomaly —
        // the TTL check rejects it. Mutating issued_at invalidates the
        // signature, so re-sign first.
        let mut record = make_record(8);
        record.issued_at = NOW_UNIX + 62; // > now (NOW_UNIX+1) + 60 → anomaly
        record.expires_at = record.issued_at + 120;
        resign_v2(&mut record, "test-key-16-bytes!");
        let counter = solve_for_test(&record).unwrap();
        let mut ctx = VerifyContext {
            record: &mut record,
            secret_key: "test-key-16-bytes!",
            secrets_by_kid: None,
            revoked_kids: None,
            counter,
            duration_ms: 5000,
            now_unix: NOW_UNIX + 1, // issued_at > now + 60 → invalid
            now_ns: NOW_NS + 5_000_000,
            min_duration_ms: 0,
            expected_scope: None,
            expected_region: None,
            expected_issuer: None,
            expected_policy_version: None,
            client_ip: Some("1.2.3.4"),
            telemetry: None,
            enforce_telemetry: false,
            max_attempts: 0,
            accept_legacy_v1: false,
        };
        assert_eq!(
            verify_solution(&mut ctx),
            VerifyOutcome::Invalid(VerifyError::Expired)
        );

        // Exactly AT the skew bound is still acceptable (issued_at ==
        // now + 60): the boundary is inclusive.
        let mut record = make_record(8);
        record.issued_at = NOW_UNIX + 61; // == now (NOW_UNIX+1) + 60
        record.expires_at = record.issued_at + 120;
        resign_v2(&mut record, "test-key-16-bytes!");
        let counter = solve_for_test(&record).unwrap();
        let mut ctx = VerifyContext {
            record: &mut record,
            secret_key: "test-key-16-bytes!",
            secrets_by_kid: None,
            revoked_kids: None,
            counter,
            duration_ms: 5000,
            now_unix: NOW_UNIX + 1,
            now_ns: NOW_NS + 5_000_000,
            min_duration_ms: 0,
            expected_scope: None,
            expected_region: None,
            expected_issuer: None,
            expected_policy_version: None,
            client_ip: Some("1.2.3.4"),
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

    // ── POST-DERIVE final re-validation ───────────────────────────────

    #[test]
    fn final_revalidation_race_expired_during_derive() {
        // The expensive derivation may straddle expires_at: the cheap TTL
        // check passes, the hash derives, and by the final re-check the
        // CURRENT server time has advanced past expiry. The final gate must
        // reject — deterministically simulated with an advanced now_unix.
        let mut record = make_record(8);
        let counter = solve_for_test(&record).unwrap();
        let cheap_now = record.expires_at - 1;

        // Cheap phase + derive + final re-check all pass just before expiry.
        let mut ctx = VerifyContext {
            record: &mut record,
            secret_key: "test-key-16-bytes!",
            secrets_by_kid: None,
            revoked_kids: None,
            counter,
            duration_ms: 5000,
            now_unix: cheap_now,
            now_ns: NOW_NS + 5_000_000,
            min_duration_ms: 0,
            expected_scope: None,
            expected_region: None,
            expected_issuer: None,
            expected_policy_version: None,
            client_ip: Some("1.2.3.4"),
            telemetry: None,
            enforce_telemetry: false,
            max_attempts: 0,
            accept_legacy_v1: false,
        };
        assert!(matches!(
            verify_solution(&mut ctx),
            VerifyOutcome::Valid { .. }
        ));

        // The final re-check with the advanced clock: the gate fires at the
        // exact expiry boundary (the ProductionVerifier re-reads the real
        // clock at this step — see tests/redis_verify.rs).
        assert_eq!(
            final_revalidate(&record, cheap_now, None, None, None),
            Ok(())
        );
        assert_eq!(
            final_revalidate(&record, record.expires_at, None, None, None),
            Err(VerifyError::Expired)
        );
        assert_eq!(
            final_revalidate(&record, record.expires_at + 5, None, None, None),
            Err(VerifyError::Expired)
        );
    }

    #[test]
    fn final_revalidation_rejects_changed_expectations() {
        // Expectations (policy epoch, region, issuer) can change while the
        // proof is deriving: the final gate re-checks them all against the
        // CURRENT configuration.
        let mut record = make_record(8);
        let counter = solve_for_test(&record).unwrap();
        let now_unix = NOW_UNIX + 1;
        let mut ctx = VerifyContext {
            record: &mut record,
            secret_key: "test-key-16-bytes!",
            secrets_by_kid: None,
            revoked_kids: None,
            counter,
            duration_ms: 5000,
            now_unix,
            now_ns: NOW_NS + 5_000_000,
            min_duration_ms: 0,
            expected_scope: None,
            expected_region: None,
            expected_issuer: None,
            expected_policy_version: None,
            client_ip: Some("1.2.3.4"),
            telemetry: None,
            enforce_telemetry: false,
            max_attempts: 0,
            accept_legacy_v1: false,
        };
        assert!(matches!(
            verify_solution(&mut ctx),
            VerifyOutcome::Valid { .. }
        ));

        // Each expectation re-checked at the final step fails closed when it
        // no longer matches the record.
        assert_eq!(
            final_revalidate(&record, now_unix, None, Some(2), None),
            Err(VerifyError::WrongPolicyVersion),
            "policy version changed between cheap and final → rejected"
        );
        assert_eq!(
            final_revalidate(&record, now_unix, Some("us"), None, None),
            Err(VerifyError::WrongRegion),
            "region expectation changed between cheap and final → rejected"
        );
        assert_eq!(
            final_revalidate(&record, now_unix, None, None, Some("auth-gw")),
            Err(VerifyError::WrongIssuer),
            "issuer expectation changed between cheap and final → rejected"
        );
        // The matching configuration passes.
        assert_eq!(
            final_revalidate(&record, now_unix, None, None, None),
            Ok(())
        );
    }

    #[test]
    fn unknown_algorithm_variants_are_rejected_at_parse_time() {
        // serde rejects unknown PoWAlgorithm variants exactly like
        // PHP's fromArray throws MalformedRecordException — "argon2d",
        // "sha1", "sha256-v2" and "ARGON2ID" are all parse errors, and the
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
                request_binding: None
            }
        );
        let invalid = VerifyOutcome::Invalid(VerifyError::Expired);
        assert_eq!(invalid.nonce(), None);
    }

    #[test]
    fn signed_argon2_records_outside_hard_ceilings_are_rejected() {
        // Signed records (valid v2 signatures over the mutated
        // parameters) with out-of-range m_kib/t must be rejected with
        // MalformedRecord before any Params::new/allocation.
        use crate::challenge::{MAX_ARGON_MEMORY_KIB, MAX_ARGON_TIME};
        for (field, value) in [
            ("m_kib", 1u32),                     // below MIN_ARGON_MEMORY_KIB
            ("m_kib", MAX_ARGON_MEMORY_KIB + 1), // 131072, above the ceiling
            ("t", 1u32),                         // below MIN_ARGON_TIME
            ("t", MAX_ARGON_TIME + 1),           // 32, above the ceiling
        ] {
            let mut record = make_argon2_record(4, 128);
            match field {
                "m_kib" => record.m_kib = value,
                "t" => record.t = value,
                _ => unreachable!(),
            }
            resign_v2(&mut record, "test-key-16-bytes!");
            assert_eq!(
                verify(&mut record, 0, 5000),
                VerifyOutcome::Invalid(VerifyError::MalformedRecord),
                "{field}={value} must be rejected by the hard ceilings"
            );
        }
    }

    #[test]
    fn signed_argon2_record_at_max_parallelism_verifies() {
        // Ceiling outcome for p: MAX_PARALLELISM = 4 is WITHIN the
        // hard range, so a properly signed record with p=4 (and m_kib >= 8*p,
        // t >= 3) must verify.
        let mut record = make_argon2_record(4, 64);
        record.p = 4;
        record.m_kib = 64; // >= 8 * 4
        resign_v2(&mut record, "test-key-16-bytes!");
        assert!(record.p <= crate::challenge::MAX_PARALLELISM);
        let counter = solve_for_test(&record).expect("p=4 argon solve finds a counter");
        assert!(
            matches!(
                verify(&mut record, counter, 5000),
                VerifyOutcome::Valid { .. }
            ),
            "p=4 (at the parallelism ceiling) must verify"
        );
    }

    #[test]
    fn signed_argon2_record_above_max_parallelism_is_rejected() {
        let mut record = make_argon2_record(4, 128);
        record.p = 5; // above MAX_PARALLELISM
        resign_v2(&mut record, "test-key-16-bytes!");
        assert_eq!(
            verify(&mut record, 0, 5000),
            VerifyOutcome::Invalid(VerifyError::MalformedRecord)
        );
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
    // unset; kid is the FINAL field, 1 when unset).
    const FIXTURE_SECRET: &str = "0123456789abcdef0123456789abcdef";
    const FIXTURE_NONCE: &str = "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVphYmNkZWY=";
    const FIXTURE_SALT: &str = "MTIzNDU2Nzg5MGFiY2RlZg==";
    const FIXTURE_BINDING_TAG: &str =
        "5b105424fe3a5cfa3afdccda95f734c9e66ee703e8b8d426a07cfe1cb9c8954f";
    const FIXTURE_CANONICAL_V2: &str = "v2|QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVphYmNkZWY=|login|5b105424fe3a5cfa3afdccda95f734c9e66ee703e8b8d426a07cfe1cb9c8954f|1700000000|1700000120|sha256|0|1|1|8|MTIzNDU2Nzg5MGFiY2RlZg==|0||1|||1";
    const FIXTURE_CHALLENGE_V2: &str = "djJ8UVVKRFJFVkdSMGhKU2t0TVRVNVBVRkZTVTFSVlZsZFlXVnBoWW1Oa1pXWT18bG9naW58NWIxMDU0MjRmZTNhNWNmYTNhZmRjY2RhOTVmNzM0YzllNjZlZTcwM2U4YjhkNDI2YTA3Y2ZlMWNiOWM4OTU0ZnwxNzAwMDAwMDAwfDE3MDAwMDAxMjB8c2hhMjU2fDB8MXwxfDh8TVRJek5EVTJOemc1TUdGaVkyUmxaZz09fDB8fDF8fHwx.145669d338579ed579537accc7be3f9b4004e01af9bc5a5ede4e5761df9bde88";
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
            hostname: None,
        }
    }

    fn verify_fixture(record: &mut ChallengeRecord, accept_legacy_v1: bool) -> VerifyOutcome {
        let counter = solve_for_test(record).expect("fixture counter found");
        let mut ctx = VerifyContext {
            record,
            secret_key: FIXTURE_SECRET,
            secrets_by_kid: None,
            revoked_kids: None,
            counter,
            duration_ms: 5000,
            now_unix: 1_700_000_100, // before expires_at 1_700_000_120
            now_ns: FIXTURE_NOW_NS + 5_000_000,
            min_duration_ms: 0,
            expected_scope: None,
            client_ip: Some("192.168.1.5"),
            expected_region: None,
            expected_issuer: None,
            expected_policy_version: None,
            telemetry: None,
            enforce_telemetry: false,
            max_attempts: 0,
            accept_legacy_v1,
        };
        verify_solution(&mut ctx)
    }

    #[test]
    fn binding_tag_matches_the_shared_fixture() {
        // Locks the exact v2 binding tag from the SHARED FIXTURE VECTOR.
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
        // verifiable ONLY during an explicit migration window.
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
    fn v2_fixture_rejects_wrong_scope_with_wrong_scope_error() {
        let mut record = fixture_record(2);
        let counter = solve_for_test(&record).unwrap();
        let mut ctx = VerifyContext {
            record: &mut record,
            secret_key: FIXTURE_SECRET,
            secrets_by_kid: None,
            revoked_kids: None,
            counter,
            duration_ms: 5000,
            now_unix: 1_700_000_100,
            now_ns: FIXTURE_NOW_NS + 5_000_000,
            min_duration_ms: 0,
            expected_scope: Some("signup"),
            client_ip: Some("1.2.3.4"),
            expected_region: None,
            expected_issuer: None,
            expected_policy_version: None,
            telemetry: None,
            enforce_telemetry: false,
            max_attempts: 0,
            accept_legacy_v1: false,
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
}
