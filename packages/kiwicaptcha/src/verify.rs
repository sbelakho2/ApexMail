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

use crate::challenge::{
    binding_tag, hash_ip, payload_from_record, verify_signature, verify_signature_v2,
    ChallengeRecord, PoWAlgorithm, SOLVER_MAX_ARGON2_TARGET_BITS, SOLVER_MAX_TARGET_BITS,
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
            // hard ceilings (audit #32) plus the Argon2 minimum
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
    /// record's `issued_at_ns` (the field names keep the historical `_ns`
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
    /// The current client's IP address. When [`Some`], the challenge is
    /// rejected if the stored `ip_hash` does not match
    /// `hash_ip(client_ip, secret_key)` — enforcing the IP binding that was
    /// recorded at issuance (relay-attack mitigation). When `None` and the
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
    /// (atomically, e.g. Redis GETDEL) so it can never be used twice.
    /// Carries the consumed challenge's canonical nonce (the jti — the
    /// single-use token identifier), so callers can correlate the outcome
    /// with the storage key and any downstream result token without
    /// re-decoding the solution.
    Valid {
        /// The consumed challenge's canonical base64 nonce.
        nonce: String,
    },
    /// The solution is invalid; the reason explains why.
    Invalid(VerifyError),
}

impl VerifyOutcome {
    /// The consumed canonical nonce (jti) when the outcome is valid, else
    /// `None`.
    pub fn nonce(&self) -> Option<&str> {
        match self {
            VerifyOutcome::Valid { nonce } => Some(nonce),
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
    /// The atomic consume (GETDEL) failed with an uncertain I/O error —
    /// the challenge may or may not have been consumed on the server. The
    /// consumer MUST NOT retry the GETDEL automatically (the record may
    /// already be burned); treat the token as unknown instead of replaying
    /// it. See the GETDEL no-retry rule in `redis_verify`.
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
/// - `scope` non-empty, at most 128 bytes, no `|`;
/// - `nonce` decodes as base64 to exactly 32 bytes;
/// - `salt` decodes as base64 to exactly 16 bytes;
/// - `expires_at > issued_at` and `expires_at - issued_at <= MAX_TTL_SECS`;
/// - `prefix` is exactly `challenge|salt|`;
/// - SHA-256: `target_bits` 1..=SOLVER_MAX_TARGET_BITS;
/// - Argon2id: `target_bits` 1..=SOLVER_MAX_ARGON2_TARGET_BITS and the hard
///   parameter ceilings (audit #32): `m_kib` 8..=65536, `t` 3..=16,
///   `p` 1..=4.
///
/// Returns [`VerifyError::MalformedRecord`] on any violation.
pub fn validate_record(record: &ChallengeRecord) -> Result<(), VerifyError> {
    // Protocol version is part of the wire contract: only 1 (legacy,
    // migration window) and 2 (current) exist — anything else is a
    // corrupt/foreign record.
    if record.protocol_version != 1 && record.protocol_version != 2 {
        return Err(VerifyError::MalformedRecord);
    }
    if record.scope.is_empty() || record.scope.len() > 128 || record.scope.contains('|') {
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
    match record.algorithm {
        PoWAlgorithm::Sha256 => {
            if record.target_bits == 0 || record.target_bits > SOLVER_MAX_TARGET_BITS {
                return Err(VerifyError::MalformedRecord);
            }
        }
        PoWAlgorithm::Argon2id => {
            if record.target_bits == 0 || record.target_bits > SOLVER_MAX_ARGON2_TARGET_BITS {
                return Err(VerifyError::MalformedRecord);
            }
            check_argon2_ceilings(record)?;
        }
    }
    Ok(())
}

/// Validate the hard Argon2id parameter ceilings (audit #32).
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
///    signatures use the HKDF-derived challenge key, audit #21).
/// 4. Hard Argon2id parameter ceilings (audit #32) — after signature
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
///    without `issued_at_ns` are malformed (the legacy client-duration
///    fallback was removed).
/// 10. Optional telemetry scoring (when `enforce_telemetry` is set).
/// 11. Re-derive the SHA-256/Argon2id hash and check leading zero bits (the
///     actual PoW). The valid outcome's `nonce` field carries the consumed
///     canonical nonce (jti — audit #37).
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

    // 1b. Signature re-check over the protocol-appropriate canonical input.
    let sig = signature_from_challenge(ctx.record);
    let sig_ok = match ctx.record.protocol_version {
        // Legacy v1 records: `nonce|scope|ip_hash|issued_at` (the binding
        // field carried the legacy hash_ip). Verified for the migration
        // window (max TTL) alongside v2.
        1 => verify_signature(&payload_from_record(ctx.record), sig, ctx.secret_key),
        _ => verify_signature_v2(ctx.record, sig, ctx.secret_key),
    };
    match sig_ok {
        Ok(true) => {}
        Ok(false) => return VerifyOutcome::Invalid(VerifyError::BadSignature),
        Err(_) => return VerifyOutcome::Invalid(VerifyError::BadSignature),
    }

    // 1c. Hard Argon2id parameter ceilings (audit #32) — validated AFTER the
    //     signature has been authenticated and BEFORE any Params::new or
    //     memory allocation: even a properly signed record must never drive
    //     an out-of-bounds memory-hard computation.
    if ctx.record.algorithm == PoWAlgorithm::Argon2id {
        if let Err(e) = check_argon2_ceilings(ctx.record) {
            return VerifyOutcome::Invalid(e);
        }
    }

    // 2. TTL.
    if ctx.now_unix >= ctx.record.expires_at {
        return VerifyOutcome::Invalid(VerifyError::Expired);
    }

    // 2b. Scope validation: reject if the challenge was issued for a different
    //     auth flow (e.g. a login challenge used on /signup).
    if let Some(expected) = ctx.expected_scope {
        if ctx.record.scope != expected {
            return VerifyOutcome::Invalid(VerifyError::WrongScope);
        }
    }

    // 2c. Region validation (audit #22): a deployment that expects a region
    //     rejects challenges issued for a different region — or for no region
    //     at all (fail closed).
    if let Some(expected) = ctx.expected_region {
        if ctx.record.region.as_deref() != Some(expected) {
            return VerifyOutcome::Invalid(VerifyError::WrongRegion);
        }
    }

    // 2c. IP binding: the challenge was issued to a client IP; a different
    //     submission IP means the token was relayed. Enforced here (not just
    //     at the route layer) so the secure behavior cannot be forgotten.
    //     An empty binding_tag means binding is disabled (BindingMode::None)
    //     the check is skipped; a `None` client_ip with a NON-EMPTY tag
    //     fails closed with MissingClientIp (only BindingMode::None records
    //     verify without an IP).
    // The stored record is AUTHORITATIVE: an empty binding tag means binding
    // is disabled (BindingMode::None); a NON-EMPTY tag means the challenge IS
    // bound, so a missing client IP fails closed (MissingClientIp) instead of
    // silently skipping the check.
    if !ctx.record.binding_tag.is_empty() {
        let Some(client_ip) = ctx.client_ip else {
            return VerifyOutcome::Invalid(VerifyError::MissingClientIp);
        };
        let expected = match ctx.record.protocol_version {
            1 => hash_ip(client_ip, ctx.secret_key),
            _ => match binding_tag(&ctx.record.nonce, client_ip, ctx.secret_key) {
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
    //    timestamp are malformed — there is no legacy client-duration
    //    fallback (XV).
    // Records without a high-resolution issuance timestamp are malformed —
    // there is no legacy client-duration fallback (XV). This is enforced
    // UNCONDITIONALLY (even when the timing floor is disabled) to match the
    // PHP verifier exactly.
    if ctx.record.issued_at_ns == 0 {
        return VerifyOutcome::Invalid(VerifyError::MalformedRecord);
    }
    let floor = ctx.min_duration_ms.max(ctx.record.min_duration_ms);
    if floor > 0 {
        if ctx.now_ns >= ctx.record.issued_at_ns {
            // High-resolution path: elapsed time between issuance and receipt,
            // both observed by the server clock. Both `now_ns` and
            // `issued_at_ns` are EPOCH MICROSECONDS (the names keep the
            // historical `_ns` suffix), so the ms floor is compared in the
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

    if leading_zero_bits(&hash) >= ctx.record.target_bits {
        // The outcome carries the consumed canonical nonce (jti) so callers
        // can correlate the result without re-decoding the solution.
        VerifyOutcome::Valid {
            nonce: ctx.record.nonce.clone(),
        }
    } else {
        VerifyOutcome::Invalid(VerifyError::InsufficientWork)
    }
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
/// - Solve takes >120s total (well beyond the ~30s expected for targetBits=14).
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

    // 2. Solve takes >300s total (well beyond expected). Increased from 120s to allow for very slow devices.
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
    // unit shared with PHP; field names keep the historical `_ns` suffix.
    const NOW_NS: u64 = 1_700_000_000_000_000;

    fn make_record(target_bits: u32) -> ChallengeRecord {
        let config = ChallengeConfig {
            secret_key: "test-key-16-bytes!".into(),
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
        };
        let issued = issue_challenge(&config, "login", "1.2.3.4", NOW_UNIX, NOW_NS, 0).unwrap();
        issued.record
    }

    fn make_argon2_record(target_bits: u32, m_kib: u32) -> ChallengeRecord {
        let config = ChallengeConfig {
            secret_key: "test-key-16-bytes!".into(),
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
        };
        let issued = issue_challenge(&config, "login", "1.2.3.4", NOW_UNIX, NOW_NS, 0).unwrap();
        issued.record
    }

    fn verify(record: &mut ChallengeRecord, counter: u64, duration_ms: u64) -> VerifyOutcome {
        let mut ctx = VerifyContext {
            record,
            secret_key: "test-key-16-bytes!",
            counter,
            duration_ms,
            now_unix: NOW_UNIX + 1,
            now_ns: NOW_NS + 5_000_000, // 5 s after issuance
            min_duration_ms: 0,
            expected_scope: None,
            expected_region: None,
            client_ip: Some("1.2.3.4"),
            telemetry: None,
            enforce_telemetry: false,
            max_attempts: 0,
            accept_legacy_v1: false,
        };
        verify_solution(&mut ctx)
    }

    /// Re-sign a mutated Argon2id record so its parameters are covered by a
    /// VALID v2 signature — the ceiling checks (audit #32) must fire on
    /// properly signed records, not on signature failures.
    fn resign_v2(record: &mut ChallengeRecord, secret: &str) {
        use hmac::Mac;
        let canonical = format!(
            "v2|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}",
            record.nonce,
            record.scope,
            record.binding_tag,
            record.issued_at,
            record.expires_at,
            record.algorithm.as_str(),
            record.m_kib,
            record.t,
            record.p,
            record.target_bits,
            record.salt,
            record.min_duration_ms
        );
        let derived = crate::keys::DerivedKeys::from_master(secret, None);
        let key = derived.challenge_key();
        let mut mac = hmac::Hmac::<Sha256>::new_from_slice(key).expect("key fits");
        mac.update(canonical.as_bytes());
        let sig = mac
            .finalize()
            .into_bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        record.challenge = format!("{}.{}", B64.encode(&canonical), sig);
        record.prefix = format!("{}|{}|", record.challenge, record.salt);
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
        };
        assert!(issue_challenge(&config, "login", "1.2.3.4", NOW_UNIX, NOW_NS, 0).is_err());
    }

    #[test]
    fn argon2_issuance_rejects_libsodium_unrepresentable_t() {
        // PHP/libsodium cannot represent Argon2id with t < 3 — issuance must
        // reject it so cross-language verification can never silently fail.
        for t in [0u32, 1, 2] {
            let config = ChallengeConfig {
                secret_key: "test-key-16-bytes!".into(),
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
            };
            assert!(
                issue_challenge(&config, "login", "1.2.3.4", NOW_UNIX, NOW_NS, 0).is_err(),
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
        };
        for ms in [10_000u64, 20_000, 100_000] {
            let mut cfg = base.clone();
            cfg.min_duration_ms = Some(ms);
            assert!(
                issue_challenge(&cfg, "login", "1.2.3.4", NOW_UNIX, NOW_NS, 0).is_err(),
                "min_duration_ms={ms} with ttl 10s must be rejected"
            );
        }
        let mut ok = base.clone();
        ok.min_duration_ms = Some(9_999);
        assert!(issue_challenge(&ok, "login", "1.2.3.4", NOW_UNIX, NOW_NS, 0).is_ok());
    }

    #[test]
    fn issuance_rejects_ttl_outside_protocol_range() {
        // The verifier's validate_record rejects lifetimes > MAX_TTL_SECS
        // (300) and TTL 0 is meaningless — issuance must refuse to mint a
        // record it would later declare malformed.
        let base = ChallengeConfig {
            secret_key: "test-key-16-bytes!".into(),
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
        };
        for ttl in [0u64, 301, 60_000] {
            let mut cfg = base.clone();
            cfg.ttl_secs = ttl;
            assert!(
                issue_challenge(&cfg, "login", "1.2.3.4", NOW_UNIX, NOW_NS, 0).is_err(),
                "ttl={ttl} must be rejected at issuance"
            );
        }
        let mut ok = base.clone();
        ok.ttl_secs = 300;
        assert!(issue_challenge(&ok, "login", "1.2.3.4", NOW_UNIX, NOW_NS, 0).is_ok());
    }

    #[test]
    fn issuance_rejects_argon_t_above_protocol_ceiling() {
        // The verifier declares t > MAX_ARGON_T (6) malformed — issuance
        // must refuse it (PHP Config already does; Rust must match).
        let config = ChallengeConfig {
            secret_key: "test-key-16-bytes!".into(),
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
        };
        assert!(
            issue_challenge(&config, "login", "1.2.3.4", NOW_UNIX, NOW_NS, 0).is_err(),
            "Argon2id t=7 must be rejected at issuance"
        );
    }

    #[test]
    fn argon2_issuance_rejects_libsodium_unrepresentable_p() {
        let config = ChallengeConfig {
            secret_key: "test-key-16-bytes!".into(),
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
        };
        assert!(issue_challenge(&config, "login", "1.2.3.4", NOW_UNIX, NOW_NS, 0).is_err());
    }

    #[test]
    fn argon2_issuance_rejects_memory_above_solver_ceiling() {
        // The verifier already rejects records above SOLVER_MAX_ARGON2_M_KIB
        // (64 MiB — the wasm heap ceiling); issuance must never mint one.
        let config = ChallengeConfig {
            secret_key: "test-key-16-bytes!".into(),
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
        };
        assert!(
            matches!(
                issue_challenge(&config, "login", "1.2.3.4", NOW_UNIX, NOW_NS, 0),
                Err(SignError::InvalidArgon2Params)
            ),
            "m_kib above the 64 MiB ceiling must be rejected at issuance"
        );
        // The ceiling itself is accepted.
        let at_ceiling = ChallengeConfig {
            m_kib: crate::challenge::SOLVER_MAX_ARGON2_M_KIB,
            ..config
        };
        assert!(issue_challenge(&at_ceiling, "login", "1.2.3.4", NOW_UNIX, NOW_NS, 0).is_ok());
    }

    #[test]
    fn argon2_issuance_validates_target_bits_range() {
        // argon2_target_bits must be 1..=SOLVER_MAX_ARGON2_TARGET_BITS: 0
        // would silently clamp to a degenerate difficulty and 11 exceeds the
        // solver ceiling — both must fail at issuance.
        for bits in [0u32, 11] {
            let config = ChallengeConfig {
                secret_key: "test-key-16-bytes!".into(),
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
            };
            assert!(
                matches!(
                    issue_challenge(&config, "login", "1.2.3.4", NOW_UNIX, NOW_NS, 0),
                    Err(SignError::InvalidArgon2Params)
                ),
                "argon2_target_bits={bits} must be rejected at issuance"
            );
        }
        // The maximum is accepted.
        let max_bits = ChallengeConfig {
            secret_key: "test-key-16-bytes!".into(),
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
        };
        assert!(issue_challenge(&max_bits, "login", "1.2.3.4", NOW_UNIX, NOW_NS, 0).is_ok());
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
            counter,
            duration_ms: 5000,
            now_unix: NOW_UNIX + 121, // past TTL
            now_ns: NOW_NS,
            min_duration_ms: 0,
            expected_scope: None,
            client_ip: Some("1.2.3.4"),
            expected_region: None,
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
            counter,
            duration_ms: 60_000, // client forges a 60 s solve — must NOT help
            now_unix: NOW_UNIX + 1,
            now_ns: NOW_NS + 1_000_000, // 1 s elapsed < 60 s floor
            min_duration_ms: 60_000,
            expected_scope: None,
            client_ip: Some("1.2.3.4"),
            expected_region: None,
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
            counter,
            duration_ms: 5000, // forged
            now_unix: NOW_UNIX,
            now_ns: NOW_NS, // same µs as issuance
            min_duration_ms: 0,
            expected_scope: None,
            client_ip: Some("1.2.3.4"),
            expected_region: None,
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
            counter,
            duration_ms: 5000,
            now_unix: NOW_UNIX + 1,
            now_ns: NOW_NS + 5_000_000,
            min_duration_ms: 0,
            expected_scope: None,
            client_ip: Some("1.2.3.4"),
            expected_region: None,
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
            counter,
            duration_ms: 5000,
            now_unix: NOW_UNIX + 1,
            now_ns: NOW_NS + 5_000_000,
            min_duration_ms: 0,
            expected_scope: None,
            client_ip: Some("1.2.3.4"),
            expected_region: None,
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
            counter,
            duration_ms: 5000,
            now_unix: NOW_UNIX + 1,
            now_ns: NOW_NS + 5_000_000,
            min_duration_ms: 0,
            expected_scope: None,
            client_ip: Some("9.9.9.9"), // different from issuance IP 1.2.3.4
            expected_region: None,
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
            counter,
            duration_ms: 5000,
            now_unix: NOW_UNIX + 1,
            now_ns: NOW_NS + 5_000_000,
            min_duration_ms: 0,
            expected_scope: None,
            client_ip: None,
            expected_region: None,
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
        };
        let issued = issue_challenge(&config, "login", "1.2.3.4", NOW_UNIX, NOW_NS, 0).unwrap();
        let mut unbound = issued.record;
        let counter2 = solve_for_test(&unbound).unwrap();
        let mut ctx2 = VerifyContext {
            record: &mut unbound,
            secret_key: "test-key-16-bytes!",
            counter: counter2,
            duration_ms: 5000,
            now_unix: NOW_UNIX + 1,
            now_ns: NOW_NS + 5_000_000,
            min_duration_ms: 0,
            expected_scope: None,
            client_ip: Some("1.2.3.4"),

            expected_region: None,
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
            counter: wrong,
            duration_ms: 5000,
            now_unix: NOW_UNIX + 1,
            now_ns: NOW_NS + 5_000_000,
            min_duration_ms: 0,
            expected_scope: None,
            client_ip: Some("1.2.3.4"),
            expected_region: None,
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
            counter,
            duration_ms: 5000,
            now_unix: NOW_UNIX + 1,
            now_ns: NOW_NS + 5_000_000,
            min_duration_ms: 0,
            expected_scope: None,
            client_ip: Some("1.2.3.4"),
            expected_region: None,
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
            counter: wrong,
            duration_ms: 5000,
            now_unix: NOW_UNIX + 1,
            now_ns: NOW_NS + 5_000_000,
            min_duration_ms: 0,
            expected_scope: None,
            client_ip: Some("1.2.3.4"),
            expected_region: None,
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
            counter,
            duration_ms: 5000,
            now_unix: NOW_UNIX + 1,
            now_ns: NOW_NS + 5_000_000,
            min_duration_ms: 0,
            expected_scope: None,
            client_ip: Some("1.2.3.4"),
            expected_region: None,
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
            counter,
            duration_ms: 5000,
            now_unix: NOW_UNIX + 1,
            now_ns: NOW_NS + 5_000_000,
            min_duration_ms: 0,
            expected_scope: None,
            client_ip: Some("1.2.3.4"),
            expected_region: None,
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
            counter,
            duration_ms: 5000,
            now_unix: NOW_UNIX + 1,
            now_ns: NOW_NS + 5_000_000,
            min_duration_ms: 0,
            expected_scope: None,
            client_ip: Some("1.2.3.4"),
            expected_region: None,
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
        // signal. (Previously `{}` slipped through because score_telemetry
        // scored it as benign.)
        use serde_json::json;
        let mut record = make_record(8);
        let counter = solve_for_test(&record).unwrap();
        let mut ctx = VerifyContext {
            record: &mut record,
            secret_key: "test-key-16-bytes!",
            counter,
            duration_ms: 5000,
            now_unix: NOW_UNIX + 1,
            now_ns: NOW_NS + 5_000_000,
            min_duration_ms: 0,
            expected_scope: None,
            client_ip: Some("1.2.3.4"),
            expected_region: None,
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
            counter,
            duration_ms: 5000,
            now_unix: NOW_UNIX + 1,
            now_ns: NOW_NS + 5_000_000,
            min_duration_ms: 0,
            expected_scope: None,
            client_ip: Some("1.2.3.4"),
            expected_region: None,
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
            counter,
            duration_ms: 5000,
            now_unix: NOW_UNIX + 1,
            now_ns: NOW_NS + 5_000_000,
            min_duration_ms: 0,
            expected_scope: None,
            client_ip: Some("1.2.3.4"),
            expected_region: None,
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
            counter,
            duration_ms: 5000,
            now_unix: NOW_UNIX + 1,
            now_ns: NOW_NS + 5_000_000,
            min_duration_ms: 0,
            expected_scope: None,
            client_ip: Some("1.2.3.4"),
            expected_region: None,
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
            counter,
            duration_ms: 5000,
            now_unix: NOW_UNIX + 1,
            now_ns: NOW_NS + 5_000_000,
            min_duration_ms: 0,
            expected_scope: None,
            client_ip: Some("1.2.3.4"),
            expected_region: None,
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
        // == 0) are rejected as MalformedRecord — the legacy client-duration
        // fallback was removed (XV): the floor can only be enforced with a
        // server-measured elapsed time.
        let mut record = make_record(8);
        record.issued_at_ns = 0;
        let counter = solve_for_test(&record).unwrap();
        let mut ctx = VerifyContext {
            record: &mut record,
            secret_key: "test-key-16-bytes!",
            counter,
            duration_ms: 60_000, // a forged long client duration must NOT resurrect the legacy path
            now_unix: NOW_UNIX + 1,
            now_ns: NOW_NS + 10_000_000,
            min_duration_ms: 0,
            expected_scope: None,
            client_ip: Some("1.2.3.4"),
            expected_region: None,
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
            counter,
            duration_ms: 5000,
            now_unix: NOW_UNIX + 1,
            now_ns: NOW_NS.saturating_sub(1_000_000), // 1 s skew, issuer ahead
            min_duration_ms: 0,
            expected_scope: None,
            client_ip: Some("1.2.3.4"),
            expected_region: None,
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
            counter,
            duration_ms: 5000,
            now_unix: NOW_UNIX + 1,
            now_ns: NOW_NS.saturating_sub(6_000_000), // 6 s skew
            min_duration_ms: 0,
            expected_scope: None,
            client_ip: Some("1.2.3.4"),
            expected_region: None,
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
            counter,
            duration_ms: 5000,
            now_unix: 1_000_001,
            now_ns: NOW_NS + 5_000_000,
            min_duration_ms: 0,
            expected_scope: Some("signup"),
            client_ip: Some("1.2.3.4"),
            expected_region: None,
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
            counter,
            duration_ms: 5000,
            now_unix: expires_at, // exactly at expiry
            now_ns: NOW_NS + 5_000_000,
            min_duration_ms: 0,
            expected_scope: None,
            client_ip: Some("1.2.3.4"),
            expected_region: None,
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
            counter,
            duration_ms: 5000,
            now_unix: expires_at - 1,
            now_ns: NOW_NS + 5_000_000,
            min_duration_ms: 0,
            expected_scope: None,
            client_ip: Some("1.2.3.4"),
            expected_region: None,
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
            counter,
            duration_ms: 5000,
            now_unix: NOW_UNIX + 1,
            now_ns: NOW_NS + 6_000, // 6 ms elapsed > 5 ms floor (µs)
            min_duration_ms: 0,
            expected_scope: None,
            client_ip: Some("1.2.3.4"),
            expected_region: None,
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
            counter,
            duration_ms: 60_000, // forged long client duration must NOT help
            now_unix: NOW_UNIX + 1,
            now_ns: NOW_NS + 4_999, // 4.999 ms elapsed < 5 ms floor (µs)
            min_duration_ms: 0,
            expected_scope: None,
            client_ip: Some("1.2.3.4"),
            expected_region: None,
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

    // ── Round-5 audit: validate_record, binding_tag, protocol v1/v2 ─────

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
        };
        assert!(
            matches!(
                issue_challenge(&config, "login", "1.2.3.4", NOW_UNIX, NOW_NS, 0),
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
            },
            "login",
            "1.2.3.4",
            NOW_UNIX,
            NOW_NS,
            0,
        )
        .unwrap();
        assert!(issued.record.binding_tag.is_empty());
        let counter = solve_for_test(&issued.record).unwrap();
        let mut ctx = VerifyContext {
            record: &mut issued.record.clone(),
            secret_key: "test-key-16-bytes!",
            counter,
            duration_ms: 5000,
            now_unix: NOW_UNIX + 1,
            now_ns: NOW_NS + 5_000_000,
            min_duration_ms: 0,
            expected_scope: None,
            client_ip: Some("1.2.3.4"),
            expected_region: None,
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
            counter,
            duration_ms: 5000,
            now_unix: NOW_UNIX + 1,
            now_ns: NOW_NS + 5_000_000,
            min_duration_ms: 0,
            expected_scope: None,
            client_ip: Some("9.9.9.9"), // different from issuance IP 1.2.3.4
            expected_region: None,
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

    // ── Round-8 audit: region binding, argon ceilings, jti exposure ─────

    #[test]
    fn region_mismatch_is_rejected_with_wrong_region() {
        // The record's region is deployment metadata carried on the JSON
        // record (never signed — the record itself is server-side
        // authoritative). A verifier configured with an expected region
        // rejects challenges issued for another region.
        let mut record = make_record(8);
        record.region = Some("eu".into());
        let counter = solve_for_test(&record).unwrap();
        let mut ctx = VerifyContext {
            record: &mut record,
            secret_key: "test-key-16-bytes!",
            counter,
            duration_ms: 5000,
            now_unix: NOW_UNIX + 1,
            now_ns: NOW_NS + 5_000_000,
            min_duration_ms: 0,
            expected_scope: None,
            expected_region: Some("us"),
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
            counter,
            duration_ms: 5000,
            now_unix: NOW_UNIX + 1,
            now_ns: NOW_NS + 5_000_000,
            min_duration_ms: 0,
            expected_scope: None,
            expected_region: Some("us"),
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
        let counter = solve_for_test(&record).unwrap();

        let mut ctx_match = VerifyContext {
            record: &mut record,
            secret_key: "test-key-16-bytes!",
            counter,
            duration_ms: 5000,
            now_unix: NOW_UNIX + 1,
            now_ns: NOW_NS + 5_000_000,
            min_duration_ms: 0,
            expected_scope: None,
            expected_region: Some("us"),
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
            counter,
            duration_ms: 5000,
            now_unix: NOW_UNIX + 1,
            now_ns: NOW_NS + 5_000_000,
            min_duration_ms: 0,
            expected_scope: None,
            expected_region: None,
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
    fn valid_outcome_exposes_the_consumed_nonce_jti() {
        // Audit #37: the VerifyOutcome must carry the canonical nonce so
        // callers can correlate the result without re-decoding the token.
        let mut record = make_record(8);
        let counter = solve_for_test(&record).unwrap();
        let expected_nonce = record.nonce.clone();
        let outcome = verify(&mut record, counter, 5000);
        assert_eq!(outcome.nonce(), Some(expected_nonce.as_str()));
        assert_eq!(
            outcome,
            VerifyOutcome::Valid {
                nonce: expected_nonce
            }
        );
        let invalid = VerifyOutcome::Invalid(VerifyError::Expired);
        assert_eq!(invalid.nonce(), None);
    }

    #[test]
    fn signed_argon2_records_outside_hard_ceilings_are_rejected() {
        // Audit #32: signed records (valid v2 signatures over the mutated
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
        // Audit #32 ceiling outcome for p: MAX_PARALLELISM = 4 is WITHIN the
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
    // ip = "192.168.1.5"; protocol_version = 2 (v1 vector below).
    const FIXTURE_SECRET: &str = "0123456789abcdef0123456789abcdef";
    const FIXTURE_NONCE: &str = "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVphYmNkZWY=";
    const FIXTURE_SALT: &str = "MTIzNDU2Nzg5MGFiY2RlZg==";
    const FIXTURE_BINDING_TAG: &str =
        "5b105424fe3a5cfa3afdccda95f734c9e66ee703e8b8d426a07cfe1cb9c8954f";
    const FIXTURE_CANONICAL_V2: &str = "v2|QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVphYmNkZWY=|login|5b105424fe3a5cfa3afdccda95f734c9e66ee703e8b8d426a07cfe1cb9c8954f|1700000000|1700000120|sha256|0|1|1|8|MTIzNDU2Nzg5MGFiY2RlZg==|0";
    const FIXTURE_CHALLENGE_V2: &str = "djJ8UVVKRFJFVkdSMGhKU2t0TVRVNVBVRkZTVTFSVlZsZFlXVnBoWW1Oa1pXWT18bG9naW58NWIxMDU0MjRmZTNhNWNmYTNhZmRjY2RhOTVmNzM0YzllNjZlZTcwM2U4YjhkNDI2YTA3Y2ZlMWNiOWM4OTU0ZnwxNzAwMDAwMDAwfDE3MDAwMDAxMjB8c2hhMjU2fDB8MXwxfDh8TVRJek5EVTJOemc1TUdGaVkyUmxaZz09fDA=.37bee30d7320977fbd902205f313b77187b85c29831f20e59d775b878fdb2c63";
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
        }
    }

    fn verify_fixture(record: &mut ChallengeRecord, accept_legacy_v1: bool) -> VerifyOutcome {
        let counter = solve_for_test(record).expect("fixture counter found");
        let mut ctx = VerifyContext {
            record,
            secret_key: FIXTURE_SECRET,
            counter,
            duration_ms: 5000,
            now_unix: 1_700_000_100, // before expires_at 1_700_000_120
            now_ns: FIXTURE_NOW_NS + 5_000_000,
            min_duration_ms: 0,
            expected_scope: None,
            client_ip: Some("192.168.1.5"),
            expected_region: None,
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
        // Legacy binding (v1) is the historical hash_ip(secret||ip).
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
            counter,
            duration_ms: 5000,
            now_unix: 1_700_000_100,
            now_ns: FIXTURE_NOW_NS + 5_000_000,
            min_duration_ms: 0,
            expected_scope: Some("signup"),
            client_ip: Some("1.2.3.4"),
            expected_region: None,
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
