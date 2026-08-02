//! Proof-of-work verification for KiwiCaptcha.
//!
//! Given a stored [`ChallengeRecord`] and a client-submitted counter, this
//! module re-derives the Argon2id hash (`Argon2id(challenge || prefix || counter, salt, m, t, p)`)
//! and checks that the raw output has at least `target_bits` leading zero bits.
//!
//! Because Argon2id is memory-hard, the server re-derivation costs real time
//! and memory — but only once per verification (the client pays the brute-force
//! cost of finding the counter). This is the asymmetry that makes PoW work:
//! cheap to verify, expensive to solve.

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use hmac::Hmac;
use pbkdf2::pbkdf2;
use sha2::{Digest, Sha256};

use crate::challenge::{payload_from_record, verify_signature, ChallengeRecord};

/// Compute the PBKDF2-HMAC-SHA256 hash for the given record + counter.
///
/// This matches the browser's WebCrypto `deriveBits` call exactly:
///   - password = `record.prefix || counter` (prefix embeds the signed challenge + salt)
///   - salt = the challenge's base64-decoded salt
///   - iterations = `record.m_kib` (repurposed as iteration count; the client
///     receives it as `mKib` and passes it to `PBKDF2.iterations`)
///   - output length = 32 bytes (256 bits)
///
/// PBKDF2 is chosen because it is natively available in every modern browser
/// via the WebCrypto API (`crypto.subtle.deriveBits`), so the widget needs no
/// external JS or WASM. The iteration count is tuned so a real browser takes
/// ~300–500ms per hash invocation.
fn derive_hash(record: &ChallengeRecord, counter: u64) -> Result<[u8; 32], VerifyError> {
    let salt = B64
        .decode(&record.salt)
        .map_err(|_| VerifyError::MalformedRecord)?;
    let password = format!("{}{}", record.prefix, counter);

    let mut out = [0u8; 32];
    pbkdf2::<Hmac<Sha256>>(
        password.as_bytes(),
        &salt,
        record.m_kib,
        &mut out,
    );
    Ok(out)
}

/// Count the number of leading zero bits in a byte slice (big-endian bit order).
fn leading_zero_bits(hash: &[u8]) -> u32 {
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
    /// The stored challenge record (looked up from Redis by nonce).
    pub record: &'a ChallengeRecord,
    /// The HMAC secret key (to re-verify the challenge signature).
    pub secret_key: &'a str,
    /// The client's claimed counter.
    pub counter: u64,
    /// The client's reported solve duration in milliseconds.
    pub duration_ms: u64,
    /// The current Unix timestamp (for TTL check).
    pub now_unix: u64,
    /// The minimum acceptable solve duration in milliseconds. A solve arriving
    /// faster than the theoretical Argon2id minimum is rejected as infeasible.
    pub min_duration_ms: u64,
}

/// Outcome of a verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyOutcome {
    /// The solution is valid. The caller should mark the challenge consumed.
    Valid,
    /// The solution is invalid; the reason explains why.
    Invalid(VerifyError),
}

/// Reasons a solution can be rejected.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum VerifyError {
    #[error("challenge signature is invalid")]
    BadSignature,
    #[error("challenge has expired")]
    Expired,
    #[error("solution arrived faster than the theoretical minimum")]
    TooFast,
    #[error("proof-of-work hash does not meet the difficulty target")]
    InsufficientWork,
    #[error("stored challenge record is malformed")]
    MalformedRecord,
    #[error("proof-of-work hash does not meet the difficulty target")]
    InsufficientWorkAlias,
}

/// Verify a solution against its stored challenge record.
///
/// This performs the full server-side check:
/// 1. Re-verify the HMAC signature (defends against forged records).
/// 2. Check the TTL (defends against stale challenges).
/// 3. Check the minimum duration (defends against impossibly-fast solves).
/// 4. Re-derive the PBKDF2 hash and check leading zero bits (the actual PoW).
pub fn verify_solution(ctx: &VerifyContext<'_>) -> VerifyOutcome {
    // 1. Signature re-check.
    let payload = payload_from_record(ctx.record);
    match verify_signature(&payload, signature_from_challenge(ctx.record), ctx.secret_key) {
        Ok(true) => {}
        Ok(false) => return VerifyOutcome::Invalid(VerifyError::BadSignature),
        Err(_) => return VerifyOutcome::Invalid(VerifyError::BadSignature),
    }

    // 2. TTL.
    if ctx.now_unix >= ctx.record.expires_at {
        return VerifyOutcome::Invalid(VerifyError::Expired);
    }

    // 3. Minimum duration (only enforced for non-trivial difficulties; a 0
    //    min_duration_ms disables this check, useful in tests).
    if ctx.min_duration_ms > 0 && ctx.duration_ms < ctx.min_duration_ms {
        return VerifyOutcome::Invalid(VerifyError::TooFast);
    }

    // 4. Re-derive and check leading zero bits.
    let hash = match derive_hash(ctx.record, ctx.counter) {
        Ok(h) => h,
        Err(e) => return VerifyOutcome::Invalid(e),
    };

    if leading_zero_bits(&hash) >= ctx.record.target_bits {
        VerifyOutcome::Valid
    } else {
        VerifyOutcome::Invalid(VerifyError::InsufficientWork)
    }
}

/// Extract the embedded signature from the stored challenge string.
///
/// The challenge is `base64(payload).signature` (the base64 payload contains no
/// dots, so `rsplit_once('.')` reliably isolates the hex HMAC signature).
fn signature_from_challenge(record: &ChallengeRecord) -> &str {
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
    for counter in 0..u64::MAX {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::challenge::{issue_challenge, ChallengeConfig};

    fn make_record(target_bits: u32) -> ChallengeRecord {
        let config = ChallengeConfig {
            secret_key: "test-key".into(),
            m_kib: 100, // 100 PBKDF2 iterations — fast enough for tests
            t: 1,
            p: 1,
            target_bits,
            ttl_secs: 120,
        };
        let issued = issue_challenge(&config, "login", "1.2.3.4", 1_000_000).unwrap();
        issued.record
    }

    #[test]
    fn valid_solution_is_accepted() {
        let record = make_record(8); // 8 bits — fast solve
        let counter = solve_for_test(&record).expect("solver finds a counter");
        let ctx = VerifyContext {
            record: &record,
            secret_key: "test-key",
            counter,
            duration_ms: 5000,
            now_unix: 1_000_001,
            min_duration_ms: 0,
        };
        assert_eq!(verify_solution(&ctx), VerifyOutcome::Valid);
    }

    #[test]
    fn wrong_counter_is_rejected() {
        let record = make_record(8);
        // Find a valid counter, then use a different one.
        let valid = solve_for_test(&record).unwrap();
        let bad = if valid == 0 { 1 } else { 0 };
        let ctx = VerifyContext {
            record: &record,
            secret_key: "test-key",
            counter: bad,
            duration_ms: 5000,
            now_unix: 1_000_001,
            min_duration_ms: 0,
        };
        assert_eq!(
            verify_solution(&ctx),
            VerifyOutcome::Invalid(VerifyError::InsufficientWork)
        );
    }

    #[test]
    fn expired_challenge_is_rejected() {
        let record = make_record(8);
        let counter = solve_for_test(&record).unwrap();
        let ctx = VerifyContext {
            record: &record,
            secret_key: "test-key",
            counter,
            duration_ms: 5000,
            now_unix: 1_000_000 + 121, // past TTL
            min_duration_ms: 0,
        };
        assert_eq!(
            verify_solution(&ctx),
            VerifyOutcome::Invalid(VerifyError::Expired)
        );
    }

    #[test]
    fn too_fast_solution_is_rejected() {
        let record = make_record(8);
        let counter = solve_for_test(&record).unwrap();
        let ctx = VerifyContext {
            record: &record,
            secret_key: "test-key",
            counter,
            duration_ms: 10, // impossibly fast
            now_unix: 1_000_001,
            min_duration_ms: 100,
        };
        assert_eq!(
            verify_solution(&ctx),
            VerifyOutcome::Invalid(VerifyError::TooFast)
        );
    }

    #[test]
    fn bad_secret_key_rejects() {
        let record = make_record(8);
        let counter = solve_for_test(&record).unwrap();
        let ctx = VerifyContext {
            record: &record,
            secret_key: "WRONG-KEY",
            counter,
            duration_ms: 5000,
            now_unix: 1_000_001,
            min_duration_ms: 0,
        };
        assert_eq!(
            verify_solution(&ctx),
            VerifyOutcome::Invalid(VerifyError::BadSignature)
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
}
