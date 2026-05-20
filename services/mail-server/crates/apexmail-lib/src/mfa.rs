//! TOTP (Time-based One-Time Password) verification — RFC 6238 with HMAC-SHA256.
//! Recovery/backup codes — cryptographically random one-time-use codes for MFA fallback.
//!
//! # Security hardening (Phase 3 audit findings)
//!
//! - **O-19.1**: Recovery codes are hashed with **Argon2id** (memory-hard,
//!   computationally expensive) instead of SHA-256, preventing fast offline
//!   brute-force attacks if the hash database is compromised.
//! - **O-19.2**: TOTP verification includes rate-limiting via [`TOTPVerifier`],
//!   which locks out the secret after `MAX_FAILED_ATTEMPTS` consecutive failures
//!   for a configurable `LOCKOUT_DURATION`.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use argon2::Argon2;
use hmac::{Hmac, Mac};
use rand::rngs::OsRng;
use rand::TryRngCore;
use sha2::Sha256;
use tracing::warn;

type HmacSha256 = Hmac<Sha256>;

/// Time step in seconds (standard TOTP interval).
const TIME_STEP: u64 = 30;

/// Number of recovery codes to generate during MFA setup.
const RECOVERY_CODE_COUNT: usize = 10;

/// Length of each recovery code (alphanumeric characters).
const RECOVERY_CODE_LENGTH: usize = 12;

/// Characters used for recovery code generation (no ambiguous chars: 0/O, 1/I/L).
const RECOVERY_CHARSET: &[u8] = b"ABCDEFGHJKMNPQRSTUVWXYZ23456789";

// ── O-19.2: TOTP rate-limiting / lockout ─────────────────────────────

/// Maximum failed TOTP attempts before the secret is locked out.
const MAX_FAILED_ATTEMPTS: u32 = 5;

/// Duration the secret remains locked after exceeding the max failed attempts.
const LOCKOUT_DURATION: Duration = Duration::from_secs(300); // 5 minutes

/// Tracks per-secret failed TOTP attempts and lockout state.
///
/// # O-19.2
/// Prevents brute-force attacks against TOTP codes by rate-limiting
/// verification attempts per secret. After `MAX_FAILED_ATTEMPTS` consecutive
/// failures, the secret is locked for `LOCKOUT_DURATION`.
#[derive(Debug, Default)]
pub struct TOTPVerifier {
    /// Map from `secret_base32` to (consecutive failures, locked_until_instant)
    attempts: parking_lot::Mutex<HashMap<String, (u32, Option<Instant>)>>,
}

impl TOTPVerifier {
    /// Create a new verifier with an empty attempt-tracking store.
    pub fn new() -> Self {
        Self {
            attempts: parking_lot::Mutex::new(HashMap::new()),
        }
    }

    /// Check whether the given secret is currently locked out.
    pub fn is_locked(&self, secret_base32: &str) -> bool {
        let map = self.attempts.lock();
        if let Some((_, Some(locked_until))) = map.get(secret_base32) {
            if Instant::now() < *locked_until {
                return true;
            }
        }
        false
    }

    /// Record a failed attempt and return whether the secret is now locked.
    pub fn record_failure(&self, secret_base32: &str) -> bool {
        let mut map = self.attempts.lock();
        let (failures, locked_until) = map.entry(secret_base32.to_string()).or_insert((0, None));

        *failures += 1;
        if *failures >= MAX_FAILED_ATTEMPTS && locked_until.is_none() {
            *locked_until = Some(Instant::now() + LOCKOUT_DURATION);
            warn!(
                "TOTP secret locked out after {} consecutive failures for {:?}",
                *failures, LOCKOUT_DURATION
            );
            return true;
        }
        false
    }

    /// Reset the failure count on successful verification.
    pub fn reset(&self, secret_base32: &str) {
        self.attempts.lock().remove(secret_base32);
    }

    /// Verify a TOTP code with rate-limiting.
    /// Returns `true` only if the code is valid and the secret is not locked out.
    pub fn verify(&self, secret_base32: &str, code: &str) -> bool {
        // Reject if locked
        if self.is_locked(secret_base32) {
            warn!("TOTP verification rejected — secret is locked out");
            return false;
        }

        if verify_totp_code_inner(secret_base32, code) {
            self.reset(secret_base32);
            true
        } else {
            self.record_failure(secret_base32);
            false
        }
    }
}

/// Legacy stateless TOTP verification (no rate-limiting).
///
/// Prefer [`TOTPVerifier::verify`] in production code.
/// Kept for backward compatibility.
pub fn verify_totp_code(secret_base32: &str, code: &str) -> bool {
    verify_totp_code_inner(secret_base32, code)
}

/// Core TOTP verification logic (no rate-limiting, no lockout check).
fn verify_totp_code_inner(secret_base32: &str, code: &str) -> bool {
    // Reject obviously invalid codes early.
    if code.len() != 6 || !code.chars().all(|c| c.is_ascii_digit()) {
        return false;
    }

    let secret = match base32_decode(secret_base32) {
        Some(s) => s,
        None => return false,
    };

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let time_step = now / TIME_STEP;

    // Check current window and ±1 for clock drift.
    for offset in [0i64, -1, 1] {
        let counter = (time_step as i64 + offset) as u64;
        let expected = generate_totp(&secret, counter);
        if constant_time_eq(code.as_bytes(), expected.as_bytes()) {
            return true;
        }
    }

    false
}

/// Generate a 6-digit TOTP code for the given counter value.
fn generate_totp(secret: &[u8], counter: u64) -> String {
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC accepts any key size");
    mac.update(&counter.to_be_bytes());
    let result = mac.finalize().into_bytes();

    // Dynamic truncation per RFC 4226 §5.4.
    let offset = (result[result.len() - 1] & 0x0f) as usize;
    let code = u32::from_be_bytes([
        result[offset] & 0x7f,
        result[offset + 1],
        result[offset + 2],
        result[offset + 3],
    ]);
    format!("{:06}", code % 1_000_000)
}

/// RS-064: Constant-time byte comparison that does NOT leak length through timing.
/// Uses a dummy comparison loop when lengths differ to avoid short-circuiting.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    let len_matches = a.len() == b.len();
    let mut diff: u8 = 0;
    // Always iterate over both slices fully to avoid timing leaks
    for (x, y) in a.iter().zip(b.iter().chain(std::iter::repeat(&0))) {
        diff |= x ^ y;
    }
    for y in b.iter().skip(a.len()) {
        diff |= *y;
    }
    len_matches && diff == 0
}

/// Decode a base32 string (RFC 4648, no padding required).
fn base32_decode(input: &str) -> Option<Vec<u8>> {
    let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let input = input.trim_end_matches('=').as_bytes();
    let mut bits: u64 = 0;
    let mut bit_count: u32 = 0;
    let mut output = Vec::with_capacity(input.len() * 5 / 8);

    for &c in input {
        let c_upper = c.to_ascii_uppercase();
        let val = match alphabet.iter().position(|&a| a == c_upper) {
            Some(v) => v as u64,
            None => return None,
        };
        bits = (bits << 5) | val;
        bit_count += 5;
        if bit_count >= 8 {
            bit_count -= 8;
            output.push((bits >> bit_count) as u8);
            bits &= (1u64 << bit_count) - 1;
        }
    }
    Some(output)
}

// ── Recovery / Backup Codes ──────────────────────────────────────

fn fill_os_random(bytes: &mut [u8]) -> anyhow::Result<()> {
    OsRng
        .try_fill_bytes(bytes)
        .map_err(|e| anyhow::anyhow!("OsRng failed while generating MFA secret material: {e}"))
}

fn random_recovery_char() -> anyhow::Result<char> {
    let charset_len = RECOVERY_CHARSET.len();
    let rejection_limit = (u8::MAX as usize + 1) / charset_len * charset_len;
    let mut byte = [0u8; 1];

    loop {
        fill_os_random(&mut byte)?;
        let value = byte[0] as usize;
        if value < rejection_limit {
            return Ok(RECOVERY_CHARSET[value % charset_len] as char);
        }
    }
}

/// Fallible recovery code generation using the OS CSPRNG. Prefer this in
/// production paths so rare RNG failures can be surfaced to the caller.
pub fn try_generate_recovery_codes(count: usize) -> anyhow::Result<Vec<String>> {
    (0..count)
        .map(|_| {
            (0..RECOVERY_CODE_LENGTH)
                .map(|_| random_recovery_char())
                .collect::<anyhow::Result<String>>()
        })
        .collect()
}

/// Generate `count` cryptographically random recovery codes.
/// Each code is `RECOVERY_CODE_LENGTH` characters from a charset
/// that excludes ambiguous characters (0/O, 1/I/L).
///
/// Returns the plaintext codes. The caller must hash these before
/// storing, and display them to the user exactly once.
pub fn generate_recovery_codes(count: usize) -> Vec<String> {
    try_generate_recovery_codes(count).expect("OsRng must be available for MFA recovery codes")
}

/// Default count of recovery codes (10).
pub fn generate_default_recovery_codes() -> Vec<String> {
    generate_recovery_codes(RECOVERY_CODE_COUNT)
}

/// Fallible default recovery code generation.
pub fn try_generate_default_recovery_codes() -> anyhow::Result<Vec<String>> {
    try_generate_recovery_codes(RECOVERY_CODE_COUNT)
}

/// Hash a recovery code using **Argon2id** for secure storage.
///
/// # O-19.1
/// Replaced SHA-256 with Argon2id (memory-hard, computationally expensive) to
/// prevent fast offline brute-force attacks if the hash database is compromised.
///
/// Uses a random 16-byte salt per hash. The output is encoded in the PHC string
/// format (`$argon2id$v=19$m=19456,t=2,p=1$<salt>$<hash>`), which includes all
/// parameters needed for verification.
pub fn try_hash_recovery_code(code: &str) -> anyhow::Result<String> {
    use argon2::password_hash::SaltString;
    use argon2::PasswordHasher;

    let mut salt_bytes = [0u8; 16];
    fill_os_random(&mut salt_bytes)?;
    let salt = SaltString::encode_b64(&salt_bytes)
        .map_err(|e| anyhow::anyhow!("Argon2id salt encoding failed: {e}"))?;
    let argon2 = Argon2::default(); // m=19456, t=2, p=1 (recommended for interactive use)
    let hash = argon2
        .hash_password(code.as_bytes(), salt.as_salt())
        .map_err(|e| anyhow::anyhow!("Argon2id hashing failed: {e}"))?;
    Ok(hash.to_string())
}

/// Hash a recovery code using **Argon2id** for secure storage.
///
/// Prefer [`try_hash_recovery_code`] in request paths; this compatibility
/// wrapper preserves the existing API for tests and non-fallible call sites.
pub fn hash_recovery_code(code: &str) -> String {
    try_hash_recovery_code(code).expect("OsRng and Argon2id must be available")
}

/// Verify a recovery code against a stored Argon2id hash.
///
/// Uses Argon2id verification which is inherently constant-time.
pub fn verify_recovery_code(code: &str, stored_hash: &str) -> bool {
    use argon2::PasswordVerifier;
    let argon2 = Argon2::default();
    let parsed_hash = match argon2::PasswordHash::new(stored_hash) {
        Ok(h) => h,
        Err(e) => {
            warn!(error = %e, "Failed to parse stored Argon2id hash");
            return false;
        }
    };
    argon2
        .verify_password(code.as_bytes(), &parsed_hash)
        .is_ok()
}

/// Consume a recovery code: verify it, then ensure it can't be reused.
/// Returns `true` if the code is valid and was consumed (removed from the set).
///
/// `hashes`: mutable list of stored Argon2id hashes.
/// After successful verification, the matching hash is removed.
pub fn consume_recovery_code(code: &str, hashes: &mut Vec<String>) -> bool {
    if let Some(pos) = hashes.iter().position(|h| verify_recovery_code(code, h)) {
        hashes.remove(pos);
        true
    } else {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_base32_decode() {
        // This common OTP example decodes to the 10-byte payload
        // "Hello!\xDE\xAD\xBE\xEF".
        let decoded = base32_decode("JBSWY3DPEHPK3PXP").unwrap();
        assert_eq!(decoded, b"Hello!\xDE\xAD\xBE\xEF");
    }

    #[test]
    fn test_base32_decode_lowercase() {
        let decoded = base32_decode("jbswy3dpehpk3pxp").unwrap();
        assert_eq!(decoded, b"Hello!\xDE\xAD\xBE\xEF");
    }

    #[test]
    fn test_base32_invalid() {
        assert!(base32_decode("JBSWY3DP!@#$").is_none());
    }

    #[test]
    fn test_constant_time_eq() {
        assert!(constant_time_eq(b"123456", b"123456"));
        assert!(!constant_time_eq(b"123456", b"654321"));
        assert!(!constant_time_eq(b"12345", b"123456"));
    }

    #[test]
    fn test_generate_totp_deterministic() {
        let secret = b"12345678901234567890";
        let code1 = generate_totp(secret, 1);
        let code2 = generate_totp(secret, 1);
        assert_eq!(code1, code2);
        assert_eq!(code1.len(), 6);
    }

    #[test]
    fn test_verify_rejects_wrong_length() {
        assert!(!verify_totp_code("JBSWY3DPEHPK3PXP", "12345")); // 5 digits
        assert!(!verify_totp_code("JBSWY3DPEHPK3PXP", "1234567")); // 7 digits
        assert!(!verify_totp_code("JBSWY3DPEHPK3PXP", "abcdef")); // non-digit
    }

    // ── Recovery Code Tests ─────────────────────────────────────

    #[test]
    fn test_generate_recovery_codes_default_count() {
        let codes = generate_default_recovery_codes();
        assert_eq!(codes.len(), 10);
    }

    #[test]
    fn test_generate_recovery_codes_custom_count() {
        let codes = generate_recovery_codes(5);
        assert_eq!(codes.len(), 5);
    }

    #[test]
    fn test_generate_recovery_codes_no_ambiguous_chars() {
        let codes = generate_default_recovery_codes();
        for code in &codes {
            assert_eq!(code.len(), 12);
            // No ambiguous characters: 0, O, 1, I, L
            for c in code.chars() {
                assert!(
                    !matches!(c, '0' | 'O' | '1' | 'I' | 'L'),
                    "recovery code contains ambiguous char '{c}' in {code}"
                );
            }
        }
    }

    #[test]
    fn test_generate_recovery_codes_unique() {
        let codes = generate_recovery_codes(50);
        let mut unique = codes.clone();
        unique.sort();
        unique.dedup();
        assert_eq!(unique.len(), 50, "all recovery codes must be unique");
    }

    #[test]
    fn test_hash_recovery_code_uses_argon2id_phc_format() {
        let code = "ABC123XYZ789";
        let hash = hash_recovery_code(code);
        // Argon2id PHC string format: $argon2id$v=19$m=19456,t=2,p=1$<salt>$<hash>
        assert!(
            hash.starts_with("$argon2id$"),
            "hash should use Argon2id PHC format, got: {hash}"
        );
        // Each call uses a random salt, so two hashes of the same input differ
        let hash2 = hash_recovery_code(code);
        assert_ne!(
            hash, hash2,
            "Argon2id uses random salts so hashes must differ"
        );
    }

    #[test]
    fn test_hash_recovery_code_different_salts() {
        let hash1 = hash_recovery_code("CODE12345678");
        let hash2 = hash_recovery_code("CODE12345678");
        // Same input but different random salts → different hashes
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_verify_recovery_code_valid() {
        let code = "MYRECOVERYCODE";
        let hash = hash_recovery_code(code);
        assert!(verify_recovery_code(code, &hash));
    }

    #[test]
    fn test_verify_recovery_code_invalid() {
        let code = "MYRECOVERYCODE";
        let hash = hash_recovery_code(code);
        assert!(!verify_recovery_code("WRONGCODE", &hash));
    }

    #[test]
    fn test_verify_recovery_code_constant_time_with_wrong_length() {
        // Should not panic on different lengths
        let hash = hash_recovery_code("SHORT");
        assert!(!verify_recovery_code("LONGERRRRCODE", &hash));
    }

    #[test]
    fn test_consume_recovery_code_valid() {
        let code = "CODE1";
        let code2 = "CODE2";
        let hash1 = hash_recovery_code(code);
        let hash2 = hash_recovery_code(code2);
        let mut hashes = vec![hash1.clone(), hash2.clone()];

        assert!(consume_recovery_code(code, &mut hashes));
        assert_eq!(hashes.len(), 1);
        assert_eq!(hashes[0], hash2);
    }

    #[test]
    fn test_consume_recovery_code_invalid() {
        let code = "REALCODE";
        let hash = hash_recovery_code(code);
        let mut hashes = vec![hash];

        assert!(!consume_recovery_code("FAKECODE", &mut hashes));
        assert_eq!(hashes.len(), 1);
    }

    #[test]
    fn test_consume_recovery_code_no_double_use() {
        let code = "SINGLEUSE";
        let hash = hash_recovery_code(code);
        let mut hashes = vec![hash];

        // First use succeeds
        assert!(consume_recovery_code(code, &mut hashes));
        assert!(hashes.is_empty());

        // Second use fails — code was consumed
        assert!(!consume_recovery_code(code, &mut hashes));
    }

    #[test]
    fn test_recovery_code_charset_is_alphanumeric() {
        let codes = generate_default_recovery_codes();
        for code in &codes {
            assert!(
                code.chars().all(|c| c.is_ascii_alphanumeric()),
                "recovery code must be alphanumeric: {code}"
            );
        }
    }

    #[test]
    fn test_recovery_code_cannot_be_empty() {
        let hash = hash_recovery_code("");
        assert!(!verify_recovery_code("NOTEMPTY", &hash));
        // Empty code should hash correctly but not match non-empty
        assert!(verify_recovery_code("", &hash));
    }

    // ── TOTPVerifier Tests ──────────────────────────────────

    #[test]
    fn test_totp_verifier_new_not_locked() {
        let verifier = TOTPVerifier::new();
        assert!(!verifier.is_locked("any_secret"));
    }

    #[test]
    fn test_totp_verifier_locks_after_max_failures() {
        let verifier = TOTPVerifier::new();
        let secret = "JBSWY3DPEHPK3PXP";

        // 5 consecutive failures should lock the secret
        for i in 0..MAX_FAILED_ATTEMPTS {
            if i < MAX_FAILED_ATTEMPTS - 1 {
                assert!(
                    !verifier.record_failure(secret),
                    "should not lock before {MAX_FAILED_ATTEMPTS} failures"
                );
            } else {
                assert!(
                    verifier.record_failure(secret),
                    "should lock on {MAX_FAILED_ATTEMPTS}th failure"
                );
            }
        }

        assert!(verifier.is_locked(secret));
    }

    #[test]
    fn test_totp_verifier_resets_after_success() {
        let verifier = TOTPVerifier::new();
        let secret = "JBSWY3DPEHPK3PXP";

        // 3 failures — not yet locked
        verifier.record_failure(secret);
        verifier.record_failure(secret);
        verifier.record_failure(secret);
        assert!(!verifier.is_locked(secret));

        // Reset clears the counter
        verifier.reset(secret);
        assert!(!verifier.is_locked(secret));

        // After reset, need 5 more failures to lock
        for _ in 0..MAX_FAILED_ATTEMPTS {
            verifier.record_failure(secret);
        }
        assert!(verifier.is_locked(secret));
    }

    #[test]
    fn test_totp_verifier_tracks_per_secret_independently() {
        let verifier = TOTPVerifier::new();
        let secret_a = "AAAAAAAAAAAAAAAAAAAAAAAA";
        let secret_b = "BBBBBBBBBBBBBBBBBBBBBBBB";

        // Lock secret_a
        for _ in 0..MAX_FAILED_ATTEMPTS {
            verifier.record_failure(secret_a);
        }
        assert!(verifier.is_locked(secret_a));
        assert!(
            !verifier.is_locked(secret_b),
            "secret_b must not be affected by failures on secret_a"
        );

        // secret_b can still accumulate failures independently
        verifier.record_failure(secret_b);
        assert!(!verifier.is_locked(secret_b));
    }

    #[test]
    fn test_totp_verifier_verify_rejects_when_locked() {
        let verifier = TOTPVerifier::new();
        let secret = "JBSWY3DPEHPK3PXP";

        // Lock the secret via record_failure
        for _ in 0..MAX_FAILED_ATTEMPTS {
            verifier.record_failure(secret);
        }

        // verify() must return false regardless of code validity
        assert!(!verifier.verify(secret, "123456"));
    }

    #[test]
    fn test_totp_verifier_verify_passes_through_when_not_locked() {
        let verifier = TOTPVerifier::new();
        // An invalid code on an unlocked secret should return false
        // but not because of lockout — it should also not lock after 1 failure
        assert!(!verifier.verify("JBSWY3DPEHPK3PXP", "000000"));
        assert!(!verifier.is_locked("JBSWY3DPEHPK3PXP"));
    }

    #[test]
    fn test_totp_verifier_default_is_send() {
        let verifier = TOTPVerifier::default();
        assert!(!verifier.is_locked("default_test"));
    }
}
