//! Cryptographic utilities — HMAC, hashing, passwords, timing-safe comparison.

use argon2::password_hash::SaltString;
use argon2::{Algorithm, Argon2, Params, PasswordHash, PasswordHasher, PasswordVerifier, Version};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use hmac::{Hmac, Mac};
use rand::rngs::OsRng;
use rand::TryRngCore;
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;
const BCRYPT_HASH_LEN: usize = 60;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasswordVerification {
    pub valid: bool,
    pub migrated_hash: Option<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum PasswordVerificationError {
    #[error("argon2 password hash error: {0}")]
    Argon2(#[from] argon2::password_hash::Error),
    #[error("bcrypt password hash error: {0}")]
    Bcrypt(#[from] bcrypt::BcryptError),
    #[error("unsupported password hash scheme")]
    UnsupportedScheme,
}

/// Fallible HMAC-SHA256 signature as hex — the canonical constructor.
///
/// `new_from_slice` only fails on key-length errors, which are structurally
/// unreachable for HMAC (any key length, including empty, is accepted), so
/// callers of the [`create_hmac_signature`] wrapper may treat failure as an
/// invariant violation — but this form makes the (theoretical) failure
/// explicit instead of silently yielding an empty signature string.
pub fn try_create_hmac_signature(
    key: &[u8],
    data: &[u8],
) -> Result<String, hmac::digest::InvalidLength> {
    let mut mac = HmacSha256::new_from_slice(key)?;
    mac.update(data);
    Ok(hex::encode(mac.finalize().into_bytes()))
}

/// Create an HMAC-SHA256 signature and return as hex.
///
/// Delegates to [`try_create_hmac_signature`]. The error branch is
/// unreachable for HMAC (any key length is valid), so it panics loudly on
/// the invariant instead of the previous behavior of returning `String::new()`
/// — an empty string that callers could not distinguish from a real
/// signature and that silently disabled signature checks downstream.
pub fn create_hmac_signature(key: &[u8], data: &[u8]) -> String {
    try_create_hmac_signature(key, data).expect("HMAC-SHA256 accepts keys of any length")
}

/// Fallible HMAC-SHA256 signature as base64 — see
/// [`try_create_hmac_signature`] for why the fallible form exists.
pub fn try_create_hmac_signature_base64(
    key: &[u8],
    data: &[u8],
) -> Result<String, hmac::digest::InvalidLength> {
    let mut mac = HmacSha256::new_from_slice(key)?;
    mac.update(data);
    Ok(BASE64.encode(mac.finalize().into_bytes()))
}

/// Create HMAC-SHA256 and return as base64.
///
/// Delegates to [`try_create_hmac_signature_base64`]; the error branch is
/// unreachable for HMAC, so it panics on the invariant rather than
/// returning an empty string (see [`create_hmac_signature`]).
pub fn create_hmac_signature_base64(key: &[u8], data: &[u8]) -> String {
    try_create_hmac_signature_base64(key, data).expect("HMAC-SHA256 accepts keys of any length")
}

/// Timing-safe comparison of two strings (constant-time).
/// Does NOT short-circuit on length difference — we use a dummy comparison
/// to avoid leaking the length of the expected value.
pub fn timing_safe_compare(a: &str, b: &str) -> bool {
    let a_bytes = a.as_bytes();
    let b_bytes = b.as_bytes();
    let len_matches = a_bytes.len() == b_bytes.len();

    // Always iterate over at least one full pass to avoid timing leaks.
    // Compare against the first string if lengths differ (result is discarded).
    let compare_against = if len_matches { b_bytes } else { a_bytes };
    let mut result: u8 = 0;
    for (x, y) in a_bytes.iter().zip(compare_against.iter()) {
        result |= x ^ y;
    }
    len_matches && result == 0
}

/// Hash an API key using SHA-256 (backward-compatible, for migration).
/// # Deprecated
/// Use [`hash_api_key_argon2`] or [`hash_api_key_with_secret`] instead.
/// Plain SHA-256 is trivially brute-forced at ~10 GHash/s and MUST NOT
/// be used for new keys.
pub fn hash_api_key(key: &str) -> String {
    use sha2::Digest;
    let hash = Sha256::digest(key.as_bytes());
    hex::encode(hash)
}

/// Hash an API key using HMAC-SHA256 with a secret.
/// This is the preferred method — the secret prevents offline brute-force
/// even if the database is leaked.
pub fn hash_api_key_with_secret(key: &str, secret: &str) -> String {
    create_hmac_signature(secret.as_bytes(), key.as_bytes())
}

/// Hash an API key using Argon2id (memory-hard, recommended for new keys).
/// The returned string encodes the salt and parameters, suitable for
/// direct storage in the `api_keys.key_hash` column.
///
/// ## Hash versioning
/// The output is prefixed with `$argon2id$` for algorithm detection.
/// Use [`verify_api_key_hash`] to verify and optionally re-hash.
pub fn hash_api_key_argon2(key: &str) -> Result<String, argon2::password_hash::Error> {
    let mut salt_bytes = [0u8; 16];
    OsRng
        .try_fill_bytes(&mut salt_bytes)
        .map_err(|_| argon2::password_hash::Error::Crypto)?;
    let salt = SaltString::encode_b64(&salt_bytes)?;
    let argon2 = argon2_default();
    let hash = argon2.hash_password(key.as_bytes(), salt.as_salt())?;
    Ok(hash.to_string())
}

/// Verify an API key against a stored hash (supports both Argon2id and
/// HMAC-SHA256 — the two actively-used schemes).  Returns `Ok(true)` if
/// the key matches, `Ok(false)` otherwise.
///
/// For plain SHA-256 legacy hashes, use [`hash_api_key`] and compare directly.
pub fn verify_api_key_hash(
    key: &str,
    stored_hash: &str,
) -> Result<bool, argon2::password_hash::Error> {
    if stored_hash.starts_with("$argon2") {
        let parsed = PasswordHash::new(stored_hash)?;
        // RS-H-02: the ALGORITHM must be Argon2id. Parameter strength is no
        // longer a hard gate (audit F11): a weak-param legacy hash used to
        // brick every verification of that API key. Verification runs
        // against the hash's own embedded params; callers can detect the
        // weak case via argon2_params_below_owasp semantics and rotate.
        validate_argon2_params(&parsed)?;
        Ok(Argon2::default()
            .verify_password(key.as_bytes(), &parsed)
            .is_ok())
    } else if stored_hash.starts_with("$2") {
        // Legacy bcrypt-encoded API keys (rare, but handle gracefully)
        Ok(bcrypt::verify(key, stored_hash).unwrap_or(false))
    } else {
        // Assume HMAC-SHA256 or plain SHA-256 — caller must compare externally
        Err(argon2::password_hash::Error::Crypto)
    }
}

/// Detect the API key hash algorithm version from the stored hash string.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApiKeyHashVersion {
    /// Plain SHA-256 (legacy, weak — must migrate)
    Sha256,
    /// HMAC-SHA256 with a server secret
    HmacSha256,
    /// Argon2id (memory-hard, recommended)
    Argon2id,
    /// Unknown or unsupported format
    Unknown,
}

impl std::fmt::Display for ApiKeyHashVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Sha256 => write!(f, "SHA-256"),
            Self::HmacSha256 => write!(f, "HMAC-SHA256"),
            Self::Argon2id => write!(f, "Argon2id"),
            Self::Unknown => write!(f, "unknown"),
        }
    }
}

/// Determine the hash version used for a stored API key hash — a
/// **shape-based heuristic**, not a definitive identification.
///
/// # Limitations
/// A 64-character lowercase-hex digest is returned as
/// [`ApiKeyHashVersion::HmacSha256`], but plain SHA-256 and HMAC-SHA256
/// digests have exactly the same shape and are indistinguishable by
/// inspection: both are 64 hex characters with no algorithm tag. Callers
/// must not treat this result as proof of scheme — use it only to decide
/// which *verification* strategy to attempt (try HMAC first, then plain
/// SHA-256), and never to conclude that a legacy plain-SHA-256 hash has
/// already been migrated. The unambiguous cases are the self-describing
/// PHC prefixes (`$argon2…`); everything else is a heuristic.
pub fn detect_api_key_hash_version(stored_hash: &str) -> ApiKeyHashVersion {
    if stored_hash.starts_with("$argon2") {
        ApiKeyHashVersion::Argon2id
    } else if stored_hash.len() == 64 && stored_hash.chars().all(|c| c.is_ascii_hexdigit()) {
        // 64-char hex: SHA-256 and HMAC-SHA256 are indistinguishable by
        // shape — reported as HmacSha256 (the actively-written scheme), see
        // the function-level limitation note above.
        ApiKeyHashVersion::HmacSha256
    } else {
        ApiKeyHashVersion::Unknown
    }
}

/// OWASP-recommended Argon2id parameters for interactive password hashing (as of 2024):
///   - Algorithm: Argon2id (hybrid, resistant to both GPU and side-channel attacks)
///   - Memory cost: 19 MiB (m=19456 KiB)
///   - Time cost: 2 iterations (t=2)
///   - Parallelism: 1 lane (p=1)
///   - Salt: 16 bytes (generated from OS random)
const OWASP_M_COST: u32 = 19456;
const OWASP_T_COST: u32 = 2;
const OWASP_P_COST: u32 = 1;

/// Construct an [`Argon2`] context with the OWASP-recommended parameters.
///
/// # Panics
/// Panics only if the parameters are invalid for the platform — this is a
/// compile-time constant set that should always be valid. A panic indicates
/// a fundamental issue with the `argon2` crate or the underlying platform.
fn argon2_default() -> Argon2<'static> {
    let params = Params::new(OWASP_M_COST, OWASP_T_COST, OWASP_P_COST, None)
        .expect("OWASP Argon2id params (m=19456, t=2, p=1) must be valid");
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
}

/// Validate that a parsed Argon2id [`PasswordHash`] uses at least the minimum
/// acceptable parameters.
///
/// RS-H-02: Validates algorithm, memory cost, time cost, and parallelism
/// against minimum recommended values.
///
/// NOTE (audit F11): this check is now used to CLASSIFY a hash, not to
/// reject it at verification time. A weak-but-parseable Argon2id hash is
/// still verified against its OWN embedded params and transparently
/// migrated by [`verify_password_for_login`] / flagged by
/// [`argon2_params_below_owasp`] — a hard failure here used to permanently
/// lock out any pre-OWASP account.
fn validate_argon2_params(hash: &PasswordHash) -> Result<(), argon2::password_hash::Error> {
    // Verify the algorithm is Argon2id
    let alg = hash.algorithm.as_str();
    if alg != "argon2id" {
        tracing::warn!(algorithm = %alg, "rejected non-argon2id password hash");
        return Err(argon2::password_hash::Error::Algorithm);
    }
    Ok(())
}

/// True when a parsed (already algorithm-validated) Argon2id hash carries
/// parameters below the OWASP recommendations — i.e. it should be re-hashed
/// with [`hash_password`] after the next successful login.
fn argon2_params_below_owasp(hash: &PasswordHash) -> bool {
    let params = &hash.params;
    let m_cost = params
        .get("m")
        .and_then(|v| v.as_str().parse::<u32>().ok())
        .unwrap_or(0);
    let t_cost = params
        .get("t")
        .and_then(|v| v.as_str().parse::<u32>().ok())
        .unwrap_or(0);
    let p_cost = params
        .get("p")
        .and_then(|v| v.as_str().parse::<u32>().ok())
        .unwrap_or(0);
    m_cost < OWASP_M_COST || t_cost < OWASP_T_COST || p_cost < OWASP_P_COST
}

/// Hash a password using Argon2id with OWASP-recommended parameters.
///
/// ## Security properties
/// - Argon2id (hybrid resistant to both GPU and side-channel attacks)
/// - 19 MiB memory cost (m=19456)
/// - 2 iterations (t=2)
/// - 1 parallelism lane (p=1)
/// - 16-byte random salt
pub fn hash_password(password: &str) -> Result<String, argon2::password_hash::Error> {
    let mut salt_bytes = [0u8; 16];
    OsRng
        .try_fill_bytes(&mut salt_bytes)
        .map_err(|_| argon2::password_hash::Error::Crypto)?;
    let salt = SaltString::encode_b64(&salt_bytes)?;
    let argon2 = argon2_default();
    let hash = argon2.hash_password(password.as_bytes(), salt.as_salt())?;
    Ok(hash.to_string())
}

/// Verify a password against an Argon2id hash.
///
/// ## Parameter validation
/// Verifies that the stored hash uses the Argon2id algorithm (not argon2i or
/// argon2d). A hash with WEAK but valid parameters (audit F11: e.g. a
/// pre-OWASP `m<19456` / `t<2` row) is still verified against its own
/// embedded parameters — the previous hard failure turned a weak hash into
/// a permanent login lockout with no migration path. Use
/// [`verify_password_for_login`] to obtain an upgraded hash.
pub fn verify_password(password: &str, hash: &str) -> Result<bool, argon2::password_hash::Error> {
    let parsed = PasswordHash::new(hash)?;
    // RS-H-02: Validate algorithm is Argon2id.
    validate_argon2_params(&parsed)?;
    // Verification uses the params embedded in the PHC string, so a legacy
    // weak hash authenticates against its own (weak) parameters here; the
    // caller migrates it forward (see verify_password_for_login).
    Ok(Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok())
}

/// Verify a password for login and return an Argon2id replacement hash when
/// a legacy bcrypt hash OR a weak-parameter Argon2id hash (audit F11)
/// authenticates successfully.
pub fn verify_password_for_login(
    password: &str,
    hash: &str,
) -> Result<PasswordVerification, PasswordVerificationError> {
    if hash.starts_with("$argon2") {
        let parsed = PasswordHash::new(hash)?;
        validate_argon2_params(&parsed)?;
        let valid = Argon2::default()
            .verify_password(password.as_bytes(), &parsed)
            .is_ok();
        // Weak-but-valid Argon2 params get the same transparent upgrade the
        // bcrypt path already had: verify against the stored params, then
        // re-hash with the OWASP defaults so the row converges on login.
        let migrated_hash = if valid && argon2_params_below_owasp(&parsed) {
            Some(hash_password(password)?)
        } else {
            None
        };
        return Ok(PasswordVerification {
            valid,
            migrated_hash,
        });
    }

    if is_bcrypt_prefix(hash) {
        if !is_valid_bcrypt_hash(hash) {
            return Ok(PasswordVerification {
                valid: false,
                migrated_hash: None,
            });
        }

        let valid = bcrypt::verify(password, hash)?;
        let migrated_hash = if valid {
            Some(hash_password(password)?)
        } else {
            None
        };

        return Ok(PasswordVerification {
            valid,
            migrated_hash,
        });
    }

    Err(PasswordVerificationError::UnsupportedScheme)
}

pub fn is_valid_bcrypt_hash(hash: &str) -> bool {
    let bytes = hash.as_bytes();
    if hash.len() != BCRYPT_HASH_LEN || !is_bcrypt_prefix(hash) {
        return false;
    }

    if bytes.get(6) != Some(&b'$') || !bytes[4..6].iter().all(u8::is_ascii_digit) {
        return false;
    }

    bytes[7..].iter().all(|byte| {
        matches!(
            byte,
            b'.' | b'/' | b'0'..=b'9' | b'A'..=b'Z' | b'a'..=b'z'
        )
    })
}

fn is_bcrypt_prefix(hash: &str) -> bool {
    hash.starts_with("$2a$") || hash.starts_with("$2b$") || hash.starts_with("$2y$")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hmac_signature() {
        let sig = create_hmac_signature(b"secret", b"hello world");
        assert_eq!(sig.len(), 64); // hex-encoded SHA-256 = 64 chars
                                   // Deterministic
        let sig2 = create_hmac_signature(b"secret", b"hello world");
        assert_eq!(sig, sig2);
    }

    #[test]
    fn test_hmac_base64() {
        let sig = create_hmac_signature_base64(b"secret", b"test");
        assert!(!sig.is_empty());
        // Should be valid base64
        assert!(BASE64.decode(&sig).is_ok());
    }

    #[test]
    fn hmac_signatures_never_silently_empty() {
        // Regression: the constructors used to return "" on (unreachable)
        // key-length errors. HMAC accepts any key length — including empty
        // — so every input must produce a full-length signature.
        for key in [&b""[..], b"k", b"secret", &[0u8; 256][..]] {
            let hex_sig = create_hmac_signature(key, b"payload");
            assert_eq!(hex_sig.len(), 64, "hex signature is 64 chars");
            let b64_sig = create_hmac_signature_base64(key, b"payload");
            assert_eq!(b64_sig.len(), 44, "base64 signature is 44 chars");
            // Fallible forms agree with the wrappers.
            assert_eq!(try_create_hmac_signature(key, b"payload").unwrap(), hex_sig);
            assert_eq!(
                try_create_hmac_signature_base64(key, b"payload").unwrap(),
                b64_sig
            );
        }
    }

    #[test]
    fn hash_version_detection_is_a_shape_heuristic() {
        // Unambiguous, self-describing formats.
        assert_eq!(
            detect_api_key_hash_version("$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$hash"),
            ApiKeyHashVersion::Argon2id
        );
        assert_eq!(
            detect_api_key_hash_version("junk"),
            ApiKeyHashVersion::Unknown
        );
        // 64-hex is reported as HmacSha256 even though a plain SHA-256
        // digest has the identical shape — documented limitation.
        assert_eq!(
            detect_api_key_hash_version(&hash_api_key("am_live_x")),
            ApiKeyHashVersion::HmacSha256
        );
    }

    #[test]
    fn test_timing_safe_compare() {
        assert!(timing_safe_compare("abc", "abc"));
        assert!(!timing_safe_compare("abc", "abd"));
        assert!(!timing_safe_compare("abc", "ab"));
        assert!(!timing_safe_compare("", "a"));
        assert!(timing_safe_compare("", ""));
    }

    #[test]
    fn test_hash_api_key() {
        let hash = hash_api_key("am_live_abc123");
        assert_eq!(hash.len(), 64);
        // Deterministic
        assert_eq!(hash, hash_api_key("am_live_abc123"));
        // Different key → different hash
        assert_ne!(hash, hash_api_key("am_live_xyz789"));
    }

    #[test]
    fn test_password_hash_and_verify() {
        let hash = hash_password("my_secure_password").unwrap();
        assert!(hash.starts_with("$argon2"));
        assert!(verify_password("my_secure_password", &hash).unwrap());
        assert!(!verify_password("wrong_password", &hash).unwrap());
    }

    #[test]
    fn test_password_hash_unique_salts() {
        let h1 = hash_password("test").unwrap();
        let h2 = hash_password("test").unwrap();
        assert_ne!(h1, h2); // Different salts produce different hashes
    }

    #[test]
    fn test_bcrypt_login_verification_returns_argon2_migration_hash() {
        let bcrypt_hash = bcrypt::hash("legacy-password", 4).unwrap();
        let result = verify_password_for_login("legacy-password", &bcrypt_hash).unwrap();

        assert!(result.valid);
        let migrated_hash = result.migrated_hash.expect("migration hash");
        assert!(migrated_hash.starts_with("$argon2"));
        assert!(verify_password("legacy-password", &migrated_hash).unwrap());
    }

    #[test]
    fn test_bcrypt_login_verification_does_not_migrate_wrong_password() {
        let bcrypt_hash = bcrypt::hash("legacy-password", 4).unwrap();
        let result = verify_password_for_login("wrong-password", &bcrypt_hash).unwrap();

        assert!(!result.valid);
        assert!(result.migrated_hash.is_none());
    }

    #[test]
    fn test_bcrypt_login_verification_rejects_malformed_hash_length() {
        let bcrypt_hash = bcrypt::hash("legacy-password", 4).unwrap();
        let truncated = &bcrypt_hash[..bcrypt_hash.len() - 1];
        let result = verify_password_for_login("legacy-password", truncated).unwrap();

        assert!(!result.valid);
        assert!(result.migrated_hash.is_none());
    }

    // ── Audit F11: weak-parameter Argon2id hashes verify and migrate ──

    /// Build a hash with BELOW-OWASP Argon2id params (m=8192, t=1, p=1),
    /// like a pre-OWASP database row.
    fn weak_argon2_hash(password: &str) -> String {
        let params = Params::new(8192, 1, 1, None).expect("weak params must be constructible");
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        let salt = SaltString::generate(&mut argon2::password_hash::rand_core::OsRng);
        argon2
            .hash_password(password.as_bytes(), &salt)
            .expect("weak hash must encode")
            .to_string()
    }

    #[test]
    fn weak_param_hash_parses_and_is_detected() {
        let hash = weak_argon2_hash("legacy-user-password");
        assert!(hash.starts_with("$argon2id$v=19$m=8192,t=1,p=1$"), "{hash}");
        let parsed = PasswordHash::new(&hash).unwrap();
        assert!(
            validate_argon2_params(&parsed).is_ok(),
            "argon2id algorithm"
        );
        assert!(argon2_params_below_owasp(&parsed));
        // The OWASP-hash path must NOT be flagged.
        let strong = hash_password("legacy-user-password").unwrap();
        assert!(!argon2_params_below_owasp(
            &PasswordHash::new(&strong).unwrap()
        ));
    }

    #[test]
    fn verify_password_accepts_weak_param_hash_instead_of_locking_out() {
        // Pre-fix behavior: verify_password returned Err for weak params —
        // a permanent login lockout with no migration path.
        let hash = weak_argon2_hash("legacy-user-password");
        assert_eq!(verify_password("legacy-user-password", &hash), Ok(true));
        assert_eq!(verify_password("wrong-password", &hash), Ok(false));
        // Non-argon2id algorithms still fail closed.
        let argon2i = hash.replacen("argon2id", "argon2i", 1);
        assert!(verify_password("legacy-user-password", &argon2i).is_err());
    }

    #[test]
    fn login_verification_migrates_weak_param_hash_to_owasp_params() {
        let hash = weak_argon2_hash("legacy-user-password");
        let result = verify_password_for_login("legacy-user-password", &hash).unwrap();
        assert!(result.valid, "weak-param hash must still authenticate");
        let migrated = result.migrated_hash.expect("weak hash must migrate");
        assert!(
            migrated.starts_with("$argon2id$v=19$m=19456,t=2,p=1$"),
            "replacement must use OWASP params: {migrated}"
        );
        assert!(verify_password("legacy-user-password", &migrated).unwrap());
        assert!(!argon2_params_below_owasp(
            &PasswordHash::new(&migrated).unwrap()
        ));

        // A WRONG password on a weak hash must not mint a migration hash.
        let result = verify_password_for_login("wrong-password", &hash).unwrap();
        assert!(!result.valid);
        assert!(result.migrated_hash.is_none());

        // An OWASP-param hash verifies with no migration.
        let strong = hash_password("legacy-user-password").unwrap();
        let result = verify_password_for_login("legacy-user-password", &strong).unwrap();
        assert!(result.valid);
        assert!(result.migrated_hash.is_none());
    }

    #[test]
    fn api_key_verification_accepts_weak_param_hash() {
        // Pre-fix: verify_api_key_hash propagated the param-validation error
        // and bricked every legacy API key.
        let key = "am_live_legacy_key";
        let hash = weak_argon2_hash(key);
        assert_eq!(verify_api_key_hash(key, &hash), Ok(true));
        assert_eq!(verify_api_key_hash("am_live_other", &hash), Ok(false));
    }
}
