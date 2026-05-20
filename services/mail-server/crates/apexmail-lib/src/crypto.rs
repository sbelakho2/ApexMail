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

/// Create an HMAC-SHA256 signature and return as hex.
pub fn create_hmac_signature(key: &[u8], data: &[u8]) -> String {
    let mut mac = match HmacSha256::new_from_slice(key) {
        Ok(mac) => mac,
        Err(error) => {
            tracing::error!(?error, "Failed to initialize HMAC-SHA256");
            return String::new();
        }
    };
    mac.update(data);
    hex::encode(mac.finalize().into_bytes())
}

/// Create HMAC-SHA256 and return as base64.
pub fn create_hmac_signature_base64(key: &[u8], data: &[u8]) -> String {
    let mut mac = match HmacSha256::new_from_slice(key) {
        Ok(mac) => mac,
        Err(error) => {
            tracing::error!(?error, "Failed to initialize HMAC-SHA256");
            return String::new();
        }
    };
    mac.update(data);
    BASE64.encode(mac.finalize().into_bytes())
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
        // RS-H-02: Validate Argon2id parameters meet minimum security requirements.
        validate_argon2_params(&parsed)?;
        Ok(argon2_default()
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

/// Determine the hash version used for a stored API key hash.
pub fn detect_api_key_hash_version(stored_hash: &str) -> ApiKeyHashVersion {
    if stored_hash.starts_with("$argon2") {
        ApiKeyHashVersion::Argon2id
    } else if stored_hash.len() == 64 && stored_hash.chars().all(|c| c.is_ascii_hexdigit()) {
        // 64-char hex = SHA-256 digest
        // HMAC-SHA256 also produces 64-char hex output, so we can't distinguish
        // between plain SHA-256 and HMAC-SHA256 based on format alone.
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
/// acceptable parameters.  Called during [`verify_password`] to detect legacy
/// hashes that were created with weak settings.
///
/// RS-H-02: Validates algorithm, memory cost, time cost, and parallelism
/// against minimum recommended values. Rejects hashes with weak parameters
/// that could be brute-forced.
fn validate_argon2_params(hash: &PasswordHash) -> Result<(), argon2::password_hash::Error> {
    // Verify the algorithm is Argon2id
    let alg = hash.algorithm.as_str();
    if alg != "argon2id" {
        tracing::warn!(algorithm = %alg, "rejected non-argon2id password hash");
        return Err(argon2::password_hash::Error::Algorithm);
    }

    // Validate parameters from the PHC string
    {
        let params = &hash.params;
        // Check memory cost (m=) — minimum 19456 KiB (19 MiB, OWASP recommendation)
        if let Some(m_val) = params.get("m") {
            if let Ok(m_cost) = m_val.as_str().parse::<u32>() {
                if m_cost < OWASP_M_COST {
                    tracing::warn!(
                        m_cost = m_cost,
                        minimum = OWASP_M_COST,
                        "rejected argon2id hash with insufficient memory cost"
                    );
                    return Err(argon2::password_hash::Error::Crypto);
                }
            }
        }

        // Check time cost (t=) — minimum 2 iterations
        if let Some(t_val) = params.get("t") {
            if let Ok(t_cost) = t_val.as_str().parse::<u32>() {
                if t_cost < OWASP_T_COST {
                    tracing::warn!(
                        t_cost = t_cost,
                        minimum = OWASP_T_COST,
                        "rejected argon2id hash with insufficient time cost"
                    );
                    return Err(argon2::password_hash::Error::Crypto);
                }
            }
        }

        // Check parallelism (p=) — minimum 1
        if let Some(p_val) = params.get("p") {
            if let Ok(p_cost) = p_val.as_str().parse::<u32>() {
                if p_cost < OWASP_P_COST {
                    tracing::warn!(
                        p_cost = p_cost,
                        minimum = OWASP_P_COST,
                        "rejected argon2id hash with insufficient parallelism"
                    );
                    return Err(argon2::password_hash::Error::Crypto);
                }
            }
        }
    }

    Ok(())
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
/// argon2d).  Parameter-level checking is enforced at hash-creation time via
/// [`hash_password`] which uses the OWASP-recommended constants.
pub fn verify_password(password: &str, hash: &str) -> Result<bool, argon2::password_hash::Error> {
    let parsed = PasswordHash::new(hash)?;
    // RS-H-02: Validate algorithm is Argon2id.
    validate_argon2_params(&parsed)?;
    Ok(argon2_default()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok())
}

/// Verify a password for login and return an Argon2id replacement hash when
/// a legacy bcrypt hash authenticates successfully.
pub fn verify_password_for_login(
    password: &str,
    hash: &str,
) -> Result<PasswordVerification, PasswordVerificationError> {
    if hash.starts_with("$argon2") {
        return Ok(PasswordVerification {
            valid: verify_password(password, hash)?,
            migrated_hash: None,
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
}
