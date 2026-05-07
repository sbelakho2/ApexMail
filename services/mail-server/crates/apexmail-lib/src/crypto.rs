//! Cryptographic utilities — HMAC, hashing, passwords, timing-safe comparison.

use argon2::password_hash::SaltString;
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
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

/// Hash a password using Argon2id.
pub fn hash_password(password: &str) -> Result<String, argon2::password_hash::Error> {
    let mut salt_bytes = [0u8; 16];
    OsRng
        .try_fill_bytes(&mut salt_bytes)
        .map_err(|_| argon2::password_hash::Error::Crypto)?;
    let salt = SaltString::encode_b64(&salt_bytes)?;
    let argon2 = Argon2::default();
    let hash = argon2.hash_password(password.as_bytes(), salt.as_salt())?;
    Ok(hash.to_string())
}

/// Verify a password against an Argon2id hash.
pub fn verify_password(password: &str, hash: &str) -> Result<bool, argon2::password_hash::Error> {
    let parsed = PasswordHash::new(hash)?;
    Ok(Argon2::default()
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
