//! Cryptographic utilities — HMAC, hashing, passwords, timing-safe comparison.

use hmac::{Hmac, Mac};
use sha2::Sha256;
use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier, password_hash::SaltString};
use rand::rngs::OsRng;

type HmacSha256 = Hmac<Sha256>;

/// Create an HMAC-SHA256 signature and return as hex.
pub fn create_hmac_signature(key: &[u8], data: &[u8]) -> String {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data);
    hex::encode(mac.finalize().into_bytes())
}

/// Create HMAC-SHA256 and return as base64.
pub fn create_hmac_signature_base64(key: &[u8], data: &[u8]) -> String {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data);
    BASE64.encode(mac.finalize().into_bytes())
}

/// Timing-safe comparison of two strings (constant-time).
pub fn timing_safe_compare(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut result: u8 = 0;
    for (x, y) in a.bytes().zip(b.bytes()) {
        result |= x ^ y;
    }
    result == 0
}

/// Hash an API key using SHA-256.
pub fn hash_api_key(key: &str) -> String {
    use sha2::Digest;
    let hash = Sha256::digest(key.as_bytes());
    hex::encode(hash)
}

/// Hash a password using Argon2id.
pub fn hash_password(password: &str) -> Result<String, argon2::password_hash::Error> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let hash = argon2.hash_password(password.as_bytes(), &salt)?;
    Ok(hash.to_string())
}

/// Verify a password against an Argon2id hash.
pub fn verify_password(password: &str, hash: &str) -> Result<bool, argon2::password_hash::Error> {
    let parsed = PasswordHash::new(hash)?;
    Ok(Argon2::default().verify_password(password.as_bytes(), &parsed).is_ok())
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
}
