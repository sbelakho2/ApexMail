//! Email hashing helpers for privacy-preserving analytics cache keys.

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

/// HMAC-SHA256 salted hash of an email for privacy (O-11.5).
///
/// When `key` is non-empty, HMAC-SHA256 is used with the key as salt.
/// When `key` is empty, falls back to bare SHA-256 for backward compatibility.
pub fn hash_email(email: &str, key: &str) -> String {
    if key.is_empty() {
        let mut hasher = Sha256::new();
        hasher.update(email.as_bytes());
        format!("{:x}", hasher.finalize())
    } else {
        let mut mac =
            Hmac::<Sha256>::new_from_slice(key.as_bytes()).expect("HMAC key should be valid");
        mac.update(email.as_bytes());
        format!("{:x}", mac.finalize().into_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bare_hash_is_deterministic() {
        let hash = hash_email("user@example.com", "");
        assert_eq!(hash.len(), 64);
        assert_eq!(hash, hash_email("user@example.com", ""));
        assert_ne!(hash, hash_email("other@example.com", ""));
    }

    #[test]
    fn keyed_hash_differs_from_bare_hash() {
        let bare_hash = hash_email("user@example.com", "");
        let keyed_hash = hash_email("user@example.com", "analytics-hmac-key");
        assert_eq!(keyed_hash.len(), 64);
        assert_ne!(bare_hash, keyed_hash);
        assert_eq!(
            keyed_hash,
            hash_email("user@example.com", "analytics-hmac-key")
        );
    }
}
