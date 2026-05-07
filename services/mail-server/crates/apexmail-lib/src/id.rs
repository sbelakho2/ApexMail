//! ID generation — nanoid, API key prefixes.

use nanoid::nanoid;
use rand::rngs::OsRng;
use rand::TryRngCore;

const DEFAULT_ALPHABET: [char; 36] = [
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i',
    'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
];

const API_KEY_ALPHABET: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

/// Generate a nano ID with an optional prefix.
pub fn generate_id(prefix: &str, length: usize) -> String {
    let id = nanoid!(length, &DEFAULT_ALPHABET);
    if prefix.is_empty() {
        id
    } else {
        format!("{}_{}", prefix, id)
    }
}

/// Generate an API key with the `am_live_` or `am_test_` prefix.
///
/// Uses `OsRng` (cryptographically secure) for key generation, not the
/// non-crypto PRNG used by nanoid. The generated key is 32 characters
/// of alphanumeric characters (upper + lower + digits) for high entropy.
pub fn generate_api_key(is_test: bool) -> String {
    let prefix = if is_test { "am_test" } else { "am_live" };

    // Generate 32 alphanumeric characters using OsRng (cryptographically secure)
    let mut key_bytes = [0u8; 32];
    OsRng
        .try_fill_bytes(&mut key_bytes)
        .expect("OsRng should not fail");

    let random_part: String = key_bytes
        .iter()
        .map(|&b| API_KEY_ALPHABET[(b as usize) % API_KEY_ALPHABET.len()] as char)
        .collect();

    format!("{}_{}", prefix, random_part)
}

/// Generate a request ID.
pub fn generate_request_id() -> String {
    generate_id("req", 16)
}

/// Generate a webhook signing key.
pub fn generate_webhook_secret() -> String {
    generate_id("whsec", 24)
}

/// Generate an email verification token.
pub fn generate_verification_token() -> String {
    generate_id("vfy", 32)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_id() {
        let id = generate_id("msg", 16);
        assert!(id.starts_with("msg_"));
        assert_eq!(id.len(), 4 + 16); // "msg_" + 16 chars
    }

    #[test]
    fn test_generate_id_no_prefix() {
        let id = generate_id("", 20);
        assert_eq!(id.len(), 20);
        assert!(!id.contains('_'));
    }

    #[test]
    fn test_generate_api_key() {
        let key = generate_api_key(false);
        assert!(key.starts_with("am_live_"));
        let key_test = generate_api_key(true);
        assert!(key_test.starts_with("am_test_"));
    }

    #[test]
    fn test_uniqueness() {
        let a = generate_id("", 20);
        let b = generate_id("", 20);
        assert_ne!(a, b);
    }

    #[test]
    fn test_request_id() {
        let id = generate_request_id();
        assert!(id.starts_with("req_"));
    }

    #[test]
    fn test_webhook_secret() {
        let s = generate_webhook_secret();
        assert!(s.starts_with("whsec_"));
    }
}
