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

/// F: generate `len` characters from `alphabet` using OsRng with rejection
/// sampling (no modulo bias). Shared by the security-sensitive generators
/// (webhook secrets, verification tokens) — the nanoid path is NOT used for
/// secrets because its PRNG is not cryptographically secure.
fn generate_secure_from_alphabet(alphabet: &[u8], len: usize) -> Result<String, String> {
    use rand::rngs::OsRng;
    use rand::TryRngCore;

    if alphabet.is_empty() {
        return Err("alphabet must not be empty".into());
    }
    // Largest multiple of alphabet.len() that fits in u8 — values above it
    // are rejected and redrawn so every character is equally likely.
    let alphabet_len = alphabet.len() as u16;
    let bound = (256u32 / alphabet_len as u32 * alphabet_len as u32) as u8;
    let mut out = String::with_capacity(len);
    let mut bytes = [0u8; 64];
    let mut filled = 0;
    while out.len() < len {
        if filled == 0 {
            OsRng
                .try_fill_bytes(&mut bytes)
                .map_err(|e| format!("OsRng failure: {e}"))?;
            filled = bytes.len();
        }
        filled -= 1;
        let b = bytes[filled];
        if b < bound {
            out.push(alphabet[(b as usize) % alphabet.len()] as char);
        }
    }
    Ok(out)
}

/// Generate a webhook signing key (F: CSPRNG-backed, 24 chars of [0-9a-z],
/// same length/format as the previous nanoid implementation but drawn from
/// OsRng with rejection sampling).
pub fn generate_webhook_secret() -> String {
    let body = generate_secure_from_alphabet(DEFAULT_ALPHABET_MAP, 24)
        .expect("OsRng-backed generation should not fail");
    format!("whsec_{body}")
}

/// Generate an email verification token (F: CSPRNG-backed, 32 chars of
/// [0-9a-z]).
pub fn generate_verification_token() -> String {
    let body = generate_secure_from_alphabet(DEFAULT_ALPHABET_MAP, 32)
        .expect("OsRng-backed generation should not fail");
    format!("vfy_{body}")
}

/// The DEFAULT_ALPHABET as bytes ([0-9a-z], 36 chars).
const DEFAULT_ALPHABET_MAP: &[u8] = b"0123456789abcdefghijklmnopqrstuvwxyz";

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

    // ── F: CSPRNG-backed secret generators ─────────────────────────────

    #[test]
    fn webhook_secret_length_and_charset() {
        for _ in 0..100 {
            let s = generate_webhook_secret();
            assert!(s.starts_with("whsec_"), "got {s}");
            let body = &s["whsec_".len()..];
            assert_eq!(body.len(), 24, "length preserved: {s}");
            assert!(
                body.chars().all(|c| c.is_ascii_digit() || c.is_ascii_lowercase()),
                "alphanumeric charset only: {s}"
            );
        }
    }

    #[test]
    fn verification_token_length_and_charset() {
        for _ in 0..100 {
            let s = generate_verification_token();
            assert!(s.starts_with("vfy_"), "got {s}");
            let body = &s["vfy_".len()..];
            assert_eq!(body.len(), 32, "length preserved: {s}");
            assert!(
                body.chars().all(|c| c.is_ascii_digit() || c.is_ascii_lowercase()),
                "alphanumeric charset only: {s}"
            );
        }
    }

    #[test]
    fn secret_generators_unique_over_10k_draws() {
        // Note: the entropy SOURCE itself cannot be asserted from userland —
        // these tests pin length, charset, and collision-freedom of the
        // output distribution.
        let mut seen = std::collections::HashSet::new();
        for _ in 0..10_000 {
            assert!(seen.insert(generate_webhook_secret()));
            assert!(seen.insert(generate_verification_token()));
        }
    }

    #[test]
    fn secure_alphabet_rejects_empty() {
        assert!(generate_secure_from_alphabet(b"", 8).is_err());
    }
}
