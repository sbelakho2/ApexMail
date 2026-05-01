//! TOTP (Time-based One-Time Password) verification — RFC 6238 with HMAC-SHA256.

use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// Time step in seconds (standard TOTP interval).
const TIME_STEP: u64 = 30;

/// Verify a 6-digit TOTP code against a base32-encoded shared secret.
/// Allows ±1 time-step drift to tolerate minor clock skew between the
/// server and the user's authenticator app.
pub fn verify_totp_code(secret_base32: &str, code: &str) -> bool {
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

/// Constant-time byte comparison to prevent timing side-channels.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
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
}
