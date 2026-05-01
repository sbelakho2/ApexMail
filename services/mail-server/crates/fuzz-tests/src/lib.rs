//! Fuzz / property-based test helpers.
//!
//! Generates random inputs of various shapes (strings, emails, ASCII, unicode,
//! raw bytes, floats) for use in property-based fuzz tests.

use rand::Rng;

/// Generate a random alphanumeric string of the given length.
pub fn random_string(len: usize) -> String {
    let mut rng = rand::thread_rng();
    (0..len)
        .map(|_| {
            let idx = rng.gen_range(0..36);
            if idx < 10 {
                (b'0' + idx) as char
            } else {
                (b'a' + idx - 10) as char
            }
        })
        .collect()
}

/// Generate a random email-like string (may or may not be valid).
pub fn random_email() -> String {
    let mut rng = rand::thread_rng();
    let local_len = rng.gen_range(1..30);
    let domain_len = rng.gen_range(1..20);
    let tld_len = rng.gen_range(2..6);
    format!(
        "{}@{}.{}",
        random_string(local_len),
        random_string(domain_len),
        random_string(tld_len)
    )
}

/// Generate a random printable ASCII string of the given length.
pub fn random_ascii(len: usize) -> String {
    let mut rng = rand::thread_rng();
    (0..len)
        .map(|_| rng.gen_range(0x20u8..0x7F) as char)
        .collect()
}

/// Generate a random Unicode string of the given length (code-points).
pub fn random_unicode(len: usize) -> String {
    let mut rng = rand::thread_rng();
    (0..len)
        .map(|_| loop {
            let cp = rng.gen_range(0x0020..0x10000u32);
            if let Some(c) = char::from_u32(cp) {
                // Skip surrogates
                if !c.is_control() || c == '\n' || c == '\t' {
                    return c;
                }
            }
        })
        .collect()
}

/// Generate random bytes of the given length.
pub fn random_bytes(len: usize) -> Vec<u8> {
    let mut rng = rand::thread_rng();
    (0..len).map(|_| rng.gen::<u8>()).collect()
}

/// Generate a random f64 in [min, max).
pub fn random_f64_range(min: f64, max: f64) -> f64 {
    let mut rng = rand::thread_rng();
    rng.gen_range(min..max)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_random_string_length() {
        assert_eq!(random_string(0).len(), 0);
        assert_eq!(random_string(100).len(), 100);
    }

    #[test]
    fn test_random_email_has_at() {
        let email = random_email();
        assert!(email.contains('@'));
    }

    #[test]
    fn test_random_bytes_length() {
        assert_eq!(random_bytes(256).len(), 256);
    }

    #[test]
    fn test_random_f64_range_bounded() {
        for _ in 0..1000 {
            let v = random_f64_range(0.0, 1.0);
            assert!((0.0..1.0).contains(&v));
        }
    }
}
