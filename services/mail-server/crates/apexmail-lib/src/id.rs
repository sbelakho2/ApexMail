//! ID generation — nanoid, API key prefixes.

use nanoid::nanoid;

const DEFAULT_ALPHABET: [char; 36] = [
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
    'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j',
    'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't',
    'u', 'v', 'w', 'x', 'y', 'z',
];

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
pub fn generate_api_key(is_test: bool) -> String {
    let prefix = if is_test { "am_test" } else { "am_live" };
    generate_id(prefix, 32)
}

/// Generate a request ID.
pub fn generate_request_id() -> String {
    generate_id("req", 16)
}

/// Generate a webhook signing key.
pub fn generate_webhook_secret() -> String {
    generate_id("whsec", 24)
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
