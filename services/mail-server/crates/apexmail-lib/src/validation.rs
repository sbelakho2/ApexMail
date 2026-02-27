//! Input validation utilities.

use regex::Regex;
use std::sync::LazyLock;

static EMAIL_RE: LazyLock<Option<Regex>> = LazyLock::new(|| {
    Regex::new(r"^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$").ok()
});

static DOMAIN_RE: LazyLock<Option<Regex>> = LazyLock::new(|| {
    Regex::new(r"^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$").ok()
});

// #216: UUID regex must be case-insensitive to accept uppercase hex
static UUID_RE: LazyLock<Option<Regex>> = LazyLock::new(|| {
    Regex::new(r"(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$").ok()
});

pub fn is_valid_email(email: &str) -> bool {
    email.len() <= 320 && EMAIL_RE.as_ref().map(|re| re.is_match(email)).unwrap_or(false)
}

pub fn is_valid_domain(domain: &str) -> bool {
    domain.len() <= 253 && DOMAIN_RE.as_ref().map(|re| re.is_match(domain)).unwrap_or(false)
}

pub fn is_valid_uuid(s: &str) -> bool {
    UUID_RE.as_ref().map(|re| re.is_match(s)).unwrap_or(false)
}

/// Check for null bytes in a string.
/// #235: Only check for actual null byte '\0', not literal "\u0000" text
pub fn has_null_bytes(s: &str) -> bool {
    s.contains('\0')
}

/// Sanitize a string by removing null bytes.
pub fn sanitize_string(s: &str) -> String {
    s.replace('\0', "").replace("\\u0000", "")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_emails() {
        assert!(is_valid_email("user@example.com"));
        assert!(is_valid_email("test+tag@sub.domain.co.uk"));
        assert!(is_valid_email("a@b.cc"));
    }

    #[test]
    fn test_invalid_emails() {
        assert!(!is_valid_email(""));
        assert!(!is_valid_email("no-at-sign"));
        assert!(!is_valid_email("@no-local.com"));
        assert!(!is_valid_email("spaces in@email.com"));
    }

    #[test]
    fn test_valid_domains() {
        assert!(is_valid_domain("example.com"));
        assert!(is_valid_domain("sub.example.co.uk"));
        assert!(is_valid_domain("a-b.test.org"));
    }

    #[test]
    fn test_invalid_domains() {
        assert!(!is_valid_domain(""));
        assert!(!is_valid_domain("no-tld"));
        assert!(!is_valid_domain("-leading.com"));
        assert!(!is_valid_domain(".leading-dot.com"));
    }

    #[test]
    fn test_uuid_validation() {
        assert!(is_valid_uuid("550e8400-e29b-41d4-a716-446655440000"));
        assert!(!is_valid_uuid("not-a-uuid"));
        assert!(!is_valid_uuid(""));
    }

    #[test]
    fn test_null_byte_detection() {
        assert!(!has_null_bytes("normal string"));
        assert!(has_null_bytes("has\0null"));
        assert!(!has_null_bytes("has\\u0000null"));
    }

    #[test]
    fn test_sanitize_string() {
        assert_eq!(sanitize_string("hello\0world"), "helloworld");
        assert_eq!(sanitize_string("clean"), "clean");
    }
}
