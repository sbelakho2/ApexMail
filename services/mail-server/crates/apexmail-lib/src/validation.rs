//! Input validation utilities — RFC 5322 email validation, domain, UUID.
//!
//! # RFC 5322 / RFC 6531 Compliance (RS-M-07)
//!
//! The `is_valid_email` function implements a practical subset of RFC 5322
//! with support for:
//!
//! - **Standard local parts**: alphanumeric, `.!$%&'*+/=?^_`{|}~-`
//! - **Quoted-string local parts**: `"test user"@example.com`
//! - **Internationalised (EAI)**: UTF-8 in both local and domain parts
//!   when the SMTPUTF8 extension is used (RFC 6531)
//! - **Domain literals**: `user@[192.168.1.1]`
//! - **Total length**: ≤ 254 characters per RFC 5321 (not 320)
//! - **Dot-sequence validation**: No consecutive or leading/trailing dots
//!
//! Limitations (acceptable for practical use):
//! - No CFWS (comment folding whitespace) — `(comment)` in addresses
//! - No obs-local-part / obs-domain (obsolete formats)
//! - No explicit MX or DNS validation (separate concern)

use regex::Regex;
use std::sync::LazyLock;

/// RFC 5322 local-part (standard characters): printable ASCII except
/// specials: `(` `)` `<` `>` `[` `]` `\` `"` `;` `:` `,` `@` and whitespace.
static STANDARD_LOCAL_RE: LazyLock<Option<Regex>> = LazyLock::new(|| {
    Regex::new(r"^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+$").ok()
});

/// Quoted-string local-part: anything inside double quotes (RFC 5322 §3.2.4).
/// Allows escaped characters (`\x`) and all printable ASCII inside the quotes.
static QUOTED_LOCAL_RE: LazyLock<Option<Regex>> = LazyLock::new(|| {
    Regex::new(r#"^"[^"]*(?:\\.[^"]*)*"$"#).ok()
});

/// Domain part: standard RFC 5322 domain name or domain literal.
/// - Domain names: letters, digits, hyphens, at least one dot, TLD ≥ 2 chars.
/// - Domain literals: `[` ... `]` containing an IP address or other text.
static DOMAIN_RE: LazyLock<Option<Regex>> = LazyLock::new(|| {
    Regex::new(
        r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}|\[[^\]]+\])$"
    ).ok()
});

/// Internationalised domain: allows non-ASCII UTF-8 characters (RFC 6531).
static IDN_DOMAIN_RE: LazyLock<Option<Regex>> = LazyLock::new(|| {
    Regex::new(
        r"^(?:[^\x00-\x1F\x7F-\x9F@\s]+\.)+[^\x00-\x1F\x7F-\x9F@\s]{2,}$"
    ).ok()
});

/// Domain literal: `[` ... `]` containing IPv4, IPv6, or other text.
static DOMAIN_LITERAL_RE: LazyLock<Option<Regex>> = LazyLock::new(|| {
    Regex::new(r"^\[[^\]]+\]$").ok()
});

// #216: UUID regex must be case-insensitive to accept uppercase hex
static UUID_RE: LazyLock<Option<Regex>> = LazyLock::new(|| {
    Regex::new(r"(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$").ok()
});

/// Validate an email address against RFC 5322 (with RFC 6531 EAI support).
///
/// Returns `true` if the address is syntactically valid.
///
/// # RS-M-07 Improvements
///
/// - Supports quoted-string local parts (`"user name"@domain`)
/// - Supports domain literals (`user@[192.168.1.1]`)
/// - Supports internationalised (UTF-8) emails (RFC 6531)
/// - Enforces RFC 5321 maximum length of 254 characters
/// - Rejects consecutive dots in local-part
/// - Rejects leading/trailing dots in local-part
pub fn is_valid_email(email: &str) -> bool {
    // RFC 5321 §4.5.3.1: max 254 characters for the full address
    if email.is_empty() || email.len() > 254 {
        return false;
    }

    // Must contain exactly one '@' (not a quoted '@')
    let at_pos = match find_unquoted_at(email) {
        Some(pos) => pos,
        None => return false,
    };

    let local = &email[..at_pos];
    let domain = &email[at_pos + 1..];

    if local.is_empty() || domain.is_empty() {
        return false;
    }

    // Validate local-part
    if !is_valid_local_part(local) {
        return false;
    }

    // Validate domain
    is_valid_domain(domain)
}

/// Find the '@' character that is not inside a quoted string.
fn find_unquoted_at(email: &str) -> Option<usize> {
    let mut in_quotes = false;
    let mut prev_was_escape = false;
    for (i, ch) in email.char_indices() {
        if prev_was_escape {
            prev_was_escape = false;
            continue;
        }
        match ch {
            '"' => in_quotes = !in_quotes,
            '\\' => prev_was_escape = true,
            '@' if !in_quotes => return Some(i),
            _ => {}
        }
    }
    None
}

/// Validate the local-part of an email address.
fn is_valid_local_part(local: &str) -> bool {
    if local.is_empty() || local.len() > 64 {
        return false;
    }

    // Check for quoted-string local-part
    if local.starts_with('"') {
        return QUOTED_LOCAL_RE
            .as_ref()
            .map(|re| re.is_match(local))
            .unwrap_or(false);
    }

    // RFC 6531 SMTPUTF8 permits UTF-8 in an unquoted local part. Retain the
    // RFC 5322 atom exclusions for ASCII controls, whitespace, and specials;
    // Unicode letters and symbols are otherwise accepted as UTF-8 bytes.
    if !local.is_ascii() {
        if local.chars().any(|ch| {
            ch.is_control()
                || ch.is_whitespace()
                || matches!(ch, '(' | ')' | '<' | '>' | '[' | ']' | '\\' | '"' | ';' | ':' | ',' | '@')
        }) {
            return false;
        }
        return !local.contains("..") && !local.starts_with('.') && !local.ends_with('.');
    }

    // Standard local-part validation
    let matched = STANDARD_LOCAL_RE
        .as_ref()
        .map(|re| re.is_match(local))
        .unwrap_or(false);

    if !matched {
        return false;
    }

    // No consecutive dots
    if local.contains("..") {
        return false;
    }

    // No leading or trailing dot
    if local.starts_with('.') || local.ends_with('.') {
        return false;
    }

    true
}

pub fn is_valid_domain(domain: &str) -> bool {
    if domain.is_empty() || domain.len() > 253 {
        return false;
    }

    // Domain literal (e.g., [192.168.1.1])
    if domain.starts_with('[') {
        return DOMAIN_LITERAL_RE
            .as_ref()
            .map(|re| re.is_match(domain))
            .unwrap_or(false);
    }

    // Standard domain name
    let is_ascii = domain.is_ascii();
    if is_ascii {
        DOMAIN_RE
            .as_ref()
            .map(|re| re.is_match(domain))
            .unwrap_or(false)
    } else {
        // Internationalised domain (RFC 6531)
        IDN_DOMAIN_RE
            .as_ref()
            .map(|re| re.is_match(domain))
            .unwrap_or(false)
    }
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
        assert!(is_valid_email("simple@example.com"));
        assert!(is_valid_email("very.common@example.com"));
        assert!(is_valid_email("disposable.style.email.with+symbol@example.com"));
        assert!(is_valid_email("other.email-with-hyphen@example.com"));
        assert!(is_valid_email("fully-qualified-domain@example.com"));
        assert!(is_valid_email("user.name+tag+sorting@example.com"));
        assert!(is_valid_email("x@example.com"));
        assert!(is_valid_email("example-indeed@strange-example.com"));
    }

    #[test]
    fn test_valid_quoted_local_part() {
        // Quoted-string local parts (RFC 5322 §3.2.4)
        assert!(is_valid_email(r#""test user"@example.com"#));
        assert!(is_valid_email(r#""test.user"@example.com"#));
        assert!(is_valid_email(r#""test@user"@example.com"#));
    }

    #[test]
    fn test_valid_domain_literals() {
        // Domain literals
        assert!(is_valid_email("user@[192.168.1.1]"));
        assert!(is_valid_email("user@[IPv6:2001:db8::1]"));
    }

    #[test]
    fn test_valid_international_emails() {
        // Internationalised (EAI)
        assert!(is_valid_email("用户@例子.广告"));
        assert!(is_valid_email("用户@例子.com"));
        assert!(is_valid_email("test@müller.de"));
    }

    #[test]
    fn test_invalid_emails() {
        assert!(!is_valid_email(""));
        assert!(!is_valid_email("no-at-sign"));
        assert!(!is_valid_email("@no-local.com"));
        assert!(!is_valid_email("spaces in@email.com"));
        assert!(!is_valid_email("too.long."));
        assert!(!is_valid_email("missing@domain"));
        assert!(!is_valid_email(".leading-dot@example.com"));
        assert!(!is_valid_email("trailing-dot.@example.com"));
        assert!(!is_valid_email("double..dot@example.com"));
    }

    #[test]
    fn test_email_length_limit() {
        // 255+ character email should be rejected
        let long_local = "a".repeat(250);
        let long_email = format!("{}@b.cc", long_local);
        assert!(long_email.len() > 254);
        assert!(!is_valid_email(&long_email));

        // Exactly 254 characters (max per RFC 5321) while preserving the
        // RFC 5321 local-part limit of 64 octets.
        let exact_local = "a".repeat(64);
        let exact_domain = format!(
            "{}.{}.{}.cc",
            "b".repeat(63),
            "b".repeat(63),
            "b".repeat(58),
        );
        let exact_email = format!("{}@{}", exact_local, exact_domain);
        assert_eq!(exact_email.len(), 254);
        assert!(is_valid_email(&exact_email));
    }

    #[test]
    fn test_valid_domains() {
        assert!(is_valid_domain("example.com"));
        assert!(is_valid_domain("sub.example.co.uk"));
        assert!(is_valid_domain("a-b.test.org"));
        assert!(is_valid_domain("[192.168.1.1]"));
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

    #[test]
    fn test_find_unquoted_at() {
        assert_eq!(find_unquoted_at("user@domain"), Some(4));
        assert_eq!(find_unquoted_at("no-at"), None);
        assert_eq!(find_unquoted_at(r#""test@user"@domain"#), Some(11));
        assert_eq!(find_unquoted_at("@start"), Some(0));
        assert_eq!(find_unquoted_at("end@"), Some(3));
    }

    #[test]
    fn test_quoted_at_not_confused() {
        // The '@' inside quotes should not be treated as separator
        assert!(is_valid_email(r#""test@user"@example.com"#));
        // Multiple '@' with one inside quotes
        assert!(is_valid_email(r#""a@b"@c.com"#));
    }
}
