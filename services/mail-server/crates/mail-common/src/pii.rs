//! PII redaction utilities for GDPR Art. 5(1)(c) compliance.
//!
//! All log output containing personal data (emails, IPs) MUST be passed through
//! these helpers before being emitted to structured logging fields.

use std::fmt;
use std::net::IpAddr;

/// Redact an email address, preserving the first character and domain for
/// debuggability while removing the full local-part.
/// ```text
/// "alice@example.com" → "a***@example.com"
/// "" → "<empty>"
/// "no-at-sign" → "***"
/// ```
pub fn redact_email(email: &str) -> RedactedEmail<'_> {
    RedactedEmail(email)
}

/// Zero-copy wrapper implementing `Display` with masking.
/// Use with tracing:`email = %redact_email(&addr)`
pub struct RedactedEmail<'a>(pub &'a str);

impl fmt::Display for RedactedEmail<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.0.is_empty() {
            return f.write_str("<empty>");
        }
        match self.0.split_once('@') {
            Some((local, domain)) => {
                let first = local.chars().next().unwrap_or('*');
                write!(f, "{first}***@{domain}")
            }
            None => f.write_str("***"),
        }
    }
}

/// Redact an optional email for logging (replaces `?Option<String>` Debug fields).
pub fn redact_email_opt(email: &Option<String>) -> RedactedOptEmail<'_> {
    RedactedOptEmail(email)
}

/// Display wrapper for `Option<String>` email fields.
pub struct RedactedOptEmail<'a>(pub &'a Option<String>);

impl fmt::Display for RedactedOptEmail<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            Some(e) => write!(f, "Some(\"{}\")", RedactedEmail(e)),
            None => f.write_str("None"),
        }
    }
}

/// Redact a list of emails for logging (replaces `?Vec<String>` Debug fields).
pub fn redact_email_list(emails: &[String]) -> RedactedEmailList<'_> {
    RedactedEmailList(emails)
}

/// Display wrapper for `Vec<String>` / `&[String]` email fields.
pub struct RedactedEmailList<'a>(pub &'a [String]);

impl fmt::Display for RedactedEmailList<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[")?;
        for (i, e) in self.0.iter().enumerate() {
            if i > 0 {
                f.write_str(", ")?;
            }
            write!(f, "\"{}\"", RedactedEmail(e))?;
        }
        f.write_str("]")
    }
}

/// Truncate an IP address for logging. IPv4 → /24, IPv6 → /48.
/// ```text
/// 192.168.1.42 → "192.168.1.0/24"
/// 2001:db8::1 → "2001:db8::/48"
/// ```
pub fn redact_ip(ip: &IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => {
            let octets = v4.octets();
            format!("{}.{}.{}.0/24", octets[0], octets[1], octets[2])
        }
        IpAddr::V6(v6) => {
            let segments = v6.segments();
            format!("{:x}:{:x}:{:x}::/48", segments[0], segments[1], segments[2])
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn email_normal() {
        assert_eq!(
            redact_email("alice@example.com").to_string(),
            "a***@example.com"
        );
    }

    #[test]
    fn email_empty() {
        assert_eq!(redact_email("").to_string(), "<empty>");
    }

    #[test]
    fn email_no_at() {
        assert_eq!(redact_email("no-at-sign").to_string(), "***");
    }

    #[test]
    fn email_short_local() {
        assert_eq!(redact_email("a@b.com").to_string(), "a***@b.com");
    }

    #[test]
    fn ipv4_truncation() {
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 42));
        assert_eq!(redact_ip(&ip), "192.168.1.0/24");
    }

    #[test]
    fn ipv6_truncation() {
        let ip = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0x1234, 0, 0, 0, 0, 1));
        assert_eq!(redact_ip(&ip), "2001:db8:1234::/48");
    }
}
