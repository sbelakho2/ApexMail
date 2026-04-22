//! PII redaction utilities for GDPR Art. 5(1)(c) compliance.

use std::fmt;

/// Redact an email address for logging:`"alice@example.com"` → `"a***@example.com"`.
pub fn redact_email(email: &str) -> RedactedEmail<'_> {
    RedactedEmail(email)
}

/// Zero-copy wrapper implementing `Display` with masking.
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
