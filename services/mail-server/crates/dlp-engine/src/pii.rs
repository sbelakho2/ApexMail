//! PII detection — credit cards (Luhn), SSNs, phone numbers
//!
//! All detection uses regex + validation (no external PII databases).

use regex::Regex;
use std::sync::OnceLock;

/// A detected PII instance
#[derive(Debug, Clone)]
pub struct PiiMatch {
    /// Type of PII found
    pub pii_type: PiiType,
    /// Redacted representation (e.g., "XXXX-XXXX-XXXX-1234")
    pub redacted: String,
    /// Risk score for this finding
    pub risk: f64,
    /// Byte offset in the scanned text
    pub offset: usize,
}

/// Types of PII
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PiiType {
    /// Credit/debit card number
    CreditCard,
    /// US Social Security Number
    Ssn,
    /// Phone number
    PhoneNumber,
    /// Email address
    EmailAddress,
}

impl std::fmt::Display for PiiType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PiiType::CreditCard => write!(f, "Credit Card"),
            PiiType::Ssn => write!(f, "SSN"),
            PiiType::PhoneNumber => write!(f, "Phone Number"),
            PiiType::EmailAddress => write!(f, "Email Address"),
        }
    }
}

fn credit_card_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"\b(?:\d[ -]*?){13,19}\b").expect("valid regex")
    })
}

fn ssn_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"\b\d{3}[-. ]\d{2}[-. ]\d{4}\b").expect("valid regex")
    })
}

fn phone_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"\b(?:\+?1[-. ]?)?\(?\d{3}\)?[-. ]?\d{3}[-. ]?\d{4}\b").expect("valid regex")
    })
}

fn email_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b").expect("valid regex")
    })
}

/// Luhn algorithm for credit card validation
pub fn luhn_check(number: &str) -> bool {
    let digits: Vec<u32> = number
        .chars()
        .filter(|c| c.is_ascii_digit())
        .filter_map(|c| c.to_digit(10))
        .collect();

    if digits.len() < 13 || digits.len() > 19 {
        return false;
    }

    let mut sum = 0u32;
    let mut double = false;

    for &digit in digits.iter().rev() {
        let mut d = digit;
        if double {
            d *= 2;
            if d > 9 {
                d -= 9;
            }
        }
        sum += d;
        double = !double;
    }

    sum % 10 == 0
}

/// Redact a credit card number, keeping last 4 digits
fn redact_cc(number: &str) -> String {
    let digits: String = number.chars().filter(|c| c.is_ascii_digit()).collect();
    if digits.len() >= 4 {
        let last4 = &digits[digits.len() - 4..];
        format!("XXXX-XXXX-XXXX-{}", last4)
    } else {
        "XXXX-XXXX-XXXX-XXXX".into()
    }
}

/// Redact an SSN, keeping last 4 digits
fn redact_ssn(ssn: &str) -> String {
    let digits: String = ssn.chars().filter(|c| c.is_ascii_digit()).collect();
    if digits.len() >= 4 {
        let last4 = &digits[digits.len() - 4..];
        format!("XXX-XX-{}", last4)
    } else {
        "XXX-XX-XXXX".into()
    }
}

/// Scan text for PII
pub fn scan_pii(
    text: &str,
    detect_cc: bool,
    detect_ssn: bool,
    detect_phone: bool,
    detect_email: bool,
) -> Vec<PiiMatch> {
    let mut matches = Vec::new();

    // Credit card detection with Luhn validation
    if detect_cc {
        for m in credit_card_regex().find_iter(text) {
            let candidate = m.as_str();
            if luhn_check(candidate) {
                matches.push(PiiMatch {
                    pii_type: PiiType::CreditCard,
                    redacted: redact_cc(candidate),
                    risk: 8.0,
                    offset: m.start(),
                });
            }
        }
    }

    // SSN detection
    if detect_ssn {
        for m in ssn_regex().find_iter(text) {
            let candidate = m.as_str();
            let digits: String = candidate.chars().filter(|c| c.is_ascii_digit()).collect();
            // Basic SSN validation: area (001-899, not 666), group (01-99), serial (0001-9999)
            if digits.len() == 9 {
                let area: u32 = digits[0..3].parse().unwrap_or(0);
                let group: u32 = digits[3..5].parse().unwrap_or(0);
                let serial: u32 = digits[5..9].parse().unwrap_or(0);
                if area > 0 && area < 900 && area != 666 && group > 0 && serial > 0 {
                    matches.push(PiiMatch {
                        pii_type: PiiType::Ssn,
                        redacted: redact_ssn(candidate),
                        risk: 9.0,
                        offset: m.start(),
                    });
                }
            }
        }
    }

    // Phone number detection
    if detect_phone {
        for m in phone_regex().find_iter(text) {
            matches.push(PiiMatch {
                pii_type: PiiType::PhoneNumber,
                redacted: "XXX-XXX-XXXX".into(),
                risk: 3.0,
                offset: m.start(),
            });
        }
    }

    // Email address detection
    if detect_email {
        for m in email_regex().find_iter(text) {
            matches.push(PiiMatch {
                pii_type: PiiType::EmailAddress,
                redacted: "xxx@xxx.xxx".into(),
                risk: 2.0,
                offset: m.start(),
            });
        }
    }

    matches
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_luhn_valid() {
        // Visa test number
        assert!(luhn_check("4111111111111111"));
        // Mastercard test number
        assert!(luhn_check("5500000000000004"));
        // Amex test number
        assert!(luhn_check("378282246310005"));
    }

    #[test]
    fn test_luhn_invalid() {
        assert!(!luhn_check("4111111111111112"));
        assert!(!luhn_check("1234567890"));
    }

    #[test]
    fn test_credit_card_detection() {
        let text = "Please charge my card 4111 1111 1111 1111 for the order.";
        let results = scan_pii(text, true, false, false, false);
        assert!(!results.is_empty(), "Should detect credit card");
        assert_eq!(results[0].pii_type, PiiType::CreditCard);
        assert!(results[0].redacted.ends_with("1111"));
    }

    #[test]
    fn test_ssn_detection() {
        let text = "My SSN is 123-45-6789 for verification.";
        let results = scan_pii(text, false, true, false, false);
        assert!(!results.is_empty(), "Should detect SSN");
        assert_eq!(results[0].pii_type, PiiType::Ssn);
        assert!(results[0].redacted.contains("6789"));
    }

    #[test]
    fn test_ssn_invalid_area() {
        // 000 area is invalid, 666 is invalid, 900+ is invalid
        let text = "SSN: 000-12-3456 and 666-12-3456 and 900-12-3456";
        let results = scan_pii(text, false, true, false, false);
        assert!(results.is_empty(), "Invalid SSNs should not match");
    }

    #[test]
    fn test_phone_detection() {
        let text = "Call me at (555) 123-4567 or +1-555-987-6543.";
        let results = scan_pii(text, false, false, true, false);
        assert!(results.len() >= 1, "Should detect phone numbers");
    }

    #[test]
    fn test_no_false_positives_normal_text() {
        let text = "The meeting is at 3pm in room 201. Budget is $50,000 for Q3.";
        let results = scan_pii(text, true, true, false, false);
        // Should not detect random numbers as CC or SSN
        assert!(
            results.is_empty(),
            "Normal text should not trigger PII: {:?}",
            results.iter().map(|r| format!("{}: {}", r.pii_type, r.redacted)).collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_redact_cc() {
        assert_eq!(redact_cc("4111111111111111"), "XXXX-XXXX-XXXX-1111");
    }
}
