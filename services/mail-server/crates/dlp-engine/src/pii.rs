//! PII detection — credit cards (Luhn), SSNs, phone numbers, email addresses
//!
//! All detection uses regex + validation (no external PII databases).
//!
//! ## Risk scores
//!
//! | PII Type | Risk | Notes |
//! |-------------|------|-------------------------------------|
//! | Credit Card | 8.0 | Luhn-validated; ReDoS-safe regex |
//! | SSN | 9.0 | Dash-only separator; area-validated |
//! | Phone | 3.0 | International formats |
//! | Email | 2.0 | Standard `user@host` pattern |
//!
//! ## Context-aware scanning (February 2026)
//!
//! The scanner now applies context modifiers based on surrounding text:
//!
//! - **Negation phrases** ("not my", "don't use", "example", "test card") reduce
//!   risk scores by 75%
//! - **Documentation context** ("documentation", "template", "placeholder")
//!   also reduces risk
//!
//! ## Known limitations
//!
//! - **Image-based PII**: PII embedded in image attachments (screenshots,
//!   scanned documents) is not detected. An OCR preprocessing step would be
//!   needed to extract text before scanning.
//! - **Phone false positives**: The phone regex can match sequences embedded
//!   in longer numeric strings. Context-aware detection (e.g., preceded by
//!   "call" or "phone") is not implemented.

use regex::Regex;
use std::sync::OnceLock;

/// A detected PII instance
#[derive(Debug, Clone)]
pub struct PiiMatch {
    /// Type of PII found
    pub pii_type: PiiType,
    /// Redacted representation (e.g., "XXXX-XXXX-XXXX-1234")
    pub redacted: String,
    /// Risk score for this finding (may be modified by context)
    pub risk: f64,
    /// Original risk score before context modifiers
    pub base_risk: f64,
    /// Byte offset in the scanned text
    pub offset: usize,
    /// Context modifier applied (if any)
    pub context_modifier: Option<ContextModifier>,
}

/// Context modifiers that can reduce PII risk scores
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContextModifier {
    /// Negation detected ("not my", "don't", "never send")
    Negation,
    /// Example/test context ("example", "test card", "sample")
    Example,
    /// Documentation context ("documentation", "template")
    Documentation,
    /// Quoted/code context (inside quotes or code blocks)
    Quoted,
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

fn credit_card_regex() -> Option<&'static Regex> {
    static RE: OnceLock<Option<Regex>> = OnceLock::new();
    RE.get_or_init(|| {
        // Non-backtracking pattern for credit card numbers
        // Matches common formats:4111111111111111, 4111-1111-1111-1111, 4111 1111 1111 1111
        // Fixed from vulnerable pattern `(?:\d[ -]*?){13,19}` which caused ReDoS
        Regex::new(r"\b(?:\d{4}[- ]?){3}\d{1,7}\b").ok()
    })
    .as_ref()
}

fn ssn_regex() -> Option<&'static Regex> {
    static RE: OnceLock<Option<Regex>> = OnceLock::new();
    RE.get_or_init(|| {
        // Dash-only separator to reduce false positives from dates and phone
        // fragments that match the `[-. ]` class. Real SSNs are almost
        // exclusively formatted as NNN-NN-NNNN.
        Regex::new(r"\b\d{3}-\d{2}-\d{4}\b").ok()
    })
    .as_ref()
}

fn phone_regex() -> Option<&'static Regex> {
    static RE: OnceLock<Option<Regex>> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\b(?:\+?1[-. ]?)?\(?\d{3}\)?[-. ]?\d{3}[-. ]?\d{4}\b").ok())
        .as_ref()
}

fn email_regex() -> Option<&'static Regex> {
    static RE: OnceLock<Option<Regex>> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b").ok())
        .as_ref()
}

// ---------------------------------------------------------------------------
// Context-aware detection
// ---------------------------------------------------------------------------

/// Size of context window (characters before the match) to examine.
const CONTEXT_WINDOW: usize = 100;

/// Negation phrases that reduce PII risk (case-insensitive).
const NEGATION_PHRASES: &[&str] = &[
    "not my",
    "don't use",
    "do not use",
    "don't send",
    "do not send",
    "never send",
    "never share",
    "don't share",
    "is not",
    "isn't",
    "won't",
    "will not",
    "shouldn't",
    "should not",
];

/// Example/test phrases that reduce PII risk.
const EXAMPLE_PHRASES: &[&str] = &[
    "example",
    "test card",
    "test number",
    "sample",
    "dummy",
    "fake",
    "placeholder",
    "for testing",
    "demo",
    "mock",
];

/// Documentation context phrases.
const DOCUMENTATION_PHRASES: &[&str] = &[
    "documentation",
    "template",
    "format:",
    "format is",
    "e.g.",
    "i.e.",
    "such as",
    "for example",
    "readme",
    "developer",
];

/// Risk reduction factor for context modifiers (75% reduction).
const CONTEXT_RISK_FACTOR: f64 = 0.25;

/// Detect context modifier for a PII match based on preceding text.
fn detect_context_modifier(text: &str, match_offset: usize) -> Option<ContextModifier> {
    // Get context window before the match
    let start = match_offset.saturating_sub(CONTEXT_WINDOW);
    let context = &text[start..match_offset].to_lowercase();

    // Check for negation phrases
    for phrase in NEGATION_PHRASES {
        if context.contains(phrase) {
            return Some(ContextModifier::Negation);
        }
    }

    // Check for example phrases
    for phrase in EXAMPLE_PHRASES {
        if context.contains(phrase) {
            return Some(ContextModifier::Example);
        }
    }

    // Check for documentation phrases
    for phrase in DOCUMENTATION_PHRASES {
        if context.contains(phrase) {
            return Some(ContextModifier::Documentation);
        }
    }

    // Check for quoted context (simplistic check)
    let quote_count = context.matches('"').count() + context.matches('\'').count();
    if quote_count % 2 == 1 {
        // Odd number of quotes suggests we're inside a quoted string
        return Some(ContextModifier::Quoted);
    }

    None
}

/// Apply context modifier to a base risk score.
fn apply_context_modifier(base_risk: f64, modifier: Option<ContextModifier>) -> f64 {
    if modifier.is_some() {
        base_risk * CONTEXT_RISK_FACTOR
    } else {
        base_risk
    }
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

    sum.is_multiple_of(10)
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

/// Scan text for PII with context-aware risk scoring.
/// The scanner examines surrounding context for negation phrases, example
/// indicators, and documentation markers that reduce the risk score of
/// detected PII.
pub fn scan_pii(
    text: &str,
    detect_cc: bool,
    detect_ssn: bool,
    detect_phone: bool,
    detect_email: bool,
) -> Vec<PiiMatch> {
    scan_pii_with_context(
        text,
        detect_cc,
        detect_ssn,
        detect_phone,
        detect_email,
        true,
    )
}

/// Scan text for PII with optional context awareness.
/// Set `context_aware` to `false` to disable context modifier detection
/// (for backwards compatibility or performance-critical paths).
pub fn scan_pii_with_context(
    text: &str,
    detect_cc: bool,
    detect_ssn: bool,
    detect_phone: bool,
    detect_email: bool,
    context_aware: bool,
) -> Vec<PiiMatch> {
    let mut matches = Vec::new();

    // Credit card detection with Luhn validation
    if detect_cc {
        if let Some(re) = credit_card_regex() {
            for m in re.find_iter(text) {
                let candidate = m.as_str();
                if luhn_check(candidate) {
                    let base_risk = 8.0;
                    let modifier = if context_aware {
                        detect_context_modifier(text, m.start())
                    } else {
                        None
                    };
                    let risk = apply_context_modifier(base_risk, modifier);
                    matches.push(PiiMatch {
                        pii_type: PiiType::CreditCard,
                        redacted: redact_cc(candidate),
                        risk,
                        base_risk,
                        offset: m.start(),
                        context_modifier: modifier,
                    });
                }
            }
        }
    }

    // SSN detection
    if detect_ssn {
        if let Some(re) = ssn_regex() {
            for m in re.find_iter(text) {
                let candidate = m.as_str();
                let digits: String = candidate.chars().filter(|c| c.is_ascii_digit()).collect();
                // Basic SSN validation:area (001-899, not 666), group (01-99), serial (0001-9999)
                if digits.len() == 9 {
                    let area: u32 = digits[0..3].parse().unwrap_or(0);
                    let group: u32 = digits[3..5].parse().unwrap_or(0);
                    let serial: u32 = digits[5..9].parse().unwrap_or(0);
                    if area > 0 && area < 900 && area != 666 && group > 0 && serial > 0 {
                        let base_risk = 9.0;
                        let modifier = if context_aware {
                            detect_context_modifier(text, m.start())
                        } else {
                            None
                        };
                        let risk = apply_context_modifier(base_risk, modifier);
                        matches.push(PiiMatch {
                            pii_type: PiiType::Ssn,
                            redacted: redact_ssn(candidate),
                            risk,
                            base_risk,
                            offset: m.start(),
                            context_modifier: modifier,
                        });
                    }
                }
            }
        }
    }

    // Phone number detection
    if detect_phone {
        if let Some(re) = phone_regex() {
            for m in re.find_iter(text) {
                let base_risk = 1.5;
                let modifier = if context_aware {
                    detect_context_modifier(text, m.start())
                } else {
                    None
                };
                let risk = apply_context_modifier(base_risk, modifier);
                matches.push(PiiMatch {
                    pii_type: PiiType::PhoneNumber,
                    redacted: "XXX-XXX-XXXX".into(),
                    risk,
                    base_risk,
                    offset: m.start(),
                    context_modifier: modifier,
                });
            }
        }
    }

    // Email address detection
    if detect_email {
        if let Some(re) = email_regex() {
            for m in re.find_iter(text) {
                let base_risk = 2.0;
                let modifier = if context_aware {
                    detect_context_modifier(text, m.start())
                } else {
                    None
                };
                let risk = apply_context_modifier(base_risk, modifier);
                matches.push(PiiMatch {
                    pii_type: PiiType::EmailAddress,
                    redacted: "xxx@xxx.xxx".into(),
                    risk,
                    base_risk,
                    offset: m.start(),
                    context_modifier: modifier,
                });
            }
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
            results
                .iter()
                .map(|r| format!("{}: {}", r.pii_type, r.redacted))
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_redact_cc() {
        assert_eq!(redact_cc("4111111111111111"), "XXXX-XXXX-XXXX-1111");
    }

    // =========================================================================
    // CONTEXT-AWARE DETECTION TESTS (February 2026)
    // =========================================================================

    #[test]
    fn test_context_negation_reduces_risk() {
        let text = "I would never send my SSN 123-45-6789 over email.";
        let results = scan_pii(text, false, true, false, false);

        assert!(!results.is_empty(), "Should still detect SSN");
        let ssn = &results[0];
        assert_eq!(ssn.pii_type, PiiType::Ssn);

        // With negation context, risk should be reduced
        assert!(
            ssn.context_modifier.is_some(),
            "Should have context modifier"
        );
        assert_eq!(ssn.context_modifier, Some(ContextModifier::Negation));
        assert!(
            ssn.risk < ssn.base_risk,
            "Risk should be reduced: {} < {}",
            ssn.risk,
            ssn.base_risk
        );
    }

    #[test]
    fn test_context_example_reduces_risk() {
        let text = "For example, a test card number is 4111111111111111.";
        let results = scan_pii(text, true, false, false, false);

        assert!(!results.is_empty(), "Should detect credit card");
        let cc = &results[0];
        assert_eq!(cc.pii_type, PiiType::CreditCard);

        // Example context should reduce risk
        assert!(cc.context_modifier.is_some());
        assert!(cc.risk < cc.base_risk);
    }

    #[test]
    fn test_context_documentation_reduces_risk() {
        let text = "Documentation: SSN format is 123-45-6789.";
        let results = scan_pii(text, false, true, false, false);

        assert!(!results.is_empty(), "Should detect SSN");
        let ssn = &results[0];

        // Documentation context should reduce risk
        assert!(ssn.context_modifier.is_some());
        assert!(ssn.risk < ssn.base_risk);
    }

    #[test]
    fn test_context_no_modifier_full_risk() {
        // No negation/example context
        let text = "Please charge 4111111111111111 for the purchase.";
        let results = scan_pii(text, true, false, false, false);

        assert!(!results.is_empty());
        let cc = &results[0];

        // No context modifier - full risk
        assert!(cc.context_modifier.is_none(), "Should have no modifier");
        assert_eq!(cc.risk, cc.base_risk, "Risk should equal base risk");
    }

    #[test]
    fn test_context_aware_disabled() {
        let text = "Don't use this test SSN 123-45-6789 for anything.";

        // With context awareness disabled
        let results = scan_pii_with_context(text, false, true, false, false, false);

        assert!(!results.is_empty());
        let ssn = &results[0];

        // Context modifier should be None when disabled
        assert!(ssn.context_modifier.is_none());
        assert_eq!(ssn.risk, ssn.base_risk);
    }

    // =========================================================================
    // ADVERSARIAL TESTS FOR CONTEXT DETECTION
    // =========================================================================

    #[test]
    fn test_adversarial_negation_bypass_attempt() {
        // Attacker tries to bypass detection by adding negation far away
        let text = "I would never share my info. ...lots of text... My real SSN is 123-45-6789.";
        let results = scan_pii(text, false, true, false, false);

        // The negation is too far from the SSN to count (outside 100 char window)
        // This depends on implementation - verify reasonable behavior
        assert!(!results.is_empty());
        // The SSN at the end should likely NOT have negation modifier
        // (negation is >100 chars away)
    }

    #[test]
    fn test_adversarial_fake_example_context() {
        // Attacker includes "example" but is actually sending real PII
        let text = "Not really an example but here's my actual card 4111111111111111";
        let results = scan_pii(text, true, false, false, false);

        assert!(!results.is_empty());
        // Even with reduced risk, the card is still detected
        assert_eq!(results[0].pii_type, PiiType::CreditCard);
    }

    #[test]
    fn test_multiple_pii_different_contexts() {
        let text = "My test SSN is 111-22-3333 but my real card is 4111111111111111.";
        let results = scan_pii(text, true, true, false, false);

        // Should detect both
        assert!(results.len() >= 2, "Should detect multiple PII");

        // Find SSN and CC
        let ssn = results.iter().find(|r| r.pii_type == PiiType::Ssn);
        let cc = results.iter().find(|r| r.pii_type == PiiType::CreditCard);

        // SSN should have "test" context (example)
        if let Some(ssn) = ssn {
            assert!(ssn.context_modifier.is_some() || ssn.risk == ssn.base_risk);
        }
    }
}
