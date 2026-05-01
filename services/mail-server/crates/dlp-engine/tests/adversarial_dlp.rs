//! Adversarial DLP (Data Loss Prevention) tests.
//!
//! Tests are designed to CATCH false negatives (missed PII) and
//! false positives (benign content mis-classified).
//!
//! Coverage://! - Luhn-valid credit card:must detect
//! - Luhn-invalid number:must NOT detect (false-positive guard)
//! - SSN formats
//! - High-entropy secrets (API keys, tokens)
//! - Multiple PII types in one email (cumulative risk)
//! - Clean email:must be allowed with zero findings

use dlp_engine::engine::{DlpAction, DlpEngine};
use dlp_engine::pii::PiiType;

fn engine() -> DlpEngine {
    DlpEngine::new()
}

// ── Credit Card detection ─────────────────────────────────────────────────────

/// Luhn-valid Visa test number must be detected.
#[test]
fn test_cc_luhn_valid_visa_detected() {
    let e = engine();
    let verdict = e.scan_body("Please charge card 4532015112830366 for invoice #1234.");
    let cc = verdict
        .pii_findings
        .iter()
        .any(|f| matches!(f.pii_type, PiiType::CreditCard));
    assert!(
        cc,
        "Luhn-valid Visa number must be detected. Findings: {:?}",
        verdict.pii_findings
    );
    assert!(verdict.risk_score > 0.0);
}

/// Different card brand (Mastercard) must also be detected.
#[test]
fn test_cc_mastercard_detected() {
    let e = engine();
    // Luhn-valid Mastercard test number
    let verdict = e.scan_body("Billing info: 5425233430109903");
    let cc = verdict
        .pii_findings
        .iter()
        .any(|f| matches!(f.pii_type, PiiType::CreditCard));
    assert!(cc, "Mastercard number must be detected");
}

/// Luhn-invalid number must NOT trigger a CC alert (reduces false positives).
#[test]
fn test_cc_luhn_invalid_not_detected() {
    let e = engine();
    // Last digit changed to make Luhn fail
    let verdict = e.scan_body("Order ref: 4532015112830367");
    let cc = verdict
        .pii_findings
        .iter()
        .any(|f| matches!(f.pii_type, PiiType::CreditCard));
    assert!(
        !cc,
        "Luhn-invalid number must NOT trigger CC detection (false-positive guard)"
    );
}

/// CC in email body with recipient domain context (external domain).
#[test]
fn test_cc_detected_external_recipient() {
    let e = engine();
    let verdict = e.scan(
        "Attach card 4532015112830366 to your account.",
        Some("external-corp.com"),
    );
    let cc = verdict
        .pii_findings
        .iter()
        .any(|f| matches!(f.pii_type, PiiType::CreditCard));
    assert!(cc, "CC must be detected regardless of recipient domain");
}

// ── SSN detection ─────────────────────────────────────────────────────────────

/// Standard dashed SSN format (XXX-XX-XXXX).
#[test]
fn test_ssn_dashed_format_detected() {
    let e = engine();
    let verdict = e.scan_body("Employee file: SSN 078-05-1120");
    let ssn = verdict
        .pii_findings
        .iter()
        .any(|f| matches!(f.pii_type, PiiType::Ssn));
    assert!(
        ssn,
        "Dashed SSN must be detected. Findings: {:?}",
        verdict.pii_findings
    );
}

/// SSN embedded in a sentence with no label.
#[test]
fn test_ssn_embedded_no_label() {
    let e = engine();
    let verdict = e.scan_body("The number 078-05-1120 corresponds to the employee record.");
    let ssn = verdict
        .pii_findings
        .iter()
        .any(|f| matches!(f.pii_type, PiiType::Ssn));
    assert!(ssn, "Unlabeled SSN pattern must be detected");
}

// ── Entropy / secret detection ────────────────────────────────────────────────

/// AWS-style secret key has very high entropy — must trigger entropy finding.
#[test]
fn test_aws_secret_key_entropy_detected() {
    let e = engine();
    // Fake but plausible AWS secret access key format (40 chars, mixed alphanumeric)
    let verdict = e.scan_body("AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY");
    assert!(
        !verdict.entropy_findings.is_empty(),
        "AWS secret-like string must trigger entropy finding"
    );
}

/// A realistic API token (mixed-case + digits + key prefix) must trigger entropy.
/// The scanner requires BOTH entropy >= 4.5 AND looks_like_secret.
/// A pure lowercase hex string fails both criteria — use a mixed-case token.
#[test]
fn test_api_token_entropy_detected() {
    let e = engine();
    // sk_ prefix triggers looks_like_secret; mixed case + digits gives > 4.5 bits entropy
    let verdict = e.scan_body("token: sk_live_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789");
    assert!(
        !verdict.entropy_findings.is_empty(),
        "API token with sk_ prefix and mixed-case must trigger entropy finding"
    );
}

/// Normal english paragraph must NOT trigger entropy finding.
#[test]
fn test_low_entropy_text_no_entropy_finding() {
    let e = engine();
    let verdict = e.scan_body(
        "Dear team, please review the quarterly report and provide your feedback by Friday.",
    );
    assert!(
        verdict.entropy_findings.is_empty(),
        "Natural language must NOT trigger entropy finding: {:?}",
        verdict.entropy_findings
    );
}

// ── Multi-PII cumulative risk ─────────────────────────────────────────────────

/// Email containing both CC and SSN must produce at least 2 PII findings.
#[test]
fn test_multiple_pii_types_cumulative() {
    let e = engine();
    let verdict = e.scan_body("CC: 4532015112830366, SSN: 078-05-1120");
    assert!(
        verdict.pii_findings.len() >= 2,
        "Both CC and SSN must generate separate findings. Got: {:?}",
        verdict.pii_findings
    );
    // Combined risk should be higher than either alone
    let solo_cc = engine().scan_body("CC: 4532015112830366").risk_score;
    let solo_ssn = engine().scan_body("SSN: 078-05-1120").risk_score;
    assert!(
        verdict.risk_score >= solo_cc.max(solo_ssn),
        "Combined risk must be >= max of individual risks"
    );
}

// ── False-positive guard (clean email) ───────────────────────────────────────

#[test]
fn test_clean_business_email_allowed() {
    let e = engine();
    let verdict = e.scan_body(
        "Hi John,\n\nPlease find attached the project proposal for Q4.\n\nBest regards,\nSarah",
    );
    assert_eq!(
        verdict.action,
        DlpAction::Allow,
        "Clean business email must be allowed. Risk: {}, Findings: {:?}",
        verdict.risk_score,
        verdict.pii_findings
    );
    assert!(
        verdict.pii_findings.is_empty(),
        "Clean email must have zero PII findings"
    );
}

/// Numbers that look like phone numbers but aren't SSNs must not trigger SSN.
#[test]
fn test_product_code_not_ssn() {
    let e = engine();
    let verdict = e.scan_body("Part number: 123-45-678 (not an SSN, only 8 digits in last group)");
    let ssn = verdict
        .pii_findings
        .iter()
        .any(|f| matches!(f.pii_type, PiiType::Ssn));
    assert!(
        !ssn,
        "Malformed SSN-like pattern with wrong digit count must NOT be detected"
    );
}
