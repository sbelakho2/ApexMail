//! DLP configuration

use serde::{Deserialize, Serialize};

/// Temporary policy exception for a recipient domain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DlpTemporaryException {
    /// Recipient domain to which exception applies.
    pub recipient_domain: String,
    /// Unix timestamp (seconds) when exception expires.
    pub expires_at_unix: i64,
    /// Maximum risk score allowed under this exception.
    pub max_risk_score: f64,
    /// Human-readable reason or ticket reference.
    pub reason: String,
}

/// DLP engine configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DlpConfig {
    /// Enable credit card number detection
    pub detect_credit_cards: bool,

    /// Enable SSN detection
    pub detect_ssn: bool,

    /// Enable phone number detection
    pub detect_phone_numbers: bool,

    /// Enable email address detection in body
    pub detect_email_addresses: bool,

    /// Enable API key / secret detection via entropy
    pub detect_secrets: bool,

    /// Shannon entropy threshold for secret detection (default:4.5)
    pub entropy_threshold: f64,

    /// Minimum token length for entropy analysis (default:20)
    pub min_entropy_token_length: usize,

    /// Confidentiality keywords that trigger elevated scanning
    pub confidential_keywords: Vec<String>,

    /// Score threshold for quarantining (default:5.0)
    pub quarantine_threshold: f64,

    /// Score threshold for blocking (default:10.0)
    pub block_threshold: f64,

    /// Maximum body size to scan in bytes (default:1 MB)
    pub max_scan_size: usize,

    /// Allowlisted recipient domains (exempt from DLP)
    pub allowlisted_domains: Vec<String>,

    /// Trusted recipient domains (reduced risk multiplier)
    pub trusted_recipient_domains: Vec<String>,

    /// Partner recipient domains (moderate risk multiplier)
    pub partner_recipient_domains: Vec<String>,

    /// Risk multiplier for trusted recipient domains
    pub trusted_domain_risk_multiplier: f64,

    /// Risk multiplier for partner recipient domains
    pub partner_domain_risk_multiplier: f64,

    /// Expiring temporary exceptions
    pub temporary_exceptions: Vec<DlpTemporaryException>,
}

impl Default for DlpConfig {
    fn default() -> Self {
        Self {
            detect_credit_cards: true,
            detect_ssn: true,
            detect_phone_numbers: true,
            detect_email_addresses: false,
            detect_secrets: true,
            entropy_threshold: 4.5,
            min_entropy_token_length: 20,
            confidential_keywords: vec![
                "confidential".into(),
                "internal only".into(),
                "do not distribute".into(),
                "restricted".into(),
                "top secret".into(),
                "classified".into(),
                "proprietary".into(),
                "trade secret".into(),
                "attorney-client".into(),
                "privileged".into(),
            ],
            quarantine_threshold: 5.0,
            block_threshold: 10.0,
            max_scan_size: 1024 * 1024,
            allowlisted_domains: Vec::new(),
            trusted_recipient_domains: Vec::new(),
            partner_recipient_domains: Vec::new(),
            trusted_domain_risk_multiplier: 0.5,
            partner_domain_risk_multiplier: 0.75,
            temporary_exceptions: Vec::new(),
        }
    }
}
