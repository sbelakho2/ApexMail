//! DLP Engine — orchestrates PII detection, entropy analysis, and content policy scanning

use crate::config::DlpConfig;
use crate::content_policy;
use crate::entropy;
use crate::pii::{self, PiiMatch};
use chrono::Utc;

/// Composite DLP verdict
#[derive(Debug, Clone)]
pub struct DlpVerdict {
/// Total risk score
    pub risk_score: f64,
/// Recommended action
    pub action: DlpAction,
/// PII findings
    pub pii_findings: Vec<PiiMatch>,
/// High-entropy (potential secret) findings
    pub entropy_findings: Vec<entropy::EntropyFinding>,
/// Content policy matches
    pub policy_matches: Vec<content_policy::PolicyMatch>,
/// Summary of all findings for logging
    pub summary: String,
}

/// DLP action
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DlpAction {
/// Allow (no sensitive content detected)
    Allow,
/// Audit (log findings but allow)
    Audit,
/// Quarantine for human review
    Quarantine,
/// Block outbound delivery
    Block,
}

impl std::fmt::Display for DlpAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DlpAction::Allow => write!(f, "ALLOW"),
            DlpAction::Audit => write!(f, "AUDIT"),
            DlpAction::Quarantine => write!(f, "QUARANTINE"),
            DlpAction::Block => write!(f, "BLOCK"),
        }
    }
}

/// The DLP engine
pub struct DlpEngine {
    config: DlpConfig,
}

impl DlpEngine {
/// Create engine with default config
    pub fn new() -> Self {
        Self {
            config: DlpConfig::default(),
        }
    }

/// Create engine with custom config
    pub fn with_config(config: DlpConfig) -> Self {
        Self { config }
    }

/// Scan outbound email content for sensitive data
/// # Arguments
/// * `body` - Email body text
/// * `recipient_domain` - The recipient's domain (for allowlist check)
    pub fn scan(&self, body: &str, recipient_domain: Option<&str>) -> DlpVerdict {
// Even for allowlisted domains, run a PII baseline scan so that
// the result contains the findings (for auditing). The action
// will still be Allow, but the findings are visible.
        let is_allowlisted = recipient_domain
            .map(|domain| self.config.allowlisted_domains.iter().any(|d| d == domain))
            .unwrap_or(false);

// Truncate body to max scan size
        let scan_text = if body.len() > self.config.max_scan_size {
            &body[..self.config.max_scan_size]
        } else {
            body
        };

        let mut total_risk = 0.0;
        let mut summary_parts = Vec::with_capacity(16);

// 1. PII scanning
        let pii_findings = pii::scan_pii(
            scan_text,
            self.config.detect_credit_cards,
            self.config.detect_ssn,
            self.config.detect_phone_numbers,
            self.config.detect_email_addresses,
        );
        for finding in &pii_findings {
            total_risk += finding.risk;
            summary_parts.push(format!("{}: {}", finding.pii_type, finding.redacted));
        }

// 2. Entropy analysis (secret detection)
        let entropy_result = if self.config.detect_secrets {
            entropy::scan_entropy(
                scan_text,
                self.config.entropy_threshold,
                self.config.min_entropy_token_length,
            )
        } else {
            entropy::EntropyResult {
                findings: vec![],
                risk_score: 0.0,
            }
        };
        total_risk += entropy_result.risk_score;
        for finding in &entropy_result.findings {
            summary_parts.push(format!("Secret: {} (entropy={:.1})", finding.token_preview, finding.entropy));
        }

// 3. Content policy scanning
        let policy_matches = content_policy::scan_content_policy(
            scan_text,
            &self.config.confidential_keywords,
        );
        for pm in &policy_matches {
            total_risk += pm.risk;
            summary_parts.push(format!("Policy: \"{}\"", pm.keyword));
        }

        if let Some(domain) = recipient_domain {
            total_risk *= self.risk_multiplier_for_domain(domain);
        }

// Determine action
        let mut action = if total_risk >= self.config.block_threshold {
            DlpAction::Block
        } else if total_risk >= self.config.quarantine_threshold {
            DlpAction::Quarantine
        } else if total_risk > 0.0 {
            DlpAction::Audit
        } else {
            DlpAction::Allow
        };

// For allowlisted domains, override action to Allow but keep findings for audit
        if is_allowlisted {
            action = DlpAction::Allow;
            summary_parts.push("Recipient domain is allowlisted (findings retained for audit)".into());
        }

        if let Some(domain) = recipient_domain {
            if let Some(exception) = self.matching_active_exception(domain) {
                if total_risk <= exception.max_risk_score {
                    action = DlpAction::Audit;
                    summary_parts.push(format!(
                        "Exception applied for {} ({})",
                        exception.recipient_domain, exception.reason
                    ));
                }
            }
        }

        let summary = if summary_parts.is_empty() {
            "No sensitive content detected".into()
        } else {
            summary_parts.join("; ")
        };

        DlpVerdict {
            risk_score: total_risk,
            action,
            pii_findings,
            entropy_findings: entropy_result.findings,
            policy_matches,
            summary,
        }
    }

/// Scan with default recipient (no allowlist bypass)
    pub fn scan_body(&self, body: &str) -> DlpVerdict {
        self.scan(body, None)
    }
}

impl DlpEngine {
    fn risk_multiplier_for_domain(&self, domain: &str) -> f64 {
        if self
            .config
            .trusted_recipient_domains
            .iter()
            .any(|d| d.eq_ignore_ascii_case(domain))
        {
            return self.config.trusted_domain_risk_multiplier.max(0.0);
        }

        if self
            .config
            .partner_recipient_domains
            .iter()
            .any(|d| d.eq_ignore_ascii_case(domain))
        {
            return self.config.partner_domain_risk_multiplier.max(0.0);
        }

        1.0
    }

    fn matching_active_exception(&self, domain: &str) -> Option<&crate::config::DlpTemporaryException> {
        let now = Utc::now().timestamp();
        self.config.temporary_exceptions.iter().find(|ex| {
            ex.recipient_domain.eq_ignore_ascii_case(domain) && ex.expires_at_unix > now
        })
    }
}

#[cfg(feature = "events")]
impl DlpEngine {
/// Scan outbound content and also produce a normalized security event.
/// Requires the `events` feature flag (which enables the `mail-common` dep).
    pub fn scan_with_event(
        &self,
        body: &str,
        recipient_domain: Option<&str>,
        correlation: Option<mail_common::security::CorrelationContext>,
    ) -> (DlpVerdict, mail_common::security::SecurityEvent) {
        let verdict = self.scan(body, recipient_domain);
        let correlation = correlation.unwrap_or_else(
            mail_common::security::CorrelationContext::generated,
        );

        let (action, severity) = match verdict.action {
            DlpAction::Allow => (
                mail_common::security::SecurityAction::Allow,
                mail_common::security::SecuritySeverity::Info,
            ),
            DlpAction::Audit => (
                mail_common::security::SecurityAction::Audit,
                mail_common::security::SecuritySeverity::Low,
            ),
            DlpAction::Quarantine => (
                mail_common::security::SecurityAction::Quarantine,
                mail_common::security::SecuritySeverity::Medium,
            ),
            DlpAction::Block => (
                mail_common::security::SecurityAction::Block,
                mail_common::security::SecuritySeverity::High,
            ),
        };

        let mut event = mail_common::security::SecurityEvent::new(
            mail_common::security::SecuritySystem::Dlp,
            action,
            severity,
            verdict.risk_score.min(10.0),
            format!(
                "DLP action={} risk={:.1} pii={} secrets={}",
                verdict.action,
                verdict.risk_score,
                verdict.pii_findings.len(),
                verdict.entropy_findings.len()
            ),
            correlation,
        );

        if let Some(alert) = mail_common::security::ingest_security_event(event.clone()) {
            event.metadata.insert("composite_alert".to_string(), "true".to_string());
            event.metadata.insert(
                "composite_score".to_string(),
                format!("{:.2}", alert.composite_score),
            );
            event.metadata.insert(
                "composite_action".to_string(),
                format!("{:?}", alert.recommended_action),
            );
        }

        (verdict, event)
    }
}

impl Default for DlpEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pii::PiiType;

    #[test]
    fn test_clean_email() {
        let engine = DlpEngine::new();
        let verdict = engine.scan_body("Hi team, please review the Q3 projections. Thanks!");
        assert_eq!(verdict.action, DlpAction::Allow);
        assert!(verdict.risk_score < 1.0);
    }

    #[test]
    fn test_credit_card_in_body() {
        let engine = DlpEngine::new();
        let verdict = engine.scan_body("Please charge card 4111 1111 1111 1111 for the order.");
        assert!(!verdict.pii_findings.is_empty());
        assert!(verdict.pii_findings.iter().any(|f| f.pii_type == PiiType::CreditCard));
        assert!(verdict.risk_score >= 5.0);
    }

    #[test]
    fn test_ssn_triggers_block() {
        let engine = DlpEngine::new();
        let verdict = engine.scan_body(
            "Employee SSN: 123-45-6789. Card: 4111 1111 1111 1111. CONFIDENTIAL."
        );
        assert_eq!(verdict.action, DlpAction::Block,
            "CC + SSN + confidential should block (score={})", verdict.risk_score);
    }

    #[test]
    fn test_confidential_marker() {
        let engine = DlpEngine::new();
        let verdict = engine.scan_body(
            "This message is CONFIDENTIAL and contains PROPRIETARY information."
        );
        assert!(!verdict.policy_matches.is_empty());
        assert!(verdict.risk_score > 0.0);
    }

    #[test]
    fn test_allowlisted_domain() {
        let config = DlpConfig {
            allowlisted_domains: vec!["internal.example.com".into()],
            ..Default::default()
        };
        let engine = DlpEngine::with_config(config);
        let verdict = engine.scan(
            "SSN: 123-45-6789 CONFIDENTIAL",
            Some("internal.example.com"),
        );
// Allowlisted domains still get action=Allow but findings are retained for audit
        assert_eq!(verdict.action, DlpAction::Allow);
        assert!(
            !verdict.pii_findings.is_empty() || !verdict.policy_matches.is_empty(),
            "Allowlisted domains should still report findings for audit"
        );
    }

    #[test]
    fn test_api_key_detection() {
        let engine = DlpEngine::new();
        let verdict = engine.scan_body(
            "Here is the production key: sk_live_4eC39HqLyjWDarjtT1zdp7dc please deploy"
        );
// Should detect high-entropy secret
        assert!(verdict.risk_score > 0.0, "Should detect API key");
    }

    #[test]
    fn test_action_display() {
        assert_eq!(DlpAction::Allow.to_string(), "ALLOW");
        assert_eq!(DlpAction::Block.to_string(), "BLOCK");
        assert_eq!(DlpAction::Quarantine.to_string(), "QUARANTINE");
        assert_eq!(DlpAction::Audit.to_string(), "AUDIT");
    }

    #[test]
    fn test_trusted_domain_risk_tier() {
        let config = DlpConfig {
            trusted_recipient_domains: vec!["trusted.example.com".into()],
            trusted_domain_risk_multiplier: 0.1,
            ..Default::default()
        };
        let engine = DlpEngine::with_config(config);
        let verdict = engine.scan(
            "Card 4111 1111 1111 1111 confidential",
            Some("trusted.example.com"),
        );
        assert!(matches!(verdict.action, DlpAction::Audit | DlpAction::Allow));
    }

    #[test]
    fn test_temporary_exception() {
        let config = DlpConfig {
            temporary_exceptions: vec![crate::config::DlpTemporaryException {
                recipient_domain: "partner.example.com".into(),
                expires_at_unix: Utc::now().timestamp() + 3600,
                max_risk_score: 12.0,
                reason: "INC-123 approved transfer".into(),
            }],
            ..Default::default()
        };
        let engine = DlpEngine::with_config(config);
        let verdict = engine.scan(
            "SSN 123-45-6789",
            Some("partner.example.com"),
        );
        assert_eq!(verdict.action, DlpAction::Audit);
    }
}
