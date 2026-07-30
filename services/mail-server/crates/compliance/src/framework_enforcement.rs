//! Per-framework compliance enforcement rules.
//!
//! Each registered framework imposes a set of controls that must be
//! satisfied before certain actions (e.g. sending marketing email) are
//! permitted.  The `FrameworkEnforcer` checks registered frameworks for
//! a tenant and returns warnings or blocks depending on severity.
//!
//! Frameworks supported:
//!   GDPR, HIPAA, CCPA, CASL, LGPD, PDPA, POPIA, SOC2, ISO 27001

use std::collections::HashMap;

/// Supported compliance frameworks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ComplianceFramework {
    Gdpr,
    Hipaa,
    Ccpa,
    Casl,
    Lgpd,
    Pdpa,
    Popia,
    Soc2,
    Iso27001,
}

impl ComplianceFramework {
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "gdpr" => Some(Self::Gdpr),
            "hipaa" => Some(Self::Hipaa),
            "ccpa" => Some(Self::Ccpa),
            "casl" => Some(Self::Casl),
            "lgpd" => Some(Self::Lgpd),
            "pdpa" => Some(Self::Pdpa),
            "popia" => Some(Self::Popia),
            "soc2" | "soc_2" => Some(Self::Soc2),
            "iso27001" | "iso_27001" => Some(Self::Iso27001),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Gdpr => "gdpr",
            Self::Hipaa => "hipaa",
            Self::Ccpa => "ccpa",
            Self::Casl => "casl",
            Self::Lgpd => "lgpd",
            Self::Pdpa => "pdpa",
            Self::Popia => "popia",
            Self::Soc2 => "soc2",
            Self::Iso27001 => "iso27001",
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            Self::Gdpr => "GDPR",
            Self::Hipaa => "HIPAA",
            Self::Ccpa => "CCPA",
            Self::Casl => "CASL",
            Self::Lgpd => "LGPD",
            Self::Pdpa => "PDPA",
            Self::Popia => "POPIA",
            Self::Soc2 => "SOC 2",
            Self::Iso27001 => "ISO 27001",
        }
    }

    pub fn dpa_contact(&self) -> Option<(&'static str, &'static str)> {
        match self {
            Self::Gdpr => Some(("EU DPA", "https://edpb.europa.eu/about-edpb/who-we-are_en")),
            Self::Casl => Some(("CRTC", "https://crtc.gc.ca/eng/contact/")),
            Self::Lgpd => Some(("ANPD (Brazil)", "https://www.gov.br/anpd/pt-br")),
            Self::Pdpa => Some(("PDPC Singapore", "https://www.pdpc.gov.sg/contact-us")),
            Self::Popia => Some(("SA Information Regulator", "https://inforegulator.org.za/contact/")),
            Self::Ccpa => Some(("California AG", "https://oag.ca.gov/privacy/ccpa")),
            _ => None,
        }
    }
}

impl std::fmt::Display for ComplianceFramework {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Action a tenant may attempt to perform.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ComplianceAction {
    SendMarketingEmail,
    SendTransactionalEmail,
    CollectPersonalData,
    ProcessHealthData,
    ExportDataToThirdParty,
    UseAutomatedDecisionMaking,
    UseProfiling,
    StorePersonalData,
}

impl ComplianceAction {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "send_marketing_email" => Some(Self::SendMarketingEmail),
            "send_transactional_email" => Some(Self::SendTransactionalEmail),
            "collect_personal_data" => Some(Self::CollectPersonalData),
            "process_health_data" => Some(Self::ProcessHealthData),
            "export_data_to_third_party" => Some(Self::ExportDataToThirdParty),
            "use_automated_decision_making" => Some(Self::UseAutomatedDecisionMaking),
            "use_profiling" => Some(Self::UseProfiling),
            "store_personal_data" => Some(Self::StorePersonalData),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::SendMarketingEmail => "send_marketing_email",
            Self::SendTransactionalEmail => "send_transactional_email",
            Self::CollectPersonalData => "collect_personal_data",
            Self::ProcessHealthData => "process_health_data",
            Self::ExportDataToThirdParty => "export_data_to_third_party",
            Self::UseAutomatedDecisionMaking => "use_automated_desision_making",
            Self::UseProfiling => "use_profiling",
            Self::StorePersonalData => "store_personal_data",
        }
    }
}

/// Outcome of a compliance check.
#[derive(Debug, Clone)]
pub enum EnforcementOutcome {
    Allowed,
    Warned { warnings: Vec<String> },
    Blocked { reason: Vec<String> },
}

/// Per-framework control requirement for audit displays.
#[derive(Debug, Clone)]
pub struct FrameworkRequirement {
    pub key: String,
    pub description: String,
    pub mandatory: bool,
}

/// Compliance enforcement engine.
pub struct FrameworkEnforcer;

impl FrameworkEnforcer {
    /// Check whether a tenant with the given registered frameworks may perform
    /// the requested action.  Returns `Allowed` (no blocking rules), `Warned`
    /// (non-blocking violations exist), or `Blocked` (hard stop).
    pub fn check_compliance(
        registered: &[ComplianceFramework],
        action: ComplianceAction,
        context: &HashMap<String, String>,
    ) -> EnforcementOutcome {
        let mut warnings: Vec<String> = Vec::new();
        let mut blocks: Vec<String> = Vec::new();

        for framework in registered {
            match framework {
                ComplianceFramework::Gdpr => {
                    Self::check_gdpr(action, context, &mut warnings, &mut blocks);
                }
                ComplianceFramework::Hipaa => {
                    Self::check_hipaa(action, context, &mut warnings, &mut blocks);
                }
                ComplianceFramework::Ccpa => {
                    Self::check_ccpa(action, context, &mut warnings, &mut blocks);
                }
                ComplianceFramework::Casl => {
                    Self::check_casl(action, context, &mut warnings, &mut blocks);
                }
                ComplianceFramework::Lgpd => {
                    Self::check_lgpd(action, context, &mut warnings, &mut blocks);
                }
                ComplianceFramework::Pdpa => {
                    Self::check_pdpa(action, context, &mut warnings, &mut blocks);
                }
                ComplianceFramework::Popia => {
                    Self::check_popia(action, context, &mut warnings, &mut blocks);
                }
                ComplianceFramework::Soc2 => {
                    // SOC2 is an operational framework, not a per-action enforcement framework.
                    // It is covered by attestation/audit workflows.
                }
                ComplianceFramework::Iso27001 => {
                    // ISO 27001 is a management framework; its controls map to SOC2.
                }
            }
        }

        if !blocks.is_empty() {
            EnforcementOutcome::Blocked { reason: blocks }
        } else if !warnings.is_empty() {
            EnforcementOutcome::Warned { warnings }
        } else {
            EnforcementOutcome::Allowed
        }
    }

    /// Return the list of required controls for a given framework,
    /// useful for audit readiness checks.
    pub fn get_framework_requirements(
        framework: ComplianceFramework,
    ) -> Vec<FrameworkRequirement> {
        match framework {
            ComplianceFramework::Gdpr => Self::gdpr_requirements(),
            ComplianceFramework::Hipaa => Self::hipaa_requirements(),
            ComplianceFramework::Ccpa => Self::ccpa_requirements(),
            ComplianceFramework::Casl => Self::casl_requirements(),
            ComplianceFramework::Lgpd => Self::lgpd_requirements(),
            ComplianceFramework::Pdpa => Self::pdpa_requirements(),
            ComplianceFramework::Popia => Self::popia_requirements(),
            ComplianceFramework::Soc2 => Self::soc2_requirements(),
            ComplianceFramework::Iso27001 => Self::iso27001_requirements(),
        }
    }

    // ── Per-framework enforcement rules ─────────────────────────────

    fn check_gdpr(
        action: ComplianceAction,
        _ctx: &HashMap<String, String>,
        warnings: &mut Vec<String>,
        blocks: &mut Vec<String>,
    ) {
        match action {
            ComplianceAction::SendMarketingEmail => {
                if _ctx.get("has_consent").map(String::as_str) != Some("true") {
                    blocks.push(
                        "GDPR: marketing emails require explicit consent with auditable record"
                            .into(),
                    );
                }
                if _ctx.get("dsar_workflow_enabled").map(String::as_str) != Some("true") {
                    warnings.push(
                        "GDPR: DSAR (data subject access request) workflow is recommended"
                            .into(),
                    );
                }
            }
            ComplianceAction::CollectPersonalData => {
                if _ctx.get("has_consent").map(String::as_str) != Some("true")
                    && _ctx.get("has_legitimate_interest").map(String::as_str) != Some("true")
                {
                    warnings.push(
                        "GDPR Art.6: lawful basis required for personal data collection".into(),
                    );
                }
            }
            ComplianceAction::ExportDataToThirdParty => {
                warnings.push(
                    "GDPR Art.28: data processing agreement required with third party recipient"
                        .into(),
                );
            }
            ComplianceAction::UseProfiling | ComplianceAction::UseAutomatedDecisionMaking => {
                if _ctx.get("has_explicit_consent").map(String::as_str) != Some("true") {
                    blocks.push(
                        "GDPR Art.22: automated decision-making requires explicit consent".into(),
                    );
                }
            }
            _ => {}
        }
    }

    fn check_hipaa(
        action: ComplianceAction,
        _ctx: &HashMap<String, String>,
        warnings: &mut Vec<String>,
        blocks: &mut Vec<String>,
    ) {
        match action {
            ComplianceAction::ProcessHealthData => {
                if _ctx.get("baa_active").map(String::as_str) != Some("true") {
                    blocks.push(
                        "HIPAA: active BAA required before processing PHI".into(),
                    );
                }
                if _ctx.get("phi_encryption_enabled").map(String::as_str) != Some("true") {
                    blocks.push(
                        "HIPAA: encryption at rest required for PHI storage".into(),
                    );
                }
            }
            ComplianceAction::StorePersonalData => {
                if _ctx.get("baa_active").map(String::as_str) != Some("true") {
                    warnings.push(
                        "HIPAA: BAA recommended if stored data includes PHI".into(),
                    );
                }
            }
            ComplianceAction::ExportDataToThirdParty => {
                if _ctx.get("baa_active").map(String::as_str) != Some("true") {
                    blocks.push(
                        "HIPAA: BAA with sub-processor required before sharing PHI".into(),
                    );
                }
            }
            _ => {}
        }
    }

    fn check_casl(
        action: ComplianceAction,
        _ctx: &HashMap<String, String>,
        warnings: &mut Vec<String>,
        blocks: &mut Vec<String>,
    ) {
        match action {
            ComplianceAction::SendMarketingEmail => {
                if _ctx.get("has_express_consent").map(String::as_str) != Some("true") {
                    blocks.push(
                        "CASL: express consent required for commercial electronic messages".into(),
                    );
                }
                if _ctx.get("sender_identified").map(String::as_str) != Some("true") {
                    blocks.push(
                        "CASL: sender must be clearly identified with contact information".into(),
                    );
                }
                if _ctx.get("unsubscribe_enabled").map(String::as_str) != Some("true") {
                    blocks.push(
                        "CASL: unsubscribe mechanism must be functional (10-day processing limit)"
                            .into(),
                    );
                }
            }
            ComplianceAction::SendTransactionalEmail => {
                if _ctx.get("sender_identified").map(String::as_str) != Some("true") {
                    warnings.push(
                        "CASL: sender identification recommended even for transactional messages"
                            .into(),
                    );
                }
            }
            _ => {}
        }
    }

    fn check_lgpd(
        action: ComplianceAction,
        _ctx: &HashMap<String, String>,
        warnings: &mut Vec<String>,
        blocks: &mut Vec<String>,
    ) {
        match action {
            ComplianceAction::SendMarketingEmail => {
                if _ctx.get("has_consent").map(String::as_str) != Some("true") {
                    blocks.push(
                        "LGPD: marketing communications require consent".into(),
                    );
                }
                if _ctx.get("dsar_workflow_enabled").map(String::as_str) != Some("true") {
                    warnings.push(
                        "LGPD: data subject rights mechanism is recommended".into(),
                    );
                }
            }
            ComplianceAction::CollectPersonalData => {
                if _ctx.get("has_consent").map(String::as_str) != Some("true")
                    && _ctx.get("has_legitimate_interest").map(String::as_str) != Some("true")
                {
                    warnings.push(
                        "LGPD Art.7: lawful basis required for personal data processing".into(),
                    );
                }
                warnings.push(
                    "LGPD: DPA contact: ANPD (Brazil) — https://www.gov.br/anpd/pt-br".into(),
                );
            }
            ComplianceAction::ExportDataToThirdParty => {
                warnings.push(
                    "LGPD: international transfer requires adequate safeguards".into(),
                );
            }
            _ => {}
        }
    }

    fn check_pdpa(
        action: ComplianceAction,
        _ctx: &HashMap<String, String>,
        warnings: &mut Vec<String>,
        blocks: &mut Vec<String>,
    ) {
        match action {
            ComplianceAction::SendMarketingEmail => {
                if _ctx.get("has_consent").map(String::as_str) != Some("true") {
                    blocks.push(
                        "PDPA: consent required for direct marketing".into(),
                    );
                }
                if _ctx.get("purpose_limited").map(String::as_str) != Some("true") {
                    warnings.push(
                        "PDPA: purpose limitation — data used only for stated purpose".into(),
                    );
                }
                warnings.push(
                    "PDPA: DPA contact: PDPC Singapore — https://www.pdpc.gov.sg/contact-us"
                        .into(),
                );
            }
            ComplianceAction::CollectPersonalData => {
                if _ctx.get("has_consent").map(String::as_str) != Some("true") {
                    warnings.push(
                        "PDPA: consent or deemed consent required for collection".into(),
                    );
                }
                warnings.push(
                    "PDPA: notification obligation — inform individuals of purpose".into(),
                );
            }
            _ => {}
        }
    }

    fn check_popia(
        action: ComplianceAction,
        _ctx: &HashMap<String, String>,
        warnings: &mut Vec<String>,
        blocks: &mut Vec<String>,
    ) {
        match action {
            ComplianceAction::ProcessHealthData => {
                if _ctx.get("prior_authorization").map(String::as_str) != Some("true") {
                    blocks.push(
                        "POPIA: Section 27 — prior authorization required for processing special personal information"
                            .into(),
                    );
                }
            }
            ComplianceAction::CollectPersonalData => {
                if _ctx.get("prior_authorization").map(String::as_str) != Some("true") {
                    warnings.push(
                        "POPIA: certain processing requires prior authorization from SA Information Regulator"
                            .into(),
                    );
                }
                warnings.push(
                    "POPIA: DPA contact: SA Information Regulator — https://inforegulator.org.za/contact/"
                        .into(),
                );
            }
            ComplianceAction::SendMarketingEmail => {
                if _ctx.get("has_consent").map(String::as_str) != Some("true") {
                    warnings.push(
                        "POPIA: consent recommended for direct marketing".into(),
                    );
                }
            }
            ComplianceAction::ExportDataToThirdParty => {
                warnings.push(
                    "POPIA: cross-border transfer requires operator agreement".into(),
                );
            }
            _ => {}
        }
    }

    fn check_ccpa(
        action: ComplianceAction,
        _ctx: &HashMap<String, String>,
        warnings: &mut Vec<String>,
        blocks: &mut Vec<String>,
    ) {
        match action {
            ComplianceAction::SendMarketingEmail => {
                if _ctx.get("do_not_sell_link").map(String::as_str) != Some("true") {
                    warnings.push(
                        "CCPA: 'Do Not Sell My Personal Information' link must be present".into(),
                    );
                }
                if _ctx.get("gpc_signal_handling").map(String::as_str) != Some("true") {
                    warnings.push(
                        "CCPA: Global Privacy Control (GPC) signal handling should be implemented"
                            .into(),
                    );
                }
            }
            ComplianceAction::ExportDataToThirdParty => {
                if _ctx.get("opt_out_processed_within_15_days").map(String::as_str) != Some("true") {
                    blocks.push(
                        "CCPA: opt-out requests must be processed within 15 business days".into(),
                    );
                }
            }
            _ => {}
        }
    }

    // ── Framework requirements catalog ─────────────────────────────

    fn gdpr_requirements() -> Vec<FrameworkRequirement> {
        vec![
            FrameworkRequirement { key: "dsar_workflow".into(), description: "DSAR workflow: access, erasure, portability, rectification, restriction, objection".into(), mandatory: true },
            FrameworkRequirement { key: "consent_tracking".into(), description: "Consent tracking with auditable record and proof document".into(), mandatory: true },
            FrameworkRequirement { key: "breach_notification_72h".into(), description: "72-hour breach notification to supervisory authority".into(), mandatory: true },
            FrameworkRequirement { key: "dpia".into(), description: "Data Protection Impact Assessment for high-risk processing".into(), mandatory: true },
            FrameworkRequirement { key: "dpo_appointment".into(), description: "Data Protection Officer appointment (if applicable)".into(), mandatory: false },
            FrameworkRequirement { key: "data_retention_policy".into(), description: "Documented data retention and deletion policy".into(), mandatory: true },
            FrameworkRequirement { key: "cross_border_transfer".into(), description: "Cross-border transfer safeguards (SCCs / adequacy decision)".into(), mandatory: true },
        ]
    }

    fn hipaa_requirements() -> Vec<FrameworkRequirement> {
        vec![
            FrameworkRequirement { key: "baa".into(), description: "Signed Business Associate Agreement".into(), mandatory: true },
            FrameworkRequirement { key: "phi_encryption".into(), description: "PHI encryption at rest and in transit".into(), mandatory: true },
            FrameworkRequirement { key: "breach_notification_60d".into(), description: "60-day breach notification to affected individuals and HHS".into(), mandatory: true },
            FrameworkRequirement { key: "access_controls".into(), description: "Unique user identification, emergency access, automatic logoff".into(), mandatory: true },
            FrameworkRequirement { key: "audit_controls".into(), description: "Hardware/software/procedural audit controls".into(), mandatory: true },
            FrameworkRequirement { key: "integrity_controls".into(), description: "Mechanisms to ensure data has not been altered or destroyed improperly".into(), mandatory: true },
            FrameworkRequirement { key: "transmission_security".into(), description: "Encryption for PHI transmitted over networks".into(), mandatory: true },
        ]
    }

    fn ccpa_requirements() -> Vec<FrameworkRequirement> {
        vec![
            FrameworkRequirement { key: "do_not_sell_link".into(), description: "Clear 'Do Not Sell My Personal Information' link on homepage".into(), mandatory: true },
            FrameworkRequirement { key: "opt_out_processing".into(), description: "Process opt-out requests within 15 business days".into(), mandatory: true },
            FrameworkRequirement { key: "gpc_signal_handling".into(), description: "Honor Global Privacy Control browser signals".into(), mandatory: true },
            FrameworkRequirement { key: "data_access".into(), description: "Provide access to personal information upon verifiable request".into(), mandatory: true },
            FrameworkRequirement { key: "data_deletion".into(), description: "Delete personal information upon request (with exceptions)".into(), mandatory: true },
            FrameworkRequirement { key: "privacy_notice".into(), description: "Updated privacy notice covering CCPA requirements".into(), mandatory: true },
        ]
    }

    fn casl_requirements() -> Vec<FrameworkRequirement> {
        vec![
            FrameworkRequirement { key: "express_consent".into(), description: "Express consent for commercial electronic messages".into(), mandatory: true },
            FrameworkRequirement { key: "sender_identification".into(), description: "Sender name, physical address, and contact info in each message".into(), mandatory: true },
            FrameworkRequirement { key: "unsubscribe_10days".into(), description: "Unsubscribe mechanism processed within 10 business days".into(), mandatory: true },
            FrameworkRequirement { key: "consent_records".into(), description: "Retain consent records and supply chain proof".into(), mandatory: true },
            FrameworkRequirement { key: "implied_consent_tracking".into(), description: "Track implied consent periods (existing business, inquiry)".into(), mandatory: true },
        ]
    }

    fn lgpd_requirements() -> Vec<FrameworkRequirement> {
        vec![
            FrameworkRequirement { key: "consent_management".into(), description: "Consent management with auditable records".into(), mandatory: true },
            FrameworkRequirement { key: "dsar_workflow".into(), description: "Data subject rights: access, correction, deletion, portability".into(), mandatory: true },
            FrameworkRequirement { key: "anpd_reporting".into(), description: "ANPD breach notification and reporting channel".into(), mandatory: true },
            FrameworkRequirement { key: "cross_border_transfer".into(), description: "International data transfer safeguards".into(), mandatory: true },
            FrameworkRequirement { key: "dpo_appointment".into(), description: "DPO appointment and ANPD registration".into(), mandatory: true },
            FrameworkRequirement { key: "dpia".into(), description: "Data Protection Impact Assessment".into(), mandatory: false },
        ]
    }

    fn pdpa_requirements() -> Vec<FrameworkRequirement> {
        vec![
            FrameworkRequirement { key: "consent_purpose".into(), description: "Consent with clear purpose limitation".into(), mandatory: true },
            FrameworkRequirement { key: "notification".into(), description: "Notification to individuals of purpose and use".into(), mandatory: true },
            FrameworkRequirement { key: "access_correction".into(), description: "Access and correction requests handling".into(), mandatory: true },
            FrameworkRequirement { key: "data_protection_officer".into(), description: "DPO appointment and PDPC registration".into(), mandatory: true },
            FrameworkRequirement { key: "retention_limitation".into(), description: "Data retention limitation policy".into(), mandatory: true },
            FrameworkRequirement { key: "cross_border_transfer".into(), description: "Overseas transfer standard (comparable protection)".into(), mandatory: true },
        ]
    }

    fn popia_requirements() -> Vec<FrameworkRequirement> {
        vec![
            FrameworkRequirement { key: "prior_authorization".into(), description: "Prior authorization from SA Information Regulator for certain processing".into(), mandatory: true },
            FrameworkRequirement { key: "information_officer".into(), description: "Designated Information Officer registration".into(), mandatory: true },
            FrameworkRequirement { key: "security_safeguards".into(), description: "Technical and organizational security safeguards".into(), mandatory: true },
            FrameworkRequirement { key: "subject_participation".into(), description: "Data subject access, correction, and objection rights".into(), mandatory: true },
            FrameworkRequirement { key: "breach_notification".into(), description: "Breach notification to Regulator and data subjects".into(), mandatory: true },
            FrameworkRequirement { key: "cross_border_transfer".into(), description: "Cross-border data flow with operator agreement".into(), mandatory: true },
        ]
    }

    fn soc2_requirements() -> Vec<FrameworkRequirement> {
        vec![
            FrameworkRequirement { key: "access_control".into(), description: "Logical and physical access controls".into(), mandatory: true },
            FrameworkRequirement { key: "change_management".into(), description: "Change management and SDLC controls".into(), mandatory: true },
            FrameworkRequirement { key: "risk_assessment".into(), description: "Annual risk assessment and mitigation".into(), mandatory: true },
            FrameworkRequirement { key: "monitoring".into(), description: "System monitoring and alerting".into(), mandatory: true },
        ]
    }

    fn iso27001_requirements() -> Vec<FrameworkRequirement> {
        vec![
            FrameworkRequirement { key: "isms_scope".into(), description: "ISM scope definition and documentation".into(), mandatory: true },
            FrameworkRequirement { key: "risk_treatment".into(), description: "Risk treatment plan with Statement of Applicability".into(), mandatory: true },
            FrameworkRequirement { key: "internal_audit".into(), description: "Internal audit program".into(), mandatory: true },
            FrameworkRequirement { key: "management_review".into(), description: "Management review of the ISMS".into(), mandatory: true },
            FrameworkRequirement { key: "continuous_improvement".into(), description: "Continuous improvement process and corrective actions".into(), mandatory: true },
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_framework_parse_roundtrip() {
        for fw in [
            ComplianceFramework::Gdpr,
            ComplianceFramework::Hipaa,
            ComplianceFramework::Ccpa,
            ComplianceFramework::Casl,
            ComplianceFramework::Lgpd,
            ComplianceFramework::Pdpa,
            ComplianceFramework::Popia,
            ComplianceFramework::Soc2,
            ComplianceFramework::Iso27001,
        ] {
            let parsed = ComplianceFramework::parse(fw.as_str());
            assert_eq!(parsed, Some(fw));
        }
    }

    #[test]
    fn test_framework_parse_case_insensitive() {
        assert_eq!(
            ComplianceFramework::parse("GDPR"),
            Some(ComplianceFramework::Gdpr)
        );
        assert_eq!(
            ComplianceFramework::parse("Casl"),
            Some(ComplianceFramework::Casl)
        );
    }

    #[test]
    fn test_dpa_contacts() {
        assert!(ComplianceFramework::Gdpr.dpa_contact().is_some());
        assert!(ComplianceFramework::Casl.dpa_contact().is_some());
        assert!(ComplianceFramework::Lgpd.dpa_contact().is_some());
        assert!(ComplianceFramework::Pdpa.dpa_contact().is_some());
        assert!(ComplianceFramework::Popia.dpa_contact().is_some());
        assert!(ComplianceFramework::Ccpa.dpa_contact().is_some());
        assert!(ComplianceFramework::Iso27001.dpa_contact().is_none());
    }

    #[test]
    fn test_gdpr_marketing_blocked_without_consent() {
        let registered = vec![ComplianceFramework::Gdpr];
        let ctx = HashMap::from([
            ("has_consent".into(), "false".into()),
        ]);
        let outcome = FrameworkEnforcer::check_compliance(
            &registered,
            ComplianceAction::SendMarketingEmail,
            &ctx,
        );
        match outcome {
            EnforcementOutcome::Blocked { reason } => {
                assert!(reason.iter().any(|r| r.contains("GDPR")));
            }
            _ => panic!("Expected Blocked, got {outcome:?}"),
        }
    }

    #[test]
    fn test_gdpr_marketing_allowed_with_consent() {
        let registered = vec![ComplianceFramework::Gdpr];
        let ctx = HashMap::from([
            ("has_consent".into(), "true".into()),
            ("dsar_workflow_enabled".into(), "true".into()),
        ]);
        let outcome = FrameworkEnforcer::check_compliance(
            &registered,
            ComplianceAction::SendMarketingEmail,
            &ctx,
        );
        match outcome {
            EnforcementOutcome::Allowed => {}
            _ => panic!("Expected Allowed, got {outcome:?}"),
        }
    }

    #[test]
    fn test_casl_marketing_blocked_without_express_consent() {
        let registered = vec![ComplianceFramework::Casl];
        let ctx = HashMap::new();
        let outcome = FrameworkEnforcer::check_compliance(
            &registered,
            ComplianceAction::SendMarketingEmail,
            &ctx,
        );
        match outcome {
            EnforcementOutcome::Blocked { reason } => {
                assert!(reason.iter().any(|r| r.contains("CASL")));
            }
            _ => panic!("Expected Blocked, got {outcome:?}"),
        }
    }

    #[test]
    fn test_hipaa_blocked_without_baa() {
        let registered = vec![ComplianceFramework::Hipaa];
        let ctx = HashMap::new();
        let outcome = FrameworkEnforcer::check_compliance(
            &registered,
            ComplianceAction::ProcessHealthData,
            &ctx,
        );
        match outcome {
            EnforcementOutcome::Blocked { reason } => {
                assert!(reason.iter().any(|r| r.contains("HIPAA")));
            }
            _ => panic!("Expected Blocked, got {outcome:?}"),
        }
    }

    #[test]
    fn test_multiple_frameworks_aggregate() {
        let registered = vec![ComplianceFramework::Gdpr, ComplianceFramework::Casl];
        let ctx = HashMap::new();
        let outcome = FrameworkEnforcer::check_compliance(
            &registered,
            ComplianceAction::SendMarketingEmail,
            &ctx,
        );
        match outcome {
            EnforcementOutcome::Blocked { reason } => {
                assert!(reason.len() >= 2);
            }
            _ => panic!("Expected Blocked, got {outcome:?}"),
        }
    }

    #[test]
    fn test_get_requirements_for_all_frameworks() {
        let frameworks = [
            ComplianceFramework::Gdpr,
            ComplianceFramework::Hipaa,
            ComplianceFramework::Ccpa,
            ComplianceFramework::Casl,
            ComplianceFramework::Lgpd,
            ComplianceFramework::Pdpa,
            ComplianceFramework::Popia,
            ComplianceFramework::Soc2,
            ComplianceFramework::Iso27001,
        ];
        for fw in frameworks {
            let reqs = FrameworkEnforcer::get_framework_requirements(fw);
            assert!(!reqs.is_empty(), "No requirements for {fw:?}");
        }
    }

    #[test]
    fn test_lgpd_dpa_contact_in_warnings() {
        let registered = vec![ComplianceFramework::Lgpd];
        let ctx = HashMap::from([
            ("has_consent".into(), "true".into()),
        ]);
        let outcome = FrameworkEnforcer::check_compliance(
            &registered,
            ComplianceAction::CollectPersonalData,
            &ctx,
        );
        match outcome {
            EnforcementOutcome::Warned { warnings } => {
                assert!(warnings.iter().any(|w| w.contains("ANPD")));
            }
            _ => panic!("Expected Warned, got {outcome:?}"),
        }
    }

    #[test]
    fn test_popia_prior_authorization_block() {
        let registered = vec![ComplianceFramework::Popia];
        let ctx = HashMap::new();
        let outcome = FrameworkEnforcer::check_compliance(
            &registered,
            ComplianceAction::ProcessHealthData,
            &ctx,
        );
        match outcome {
            EnforcementOutcome::Blocked { reason } => {
                assert!(reason.iter().any(|r| r.contains("POPIA")));
            }
            _ => panic!("Expected Blocked, got {outcome:?}"),
        }
    }
}
