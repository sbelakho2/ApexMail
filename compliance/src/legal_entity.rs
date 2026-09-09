//! Legal-entity and non-billing public claim constants.
//!
//! This module is deliberately **not** a source of truth for plans, prices,
//! quotas, Stripe products, invoices, or application entitlements. Those are
//! operational concerns owned by
//! `services/mail-server/crates/billing-service/src/plans.rs`, the live
//! `plans` table, and verified Stripe webhooks. Static marketing surfaces are
//! checked against that catalog by `tools/validate_pricing_drift.py`.
//!
//! Keep company identity and legal/compliance wording here; do not add a
//! second commercial catalog to this crate.

use serde::{Deserialize, Serialize};

/// Location of the executable subscription-catalog authority, recorded here
/// so documentation consumers cannot mistake this module for billing config.
pub const RUNTIME_PRICING_AUTHORITY: &str =
    "services/mail-server/crates/billing-service/src/plans.rs";

// ─── Company constants ────────────────────────────────────────────────

pub const LEGAL_NAME: &str = "Bel Consulting OÜ";
pub const TRADING_NAME: &str = "ApexMail";
pub const REGISTRY_CODE: &str = "16588745";
pub const VAT_NUMBER: &str = "EE102951727";
pub const ADDRESS: &str = "Sakala tn 7-2, 10141 Tallinn, Estonia";
pub const CITY: &str = "Tallinn";
pub const POSTAL_CODE: &str = "10141";
pub const COUNTRY: &str = "Estonia";
pub const COUNTRY_CODE: &str = "EE";
pub const JURISDICTION: &str = "Republic of Estonia";
pub const GOVERNING_LAW: &str = "Estonian law";
pub const COURT_JURISDICTION: &str = "Harju County Court, Tallinn, Estonia";
pub const SUPPORT_EMAIL: &str = "support@apexmail.ee";
pub const PRIVACY_EMAIL: &str = "privacy@apexmail.ee";
pub const ABUSE_EMAIL: &str = "abuse@apexmail.ee";
pub const SECURITY_EMAIL: &str = "security@apexmail.ee";
pub const SALES_EMAIL: &str = "sales@apexmail.ee";
pub const BILLING_EMAIL: &str = "billing@apexmail.ee";
pub const ENTERPRISE_EMAIL: &str = "enterprise@apexmail.ee";
pub const DPO_CONTACT: &str = "privacy@apexmail.ee";
pub const GENERAL_EMAIL: &str = "hello@apexmail.ee";
pub const COPYRIGHT_ENTITY: &str = "Bel Consulting OÜ";
pub const COPYRIGHT_START_YEAR: u16 = 2025;
pub const FOUNDING_DATE: &str = "2025";

// ─── Public-claim constants ───────────────────────────────────────────

pub const API_LATENCY_TARGET: &str = "Production API SLA: P95 ≤ 500ms measured at gateway";
pub const API_LATENCY_P99_TARGET: &str = "Production API SLA: P99 < 1000ms measured at gateway";
pub const SANDBOX_LATENCY_TARGET: &str = "Sandbox validation target: typically under 120ms";
pub const PRIVATE_CLOUD_LATENCY_STATEMENT: &str =
    "Private Cloud illustrative: architecture-dependent, not an SLA";
pub const DELIVERY_PROCESSING_TARGET: &str = "≥99.9% within 5 minutes of submission";
pub const RECIPIENT_SERVER_ACCEPTANCE_TARGET: &str = "< 1 second at p95 first-hop SMTP";
pub const PLATFORM_UPTIME_TARGET: &str = "99.9%";
pub const WEBHOOK_PROCESSING_TARGET: &str = "p95 ≤ 5 seconds";
pub const DATA_RESIDENCY_WORDING: &str =
    "Data-residency commitments depend on the active deployment and applicable agreement. The supplied production configuration defaults telemetry object storage to an EU/EEA region; confirm active storage locations and transfer safeguards with ApexMail.";
pub const SECURITY_STATUS_WORDING: &str =
    "An independent penetration test has not yet been completed. Internal defense-in-depth controls include WAF, rate limiting, DDoS protection, audit logging, and encryption at rest and in transit.";
pub const COMPLIANCE_STATUS_WORDING: &str =
    "GDPR-oriented data-processing service. DPA available for review. Subprocessor list maintained. HIPAA not currently available. ISO 27001 certification is not currently offered.";
pub const CERTIFICATION_STATUS: &str =
    "ISO 27001: not currently certified. PCI DSS: not applicable (Stripe processes payments).";
pub const PENETRATION_TEST_STATUS: &str =
    "Planned — annual independent penetration test not yet completed.";

/// Backward-compatible name for the company-and-claims snapshot.
///
/// It intentionally has no plan or pricing fields. Consumers requiring
/// operational pricing must query the billing catalog instead.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CanonicalConfig {
    pub company: CompanyConfig,
    pub claims: ClaimsConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompanyConfig {
    pub trading_name: String,
    pub legal_name: String,
    pub registry_code: String,
    pub vat_number: String,
    pub address_street: String,
    pub address_city: String,
    pub address_postal_code: String,
    pub address_country: String,
    pub address_country_code: String,
    pub jurisdiction: String,
    pub governing_law: String,
    pub court_jurisdiction: String,
    pub founding_date: String,
    pub support_email: String,
    pub privacy_email: String,
    pub security_email: String,
    pub abuse_email: String,
    pub sales_email: String,
    pub billing_email: String,
    pub enterprise_email: String,
    pub general_email: String,
    pub dpo_contact: String,
    pub copyright_entity: String,
    pub copyright_start_year: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClaimsConfig {
    pub api_latency_target: String,
    pub api_latency_p99_target: String,
    pub sandbox_latency_target: String,
    pub private_cloud_latency_statement: String,
    pub delivery_processing_target: String,
    pub recipient_server_acceptance_target: String,
    pub platform_uptime_target: String,
    pub webhook_processing_target: String,
    pub data_residency_wording: String,
    pub security_status_wording: String,
    pub compliance_status_wording: String,
    pub certification_status: String,
    pub penetration_test_status: String,
}

impl Default for CanonicalConfig {
    fn default() -> Self {
        Self {
            company: CompanyConfig {
                trading_name: TRADING_NAME.into(),
                legal_name: LEGAL_NAME.into(),
                registry_code: REGISTRY_CODE.into(),
                vat_number: VAT_NUMBER.into(),
                address_street: "Sakala tn 7-2".into(),
                address_city: CITY.into(),
                address_postal_code: POSTAL_CODE.into(),
                address_country: COUNTRY.into(),
                address_country_code: COUNTRY_CODE.into(),
                jurisdiction: JURISDICTION.into(),
                governing_law: GOVERNING_LAW.into(),
                court_jurisdiction: COURT_JURISDICTION.into(),
                founding_date: FOUNDING_DATE.into(),
                support_email: SUPPORT_EMAIL.into(),
                privacy_email: PRIVACY_EMAIL.into(),
                security_email: SECURITY_EMAIL.into(),
                abuse_email: ABUSE_EMAIL.into(),
                sales_email: SALES_EMAIL.into(),
                billing_email: BILLING_EMAIL.into(),
                enterprise_email: ENTERPRISE_EMAIL.into(),
                general_email: GENERAL_EMAIL.into(),
                dpo_contact: DPO_CONTACT.into(),
                copyright_entity: COPYRIGHT_ENTITY.into(),
                copyright_start_year: COPYRIGHT_START_YEAR,
            },
            claims: ClaimsConfig {
                api_latency_target: API_LATENCY_TARGET.into(),
                api_latency_p99_target: API_LATENCY_P99_TARGET.into(),
                sandbox_latency_target: SANDBOX_LATENCY_TARGET.into(),
                private_cloud_latency_statement: PRIVATE_CLOUD_LATENCY_STATEMENT.into(),
                delivery_processing_target: DELIVERY_PROCESSING_TARGET.into(),
                recipient_server_acceptance_target: RECIPIENT_SERVER_ACCEPTANCE_TARGET.into(),
                platform_uptime_target: PLATFORM_UPTIME_TARGET.into(),
                webhook_processing_target: WEBHOOK_PROCESSING_TARGET.into(),
                data_residency_wording: DATA_RESIDENCY_WORDING.into(),
                security_status_wording: SECURITY_STATUS_WORDING.into(),
                compliance_status_wording: COMPLIANCE_STATUS_WORDING.into(),
                certification_status: CERTIFICATION_STATUS.into(),
                penetration_test_status: PENETRATION_TEST_STATUS.into(),
            },
        }
    }
}

impl CanonicalConfig {
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    pub fn to_json_minimal(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn company_identity_is_stable() {
        let config = CanonicalConfig::default();
        assert_eq!(config.company.registry_code, "16588745");
        assert_eq!(config.company.legal_name, "Bel Consulting OÜ");
        assert_eq!(config.company.trading_name, "ApexMail");
    }

    #[test]
    fn serialized_snapshot_has_no_pricing_catalog() {
        let config = CanonicalConfig::default();
        let json = serde_json::to_value(config).expect("serialize company snapshot");
        assert!(json.get("plans").is_none());
        assert!(json.get("pricing_plans").is_none());
    }

    #[test]
    fn canonical_json_round_trips() {
        let config = CanonicalConfig::default();
        let json = config.to_json().expect("serialize company snapshot");
        let parsed: CanonicalConfig = serde_json::from_str(&json).expect("deserialize snapshot");
        assert_eq!(parsed.company.vat_number, VAT_NUMBER);
    }

    #[test]
    fn pricing_authority_is_explicitly_external() {
        assert_eq!(
            RUNTIME_PRICING_AUTHORITY,
            "services/mail-server/crates/billing-service/src/plans.rs"
        );
    }
}
