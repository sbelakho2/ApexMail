// compliance/src/legal_entity.rs
// SINGLE SOURCE OF TRUTH for the entire ApexMail website.
// Every page, template, document, email, invoice, and API response
// MUST retrieve these values from this file.
//
// DO NOT duplicate any of these values in page content, templates,
// localized pages, headers, footers, or billing code.

use serde::{Deserialize, Serialize};

// ─── Company Constants ──────────────────────────────────────────

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

// ─── Product Constants ──────────────────────────────────────────

// Plan email allowances (monthly)
pub const FREE_MONTHLY_EMAILS: u64 = 30_000;
pub const DEVELOPER_MONTHLY_EMAILS: u64 = 50_000;
pub const PRO_MONTHLY_EMAILS: u64 = 150_000;
pub const GROWTH_MONTHLY_EMAILS: u64 = 500_000;
pub const BUSINESS_MONTHLY_EMAILS: u64 = 2_000_000;
pub const ENTERPRISE_MONTHLY_EMAILS: u64 = 5_000_000;
pub const DEDICATED_TENANT_MONTHLY_EMAILS: u64 = 5_000_000;
pub const BYOC_MONTHLY_EMAILS: &str = "Contractual";

// Monthly prices (EUR)
pub const FREE_PRICE_EUR_MONTHLY: u64 = 0;
pub const DEVELOPER_PRICE_EUR_MONTHLY: u64 = 29;
pub const PRO_PRICE_EUR_MONTHLY: u64 = 89;
pub const GROWTH_PRICE_EUR_MONTHLY: u64 = 229;
pub const BUSINESS_PRICE_EUR_MONTHLY: u64 = 699;
pub const ENTERPRISE_PRICE_EUR_MONTHLY: u64 = 3_000;
pub const DEDICATED_TENANT_PRICE_EUR_MONTHLY: u64 = 4_000;
pub const BYOC_PRICE_EUR_MONTHLY: u64 = 6_500;

// Annual prices (EUR/month equivalent)
pub const DEVELOPER_PRICE_EUR_ANNUAL: u64 = 26;
pub const PRO_PRICE_EUR_ANNUAL: u64 = 80;
pub const GROWTH_PRICE_EUR_ANNUAL: u64 = 206;
pub const BUSINESS_PRICE_EUR_ANNUAL: u64 = 629;

// Annual discount ≈10%
pub const ANNUAL_DISCOUNT_PERCENT: u8 = 10;

// Overage rates (EUR cents per 1000 emails)
pub const FREE_OVERAGE_CENTS_PER_1K: u64 = 0;
pub const DEVELOPER_OVERAGE_CENTS_PER_1K: u64 = 80;
pub const PRO_OVERAGE_CENTS_PER_1K: u64 = 60;
pub const GROWTH_OVERAGE_CENTS_PER_1K: u64 = 35;
pub const BUSINESS_OVERAGE_CENTS_PER_1K: u64 = 35;
pub const ENTERPRISE_OVERAGE_CENTS_PER_1K_MIN: u64 = 22;
pub const ENTERPRISE_OVERAGE_CENTS_PER_1K_MAX: u64 = 35;

// Dedicated IP fees
pub const DEDICATED_IP_FEE_EUR_MONTHLY: u64 = 30;
pub const FREE_INCLUDED_DEDICATED_IPS: u32 = 0;
pub const DEVELOPER_INCLUDED_DEDICATED_IPS: u32 = 0;
pub const PRO_INCLUDED_DEDICATED_IPS: u32 = 0;
pub const GROWTH_INCLUDED_DEDICATED_IPS: u32 = 1;
pub const BUSINESS_INCLUDED_DEDICATED_IPS: u32 = 1;
pub const ENTERPRISE_INCLUDED_DEDICATED_IPS: u32 = 10;
pub const DEDICATED_TENANT_INCLUDED_DEDICATED_IPS: u32 = 2;

// Setup fees
pub const ENTERPRISE_SETUP_FEE: &str = "Negotiated per contract";
pub const DEDICATED_TENANT_SETUP_FEE: &str = "Negotiated per contract";
pub const BYOC_SETUP_FEE: &str = "Implementation fee per contract";

// Minimum contract periods
pub const ENTERPRISE_MINIMUM_MONTHS: u32 = 12;
pub const DEDICATED_TENANT_MINIMUM_MONTHS: u32 = 12;
pub const BYOC_MINIMUM_MONTHS: u32 = 12;

// API rate limits
pub const FREE_API_RATE_LIMIT: &str = "10 req/s";
pub const DEVELOPER_API_RATE_LIMIT: &str = "100 req/s";
pub const PRO_API_RATE_LIMIT: &str = "100 req/s";
pub const GROWTH_API_RATE_LIMIT: &str = "500 req/s";
pub const BUSINESS_API_RATE_LIMIT: &str = "500 req/s";
pub const ENTERPRISE_API_RATE_LIMIT: &str = "5,000 req/s";

// Retention periods
pub const FREE_EVENT_RETENTION_DAYS: u32 = 7;
pub const DEVELOPER_EVENT_RETENTION_DAYS: u32 = 30;
pub const PRO_EVENT_RETENTION_DAYS: u32 = 90;
pub const GROWTH_EVENT_RETENTION_DAYS: u32 = 90;
pub const BUSINESS_EVENT_RETENTION_DAYS: u32 = 180;

// Support levels
pub const FREE_SUPPORT: &str = "Community support";
pub const DEVELOPER_SUPPORT: &str = "2 business day response";
pub const PRO_SUPPORT: &str = "1 business day response";
pub const GROWTH_SUPPORT: &str = "8 business hour priority";
pub const BUSINESS_SUPPORT: &str = "4 business hour high-severity";
pub const ENTERPRISE_SUPPORT: &str = "Negotiated support hours";

// SLA availability
pub const SLA_AVAILABILITY_FREE: &str = "Best-effort, no SLA";
pub const SLA_AVAILABILITY_DEVELOPER: &str = "Best-effort, no SLA";
pub const SLA_AVAILABILITY_PRO: &str = "Best-effort, no SLA";
pub const SLA_AVAILABILITY_GROWTH: &str = "Best-effort, no SLA";
pub const SLA_AVAILABILITY_BUSINESS: &str = "Best-effort, no SLA";
pub const SLA_AVAILABILITY_ENTERPRISE: &str = "99.9% (contractual)";
pub const SLA_UPTIME_TARGET: &str = "99.9%";

// ─── Claim Constants ────────────────────────────────────────────

// Production API latency — measured at the API gateway over rolling 30-day windows.
// This is the contractual SLA metric for Enterprise plans.
pub const API_LATENCY_TARGET: &str = "Production API SLA: P95 ≤ 500ms measured at gateway";
pub const API_LATENCY_P99_TARGET: &str = "Production API SLA: P99 < 1000ms measured at gateway";

// Sandbox/validation latency — no email is sent; measures internal validation
// and queue acceptance only. Target is guidance, not an SLA.
pub const SANDBOX_LATENCY_TARGET: &str = "Sandbox validation target: typically under 120ms";

// Private Cloud latency — architecture-dependent. Actual latency depends on
// customer region, network topology, and deployment model. Not an SLA.
pub const PRIVATE_CLOUD_LATENCY_STATEMENT: &str = "Private Cloud illustrative: architecture-dependent, not an SLA";

pub const DELIVERY_PROCESSING_TARGET: &str = "≥99.9% within 5 minutes of submission";
pub const RECIPIENT_SERVER_ACCEPTANCE_TARGET: &str = "< 1 second at p95 first-hop SMTP";
pub const PLATFORM_UPTIME_TARGET: &str = "99.9%";
pub const WEBHOOK_PROCESSING_TARGET: &str = "p95 ≤ 5 seconds";
pub const DATA_RESIDENCY_WORDING: &str = "Data hosted in EU/EEA (Helsinki, Finland). No data transferred outside EU/EEA during processing and storage.";
pub const SECURITY_STATUS_WORDING: &str = "SOC 2 Type I planned (Q3 2027), Type II planned (Q2 2028). Penetration tests planned. Infrastructure secured with defense-in-depth: WAF, rate limiting, DDoS protection, audit logging, encryption at rest and in transit.";
pub const COMPLIANCE_STATUS_WORDING: &str = "GDPR-compliant data processing infrastructure. DPA pre-signed and available. Subprocessor list maintained. HIPAA not currently available. ISO 27001 planned based on customer demand.";
pub const CERTIFICATION_STATUS: &str = "SOC 2 Type I: planned Q3 2027. SOC 2 Type II: planned Q2 2028. ISO 27001: planned (subject to customer demand). GDPR compliance: active. PCI DSS: not applicable (Stripe processes payments).";
pub const PENETRATION_TEST_STATUS: &str = "Planned — annual independent penetration test not yet completed.";

// ─── Canonical Config Struct ────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CanonicalConfig {
    pub company: CompanyConfig,
    pub plans: Vec<PlanConfig>,
    pub claims: ClaimsConfig,
    pub dedicated_tenant: DedicatedTenantConfig,
    pub byoc: ByocConfig,
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
    pub support_email_alt: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlanConfig {
    pub name: String,
    pub price_eur_monthly: serde_json::Value,
    pub annual_price_eur_monthly: String,
    pub period: String,
    pub annual_suffix: String,
    pub description: String,
    pub features: Vec<String>,
    pub cta_label: String,
    pub cta_url_suffix: String,
    pub is_popular: bool,
    pub is_enterprise: bool,
    pub button_primary: bool,
    pub popular_label: Option<String>,
    pub monthly_emails: serde_json::Value,
    pub overage: String,
    pub api_rate_limit: String,
    pub event_retention: String,
    pub included_dedicated_ips: u32,
    pub dedicated_ip_addon_available: bool,
    pub dedicated_ip_fee: Option<String>,
    pub sla: String,
    pub support_level: String,
    pub minimum_contract_months: Option<u32>,
    pub setup_fee: Option<String>,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DedicatedTenantConfig {
    pub name: String,
    pub price_eur_monthly: u64,
    pub period: String,
    pub description: String,
    pub features: Vec<String>,
    pub cta_label: String,
    pub cta_url_suffix: String,
    pub is_enterprise: bool,
    pub monthly_emails: u64,
    pub included_dedicated_ips: u32,
    pub sla: String,
    pub minimum_contract_months: u32,
    pub setup_fee: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ByocConfig {
    pub name: String,
    pub price_eur_monthly: u64,
    pub period: String,
    pub description: String,
    pub features: Vec<String>,
    pub cta_label: String,
    pub cta_url_suffix: String,
    pub is_enterprise: bool,
    pub monthly_emails: String,
    pub sla: String,
    pub minimum_contract_months: u32,
    pub minimum_contract_months_max: u32,
    pub setup_fee: String,
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
                support_email_alt: SUPPORT_EMAIL.into(),
            },
            plans: vec![
                PlanConfig {
                    name: "Free".into(),
                    price_eur_monthly: serde_json::json!(0),
                    annual_price_eur_monthly: "0".into(),
                    period: "/month".into(),
                    annual_suffix: "/month".into(),
                    description: "Development, testing, and learning.".into(),
                    features: vec![
                        "30,000 emails/month (no auto overage)".into(),
                        "1 sending domain".into(),
                        "1 user".into(),
                        "REST API + SMTP relay".into(),
                        "Test mode (6 test addresses)".into(),
                        "7-day event history".into(),
                        "24hr content retention".into(),
                        "Community support".into(),
                    ],
                    cta_label: "Start Free".into(),
                    cta_url_suffix: "/signup".into(),
                    is_popular: false,
                    is_enterprise: false,
                    button_primary: false,
                    popular_label: None,
                    monthly_emails: serde_json::json!(FREE_MONTHLY_EMAILS),
                    overage: "None (no auto overage)".into(),
                    api_rate_limit: FREE_API_RATE_LIMIT.into(),
                    event_retention: format!("{} days", FREE_EVENT_RETENTION_DAYS),
                    included_dedicated_ips: FREE_INCLUDED_DEDICATED_IPS,
                    dedicated_ip_addon_available: false,
                    dedicated_ip_fee: None,
                    sla: SLA_AVAILABILITY_FREE.into(),
                    support_level: FREE_SUPPORT.into(),
                    minimum_contract_months: None,
                    setup_fee: None,
                },
                PlanConfig {
                    name: "Developer".into(),
                    price_eur_monthly: serde_json::json!(DEVELOPER_PRICE_EUR_MONTHLY),
                    annual_price_eur_monthly: DEVELOPER_PRICE_EUR_ANNUAL.to_string(),
                    period: "/month".into(),
                    annual_suffix: "/month (annual)".into(),
                    description: "For production applications needing dependable transactional sending.".into(),
                    features: vec![
                        "50,000 emails/month".into(),
                        "5 sending domains".into(),
                        "3 users".into(),
                        "Stored templates".into(),
                        "Signed webhooks (3 endpoints)".into(),
                        "30-day event history".into(),
                        "7-day content retention".into(),
                        "Basic inbound email".into(),
                        "Batch & scheduled sending".into(),
                        "2 business day support response".into(),
                    ],
                    cta_label: "Start Developer".into(),
                    cta_url_suffix: "/signup?plan=developer".into(),
                    is_popular: false,
                    is_enterprise: false,
                    button_primary: false,
                    popular_label: None,
                    monthly_emails: serde_json::json!(DEVELOPER_MONTHLY_EMAILS),
                    overage: "€0.80 per 1,000".into(),
                    api_rate_limit: DEVELOPER_API_RATE_LIMIT.into(),
                    event_retention: format!("{} days", DEVELOPER_EVENT_RETENTION_DAYS),
                    included_dedicated_ips: DEVELOPER_INCLUDED_DEDICATED_IPS,
                    dedicated_ip_addon_available: false,
                    dedicated_ip_fee: None,
                    sla: SLA_AVAILABILITY_DEVELOPER.into(),
                    support_level: DEVELOPER_SUPPORT.into(),
                    minimum_contract_months: None,
                    setup_fee: None,
                },
                PlanConfig {
                    name: "Pro".into(),
                    price_eur_monthly: serde_json::json!(PRO_PRICE_EUR_MONTHLY),
                    annual_price_eur_monthly: PRO_PRICE_EUR_ANNUAL.to_string(),
                    period: "/month".into(),
                    annual_suffix: "/month (annual)".into(),
                    description: "For growing SaaS teams needing deeper delivery visibility.".into(),
                    features: vec![
                        "150,000 emails/month".into(),
                        "15 sending domains".into(),
                        "8 users".into(),
                        "Custom tracking domain".into(),
                        "Advanced analytics".into(),
                        "5 webhook endpoints".into(),
                        "90-day event history".into(),
                        "30-day content retention".into(),
                        "10 inbox-placement tests/mo".into(),
                        "Email Grader".into(),
                        "Dedicated IP add-on (€30/mo)".into(),
                        "1 business day support response".into(),
                    ],
                    cta_label: "Start Pro".into(),
                    cta_url_suffix: "/signup?plan=pro".into(),
                    is_popular: true,
                    is_enterprise: false,
                    button_primary: true,
                    popular_label: Some("Popular".into()),
                    monthly_emails: serde_json::json!(PRO_MONTHLY_EMAILS),
                    overage: "€0.60 per 1,000".into(),
                    api_rate_limit: PRO_API_RATE_LIMIT.into(),
                    event_retention: format!("{} days", PRO_EVENT_RETENTION_DAYS),
                    included_dedicated_ips: PRO_INCLUDED_DEDICATED_IPS,
                    dedicated_ip_addon_available: true,
                    dedicated_ip_fee: Some(format!("€{}/mo", DEDICATED_IP_FEE_EUR_MONTHLY)),
                    sla: SLA_AVAILABILITY_PRO.into(),
                    support_level: PRO_SUPPORT.into(),
                    minimum_contract_months: None,
                    setup_fee: None,
                },
                PlanConfig {
                    name: "Growth".into(),
                    price_eur_monthly: serde_json::json!(GROWTH_PRICE_EUR_MONTHLY),
                    annual_price_eur_monthly: GROWTH_PRICE_EUR_ANNUAL.to_string(),
                    period: "/month".into(),
                    annual_suffix: "/month (annual)".into(),
                    description: "For established high-volume transactional applications.".into(),
                    features: vec![
                        "500,000 emails/month".into(),
                        "50 sending domains".into(),
                        "15 users".into(),
                        "1 managed dedicated IP (eligibility review)".into(),
                        "Managed IP warm-up".into(),
                        "Audit logs".into(),
                        "5 subaccounts".into(),
                        "20 inbox-placement tests/mo".into(),
                        "90-day event history".into(),
                        "Saved searches & data exports".into(),
                        "8 business hour priority support".into(),
                    ],
                    cta_label: "Start Growth".into(),
                    cta_url_suffix: "/signup?plan=growth".into(),
                    is_popular: false,
                    is_enterprise: false,
                    button_primary: false,
                    popular_label: None,
                    monthly_emails: serde_json::json!(GROWTH_MONTHLY_EMAILS),
                    overage: "€0.35 per 1,000".into(),
                    api_rate_limit: GROWTH_API_RATE_LIMIT.into(),
                    event_retention: format!("{} days", GROWTH_EVENT_RETENTION_DAYS),
                    included_dedicated_ips: GROWTH_INCLUDED_DEDICATED_IPS,
                    dedicated_ip_addon_available: true,
                    dedicated_ip_fee: Some(format!("€{}/mo (1 included)", DEDICATED_IP_FEE_EUR_MONTHLY)),
                    sla: SLA_AVAILABILITY_GROWTH.into(),
                    support_level: GROWTH_SUPPORT.into(),
                    minimum_contract_months: None,
                    setup_fee: None,
                },
                PlanConfig {
                    name: "Business".into(),
                    price_eur_monthly: serde_json::json!(BUSINESS_PRICE_EUR_MONTHLY),
                    annual_price_eur_monthly: BUSINESS_PRICE_EUR_ANNUAL.to_string(),
                    period: "/month".into(),
                    annual_suffix: "/month (annual)".into(),
                    description: "For platforms needing identity controls and account separation.".into(),
                    features: vec![
                        "2,000,000 emails/month".into(),
                        "Unlimited domains (subject to review)".into(),
                        "25 users".into(),
                        "1 managed dedicated IP (eligibility review)".into(),
                        "25 subaccounts".into(),
                        "SAML SSO + RBAC".into(),
                        "180-day event history".into(),
                        "30–90 day content retention".into(),
                        "50 inbox-placement tests/mo".into(),
                        "Quarterly deliverability review".into(),
                        "DPA support".into(),
                        "4 business hour high-severity response".into(),
                    ],
                    cta_label: "Start Business".into(),
                    cta_url_suffix: "/signup?plan=business".into(),
                    is_popular: false,
                    is_enterprise: false,
                    button_primary: false,
                    popular_label: None,
                    monthly_emails: serde_json::json!(BUSINESS_MONTHLY_EMAILS),
                    overage: "€0.35 per 1,000".into(),
                    api_rate_limit: BUSINESS_API_RATE_LIMIT.into(),
                    event_retention: format!("{} days", BUSINESS_EVENT_RETENTION_DAYS),
                    included_dedicated_ips: BUSINESS_INCLUDED_DEDICATED_IPS,
                    dedicated_ip_addon_available: true,
                    dedicated_ip_fee: Some(format!("€{}/mo (1 included)", DEDICATED_IP_FEE_EUR_MONTHLY)),
                    sla: SLA_AVAILABILITY_BUSINESS.into(),
                    support_level: BUSINESS_SUPPORT.into(),
                    minimum_contract_months: None,
                    setup_fee: None,
                },
                PlanConfig {
                    name: "Enterprise".into(),
                    price_eur_monthly: serde_json::json!(ENTERPRISE_PRICE_EUR_MONTHLY),
                    annual_price_eur_monthly: ENTERPRISE_PRICE_EUR_MONTHLY.to_string(),
                    period: "/month".into(),
                    annual_suffix: "/month (annual commitment)".into(),
                    description: "For regulated organizations with contractual controls. Annual commitment.".into(),
                    features: vec![
                        "5,000,000 emails/month".into(),
                        "10 managed dedicated IPs".into(),
                        "50 subaccounts".into(),
                        "SAML SSO + SCIM".into(),
                        "Custom RBAC + premium audit logs".into(),
                        "Named CSM".into(),
                        "DPA + BAA review eligibility".into(),
                        "SIG/CAIQ/HECVAT response".into(),
                        "Custom retention".into(),
                        "99.9% SLA (contractual)".into(),
                        "Negotiated support hours".into(),
                        "Monthly service review".into(),
                    ],
                    cta_label: "Contact Sales".into(),
                    cta_url_suffix: "/contact/sales/".into(),
                    is_popular: false,
                    is_enterprise: true,
                    button_primary: false,
                    popular_label: None,
                    monthly_emails: serde_json::json!(ENTERPRISE_MONTHLY_EMAILS),
                    overage: "€0.22–€0.35 per 1,000 (contract)".into(),
                    api_rate_limit: ENTERPRISE_API_RATE_LIMIT.into(),
                    event_retention: "Custom".into(),
                    included_dedicated_ips: ENTERPRISE_INCLUDED_DEDICATED_IPS,
                    dedicated_ip_addon_available: true,
                    dedicated_ip_fee: Some(format!("10 included (€{}/mo per additional)", DEDICATED_IP_FEE_EUR_MONTHLY)),
                    sla: SLA_AVAILABILITY_ENTERPRISE.into(),
                    support_level: ENTERPRISE_SUPPORT.into(),
                    minimum_contract_months: Some(ENTERPRISE_MINIMUM_MONTHS),
                    setup_fee: Some(ENTERPRISE_SETUP_FEE.into()),
                },
            ],
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
            dedicated_tenant: DedicatedTenantConfig {
                name: "Dedicated Tenant".into(),
                price_eur_monthly: DEDICATED_TENANT_PRICE_EUR_MONTHLY,
                period: "/month".into(),
                description: "Dedicated application and data tenancy. 12-month minimum.".into(),
                features: vec![
                    "Dedicated application tenancy".into(),
                    "Dedicated data tenancy".into(),
                    "Defined EEA region".into(),
                    "5,000,000 emails/month baseline".into(),
                    "2 managed dedicated IPs".into(),
                    "Custom backup policy".into(),
                    "Enhanced SLA".into(),
                    "Monthly service review".into(),
                    "Named technical owner".into(),
                ],
                cta_label: "Contact Sales".into(),
                cta_url_suffix: "/contact/sales/".into(),
                is_enterprise: true,
                monthly_emails: DEDICATED_TENANT_MONTHLY_EMAILS,
                included_dedicated_ips: DEDICATED_TENANT_INCLUDED_DEDICATED_IPS,
                sla: "99.95% uptime".into(),
                minimum_contract_months: DEDICATED_TENANT_MINIMUM_MONTHS,
                setup_fee: DEDICATED_TENANT_SETUP_FEE.into(),
            },
            byoc: ByocConfig {
                name: "BYOC".into(),
                price_eur_monthly: BYOC_PRICE_EUR_MONTHLY,
                period: "/month".into(),
                description: "Private deployment in your cloud. 12–24 month minimum.".into(),
                features: vec![
                    "Customer cloud account".into(),
                    "Infrastructure as code".into(),
                    "Supported cloud providers".into(),
                    "Software license + upgrades".into(),
                    "Deployment automation".into(),
                    "Operational support".into(),
                    "Deliverability services".into(),
                    "Architecture reviews".into(),
                    "Security document maintenance".into(),
                ],
                cta_label: "Contact Sales".into(),
                cta_url_suffix: "/contact/sales/".into(),
                is_enterprise: true,
                monthly_emails: BYOC_MONTHLY_EMAILS.into(),
                sla: "App SLA 99.9%; infra is customer responsibility".into(),
                minimum_contract_months: BYOC_MINIMUM_MONTHS,
                minimum_contract_months_max: 24,
                setup_fee: BYOC_SETUP_FEE.into(),
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
    fn test_registry_code_is_16588745() {
        assert_eq!(REGISTRY_CODE, "16588745");
    }

    #[test]
    fn test_legal_name_is_bel_consulting_ou() {
        assert_eq!(LEGAL_NAME, "Bel Consulting OÜ");
    }

    #[test]
    fn test_all_plans_have_names() {
        let config = CanonicalConfig::default();
        assert!(!config.plans.is_empty());
        for plan in &config.plans {
            assert!(!plan.name.is_empty(), "Plan has empty name");
            assert!(!plan.features.is_empty(), "Plan {} has no features", plan.name);
        }
        assert_eq!(config.plans.len(), 6, "Expected 6 self-serve plans (Free, Developer, Pro, Growth, Business, Enterprise); Dedicated Tenant and BYOC are separate structs");
    }

    #[test]
    fn test_plan_prices_are_consistent() {
        let config = CanonicalConfig::default();
        let enterprise = config.plans.iter().find(|p| p.name == "Enterprise").unwrap();
        assert_eq!(enterprise.price_eur_monthly, serde_json::json!(ENTERPRISE_PRICE_EUR_MONTHLY));
        let free = config.plans.iter().find(|p| p.name == "Free").unwrap();
        assert_eq!(free.price_eur_monthly, serde_json::json!(0));
    }

    #[test]
    fn test_enterprise_emails_are_5m() {
        let config = CanonicalConfig::default();
        let enterprise = config.plans.iter().find(|p| p.name == "Enterprise").unwrap();
        assert_eq!(enterprise.monthly_emails, serde_json::json!(ENTERPRISE_MONTHLY_EMAILS));
    }

    #[test]
    fn test_dedicated_ip_entitlements() {
        let config = CanonicalConfig::default();
        let pro = config.plans.iter().find(|p| p.name == "Pro").unwrap();
        assert_eq!(pro.included_dedicated_ips, 0);
        let enterprise = config.plans.iter().find(|p| p.name == "Enterprise").unwrap();
        assert_eq!(enterprise.included_dedicated_ips, 10);
    }

    #[test]
    fn test_company_config_matches_constants() {
        let config = CanonicalConfig::default();
        assert_eq!(config.company.legal_name, LEGAL_NAME);
        assert_eq!(config.company.registry_code, REGISTRY_CODE);
        assert_eq!(config.company.vat_number, VAT_NUMBER);
        assert_eq!(config.company.copyright_entity, COPYRIGHT_ENTITY);
    }

    #[test]
    fn test_canonical_json_is_valid() {
        let config = CanonicalConfig::default();
        let json = config.to_json().unwrap();
        let parsed: CanonicalConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.company.registry_code, REGISTRY_CODE);
    }

    #[test]
    fn test_single_source_of_truth_for_company() {
        let config = CanonicalConfig::default();
        assert_eq!(config.company.registry_code, "16588745", "Registry code must be 16588745 everywhere");
        assert_eq!(config.company.legal_name, "Bel Consulting OÜ", "Legal entity must be Bel Consulting OÜ everywhere");
        assert_eq!(config.company.trading_name, "ApexMail", "Trading name must be ApexMail everywhere");
    }
}
