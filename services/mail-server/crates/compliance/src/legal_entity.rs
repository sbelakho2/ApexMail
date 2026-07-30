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
pub const DPO_CONTACT: &str = "privacy@apexmail.ee";
pub const CONTACT_EMAIL: &str = "hello@apexmail.ee";
pub const ENTERPRISE_EMAIL: &str = "enterprise@apexmail.ee";
pub const PHONE: &str = "+372 (TBD)";
pub const COPYRIGHT_ENTITY: &str = "Bel Consulting OÜ";
pub const COPYRIGHT_START_YEAR: u16 = 2025;
pub const FOUNDING_DATE: &str = "2025";

#[derive(serde::Serialize, Debug, Clone)]
pub struct CanonicalConfig {
    pub company: CompanyConfig,
    pub plans: Vec<PlanConfig>,
    pub claims: ClaimsConfig,
}

#[derive(serde::Serialize, Debug, Clone)]
pub struct CompanyConfig {
    pub product_name: String,
    pub legal_name: String,
    pub registry_code: String,
    pub vat_number: String,
    pub address: String,
    pub city: String,
    pub country: String,
    pub governing_law: String,
    pub support_email: String,
    pub privacy_email: String,
    pub security_email: String,
    pub sales_email: String,
    pub billing_email: String,
    pub copyright_entity: String,
    pub copyright_start_year: u16,
}

#[derive(serde::Serialize, Debug, Clone)]
pub struct PlanConfig {
    pub name: String,
    pub display_name: String,
    pub price_monthly: i64,
    pub email_limit: i64,
    pub domain_limit: i32,
    pub user_limit: i32,
    pub dedicated_ips: i32,
    pub sla: String,
    pub features: Vec<String>,
}

#[derive(serde::Serialize, Debug, Clone)]
pub struct ClaimsConfig {
    pub soc2_status: String,
    pub pen_test_status: String,
    pub gdpr_status: String,
    pub hipaa_status: String,
    pub latency_p95_ms: u32,
    pub sla_uptime_pct: String,
    pub free_emails: u32,
    pub data_regions: Vec<String>,
    pub tls_version: String,
    pub encryption: String,
}

impl CanonicalConfig {
    pub fn default_config() -> Self {
        Self {
            company: CompanyConfig {
                product_name: TRADING_NAME.into(), legal_name: LEGAL_NAME.into(),
                registry_code: REGISTRY_CODE.into(), vat_number: VAT_NUMBER.into(),
                address: ADDRESS.into(), city: CITY.into(), country: COUNTRY.into(),
                governing_law: GOVERNING_LAW.into(), support_email: SUPPORT_EMAIL.into(),
                privacy_email: PRIVACY_EMAIL.into(), security_email: SECURITY_EMAIL.into(),
                sales_email: SALES_EMAIL.into(), billing_email: BILLING_EMAIL.into(),
                copyright_entity: COPYRIGHT_ENTITY.into(), copyright_start_year: COPYRIGHT_START_YEAR,
            },
            plans: vec![
                PlanConfig { name: "free".into(), display_name: "Free".into(), price_monthly: 0, email_limit: 30000, domain_limit: 1, user_limit: 1, dedicated_ips: 0, sla: "None".into(), features: vec!["30,000 emails/mo".into(), "1 domain".into(), "Community support".into()] },
                PlanConfig { name: "developer".into(), display_name: "Developer".into(), price_monthly: 29, email_limit: 50000, domain_limit: 5, user_limit: 3, dedicated_ips: 0, sla: "None".into(), features: vec!["50,000 emails/mo".into(), "€0.80/1,000 overage".into(), "5 domains".into(), "3 users".into()] },
                PlanConfig { name: "pro".into(), display_name: "Pro".into(), price_monthly: 89, email_limit: 150000, domain_limit: 15, user_limit: 8, dedicated_ips: 0, sla: "None".into(), features: vec!["150,000 emails/mo".into(), "€0.60/1,000 overage".into(), "15 domains".into(), "Dedicated IP eligible".into()] },
                PlanConfig { name: "growth".into(), display_name: "Growth".into(), price_monthly: 229, email_limit: 500000, domain_limit: 50, user_limit: 15, dedicated_ips: 1, sla: "None".into(), features: vec!["500,000 emails/mo".into(), "€0.35/1,000 overage".into(), "50 domains".into(), "1 managed dedicated IP".into()] },
                PlanConfig { name: "business".into(), display_name: "Business".into(), price_monthly: 699, email_limit: 2000000, domain_limit: 999999, user_limit: 25, dedicated_ips: 1, sla: "99.9% eligible".into(), features: vec!["2,000,000 emails/mo".into(), "€0.35/1,000 overage".into(), "Unlimited domains".into(), "1 managed dedicated IP".into()] },
                PlanConfig { name: "enterprise".into(), display_name: "Enterprise".into(), price_monthly: 3000, email_limit: 5000000, domain_limit: 999999, user_limit: 999999, dedicated_ips: 10, sla: "99.9%".into(), features: vec!["5,000,000 emails/mo".into(), "10 managed dedicated IPs".into(), "Annual commitment".into()] },
            ],
            claims: ClaimsConfig {
                soc2_status: "Not certified. SOC 2 Type II planned for 2028. Control mapping available.".into(),
                pen_test_status: "First external test planned — in procurement. Summary available after completion.".into(),
                gdpr_status: "GDPR-aligned processing in EU data centers.".into(),
                hipaa_status: "BAA available on Enterprise plan.".into(),
                latency_p95_ms: 500,
                sla_uptime_pct: "99.9% (Enterprise, annual contract)".into(),
                free_emails: 30000,
                data_regions: vec!["Germany".into(), "Finland".into()],
                tls_version: "TLS 1.2+ required, TLS 1.3 preferred".into(),
                encryption: "AES-256-GCM at rest, TLS in transit".into(),
            },
        }
    }

    pub fn to_json(&self) -> serde_json::Value {
        serde_json::to_value(self).unwrap_or_default()
    }
}
