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

/// Single source of truth for plan pricing and limits is the runtime
/// billing catalog — `services/mail-server/crates/billing-service/src/plans.rs`
/// (seeded from `docs/pricing.md`). This module deliberately does NOT embed a
/// plan catalog: a previous embedded copy drifted (free tier 10× the real
/// quota, Enterprise €3,000 vs the authoritative €1,750) and had zero
/// consumers. Validate marketing claims against the runtime authority with
/// `tools/validate_pricing_drift.py` and
/// `docs/marketing/check_pricing_parity.py`.
pub const RUNTIME_PRICING_AUTHORITY: &str =
    "services/mail-server/crates/billing-service/src/plans.rs";

