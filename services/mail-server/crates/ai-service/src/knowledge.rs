//! Canonical knowledge — the SINGLE source of truth every AI surface reads.
//!
//! The prompt builders (pipeline, email agent), the deterministic verifier,
//! and the DNS record generator must never carry their own copies of facts.
//! Everything here mirrors the deployed runtime catalog
//! (`billing-service/src/plans.rs`) and the published docs; the runtime
//! remains authoritative and this module must be updated with it.
//!
//! Truthfulness rules (locked by tests + the marketing/compliance docs):
//! - HIPAA and SOC 2 are **not currently offered** on any plan.
//! - Security posture lists only controls that are actually wired in.

use std::sync::LazyLock;

/// One plan row of the canonical catalog (prices in whole EUR).
#[derive(Debug, Clone, Copy)]
pub struct PlanFacts {
    pub name: &'static str,
    pub price_eur: i64,
    pub email_limit: i64,
    pub api_call_limit: i64,
    pub team: i64,
    pub retention_days: i64,
}

/// DERIVED from `platform-catalog` — the canonical source the billing
/// runtime seeds from. The catalog prices are euro CENTS; the chat/verifier
/// surfaces speak whole EUR (the deployed catalog has no sub-euro monthly
/// price). This cannot drift: the catalog row IS the value.
pub static PLANS: LazyLock<Vec<PlanFacts>> = LazyLock::new(|| {
    platform_catalog::PLANS
        .iter()
        .map(|row| PlanFacts {
            name: row.display_name,
            price_eur: row.price_monthly_cents / 100,
            email_limit: row.email_limit,
            api_call_limit: row.api_call_limit,
            team: row.max_team_members,
            retention_days: row.max_retention_days,
        })
        .collect()
});

/// PAYG per-email tier rates (EUR/email) by cumulative volume — derived
/// from `platform-catalog`.
pub static PAYG_TIERS: LazyLock<Vec<f64>> = LazyLock::new(|| {
    platform_catalog::PAYG_TIERS_EUR_PER_EMAIL
        .iter()
        .map(|(_, rate)| *rate)
        .collect()
});
/// Per-plan subscription overage rates (EUR per 1,000 emails beyond the
/// included volume) — derived from the catalog. Plan order matches PLANS.
pub static OVERAGE_PER_1K: LazyLock<Vec<f64>> = LazyLock::new(|| {
    platform_catalog::PLANS
        .iter()
        .map(|row| {
            // millicents/email (cents/1000) → EUR per 1,000 emails:
            // 80 millicents/email = 0.08 cents/email = €0.80 per 1,000.
            row.overage_millicents_per_email
                .map(|m| m as f64 / 100.0)
                .unwrap_or(0.0)
        })
        .collect()
});
/// PAYG API calls: first 100K/month free, then EUR per 1,000 calls.
pub const PAYG_API_PER_1K: f64 = 0.10;
/// Paid plans may send into an overage allowance of +100% of the included
/// volume before the hard quota gate; the excess is invoiced at period end.
pub const OVERAGE_ALLOWANCE_PERCENT: i64 = 100;

/// Canonical whole-EUR monthly prices (verifier input). PAYG is excluded:
/// it is usage-priced with no monthly subscription price to verify.
pub fn plan_prices() -> Vec<i64> {
    PLANS
        .iter()
        .filter(|p| p.name != "Pay As You Go")
        .map(|p| p.price_eur)
        .collect()
}

/// Canonical email limits (verifier input). PAYG excluded (unlimited, not a
/// verifiable monthly limit).
pub fn email_limits() -> Vec<i64> {
    PLANS
        .iter()
        .filter(|p| p.name != "Pay As You Go")
        .map(|p| p.email_limit)
        .collect()
}

/// Canonical sub-EUR rates: PAYG tiers, then the per-plan overage rates,
/// then the PAYG API overage (verifier input; mirrors verifier::CANONICAL_RATES).
pub fn canonical_rates() -> Vec<f64> {
    let mut r: Vec<f64> = PAYG_TIERS.to_vec();
    for rate in OVERAGE_PER_1K.iter() {
        if *rate > 0.0 {
            r.push(*rate);
        }
    }
    r.push(PAYG_API_PER_1K);
    r
}

/// Hosts the assistant may reference in answers (verifier input).
pub const ALLOWED_HOSTS: &[&str] = &[
    "apexmail.ee",
    "api.apexmail.ee",
    "app.apexmail.ee",
    "track.apexmail.ee",
    "status.apexmail.ee",
];

/// Truthful compliance posture — matches the published compliance pages.
pub const COMPLIANCE_FACTS: &str = "GDPR: EU/EEA processing; a Data Processing \
Agreement is available. HIPAA: not currently offered. SOC 2: not currently \
offered. Encryption: TLS 1.2+ in transit, AES-256 at rest. Data locations and \
the subprocessor register are published on apexmail.ee.";

/// Truthful security posture — only controls wired into the deployed stack.
pub const SECURITY_FACTS: &str = "Security: TLS 1.2+ everywhere, AES-256 at \
rest, hashed API keys (keyed HMAC), MFA/TOTP support, KiwiCaptcha proof-of-work \
protection on login routes (web and control plane), per-tenant rate limits \
and quotas, signed audit logs, EU/EEA hosting, encrypted daily backups with \
verified restores.";

/// SDK availability — packages are NOT on public registries yet.
pub const SDK_FACTS: &str = "SDKs exist for Python, Go, PHP, Ruby and Java but \
are not yet published to public registries; source drops are provided on \
request via support@apexmail.ee. The REST API and SMTP submission work today.";

/// Stable shared-knowledge text for the CAG prefix. This block is byte-stable
/// across requests and tenants so serving-stack prefix caching (vLLM APC /
/// SGLang RadixAttention) always hits; facts change only with a new build.
pub fn shared_knowledge_markdown() -> String {
    use std::fmt::Write as _;
    let mut md = String::with_capacity(2048);
    let _ = writeln!(
        md,
        "# ApexMail canonical facts (authoritative — never contradict or recompute)"
    );
    let _ = writeln!(
        md,
        "\n| Plan | Price | Emails/mo | API calls/mo | Team | Event retention |"
    );
    let _ = writeln!(md, "|---|---|---|---|---|---|");
    for p in PLANS.iter() {
        let _ = writeln!(
            md,
            "| {} | €{} | {} | {} | {} | {} days |",
            p.name,
            p.price_eur,
            format_limit(p.email_limit),
            format_limit(p.api_call_limit),
            format_limit(p.team),
            p.retention_days
        );
    }
    let _ = write!(
        md,
        "\nPAYG per-email tiers: €0.001 (0–10K), €0.0008 (10K–100K), €0.0005 (100K–1M), €0.0003 (1M+); \
first 100K API calls/month free, then €0.10/1K. Subscription overage per 1,000 emails beyond \
the included volume: Developer €0.80, Pro €0.60, Growth/Business €0.35 (Enterprise Cloud \
contractual, €0.35 runtime default) — paid plans keep sending into a +{}% allowance and the \
excess is invoiced at period end; free plans stop at the limit.\n\n{}\n\n{}\n\n{}\n",
        OVERAGE_ALLOWANCE_PERCENT,
        COMPLIANCE_FACTS,
        SECURITY_FACTS,
        SDK_FACTS
    );
    md
}

fn format_limit(v: i64) -> String {
    if v < 0 {
        "Unlimited".to_string()
    } else {
        v.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalog_is_the_canonical_source() {
        // The catalog IS the source now: this pins the derived table to
        // platform-catalog and carries the pricing review's numbers as the
        // regression record.
        assert_eq!(plan_prices(), vec![0, 29, 89, 229, 699, 1750]);
        assert_eq!(
            email_limits(),
            vec![3_000, 50_000, 150_000, 500_000, 2_000_000, 5_000_000]
        );
    }

    #[test]
    fn shared_knowledge_is_truthful_about_certifications() {
        let md = shared_knowledge_markdown();
        assert!(md.contains("HIPAA: not currently offered"));
        assert!(md.contains("SOC 2: not currently offered"));
        assert!(!md.to_lowercase().contains("hipaa baa"));
        assert!(!md.to_lowercase().contains("soc 2 type ii"));
        // no unwired security-engine claims
        assert!(!md.contains("WAF"));
        assert!(!md.contains("IDS"));
    }

    #[test]
    fn shared_knowledge_is_stable_for_prefix_caching() {
        // Byte-stable across calls: required for KV-prefix cache hits.
        assert_eq!(shared_knowledge_markdown(), shared_knowledge_markdown());
        assert!(shared_knowledge_markdown().contains("Developer €0.80"));
        assert!(shared_knowledge_markdown().contains("Pro €0.60"));
    }

    #[test]
    fn security_facts_name_the_deployed_controls() {
        // KiwiCaptcha is a REAL deployed control (login PoW CAPTCHA) and the
        // assistant must be able to answer questions about it truthfully;
        // it must never reappear alongside the fake engine list.
        assert!(SECURITY_FACTS.contains("KiwiCaptcha"));
        assert!(SECURITY_FACTS.contains("proof-of-work"));
        assert!(!SECURITY_FACTS.contains("WAF"));
        assert!(!SECURITY_FACTS.contains("IDS"));
    }

    #[test]
    fn sdks_are_described_as_unpublished() {
        assert!(SDK_FACTS.contains("not yet published"));
    }
}
