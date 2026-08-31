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

/// Mirrors `billing-service/src/plans.rs` seeds.
pub static PLANS: LazyLock<[PlanFacts; 6]> = LazyLock::new(|| {
    [
        PlanFacts {
            name: "Free",
            price_eur: 0,
            email_limit: 30_000,
            api_call_limit: 300_000,
            team: 1,
            retention_days: 7,
        },
        PlanFacts {
            name: "Starter",
            price_eur: 25,
            email_limit: 50_000,
            api_call_limit: 500_000,
            team: 5,
            retention_days: 30,
        },
        PlanFacts {
            name: "Pro",
            price_eur: 65,
            email_limit: 150_000,
            api_call_limit: 2_000_000,
            team: 10,
            retention_days: 60,
        },
        PlanFacts {
            name: "Growth",
            price_eur: 150,
            email_limit: 500_000,
            api_call_limit: 5_000_000,
            team: 25,
            retention_days: 90,
        },
        PlanFacts {
            name: "Scale",
            price_eur: 350,
            email_limit: 2_000_000,
            api_call_limit: 20_000_000,
            team: 50,
            retention_days: 365,
        },
        PlanFacts {
            name: "Enterprise",
            price_eur: 3_000,
            email_limit: 5_000_000,
            api_call_limit: -1,
            team: -1,
            retention_days: 730,
        },
    ]
});

/// PAYG per-email tier rates (EUR/email) by cumulative volume.
pub const PAYG_TIERS: &[f64] = &[0.001, 0.0008, 0.0005, 0.0003];
/// Subscription overage: EUR per 1,000 emails beyond the included volume.
pub const OVERAGE_PER_1K: f64 = 0.40;
/// PAYG API calls: first 100K/month free, then EUR per 1,000 calls.
pub const PAYG_API_PER_1K: f64 = 0.10;
/// Paid plans may send into an overage allowance of +100% of the included
/// volume before the hard quota gate; the excess is invoiced at period end.
pub const OVERAGE_ALLOWANCE_PERCENT: i64 = 100;

/// Canonical whole-EUR prices (verifier input).
pub fn plan_prices() -> Vec<i64> {
    PLANS.iter().map(|p| p.price_eur).collect()
}

/// Canonical email limits (verifier input).
pub fn email_limits() -> Vec<i64> {
    PLANS.iter().map(|p| p.email_limit).collect()
}

/// Canonical sub-EUR rates: PAYG tiers, overage, API overage (verifier input).
pub fn canonical_rates() -> Vec<f64> {
    let mut r: Vec<f64> = PAYG_TIERS.to_vec();
    r.push(OVERAGE_PER_1K);
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
first 100K API calls/month free, then €0.10/1K. Subscription overage: €0.40 per 1,000 emails \
beyond the included volume — paid plans keep sending into a +{}% allowance and the excess is \
invoiced at period end; free plans stop at the limit.\n\n{}\n\n{}\n\n{}\n",
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
    fn catalog_matches_runtime_plans() {
        // Mirror of billing-service seeds (kept in lockstep deliberately;
        // a runtime catalog change must update this too — see module docs).
        assert_eq!(plan_prices(), vec![0, 25, 65, 150, 350, 3000]);
        assert_eq!(
            email_limits(),
            vec![30_000, 50_000, 150_000, 500_000, 2_000_000, 5_000_000]
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
        assert!(shared_knowledge_markdown().contains("€0.40 per 1,000"));
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
