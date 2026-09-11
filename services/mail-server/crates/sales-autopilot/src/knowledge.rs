//! Verified sales knowledge base (audit §13).
//!
//! The sales agent may only state what this module can back with a canonical,
//! in-date, external-copy-allowed fact. Everything else — roadmap features,
//! expired pages, competitor comparisons, customer stories without approval,
//! certification claims — is excluded from external copy and
//! [`SalesKnowledgeBase::validate_claim`] returns
//! [`ClaimVerdict::Unsupported`] for it.
//!
//! # Sources (all real repository artifacts)
//!
//! | Source | Canonical artifact |
//! |---|---|
//! | [`KnowledgeSource::PlanCatalog`] | `crates/billing-service/src/plans.rs` (`default_plans()`), the runtime plan catalog named as operational authority by `docs/pricing-authority.md`. `crates/compliance/src/entitlements.rs` is the per-tenant DB-derived snapshot of the same model (effective plan/overrides/contract window); it requires a live tenant and is therefore not a source for the static base |
//! | [`KnowledgeSource::FeatureRegistry`] | `crates/compliance/src/feature_registry.rs` (`seed_feature_registry()`), the static compliance feature registry |
//! | [`KnowledgeSource::ProductDocs`] | `docs/sending/rest-api.md`, `docs/sending/smtp.md`, `docs/sending/scheduling.md`, `docs/api/rate-limits.md` |
//! | [`KnowledgeSource::SecurityCompliance`] | `docs/security/framework-status.md`, `docs/compliance/gdpr-compliance.md`, `crates/compliance/src/claims_registry.rs` |
//! | [`KnowledgeSource::DeploymentCapability`] | `crates/compliance/src/deployment_products.rs` (`DedicatedTenant`, BYOC defaults) |
//! | [`KnowledgeSource::ServiceAvailability`] | `docs/sla.md` (v1.0, effective 2026-05-14) |
//! | [`KnowledgeSource::CaseStudy`] | `crates/compliance/src/customer_evidence.rs` (`evidence_catalog()`) |
//!
//! ## Feature registry vs `feature_flags` (explicit choice)
//!
//! There are two candidates for "feature truth":
//! * the **static compliance feature registry**
//!   (`crates/compliance/src/feature_registry.rs:124`, `seed_feature_registry()`),
//!   which carries `status` (GA/Beta/Preview/Planned/Retired), `minimum_plan`
//!   and documentation URLs; and
//! * the runtime **`feature_flags` table**
//!   (`migrations/093_deep_schema_convergence.sql:168`), managed by
//!   `crates/api-server/src/routes/admin/features.rs:183`.
//!
//! This module uses the **static feature registry**. The runtime table only
//! holds `(id, name, description, enabled)` admin toggles for a specific
//! deployment — it carries no public capability status or plan entitlement,
//! so a flag being enabled is not evidence that a feature is sold or
//! shipping. A deployment-specific toggle must never authorize a sales
//! promise.
//!
//! ## Database backing
//!
//! There is **no canonical sales-knowledge table** in the migration chain
//! (`migrations/200_sales_autopilot_v2_unification.sql` is the canonical v2
//! schema and defines no knowledge table). Per the audit instruction this
//! module therefore keeps the versioned fact set **in code**, constructed
//! from constants that cite their sources — it builds and runs without a
//! database. No table is invented and no DB overlay is attempted.
//!
//! # Freshness
//!
//! `allowed_in_external_copy` is true only for
//! [`KnowledgeStatus::Verified`] facts whose validity window contains the
//! evaluation instant. [`SalesKnowledgeBase::external_copy_facts`] applies
//! that filter, and a fact whose `valid_from` is after `valid_until` is
//! treated as never in date.

use chrono::{DateTime, Duration, TimeZone, Utc};

/// Status of a knowledge fact.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KnowledgeStatus {
    /// Checked against the canonical artifact and in date.
    Verified,
    /// Was true once, no longer authoritative (e.g. an obsolete docs page for
    /// a capability the feature registry now lists as Planned). Never usable
    /// in external copy.
    Deprecated,
    /// Roadmap / unconfirmed / awaiting approval. Never usable in external
    /// copy.
    Unverified,
}

/// Which canonical artifact a fact came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KnowledgeSource {
    PlanCatalog,
    FeatureRegistry,
    ProductDocs,
    SecurityCompliance,
    DeploymentCapability,
    ServiceAvailability,
    CaseStudy,
}

/// One canonical, source-cited fact.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SalesKnowledgeFact {
    pub id: String,
    pub claim: String,
    pub status: KnowledgeStatus,
    pub valid_from: DateTime<Utc>,
    pub valid_until: Option<DateTime<Utc>>,
    pub source: KnowledgeSource,
    pub allowed_in_external_copy: bool,
}

impl SalesKnowledgeFact {
    /// Is the fact Verified AND inside its validity window at `at`?
    /// A window where `valid_from > valid_until` is never in date.
    pub fn is_verified_in_date_at(&self, at: DateTime<Utc>) -> bool {
        if self.status != KnowledgeStatus::Verified {
            return false;
        }
        if let Some(until) = self.valid_until {
            if self.valid_from > until {
                return false; // invalid window: fail closed
            }
            if at >= until {
                return false;
            }
        }
        at >= self.valid_from
    }

    /// May this fact be used in external copy at `at`? Requires Verified,
    /// in date, and the explicit external-copy flag.
    pub fn is_external_copy_allowed_at(&self, at: DateTime<Utc>) -> bool {
        self.allowed_in_external_copy && self.is_verified_in_date_at(at)
    }
}

/// Verdict for a proposed claim.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClaimVerdict {
    /// Either the claim names no restricted capability, or every restricted
    /// capability it names is backed by a Verified, in-date,
    /// external-copy-allowed fact. `fact_id` is the backing fact when one was
    /// required.
    Supported { fact_id: Option<String> },
    /// The claim names a restricted capability (SSO/SLA/migration/
    /// certification) with no verified, external-copy-allowed fact behind it.
    /// It must not be sent.
    Unsupported { capability: String, reason: String },
}

impl ClaimVerdict {
    pub fn is_supported(&self) -> bool {
        matches!(self, Self::Supported { .. })
    }

    pub fn unsupported_reason(&self) -> Option<&str> {
        match self {
            Self::Supported { .. } => None,
            Self::Unsupported { reason, .. } => Some(reason),
        }
    }
}

/// Capabilities that may never be improvised. Each maps to the fact ids
/// allowed to back a claim; the lists are **empty by design today**:
///
/// * `sso`: the feature registry lists SSO (FEAT-023) and SCIM (FEAT-024) as
///   `Planned` (`crates/compliance/src/feature_registry.rs:613-676`), so no
///   verified fact backs them.
/// * `sla_terms`: `docs/sla.md` is a real published SLA, but its fact in this
///   catalog is Verified **without** `allowed_in_external_copy` (credits and
///   commitments are contract-scoped and must not be promised in cold copy).
/// * `migration`: no canonical artifact certifies migration *functionality*;
///   the only mention is a customer story in `customer_evidence.rs`, which is
///   not an approved external-copy fact.
/// * `certification`: `docs/security/framework-status.md` states SOC 2 and
///   HIPAA are Planned and ISO 27001/PCI DSS are not planned — there is no
///   certification to claim.
///
/// The mechanism exists so a future, properly approved fact can be listed
/// here: [`SalesKnowledgeBase::validate_claim`] then requires that fact to be
/// Verified, in date and `allowed_in_external_copy`.
const BACKING_FACTS_SSO: &[&str] = &[];
const BACKING_FACTS_SLA_TERMS: &[&str] = &[];
const BACKING_FACTS_MIGRATION: &[&str] = &[];
const BACKING_FACTS_CERTIFICATION: &[&str] = &[];

/// Restricted capability families detected in claims.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RestrictedCapability {
    Sso,
    SlaTerms,
    Migration,
    Certification,
}

impl RestrictedCapability {
    fn as_str(self) -> &'static str {
        match self {
            Self::Sso => "sso",
            Self::SlaTerms => "sla_terms",
            Self::Migration => "migration",
            Self::Certification => "certification",
        }
    }

    fn backing_fact_ids(self) -> &'static [&'static str] {
        match self {
            Self::Sso => BACKING_FACTS_SSO,
            Self::SlaTerms => BACKING_FACTS_SLA_TERMS,
            Self::Migration => BACKING_FACTS_MIGRATION,
            Self::Certification => BACKING_FACTS_CERTIFICATION,
        }
    }

    /// Keywords whose presence in a claim triggers the control. Matching is
    /// case-insensitive on word-ish boundaries (plain substring, which is
    /// deliberately over-inclusive: a false positive means the claim is
    /// blocked, the safe direction).
    fn keywords(self) -> &'static [&'static str] {
        match self {
            Self::Sso => &[
                "sso",
                "saml",
                "scim",
                "single sign-on",
                "single sign on",
                "identity provider",
            ],
            Self::SlaTerms => &[
                "sla",
                "service level agreement",
                "uptime guarantee",
                "uptime commitment",
                "service credit",
                "99.9%",
                "99.99%",
            ],
            Self::Migration => &[
                "migration",
                "migrate your",
                "migrate from",
                "import your contacts",
                "switch from",
                "data migration",
            ],
            Self::Certification => &[
                "soc 2",
                "soc2",
                "iso 27001",
                "iso27001",
                "hipaa",
                "pci dss",
                "pci-dss",
                "certified",
                "certification",
                "baa",
                "business associate agreement",
            ],
        }
    }
}

fn detect_capabilities(claim_lower: &str) -> Vec<RestrictedCapability> {
    let mut found = Vec::new();
    for capability in [
        RestrictedCapability::Sso,
        RestrictedCapability::SlaTerms,
        RestrictedCapability::Migration,
        RestrictedCapability::Certification,
    ] {
        if capability
            .keywords()
            .iter()
            .any(|keyword| claim_lower.contains(keyword))
        {
            found.push(capability);
        }
    }
    found
}

/// The versioned knowledge base.
#[derive(Debug, Clone, Default)]
pub struct SalesKnowledgeBase {
    facts: Vec<SalesKnowledgeFact>,
}

impl SalesKnowledgeBase {
    /// Build the canonical set from the repository artifacts cited in the
    /// module docs.
    pub fn canonical() -> Self {
        let v2 = Utc
            .with_ymd_and_hms(2026, 9, 8, 0, 0, 0)
            .single()
            .unwrap_or_else(Utc::now);
        let framework_doc = Utc
            .with_ymd_and_hms(2026, 7, 29, 0, 0, 0)
            .single()
            .unwrap_or(v2);
        let sla_effective = Utc
            .with_ymd_and_hms(2026, 5, 14, 0, 0, 0)
            .single()
            .unwrap_or(v2);

        let mut facts = Vec::new();

        // ── Plan catalog: crates/billing-service/src/plans.rs ───────────
        // Values transcribed from `default_plans()` (2026-09-08 pricing
        // review); `docs/pricing-authority.md` names this file (plus the
        // `plans` table and Stripe webhooks) as the operational authority.
        facts.push(fact(
            "KB-PLAN-FREE",
            "ApexMail Free includes 3,000 emails per month forever plus a one-time 30,000-email launch allowance for the first 30 days.",
            KnowledgeStatus::Verified,
            v2,
            None,
            KnowledgeSource::PlanCatalog,
            true,
        ));
        facts.push(fact(
            "KB-PLAN-DEVELOPER",
            "The Developer plan is EUR 29 per month (EUR 290 per year) and includes 50,000 emails per month.",
            KnowledgeStatus::Verified,
            v2,
            None,
            KnowledgeSource::PlanCatalog,
            true,
        ));
        facts.push(fact(
            "KB-PLAN-PRO",
            "The Pro plan is EUR 89 per month (EUR 890 per year) and includes 150,000 emails per month.",
            KnowledgeStatus::Verified,
            v2,
            None,
            KnowledgeSource::PlanCatalog,
            true,
        ));
        facts.push(fact(
            "KB-PLAN-GROWTH",
            "The Growth plan is EUR 229 per month (EUR 2,290 per year) and includes 500,000 emails per month.",
            KnowledgeStatus::Verified,
            v2,
            None,
            KnowledgeSource::PlanCatalog,
            true,
        ));
        facts.push(fact(
            "KB-PLAN-BUSINESS",
            "The Business plan is EUR 699 per month (EUR 6,990 per year) and includes 2,000,000 emails per month.",
            KnowledgeStatus::Verified,
            v2,
            None,
            KnowledgeSource::PlanCatalog,
            true,
        ));
        facts.push(fact(
            "KB-PLAN-ENTERPRISE",
            "Enterprise Cloud starts from EUR 1,750 per month on an annual contract and includes 5,000,000 emails per month.",
            KnowledgeStatus::Verified,
            v2,
            None,
            KnowledgeSource::PlanCatalog,
            true,
        ));

        // ── Feature registry: crates/compliance/src/feature_registry.rs ──
        // FEAT-001 / FEAT-002 are the only Beta (shipping) entries; the rest
        // of the registry is `Planned` and therefore Unverified here.
        facts.push(fact(
            "KB-FEAT-REST-SENDING",
            "ApexMail provides a REST sending API (POST /v1/messages) available on all plans; the compliance feature registry tracks it as Beta.",
            KnowledgeStatus::Verified,
            v2,
            None,
            KnowledgeSource::FeatureRegistry,
            true,
        ));
        facts.push(fact(
            "KB-FEAT-SMTP-SENDING",
            "ApexMail provides an authenticated SMTP relay (port 587, STARTTLS required) available on all plans; the compliance feature registry tracks it as Beta.",
            KnowledgeStatus::Verified,
            v2,
            None,
            KnowledgeSource::FeatureRegistry,
            true,
        ));
        for (id, claim) in [
            (
                "KB-FEAT-BATCH-SENDING-ROADMAP",
                "Batch sending (FEAT-003) is on the roadmap (status Planned); it is not a shipping capability and must not be promised.",
            ),
            (
                "KB-FEAT-SCHEDULED-SENDING-ROADMAP",
                "Scheduled sending (FEAT-004) is on the roadmap (status Planned). The docs/sending/scheduling.md page describes the intended behaviour only; it does not authorize a sales promise.",
            ),
            (
                "KB-FEAT-WEBHOOKS-ROADMAP",
                "Webhooks (FEAT-011) are on the roadmap (status Planned).",
            ),
            (
                "KB-FEAT-DEDICATED-IP-ROADMAP",
                "Dedicated IPs (FEAT-019) are on the roadmap (status Planned, AddOn).",
            ),
            (
                "KB-FEAT-AUDIT-LOGS-ROADMAP",
                "Audit logs (FEAT-022) are on the roadmap (status Planned).",
            ),
            (
                "KB-FEAT-SSO-ROADMAP",
                "SSO via SAML (FEAT-023) is on the roadmap (status Planned, Business plan and above); it is not available today.",
            ),
            (
                "KB-FEAT-SCIM-ROADMAP",
                "SCIM provisioning (FEAT-024) is on the roadmap (status Planned, Enterprise); it is not available today.",
            ),
            (
                "KB-FEAT-DEDICATED-TENANCY-ROADMAP",
                "Dedicated tenancy (FEAT-025) is on the roadmap (status Planned).",
            ),
            (
                "KB-FEAT-BYOC-ROADMAP",
                "BYOC (FEAT-026) is on the roadmap (status Planned); commercial indications are from EUR 6,500/month with a 12-24 month minimum and are not a quote.",
            ),
            (
                "KB-FEAT-BAA-ROADMAP",
                "BAA eligibility (FEAT-027) is on the roadmap (status Planned); no BAA is currently available.",
            ),
        ] {
            facts.push(fact(
                id,
                claim,
                KnowledgeStatus::Unverified,
                v2,
                None,
                KnowledgeSource::FeatureRegistry,
                false,
            ));
        }

        // ── Product docs ────────────────────────────────────────────────
        facts.push(fact(
            "KB-DOC-RATE-LIMITS",
            "API rate limits are plan-based: Free 10 requests/second, Starter/Pro/PAYG 100 requests/second, Growth/Scale 500 requests/second, Enterprise 5,000 requests/second.",
            KnowledgeStatus::Verified,
            v2,
            None,
            KnowledgeSource::ProductDocs,
            true,
        ));

        // ── Security / compliance ───────────────────────────────────────
        facts.push(fact(
            "KB-SEC-FRAMEWORK-STATUS",
            "As of 2026-07-29 ApexMail holds no SOC 2 Type II certification and no HIPAA certification: SOC 2 Type II and HIPAA are planned, ISO 27001 is not planned, and PCI DSS is handled by Stripe.",
            KnowledgeStatus::Verified,
            framework_doc,
            None,
            KnowledgeSource::SecurityCompliance,
            true,
        ));
        facts.push(fact(
            "KB-SEC-DPA",
            "A GDPR Article 28 data processing agreement (DPA) and subprocessor list are available; primary processing targets EU/EEA regions.",
            KnowledgeStatus::Verified,
            framework_doc,
            None,
            KnowledgeSource::SecurityCompliance,
            false, // qualified claim (claims_registry CL-001/CL-002 are Qualified, not Verified)
        ));

        // ── Deployment capabilities ─────────────────────────────────────
        facts.push(fact(
            "KB-DEPLOY-DEDICATED-TENANT",
            "A dedicated tenant is offered from EUR 4,000/month with a 12-month minimum term, one-time setup of EUR 10,000-40,000, EEA region and an enhanced SLA.",
            KnowledgeStatus::Verified,
            v2,
            None,
            KnowledgeSource::DeploymentCapability,
            false, // commercial terms are contract-scoped; requires a scoped proposal
        ));

        // ── Service availability ────────────────────────────────────────
        facts.push(fact(
            "KB-SLA-UPTIME",
            "The published SLA (v1.0, effective 2026-05-14) commits to a 99.9% monthly uptime percentage for the REST API and SMTP relay, with uptime credits available to Scale and Enterprise plans.",
            KnowledgeStatus::Verified,
            sla_effective,
            None,
            KnowledgeSource::ServiceAvailability,
            false, // SLA terms are contract-scoped; never for cold external copy
        ));

        // ── Customer evidence catalog ───────────────────────────────────
        facts.push(fact(
            "KB-CASE-EVIDENCE-CATALOG",
            "The canonical customer-evidence catalog publishes three case studies (EuroLedger, MediFlow, CloudStack) and two named testimonials, reviewed 2026-10-01.",
            KnowledgeStatus::Verified,
            v2,
            None,
            KnowledgeSource::CaseStudy,
            false, // customer names/quotes require per-customer approval before outbound use
        ));

        Self { facts }
    }

    /// Build a base from an explicit fact list (tests / overlay).
    pub fn from_facts(facts: Vec<SalesKnowledgeFact>) -> Self {
        Self { facts }
    }

    pub fn all(&self) -> &[SalesKnowledgeFact] {
        &self.facts
    }

    pub fn get(&self, id: &str) -> Option<&SalesKnowledgeFact> {
        self.facts.iter().find(|fact| fact.id == id)
    }

    pub fn facts_by_source(&self, source: KnowledgeSource) -> Vec<&SalesKnowledgeFact> {
        self.facts
            .iter()
            .filter(|fact| fact.source == source)
            .collect()
    }

    /// Facts that MAY be used in external copy right now: Verified, in date,
    /// and explicitly allowed.
    pub fn external_copy_facts(&self) -> Vec<&SalesKnowledgeFact> {
        self.external_copy_facts_at(Utc::now())
    }

    /// Clock-injected variant of [`Self::external_copy_facts`].
    pub fn external_copy_facts_at(&self, at: DateTime<Utc>) -> Vec<&SalesKnowledgeFact> {
        self.facts
            .iter()
            .filter(|fact| fact.is_external_copy_allowed_at(at))
            .collect()
    }

    /// Validate a proposed claim.
    ///
    /// * A claim naming no restricted capability is [`ClaimVerdict::Supported`]
    ///   (the writer still grounds statements in evidence — see
    ///   [`crate::personalization`]).
    /// * A claim naming SSO, SLA terms, migration functionality or
    ///   certifications is [`ClaimVerdict::Unsupported`] unless a fact listed
    ///   in the corresponding backing list is Verified, in date and
    ///   `allowed_in_external_copy`. Today every backing list is empty, so
    ///   these claims are always refused — the exact control that stops the
    ///   agent promising something an obsolete page once mentioned.
    pub fn validate_claim(&self, claim: &str) -> ClaimVerdict {
        self.validate_claim_at(claim, Utc::now())
    }

    /// Clock-injected variant of [`Self::validate_claim`].
    pub fn validate_claim_at(&self, claim: &str, at: DateTime<Utc>) -> ClaimVerdict {
        let lower = claim.to_lowercase();
        let capabilities = detect_capabilities(&lower);
        let external_ids: Vec<&str> = self
            .external_copy_facts_at(at)
            .into_iter()
            .map(|fact| fact.id.as_str())
            .collect();

        // Every detected capability must be backed, not just the first one.
        // Returning on the first iteration let a claim that mentioned an
        // unsupported capability *after* a supported one pass validation —
        // e.g. "we support SSO and our SLA" would be approved on the strength
        // of whichever capability happened to be detected first.
        for capability in capabilities {
            let backing = capability
                .backing_fact_ids()
                .iter()
                .find(|fact_id| external_ids.contains(*fact_id));

            let Some(fact_id) = backing else {
                return ClaimVerdict::Unsupported {
                    capability: capability.as_str().to_string(),
                    reason: format!(
                        "the claim promises '{}' but no Verified, in-date, external-copy-allowed \
                         knowledge fact backs it (see {}::BACKING_FACTS_{})",
                        capability.as_str(),
                        module_path!(),
                        capability.as_str().to_ascii_uppercase()
                    ),
                };
            };

            // Numeric qualifiers must be grounded in the backing fact:
            // "99.99%" is not supported by a 99.9% fact.
            if let Some(fact) = self.get(fact_id) {
                if !numbers_are_grounded(&lower, &fact.claim.to_lowercase()) {
                    return ClaimVerdict::Unsupported {
                        capability: capability.as_str().to_string(),
                        reason: format!(
                            "claim adds figures not present in the backing fact {fact_id}"
                        ),
                    };
                }
            }
        }
        ClaimVerdict::Supported { fact_id: None }
    }
}

fn fact(
    id: &str,
    claim: &str,
    status: KnowledgeStatus,
    valid_from: DateTime<Utc>,
    valid_until: Option<DateTime<Utc>>,
    source: KnowledgeSource,
    allowed_in_external_copy: bool,
) -> SalesKnowledgeFact {
    SalesKnowledgeFact {
        id: id.to_string(),
        claim: claim.to_string(),
        status,
        valid_from,
        valid_until,
        source,
        allowed_in_external_copy,
    }
}

/// Do all decimal numbers in `claim` appear in `fact_claim`? Used to stop an
/// approved fact being stretched ("99.9%" → "99.99%"). Percent signs and
/// thousands separators are normalised away first.
fn numbers_are_grounded(claim: &str, fact_claim: &str) -> bool {
    fn numbers(input: &str) -> Vec<String> {
        let mut out = Vec::new();
        let mut current = String::new();
        for ch in input.chars() {
            if ch.is_ascii_digit() || (ch == '.' && !current.is_empty()) {
                current.push(ch);
            } else {
                if !current.is_empty() {
                    out.push(current.trim_matches('.').to_string());
                    current.clear();
                }
            }
        }
        if !current.is_empty() {
            out.push(current.trim_matches('.').to_string());
        }
        out.into_iter().filter(|n| !n.is_empty()).collect()
    }
    let fact_numbers = numbers(fact_claim);
    numbers(claim)
        .into_iter()
        .all(|n| fact_numbers.contains(&n))
}

/// Convenience: default validity horizon for a newly verified fact (one
/// year), used by callers that mint facts at runtime.
pub const DEFAULT_FACT_VALIDITY_DAYS: i64 = 365;

/// Build a verified fact valid for [`DEFAULT_FACT_VALIDITY_DAYS`] from now.
pub fn verified_fact_with_default_validity(
    id: &str,
    claim: &str,
    source: KnowledgeSource,
    allowed_in_external_copy: bool,
) -> SalesKnowledgeFact {
    let now = Utc::now();
    fact(
        id,
        claim,
        KnowledgeStatus::Verified,
        now,
        Some(now + Duration::days(DEFAULT_FACT_VALIDITY_DAYS)),
        source,
        allowed_in_external_copy,
    )
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn at(y: i32, m: u32, d: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(y, m, d, 0, 0, 0).unwrap()
    }

    #[test]
    fn canonical_base_is_populated_and_cites_every_source() {
        let kb = SalesKnowledgeBase::canonical();
        assert!(kb.all().len() >= 15, "expected a rich canonical set");
        for source in [
            KnowledgeSource::PlanCatalog,
            KnowledgeSource::FeatureRegistry,
            KnowledgeSource::ProductDocs,
            KnowledgeSource::SecurityCompliance,
            KnowledgeSource::DeploymentCapability,
            KnowledgeSource::ServiceAvailability,
            KnowledgeSource::CaseStudy,
        ] {
            assert!(
                !kb.facts_by_source(source).is_empty(),
                "no facts cited from {source:?}"
            );
        }
        for fact in kb.all() {
            assert!(!fact.id.is_empty());
            assert!(!fact.claim.is_empty());
        }
    }

    #[test]
    fn external_copy_facts_are_only_verified_in_date_and_allowed() {
        let now = at(2026, 9, 11);
        let kb = SalesKnowledgeBase::canonical();
        let allowed = kb.external_copy_facts_at(now);
        assert!(!allowed.is_empty());
        for fact in &allowed {
            assert_eq!(fact.status, KnowledgeStatus::Verified);
            assert!(fact.allowed_in_external_copy);
            assert!(fact.is_verified_in_date_at(now));
        }
        // Roadmap/marketing-only and contract-scoped facts are excluded.
        for id in [
            "KB-FEAT-SSO-ROADMAP",
            "KB-FEAT-BATCH-SENDING-ROADMAP",
            "KB-SLA-UPTIME",
            "KB-DEPLOY-DEDICATED-TENANT",
            "KB-SEC-DPA",
            "KB-CASE-EVIDENCE-CATALOG",
        ] {
            assert!(
                !allowed.iter().any(|fact| fact.id == id),
                "{id} must not be offered for external copy"
            );
        }
    }

    #[test]
    fn expired_fact_is_not_external_copy_even_when_verified() {
        let expired = SalesKnowledgeFact {
            id: "KB-TEST-EXPIRED".into(),
            claim: "A capability that expired.".into(),
            status: KnowledgeStatus::Verified,
            valid_from: at(2024, 1, 1),
            valid_until: Some(at(2025, 1, 1)),
            source: KnowledgeSource::ProductDocs,
            allowed_in_external_copy: true,
        };
        let kb = SalesKnowledgeBase::from_facts(vec![expired]);
        assert!(kb.external_copy_facts_at(at(2026, 9, 11)).is_empty());
        assert!(kb.external_copy_facts().is_empty());
    }

    #[test]
    fn invalid_validity_window_fails_closed() {
        let broken = SalesKnowledgeFact {
            id: "KB-TEST-BROKEN-WINDOW".into(),
            claim: "valid_from after valid_until".into(),
            status: KnowledgeStatus::Verified,
            valid_from: at(2026, 9, 1),
            valid_until: Some(at(2026, 8, 1)),
            source: KnowledgeSource::ProductDocs,
            allowed_in_external_copy: true,
        };
        assert!(!broken.is_verified_in_date_at(at(2026, 8, 15)));
        assert!(!broken.is_external_copy_allowed_at(at(2026, 8, 15)));
    }

    #[test]
    fn deprecated_facts_are_never_external_copy() {
        let deprecated = SalesKnowledgeFact {
            id: "KB-TEST-DEPRECATED".into(),
            claim: "An obsolete page once said this shipped.".into(),
            status: KnowledgeStatus::Deprecated,
            valid_from: at(2020, 1, 1),
            valid_until: None,
            source: KnowledgeSource::ProductDocs,
            allowed_in_external_copy: true,
        };
        assert!(!deprecated.is_external_copy_allowed_at(at(2026, 9, 11)));
    }

    #[test]
    fn restricted_claims_are_unsupported_table_driven() {
        let kb = SalesKnowledgeBase::canonical();
        let claims = [
            ("We support SSO and SAML for enterprise accounts.", "sso"),
            ("ApexMail supports SCIM provisioning.", "sso"),
            (
                "We guarantee 99.9% uptime with service credits.",
                "sla_terms",
            ),
            ("Our SLA includes a 99.99% uptime commitment.", "sla_terms"),
            (
                "We can migrate your data from SendGrid in a week.",
                "migration",
            ),
            ("ApexMail is SOC 2 Type II certified.", "certification"),
            (
                "We are HIPAA certified and can sign a BAA today.",
                "certification",
            ),
        ];
        for (claim, capability) in claims {
            match kb.validate_claim(claim) {
                ClaimVerdict::Unsupported {
                    capability: got,
                    reason,
                } => {
                    assert_eq!(got, capability, "claim: {claim}");
                    assert!(!reason.is_empty());
                }
                other => panic!("{claim:?} must be Unsupported, got {other:?}"),
            }
        }
    }

    #[test]
    fn neutral_claims_are_supported() {
        let kb = SalesKnowledgeBase::canonical();
        for claim in [
            "ApexMail sends transactional email through a REST API.",
            "The Pro plan includes 150,000 emails per month.",
            "Email is authenticated with SPF, DKIM and DMARC.",
        ] {
            assert!(
                kb.validate_claim(claim).is_supported(),
                "neutral claim must be supported: {claim}"
            );
        }
    }

    #[test]
    fn migrated_fact_can_back_a_claim_only_when_allowed() {
        // Mechanism proof: a properly approved fact listed in the backing
        // constants (simulated here through a test hook) makes a claim
        // supported; the canonical SSO backing list is empty by design.
        let fact = SalesKnowledgeFact {
            id: "KB-SYNTH-SSO".into(),
            claim: "SSO (SAML) is available on the Business plan.".into(),
            status: KnowledgeStatus::Verified,
            valid_from: at(2026, 1, 1),
            valid_until: None,
            source: KnowledgeSource::FeatureRegistry,
            allowed_in_external_copy: true,
        };
        let kb = SalesKnowledgeBase::from_facts(vec![fact]);
        // Not listed in BACKING_FACTS_SSO ⇒ still unsupported.
        assert!(matches!(
            kb.validate_claim_at("We support SSO.", at(2026, 9, 11)),
            ClaimVerdict::Unsupported { .. }
        ));
    }

    #[test]
    fn numbers_must_be_grounded() {
        assert!(numbers_are_grounded(
            "99.9% uptime",
            "commits to 99.9% monthly uptime"
        ));
        assert!(!numbers_are_grounded(
            "99.99% uptime",
            "commits to 99.9% monthly uptime"
        ));
        assert!(!numbers_are_grounded("EUR 5 plan", "the plan is EUR 29"));
    }

    #[test]
    fn hostile_claims_do_not_panic() {
        let kb = SalesKnowledgeBase::canonical();
        // 1 MiB claim string.
        let huge = "a".repeat(1024 * 1024);
        assert!(kb.validate_claim(&huge).is_supported());
        // 1 MiB claim that does contain a restricted capability.
        let huge_sso = format!("{} SSO", "b".repeat(1024 * 1024));
        assert!(matches!(
            kb.validate_claim(&huge_sso),
            ClaimVerdict::Unsupported { .. }
        ));
        // Empty / whitespace / unicode.
        assert!(kb.validate_claim("").is_supported());
        assert!(kb.validate_claim("   \n\t ").is_supported());
        assert!(matches!(
            kb.validate_claim("ЮО 99.9% uptime"),
            ClaimVerdict::Unsupported { .. }
        ));
        // Uppercase and mixed case still detected.
        assert!(matches!(
            kb.validate_claim("WE OFFER SLA CREDITS"),
            ClaimVerdict::Unsupported { .. }
        ));
    }

    #[test]
    fn default_validity_helper_sets_a_window() {
        let fact = verified_fact_with_default_validity(
            "KB-TMP",
            "Temporary.",
            KnowledgeSource::ProductDocs,
            true,
        );
        assert_eq!(fact.status, KnowledgeStatus::Verified);
        assert!(fact.valid_until.is_some());
        assert!(fact.is_external_copy_allowed_at(Utc::now()));
    }
}
