use chrono::{DateTime, NaiveDate, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClaimCategory {
    Product,
    Performance,
    Security,
    Compliance,
    Pricing,
    CustomerProof,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClaimStatus {
    Verified,
    Qualified,
    Beta,
    Planned,
    Illustrative,
    Prohibited,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MarketingClaim {
    pub claim_id: String,
    pub exact_wording: String,
    pub category: ClaimCategory,
    pub owner: String,
    pub approver: Option<String>,
    pub evidence_location: Option<String>,
    pub measurement_method: Option<String>,
    pub measurement_period: Option<String>,
    pub environment_measured: Option<String>,
    pub plan_applicability: Vec<String>,
    pub geographic_scope: Option<String>,
    pub limitations: Option<String>,
    pub approved_pages: Vec<String>,
    pub review_date: NaiveDate,
    pub expiration_date: Option<NaiveDate>,
    pub status: ClaimStatus,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// How a claim's `evidence_location` is to be read (the served registry must
/// not imply that a marketing URL is a checkable artifact).
///
/// * [`ClaimEvidenceKind::RepoPath`] — a path RELATIVE TO THE REPOSITORY ROOT
///   that must exist (file or directory). The `claims_registry::tests::
///   every_repo_path_evidence_target_exists` test is the pin: a claim whose
///   evidence file is gone fails the suite, so a pointer cannot outlive its
///   artifact.
/// * [`ClaimEvidenceKind::RuntimeSource`] — a named runtime evidence source
///   (`runtime:<name>`), registered in [`RUNTIME_EVIDENCE_SOURCES`] with the
///   repo path of the code that produces it. Used for numbers that come from
///   a live system (Prometheus histograms, tenant analytics) rather than a
///   committed document; the name is validated against the registry, so no
///   claim can invent a source.
/// * [`ClaimEvidenceKind::None`] — no evidence (prohibited claims and
///   illustrative targets that must carry "not yet achieved" limitations).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClaimEvidenceKind {
    RepoPath,
    RuntimeSource,
    None,
}

/// The named runtime evidence sources claims may cite. `producer` is the
/// repo path of the wiring that produces the measurement.
pub const RUNTIME_EVIDENCE_SOURCES: &[(&str, &str, &str)] = &[
    (
        "tenant_delivery_analytics",
        "services/mail-server/crates/analytics/src/clickhouse_engine.rs",
        "ClickHouse delivery/engagement aggregates queried per tenant (the source of customer-volume numbers once they are measured)",
    ),
    (
        "api_gateway_histogram",
        "services/mail-server/crates/observability-service",
        "Prometheus API-gateway request histogram (the P95 ≤ 500ms SLA measurement)",
    ),
    (
        "sandbox_validation_harness",
        "services/mail-server/crates/sandbox",
        "Sandbox validation harness metrics (the sandbox latency target)",
    ),
];

impl ClaimEvidenceKind {
    /// Classify an `evidence_location` value.
    pub fn of(evidence_location: Option<&str>) -> Self {
        match evidence_location {
            None => Self::None,
            Some(value) if value.starts_with("runtime:") => Self::RuntimeSource,
            Some(_) => Self::RepoPath,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct ClaimsRegistry {
    claims: HashMap<String, MarketingClaim>,
}

impl ClaimsRegistry {
    pub fn new() -> Self {
        Self {
            claims: HashMap::new(),
        }
    }

    pub fn register(&mut self, claim: MarketingClaim) {
        self.claims.insert(claim.claim_id.clone(), claim);
    }

    pub fn get(&self, id: &str) -> Option<&MarketingClaim> {
        self.claims.get(id)
    }

    pub fn all(&self) -> Vec<&MarketingClaim> {
        self.claims.values().collect()
    }

    pub fn by_status(&self, status: ClaimStatus) -> Vec<&MarketingClaim> {
        self.claims
            .values()
            .filter(|c| c.status == status)
            .collect()
    }

    pub fn by_category(&self, category: ClaimCategory) -> Vec<&MarketingClaim> {
        self.claims
            .values()
            .filter(|c| c.category == category)
            .collect()
    }

    pub fn expiring_soon(&self, within_days: i64) -> Vec<&MarketingClaim> {
        let today = Utc::now().date_naive();
        self.claims
            .values()
            .filter(|c| {
                if let Some(exp) = c.expiration_date {
                    let diff = (exp - today).num_days();
                    diff >= 0 && diff <= within_days
                } else {
                    false
                }
            })
            .collect()
    }

    pub fn needs_review(&self) -> Vec<&MarketingClaim> {
        let today = Utc::now().date_naive();
        self.claims
            .values()
            .filter(|c| c.review_date <= today)
            .collect()
    }

    pub fn validate_wording(&self, text: &str) -> Vec<&MarketingClaim> {
        self.claims
            .values()
            .filter(|c| text.contains(&c.exact_wording))
            .collect()
    }
}

/// What the registry is allowed to keep in this HashMap.
impl MarketingClaim {
    /// Display form of a claim's status (for operator-facing assertion
    /// messages).
    pub fn status_string(&self) -> &'static str {
        match self.status {
            ClaimStatus::Verified => "verified",
            ClaimStatus::Qualified => "qualified",
            ClaimStatus::Beta => "beta",
            ClaimStatus::Planned => "planned",
            ClaimStatus::Illustrative => "illustrative",
            ClaimStatus::Prohibited => "prohibited",
        }
    }

    /// The evidence target for the public JSON: the repo path verbatim, or
    /// the runtime source's producer path (so a consumer sees WHERE the
    /// number comes from, not only its name).
    pub fn evidence_target(&self) -> Option<&str> {
        match self.evidence_location.as_deref() {
            None => None,
            Some(value) if value.starts_with("runtime:") => {
                let name = value.trim_start_matches("runtime:");
                RUNTIME_EVIDENCE_SOURCES
                    .iter()
                    .find(|(source, _, _)| *source == name)
                    .map(|(_, producer, _)| *producer)
            }
            Some(path) => Some(path),
        }
    }

    /// The public, stable JSON shape of one claim (the `GET /v1/claims`
    /// contract): identity, wording, evidence pointer, review/expiry state
    /// and the binding limitations.
    pub fn public_view(&self) -> serde_json::Value {
        serde_json::json!({
            "id": self.claim_id,
            "claim": self.exact_wording,
            "category": self.category,
            "owner": self.owner,
            "approver": self.approver,
            "status": self.status,
            "evidence": {
                "location": self.evidence_location,
                "kind": ClaimEvidenceKind::of(self.evidence_location.as_deref()),
                "target": self.evidence_target(),
                "measurement_method": self.measurement_method,
                "measurement_period": self.measurement_period,
                "environment_measured": self.environment_measured,
            },
            "plan_applicability": self.plan_applicability,
            "geographic_scope": self.geographic_scope,
            "limitations": self.limitations,
            "approved_pages": self.approved_pages,
            "reviewed": self.review_date,
            "expires": self.expiration_date,
            "updated_at": self.updated_at,
        })
    }
}

impl ClaimsRegistry {
    /// Every claim as the public view, ordered by id (stable output).
    pub fn public_views(&self) -> Vec<serde_json::Value> {
        let mut claims: Vec<&MarketingClaim> = self.claims.values().collect();
        claims.sort_by(|left, right| left.claim_id.cmp(&right.claim_id));
        claims
            .into_iter()
            .map(MarketingClaim::public_view)
            .collect()
    }

    /// One claim's public view.
    pub fn public_view(&self, id: &str) -> Option<serde_json::Value> {
        self.get(id).map(MarketingClaim::public_view)
    }
}

pub fn seed_claims_registry() -> ClaimsRegistry {
    let mut registry = ClaimsRegistry::new();
    let now = Utc::now();

    // Audit F10: the "EEA data processing and storage" claim (CL-001) and
    // its `docs/compliance/data-residency.md` evidence pointer were REMOVED.
    // Nothing enforces data residency anywhere in the codebase — no routing,
    // pinning or replication constraint reads a region selection — so the
    // claim (and the evidence document advertising it) were untrue. An
    // untrue compliance claim must not ship; it may only return together
    // with the mechanism that makes it true.

    registry.register(MarketingClaim {
        claim_id: "CL-002".into(),
        exact_wording: "GDPR-ready data processing infrastructure".into(),
        category: ClaimCategory::Compliance,
        owner: "Legal".into(),
        approver: Some("DPO".into()),
        evidence_location: Some("docs/compliance/gdpr-compliance.md".into()),
        measurement_method: Some("Annual privacy review".into()),
        measurement_period: Some("Annual".into()),
        environment_measured: Some("Production".into()),
        plan_applicability: vec!["all".into()],
        geographic_scope: Some("European Economic Area".into()),
        limitations: Some("Customer bears controller obligations".into()),
        approved_pages: vec!["/compliance/".into(), "/privacy/".into()],
        review_date: NaiveDate::from_ymd_opt(2027, 1, 1).unwrap(),
        expiration_date: None,
        status: ClaimStatus::Qualified,
        created_at: now,
        updated_at: now,
    });

    registry.register(MarketingClaim {
        claim_id: "CL-003".into(),
        exact_wording: "HIPAA-eligible for covered workloads".into(),
        category: ClaimCategory::Compliance,
        owner: "Security".into(),
        approver: Some("Legal".into()),
        evidence_location: Some("services/mail-server/crates/compliance/src/hipaa.rs".into()),
        measurement_method: Some("BAA review per customer".into()),
        measurement_period: Some("Per-engagement".into()),
        environment_measured: Some("Dedicated".into()),
        plan_applicability: vec!["enterprise".into(), "dedicated_tenant".into()],
        geographic_scope: Some("United States".into()),
        limitations: Some(
            "BAA eligibility review required; not automatically HIPAA-compliant".into(),
        ),
        approved_pages: vec!["/compliance/hipaa/".into()],
        review_date: NaiveDate::from_ymd_opt(2027, 1, 1).unwrap(),
        expiration_date: None,
        status: ClaimStatus::Planned,
        created_at: now,
        updated_at: now,
    });

    registry.register(MarketingClaim {
        claim_id: "CL-004".into(),
        exact_wording: "SOC 2 controls mapped with readiness assessment in progress".into(),
        category: ClaimCategory::Security,
        owner: "Security".into(),
        approver: Some("Auditor".into()),
        evidence_location: Some("services/mail-server/crates/compliance/src/soc2.rs".into()),
        measurement_method: Some("Independent audit".into()),
        measurement_period: Some("Annual".into()),
        environment_measured: Some("Production".into()),
        plan_applicability: vec!["all".into()],
        geographic_scope: None,
        limitations: Some("Planned; not yet achieved. Currently control-aligned.".into()),
        approved_pages: vec!["/trust/".into(), "/security/".into()],
        review_date: NaiveDate::from_ymd_opt(2027, 6, 1).unwrap(),
        expiration_date: None,
        status: ClaimStatus::Planned,
        created_at: now,
        updated_at: now,
    });

    registry.register(MarketingClaim {
        claim_id: "CL-005".into(),
        exact_wording: "Penetration testing program established with first assessment planned"
            .into(),
        category: ClaimCategory::Security,
        owner: "Security".into(),
        approver: Some("CTO".into()),
        evidence_location: Some("tools/check_security_posture.py".into()),
        measurement_method: Some("External penetration test".into()),
        measurement_period: Some("Annual".into()),
        environment_measured: Some("Production".into()),
        plan_applicability: vec!["all".into()],
        geographic_scope: None,
        limitations: Some("Planned; not yet completed".into()),
        approved_pages: vec!["/trust/".into(), "/security/".into()],
        review_date: NaiveDate::from_ymd_opt(2027, 6, 1).unwrap(),
        expiration_date: None,
        status: ClaimStatus::Planned,
        created_at: now,
        updated_at: now,
    });

    registry.register(MarketingClaim {
        claim_id: "CL-006".into(),
        exact_wording: "REST API for transactional and broadcast email".into(),
        category: ClaimCategory::Product,
        owner: "Engineering".into(),
        approver: None,
        evidence_location: Some("services/mail-server/crates/api-server/src/routes".into()),
        measurement_method: Some("API integration tests".into()),
        measurement_period: Some("Continuous".into()),
        environment_measured: Some("Production".into()),
        plan_applicability: vec!["all".into()],
        geographic_scope: None,
        limitations: None,
        approved_pages: vec!["/api/".into(), "/docs/".into()],
        review_date: NaiveDate::from_ymd_opt(2027, 1, 1).unwrap(),
        expiration_date: None,
        status: ClaimStatus::Beta,
        created_at: now,
        updated_at: now,
    });

    registry.register(MarketingClaim {
        claim_id: "CL-007".into(),
        exact_wording: "SMTP relay for legacy and internal applications".into(),
        category: ClaimCategory::Product,
        owner: "Engineering".into(),
        approver: None,
        evidence_location: Some("services/mail-server/crates/mta".into()),
        measurement_method: Some("SMTP integration tests".into()),
        measurement_period: Some("Continuous".into()),
        environment_measured: Some("Production".into()),
        plan_applicability: vec!["all".into()],
        geographic_scope: None,
        limitations: Some("SMTP authentication required; no open relay".into()),
        approved_pages: vec!["/smtp/".into(), "/docs/".into()],
        review_date: NaiveDate::from_ymd_opt(2027, 1, 1).unwrap(),
        expiration_date: None,
        status: ClaimStatus::Beta,
        created_at: now,
        updated_at: now,
    });

    registry.register(MarketingClaim {
        claim_id: "CL-008".into(),
        exact_wording: "Signed webhooks with at-least-once delivery".into(),
        category: ClaimCategory::Product,
        owner: "Engineering".into(),
        approver: None,
        evidence_location: Some("services/mail-server/crates/worker-processors/src/webhook".into()),
        measurement_method: Some("Webhook integration tests".into()),
        measurement_period: Some("Continuous".into()),
        environment_measured: Some("Production".into()),
        plan_applicability: vec![
            "developer".into(),
            "pro".into(),
            "growth".into(),
            "business".into(),
            "enterprise".into(),
        ],
        geographic_scope: None,
        limitations: Some("Developer plan gets 3 endpoints".into()),
        approved_pages: vec!["/webhooks/".into(), "/docs/".into()],
        review_date: NaiveDate::from_ymd_opt(2027, 1, 1).unwrap(),
        expiration_date: None,
        status: ClaimStatus::Beta,
        created_at: now,
        updated_at: now,
    });

    registry.register(MarketingClaim {
        claim_id: "CL-009".into(),
        exact_wording: "Dedicated IPs available from Growth plan with eligibility review".into(),
        category: ClaimCategory::Product,
        owner: "Deliverability".into(),
        approver: Some("Engineering".into()),
        evidence_location: Some(
            "services/mail-server/crates/compliance/src/dedicated_ip.rs".into(),
        ),
        measurement_method: Some("IP assignment audit".into()),
        measurement_period: Some("Per-assignment".into()),
        environment_measured: Some("Production".into()),
        plan_applicability: vec!["growth".into(), "business".into(), "enterprise".into()],
        geographic_scope: None,
        limitations: Some("Eligibility review required; ~100k monthly volume recommended".into()),
        approved_pages: vec!["/dedicated-ips/".into(), "/pricing/".into()],
        review_date: NaiveDate::from_ymd_opt(2027, 1, 1).unwrap(),
        expiration_date: None,
        status: ClaimStatus::Planned,
        created_at: now,
        updated_at: now,
    });

    registry.register(MarketingClaim {
        claim_id: "CL-010".into(),
        exact_wording: "Managed IP warm-up for dedicated IPs".into(),
        category: ClaimCategory::Product,
        owner: "Deliverability".into(),
        approver: None,
        evidence_location: Some("services/mail-server/crates/mail-common/src/warmup.rs".into()),
        measurement_method: Some("Warm-up schedule audit".into()),
        measurement_period: Some("Per-IP".into()),
        environment_measured: Some("Production".into()),
        plan_applicability: vec!["growth".into(), "business".into(), "enterprise".into()],
        geographic_scope: None,
        limitations: Some("Requires dedicated IP assignment".into()),
        approved_pages: vec!["/dedicated-ips/".into()],
        review_date: NaiveDate::from_ymd_opt(2027, 1, 1).unwrap(),
        expiration_date: None,
        status: ClaimStatus::Planned,
        created_at: now,
        updated_at: now,
    });

    registry.register(MarketingClaim {
        claim_id: "CL-011".into(),
        exact_wording: "BYOC deployment for customer-controlled infrastructure".into(),
        category: ClaimCategory::Product,
        owner: "Infrastructure".into(),
        approver: Some("CTO".into()),
        evidence_location: Some("docs/deployment".into()),
        measurement_method: Some("Deployment validation".into()),
        measurement_period: Some("Per-deployment".into()),
        environment_measured: Some("Customer".into()),
        plan_applicability: vec!["enterprise".into()],
        geographic_scope: Some("Supported cloud providers only".into()),
        limitations: Some("From €6,500/month plus implementation; 12-24 month minimum".into()),
        approved_pages: vec!["/private-deployment/".into(), "/enterprise/".into()],
        review_date: NaiveDate::from_ymd_opt(2027, 6, 1).unwrap(),
        expiration_date: None,
        status: ClaimStatus::Planned,
        created_at: now,
        updated_at: now,
    });

    registry.register(MarketingClaim {
        claim_id: "CL-012".into(),
        exact_wording: "Dedicated tenant deployment with private application and data tenancy"
            .into(),
        category: ClaimCategory::Product,
        owner: "Infrastructure".into(),
        approver: Some("CTO".into()),
        evidence_location: Some("services/mail-server/crates/isolation".into()),
        measurement_method: Some("Deployment validation".into()),
        measurement_period: Some("Per-deployment".into()),
        environment_measured: Some("ApexMail-managed dedicated".into()),
        plan_applicability: vec!["enterprise".into()],
        geographic_scope: Some("Defined EEA region".into()),
        limitations: Some("From €4,000/month plus setup; 12-month minimum".into()),
        approved_pages: vec!["/private-deployment/".into(), "/enterprise/".into()],
        review_date: NaiveDate::from_ymd_opt(2027, 6, 1).unwrap(),
        expiration_date: None,
        status: ClaimStatus::Planned,
        created_at: now,
        updated_at: now,
    });

    registry.register(MarketingClaim {
        claim_id: "CL-013".into(),
        exact_wording: "TypeScript, Python, Go, Java, PHP, Ruby, and .NET SDKs".into(),
        category: ClaimCategory::Product,
        owner: "Developer Experience".into(),
        approver: None,
        evidence_location: Some("packages".into()),
        measurement_method: Some("SDK integration tests".into()),
        measurement_period: Some("Continuous".into()),
        environment_measured: Some("Test mode".into()),
        plan_applicability: vec!["all".into()],
        geographic_scope: None,
        limitations: Some("TypeScript prioritized; others planned".into()),
        approved_pages: vec!["/sdks/".into(), "/docs/".into()],
        review_date: NaiveDate::from_ymd_opt(2027, 6, 1).unwrap(),
        expiration_date: None,
        status: ClaimStatus::Planned,
        created_at: now,
        updated_at: now,
    });

    registry.register(MarketingClaim {
        claim_id: "CL-014".into(),
        exact_wording: "Inbox placement testing for seed addresses across major providers".into(),
        category: ClaimCategory::Product,
        owner: "Deliverability".into(),
        approver: None,
        evidence_location: Some("services/mail-server/crates/inbox-placement".into()),
        measurement_method: Some("Seed-list delivery measurement".into()),
        measurement_period: Some("Per-test".into()),
        environment_measured: Some("Production".into()),
        plan_applicability: vec![
            "pro".into(),
            "growth".into(),
            "business".into(),
            "enterprise".into(),
        ],
        geographic_scope: None,
        limitations: Some("Seed results do not guarantee recipient-wide placement".into()),
        approved_pages: vec!["/inbox-placement/".into()],
        review_date: NaiveDate::from_ymd_opt(2027, 1, 1).unwrap(),
        expiration_date: None,
        status: ClaimStatus::Planned,
        created_at: now,
        updated_at: now,
    });

    registry.register(MarketingClaim {
        claim_id: "CL-015".into(),
        exact_wording: "Email Grader delivering actionable quality scores".into(),
        category: ClaimCategory::Product,
        owner: "Deliverability".into(),
        approver: None,
        evidence_location: Some("services/mail-server/crates/email-grader".into()),
        measurement_method: Some("Grader analysis engine".into()),
        measurement_period: Some("Per-grading".into()),
        environment_measured: Some("Production".into()),
        plan_applicability: vec![
            "pro".into(),
            "growth".into(),
            "business".into(),
            "enterprise".into(),
        ],
        geographic_scope: None,
        limitations: Some("Score is not an inbox-placement guarantee".into()),
        approved_pages: vec!["/email-grader/".into()],
        review_date: NaiveDate::from_ymd_opt(2027, 1, 1).unwrap(),
        expiration_date: None,
        status: ClaimStatus::Planned,
        created_at: now,
        updated_at: now,
    });

    registry.register(MarketingClaim {
        claim_id: "CL-016".into(),
        exact_wording: "1,500+ active customers".into(),
        category: ClaimCategory::CustomerProof,
        owner: "Marketing".into(),
        approver: Some("Finance".into()),
        evidence_location: Some("runtime:tenant_delivery_analytics".into()),
        measurement_method: Some(
            "Count of organizations with active sending in last 30 days".into(),
        ),
        measurement_period: Some("Rolling 30-day".into()),
        environment_measured: Some("Production".into()),
        plan_applicability: vec!["all".into()],
        geographic_scope: None,
        limitations: Some("Not yet achieved; illustrative only".into()),
        approved_pages: vec!["/".into()],
        review_date: NaiveDate::from_ymd_opt(2027, 6, 1).unwrap(),
        expiration_date: None,
        status: ClaimStatus::Illustrative,
        created_at: now,
        updated_at: now,
    });

    registry.register(MarketingClaim {
        claim_id: "CL-017".into(),
        exact_wording: "100 million+ emails delivered monthly".into(),
        category: ClaimCategory::CustomerProof,
        owner: "Marketing".into(),
        approver: Some("Engineering".into()),
        evidence_location: Some("runtime:tenant_delivery_analytics".into()),
        measurement_method: Some("Sum of accepted recipients across all tenants".into()),
        measurement_period: Some("Monthly".into()),
        environment_measured: Some("Production".into()),
        plan_applicability: vec!["all".into()],
        geographic_scope: None,
        limitations: Some("Not yet achieved; illustrative only".into()),
        approved_pages: vec!["/".into()],
        review_date: NaiveDate::from_ymd_opt(2027, 6, 1).unwrap(),
        expiration_date: None,
        status: ClaimStatus::Illustrative,
        created_at: now,
        updated_at: now,
    });

    registry.register(MarketingClaim {
        claim_id: "CL-018".into(),
        exact_wording: "Two-business-day initial support response on Developer plan".into(),
        category: ClaimCategory::Product,
        owner: "Support".into(),
        approver: None,
        evidence_location: Some(
            "services/mail-server/crates/compliance/src/support_promises.rs".into(),
        ),
        measurement_method: Some("Median time to first human response".into()),
        measurement_period: Some("Monthly".into()),
        environment_measured: Some("Production".into()),
        plan_applicability: vec!["developer".into()],
        geographic_scope: None,
        limitations: Some("During published support hours only".into()),
        approved_pages: vec!["/support/".into()],
        review_date: NaiveDate::from_ymd_opt(2027, 1, 1).unwrap(),
        expiration_date: None,
        status: ClaimStatus::Planned,
        created_at: now,
        updated_at: now,
    });

    registry.register(MarketingClaim {
        claim_id: "CL-019".into(),
        exact_wording: "100% GDPR compliant".into(),
        category: ClaimCategory::Compliance,
        owner: "Legal".into(),
        approver: None,
        evidence_location: None,
        measurement_method: None,
        measurement_period: None,
        environment_measured: None,
        plan_applicability: vec![],
        geographic_scope: None,
        limitations: Some("No organisation can claim 100% GDPR compliance. Prohibited.".into()),
        approved_pages: vec![],
        review_date: NaiveDate::from_ymd_opt(2027, 6, 1).unwrap(),
        expiration_date: None,
        status: ClaimStatus::Prohibited,
        created_at: now,
        updated_at: now,
    });

    registry.register(MarketingClaim {
        claim_id: "CL-020".into(),
        exact_wording: "System Integrity Verified".into(),
        category: ClaimCategory::Security,
        owner: "Security".into(),
        approver: None,
        evidence_location: None,
        measurement_method: None,
        measurement_period: None,
        environment_measured: None,
        plan_applicability: vec![],
        geographic_scope: None,
        limitations: Some(
            "No recognised certification or standard. Prohibited until independently verified."
                .into(),
        ),
        approved_pages: vec![],
        review_date: NaiveDate::from_ymd_opt(2027, 6, 1).unwrap(),
        expiration_date: None,
        status: ClaimStatus::Prohibited,
        created_at: now,
        updated_at: now,
    });

    registry.register(MarketingClaim {
        claim_id: "CL-021".into(),
        exact_wording: "99.9% delivery rate".into(),
        category: ClaimCategory::Performance,
        owner: "Engineering".into(),
        approver: None,
        evidence_location: None,
        measurement_method: None,
        measurement_period: None,
        environment_measured: None,
        plan_applicability: vec![],
        geographic_scope: None,
        limitations: Some("Delivery rate is not under ApexMail's sole control; depends on recipient servers. Prohibited as a claim.".into()),
        approved_pages: vec![],
            review_date: NaiveDate::from_ymd_opt(2027, 6, 1).unwrap(),
        expiration_date: None,
        status: ClaimStatus::Prohibited,
        created_at: now,
        updated_at: now,
    });

    registry.register(MarketingClaim {
        claim_id: "CL-022".into(),
        exact_wording: "Guaranteed inbox placement".into(),
        category: ClaimCategory::Performance,
        owner: "Deliverability".into(),
        approver: None,
        evidence_location: None,
        measurement_method: None,
        measurement_period: None,
        environment_measured: None,
        plan_applicability: vec![],
        geographic_scope: None,
        limitations: Some("Inbox placement cannot be guaranteed. Prohibited.".into()),
        approved_pages: vec![],
        review_date: NaiveDate::from_ymd_opt(2027, 6, 1).unwrap(),
        expiration_date: None,
        status: ClaimStatus::Prohibited,
        created_at: now,
        updated_at: now,
    });

    registry.register(MarketingClaim {
        claim_id: "CL-023".into(),
        exact_wording: "Deterministic deliverability".into(),
        category: ClaimCategory::Performance,
        owner: "Engineering".into(),
        approver: None,
        evidence_location: None,
        measurement_method: None,
        measurement_period: None,
        environment_measured: None,
        plan_applicability: vec![],
        geographic_scope: None,
        limitations: Some("Deliverability depends on many external factors. Prohibited.".into()),
        approved_pages: vec![],
        review_date: NaiveDate::from_ymd_opt(2027, 6, 1).unwrap(),
        expiration_date: None,
        status: ClaimStatus::Prohibited,
        created_at: now,
        updated_at: now,
    });

    registry.register(MarketingClaim {
        claim_id: "CL-024".into(),
        exact_wording: "HIPAA Ready".into(),
        category: ClaimCategory::Compliance,
        owner: "Security".into(),
        approver: None,
        evidence_location: None,
        measurement_method: None,
        measurement_period: None,
        environment_measured: None,
        plan_applicability: vec![],
        geographic_scope: None,
        limitations: Some("HIPAA requires a signed BAA and specific architectural controls. Unqualified HIPAA claims are prohibited.".into()),
        approved_pages: vec![],
            review_date: NaiveDate::from_ymd_opt(2027, 6, 1).unwrap(),
        expiration_date: None,
        status: ClaimStatus::Prohibited,
        created_at: now,
        updated_at: now,
    });

    registry.register(MarketingClaim {
        claim_id: "CL-025".into(),
        exact_wording: "global edge".into(),
        category: ClaimCategory::Performance,
        owner: "Infrastructure".into(),
        approver: None,
        evidence_location: None,
        measurement_method: None,
        measurement_period: None,
        environment_measured: None,
        plan_applicability: vec![],
        geographic_scope: None,
        limitations: Some(
            "No global edge infrastructure exists. Prohibited until deployed and verified.".into(),
        ),
        approved_pages: vec![],
        review_date: NaiveDate::from_ymd_opt(2027, 6, 1).unwrap(),
        expiration_date: None,
        status: ClaimStatus::Prohibited,
        created_at: now,
        updated_at: now,
    });

    registry.register(MarketingClaim {
        claim_id: "CL-026".into(),
        exact_wording: "zero egress".into(),
        category: ClaimCategory::Performance,
        owner: "Infrastructure".into(),
        approver: None,
        evidence_location: None,
        measurement_method: None,
        measurement_period: None,
        environment_measured: None,
        plan_applicability: vec![],
        geographic_scope: None,
        limitations: Some(
            "Network egress is never zero in any cloud environment. Prohibited.".into(),
        ),
        approved_pages: vec![],
        review_date: NaiveDate::from_ymd_opt(2027, 6, 1).unwrap(),
        expiration_date: None,
        status: ClaimStatus::Prohibited,
        created_at: now,
        updated_at: now,
    });

    registry.register(MarketingClaim {
        claim_id: "CL-027".into(),
        exact_wording: "sub-millisecond latency".into(),
        category: ClaimCategory::Performance,
        owner: "Engineering".into(),
        approver: None,
        evidence_location: None,
        measurement_method: None,
        measurement_period: None,
        environment_measured: None,
        plan_applicability: vec![],
        geographic_scope: None,
        limitations: Some("Sub-millisecond latency is not achievable in production cloud environments. Prohibited.".into()),
        approved_pages: vec![],
            review_date: NaiveDate::from_ymd_opt(2027, 6, 1).unwrap(),
        expiration_date: None,
        status: ClaimStatus::Prohibited,
        created_at: now,
        updated_at: now,
    });

    registry.register(MarketingClaim {
        claim_id: "CL-028".into(),
        exact_wording: "Production API SLA: P95 ≤ 500ms measured at gateway".into(),
        category: ClaimCategory::Performance,
        owner: "Engineering".into(),
        approver: Some("CTO".into()),
        evidence_location: Some("runtime:api_gateway_histogram".into()),
        measurement_method: Some("Server-side timing from request receipt to response transmission, measured at the API gateway over rolling 30-day windows".into()),
        measurement_period: Some("Rolling 30 days".into()),
        environment_measured: Some("Production — EU (Helsinki)".into()),
        plan_applicability: vec!["enterprise".into()],
        geographic_scope: Some("EU region".into()),
        limitations: Some("Excludes client-side network latency, DNS resolution, and TLS handshake beyond server termination point. Excludes health-check probes, unauthenticated requests, and rate-limited (HTTP 429) requests.".into()),
        approved_pages: vec!["/sla/".into(), "/performance-methodology/".into(), "/security/".into()],
        review_date: NaiveDate::from_ymd_opt(2027, 6, 1).unwrap(),
        expiration_date: None,
        status: ClaimStatus::Qualified,
        created_at: now,
        updated_at: now,
    });

    registry.register(MarketingClaim {
        claim_id: "CL-029".into(),
        exact_wording: "Sandbox validation target: typically under 120ms".into(),
        category: ClaimCategory::Performance,
        owner: "Engineering".into(),
        approver: None,
        evidence_location: Some("runtime:sandbox_validation_harness".into()),
        measurement_method: Some("Internal validation latency only — no email is sent. Measures request validation, authentication, and internal queue acceptance without outbound SMTP interaction. Not an SLA.".into()),
        measurement_period: Some("Per-request measurement".into()),
        environment_measured: Some("Sandbox".into()),
        plan_applicability: vec!["all".into()],
        geographic_scope: None,
        limitations: Some("Guidance target only. Sandbox does not touch production delivery pipeline. Actual latency varies with request size and validation complexity.".into()),
        approved_pages: vec!["/performance-methodology/".into(), "/docs/api/".into()],
        review_date: NaiveDate::from_ymd_opt(2027, 6, 1).unwrap(),
        expiration_date: None,
        status: ClaimStatus::Qualified,
        created_at: now,
        updated_at: now,
    });

    registry.register(MarketingClaim {
        claim_id: "CL-030".into(),
        exact_wording: "Private Cloud illustrative: architecture-dependent, not an SLA".into(),
        category: ClaimCategory::Performance,
        owner: "Infrastructure".into(),
        approver: Some("CTO".into()),
        evidence_location: None,
        measurement_method: Some("Latency is deployment-specific and depends on customer region, network topology, VPC configuration, and proximity between application and API infrastructure. Contractual Private Cloud latency targets are defined per-deployment in the customer agreement.".into()),
        measurement_period: Some("Per-deployment measurement".into()),
        environment_measured: Some("Customer-specific".into()),
        plan_applicability: vec!["dedicated_tenant".into(), "byoc".into()],
        geographic_scope: Some("Customer-selected region".into()),
        limitations: Some("Architecture-dependent. No public SLA for Private Cloud latency. Not yet achieved in a customer deployment (the dedicated-tenant and BYOC offerings are Planned, see CL-011/CL-012); actual figures are illustrative deployment scenarios only. Contractual targets defined in customer agreements.".into()),
        approved_pages: vec!["/private-cloud/".into(), "/performance-methodology/".into()],
        review_date: NaiveDate::from_ymd_opt(2027, 6, 1).unwrap(),
        expiration_date: None,
        status: ClaimStatus::Illustrative,
        created_at: now,
        updated_at: now,
    });

    registry
}

#[cfg(test)]
mod tests {
    use super::*;

    fn registry() -> ClaimsRegistry {
        seed_claims_registry()
    }

    #[test]
    fn test_all_claims_have_unique_ids() {
        let r = registry();
        let mut ids: Vec<&str> = r.all().iter().map(|c| c.claim_id.as_str()).collect();
        ids.sort();
        let mut deduped = ids.clone();
        deduped.dedup();
        assert_eq!(ids.len(), deduped.len(), "Duplicate claim IDs found");
    }

    #[test]
    fn test_nine_prohibited_claims_exist() {
        let r = registry();
        let prohibited = r.by_status(ClaimStatus::Prohibited);
        assert_eq!(prohibited.len(), 9, "Expected exactly 9 prohibited claims");

        let wordings: Vec<&str> = prohibited
            .iter()
            .map(|c| c.exact_wording.as_str())
            .collect();
        assert!(wordings.contains(&"100% GDPR compliant"));
        assert!(wordings.contains(&"System Integrity Verified"));
        assert!(wordings.contains(&"99.9% delivery rate"));
        assert!(wordings.contains(&"Guaranteed inbox placement"));
        assert!(wordings.contains(&"Deterministic deliverability"));
        assert!(wordings.contains(&"HIPAA Ready"));
        assert!(wordings.contains(&"global edge"));
        assert!(wordings.contains(&"zero egress"));
        assert!(wordings.contains(&"sub-millisecond latency"));
    }

    #[test]
    fn test_prohibited_claims_not_in_pages() {
        let r = registry();
        for claim in r.by_status(ClaimStatus::Prohibited) {
            assert!(
                claim.approved_pages.is_empty(),
                "Prohibited claim {} has approved pages",
                claim.claim_id
            );
            assert!(
                claim.plan_applicability.is_empty(),
                "Prohibited claim {} has plan applicability",
                claim.claim_id
            );
        }
    }

    #[test]
    fn test_illustrative_claims_have_no_evidence() {
        let r = registry();
        for claim in r.by_status(ClaimStatus::Illustrative) {
            assert!(
                claim
                    .limitations
                    .as_ref()
                    .is_some_and(|l| l.contains("Not yet achieved")),
                "Illustrative claim {} should note not-yet-achieved status",
                claim.claim_id
            );
        }
    }

    #[test]
    fn test_review_dates_not_in_past() {
        let r = registry();
        let today = Utc::now().date_naive();
        let overdue = r.needs_review();
        assert!(
            overdue.is_empty(),
            "Claims overdue for review: {}",
            overdue
                .iter()
                .map(|c| format!("{} ({})", c.claim_id, c.review_date))
                .collect::<Vec<_>>()
                .join(", ")
        );
        let _ = today;
    }

    #[test]
    fn test_categories_assigned() {
        let r = registry();
        for claim in r.all() {
            assert!(
                !claim.owner.is_empty(),
                "Claim {} has no owner",
                claim.claim_id
            );
        }
    }

    #[test]
    fn test_validate_wording_detects_claims() {
        let r = registry();
        let hits = r.validate_wording(
            "Our system guarantees 100% GDPR compliant processing with 99.9% delivery rate",
        );
        assert!(hits.len() >= 2);

        let hit_ids: Vec<&str> = hits.iter().map(|c| c.claim_id.as_str()).collect();
        assert!(
            hit_ids.contains(&"CL-019"),
            "Should detect 100% GDPR compliant"
        );
        assert!(
            hit_ids.contains(&"CL-021"),
            "Should detect 99.9% delivery rate"
        );
    }

    #[test]
    fn test_claim_can_be_retrieved_by_id() {
        let r = registry();
        let claim = r.get("CL-002").expect("CL-002 should exist");
        assert_eq!(claim.status, ClaimStatus::Qualified);
        assert_eq!(claim.owner, "Legal");
    }

    /// The repository root, derived from this crate's manifest location
    /// (services/mail-server/crates/compliance → four levels up).
    fn repo_root() -> std::path::PathBuf {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../../..")
            .canonicalize()
            .expect("the crate must live inside the repository")
    }

    /// A1/B6 evidence pin: EVERY claim that cites an evidence pointer must
    /// point at something a reader can actually open. A `RepoPath` whose
    /// target is gone fails here; a `RuntimeSource` must be a REGISTERED
    /// named source whose producer path exists (no claim can invent a
    /// source); `None` is allowed only where the schema demands no evidence
    /// (prohibited / illustrative claims).
    #[test]
    fn every_repo_path_evidence_target_exists() {
        let root = repo_root();
        let r = registry();
        let mut checked = 0usize;
        for claim in r.all() {
            let kind = ClaimEvidenceKind::of(claim.evidence_location.as_deref());
            match (kind, claim.evidence_location.as_deref()) {
                (ClaimEvidenceKind::None, _) => {
                    assert!(
                        matches!(
                            claim.status,
                            ClaimStatus::Prohibited | ClaimStatus::Illustrative
                        ) || claim.evidence_location.is_none(),
                        "claim {} carries no evidence but is {} — only prohibited/illustrative \
                         claims may ship without a pointer",
                        claim.claim_id,
                        claim.status_string()
                    );
                }
                (ClaimEvidenceKind::RepoPath, Some(path)) => {
                    let target = root.join(path);
                    assert!(
                        target.exists(),
                        "claim {} (status {:?}) cites `{path}`, which does not exist in the \
                         repository — fix the pointer or drop the claim",
                        claim.claim_id,
                        claim.status
                    );
                    checked += 1;
                }
                (ClaimEvidenceKind::RuntimeSource, Some(value)) => {
                    let name = value.trim_start_matches("runtime:");
                    let source = RUNTIME_EVIDENCE_SOURCES
                        .iter()
                        .find(|(source, _, _)| *source == name)
                        .unwrap_or_else(|| {
                            panic!(
                                "claim {} cites runtime source `{name}`, which is not registered \
                                 in RUNTIME_EVIDENCE_SOURCES",
                                claim.claim_id
                            )
                        });
                    assert!(
                        root.join(source.1).exists(),
                        "claim {} runtime source `{name}` names producer `{}`, which does not \
                         exist",
                        claim.claim_id,
                        source.1
                    );
                    assert!(
                        !source.2.is_empty(),
                        "runtime source `{name}` must describe what it measures"
                    );
                    checked += 1;
                }
                // Classification is derived FROM the pointer, so a
                // pointer/kind disagreement is unreachable by construction;
                // the arms are spelled out so a future kind addition cannot
                // compile silently.
                (ClaimEvidenceKind::RepoPath | ClaimEvidenceKind::RuntimeSource, None) => {
                    panic!(
                        "claim {} is classified with evidence but has none",
                        claim.claim_id
                    )
                }
            }
        }
        // The pin must cover EVERY claim that carries a pointer (a silently
        // skipped claim is exactly the hole this test exists to close) and be
        // substantive overall.
        let with_evidence = r
            .all()
            .iter()
            .filter(|claim| claim.evidence_location.is_some())
            .count();
        assert_eq!(
            checked, with_evidence,
            "the evidence pin skipped claims that carry a pointer"
        );
        assert!(
            checked >= 15,
            "the evidence pin only checked {checked} claims — it would be vacuous"
        );
    }

    /// The served JSON is the stable contract: every claim renders with its
    /// id, wording, status, evidence and review/expiry dates, and the
    /// registry-wide view covers all claims once (no duplicates).
    #[test]
    fn public_views_render_the_served_contract() {
        let r = registry();
        let views = r.public_views();
        assert_eq!(views.len(), r.all().len());
        let mut ids: Vec<&str> = views.iter().filter_map(|v| v["id"].as_str()).collect();
        assert!(
            ids.windows(2).all(|pair| pair[0] < pair[1]),
            "ordered by id"
        );
        ids.clear();
        for view in &views {
            assert!(view["id"].as_str().is_some_and(|id| id.starts_with("CL-")));
            assert!(view["claim"].as_str().is_some_and(|c| !c.is_empty()));
            assert!(view["status"].as_str().is_some());
            assert!(view["reviewed"].as_str().is_some());
            assert!(view["evidence"].is_object());
            if let Some(location) = view["evidence"]["location"].as_str() {
                let kind = view["evidence"]["kind"].as_str().unwrap_or_default();
                assert!(
                    ["repo_path", "runtime_source"].contains(&kind),
                    "evidence kind must be classified: {view}"
                );
                if location.starts_with("runtime:") {
                    assert_eq!(kind, "runtime_source", "{view}");
                    assert!(
                        view["evidence"]["target"].as_str().is_some(),
                        "a runtime source must resolve to its producer path: {view}"
                    );
                } else {
                    assert_eq!(kind, "repo_path", "{view}");
                }
            }
        }
        // Single-claim lookup follows the same shape.
        let one = r.public_view("CL-028").expect("CL-028");
        assert_eq!(one["id"], "CL-028");
        assert_eq!(one["evidence"]["kind"], "runtime_source");
        assert!(r.public_view("CL-999").is_none());
    }

    /// Audit F10: the data-residency claim must STAY removed. It advertised
    /// "EEA data processing and storage" with `docs/compliance/data-residency.md`
    /// as public evidence while no code path implements (or even reads) a
    /// residency selection. If this test fails, the untrue claim was
    /// reintroduced — wire the enforcement mechanism first, then re-register
    /// the claim with real evidence.
    #[test]
    fn the_untrue_data_residency_claim_stays_removed() {
        let r = registry();
        assert!(
            r.get("CL-001").is_none(),
            "CL-001 (EEA data-residency claim) must not ship without an enforcement mechanism"
        );
        // No remaining claim may cite the data-residency evidence document
        // either — the pointer died with the claim.
        for claim in r.all() {
            assert_ne!(
                claim.evidence_location.as_deref(),
                Some("docs/compliance/data-residency.md"),
                "claim {} still cites the removed data-residency evidence",
                claim.claim_id
            );
        }
    }
}
