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

pub fn seed_claims_registry() -> ClaimsRegistry {
    let mut registry = ClaimsRegistry::new();
    let now = Utc::now();

    registry.register(MarketingClaim {
        claim_id: "CL-001".into(),
        exact_wording: "EEA data processing and storage".into(),
        category: ClaimCategory::Compliance,
        owner: "Infrastructure".into(),
        approver: Some("Security".into()),
        evidence_location: Some("docs/compliance/data-residency.md".into()),
        measurement_method: Some("Infrastructure audit of all data stores".into()),
        measurement_period: Some("Continuous".into()),
        environment_measured: Some("Production".into()),
        plan_applicability: vec!["all".into()],
        geographic_scope: Some("European Economic Area".into()),
        limitations: Some("BYOC may use customer-specified regions".into()),
        approved_pages: vec!["/compliance/".into(), "/security/".into()],
        review_date: NaiveDate::from_ymd_opt(2027, 1, 1).unwrap(),
        expiration_date: None,
        status: ClaimStatus::Qualified,
        created_at: now,
        updated_at: now,
    });

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
        evidence_location: Some("docs/compliance/hipaa/".into()),
        measurement_method: Some("BAA review per customer".into()),
        measurement_period: Some("Per-engagement".into()),
        environment_measured: Some("Dedicated".into()),
        plan_applicability: vec!["enterprise".into(), "dedicated_tenant".into()],
        geographic_scope: Some("United States".into()),
        limitations: Some("BAA eligibility review required; not automatically HIPAA-compliant".into()),
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
        evidence_location: Some("trust/".into()),
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
        exact_wording: "Penetration testing program established with first assessment planned".into(),
        category: ClaimCategory::Security,
        owner: "Security".into(),
        approver: Some("CTO".into()),
        evidence_location: Some("trust/pentest-summary.pdf".into()),
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
        evidence_location: Some("api/".into()),
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
        evidence_location: Some("smtp/".into()),
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
        evidence_location: Some("webhooks/".into()),
        measurement_method: Some("Webhook integration tests".into()),
        measurement_period: Some("Continuous".into()),
        environment_measured: Some("Production".into()),
        plan_applicability: vec!["developer".into(), "pro".into(), "growth".into(), "business".into(), "enterprise".into()],
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
        evidence_location: Some("docs/dedicated-ips/".into()),
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
        evidence_location: Some("docs/warm-up/".into()),
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
        evidence_location: Some("docs/byoc/".into()),
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
        exact_wording: "Dedicated tenant deployment with private application and data tenancy".into(),
        category: ClaimCategory::Product,
        owner: "Infrastructure".into(),
        approver: Some("CTO".into()),
        evidence_location: Some("docs/dedicated-tenant/".into()),
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
        evidence_location: Some("sdks/".into()),
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
        evidence_location: Some("docs/inbox-placement/".into()),
        measurement_method: Some("Seed-list delivery measurement".into()),
        measurement_period: Some("Per-test".into()),
        environment_measured: Some("Production".into()),
        plan_applicability: vec!["pro".into(), "growth".into(), "business".into(), "enterprise".into()],
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
        evidence_location: Some("docs/email-grader/".into()),
        measurement_method: Some("Grader analysis engine".into()),
        measurement_period: Some("Per-grading".into()),
        environment_measured: Some("Production".into()),
        plan_applicability: vec!["pro".into(), "growth".into(), "business".into(), "enterprise".into()],
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
        evidence_location: Some("analytics/".into()),
        measurement_method: Some("Count of organizations with active sending in last 30 days".into()),
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
        evidence_location: Some("analytics/".into()),
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
        evidence_location: Some("support/sla-metrics/".into()),
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
        limitations: Some("No recognised certification or standard. Prohibited until independently verified.".into()),
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
        limitations: Some("No global edge infrastructure exists. Prohibited until deployed and verified.".into()),
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
        limitations: Some("Network egress is never zero in any cloud environment. Prohibited.".into()),
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
        evidence_location: Some("Prometheus API gateway histogram".into()),
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
        evidence_location: Some("Sandbox test harness metrics".into()),
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
        limitations: Some("Architecture-dependent. No public SLA for Private Cloud latency. Actual figures are illustrative deployment scenarios only. Contractual targets defined in customer agreements.".into()),
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

        let wordings: Vec<&str> = prohibited.iter().map(|c| c.exact_wording.as_str()).collect();
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
                claim.limitations.as_ref().map_or(false, |l| l.contains("Not yet achieved")),
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
            overdue.iter().map(|c| format!("{} ({})", c.claim_id, c.review_date)).collect::<Vec<_>>().join(", ")
        );
        let _ = today;
    }

    #[test]
    fn test_categories_assigned() {
        let r = registry();
        for claim in r.all() {
            assert!(!claim.owner.is_empty(), "Claim {} has no owner", claim.claim_id);
        }
    }

    #[test]
    fn test_validate_wording_detects_claims() {
        let r = registry();
        let hits = r.validate_wording("Our system guarantees 100% GDPR compliant processing with 99.9% delivery rate");
        assert!(hits.len() >= 2);

        let hit_ids: Vec<&str> = hits.iter().map(|c| c.claim_id.as_str()).collect();
        assert!(hit_ids.contains(&"CL-019"), "Should detect 100% GDPR compliant");
        assert!(hit_ids.contains(&"CL-021"), "Should detect 99.9% delivery rate");
    }

    #[test]
    fn test_claim_can_be_retrieved_by_id() {
        let r = registry();
        let claim = r.get("CL-001").expect("CL-001 should exist");
        assert_eq!(claim.status, ClaimStatus::Qualified);
        assert_eq!(claim.owner, "Infrastructure");
    }
}
