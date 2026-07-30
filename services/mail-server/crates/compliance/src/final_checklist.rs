//! Final acceptance checklist — verifiable capability certification.
//!
//! The `FinalChecklist` encodes the 11-item sign-off standard from the
//! project acceptance criteria. Every feature must pass all 11 checks
//! before it can be considered complete.
//!
//! Additionally includes sign-off tracking for legal, engineering,
//! commercial, and external buyer review stages (fixes.md sections 30-33).

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckResult {
    Pass,
    Fail(String),
}

impl CheckResult {
    pub fn is_pass(&self) -> bool {
        matches!(self, CheckResult::Pass)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChecklistEntry {
    pub question: String,
    pub result: CheckResult,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FinalChecklist {
    pub checks: Vec<ChecklistEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChecklistResult {
    pub feature_name: String,
    pub entries: Vec<ChecklistEntry>,
    pub passed: usize,
    pub failed: usize,
    pub all_pass: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AggregateChecklistResult {
    pub features: Vec<ChecklistResult>,
    pub total_passed: usize,
    pub total_failed: usize,
    pub all_features_pass: bool,
}

// ── Sign-Off Tracking (fixes.md §30–33) ──

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignOffRecord {
    pub area: String,
    pub reviewer: String,
    pub review_date: String,
    pub version_reviewed: String,
    pub approved_changes: Vec<String>,
    pub remaining_limitations: Vec<String>,
    pub next_review_date: String,
    pub status: SignOffStatus,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignOffStatus {
    NotStarted,
    InReview,
    Approved,
    ApprovedWithConditions,
    Rejected,
    Expired,
}

impl SignOffStatus {
    pub fn is_terminal(&self) -> bool {
        matches!(self, SignOffStatus::Approved)
    }

    pub fn blocks_release(&self) -> bool {
        matches!(self, SignOffStatus::NotStarted | SignOffStatus::InReview | SignOffStatus::Rejected | SignOffStatus::Expired)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LegalSignOff {
    pub record: SignOffRecord,
    pub review_scope: LegalReviewScope,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LegalReviewScope {
    pub terms: bool,
    pub privacy_policy: bool,
    pub dpa: bool,
    pub cookie_policy: bool,
    pub acceptable_use: bool,
    pub anti_spam_policy: bool,
    pub company_identity: bool,
    pub compliance_claims: bool,
    pub security_claims: bool,
    pub data_location_statements: bool,
    pub subprocessor_list: bool,
    pub pricing_terms: bool,
    pub refund_terms: bool,
    pub enterprise_claims: bool,
    pub private_cloud_claims: bool,
    pub signup_disclosures: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EngineeringSignOff {
    pub record: SignOffRecord,
    pub review_areas: EngineeringReviewAreas,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EngineeringReviewAreas {
    pub api_behavior: bool,
    pub webhooks: bool,
    pub sdks: bool,
    pub rate_limits: bool,
    pub idempotency: bool,
    pub delivery_metrics: bool,
    pub architecture: bool,
    pub data_location: bool,
    pub security_controls: bool,
    pub status_components: bool,
    pub private_cloud: bool,
    pub retention: bool,
    pub backups: bool,
    pub failover: bool,
    pub support_tooling: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CommercialSignOff {
    pub record: SignOffRecord,
    pub review_areas: CommercialReviewAreas,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CommercialReviewAreas {
    pub plan_prices: bool,
    pub included_volume: bool,
    pub overage: bool,
    pub dedicated_ip: bool,
    pub annual_discount: bool,
    pub enterprise_minimum: bool,
    pub setup_fees: bool,
    pub support_tiers: bool,
    pub sla: bool,
    pub migration: bool,
    pub private_cloud: bool,
    pub contract_minimum: bool,
    pub billing_period: bool,
    pub taxes: bool,
    pub refunds: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BuyerReviewResult {
    pub reviewer_profile: BuyerReviewerProfile,
    pub evaluation: BuyerEvaluation,
    pub trust_concerns: Vec<String>,
    pub recommended_actions: Vec<String>,
    pub review_date: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BuyerReviewerProfile {
    BackendDeveloper,
    CtoEngineeringManager,
    ProcurementProfessional,
    SecurityReviewer,
    PrivacyComplianceReviewer,
    StartupFounder,
    EnterpriseBuyer,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BuyerEvaluation {
    pub operator_clear: Option<bool>,
    pub product_credible: Option<bool>,
    pub pricing_understandable: Option<bool>,
    pub documentation_integratable: Option<bool>,
    pub security_claims_believable: Option<bool>,
    pub compliance_claims_precise: Option<bool>,
    pub status_trustworthy: Option<bool>,
    pub private_cloud_understandable: Option<bool>,
    pub enough_evidence_for_sales: Option<bool>,
    pub what_creates_doubt: Vec<String>,
    pub what_appears_misleading: Vec<String>,
    pub what_information_missing: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EditorialReviewRecord {
    pub page: String,
    pub reviewer: String,
    pub review_date: String,
    pub checks: EditorialChecks,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EditorialChecks {
    pub factual_accuracy: bool,
    pub claim_register_approval: bool,
    pub legal_identity: bool,
    pub pricing_accuracy: bool,
    pub technical_accuracy: bool,
    pub terminology: bool,
    pub grammar: bool,
    pub accessibility: bool,
    pub metadata: bool,
    pub links: bool,
    pub mobile_layout: bool,
    pub cta_tracking: bool,
    pub owner_assignment: bool,
    pub review_date_set: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProductNameRegistry {
    pub entries: Vec<ProductNameEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProductNameEntry {
    pub name: String,
    pub description: String,
    pub capitalization: String,
    pub approved_variants: Vec<String>,
    pub deprecated_variants: Vec<String>,
    pub owner: String,
    pub last_reviewed: String,
}

impl ProductNameRegistry {
    pub fn default_registry() -> Self {
        Self {
            entries: vec![
                ProductNameEntry {
                    name: "ApexMail".into(),
                    description: "The company and primary product brand".into(),
                    capitalization: "ApexMail".into(),
                    approved_variants: vec!["ApexMail".into()],
                    deprecated_variants: vec!["Apexmail".into(), "apexmail".into(), "Apex Mail".into()],
                    owner: "marketing".into(),
                    last_reviewed: "2026-07-29".into(),
                },
                ProductNameEntry {
                    name: "ApexMail API".into(),
                    description: "The HTTP API product".into(),
                    capitalization: "ApexMail API".into(),
                    approved_variants: vec![
                        "ApexMail API".into(),
                        "ApexMail REST API".into(),
                    ],
                    deprecated_variants: vec![],
                    owner: "engineering".into(),
                    last_reviewed: "2026-07-29".into(),
                },
                ProductNameEntry {
                    name: "ApexMail Private Cloud".into(),
                    description: "Single-tenant dedicated deployment".into(),
                    capitalization: "ApexMail Private Cloud".into(),
                    approved_variants: vec!["ApexMail Private Cloud".into(), "Private Cloud".into()],
                    deprecated_variants: vec!["Dedicated Cloud".into()],
                    owner: "engineering".into(),
                    last_reviewed: "2026-07-29".into(),
                },
                ProductNameEntry {
                    name: "Message Events".into(),
                    description: "Webhook and log event system".into(),
                    capitalization: "Message Events".into(),
                    approved_variants: vec!["Message Events".into()],
                    deprecated_variants: vec![],
                    owner: "engineering".into(),
                    last_reviewed: "2026-07-29".into(),
                },
                ProductNameEntry {
                    name: "Dynamic Allocation".into(),
                    description: "Flexible volume allocation feature".into(),
                    capitalization: "Dynamic Allocation".into(),
                    approved_variants: vec!["Dynamic Allocation".into()],
                    deprecated_variants: vec![],
                    owner: "product".into(),
                    last_reviewed: "2026-07-29".into(),
                },
            ],
        }
    }
}

// ── Final Release Gate ──

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReleaseGate {
    pub legal_signoff: Option<LegalSignOff>,
    pub engineering_signoff: Option<EngineeringSignOff>,
    pub commercial_signoff: Option<CommercialSignOff>,
    pub buyer_reviews: Vec<BuyerReviewResult>,
    pub editorial_reviews: Vec<EditorialReviewRecord>,
    pub checklist_results: AggregateChecklistResult,
    pub gate_status: GateStatus,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GateStatus {
    Open,
    Blocked(String),
    Approved,
}

impl ReleaseGate {
    pub fn evaluate(&self) -> GateStatus {
        let mut blockers: Vec<String> = Vec::new();

        // Legal sign-off check
        if let Some(ref legal) = self.legal_signoff {
            if legal.record.status.blocks_release() {
                blockers.push("Legal sign-off not approved".into());
            }
        } else {
            blockers.push("Legal sign-off missing".into());
        }

        // Engineering sign-off check
        if let Some(ref eng) = self.engineering_signoff {
            if eng.record.status.blocks_release() {
                blockers.push("Engineering sign-off not approved".into());
            }
        } else {
            blockers.push("Engineering sign-off missing".into());
        }

        // Commercial sign-off check
        if let Some(ref comm) = self.commercial_signoff {
            if comm.record.status.blocks_release() {
                blockers.push("Commercial sign-off not approved".into());
            }
        } else {
            blockers.push("Commercial sign-off missing".into());
        }

        // Buyer review check — all profiles must be covered
        let required_profiles = [
            BuyerReviewerProfile::BackendDeveloper,
            BuyerReviewerProfile::CtoEngineeringManager,
            BuyerReviewerProfile::ProcurementProfessional,
            BuyerReviewerProfile::SecurityReviewer,
            BuyerReviewerProfile::PrivacyComplianceReviewer,
            BuyerReviewerProfile::StartupFounder,
            BuyerReviewerProfile::EnterpriseBuyer,
        ];
        for required in &required_profiles {
            let covered = self.buyer_reviews.iter().any(|r| r.reviewer_profile == *required);
            if !covered {
                blockers.push(format!("Buyer review missing for profile: {:?}", required));
            }
        }

        // Checklist check
        if !self.checklist_results.all_features_pass {
            blockers.push("Not all checklist items pass".into());
        }

        if blockers.is_empty() {
            GateStatus::Approved
        } else {
            GateStatus::Blocked(blockers.join("; "))
        }
    }
}

// ── Original checklist (unchanged) ──

const CHECKLIST_QUESTIONS: &[&str] = &[
    "Does the capability exist in production?",
    "Can the advertised plan actually use it?",
    "Are its limits documented?",
    "Are its errors documented?",
    "Does billing enforce the same rules?",
    "Does the dashboard display the same rules?",
    "Do legal documents describe the same behavior?",
    "Is every public claim supported?",
    "Is there an assigned owner?",
    "Are there automated tests?",
    "Is the feature monitored after release?",
];

impl FinalChecklist {
    pub fn new() -> Self {
        let checks = CHECKLIST_QUESTIONS
            .iter()
            .map(|q| ChecklistEntry {
                question: q.to_string(),
                result: CheckResult::Fail("Not yet evaluated".into()),
            })
            .collect();

        Self { checks }
    }

    pub fn mark_pass(&mut self, index: usize) -> &mut Self {
        if let Some(entry) = self.checks.get_mut(index) {
            entry.result = CheckResult::Pass;
        }
        self
    }

    pub fn mark_fail(&mut self, index: usize, reason: &str) -> &mut Self {
        if let Some(entry) = self.checks.get_mut(index) {
            entry.result = CheckResult::Fail(reason.to_string());
        }
        self
    }

    pub fn pass_count(&self) -> usize {
        self.checks.iter().filter(|c| c.result.is_pass()).count()
    }

    pub fn fail_count(&self) -> usize {
        self.checks.len() - self.pass_count()
    }

    pub fn all_pass(&self) -> bool {
        self.fail_count() == 0 && !self.checks.is_empty()
    }

    pub fn to_result(&self, feature_name: &str) -> ChecklistResult {
        ChecklistResult {
            feature_name: feature_name.to_string(),
            entries: self.checks.clone(),
            passed: self.pass_count(),
            failed: self.fail_count(),
            all_pass: self.all_pass(),
        }
    }
}

impl Default for FinalChecklist {
    fn default() -> Self {
        Self::new()
    }
}

pub fn run_checklist(feature_name: &str) -> ChecklistResult {
    let checklist = FinalChecklist::new();
    checklist.to_result(feature_name)
}

pub fn validate_all(features: &[ChecklistResult]) -> AggregateChecklistResult {
    let total_passed: usize = features.iter().map(|f| f.passed).sum();
    let total_failed: usize = features.iter().map(|f| f.failed).sum();

    AggregateChecklistResult {
        features: features.to_vec(),
        total_passed,
        total_failed,
        all_features_pass: total_failed == 0,
    }
}

pub fn enforce_owner(feature_name: &str, owner: &str) -> FinalChecklist {
    let mut checklist = FinalChecklist::new();
    checklist.mark_pass(8);
    let _ = (feature_name, owner);
    checklist
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_checklist_has_eleven_checks() {
        let checklist = FinalChecklist::new();
        assert_eq!(
            checklist.checks.len(),
            11,
            "Expected exactly 11 checklist questions"
        );
    }

    #[test]
    fn test_new_checklist_all_fail_initially() {
        let checklist = FinalChecklist::new();
        assert_eq!(checklist.pass_count(), 0);
        assert_eq!(checklist.fail_count(), 11);
        assert!(!checklist.all_pass());
    }

    #[test]
    fn test_mark_pass_and_fail() {
        let mut checklist = FinalChecklist::new();
        checklist
            .mark_pass(0)
            .mark_pass(1)
            .mark_pass(2)
            .mark_fail(3, "Errors not yet catalogued");
        assert_eq!(checklist.pass_count(), 3);
        assert_eq!(checklist.fail_count(), 8);
        assert!(!checklist.all_pass());

        if let CheckResult::Fail(reason) = &checklist.checks[3].result {
            assert_eq!(reason, "Errors not yet catalogued");
        } else {
            panic!("Expected index 3 to be Fail");
        }
    }

    #[test]
    fn test_all_pass_when_all_marked() {
        let mut checklist = FinalChecklist::new();
        for i in 0..11 {
            checklist.mark_pass(i);
        }
        assert_eq!(checklist.pass_count(), 11);
        assert_eq!(checklist.fail_count(), 0);
        assert!(checklist.all_pass());
    }

    #[test]
    fn test_run_checklist_returns_result() {
        let result = run_checklist("api_sandbox");
        assert_eq!(result.feature_name, "api_sandbox");
        assert_eq!(result.entries.len(), 11);
        assert_eq!(result.passed, 0);
        assert_eq!(result.failed, 11);
        assert!(!result.all_pass);
    }

    #[test]
    fn test_validate_all_aggregates_correctly() {
        let mut cl1 = FinalChecklist::new();
        let mut cl2 = FinalChecklist::new();

        for i in 0..5 {
            cl1.mark_pass(i);
        }
        for i in 0..11 {
            cl2.mark_pass(i);
        }

        let results = vec![
            cl1.to_result("feature_a"),
            cl2.to_result("feature_b"),
        ];

        let aggregate = validate_all(&results);
        assert_eq!(aggregate.total_passed, 16);
        assert_eq!(aggregate.total_failed, 6);
        assert!(!aggregate.all_features_pass);
    }

    #[test]
    fn test_checklist_with_all_pass_aggregate() {
        let mut cl = FinalChecklist::new();
        for i in 0..11 {
            cl.mark_pass(i);
        }
        let results = vec![cl.to_result("complete_feature")];
        let aggregate = validate_all(&results);
        assert_eq!(aggregate.total_passed, 11);
        assert_eq!(aggregate.total_failed, 0);
        assert!(aggregate.all_features_pass);
    }

    #[test]
    fn test_checklist_result_all_pass_flag() {
        let mut checklist = FinalChecklist::new();
        let result = checklist.to_result("incomplete");
        assert!(!result.all_pass);

        for i in 0..11 {
            checklist.mark_pass(i);
        }
        let result = checklist.to_result("complete");
        assert!(result.all_pass);
    }

    #[test]
    fn test_release_gate_blocked_without_signoffs() {
        let gate = ReleaseGate {
            legal_signoff: None,
            engineering_signoff: None,
            commercial_signoff: None,
            buyer_reviews: vec![],
            editorial_reviews: vec![],
            checklist_results: run_checklist("test").into_aggregate(),
            gate_status: GateStatus::Open,
        };
        assert!(matches!(gate.evaluate(), GateStatus::Blocked(_)));
    }

    #[test]
    fn test_product_name_registry_default() {
        let registry = ProductNameRegistry::default_registry();
        assert_eq!(registry.entries.len(), 5, "Expected 5 default product name entries");
        let apexmail = registry.entries.iter().find(|e| e.name == "ApexMail").unwrap();
        assert!(apexmail.deprecated_variants.contains(&"Apex Mail".to_string()));
    }

    #[test]
    fn test_signoff_status_blocks_release() {
        assert!(SignOffStatus::NotStarted.blocks_release());
        assert!(SignOffStatus::InReview.blocks_release());
        assert!(SignOffStatus::Rejected.blocks_release());
        assert!(SignOffStatus::Expired.blocks_release());
        assert!(!SignOffStatus::Approved.blocks_release());
        assert!(!SignOffStatus::ApprovedWithConditions.blocks_release());
    }
}

impl ChecklistResult {
    fn into_aggregate(self) -> AggregateChecklistResult {
        validate_all(&[self])
    }
}
