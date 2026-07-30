// compliance/src/customer_evidence.rs
// Customer evidence and claims registry for ApexMail marketing claims.
// All customer metrics must be verifiable with approval records.

/// Represents a customer evidence entry with full verification trail
#[derive(Debug, Clone)]
pub struct CustomerEvidenceEntry {
    pub claim_id: String,
    pub claim_type: ClaimType,
    pub customer_identity: CustomerIdentity,
    pub metric: MetricEvidence,
    pub approval: ApprovalRecord,
}

#[derive(Debug, Clone)]
pub enum ClaimType {
    PerformanceImprovement,
    CostReduction,
    DeliveryRate,
    TimeToValue,
    MigrationSuccess,
}

#[derive(Debug, Clone)]
pub enum CustomerIdentity {
    Named {
        company_name: String,
        industry: String,
        scale: String,
        logo_permission: bool,
        quote_permission: bool,
    },
    Anonymous {
        industry: String,
        approximate_scale: String,
        anonymity_reason: String,
    },
}

#[derive(Debug, Clone)]
pub struct MetricEvidence {
    pub metric_description: String,
    pub measurement_period: String,
    pub baseline: f64,
    pub result: f64,
    pub sample_size: u64,
    pub exclusions: Vec<String>,
    pub methodology: String,
    pub public_evidence: Option<String>,
    pub internal_evidence: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ApprovalRecord {
    pub reviewer: String,
    pub review_date: String,
    pub expiration_date: String,
    pub customer_approved_quote: bool,
    pub customer_approved_logo: bool,
    pub metric_verification_status: VerificationStatus,
}

#[derive(Debug, Clone, PartialEq)]
pub enum VerificationStatus {
    Verified,
    Pending,
    Expired,
    Disputed,
}

/// Claims registry entries as defined in the compliance claims system.
/// CL-016 and CL-017 track customer proof with full methodology.
pub struct ClaimsRegistry;

impl ClaimsRegistry {
    pub fn entry_cl_016() -> CustomerEvidenceEntry {
        CustomerEvidenceEntry {
            claim_id: "CL-016".into(),
            claim_type: ClaimType::PerformanceImprovement,
            customer_identity: CustomerIdentity::Anonymous {
                industry: "SaaS Platform".into(),
                approximate_scale: "5-10M monthly emails".into(),
                anonymity_reason: "Customer NDA prevents public naming".into(),
            },
            metric: MetricEvidence {
                metric_description: "Inbox placement rate improvement after migration from competitor".into(),
                measurement_period: "Q1 2026 (90 days)".into(),
                baseline: 94.5,
                result: 99.2,
                sample_size: 2_450_000,
                exclusions: vec!["Bounce events".into(), "Spam-trap hits".into()],
                methodology: "Independent inbox-placement testing via 3rd-party seed list (50 providers, 6 geos)".into(),
                public_evidence: Some("/case-studies/".into()),
                internal_evidence: Some("evidence/CL-016-placement-report-2026Q1.pdf".into()),
            },
            approval: ApprovalRecord {
                reviewer: "Compliance Team".into(),
                review_date: "2026-07-01".into(),
                expiration_date: "2027-01-01".into(),
                customer_approved_quote: true,
                customer_approved_logo: false,
                metric_verification_status: VerificationStatus::Verified,
            },
        }
    }

    pub fn entry_cl_017() -> CustomerEvidenceEntry {
        CustomerEvidenceEntry {
            claim_id: "CL-017".into(),
            claim_type: ClaimType::TimeToValue,
            customer_identity: CustomerIdentity::Anonymous {
                industry: "Fintech".into(),
                approximate_scale: "1-2M monthly emails".into(),
                anonymity_reason: "Regulatory sensitivity — customer requests anonymity".into(),
            },
            metric: MetricEvidence {
                metric_description: "Time from signup to first accepted send".into(),
                measurement_period: "2026".into(),
                baseline: 2880.0,
                result: 12.0,
                sample_size: 1,
                exclusions: vec![],
                methodology: "Tracked via analytics funnel events: signup_completed → first_send_accepted".into(),
                public_evidence: Some("/case-studies/".into()),
                internal_evidence: Some("evidence/CL-017-quickstart-timing-2026.pdf".into()),
            },
            approval: ApprovalRecord {
                reviewer: "Compliance Team".into(),
                review_date: "2026-07-01".into(),
                expiration_date: "2027-01-01".into(),
                customer_approved_quote: true,
                customer_approved_logo: false,
                metric_verification_status: VerificationStatus::Verified,
            },
        }
    }
}

/// No invented quotes or logos appear.
/// Every metric can be substantiated.
/// Approval records are retained.
/// Outdated case studies are reviewed on expiration.
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_no_invented_quotes() {
        let cl_016 = ClaimsRegistry::entry_cl_016();
        assert!(cl_016.approval.customer_approved_quote,
            "CL-016: quote must have customer approval");
        let cl_017 = ClaimsRegistry::entry_cl_017();
        assert!(cl_017.approval.customer_approved_quote,
            "CL-017: quote must have customer approval");
    }

    #[test]
    fn test_no_unapproved_logos() {
        let cl_016 = ClaimsRegistry::entry_cl_016();
        assert!(!cl_016.approval.customer_approved_logo,
            "CL-016: anonymous entry — logo not approved");
        let cl_017 = ClaimsRegistry::entry_cl_017();
        assert!(!cl_017.approval.customer_approved_logo,
            "CL-017: anonymous entry — logo not approved");
    }

    #[test]
    fn test_all_metrics_verifiable() {
        let cl_016 = ClaimsRegistry::entry_cl_016();
        assert_eq!(cl_016.approval.metric_verification_status, VerificationStatus::Verified);
        assert!(cl_016.metric.internal_evidence.is_some());
        let cl_017 = ClaimsRegistry::entry_cl_017();
        assert_eq!(cl_017.approval.metric_verification_status, VerificationStatus::Verified);
        assert!(cl_017.metric.internal_evidence.is_some());
    }

    #[test]
    fn test_anonymous_entries_follow_requirements() {
        // Anonymous entries must state anonymity, industry, scale, reason
        for entry in [ClaimsRegistry::entry_cl_016(), ClaimsRegistry::entry_cl_017()] {
            if let CustomerIdentity::Anonymous { industry, approximate_scale, anonymity_reason } = &entry.customer_identity {
                assert!(!industry.is_empty());
                assert!(!approximate_scale.is_empty());
                assert!(!anonymity_reason.is_empty());
            }
        }
    }
}
