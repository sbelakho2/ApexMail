use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProcurementDocument {
    CompanyProfile,
    ProductOverview,
    SecurityOverview,
    ComplianceOverview,
    DPA,
    SubprocessorList,
    SLATemplate,
    SupportPolicy,
    BusinessContinuitySummary,
    DisasterRecoverySummary,
    IncidentResponseSummary,
    DataRetentionPolicy,
    DataDeletionPolicy,
    ArchitectureOverview,
    InsuranceDetails,
    CertificationStatus,
    StandardVendorQuestionnaire,
    /// A DRAFT document: written, not approved, not offered to customers. It
    /// is listed so the package's pending work is visible and honest — never
    /// as an available artifact.
    UsDpaAddendum,
}

impl ProcurementDocument {
    pub fn doc_id(&self) -> &'static str {
        match self {
            Self::CompanyProfile => "PROC-001",
            Self::ProductOverview => "PROC-002",
            Self::SecurityOverview => "PROC-003",
            Self::ComplianceOverview => "PROC-004",
            Self::DPA => "PROC-005",
            Self::SubprocessorList => "PROC-006",
            Self::SLATemplate => "PROC-007",
            Self::SupportPolicy => "PROC-008",
            Self::BusinessContinuitySummary => "PROC-009",
            Self::DisasterRecoverySummary => "PROC-010",
            Self::IncidentResponseSummary => "PROC-011",
            Self::DataRetentionPolicy => "PROC-012",
            Self::DataDeletionPolicy => "PROC-013",
            Self::ArchitectureOverview => "PROC-014",
            Self::InsuranceDetails => "PROC-015",
            Self::CertificationStatus => "PROC-016",
            Self::StandardVendorQuestionnaire => "PROC-017",
            Self::UsDpaAddendum => "PROC-018",
        }
    }

    pub fn display_name(&self) -> &'static str {
        match self {
            Self::CompanyProfile => "Company Profile",
            Self::ProductOverview => "Product Overview",
            Self::SecurityOverview => "Security Overview",
            Self::ComplianceOverview => "Compliance Overview",
            Self::DPA => "Data Processing Agreement",
            Self::SubprocessorList => "Subprocessor List",
            Self::SLATemplate => "SLA Template",
            Self::SupportPolicy => "Support Policy",
            Self::BusinessContinuitySummary => "Business Continuity Summary",
            Self::DisasterRecoverySummary => "Disaster Recovery Summary",
            Self::IncidentResponseSummary => "Incident Response Summary",
            Self::DataRetentionPolicy => "Data Retention Policy",
            Self::DataDeletionPolicy => "Data Deletion Policy",
            Self::ArchitectureOverview => "Architecture Overview",
            Self::InsuranceDetails => "Insurance Details",
            Self::CertificationStatus => "Certification Status",
            Self::StandardVendorQuestionnaire => "Standard Vendor Questionnaire",
            Self::UsDpaAddendum => "US DPA Addendum (draft — awaiting owner approval)",
        }
    }

    pub fn description(&self) -> &'static str {
        match self {
            Self::CompanyProfile => "Legal entity information, registry details, founding date, and company overview.",
            Self::ProductOverview => "Product description, core features, deployment models, and integration methods.",
            Self::SecurityOverview => "Security controls, encryption, authentication, access controls, monitoring, and incident response.",
            Self::ComplianceOverview => "Framework status (GDPR, HIPAA, SOC 2, ISO), certifications, and compliance controls.",
            Self::DPA => "Data Processing Agreement with Article 28 GDPR terms, subprocessor provisions, and data transfer mechanisms.",
            Self::SubprocessorList => "Complete register of subprocessors with data categories, processing countries, and transfer mechanisms.",
            Self::SLATemplate => "Service Level Agreement with uptime targets, service credits, and support response commitments.",
            Self::SupportPolicy => "Support tiers, channels, response targets, escalation paths, and operational hours.",
            Self::BusinessContinuitySummary => "Business continuity planning, critical function identification, and recovery strategies.",
            Self::DisasterRecoverySummary => "Disaster recovery procedures, RPO and RTO targets, backup strategy, and testing schedule.",
            Self::IncidentResponseSummary => "Incident detection, classification, response procedures, notification commitments, and postmortem process.",
            Self::DataRetentionPolicy => "Data retention periods by category, legal hold procedures, and archival policies.",
            Self::DataDeletionPolicy => "Data deletion procedures, backup expiry, account termination process, and verification.",
            Self::ArchitectureOverview => "System architecture, deployment diagrams, data flow, network design, and component inventory.",
            Self::InsuranceDetails => "Insurance coverage types, policy limits, and insurer information where applicable.",
            Self::CertificationStatus => "Current certification and attestation status with scope, auditor, and validity dates.",
            Self::StandardVendorQuestionnaire => "Pre-completed SIG/CAIQ/HECVAT questionnaire with current response data.",
            Self::UsDpaAddendum => {
                "DRAFT addendum to the Data Processing Agreement for US customers \
                 (templates/legal/us-dpa-addendum.md): CCPA/CPRA service-provider terms, US state \
                 privacy law consumer-rights assistance, the GDPR transfer and residency clauses \
                 for EU data a US customer sends, breach notification, deletion and return, audit, \
                 and the state-law order of precedence. Not effective and not offered to customers \
                 until the owner approves it; no approved_by/approved_at record exists."
            }
        }
    }

    pub fn visibility(&self) -> DocumentVisibility {
        match self {
            Self::CompanyProfile => DocumentVisibility::Public,
            Self::ProductOverview => DocumentVisibility::Public,
            Self::SecurityOverview => DocumentVisibility::Public,
            Self::ComplianceOverview => DocumentVisibility::Public,
            Self::DPA => DocumentVisibility::Public,
            Self::SubprocessorList => DocumentVisibility::Public,
            Self::SLATemplate => DocumentVisibility::Qualified,
            Self::SupportPolicy => DocumentVisibility::Public,
            Self::BusinessContinuitySummary => DocumentVisibility::NDA,
            Self::DisasterRecoverySummary => DocumentVisibility::NDA,
            Self::IncidentResponseSummary => DocumentVisibility::NDA,
            Self::DataRetentionPolicy => DocumentVisibility::Public,
            Self::DataDeletionPolicy => DocumentVisibility::Public,
            Self::ArchitectureOverview => DocumentVisibility::Public,
            Self::InsuranceDetails => DocumentVisibility::NDA,
            Self::CertificationStatus => DocumentVisibility::Qualified,
            Self::StandardVendorQuestionnaire => DocumentVisibility::NDA,
            // A draft is not available to anyone yet, so it is not routed
            // through the Public/Qualified/NDA availability ladder.
            Self::UsDpaAddendum => DocumentVisibility::Draft,
        }
    }

    pub fn version_controlled(&self) -> bool {
        true
    }

    pub fn all_documents() -> Vec<ProcurementDocumentEntry> {
        use ProcurementDocument::*;
        [
            CompanyProfile,
            ProductOverview,
            SecurityOverview,
            ComplianceOverview,
            DPA,
            SubprocessorList,
            SLATemplate,
            SupportPolicy,
            BusinessContinuitySummary,
            DisasterRecoverySummary,
            IncidentResponseSummary,
            DataRetentionPolicy,
            DataDeletionPolicy,
            ArchitectureOverview,
            InsuranceDetails,
            CertificationStatus,
            StandardVendorQuestionnaire,
            UsDpaAddendum,
        ]
        .iter()
        .map(|doc| ProcurementDocumentEntry {
            id: doc.doc_id().to_string(),
            display_name: doc.display_name().to_string(),
            description: doc.description().to_string(),
            visibility: doc.visibility(),
            version_controlled: doc.version_controlled(),
        })
        .collect()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DocumentVisibility {
    Public,
    Qualified,
    NDA,
    /// Written but NOT approved and NOT offered: the package lists it so the
    /// pending work is visible, and no availability claim is made.
    Draft,
}

impl DocumentVisibility {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Public => "Publicly available",
            Self::Qualified => "Available to qualified prospects",
            Self::NDA => "Available under NDA only",
            Self::Draft => "Draft — awaiting owner approval; not offered",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcurementDocumentEntry {
    pub id: String,
    pub display_name: String,
    pub description: String,
    pub visibility: DocumentVisibility,
    pub version_controlled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcurementRequest {
    pub customer_name: String,
    pub customer_company: String,
    pub customer_email: String,
    pub documents_requested: Vec<String>,
    pub purpose: String,
    pub nda_signed: bool,
    pub timestamp: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcurementRequestConfirmation {
    pub request_id: String,
    pub status: ProcurementRequestStatus,
    pub documents_granted: Vec<String>,
    pub documents_pending_nda: Vec<String>,
    pub message: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProcurementRequestStatus {
    Fulfilled,
    PartiallyFulfilled,
    PendingNDA,
    Rejected,
}

impl ProcurementRequestStatus {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Fulfilled => "All documents granted",
            Self::PartiallyFulfilled => "Some documents granted",
            Self::PendingNDA => "NDA required",
            Self::Rejected => "Not eligible",
        }
    }
}

pub fn validate_procurement_package() -> ProcurementPackageValidation {
    let docs = ProcurementDocument::all_documents();
    // 17 available documents + the US DPA addendum, which is listed as a
    // DRAFT while it awaits owner approval.
    let expected = 18;

    ProcurementPackageValidation {
        total_documents: docs.len(),
        expected_count: expected,
        all_present: docs.len() == expected,
        all_version_controlled: docs.iter().all(|d| d.version_controlled),
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcurementPackageValidation {
    pub total_documents: usize,
    pub expected_count: usize,
    pub all_present: bool,
    pub all_version_controlled: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_all_procurement_documents_defined() {
        // 17 available documents plus PROC-018, the US DPA addendum, which is
        // carried as a draft (see `test_the_us_dpa_addendum_is_a_draft`).
        let docs = ProcurementDocument::all_documents();
        assert_eq!(docs.len(), 18);
    }

    /// The US DPA addendum is a DRAFT row: listed, clearly not approved, and
    /// NOT offered (its visibility is `Draft`, not an availability tier).
    #[test]
    fn test_the_us_dpa_addendum_is_a_draft() {
        let docs = ProcurementDocument::all_documents();
        let addendum = docs
            .iter()
            .find(|d| d.id == "PROC-018")
            .expect("the US DPA addendum row must be listed");
        assert_eq!(addendum.visibility, DocumentVisibility::Draft);
        assert!(
            addendum.display_name.contains("draft"),
            "the display name must say it is a draft: {}",
            addendum.display_name
        );
        let description = addendum.description.to_ascii_lowercase();
        for needle in ["draft", "not effective", "owner approves", "approved_by"] {
            assert!(
                description.contains(needle),
                "the description must carry '{needle}': {}",
                addendum.description
            );
        }
        // No other document is a draft, and no row claims an approval.
        assert_eq!(
            docs.iter()
                .filter(|d| d.visibility == DocumentVisibility::Draft)
                .count(),
            1,
            "only the US DPA addendum may be carried as a draft"
        );
        for doc in &docs {
            for forbidden in ["approved_by:", "approved_at:", "approved by ApexMail"] {
                assert!(
                    !doc.description.contains(forbidden),
                    "{} must not claim an approval ({forbidden})",
                    doc.id
                );
            }
        }
    }

    /// The draft tier's label is honest: it says the document is not offered.
    #[test]
    fn test_draft_visibility_label_is_honest() {
        assert_eq!(
            DocumentVisibility::Draft.label(),
            "Draft — awaiting owner approval; not offered"
        );
    }

    #[test]
    fn test_all_documents_have_unique_ids() {
        let docs = ProcurementDocument::all_documents();
        let mut ids = std::collections::HashSet::new();
        for doc in &docs {
            assert!(
                ids.insert(doc.id.clone()),
                "Duplicate document ID: {}",
                doc.id
            );
        }
    }

    #[test]
    fn test_all_documents_version_controlled() {
        let docs = ProcurementDocument::all_documents();
        for doc in &docs {
            assert!(
                doc.version_controlled,
                "Document {} must be version controlled",
                doc.id
            );
        }
    }

    #[test]
    fn test_visibility_categories() {
        let docs = ProcurementDocument::all_documents();
        let public_count = docs
            .iter()
            .filter(|d| d.visibility == DocumentVisibility::Public)
            .count();
        let nda_count = docs
            .iter()
            .filter(|d| d.visibility == DocumentVisibility::NDA)
            .count();
        assert!(public_count > 0, "Must have public documents");
        assert!(nda_count > 0, "Must have NDA-restricted documents");
    }

    #[test]
    fn test_no_confidential_public_exposure() {
        let docs = ProcurementDocument::all_documents();
        let insurance = docs.iter().find(|d| d.id == "PROC-015").unwrap();
        assert_eq!(
            insurance.visibility,
            DocumentVisibility::NDA,
            "Insurance details must not be publicly exposed"
        );
        let bc = docs.iter().find(|d| d.id == "PROC-009").unwrap();
        assert_eq!(
            bc.visibility,
            DocumentVisibility::NDA,
            "Business continuity details must not be publicly exposed"
        );
    }

    #[test]
    fn test_validate_procurement_package() {
        let validation = validate_procurement_package();
        assert!(validation.all_present);
        assert!(validation.all_version_controlled);
    }
}
