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
        }
    }

    pub fn version_controlled(&self) -> bool {
        true
    }

    pub fn all_documents() -> Vec<ProcurementDocumentEntry> {
        use ProcurementDocument::*;
        [
            CompanyProfile, ProductOverview, SecurityOverview, ComplianceOverview, DPA,
            SubprocessorList, SLATemplate, SupportPolicy, BusinessContinuitySummary,
            DisasterRecoverySummary, IncidentResponseSummary, DataRetentionPolicy,
            DataDeletionPolicy, ArchitectureOverview, InsuranceDetails,
            CertificationStatus, StandardVendorQuestionnaire,
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
}

impl DocumentVisibility {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Public => "Publicly available",
            Self::Qualified => "Available to qualified prospects",
            Self::NDA => "Available under NDA only",
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
    let expected = 17;

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
    fn test_all_17_procurement_documents_defined() {
        let docs = ProcurementDocument::all_documents();
        assert_eq!(docs.len(), 17);
    }

    #[test]
    fn test_all_documents_have_unique_ids() {
        let docs = ProcurementDocument::all_documents();
        let mut ids = std::collections::HashSet::new();
        for doc in &docs {
            assert!(ids.insert(doc.id.clone()), "Duplicate document ID: {}", doc.id);
        }
    }

    #[test]
    fn test_all_documents_version_controlled() {
        let docs = ProcurementDocument::all_documents();
        for doc in &docs {
            assert!(doc.version_controlled, "Document {} must be version controlled", doc.id);
        }
    }

    #[test]
    fn test_visibility_categories() {
        let docs = ProcurementDocument::all_documents();
        let public_count = docs.iter().filter(|d| d.visibility == DocumentVisibility::Public).count();
        let nda_count = docs.iter().filter(|d| d.visibility == DocumentVisibility::NDA).count();
        assert!(public_count > 0, "Must have public documents");
        assert!(nda_count > 0, "Must have NDA-restricted documents");
    }

    #[test]
    fn test_no_confidential_public_exposure() {
        let docs = ProcurementDocument::all_documents();
        let insurance = docs.iter().find(|d| d.id == "PROC-015").unwrap();
        assert_eq!(insurance.visibility, DocumentVisibility::NDA,
            "Insurance details must not be publicly exposed");
        let bc = docs.iter().find(|d| d.id == "PROC-009").unwrap();
        assert_eq!(bc.visibility, DocumentVisibility::NDA,
            "Business continuity details must not be publicly exposed");
    }

    #[test]
    fn test_validate_procurement_package() {
        let validation = validate_procurement_package();
        assert!(validation.all_present);
        assert!(validation.all_version_controlled);
    }
}
