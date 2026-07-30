use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ImplementationStage {
    Qualification,
    RequirementsCollection,
    SecurityWorkshop,
    ArchitectureDesign,
    DataResidencyReview,
    CommercialProposal,
    ContractAndDPA,
    EnvironmentProvisioning,
    Deployment,
    Integration,
    SecurityValidation,
    PerformanceTesting,
    Migration,
    GoLive,
    Stabilization,
    OngoingOperations,
}

impl ImplementationStage {
    pub fn stage_number(&self) -> u8 {
        match self {
            Self::Qualification => 1,
            Self::RequirementsCollection => 2,
            Self::SecurityWorkshop => 3,
            Self::ArchitectureDesign => 4,
            Self::DataResidencyReview => 5,
            Self::CommercialProposal => 6,
            Self::ContractAndDPA => 7,
            Self::EnvironmentProvisioning => 8,
            Self::Deployment => 9,
            Self::Integration => 10,
            Self::SecurityValidation => 11,
            Self::PerformanceTesting => 12,
            Self::Migration => 13,
            Self::GoLive => 14,
            Self::Stabilization => 15,
            Self::OngoingOperations => 16,
        }
    }

    pub fn display_name(&self) -> &'static str {
        match self {
            Self::Qualification => "Qualification",
            Self::RequirementsCollection => "Requirements Collection",
            Self::SecurityWorkshop => "Security Workshop",
            Self::ArchitectureDesign => "Architecture Design",
            Self::DataResidencyReview => "Data Residency Review",
            Self::CommercialProposal => "Commercial Proposal",
            Self::ContractAndDPA => "Contract and DPA",
            Self::EnvironmentProvisioning => "Environment Provisioning",
            Self::Deployment => "Deployment",
            Self::Integration => "Integration",
            Self::SecurityValidation => "Security Validation",
            Self::PerformanceTesting => "Performance Testing",
            Self::Migration => "Migration",
            Self::GoLive => "Go-Live",
            Self::Stabilization => "Stabilization",
            Self::OngoingOperations => "Ongoing Operations",
        }
    }

    pub fn owner(&self) -> Responsibility {
        match self {
            Self::Qualification => Responsibility::ApexMailSales,
            Self::RequirementsCollection => Responsibility::Shared,
            Self::SecurityWorkshop => Responsibility::ApexMailEngineering,
            Self::ArchitectureDesign => Responsibility::ApexMailEngineering,
            Self::DataResidencyReview => Responsibility::Shared,
            Self::CommercialProposal => Responsibility::ApexMailSales,
            Self::ContractAndDPA => Responsibility::Shared,
            Self::EnvironmentProvisioning => Responsibility::ApexMailEngineering,
            Self::Deployment => Responsibility::ApexMailEngineering,
            Self::Integration => Responsibility::Shared,
            Self::SecurityValidation => Responsibility::Customer,
            Self::PerformanceTesting => Responsibility::Customer,
            Self::Migration => Responsibility::Shared,
            Self::GoLive => Responsibility::Shared,
            Self::Stabilization => Responsibility::ApexMailEngineering,
            Self::OngoingOperations => Responsibility::Shared,
        }
    }

    pub fn customer_inputs(&self) -> &'static str {
        match self {
            Self::Qualification => "Volume estimates, compliance requirements, deployment preference, target timeline",
            Self::RequirementsCollection => "Functional requirements, integration architecture, security policies, compliance frameworks",
            Self::SecurityWorkshop => "Security questionnaire, internal security policies, access control requirements, encryption requirements",
            Self::ArchitectureDesign => "Network topology, existing cloud providers, data flow diagrams, availability requirements",
            Self::DataResidencyReview => "Data categories, jurisdiction requirements, data sovereignty constraints, cross-border transfer assessments",
            Self::CommercialProposal => "Budget authorization, procurement contact, preferred contract terms",
            Self::ContractAndDPA => "Legal review, data processing needs, subprocessor review, signature authority",
            Self::EnvironmentProvisioning => "Cloud account (BYOC), network configuration, IAM roles, DNS configuration",
            Self::Deployment => "Access credentials, domain verification records, initial user accounts",
            Self::Integration => "API keys, webhook endpoints, SMTP credentials, SDK integration, test recipients",
            Self::SecurityValidation => "Penetration test scope, security scan authorization, compliance audit access",
            Self::PerformanceTesting => "Test message volumes, load profiles, latency requirements, monitoring dashboards",
            Self::Migration => "Existing provider API keys, current domain configurations, suppression lists, template exports",
            Self::GoLive => "Production DNS changes, cutover authorization, monitoring escalation contacts",
            Self::Stabilization => "Performance metrics, error reports, deliverability feedback, support ticket review",
            Self::OngoingOperations => "Monthly volume forecasts, upgrade preferences, maintenance window preferences, SLA reporting",
        }
    }

    pub fn apexmail_deliverables(&self) -> &'static str {
        match self {
            Self::Qualification => "Qualification summary, rough pricing estimate, deployment model recommendation",
            Self::RequirementsCollection => "Requirements document, gap analysis, preliminary architecture proposal",
            Self::SecurityWorkshop => "Security controls mapping, shared responsibility model, data flow analysis",
            Self::ArchitectureDesign => "Reference architecture, network diagram, deployment topology, monitoring design",
            Self::DataResidencyReview => "Data residency matrix, transfer mechanism documentation, subprocessor alignment",
            Self::CommercialProposal => "Pricing proposal, SLA terms, support plan, deployment timeline, scope of work",
            Self::ContractAndDPA => "Contract, DPA, SLA, order form, security exhibits",
            Self::EnvironmentProvisioning => "Provisioned infrastructure, access credentials, network configuration, monitoring setup",
            Self::Deployment => "Deployed ApexMail software, configured services, verified connectivity, initial health checks",
            Self::Integration => "Integration test results, API connectivity validation, webhook delivery confirmation",
            Self::SecurityValidation => "Security documentation package, penetration test summary, compliance matrix",
            Self::PerformanceTesting => "Load test results, throughput benchmarks, latency measurements, capacity plan",
            Self::Migration => "Migration plan, data transfer scripts, validation reports, cutover runbook",
            Self::GoLive => "Production deployment, DNS cutover, monitoring activation, escalation path confirmation",
            Self::Stabilization => "Daily health reports, performance tuning recommendations, issue resolution",
            Self::OngoingOperations => "Monthly service review, capacity planning, upgrade schedule, SLA reporting, trend analysis",
        }
    }

    pub fn estimated_duration_range(&self) -> &'static str {
        match self {
            Self::Qualification => "2–5 business days",
            Self::RequirementsCollection => "1–2 weeks",
            Self::SecurityWorkshop => "1–2 weeks",
            Self::ArchitectureDesign => "1–3 weeks",
            Self::DataResidencyReview => "1–2 weeks",
            Self::CommercialProposal => "1–2 weeks",
            Self::ContractAndDPA => "2–6 weeks",
            Self::EnvironmentProvisioning => "1–3 weeks",
            Self::Deployment => "3–5 business days",
            Self::Integration => "1–3 weeks",
            Self::SecurityValidation => "2–4 weeks",
            Self::PerformanceTesting => "1–2 weeks",
            Self::Migration => "2–8 weeks",
            Self::GoLive => "1–3 business days",
            Self::Stabilization => "2–4 weeks",
            Self::OngoingOperations => "Continuous",
        }
    }

    pub fn approval_required(&self) -> bool {
        match self {
            Self::Qualification => false,
            Self::RequirementsCollection => false,
            Self::SecurityWorkshop => false,
            Self::ArchitectureDesign => true,
            Self::DataResidencyReview => true,
            Self::CommercialProposal => true,
            Self::ContractAndDPA => true,
            Self::EnvironmentProvisioning => false,
            Self::Deployment => false,
            Self::Integration => false,
            Self::SecurityValidation => true,
            Self::PerformanceTesting => true,
            Self::Migration => true,
            Self::GoLive => true,
            Self::Stabilization => false,
            Self::OngoingOperations => false,
        }
    }

    pub fn exit_criteria(&self) -> &'static str {
        match self {
            Self::Qualification => "Volume, compliance, and deployment requirements documented. Mutual agreement to proceed.",
            Self::RequirementsCollection => "All functional and non-functional requirements documented and reviewed.",
            Self::SecurityWorkshop => "Security controls mapped. Shared responsibility model agreed. Residual risks documented.",
            Self::ArchitectureDesign => "Architecture approved by both ApexMail engineering and customer technical team.",
            Self::DataResidencyReview => "All data categories mapped to processing and storage locations. Transfer mechanisms documented.",
            Self::CommercialProposal => "Pricing, terms, and scope approved by customer procurement.",
            Self::ContractAndDPA => "Contract, DPA, and SLA executed by both parties.",
            Self::EnvironmentProvisioning => "Infrastructure provisioned, accessible, and passing health checks.",
            Self::Deployment => "ApexMail software deployed, all services healthy, connectivity verified.",
            Self::Integration => "API, SMTP, and webhook integration passing all test cases.",
            Self::SecurityValidation => "Security validation complete. Residual risks accepted or remediated.",
            Self::PerformanceTesting => "All performance targets met under defined load profiles.",
            Self::Migration => "Production traffic migrated. Verification confirms parity. Rollback plan available.",
            Self::GoLive => "Production DNS switched. Monitoring confirms normal operation for 24+ hours.",
            Self::Stabilization => "No critical issues for 7 consecutive days. Performance within targets.",
            Self::OngoingOperations => "Not applicable — continuous operations.",
        }
    }

    pub fn all_stages() -> Vec<ImplementationStageDetail> {
        use ImplementationStage::*;
        [
            Qualification, RequirementsCollection, SecurityWorkshop, ArchitectureDesign,
            DataResidencyReview, CommercialProposal, ContractAndDPA, EnvironmentProvisioning,
            Deployment, Integration, SecurityValidation, PerformanceTesting, Migration,
            GoLive, Stabilization, OngoingOperations,
        ]
        .iter()
        .map(|stage| ImplementationStageDetail {
            stage_number: stage.stage_number(),
            display_name: stage.display_name().to_string(),
            owner: stage.owner().to_string(),
            customer_inputs: stage.customer_inputs().to_string(),
            apexmail_deliverables: stage.apexmail_deliverables().to_string(),
            estimated_duration: stage.estimated_duration_range().to_string(),
            approval_required: stage.approval_required(),
            exit_criteria: stage.exit_criteria().to_string(),
        })
        .collect()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Responsibility {
    ApexMailEngineering,
    ApexMailSales,
    Customer,
    Shared,
}

impl Responsibility {
    pub fn to_string(&self) -> String {
        match self {
            Self::ApexMailEngineering => "ApexMail Engineering".to_string(),
            Self::ApexMailSales => "ApexMail Sales".to_string(),
            Self::Customer => "Customer".to_string(),
            Self::Shared => "Shared".to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImplementationStageDetail {
    pub stage_number: u8,
    pub display_name: String,
    pub owner: String,
    pub customer_inputs: String,
    pub apexmail_deliverables: String,
    pub estimated_duration: String,
    pub approval_required: bool,
    pub exit_criteria: String,
}

pub fn validate_stages_completeness() -> ImplementationStageValidation {
    let stages = ImplementationStage::all_stages();
    let expected_count = 16;
    let all_covered = stages.iter().all(|s| {
        s.stage_number > 0
            && s.stage_number <= 16
            && !s.display_name.is_empty()
            && !s.owner.is_empty()
            && !s.customer_inputs.is_empty()
            && !s.apexmail_deliverables.is_empty()
            && !s.estimated_duration.is_empty()
            && !s.exit_criteria.is_empty()
    });

    ImplementationStageValidation {
        total_stages: stages.len(),
        expected_count,
        all_present: stages.len() == expected_count,
        all_fields_complete: all_covered,
        sequential_numbering: stages.windows(2).all(|w| w[0].stage_number + 1 == w[1].stage_number),
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImplementationStageValidation {
    pub total_stages: usize,
    pub expected_count: usize,
    pub all_present: bool,
    pub all_fields_complete: bool,
    pub sequential_numbering: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_all_16_stages_defined() {
        let stages = ImplementationStage::all_stages();
        assert_eq!(stages.len(), 16);
    }

    #[test]
    fn test_stages_are_sequentially_numbered() {
        let stages = ImplementationStage::all_stages();
        for window in stages.windows(2) {
            assert_eq!(
                window[0].stage_number + 1,
                window[1].stage_number,
                "Stage {} must precede stage {}",
                window[0].display_name,
                window[1].display_name
            );
        }
    }

    #[test]
    fn test_all_stages_have_exit_criteria() {
        let stages = ImplementationStage::all_stages();
        for stage in &stages {
            assert!(!stage.exit_criteria.is_empty(), "Stage {} missing exit criteria", stage.display_name);
        }
    }

    #[test]
    fn test_all_stages_have_estimated_duration() {
        let stages = ImplementationStage::all_stages();
        for stage in &stages {
            assert!(!stage.estimated_duration.is_empty(), "Stage {} missing duration estimate", stage.display_name);
        }
    }

    #[test]
    fn test_validate_stages_completeness() {
        let validation = validate_stages_completeness();
        assert!(validation.all_present);
        assert!(validation.all_fields_complete);
        assert!(validation.sequential_numbering);
    }

    #[test]
    fn test_approval_stages() {
        let stages = ImplementationStage::all_stages();
        let approval_stages: Vec<_> = stages.iter().filter(|s| s.approval_required).collect();
        assert!(!approval_stages.is_empty(), "At least some stages must require approval");
    }
}
