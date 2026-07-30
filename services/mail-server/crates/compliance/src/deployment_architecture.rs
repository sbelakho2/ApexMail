use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeploymentModel {
    SharedEuCloud,
    DedicatedTenant,
    Byoc,
}

impl std::fmt::Display for DeploymentModel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::SharedEuCloud => "shared_eu_cloud",
            Self::DedicatedTenant => "dedicated_tenant",
            Self::Byoc => "byoc",
        };
        f.write_str(s)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeploymentSpec {
    pub model: DeploymentModel,
    pub tenancy: String,
    pub region: Vec<String>,
    pub ip_option: String,
    pub monitoring: String,
    pub maintenance: String,
    pub sla: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Responsibility {
    ApexMail,
    Customer,
    Shared,
}

impl std::fmt::Display for Responsibility {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ApexMail => f.write_str("ApexMail"),
            Self::Customer => f.write_str("Customer"),
            Self::Shared => f.write_str("Shared"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResponsibilityArea {
    CloudAccount,
    InfrastructurePatching,
    ApplicationUpdates,
    EncryptionKeys,
    Monitoring,
    SendingIps,
    Dns,
    Backups,
    IncidentResponse,
    DataDeletion,
    CostResponsibility,
}

impl std::fmt::Display for ResponsibilityArea {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::CloudAccount => "Cloud account",
            Self::InfrastructurePatching => "Infrastructure patching",
            Self::ApplicationUpdates => "Application updates",
            Self::EncryptionKeys => "Encryption keys",
            Self::Monitoring => "Monitoring",
            Self::SendingIps => "Sending IPs",
            Self::Dns => "DNS",
            Self::Backups => "Backups",
            Self::IncidentResponse => "Incident response",
            Self::DataDeletion => "Data deletion",
            Self::CostResponsibility => "Cost responsibility",
        };
        f.write_str(s)
    }
}

#[cfg(test)]
const fn all_responsibility_areas() -> [ResponsibilityArea; 11] {
    [
        ResponsibilityArea::CloudAccount,
        ResponsibilityArea::InfrastructurePatching,
        ResponsibilityArea::ApplicationUpdates,
        ResponsibilityArea::EncryptionKeys,
        ResponsibilityArea::Monitoring,
        ResponsibilityArea::SendingIps,
        ResponsibilityArea::Dns,
        ResponsibilityArea::Backups,
        ResponsibilityArea::IncidentResponse,
        ResponsibilityArea::DataDeletion,
        ResponsibilityArea::CostResponsibility,
    ]
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponsibilityMatrixEntry {
    pub area: ResponsibilityArea,
    pub shared_eu_cloud: Responsibility,
    pub dedicated_tenant: Responsibility,
    pub byoc: Responsibility,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponsibilityMatrix {
    pub entries: Vec<ResponsibilityMatrixEntry>,
}

impl ResponsibilityMatrix {
    pub fn new() -> Self {
        Self {
            entries: vec![
                ResponsibilityMatrixEntry {
                    area: ResponsibilityArea::CloudAccount,
                    shared_eu_cloud: Responsibility::ApexMail,
                    dedicated_tenant: Responsibility::ApexMail,
                    byoc: Responsibility::Customer,
                },
                ResponsibilityMatrixEntry {
                    area: ResponsibilityArea::InfrastructurePatching,
                    shared_eu_cloud: Responsibility::ApexMail,
                    dedicated_tenant: Responsibility::ApexMail,
                    byoc: Responsibility::Customer,
                },
                ResponsibilityMatrixEntry {
                    area: ResponsibilityArea::ApplicationUpdates,
                    shared_eu_cloud: Responsibility::ApexMail,
                    dedicated_tenant: Responsibility::Shared,
                    byoc: Responsibility::Customer,
                },
                ResponsibilityMatrixEntry {
                    area: ResponsibilityArea::EncryptionKeys,
                    shared_eu_cloud: Responsibility::ApexMail,
                    dedicated_tenant: Responsibility::Customer,
                    byoc: Responsibility::Customer,
                },
                ResponsibilityMatrixEntry {
                    area: ResponsibilityArea::Monitoring,
                    shared_eu_cloud: Responsibility::ApexMail,
                    dedicated_tenant: Responsibility::ApexMail,
                    byoc: Responsibility::Shared,
                },
                ResponsibilityMatrixEntry {
                    area: ResponsibilityArea::SendingIps,
                    shared_eu_cloud: Responsibility::ApexMail,
                    dedicated_tenant: Responsibility::ApexMail,
                    byoc: Responsibility::Customer,
                },
                ResponsibilityMatrixEntry {
                    area: ResponsibilityArea::Dns,
                    shared_eu_cloud: Responsibility::Customer,
                    dedicated_tenant: Responsibility::Customer,
                    byoc: Responsibility::Customer,
                },
                ResponsibilityMatrixEntry {
                    area: ResponsibilityArea::Backups,
                    shared_eu_cloud: Responsibility::ApexMail,
                    dedicated_tenant: Responsibility::ApexMail,
                    byoc: Responsibility::Customer,
                },
                ResponsibilityMatrixEntry {
                    area: ResponsibilityArea::IncidentResponse,
                    shared_eu_cloud: Responsibility::ApexMail,
                    dedicated_tenant: Responsibility::Shared,
                    byoc: Responsibility::Shared,
                },
                ResponsibilityMatrixEntry {
                    area: ResponsibilityArea::DataDeletion,
                    shared_eu_cloud: Responsibility::ApexMail,
                    dedicated_tenant: Responsibility::Shared,
                    byoc: Responsibility::Customer,
                },
                ResponsibilityMatrixEntry {
                    area: ResponsibilityArea::CostResponsibility,
                    shared_eu_cloud: Responsibility::ApexMail,
                    dedicated_tenant: Responsibility::ApexMail,
                    byoc: Responsibility::Customer,
                },
            ],
        }
    }

    pub fn get_responsibility(&self, area: ResponsibilityArea, model: DeploymentModel) -> Option<Responsibility> {
        self.entries.iter().find(|e| e.area == area).map(|e| match model {
            DeploymentModel::SharedEuCloud => e.shared_eu_cloud,
            DeploymentModel::DedicatedTenant => e.dedicated_tenant,
            DeploymentModel::Byoc => e.byoc,
        })
    }

    pub fn row_count(&self) -> usize {
        self.entries.len()
    }
}

impl Default for ResponsibilityMatrix {
    fn default() -> Self {
        Self::new()
    }
}

pub fn deployment_specs() -> Vec<DeploymentSpec> {
    vec![
        DeploymentSpec {
            model: DeploymentModel::SharedEuCloud,
            tenancy: "Multi-tenant".to_string(),
            region: vec!["EU (EEA)".to_string()],
            ip_option: "Shared or managed dedicated IP".to_string(),
            monitoring: "ApexMail-operated, shared dashboard".to_string(),
            maintenance: "Standard maintenance windows, ApexMail-managed".to_string(),
            sla: "99.9% uptime target".to_string(),
        },
        DeploymentSpec {
            model: DeploymentModel::DedicatedTenant,
            tenancy: "Dedicated application tenancy, dedicated data tenancy where contracted".to_string(),
            region: vec!["EU (EEA), plus defined region".to_string()],
            ip_option: "Dedicated IP pool".to_string(),
            monitoring: "Dedicated monitoring with customer access".to_string(),
            maintenance: "Customer-specific maintenance schedule".to_string(),
            sla: "99.95% uptime, enhanced SLA".to_string(),
        },
        DeploymentSpec {
            model: DeploymentModel::Byoc,
            tenancy: "Customer cloud account, customer-managed infrastructure".to_string(),
            region: vec!["Customer-defined".to_string()],
            ip_option: "Customer provisioned".to_string(),
            monitoring: "Shared monitoring responsibility, documented control plane".to_string(),
            maintenance: "Documented patch responsibility: infrastructure (customer), application (shared)".to_string(),
            sla: "Variable, defined per contract".to_string(),
        },
    ]
}

pub fn validate_deployment_readiness(model: DeploymentModel) -> DeploymentReadiness {
    let has_architecture = true;
    let has_deployment_procedure = true;
    let has_upgrade_procedure = model != DeploymentModel::Byoc;
    let has_backup_procedure = true;
    let has_incident_procedure = true;

    let all_ready = has_architecture
        && has_deployment_procedure
        && has_upgrade_procedure
        && has_backup_procedure
        && has_incident_procedure;

    DeploymentReadiness {
        model,
        has_reference_architecture: has_architecture,
        has_deployment_procedure,
        has_upgrade_procedure,
        has_backup_procedure,
        has_incident_procedure,
        all_ready,
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeploymentReadiness {
    pub model: DeploymentModel,
    pub has_reference_architecture: bool,
    pub has_deployment_procedure: bool,
    pub has_upgrade_procedure: bool,
    pub has_backup_procedure: bool,
    pub has_incident_procedure: bool,
    pub all_ready: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_responsibility_matrix_has_11_rows() {
        let matrix = ResponsibilityMatrix::new();
        assert_eq!(matrix.row_count(), 11);
        assert_eq!(matrix.entries.len(), all_responsibility_areas().len());
    }

    #[test]
    fn test_dns_is_customer_responsibility_for_all_models() {
        let matrix = ResponsibilityMatrix::new();
        assert_eq!(
            matrix.get_responsibility(ResponsibilityArea::Dns, DeploymentModel::SharedEuCloud),
            Some(Responsibility::Customer)
        );
        assert_eq!(
            matrix.get_responsibility(ResponsibilityArea::Dns, DeploymentModel::DedicatedTenant),
            Some(Responsibility::Customer)
        );
        assert_eq!(
            matrix.get_responsibility(ResponsibilityArea::Dns, DeploymentModel::Byoc),
            Some(Responsibility::Customer)
        );
    }

    #[test]
    fn test_deployment_specs_cover_all_three_models() {
        let specs = deployment_specs();
        assert_eq!(specs.len(), 3);
        let models: Vec<DeploymentModel> = specs.iter().map(|s| s.model).collect();
        assert!(models.contains(&DeploymentModel::SharedEuCloud));
        assert!(models.contains(&DeploymentModel::DedicatedTenant));
        assert!(models.contains(&DeploymentModel::Byoc));
    }

    #[test]
    fn test_validate_deployment_readiness() {
        let shared = validate_deployment_readiness(DeploymentModel::SharedEuCloud);
        assert!(shared.all_ready);
        assert!(shared.has_reference_architecture);

        let dedicated = validate_deployment_readiness(DeploymentModel::DedicatedTenant);
        assert!(dedicated.all_ready);
        assert!(dedicated.has_upgrade_procedure);

        let byoc = validate_deployment_readiness(DeploymentModel::Byoc);
        assert!(!byoc.all_ready);
        assert!(!byoc.has_upgrade_procedure);
    }

    #[test]
    fn test_deployment_model_display() {
        assert_eq!(DeploymentModel::SharedEuCloud.to_string(), "shared_eu_cloud");
        assert_eq!(DeploymentModel::DedicatedTenant.to_string(), "dedicated_tenant");
        assert_eq!(DeploymentModel::Byoc.to_string(), "byoc");
    }
}
