use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeploymentType {
    SharedEnterprise,
    DedicatedTenant,
    BYOC,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Responsibility {
    ApexMail,
    Customer,
    Shared,
    NotApplicable,
}

impl Responsibility {
    pub fn label(&self) -> &str {
        match self {
            Responsibility::ApexMail => "ApexMail",
            Responsibility::Customer => "Customer",
            Responsibility::Shared => "Shared",
            Responsibility::NotApplicable => "N/A",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DedicatedTenant {
    pub monthly_fee_eur: u32,
    pub minimum_term_months: u32,
    pub one_time_setup_min_eur: u32,
    pub one_time_setup_max_eur: u32,
    pub included_recipients: u64,
    pub managed_dedicated_ips: u32,
    pub region: String,
    pub private_network_available: bool,
    pub custom_maintenance_window: bool,
    pub named_technical_owner: bool,
    pub monthly_service_review: bool,
    pub custom_backup_policy: bool,
    pub custom_retention: bool,
    pub enhanced_sla: bool,
    pub dedicated_monitoring_views: bool,
    pub security_review_support: bool,
}

impl Default for DedicatedTenant {
    fn default() -> Self {
        Self {
            monthly_fee_eur: 4_000,
            minimum_term_months: 12,
            one_time_setup_min_eur: 10_000,
            one_time_setup_max_eur: 40_000,
            included_recipients: 5_000_000,
            managed_dedicated_ips: 2,
            region: "EEA".to_string(),
            private_network_available: true,
            custom_maintenance_window: true,
            named_technical_owner: true,
            monthly_service_review: true,
            custom_backup_policy: true,
            custom_retention: true,
            enhanced_sla: true,
            dedicated_monitoring_views: true,
            security_review_support: true,
        }
    }
}

impl DedicatedTenant {
    pub fn monthly_fee(&self) -> u32 {
        self.monthly_fee_eur
    }

    pub fn setup_fee_range(&self) -> (u32, u32) {
        (self.one_time_setup_min_eur, self.one_time_setup_max_eur)
    }

    pub fn annual_commitment(&self) -> u32 {
        self.monthly_fee_eur * self.minimum_term_months
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BYOC {
    pub monthly_fee_eur: u32,
    pub one_time_setup_min_eur: u32,
    pub one_time_setup_max_eur: u32,
    pub minimum_term_months_standard: u32,
    pub minimum_term_months_engineering: u32,
    pub includes_software_license: bool,
    pub includes_deployment_automation: bool,
    pub includes_upgrades: bool,
    pub includes_release_management: bool,
    pub includes_monitoring_integration: bool,
    pub includes_operational_support: bool,
    pub includes_deliverability_services: bool,
    pub includes_architecture_reviews: bool,
    pub includes_security_documentation: bool,
    pub includes_incident_coordination: bool,
}

impl Default for BYOC {
    fn default() -> Self {
        Self {
            monthly_fee_eur: 6_500,
            one_time_setup_min_eur: 20_000,
            one_time_setup_max_eur: 60_000,
            minimum_term_months_standard: 12,
            minimum_term_months_engineering: 24,
            includes_software_license: true,
            includes_deployment_automation: true,
            includes_upgrades: true,
            includes_release_management: true,
            includes_monitoring_integration: true,
            includes_operational_support: true,
            includes_deliverability_services: true,
            includes_architecture_reviews: true,
            includes_security_documentation: true,
            includes_incident_coordination: true,
        }
    }
}

impl BYOC {
    pub fn monthly_fee(&self) -> u32 {
        self.monthly_fee_eur
    }

    pub fn setup_fee_range(&self) -> (u32, u32) {
        (self.one_time_setup_min_eur, self.one_time_setup_max_eur)
    }

    pub fn annual_commitment_standard(&self) -> u32 {
        self.monthly_fee_eur * self.minimum_term_months_standard
    }

    pub fn annual_commitment_engineering(&self) -> u32 {
        self.monthly_fee_eur * self.minimum_term_months_engineering
    }

    pub fn customer_pays_directly(&self) -> Vec<&str> {
        vec![
            "Cloud infrastructure",
            "Databases",
            "Networking",
            "Egress",
            "Customer-required security tooling",
            "Customer-specific third-party assessments",
        ]
    }
}

pub const RESPONSIBILITY_AREAS: [&str; 11] = [
    "Application uptime and SLA",
    "Infrastructure provisioning",
    "Data residency compliance",
    "Security patching (OS, dependencies)",
    "Database administration",
    "Network configuration and firewalls",
    "Backup and disaster recovery",
    "Monitoring and alerting",
    "Incident response coordination",
    "Audit and assessment facilitation",
    "Upgrade and release management",
];

pub fn responsibility_matrix(deployment: DeploymentType, area: usize) -> Responsibility {
    match (deployment, area) {
        (DeploymentType::SharedEnterprise, 0) => Responsibility::ApexMail,
        (DeploymentType::SharedEnterprise, 1) => Responsibility::ApexMail,
        (DeploymentType::SharedEnterprise, 2) => Responsibility::ApexMail,
        (DeploymentType::SharedEnterprise, 3) => Responsibility::ApexMail,
        (DeploymentType::SharedEnterprise, 4) => Responsibility::ApexMail,
        (DeploymentType::SharedEnterprise, 5) => Responsibility::ApexMail,
        (DeploymentType::SharedEnterprise, 6) => Responsibility::ApexMail,
        (DeploymentType::SharedEnterprise, 7) => Responsibility::ApexMail,
        (DeploymentType::SharedEnterprise, 8) => Responsibility::ApexMail,
        (DeploymentType::SharedEnterprise, 9) => Responsibility::ApexMail,
        (DeploymentType::SharedEnterprise, 10) => Responsibility::ApexMail,

        (DeploymentType::DedicatedTenant, 0) => Responsibility::ApexMail,
        (DeploymentType::DedicatedTenant, 1) => Responsibility::ApexMail,
        (DeploymentType::DedicatedTenant, 2) => Responsibility::ApexMail,
        (DeploymentType::DedicatedTenant, 3) => Responsibility::Shared,
        (DeploymentType::DedicatedTenant, 4) => Responsibility::ApexMail,
        (DeploymentType::DedicatedTenant, 5) => Responsibility::Shared,
        (DeploymentType::DedicatedTenant, 6) => Responsibility::ApexMail,
        (DeploymentType::DedicatedTenant, 7) => Responsibility::ApexMail,
        (DeploymentType::DedicatedTenant, 8) => Responsibility::Shared,
        (DeploymentType::DedicatedTenant, 9) => Responsibility::ApexMail,
        (DeploymentType::DedicatedTenant, 10) => Responsibility::ApexMail,

        (DeploymentType::BYOC, 0) => Responsibility::ApexMail,
        (DeploymentType::BYOC, 1) => Responsibility::Customer,
        (DeploymentType::BYOC, 2) => Responsibility::Shared,
        (DeploymentType::BYOC, 3) => Responsibility::Customer,
        (DeploymentType::BYOC, 4) => Responsibility::Customer,
        (DeploymentType::BYOC, 5) => Responsibility::Customer,
        (DeploymentType::BYOC, 6) => Responsibility::Shared,
        (DeploymentType::BYOC, 7) => Responsibility::Shared,
        (DeploymentType::BYOC, 8) => Responsibility::Shared,
        (DeploymentType::BYOC, 9) => Responsibility::Customer,
        (DeploymentType::BYOC, 10) => Responsibility::ApexMail,

        _ => Responsibility::NotApplicable,
    }
}

pub fn full_responsibility_matrix() -> Vec<Vec<Responsibility>> {
    let types = [
        DeploymentType::SharedEnterprise,
        DeploymentType::DedicatedTenant,
        DeploymentType::BYOC,
    ];
    types
        .iter()
        .map(|&deployment| {
            (0..RESPONSIBILITY_AREAS.len())
                .map(|area| responsibility_matrix(deployment, area))
                .collect()
        })
        .collect()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivateCloudOperations {
    pub support_hours: SupportHours,
    pub incident_response_sla: IncidentResponseSLA,
    pub upgrade_cadence: UpgradeCadence,
    pub maintenance_windows: MaintenanceWindows,
    pub monitoring: MonitoringOwnership,
    pub backup_operations: BackupOperations,
    pub restore_testing: RestoreTesting,
    pub capacity_planning: CapacityPlanning,
    pub security_updates: SecurityUpdatePolicy,
    pub configuration_changes: ConfigurationChangeProcess,
    pub access_approvals: AccessApprovalPolicy,
    pub log_access: LogAccessPolicy,
    pub termination_and_export: TerminationAndExportPolicy,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SupportHours {
    pub hours: String,
    pub timezone: String,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IncidentResponseSLA {
    pub severity1_ack: String,
    pub severity1_resolution_target: String,
    pub severity2_ack: String,
    pub severity2_resolution_target: String,
    pub severity3_ack: String,
    pub severity4_ack: String,
    pub on_call_rotation: String,
    pub major_incident_manager: String,
    pub postmortem_required: bool,
    pub postmortem_delivery_days: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpgradeCadence {
    pub regular_releases: String,
    pub emergency_patches: String,
    pub notification_period: String,
    pub customer_approval_required: bool,
    pub rollback_window: String,
    pub release_notes_provided: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MaintenanceWindows {
    pub standard_window: String,
    pub custom_window_available: bool,
    pub emergency_window: String,
    pub notification_advance: String,
    pub maximum_duration: String,
    pub excluded_periods_negotiable: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitoringOwnership {
    pub apexmail_responsible: Vec<String>,
    pub customer_responsible: Vec<String>,
    pub shared_monitoring_dashboard: bool,
    pub alerting_channels: Vec<String>,
    pub tenant_separated_metrics: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupOperations {
    pub frequency: String,
    pub retention: String,
    pub geographic_separation: bool,
    pub encryption: String,
    pub ownership: BackupOwnership,
    pub verification_enabled: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BackupOwnership {
    ApexMail,
    Customer,
    Shared,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RestoreTesting {
    pub frequency: String,
    pub test_scope: String,
    pub results_shared: bool,
    pub rpo_seconds: Option<u64>,
    pub rto_minutes: Option<u64>,
    pub last_tested: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapacityPlanning {
    pub review_frequency: String,
    pub metrics_tracked: Vec<String>,
    pub capacity_report_shared: bool,
    pub scaling_lead_time: String,
    pub headroom_percentage: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityUpdatePolicy {
    pub critical_patch_window: String,
    pub high_severity_window: String,
    pub medium_severity_window: String,
    pub zero_day_handling: String,
    pub cvss_threshold_for_emergency: f64,
    pub testing_required: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigurationChangeProcess {
    pub standard_request_lead_time: String,
    pub emergency_request_process: String,
    pub approval_chain: Vec<String>,
    pub change_log_retention: String,
    pub customer_initiated_changes: bool,
    pub rollback_procedure: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessApprovalPolicy {
    pub access_request_process: String,
    pub approval_required_by: Vec<String>,
    pub access_log_retention: String,
    pub session_recording: bool,
    pub just_in_time_access: bool,
    pub periodic_access_review: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogAccessPolicy {
    pub customer_accessible_logs: Vec<String>,
    pub apexmail_reserved_logs: Vec<String>,
    pub log_retention_days: u32,
    pub export_format: String,
    pub siem_integration_available: bool,
    pub streaming_available: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TerminationAndExportPolicy {
    pub data_export_format: String,
    pub export_window_days: u32,
    pub export_assistance_provided: bool,
    pub secure_deletion_method: String,
    pub deletion_certificate_provided: bool,
    pub post_termination_retention: String,
    pub transition_support_available: bool,
}

impl Default for PrivateCloudOperations {
    fn default() -> Self {
        Self {
            support_hours: SupportHours {
                hours: "24/7 for Critical (SEV-1); business hours for SEV-2/3/4".to_string(),
                timezone: "Europe/Tallinn (EET/EEST)".to_string(),
                description: "Enterprise and Dedicated Tenant customers receive 24/7 support for critical incidents. Standard severity issues handled during business hours (09:00–18:00 EET Mon–Fri, 10:00–16:00 Sat).".to_string(),
            },
            incident_response_sla: IncidentResponseSLA {
                severity1_ack: "15 minutes".to_string(),
                severity1_resolution_target: "4 hours or continuous until resolved".to_string(),
                severity2_ack: "30 minutes".to_string(),
                severity2_resolution_target: "8 business hours".to_string(),
                severity3_ack: "4 business hours".to_string(),
                severity4_ack: "1 business day".to_string(),
                on_call_rotation: "Dedicated on-call engineer for Enterprise and Dedicated Tenant".to_string(),
                major_incident_manager: "Named incident manager assigned per contract".to_string(),
                postmortem_required: true,
                postmortem_delivery_days: 10,
            },
            upgrade_cadence: UpgradeCadence {
                regular_releases: "Monthly scheduled releases".to_string(),
                emergency_patches: "Deployed within SLA window based on severity".to_string(),
                notification_period: "2 weeks for regular releases; immediate for emergency patches".to_string(),
                customer_approval_required: true,
                rollback_window: "1 hour during standard maintenance; immediate for emergency rollback".to_string(),
                release_notes_provided: true,
            },
            maintenance_windows: MaintenanceWindows {
                standard_window: "Sunday 02:00–06:00 EET (default)".to_string(),
                custom_window_available: true,
                emergency_window: "As needed with immediate notification".to_string(),
                notification_advance: "14 days for standard; immediate for emergency".to_string(),
                maximum_duration: "4 hours for standard window".to_string(),
                excluded_periods_negotiable: true,
            },
            monitoring: MonitoringOwnership {
                apexmail_responsible: vec![
                    "Application uptime and health".to_string(),
                    "Delivery pipeline latency and throughput".to_string(),
                    "Error rates and anomaly detection".to_string(),
                    "Security monitoring and intrusion detection".to_string(),
                    "Infrastructure resource utilization (Dedicated Tenant)".to_string(),
                ],
                customer_responsible: vec![
                    "Cloud infrastructure health (BYOC)".to_string(),
                    "Network connectivity (BYOC)".to_string(),
                    "Integration endpoint availability".to_string(),
                ],
                shared_monitoring_dashboard: true,
                alerting_channels: vec![
                    "Email".to_string(),
                    "Slack/Teams (Dedicated Tenant and Enterprise)".to_string(),
                    "Phone (Critical incidents)".to_string(),
                ],
                tenant_separated_metrics: true,
            },
            backup_operations: BackupOperations {
                frequency: "Daily full backup; transaction logs every 15 minutes".to_string(),
                retention: "30 days standard; configurable up to 730 days for Enterprise".to_string(),
                geographic_separation: true,
                encryption: "AES-256 at rest; TLS 1.2+ in transit".to_string(),
                ownership: BackupOwnership::ApexMail,
                verification_enabled: true,
            },
            restore_testing: RestoreTesting {
                frequency: "Quarterly restore tests".to_string(),
                test_scope: "Full database restore and application recovery".to_string(),
                results_shared: true,
                rpo_seconds: Some(900),
                rto_minutes: Some(60),
                last_tested: None,
            },
            capacity_planning: CapacityPlanning {
                review_frequency: "Monthly".to_string(),
                metrics_tracked: vec![
                    "Email volume (hourly/daily/monthly)".to_string(),
                    "API request rate".to_string(),
                    "Database storage utilization".to_string(),
                    "Queue depth".to_string(),
                    "CPU and memory utilization".to_string(),
                    "Network throughput".to_string(),
                ],
                capacity_report_shared: true,
                scaling_lead_time: "24 hours for standard scaling; immediate for emergency".to_string(),
                headroom_percentage: 40.0,
            },
            security_updates: SecurityUpdatePolicy {
                critical_patch_window: "24 hours".to_string(),
                high_severity_window: "7 days".to_string(),
                medium_severity_window: "30 days".to_string(),
                zero_day_handling: "Immediate investigation and deployment upon verified advisory".to_string(),
                cvss_threshold_for_emergency: 9.0,
                testing_required: true,
            },
            configuration_changes: ConfigurationChangeProcess {
                standard_request_lead_time: "5 business days".to_string(),
                emergency_request_process: "Direct to on-call engineer with post-change approval".to_string(),
                approval_chain: vec![
                    "Customer technical contact".to_string(),
                    "ApexMail support lead".to_string(),
                    "ApexMail engineering manager (for infrastructure changes)".to_string(),
                ],
                change_log_retention: "Permanent (immutable audit log)".to_string(),
                customer_initiated_changes: true,
                rollback_procedure: "Documented per change type; immediate rollback capability".to_string(),
            },
            access_approvals: AccessApprovalPolicy {
                access_request_process: "Formal ticket with customer approval and access justification".to_string(),
                approval_required_by: vec![
                    "Customer technical contact (always)".to_string(),
                    "ApexMail support lead".to_string(),
                ],
                access_log_retention: "Permanent (immutable audit log)".to_string(),
                session_recording: true,
                just_in_time_access: true,
                periodic_access_review: "Quarterly".to_string(),
            },
            log_access: LogAccessPolicy {
                customer_accessible_logs: vec![
                    "Message delivery events".to_string(),
                    "API access logs".to_string(),
                    "Webhook delivery logs".to_string(),
                    "Authentication events".to_string(),
                    "Dashboard audit trail".to_string(),
                ],
                apexmail_reserved_logs: vec![
                    "Internal security monitoring logs".to_string(),
                    "Root access session recordings".to_string(),
                    "Intrusion detection alerts".to_string(),
                    "Internal infrastructure metrics".to_string(),
                ],
                log_retention_days: 365,
                export_format: "JSON Lines or CSV".to_string(),
                siem_integration_available: true,
                streaming_available: true,
            },
            termination_and_export: TerminationAndExportPolicy {
                data_export_format: "JSON, CSV, or raw database dump as negotiated".to_string(),
                export_window_days: 30,
                export_assistance_provided: true,
                secure_deletion_method: "NIST 800-88 compliant media sanitization".to_string(),
                deletion_certificate_provided: true,
                post_termination_retention: "30 days after termination; then secure deletion of all customer data".to_string(),
                transition_support_available: true,
            },
        }
    }
}

pub fn validate_private_cloud_operations() -> PrivateCloudOperationsValidation {
    let ops = PrivateCloudOperations::default();
    let all_fields_populated = !ops.support_hours.hours.is_empty()
        && !ops.incident_response_sla.severity1_ack.is_empty()
        && !ops.upgrade_cadence.regular_releases.is_empty()
        && !ops.maintenance_windows.standard_window.is_empty()
        && !ops.monitoring.apexmail_responsible.is_empty()
        && !ops.backup_operations.frequency.is_empty()
        && !ops.restore_testing.frequency.is_empty()
        && !ops.capacity_planning.review_frequency.is_empty()
        && !ops.security_updates.critical_patch_window.is_empty()
        && !ops.configuration_changes.standard_request_lead_time.is_empty()
        && !ops.access_approvals.access_request_process.is_empty()
        && !ops.log_access.customer_accessible_logs.is_empty()
        && !ops.termination_and_export.data_export_format.is_empty();

    PrivateCloudOperationsValidation {
        all_fields_populated,
        has_support_hours: !ops.support_hours.hours.is_empty(),
        has_incident_response: !ops.incident_response_sla.severity1_ack.is_empty(),
        has_upgrade_cadence: !ops.upgrade_cadence.regular_releases.is_empty(),
        has_maintenance_windows: !ops.maintenance_windows.standard_window.is_empty(),
        has_monitoring: !ops.monitoring.apexmail_responsible.is_empty(),
        has_backup_operations: !ops.backup_operations.frequency.is_empty(),
        has_restore_testing: !ops.restore_testing.frequency.is_empty(),
        has_capacity_planning: !ops.capacity_planning.review_frequency.is_empty(),
        has_security_updates: !ops.security_updates.critical_patch_window.is_empty(),
        has_configuration_changes: !ops.configuration_changes.standard_request_lead_time.is_empty(),
        has_access_approvals: !ops.access_approvals.access_request_process.is_empty(),
        has_log_access: !ops.log_access.customer_accessible_logs.is_empty(),
        has_termination_and_export: !ops.termination_and_export.data_export_format.is_empty(),
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivateCloudOperationsValidation {
    pub all_fields_populated: bool,
    pub has_support_hours: bool,
    pub has_incident_response: bool,
    pub has_upgrade_cadence: bool,
    pub has_maintenance_windows: bool,
    pub has_monitoring: bool,
    pub has_backup_operations: bool,
    pub has_restore_testing: bool,
    pub has_capacity_planning: bool,
    pub has_security_updates: bool,
    pub has_configuration_changes: bool,
    pub has_access_approvals: bool,
    pub has_log_access: bool,
    pub has_termination_and_export: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dedicated_tenant_default_pricing() {
        let dt = DedicatedTenant::default();
        assert_eq!(dt.monthly_fee_eur, 4_000);
        assert_eq!(dt.minimum_term_months, 12);
        assert_eq!(dt.annual_commitment(), 48_000);
    }

    #[test]
    fn test_byoc_default_pricing() {
        let byoc = BYOC::default();
        assert_eq!(byoc.monthly_fee_eur, 6_500);
        assert_eq!(byoc.one_time_setup_min_eur, 20_000);
        assert_eq!(byoc.annual_commitment_standard(), 78_000);
    }

    #[test]
    fn test_responsibility_matrix_shared_enterprise() {
        for area in 0..RESPONSIBILITY_AREAS.len() {
            assert_eq!(
                responsibility_matrix(DeploymentType::SharedEnterprise, area),
                Responsibility::ApexMail,
                "Area {} should be ApexMail for SharedEnterprise",
                area
            );
        }
    }

    #[test]
    fn test_responsibility_matrix_byoc_infrastructure_is_customer() {
        let infra_resp = responsibility_matrix(DeploymentType::BYOC, 1);
        assert_eq!(infra_resp, Responsibility::Customer);

        let db_resp = responsibility_matrix(DeploymentType::BYOC, 4);
        assert_eq!(db_resp, Responsibility::Customer);

        let app_uptime_resp = responsibility_matrix(DeploymentType::BYOC, 0);
        assert_eq!(app_uptime_resp, Responsibility::ApexMail);
    }

    #[test]
    fn test_full_matrix_has_3_deployments_11_areas() {
        let matrix = full_responsibility_matrix();
        assert_eq!(matrix.len(), 3);
        for row in &matrix {
            assert_eq!(row.len(), 11);
        }
    }

    #[test]
    fn test_byoc_customer_pays_directly_list() {
        let byoc = BYOC::default();
        let direct_costs = byoc.customer_pays_directly();
        assert_eq!(direct_costs.len(), 6);
        assert!(direct_costs.contains(&"Cloud infrastructure"));
        assert!(direct_costs.contains(&"Egress"));
    }

    #[test]
    fn test_private_cloud_operations_default() {
        let ops = PrivateCloudOperations::default();
        assert_eq!(ops.incident_response_sla.severity1_ack, "15 minutes");
        assert_eq!(ops.incident_response_sla.postmortem_delivery_days, 10);
        assert!(ops.maintenance_windows.custom_window_available);
        assert!(ops.access_approvals.just_in_time_access);
        assert!(ops.termination_and_export.deletion_certificate_provided);
    }

    #[test]
    fn test_validate_private_cloud_operations() {
        let validation = validate_private_cloud_operations();
        assert!(validation.all_fields_populated);
        assert!(validation.has_support_hours);
        assert!(validation.has_incident_response);
        assert!(validation.has_upgrade_cadence);
        assert!(validation.has_maintenance_windows);
        assert!(validation.has_monitoring);
        assert!(validation.has_backup_operations);
        assert!(validation.has_restore_testing);
        assert!(validation.has_capacity_planning);
        assert!(validation.has_security_updates);
        assert!(validation.has_configuration_changes);
        assert!(validation.has_access_approvals);
        assert!(validation.has_log_access);
        assert!(validation.has_termination_and_export);
    }

    #[test]
    fn test_incident_response_has_escalation() {
        let ops = PrivateCloudOperations::default();
        assert!(!ops.incident_response_sla.on_call_rotation.is_empty());
        assert!(!ops.incident_response_sla.major_incident_manager.is_empty());
        assert!(ops.incident_response_sla.postmortem_required);
    }

    #[test]
    fn test_backup_rpo_rto_defined() {
        let ops = PrivateCloudOperations::default();
        assert!(ops.restore_testing.rpo_seconds.is_some());
        assert!(ops.restore_testing.rto_minutes.is_some());
        assert_eq!(ops.restore_testing.rpo_seconds.unwrap(), 900);
        assert_eq!(ops.restore_testing.rto_minutes.unwrap(), 60);
    }

    #[test]
    fn test_security_update_critical_patch_within_24h() {
        let ops = PrivateCloudOperations::default();
        assert_eq!(ops.security_updates.critical_patch_window, "24 hours");
        assert!(ops.security_updates.cvss_threshold_for_emergency >= 9.0);
    }

    #[test]
    fn test_termination_export_within_30_days() {
        let ops = PrivateCloudOperations::default();
        assert_eq!(ops.termination_and_export.export_window_days, 30);
        assert!(ops.termination_and_export.transition_support_available);
    }
}
