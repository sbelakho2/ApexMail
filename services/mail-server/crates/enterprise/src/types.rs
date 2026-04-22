use chrono::{DateTime, NaiveDate, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

// ── SSO types ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct SSOConfiguration {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub provider_type: String,
    pub enabled: bool,
    pub domain: String,
    pub metadata_url: Option<String>,
    pub entity_id: Option<String>,
    pub sso_url: Option<String>,
    pub slo_url: Option<String>,
    pub certificate: Option<String>,
    pub private_key_encrypted: Option<String>,
    pub oidc_client_id: Option<String>,
    pub oidc_client_secret_encrypted: Option<String>,
    pub oidc_issuer: Option<String>,
    pub oidc_redirect_uri: Option<String>,
    pub oidc_scopes: Option<String>,
    pub attribute_mapping: Option<serde_json::Value>,
    pub enforce_sso: bool,
    pub allow_idp_initiated: bool,
    pub session_duration_hours: i32,
    pub created_at: Option<DateTime<Utc>>,
    pub updated_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct SSOSession {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub user_id: Option<String>,
    pub provider_type: String,
    pub external_user_id: String,
    pub email: String,
    pub display_name: Option<String>,
    pub groups: Option<serde_json::Value>,
    pub attributes: Option<serde_json::Value>,
    pub session_token: String,
    pub access_token_encrypted: Option<String>,
    pub refresh_token_encrypted: Option<String>,
    pub expires_at: DateTime<Utc>,
    pub last_activity_at: Option<DateTime<Utc>>,
    pub created_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SSOConfigureRequest {
    pub tenant_id: Uuid,
    pub provider_type: String,
    pub domain: String,
    pub enabled: Option<bool>,
    pub entity_id: Option<String>,
    pub sso_url: Option<String>,
    pub certificate: Option<String>,
    pub oidc_client_id: Option<String>,
    pub oidc_client_secret: Option<String>,
    pub oidc_issuer: Option<String>,
    pub attribute_mapping: Option<serde_json::Value>,
    pub enforce_sso: Option<bool>,
    pub session_duration_hours: Option<i32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SSOLoginRedirect {
    pub redirect_url: String,
    pub request_id: String,
}

/// OIDC state stored during login flow
#[derive(Debug, Clone)]
pub struct OidcStateData {
    pub code_verifier: String,
    pub domain: String,
    pub tenant_id: Option<Uuid>,
}

/// OIDC state row from database
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct OidcStateRow {
    pub state: String,
    pub code_verifier: String,
    pub domain: String,
    pub tenant_id: Uuid,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SSOCallbackResult {
    pub session: SSOSessionInfo,
    pub is_new_user: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SSOSessionInfo {
    pub session_token: String,
    pub email: String,
    pub display_name: Option<String>,
    pub groups: Option<Vec<String>>,
    pub expires_at: DateTime<Utc>,
}

// ── Compliance types ───────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ComplianceFramework {
    Hipaa,
    Soc2,
    Gdpr,
    Ccpa,
    Iso27001,
}

impl std::fmt::Display for ComplianceFramework {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Hipaa => write!(f, "hipaa"),
            Self::Soc2 => write!(f, "soc2"),
            Self::Gdpr => write!(f, "gdpr"),
            Self::Ccpa => write!(f, "ccpa"),
            Self::Iso27001 => write!(f, "iso27001"),
        }
    }
}

impl std::str::FromStr for ComplianceFramework {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "hipaa" => Ok(Self::Hipaa),
            "soc2" => Ok(Self::Soc2),
            "gdpr" => Ok(Self::Gdpr),
            "ccpa" => Ok(Self::Ccpa),
            "iso27001" => Ok(Self::Iso27001),
            _ => Err(format!("Unknown framework: {s}")),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ComplianceStatus {
    Pending,
    Active,
    Review,
    Suspended,
    Expired,
}

impl std::fmt::Display for ComplianceStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pending => write!(f, "pending"),
            Self::Active => write!(f, "active"),
            Self::Review => write!(f, "review"),
            Self::Suspended => write!(f, "suspended"),
            Self::Expired => write!(f, "expired"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct ComplianceConfig {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub enabled_frameworks: Option<Vec<String>>,
    pub status: String,
    pub zero_retention_mode: bool,
    pub encryption_at_rest: bool,
    pub encryption_in_transit: bool,
    pub audit_log_retention_days: i32,
    pub data_retention_days: Option<i32>,
    pub require_mfa: bool,
    pub baa_signed: bool,
    pub baa_signed_at: Option<DateTime<Utc>>,
    pub baa_signatory_name: Option<String>,
    pub baa_signatory_title: Option<String>,
    pub baa_signatory_email: Option<String>,
    pub dpa_signed: bool,
    pub dpa_signed_at: Option<DateTime<Utc>>,
    pub created_at: Option<DateTime<Utc>>,
    pub updated_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct AuditLogEntry {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub user_id: Option<String>,
    pub action: String,
    pub resource_type: String,
    pub resource_id: Option<String>,
    pub old_value: Option<serde_json::Value>,
    pub new_value: Option<serde_json::Value>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub session_id: Option<String>,
    pub request_id: Option<String>,
    pub metadata: Option<serde_json::Value>,
    pub created_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DataRequestType {
    Access,
    Export,
    Deletion,
}

impl std::fmt::Display for DataRequestType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Access => write!(f, "access"),
            Self::Export => write!(f, "export"),
            Self::Deletion => write!(f, "deletion"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DataRequestStatus {
    Pending,
    Approved,
    Processing,
    Completed,
    Rejected,
}

impl std::fmt::Display for DataRequestStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pending => write!(f, "pending"),
            Self::Approved => write!(f, "approved"),
            Self::Processing => write!(f, "processing"),
            Self::Completed => write!(f, "completed"),
            Self::Rejected => write!(f, "rejected"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct DataAccessRequest {
    pub id: Uuid,
    pub tenant_id: Uuid,
    #[sqlx(rename = "type")]
    #[serde(rename = "type")]
    pub request_type: String,
    pub status: String,
    pub requester_id: String,
    pub requester_email: String,
    pub resource_type: Option<String>,
    pub resource_id: Option<String>,
    pub scope: Option<String>,
    pub identifiers: Option<serde_json::Value>,
    pub justification: Option<String>,
    pub approved_by: Option<String>,
    pub approved_at: Option<DateTime<Utc>>,
    pub access_token: Option<String>,
    pub expires_at: Option<DateTime<Utc>>,
    pub duration_minutes: Option<i32>,
    pub completed_at: Option<DateTime<Utc>>,
    pub completion_details: Option<serde_json::Value>,
    pub created_at: Option<DateTime<Utc>>,
}

// ── Log Streaming types ────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum StreamDestinationType {
    S3,
    Gcs,
    AzureBlob,
    Webhook,
    Splunk,
    Datadog,
    SumoLogic,
    Elasticsearch,
}

impl std::fmt::Display for StreamDestinationType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::S3 => write!(f, "s3"),
            Self::Gcs => write!(f, "gcs"),
            Self::AzureBlob => write!(f, "azure_blob"),
            Self::Webhook => write!(f, "webhook"),
            Self::Splunk => write!(f, "splunk"),
            Self::Datadog => write!(f, "datadog"),
            Self::SumoLogic => write!(f, "sumo_logic"),
            Self::Elasticsearch => write!(f, "elasticsearch"),
        }
    }
}

impl std::str::FromStr for StreamDestinationType {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "s3" => Ok(Self::S3),
            "gcs" => Ok(Self::Gcs),
            "azure_blob" => Ok(Self::AzureBlob),
            "webhook" => Ok(Self::Webhook),
            "splunk" => Ok(Self::Splunk),
            "datadog" => Ok(Self::Datadog),
            "sumo_logic" => Ok(Self::SumoLogic),
            "elasticsearch" => Ok(Self::Elasticsearch),
            _ => Err(format!("Unknown destination: {s}")),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum StreamStatus {
    Active,
    Paused,
    Error,
    Disabled,
}

impl std::fmt::Display for StreamStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Active => write!(f, "active"),
            Self::Paused => write!(f, "paused"),
            Self::Error => write!(f, "error"),
            Self::Disabled => write!(f, "disabled"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct LogStream {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub destination_type: String,
    pub status: String,
    pub enabled: bool,
    pub destination_config: Option<serde_json::Value>,
    pub credentials_encrypted: Option<String>,
    pub log_categories: Option<Vec<String>>,
    pub filter_rules: Option<serde_json::Value>,
    pub batch_size: Option<i32>,
    pub batch_interval_seconds: Option<i32>,
    pub compression_enabled: bool,
    pub format: Option<String>,
    pub total_events_delivered: i64,
    pub total_bytes_delivered: i64,
    pub delivery_failures_count: i32,
    pub last_delivery_at: Option<DateTime<Utc>>,
    pub last_error: Option<String>,
    pub last_error_at: Option<DateTime<Utc>>,
    pub created_at: Option<DateTime<Utc>>,
    pub updated_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct StreamDelivery {
    pub id: Uuid,
    pub stream_id: Uuid,
    pub batch_id: String,
    pub event_count: i32,
    pub bytes_delivered: i64,
    pub duration_ms: i32,
    pub success: bool,
    pub error_message: Option<String>,
    pub created_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamStats {
    pub total_deliveries: i64,
    pub total_events: i64,
    pub total_bytes: i64,
    pub avg_duration_ms: f64,
    pub success_rate: f64,
}

// ── Private Deploy types ───────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DeploymentType {
    Dedicated,
    PrivateCloud,
    Hybrid,
    OnPremise,
}

impl std::fmt::Display for DeploymentType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Dedicated => write!(f, "dedicated"),
            Self::PrivateCloud => write!(f, "private_cloud"),
            Self::Hybrid => write!(f, "hybrid"),
            Self::OnPremise => write!(f, "on_premise"),
        }
    }
}

impl std::str::FromStr for DeploymentType {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "dedicated" => Ok(Self::Dedicated),
            "private_cloud" => Ok(Self::PrivateCloud),
            "hybrid" => Ok(Self::Hybrid),
            "on_premise" => Ok(Self::OnPremise),
            _ => Err(format!("Unknown deployment type: {s}")),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DeploymentStatus {
    Pending,
    Provisioning,
    Active,
    Maintenance,
    Decommissioning,
    Failed,
}

impl std::fmt::Display for DeploymentStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pending => write!(f, "pending"),
            Self::Provisioning => write!(f, "provisioning"),
            Self::Active => write!(f, "active"),
            Self::Maintenance => write!(f, "maintenance"),
            Self::Decommissioning => write!(f, "decommissioning"),
            Self::Failed => write!(f, "failed"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum IPStatus {
    Pending,
    Warming,
    Active,
    Suspended,
    Decommissioned,
}

impl std::fmt::Display for IPStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pending => write!(f, "pending"),
            Self::Warming => write!(f, "warming"),
            Self::Active => write!(f, "active"),
            Self::Suspended => write!(f, "suspended"),
            Self::Decommissioned => write!(f, "decommissioned"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct PrivateDeployment {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub name: String,
    pub deployment_type: String,
    pub status: String,
    pub region: Option<String>,
    pub availability_zones: Option<Vec<String>>,
    pub vpc_id: Option<String>,
    pub instance_type: Option<String>,
    pub instance_count: Option<i32>,
    pub storage_gb: Option<i32>,
    pub config: Option<serde_json::Value>,
    pub custom_domain: Option<String>,
    pub health_check_url: Option<String>,
    pub health_status: Option<String>,
    pub last_health_check_at: Option<DateTime<Utc>>,
    pub created_at: Option<DateTime<Utc>>,
    pub updated_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct DedicatedIP {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub deployment_id: Option<Uuid>,
    pub ip_address: String,
    pub ptr_record: Option<String>,
    pub status: String,
    pub warming_started_at: Option<DateTime<Utc>>,
    pub warming_progress_percent: Option<i32>,
    pub warming_plan: Option<serde_json::Value>,
    pub current_daily_limit: Option<i32>,
    pub reputation_score: Option<f64>,
    pub reputation_history: Option<serde_json::Value>,
    pub emails_sent_total: i64,
    pub bounces_total: i32,
    pub complaints_total: i32,
    pub blocklisted: bool,
    pub blocklist_details: Option<serde_json::Value>,
    pub created_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IPWarmingPlan {
    pub days: Vec<WarmingDay>,
    pub total_days: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WarmingDay {
    pub day: i32,
    pub daily_limit: i32,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IPReputation {
    pub ip_address: String,
    pub reputation_score: f64,
    pub bounce_rate: f64,
    pub complaint_rate: f64,
    pub blocklisted: bool,
    pub emails_sent_total: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AvailableIpCount {
    pub total: i64,
    pub by_region: std::collections::HashMap<String, i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct BYOIPRange {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub cidr_block: String,
    pub status: String,
    pub verification_token: Option<String>,
    pub verification_method: Option<String>,
    pub verified_at: Option<DateTime<Utc>>,
    pub created_at: Option<DateTime<Utc>>,
}

// ── Sub-Account types ──────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SubAccountStatus {
    Active,
    Suspended,
    Pending,
    Deactivated,
}

impl std::fmt::Display for SubAccountStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Active => write!(f, "active"),
            Self::Suspended => write!(f, "suspended"),
            Self::Pending => write!(f, "pending"),
            Self::Deactivated => write!(f, "deactivated"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct SubAccount {
    pub id: Uuid,
    pub parent_id: Uuid,
    pub name: String,
    pub status: String,
    pub email: Option<String>,
    pub domain: Option<String>,
    pub plan: Option<String>,
    pub volume_limit: Option<i64>,
    pub volume_used: i64,
    pub inherit_parent_settings: bool,
    pub settings: Option<serde_json::Value>,
    pub metadata: Option<serde_json::Value>,
    pub created_at: Option<DateTime<Utc>>,
    pub updated_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct SubAccountApiKey {
    pub id: Uuid,
    pub sub_account_id: Uuid,
    pub key_hash: String,
    pub key_prefix: String,
    pub name: String,
    pub permissions: Option<Vec<String>>,
    pub rate_limit: Option<i32>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub expires_at: Option<DateTime<Utc>>,
    pub revoked: bool,
    pub created_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubAccountStats {
    pub total: i64,
    pub active: i64,
    pub total_volume_used: i64,
    pub total_volume_limit: i64,
}

// ── Support types ──────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TicketStatus {
    New,
    Open,
    Pending,
    OnHold,
    WaitingCustomer,
    Escalated,
    Resolved,
    Closed,
}

impl std::fmt::Display for TicketStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::New => write!(f, "new"),
            Self::Open => write!(f, "open"),
            Self::Pending => write!(f, "pending"),
            Self::OnHold => write!(f, "on_hold"),
            Self::WaitingCustomer => write!(f, "waiting_customer"),
            Self::Escalated => write!(f, "escalated"),
            Self::Resolved => write!(f, "resolved"),
            Self::Closed => write!(f, "closed"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TicketPriority {
    Critical,
    High,
    Medium,
    Low,
}

impl std::fmt::Display for TicketPriority {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Critical => write!(f, "critical"),
            Self::High => write!(f, "high"),
            Self::Medium => write!(f, "medium"),
            Self::Low => write!(f, "low"),
        }
    }
}

impl std::str::FromStr for TicketPriority {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "critical" | "p1" => Ok(Self::Critical),
            "high" | "p2" => Ok(Self::High),
            "medium" | "normal" | "p3" => Ok(Self::Medium),
            "low" | "p4" => Ok(Self::Low),
            _ => Err(format!("Unknown priority: {s}")),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TicketCategory {
    Delivery,
    Authentication,
    Billing,
    Api,
    Integration,
    Security,
    FeatureRequest,
    Other,
}

impl std::fmt::Display for TicketCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Delivery => write!(f, "delivery"),
            Self::Authentication => write!(f, "authentication"),
            Self::Billing => write!(f, "billing"),
            Self::Api => write!(f, "api"),
            Self::Integration => write!(f, "integration"),
            Self::Security => write!(f, "security"),
            Self::FeatureRequest => write!(f, "feature_request"),
            Self::Other => write!(f, "other"),
        }
    }
}

impl std::str::FromStr for TicketCategory {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "delivery" => Ok(Self::Delivery),
            "authentication" => Ok(Self::Authentication),
            "billing" => Ok(Self::Billing),
            "api" => Ok(Self::Api),
            "integration" => Ok(Self::Integration),
            "security" => Ok(Self::Security),
            "feature_request" => Ok(Self::FeatureRequest),
            "other" => Ok(Self::Other),
            _ => Err(format!("Unknown category: {s}")),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct SupportTicket {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub number: Option<i32>,
    pub subject: String,
    pub description: String,
    pub category: String,
    pub priority: String,
    pub status: String,
    pub assigned_to: Option<Uuid>,
    pub team: Option<String>,
    pub sla_first_response_due: Option<DateTime<Utc>>,
    pub sla_resolution_due: Option<DateTime<Utc>>,
    pub sla_breached: bool,
    pub first_response_at: Option<DateTime<Utc>>,
    pub escalation_level: i32,
    pub escalated_at: Option<DateTime<Utc>>,
    pub created_by: String,
    pub contact_email: Option<String>,
    pub satisfaction_rating: Option<i32>,
    pub tags: Option<Vec<String>>,
    pub custom_fields: Option<serde_json::Value>,
    pub created_at: Option<DateTime<Utc>>,
    pub updated_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct TicketComment {
    pub id: Uuid,
    pub ticket_id: Uuid,
    pub author_id: String,
    pub author_name: String,
    pub author_type: String,
    pub content: String,
    pub is_internal: bool,
    pub attachments: Option<serde_json::Value>,
    pub created_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct SupportAgent {
    pub id: Uuid,
    pub user_id: String,
    pub name: String,
    pub email: String,
    pub team: Option<String>,
    pub role: Option<String>,
    pub max_tickets: i32,
    pub current_ticket_count: i32,
    pub specialties: Option<Vec<String>>,
    pub available: bool,
    pub last_assignment_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SupportMetrics {
    pub avg_first_response_minutes: f64,
    pub avg_resolution_minutes: f64,
    pub sla_compliance_rate: f64,
    pub satisfaction_avg: f64,
    pub total_tickets: i64,
    pub open_tickets: i64,
    pub tickets_by_priority: serde_json::Value,
    pub tickets_by_category: serde_json::Value,
}

/// SLA deadlines by priority:(first_response_minutes, resolution_minutes)
pub fn sla_deadlines(priority: &str) -> (i64, i64) {
    match priority {
        "critical" => (15, 240), // 15 min / 4 hours
        "high" => (60, 480), // 1 hr / 8 hours
        "medium" => (240, 1440), // 4 hr / 24 hours
        "low" => (480, 4320), // 8 hr / 72 hours
        _ => (240, 1440),
    }
}

// ── Template Approval types ────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TemplateApprovalStatus {
    Draft,
    Pending,
    Approved,
    Rejected,
    ChangesRequested,
}

impl std::fmt::Display for TemplateApprovalStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Draft => write!(f, "draft"),
            Self::Pending => write!(f, "pending"),
            Self::Approved => write!(f, "approved"),
            Self::Rejected => write!(f, "rejected"),
            Self::ChangesRequested => write!(f, "changes_requested"),
        }
    }
}

impl std::str::FromStr for TemplateApprovalStatus {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "draft" => Ok(Self::Draft),
            "pending" => Ok(Self::Pending),
            "approved" => Ok(Self::Approved),
            "rejected" => Ok(Self::Rejected),
            "changes_requested" => Ok(Self::ChangesRequested),
            _ => Err(format!("Unknown status: {s}")),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct TemplateSubmission {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub html_content: String,
    pub text_content: Option<String>,
    pub subject: String,
    pub status: String,
    pub submitted_by: String,
    pub reviewed_by: Option<String>,
    pub review_notes: Option<String>,
    pub spam_score: Option<f64>,
    pub spam_details: Option<serde_json::Value>,
    pub created_at: Option<DateTime<Utc>>,
    pub updated_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpamScoreResult {
    pub score: f64,
    pub details: Vec<SpamScoreDetail>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpamScoreDetail {
    pub rule: String,
    pub description: String,
    pub points: f64,
}

// ── White-label types ──────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DomainVerificationStatus {
    Pending,
    Verified,
    Failed,
    Expired,
}

impl std::fmt::Display for DomainVerificationStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pending => write!(f, "pending"),
            Self::Verified => write!(f, "verified"),
            Self::Failed => write!(f, "failed"),
            Self::Expired => write!(f, "expired"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DomainType {
    Tracking,
    ReturnPath,
    CustomFrom,
    LandingPage,
}

impl std::fmt::Display for DomainType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Tracking => write!(f, "tracking"),
            Self::ReturnPath => write!(f, "return_path"),
            Self::CustomFrom => write!(f, "custom_from"),
            Self::LandingPage => write!(f, "landing_page"),
        }
    }
}

impl std::str::FromStr for DomainType {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "tracking" => Ok(Self::Tracking),
            "return_path" => Ok(Self::ReturnPath),
            "custom_from" => Ok(Self::CustomFrom),
            "landing_page" => Ok(Self::LandingPage),
            _ => Err(format!("Unknown domain type: {s}")),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct WhiteLabelConfigRow {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub company_name: Option<String>,
    pub logo_url: Option<String>,
    pub primary_color: Option<String>,
    pub secondary_color: Option<String>,
    pub accent_color: Option<String>,
    pub font_family: Option<String>,
    pub custom_css: Option<String>,
    pub favicon_url: Option<String>,
    pub footer_text: Option<String>,
    pub support_email: Option<String>,
    pub support_url: Option<String>,
    pub privacy_url: Option<String>,
    pub terms_url: Option<String>,
    pub created_at: Option<DateTime<Utc>>,
    pub updated_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct WhiteLabelDomain {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub domain: String,
    pub domain_type: String,
    pub verification_status: String,
    pub verification_token: Option<String>,
    pub dns_records: Option<serde_json::Value>,
    pub verified_at: Option<DateTime<Utc>>,
    pub ssl_status: Option<String>,
    pub ssl_certificate_id: Option<String>,
    pub ssl_expires_at: Option<DateTime<Utc>>,
    pub created_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct WhiteLabelEmailTemplate {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub template_type: String,
    pub subject_template: Option<String>,
    pub html_template: Option<String>,
    pub text_template: Option<String>,
    pub created_at: Option<DateTime<Utc>>,
    pub updated_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DNSRecord {
    pub record_type: String,
    pub host: String,
    pub value: String,
    pub ttl: i32,
}

// ── QBR types ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum QBRStatus {
    Scheduled,
    DataGathering,
    Generating,
    Review,
    Delivered,
    FeedbackReceived,
}

impl std::fmt::Display for QBRStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Scheduled => write!(f, "scheduled"),
            Self::DataGathering => write!(f, "data_gathering"),
            Self::Generating => write!(f, "generating"),
            Self::Review => write!(f, "review"),
            Self::Delivered => write!(f, "delivered"),
            Self::FeedbackReceived => write!(f, "feedback_received"),
        }
    }
}

impl std::str::FromStr for QBRStatus {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "scheduled" => Ok(Self::Scheduled),
            "data_gathering" => Ok(Self::DataGathering),
            "generating" => Ok(Self::Generating),
            "review" => Ok(Self::Review),
            "delivered" => Ok(Self::Delivered),
            "feedback_received" => Ok(Self::FeedbackReceived),
            _ => Err(format!("Unknown QBR status: {s}")),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum GoalStatus {
    NotStarted,
    InProgress,
    AtRisk,
    Completed,
    Cancelled,
}

impl std::fmt::Display for GoalStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotStarted => write!(f, "not_started"),
            Self::InProgress => write!(f, "in_progress"),
            Self::AtRisk => write!(f, "at_risk"),
            Self::Completed => write!(f, "completed"),
            Self::Cancelled => write!(f, "cancelled"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct QuarterlyBusinessReview {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub quarter: i32,
    pub year: i32,
    pub status: String,
    pub scheduled_date: Option<NaiveDate>,
    pub delivered_date: Option<DateTime<Utc>>,
    pub attendees: Option<serde_json::Value>,
    pub metrics: Option<serde_json::Value>,
    pub insights: Option<serde_json::Value>,
    pub recommendations: Option<serde_json::Value>,
    pub highlights: Option<serde_json::Value>,
    pub concerns: Option<serde_json::Value>,
    pub goals: Option<serde_json::Value>,
    pub previous_qbr_id: Option<Uuid>,
    pub quarter_over_quarter_change: Option<serde_json::Value>,
    pub presentation_url: Option<String>,
    pub report_url: Option<String>,
    pub recording_url: Option<String>,
    pub feedback: Option<serde_json::Value>,
    pub action_items: Option<serde_json::Value>,
    pub created_at: Option<DateTime<Utc>>,
    pub updated_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct QBRGoal {
    pub id: Uuid,
    pub qbr_id: Uuid,
    pub title: String,
    pub category: Option<String>,
    pub target_metric: Option<String>,
    pub target_value: Option<f64>,
    pub current_value: Option<f64>,
    pub baseline_value: Option<f64>,
    pub unit: Option<String>,
    pub due_date: Option<NaiveDate>,
    pub status: String,
    pub progress_percent: Option<f64>,
    pub owner: Option<String>,
    pub created_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct IndustryBenchmark {
    pub id: Uuid,
    pub industry: String,
    pub metric_name: String,
    pub metric_value: f64,
    pub percentile_25: Option<f64>,
    pub percentile_50: Option<f64>,
    pub percentile_75: Option<f64>,
    pub percentile_90: Option<f64>,
    pub unit: Option<String>,
    pub period: Option<String>,
    pub source: Option<String>,
    pub valid_from: Option<NaiveDate>,
    pub valid_until: Option<NaiveDate>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QBRInsight {
    pub category: String,
    pub severity: String,
    pub message: String,
    pub metric_name: Option<String>,
    pub metric_value: Option<f64>,
    pub threshold: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchmarkComparison {
    pub metric_name: String,
    pub account_value: f64,
    pub industry_avg: f64,
    pub percentile_ranking: String,
    pub unit: String,
}

// ── Common API types ───────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiResult<T: Serialize> {
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
}

impl<T: Serialize> ApiResult<T> {
    pub fn ok(data: T) -> Self {
        Self { success: true, data: Some(data), error: None, code: None }
    }

    pub fn err(error: impl Into<String>, code: impl Into<String>) -> Self {
        Self { success: false, data: None, error: Some(error.into()), code: Some(code.into()) }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaginationParams {
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

impl PaginationParams {
    pub fn limit(&self) -> i64 { self.limit.unwrap_or(50).min(200) }
    pub fn offset(&self) -> i64 { self.offset.unwrap_or(0) }
}

// ── Tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compliance_framework_parse() {
        assert_eq!("hipaa".parse::<ComplianceFramework>().unwrap(), ComplianceFramework::Hipaa);
        assert_eq!("iso27001".parse::<ComplianceFramework>().unwrap(), ComplianceFramework::Iso27001);
        assert!("unknown".parse::<ComplianceFramework>().is_err());
    }

    #[test]
    fn test_stream_destination_parse() {
        assert_eq!("s3".parse::<StreamDestinationType>().unwrap(), StreamDestinationType::S3);
        assert_eq!("splunk".parse::<StreamDestinationType>().unwrap(), StreamDestinationType::Splunk);
        assert_eq!("sumo_logic".parse::<StreamDestinationType>().unwrap(), StreamDestinationType::SumoLogic);
    }

    #[test]
    fn test_deployment_type_round_trip() {
        let dt = DeploymentType::PrivateCloud;
        assert_eq!(dt.to_string(), "private_cloud");
        assert_eq!("private_cloud".parse::<DeploymentType>().unwrap(), dt);
    }

    #[test]
    fn test_ticket_priority_parse() {
        assert_eq!("p1".parse::<TicketPriority>().unwrap(), TicketPriority::Critical);
        assert_eq!("high".parse::<TicketPriority>().unwrap(), TicketPriority::High);
        assert_eq!("normal".parse::<TicketPriority>().unwrap(), TicketPriority::Medium);
    }

    #[test]
    fn test_ticket_category_parse() {
        assert_eq!("delivery".parse::<TicketCategory>().unwrap(), TicketCategory::Delivery);
        assert_eq!("feature_request".parse::<TicketCategory>().unwrap(), TicketCategory::FeatureRequest);
    }

    #[test]
    fn test_sla_deadlines() {
        let (fr, res) = sla_deadlines("critical");
        assert_eq!(fr, 15);
        assert_eq!(res, 240);
        let (fr, res) = sla_deadlines("low");
        assert_eq!(fr, 480);
        assert_eq!(res, 4320);
    }

    #[test]
    fn test_template_status_round_trip() {
        let s = TemplateApprovalStatus::ChangesRequested;
        assert_eq!(s.to_string(), "changes_requested");
        assert_eq!("changes_requested".parse::<TemplateApprovalStatus>().unwrap(), s);
    }

    #[test]
    fn test_qbr_status_round_trip() {
        let s = QBRStatus::DataGathering;
        assert_eq!(s.to_string(), "data_gathering");
        assert_eq!("data_gathering".parse::<QBRStatus>().unwrap(), s);
    }

    #[test]
    fn test_goal_status_display() {
        assert_eq!(GoalStatus::InProgress.to_string(), "in_progress");
        assert_eq!(GoalStatus::AtRisk.to_string(), "at_risk");
    }

    #[test]
    fn test_domain_type_round_trip() {
        let dt = DomainType::ReturnPath;
        assert_eq!(dt.to_string(), "return_path");
        assert_eq!("return_path".parse::<DomainType>().unwrap(), dt);
    }

    #[test]
    fn test_api_result_ok() {
        let r = ApiResult::ok("hello");
        assert!(r.success);
        assert_eq!(r.data, Some("hello"));
    }

    #[test]
    fn test_api_result_err() {
        let r: ApiResult<()> = ApiResult::err("not found", "NOT_FOUND");
        assert!(!r.success);
        assert_eq!(r.error.as_deref(), Some("not found"));
        assert_eq!(r.code.as_deref(), Some("NOT_FOUND"));
    }

    #[test]
    fn test_pagination_defaults() {
        let p = PaginationParams { limit: None, offset: None };
        assert_eq!(p.limit(), 50);
        assert_eq!(p.offset(), 0);
    }

    #[test]
    fn test_pagination_max_limit() {
        let p = PaginationParams { limit: Some(500), offset: Some(10) };
        assert_eq!(p.limit(), 200);
        assert_eq!(p.offset(), 10);
    }

    #[test]
    fn test_ip_warming_plan_serde() {
        let plan = IPWarmingPlan {
            days: vec![WarmingDay { day: 1, daily_limit: 50, description: "Ramp start".into() }],
            total_days: 30,
        };
        let json = serde_json::to_string(&plan).unwrap();
        let parsed: IPWarmingPlan = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.total_days, 30);
        assert_eq!(parsed.days[0].daily_limit, 50);
    }

    #[test]
    fn test_spam_score_result_serde() {
        let r = SpamScoreResult {
            score: 25.0,
            details: vec![SpamScoreDetail {
                rule: "caps".into(),
                description: "Too many caps".into(),
                points: 10.0,
            }],
        };
        let json = serde_json::to_string(&r).unwrap();
        let parsed: SpamScoreResult = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.score, 25.0);
        assert_eq!(parsed.details.len(), 1);
    }

    #[test]
    fn test_data_request_type_display() {
        assert_eq!(DataRequestType::Access.to_string(), "access");
        assert_eq!(DataRequestType::Deletion.to_string(), "deletion");
    }

    #[test]
    fn test_ip_status_display() {
        assert_eq!(IPStatus::Warming.to_string(), "warming");
        assert_eq!(IPStatus::Decommissioned.to_string(), "decommissioned");
    }

    #[test]
    fn test_sub_account_status_display() {
        assert_eq!(SubAccountStatus::Active.to_string(), "active");
        assert_eq!(SubAccountStatus::Deactivated.to_string(), "deactivated");
    }

    #[test]
    fn test_domain_verification_status_display() {
        assert_eq!(DomainVerificationStatus::Verified.to_string(), "verified");
        assert_eq!(DomainVerificationStatus::Expired.to_string(), "expired");
    }

    #[test]
    fn test_stream_status_display() {
        assert_eq!(StreamStatus::Active.to_string(), "active");
        assert_eq!(StreamStatus::Error.to_string(), "error");
    }

    #[test]
    fn test_compliance_status_display() {
        assert_eq!(ComplianceStatus::Active.to_string(), "active");
        assert_eq!(ComplianceStatus::Suspended.to_string(), "suspended");
    }

    #[test]
    fn test_benchmark_comparison_serde() {
        let b = BenchmarkComparison {
            metric_name: "delivery_rate".into(),
            account_value: 98.5,
            industry_avg: 95.0,
            percentile_ranking: "Top 10% performer".into(),
            unit: "percent".into(),
        };
        let json = serde_json::to_string(&b).unwrap();
        assert!(json.contains("delivery_rate"));
        let parsed: BenchmarkComparison = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.account_value, 98.5);
    }

    #[test]
    fn test_qbr_insight_serde() {
        let i = QBRInsight {
            category: "delivery".into(),
            severity: "warning".into(),
            message: "Rate below average".into(),
            metric_name: Some("delivery_rate".into()),
            metric_value: Some(93.5),
            threshold: Some(95.0),
        };
        let json = serde_json::to_value(&i).unwrap();
        assert_eq!(json["severity"], "warning");
    }

    #[test]
    fn test_deployment_status_display() {
        assert_eq!(DeploymentStatus::Provisioning.to_string(), "provisioning");
        assert_eq!(DeploymentStatus::Decommissioning.to_string(), "decommissioning");
    }
}
