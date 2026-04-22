//! Domain types for the Isolation service.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fmt;

use crate::config::{IsolationLevel, QuotaConfig};

// ── Tenant Status ──────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TenantStatus {
    Pending,
    Active,
    Suspended,
    Deactivated,
    Deleted,
}

impl fmt::Display for TenantStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Pending => write!(f, "pending"),
            Self::Active => write!(f, "active"),
            Self::Suspended => write!(f, "suspended"),
            Self::Deactivated => write!(f, "deactivated"),
            Self::Deleted => write!(f, "deleted"),
        }
    }
}

impl TenantStatus {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "pending" => Some(Self::Pending),
            "active" => Some(Self::Active),
            "suspended" => Some(Self::Suspended),
            "deactivated" => Some(Self::Deactivated),
            "deleted" => Some(Self::Deleted),
            _ => None,
        }
    }
}

// ── Tenant Role ────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TenantRole {
    Owner,
    Admin,
    Member,
    Viewer,
}

impl fmt::Display for TenantRole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Owner => write!(f, "owner"),
            Self::Admin => write!(f, "admin"),
            Self::Member => write!(f, "member"),
            Self::Viewer => write!(f, "viewer"),
        }
    }
}

impl TenantRole {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "owner" => Some(Self::Owner),
            "admin" => Some(Self::Admin),
            "member" => Some(Self::Member),
            "viewer" | "readonly" => Some(Self::Viewer),
            _ => None,
        }
    }
}

// ── Organization ───────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrgSettings {
    pub default_workspace_quota: QuotaConfig,
    pub sso_enabled: bool,
    pub sso_provider: Option<String>,
    pub sso_config: Option<serde_json::Value>,
    pub enforce_mfa: bool,
    pub allowed_domains: Vec<String>,
    pub ip_whitelist: Vec<String>,
    pub data_retention_days: i64,
    pub audit_log_enabled: bool,
}

impl Default for OrgSettings {
    fn default() -> Self {
        Self {
            default_workspace_quota: QuotaConfig::default(),
            sso_enabled: false,
            sso_provider: None,
            sso_config: None,
            enforce_mfa: false,
            allowed_domains: vec![],
            ip_whitelist: vec![],
            data_retention_days: 365,
            audit_log_enabled: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Organization {
    pub id: String,
    pub name: String,
    pub slug: String,
    pub billing_email: String,
    pub plan: String,
    pub status: TenantStatus,
    pub isolation_level: IsolationLevel,
    pub schema_name: Option<String>,
    pub database_name: Option<String>,
    pub owner_id: String,
    pub metadata: serde_json::Value,
    pub settings: OrgSettings,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

// ── Workspace ──────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct WorkspaceUsage {
    pub emails_sent_this_month: i64,
    pub storage_used_bytes: i64,
    pub api_requests_this_minute: i64,
    pub webhooks_sent_this_month: i64,
    pub contacts_count: i64,
    pub templates_count: i64,
    pub domains_count: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkspaceSettings {
    pub timezone: String,
    pub locale: String,
    pub default_from_email: Option<String>,
    pub default_from_name: Option<String>,
    pub track_opens: bool,
    pub track_clicks: bool,
    pub custom_branding: bool,
    pub webhook_enabled: bool,
}

impl Default for WorkspaceSettings {
    fn default() -> Self {
        Self {
            timezone: "UTC".into(),
            locale: "en-US".into(),
            default_from_email: None,
            default_from_name: None,
            track_opens: true,
            track_clicks: true,
            custom_branding: false,
            webhook_enabled: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Workspace {
    pub id: String,
    pub organization_id: String,
    pub name: String,
    pub slug: String,
    pub status: TenantStatus,
    pub schema_name: Option<String>,
    pub database_name: Option<String>,
    pub quota: QuotaConfig,
    pub usage: WorkspaceUsage,
    pub settings: WorkspaceSettings,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

// ── Tenant User ────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TenantUser {
    pub id: String,
    pub organization_id: String,
    pub workspace_ids: Vec<String>,
    pub email: String,
    pub role: TenantRole,
    pub status: TenantStatus,
    pub permissions: Vec<String>,
    pub last_active_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

// ── Isolation Context ──────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IsolationContext {
    pub organization_id: String,
    pub workspace_id: String,
    pub user_id: String,
    pub isolation_level: IsolationLevel,
    pub schema_name: Option<String>,
    pub permissions: Vec<String>,
}

// ── Data Access Policy ─────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataAccessPolicy {
    pub id: String,
    pub name: String,
    pub resource: String,
    pub conditions: Vec<PolicyCondition>,
    pub actions: Vec<String>, // "read", "write", "delete"
    pub effect: PolicyEffect,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyEffect {
    Allow,
    Deny,
}

impl PolicyEffect {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "allow" => Some(Self::Allow),
            "deny" => Some(Self::Deny),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyCondition {
    pub field: String,
    pub operator: ConditionOperator,
    pub value: serde_json::Value,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConditionOperator {
    Equals,
    NotEquals,
    In,
    NotIn,
    Contains,
    StartsWith,
}

// ── Encryption ─────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptionKey {
    pub id: String,
    pub organization_id: String,
    pub version: i32,
    pub algorithm: String,
    pub encrypted_key: String,
    pub status: KeyStatus,
    pub created_at: DateTime<Utc>,
    pub rotated_at: Option<DateTime<Utc>>,
    pub expires_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyStatus {
    Active,
    Rotating,
    Retired,
}

impl fmt::Display for KeyStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Active => write!(f, "active"),
            Self::Rotating => write!(f, "rotating"),
            Self::Retired => write!(f, "retired"),
        }
    }
}

impl KeyStatus {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "active" => Some(Self::Active),
            "rotating" => Some(Self::Rotating),
            "retired" => Some(Self::Retired),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedField {
    pub ciphertext: String,
    pub key_id: String,
    pub algorithm: String,
    pub iv: String,
    pub auth_tag: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptionPolicy {
    pub id: String,
    pub name: String,
    pub resource: String,
    pub fields: Vec<String>,
    pub algorithm: String,
    pub key_rotation_days: i64,
    pub enabled: bool,
}

// ── Rate Limit ─────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitConfig {
    pub window_ms: i64,
    pub max_requests: i64,
    pub burst_limit: Option<i64>,
    pub key_prefix: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitResult {
    pub allowed: bool,
    pub remaining: i64,
    pub reset_at: DateTime<Utc>,
    pub retry_after: Option<i64>,
    pub limit: i64,
}

#[derive(Debug, Clone)]
pub struct TokenBucketConfig {
    pub capacity: i64,
    pub refill_rate: f64,
    pub refill_interval_ms: i64,
}

// ── Audit ──────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuditEventType {
// Auth
    AuthLogin,
    AuthLogout,
    AuthFailed,
    AuthMfaEnabled,
    AuthMfaDisabled,
    AuthPasswordChanged,
    AuthApiKeyCreated,
    AuthApiKeyRevoked,
// Org
    OrgCreated,
    OrgUpdated,
    OrgSuspended,
    OrgReactivated,
    OrgDeleted,
// Workspace
    WorkspaceCreated,
    WorkspaceUpdated,
    WorkspaceDeleted,
// Member
    MemberInvited,
    MemberAdded,
    MemberRemoved,
    MemberRoleChanged,
// Data
    DataCreated,
    DataRead,
    DataUpdated,
    DataDeleted,
    DataExported,
    DataImported,
// Security
    SecurityPermissionGranted,
    SecurityPermissionRevoked,
    SecurityAccessDenied,
    SecuritySuspiciousActivity,
    SecurityRateLimited,
// Billing
    BillingPlanChanged,
    BillingPaymentSuccess,
    BillingPaymentFailed,
// Email
    EmailSent,
    EmailFailed,
    EmailBounced,
    EmailComplained,
// Settings
    SettingsChanged,
    WebhookConfigured,
    DomainAdded,
    DomainVerified,
    DomainRemoved,
}

impl fmt::Display for AuditEventType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::AuthLogin => "AUTH_LOGIN",
            Self::AuthLogout => "AUTH_LOGOUT",
            Self::AuthFailed => "AUTH_FAILED",
            Self::AuthMfaEnabled => "AUTH_MFA_ENABLED",
            Self::AuthMfaDisabled => "AUTH_MFA_DISABLED",
            Self::AuthPasswordChanged => "AUTH_PASSWORD_CHANGED",
            Self::AuthApiKeyCreated => "AUTH_API_KEY_CREATED",
            Self::AuthApiKeyRevoked => "AUTH_API_KEY_REVOKED",
            Self::OrgCreated => "ORG_CREATED",
            Self::OrgUpdated => "ORG_UPDATED",
            Self::OrgSuspended => "ORG_SUSPENDED",
            Self::OrgReactivated => "ORG_REACTIVATED",
            Self::OrgDeleted => "ORG_DELETED",
            Self::WorkspaceCreated => "WORKSPACE_CREATED",
            Self::WorkspaceUpdated => "WORKSPACE_UPDATED",
            Self::WorkspaceDeleted => "WORKSPACE_DELETED",
            Self::MemberInvited => "MEMBER_INVITED",
            Self::MemberAdded => "MEMBER_ADDED",
            Self::MemberRemoved => "MEMBER_REMOVED",
            Self::MemberRoleChanged => "MEMBER_ROLE_CHANGED",
            Self::DataCreated => "DATA_CREATED",
            Self::DataRead => "DATA_READ",
            Self::DataUpdated => "DATA_UPDATED",
            Self::DataDeleted => "DATA_DELETED",
            Self::DataExported => "DATA_EXPORTED",
            Self::DataImported => "DATA_IMPORTED",
            Self::SecurityPermissionGranted => "SECURITY_PERMISSION_GRANTED",
            Self::SecurityPermissionRevoked => "SECURITY_PERMISSION_REVOKED",
            Self::SecurityAccessDenied => "SECURITY_ACCESS_DENIED",
            Self::SecuritySuspiciousActivity => "SECURITY_SUSPICIOUS_ACTIVITY",
            Self::SecurityRateLimited => "SECURITY_RATE_LIMITED",
            Self::BillingPlanChanged => "BILLING_PLAN_CHANGED",
            Self::BillingPaymentSuccess => "BILLING_PAYMENT_SUCCESS",
            Self::BillingPaymentFailed => "BILLING_PAYMENT_FAILED",
            Self::EmailSent => "EMAIL_SENT",
            Self::EmailFailed => "EMAIL_FAILED",
            Self::EmailBounced => "EMAIL_BOUNCED",
            Self::EmailComplained => "EMAIL_COMPLAINED",
            Self::SettingsChanged => "SETTINGS_CHANGED",
            Self::WebhookConfigured => "WEBHOOK_CONFIGURED",
            Self::DomainAdded => "DOMAIN_ADDED",
            Self::DomainVerified => "DOMAIN_VERIFIED",
            Self::DomainRemoved => "DOMAIN_REMOVED",
        };
        write!(f, "{}", s)
    }
}

impl AuditEventType {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "AUTH_LOGIN" => Some(Self::AuthLogin),
            "AUTH_LOGOUT" => Some(Self::AuthLogout),
            "AUTH_FAILED" => Some(Self::AuthFailed),
            "AUTH_MFA_ENABLED" => Some(Self::AuthMfaEnabled),
            "AUTH_MFA_DISABLED" => Some(Self::AuthMfaDisabled),
            "AUTH_PASSWORD_CHANGED" => Some(Self::AuthPasswordChanged),
            "AUTH_API_KEY_CREATED" => Some(Self::AuthApiKeyCreated),
            "AUTH_API_KEY_REVOKED" => Some(Self::AuthApiKeyRevoked),
            "ORG_CREATED" => Some(Self::OrgCreated),
            "ORG_UPDATED" => Some(Self::OrgUpdated),
            "ORG_SUSPENDED" => Some(Self::OrgSuspended),
            "ORG_REACTIVATED" => Some(Self::OrgReactivated),
            "ORG_DELETED" => Some(Self::OrgDeleted),
            "WORKSPACE_CREATED" => Some(Self::WorkspaceCreated),
            "WORKSPACE_UPDATED" => Some(Self::WorkspaceUpdated),
            "WORKSPACE_DELETED" => Some(Self::WorkspaceDeleted),
            "MEMBER_INVITED" => Some(Self::MemberInvited),
            "MEMBER_ADDED" => Some(Self::MemberAdded),
            "MEMBER_REMOVED" => Some(Self::MemberRemoved),
            "MEMBER_ROLE_CHANGED" => Some(Self::MemberRoleChanged),
            "DATA_CREATED" => Some(Self::DataCreated),
            "DATA_READ" => Some(Self::DataRead),
            "DATA_UPDATED" => Some(Self::DataUpdated),
            "DATA_DELETED" => Some(Self::DataDeleted),
            "DATA_EXPORTED" => Some(Self::DataExported),
            "DATA_IMPORTED" => Some(Self::DataImported),
            "SECURITY_PERMISSION_GRANTED" => Some(Self::SecurityPermissionGranted),
            "SECURITY_PERMISSION_REVOKED" => Some(Self::SecurityPermissionRevoked),
            "SECURITY_ACCESS_DENIED" => Some(Self::SecurityAccessDenied),
            "SECURITY_SUSPICIOUS_ACTIVITY" => Some(Self::SecuritySuspiciousActivity),
            "SECURITY_RATE_LIMITED" => Some(Self::SecurityRateLimited),
            "BILLING_PLAN_CHANGED" => Some(Self::BillingPlanChanged),
            "BILLING_PAYMENT_SUCCESS" => Some(Self::BillingPaymentSuccess),
            "BILLING_PAYMENT_FAILED" => Some(Self::BillingPaymentFailed),
            "EMAIL_SENT" => Some(Self::EmailSent),
            "EMAIL_FAILED" => Some(Self::EmailFailed),
            "EMAIL_BOUNCED" => Some(Self::EmailBounced),
            "EMAIL_COMPLAINED" => Some(Self::EmailComplained),
            "SETTINGS_CHANGED" => Some(Self::SettingsChanged),
            "WEBHOOK_CONFIGURED" => Some(Self::WebhookConfigured),
            "DOMAIN_ADDED" => Some(Self::DomainAdded),
            "DOMAIN_VERIFIED" => Some(Self::DomainVerified),
            "DOMAIN_REMOVED" => Some(Self::DomainRemoved),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditSeverity {
    Info,
    Warning,
    Critical,
}

impl fmt::Display for AuditSeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Info => write!(f, "info"),
            Self::Warning => write!(f, "warning"),
            Self::Critical => write!(f, "critical"),
        }
    }
}

impl AuditSeverity {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "info" | "INFO" => Some(Self::Info),
            "warning" | "WARNING" => Some(Self::Warning),
            "critical" | "CRITICAL" => Some(Self::Critical),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    pub id: String,
    pub organization_id: String,
    pub workspace_id: Option<String>,
    pub event_type: AuditEventType,
    pub severity: AuditSeverity,
    pub actor_id: String,
    pub actor_type: String, // "user", "system", "api_key"
    pub actor_ip: Option<String>,
    pub actor_user_agent: Option<String>,
    pub resource: Option<String>,
    pub resource_id: Option<String>,
    pub action: String,
    pub details: serde_json::Value,
    pub metadata: serde_json::Value,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AuditQuery {
    pub organization_id: String,
    pub workspace_id: Option<String>,
    pub types: Option<Vec<String>>,
    pub severity: Option<String>,
    pub actor_id: Option<String>,
    pub resource: Option<String>,
    pub start_time: Option<DateTime<Utc>>,
    pub end_time: Option<DateTime<Utc>>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

// ── Member Access ──────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemberAccess {
    pub has_access: bool,
    pub role: Option<TenantRole>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tenant_status_roundtrip() {
        let statuses = vec![
            TenantStatus::Pending,
            TenantStatus::Active,
            TenantStatus::Suspended,
            TenantStatus::Deactivated,
            TenantStatus::Deleted,
        ];
        for s in statuses {
            let name = s.to_string();
            assert_eq!(TenantStatus::parse(&name), Some(s));
        }
    }

    #[test]
    fn test_tenant_role_roundtrip() {
        assert_eq!(TenantRole::parse("owner"), Some(TenantRole::Owner));
        assert_eq!(TenantRole::parse("viewer"), Some(TenantRole::Viewer));
        assert_eq!(TenantRole::parse("readonly"), Some(TenantRole::Viewer));
        assert!(TenantRole::parse("unknown").is_none());
    }

    #[test]
    fn test_audit_event_type_roundtrip() {
        let events = vec![
            AuditEventType::AuthLogin,
            AuditEventType::OrgCreated,
            AuditEventType::WorkspaceDeleted,
            AuditEventType::SecurityAccessDenied,
            AuditEventType::EmailSent,
        ];
        for e in events {
            let name = e.to_string();
            assert_eq!(AuditEventType::parse(&name), Some(e));
        }
    }

    #[test]
    fn test_audit_severity_parse() {
        assert_eq!(AuditSeverity::parse("info"), Some(AuditSeverity::Info));
        assert_eq!(AuditSeverity::parse("CRITICAL"), Some(AuditSeverity::Critical));
        assert!(AuditSeverity::parse("fatal").is_none());
    }

    #[test]
    fn test_key_status_roundtrip() {
        assert_eq!(KeyStatus::parse("active"), Some(KeyStatus::Active));
        assert_eq!(KeyStatus::parse("rotating"), Some(KeyStatus::Rotating));
        assert_eq!(KeyStatus::parse("retired"), Some(KeyStatus::Retired));
    }

    #[test]
    fn test_policy_effect_parse() {
        assert_eq!(PolicyEffect::parse("allow"), Some(PolicyEffect::Allow));
        assert_eq!(PolicyEffect::parse("deny"), Some(PolicyEffect::Deny));
        assert!(PolicyEffect::parse("maybe").is_none());
    }

    #[test]
    fn test_org_settings_default() {
        let s = OrgSettings::default();
        assert!(!s.sso_enabled);
        assert!(s.audit_log_enabled);
        assert_eq!(s.data_retention_days, 365);
    }

    #[test]
    fn test_workspace_settings_default() {
        let s = WorkspaceSettings::default();
        assert_eq!(s.timezone, "UTC");
        assert!(s.track_opens);
    }
}
