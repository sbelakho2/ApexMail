use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ─── Risk Scoring ──────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

impl RiskLevel {
    pub fn from_score(score: f64) -> Self {
        if score >= 75.0 {
            Self::Critical
        } else if score >= 50.0 {
            Self::High
        } else if score >= 25.0 {
            Self::Medium
        } else {
            Self::Low
        }
    }

/// Multiplier applied to base sending limits.
    pub fn limit_multiplier(&self) -> f64 {
        match self {
            Self::Low => 1.0,
            Self::Medium => 0.75,
            Self::High => 0.5,
            Self::Critical => 0.1,
        }
    }

/// Reassessment interval in seconds.
    pub fn reassessment_secs(&self) -> i64 {
        match self {
            Self::Low => 86_400, // 24h
            Self::Medium => 21_600, // 6h
            Self::High => 3_600, // 1h
            Self::Critical => 900, // 15m
        }
    }
}

impl std::fmt::Display for RiskLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        };
        f.write_str(s)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskFactorType {
    SpamComplaints,
    BounceRate,
    PhishingDetection,
    ContentViolation,
    SendingPattern,
    AccountAge,
    VerificationStatus,
    PaymentHistory,
    ListQuality,
    EngagementRate,
    BlocklistListing,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskFactor {
    pub factor_type: RiskFactorType,
    pub score: f64,
    pub weight: f64,
    pub details: String,
    pub evidence: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskFlagType {
    HighBounceRate,
    SpamTrapHit,
    BlocklistDetected,
    UnusualSendingPattern,
    PhishingContent,
    MalwareAttachment,
    SuspendedAccount,
    PaymentFailed,
}

impl std::fmt::Display for RiskFlagType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::HighBounceRate => "high_bounce_rate",
            Self::SpamTrapHit => "spam_trap_hit",
            Self::BlocklistDetected => "blocklist_detected",
            Self::UnusualSendingPattern => "unusual_sending_pattern",
            Self::PhishingContent => "phishing_content",
            Self::MalwareAttachment => "malware_attachment",
            Self::SuspendedAccount => "suspended_account",
            Self::PaymentFailed => "payment_failed",
        };
        f.write_str(s)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskFlag {
    pub flag_type: RiskFlagType,
    pub severity: FlagSeverity,
    pub message: String,
    pub raised_at: DateTime<Utc>,
    pub resolved_at: Option<DateTime<Utc>>,
    pub auto_resolved: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FlagSeverity {
    Warning,
    Alert,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TenantLimits {
    pub max_daily_emails: i64,
    pub max_hourly_emails: i64,
    pub max_recipients: i64,
    pub max_attachment_size_mb: i64,
    pub require_double_opt_in: bool,
    pub require_unsubscribe_link: bool,
    pub allowed_domains: Vec<String>,
    pub blocked_recipient_patterns: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TenantRiskProfile {
    pub tenant_id: String,
    pub risk_score: f64,
    pub risk_level: RiskLevel,
    pub factors: Vec<RiskFactor>,
    pub limits: TenantLimits,
    pub flags: Vec<RiskFlag>,
    pub last_assessed_at: DateTime<Utc>,
    pub next_assessment_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

// ─── Content Scanning ──────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ScanVerdict {
    Clean,
    Suspicious,
    Blocked,
}

impl std::fmt::Display for ScanVerdict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Clean => f.write_str("clean"),
            Self::Suspicious => f.write_str("suspicious"),
            Self::Blocked => f.write_str("blocked"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContentScanResult {
    pub id: String,
    pub tenant_id: String,
    pub message_id: String,
    pub scanned_at: DateTime<Utc>,
    pub spam: SpamAnalysis,
    pub phishing: PhishingAnalysis,
    pub malware: MalwareAnalysis,
    pub policy: PolicyAnalysis,
    pub overall_verdict: ScanVerdict,
    pub actions: Vec<ContentAction>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpamAnalysis {
    pub score: f64,
    pub is_spam: bool,
    pub triggers: Vec<SpamTrigger>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpamTrigger {
    pub rule: String,
    pub score: f64,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PhishingAnalysis {
    pub score: f64,
    pub is_phishing: bool,
    pub indicators: Vec<PhishingIndicator>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PhishingIndicator {
    pub indicator_type: PhishingIndicatorType,
    pub indicator: String,
    pub confidence: f64,
    pub description: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PhishingIndicatorType {
    Url,
    Content,
    Sender,
    Attachment,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MalwareAnalysis {
    pub clean: bool,
    pub threats: Vec<MalwareThreat>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MalwareThreat {
    pub name: String,
    pub threat_type: String,
    pub severity: ThreatSeverity,
    pub location: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ThreatSeverity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyAnalysis {
    pub compliant: bool,
    pub violations: Vec<PolicyViolation>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyViolation {
    pub policy: String,
    pub rule: String,
    pub description: String,
    pub severity: ViolationSeverity,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ViolationSeverity {
    Warning,
    Error,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContentAction {
    pub action: ContentActionType,
    pub reason: String,
    pub applied_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ContentActionType {
    Allow,
    Quarantine,
    Reject,
    Modify,
}

/// Input payload for content scanning.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmailContent {
    pub tenant_id: String,
    pub message_id: String,
    pub from_address: String,
    pub from_display_name: Option<String>,
    pub subject: String,
    pub text_body: Option<String>,
    pub html_body: Option<String>,
    pub headers: HashMap<String, String>,
    pub attachments: Vec<AttachmentInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttachmentInfo {
    pub filename: String,
    pub content_type: String,
    pub size: usize,
/// First 16 bytes for magic-byte detection (base64 if transmitted).
    pub header_bytes: Option<Vec<u8>>,
}

// ─── Audit Logging ─────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AuditAction {
    Create,
    Read,
    Update,
    Delete,
    Login,
    Logout,
    Export,
    Import,
    Send,
    Receive,
    Configure,
    Approve,
    Reject,
    Escalate,
}

impl std::fmt::Display for AuditAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::Create => "create",
            Self::Read => "read",
            Self::Update => "update",
            Self::Delete => "delete",
            Self::Login => "login",
            Self::Logout => "logout",
            Self::Export => "export",
            Self::Import => "import",
            Self::Send => "send",
            Self::Receive => "receive",
            Self::Configure => "configure",
            Self::Approve => "approve",
            Self::Reject => "reject",
            Self::Escalate => "escalate",
        };
        f.write_str(s)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditResource {
    Tenant,
    User,
    Domain,
    ApiKey,
    Message,
    Campaign,
    List,
    Subscriber,
    Template,
    Webhook,
    Settings,
    Billing,
    Consent,
}

impl std::fmt::Display for AuditResource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::Tenant => "tenant",
            Self::User => "user",
            Self::Domain => "domain",
            Self::ApiKey => "api_key",
            Self::Message => "message",
            Self::Campaign => "campaign",
            Self::List => "list",
            Self::Subscriber => "subscriber",
            Self::Template => "template",
            Self::Webhook => "webhook",
            Self::Settings => "settings",
            Self::Billing => "billing",
            Self::Consent => "consent",
        };
        f.write_str(s)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditLogEntry {
    pub id: String,
    pub tenant_id: Option<String>,
    pub user_id: Option<String>,
    pub session_id: Option<String>,
    pub action: AuditAction,
    pub resource: AuditResource,
    pub resource_id: Option<String>,
    pub details: serde_json::Value,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub outcome: AuditOutcome,
    pub error_message: Option<String>,
    pub timestamp: DateTime<Utc>,
    pub hash: String,
    pub previous_hash: Option<String>,
    pub signature: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AuditOutcome {
    Success,
    Failure,
}

impl std::fmt::Display for AuditOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Success => f.write_str("success"),
            Self::Failure => f.write_str("failure"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AuditLogQuery {
    pub tenant_id: Option<String>,
    pub user_id: Option<String>,
    pub action: Option<AuditAction>,
    pub resource: Option<AuditResource>,
    pub resource_id: Option<String>,
    pub start_date: Option<DateTime<Utc>>,
    pub end_date: Option<DateTime<Utc>>,
    pub outcome: Option<AuditOutcome>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogContext {
    pub tenant_id: Option<String>,
    pub user_id: Option<String>,
    pub session_id: Option<String>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainValidationResult {
    pub valid: bool,
    pub entries_checked: usize,
    pub first_invalid_entry: Option<String>,
    pub error: Option<String>,
}

// ─── GDPR / Privacy ───────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConsentType {
    Marketing,
    Transactional,
    Analytics,
    Profiling,
    ThirdParty,
    DataProcessing,
}

impl std::fmt::Display for ConsentType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::Marketing => "marketing",
            Self::Transactional => "transactional",
            Self::Analytics => "analytics",
            Self::Profiling => "profiling",
            Self::ThirdParty => "third_party",
            Self::DataProcessing => "data_processing",
        };
        f.write_str(s)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConsentSource {
    Form,
    Api,
    Import,
    DoubleOptIn,
    PreferenceCenter,
    System,
}

impl std::fmt::Display for ConsentSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::Form => "form",
            Self::Api => "api",
            Self::Import => "import",
            Self::DoubleOptIn => "double_opt_in",
            Self::PreferenceCenter => "preference_center",
            Self::System => "system",
        };
        f.write_str(s)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DataSubjectRequestType {
    Access,
    Rectification,
    Erasure,
    Portability,
    Restriction,
    Objection,
}

impl std::fmt::Display for DataSubjectRequestType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::Access => "access",
            Self::Rectification => "rectification",
            Self::Erasure => "erasure",
            Self::Portability => "portability",
            Self::Restriction => "restriction",
            Self::Objection => "objection",
        };
        f.write_str(s)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RequestStatus {
    PendingVerification,
    Verified,
    Processing,
    Completed,
    Rejected,
    Expired,
}

impl std::fmt::Display for RequestStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::PendingVerification => "pending_verification",
            Self::Verified => "verified",
            Self::Processing => "processing",
            Self::Completed => "completed",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
        };
        f.write_str(s)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsentRecord {
    pub id: String,
    pub tenant_id: String,
    pub subscriber_id: String,
    pub email: String,
    pub consent_type: ConsentType,
    pub granted: bool,
    pub granted_at: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub source: ConsentSource,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub proof_document: Option<String>,
    pub expires_at: Option<DateTime<Utc>>,
    pub metadata: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataSubjectRequest {
    pub id: String,
    pub tenant_id: String,
    pub request_type: DataSubjectRequestType,
    pub email: String,
    pub verification_token_hash: String,
    pub verified: bool,
    pub verified_at: Option<DateTime<Utc>>,
    pub status: RequestStatus,
    pub requested_at: DateTime<Utc>,
    pub processed_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
    pub expires_at: DateTime<Utc>,
    pub result: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataSubjectRequestResult {
    pub data: Option<serde_json::Value>,
    pub export_url: Option<String>,
    pub export_expires_at: Option<DateTime<Utc>>,
    pub deleted_records: Option<i64>,
    pub deletion_confirmation: Option<serde_json::Value>,
    pub modified_records: Option<i64>,
    pub rejection_reason: Option<String>,
}

// ─── Secret Management ─────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretType {
    ApiKey,
    SmtpPassword,
    WebhookSecret,
    EncryptionKey,
    OauthToken,
    Certificate,
}

impl std::fmt::Display for SecretType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::ApiKey => "api_key",
            Self::SmtpPassword => "smtp_password",
            Self::WebhookSecret => "webhook_secret",
            Self::EncryptionKey => "encryption_key",
            Self::OauthToken => "oauth_token",
            Self::Certificate => "certificate",
        };
        f.write_str(s)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Secret {
    pub id: String,
    pub tenant_id: String,
    pub name: String,
    pub secret_type: SecretType,
    pub encrypted_value: String,
    pub version: i32,
    pub rotation_schedule: Option<RotationSchedule>,
    pub last_rotated_at: Option<DateTime<Utc>>,
    pub next_rotation_at: Option<DateTime<Utc>>,
    pub created_by: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RotationSchedule {
    pub interval_days: i64,
    pub auto_rotate: bool,
    pub notify_before_days: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretAccess {
    pub id: String,
    pub secret_id: String,
    pub user_id: String,
    pub access_type: AccessLevel,
    pub granted_by: String,
    pub granted_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AccessLevel {
    Read,
    Write,
    Admin,
}

impl AccessLevel {
    pub fn level(&self) -> u8 {
        match self {
            Self::Read => 1,
            Self::Write => 2,
            Self::Admin => 3,
        }
    }
}

impl std::fmt::Display for AccessLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Read => f.write_str("read"),
            Self::Write => f.write_str("write"),
            Self::Admin => f.write_str("admin"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretCreateInput {
    pub tenant_id: String,
    pub name: String,
    pub secret_type: SecretType,
    pub value: Option<String>,
    pub created_by: String,
    pub rotation_schedule: Option<RotationSchedule>,
    pub expires_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretUpdateInput {
    pub name: Option<String>,
    pub rotation_schedule: Option<RotationSchedule>,
    pub expires_at: Option<DateTime<Utc>>,
}

// ─── Abuse (type-only, for routes/risk) ────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AbuseReportType {
    Spam,
    Phishing,
    Malware,
    Harassment,
    Fraud,
    Impersonation,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_risk_level_from_score() {
        assert_eq!(RiskLevel::from_score(0.0), RiskLevel::Low);
        assert_eq!(RiskLevel::from_score(24.9), RiskLevel::Low);
        assert_eq!(RiskLevel::from_score(25.0), RiskLevel::Medium);
        assert_eq!(RiskLevel::from_score(49.9), RiskLevel::Medium);
        assert_eq!(RiskLevel::from_score(50.0), RiskLevel::High);
        assert_eq!(RiskLevel::from_score(74.9), RiskLevel::High);
        assert_eq!(RiskLevel::from_score(75.0), RiskLevel::Critical);
        assert_eq!(RiskLevel::from_score(100.0), RiskLevel::Critical);
    }

    #[test]
    fn test_risk_level_multiplier() {
        assert_eq!(RiskLevel::Low.limit_multiplier(), 1.0);
        assert_eq!(RiskLevel::Critical.limit_multiplier(), 0.1);
    }

    #[test]
    fn test_access_level_ordering() {
        assert!(AccessLevel::Admin > AccessLevel::Write);
        assert!(AccessLevel::Write > AccessLevel::Read);
        assert_eq!(AccessLevel::Admin.level(), 3);
    }

    #[test]
    fn test_scan_verdict_display() {
        assert_eq!(ScanVerdict::Clean.to_string(), "clean");
        assert_eq!(ScanVerdict::Blocked.to_string(), "blocked");
    }

    #[test]
    fn test_consent_type_display() {
        assert_eq!(ConsentType::Marketing.to_string(), "marketing");
        assert_eq!(ConsentType::ThirdParty.to_string(), "third_party");
    }

    #[test]
    fn test_request_status_display() {
        assert_eq!(
            RequestStatus::PendingVerification.to_string(),
            "pending_verification"
        );
        assert_eq!(RequestStatus::Completed.to_string(), "completed");
    }

    #[test]
    fn test_audit_action_display() {
        assert_eq!(AuditAction::Create.to_string(), "create");
        assert_eq!(AuditAction::Escalate.to_string(), "escalate");
    }

    #[test]
    fn test_secret_type_display() {
        assert_eq!(SecretType::ApiKey.to_string(), "api_key");
        assert_eq!(SecretType::WebhookSecret.to_string(), "webhook_secret");
    }
}
