use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Overall grade letter for an email/domain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum GradeLetter {
    #[serde(rename = "A+")]
    APlus,
    A,
    B,
    C,
    D,
    F,
}

impl GradeLetter {
    pub fn from_score(score: u16) -> Self {
        match score {
            90..=100 => GradeLetter::APlus,
            80..=89 => GradeLetter::A,
            70..=79 => GradeLetter::B,
            60..=69 => GradeLetter::C,
            40..=59 => GradeLetter::D,
            _ => GradeLetter::F,
        }
    }
}

impl std::fmt::Display for GradeLetter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GradeLetter::APlus => write!(f, "A+"),
            GradeLetter::A => write!(f, "A"),
            GradeLetter::B => write!(f, "B"),
            GradeLetter::C => write!(f, "C"),
            GradeLetter::D => write!(f, "D"),
            GradeLetter::F => write!(f, "F"),
        }
    }
}

/// Severity level for findings.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FindingSeverity {
    Critical,
    Error,
    Warning,
    Info,
}

/// A single finding or issue discovered during grading.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub severity: FindingSeverity,
    pub category: String,
    pub message: String,
}

/// Score breakdown for a single dimension.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScoreBreakdown {
    pub score: u16,
    pub max: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<serde_json::Value>,
}

/// Full score breakdown across all dimensions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GradeBreakdown {
    pub dns_health: ScoreBreakdown,
    pub authentication: ScoreBreakdown,
    pub spam_likelihood: ScoreBreakdown,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_quality: Option<ScoreBreakdown>,
    pub reputation: ScoreBreakdown,
}

/// Request body for domain-only check.
#[derive(Debug, Deserialize)]
pub struct DomainCheckRequest {
    pub domain: String,
    #[serde(default)]
    pub selectors: Vec<String>,
}

/// Request body for full email submission.
#[derive(Debug, Deserialize)]
pub struct EmailSubmitRequest {
    #[serde(default)]
    pub domain: Option<String>,
    #[serde(default)]
    pub from: Option<String>,
    #[serde(default)]
    pub to: Vec<String>,
    #[serde(default)]
    pub subject: Option<String>,
    #[serde(default)]
    pub body_text: Option<String>,
    #[serde(default)]
    pub body_html: Option<String>,
    #[serde(default)]
    pub headers: Option<HashMap<String, String>>,
    #[serde(default)]
    pub selectors: Vec<String>,
    /// Optional sender IP from the SMTP transaction. When supplied with
    /// `helo_hostname`, the grader runs real SPF/DKIM/DMARC message
    /// authentication instead of domain-readiness-only authentication.
    #[serde(default)]
    pub sender_ip: Option<String>,
    #[serde(default)]
    pub helo_hostname: Option<String>,
    #[serde(default)]
    pub mail_from: Option<String>,
}

/// Authenticated tenant context supplied by the API server middleware.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraderAuthContext {
    pub tenant_id: String,
    pub scopes: Vec<String>,
    /// Optional `Idempotency-Key` value supplied by the client. When present
    /// and a row with the same `(tenant_id, idempotency_key)` exists within
    /// the dedup window, the stored result is returned instead of running a
    /// fresh analysis.
    #[serde(default)]
    pub idempotency_key: Option<String>,
}

impl GraderAuthContext {
    pub fn has_scope(&self, required: &str) -> bool {
        self.scopes
            .iter()
            .any(|scope| scope == "*" || scope == required)
    }
}

/// Pagination query parameters.
#[derive(Debug, Deserialize)]
pub struct PaginationParams {
    pub page: Option<u32>,
    pub per_page: Option<u32>,
}

/// A stored grader result from the database.
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct GraderResultRow {
    pub id: uuid::Uuid,
    pub domain: String,
    pub score: i16,
    pub grade: String,
    pub breakdown: serde_json::Value,
    pub findings: serde_json::Value,
    pub recommendations: Vec<String>,
    pub created_at: DateTime<Utc>,
}

/// Full grader API response (internal use; never serialized to external clients).
#[derive(Debug, Clone, Serialize)]
pub struct GraderResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<uuid::Uuid>,
    pub domain: String,
    pub score: u16,
    pub grade: String,
    pub breakdown: GradeBreakdown,
    pub findings: Vec<Finding>,
    pub recommendations: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_at: Option<DateTime<Utc>>,
}

/// Safe grader API response exposed to external clients.
///
/// Deliberately omits `breakdown` and `findings` (which may contain
/// body-derived PII such as content analysis details, spam keyword matches,
/// or raw email excerpts) and exposes only aggregated, sanitised fields.
#[derive(Debug, Clone, Serialize)]
pub struct GraderResultResponse {
    pub id: uuid::Uuid,
    pub domain: String,
    pub score: u16,
    pub grade: String,
    pub recommendations: Vec<String>,
    pub created_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub idempotency_replayed: bool,
}

impl From<GraderResponse> for GraderResultResponse {
    fn from(r: GraderResponse) -> Self {
        Self {
            id: r.id.unwrap_or_else(uuid::Uuid::new_v4),
            domain: r.domain,
            score: r.score,
            grade: r.grade,
            recommendations: r.recommendations,
            created_at: r.created_at.unwrap_or_else(Utc::now),
            idempotency_replayed: false,
        }
    }
}
