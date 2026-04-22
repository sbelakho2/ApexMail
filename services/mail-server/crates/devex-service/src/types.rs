//! Core domain types for the DevEx service.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

// ── SDK Language ─────────────────────────────────────────────────────────────

/// Supported SDK languages — mirrors the TS `SDK_LANGUAGES` constant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SdkLanguage {
    Go,
    Java,
    Node,
    #[serde(rename = "php")]
    Php,
    Python,
    Ruby,
}

impl SdkLanguage {
/// Human-readable display name.
    pub fn display_name(&self) -> &'static str {
        match self {
            Self::Go => "Go",
            Self::Java => "Java",
            Self::Node => "Node.js / TypeScript",
            Self::Php => "PHP",
            Self::Python => "Python",
            Self::Ruby => "Ruby",
        }
    }

/// Primary package manager for this language.
    pub fn package_manager(&self) -> &'static str {
        match self {
            Self::Go => "go mod",
            Self::Java => "maven",
            Self::Node => "npm",
            Self::Php => "composer",
            Self::Python => "pip",
            Self::Ruby => "gem",
        }
    }

/// All supported SDK languages.
    pub fn all() -> &'static [SdkLanguage] {
        &[
            Self::Go,
            Self::Java,
            Self::Node,
            Self::Php,
            Self::Python,
            Self::Ruby,
        ]
    }
}

impl std::fmt::Display for SdkLanguage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::Go => "go",
            Self::Java => "java",
            Self::Node => "node",
            Self::Php => "php",
            Self::Python => "python",
            Self::Ruby => "ruby",
        };
        f.write_str(s)
    }
}

impl std::str::FromStr for SdkLanguage {
    type Err = DevExError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "go" => Ok(Self::Go),
            "java" => Ok(Self::Java),
            "node" | "typescript" | "javascript" => Ok(Self::Node),
            "php" => Ok(Self::Php),
            "python" => Ok(Self::Python),
            "ruby" => Ok(Self::Ruby),
            _ => Err(DevExError::UnsupportedLanguage(s.to_string())),
        }
    }
}

// ── API Version ──────────────────────────────────────────────────────────────

/// Status of an API version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum VersionStatus {
    Current,
    Supported,
    Deprecated,
    Sunset,
}

impl std::fmt::Display for VersionStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::Current => "current",
            Self::Supported => "supported",
            Self::Deprecated => "deprecated",
            Self::Sunset => "sunset",
        };
        f.write_str(s)
    }
}

/// Describes a single API version.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiVersion {
    pub version: String,
    pub release_date: DateTime<Utc>,
    pub status: VersionStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sunset_date: Option<DateTime<Utc>>,
    pub changelog: Vec<ChangelogEntry>,
}

// ── Changelog ────────────────────────────────────────────────────────────────

/// Type of changelog entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ChangelogType {
    Added,
    Changed,
    Deprecated,
    Removed,
    Fixed,
    Security,
}

/// Single entry in a version changelog.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChangelogEntry {
    #[serde(rename = "type")]
    pub change_type: ChangelogType,
    pub description: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
    pub breaking: bool,
}

// ── SDK Info ─────────────────────────────────────────────────────────────────

/// Information about an SDK.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SdkInfo {
    pub language: SdkLanguage,
    pub package_name: String,
    pub latest_version: String,
    pub api_version: String,
    pub repository_url: String,
    pub install_command: String,
    pub min_runtime_version: String,
}

// ── Webhook Test Result ──────────────────────────────────────────────────────

/// Result of a webhook test invocation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookTestResult {
    pub id: String,
    pub url: String,
    pub success: bool,
    pub status_code: Option<u16>,
    pub response_body: Option<String>,
    pub latency_ms: u64,
    pub signature_valid: bool,
    pub timestamp: DateTime<Utc>,
}

// ── API Key Info ─────────────────────────────────────────────────────────────

/// Metadata about an API key (never contains the secret itself).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiKeyInfo {
    pub id: Uuid,
    pub name: String,
    pub prefix: String,
    pub scopes: Vec<String>,
    pub created_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_used_at: Option<DateTime<Utc>>,
    pub revoked: bool,
}

// ── CLI Command ──────────────────────────────────────────────────────────────

/// Option for a CLI command.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CliOption {
    pub flag: String,
    pub description: String,
    pub required: bool,
    #[serde(rename = "type")]
    pub value_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_value: Option<String>,
}

/// Describes a single CLI sub-command.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CliCommand {
    pub name: String,
    pub description: String,
    pub usage: String,
    pub options: Vec<CliOption>,
    pub examples: Vec<String>,
}

// ── Error ────────────────────────────────────────────────────────────────────

/// Service-level errors.
#[derive(Debug, thiserror::Error)]
pub enum DevExError {
    #[error("unsupported SDK language: {0}")]
    UnsupportedLanguage(String),
    #[error("version not found: {0}")]
    VersionNotFound(String),
    #[error("validation error: {0}")]
    Validation(String),
    #[error("webhook error: {0}")]
    WebhookError(String),
    #[error("openapi error: {0}")]
    OpenApiError(String),
    #[error("onboarding error: {0}")]
    OnboardingError(String),
    #[error("http error: {0}")]
    HttpError(#[from] reqwest::Error),
    #[error("serialization error: {0}")]
    SerdeError(#[from] serde_json::Error),
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sdk_language_roundtrip() {
        for lang in SdkLanguage::all() {
            let s = lang.to_string();
            let parsed: SdkLanguage = s.parse().unwrap();
            assert_eq!(*lang, parsed);
        }
    }

    #[test]
    fn test_sdk_language_from_aliases() {
        assert_eq!("typescript".parse::<SdkLanguage>().unwrap(), SdkLanguage::Node);
        assert_eq!("javascript".parse::<SdkLanguage>().unwrap(), SdkLanguage::Node);
        assert!("cobol".parse::<SdkLanguage>().is_err());
    }

    #[test]
    fn test_version_status_display() {
        assert_eq!(VersionStatus::Current.to_string(), "current");
        assert_eq!(VersionStatus::Sunset.to_string(), "sunset");
    }

    #[test]
    fn test_changelog_entry_serde() {
        let entry = ChangelogEntry {
            change_type: ChangelogType::Added,
            description: "Batch email endpoint".into(),
            endpoint: Some("POST /v1/emails/batch".into()),
            breaking: false,
        };
        let json = serde_json::to_string(&entry).unwrap();
        assert!(json.contains("\"type\":\"added\""));
        assert!(json.contains("\"breaking\":false"));

        let back: ChangelogEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(back.change_type, ChangelogType::Added);
        assert_eq!(back.endpoint.as_deref(), Some("POST /v1/emails/batch"));
    }
}
