//! Configuration for the edge-cases service.

use serde::{Deserialize, Serialize};

/// Top-level edge-cases configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EdgeCasesConfig {
    pub port: u16,
    pub database_url: String,
    pub redis_url: String,
    pub api_key: String,
    pub node_env: String,
    pub attachments: AttachmentLimits,
    pub retry: RetryConfig,
    pub loop_detection: LoopDetectionConfig,
    pub auto_responder: AutoResponderConfig,
    pub clamav: ClamAVConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttachmentLimits {
    pub max_single_size: usize,
    pub max_total_size: usize,
    pub max_count: usize,
    pub blocked_extensions: Vec<String>,
    pub blocked_mime_types: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetryConfig {
    pub max_retries: u32,
    pub initial_delay_secs: u64,
    pub max_delay_secs: u64,
    pub backoff_multiplier: f64,
    pub greylist_retry_delay_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoopDetectionConfig {
    pub max_hops: usize,
    pub max_received_headers: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutoResponderConfig {
    pub patterns: Vec<String>,
    pub header_indicators: Vec<String>,
    pub subject_patterns: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClamAVConfig {
    pub host: String,
    pub port: u16,
    pub timeout_secs: u64,
    pub enabled: bool,
}

// ── constants ──────────────────────────────────────────────────────────────────

pub const UNICODE_NORMALIZATION: &str = "NFC";
pub const BASE64_OVERHEAD: f64 = 1.37;
pub const SMTPUTF8_EXTENSION: &str = "SMTPUTF8";
pub const CALENDAR_CONTENT_TYPES: &[&str] = &["text/calendar", "application/ics"];
pub const GREYLIST_CODES: &[u16] = &[450, 451, 452, 421];
pub const AUTO_SUBMITTED_VALUES: &[&str] = &["auto-generated", "auto-replied", "auto-notified"];

pub const DEFAULT_BLOCKED_EXTENSIONS: &[&str] = &[
    ".exe", ".bat", ".cmd", ".com", ".dll", ".scr", ".pif", ".vbs", ".js", ".jar", ".msi", ".ps1",
    ".sh",
];

pub const DEFAULT_BLOCKED_MIME_TYPES: &[&str] = &[
    "application/x-msdownload",
    "application/x-executable",
    "application/x-dosexec",
];

// ── defaults ───────────────────────────────────────────────────────────────────

impl Default for AttachmentLimits {
    fn default() -> Self {
        Self {
            max_single_size: 25 * 1024 * 1024,
            max_total_size: 35 * 1024 * 1024,
            max_count: 20,
            blocked_extensions: DEFAULT_BLOCKED_EXTENSIONS.iter().map(|s| s.to_string()).collect(),
            blocked_mime_types: DEFAULT_BLOCKED_MIME_TYPES.iter().map(|s| s.to_string()).collect(),
        }
    }
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_retries: 3,
            initial_delay_secs: 1,
            max_delay_secs: 300,
            backoff_multiplier: 2.0,
            greylist_retry_delay_secs: 300,
        }
    }
}

impl Default for LoopDetectionConfig {
    fn default() -> Self {
        Self {
            max_hops: 25,
            max_received_headers: 30,
        }
    }
}

impl Default for AutoResponderConfig {
    fn default() -> Self {
        Self {
            patterns: vec![],
            header_indicators: vec![
                "Auto-Submitted".into(),
                "Precedence".into(),
                "X-Auto-Response-Suppress".into(),
                "X-Autorespond".into(),
                "X-Autoreply".into(),
            ],
            subject_patterns: vec![
                r"(?i)^out of office".into(),
                r"(?i)^automatic reply".into(),
                r"(?i)^auto:".into(),
                r"(?i)^auto-reply".into(),
                r"(?i)\bvacation\b".into(),
                r"(?i)\babsence\b".into(),
            ],
        }
    }
}

impl Default for ClamAVConfig {
    fn default() -> Self {
        Self {
            host: "localhost".into(),
            port: 3310,
            timeout_secs: 30,
            enabled: true,
        }
    }
}

impl Default for EdgeCasesConfig {
    fn default() -> Self {
        Self {
            port: 4600,
            database_url: String::new(),
            redis_url: "redis://127.0.0.1:6379".into(),
            api_key: String::new(),
            node_env: "development".into(),
            attachments: AttachmentLimits::default(),
            retry: RetryConfig::default(),
            loop_detection: LoopDetectionConfig::default(),
            auto_responder: AutoResponderConfig::default(),
            clamav: ClamAVConfig::default(),
        }
    }
}

impl EdgeCasesConfig {
    pub fn from_env() -> Result<Self, ConfigError> {
        let _ = dotenvy::dotenv();
        let node_env = std::env::var("NODE_ENV").unwrap_or_else(|_| "development".into());
        let api_key = std::env::var("INTERNAL_API_KEY").unwrap_or_default();
        if node_env != "development" && api_key.trim().is_empty() {
            return Err(ConfigError::SecurityViolation(
                "INTERNAL_API_KEY must be set outside development".into(),
            ));
        }
        Ok(Self {
            port: std::env::var("EDGE_CASES_PORT")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(4600),
            database_url: std::env::var("DATABASE_URL").unwrap_or_default(),
            redis_url: std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".into()),
            api_key,
            node_env,
            attachments: AttachmentLimits::default(),
            retry: RetryConfig::default(),
            loop_detection: LoopDetectionConfig::default(),
            auto_responder: AutoResponderConfig::default(),
            clamav: ClamAVConfig {
                host: std::env::var("CLAMAV_HOST").unwrap_or_else(|_| "localhost".into()),
                port: std::env::var("CLAMAV_PORT")
                    .ok()
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(3310),
                timeout_secs: 30,
                enabled: std::env::var("CLAMAV_ENABLED")
                    .map(|v| v != "false" && v != "0")
                    .unwrap_or(true),
            },
        })
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("security violation: {0}")]
    SecurityViolation(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_defaults() {
        let cfg = EdgeCasesConfig::default();
        assert_eq!(cfg.port, 4600);
        assert_eq!(cfg.attachments.max_single_size, 25 * 1024 * 1024);
        assert_eq!(cfg.attachments.max_count, 20);
        assert_eq!(cfg.retry.max_retries, 3);
        assert_eq!(cfg.loop_detection.max_hops, 25);
        assert!(cfg.clamav.enabled);
    }
}
