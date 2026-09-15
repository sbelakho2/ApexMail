//! Configuration for the edge-cases service.

use serde::{Deserialize, Serialize};

/// Top-level edge-cases configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EdgeCasesConfig {
    pub port: u16,
    pub database_url: String,
    pub redis_url: String,
    pub api_key: String,
    pub node_env: String,
    /// A. Fail-closed auth: explicit development-only bypass for the missing
    /// INTERNAL_API_KEY case. Default false; a true value logs a loud warning.
    pub allow_anonymous: bool,
    pub attachments: AttachmentLimits,
    pub retry: RetryConfig,
    pub loop_detection: LoopDetectionConfig,
    pub auto_responder: AutoResponderConfig,
    pub clamav: ClamAVConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttachmentLimits {
    pub max_single_size: usize,
    pub max_total_size: usize,
    pub max_count: usize,
    pub blocked_extensions: Vec<String>,
    pub blocked_mime_types: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetryConfig {
    pub max_retries: u32,
    pub initial_delay_secs: u64,
    pub max_delay_secs: u64,
    pub backoff_multiplier: f64,
    pub greylist_retry_delay_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoopDetectionConfig {
    pub max_hops: usize,
    pub max_received_headers: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AutoResponderConfig {
    pub patterns: Vec<String>,
    pub header_indicators: Vec<String>,
    pub subject_patterns: Vec<String>,
}

/// O-21.1: Configurable ClamAV chunk size for virus scanning.
/// The default chunk size (8 192 bytes) matches ClamAV's recommended
/// INSTREAM chunk limit. Override via env var `CLAMAV_CHUNK_SIZE`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClamAVConfig {
    pub host: String,
    pub port: u16,
    pub timeout_secs: u64,
    pub enabled: bool,
    /// Maximum chunk size (in bytes) sent to ClamAV per INSTREAM command.
    /// Default: 8 192 (8 KB). Larger values reduce overhead but increase
    /// memory pressure per scan.
    pub chunk_size: usize,
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
            blocked_extensions: DEFAULT_BLOCKED_EXTENSIONS
                .iter()
                .map(|s| s.to_string())
                .collect(),
            blocked_mime_types: DEFAULT_BLOCKED_MIME_TYPES
                .iter()
                .map(|s| s.to_string())
                .collect(),
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
            host: "127.0.0.1".into(),
            port: 3310,
            timeout_secs: 30,
            enabled: true,
            chunk_size: 8192, // 8 KB — ClamAV recommended default
        }
    }
}

impl Default for EdgeCasesConfig {
    fn default() -> Self {
        Self {
            port: 4600,
            database_url: String::new(),
            redis_url: "redis://localhost:6379".into(),
            api_key: String::new(),
            node_env: "development".into(),
            allow_anonymous: false,
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
        // A. Fail-closed auth: anonymous access requires an explicit opt-in
        // and is never permitted outside development.
        let allow_anonymous = std::env::var("EDGE_CASES_ALLOW_ANONYMOUS")
            .map(|v| v == "true" || v == "1")
            .unwrap_or(false);
        if allow_anonymous {
            if node_env != "development" {
                return Err(ConfigError::SecurityViolation(
                    "EDGE_CASES_ALLOW_ANONYMOUS may only be enabled in development".into(),
                ));
            }
            tracing::warn!(
                "SECURITY: EDGE_CASES_ALLOW_ANONYMOUS=true — edge-cases protected routes are \
                 UNAUTHENTICATED. Never enable this in production."
            );
        }
        Ok(Self {
            port: std::env::var("EDGE_CASES_PORT")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(4600),
            database_url: std::env::var("DATABASE_URL").unwrap_or_default(),
            redis_url: std::env::var("REDIS_URL")
                .unwrap_or_else(|_| "redis://127.0.0.1:6379".into()),
            api_key,
            node_env,
            allow_anonymous,
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
                // O-21.1: Configurable chunk size for ClamAV INSTREAM scanning.
                // A value of 0 would make the scanner loop forever sending
                // empty chunks (or slice-panic), so fall back to the default.
                chunk_size: std::env::var("CLAMAV_CHUNK_SIZE")
                    .ok()
                    .and_then(|v| v.parse().ok())
                    .filter(|v| *v > 0)
                    .unwrap_or(8192),
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

    /// Serializes env-mutating tests in this module.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// Run `f` with the given env overrides applied, restoring the previous
    /// values afterwards (even on panic).
    fn with_env<T>(vars: &[(&str, Option<&str>)], f: impl FnOnce() -> T) -> T {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let saved: Vec<(String, Option<String>)> = vars
            .iter()
            .map(|(k, _)| ((*k).to_string(), std::env::var(k).ok()))
            .collect();
        for (k, v) in vars {
            match v {
                Some(value) => std::env::set_var(k, value),
                None => std::env::remove_var(k),
            }
        }
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f));
        for (k, v) in saved {
            match v {
                Some(value) => std::env::set_var(&k, value),
                None => std::env::remove_var(&k),
            }
        }
        match result {
            Ok(value) => value,
            Err(panic) => std::panic::resume_unwind(panic),
        }
    }

    #[test]
    fn from_env_parses_overrides_and_clamps_chunk_size() {
        let cfg = with_env(
            &[
                ("NODE_ENV", Some("development")),
                ("EDGE_CASES_PORT", Some("9999")),
                ("REDIS_URL", Some("redis://127.0.0.1:6390/2")),
                ("DATABASE_URL", Some("postgres://u@h/db")),
                ("INTERNAL_API_KEY", Some("k")),
                ("CLAMAV_HOST", Some("clam.internal")),
                ("CLAMAV_PORT", Some("3311")),
                ("CLAMAV_ENABLED", Some("false")),
                ("CLAMAV_CHUNK_SIZE", Some("0")),
                ("EDGE_CASES_ALLOW_ANONYMOUS", None),
            ],
            EdgeCasesConfig::from_env,
        )
        .expect("development config never fails");
        assert_eq!(cfg.port, 9999);
        assert_eq!(cfg.redis_url, "redis://127.0.0.1:6390/2");
        assert_eq!(cfg.database_url, "postgres://u@h/db");
        assert_eq!(cfg.api_key, "k");
        assert!(!cfg.allow_anonymous);
        assert_eq!(cfg.clamav.host, "clam.internal");
        assert_eq!(cfg.clamav.port, 3311);
        assert!(!cfg.clamav.enabled);
        // A zero chunk size would loop forever: it falls back to 8192.
        assert_eq!(cfg.clamav.chunk_size, 8192);

        let cfg = with_env(
            &[
                ("NODE_ENV", Some("development")),
                ("CLAMAV_CHUNK_SIZE", Some("4096")),
                ("EDGE_CASES_ALLOW_ANONYMOUS", Some("1")),
            ],
            EdgeCasesConfig::from_env,
        )
        .expect("anonymous dev opt-in is allowed");
        assert!(cfg.allow_anonymous);
        assert_eq!(cfg.clamav.chunk_size, 4096);
    }

    #[test]
    fn from_env_refuses_missing_api_key_outside_development() {
        let err = with_env(
            &[
                ("NODE_ENV", Some("production")),
                ("INTERNAL_API_KEY", Option::Some("")),
                ("EDGE_CASES_ALLOW_ANONYMOUS", None),
            ],
            EdgeCasesConfig::from_env,
        )
        .expect_err("production without an API key must be refused");
        assert!(matches!(err, ConfigError::SecurityViolation(_)));
    }

    #[test]
    fn from_env_refuses_anonymous_outside_development() {
        let err = with_env(
            &[
                ("NODE_ENV", Some("staging")),
                ("INTERNAL_API_KEY", Some("configured")),
                ("EDGE_CASES_ALLOW_ANONYMOUS", Some("true")),
            ],
            EdgeCasesConfig::from_env,
        )
        .expect_err("anonymous access outside development must be refused");
        assert!(matches!(err, ConfigError::SecurityViolation(_)));
    }

    #[test]
    fn default_config_is_deny_unknown_fields() {
        let json = serde_json::json!({
            "port": 4600,
            "database_url": "",
            "redis_url": "redis://localhost:6379",
            "api_key": "",
            "node_env": "development",
            "allow_anonymous": false,
            "attachments": {
                "max_single_size": 1, "max_total_size": 1, "max_count": 1,
                "blocked_extensions": [], "blocked_mime_types": []
            },
            "retry": {
                "max_retries": 1, "initial_delay_secs": 1, "max_delay_secs": 1,
                "backoff_multiplier": 1.0, "greylist_retry_delay_secs": 1
            },
            "loop_detection": { "max_hops": 1, "max_received_headers": 1 },
            "auto_responder": { "patterns": [], "header_indicators": [], "subject_patterns": [] },
            "clamav": { "host": "h", "port": 1, "timeout_secs": 1, "enabled": false, "chunk_size": 1 }
        });
        let cfg: EdgeCasesConfig = serde_json::from_value(json.clone()).expect("valid config");
        assert_eq!(cfg.port, 4600);
        let mut with_extra = json;
        with_extra["surprise"] = serde_json::json!(true);
        assert!(
            serde_json::from_value::<EdgeCasesConfig>(with_extra).is_err(),
            "unknown fields must be rejected"
        );
    }
}
