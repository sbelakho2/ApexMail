//! Configuration management for the mail server.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Main configuration structure
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Config {
    pub server: ServerConfig,
    pub database: DatabaseConfig,
    pub storage: StorageConfig,
    pub tls: TlsConfig,
    pub dkim: DkimConfig,
    pub outbound: OutboundConfig,
    #[serde(default)]
    pub limits: LimitsConfig,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ServerConfig {
    pub hostname: String,
    pub domain: String,
    #[serde(default = "default_grpc_port")]
    pub grpc_port: u16,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DatabaseConfig {
    pub url: String,
    #[serde(default = "default_max_connections")]
    pub max_connections: u32,
    #[serde(default = "default_connect_timeout")]
    pub connect_timeout_secs: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct StorageConfig {
    pub blob_path: PathBuf,
    pub index_path: PathBuf,
    #[serde(default = "default_true")]
    pub deduplicate: bool,
    #[serde(default = "default_true")]
    pub compress: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TlsConfig {
    #[serde(default)]
    pub enabled: bool,
    pub cert_path: Option<String>,
    pub key_path: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DkimConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_dkim_selector")]
    pub selector: String,
    pub private_key_path: Option<String>,
    /// Base64-encoded private key (alternative to file path)
    pub private_key: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct OutboundConfig {
    #[serde(default = "default_max_retries")]
    pub max_retries: u32,
    #[serde(default = "default_retry_delay")]
    pub retry_delay_seconds: u64,
    #[serde(default = "default_concurrent_deliveries")]
    pub concurrent_deliveries: usize,
    #[serde(default = "default_smtp_timeout")]
    pub smtp_timeout_seconds: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct LimitsConfig {
    #[serde(default = "default_max_message_size")]
    pub max_message_size: usize,
    #[serde(default = "default_max_recipients")]
    pub max_recipients: usize,
    #[serde(default = "default_quota_bytes")]
    pub default_quota_bytes: u64,
    #[serde(default = "default_rate_limit")]
    pub rate_limit_per_minute: u32,
}

// Default value functions
fn default_grpc_port() -> u16 {
    50051
}
fn default_max_connections() -> u32 {
    20
}
fn default_connect_timeout() -> u64 {
    10
}
fn default_true() -> bool {
    true
}
fn default_dkim_selector() -> String {
    "apexmail2026".to_string()
}
fn default_max_retries() -> u32 {
    5
}
fn default_retry_delay() -> u64 {
    300
}
fn default_concurrent_deliveries() -> usize {
    10
}
fn default_smtp_timeout() -> u64 {
    60
}
fn default_max_message_size() -> usize {
    25 * 1024 * 1024
} // 25MB
fn default_max_recipients() -> usize {
    100
}
fn default_quota_bytes() -> u64 {
    1024 * 1024 * 1024
} // 1GB
fn default_rate_limit() -> u32 {
    100
}

impl Default for LimitsConfig {
    fn default() -> Self {
        Self {
            max_message_size: default_max_message_size(),
            max_recipients: default_max_recipients(),
            default_quota_bytes: default_quota_bytes(),
            rate_limit_per_minute: default_rate_limit(),
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            server: ServerConfig {
                hostname: "localhost".to_string(),
                domain: "localhost".to_string(),
                grpc_port: default_grpc_port(),
            },
            database: DatabaseConfig {
                url: "postgresql://localhost/apexmail".to_string(),
                max_connections: default_max_connections(),
                connect_timeout_secs: default_connect_timeout(),
            },
            storage: StorageConfig {
                blob_path: PathBuf::from("/var/lib/apexmail/blobs"),
                index_path: PathBuf::from("/var/lib/apexmail/index"),
                deduplicate: true,
                compress: true,
            },
            tls: TlsConfig {
                enabled: false,
                cert_path: None,
                key_path: None,
            },
            dkim: DkimConfig {
                enabled: true,
                selector: default_dkim_selector(),
                private_key_path: None,
                private_key: None,
            },
            outbound: OutboundConfig {
                max_retries: default_max_retries(),
                retry_delay_seconds: default_retry_delay(),
                concurrent_deliveries: default_concurrent_deliveries(),
                smtp_timeout_seconds: default_smtp_timeout(),
            },
            limits: LimitsConfig::default(),
        }
    }
}

impl Config {
    /// Load configuration from file
    pub fn load_from(path: &str) -> anyhow::Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let config: Config = toml::from_str(&content)?;
        Ok(config)
    }

    /// Load configuration from environment variables
    pub fn from_env() -> anyhow::Result<Self> {
        dotenvy::dotenv().ok();

        let mut config = Config::default();

        if let Ok(val) = std::env::var("MAIL_HOSTNAME") {
            config.server.hostname = val;
        }
        if let Ok(val) = std::env::var("MAIL_DOMAIN") {
            config.server.domain = val;
        }
        if let Ok(val) = std::env::var("DATABASE_URL") {
            config.database.url = val;
        }
        if let Ok(val) = std::env::var("BLOB_PATH") {
            config.storage.blob_path = PathBuf::from(val);
        }
        if let Ok(val) = std::env::var("DKIM_SELECTOR") {
            config.dkim.selector = val;
        }
        if let Ok(val) = std::env::var("DKIM_PRIVATE_KEY") {
            config.dkim.private_key = Some(val);
        }
        if let Ok(val) = std::env::var("DKIM_PRIVATE_KEY_PATH") {
            config.dkim.private_key_path = Some(val);
        }

        Ok(config)
    }
}
