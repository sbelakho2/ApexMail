//! MTA configuration.

use serde::{Deserialize, Serialize};

// ── top‑level ──────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct MtaConfig {
    #[serde(default = "default_env")]
    pub node_env: String,
    #[serde(default = "default_mta_id")]
    pub mta_id: String,
    pub database: DatabaseConfig,
    pub redis: RedisConfig,
    #[serde(default)]
    pub inbound: InboundConfig,
    #[serde(default)]
    pub bounce: BounceConfig,
    #[serde(default)]
    pub feedback: FeedbackConfig,
    #[serde(default)]
    pub dkim: DkimConfig,
    #[serde(default)]
    pub spf: SpfConfig,
    #[serde(default)]
    pub dmarc: DmarcConfig,
    #[serde(default)]
    pub rate_limit: RateLimitConfig,
    #[serde(default)]
    pub email_auth: EmailAuthConfig,
    #[serde(default)]
    pub metrics: MetricsConfig,
    #[serde(default = "default_health_port")]
    pub health_port: u16,
    #[serde(default = "default_shutdown_timeout")]
    pub graceful_shutdown_timeout: u64,
}

// ── sub configs ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DatabaseConfig {
    pub connection_string: String,
    #[serde(default = "default_max_connections")]
    pub max_connections: u32,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RedisConfig {
    pub url: String,
    #[serde(default = "default_key_prefix")]
    pub key_prefix: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct InboundConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_host")]
    pub host: String,
    #[serde(default = "default_smtp_port")]
    pub port: u16,
    #[serde(default = "default_smtps_port")]
    pub secure_port: u16,
    #[serde(default = "default_hostname")]
    pub hostname: String,
    #[serde(default = "default_max_message_size")]
    pub max_message_size: usize,
    #[serde(default = "default_max_recipients")]
    pub max_recipients: usize,
    #[serde(default)]
    pub auth_required: bool,
    #[serde(default)]
    pub tls: TlsConfig,
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct TlsConfig {
    #[serde(default)]
    pub enabled: bool,
    pub key_path: Option<String>,
    pub cert_path: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct BounceConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_host")]
    pub host: String,
    #[serde(default = "default_bounce_port")]
    pub port: u16,
    #[serde(default = "default_hostname")]
    pub hostname: String,
    #[serde(default = "default_verp_domain")]
    pub verp_domain: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct FeedbackConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_host")]
    pub host: String,
    #[serde(default = "default_fbl_port")]
    pub port: u16,
    #[serde(default = "default_hostname")]
    pub hostname: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DkimConfig {
    #[serde(default = "default_selector")]
    pub selector: String,
    pub default_key_path: Option<String>,
    pub key_directory: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SpfConfig {
    #[serde(default)]
    pub strict_mode: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DmarcConfig {
    #[serde(default = "default_report_email")]
    pub report_email: String,
    #[serde(default)]
    pub report_domain: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RateLimitConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_max_conn_per_ip")]
    pub max_connections_per_ip: u32,
    #[serde(default = "default_max_msg_per_conn")]
    pub max_messages_per_connection: u32,
    #[serde(default = "default_max_recipients")]
    pub max_recipients_per_message: usize,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct EmailAuthConfig {
    #[serde(default)]
    pub require_spf: bool,
    #[serde(default)]
    pub require_dkim: bool,
    #[serde(default)]
    pub enforce_dmarc: bool,
    #[serde(default = "default_true")]
    pub allow_soft_fail: bool,
    #[serde(default)]
    pub trusted_relays: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct MetricsConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_metrics_port")]
    pub port: u16,
}

// ── defaults ───────────────────────────────────────────────────────────────────

impl Default for MtaConfig {
    fn default() -> Self {
        Self {
            node_env: default_env(),
            mta_id: default_mta_id(),
            database: DatabaseConfig {
                connection_string: "postgres://127.0.0.1:5432/apexmail".into(),
                max_connections: default_max_connections(),
            },
            redis: RedisConfig {
                url: "redis://127.0.0.1:6379".into(),
                key_prefix: default_key_prefix(),
            },
            inbound: InboundConfig::default(),
            bounce: BounceConfig::default(),
            feedback: FeedbackConfig::default(),
            dkim: DkimConfig::default(),
            spf: SpfConfig::default(),
            dmarc: DmarcConfig::default(),
            rate_limit: RateLimitConfig::default(),
            email_auth: EmailAuthConfig::default(),
            metrics: MetricsConfig::default(),
            health_port: default_health_port(),
            graceful_shutdown_timeout: default_shutdown_timeout(),
        }
    }
}

macro_rules! impl_default {
    ($ty:ty, $body:expr) => {
        impl Default for $ty {
            fn default() -> Self {
                $body
            }
        }
    };
}

impl_default!(
    InboundConfig,
    Self {
        enabled: true,
        host: default_host(),
        port: default_smtp_port(),
        secure_port: default_smtps_port(),
        hostname: default_hostname(),
        max_message_size: default_max_message_size(),
        max_recipients: default_max_recipients(),
        auth_required: false,
        tls: TlsConfig::default(),
    }
);
impl_default!(
    BounceConfig,
    Self {
        enabled: true,
        host: default_host(),
        port: default_bounce_port(),
        hostname: default_hostname(),
        verp_domain: default_verp_domain(),
    }
);
impl_default!(
    FeedbackConfig,
    Self {
        enabled: true,
        host: default_host(),
        port: default_fbl_port(),
        hostname: default_hostname(),
    }
);
impl_default!(
    DkimConfig,
    Self {
        selector: default_selector(),
        default_key_path: None,
        key_directory: None,
    }
);
impl_default!(SpfConfig, Self { strict_mode: false });
impl_default!(
    DmarcConfig,
    Self {
        report_email: default_report_email(),
        report_domain: default_hostname(),
    }
);
impl_default!(
    RateLimitConfig,
    Self {
        enabled: true,
        max_connections_per_ip: default_max_conn_per_ip(),
        max_messages_per_connection: default_max_msg_per_conn(),
        max_recipients_per_message: default_max_recipients(),
    }
);
impl_default!(
    EmailAuthConfig,
    Self {
        require_spf: false,
        require_dkim: false,
        enforce_dmarc: false,
        allow_soft_fail: true,
        trusted_relays: Vec::new(),
    }
);
impl_default!(
    MetricsConfig,
    Self {
        enabled: false,
        port: default_metrics_port()
    }
);

fn default_env() -> String {
    "development".into()
}
fn default_mta_id() -> String {
    uuid::Uuid::new_v4().to_string()
}
fn default_host() -> String {
    "0.0.0.0".into()
}
fn default_hostname() -> String {
    "mail.apexmail.ee".into()
}
fn default_smtp_port() -> u16 {
    25
}
fn default_smtps_port() -> u16 {
    465
}
fn default_bounce_port() -> u16 {
    2525
}
fn default_fbl_port() -> u16 {
    2526
}
fn default_max_message_size() -> usize {
    25 * 1024 * 1024
}
fn default_max_recipients() -> usize {
    100
}
fn default_max_connections() -> u32 {
    20
}
fn default_key_prefix() -> String {
    "mta:".into()
}
fn default_selector() -> String {
    "apexmail2026".into()
}
fn default_report_email() -> String {
    "dmarc-reports@apexmail.ee".into()
}
fn default_verp_domain() -> String {
    "bounces.apexmail.ee".into()
}
fn default_max_conn_per_ip() -> u32 {
    10
}
fn default_max_msg_per_conn() -> u32 {
    100
}
fn default_metrics_port() -> u16 {
    9100
}
fn default_health_port() -> u16 {
    8081
}
fn default_shutdown_timeout() -> u64 {
    30
}
fn default_true() -> bool {
    true
}

impl MtaConfig {
    /// Load configuration from environment variables.
    pub fn from_env() -> anyhow::Result<Self> {
        dotenvy::dotenv().ok();
        let cfg = Self {
            node_env: std::env::var("NODE_ENV").unwrap_or_else(|_| default_env()),
            mta_id: std::env::var("MTA_ID").unwrap_or_else(|_| default_mta_id()),
            database: DatabaseConfig {
                connection_string: std::env::var("DATABASE_URL")
                    .unwrap_or_else(|_| "postgres://localhost/apexmail".into()),
                max_connections: std::env::var("DB_MAX_CONNECTIONS")
                    .ok()
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(default_max_connections()),
            },
            redis: RedisConfig {
                url: std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".into()),
                key_prefix: std::env::var("REDIS_KEY_PREFIX")
                    .unwrap_or_else(|_| default_key_prefix()),
            },
            inbound: InboundConfig {
                enabled: parse_bool_env("INBOUND_ENABLED", true),
                host: std::env::var("INBOUND_HOST").unwrap_or_else(|_| default_host()),
                port: parse_u16_env("INBOUND_PORT", default_smtp_port()),
                secure_port: parse_u16_env("INBOUND_SECURE_PORT", default_smtps_port()),
                hostname: std::env::var("INBOUND_HOSTNAME").unwrap_or_else(|_| default_hostname()),
                max_message_size: parse_usize_env("MAX_MESSAGE_SIZE", default_max_message_size()),
                max_recipients: parse_usize_env("MAX_RECIPIENTS", default_max_recipients()),
                auth_required: parse_bool_env("AUTH_REQUIRED", false),
                tls: TlsConfig {
                    enabled: parse_bool_env("TLS_ENABLED", false),
                    key_path: std::env::var("TLS_KEY_PATH").ok(),
                    cert_path: std::env::var("TLS_CERT_PATH").ok(),
                },
            },
            bounce: BounceConfig {
                enabled: parse_bool_env("BOUNCE_ENABLED", true),
                host: std::env::var("BOUNCE_HOST").unwrap_or_else(|_| default_host()),
                port: parse_u16_env("BOUNCE_PORT", default_bounce_port()),
                hostname: std::env::var("BOUNCE_HOSTNAME").unwrap_or_else(|_| default_hostname()),
                verp_domain: std::env::var("VERP_DOMAIN").unwrap_or_else(|_| default_verp_domain()),
            },
            feedback: FeedbackConfig {
                enabled: parse_bool_env("FBL_ENABLED", true),
                host: std::env::var("FBL_HOST").unwrap_or_else(|_| default_host()),
                port: parse_u16_env("FBL_PORT", default_fbl_port()),
                hostname: std::env::var("FBL_HOSTNAME").unwrap_or_else(|_| default_hostname()),
            },
            dkim: DkimConfig {
                selector: std::env::var("DKIM_SELECTOR").unwrap_or_else(|_| default_selector()),
                default_key_path: std::env::var("DKIM_KEY_PATH").ok(),
                key_directory: std::env::var("DKIM_KEY_DIR").ok(),
            },
            spf: SpfConfig {
                strict_mode: parse_bool_env("SPF_STRICT_MODE", false),
            },
            dmarc: DmarcConfig {
                report_email: std::env::var("DMARC_REPORT_EMAIL")
                    .unwrap_or_else(|_| default_report_email()),
                report_domain: std::env::var("DMARC_REPORT_DOMAIN").unwrap_or_default(),
            },
            rate_limit: RateLimitConfig::default(),
            email_auth: EmailAuthConfig {
                require_spf: parse_bool_env("REQUIRE_SPF", false),
                require_dkim: parse_bool_env("REQUIRE_DKIM", false),
                enforce_dmarc: parse_bool_env("ENFORCE_DMARC", false),
                allow_soft_fail: parse_bool_env("ALLOW_SOFT_FAIL", true),
                trusted_relays: std::env::var("TRUSTED_RELAYS")
                    .ok()
                    .map(|v| v.split(',').map(|s| s.trim().to_string()).collect())
                    .unwrap_or_default(),
            },
            metrics: MetricsConfig {
                enabled: parse_bool_env("METRICS_ENABLED", false),
                port: parse_u16_env("METRICS_PORT", default_metrics_port()),
            },
            health_port: parse_u16_env("HEALTH_PORT", default_health_port()),
            graceful_shutdown_timeout: std::env::var("GRACEFUL_SHUTDOWN_TIMEOUT")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(default_shutdown_timeout()),
        };
        cfg.validate()?;
        Ok(cfg)
    }

    /// #155:Validate all config values to catch misconfiguration early.
    pub fn validate(&self) -> anyhow::Result<()> {
        let mut errors: Vec<String> = Vec::new();

        // --- ports must be 1..=65535 (already u16, but 0 is invalid) ---
        let port_checks: &[(&str, u16)] = &[
            ("inbound.port", self.inbound.port),
            ("inbound.secure_port", self.inbound.secure_port),
            ("bounce.port", self.bounce.port),
            ("feedback.port", self.feedback.port),
            ("health_port", self.health_port),
            ("metrics.port", self.metrics.port),
        ];
        for (name, val) in port_checks {
            if *val == 0 {
                errors.push(format!("{name} must be > 0, got {val}"));
            }
        }

        // ports must not collide (among enabled listeners)
        {
            let mut active_ports: Vec<(&str, u16)> = Vec::new();
            if self.inbound.enabled {
                active_ports.push(("inbound.port", self.inbound.port));
                if self.inbound.tls.enabled {
                    active_ports.push(("inbound.secure_port", self.inbound.secure_port));
                }
            }
            if self.bounce.enabled {
                active_ports.push(("bounce.port", self.bounce.port));
            }
            if self.feedback.enabled {
                active_ports.push(("feedback.port", self.feedback.port));
            }
            active_ports.push(("health_port", self.health_port));
            if self.metrics.enabled {
                active_ports.push(("metrics.port", self.metrics.port));
            }
            for i in 0..active_ports.len() {
                for j in (i + 1)..active_ports.len() {
                    let (n1, p1) = active_ports[i];
                    let (n2, p2) = active_ports[j];
                    if p1 == p2 {
                        errors.push(format!("Port collision: {n1} and {n2} both use port {p1}"));
                    }
                }
            }
        }

        // --- numeric bounds ---
        if self.database.max_connections == 0 {
            errors.push("database.max_connections must be > 0".into());
        }
        if self.inbound.max_message_size == 0 {
            errors.push("inbound.max_message_size must be > 0".into());
        }
        if self.inbound.max_message_size > 100 * 1024 * 1024 {
            errors.push(format!(
                "inbound.max_message_size ({}) exceeds 100 MiB safety limit",
                self.inbound.max_message_size
            ));
        }
        if self.inbound.max_recipients == 0 {
            errors.push("inbound.max_recipients must be > 0".into());
        }
        if self.rate_limit.enabled {
            if self.rate_limit.max_connections_per_ip == 0 {
                errors.push("rate_limit.max_connections_per_ip must be > 0".into());
            }
            if self.rate_limit.max_messages_per_connection == 0 {
                errors.push("rate_limit.max_messages_per_connection must be > 0".into());
            }
            if self.rate_limit.max_recipients_per_message == 0 {
                errors.push("rate_limit.max_recipients_per_message must be > 0".into());
            }
        }
        if self.graceful_shutdown_timeout == 0 {
            errors.push("graceful_shutdown_timeout must be > 0".into());
        }

        // --- TLS config coherence ---
        if self.inbound.tls.enabled {
            if self.inbound.tls.cert_path.is_none() {
                errors.push("TLS enabled but tls.cert_path is not set".into());
            }
            if self.inbound.tls.key_path.is_none() {
                errors.push("TLS enabled but tls.key_path is not set".into());
            }
        }

        // --- required non-empty strings ---
        if self.database.connection_string.is_empty() {
            errors.push("database.connection_string must not be empty".into());
        }
        if self.redis.url.is_empty() {
            errors.push("redis.url must not be empty".into());
        }
        if self.inbound.enabled && self.inbound.hostname.is_empty() {
            errors.push("inbound.hostname must not be empty when inbound is enabled".into());
        }

        if errors.is_empty() {
            Ok(())
        } else {
            anyhow::bail!(
                "MTA configuration validation failed:\n  - {}",
                errors.join("\n  - ")
            );
        }
    }
}

fn parse_bool_env(name: &str, default: bool) -> bool {
    std::env::var(name)
        .ok()
        .map(|v| matches!(v.to_lowercase().as_str(), "true" | "1" | "yes"))
        .unwrap_or(default)
}

fn parse_u16_env(name: &str, default: u16) -> u16 {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn parse_usize_env(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}
