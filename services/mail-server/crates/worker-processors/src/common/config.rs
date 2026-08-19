//! Processor configuration types.

use std::time::Duration;
use zeroize::Zeroizing;

/// Common processor configuration.
#[derive(Debug, Clone)]
pub struct ProcessorConfig {
    /// Processor name (for logging/metrics).
    pub name: String,
    /// Maximum concurrent jobs.
    pub concurrency: usize,
    /// Interval between queue polls.
    pub poll_interval: Duration,
    /// Maximum number of retries for failed jobs.
    pub max_retries: u32,
    /// Base delay between retries (exponential backoff).
    pub retry_delay: Duration,
    /// Job visibility timeout (how long a job is invisible after being claimed).
    pub visibility_timeout: Duration,
    /// Batch size for queue fetching.
    pub batch_size: usize,
    /// Flush interval for buffered writes.
    pub flush_interval: Duration,
}

impl Default for ProcessorConfig {
    fn default() -> Self {
        Self {
            name: "processor".to_string(),
            concurrency: 10,
            poll_interval: Duration::from_secs(1),
            max_retries: 3,
            retry_delay: Duration::from_secs(30),
            visibility_timeout: Duration::from_secs(300),
            batch_size: 100,
            flush_interval: Duration::from_secs(5),
        }
    }
}

/// Analytics processor-specific configuration.
#[derive(Debug, Clone)]
pub struct AnalyticsConfig {
    /// Base processor config.
    pub base: ProcessorConfig,
    /// Redis key TTL for stats (7 days by default).
    pub stats_ttl: Duration,
}

impl Default for AnalyticsConfig {
    fn default() -> Self {
        Self {
            base: ProcessorConfig {
                name: "analytics".to_string(),
                ..Default::default()
            },
            stats_ttl: Duration::from_secs(7 * 24 * 60 * 60),
        }
    }
}

/// Which transport backend to use for email delivery.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum TransportType {
    /// Self-hosted SMTP (direct-to-MX via outbound queue or relay).
    Smtp,
    /// AWS SES v2 API.
    #[default]
    Ses,
}

impl TransportType {
    /// Parse the shared deployment-wide transport setting.
    ///
    /// Only an explicit `smtp` value selects SMTP. All other values select
    /// SES, matching API readiness enforcement.
    pub fn from_env(s: &str) -> Self {
        if apexmail_lib::transport::email_transport_is_ses(Some(s)) {
            Self::Ses
        } else {
            Self::Smtp
        }
    }
}

/// Email processor-specific configuration.
#[derive(Debug, Clone)]
pub struct EmailConfig {
    /// Base processor config.
    pub base: ProcessorConfig,
    /// Which transport backend to use.
    pub transport_type: TransportType,
    /// SMTP configuration (used when transport_type == Smtp).
    pub smtp: SmtpConfig,
    /// SES configuration (used when transport_type == Ses).
    pub ses: SesConfig,
    /// DKIM configuration.
    pub dkim: DkimConfig,
    /// Tracking configuration.
    pub tracking: TrackingConfig,
    /// Warmup configuration.
    pub warmup: WarmupConfig,
    /// IP rate limiting configuration.
    pub ip_rate_limiting: IpRateLimitConfig,
}

impl Default for EmailConfig {
    fn default() -> Self {
        Self {
            base: ProcessorConfig {
                name: "email".to_string(),
                ..Default::default()
            },
            transport_type: TransportType::default(),
            smtp: SmtpConfig::default(),
            ses: SesConfig::default(),
            dkim: DkimConfig::default(),
            tracking: TrackingConfig::default(),
            warmup: WarmupConfig::default(),
            ip_rate_limiting: IpRateLimitConfig::default(),
        }
    }
}

/// SMTP configuration.
#[derive(Debug, Clone)]
pub struct SmtpConfig {
    pub host: String,
    pub port: u16,
    pub secure: bool,
    pub username: Option<String>,
    pub password: Option<Zeroizing<String>>,
    pub pool_size: usize,
    pub max_connections: usize,
    pub rate_limit_per_second: u32,
}

impl Default for SmtpConfig {
    /// Defaults — host is intentionally invalid to force explicit configuration.
    fn default() -> Self {
        Self {
            host: "smtp.unset.invalid".to_string(),
            port: 25,
            secure: false,
            username: None,
            password: None,
            pool_size: 5,
            max_connections: 10,
            rate_limit_per_second: 100,
        }
    }
}

/// DKIM configuration.
#[derive(Debug, Clone)]
pub struct DkimConfig {
    /// Enables required local signing for direct SMTP transport. The selector
    /// and key themselves always come from the verified customer-domain row.
    pub enabled: bool,
    /// Legacy compatibility fields. They are intentionally not used as a
    /// fallback by the email processor: one global key must never sign an
    /// arbitrary customer domain.
    pub selector: String,
    pub key_path: Option<String>,
    /// Domain the `key_path` key belongs to; the fallback key is only used
    /// for jobs whose envelope domain matches (see `EmailProcessor`).
    pub domain: Option<String>,
}

impl Default for DkimConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            selector: "default".to_string(),
            key_path: None,
            domain: None,
        }
    }
}

/// Tracking configuration.
#[derive(Debug, Clone)]
pub struct TrackingConfig {
    pub enabled: bool,
    pub base_url: String,
    pub open_pixel_path: String,
    pub click_redirect_path: String,
}

impl Default for TrackingConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            base_url: "https://tracking.apexmail.ee".to_string(),
            open_pixel_path: "/o".to_string(),
            click_redirect_path: "/c".to_string(),
        }
    }
}

/// Warmup configuration.
/// DEPRECATED: This warmup config is unused. Hetzner dedicated IP warmup is managed
/// by the API server's DedicatedIpProvider (mail-common::warmup).
#[derive(Debug, Clone)]
pub struct WarmupConfig {
    pub enabled: bool,
    /// Daily send limits per day number (day 1 -> 50 emails, day 2 -> 100, etc.)
    pub schedule: Vec<u32>,
}

impl Default for WarmupConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            schedule: vec![50, 100, 200, 400, 800, 1500, 3000, 5000, 10000],
        }
    }
}

/// IP rate limiting configuration.
#[derive(Debug, Clone, Default)]
pub struct IpRateLimitConfig {
    pub enabled: bool,
    pub ip_address: Option<String>,
}

/// AWS SES v2 configuration.
#[derive(Debug, Clone)]
pub struct SesConfig {
    /// AWS region for SES (e.g. "eu-west-1", "us-east-1").
    pub region: String,
    /// SES configuration set name (for tracking, reputation, etc.).
    pub configuration_set: Option<String>,
    /// Default "From" domain when tenant domain is not yet verified in SES.
    pub default_from_domain: Option<String>,
    /// Maximum send rate (emails per second) — SES account-level limit.
    pub max_send_rate: u32,
    /// Enable SES feedback forwarding (bounces/complaints via email in addition to SNS).
    pub feedback_forwarding: bool,
}

impl Default for SesConfig {
    fn default() -> Self {
        Self {
            region: "eu-west-1".to_string(),
            configuration_set: None,
            default_from_domain: None,
            max_send_rate: 50,
            feedback_forwarding: false,
        }
    }
}

/// Webhook processor-specific configuration.
#[derive(Debug, Clone)]
pub struct WebhookConfig {
    /// Base processor config.
    pub base: ProcessorConfig,
    /// Maximum payload size in bytes.
    pub max_payload_bytes: usize,
    /// Maximum concurrent deliveries per tenant.
    pub max_concurrent_per_tenant: usize,
    /// HTTP request timeout.
    pub request_timeout: Duration,
    /// DNS cache TTL.
    pub dns_cache_ttl: Duration,
    /// HMAC key for webhook dedup key derivation (O-16.2 fix).
    /// When set, dedup keys are HMAC(webhook_id || nonce, key) instead of
    /// plain `format!("webhook:dedup:{}:{}", job.id, job.attempt)`.
    pub dedup_hmac_key: Option<zeroize::Zeroizing<String>>,
    /// Maximum retries per webhook endpoint within the retry budget window
    /// (RS-H-07). When the retry budget is exhausted, new failures are moved
    /// directly to the dead letter queue rather than scheduled for retry.
    /// Set to 0 to disable budget enforcement.
    pub retry_budget_max: u32,
    /// Time window in seconds for the retry budget (RS-H-07).
    /// Retry counts are tracked in Redis and reset after this window elapses.
    pub retry_budget_window_secs: u64,
}

impl Default for WebhookConfig {
    fn default() -> Self {
        Self {
            base: ProcessorConfig {
                name: "webhook".to_string(),
                ..Default::default()
            },
            max_payload_bytes: 1024 * 1024, // 1 MB
            max_concurrent_per_tenant: 5,
            request_timeout: Duration::from_secs(30),
            dns_cache_ttl: Duration::from_secs(60),
            dedup_hmac_key: None,
            retry_budget_max: 50,
            retry_budget_window_secs: 3600, // 1 hour
        }
    }
}

/// Reply handler-specific configuration.
#[derive(Debug, Clone)]
pub struct ReplyHandlerConfig {
    /// Base processor config.
    pub base: ProcessorConfig,
    /// Enable LLM classification (fallback from pattern matching).
    pub llm_enabled: bool,
    /// LLM API endpoint.
    pub llm_endpoint: Option<String>,
    /// LLM API key (zeroized for security -).
    pub llm_api_key: Option<Zeroizing<String>>,
    /// Maximum inbound reply message body size in bytes (O-16.5 fix).
    /// Messages larger than this will be truncated before classification.
    pub max_reply_size: usize,
    /// Whether to auto-execute suppression/unsubscribe actions (O-16.6 fix).
    /// When false, actions are queued for admin review instead of executing immediately.
    pub auto_suppress: bool,
    /// Confidence threshold for auto-execution when auto_suppress is enabled (0.0–1.0).
    pub auto_suppress_confidence_threshold: f64,
}

impl Default for ReplyHandlerConfig {
    fn default() -> Self {
        Self {
            base: ProcessorConfig {
                name: "reply_handler".to_string(),
                ..Default::default()
            },
            llm_enabled: false,
            llm_endpoint: None,
            llm_api_key: None,
            max_reply_size: 1024 * 100, // 100 KB default
            auto_suppress: false,
            auto_suppress_confidence_threshold: 0.85,
        }
    }
}
