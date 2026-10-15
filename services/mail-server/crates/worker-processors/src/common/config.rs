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
    /// WORKER PRE-SEND DLP gate configuration (`WORKER_DLP_ENABLED`,
    /// default OFF — see [`DlpGateConfig`]).
    pub dlp: DlpGateConfig,
    /// Dedicated SALES transport slot (`SALES_TRANSPORT` et al — see
    /// [`SalesTransportConfig`]). Separate from `smtp`/`ses` by design:
    /// sales mail never rides the customer transport.
    pub sales: SalesTransportConfig,
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
            dlp: DlpGateConfig::default(),
            sales: SalesTransportConfig::default(),
        }
    }
}

/// Which dedicated SALES transport carries sales-autopilot mail.
///
/// The sales isolation invariant ("sales sending never shares a transport
/// account, IP, sending domain or suppression list with customer mail")
/// makes the sales transport a SEPARATE slot from the customer
/// [`SmtpConfig`]/[`SesConfig`] routes: sales mail never rides the customer
/// SES account or the customer relay, whatever the customer transport's
/// configuration says. Absent/unrecognized configuration resolves to
/// [`SalesTransportMode::None`] — sales sends then HOLD in the queue with
/// the named reason `sales_transport_unconfigured` instead of falling back
/// (fail closed; see `crate::email::sales`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SalesTransportMode {
    /// No dedicated sales transport configured (the default): sales sends
    /// are HELD, never routed through the customer transport.
    #[default]
    None,
    /// ApexMail's own outbound MTA dedicated to sales (`SALES_TRANSPORT=relay`).
    /// The relay binds the sales identity's source IP for the recipient-facing
    /// socket and reports the verified IP in the same acceptance record, so
    /// `metadata.sales_sender_source_ip` is BINDING and required.
    Relay,
    /// A dedicated AWS SES account purchased for sales
    /// (`SALES_TRANSPORT=ses_account`), constructed from the `SALES_SES_*`
    /// credentials — never the customer account's AWS provider chain.
    SesAccount,
}

impl SalesTransportMode {
    /// Parse the `SALES_TRANSPORT` switch. `none`/`off`/absent → `None`;
    /// `relay`/`own_mta`/`smtp` → `Relay`; `ses_account`/`ses` → `SesAccount`;
    /// anything else → `None` with the caller logging the unrecognized value
    /// (fail closed: an unknown mode must never be treated as "configured").
    pub fn parse(raw: &str) -> Option<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "none" | "off" | "disabled" | "" => Some(Self::None),
            "relay" | "own_mta" | "smtp" => Some(Self::Relay),
            "ses_account" | "ses" => Some(Self::SesAccount),
            _ => None,
        }
    }

    /// Whether this mode has a transport that could carry a sales send.
    pub fn is_configured(self) -> bool {
        !matches!(self, Self::None)
    }

    /// The wire label recorded in hold annotations and logs.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Relay => "relay",
            Self::SesAccount => "ses_account",
        }
    }
}

/// The dedicated sales RELAY endpoint (`SALES_RELAY_URL`).
///
/// Accepts `smtp://host` and `smtps://host`. The host is the relay identity
/// sales submissions present (HELO name / `Reporting-MTA`), so the deployment
/// declares one explicit endpoint instead of inheriting the customer relay's
/// default name; the scheme selects the TLS posture (`smtps://` requires
/// STARTTLS on every recipient-facing connection, `smtp://` keeps the relay's
/// per-destination-port policy).
///
/// Deliberately NOT accepted: an explicit port (the own MTA delivers to
/// recipient MX ports, so a submission port in the URL would be a lie), user
/// info (the own MTA is ApexMail's own infrastructure — there is no
/// third-party AUTH to carry), paths, and unknown schemes. Any of those is
/// MISCONFIGURED and the caller refuses to build a sales transport.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SalesRelayConfig {
    /// The relay's declared identity (HELO name / `Reporting-MTA`).
    pub host: String,
    /// `smtps://` — every recipient-facing connection must complete STARTTLS.
    pub require_starttls: bool,
}

impl SalesRelayConfig {
    /// Parse `SALES_RELAY_URL`; `None` for anything that is not a bare
    /// `smtp(s)://host` endpoint (see the type docs).
    pub fn parse(url: &str) -> Option<Self> {
        let trimmed = url.trim();
        let (require_starttls, rest) = if let Some(rest) = trimmed.strip_prefix("smtps://") {
            (true, rest)
        } else {
            (false, trimmed.strip_prefix("smtp://")?)
        };
        if rest.contains('@') || rest.contains(':') {
            return None;
        }
        // A path (other than a bare trailing slash) is not part of an
        // endpoint and is refused rather than silently ignored.
        let host = rest.trim_end_matches('/');
        if host.is_empty() || host.trim() != host || host.contains('/') || host.contains(' ') {
            return None;
        }
        Some(Self {
            host: host.to_string(),
            require_starttls,
        })
    }
}

/// The dedicated sales SES account credentials (`SALES_SES_*`).
///
/// A separate AWS account is an owner purchase; this struct only carries
/// what the owner provisioned. Both key id and secret are REQUIRED for the
/// account to count as configured (an account without credentials is not a
/// transport).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SalesSesConfig {
    pub region: String,
    pub configuration_set: Option<String>,
    pub access_key_id: Zeroizing<String>,
    pub secret_access_key: Zeroizing<String>,
}

/// Dedicated SALES transport configuration — the `SALES_TRANSPORT` switch
/// plus its endpoint/credentials and the sales sending-domain allowlist.
///
/// Default is [`SalesTransportMode::None`] with an EMPTY allowlist: an
/// unconfigured deployment holds sales mail by name rather than guessing a
/// route. Every field is `SALES_*`-namespaced so it can never collide with
/// the customer transport's variables.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SalesTransportConfig {
    pub mode: SalesTransportMode,
    /// `SALES_SENDING_DOMAINS` — the exact sender domains a sales send may
    /// use (comma-separated, lowercased, deduplicated). A sender domain
    /// outside this list is refused BY NAME
    /// (`sales_send_domain_not_allowed`); an empty list refuses every sales
    /// send by name rather than allowing any domain.
    pub sending_domains: Vec<String>,
    /// The relay endpoint (`SALES_RELAY_URL`); required for
    /// [`SalesTransportMode::Relay`].
    pub relay: Option<SalesRelayConfig>,
    /// The dedicated SES account; required for
    /// [`SalesTransportMode::SesAccount`].
    pub ses_account: Option<SalesSesConfig>,
    /// Admission rate for sales sends (sends/second; `0` disables the gate).
    pub send_rate_per_second: u32,
}

impl SalesTransportConfig {
    const MODE_ENV: &'static str = "SALES_TRANSPORT";
    const DOMAINS_ENV: &'static str = "SALES_SENDING_DOMAINS";
    const RELAY_URL_ENV: &'static str = "SALES_RELAY_URL";
    const SES_REGION_ENV: &'static str = "SALES_SES_REGION";
    const SES_CONFIG_SET_ENV: &'static str = "SALES_SES_CONFIGURATION_SET";
    const SES_ACCESS_KEY_ENV: &'static str = "SALES_SES_ACCESS_KEY_ID";
    const SES_SECRET_KEY_ENV: &'static str = "SALES_SES_SECRET_ACCESS_KEY";
    const RATE_ENV: &'static str = "SALES_SEND_RATE_PER_SECOND";

    /// The default sales admission rate when `SALES_SEND_RATE_PER_SECOND` is
    /// unset: deliberately conservative (sales is a low-volume motion) and
    /// small enough that a misconfigured deployment cannot blast the relay.
    pub const DEFAULT_SEND_RATE_PER_SECOND: u32 = 5;

    /// Parse the allowlist: trimmed, lowercased, dot-trimmed, deduplicated,
    /// order-preserved.
    pub fn parse_sending_domains(raw: &str) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        for entry in raw.split(',') {
            let domain = entry.trim().trim_end_matches('.').to_ascii_lowercase();
            if !domain.is_empty() && !out.contains(&domain) {
                out.push(domain);
            }
        }
        out
    }

    /// Build from the environment. The mode is the only switch: absent →
    /// `None` (fail closed). Endpoint/credential material is read only for
    /// the selected mode, so customer variables are never repurposed.
    pub fn from_env() -> Self {
        let mode = match std::env::var(Self::MODE_ENV) {
            Ok(raw) => match SalesTransportMode::parse(&raw) {
                Some(parsed) => parsed,
                None => {
                    tracing::warn!(
                        value = %raw,
                        "unrecognized SALES_TRANSPORT value — failing CLOSED to 'none' \
                         (sales sends will be held, never routed through the customer transport)"
                    );
                    SalesTransportMode::None
                }
            },
            Err(_) => SalesTransportMode::None,
        };
        let env_value = |name: &str| {
            std::env::var(name)
                .ok()
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty())
        };
        let sending_domains =
            Self::parse_sending_domains(&std::env::var(Self::DOMAINS_ENV).unwrap_or_default());
        let relay = if mode == SalesTransportMode::Relay {
            env_value(Self::RELAY_URL_ENV).and_then(|url| SalesRelayConfig::parse(&url))
        } else {
            None
        };
        let ses_account = if mode == SalesTransportMode::SesAccount {
            let access_key_id = env_value(Self::SES_ACCESS_KEY_ENV);
            let secret_access_key = env_value(Self::SES_SECRET_KEY_ENV);
            match (access_key_id, secret_access_key) {
                (Some(access_key_id), Some(secret_access_key)) => Some(SalesSesConfig {
                    region: env_value(Self::SES_REGION_ENV)
                        .unwrap_or_else(|| "eu-west-1".to_string()),
                    configuration_set: env_value(Self::SES_CONFIG_SET_ENV),
                    access_key_id: Zeroizing::new(access_key_id),
                    secret_access_key: Zeroizing::new(secret_access_key),
                }),
                _ => None,
            }
        } else {
            None
        };
        let send_rate_per_second = std::env::var(Self::RATE_ENV)
            .ok()
            .and_then(|v| v.trim().parse::<u32>().ok())
            .unwrap_or(Self::DEFAULT_SEND_RATE_PER_SECOND);
        Self {
            mode,
            sending_domains,
            relay,
            ses_account,
            send_rate_per_second,
        }
    }

    /// Whether the mode's endpoint/credentials are actually present. A mode
    /// selected without its material is MISCONFIGURED: the worker refuses to
    /// boot (loud) rather than silently holding every sales send, and the
    /// send path additionally fails closed if this is ever reached.
    pub fn is_provisioned(&self) -> bool {
        match self.mode {
            SalesTransportMode::None => true,
            SalesTransportMode::Relay => self.relay.is_some(),
            SalesTransportMode::SesAccount => self.ses_account.is_some(),
        }
    }

    /// Whether `domain` (case/dot-insensitive) is on the sales allowlist.
    pub fn domain_allowed(&self, domain: &str) -> bool {
        let normalized = domain.trim().trim_end_matches('.').to_ascii_lowercase();
        self.sending_domains
            .iter()
            .any(|allowed| allowed == &normalized)
    }

    /// The mode's wire label, for hold annotations and logs.
    pub fn mode_label(&self) -> &'static str {
        self.mode.as_str()
    }
}

impl Default for SalesTransportConfig {
    fn default() -> Self {
        Self::from_env()
    }
}

/// WORKER PRE-SEND DLP gate configuration.
///
/// When enabled, every outbound copy is scanned by the `dlp-engine` in the
/// email processor's dispatch (`process_job_inner`) BEFORE the durable
/// acceptance reservation and any SMTP effect, with the severity mapping:
/// low → allow+log, medium → hold (`deferred` + annotation + audit row),
/// high → refuse (`bounced` + sender-visible copy + audit row). An engine
/// error fails OPEN (deliver + loud log); a detection fails CLOSED per the
/// mapping. See `crate::email::dlp` for the full contract.
///
/// The default is OFF so existing deployments keep byte-identical behavior
/// on upgrade; compose/production set `WORKER_DLP_ENABLED` explicitly.
/// Enforcement is global — no per-tenant override surface exists (that
/// would be a new policy table/migration, out of this crate's scope).
#[derive(Debug, Clone)]
pub struct DlpGateConfig {
    /// Gate switch (`WORKER_DLP_ENABLED`: `true`/`1` enables).
    pub enabled: bool,
}

impl DlpGateConfig {
    /// Env var gating the pre-send DLP scan (`WORKER_DLP_ENABLED`).
    const ENABLED_ENV: &'static str = "WORKER_DLP_ENABLED";

    /// Build from the environment. Absent / any value other than `true`
    /// or `1` keeps the gate OFF (historical default).
    pub fn from_env() -> Self {
        let enabled = std::env::var(Self::ENABLED_ENV)
            .map(|v| {
                let v = v.trim();
                v == "true" || v == "1"
            })
            .unwrap_or(false);
        Self { enabled }
    }
}

impl Default for DlpGateConfig {
    fn default() -> Self {
        Self::from_env()
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
    /// Shared AES-GCM master secret (`TRACKING_SECRET_KEY`, >= 32 chars) —
    /// the SAME secret the tracking-service verifies tokens with. Held
    /// zeroized; `None` means unset (token encoding is refused then, see
    /// `email::tracking`).
    pub secret_key: Option<Zeroizing<String>>,
    /// F13: the tracking-service's unsubscribe route (`/u/:token`), used to
    /// build the List-Unsubscribe URL. Defaults to the service's own
    /// `TRACKING_UNSUBSCRIBE_PATH` default (`/u`).
    pub unsubscribe_path: String,
}

impl TrackingConfig {
    /// Env var gating the pixel/link rewrite (`TRACKING_ENABLED`).
    const ENABLED_ENV: &'static str = "TRACKING_ENABLED";
    /// Env var holding the shared tracking master secret.
    const SECRET_KEY_ENV: &'static str = "TRACKING_SECRET_KEY";

    /// Build the tracking config from the environment:
    ///
    /// * `TRACKING_ENABLED` — `true`/`1` enables the rewrite gate. Absent
    ///   keeps the historical default (`false`) so existing deployments do
    ///   not silently change behaviour on upgrade; compose sets it
    ///   explicitly.
    /// * `TRACKING_SECRET_KEY` — shared with the tracking-service; too-short
    ///   values are treated as unset (the encoder refuses short keys anyway,
    ///   and a deployment that disagrees on key policy must not half-encode).
    /// * `TRACKING_PUBLIC_HOST` / `TRACKING_BASE_URL` — public tracking host.
    pub fn from_env() -> Self {
        let base_url = tracking_base_url_from_env();
        let enabled = std::env::var(Self::ENABLED_ENV)
            .map(|v| v.trim() == "true" || v.trim() == "1")
            .unwrap_or(false);
        let secret_key = std::env::var(Self::SECRET_KEY_ENV)
            .ok()
            .map(|v| v.trim().to_string())
            .filter(|v| v.len() >= 32)
            .map(Zeroizing::new);
        Self {
            enabled,
            base_url,
            open_pixel_path: "/o".to_string(),
            click_redirect_path: "/c".to_string(),
            unsubscribe_path: std::env::var("TRACKING_UNSUBSCRIBE_PATH")
                .ok()
                .map(|v| v.trim().trim_end_matches('/').to_string())
                .filter(|v| !v.is_empty())
                .unwrap_or_else(|| "/u".to_string()),
            secret_key,
        }
    }
}

impl Default for TrackingConfig {
    fn default() -> Self {
        Self::from_env()
    }
}

/// C: the public tracking host is unified with tracking-service — both read
/// TRACKING_PUBLIC_HOST (falling back to TRACKING_BASE_URL, the service's
/// legacy variable) with the service's default `https://t.apexmail.ee`. The
/// worker previously defaulted to `tracking.apexmail.ee`, which does not
/// serve the tracking routes.
fn tracking_base_url_from_env() -> String {
    std::env::var("TRACKING_PUBLIC_HOST")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .or_else(|| {
            std::env::var("TRACKING_BASE_URL")
                .ok()
                .filter(|v| !v.trim().is_empty())
        })
        .unwrap_or_else(|| "https://t.apexmail.ee".to_string())
}

/// Warmup configuration.
///
/// The canonical schedule is `mail_common::warmup::WarmupSchedule` (60 days,
/// 50/day ramping to unlimited) — there is deliberately no per-process
/// schedule copy here (the old `schedule` vec was a second, wrong ~9-step
/// ramp and was never read). This switch only gates the worker's send-time
/// warmup cap. It defaults ON now that `get_domain` reads the REAL warmup
/// state (the tenant's `dedicated_ips` rows, migrations 003/071/093):
/// the cap can only ever engage for a domain whose tenant actually has a
/// dedicated IP still in status 'warming' — every shared-pool domain is
/// unaffected (warmup_enabled comes back false for them).
#[derive(Debug, Clone)]
pub struct WarmupConfig {
    pub enabled: bool,
}

impl Default for WarmupConfig {
    fn default() -> Self {
        Self { enabled: true }
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

impl EmailConfig {
    /// Send-time admission rate (emails/second) enforced by the email
    /// processor's Redis token bucket before every transport.send —
    /// Audit-2: previously `SmtpConfig::rate_limit_per_second` and
    /// `SesConfig::max_send_rate` were configured but read by no send path.
    /// SES accounts use the account-level `max_send_rate`; SMTP uses the
    /// relay's `rate_limit_per_second`. `0` disables the gate.
    pub fn send_rate_per_second(&self) -> u32 {
        match self.transport_type {
            TransportType::Ses => self.ses.max_send_rate,
            TransportType::Smtp => self.smtp.rate_limit_per_second,
        }
    }
}

#[cfg(test)]
mod dlp_gate_tests {
    use super::*;
    use crate::test_support::ENV_LOCK;

    fn clear_dlp_env() {
        std::env::remove_var("WORKER_DLP_ENABLED");
    }

    /// The pre-send DLP gate defaults OFF (dev deployments keep
    /// byte-identical behavior on upgrade); only `true`/`1` enable it.
    #[test]
    fn dlp_gate_defaults_off_and_parses_the_env_switch() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        clear_dlp_env();
        assert!(
            !DlpGateConfig::from_env().enabled,
            "absent env must keep the gate OFF"
        );

        for (value, expected) in [
            ("true", true),
            ("1", true),
            (" true ", true),
            ("false", false),
            ("yes", false),
            ("0", false),
            ("", false),
        ] {
            std::env::set_var("WORKER_DLP_ENABLED", value);
            assert_eq!(
                DlpGateConfig::from_env().enabled,
                expected,
                "WORKER_DLP_ENABLED={value:?}"
            );
        }

        clear_dlp_env();
    }

    /// `Default` delegates to `from_env`, so `EmailConfig::default()`
    /// construction sites (bin/worker.rs, suites) honor the same switch.
    #[test]
    fn dlp_gate_default_reads_env() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        clear_dlp_env();
        assert!(!EmailConfig::default().dlp.enabled);

        std::env::set_var("WORKER_DLP_ENABLED", "true");
        assert!(EmailConfig::default().dlp.enabled);

        clear_dlp_env();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Audit-2: the configured per-second send rate must actually be
    /// reachable from the email processor's admission gate — the SES path
    /// plumbed from SesConfig.max_send_rate, the SMTP path from
    /// SmtpConfig.rate_limit_per_second.
    #[test]
    fn send_rate_per_second_plumbs_both_transport_configs() {
        let ses = EmailConfig::default();
        assert_eq!(
            ses.send_rate_per_second(),
            ses.ses.max_send_rate,
            "SES transport must use the account-level max_send_rate"
        );

        let smtp = EmailConfig {
            transport_type: TransportType::Smtp,
            smtp: SmtpConfig {
                rate_limit_per_second: 7,
                ..Default::default()
            },
            ..Default::default()
        };
        assert_eq!(smtp.send_rate_per_second(), 7);
    }

    /// Serializes env-mutating tests against every other module in this
    /// crate (std::env is process-global; see `crate::test_support`).
    use crate::test_support::ENV_LOCK;

    fn clear_tracking_env() {
        std::env::remove_var("TRACKING_ENABLED");
        std::env::remove_var("TRACKING_SECRET_KEY");
        std::env::remove_var("TRACKING_PUBLIC_HOST");
        std::env::remove_var("TRACKING_BASE_URL");
    }

    /// B: TRACKING_ENABLED=true flips the rewrite gate on; the shared secret
    /// is captured from the environment.
    #[test]
    fn tracking_config_parses_enabled_and_secret_from_env() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        clear_tracking_env();
        std::env::set_var("TRACKING_ENABLED", "true");
        std::env::set_var("TRACKING_SECRET_KEY", "k".repeat(40));

        let cfg = TrackingConfig::from_env();
        assert!(cfg.enabled, "TRACKING_ENABLED=true must enable the gate");
        assert_eq!(
            cfg.secret_key.as_deref().map(String::as_str),
            Some("k".repeat(40).as_str()),
            "the shared secret must be captured"
        );
        assert_eq!(cfg.base_url, "https://t.apexmail.ee");

        clear_tracking_env();
    }

    /// B: absent / non-true values keep the historical default (disabled) so
    /// existing deployments do not change behaviour implicitly; short secrets
    /// are treated as unset (policy disagreement must not half-encode).
    #[test]
    fn tracking_config_disabled_by_default_and_rejects_short_secrets() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        clear_tracking_env();
        assert!(!TrackingConfig::from_env().enabled);

        for value in ["false", "1 ", "yes", "0"] {
            std::env::set_var("TRACKING_ENABLED", value);
            let expected = value.trim() == "1";
            assert_eq!(
                TrackingConfig::from_env().enabled,
                expected,
                "TRACKING_ENABLED={value:?}"
            );
        }

        std::env::set_var("TRACKING_ENABLED", "true");
        std::env::set_var("TRACKING_SECRET_KEY", "too-short");
        let cfg = TrackingConfig::from_env();
        assert!(cfg.enabled);
        assert!(
            cfg.secret_key.is_none(),
            "a short secret must be treated as unset"
        );

        clear_tracking_env();
    }

    /// B: Default delegates to from_env so `..Default::default()` construction
    /// sites (bin/worker.rs and EmailConfig) pick up the env-driven fields.
    #[test]
    fn tracking_config_default_reads_env() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        clear_tracking_env();
        std::env::set_var("TRACKING_ENABLED", "true");
        assert!(TrackingConfig::default().enabled);

        std::env::set_var("TRACKING_ENABLED", "false");
        assert!(!TrackingConfig::default().enabled);

        clear_tracking_env();
    }
}

#[cfg(test)]
mod sales_transport_config_tests {
    use super::*;
    use crate::test_support::ENV_LOCK;

    const SALES_ENV: [&str; 7] = [
        "SALES_TRANSPORT",
        "SALES_SENDING_DOMAINS",
        "SALES_RELAY_URL",
        "SALES_SES_REGION",
        "SALES_SES_CONFIGURATION_SET",
        "SALES_SES_ACCESS_KEY_ID",
        "SALES_SES_SECRET_ACCESS_KEY",
    ];

    fn clear_sales_env() {
        for name in SALES_ENV {
            std::env::remove_var(name);
        }
    }

    /// The mode switch: absent is NONE (fail closed — sales mail is held,
    /// never routed through the customer transport), every documented
    /// spelling maps, and an UNRECOGNIZED value fails closed to NONE rather
    /// than being treated as "configured".
    #[test]
    fn sales_transport_mode_parses_documented_values_and_fails_closed() {
        assert_eq!(
            SalesTransportMode::parse("none"),
            Some(SalesTransportMode::None)
        );
        assert_eq!(
            SalesTransportMode::parse(""),
            Some(SalesTransportMode::None)
        );
        assert_eq!(
            SalesTransportMode::parse(" relay "),
            Some(SalesTransportMode::Relay)
        );
        assert_eq!(
            SalesTransportMode::parse("SES_ACCOUNT"),
            Some(SalesTransportMode::SesAccount)
        );
        assert_eq!(
            SalesTransportMode::parse("something-else"),
            None,
            "an unknown mode must never parse as configured"
        );
        assert!(!SalesTransportMode::None.is_configured());
        assert!(SalesTransportMode::Relay.is_configured());
        assert!(SalesTransportMode::SesAccount.is_configured());
        assert_eq!(SalesTransportMode::default(), SalesTransportMode::None);
    }

    /// Absent env: the default is an UNCONFIGURED sales slot with an empty
    /// allowlist — nothing is guessed, nothing falls back.
    #[test]
    fn sales_config_defaults_to_unconfigured_and_holds() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        clear_sales_env();
        let config = SalesTransportConfig::from_env();
        assert_eq!(config.mode, SalesTransportMode::None);
        assert!(config.relay.is_none());
        assert!(config.ses_account.is_none());
        assert!(config.sending_domains.is_empty());
        assert!(!config.domain_allowed("sales.example.com"));
        assert!(config.is_provisioned(), "`none` needs no material");
        clear_sales_env();
    }

    /// The allowlist parser: trimmed, lowercased, dot-stripped, deduplicated,
    /// order preserved; an empty list allows NOTHING.
    #[test]
    fn sales_sending_domains_parse_normalizes_and_allows_nothing_when_empty() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        clear_sales_env();
        assert_eq!(
            SalesTransportConfig::parse_sending_domains(
                " Sales.ApexMail.EE , sales.apexmail.ee,outbound.example.com., , "
            ),
            vec!["sales.apexmail.ee", "outbound.example.com"]
        );
        assert!(SalesTransportConfig::parse_sending_domains(" , ").is_empty());
        let config = SalesTransportConfig::from_env();
        assert!(!config.domain_allowed("anything.example"));
        clear_sales_env();
    }

    /// `SALES_RELAY_URL` parsing: bare `smtp(s)://host` endpoints only. The
    /// scheme selects the TLS posture; ports, user info, paths and unknown
    /// schemes are refused (an endpoint that cannot mean what it says must
    /// not be silently accepted).
    #[test]
    fn sales_relay_url_parses_only_bare_endpoints() {
        let plain = SalesRelayConfig::parse("smtp://relay.sales.example").expect("plain smtp");
        assert_eq!(plain.host, "relay.sales.example");
        assert!(
            !plain.require_starttls,
            "smtp:// keeps the relay's per-destination-port TLS policy"
        );

        let secure = SalesRelayConfig::parse("smtps://relay.sales.example").expect("smtps");
        assert!(secure.require_starttls);
        let trailing = SalesRelayConfig::parse("smtps://relay.sales.example/").expect("slash");
        assert_eq!(trailing, secure, "a bare trailing slash is harmless");

        for bad in [
            "",
            "relay.sales.example",
            "http://relay.sales.example",
            "smtp://",
            "smtp://user:secret@relay.sales.example",
            "smtp://relay.sales.example:587",
            "smtp://relay.sales.example:not-a-port",
            "smtp://relay.sales.example/submission",
            "smtp://relay .sales.example",
        ] {
            assert!(
                SalesRelayConfig::parse(bad).is_none(),
                "{bad:?} must not parse as a relay endpoint"
            );
        }
    }

    /// The env-driven mode requires its material: `relay` without
    /// `SALES_RELAY_URL` (and `ses_account` without `SALES_SES_*`) is
    /// MISCONFIGURED — the caller refuses to boot, never silently holds.
    #[test]
    fn selected_sales_mode_without_material_is_unprovisioned() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        clear_sales_env();

        std::env::set_var("SALES_TRANSPORT", "relay");
        std::env::set_var("SALES_SENDING_DOMAINS", "sales.example.com");
        let relay_missing = SalesTransportConfig::from_env();
        assert_eq!(relay_missing.mode, SalesTransportMode::Relay);
        assert!(!relay_missing.is_provisioned());

        std::env::set_var("SALES_RELAY_URL", "smtps://relay.sales.example");
        std::env::set_var("SALES_SES_ACCESS_KEY_ID", "AKIA-not-used-in-relay-mode");
        let relay_ready = SalesTransportConfig::from_env();
        assert!(relay_ready.is_provisioned());
        assert!(relay_ready.relay.is_some());
        assert!(
            relay_ready.ses_account.is_none(),
            "the non-selected mode's credentials are never read"
        );

        std::env::set_var("SALES_TRANSPORT", "ses_account");
        let ses_missing = SalesTransportConfig::from_env();
        assert_eq!(ses_missing.mode, SalesTransportMode::SesAccount);
        assert!(
            !ses_missing.is_provisioned(),
            "ses_account without SALES_SES_SECRET_ACCESS_KEY is unprovisioned"
        );

        std::env::set_var("SALES_SES_SECRET_ACCESS_KEY", "secret");
        let ses_ready = SalesTransportConfig::from_env();
        assert!(ses_ready.is_provisioned());
        assert_eq!(
            ses_ready
                .ses_account
                .as_ref()
                .map(|ses| ses.access_key_id.as_str()),
            Some("AKIA-not-used-in-relay-mode")
        );

        // An unrecognized switch value fails CLOSED to `none`.
        std::env::set_var("SALES_TRANSPORT", "carrier-pigeon");
        let unknown = SalesTransportConfig::from_env();
        assert_eq!(unknown.mode, SalesTransportMode::None);

        clear_sales_env();
    }

    /// `EmailConfig::default()` picks the sales slot up from the environment
    /// (the same env-driven construction contract as the DLP/tracking
    /// switches), and the field defaults to the unconfigured mode in tests
    /// that do not set it.
    #[test]
    fn email_config_default_carries_the_sales_slot() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        clear_sales_env();
        assert_eq!(
            EmailConfig::default().sales.mode,
            SalesTransportMode::None,
            "the shipped default must be the fail-closed (unconfigured) mode"
        );
        clear_sales_env();
    }
}

#[cfg(test)]
mod default_tests {
    use super::*;

    #[test]
    fn analytics_defaults_are_documented_values() {
        let config = AnalyticsConfig::default();
        assert_eq!(config.base.name, "analytics");
        assert_eq!(config.stats_ttl, Duration::from_secs(7 * 24 * 60 * 60));
        assert_eq!(config.base.concurrency, 10);
    }

    #[test]
    fn transport_type_from_env_selects_smtp_only_on_smtp() {
        assert_eq!(TransportType::from_env("smtp"), TransportType::Smtp);
        assert_eq!(TransportType::from_env("SMTP"), TransportType::Smtp);
        assert_eq!(TransportType::from_env("ses"), TransportType::Ses);
        assert_eq!(TransportType::from_env(""), TransportType::Ses);
        assert_eq!(TransportType::from_env("anything-else"), TransportType::Ses);
        assert_eq!(TransportType::default(), TransportType::Ses);
    }
}
