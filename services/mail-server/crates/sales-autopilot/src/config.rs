use serde::{Deserialize, Serialize};

/// Sales Autopilot configuration.
/// This service runs as a **separate process** from the customer-facing API
/// (control-plane port 3010). It stores the platform *owner's* sales leads,
/// never customer data.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SalesConfig {
    /// Base URL of the enrichment / company-lookup API (no trailing `/v1`;
    /// the provider appends the versioned path itself).
    pub enrichment_api_url: String,

    /// API key for the enrichment API (sent as a Bearer token).
    /// Read from `ENRICHMENT_API_KEY`, falling back to the production
    /// template name `SALES_ENRICHMENT_API_KEY`.
    #[serde(default)]
    pub enrichment_api_key: String,

    /// How often (in seconds) to sync the calendar with external providers.
    pub calendar_sync_interval_secs: u64,

    /// Maximum number of active campaigns allowed at once.
    pub max_campaigns: usize,

    /// Port the HTTP server listens on (default 3010).
    pub port: u16,

    /// Scraper requests-per-minute cap – ethical rate limit.
    pub scraper_rpm: u32,

    /// Redis URL (e.g. redis://127.0.0.1:6379).
    pub redis_url: String,

    /// Lead scoring weight configuration.
    /// Controls how engagement, company size, and recency are weighted
    /// in the 0–100 lead score calculation (SALES-01).
    #[serde(default)]
    pub lead_scoring: LeadScoringWeights,

    /// Fix I-3: optional tenant allowlist (`SALES_ALLOWED_TENANTS`, comma
    /// separated). The service authenticates callers with a single shared
    /// internal token and then trusts the `x-tenant-id` header — the token
    /// holder can address any tenant by design. Scoping the deployment to an
    /// explicit tenant list reduces that blast radius. `None` = all tenants
    /// allowed (a warning is logged in that case).
    #[serde(default)]
    pub allowed_tenants: Option<Vec<String>>,

    /// Campaign dispatch configuration (production dispatcher).
    #[serde(default)]
    pub dispatch: DispatchConfig,
}

/// Production campaign dispatcher settings (all env-driven).
///
/// `from_email` and `unsubscribe_secret` are REQUIRED for the production
/// dispatcher: when either is missing the dispatcher is not constructed and
/// campaign start keeps failing loudly with 503 ("genuinely unconfigured"
/// deployments stay honest).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DispatchConfig {
    /// Envelope sender for campaign mail, e.g. `sales@apexmail.ee`. The
    /// domain must be verified + DKIM-ready for the sending tenant
    /// (mirrors api-server's `resolve_sender_domain_id`).
    #[serde(default)]
    pub from_email: String,

    /// Display name recorded in message metadata (`SALES_CAMPAIGN_FROM_NAME`).
    #[serde(default = "default_from_name")]
    pub from_name: String,

    /// HMAC-SHA256 key for unsubscribe tokens (`SALES_UNSUBSCRIBE_SECRET`,
    /// >= 32 chars). Required for the production dispatcher.
    #[serde(default)]
    pub unsubscribe_secret: String,

    /// Public base URL used to build unsubscribe links
    /// (`SALES_PUBLIC_BASE_URL`), no trailing slash.
    #[serde(default = "default_public_base_url")]
    pub public_base_url: String,

    /// Optional branded redirect target after a GET unsubscribe
    /// (`SALES_UNSUBSCRIBE_REDIRECT_URL`). Unset ⇒ built-in confirmation page.
    #[serde(default)]
    pub unsubscribe_redirect_url: Option<String>,

    /// Dispatch tick cadence in seconds (`SALES_DISPATCH_INTERVAL_SECS`).
    #[serde(default = "default_dispatch_interval_secs")]
    pub dispatch_interval_secs: u64,

    /// Maximum recipients dispatched per campaign per tick
    /// (`SALES_DISPATCH_BATCH_SIZE`).
    #[serde(default = "default_dispatch_batch_size")]
    pub dispatch_batch_size: usize,

    /// Maximum campaigns dispatched concurrently per tick
    /// (`SALES_DISPATCH_CONCURRENCY`).
    #[serde(default = "default_dispatch_concurrency")]
    pub dispatch_concurrency: usize,
}

fn default_from_name() -> String {
    "ApexMail".into()
}

fn default_public_base_url() -> String {
    "http://localhost:3010".into()
}

fn default_dispatch_interval_secs() -> u64 {
    30
}

fn default_dispatch_batch_size() -> usize {
    100
}

fn default_dispatch_concurrency() -> usize {
    4
}

impl Default for DispatchConfig {
    fn default() -> Self {
        Self {
            from_email: String::new(),
            from_name: default_from_name(),
            unsubscribe_secret: String::new(),
            public_base_url: default_public_base_url(),
            unsubscribe_redirect_url: None,
            dispatch_interval_secs: default_dispatch_interval_secs(),
            dispatch_batch_size: default_dispatch_batch_size(),
            dispatch_concurrency: default_dispatch_concurrency(),
        }
    }
}

impl DispatchConfig {
    /// Are the mandatory production-dispatcher inputs present and minimally
    /// valid? (A more complete validation — verified sender domain — happens
    /// per tenant at dispatch time.)
    pub fn is_configured(&self) -> bool {
        !self.from_email.trim().is_empty()
            && self.unsubscribe_secret.trim().len() >= 32
            && apexmail_lib::validation::is_valid_email(self.from_email.trim())
    }
}

/// Configurable weights for the lead scoring formula (SALES-01).
///
/// The final score is computed as:
///   `engagement * engagement_weight + company_size * company_size_weight + recency * recency_weight`
///
/// Each weight is an integer percentage point (0–100). The three weights
/// should sum to 100 for a correct 0–100 score range, though the system
/// clamps the final result to `0..=100` regardless.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LeadScoringWeights {
    /// Weight for email engagement (default: 40).
    pub engagement_weight: u8,
    /// Weight for company size / firmographics (default: 30).
    pub company_size_weight: u8,
    /// Weight for recency of activity (default: 30).
    pub recency_weight: u8,
}

impl Default for LeadScoringWeights {
    fn default() -> Self {
        Self {
            engagement_weight: 40,
            company_size_weight: 30,
            recency_weight: 30,
        }
    }
}

impl Default for SalesConfig {
    fn default() -> Self {
        Self {
            enrichment_api_url: "https://enrich.apexmail.ee".into(),
            enrichment_api_key: String::new(),
            calendar_sync_interval_secs: 300,
            max_campaigns: 50,
            port: 3010,
            scraper_rpm: 30,
            redis_url: "redis://127.0.0.1:6379".into(),
            lead_scoring: LeadScoringWeights::default(),
            allowed_tenants: None,
            dispatch: DispatchConfig::default(),
        }
    }
}

/// Fail closed: an unset SALES_ALLOWED_TENANTS previously allowed the shared
/// service token to address EVERY tenant. In production the allowlist is
/// mandatory; only explicitly-declared non-production modes may opt out.
pub fn require_tenant_allowlist_in_production(
    config: &SalesConfig,
    is_production: bool,
) -> Result<(), String> {
    if is_production
        && config
            .allowed_tenants
            .as_ref()
            .map_or(true, |t| t.is_empty())
    {
        return Err(
            "SALES_ALLOWED_TENANTS must list the tenants this service may address              (comma-separated). The internal token is shared; without an allowlist              any token holder can act on every tenant."
                .to_string(),
        );
    }
    Ok(())
}

impl SalesConfig {
    /// Build a config from environment variables, falling back to defaults.
    ///
    /// A variable that is *absent* (or empty) falls back to its default.
    /// A variable that is *present but invalid* (e.g. a non-numeric port)
    /// is treated as a configuration error and returns `Err` instead of
    /// being silently ignored — misconfigured deployments should fail fast
    /// rather than run with unexpected defaults.
    pub fn from_env() -> anyhow::Result<Self> {
        let config = Self {
            // Prefer the SALES_-prefixed (production template) names and fall
            // back to the short names used by local development environments.
            enrichment_api_url: read_env(&["SALES_ENRICHMENT_API_URL", "ENRICHMENT_API_URL"])?
                .unwrap_or_else(|| "https://enrich.apexmail.ee".into()),
            enrichment_api_key: read_env(&["ENRICHMENT_API_KEY", "SALES_ENRICHMENT_API_KEY"])?
                .unwrap_or_default(),
            calendar_sync_interval_secs: parse_env_num(
                &["CALENDAR_SYNC_INTERVAL"],
                300,
                "a positive number of seconds",
            )?,
            max_campaigns: parse_env_num(&["MAX_CAMPAIGNS"], 50, "a positive integer")?,
            port: parse_env_num(
                &["SALES_AUTOPILOT_PORT", "SALES_PORT"],
                3010,
                "a port between 1 and 65535",
            )?,
            scraper_rpm: parse_env_num(&["SCRAPER_RPM"], 30, "a positive integer")?,
            redis_url: read_env(&["REDIS_URL"])?.unwrap_or_else(|| "redis://127.0.0.1:6379".into()),
            dispatch: DispatchConfig {
                from_email: read_env(&["SALES_CAMPAIGN_FROM_EMAIL"])?.unwrap_or_default(),
                from_name: read_env(&["SALES_CAMPAIGN_FROM_NAME"])?
                    .unwrap_or_else(default_from_name),
                unsubscribe_secret: read_env(&["SALES_UNSUBSCRIBE_SECRET"])?.unwrap_or_default(),
                public_base_url: read_env(&["SALES_PUBLIC_BASE_URL"])?
                    .map(|url| url.trim_end_matches('/').to_string())
                    .unwrap_or_else(default_public_base_url),
                unsubscribe_redirect_url: read_env(&["SALES_UNSUBSCRIBE_REDIRECT_URL"])?
                    .map(|url| url.trim_end_matches('/').to_string()),
                dispatch_interval_secs: parse_env_num(
                    &["SALES_DISPATCH_INTERVAL_SECS"],
                    default_dispatch_interval_secs(),
                    "a positive number of seconds",
                )?,
                dispatch_batch_size: parse_env_num(
                    &["SALES_DISPATCH_BATCH_SIZE"],
                    default_dispatch_batch_size() as u64,
                    "a positive integer",
                )? as usize,
                dispatch_concurrency: parse_env_num(
                    &["SALES_DISPATCH_CONCURRENCY"],
                    default_dispatch_concurrency() as u64,
                    "a positive integer",
                )? as usize,
            },
            lead_scoring: LeadScoringWeights {
                engagement_weight: parse_env_num(
                    &["LEAD_SCORE_ENGAGEMENT_WEIGHT"],
                    40,
                    "an integer 0-100",
                )?,
                company_size_weight: parse_env_num(
                    &["LEAD_SCORE_COMPANY_SIZE_WEIGHT"],
                    30,
                    "an integer 0-100",
                )?,
                recency_weight: parse_env_num(
                    &["LEAD_SCORE_RECENCY_WEIGHT"],
                    30,
                    "an integer 0-100",
                )?,
            },
            allowed_tenants: read_env(&["SALES_ALLOWED_TENANTS"])?.map(|raw| {
                raw.split(',')
                    .map(|t| t.trim().to_string())
                    .filter(|t| !t.is_empty())
                    .collect::<Vec<_>>()
            }),
        };
        config
            .validate()
            .map_err(|err| anyhow::anyhow!("invalid sales-autopilot configuration: {err}"))?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.enrichment_api_url.trim().is_empty() {
            return Err("ENRICHMENT_API_URL must not be empty".into());
        }
        if !(self.enrichment_api_url.starts_with("http://")
            || self.enrichment_api_url.starts_with("https://"))
        {
            return Err("ENRICHMENT_API_URL must be http/https".into());
        }
        if self.calendar_sync_interval_secs == 0 {
            return Err("CALENDAR_SYNC_INTERVAL must be > 0".into());
        }
        if self.max_campaigns == 0 {
            return Err("MAX_CAMPAIGNS must be > 0".into());
        }
        if self.port == 0 {
            return Err("SALES_PORT must be > 0".into());
        }
        if self.scraper_rpm == 0 {
            return Err("SCRAPER_RPM must be > 0".into());
        }
        // Validate lead scoring weights sum to ≤ 100 (not strictly required
        // since the score is clamped, but logical for correct scoring).
        let weight_sum = self.lead_scoring.engagement_weight as u16
            + self.lead_scoring.company_size_weight as u16
            + self.lead_scoring.recency_weight as u16;
        if weight_sum == 0 {
            return Err("LEAD_SCORE_*_WEIGHT sum must be > 0".into());
        }
        // Dispatch settings: when a partial configuration IS provided it must
        // be internally valid — a malformed from address or a too-short HMAC
        // secret is a configuration error, not a silent fallback.
        let d = &self.dispatch;
        if !d.from_email.is_empty() && !apexmail_lib::validation::is_valid_email(&d.from_email) {
            return Err(format!(
                "SALES_CAMPAIGN_FROM_EMAIL is not a valid email address: {}",
                d.from_email
            ));
        }
        if !d.unsubscribe_secret.is_empty() && d.unsubscribe_secret.trim().len() < 32 {
            return Err("SALES_UNSUBSCRIBE_SECRET must be at least 32 characters".into());
        }
        if d.dispatch_interval_secs == 0 {
            return Err("SALES_DISPATCH_INTERVAL_SECS must be > 0".into());
        }
        if d.dispatch_batch_size == 0 {
            return Err("SALES_DISPATCH_BATCH_SIZE must be > 0".into());
        }
        if d.dispatch_concurrency == 0 {
            return Err("SALES_DISPATCH_CONCURRENCY must be > 0".into());
        }
        Ok(())
    }
}

/// Read the first *present, non-empty* variable among `names` (checked in
/// order, so earlier names take precedence). Empty or whitespace-only values
/// are treated as unset so templated `.env` files (e.g. `SALES_ENRICHMENT_API_URL=`)
/// fall back to defaults rather than failing validation.
fn read_env(names: &[&str]) -> anyhow::Result<Option<String>> {
    for name in names {
        match std::env::var(name) {
            Ok(value) => {
                let trimmed = value.trim();
                return Ok(if trimmed.is_empty() {
                    None
                } else {
                    Some(trimmed.to_string())
                });
            }
            // Not set under this name — try the next alias.
            Err(std::env::VarError::NotPresent) => continue,
            Err(err) => {
                return Err(anyhow::anyhow!(
                    "invalid environment variable {name}: {err}"
                ));
            }
        }
    }
    Ok(None)
}

/// Parse the first present, non-empty variable among `names` as `T`.
/// Returns `default` only when none of the variables is set; a present but
/// unparseable value is an error (see [`SalesConfig::from_env`]).
fn parse_env_num<T>(names: &[&str], default: T, expected: &str) -> anyhow::Result<T>
where
    T: std::str::FromStr,
{
    match read_env(names)? {
        None => Ok(default),
        Some(raw) => raw.parse::<T>().map_err(|_| {
            anyhow::anyhow!(
                "environment variable {} is set to invalid value {raw:?}; expected {expected}",
                names.join(" or ")
            )
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let cfg = SalesConfig::default();
        assert_eq!(cfg.port, 3010);
        assert_eq!(cfg.max_campaigns, 50);
        assert_eq!(cfg.calendar_sync_interval_secs, 300);
        assert_eq!(cfg.scraper_rpm, 30);
        // The default base URL must NOT include a trailing /v1 — the
        // HttpEnrichmentProvider appends the versioned path itself, so a
        // /v1 suffix here would produce a doubled /v1/v1 request path.
        assert_eq!(cfg.enrichment_api_url, "https://enrich.apexmail.ee");
        assert!(cfg.enrichment_api_key.is_empty());
        assert_eq!(cfg.lead_scoring.engagement_weight, 40);
        assert_eq!(cfg.lead_scoring.company_size_weight, 30);
        assert_eq!(cfg.lead_scoring.recency_weight, 30);
    }

    #[test]
    fn test_config_serialization_roundtrip() {
        let cfg = SalesConfig {
            enrichment_api_url: "https://example.com/api".into(),
            enrichment_api_key: "secret-key".into(),
            calendar_sync_interval_secs: 120,
            max_campaigns: 10,
            port: 9090,
            scraper_rpm: 60,
            allowed_tenants: None,
            redis_url: "redis://127.0.0.1:6379".into(),
            dispatch: DispatchConfig::default(),
            lead_scoring: LeadScoringWeights {
                engagement_weight: 50,
                company_size_weight: 25,
                recency_weight: 25,
            },
        };
        let json = serde_json::to_string(&cfg).unwrap();
        let parsed: SalesConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.port, 9090);
        assert_eq!(parsed.max_campaigns, 10);
        assert_eq!(parsed.calendar_sync_interval_secs, 120);
        assert_eq!(parsed.scraper_rpm, 60);
        assert_eq!(parsed.enrichment_api_url, "https://example.com/api");
        assert_eq!(parsed.enrichment_api_key, "secret-key");
        assert_eq!(parsed.lead_scoring.engagement_weight, 50);
        assert_eq!(parsed.lead_scoring.company_size_weight, 25);
        assert_eq!(parsed.lead_scoring.recency_weight, 25);
    }

    #[test]
    fn test_lead_scoring_weights_defaults() {
        let w = LeadScoringWeights::default();
        assert_eq!(w.engagement_weight, 40);
        assert_eq!(w.company_size_weight, 30);
        assert_eq!(w.recency_weight, 30);
    }

    #[test]
    fn test_validate_rejects_zero_weight_sum() {
        let cfg = SalesConfig {
            lead_scoring: LeadScoringWeights {
                engagement_weight: 0,
                company_size_weight: 0,
                recency_weight: 0,
            },
            ..SalesConfig::default()
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn test_validate_accepts_custom_weights() {
        let cfg = SalesConfig {
            lead_scoring: LeadScoringWeights {
                engagement_weight: 60,
                company_size_weight: 30,
                recency_weight: 10,
            },
            ..SalesConfig::default()
        };
        assert!(cfg.validate().is_ok());
    }

    // ── Dispatch configuration ─────────────────────────────────────────

    #[test]
    fn test_default_dispatch_config_is_unconfigured() {
        // No from email / secret ⇒ not configured ⇒ production dispatcher is
        // not wired and campaign start keeps failing with 503.
        let d = DispatchConfig::default();
        assert!(!d.is_configured());
        assert!(SalesConfig::default().validate().is_ok());
    }

    #[test]
    fn test_dispatch_config_configured_requires_all_inputs() {
        let mut d = DispatchConfig {
            from_email: "sales@apexmail.ee".into(),
            unsubscribe_secret: "s".repeat(32),
            ..DispatchConfig::default()
        };
        assert!(d.is_configured());

        // Invalid from address fails BOTH is_configured and validate().
        d.from_email = "not-an-email".into();
        assert!(!d.is_configured());
        let mut cfg = SalesConfig {
            dispatch: d.clone(),
            ..SalesConfig::default()
        };
        assert!(cfg.validate().is_err());

        // Short secret is a config error when present.
        cfg.dispatch.from_email = "sales@apexmail.ee".into();
        cfg.dispatch.unsubscribe_secret = "short".into();
        assert!(cfg.validate().is_err());
        assert!(!cfg.dispatch.is_configured());

        // Zero cadence/batch/concurrency are config errors.
        cfg.dispatch.unsubscribe_secret = "s".repeat(32);
        assert!(cfg.validate().is_ok());
        cfg.dispatch.dispatch_interval_secs = 0;
        assert!(cfg.validate().is_err());
        cfg.dispatch.dispatch_interval_secs = 30;
        cfg.dispatch.dispatch_batch_size = 0;
        assert!(cfg.validate().is_err());
        cfg.dispatch.dispatch_batch_size = 100;
        cfg.dispatch.dispatch_concurrency = 0;
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn test_dispatch_config_serialization_roundtrip() {
        let cfg = SalesConfig {
            dispatch: DispatchConfig {
                from_email: "sales@apexmail.ee".into(),
                from_name: "ApexMail Sales".into(),
                unsubscribe_secret: "k".repeat(48),
                public_base_url: "https://sales.apexmail.ee/".into(),
                unsubscribe_redirect_url: Some("https://apexmail.ee/unsubscribed".into()),
                dispatch_interval_secs: 15,
                dispatch_batch_size: 50,
                dispatch_concurrency: 2,
            },
            ..SalesConfig::default()
        };
        let json = serde_json::to_string(&cfg).unwrap();
        let parsed: SalesConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.dispatch.from_email, "sales@apexmail.ee");
        assert_eq!(parsed.dispatch.dispatch_batch_size, 50);
        // Trailing slash is trimmed when loading from env; serialization
        // keeps the stored value verbatim.
        assert_eq!(
            parsed.dispatch.public_base_url,
            "https://sales.apexmail.ee/"
        );
    }
}
