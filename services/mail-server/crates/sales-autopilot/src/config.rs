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
        }
    }
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
}
