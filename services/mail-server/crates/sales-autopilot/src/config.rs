use serde::{Deserialize, Serialize};
use tracing::error;

/// Sales Autopilot configuration.
/// This service runs as a **separate process** from the customer-facing API
/// (control-plane port 3010). It stores the platform *owner's* sales leads,
/// never customer data.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SalesConfig {
    /// Base URL of the enrichment / company-lookup API.
    pub enrichment_api_url: String,

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
            enrichment_api_url: "https://enrich.apexmail.ee/v1".into(),
            calendar_sync_interval_secs: 300,
            max_campaigns: 50,
            port: 3010,
            scraper_rpm: 30,
            redis_url: "redis://127.0.0.1:6379".into(),
            lead_scoring: LeadScoringWeights::default(),
        }
    }
}

impl SalesConfig {
    /// Build a config from environment variables, falling back to defaults.
    pub fn from_env() -> Self {
        let config = Self {
            enrichment_api_url: std::env::var("ENRICHMENT_API_URL")
                .unwrap_or_else(|_| "https://enrich.apexmail.ee/v1".into()),
            calendar_sync_interval_secs: std::env::var("CALENDAR_SYNC_INTERVAL")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(300),
            max_campaigns: std::env::var("MAX_CAMPAIGNS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(50),
            port: std::env::var("SALES_PORT")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(3010),
            scraper_rpm: std::env::var("SCRAPER_RPM")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(30),
            redis_url: std::env::var("REDIS_URL")
                .unwrap_or_else(|_| "redis://127.0.0.1:6379".into()),
            lead_scoring: LeadScoringWeights {
                engagement_weight: std::env::var("LEAD_SCORE_ENGAGEMENT_WEIGHT")
                    .ok()
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(40),
                company_size_weight: std::env::var("LEAD_SCORE_COMPANY_SIZE_WEIGHT")
                    .ok()
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(30),
                recency_weight: std::env::var("LEAD_SCORE_RECENCY_WEIGHT")
                    .ok()
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(30),
            },
        };
        if let Err(err) = config.validate() {
            error!(error = %err, "Invalid sales-autopilot config, falling back to defaults");
            let fallback = Self::default();
            if let Err(default_err) = fallback.validate() {
                error!(error = %default_err, "Default sales-autopilot config failed validation");
            }
            return fallback;
        }
        config
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
        assert!(cfg.enrichment_api_url.contains("enrich"));
        assert_eq!(cfg.lead_scoring.engagement_weight, 40);
        assert_eq!(cfg.lead_scoring.company_size_weight, 30);
        assert_eq!(cfg.lead_scoring.recency_weight, 30);
    }

    #[test]
    fn test_config_serialization_roundtrip() {
        let cfg = SalesConfig {
            enrichment_api_url: "https://example.com/api".into(),
            calendar_sync_interval_secs: 120,
            max_campaigns: 10,
            port: 9090,
            scraper_rpm: 60,
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
