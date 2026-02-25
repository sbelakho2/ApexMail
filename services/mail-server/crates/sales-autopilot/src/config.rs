use serde::{Deserialize, Serialize};

/// Sales Autopilot configuration.
///
/// This service runs as a **separate process** from the customer-facing API
/// (control-plane port 3010). It stores the platform *owner's* sales leads,
/// never customer data.
#[derive(Debug, Clone, Serialize, Deserialize)]
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
}

impl Default for SalesConfig {
    fn default() -> Self {
        Self {
            enrichment_api_url: "https://enrich.apexmail.ee/v1".into(),
            calendar_sync_interval_secs: 300,
            max_campaigns: 50,
            port: 3010,
            scraper_rpm: 30,
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
        };
        if let Err(err) = config.validate() {
            panic!("Invalid sales-autopilot config: {err}");
        }
        config
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.enrichment_api_url.trim().is_empty() {
            return Err("ENRICHMENT_API_URL must not be empty".into());
        }
        if !(self.enrichment_api_url.starts_with("http://") || self.enrichment_api_url.starts_with("https://")) {
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
    }

    #[test]
    fn test_config_serialization_roundtrip() {
        let cfg = SalesConfig {
            enrichment_api_url: "https://example.com/api".into(),
            calendar_sync_interval_secs: 120,
            max_campaigns: 10,
            port: 9090,
            scraper_rpm: 60,
        };
        let json = serde_json::to_string(&cfg).unwrap();
        let parsed: SalesConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.port, 9090);
        assert_eq!(parsed.max_campaigns, 10);
        assert_eq!(parsed.calendar_sync_interval_secs, 120);
        assert_eq!(parsed.scraper_rpm, 60);
        assert_eq!(parsed.enrichment_api_url, "https://example.com/api");
    }
}
