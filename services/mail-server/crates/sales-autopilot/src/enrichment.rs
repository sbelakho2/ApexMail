use std::time::Duration;

use chrono::Utc;
use tracing::debug;
use uuid::Uuid;

use crate::types::{Company, SalesError};

/// Maximum number of retry attempts for enrichment API calls.
const MAX_RETRIES: u32 = 3;
/// Initial backoff delay (doubles each retry).
const INITIAL_BACKOFF_MS: u64 = 200;

/// Execute a fallible async operation with exponential backoff retry.
/// Returns `Ok(value)` on success, or the last error after exhausting retries.
pub async fn with_retry<F, Fut, T, E>(f: F) -> Result<T, E>
where
    F: Fn() -> Fut,
    Fut: std::future::Future<Output = Result<T, E>>,
    E: std::fmt::Display,
{
    let mut delay = Duration::from_millis(INITIAL_BACKOFF_MS);
    let mut last_err = None;

    for attempt in 1..=MAX_RETRIES {
        match f().await {
            Ok(val) => return Ok(val),
            Err(e) => {
                if attempt == MAX_RETRIES {
                    return Err(e);
                }
                debug!(
                    attempt,
                    max_retries = MAX_RETRIES,
                    error = %e,
                    backoff_ms = delay.as_millis(),
                    "enrichment API call failed, retrying"
                );
                tokio::time::sleep(delay).await;
                delay *= 2;
                last_err = Some(e);
            }
        }
    }

    Err(last_err.expect("retry loop should have produced at least one error"))
}

/// Company enrichment service.
/// Given a lead email or domain, it resolves firmographic data (industry,
/// employee band, revenue range, …). The real implementation fans out to
/// external APIs; this crate ships a deterministic mock so tests are
/// hermetic and deterministic.
///
/// # Security (O-12.3)
///
/// **Root cause**: The enrichment service shipped with hardcoded deterministic
/// mock data keyed on domain name. There was no way to distinguish mock data
/// from real enrichment API responses at the call site. In production, this
/// could lead to incorrect business decisions based on fake enrichment data.
///
/// **Fix**: Added a `mock_enabled: bool` flag to `EnrichmentService`. When
/// `mock_enabled` is `true`, the service returns the deterministic mock data.
/// When `false` (production mode), the service should connect to a real
/// enrichment API (Clearbit, Hunter, etc.). The flag is logged and exposed
/// via `is_mock_enabled()` for visibility. The `new()` constructor defaults
/// to mock mode for backward compatibility; use `EnrichmentService::production()`
/// for real deployments.
#[derive(Debug, Clone)]
pub struct EnrichmentService {
    /// Base URL of the external enrichment API (unused in mock mode).
    api_url: String,
    /// When `true`, returns deterministic mock data instead of calling an
    /// external API. Defaults to `true` for backward compatibility.
    mock_enabled: bool,
}

impl EnrichmentService {
    /// Create a new enrichment service with mock data enabled (default).
    /// This is suitable for testing and development.
    pub fn new(api_url: &str) -> Self {
        Self {
            api_url: api_url.to_owned(),
            mock_enabled: true,
        }
    }

    /// Create a new enrichment service for production use.
    /// Mock data is disabled; the service will attempt to call the external API.
    pub fn production(api_url: &str) -> Self {
        Self {
            api_url: api_url.to_owned(),
            mock_enabled: false,
        }
    }

    /// Returns `true` if the service is returning mock (deterministic) data.
    pub fn is_mock_enabled(&self) -> bool {
        self.mock_enabled
    }

    /// Extract the domain portion from an email address.
    /// Returns `None` if the address is malformed.
    pub fn extract_domain(email: &str) -> Option<String> {
        let parts: Vec<&str> = email.splitn(2, '@').collect();
        if parts.len() == 2 && !parts[1].is_empty() {
            Some(parts[1].to_lowercase())
        } else {
            None
        }
    }

    /// Enrich a lead by email – extracts the domain and delegates to
    /// [`enrich_company`].
    pub fn enrich_lead(&self, email: &str) -> Result<Company, SalesError> {
        let domain = Self::extract_domain(email)
            .ok_or_else(|| SalesError::InvalidInput(format!("bad email: {email}")))?;
        self.enrich_company(&domain)
    }

    /// Look up (or mock) company data for a domain.
    ///
    /// When `mock_enabled` is true (default), returns deterministic mock data
    /// keyed on domain name. When false (production mode), this will attempt
    /// to call the external enrichment API.
    pub fn enrich_company(&self, domain: &str) -> Result<Company, SalesError> {
        if self.mock_enabled {
            debug!(api_url = %self.api_url, mock_enabled = %self.mock_enabled, "using mock enrichment backend");
        } else {
            // Production mode — real API integration should go here.
            // For now, return an error so call-sites are aware no real data
            // is being returned.
            debug!(api_url = %self.api_url, mock_enabled = %self.mock_enabled, "production enrichment API not yet implemented");
            return Err(SalesError::InvalidInput(
                "Real enrichment API not configured; set mock_enabled=true for mock data".into(),
            ));
        }

        // Deterministic mock data keyed on domain.
        let (name, industry, size, revenue) = match domain {
            "acme.com" => ("Acme Corp", "SaaS", "50-200", "$5M-$20M"),
            "beta.io" => ("Beta Inc", "FinTech", "10-50", "$1M-$5M"),
            "gamma.dev" => ("Gamma Labs", "DevTools", "200-1000", "$20M-$50M"),
            other => {
                // Fallback:derive a name from the domain
                let name_part = other.split('.').next().unwrap_or(other);
                return Ok(Company {
                    id: Uuid::new_v4(),
                    name: format!("{} (unknown)", capitalize(name_part)),
                    domain: domain.to_owned(),
                    industry: "Unknown".into(),
                    size: "Unknown".into(),
                    revenue_range: "Unknown".into(),
                    enriched_at: Utc::now(),
                });
            }
        };

        Ok(Company {
            id: Uuid::new_v4(),
            name: name.into(),
            domain: domain.to_owned(),
            industry: industry.into(),
            size: size.into(),
            revenue_range: revenue.into(),
            enriched_at: Utc::now(),
        })
    }

    /// Enrich multiple emails in batch (convenience wrapper).
    pub fn batch_enrich(&self, emails: &[String]) -> Vec<Result<Company, SalesError>> {
        emails.iter().map(|e| self.enrich_lead(e)).collect()
    }
}

fn capitalize(s: &str) -> String {
    let mut c = s.chars();
    match c.next() {
        None => String::new(),
        Some(f) => f.to_uppercase().collect::<String>() + c.as_str(),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_domain() {
        assert_eq!(
            EnrichmentService::extract_domain("alice@acme.com"),
            Some("acme.com".into())
        );
        assert_eq!(
            EnrichmentService::extract_domain("BOB@Beta.IO"),
            Some("beta.io".into())
        );
        assert_eq!(EnrichmentService::extract_domain("nodomain"), None);
        assert_eq!(EnrichmentService::extract_domain("@"), None);
    }

    #[test]
    fn test_enrich_known_domain() {
        let svc = EnrichmentService::new("http://mock");
        let company = svc.enrich_company("acme.com").unwrap();
        assert_eq!(company.name, "Acme Corp");
        assert_eq!(company.industry, "SaaS");
        assert_eq!(company.size, "50-200");
    }

    #[test]
    fn test_enrich_unknown_and_batch() {
        let svc = EnrichmentService::new("http://mock");

        // unknown domain still succeeds with fallback
        let c = svc.enrich_company("startup.xyz").unwrap();
        assert!(c.name.contains("Startup"));
        assert_eq!(c.industry, "Unknown");

        // batch
        let results =
            svc.batch_enrich(&["a@acme.com".into(), "b@beta.io".into(), "bad-email".into()]);
        assert_eq!(results.len(), 3);
        assert!(results[0].is_ok());
        assert!(results[1].is_ok());
        assert!(results[2].is_err()); // invalid email
    }
}
