use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use serde::Deserialize;
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

    // SAFETY: The loop always returns via `Ok(val)` or `Err(e)` on the final
    // attempt (MAX_RETRIES >= 1).  This line is unreachable in practice.
    Err(last_err
        .unwrap_or_else(|| unreachable!("with_retry: MAX_RETRIES >= 1 guarantees loop return")))
}

// ---------------------------------------------------------------------------
// EnrichmentProvider trait — supports mock and real implementations (SA-2)
// ---------------------------------------------------------------------------

/// Abstraction for company enrichment data providers.
///
/// # Security (SA-2)
///
/// **Root cause**: The enrichment service returned deterministic mock data
/// even in "production" mode (`mock_enabled: false`); the real API client
/// was never called. Instead, production mode returned an error, making the
/// entire enrichment pipeline non-functional outside of development.
///
/// **Fix**: Introduced the `EnrichmentProvider` trait with two implementations:
///   1. `MockEnrichmentProvider` — deterministic mock data for testing
///   2. `HttpEnrichmentProvider` — real HTTP client (Clearbit/Hunter API)
/// The `EnrichmentService` now holds an `Arc<dyn EnrichmentProvider>` and
/// delegates all enrichment calls to the provider. The caller selects which
/// provider to use at construction time.
#[async_trait::async_trait]
pub trait EnrichmentProvider: Send + Sync + std::fmt::Debug {
    /// Enrich a company by domain. Returns firmographic data or an error.
    async fn enrich(&self, domain: &str) -> Result<Company, SalesError>;
}

// ---------------------------------------------------------------------------
// MockEnrichmentProvider — deterministic mock for tests
// ---------------------------------------------------------------------------

/// Deterministic mock enrichment provider.
///
/// Returns hardcoded data for known domains (`acme.com`, `beta.io`,
/// `gamma.dev`) and a fallback for unknown domains. Suitable for testing
/// and development — never use in production.
#[derive(Debug, Clone)]
pub struct MockEnrichmentProvider;

#[async_trait::async_trait]
impl EnrichmentProvider for MockEnrichmentProvider {
    async fn enrich(&self, domain: &str) -> Result<Company, SalesError> {
        // Deterministic mock data keyed on domain.
        let (name, industry, size, revenue) = match domain {
            "acme.com" => ("Acme Corp", "SaaS", "50-200", "$5M-$20M"),
            "beta.io" => ("Beta Inc", "FinTech", "10-50", "$1M-$5M"),
            "gamma.dev" => ("Gamma Labs", "DevTools", "200-1000", "$20M-$50M"),
            other => {
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
}

// ---------------------------------------------------------------------------
// HttpEnrichmentProvider — real HTTP client (Clearbit/Hunter API)
// ---------------------------------------------------------------------------

/// A real HTTP enrichment provider that calls the Clearbit Company API
/// (or compatible endpoint).
///
/// ## API contract
///
/// Calls `GET {base_url}/v1/companies/domain/{domain}` with the API key
/// in the `Authorization` header as `Bearer {api_key}`.
///
/// ## Error handling
///
/// - HTTP 404: domain not found → `SalesError::InvalidInput`
/// - HTTP 429: rate limited → `SalesError::RateLimited`
/// - Network errors: retried with exponential backoff via `with_retry`
/// - All other non-2xx: `SalesError::EnrichmentFailed`
#[derive(Debug, Clone)]
pub struct HttpEnrichmentProvider {
    /// Base URL of the enrichment API (e.g. `https://company.clearbit.com`).
    base_url: String,
    /// API key for authentication.
    api_key: String,
    /// Shared HTTP client.
    client: reqwest::Client,
}

/// Clearbit Company API response shape.
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct ClearbitCompanyResponse {
    name: Option<String>,
    legal_name: Option<String>,
    domain: String,
    category: Option<ClearbitCategory>,
    metrics: Option<ClearbitMetrics>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct ClearbitCategory {
    industry: Option<String>,
    sector: Option<String>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct ClearbitMetrics {
    estimated_number_of_employees: Option<u32>,
    annual_revenue: Option<String>,
}

impl HttpEnrichmentProvider {
    /// Create a new HTTP enrichment provider.
    ///
    /// `base_url` — the API base URL (e.g. `https://company.clearbit.com`).
    /// `api_key` — the API key for Bearer authentication.
    pub fn new(base_url: &str, api_key: &str) -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .user_agent("ApexMail/1.0 (enrichment)")
            .build()
            .expect("valid reqwest client configuration");
        Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            api_key: api_key.to_string(),
            client,
        }
    }
}

#[async_trait::async_trait]
impl EnrichmentProvider for HttpEnrichmentProvider {
    async fn enrich(&self, domain: &str) -> Result<Company, SalesError> {
        let url = format!("{}/v1/companies/domain/{}", self.base_url, domain);
        let client = self.client.clone();

        // Wrap the enrichment call in a 5-second timeout to prevent hanging
        let response = tokio::time::timeout(Duration::from_secs(5), async {
            with_retry(|| {
                let client = client.clone();
                let url = url.clone();
                async move {
                    client
                        .get(&url)
                        .header("Authorization", format!("Bearer {}", self.api_key))
                        .send()
                        .await
                        .map_err(|e| format!("HTTP request failed: {e}"))
                }
            })
            .await
        })
        .await
        .map_err(|_elapsed| {
            tracing::warn!(domain = %domain, "enrichment HTTP call timed out after 5s");
            SalesError::EnrichmentFailed("enrichment HTTP call timed out".into())
        })?
        .map_err(SalesError::EnrichmentFailed)?;

        let status = response.status();
        match status {
            reqwest::StatusCode::OK => {
                let clearbit: ClearbitCompanyResponse = response
                    .json()
                    .await
                    .map_err(|e| SalesError::EnrichmentFailed(format!("JSON parse error: {e}")))?;

                let industry = clearbit
                    .category
                    .as_ref()
                    .and_then(|c| c.industry.as_deref())
                    .or_else(|| clearbit.category.as_ref().and_then(|c| c.sector.as_deref()))
                    .unwrap_or("Unknown")
                    .to_string();

                let size = clearbit
                    .metrics
                    .as_ref()
                    .and_then(|m| m.estimated_number_of_employees)
                    .map(|e| match e {
                        0..=10 => "1-10".to_string(),
                        11..=50 => "10-50".to_string(),
                        51..=200 => "50-200".to_string(),
                        201..=1000 => "200-1000".to_string(),
                        _ => "1000+".to_string(),
                    })
                    .unwrap_or_else(|| "Unknown".to_string());

                let revenue_range = clearbit
                    .metrics
                    .as_ref()
                    .and_then(|m| m.annual_revenue.as_deref())
                    .unwrap_or("Unknown")
                    .to_string();

                let name = clearbit
                    .name
                    .or(clearbit.legal_name)
                    .unwrap_or_else(|| capitalize(domain.split('.').next().unwrap_or(domain)));

                Ok(Company {
                    id: Uuid::new_v4(),
                    name,
                    domain: domain.to_owned(),
                    industry,
                    size,
                    revenue_range,
                    enriched_at: Utc::now(),
                })
            }
            reqwest::StatusCode::NOT_FOUND => Err(SalesError::InvalidInput(format!(
                "domain not found: {domain}"
            ))),
            reqwest::StatusCode::TOO_MANY_REQUESTS => Err(SalesError::RateLimited(
                "enrichment API rate limit exceeded".into(),
            )),
            _ => {
                let body = response.text().await.unwrap_or_default();
                Err(SalesError::EnrichmentFailed(format!(
                    "API returned {status}: {body}"
                )))
            }
        }
    }
}

/// Company enrichment service.
///
/// Given a lead email or domain, it resolves firmographic data (industry,
/// employee band, revenue range, …) by delegating to an [`EnrichmentProvider`].
///
/// # Security (SA-2)
///
/// **Root cause**: The enrichment service returned deterministic mock data
/// even in "production" mode (`mock_enabled: false`); the real API client
/// was never called. Instead, production mode returned an error, making the
/// entire enrichment pipeline non-functional outside of development.
///
/// **Fix**: Replaced the `mock_enabled: bool` flag with a provider trait
/// (`EnrichmentProvider`) so the caller explicitly chooses which backend to
/// inject at construction time. See [`EnrichmentProvider`] docs for details.
///
/// # Examples
///
/// ```ignore
/// // Production
/// let provider = HttpEnrichmentProvider::new("https://company.clearbit.com", api_key);
/// let svc = EnrichmentService::new(Arc::new(provider));
///
/// // Testing
/// let svc = EnrichmentService::new(Arc::new(MockEnrichmentProvider));
/// ```
#[derive(Debug, Clone)]
pub struct EnrichmentService {
    /// The enrichment provider backend (mock or real HTTP).
    provider: Arc<dyn EnrichmentProvider>,
}

impl EnrichmentService {
    /// Create a new enrichment service wrapping the given provider.
    ///
    /// Use [`MockEnrichmentProvider`] for testing/development and
    /// [`HttpEnrichmentProvider`] for production.
    pub fn new(provider: Arc<dyn EnrichmentProvider>) -> Self {
        Self { provider }
    }

    /// Convenience constructor for tests: wraps a [`MockEnrichmentProvider`].
    pub fn mock() -> Self {
        Self {
            provider: Arc::new(MockEnrichmentProvider),
        }
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
    pub async fn enrich_lead(&self, email: &str) -> Result<Company, SalesError> {
        let domain = Self::extract_domain(email)
            .ok_or_else(|| SalesError::InvalidInput(format!("bad email: {email}")))?;
        self.enrich_company(&domain).await
    }

    /// Look up company data for a domain via the configured provider.
    pub async fn enrich_company(&self, domain: &str) -> Result<Company, SalesError> {
        self.provider.enrich(domain).await
    }

    /// Enrich multiple emails in batch (convenience wrapper).
    pub async fn batch_enrich(&self, emails: &[String]) -> Vec<Result<Company, SalesError>> {
        let mut results = Vec::with_capacity(emails.len());
        for email in emails {
            results.push(self.enrich_lead(email).await);
        }
        results
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

    #[tokio::test]
    async fn test_enrich_known_domain() {
        let svc = EnrichmentService::mock();
        let company = svc.enrich_company("acme.com").await.unwrap();
        assert_eq!(company.name, "Acme Corp");
        assert_eq!(company.industry, "SaaS");
        assert_eq!(company.size, "50-200");
    }

    #[tokio::test]
    async fn test_enrich_unknown_and_batch() {
        let svc = EnrichmentService::mock();

        // unknown domain still succeeds with fallback
        let c = svc.enrich_company("startup.xyz").await.unwrap();
        assert!(c.name.contains("Startup"));
        assert_eq!(c.industry, "Unknown");

        // batch
        let results = svc
            .batch_enrich(&["a@acme.com".into(), "b@beta.io".into(), "bad-email".into()])
            .await;
        assert_eq!(results.len(), 3);
        assert!(results[0].is_ok());
        assert!(results[1].is_ok());
        assert!(results[2].is_err()); // invalid email
    }
}
