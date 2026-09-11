//! HTTP provider that calls the configured company-data gateway.
//!
//! ## API contract
//!
//! Calls `GET {base_url}/v1/companies/domain/{domain}` with the API key in
//! the `Authorization` header as `Bearer {api_key}`.
//!
//! The gateway is the ApexMail enrichment gateway (the same
//! `enrichment_api_url` / `enrichment_api_key` configuration the previous
//! single-provider implementation used). The response is Clearbit-shaped for
//! firmographics; the gateway may additionally return the extended fields
//! (tech stack, ESP, person/email verification, language) documented below.
//!
//! ## Error handling
//!
//! - HTTP 404: domain not found → [`EnrichmentError::NotFound`]
//! - HTTP 429: rate limited → [`EnrichmentError::RateLimited`]
//! - Network errors: retried with exponential backoff via
//!   [`with_retry`](super::super::with_retry)
//! - All other non-2xx: [`EnrichmentError::Unavailable`]

use std::time::Duration;

use serde::Deserialize;
use serde_json::Value;

use super::super::{
    fields, with_retry, EnrichmentError, EnrichmentProvider, EnrichmentRequest, ProviderId,
    ProviderPayload,
};

/// Default marginal cost of one gateway lookup, in EUR.
///
/// The gateway bills per successful lookup; callers can override this with
/// [`HttpEnrichmentProvider::with_cost_eur`] when they have a different
/// contract.
pub const DEFAULT_HTTP_COST_EUR: f64 = 0.03;

/// Real HTTP enrichment provider.
#[derive(Debug, Clone)]
pub struct HttpEnrichmentProvider {
    /// Base URL of the enrichment API (e.g. `https://company.clearbit.com`).
    base_url: String,
    /// API key for authentication.
    api_key: String,
    /// Marginal cost per filled field lookup.
    cost_eur: f64,
    /// Shared HTTP client.
    client: reqwest::Client,
}

/// Company API response shape. Firmographic fields follow Clearbit; the
/// extended fields are optional so any gateway subset parses.
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct CompanyGatewayResponse {
    name: Option<String>,
    legal_name: Option<String>,
    domain: Option<String>,
    category: Option<GatewayCategory>,
    metrics: Option<GatewayMetrics>,
    description: Option<String>,
    location: Option<String>,
    country: Option<String>,
    headquarters: Option<String>,
    #[serde(alias = "foundedYear")]
    founded_year: Option<i64>,
    #[serde(alias = "linkedinUrl")]
    linkedin_url: Option<String>,
    technologies: Option<Vec<String>>,
    #[serde(alias = "emailProvider")]
    email_provider: Option<String>,
    #[serde(alias = "emailStatus")]
    email_status: Option<String>,
    #[serde(alias = "emailVerified")]
    email_verified: Option<bool>,
    #[serde(alias = "personVerified")]
    person_verified: Option<bool>,
    #[serde(alias = "contactName")]
    contact_name: Option<String>,
    #[serde(alias = "contactTitle")]
    contact_title: Option<String>,
    language: Option<String>,
    locale: Option<String>,
    city: Option<String>,
    timezone: Option<String>,
    #[serde(alias = "fundingStage")]
    funding_stage: Option<String>,
    #[serde(alias = "changeSignal")]
    change_signal: Option<String>,
    #[serde(alias = "fundingSignal")]
    funding_signal: Option<String>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct GatewayCategory {
    industry: Option<String>,
    sector: Option<String>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct GatewayMetrics {
    estimated_number_of_employees: Option<u32>,
    annual_revenue: Option<String>,
}

impl HttpEnrichmentProvider {
    /// Create a new HTTP enrichment provider.
    ///
    /// `base_url` — the API base URL (e.g. `https://company.clearbit.com`).
    /// `api_key` — the API key for Bearer authentication.
    pub fn new(base_url: &str, api_key: &str) -> Self {
        // A client-build failure (e.g. TLS backend unavailable) must not
        // panic the service; the default client is the degraded fallback.
        let client = match reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .user_agent("ApexMail/1.0 (enrichment)")
            // Never follow redirects: a redirect could leak the Bearer API
            // key to whatever host the response points at.
            .redirect(reqwest::redirect::Policy::none())
            .build()
        {
            Ok(client) => client,
            Err(error) => {
                tracing::warn!(%error, "failed to build enrichment HTTP client — using default client");
                reqwest::Client::new()
            }
        };
        Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            api_key: api_key.to_string(),
            cost_eur: DEFAULT_HTTP_COST_EUR,
            client,
        }
    }

    /// Override the marginal cost per filled lookup.
    pub fn with_cost_eur(mut self, cost_eur: f64) -> Self {
        self.cost_eur = if cost_eur.is_finite() && cost_eur > 0.0 {
            cost_eur
        } else {
            0.0
        };
        self
    }
}

#[async_trait::async_trait]
impl EnrichmentProvider for HttpEnrichmentProvider {
    fn id(&self) -> ProviderId {
        ProviderId("http_gateway")
    }

    fn fields(&self) -> &[&'static str] {
        &[
            fields::COMPANY_NAME,
            fields::DOMAIN,
            fields::INDUSTRY,
            fields::EMPLOYEE_COUNT,
            fields::REVENUE_BAND,
            fields::FUNDING_STAGE,
            fields::HEADQUARTERS,
            fields::FOUNDED_YEAR,
            fields::DESCRIPTION,
            fields::LINKEDIN_URL,
            fields::TECHNOLOGIES,
            fields::EMAIL_PROVIDER,
            fields::EMAIL_STATUS,
            fields::EMAIL_VERIFIED,
            fields::CONTACT_FULL_NAME,
            fields::CONTACT_JOB_TITLE,
            fields::CONTACT_PERSON_VERIFIED,
            fields::LANGUAGE,
            fields::LOCATION_COUNTRY,
            fields::LOCATION_CITY,
            fields::TIMEZONE,
            fields::FUNDING_SIGNAL,
            fields::CHANGE_SIGNAL,
        ]
    }

    fn cost_eur(&self) -> f64 {
        self.cost_eur
    }

    async fn fetch(
        &self,
        request: &EnrichmentRequest<'_>,
    ) -> Result<ProviderPayload, EnrichmentError> {
        let domain = request.domain.trim().to_ascii_lowercase();
        // The domain is interpolated into the request path, so reject
        // anything outside a strict hostname character set. This prevents
        // path traversal / query injection (e.g. `evil.com/../../admin` or
        // `evil.com?x=1`) from altering the request target.
        if domain.is_empty()
            || !domain
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_')
        {
            return Err(EnrichmentError::InvalidInput(format!(
                "invalid domain: {domain:?}"
            )));
        }
        let url = format!("{}/v1/companies/domain/{}", self.base_url, domain);
        let client = self.client.clone();

        // Wrap the enrichment call in a 5-second timeout to prevent hanging.
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
            EnrichmentError::Unavailable("enrichment HTTP call timed out".into())
        })?
        .map_err(EnrichmentError::Unavailable)?;

        let status = response.status();
        match status {
            reqwest::StatusCode::OK => {
                let body: CompanyGatewayResponse = response.json().await.map_err(|e| {
                    EnrichmentError::Other(format!("gateway response parse error: {e}"))
                })?;
                Ok(response_to_payload(body, &domain))
            }
            reqwest::StatusCode::NOT_FOUND => Err(EnrichmentError::NotFound(format!(
                "domain not found: {domain}"
            ))),
            reqwest::StatusCode::TOO_MANY_REQUESTS => Err(EnrichmentError::RateLimited(
                "enrichment API rate limit exceeded".into(),
            )),
            reqwest::StatusCode::UNAUTHORIZED | reqwest::StatusCode::FORBIDDEN => {
                Err(EnrichmentError::Unavailable(format!(
                    "enrichment API rejected credentials: {status}"
                )))
            }
            _ => {
                let body = response.text().await.unwrap_or_default();
                Err(EnrichmentError::Unavailable(format!(
                    "API returned {status}: {body}"
                )))
            }
        }
    }
}

fn response_to_payload(body: CompanyGatewayResponse, domain: &str) -> ProviderPayload {
    let mut payload = ProviderPayload::new();

    let name = body
        .name
        .or(body.legal_name)
        .unwrap_or_else(|| capitalize(domain.split('.').next().unwrap_or(domain)));
    payload.insert(fields::COMPANY_NAME, Value::String(name), 0.9);
    payload.insert(
        fields::DOMAIN,
        Value::String(body.domain.unwrap_or_else(|| domain.to_owned())),
        0.95,
    );

    if let Some(industry) = body
        .category
        .as_ref()
        .and_then(|category| category.industry.clone())
        .or_else(|| {
            body.category
                .as_ref()
                .and_then(|category| category.sector.clone())
        })
    {
        payload.insert(fields::INDUSTRY, Value::String(industry), 0.85);
    }

    if let Some(employees) = body
        .metrics
        .as_ref()
        .and_then(|metrics| metrics.estimated_number_of_employees)
    {
        payload.insert(
            fields::EMPLOYEE_COUNT,
            Value::String(employee_band(employees)),
            0.85,
        );
    }
    if let Some(revenue) = body
        .metrics
        .as_ref()
        .and_then(|metrics| metrics.annual_revenue.clone())
    {
        payload.insert(fields::REVENUE_BAND, Value::String(revenue), 0.8);
    }

    insert_string(&mut payload, fields::FUNDING_STAGE, body.funding_stage, 0.7);
    insert_string(
        &mut payload,
        fields::HEADQUARTERS,
        body.headquarters.or(body.location),
        0.7,
    );
    if let Some(year) = body.founded_year {
        payload.insert(fields::FOUNDED_YEAR, Value::Number(year.into()), 0.7);
    }
    insert_string(&mut payload, fields::DESCRIPTION, body.description, 0.6);
    insert_string(&mut payload, fields::LINKEDIN_URL, body.linkedin_url, 0.7);
    if let Some(technologies) = body.technologies {
        let technologies: Vec<Value> = technologies.into_iter().map(Value::String).collect();
        if !technologies.is_empty() {
            payload.insert(fields::TECHNOLOGIES, Value::Array(technologies), 0.65);
        }
    }

    insert_string(
        &mut payload,
        fields::EMAIL_PROVIDER,
        body.email_provider,
        0.7,
    );
    insert_string(&mut payload, fields::EMAIL_STATUS, body.email_status, 0.7);
    if let Some(verified) = body.email_verified {
        payload.insert(fields::EMAIL_VERIFIED, Value::Bool(verified), 0.8);
    }
    insert_string(
        &mut payload,
        fields::CONTACT_FULL_NAME,
        body.contact_name,
        0.7,
    );
    insert_string(
        &mut payload,
        fields::CONTACT_JOB_TITLE,
        body.contact_title,
        0.7,
    );
    if let Some(verified) = body.person_verified {
        payload.insert(fields::CONTACT_PERSON_VERIFIED, Value::Bool(verified), 0.75);
    }

    let language = body.language.or(body.locale);
    insert_string(&mut payload, fields::LANGUAGE, language, 0.6);
    insert_string(&mut payload, fields::LOCATION_COUNTRY, body.country, 0.7);
    insert_string(&mut payload, fields::LOCATION_CITY, body.city, 0.6);
    insert_string(&mut payload, fields::TIMEZONE, body.timezone, 0.6);
    insert_string(
        &mut payload,
        fields::FUNDING_SIGNAL,
        body.funding_signal,
        0.5,
    );
    insert_string(&mut payload, fields::CHANGE_SIGNAL, body.change_signal, 0.5);

    payload
}

fn insert_string(
    payload: &mut ProviderPayload,
    field: &str,
    value: Option<String>,
    confidence: f32,
) {
    if let Some(value) = value
        .map(|value| value.trim().to_string())
        .filter(|v| !v.is_empty())
    {
        payload.insert(field, Value::String(value), confidence);
    }
}

fn employee_band(employees: u32) -> String {
    match employees {
        0..=10 => "1-10",
        11..=50 => "10-50",
        51..=200 => "50-200",
        201..=1000 => "200-1000",
        _ => "1000+",
    }
    .to_string()
}

fn capitalize(s: &str) -> String {
    let mut c = s.chars();
    match c.next() {
        None => String::new(),
        Some(f) => f.to_uppercase().collect::<String>() + c.as_str(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn http_provider_rejects_invalid_domains() {
        let provider = HttpEnrichmentProvider::new("https://enrich.example.com", "test-key");
        for bad in [
            "",
            "evil.com/../../admin",
            "evil.com?x=1",
            "evil.com#fragment",
            "ev il.com",
            "evil.com%2f..",
        ] {
            let err = provider
                .fetch(&EnrichmentRequest::new("tenant-a", bad))
                .await
                .unwrap_err();
            assert!(
                matches!(err, EnrichmentError::InvalidInput(_)),
                "expected InvalidInput for {bad:?}, got {err:?}"
            );
        }
    }

    #[test]
    fn gateway_response_maps_extended_fields() {
        let body: CompanyGatewayResponse = serde_json::from_value(serde_json::json!({
            "name": "Acme Corp",
            "domain": "acme.com",
            "category": { "industry": "SaaS" },
            "metrics": { "estimated_number_of_employees": 120, "annual_revenue": "$5M-$20M" },
            "technologies": ["Google Workspace", "AWS"],
            "emailProvider": "google",
            "emailVerified": true,
            "personVerified": true,
            "language": "en",
            "country": "EE",
            "fundingSignal": "series_a"
        }))
        .expect("valid gateway response");

        let payload = response_to_payload(body, "acme.com");
        assert_eq!(
            payload.facts.get(fields::EMPLOYEE_COUNT).unwrap().value,
            Value::String("50-200".into())
        );
        assert_eq!(
            payload.facts.get(fields::EMAIL_PROVIDER).unwrap().value,
            Value::String("google".into())
        );
        assert!(matches!(
            payload.facts.get(fields::EMAIL_VERIFIED).unwrap().value,
            Value::Bool(true)
        ));
        assert_eq!(
            payload.facts.get(fields::LANGUAGE).unwrap().value,
            Value::String("en".into())
        );
        assert!(payload.facts.contains_key(fields::FUNDING_SIGNAL));
    }

    #[test]
    fn cost_override_ignores_non_finite_values() {
        let provider = HttpEnrichmentProvider::new("https://x.example", "k");
        assert_eq!(provider.cost_eur(), DEFAULT_HTTP_COST_EUR);
        let provider = provider.with_cost_eur(f64::NAN);
        assert_eq!(provider.cost_eur(), 0.0);
    }
}
