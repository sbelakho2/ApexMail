//! HTTP discovery source.
//!
//! Calls a configured, approved discovery provider API:
//!
//! ```text
//! POST {base_url}/v1/discovery/search
//! Authorization: Bearer {token}
//! { "keywords": [...], "industries": [...], "countries": [...],
//!   "max_results": 100, "categories": [...], "cursor": "…" }
//! ```
//!
//! and expects:
//!
//! ```json
//! { "candidates": [ { "source_url": "…", "company_name": "…", "domain": "…",
//!                     "jurisdiction": "EE", "jurisdiction_confidence": 0.9,
//!                     "confidence": 0.7, "raw_snapshot_hash": "…" } ],
//!   "next_cursor": "…", "cost_eur": 0.05 }
//! ```
//!
//! Redirects are never followed: the Bearer token must not leak to another
//! host. Configured through `SalesConfig::enrichment_api_url` /
//! `enrichment_api_key` (with `SALES_DISCOVERY_API_URL` /
//! `SALES_DISCOVERY_API_KEY` overrides) by
//! [`default_sources`](crate::discovery::default_sources).

use std::sync::atomic::{AtomicI32, Ordering};
use std::time::Duration;

use serde::Deserialize;

use super::provider::{
    DiscoveredCandidate, DiscoveryError, DiscoveryPage, DiscoveryQuery, DiscoverySource,
};

/// Default cost charged per page when the provider does not report one.
pub const DEFAULT_DISCOVERY_COST_EUR: f64 = 0.05;

/// HTTP status "no call yet".
const NO_STATUS: i32 = 0;

/// Approved provider API discovery source.
#[derive(Debug)]
pub struct HttpDiscoverySource {
    id: &'static str,
    base_url: String,
    api_key: String,
    allowed_jurisdictions: Vec<&'static str>,
    default_cost_eur: f64,
    client: reqwest::Client,
    last_status: AtomicI32,
}

impl HttpDiscoverySource {
    /// `id` must be a static name (it is persisted in
    /// `sales_discovery_candidates.source`).
    pub fn new(
        id: &'static str,
        base_url: &str,
        api_key: &str,
        allowed_jurisdictions: Vec<&'static str>,
    ) -> Self {
        // A client-build failure must not panic the service; the default
        // client is the degraded fallback.
        let client = match reqwest::Client::builder()
            .timeout(Duration::from_secs(15))
            .user_agent("ApexMail/1.0 (discovery)")
            .redirect(reqwest::redirect::Policy::none())
            .build()
        {
            Ok(client) => client,
            Err(error) => {
                tracing::warn!(%error, "failed to build discovery HTTP client — using default client");
                reqwest::Client::new()
            }
        };
        Self {
            id,
            base_url: base_url.trim_end_matches('/').to_string(),
            api_key: api_key.to_string(),
            allowed_jurisdictions,
            default_cost_eur: DEFAULT_DISCOVERY_COST_EUR,
            client,
            last_status: AtomicI32::new(NO_STATUS),
        }
    }

    /// Override the per-page cost used when the provider reports none.
    pub fn with_default_cost_eur(mut self, cost: f64) -> Self {
        self.default_cost_eur = if cost.is_finite() && cost > 0.0 {
            cost
        } else {
            0.0
        };
        self
    }
}

#[derive(Debug, Deserialize)]
struct DiscoveryResponse {
    #[serde(default)]
    candidates: Vec<ResponseCandidate>,
    #[serde(default)]
    next_cursor: Option<String>,
    #[serde(default)]
    cost_eur: Option<f64>,
}

#[derive(Debug, Deserialize)]
struct ResponseCandidate {
    #[serde(default)]
    source_url: Option<String>,
    #[serde(default)]
    company_name: Option<String>,
    #[serde(default)]
    domain: Option<String>,
    #[serde(default)]
    jurisdiction: Option<String>,
    #[serde(default)]
    jurisdiction_confidence: f32,
    #[serde(default)]
    confidence: f32,
    #[serde(default)]
    raw_snapshot_hash: Option<String>,
}

#[async_trait::async_trait]
impl DiscoverySource for HttpDiscoverySource {
    fn id(&self) -> &'static str {
        self.id
    }

    fn allowed_jurisdictions(&self) -> &[&'static str] {
        &self.allowed_jurisdictions
    }

    async fn discover(
        &self,
        query: &DiscoveryQuery,
        cursor: Option<&str>,
    ) -> Result<DiscoveryPage, DiscoveryError> {
        let url = format!("{}/v1/discovery/search", self.base_url);
        let body = serde_json::json!({
            "keywords": query.keywords,
            "industries": query.industries,
            "countries": query.countries,
            "max_results": query.effective_max_results(),
            "categories": query.categories,
            "cursor": cursor,
        });

        let response = self
            .client
            .post(&url)
            .header("Authorization", format!("Bearer {}", self.api_key))
            .json(&body)
            .send()
            .await
            .map_err(|error| {
                self.last_status.store(NO_STATUS, Ordering::SeqCst);
                DiscoveryError::Unavailable(format!("discovery HTTP request failed: {error}"))
            })?;

        let status = response.status();
        self.last_status
            .store(i32::from(status.as_u16()), Ordering::SeqCst);

        match status {
            reqwest::StatusCode::OK => {
                let parsed: DiscoveryResponse = response.json().await.map_err(|error| {
                    DiscoveryError::InvalidResponse(format!(
                        "discovery response parse error: {error}"
                    ))
                })?;
                let candidates = parsed
                    .candidates
                    .into_iter()
                    .map(|candidate| DiscoveredCandidate {
                        source: self.id.to_string(),
                        source_url: candidate.source_url,
                        company_name: candidate.company_name,
                        domain: candidate.domain,
                        jurisdiction: candidate.jurisdiction,
                        jurisdiction_confidence: candidate.jurisdiction_confidence,
                        confidence: candidate.confidence,
                        raw_snapshot_hash: candidate.raw_snapshot_hash,
                    })
                    .collect();
                let cost = parsed
                    .cost_eur
                    .filter(|cost| cost.is_finite() && *cost >= 0.0)
                    .unwrap_or(self.default_cost_eur);
                Ok(DiscoveryPage {
                    candidates,
                    next_cursor: parsed.next_cursor,
                    cost_eur: cost,
                })
            }
            reqwest::StatusCode::UNAUTHORIZED | reqwest::StatusCode::FORBIDDEN => {
                Err(DiscoveryError::Unauthorized(format!(
                    "discovery API rejected credentials: {status}"
                )))
            }
            reqwest::StatusCode::TOO_MANY_REQUESTS => Err(DiscoveryError::RateLimited(
                "discovery API rate limit exceeded".into(),
            )),
            _ => {
                let body = response.text().await.unwrap_or_default();
                Err(DiscoveryError::Unavailable(format!(
                    "discovery API returned {status}: {}",
                    body.chars().take(300).collect::<String>()
                )))
            }
        }
    }

    fn last_http_status(&self) -> Option<i32> {
        match self.last_status.load(Ordering::SeqCst) {
            NO_STATUS => None,
            status => Some(status),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn response_parses_and_defaults() {
        let response: DiscoveryResponse = serde_json::from_value(serde_json::json!({
            "candidates": [
                { "source_url": "https://registry.example/company/1",
                  "company_name": "Acme",
                  "domain": "acme.ee",
                  "jurisdiction": "EE",
                  "jurisdiction_confidence": 0.9,
                  "confidence": 0.7,
                  "raw_snapshot_hash": "abc123" },
                { "company_name": "Minimal" }
            ],
            "next_cursor": "2",
            "cost_eur": 0.12
        }))
        .expect("valid response");
        assert_eq!(response.candidates.len(), 2);
        assert_eq!(response.next_cursor.as_deref(), Some("2"));
        assert_eq!(response.cost_eur, Some(0.12));
        assert!(response.candidates[1].source_url.is_none());
    }

    #[test]
    fn hostile_response_values_are_tolerated() {
        let response: DiscoveryResponse = serde_json::from_value(serde_json::json!({
            "candidates": [{ "jurisdiction_confidence": 5.0, "confidence": -3.0 }],
            "cost_eur": -1.0
        }))
        .expect("valid response");
        // Sanitization and clamping happen in the job runner; parsing must
        // never panic on out-of-range numbers.
        assert_eq!(response.candidates[0].confidence, -3.0);
    }

    #[tokio::test]
    async fn invalid_base_url_fails_without_panicking() {
        let source = HttpDiscoverySource::new("provider_api", "http://127.0.0.1:1", "k", vec![]);
        let result = source.discover(&DiscoveryQuery::default(), None).await;
        assert!(result.is_err());
        assert!(source.last_http_status().is_none());
    }
}
