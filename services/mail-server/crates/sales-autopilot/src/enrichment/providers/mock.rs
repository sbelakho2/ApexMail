//! Deterministic mock enrichment provider.
//!
//! Returns hardcoded data for known domains (`acme.com`, `beta.io`,
//! `gamma.dev`) and a labelled fallback for unknown domains. Suitable for
//! testing and development — never use in production.

use serde_json::Value;

use super::super::{
    fields, EnrichmentError, EnrichmentProvider, EnrichmentRequest, ProviderId, ProviderPayload,
};

/// Deterministic mock provider used by tests and `EnrichmentService::mock()`.
#[derive(Debug, Clone, Default)]
pub struct MockEnrichmentProvider;

/// Stable provider id.
pub const MOCK_PROVIDER_ID: ProviderId = ProviderId("mock");

#[async_trait::async_trait]
impl EnrichmentProvider for MockEnrichmentProvider {
    fn id(&self) -> ProviderId {
        MOCK_PROVIDER_ID
    }

    fn fields(&self) -> &[&'static str] {
        &[
            fields::COMPANY_NAME,
            fields::DOMAIN,
            fields::INDUSTRY,
            fields::EMPLOYEE_COUNT,
            fields::REVENUE_BAND,
        ]
    }

    fn cost_eur(&self) -> f64 {
        0.0
    }

    async fn fetch(
        &self,
        request: &EnrichmentRequest<'_>,
    ) -> Result<ProviderPayload, EnrichmentError> {
        let domain = request.domain.trim().to_ascii_lowercase();
        let (name, industry, size, revenue) = match domain.as_str() {
            "acme.com" => ("Acme Corp", "SaaS", "50-200", "$5M-$20M"),
            "beta.io" => ("Beta Inc", "FinTech", "10-50", "$1M-$5M"),
            "gamma.dev" => ("Gamma Labs", "DevTools", "200-1000", "$20M-$50M"),
            other => {
                let name_part = other.split('.').next().unwrap_or(other);
                return Ok(ProviderPayload::new()
                    .with(
                        fields::COMPANY_NAME,
                        Value::String(format!("{} (unknown)", capitalize(name_part))),
                        0.3,
                    )
                    .with(fields::DOMAIN, Value::String(domain), 0.5)
                    .with(fields::INDUSTRY, Value::String("Unknown".into()), 0.2)
                    .with(fields::EMPLOYEE_COUNT, Value::String("Unknown".into()), 0.2)
                    .with(fields::REVENUE_BAND, Value::String("Unknown".into()), 0.2));
            }
        };

        Ok(ProviderPayload::new()
            .with(fields::COMPANY_NAME, Value::String(name.into()), 0.9)
            .with(fields::DOMAIN, Value::String(domain), 0.95)
            .with(fields::INDUSTRY, Value::String(industry.into()), 0.9)
            .with(fields::EMPLOYEE_COUNT, Value::String(size.into()), 0.85)
            .with(fields::REVENUE_BAND, Value::String(revenue.into()), 0.8))
    }
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
    async fn known_domains_are_deterministic() {
        let provider = MockEnrichmentProvider;
        let request = EnrichmentRequest::new("tenant-a", "acme.com");
        let payload = provider.fetch(&request).await.unwrap();
        assert_eq!(
            payload.facts.get(fields::COMPANY_NAME).unwrap().value,
            Value::String("Acme Corp".into())
        );
        assert_eq!(
            payload.facts.get(fields::INDUSTRY).unwrap().value,
            Value::String("SaaS".into())
        );
        assert_eq!(
            payload.facts.get(fields::EMPLOYEE_COUNT).unwrap().value,
            Value::String("50-200".into())
        );
    }

    #[tokio::test]
    async fn unknown_domain_falls_back_with_nonzero_confidence() {
        let provider = MockEnrichmentProvider;
        let payload = provider
            .fetch(&EnrichmentRequest::new("tenant-a", "startup.xyz"))
            .await
            .unwrap();
        assert_eq!(
            payload.facts.get(fields::COMPANY_NAME).unwrap().value,
            Value::String("Startup (unknown)".into())
        );
        assert!(payload.facts.values().all(|fact| fact.confidence > 0.0));
    }
}
