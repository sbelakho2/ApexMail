//! Internal research fallback provider.
//!
//! The last step of the waterfall: cheap, first-party heuristics derived from
//! data ApexMail already holds (the domain TLD, the caller's email). It never
//! makes a network call and it labels everything with low confidence — it
//! exists so a cold start still produces *some* provenance-carrying fields
//! instead of silently degrading to nothing.

use serde_json::Value;

use super::super::{
    fields, EnrichmentError, EnrichmentProvider, EnrichmentRequest, ProviderId, ProviderPayload,
};

/// Provider id used in `sales_enrichment_facts.provider` and
/// `sales_provider_stats.provider`.
pub const INTERNAL_RESEARCH_ID: ProviderId = ProviderId("internal_research");

/// Internal research provider.
#[derive(Debug, Clone)]
pub struct ResearchEnrichmentProvider {
    cost_eur: f64,
}

impl Default for ResearchEnrichmentProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl ResearchEnrichmentProvider {
    pub fn new() -> Self {
        Self { cost_eur: 0.0 }
    }

    /// Override the (symbolic) internal cost used for routing.
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
impl EnrichmentProvider for ResearchEnrichmentProvider {
    fn id(&self) -> ProviderId {
        INTERNAL_RESEARCH_ID
    }

    fn fields(&self) -> &[&'static str] {
        &[
            fields::LANGUAGE,
            fields::LOCATION_COUNTRY,
            fields::TIMEZONE,
            fields::FUNDING_SIGNAL,
            fields::CHANGE_SIGNAL,
        ]
    }

    fn cost_eur(&self) -> f64 {
        self.cost_eur
    }

    fn source_kind(&self) -> &'static str {
        "first_party"
    }

    async fn fetch(
        &self,
        request: &EnrichmentRequest<'_>,
    ) -> Result<ProviderPayload, EnrichmentError> {
        let domain = request.domain.trim().to_ascii_lowercase();
        if domain.is_empty() {
            return Err(EnrichmentError::InvalidInput("empty domain".into()));
        }
        let mut payload = ProviderPayload::new();

        let tld = domain.rsplit('.').next().unwrap_or_default();
        if let Some((country, language, timezone)) = tld_profile(tld) {
            payload.insert(fields::LOCATION_COUNTRY, Value::String(country.into()), 0.5);
            payload.insert(fields::LANGUAGE, Value::String(language.into()), 0.4);
            if let Some(timezone) = timezone {
                payload.insert(fields::TIMEZONE, Value::String(timezone.into()), 0.4);
            }
        } else {
            // Generic-language prior for international TLDs.
            payload.insert(fields::LANGUAGE, Value::String("en".into()), 0.3);
        }

        // "No change observed" is itself a signal, with appropriately low
        // confidence, rather than an absence of a row.
        payload.insert(
            fields::CHANGE_SIGNAL,
            Value::String("none_observed".into()),
            0.2,
        );
        payload.insert(
            fields::FUNDING_SIGNAL,
            Value::String("none_observed".into()),
            0.2,
        );

        Ok(payload)
    }
}

/// (ISO country, language, optional timezone) for a small set of ccTLDs.
fn tld_profile(tld: &str) -> Option<(&'static str, &'static str, Option<&'static str>)> {
    match tld {
        "ee" => Some(("EE", "et", Some("Europe/Tallinn"))),
        "de" => Some(("DE", "de", Some("Europe/Berlin"))),
        "fr" => Some(("FR", "fr", Some("Europe/Paris"))),
        "es" => Some(("ES", "es", Some("Europe/Madrid"))),
        "it" => Some(("IT", "it", Some("Europe/Rome"))),
        "nl" => Some(("NL", "nl", Some("Europe/Amsterdam"))),
        "se" => Some(("SE", "sv", Some("Europe/Stockholm"))),
        "no" => Some(("NO", "no", Some("Europe/Oslo"))),
        "dk" => Some(("DK", "da", Some("Europe/Copenhagen"))),
        "fi" => Some(("FI", "fi", Some("Europe/Helsinki"))),
        "pl" => Some(("PL", "pl", Some("Europe/Warsaw"))),
        "pt" => Some(("PT", "pt", Some("Europe/Lisbon"))),
        "ie" => Some(("IE", "en", Some("Europe/Dublin"))),
        "uk" | "co" => None,
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn research_fills_language_and_signals_with_low_confidence() {
        let provider = ResearchEnrichmentProvider::new();
        let payload = provider
            .fetch(&EnrichmentRequest::new("tenant-a", "acme.ee"))
            .await
            .unwrap();
        assert_eq!(
            payload.facts.get(fields::LOCATION_COUNTRY).unwrap().value,
            Value::String("EE".into())
        );
        assert_eq!(
            payload.facts.get(fields::LANGUAGE).unwrap().value,
            Value::String("et".into())
        );
        assert!(payload
            .facts
            .values()
            .all(|fact| fact.confidence > 0.0 && fact.confidence < 0.7));
        assert_eq!(provider.source_kind(), "first_party");
    }

    #[tokio::test]
    async fn research_rejects_empty_domain() {
        let provider = ResearchEnrichmentProvider::new();
        assert!(provider
            .fetch(&EnrichmentRequest::new("tenant-a", "  "))
            .await
            .is_err());
    }
}
