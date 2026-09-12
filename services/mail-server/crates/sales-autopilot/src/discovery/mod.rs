//! Real discovery behind a provider abstraction.
//!
//! The pipeline is:
//!
//! ```text
//! DiscoveryJobRunner (job.rs)
//!   → sales_discovery_jobs      (one row per command)
//!   → DiscoverySource::discover (provider.rs; HTTP gateway / first-party / fixture)
//!   → sales_source_runs         (one row per source per run)
//!   → sales_discovery_candidates (upsert on the (tenant, source, source_url)
//!                                 partial unique index)
//!   → promote_candidate          (sales_accounts, immutable on conflict)
//! ```
//!
//! No scraping is implemented here: every source is an approved provider API,
//! ApexMail's own first-party data, or an explicitly labelled test fixture.
//! Every source declares the jurisdictions it may lawfully return data for and
//! the job runner enforces that declaration.
//!
//! Job execution is leased and fenced ([`DiscoveryJobRunner::run_job`], see
//! the lease-protocol section of `job.rs`): one runner owns a job at a time,
//! a crashed runner's lease expires and the job is recoverable, and a
//! superseded runner cannot write. Requesting a source that is not configured
//! is [`SalesError::InvalidInput`](crate::types::SalesError) — there is no
//! fallback to running every configured (possibly paid) provider.

pub mod first_party;
pub mod http;
pub mod job;
pub mod provider;

pub use first_party::FirstPartySource;
pub use http::HttpDiscoverySource;
pub use job::{
    promote_candidate, DiscoveryJob, DiscoveryJobRunner, DiscoveryRunReport, SourceRunReport,
    JOB_LEASED_MARKER, JOB_LEASE_MINUTES, MAX_CANDIDATES_PER_PAGE, MAX_JOB_ATTEMPTS,
    MAX_PAGES_PER_RUN,
};
pub use provider::{
    candidate_allowed_by_jurisdiction, DiscoveredCandidate, DiscoveryError, DiscoveryPage,
    DiscoveryQuery, DiscoverySource, FixtureSource,
};

use std::sync::OnceLock;

/// Build the production discovery source set.
///
/// * `provider_api` — the configured discovery/company-data gateway. URL and
///   token come from the existing `SalesConfig` (`enrichment_api_url` /
///   `enrichment_api_key`); `SALES_DISCOVERY_API_URL` /
///   `SALES_DISCOVERY_API_KEY` override them when a separate discovery
///   endpoint exists. The provider API is only included when a base URL is
///   configured.
/// * `first_party` — ApexMail's own accounts for the tenant (no external
///   call; no jurisdiction restriction, it is our own data).
///
/// Jurisdiction restrictions for the provider API are operator-configured
/// through `SALES_DISCOVERY_ALLOWED_JURISDICTIONS` (comma-separated ISO
/// codes); unset means the operator has not declared a restriction.
pub fn default_sources(
    db: &sqlx::PgPool,
    config: &crate::config::SalesConfig,
    tenant_id: &str,
) -> Vec<std::sync::Arc<dyn DiscoverySource>> {
    let mut sources: Vec<std::sync::Arc<dyn DiscoverySource>> = Vec::new();

    let api_url = std::env::var("SALES_DISCOVERY_API_URL")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| config.enrichment_api_url.clone());
    let api_key = std::env::var("SALES_DISCOVERY_API_KEY")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| config.enrichment_api_key.clone());

    if !api_url.trim().is_empty() {
        sources.push(std::sync::Arc::new(HttpDiscoverySource::new(
            "provider_api",
            &api_url,
            &api_key,
            configured_allowed_jurisdictions(),
        )));
    }

    sources.push(std::sync::Arc::new(FirstPartySource::new(
        db.clone(),
        tenant_id,
    )));

    sources
}

/// Operator-configured jurisdictions the HTTP provider may return.
///
/// Read once per process (the values are `&'static str` by trait contract).
fn configured_allowed_jurisdictions() -> Vec<&'static str> {
    static CELL: OnceLock<Vec<&'static str>> = OnceLock::new();
    CELL.get_or_init(|| {
        std::env::var("SALES_DISCOVERY_ALLOWED_JURISDICTIONS")
            .ok()
            .map(|raw| {
                raw.split(',')
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                    .map(|value| {
                        // Config is process-lifetime data; leaking these few
                        // strings once is deliberate and bounded.
                        Box::leak(value.to_ascii_uppercase().into_boxed_str()) as &'static str
                    })
                    .collect()
            })
            .unwrap_or_default()
    })
    .clone()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::SalesConfig;

    #[tokio::test]
    async fn default_sources_always_include_first_party() {
        // A lazy pool is enough: the source is only constructed, not called.
        let pool = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://localhost/unused")
            .expect("lazy pool");
        let config = SalesConfig::default();
        let sources = default_sources(&pool, &config, "tenant-a");
        assert!(sources.iter().any(|source| source.id() == "first_party"));
        assert!(sources.iter().any(|source| source.id() == "provider_api"));
    }
}
