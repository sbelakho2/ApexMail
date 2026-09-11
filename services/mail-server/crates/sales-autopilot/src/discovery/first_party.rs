//! First-party discovery source.
//!
//! Surfaces companies ApexMail already knows about for the tenant
//! (`sales_accounts`) as discovery candidates — the "our own activity" source.
//! No external call, no scraping. The tenant is fixed at construction because
//! [`DiscoverySource::discover`] receives only the query.

use std::hash::{Hash, Hasher};

use sqlx::PgPool;

use super::provider::{
    DiscoveredCandidate, DiscoveryError, DiscoveryPage, DiscoveryQuery, DiscoverySource,
};

/// Page size ceiling for first-party lookups.
const FIRST_PARTY_PAGE_SIZE: usize = 200;

/// First-party (ApexMail activity) discovery source.
#[derive(Debug)]
pub struct FirstPartySource {
    db: PgPool,
    tenant_id: String,
}

impl FirstPartySource {
    pub fn new(db: PgPool, tenant_id: &str) -> Self {
        Self {
            db,
            tenant_id: tenant_id.to_string(),
        }
    }
}

#[async_trait::async_trait]
impl DiscoverySource for FirstPartySource {
    fn id(&self) -> &'static str {
        "first_party"
    }

    /// First-party data is ApexMail's own; no jurisdiction restriction.
    fn allowed_jurisdictions(&self) -> &[&'static str] {
        &[]
    }

    async fn discover(
        &self,
        query: &DiscoveryQuery,
        cursor: Option<&str>,
    ) -> Result<DiscoveryPage, DiscoveryError> {
        let offset = cursor
            .and_then(|value| value.parse::<i64>().ok())
            .unwrap_or(0)
            .max(0);
        let limit = query
            .effective_max_results()
            .min(FIRST_PARTY_PAGE_SIZE)
            .max(1) as i64;

        let mut patterns: Vec<String> = Vec::new();
        for term in query.keywords.iter().chain(query.industries.iter()) {
            let term = term.trim();
            if !term.is_empty() {
                patterns.push(format!("%{}%", escape_like(term)));
            }
        }
        let countries: Vec<String> = query
            .countries
            .iter()
            .map(|country| country.trim().to_ascii_uppercase())
            .filter(|country| !country.is_empty())
            .collect();

        let rows: Vec<(String, String, String, Option<String>, Option<String>)> = sqlx::query_as(
            "SELECT id::text, company, domain, country, industry
             FROM sales_accounts
             WHERE tenant_id = $1
               AND (cardinality($2::text[]) = 0
                    OR company ILIKE ANY($2)
                    OR COALESCE(industry, '') ILIKE ANY($2))
               AND (cardinality($3::text[]) = 0
                    OR upper(COALESCE(country, '')) = ANY($3))
             ORDER BY updated_at DESC, id ASC
             LIMIT $4 OFFSET $5",
        )
        .bind(&self.tenant_id)
        .bind(&patterns)
        .bind(&countries)
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.db)
        .await
        .map_err(|error| {
            DiscoveryError::Internal(format!("first-party discovery query failed: {error}"))
        })?;

        let candidates: Vec<DiscoveredCandidate> = rows
            .into_iter()
            .map(
                |(id, company, domain, country, industry)| DiscoveredCandidate {
                    source: "first_party".to_string(),
                    source_url: Some(format!("first-party://account/{id}")),
                    company_name: Some(company),
                    domain: Some(domain),
                    jurisdiction: country.clone(),
                    jurisdiction_confidence: if country.is_some() { 0.6 } else { 0.0 },
                    confidence: 0.8,
                    raw_snapshot_hash: Some(row_hash(&id, industry.as_deref())),
                },
            )
            .collect();

        let next_cursor = if candidates.len() as i64 == limit {
            Some((offset + limit).to_string())
        } else {
            None
        };

        Ok(DiscoveryPage {
            candidates,
            next_cursor,
            cost_eur: 0.0,
        })
    }
}

fn row_hash(id: &str, industry: Option<&str>) -> String {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    id.hash(&mut hasher);
    industry.hash(&mut hasher);
    format!("{:016x}", hasher.finish())
}

fn escape_like(input: &str) -> String {
    input
        .replace('\\', "\\\\")
        .replace('%', "\\%")
        .replace('_', "\\_")
}
