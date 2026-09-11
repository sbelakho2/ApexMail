//! Discovery provider abstraction.
//!
//! A [`DiscoverySource`] is an approved data source: a provider API, a
//! public source where permitted, ApexMail's own first-party activity, or a
//! clearly-labelled test fixture. Scraping arbitrary websites is deliberately
//! not part of this abstraction.
//!
//! Every source declares `allowed_jurisdictions()`. The empty slice means
//! "unrestricted"; a non-empty list is enforced by
//! [`crate::discovery::job`] before a candidate is persisted.

use serde::{Deserialize, Serialize};

/// Query handed to every source.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct DiscoveryQuery {
    #[serde(default)]
    pub keywords: Vec<String>,
    #[serde(default)]
    pub industries: Vec<String>,
    #[serde(default)]
    pub countries: Vec<String>,
    #[serde(default)]
    pub max_results: usize,
    #[serde(default)]
    pub categories: Vec<String>,
}

impl DiscoveryQuery {
    /// Hard cap on candidates requested from one page. A provider that
    /// ignores the query can still return more; the job runner truncates.
    pub const HARD_MAX_RESULTS: usize = 1_000;

    /// Clamp `max_results` into `1..=HARD_MAX_RESULTS`, defaulting to 25.
    pub fn effective_max_results(&self) -> usize {
        if self.max_results == 0 {
            25
        } else {
            self.max_results.clamp(1, Self::HARD_MAX_RESULTS)
        }
    }
}

/// One page of discovery results.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DiscoveryPage {
    pub candidates: Vec<DiscoveredCandidate>,
    #[serde(default)]
    pub next_cursor: Option<String>,
    #[serde(default)]
    pub cost_eur: f64,
}

/// One discovered company with full provenance.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DiscoveredCandidate {
    pub source: String,
    pub source_url: Option<String>,
    pub company_name: Option<String>,
    pub domain: Option<String>,
    pub jurisdiction: Option<String>,
    #[serde(default)]
    pub jurisdiction_confidence: f32,
    #[serde(default)]
    pub confidence: f32,
    pub raw_snapshot_hash: Option<String>,
}

/// Errors a discovery source may return.
#[derive(Debug, Clone, thiserror::Error)]
pub enum DiscoveryError {
    #[error("discovery source rejected credentials: {0}")]
    Unauthorized(String),
    #[error("discovery source unavailable: {0}")]
    Unavailable(String),
    #[error("discovery source rate limited: {0}")]
    RateLimited(String),
    #[error("discovery source returned invalid data: {0}")]
    InvalidResponse(String),
    #[error("discovery source failed: {0}")]
    Internal(String),
}

impl DiscoveryError {
    /// `sales_source_runs.status` value for this error.
    pub fn run_status(&self) -> &'static str {
        match self {
            DiscoveryError::RateLimited(_) => "rate_limited",
            _ => "failed",
        }
    }
}

/// An approved source of discovery candidates.
#[async_trait::async_trait]
pub trait DiscoverySource: Send + Sync + std::fmt::Debug {
    fn id(&self) -> &'static str;

    /// Jurisdictions this source is permitted to return data for;
    /// empty = unrestricted.
    fn allowed_jurisdictions(&self) -> &[&'static str];

    async fn discover(
        &self,
        query: &DiscoveryQuery,
        cursor: Option<&str>,
    ) -> Result<DiscoveryPage, DiscoveryError>;

    /// HTTP status of the most recent call, when the source talks HTTP. Used
    /// to populate `sales_source_runs.http_status`.
    fn last_http_status(&self) -> Option<i32> {
        None
    }
}

/// Enforce a source's jurisdiction declaration for one candidate.
///
/// * unrestricted source → always permitted;
/// * restricted source + known jurisdiction → exact (case-insensitive) match;
/// * restricted source + unknown jurisdiction → permitted, because the
///   declaration restricts *known* jurisdictions and refusing unknown ones
///   would silently discard every unlabelled candidate.
pub fn candidate_allowed_by_jurisdiction(
    allowed_jurisdictions: &[&str],
    candidate_jurisdiction: Option<&str>,
) -> bool {
    if allowed_jurisdictions.is_empty() {
        return true;
    }
    match candidate_jurisdiction
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        None => true,
        Some(jurisdiction) => allowed_jurisdictions
            .iter()
            .any(|allowed| allowed.eq_ignore_ascii_case(jurisdiction)),
    }
}

// ---------------------------------------------------------------------------
// FixtureSource — explicitly labelled test source
// ---------------------------------------------------------------------------

/// A deterministic in-memory source for tests and local development.
///
/// It is **not** wired into [`default_sources`](crate::discovery::default_sources):
/// tests must opt into it by constructing it by name.
#[derive(Debug)]
pub struct FixtureSource {
    id: &'static str,
    allowed_jurisdictions: Vec<&'static str>,
    candidates: Vec<DiscoveredCandidate>,
    page_size: usize,
    cost_per_page_eur: f64,
    fail_with: Option<DiscoveryError>,
}

impl FixtureSource {
    /// Create a fixture source with the given id and candidates.
    pub fn new(id: &'static str, candidates: Vec<DiscoveredCandidate>) -> Self {
        Self {
            id,
            allowed_jurisdictions: Vec::new(),
            candidates,
            page_size: 100,
            cost_per_page_eur: 0.0,
            fail_with: None,
        }
    }

    /// Restrict this source to the given jurisdictions.
    pub fn with_allowed_jurisdictions(mut self, allowed: Vec<&'static str>) -> Self {
        self.allowed_jurisdictions = allowed;
        self
    }

    /// Set the page size used for cursor pagination.
    pub fn with_page_size(mut self, page_size: usize) -> Self {
        self.page_size = page_size.max(1);
        self
    }

    /// Charge this many EUR for every page served.
    pub fn with_cost_per_page_eur(mut self, cost: f64) -> Self {
        self.cost_per_page_eur = if cost.is_finite() && cost > 0.0 {
            cost
        } else {
            0.0
        };
        self
    }

    /// Make every call fail with the given error.
    pub fn failing(mut self, error: DiscoveryError) -> Self {
        self.fail_with = Some(error);
        self
    }

    /// Build a candidate with only a company name, useful for tests.
    pub fn candidate(company_name: &str) -> DiscoveredCandidate {
        DiscoveredCandidate {
            source: String::new(),
            source_url: None,
            company_name: Some(company_name.to_string()),
            domain: None,
            jurisdiction: None,
            jurisdiction_confidence: 0.0,
            confidence: 0.5,
            raw_snapshot_hash: None,
        }
    }
}

#[async_trait::async_trait]
impl DiscoverySource for FixtureSource {
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
        if let Some(error) = &self.fail_with {
            return Err(error.clone());
        }

        let offset: usize = cursor
            .and_then(|value| value.parse().ok())
            .unwrap_or(0)
            .min(self.candidates.len());
        let limit = self.page_size.min(query.effective_max_results()).max(1);
        let end = (offset + limit).min(self.candidates.len());

        let candidates = self.candidates[offset..end]
            .iter()
            .cloned()
            .map(|mut candidate| {
                if candidate.source.is_empty() {
                    candidate.source = self.id.to_string();
                }
                candidate
            })
            .collect();

        let next_cursor = if end < self.candidates.len() {
            Some(end.to_string())
        } else {
            None
        };

        Ok(DiscoveryPage {
            candidates,
            next_cursor,
            cost_eur: self.cost_per_page_eur,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unrestricted_source_permits_every_jurisdiction() {
        assert!(candidate_allowed_by_jurisdiction(&[], Some("US")));
        assert!(candidate_allowed_by_jurisdiction(&[], None));
    }

    #[test]
    fn restricted_source_drops_disallowed_known_jurisdiction() {
        assert!(candidate_allowed_by_jurisdiction(&["EE", "FI"], Some("ee")));
        assert!(!candidate_allowed_by_jurisdiction(
            &["EE", "FI"],
            Some("US")
        ));
        // Unknown jurisdiction cannot be proven disallowed.
        assert!(candidate_allowed_by_jurisdiction(&["EE"], None));
        assert!(candidate_allowed_by_jurisdiction(&["EE"], Some("  ")));
    }

    #[tokio::test]
    async fn fixture_paginates_with_cursor_and_stamps_source() {
        let candidates = (0..5)
            .map(|index| FixtureSource::candidate(&format!("Company {index}")))
            .collect();
        let source = FixtureSource::new("fixture", candidates)
            .with_page_size(2)
            .with_cost_per_page_eur(0.25);
        let query = DiscoveryQuery {
            max_results: 100,
            ..DiscoveryQuery::default()
        };

        let first = source.discover(&query, None).await.unwrap();
        assert_eq!(first.candidates.len(), 2);
        assert_eq!(first.next_cursor.as_deref(), Some("2"));
        assert_eq!(first.cost_eur, 0.25);
        assert_eq!(first.candidates[0].source, "fixture");

        let second = source
            .discover(&query, first.next_cursor.as_deref())
            .await
            .unwrap();
        assert_eq!(second.candidates.len(), 2);
        let third = source
            .discover(&query, second.next_cursor.as_deref())
            .await
            .unwrap();
        assert_eq!(third.candidates.len(), 1);
        assert!(third.next_cursor.is_none());
    }

    #[tokio::test]
    async fn fixture_respects_query_max_results() {
        let candidates = (0..100)
            .map(|index| FixtureSource::candidate(&format!("Company {index}")))
            .collect();
        let source = FixtureSource::new("fixture", candidates).with_page_size(100);
        let query = DiscoveryQuery {
            max_results: 10,
            ..DiscoveryQuery::default()
        };
        let page = source.discover(&query, None).await.unwrap();
        assert_eq!(page.candidates.len(), 10);
    }

    #[tokio::test]
    async fn fixture_can_simulate_failures() {
        let source = FixtureSource::new("fixture", Vec::new())
            .failing(DiscoveryError::RateLimited("slow down".into()));
        let error = source
            .discover(&DiscoveryQuery::default(), None)
            .await
            .unwrap_err();
        assert_eq!(error.run_status(), "rate_limited");
        assert!(matches!(error, DiscoveryError::RateLimited(_)));
    }

    #[test]
    fn max_results_is_clamped() {
        let query = DiscoveryQuery {
            max_results: 0,
            ..DiscoveryQuery::default()
        };
        assert_eq!(query.effective_max_results(), 25);
        let query = DiscoveryQuery {
            max_results: usize::MAX,
            ..DiscoveryQuery::default()
        };
        assert_eq!(
            query.effective_max_results(),
            DiscoveryQuery::HARD_MAX_RESULTS
        );
    }
}
