//! Cost-aware provider routing (§10).
//!
//! # Objective
//!
//! For one field, choose the provider that maximises
//! `expected_information_gain / marginal_cost`. The exact ratio is unbounded
//! when a provider is free (and a free provider with zero observed coverage
//! would win an unbounded ratio with a division-by-zero limit), so the
//! implemented score expresses the same trade-off as a bounded additive
//! utility: information gain in field-coverage units minus the marginal cost
//! converted into the same units.
//!
//! # Formula
//!
//! ```text
//! gain      = coverage × (0.5 + 0.5 × accuracy) × (1 − error_rate) × staleness
//! staleness = 1 / (1 + max(0, days_since_success − 30) / 30)
//! score     = gain − COST_LAMBDA × cost_eur
//! ```
//!
//! * `coverage = fills / attempts` — probability the provider actually fills
//!   the field.
//! * `accuracy = verified_correct / fills` — discounted to
//!   `0.5 + 0.5·accuracy` because verification is asynchronous: a provider
//!   that has served fills but no verification yet is not treated as a liar,
//!   it is treated as half-known. Verified-wrong data decays the score.
//! * `1 − error_rate` — a provider that errors cannot deliver its coverage.
//! * `staleness` — no success in 30+ days starts discounting the score; a
//!   year-old success counts roughly half. An explicit `None` (no history)
//!   is *not* penalised; that is the exploration case.
//! * `COST_LAMBDA = 1.0` — one score unit per EUR. A provider must buy its
//!   extra coverage with at most that much price difference.
//!
//! # Cold start
//!
//! A provider with no `sales_provider_stats` row uses the documented priors
//! `coverage = 0.5`, `accuracy = 0.5`, `error_rate = 0`: the router explores
//! instead of refusing. With two equally unknown providers the cheaper one
//! wins; with equal cost the waterfall priority order breaks the tie.
//!
//! # Statistics
//!
//! [`record_attempt`], [`record_fill`], [`record_error`], [`record_cost`],
//! [`record_latency`] and [`record_verified_correct`] maintain
//! `sales_provider_stats` (migration
//! `200_sales_autopilot_v2_unification.sql:358-372`). Cost is only recorded
//! by the caller on a successful fill, so `total_cost_eur` never grows for a
//! failed lookup.

use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

use super::{EnrichmentProvider, ProviderId};
use crate::types::SalesError;

/// Coverage used when a provider has no history yet.
pub const PRIOR_COVERAGE: f64 = 0.5;
/// Accuracy used when a provider has no verification history yet.
pub const PRIOR_ACCURACY: f64 = 0.5;
/// Score units charged per EUR of marginal cost.
pub const COST_LAMBDA: f64 = 1.0;
/// Age (days) after which an old success starts to discount the score.
pub const STALE_AFTER_DAYS: f64 = 30.0;

/// Rolling statistics for one `(provider, field)` pair.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ProviderStats {
    pub attempts: i64,
    pub fills: i64,
    pub verified_correct: i64,
    pub total_latency_ms: i64,
    pub total_cost_eur: f64,
    pub errors: i64,
    pub last_success_at: Option<DateTime<Utc>>,
}

impl ProviderStats {
    /// `fills / attempts`; the documented prior when there is no history.
    pub fn coverage(&self) -> f64 {
        if self.attempts <= 0 {
            PRIOR_COVERAGE
        } else {
            ratio(self.fills, self.attempts)
        }
    }

    /// `verified_correct / fills`; the documented prior when nothing was
    /// filled yet.
    pub fn accuracy(&self) -> f64 {
        if self.fills <= 0 {
            PRIOR_ACCURACY
        } else {
            ratio(self.verified_correct, self.fills)
        }
    }

    /// `errors / attempts`.
    pub fn error_rate(&self) -> f64 {
        if self.attempts <= 0 {
            0.0
        } else {
            ratio(self.errors, self.attempts)
        }
    }

    /// `total_latency_ms / attempts`.
    pub fn latency_ms(&self) -> f64 {
        if self.attempts <= 0 {
            0.0
        } else {
            self.total_latency_ms as f64 / self.attempts as f64
        }
    }

    /// Observed average cost per fill, when both are known.
    pub fn observed_cost(&self) -> Option<f64> {
        if self.fills > 0 && self.total_cost_eur > 0.0 {
            Some(self.total_cost_eur / self.fills as f64)
        } else {
            None
        }
    }

    /// Days since the last successful fill, when known.
    pub fn days_since_success(&self) -> Option<f64> {
        self.last_success_at
            .map(|success| (Utc::now() - success).num_seconds().max(0) as f64 / 86_400.0)
    }
}

fn ratio(numerator: i64, denominator: i64) -> f64 {
    if denominator <= 0 {
        return 0.0;
    }
    (numerator.max(0) as f64 / denominator as f64).clamp(0.0, 1.0)
}

/// The router's choice for one field.
#[derive(Debug, Clone, PartialEq)]
pub struct ProviderChoice {
    pub provider: ProviderId,
    pub expected_fill_probability: f64,
    pub cost_eur: f64,
    pub score: f64,
}

/// A routing candidate: the provider plus whatever statistics we have.
#[derive(Debug, Clone)]
pub struct RoutingCandidate<'a> {
    pub provider: &'a dyn EnrichmentProvider,
    /// `None` = no `sales_provider_stats` row → cold-start priors.
    pub stats: Option<ProviderStats>,
}

/// Pure routing score — the single place the trade-off is encoded, so it is
/// directly unit-testable. See the module docs for the formula.
pub fn routing_score(
    coverage: f64,
    accuracy: f64,
    cost_eur: f64,
    error_rate: f64,
    days_since_success: Option<f64>,
) -> f64 {
    let coverage = finite_clamp01(coverage);
    let accuracy = finite_clamp01(accuracy);
    let error_rate = finite_clamp01(error_rate);
    let cost = if cost_eur.is_finite() && cost_eur > 0.0 {
        cost_eur
    } else {
        0.0
    };
    let staleness = staleness_factor(days_since_success);

    let gain = coverage * (0.5 + 0.5 * accuracy) * (1.0 - error_rate) * staleness;
    gain - COST_LAMBDA * cost
}

fn staleness_factor(days_since_success: Option<f64>) -> f64 {
    match days_since_success {
        Some(days) if days.is_finite() && days > STALE_AFTER_DAYS => {
            1.0 / (1.0 + (days - STALE_AFTER_DAYS) / STALE_AFTER_DAYS)
        }
        _ => 1.0,
    }
}

fn finite_clamp01(value: f64) -> f64 {
    if value.is_nan() {
        0.0
    } else {
        value.clamp(0.0, 1.0)
    }
}

/// Effective (coverage, accuracy, error_rate, cost, days) for a candidate.
fn effective(candidate: &RoutingCandidate<'_>) -> (f64, f64, f64, f64, Option<f64>) {
    match &candidate.stats {
        Some(stats) if stats.attempts > 0 => (
            stats.coverage(),
            stats.accuracy(),
            stats.error_rate(),
            stats
                .observed_cost()
                .unwrap_or(candidate.provider.cost_eur().max(0.0)),
            stats.days_since_success(),
        ),
        _ => (
            PRIOR_COVERAGE,
            PRIOR_ACCURACY,
            0.0,
            candidate.provider.cost_eur().max(0.0),
            None,
        ),
    }
}

/// Choose the best provider for one field from already-loaded statistics.
///
/// Pure: no database, no clock reads beyond `Utc::now()` inside
/// `days_since_success` conversion. Returns `None` only for an empty
/// candidate list — a router that fails to act is never the answer.
pub fn choose_provider_from_stats(candidates: &[RoutingCandidate<'_>]) -> Option<ProviderChoice> {
    let mut best: Option<ProviderChoice> = None;
    for candidate in candidates {
        let (coverage, accuracy, error_rate, cost, days) = effective(candidate);
        let score = routing_score(coverage, accuracy, cost, error_rate, days);
        let choice = ProviderChoice {
            provider: candidate.provider.id(),
            expected_fill_probability: coverage,
            cost_eur: cost,
            score,
        };
        let replace = match &best {
            None => true,
            // Strictly greater keeps waterfall order on ties.
            Some(current) => choice.score > current.score,
        };
        if replace {
            best = Some(choice);
        }
    }
    best
}

/// Load the rolling statistics for one field and choose a provider.
///
/// `candidates` arrive in waterfall priority order; ties keep that order.
/// A provider with no row explores with [`PRIOR_COVERAGE`].
pub async fn choose_provider(
    db: &PgPool,
    tenant_id: &str,
    field: &str,
    candidates: &[&dyn EnrichmentProvider],
) -> Result<Option<ProviderChoice>, SalesError> {
    if candidates.is_empty() {
        return Ok(None);
    }

    let provider_ids: Vec<String> = candidates
        .iter()
        .map(|provider| provider.id().as_str().to_string())
        .collect();

    let rows: Vec<(String, i64, i64, i64, i64, f64, i64, Option<DateTime<Utc>>)> = sqlx::query_as(
        "SELECT provider, attempts, fills, verified_correct, total_latency_ms,
                    total_cost_eur::float8, errors, last_success_at
             FROM sales_provider_stats
             WHERE tenant_id = $1 AND field = $2 AND provider = ANY($3)",
    )
    .bind(tenant_id)
    .bind(field)
    .bind(&provider_ids)
    .fetch_all(db)
    .await
    .map_err(|error| SalesError::Database(error.to_string()))?;

    let routing: Vec<RoutingCandidate<'_>> = candidates
        .iter()
        .map(|provider| {
            let stats = rows
                .iter()
                .find(|(provider_name, ..)| provider_name == provider.id().as_str())
                .map(
                    |(
                        _,
                        attempts,
                        fills,
                        verified_correct,
                        total_latency_ms,
                        total_cost_eur,
                        errors,
                        last_success_at,
                    )| {
                        ProviderStats {
                            attempts: *attempts,
                            fills: *fills,
                            verified_correct: *verified_correct,
                            total_latency_ms: *total_latency_ms,
                            total_cost_eur: *total_cost_eur,
                            errors: *errors,
                            last_success_at: *last_success_at,
                        }
                    },
                );
            RoutingCandidate {
                provider: *provider,
                stats,
            }
        })
        .collect();

    Ok(choose_provider_from_stats(&routing))
}

// ---------------------------------------------------------------------------
// Statistics recording
// ---------------------------------------------------------------------------

async fn upsert_stat(
    db: &PgPool,
    tenant_id: &str,
    provider: ProviderId,
    field: &str,
    // (attempts, fills, verified, latency, cost, errors, success_now)
    delta: (i64, i64, i64, i64, f64, i64, bool),
) -> Result<(), SalesError> {
    let (attempts, fills, verified, latency, cost, errors, success) = delta;
    sqlx::query(
        "INSERT INTO sales_provider_stats (
            id, tenant_id, provider, field, attempts, fills, verified_correct,
            total_latency_ms, total_cost_eur, errors, last_success_at, updated_at
         ) VALUES (
            $1, $2, $3, $4, $5, $6, $7, $8, $9::float8::numeric, $10,
            CASE WHEN $11 THEN NOW() ELSE NULL END, NOW()
         )
         ON CONFLICT (tenant_id, provider, field) DO UPDATE SET
            attempts = sales_provider_stats.attempts + $5,
            fills = sales_provider_stats.fills + $6,
            verified_correct = sales_provider_stats.verified_correct + $7,
            total_latency_ms = sales_provider_stats.total_latency_ms + $8,
            total_cost_eur = sales_provider_stats.total_cost_eur + $9::float8::numeric,
            errors = sales_provider_stats.errors + $10,
            last_success_at = CASE WHEN $11 THEN NOW() ELSE sales_provider_stats.last_success_at END,
            updated_at = NOW()",
    )
    .bind(Uuid::new_v4())
    .bind(tenant_id)
    .bind(provider.as_str())
    .bind(field)
    .bind(attempts)
    .bind(fills)
    .bind(verified)
    .bind(latency)
    .bind(cost.max(0.0))
    .bind(errors)
    .bind(success)
    .execute(db)
    .await
    .map_err(|error| SalesError::Database(error.to_string()))?;
    Ok(())
}

/// Record that `(provider, field)` was attempted (called).
pub async fn record_attempt(
    db: &PgPool,
    tenant_id: &str,
    provider: ProviderId,
    field: &str,
) -> Result<(), SalesError> {
    upsert_stat(db, tenant_id, provider, field, (1, 0, 0, 0, 0.0, 0, false)).await
}

/// Record that an attempt produced a value.
pub async fn record_fill(
    db: &PgPool,
    tenant_id: &str,
    provider: ProviderId,
    field: &str,
) -> Result<(), SalesError> {
    upsert_stat(db, tenant_id, provider, field, (0, 1, 0, 0, 0.0, 0, true)).await
}

/// Record a provider call failure.
pub async fn record_error(
    db: &PgPool,
    tenant_id: &str,
    provider: ProviderId,
    field: &str,
) -> Result<(), SalesError> {
    upsert_stat(db, tenant_id, provider, field, (0, 0, 0, 0, 0.0, 1, false)).await
}

/// Record the marginal cost of a **successful** fill.
///
/// Callers must only invoke this after a fill — this is what keeps
/// `total_cost_eur` from growing on failed lookups.
pub async fn record_cost(
    db: &PgPool,
    tenant_id: &str,
    provider: ProviderId,
    field: &str,
    cost_eur: f64,
) -> Result<(), SalesError> {
    let cost = if cost_eur.is_finite() && cost_eur > 0.0 {
        cost_eur
    } else {
        return Ok(());
    };
    upsert_stat(db, tenant_id, provider, field, (0, 0, 0, 0, cost, 0, false)).await
}

/// Record call latency (milliseconds) for one lookup.
pub async fn record_latency(
    db: &PgPool,
    tenant_id: &str,
    provider: ProviderId,
    field: &str,
    latency_ms: i64,
) -> Result<(), SalesError> {
    upsert_stat(
        db,
        tenant_id,
        provider,
        field,
        (0, 0, 0, latency_ms.max(0), 0.0, 0, false),
    )
    .await
}

/// Record later verification of a filled value (`verified_correct`), which is
/// what turns reported coverage into accuracy.
pub async fn record_verified_correct(
    db: &PgPool,
    tenant_id: &str,
    provider: ProviderId,
    field: &str,
    delta: i64,
) -> Result<(), SalesError> {
    upsert_stat(
        db,
        tenant_id,
        provider,
        field,
        (0, 0, delta, 0, 0.0, 0, false),
    )
    .await
}

// ---------------------------------------------------------------------------
// Tests — pure routing semantics pinned by the audit examples
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::enrichment::{fields, EnrichmentError, EnrichmentRequest, ProviderPayload};

    #[derive(Debug)]
    struct StubProvider {
        id: ProviderId,
        cost: f64,
    }

    #[async_trait::async_trait]
    impl EnrichmentProvider for StubProvider {
        fn id(&self) -> ProviderId {
            self.id
        }
        fn fields(&self) -> &[&'static str] {
            &[fields::EMPLOYEE_COUNT]
        }
        fn cost_eur(&self) -> f64 {
            self.cost
        }
        async fn fetch(
            &self,
            _request: &EnrichmentRequest<'_>,
        ) -> Result<ProviderPayload, EnrichmentError> {
            Ok(ProviderPayload::new())
        }
    }

    fn stats(fills: i64, attempts: i64, verified: i64, errors: i64, cost: f64) -> ProviderStats {
        ProviderStats {
            attempts,
            fills,
            verified_correct: verified,
            total_latency_ms: attempts * 100,
            total_cost_eur: cost,
            errors,
            last_success_at: Some(Utc::now()),
        }
    }

    /// §10 headline example: equal coverage, A costs €0.002 vs B €0.03 → A.
    #[test]
    fn cheaper_provider_wins_at_equal_coverage() {
        let a = stats(94, 100, 94, 0, 0.188);
        let b = stats(94, 100, 94, 0, 2.82);
        let provider_a = StubProvider {
            id: ProviderId("provider_a"),
            cost: 0.002,
        };
        let provider_b = StubProvider {
            id: ProviderId("provider_b"),
            cost: 0.03,
        };
        let candidates = [
            RoutingCandidate {
                provider: &provider_a,
                stats: Some(a.clone()),
            },
            RoutingCandidate {
                provider: &provider_b,
                stats: Some(b.clone()),
            },
        ];
        let choice = choose_provider_from_stats(&candidates).expect("a choice");
        assert_eq!(choice.provider, ProviderId("provider_a"));
        assert!((choice.expected_fill_probability - 0.94).abs() < 1e-9);
        assert!(choice.cost_eur < 0.01);
    }

    /// ...but B can win when its much higher coverage justifies 15× the cost.
    #[test]
    fn higher_coverage_can_justify_higher_cost() {
        let a = stats(40, 100, 40, 0, 0.08);
        let b = stats(100, 100, 100, 0, 3.0);
        let provider_a = StubProvider {
            id: ProviderId("provider_a"),
            cost: 0.002,
        };
        let provider_b = StubProvider {
            id: ProviderId("provider_b"),
            cost: 0.03,
        };
        let candidates = [
            RoutingCandidate {
                provider: &provider_a,
                stats: Some(a),
            },
            RoutingCandidate {
                provider: &provider_b,
                stats: Some(b),
            },
        ];
        let choice = choose_provider_from_stats(&candidates).expect("a choice");
        assert_eq!(
            choice.provider,
            ProviderId("provider_b"),
            "information gain must be able to outbid a 15x price difference"
        );
        // Sanity check the pure function directly.
        let score_a = routing_score(0.4, 1.0, 0.002, 0.0, Some(0.0));
        let score_b = routing_score(1.0, 1.0, 0.03, 0.0, Some(0.0));
        assert!(score_b > score_a, "{score_b} should beat {score_a}");
    }

    /// Cold start: no history must still choose (explore) — never refuse.
    #[test]
    fn cold_start_explores_instead_of_refusing() {
        let provider_a = StubProvider {
            id: ProviderId("provider_a"),
            cost: 0.0,
        };
        let provider_b = StubProvider {
            id: ProviderId("provider_b"),
            cost: 0.01,
        };
        let candidates = [
            RoutingCandidate {
                provider: &provider_a,
                stats: None,
            },
            RoutingCandidate {
                provider: &provider_b,
                stats: None,
            },
        ];
        let choice = choose_provider_from_stats(&candidates).expect("cold start must still choose");
        assert_eq!(choice.provider, ProviderId("provider_a"));
        assert!(
            choice.score > 0.0,
            "prior coverage must produce a positive score: {}",
            choice.score
        );
        assert!((choice.expected_fill_probability - PRIOR_COVERAGE).abs() < 1e-9);
    }

    /// A provider with zero coverage after real attempts loses to exploration.
    #[test]
    fn dead_provider_loses_to_any_alternative() {
        let dead = stats(0, 100, 0, 40, 0.0);
        let provider_dead = StubProvider {
            id: ProviderId("dead"),
            cost: 0.0,
        };
        let provider_fresh = StubProvider {
            id: ProviderId("fresh"),
            cost: 0.02,
        };
        let candidates = [
            RoutingCandidate {
                provider: &provider_dead,
                stats: Some(dead),
            },
            RoutingCandidate {
                provider: &provider_fresh,
                stats: None,
            },
        ];
        let choice = choose_provider_from_stats(&candidates).expect("a choice");
        assert_eq!(choice.provider, ProviderId("fresh"));
    }

    /// An error rate near 1 must be deprioritised even when it is free.
    #[test]
    fn error_prone_provider_is_deprioritised_even_when_cheap() {
        let flaky = stats(50, 100, 50, 99, 0.0);
        let solid = stats(80, 100, 80, 1, 0.0);
        let provider_flaky = StubProvider {
            id: ProviderId("flaky"),
            cost: 0.0,
        };
        let provider_solid = StubProvider {
            id: ProviderId("solid"),
            cost: 0.02,
        };
        let candidates = [
            RoutingCandidate {
                provider: &provider_flaky,
                stats: Some(flaky),
            },
            RoutingCandidate {
                provider: &provider_solid,
                stats: Some(solid),
            },
        ];
        let choice = choose_provider_from_stats(&candidates).expect("a choice");
        assert_eq!(
            choice.provider,
            ProviderId("solid"),
            "near-total error rate must lose despite being free"
        );
        // Pure-function pin: gain is multiplied by (1 - error_rate).
        let with_errors = routing_score(0.9, 1.0, 0.0, 0.95, Some(0.0));
        let without_errors = routing_score(0.9, 1.0, 0.0, 0.0, Some(0.0));
        assert!(with_errors < without_errors);
    }

    /// Staleness discounts the score monotonically.
    #[test]
    fn stale_success_reduces_the_score() {
        let fresh = routing_score(0.9, 1.0, 0.0, 0.0, Some(1.0));
        let month = routing_score(0.9, 1.0, 0.0, 0.0, Some(60.0));
        let year = routing_score(0.9, 1.0, 0.0, 0.0, Some(365.0));
        assert!(fresh > month, "{fresh} > {month}");
        assert!(month > year, "{month} > {year}");

        // And it can flip a choice against a fresh competitor.
        let stale = ProviderStats {
            last_success_at: Some(Utc::now() - chrono::Duration::days(730)),
            ..stats(90, 100, 90, 0, 0.0)
        };
        let provider_stale = StubProvider {
            id: ProviderId("stale"),
            cost: 0.0,
        };
        let provider_fresh = StubProvider {
            id: ProviderId("fresh"),
            cost: 0.05,
        };
        let candidates = [
            RoutingCandidate {
                provider: &provider_stale,
                stats: Some(stale),
            },
            RoutingCandidate {
                provider: &provider_fresh,
                stats: None,
            },
        ];
        let choice = choose_provider_from_stats(&candidates).expect("a choice");
        assert_eq!(choice.provider, ProviderId("fresh"));
    }

    #[test]
    fn empty_candidate_list_is_the_only_none() {
        assert!(choose_provider_from_stats(&[]).is_none());
    }

    #[test]
    fn routing_score_is_bounded_and_nan_safe() {
        let score = routing_score(f64::NAN, f64::NAN, f64::NAN, f64::NAN, None);
        assert!(score.is_finite());
        assert!(score <= 0.0);
        let best = routing_score(1.0, 1.0, 0.0, 0.0, Some(0.0));
        assert!((best - 1.0).abs() < 1e-9);
    }

    #[test]
    fn stats_ratios_match_the_documented_definitions() {
        let stats = ProviderStats {
            attempts: 200,
            fills: 100,
            verified_correct: 80,
            total_latency_ms: 20_000,
            total_cost_eur: 2.0,
            errors: 20,
            last_success_at: Some(Utc::now() - chrono::Duration::days(10)),
        };
        assert!((stats.coverage() - 0.5).abs() < 1e-9);
        assert!((stats.accuracy() - 0.8).abs() < 1e-9);
        assert!((stats.error_rate() - 0.1).abs() < 1e-9);
        assert!((stats.latency_ms() - 100.0).abs() < 1e-9);
        assert!((stats.observed_cost().unwrap() - 0.02).abs() < 1e-9);
        assert!(stats.days_since_success().unwrap() > 9.0);
    }
}
