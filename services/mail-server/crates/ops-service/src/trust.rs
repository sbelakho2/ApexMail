//! Tenant trust scoring.
//!
//! Computes a 0–100 score based on sending behaviour metrics:
//! bounce rate, complaint rate, engagement rate, account age, and volume.
//!
//! Scoring weights are configurable via [`TrustScorerConfig`] (O-23.6).

use chrono::Utc;
use uuid::Uuid;

use crate::types::{TrustFactors, TrustScore};

/// Input metrics used to compute a trust score.
#[derive(Debug, Clone)]
pub struct TenantMetrics {
    pub tenant_id: Uuid,
    /// Fraction of bounced emails (0.0–1.0).
    pub bounce_rate: f64,
    /// Fraction of complaint reports (0.0–1.0).
    pub complaint_rate: f64,
    /// Fraction of opens + clicks vs. delivered (0.0–1.0).
    pub engagement_rate: f64,
    /// Account age in days.
    pub age_days: u64,
    /// Total emails sent in the evaluation window.
    pub volume: u64,
}

/// Configurable scoring weights (O-23.6).
///
/// Each weight controls how many points that factor contributes to the
/// final 0–100 trust score. The weights do not need to sum to exactly 100;
/// each factor is scored 0.0–1.0 then multiplied by its weight.
#[derive(Debug, Clone)]
pub struct TrustScorerConfig {
    /// Weight for bounce rate (lower is better). Default: 30.0
    pub bounce_weight: f64,
    /// Weight for complaint rate (lower is better). Default: 25.0
    pub complaint_weight: f64,
    /// Weight for engagement rate (higher is better). Default: 20.0
    pub engagement_weight: f64,
    /// Weight for account age (older is better, cap at 365 d). Default: 15.0
    pub age_weight: f64,
    /// Weight for sending volume (higher is better, cap at 100 k). Default: 10.0
    pub volume_weight: f64,
    /// Bounce rate threshold for full penalty. Default: 0.10 (10%)
    pub bounce_threshold: f64,
    /// Complaint rate threshold for full penalty. Default: 0.01 (1%)
    pub complaint_threshold: f64,
    /// Account age cap in days. Default: 365.0
    pub age_cap_days: f64,
    /// Volume cap. Default: 100_000.0
    pub volume_cap: f64,
}

impl Default for TrustScorerConfig {
    fn default() -> Self {
        Self {
            bounce_weight: 30.0,
            complaint_weight: 25.0,
            engagement_weight: 20.0,
            age_weight: 15.0,
            volume_weight: 10.0,
            bounce_threshold: 0.10,
            complaint_threshold: 0.01,
            age_cap_days: 365.0,
            volume_cap: 100_000.0,
        }
    }
}

/// Trust scorer with optional custom weights.
///
/// Uses [`TrustScorerConfig::default`] when no custom config is provided.
#[derive(Default)]
pub struct TrustScorer {
    config: TrustScorerConfig,
}

impl TrustScorer {
    /// Create a scorer with default weights.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a scorer with custom weights.
    pub fn with_config(config: TrustScorerConfig) -> Self {
        Self { config }
    }

    /// Compute a trust score in the range 0–100.
    /// Weights are read from `self.config` instead of being hardcoded (O-23.6).
    pub fn compute_score(&self, metrics: &TenantMetrics) -> TrustScore {
        let cfg = &self.config;
        let bounce_score =
            Self::inverse_score(metrics.bounce_rate, cfg.bounce_threshold) * cfg.bounce_weight;
        let complaint_score = Self::inverse_score(metrics.complaint_rate, cfg.complaint_threshold)
            * cfg.complaint_weight;
        let engagement_score = metrics.engagement_rate.clamp(0.0, 1.0) * cfg.engagement_weight;
        let age_score =
            (metrics.age_days as f64 / cfg.age_cap_days).clamp(0.0, 1.0) * cfg.age_weight;
        let volume_score =
            (metrics.volume as f64 / cfg.volume_cap).clamp(0.0, 1.0) * cfg.volume_weight;

        let raw = bounce_score + complaint_score + engagement_score + age_score + volume_score;
        let score = raw.clamp(0.0, 100.0);

        TrustScore {
            tenant_id: metrics.tenant_id,
            score,
            factors: TrustFactors {
                bounce_rate: metrics.bounce_rate,
                complaint_rate: metrics.complaint_rate,
                engagement_rate: metrics.engagement_rate,
                age_days: metrics.age_days,
                volume: metrics.volume,
            },
            computed_at: Utc::now(),
        }
    }

    /// Returns 1.0 when `rate` is 0 and approaches 0.0 as `rate` reaches `bad_threshold`.
    fn inverse_score(rate: f64, bad_threshold: f64) -> f64 {
        if bad_threshold <= 0.0 {
            return if rate <= 0.0 { 1.0 } else { 0.0 };
        }
        (1.0 - (rate / bad_threshold)).clamp(0.0, 1.0)
    }

    /// Convenience: compute score using default config (backwards-compatible).
    pub fn compute_score_default(metrics: &TenantMetrics) -> TrustScore {
        Self::default().compute_score(metrics)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ideal_metrics() -> TenantMetrics {
        TenantMetrics {
            tenant_id: Uuid::new_v4(),
            bounce_rate: 0.0,
            complaint_rate: 0.0,
            engagement_rate: 0.8,
            age_days: 400,
            volume: 200_000,
        }
    }

    #[test]
    fn test_perfect_sender_high_score() {
        let scorer = TrustScorer::new();
        let score = scorer.compute_score(&ideal_metrics());
        assert!(
            score.score >= 90.0,
            "ideal sender should score ≥90, got {}",
            score.score
        );
    }

    #[test]
    fn test_bad_bounce_rate_lowers_score() {
        let scorer = TrustScorer::new();
        let mut m = ideal_metrics();
        m.bounce_rate = 0.15; // over the 10% threshold
        let score = scorer.compute_score(&m);
        assert!(
            score.score < 80.0,
            "high bounce rate should lower score; got {}",
            score.score
        );
    }

    #[test]
    fn test_new_tenant_lower_score() {
        let scorer = TrustScorer::new();
        let mut m = ideal_metrics();
        m.age_days = 7;
        m.volume = 50;
        let score = scorer.compute_score(&m);
        let ideal_score = scorer.compute_score(&ideal_metrics()).score;
        assert!(
            score.score < ideal_score,
            "new tenant ({}) should score lower than ideal ({})",
            score.score,
            ideal_score
        );
    }

    #[test]
    fn test_score_clamped_to_0_100() {
        let scorer = TrustScorer::new();
        let m = TenantMetrics {
            tenant_id: Uuid::new_v4(),
            bounce_rate: 1.0,
            complaint_rate: 1.0,
            engagement_rate: 0.0,
            age_days: 0,
            volume: 0,
        };
        let score = scorer.compute_score(&m);
        assert!(score.score >= 0.0 && score.score <= 100.0);
    }

    #[test]
    fn test_custom_config_weights() {
        let cfg = TrustScorerConfig {
            bounce_weight: 50.0,
            complaint_weight: 50.0,
            engagement_weight: 0.0,
            age_weight: 0.0,
            volume_weight: 0.0,
            ..Default::default()
        };
        let scorer = TrustScorer::with_config(cfg);
        let mut m = ideal_metrics();
        m.bounce_rate = 0.05; // halfway to threshold, should get ~25 pts
        m.complaint_rate = 0.005; // halfway to threshold, should get ~25 pts
        let score = scorer.compute_score(&m);
        // With only bounce+complaint active, both at half → ~50 pts
        assert!((score.score - 50.0).abs() < 1e-9);
    }
}
