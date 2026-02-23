//! Tenant trust scoring.
//!
//! Computes a 0–100 score based on sending behaviour metrics:
//! bounce rate, complaint rate, engagement rate, account age, and volume.

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

/// Stateless trust scorer.
pub struct TrustScorer;

impl TrustScorer {
    /// Compute a trust score in the range 0–100.
    ///
    /// Scoring weights (total = 100):
    ///  - Bounce rate:     30 pts (lower is better)
    ///  - Complaint rate:  25 pts (lower is better)
    ///  - Engagement rate: 20 pts (higher is better)
    ///  - Account age:     15 pts (older is better, cap at 365 d)
    ///  - Volume:          10 pts (higher is better, cap at 100 k)
    pub fn compute_score(metrics: &TenantMetrics) -> TrustScore {
        let bounce_score = Self::inverse_score(metrics.bounce_rate, 0.10) * 30.0;
        let complaint_score = Self::inverse_score(metrics.complaint_rate, 0.01) * 25.0;
        let engagement_score = metrics.engagement_rate.clamp(0.0, 1.0) * 20.0;
        let age_score = (metrics.age_days as f64 / 365.0).clamp(0.0, 1.0) * 15.0;
        let volume_score = (metrics.volume as f64 / 100_000.0).clamp(0.0, 1.0) * 10.0;

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
        let score = TrustScorer::compute_score(&ideal_metrics());
        assert!(score.score >= 90.0, "ideal sender should score ≥90, got {}", score.score);
    }

    #[test]
    fn test_bad_bounce_rate_lowers_score() {
        let mut m = ideal_metrics();
        m.bounce_rate = 0.15; // over the 10% threshold
        let score = TrustScorer::compute_score(&m);
        assert!(score.score < 80.0, "high bounce rate should lower score; got {}", score.score);
    }

    #[test]
    fn test_new_tenant_lower_score() {
        let mut m = ideal_metrics();
        m.age_days = 7;
        m.volume = 50;
        let score = TrustScorer::compute_score(&m);
        let ideal_score = TrustScorer::compute_score(&ideal_metrics()).score;
        assert!(
            score.score < ideal_score,
            "new tenant ({}) should score lower than ideal ({})",
            score.score,
            ideal_score
        );
    }

    #[test]
    fn test_score_clamped_to_0_100() {
        let m = TenantMetrics {
            tenant_id: Uuid::new_v4(),
            bounce_rate: 1.0,
            complaint_rate: 1.0,
            engagement_rate: 0.0,
            age_days: 0,
            volume: 0,
        };
        let score = TrustScorer::compute_score(&m);
        assert!(score.score >= 0.0 && score.score <= 100.0);
    }
}
