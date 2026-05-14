//! Predictive analytics — open rate, click rate, unsub risk, k-means segmentation.

use crate::types::AiError;

/// Predictive analytics engine using simple statistical models.
pub struct AnalyticsPredictor {
    /// Baseline open-rate intercept.
    base_open_rate: f64,
    /// Baseline click-rate intercept.
    base_click_rate: f64,
}

impl Default for AnalyticsPredictor {
    fn default() -> Self {
        Self::new()
    }
}

impl AnalyticsPredictor {
    pub fn new() -> Self {
        Self {
            base_open_rate: 0.22,
            base_click_rate: 0.035,
        }
    }

    /// Predict the open rate for a subject line sent at a given hour/day.
    /// Uses a simple heuristic model:/// - Subject length sweet-spot bonus (30-60 chars)
    /// - Hour-of-day factor (business hours boost)
    /// - Day-of-week factor (Tue-Thu boost)
    pub fn predict_open_rate(&self, subject: &str, hour: u8, day_of_week: u8) -> f64 {
        let len = subject.len() as f64;

        // Length factor — sweet spot 30-60 chars
        let len_factor = if (30.0..=60.0).contains(&len) {
            1.1
        } else if !(15.0..=100.0).contains(&len) {
            0.85
        } else {
            1.0
        };

        // Hour factor — peak 9-11 and 14-16
        let hour_factor = match hour {
            9..=11 => 1.15,
            14..=16 => 1.10,
            7..=8 | 17..=19 => 1.0,
            _ => 0.85,
        };

        // Day factor — Tue(1), Wed(2), Thu(3) best (0=Mon)
        let day_factor = match day_of_week {
            1..=3 => 1.12,
            0 | 4 => 1.0,
            _ => 0.88,
        };

        let rate = self.base_open_rate * len_factor * hour_factor * day_factor;
        rate.clamp(0.0, 1.0)
    }

    /// Predict click-through rate given CTA text and its position.
    /// Position:0 = above-fold (best), higher = further down.
    pub fn predict_click_rate(&self, cta_text: &str, position: u32) -> f64 {
        let word_count = cta_text.split_whitespace().count();
        // Short CTAs (2-5 words) perform best
        let word_factor = if (2..=5).contains(&word_count) {
            1.2
        } else if word_count == 1 {
            0.9
        } else {
            0.85
        };

        // Urgency keywords boost
        let lower = cta_text.to_lowercase();
        let urgency_factor = if lower.contains("now")
            || lower.contains("today")
            || lower.contains("free")
            || lower.contains("limited")
        {
            1.15
        } else {
            1.0
        };

        // Position decay
        let pos_factor = 1.0 / (1.0 + 0.15 * position as f64);

        let rate = self.base_click_rate * word_factor * urgency_factor * pos_factor;
        rate.clamp(0.0, 1.0)
    }

    /// Predict unsubscribe risk given send frequency (per week) and
    /// engagement score (0.0 – 1.0).
    pub fn predict_unsubscribe_risk(&self, frequency: f64, engagement: f64) -> f64 {
        // High frequency + low engagement → high risk
        let freq_factor = if frequency > 5.0 {
            1.6
        } else if frequency > 3.0 {
            1.2
        } else {
            1.0
        };
        let eng_factor = 1.0 - engagement.clamp(0.0, 1.0) * 0.8;
        let base_risk = 0.02;
        (base_risk * freq_factor * eng_factor * 10.0).clamp(0.0, 1.0)
    }

    /// Simple k-means clustering of engagement scores.
    /// Returns a `Vec<usize>` of cluster assignments (0..k) for each score.
    pub fn segment_users(
        &self,
        engagement_scores: &[f64],
        k: usize,
    ) -> Result<Vec<usize>, AiError> {
        if k == 0 || engagement_scores.is_empty() {
            return Err(AiError::InvalidInput(
                "k and scores must be non-empty".into(),
            ));
        }
        let n = engagement_scores.len();
        if k > n {
            return Err(AiError::InvalidInput(
                "k must be <= number of scores".into(),
            ));
        }

        // K-means++ initialisation: select centroids probabilistically, with
        // probability proportional to squared distance from nearest existing
        // centroid. This avoids empty clusters common with naive first-k-points
        // or evenly-spaced initialization (M-37).
        use rand::Rng;
        let mut rng = rand::rng();
        let mut centroids: Vec<f64> = Vec::with_capacity(k);

        // Pick the first centroid uniformly at random
        let first_idx = rng.random_range(0..n);
        centroids.push(engagement_scores[first_idx]);

        for _ in 1..k {
            // Compute squared distance from each point to its nearest centroid
            let mut distances: Vec<f64> = engagement_scores
                .iter()
                .map(|&score| {
                    centroids
                        .iter()
                        .map(|&c| (score - c).abs().powi(2))
                        .fold(f64::INFINITY, f64::min)
                })
                .collect();

            // Total of all distances for normalisation
            let total: f64 = distances.iter().sum();
            if total <= 0.0 {
                // All remaining points are identical to existing centroids;
                // pick remaining centroids uniformly as fallback
                let fallback_idx = rng.random_range(0..n);
                centroids.push(engagement_scores[fallback_idx]);
                continue;
            }

            // Normalise to probabilities
            let mut cumulative = 0.0_f64;
            for d in distances.iter_mut() {
                cumulative += *d / total;
                *d = cumulative;
            }

            // Sample next centroid according to weighted distribution
            let r: f64 = rng.random();
            let chosen = distances.iter().position(|&d| r <= d).unwrap_or(n - 1);
            centroids.push(engagement_scores[chosen]);
        }

        let mut assignments = vec![0usize; n];
        let max_iters = 100;

        for _ in 0..max_iters {
            // Assign each point to the nearest centroid
            let mut changed = false;
            for (i, &score) in engagement_scores.iter().enumerate() {
                let best = centroids
                    .iter()
                    .enumerate()
                    .min_by(|(_, a), (_, b)| {
                        (score - *a)
                            .abs()
                            .partial_cmp(&(score - *b).abs())
                            .unwrap_or(std::cmp::Ordering::Equal)
                    })
                    .map(|(idx, _)| idx)
                    .unwrap_or(0);
                if assignments[i] != best {
                    assignments[i] = best;
                    changed = true;
                }
            }
            if !changed {
                break;
            }

            // Recompute centroids
            for (c, centroid) in centroids.iter_mut().enumerate().take(k) {
                let (sum, count) = engagement_scores
                    .iter()
                    .zip(assignments.iter())
                    .filter(|(_, &a)| a == c)
                    .fold((0.0, 0u64), |(s, cnt), (&v, _)| (s + v, cnt + 1));
                if count > 0 {
                    *centroid = sum / count as f64;
                }
            }
        }

        Ok(assignments)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_predict_open_rate_business_hours() {
        let p = AnalyticsPredictor::new();
        let morning = p.predict_open_rate("Great deal inside", 10, 2);
        let midnight = p.predict_open_rate("Great deal inside", 2, 2);
        assert!(
            morning > midnight,
            "morning rate {morning} should beat midnight {midnight}"
        );
    }

    #[test]
    fn test_predict_click_rate_urgency_boost() {
        let p = AnalyticsPredictor::new();
        let urgent = p.predict_click_rate("Buy now free shipping", 0);
        let bland = p.predict_click_rate("Learn more about features", 0);
        assert!(
            urgent > bland,
            "urgent CTA {urgent} should beat bland {bland}"
        );
    }

    #[test]
    fn test_predict_unsubscribe_risk() {
        let p = AnalyticsPredictor::new();
        let high_risk = p.predict_unsubscribe_risk(7.0, 0.1);
        let low_risk = p.predict_unsubscribe_risk(1.0, 0.9);
        assert!(
            high_risk > low_risk,
            "high-freq low-engagement {high_risk} should be riskier than {low_risk}"
        );
        assert!(high_risk <= 1.0);
        assert!(low_risk >= 0.0);
    }

    #[test]
    fn test_segment_users_kmeans() {
        let p = AnalyticsPredictor::new();
        let scores = vec![0.1, 0.12, 0.15, 0.5, 0.55, 0.9, 0.92, 0.95];
        let assignments = p.segment_users(&scores, 3).unwrap();
        assert_eq!(assignments.len(), 8);
        // Points close together should be in the same cluster
        assert_eq!(assignments[0], assignments[1]);
        assert_eq!(assignments[5], assignments[6]);
        // Low-engagement and high-engagement should differ
        assert_ne!(assignments[0], assignments[7]);
    }
}
