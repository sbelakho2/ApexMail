//! Campaign autopilot – Thompson sampling with Beta-Bernoulli model.

use rand::Rng;

use crate::types::*;

/// Number of Monte Carlo samples for selection probabilities.
const MONTE_CARLO_SAMPLES: usize = 10_000;

pub struct CampaignAutopilot {
    pool: sqlx::PgPool,
    redis: deadpool_redis::Pool,
}

impl CampaignAutopilot {
    pub fn new(pool: sqlx::PgPool, redis: deadpool_redis::Pool) -> Self {
        Self { pool, redis }
    }

/// Select the best template arm using Thompson sampling.
    pub async fn select_arm(
        &self,
        campaign_id: &str,
    ) -> anyhow::Result<TemplateSelection> {
        let arms = self.load_arms(campaign_id).await?;

        if arms.is_empty() {
            return Err(anyhow::anyhow!("No arms found for campaign {campaign_id}"));
        }

// Sample from each arm's Beta distribution
        let mut rng = rand::thread_rng();
        let mut best_idx = 0;
        let mut best_sample = f64::NEG_INFINITY;

        for (i, arm) in arms.iter().enumerate() {
            let sample = sample_beta(&mut rng, arm.state.alpha, arm.state.beta);
            if sample > best_sample {
                best_sample = sample;
                best_idx = i;
            }
        }

// Monte Carlo:compute selection probabilities
        let selection_probs = monte_carlo_selection_probs(&arms).await;

// Credible intervals
        let intervals: Vec<(f64, f64)> = arms
            .iter()
            .map(|a| credible_interval_95(a.state.alpha, a.state.beta))
            .collect();

        let expected_regret = compute_expected_regret(&arms);

        let converged = is_converged(&arms, &selection_probs);

        Ok(TemplateSelection {
            selected_arm: best_idx,
            template_id: arms[best_idx].template_id.clone(),
            selection_probabilities: selection_probs,
            credible_intervals: intervals,
            expected_regret,
            converged,
        })
    }

/// Update arm statistics with new observation.
    pub async fn update_arm(
        &self,
        campaign_id: &str,
        arm_idx: usize,
        success: bool,
    ) -> anyhow::Result<()> {
        let (alpha_inc, beta_inc) = if success { (1.0, 0.0) } else { (0.0, 1.0) };

        sqlx::query(
            "UPDATE campaign_arms SET alpha = alpha + $1, beta = beta + $2, \
             trials = trials + 1, successes = successes + $3 \
             WHERE campaign_id = $4 AND arm_index = $5",
        )
        .bind(alpha_inc)
        .bind(beta_inc)
        .bind(if success { 1_i64 } else { 0 })
        .bind(campaign_id)
        .bind(arm_idx as i32)
        .execute(&self.pool)
        .await?;

// Invalidate cache
        let cache_key = format!("autopilot:{campaign_id}");
        let mut conn = self.redis.get().await.map_err(|e| anyhow::anyhow!("{e}"))?;
        redis::cmd("DEL")
            .arg(&cache_key)
            .query_async::<()>(&mut *conn)
            .await
            .ok();

        Ok(())
    }

/// Generate optimization report.
    pub async fn report(
        &self,
        campaign_id: &str,
    ) -> anyhow::Result<OptimizationReport> {
        let arms = self.load_arms(campaign_id).await?;
        let selection_probs = monte_carlo_selection_probs(&arms).await;
        let intervals: Vec<(f64, f64)> = arms
            .iter()
            .map(|a| credible_interval_95(a.state.alpha, a.state.beta))
            .collect();
        let converged = is_converged(&arms, &selection_probs);

        let total_trials: i64 = arms.iter().map(|a| a.state.trials).sum();
        let best_arm = selection_probs
            .iter()
            .enumerate()
            .max_by(|a, b| a.1.partial_cmp(b.1).unwrap_or(std::cmp::Ordering::Equal))
            .map(|(i, _)| i)
            .unwrap_or(0);

        Ok(OptimizationReport {
            campaign_id: campaign_id.into(),
            arms: arms.iter().map(|a| a.state.clone()).collect(),
            selection_probabilities: selection_probs,
            credible_intervals: intervals,
            total_trials,
            converged,
            recommended_arm: best_arm,
        })
    }

    async fn load_arms(&self, campaign_id: &str) -> anyhow::Result<Vec<TemplateArm>> {
        let rows = sqlx::query_as::<_, (String, f64, f64, i64, i64, i32)>(
            "SELECT template_id, alpha, beta, trials, successes, arm_index \
             FROM campaign_arms WHERE campaign_id = $1 ORDER BY arm_index",
        )
        .bind(campaign_id)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows
            .into_iter()
            .map(|(template_id, alpha, beta, trials, successes, _)| TemplateArm {
                template_id,
                state: BanditState {
                    alpha,
                    beta,
                    trials,
                    successes,
                },
            })
            .collect())
    }
}

/// Sample from Beta(alpha, beta) distribution using Marsaglia-Tsang Gamma method.
pub fn sample_beta(rng: &mut impl Rng, alpha: f64, beta: f64) -> f64 {
// Normal approximation for large alpha, beta
    if alpha > 50.0 && beta > 50.0 {
        let mean = alpha / (alpha + beta);
        let var = (alpha * beta) / ((alpha + beta).powi(2) * (alpha + beta + 1.0));
        let std = var.sqrt();
        let z = box_muller_normal(rng);
        return (mean + z * std).clamp(0.0, 1.0);
    }

    let x = sample_gamma(rng, alpha);
    let y = sample_gamma(rng, beta);

    if x + y == 0.0 {
        return 0.5;
    }

    x / (x + y)
}

/// Marsaglia-Tsang Gamma sampling.
fn sample_gamma(rng: &mut impl Rng, shape: f64) -> f64 {
    if shape < 1.0 {
        let u: f64 = rng.gen();
        return sample_gamma(rng, shape + 1.0) * u.powf(1.0 / shape);
    }

    let d = shape - 1.0 / 3.0;
    let c = 1.0 / (9.0 * d).sqrt();

    loop {
        let x = box_muller_normal(rng);
        let v = (1.0 + c * x).powi(3);

        if v > 0.0 {
            let u: f64 = rng.gen();
            if u.ln() < 0.5 * x * x + d - d * v + d * v.ln() {
                return d * v;
            }
        }
    }
}

/// Box-Muller transform for standard normal.
fn box_muller_normal(rng: &mut impl Rng) -> f64 {
    let u1: f64 = rng.gen::<f64>().max(f64::EPSILON);
    let u2: f64 = rng.gen();
    (-2.0 * u1.ln()).sqrt() * (2.0 * std::f64::consts::PI * u2).cos()
}

/// Monte Carlo selection probabilities.
/// #192:Use spawn_blocking to avoid blocking the async runtime
/// with 10,000 synchronous iterations.
pub async fn monte_carlo_selection_probs(arms: &[TemplateArm]) -> Vec<f64> {
    if arms.is_empty() {
        return vec![];
    }

    let arms_owned: Vec<(f64, f64)> = arms.iter().map(|a| (a.state.alpha, a.state.beta)).collect();
    let len = arms_owned.len();

    tokio::task::spawn_blocking(move || {
        let mut wins = vec![0_usize; len];
        let mut rng = rand::thread_rng();

        for _ in 0..MONTE_CARLO_SAMPLES {
            let mut best_idx = 0;
            let mut best_val = f64::NEG_INFINITY;

            for (i, &(alpha, beta)) in arms_owned.iter().enumerate() {
                let sample = sample_beta(&mut rng, alpha, beta);
                if sample > best_val {
                    best_val = sample;
                    best_idx = i;
                }
            }
            wins[best_idx] += 1;
        }

        wins.iter()
            .map(|&w| w as f64 / MONTE_CARLO_SAMPLES as f64)
            .collect()
    })
    .await
    .unwrap_or_else(|_| vec![1.0 / len as f64; len])
}

/// 95% credible interval using normal approximation to Beta.
pub fn credible_interval_95(alpha: f64, beta: f64) -> (f64, f64) {
    let mean = alpha / (alpha + beta);
    let var = (alpha * beta) / ((alpha + beta).powi(2) * (alpha + beta + 1.0));
    let std = var.sqrt();
    let lower = (mean - 1.96 * std).max(0.0);
    let upper = (mean + 1.96 * std).min(1.0);
    (lower, upper)
}

/// Expected regret relative to best arm.
pub fn compute_expected_regret(arms: &[TemplateArm]) -> f64 {
    if arms.is_empty() {
        return 0.0;
    }

    let means: Vec<f64> = arms
        .iter()
        .map(|a| a.state.alpha / (a.state.alpha + a.state.beta))
        .collect();

    let best_mean = means.iter().cloned().fold(f64::NEG_INFINITY, f64::max);

    means
        .iter()
        .map(|&m| best_mean - m)
        .sum::<f64>()
        / means.len() as f64
}

/// Check if experiment has converged (one arm dominates >95%).
fn is_converged(_arms: &[TemplateArm], selection_probs: &[f64]) -> bool {
    selection_probs.iter().any(|&p| p > 0.95)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sample_beta_uniform_prior() {
        let mut rng = rand::thread_rng();
        let mut sum = 0.0;
        let n = 10_000;
        for _ in 0..n {
            sum += sample_beta(&mut rng, 1.0, 1.0);
        }
        let mean = sum / n as f64;
// Beta(1,1) = Uniform(0,1), mean = 0.5
        assert!((mean - 0.5).abs() < 0.05);
    }

    #[test]
    fn test_sample_beta_skewed() {
        let mut rng = rand::thread_rng();
        let mut sum = 0.0;
        let n = 10_000;
        for _ in 0..n {
            sum += sample_beta(&mut rng, 10.0, 2.0);
        }
        let mean = sum / n as f64;
// Beta(10,2) mean = 10/12 ≈ 0.833
        assert!((mean - 0.833).abs() < 0.05);
    }

    #[test]
    fn test_box_muller_normal_mean() {
        let mut rng = rand::thread_rng();
        let mut sum = 0.0;
        let n = 10_000;
        for _ in 0..n {
            sum += box_muller_normal(&mut rng);
        }
        let mean = sum / n as f64;
        assert!(mean.abs() < 0.1);
    }

    #[test]
    fn test_credible_interval_symmetric() {
        let (lo, hi) = credible_interval_95(50.0, 50.0);
        let mean = 0.5;
        assert!((lo + hi) / 2.0 - mean < 0.001);
        assert!(lo < mean);
        assert!(hi > mean);
    }

    #[test]
    fn test_credible_interval_tight_with_data() {
        let (lo, hi) = credible_interval_95(100.0, 100.0);
        let width = hi - lo;
        assert!(width < 0.15);
    }

    #[test]
    fn test_credible_interval_wide_with_little_data() {
        let (lo, hi) = credible_interval_95(1.0, 1.0);
        let width = hi - lo;
        assert!(width > 0.5);
    }

    #[test]
    fn test_expected_regret_identical_arms() {
        let arms = vec![
            TemplateArm {
                template_id: "a".into(),
                state: BanditState { alpha: 10.0, beta: 10.0, trials: 20, successes: 10 },
            },
            TemplateArm {
                template_id: "b".into(),
                state: BanditState { alpha: 10.0, beta: 10.0, trials: 20, successes: 10 },
            },
        ];
        let regret = compute_expected_regret(&arms);
        assert!((regret - 0.0).abs() < 0.001);
    }

    #[test]
    fn test_expected_regret_different_arms() {
        let arms = vec![
            TemplateArm {
                template_id: "a".into(),
                state: BanditState { alpha: 30.0, beta: 10.0, trials: 40, successes: 30 },
            },
            TemplateArm {
                template_id: "b".into(),
                state: BanditState { alpha: 10.0, beta: 30.0, trials: 40, successes: 10 },
            },
        ];
        let regret = compute_expected_regret(&arms);
        assert!(regret > 0.1);
    }

    #[tokio::test]
    async fn test_monte_carlo_clear_winner() {
        let arms = vec![
            TemplateArm {
                template_id: "strong".into(),
                state: BanditState { alpha: 100.0, beta: 10.0, trials: 110, successes: 100 },
            },
            TemplateArm {
                template_id: "weak".into(),
                state: BanditState { alpha: 10.0, beta: 100.0, trials: 110, successes: 10 },
            },
        ];
        let probs = monte_carlo_selection_probs(&arms).await;
        assert!(probs[0] > 0.95);
    }

    #[tokio::test]
    async fn test_convergence_check() {
        let arms = vec![
            TemplateArm {
                template_id: "a".into(),
                state: BanditState { alpha: 100.0, beta: 5.0, trials: 105, successes: 100 },
            },
            TemplateArm {
                template_id: "b".into(),
                state: BanditState { alpha: 5.0, beta: 100.0, trials: 105, successes: 5 },
            },
        ];
        let probs = monte_carlo_selection_probs(&arms).await;
        assert!(is_converged(&arms, &probs));
    }

    #[tokio::test]
    async fn test_no_convergence_equal_arms() {
        let arms = vec![
            TemplateArm {
                template_id: "a".into(),
                state: BanditState { alpha: 5.0, beta: 5.0, trials: 10, successes: 5 },
            },
            TemplateArm {
                template_id: "b".into(),
                state: BanditState { alpha: 5.0, beta: 5.0, trials: 10, successes: 5 },
            },
        ];
        let probs = monte_carlo_selection_probs(&arms).await;
        assert!(!is_converged(&arms, &probs));
    }
}
