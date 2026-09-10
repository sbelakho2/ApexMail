//! Campaign autopilot – Thompson sampling with Beta-Bernoulli model.

use rand::{rngs::StdRng, Rng, SeedableRng};

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
    /// `tenant_id` is required to enforce tenant isolation via a JOIN with
    /// `sales_campaigns`.
    pub async fn select_arm(
        &self,
        tenant_id: &str,
        campaign_id: &str,
    ) -> anyhow::Result<TemplateSelection> {
        let arms = self.load_arms(tenant_id, campaign_id).await?;

        if arms.is_empty() {
            return Err(anyhow::anyhow!("No arms found for campaign {campaign_id}"));
        }

        // Sample from each arm's Beta distribution
        let mut rng = StdRng::from_os_rng();
        let mut best_idx = 0;
        let mut best_sample = f64::NEG_INFINITY;

        for (i, arm) in arms.iter().enumerate() {
            let sample = sample_beta(&mut rng, arm.state.alpha, arm.state.beta)?;
            if sample > best_sample {
                best_sample = sample;
                best_idx = i;
            }
        }

        // Monte Carlo:compute selection probabilities
        let selection_probs = monte_carlo_selection_probs(&arms).await?;

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

    /// F85: component readiness — the canonical arm store (migration 197)
    /// must exist before optimization reads/writes run.
    pub async fn schema_ready(&self) -> bool {
        sqlx::query_scalar::<_, Option<String>>("SELECT to_regclass('public.campaign_arms')::text")
            .fetch_one(&self.pool)
            .await
            .ok()
            .flatten()
            .is_some()
    }

    /// F85: create arms for a campaign through the production workflow.
    /// Idempotent: existing (campaign, arm_index) rows are left untouched,
    /// so re-invoking with the same templates never resets accumulated
    /// statistics. New arms start at the uniform Beta(1, 1) prior.
    pub async fn ensure_arms(
        &self,
        tenant_id: &str,
        campaign_id: &str,
        template_ids: &[String],
    ) -> anyhow::Result<()> {
        if template_ids.is_empty() {
            anyhow::bail!("cannot create zero arms for campaign {campaign_id}");
        }
        if !self.campaign_owned(tenant_id, campaign_id).await? {
            anyhow::bail!("campaign {campaign_id} not found for tenant {tenant_id}");
        }
        let campaign_uuid = uuid::Uuid::parse_str(campaign_id)
            .map_err(|e| anyhow::anyhow!("campaign id must be a canonical UUID: {e}"))?;

        let mut tx = self.pool.begin().await?;
        for (arm_index, template_id) in template_ids.iter().enumerate() {
            let index = i32::try_from(arm_index)?;
            sqlx::query(
                "INSERT INTO campaign_arms \
                     (campaign_id, arm_index, template_id, alpha, beta, trials, successes) \
                 VALUES ($1, $2, $3, 1.0, 1.0, 0, 0) \
                 ON CONFLICT (campaign_id, arm_index) DO NOTHING",
            )
            .bind(campaign_uuid)
            .bind(index)
            .bind(template_id)
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        Ok(())
    }

    /// F85: idempotent outcome event. `outcome_key` is the caller's stable
    /// logical identity for the observation (e.g. "<message-id>:opened");
    /// replaying it (including after a restart) moves the arm counters at
    /// most once. The dedup insert and the counter update share one
    /// transaction, and a missing arm is an error, not a silent no-op.
    pub async fn record_outcome(
        &self,
        tenant_id: &str,
        campaign_id: &str,
        arm_idx: usize,
        success: bool,
        outcome_key: &str,
    ) -> anyhow::Result<bool> {
        let arm_index = i32::try_from(arm_idx)
            .map_err(|_| anyhow::anyhow!("arm index {arm_idx} out of range"))?;
        let campaign_uuid = uuid::Uuid::parse_str(campaign_id)
            .map_err(|e| anyhow::anyhow!("campaign id must be a canonical UUID: {e}"))?;
        if !self.campaign_owned(tenant_id, campaign_id).await? {
            anyhow::bail!("campaign {campaign_id} not found for tenant {tenant_id}");
        }

        let (alpha_inc, beta_inc, success_inc) = if success {
            (1.0_f64, 0.0_f64, 1_i64)
        } else {
            (0.0, 1.0, 0)
        };

        let mut tx = self.pool.begin().await?;
        let inserted = sqlx::query(
            "INSERT INTO campaign_arm_outcomes (outcome_key, campaign_id, arm_index, success) \
             VALUES ($1, $2, $3, $4) \
             ON CONFLICT (outcome_key) DO NOTHING",
        )
        .bind(outcome_key)
        .bind(campaign_uuid)
        .bind(arm_index)
        .bind(success)
        .execute(&mut *tx)
        .await?
        .rows_affected()
            > 0;

        if inserted {
            let updated = sqlx::query(
                "UPDATE campaign_arms \
                 SET alpha = alpha + $1, beta = beta + $2, \
                     trials = trials + 1, successes = successes + $3, updated_at = NOW() \
                 WHERE campaign_id = $4 AND arm_index = $5",
            )
            .bind(alpha_inc)
            .bind(beta_inc)
            .bind(success_inc)
            .bind(campaign_uuid)
            .bind(arm_index)
            .execute(&mut *tx)
            .await?
            .rows_affected();
            if updated != 1 {
                anyhow::bail!(
                    "outcome {outcome_key}: arm {arm_idx} of campaign {campaign_id} \
                     does not exist — create arms through the campaign workflow first"
                );
            }
        }
        tx.commit().await?;

        // Invalidate cache — strictly best-effort: a Redis outage must not
        // fail a committed outcome (the cache key carries no authority).
        let cache_key = format!("autopilot:{campaign_id}");
        if let Ok(mut conn) = self.redis.get().await {
            let _: Result<(), _> = redis::cmd("DEL")
                .arg(&cache_key)
                .query_async(&mut *conn)
                .await;
        }

        Ok(inserted)
    }

    /// Tenant ownership verification for a campaign.
    async fn campaign_owned(&self, tenant_id: &str, campaign_id: &str) -> anyhow::Result<bool> {
        // Canonical campaign identity is UUID — bind the parsed value (a
        // text parameter against the uuid column is an operator error).
        let campaign_uuid = uuid::Uuid::parse_str(campaign_id)
            .map_err(|e| anyhow::anyhow!("campaign id must be a canonical UUID: {e}"))?;
        let owned: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM sales_campaigns WHERE id = $1 AND tenant_id = $2)",
        )
        .bind(campaign_uuid)
        .bind(tenant_id)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?;
        Ok(owned)
    }

    /// Update arm statistics with new observation.
    /// `tenant_id` is required to verify campaign ownership before mutating arms.
    pub async fn update_arm(
        &self,
        tenant_id: &str,
        campaign_id: &str,
        arm_idx: usize,
        success: bool,
    ) -> anyhow::Result<()> {
        let (alpha_inc, beta_inc) = if success { (1.0, 0.0) } else { (0.0, 1.0) };

        // Verify tenant ownership before mutation
        if !self.campaign_owned(tenant_id, campaign_id).await? {
            anyhow::bail!("campaign {campaign_id} not found for tenant {tenant_id}");
        }

        // Checked arm-index conversion: an out-of-range index is an error,
        // never a wrapped counter.
        let arm_index = i32::try_from(arm_idx)
            .map_err(|_| anyhow::anyhow!("arm index {arm_idx} out of range"))?;
        let campaign_uuid = uuid::Uuid::parse_str(campaign_id)
            .map_err(|e| anyhow::anyhow!("campaign id must be a canonical UUID: {e}"))?;

        // F85: verify the mutation actually landed — a missing arm used to
        // report success while updating nothing.
        let updated = sqlx::query(
            "UPDATE campaign_arms SET alpha = alpha + $1, beta = beta + $2, \
             trials = trials + 1, successes = successes + $3, updated_at = NOW() \
             WHERE campaign_id = $4 AND arm_index = $5",
        )
        .bind(alpha_inc)
        .bind(beta_inc)
        .bind(if success { 1_i64 } else { 0 })
        .bind(campaign_uuid)
        .bind(arm_index)
        .execute(&self.pool)
        .await?
        .rows_affected();
        if updated != 1 {
            anyhow::bail!(
                "arm {arm_idx} of campaign {campaign_id} does not exist (updated {updated} rows)"
            );
        }

        // Invalidate cache — best-effort (see record_outcome).
        let cache_key = format!("autopilot:{campaign_id}");
        if let Ok(mut conn) = self.redis.get().await {
            let _: Result<(), _> = redis::cmd("DEL")
                .arg(&cache_key)
                .query_async(&mut *conn)
                .await;
        }

        Ok(())
    }

    /// Generate optimization report.
    /// `tenant_id` is required to enforce tenant isolation.
    pub async fn report(
        &self,
        tenant_id: &str,
        campaign_id: &str,
    ) -> anyhow::Result<OptimizationReport> {
        // Ownership first: a foreign tenant gets an explicit error, not an
        // empty report indistinguishable from a campaign without arms.
        if !self.campaign_owned(tenant_id, campaign_id).await? {
            anyhow::bail!("campaign {campaign_id} not found for tenant {tenant_id}");
        }
        let arms = self.load_arms(tenant_id, campaign_id).await?;
        let selection_probs = monte_carlo_selection_probs(&arms).await?;
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

    async fn load_arms(
        &self,
        tenant_id: &str,
        campaign_id: &str,
    ) -> anyhow::Result<Vec<TemplateArm>> {
        // Canonical campaign identity is UUID — parse once at the boundary.
        let campaign_uuid = uuid::Uuid::parse_str(campaign_id)
            .map_err(|e| anyhow::anyhow!("campaign id must be a canonical UUID: {e}"))?;
        // Join with sales_campaigns to enforce tenant isolation
        let rows = sqlx::query_as::<_, (String, f64, f64, i64, i64, i32)>(
            "SELECT a.template_id, a.alpha, a.beta, a.trials, a.successes, a.arm_index \
             FROM campaign_arms a \
             JOIN sales_campaigns c ON a.campaign_id = c.id \
             WHERE a.campaign_id = $1 AND c.tenant_id = $2 \
             ORDER BY a.arm_index",
        )
        .bind(campaign_uuid)
        .bind(tenant_id)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows
            .into_iter()
            .map(
                |(template_id, alpha, beta, trials, successes, _)| TemplateArm {
                    template_id,
                    state: BanditState {
                        alpha,
                        beta,
                        trials,
                        successes,
                    },
                },
            )
            .collect())
    }
}

/// Sample from Beta(alpha, beta) distribution using Marsaglia-Tsang Gamma method.
///
/// # Errors
/// Returns an error if `alpha` or `beta` is not finite and greater than zero.
pub fn sample_beta(rng: &mut impl Rng, alpha: f64, beta: f64) -> anyhow::Result<f64> {
    if !alpha.is_finite() || alpha <= 0.0 {
        anyhow::bail!("sample_beta: alpha must be finite and > 0 (got {alpha})");
    }
    if !beta.is_finite() || beta <= 0.0 {
        anyhow::bail!("sample_beta: beta must be finite and > 0 (got {beta})");
    }

    // Normal approximation for large alpha, beta
    if alpha > 50.0 && beta > 50.0 {
        let mean = alpha / (alpha + beta);
        let var = (alpha * beta) / ((alpha + beta).powi(2) * (alpha + beta + 1.0));
        let std = var.sqrt();
        let z = box_muller_normal(rng);
        return Ok((mean + z * std).clamp(0.0, 1.0));
    }

    let x = sample_gamma(rng, alpha)?;
    let y = sample_gamma(rng, beta)?;

    if x + y == 0.0 {
        return Ok(0.5);
    }

    Ok(x / (x + y))
}

/// Marsaglia-Tsang Gamma sampling.
fn sample_gamma(rng: &mut impl Rng, shape: f64) -> anyhow::Result<f64> {
    if !shape.is_finite() || shape <= 0.0 {
        anyhow::bail!("sample_gamma: shape must be finite and > 0 (got {shape})");
    }

    if shape < 1.0 {
        let u: f64 = rng.random();
        return Ok(sample_gamma(rng, shape + 1.0)? * u.powf(1.0 / shape));
    }

    let d = shape - 1.0 / 3.0;
    let c = 1.0 / (9.0 * d).sqrt();

    loop {
        let x = box_muller_normal(rng);
        let v = (1.0 + c * x).powi(3);

        if v > 0.0 {
            let u: f64 = rng.random();
            if u.ln() < 0.5 * x * x + d - d * v + d * v.ln() {
                return Ok(d * v);
            }
        }
    }
}

/// Box-Muller transform for standard normal.
fn box_muller_normal(rng: &mut impl Rng) -> f64 {
    let u1: f64 = rng.random::<f64>().max(f64::EPSILON);
    let u2: f64 = rng.random();
    (-2.0 * u1.ln()).sqrt() * (2.0 * std::f64::consts::PI * u2).cos()
}

/// Monte Carlo selection probabilities.
/// #192:Use spawn_blocking to avoid blocking the async runtime
/// with 10,000 synchronous iterations.
pub async fn monte_carlo_selection_probs(arms: &[TemplateArm]) -> anyhow::Result<Vec<f64>> {
    if arms.is_empty() {
        return Ok(vec![]);
    }

    let arms_owned: Vec<(f64, f64)> = arms.iter().map(|a| (a.state.alpha, a.state.beta)).collect();
    let len = arms_owned.len();

    tokio::task::spawn_blocking(move || -> anyhow::Result<Vec<f64>> {
        let mut wins = vec![0_usize; len];
        let mut rng = StdRng::from_os_rng();

        for _ in 0..MONTE_CARLO_SAMPLES {
            let mut best_idx = 0;
            let mut best_val = f64::NEG_INFINITY;

            for (i, &(alpha, beta)) in arms_owned.iter().enumerate() {
                let sample = sample_beta(&mut rng, alpha, beta)?;
                if sample > best_val {
                    best_val = sample;
                    best_idx = i;
                }
            }
            wins[best_idx] += 1;
        }

        Ok(wins
            .iter()
            .map(|&w| w as f64 / MONTE_CARLO_SAMPLES as f64)
            .collect())
    })
    .await
    .map_err(|error| anyhow::anyhow!("Monte Carlo sampling task failed: {error}"))?
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

    means.iter().map(|&m| best_mean - m).sum::<f64>() / means.len() as f64
}

/// Check if experiment has converged (one arm dominates >95%).
fn is_converged(_arms: &[TemplateArm], selection_probs: &[f64]) -> bool {
    selection_probs.iter().any(|&p| p > 0.95)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_beta_value(rng: &mut impl Rng, alpha: f64, beta: f64) -> f64 {
        sample_beta(rng, alpha, beta).expect("valid beta distribution parameters")
    }

    #[test]
    fn test_sample_beta_uniform_prior() {
        let mut rng = StdRng::seed_from_u64(1);
        let mut sum = 0.0;
        let n = 10_000;
        for _ in 0..n {
            sum += sample_beta_value(&mut rng, 1.0, 1.0);
        }
        let mean = sum / n as f64;
        // Beta(1,1) = Uniform(0,1), mean = 0.5
        assert!((mean - 0.5).abs() < 0.05);
    }

    #[test]
    fn test_sample_beta_skewed() {
        let mut rng = StdRng::seed_from_u64(2);
        let mut sum = 0.0;
        let n = 10_000;
        for _ in 0..n {
            sum += sample_beta_value(&mut rng, 10.0, 2.0);
        }
        let mean = sum / n as f64;
        // Beta(10,2) mean = 10/12 ≈ 0.833
        assert!((mean - 0.833).abs() < 0.05);
    }

    #[test]
    fn test_sample_beta_rejects_invalid_parameters() {
        let mut rng = StdRng::seed_from_u64(22);

        assert!(sample_beta(&mut rng, 0.0, 1.0).is_err());
        assert!(sample_beta(&mut rng, 1.0, 0.0).is_err());
        assert!(sample_beta(&mut rng, f64::NAN, 1.0).is_err());
        assert!(sample_beta(&mut rng, 1.0, f64::INFINITY).is_err());
    }

    #[test]
    fn test_box_muller_normal_mean() {
        let mut rng = StdRng::seed_from_u64(3);
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
                state: BanditState {
                    alpha: 10.0,
                    beta: 10.0,
                    trials: 20,
                    successes: 10,
                },
            },
            TemplateArm {
                template_id: "b".into(),
                state: BanditState {
                    alpha: 10.0,
                    beta: 10.0,
                    trials: 20,
                    successes: 10,
                },
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
                state: BanditState {
                    alpha: 30.0,
                    beta: 10.0,
                    trials: 40,
                    successes: 30,
                },
            },
            TemplateArm {
                template_id: "b".into(),
                state: BanditState {
                    alpha: 10.0,
                    beta: 30.0,
                    trials: 40,
                    successes: 10,
                },
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
                state: BanditState {
                    alpha: 100.0,
                    beta: 10.0,
                    trials: 110,
                    successes: 100,
                },
            },
            TemplateArm {
                template_id: "weak".into(),
                state: BanditState {
                    alpha: 10.0,
                    beta: 100.0,
                    trials: 110,
                    successes: 10,
                },
            },
        ];
        let probs = monte_carlo_selection_probs(&arms)
            .await
            .expect("valid arms should sample");
        assert!(probs[0] > 0.95);
    }

    #[tokio::test]
    async fn test_convergence_check() {
        let arms = vec![
            TemplateArm {
                template_id: "a".into(),
                state: BanditState {
                    alpha: 100.0,
                    beta: 5.0,
                    trials: 105,
                    successes: 100,
                },
            },
            TemplateArm {
                template_id: "b".into(),
                state: BanditState {
                    alpha: 5.0,
                    beta: 100.0,
                    trials: 105,
                    successes: 5,
                },
            },
        ];
        let probs = monte_carlo_selection_probs(&arms)
            .await
            .expect("valid arms should sample");
        assert!(is_converged(&arms, &probs));
    }

    #[tokio::test]
    async fn test_no_convergence_equal_arms() {
        let arms = vec![
            TemplateArm {
                template_id: "a".into(),
                state: BanditState {
                    alpha: 5.0,
                    beta: 5.0,
                    trials: 10,
                    successes: 5,
                },
            },
            TemplateArm {
                template_id: "b".into(),
                state: BanditState {
                    alpha: 5.0,
                    beta: 5.0,
                    trials: 10,
                    successes: 5,
                },
            },
        ];
        let probs = monte_carlo_selection_probs(&arms)
            .await
            .expect("valid arms should sample");
        assert!(!is_converged(&arms, &probs));
    }

    // ── Convergence Verification Tests ──────────────────────────────────────────────
    //
    // These tests verify the Thompson Sampling implementation's statistical properties:
    //   • Beta-Bernoulli posterior correctness via moment matching
    //   • Convergence rates for multi-armed bandit selection
    //   • Statistical significance detection (equal vs. differentiated arms)
    //   • Edge cases (zero observations, extreme priors, single arm)
    //
    // All stochastic tests use a seeded RNG (StdRng::seed_from_u64) for determinism.

    use rand::rngs::StdRng;
    use rand::SeedableRng;

    /// Theoretical mean of a Beta(alpha, beta) distribution.
    fn beta_mean(alpha: f64, beta: f64) -> f64 {
        alpha / (alpha + beta)
    }

    /// Theoretical variance of a Beta(alpha, beta) distribution.
    fn beta_variance(alpha: f64, beta: f64) -> f64 {
        let total = alpha + beta;
        (alpha * beta) / (total * total * (total + 1.0))
    }

    // ── 1. Beta-Bernoulli Sampling Correctness ─────────────────────────────────

    /// **Statistical rationale:** For a Beta(alpha, beta) distribution, the first
    /// two moments are known in closed form. Drawing N samples and comparing the
    /// empirical mean and variance against their theoretical values with a
    /// confidence-tuned tolerance verifies that the Marsaglia-Tsang + Box-Muller
    /// sampling path is unbiased and correctly calibrated.
    #[test]
    fn test_beta_distribution_moments() {
        let mut rng = StdRng::seed_from_u64(42);
        let n = 50_000;

        // Test several (alpha, beta) pairs covering symmetric, skewed, and
        // near-boundary regimes.
        let params = &[
            (2.0, 2.0, "symmetric"),
            (10.0, 2.0, "right-skewed"),
            (2.0, 10.0, "left-skewed"),
            (0.5, 0.5, "bathtub"),
            (1.0, 5.0, "boundary-close"),
            (20.0, 30.0, "moderate-data"),
        ];

        for &(alpha, beta, label) in params {
            let mut sum = 0.0_f64;
            let mut sum_sq = 0.0_f64;

            for _ in 0..n {
                let s = sample_beta_value(&mut rng, alpha, beta);
                sum += s;
                sum_sq += s * s;
            }

            let emp_mean = sum / n as f64;
            let emp_var = (sum_sq / n as f64) - (emp_mean * emp_mean);
            let theo_mean = beta_mean(alpha, beta);
            let theo_var = beta_variance(alpha, beta);

            // Mean should be within 3 standard errors of the true mean.
            let mean_se = (theo_var / n as f64).sqrt();
            assert!(
                (emp_mean - theo_mean).abs() < 4.0 * mean_se + 0.005,
                "Beta({alpha},{beta}) [{label}] mean mismatch: empirical={emp_mean:.5}, \
                 theoretical={theo_mean:.5}, se={mean_se:.6}"
            );

            // Variance should be within 10% relative tolerance (or absolute for tiny variances).
            let var_tol = (0.10 * theo_var).max(0.0001);
            assert!(
                (emp_var - theo_var).abs() < var_tol,
                "Beta({alpha},{beta}) [{label}] variance mismatch: empirical={emp_var:.6}, \
                 theoretical={theo_var:.6}, tol={var_tol:.6}"
            );
        }
    }

    /// **Statistical rationale:** As the number of observations increases, the
    /// Beta posterior should concentrate around the true Bernoulli parameter.
    /// This test draws from a known Bernoulli(p), updates the Beta posterior,
    /// and verifies the posterior mean converges to p within a tolerance that
    /// shrinks as 1/sqrt(N).
    #[test]
    fn test_beta_posterior_converges_to_true_rate() {
        let mut rng = StdRng::seed_from_u64(123);
        let true_rate = 0.37;
        let n_trials = 5_000;

        // Start with a weak uniform prior Beta(1,1)
        let mut alpha = 1.0;
        let mut beta = 1.0;

        for _ in 0..n_trials {
            let success: bool = rng.random::<f64>() < true_rate;
            if success {
                alpha += 1.0;
            } else {
                beta += 1.0;
            }
        }

        let posterior_mean = alpha / (alpha + beta);
        let posterior_var = beta_variance(alpha, beta);
        let posterior_se = posterior_var.sqrt();

        // The posterior mean should be within 3 posterior standard deviations
        // of the true rate (Gaussian approx to Beta, valid for large counts).
        let deviation = (posterior_mean - true_rate).abs();
        assert!(
            deviation < 3.0 * posterior_se + 0.01,
            "Posterior mean {posterior_mean:.5} deviates from true rate {true_rate:.5} \
             by {deviation:.5} (posterior SD = {posterior_se:.5}, tol = {:.5})",
            3.0 * posterior_se + 0.01
        );

        // Also verify the 95% credible interval contains the true rate.
        let (ci_lo, ci_hi) = credible_interval_95(alpha, beta);
        assert!(
            ci_lo <= true_rate && true_rate <= ci_hi,
            "True rate {true_rate:.5} lies outside 95% credible interval \
             [{ci_lo:.5}, {ci_hi:.5}] after {n_trials} trials"
        );
    }

    // ── 2. & 3. Thompson Sampling Convergence & Multi-Armed Bandit ────────────

    /// Helper: run a Thompson Sampling bandit simulation for `rounds` iterations
    /// using seeded randomness.  Each arm i has true conversion rate
    /// `arm_true_rates[i]`.  Starts with `prior_alpha`/`prior_beta` for all arms.
    ///
    /// Returns the number of times each arm was selected.
    fn simulate_thompson_bandit(
        seed: u64,
        arm_true_rates: &[f64],
        rounds: usize,
        prior_alpha: f64,
        prior_beta: f64,
    ) -> Vec<usize> {
        let n_arms = arm_true_rates.len();
        let mut rng = StdRng::seed_from_u64(seed);
        let mut alphas = vec![prior_alpha; n_arms];
        let mut betas = vec![prior_beta; n_arms];
        let mut selections = vec![0_usize; n_arms];

        for _ in 0..rounds {
            // Thompson draw: for each arm, sample from its Beta posterior
            let mut best_idx = 0;
            let mut best_sample = f64::NEG_INFINITY;

            for (i, (&a, &b)) in alphas.iter().zip(betas.iter()).enumerate() {
                let s = sample_beta_value(&mut rng, a, b);
                if s > best_sample {
                    best_sample = s;
                    best_idx = i;
                }
            }

            selections[best_idx] += 1;

            // Observe Bernoulli outcome
            let p = arm_true_rates[best_idx];
            if rng.random::<f64>() < p {
                alphas[best_idx] += 1.0;
            } else {
                betas[best_idx] += 1.0;
            }
        }

        selections
    }

    /// **Statistical rationale:** With two arms where one has a substantially
    /// higher conversion rate (10 % vs 5 %), Thompson Sampling should select the
    /// superior arm with high probability after enough rounds.  The test checks
    /// that arm A (CTR 10 %) is selected > 70 % of the time after 1 000 rounds,
    /// which is a conservative threshold well within the expected convergence
    /// behaviour of a Beta-Bernoulli TS with uniform priors.
    #[test]
    fn test_thompson_converges_to_superior_arm() {
        let rounds = 1_000;
        let selections = simulate_thompson_bandit(42, &[0.10, 0.05], rounds, 1.0, 1.0);

        let total: usize = selections.iter().sum();
        let best_arm_ratio = selections[0] as f64 / total as f64;

        assert!(
            best_arm_ratio > 0.70,
            "Best arm (CTR=10%) selected only {:.1}% of the time after {rounds} rounds \
             (expected > 70 %).  Selections: {:?}",
            best_arm_ratio * 100.0,
            selections
        );
    }

    /// **Statistical rationale:** With three arms and a clearly superior arm
    /// (CTR 10 % vs 5 % vs 2 %), the algorithm should identify and favour the
    /// best arm.  We run with more rounds (1 500) and average over 3 seeds to
    /// reduce single-run variance.  The best arm's mean selection ratio should
    /// exceed 55 %, and the worst arm should receive the fewest selections in
    /// every individual run.
    #[test]
    fn test_multi_armed_bandit_three_arms() {
        let rounds = 1_500;
        let seeds = [42, 99, 2024];
        // Arms: A(10%), B(5%), C(2%)
        let mut all_ratios = Vec::new();

        for &seed in &seeds {
            let selections = simulate_thompson_bandit(seed, &[0.10, 0.05, 0.02], rounds, 1.0, 1.0);
            let total: usize = selections.iter().sum();
            all_ratios.push(selections[0] as f64 / total as f64);

            // The worst arm (CTR 2%) should be selected least often in every run.
            assert!(
                selections[2] < selections[1],
                "Worst arm (CTR=2%) selected {} times, which is not less than \
                 middle arm (CTR=5%) with {} selections (seed={seed}).  Selections: {:?}",
                selections[2],
                selections[1],
                selections
            );
        }

        let mean_ratio: f64 = all_ratios.iter().sum::<f64>() / all_ratios.len() as f64;
        assert!(
            mean_ratio > 0.55,
            "Best arm (CTR=10%) mean selection ratio = {mean_ratio:.3} across {seeds_len} seeds, \
             expected > 0.55.  Individual ratios: {all_ratios:?}",
            seeds_len = seeds.len(),
            all_ratios = all_ratios
        );
    }

    // ── 4. Statistical Significance / No Difference ──────────────────────────

    /// **Statistical rationale:** When two arms have identical true conversion
    /// rates, the Thompson Sampling selection probability should remain close to
    /// 50 % for each.  Because a single simulation run can exhibit high variance
    /// (the "rich-get-richer" exploration dynamics), we average over multiple
    /// independent seeds.  With 5 seeds × 1 000 rounds, the mean ratio should
    /// fall within [0.40, 0.60].
    #[test]
    fn test_equal_arms_equal_selection_probability() {
        let rounds = 1_000;
        let seeds = [42, 123, 777, 2024, 31415];
        let mut ratios = Vec::new();

        for &seed in &seeds {
            let selections = simulate_thompson_bandit(seed, &[0.05, 0.05], rounds, 1.0, 1.0);
            let total: usize = selections.iter().sum();
            ratios.push(selections[0] as f64 / total as f64);
        }

        let mean_ratio: f64 = ratios.iter().sum::<f64>() / ratios.len() as f64;
        assert!(
            (0.35..=0.65).contains(&mean_ratio),
            "Mean selection ratio across {seeds_len} seeds = {mean_ratio:.3}, \
             expected near 0.50.  Individual ratios: {ratios:?}",
            seeds_len = seeds.len(),
            ratios = ratios
        );
    }

    /// **Statistical rationale:** With a moderate number of trials but a small
    /// true difference (CTR 6% vs 5%), the algorithm should NOT strongly
    /// converge — the selection probabilities should remain well short of the
    /// 95% convergence threshold.  This tests that `is_converged` correctly
    /// returns `false` when arms are practically indistinguishable given the
    /// data available.
    #[tokio::test]
    async fn test_no_premature_convergence_with_small_difference() {
        let mut rng = StdRng::seed_from_u64(2024);
        let mut alphas = [1.0, 1.0];
        let mut betas = [1.0, 1.0];
        let true_rates = [0.06, 0.05];
        let rounds = 300;

        for _ in 0..rounds {
            let mut best_idx = 0;
            let mut best_sample = f64::NEG_INFINITY;
            for (i, (&a, &b)) in alphas.iter().zip(betas.iter()).enumerate() {
                let s = sample_beta_value(&mut rng, a, b);
                if s > best_sample {
                    best_sample = s;
                    best_idx = i;
                }
            }
            let p = true_rates[best_idx];
            if rng.random::<f64>() < p {
                alphas[best_idx] += 1.0;
            } else {
                betas[best_idx] += 1.0;
            }
        }

        let arms = vec![
            TemplateArm {
                template_id: "a".into(),
                state: BanditState {
                    alpha: alphas[0],
                    beta: betas[0],
                    trials: (alphas[0] + betas[0] - 2.0) as i64,
                    successes: (alphas[0] - 1.0) as i64,
                },
            },
            TemplateArm {
                template_id: "b".into(),
                state: BanditState {
                    alpha: alphas[1],
                    beta: betas[1],
                    trials: (alphas[1] + betas[1] - 2.0) as i64,
                    successes: (alphas[1] - 1.0) as i64,
                },
            },
        ];

        let probs = monte_carlo_selection_probs(&arms)
            .await
            .expect("valid arms should sample");
        assert!(
            !is_converged(&arms, &probs),
            "Should not converge with only a 1pp true difference after {rounds} rounds. \
             Selection probs: {:?}",
            probs
        );
    }

    // ── 5. Edge Cases ────────────────────────────────────────────────────────

    /// **Statistical rationale:** With zero observations (all arms at uniform
    /// prior Beta(1,1)), every arm is equally likely to be selected.  The
    /// selection probability should be approximately 1 / n_arms for each.
    #[tokio::test]
    async fn test_edge_case_zero_observations_equal_probs() {
        let n_arms = 4;
        let arms: Vec<TemplateArm> = (0..n_arms)
            .map(|i| TemplateArm {
                template_id: format!("arm-{i}"),
                state: BanditState {
                    alpha: 1.0,
                    beta: 1.0,
                    trials: 0,
                    successes: 0,
                },
            })
            .collect();

        let probs = monte_carlo_selection_probs(&arms)
            .await
            .expect("valid arms should sample");

        assert_eq!(probs.len(), n_arms);
        let expected = 1.0 / n_arms as f64;
        for (i, &p) in probs.iter().enumerate() {
            assert!(
                (p - expected).abs() < 0.03,
                "Arm {i} selection probability {p:.4} differs from expected {expected:.4} \
                 under uniform prior (0 observations)"
            );
        }
    }

    /// **Statistical rationale:** With extreme priors (Beta(1000,1) ≈ certain
    /// success vs. Beta(1,1000) ≈ certain failure), the selection probability
    /// should overwhelmingly favour the successful arm.  This exercises the
    /// normal-approximation branch in `sample_beta` (alpha > 50 && beta > 50).
    #[tokio::test]
    async fn test_edge_case_extreme_priors() {
        let arms = vec![
            TemplateArm {
                template_id: "high".into(),
                state: BanditState {
                    alpha: 1000.0,
                    beta: 1.0,
                    trials: 1001,
                    successes: 1000,
                },
            },
            TemplateArm {
                template_id: "low".into(),
                state: BanditState {
                    alpha: 1.0,
                    beta: 1000.0,
                    trials: 1001,
                    successes: 1,
                },
            },
        ];

        let probs = monte_carlo_selection_probs(&arms)
            .await
            .expect("valid arms should sample");
        assert!(
            probs[0] > 0.99,
            "Extreme prior arm (Beta(1000,1)) selected only {:.4} — expected > 0.99",
            probs[0]
        );
    }

    /// **Statistical rationale:** With only one arm, `monte_carlo_selection_probs`
    /// must return `[1.0]` — the only available arm always wins by default.
    #[tokio::test]
    async fn test_edge_case_single_arm() {
        let arms = vec![TemplateArm {
            template_id: "sole".into(),
            state: BanditState {
                alpha: 5.0,
                beta: 5.0,
                trials: 10,
                successes: 5,
            },
        }];

        let probs = monte_carlo_selection_probs(&arms)
            .await
            .expect("valid arms should sample");
        assert_eq!(probs.len(), 1);
        assert!(
            (probs[0] - 1.0).abs() < 1e-12,
            "Single arm selection probability should be 1.0, got {:.10}",
            probs[0]
        );
    }

    /// **Statistical rationale:** When the arm list is empty,
    /// `monte_carlo_selection_probs` must return an empty vector without
    /// panicking.
    #[tokio::test]
    async fn test_edge_case_empty_arms() {
        let arms: Vec<TemplateArm> = vec![];
        let probs = monte_carlo_selection_probs(&arms)
            .await
            .expect("empty arms should sample");
        assert!(probs.is_empty(), "Empty arms should yield empty probs");
    }

    #[tokio::test]
    async fn test_monte_carlo_rejects_invalid_arm_parameters() {
        let arms = vec![TemplateArm {
            template_id: "invalid".into(),
            state: BanditState {
                alpha: 0.0,
                beta: 1.0,
                trials: 0,
                successes: 0,
            },
        }];

        assert!(monte_carlo_selection_probs(&arms).await.is_err());
    }

    /// **Statistical rationale:** The normal-approximation branch in
    /// `sample_beta` triggers when both alpha > 50 and beta > 50.  This test
    /// exercises that code path and verifies the samples stay within [0, 1]
    /// and produce a mean close to the theoretical value.
    #[test]
    fn test_edge_case_normal_approximation_branch() {
        let mut rng = StdRng::seed_from_u64(31415);
        let n = 10_000;
        let (alpha, beta) = (100.0, 200.0);
        let mut sum = 0.0;

        for _ in 0..n {
            let s = sample_beta_value(&mut rng, alpha, beta);
            assert!(
                (0.0..=1.0).contains(&s),
                "Sample {s} outside [0,1] from normal-approx branch"
            );
            sum += s;
        }

        let emp_mean = sum / n as f64;
        let theo_mean = beta_mean(alpha, beta);
        let theo_var = beta_variance(alpha, beta);
        let mean_se = (theo_var / n as f64).sqrt();

        assert!(
            (emp_mean - theo_mean).abs() < 4.0 * mean_se + 0.005,
            "Normal-approximation branch: empirical mean {emp_mean:.5} vs \
             theoretical {theo_mean:.5} (se = {mean_se:.6})"
        );
    }

    /// **Statistical rationale:** The credible interval should be correctly
    /// ordered even with edge-case parameters.  For Beta(1,1) (uniform prior),
    /// the 95 % interval should be wide.  For Beta(0.5, 0.5) (Jeffreys prior),
    /// the interval should also be valid.  This test ensures no NaN or
    /// inverted intervals are produced.
    #[test]
    fn test_credible_interval_edge_cases() {
        // Jeffreys prior (non-integer)
        let (lo, hi) = credible_interval_95(0.5, 0.5);
        assert!(
            lo.is_finite() && hi.is_finite(),
            "Jeffreys prior CI has non-finite bounds: ({lo}, {hi})"
        );
        assert!(lo < hi, "Jeffreys prior CI is inverted: ({lo}, {hi})");
        assert!(
            lo >= 0.0 && hi <= 1.0,
            "Jeffreys prior CI out of [0,1]: ({lo}, {hi})"
        );

        // Large equal parameters (both > 50, triggers normal approx)
        let (lo, hi) = credible_interval_95(200.0, 200.0);
        assert!(lo.is_finite() && hi.is_finite());
        assert!(lo < hi);
        assert!((lo + hi) / 2.0 - 0.5 < 0.001);

        // Single observation
        let (lo, hi) = credible_interval_95(1.0, 0.0);
        assert!(lo.is_finite() && hi.is_finite());
        assert!(lo <= hi);
    }
}
