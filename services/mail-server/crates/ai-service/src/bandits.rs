//! Multi-armed bandit optimiser — epsilon-greedy with Thompson sampling.

use parking_lot::RwLock;
use rand::Rng;
use std::sync::Arc;

use crate::types::{AiError, BanditArm};

/// Epsilon-greedy multi-armed bandit with Thompson-sampling support.
pub struct BanditOptimizer {
    epsilon: f64,
    arms: Arc<RwLock<Vec<BanditArm>>>,
}

impl BanditOptimizer {
/// Create a new optimiser with the given exploration rate (0.0–1.0).
    pub fn new(epsilon: f64) -> Self {
        Self {
            epsilon: epsilon.clamp(0.0, 1.0),
            arms: Arc::new(RwLock::new(Vec::new())),
        }
    }

/// Register a new arm and return its ID.
    pub fn add_arm(&self, name: &str) -> String {
        let arm = BanditArm::new(name);
        let id = arm.id.clone();
        self.arms.write().push(arm);
        id
    }

/// Select an arm using epsilon-greedy strategy.
/// With probability `epsilon` choose a random arm (explore);
/// otherwise choose the arm with the highest observed reward (exploit).
    pub fn select_arm(&self) -> Result<String, AiError> {
        let arms = self.arms.read();
        if arms.is_empty() {
            return Err(AiError::InvalidInput("no arms registered".into()));
        }

        let mut rng = rand::thread_rng();
        let idx = if rng.gen::<f64>() < self.epsilon || arms.iter().all(|a| a.impressions == 0) {
// Explore:pick random arm
            rng.gen_range(0..arms.len())
        } else {
// Exploit:pick best conversion rate
            match arms.iter()
                .enumerate()
                .max_by(|(_, a), (_, b)| {
                    a.conversion_rate()
                        .partial_cmp(&b.conversion_rate())
                        .unwrap_or(std::cmp::Ordering::Equal)
                })
                .map(|(i, _)| i)
            {
                Some(i) => i,
                None => return Err(AiError::InvalidInput("no available bandit arms".into())),
            }
        };

        Ok(arms[idx].id.clone())
    }

/// Record a reward observation for an arm.
    pub fn record_reward(&self, arm_id: &str, reward: f64) -> Result<(), AiError> {
        let mut arms = self.arms.write();
        let arm = arms
            .iter_mut()
            .find(|a| a.id == arm_id)
            .ok_or_else(|| AiError::ArmNotFound(arm_id.to_string()))?;

        arm.impressions += 1;
        arm.reward += reward;
        if reward > 0.0 {
            arm.conversions += 1;
        }
        Ok(())
    }

/// Return a snapshot of all arms with their statistics.
    pub fn get_stats(&self) -> Vec<BanditArm> {
        self.arms.read().clone()
    }

/// Thompson sampling approximation for an arm using the Beta distribution.
/// Uses the normal approximation to Beta(α, β):mean = α/(α+β),
/// variance = αβ / ((α+β)²(α+β+1)).
    pub fn thompson_sample(&self, arm_id: &str) -> Result<f64, AiError> {
        let arms = self.arms.read();
        let arm = arms
            .iter()
            .find(|a| a.id == arm_id)
            .ok_or_else(|| AiError::ArmNotFound(arm_id.to_string()))?;

        let alpha = arm.conversions as f64 + 1.0;
        let beta = arm.impressions.saturating_sub(arm.conversions) as f64 + 1.0;

// Normal approximation to Beta
        let mean = alpha / (alpha + beta);
        let variance = (alpha * beta) / ((alpha + beta).powi(2) * (alpha + beta + 1.0));
        let std_dev = variance.sqrt();

        let mut rng = rand::thread_rng();
// Box-Muller transform for a normal sample
        let u1: f64 = rng.gen::<f64>().max(1e-10);
        let u2: f64 = rng.gen();
        let z = (-2.0 * u1.ln()).sqrt() * (2.0 * std::f64::consts::PI * u2).cos();

        let sample = mean + std_dev * z;
        Ok(sample.clamp(0.0, 1.0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_add_and_select_arm() {
        let b = BanditOptimizer::new(1.0); // always explore
        let id1 = b.add_arm("variant-a");
        let id2 = b.add_arm("variant-b");
        let selected = b.select_arm().unwrap();
        assert!(selected == id1 || selected == id2);
    }

    #[test]
    fn test_record_reward_and_stats() {
        let b = BanditOptimizer::new(0.0);
        let id = b.add_arm("cta-red");
        b.record_reward(&id, 1.0).unwrap();
        b.record_reward(&id, 0.0).unwrap();
        b.record_reward(&id, 1.0).unwrap();

        let stats = b.get_stats();
        assert_eq!(stats.len(), 1);
        assert_eq!(stats[0].impressions, 3);
        assert_eq!(stats[0].conversions, 2);
        assert!((stats[0].conversion_rate() - 2.0 / 3.0).abs() < 1e-9);
    }

    #[test]
    fn test_reward_unknown_arm_errors() {
        let b = BanditOptimizer::new(0.1);
        let res = b.record_reward("nonexistent", 1.0);
        assert!(res.is_err());
    }

    #[test]
    fn test_thompson_sample_in_range() {
        let b = BanditOptimizer::new(0.1);
        let id = b.add_arm("test");
        for _ in 0..20 {
            b.record_reward(&id, 1.0).unwrap();
        }
        for _ in 0..80 {
            b.record_reward(&id, 0.0).unwrap();
        }
// Sample multiple times — all should be in [0,1]
        for _ in 0..50 {
            let s = b.thompson_sample(&id).unwrap();
            assert!((0.0..=1.0).contains(&s), "sample {s} out of range");
        }
    }
}
