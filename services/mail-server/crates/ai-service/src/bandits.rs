//! Multi-armed bandit optimiser — epsilon-greedy with Thompson sampling.

use parking_lot::RwLock;
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::types::{AiError, BanditArm};

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PersistedBanditState {
    arms: Vec<BanditArm>,
}

/// Epsilon-greedy multi-armed bandit with Thompson-sampling support.
pub struct BanditOptimizer {
    epsilon: f64,
    arms: Arc<RwLock<Vec<BanditArm>>>,
    state_path: Option<PathBuf>,
}

impl BanditOptimizer {
    /// Create a new optimiser with the given exploration rate (0.0–1.0).
    pub fn new(epsilon: f64) -> Self {
        Self {
            epsilon: epsilon.clamp(0.0, 1.0),
            arms: Arc::new(RwLock::new(Vec::new())),
            state_path: None,
        }
    }

    /// Create an optimiser backed by a JSON snapshot file.
    pub fn with_state_path(epsilon: f64, state_path: impl AsRef<Path>) -> Result<Self, AiError> {
        let state_path = state_path.as_ref().to_path_buf();
        let arms = Self::load_persisted_arms(&state_path)?;
        Ok(Self {
            epsilon: epsilon.clamp(0.0, 1.0),
            arms: Arc::new(RwLock::new(arms)),
            state_path: Some(state_path),
        })
    }

    fn load_persisted_arms(state_path: &Path) -> Result<Vec<BanditArm>, AiError> {
        let bytes = match fs::read(state_path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => {
                return Err(AiError::Internal(format!(
                    "failed to read bandit state from {}: {error}",
                    state_path.display()
                )));
            }
        };

        if bytes.is_empty() {
            return Ok(Vec::new());
        }

        serde_json::from_slice::<PersistedBanditState>(&bytes)
            .map(|state| state.arms)
            .map_err(|error| {
                AiError::Internal(format!(
                    "failed to parse bandit state from {}: {error}",
                    state_path.display()
                ))
            })
    }

    fn persist_locked(&self, arms: &[BanditArm]) -> Result<(), AiError> {
        let Some(state_path) = &self.state_path else {
            return Ok(());
        };

        if let Some(parent) = state_path.parent() {
            fs::create_dir_all(parent).map_err(|error| {
                AiError::Internal(format!(
                    "failed to create bandit state directory {}: {error}",
                    parent.display()
                ))
            })?;
        }

        let payload = serde_json::to_vec_pretty(&PersistedBanditState {
            arms: arms.to_vec(),
        })
        .map_err(|error| {
            AiError::Internal(format!(
                "failed to serialize bandit state for {}: {error}",
                state_path.display()
            ))
        })?;

        let temp_path = state_path.with_extension(format!("{}.tmp", uuid::Uuid::new_v4()));
        fs::write(&temp_path, payload).map_err(|error| {
            AiError::Internal(format!(
                "failed to write bandit state snapshot {}: {error}",
                temp_path.display()
            ))
        })?;

        fs::rename(&temp_path, state_path).map_err(|error| {
            AiError::Internal(format!(
                "failed to move bandit state snapshot into {}: {error}",
                state_path.display()
            ))
        })?;

        Ok(())
    }

    /// Register a new arm and return its ID.
    pub fn add_arm(&self, name: &str) -> Result<String, AiError> {
        let arm = BanditArm::new(name);
        let id = arm.id.clone();
        let mut arms = self.arms.write();
        arms.push(arm);
        self.persist_locked(&arms)?;
        Ok(id)
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
            match arms
                .iter()
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
        self.persist_locked(&arms)?;
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
    use std::fs;

    #[test]
    fn test_add_and_select_arm() {
        let b = BanditOptimizer::new(1.0); // always explore
        let id1 = b.add_arm("variant-a").unwrap();
        let id2 = b.add_arm("variant-b").unwrap();
        let selected = b.select_arm().unwrap();
        assert!(selected == id1 || selected == id2);
    }

    #[test]
    fn test_record_reward_and_stats() {
        let b = BanditOptimizer::new(0.0);
        let id = b.add_arm("cta-red").unwrap();
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
        let id = b.add_arm("test").unwrap();
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

    #[test]
    fn test_persisted_state_survives_restart() {
        let state_path =
            std::env::temp_dir().join(format!("apexmail-bandits-{}.json", uuid::Uuid::new_v4()));

        let optimizer = BanditOptimizer::with_state_path(0.0, &state_path).unwrap();
        let arm_id = optimizer.add_arm("persisted-variant").unwrap();
        optimizer.record_reward(&arm_id, 1.0).unwrap();
        drop(optimizer);

        let restored = BanditOptimizer::with_state_path(0.0, &state_path).unwrap();
        let stats = restored.get_stats();
        assert_eq!(stats.len(), 1);
        assert_eq!(stats[0].id, arm_id);
        assert_eq!(stats[0].name, "persisted-variant");
        assert_eq!(stats[0].impressions, 1);
        assert_eq!(stats[0].conversions, 1);

        let _ = fs::remove_file(state_path);
    }

    #[test]
    fn test_invalid_persisted_state_fails_to_load() {
        let state_path = std::env::temp_dir().join(format!(
            "apexmail-bandits-invalid-{}.json",
            uuid::Uuid::new_v4()
        ));
        fs::write(&state_path, b"{not-json").unwrap();

        let error = BanditOptimizer::with_state_path(0.0, &state_path)
            .err()
            .expect("invalid persisted state should fail to load");
        match error {
            AiError::Internal(message) => assert!(message.contains("failed to parse bandit state")),
            other => panic!("expected internal persistence error, got {other:?}"),
        }

        let _ = fs::remove_file(state_path);
    }
}
