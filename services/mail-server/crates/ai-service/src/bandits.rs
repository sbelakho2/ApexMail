//! Multi-armed bandit optimiser — epsilon-greedy with Thompson sampling.
//!
//! # Security (O-10.1)
//! Bandit state is encrypted at rest using AES-256-GCM when an encryption key
//! is configured.  The key is hex-decoded and held in a [`zeroize::Zeroizing`]
//! buffer so it is scrubbed from memory on drop.

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use parking_lot::RwLock;
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use zeroize::Zeroizing;

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
    /// AES-256-GCM key (32 bytes), hex-decoded and zeroized on drop.
    encryption_key: Option<Zeroizing<Vec<u8>>>,
}

impl BanditOptimizer {
    /// Create a new optimiser with the given exploration rate (0.0–1.0).
    pub fn new(epsilon: f64) -> Self {
        Self {
            epsilon: epsilon.clamp(0.0, 1.0),
            arms: Arc::new(RwLock::new(Vec::new())),
            state_path: None,
            encryption_key: None,
        }
    }

    /// Create an optimiser backed by a JSON snapshot file.
    ///
    /// `encryption_key_hex` — optional hex-encoded 32-byte AES-256 key.
    /// Pass an empty string or `None` for plaintext persistence.
    pub fn with_state_path(
        epsilon: f64,
        state_path: impl AsRef<Path>,
        encryption_key_hex: Option<&str>,
    ) -> Result<Self, AiError> {
        let state_path = state_path.as_ref().to_path_buf();
        let encryption_key = match encryption_key_hex {
            Some(h) if !h.is_empty() => {
                let key_bytes = hex::decode(h).map_err(|e| {
                    AiError::EncryptionFailed(format!("invalid hex encryption key: {e}"))
                })?;
                Some(Zeroizing::new(key_bytes))
            }
            _ => None,
        };

        let arms =
            Self::load_persisted_arms(&state_path, encryption_key.as_ref().map(|k| k.as_slice()))?;
        Ok(Self {
            epsilon: epsilon.clamp(0.0, 1.0),
            arms: Arc::new(RwLock::new(arms)),
            state_path: Some(state_path),
            encryption_key,
        })
    }

    fn load_persisted_arms(
        state_path: &Path,
        key: Option<&[u8]>,
    ) -> Result<Vec<BanditArm>, AiError> {
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

        if key.is_none() && Self::looks_like_encrypted_state(&bytes) {
            return Err(AiError::EncryptionFailed(format!(
                "bandit state at {} appears encrypted but no encryption key was provided",
                state_path.display()
            )));
        }

        // Decrypt if encryption key is configured
        let plaintext = if let Some(k) = key {
            Self::decrypt_state(k, &bytes).map_err(|e| {
                AiError::EncryptionFailed(format!(
                    "failed to decrypt bandit state from {}: {e}",
                    state_path.display()
                ))
            })?
        } else {
            bytes
        };

        serde_json::from_slice::<PersistedBanditState>(&plaintext)
            .map(|state| state.arms)
            .map_err(|error| {
                AiError::Internal(format!(
                    "failed to parse bandit state from {}: {error}",
                    state_path.display()
                ))
            })
    }

    fn looks_like_encrypted_state(bytes: &[u8]) -> bool {
        bytes
            .iter()
            .copied()
            .find(|byte| !byte.is_ascii_whitespace())
            .is_some_and(|byte| byte != b'{')
    }

    fn encrypt_state(key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, String> {
        let key_arr: [u8; 32] = key
            .try_into()
            .map_err(|_| "encryption key must be exactly 32 bytes".to_string())?;
        let cipher = Aes256Gcm::new_from_slice(&key_arr)
            .map_err(|e| format!("failed to create AES-256-GCM cipher: {e}"))?;

        // 96-bit random nonce
        let nonce_bytes: [u8; 12] = rand::random();
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = cipher
            .encrypt(nonce, plaintext)
            .map_err(|e| format!("AES-256-GCM encryption failed: {e}"))?;

        // Prepend nonce to ciphertext for storage
        let mut out = Vec::with_capacity(12 + ciphertext.len());
        out.extend_from_slice(&nonce_bytes);
        out.extend_from_slice(&ciphertext);
        Ok(out)
    }

    fn decrypt_state(key: &[u8], data: &[u8]) -> Result<Vec<u8>, String> {
        if data.len() < 12 {
            return Err("encrypted data too short (missing nonce)".to_string());
        }
        let key_arr: [u8; 32] = key
            .try_into()
            .map_err(|_| "encryption key must be exactly 32 bytes".to_string())?;
        let cipher = Aes256Gcm::new_from_slice(&key_arr)
            .map_err(|e| format!("failed to create AES-256-GCM cipher: {e}"))?;

        let (nonce_bytes, ciphertext) = data.split_at(12);
        let nonce = Nonce::from_slice(nonce_bytes);

        cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| format!("AES-256-GCM decryption failed (tampered data?): {e}"))
    }

    async fn persist_locked(&self, arms: &[BanditArm]) -> Result<(), AiError> {
        let Some(state_path) = &self.state_path else {
            return Ok(());
        };

        // Clone data needed for spawn_blocking (H-18)
        let state_path = state_path.clone();
        let encryption_key = self.encryption_key.clone();
        let arms = arms.to_vec();

        tokio::task::spawn_blocking(move || -> Result<(), AiError> {
            if let Some(parent) = state_path.parent() {
                std::fs::create_dir_all(parent).map_err(|error| {
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

            // Encrypt if key is configured
            let bytes_to_write: Vec<u8> = if let Some(ref key) = encryption_key {
                Self::encrypt_state(key, &payload).map_err(|e| {
                    AiError::EncryptionFailed(format!(
                        "failed to encrypt bandit state for {}: {e}",
                        state_path.display()
                    ))
                })?
            } else {
                payload
            };

            let temp_path = state_path.with_extension(format!("{}.tmp", uuid::Uuid::new_v4()));
            std::fs::write(&temp_path, bytes_to_write).map_err(|error| {
                AiError::Internal(format!(
                    "failed to write bandit state snapshot {}: {error}",
                    temp_path.display()
                ))
            })?;

            std::fs::rename(&temp_path, &state_path).map_err(|error| {
                AiError::Internal(format!(
                    "failed to move bandit state snapshot into {}: {error}",
                    state_path.display()
                ))
            })?;

            Ok(())
        })
        .await
        .map_err(|e| AiError::Internal(format!("spawn_blocking join failed: {e}")))?
    }

    /// Register a new arm and return its ID.
    pub async fn add_arm(&self, name: &str) -> Result<String, AiError> {
        let arm = BanditArm::new(name);
        let id = arm.id.clone();
        let snapshot = {
            let mut arms = self.arms.write();
            arms.push(arm);
            arms.clone()
        };
        self.persist_locked(&snapshot).await?;
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

        let mut rng = rand::rng();
        let idx = if rng.random::<f64>() < self.epsilon || arms.iter().all(|a| a.impressions == 0) {
            // Explore:pick random arm
            rng.random_range(0..arms.len())
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
    pub async fn record_reward(&self, arm_id: &str, reward: f64) -> Result<(), AiError> {
        let snapshot = {
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
            arms.clone()
        };
        self.persist_locked(&snapshot).await?;
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

        let mut rng = rand::rng();
        // Box-Muller transform for a normal sample
        let u1: f64 = rng.random::<f64>().max(1e-10);
        let u2: f64 = rng.random();
        let z = (-2.0 * u1.ln()).sqrt() * (2.0 * std::f64::consts::PI * u2).cos();

        let sample = mean + std_dev * z;
        Ok(sample.clamp(0.0, 1.0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[tokio::test]
    async fn test_add_and_select_arm() {
        let b = BanditOptimizer::new(1.0); // always explore
        let id1 = b.add_arm("variant-a").await.unwrap();
        let id2 = b.add_arm("variant-b").await.unwrap();
        let selected = b.select_arm().unwrap();
        assert!(selected == id1 || selected == id2);
    }

    #[tokio::test]
    async fn test_record_reward_and_stats() {
        let b = BanditOptimizer::new(0.0);
        let id = b.add_arm("cta-red").await.unwrap();
        b.record_reward(&id, 1.0).await.unwrap();
        b.record_reward(&id, 0.0).await.unwrap();
        b.record_reward(&id, 1.0).await.unwrap();

        let stats = b.get_stats();
        assert_eq!(stats.len(), 1);
        assert_eq!(stats[0].impressions, 3);
        assert_eq!(stats[0].conversions, 2);
        assert!((stats[0].conversion_rate() - 2.0 / 3.0).abs() < 1e-9);
    }

    #[tokio::test]
    async fn test_reward_unknown_arm_errors() {
        let b = BanditOptimizer::new(0.1);
        let res = b.record_reward("nonexistent", 1.0).await;
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn test_thompson_sample_in_range() {
        let b = BanditOptimizer::new(0.1);
        let id = b.add_arm("test").await.unwrap();
        for _ in 0..20 {
            b.record_reward(&id, 1.0).await.unwrap();
        }
        for _ in 0..80 {
            b.record_reward(&id, 0.0).await.unwrap();
        }
        // Sample multiple times — all should be in [0,1]
        for _ in 0..50 {
            let s = b.thompson_sample(&id).unwrap();
            assert!((0.0..=1.0).contains(&s), "sample {s} out of range");
        }
    }

    #[tokio::test]
    async fn test_persisted_state_survives_restart() {
        let state_path =
            std::env::temp_dir().join(format!("apexmail-bandits-{}.json", uuid::Uuid::new_v4()));

        let optimizer = BanditOptimizer::with_state_path(0.0, &state_path, None).unwrap();
        let arm_id = optimizer.add_arm("persisted-variant").await.unwrap();
        optimizer.record_reward(&arm_id, 1.0).await.unwrap();
        drop(optimizer);

        let restored = BanditOptimizer::with_state_path(0.0, &state_path, None).unwrap();
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

        let error = BanditOptimizer::with_state_path(0.0, &state_path, None)
            .err()
            .expect("invalid persisted state should fail to load");
        match error {
            AiError::Internal(message) => assert!(message.contains("failed to parse bandit state")),
            other => panic!("expected internal persistence error, got {other:?}"),
        }

        let _ = fs::remove_file(state_path);
    }

    #[tokio::test]
    async fn test_encrypted_state_survives_restart() {
        let state_path = std::env::temp_dir().join(format!(
            "apexmail-bandits-enc-{}.json",
            uuid::Uuid::new_v4()
        ));
        let key_hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

        let optimizer = BanditOptimizer::with_state_path(0.0, &state_path, Some(key_hex)).unwrap();
        let arm_id = optimizer.add_arm("encrypted-variant").await.unwrap();
        optimizer.record_reward(&arm_id, 1.0).await.unwrap();
        drop(optimizer);

        // File should not contain plaintext JSON
        let raw = fs::read(&state_path).unwrap();
        assert!(!raw.is_empty(), "encrypted state file is empty");
        assert!(
            !raw.starts_with(b"{"),
            "file starts with '{{' — possible plaintext leak"
        );

        // Restore with the same key
        let restored = BanditOptimizer::with_state_path(0.0, &state_path, Some(key_hex)).unwrap();
        let stats = restored.get_stats();
        assert_eq!(stats.len(), 1);
        assert_eq!(stats[0].id, arm_id);
        assert_eq!(stats[0].impressions, 1);
        assert_eq!(stats[0].conversions, 1);

        // Restore without key should fail
        let err = BanditOptimizer::with_state_path(0.0, &state_path, None)
            .err()
            .expect("loading encrypted state without key should fail");
        assert!(
            matches!(err, AiError::EncryptionFailed(_)),
            "expected EncryptionFailed error, got {err:?}"
        );

        let _ = fs::remove_file(state_path);
    }
}
