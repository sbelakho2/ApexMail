//! Training manager — job lifecycle, model evaluation, and periodic checkpointing (O-10.3).

use chrono::Utc;
use parking_lot::RwLock;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use crate::types::{AiError, EvalMetrics, JobStatus, TrainingJob};

/// Configuration for a training run.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct TrainingConfig {
    pub epochs: u32,
    pub learning_rate: f64,
    pub batch_size: u32,
}

impl Default for TrainingConfig {
    fn default() -> Self {
        Self {
            epochs: 10,
            learning_rate: 0.001,
            batch_size: 32,
        }
    }
}

/// Manages training jobs in-memory with optional disk checkpointing (O-10.3).
pub struct TrainingManager {
    jobs: Arc<RwLock<Vec<TrainingJob>>>,
    /// Directory where checkpoint files are written.
    checkpoint_path: Option<PathBuf>,
    /// Interval between periodic checkpoint writes.
    checkpoint_interval: Duration,
}

impl Default for TrainingManager {
    fn default() -> Self {
        Self::new()
    }
}

impl TrainingManager {
    /// Create an in-memory-only training manager with no checkpointing.
    pub fn new() -> Self {
        Self {
            jobs: Arc::new(RwLock::new(Vec::new())),
            checkpoint_path: None,
            checkpoint_interval: Duration::from_secs(60),
        }
    }

    /// Create a training manager that periodically checkpoints job state to disk.
    ///
    /// `checkpoint_path` — directory where checkpoint JSON files are stored.
    /// `checkpoint_interval_secs` — how often (in seconds) to persist state.
    pub fn with_checkpointing(
        checkpoint_path: impl AsRef<Path>,
        checkpoint_interval_secs: u64,
    ) -> Self {
        let path = checkpoint_path.as_ref().to_path_buf();
        // Ensure directory exists
        if let Some(parent) = path.parent() {
            let _ = fs::create_dir_all(parent);
        }
        let _ = fs::create_dir_all(&path);

        // Attempt to restore previous checkpoint
        let jobs = Self::load_checkpoint(&path).unwrap_or_default();

        Self {
            jobs: Arc::new(RwLock::new(jobs)),
            checkpoint_path: Some(path),
            checkpoint_interval: Duration::from_secs(checkpoint_interval_secs.max(1)),
        }
    }

    /// Load training jobs from a checkpoint file on disk.
    fn load_checkpoint(path: &Path) -> Result<Vec<TrainingJob>, AiError> {
        let checkpoint_file = path.join("training_checkpoint.json");
        if !checkpoint_file.exists() {
            return Ok(Vec::new());
        }
        let bytes = fs::read(&checkpoint_file).map_err(|e| {
            AiError::CheckpointError(format!(
                "failed to read checkpoint {}: {e}",
                checkpoint_file.display()
            ))
        })?;
        if bytes.is_empty() {
            return Ok(Vec::new());
        }
        serde_json::from_slice(&bytes).map_err(|e| {
            AiError::CheckpointError(format!(
                "failed to parse checkpoint {}: {e}",
                checkpoint_file.display()
            ))
        })
    }

    /// Persist all current training jobs to the checkpoint file (H-18: spawn_blocking).
    pub async fn checkpoint_now(&self) -> Result<(), AiError> {
        let Some(ref path) = self.checkpoint_path else {
            return Ok(());
        };

        // Serialize outside spawn_blocking (brief lock).
        let payload = {
            let jobs = self.jobs.read();
            serde_json::to_vec_pretty(&*jobs).map_err(|e| {
                AiError::CheckpointError(format!("failed to serialize checkpoint: {e}"))
            })?
        };

        let checkpoint_file = path.join("training_checkpoint.json");
        let temp_path = checkpoint_file.with_extension(format!("tmp.{}", uuid::Uuid::new_v4()));

        // H-18: Offload sync file I/O to a blocking thread to avoid Tokio starvation.
        tokio::task::spawn_blocking(move || -> Result<(), AiError> {
            std::fs::write(&temp_path, &payload).map_err(|e| {
                AiError::CheckpointError(format!(
                    "failed to write checkpoint {}: {e}",
                    temp_path.display()
                ))
            })?;

            std::fs::rename(&temp_path, &checkpoint_file).map_err(|e| {
                AiError::CheckpointError(format!(
                    "failed to move checkpoint {}: {e}",
                    checkpoint_file.display()
                ))
            })?;

            Ok(())
        })
        .await
        .map_err(|e| AiError::CheckpointError(format!("spawn_blocking join failed: {e}")))?
    }

    /// Return the checkpoint interval.
    pub fn checkpoint_interval(&self) -> Duration {
        self.checkpoint_interval
    }

    /// Start a new training job for the given model. Returns the created job.
    pub async fn start_job(&self, model_id: &str, config: &TrainingConfig) -> TrainingJob {
        let mut job = TrainingJob::new(model_id, config.epochs);
        job.status = JobStatus::Running;
        // Simulate immediate "training" with a synthetic loss
        job.loss = 1.0 / (config.epochs as f64 + 1.0);
        job.completed_at = Some(Utc::now());
        job.status = JobStatus::Completed;

        let ret = job.clone();
        self.jobs.write().push(job);
        let _ = self.checkpoint_now().await; // best-effort checkpoint (H-18: async)
        ret
    }

    /// Retrieve a training job by ID.
    pub fn get_job(&self, id: &str) -> Result<TrainingJob, AiError> {
        self.jobs
            .read()
            .iter()
            .find(|j| j.id == id)
            .cloned()
            .ok_or_else(|| AiError::JobNotFound(id.to_string()))
    }

    /// List all training jobs.
    pub fn list_jobs(&self) -> Vec<TrainingJob> {
        self.jobs.read().clone()
    }

    /// Cancel a running or queued training job.
    #[allow(clippy::await_holding_lock)]
    pub async fn cancel_job(&self, id: &str) -> Result<TrainingJob, AiError> {
        let mut jobs = self.jobs.write();
        let job = jobs
            .iter_mut()
            .find(|j| j.id == id)
            .ok_or_else(|| AiError::JobNotFound(id.to_string()))?;

        match job.status {
            JobStatus::Queued | JobStatus::Running => {
                job.status = JobStatus::Cancelled;
                job.completed_at = Some(Utc::now());
                let ret = job.clone();
                drop(jobs);
                let _ = self.checkpoint_now().await; // best-effort checkpoint (H-18: async)
                Ok(ret)
            }
            _ => Err(AiError::TrainingError(format!(
                "cannot cancel job in status {:?}",
                job.status
            ))),
        }
    }

    /// Evaluate a model by comparing predicted labels to ground truth.
    /// Binary classification:predictions and actuals are 0.0 or 1.0.
    pub fn evaluate_model(
        &self,
        predictions: &[f64],
        actuals: &[f64],
    ) -> Result<EvalMetrics, AiError> {
        if predictions.len() != actuals.len() || predictions.is_empty() {
            return Err(AiError::InvalidInput(
                "predictions and actuals must be non-empty and equal length".into(),
            ));
        }

        let n = predictions.len() as f64;
        let mut tp = 0.0f64;
        let mut fp = 0.0f64;
        let mut fn_ = 0.0f64;
        let mut correct = 0.0f64;

        for (p, a) in predictions.iter().zip(actuals.iter()) {
            let pred_pos = *p >= 0.5;
            let actual_pos = *a >= 0.5;
            if pred_pos && actual_pos {
                tp += 1.0;
                correct += 1.0;
            } else if pred_pos && !actual_pos {
                fp += 1.0;
            } else if !pred_pos && actual_pos {
                fn_ += 1.0;
            } else {
                correct += 1.0;
            }
        }

        let accuracy = correct / n;
        let precision = if tp + fp > 0.0 { tp / (tp + fp) } else { 0.0 };
        let recall = if tp + fn_ > 0.0 { tp / (tp + fn_) } else { 0.0 };
        let f1 = if precision + recall > 0.0 {
            2.0 * precision * recall / (precision + recall)
        } else {
            0.0
        };

        Ok(EvalMetrics {
            accuracy,
            precision,
            recall,
            f1,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_start_and_get_job() {
        let mgr = TrainingManager::new();
        let cfg = TrainingConfig::default();
        let job = mgr.start_job("model-1", &cfg).await;
        assert_eq!(job.status, JobStatus::Completed);
        assert_eq!(job.epochs, 10);

        let fetched = mgr.get_job(&job.id).unwrap();
        assert_eq!(fetched.id, job.id);
    }

    #[test]
    fn test_evaluate_model_perfect() {
        let mgr = TrainingManager::new();
        let preds = vec![1.0, 0.0, 1.0, 0.0];
        let actuals = vec![1.0, 0.0, 1.0, 0.0];
        let metrics = mgr.evaluate_model(&preds, &actuals).unwrap();
        assert!((metrics.accuracy - 1.0).abs() < f64::EPSILON);
        assert!((metrics.f1 - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_evaluate_model_imperfect() {
        let mgr = TrainingManager::new();
        // 3 correct out of 4
        let preds = vec![1.0, 0.0, 1.0, 1.0];
        let actuals = vec![1.0, 0.0, 1.0, 0.0];
        let metrics = mgr.evaluate_model(&preds, &actuals).unwrap();
        assert!((metrics.accuracy - 0.75).abs() < f64::EPSILON);
        // TP=2 (idx 0,2), FP=1 (idx 3), FN=0, TN=1 (idx 1)
        // precision = 2/3, recall = 2/2 = 1.0, f1 = 2*(2/3)*1.0 / (2/3+1.0)
        let expected_precision = 2.0 / 3.0;
        assert!((metrics.precision - expected_precision).abs() < 1e-9);
        assert!((metrics.recall - 1.0).abs() < f64::EPSILON);
        let expected_f1 = 2.0 * expected_precision * 1.0 / (expected_precision + 1.0);
        assert!((metrics.f1 - expected_f1).abs() < 1e-9);
    }

    #[tokio::test]
    async fn test_checkpoint_survives_restart() {
        let checkpoint_dir =
            std::env::temp_dir().join(format!("apexmail-training-{}", uuid::Uuid::new_v4()));

        // Create manager with checkpointing
        let mgr = TrainingManager::with_checkpointing(&checkpoint_dir, 60);
        let cfg = TrainingConfig::default();
        let job = mgr.start_job("model-ckpt", &cfg).await;
        let job_id = job.id.clone();
        drop(mgr);

        // Restore from checkpoint
        let restored = TrainingManager::with_checkpointing(&checkpoint_dir, 60);
        let fetched = restored.get_job(&job_id).unwrap();
        assert_eq!(fetched.model_id, "model-ckpt");
        assert_eq!(fetched.status, JobStatus::Completed);

        // Cleanup
        let _ = std::fs::remove_dir_all(checkpoint_dir);
    }

    #[tokio::test]
    async fn test_cancel_job_checkpoints() {
        let checkpoint_dir =
            std::env::temp_dir().join(format!("apexmail-training-cancel-{}", uuid::Uuid::new_v4()));

        let mgr = TrainingManager::with_checkpointing(&checkpoint_dir, 60);
        let cfg = TrainingConfig {
            epochs: 100,
            learning_rate: 0.01,
            batch_size: 16,
        };
        let job = mgr.start_job("model-cancel", &cfg).await;
        let job_id = job.id.clone();

        // Create a new "running" job by directly injecting one
        let mut running = TrainingJob::new("model-running", 50);
        running.status = JobStatus::Running;
        let running_id = running.id.clone();
        mgr.jobs.write().push(running);

        let cancelled = mgr.cancel_job(&running_id).await.unwrap();
        assert_eq!(cancelled.status, JobStatus::Cancelled);
        drop(mgr);

        // Restore — the cancelled job should still be saved
        let restored = TrainingManager::with_checkpointing(&checkpoint_dir, 60);
        assert!(restored.get_job(&job_id).is_ok(), "completed job missing");
        assert!(
            restored.get_job(&running_id).is_ok(),
            "cancelled job missing"
        );
        let restored_cancelled = restored.get_job(&running_id).unwrap();
        assert_eq!(restored_cancelled.status, JobStatus::Cancelled);

        let _ = std::fs::remove_dir_all(checkpoint_dir);
    }
}
