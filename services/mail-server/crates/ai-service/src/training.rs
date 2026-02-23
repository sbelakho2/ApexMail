//! Training manager — job lifecycle and model evaluation.

use chrono::Utc;
use parking_lot::RwLock;
use std::sync::Arc;

use crate::types::{AiError, EvalMetrics, JobStatus, TrainingJob};

/// Configuration for a training run.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
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

/// Manages training jobs in-memory.
pub struct TrainingManager {
    jobs: Arc<RwLock<Vec<TrainingJob>>>,
}

impl Default for TrainingManager {
    fn default() -> Self {
        Self::new()
    }
}

impl TrainingManager {
    pub fn new() -> Self {
        Self {
            jobs: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Start a new training job for the given model. Returns the created job.
    pub fn start_job(&self, model_id: &str, config: &TrainingConfig) -> TrainingJob {
        let mut job = TrainingJob::new(model_id, config.epochs);
        job.status = JobStatus::Running;
        // Simulate immediate "training" with a synthetic loss
        job.loss = 1.0 / (config.epochs as f64 + 1.0);
        job.completed_at = Some(Utc::now());
        job.status = JobStatus::Completed;

        let ret = job.clone();
        self.jobs.write().push(job);
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
    pub fn cancel_job(&self, id: &str) -> Result<TrainingJob, AiError> {
        let mut jobs = self.jobs.write();
        let job = jobs
            .iter_mut()
            .find(|j| j.id == id)
            .ok_or_else(|| AiError::JobNotFound(id.to_string()))?;

        match job.status {
            JobStatus::Queued | JobStatus::Running => {
                job.status = JobStatus::Cancelled;
                job.completed_at = Some(Utc::now());
                Ok(job.clone())
            }
            _ => Err(AiError::TrainingError(format!(
                "cannot cancel job in status {:?}",
                job.status
            ))),
        }
    }

    /// Evaluate a model by comparing predicted labels to ground truth.
    ///
    /// Binary classification: predictions and actuals are 0.0 or 1.0.
    pub fn evaluate_model(&self, predictions: &[f64], actuals: &[f64]) -> Result<EvalMetrics, AiError> {
        if predictions.len() != actuals.len() || predictions.is_empty() {
            return Err(AiError::InvalidInput(
                "predictions and actuals must be non-empty and equal length".into(),
            ));
        }

        let n = predictions.len() as f64;
        let mut tp = 0.0f64;
        let mut fp = 0.0f64;
        let mut _tn = 0.0f64;
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
                _tn += 1.0;
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

    #[test]
    fn test_start_and_get_job() {
        let mgr = TrainingManager::new();
        let cfg = TrainingConfig::default();
        let job = mgr.start_job("model-1", &cfg);
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
}
