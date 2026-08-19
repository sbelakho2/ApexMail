//! Core types for the AI service.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

// ── Error ────────────────────────────────────────────────────────

/// Unified error type for the AI crate.
#[derive(Debug, thiserror::Error)]
pub enum AiError {
    #[error("model not found: {0}")]
    ModelNotFound(String),
    #[error("model inference failed: {0}")]
    InferenceFailed(String),
    #[error("model runtime is unavailable: {0}")]
    ModelUnavailable(String),
    #[error("training error: {0}")]
    TrainingError(String),
    #[error("training runner is unavailable: {0}")]
    TrainingUnavailable(String),
    #[error("invalid input: {0}")]
    InvalidInput(String),
    #[error("arm not found: {0}")]
    ArmNotFound(String),
    #[error("job not found: {0}")]
    JobNotFound(String),
    #[error("encryption/decryption failed: {0}")]
    EncryptionFailed(String),
    #[error("checkpoint error: {0}")]
    CheckpointError(String),
    #[error("internal: {0}")]
    Internal(String),
}

impl AiError {
    pub fn status_code(&self) -> u16 {
        match self {
            AiError::ModelNotFound(_) | AiError::ArmNotFound(_) | AiError::JobNotFound(_) => 404,
            AiError::InvalidInput(_) => 400,
            AiError::ModelUnavailable(_) | AiError::TrainingUnavailable(_) => 503,
            _ => 500,
        }
    }
}

// ── Enums ────────────────────────────────────────────────────────

/// The supported model operation class.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModelType {
    Classification,
    Regression,
    Embedding,
    GenerativeText,
}

/// Lifecycle status reported by the model registry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModelStatus {
    Training,
    Ready,
    Deprecated,
}

/// What aspect of content was improved.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ImprovementType {
    SubjectLine,
    Preview,
    Cta,
    Personalization,
}

/// Status of an externally executed training job.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JobStatus {
    Queued,
    Running,
    Completed,
    Failed,
    Cancelled,
}

// ── Structs ──────────────────────────────────────────────────────

/// A result returned from the configured model provider.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Prediction {
    pub id: String,
    pub model_id: String,
    pub input: serde_json::Value,
    pub output: serde_json::Value,
    pub confidence: Option<f64>,
    pub latency_ms: u64,
    pub created_at: DateTime<Utc>,
}

/// A configured model available to the AI service.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Model {
    pub id: String,
    pub name: String,
    pub version: String,
    pub model_type: ModelType,
    pub accuracy: Option<f64>,
    pub trained_at: Option<DateTime<Utc>>,
    pub status: ModelStatus,
}

/// A suggestion for improving email content.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContentSuggestion {
    pub id: String,
    pub original: String,
    pub suggested: String,
    pub improvement_type: ImprovementType,
    pub confidence: f64,
}

/// A send-time slot with engagement score.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SendTimeSlot {
    pub hour: u8,
    pub day_of_week: u8,
    pub score: f64,
}

/// One tenant-scoped experiment variant.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BanditArm {
    pub id: String,
    pub name: String,
    pub impressions: u64,
    pub conversions: u64,
    pub reward: f64,
}

/// A persisted training command lifecycle record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrainingJob {
    pub id: String,
    pub model_id: String,
    pub status: JobStatus,
    pub epochs: u32,
    pub loss: Option<f64>,
    pub started_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
    pub error: Option<String>,
}

/// Binary-classification evaluation metrics emitted by offline evaluation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvalMetrics {
    pub accuracy: f64,
    pub precision: f64,
    pub recall: f64,
    pub f1: f64,
}

// ── Helpers ──────────────────────────────────────────────────────

impl Prediction {
    pub fn new(
        model_id: &str,
        input: serde_json::Value,
        output: serde_json::Value,
        confidence: Option<f64>,
        latency_ms: u64,
    ) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            model_id: model_id.to_string(),
            input,
            output,
            confidence,
            latency_ms,
            created_at: Utc::now(),
        }
    }
}

impl BanditArm {
    pub fn new(name: &str) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            name: name.to_string(),
            impressions: 0,
            conversions: 0,
            reward: 0.0,
        }
    }

    pub fn conversion_rate(&self) -> f64 {
        if self.impressions == 0 {
            0.0
        } else {
            self.conversions as f64 / self.impressions as f64
        }
    }
}

impl TrainingJob {
    pub fn new(model_id: &str, epochs: u32) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            model_id: model_id.to_string(),
            status: JobStatus::Queued,
            epochs,
            loss: None,
            started_at: Utc::now(),
            completed_at: None,
            error: None,
        }
    }
}

impl ContentSuggestion {
    pub fn new(
        original: &str,
        suggested: &str,
        improvement_type: ImprovementType,
        confidence: f64,
    ) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            original: original.to_string(),
            suggested: suggested.to_string(),
            improvement_type,
            confidence,
        }
    }
}

// ── Tests ────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ai_error_status_codes() {
        assert_eq!(AiError::ModelNotFound("x".into()).status_code(), 404);
        assert_eq!(AiError::InvalidInput("x".into()).status_code(), 400);
        assert_eq!(AiError::ModelUnavailable("x".into()).status_code(), 503);
        assert_eq!(AiError::Internal("x".into()).status_code(), 500);
    }

    #[test]
    fn model_and_training_records_have_safe_defaults() {
        let arm = BanditArm::new("subject-a");
        assert_eq!(arm.conversion_rate(), 0.0);

        let job = TrainingJob::new("support-assistant", 3);
        assert_eq!(job.status, JobStatus::Queued);
        assert!(job.error.is_none());
    }
}
