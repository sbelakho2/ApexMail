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
    #[error("inference failed: {0}")]
    InferenceFailed(String),
    #[error("training error: {0}")]
    TrainingError(String),
    #[error("invalid input: {0}")]
    InvalidInput(String),
    #[error("arm not found: {0}")]
    ArmNotFound(String),
    #[error("job not found: {0}")]
    JobNotFound(String),
    #[error("internal: {0}")]
    Internal(String),
}

impl AiError {
    pub fn status_code(&self) -> u16 {
        match self {
            AiError::ModelNotFound(_) | AiError::ArmNotFound(_) | AiError::JobNotFound(_) => 404,
            AiError::InvalidInput(_) => 400,
            _ => 500,
        }
    }
}

// ── Enums ────────────────────────────────────────────────────────

/// The kind of ML model.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModelType {
    Classification,
    Regression,
    Embedding,
    GenerativeText,
}

/// Lifecycle status of a model.
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

/// Status of a training job.
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

/// A single prediction produced by the inference engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Prediction {
    pub id: String,
    pub model_id: String,
    pub input: serde_json::Value,
    pub output: serde_json::Value,
    pub confidence: f64,
    pub latency_ms: u64,
    pub created_at: DateTime<Utc>,
}

/// A registered ML model.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Model {
    pub id: String,
    pub name: String,
    pub version: String,
    pub model_type: ModelType,
    pub accuracy: f64,
    pub trained_at: DateTime<Utc>,
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

/// One arm in a multi-armed bandit.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BanditArm {
    pub id: String,
    pub name: String,
    pub impressions: u64,
    pub conversions: u64,
    pub reward: f64,
}

/// A training job record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrainingJob {
    pub id: String,
    pub model_id: String,
    pub status: JobStatus,
    pub epochs: u32,
    pub loss: f64,
    pub started_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
}

/// Evaluation metrics for a model.
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
        confidence: f64,
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
            loss: 0.0,
            started_at: Utc::now(),
            completed_at: None,
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
    fn test_prediction_new() {
        let p = Prediction::new(
            "m1",
            serde_json::json!({"x":1}),
            serde_json::json!(0.8),
            0.95,
            12,
        );
        assert_eq!(p.model_id, "m1");
        assert!((p.confidence - 0.95).abs() < f64::EPSILON);
        assert_eq!(p.latency_ms, 12);
    }

    #[test]
    fn test_bandit_arm_conversion_rate() {
        let mut arm = BanditArm::new("test");
        assert!((arm.conversion_rate() - 0.0).abs() < f64::EPSILON);
        arm.impressions = 100;
        arm.conversions = 25;
        assert!((arm.conversion_rate() - 0.25).abs() < f64::EPSILON);
    }

    #[test]
    fn test_training_job_new() {
        let job = TrainingJob::new("model-1", 10);
        assert_eq!(job.epochs, 10);
        assert_eq!(job.status, JobStatus::Queued);
        assert!(job.completed_at.is_none());
    }

    #[test]
    fn test_model_serialization() {
        let m = Model {
            id: "m1".into(),
            name: "test-model".into(),
            version: "1.0".into(),
            model_type: ModelType::Classification,
            accuracy: 0.92,
            trained_at: Utc::now(),
            status: ModelStatus::Ready,
        };
        let json = serde_json::to_string(&m).unwrap();
        assert!(json.contains("classification"));
        assert!(json.contains("ready"));
    }

    #[test]
    fn test_ai_error_status_codes() {
        assert_eq!(AiError::ModelNotFound("x".into()).status_code(), 404);
        assert_eq!(AiError::InvalidInput("x".into()).status_code(), 400);
        assert_eq!(AiError::Internal("x".into()).status_code(), 500);
        assert_eq!(AiError::ArmNotFound("x".into()).status_code(), 404);
        assert_eq!(AiError::JobNotFound("x".into()).status_code(), 404);
    }
}
