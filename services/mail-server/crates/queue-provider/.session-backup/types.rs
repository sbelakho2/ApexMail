use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

// ─── Job status ────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[serde(rename_all = "snake_case")]
#[sqlx(type_name = "text", rename_all = "snake_case")]
pub enum JobStatus {
    Pending,
    Processing,
    Completed,
    Failed,
    DeadLetter,
}

impl std::fmt::Display for JobStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pending => write!(f, "pending"),
            Self::Processing => write!(f, "processing"),
            Self::Completed => write!(f, "completed"),
            Self::Failed => write!(f, "failed"),
            Self::DeadLetter => write!(f, "dead_letter"),
        }
    }
}

// ─── Job ───────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Job {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub queue: String,
    pub payload: serde_json::Value,
    pub status: JobStatus,
    pub attempts: i32,
    pub max_attempts: i32,
    pub priority: i32,
    pub scheduled_at: DateTime<Utc>,
    pub started_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
    pub failed_at: Option<DateTime<Utc>>,
    pub error_message: Option<String>,
    pub visibility_timeout: i32,
    /// Lease token minted by dequeue (migration 103). Ownership proof for
    /// complete()/fail()/dead_letter(): the call is a no-op unless the job
    /// is still `processing` under THIS token.
    pub lease_token: Option<Uuid>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

// ─── Job creation options ──────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnqueueOptions {
    pub tenant_id: Uuid,
    pub queue: String,
    pub payload: serde_json::Value,
    #[serde(default = "default_max_attempts")]
    pub max_attempts: i32,
    #[serde(default)]
    pub priority: i32,
    /// When to make the job visible (None = now)
    pub scheduled_at: Option<DateTime<Utc>>,
    /// Seconds before a processing job becomes visible again
    #[serde(default = "default_visibility_timeout")]
    pub visibility_timeout: i32,
}

fn default_max_attempts() -> i32 {
    3
}
fn default_visibility_timeout() -> i32 {
    300
}

// ─── Queue stats ───────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueueStats {
    pub queue: String,
    pub pending: i64,
    pub processing: i64,
    pub completed: i64,
    pub failed: i64,
    pub dead_letter: i64,
}

// ─── Errors ────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum QueueError {
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),

    #[error("Job not found: {id}")]
    NotFound { id: Uuid },

    #[error("Invalid payload: {0}")]
    InvalidPayload(String),

    #[error("Queue is full: {queue} has {count} pending jobs")]
    QueueFull { queue: String, count: i64 },

    #[error("Job already completed: {id}")]
    AlreadyCompleted { id: Uuid },

    #[error("Max attempts exceeded: {id} ({attempts}/{max})")]
    MaxAttempts { id: Uuid, attempts: i32, max: i32 },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_job_status_display() {
        assert_eq!(JobStatus::Pending.to_string(), "pending");
        assert_eq!(JobStatus::Processing.to_string(), "processing");
        assert_eq!(JobStatus::Completed.to_string(), "completed");
        assert_eq!(JobStatus::Failed.to_string(), "failed");
        assert_eq!(JobStatus::DeadLetter.to_string(), "dead_letter");
    }

    #[test]
    fn test_job_status_serialization() {
        let json = serde_json::to_string(&JobStatus::Pending).unwrap();
        assert_eq!(json, r#""pending""#);
        let de: JobStatus = serde_json::from_str(r#""failed""#).unwrap();
        assert_eq!(de, JobStatus::Failed);
    }

    #[test]
    fn test_enqueue_options_defaults() {
        let json =
            r#"{"tenant_id":"00000000-0000-0000-0000-000000000000","queue":"email","payload":{}}"#;
        let opts: EnqueueOptions = serde_json::from_str(json).unwrap();
        assert_eq!(opts.max_attempts, 3);
        assert_eq!(opts.priority, 0);
        assert_eq!(opts.visibility_timeout, 300);
        assert!(opts.scheduled_at.is_none());
    }

    #[test]
    fn test_queue_error_display() {
        let err = QueueError::NotFound { id: Uuid::nil() };
        assert!(err.to_string().contains("not found"));

        let err = QueueError::MaxAttempts {
            id: Uuid::nil(),
            attempts: 3,
            max: 3,
        };
        assert!(err.to_string().contains("3/3"));
    }

    #[test]
    fn test_queue_stats() {
        let stats = QueueStats {
            queue: "email".into(),
            pending: 100,
            processing: 5,
            completed: 1000,
            failed: 10,
            dead_letter: 2,
        };
        let json = serde_json::to_string(&stats).unwrap();
        assert!(json.contains("\"pending\":100"));
    }
}
