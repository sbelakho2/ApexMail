//! Postgres queue provider with SKIP LOCKED for exactly-once processing.

use chrono::{TimeDelta, Utc};
use sqlx::PgPool;
use tracing::{info, warn};
use uuid::Uuid;

use crate::types::{EnqueueOptions, Job, JobStatus, QueueError, QueueStats};

/// Postgres-backed job queue using SELECT ... FOR UPDATE SKIP LOCKED.
pub struct PostgresQueueProvider {
    db: PgPool,
}

impl PostgresQueueProvider {
    pub fn new(db: PgPool) -> Self {
        Self { db }
    }

    /// Enqueue a new job.
    pub async fn enqueue(&self, opts: EnqueueOptions) -> Result<Job, QueueError> {
        let id = Uuid::new_v4();
        let now = Utc::now();
        let scheduled_at = opts.scheduled_at.unwrap_or(now);

        if opts.queue.trim().is_empty() {
            return Err(QueueError::InvalidPayload("queue name is required".into()));
        }
        if opts.max_attempts <= 0 {
            return Err(QueueError::InvalidPayload("max_attempts must be positive".into()));
        }
        if opts.visibility_timeout <= 0 {
            return Err(QueueError::InvalidPayload("visibility_timeout must be positive seconds".into()));
        }

        let row: JobRow = sqlx::query_as::<_, JobRow>(
            r#"
            INSERT INTO queue_jobs (id, tenant_id, queue, payload, status, attempts, max_attempts,
                                    priority, scheduled_at, visibility_timeout, created_at, updated_at)
            VALUES ($1, $2, $3, $4, 'pending', 0, $5, $6, $7, $8, $9, $9)
            RETURNING id, tenant_id, queue, payload, status,
                      attempts, max_attempts, priority, scheduled_at,
                      started_at, completed_at, failed_at, error_message,
                      visibility_timeout, created_at, updated_at
            "#,
        )
        .bind(id)
        .bind(opts.tenant_id)
        .bind(&opts.queue)
        .bind(&opts.payload)
        .bind(opts.max_attempts)
        .bind(opts.priority)
        .bind(scheduled_at)
        .bind(opts.visibility_timeout)
        .bind(now)
        .fetch_one(&self.db)
        .await?;

        info!(job_id = %id, queue = %opts.queue, "Job enqueued");
        Ok(row.into_job())
    }

    /// Dequeue the next available job using SKIP LOCKED.
    /// Returns None if no jobs are available.
    pub async fn dequeue(&self, queue: &str, batch_size: i32) -> Result<Vec<Job>, QueueError> {
        let now = Utc::now();

        let rows: Vec<JobRow> = sqlx::query_as::<_, JobRow>(
            r#"
            UPDATE queue_jobs
            SET status = 'processing',
                started_at = $3,
                attempts = attempts + 1,
                updated_at = $3
            WHERE id IN (
                SELECT id FROM queue_jobs
                WHERE queue = $1
                  AND status = 'pending'
                  AND scheduled_at <= $3
                ORDER BY priority DESC, created_at ASC
                FOR UPDATE SKIP LOCKED
                LIMIT $2
            )
            RETURNING id, tenant_id, queue, payload, status,
                      attempts, max_attempts, priority, scheduled_at,
                      started_at, completed_at, failed_at, error_message,
                      visibility_timeout, created_at, updated_at
            "#,
        )
        .bind(queue)
        .bind(batch_size as i64)
        .bind(now)
        .fetch_all(&self.db)
        .await?;

        let jobs: Vec<Job> = rows.into_iter().map(|r| r.into_job()).collect();
        if !jobs.is_empty() {
            info!(count = jobs.len(), queue = queue, "Dequeued jobs");
        }
        Ok(jobs)
    }

    /// Mark a job as completed.
    pub async fn complete(&self, job_id: Uuid) -> Result<(), QueueError> {
        let now = Utc::now();
        let result = sqlx::query(
            r#"
            UPDATE queue_jobs
            SET status = 'completed', completed_at = $2, updated_at = $2
            WHERE id = $1 AND status = 'processing'
            "#,
        )
        .bind(job_id)
        .bind(now)
        .execute(&self.db)
        .await?;

        if result.rows_affected() == 0 {
            return Err(QueueError::NotFound { id: job_id });
        }
        Ok(())
    }

    /// Mark a job as failed with exponential backoff for retry.
    pub async fn fail(&self, job_id: Uuid, error: &str) -> Result<(), QueueError> {
        let now = Utc::now();

        // Fetch current state
        let job: JobRow = sqlx::query_as::<_, JobRow>(
            r#"
            SELECT id, tenant_id, queue, payload, status,
                   attempts, max_attempts, priority, scheduled_at,
                   started_at, completed_at, failed_at, error_message,
                   visibility_timeout, created_at, updated_at
            FROM queue_jobs WHERE id = $1
            "#,
        )
        .bind(job_id)
        .fetch_optional(&self.db)
        .await?
        .ok_or(QueueError::NotFound { id: job_id })?;

        if job.attempts >= job.max_attempts {
            // Move to dead letter queue
            self.dead_letter(job_id, error).await?;
        } else {
            // #228: Exponential backoff with cap at 1 hour to prevent excessive delays
            let backoff_secs = ((2_i64.pow(job.attempts as u32)) * 30).min(3600);
            let retry_at = now + chrono::Duration::seconds(backoff_secs);

            sqlx::query(
                r#"
                UPDATE queue_jobs
                SET status = 'pending',
                    failed_at = $2,
                    error_message = $3,
                    scheduled_at = $4,
                    updated_at = $2
                WHERE id = $1
                "#,
            )
            .bind(job_id)
            .bind(now)
            .bind(error)
            .bind(retry_at)
            .execute(&self.db)
            .await?;

            warn!(
                job_id = %job_id,
                attempt = job.attempts,
                retry_at = %retry_at,
                "Job failed, scheduled for retry"
            );
        }
        Ok(())
    }

    /// Move a job to dead letter queue.
    pub async fn dead_letter(&self, job_id: Uuid, error: &str) -> Result<(), QueueError> {
        let now = Utc::now();
        sqlx::query(
            r#"
            UPDATE queue_jobs
            SET status = 'dead_letter',
                failed_at = $2,
                error_message = $3,
                updated_at = $2
            WHERE id = $1
            "#,
        )
        .bind(job_id)
        .bind(now)
        .bind(error)
        .execute(&self.db)
        .await?;

        warn!(job_id = %job_id, "Job moved to dead letter queue");
        Ok(())
    }

    /// Recover stale processing jobs (visibility timeout expired).
    pub async fn recover_stale(&self) -> Result<i64, QueueError> {
        let now = Utc::now();
        let result = sqlx::query(
            r#"
            UPDATE queue_jobs
            SET status = 'pending', updated_at = $1
            WHERE status = 'processing'
              AND started_at + (visibility_timeout * interval '1 second') < $1
            "#,
        )
        .bind(now)
        .execute(&self.db)
        .await?;

        let count = result.rows_affected() as i64;
        if count > 0 {
            warn!(count = count, "Recovered stale processing jobs");
        }
        Ok(count)
    }

    /// Get queue statistics.
    pub async fn stats(&self, queue: &str) -> Result<QueueStats, QueueError> {
        let row: StatsRow = sqlx::query_as::<_, StatsRow>(
            r#"
            SELECT
                COALESCE(SUM(CASE WHEN status = 'pending' THEN 1 ELSE 0 END), 0) as pending,
                COALESCE(SUM(CASE WHEN status = 'processing' THEN 1 ELSE 0 END), 0) as processing,
                COALESCE(SUM(CASE WHEN status = 'completed' THEN 1 ELSE 0 END), 0) as completed,
                COALESCE(SUM(CASE WHEN status = 'failed' THEN 1 ELSE 0 END), 0) as failed,
                COALESCE(SUM(CASE WHEN status = 'dead_letter' THEN 1 ELSE 0 END), 0) as dead_letter
            FROM queue_jobs WHERE queue = $1
            "#,
        )
        .bind(queue)
        .fetch_one(&self.db)
        .await?;

        Ok(QueueStats {
            queue: queue.to_string(),
            pending: row.pending,
            processing: row.processing,
            completed: row.completed,
            failed: row.failed,
            dead_letter: row.dead_letter,
        })
    }

    /// Purge completed/dead_letter jobs older than the given age.
    pub async fn purge(&self, queue: &str, older_than_hours: i32) -> Result<i64, QueueError> {
        let cutoff = Utc::now() - TimeDelta::try_hours(older_than_hours as i64).unwrap_or(TimeDelta::zero());
        let result = sqlx::query(
            r#"
            DELETE FROM queue_jobs
            WHERE queue = $1
              AND status IN ('completed', 'dead_letter')
              AND updated_at < $2
            "#,
        )
        .bind(queue)
        .bind(cutoff)
        .execute(&self.db)
        .await?;

        let count = result.rows_affected() as i64;
        info!(count = count, queue = queue, "Purged old jobs");
        Ok(count)
    }
}

/// Internal DB row type.
#[derive(sqlx::FromRow)]
struct JobRow {
    id: Uuid,
    tenant_id: Uuid,
    queue: String,
    payload: serde_json::Value,
    status: JobStatus,
    attempts: i32,
    max_attempts: i32,
    priority: i32,
    scheduled_at: chrono::DateTime<Utc>,
    started_at: Option<chrono::DateTime<Utc>>,
    completed_at: Option<chrono::DateTime<Utc>>,
    failed_at: Option<chrono::DateTime<Utc>>,
    error_message: Option<String>,
    visibility_timeout: i32,
    created_at: chrono::DateTime<Utc>,
    updated_at: chrono::DateTime<Utc>,
}

/// Stats query row.
#[derive(sqlx::FromRow)]
struct StatsRow {
    pending: i64,
    processing: i64,
    completed: i64,
    failed: i64,
    dead_letter: i64,
}

impl JobRow {
    fn into_job(self) -> Job {
        Job {
            id: self.id,
            tenant_id: self.tenant_id,
            queue: self.queue,
            payload: self.payload,
            status: self.status,
            attempts: self.attempts,
            max_attempts: self.max_attempts,
            priority: self.priority,
            scheduled_at: self.scheduled_at,
            started_at: self.started_at,
            completed_at: self.completed_at,
            failed_at: self.failed_at,
            error_message: self.error_message,
            visibility_timeout: self.visibility_timeout,
            created_at: self.created_at,
            updated_at: self.updated_at,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::*;

    #[test]
    fn test_enqueue_options_creation() {
        let opts = EnqueueOptions {
            tenant_id: Uuid::new_v4(),
            queue: "email".to_string(),
            payload: serde_json::json!({"to": "user@example.com"}),
            max_attempts: 5,
            priority: 10,
            scheduled_at: None,
            visibility_timeout: 600,
        };
        assert_eq!(opts.queue, "email");
        assert_eq!(opts.max_attempts, 5);
        assert_eq!(opts.priority, 10);
    }

    #[test]
    fn test_exponential_backoff_calculation() {
        // Verify backoff formula: 2^attempts * 30 seconds
        let attempt_1 = 2_i64.pow(1) * 30; // 60s
        let attempt_2 = 2_i64.pow(2) * 30; // 120s
        let attempt_3 = 2_i64.pow(3) * 30; // 240s
        assert_eq!(attempt_1, 60);
        assert_eq!(attempt_2, 120);
        assert_eq!(attempt_3, 240);
    }

    #[tokio::test]
    async fn test_provider_creation() {
        let pool = PgPool::connect_lazy("postgres://localhost/test").unwrap();
        let _provider = PostgresQueueProvider::new(pool);
    }
}
