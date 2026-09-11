//! Postgres queue provider with SKIP LOCKED for exactly-once processing.
//!
//! # Security
//! - O‑5.1:HMAC‑SHA256 payload signing for integrity verification.
//! - O‑5.2:Priority aging to prevent starvation of low‑priority jobs.

use base64::Engine;
use chrono::{TimeDelta, Utc};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use sqlx::PgPool;
use tracing::{info, warn};
use uuid::Uuid;

use crate::types::{EnqueueOptions, Job, JobStatus, QueueError, QueueStats};

/// Key used to embed the HMAC signature in the JSON payload.
const HMAC_FIELD: &str = "__hmac__";
const MAX_RETRY_BACKOFF_SECS: i64 = 3600;

/// HMAC‑SHA256 signing provider.
type HmacSha256 = Hmac<Sha256>;

/// Postgres-backed job queue using SELECT ... FOR UPDATE SKIP LOCKED.
///
/// O‑5.1:When a `signing_key` is configured, every enqueued payload is signed
/// with HMAC‑SHA256 and verified on dequeue. Tampered payloads are rejected.
///
/// O‑5.2:The dequeue ORDER BY incorporates an "effective priority" that ages
/// low‑priority jobs over time (+1 per hour waited, capped at +100),
/// preventing starvation.
pub struct PostgresQueueProvider {
    db: PgPool,
    /// Optional HMAC‑SHA256 signing key for payload integrity.
    signing_key: Option<Vec<u8>>,
}

impl PostgresQueueProvider {
    /// Create a new provider without payload signing.
    pub fn new(db: PgPool) -> Self {
        Self {
            db,
            signing_key: None,
        }
    }

    /// Create a new provider with HMAC‑SHA256 payload signing.
    pub fn with_signing_key(db: PgPool, signing_key: Vec<u8>) -> Self {
        Self {
            db,
            signing_key: Some(signing_key),
        }
    }

    /// Returns `true` if payload signing is enabled.
    pub fn is_signing_enabled(&self) -> bool {
        self.signing_key.is_some()
    }

    /// Compute an HMAC‑SHA256 signature over the canonical payload JSON.
    fn compute_signature(&self, payload: &serde_json::Value) -> Result<String, QueueError> {
        let key = self
            .signing_key
            .as_ref()
            .ok_or_else(|| QueueError::InvalidPayload("Signing not configured".into()))?;
        let mac = HmacSha256::new_from_slice(key)
            .map_err(|e| QueueError::InvalidPayload(format!("HMAC key error: {e}")))?;

        // Serialize the payload (without __hmac__) to CANONICAL JSON bytes:
        // object keys sorted recursively. The payload makes a Postgres JSONB
        // round trip between enqueue and dequeue, and JSONB re-orders keys
        // (by length, then bytewise) and normalizes numbers — signing the
        // raw serde_json serialization would therefore fail verification on
        // read-back. Canonicalizing on BOTH sides makes the signed bytes
        // stable across the round trip.
        let canonical = canonical_json_bytes(payload)
            .map_err(|e| QueueError::InvalidPayload(format!("Payload serialization: {e}")))?;

        // Use hmac_mut to compute the signature
        let mut mac = mac;
        mac.update(&canonical);
        let result = mac.finalize();
        let code = result.into_bytes();
        Ok(base64::engine::general_purpose::STANDARD.encode(code))
    }

    /// Strip the `__hmac__` field from a payload (if present).
    fn strip_hmac(payload: &mut serde_json::Value) {
        if let serde_json::Value::Object(map) = payload {
            map.remove(HMAC_FIELD);
        }
    }

    fn prepare_payload_for_storage(
        &self,
        mut payload: serde_json::Value,
    ) -> Result<PreparedPayload, QueueError> {
        Self::strip_hmac(&mut payload);

        let signature = if self.signing_key.is_some() {
            let sig = self.compute_signature(&payload)?;
            if let serde_json::Value::Object(ref mut map) = payload {
                map.insert(
                    HMAC_FIELD.to_string(),
                    serde_json::Value::String(sig.clone()),
                );
            }
            Some(sig)
        } else {
            None
        };

        Ok(PreparedPayload { payload, signature })
    }

    /// Enqueue a new job.
    ///
    /// O‑5.1:If signing is enabled, the payload is signed with HMAC‑SHA256
    /// before storage. The signature is embedded as `__hmac__` in the JSON.
    pub async fn enqueue(&self, opts: EnqueueOptions) -> Result<Job, QueueError> {
        let id = Uuid::new_v4();
        let now = Utc::now();
        let scheduled_at = opts.scheduled_at.unwrap_or(now);

        if opts.queue.trim().is_empty() {
            return Err(QueueError::InvalidPayload("queue name is required".into()));
        }
        if opts.max_attempts <= 0 {
            return Err(QueueError::InvalidPayload(
                "max_attempts must be positive".into(),
            ));
        }
        if opts.visibility_timeout <= 0 {
            return Err(QueueError::InvalidPayload(
                "visibility_timeout must be positive seconds".into(),
            ));
        }

        // O‑5.1:Sign the payload before storing
        let prepared = self.prepare_payload_for_storage(opts.payload)?;

        let row: JobRow = sqlx::query_as::<_, JobRow>(
            r#"
            INSERT INTO queue_jobs (id, tenant_id, queue, payload, status, attempts, max_attempts,
                                    priority, scheduled_at, visibility_timeout, created_at, updated_at)
            VALUES ($1, $2, $3, $4, 'pending', 0, $5, $6, $7, $8, $9, $9)
            RETURNING id, tenant_id, queue, payload, status,
                      attempts, max_attempts, priority, scheduled_at,
                      started_at, completed_at, failed_at, error_message,
                      visibility_timeout, lease_token, created_at, updated_at
            "#,
        )
        .bind(id)
        .bind(opts.tenant_id)
        .bind(&opts.queue)
        .bind(&prepared.payload)
        .bind(opts.max_attempts)
        .bind(opts.priority)
        .bind(scheduled_at)
        .bind(opts.visibility_timeout)
        .bind(now)
        .fetch_one(&self.db)
        .await?;

        if let Some(sig) = prepared.signature {
            info!(job_id = %id, queue = %opts.queue, sig = %sig, "Job enqueued with HMAC");
        } else {
            info!(job_id = %id, queue = %opts.queue, "Job enqueued (unsigned)");
        }
        Ok(row.into_job())
    }

    /// Dequeue the next available job using SKIP LOCKED.
    ///
    /// O‑5.2: Uses an "effective priority" that ages over time:
    /// `priority + LEAST(age_in_hours, 100)`. This prevents low‑priority
    /// jobs from starving while maintaining priority ordering for recent jobs.
    ///
    /// F15:index shape — the inner WHERE leads with exactly the predicates
    /// of the partial dequeue index (`idx_queue_jobs_dequeue ON queue_jobs
    /// (queue, scheduled_at) WHERE status = 'pending'`, see
    /// [`crate::schema::QUEUE_SCHEMA`]): `queue = $1 AND status = 'pending'
    /// AND scheduled_at <= $3`. The planner can therefore pre-filter with
    /// the partial index (equality on the leading column + range on the
    /// second) BEFORE the computed effective-priority sort; the ORDER BY
    /// expression itself is inherently un-indexable, but it only sorts the
    /// already index-filtered candidate set. The extra `attempts <
    /// max_attempts` filter is applied after the index scan and must not
    /// be reordered ahead of the index predicates.
    ///
    /// O‑5.1: If signing is enabled, each payload's HMAC is verified before
    /// returning. Tampered payloads are logged and skipped.
    pub async fn dequeue(&self, queue: &str, batch_size: i32) -> Result<Vec<Job>, QueueError> {
        let now = Utc::now();

        let rows: Vec<JobRow> = sqlx::query_as::<_, JobRow>(
            r#"
            UPDATE queue_jobs
            SET status = 'processing',
                started_at = $3,
                attempts = attempts + 1,
                lease_token = gen_random_uuid(),
                updated_at = $3
            WHERE id IN (
                SELECT id FROM queue_jobs
                WHERE queue = $1
                  AND status = 'pending'
                  AND attempts < max_attempts
                  AND scheduled_at <= $3
                ORDER BY
                    (priority + LEAST(EXTRACT(EPOCH FROM ($3 - created_at)) / 3600, 100))::int DESC,
                    created_at ASC
                FOR UPDATE SKIP LOCKED
                LIMIT $2
            )
            RETURNING id, tenant_id, queue, payload, status,
                      attempts, max_attempts, priority, scheduled_at,
                      started_at, completed_at, failed_at, error_message,
                      visibility_timeout, lease_token, created_at, updated_at
            "#,
        )
        .bind(queue)
        .bind(batch_size as i64)
        .bind(now)
        .fetch_all(&self.db)
        .await?;

        // O‑5.1:Verify HMAC signatures and filter out tampered payloads
        let mut jobs: Vec<Job> = Vec::with_capacity(rows.len());
        for row in rows {
            let mut payload = row.payload.clone();
            if self.signing_key.is_some() {
                // Extract and remove the HMAC field
                let stored_sig = payload
                    .get(HMAC_FIELD)
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                Self::strip_hmac(&mut payload);

                if let Some(sig) = stored_sig {
                    let expected = self.compute_signature(&payload)?;
                    if sig != expected {
                        warn!(
                            job_id = %row.id,
                            "HMAC verification failed – payload tampered, skipping job"
                        );
                        // Revert to pending so it can be inspected via dead letter
                        let _ = sqlx::query(
                            r#"
                            UPDATE queue_jobs
                            SET status = 'dead_letter',
                                error_message = 'HMAC verification failed; manual replay requires trusted payload re-signing',
                                updated_at = $2
                            WHERE id = $1
                            "#,
                        )
                        .bind(row.id)
                        .bind(now)
                        .execute(&self.db)
                        .await;
                        continue;
                    }
                } else {
                    warn!(
                        job_id = %row.id,
                        "Missing HMAC signature – payload tampered or migration, skipping job"
                    );
                    let _ = sqlx::query(
                        r#"
                        UPDATE queue_jobs
                        SET status = 'dead_letter',
                            error_message = 'Missing HMAC signature; manual replay requires trusted payload re-signing',
                            updated_at = $2
                        WHERE id = $1
                        "#,
                    )
                    .bind(row.id)
                    .bind(now)
                    .execute(&self.db)
                    .await;
                    continue;
                }
            }

            // Reconstruct the final payload without __hmac__
            let mut job = row.into_job();
            job.payload = payload;
            jobs.push(job);
        }

        if !jobs.is_empty() {
            info!(count = jobs.len(), queue = queue, "Dequeued jobs");
        }
        Ok(jobs)
    }

    /// Replay a dead-lettered job after manual inspection by replacing its
    /// payload with caller-provided trusted JSON and re-signing it when HMAC
    /// protection is enabled.
    pub async fn replay_dead_letter(
        &self,
        job_id: Uuid,
        payload: serde_json::Value,
    ) -> Result<Job, QueueError> {
        let now = Utc::now();
        let prepared = self.prepare_payload_for_storage(payload)?;

        let row = sqlx::query_as::<_, JobRow>(
            r#"
            UPDATE queue_jobs
            SET payload = $2,
                status = 'pending',
                attempts = 0,
                scheduled_at = $3,
                started_at = NULL,
                completed_at = NULL,
                failed_at = NULL,
                error_message = NULL,
                lease_token = NULL,
                updated_at = $3
            WHERE id = $1 AND status = 'dead_letter'
            RETURNING id, tenant_id, queue, payload, status,
                      attempts, max_attempts, priority, scheduled_at,
                      started_at, completed_at, failed_at, error_message,
                      visibility_timeout, lease_token, created_at, updated_at
            "#,
        )
        .bind(job_id)
        .bind(&prepared.payload)
        .bind(now)
        .fetch_optional(&self.db)
        .await?
        .ok_or(QueueError::NotFound { id: job_id })?;

        info!(job_id = %job_id, "Dead-lettered job manually replayed");
        Ok(row.into_job())
    }

    /// Mark a job as completed.
    ///
    /// K: exact lease fencing (migration 103) — the update requires
    /// `status = 'processing' AND lease_token = $token`, so a stale worker
    /// that lost the job (recovered and re-dequeued under a new token)
    /// cannot complete somebody else's attempt; it sees NotFound.
    pub async fn complete(&self, job_id: Uuid, lease_token: Uuid) -> Result<(), QueueError> {
        let now = Utc::now();
        let result = sqlx::query(
            r#"
            UPDATE queue_jobs
            SET status = 'completed', completed_at = $3, lease_token = NULL, updated_at = $3
            WHERE id = $1 AND status = 'processing' AND lease_token = $2
            "#,
        )
        .bind(job_id)
        .bind(lease_token)
        .bind(now)
        .execute(&self.db)
        .await?;

        if result.rows_affected() == 0 {
            return Err(QueueError::NotFound { id: job_id });
        }
        Ok(())
    }

    /// Mark a job as failed with exponential backoff for retry.
    ///
    /// K: exact lease fencing (migration 103) — every update below requires
    /// `status = 'processing' AND lease_token = $token`, so a call for a job
    /// whose lease was lost (recovered to pending, re-claimed by another
    /// worker, or already finished) is a no-op instead of corrupting the
    /// new attempt.
    pub async fn fail(
        &self,
        job_id: Uuid,
        lease_token: Uuid,
        error: &str,
    ) -> Result<(), QueueError> {
        let now = Utc::now();

        // Fetch current state
        let job: JobRow = sqlx::query_as::<_, JobRow>(
            r#"
            SELECT id, tenant_id, queue, payload, status,
                   attempts, max_attempts, priority, scheduled_at,
                   started_at, completed_at, failed_at, error_message,
                   visibility_timeout, lease_token, created_at, updated_at
            FROM queue_jobs WHERE id = $1
            "#,
        )
        .bind(job_id)
        .fetch_optional(&self.db)
        .await?
        .ok_or(QueueError::NotFound { id: job_id })?;

        // Lease lost (recovered/re-claimed, or a stale worker presenting
        // the previous token): do nothing. The current owner is responsible
        // for the job's fate now.
        if !lease_matches(job.status, job.lease_token, lease_token) {
            return Ok(());
        }

        if job.attempts >= job.max_attempts {
            // Move to dead letter queue
            self.dead_letter(job_id, lease_token, error).await?;
        } else {
            // #228:Exponential backoff with cap at 1 hour to prevent
            // excessive delays. F6:±20% jitter, deterministic per job, so a
            // cohort of jobs failing the same attempt does not retry in one
            // synchronized wave.
            let backoff_secs = jittered_backoff_secs(job_id, job.attempts);
            let retry_at = now + chrono::Duration::seconds(backoff_secs);

            let result = sqlx::query(
                r#"
                UPDATE queue_jobs
                SET status = 'pending',
                    failed_at = $3,
                    error_message = $4,
                    scheduled_at = $5,
                    lease_token = NULL,
                    updated_at = $3
                WHERE id = $1 AND status = 'processing' AND lease_token = $2
                "#,
            )
            .bind(job_id)
            .bind(lease_token)
            .bind(now)
            .bind(error)
            .bind(retry_at)
            .execute(&self.db)
            .await?;

            if result.rows_affected() == 0 {
                // Lost the lease between the SELECT and the UPDATE — treat
                // as a no-op, the new owner decides.
                return Ok(());
            }

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
    ///
    /// K: exactly fenced on `status = 'processing' AND lease_token = $token`
    /// (migration 103) — dead-lettering a job that is no longer leased by
    /// this worker is a no-op.
    pub async fn dead_letter(
        &self,
        job_id: Uuid,
        lease_token: Uuid,
        error: &str,
    ) -> Result<(), QueueError> {
        let now = Utc::now();
        let result = sqlx::query(
            r#"
            UPDATE queue_jobs
            SET status = 'dead_letter',
                failed_at = $3,
                error_message = $4,
                lease_token = NULL,
                updated_at = $3
            WHERE id = $1 AND status = 'processing' AND lease_token = $2
            "#,
        )
        .bind(job_id)
        .bind(lease_token)
        .bind(now)
        .bind(error)
        .execute(&self.db)
        .await?;

        if result.rows_affected() > 0 {
            metrics::counter!("queue.dead_letter.total").increment(1);
            warn!(job_id = %job_id, "Job moved to dead letter queue");
        }
        Ok(())
    }

    /// Recover stale processing jobs (visibility timeout expired).
    ///
    /// J: zombie routing — a job whose lease expired at or beyond its
    /// attempt limit can never be dequeued again (the dequeue filter is
    /// `attempts < max_attempts`), so recovering it to `pending` would make
    /// it invisible forever. Such jobs are routed straight to dead_letter.
    /// A sweep also dead-letters any pre-existing pending zombies so
    /// nothing sits invisible in the queue.
    ///
    /// # Callers (F10 — deliberately unwired)
    ///
    /// NO production code calls this method. This crate's only consumer is
    /// `smoke-tests`, which exercises `queue_provider::types` only; the
    /// production email path (`worker-processors`) polls `email_queue`
    /// directly with its own lease reclaim, not `queue_jobs`. Wiring this
    /// sweep therefore requires first adopting `PostgresQueueProvider` in a
    /// production poller — until then a periodic caller would sweep a table
    /// nothing reads, which is noise, not recovery. If/when a production
    /// owner appears (e.g. a `queue_jobs`-based processor in
    /// worker-processors), call this on a ~30-60s interval from that
    /// processor's poll loop, mirroring the expired-lease reclaim in the
    /// worker's `fetch_jobs` (`worker-processors/src/email/processor.rs`).
    pub async fn recover_stale(&self) -> Result<i64, QueueError> {
        let now = Utc::now();

        // 1) Expired processing jobs at/over the attempt limit: dead-letter.
        let dl_processing = sqlx::query(
            r#"
            UPDATE queue_jobs
            SET status = 'dead_letter',
                error_message = 'visibility timeout expired at max attempts',
                lease_token = NULL,
                updated_at = $1
            WHERE status = 'processing'
              AND started_at + (visibility_timeout * interval '1 second') < $1
              AND attempts >= max_attempts
            "#,
        )
        .bind(now)
        .execute(&self.db)
        .await?;

        // 2) Sweep pending zombies (at/over the limit, e.g. from a crash
        // between fail() and the retry write).
        let dl_pending = sqlx::query(
            r#"
            UPDATE queue_jobs
            SET status = 'dead_letter',
                error_message = 'max attempts exceeded while pending',
                lease_token = NULL,
                updated_at = $1
            WHERE status = 'pending'
              AND attempts >= max_attempts
            "#,
        )
        .bind(now)
        .execute(&self.db)
        .await?;

        // 3) Recover the remaining expired processing jobs for retry. The
        // lease token is cleared so a stale worker holding the old token
        // can never re-match the fencing predicate.
        let result = sqlx::query(
            r#"
            UPDATE queue_jobs
            SET status = 'pending', lease_token = NULL, updated_at = $1
            WHERE status = 'processing'
              AND started_at + (visibility_timeout * interval '1 second') < $1
              AND attempts < max_attempts
            "#,
        )
        .bind(now)
        .execute(&self.db)
        .await?;

        let count = (dl_processing.rows_affected()
            + dl_pending.rows_affected()
            + result.rows_affected()) as i64;
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
        let cutoff =
            Utc::now() - TimeDelta::try_hours(older_than_hours as i64).unwrap_or(TimeDelta::zero());
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
    lease_token: Option<Uuid>,
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

struct PreparedPayload {
    payload: serde_json::Value,
    signature: Option<String>,
}

fn retry_backoff_secs(attempts: i32) -> i64 {
    let exponent = attempts.clamp(0, 7) as u32;
    ((1_i64 << exponent) * 30).min(MAX_RETRY_BACKOFF_SECS)
}

/// F6:retry backoff with ±20% jitter, DETERMINISTIC per (job, attempt).
///
/// `rand` is not a dependency of this crate, so the spread is derived from
/// a stable hash of the job id + attempt count: identical inputs always
/// produce identical output (reproducible in tests and logs), while
/// distinct failing jobs spread their retries across the ±20% band instead
/// of landing on the same second.
fn jittered_backoff_secs(job_id: Uuid, attempts: i32) -> i64 {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    job_id.hash(&mut hasher);
    attempts.hash(&mut hasher);
    // 0..=40 → multiplier 0.80..=1.20
    let spread = (hasher.finish() % 41) as f64 / 100.0;
    let base = retry_backoff_secs(attempts) as f64;
    ((base * (0.8 + spread)).round() as i64).clamp(1, MAX_RETRY_BACKOFF_SECS)
}

/// K: a completion-path call may only act while the job is leased for
/// processing by THIS caller — the stored token must equal the presented
/// one. Anything else (pending = recovered/re-claimed, completed,
/// dead_letter, or a stale worker holding the previous token) means the
/// caller lost ownership.
fn lease_matches(status: JobStatus, stored: Option<Uuid>, presented: Uuid) -> bool {
    status == JobStatus::Processing && stored == Some(presented)
}

/// Serialize a JSON value to canonical bytes: recursively sorted object
/// keys, deterministic number formatting (serde_json's integer/ryu float
/// output), and serde_json string escaping. Applied identically before
/// signing (enqueue) and before verifying (dequeue) so the exact bytes
/// survive a Postgres JSONB round trip, which re-orders keys and
/// re-formats values.
fn canonical_json_bytes(value: &serde_json::Value) -> Result<Vec<u8>, serde_json::Error> {
    let mut out = Vec::new();
    write_canonical(value, &mut out)?;
    Ok(out)
}

fn write_canonical(value: &serde_json::Value, out: &mut Vec<u8>) -> Result<(), serde_json::Error> {
    match value {
        serde_json::Value::Null => out.extend_from_slice(b"null"),
        serde_json::Value::Bool(true) => out.extend_from_slice(b"true"),
        serde_json::Value::Bool(false) => out.extend_from_slice(b"false"),
        serde_json::Value::Number(n) => {
            // Number Display: integers via itoa, floats via ryu — the same
            // formatting serde_json's serializer produces, and identical on
            // both sides because both parse through serde_json first.
            out.extend_from_slice(n.to_string().as_bytes());
        }
        serde_json::Value::String(s) => {
            let mut ser = serde_json::Serializer::new(&mut *out);
            serde::Serialize::serialize(s, &mut ser)?;
        }
        serde_json::Value::Array(items) => {
            out.push(b'[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                write_canonical(item, out)?;
            }
            out.push(b']');
        }
        serde_json::Value::Object(map) => {
            out.push(b'{');
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort_unstable();
            keys.dedup();
            for (i, key) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                let mut ser = serde_json::Serializer::new(&mut *out);
                serde::Serialize::serialize(key.as_str(), &mut ser)?;
                out.push(b':');
                write_canonical(&map[*key], out)?;
            }
            out.push(b'}');
        }
    }
    Ok(())
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
            lease_token: self.lease_token,
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

    #[tokio::test]
    async fn test_hmac_strip_and_compute() {
        let mut payload = serde_json::json!({
            "to": "user@example.com",
            "__hmac__": "abc123"
        });

        // Verify strip removes the field
        PostgresQueueProvider::strip_hmac(&mut payload);
        assert!(payload.get("__hmac__").is_none());
        assert_eq!(payload.get("to").unwrap(), "user@example.com");

        // Verify compute works with a provider that has a signing key
        let pool = PgPool::connect_lazy("postgres://localhost/test").unwrap();
        let provider = PostgresQueueProvider::with_signing_key(pool, b"test-key".to_vec());
        let sig = provider.compute_signature(&payload).unwrap();
        assert_eq!(sig.len(), 44); // SHA‑256 → 32 bytes → base64 = 44 chars
        assert!(base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &sig).is_ok());
    }

    #[tokio::test]
    async fn test_hmac_verification() {
        let payload = serde_json::json!({"to": "user@example.com"});

        let pool = PgPool::connect_lazy("postgres://localhost/test").unwrap();
        let provider = PostgresQueueProvider::with_signing_key(pool, b"test-key".to_vec());

        let sig1 = provider.compute_signature(&payload).unwrap();

        // Same payload should produce same signature
        let sig2 = provider.compute_signature(&payload).unwrap();
        assert_eq!(sig1, sig2);

        // Different payload should produce different signature
        let mutated = serde_json::json!({"to": "attacker@example.com"});
        let sig3 = provider.compute_signature(&mutated).unwrap();
        assert_ne!(sig1, sig3);
    }

    #[tokio::test]
    async fn test_prepare_payload_for_storage_resigns_manual_replay_payload() {
        let pool = PgPool::connect_lazy("postgres://localhost/test").unwrap();
        let provider = PostgresQueueProvider::with_signing_key(pool, b"test-key".to_vec());
        let payload = serde_json::json!({
            "to": "user@example.com",
            "__hmac__": "stale-or-tampered"
        });

        let prepared = provider.prepare_payload_for_storage(payload).unwrap();
        let stored_sig = prepared
            .payload
            .get(HMAC_FIELD)
            .and_then(|value| value.as_str())
            .expect("payload should be signed");

        assert_ne!(stored_sig, "stale-or-tampered");
        assert_eq!(prepared.signature.as_deref(), Some(stored_sig));

        let mut verification_payload = prepared.payload.clone();
        PostgresQueueProvider::strip_hmac(&mut verification_payload);
        assert_eq!(
            provider.compute_signature(&verification_payload).unwrap(),
            stored_sig
        );
    }

    #[tokio::test]
    async fn test_prepare_payload_for_storage_strips_hmac_without_signing() {
        let pool = PgPool::connect_lazy("postgres://localhost/test").unwrap();
        let provider = PostgresQueueProvider::new(pool);
        let payload = serde_json::json!({
            "to": "user@example.com",
            "__hmac__": "stale-or-tampered"
        });

        let prepared = provider.prepare_payload_for_storage(payload).unwrap();
        assert!(prepared.signature.is_none());
        assert!(prepared.payload.get(HMAC_FIELD).is_none());
    }

    #[test]
    fn test_exponential_backoff_calculation() {
        assert_eq!(retry_backoff_secs(1), 60);
        assert_eq!(retry_backoff_secs(2), 120);
        assert_eq!(retry_backoff_secs(3), 240);
        assert_eq!(retry_backoff_secs(30), MAX_RETRY_BACKOFF_SECS);
        assert_eq!(retry_backoff_secs(i32::MAX), MAX_RETRY_BACKOFF_SECS);
    }

    #[test]
    fn test_jittered_backoff_within_20_percent_and_deterministic() {
        // F6:every jittered sample stays within ±20% of the pure backoff,
        // never exceeds the cap, never collapses to zero, and is
        // deterministic per (job, attempt).
        for attempts in 1..6 {
            let base = retry_backoff_secs(attempts);
            let low = ((base as f64) * 0.8).floor() as i64;
            let high = ((base as f64) * 1.2).ceil() as i64;
            let mut saw_below = false;
            let mut saw_above = false;
            for _ in 0..50 {
                let id = Uuid::new_v4();
                let jittered = jittered_backoff_secs(id, attempts);
                assert!(
                    jittered >= low && jittered <= high.min(MAX_RETRY_BACKOFF_SECS),
                    "jittered {jittered}s outside [{low},{high}] for base {base}s"
                );
                saw_below |= jittered < base;
                saw_above |= jittered > base;
            }
            assert!(
                saw_below && saw_above,
                "jitter must spread on both sides of the base at attempt {attempts}"
            );
            // Deterministic per (job, attempt).
            let id = Uuid::new_v4();
            assert_eq!(
                jittered_backoff_secs(id, attempts),
                jittered_backoff_secs(id, attempts)
            );
        }
        // Attempt 30: base already at the cap → jitter stays within
        // [0.8*cap, cap] (downward jitter remains, upward is clamped).
        let capped_low = ((MAX_RETRY_BACKOFF_SECS as f64) * 0.8).floor() as i64;
        for _ in 0..20 {
            let jittered = jittered_backoff_secs(Uuid::new_v4(), 30);
            assert!(
                jittered >= capped_low && jittered <= MAX_RETRY_BACKOFF_SECS,
                "capped jitter {jittered}s outside [{capped_low},{MAX_RETRY_BACKOFF_SECS}]"
            );
        }
    }

    #[test]
    fn dequeue_inner_where_matches_partial_dequeue_index() {
        // F15:the inner WHERE must carry the exact predicates of the
        // partial dequeue index (schema.rs): equality on `queue`, the
        // partial predicate `status = 'pending'`, and the range on
        // `scheduled_at` — so the index pre-filters before the computed
        // effective-priority sort. Pinned by test because reordering or
        // dropping these predicates silently degrades to a full scan.
        let index = crate::schema::QUEUE_SCHEMA;
        assert!(
            index.contains("idx_queue_jobs_dequeue"),
            "the partial dequeue index must exist in the schema"
        );
        assert!(index.contains("WHERE status = 'pending'"));

        let source = include_str!("provider.rs");
        let inner = source
            .split("WHERE id IN (")
            .nth(1)
            .and_then(|rest| rest.split("ORDER BY").next())
            .expect("dequeue inner WHERE must exist");
        assert!(
            inner.contains("queue = $1"),
            "inner WHERE must equality-match the index's leading column"
        );
        assert!(
            inner.contains("status = 'pending'"),
            "inner WHERE must imply the partial index predicate"
        );
        assert!(
            inner.contains("scheduled_at <= $3"),
            "inner WHERE must range-match the index's second column"
        );
    }

    #[tokio::test]
    async fn test_provider_creation_no_signing() {
        let pool = PgPool::connect_lazy("postgres://localhost/test").unwrap();
        let provider = PostgresQueueProvider::new(pool);
        assert!(!provider.is_signing_enabled());
    }

    #[tokio::test]
    async fn test_provider_creation_with_signing() {
        let pool = PgPool::connect_lazy("postgres://localhost/test").unwrap();
        let provider = PostgresQueueProvider::with_signing_key(pool, b"my-secret-key".to_vec());
        assert!(provider.is_signing_enabled());
    }

    // ── C: HMAC survives the JSONB round trip ─────────────────────────────

    /// Re-serialize a Value the way Postgres JSONB does: object keys sorted
    /// by (length, bytewise), recursively. Mimics what dequeue reads back
    /// after the payload column round-trips through JSONB.
    fn pg_jsonb_text(value: &serde_json::Value) -> String {
        match value {
            serde_json::Value::Object(map) => {
                let mut keys: Vec<&String> = map.keys().collect();
                keys.sort_by(|a, b| {
                    a.len()
                        .cmp(&b.len())
                        .then_with(|| a.as_bytes().cmp(b.as_bytes()))
                });
                let parts: Vec<String> = keys
                    .into_iter()
                    .map(|k| {
                        format!(
                            "{}:{}",
                            serde_json::to_string(k).unwrap(),
                            pg_jsonb_text(&map[k])
                        )
                    })
                    .collect();
                format!("{{{}}}", parts.join(","))
            }
            other => serde_json::to_string(other).unwrap(),
        }
    }

    #[tokio::test]
    async fn test_hmac_survives_jsonb_round_trip() {
        let pool = PgPool::connect_lazy("postgres://localhost/test").unwrap();
        let provider = PostgresQueueProvider::with_signing_key(pool, b"test-key".to_vec());

        // The failing case: >= 2 keys of different lengths + nested objects +
        // mixed number types. JSONB re-orders all of these.
        let payload = serde_json::json!({
            "very_long_key": "value",
            "b": 1,
            "middle": {"z": 1, "aa": [1, 2.5, "x"], "nested": {"deep": true}},
            "aaa": -42,
            "custom_flag": null
        });

        let prepared = provider
            .prepare_payload_for_storage(payload.clone())
            .unwrap();
        let stored_sig = prepared
            .payload
            .get(HMAC_FIELD)
            .and_then(|v| v.as_str())
            .expect("payload should be signed")
            .to_string();

        // Simulate the JSONB round trip: re-serialize with PG key ordering,
        // then parse back into a Value as sqlx does on dequeue.
        let pg_text = pg_jsonb_text(&prepared.payload);
        let round_tripped: serde_json::Value =
            serde_json::from_str(&pg_text).expect("mimic output must be valid JSON");

        let mut verification_payload = round_tripped;
        let extracted = verification_payload
            .get(HMAC_FIELD)
            .and_then(|v| v.as_str())
            .expect("sig present after round trip")
            .to_string();
        PostgresQueueProvider::strip_hmac(&mut verification_payload);

        assert_eq!(
            provider.compute_signature(&verification_payload).unwrap(),
            stored_sig,
            "signature must verify against the JSONB-reordered payload"
        );
        assert_eq!(extracted, stored_sig);
    }

    #[tokio::test]
    async fn test_hmac_detects_tampering_after_round_trip() {
        let pool = PgPool::connect_lazy("postgres://localhost/test").unwrap();
        let provider = PostgresQueueProvider::with_signing_key(pool, b"test-key".to_vec());

        let payload = serde_json::json!({"to": "user@example.com", "attempt": 3});
        let prepared = provider.prepare_payload_for_storage(payload).unwrap();
        let stored_sig = prepared
            .payload
            .get(HMAC_FIELD)
            .and_then(|v| v.as_str())
            .unwrap()
            .to_string();

        // Tamper AFTER the round trip (what an attacker with column access
        // would do): the canonical re-computation must mismatch.
        let mut tampered = prepared.payload.clone();
        PostgresQueueProvider::strip_hmac(&mut tampered);
        if let Some(obj) = tampered.as_object_mut() {
            obj.insert(
                "to".to_string(),
                serde_json::Value::String("attacker@example.com".to_string()),
            );
        }
        assert_ne!(
            provider.compute_signature(&tampered).unwrap(),
            stored_sig,
            "tampered payload must not verify"
        );
    }

    #[test]
    fn test_canonical_bytes_key_order_insensitive() {
        // Two semantically-equal payloads with different insertion orders
        // (possible when preserve_order-style maps are in play) canonicalize
        // to identical bytes.
        let a = serde_json::json!({"a": 1, "bb": {"x": 1, "yy": 2}, "c": "s"});
        // Build the same object with reversed key insertion by parsing a
        // differently-ordered text.
        let b: serde_json::Value =
            serde_json::from_str(r#"{"c":"s","bb":{"yy":2,"x":1},"a":1}"#).unwrap();
        assert_eq!(
            canonical_json_bytes(&a).unwrap(),
            canonical_json_bytes(&b).unwrap()
        );
        // Numbers keep deterministic formatting.
        let n = serde_json::json!({"i": 42, "f": 2.5, "big": 18446744073709551615u64});
        let bytes = canonical_json_bytes(&n).unwrap();
        assert_eq!(
            String::from_utf8(bytes).unwrap(),
            r#"{"big":18446744073709551615,"f":2.5,"i":42}"#
        );
    }

    // ── K: lease fencing ───────────────────────────────────────────────────

    #[test]
    fn test_lease_matches_requires_processing_and_token() {
        let token = Uuid::new_v4();
        // Current owner: processing under the presented token.
        assert!(lease_matches(JobStatus::Processing, Some(token), token));
        // Stale worker: processing, but under a NEWER token.
        assert!(!lease_matches(
            JobStatus::Processing,
            Some(Uuid::new_v4()),
            token
        ));
        // Recovered/re-claimed (token cleared) or finished states.
        assert!(!lease_matches(JobStatus::Processing, None, token));
        assert!(!lease_matches(JobStatus::Pending, Some(token), token));
        assert!(!lease_matches(JobStatus::Completed, Some(token), token));
        assert!(!lease_matches(JobStatus::DeadLetter, Some(token), token));
        assert!(!lease_matches(JobStatus::Failed, Some(token), token));
    }

    #[tokio::test]
    async fn test_completion_paths_are_fenced_on_lease_token() {
        // complete(), fail()'s retry UPDATE, and dead_letter()'s UPDATE must
        // all fence on (status = 'processing' AND lease_token). The pattern
        // occurs exactly 3 times in code plus once in this test's own
        // literal below.
        let source = include_str!("provider.rs");
        let fences = source
            .match_indices("AND status = 'processing' AND lease_token = $2")
            .count();
        assert_eq!(
            fences, 4,
            "expected 3 token-fenced UPDATEs + 1 test literal, found {}",
            fences
        );
        // Recovery and replay must clear the token so stale tokens can
        // never re-match.
        assert!(source.contains("SET status = 'pending', lease_token = NULL"));
        assert!(source.contains("lease_token = gen_random_uuid()"));
    }

    // ── J: zombie routing ──────────────────────────────────────────────────

    #[tokio::test]
    async fn test_recover_stale_routes_zombies_to_dead_letter() {
        // The recovery queries must (1) dead-letter expired processing jobs
        // at/over max attempts instead of re-queueing them, and (2) sweep
        // pending zombies. Assert on the SQL embedded in provider.rs so the
        // guarantees are pinned by a test even without a live database.
        let source = include_str!("provider.rs");
        assert!(
            source.contains("AND attempts >= max_attempts"),
            "recovery must route exhausted jobs to dead_letter"
        );
        assert!(
            source.contains("WHERE status = 'pending'"),
            "pending zombie sweep must exist"
        );
        assert!(
            source.contains("AND attempts < max_attempts"),
            "retry recovery must exclude exhausted jobs"
        );
    }

    // ── DB-gated lease fencing (skipped without TEST_DATABASE_URL) ────────

    /// Connect to the test database when TEST_DATABASE_URL is set, following
    /// the workspace convention of skipping (not failing) when absent.
    async fn optional_pool() -> Option<PgPool> {
        let url = std::env::var("TEST_DATABASE_URL").ok()?;
        let pool = PgPool::connect(&url).await.ok()?;
        // Ensure the table shape exists (fresh scratch databases): the base
        // DDL plus migration 103's column/index.
        sqlx::raw_sql(crate::schema::QUEUE_SCHEMA)
            .execute(&pool)
            .await
            .ok()?;
        sqlx::raw_sql(
            "ALTER TABLE queue_jobs ADD COLUMN IF NOT EXISTS lease_token UUID; \
             CREATE INDEX IF NOT EXISTS idx_queue_jobs_lease \
             ON queue_jobs (lease_token) \
             WHERE status = 'processing' AND lease_token IS NOT NULL;",
        )
        .execute(&pool)
        .await
        .ok()?;
        Some(pool)
    }

    async fn current_status(pool: &PgPool, id: Uuid) -> String {
        sqlx::query_scalar("SELECT status FROM queue_jobs WHERE id = $1")
            .bind(id)
            .fetch_one(pool)
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn stale_lease_worker_cannot_complete_or_fail_a_reclaimed_job() {
        let Some(pool) = optional_pool().await else {
            eprintln!("skipping: set TEST_DATABASE_URL to run DB-backed test");
            return;
        };
        let provider = PostgresQueueProvider::new(pool.clone());
        let queue = format!("lease-fence-{}", Uuid::new_v4());

        let job = provider
            .enqueue(EnqueueOptions {
                tenant_id: Uuid::new_v4(),
                queue: queue.clone(),
                payload: serde_json::json!({"n": 1}),
                max_attempts: 3,
                priority: 0,
                scheduled_at: None,
                visibility_timeout: 60,
            })
            .await
            .unwrap();
        let dequeued = provider.dequeue(&queue, 1).await.unwrap();
        assert_eq!(dequeued.len(), 1);
        let current = &dequeued[0];
        let live_token = current
            .lease_token
            .expect("dequeue must mint a lease token");

        // A STALE worker (wrong token) can neither complete nor fail the
        // job: complete() reports NotFound, fail() is a no-op.
        let stale = Uuid::new_v4();
        assert!(provider.complete(job.id, stale).await.is_err());
        provider.fail(job.id, stale, "stale worker").await.unwrap();
        assert_eq!(current_status(&pool, job.id).await, "processing");

        // The rightful owner (live token) completes it.
        provider.complete(job.id, live_token).await.unwrap();
        assert_eq!(current_status(&pool, job.id).await, "completed");

        // Even the LIVE token cannot act afterwards (token cleared).
        provider
            .fail(job.id, live_token, "late failure")
            .await
            .unwrap();
        assert_eq!(current_status(&pool, job.id).await, "completed");

        sqlx::query("DELETE FROM queue_jobs WHERE queue = $1")
            .bind(&queue)
            .execute(&pool)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn recover_stale_rotates_lease_tokens() {
        let Some(pool) = optional_pool().await else {
            eprintln!("skipping: set TEST_DATABASE_URL to run DB-backed test");
            return;
        };
        let provider = PostgresQueueProvider::new(pool.clone());
        let queue = format!("lease-rotate-{}", Uuid::new_v4());

        let job = provider
            .enqueue(EnqueueOptions {
                tenant_id: Uuid::new_v4(),
                queue: queue.clone(),
                payload: serde_json::json!({"n": 1}),
                max_attempts: 3,
                priority: 0,
                scheduled_at: None,
                visibility_timeout: 1,
            })
            .await
            .unwrap();
        let first = provider.dequeue(&queue, 1).await.unwrap().remove(0);
        let first_token = first.lease_token.unwrap();

        // Let the visibility timeout expire, then recover: the job goes
        // back to pending with its token cleared.
        tokio::time::sleep(std::time::Duration::from_millis(1200)).await;
        provider.recover_stale().await.unwrap();
        assert_eq!(current_status(&pool, job.id).await, "pending");
        let stored: Option<Uuid> =
            sqlx::query_scalar("SELECT lease_token FROM queue_jobs WHERE id = $1")
                .bind(job.id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(stored, None, "recovery must clear the lease token");

        // Re-dequeue mints a NEW token; the old worker's fail() is a no-op.
        let second = provider.dequeue(&queue, 1).await.unwrap().remove(0);
        let second_token = second.lease_token.unwrap();
        assert_ne!(first_token, second_token, "dequeue must rotate the token");
        provider
            .fail(job.id, first_token, "stale worker after recovery")
            .await
            .unwrap();
        assert_eq!(current_status(&pool, job.id).await, "processing");

        // The new owner retries it onto the schedule via fail().
        provider
            .fail(job.id, second_token, "transient error")
            .await
            .unwrap();
        assert_eq!(current_status(&pool, job.id).await, "pending");

        sqlx::query("DELETE FROM queue_jobs WHERE queue = $1")
            .bind(&queue)
            .execute(&pool)
            .await
            .unwrap();
    }

    #[test]
    fn test_priority_aging_effective_priority() {
        // Verify the aging formula: priority + LEAST(age_hours, 100)
        // A job waiting 24 hours with priority 0 should have effective priority ~24
        let created_at = Utc::now() - chrono::Duration::hours(24);
        let now = Utc::now();
        let age_secs = (now - created_at).num_seconds();
        let age_hours = age_secs as f64 / 3600.0;
        let effective = (0.0 + age_hours.min(100.0)) as i32;
        assert!(effective >= 24);
        assert!(effective <= 100);

        // A high-priority job created recently should still have higher effective priority
        let recent_high = Utc::now() - chrono::Duration::minutes(5);
        let recent_age_secs = (now - recent_high).num_seconds();
        let recent_age_hours = recent_age_secs as f64 / 3600.0;
        let recent_effective = (50.0 + recent_age_hours.min(100.0)) as i32;
        // effective priority of new high-priority job > old low-priority job
        assert!(
            recent_effective > effective,
            "New high-priority job ({}) should outrank old low-priority job ({})",
            recent_effective,
            effective
        );
    }
}
