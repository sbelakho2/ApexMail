//! Webhook processor implementation.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use chrono::Utc;
use deadpool_redis::Pool as RedisPool;
use hmac::{Hmac, Mac};
use reqwest::Client;
use sha2::Sha256;
use sqlx::PgPool;
use tokio::sync::Notify;
use tokio::time::sleep;
use tracing::{debug, error, info, warn};

use super::ssrf::SsrfValidator;
use super::types::{
    truncate_payload, PendingSuccess, WebhookDeliveryResult, WebhookJob, MAX_CONCURRENT_PER_TENANT,
    MAX_RESPONSE_BYTES, MAX_WEBHOOK_PAYLOAD_BYTES, SIGNATURE_VERSION,
};
use crate::common::circuit_breaker::CircuitBreaker;
use crate::common::{ProcessorError, ProcessorResult, WebhookConfig};

type HmacSha256 = Hmac<Sha256>;

/// Webhook processor.
pub struct WebhookProcessor {
    db: PgPool,
    redis: RedisPool,
    config: WebhookConfig,
    client: Client,
    ssrf_validator: SsrfValidator,
    circuit_breakers: Mutex<HashMap<String, Arc<CircuitBreaker>>>,
    is_running: AtomicBool,
    active_jobs: AtomicUsize,
    tenant_active_jobs: Mutex<HashMap<String, usize>>,
    pending_successes: Mutex<Vec<PendingSuccess>>,
    shutdown_notify: Arc<Notify>,
}

impl WebhookProcessor {
    /// Create a new webhook processor.
    pub fn new(db: PgPool, redis: RedisPool, config: WebhookConfig) -> ProcessorResult<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .user_agent("ApexMail-Webhook/1.0")
            .build()
            .map_err(|e| ProcessorError::Job(format!("Failed to create HTTP client: {}", e)))?;

        let ssrf_validator = SsrfValidator::new()?;

        Ok(Self {
            db,
            redis,
            config,
            client,
            ssrf_validator,
            circuit_breakers: Mutex::new(HashMap::new()),
            is_running: AtomicBool::new(false),
            active_jobs: AtomicUsize::new(0),
            tenant_active_jobs: Mutex::new(HashMap::new()),
            pending_successes: Mutex::new(Vec::new()),
            shutdown_notify: Arc::new(Notify::new()),
        })
    }

    /// Start the processor.
    pub async fn start(self: Arc<Self>) -> ProcessorResult<()> {
        info!(
            concurrency = self.config.base.concurrency,
            "Starting webhook processor"
        );

        self.is_running.store(true, Ordering::SeqCst);
        self.poll_loop().await;

        Ok(())
    }

    /// Stop the processor gracefully.
    pub async fn stop(&self) -> ProcessorResult<()> {
        info!("Stopping webhook processor");
        self.is_running.store(false, Ordering::SeqCst);
        self.shutdown_notify.notify_waiters();

        // Wait for active jobs
        let max_wait = Duration::from_secs(30);
        let start = Instant::now();

        while self.active_jobs.load(Ordering::SeqCst) > 0 && start.elapsed() < max_wait {
            sleep(Duration::from_millis(100)).await;
        }

        // Flush any pending successes
        self.flush_pending_successes().await;

        info!("Webhook processor stopped");
        Ok(())
    }

    /// Main poll loop.
    async fn poll_loop(&self) {
        while self.is_running.load(Ordering::SeqCst) {
            // Check capacity
            let available =
                self.config.base.concurrency.saturating_sub(self.active_jobs.load(Ordering::SeqCst));
            if available == 0 {
                sleep(Duration::from_millis(100)).await;
                continue;
            }

            match self.fetch_jobs(available).await {
                Ok(jobs) if jobs.is_empty() => {
                    tokio::select! {
                        _ = sleep(self.config.base.poll_interval) => {}
                        _ = self.shutdown_notify.notified() => break,
                    }
                }
                Ok(jobs) => {
                    for job in jobs {
                        if let Err(e) = self.process_job(job).await {
                            error!(error = %e, "Failed to process webhook job");
                        }
                    }
                    // Flush pending successes in batch
                    self.flush_pending_successes().await;
                    sleep(Duration::from_millis(100)).await;
                }
                Err(e) => {
                    error!(error = %e, "Failed to fetch webhook jobs");
                    sleep(self.config.base.poll_interval).await;
                }
            }
        }
    }

    /// Fetch webhook jobs from queue.
    async fn fetch_jobs(&self, limit: usize) -> ProcessorResult<Vec<WebhookJob>> {
        let jobs = sqlx::query_as::<_, WebhookJob>(
            r#"
            WITH claimed_jobs AS (
                UPDATE webhook_queue wq
                SET status = 'processing', locked_until = NOW() + INTERVAL '1 minute', updated_at = NOW()
                WHERE wq.id IN (
                    SELECT wq2.id
                    FROM webhook_queue wq2
                    JOIN webhooks w ON w.id = wq2.webhook_id
                    WHERE wq2.status = 'pending'
                      AND (wq2.scheduled_at IS NULL OR wq2.scheduled_at <= NOW())
                      AND (wq2.locked_until IS NULL OR wq2.locked_until < NOW())
                      AND w.enabled = true
                    ORDER BY wq2.created_at ASC
                    LIMIT $1
                    FOR UPDATE OF wq2 SKIP LOCKED
                )
                RETURNING wq.id, wq.webhook_id, wq.tenant_id, wq.event_type,
                          wq.payload, wq.attempt, wq.created_at
            )
            SELECT
                cj.id, cj.webhook_id as "webhookId", cj.tenant_id as "tenantId",
                cj.event_type as "eventType", cj.payload, cj.attempt, cj.created_at as "createdAt",
                w.url, w.secret, w.headers,
                (w.retry_policy->>'maxRetries')::int as "maxRetries",
                (w.retry_policy->>'retryDelay')::int as "retryDelay",
                (w.retry_policy->>'backoffMultiplier')::float as "backoffMultiplier"
            FROM claimed_jobs cj
            JOIN webhooks w ON w.id = cj.webhook_id
            "#,
        )
        .bind(limit as i64)
        .fetch_all(&self.db)
        .await?;

        Ok(jobs)
    }

    /// Process a single webhook job.
    async fn process_job(&self, job: WebhookJob) -> ProcessorResult<()> {
        // Enforce per-tenant concurrency limit
        let tenant_count = {
            let tenant_jobs = self.tenant_active_jobs.lock().unwrap();
            *tenant_jobs.get(&job.tenant_id).unwrap_or(&0)
        };

        if tenant_count >= MAX_CONCURRENT_PER_TENANT {
            warn!(
                tenant_id = %job.tenant_id,
                tenant_active = tenant_count,
                limit = MAX_CONCURRENT_PER_TENANT,
                job_id = %job.id,
                "Per-tenant concurrency limit reached, rescheduling"
            );
            // Reschedule for later
            sqlx::query(
                "UPDATE webhook_queue SET status = 'pending', scheduled_at = NOW() + INTERVAL '5 seconds', locked_until = NULL, updated_at = NOW() WHERE id = $1"
            )
            .bind(&job.id)
            .execute(&self.db)
            .await?;
            return Ok(());
        }

        // Track active job
        self.active_jobs.fetch_add(1, Ordering::SeqCst);
        {
            let mut tenant_jobs = self.tenant_active_jobs.lock().unwrap();
            *tenant_jobs.entry(job.tenant_id.clone()).or_insert(0) += 1;
        }

        let start = Instant::now();
        let result = self.process_job_inner(&job).await;

        // Decrement counters
        self.active_jobs.fetch_sub(1, Ordering::SeqCst);
        {
            let mut tenant_jobs = self.tenant_active_jobs.lock().unwrap();
            if let Some(count) = tenant_jobs.get_mut(&job.tenant_id) {
                *count = count.saturating_sub(1);
                if *count == 0 {
                    tenant_jobs.remove(&job.tenant_id);
                }
            }
        }

        debug!(
            job_id = %job.id,
            duration_ms = start.elapsed().as_millis(),
            "Webhook job completed"
        );

        result
    }

    async fn process_job_inner(&self, job: &WebhookJob) -> ProcessorResult<()> {
        debug!(
            job_id = %job.id,
            webhook_id = %job.webhook_id,
            event_type = %job.event_type,
            attempt = job.attempt,
            "Processing webhook job"
        );

        // Check dedup key to prevent double delivery
        let dedup_key = format!("webhook:dedup:{}:{}", job.id, job.attempt);
        let mut conn = self.redis.get().await?;
        let previously_delivered: Option<String> = redis::cmd("GET")
            .arg(&dedup_key)
            .query_async(&mut *conn)
            .await?;

        if previously_delivered.is_some() {
            warn!(
                job_id = %job.id,
                attempt = job.attempt,
                "Webhook already delivered (dedup), cleaning up"
            );
            sqlx::query("DELETE FROM webhook_queue WHERE id = $1")
                .bind(&job.id)
                .execute(&self.db)
                .await?;
            return Ok(());
        }

        // Get or create circuit breaker for this webhook
        let circuit_breaker = self.get_circuit_breaker(&job.webhook_id);

        // Check if circuit is open
        if !circuit_breaker.as_ref().is_allowed() {
            warn!(
                webhook_id = %job.webhook_id,
                job_id = %job.id,
                "Circuit breaker open for webhook"
            );
            // Reschedule without incrementing attempt
            let retry_delay = job.next_retry_delay_ms().min(30000);
            sqlx::query(
                "UPDATE webhook_queue SET status = 'pending', scheduled_at = NOW() + $1 * INTERVAL '1 millisecond', locked_until = NULL, last_error = 'Circuit breaker open — waiting for recovery', updated_at = NOW() WHERE id = $2"
            )
            .bind(retry_delay)
            .bind(&job.id)
            .execute(&self.db)
            .await?;
            return Ok(());
        }

        // Validate URL for SSRF protection
        if let Err(e) = self.ssrf_validator.validate_url(&job.url).await {
            let result = WebhookDeliveryResult::failure(
                None,
                0,
                format!("SSRF protection: {}", e),
                None,
                None,
            );
            self.handle_failure(job, result).await?;
            return Ok(());
        }

        // Truncate payload if too large
        let payload = if serde_json::to_string(&job.payload)
            .map(|s| s.len())
            .unwrap_or(0)
            > MAX_WEBHOOK_PAYLOAD_BYTES
        {
            warn!(
                job_id = %job.id,
                webhook_id = %job.webhook_id,
                "Payload exceeds size limit, truncating"
            );
            truncate_payload(&job.payload, MAX_WEBHOOK_PAYLOAD_BYTES)
        } else {
            job.payload.clone()
        };

        // Serialize payload once for signature and body
        let serialized_payload = serde_json::to_string(&payload)
            .map_err(|e| ProcessorError::Job(format!("Failed to serialize payload: {}", e)))?;

        // Set dedup key before delivery (24h TTL)
        redis::cmd("SETEX")
            .arg(&dedup_key)
            .arg(86400)
            .arg("1")
            .query_async::<()>(&mut *conn)
            .await?;

        // Deliver webhook
        let result = self.deliver_webhook(job, &serialized_payload).await;

        // Update circuit breaker
        if result.success {
            circuit_breaker.as_ref().record_success();
            self.handle_success(job, result).await?;
        } else {
            circuit_breaker.as_ref().record_failure();
            // Remove dedup key on failure so retries work
            let _ = redis::cmd("DEL")
                .arg(&dedup_key)
                .query_async::<()>(&mut *conn)
                .await;
            self.handle_failure(job, result).await?;
        }

        Ok(())
    }

    /// Get or create circuit breaker for a webhook.
    fn get_circuit_breaker(&self, webhook_id: &str) -> Arc<CircuitBreaker> {
        let key = format!("webhook:{}", webhook_id);
        let mut cbs = self.circuit_breakers.lock().unwrap();

        if let Some(cb) = cbs.get(&key) {
            return Arc::clone(cb);
        }

        let cb = Arc::new(CircuitBreaker::new(
            crate::common::CircuitBreakerConfig {
                failure_threshold: 5,
                open_duration: std::time::Duration::from_secs(30),
                success_threshold: 2,
                window_duration: std::time::Duration::from_secs(60),
            },
        ));
        cbs.insert(key, Arc::clone(&cb));
        cb
    }

    /// Deliver webhook to endpoint.
    async fn deliver_webhook(
        &self,
        job: &WebhookJob,
        serialized_payload: &str,
    ) -> WebhookDeliveryResult {
        let timestamp = Utc::now().timestamp_millis();
        let delivery_id = format!("dlv_{}", uuid::Uuid::new_v4());

        // Sign payload
        let signature = self.sign_payload(&job.secret, timestamp, serialized_payload);

        // Build headers
        let mut headers = job.get_headers();
        headers.insert("Content-Type".to_string(), "application/json".to_string());
        headers.insert("X-ApexMail-Webhook-Id".to_string(), job.webhook_id.clone());
        headers.insert("X-ApexMail-Signature".to_string(), signature);
        headers.insert("X-ApexMail-Timestamp".to_string(), timestamp.to_string());
        headers.insert("X-ApexMail-Event".to_string(), job.event_type.clone());
        headers.insert("X-ApexMail-Delivery-Id".to_string(), delivery_id);

        let start = Instant::now();

        // Build request
        let mut request = self.client.post(&job.url).body(serialized_payload.to_string());

        for (key, value) in &headers {
            request = request.header(key.as_str(), value.as_str());
        }

        match request.send().await {
            Ok(response) => {
                let status = response.status().as_u16();
                let response_time = start.elapsed().as_millis() as u64;

                // Parse Retry-After header for 429/503
                let retry_after_ms = if status == 429 || status == 503 {
                    response
                        .headers()
                        .get("retry-after")
                        .and_then(|v| v.to_str().ok())
                        .and_then(|v| {
                            // Try parsing as seconds
                            if let Ok(secs) = v.parse::<u64>() {
                                Some(secs.min(3600) * 1000)
                            } else {
                                // Try parsing as date
                                chrono::DateTime::parse_from_rfc2822(v)
                                    .ok()
                                    .map(|dt| {
                                        let delay = dt.timestamp_millis() - Utc::now().timestamp_millis();
                                        (delay.max(0) as u64).min(3600_000)
                                    })
                            }
                        })
                } else {
                    None
                };

                // Read limited response body
                let response_body = match response.bytes().await {
                    Ok(bytes) => {
                        let truncated = &bytes[..bytes.len().min(MAX_RESPONSE_BYTES)];
                        let body = String::from_utf8_lossy(truncated).to_string();
                        if bytes.len() > MAX_RESPONSE_BYTES {
                            Some(format!("{}...", body))
                        } else {
                            Some(body)
                        }
                    }
                    Err(_) => None,
                };

                if status >= 200 && status < 300 {
                    WebhookDeliveryResult::success(status, response_time, response_body)
                } else {
                    WebhookDeliveryResult::failure(
                        Some(status),
                        response_time,
                        format!("HTTP {}", status),
                        response_body,
                        retry_after_ms,
                    )
                }
            }
            Err(e) => {
                let response_time = start.elapsed().as_millis() as u64;
                WebhookDeliveryResult::failure(
                    None,
                    response_time,
                    e.to_string(),
                    None,
                    None,
                )
            }
        }
    }

    /// Sign payload with HMAC-SHA256.
    fn sign_payload(&self, secret: &str, timestamp: i64, payload: &str) -> String {
        let message = format!("{}.{}", timestamp, payload);
        let mut mac = HmacSha256::new_from_slice(secret.as_bytes())
            .expect("HMAC can take key of any size");
        mac.update(message.as_bytes());
        let result = mac.finalize();
        format!("{}{}", SIGNATURE_VERSION, hex::encode(result.into_bytes()))
    }

    /// Queue success for batch flush.
    async fn handle_success(&self, job: &WebhookJob, result: WebhookDeliveryResult) -> ProcessorResult<()> {
        info!(
            job_id = %job.id,
            webhook_id = %job.webhook_id,
            status_code = ?result.status_code,
            response_time_ms = result.response_time_ms,
            "Webhook delivered successfully"
        );

        self.pending_successes.lock().unwrap().push(PendingSuccess {
            job: job.clone(),
            result,
        });

        Ok(())
    }

    /// Handle failed delivery.
    async fn handle_failure(&self, job: &WebhookJob, result: WebhookDeliveryResult) -> ProcessorResult<()> {
        let error_msg = result.error.as_deref().unwrap_or("Unknown error");

        warn!(
            job_id = %job.id,
            webhook_id = %job.webhook_id,
            attempt = job.attempt,
            max_retries = job.max_retries,
            error = error_msg,
            "Webhook delivery failed"
        );

        if job.attempt >= job.max_retries && result.is_retryable() {
            // Exhausted retries — move to dead letter
            sqlx::query(
                r#"
                INSERT INTO webhook_deliveries (id, webhook_id, tenant_id, event_type, payload, status_code, response_time_ms, response_body, attempt, error, delivered_at)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, NOW())
                "#,
            )
            .bind(format!("dlv_{}", uuid::Uuid::new_v4()))
            .bind(&job.webhook_id)
            .bind(&job.tenant_id)
            .bind(&job.event_type)
            .bind(&job.payload)
            .bind(result.status_code.map(|c| c as i32))
            .bind(result.response_time_ms as i64)
            .bind(&result.response_body)
            .bind(job.attempt)
            .bind(error_msg)
            .execute(&self.db)
            .await?;

            sqlx::query("DELETE FROM webhook_queue WHERE id = $1")
                .bind(&job.id)
                .execute(&self.db)
                .await?;

            error!(
                job_id = %job.id,
                webhook_id = %job.webhook_id,
                "Webhook exhausted retries, moved to dead letter"
            );
        } else if result.is_retryable() {
            // Schedule retry with backoff
            let retry_delay = result
                .retry_after_ms
                .map(|ms| ms as i64)
                .unwrap_or_else(|| job.next_retry_delay_ms());

            sqlx::query(
                "UPDATE webhook_queue SET status = 'pending', attempt = attempt + 1, scheduled_at = NOW() + $1 * INTERVAL '1 millisecond', locked_until = NULL, last_error = $2, updated_at = NOW() WHERE id = $3"
            )
            .bind(retry_delay)
            .bind(error_msg)
            .bind(&job.id)
            .execute(&self.db)
            .await?;

            debug!(
                job_id = %job.id,
                retry_delay_ms = retry_delay,
                "Webhook scheduled for retry"
            );
        } else {
            // Non-retryable error — fail permanently
            sqlx::query("DELETE FROM webhook_queue WHERE id = $1")
                .bind(&job.id)
                .execute(&self.db)
                .await?;

            warn!(
                job_id = %job.id,
                "Webhook failed with non-retryable error"
            );
        }

        Ok(())
    }

    /// Flush pending successes in a batch transaction.
    async fn flush_pending_successes(&self) {
        let successes: Vec<PendingSuccess> = {
            let mut pending = self.pending_successes.lock().unwrap();
            std::mem::take(&mut *pending)
        };

        if successes.is_empty() {
            return;
        }

        let mut tx = match self.db.begin().await {
            Ok(tx) => tx,
            Err(e) => {
                error!(error = %e, "Failed to begin transaction for batch flush");
                // Put them back
                self.pending_successes.lock().unwrap().extend(successes);
                return;
            }
        };

        for success in &successes {
            let job = &success.job;
            let result = &success.result;

            // Insert delivery record
            if let Err(e) = sqlx::query(
                r#"
                INSERT INTO webhook_deliveries (id, webhook_id, tenant_id, event_type, payload, status_code, response_time_ms, response_body, attempt, delivered_at)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NOW())
                "#,
            )
            .bind(format!("dlv_{}", uuid::Uuid::new_v4()))
            .bind(&job.webhook_id)
            .bind(&job.tenant_id)
            .bind(&job.event_type)
            .bind(&job.payload)
            .bind(result.status_code.map(|c| c as i32))
            .bind(result.response_time_ms as i64)
            .bind(&result.response_body)
            .bind(job.attempt)
            .execute(&mut *tx)
            .await
            {
                error!(error = %e, job_id = %job.id, "Failed to insert delivery record");
            }

            // Delete from queue
            if let Err(e) = sqlx::query("DELETE FROM webhook_queue WHERE id = $1")
                .bind(&job.id)
                .execute(&mut *tx)
                .await
            {
                error!(error = %e, job_id = %job.id, "Failed to delete from queue");
            }
        }

        if let Err(e) = tx.commit().await {
            error!(error = %e, "Failed to commit batch flush transaction");
        }
    }
}
