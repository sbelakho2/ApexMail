//! Webhook processor implementation.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use chrono::Utc;
use deadpool_redis::Pool as RedisPool;
use futures::stream::{self, StreamExt};
use hmac::{Hmac, Mac};
use reqwest::Client;
use sha2::Sha256;
use sqlx::PgPool;
use tokio::sync::Notify;
use tokio::time::sleep;
use tracing::{debug, error, info, warn};

use super::ssrf::{ResolvedWebhookTarget, SsrfValidator};
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
    circuit_breakers: RwLock<HashMap<String, Arc<CircuitBreaker>>>,
    is_running: AtomicBool,
    active_jobs: AtomicUsize,
    tenant_active_jobs: RwLock<HashMap<String, usize>>,
    pending_successes: Mutex<Vec<PendingSuccess>>,
    shutdown_notify: Arc<Notify>,
}

impl WebhookProcessor {
    /// Create a new webhook processor.
    pub fn new(db: PgPool, redis: RedisPool, config: WebhookConfig) -> ProcessorResult<Self> {
        let client = Client::builder()
            .timeout(config.request_timeout)
            .user_agent("ApexMail-Webhook/1.0")
            // SSRF: never follow redirects. The target URL passed the SSRF
            // validator, but a 3xx could bounce the delivery to an arbitrary
            // host (e.g. cloud metadata). A 3xx is treated as a delivery
            // failure instead.
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| ProcessorError::Job(format!("Failed to create HTTP client: {}", e)))?;

        let ssrf_validator = SsrfValidator::new()?;

        Ok(Self {
            db,
            redis,
            config,
            client,
            ssrf_validator,
            circuit_breakers: RwLock::new(HashMap::new()),
            is_running: AtomicBool::new(false),
            active_jobs: AtomicUsize::new(0),
            tenant_active_jobs: RwLock::new(HashMap::new()),
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
            let available = self
                .config
                .base
                .concurrency
                .saturating_sub(self.active_jobs.load(Ordering::SeqCst));
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
                    stream::iter(jobs)
                        .for_each_concurrent(available, |job| async {
                            if let Err(error) = self.process_job(job).await {
                                error!(error = %error, "Failed to process webhook job");
                            }
                        })
                        .await;
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
                SET status = 'processing',
                    locked_until = NOW() + $2 * INTERVAL '1 second',
                    -- F10: mint the claim's owner token — every completion
                    -- write below is fenced on it, so a worker whose lease
                    -- expired cannot reschedule or delete a row the new
                    -- owner holds.
                    claim_token = gen_random_uuid()::text,
                    updated_at = NOW()
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
                          wq.payload, wq.attempt, wq.created_at, wq.claim_token
            )
            SELECT
                cj.id, cj.webhook_id as "webhookId", cj.tenant_id as "tenantId",
                cj.event_type as "eventType", cj.payload, cj.attempt, cj.created_at as "createdAt",
                cj.claim_token as "claimToken",
                w.url, w.secret, w.headers,
                (w.retry_policy->>'maxRetries')::int as "maxRetries",
                (w.retry_policy->>'retryDelay')::int as "retryDelay",
                (w.retry_policy->>'backoffMultiplier')::float as "backoffMultiplier"
            FROM claimed_jobs cj
            JOIN webhooks w ON w.id = cj.webhook_id
            "#,
        )
        .bind(limit as i64)
        .bind(self.config.base.visibility_timeout.as_secs() as i64)
        .fetch_all(&self.db)
        .await?;

        Ok(jobs)
    }

    /// Process a single webhook job.
    async fn process_job(&self, job: WebhookJob) -> ProcessorResult<()> {
        // Enforce per-tenant concurrency limit
        let tenant_count = {
            let tenant_jobs = self
                .tenant_active_jobs
                .read()
                .unwrap_or_else(|e| e.into_inner());
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
            // F10: fenced on this claim's owner token.
            let rescheduled = sqlx::query(
                "UPDATE webhook_queue SET status = 'pending', scheduled_at = NOW() + INTERVAL '5 seconds', locked_until = NULL, updated_at = NOW()
                 WHERE id = $1 AND (claim_token IS NOT DISTINCT FROM $2)"
            )
            .bind(&job.id)
            .bind(&job.claim_token)
            .execute(&self.db)
            .await?;
            if rescheduled.rows_affected() == 0 {
                warn!(job_id = %job.id, "per-tenant-limit reschedule fenced out — lease lost");
            }
            return Ok(());
        }

        // Track active job
        self.active_jobs.fetch_add(1, Ordering::SeqCst);
        {
            let mut tenant_jobs = self
                .tenant_active_jobs
                .write()
                .unwrap_or_else(|e| e.into_inner());
            *tenant_jobs.entry(job.tenant_id.clone()).or_insert(0) += 1;
        }

        let start = Instant::now();
        let result = self.process_job_inner(&job).await;

        // Decrement counters
        self.active_jobs.fetch_sub(1, Ordering::SeqCst);
        {
            let mut tenant_jobs = self
                .tenant_active_jobs
                .write()
                .unwrap_or_else(|e| e.into_inner());
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

    /// Retry budget Redis key for a webhook endpoint (RS-H-07).
    fn retry_budget_redis_key(&self, webhook_id: &str) -> String {
        format!("webhook:retry_budget:{}", webhook_id)
    }

    /// Check and consume the retry budget for a webhook endpoint (RS-H-07).
    ///
    /// Uses Redis INCR with EXPIRE to atomically track retry attempts within a
    /// configurable time window. When the budget is exhausted, returns `false`
    /// to signal that the job should be moved to the dead letter queue.
    async fn check_retry_budget(&self, webhook_id: &str) -> ProcessorResult<bool> {
        let budget_max = self.config.retry_budget_max;
        if budget_max == 0 {
            // Budget enforcement disabled
            return Ok(true);
        }

        let key = self.retry_budget_redis_key(webhook_id);
        let mut conn = self.redis.get().await?;

        // Atomically increment the retry counter
        let count: u32 = redis::cmd("INCR").arg(&key).query_async(&mut *conn).await?;

        // Set expiry on first increment
        if count == 1 {
            let _: Result<(), _> = redis::cmd("EXPIRE")
                .arg(&key)
                .arg(self.config.retry_budget_window_secs as i64)
                .query_async(&mut *conn)
                .await;
        }

        if count > budget_max {
            warn!(
                webhook_id = %webhook_id,
                retry_count = count,
                budget_max = budget_max,
                window_secs = self.config.retry_budget_window_secs,
                "Webhook retry budget exhausted, moving to dead letter queue"
            );
            Ok(false)
        } else {
            debug!(
                webhook_id = %webhook_id,
                retry_count = count,
                budget_max = budget_max,
                "Webhook retry budget consumed"
            );
            Ok(true)
        }
    }

    /// Derive an HMAC-based dedup key for the webhook job (O-16.2 fix).
    /// Instead of a deterministic `format!("webhook:dedup:{}:{}", job.id, job.attempt)`
    /// which is predictable, we use `HMAC-SHA256(job.id, dedup_hmac_key)` to make the
    /// Redis key unpredictable to an outside observer.
    fn dedup_key(&self, job: &WebhookJob) -> String {
        if let Some(ref hmac_key) = self.config.dedup_hmac_key {
            // HMAC-based key derivation — unpredictable without the key
            let mut mac =
                HmacSha256::new_from_slice(hmac_key.as_bytes()).expect("HMAC key should be valid");
            mac.update(job.id.as_bytes());
            let result = mac.finalize();
            let hmac_hex = hex::encode(result.into_bytes());
            format!("webhook:dedup:v2:{}", hmac_hex)
        } else {
            // Fallback when no HMAC key is configured (backward compatibility)
            format!("webhook:dedup:{}:{}", job.id, job.attempt)
        }
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
        // O-16.2: Uses HMAC-based key derivation when configured
        let dedup_key = self.dedup_key(job);
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
            // F10: fenced on this claim's owner token.
            let deleted = sqlx::query(
                "DELETE FROM webhook_queue WHERE id = $1 AND (claim_token IS NOT DISTINCT FROM $2)",
            )
            .bind(&job.id)
            .bind(&job.claim_token)
            .execute(&self.db)
            .await?;
            if deleted.rows_affected() == 0 {
                warn!(job_id = %job.id, "dedup cleanup fenced out — lease lost");
            }
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
            // F10: the column is error_message (webhook_queue has no
            // last_error — the old write failed every time); fenced on the
            // claim's owner token; attempt is intentionally NOT incremented
            // (a breaker-open deferral is not a delivery attempt).
            let rescheduled = sqlx::query(
                "UPDATE webhook_queue SET status = 'pending', scheduled_at = NOW() + $1 * INTERVAL '1 millisecond', locked_until = NULL, error_message = 'Circuit breaker open — waiting for recovery', updated_at = NOW()
                 WHERE id = $2 AND (claim_token IS NOT DISTINCT FROM $3)"
            )
            .bind(retry_delay)
            .bind(&job.id)
            .bind(&job.claim_token)
            .execute(&self.db)
            .await?;
            if rescheduled.rows_affected() == 0 {
                warn!(job_id = %job.id, "circuit-breaker reschedule fenced out — lease lost");
            }
            return Ok(());
        }

        // Validate URL for SSRF protection and pin DNS resolution used at send time
        let resolved_target = match self.ssrf_validator.validate_and_resolve_url(&job.url).await {
            Ok(target) => target,
            Err(e) => {
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
        };

        if resolved_target.resolved_ips.is_empty() {
            let result = WebhookDeliveryResult::failure(
                None,
                0,
                "SSRF protection: URL hostname resolved to no IP addresses".to_string(),
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

        // on crash between SET and HTTP delivery.
        let result = self
            .deliver_webhook(job, &serialized_payload, &resolved_target)
            .await;

        // Update circuit breaker
        if result.success {
            circuit_breaker.as_ref().record_success();
            // Set dedup key AFTER successful delivery (24h TTL)
            if let Err(error) = redis::cmd("SETEX")
                .arg(&dedup_key)
                .arg(86400)
                .arg("1")
                .query_async::<()>(&mut *conn)
                .await
            {
                warn!(webhook_id = %job.webhook_id, error = %error, "Failed to write webhook dedup key");
            }
            self.handle_success(job, result).await?;
        } else {
            circuit_breaker.as_ref().record_failure();
            self.handle_failure(job, result).await?;
        }

        Ok(())
    }

    /// Get or create circuit breaker for a webhook (O-16.9 fix).
    ///
    /// Previously, eviction evicted *any* closed breaker, destroying failure
    /// history for recently active webhooks. Now it evicts only breakers whose
    /// `last_used()` timestamp is older than `STALE_THRESHOLD`, preserving
    /// history for recently active webhooks.
    fn get_circuit_breaker(&self, webhook_id: &str) -> Arc<CircuitBreaker> {
        const MAX_CIRCUIT_BREAKERS: usize = 10_000;
        /// Only evict breakers that haven't been used in this duration (O-16.9).
        const STALE_THRESHOLD: std::time::Duration = std::time::Duration::from_secs(300); // 5 minutes
        let key = format!("webhook:{}", webhook_id);
        let mut cbs = self
            .circuit_breakers
            .write()
            .unwrap_or_else(|e| e.into_inner());

        if let Some(cb) = cbs.get(&key) {
            return Arc::clone(cb);
        }

        // Evict only STALE circuit breakers (O-16.9 fix), preserving failure
        // history for recently active webhooks.
        if cbs.len() >= MAX_CIRCUIT_BREAKERS {
            let now = std::time::Instant::now();
            let stale_keys: Vec<String> = cbs
                .iter()
                .filter(|(_, cb)| {
                    // Only evict breakers that haven't been used recently
                    cb.state() == crate::common::CircuitState::Closed
                        && now.duration_since(cb.last_used()) > STALE_THRESHOLD
                })
                .map(|(k, _)| k.clone())
                .take(cbs.len() / 4) // Evict up to 25% of stale closed entries
                .collect();
            for k in &stale_keys {
                cbs.remove(k);
            }
            if stale_keys.is_empty() {
                tracing::warn!(
                    size = cbs.len(),
                    "Circuit breaker map at capacity with no stale entries to evict"
                );
            }
        }

        let cb = Arc::new(CircuitBreaker::new(crate::common::CircuitBreakerConfig {
            failure_threshold: 5,
            open_duration: std::time::Duration::from_secs(30),
            success_threshold: 2,
            window_duration: std::time::Duration::from_secs(60),
        }));
        cbs.insert(key, Arc::clone(&cb));
        cb
    }

    /// Deliver webhook to endpoint.
    async fn deliver_webhook(
        &self,
        job: &WebhookJob,
        serialized_payload: &str,
        resolved_target: &ResolvedWebhookTarget,
    ) -> WebhookDeliveryResult {
        let timestamp = Utc::now().timestamp_millis();
        let delivery_id = format!("dlv_{}", uuid::Uuid::new_v4());

        // Sign payload — secret is zeroized inside sign_payload (O-16.3)
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

        let send_result = if resolved_target.host_is_ip {
            let mut request = self
                .client
                .post(&job.url)
                .body(serialized_payload.to_string());
            for (key, value) in &headers {
                request = request.header(key.as_str(), value.as_str());
            }
            request.send().await
        } else {
            let socket_addrs: Vec<SocketAddr> = resolved_target
                .resolved_ips
                .iter()
                .map(|ip| SocketAddr::new(*ip, resolved_target.port))
                .collect();

            if socket_addrs.is_empty() {
                return WebhookDeliveryResult::failure(
                    None,
                    start.elapsed().as_millis() as u64,
                    "No resolved IP addresses available for pinned webhook delivery".to_string(),
                    None,
                    None,
                );
            }

            let pinned_client = match Client::builder()
                .timeout(self.config.request_timeout)
                .user_agent("ApexMail-Webhook/1.0")
                .resolve_to_addrs(resolved_target.host.as_str(), &socket_addrs)
                // SSRF: no redirect following on the pinned client either —
                // a 3xx must not re-target the delivery to an unvalidated
                // host (see the shared client builder above).
                .redirect(reqwest::redirect::Policy::none())
                .build()
            {
                Ok(client) => client,
                Err(e) => {
                    return WebhookDeliveryResult::failure(
                        None,
                        start.elapsed().as_millis() as u64,
                        format!("Failed to build pinned webhook client: {}", e),
                        None,
                        None,
                    );
                }
            };

            let mut request = pinned_client
                .post(&job.url)
                .body(serialized_payload.to_string());
            for (key, value) in &headers {
                request = request.header(key.as_str(), value.as_str());
            }
            request.send().await
        };

        match send_result {
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
                                chrono::DateTime::parse_from_rfc2822(v).ok().map(|dt| {
                                    let delay =
                                        dt.timestamp_millis() - Utc::now().timestamp_millis();
                                    (delay.max(0) as u64).min(3_600_000)
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

                if (200..300).contains(&status) {
                    WebhookDeliveryResult::success(status, response_time, response_body)
                } else if (300..400).contains(&status) {
                    // Redirects are refused (Policy::none) — the destination
                    // has not passed SSRF validation, so a 3xx is a failure.
                    WebhookDeliveryResult::failure(
                        Some(status),
                        response_time,
                        format!(
                            "HTTP {} — redirect refused (webhook endpoint must not redirect)",
                            status
                        ),
                        response_body,
                        retry_after_ms,
                    )
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
                WebhookDeliveryResult::failure(None, response_time, e.to_string(), None, None)
            }
        }
    }

    /// Sign payload with HMAC-SHA256.
    /// The secret is wrapped in `Zeroizing<String>` for zeroization on drop (O-16.3).
    fn sign_payload(&self, secret: &str, timestamp: i64, payload: &str) -> String {
        let message = format!("{}.{}", timestamp, payload);
        let zeroized_secret = zeroize::Zeroizing::new(secret.to_string());
        let mut mac = match HmacSha256::new_from_slice(zeroized_secret.as_bytes()) {
            Ok(mac) => mac,
            Err(e) => {
                tracing::warn!(error = %e, "Failed to initialize webhook HMAC signer");
                return SIGNATURE_VERSION.to_string();
            }
        };
        mac.update(message.as_bytes());
        let result = mac.finalize();
        format!("{}{}", SIGNATURE_VERSION, hex::encode(result.into_bytes()))
    }

    /// Queue success for batch flush.
    async fn handle_success(
        &self,
        job: &WebhookJob,
        result: WebhookDeliveryResult,
    ) -> ProcessorResult<()> {
        info!(
            job_id = %job.id,
            webhook_id = %job.webhook_id,
            status_code = ?result.status_code,
            response_time_ms = result.response_time_ms,
            "Webhook delivered successfully"
        );

        self.pending_successes
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(PendingSuccess {
                job: job.clone(),
                result,
            });

        Ok(())
    }

    /// Handle failed delivery.
    async fn handle_failure(
        &self,
        job: &WebhookJob,
        result: WebhookDeliveryResult,
    ) -> ProcessorResult<()> {
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
            // Exhausted retries — move to dead letter (fenced on the claim).
            self.dead_letter(job, &result, error_msg).await?;
            error!(
                job_id = %job.id,
                webhook_id = %job.webhook_id,
                "Webhook exhausted retries, moved to dead letter"
            );
        } else if result.is_retryable() {
            // Check retry budget before scheduling (RS-H-07)
            match self.check_retry_budget(&job.webhook_id).await {
                Ok(true) => {
                    // Budget available — schedule retry with backoff
                    let retry_delay = result
                        .retry_after_ms
                        .map(|ms| ms as i64)
                        .unwrap_or_else(|| job.next_retry_delay_ms());

                    // F10: the column is error_message (webhook_queue has
                    // no last_error); fenced on the claim's owner token — a
                    // stale worker must not reschedule the new owner's row.
                    // Attempt counting and backoff scheduling are unchanged.
                    let rescheduled = sqlx::query(
                        "UPDATE webhook_queue SET status = 'pending', attempt = attempt + 1, scheduled_at = NOW() + $1 * INTERVAL '1 millisecond', locked_until = NULL, error_message = $2, updated_at = NOW()
                         WHERE id = $3 AND (claim_token IS NOT DISTINCT FROM $4)"
                    )
                    .bind(retry_delay)
                    .bind(error_msg)
                    .bind(&job.id)
                    .bind(&job.claim_token)
                    .execute(&self.db)
                    .await?;
                    if rescheduled.rows_affected() == 0 {
                        warn!(job_id = %job.id, "retry reschedule fenced out — lease lost");
                        return Ok(());
                    }

                    debug!(
                        job_id = %job.id,
                        retry_delay_ms = retry_delay,
                        "Webhook scheduled for retry"
                    );
                }
                Ok(false) => {
                    // Budget exhausted — move to dead letter queue immediately
                    // (fenced on the claim like every other completion write).
                    self.dead_letter(job, &result, error_msg).await?;

                    error!(
                        job_id = %job.id,
                        webhook_id = %job.webhook_id,
                        "Webhook retry budget exhausted, moved to dead letter"
                    );
                }
                Err(e) => {
                    // Redis unavailable — fall through to schedule retry
                    warn!(
                        job_id = %job.id,
                        webhook_id = %job.webhook_id,
                        error = %e,
                        "Retry budget check failed (Redis may be unavailable), scheduling retry"
                    );
                    let retry_delay = result
                        .retry_after_ms
                        .map(|ms| ms as i64)
                        .unwrap_or_else(|| job.next_retry_delay_ms());

                    // F10: error_message (not the nonexistent last_error)
                    // + claim-token fencing, same as the budget-available
                    // retry branch.
                    let rescheduled = sqlx::query(
                        "UPDATE webhook_queue SET status = 'pending', attempt = attempt + 1, scheduled_at = NOW() + $1 * INTERVAL '1 millisecond', locked_until = NULL, error_message = $2, updated_at = NOW()
                         WHERE id = $3 AND (claim_token IS NOT DISTINCT FROM $4)"
                    )
                    .bind(retry_delay)
                    .bind(error_msg)
                    .bind(&job.id)
                    .bind(&job.claim_token)
                    .execute(&self.db)
                    .await?;
                    if rescheduled.rows_affected() == 0 {
                        warn!(job_id = %job.id, "retry reschedule (budget-check failure) fenced out — lease lost");
                        return Ok(());
                    }

                    debug!(
                        job_id = %job.id,
                        retry_delay_ms = retry_delay,
                        "Webhook scheduled for retry (after budget check failure)"
                    );
                }
            }
        } else {
            // Non-retryable (4xx/redirect): record once and consume the row,
            // both fenced on the claim's owner token.
            self.dead_letter(job, &result, error_msg).await?;

            warn!(
                job_id = %job.id,
                "Webhook failed with non-retryable error, recorded in deliveries"
            );
        }

        Ok(())
    }

    /// Consume an owned queue row and record the terminal delivery in ONE
    /// transaction, fencing on the claim token FIRST (F10).
    ///
    /// The insert must not outlive the fenced delete: a worker whose lease
    /// expired would otherwise append a duplicate `webhook_deliveries` record
    /// for a job the new owner is still responsible for (the previous
    /// insert-then-delete order did exactly that and still reported success).
    async fn dead_letter(
        &self,
        job: &WebhookJob,
        result: &WebhookDeliveryResult,
        error_msg: &str,
    ) -> ProcessorResult<()> {
        let mut tx = self.db.begin().await?;

        let deleted = sqlx::query(
            "DELETE FROM webhook_queue WHERE id = $1 AND (claim_token IS NOT DISTINCT FROM $2)",
        )
        .bind(&job.id)
        .bind(&job.claim_token)
        .execute(&mut *tx)
        .await?;
        if deleted.rows_affected() == 0 {
            warn!(job_id = %job.id, "dead-letter fenced out — lease lost; nothing recorded");
            return Ok(());
        }

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
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;
        Ok(())
    }

    /// Flush pending successes in a batch transaction.
    async fn flush_pending_successes(&self) {
        let successes: Vec<PendingSuccess> = {
            let mut pending = self
                .pending_successes
                .lock()
                .unwrap_or_else(|e| e.into_inner());
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
                self.pending_successes
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .extend(successes);
                return;
            }
        };

        for success in &successes {
            let job = &success.job;
            let result = &success.result;

            // Delete from queue FIRST — F10: fenced on this claim's owner
            // token (a success flush can outlive its visibility lease). Only
            // the owner of the row may append the delivery record: inserting
            // before the fenced delete let a stale worker write a duplicate
            // `webhook_deliveries` row for a job the new owner still owns.
            let deleted = match sqlx::query(
                "DELETE FROM webhook_queue WHERE id = $1 AND (claim_token IS NOT DISTINCT FROM $2)",
            )
            .bind(&job.id)
            .bind(&job.claim_token)
            .execute(&mut *tx)
            .await
            {
                Ok(result) => result,
                Err(e) => {
                    error!(error = %e, job_id = %job.id, "Failed to delete from queue");
                    continue;
                }
            };

            if deleted.rows_affected() == 0 {
                warn!(job_id = %job.id, "success flush fenced out — lease lost; not recorded");
                continue;
            }

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
        }

        if let Err(e) = tx.commit().await {
            error!(error = %e, "Failed to commit batch flush transaction");
        }
    }
}

#[cfg(test)]
mod adversarial_tests {
    //! Adversarial, DB-backed tests for the webhook delivery pipeline.
    //!
    //! Every test drives a REAL entry point (`fetch_jobs`, `process_job`,
    //! `process_job_inner`, `deliver_webhook`, `handle_failure`,
    //! `flush_pending_successes`, `check_retry_budget`) against the canonical
    //! provisioned schema (`migrator::test_support::fresh_canonical_pool`) and
    //! a local HTTP stub. `TEST_DATABASE_URL` gates the suite exactly like the
    //! rest of the crate: unset soft-skips, configured-but-broken FAILS.

    use super::*;
    use serde_json::json;
    use sqlx::PgPool;
    use std::net::SocketAddr;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    const TEST_REDIS_FALLBACK: &str = "redis://127.0.0.1:6379";

    fn redis_url() -> String {
        std::env::var("TEST_REDIS_URL")
            .ok()
            .filter(|v| !v.trim().is_empty())
            .unwrap_or_else(|| TEST_REDIS_FALLBACK.to_string())
    }

    fn redis_pool() -> RedisPool {
        deadpool_redis::Config::from_url(redis_url())
            .create_pool(Some(deadpool_redis::Runtime::Tokio1))
            .expect("redis pool")
    }

    /// Unroutable Redis with short timeouts — exercises the fail-open branch
    /// of the retry-budget check without stalling the suite.
    fn dead_redis_pool() -> RedisPool {
        let mut cfg = deadpool_redis::Config::from_url("redis://127.0.0.1:1");
        let mut pool_cfg = deadpool_redis::PoolConfig::default();
        pool_cfg.timeouts.create = Some(Duration::from_millis(100));
        pool_cfg.timeouts.wait = Some(Duration::from_millis(100));
        pool_cfg.timeouts.recycle = Some(Duration::from_millis(100));
        cfg.pool = Some(pool_cfg);
        cfg.create_pool(Some(deadpool_redis::Runtime::Tokio1))
            .expect("lazy redis pool construction")
    }

    async fn test_pool(test_name: &str) -> Option<PgPool> {
        match migrator::test_support::fresh_canonical_pool(test_name, test_name).await {
            Ok(pool) => pool,
            Err(error) => panic!("{}", error.panic_message()),
        }
    }

    fn test_config() -> WebhookConfig {
        WebhookConfig {
            request_timeout: Duration::from_millis(300),
            base: crate::common::ProcessorConfig {
                poll_interval: Duration::from_millis(20),
                ..Default::default()
            },
            ..Default::default()
        }
    }

    fn processor(pool: PgPool, config: WebhookConfig) -> WebhookProcessor {
        WebhookProcessor::new(pool, redis_pool(), config).expect("processor construction")
    }

    fn unique_tenant() -> String {
        format!("wh-{}", &uuid::Uuid::new_v4().simple().to_string()[..20])
    }

    async fn insert_webhook(pool: &PgPool, tenant: &str, url: &str, enabled: bool) -> String {
        let id = format!("whk{}", &uuid::Uuid::new_v4().simple().to_string()[..20]);
        sqlx::query(
            "INSERT INTO webhooks (id, tenant_id, name, url, secret, events, enabled, headers, retry_policy)
             VALUES ($1, $2, 'adversarial', $3, 'sh-secret', '[\"*\"]'::jsonb, $4, '{\"X-Custom\":\"yes\"}'::jsonb,
                     '{\"maxRetries\":5,\"retryDelay\":1,\"backoffMultiplier\":2.0}'::jsonb)",
        )
        .bind(&id)
        .bind(tenant)
        .bind(url)
        .bind(enabled)
        .execute(pool)
        .await
        .expect("insert webhook");
        id
    }

    #[derive(Clone, Copy, Default)]
    struct ClaimOffsets {
        scheduled_secs: Option<i64>,
        locked_secs: Option<i64>,
    }

    async fn insert_queue_row(
        pool: &PgPool,
        webhook_id: &str,
        tenant: &str,
        payload: serde_json::Value,
        attempt: i32,
        claim_token: &str,
        offsets: ClaimOffsets,
    ) -> String {
        let id = format!("whq-{}", uuid::Uuid::new_v4());
        sqlx::query(
            "INSERT INTO webhook_queue
                 (id, webhook_id, tenant_id, event_type, payload, status, attempt,
                  scheduled_at, locked_until, claim_token, created_at, updated_at)
             VALUES ($1, $2, $3, 'email.delivered', $4, 'pending', $5,
                     CASE WHEN $6::bigint IS NULL THEN NULL ELSE NOW() + ($6 * INTERVAL '1 second') END,
                     CASE WHEN $7::bigint IS NULL THEN NULL ELSE NOW() + ($7 * INTERVAL '1 second') END,
                     $8, NOW(), NOW())",
        )
        .bind(&id)
        .bind(webhook_id)
        .bind(tenant)
        .bind(payload)
        .bind(attempt)
        .bind(offsets.scheduled_secs)
        .bind(offsets.locked_secs)
        .bind(claim_token)
        .execute(pool)
        .await
        .expect("insert queue row");
        id
    }

    fn job_for(webhook_id: &str, tenant: &str, url: &str) -> WebhookJob {
        WebhookJob {
            id: format!("whq-{}", uuid::Uuid::new_v4()),
            webhook_id: webhook_id.to_string(),
            tenant_id: tenant.to_string(),
            event_type: "email.delivered".to_string(),
            payload: json!({"hello": "world"}),
            url: url.to_string(),
            secret: "sh-secret".to_string(),
            headers: Some(json!({"X-Custom": "yes"})),
            attempt: 1,
            max_retries: 5,
            retry_delay: 1,
            backoff_multiplier: 2.0,
            created_at: Utc::now(),
            claim_token: Some("claim-token-1".to_string()),
        }
    }

    async fn queue_state(pool: &PgPool, id: &str) -> Option<(String, i32, Option<String>)> {
        sqlx::query_as::<_, (String, i32, Option<String>)>(
            "SELECT status, attempt, error_message FROM webhook_queue WHERE id = $1",
        )
        .bind(id)
        .fetch_optional(pool)
        .await
        .expect("queue state")
    }

    async fn delivery_rows(pool: &PgPool, webhook_id: &str) -> i64 {
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM webhook_deliveries WHERE webhook_id = $1",
        )
        .bind(webhook_id)
        .fetch_one(pool)
        .await
        .expect("delivery count")
    }

    // ── local HTTP stub (no network) ────────────────────────────────────────

    #[derive(Clone)]
    struct StubResponse {
        status: u16,
        headers: Vec<(String, String)>,
        body: Vec<u8>,
    }

    impl StubResponse {
        fn new(status: u16, body: &str) -> Self {
            Self {
                status,
                headers: Vec::new(),
                body: body.as_bytes().to_vec(),
            }
        }

        fn with_header(mut self, key: &str, value: &str) -> Self {
            self.headers.push((key.to_string(), value.to_string()));
            self
        }
    }

    #[derive(Clone, Debug)]
    struct RecordedRequest {
        head: String,
        body: Vec<u8>,
    }

    struct Stub {
        addr: SocketAddr,
        requests: Arc<Mutex<Vec<RecordedRequest>>>,
    }

    fn spawn_stub(responses: Vec<StubResponse>) -> Stub {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind stub");
        let addr = listener.local_addr().expect("stub addr");
        listener.set_nonblocking(true).expect("nonblocking");
        let listener = tokio::net::TcpListener::from_std(listener).expect("tokio listener");
        let requests: Arc<Mutex<Vec<RecordedRequest>>> = Arc::new(Mutex::new(Vec::new()));
        let recorded = Arc::clone(&requests);
        tokio::spawn(async move {
            let mut idx = 0usize;
            loop {
                let Ok((mut socket, _)) = listener.accept().await else {
                    break;
                };
                let response = responses
                    .get(idx)
                    .or_else(|| responses.last())
                    .cloned()
                    .unwrap_or_else(|| StubResponse::new(200, ""));
                idx += 1;
                let recorded = Arc::clone(&recorded);
                tokio::spawn(async move {
                    let mut buf = Vec::new();
                    let mut tmp = [0u8; 8192];
                    let head_end = loop {
                        let n = match socket.read(&mut tmp).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => n,
                        };
                        buf.extend_from_slice(&tmp[..n]);
                        if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                            break pos + 4;
                        }
                        if buf.len() > 1 << 20 {
                            return;
                        }
                    };
                    let head = String::from_utf8_lossy(&buf[..head_end]).to_string();
                    let content_length = head
                        .lines()
                        .find_map(|line| {
                            let (key, value) = line.split_once(':')?;
                            if key.eq_ignore_ascii_case("content-length") {
                                value.trim().parse::<usize>().ok()
                            } else {
                                None
                            }
                        })
                        .unwrap_or(0);
                    while buf.len() < head_end + content_length {
                        let n = match socket.read(&mut tmp).await {
                            Ok(0) | Err(_) => break,
                            Ok(n) => n,
                        };
                        buf.extend_from_slice(&tmp[..n]);
                    }
                    let body = buf[head_end..(head_end + content_length).min(buf.len())].to_vec();
                    recorded
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .push(RecordedRequest { head, body });
                    let reason = match response.status {
                        200 => "OK",
                        302 => "Found",
                        404 => "Not Found",
                        429 => "Too Many Requests",
                        500 => "Internal Server Error",
                        503 => "Service Unavailable",
                        _ => "Status",
                    };
                    let mut out = format!("HTTP/1.1 {} {}\r\n", response.status, reason);
                    for (key, value) in &response.headers {
                        out.push_str(&format!("{}: {}\r\n", key, value));
                    }
                    out.push_str(&format!(
                        "Content-Length: {}\r\nConnection: close\r\n\r\n",
                        response.body.len()
                    ));
                    let _ = socket.write_all(out.as_bytes()).await;
                    let _ = socket.write_all(&response.body).await;
                    let _ = socket.flush().await;
                });
            }
        });
        Stub { addr, requests }
    }

    fn ip_target(stub: &Stub) -> ResolvedWebhookTarget {
        ResolvedWebhookTarget {
            host: "127.0.0.1".to_string(),
            port: stub.addr.port(),
            resolved_ips: vec![std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)],
            host_is_ip: true,
            resolved_at: std::time::Instant::now(),
        }
    }

    fn pinned_target(stub: &Stub, host: &str) -> ResolvedWebhookTarget {
        ResolvedWebhookTarget {
            host: host.to_string(),
            port: stub.addr.port(),
            resolved_ips: vec![std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)],
            host_is_ip: false,
            resolved_at: std::time::Instant::now(),
        }
    }

    // ── signature / dedup key derivation ───────────────────────────────────

    #[tokio::test]
    async fn sign_payload_is_hmac_sha256_over_timestamp_dot_payload() {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://localhost/unused")
            .unwrap();
        let proc = WebhookProcessor::new(pool, redis_pool(), test_config()).unwrap();

        let signature = proc.sign_payload("topsecret", 1_700_000_000_000, "{\"a\":1}");
        assert!(
            signature.starts_with(SIGNATURE_VERSION),
            "signature must carry the version prefix"
        );

        let mut mac = HmacSha256::new_from_slice(b"topsecret").unwrap();
        mac.update(b"1700000000000.{\"a\":1}");
        let expected = format!(
            "{}{}",
            SIGNATURE_VERSION,
            hex::encode(mac.finalize().into_bytes())
        );
        assert_eq!(signature, expected, "signature must bind timestamp+payload");

        // A different timestamp or payload must not verify.
        assert_ne!(signature, proc.sign_payload("topsecret", 1, "{\"a\":1}"));
        assert_ne!(
            signature,
            proc.sign_payload("topsecret", 1_700_000_000_000, "{}")
        );
    }

    #[tokio::test]
    async fn dedup_key_is_unpredictable_with_hmac_and_legacy_without() {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://localhost/unused")
            .unwrap();

        let with_key = WebhookProcessor::new(
            pool.clone(),
            redis_pool(),
            WebhookConfig {
                dedup_hmac_key: Some(zeroize::Zeroizing::new("dedup-master-key".to_string())),
                ..test_config()
            },
        )
        .unwrap();
        let job = job_for("whk1", "t1", "https://example.test/hook");
        let key = with_key.dedup_key(&job);
        assert!(key.starts_with("webhook:dedup:v2:"), "got {key}");
        assert!(
            !key.contains(&job.id),
            "HMAC dedup key must not leak the raw job id"
        );
        // Same job id, same key (retry-safe)…
        assert_eq!(key, with_key.dedup_key(&job));
        // …but a different job id differs.
        let mut other = job.clone();
        other.id = "whq-other".to_string();
        assert_ne!(key, with_key.dedup_key(&other));

        let legacy = WebhookProcessor::new(pool, redis_pool(), test_config()).unwrap();
        assert_eq!(
            legacy.dedup_key(&job),
            format!("webhook:dedup:{}:{}", job.id, job.attempt)
        );
        assert_eq!(
            legacy.retry_budget_redis_key("whk1"),
            "webhook:retry_budget:whk1"
        );
    }

    // ── delivery (local HTTP stub) ─────────────────────────────────────────

    #[tokio::test]
    async fn deliver_webhook_signs_headers_and_truncates_oversized_response() {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://localhost/unused")
            .unwrap();
        let proc = processor(pool, test_config());
        let stub = spawn_stub(vec![StubResponse::new(200, &"r".repeat(4096))]);
        let job = job_for(
            "whk1",
            "t1",
            &format!("http://127.0.0.1:{}/hook", stub.addr.port()),
        );
        let payload = "{\"k\":\"v\"}";

        let result = proc.deliver_webhook(&job, payload, &ip_target(&stub)).await;
        assert!(result.success, "2xx must be a success: {:?}", result.error);
        assert_eq!(result.status_code, Some(200));
        let body = result.response_body.expect("response body recorded");
        assert!(
            body.len() <= MAX_RESPONSE_BYTES + 3,
            "response body must be capped ({} bytes)",
            body.len()
        );
        assert!(
            body.ends_with("..."),
            "truncated body must be marked: {body:?}"
        );

        let requests = stub
            .requests
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        assert_eq!(requests.len(), 1);
        let req = &requests[0];
        assert_eq!(
            req.body,
            payload.as_bytes(),
            "body must be the payload verbatim"
        );
        assert!(req.head.contains("content-type: application/json"));
        assert!(
            req.head.contains("x-custom: yes"),
            "custom header must be sent"
        );
        assert!(req
            .head
            .contains(&format!("x-apexmail-webhook-id: {}", job.webhook_id)));
        assert!(req
            .head
            .contains(&format!("x-apexmail-event: {}", job.event_type)));
        assert!(req.head.contains("x-apexmail-delivery-id: dlv_"));
        let timestamp = req
            .head
            .lines()
            .find_map(|line| {
                let (k, v) = line.split_once(':')?;
                if k.eq_ignore_ascii_case("x-apexmail-timestamp") {
                    v.trim().parse::<i64>().ok()
                } else {
                    None
                }
            })
            .expect("timestamp header");
        let signature = req
            .head
            .lines()
            .find_map(|line| {
                let (k, v) = line.split_once(':')?;
                if k.eq_ignore_ascii_case("x-apexmail-signature") {
                    Some(v.trim().to_string())
                } else {
                    None
                }
            })
            .expect("signature header");
        let mut mac = HmacSha256::new_from_slice(job.secret.as_bytes()).unwrap();
        mac.update(format!("{}.{}", timestamp, payload).as_bytes());
        assert_eq!(
            signature,
            format!(
                "{}{}",
                SIGNATURE_VERSION,
                hex::encode(mac.finalize().into_bytes())
            ),
            "delivery signature must bind the actual timestamp and body"
        );
    }

    #[tokio::test]
    async fn deliver_webhook_pins_dns_for_hostname_targets() {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://localhost/unused")
            .unwrap();
        let proc = processor(pool, test_config());
        let stub = spawn_stub(vec![StubResponse::new(200, "ok")]);
        let job = job_for(
            "whk1",
            "t1",
            &format!("http://pinned.webhook.test:{}/hook", stub.addr.port()),
        );
        // host_is_ip=false forces the pinned-client branch; the resolution
        // comes from the (validated) resolved_ips, never a fresh DNS lookup.
        let target = pinned_target(&stub, "pinned.webhook.test");
        let result = proc.deliver_webhook(&job, "{}", &target).await;
        assert!(
            result.success,
            "pinned delivery must succeed: {:?}",
            result.error
        );
        let requests = stub
            .requests
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        assert_eq!(requests.len(), 1);
        assert!(
            requests[0].head.contains("host: pinned.webhook.test"),
            "pinned client must keep the original Host header: {}",
            requests[0].head
        );
    }

    #[tokio::test]
    async fn deliver_webhook_refuses_redirects_and_classifies_status_matrix() {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://localhost/unused")
            .unwrap();
        let proc = processor(pool, test_config());
        let stub = spawn_stub(vec![
            StubResponse::new(302, "").with_header("Location", "http://169.254.169.254/"),
            StubResponse::new(404, "missing"),
            StubResponse::new(503, "unavailable").with_header("Retry-After", "5"),
            StubResponse::new(429, "slow down").with_header(
                "Retry-After",
                &(Utc::now() + chrono::Duration::seconds(60)).to_rfc2822(),
            ),
            StubResponse::new(429, "no header"),
            StubResponse::new(500, "boom"),
        ]);
        let job = job_for(
            "whk1",
            "t1",
            &format!("http://127.0.0.1:{}/hook", stub.addr.port()),
        );

        let redirect = proc.deliver_webhook(&job, "{}", &ip_target(&stub)).await;
        assert!(!redirect.success);
        assert_eq!(redirect.status_code, Some(302));
        assert!(redirect
            .error
            .as_ref()
            .unwrap()
            .contains("redirect refused"));
        assert!(
            !redirect.is_retryable(),
            "a redirected delivery must not retry"
        );

        let not_found = proc.deliver_webhook(&job, "{}", &ip_target(&stub)).await;
        assert!(!not_found.success);
        assert!(!not_found.is_retryable(), "404 is terminal");
        assert_eq!(not_found.response_body.as_deref(), Some("missing"));

        let unavailable = proc.deliver_webhook(&job, "{}", &ip_target(&stub)).await;
        assert!(unavailable.is_retryable());
        assert_eq!(
            unavailable.retry_after_ms,
            Some(5_000),
            "Retry-After seconds must be honoured and capped"
        );

        let throttled = proc.deliver_webhook(&job, "{}", &ip_target(&stub)).await;
        assert!(throttled.is_retryable());
        let ms = throttled.retry_after_ms.expect("HTTP-date parsed");
        assert!(
            (55_000..=61_000).contains(&ms),
            "Retry-After HTTP-date must convert to ~60s, got {ms}"
        );

        let missing_header = proc.deliver_webhook(&job, "{}", &ip_target(&stub)).await;
        assert_eq!(missing_header.retry_after_ms, None);

        let server_error = proc.deliver_webhook(&job, "{}", &ip_target(&stub)).await;
        assert!(server_error.is_retryable(), "5xx is retryable");
    }

    #[tokio::test]
    async fn deliver_webhook_network_failure_is_retryable_without_status() {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://localhost/unused")
            .unwrap();
        let proc = processor(pool, test_config());
        // Bind and immediately drop: the port is (almost certainly) closed.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let target = ResolvedWebhookTarget {
            host: "127.0.0.1".to_string(),
            port,
            resolved_ips: vec![std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)],
            host_is_ip: true,
            resolved_at: std::time::Instant::now(),
        };
        let job = job_for("whk1", "t1", "http://ignored.test/hook");
        let result = proc.deliver_webhook(&job, "{}", &target).await;
        assert!(!result.success);
        assert_eq!(result.status_code, None);
        assert!(result.is_retryable(), "connection failures must retry");
        assert!(result.error.is_some());
    }

    // ── queue claiming / fencing ───────────────────────────────────────────

    #[tokio::test]
    async fn fetch_jobs_claims_due_rows_and_skips_deferred_disabled_and_done() {
        let Some(pool) = test_pool("wh_fetch_jobs").await else {
            return;
        };
        let proc = processor(pool.clone(), test_config());
        let tenant = unique_tenant();
        let enabled = insert_webhook(&pool, &tenant, "https://example.test/hook", true).await;
        let disabled = insert_webhook(&pool, &tenant, "https://example.test/off", false).await;

        let due = insert_queue_row(
            &pool,
            &enabled,
            &tenant,
            json!({"e": "due"}),
            1,
            "tok-due",
            ClaimOffsets {
                scheduled_secs: None,
                locked_secs: None,
            },
        )
        .await;
        let _future = insert_queue_row(
            &pool,
            &enabled,
            &tenant,
            json!({"e": "future"}),
            1,
            "tok-future",
            ClaimOffsets {
                scheduled_secs: Some(600),
                locked_secs: None,
            },
        )
        .await;
        let _locked = insert_queue_row(
            &pool,
            &enabled,
            &tenant,
            json!({"e": "locked"}),
            1,
            "tok-locked",
            ClaimOffsets {
                scheduled_secs: None,
                locked_secs: Some(600),
            },
        )
        .await;
        let _disabled_row = insert_queue_row(
            &pool,
            &disabled,
            &tenant,
            json!({"e": "disabled"}),
            1,
            "tok-disabled",
            ClaimOffsets {
                scheduled_secs: None,
                locked_secs: None,
            },
        )
        .await;
        let done = insert_queue_row(
            &pool,
            &enabled,
            &tenant,
            json!({"e": "done"}),
            1,
            "tok-done",
            ClaimOffsets {
                scheduled_secs: None,
                locked_secs: None,
            },
        )
        .await;
        sqlx::query("UPDATE webhook_queue SET status = 'done' WHERE id = $1")
            .bind(&done)
            .execute(&pool)
            .await
            .unwrap();

        let jobs = proc.fetch_jobs(50).await.expect("fetch jobs");
        assert_eq!(
            jobs.len(),
            1,
            "only the enabled, due, unlocked row is claimable"
        );
        let job = &jobs[0];
        assert_eq!(job.id, due);
        assert_eq!(job.max_retries, 5);
        assert_eq!(job.retry_delay, 1);
        assert!((job.backoff_multiplier - 2.0).abs() < f64::EPSILON);
        assert!(
            job.claim_token.is_some(),
            "the claim must mint an owner token"
        );

        let (status, _): (String, Option<String>) =
            sqlx::query_as("SELECT status, claim_token FROM webhook_queue WHERE id = $1")
                .bind(&due)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(status, "processing");
    }

    #[tokio::test]
    async fn tenant_concurrency_limit_reschedules_instead_of_dropping() {
        let Some(pool) = test_pool("wh_tenant_limit").await else {
            return;
        };
        let proc = processor(pool.clone(), test_config());
        let tenant = unique_tenant();
        let webhook_id = insert_webhook(&pool, &tenant, "https://example.test/hook", true).await;
        let row = insert_queue_row(
            &pool,
            &webhook_id,
            &tenant,
            json!({}),
            1,
            "tok",
            ClaimOffsets {
                scheduled_secs: None,
                locked_secs: None,
            },
        )
        .await;
        let job = job_for(&webhook_id, &tenant, "https://example.test/hook");

        {
            let mut active = proc.tenant_active_jobs.write().unwrap();
            active.insert(tenant.clone(), MAX_CONCURRENT_PER_TENANT);
        }

        proc.process_job(job).await.expect("process job");

        let (status, error): (String, Option<String>) =
            sqlx::query_as("SELECT status, error_message FROM webhook_queue WHERE id = $1")
                .bind(&row)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(status, "pending", "an over-limit job must be rescheduled");
        assert_eq!(proc.active_jobs.load(Ordering::SeqCst), 0);
        // A limit deferral is not a delivery failure: no error recorded.
        assert!(error.is_none());
        let deliveries = delivery_rows(&pool, &webhook_id).await;
        assert_eq!(deliveries, 0);

        // A stale claim token must be fenced out of the reschedule.
        sqlx::query("UPDATE webhook_queue SET status = 'pending' WHERE id = $1")
            .bind(&row)
            .execute(&pool)
            .await
            .unwrap();
        let mut stale = job_for(&webhook_id, &tenant, "https://example.test/hook");
        stale.claim_token = Some("someone-elses-token".to_string());
        proc.process_job(stale).await.expect("stale process job");
        let (status, _): (String, Option<String>) =
            sqlx::query_as("SELECT status, error_message FROM webhook_queue WHERE id = $1")
                .bind(&row)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(
            status, "pending",
            "the fenced-out write must not touch the row"
        );
    }

    // ── failure handling / retry budget ────────────────────────────────────

    #[tokio::test]
    async fn retryable_failure_schedules_backoff_and_stale_token_cannot_reschedule() {
        let Some(pool) = test_pool("wh_retry_backoff").await else {
            return;
        };
        let proc = processor(pool.clone(), test_config());
        let tenant = unique_tenant();
        let webhook_id = insert_webhook(&pool, &tenant, "https://example.test/hook", true).await;
        let row = insert_queue_row(
            &pool,
            &webhook_id,
            &tenant,
            json!({}),
            1,
            "claim-token-1",
            ClaimOffsets {
                scheduled_secs: None,
                locked_secs: None,
            },
        )
        .await;

        let job = WebhookJob {
            id: row.clone(),
            claim_token: Some("claim-token-1".to_string()),
            ..job_for(&webhook_id, &tenant, "https://example.test/hook")
        };
        let result =
            WebhookDeliveryResult::failure(None, 5, "connect timeout".to_string(), None, None);
        proc.handle_failure(&job, result)
            .await
            .expect("handle failure");

        let (status, attempt, error): (String, i32, Option<String>) = sqlx::query_as(
            "SELECT status, attempt, error_message FROM webhook_queue WHERE id = $1",
        )
        .bind(&row)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(status, "pending");
        assert_eq!(attempt, 2, "a retry counts one delivery attempt");
        assert_eq!(error.as_deref(), Some("connect timeout"));

        // The OLD owner must not be able to reschedule the row again.
        let stale = WebhookJob {
            claim_token: Some("claim-token-0".to_string()),
            ..job.clone()
        };
        proc.handle_failure(
            &stale,
            WebhookDeliveryResult::failure(None, 5, "late".to_string(), None, None),
        )
        .await
        .expect("fenced failure");
        let (_, attempt_after, error_after): (String, i32, Option<String>) = sqlx::query_as(
            "SELECT status, attempt, error_message FROM webhook_queue WHERE id = $1",
        )
        .bind(&row)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(attempt_after, 2, "stale lease must not increment attempt");
        assert_eq!(error_after.as_deref(), Some("connect timeout"));
    }

    #[tokio::test]
    async fn exhausted_and_non_retryable_failures_dead_letter_exactly_once() {
        let Some(pool) = test_pool("wh_dead_letter").await else {
            return;
        };
        let proc = processor(pool.clone(), test_config());
        let tenant = unique_tenant();

        // Exhausted retries on a retryable error → dead letter.
        let exhausted_webhook =
            insert_webhook(&pool, &tenant, "https://example.test/a", true).await;
        let row_a = insert_queue_row(
            &pool,
            &exhausted_webhook,
            &tenant,
            json!({"a": 1}),
            5,
            "tok-a",
            ClaimOffsets {
                scheduled_secs: None,
                locked_secs: None,
            },
        )
        .await;
        let job_a = WebhookJob {
            attempt: 5,
            max_retries: 5,
            id: row_a.clone(),
            claim_token: Some("tok-a".to_string()),
            ..job_for(&exhausted_webhook, &tenant, "http://example.test/a")
        };
        proc.handle_failure(
            &job_a,
            WebhookDeliveryResult::failure(None, 5, "down".to_string(), None, None),
        )
        .await
        .unwrap();
        assert_eq!(queue_state(&pool, &row_a).await, None, "queue row consumed");
        let (status_code, error, attempt): (Option<i32>, Option<String>, i32) = sqlx::query_as(
            "SELECT status_code, error, attempt FROM webhook_deliveries WHERE webhook_id = $1",
        )
        .bind(&exhausted_webhook)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(status_code, None);
        assert_eq!(error.as_deref(), Some("down"));
        assert_eq!(attempt, 5);

        // A stale token must NOT dead-letter the new owner's row.
        let fenced_webhook = insert_webhook(&pool, &tenant, "https://example.test/b", true).await;
        let row_b = insert_queue_row(
            &pool,
            &fenced_webhook,
            &tenant,
            json!({}),
            5,
            "tok-b",
            ClaimOffsets {
                scheduled_secs: None,
                locked_secs: None,
            },
        )
        .await;
        let mut stale = job_for(&fenced_webhook, &tenant, "http://example.test/b");
        stale.id = row_b.clone();
        stale.attempt = 5;
        stale.max_retries = 5;
        stale.claim_token = Some("already-expired".to_string());
        proc.handle_failure(
            &stale,
            WebhookDeliveryResult::failure(None, 5, "stale".to_string(), None, None),
        )
        .await
        .unwrap();
        assert!(
            queue_state(&pool, &row_b).await.is_some(),
            "fenced row survives"
        );
        assert_eq!(delivery_rows(&pool, &fenced_webhook).await, 0);

        // Non-retryable (4xx) → immediate dead letter, no retry.
        let terminal_webhook = insert_webhook(&pool, &tenant, "https://example.test/c", true).await;
        let row_c = insert_queue_row(
            &pool,
            &terminal_webhook,
            &tenant,
            json!({}),
            1,
            "tok-c",
            ClaimOffsets {
                scheduled_secs: None,
                locked_secs: None,
            },
        )
        .await;
        let job_c = WebhookJob {
            id: row_c.clone(),
            claim_token: Some("tok-c".to_string()),
            ..job_for(&terminal_webhook, &tenant, "http://example.test/c")
        };
        proc.handle_failure(
            &job_c,
            WebhookDeliveryResult::failure(
                Some(404),
                7,
                "HTTP 404".to_string(),
                Some("nope".to_string()),
                None,
            ),
        )
        .await
        .unwrap();
        assert_eq!(queue_state(&pool, &row_c).await, None);
        let (code, body): (Option<i32>, Option<String>) = sqlx::query_as(
            "SELECT status_code, response_body FROM webhook_deliveries WHERE webhook_id = $1",
        )
        .bind(&terminal_webhook)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(code, Some(404));
        assert_eq!(body.as_deref(), Some("nope"));
    }

    #[tokio::test]
    async fn retry_budget_exhaustion_dead_letters_and_disabled_budget_always_allows() {
        let Some(pool) = test_pool("wh_retry_budget").await else {
            return;
        };
        let tenant = unique_tenant();
        let webhook_id = insert_webhook(&pool, &tenant, "https://example.test/hook", true).await;

        // Budget of 2: the first two checks pass, the third trips.
        let proc = processor(
            pool.clone(),
            WebhookConfig {
                retry_budget_max: 2,
                retry_budget_window_secs: 60,
                ..test_config()
            },
        );
        let key = proc.retry_budget_redis_key(&webhook_id);
        let mut conn = proc.redis.get().await.unwrap();
        let _: () = redis::cmd("DEL")
            .arg(&key)
            .query_async(&mut *conn)
            .await
            .unwrap();
        drop(conn);

        assert!(proc.check_retry_budget(&webhook_id).await.unwrap());
        assert!(proc.check_retry_budget(&webhook_id).await.unwrap());
        assert!(
            !proc.check_retry_budget(&webhook_id).await.unwrap(),
            "the third retry exceeds a budget of 2"
        );

        // With the budget exhausted, a retryable failure dead-letters NOW.
        let row = insert_queue_row(
            &pool,
            &webhook_id,
            &tenant,
            json!({}),
            1,
            "tok",
            ClaimOffsets {
                scheduled_secs: None,
                locked_secs: None,
            },
        )
        .await;
        let job = WebhookJob {
            id: row.clone(),
            claim_token: Some("tok".to_string()),
            ..job_for(&webhook_id, &tenant, "http://example.test/hook")
        };
        proc.handle_failure(
            &job,
            WebhookDeliveryResult::failure(Some(500), 3, "HTTP 500".to_string(), None, None),
        )
        .await
        .unwrap();
        assert_eq!(
            queue_state(&pool, &row).await,
            None,
            "budget exhaustion dead-letters"
        );
        assert_eq!(delivery_rows(&pool, &webhook_id).await, 1);

        // Budget disabled (0) → always allowed, and Redis is never touched.
        let disabled = processor(
            pool.clone(),
            WebhookConfig {
                retry_budget_max: 0,
                ..test_config()
            },
        );
        assert!(disabled.check_retry_budget(&webhook_id).await.unwrap());

        // Redis unavailable → the check errors (caller must fail open to retry).
        assert!(dead_redis_pool_check().await);
    }

    async fn dead_redis_pool_check() -> bool {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://localhost/unused")
            .unwrap();
        let proc = WebhookProcessor::new(pool, dead_redis_pool(), test_config()).unwrap();
        proc.check_retry_budget("whk-dead").await.is_err()
    }

    #[tokio::test]
    async fn budget_check_failure_still_schedules_a_retry() {
        let Some(pool) = test_pool("wh_budget_failure").await else {
            return;
        };
        let tenant = unique_tenant();
        let webhook_id = insert_webhook(&pool, &tenant, "https://example.test/hook", true).await;
        let row = insert_queue_row(
            &pool,
            &webhook_id,
            &tenant,
            json!({}),
            3,
            "tok",
            ClaimOffsets {
                scheduled_secs: None,
                locked_secs: None,
            },
        )
        .await;
        // Unroutable Redis while the budget is ENABLED: the failure branch
        // must fail open (retry), never silently drop the delivery.
        let proc = WebhookProcessor::new(pool.clone(), dead_redis_pool(), test_config()).unwrap();
        let job = WebhookJob {
            id: row.clone(),
            claim_token: Some("tok".to_string()),
            ..job_for(&webhook_id, &tenant, "http://example.test/hook")
        };
        proc.handle_failure(
            &job,
            WebhookDeliveryResult::failure(None, 1, "network".to_string(), None, None),
        )
        .await
        .unwrap();
        let (status, attempt): (String, i32) =
            sqlx::query_as("SELECT status, attempt FROM webhook_queue WHERE id = $1")
                .bind(&row)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(status, "pending");
        assert_eq!(attempt, 4);
    }

    // ── process_job_inner paths ────────────────────────────────────────────

    #[tokio::test]
    async fn dedup_hit_deletes_the_claimed_row_without_delivering() {
        let Some(pool) = test_pool("wh_dedup").await else {
            return;
        };
        let proc = processor(pool.clone(), test_config());
        let tenant = unique_tenant();
        let webhook_id = insert_webhook(&pool, &tenant, "https://example.test/hook", true).await;
        let row = insert_queue_row(
            &pool,
            &webhook_id,
            &tenant,
            json!({}),
            1,
            "tok",
            ClaimOffsets {
                scheduled_secs: None,
                locked_secs: None,
            },
        )
        .await;
        let job = WebhookJob {
            id: row.clone(),
            claim_token: Some("tok".to_string()),
            ..job_for(&webhook_id, &tenant, "https://example.test/hook")
        };

        let dedup_key = proc.dedup_key(&job);
        {
            let mut conn = proc.redis.get().await.unwrap();
            let _: () = redis::cmd("SET")
                .arg(&dedup_key)
                .arg("1")
                .query_async(&mut *conn)
                .await
                .unwrap();
        }

        proc.process_job_inner(&job).await.expect("dedup path");
        assert_eq!(
            queue_state(&pool, &row).await,
            None,
            "deduped job is cleaned up"
        );
        assert_eq!(delivery_rows(&pool, &webhook_id).await, 0);

        // The same dedup hit with a stale token must NOT delete the row.
        let row2 = insert_queue_row(
            &pool,
            &webhook_id,
            &tenant,
            json!({}),
            1,
            "tok-2",
            ClaimOffsets {
                scheduled_secs: None,
                locked_secs: None,
            },
        )
        .await;
        let mut stale = job.clone();
        stale.id = row2.clone();
        stale.claim_token = Some("expired".to_string());
        proc.process_job_inner(&stale).await.expect("fenced dedup");
        assert!(
            queue_state(&pool, &row2).await.is_some(),
            "fenced row survives dedup"
        );

        let mut conn = proc.redis.get().await.unwrap();
        let _: () = redis::cmd("DEL")
            .arg(&dedup_key)
            .query_async(&mut *conn)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn ssrf_refusal_is_a_retry_and_never_a_success() {
        let Some(pool) = test_pool("wh_ssrf").await else {
            return;
        };
        let proc = processor(pool.clone(), test_config());
        let tenant = unique_tenant();
        let webhook_id =
            insert_webhook(&pool, &tenant, "https://169.254.169.254/latest", true).await;
        let row = insert_queue_row(
            &pool,
            &webhook_id,
            &tenant,
            json!({}),
            1,
            "tok",
            ClaimOffsets {
                scheduled_secs: None,
                locked_secs: None,
            },
        )
        .await;
        let job = WebhookJob {
            id: row.clone(),
            claim_token: Some("tok".to_string()),
            ..job_for(&webhook_id, &tenant, "https://169.254.169.254/latest")
        };
        proc.process_job_inner(&job).await.expect("ssrf refusal");

        let (status, attempt, error): (String, i32, Option<String>) = sqlx::query_as(
            "SELECT status, attempt, error_message FROM webhook_queue WHERE id = $1",
        )
        .bind(&row)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(
            status, "pending",
            "an SSRF refusal is retryable, not terminal"
        );
        assert_eq!(attempt, 2);
        assert!(
            error.as_deref().unwrap_or_default().contains("SSRF"),
            "the record must name SSRF: {error:?}"
        );
        assert_eq!(delivery_rows(&pool, &webhook_id).await, 0);
    }

    #[tokio::test]
    async fn open_circuit_defers_without_consuming_an_attempt() {
        let Some(pool) = test_pool("wh_circuit").await else {
            return;
        };
        let proc = processor(pool.clone(), test_config());
        let tenant = unique_tenant();
        let webhook_id = insert_webhook(&pool, &tenant, "https://example.test/hook", true).await;
        let row = insert_queue_row(
            &pool,
            &webhook_id,
            &tenant,
            json!({}),
            4,
            "tok",
            ClaimOffsets {
                scheduled_secs: None,
                locked_secs: None,
            },
        )
        .await;

        let breaker = proc.get_circuit_breaker(&webhook_id);
        assert!(Arc::ptr_eq(
            &breaker,
            &proc.get_circuit_breaker(&webhook_id)
        ));
        for _ in 0..5 {
            breaker.record_failure();
        }
        assert!(!breaker.is_allowed(), "5 failures must open the circuit");

        let job = WebhookJob {
            id: row.clone(),
            claim_token: Some("tok".to_string()),
            ..job_for(&webhook_id, &tenant, "https://example.test/hook")
        };
        proc.process_job_inner(&job)
            .await
            .expect("circuit deferral");

        let (status, attempt, error): (String, i32, Option<String>) = sqlx::query_as(
            "SELECT status, attempt, error_message FROM webhook_queue WHERE id = $1",
        )
        .bind(&row)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(status, "pending");
        assert_eq!(attempt, 4, "a breaker deferral must not consume an attempt");
        assert!(error.unwrap_or_default().contains("Circuit breaker open"));
    }

    #[tokio::test]
    async fn oversized_payload_is_truncated_and_still_processed() {
        let Some(pool) = test_pool("wh_truncate").await else {
            return;
        };
        let proc = processor(pool.clone(), test_config());
        let tenant = unique_tenant();
        let webhook_id = insert_webhook(&pool, &tenant, "https://240.0.0.1:9/hook", true).await;
        let huge = json!({
            "body": "x".repeat(MAX_WEBHOOK_PAYLOAD_BYTES + 1024),
            "keep": "small",
        });
        let row = insert_queue_row(
            &pool,
            &webhook_id,
            &tenant,
            huge,
            1,
            "tok",
            ClaimOffsets {
                scheduled_secs: None,
                locked_secs: None,
            },
        )
        .await;
        let job = WebhookJob {
            id: row.clone(),
            claim_token: Some("tok".to_string()),
            ..job_for(&webhook_id, &tenant, "https://240.0.0.1:9/hook")
        };
        // The delivery itself is refused (240.0.0.1 is not routable) but the
        // oversize truncation path must run first and the job must survive as
        // a retry rather than panicking or being dropped.
        proc.process_job_inner(&job)
            .await
            .expect("oversize handling");
        let (status, attempt): (String, i32) =
            sqlx::query_as("SELECT status, attempt FROM webhook_queue WHERE id = $1")
                .bind(&row)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(status, "pending");
        assert_eq!(attempt, 2, "the oversize delivery attempt is retried");
    }

    #[tokio::test]
    async fn circuit_breaker_map_saturates_without_panicking() {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://localhost/unused")
            .unwrap();
        let proc = processor(pool, test_config());
        {
            let mut map = proc.circuit_breakers.write().unwrap();
            for i in 0..10_000 {
                map.insert(
                    format!("webhook:stale-{i}"),
                    Arc::new(CircuitBreaker::new(
                        crate::common::CircuitBreakerConfig::default(),
                    )),
                );
            }
        }
        // At capacity with fresh (non-stale) breakers: the eviction finds
        // nothing to evict, warns, and still serves a new breaker.
        let cb = proc.get_circuit_breaker("brand-new");
        assert!(cb.is_allowed());
        assert!(proc
            .circuit_breakers
            .read()
            .unwrap()
            .contains_key("webhook:brand-new"));
    }

    // ── success flushing / shutdown ────────────────────────────────────────

    #[tokio::test]
    async fn flush_pending_successes_writes_deliveries_and_consumes_queue_rows() {
        let Some(pool) = test_pool("wh_flush").await else {
            return;
        };
        let proc = processor(pool.clone(), test_config());
        let tenant = unique_tenant();
        let webhook_id = insert_webhook(&pool, &tenant, "https://example.test/hook", true).await;
        let owned = insert_queue_row(
            &pool,
            &webhook_id,
            &tenant,
            json!({}),
            1,
            "tok-owned",
            ClaimOffsets {
                scheduled_secs: None,
                locked_secs: None,
            },
        )
        .await;
        let fenced = insert_queue_row(
            &pool,
            &webhook_id,
            &tenant,
            json!({}),
            1,
            "tok-real",
            ClaimOffsets {
                scheduled_secs: None,
                locked_secs: None,
            },
        )
        .await;

        let mut good = job_for(&webhook_id, &tenant, "https://example.test/hook");
        good.id = owned.clone();
        good.claim_token = Some("tok-owned".to_string());
        let mut stale = job_for(&webhook_id, &tenant, "https://example.test/hook");
        stale.id = fenced.clone();
        stale.claim_token = Some("not-the-owner".to_string());

        {
            let mut pending = proc.pending_successes.lock().unwrap();
            pending.push(PendingSuccess {
                job: good,
                result: WebhookDeliveryResult::success(200, 12, Some("ok".to_string())),
            });
            pending.push(PendingSuccess {
                job: stale,
                result: WebhookDeliveryResult::success(200, 12, None),
            });
        }
        proc.flush_pending_successes().await;
        assert!(proc.pending_successes.lock().unwrap().is_empty());
        assert_eq!(queue_state(&pool, &owned).await, None, "owned row consumed");
        assert!(
            queue_state(&pool, &fenced).await.is_some(),
            "fenced row survives"
        );
        assert_eq!(
            delivery_rows(&pool, &webhook_id).await,
            1,
            "a stale owner must not append a duplicate delivery record"
        );

        // Nothing pending → the flush is a no-op.
        proc.flush_pending_successes().await;
    }

    #[tokio::test]
    async fn stop_flushes_pending_successes_and_clears_running_flag() {
        let Some(pool) = test_pool("wh_stop").await else {
            return;
        };
        let proc = Arc::new(processor(pool.clone(), test_config()));
        let tenant = unique_tenant();
        let webhook_id = insert_webhook(&pool, &tenant, "https://example.test/hook", true).await;
        let row = insert_queue_row(
            &pool,
            &webhook_id,
            &tenant,
            json!({}),
            1,
            "tok",
            ClaimOffsets {
                scheduled_secs: None,
                locked_secs: None,
            },
        )
        .await;
        let mut job = job_for(&webhook_id, &tenant, "https://example.test/hook");
        job.id = row.clone();
        job.claim_token = Some("tok".to_string());
        proc.pending_successes.lock().unwrap().push(PendingSuccess {
            job,
            result: WebhookDeliveryResult::success(204, 1, None),
        });
        proc.is_running.store(true, Ordering::SeqCst);

        proc.stop().await.expect("stop");
        assert!(!proc.is_running.load(Ordering::SeqCst));
        assert_eq!(queue_state(&pool, &row).await, None);
        assert_eq!(delivery_rows(&pool, &webhook_id).await, 1);
    }

    #[tokio::test]
    async fn poll_loop_processes_a_claimable_job_until_stop() {
        let Some(pool) = test_pool("wh_poll_loop").await else {
            return;
        };
        let tenant = unique_tenant();
        // 240.0.0.1 passes the SSRF validator (public, not reserved by the
        // checker) but is not routable: the attempt fails fast and is retried,
        // which is exactly the loop path under test.
        let webhook_id = insert_webhook(&pool, &tenant, "https://240.0.0.1:9/hook", true).await;
        insert_queue_row(
            &pool,
            &webhook_id,
            &tenant,
            json!({"loop": true}),
            1,
            "tok",
            ClaimOffsets {
                scheduled_secs: None,
                locked_secs: None,
            },
        )
        .await;

        let proc = Arc::new(processor(pool.clone(), test_config()));
        let running = Arc::clone(&proc);
        let handle = tokio::spawn(async move { running.start().await });

        let mut observed_attempt = None;
        for _ in 0..100 {
            let attempt: i32 = sqlx::query_scalar(
                "SELECT attempt FROM webhook_queue WHERE webhook_id = $1 AND status = 'pending'",
            )
            .bind(&webhook_id)
            .fetch_optional(&pool)
            .await
            .unwrap()
            .unwrap_or(1);
            if attempt >= 2 {
                observed_attempt = Some(attempt);
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        proc.stop().await.expect("stop");
        let _ = tokio::time::timeout(Duration::from_secs(5), handle).await;
        assert_eq!(
            observed_attempt,
            Some(2),
            "the poll loop must claim and fail-retry the job"
        );
    }
    // ── poll-loop + payload-shaping arms (batch 2) ────────────────────────

    fn loop_redis() -> RedisPool {
        let url = std::env::var("TEST_REDIS_URL")
            .ok()
            .filter(|v| !v.trim().is_empty())
            .unwrap_or_else(|| "redis://127.0.0.1:6379".to_string());
        deadpool_redis::Config::from_url(url)
            .create_pool(Some(deadpool_redis::Runtime::Tokio1))
            .expect("redis pool")
    }

    fn loop_config() -> WebhookConfig {
        WebhookConfig {
            base: crate::common::ProcessorConfig {
                name: "webhook-loop".into(),
                concurrency: 2,
                poll_interval: std::time::Duration::from_millis(20),
                ..Default::default()
            },
            ..Default::default()
        }
    }

    fn dead_db() -> PgPool {
        sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .acquire_timeout(std::time::Duration::from_secs(2))
            .connect_lazy("postgresql://127.0.0.1:1/none")
            .expect("lazy pool")
    }

    /// Empty queue + shutdown: the select on poll_interval breaks on the
    /// shutdown notification.
    #[tokio::test] // real time: pool provisioning cannot run under a paused clock
    async fn webhook_poll_loop_breaks_on_shutdown_when_queue_is_empty() {
        let pool = match migrator::test_support::fresh_canonical_pool(
            "worker_webhook_loop",
            "webhook_loop_empty",
        )
        .await
        {
            Ok(Some(pool)) => pool,
            Ok(None) => {
                eprintln!("skipping: set TEST_DATABASE_URL to run DB-backed test");
                return;
            }
            Err(error) => panic!("{}", error.panic_message()),
        };
        let processor = std::sync::Arc::new(
            WebhookProcessor::new(pool.clone(), loop_redis(), loop_config()).expect("processor"),
        );
        processor.is_running.store(true, Ordering::SeqCst);
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        processor.is_running.store(false, Ordering::SeqCst);
        processor.shutdown_notify.notify_waiters();
        let p = processor.clone();
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            tokio::spawn(async move { p.poll_loop().await }),
        )
        .await
        .expect("loop exits on shutdown")
        .expect("join ok");
        pool.close().await;
    }

    /// A dead database drives the fetch-error arm; the loop keeps polling
    /// until shutdown.
    #[tokio::test] // real time: pool provisioning cannot run under a paused clock
    async fn webhook_poll_loop_survives_fetch_errors_until_shutdown() {
        let processor = std::sync::Arc::new(
            WebhookProcessor::new(dead_db(), loop_redis(), loop_config()).expect("processor"),
        );
        processor.is_running.store(true, Ordering::SeqCst);
        tokio::time::sleep(std::time::Duration::from_millis(60)).await;
        processor.is_running.store(false, Ordering::SeqCst);
        processor.shutdown_notify.notify_waiters();
        let p = processor.clone();
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            tokio::spawn(async move { p.poll_loop().await }),
        )
        .await
        .expect("loop exits after error polls")
        .expect("join ok");
    }

    /// Zero available capacity parks the loop for the 100ms tick; draining
    /// plus shutdown ends it.
    #[tokio::test] // real time: pool provisioning cannot run under a paused clock
    async fn webhook_poll_loop_parks_when_capacity_is_exhausted() {
        let processor = std::sync::Arc::new(
            WebhookProcessor::new(dead_db(), loop_redis(), loop_config()).expect("processor"),
        );
        processor.is_running.store(true, Ordering::SeqCst);
        processor.active_jobs.fetch_add(2, Ordering::SeqCst);
        tokio::time::sleep(std::time::Duration::from_millis(60)).await;
        processor.active_jobs.fetch_sub(2, Ordering::SeqCst);
        processor.is_running.store(false, Ordering::SeqCst);
        processor.shutdown_notify.notify_waiters();
        let p = processor.clone();
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            tokio::spawn(async move { p.poll_loop().await }),
        )
        .await
        .expect("loop exits after capacity drain")
        .expect("join ok");
    }
}
