//! Email processor implementation.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use chrono::Utc;
use moka::sync::Cache;
use sqlx::PgPool;
use std::sync::{Mutex, RwLock};
use tokio::sync::Notify;
use tokio::time::sleep;
use tracing::{debug, error, info, warn};

use super::tracking::{add_tracking_pixel, rewrite_links};
use super::transport::{create_transport_from_config, EmailTransport};
use super::types::{
    Attachment, CachedSuppression, DkimConfig, Domain, EmailJob, PreparedEmail, SendOutcome,
    SendResult, WarmupLimits,
};
use crate::common::{
    CircuitBreaker, CircuitBreakerConfig, EmailConfig, ProcessorError, ProcessorResult, RedisPool,
};

/// Maximum suppression cache size.
const SUPPRESSION_CACHE_MAX_SIZE: u64 = 10_000;

/// Suppression cache TTL.
const SUPPRESSION_CACHE_TTL: Duration = Duration::from_secs(5 * 60);

/// Error rate window size.
const ERROR_WINDOW_SIZE: usize = 20;

/// Error threshold for circuit breaker (50% failure rate).
const ERROR_THRESHOLD: usize = 10;

/// Cooldown duration when error rate is too high.
const ERROR_COOLDOWN: Duration = Duration::from_secs(60);

/// Email processor for sending emails from the queue.
pub struct EmailProcessor {
    db: PgPool,
    #[allow(unused)]
    redis: RedisPool,
    config: EmailConfig,
    transport: Box<dyn EmailTransport>,
    is_running: AtomicBool,
    active_jobs: AtomicUsize,
    shutdown_notify: Arc<Notify>,

    // Caches
    suppression_cache: Cache<String, CachedSuppression>,
    #[allow(unused)]
    warmup_day_cache: Cache<String, i32>,
    dkim_keys: RwLock<HashMap<String, DkimConfig>>,
    domain_cache: Cache<String, Domain>,

    // Circuit breakers for SMTP endpoints
    smtp_circuit_breaker: CircuitBreaker,

    // Error rate tracking
    recent_outcomes: Mutex<Vec<(SendOutcome, Instant)>>,
    error_cooldown_until: AtomicI64,
}

impl EmailProcessor {
    /// Create a new email processor.
    /// This is async because SES transport requires AWS SDK initialisation.
    pub async fn new(db: PgPool, redis: RedisPool, config: EmailConfig) -> ProcessorResult<Self> {
        let transport = create_transport_from_config(&config).await?;

        let smtp_circuit_breaker = CircuitBreaker::new(CircuitBreakerConfig {
            failure_threshold: 10,
            open_duration: Duration::from_secs(60),
            success_threshold: 3,
            window_duration: Duration::from_secs(120),
        });

        Ok(Self {
            db,
            redis,
            config,
            transport,
            is_running: AtomicBool::new(false),
            active_jobs: AtomicUsize::new(0),
            shutdown_notify: Arc::new(Notify::new()),
            suppression_cache: Cache::builder()
                .max_capacity(SUPPRESSION_CACHE_MAX_SIZE)
                .time_to_live(SUPPRESSION_CACHE_TTL)
                .build(),
            warmup_day_cache: Cache::builder()
                .max_capacity(1000)
                .time_to_live(Duration::from_secs(3600))
                .build(),
            dkim_keys: RwLock::new(HashMap::new()),
            domain_cache: Cache::builder()
                .max_capacity(1000)
                .time_to_live(Duration::from_secs(300))
                .build(),
            smtp_circuit_breaker,
            recent_outcomes: Mutex::new(Vec::new()),
            error_cooldown_until: AtomicI64::new(0),
        })
    }

    /// Start the processor.
    pub async fn start(self: Arc<Self>) -> ProcessorResult<()> {
        info!(
            concurrency = self.config.base.concurrency,
            "Starting email processor"
        );

        // Verify transport
        self.transport.verify().await?;
        info!("Email transport verified");

        // Load DKIM keys
        if self.config.dkim.enabled {
            self.load_dkim_keys().await?;
        }

        self.is_running.store(true, Ordering::SeqCst);

        // Run poll loop
        self.poll_loop().await;

        Ok(())
    }

    /// Stop the processor gracefully.
    pub async fn stop(&self) -> ProcessorResult<()> {
        info!("Stopping email processor");
        self.is_running.store(false, Ordering::SeqCst);
        self.shutdown_notify.notify_waiters();

        // Wait for active jobs
        let max_wait = Duration::from_secs(30);
        let start = Instant::now();

        while self.active_jobs.load(Ordering::SeqCst) > 0 && start.elapsed() < max_wait {
            sleep(Duration::from_millis(100)).await;
        }

        // Close transport
        self.transport.close().await?;

        info!("Email processor stopped");
        Ok(())
    }

    /// Main poll loop.
    async fn poll_loop(&self) {
        while self.is_running.load(Ordering::SeqCst) {
            // Check error rate cooldown
            let cooldown_until = self.error_cooldown_until.load(Ordering::SeqCst);
            let now = Utc::now().timestamp_millis();
            if now < cooldown_until {
                let remaining = cooldown_until - now;
                warn!(
                    remaining_ms = remaining,
                    "Worker paused due to high error rate"
                );
                sleep(Duration::from_millis(remaining.min(5000) as u64)).await;
                continue;
            }

            // Check capacity
            let available_slots = self
                .config
                .base
                .concurrency
                .saturating_sub(self.active_jobs.load(Ordering::SeqCst));
            if available_slots == 0 {
                sleep(Duration::from_millis(100)).await;
                continue;
            }

            // Fetch jobs
            match self.fetch_jobs(available_slots).await {
                Ok(jobs) if jobs.is_empty() => {
                    tokio::select! {
                        _ = sleep(self.config.base.poll_interval) => {}
                        _ = self.shutdown_notify.notified() => break,
                    }
                }
                Ok(jobs) => {
                    // Batch suppression check
                    let suppressions = self.batch_suppression_check(&jobs).await;

                    let mut handles = Vec::with_capacity(jobs.len());
                    for job in jobs {
                        let suppression =
                            suppressions.get(&format!("{}:{}", job.tenant_id, job.to));
                        if let Some(reason) = suppression {
                            // Skip suppressed recipients
                            if let Err(e) = self.handle_suppressed(&job, reason).await {
                                error!(
                                    job_id = %job.id,
                                    message_id = %job.message_id,
                                    tenant_id = %job.tenant_id,
                                    recipient = %job.to,
                                    error = %e,
                                    "Failed to handle suppression"
                                );
                            }
                            continue;
                        }

                        // Process non-suppressed jobs concurrently
                        handles.push(self.process_job(job));
                    }

                    // Await all concurrently
                    let results = futures::future::join_all(handles).await;
                    for result in results {
                        if let Err(e) = result {
                            debug!(error = %e, "Job failed");
                        }
                    }

                    // Short delay before next batch
                    sleep(Duration::from_millis(100)).await;
                }
                Err(e) => {
                    error!(error = %e, "Failed to fetch jobs");
                    sleep(self.config.base.poll_interval).await;
                }
            }
        }
    }

    /// Fetch jobs from the queue.
    async fn fetch_jobs(&self, limit: usize) -> ProcessorResult<Vec<EmailJob>> {
        let visibility_ms = self.config.base.visibility_timeout.as_millis();
        let visibility_ms_i64 = if visibility_ms > i64::MAX as u128 {
            i64::MAX
        } else {
            visibility_ms as i64
        };
        let lock_until = Utc::now() + chrono::Duration::milliseconds(visibility_ms_i64);

        let jobs = sqlx::query_as::<_, EmailJob>(
            r#"
            UPDATE email_queue
            SET status = 'processing', locked_until = $1, updated_at = NOW()
            WHERE id IN (
                SELECT id
                FROM email_queue
                WHERE status = 'pending'
                  AND (scheduled_at IS NULL OR scheduled_at <= NOW())
                  AND (locked_until IS NULL OR locked_until < NOW())
                ORDER BY priority DESC, created_at ASC
                LIMIT $2
                FOR UPDATE SKIP LOCKED
            )
            RETURNING
                id, message_id as "messageId", tenant_id as "tenantId", domain_id as "domainId",
                "from", "to", subject, html, text, headers, attachments,
                campaign_id as "campaignId", tags, metadata, scheduled_at as "scheduledAt",
                attempt, created_at as "createdAt"
            "#,
        )
        .bind(lock_until)
        .bind(limit as i64)
        .fetch_all(&self.db)
        .await?;

        Ok(jobs)
    }

    /// Batch suppression check for efficiency.
    async fn batch_suppression_check(&self, jobs: &[EmailJob]) -> HashMap<String, String> {
        let mut result = HashMap::new();

        // Group by tenant
        let mut by_tenant: HashMap<String, Vec<&str>> = HashMap::new();
        for job in jobs {
            by_tenant
                .entry(job.tenant_id.clone())
                .or_default()
                .push(&job.to);
        }

        for (tenant_id, emails) in by_tenant {
            // Check cache first
            let mut uncached: Vec<&str> = Vec::new();
            for email in &emails {
                let cache_key = format!("{}:{}", tenant_id, email);
                if let Some(cached) = self.suppression_cache.get(&cache_key) {
                    if cached.suppressed {
                        result.insert(cache_key, cached.reason.clone().unwrap_or_default());
                    }
                } else {
                    uncached.push(*email);
                }
            }

            // Query database for uncached
            if !uncached.is_empty() {
                // to avoid sending to potentially suppressed recipients.
                let db_result = sqlx::query_as::<_, (String, String)>(
                    r#"
                    SELECT email, reason
                    FROM suppressions
                    WHERE tenant_id = $1 AND email = ANY($2)
                    "#,
                )
                .bind(&tenant_id)
                .bind(&uncached)
                .fetch_all(&self.db)
                .await;

                let suppressions: Vec<(String, String)> = match db_result {
                    Ok(rows) => rows,
                    Err(e) => {
                        tracing::error!(tenant_id = %tenant_id, error = %e,
                            "Failed to check suppressions; treating all as suppressed for safety");
                        // Fail safe:treat all uncached emails as suppressed
                        for email in &uncached {
                            let cache_key = format!("{}:{}", tenant_id, email);
                            result.insert(cache_key, "suppression_check_failed".to_string());
                        }
                        continue;
                    }
                };

                // Build set of suppressed emails
                let suppressed_emails: std::collections::HashSet<String> =
                    suppressions.iter().map(|(e, _)| e.clone()).collect();

                // Cache and collect positive results
                for (email, reason) in suppressions {
                    let cache_key = format!("{}:{}", tenant_id, email);
                    self.suppression_cache.insert(
                        cache_key.clone(),
                        CachedSuppression {
                            suppressed: true,
                            reason: Some(reason.clone()),
                            expires_at: Instant::now() + SUPPRESSION_CACHE_TTL,
                        },
                    );
                    result.insert(cache_key, reason);
                }

                // Cache negative results
                for email in &uncached {
                    if !suppressed_emails.contains(*email) {
                        let cache_key = format!("{}:{}", tenant_id, email);
                        self.suppression_cache.insert(
                            cache_key,
                            CachedSuppression {
                                suppressed: false,
                                reason: None,
                                expires_at: Instant::now() + SUPPRESSION_CACHE_TTL,
                            },
                        );
                    }
                }
            }
        }

        result
    }

    /// Process a single job.
    async fn process_job(&self, job: EmailJob) -> ProcessorResult<()> {
        self.active_jobs.fetch_add(1, Ordering::SeqCst);
        let start = Instant::now();
        let job_id = job.id.clone();

        let result = self.process_job_inner(&job).await;

        self.active_jobs.fetch_sub(1, Ordering::SeqCst);

        // Record outcome for error rate tracking
        let outcome = match &result {
            Ok(_) => SendOutcome::Success,
            Err(ProcessorError::Transport(msg)) if msg.contains("Soft bounce") => {
                SendOutcome::SoftBounce
            }
            Err(ProcessorError::Transport(msg)) if msg.contains("Hard bounce") => {
                SendOutcome::HardBounce
            }
            Err(ProcessorError::RateLimited(_)) => SendOutcome::RateLimit,
            Err(_) => SendOutcome::TransportError,
        };
        self.record_outcome(outcome);

        let duration = start.elapsed();
        debug!(
            job_id = %job_id,
            duration_ms = duration.as_millis(),
            outcome = ?outcome,
            "Job processed"
        );

        result
    }

    async fn process_job_inner(&self, job: &EmailJob) -> ProcessorResult<()> {
        // Check circuit breaker
        if !self.smtp_circuit_breaker.is_allowed() {
            return Err(ProcessorError::CircuitOpen(
                "SMTP circuit breaker open".into(),
            ));
        }

        // Check warmup limits
        if self.config.warmup.enabled && !self.check_warmup_limit(job).await? {
            self.requeue_job(job, "warmup_limit").await?;
            return Ok(());
        }

        // Get domain
        let domain = self.get_domain(&job.domain_id, &job.tenant_id).await?;

        // Prepare email
        let email = self.prepare_email(job, &domain)?;

        // Send email
        match self.transport.send(&email).await {
            Ok(result) => {
                self.smtp_circuit_breaker.record_success();
                self.handle_success(job, &result).await?;
            }
            Err(e) => {
                self.smtp_circuit_breaker.record_failure();

                // Check if retryable
                let err_str = e.to_string();
                if err_str.contains("Soft bounce") || err_str.contains("temporary") {
                    self.handle_soft_bounce(job, &e).await?;
                } else if err_str.contains("Hard bounce") {
                    self.handle_hard_bounce(job, &e).await?;
                } else {
                    self.handle_error(job, &e).await?;
                }

                return Err(e);
            }
        }

        Ok(())
    }

    /// Check warmup limits for a domain.
    ///
    /// # Security (O-16.8)
    ///
    /// **Root cause**: Previously used an in-memory `RwLock<HashMap<String, i64>>`
    /// which is local to each process. Multiple workers would each have their own
    /// counter, allowing up to N × daily_limit sends per domain (where N is the
    /// number of workers). This is a bypass of warmup rate limiting.
    ///
    /// **Fix**: Replaced the per-process `HashMap` with a Redis `INCR` + `EXPIRE`
    /// key (`warmup:count:<date>:<domain_id>`). The key has a 24-hour TTL and uses
    /// atomic `INCR` for cross-worker correctness. The first worker to increment
    /// (return value == 1) also sets the TTL via `EXPIRE` (race-safe; extra EXPIRE
    /// calls are harmless). All workers share a single counter per domain per day.
    async fn check_warmup_limit(&self, job: &EmailJob) -> ProcessorResult<bool> {
        let domain = self.get_domain(&job.domain_id, &job.tenant_id).await?;

        if !domain.warmup_enabled {
            return Ok(true);
        }

        let limits = WarmupLimits::for_day(domain.warmup_day);

        // Use Redis INCR for atomic cross-worker counters with 24h TTL.
        // Key format: warmup:count:<YYYY-MM-DD>:<domain_id>
        let today = Utc::now().format("%Y-%m-%d").to_string();
        let redis_key = format!("warmup:count:{}:{}", today, job.domain_id);

        let mut conn = self.redis.get().await.map_err(|e| {
            warn!(domain_id = %job.domain_id, error = %e, "Failed to get Redis connection for warmup check");
            ProcessorError::Job(format!("Redis unavailable for warmup check: {}", e))
        })?;

        // Atomically increment the counter — shared across all workers
        let current: i64 = redis::cmd("INCR")
            .arg(&redis_key)
            .query_async(&mut *conn)
            .await
            .map_err(|e| {
                warn!(domain_id = %job.domain_id, error = %e, "Redis INCR failed for warmup check");
                ProcessorError::Job(format!("Redis INCR failed: {}", e))
            })?;

        // Set expiry on first increment (return value == 1 means this is a new key).
        // Race-safe: multiple workers may call EXPIRE concurrently, which is idempotent.
        if current == 1 {
            let _: () = redis::cmd("EXPIRE")
                .arg(&redis_key)
                .arg(86400) // 24 hours
                .query_async(&mut *conn)
                .await
                .unwrap_or_default();
        }

        if current > limits.daily_limit {
            // We've exceeded the limit. Decrement to keep the counter accurate.
            let _: () = redis::cmd("DECR")
                .arg(&redis_key)
                .query_async(&mut *conn)
                .await
                .unwrap_or_default();
            return Ok(false);
        }

        Ok(true)
    }

    /// Get domain configuration.
    async fn get_domain(&self, domain_id: &str, tenant_id: &str) -> ProcessorResult<Domain> {
        let cache_key = format!("{}:{}", tenant_id, domain_id);

        if let Some(domain) = self.domain_cache.get(&cache_key) {
            return Ok(domain);
        }

        let domain = sqlx::query_as::<_, Domain>(
            r#"
            SELECT
                id, tenant_id, domain, dkim_selector, dkim_private_key,
                warmup_enabled, warmup_day, return_path
            FROM domains
            WHERE id = $1 AND tenant_id = $2
            "#,
        )
        .bind(domain_id)
        .bind(tenant_id)
        .fetch_optional(&self.db)
        .await?
        .ok_or_else(|| ProcessorError::Job(format!("Domain not found: {}", domain_id)))?;

        self.domain_cache.insert(cache_key, domain.clone());
        Ok(domain)
    }

    /// Prepare email for sending.
    fn prepare_email(&self, job: &EmailJob, domain: &Domain) -> ProcessorResult<PreparedEmail> {
        let mut html = job.html.clone();

        // Add tracking if enabled
        if self.config.tracking.enabled {
            if let Some(ref h) = html {
                let tracked = add_tracking_pixel(h, job, &self.config.tracking);
                let tracked = rewrite_links(&tracked, job, &self.config.tracking);
                html = Some(tracked);
            }
        }

        // Build headers
        let mut headers = vec![
            ("X-ApexMail-Message-ID".to_string(), job.message_id.clone()),
            ("X-ApexMail-Tenant-ID".to_string(), job.tenant_id.clone()),
        ];

        if let Some(ref campaign_id) = job.campaign_id {
            headers.push(("X-ApexMail-Campaign-ID".to_string(), campaign_id.clone()));
        }

        const PROTECTED_HEADERS: &[&str] = &[
            "from",
            "to",
            "cc",
            "bcc",
            "subject",
            "date",
            "message-id",
            "dkim-signature",
            "arc-seal",
            "arc-message-signature",
            "arc-authentication-results",
            "return-path",
            "received",
            "received-spf",
            "authentication-results",
            "x-apexmail-message-id",
            "x-apexmail-tenant-id",
            "x-apexmail-campaign-id",
            "x-originating-ip",
            "x-mailer",
            "mime-version",
            "content-type",
            "content-transfer-encoding",
        ];

        // Add custom headers from job (filtering protected headers)
        if let Some(ref job_headers) = job.headers {
            if let Some(obj) = job_headers.as_object() {
                for (key, value) in obj {
                    let key_lower = key.to_lowercase();
                    if PROTECTED_HEADERS.contains(&key_lower.as_str()) {
                        tracing::warn!(header = %key, "Blocked attempt to set protected header via custom headers");
                        continue;
                    }
                    if let Some(v) = value.as_str() {
                        headers.push((key.clone(), v.to_string()));
                    }
                }
            }
        }

        // DKIM config
        let dkim = if self.config.dkim.enabled {
            domain
                .dkim_private_key
                .as_ref()
                .map(|key| DkimConfig {
                    selector: domain
                        .dkim_selector
                        .clone()
                        .unwrap_or_else(|| self.config.dkim.selector.clone()),
                    domain: domain.domain.clone(),
                    private_key: key.clone(),
                })
                .or_else(|| {
                    // Fallback:check pre-loaded dkim_keys map
                    let dkim_keys = self.dkim_keys.read().unwrap_or_else(|e| e.into_inner());
                    dkim_keys.get(&domain.id).cloned()
                })
        } else {
            None
        };

        // Parse attachments
        let attachments = job
            .attachments
            .as_ref()
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|a| {
                        let obj = a.as_object()?;
                        Some(Attachment {
                            filename: obj.get("filename")?.as_str()?.to_string(),
                            content: base64::engine::general_purpose::STANDARD
                                .decode(obj.get("content")?.as_str()?)
                                .ok()?,
                            content_type: obj.get("contentType")?.as_str()?.to_string(),
                        })
                    })
                    .collect()
            })
            .unwrap_or_default();

        Ok(PreparedEmail {
            from: job.from.clone(),
            to: job.to.clone(),
            subject: job.subject.clone(),
            html,
            text: job.text.clone(),
            headers,
            attachments,
            dkim,
        })
    }

    /// Handle successful send.
    async fn handle_success(&self, job: &EmailJob, result: &SendResult) -> ProcessorResult<()> {
        sqlx::query(
            r#"
            UPDATE email_queue
            SET status = 'sent', sent_at = NOW(), smtp_message_id = $1
            WHERE id = $2
            "#,
        )
        .bind(&result.smtp_message_id)
        .bind(&job.id)
        .execute(&self.db)
        .await?;

        // Record sent event
        sqlx::query(
            r#"
            INSERT INTO events (id, tenant_id, message_id, domain_id, campaign_id, event_type, recipient_email, created_at)
            VALUES ($1, $2, $3, $4, $5, 'sent', $6, NOW())
            "#,
        )
        .bind(format!("evt_{}", uuid::Uuid::new_v4()))
        .bind(&job.tenant_id)
        .bind(&job.message_id)
        .bind(&job.domain_id)
        .bind(&job.campaign_id)
        .bind(&job.to)
        .execute(&self.db)
        .await?;

        Ok(())
    }

    /// Handle suppressed recipient.
    async fn handle_suppressed(&self, job: &EmailJob, reason: &str) -> ProcessorResult<()> {
        sqlx::query(
            r#"
            UPDATE email_queue SET status = 'suppressed', error_message = $1 WHERE id = $2
            "#,
        )
        .bind(reason)
        .bind(&job.id)
        .execute(&self.db)
        .await?;

        Ok(())
    }

    /// Handle soft bounce (retry later).
    async fn handle_soft_bounce(
        &self,
        job: &EmailJob,
        error: &ProcessorError,
    ) -> ProcessorResult<()> {
        if job.attempt >= self.config.base.max_retries as i32 {
            return self.handle_hard_bounce(job, error).await;
        }

        let next_attempt = job.attempt + 1;
        let backoff_multiplier = 2_i64.saturating_pow(job.attempt.min(30) as u32);
        let retry_at = Utc::now()
            + chrono::Duration::seconds(
                (self.config.base.retry_delay.as_secs() as i64).saturating_mul(backoff_multiplier),
            );

        sqlx::query(
            r#"
            UPDATE email_queue
            SET status = 'pending', attempt = $1, scheduled_at = $2,
                error_message = $3, locked_until = NULL
            WHERE id = $4
            "#,
        )
        .bind(next_attempt)
        .bind(retry_at)
        .bind(error.to_string())
        .bind(&job.id)
        .execute(&self.db)
        .await?;

        Ok(())
    }

    /// Handle hard bounce (permanent failure).
    async fn handle_hard_bounce(
        &self,
        job: &EmailJob,
        error: &ProcessorError,
    ) -> ProcessorResult<()> {
        sqlx::query(
            r#"
            UPDATE email_queue SET status = 'bounced', error_message = $1 WHERE id = $2
            "#,
        )
        .bind(error.to_string())
        .bind(&job.id)
        .execute(&self.db)
        .await?;

        // Add to suppressions
        sqlx::query(
            r#"
            INSERT INTO suppressions (id, tenant_id, email, reason, created_at)
            VALUES ($1, $2, $3, 'hard_bounce', NOW())
            ON CONFLICT (tenant_id, email) DO NOTHING
            "#,
        )
        .bind(format!("sup_{}", uuid::Uuid::new_v4()))
        .bind(&job.tenant_id)
        .bind(&job.to)
        .execute(&self.db)
        .await?;

        // Record bounce event
        sqlx::query(
            r#"
            INSERT INTO events (id, tenant_id, message_id, domain_id, campaign_id, event_type, recipient_email, created_at)
            VALUES ($1, $2, $3, $4, $5, 'bounced', $6, NOW())
            "#,
        )
        .bind(format!("evt_{}", uuid::Uuid::new_v4()))
        .bind(&job.tenant_id)
        .bind(&job.message_id)
        .bind(&job.domain_id)
        .bind(&job.campaign_id)
        .bind(&job.to)
        .execute(&self.db)
        .await?;

        Ok(())
    }

    /// Handle generic error.
    async fn handle_error(&self, job: &EmailJob, error: &ProcessorError) -> ProcessorResult<()> {
        if job.attempt >= self.config.base.max_retries as i32 {
            // Move to DLQ
            sqlx::query(
                r#"
                INSERT INTO email_dlq (id, job_id, tenant_id, message_id, error_message, created_at)
                VALUES ($1, $2, $3, $4, $5, NOW())
                "#,
            )
            .bind(format!("dlq_{}", uuid::Uuid::new_v4()))
            .bind(&job.id)
            .bind(&job.tenant_id)
            .bind(&job.message_id)
            .bind(error.to_string())
            .execute(&self.db)
            .await?;

            sqlx::query(
                r#"
                UPDATE email_queue SET status = 'failed', error_message = $1 WHERE id = $2
                "#,
            )
            .bind(error.to_string())
            .bind(&job.id)
            .execute(&self.db)
            .await?;
        } else {
            self.handle_soft_bounce(job, error).await?;
        }

        Ok(())
    }

    /// Requeue a job for later processing.
    async fn requeue_job(&self, job: &EmailJob, reason: &str) -> ProcessorResult<()> {
        let retry_at = Utc::now() + chrono::Duration::minutes(5);

        sqlx::query(
            r#"
            UPDATE email_queue
            SET status = 'pending', scheduled_at = $1, locked_until = NULL,
                metadata = jsonb_set(COALESCE(metadata, '{}'), '{requeue_reason}', $2::jsonb)
            WHERE id = $3
            "#,
        )
        .bind(retry_at)
        .bind(
            serde_json::to_value(reason)
                .map_err(|e| sqlx::Error::Protocol(format!("serialization: {e}")))?,
        )
        .bind(&job.id)
        .execute(&self.db)
        .await?;

        Ok(())
    }

    /// Record send outcome for error rate tracking.
    fn record_outcome(&self, outcome: SendOutcome) {
        let now = Instant::now();

        let mut outcomes = self
            .recent_outcomes
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        outcomes.push((outcome, now));

        // Evict old entries (>60s)
        outcomes.retain(|(_, t)| now.duration_since(*t) < Duration::from_secs(60));

        // Also cap at window size
        let len = outcomes.len();
        if len > ERROR_WINDOW_SIZE {
            let drain_count = len - ERROR_WINDOW_SIZE;
            outcomes.drain(0..drain_count);
        }

        // Check error rate
        let len = outcomes.len();
        if len >= ERROR_WINDOW_SIZE {
            let failures = outcomes
                .iter()
                .filter(|(o, _)| !matches!(o, SendOutcome::Success | SendOutcome::Suppressed))
                .count();

            if failures >= ERROR_THRESHOLD {
                let cooldown_until =
                    Utc::now().timestamp_millis() + ERROR_COOLDOWN.as_millis() as i64;
                self.error_cooldown_until
                    .store(cooldown_until, Ordering::SeqCst);
                error!(
                    failures = failures,
                    window = len,
                    "Error rate circuit breaker activated"
                );
            }
        }
    }

    /// Load DKIM keys from database.
    async fn load_dkim_keys(&self) -> ProcessorResult<()> {
        let keys: Vec<(String, String, String, String)> = sqlx::query_as(
            r#"
            SELECT id, domain, dkim_selector, dkim_private_key
            FROM domains
            WHERE dkim_private_key IS NOT NULL
            "#,
        )
        .fetch_all(&self.db)
        .await?;

        let mut dkim_keys = self.dkim_keys.write().unwrap_or_else(|e| e.into_inner());
        dkim_keys.clear();

        for (id, domain, selector, key) in keys {
            dkim_keys.insert(
                id,
                DkimConfig {
                    selector,
                    domain,
                    private_key: key,
                },
            );
        }

        info!(count = dkim_keys.len(), "Loaded DKIM keys");
        Ok(())
    }
}

use base64::Engine;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::{CircuitBreaker, CircuitBreakerConfig, CircuitState};
    use std::sync::Arc;
    use std::thread;
    use std::time::{Duration, Instant};

    // ---------------------------------------------------------------------------
    // 1. Initial State
    // ---------------------------------------------------------------------------
    #[test]
    fn test_initial_state_closed() {
        let cb = CircuitBreaker::new(CircuitBreakerConfig {
            failure_threshold: 10,
            open_duration: Duration::from_secs(60),
            success_threshold: 3,
            window_duration: Duration::from_secs(120),
        });

        assert_eq!(
            cb.state(),
            CircuitState::Closed,
            "circuit must start Closed"
        );
        assert!(cb.is_allowed(), "requests must be allowed in Closed state");
    }

    #[test]
    fn test_initial_failure_count_zero() {
        let cb = CircuitBreaker::new(CircuitBreakerConfig {
            failure_threshold: 10,
            ..Default::default()
        });
        // No failures recorded yet; state is still closed
        assert_eq!(cb.state(), CircuitState::Closed);
        // record one failure and check we're still closed (threshold = 10)
        cb.record_failure();
        assert_eq!(cb.state(), CircuitState::Closed);
    }

    #[test]
    fn test_initial_success_count_zero() {
        let cb = CircuitBreaker::new(CircuitBreakerConfig {
            failure_threshold: 10,
            ..Default::default()
        });
        // No successes recorded yet; recording success in Closed resets failures
        cb.record_success();
        assert_eq!(cb.state(), CircuitState::Closed);
    }

    #[test]
    fn test_initial_last_failure_none() {
        let cb = CircuitBreaker::new(CircuitBreakerConfig {
            failure_threshold: 10,
            ..Default::default()
        });
        // After reset, no failure should have been recorded
        cb.reset();
        assert_eq!(cb.state(), CircuitState::Closed);
        // Manually verify by recording one failure (1 << 10), so still closed
        for _ in 0..9 {
            cb.record_failure();
        }
        assert_eq!(cb.state(), CircuitState::Closed);
        // One more to trigger open
        cb.record_failure();
        assert_eq!(cb.state(), CircuitState::Open);
    }

    // ---------------------------------------------------------------------------
    // 2. State Transitions: Closed → Open
    // ---------------------------------------------------------------------------
    #[test]
    fn test_closed_to_open_after_threshold() {
        let cb = CircuitBreaker::new(CircuitBreakerConfig {
            failure_threshold: 5,
            open_duration: Duration::from_secs(60),
            success_threshold: 3,
            window_duration: Duration::from_secs(120),
        });

        assert_eq!(cb.state(), CircuitState::Closed);

        // Record failures below threshold
        for _ in 0..4 {
            cb.record_failure();
            assert_eq!(cb.state(), CircuitState::Closed);
        }

        // Fifth failure triggers transition to Open
        cb.record_failure();
        assert_eq!(
            cb.state(),
            CircuitState::Open,
            "circuit must transition to Open after failure_threshold failures"
        );
        assert!(!cb.is_allowed(), "requests must be rejected in Open state");
    }

    #[test]
    fn test_closed_to_open_failure_count_reset() {
        let cb = CircuitBreaker::new(CircuitBreakerConfig {
            failure_threshold: 3,
            open_duration: Duration::from_secs(60),
            ..Default::default()
        });

        cb.record_failure(); // 1
        cb.record_failure(); // 2
        assert_eq!(cb.state(), CircuitState::Closed);
        cb.record_failure(); // 3 → Open
        assert_eq!(cb.state(), CircuitState::Open);

        // Verify that failure count is effectively reset — after open_duration,
        // the circuit transitions to Half-Open where success count starts at 0
        // and failures are tracked separately.
        // We can't directly read failure_count, but we can check state.
        assert!(!cb.is_allowed());
    }

    // ---------------------------------------------------------------------------
    // 3. State Transitions: Open → Half-Open
    // ---------------------------------------------------------------------------
    #[test]
    fn test_open_to_half_open_after_duration() {
        let cb = CircuitBreaker::new(CircuitBreakerConfig {
            failure_threshold: 1,
            open_duration: Duration::from_millis(10),
            ..Default::default()
        });

        // Trigger Open
        cb.record_failure();
        assert_eq!(cb.state(), CircuitState::Open);
        assert!(!cb.is_allowed());

        // Wait for open duration to elapse
        thread::sleep(Duration::from_millis(20));

        // is_allowed() should transition to Half-Open
        assert!(
            cb.is_allowed(),
            "is_allowed() must return true and transition to Half-Open after open_duration"
        );
        assert_eq!(
            cb.state(),
            CircuitState::HalfOpen,
            "circuit must transition to Half-Open after open_duration"
        );
    }

    #[test]
    fn test_open_stays_open_before_duration_elapses() {
        let cb = CircuitBreaker::new(CircuitBreakerConfig {
            failure_threshold: 1,
            open_duration: Duration::from_secs(60),
            ..Default::default()
        });

        cb.record_failure();
        assert_eq!(cb.state(), CircuitState::Open);

        // Immediately check — should still be Open
        assert!(!cb.is_allowed());
        assert_eq!(cb.state(), CircuitState::Open);
    }

    // ---------------------------------------------------------------------------
    // 4. State Transitions: Half-Open → Closed
    // ---------------------------------------------------------------------------
    #[test]
    fn test_half_open_to_closed_after_successes() {
        let cb = CircuitBreaker::new(CircuitBreakerConfig {
            failure_threshold: 1,
            open_duration: Duration::from_millis(10),
            success_threshold: 3,
            ..Default::default()
        });

        // Trigger Open
        cb.record_failure();
        assert_eq!(cb.state(), CircuitState::Open);

        // Wait for open duration
        thread::sleep(Duration::from_millis(20));

        // Transition to Half-Open
        assert!(cb.is_allowed());
        assert_eq!(cb.state(), CircuitState::HalfOpen);

        // Record successes below threshold
        cb.record_success();
        assert_eq!(
            cb.state(),
            CircuitState::HalfOpen,
            "still Half-Open after 1 success (threshold=3)"
        );
        cb.record_success();
        assert_eq!(
            cb.state(),
            CircuitState::HalfOpen,
            "still Half-Open after 2 successes (threshold=3)"
        );

        // Third success transitions to Closed
        cb.record_success();
        assert_eq!(
            cb.state(),
            CircuitState::Closed,
            "circuit must transition to Closed after success_threshold successes in Half-Open"
        );

        // Now requests flow normally again
        assert!(cb.is_allowed());
    }

    #[test]
    fn test_half_open_to_closed_success_count_resets() {
        let cb = CircuitBreaker::new(CircuitBreakerConfig {
            failure_threshold: 1,
            open_duration: Duration::from_millis(10),
            success_threshold: 2,
            ..Default::default()
        });

        cb.record_failure();
        thread::sleep(Duration::from_millis(20));
        assert!(cb.is_allowed()); // → Half-Open
        assert_eq!(cb.state(), CircuitState::HalfOpen);

        // Two successes → Closed
        cb.record_success();
        cb.record_success();
        assert_eq!(cb.state(), CircuitState::Closed);

        // Now we're back in Closed — a failure should use Closed logic, not Half-Open
        // Record one failure (threshold=1) → should go to Open
        cb.record_failure();
        assert_eq!(
            cb.state(),
            CircuitState::Open,
            "after reset to Closed, one failure should open again"
        );
    }

    // ---------------------------------------------------------------------------
    // 5. State Transitions: Half-Open → Open
    // ---------------------------------------------------------------------------
    #[test]
    fn test_half_open_to_open_on_failure() {
        let cb = CircuitBreaker::new(CircuitBreakerConfig {
            failure_threshold: 5,
            open_duration: Duration::from_millis(10),
            success_threshold: 3,
            ..Default::default()
        });

        // Trigger Open
        for _ in 0..5 {
            cb.record_failure();
        }
        assert_eq!(cb.state(), CircuitState::Open);

        // Wait for open duration
        thread::sleep(Duration::from_millis(20));

        // Transition to Half-Open
        assert!(cb.is_allowed());
        assert_eq!(cb.state(), CircuitState::HalfOpen);

        // A single failure in Half-Open should reopen the circuit
        cb.record_failure();
        assert_eq!(
            cb.state(),
            CircuitState::Open,
            "any failure in Half-Open must transition back to Open"
        );
        assert!(
            !cb.is_allowed(),
            "requests must be rejected after reopening"
        );

        // Verify the opened_at timestamp was reset — wait again to transition back
        thread::sleep(Duration::from_millis(20));
        assert!(cb.is_allowed());
        assert_eq!(cb.state(), CircuitState::HalfOpen);
    }

    // ---------------------------------------------------------------------------
    // 6. Error Rate Tracking
    // ---------------------------------------------------------------------------

    /// Replica of the sliding-window error-rate logic from `EmailProcessor::record_outcome`.
    /// We test the algorithm in isolation since we cannot instantiate `EmailProcessor`
    /// without a database.
    fn simulate_error_tracking(
        outcomes: &mut Vec<(SendOutcome, Instant)>,
        outcome: SendOutcome,
        now: Instant,
    ) -> bool {
        outcomes.push((outcome, now));
        // Evict entries older than 60s
        outcomes.retain(|(_, t)| now.duration_since(*t) < Duration::from_secs(60));
        // Cap at window size
        let len = outcomes.len();
        if len > ERROR_WINDOW_SIZE {
            outcomes.drain(0..(len - ERROR_WINDOW_SIZE));
        }
        // Check if cooldown should be triggered
        let failures = outcomes
            .iter()
            .filter(|(o, _)| !matches!(o, SendOutcome::Success | SendOutcome::Suppressed))
            .count();
        failures >= ERROR_THRESHOLD
    }

    #[test]
    fn test_error_rate_window_tracks_20_outcomes() {
        let mut outcomes = Vec::new();
        let now = Instant::now();

        // Add 25 successes → window should cap at 20
        for _ in 0..25 {
            simulate_error_tracking(&mut outcomes, SendOutcome::Success, now);
        }
        assert_eq!(
            outcomes.len(),
            ERROR_WINDOW_SIZE,
            "sliding window must be capped at ERROR_WINDOW_SIZE ({})",
            ERROR_WINDOW_SIZE
        );

        // After eviction, the oldest entries are removed. Since we pushed 25 items
        // and the window is 20, the first 5 entries are gone.
        assert_eq!(outcomes.len(), 20);
    }

    #[test]
    fn test_error_rate_triggers_cooldown_at_threshold() {
        let mut outcomes = Vec::new();
        let now = Instant::now();

        // Fill window with successes
        for _ in 0..10 {
            simulate_error_tracking(&mut outcomes, SendOutcome::Success, now);
        }
        // Now add 10 failures → total 20; 10 failures >= ERROR_THRESHOLD (10)
        for _ in 0..10 {
            let triggered =
                simulate_error_tracking(&mut outcomes, SendOutcome::TransportError, now);
            if outcomes.len() >= ERROR_WINDOW_SIZE {
                // Once we have a full window of 20 with 10 failures, trigger
                if outcomes
                    .iter()
                    .filter(|(o, _)| !matches!(o, SendOutcome::Success | SendOutcome::Suppressed))
                    .count()
                    >= ERROR_THRESHOLD
                {
                    assert!(
                        triggered,
                        "cooldown must trigger when >=10 failures in window"
                    );
                }
            }
        }

        // Final verification
        assert_eq!(outcomes.len(), ERROR_WINDOW_SIZE);
        let failures = outcomes
            .iter()
            .filter(|(o, _)| !matches!(o, SendOutcome::Success | SendOutcome::Suppressed))
            .count();
        assert!(
            failures >= ERROR_THRESHOLD,
            "expected >= {} failures, got {}",
            ERROR_THRESHOLD,
            failures
        );
    }

    #[test]
    fn test_error_rate_no_cooldown_below_threshold() {
        let mut outcomes = Vec::new();
        let now = Instant::now();

        // Fill window with 11 successes and 9 failures → 9 < 10 threshold
        for _ in 0..11 {
            simulate_error_tracking(&mut outcomes, SendOutcome::Success, now);
        }
        for _ in 0..9 {
            let triggered =
                simulate_error_tracking(&mut outcomes, SendOutcome::TransportError, now);
            // Should not trigger since 9 < 10
            if outcomes.len() >= ERROR_WINDOW_SIZE {
                let failures = outcomes
                    .iter()
                    .filter(|(o, _)| !matches!(o, SendOutcome::Success | SendOutcome::Suppressed))
                    .count();
                assert!(
                    failures < ERROR_THRESHOLD,
                    "expected < {} failures, got {}",
                    ERROR_THRESHOLD,
                    failures
                );
                assert!(
                    !triggered,
                    "cooldown must NOT trigger when <10 failures in window"
                );
            }
        }
    }

    #[test]
    fn test_error_rate_window_evicts_old_entries() {
        let mut outcomes = Vec::new();

        // Add 10 failures with old timestamps
        let old = Instant::now() - Duration::from_secs(120);
        for _ in 0..10 {
            // Use the old timestamp as the "now" so they are all added
            simulate_error_tracking(&mut outcomes, SendOutcome::TransportError, old);
        }
        assert_eq!(outcomes.len(), 10, "10 old entries added");

        // Now simulate a new event at a much later time — this triggers eviction
        // of entries whose timestamps are >60s behind `new_now`.
        let new_now = Instant::now();
        simulate_error_tracking(&mut outcomes, SendOutcome::Success, new_now);

        // The 10 old entries (timestamp = old, ~120s before new_now) should be
        // evicted by the retain(... < 60s) clause, leaving only the success.
        assert_eq!(
            outcomes.len(),
            1,
            "old entries must be evicted; only the new success remains"
        );
        assert!(
            matches!(outcomes[0].0, SendOutcome::Success),
            "remaining entry must be Success"
        );
    }

    // ---------------------------------------------------------------------------
    // 7. Edge Cases
    // ---------------------------------------------------------------------------

    #[test]
    fn test_zero_failure_threshold() {
        // failure_threshold = 1 is the minimum; test that even one failure opens
        let cb = CircuitBreaker::new(CircuitBreakerConfig {
            failure_threshold: 1,
            open_duration: Duration::from_secs(60),
            ..Default::default()
        });

        assert_eq!(cb.state(), CircuitState::Closed);
        cb.record_failure();
        assert_eq!(
            cb.state(),
            CircuitState::Open,
            "failure_threshold=1 means one failure opens the circuit"
        );
        assert!(!cb.is_allowed());
    }

    #[test]
    fn test_exponential_backoff_formula() {
        // The formula used in handle_soft_bounce:
        //   2_i64.saturating_pow(job.attempt.min(30) as u32)
        // base_delay * 2^attempt

        let base: i64 = 1; // seconds

        // attempt 0 → 2^0 = 1
        assert_eq!(
            base.saturating_mul(2_i64.saturating_pow(0u32.min(30))),
            1,
            "attempt 0: 2^0 = 1s"
        );

        // attempt 1 → 2^1 = 2
        assert_eq!(
            base.saturating_mul(2_i64.saturating_pow(1u32.min(30))),
            2,
            "attempt 1: 2^1 = 2s"
        );

        // attempt 5 → 2^5 = 32
        assert_eq!(
            base.saturating_mul(2_i64.saturating_pow(5u32.min(30))),
            32,
            "attempt 5: 2^5 = 32s"
        );

        // attempt 29 → 2^29 = 536_870_912
        assert_eq!(
            base.saturating_mul(2_i64.saturating_pow(29u32.min(30))),
            536_870_912,
            "attempt 29: 2^29 = 536_870_912s"
        );

        // attempt 30 → capped at 30: 2^30 = 1_073_741_824
        assert_eq!(
            base.saturating_mul(2_i64.saturating_pow(30u32.min(30))),
            1_073_741_824,
            "attempt 30: 2^30 = 1_073_741_824s (capped)"
        );

        // attempt 31 → still capped at 30: 2^30 = 1_073_741_824
        assert_eq!(
            base.saturating_mul(2_i64.saturating_pow(31u32.min(30))),
            1_073_741_824,
            "attempt 31: capped at 2^30 = 1_073_741_824s"
        );

        // Verify i64::MAX safety: 2^62 fits, 2^63 would overflow
        // The saturating_pow ensures we don't overflow
        assert_eq!(
            2_i64.saturating_pow(62),
            4_611_686_018_427_387_904_i64,
            "2^62 fits in i64"
        );
        assert_eq!(
            2_i64.saturating_pow(63),
            i64::MAX,
            "2^63 saturates to i64::MAX"
        );
    }

    #[test]
    fn test_exponential_backoff_in_context_of_handle_soft_bounce() {
        // Simulate the exact expression from handle_soft_bounce:
        //   let backoff_multiplier = 2_i64.saturating_pow(job.attempt.min(30) as u32);
        //   let retry_at = Utc::now() + chrono::Duration::seconds(
        //       (self.config.base.retry_delay.as_secs() as i64).saturating_mul(backoff_multiplier),
        //   );

        let retry_delay_secs: i64 = 60; // example value

        // attempt 0 → multiplier = 1 → delay = 60 * 1 = 60s
        let attempt: i32 = 0;
        let multiplier = 2_i64.saturating_pow(attempt.min(30) as u32);
        let delay = retry_delay_secs.saturating_mul(multiplier);
        assert_eq!(delay, 60, "attempt 0: delay = 60 * 1 = 60s");

        // attempt 5 → multiplier = 32 → delay = 60 * 32 = 1920s
        let attempt: i32 = 5;
        let multiplier = 2_i64.saturating_pow(attempt.min(30) as u32);
        let delay = retry_delay_secs.saturating_mul(multiplier);
        assert_eq!(delay, 1920, "attempt 5: delay = 60 * 32 = 1920s");

        // attempt 30 → capped at 30 → 2^30 = 1_073_741_824 → saturating_mul
        let attempt: i32 = 30;
        let multiplier = 2_i64.saturating_pow(attempt.min(30) as u32);
        let delay = retry_delay_secs.saturating_mul(multiplier);
        assert_eq!(
            delay,
            60_i64.saturating_mul(1_073_741_824),
            "attempt 30: delay capped at 2^30 * base"
        );
    }

    #[tokio::test]
    async fn test_concurrent_state_transitions() {
        let cb = Arc::new(CircuitBreaker::new(CircuitBreakerConfig {
            failure_threshold: 5,
            open_duration: Duration::from_secs(60),
            success_threshold: 3,
            window_duration: Duration::from_secs(120),
        }));

        let mut handles = Vec::new();

        // Spawn 10 concurrent tasks, each recording failures
        for _ in 0..10 {
            let cb_clone = Arc::clone(&cb);
            handles.push(tokio::spawn(async move {
                cb_clone.record_failure();
            }));
        }

        // Wait for all tasks to complete
        for handle in handles {
            handle.await.expect("concurrent task panicked");
        }

        // With 10 failures and threshold=5, circuit should be Open
        assert_eq!(
            cb.state(),
            CircuitState::Open,
            "concurrent failures should trigger circuit open"
        );
        assert!(!cb.is_allowed());
    }

    #[tokio::test]
    async fn test_concurrent_success_and_failure() {
        let cb = Arc::new(CircuitBreaker::new(CircuitBreakerConfig {
            failure_threshold: 3,
            open_duration: Duration::from_secs(60),
            success_threshold: 2,
            window_duration: Duration::from_secs(120),
        }));

        // First, open the circuit
        cb.record_failure();
        cb.record_failure();
        cb.record_failure();
        assert_eq!(cb.state(), CircuitState::Open);

        // We need to get to Half-Open first. Use a short duration.
        let cb2 = Arc::new(CircuitBreaker::new(CircuitBreakerConfig {
            failure_threshold: 1,
            open_duration: Duration::from_millis(5),
            success_threshold: 3,
            window_duration: Duration::from_secs(120),
        }));

        cb2.record_failure();
        assert_eq!(cb2.state(), CircuitState::Open);
        thread::sleep(Duration::from_millis(10));
        assert!(cb2.is_allowed()); // → Half-Open
        assert_eq!(cb2.state(), CircuitState::HalfOpen);

        // Spawn concurrent successes and a failure in Half-Open
        let mut handles = Vec::new();
        for _ in 0..3 {
            let cb_clone = Arc::clone(&cb2);
            handles.push(tokio::spawn(async move {
                cb_clone.record_success();
            }));
        }
        // And one failure
        let cb_clone = Arc::clone(&cb2);
        handles.push(tokio::spawn(async move {
            cb_clone.record_failure();
        }));

        for handle in handles {
            handle.await.expect("concurrent task panicked");
        }

        // The failure in Half-Open should have reopened the circuit
        // But due to race conditions, if all successes happen first, it might close.
        // Either way, the circuit is in a valid state.
        let state = cb2.state();
        assert!(
            state == CircuitState::Open || state == CircuitState::Closed,
            "concurrent operations in Half-Open must result in a valid state: got {:?}",
            state
        );
    }

    #[tokio::test]
    async fn test_concurrent_is_allowed_and_record_failure() {
        let cb = Arc::new(CircuitBreaker::new(CircuitBreakerConfig {
            failure_threshold: 5,
            open_duration: Duration::from_millis(10),
            success_threshold: 3,
            window_duration: Duration::from_secs(120),
        }));

        // Open the circuit
        for _ in 0..5 {
            cb.record_failure();
        }
        assert_eq!(cb.state(), CircuitState::Open);

        // Wait for open duration
        thread::sleep(Duration::from_millis(20));

        // Concurrently call is_allowed (which transitions to Half-Open) and record_failure
        let cb_clone = Arc::clone(&cb);
        let h1 = tokio::spawn(async move {
            cb_clone.is_allowed(); // may transition to Half-Open
        });

        let cb_clone = Arc::clone(&cb);
        let h2 = tokio::spawn(async move {
            cb_clone.record_failure(); // records in Open or Half-Open
        });

        h1.await.expect("task panicked");
        h2.await.expect("task panicked");

        // The circuit must be in a valid state
        let state = cb.state();
        assert!(
            state == CircuitState::Open || state == CircuitState::HalfOpen,
            "concurrent is_allowed + record_failure must produce valid state: got {:?}",
            state
        );
    }
}
