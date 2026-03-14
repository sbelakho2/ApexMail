//! Email processor implementation.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use chrono::Utc;
use moka::sync::Cache;
use std::sync::{Mutex, RwLock};
use sqlx::PgPool;
use tokio::sync::Notify;
use tokio::time::sleep;
use tracing::{debug, error, info, warn};

use super::tracking::{add_tracking_pixel, rewrite_links};
use super::transport::{create_transport_from_config, EmailTransport};
use super::types::{
    Attachment, CachedSuppression, Domain, DkimConfig, EmailJob, PreparedEmail,
    SendOutcome, SendResult, WarmupLimits,
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

    // Warmup counters (domain_id -> today's send count)
    warmup_counters: RwLock<HashMap<String, i64>>,
}

impl EmailProcessor {
    /// Create a new email processor.
    ///
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
            warmup_counters: RwLock::new(HashMap::new()),
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
            let available_slots =
                self.config.base.concurrency.saturating_sub(self.active_jobs.load(Ordering::SeqCst));
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

                    // Fix #94: Process jobs concurrently using tokio::spawn
                    let mut handles = Vec::with_capacity(jobs.len());
                    for job in jobs {
                        let suppression = suppressions.get(&format!("{}:{}", job.tenant_id, job.to));
                        if let Some(reason) = suppression {
                            // Skip suppressed recipients
                            if let Err(e) = self.handle_suppressed(&job, reason).await {
                                error!(job_id = %job.id, error = %e, "Failed to handle suppression");
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
        // Fix #63: Use saturating_as to prevent truncation on large timeouts.
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
                // Fix #64: Properly handle DB errors - fail safe by treating as suppressed
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
                        // Fail safe: treat all uncached emails as suppressed
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
            return Err(ProcessorError::CircuitOpen("SMTP circuit breaker open".into()));
        }

        // Check warmup limits
        if self.config.warmup.enabled {
            if !self.check_warmup_limit(job).await? {
                self.requeue_job(job, "warmup_limit").await?;
                return Ok(());
            }
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
    async fn check_warmup_limit(&self, job: &EmailJob) -> ProcessorResult<bool> {
        let domain = self.get_domain(&job.domain_id, &job.tenant_id).await?;

        if !domain.warmup_enabled {
            return Ok(true);
        }

        let limits = WarmupLimits::for_day(domain.warmup_day);

        // Get and increment current count
        let mut counters = self.warmup_counters.write().unwrap_or_else(|e| e.into_inner());
        let current = counters.entry(job.domain_id.clone()).or_insert(0);

        if *current >= limits.daily_limit {
            return Ok(false);
        }

        *current += 1;
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

        // Fix #77: Protected headers that cannot be overwritten by custom headers
        const PROTECTED_HEADERS: &[&str] = &[
            "from", "to", "cc", "bcc", "subject", "date", "message-id",
            "dkim-signature", "arc-seal", "arc-message-signature", "arc-authentication-results",
            "return-path", "received", "received-spf", "authentication-results",
            "x-apexmail-message-id", "x-apexmail-tenant-id", "x-apexmail-campaign-id",
            "x-originating-ip", "x-mailer", "mime-version", "content-type", "content-transfer-encoding",
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
        // Fix #99: Consult pre-loaded dkim_keys map as fallback when domain doesn't have DKIM config
        let dkim = if self.config.dkim.enabled {
            domain.dkim_private_key.as_ref().map(|key| DkimConfig {
                selector: domain
                    .dkim_selector
                    .clone()
                    .unwrap_or_else(|| self.config.dkim.selector.clone()),
                domain: domain.domain.clone(),
                private_key: key.clone(),
            }).or_else(|| {
                // Fallback: check pre-loaded dkim_keys map
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
                            content_type: obj
                                .get("contentType")?
                                .as_str()?
                                .to_string(),
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
    async fn handle_soft_bounce(&self, job: &EmailJob, error: &ProcessorError) -> ProcessorResult<()> {
        if job.attempt >= self.config.base.max_retries as i32 {
            return self.handle_hard_bounce(job, error).await;
        }

        let next_attempt = job.attempt + 1;
        // Fix #65: Use saturating_pow to prevent overflow for large attempt counts.
        let backoff_multiplier = 2_i64.saturating_pow(job.attempt.min(30) as u32);
        let retry_at = Utc::now() + chrono::Duration::seconds(
            (self.config.base.retry_delay.as_secs() as i64).saturating_mul(backoff_multiplier)
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
    async fn handle_hard_bounce(&self, job: &EmailJob, error: &ProcessorError) -> ProcessorResult<()> {
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
        .bind(serde_json::to_value(reason)
            .map_err(|e| sqlx::Error::Protocol(format!("serialization: {e}")))?)
        .bind(&job.id)
        .execute(&self.db)
        .await?;

        Ok(())
    }

    /// Record send outcome for error rate tracking.
    fn record_outcome(&self, outcome: SendOutcome) {
        let now = Instant::now();

        let mut outcomes = self.recent_outcomes.lock().unwrap_or_else(|e| e.into_inner());
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
                let cooldown_until = Utc::now().timestamp_millis() + ERROR_COOLDOWN.as_millis() as i64;
                self.error_cooldown_until.store(cooldown_until, Ordering::SeqCst);
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
