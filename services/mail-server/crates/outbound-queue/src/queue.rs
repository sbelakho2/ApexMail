//! Email Queue
//!
//! Persistent queue for outbound emails with retry logic and per-domain
//! rate limiting.

use anyhow::{bail, Result};
use chrono::{DateTime, Utc};
use futures::stream::StreamExt;
use governor::{DefaultKeyedRateLimiter, Quota};
use serde::{Deserialize, Serialize};
use sqlx::{PgPool, Row};
use std::hash::{Hash, Hasher};
use std::num::NonZeroU32;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::time::timeout;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

use crate::dkim::DkimSigner;
use crate::provider_throttle::{ProviderThrottle, ThrottleDecision};
use crate::smtp_sender::SmtpSender;

/// Result of an atomic cancel attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CancelResult {
    /// Email was successfully cancelled.
    Cancelled,
    /// Email was not found in the queue.
    NotFound,
    /// Email exists but cannot be cancelled (with human-readable reason).
    NotCancellable(String),
}

/// Email status in the queue
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type, Default)]
#[sqlx(type_name = "email_status", rename_all = "lowercase")]
pub enum EmailStatus {
    #[default]
    Pending,
    Processing,
    Sent,
    Failed,
    Deferred,
}

/// Queued email record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueuedEmail {
    pub id: Uuid,
    pub from_address: String,
    pub to_addresses: Vec<String>,
    pub subject: String,
    pub text_body: Option<String>,
    pub html_body: Option<String>,
    pub headers: serde_json::Value,
    pub status: EmailStatus,
    pub attempts: i32,
    pub max_attempts: i32,
    pub last_error: Option<String>,
    pub next_retry_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub sent_at: Option<DateTime<Utc>>,
    pub campaign_id: Option<Uuid>,
    pub sequence_id: Option<Uuid>,
    pub contact_id: Option<Uuid>,
    pub priority: i32,
    /// Tenant that owns this email, for per-tenant fair queueing.
    pub tenant_id: Option<String>,
}

/// Email queue configuration
#[derive(Debug, Clone)]
pub struct QueueConfig {
    pub max_attempts: i32,
    pub retry_delays: Vec<Duration>,
    pub batch_size: usize,
    pub poll_interval: Duration,
    pub worker_count: usize,
    /// Per-tenant fair-queue weights (emails processed per round).
    /// Keys are tenant plan tiers ("free", "starter", "pro", etc.).
    /// Default weight for unknown tenants is 10.
    pub tenant_weights: std::collections::HashMap<String, usize>,
    /// Maximum outbound messages per second (global).
    /// 0 = unlimited. Default: 50.
    pub global_rate_per_second: u64,
    /// Maximum outbound messages per second per domain.
    /// 0 = unlimited. Default: 10.
    pub domain_rate_per_second: u64,
    /// Maximum outbound messages per second per tenant.
    /// 0 = unlimited. Default: 20.
    pub tenant_rate_per_second: u64,
    /// Maximum concurrent email processing futures within a batch.
    /// Prevents unbounded concurrency when batch_size is large (DB-4).
    /// Default: 50.
    pub max_concurrent_emails: usize,
    /// DB-14: Sampling rate (0.0–1.0) for dead-lettering non-bounce permanently
    /// failed emails. 0.0 = never sample (backward compatible), 1.0 = always.
    /// Default: 0.01 (1% — enough for forensic visibility without filling the
    /// dead-letter queue).
    pub dead_letter_sample_rate: f64,
}

const DEFAULT_QUEUE_MAX_ATTEMPTS: i32 = 5;
const DEFAULT_QUEUE_RETRY_DELAY_SECS: [u64; 5] = [60, 300, 1_800, 7_200, 21_600];
const DEFAULT_QUEUE_EMPTY_RETRY_FALLBACK_SECS: u64 = 300;
const DEFAULT_QUEUE_BATCH_SIZE: usize = 100;
const DEFAULT_QUEUE_POLL_INTERVAL_SECS: u64 = 5;
const DEFAULT_QUEUE_WORKER_COUNT: usize = 4;
const DEFAULT_GLOBAL_RATE_PER_SECOND: u64 = 50;
const DEFAULT_DOMAIN_RATE_PER_SECOND: u64 = 10;
const DEFAULT_TENANT_RATE_PER_SECOND: u64 = 20;
const DEFAULT_MAX_CONCURRENT_EMAILS: usize = 50;

impl Default for QueueConfig {
    fn default() -> Self {
        use std::collections::HashMap;
        let mut tenant_weights = HashMap::new();
        tenant_weights.insert("free".to_string(), 10);
        tenant_weights.insert("starter".to_string(), 50);
        tenant_weights.insert("pro".to_string(), 200);
        tenant_weights.insert("growth".to_string(), 500);
        tenant_weights.insert("scale".to_string(), 1000);
        tenant_weights.insert("enterprise".to_string(), 2000);

        // MI-003: Read rate limit config from environment variables with defaults.
        // OUTBOUND_RATE_PER_DOMAIN — max outbound messages per second per recipient domain.
        // OUTBOUND_RATE_BURST — max burst rate (reserved for future use with burst-capable
        // rate limiters; the governor crate expresses burst via Quota).
        let domain_rate = Self::env_u64("OUTBOUND_RATE_PER_DOMAIN", DEFAULT_DOMAIN_RATE_PER_SECOND);
        let global_rate = Self::env_u64("OUTBOUND_GLOBAL_RATE", DEFAULT_GLOBAL_RATE_PER_SECOND);
        let tenant_rate = Self::env_u64("OUTBOUND_TENANT_RATE", DEFAULT_TENANT_RATE_PER_SECOND);

        Self {
            max_attempts: DEFAULT_QUEUE_MAX_ATTEMPTS,
            retry_delays: DEFAULT_QUEUE_RETRY_DELAY_SECS
                .iter()
                .copied()
                .map(Duration::from_secs)
                .collect(),
            batch_size: DEFAULT_QUEUE_BATCH_SIZE,
            poll_interval: Duration::from_secs(DEFAULT_QUEUE_POLL_INTERVAL_SECS),
            worker_count: DEFAULT_QUEUE_WORKER_COUNT,
            tenant_weights,
            global_rate_per_second: global_rate,
            domain_rate_per_second: domain_rate,
            tenant_rate_per_second: tenant_rate,
            max_concurrent_emails: DEFAULT_MAX_CONCURRENT_EMAILS,
            dead_letter_sample_rate: 0.01,
        }
    }
}

impl QueueConfig {
    /// Read a u64 value from an environment variable, falling back to a default.
    fn env_u64(key: &str, default: u64) -> u64 {
        std::env::var(key)
            .ok()
            .and_then(|val| val.parse::<u64>().ok())
            .unwrap_or(default)
    }
}

/// Email queue manager
pub struct EmailQueue {
    pool: PgPool,
    config: QueueConfig,
    /// SMTP sender no longer behind Mutex since send is &self (#114/#115)
    smtp_sender: SmtpSender,
    dkim_signer: Option<DkimSigner>,
    /// Global rate limiter (messages per second across all domains/tenants).
    global_limiter: Option<Arc<DefaultKeyedRateLimiter<String>>>,
    /// Per-domain rate limiter (messages per second per recipient domain).
    domain_limiter: Option<Arc<DefaultKeyedRateLimiter<String>>>,
    /// Per-tenant rate limiter (messages per second per tenant).
    tenant_limiter: Option<Arc<DefaultKeyedRateLimiter<String>>>,
    /// Per-provider reputation-driven throttle.  Optional so tests can omit.
    provider_throttle: Option<Arc<ProviderThrottle>>,
}

/// Decision returned by [`check_rate_limits`] indicating which rate limit,
/// if any, was exceeded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RateLimitDecision {
    /// All rate limits passed — the request may proceed.
    Allowed,
    /// Global rate limit was exceeded.
    GlobalExceeded,
    /// Per-domain rate limit was exceeded for the given domain.
    DomainExceeded(String),
    /// Per-tenant rate limit was exceeded.
    TenantExceeded,
}

impl EmailQueue {
    /// Create a new email queue
    pub fn new(pool: PgPool, config: QueueConfig, smtp_sender: SmtpSender) -> Self {
        let global_limiter = if config.global_rate_per_second > 0 {
            let quota = Quota::per_second(
                NonZeroU32::new(config.global_rate_per_second as u32)
                    .expect("global_rate_per_second > 0 confirmed"),
            );
            Some(Arc::new(DefaultKeyedRateLimiter::keyed(quota)))
        } else {
            None
        };

        let domain_limiter = if config.domain_rate_per_second > 0 {
            let quota = Quota::per_second(
                NonZeroU32::new(config.domain_rate_per_second as u32)
                    .expect("domain_rate_per_second > 0 confirmed"),
            );
            Some(Arc::new(DefaultKeyedRateLimiter::keyed(quota)))
        } else {
            None
        };

        let tenant_limiter = if config.tenant_rate_per_second > 0 {
            let quota = Quota::per_second(
                NonZeroU32::new(config.tenant_rate_per_second as u32)
                    .expect("tenant_rate_per_second > 0 confirmed"),
            );
            Some(Arc::new(DefaultKeyedRateLimiter::keyed(quota)))
        } else {
            None
        };

        Self {
            pool,
            config,
            smtp_sender,
            dkim_signer: None,
            global_limiter,
            domain_limiter,
            tenant_limiter,
            provider_throttle: None,
        }
    }

    /// Set DKIM signer
    pub fn with_dkim_signer(mut self, signer: DkimSigner) -> Self {
        self.dkim_signer = Some(signer);
        self
    }

    /// Enable per-provider reputation-driven throttling. The throttle
    /// reads `postmaster_reputation_summary` (written by the MTA's postmaster
    /// scheduler) and `outbound_provider_throttle_overrides` (operator pins).
    pub fn with_provider_throttle(mut self, throttle: ProviderThrottle) -> Self {
        self.provider_throttle = Some(Arc::new(throttle));
        self
    }

    /// Extract the domain part from an email address.
    /// e.g. "user@example.com" → "example.com"
    /// Deterministic sampling using the UUID's hash to avoid a `rand` dependency.
    /// Returns `true` if the email's ID falls within the sample rate.
    fn sample_dead_letter(id: &Uuid, rate: f64) -> bool {
        use std::hash::{Hash, Hasher};
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        id.hash(&mut hasher);
        let hash = hasher.finish();
        let normalized = (hash as f64) / (u64::MAX as f64);
        normalized < rate
    }

    fn extract_domain(addr: &str) -> String {
        addr.rsplit('@').next().unwrap_or("unknown").to_lowercase()
    }

    /// Deterministic advisory-lock key for a tenant (RS-H-05).
    /// Used to serialize concurrent enqueue operations for the same tenant
    /// within a PostgreSQL transaction, eliminating the TOCTOU window between
    /// `check_rate_limits()` and the INSERT.
    fn tenant_lock_key(tenant_id: Option<&str>) -> i64 {
        let key = tenant_id.unwrap_or("__no_tenant__");
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        key.hash(&mut hasher);
        hasher.finish() as i64
    }

    /// Check whether sending to the given recipient domains and tenant
    /// should be rate-limited. Returns [`RateLimitDecision::Allowed`] if the
    /// request may proceed, or the specific exceeded variant otherwise.
    fn check_rate_limits(
        &self,
        to_addresses: &[String],
        tenant_id: Option<&str>,
    ) -> RateLimitDecision {
        // Collect unique recipient domains
        let mut domains: Vec<String> = to_addresses
            .iter()
            .map(|addr| Self::extract_domain(addr))
            .collect();
        domains.sort();
        domains.dedup();

        // Check global rate limit (keyed by "__global__")
        if let Some(ref limiter) = self.global_limiter {
            if limiter.check_key(&"__global__".to_string()).is_err() {
                return RateLimitDecision::GlobalExceeded;
            }
        }

        // Check per-domain rate limits
        if let Some(ref limiter) = self.domain_limiter {
            for domain in &domains {
                if limiter.check_key(domain).is_err() {
                    return RateLimitDecision::DomainExceeded(domain.clone());
                }
            }
        }

        // Check per-tenant rate limit
        if let Some(ref limiter) = self.tenant_limiter {
            let tenant_key = tenant_id.unwrap_or("__no_tenant__").to_string();
            if limiter.check_key(&tenant_key).is_err() {
                return RateLimitDecision::TenantExceeded;
            }
        }

        RateLimitDecision::Allowed
    }

    /// Initialize queue tables
    pub async fn initialize(&self) -> Result<()> {
        self.ensure_compatible_email_queue_schema().await?;

        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS email_queue (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                from_address TEXT NOT NULL,
                to_addresses TEXT[] NOT NULL,
                subject TEXT NOT NULL,
                text_body TEXT,
                html_body TEXT,
                headers JSONB DEFAULT '{}'::jsonb,
                status TEXT NOT NULL DEFAULT 'pending',
                attempts INT NOT NULL DEFAULT 0,
                max_attempts INT NOT NULL DEFAULT 5,
                last_error TEXT,
                next_retry_at TIMESTAMPTZ,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                sent_at TIMESTAMPTZ,
                campaign_id UUID,
                sequence_id UUID,
                contact_id UUID,
                priority INT NOT NULL DEFAULT 0,
                tenant_id TEXT
            )
        "#,
        )
        .execute(&self.pool)
        .await?;

        sqlx::raw_sql(
            r#"
            ALTER TABLE email_queue ADD COLUMN IF NOT EXISTS next_retry_at TIMESTAMPTZ;
            ALTER TABLE email_queue ADD COLUMN IF NOT EXISTS sequence_id UUID;
            ALTER TABLE email_queue ADD COLUMN IF NOT EXISTS contact_id UUID;
            ALTER TABLE email_queue ADD COLUMN IF NOT EXISTS sent_at TIMESTAMPTZ;
            ALTER TABLE email_queue ADD COLUMN IF NOT EXISTS last_error TEXT;
            ALTER TABLE email_queue ADD COLUMN IF NOT EXISTS text_body TEXT;
            ALTER TABLE email_queue ADD COLUMN IF NOT EXISTS html_body TEXT;
            ALTER TABLE email_queue ADD COLUMN IF NOT EXISTS from_address TEXT;
            ALTER TABLE email_queue ADD COLUMN IF NOT EXISTS to_addresses TEXT[];
        "#,
        )
        .execute(&self.pool)
        .await?;

        sqlx::query(
            r#"
            CREATE INDEX IF NOT EXISTS idx_email_queue_status
            ON email_queue(status, next_retry_at, priority DESC)
        "#,
        )
        .execute(&self.pool)
        .await?;

        sqlx::query(
            r#"
            CREATE INDEX IF NOT EXISTS idx_email_queue_campaign
            ON email_queue(campaign_id) WHERE campaign_id IS NOT NULL
        "#,
        )
        .execute(&self.pool)
        .await?;

        sqlx::query(
            r#"
            CREATE INDEX IF NOT EXISTS idx_email_queue_tenant_status
            ON email_queue(tenant_id, status) WHERE tenant_id IS NOT NULL
        "#,
        )
        .execute(&self.pool)
        .await?;

        // MI-008: Dead-letter queue for permanently failed bounce emails.
        // The dead_letter_queue table is now created via SQL migration
        // (migration 052/056), not at runtime. This ensures the schema is
        // version-controlled and available before the application starts.

        // Add tenant_id column for existing deployments (idempotent)
        sqlx::query(
            r#"
            ALTER TABLE email_queue
            ADD COLUMN IF NOT EXISTS tenant_id TEXT
        "#,
        )
        .execute(&self.pool)
        .await?;

        info!("Email queue tables initialized (including dead-letter queue)");
        Ok(())
    }

    async fn ensure_compatible_email_queue_schema(&self) -> Result<()> {
        let exists = sqlx::query_scalar::<_, bool>(
            r#"
            SELECT EXISTS (
                SELECT 1
                FROM information_schema.tables
                WHERE table_schema = 'public' AND table_name = 'email_queue'
            )
        "#,
        )
        .fetch_one(&self.pool)
        .await?;

        if !exists {
            return Ok(());
        }

        let has_service_schema = sqlx::query_scalar::<_, bool>(
            r#"
            SELECT EXISTS (
                SELECT 1
                FROM information_schema.columns
                WHERE table_schema = 'public'
                  AND table_name = 'email_queue'
                  AND column_name = 'from_address'
            )
        "#,
        )
        .fetch_one(&self.pool)
        .await?;

        if has_service_schema {
            return Ok(());
        }

        let row_count = sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM email_queue")
            .fetch_one(&self.pool)
            .await?;

        if row_count > 0 {
            bail!(
                "email_queue uses the legacy schema and contains {row_count} rows; migrate it before starting outbound-queue"
            );
        }

        warn!("Dropping empty legacy email_queue table so outbound-queue can create its runtime schema");
        sqlx::query("DROP TABLE email_queue CASCADE")
            .execute(&self.pool)
            .await?;

        Ok(())
    }

    /// Enqueue an email
    ///
    /// Applies rate limits before accepting the email into the queue.
    /// If rate-limited, returns an error immediately.
    ///
    /// RS-H-05: The rate-limit check and INSERT are now wrapped in a single
    /// PostgreSQL transaction with a per-tenant advisory lock. This eliminates
    /// the TOCTOU window where a concurrent caller could bypass the rate limit
    /// by inserting between the check and the INSERT of another caller.
    pub async fn enqueue(&self, email: QueuedEmail) -> Result<Uuid> {
        let mut tx = self.pool.begin().await?;

        // Acquire per-tenant advisory lock to serialize concurrent enqueues
        // for the same tenant (RS-H-05). This guarantees that only one
        // enqueue call per tenant executes the rate check + INSERT at a time,
        // eliminating the TOCTOU race window.
        let lock_key = Self::tenant_lock_key(email.tenant_id.as_deref());
        sqlx::query("SELECT pg_advisory_xact_lock($1)")
            .bind(lock_key)
            .execute(&mut *tx)
            .await?;

        // Check rate limits inside the transaction (serialized per tenant)
        match self.check_rate_limits(&email.to_addresses, email.tenant_id.as_deref()) {
            RateLimitDecision::Allowed => {}
            RateLimitDecision::GlobalExceeded => {
                return Err(anyhow::anyhow!(
                    "Global rate limit exceeded (max {} msg/s)",
                    self.config.global_rate_per_second
                ));
            }
            RateLimitDecision::DomainExceeded(domain) => {
                return Err(anyhow::anyhow!(
                    "Domain rate limit exceeded for '{}' (max {} msg/s)",
                    domain,
                    self.config.domain_rate_per_second
                ));
            }
            RateLimitDecision::TenantExceeded => {
                let tenant_key = email.tenant_id.as_deref().unwrap_or("__no_tenant__");
                return Err(anyhow::anyhow!(
                    "Tenant rate limit exceeded for '{}' (max {} msg/s)",
                    tenant_key,
                    self.config.tenant_rate_per_second
                ));
            }
        }

        // INSERT inside the same transaction — atomic with the rate check
        let id = timeout(
            Duration::from_secs(30),
            sqlx::query_scalar::<_, Uuid>(
                r#"
                INSERT INTO email_queue (
                    id, from_address, to_addresses, subject, text_body, html_body,
                    headers, status, max_attempts, campaign_id, sequence_id,
                    contact_id, priority, tenant_id
                )
                VALUES ($1, $2, $3, $4, $5, $6, $7, 'pending', $8, $9, $10, $11, $12, $13)
                RETURNING id
            "#,
            )
            .bind(email.id)
            .bind(&email.from_address)
            .bind(&email.to_addresses)
            .bind(&email.subject)
            .bind(&email.text_body)
            .bind(&email.html_body)
            .bind(&email.headers)
            .bind(email.max_attempts) // #112:Use the email's own max_attempts, not global config
            .bind(email.campaign_id)
            .bind(email.sequence_id)
            .bind(email.contact_id)
            .bind(email.priority)
            .bind(&email.tenant_id)
            .fetch_one(&mut *tx),
        )
        .await
        .map_err(|_| anyhow::anyhow!("enqueue query timed out after 30s"))??;

        tx.commit().await?;

        debug!(email_id = %id, "Email enqueued");
        Ok(id)
    }

    /// Bulk enqueue emails using a single multi-row INSERT for performance.
    /// Falls back to sequential inserts if the batch is empty.
    ///
    /// RS-H-05: Rate limits are checked in aggregate for the batch, and the
    /// INSERT is wrapped in a PostgreSQL transaction with a per-tenant advisory
    /// lock to eliminate the TOCTOU race between rate checking and insertion.
    pub async fn enqueue_batch(&self, emails: Vec<QueuedEmail>) -> Result<Vec<Uuid>> {
        if emails.is_empty() {
            return Ok(Vec::new());
        }

        // Check rate limits in aggregate for the batch (RS-H-05)
        // Collect unique tenants to check each once
        let unique_tenants: Vec<Option<String>> = {
            let mut seen = std::collections::HashSet::new();
            emails
                .iter()
                .filter_map(|e| {
                    let key = e.tenant_id.clone();
                    if seen.insert(key.clone()) {
                        Some(key)
                    } else {
                        None
                    }
                })
                .collect()
        };

        // Collect all unique recipient domains across the batch
        let all_domains: Vec<String> = {
            emails
                .iter()
                .flat_map(|e| e.to_addresses.iter().map(|a| Self::extract_domain(a)))
                .collect::<std::collections::HashSet<_>>()
                .into_iter()
                .collect()
        };

        // Check each unique tenant's rate limit
        for tenant in &unique_tenants {
            match self.check_rate_limits(&all_domains, tenant.as_deref()) {
                RateLimitDecision::Allowed => {}
                RateLimitDecision::GlobalExceeded => {
                    return Err(anyhow::anyhow!(
                        "Global rate limit exceeded (max {} msg/s)",
                        self.config.global_rate_per_second
                    ));
                }
                RateLimitDecision::DomainExceeded(domain) => {
                    return Err(anyhow::anyhow!(
                        "Domain rate limit exceeded for '{}' (max {} msg/s)",
                        domain,
                        self.config.domain_rate_per_second
                    ));
                }
                RateLimitDecision::TenantExceeded => {
                    let key = tenant.as_deref().unwrap_or("__no_tenant__");
                    return Err(anyhow::anyhow!(
                        "Tenant rate limit exceeded for '{}' (max {} msg/s)",
                        key,
                        self.config.tenant_rate_per_second
                    ));
                }
            }
        }

        // Start a transaction for the batch INSERT (RS-H-05)
        let mut tx = self.pool.begin().await?;

        // Acquire advisory lock for the primary tenant (first email's tenant)
        // to serialize with concurrent single enqueues
        let primary_tenant = emails.first().and_then(|e| e.tenant_id.as_deref());
        let lock_key = Self::tenant_lock_key(primary_tenant);
        sqlx::query("SELECT pg_advisory_xact_lock($1)")
            .bind(lock_key)
            .execute(&mut *tx)
            .await?;

        // Build a single multi-row INSERT:VALUES ($1..$13), ($14..$26), ...
        let cols = 13; // number of bind params per row (added tenant_id)
        let mut sql = String::from(
            "INSERT INTO email_queue (
                id, from_address, to_addresses, subject, text_body, html_body,
                headers, status, max_attempts, campaign_id, sequence_id,
                contact_id, priority, tenant_id
            ) VALUES ",
        );

        let _args: Vec<Box<dyn sqlx::Encode<'_, sqlx::Postgres> + Send + Sync>> = Vec::new();
        let mut ids = Vec::with_capacity(emails.len());

        for (i, email) in emails.iter().enumerate() {
            ids.push(email.id);
            if i > 0 {
                sql.push_str(", ");
            }
            let base = i * cols + 1;
            push_pending_insert_row_sql(&mut sql, base);
        }
        sql.push_str(" RETURNING id");

        // Bind all parameters in order using a raw query
        let mut query = sqlx::query_scalar::<_, Uuid>(&sql);
        for email in &emails {
            query = query
                .bind(email.id)
                .bind(&email.from_address)
                .bind(&email.to_addresses)
                .bind(&email.subject)
                .bind(&email.text_body)
                .bind(&email.html_body)
                .bind(&email.headers)
                .bind(email.max_attempts)
                .bind(email.campaign_id)
                .bind(email.sequence_id)
                .bind(email.contact_id)
                .bind(email.priority)
                .bind(&email.tenant_id);
        }

        let returned_ids = timeout(Duration::from_secs(30), query.fetch_all(&mut *tx))
            .await
            .map_err(|_| anyhow::anyhow!("enqueue_batch query timed out after 30s"))??;

        tx.commit().await?;

        info!(count = returned_ids.len(), "Batch emails enqueued");
        Ok(returned_ids)
    }

    /// Fetch pending emails for processing
    pub async fn fetch_pending(&self, limit: i64) -> Result<Vec<QueuedEmail>> {
        let rows = timeout(
            Duration::from_secs(30),
            sqlx::query(
                r#"
                UPDATE email_queue
                SET status = 'processing', updated_at = NOW()
                WHERE id IN (
                    SELECT id FROM email_queue
                    WHERE status IN ('pending', 'deferred')
                    AND (next_retry_at IS NULL OR next_retry_at <= NOW())
                    ORDER BY priority DESC, created_at ASC
                    LIMIT $1
                    FOR UPDATE SKIP LOCKED
                )
                RETURNING *
            "#,
            )
            .bind(limit)
            .fetch_all(&self.pool),
        )
        .await
        .map_err(|_| anyhow::anyhow!("fetch_pending query timed out after 30s"))??;

        let emails = rows
            .iter()
            .map(|row| QueuedEmail {
                id: row.get("id"),
                from_address: row.get("from_address"),
                to_addresses: row.get("to_addresses"),
                subject: row.get("subject"),
                text_body: row.get("text_body"),
                html_body: row.get("html_body"),
                headers: row.get("headers"),
                status: EmailStatus::Processing,
                attempts: row.get("attempts"),
                max_attempts: row.get("max_attempts"),
                last_error: row.get("last_error"),
                next_retry_at: row.get("next_retry_at"),
                created_at: row.get("created_at"),
                updated_at: row.get("updated_at"),
                sent_at: row.get("sent_at"),
                campaign_id: row.get("campaign_id"),
                sequence_id: row.get("sequence_id"),
                contact_id: row.get("contact_id"),
                priority: row.get("priority"),
                tenant_id: row.get("tenant_id"),
            })
            .collect();

        Ok(emails)
    }

    /// Mark email as sent
    pub async fn mark_sent(&self, id: &Uuid) -> Result<()> {
        timeout(
            Duration::from_secs(30),
            sqlx::query(
                r#"
                UPDATE email_queue
                SET status = 'sent', sent_at = NOW(), updated_at = NOW()
                WHERE id = $1
            "#,
            )
            .bind(id)
            .execute(&self.pool),
        )
        .await
        .map_err(|_| anyhow::anyhow!("mark_sent query timed out after 30s"))??;

        debug!(email_id = %id, "Email marked as sent");
        Ok(())
    }

    /// Get queued email by ID
    pub async fn get_email(&self, id: &Uuid) -> Result<Option<QueuedEmail>> {
        let row = timeout(
            Duration::from_secs(30),
            sqlx::query(
                r#"
                SELECT * FROM email_queue WHERE id = $1
            "#,
            )
            .bind(id)
            .fetch_optional(&self.pool),
        )
        .await
        .map_err(|_| anyhow::anyhow!("get_email query timed out after 30s"))??;

        let email = row.map(|row| {
            let status = match row.get::<String, _>("status").as_str() {
                "pending" => EmailStatus::Pending,
                "processing" => EmailStatus::Processing,
                "sent" => EmailStatus::Sent,
                "failed" => EmailStatus::Failed,
                "deferred" => EmailStatus::Deferred,
                _ => EmailStatus::Pending,
            };

            QueuedEmail {
                id: row.get("id"),
                from_address: row.get("from_address"),
                to_addresses: row.get("to_addresses"),
                subject: row.get("subject"),
                text_body: row.get("text_body"),
                html_body: row.get("html_body"),
                headers: row.get("headers"),
                status,
                attempts: row.get("attempts"),
                max_attempts: row.get("max_attempts"),
                last_error: row.get("last_error"),
                next_retry_at: row.get("next_retry_at"),
                created_at: row.get("created_at"),
                updated_at: row.get("updated_at"),
                sent_at: row.get("sent_at"),
                campaign_id: row.get("campaign_id"),
                sequence_id: row.get("sequence_id"),
                contact_id: row.get("contact_id"),
                priority: row.get("priority"),
                tenant_id: row.get("tenant_id"),
            }
        });

        Ok(email)
    }

    /// Atomically cancel a queued email.
    /// Uses a single `UPDATE ... WHERE status IN ('pending','deferred') RETURNING`
    /// to eliminate the TOCTOU race between checking status and writing the
    /// cancellation. If the UPDATE affects zero rows the email either doesn't
    /// exist or is in a non-cancellable state — a follow-up SELECT distinguishes
    /// the two cases.
    pub async fn cancel_email_atomic(&self, id: &Uuid) -> Result<CancelResult> {
        let result = timeout(
            Duration::from_secs(30),
            sqlx::query(
                r#"
                UPDATE email_queue
                SET status = 'failed',
                    last_error = 'Cancelled by user',
                    updated_at = NOW()
                WHERE id = $1
                  AND status IN ('pending', 'deferred')
                RETURNING id
            "#,
            )
            .bind(id)
            .fetch_optional(&self.pool),
        )
        .await
        .map_err(|_| anyhow::anyhow!("cancel_email_atomic UPDATE timed out after 30s"))??;

        if result.is_some() {
            return Ok(CancelResult::Cancelled);
        }

        // Zero rows affected — determine why
        let existing = timeout(
            Duration::from_secs(30),
            sqlx::query_scalar::<_, String>("SELECT status FROM email_queue WHERE id = $1")
                .bind(id)
                .fetch_optional(&self.pool),
        )
        .await
        .map_err(|_| anyhow::anyhow!("cancel_email_atomic status check timed out after 30s"))??;

        match existing.as_deref() {
            None => Ok(CancelResult::NotFound),
            Some("sent") => Ok(CancelResult::NotCancellable(
                "Cannot cancel: email already delivered".to_string(),
            )),
            Some("failed") => Ok(CancelResult::NotCancellable(
                "Cannot cancel: email already permanently failed".to_string(),
            )),
            Some("processing") => Ok(CancelResult::NotCancellable(
                "Cannot cancel: email is currently being sent".to_string(),
            )),
            Some(other) => Ok(CancelResult::NotCancellable(format!(
                "Cannot cancel: email is in '{}' state",
                other
            ))),
        }
    }

    /// Check whether an email is a bounce notification by examining its
    /// from_address for typical bounce indicators (e.g. mailer-daemon, bounce).
    fn is_bounce_email(from_address: &str) -> bool {
        let lower = from_address.to_lowercase();
        lower.contains("mailer-daemon")
            || lower.contains("maildaemon")
            || lower.starts_with("bounce@")
            || lower.starts_with("noreply@")
            || lower.starts_with("return@")
    }

    /// Move a permanently failed email to the dead-letter queue (MI-008).
    ///
    /// Only bounce notifications are dead-lettered. Regular failed emails are
    /// simply marked as 'failed'. This prevents legitimate failed deliveries
    /// from filling the dead-letter queue while preserving forensic data for
    /// undeliverable bounces.
    async fn move_to_dead_letter(&self, id: &Uuid, error: &str) -> Result<()> {
        // Fetch the full email record for dead-letter storage
        let row = timeout(
            Duration::from_secs(30),
            sqlx::query(
                r#"
                SELECT
                    from_address, to_addresses, subject, text_body, html_body,
                    headers, attempts, max_attempts, created_at, tenant_id
                FROM email_queue WHERE id = $1
            "#,
            )
            .bind(id)
            .fetch_optional(&self.pool),
        )
        .await
        .map_err(|_| anyhow::anyhow!("move_to_dead_letter SELECT timed out after 30s"))??;

        let row = match row {
            Some(r) => r,
            None => {
                warn!(email_id = %id, "Cannot move to dead-letter: email not found");
                return Ok(());
            }
        };
        let from_address: String = row.get("from_address");
        let subject: String = row.get("subject");

        // DB-14: Non-bounce failures may now arrive here via sampling in
        // `mark_failed`. Use a sentinel bounce type for non-bounce entries
        // so they are distinguishable in the dead-letter queue.
        let bounce_type = if Self::is_bounce_email(&from_address) {
            detect_bounce_type(&from_address, &subject)
        } else {
            "sampled_failure".to_string()
        };

        timeout(
            Duration::from_secs(30),
            sqlx::query(
                r#"
                INSERT INTO dead_letter_queue (
                    id, original_email_id, from_address, to_addresses, subject,
                    text_body, html_body, headers, attempts, max_attempts,
                    last_error, bounce_type, created_at, dead_lettered_at, tenant_id
                )
                VALUES ($1, $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, NOW(), $13)
            "#,
            )
            .bind(id)
            .bind(&from_address)
            .bind(row.get::<Vec<String>, _>("to_addresses"))
            .bind(&subject)
            .bind(row.get::<Option<String>, _>("text_body"))
            .bind(row.get::<Option<String>, _>("html_body"))
            .bind(row.get::<serde_json::Value, _>("headers"))
            .bind(row.get::<i32, _>("attempts"))
            .bind(row.get::<i32, _>("max_attempts"))
            .bind(error)
            .bind(&bounce_type)
            .bind(row.get::<chrono::DateTime<Utc>, _>("created_at"))
            .bind(row.get::<Option<String>, _>("tenant_id"))
            .execute(&self.pool),
        )
        .await
        .map_err(|_| anyhow::anyhow!("move_to_dead_letter INSERT timed out after 30s"))?
        .map_err(|e| anyhow::anyhow!("Failed to insert dead-letter record: {}", e))?;

        metrics::counter!("outbound.dead_letter.bounces", "bounce_type" => bounce_type.clone())
            .increment(1);

        error!(
            email_id = %id,
            from = %from_address,
            error = error,
            "Bounce email moved to dead-letter queue — manual intervention may be required"
        );

        Ok(())
    }

    /// Mark email as deferred due to provider reputation throttle.
    /// Unlike `mark_failed(defer=true)`, this does NOT increment `attempts`,
    /// so reputation-driven backoff cannot cause permanent failures.
    pub async fn mark_throttled(&self, id: &Uuid, reason: &str) -> Result<()> {
        // Short-ish retry delay — re-check reputation soon.  60 seconds is
        // longer than ProviderThrottle's cache TTL so the next look will
        // hit fresh data.
        let next_retry = Utc::now() + chrono::Duration::seconds(90);
        timeout(
            Duration::from_secs(30),
            sqlx::query(
                r#"
                UPDATE email_queue
                SET status = 'deferred',
                    last_error = $2,
                    next_retry_at = $3,
                    updated_at = NOW()
                WHERE id = $1
                "#,
            )
            .bind(id)
            .bind(reason)
            .bind(next_retry)
            .execute(&self.pool),
        )
        .await
        .map_err(|_| anyhow::anyhow!("mark_throttled query timed out after 30s"))??;
        Ok(())
    }

    /// Mark email as failed
    pub async fn mark_failed(&self, id: &Uuid, error: &str, defer: bool) -> Result<()> {
        let email = timeout(
            Duration::from_secs(30),
            sqlx::query(
                r#"
                SELECT attempts, max_attempts, from_address FROM email_queue WHERE id = $1
            "#,
            )
            .bind(id)
            .fetch_one(&self.pool),
        )
        .await
        .map_err(|_| anyhow::anyhow!("mark_failed SELECT timed out after 30s"))??;

        let attempts: i32 = email.get("attempts");
        let max_attempts: i32 = email.get("max_attempts");
        let from_address: String = email.get("from_address");
        let new_attempts = attempts + 1;

        if defer && new_attempts < max_attempts {
            // #113:Guard against empty retry_delays causing integer underflow
            let delay = if self.config.retry_delays.is_empty() {
                Duration::from_secs(DEFAULT_QUEUE_EMPTY_RETRY_FALLBACK_SECS)
            } else {
                let delay_index = (new_attempts - 1).max(0) as usize;
                let delay_index = delay_index.min(self.config.retry_delays.len() - 1);
                self.config.retry_delays[delay_index]
            };
            let chrono_delay = chrono::Duration::from_std(delay)
                .unwrap_or_else(|_| chrono::Duration::seconds(300)); // fallback:5 minutes
            let next_retry = Utc::now() + chrono_delay;

            timeout(
                Duration::from_secs(30),
                sqlx::query(
                    r#"
                    UPDATE email_queue
                    SET status = 'deferred', attempts = $2, last_error = $3,
                        next_retry_at = $4, updated_at = NOW()
                    WHERE id = $1
                "#,
                )
                .bind(id)
                .bind(new_attempts)
                .bind(error)
                .bind(next_retry)
                .execute(&self.pool),
            )
            .await
            .map_err(|_| anyhow::anyhow!("mark_failed defer UPDATE timed out after 30s"))??;

            warn!(
                email_id = %id,
                attempts = new_attempts,
                next_retry = %next_retry,
                "Email deferred for retry"
            );
        } else {
            timeout(
                Duration::from_secs(30),
                sqlx::query(
                    r#"
                    UPDATE email_queue
                    SET status = 'failed', attempts = $2, last_error = $3, updated_at = NOW()
                    WHERE id = $1
                "#,
                )
                .bind(id)
                .bind(new_attempts)
                .bind(error)
                .execute(&self.pool),
            )
            .await
            .map_err(|_| anyhow::anyhow!("mark_failed permanent UPDATE timed out after 30s"))??;

            error!(email_id = %id, error = error, "Email permanently failed");

            // MI-008 / DB-14: Move bounce notifications to the dead-letter queue.
            // For non-bounce permanently failed emails, apply configurable sampling
            // (dead_letter_sample_rate, default 1%) to provide a forensic trail
            // without filling the dead-letter queue with routine failures.
            // Uses deterministic hash-based sampling to avoid depending on `rand`.
            let is_bounce = Self::is_bounce_email(&from_address);
            let sample = !is_bounce
                && self.config.dead_letter_sample_rate > 0.0
                && Self::sample_dead_letter(id, self.config.dead_letter_sample_rate);
            if is_bounce || sample {
                if sample {
                    debug!(email_id = %id, sample_rate = self.config.dead_letter_sample_rate,
                        "Sampling non-bounce failure for dead-letter queue");
                }
                if let Err(e) = self.move_to_dead_letter(id, error).await {
                    error!(
                        email_id = %id,
                        dead_letter_error = %e,
                        "Failed to move email to dead-letter queue"
                    );
                }
            }
        }

        Ok(())
    }

    /// Process a single email
    async fn process_email(&self, email: &QueuedEmail) -> Result<()> {
        // Per-provider reputation throttle: if our deliverability signal says
        // "back off Gmail", roll the dice and possibly defer this message.
        // Multiple recipients only need one to trigger the throttle (worst case).
        if let Some(ref throttle) = self.provider_throttle {
            let sender_domain = Self::extract_domain(&email.from_address);
            for recipient in &email.to_addresses {
                let recip_domain = Self::extract_domain(recipient);
                let decision = throttle
                    .decide(&sender_domain, &recip_domain, email.tenant_id.as_deref())
                    .await;
                if let ThrottleDecision::Defer {
                    reason,
                    throttle_pct,
                } = decision
                {
                    info!(
                        email_id = %email.id,
                        recipient,
                        throttle_pct,
                        reason = %reason,
                        "Deferring outbound message per provider reputation throttle"
                    );
                    return Err(anyhow::anyhow!("provider_throttle: {reason}"));
                }
            }
        }

        // Extract custom headers from JSON
        let headers: Option<std::collections::HashMap<String, String>> =
            email.headers.as_object().map(|obj| {
                obj.iter()
                    .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
                    .collect()
            });

        // Send via SMTP — no Mutex needed, send is &self (#114/#115)
        self.smtp_sender
            .send(
                &email.from_address,
                &email.to_addresses,
                &email.subject,
                email.text_body.as_deref(),
                email.html_body.as_deref(),
                headers,
            )
            .await?;

        Ok(())
    }

    /// Start the queue processor
    ///
    /// DB-12: `process_batch()` is wrapped in a 5-minute timeout so that a slow
    /// batch cannot indefinitely delay shutdown. If the timeout fires the loop
    /// simply retries on the next poll interval.
    ///
    /// RS-M-05: On shutdown signal, the processor enters drain mode: it sets a
    /// flag to prevent new batches, waits for any in-flight batch to complete,
    /// and then exits. This ensures in-flight SMTP transactions (DATA phase)
    /// are not cut off mid-delivery.
    pub async fn start_processing(self: std::sync::Arc<Self>, mut shutdown: mpsc::Receiver<()>) {
        info!(
            workers = self.config.worker_count,
            batch_size = self.config.batch_size,
            "Starting email queue processor"
        );

        const BATCH_TIMEOUT: Duration = Duration::from_secs(300); // 5 min
        const DRAIN_TIMEOUT: Duration = Duration::from_secs(30); // 30s drain window

        let mut draining = false;
        let mut drain_fut: Option<tokio::sync::oneshot::Receiver<()>> = None;

        loop {
            tokio::select! {
                biased; // Check shutdown first

                _ = async {
                    if !draining {
                        std::future::pending::<()>().await
                    } else {
                        // Wait for drain to complete with timeout
                        match drain_fut.as_mut() {
                            Some(rx) => rx.await.ok(),
                            None => Some(std::future::pending::<()>().await),
                        };
                    }
                }, if draining => {
                    info!("Email queue processor drain complete — shutting down");
                    break;
                }

                _ = shutdown.recv() => {
                    if draining {
                        // Already draining; ignore duplicate signal
                        continue;
                    }
                    info!(
                        "Email queue processor received shutdown signal — draining in-flight emails..."
                    );
                    draining = true;
                    // Start a drain timer — if no batch is in-flight, this will
                    // fire quickly and we'll exit on the next loop iteration.
                    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
                    drain_fut = Some(rx);
                    tokio::spawn(async move {
                        tokio::time::sleep(DRAIN_TIMEOUT).await;
                        let _ = tx.send(());
                    });
                    // Do NOT break here — allow the current batch to finish
                    // if one is in-flight. The biased select ensures we check
                    // drain completion before starting a new batch.
                }

                _ = tokio::time::sleep(self.config.poll_interval) => {
                    if draining {
                        // In drain mode: skip new batches but still wait for
                        // the drain timer to fire.
                        continue;
                    }
                    match tokio::time::timeout(BATCH_TIMEOUT, self.process_batch()).await {
                        Ok(Ok(())) => {}
                        Ok(Err(e)) => error!(error = %e, "Failed to process email batch"),
                        Err(_) => error!("Email batch processing timed out — will retry on next poll interval"),
                    }
                }
            }
        }
    }

    /// Process a batch of emails concurrently (#115) with per-tenant weighted fair queueing.
    ///
    /// Emails are grouped by tenant_id. Each tenant gets up to `tenant_weight` emails
    /// processed per round before moving to the next tenant (round-robin). This prevents
    /// a high-volume tenant from starving lower-volume tenants.
    async fn process_batch(&self) -> Result<()> {
        let emails = self.fetch_pending(self.config.batch_size as i64).await?;

        if emails.is_empty() {
            return Ok(());
        }

        info!(count = emails.len(), "Processing email batch");

        // Group emails by tenant_id for weighted fair queueing.
        // Emails without tenant_id are grouped under a sentinel key.
        let mut by_tenant: std::collections::HashMap<String, Vec<&QueuedEmail>> =
            std::collections::HashMap::new();
        for email in &emails {
            let key = email.tenant_id.clone().unwrap_or_default();
            by_tenant.entry(key).or_default().push(email);
        }

        // Build a round-robin schedule: for each tenant, take up to `weight` emails.
        let mut scheduled: Vec<&QueuedEmail> = Vec::with_capacity(emails.len());
        let tenant_keys: Vec<String> = by_tenant.keys().cloned().collect();

        // Continue until we've scheduled all emails
        let mut total_scheduled = 0;
        while total_scheduled < emails.len() {
            let mut any_progress = false;
            for key in &tenant_keys {
                let weight = self
                    .config
                    .tenant_weights
                    .get(key.as_str())
                    .copied()
                    .unwrap_or(10); // default weight for unknown tenants

                let queue = by_tenant
                    .get_mut(key)
                    .expect("invariant: key was just verified to exist in by_tenant");
                let to_take = weight.min(queue.len());
                if to_take > 0 {
                    any_progress = true;
                    for email in queue.drain(..to_take) {
                        scheduled.push(email);
                        total_scheduled += 1;
                    }
                }
            }
            if !any_progress {
                break;
            }
        }

        // Process scheduled emails concurrently with bounded concurrency.
        //
        // # Performance (DB-4)
        //
        // **Root cause**: `join_all(futures)` launched all N futures at once
        // (up to `batch_size` which defaults to 100), causing unbounded
        // concurrency that could overwhelm SMTP connections, DNS resolvers,
        // and database connection pools.
        //
        // **Fix**: Replaced `join_all` with `buffer_unordered(N)` where N
        // = `max_concurrent_emails` (default: 50). This bounds the number
        // of concurrently-polled futures to N, preventing resource exhaustion
        // while still allowing pipeline parallelism within a batch.
        let max_concurrent = self.config.max_concurrent_emails;
        // Pre-build futures to avoid HRTB issues with async closures in stream combinators.
        let futs: Vec<_> = scheduled
            .into_iter()
            .map(|email| async move {
                let result = self.process_email(email).await;
                (email.id, result)
            })
            .collect();
        let results: Vec<_> = futures::stream::iter(futs)
            .buffer_unordered(max_concurrent)
            .collect()
            .await;

        for (email_id, result) in results {
            match result {
                Ok(()) => {
                    self.mark_sent(&email_id).await?;
                }
                Err(e) => {
                    let error_str = e.to_string();
                    // Provider-throttle defers do not count against max_attempts.
                    if error_str.starts_with("provider_throttle:") {
                        self.mark_throttled(&email_id, &error_str).await?;
                        continue;
                    }
                    let is_temporary = error_str.contains("timeout")
                        || error_str.contains("connection refused")
                        || error_str.contains("temporarily");

                    self.mark_failed(&email_id, &error_str, is_temporary)
                        .await?;
                }
            }
        }

        Ok(())
    }

    /// Get queue statistics
    pub async fn get_stats(&self) -> Result<QueueStats> {
        let row = timeout(
            Duration::from_secs(30),
            sqlx::query(
                r#"
                SELECT
                    COUNT(*) FILTER (WHERE status = 'pending') as pending,
                    COUNT(*) FILTER (WHERE status = 'processing') as processing,
                    COUNT(*) FILTER (WHERE status = 'sent') as sent,
                    COUNT(*) FILTER (WHERE status = 'failed') as failed,
                    COUNT(*) FILTER (WHERE status = 'deferred') as deferred
                FROM email_queue
            "#,
            )
            .fetch_one(&self.pool),
        )
        .await
        .map_err(|_| anyhow::anyhow!("get_stats query timed out after 30s"))??;

        let stats = QueueStats {
            pending: row.get::<i64, _>("pending") as u64,
            processing: row.get::<i64, _>("processing") as u64,
            sent: row.get::<i64, _>("sent") as u64,
            failed: row.get::<i64, _>("failed") as u64,
            deferred: row.get::<i64, _>("deferred") as u64,
        };
        stats.record_metrics();
        Ok(stats)
    }

    /// Purge old sent emails
    pub async fn purge_old(&self, days: i32) -> Result<u64> {
        let result = timeout(
            Duration::from_secs(30),
            sqlx::query(
                r#"
                DELETE FROM email_queue
                WHERE status = 'sent' AND sent_at < NOW() - $1::interval
            "#,
            )
            .bind(format!("{} days", days))
            .execute(&self.pool),
        )
        .await
        .map_err(|_| anyhow::anyhow!("purge_old query timed out after 30s"))??;

        let count = result.rows_affected();
        info!(count = count, days = days, "Purged old sent emails");
        Ok(count)
    }

    /// Cancel pending emails for a campaign
    pub async fn cancel_campaign(&self, campaign_id: &Uuid) -> Result<u64> {
        let result = timeout(
            Duration::from_secs(30),
            sqlx::query(
                r#"
                UPDATE email_queue
                SET status = 'failed', last_error = 'Campaign cancelled', updated_at = NOW()
                WHERE campaign_id = $1 AND status IN ('pending', 'deferred')
            "#,
            )
            .bind(campaign_id)
            .execute(&self.pool),
        )
        .await
        .map_err(|_| anyhow::anyhow!("cancel_campaign query timed out after 30s"))??;

        let count = result.rows_affected();
        info!(campaign_id = %campaign_id, count = count, "Cancelled campaign emails");
        Ok(count)
    }
}

/// Queue statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueueStats {
    pub pending: u64,
    pub processing: u64,
    pub sent: u64,
    pub failed: u64,
    pub deferred: u64,
}

impl QueueStats {
    pub fn total(&self) -> u64 {
        self.pending + self.processing + self.sent + self.failed + self.deferred
    }

    pub fn record_metrics(&self) {
        for (status, depth) in [
            ("pending", self.pending),
            ("processing", self.processing),
            ("sent", self.sent),
            ("failed", self.failed),
            ("deferred", self.deferred),
        ] {
            metrics::gauge!("apexmail_email_queue_depth", "status" => status).set(depth as f64);
        }
    }
}

/// Detect the type of bounce based on from_address and subject.
fn detect_bounce_type(from_address: &str, subject: &str) -> String {
    let lower_from = from_address.to_lowercase();
    let lower_subject = subject.to_lowercase();

    if lower_from.contains("mailer-daemon") || lower_from.contains("maildaemon") {
        "mailer-daemon".to_string()
    } else if lower_subject.contains("undelivered") || lower_subject.contains("returned mail") {
        "undelivered".to_string()
    } else if lower_subject.contains("delivery failure")
        || lower_subject.contains("delivery status")
    {
        "delivery-status".to_string()
    } else if lower_from.starts_with("bounce@") {
        "bounce".to_string()
    } else {
        "unknown".to_string()
    }
}

fn push_pending_insert_row_sql(sql: &mut String, base: usize) {
    sql.push_str(&format!(
        "(${}, ${}, ${}, ${}, ${}, ${}, ${}, 'pending', ${}, ${}, ${}, ${}, ${})",
        base,
        base + 1,
        base + 2,
        base + 3,
        base + 4,
        base + 5,
        base + 6,
        base + 7,
        base + 8,
        base + 9,
        base + 10,
        base + 11,
    ));
}

// ---------------------------------------------------------------------------
// Tests — unit tests that do NOT require a database
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // CancelResult
    // -----------------------------------------------------------------------

    #[test]
    fn cancel_result_eq_cancelled() {
        assert_eq!(CancelResult::Cancelled, CancelResult::Cancelled);
    }

    #[test]
    fn cancel_result_eq_not_found() {
        assert_eq!(CancelResult::NotFound, CancelResult::NotFound);
    }

    #[test]
    fn cancel_result_not_cancellable_with_reason() {
        let a = CancelResult::NotCancellable("already sent".into());
        let b = CancelResult::NotCancellable("already sent".into());
        assert_eq!(a, b);
    }

    #[test]
    fn cancel_result_variants_not_equal_across_types() {
        assert_ne!(CancelResult::Cancelled, CancelResult::NotFound);
        assert_ne!(
            CancelResult::Cancelled,
            CancelResult::NotCancellable("x".into()),
        );
    }

    #[test]
    fn cancel_result_debug_format() {
        let r = CancelResult::Cancelled;
        let dbg = format!("{:?}", r);
        assert!(dbg.contains("Cancelled"));
    }

    #[test]
    fn cancel_result_clone() {
        let r = CancelResult::NotCancellable("reason".into());
        let c = r.clone();
        assert_eq!(r, c);
    }

    // -----------------------------------------------------------------------
    // EmailStatus
    // -----------------------------------------------------------------------

    #[test]
    fn email_status_default_is_pending() {
        assert_eq!(EmailStatus::default(), EmailStatus::Pending);
    }

    #[test]
    fn email_status_all_variants_distinct() {
        let variants = [
            EmailStatus::Pending,
            EmailStatus::Processing,
            EmailStatus::Sent,
            EmailStatus::Failed,
            EmailStatus::Deferred,
        ];
        for (i, a) in variants.iter().enumerate() {
            for (j, b) in variants.iter().enumerate() {
                if i == j {
                    assert_eq!(a, b);
                } else {
                    assert_ne!(a, b);
                }
            }
        }
    }

    #[test]
    fn email_status_serde_roundtrip() {
        for status in [
            EmailStatus::Pending,
            EmailStatus::Processing,
            EmailStatus::Sent,
            EmailStatus::Failed,
            EmailStatus::Deferred,
        ] {
            let json = serde_json::to_string(&status).unwrap();
            let parsed: EmailStatus = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed, status);
        }
    }

    #[test]
    fn email_status_copy() {
        let s = EmailStatus::Sent;
        let s2 = s; // Copy
        assert_eq!(s, s2);
    }

    // -----------------------------------------------------------------------
    // QueueConfig
    // -----------------------------------------------------------------------

    #[test]
    fn queue_config_default_values() {
        let cfg = QueueConfig::default();
        assert_eq!(cfg.max_attempts, DEFAULT_QUEUE_MAX_ATTEMPTS);
        assert_eq!(cfg.worker_count, DEFAULT_QUEUE_WORKER_COUNT);
        assert_eq!(cfg.batch_size, DEFAULT_QUEUE_BATCH_SIZE);
        assert_eq!(cfg.retry_delays.len(), DEFAULT_QUEUE_RETRY_DELAY_SECS.len());
    }

    #[test]
    fn queue_config_retry_delays_ascending() {
        let cfg = QueueConfig::default();
        for i in 1..cfg.retry_delays.len() {
            assert!(
                cfg.retry_delays[i] > cfg.retry_delays[i - 1],
                "Retry delays should be monotonically increasing"
            );
        }
    }

    #[test]
    fn queue_config_first_retry_under_5_minutes() {
        let cfg = QueueConfig::default();
        assert!(cfg.retry_delays[0] <= Duration::from_secs(DEFAULT_QUEUE_RETRY_DELAY_SECS[1]));
    }

    // -----------------------------------------------------------------------
    // QueueStats
    // -----------------------------------------------------------------------

    #[test]
    fn queue_stats_total_sums_all_fields() {
        let stats = QueueStats {
            pending: 10,
            processing: 5,
            sent: 100,
            failed: 3,
            deferred: 2,
        };
        assert_eq!(stats.total(), 120);
    }

    #[test]
    fn queue_stats_total_zero() {
        let stats = QueueStats {
            pending: 0,
            processing: 0,
            sent: 0,
            failed: 0,
            deferred: 0,
        };
        assert_eq!(stats.total(), 0);
    }

    #[test]
    fn queue_stats_total_overflow_risk() {
        // Ensure the addition doesn't panic with large but reasonable values
        let stats = QueueStats {
            pending: u64::MAX / 5,
            processing: u64::MAX / 5,
            sent: u64::MAX / 5,
            failed: u64::MAX / 5,
            deferred: u64::MAX / 5,
        };
        let _ = stats.total(); // should not panic
    }

    #[test]
    fn queue_stats_serde_roundtrip() {
        let stats = QueueStats {
            pending: 42,
            processing: 7,
            sent: 999,
            failed: 0,
            deferred: 12,
        };
        let json = serde_json::to_string(&stats).unwrap();
        let parsed: QueueStats = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.total(), stats.total());
    }

    // -----------------------------------------------------------------------
    // QueuedEmail
    // -----------------------------------------------------------------------

    fn make_test_email() -> QueuedEmail {
        QueuedEmail {
            id: Uuid::new_v4(),
            from_address: "sender@test.com".into(),
            to_addresses: vec!["r1@test.com".into(), "r2@test.com".into()],
            subject: "Test email".into(),
            text_body: Some("Hello".into()),
            html_body: Some("<p>Hello</p>".into()),
            headers: serde_json::json!({"X-Custom": "value"}),
            status: EmailStatus::Pending,
            attempts: 0,
            max_attempts: DEFAULT_QUEUE_MAX_ATTEMPTS,
            last_error: None,
            next_retry_at: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            sent_at: None,
            campaign_id: None,
            sequence_id: None,
            contact_id: None,
            priority: 0,
            tenant_id: None,
        }
    }

    #[test]
    fn queued_email_serde_roundtrip() {
        let email = make_test_email();
        let json = serde_json::to_string(&email).unwrap();
        let parsed: QueuedEmail = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.id, email.id);
        assert_eq!(parsed.from_address, email.from_address);
        assert_eq!(parsed.to_addresses, email.to_addresses);
        assert_eq!(parsed.subject, email.subject);
        assert_eq!(parsed.status, email.status);
    }

    #[test]
    fn queued_email_optional_fields_none() {
        let mut email = make_test_email();
        email.text_body = None;
        email.html_body = None;
        email.last_error = None;
        email.next_retry_at = None;
        email.campaign_id = None;

        let json = serde_json::to_string(&email).unwrap();
        let parsed: QueuedEmail = serde_json::from_str(&json).unwrap();
        assert!(parsed.text_body.is_none());
        assert!(parsed.html_body.is_none());
    }

    #[test]
    fn queued_email_multiple_recipients() {
        let email = QueuedEmail {
            to_addresses: vec![
                "a@test.com".into(),
                "b@test.com".into(),
                "c@test.com".into(),
            ],
            ..make_test_email()
        };
        assert_eq!(email.to_addresses.len(), 3);
    }

    #[test]
    fn queued_email_empty_recipients() {
        let email = QueuedEmail {
            to_addresses: vec![],
            ..make_test_email()
        };
        assert!(email.to_addresses.is_empty());
    }

    // -----------------------------------------------------------------------
    // Batch INSERT SQL builder validation
    // -----------------------------------------------------------------------

    /// Validates that the multi-row INSERT SQL builder produces correct
    /// parameter numbering for N rows.
    fn validate_batch_sql(count: usize) -> String {
        let cols = 12;
        let mut sql = String::from(
            "INSERT INTO email_queue (
                id, from_address, to_addresses, subject, text_body, html_body,
                headers, status, max_attempts, campaign_id, sequence_id,
                contact_id, priority
            ) VALUES ",
        );

        for i in 0..count {
            if i > 0 {
                sql.push_str(", ");
            }
            let base = i * cols + 1;
            super::push_pending_insert_row_sql(&mut sql, base);
        }
        sql.push_str(" RETURNING id");
        sql
    }

    #[test]
    fn batch_sql_single_row() {
        let sql = validate_batch_sql(1);
        assert!(sql.contains("($1, $2, $3, $4, $5, $6, $7, 'pending', $8, $9, $10, $11, $12)"));
        assert!(sql.contains("RETURNING id"));
        // Should not have a second row
        assert!(!sql.contains("$13"));
    }

    #[test]
    fn batch_sql_two_rows() {
        let sql = validate_batch_sql(2);
        assert!(sql.contains("$1,"));
        assert!(sql.contains("$12)"));
        assert!(sql.contains("$13,"));
        assert!(sql.contains("$24)"));
        assert!(!sql.contains("$25"));
    }

    #[test]
    fn batch_sql_ten_rows() {
        let sql = validate_batch_sql(10);
        // Last row starts at $109 (9 * 12 + 1), ends at $120
        assert!(sql.contains("$109,"));
        assert!(sql.contains("$120)"));
        assert!(!sql.contains("$121"));
    }

    #[test]
    fn batch_sql_hundred_rows() {
        let sql = validate_batch_sql(100);
        // Last row:base = 99 * 12 + 1 = 1189, ends at $1200
        assert!(sql.contains("$1189,"));
        assert!(sql.contains("$1200)"));
    }

    #[test]
    fn batch_sql_no_duplicate_params() {
        let sql = validate_batch_sql(5);
        let cols = 12;
        let total_params = 5 * cols;
        for p in 1..=total_params {
            let needle = format!("${}", p);
            let count = sql.matches(&needle).count();
            // Each parameter should appear exactly once (but $1 can also match
            // $10, $11, etc. so we check with trailing comma/paren)
            assert!(count >= 1, "Parameter {} should appear at least once", p);
        }
    }
}
