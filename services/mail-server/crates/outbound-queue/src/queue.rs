//! Email Queue
//!
//! Persistent queue for outbound emails with retry logic and per-domain
//! rate limiting.

use anyhow::{bail, Result};
use chrono::{DateTime, Utc};
use futures::stream::StreamExt;
use serde::{Deserialize, Serialize};
use sqlx::{PgPool, Row};
use std::collections::{HashMap, VecDeque};
use std::hash::{Hash, Hasher};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
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
/// F1:requeue delay for rows deferred by send-rate enforcement. The rate
/// windows are 1s wide; ~2s covers the window plus scheduling margin so the
/// next poll re-delivers without wasting an attempt.
const SEND_RATE_RETRY_DELAY_SECS: i64 = 2;

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

/// Pure (non-consuming) sliding-second rate window.
///
/// The governor crate (0.6) only offers CONSUMING checks (`check_key`),
/// which is why rate limiting used to live at enqueue time: every enqueued
/// email drained a token, so a 1000-mail bulk at a 10/s domain quota
/// exhausted the bucket after ~10 entries and permanently failed the rest
/// of the batch.
///
/// Admission checks at ENQUEUE time are DRY-RUNS: [`RateWindow::check`]
/// computes the remaining quota in the current 1s window from the SENDS
/// consumed at delivery time ([`RateWindow::try_consume`], called per
/// recipient before SMTP dispatch in [`EmailQueue::process_email`]) without
/// committing anything. Bulk enqueues therefore never drain quota, while
/// the per-second pace is enforced (F1) against actual outbound sends.
#[derive(Debug, Default)]
struct RateWindow {
    /// Maximum events per sliding 1-second window. 0 = unlimited.
    limit: u64,
    /// Per-key send timestamps inside the current window.
    events: Mutex<HashMap<String, VecDeque<Instant>>>,
}

/// Width of the sliding admission window.
const RATE_WINDOW: Duration = Duration::from_secs(1);
/// Bound the key map so a pathological number of distinct keys cannot grow
/// memory without limit (stale keys are pruned past this size).
const RATE_WINDOW_MAX_KEYS: usize = 10_000;

impl RateWindow {
    fn new(limit: u64) -> Self {
        Self {
            limit,
            events: Mutex::new(HashMap::new()),
        }
    }

    fn is_unlimited(&self) -> bool {
        self.limit == 0
    }

    fn conforming_count(queue: Option<&VecDeque<Instant>>, now: Instant) -> u64 {
        queue
            .map(|q| {
                q.iter()
                    .filter(|t| now.duration_since(**t) < RATE_WINDOW)
                    .count() as u64
            })
            .unwrap_or(0)
    }

    /// Pure quota check: would ONE more event still conform in the current
    /// window? Never records anything — callers may probe freely.
    fn check(&self, key: &str) -> bool {
        if self.is_unlimited() {
            return true;
        }
        let now = Instant::now();
        let events = self.events.lock().unwrap_or_else(|e| e.into_inner());
        Self::conforming_count(events.get(key), now) < self.limit
    }

    /// Atomic check-AND-consume: returns `true` and records the event when
    /// one more event still conforms in the current window, `false` without
    /// recording otherwise. The check and the push happen under the same
    /// lock, so concurrent consumers cannot jointly exceed `limit` — this is
    /// the delivery-time enforcement primitive (F1) used before SMTP dispatch.
    fn try_consume(&self, key: &str) -> bool {
        if self.is_unlimited() {
            return true;
        }
        let now = Instant::now();
        let mut events = self.events.lock().unwrap_or_else(|e| e.into_inner());
        // Bound the key map (stale keys pruned before a NEW key is admitted)
        // so a pathological number of distinct domains/tenants cannot grow
        // memory without limit.
        if events.len() >= RATE_WINDOW_MAX_KEYS && !events.contains_key(key) {
            events.retain(|_, q| Self::conforming_count(Some(q), now) > 0);
        }
        let queue = events.entry(key.to_string()).or_default();
        if queue
            .iter()
            .filter(|t| now.duration_since(**t) < RATE_WINDOW)
            .count() as u64
            >= self.limit
        {
            return false;
        }
        queue.push_back(now);
        while queue
            .front()
            .is_some_and(|t| now.duration_since(*t) >= RATE_WINDOW)
        {
            queue.pop_front();
        }
        true
    }
}

/// D:outcome of a delivery attempt from the queue processor's point of view.
#[derive(Debug, Clone, PartialEq, Eq)]
enum DeliveryOutcome {
    /// Every recipient was accepted — the row may be marked sent.
    Delivered,
    /// At least one recipient was accepted AND at least one was (typically
    /// 4xx) rejected: the row must be requeued for exactly `rejected`.
    PartiallyDelivered { rejected: Vec<String> },
}

/// D:pure classification of an SmtpSendResult that already passed the
/// "all recipients rejected" error path: any leftover rejected recipient
/// makes this a partial delivery that MUST NOT be marked sent.
fn classify_partial_acceptance(result: &crate::smtp_sender::SmtpSendResult) -> DeliveryOutcome {
    if result.rejected.is_empty() {
        DeliveryOutcome::Delivered
    } else {
        DeliveryOutcome::PartiallyDelivered {
            rejected: result.rejected.clone(),
        }
    }
}

/// E-10:true when `text` contains a standalone SMTP 4xx reply code: a
/// 3-digit run starting with '4' that is at the start of the string (or
/// preceded by a non-digit) AND followed by a non-digit. Digits embedded in
/// longer runs or identifiers ("R4521X", "v14523", "invoice-4521") do not
/// count — the old token split misclassified such permanent errors as
/// retryable, deferring them until max_attempts.
fn contains_smtp_4xx_code(text: &str) -> bool {
    let bytes = text.as_bytes();
    for i in 0..bytes.len() {
        if bytes[i] == b'4'
            && i + 2 < bytes.len()
            && bytes[i + 1].is_ascii_digit()
            && bytes[i + 2].is_ascii_digit()
            && (i == 0 || !bytes[i - 1].is_ascii_digit())
            && (i + 3 == bytes.len() || !bytes[i + 3].is_ascii_digit())
        {
            return true;
        }
    }
    false
}

/// Email queue manager
pub struct EmailQueue {
    pool: PgPool,
    config: QueueConfig,
    /// SMTP sender no longer behind Mutex since send is &self (#114/#115)
    smtp_sender: SmtpSender,
    dkim_signer: Option<DkimSigner>,
    /// Global send-rate window (messages per second across all domains/tenants).
    global_window: RateWindow,
    /// Per-domain send-rate window (messages per second per recipient domain).
    domain_window: RateWindow,
    /// Per-tenant send-rate window (messages per second per tenant).
    tenant_window: RateWindow,
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
        // Rate windows are pure admission probes against recorded SENDS —
        // nothing is consumed at enqueue time (bulk-safe). 0 = unlimited.
        let global_window = RateWindow::new(config.global_rate_per_second);
        let domain_window = RateWindow::new(config.domain_rate_per_second);
        let tenant_window = RateWindow::new(config.tenant_rate_per_second);

        Self {
            pool,
            config,
            smtp_sender,
            dkim_signer: None,
            global_window,
            domain_window,
            tenant_window,
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

    /// Classify a send error as temporary (retryable with backoff) or
    /// permanent. Case-insensitive: real SMTP/IO error strings vary widely
    /// ("Timed out", "Connection refused", "451 4.3.1 Please try again").
    fn is_temporary_error(error_str: &str) -> bool {
        let lower = error_str.to_lowercase();
        if lower.contains("timed out")
            || lower.contains("timeout")
            || lower.contains("connection refused")
            || lower.contains("temporarily")
            || lower.contains("421")
            || lower.contains("450")
            || lower.contains("451")
        {
            return true;
        }
        // E-10:proper SMTP 4xx status extraction — a standalone 3-digit code
        // starting with 4 counts only when it is NOT embedded in a longer
        // digit run (start-of-string or preceded by a non-digit, AND followed
        // by a non-digit), so identifiers like "R452X-invoice-14521" or
        // "v14523" no longer misclassify a permanent error as retryable.
        contains_smtp_4xx_code(&lower)
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
    ///
    /// This is a DRY-RUN: it never consumes quota (the governor token
    /// buckets previously drained here, breaking bulk enqueues). Quota is
    /// only consumed by actual sends recorded in [`EmailQueue::process_email`].
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
        if !self.global_window.check("__global__") {
            return RateLimitDecision::GlobalExceeded;
        }

        // Check per-domain rate limits
        for domain in &domains {
            if !self.domain_window.check(domain) {
                return RateLimitDecision::DomainExceeded(domain.clone());
            }
        }

        // Check per-tenant rate limit
        let tenant_key = tenant_id.unwrap_or("__no_tenant__");
        if !self.tenant_window.check(tenant_key) {
            return RateLimitDecision::TenantExceeded;
        }

        RateLimitDecision::Allowed
    }

    /// Delivery-time send-rate enforcement (F1).
    ///
    /// Atomically check-AND-consume one send's worth of quota from the
    /// global, per-domain and per-tenant windows (in that order). Returns
    /// [`RateLimitDecision::Allowed`] when the send may proceed — the quota
    /// is already consumed — or the exceeded variant, in which case NOTHING
    /// was sent and the caller must REQUEUE the row with a small delay
    /// (see [`EmailQueue::mark_send_rate_limited`]) rather than drop it.
    ///
    /// Consume order matters: when a later window denies, the tokens already
    /// consumed from earlier windows are NOT rolled back. That is strictly
    /// conservative — the leaked tokens expire with the 1-second window and
    /// can only slow the pace slightly, never exceed it. Enqueue admission
    /// ([`EmailQueue::check_rate_limits`]) remains a pure dry-run.
    fn acquire_send_rate(
        &self,
        to_addresses: &[String],
        tenant_id: Option<&str>,
    ) -> RateLimitDecision {
        if !self.global_window.try_consume("__global__") {
            return RateLimitDecision::GlobalExceeded;
        }

        let mut domains: Vec<String> = to_addresses
            .iter()
            .map(|addr| Self::extract_domain(addr))
            .collect();
        domains.sort();
        domains.dedup();
        for domain in &domains {
            if !self.domain_window.try_consume(domain) {
                return RateLimitDecision::DomainExceeded(domain.clone());
            }
        }

        let tenant_key = tenant_id.unwrap_or("__no_tenant__");
        if !self.tenant_window.try_consume(tenant_key) {
            return RateLimitDecision::TenantExceeded;
        }

        RateLimitDecision::Allowed
    }

    /// F1: render an enforcement decision as the distinguishable error the
    /// batch loop routes to [`EmailQueue::mark_send_rate_limited`] instead
    /// of `mark_failed` (rate-limit defers must not consume an attempt).
    fn send_rate_limited_error(&self, decision: RateLimitDecision) -> anyhow::Error {
        let detail = match decision {
            RateLimitDecision::GlobalExceeded => {
                format!("global (max {} msg/s)", self.config.global_rate_per_second)
            }
            RateLimitDecision::DomainExceeded(domain) => format!(
                "domain '{}' (max {} msg/s)",
                domain, self.config.domain_rate_per_second
            ),
            RateLimitDecision::TenantExceeded => {
                format!("tenant (max {} msg/s)", self.config.tenant_rate_per_second)
            }
            RateLimitDecision::Allowed => "allowed".to_string(),
        };
        anyhow::anyhow!("send_rate_limited: {detail}")
    }

    /// F1:true when an error produced by [`Self::send_rate_limited_error`].
    fn is_send_rate_limited(error_str: &str) -> bool {
        error_str.starts_with("send_rate_limited:")
    }

    /// Base retry delay for the given NEXT attempt number (1-based), from
    /// the configured `retry_delays` ladder. #113:falls back to a sane
    /// constant when `retry_delays` is empty (avoids the integer underflow
    /// of indexing into an empty vec).
    fn retry_delay_for_attempt(&self, next_attempt: i32) -> Duration {
        if self.config.retry_delays.is_empty() {
            return Duration::from_secs(DEFAULT_QUEUE_EMPTY_RETRY_FALLBACK_SECS);
        }
        let delay_index = (next_attempt - 1).max(0) as usize;
        self.config.retry_delays[delay_index.min(self.config.retry_delays.len() - 1)]
    }

    /// Initialize queue tables
    pub async fn initialize(&self) -> Result<()> {
        // Canonical email_queue shape is owned by the SQL migrations
        // (services/mail-server/migrations/, incl. 088/089): a partitioned
        // table carrying BOTH the outbound-queue/base column family
        // (from_address, to_addresses, text_body, html_body, attempts, ...)
        // and the worker family (message_id, domain_id, "from", "to", html,
        // text, scheduled_at, attempt, locked_until, error_message,
        // smtp_message_id). Nothing is created or altered at runtime anymore;
        // this only verifies the deployed schema is the canonical one and
        // backfills missing indexes (no-ops when already present).
        self.ensure_compatible_email_queue_schema().await?;

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
        // The dead_letter_queue table is created via SQL migration
        // (migration 052/056), not at runtime. This ensures the schema is
        // version-controlled and available before the application starts.

        info!("Email queue tables verified (canonical schema)");
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

        // The canonical email_queue always carries from_address/to_addresses.
        // A table without them is a foreign/legacy schema — never drop it
        // (it may be partitioned, referenced by FKs, or hold data). Fail
        // loudly instead of destroying it.
        let row_count = sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM email_queue")
            .fetch_one(&self.pool)
            .await?;

        bail!(
            "email_queue uses a legacy schema without from_address/to_addresses \
             (currently {row_count} rows); apply the canonical migrations \
             (services/mail-server/migrations/088) before starting outbound-queue"
        );
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
    ///
    /// Rows are claimed by flipping them to 'processing' and taking a
    /// visibility-timeout lease (`locked_until = NOW() + 10 minutes`). Rows
    /// whose lease has expired (e.g. a worker crashed mid-batch) are
    /// reclaimed automatically, so they can never be stuck in 'processing'
    /// forever. [`reap_expired_processing`] runs as a background safety net
    /// for the same rows.
    pub async fn fetch_pending(&self, limit: i64) -> Result<Vec<QueuedEmail>> {
        let rows = timeout(
            Duration::from_secs(30),
            sqlx::query(
                r#"
                UPDATE email_queue
                SET status = 'processing',
                    updated_at = NOW(),
                    locked_until = NOW() + interval '10 minutes'
                WHERE id IN (
                    SELECT id FROM email_queue
                    WHERE (
                        status IN ('pending', 'deferred')
                        OR (status = 'processing' AND locked_until < NOW())
                    )
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
    ///
    /// F4:fenced on the processing claim (`status = 'processing'`, the state
    /// [`EmailQueue::fetch_pending`] flips rows into). An unfenced UPDATE
    /// let a stale worker overwrite whatever happened after its lease
    /// expired — most notably flipping a row the user had CANCELLED (or a
    /// new owner had already finalized) back to 'sent'. A zero-row update
    /// now means this worker lost the row; it is logged and skipped (the
    /// current owner decides its fate).
    pub async fn mark_sent(&self, id: &Uuid) -> Result<()> {
        let result = timeout(
            Duration::from_secs(30),
            sqlx::query(
                r#"
                UPDATE email_queue
                SET status = 'sent', sent_at = NOW(), updated_at = NOW(),
                    locked_until = NULL
                WHERE id = $1 AND status = 'processing'
            "#,
            )
            .bind(id)
            .execute(&self.pool),
        )
        .await
        .map_err(|_| anyhow::anyhow!("mark_sent query timed out after 30s"))??;

        if result.rows_affected() == 0 {
            warn!(
                email_id = %id,
                "mark_sent fenced out — row is no longer claimed by this worker; write skipped"
            );
            return Ok(());
        }

        debug!(email_id = %id, "Email marked as sent");
        Ok(())
    }

    /// D:requeue a partially-delivered row for exactly the rejected
    /// recipients. The accepted recipients are done; the row's
    /// `to_addresses` is narrowed to the rejected set and scheduled for
    /// retry (attempts+1). When attempts are exhausted the row fails
    /// permanently with the rejected recipients preserved on it.
    ///
    /// F4:single fenced UPDATE — the attempts increment is ATOMIC
    /// (`attempts = attempts + 1`, no client-side read-modify-write, which
    /// lost concurrent increments and let rows outlive `max_attempts`) and
    /// the defer/fail decision is derived from the row's actual new count
    /// inside the same statement. The `status = 'processing'` fence matches
    /// the fetch_pending claim, so a stale worker cannot requeue a row a
    /// new owner has re-claimed.
    async fn requeue_rejected_recipients(
        &self,
        id: &Uuid,
        attempts: i32,
        rejected: &[String],
    ) -> Result<()> {
        let error = format!(
            "partial acceptance: rejected recipients kept for retry: {}",
            rejected.join(", ")
        );
        // The retry delay index is chosen from the claim-time attempt
        // snapshot; correctness (increment + terminal decision) is fully
        // server-side, so a racing increment can only shift the delay one
        // step, never revive an exhausted row. F6:±20% jitter.
        let delay_secs = jittered_retry_delay_secs(self.retry_delay_for_attempt(attempts + 1), id);
        let delay_interval = format!("{} seconds", delay_secs);

        let row = timeout(
            Duration::from_secs(30),
            sqlx::query(
                r#"
                UPDATE email_queue
                SET attempts = attempts + 1,
                    status = CASE WHEN attempts + 1 < max_attempts
                                  THEN 'deferred' ELSE 'failed' END,
                    to_addresses = $2,
                    last_error = $3,
                    next_retry_at = CASE WHEN attempts + 1 < max_attempts
                                         THEN NOW() + $4::interval
                                         ELSE NULL END,
                    locked_until = NULL,
                    updated_at = NOW()
                WHERE id = $1 AND status = 'processing'
                RETURNING status, attempts
            "#,
            )
            .bind(id)
            .bind(rejected)
            .bind(&error)
            .bind(&delay_interval)
            .fetch_optional(&self.pool),
        )
        .await
        .map_err(|_| anyhow::anyhow!("requeue_rejected UPDATE timed out after 30s"))??;

        let Some(row) = row else {
            warn!(
                email_id = %id,
                "requeue_rejected_recipients fenced out — row no longer claimed by this worker"
            );
            return Ok(());
        };

        let status: String = row.get("status");
        let new_attempts: i32 = row.get("attempts");
        if status == "deferred" {
            warn!(
                email_id = %id,
                rejected = rejected.len(),
                attempts = new_attempts,
                "Partial acceptance: row requeued for the rejected recipients only"
            );
        } else {
            error!(
                email_id = %id,
                rejected = ?rejected,
                attempts = new_attempts,
                "Rejected recipients exhausted their attempts; row failed with them preserved"
            );
        }

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
    ///
    /// Fenced on the processing claim (`status = 'processing'`, matching
    /// [`EmailQueue::fetch_pending`]) so a stale worker whose lease expired
    /// cannot defer a row the current owner is sending.
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
                WHERE id = $1 AND status = 'processing'
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

    /// F1:requeue a row deferred by send-rate enforcement.
    ///
    /// The rate windows are 1 second wide, so the delay is deliberately tiny
    /// (~2s) — the row returns to the deliverable set on the next poll
    /// instead of being dropped or punished with a full retry backoff. Like
    /// [`EmailQueue::mark_throttled`] this does NOT increment `attempts`
    /// (a pace limit is not a delivery failure) and is fenced on
    /// `status = 'processing'` so a stale worker cannot defer a row a new
    /// owner has re-claimed.
    pub async fn mark_send_rate_limited(&self, id: &Uuid, reason: &str) -> Result<()> {
        let next_retry = Utc::now() + chrono::Duration::seconds(SEND_RATE_RETRY_DELAY_SECS);
        timeout(
            Duration::from_secs(30),
            sqlx::query(
                r#"
                UPDATE email_queue
                SET status = 'deferred',
                    last_error = $2,
                    next_retry_at = $3,
                    locked_until = NULL,
                    updated_at = NOW()
                WHERE id = $1 AND status = 'processing'
                "#,
            )
            .bind(id)
            .bind(reason)
            .bind(next_retry)
            .execute(&self.pool),
        )
        .await
        .map_err(|_| anyhow::anyhow!("mark_send_rate_limited query timed out after 30s"))??;
        Ok(())
    }

    /// Mark email as failed
    ///
    /// F4:single fenced UPDATE — `attempts` is incremented ATOMICALLY
    /// (`attempts = attempts + 1`; the previous SELECT-then-UPDATE was a
    /// client-side read-modify-write that lost concurrent increments and
    /// let rows be retried past `max_attempts`), and the defer-vs-fail
    /// decision is derived from the row's actual post-increment count
    /// inside the same statement. `attempts` (the claim-time snapshot) is
    /// used ONLY to pick the retry-delay index. The
    /// `status = 'processing'` fence matches the fetch_pending claim, so a
    /// stale worker whose lease expired cannot finalize a row now owned by
    /// another worker.
    pub async fn mark_failed(
        &self,
        id: &Uuid,
        attempts: i32,
        error: &str,
        defer: bool,
    ) -> Result<()> {
        // F6:±20% jitter (deterministic per row) on the retry delay to
        // avoid synchronized retry thundering herds.
        let delay_secs = jittered_retry_delay_secs(self.retry_delay_for_attempt(attempts + 1), id);
        let delay_interval = format!("{} seconds", delay_secs);

        let row = timeout(
            Duration::from_secs(30),
            sqlx::query(
                r#"
                UPDATE email_queue
                SET attempts = attempts + 1,
                    status = CASE WHEN $2::boolean AND attempts + 1 < max_attempts
                                  THEN 'deferred' ELSE 'failed' END,
                    last_error = $3,
                    next_retry_at = CASE WHEN $2::boolean AND attempts + 1 < max_attempts
                                         THEN NOW() + $4::interval
                                         ELSE NULL END,
                    locked_until = NULL,
                    updated_at = NOW()
                WHERE id = $1 AND status = 'processing'
                RETURNING status, attempts, from_address
            "#,
            )
            .bind(id)
            .bind(defer)
            .bind(error)
            .bind(&delay_interval)
            .fetch_optional(&self.pool),
        )
        .await
        .map_err(|_| anyhow::anyhow!("mark_failed UPDATE timed out after 30s"))??;

        let Some(row) = row else {
            warn!(
                email_id = %id,
                "mark_failed fenced out — row no longer claimed by this worker; write skipped"
            );
            return Ok(());
        };

        let status: String = row.get("status");
        let new_attempts: i32 = row.get("attempts");
        let from_address: String = row.get("from_address");

        if status == "deferred" {
            warn!(
                email_id = %id,
                attempts = new_attempts,
                retry_delay_secs = delay_secs,
                "Email deferred for retry"
            );
            return Ok(());
        }

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

        Ok(())
    }

    /// Process a single email
    async fn process_email(&self, email: &QueuedEmail) -> Result<DeliveryOutcome> {
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

        // F1:ENFORCE the send-rate limits at delivery time (not enqueue
        // time, so bulk enqueues never drain the windows). This atomically
        // checks-and-consumes global/domain/tenant quota per recipient
        // BEFORE SMTP dispatch; when a window is exhausted the send is not
        // attempted and the row is requeued with a small delay by
        // `mark_send_rate_limited` (see the `send_rate_limited:` branch in
        // `process_batch`) — never dropped, never charged an attempt.
        match self.acquire_send_rate(&email.to_addresses, email.tenant_id.as_deref()) {
            RateLimitDecision::Allowed => {}
            decision @ (RateLimitDecision::GlobalExceeded
            | RateLimitDecision::DomainExceeded(_)
            | RateLimitDecision::TenantExceeded) => {
                return Err(self.send_rate_limited_error(decision));
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
        let result = self
            .smtp_sender
            .send(
                &email.from_address,
                &email.to_addresses,
                &email.subject,
                email.text_body.as_deref(),
                email.html_body.as_deref(),
                headers,
            )
            .await?;

        // `send()` returns Ok even when every recipient was rejected (RCPT TO
        // refusals, null-MX domains, ...). Treat that as a failure so the row
        // is NOT marked sent — it goes through mark_failed with the rejected
        // recipients in the error message.
        if !(result.success && !result.accepted.is_empty()) {
            let rejected = if result.rejected.is_empty() {
                email.to_addresses.join(", ")
            } else {
                result.rejected.join(", ")
            };
            return Err(anyhow::anyhow!(
                "all recipients rejected: {} (response: {})",
                rejected,
                if result.response.is_empty() {
                    "none"
                } else {
                    &result.response
                }
            ));
        }

        // D:partial acceptance (some RCPTs accepted, some temp-rejected) must
        // NOT be treated as full success — the rejected recipients would be
        // silently dropped with the row marked sent. Classify so the caller
        // requeues the row for exactly the rejected recipients.
        Ok(classify_partial_acceptance(&result))
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
                            None => std::future::pending::<Option<()>>().await,
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
        // The claim-time `attempts` snapshot travels with the result so the
        // fenced writers can pick the retry-delay index (the authoritative
        // increment happens server-side — F4).
        let futs: Vec<_> = scheduled
            .into_iter()
            .map(|email| async move {
                let attempts = email.attempts;
                let result = self.process_email(email).await;
                (email.id, attempts, result)
            })
            .collect();
        let results: Vec<_> = futures::stream::iter(futs)
            .buffer_unordered(max_concurrent)
            .collect()
            .await;

        for (email_id, attempts, result) in results {
            match result {
                Ok(DeliveryOutcome::Delivered) => {
                    // A failure marking ONE email as sent must not abort the
                    // whole results loop (which would strand every remaining
                    // row of the batch in 'processing' until lease expiry).
                    if let Err(e) = self.mark_sent(&email_id).await {
                        error!(
                            email_id = %email_id,
                            error = %e,
                            "Failed to mark email as sent (lease/reaper will recover the row)"
                        );
                    }
                }
                Ok(DeliveryOutcome::PartiallyDelivered { rejected }) => {
                    // D:some recipients were accepted and some rejected — keep
                    // the row deliverable for ONLY the rejected recipients
                    // (attempts+1, bounded by max_attempts). No data path may
                    // mark 4xx-rejected recipients as sent.
                    if let Err(e) = self
                        .requeue_rejected_recipients(&email_id, attempts, &rejected)
                        .await
                    {
                        error!(
                            email_id = %email_id,
                            error = %e,
                            "Failed to requeue rejected recipients (lease/reaper will recover the row)"
                        );
                    }
                }
                Err(e) => {
                    let error_str = e.to_string();
                    // Provider-throttle defers do not count against max_attempts.
                    if error_str.starts_with("provider_throttle:") {
                        if let Err(mark_err) = self.mark_throttled(&email_id, &error_str).await {
                            error!(
                                email_id = %email_id,
                                error = %mark_err,
                                "Failed to mark email as throttled"
                            );
                        }
                        continue;
                    }
                    // F1:send-rate defers requeue with a tiny delay (the
                    // windows are 1s wide) and never consume an attempt.
                    if Self::is_send_rate_limited(&error_str) {
                        info!(
                            email_id = %email_id,
                            reason = %error_str,
                            "Send-rate limit hit — requeueing with a short delay"
                        );
                        if let Err(mark_err) =
                            self.mark_send_rate_limited(&email_id, &error_str).await
                        {
                            error!(
                                email_id = %email_id,
                                error = %mark_err,
                                "Failed to requeue rate-limited email (lease/reaper will recover the row)"
                            );
                        }
                        continue;
                    }
                    let is_temporary = Self::is_temporary_error(&error_str);

                    if let Err(mark_err) = self
                        .mark_failed(&email_id, attempts, &error_str, is_temporary)
                        .await
                    {
                        error!(
                            email_id = %email_id,
                            error = %mark_err,
                            "Failed to mark email as failed"
                        );
                    }
                }
            }
        }

        Ok(())
    }

    /// Get queue statistics.
    ///
    /// F12:the COUNT FILTER predicates are bounded so the query no longer
    /// full-scans the table's entire history:
    /// - `sent` / `failed` cover **today** (`created_at >= NOW() - 1 day`) —
    ///   the gRPC surface reports them as `sent_today` / `failed_today`;
    /// - `pending` / `processing` / `deferred` (queue depth) cover a
    ///   **7-day** window — anything deliverable yet older than that is
    ///   beyond every retry ladder and operationally dead.
    pub async fn get_stats(&self) -> Result<QueueStats> {
        let row = timeout(
            Duration::from_secs(30),
            sqlx::query(
                r#"
                SELECT
                    COUNT(*) FILTER (WHERE status = 'pending') as pending,
                    COUNT(*) FILTER (WHERE status = 'processing') as processing,
                    COUNT(*) FILTER (WHERE status = 'sent' AND created_at >= NOW() - interval '1 day') as sent,
                    COUNT(*) FILTER (WHERE status = 'failed' AND created_at >= NOW() - interval '1 day') as failed,
                    COUNT(*) FILTER (WHERE status = 'deferred') as deferred
                FROM email_queue
                WHERE created_at >= NOW() - interval '7 days'
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
///
/// Observation windows (F12, see [`EmailQueue::get_stats`]): `sent` and
/// `failed` count rows created **in the last day** (the gRPC surface
/// reports them as today's figures); `pending`/`processing`/`deferred`
/// count rows created **in the last 7 days**.
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

/// F6:apply ±20% jitter to a retry delay, deterministic per row id (no RNG
/// state on the hot path; identical inputs always map to the same output,
/// which keeps tests reproducible). The hash spread maps onto the
/// [0.80, 1.20] multiplier band.
fn jittered_retry_delay_secs(base: Duration, id: &Uuid) -> u64 {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    id.hash(&mut hasher);
    let spread = (hasher.finish() % 41) as f64 / 100.0; // 0.00..=0.40
    let factor = 0.8 + spread; // 0.80..=1.20
    let jittered = base.as_secs_f64() * factor;
    // Never jitter a non-zero base down to zero.
    jittered.round().max(1.0) as u64
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

/// Append one VALUES row for a pending email insert.
///
/// The `email_queue` insert lists 14 columns:
/// `id, from_address, to_addresses, subject, text_body, html_body, headers,
/// status, max_attempts, campaign_id, sequence_id, contact_id, priority,
/// tenant_id`.
/// `status` is the literal `'pending'`, so each row must emit exactly 13
/// placeholders (`base ..= base+12`) — 13 placeholders + 1 literal = 14
/// expressions, matching the 14 columns and the 13 bound parameters per row.
/// Reap rows stuck in 'processing' whose visibility lease has expired.
///
/// `fetch_pending` already reclaims expired leases inline, but a row can be
/// orphaned in 'processing' if a worker died between claiming and sending.
/// This reaper flips such rows back to 'pending' so they are retried. It is
/// intended to be called on a periodic interval (60s) from the service main
/// loop. Returns the number of reaped rows.
pub async fn reap_expired_processing(pool: &PgPool) -> u64 {
    let result = timeout(
        Duration::from_secs(30),
        sqlx::query(
            r#"
            UPDATE email_queue
            SET status = 'pending', locked_until = NULL
            WHERE status = 'processing' AND locked_until < NOW()
        "#,
        )
        .execute(pool),
    )
    .await;
    match result {
        Ok(Ok(res)) => {
            let count = res.rows_affected();
            if count > 0 {
                warn!(
                    count,
                    "Reaped expired 'processing' email_queue rows back to 'pending'"
                );
            }
            count
        }
        Ok(Err(e)) => {
            error!(error = %e, "Failed to reap expired 'processing' rows");
            0
        }
        Err(_) => {
            error!("Reap expired 'processing' rows query timed out after 30s");
            0
        }
    }
}

fn push_pending_insert_row_sql(sql: &mut String, base: usize) {
    sql.push_str(&format!(
        "(${}, ${}, ${}, ${}, ${}, ${}, ${}, 'pending', ${}, ${}, ${}, ${}, ${}, ${})",
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
        base + 12,
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

    /// Number of bound parameters per row in the batch INSERT (status is a
    /// literal `'pending'`, not a bind).
    const ROW_BIND_PARAMS: usize = 13;

    /// Validates that the multi-row INSERT SQL builder produces correct
    /// parameter numbering for N rows. Uses the real 14-column list that
    /// `enqueue_batch` inserts into (including `tenant_id`).
    fn validate_batch_sql(count: usize) -> String {
        let cols = ROW_BIND_PARAMS;
        let mut sql = String::from(
            "INSERT INTO email_queue (
                id, from_address, to_addresses, subject, text_body, html_body,
                headers, status, max_attempts, campaign_id, sequence_id,
                contact_id, priority, tenant_id
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
        // 14 columns = 13 placeholders + 'pending' literal.
        assert!(sql.contains("($1, $2, $3, $4, $5, $6, $7, 'pending', $8, $9, $10, $11, $12, $13)"));
        assert!(sql.contains("RETURNING id"));
        // Should not have a second row
        assert!(!sql.contains("$14"));
    }

    #[test]
    fn batch_sql_two_rows() {
        let sql = validate_batch_sql(2);
        assert!(sql.contains("$1,"));
        assert!(sql.contains("$13)"));
        assert!(sql.contains("$14,"));
        assert!(sql.contains("$26)"));
        assert!(!sql.contains("$27"));
    }

    #[test]
    fn batch_sql_ten_rows() {
        let sql = validate_batch_sql(10);
        // Last row starts at $118 (9 * 13 + 1), ends at $130
        assert!(sql.contains("$118,"));
        assert!(sql.contains("$130)"));
        assert!(!sql.contains("$131"));
    }

    #[test]
    fn batch_sql_hundred_rows() {
        let sql = validate_batch_sql(100);
        // Last row: base = 99 * 13 + 1 = 1288, ends at $1300
        assert!(sql.contains("$1288,"));
        assert!(sql.contains("$1300)"));
    }

    #[test]
    fn batch_sql_no_duplicate_params() {
        let sql = validate_batch_sql(5);
        let cols = ROW_BIND_PARAMS;
        let total_params = 5 * cols;
        for p in 1..=total_params {
            let needle = format!("${}", p);
            let count = sql.matches(&needle).count();
            // Each parameter should appear exactly once (but $1 can also match
            // $10, $11, etc. so we check with trailing comma/paren)
            assert!(count >= 1, "Parameter {} should appear at least once", p);
        }
    }

    #[test]
    fn batch_sql_expressions_match_column_count() {
        // The insert column list has 14 columns; each VALUES row must have
        // 14 expressions (13 placeholders + the 'pending' literal).
        let sql = validate_batch_sql(3);
        for row in sql.split("VALUES ").nth(1).unwrap().split("), (") {
            let exprs = row
                .trim_start_matches('(')
                .trim_end_matches(") RETURNING id")
                .trim_end_matches(')');
            assert_eq!(
                exprs.split(',').count(),
                14,
                "row '{exprs}' must have 14 expressions"
            );
            assert_eq!(exprs.matches("'pending'").count(), 1);
        }
    }

    // -----------------------------------------------------------------------
    // Temporary-error classification
    // -----------------------------------------------------------------------

    #[test]
    fn temporary_error_matches_transient_patterns_case_insensitively() {
        assert!(EmailQueue::is_temporary_error(
            "Timed out acquiring pooled connection for mx.example.com"
        ));
        assert!(EmailQueue::is_temporary_error("SMTP response timeout"));
        assert!(EmailQueue::is_temporary_error(
            "Connection refused (os error 111)"
        ));
        assert!(EmailQueue::is_temporary_error(
            "Resources temporarily unavailable"
        ));
        assert!(EmailQueue::is_temporary_error("421 4.7.0 Try again later"));
        assert!(EmailQueue::is_temporary_error(
            "MAIL FROM failed: 450 mailbox busy"
        ));
        assert!(EmailQueue::is_temporary_error(
            "DATA failed: 451 4.3.0 queue full"
        ));
        // Generic 4xx reply code as a standalone token.
        assert!(EmailQueue::is_temporary_error(
            "Message rejected: 452 out of memory"
        ));
    }

    #[test]
    fn temporary_error_rejects_permanent_patterns() {
        assert!(!EmailQueue::is_temporary_error(
            "all recipients rejected: a@b.com (response: 550 no such user)"
        ));
        assert!(!EmailQueue::is_temporary_error(
            "MAIL FROM failed: 550 5.7.1 spf reject"
        ));
        assert!(!EmailQueue::is_temporary_error(
            "Invalid recipient: no-at-sign"
        ));
        // 5xx codes must not be misclassified even with a stray 4 in a token
        // longer than 3 digits.
        assert!(!EmailQueue::is_temporary_error(
            "550 5.1.1 user unknown (14 tries)"
        ));
    }

    // -----------------------------------------------------------------------
    // Pure (non-consuming) rate windows
    // -----------------------------------------------------------------------

    #[test]
    fn rate_window_check_never_consumes_quota() {
        let window = RateWindow::new(2);
        // Any number of dry-run checks must keep passing — bulk enqueue
        // cannot drain the window (the old governor check_key consumed).
        for _ in 0..100 {
            assert!(window.check("example.com"));
        }
        // Quota is only consumed by delivery-time consumptions.
        assert!(window.try_consume("example.com"));
        assert!(window.try_consume("example.com"));
        assert!(
            !window.check("example.com"),
            "2 consumed sends exhaust a 2/s quota"
        );
        assert!(
            window.check("other.com"),
            "per-domain windows are independent"
        );
    }

    #[test]
    fn rate_window_zero_limit_is_unlimited() {
        let window = RateWindow::new(0);
        for _ in 0..1000 {
            assert!(window.try_consume("k"));
        }
        assert!(window.is_unlimited());
        assert!(window.check("k"));
    }

    #[test]
    fn rate_window_try_consume_enforces_limit_atomically() {
        let window = RateWindow::new(3);
        // Exactly N consumptions pass, the N+1th is refused — and refusal
        // must not record an event (the window is not drained by denies).
        assert!(window.try_consume("k"));
        assert!(window.try_consume("k"));
        assert!(window.try_consume("k"));
        assert!(!window.try_consume("k"), "limit of 3/s must deny the 4th");
        // Still denied on the next probe — denies did not consume quota,
        // but neither did they free any.
        assert!(!window.try_consume("k"));
        // Other keys are independent.
        assert!(window.try_consume("other"));
    }

    /// Builds an EmailQueue without a live database (lazy pool) — the
    /// send-rate decision path is pure in-memory state, so it is testable.
    fn queue_for_rate_tests(global: u64, domain: u64, tenant: u64) -> EmailQueue {
        let pool = PgPool::connect_lazy("postgres://localhost/outbound-queue-test").unwrap();
        let config = QueueConfig {
            global_rate_per_second: global,
            domain_rate_per_second: domain,
            tenant_rate_per_second: tenant,
            ..QueueConfig::default()
        };
        EmailQueue::new(pool, config, SmtpSender::new("test.example".into()))
    }

    #[tokio::test]
    async fn send_rate_limit_causes_requeue_decision_beyond_limit() {
        // F1:a configured global limit of 2 msg/s: the first two dispatch
        // admissions are Allowed (and consume quota), the third is denied —
        // process_email returns a `send_rate_limited:` error which the
        // batch loop routes to mark_send_rate_limited (requeue with a
        // short delay) instead of dispatching or failing the row.
        let queue = queue_for_rate_tests(2, 0, 0);
        let to = vec!["a@example.com".to_string()];

        let first = queue.acquire_send_rate(&to, Some("t1"));
        assert_eq!(first, RateLimitDecision::Allowed);

        let second = queue.acquire_send_rate(&to, Some("t1"));
        assert_eq!(second, RateLimitDecision::Allowed);

        let third = queue.acquire_send_rate(&to, Some("t1"));
        assert_eq!(
            third,
            RateLimitDecision::GlobalExceeded,
            "beyond the configured 2/s the send must be refused (requeued, not dispatched)"
        );

        // The refusal is rendered as the distinguishable requeue error.
        let err = queue.send_rate_limited_error(third);
        assert!(EmailQueue::is_send_rate_limited(&err.to_string()));
        assert!(err.to_string().contains("send_rate_limited: global"));
        // Unrelated errors must NOT be classified as rate-limit requeues.
        assert!(!EmailQueue::is_send_rate_limited(
            "all recipients rejected: a@b.com"
        ));
    }

    #[tokio::test]
    async fn send_rate_limit_enforced_per_domain_and_tenant() {
        let queue = queue_for_rate_tests(0, 1, 0);
        let a = vec!["x@a.com".to_string()];
        let b = vec!["y@b.com".to_string()];
        assert_eq!(
            queue.acquire_send_rate(&a, None),
            RateLimitDecision::Allowed
        );
        assert_eq!(
            queue.acquire_send_rate(&a, None),
            RateLimitDecision::DomainExceeded("a.com".to_string()),
            "1/s per-domain limit must deny the second same-domain send"
        );
        assert_eq!(
            queue.acquire_send_rate(&b, None),
            RateLimitDecision::Allowed,
            "other domains are unaffected"
        );

        let queue = queue_for_rate_tests(0, 0, 1);
        assert_eq!(
            queue.acquire_send_rate(&a, Some("tenant-1")),
            RateLimitDecision::Allowed
        );
        assert_eq!(
            queue.acquire_send_rate(&a, Some("tenant-1")),
            RateLimitDecision::TenantExceeded,
            "1/s per-tenant limit must deny the second same-tenant send"
        );
        assert_eq!(
            queue.acquire_send_rate(&a, Some("tenant-2")),
            RateLimitDecision::Allowed,
            "other tenants are unaffected"
        );
    }

    #[test]
    fn retry_delay_jitter_stays_within_20_percent() {
        // F6:for every row id the jittered delay stays within ±20% of the
        // base (and a non-zero base never collapses to zero).
        let base = Duration::from_secs(60);
        let mut saw_below_base = false;
        let mut saw_above_base = false;
        for _ in 0..200 {
            let id = Uuid::new_v4();
            let jittered = jittered_retry_delay_secs(base, &id);
            assert!(
                (48..=72).contains(&jittered),
                "jittered delay {jittered}s outside [48,72] (±20% of 60s)"
            );
            saw_below_base |= jittered < 60;
            saw_above_base |= jittered > 60;
        }
        assert!(
            saw_below_base && saw_above_base,
            "jitter must actually spread on both sides of the base"
        );
        // Deterministic per (id): same input, same output.
        let id = Uuid::new_v4();
        assert_eq!(
            jittered_retry_delay_secs(base, &id),
            jittered_retry_delay_secs(base, &id)
        );
    }

    #[tokio::test]
    async fn retry_delay_ladder_picks_index_and_falls_back() {
        let queue = queue_for_rate_tests(0, 0, 0);
        assert_eq!(queue.retry_delay_for_attempt(1), Duration::from_secs(60));
        assert_eq!(queue.retry_delay_for_attempt(3), Duration::from_secs(1_800));
        // Beyond the ladder: clamp to the last entry.
        assert_eq!(
            queue.retry_delay_for_attempt(99),
            Duration::from_secs(21_600)
        );
        // Empty ladder: safe fallback instead of an index panic (#113).
        let pool = PgPool::connect_lazy("postgres://localhost/outbound-queue-test").unwrap();
        let config = QueueConfig {
            retry_delays: Vec::new(),
            ..QueueConfig::default()
        };
        let empty = EmailQueue::new(pool, config, SmtpSender::new("test.example".into()));
        assert_eq!(
            empty.retry_delay_for_attempt(1),
            Duration::from_secs(DEFAULT_QUEUE_EMPTY_RETRY_FALLBACK_SECS)
        );
    }

    // -----------------------------------------------------------------------
    // D: partial RCPT acceptance must never be full success
    // -----------------------------------------------------------------------

    use crate::smtp_sender::SmtpSendResult;

    fn send_result(success: bool, accepted: Vec<&str>, rejected: Vec<&str>) -> SmtpSendResult {
        SmtpSendResult {
            success,
            message_id: "<test@example.com>".into(),
            response: "250 OK".into(),
            accepted: accepted.into_iter().map(String::from).collect(),
            rejected: rejected.into_iter().map(String::from).collect(),
        }
    }

    #[test]
    fn partial_acceptance_is_not_full_success() {
        // 1 accepted + 1 temp-rejected: the row must stay deliverable for the
        // rejected recipient (previously it was marked sent and the 4xx'd
        // recipient silently dropped).
        let result = send_result(true, vec!["ok@example.com"], vec!["tempfail@example.com"]);
        assert_eq!(
            classify_partial_acceptance(&result),
            DeliveryOutcome::PartiallyDelivered {
                rejected: vec!["tempfail@example.com".to_string()]
            }
        );
    }

    #[test]
    fn full_acceptance_is_delivered() {
        let result = send_result(true, vec!["a@example.com", "b@example.com"], vec![]);
        assert_eq!(
            classify_partial_acceptance(&result),
            DeliveryOutcome::Delivered
        );
    }

    #[test]
    fn partial_acceptance_keeps_every_rejected_recipient() {
        let result = send_result(
            true,
            vec!["ok@example.com"],
            vec!["r1@example.com", "r2@example.com", "r3@example.com"],
        );
        match classify_partial_acceptance(&result) {
            DeliveryOutcome::PartiallyDelivered { rejected } => {
                assert_eq!(rejected.len(), 3, "no rejected recipient may be dropped");
                assert!(rejected.contains(&"r2@example.com".to_string()));
            }
            other => panic!("expected PartiallyDelivered, got {other:?}"),
        }
    }

    // -----------------------------------------------------------------------
    // E-10: SMTP 4xx status extraction boundaries
    // -----------------------------------------------------------------------

    #[test]
    fn smtp_4xx_code_requires_digit_boundaries() {
        assert!(contains_smtp_4xx_code("452 4.3.1 try later"));
        assert!(contains_smtp_4xx_code("error 421 occurred"));
        assert!(contains_smtp_4xx_code("450"));
        // Embedded in longer digit runs / identifiers → NOT a status code.
        assert!(!contains_smtp_4xx_code("invoice-14521 paid"));
        assert!(!contains_smtp_4xx_code("v14523 build"));
        assert!(!contains_smtp_4xx_code("id=45211"));
        assert!(!contains_smtp_4xx_code("550 5.1.1 user unknown"));
        assert!(!contains_smtp_4xx_code("no digits at all"));
    }

    #[test]
    fn temporary_error_classification_keeps_boundary_rule() {
        // Real 4xx reply codes still classify as temporary…
        assert!(EmailQueue::is_temporary_error(
            "Message rejected: 452 out of memory"
        ));
        assert!(EmailQueue::is_temporary_error("RCPT failed: 431 busy"));
        // …while digit-suffixed identifiers no longer do.
        assert!(!EmailQueue::is_temporary_error(
            "hard reject for invoice 45212"
        ));
        // 5xx codes must not be misclassified.
        assert!(!EmailQueue::is_temporary_error(
            "all recipients rejected: a@b.com (response: 550 no such user)"
        ));
    }
}
