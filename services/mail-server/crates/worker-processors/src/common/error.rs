//! Error types for worker processors.

use thiserror::Error;

/// Result type alias for processor operations.
pub type ProcessorResult<T> = Result<T, ProcessorError>;

/// Errors that can occur during processor operations.
#[derive(Debug, Error)]
pub enum ProcessorError {
    /// Database error.
    #[error("database error: {0}")]
    Database(#[from] sqlx::Error),

    /// Redis error.
    #[error("redis error: {0}")]
    Redis(#[from] redis::RedisError),

    /// Redis pool error.
    #[error("redis pool error: {0}")]
    RedisPool(#[from] deadpool_redis::PoolError),

    /// HTTP request error (webhook delivery).
    #[error("http error: {0}")]
    Http(#[from] reqwest::Error),

    /// JSON serialization/deserialization error.
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),

    /// DNS resolution error.
    #[error("dns error: {0}")]
    Dns(String),

    /// SSRF protection triggered.
    #[error("ssrf blocked: {0}")]
    SsrfBlocked(String),

    /// Circuit breaker is open.
    #[error("circuit breaker open for {0}")]
    CircuitOpen(String),

    /// Rate limit exceeded.
    #[error("rate limit exceeded: {0}")]
    RateLimited(String),

    /// Invalid configuration.
    #[error("config error: {0}")]
    Config(String),

    /// Email transport error.
    #[error("email transport error: {0}")]
    Transport(String),

    /// SMTP reply error carrying the structured reply code (F-21).
    ///
    /// `code` is the leading 3-digit SMTP reply code (e.g. 550) and is never
    /// redacted; only the free-text `message` tail passes through redaction.
    /// Callers classify by `code` (4xx temporary → retry, 5xx permanent →
    /// hard bounce) instead of substring matching on a redacted string.
    #[error("smtp error {code}: {message}")]
    Smtp {
        /// 3-digit SMTP reply code (400..=599).
        code: u16,
        /// Enhanced status code (e.g. "5.1.1"), when the reply carried one.
        enhanced: Option<String>,
        /// Redacted free-text part of the reply.
        message: String,
    },

    /// AWS SES send failure carrying the retry disposition decided at the
    /// transport SOURCE, where the typed SDK error (modeled exception code /
    /// HTTP status) is still available — mirroring the `Smtp { code }`
    /// pattern so the processor never has to substring-match a flattened
    /// `Transport("SES send failed: …")` string.
    ///
    /// * `permanent: true` takes the no-retry (hard-bounce) path for THIS
    ///   message: 5xx-class service refusals and address-shaped rejections.
    /// * `permanent: false` (4xx / network / dispatch) retries with the
    ///   standard exponential backoff, bounded by `max_retries`.
    /// * `address_proving` is the SUPPRESSION verdict and is independent of
    ///   `permanent`: only address-proving failures (mailbox does not
    ///   exist / malformed recipient) may suppress the recipient
    ///   tenant-wide. Account/configuration states (sending paused,
    ///   suspended, missing resource) can permanent-fail a message without
    ///   saying anything about the validity of the mailbox — suppressing on
    ///   those silences valid recipients for the whole tenant.
    /// * Throttle-class errors keep the distinct
    ///   [`ProcessorError::RateLimited`] variant.
    #[error("ses error: {message}")]
    Ses {
        /// Retry disposition decided from the typed SDK error.
        permanent: bool,
        /// Whether the failure PROVES the recipient address is invalid —
        /// the sole justification for tenant-wide suppression.
        address_proving: bool,
        /// SDK error message (already classified; not re-parsed downstream).
        message: String,
    },

    /// The outbound-MTA acceptance record did not VERIFY the dedicated
    /// source-IP binding the route reserved: the report was missing, or the
    /// requested/actual IP disagreed with the route.
    ///
    /// This is a HARD failure for this message — the relay already completed
    /// the external effect (post-DATA acceptance), so retrying would risk a
    /// duplicate; and it is deliberately NOT address-proving, so the
    /// recipient is never suppressed. The processor releases the warmup
    /// reservation (capacity may only count a VERIFIED binding).
    #[error("source binding unverified: {0}")]
    SourceBindingUnverified(String),

    /// DKIM signing error.
    #[error("dkim error: {0}")]
    Dkim(String),

    /// Classification error.
    #[error("classification error: {0}")]
    Classification(String),

    /// Suppression check error.
    #[error("suppression error: {0}")]
    Suppression(String),

    /// Job processing error.
    #[error("job error: {0}")]
    Job(String),

    /// Task cancelled/shutdown.
    #[error("processor shutdown")]
    Shutdown,

    /// Generic internal error.
    #[error("internal error: {0}")]
    Internal(#[from] anyhow::Error),
}
