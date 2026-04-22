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
