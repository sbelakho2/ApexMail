//! Common types, traits, and utilities shared across all processors.

pub mod circuit_breaker;
pub mod config;
pub mod error;
pub mod pool;

pub use circuit_breaker::{CircuitBreaker, CircuitBreakerConfig, CircuitState};
pub use config::{
    AnalyticsConfig, DkimConfig, EmailConfig, IpRateLimitConfig,
    ProcessorConfig, ReplyHandlerConfig, SmtpConfig, TrackingConfig, WarmupConfig, WebhookConfig,
};
pub use error::{ProcessorError, ProcessorResult};
pub use pool::{create_db_pool, create_redis_pool, DbPool, RedisPool};
