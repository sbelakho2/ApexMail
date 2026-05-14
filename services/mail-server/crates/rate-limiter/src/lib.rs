//! Reusable rate-limiting primitives for ApexMail.
//!
//! Provides complementary strategies:
//! - **In-memory governor-based** rate limiter (token bucket, zero-alloc hot path)
//! - **Sliding window** counter (for quota enforcement without Redis)
//! - **Keyed multi-tenant** limiter with per-key governors and auto-eviction
//! - **Redis-backed** distributed rate limiter (shared state across all pods)

#![deny(unsafe_code)]
pub mod config;
pub mod governor_limiter;
pub mod keyed;
pub mod sliding_window;
pub mod types;

#[cfg(feature = "redis")]
pub mod redis_limiter;

pub use config::RateLimitConfig;
pub use governor_limiter::GovernorLimiter;
pub use keyed::KeyedRateLimiter;
pub use sliding_window::SlidingWindowCounter;
pub use types::{Decision, RateLimitError};

#[cfg(feature = "redis")]
pub use redis_limiter::RedisLimiter;
