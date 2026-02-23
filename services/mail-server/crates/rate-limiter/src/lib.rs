//! Reusable rate-limiting primitives for ApexMail.
//!
//! Provides three complementary strategies:
//! - **In-memory governor-based** rate limiter (token bucket, zero-alloc hot path)
//! - **Sliding window** counter (for quota enforcement without Redis)
//! - **Keyed multi-tenant** limiter with per-key governors and auto-eviction

pub mod config;
pub mod governor_limiter;
pub mod keyed;
pub mod sliding_window;
pub mod types;

pub use config::RateLimitConfig;
pub use governor_limiter::GovernorLimiter;
pub use keyed::KeyedRateLimiter;
pub use sliding_window::SlidingWindowCounter;
pub use types::{Decision, RateLimitError};
