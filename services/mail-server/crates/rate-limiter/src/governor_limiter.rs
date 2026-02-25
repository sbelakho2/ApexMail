//! Governor-based in-memory rate limiter.
//!
//! Wraps the `governor` crate in a simple interface with optional jitter.

use governor::{
    clock::DefaultClock,
    state::{InMemoryState, NotKeyed},
    Quota, RateLimiter,
};
use std::num::NonZeroU32;
use std::sync::Arc;
use std::time::Duration;
use tracing::debug;

use crate::config::RateLimitConfig;
use crate::types::Decision;

/// Single-key in-memory rate limiter backed by governor.
#[derive(Clone)]
pub struct GovernorLimiter {
    limiter: Arc<RateLimiter<NotKeyed, InMemoryState, DefaultClock>>,
    burst: NonZeroU32,
    jitter: Option<Duration>,
}

impl GovernorLimiter {
    /// Create a new limiter from config.
    pub fn new(config: &RateLimitConfig) -> Self {
        let burst = config.effective_burst();
        let quota = Quota::per_second(config.requests_per_second).allow_burst(burst);
        let limiter = Arc::new(RateLimiter::direct(quota));

        Self {
            limiter,
            burst,
            jitter: config.jitter_duration(),
        }
    }

    /// Create a limiter from raw parameters.
    pub fn from_params(rps: u32, burst: u32) -> Self {
        let config = RateLimitConfig::new(rps).with_burst(burst);
        Self::new(&config)
    }

    /// Check if a single request is allowed.
    /// #229: Note: `remaining` is approximate (burst capacity) as Governor doesn't expose actual count
    pub fn check(&self) -> Decision {
        match self.limiter.check() {
            Ok(()) => {
                // Governor doesn't expose remaining directly; approximate from burst.
                // For accurate remaining counts, use sliding_window limiter instead.
                Decision::Allowed {
                    remaining: self.burst.get() as u64,
                }
            }
            Err(not_until) => {
                let mut wait = not_until.wait_time_from(DefaultClock::default().now());
                if let Some(jitter) = self.jitter {
                    wait += jitter;
                }
                debug!(wait_ms = wait.as_millis(), "Rate limit exceeded");
                Decision::Denied { retry_after: wait }
            }
        }
    }

    /// Check if `n` requests are allowed (batch check).
    pub fn check_n(&self, n: u32) -> Decision {
        match NonZeroU32::new(n) {
            None => Decision::Allowed {
                remaining: self.burst.get() as u64,
            },
            Some(n) => match self.limiter.check_n(n) {
                Ok(Ok(())) => Decision::Allowed {
                    remaining: self.burst.get() as u64,
                },
                Ok(Err(_insufficient)) => Decision::Denied {
                    retry_after: Duration::from_millis(100),
                },
                Err(_insufficient) => Decision::Denied {
                    retry_after: Duration::from_millis(100),
                },
            },
        }
    }

    /// Async check that waits until a cell is available.
    pub async fn until_ready(&self) {
        self.limiter.until_ready().await;
    }

    /// Burst capacity.
    pub fn burst_size(&self) -> u32 {
        self.burst.get()
    }
}

// Need this for governor::clock
use governor::clock::Clock;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_governor_allows_burst() {
        let limiter = GovernorLimiter::from_params(10, 5);
        // First 5 should be allowed (burst)
        for _ in 0..5 {
            assert!(limiter.check().is_allowed());
        }
    }

    #[test]
    fn test_governor_denies_after_burst() {
        let limiter = GovernorLimiter::from_params(1, 1);
        assert!(limiter.check().is_allowed());
        // Second request should be denied (only 1 burst, 1/sec refill)
        let d = limiter.check();
        assert!(d.is_denied());
    }

    #[test]
    fn test_governor_retry_after() {
        let limiter = GovernorLimiter::from_params(1, 1);
        limiter.check(); // consume burst
        if let Decision::Denied { retry_after } = limiter.check() {
            assert!(retry_after > Duration::ZERO);
            assert!(retry_after <= Duration::from_secs(2));
        }
    }

    #[test]
    fn test_governor_with_jitter() {
        let config = RateLimitConfig::new(1).with_burst(1).with_jitter(500);
        let limiter = GovernorLimiter::new(&config);
        limiter.check(); // consume burst
        if let Decision::Denied { retry_after } = limiter.check() {
            // Should include jitter
            assert!(retry_after >= Duration::from_millis(500));
        }
    }

    #[test]
    fn test_governor_check_n_zero() {
        let limiter = GovernorLimiter::from_params(10, 5);
        assert!(limiter.check_n(0).is_allowed());
    }

    #[test]
    fn test_governor_check_n_within_burst() {
        let limiter = GovernorLimiter::from_params(10, 5);
        assert!(limiter.check_n(3).is_allowed());
    }

    #[test]
    fn test_governor_burst_size() {
        let limiter = GovernorLimiter::from_params(10, 25);
        assert_eq!(limiter.burst_size(), 25);
    }

    #[tokio::test]
    async fn test_governor_until_ready() {
        let limiter = GovernorLimiter::from_params(1000, 1);
        limiter.check(); // consume one
        // should complete quickly at 1000 rps
        tokio::time::timeout(Duration::from_millis(50), limiter.until_ready())
            .await
            .expect("Should complete within 50ms");
    }
}
