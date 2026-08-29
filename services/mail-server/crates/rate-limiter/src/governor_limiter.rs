//! Governor-based in-memory rate limiter.
//!
//! Wraps the `governor` crate in a simple interface with optional jitter.

use governor::{
    clock::DefaultClock,
    state::{InMemoryState, NotKeyed},
    Quota, RateLimiter,
};
use std::num::NonZeroU32;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tracing::debug;

use crate::config::RateLimitConfig;
use crate::types::Decision;

/// Single-key in-memory rate limiter backed by governor.
#[derive(Clone)]
pub struct GovernorLimiter {
    limiter: Arc<RateLimiter<NotKeyed, InMemoryState, DefaultClock>>,
    burst: NonZeroU32,
    /// Steady refill rate (requests per second), used to compute the
    /// retry-after for batch requests that can never fit in the burst.
    rps: u32,
    jitter: Option<Duration>,
    /// F14:tokens consumed in the current window (approximation — decayed
    /// at the steady refill rate, clamped at 0). Shared across clones so
    /// the reported `remaining` reflects real consumption instead of
    /// always reporting the full burst.
    consumed: Arc<AtomicI64>,
    /// Wall clock of the last refill decay applied to `consumed`.
    last_decay: Arc<Mutex<Instant>>,
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
            rps: config.requests_per_second.get(),
            jitter: config.jitter_duration(),
            consumed: Arc::new(AtomicI64::new(0)),
            last_decay: Arc::new(Mutex::new(Instant::now())),
        }
    }

    /// Create a limiter from raw parameters.
    pub fn from_params(rps: u32, burst: u32) -> Self {
        let config = RateLimitConfig::new(rps).with_burst(burst);
        Self::new(&config)
    }

    /// F14:decay the consumed-token approximation by the tokens refilled
    /// since the last decay (steady `rps` rate, floored, clamped at 0).
    fn decay_consumed(&self) {
        let mut last = self.last_decay.lock().unwrap_or_else(|e| e.into_inner());
        let elapsed = last.elapsed();
        if elapsed.is_zero() {
            return;
        }
        let refilled = (elapsed.as_secs_f64() * f64::from(self.rps)).floor() as i64;
        if refilled > 0 {
            let prev = self.consumed.fetch_sub(refilled, Ordering::Relaxed);
            if prev - refilled < 0 {
                self.consumed.store(0, Ordering::Relaxed);
            }
            *last = Instant::now();
        }
    }

    /// F14:record `n` allowed requests against the consumption tracker.
    fn record_consumed(&self, n: u32) {
        self.consumed.fetch_add(i64::from(n), Ordering::Relaxed);
    }

    /// F14:tokens remaining after the recorded consumption. For an unused
    /// limiter this equals the burst — the true remaining of a full bucket;
    /// the burst is only reported when nothing has been consumed.
    fn remaining(&self) -> u64 {
        let consumed = self.consumed.load(Ordering::Relaxed).max(0) as u64;
        (self.burst.get() as u64).saturating_sub(consumed)
    }

    /// Check if a single request is allowed.
    ///
    /// F14/#229:`remaining` used to ALWAYS report the full burst because
    /// governor exposes no token count — callers could not see exhaustion
    /// approaching. Consumption is now tracked (decayed at the refill
    /// rate), so `remaining` is the real post-check budget.
    pub fn check(&self) -> Decision {
        match self.limiter.check() {
            Ok(()) => {
                metrics::counter!("rate_limiter_requests_total", "strategy" => "governor", "decision" => "allowed").increment(1);
                self.decay_consumed();
                self.record_consumed(1);
                Decision::Allowed {
                    remaining: self.remaining(),
                }
            }
            Err(not_until) => {
                self.decay_consumed();
                metrics::counter!("rate_limiter_requests_total", "strategy" => "governor", "decision" => "denied").increment(1);
                metrics::counter!("rate_limiter_blocked_total", "strategy" => "governor")
                    .increment(1);
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
            None => {
                self.decay_consumed();
                Decision::Allowed {
                    remaining: self.remaining(),
                }
            }
            Some(n) => {
                let rps = self.rps;
                match self.limiter.check_n(n) {
                    Ok(Ok(())) => {
                        metrics::counter!("rate_limiter_requests_total", "strategy" => "governor_batch", "decision" => "allowed").increment(n.get() as u64);
                        self.decay_consumed();
                        self.record_consumed(n.get());
                        Decision::Allowed {
                            remaining: self.remaining(),
                        }
                    }
                    Err(_insufficient) => {
                        // `n` exceeds the burst capacity permanently — the
                        // wait is the time to accumulate `n` tokens at the
                        // steady rate (fix K5: previously a hardcoded 100ms
                        // regardless of state).
                        metrics::counter!("rate_limiter_requests_total", "strategy" => "governor_batch", "decision" => "denied").increment(n.get() as u64);
                        metrics::counter!("rate_limiter_blocked_total", "strategy" => "governor_batch").increment(1);
                        Decision::Denied {
                            retry_after: tokens_wait_time(n.get(), rps),
                        }
                    }
                    Ok(Err(not_until)) => {
                        // Not enough tokens RIGHT NOW — compute the real
                        // wait from the limiter state instead of a constant.
                        metrics::counter!("rate_limiter_requests_total", "strategy" => "governor_batch", "decision" => "denied").increment(n.get() as u64);
                        metrics::counter!("rate_limiter_blocked_total", "strategy" => "governor_batch").increment(1);
                        let mut wait = not_until.wait_time_from(DefaultClock::default().now());
                        if let Some(jitter) = self.jitter {
                            wait += jitter;
                        }
                        Decision::Denied { retry_after: wait }
                    }
                }
            }
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

/// Time to accumulate `n` tokens at `rps` requests/second (rounded up,
/// minimum 1ms so callers never see a zero retry-after).
fn tokens_wait_time(n: u32, rps: u32) -> Duration {
    let nanos = (u64::from(n) * 1_000_000_000) / u64::from(rps.max(1));
    Duration::from_nanos(nanos.max(1_000_000))
}

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
        let result = tokio::time::timeout(Duration::from_millis(50), limiter.until_ready()).await;
        assert!(result.is_ok(), "Should complete within 50ms");
    }

    // ── Fix K5:check_n retry_after computed from state ─────────────

    #[test]
    fn test_check_n_insufficient_capacity_retry_after_scaled() {
        // Requesting more than the burst can EVER hold: retry-after must
        // reflect the time to accumulate n tokens (10 tokens at 2 rps ≈ 5s),
        // not the previous hardcoded 100ms.
        let limiter = GovernorLimiter::from_params(2, 5);
        let decision = limiter.check_n(10);
        match decision {
            Decision::Denied { retry_after } => {
                assert!(
                    retry_after >= Duration::from_secs(4),
                    "10 tokens at 2rps needs ~5s, got {retry_after:?}"
                );
                assert!(retry_after <= Duration::from_secs(6));
            }
            other => panic!("expected denied, got {other:?}"),
        }
    }

    #[test]
    fn test_check_n_not_enough_tokens_retry_after_from_state() {
        // n fits in burst capacity but tokens are exhausted: retry-after
        // comes from the limiter's state (≈ refill time), not a constant.
        let limiter = GovernorLimiter::from_params(1, 2);
        assert!(limiter.check_n(2).is_allowed()); // drain burst
        let decision = limiter.check_n(2);
        match decision {
            Decision::Denied { retry_after } => {
                assert!(
                    retry_after > Duration::from_millis(500),
                    "2 tokens at 1rps needs ~2s, got {retry_after:?}"
                );
            }
            other => panic!("expected denied, got {other:?}"),
        }
    }

    // ── F14:remaining must reflect real consumption ──────────────────
    //
    // All use rps=1 so the consumed-tracker decay (which refills at the
    // rps rate) needs a FULL second of wall time — adjacent statements
    // execute in microseconds, so the counts are deterministic.

    #[test]
    fn test_remaining_falls_with_each_allowed_check() {
        // Previously `remaining` always reported the full burst — callers
        // could not see exhaustion approaching.
        let limiter = GovernorLimiter::from_params(1, 5);
        assert_eq!(limiter.check().remaining(), 4, "burst 5, 1 consumed");
        assert_eq!(limiter.check().remaining(), 3);
        assert_eq!(limiter.check().remaining(), 2);
    }

    #[test]
    fn test_remaining_reaches_zero_at_exhaustion() {
        let limiter = GovernorLimiter::from_params(1, 3);
        for expected in [2u64, 1, 0] {
            let d = limiter.check();
            assert!(d.is_allowed());
            assert_eq!(d.remaining(), expected);
        }
        // Fully drained: the next check is denied.
        assert!(limiter.check().is_denied());
    }

    #[test]
    fn test_remaining_batch_consumes_n() {
        let limiter = GovernorLimiter::from_params(1, 5);
        let d = limiter.check_n(3);
        assert!(d.is_allowed());
        assert_eq!(d.remaining(), 2, "burst 5 minus a 3-token batch");
        // Zero-batch must not consume.
        assert_eq!(limiter.check_n(0).remaining(), 2);
    }

    #[test]
    fn test_remaining_recovers_with_refill() {
        // Drain fully (remaining 0, denied), wait for the 1rps steady
        // refill, then an allowed check consumes exactly the refilled
        // token — remaining reports 0 again, proving the tracker follows
        // the refill rather than sticking at the drained value.
        let limiter = GovernorLimiter::from_params(1, 2);
        assert_eq!(limiter.check().remaining(), 1);
        assert_eq!(limiter.check().remaining(), 0);
        assert!(limiter.check().is_denied());
        std::thread::sleep(Duration::from_millis(1_200));
        let d = limiter.check();
        assert!(
            d.is_allowed(),
            "refill at 1rps must recover a token within 1.2s"
        );
        assert_eq!(
            d.remaining(),
            0,
            "the single refilled token was just consumed"
        );
    }
}
