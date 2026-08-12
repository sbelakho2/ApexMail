//! In-process circuit breaker guarding the risk state backend.
//!
//! After `failure_threshold` consecutive failures the breaker opens for
//! `open_ms`; while open, the engine skips the state backend entirely and
//! returns degraded decisions. Any success closes it again.
//!
//! Counters are per-instance (in-process, non-persistent): independent
//! breakers never bleed state into each other.

use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

/// Consecutive-failure circuit breaker (defaults: 2 failures, 1000 ms open).
pub struct CircuitBreaker {
    failures: AtomicU32,
    /// 0 = closed; otherwise the epoch-ms timestamp when the breaker opened.
    opened_at_ms: AtomicU64,
    failure_threshold: u32,
    open_ms: u64,
}

impl Default for CircuitBreaker {
    fn default() -> CircuitBreaker {
        CircuitBreaker::new(2, 1000)
    }
}

impl CircuitBreaker {
    pub fn new(failure_threshold: u32, open_ms: u64) -> CircuitBreaker {
        assert!(failure_threshold >= 1, "failureThreshold must be >= 1");
        assert!(open_ms >= 1, "openMs must be >= 1");
        CircuitBreaker {
            failures: AtomicU32::new(0),
            opened_at_ms: AtomicU64::new(0),
            failure_threshold,
            open_ms,
        }
    }

    /// True when the breaker is currently open. An expired open window
    /// closes the breaker (half-open on the next probe).
    pub fn is_open(&self) -> bool {
        let opened_at = self.opened_at_ms.load(Ordering::Relaxed);
        if opened_at == 0 {
            return false;
        }
        if now_ms().saturating_sub(opened_at) >= self.open_ms {
            self.opened_at_ms.store(0, Ordering::Relaxed);
            self.failures.store(0, Ordering::Relaxed);
            return false;
        }
        true
    }

    /// Records one backend failure; opens the breaker when the consecutive
    /// failure count reaches the threshold.
    pub fn record_failure(&self) {
        if self.opened_at_ms.load(Ordering::Relaxed) != 0 {
            return;
        }
        let failures = self.failures.fetch_add(1, Ordering::Relaxed) + 1;
        if failures >= self.failure_threshold {
            self.opened_at_ms.store(now_ms(), Ordering::Relaxed);
        }
    }

    /// Records one backend success; closes the breaker and resets the
    /// failure count.
    pub fn record_success(&self) {
        self.failures.store(0, Ordering::Relaxed);
        self.opened_at_ms.store(0, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn opens_after_two_consecutive_failures() {
        let breaker = CircuitBreaker::new(2, 60_000);
        assert!(!breaker.is_open());
        breaker.record_failure();
        assert!(!breaker.is_open());
        breaker.record_failure();
        assert!(breaker.is_open());
        // Failures while open are ignored.
        breaker.record_failure();
        assert!(breaker.is_open());
    }

    #[test]
    fn success_resets() {
        let breaker = CircuitBreaker::new(2, 60_000);
        breaker.record_failure();
        breaker.record_success();
        breaker.record_failure();
        assert!(!breaker.is_open());
        breaker.record_failure();
        assert!(breaker.is_open());
    }

    #[test]
    fn recovers_after_open_window() {
        let breaker = CircuitBreaker::new(2, 50);
        breaker.record_failure();
        breaker.record_failure();
        assert!(breaker.is_open());
        std::thread::sleep(Duration::from_millis(60));
        assert!(
            !breaker.is_open(),
            "window must elapse and close the breaker"
        );
    }
}
