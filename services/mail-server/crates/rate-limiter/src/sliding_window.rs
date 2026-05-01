//! In-memory sliding window counter without Redis dependency.
//!
//! Uses two half-windows for interpolation to avoid the boundary-spike issue
//! of simple fixed-window counters.

use parking_lot::RwLock;
use std::time::{Duration, Instant};

use crate::config::SlidingWindowConfig;
use crate::types::Decision;

/// In-memory sliding window rate limiter.
/// Uses two consecutive fixed windows and interpolates the count
/// based on the current position within the window.
pub struct SlidingWindowCounter {
    state: RwLock<WindowState>,
    max_events: u64,
    window: Duration,
}

struct WindowState {
    /// Count in the previous window.
    prev_count: u64,
    /// Count in the current window.
    curr_count: u64,
    /// When the current window started.
    curr_window_start: Instant,
    /// Window duration.
    window: Duration,
}

impl WindowState {
    fn new(window: Duration) -> Self {
        Self {
            prev_count: 0,
            curr_count: 0,
            curr_window_start: Instant::now(),
            window,
        }
    }

    /// Rotate windows if the current one has expired.
    fn maybe_rotate(&mut self, now: Instant) {
        let elapsed = now.duration_since(self.curr_window_start);

        if elapsed >= self.window * 2 {
            // Been idle for 2+ windows — reset everything
            self.prev_count = 0;
            self.curr_count = 0;
            self.curr_window_start = now;
        } else if elapsed >= self.window {
            // Rotate:current → previous
            self.prev_count = self.curr_count;
            self.curr_count = 0;
            // Advance window start by one window duration
            self.curr_window_start += self.window;
        }
    }

    /// Calculate the weighted count using linear interpolation.
    fn weighted_count(&self, now: Instant) -> f64 {
        let elapsed = now.duration_since(self.curr_window_start).as_secs_f64();
        let window_secs = self.window.as_secs_f64();
        let pct_into_window = (elapsed / window_secs).min(1.0);

        // Weight of previous window decreases as we move through current window
        let prev_weight = 1.0 - pct_into_window;
        (self.prev_count as f64 * prev_weight) + self.curr_count as f64
    }
}

impl SlidingWindowCounter {
    /// Create a new sliding window counter.
    pub fn new(config: &SlidingWindowConfig) -> Self {
        let window = Duration::from_millis(config.window_ms);
        Self {
            state: RwLock::new(WindowState::new(window)),
            max_events: config.max_events,
            window,
        }
    }

    /// Create with simple parameters.
    pub fn from_params(window: Duration, max_events: u64) -> Self {
        Self {
            state: RwLock::new(WindowState::new(window)),
            max_events,
            window,
        }
    }

    /// Record an event and check if it's within limits.
    pub fn check_and_increment(&self) -> Decision {
        let now = Instant::now();
        let mut state = self.state.write();
        state.maybe_rotate(now);

        let current_estimate = state.weighted_count(now);

        if current_estimate >= self.max_events as f64 {
            let elapsed = now.duration_since(state.curr_window_start);
            let remaining_window = self.window.saturating_sub(elapsed);
            Decision::Denied {
                retry_after: remaining_window,
            }
        } else {
            state.curr_count += 1;
            let new_estimate = state.weighted_count(now);
            let remaining = (self.max_events as f64 - new_estimate).max(0.0) as u64;
            Decision::Allowed { remaining }
        }
    }

    /// Read-only check without incrementing.
    pub fn peek(&self) -> Decision {
        let now = Instant::now();
        let mut state = self.state.write();
        state.maybe_rotate(now);

        let current_estimate = state.weighted_count(now);
        if current_estimate >= self.max_events as f64 {
            let elapsed = now.duration_since(state.curr_window_start);
            let remaining_window = self.window.saturating_sub(elapsed);
            Decision::Denied {
                retry_after: remaining_window,
            }
        } else {
            let remaining = (self.max_events as f64 - current_estimate).max(0.0) as u64;
            Decision::Allowed { remaining }
        }
    }

    /// Current approximate event count.
    pub fn current_count(&self) -> u64 {
        let now = Instant::now();
        let mut state = self.state.write();
        state.maybe_rotate(now);
        state.weighted_count(now).ceil() as u64
    }

    /// Reset the counter.
    pub fn reset(&self) {
        let mut state = self.state.write();
        *state = WindowState::new(self.window);
    }

    /// Max events allowed.
    pub fn limit(&self) -> u64 {
        self.max_events
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sliding_window_allows_initial() {
        let counter = SlidingWindowCounter::from_params(Duration::from_secs(1), 10);
        let decision = counter.check_and_increment();
        assert!(decision.is_allowed());
        assert!(decision.remaining() > 0);
    }

    #[test]
    fn test_sliding_window_blocks_at_limit() {
        let counter = SlidingWindowCounter::from_params(Duration::from_secs(60), 5);
        for _ in 0..5 {
            assert!(counter.check_and_increment().is_allowed());
        }
        let decision = counter.check_and_increment();
        assert!(decision.is_denied());
    }

    #[test]
    fn test_sliding_window_peek_no_mutation() {
        let counter = SlidingWindowCounter::from_params(Duration::from_secs(60), 5);
        counter.check_and_increment();
        let count_before = counter.current_count();
        counter.peek();
        let count_after = counter.current_count();
        assert_eq!(count_before, count_after);
    }

    #[test]
    fn test_sliding_window_reset() {
        let counter = SlidingWindowCounter::from_params(Duration::from_secs(60), 5);
        for _ in 0..5 {
            counter.check_and_increment();
        }
        counter.reset();
        assert_eq!(counter.current_count(), 0);
        assert!(counter.check_and_increment().is_allowed());
    }

    #[test]
    fn test_sliding_window_limit() {
        let counter = SlidingWindowCounter::from_params(Duration::from_secs(60), 42);
        assert_eq!(counter.limit(), 42);
    }

    #[test]
    fn test_sliding_window_denies_with_retry_after() {
        let counter = SlidingWindowCounter::from_params(Duration::from_secs(10), 1);
        counter.check_and_increment();
        let decision = counter.check_and_increment();
        if let Decision::Denied { retry_after } = decision {
            assert!(retry_after > Duration::ZERO);
            assert!(retry_after <= Duration::from_secs(10));
        } else {
            assert!(decision.is_denied(), "Expected Denied");
        }
    }

    #[test]
    fn test_sliding_window_from_config() {
        let cfg = SlidingWindowConfig::per_minute(100);
        let counter = SlidingWindowCounter::new(&cfg);
        assert_eq!(counter.limit(), 100);
    }
}
