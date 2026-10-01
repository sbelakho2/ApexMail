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
            metrics::counter!("rate_limiter_requests_total", "strategy" => "sliding_window", "decision" => "denied").increment(1);
            metrics::counter!("rate_limiter_blocked_total", "strategy" => "sliding_window")
                .increment(1);
            let retry_after = retry_after_until_below_max(
                state.prev_count,
                state.curr_count,
                self.max_events,
                now.duration_since(state.curr_window_start),
                self.window,
            );
            Decision::Denied { retry_after }
        } else {
            metrics::counter!("rate_limiter_requests_total", "strategy" => "sliding_window", "decision" => "allowed").increment(1);
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
            let retry_after = retry_after_until_below_max(
                state.prev_count,
                state.curr_count,
                self.max_events,
                now.duration_since(state.curr_window_start),
                self.window,
            );
            Decision::Denied { retry_after }
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

/// Time until the weighted estimate `prev·(1-p) + curr` actually drops
/// below `max_events` for a compliant (waiting) client (audit F13).
///
/// The previous denial path returned `window - elapsed`, but the weighted
/// estimate stays `>= max_events` for the rest of the current window AND —
/// once `curr` rotates into the previous weight — potentially through the
/// whole next window when `curr_count` alone exceeds the limit. A client
/// honoring the old `retry_after` re-requested up to a full window early
/// and was denied again.
///
/// Solve `prev·(1-p) + curr < max` for the window progress `p`:
/// * solvable inside the current window (when `0 < prev` and `curr < max`)
///   → `retry = W·(prev+curr-max)/prev − elapsed`;
/// * otherwise the current window must fully elapse; after the rotation the
///   current count becomes the previous weight, and (when `curr > max`) the
///   estimate only drops below `max` after a further
///   `W·(curr−max)/curr` — the old code reported just `window − elapsed`.
///
/// A 1 ms floor guarantees the caller re-arrives strictly PAST the solved
/// boundary (the estimate is a closed `>=` comparison at exactly `p*`).
fn retry_after_until_below_max(
    prev_count: u64,
    curr_count: u64,
    max_events: u64,
    elapsed: Duration,
    window: Duration,
) -> Duration {
    const FLOOR: Duration = Duration::from_millis(1);
    let remaining_window = window.saturating_sub(elapsed);

    if prev_count > 0 && curr_count < max_events {
        // prev + curr - max > 0 whenever the estimate is at/over the limit
        // (prev·(1-e/W) >= max - curr implies prev+curr-max >= prev·e/W).
        let numer = prev_count
            .saturating_add(curr_count)
            .saturating_sub(max_events);
        if numer == 0 {
            return FLOOR;
        }
        let progress_needed = numer as f64 / prev_count as f64; // in (0, 1): curr < max
        let needed_from_window_start = window.mul_f64(progress_needed);
        // ADD the floor, don't clamp to it: the estimate's `>= max` denial is
        // a CLOSED comparison, so a client arriving at exactly `p*` (the
        // solved boundary) is still denied. The old `.max(FLOOR)` clamp only
        // protected sub-millisecond waits — for any longer solved wait the
        // return landed exactly ON the boundary and the compliant client was
        // denied again (adversarial re-verification of audit F13).
        return needed_from_window_start
            .saturating_sub(elapsed)
            .saturating_add(FLOOR);
    }

    // Unsolvable within the current window: it must rotate first (prev→curr
    // becomes the only weight). If curr alone already exceeds the limit the
    // estimate additionally needs W·(curr-max)/curr of the NEXT window to
    // decay below max. The floor guarantees arrival strictly after the
    // rotation boundary (at exactly `remaining` the estimate still equals
    // curr, which is >= max when curr == max).
    let extra_next_window = if curr_count > max_events {
        window.mul_f64((curr_count - max_events) as f64 / curr_count as f64)
    } else {
        Duration::ZERO
    };
    remaining_window
        .saturating_add(extra_next_window)
        .saturating_add(FLOOR)
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
        let window = Duration::from_secs(10);
        let counter = SlidingWindowCounter::from_params(window, 1);
        counter.check_and_increment();
        let decision = counter.check_and_increment();
        if let Decision::Denied { retry_after } = decision {
            // prev=0, curr=1 at the limit: the solved wait is the remaining
            // window plus the 1 ms strict-boundary floor (audit F13).
            assert!(retry_after > Duration::ZERO);
            assert!(
                retry_after <= window + Duration::from_millis(5),
                "rotation-boundary wait may exceed the window only by the floor"
            );
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

    // ── Fix K4 verification:weighted sliding window prevents the
    // 2× boundary burst of a plain fixed-window counter. ────────────

    #[test]
    fn test_sliding_window_no_boundary_double_burst() {
        // Adversarial timing: exhaust the limit at the very end of a
        // window and immediately hammer the boundary. With a fixed-window
        // counter the attacker gets a full second burst (2× limit); the
        // weighted previous-window count must deny it.
        let window = Duration::from_millis(200);
        let counter = SlidingWindowCounter::from_params(window, 3);

        // Exhaust the limit inside window 1
        for _ in 0..3 {
            assert!(counter.check_and_increment().is_allowed());
        }
        assert!(counter.check_and_increment().is_denied());

        // Cross the window boundary
        std::thread::sleep(window + Duration::from_millis(15));

        // The previous window's count is still weighted at ~93% — at most
        // a single extra event may slip in before denial.
        let mut allowed_after_boundary = 0;
        for _ in 0..3 {
            if counter.check_and_increment().is_allowed() {
                allowed_after_boundary += 1;
            }
        }
        assert!(
            allowed_after_boundary <= 1,
            "boundary must not grant a second full burst, got {allowed_after_boundary} extra events"
        );
    }

    #[test]
    fn test_sliding_window_old_events_age_out() {
        // Legitimate recovery: after a full window idle, the budget resets.
        let window = Duration::from_millis(80);
        let counter = SlidingWindowCounter::from_params(window, 2);
        assert!(counter.check_and_increment().is_allowed());
        assert!(counter.check_and_increment().is_allowed());
        assert!(counter.check_and_increment().is_denied());

        // Idle for 2+ windows (full reset in maybe_rotate)
        std::thread::sleep(window * 2 + Duration::from_millis(30));
        assert!(
            counter.check_and_increment().is_allowed(),
            "after 2 idle windows the budget must fully reset"
        );
    }

    // ── Audit F13: retry_after must cover the REAL admission time ──────

    /// Pure-math table for `retry_after_until_below_max` (no sleeps).
    /// Durations are compared with a 2 ms tolerance (f64 progress math).
    #[test]
    fn retry_after_solver_matches_the_weighted_estimate() {
        let window = Duration::from_secs(10);
        let tol = Duration::from_millis(2);
        let near = |a: Duration, b: Duration| a.abs_diff(b) <= tol;

        // Case 1 — solvable in-window: prev=5, curr=0, max=4, elapsed=0.
        // Need p > (5+0-4)/5 = 0.2 → 2s into the window.
        assert!(near(
            retry_after_until_below_max(5, 0, 4, Duration::ZERO, window),
            Duration::from_secs(2)
        ));
        // Mid-window: elapsed=1s → 1s left.
        assert!(near(
            retry_after_until_below_max(5, 0, 4, Duration::from_secs(1), window),
            Duration::from_secs(1)
        ));

        // Case 2 — unsolvable in-window (curr alone at the limit):
        // prev=0, curr=4, max=4 → the window must rotate; 10s remaining.
        assert!(near(
            retry_after_until_below_max(0, 4, 4, Duration::ZERO, window),
            Duration::from_secs(10) + Duration::from_millis(1)
        ));

        // Case 3 — curr EXCEEDS max: prev=0, curr=10, max=4 → after the
        // rotation a further 10s·(10-4)/10 = 6s of decay is needed.
        assert!(near(
            retry_after_until_below_max(0, 10, 4, Duration::from_secs(3), window),
            Duration::from_secs(13) + Duration::from_millis(1)
        ));

        // Case 4 — floor: solvable exactly now (elapsed == boundary) still
        // returns a positive duration.
        let d = retry_after_until_below_max(2, 0, 2, Duration::from_secs(2), window);
        assert!(d > Duration::ZERO);
    }

    /// The old behavior for comparison: a full-window denial with
    /// `curr_count` alone over the limit used to report only the remaining
    /// current window — less than half the real wait.
    #[test]
    fn retry_after_covers_full_window_when_curr_exceeds_limit() {
        let window = Duration::from_secs(10);
        let solved = retry_after_until_below_max(0, 10, 4, Duration::ZERO, window);
        assert!(
            solved > window,
            "curr=10 > max=4 must span into the NEXT window, got {solved:?}"
        );
    }

    /// Behavioral: a compliant client honoring `retry_after` must be
    /// admitted on its first re-request (the old code denied again).
    #[test]
    fn honoring_retry_after_admits_the_client_on_first_retry() {
        let window = Duration::from_millis(300);
        let counter = SlidingWindowCounter::from_params(window, 2);

        // Drain the first window completely.
        assert!(counter.check_and_increment().is_allowed());
        assert!(counter.check_and_increment().is_allowed());
        let denied = counter.check_and_increment();
        let retry_after = denied
            .retry_after()
            .expect("denied decision carries retry_after");
        assert!(retry_after > Duration::ZERO);

        // Sleep exactly the reported wait (plus 5ms scheduling slack).
        std::thread::sleep(retry_after + Duration::from_millis(5));
        assert!(
            counter.check_and_increment().is_allowed(),
            "a client that waited retry_after must be admitted"
        );
    }

    /// Behavioral: the hard rotation case (curr alone AT the limit — the
    /// reachable maximum, since events only count when admitted). The wait
    /// must span the current window boundary, and honoring it must admit.
    #[test]
    fn retry_after_when_curr_alone_exceeds_limit_spans_next_window() {
        let window = Duration::from_millis(200);
        let counter = SlidingWindowCounter::from_params(window, 2);

        // Drain the first window completely: prev=0, curr=2, max=2.
        assert!(counter.check_and_increment().is_allowed());
        assert!(counter.check_and_increment().is_allowed());
        let denied = counter
            .check_and_increment()
            .retry_after()
            .expect("denied at the window limit");
        // The wait must extend to the current window boundary (+ floor) —
        // strictly longer than the raw remaining time at the moment of the
        // check was NOT the old bug here; the old bug was UNDER-reporting in
        // the weighted case. Pin the boundary-spanning lower bound anyway.
        assert!(
            denied > Duration::from_millis(100),
            "rotation wait must cover the remaining window, got {denied:?}"
        );

        // Waiting the reported time admits the client again.
        std::thread::sleep(denied + Duration::from_millis(5));
        assert!(
            counter.check_and_increment().is_allowed(),
            "waiting the solved retry_after must admit"
        );
    }

    /// Adversarial re-verification of audit F13: in the WEIGHTED (solvable)
    /// branch the floor must be ADDED to the solved wait, not merely clamped
    /// to. The denial is a closed `estimate >= max` comparison, so a wait of
    /// exactly `p*·W − elapsed` lands ON the boundary where the estimate
    /// still equals the limit and the compliant client is denied a second
    /// time. The old `.max(FLOOR)` had exactly that defect; the +1 ms here
    /// is the pinned, load-bearing difference (prev=4, curr=1, max=4,
    /// elapsed=10ms of a 300ms window → p* = 1/4 → 75 − 10 + 1 = 66ms).
    #[test]
    fn weighted_case_adds_the_strict_boundary_floor() {
        let window = Duration::from_millis(300);
        let solved = retry_after_until_below_max(4, 1, 4, Duration::from_millis(10), window);
        assert_eq!(
            solved,
            Duration::from_millis(66),
            "the solved wait must be strictly PAST the boundary: 75ms·(1/4) − 10ms + 1ms floor"
        );

        // The same contract at the degenerate point: a wait that solves to
        // ≤ 0 still returns a positive, boundary-crossing duration.
        let now = retry_after_until_below_max(4, 1, 4, Duration::from_millis(75), window);
        assert_eq!(now, Duration::from_millis(1));
    }
}
