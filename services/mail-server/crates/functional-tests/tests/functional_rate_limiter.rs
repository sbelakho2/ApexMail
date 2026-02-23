//! Functional tests for apexmail-rate-limiter: SlidingWindowCounter.

use std::time::Duration;
use apexmail_rate_limiter::SlidingWindowCounter;

// ── Allows within limit ────────────────────────────────────────

#[test]
fn sliding_window_allows_requests_within_limit() {
    let counter = SlidingWindowCounter::from_params(Duration::from_secs(60), 10);
    for i in 0..10 {
        let decision = counter.check_and_increment();
        assert!(
            decision.is_allowed(),
            "request {} should be allowed", i
        );
    }
}

// ── Rejects after limit ────────────────────────────────────────

#[test]
fn sliding_window_rejects_after_limit_exceeded() {
    let counter = SlidingWindowCounter::from_params(Duration::from_secs(60), 5);
    for _ in 0..5 {
        assert!(counter.check_and_increment().is_allowed());
    }
    let decision = counter.check_and_increment();
    assert!(decision.is_denied(), "should be denied after limit");
}

// ── Reset restores capacity ────────────────────────────────────

#[test]
fn window_reset_allows_requests_again() {
    let counter = SlidingWindowCounter::from_params(Duration::from_secs(60), 5);
    for _ in 0..5 {
        counter.check_and_increment();
    }
    assert!(counter.check_and_increment().is_denied());

    counter.reset();
    assert_eq!(counter.current_count(), 0);
    assert!(counter.check_and_increment().is_allowed());
}

// ── Concurrent access safety ───────────────────────────────────

#[test]
fn concurrent_access_does_not_panic() {
    use std::sync::Arc;
    use std::thread;

    let counter = Arc::new(SlidingWindowCounter::from_params(Duration::from_secs(1), 1000));
    let mut handles = Vec::new();

    for _ in 0..10 {
        let c = Arc::clone(&counter);
        handles.push(thread::spawn(move || {
            for _ in 0..100 {
                let _ = c.check_and_increment();
            }
        }));
    }

    for h in handles {
        h.join().expect("thread panicked");
    }

    // Just ensure we didn't panic — the count should be roughly 1000
    let count = counter.current_count();
    assert!(count > 0, "some events should have been counted");
}

// ── Different keys are independent (via separate counters) ─────

#[test]
fn independent_counters_do_not_interfere() {
    let counter_a = SlidingWindowCounter::from_params(Duration::from_secs(60), 5);
    let counter_b = SlidingWindowCounter::from_params(Duration::from_secs(60), 5);

    // Exhaust counter A
    for _ in 0..5 {
        counter_a.check_and_increment();
    }
    assert!(counter_a.check_and_increment().is_denied());

    // Counter B should still be fresh
    assert!(counter_b.check_and_increment().is_allowed());
}
