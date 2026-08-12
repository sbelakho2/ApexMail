//! Scoring performance micro-benchmark (asserted #[test], no external
//! bench harness): 1,000,000 vectors must score well under the budget.
//!
//! The spec target is ~5 s total (p99 implied); the asserted bound is a
//! generous 10 s so CI noise cannot flake it. The measured rate is printed
//! for the report.

mod common;

use kiwicaptcha_risk::score::{score, RiskWeights};
use std::time::Instant;

#[test]
fn million_vectors_score_under_budget() {
    let weights = RiskWeights::default();
    let mut state = 42u64;
    let mut total: u64 = 0;

    let start = Instant::now();
    for _ in 0..1_000_000 {
        total += score(100, &common::vector(&mut state), &weights) as u64;
    }
    let elapsed = start.elapsed();

    let rate = 1_000_000f64 / elapsed.as_secs_f64();
    println!(
        "scored 1,000,000 vectors in {:.3}s ({:.0} vec/s, checksum {total})",
        elapsed.as_secs_f64(),
        rate
    );

    assert!(total > 0, "the checksum must be meaningful");
    assert!(
        elapsed.as_secs_f64() < 10.0,
        "scoring 1,000,000 vectors took {elapsed:?} (budget 10 s)"
    );
}
