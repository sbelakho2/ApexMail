//! High-throughput tests — measure sustained operations per second.

use std::time::{Duration, Instant};

use ai_service::content::ContentOptimizer;
use apexmail_lib::generate_id;
use apexmail_lib::validation::is_valid_email;
use billing_service::config::PaygPricing;
use billing_service::invoices::calculate_vat;
use billing_service::plans::calculate_overage_cost;
use pattern_matcher::matcher::build_matcher;

/// Run `op` continuously for `duration` and return the count of iterations.
///
/// A brief warm-up phase (1 000 iterations) is performed before timing begins
/// to prime CPU caches, branch predictors, and any JIT-like optimisations, so
/// the measured throughput reflects steady-state performance (O-29.2).
fn run_for<F: FnMut()>(duration: Duration, mut op: F) -> u64 {
    // Warm-up: 1 000 iterations to reach steady state
    for _ in 0..1_000 {
        op();
    }
    let start = Instant::now();
    let mut count: u64 = 0;
    while start.elapsed() < duration {
        op();
        count += 1;
    }
    count
}

// ---------------------------------------------------------------------------
// 1. Sustained ID generation — >10 000/sec
// ---------------------------------------------------------------------------

#[test]
fn test_sustained_id_generation() {
    let dur = Duration::from_secs(2);
    let count = run_for(dur, || {
        let _ = generate_id("lt", 20);
    });
    let throughput = count as f64 / dur.as_secs_f64();
    eprintln!("ID generation throughput: {throughput:.0} ops/sec ({count} total)");
    assert!(
        throughput > 10_000.0,
        "expected >10 000 IDs/sec, got {throughput:.0}"
    );
}

// ---------------------------------------------------------------------------
// 2. Sustained validation — >50 000/sec
// ---------------------------------------------------------------------------

#[test]
fn test_sustained_validation() {
    let dur = Duration::from_secs(2);
    let count = run_for(dur, || {
        let _ = is_valid_email("user@example.com");
        let _ = is_valid_email("invalid");
    });
    let throughput = count as f64 / dur.as_secs_f64();
    eprintln!("Validation throughput: {throughput:.0} ops/sec ({count} total)");
    assert!(
        throughput > 50_000.0,
        "expected >50 000 validations/sec, got {throughput:.0}"
    );
}

// ---------------------------------------------------------------------------
// 3. Sustained deterministic subject scoring — >5 000/sec
// ---------------------------------------------------------------------------

#[test]
fn test_sustained_subject_scoring() {
    let optimizer = ContentOptimizer::new();
    let dur = Duration::from_secs(2);
    let count = run_for(dur, || {
        let _ = optimizer.score_subject_line("Your weekly account update is ready");
    });
    let throughput = count as f64 / dur.as_secs_f64();
    eprintln!("Subject scoring throughput: {throughput:.0} ops/sec ({count} total)");
    assert!(
        throughput > 5_000.0,
        "expected >5 000 subject scorings/sec, got {throughput:.0}"
    );
}

// ---------------------------------------------------------------------------
// 4. Sustained pattern matching — >10 000/sec
// ---------------------------------------------------------------------------

#[test]
fn test_sustained_pattern_matching() {
    let matcher = build_matcher(vec![
        ("spam", "spam"),
        ("phishing", "phishing"),
        ("malware", "malware"),
        ("buy now", "spam:cta"),
        ("free money", "spam:money"),
        ("verify your account", "phishing:verify"),
    ]);

    let text = "This email asks you to buy now and get free money by verifying your account";
    let dur = Duration::from_secs(2);
    let count = run_for(dur, || {
        let _ = matcher.find_all(text);
    });
    let throughput = count as f64 / dur.as_secs_f64();
    eprintln!("Pattern matching throughput: {throughput:.0} ops/sec ({count} total)");
    assert!(
        throughput > 10_000.0,
        "expected >10 000 matches/sec, got {throughput:.0}"
    );
}

// ---------------------------------------------------------------------------
// 5. Sustained billing calculations — >50 000/sec
// ---------------------------------------------------------------------------

#[test]
fn test_sustained_billing_calculations() {
    let pricing = PaygPricing::default();
    let dur = Duration::from_secs(2);
    let count = run_for(dur, || {
        let _ = pricing.calculate(25_000, 500_000);
        let _ = calculate_overage_cost(60_000, 50_000);
        let _ = calculate_vat(10_000, "EE", None);
    });
    let throughput = count as f64 / dur.as_secs_f64();
    eprintln!("Billing calc throughput: {throughput:.0} ops/sec ({count} total)");
    assert!(
        throughput > 50_000.0,
        "expected >50 000 calcs/sec, got {throughput:.0}"
    );
}
