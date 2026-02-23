//! Billing service performance tests.

use std::time::{Duration, Instant};

use billing_service::invoices::calculate_vat;
use billing_service::plans::{calculate_overage_cost, default_plans};
use billing_service::types::RateLimitTier;

#[test]
fn test_plan_lookup_throughput() {
    let iterations = 100_000;
    let plans = default_plans();

    let start = Instant::now();
    for i in 0..iterations {
        let plan = &plans[i % plans.len()];
        // Simulate plan lookup by name comparison and feature access
        let _ = plan.name;
        let _ = plan.price_monthly;
        let _ = plan.email_limit;
        let _ = plan.features.api_access;
        let _ = plan.features.support_level;
    }
    let elapsed = start.elapsed();

    println!(
        "Plan lookup throughput: {} ops in {:?} ({:.0} ops/sec)",
        iterations,
        elapsed,
        iterations as f64 / elapsed.as_secs_f64()
    );
    assert!(
        elapsed < Duration::from_secs(1),
        "100,000 plan lookups took {:?}, expected < 1s",
        elapsed
    );
}

#[test]
fn test_payg_cost_calculation_throughput() {
    let iterations = 100_000;
    let scenarios: Vec<(i64, i64)> = vec![
        (1_000, 3_000),
        (5_000, 3_000),
        (50_000, 50_000),
        (200_000, 150_000),
        (1_000_000, 500_000),
        (100, -1),
        (0, 3_000),
    ];

    let start = Instant::now();
    for i in 0..iterations {
        let (sent, limit) = scenarios[i % scenarios.len()];
        let _ = calculate_overage_cost(sent, limit);
    }
    let elapsed = start.elapsed();

    println!(
        "PAYG cost calculation throughput: {} ops in {:?} ({:.0} ops/sec)",
        iterations,
        elapsed,
        iterations as f64 / elapsed.as_secs_f64()
    );
    assert!(
        elapsed < Duration::from_secs(1),
        "100,000 cost calculations took {:?}, expected < 1s",
        elapsed
    );
}

#[test]
fn test_vat_calculation_throughput() {
    let iterations = 100_000;
    let scenarios: Vec<(i64, &str, Option<&str>)> = vec![
        (10_000, "EE", None),
        (25_000, "DE", Some("DE123456789")),
        (25_000, "DE", None),
        (50_000, "US", None),
        (15_000, "FR", Some("FR12345678901")),
        (30_000, "GB", None),
        (5_000, "JP", None),
    ];

    let start = Instant::now();
    for i in 0..iterations {
        let (subtotal, country, vat_num) = scenarios[i % scenarios.len()];
        let _ = calculate_vat(subtotal, country, vat_num);
    }
    let elapsed = start.elapsed();

    println!(
        "VAT calculation throughput: {} ops in {:?} ({:.0} ops/sec)",
        iterations,
        elapsed,
        iterations as f64 / elapsed.as_secs_f64()
    );
    assert!(
        elapsed < Duration::from_millis(500),
        "100,000 VAT calculations took {:?}, expected < 500ms",
        elapsed
    );
}

#[test]
fn test_quota_check_throughput() {
    let iterations = 100_000;
    let tiers = [
        RateLimitTier::Free,
        RateLimitTier::Standard,
        RateLimitTier::High,
        RateLimitTier::Unlimited,
    ];

    let start = Instant::now();
    for i in 0..iterations {
        let tier = tiers[i % tiers.len()];
        let rps = tier.rps();
        // Simulate quota check: is usage under the rate limit?
        let current_rps: u32 = (i % 1000) as u32;
        let _ = current_rps <= rps;
    }
    let elapsed = start.elapsed();

    println!(
        "Quota check throughput: {} ops in {:?} ({:.0} ops/sec)",
        iterations,
        elapsed,
        iterations as f64 / elapsed.as_secs_f64()
    );
    assert!(
        elapsed < Duration::from_secs(1),
        "100,000 quota checks took {:?}, expected < 1s",
        elapsed
    );
}
