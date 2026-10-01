//! Billing service performance tests (SM12 F9: real work, black-boxed).
//!
//! Audit finding 9: the two "fake workload" tests are gone —
//! `test_plan_lookup_throughput` measured discarded plan-field reads
//! (`let _ = plan.name;`) and `test_quota_check_throughput` measured a
//! local `current_rps <= rps` boolean. Both now drive REAL production
//! functions:
//!
//! * plan lookup → `billing_service::plans::{is_builtin_plan_name,
//!   builtin_quota_limits, builtin_email_limit_for_plan,
//!   plan_overage_rate_millicents}` — the actual lookup helpers the plan
//!   seed/enforcement path uses;
//! * quota check → `billing_entitlements::EntitlementSnapshot::
//!   require_capacity/require_feature` — the backend authority handlers
//!   call to refuse over-quota requests.
//!
//! Every input and output crosses `std::hint::black_box`, so LLVM cannot
//! delete the measured work, and each test emits a metric line in
//! `scripts/compare-baseline.sh` format (see `budget.rs`).

use std::hint::black_box;
use std::time::Instant;

use billing_entitlements::classify::{CapacityKey, FeatureKey};
use billing_entitlements::snapshot::EntitlementSnapshot;
use billing_service::invoices::calculate_vat;
use billing_service::plans::{
    builtin_email_limit_for_plan, builtin_quota_limits, calculate_overage_cost, default_plans,
    is_builtin_plan_name, plan_overage_rate_millicents,
};
mod budget;

/// One real entitlement snapshot per built-in plan, built exactly the way
/// `billing-service` builds them for enforcement (PlanFeatures → JSON →
/// snapshot).
fn real_snapshots() -> Vec<(&'static str, EntitlementSnapshot)> {
    default_plans()
        .into_iter()
        .map(|seed| {
            let features = serde_json::to_value(&seed.features)
                .expect("PlanFeatures serializes by construction");
            let snapshot =
                EntitlementSnapshot::from_plan_features_json("perf-tenant", seed.name, &features);
            (seed.name, snapshot)
        })
        .collect()
}

#[test]
fn test_plan_lookup_throughput() {
    let iterations = 100_000;
    let plan_names: Vec<&'static str> = default_plans().iter().map(|p| p.name).collect();
    // Sanity: the fixtures must actually hit production lookups.
    assert!(
        !plan_names.is_empty() && plan_names.iter().all(|n| is_builtin_plan_name(n)),
        "default_plans must produce built-in plan names for this benchmark"
    );

    let start = Instant::now();
    for i in 0..iterations {
        let name = plan_names[i % plan_names.len()];
        // The real lookup chain used by plan seeding and enforcement:
        // recognition → quota limits → email limit → overage rate.
        let builtin = black_box(is_builtin_plan_name(black_box(name)));
        let (email_limit, api_limit) = black_box(builtin_quota_limits(black_box(Some(name))));
        let email_cap = black_box(builtin_email_limit_for_plan(black_box(name)));
        let overage = black_box(plan_overage_rate_millicents(black_box(name)));
        // Fold the outputs together so none of the four lookups can be
        // dead-code-eliminated; every iteration must produce this value.
        let folded = (builtin as u64)
            .wrapping_add(email_limit as u64)
            .wrapping_add(api_limit as u64)
            .wrapping_add(email_cap.unwrap_or(-1) as u64)
            .wrapping_add(overage.unwrap_or(-1) as u64);
        black_box(folded);
    }
    let elapsed = start.elapsed();
    let ops_per_sec = iterations as f64 / elapsed.as_secs_f64();

    println!(
        "Plan lookup throughput: {} ops in {:?} ({:.0} ops/sec)",
        iterations, elapsed, ops_per_sec
    );
    budget::emit_baseline_metric("plan_lookup", "throughput_ops_per_sec", ops_per_sec);
    assert!(
        elapsed < budget::from_secs(1),
        "100,000 production plan lookups took {:?}, expected < 1s",
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
        let (sent, limit) = black_box(scenarios[i % scenarios.len()]);
        let cost = black_box(calculate_overage_cost(black_box(sent), black_box(limit)));
        black_box(cost);
    }
    let elapsed = start.elapsed();
    let ops_per_sec = iterations as f64 / elapsed.as_secs_f64();

    println!(
        "PAYG cost calculation throughput: {} ops in {:?} ({:.0} ops/sec)",
        iterations, elapsed, ops_per_sec
    );
    budget::emit_baseline_metric("billing_calculations", "throughput_ops_per_sec", ops_per_sec);
    assert!(
        elapsed < budget::from_millis(500),
        "100,000 cost calculations took {:?}, expected < 500ms",
        elapsed
    );
    // Release builds must sustain a fraction of the committed baseline
    // (v1.0.json: billing_calculations, release/Apple-Silicon).
    budget::assert_release_throughput(
        ops_per_sec,
        budget::baseline_ops_per_sec::BILLING_CALCULATIONS,
        "billing_calculations",
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
        let (subtotal, country, vat_num) = black_box(scenarios[i % scenarios.len()]);
        let (rate, amount) = black_box(calculate_vat(
            black_box(subtotal),
            black_box(country),
            black_box(vat_num),
        ));
        black_box((rate, amount));
    }
    let elapsed = start.elapsed();
    let ops_per_sec = iterations as f64 / elapsed.as_secs_f64();

    println!(
        "VAT calculation throughput: {} ops in {:?} ({:.0} ops/sec)",
        iterations, elapsed, ops_per_sec
    );
    assert!(
        elapsed < budget::from_millis(500),
        "100,000 VAT calculations took {:?}, expected < 500ms",
        elapsed
    );
}

/// The REAL quota-enforcement path (audit finding 9): handlers call
/// `EntitlementSnapshot::require_capacity` / `require_feature` to refuse
/// over-quota or unentitled requests. This measures that authority check,
/// including the verdicts (an over-limit amount must be REJECTED — the
/// assertion at the bottom fails if the enforcement ever degrades into a
/// rubber stamp).
#[test]
fn test_quota_check_throughput() {
    let iterations = 100_000;
    let snapshots = real_snapshots();
    assert!(!snapshots.is_empty(), "built-in plans must seed snapshots");

    let start = Instant::now();
    for i in 0..iterations {
        let (plan, snapshot) = black_box(&snapshots[i % snapshots.len()]);
        // Alternate an in-limit request (Ok) with an over-limit one (Err):
        // both verdicts are real work the enforcement path produces.
        let amount = if i % 2 == 0 { 1 } else { i64::MAX };
        let verdict = black_box(snapshot.require_capacity(black_box(CapacityKey::SendingDomains), black_box(amount)));
        let entitled = black_box(snapshot.require_feature(black_box(FeatureKey::ApiAccess)));
        black_box((plan, verdict.is_err(), entitled.is_ok()));
    }
    let elapsed = start.elapsed();
    let ops_per_sec = iterations as f64 / elapsed.as_secs_f64();

    println!(
        "Quota check throughput: {} ops in {:?} ({:.0} ops/sec)",
        iterations, elapsed, ops_per_sec
    );
    assert!(
        elapsed < budget::from_millis(500),
        "100,000 entitlement quota checks took {:?}, expected < 500ms",
        elapsed
    );

    // Correctness pin (the fake workload asserted a local boolean; this
    // asserts the production verdicts): every plan grants api_access, an
    // in-limit amount is admitted, and an over-limit amount is refused —
    // except on unlimited (-1) caps, which admit by contract.
    for (plan, snapshot) in &snapshots {
        assert!(
            snapshot.require_feature(FeatureKey::ApiAccess).is_ok(),
            "plan {plan} must grant api_access"
        );
        assert!(
            snapshot.require_capacity(CapacityKey::SendingDomains, 1).is_ok(),
            "plan {plan} must admit an in-limit capacity request"
        );
        let sending_limit = snapshot.capacity(CapacityKey::SendingDomains);
        let over_limit = snapshot.require_capacity(CapacityKey::SendingDomains, i64::MAX);
        if sending_limit < 0 {
            assert!(
                over_limit.is_ok(),
                "unlimited plan {plan} must admit any capacity request"
            );
        } else {
            assert!(
                over_limit.is_err(),
                "plan {plan} (limit {sending_limit}) must refuse an over-limit request"
            );
        }
    }
}
