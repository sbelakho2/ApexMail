//! Commercial “perfect” contract: the pricing authority, Free quota, and
//! annual-billing math as the runtime actually implements them.
//!
//! Source of truth: `platform-catalog` (see `docs/pricing-authority.md`).
//! Marketing `pricing.json` is presentation-only and must never be used to
//! grant entitlement — these tests pin the runtime catalog so drift is loud.

use platform_catalog as catalog;

/// Perfect commercial fact: Free is 3,000 emails/month recurring, plus a
/// one-time 30,000-email launch allowance. Marketing copy that says
/// “30,000/month Free” is a billing-lie.
#[test]
fn free_quota_is_3000_recurring_plus_30000_launch_allowance() {
    let free = catalog::plan_by_name("free").expect("free plan exists");
    assert_eq!(
        free.email_limit, 3_000,
        "Free recurring email volume is 3,000/month (not 30,000)"
    );
    assert_eq!(
        catalog::FREE_LAUNCH_ALLOWANCE,
        30_000,
        "launch allowance is one-time 30,000"
    );
    assert_eq!(
        catalog::FREE_LAUNCH_WINDOW_DAYS,
        30,
        "launch allowance window is 30 days"
    );
    // Free has no automatic overage — the quota gate blocks.
    assert_eq!(
        free.overage_millicents_per_email, None,
        "Free must not silently overage"
    );
}

/// Perfect commercial fact: annual billing is 10 monthly payments
/// (≈16.7% below 12 monthly payments) — NOT a 10% discount.
#[test]
fn annual_billing_is_ten_monthly_payments_not_10_percent() {
    for plan in catalog::PLANS {
        if plan.name == "free" || plan.name == "enterprise" {
            continue;
        }
        if plan.price_monthly_cents <= 0 {
            continue;
        }
        // Yearly must equal 10 × monthly (the documented billing rule).
        assert_eq!(
            plan.price_yearly_cents,
            plan.price_monthly_cents * 10,
            "plan {}: annual = 10 monthly payments",
            plan.name
        );
        // Effective savings vs 12 monthly payments is 2/12 ≈ 16.67%.
        let twelve = plan.price_monthly_cents * 12;
        let saved = twelve - plan.price_yearly_cents;
        let pct_x100 = saved * 100 / twelve;
        assert!(
            (16..=17).contains(&pct_x100),
            "plan {}: savings {}% must be ~16.7%, not 10%",
            plan.name,
            pct_x100
        );
    }
}

/// Perfect catalog integrity: every plan is uniquely named and priced in a
/// monotone commercial ladder (self-serve → enterprise).
#[test]
fn catalog_plans_are_unique_and_monotone() {
    let mut names = std::collections::BTreeSet::new();
    let mut last_price = 0i64;
    for plan in catalog::PLANS {
        assert!(names.insert(plan.name), "duplicate plan id {}", plan.name);
        assert!(
            plan.price_monthly_cents >= last_price,
            "plan {} dropped below the previous rung",
            plan.name
        );
        last_price = plan.price_monthly_cents;
        // Retention is a real product promise — never zero.
        assert!(plan.max_retention_days > 0, "plan {} retention", plan.name);
    }
    assert!(names.contains("free"));
    assert!(names.contains("starter"));
    assert!(names.contains("pro"));
}

/// Perfect entitlement boundary: paid features are off on Free/starter
/// where the catalog says so (fail-closed feature gates).
#[test]
fn entitlement_defaults_fail_closed_on_low_plans() {
    let free = catalog::plan_by_name("free").unwrap();
    assert!(!free.audit_logs);
    assert!(!free.ab_testing);
    assert!(!free.subaccounts);
    assert!(!free.template_approval_workflow);
    assert!(!free.time_travel_debugging);
    assert_eq!(free.max_subaccounts, 0);

    let starter = catalog::plan_by_name("starter").unwrap();
    assert!(!starter.audit_logs, "Developer does not include audit_logs");
    assert!(!starter.subaccounts);
}

/// Perfect public boundary: self-serve plan ids are the only generic
/// Checkout names. Enterprise is a sales/contract flow, not a public plan
/// the catalog sells at a monthly self-serve price without contract.
#[test]
fn self_serve_boundary_matches_pricing_authority() {
    // docs/pricing-authority.md: free is always initial; enterprise is
    // contract; payg is configured, not generic Checkout.
    let free = catalog::plan_by_name("free").unwrap();
    assert_eq!(free.price_monthly_cents, 0);
    // There must be a path from free → paid self-serve.
    for name in ["starter", "pro", "growth", "scale"] {
        let plan = catalog::plan_by_name(name)
            .unwrap_or_else(|| panic!("{name} must exist as self-serve"));
        assert!(plan.price_monthly_cents > 0, "{name} must be priced");
    }
}
