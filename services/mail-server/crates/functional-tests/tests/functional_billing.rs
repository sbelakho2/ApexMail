//! Functional tests for billing-service:plans, overage, VAT, types.

use billing_service::plans::{calculate_overage_cost, default_plans};
use billing_service::invoices::calculate_vat;
use billing_service::types::*;

// ── Plans ──────────────────────────────────────────────────────

#[test]
fn all_seven_default_plans_exist() {
    let plans = default_plans();
    assert_eq!(plans.len(), 7, "expected 7 default plans");
    let names: Vec<&str> = plans.iter().map(|p| p.name).collect();
    assert!(names.contains(&"free"));
    assert!(names.contains(&"starter"));
    assert!(names.contains(&"pro"));
    assert!(names.contains(&"growth"));
    assert!(names.contains(&"scale"));
    assert!(names.contains(&"enterprise"));
    assert!(names.contains(&"payg"));
}

#[test]
fn plan_lookup_by_name() {
    let plans = default_plans();
    let free = plans.iter().find(|p| p.name == "free").expect("free plan must exist");
    assert_eq!(free.price_monthly, 0);
    assert_eq!(free.email_limit, 3_000);

    let ent = plans.iter().find(|p| p.name == "enterprise").expect("enterprise plan must exist");
    assert!(ent.features.hipaa_compliance);
    assert!(ent.features.sso_enabled);
}

#[test]
fn plans_sorted_by_sort_order() {
    let plans = default_plans();
    for (i, p) in plans.iter().enumerate() {
        assert_eq!(p.sort_order, i as i32, "plan {} out of order", p.name);
    }
}

#[test]
fn free_plan_has_zero_cost() {
    let plans = default_plans();
    let free = plans.iter().find(|p| p.name == "free").unwrap();
    assert_eq!(free.price_monthly, 0);
    assert_eq!(free.price_yearly, 0);
}

// ── Overage cost ───────────────────────────────────────────────

#[test]
fn overage_within_limit_is_zero() {
    assert_eq!(calculate_overage_cost(2_000, 3_000), 0);
    assert_eq!(calculate_overage_cost(3_000, 3_000), 0);
}

#[test]
fn overage_unlimited_is_zero() {
    assert_eq!(calculate_overage_cost(999_999, -1), 0);
}

#[test]
fn overage_above_limit() {
// 1000 overage * 0.04 cents = 40 cents
    assert_eq!(calculate_overage_cost(4_000, 3_000), 40);
// 10_000 overage * 0.04 = 400 cents
    assert_eq!(calculate_overage_cost(13_000, 3_000), 400);
}

// ── VAT calculation ────────────────────────────────────────────

#[test]
fn vat_estonian_customer_22_percent() {
    let (rate, amt) = calculate_vat(10_000, "EE", None);
    assert_eq!(rate, 22);
    assert_eq!(amt, 2200);
}

#[test]
fn vat_eu_b2b_with_vat_number_reverse_charge() {
    let (rate, amt) = calculate_vat(10_000, "DE", Some("DE123456789"));
    assert_eq!(rate, 0);
    assert_eq!(amt, 0);
}

#[test]
fn vat_eu_b2c_without_vat_number() {
    let (rate, amt) = calculate_vat(10_000, "FR", None);
    assert_eq!(rate, 22, "EU B2C uses Estonian rate");
    assert_eq!(amt, 2200);
}

#[test]
fn vat_non_eu_is_zero() {
    let (rate, amt) = calculate_vat(10_000, "US", None);
    assert_eq!(rate, 0);
    assert_eq!(amt, 0);
    let (rate2, amt2) = calculate_vat(10_000, "JP", None);
    assert_eq!(rate2, 0);
    assert_eq!(amt2, 0);
}

// ── Types ──────────────────────────────────────────────────────

#[test]
fn rate_limit_tier_rps_values() {
    assert_eq!(RateLimitTier::Free.rps(), 10);
    assert_eq!(RateLimitTier::Standard.rps(), 100);
    assert_eq!(RateLimitTier::High.rps(), 500);
    assert_eq!(RateLimitTier::Unlimited.rps(), 5_000);
}

#[test]
fn support_level_serde_roundtrip() {
    let level = SupportLevel::Dedicated;
    let json = serde_json::to_string(&level).unwrap();
    assert_eq!(json, "\"dedicated\"");
    let back: SupportLevel = serde_json::from_str(&json).unwrap();
    assert_eq!(back, level);
}

#[test]
fn plan_features_default_is_restrictive() {
    let f = PlanFeatures::default();
    assert!(!f.dedicated_ip);
    assert!(!f.sso_enabled);
    assert!(!f.hipaa_compliance);
    assert!(matches!(f.support_level, SupportLevel::Community));
}

#[test]
fn invoice_status_serde_roundtrip() {
    for status in [
        InvoiceStatus::Draft,
        InvoiceStatus::Pending,
        InvoiceStatus::Paid,
        InvoiceStatus::Void,
        InvoiceStatus::Uncollectible,
    ] {
        let json = serde_json::to_string(&status).unwrap();
        let back: InvoiceStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(back, status);
    }
}
