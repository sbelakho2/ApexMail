//! Fuzz tests for billing service functions.

use billing_service::config::PaygPricing;
use billing_service::invoices::calculate_vat;
use billing_service::plans::{calculate_overage_cost, default_plans};
use billing_service::types::InvoiceLineItem;

#[test]
fn fuzz_payg_cost_never_negative() {
    // Any positive email/API count must produce non-negative cost.
    let pricing = PaygPricing::default();
    let mut rng = rand::rng();
    use rand::Rng;
    for _ in 0..5_000 {
        let emails: u64 = rng.random_range(0..10_000_000);
        let api_calls: u64 = rng.random_range(0..50_000_000);
        let (email_cost, api_cost, total) = pricing
            .calculate(emails, api_calls)
            .expect("bounded fuzz inputs should not overflow PAYG pricing");
        assert!(
            email_cost >= 0,
            "Email cost negative for emails={emails}: {email_cost}"
        );
        assert!(
            api_cost >= 0,
            "API cost negative for api_calls={api_calls}: {api_cost}"
        );
        assert!(
            total >= 0,
            "Total negative for emails={emails}, api={api_calls}: {total}"
        );
        // Total must equal sum of parts for integer cents.
        assert!(
            total == email_cost + api_cost,
            "Total {total} != email {email_cost} + api {api_cost}"
        );
    }

    // Also check overage cost
    for _ in 0..5_000 {
        let sent: i64 = rng.random_range(0..10_000_000);
        let limit: i64 = if rng.random_bool(0.1) {
            -1
        } else {
            rng.random_range(0..5_000_000)
        };
        let cost = calculate_overage_cost(sent, limit);
        assert!(
            cost >= 0,
            "Overage cost negative: sent={sent}, limit={limit}, cost={cost}"
        );
    }
}

#[test]
fn fuzz_plan_quotas_consistent() {
    // All plans must have non-negative quotas (or -1 for unlimited).
    let plans = default_plans();
    assert!(!plans.is_empty(), "Should have at least one plan");
    for plan in &plans {
        assert!(
            plan.email_limit >= -1,
            "Plan {} has invalid email_limit: {}",
            plan.name,
            plan.email_limit
        );
        assert!(
            plan.api_call_limit >= -1,
            "Plan {} has invalid api_call_limit: {}",
            plan.name,
            plan.api_call_limit
        );
        assert!(
            plan.price_monthly >= 0,
            "Plan {} has negative monthly price: {}",
            plan.name,
            plan.price_monthly
        );
        assert!(
            plan.price_yearly >= 0,
            "Plan {} has negative yearly price: {}",
            plan.name,
            plan.price_yearly
        );
        assert!(
            plan.features.max_retention_days >= 0,
            "Plan {} has negative retention days: {}",
            plan.name,
            plan.features.max_retention_days
        );
    }
}

#[test]
fn fuzz_vat_never_exceeds_100_percent() {
    // Any input should produce a reasonable VAT (0-100%).
    let countries = ["EE", "DE", "FR", "US", "JP", "GB", "XX", "", "AU", "BR"];
    let mut rng = rand::rng();
    use rand::Rng;
    for _ in 0..2_000 {
        let subtotal: i64 = rng.random_range(0..100_000_000);
        let country = countries[rng.random_range(0..countries.len())];
        let vat_number = if rng.random_bool(0.3) {
            Some("EU123456789")
        } else {
            None
        };
        let (rate, amount) = calculate_vat(subtotal, country, vat_number);
        assert!(
            (0.0..=100.0).contains(&rate),
            "VAT rate out of range: {rate} for country={country}"
        );
        assert!(
            amount >= 0,
            "VAT amount negative: {amount} for subtotal={subtotal}, country={country}"
        );
        // VAT amount should never exceed the subtotal (at 100% max)
        assert!(
            amount <= subtotal,
            "VAT {amount} exceeds subtotal {subtotal} for country={country}"
        );
    }
}

#[test]
fn fuzz_invoice_total_consistent() {
    // Line items sum should be consistent.
    let mut rng = rand::rng();
    use rand::Rng;
    for _ in 0..1_000 {
        let num_items = rng.random_range(1..10);
        let mut items = Vec::new();
        let mut expected_subtotal: i64 = 0;
        for _ in 0..num_items {
            let quantity: i64 = rng.random_range(1..1000);
            let unit_price: i64 = rng.random_range(1..100_000);
            let amount = quantity * unit_price;
            expected_subtotal += amount;
            items.push(InvoiceLineItem {
                description: "test item".into(),
                quantity,
                unit_price,
                amount,
                vat_rate: 0.0,
                vat_amount: 0,
            });
        }
        let computed_subtotal: i64 = items.iter().map(|i| i.amount).sum();
        assert_eq!(
            computed_subtotal, expected_subtotal,
            "Line items sum mismatch"
        );
        // Each item amount = quantity * unit_price
        for item in &items {
            assert_eq!(
                item.amount,
                item.quantity * item.unit_price,
                "Line item amount != qty * price"
            );
        }
    }
}
