#[cfg(test)]
mod simulation {
    use billing_common::proration;
    use billing_common::vat_rates;
    use crate::plans;
    use crate::types::{PlanFeatures, RateLimitTier, SupportLevel};

    #[test]
    fn sim_all_plans_have_valid_features() {
        let all_plans = plans::default_plans();
        let plan_names: Vec<&str> = all_plans.iter().map(|p| p.name).collect();

        assert!(plan_names.contains(&"free"));
        assert!(plan_names.contains(&"starter"));
        assert!(plan_names.contains(&"pro"));
        assert!(plan_names.contains(&"growth"));
        assert!(plan_names.contains(&"scale"));
        assert!(plan_names.contains(&"enterprise"));
        assert!(plan_names.contains(&"payg"));
        assert_eq!(all_plans.len(), 7, "Must have 7 plans");
    }

    #[test]
    fn sim_plan_sort_order_correct() {
        let all_plans = plans::default_plans();
        let order: Vec<&str> = all_plans.iter().map(|p| p.name).collect();
        assert_eq!(
            order,
            vec!["free", "starter", "pro", "growth", "scale", "enterprise", "payg"]
        );
    }

    #[test]
    fn sim_free_tier_limits_are_generous() {
        let free = plans::builtin_plan_seed(Some("free"));
        assert_eq!(free.email_limit, 30_000);
        assert_eq!(free.api_call_limit, 300_000);
        assert_eq!(free.price_monthly, 0);
        assert!(free.features.powered_by_footer);
        assert!(!free.features.webhooks_enabled);
    }

    #[test]
    fn sim_enterprise_has_all_premium_features() {
        let ent = plans::builtin_plan_seed(Some("enterprise"));
        assert!(ent.features.sso_enabled);
        assert!(ent.features.hipaa_compliance);
        assert!(ent.features.soc2_compliance);
        assert!(ent.features.private_cloud);
        assert!(ent.features.byoip);
        assert!(ent.features.dedicated_ip);
        assert_eq!(ent.features.dedicated_ip_count, 10);
        assert_eq!(ent.features.max_sending_domains, -1);
        assert_eq!(ent.features.max_team_members, -1);
        assert_eq!(ent.features.sla_credit_percentage, 25);
    }

    #[test]
    fn sim_rate_limit_tier_mapping_correct() {
        assert_eq!(RateLimitTier::Free.rps(), 10);
        assert_eq!(RateLimitTier::Standard.rps(), 100);
        assert_eq!(RateLimitTier::High.rps(), 500);
        assert_eq!(RateLimitTier::Unlimited.rps(), 5_000);
    }

    #[test]
    fn sim_rate_limit_tiers_strictly_ordered() {
        assert!(RateLimitTier::Free.rps() < RateLimitTier::Standard.rps());
        assert!(RateLimitTier::Standard.rps() < RateLimitTier::High.rps());
        assert!(RateLimitTier::High.rps() < RateLimitTier::Unlimited.rps());
    }

    #[test]
    fn sim_support_level_slas_are_monotonic() {
        assert_eq!(SupportLevel::Community.response_sla_hours(), None);
        let email = SupportLevel::Email.response_sla_hours().unwrap();
        let priority = SupportLevel::Priority.response_sla_hours().unwrap();
        let dedicated = SupportLevel::Dedicated.response_sla_hours().unwrap();
        assert!(dedicated < priority);
        assert!(priority < email);
        assert!(dedicated >= 1);
    }

    #[test]
    fn sim_proration_half_period_returns_half_price() {
        assert_eq!(proration::prorated_amount(1000, 15, 30).unwrap(), 500);
    }

    #[test]
    fn sim_proration_full_period_returns_full_price() {
        assert_eq!(proration::prorated_amount(12000, 365, 365).unwrap(), 12000);
    }

    #[test]
    fn sim_proration_rounding_is_half_up() {
        assert_eq!(proration::prorated_amount(1000, 10, 30).unwrap(), 333);
    }

    #[test]
    fn sim_proration_zero_days_remaining_returns_zero() {
        assert_eq!(proration::prorated_amount(1000, 0, 30).unwrap(), 0);
        assert_eq!(proration::prorated_amount(1000, -5, 30).unwrap(), 0);
    }

    #[test]
    fn sim_proration_rejects_invalid_period() {
        assert!(proration::prorated_amount(1000, 10, 0).is_err());
        assert!(proration::prorated_amount(1000, 10, -1).is_err());
    }

    #[test]
    fn sim_proration_yearly_subscription() {
        let credit = proration::prorated_amount(12000, 180, 365).unwrap();
        let charge = proration::prorated_amount(24000, 180, 365).unwrap();
        assert_eq!(credit, 5918);
        assert_eq!(charge, 11836);
    }

    #[test]
    fn sim_ceil_day_count_rounds_up() {
        assert_eq!(proration::ceil_day_count(proration::MILLISECONDS_PER_DAY - 1), 1);
        assert_eq!(proration::ceil_day_count(proration::MILLISECONDS_PER_DAY), 1);
        assert_eq!(proration::ceil_day_count(proration::MILLISECONDS_PER_DAY + 1), 2);
        assert_eq!(proration::ceil_day_count(0), 0);
        assert_eq!(proration::ceil_day_count(-1000), 0);
    }

    #[test]
    fn sim_vat_all_27_eu_member_states_present() {
        for code in &[
            "AT", "BE", "BG", "HR", "CY", "CZ", "DK", "EE", "FI", "FR",
            "DE", "GR", "HU", "IE", "IT", "LV", "LT", "LU", "MT", "NL",
            "PL", "PT", "RO", "SK", "SI", "ES", "SE",
        ] {
            assert!(vat_rates::is_eu_country(code), "Missing EU member: {code}");
        }
    }

    #[test]
    fn sim_vat_rates_all_eu_countries_have_rates() {
        let expected: Vec<(&str, i32)> = vec![
            ("AT", 20), ("BE", 21), ("BG", 20), ("HR", 25), ("CY", 19),
            ("CZ", 21), ("DK", 25), ("EE", 24), ("FI", 26), ("FR", 20),
            ("DE", 19), ("GR", 24), ("HU", 27), ("IE", 23), ("IT", 22),
            ("LV", 21), ("LT", 21), ("LU", 17), ("MT", 18), ("NL", 21),
            ("PL", 23), ("PT", 23), ("RO", 19), ("SK", 23), ("SI", 22),
            ("ES", 21), ("SE", 25),
        ];
        for (code, rate) in expected {
            assert_eq!(vat_rates::get_eu_vat_rate(code), Some(rate), "VAT rate mismatch for {code}");
        }
    }

    #[test]
    fn sim_vat_estonia_b2c_calculates_correctly() {
        let (rate, amount) = vat_rates::calculate_vat(1000, "EE", None);
        assert_eq!(rate, 24);
        assert_eq!(amount, 240);
    }

    #[test]
    fn sim_vat_eu_b2b_reverse_charge_zero() {
        let (rate, amount) = vat_rates::calculate_vat(1000, "DE", Some("DE123456789"));
        assert_eq!(rate, 0);
        assert_eq!(amount, 0);
    }

    #[test]
    fn sim_vat_eu_b2c_destination_rate() {
        let (rate, amount) = vat_rates::calculate_vat(1000, "DE", None);
        assert_eq!(rate, 19);
        assert_eq!(amount, 190);
    }

    #[test]
    fn sim_vat_non_eu_zero() {
        let (rate, amount) = vat_rates::calculate_vat(1000, "US", None);
        assert_eq!(rate, 0);
        assert_eq!(amount, 0);
    }

    #[test]
    fn sim_vat_case_insensitive_country() {
        assert_eq!(vat_rates::calculate_vat(1000, "ee", None), (24, 240));
        assert_eq!(vat_rates::calculate_vat(1000, "de", None), (19, 190));
    }

    #[test]
    fn sim_vat_zero_subtotal_returns_zero() {
        assert_eq!(vat_rates::calculate_vat(0, "DE", None), (0, 0));
        assert_eq!(vat_rates::calculate_vat(-1000, "EE", None), (0, 0));
    }

    #[test]
    fn sim_overage_within_limit_is_zero() {
        assert_eq!(plans::calculate_overage_cost(30_000, 30_000, "pro"), 0);
    }

    #[test]
    fn sim_overage_unlimited_is_zero() {
        assert_eq!(plans::calculate_overage_cost(999_999, -1, "enterprise"), 0);
    }

    #[test]
    fn sim_overage_above_limit() {
        assert_eq!(plans::calculate_overage_cost(31_000, 30_000, "pro"), 60);
    }

    #[test]
    fn sim_plan_features_default_is_restrictive() {
        let f = PlanFeatures::default();
        assert!(!f.dedicated_ip);
        assert!(!f.sso_enabled);
        assert!(!f.hipaa_compliance);
        assert!(!f.soc2_compliance);
        assert!(!f.private_cloud);
        assert!(!f.byoip);
        assert!(!f.white_label);
        assert!(f.max_team_members <= 10);
    }

    #[test]
    fn sim_builtin_plan_seed_falls_back_to_free() {
        let fallback = plans::builtin_plan_seed(Some("nonexistent"));
        assert_eq!(fallback.name, "free");
        assert_eq!(fallback.email_limit, 30_000);
    }

    #[test]
    fn sim_quota_limits_fall_back_to_free() {
        let (emails, api_calls) = plans::builtin_quota_limits(Some("does-not-exist"));
        assert_eq!(emails, 30_000);
        assert_eq!(api_calls, 300_000);
    }

    #[test]
    fn sim_proration_explanation_includes_days_and_amounts() {
        let explanation = proration::build_proration_explanation(
            "Starter", "Growth", 12000, 24000, 180, 365, 5918, 11836, 5918,
        );
        assert!(explanation.contains("365 days"));
        assert!(explanation.contains("Starter"));
        assert!(explanation.contains("Growth"));
        assert!(explanation.contains("Net charge"));
    }

    #[test]
    fn sim_proration_explanation_net_credit_when_downgrading() {
        let explanation = proration::build_proration_explanation(
            "Growth", "Starter", 24000, 12000, 180, 365, 11836, 5918, -5918,
        );
        assert!(explanation.contains("Net credit"));
    }

    #[test]
    fn sim_proration_explanation_no_change() {
        let explanation = proration::build_proration_explanation(
            "Starter", "Starter", 12000, 12000, 0, 365, 0, 0, 0,
        );
        assert!(explanation.contains("No additional charge"));
    }

    #[test]
    fn sim_proration_overflow_protection_i128() {
        // Very large price with few remaining days — should not panic
        let result = proration::prorated_amount(i64::MAX / 2, 1, 365);
        assert!(result.is_ok());

        // Extreme: max i64 price for 1 day of 1 day period = should be exact
        let result = proration::prorated_amount(100_000_000, 1, 1);
        assert_eq!(result.unwrap(), 100_000_000);
    }
}
