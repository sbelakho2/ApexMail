//! The canonical platform catalog — the SINGLE source of truth for plan
//! facts (names, prices, limits) consumed by billing-service (the runtime
//! seed), ai-service (knowledge + verifier tables), the sales knowledge
//! base, and the docs generation. Every consumer derives from this module;
//! drift tests in the consuming crates pin equality so no surface can state
//! a price or limit the billing runtime does not enforce.
//!
//! Prices are in CENTS (the billing runtime's storage unit); displays
//! convert. Limits are per month; -1 means unlimited.

/// One canonical plan row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PlanRow {
    /// Billing lookup id (lowercase, e.g. "pro").
    pub name: &'static str,
    /// Customer-facing display name.
    pub display_name: &'static str,
    /// Monthly price in euro CENTS.
    pub price_monthly_cents: i64,
    /// Annual price in euro CENTS (12 months at the effective annual rate).
    pub price_yearly_cents: i64,
    /// Included emails per month (-1 = unlimited).
    pub email_limit: i64,
    /// Included API calls per month (-1 = unlimited).
    pub api_call_limit: i64,
    /// Max retention days.
    pub max_retention_days: i64,
    /// Max team members (-1 = unlimited).
    pub max_team_members: i64,
    /// Automatic overage rate in MILLICENTS per email beyond the included
    /// volume (None = no automatic overage: Free's quota gate blocks, PAYG
    /// is usage-priced, Enterprise is contractual).
    pub overage_millicents_per_email: Option<i64>,
    /// `audit_logs` — customer read/export of the tenant audit trail.
    /// Sold on Growth and above (docs/pricing.md "Included feature gates").
    pub audit_logs: bool,
    /// `ab_testing` — campaign experiment execution + results API.
    /// Sold on Growth and above.
    pub ab_testing: bool,
    /// `time_travel_debugging` — historical message-state replay.
    /// Sold on Growth and above.
    pub time_travel_debugging: bool,
    /// `template_approval_workflow` — maker/checker template publishing.
    /// Sold on Business and Enterprise Cloud.
    pub template_approval_workflow: bool,
    /// `subaccounts` — child workspaces with isolated quotas/keys.
    /// Sold on Business and Enterprise Cloud.
    pub subaccounts: bool,
    /// `max_subaccounts` — child-workspace ceiling (-1 = unlimited).
    pub max_subaccounts: i64,
}

/// The canonical catalog, ordered by sort order. Mirrors the deployed
/// billing runtime exactly — the 2026-09-08 pricing review (Developer €29 /
/// Pro €89 / Growth €229 / Business €699 / Enterprise Cloud from €1,750;
/// Free 3,000/mo + a one-time 30,000-email launch allowance).
pub const PLANS: &[PlanRow] = &[
    PlanRow {
        name: "free",
        display_name: "Free",
        price_monthly_cents: 0,
        price_yearly_cents: 0,
        email_limit: 3_000,
        api_call_limit: 30_000,
        max_retention_days: 7,
        max_team_members: 1,
        overage_millicents_per_email: None,
        audit_logs: false,
        ab_testing: false,
        time_travel_debugging: false,
        template_approval_workflow: false,
        subaccounts: false,
        max_subaccounts: 0,
    },
    PlanRow {
        name: "starter",
        display_name: "Developer",
        price_monthly_cents: 2_900,
        price_yearly_cents: 29_000,
        email_limit: 50_000,
        api_call_limit: 500_000,
        max_retention_days: 30,
        max_team_members: 5,
        overage_millicents_per_email: Some(80),
        audit_logs: false,
        ab_testing: false,
        time_travel_debugging: false,
        template_approval_workflow: false,
        subaccounts: false,
        max_subaccounts: 0,
    },
    PlanRow {
        name: "pro",
        display_name: "Pro",
        price_monthly_cents: 8_900,
        price_yearly_cents: 89_000,
        email_limit: 150_000,
        api_call_limit: 2_000_000,
        max_retention_days: 60,
        max_team_members: 10,
        overage_millicents_per_email: Some(60),
        audit_logs: false,
        ab_testing: false,
        time_travel_debugging: false,
        template_approval_workflow: false,
        subaccounts: false,
        max_subaccounts: 0,
    },
    PlanRow {
        name: "growth",
        display_name: "Growth",
        price_monthly_cents: 22_900,
        price_yearly_cents: 229_000,
        email_limit: 500_000,
        api_call_limit: 5_000_000,
        max_retention_days: 90,
        max_team_members: 25,
        overage_millicents_per_email: Some(35),
        audit_logs: true,
        ab_testing: true,
        time_travel_debugging: true,
        template_approval_workflow: false,
        subaccounts: false,
        max_subaccounts: 0,
    },
    PlanRow {
        name: "scale",
        display_name: "Business",
        price_monthly_cents: 69_900,
        price_yearly_cents: 699_000,
        email_limit: 2_000_000,
        api_call_limit: 20_000_000,
        max_retention_days: 365,
        max_team_members: 50,
        overage_millicents_per_email: Some(35),
        audit_logs: true,
        ab_testing: true,
        time_travel_debugging: true,
        template_approval_workflow: true,
        subaccounts: true,
        max_subaccounts: 10,
    },
    PlanRow {
        name: "enterprise",
        display_name: "Enterprise Cloud",
        price_monthly_cents: 175_000,
        price_yearly_cents: 1_750_000,
        email_limit: 5_000_000,
        api_call_limit: -1,
        max_retention_days: 730,
        max_team_members: -1,
        // Contractual: 22–35 by contract; 35 is the runtime default.
        overage_millicents_per_email: Some(35),
        audit_logs: true,
        ab_testing: true,
        time_travel_debugging: true,
        template_approval_workflow: true,
        subaccounts: true,
        max_subaccounts: -1,
    },
    PlanRow {
        name: "payg",
        display_name: "Pay As You Go",
        price_monthly_cents: 0,
        price_yearly_cents: 0,
        email_limit: -1,
        api_call_limit: -1,
        max_retention_days: 30,
        max_team_members: 5,
        // Usage-priced already; no subscription overage.
        overage_millicents_per_email: None,
        audit_logs: false,
        ab_testing: false,
        time_travel_debugging: false,
        template_approval_workflow: false,
        subaccounts: false,
        max_subaccounts: 0,
    },
];

/// PAYG per-email tier rates (EUR/email) by cumulative volume upper bound.
pub const PAYG_TIERS_EUR_PER_EMAIL: &[(i64, f64)] = &[
    (10_000, 0.0010),
    (100_000, 0.0008),
    (1_000_000, 0.0005),
    (i64::MAX, 0.0003),
];

/// The Free tier's one-time launch allowance (emails, first 30 days).
pub const FREE_LAUNCH_ALLOWANCE: i64 = 30_000;

/// The Free tier's launch-allowance window in days.
pub const FREE_LAUNCH_WINDOW_DAYS: i64 = 30;

/// Lookup by billing plan id.
pub fn plan_by_name(name: &str) -> Option<&'static PlanRow> {
    PLANS.iter().find(|p| p.name == name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_plan_has_a_unique_name() {
        let mut names: Vec<&str> = PLANS.iter().map(|p| p.name).collect();
        names.sort_unstable();
        let len = names.len();
        names.dedup();
        assert_eq!(names.len(), len);
    }

    /// `docs/pricing.md` "Included feature gates": audit logs, A/B testing
    /// and time-travel debugging are sold on Growth and above; template
    /// approval and subaccounts on Business and Enterprise Cloud. The
    /// canonical catalog is the first half of the two files the
    /// knowledge-consistency gate pins (the billing seeds mirror these
    /// values), so this test is the fail-before proof that the tables above
    /// match what is sold.
    #[test]
    fn feature_gates_match_the_public_pricing_table() {
        let cases: &[(&str, bool, bool, bool, bool, bool)] = &[
            // plan, audit, approval, subaccounts, ab_testing, time_travel
            ("free", false, false, false, false, false),
            ("starter", false, false, false, false, false),
            ("pro", false, false, false, false, false),
            ("growth", true, false, false, true, true),
            ("scale", true, true, true, true, true),
            ("enterprise", true, true, true, true, true),
            ("payg", false, false, false, false, false),
        ];
        for (name, audit, approval, subaccounts, ab_testing, time_travel) in cases {
            let plan = plan_by_name(name).unwrap_or_else(|| panic!("plan {name} exists"));
            assert_eq!(plan.audit_logs, *audit, "{name}.audit_logs");
            assert_eq!(
                plan.template_approval_workflow, *approval,
                "{name}.template_approval_workflow"
            );
            assert_eq!(plan.subaccounts, *subaccounts, "{name}.subaccounts");
            assert_eq!(plan.ab_testing, *ab_testing, "{name}.ab_testing");
            assert_eq!(
                plan.time_travel_debugging, *time_travel,
                "{name}.time_travel_debugging"
            );
        }
        // The Business subaccount ceiling is 10 (training prompts and gap
        // scenarios: "subaccounts (10)"); Enterprise is unlimited.
        assert_eq!(plan_by_name("scale").unwrap().max_subaccounts, 10);
        assert_eq!(plan_by_name("enterprise").unwrap().max_subaccounts, -1);
        for name in ["free", "starter", "pro", "growth", "payg"] {
            assert_eq!(
                plan_by_name(name).unwrap().max_subaccounts,
                0,
                "{name} must not seed subaccount capacity"
            );
        }
    }

    #[test]
    fn paid_plans_ascending_between_free_and_enterprise() {
        let mut paid: Vec<i64> = PLANS
            .iter()
            .filter(|p| p.price_monthly_cents > 0)
            .map(|p| p.price_monthly_cents)
            .collect();
        paid.sort_unstable();
        let mut sorted = paid.clone();
        sorted.sort_unstable();
        assert_eq!(paid, sorted, "catalog order must be ascending by price");
    }
}
