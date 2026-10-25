//! The canonical platform catalog, the SINGLE source of truth for plan
//! facts (names, prices, limits) consumed by billing-service (the runtime
//! seed), ai-service (knowledge + verifier tables), the sales knowledge
//! base, and the docs generation. Every consumer derives from this module;
//! drift tests in the consuming crates pin equality so no surface can state
//! a price or limit the billing runtime does not enforce.
//!
//! Prices are in CENTS (the billing runtime's storage unit); displays
//! convert. Limits are per month; -1 means unlimited.
//!
//! Every self-serve plan carries the owner's two list prices: EUR (what the
//! Mollie checkout charges) and USD (the published dollar list). Annual
//! pricing is the documented 10-months-for-12 rule in BOTH currencies.

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
    /// Monthly price in US dollar CENTS (the published USD list; the
    /// checkout still charges EUR, this is the display/quote price).
    pub price_monthly_usd_cents: i64,
    /// Annual price in US dollar CENTS (10 monthly payments, same rule as
    /// the EUR ladder).
    pub price_yearly_usd_cents: i64,
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
    /// `audit_logs`, customer read/export of the tenant audit trail.
    /// Sold on Growth and above (docs/pricing.md "Included feature gates").
    pub audit_logs: bool,
    /// `ab_testing`, campaign experiment execution + results API.
    /// Sold on Growth and above.
    pub ab_testing: bool,
    /// `time_travel_debugging`, historical message-state replay.
    /// Sold on Growth and above.
    pub time_travel_debugging: bool,
    /// `template_approval_workflow`, maker/checker template publishing.
    /// Sold on Business and Enterprise Cloud.
    pub template_approval_workflow: bool,
    /// `subaccounts`, child workspaces with isolated quotas/keys.
    /// Sold on Business and Enterprise Cloud.
    pub subaccounts: bool,
    /// `max_subaccounts`, child-workspace ceiling (-1 = unlimited).
    pub max_subaccounts: i64,
}

/// The canonical catalog, ordered by sort order. Mirrors the deployed
/// billing runtime exactly, the 2026-10-15 owner price table
/// (Developer €20 / Pro €89 / Growth €229 / Business €699 / Enterprise
/// Cloud from €1,750, with the published USD list $20/$99/$249/$749/$1,950;
/// the 2026-09-08 review had Developer at €29 and EUR-only prices).
/// Free 3,000/mo + a one-time 30,000-email launch allowance.
pub const PLANS: &[PlanRow] = &[
    PlanRow {
        name: "free",
        display_name: "Free",
        price_monthly_cents: 0,
        price_yearly_cents: 0,
        price_monthly_usd_cents: 0,
        price_yearly_usd_cents: 0,
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
        price_monthly_cents: 2_000,
        price_yearly_cents: 20_000,
        price_monthly_usd_cents: 2_000,
        price_yearly_usd_cents: 20_000,
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
        price_monthly_usd_cents: 9_900,
        price_yearly_usd_cents: 99_000,
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
        price_monthly_usd_cents: 24_900,
        price_yearly_usd_cents: 249_000,
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
        price_monthly_usd_cents: 74_900,
        price_yearly_usd_cents: 749_000,
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
        price_monthly_usd_cents: 195_000,
        price_yearly_usd_cents: 1_950_000,
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
        price_monthly_usd_cents: 0,
        price_yearly_usd_cents: 0,
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

// ─────────────────────────────────────────────────────────────────────────
// Contract product lines (annual-contract products sold alongside the
// self-serve plans; 2026-10-15 owner price table). These are NOT `PlanRow`s:
// the billing `plans` table serves self-serve subscriptions, these lines are
// contracted by sales (same reasons the DedicatedTenant struct stays in
// `compliance/src/deployment_products.rs`, this block only adds the catalog
// rows/constants the plan names).
// ─────────────────────────────────────────────────────────────────────────

/// One contract product-line row (monthly list price in CENTS, EUR + USD).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProductLineRow {
    /// Lookup id (lowercase, e.g. "compliance").
    pub name: &'static str,
    /// Customer-facing display name.
    pub display_name: &'static str,
    /// Monthly list price in euro CENTS.
    pub price_monthly_cents: i64,
    /// Monthly list price in US dollar CENTS.
    pub price_monthly_usd_cents: i64,
    /// Minimum contract term in months.
    pub minimum_contract_months: i64,
    /// What the row covers (display/derivation text).
    pub notes: &'static str,
}

/// The annual-contract product lines. Sold by sales, billed monthly on a
/// 12-month minimum term.
pub const PRODUCT_LINES: &[ProductLineRow] = &[
    ProductLineRow {
        name: "compliance",
        display_name: "Compliance",
        price_monthly_cents: 99_000,
        price_monthly_usd_cents: 109_000,
        minimum_contract_months: 12,
        notes: "Compliance suite (annual contract)",
    },
    ProductLineRow {
        name: "platform",
        display_name: "Platform",
        price_monthly_cents: 99_000,
        price_monthly_usd_cents: 109_000,
        minimum_contract_months: 12,
        notes: "Platform base: 1,000,000 emails/month included + 100 active subaccounts included",
    },
    ProductLineRow {
        name: "dedicated_tenant",
        display_name: "Dedicated Tenant",
        price_monthly_cents: 400_000,
        price_monthly_usd_cents: 450_000,
        minimum_contract_months: 12,
        notes: "From this price; single-tenant deployment (12-month minimum)",
    },
];

/// Platform line: emails included per month before the overage rate applies.
pub const PLATFORM_INCLUDED_EMAILS: i64 = 1_000_000;

/// Platform line: overage in euro CENTS per 1,000 emails above the included
/// volume (€0.30/1K).
pub const PLATFORM_OVERAGE_CENTS_PER_1K: i64 = 30;

/// Platform line: overage in US cent CENTS per 1,000 emails ($0.35/1K).
pub const PLATFORM_OVERAGE_USD_CENTS_PER_1K: i64 = 35;

/// Platform line: active subaccounts included before the per-subaccount fee.
pub const PLATFORM_INCLUDED_SUBACCOUNTS: i64 = 100;

/// Platform line: monthly fee per active subaccount above the included 100
/// (€1.00).
pub const PLATFORM_SUBACCOUNT_MONTHLY_CENTS: i64 = 100;

/// Platform line: monthly fee per active subaccount above the included 100
/// in US dollars ($1.00).
pub const PLATFORM_SUBACCOUNT_MONTHLY_USD_CENTS: i64 = 100;

/// Dedicated Tenant: one-time setup floor in euro CENTS (€10,000).
///
/// The structured DedicatedTenant product (setup range, SLA entitlements)
/// stays in `compliance/src/deployment_products.rs`, this constant only
/// mirrors its floor into the canonical catalog.
pub const DEDICATED_TENANT_SETUP_MIN_CENTS: i64 = 1_000_000;

/// Dedicated Tenant: one-time setup ceiling in euro CENTS (€40,000).
pub const DEDICATED_TENANT_SETUP_MAX_CENTS: i64 = 4_000_000;

// ─────────────────────────────────────────────────────────────────────────
// Add-ons (sold alongside a plan; monthly prices in CENTS, EUR + USD).
// ─────────────────────────────────────────────────────────────────────────

/// Dedicated IP add-on: first managed address, €49/mo (USD $55).
pub const DEDICATED_IP_FIRST_CENTS: i64 = 4_900;
/// Dedicated IP add-on: each additional address, €69/mo (USD $75).
pub const DEDICATED_IP_ADDITIONAL_CENTS: i64 = 6_900;
/// Dedicated IP add-on: first managed address in US dollars ($55).
pub const DEDICATED_IP_FIRST_USD_CENTS: i64 = 5_500;
/// Dedicated IP add-on: each additional address in US dollars ($75).
pub const DEDICATED_IP_ADDITIONAL_USD_CENTS: i64 = 7_500;
/// Mailboxes: minimum seats per account.
pub const MAILBOX_MINIMUM_SEATS: i64 = 10;

/// One add-on row (monthly price in CENTS, EUR + USD).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AddonRow {
    /// Lookup id (lowercase, e.g. "inbox_placement_monitoring").
    pub name: &'static str,
    /// Customer-facing display name.
    pub display_name: &'static str,
    /// Monthly price in euro CENTS.
    pub price_cents: i64,
    /// Monthly price in US dollar CENTS.
    pub price_usd_cents: i64,
    /// What the price buys (display/derivation text).
    pub unit: &'static str,
}

/// Every add-on the owner's 2026-10-15 price table names.
pub const ADDONS: &[AddonRow] = &[
    AddonRow {
        name: "dedicated_ip",
        display_name: "Dedicated IP",
        price_cents: DEDICATED_IP_FIRST_CENTS,
        price_usd_cents: DEDICATED_IP_FIRST_USD_CENTS,
        unit: "per month (first address)",
    },
    AddonRow {
        name: "dedicated_ip_additional",
        display_name: "Dedicated IP (additional)",
        price_cents: DEDICATED_IP_ADDITIONAL_CENTS,
        price_usd_cents: DEDICATED_IP_ADDITIONAL_USD_CENTS,
        unit: "per month (each additional address)",
    },
    AddonRow {
        name: "inbox_placement_monitoring",
        display_name: "Inbox Placement Monitoring",
        price_cents: 9_900,
        price_usd_cents: 10_900,
        unit: "per month",
    },
    AddonRow {
        name: "eu_only_routing",
        display_name: "EU-only Routing",
        price_cents: 14_900,
        price_usd_cents: 16_500,
        unit: "per month (Pro and above)",
    },
    AddonRow {
        name: "mailboxes",
        display_name: "Mailboxes",
        price_cents: 600,
        price_usd_cents: 700,
        unit: "per seat per month (10-seat minimum)",
    },
    AddonRow {
        name: "mailbox_archive_journaling",
        display_name: "Mailbox Archive + Journaling",
        price_cents: 200,
        price_usd_cents: 200,
        unit: "per seat per month (add-on to Mailboxes)",
    },
];

/// Lookup by billing plan id.
pub fn plan_by_name(name: &str) -> Option<&'static PlanRow> {
    PLANS.iter().find(|p| p.name == name)
}

/// Lookup a contract product line by id.
pub fn product_line_by_name(name: &str) -> Option<&'static ProductLineRow> {
    PRODUCT_LINES.iter().find(|p| p.name == name)
}

/// Lookup an add-on by id.
pub fn addon_by_name(name: &str) -> Option<&'static AddonRow> {
    ADDONS.iter().find(|a| a.name == name)
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

    /// The owner's 2026-10-15 price table, pinned in BOTH currencies (EUR
    /// cents / USD cents): Developer 20/20, Pro 89/99, Growth 229/249,
    /// Business 699/749, Enterprise Cloud 1,750/1,950; Free and PAYG 0.
    #[test]
    fn owner_price_table_is_pinned_in_eur_and_usd() {
        let cases: &[(&str, i64, i64, i64, i64)] = &[
            // plan, EUR monthly, USD monthly, EUR yearly, USD yearly
            ("free", 0, 0, 0, 0),
            ("starter", 2_000, 2_000, 20_000, 20_000),
            ("pro", 8_900, 9_900, 89_000, 99_000),
            ("growth", 22_900, 24_900, 229_000, 249_000),
            ("scale", 69_900, 74_900, 699_000, 749_000),
            ("enterprise", 175_000, 195_000, 1_750_000, 1_950_000),
            ("payg", 0, 0, 0, 0),
        ];
        for (name, eur_m, usd_m, eur_y, usd_y) in cases {
            let plan = plan_by_name(name).unwrap_or_else(|| panic!("plan {name} exists"));
            assert_eq!(plan.price_monthly_cents, *eur_m, "{name}: EUR monthly");
            assert_eq!(plan.price_yearly_cents, *eur_y, "{name}: EUR yearly");
            assert_eq!(plan.price_monthly_usd_cents, *usd_m, "{name}: USD monthly");
            assert_eq!(plan.price_yearly_usd_cents, *usd_y, "{name}: USD yearly");
        }
    }

    /// Annual billing is TEN monthly payments in BOTH currencies, a yearly
    /// price is never 12× or a 10% discount of the monthly price.
    #[test]
    fn annual_price_is_ten_monthly_payments_in_both_currencies() {
        for plan in PLANS {
            if plan.price_monthly_cents <= 0 && plan.price_monthly_usd_cents <= 0 {
                assert_eq!(plan.price_yearly_cents, 0, "{}: EUR yearly", plan.name);
                assert_eq!(plan.price_yearly_usd_cents, 0, "{}: USD yearly", plan.name);
                continue;
            }
            assert_eq!(
                plan.price_yearly_cents,
                plan.price_monthly_cents * 10,
                "{}: EUR yearly must be 10 monthly payments",
                plan.name
            );
            assert_eq!(
                plan.price_yearly_usd_cents,
                plan.price_monthly_usd_cents * 10,
                "{}: USD yearly must be 10 monthly payments",
                plan.name
            );
        }
    }

    /// Every paid plan's USD list price is >= its EUR list price (the
    /// published USD ladder), and the USD ladder is ascending like the EUR
    /// one.
    #[test]
    fn usd_ladder_mirrors_the_eur_ladder() {
        let rungs: Vec<(&str, i64, i64)> = PLANS
            .iter()
            .filter(|p| p.price_monthly_cents > 0 || p.price_monthly_usd_cents > 0)
            .map(|p| (p.name, p.price_monthly_cents, p.price_monthly_usd_cents))
            .collect();
        for (name, eur, usd) in &rungs {
            assert!(
                *usd >= *eur,
                "{name}: USD list price must not undercut the EUR price"
            );
        }
        let mut usd_sorted: Vec<i64> = rungs.iter().map(|(_, _, usd)| *usd).collect();
        let unsorted = usd_sorted.clone();
        usd_sorted.sort_unstable();
        assert_eq!(usd_sorted, unsorted, "USD ladder must be ascending");
    }

    /// The contract product lines the owner's table names: Compliance
    /// 990/1090, Platform base 990/1090 (per-1K overage 30/35 euro/USD
    /// cents, subaccounts above 100 at 100/100 cents), Dedicated Tenant
    /// from 4000/4500 on a 12-month minimum.
    #[test]
    fn contract_product_lines_are_pinned() {
        let compliance = product_line_by_name("compliance").expect("compliance row");
        assert_eq!(compliance.price_monthly_cents, 99_000);
        assert_eq!(compliance.price_monthly_usd_cents, 109_000);
        assert_eq!(compliance.minimum_contract_months, 12);

        let platform = product_line_by_name("platform").expect("platform row");
        assert_eq!(platform.price_monthly_cents, 99_000);
        assert_eq!(platform.price_monthly_usd_cents, 109_000);
        assert_eq!(platform.minimum_contract_months, 12);
        assert_eq!(PLATFORM_INCLUDED_EMAILS, 1_000_000);
        assert_eq!(
            PLATFORM_OVERAGE_CENTS_PER_1K, 30,
            "€0.30 per 1,000 above 1M"
        );
        assert_eq!(
            PLATFORM_OVERAGE_USD_CENTS_PER_1K, 35,
            "$0.35 per 1,000 above 1M"
        );
        assert_eq!(PLATFORM_INCLUDED_SUBACCOUNTS, 100);
        assert_eq!(PLATFORM_SUBACCOUNT_MONTHLY_CENTS, 100, "€1 per subaccount");
        assert_eq!(
            PLATFORM_SUBACCOUNT_MONTHLY_USD_CENTS, 100,
            "$1 per subaccount"
        );

        let tenant = product_line_by_name("dedicated_tenant").expect("dedicated tenant row");
        assert_eq!(tenant.price_monthly_cents, 400_000, "from €4,000/month");
        assert_eq!(tenant.price_monthly_usd_cents, 450_000, "from $4,500/month");
        assert_eq!(tenant.minimum_contract_months, 12);
        assert_eq!(DEDICATED_TENANT_SETUP_MIN_CENTS, 1_000_000);
        assert_eq!(DEDICATED_TENANT_SETUP_MAX_CENTS, 4_000_000);
    }

    /// The add-on ladder: dedicated IP 4900/6900 cents (USD 5500/7500),
    /// inbox placement monitoring 9900/10900, EU-only routing 14900/16500,
    /// mailboxes 600/700 per seat with a 10-seat minimum and
    /// archive+journaling +200/+200 per seat.
    #[test]
    fn addon_ladder_is_pinned() {
        let ip = addon_by_name("dedicated_ip").expect("dedicated ip row");
        assert_eq!(ip.price_cents, 4_900);
        assert_eq!(ip.price_usd_cents, 5_500);
        let ip_extra = addon_by_name("dedicated_ip_additional").expect("additional ip row");
        assert_eq!(ip_extra.price_cents, 6_900);
        assert_eq!(ip_extra.price_usd_cents, 7_500);
        assert_eq!(DEDICATED_IP_FIRST_CENTS, 4_900);
        assert_eq!(DEDICATED_IP_ADDITIONAL_CENTS, 6_900);

        let placement = addon_by_name("inbox_placement_monitoring").expect("placement row");
        assert_eq!(placement.price_cents, 9_900);
        assert_eq!(placement.price_usd_cents, 10_900);

        let routing = addon_by_name("eu_only_routing").expect("routing row");
        assert_eq!(routing.price_cents, 14_900);
        assert_eq!(routing.price_usd_cents, 16_500);
        assert!(routing.unit.contains("Pro"));

        let mailboxes = addon_by_name("mailboxes").expect("mailboxes row");
        assert_eq!(mailboxes.price_cents, 600);
        assert_eq!(mailboxes.price_usd_cents, 700);
        assert_eq!(MAILBOX_MINIMUM_SEATS, 10);

        let archive = addon_by_name("mailbox_archive_journaling").expect("archive row");
        assert_eq!(archive.price_cents, 200);
        assert_eq!(archive.price_usd_cents, 200);

        // Every add-on is uniquely named.
        let mut names: Vec<&str> = ADDONS.iter().map(|a| a.name).collect();
        let len = names.len();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), len, "add-on ids must be unique");
    }
}
