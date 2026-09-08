//! Plan definitions and quota management.
//!
//! Canonical plan definitions for free / starter / pro / growth / scale /
//! enterprise / pay-as-you-go tiers.

use chrono::Utc;
use sqlx::PgPool;
use uuid::Uuid;

use crate::types::{Plan, PlanFeatures, QuotaLimit, RateLimitTier, SupportLevel};

/// Static seed data for default plans.
#[derive(Debug, Clone)]
pub struct PlanSeed {
    pub name: &'static str,
    pub display_name: &'static str,
    pub description: &'static str,
    pub price_monthly: i64,
    pub price_yearly: i64,
    pub email_limit: i64,
    pub api_call_limit: i64,
    pub sort_order: i32,
    pub features: PlanFeatures,
}

#[derive(Debug, Clone)]
pub struct PlanUpsertInput {
    pub name: String,
    pub display_name: String,
    pub description: String,
    pub price_monthly: i64,
    pub price_yearly: i64,
    pub email_limit: i64,
    pub api_call_limit: i64,
    pub sort_order: i32,
    pub features: PlanFeatures,
    pub stripe_price_id_monthly: Option<String>,
    pub stripe_price_id_yearly: Option<String>,
}

/// All default plans shipped with ApexMail.
///
/// 2026-09-08 pricing review: the Free tier moved from 30,000/mo to
/// 3,000/mo — 30k/month forever gave away a meaningful production
/// workload (competitors: Resend 3k, Scaleway €80/100k). New free
/// tenants instead get a ONE-TIME 30-day launch allowance of 30,000
/// emails (enforced in usage.rs `resolve_plan_limits`: the effective
/// ceiling is 30,000 for the tenant's first 30 days, then 3,000).
/// Paid tiers were repositioned so Growth/Business are no longer
/// suspiciously inexpensive for what they include (dedicated IPs,
/// SSO, SLA): Developer €29, Pro €89, Growth €229, Business €699,
/// Enterprise Cloud from €1,750.
fn free_plan_seed() -> PlanSeed {
    PlanSeed {
        name: "free",
        display_name: "Free",
        description: "3,000 emails/month forever + a one-time 30,000-email launch allowance for your first 30 days",
        price_monthly: 0,
        price_yearly: 0,
        email_limit: 3_000,
        api_call_limit: 30_000,
        sort_order: 0,
        features: PlanFeatures {
            api_access: true,
            max_sending_domains: 1,
            max_retention_days: 7,
            max_team_members: 1,
            powered_by_footer: true,
            support_level: SupportLevel::Community,
            ..PlanFeatures::default()
        },
    }
}

pub fn default_plans() -> Vec<PlanSeed> {
    vec![
        free_plan_seed(),
        PlanSeed {
            name: "starter",
            display_name: "Developer",
            description: "For developers wiring up production email",
            price_monthly: 2_900,
            price_yearly: 29_000,
            email_limit: 50_000,
            api_call_limit: 500_000,
            sort_order: 1,
            features: PlanFeatures {
                api_access: true,
                webhooks_enabled: true,
                advanced_analytics: true,
                data_export: true,
                custom_templates: true,
                max_sending_domains: 5,
                max_retention_days: 30,
                max_team_members: 5,
                support_level: SupportLevel::Email,
                ..PlanFeatures::default()
            },
        },
        PlanSeed {
            name: "pro",
            display_name: "Pro",
            description: "For scaling teams with custom tracking needs",
            price_monthly: 8_900,
            price_yearly: 89_000,
            email_limit: 150_000,
            api_call_limit: 2_000_000,
            sort_order: 2,
            features: PlanFeatures {
                dedicated_ip: true,
                dedicated_ip_count: 0,
                api_access: true,
                webhooks_enabled: true,
                advanced_analytics: true,
                send_time_optimization: true,
                data_export: true,
                custom_tracking_domain: true,
                custom_templates: true,
                max_sending_domains: 25,
                max_retention_days: 60,
                max_team_members: 10,
                priority_onboarding: true,
                support_level: SupportLevel::Email,
                ..PlanFeatures::default()
            },
        },
        PlanSeed {
            name: "growth",
            display_name: "Growth",
            description: "For teams that need advanced deliverability features",
            price_monthly: 22_900,
            price_yearly: 229_000,
            email_limit: 500_000,
            api_call_limit: 5_000_000,
            sort_order: 3,
            features: PlanFeatures {
                dedicated_ip: true,
                dedicated_ip_count: 1,
                api_access: true,
                webhooks_enabled: true,
                audit_logs: true,
                advanced_analytics: true,
                send_time_optimization: true,
                ab_testing: true,
                time_travel_debugging: true,
                data_export: true,
                custom_tracking_domain: true,
                custom_templates: true,
                custom_retention: true,
                max_sending_domains: 100,
                max_retention_days: 90,
                max_team_members: 25,
                priority_onboarding: true,
                // Growth keeps Email tier per the async-first support policy
                // (24–48h response, no live chat, no per-customer Discord).
                support_level: SupportLevel::Email,
                ..PlanFeatures::default()
            },
        },
        PlanSeed {
            name: "scale",
            display_name: "Business",
            description: "For high-volume senders needing isolation",
            price_monthly: 69_900,
            price_yearly: 699_000,
            email_limit: 2_000_000,
            api_call_limit: 20_000_000,
            sort_order: 4,
            features: PlanFeatures {
                dedicated_ip: true,
                dedicated_ip_count: 3,
                max_sending_domains: -1,
                sso_enabled: true,
                audit_logs: true,
                api_access: true,
                webhooks_enabled: true,
                inbound_email: true,
                advanced_analytics: true,
                send_time_optimization: true,
                ab_testing: true,
                time_travel_debugging: true,
                data_export: true,
                custom_tracking_domain: true,
                custom_templates: true,
                template_approval_workflow: true,
                custom_retention: true,
                max_retention_days: 365,
                max_team_members: 50,
                subaccounts: true,
                max_subaccounts: 10,
                dedicated_csm: true,
                priority_onboarding: true,
                sla_guarantee: true,
                sla_credit_percentage: 10,
                // Scale = priority email + shared Slack hub (no per-customer
                // Discord, no 24/7 phone). Live calls are scheduled, capped.
                support_level: SupportLevel::Priority,
                ..PlanFeatures::default()
            },
        },
        PlanSeed {
            name: "enterprise",
            display_name: "Enterprise Cloud",
            description:
                "From €1,750/month — annual-contract platform plan for large organizations",
            price_monthly: 175_000,
            price_yearly: 1_750_000,
            email_limit: 5_000_000,
            api_call_limit: -1,
            sort_order: 5,
            features: PlanFeatures {
                dedicated_ip: true,
                dedicated_ip_count: 10,
                max_sending_domains: -1,
                sso_enabled: true,
                audit_logs: true,
                api_access: true,
                webhooks_enabled: true,
                inbound_email: true,
                advanced_analytics: true,
                send_time_optimization: true,
                ab_testing: true,
                time_travel_debugging: true,
                data_export: true,
                custom_tracking_domain: true,
                custom_templates: true,
                template_approval_workflow: true,
                white_label: true,
                custom_retention: true,
                max_retention_days: 730,
                max_team_members: -1,
                subaccounts: true,
                max_subaccounts: 100,
                dedicated_csm: true,
                priority_onboarding: true,
                sla_guarantee: true,
                sla_credit_percentage: 25,
                // Compliance certifications and HIPAA availability are not
                // currently offered. Do not expose these as entitlement
                // flags merely because Enterprise has related workflows.
                hipaa_compliance: false,
                soc2_compliance: false,
                private_cloud: true,
                byoip: true,
                support_level: SupportLevel::Dedicated,
                ..PlanFeatures::default()
            },
        },
        PlanSeed {
            name: "payg",
            display_name: "Pay As You Go",
            description: "Flexible usage-based pricing for variable volume",
            price_monthly: 0,
            price_yearly: 0,
            email_limit: -1,
            api_call_limit: -1,
            sort_order: 6,
            features: PlanFeatures {
                api_access: true,
                webhooks_enabled: true,
                advanced_analytics: true,
                data_export: true,
                custom_templates: true,
                max_sending_domains: 5,
                max_retention_days: 30,
                max_team_members: 5,
                support_level: SupportLevel::Email,
                ..PlanFeatures::default()
            },
        },
    ]
}

pub fn builtin_plan_seed(plan_name: Option<&str>) -> PlanSeed {
    let preferred = plan_name.unwrap_or("free");
    let plans = default_plans();

    plans
        .iter()
        .find(|plan| plan.name == preferred)
        .cloned()
        .unwrap_or_else(free_plan_seed)
}

pub fn builtin_quota_limits(plan_name: Option<&str>) -> (i64, i64) {
    let plan = builtin_plan_seed(plan_name);
    (plan.email_limit, plan.api_call_limit)
}

/// The builtin email limit for a KNOWN plan name, or `None` when the name
/// matches no builtin plan.
///
/// [`builtin_quota_limits`] deliberately falls back to the free plan for
/// unknown names (quota lookups must always resolve to something). The
/// overage sweep needs the stricter variant: a missing `plans` row must be
/// resolved to the builtin limit by name, and an UNKNOWN name must surface
/// as unknown (skip with a warning) rather than silently borrowing the free
/// plan's 30 000-email limit — or worse, the historical `unwrap_or(0)`
/// which billed the tenant's entire volume as overage.
pub fn builtin_email_limit_for_plan(plan_name: &str) -> Option<i64> {
    default_plans()
        .into_iter()
        .find(|plan| plan.name == plan_name)
        .map(|plan| plan.email_limit)
}

/// Whether `plan_name` is one of the builtin plan identifiers.
pub fn is_builtin_plan_name(plan_name: &str) -> bool {
    builtin_email_limit_for_plan(plan_name).is_some()
}

// ---------------------------------------------------------------------------
// Database helpers
// ---------------------------------------------------------------------------

/// ON CONFLICT clause shape used by [`upsert_plan`] (Fix I1): re-seeding
/// preserves operator-configured prices/limits/features via COALESCE toward
/// the existing row; only missing plans receive the seed defaults.
const SEED_PLAN_UPSERT_SQL: &str = r#"
        INSERT INTO plans (
            id, name, display_name, description,
            price_monthly, price_yearly, email_limit, api_call_limit,
            features, stripe_price_id_monthly, stripe_price_id_yearly,
            is_active, sort_order, created_at, updated_at
        ) VALUES (
            gen_random_uuid(), $1, $2, $3,
            $4, $5, $6, $7,
            $8, NULL, NULL, true, $9, $10, $10
        )
        ON CONFLICT (name) DO UPDATE SET
            display_name  = EXCLUDED.display_name,
            description   = EXCLUDED.description,
            price_monthly = COALESCE(plans.price_monthly, EXCLUDED.price_monthly),
            price_yearly  = COALESCE(plans.price_yearly, EXCLUDED.price_yearly),
            email_limit   = COALESCE(plans.email_limit, EXCLUDED.email_limit),
            api_call_limit= COALESCE(plans.api_call_limit, EXCLUDED.api_call_limit),
            features      = COALESCE(plans.features, EXCLUDED.features),
            sort_order    = EXCLUDED.sort_order,
            updated_at    = $10
        RETURNING
            id, name, display_name, description,
            price_monthly, price_yearly, email_limit, api_call_limit,
            features, stripe_price_id_monthly, stripe_price_id_yearly,
            is_active, sort_order, created_at, updated_at
        "#;

/// Upsert a plan seed into the database.
///
/// Fix I1 — seeding must never clobber prices, limits, or features an
/// operator has already configured (e.g. a custom Enterprise price set via
/// the admin PATCH route). Existing values win; only missing plans are
/// inserted with the seed defaults.
pub async fn upsert_plan(pool: &PgPool, seed: &PlanSeed) -> Result<Plan, sqlx::Error> {
    let features_json =
        serde_json::to_value(&seed.features).map_err(|e| sqlx::Error::Decode(Box::new(e)))?;
    let now = Utc::now();

    let row: PlanRow = sqlx::query_as(SEED_PLAN_UPSERT_SQL)
        .bind(seed.name)
        .bind(seed.display_name)
        .bind(seed.description)
        .bind(seed.price_monthly)
        .bind(seed.price_yearly)
        .bind(seed.email_limit)
        .bind(seed.api_call_limit)
        .bind(&features_json)
        .bind(seed.sort_order)
        .bind(now)
        .fetch_one(pool)
        .await?;

    Ok(row.into_plan())
}

pub async fn upsert_plan_input(
    pool: &PgPool,
    input: &PlanUpsertInput,
) -> Result<Plan, sqlx::Error> {
    let features_json =
        serde_json::to_value(&input.features).map_err(|e| sqlx::Error::Decode(Box::new(e)))?;
    let now = Utc::now();

    let row: PlanRow = sqlx::query_as(
        r#"
        INSERT INTO plans (
            id, name, display_name, description,
            price_monthly, price_yearly, email_limit, api_call_limit,
            features, stripe_price_id_monthly, stripe_price_id_yearly,
            is_active, sort_order, created_at, updated_at
        ) VALUES (
            gen_random_uuid(), $1, $2, $3,
            $4, $5, $6, $7,
            $8, $11, $12, true, $9, $10, $10
        )
        ON CONFLICT (name) DO UPDATE SET
            display_name  = EXCLUDED.display_name,
            description   = EXCLUDED.description,
            price_monthly = EXCLUDED.price_monthly,
            price_yearly  = EXCLUDED.price_yearly,
            email_limit   = EXCLUDED.email_limit,
            api_call_limit= EXCLUDED.api_call_limit,
            features      = EXCLUDED.features,
            stripe_price_id_monthly = COALESCE(EXCLUDED.stripe_price_id_monthly, plans.stripe_price_id_monthly),
            stripe_price_id_yearly  = COALESCE(EXCLUDED.stripe_price_id_yearly, plans.stripe_price_id_yearly),
            sort_order    = EXCLUDED.sort_order,
            updated_at    = $10
        RETURNING
            id, name, display_name, description,
            price_monthly, price_yearly, email_limit, api_call_limit,
            features, stripe_price_id_monthly, stripe_price_id_yearly,
            is_active, sort_order, created_at, updated_at
        "#,
    )
    .bind(&input.name)
    .bind(&input.display_name)
    .bind(&input.description)
    .bind(input.price_monthly)
    .bind(input.price_yearly)
    .bind(input.email_limit)
    .bind(input.api_call_limit)
    .bind(&features_json)
    .bind(input.sort_order)
    .bind(now)
    .bind(&input.stripe_price_id_monthly)
    .bind(&input.stripe_price_id_yearly)
    .fetch_one(pool)
    .await?;

    Ok(row.into_plan())
}

/// Fetch all active plans ordered by `sort_order`.
pub async fn get_active_plans(pool: &PgPool) -> Result<Vec<Plan>, sqlx::Error> {
    let rows: Vec<PlanRow> = sqlx::query_as(
        r#"
        SELECT
            id, name, display_name, description,
            price_monthly, price_yearly, email_limit, api_call_limit,
            features, stripe_price_id_monthly, stripe_price_id_yearly,
            is_active, sort_order, created_at, updated_at
        FROM plans
        WHERE is_active = true
        ORDER BY sort_order ASC
        "#,
    )
    .fetch_all(pool)
    .await?;

    Ok(rows.into_iter().map(|r| r.into_plan()).collect())
}

/// Get a single plan by name.
pub async fn get_plan_by_name(pool: &PgPool, name: &str) -> Result<Option<Plan>, sqlx::Error> {
    let row: Option<PlanRow> = sqlx::query_as(
        r#"
        SELECT
            id, name, display_name, description,
            price_monthly, price_yearly, email_limit, api_call_limit,
            features, stripe_price_id_monthly, stripe_price_id_yearly,
            is_active, sort_order, created_at, updated_at
        FROM plans
        WHERE name = $1
        "#,
    )
    .bind(name)
    .fetch_optional(pool)
    .await?;

    Ok(row.map(|r| r.into_plan()))
}

/// Resolve a tenant's effective plan.
///
/// An admin plan override (plan_overrides, migration 069/093) takes
/// precedence over the tenant's own plan while it is `active` and either
/// unexpired or without an expiry. Otherwise the tenant's plan is used.
pub async fn get_plan_for_tenant(
    pool: &PgPool,
    tenant_id: &str,
) -> Result<Option<Plan>, sqlx::Error> {
    let row: Option<(String,)> = sqlx::query_as(
        r#"
        SELECT COALESCE(po.plan, t.plan) AS plan_name
        FROM tenants t
        LEFT JOIN plan_overrides po
          ON po.tenant_id = t.id
         AND po.active = true
         AND (po.expires_at IS NULL OR po.expires_at > NOW())
        WHERE t.id = $1
        "#,
    )
    .bind(tenant_id)
    .fetch_optional(pool)
    .await?;

    match row {
        Some((plan_name,)) => get_plan_by_name(pool, &plan_name).await,
        None => Ok(None),
    }
}

/// Derive quota/rate-limit info for a tenant from their current plan.
///
/// Fix I2 — quota resolution honours active admin plan overrides exactly
/// like [`get_plan_for_tenant`], instead of only consulting `tenants.plan`.
pub async fn get_quota_for_tenant(
    pool: &PgPool,
    tenant_id: &str,
) -> Result<Option<QuotaLimit>, sqlx::Error> {
    let row: Option<TenantPlanRow> = sqlx::query_as(
        r#"
        SELECT
            t.id    as tenant_id,
            COALESCE(po.plan, t.plan) as plan_name,
            p.email_limit,
            p.api_call_limit,
            p.features
        FROM tenants t
        LEFT JOIN plan_overrides po
          ON po.tenant_id = t.id
         AND po.active = true
         AND (po.expires_at IS NULL OR po.expires_at > NOW())
        LEFT JOIN plans p ON p.name = COALESCE(po.plan, t.plan)
        WHERE t.id = $1
        "#,
    )
    .bind(tenant_id)
    .fetch_optional(pool)
    .await?;

    let Some(row) = row else { return Ok(None) };

    let fallback_plan = builtin_plan_seed(Some(&row.plan_name));
    let plan_found =
        row.email_limit.is_some() || row.api_call_limit.is_some() || row.features.is_some();
    let effective_plan_name = if plan_found {
        row.plan_name.clone()
    } else {
        fallback_plan.name.to_string()
    };
    let features = row
        .features
        .and_then(|value| serde_json::from_value(value).ok())
        .unwrap_or_else(|| fallback_plan.features.clone());

    let tier = match effective_plan_name.as_str() {
        "free" => RateLimitTier::Free,
        "starter" | "pro" | "payg" => RateLimitTier::Standard,
        "growth" | "scale" => RateLimitTier::High,
        "enterprise" => RateLimitTier::Unlimited,
        _ => RateLimitTier::Standard,
    };

    Ok(Some(QuotaLimit {
        tenant_id: row.tenant_id,
        plan_name: effective_plan_name,
        emails_per_month: row.email_limit.unwrap_or(fallback_plan.email_limit),
        api_calls_per_month: row.api_call_limit.unwrap_or(fallback_plan.api_call_limit),
        max_sending_domains: features.max_sending_domains,
        max_team_members: features.max_team_members,
        max_subaccounts: features.max_subaccounts,
        rate_limit_tier: tier,
    }))
}

/// Default overage price per email in millicents
/// (`€0.40 / 1 000 emails = 0.04 cents = 40 millicents`). Kept as a constant
/// so the legacy two-argument [`calculate_overage_cost`] wrapper and
/// [`crate::config::BillingConfig::overage_rate_per_email_millicents`]
/// (Fix I10) stay in sync.
pub const DEFAULT_OVERAGE_RATE_MILLICENTS: i64 = 40;

/// Calculate overage cost in cents.
/// `€0.40 / 1 000 emails = 0.04 cents / email`
///
/// Legacy signature kept for API compatibility (api-server callers); uses
/// the default rate. New call sites should thread the configured rate via
/// [`calculate_overage_cost_with_rate`].
pub fn calculate_overage_cost(emails_sent: i64, email_limit: i64) -> i64 {
    calculate_overage_cost_with_rate(emails_sent, email_limit, DEFAULT_OVERAGE_RATE_MILLICENTS)
}

/// Calculate overage cost in cents using an explicit per-email rate in
/// millicents (Fix I10 — the rate is config-driven, defaulting to 40).
pub fn calculate_overage_cost_with_rate(
    emails_sent: i64,
    email_limit: i64,
    rate_millicents: i64,
) -> i64 {
    if email_limit < 0 {
        return 0; // unlimited
    }
    if emails_sent <= email_limit {
        return 0;
    }
    let overage = emails_sent - email_limit;
    // rate millicents/email → cents: ceil(overage * rate / 1000).
    // Use i128 intermediate arithmetic to prevent overflow near i64 bounds.
    let safe_rate = rate_millicents.max(0);
    ((overage as i128)
        .saturating_mul(safe_rate as i128)
        .saturating_add(999))
    .div_euclid(1000) as i64
}

// ---------------------------------------------------------------------------
// Internal row types
// ---------------------------------------------------------------------------

#[derive(sqlx::FromRow)]
struct PlanRow {
    id: Uuid,
    name: String,
    display_name: String,
    description: String,
    price_monthly: i64,
    price_yearly: i64,
    email_limit: i64,
    api_call_limit: i64,
    features: Option<serde_json::Value>,
    stripe_price_id_monthly: Option<String>,
    stripe_price_id_yearly: Option<String>,
    is_active: bool,
    sort_order: i32,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

use chrono::DateTime;

impl PlanRow {
    fn into_plan(self) -> Plan {
        let features: PlanFeatures =
            serde_json::from_value(self.features.unwrap_or_default()).unwrap_or_default();
        Plan {
            id: self.id,
            name: self.name,
            display_name: self.display_name,
            description: self.description,
            price_monthly: self.price_monthly,
            price_yearly: self.price_yearly,
            email_limit: self.email_limit,
            api_call_limit: self.api_call_limit,
            features,
            stripe_price_id_monthly: self.stripe_price_id_monthly,
            stripe_price_id_yearly: self.stripe_price_id_yearly,
            is_active: self.is_active,
            sort_order: self.sort_order,
            created_at: self.created_at,
            updated_at: self.updated_at,
        }
    }
}

#[derive(sqlx::FromRow)]
struct TenantPlanRow {
    tenant_id: String,
    plan_name: String,
    email_limit: Option<i64>,
    api_call_limit: Option<i64>,
    features: Option<serde_json::Value>,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_plans_are_sorted() {
        let plans = default_plans();
        for (i, plan) in plans.iter().enumerate() {
            assert_eq!(plan.sort_order, i as i32);
        }
    }

    #[test]
    fn dedicated_ip_included_counts_match_public_pricing() {
        let plans = default_plans();
        let pro_plan = plans
            .iter()
            .find(|plan| plan.name == "pro")
            .expect("pro plan must exist");
        let growth_plan = plans
            .iter()
            .find(|plan| plan.name == "growth")
            .expect("growth plan must exist");
        let scale_plan = plans
            .iter()
            .find(|plan| plan.name == "scale")
            .expect("scale plan must exist");
        let enterprise_plan = plans
            .iter()
            .find(|plan| plan.name == "enterprise")
            .expect("enterprise plan must exist");

        assert!(pro_plan.features.dedicated_ip);
        assert_eq!(pro_plan.features.dedicated_ip_count, 0);
        assert_eq!(growth_plan.features.dedicated_ip_count, 1);
        assert_eq!(scale_plan.features.dedicated_ip_count, 3);
        assert_eq!(enterprise_plan.features.dedicated_ip_count, 10);
    }

    #[test]
    fn analytics_optimization_gates_match_public_pricing() {
        let plans = default_plans();
        let starter_features = plans
            .iter()
            .find(|plan| plan.name == "starter")
            .map(|plan| plan.features.clone())
            .expect("starter plan must exist");
        let pro_features = plans
            .iter()
            .find(|plan| plan.name == "pro")
            .map(|plan| plan.features.clone())
            .expect("pro plan must exist");
        let growth_features = plans
            .iter()
            .find(|plan| plan.name == "growth")
            .map(|plan| plan.features.clone())
            .expect("growth plan must exist");
        let enterprise_features = plans
            .iter()
            .find(|plan| plan.name == "enterprise")
            .map(|plan| plan.features.clone())
            .expect("enterprise plan must exist");

        assert!(!starter_features.send_time_optimization);
        assert!(!starter_features.ab_testing);
        assert!(pro_features.send_time_optimization);
        assert!(!pro_features.ab_testing);
        assert!(growth_features.send_time_optimization);
        assert!(growth_features.ab_testing);
        assert!(enterprise_features.send_time_optimization);
        assert!(enterprise_features.ab_testing);
    }

    #[test]
    fn builtin_quota_limits_fall_back_to_free() {
        assert_eq!(
            builtin_quota_limits(Some("does-not-exist")),
            (3_000, 30_000)
        );
    }

    // ------------------------------------------------------------------
    // Overage sweep fallback (audit 1.3): a missing plans row resolves to
    // the builtin limit BY NAME; unknown names stay unknown.
    // ------------------------------------------------------------------

    #[test]
    fn builtin_email_limit_resolves_known_plans_by_name() {
        assert_eq!(builtin_email_limit_for_plan("free"), Some(3_000));
        assert_eq!(builtin_email_limit_for_plan("starter"), Some(50_000));
        assert_eq!(builtin_email_limit_for_plan("enterprise"), Some(5_000_000));
        // PAYG is unlimited.
        assert_eq!(builtin_email_limit_for_plan("payg"), Some(-1));
        assert!(is_builtin_plan_name("payg"));
    }

    #[test]
    fn builtin_email_limit_is_none_for_unknown_plans() {
        assert_eq!(builtin_email_limit_for_plan("does-not-exist"), None);
        assert_eq!(builtin_email_limit_for_plan(""), None);
        assert!(!is_builtin_plan_name("legacy-custom"));
    }

    #[test]
    fn overage_unlimited_is_zero() {
        assert_eq!(calculate_overage_cost(999_999, -1), 0);
    }

    #[test]
    fn overage_within_limit() {
        assert_eq!(calculate_overage_cost(30_000, 30_000), 0);
    }

    #[test]
    fn overage_above_limit() {
        // 1 000 overage emails * 0.04 cents = 40 cents
        assert_eq!(calculate_overage_cost(31_000, 30_000), 40);
    }

    // ------------------------------------------------------------------
    // Fix I10 — overage rate is configurable (default 40 millicents).
    // ------------------------------------------------------------------

    #[test]
    fn overage_with_rate_defaults_match_legacy_math() {
        for (sent, limit) in [(31_000, 30_000), (50_000, 30_000), (1, 0)] {
            assert_eq!(
                calculate_overage_cost_with_rate(sent, limit, DEFAULT_OVERAGE_RATE_MILLICENTS),
                calculate_overage_cost(sent, limit),
                "legacy wrapper and default rate must agree for ({sent}, {limit})"
            );
        }
    }

    #[test]
    fn overage_with_custom_rate_scales_linearly() {
        // Double the rate → double the cost.
        assert_eq!(
            calculate_overage_cost_with_rate(31_000, 30_000, 80),
            2 * calculate_overage_cost(31_000, 30_000)
        );
        // Zero rate → free overage.
        assert_eq!(calculate_overage_cost_with_rate(31_000, 30_000, 0), 0);
    }

    #[test]
    fn overage_with_rate_rounds_up_per_millicent_precision() {
        // 1 overage email at 40 millicents = 0.04 cents → rounds up to 1 cent.
        assert_eq!(calculate_overage_cost_with_rate(31, 30, 40), 1);
        // 25 overage emails at 40 millicents = exactly 1 cent.
        assert_eq!(calculate_overage_cost_with_rate(55, 30, 40), 1);
        // 26 overage emails → 1.04 cents → 2 cents.
        assert_eq!(calculate_overage_cost_with_rate(56, 30, 40), 2);
    }

    // ------------------------------------------------------------------
    // Fix I1 — seeding preserves operator-configured plan values.
    // ------------------------------------------------------------------

    #[test]
    fn seed_upsert_sql_preserves_configured_plan_values() {
        // The seed SQL must COALESCE toward the existing row so re-seeding
        // never reverts admin-configured prices/limits/features.
        for column in [
            "price_monthly",
            "price_yearly",
            "email_limit",
            "api_call_limit",
            "features",
        ] {
            let preserve = format!("COALESCE(plans.{column}, EXCLUDED.{column})");
            assert!(
                SEED_PLAN_UPSERT_SQL.contains(&preserve),
                "seed upsert must preserve plans.{column} (expected `{preserve}`)"
            );
        }
    }

    #[test]
    fn enterprise_exposes_only_currently_available_compliance_features() {
        let plans = default_plans();
        let ent_features = plans
            .iter()
            .find(|p| p.name == "enterprise")
            .map(|p| p.features.clone());
        assert!(ent_features
            .as_ref()
            .map(|f| f.sso_enabled)
            .unwrap_or(false));
        assert!(!ent_features
            .as_ref()
            .map(|f| f.hipaa_compliance)
            .unwrap_or(false));
        assert!(!ent_features
            .as_ref()
            .map(|f| f.soc2_compliance)
            .unwrap_or(false));
        assert!(ent_features
            .as_ref()
            .map(|f| f.send_time_optimization)
            .unwrap_or(false));
        assert!(ent_features.as_ref().map(|f| f.ab_testing).unwrap_or(false));
        assert!(ent_features
            .as_ref()
            .map(|f| f.private_cloud)
            .unwrap_or(false));
        assert!(ent_features.as_ref().map(|f| f.byoip).unwrap_or(false));
        assert_eq!(
            ent_features
                .as_ref()
                .map(|f| f.support_level)
                .unwrap_or(SupportLevel::Community),
            SupportLevel::Dedicated
        );
    }
}
