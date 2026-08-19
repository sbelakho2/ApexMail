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
/// The Free tier ships **30,000 emails / month**. Rust runtime margins
/// (Hetzner + Rust per-core throughput) make a 10x competitive Free tier
/// affordable. This is intentionally an order-of-magnitude above Resend's
/// 3,000/mo and is the primary acquisition wedge.
fn free_plan_seed() -> PlanSeed {
    PlanSeed {
        name: "free",
        display_name: "Free",
        description: "Generous free tier — 30,000 emails/month forever",
        price_monthly: 0,
        price_yearly: 0,
        email_limit: 30_000,
        api_call_limit: 300_000,
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
            display_name: "Starter",
            description: "For growing businesses with moderate email needs",
            price_monthly: 2_500,
            price_yearly: 25_000,
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
            price_monthly: 6_500,
            price_yearly: 65_000,
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
            price_monthly: 15_000,
            price_yearly: 150_000,
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
            display_name: "Scale",
            description: "For high-volume senders needing isolation",
            price_monthly: 35_000,
            price_yearly: 350_000,
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
            display_name: "Enterprise",
            description: "Annual-contract platform plan for large organizations",
            price_monthly: 300_000,
            price_yearly: 3_000_000,
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

// ---------------------------------------------------------------------------
// Database helpers
// ---------------------------------------------------------------------------

/// Upsert a plan seed into the database.
pub async fn upsert_plan(pool: &PgPool, seed: &PlanSeed) -> Result<Plan, sqlx::Error> {
    let input = PlanUpsertInput {
        name: seed.name.to_string(),
        display_name: seed.display_name.to_string(),
        description: seed.description.to_string(),
        price_monthly: seed.price_monthly,
        price_yearly: seed.price_yearly,
        email_limit: seed.email_limit,
        api_call_limit: seed.api_call_limit,
        sort_order: seed.sort_order,
        features: seed.features.clone(),
        stripe_price_id_monthly: None,
        stripe_price_id_yearly: None,
    };

    upsert_plan_input(pool, &input).await
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
pub async fn get_quota_for_tenant(
    pool: &PgPool,
    tenant_id: &str,
) -> Result<Option<QuotaLimit>, sqlx::Error> {
    let row: Option<TenantPlanRow> = sqlx::query_as(
        r#"
        SELECT
            t.id    as tenant_id,
            t.plan  as plan_name,
            p.email_limit,
            p.api_call_limit,
            p.features
        FROM tenants t
        LEFT JOIN plans p ON t.plan = p.name
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

/// Calculate overage cost in cents.
/// `€0.40 / 1 000 emails = 0.04 cents / email`
pub fn calculate_overage_cost(emails_sent: i64, email_limit: i64) -> i64 {
    if email_limit < 0 {
        return 0; // unlimited
    }
    if emails_sent <= email_limit {
        return 0;
    }
    let overage = emails_sent - email_limit;
    // 0.04 cents per email → ceil(overage * 4 / 100)
    // Use i128 intermediate arithmetic to prevent overflow for values near i64::MAX/4.
    ((overage as i128).saturating_mul(4).saturating_add(99) / 100) as i64
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
            (30_000, 300_000)
        );
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
