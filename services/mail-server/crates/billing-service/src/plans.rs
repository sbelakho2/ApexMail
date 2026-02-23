//! Plan definitions and quota management.
//!
//! Mirrors the plans defined in `apps/billing/src/services/plans.ts` –
//! free / starter / pro / growth / scale / enterprise / payg.

use chrono::Utc;
use sqlx::PgPool;
use uuid::Uuid;

use crate::types::{Plan, PlanFeatures, QuotaLimit, RateLimitTier, SupportLevel};

/// Static seed data for default plans.
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

/// All default plans shipped with ApexMail.
pub fn default_plans() -> Vec<PlanSeed> {
    vec![
        PlanSeed {
            name: "free",
            display_name: "Free",
            description: "Get started with basic email sending",
            price_monthly: 0,
            price_yearly: 0,
            email_limit: 3_000,
            api_call_limit: 50_000,
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
        },
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
                api_access: true,
                webhooks_enabled: true,
                advanced_analytics: true,
                send_time_optimization: true,
                ab_testing: true,
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
                support_level: SupportLevel::Priority,
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
                support_level: SupportLevel::Phone,
                ..PlanFeatures::default()
            },
        },
        PlanSeed {
            name: "enterprise",
            display_name: "Enterprise",
            description: "Custom solutions for large organizations",
            price_monthly: 80_000,
            price_yearly: 800_000,
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
                byoip: true,
                sla_guarantee: true,
                sla_credit_percentage: 25,
                hipaa_compliance: true,
                soc2_compliance: true,
                private_cloud: true,
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

// ---------------------------------------------------------------------------
// Database helpers
// ---------------------------------------------------------------------------

/// Upsert a plan seed into the database.
pub async fn upsert_plan(pool: &PgPool, seed: &PlanSeed) -> Result<Plan, sqlx::Error> {
    let features_json = serde_json::to_value(&seed.features).unwrap_or_default();
    let now = Utc::now();

    let row: PlanRow = sqlx::query_as(
        r#"
        INSERT INTO plans (
            id, name, display_name, description,
            price_monthly, price_yearly, email_limit, api_call_limit,
            features, is_active, sort_order, created_at, updated_at
        ) VALUES (
            gen_random_uuid(), $1, $2, $3,
            $4, $5, $6, $7,
            $8, true, $9, $10, $10
        )
        ON CONFLICT (name) DO UPDATE SET
            display_name  = EXCLUDED.display_name,
            description   = EXCLUDED.description,
            price_monthly = EXCLUDED.price_monthly,
            price_yearly  = EXCLUDED.price_yearly,
            email_limit   = EXCLUDED.email_limit,
            api_call_limit= EXCLUDED.api_call_limit,
            features      = EXCLUDED.features,
            sort_order    = EXCLUDED.sort_order,
            updated_at    = $10
        RETURNING
            id, name, display_name, description,
            price_monthly, price_yearly, email_limit, api_call_limit,
            features,
            stripe_price_id_monthly, stripe_price_id_yearly,
            is_active, sort_order, created_at, updated_at
        "#,
    )
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

/// Fetch all active plans ordered by `sort_order`.
pub async fn get_active_plans(pool: &PgPool) -> Result<Vec<Plan>, sqlx::Error> {
    let rows: Vec<PlanRow> = sqlx::query_as(
        r#"
        SELECT
            id, name, display_name, description,
            price_monthly, price_yearly, email_limit, api_call_limit,
            features,
            stripe_price_id_monthly, stripe_price_id_yearly,
            is_active, sort_order, created_at, updated_at
        FROM plans
        WHERE is_active = true
        ORDER BY sort_order ASC
        LIMIT 100
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
            features,
            stripe_price_id_monthly, stripe_price_id_yearly,
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

/// Derive quota/rate-limit info for a tenant from their current plan.
pub async fn get_quota_for_tenant(
    pool: &PgPool,
    tenant_id: Uuid,
) -> Result<Option<QuotaLimit>, sqlx::Error> {
    let row: Option<TenantPlanRow> = sqlx::query_as(
        r#"
        SELECT
            t.id    as tenant_id,
            p.name  as plan_name,
            p.email_limit,
            p.api_call_limit,
            p.features
        FROM tenants t
        JOIN plans p ON t.plan = p.name
        WHERE t.id = $1
        "#,
    )
    .bind(tenant_id)
    .fetch_optional(pool)
    .await?;

    let Some(row) = row else { return Ok(None) };

    let features: PlanFeatures = serde_json::from_value(
        row.features.unwrap_or_default(),
    )
    .unwrap_or_default();

    let tier = match row.plan_name.as_str() {
        "free" => RateLimitTier::Free,
        "starter" | "pro" | "payg" => RateLimitTier::Standard,
        "growth" | "scale" => RateLimitTier::High,
        "enterprise" => RateLimitTier::Unlimited,
        _ => RateLimitTier::Standard,
    };

    Ok(Some(QuotaLimit {
        tenant_id: row.tenant_id,
        plan_name: row.plan_name,
        emails_per_month: row.email_limit,
        api_calls_per_month: row.api_call_limit,
        max_sending_domains: features.max_sending_domains,
        max_team_members: features.max_team_members,
        max_subaccounts: features.max_subaccounts,
        rate_limit_tier: tier,
    }))
}

/// Calculate overage cost in cents.
/// `$0.40 / 1 000 emails = 0.04 cents / email`
pub fn calculate_overage_cost(emails_sent: i64, email_limit: i64) -> i64 {
    if email_limit < 0 {
        return 0; // unlimited
    }
    if emails_sent <= email_limit {
        return 0;
    }
    let overage = emails_sent - email_limit;
    // 0.04 cents per email → multiply then ceil
    ((overage as f64) * 0.04).ceil() as i64
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
    tenant_id: Uuid,
    plan_name: String,
    email_limit: i64,
    api_call_limit: i64,
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
    fn overage_unlimited_is_zero() {
        assert_eq!(calculate_overage_cost(999_999, -1), 0);
    }

    #[test]
    fn overage_within_limit() {
        assert_eq!(calculate_overage_cost(3_000, 3_000), 0);
    }

    #[test]
    fn overage_above_limit() {
        // 1 000 overage emails * 0.04 cents = 40 cents
        assert_eq!(calculate_overage_cost(4_000, 3_000), 40);
    }

    #[test]
    fn enterprise_has_all_premium_features() {
        let plans = default_plans();
        let ent = plans.iter().find(|p| p.name == "enterprise").unwrap();
        assert!(ent.features.sso_enabled);
        assert!(ent.features.hipaa_compliance);
        assert!(ent.features.private_cloud);
        assert_eq!(ent.features.support_level, SupportLevel::Dedicated);
    }
}
