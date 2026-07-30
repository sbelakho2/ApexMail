use chrono::{DateTime, NaiveDate, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntitlementResponse {
    pub active_plan: String,
    pub contract_start: Option<NaiveDate>,
    pub contract_end: Option<NaiveDate>,
    pub monthly_message_allowance: i64,
    pub current_usage: i64,
    pub overage_rate_cents_per_1000: i64,
    pub daily_send_limit: Option<i64>,
    pub hourly_burst_limit: Option<i64>,
    pub sending_domain_limit: i32,
    pub user_limit: i32,
    pub api_key_limit: i32,
    pub smtp_credential_limit: i32,
    pub template_limit: i32,
    pub webhook_endpoint_limit: i32,
    pub event_retention_days: i32,
    pub message_content_retention_days: i32,
    pub attachment_limit_mb: i32,
    pub batch_limit: i32,
    pub scheduling_horizon_days: i32,
    pub inbound_email: bool,
    pub inbox_placement_credits: i32,
    pub grader_credits: i32,
    pub subaccount_limit: i32,
    pub audit_logs: bool,
    pub sso_enabled: bool,
    pub scim_enabled: bool,
    pub dedicated_ip_entitlement: i32,
    pub support_target_hours: Option<u32>,
    pub sla_eligible: bool,
    pub dpa_available: bool,
    pub baa_review_eligible: bool,
    pub dedicated_tenancy_eligible: bool,
    pub byoc_eligible: bool,

    pub discount_type: Option<String>,
    pub discount_percentage: Option<f64>,
    pub founding_customer: bool,
    pub startup_program: bool,
    pub contract_override: bool,
    pub expiring_entitlements_at: Option<DateTime<Utc>>,
    pub suspended: bool,
    pub trial_or_beta: bool,
}

#[derive(sqlx::FromRow)]
struct TenantEntitlementRow {
    tenant_id: String,
    plan_name: String,
    status: String,
    email_limit: Option<i64>,
    api_call_limit: Option<i64>,
    features: Option<serde_json::Value>,
    contract_start: Option<NaiveDate>,
    contract_end: Option<NaiveDate>,
    discount_type: Option<String>,
    discount_percentage: Option<f64>,
    founding_customer: Option<bool>,
    startup_program: Option<bool>,
    contract_override: Option<bool>,
    expiring_at: Option<DateTime<Utc>>,
    trial: Option<bool>,
}

#[derive(sqlx::FromRow)]
struct UsageRow {
    current_usage: Option<i64>,
}

pub async fn get_tenant_entitlements(
    pool: &PgPool,
    tenant_id: &str,
) -> Result<EntitlementResponse, anyhow::Error> {
    let row: Option<TenantEntitlementRow> = sqlx::query_as(
        r#"
        SELECT
            t.id               AS tenant_id,
            t.plan             AS plan_name,
            COALESCE(t.status, 'active') AS status,
            p.email_limit,
            p.api_call_limit,
            p.features,
            s.contract_start,
            s.contract_end,
            d.discount_type,
            d.discount_percentage,
            d.founding_customer,
            d.startup_program,
            d.contract_override,
            d.expiring_at,
            d.trial_or_beta AS trial
        FROM tenants t
        LEFT JOIN plans p ON t.plan = p.name
        LEFT JOIN subscription_contracts s ON s.tenant_id = t.id
        LEFT JOIN plan_discounts d ON d.tenant_id = t.id
        WHERE t.id = $1
        "#,
    )
    .bind(tenant_id)
    .fetch_optional(pool)
    .await?;

    let Some(row) = row else {
        return Err(anyhow::anyhow!("Tenant {tenant_id} not found"));
    };

    let suspended = row.status == "suspended";
    let trial_or_beta = row.trial.unwrap_or(false);

    let usage: UsageRow = sqlx::query_as(
        r#"
        SELECT COUNT(*)::bigint AS current_usage
        FROM messages
        WHERE tenant_id = $1
          AND created_at >= date_trunc('month', NOW())
        "#,
    )
    .bind(tenant_id)
    .fetch_one(pool)
    .await?;

    let features: serde_json::Value = row.features.unwrap_or_default();

    let domain_limit = features["max_sending_domains"]
        .as_i64()
        .unwrap_or(1) as i32;
    let user_limit = features["max_team_members"]
        .as_i64()
        .unwrap_or(1) as i32;
    let event_retention = features["max_retention_days"]
        .as_i64()
        .unwrap_or(7) as i32;
    let content_retention = features["max_retention_days"]
        .as_i64()
        .unwrap_or(1) as i32;
    let sso = features["sso_enabled"].as_bool().unwrap_or(false);
    let audit = features["audit_logs"].as_bool().unwrap_or(false);
    let dedicated_ips = features["dedicated_ip_count"]
        .as_i64()
        .unwrap_or(0) as i32;
    let subaccounts = features["max_subaccounts"]
        .as_i64()
        .unwrap_or(0) as i32;
    let sla = features["sla_guarantee"].as_bool().unwrap_or(false);
    let inbound = features["inbound_email"].as_bool().unwrap_or(false);

    let support_target = match row.plan_name.as_str() {
        "free" | "developer" => Some(48u32),
        "pro" | "growth" => Some(24),
        "business" => Some(8),
        "enterprise" => Some(4),
        _ => None,
    };

    let overage_rate = match row.plan_name.as_str() {
        "free" => 0,
        "developer" => 80,
        "pro" => 60,
        "growth" => 35,
        "business" => 35,
        "enterprise" => 35,
        _ => 40,
    };

    let api_key_limit: i32 = match row.plan_name.as_str() {
        "free" => 2,
        "developer" => 5,
        "pro" => 10,
        "growth" => 20,
        "business" => 50,
        "enterprise" => -1,
        _ => 5,
    };

    let smtp_credential_limit: i32 = match row.plan_name.as_str() {
        "free" => 1,
        "developer" => 3,
        "pro" => 5,
        "growth" => 10,
        "business" => 25,
        "enterprise" => -1,
        _ => 3,
    };

    let template_limit: i32 = match row.plan_name.as_str() {
        "free" => 5,
        "developer" => 25,
        "pro" => 100,
        "growth" => 250,
        "business" => -1,
        "enterprise" => -1,
        _ => 25,
    };

    let webhook_limit: i32 = match row.plan_name.as_str() {
        "free" => 0,
        "developer" => 3,
        "pro" => 5,
        "growth" => 10,
        "business" => 25,
        "enterprise" => 50,
        _ => 3,
    };

    let attachment_limit_mb: i32 = match row.plan_name.as_str() {
        "free" => 5,
        "developer" | "pro" => 25,
        "growth" | "business" => 50,
        "enterprise" => 100,
        _ => 25,
    };

    let batch_limit: i32 = match row.plan_name.as_str() {
        "free" => 10,
        "developer" => 500,
        "pro" => 1_000,
        "growth" => 5_000,
        "business" => 10_000,
        "enterprise" => -1,
        _ => 500,
    };

    let daily_send = match row.plan_name.as_str() {
        "free" => Some(100i64),
        "developer" => Some(5_000),
        "pro" => Some(15_000),
        _ => None,
    };

    let burst_limit = match row.plan_name.as_str() {
        "free" => Some(10i64),
        "developer" => Some(100),
        "pro" => Some(500),
        _ => None,
    };

    Ok(EntitlementResponse {
        active_plan: row.plan_name.clone(),
        contract_start: row.contract_start,
        contract_end: row.contract_end,
        monthly_message_allowance: row.email_limit.unwrap_or(0),
        current_usage: usage.current_usage.unwrap_or(0),
        overage_rate_cents_per_1000: overage_rate,
        daily_send_limit: daily_send,
        hourly_burst_limit: burst_limit,
        sending_domain_limit: domain_limit,
        user_limit,
        api_key_limit,
        smtp_credential_limit,
        template_limit,
        webhook_endpoint_limit: webhook_limit,
        event_retention_days: event_retention,
        message_content_retention_days: content_retention,
        attachment_limit_mb,
        batch_limit,
        scheduling_horizon_days: 30,
        inbound_email: inbound,
        inbox_placement_credits: 0,
        grader_credits: 0,
        subaccount_limit: subaccounts,
        audit_logs: audit,
        sso_enabled: sso,
        scim_enabled: row.plan_name.as_str() == "enterprise",
        dedicated_ip_entitlement: dedicated_ips,
        support_target_hours: support_target,
        sla_eligible: sla,
        dpa_available: true,
        baa_review_eligible: matches!(row.plan_name.as_str(), "enterprise"),
        dedicated_tenancy_eligible: matches!(row.plan_name.as_str(), "enterprise"),
        byoc_eligible: matches!(row.plan_name.as_str(), "enterprise"),
        discount_type: row.discount_type,
        discount_percentage: row.discount_percentage,
        founding_customer: row.founding_customer.unwrap_or(false),
        startup_program: row.startup_program.unwrap_or(false),
        contract_override: row.contract_override.unwrap_or(false),
        expiring_entitlements_at: row.expiring_at,
        suspended,
        trial_or_beta,
    })
}
