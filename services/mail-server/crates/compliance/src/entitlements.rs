//! Tenant entitlement snapshot derived from the authoritative billing
//! model — the same tables api-server and billing-service compute with:
//!
//! - effective plan: `tenants.plan`, overridden by an active, unexpired
//!   `plan_overrides` row, joined to `plans` for limits/features
//!   (mirrors billing-service `TENANT_PLAN_LIMITS_SQL`, migrations
//!   069/093/098 — producers: api-server billing admin routes);
//! - contract window: `enterprise_contracts` active period
//!   (migration 022 — producers: enterprise contracts + billing admin);
//! - subscription state: `stripe_subscriptions` (producer: billing-service
//!   stripe webhooks);
//! - monthly usage: `metering_events` `emails_sent` month-to-date — the
//!   same counter the quota-enforcement path (`record_with_quota_check`)
//!   charges.
//!
//! F61: the previous version joined `subscription_contracts` and
//! `plan_discounts`, which have no migration and no producer — the helper
//! could never answer a request. Every table read here has a producer.

use chrono::{DateTime, NaiveDate, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;

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
    /// Selected to preserve the row anchor used by the authoritative
    /// limits statement (billing-service TENANT_PLAN_LIMITS_SQL).
    #[expect(
        dead_code,
        reason = "tenant_id is selected to mirror the authoritative limits SQL"
    )]
    tenant_id: String,
    plan_name: String,
    /// An active, unexpired plan override applies to this tenant.
    has_override: bool,
    override_expires_at: Option<DateTime<Utc>>,
    status: String,
    email_limit: Option<i64>,
    /// Selected alongside email_limit for parity with the authoritative
    /// limits statement; the response surface only exposes email allowance.
    #[expect(
        dead_code,
        reason = "api_call_limit is selected to mirror the authoritative limits SQL"
    )]
    api_call_limit: Option<i64>,
    features: Option<serde_json::Value>,
    contract_start: Option<NaiveDate>,
    contract_end: Option<NaiveDate>,
    /// `enterprise_contracts.annual_prepay_discount` (percent, 0 = none).
    annual_prepay_discount: Option<i32>,
    /// Latest stripe subscription status (NULL when never subscribed).
    stripe_status: Option<String>,
}

/// Effective-plan + contract + subscription lookup. Mirrors billing-service
/// `TENANT_PLAN_LIMITS_SQL` (usage.rs): an active, unexpired override wins
/// over the tenant's own plan. $1 = tenant_id.
const TENANT_ENTITLEMENT_SQL: &str = r#"
        SELECT
            t.id                                AS tenant_id,
            COALESCE(po.plan, t.plan)           AS plan_name,
            (po.id IS NOT NULL)                 AS has_override,
            po.expires_at                       AS override_expires_at,
            COALESCE(t.status, 'active')        AS status,
            p.email_limit,
            p.api_call_limit,
            p.features,
            ec.start_date::date                 AS contract_start,
            ec.end_date::date                   AS contract_end,
            ec.annual_prepay_discount,
            ss.status                           AS stripe_status
        FROM tenants t
        LEFT JOIN plan_overrides po
               ON po.tenant_id = t.id
              AND po.active = true
              AND (po.expires_at IS NULL OR po.expires_at > NOW())
        LEFT JOIN plans p ON p.name = COALESCE(po.plan, t.plan)
        LEFT JOIN LATERAL (
            SELECT start_date, end_date, annual_prepay_discount
            FROM enterprise_contracts
            WHERE tenant_id = t.id
              AND status = 'active'
              AND start_date <= NOW()
              AND end_date > NOW()
            ORDER BY end_date DESC
            LIMIT 1
        ) ec ON true
        LEFT JOIN LATERAL (
            SELECT status
            FROM stripe_subscriptions
            WHERE tenant_id = t.id
            ORDER BY updated_at DESC
            LIMIT 1
        ) ss ON true
        WHERE t.id = $1
        "#;

/// Month-to-date `emails_sent` usage — the same metering counter the
/// quota-enforcement path charges (billing-service usage.rs). $1 = tenant.
const TENANT_USAGE_SQL: &str = r#"
        SELECT COALESCE(SUM(quantity), 0)::bigint AS current_usage
        FROM metering_events
        WHERE tenant_id = $1
          AND event_type = 'emails_sent'
          AND timestamp >= date_trunc('month', NOW())
        "#;

/// Map the active contract's annual-prepay discount onto the response
/// fields. Only real, producer-backed discounts surface here — the legacy
/// `plan_discounts` notions (founding customer, startup program) have no
/// source and report `false` rather than invented values.
fn contract_discount(annual_prepay_discount: Option<i32>) -> (Option<String>, Option<f64>) {
    match annual_prepay_discount {
        Some(pct) if pct > 0 => (Some("annual_prepay".to_string()), Some(pct as f64)),
        _ => (None, None),
    }
}

pub async fn get_tenant_entitlements(
    pool: &PgPool,
    tenant_id: &str,
) -> Result<EntitlementResponse, anyhow::Error> {
    let row: Option<TenantEntitlementRow> = sqlx::query_as(TENANT_ENTITLEMENT_SQL)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await?;

    let Some(row) = row else {
        return Err(anyhow::anyhow!("Tenant {tenant_id} not found"));
    };

    let suspended = row.status == "suspended";
    let trial_or_beta = row.stripe_status.as_deref() == Some("trialing");

    let usage: (i64,) = sqlx::query_as(TENANT_USAGE_SQL)
        .bind(tenant_id)
        .fetch_one(pool)
        .await?;

    let features: serde_json::Value = row.features.unwrap_or_default();

    let domain_limit = features["max_sending_domains"].as_i64().unwrap_or(1) as i32;
    let user_limit = features["max_team_members"].as_i64().unwrap_or(1) as i32;
    let event_retention = features["max_retention_days"].as_i64().unwrap_or(7) as i32;
    let content_retention = features["max_retention_days"].as_i64().unwrap_or(1) as i32;
    let sso = features["sso_enabled"].as_bool().unwrap_or(false);
    let audit = features["audit_logs"].as_bool().unwrap_or(false);
    let dedicated_ips = features["dedicated_ip_count"].as_i64().unwrap_or(0) as i32;
    let subaccounts = features["max_subaccounts"].as_i64().unwrap_or(0) as i32;
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

    let (discount_type, discount_percentage) = contract_discount(row.annual_prepay_discount);

    // Expiring entitlements: the plan override's expiry timestamp. The
    // active contract's end date is surfaced separately via `contract_end`.
    let expiring_entitlements_at = row.override_expires_at;

    Ok(EntitlementResponse {
        active_plan: row.plan_name.clone(),
        contract_start: row.contract_start,
        contract_end: row.contract_end,
        // Authoritative allowance: the effective plan's email limit (the
        // override path swaps the plan rather than patching the number).
        monthly_message_allowance: row.email_limit.unwrap_or(0),
        current_usage: usage.0,
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
        discount_type,
        discount_percentage,
        // No producer-backed source for these legacy plan_discounts flags.
        founding_customer: false,
        startup_program: false,
        // An active plan override is the real "contract override" signal.
        contract_override: row.has_override,
        expiring_entitlements_at,
        suspended,
        trial_or_beta,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entitlement_sql_resolves_effective_plan_via_overrides() {
        // Authoritative pattern (billing-service TENANT_PLAN_LIMITS_SQL):
        // an active, unexpired override wins over tenants.plan.
        assert!(TENANT_ENTITLEMENT_SQL.contains("plan_overrides po"));
        assert!(TENANT_ENTITLEMENT_SQL.contains("po.active = true"));
        assert!(TENANT_ENTITLEMENT_SQL.contains("po.expires_at > NOW()"));
        assert!(TENANT_ENTITLEMENT_SQL.contains("COALESCE(po.plan, t.plan)"));
    }

    #[test]
    fn entitlement_sql_reads_only_producer_backed_tables() {
        for table in [
            "tenants t",
            "plan_overrides po",
            "plans p",
            "enterprise_contracts",
            "stripe_subscriptions",
        ] {
            assert!(
                TENANT_ENTITLEMENT_SQL.contains(table),
                "expected entitlement source {table}"
            );
        }
        // F61: the absent, producer-less tables must be gone.
        assert!(!TENANT_ENTITLEMENT_SQL.contains("subscription_contracts"));
        assert!(!TENANT_ENTITLEMENT_SQL.contains("plan_discounts"));
    }

    #[test]
    fn entitlement_contract_window_requires_active_period() {
        assert!(TENANT_ENTITLEMENT_SQL.contains("status = 'active'"));
        assert!(TENANT_ENTITLEMENT_SQL.contains("start_date <= NOW()"));
        assert!(TENANT_ENTITLEMENT_SQL.contains("end_date > NOW()"));
    }

    #[test]
    fn usage_sql_reads_canonical_metering_counter() {
        // Same counter the quota-enforcement path charges.
        assert!(TENANT_USAGE_SQL.contains("FROM metering_events"));
        assert!(TENANT_USAGE_SQL.contains("event_type = 'emails_sent'"));
        assert!(TENANT_USAGE_SQL.contains("date_trunc('month', NOW())"));
        assert!(!TENANT_USAGE_SQL.contains("FROM messages"));
    }

    #[test]
    fn contract_discount_maps_active_prepay_only() {
        assert_eq!(contract_discount(None), (None, None));
        assert_eq!(contract_discount(Some(0)), (None, None));
        assert_eq!(contract_discount(Some(-5)), (None, None));
        let (kind, pct) = contract_discount(Some(20));
        assert_eq!(kind.as_deref(), Some("annual_prepay"));
        assert_eq!(pct, Some(20.0));
    }
}
