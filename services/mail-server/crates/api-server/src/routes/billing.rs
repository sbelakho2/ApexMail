//! Public billing routes served by api-server.

use axum::extract::{Path, Query, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use billing_common::proration;
use billing_service::{
    config::{BillingConfig, PaygPricing},
    plans,
    types::{BillingInterval, MeterEventType, Plan, PlanFeatures},
    usage,
};
use chrono::{Datelike, Months, NaiveTime, Utc};
use deadpool_redis::redis::AsyncCommands;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
// Unconditional: `invoice_style_nonce` (H-6 CSP nonces) hashes in production
// code, not only under cfg(test).
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::error::{success, ApiError, ApiResponse};
use crate::middleware::auth::AuthUser;
use crate::routes::helpers::hash_token;
use crate::state::AppState;

const MINIMUM_MONTHLY_CHARGE_CENTS: i64 = 0;
const SELF_SERVE_CHECKOUT_PLAN_IDS: [&str; 4] = ["starter", "pro", "growth", "scale"];
const DEFAULT_BILLING_CURRENCY: &str = "EUR";
const DEFAULT_NET_DAYS: i64 = 30;
const USAGE_QUERY_CACHE_TTL_SECONDS: u64 = 30;
/// How long an admin-credit Idempotency-Key stays claimed in Redis (F6).
/// 48 h comfortably exceeds any reasonable retry window for an operator
/// action while still allowing key reuse after that period.
const ADMIN_CREDIT_IDEMPOTENCY_TTL_SECS: u64 = 48 * 60 * 60;
const BILLING_COMPANY_NAME: &str = "Bel Consulting OÜ";
const BILLING_COMPANY_TRADING_AS: &str = "ApexMail";
const BILLING_COMPANY_STREET: &str = "Sakala 7-2";
const BILLING_COMPANY_CITY: &str = "Tallinn";
const BILLING_COMPANY_POSTAL_CODE: &str = "10141";
const BILLING_COMPANY_COUNTRY: &str = "Estonia";
const BILLING_COMPANY_REGISTRY_CODE: &str = "16588745";
const BILLING_COMPANY_VAT_NUMBER: &str = "EE102951727";
const BILLING_COMPANY_BILLING_EMAIL: &str = "billing@apexmail.ee";
const BILLING_COMPANY_BANK_NAME: &str = "Wise";

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/plans", get(list_plans))
        .route("/plans/tenant/current", get(get_current_plan))
        .route("/plans/features/:feature", get(get_plan_feature))
        .route("/plans/tenant/features", get(get_plan_features))
        .route("/plans/tenant/limits", get(get_plan_limits))
        .route("/plans/compare/:planId1/:planId2", get(compare_plans))
        .route("/plans/:planId", get(get_plan))
        .route("/usage", get(get_usage))
        .route("/usage/realtime/:metric", get(get_realtime_usage_counter))
        .route("/payg/pricing", get(get_payg_pricing))
        .route("/payg/estimate", post(estimate_payg_cost))
        .route("/payg/usage", get(get_payg_usage))
        .route("/overage/estimate", post(estimate_overage_cost))
        .route("/alerts", post(configure_usage_alerts))
        .route("/checkout", post(create_checkout_session))
        .route("/portal", post(create_portal_session))
        .route("/proration/:planName", get(get_proration_preview))
        .route("/switch-plan", post(switch_plan))
        .route("/cancel", post(cancel_subscription_request))
        .route("/subscription", get(get_subscription))
        .route("/invoices", get(list_invoices))
        .route("/invoices/:id", get(get_invoice))
        .route("/invoices/:id/pdf", get(get_invoice_pdf_html))
        .route("/invoices/:id/xml", get(get_invoice_xml))
        .route("/quota", get(check_quota))
        .route("/admin/tenants", get(admin_list_tenants))
        .route("/admin/tenants/:tenantId", get(admin_get_tenant_details))
        .route("/admin/tenants/:tenantId/credits", post(admin_apply_credit))
        .route(
            "/admin/tenants/:tenantId/plan-override",
            post(admin_apply_plan_override),
        )
        .route(
            "/admin/tenants/:tenantId/subscription-status",
            post(admin_force_subscription_status),
        )
        .route(
            "/admin/tenants/:tenantId/dunning/reset",
            post(admin_reset_dunning),
        )
        .route(
            "/admin/tenants/:tenantId/invoices",
            post(admin_create_invoice),
        )
        .route("/admin/reports/revenue", get(admin_get_revenue_report))
        .route("/admin/reports/mrr", get(admin_get_mrr_report))
        .route("/admin/reports/churn", get(admin_get_churn_report))
        .route("/admin/reports/dunning", get(admin_get_dunning_report))
        .route("/admin/reports/costs", get(admin_get_cost_report))
        .route("/admin/export", get(admin_export_billing_data))
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct LegacyPlanFeaturesPayload {
    dedicated_ip: bool,
    dedicated_ip_count: i32,
    max_sending_domains: i32,
    sso_enabled: bool,
    audit_logs: bool,
    api_access: bool,
    webhooks_enabled: bool,
    inbound_email: bool,
    advanced_analytics: bool,
    send_time_optimization: bool,
    ab_testing: bool,
    time_travel_debugging: bool,
    data_export: bool,
    custom_tracking_domain: bool,
    custom_templates: bool,
    template_approval_workflow: bool,
    white_label: bool,
    powered_by_footer: bool,
    custom_retention: bool,
    max_retention_days: i32,
    max_team_members: i32,
    subaccounts: bool,
    max_subaccounts: i32,
    support_level: billing_service::types::SupportLevel,
    dedicated_csm: bool,
    priority_onboarding: bool,
    byoip: bool,
    sla_guarantee: bool,
    sla_credit_percentage: i32,
    hipaa_compliance: bool,
    soc2_compliance: bool,
    private_cloud: bool,
}

impl From<PlanFeatures> for LegacyPlanFeaturesPayload {
    fn from(features: PlanFeatures) -> Self {
        Self {
            dedicated_ip: features.dedicated_ip,
            dedicated_ip_count: features.dedicated_ip_count,
            max_sending_domains: features.max_sending_domains,
            sso_enabled: features.sso_enabled,
            audit_logs: features.audit_logs,
            api_access: features.api_access,
            webhooks_enabled: features.webhooks_enabled,
            inbound_email: features.inbound_email,
            advanced_analytics: features.advanced_analytics,
            send_time_optimization: features.send_time_optimization,
            ab_testing: features.ab_testing,
            time_travel_debugging: features.time_travel_debugging,
            data_export: features.data_export,
            custom_tracking_domain: features.custom_tracking_domain,
            custom_templates: features.custom_templates,
            template_approval_workflow: features.template_approval_workflow,
            white_label: features.white_label,
            powered_by_footer: features.powered_by_footer,
            custom_retention: features.custom_retention,
            max_retention_days: features.max_retention_days,
            max_team_members: features.max_team_members,
            subaccounts: features.subaccounts,
            max_subaccounts: features.max_subaccounts,
            support_level: features.support_level,
            dedicated_csm: features.dedicated_csm,
            priority_onboarding: features.priority_onboarding,
            byoip: features.byoip,
            sla_guarantee: features.sla_guarantee,
            sla_credit_percentage: features.sla_credit_percentage,
            hipaa_compliance: features.hipaa_compliance,
            soc2_compliance: features.soc2_compliance,
            private_cloud: features.private_cloud,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct LegacyPlanDto {
    id: uuid::Uuid,
    name: String,
    display_name: String,
    description: String,
    price_monthly: i64,
    price_yearly: i64,
    email_limit: i64,
    api_call_limit: i64,
    features: LegacyPlanFeaturesPayload,
    stripe_price_id_monthly: Option<String>,
    stripe_price_id_yearly: Option<String>,
    is_active: bool,
    sort_order: i32,
    created_at: chrono::DateTime<Utc>,
    updated_at: chrono::DateTime<Utc>,
}

impl From<Plan> for LegacyPlanDto {
    fn from(plan: Plan) -> Self {
        Self {
            id: plan.id,
            name: plan.name,
            display_name: plan.display_name,
            description: plan.description,
            price_monthly: plan.price_monthly,
            price_yearly: plan.price_yearly,
            email_limit: plan.email_limit,
            api_call_limit: plan.api_call_limit,
            features: plan.features.into(),
            stripe_price_id_monthly: plan.stripe_price_id_monthly,
            stripe_price_id_yearly: plan.stripe_price_id_yearly,
            is_active: plan.is_active,
            sort_order: plan.sort_order,
            created_at: plan.created_at,
            updated_at: plan.updated_at,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct LegacyPlanLimitsDto {
    email_limit: i64,
    api_call_limit: i64,
    features: LegacyPlanFeaturesPayload,
}

impl From<&Plan> for LegacyPlanLimitsDto {
    fn from(plan: &Plan) -> Self {
        Self {
            email_limit: plan.email_limit,
            api_call_limit: plan.api_call_limit,
            features: plan.features.clone().into(),
        }
    }
}

fn feature_map(features: &LegacyPlanFeaturesPayload) -> serde_json::Map<String, serde_json::Value> {
    serde_json::to_value(features)
        .ok()
        .and_then(|value| value.as_object().cloned())
        .unwrap_or_default()
}

fn truthy_json(value: &serde_json::Value) -> bool {
    match value {
        serde_json::Value::Bool(value) => *value,
        serde_json::Value::Number(value) => value
            .as_i64()
            .map(|number| number != 0)
            .or_else(|| value.as_u64().map(|number| number != 0))
            .or_else(|| value.as_f64().map(|number| number != 0.0))
            .unwrap_or(false),
        serde_json::Value::String(value) => !value.is_empty(),
        serde_json::Value::Null => false,
        serde_json::Value::Array(value) => !value.is_empty(),
        serde_json::Value::Object(value) => !value.is_empty(),
    }
}

fn feature_has_access(features: &LegacyPlanFeaturesPayload, feature: &str) -> bool {
    feature_map(features)
        .get(feature)
        .map(truthy_json)
        .unwrap_or(false)
}

fn comparison_differences(
    plan1: &LegacyPlanFeaturesPayload,
    plan2: &LegacyPlanFeaturesPayload,
) -> Vec<serde_json::Value> {
    let features1 = feature_map(plan1);
    let features2 = feature_map(plan2);
    let mut keys: Vec<String> = features1.keys().chain(features2.keys()).cloned().collect();
    keys.sort();
    keys.dedup();

    keys.into_iter()
        .filter_map(|feature| {
            let value1 = features1
                .get(&feature)
                .cloned()
                .unwrap_or(serde_json::Value::Bool(false));
            let value2 = features2
                .get(&feature)
                .cloned()
                .unwrap_or(serde_json::Value::Bool(false));
            if value1 == value2 {
                None
            } else {
                Some(serde_json::json!({
                    "feature": feature,
                    "plan1": value1,
                    "plan2": value2,
                }))
            }
        })
        .collect()
}

fn usage_payload(summary: billing_service::types::UsageSummary) -> serde_json::Value {
    let emails_sent = summary.emails_sent.max(0);
    let api_calls = summary.api_calls.max(0);
    let percent_used = if summary.emails_limit > 0 {
        // Integer percentage, rounded half-up — no float round-trip.
        (emails_sent * 100 + summary.emails_limit / 2) / summary.emails_limit
    } else {
        0
    };

    serde_json::json!({
        "tenantId": summary.tenant_id,
        "period": {
            "start": summary.period_start,
            "end": summary.period_end,
        },
        "metrics": summary.metrics,
        "billingCycleUsage": {
            "emailsSent": emails_sent,
            "emailsLimit": summary.emails_limit,
            "apiCalls": api_calls,
            "apiCallsLimit": summary.api_calls_limit,
            "percentUsed": percent_used,
        },
    })
}

fn usage_cache_key(
    tenant_id: &str,
    period_start: chrono::DateTime<Utc>,
    period_end: chrono::DateTime<Utc>,
    namespace: &str,
) -> String {
    format!(
        "billing:usage-query:{namespace}:{tenant_id}:{}:{}",
        period_start.timestamp(),
        period_end.timestamp()
    )
}

fn map_usage_error(error: usage::UsageError) -> ApiError {
    match error {
        usage::UsageError::Db(db_error) => ApiError::from(db_error),
        usage::UsageError::Audit(audit_error) => ApiError::Internal(audit_error),
        usage::UsageError::Redis(pool_error) => ApiError::from(pool_error),
        usage::UsageError::RedisCmd(redis_error) => ApiError::from(redis_error),
        usage::UsageError::InvalidQuantity(quantity) => {
            ApiError::BadRequest(format!("usage quantity must be positive, got {quantity}"))
        }
    }
}

async fn cached_usage_payload_for_period(
    state: &AppState,
    tenant_id: &str,
    period_start: chrono::DateTime<Utc>,
    period_end: chrono::DateTime<Utc>,
    namespace: &str,
) -> Result<serde_json::Value, ApiError> {
    let cache_key = usage_cache_key(tenant_id, period_start, period_end, namespace);

    if let Ok(mut conn) = state.redis.get().await {
        let cached: Result<Option<String>, _> = conn.get(&cache_key).await;
        if let Ok(Some(cached)) = cached {
            if let Ok(payload) = serde_json::from_str(&cached) {
                return Ok(payload);
            }
        }
    }

    let summary = usage::get_usage(&state.db, tenant_id, period_start, period_end)
        .await
        .map_err(map_usage_error)?;
    let payload = usage_payload(summary);

    if let Ok(serialized) = serde_json::to_string(&payload) {
        if let Ok(mut conn) = state.redis.get().await {
            let _: Result<(), _> = conn
                .set_ex(&cache_key, serialized, USAGE_QUERY_CACHE_TTL_SECONDS)
                .await;
        }
    }

    Ok(payload)
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "camelCase")]
struct PaygEstimateBody {
    emails_sent: i64,
    #[serde(default)]
    api_calls: i64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "camelCase")]
struct OverageEstimateBody {
    emails_sent: i64,
    email_limit: i64,
    /// Optional tenant for server-side limit recomputation. When present the
    /// client-supplied email_limit is ignored — the server resolves the
    /// tenant's override-aware plan limit (mirror of billing-service Fix
    /// I13; plan limits are published pricing, not tenant secrets).
    #[serde(default)]
    tenant_id: Option<String>,
}

#[derive(Debug, Clone)]
struct RouteSubscription {
    plan_name: String,
    billing_interval: BillingInterval,
    current_period_start: chrono::DateTime<Utc>,
    current_period_end: chrono::DateTime<Utc>,
}

#[derive(sqlx::FromRow)]
struct RouteSubscriptionRow {
    plan_name: String,
    billing_interval: String,
    current_period_start: chrono::DateTime<Utc>,
    current_period_end: chrono::DateTime<Utc>,
}

impl RouteSubscriptionRow {
    fn into_subscription(self) -> RouteSubscription {
        RouteSubscription {
            plan_name: self.plan_name,
            billing_interval: parse_billing_interval(&self.billing_interval),
            current_period_start: self.current_period_start,
            current_period_end: self.current_period_end,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct LegacyProrationDto {
    credit_amount: i64,
    charge_amount: i64,
    net_amount: i64,
    current_plan_days_remaining: i64,
    new_plan_days_in_period: i64,
    effective_date: chrono::DateTime<Utc>,
    explanation: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    warnings: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "camelCase")]
struct LegacySwitchPlanBody {
    plan_name: String,
    #[serde(default = "default_billing_interval")]
    billing_interval: BillingInterval,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "camelCase")]
struct LegacyCancelBody {
    reason: Option<String>,
    feedback: Option<String>,
    #[serde(default)]
    cancel_immediately: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BillingListQuery {
    limit: Option<i64>,
    offset: Option<i64>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct UsageAlertThresholdDto {
    id: String,
    tenant_id: String,
    metric_type: String,
    threshold_percent: i32,
    notification_channel: String,
    is_enabled: bool,
    last_triggered_at: Option<chrono::DateTime<Utc>>,
}

#[derive(sqlx::FromRow)]
struct UsageAlertThresholdRow {
    id: String,
    tenant_id: String,
    metric_type: String,
    threshold_percent: i32,
    notification_channel: String,
    enabled: bool,
    last_triggered_at: Option<chrono::DateTime<Utc>>,
}

impl From<UsageAlertThresholdRow> for UsageAlertThresholdDto {
    fn from(row: UsageAlertThresholdRow) -> Self {
        Self {
            id: row.id,
            tenant_id: row.tenant_id,
            metric_type: row.metric_type,
            threshold_percent: row.threshold_percent,
            notification_channel: row.notification_channel,
            is_enabled: row.enabled,
            last_triggered_at: row.last_triggered_at,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "camelCase")]
struct UsageAlertThresholdInput {
    metric_type: String,
    threshold_percent: i32,
    notification_channel: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "camelCase")]
struct UsageAlertThresholdsBody {
    thresholds: Vec<UsageAlertThresholdInput>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "camelCase")]
struct CheckoutSessionBody {
    price_id: String,
    success_url: String,
    cancel_url: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "camelCase")]
struct PortalSessionBody {
    return_url: String,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct TenantStripeSettings {
    billing_email: Option<String>,
    default_from_email: Option<String>,
}

#[derive(Debug, Deserialize)]
struct StripeCustomerResponse {
    id: String,
}

#[derive(Debug, Deserialize)]
struct StripeCheckoutSessionResponse {
    id: String,
    url: Option<String>,
}

#[derive(Debug, Deserialize)]
struct StripePortalSessionResponse {
    url: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DateRangeQuery {
    start_date: Option<String>,
    end_date: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct BillingExportQuery {
    #[serde(rename = "type")]
    export_type: Option<String>,
    start_date: Option<String>,
    end_date: Option<String>,
    #[serde(default = "default_export_format")]
    format: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AdminTenantListQuery {
    limit: Option<i64>,
    offset: Option<i64>,
    status: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "camelCase")]
struct AdminCreditBody {
    amount: i64,
    reason: String,
    // Accepted for API compatibility (camelCase `expiresAt` in the request
    // body must keep deserializing under deny_unknown_fields) even though
    // the credit-granting handler does not read it.
    #[allow(dead_code)]
    expires_at: Option<String>,
    // F6: idempotency now comes from the required Idempotency-Key header;
    // the body field is only still accepted so old request payloads keep
    // deserializing under deny_unknown_fields.
    #[allow(dead_code)]
    idempotency_key: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "camelCase")]
struct AdminPlanOverrideBody {
    plan_id: String,
    reason: String,
    expires_at: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AdminSubscriptionStatusBody {
    status: String,
    reason: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AdminDunningResetBody {
    reason: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "camelCase")]
struct AdminInvoiceLineItemInput {
    description: String,
    quantity: i64,
    unit_price: i64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "camelCase")]
struct AdminCreateInvoiceBody {
    period_start: String,
    period_end: String,
    line_items: Vec<AdminInvoiceLineItemInput>,
    notes: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct LegacyWalletBalanceDto {
    tenant_id: String,
    balance: i64,
    reserved_balance: i64,
    available_balance: i64,
    currency: String,
    updated_at: chrono::DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct LegacyDunningStateDto {
    tenant_id: String,
    status: String,
    failed_payment_count: i64,
    first_failed_at: Option<chrono::DateTime<Utc>>,
    last_failed_at: Option<chrono::DateTime<Utc>>,
    next_retry_at: Option<chrono::DateTime<Utc>>,
    suspended_at: Option<chrono::DateTime<Utc>>,
    queued_messages_count: i64,
    grace_period_ends_at: Option<chrono::DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct LegacyWalletTransactionDto {
    id: String,
    tenant_id: String,
    #[serde(rename = "type")]
    transaction_type: String,
    amount: i64,
    balance: i64,
    description: String,
    reference: Option<String>,
    metadata: serde_json::Value,
    created_at: chrono::DateTime<Utc>,
}

#[derive(sqlx::FromRow)]
struct LegacyWalletTransactionRow {
    id: String,
    tenant_id: String,
    transaction_type: String,
    amount: i64,
    balance: i64,
    description: String,
    reference: Option<String>,
    metadata: serde_json::Value,
    created_at: chrono::DateTime<Utc>,
}

impl From<LegacyWalletTransactionRow> for LegacyWalletTransactionDto {
    fn from(row: LegacyWalletTransactionRow) -> Self {
        Self {
            id: row.id,
            tenant_id: row.tenant_id,
            transaction_type: row.transaction_type,
            amount: row.amount,
            balance: row.balance,
            description: row.description,
            reference: row.reference,
            metadata: row.metadata,
            created_at: row.created_at,
        }
    }
}

#[derive(sqlx::FromRow)]
struct AdminBillingAddressRow {
    company_name: String,
    vat_number: Option<String>,
    address_line1: String,
    address_line2: Option<String>,
    city: String,
    state: Option<String>,
    postal_code: String,
    country: String,
    email: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct LegacyStripeSubscriptionDto {
    id: String,
    tenant_id: String,
    stripe_subscription_id: String,
    stripe_customer_id: String,
    stripe_price_id: String,
    status: String,
    billing_interval: String,
    billing_cycle_start: chrono::DateTime<Utc>,
    billing_cycle_end: chrono::DateTime<Utc>,
    cancel_at_period_end: bool,
    canceled_at: Option<chrono::DateTime<Utc>>,
    trial_end: Option<chrono::DateTime<Utc>>,
    created_at: chrono::DateTime<Utc>,
    updated_at: chrono::DateTime<Utc>,
}

#[derive(sqlx::FromRow)]
struct LegacyStripeSubscriptionRow {
    id: String,
    tenant_id: String,
    stripe_subscription_id: String,
    stripe_customer_id: String,
    stripe_price_id: String,
    status: String,
    billing_interval: String,
    billing_cycle_start: chrono::DateTime<Utc>,
    billing_cycle_end: chrono::DateTime<Utc>,
    cancel_at_period_end: bool,
    canceled_at: Option<chrono::DateTime<Utc>>,
    trial_end: Option<chrono::DateTime<Utc>>,
    created_at: chrono::DateTime<Utc>,
    updated_at: chrono::DateTime<Utc>,
}

impl From<LegacyStripeSubscriptionRow> for LegacyStripeSubscriptionDto {
    fn from(row: LegacyStripeSubscriptionRow) -> Self {
        Self {
            id: row.id,
            tenant_id: row.tenant_id,
            stripe_subscription_id: row.stripe_subscription_id,
            stripe_customer_id: row.stripe_customer_id,
            stripe_price_id: row.stripe_price_id,
            status: row.status,
            billing_interval: row.billing_interval,
            billing_cycle_start: row.billing_cycle_start,
            billing_cycle_end: row.billing_cycle_end,
            cancel_at_period_end: row.cancel_at_period_end,
            canceled_at: row.canceled_at,
            trial_end: row.trial_end,
            created_at: row.created_at,
            updated_at: row.updated_at,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct LegacyInvoiceLineItemDto {
    description: String,
    quantity: i64,
    unit_price: i64,
    amount: i64,
    vat_rate: f64,
    vat_amount: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct LegacyBillingAddressDto {
    company_name: String,
    vat_number: Option<String>,
    address_line1: String,
    address_line2: Option<String>,
    city: String,
    state: Option<String>,
    postal_code: String,
    country: String,
    email: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct LegacyInvoiceDto {
    id: String,
    tenant_id: String,
    stripe_invoice_id: Option<String>,
    invoice_number: String,
    status: String,
    currency: String,
    subtotal: i64,
    vat_total: i64,
    total: i64,
    line_items: Vec<LegacyInvoiceLineItemDto>,
    billing_address: LegacyBillingAddressDto,
    issued_at: chrono::DateTime<Utc>,
    due_at: chrono::DateTime<Utc>,
    paid_at: Option<chrono::DateTime<Utc>>,
    period_start: chrono::DateTime<Utc>,
    period_end: chrono::DateTime<Utc>,
    purchase_order_number: Option<String>,
    notes: Option<String>,
    pdf_url: Option<String>,
    xml_url: Option<String>,
    created_at: chrono::DateTime<Utc>,
    updated_at: chrono::DateTime<Utc>,
}

#[derive(sqlx::FromRow)]
struct LegacyInvoiceRow {
    id: String,
    tenant_id: String,
    stripe_invoice_id: Option<String>,
    invoice_number: String,
    status: String,
    currency: String,
    subtotal: i64,
    vat_total: i64,
    total: i64,
    line_items: String,
    billing_address: String,
    issued_at: chrono::DateTime<Utc>,
    due_at: chrono::DateTime<Utc>,
    paid_at: Option<chrono::DateTime<Utc>>,
    period_start: chrono::DateTime<Utc>,
    period_end: chrono::DateTime<Utc>,
    purchase_order_number: Option<String>,
    notes: Option<String>,
    pdf_url: Option<String>,
    xml_url: Option<String>,
    created_at: chrono::DateTime<Utc>,
    updated_at: chrono::DateTime<Utc>,
}

fn default_billing_interval() -> BillingInterval {
    BillingInterval::Monthly
}

fn default_export_format() -> String {
    "csv".into()
}

fn validate_usage_alert_metric(metric: &str) -> bool {
    matches!(metric, "emails" | "api_calls" | "storage")
}

fn validate_usage_alert_channel(channel: &str) -> bool {
    matches!(channel, "email" | "webhook" | "both")
}

const DEFAULT_STRIPE_API_VERSION: &str = "2026-04-22.dahlia";

fn stripe_api_base_url() -> String {
    std::env::var("STRIPE_API_BASE_URL").unwrap_or_else(|_| "https://api.stripe.com".into())
}

fn stripe_api_version() -> String {
    std::env::var("STRIPE_API_VERSION")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| DEFAULT_STRIPE_API_VERSION.into())
}

#[derive(Clone)]
struct StripeClient {
    http: reqwest::Client,
    base_url: String,
    api_version: String,
    secret_key: String,
}

impl StripeClient {
    fn from_env(http: &reqwest::Client) -> Result<Self, String> {
        let secret_key = std::env::var("STRIPE_SECRET_KEY")
            .map_err(|_| "Stripe secret key is not configured".to_string())?;

        // A test-mode key must never silently drive real customer billing.
        // It is only accepted when the deployment explicitly opts in.
        if secret_key.starts_with("sk_test_")
            && std::env::var("STRIPE_ALLOW_TEST_KEY").as_deref() != Ok("true")
        {
            return Err(
                "STRIPE_SECRET_KEY is a Stripe test key; set STRIPE_ALLOW_TEST_KEY=true only in non-production development deployments"
                    .to_string(),
            );
        }

        Ok(Self {
            http: http.clone(),
            base_url: stripe_api_base_url(),
            api_version: stripe_api_version(),
            secret_key,
        })
    }

    #[cfg_attr(not(test), allow(dead_code))]
    fn new(
        http: reqwest::Client,
        base_url: String,
        api_version: String,
        secret_key: String,
    ) -> Self {
        Self {
            http,
            base_url,
            api_version,
            secret_key,
        }
    }

    async fn form_post<T: DeserializeOwned>(
        &self,
        path: &str,
        form: &[(&str, String)],
        idempotency_key: Option<&str>,
    ) -> Result<T, String> {
        let response = self
            .form_request(path, form, idempotency_key)
            .send()
            .await
            .map_err(|error| format!("Stripe request failed: {error}"))?;
        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(format!("Stripe returned {status}: {body}"));
        }

        response
            .json::<T>()
            .await
            .map_err(|error| format!("Stripe response decode failed: {error}"))
    }

    fn form_request(
        &self,
        path: &str,
        form: &[(&str, String)],
        idempotency_key: Option<&str>,
    ) -> reqwest::RequestBuilder {
        let mut request = self
            .http
            .post(format!("{}{}", self.base_url, path))
            .bearer_auth(&self.secret_key)
            .header("Stripe-Version", &self.api_version)
            .form(form);

        if let Some(idempotency_key) = idempotency_key {
            request = request.header("Idempotency-Key", idempotency_key);
        }

        request
    }
}

fn is_allowed_billing_redirect_url(
    url_string: &str,
    environment: crate::config::Environment,
) -> bool {
    let Ok(url) = url::Url::parse(url_string) else {
        return false;
    };

    let Some(host) = url.host_str() else {
        return false;
    };
    if !host.is_ascii() {
        return false;
    }

    let hostname = host.to_ascii_lowercase();
    if hostname.starts_with("xn--") || hostname.contains(".xn--") {
        return false;
    }

    let is_apexmail_host = hostname == "apexmail.ee" || hostname.ends_with(".apexmail.ee");
    if is_apexmail_host {
        return url.scheme() == "https";
    }

    if !environment.is_production() && hostname == "localhost" {
        return matches!(url.scheme(), "http" | "https");
    }

    false
}

fn billing_operation_failed_response() -> Response {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(serde_json::json!({ "error": "Operation failed" })),
    )
        .into_response()
}

fn tenant_billing_email(settings_raw: &str) -> Option<String> {
    let settings: TenantStripeSettings = serde_json::from_str(settings_raw).unwrap_or_default();
    settings.billing_email.or(settings.default_from_email)
}

async fn get_or_create_stripe_customer_id(
    state: &AppState,
    tenant_id: &str,
) -> Result<String, String> {
    let mut tx = state
        .db
        .begin()
        .await
        .map_err(|error| format!("Failed to open billing transaction: {error}"))?;

    sqlx::query("SELECT pg_advisory_xact_lock(hashtext($1))")
        .bind(tenant_id)
        .execute(&mut *tx)
        .await
        .map_err(|error| format!("Failed to acquire Stripe customer lock: {error}"))?;

    if let Some(stripe_customer_id) = sqlx::query_scalar::<_, String>(
        "SELECT stripe_customer_id FROM stripe_customers WHERE tenant_id = $1",
    )
    .bind(tenant_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|error| format!("Failed to query Stripe customer: {error}"))?
    {
        tx.commit()
            .await
            .map_err(|error| format!("Failed to close billing transaction: {error}"))?;
        return Ok(stripe_customer_id);
    }

    let Some((tenant_name, settings_raw)) = sqlx::query_as::<_, (String, String)>(
        "SELECT name, settings::text AS settings FROM tenants WHERE id = $1",
    )
    .bind(tenant_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|error| format!("Failed to query tenant for Stripe checkout: {error}"))?
    else {
        return Err("Tenant not found".into());
    };

    let Some(email) = tenant_billing_email(&settings_raw) else {
        return Err("No billing email configured".into());
    };

    let stripe = StripeClient::from_env(&state.http_client)?;
    let customer = stripe
        .form_post::<StripeCustomerResponse>(
            "/v1/customers",
            &[
                ("email", email.clone()),
                ("name", tenant_name.clone()),
                ("metadata[tenant_id]", tenant_id.to_string()),
            ],
            Some(&format!("customer_create_{tenant_id}")),
        )
        .await?;

    sqlx::query(
        r#"
        INSERT INTO stripe_customers (
            id, tenant_id, stripe_customer_id, email, name, created_at, updated_at
        ) VALUES (
            gen_random_uuid(), $1, $2, $3, $4, NOW(), NOW()
        )
        "#,
    )
    .bind(tenant_id)
    .bind(&customer.id)
    .bind(&email)
    .bind(&tenant_name)
    .execute(&mut *tx)
    .await
    .map_err(|error| format!("Failed to persist Stripe customer: {error}"))?;

    tx.commit()
        .await
        .map_err(|error| format!("Failed to commit Stripe customer transaction: {error}"))?;

    Ok(customer.id)
}

fn parse_query_date(value: &str) -> Option<chrono::DateTime<Utc>> {
    chrono::DateTime::parse_from_rfc3339(value)
        .map(|date| date.with_timezone(&Utc))
        .ok()
        .or_else(|| {
            chrono::NaiveDate::parse_from_str(value, "%Y-%m-%d")
                .ok()
                .and_then(|date| date.and_hms_opt(0, 0, 0))
                .map(|date| date.and_utc())
        })
}

fn csv_text_response(body: String, filename: Option<String>) -> Response {
    let mut builder = axum::response::Response::builder()
        .status(StatusCode::OK)
        .header(axum::http::header::CONTENT_TYPE, "text/csv");

    if let Some(filename) = filename {
        builder = builder.header(
            axum::http::header::CONTENT_DISPOSITION,
            format!("attachment; filename=\"{filename}\""),
        );
    }

    builder
        .body(axum::body::Body::from(body))
        .unwrap_or_else(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": "Operation failed" })),
            )
                .into_response()
        })
}

fn sanitize_csv_value(value: &serde_json::Value) -> String {
    let mut text = match value {
        serde_json::Value::Null => String::new(),
        serde_json::Value::String(value) => value.clone(),
        other => other.to_string(),
    };

    if text.starts_with(['=', '+', '-', '@', '\t', '\r']) {
        text = format!("'{}", text);
    }

    if text.contains(',') || text.contains('"') || text.contains('\n') {
        format!("\"{}\"", text.replace('"', "\"\""))
    } else {
        text
    }
}

fn json_rows_to_csv(data: &serde_json::Value) -> String {
    let rows = data.as_array().cloned().unwrap_or_default();
    if rows.is_empty() {
        return String::new();
    }

    let headers: Vec<String> = rows[0]
        .as_object()
        .map(|row| row.keys().cloned().collect())
        .unwrap_or_default();

    let mut csv_rows = vec![headers.join(",")];
    for row in rows {
        let object = row.as_object().cloned().unwrap_or_default();
        let values = headers
            .iter()
            .map(|header| {
                sanitize_csv_value(object.get(header).unwrap_or(&serde_json::Value::Null))
            })
            .collect::<Vec<_>>();
        csv_rows.push(values.join(","));
    }

    csv_rows.join("\n")
}

fn safe_export_date(value: &str) -> String {
    value
        .chars()
        .filter(|character| character.is_ascii_digit() || *character == '-')
        .collect()
}

fn admin_revenue_report_query(use_legacy_schema: bool) -> &'static str {
    if use_legacy_schema {
        r#"
        SELECT COALESCE(json_agg(row_to_json(report_row) ORDER BY report_row.date), '[]'::json)
        FROM (
            SELECT
                DATE_TRUNC('day', COALESCE(paid_at, created_at)) as date,
                SUM(amount_cents) as total_revenue,
                COUNT(*) as invoice_count,
                0::bigint as total_tax,
                currency
            FROM invoices
            WHERE status = 'paid' AND COALESCE(paid_at, created_at) >= $1 AND COALESCE(paid_at, created_at) < $2
            GROUP BY DATE_TRUNC('day', COALESCE(paid_at, created_at)), currency
            ORDER BY date
        ) report_row
        "#
    } else {
        r#"
        SELECT COALESCE(json_agg(row_to_json(report_row) ORDER BY report_row.date), '[]'::json)
        FROM (
            SELECT
                DATE_TRUNC('day', paid_at) as date,
                SUM(total) as total_revenue,
                COUNT(*) as invoice_count,
                SUM(vat_total) as total_tax,
                currency
            FROM invoices
            WHERE status = 'paid' AND paid_at >= $1 AND paid_at < $2
            GROUP BY DATE_TRUNC('day', paid_at), currency
            ORDER BY date
        ) report_row
        "#
    }
}

fn admin_invoice_export_query(use_legacy_schema: bool) -> &'static str {
    if use_legacy_schema {
        r#"
        SELECT COALESCE(json_agg(row_to_json(export_row) ORDER BY export_row.issued_at), '[]'::json)
        FROM (
            SELECT
                i.invoice_number, i.tenant_id, t.name as tenant_name,
                i.amount_cents as subtotal,
                0::bigint as vat_total,
                i.amount_cents as total,
                i.currency,
                i.status,
                i.created_at as issued_at,
                i.paid_at,
                i.due_date as due_at
            FROM invoices i
            JOIN tenants t ON i.tenant_id = t.id
            WHERE i.created_at >= $1 AND i.created_at < $2
            ORDER BY i.created_at
        ) export_row
        "#
    } else {
        r#"
        SELECT COALESCE(json_agg(row_to_json(export_row) ORDER BY export_row.issued_at), '[]'::json)
        FROM (
            SELECT
                i.invoice_number, i.tenant_id, t.name as tenant_name,
                i.subtotal, i.vat_total, i.total, i.currency,
                i.status, i.issued_at, i.paid_at, i.due_at
            FROM invoices i
            JOIN tenants t ON i.tenant_id = t.id
            WHERE i.issued_at >= $1 AND i.issued_at < $2
            ORDER BY i.issued_at
        ) export_row
        "#
    }
}

/// Platform billing-admin capability check.
///
/// SECURITY (audit A): the wildcard scope `"*"` is granted to every tenant's
/// admin/owner role (`scopes_for_role` in routes/auth.rs) so customers can
/// manage their OWN tenant — it must never grant platform-level billing
/// administration. Platform billing admin (`/v1/billing/admin/*`) is a
/// system-tenant capability, exactly like the `/v1/admin/*` control plane
/// (see `require_system_tenant_middleware`), so the caller must BOTH be a
/// system-tenant user AND carry an admin scope.
///
/// Slug-aware (same fix class as the control plane's): the literal `system`
/// is carried only by static API keys — every human operator authenticates
/// as the SEEDED system tenant (`system_internal_tenant01`, migration 072;
/// see `routes::system_sender::SYSTEM_TENANT_ID`). Accepting only the
/// literal 403'd every human platform operator from billing admin.
fn has_admin_access(auth: &AuthUser) -> bool {
    (auth.tenant_id == "system"
        || auth.tenant_id == crate::routes::system_sender::SYSTEM_TENANT_ID)
        && auth
            .scopes
            .iter()
            .any(|scope| scope == "*" || scope == "billing:admin")
}

fn has_tenant_access(auth: &AuthUser, tenant_id: &str) -> bool {
    let tenant_scope = format!("tenant:{tenant_id}");
    auth.scopes.iter().any(|scope| {
        scope == "*" || scope == "billing:admin" || scope == "tenant:*" || scope == &tenant_scope
    })
}

fn require_admin_access(auth: &AuthUser) -> Result<(), Response> {
    if has_admin_access(auth) {
        Ok(())
    } else {
        Err((
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({ "error": "Admin access required" })),
        )
            .into_response())
    }
}

fn require_admin_tenant_access(auth: &AuthUser, tenant_id: &str) -> Result<(), Response> {
    require_admin_access(auth)?;
    if has_tenant_access(auth, tenant_id) {
        Ok(())
    } else {
        Err((
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({ "error": "Tenant access denied" })),
        )
            .into_response())
    }
}

fn admin_actor_id(auth: &AuthUser) -> String {
    auth.user_id.clone().unwrap_or_else(|| "system".to_string())
}

async fn invalidate_cache_key(state: &AppState, key: &str) {
    if let Ok(mut conn) = state.redis.get().await {
        let _: Result<(), _> = conn.del(key).await;
    }
}

async fn resolve_tenant_billing_currency(state: &AppState, tenant_id: &str) -> String {
    let currency: Option<String> = sqlx::query_scalar(
        "SELECT settings->>'billingCurrency' AS billing_currency FROM tenants WHERE id = $1",
    )
    .bind(tenant_id)
    .fetch_optional(&state.db)
    .await
    .ok()
    .flatten();

    let normalized = currency.unwrap_or_else(|| DEFAULT_BILLING_CURRENCY.to_string());
    let normalized = normalized.trim().to_uppercase();
    if normalized.len() == 3
        && normalized
            .chars()
            .all(|character| character.is_ascii_uppercase())
    {
        normalized
    } else {
        DEFAULT_BILLING_CURRENCY.to_string()
    }
}

async fn get_or_create_wallet_balance(
    state: &AppState,
    tenant_id: &str,
) -> Result<LegacyWalletBalanceDto, ApiError> {
    if let Some(row) = sqlx::query_as::<_, (String, i64, i64, String, chrono::DateTime<Utc>)>(
        r#"
        SELECT tenant_id, balance, reserved, currency, updated_at
        FROM wallets WHERE tenant_id = $1
        "#,
    )
    .bind(tenant_id)
    .fetch_optional(&state.db)
    .await?
    {
        return Ok(LegacyWalletBalanceDto {
            tenant_id: row.0,
            balance: row.1,
            reserved_balance: row.2,
            available_balance: row.1 - row.2,
            currency: row.3,
            updated_at: row.4,
        });
    }

    let currency = resolve_tenant_billing_currency(state, tenant_id).await;
    let row = sqlx::query_as::<_, (String, i64, i64, String, chrono::DateTime<Utc>)>(
        r#"
        INSERT INTO wallets (tenant_id, balance, reserved, currency, created_at, updated_at)
        VALUES ($1, 0, 0, $2, NOW(), NOW())
        ON CONFLICT (tenant_id) DO UPDATE SET updated_at = wallets.updated_at
        RETURNING tenant_id, balance, reserved, currency, updated_at
        "#,
    )
    .bind(tenant_id)
    .bind(&currency)
    .fetch_one(&state.db)
    .await?;

    Ok(LegacyWalletBalanceDto {
        tenant_id: row.0,
        balance: row.1,
        reserved_balance: row.2,
        available_balance: row.1 - row.2,
        currency: row.3,
        updated_at: row.4,
    })
}

async fn get_dunning_state(
    state: &AppState,
    tenant_id: &str,
) -> Result<Option<LegacyDunningStateDto>, ApiError> {
    let row = sqlx::query_as::<
        _,
        (
            String,
            String,
            i64,
            Option<chrono::DateTime<Utc>>,
            Option<chrono::DateTime<Utc>>,
            Option<chrono::DateTime<Utc>>,
            Option<chrono::DateTime<Utc>>,
            Option<chrono::DateTime<Utc>>,
        ),
    >(
        r#"
        SELECT tenant_id, status, failed_payment_count, first_failed_at, last_failed_at,
               next_retry_at, suspended_at, grace_period_ends_at
        FROM dunning_records WHERE tenant_id = $1
        "#,
    )
    .bind(tenant_id)
    .fetch_optional(&state.db)
    .await?;

    let Some(row) = row else {
        return Ok(None);
    };

    let queued_messages_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*)::bigint FROM messages WHERE tenant_id = $1 AND status = 'dunning_queued'",
    )
    .bind(tenant_id)
    .fetch_one(&state.db)
    .await?;

    Ok(Some(LegacyDunningStateDto {
        tenant_id: row.0,
        status: row.1,
        failed_payment_count: row.2,
        first_failed_at: row.3,
        last_failed_at: row.4,
        next_retry_at: row.5,
        suspended_at: row.6,
        queued_messages_count,
        grace_period_ends_at: row.7,
    }))
}

/// Returns `true` if the Postgres error matches one of the given codes.
///
/// This is used to detect schema-mismatch errors (e.g. `42703` = undefined
/// column, `42P01` = undefined table) and fall back to a legacy query during
/// zero-downtime migrations. **Only** expected migration codes should be passed;
/// all other errors must be propagated to avoid silently masking real failures.
fn is_postgres_error_code(error: &sqlx::Error, code: &str) -> bool {
    match error {
        sqlx::Error::Database(db_error) => db_error.code().as_deref() == Some(code),
        _ => false,
    }
}

/// Returns `true` if the Postgres error matches any of the schema-mismatch
/// codes that signal a column or table is missing in the current schema.
///
/// A warning is emitted so operators can observe fallback events. This should
/// only be used at the few call sites that explicitly support a legacy schema
/// path during rolling migrations.
fn is_expected_schema_fallback_error(error: &sqlx::Error, expected_codes: &[&str]) -> bool {
    // Extract the error code as an owned String to avoid lifetime issues with
    // the database error's inner references.
    let error_code = match error {
        sqlx::Error::Database(db_error) => db_error.code().map(|c| c.to_string()),
        _ => None,
    };

    let matched = match error_code.as_deref() {
        Some(actual) => expected_codes.contains(&actual),
        None => false,
    };

    if matched {
        if let Some(ref code) = error_code {
            tracing::warn!(
                error.code = %code,
                "schema fallback triggered – column(s) or table(s) missing in current schema",
            );
        }
    }

    matched
}

fn clamp_limit(limit: i64, max: i64) -> i64 {
    limit.clamp(1, max)
}

fn clamp_offset(offset: i64, max: i64) -> i64 {
    offset.clamp(0, max)
}

fn empty_billing_address() -> LegacyBillingAddressDto {
    LegacyBillingAddressDto {
        company_name: String::new(),
        vat_number: None,
        address_line1: String::new(),
        address_line2: None,
        city: String::new(),
        state: None,
        postal_code: String::new(),
        country: String::new(),
        email: String::new(),
    }
}

fn parse_json_or_default<T>(raw: &str, default: T) -> T
where
    T: DeserializeOwned,
{
    serde_json::from_str(raw).unwrap_or(default)
}

/// Bank account identifiers are deployment configuration (Wise by default).
/// They return empty when unset so renderers can omit the field entirely
/// instead of printing a placeholder like "UNCONFIGURED" on a legal document.
fn billing_company_iban() -> String {
    std::env::var("BILLING_COMPANY_IBAN").unwrap_or_default()
}

fn billing_company_bic() -> String {
    std::env::var("BILLING_COMPANY_BIC").unwrap_or_default()
}

fn billing_company_bank_name() -> String {
    std::env::var("BILLING_COMPANY_BANK").unwrap_or_else(|_| BILLING_COMPANY_BANK_NAME.into())
}

fn billing_company_phone() -> String {
    std::env::var("BILLING_COMPANY_PHONE").unwrap_or_default()
}

fn escape_html(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

fn escape_xml(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

fn format_invoice_date(date: chrono::DateTime<Utc>) -> String {
    date.format("%Y-%m-%d").to_string()
}

/// Format cents with the invoice's actual currency (the invoice carries a
/// `currency` column; USD invoices were being rendered with a € symbol).
fn format_invoice_currency_with(cents: i64, currency: &str) -> String {
    let symbol = match currency.to_uppercase().as_str() {
        "USD" => "$",
        "GBP" => "£",
        _ => "€", // EUR default
    };
    format!("{}{}", symbol, cents_to_decimal_string(cents))
}

/// Format integer cents as a plain decimal string ("123.45") using integer
/// math only — money formatting must not round-trip through f64.
fn cents_to_decimal_string(cents: i64) -> String {
    let sign = if cents < 0 { "-" } else { "" };
    let abs = cents.unsigned_abs();
    format!("{}{}.{:02}", sign, abs / 100, abs % 100)
}

fn invoice_payment_terms_days(invoice: &LegacyInvoiceDto) -> i64 {
    let diff_ms = invoice
        .due_at
        .signed_duration_since(invoice.issued_at)
        .num_milliseconds();

    proration::ceil_day_count(diff_ms)
}

fn invoice_vat_label(invoice: &LegacyInvoiceDto) -> String {
    let mut vat_rates: Vec<f64> = invoice
        .line_items
        .iter()
        .map(|item| item.vat_rate)
        .collect();
    vat_rates.sort_unstable_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    vat_rates.dedup();

    let fmt = |rate: &f64| format!("{}%", billing_common::vat_rates::format_vat_rate(*rate));
    if vat_rates.len() <= 1 {
        format!(
            "VAT ({})",
            vat_rates.first().map(fmt).unwrap_or_else(|| fmt(&0.0))
        )
    } else {
        format!(
            "VAT (Mixed: {})",
            vat_rates.iter().map(fmt).collect::<Vec<_>>().join(", ")
        )
    }
}

/// Per-response CSP nonce for the invoice document's single `<style>` element
/// (audit H-6). 128 bits of OS randomness via UUIDv4, flattened to hex —
/// characters that need no escaping inside a CSP header or an attribute.
fn invoice_style_nonce() -> String {
    let mut hasher = Sha256::new();
    hasher.update(Uuid::new_v4().as_u128().to_le_bytes());
    let digest = hasher.finalize();
    digest[..16]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// Build the print-to-PDF invoice response (audit H-6).
///
/// The global security-headers middleware injects
/// `Content-Security-Policy: default-src 'none'; frame-ancestors 'none'`
/// into every response that does not carry its own CSP — which blocked the
/// document's inline `<style>` and left the browser print dialog rendering
/// an unstyled invoice. Instead of loosening the global policy, the route
/// emits its own COMPLETE document-scoped CSP: everything stays `default-src
/// 'none'` except the single nonce-stamped stylesheet, and the middleware
/// respects the pre-set header (it only fills in a default when absent).
///
/// Escaping was audited before allowing an inline style element: every
/// interpolated customer-controlled field (company, address, PO, notes,
/// invoice number, IBAN, e-mail) goes through `escape_html`; all other
/// interpolations are compile-time constants, formatted dates, or numeric
/// currency/percentage renderings.
fn invoice_html_response(invoice: &LegacyInvoiceDto) -> Response {
    let nonce = invoice_style_nonce();
    let html = render_invoice_html(invoice, &nonce);
    let csp = format!(
        "default-src 'none'; style-src 'nonce-{nonce}'; base-uri 'none'; \
         form-action 'none'; frame-ancestors 'none'"
    );
    let mut response = Html(html).into_response();
    response.headers_mut().insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_str(&csp).expect("invoice CSP contains only header-safe characters"),
    );
    response
}

fn render_invoice_html(invoice: &LegacyInvoiceDto, style_nonce: &str) -> String {
    let purchase_order = invoice
        .purchase_order_number
        .as_ref()
        .map(|value| format!("      <div>PO: {}</div>\n", escape_html(value)))
        .unwrap_or_default();
    let address_line_2 = invoice
        .billing_address
        .address_line2
        .as_ref()
        .map(|value| format!("      {}<br>\n", escape_html(value)))
        .unwrap_or_default();
    let vat_number = invoice
        .billing_address
        .vat_number
        .as_ref()
        .map(|value| format!("      VAT: {}<br>\n", escape_html(value)))
        .unwrap_or_default();
    let state_prefix = invoice
        .billing_address
        .state
        .as_ref()
        .map(|value| format!("{}, ", escape_html(value)))
        .unwrap_or_default();
    let notes = invoice
        .notes
        .as_ref()
        .map(|value| {
            format!(
                "\n  <div style=\"margin-top: 30px;\"><strong>Notes:</strong> {}</div>\n",
                escape_html(value)
            )
        })
        .unwrap_or_default();
    // The reverse-charge note may only appear on invoices where reverse charge
    // was actually applied: a *valid* VAT number for the buyer's country,
    // outside Estonia, and zero VAT charged. Printing it on an invoice that
    // charged VAT (e.g. malformed VAT number) produces a self-contradicting
    // tax document.
    let reverse_charge_applied = invoice.vat_total == 0
        && invoice.billing_address.country != "EE"
        && invoice
            .billing_address
            .vat_number
            .as_deref()
            .map(|vat| {
                billing_common::vat_rates::is_valid_vat_number(
                    vat,
                    Some(&invoice.billing_address.country),
                )
            })
            .unwrap_or(false);
    let reverse_charge_note = if reverse_charge_applied {
        "\n  <div class=\"vat-note\">\n      Reverse charge: VAT to be paid by the recipient per Article 196, EU VAT Directive 2006/112/EC\n    </div>\n".to_string()
    } else {
        String::new()
    };

    let mut line_items_html = String::new();
    for item in &invoice.line_items {
        line_items_html.push_str(&format!(
            "\n        <tr>\n          <td>{}</td>\n          <td>{}</td>\n          <td class=\"amount\">{}</td>\n          <td class=\"amount\">{}%</td>\n          <td class=\"amount\">{}</td>\n        </tr>",
            escape_html(&item.description),
            item.quantity,
            format_invoice_currency_with(item.unit_price, &invoice.currency),
            billing_common::vat_rates::format_vat_rate(item.vat_rate),
            format_invoice_currency_with(item.amount, &invoice.currency),
        ));
    }

    format!(
        r#"<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>Invoice {invoice_number}</title>
  <style nonce="{style_nonce}">
    body {{ font-family:ui-monospace, 'JetBrains Mono', monospace; font-size: 12px; color: #18181b; margin: 40px; }}
    .header {{ display: flex; justify-content: space-between; margin-bottom: 40px; }}
    .logo {{ font-size: 24px; font-weight: bold; color: #09090b; }}
    .invoice-info {{ text-align: right; }}
    .invoice-number {{ font-size: 18px; font-weight: bold; }}
    .addresses {{ display: flex; justify-content: space-between; margin-bottom: 40px; }}
    .address {{ width: 45%; }}
    .address h3 {{ font-size: 10px; text-transform: uppercase; color: #71717a; margin-bottom: 10px; }}
    table {{ width: 100%; border-collapse: collapse; margin-bottom: 30px; }}
    th {{ background: #f4f4f5; padding: 12px; text-align: left; font-weight: 600; border-bottom: 2px solid #d4d4d8; }}
    td {{ padding: 12px; border-bottom: 1px solid #e4e4e7; }}
    .amount {{ text-align: right; }}
    .totals {{ margin-left: auto; width: 300px; }}
    .totals table {{ margin-bottom: 0; }}
    .totals td {{ border: none; padding: 8px 12px; }}
    .total-row {{ font-weight: bold; font-size: 14px; background: #f4f4f5; }}
    .footer {{ margin-top: 60px; padding-top: 20px; border-top: 1px solid #e4e4e7; font-size: 10px; color: #71717a; }}
    .vat-note {{ font-style: italic; margin-top: 20px; }}
  </style>
</head>
<body>
  <div class="header">
    <div class="logo">{trading_as}</div>
    <div class="invoice-info">
      <div class="invoice-number">Invoice {invoice_number}</div>
      <div>Issued: {issued_at}</div>
      <div>Due: {due_at}</div>
{purchase_order}    </div>
  </div>

  <div class="addresses">
    <div class="address">
      <h3>From</h3>
      <strong>{company_name}</strong><br>
      (trading as {trading_as})<br>
      {company_street}<br>
      {company_postal_code} {company_city}<br>
      {company_country}<br>
      Reg. {registry_code}<br>
      VAT: {company_vat}<br>
      {billing_email}
    </div>
    <div class="address">
      <h3>Bill To</h3>
      <strong>{bill_to_company}</strong><br>
      {bill_to_line1}<br>
{address_line_2}      {bill_to_postal_code} {bill_to_city}<br>
      {bill_to_state}{bill_to_country}<br>
{vat_number}      {bill_to_email}
    </div>
  </div>

  <table>
    <thead>
      <tr>
        <th>Description</th>
        <th>Qty</th>
        <th class="amount">Unit Price</th>
        <th class="amount">VAT</th>
        <th class="amount">Amount</th>
      </tr>
    </thead>
    <tbody>{line_items_html}
    </tbody>
  </table>

  <div class="totals">
    <table>
      <tr>
        <td>Subtotal</td>
        <td class="amount">{subtotal}</td>
      </tr>
      <tr>
        <td>{vat_label}</td>
        <td class="amount">{vat_total}</td>
      </tr>
      <tr class="total-row">
        <td>Total</td>
        <td class="amount">{total}</td>
      </tr>
    </table>
  </div>{reverse_charge_note}{notes}
  <div class="footer">
    <p>Payment terms: Net {payment_terms_days} days. Please include invoice number in payment reference.</p>
    <p>{company_name} (trading as {trading_as}) | Reg. {registry_code} | VAT: {company_vat}{bank_details}</p>
    <p>{company_street}, {company_postal_code} {company_city}, {company_country}</p>
    <p>Period: {period_start} to {period_end}</p>
  </div>
</body>
</html>"#,
        invoice_number = escape_html(&invoice.invoice_number),
        trading_as = BILLING_COMPANY_TRADING_AS,
        issued_at = format_invoice_date(invoice.issued_at),
        due_at = format_invoice_date(invoice.due_at),
        purchase_order = purchase_order,
        company_name = BILLING_COMPANY_NAME,
        company_street = BILLING_COMPANY_STREET,
        company_postal_code = BILLING_COMPANY_POSTAL_CODE,
        company_city = BILLING_COMPANY_CITY,
        company_country = BILLING_COMPANY_COUNTRY,
        registry_code = BILLING_COMPANY_REGISTRY_CODE,
        company_vat = BILLING_COMPANY_VAT_NUMBER,
        billing_email = BILLING_COMPANY_BILLING_EMAIL,
        bill_to_company = escape_html(&invoice.billing_address.company_name),
        bill_to_line1 = escape_html(&invoice.billing_address.address_line1),
        address_line_2 = address_line_2,
        bill_to_postal_code = escape_html(&invoice.billing_address.postal_code),
        bill_to_city = escape_html(&invoice.billing_address.city),
        bill_to_state = state_prefix,
        bill_to_country = escape_html(&invoice.billing_address.country),
        vat_number = vat_number,
        bill_to_email = escape_html(&invoice.billing_address.email),
        line_items_html = line_items_html,
        subtotal = format_invoice_currency_with(invoice.subtotal, &invoice.currency),
        vat_label = invoice_vat_label(invoice),
        vat_total = format_invoice_currency_with(invoice.vat_total, &invoice.currency),
        total = format_invoice_currency_with(invoice.total, &invoice.currency),
        reverse_charge_note = reverse_charge_note,
        notes = notes,
        payment_terms_days = invoice_payment_terms_days(invoice),
        bank_details = {
            let iban = billing_company_iban();
            let bic = billing_company_bic();
            let bank = billing_company_bank_name();
            let mut parts = format!(" | Bank: {}", escape_html(&bank));
            if !iban.is_empty() {
                parts.push_str(&format!(" | IBAN: {}", escape_html(&iban)));
            }
            if !bic.is_empty() {
                parts.push_str(&format!(" | BIC: {}", escape_html(&bic)));
            }
            parts
        },
        period_start = format_invoice_date(invoice.period_start),
        period_end = format_invoice_date(invoice.period_end),
    )
}

fn render_invoice_xml(invoice: &LegacyInvoiceDto) -> String {
    let reference_number = invoice
        .purchase_order_number
        .as_ref()
        .map(|value| {
            format!(
                "      <ReferenceNumber>{}</ReferenceNumber>\n",
                escape_xml(value)
            )
        })
        .unwrap_or_default();
    let buyer_vat_number = invoice
        .billing_address
        .vat_number
        .as_ref()
        .map(|value| {
            format!(
                "        <VATRegNumber>{}</VATRegNumber>\n",
                escape_xml(value)
            )
        })
        .unwrap_or_default();
    let buyer_address_line_2 = invoice
        .billing_address
        .address_line2
        .as_ref()
        .map(|value| {
            format!(
                "            <PostalAddress2>{}</PostalAddress2>\n",
                escape_xml(value)
            )
        })
        .unwrap_or_default();

    let currency = invoice.currency.to_uppercase();
    let mut item_entries = String::new();
    for (index, item) in invoice.line_items.iter().enumerate() {
        item_entries.push_str(&format!(
            "      <ItemEntry>\n        <RowNo>{}</RowNo>\n        <Description>{}</Description>\n        <ItemDetailInfo>\n          <ItemUnit>PCS</ItemUnit>\n          <ItemAmount>{}</ItemAmount>\n          <ItemPrice>{}</ItemPrice>\n        </ItemDetailInfo>\n        <ItemSum>\n          <Amount>{}</Amount>\n          <VAT>\n            <VATRate>{}</VATRate>\n            <VATSum>{}</VATSum>\n            <SumBeforeVAT>{}</SumBeforeVAT>\n            <SumAfterVAT>{}</SumAfterVAT>\n            <Currency>{}</Currency>\n          </VAT>\n          <TotalSum>{}</TotalSum>\n        </ItemSum>\n      </ItemEntry>\n",
            index + 1,
            escape_xml(&item.description),
            item.quantity,
            cents_to_decimal_string(item.unit_price),
            cents_to_decimal_string(item.amount),
            billing_common::vat_rates::format_vat_rate(item.vat_rate),
            cents_to_decimal_string(item.vat_amount),
            cents_to_decimal_string(item.amount),
            cents_to_decimal_string(item.amount + item.vat_amount),
            cents_to_decimal_string(item.amount + item.vat_amount),
            escape_xml(&currency),
        ));
    }

    // Optional blocks: omit contact/bank elements that have no configured
    // value rather than emitting empty XML tags on a legal document.
    let phone_xml_block = {
        let phone = billing_company_phone();
        if phone.is_empty() {
            String::new()
        } else {
            format!(
                "<PhoneNumber>{}</PhoneNumber>\n          ",
                escape_xml(&phone)
            )
        }
    };
    let account_info = {
        let iban = billing_company_iban();
        let bic = billing_company_bic();
        if iban.is_empty() && bic.is_empty() {
            String::new()
        } else {
            format!(
                "        <AccountInfo>\n          <AccountNumber>{}</AccountNumber>\n{}\n          <BankName>{}</BankName>\n        </AccountInfo>\n",
                escape_xml(&iban),
                if bic.is_empty() {
                    String::new()
                } else {
                    format!("          <BIC>{}</BIC>", escape_xml(&bic))
                },
                escape_xml(&billing_company_bank_name()),
            )
        }
    };
    let payto_block = {
        let iban = billing_company_iban();
        let bic = billing_company_bic();
        let mut block = String::new();
        if !iban.is_empty() {
            block.push_str(&format!(
                "      <PayToAccount>{}</PayToAccount>\n",
                escape_xml(&iban)
            ));
        }
        if !bic.is_empty() {
            block.push_str(&format!(
                "      <PayToBIC>{}</PayToBIC>\n",
                escape_xml(&bic)
            ));
        }
        block
    };

    // <PaidAmount> must reflect the invoice's settlement state: a paid
    // invoice carries its full total as paid (and nothing payable), an
    // open one shows 0.00 paid. The hardcoded 0.00 told every recipient's
    // accounting package that settled invoices were still outstanding.
    let is_paid = invoice.paid_at.is_some() || invoice.status.eq_ignore_ascii_case("paid");
    let paid_amount = if is_paid {
        cents_to_decimal_string(invoice.total)
    } else {
        cents_to_decimal_string(0)
    };
    let payable_amount = if is_paid {
        cents_to_decimal_string(0)
    } else {
        cents_to_decimal_string(invoice.total)
    };

    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<E_Invoice xmlns=\"http://www.pangaliit.ee/e-arve/e-arve\">\n  <Header>\n    <Date>{issued_at}</Date>\n    <FileId>{file_id}</FileId>\n    <Version>1.2</Version>\n  </Header>\n  <Invoice>\n    <InvoiceParties>\n      <SellerParty>\n        <Name>{company_name}</Name>\n        <RegNumber>{registry_code}</RegNumber>\n        <VATRegNumber>{company_vat}</VATRegNumber>\n        <ContactData>\n          <LegalAddress>\n            <PostalAddress1>{company_street}</PostalAddress1>\n            <City>{company_city}</City>\n            <PostalCode>{company_postal_code}</PostalCode>\n            <Country>EE</Country>\n          </LegalAddress>\n          {phone_xml_block}<E-mailAddress>{billing_email}</E-mailAddress>\n        </ContactData>\n{account_info}      </SellerParty>\n      <BuyerParty>\n        <Name>{buyer_name}</Name>\n{buyer_vat_number}        <ContactData>\n          <LegalAddress>\n            <PostalAddress1>{buyer_line1}</PostalAddress1>\n{buyer_address_line_2}            <City>{buyer_city}</City>\n            <PostalCode>{buyer_postal_code}</PostalCode>\n            <Country>{buyer_country}</Country>\n          </LegalAddress>\n          <E-mailAddress>{buyer_email}</E-mailAddress>\n        </ContactData>\n      </BuyerParty>\n    </InvoiceParties>\n    <InvoiceInformation>\n      <Type Type=\"DEB\"/>\n      <InvoiceNumber>{invoice_number}</InvoiceNumber>\n      <InvoiceDate>{issued_at}</InvoiceDate>\n      <DueDate>{due_at}</DueDate>\n      <InvoiceContentCode>SERVICES</InvoiceContentCode>\n      <Currency>{currency}</Currency>\n{reference_number}    </InvoiceInformation>\n    <InvoiceSumGroup>\n      <InvoiceSum>{total}</InvoiceSum>\n      <PaidAmount>{paid_amount}</PaidAmount>\n      <PayableAmount>{payable_amount}</PayableAmount>\n      <Currency>{currency}</Currency>\n    </InvoiceSumGroup>\n    <InvoiceItem>\n{item_entries}    </InvoiceItem>\n    <PaymentInfo>\n      <Currency>{currency}</Currency>\n      <PaymentDescription>Invoice {invoice_number}</PaymentDescription>\n      <Payable>YES</Payable>\n      <DueDate>{due_at}</DueDate>\n      <PaymentId>{invoice_number}</PaymentId>\n      <PaymentTotalSum>{total}</PaymentTotalSum>\n      <PayerName>{buyer_name}</PayerName>\n{payto_block}      <PayToName>{company_name}</PayToName>\n    </PaymentInfo>\n  </Invoice>\n</E_Invoice>",
        issued_at = format_invoice_date(invoice.issued_at),
        file_id = escape_xml(&invoice.id),
        company_name = escape_xml(BILLING_COMPANY_NAME),
        registry_code = BILLING_COMPANY_REGISTRY_CODE,
        company_vat = BILLING_COMPANY_VAT_NUMBER,
        company_street = escape_xml(BILLING_COMPANY_STREET),
        company_city = escape_xml(BILLING_COMPANY_CITY),
        company_postal_code = BILLING_COMPANY_POSTAL_CODE,
        phone_xml_block = phone_xml_block,
        billing_email = escape_xml(BILLING_COMPANY_BILLING_EMAIL),
        account_info = account_info,
        payto_block = payto_block,
        currency = escape_xml(&currency),
        buyer_name = escape_xml(&invoice.billing_address.company_name),
        buyer_vat_number = buyer_vat_number,
        buyer_line1 = escape_xml(&invoice.billing_address.address_line1),
        buyer_address_line_2 = buyer_address_line_2,
        buyer_city = escape_xml(&invoice.billing_address.city),
        buyer_postal_code = escape_xml(&invoice.billing_address.postal_code),
        buyer_country = escape_xml(&invoice.billing_address.country),
        buyer_email = escape_xml(&invoice.billing_address.email),
        invoice_number = escape_xml(&invoice.invoice_number),
        due_at = format_invoice_date(invoice.due_at),
        reference_number = reference_number,
        total = cents_to_decimal_string(invoice.total),
        paid_amount = paid_amount,
        payable_amount = payable_amount,
        item_entries = item_entries,
    )
}

fn safe_invoice_filename(invoice_number: &str) -> String {
    let sanitized: String = invoice_number
        .chars()
        .filter(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.')
        })
        .collect();

    if sanitized.is_empty() {
        "invoice".into()
    } else {
        sanitized
    }
}

fn map_invoice_row(row: LegacyInvoiceRow) -> LegacyInvoiceDto {
    LegacyInvoiceDto {
        id: row.id,
        tenant_id: row.tenant_id,
        stripe_invoice_id: row.stripe_invoice_id,
        invoice_number: row.invoice_number,
        status: row.status,
        currency: row.currency,
        subtotal: row.subtotal,
        vat_total: row.vat_total,
        total: row.total,
        line_items: parse_json_or_default(&row.line_items, Vec::new()),
        billing_address: parse_json_or_default(&row.billing_address, empty_billing_address()),
        issued_at: row.issued_at,
        due_at: row.due_at,
        paid_at: row.paid_at,
        period_start: row.period_start,
        period_end: row.period_end,
        purchase_order_number: row.purchase_order_number,
        notes: row.notes,
        pdf_url: row.pdf_url,
        xml_url: row.xml_url,
        created_at: row.created_at,
        updated_at: row.updated_at,
    }
}

async fn query_invoice_list_rows_with_legacy_fallback(
    pool: &sqlx::PgPool,
    tenant_id: &str,
    limit: i64,
    offset: i64,
) -> Result<Vec<LegacyInvoiceRow>, sqlx::Error> {
    match sqlx::query_as::<_, LegacyInvoiceRow>(
        r#"
        SELECT
            id::text AS id,
            tenant_id,
            stripe_invoice_id,
            invoice_number,
            status::text AS status,
            currency,
            subtotal,
            vat_total,
            total,
            line_items::text AS line_items,
            billing_address::text AS billing_address,
            issued_at,
            due_at,
            paid_at,
            period_start,
            period_end,
            purchase_order_number,
            notes,
            pdf_url,
            xml_url,
            created_at,
            updated_at
        FROM invoices
        WHERE tenant_id = $1
        ORDER BY issued_at DESC
        LIMIT $2 OFFSET $3
        "#,
    )
    .bind(tenant_id)
    .bind(limit)
    .bind(offset)
    .fetch_all(pool)
    .await
    {
        Ok(rows) => Ok(rows),
        Err(error) if is_expected_schema_fallback_error(&error, &["42703", "42P01"]) => {
            sqlx::query_as::<_, LegacyInvoiceRow>(
                r#"
                SELECT
                    id::text AS id,
                    tenant_id,
                    stripe_invoice_id,
                    invoice_number,
                    status::text AS status,
                    currency,
                    amount_cents AS subtotal,
                    0::bigint AS vat_total,
                    amount_cents AS total,
                    line_items::text AS line_items,
                    '{}'::text AS billing_address,
                    created_at AS issued_at,
                    due_date AS due_at,
                    paid_at,
                    period_start,
                    period_end,
                    NULL::text AS purchase_order_number,
                    NULL::text AS notes,
                    NULL::text AS pdf_url,
                    NULL::text AS xml_url,
                    created_at,
                    updated_at
                FROM invoices
                WHERE tenant_id = $1
                ORDER BY created_at DESC
                LIMIT $2 OFFSET $3
                "#,
            )
            .bind(tenant_id)
            .bind(limit)
            .bind(offset)
            .fetch_all(pool)
            .await
        }
        Err(error) => Err(error),
    }
}

async fn query_invoice_detail_rows_with_legacy_fallback(
    pool: &sqlx::PgPool,
    id: &str,
    tenant_id: &str,
) -> Result<Vec<LegacyInvoiceRow>, sqlx::Error> {
    match sqlx::query_as::<_, LegacyInvoiceRow>(
        r#"
        SELECT
            id::text AS id,
            tenant_id,
            stripe_invoice_id,
            invoice_number,
            status::text AS status,
            currency,
            subtotal,
            vat_total,
            total,
            line_items::text AS line_items,
            billing_address::text AS billing_address,
            issued_at,
            due_at,
            paid_at,
            period_start,
            period_end,
            purchase_order_number,
            notes,
            pdf_url,
            xml_url,
            created_at,
            updated_at
        FROM invoices
        WHERE id::text = $1 AND tenant_id = $2
        LIMIT 1
        "#,
    )
    .bind(id)
    .bind(tenant_id)
    .fetch_all(pool)
    .await
    {
        Ok(rows) => Ok(rows),
        Err(error) if is_expected_schema_fallback_error(&error, &["42703", "42P01"]) => {
            sqlx::query_as::<_, LegacyInvoiceRow>(
                r#"
                SELECT
                    id::text AS id,
                    tenant_id,
                    stripe_invoice_id,
                    invoice_number,
                    status::text AS status,
                    currency,
                    amount_cents AS subtotal,
                    0::bigint AS vat_total,
                    amount_cents AS total,
                    line_items::text AS line_items,
                    '{}'::text AS billing_address,
                    created_at AS issued_at,
                    due_date AS due_at,
                    paid_at,
                    period_start,
                    period_end,
                    NULL::text AS purchase_order_number,
                    NULL::text AS notes,
                    NULL::text AS pdf_url,
                    NULL::text AS xml_url,
                    created_at,
                    updated_at
                FROM invoices
                WHERE id::text = $1 AND tenant_id = $2
                LIMIT 1
                "#,
            )
            .bind(id)
            .bind(tenant_id)
            .fetch_all(pool)
            .await
        }
        Err(error) => Err(error),
    }
}

fn parse_billing_interval(interval: &str) -> BillingInterval {
    match interval {
        "yearly" => BillingInterval::Yearly,
        _ => BillingInterval::Monthly,
    }
}

// Replaced by billing_common::proration::ceil_day_count

fn preview_plan_proration(
    config: &BillingConfig,
    current_plan: &Plan,
    new_plan: &Plan,
    subscription: &RouteSubscription,
) -> Result<LegacyProrationDto, String> {
    let now = Utc::now();
    let days_in_period = proration::ceil_day_count(
        subscription
            .current_period_end
            .signed_duration_since(subscription.current_period_start)
            .num_milliseconds(),
    );
    if days_in_period <= 0 {
        return Err("Invalid period: daysInPeriod must be greater than 0".into());
    }

    // Elapsed time must be floored: ceil-ing BOTH elapsed and period length
    // discards up to a full day of remaining time and systematically
    // overcharges (see billing_common::proration, which pins this in tests).
    let days_elapsed = proration::floor_day_count(
        now.signed_duration_since(subscription.current_period_start)
            .num_milliseconds(),
    );
    let days_remaining = (days_in_period - days_elapsed).max(0);
    let is_yearly = matches!(subscription.billing_interval, BillingInterval::Yearly);
    let current_price_numerator = if is_yearly {
        current_plan.price_yearly
    } else {
        current_plan.price_monthly
    };
    let new_price_numerator = if is_yearly {
        new_plan.price_yearly
    } else {
        new_plan.price_monthly
    };
    // Display-only: the monthly-equivalent rate for the explanation strings.
    let price_divisor = if is_yearly { 12 } else { 1 };

    // Money math goes through proration::prorated_amount (i128, half-up,
    // overflow-checked) — never f64.
    let credit_amount =
        proration::prorated_amount(current_price_numerator, days_remaining, days_in_period)?;
    let charge_amount =
        proration::prorated_amount(new_price_numerator, days_remaining, days_in_period)?;
    let net_amount = charge_amount - credit_amount;

    if net_amount > config.max_proration_charge_cents {
        return Err(format!(
            "Proration charge exceeds maximum allowed: €{} > €{}. Please contact support for assistance with this plan change.",
            cents_to_decimal_string(net_amount),
            cents_to_decimal_string(config.max_proration_charge_cents),
        ));
    }

    if net_amount < 0 && net_amount.abs() > config.max_proration_credit_cents {
        return Err(format!(
            "Proration credit exceeds maximum allowed: €{} > €{}. Please contact support for assistance with this plan change.",
            cents_to_decimal_string(net_amount.abs()),
            cents_to_decimal_string(config.max_proration_credit_cents),
        ));
    }

    let warnings = if net_amount > config.warn_proration_charge_cents {
        Some(vec![format!(
            "This plan change will result in a charge of €{}. Please confirm this is intended.",
            cents_to_decimal_string(net_amount),
        )])
    } else {
        None
    };

    Ok(LegacyProrationDto {
        credit_amount,
        charge_amount,
        net_amount,
        current_plan_days_remaining: days_remaining,
        new_plan_days_in_period: days_remaining,
        effective_date: now,
        explanation: proration::build_proration_explanation(
            &current_plan.display_name,
            &new_plan.display_name,
            current_price_numerator / price_divisor,
            new_price_numerator / price_divisor,
            days_remaining,
            days_in_period,
            credit_amount,
            charge_amount,
            net_amount,
        ),
        warnings,
    })
}

// Replaced by billing_common::proration::build_proration_explanation

#[cfg(test)]
fn generate_audit_log_id() -> String {
    Uuid::new_v4()
        .simple()
        .to_string()
        .chars()
        .take(26)
        .collect()
}

#[cfg(test)]
fn compute_audit_log_hash(
    tenant_id: &str,
    action: &str,
    resource_type: &str,
    resource_id: Option<&str>,
    metadata: &serde_json::Value,
    previous_hash: Option<&str>,
    timestamp: chrono::DateTime<Utc>,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(tenant_id.as_bytes());
    hasher.update(b"|");
    hasher.update(action.as_bytes());
    hasher.update(b"|");
    hasher.update(resource_type.as_bytes());
    hasher.update(b"|");
    hasher.update(resource_id.unwrap_or_default().as_bytes());
    hasher.update(b"|");
    hasher.update(metadata.to_string().as_bytes());
    hasher.update(b"|");
    hasher.update(previous_hash.unwrap_or_default().as_bytes());
    hasher.update(b"|");
    hasher.update(timestamp.to_rfc3339().as_bytes());
    format!("{:x}", hasher.finalize())
}

async fn get_route_subscription(
    pool: &sqlx::PgPool,
    tenant_id: &str,
) -> Result<Option<RouteSubscription>, ApiError> {
    // The legacy `subscriptions` table is never populated in production; the
    // live record is `stripe_subscriptions`. Read the live table first and
    // fall back to the legacy one only for old deployments.
    let row: Option<RouteSubscriptionRow> = sqlx::query_as(
        r#"
        SELECT plan AS plan_name, billing_interval,
               billing_cycle_start AS current_period_start,
               billing_cycle_end AS current_period_end
        FROM stripe_subscriptions
        WHERE tenant_id = $1
          AND status IN ('active', 'trialing', 'past_due')
        ORDER BY created_at DESC
        LIMIT 1
        "#,
    )
    .bind(tenant_id)
    .fetch_optional(pool)
    .await?;

    if let Some(row) = row {
        return Ok(Some(row.into_subscription()));
    }

    let legacy: Option<RouteSubscriptionRow> = sqlx::query_as(
        r#"
        SELECT plan_name, billing_interval, current_period_start, current_period_end
        FROM subscriptions
        WHERE tenant_id = $1
          AND status IN ('active', 'trialing', 'past_due')
        ORDER BY created_at DESC
        LIMIT 1
        "#,
    )
    .bind(tenant_id)
    .fetch_optional(pool)
    .await?;

    Ok(legacy.map(RouteSubscriptionRow::into_subscription))
}

/// The platform bills exclusively in EUR; the legacy `*CostUsd` JSON field
/// names are kept for API compatibility but the value is a euro amount,
/// matching billing-service's PAYG payload (tests there assert "€..." values).
fn cents_to_usd_string(cents: i64) -> String {
    format!("€{}", cents_to_decimal_string(cents))
}

fn validate_non_negative(value: i64, field_name: &str) -> Result<u64, ApiError> {
    if value < 0 {
        return Err(ApiError::Validation(vec![format!(
            "{field_name} must be non-negative"
        )]));
    }

    Ok(value as u64)
}

fn billing_success(data: serde_json::Value) -> Json<ApiResponse<serde_json::Value>> {
    success(data)
}

fn billing_success_response(data: serde_json::Value) -> Response {
    billing_success(data).into_response()
}

fn payg_pricing_payload(pricing: &PaygPricing) -> serde_json::Value {
    serde_json::json!({
        "emailPricing": pricing
            .email_tiers
            .iter()
            .map(|tier| serde_json::json!({
                "upTo": if tier.up_to == u64::MAX { None } else { Some(tier.up_to) },
                "pricePerEmailMillicents": tier.price_per_email_millicents,
            }))
            .collect::<Vec<_>>(),
        "apiPricing": {
            "freeCallsPerMonth": pricing.free_api_calls_per_month,
            "pricePerThousandCallsCents": pricing.price_per_thousand_api_calls,
        },
        "minimumMonthlyChargeCents": MINIMUM_MONTHLY_CHARGE_CENTS,
    })
}

fn payg_cost_payload(
    pricing: &PaygPricing,
    emails_sent: u64,
    api_calls: u64,
) -> Result<serde_json::Value, ApiError> {
    let (email_cost_cents, api_cost_cents, total_cost_cents) = pricing
        .calculate(emails_sent, api_calls)
        .map_err(|err| ApiError::Validation(vec![err.to_string()]))?;
    let capped_total = total_cost_cents.max(MINIMUM_MONTHLY_CHARGE_CENTS);

    Ok(serde_json::json!({
        "emailCostCents": email_cost_cents,
        "apiCostCents": api_cost_cents,
        "totalCostCents": capped_total,
        "emailCostUsd": cents_to_usd_string(email_cost_cents),
        "apiCostUsd": cents_to_usd_string(api_cost_cents),
        "totalCostUsd": cents_to_usd_string(capped_total),
    }))
}

async fn list_plans(
    State(state): State<AppState>,
) -> Result<Json<ApiResponse<serde_json::Value>>, ApiError> {
    let available_plans = plans::get_active_plans(&state.db).await?;
    let payload: Vec<LegacyPlanDto> = available_plans.into_iter().map(Into::into).collect();
    Ok(billing_success(serde_json::json!({ "plans": payload })))
}

async fn get_plan(
    State(state): State<AppState>,
    Path(plan_id): Path<String>,
) -> Result<Json<ApiResponse<serde_json::Value>>, ApiError> {
    let plan = plans::get_plan_by_name(&state.db, &plan_id).await?;
    match plan {
        Some(plan) => Ok(billing_success(serde_json::to_value(LegacyPlanDto::from(
            plan,
        ))?)),
        None => Err(ApiError::NotFound("Plan not found".into())),
    }
}

async fn get_current_plan(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<Json<ApiResponse<serde_json::Value>>, ApiError> {
    let plan = plans::get_plan_for_tenant(&state.db, &auth.tenant_id).await?;
    match plan {
        Some(plan) => Ok(billing_success(serde_json::to_value(
            LegacyPlanLimitsDto::from(&plan),
        )?)),
        None => Ok(billing_success(serde_json::Value::Null)),
    }
}

async fn get_plan_feature(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(feature): Path<String>,
) -> Result<Json<ApiResponse<serde_json::Value>>, ApiError> {
    let plan = plans::get_plan_for_tenant(&state.db, &auth.tenant_id).await?;
    let has_access = plan
        .map(|plan| feature_has_access(&LegacyPlanFeaturesPayload::from(plan.features), &feature))
        .unwrap_or(false);

    Ok(billing_success(serde_json::json!({
        "feature": feature,
        "hasAccess": has_access,
    })))
}

async fn get_plan_features(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<Json<ApiResponse<serde_json::Value>>, ApiError> {
    let plan = plans::get_plan_for_tenant(&state.db, &auth.tenant_id).await?;
    match plan {
        Some(plan) => Ok(billing_success(serde_json::to_value(
            LegacyPlanFeaturesPayload::from(plan.features),
        )?)),
        None => Ok(billing_success(serde_json::json!({}))),
    }
}

async fn get_plan_limits(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<Json<ApiResponse<serde_json::Value>>, ApiError> {
    get_current_plan(State(state), auth).await
}

async fn compare_plans(
    State(state): State<AppState>,
    Path((plan_id1, plan_id2)): Path<(String, String)>,
) -> Result<Json<ApiResponse<serde_json::Value>>, ApiError> {
    let plan1 = plans::get_plan_by_name(&state.db, &plan_id1).await?;
    let plan2 = plans::get_plan_by_name(&state.db, &plan_id2).await?;

    match (plan1, plan2) {
        (Some(plan1), Some(plan2)) => {
            let plan1_features = LegacyPlanFeaturesPayload::from(plan1.features.clone());
            let plan2_features = LegacyPlanFeaturesPayload::from(plan2.features.clone());
            Ok(billing_success(serde_json::json!({
                "plan1": {
                    "id": plan1.id,
                    "name": plan1.name,
                    "priceMonthly": plan1.price_monthly,
                    "features": plan1_features,
                    "limits": {
                        "emailLimit": plan1.email_limit,
                        "apiCallsPerMonth": plan1.api_call_limit,
                    }
                },
                "plan2": {
                    "id": plan2.id,
                    "name": plan2.name,
                    "priceMonthly": plan2.price_monthly,
                    "features": plan2_features,
                    "limits": {
                        "emailLimit": plan2.email_limit,
                        "apiCallsPerMonth": plan2.api_call_limit,
                    }
                },
                "differences": {
                    "priceDifference": plan2.price_monthly - plan1.price_monthly,
                    "featureDifferences": comparison_differences(
                        &LegacyPlanFeaturesPayload::from(plan1.features),
                        &LegacyPlanFeaturesPayload::from(plan2.features),
                    ),
                }
            })))
        }
        _ => Err(ApiError::NotFound("One or both plans not found".into())),
    }
}

async fn get_payg_pricing() -> Json<ApiResponse<serde_json::Value>> {
    let pricing = PaygPricing::default();
    billing_success(payg_pricing_payload(&pricing))
}

async fn get_usage(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<Json<ApiResponse<serde_json::Value>>, ApiError> {
    let now = Utc::now();
    let month_start_date = now.date_naive().with_day(1).unwrap_or(now.date_naive());
    let period_start = month_start_date.and_time(NaiveTime::MIN).and_utc();
    let period_end = period_start + Months::new(1);

    let payload = cached_usage_payload_for_period(
        &state,
        &auth.tenant_id,
        period_start,
        period_end,
        "summary",
    )
    .await?;

    Ok(billing_success(payload))
}

async fn get_realtime_usage_counter(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(metric): Path<String>,
) -> Result<Response, ApiError> {
    if !matches!(metric.as_str(), "emails_sent" | "api_calls") {
        return Ok((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "Invalid metric" })),
        )
            .into_response());
    }

    let event_type = match metric.as_str() {
        "emails_sent" => MeterEventType::EmailsSent,
        _ => MeterEventType::ApiCalls,
    };

    // F7: read the counter the quota gate actually enforces. For subscribed
    // tenants the gate meters the billing-cycle-anchored key
    // (`meter:rt:...:c{year}-{month}`), not the calendar-month key, so the
    // dashboard must ask billing-service for the exact enforced key instead
    // of re-deriving (and drifting from) the key shape. Source fn:
    // billing_service::usage::enforced_counter_key (exported for this
    // exact purpose).
    let now = Utc::now();
    let key = usage::enforced_counter_key(&state.db, &auth.tenant_id, event_type, now).await;
    let period = usage_counter_period_label(&key);
    let mut conn = state.redis.get().await?;
    let value: Option<i64> = conn.get(&key).await.map_err(ApiError::from)?;

    Ok(billing_success_response(serde_json::json!({
        "metric": metric,
        "count": value.unwrap_or(0),
        "period": period,
    })))
}

/// Extract the period label from a realtime counter key. Anchored keys look
/// like `meter:rt:{tenant}:{metric}:c2026-03` (note the `c` prefix on the
/// cycle label); legacy calendar keys are `meter:rt:{tenant}:{metric}:2026-03`.
/// The `c` is stripped so the label stays comparable across both shapes. A
/// final segment that is not a `YYYY-MM` label (malformed key) falls back to
/// the current calendar month.
fn usage_counter_period_label(counter_key: &str) -> String {
    let suffix = counter_key.rsplit(':').next().unwrap_or_default();
    let label = suffix.strip_prefix('c').unwrap_or(suffix);
    let bytes = label.as_bytes();
    let looks_like_period = bytes.len() == 7
        && bytes[..4].iter().all(|b| b.is_ascii_digit())
        && bytes[4] == b'-'
        && bytes[5..].iter().all(|b| b.is_ascii_digit());

    if looks_like_period {
        label.to_string()
    } else {
        format!("{}-{:02}", Utc::now().year(), Utc::now().month())
    }
}

async fn estimate_payg_cost(
    Json(body): Json<PaygEstimateBody>,
) -> Result<Json<ApiResponse<serde_json::Value>>, ApiError> {
    let emails_sent = validate_non_negative(body.emails_sent, "emailsSent")?;
    let api_calls = validate_non_negative(body.api_calls, "apiCalls")?;
    let pricing = PaygPricing::default();

    Ok(billing_success(serde_json::json!({
        "usage": {
            "emailsSent": emails_sent,
            "apiCalls": api_calls,
        },
        "cost": payg_cost_payload(&pricing, emails_sent, api_calls)?,
        "pricing": payg_pricing_payload(&pricing),
    })))
}

async fn get_payg_usage(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<Json<ApiResponse<serde_json::Value>>, ApiError> {
    let now = Utc::now();
    let month_start_date = now.date_naive().with_day(1).unwrap_or(now.date_naive());
    let period_start = month_start_date.and_time(NaiveTime::MIN).and_utc();
    let period_end = period_start + Months::new(1);

    let usage_payload =
        cached_usage_payload_for_period(&state, &auth.tenant_id, period_start, period_end, "payg")
            .await?;
    let billing_cycle_usage = usage_payload
        .get("billingCycleUsage")
        .and_then(|value| value.as_object())
        .cloned()
        .unwrap_or_default();
    let emails_sent = billing_cycle_usage
        .get("emailsSent")
        .and_then(|value| value.as_i64())
        .unwrap_or_default()
        .max(0) as u64;
    let api_calls = billing_cycle_usage
        .get("apiCalls")
        .and_then(|value| value.as_i64())
        .unwrap_or_default()
        .max(0) as u64;
    let pricing = PaygPricing::default();

    Ok(billing_success(serde_json::json!({
        "period": {
            "start": period_start.to_rfc3339(),
            "end": period_end.to_rfc3339(),
        },
        "usage": {
            "emailsSent": emails_sent,
            "apiCalls": api_calls,
        },
        "cost": payg_cost_payload(&pricing, emails_sent, api_calls)?,
        "pricing": payg_pricing_payload(&pricing),
    })))
}

async fn estimate_overage_cost(
    State(state): State<AppState>,
    Json(body): Json<OverageEstimateBody>,
) -> Result<Json<ApiResponse<serde_json::Value>>, ApiError> {
    let emails_sent = validate_non_negative(body.emails_sent, "emailsSent")? as i64;
    if body.email_limit < 0 {
        return Err(ApiError::Validation(vec![
            "emailLimit must be non-negative".into(),
        ]));
    }

    // Fix I13 mirror (billing-service routes.rs) — recompute the limit
    // server-side when a tenant is named: a client-supplied limit is only a
    // display default, never the billing truth. The resolved limit honours
    // active admin plan overrides via plans::get_plan_for_tenant.
    let email_limit = match body.tenant_id.as_deref() {
        Some(tenant_id) => {
            plans::get_plan_for_tenant(&state.db, tenant_id)
                .await?
                .map(|plan| plan.email_limit)
                // Unknown tenant: fall back to the validated client value
                // (legacy callers) — the estimate is advisory.
                .unwrap_or(body.email_limit)
        }
        None => body.email_limit,
    };

    // The deployed overage rate (env-configurable), not a hardcoded 40 —
    // must quote the same rate the overage sweep invoices with.
    let overage_cost_cents = plans::calculate_overage_cost_with_rate(
        emails_sent,
        email_limit,
        billing_service::config::configured_overage_rate_millicents(),
    );

    Ok(billing_success(serde_json::json!({
        "usage": {
            "emailsSent": emails_sent,
            "emailLimit": email_limit,
        },
        "overageCostCents": overage_cost_cents,
        "overageCostUsd": cents_to_usd_string(overage_cost_cents),
    })))
}

async fn configure_usage_alerts(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(body): Json<UsageAlertThresholdsBody>,
) -> Result<Response, ApiError> {
    crate::middleware::auth::require_scopes(&auth, &["billing:write"])?;
    if body.thresholds.is_empty() {
        return Ok((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "At least one threshold is required" })),
        )
            .into_response());
    }

    let mut created = Vec::with_capacity(body.thresholds.len());
    for threshold in body.thresholds {
        if !validate_usage_alert_metric(&threshold.metric_type) {
            return Ok((
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": "Invalid metricType" })),
            )
                .into_response());
        }
        if !(1..=100).contains(&threshold.threshold_percent) {
            return Ok((
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": "thresholdPercent must be between 1 and 100" })),
            )
                .into_response());
        }
        if !validate_usage_alert_channel(&threshold.notification_channel) {
            return Ok((
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": "Invalid notificationChannel" })),
            )
                .into_response());
        }

        let row = sqlx::query_as::<_, UsageAlertThresholdRow>(
            r#"
            INSERT INTO usage_alert_configs (
                id, tenant_id, metric_type, threshold_percent, notification_channel, enabled
            ) VALUES (
                gen_random_uuid(), $1, $2, $3, $4, true
            )
            ON CONFLICT (tenant_id, metric_type, threshold_percent)
            DO UPDATE SET notification_channel = $4, enabled = true, updated_at = NOW()
            RETURNING id::text, tenant_id, metric_type, threshold_percent, notification_channel, enabled, last_triggered_at
            "#,
        )
        .bind(&auth.tenant_id)
        .bind(&threshold.metric_type)
        .bind(threshold.threshold_percent)
        .bind(&threshold.notification_channel)
        .fetch_one(&state.db)
        .await?;

        created.push(UsageAlertThresholdDto::from(row));
    }

    Ok((
        StatusCode::CREATED,
        billing_success(serde_json::to_value(created)?),
    )
        .into_response())
}

async fn create_checkout_session(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(body): Json<CheckoutSessionBody>,
) -> Result<Response, ApiError> {
    crate::middleware::auth::require_scopes(&auth, &["billing:write"])?;
    let price_id = body.price_id.trim();
    if price_id.is_empty() || price_id.len() > 128 {
        return Ok((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "priceId is required" })),
        )
            .into_response());
    }

    // Never forward an arbitrary Stripe price identifier supplied by a
    // customer. The price must map to an active ApexMail plan in our catalog,
    // which prevents cross-product purchases and makes the plan selection
    // independently verifiable when the webhook arrives.
    let plan_name = match active_plan_name_for_stripe_price(&state.db, price_id).await? {
        Some(plan_name) => plan_name,
        None => {
            return Ok((
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": "Unsupported priceId" })),
            )
                .into_response())
        }
    };

    if !is_allowed_billing_redirect_url(&body.success_url, state.config.environment) {
        return Ok((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "Redirect URL must belong to apexmail.ee domain" })),
        )
            .into_response());
    }
    if !is_allowed_billing_redirect_url(&body.cancel_url, state.config.environment) {
        return Ok((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "Redirect URL must belong to apexmail.ee domain" })),
        )
            .into_response());
    }

    let customer_id = match get_or_create_stripe_customer_id(&state, &auth.tenant_id).await {
        Ok(customer_id) => customer_id,
        Err(error) => {
            tracing::error!(tenant_id = %auth.tenant_id, error = %error, "Failed to resolve Stripe customer for checkout");
            return Ok(billing_operation_failed_response());
        }
    };

    let stripe = match StripeClient::from_env(&state.http_client) {
        Ok(stripe) => stripe,
        Err(error) => {
            tracing::error!(tenant_id = %auth.tenant_id, error = %error, "Failed to initialize Stripe client for checkout");
            return Ok(billing_operation_failed_response());
        }
    };

    let session = match stripe
        .form_post::<StripeCheckoutSessionResponse>(
            "/v1/checkout/sessions",
            &[
                ("customer", customer_id),
                ("payment_method_types[0]", "card".into()),
                ("line_items[0][price]", price_id.to_string()),
                ("line_items[0][quantity]", "1".into()),
                ("mode", "subscription".into()),
                ("success_url", body.success_url),
                ("cancel_url", body.cancel_url),
                ("metadata[tenant_id]", auth.tenant_id.clone()),
                ("metadata[plan_name]", plan_name.clone()),
                (
                    "subscription_data[metadata][tenant_id]",
                    auth.tenant_id.clone(),
                ),
                ("subscription_data[metadata][plan_name]", plan_name.clone()),
                ("allow_promotion_codes", "true".into()),
                ("billing_address_collection", "required".into()),
                ("tax_id_collection[enabled]", "true".into()),
            ],
            // Deterministic idempotency key so a retried checkout request
            // (client timeout, network blip) cannot mint duplicate sessions.
            Some(&format!(
                "checkout_{}_{}_{}",
                auth.tenant_id, plan_name, price_id
            )),
        )
        .await
    {
        Ok(session) => session,
        Err(error) => {
            tracing::error!(tenant_id = %auth.tenant_id, error = %error, "Failed to create Stripe checkout session");
            return Ok(billing_operation_failed_response());
        }
    };

    let Some(url) = session.url else {
        tracing::error!(tenant_id = %auth.tenant_id, session_id = %session.id, "Stripe checkout session returned without URL");
        return Ok(billing_operation_failed_response());
    };

    Ok(billing_success_response(serde_json::json!({
        "sessionId": session.id,
        "url": url,
    })))
}

/// Resolve a Stripe price only when it is attached to an active self-service
/// ApexMail plan. Enterprise and PAYG follow managed/contractual flows and
/// must not be purchased through the generic public Checkout endpoint.
/// Stripe webhooks separately resolve all active catalog prices before
/// granting an entitlement, so manual Enterprise subscriptions can still be
/// reconciled through their verified Stripe lifecycle.
async fn active_plan_name_for_stripe_price(
    pool: &sqlx::PgPool,
    price_id: &str,
) -> Result<Option<String>, sqlx::Error> {
    sqlx::query_scalar::<_, String>(
        r#"
        SELECT name
        FROM plans
        WHERE is_active = true
          AND (stripe_price_id_monthly = $1 OR stripe_price_id_yearly = $1)
        LIMIT 1
        "#,
    )
    .bind(price_id)
    .fetch_optional(pool)
    .await
    .map(|plan_name| {
        plan_name.filter(|plan_name| SELF_SERVE_CHECKOUT_PLAN_IDS.contains(&plan_name.as_str()))
    })
}

async fn create_portal_session(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(body): Json<PortalSessionBody>,
) -> Result<Response, ApiError> {
    if !is_allowed_billing_redirect_url(&body.return_url, state.config.environment) {
        return Ok((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "Redirect URL must belong to apexmail.ee domain" })),
        )
            .into_response());
    }

    let stripe_customer_id = match sqlx::query_scalar::<_, String>(
        "SELECT stripe_customer_id FROM stripe_customers WHERE tenant_id = $1",
    )
    .bind(&auth.tenant_id)
    .fetch_optional(&state.db)
    .await?
    {
        Some(stripe_customer_id) => stripe_customer_id,
        None => {
            tracing::error!(tenant_id = %auth.tenant_id, "Stripe portal requested without a Stripe customer");
            return Ok(billing_operation_failed_response());
        }
    };

    let stripe = match StripeClient::from_env(&state.http_client) {
        Ok(stripe) => stripe,
        Err(error) => {
            tracing::error!(tenant_id = %auth.tenant_id, error = %error, "Failed to initialize Stripe client for portal session");
            return Ok(billing_operation_failed_response());
        }
    };

    let session = match stripe
        .form_post::<StripePortalSessionResponse>(
            "/v1/billing_portal/sessions",
            &[
                ("customer", stripe_customer_id.clone()),
                ("return_url", body.return_url),
            ],
            // Retry-safe without serving a stale expired portal URL for a
            // full day: the key dedupes within the current hour only.
            Some(&format!(
                "portal_{}_{}",
                auth.tenant_id,
                chrono::Utc::now().timestamp() / 3600
            )),
        )
        .await
    {
        Ok(session) => session,
        Err(error) => {
            tracing::error!(tenant_id = %auth.tenant_id, error = %error, "Failed to create Stripe portal session");
            return Ok(billing_operation_failed_response());
        }
    };

    Ok(billing_success_response(
        serde_json::json!({ "url": session.url }),
    ))
}

async fn get_proration_preview(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(plan_name): Path<String>,
) -> Result<Response, ApiError> {
    let subscription = match get_route_subscription(&state.db, &auth.tenant_id).await? {
        Some(subscription) => subscription,
        None => {
            return Ok((
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": "Cannot change plans: subscription status is unknown, must be 'active'" })),
            )
                .into_response())
        }
    };

    let current_plan = match plans::get_plan_by_name(&state.db, &subscription.plan_name).await? {
        Some(plan) => plan,
        None => {
            return Ok((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": "Operation failed" })),
            )
                .into_response())
        }
    };
    let new_plan = match plans::get_plan_by_name(&state.db, &plan_name).await? {
        Some(plan) => plan,
        None => {
            return Ok((
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({ "error": "New plan not found" })),
            )
                .into_response())
        }
    };

    match preview_plan_proration(
        &BillingConfig::default(),
        &current_plan,
        &new_plan,
        &subscription,
    ) {
        Ok(proration) => Ok(billing_success_response(serde_json::to_value(proration)?)),
        Err(error) => Ok((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": error })),
        )
            .into_response()),
    }
}

/// Direct mutation of a tenant's plan bypasses Stripe's payment confirmation
/// and webhook reconciliation. Keep the legacy endpoint as an explicit,
/// safe failure so old clients receive a deterministic migration signal rather
/// than an accidental paid entitlement.
fn checkout_required_response() -> Response {
    (
        StatusCode::CONFLICT,
        Json(serde_json::json!({
            "error": "Direct plan changes are disabled. Create a Stripe Checkout session and wait for the verified Stripe webhook before paid access is activated.",
            "code": "CHECKOUT_REQUIRED",
        })),
    )
        .into_response()
}

async fn switch_plan(
    State(_state): State<AppState>,
    auth: AuthUser,
    Json(body): Json<LegacySwitchPlanBody>,
) -> Result<Response, ApiError> {
    crate::middleware::auth::require_scopes(&auth, &["billing:write"])?;
    let _ = (&body.plan_name, body.billing_interval);

    tracing::warn!(
        tenant_id = %auth.tenant_id,
        "rejected direct billing plan transition; checkout and verified Stripe webhooks are required"
    );

    Ok(checkout_required_response())
}

fn billing_portal_required_response() -> Response {
    (
        StatusCode::CONFLICT,
        Json(serde_json::json!({
            "error": "Direct cancellation is disabled. Create a Stripe billing portal session and wait for the verified Stripe webhook before subscription access changes.",
            "code": "BILLING_PORTAL_REQUIRED",
        })),
    )
        .into_response()
}

async fn cancel_subscription_request(
    State(_state): State<AppState>,
    auth: AuthUser,
    Json(body): Json<LegacyCancelBody>,
) -> Result<Response, ApiError> {
    crate::middleware::auth::require_scopes(&auth, &["billing:write"])?;
    let _ = (body.reason, body.feedback, body.cancel_immediately);

    // Cancellation must be executed by Stripe (normally through the billing
    // portal) and then reconciled from a verified webhook. Updating the local
    // subscription record here can leave ApexMail and Stripe in different
    // states and may revoke access without a confirmed cancellation.
    tracing::warn!(
        tenant_id = %auth.tenant_id,
        "rejected direct subscription cancellation; Stripe billing portal and verified webhooks are required"
    );

    Ok(billing_portal_required_response())
}

async fn get_subscription(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<Response, ApiError> {
    let query = sqlx::query_as::<_, LegacyStripeSubscriptionRow>(
        r#"
        SELECT
            id::text AS id,
            tenant_id,
            stripe_subscription_id,
            stripe_customer_id,
            stripe_price_id,
            status::text AS status,
            billing_interval,
            billing_cycle_start,
            billing_cycle_end,
            cancel_at_period_end,
            canceled_at,
            trial_end,
            created_at,
            updated_at
        FROM stripe_subscriptions
        WHERE tenant_id = $1 AND status != 'canceled'
        ORDER BY created_at DESC
        LIMIT 1
        "#,
    )
    .bind(&auth.tenant_id);

    let subscription = match query.fetch_optional(&state.db).await {
        Ok(subscription) => subscription,
        Err(error) if is_postgres_error_code(&error, "42P01") => None,
        Err(error) => return Err(ApiError::from(error)),
    };

    match subscription {
        Some(subscription) => Ok(billing_success_response(serde_json::json!({
            "subscription": LegacyStripeSubscriptionDto::from(subscription),
        }))),
        None => Ok(billing_success_response(serde_json::json!({
            "subscription": null,
            "message": "No active subscription"
        }))),
    }
}

async fn list_invoices(
    State(state): State<AppState>,
    auth: AuthUser,
    Query(query): Query<BillingListQuery>,
) -> Result<Response, ApiError> {
    let limit = clamp_limit(query.limit.unwrap_or(50), 200);
    let offset = clamp_offset(query.offset.unwrap_or(0), 100_000);

    let total_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*)::bigint FROM invoices WHERE tenant_id = $1")
            .bind(&auth.tenant_id)
            .fetch_one(&state.db)
            .await?;

    let rows =
        query_invoice_list_rows_with_legacy_fallback(&state.db, &auth.tenant_id, limit, offset)
            .await?;

    let invoices: Vec<LegacyInvoiceDto> = rows.into_iter().map(map_invoice_row).collect();

    Ok(billing_success_response(serde_json::json!({
        "invoices": invoices,
        "totalCount": total_count,
        "limit": limit,
        "offset": offset,
    })))
}

async fn get_invoice(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    match load_legacy_invoice_detail(&state.db, &id, &auth.tenant_id).await? {
        Some(invoice) => Ok(billing_success_response(serde_json::to_value(invoice)?)),
        None => Ok((
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "Invoice not found" })),
        )
            .into_response()),
    }
}

async fn get_invoice_pdf_html(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    match load_legacy_invoice_detail(&state.db, &id, &auth.tenant_id).await? {
        Some(invoice) => Ok(invoice_html_response(&invoice)),
        None => Ok((
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "Invoice not found" })),
        )
            .into_response()),
    }
}

async fn get_invoice_xml(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    match load_legacy_invoice_detail(&state.db, &id, &auth.tenant_id).await? {
        Some(invoice) => {
            let mut response = render_invoice_xml(&invoice).into_response();
            response.headers_mut().insert(
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/xml"),
            );
            response.headers_mut().insert(
                header::CONTENT_DISPOSITION,
                HeaderValue::from_str(&format!(
                    "attachment; filename=\"invoice-{}.xml\"",
                    safe_invoice_filename(&invoice.invoice_number)
                ))
                .unwrap_or_else(|e| {
                    tracing::error!(error = %e, invoice = %invoice.invoice_number, "invalid invoice filename header, falling back to default");
                    HeaderValue::from_static("attachment; filename=\"invoice.xml\"")
                }),
            );
            Ok(response)
        }
        None => Ok((
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "Invoice not found" })),
        )
            .into_response()),
    }
}

async fn load_legacy_invoice_detail(
    pool: &sqlx::PgPool,
    id: &str,
    tenant_id: &str,
) -> Result<Option<LegacyInvoiceDto>, ApiError> {
    let rows = query_invoice_detail_rows_with_legacy_fallback(pool, id, tenant_id).await?;
    Ok(rows.into_iter().next().map(map_invoice_row))
}

async fn check_quota(State(state): State<AppState>, auth: AuthUser) -> Result<Response, ApiError> {
    let status = usage::check_quota(&state.db, &state.redis, &auth.tenant_id)
        .await
        .map_err(map_usage_error)?;

    Ok(billing_success_response(serde_json::to_value(status)?))
}

async fn admin_list_tenants(
    State(state): State<AppState>,
    auth: AuthUser,
    Query(query): Query<AdminTenantListQuery>,
) -> Result<Response, ApiError> {
    if let Err(response) = require_admin_access(&auth) {
        return Ok(response);
    }

    let limit = clamp_limit(query.limit.unwrap_or(50), 200);
    let offset = clamp_offset(query.offset.unwrap_or(0), 100_000);
    let valid_statuses = [
        "active",
        "past_due",
        "canceled",
        "trialing",
        "incomplete",
        "incomplete_expired",
        "unpaid",
        "paused",
    ];
    let status = query
        .status
        .filter(|value| valid_statuses.contains(&value.as_str()));

    let tenants: serde_json::Value = if let Some(status) = status {
        sqlx::query_scalar(
            r#"
            SELECT COALESCE(json_agg(row_to_json(tenant_row) ORDER BY tenant_row.created_at DESC), '[]'::json)
            FROM (
                SELECT
                    t.id,
                    t.name,
                    t.created_at,
                    s.status AS subscription_status,
                    s.current_period_end,
                    p.name AS plan_name,
                    d.status AS dunning_state,
                    w.balance AS wallet_balance
                FROM tenants t
                LEFT JOIN stripe_subscriptions s ON t.id = s.tenant_id
                LEFT JOIN plans p ON p.name = s.plan
                LEFT JOIN dunning_records d ON t.id = d.tenant_id
                LEFT JOIN wallets w ON t.id = w.tenant_id
                WHERE s.status = $1
                ORDER BY t.created_at DESC
                LIMIT $2 OFFSET $3
            ) tenant_row
            "#,
        )
        .bind(status)
        .bind(limit)
        .bind(offset)
        .fetch_one(&state.db)
        .await?
    } else {
        sqlx::query_scalar(
            r#"
            SELECT COALESCE(json_agg(row_to_json(tenant_row) ORDER BY tenant_row.created_at DESC), '[]'::json)
            FROM (
                SELECT
                    t.id,
                    t.name,
                    t.created_at,
                    s.status AS subscription_status,
                    s.current_period_end,
                    p.name AS plan_name,
                    d.status AS dunning_state,
                    w.balance AS wallet_balance
                FROM tenants t
                LEFT JOIN stripe_subscriptions s ON t.id = s.tenant_id
                LEFT JOIN plans p ON p.name = s.plan
                LEFT JOIN dunning_records d ON t.id = d.tenant_id
                LEFT JOIN wallets w ON t.id = w.tenant_id
                ORDER BY t.created_at DESC
                LIMIT $1 OFFSET $2
            ) tenant_row
            "#,
        )
        .bind(limit)
        .bind(offset)
        .fetch_one(&state.db)
        .await?
    };

    Ok(billing_success_response(serde_json::json!({
        "tenants": tenants,
        "limit": limit,
        "offset": offset,
    })))
}

async fn admin_get_tenant_details(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(tenant_id): Path<String>,
) -> Result<Response, ApiError> {
    if let Err(response) = require_admin_tenant_access(&auth, &tenant_id) {
        return Ok(response);
    }

    let subscription = match sqlx::query_as::<_, LegacyStripeSubscriptionRow>(
        r#"
        SELECT
            id::text AS id,
            tenant_id,
            stripe_subscription_id,
            stripe_customer_id,
            stripe_price_id,
            status::text AS status,
            billing_interval,
            billing_cycle_start,
            billing_cycle_end,
            cancel_at_period_end,
            canceled_at,
            trial_end,
            created_at,
            updated_at
        FROM stripe_subscriptions
        WHERE tenant_id = $1 AND status != 'canceled'
        ORDER BY created_at DESC
        LIMIT 1
        "#,
    )
    .bind(&tenant_id)
    .fetch_optional(&state.db)
    .await
    {
        Ok(subscription) => subscription.map(LegacyStripeSubscriptionDto::from),
        Err(error) if is_postgres_error_code(&error, "42P01") => None,
        Err(error) => return Err(ApiError::from(error)),
    };

    let plan = plans::get_plan_for_tenant(&state.db, &tenant_id)
        .await?
        .map(|plan| LegacyPlanLimitsDto::from(&plan));
    let dunning = get_dunning_state(&state, &tenant_id).await?;
    let wallet = get_or_create_wallet_balance(&state, &tenant_id).await?;
    let total_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*)::bigint FROM invoices WHERE tenant_id = $1")
            .bind(&tenant_id)
            .fetch_one(&state.db)
            .await?;
    let recent_invoices: Vec<LegacyInvoiceDto> =
        query_invoice_list_rows_with_legacy_fallback(&state.db, &tenant_id, 10, 0)
            .await?
            .into_iter()
            .map(map_invoice_row)
            .collect();

    Ok(billing_success_response(serde_json::json!({
        "tenantId": tenant_id,
        "subscription": subscription,
        "plan": plan,
        "dunning": dunning,
        "wallet": wallet,
        "recentInvoices": {
            "invoices": recent_invoices,
            "totalCount": total_count,
        },
    })))
}

async fn admin_apply_credit(
    State(state): State<AppState>,
    auth: AuthUser,
    headers: HeaderMap,
    Path(tenant_id): Path<String>,
    Json(body): Json<AdminCreditBody>,
) -> Result<Response, ApiError> {
    if let Err(response) = require_admin_tenant_access(&auth, &tenant_id) {
        return Ok(response);
    }
    if body.amount <= 0 {
        return Ok((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "Amount must be positive" })),
        )
            .into_response());
    }

    // F6: an explicit Idempotency-Key header is required. The previous
    // default (timestamp + UUID) was unique per request, so a retried or
    // duplicated admin credit was applied twice. The key is claimed via
    // Redis SET NX before the money moves, and the existing `reference`
    // column keeps storing it for auditability.
    let idempotency_key = headers
        .get("idempotency-key")
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|key| !key.is_empty())
        .ok_or_else(|| {
            ApiError::BadRequest(
                "Idempotency-Key header is required for admin wallet credits".into(),
            )
        })?;
    if idempotency_key.len() > 255 {
        return Ok((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "Idempotency-Key header must be at most 255 characters"
            })),
        )
            .into_response());
    }

    let claim_key = format!(
        "apexmail:billing:admin_credit_idem:{tenant_id}:{}",
        hash_token(idempotency_key)
    );
    let mut conn = state.redis.get().await.map_err(|error| {
        tracing::error!(error = %error, tenant_id = %tenant_id, "admin credit idempotency claim Redis unavailable");
        ApiError::ServiceUnavailable(
            "idempotency enforcement is temporarily unavailable".into(),
        )
    })?;
    let claimed: Option<String> = deadpool_redis::redis::cmd("SET")
        .arg(&claim_key)
        .arg("1")
        .arg("NX")
        .arg("EX")
        .arg(ADMIN_CREDIT_IDEMPOTENCY_TTL_SECS)
        .query_async(&mut conn)
        .await
        .map_err(|error| {
            tracing::error!(error = %error, tenant_id = %tenant_id, "admin credit idempotency claim failed");
            ApiError::ServiceUnavailable(
                "idempotency enforcement is temporarily unavailable".into(),
            )
        })?;
    if claimed.is_none() {
        // Fail closed: this is a money-minting endpoint, so when uniqueness
        // cannot be verified the duplicate is rejected rather than applied.
        return Ok((
            StatusCode::CONFLICT,
            Json(serde_json::json!({
                "error": "This Idempotency-Key has already been used for a credit on this tenant"
            })),
        )
            .into_response());
    }

    // Currency guard (mirrors credit_notes.rs): the credit lands in the
    // tenant's BILLING currency, and a wallet that already exists in a
    // DIFFERENT currency is refused instead of mixed — a 10 000-cent USD
    // credit in a EUR wallet is €100.00 of phantom money. New wallets are
    // created with the billing currency rather than the column's legacy
    // 'USD' default.
    let billing_currency = resolve_tenant_billing_currency(&state, &tenant_id).await;
    let existing_wallet_currency: Option<String> =
        sqlx::query_scalar("SELECT currency FROM wallets WHERE tenant_id = $1")
            .bind(&tenant_id)
            .fetch_optional(&state.db)
            .await?;
    if let Some(wallet_currency) = existing_wallet_currency {
        if !wallet_currency.eq_ignore_ascii_case(&billing_currency) {
            tracing::error!(
                tenant_id = %tenant_id,
                wallet_currency = %wallet_currency,
                billing_currency = %billing_currency,
                "admin wallet credit currency mismatch refused — refund via the payment provider instead"
            );
            return Ok((
                StatusCode::CONFLICT,
                Json(serde_json::json!({
                    "error": format!(
                        "Wallet currency {wallet_currency} does not match tenant billing currency {billing_currency}; refund via the payment provider instead"
                    )
                })),
            )
                .into_response());
        }
    }

    let transaction = sqlx::query_as::<_, LegacyWalletTransactionRow>(
        r#"
        WITH ensure_wallet AS (
            INSERT INTO wallets (tenant_id, balance, reserved, currency, created_at, updated_at)
            VALUES ($2, 0, 0, $5, NOW(), NOW())
            ON CONFLICT (tenant_id) DO UPDATE SET updated_at = wallets.updated_at
            RETURNING id AS wallet_id, tenant_id
        ),
        updated_wallet AS (
            UPDATE wallets
            SET balance = balance + $1::int8, updated_at = NOW()
            WHERE tenant_id = $2
            RETURNING id AS wallet_id, tenant_id, balance
        ),
        new_transaction AS (
            INSERT INTO wallet_transactions (
                id, tenant_id, wallet_id, type, amount, balance_after, description, reference, created_at
            )
            SELECT
                gen_random_uuid(),
                tenant_id,
                wallet_id,
                'credit',
                $1::int8,
                balance,
                $3,
                $4,
                NOW()
            FROM updated_wallet
            RETURNING id::text AS id, tenant_id, type::text AS transaction_type, amount::bigint,
                      balance_after::bigint AS balance, description, reference,
                      '{}'::jsonb AS metadata, created_at
        )
        SELECT id, tenant_id, transaction_type, amount, balance, description, reference, metadata, created_at
        FROM new_transaction
        "#,
    )
    .bind(body.amount)
    .bind(&tenant_id)
    .bind(format!("Admin credit: {}", body.reason))
    .bind(idempotency_key)
    .bind(&billing_currency)
    .fetch_one(&state.db)
    .await?;

    crate::audit_log::insert_audit_log(
        &state.db,
        Some(&tenant_id),
        None,
        "wallet.credit",
        "wallet",
        Some(&transaction.id),
        serde_json::json!({
            "amount": transaction.amount,
            "description": transaction.description,
            "reference": transaction.reference,
            "balanceAfter": transaction.balance,
        }),
        None,
        None,
    )
    .await?;

    invalidate_cache_key(&state, &format!("wallet:balance:{tenant_id}")).await;

    Ok((
        StatusCode::CREATED,
        billing_success(serde_json::to_value(LegacyWalletTransactionDto::from(
            transaction,
        ))?),
    )
        .into_response())
}

async fn admin_apply_plan_override(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(tenant_id): Path<String>,
    Json(body): Json<AdminPlanOverrideBody>,
) -> Result<Response, ApiError> {
    if let Err(response) = require_admin_tenant_access(&auth, &tenant_id) {
        return Ok(response);
    }
    let plan_id = body.plan_id.trim();
    let reason = body.reason.trim();
    if plan_id.is_empty() || reason.is_empty() {
        return Ok((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "planId and reason are required for an audited plan override"
            })),
        )
            .into_response());
    }
    let plan_exists = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM plans WHERE name = $1 AND is_active = true)",
    )
    .bind(plan_id)
    .fetch_one(&state.db)
    .await?;
    if !plan_exists {
        return Ok((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "Unknown or inactive planId" })),
        )
            .into_response());
    }
    let admin_id = admin_actor_id(&auth);
    let expires_at = body.expires_at.as_deref().and_then(parse_query_date);

    sqlx::query(
        r#"
        INSERT INTO plan_overrides (
            tenant_id, plan, plan_id, reason, admin_id, expires_at, created_at
        ) VALUES ($1, $2, $2, $3, $4, $5, NOW())
        ON CONFLICT (tenant_id) DO UPDATE SET
            plan = $2,
            plan_id = $2,
            reason = $3,
            admin_id = $4,
            expires_at = $5,
            updated_at = NOW()
        "#,
    )
    .bind(&tenant_id)
    .bind(plan_id)
    .bind(reason)
    .bind(&admin_id)
    .bind(expires_at)
    .execute(&state.db)
    .await?;

    let actor_id: Option<uuid::Uuid> = uuid::Uuid::parse_str(&admin_id).ok();
    sqlx::query(
        r#"
        INSERT INTO billing_audit_log (
            tenant_id, action, actor_id, actor_type, details, created_at
        ) VALUES ($1, $2, $3, $4, $5, NOW())
        "#,
    )
    .bind(&tenant_id)
    .bind("plan_override")
    .bind(actor_id)
    .bind("admin")
    .bind(serde_json::json!({
        "planId": plan_id,
        "reason": reason,
        "expiresAt": body.expires_at,
    }))
    .execute(&state.db)
    .await?;

    Ok(billing_success_response(serde_json::json!({
        "success": true,
        "message": "Plan override applied"
    })))
}

async fn admin_force_subscription_status(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(tenant_id): Path<String>,
    Json(body): Json<AdminSubscriptionStatusBody>,
) -> Result<Response, ApiError> {
    if let Err(response) = require_admin_tenant_access(&auth, &tenant_id) {
        return Ok(response);
    }

    let allowed_statuses = ["active", "past_due", "canceled", "suspended"];
    if !allowed_statuses.contains(&body.status.as_str()) {
        return Ok((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "Invalid subscription status" })),
        )
            .into_response());
    }

    let admin_id = admin_actor_id(&auth);
    let mut tx = state.db.begin().await?;

    let update = sqlx::query(
        r#"
        UPDATE stripe_subscriptions
        SET status = $2,
            admin_override_at = NOW(),
            admin_override_by = $3,
            admin_override_reason = $4
        WHERE tenant_id = $1
        "#,
    )
    .bind(&tenant_id)
    .bind(&body.status)
    .bind(&admin_id)
    .bind(&body.reason)
    .execute(&mut *tx)
    .await?;

    if update.rows_affected() != 1 {
        return Ok((
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "Subscription not found for tenant" })),
        )
            .into_response());
    }

    let actor_id: Option<uuid::Uuid> = uuid::Uuid::parse_str(&admin_id).ok();
    sqlx::query(
        r#"
        INSERT INTO billing_audit_log (
            tenant_id, action, actor_id, actor_type, details, created_at
        ) VALUES ($1, $2, $3, $4, $5, NOW())
        "#,
    )
    .bind(&tenant_id)
    .bind("subscription_status_override")
    .bind(actor_id)
    .bind("admin")
    .bind(serde_json::json!({ "newStatus": body.status, "reason": body.reason }))
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;

    Ok(billing_success_response(serde_json::json!({
        "success": true,
        "message": "Subscription status updated"
    })))
}

async fn admin_reset_dunning(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(tenant_id): Path<String>,
    Json(body): Json<AdminDunningResetBody>,
) -> Result<Response, ApiError> {
    if let Err(response) = require_admin_tenant_access(&auth, &tenant_id) {
        return Ok(response);
    }

    let admin_id = admin_actor_id(&auth);
    let mut tx = state.db.begin().await?;

    sqlx::query(
        r#"
        WITH update_dunning AS (
            UPDATE dunning_records
            SET status = 'healthy',
                failed_payment_count = 0,
                first_failed_at = NULL,
                last_failed_at = NULL,
                next_retry_at = NULL,
                suspended_at = NULL,
                grace_period_ends_at = NULL,
                updated_at = NOW()
            WHERE tenant_id = $1
            RETURNING tenant_id
        ),
        log_recovery AS (
            INSERT INTO dunning_events (id, tenant_id, event_type, created_at)
            VALUES (gen_random_uuid(), $1, 'payment_recovered', NOW())
            RETURNING tenant_id
        ),
        reactivate_tenant AS (
            UPDATE tenants
            SET status = 'active', updated_at = NOW()
            WHERE id = $1
              AND NOT EXISTS (
                SELECT 1 FROM abuse_reports ar
                WHERE ar.tenant_id = $1 AND ar.status IN ('open', 'investigating', 'confirmed')
              )
            RETURNING id
        )
        SELECT 1
        "#,
    )
    .bind(&tenant_id)
    .execute(&mut *tx)
    .await?;

    let _released_count: i64 = sqlx::query_scalar(
        r#"
        WITH updated AS (
            UPDATE messages
            SET status = 'queued', updated_at = NOW()
            WHERE tenant_id = $1 AND status = 'dunning_queued'
            RETURNING id
        )
        SELECT COUNT(*)::bigint FROM updated
        "#,
    )
    .bind(&tenant_id)
    .fetch_one(&mut *tx)
    .await?;

    let actor_id: Option<uuid::Uuid> = uuid::Uuid::parse_str(&admin_id).ok();
    sqlx::query(
        r#"
        INSERT INTO billing_audit_log (
            tenant_id, action, actor_id, actor_type, details, created_at
        ) VALUES ($1, $2, $3, $4, $5, NOW())
        "#,
    )
    .bind(&tenant_id)
    .bind("dunning_reset")
    .bind(actor_id)
    .bind("admin")
    .bind(serde_json::json!({ "reason": body.reason }))
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;
    invalidate_cache_key(&state, &format!("dunning:status:{tenant_id}")).await;

    Ok(billing_success_response(serde_json::json!({
        "success": true,
        "message": "Dunning state reset"
    })))
}

async fn admin_create_invoice(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(tenant_id): Path<String>,
    Json(body): Json<AdminCreateInvoiceBody>,
) -> Result<Response, ApiError> {
    if let Err(response) = require_admin_tenant_access(&auth, &tenant_id) {
        return Ok(response);
    }

    let Some(period_start) = parse_query_date(&body.period_start) else {
        return Ok((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "Invalid periodStart" })),
        )
            .into_response());
    };
    let Some(period_end) = parse_query_date(&body.period_end) else {
        return Ok((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "Invalid periodEnd" })),
        )
            .into_response());
    };

    let mut tx = state.db.begin().await?;
    let period_lock_key = format!("{}:{}", period_start.to_rfc3339(), period_end.to_rfc3339());

    sqlx::query("SELECT pg_advisory_xact_lock(hashtext($1), hashtext($2))")
        .bind(&tenant_id)
        .bind(&period_lock_key)
        .execute(&mut *tx)
        .await?;

    let existing: Option<(String, String, String)> = sqlx::query_as(
        r#"
        SELECT id::text, invoice_number, status::text
        FROM invoices
        WHERE tenant_id = $1
          AND period_start = $2
          AND period_end = $3
          AND status NOT IN ('void')
        LIMIT 1
        "#,
    )
    .bind(&tenant_id)
    .bind(period_start)
    .bind(period_end)
    .fetch_optional(&mut *tx)
    .await?;

    if let Some((existing_invoice_id, invoice_number, status)) = existing {
        return Ok((
            StatusCode::CONFLICT,
            Json(serde_json::json!({
                "error": "Invoice already exists for this period",
                "existingInvoiceId": existing_invoice_id,
                "invoiceNumber": invoice_number,
                "status": status,
            })),
        )
            .into_response());
    }

    let tenant_exists: Option<String> = sqlx::query_scalar("SELECT id FROM tenants WHERE id = $1")
        .bind(&tenant_id)
        .fetch_optional(&mut *tx)
        .await?;
    if tenant_exists.is_none() {
        return Ok((
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "Tenant not found" })),
        )
            .into_response());
    }

    let address = match sqlx::query_as::<_, AdminBillingAddressRow>(
        r#"
        SELECT company_name, vat_number, address_line1, address_line2,
               city, state, postal_code, country, email
        FROM billing_addresses WHERE tenant_id = $1
        "#,
    )
    .bind(&tenant_id)
    .fetch_optional(&mut *tx)
    .await?
    {
        Some(address) => address,
        None => {
            return Ok((
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": "Billing address not found" })),
            )
                .into_response())
        }
    };

    let billing_address = LegacyBillingAddressDto {
        company_name: address.company_name,
        vat_number: address.vat_number,
        address_line1: address.address_line1,
        address_line2: address.address_line2,
        city: address.city,
        state: address.state,
        postal_code: address.postal_code,
        country: address.country,
        email: address.email,
    };

    // EU/Estonian VAT requires unique, sequential invoice numbers; the admin
    // path shares the platform sequence (YYYY-NNNNNN) instead of minting
    // random, gapped numbers that interleave with the sequence-based ones.
    let invoice_number = billing_service::invoices::generate_invoice_number(&state.db)
        .await
        .map_err(|error| ApiError::BadRequest(format!("invoice numbering failed: {error}")))?;

    // Line-item validation (audit 2): quantity must be strictly positive,
    // unit price non-negative, and each line total computed with checked
    // multiplication — the previous unchecked `quantity * unit_price`
    // accepted negative quantities/prices (negative totals netting out
    // other lines) and could overflow.
    let mut base_line_items: Vec<(String, i64, i64, i64)> = Vec::with_capacity(body.line_items.len());
    for item in &body.line_items {
        if item.quantity <= 0 {
            return Ok((
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": "Line item quantity must be greater than zero"
                })),
            )
                .into_response());
        }
        if item.unit_price < 0 {
            return Ok((
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": "Line item unitPrice must be non-negative"
                })),
            )
                .into_response());
        }
        let amount = item
            .quantity
            .checked_mul(item.unit_price)
            .ok_or_else(|| ApiError::Validation(vec!["Line total overflows".into()]))?;
        base_line_items.push((
            item.description.clone(),
            item.quantity,
            item.unit_price,
            amount,
        ));
    }
    let subtotal: i64 = base_line_items
        .iter()
        .map(|(_, _, _, amount)| *amount)
        .sum();
    if subtotal < 0 {
        return Ok((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "Invoice subtotal must be non-negative"
            })),
        )
            .into_response());
    }
    let (vat_rate, vat_total) = billing_service::invoices::calculate_vat(
        subtotal,
        &billing_address.country,
        billing_address.vat_number.as_deref(),
    );

    // Single platform VAT allocator (round half-up per line, reconcile the
    // final line to the rounded total) — must not diverge from
    // billing-service's invoice writer.
    let amounts: Vec<i64> = base_line_items
        .iter()
        .map(|(_, _, _, amount)| *amount)
        .collect();
    let vat_per_line = billing_service::invoices::allocate_vat_across_lines(&amounts, vat_rate);
    let line_items: Vec<LegacyInvoiceLineItemDto> = base_line_items
        .iter()
        .zip(vat_per_line.iter())
        .map(
            |((description, quantity, unit_price, amount), vat_amount)| LegacyInvoiceLineItemDto {
                description: description.clone(),
                quantity: *quantity,
                unit_price: *unit_price,
                amount: *amount,
                vat_rate,
                vat_amount: *vat_amount,
            },
        )
        .collect();

    let total = subtotal + vat_total;
    let now = Utc::now();
    let due_at = now + chrono::Duration::days(DEFAULT_NET_DAYS);
    let currency = resolve_tenant_billing_currency(&state, &tenant_id).await;

    let inserted: (String, chrono::DateTime<Utc>, chrono::DateTime<Utc>) = sqlx::query_as(
        r#"
        INSERT INTO invoices (
            id, tenant_id, stripe_invoice_id, invoice_number, status, currency,
            amount, subtotal, vat_total, total, line_items, billing_address,
            issued_at, due_at, period_start, period_end,
            purchase_order_number, notes, created_at, updated_at
        ) VALUES (
            gen_random_uuid(), $1, NULL, $2, 'draft', $3,
            $6, $4, $5, $6, $7, $8,
            $9, $10, $11, $12,
            NULL, $13, NOW(), NOW()
        )
        RETURNING id::text, created_at, updated_at
        "#,
    )
    .bind(&tenant_id)
    .bind(&invoice_number)
    .bind(&currency)
    .bind(subtotal)
    .bind(vat_total)
    .bind(total)
    .bind(serde_json::to_value(&line_items)?)
    .bind(serde_json::to_value(&billing_address)?)
    .bind(now)
    .bind(due_at)
    .bind(period_start)
    .bind(period_end)
    .bind(body.notes.clone())
    .fetch_one(&mut *tx)
    .await?;

    tx.commit().await?;

    Ok((
        StatusCode::CREATED,
        billing_success(serde_json::to_value(LegacyInvoiceDto {
            id: inserted.0,
            tenant_id,
            stripe_invoice_id: None,
            invoice_number,
            status: "draft".to_string(),
            currency,
            subtotal,
            vat_total,
            total,
            line_items,
            billing_address,
            issued_at: now,
            due_at,
            paid_at: None,
            period_start,
            period_end,
            purchase_order_number: None,
            notes: body.notes,
            pdf_url: None,
            xml_url: None,
            created_at: inserted.1,
            updated_at: inserted.2,
        })?),
    )
        .into_response())
}

async fn admin_get_revenue_report(
    State(state): State<AppState>,
    auth: AuthUser,
    Query(query): Query<DateRangeQuery>,
) -> Result<Response, ApiError> {
    if let Err(response) = require_admin_access(&auth) {
        return Ok(response);
    }

    let (Some(start_date), Some(end_date)) =
        (query.start_date.as_deref(), query.end_date.as_deref())
    else {
        return Ok((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "startDate and endDate required" })),
        )
            .into_response());
    };
    let (Some(start_date), Some(end_date)) =
        (parse_query_date(start_date), parse_query_date(end_date))
    else {
        return Ok((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "Invalid startDate or endDate" })),
        )
            .into_response());
    };

    let report: serde_json::Value = match sqlx::query_scalar(admin_revenue_report_query(false))
        .bind(start_date)
        .bind(end_date)
        .fetch_one(&state.db)
        .await
    {
        Ok(report) => report,
        Err(error) if is_expected_schema_fallback_error(&error, &["42703", "42P01"]) => {
            sqlx::query_scalar(admin_revenue_report_query(true))
                .bind(start_date)
                .bind(end_date)
                .fetch_one(&state.db)
                .await?
        }
        Err(error) => return Err(error.into()),
    };

    Ok(billing_success_response(
        serde_json::json!({ "report": report }),
    ))
}

async fn admin_get_mrr_report(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<Response, ApiError> {
    if let Err(response) = require_admin_access(&auth) {
        return Ok(response);
    }

    // Shared with billing-service (audit 2: this local copy retained the
    // bugs billing-service fixed — truncated yearly/12 pricing,
    // creation-date instead of billing-cycle-start bucketing, and no
    // tenants join). Single source: billing_service::routes::MRR_REPORT_SQL.
    let report: serde_json::Value =
        sqlx::query_scalar(billing_service::routes::MRR_REPORT_SQL)
            .fetch_one(&state.db)
            .await?;

    Ok(billing_success_response(
        serde_json::json!({ "report": report }),
    ))
}

async fn admin_get_churn_report(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<Response, ApiError> {
    if let Err(response) = require_admin_access(&auth) {
        return Ok(response);
    }

    // Shared with billing-service (audit 2: this local copy priced churn
    // from the tenant's post-cancellation 'free' plan — structurally ~0 —
    // and truncated yearly/12). Single source:
    // billing_service::routes::CHURN_REPORT_SQL (stripe_price_id snapshot
    // join + unpriced-churn coverage).
    let report: serde_json::Value =
        sqlx::query_scalar(billing_service::routes::CHURN_REPORT_SQL)
            .fetch_one(&state.db)
            .await?;

    Ok(billing_success_response(
        serde_json::json!({ "report": report }),
    ))
}

async fn admin_get_dunning_report(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<Response, ApiError> {
    if let Err(response) = require_admin_access(&auth) {
        return Ok(response);
    }

    let report: serde_json::Value = sqlx::query_scalar(
        r#"
        SELECT COALESCE(json_agg(row_to_json(report_row) ORDER BY report_row.dunning_state), '[]'::json)
        FROM (
            SELECT
                dr.status AS dunning_state,
                COUNT(DISTINCT dr.tenant_id) as tenant_count,
                COALESCE(SUM(owed.amount_owed), 0) as total_owed
            FROM dunning_records dr
            LEFT JOIN LATERAL (
                SELECT COALESCE(SUM(i.total), 0) AS amount_owed
                FROM invoices i
                WHERE i.tenant_id = dr.tenant_id
                  AND i.status NOT IN ('paid', 'void', 'uncollectible')
            ) owed ON true
            WHERE dr.status NOT IN ('payment_recovered')
            GROUP BY dr.status
        ) report_row
        "#,
    )
    .fetch_one(&state.db)
    .await?;

    Ok(billing_success_response(
        serde_json::json!({ "report": report }),
    ))
}

async fn admin_get_cost_report(
    State(state): State<AppState>,
    auth: AuthUser,
    Query(query): Query<DateRangeQuery>,
) -> Result<Response, ApiError> {
    if let Err(response) = require_admin_access(&auth) {
        return Ok(response);
    }

    let (Some(start_date), Some(end_date)) =
        (query.start_date.as_deref(), query.end_date.as_deref())
    else {
        return Ok((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "startDate and endDate required" })),
        )
            .into_response());
    };
    let (Some(start_date), Some(end_date)) =
        (parse_query_date(start_date), parse_query_date(end_date))
    else {
        return Ok((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "Invalid startDate or endDate" })),
        )
            .into_response());
    };

    let report: serde_json::Value = sqlx::query_scalar(
        r#"
        SELECT COALESCE(json_agg(row_to_json(report_row) ORDER BY report_row.date), '[]'::json)
        FROM (
            SELECT
                DATE_TRUNC('day', recorded_at) as date,
                SUM(storage_cost) as storage_cost,
                SUM(bandwidth_cost) as bandwidth_cost,
                SUM(compute_cost) as compute_cost,
                SUM(dedicated_ip_cost) as dedicated_ip_cost,
                SUM(total_cost) as total_cost,
                SUM(revenue) as revenue,
                (SUM(revenue) - SUM(total_cost)) / NULLIF(SUM(revenue), 0) * 100 as margin_percent
            FROM tenant_costs
            WHERE recorded_at >= $1 AND recorded_at < $2
            GROUP BY DATE_TRUNC('day', recorded_at)
            ORDER BY date
        ) report_row
        "#,
    )
    .bind(start_date)
    .bind(end_date)
    .fetch_one(&state.db)
    .await?;

    Ok(billing_success_response(
        serde_json::json!({ "report": report }),
    ))
}

async fn admin_export_billing_data(
    State(state): State<AppState>,
    auth: AuthUser,
    Query(query): Query<BillingExportQuery>,
) -> Result<Response, ApiError> {
    if let Err(response) = require_admin_access(&auth) {
        return Ok(response);
    }

    let (Some(export_type), Some(start_date), Some(end_date)) = (
        query.export_type.as_deref(),
        query.start_date.as_deref(),
        query.end_date.as_deref(),
    ) else {
        return Ok((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "type, startDate, and endDate required" })),
        )
            .into_response());
    };

    let (Some(start_date_parsed), Some(end_date_parsed)) =
        (parse_query_date(start_date), parse_query_date(end_date))
    else {
        return Ok((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "Invalid startDate or endDate" })),
        )
            .into_response());
    };

    let export_query = match export_type {
        "invoices" => Some(admin_invoice_export_query(false)),
        "subscriptions" => Some(
            r#"
            SELECT COALESCE(json_agg(row_to_json(export_row) ORDER BY export_row.created_at), '[]'::json)
            FROM (
                SELECT
                    s.tenant_id, t.name as tenant_name,
                    p.name as plan_name, s.status,
                    CASE
                        WHEN s.billing_interval = 'yearly' THEN COALESCE(p.price_yearly, 0)
                        ELSE COALESCE(p.price_monthly, 0)
                    END as amount,
                    s.billing_interval,
                    s.billing_cycle_start as current_period_start, s.current_period_end,
                    s.created_at, s.canceled_at
                FROM stripe_subscriptions s
                JOIN tenants t ON s.tenant_id = t.id
                LEFT JOIN plans p ON p.name = s.plan
                WHERE s.created_at >= $1 AND s.created_at < $2
                ORDER BY s.created_at
            ) export_row
            "#,
        ),
        "transactions" => Some(
            r#"
            SELECT COALESCE(json_agg(row_to_json(export_row) ORDER BY export_row.created_at), '[]'::json)
            FROM (
                SELECT
                    w.tenant_id, t.name as tenant_name,
                    w.type, w.amount, w.balance_after,
                    w.description, w.reference, w.created_at
                FROM wallet_transactions w
                JOIN tenants t ON w.tenant_id = t.id
                WHERE w.created_at >= $1 AND w.created_at < $2
                ORDER BY w.created_at
            ) export_row
            "#,
        ),
        _ => None,
    };

    let Some(export_query) = export_query else {
        return Ok((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "Invalid export type" })),
        )
            .into_response());
    };

    let data: serde_json::Value = match sqlx::query_scalar(export_query)
        .bind(start_date_parsed)
        .bind(end_date_parsed)
        .fetch_one(&state.db)
        .await
    {
        Ok(data) => data,
        Err(error)
            if export_type == "invoices"
                && is_expected_schema_fallback_error(&error, &["42703", "42P01"]) =>
        {
            sqlx::query_scalar(admin_invoice_export_query(true))
                .bind(start_date_parsed)
                .bind(end_date_parsed)
                .fetch_one(&state.db)
                .await?
        }
        Err(error) => return Err(error.into()),
    };

    if query.format.eq_ignore_ascii_case("json") {
        return Ok(billing_success_response(data));
    }

    let csv = json_rows_to_csv(&data);
    let filename = format!(
        "{}_{}_{}.csv",
        export_type,
        safe_export_date(start_date),
        safe_export_date(end_date),
    );

    Ok(csv_text_response(csv, Some(filename)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    use axum::body::Body;
    use axum::http::{Method, Request};
    use deadpool_redis::Config as RedisConfig;
    use sqlx::postgres::PgPoolOptions;
    use tower::ServiceExt;

    use crate::app::build_app;
    use crate::config::{Config, Environment};
    use crate::ses_provider::SesIpProvider;
    use crate::state::AppStateInner;

    async fn response_json(response: Response) -> (StatusCode, serde_json::Value) {
        let status = response.status();
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("conflict response body should be readable");
        let json = serde_json::from_slice(&body).expect("conflict response should be JSON");
        (status, json)
    }

    fn initialize_billing_test_env() {
        static INIT: std::sync::Once = std::sync::Once::new();
        INIT.call_once(|| {
            std::env::set_var("AWS_EC2_METADATA_DISABLED", "true");
            std::env::set_var("AWS_ACCESS_KEY_ID", "test");
            std::env::set_var("AWS_SECRET_ACCESS_KEY", "test");
            std::env::set_var("BILLING_COMPANY_IBAN", "EE381010220123456789");
            std::env::set_var("BILLING_COMPANY_PHONE", "+3721234567");
        });
    }

    fn test_config() -> Config {
        Config {
            public_rate_limit_enabled: false,
            ai_service_base_url: String::new(),
            port: 3000,
            host: "0.0.0.0".into(),
            base_url: "http://localhost:3000".into(),
            environment: Environment::Development,
            db_host: "localhost".into(),
            db_port: 5432,
            db_name: "apexmail".into(),
            db_user: "apexmail".into(),
            db_password: "password".into(),
            db_max_connections: 20,
            api_replica_count: 1,
            db_cluster_connection_budget: None,
            expected_replica_count: 3,
            statement_cache_capacity: 500,
            query_timeout_seconds: 30,
            database_replica_url: None,
            redis_host: "localhost".into(),
            redis_port: 6379,
            redis_password: None,
            redis_db: 0,
            redis_pool_max_size: 40,
            jwt_private_key_pem: "BEGIN TEST".into(),
            jwt_public_key_pem: "BEGIN TEST".into(),
            jwt_previous_public_keys_pem: vec![],
            jwt_expiry: Duration::from_secs(86_400),
            api_key_hash_secret: "test-api-key-secret-12345678901234567890".into(),
            rate_limit_window_ms: 60_000,
            rate_limit_max_requests: 1_000,
            max_inflight_requests: 80,
            cors_origins: vec!["*".into()],
            trusted_proxies: vec![],
            ui_web_hosts: vec!["app.apexmail.ee".into(), "127.0.0.1".into()],
            ui_control_plane_hosts: vec!["admin.apexmail.ee".into(), "localhost".into()],
            ui_marketing_hosts: vec!["apexmail.ee".into()],
            ui_marketing_surface: "marketing-zola".into(),
            ui_default_surface: Some("web".into()),
            webhook_signing_secret: "test-webhook-signing-secret-1234567890".into(),
            webhook_timeout_ms: 5_000,
            webhook_max_retries: 3,
            idempotency_ttl_seconds: 86_400,
            aws_region: "us-east-1".into(),
            ses_ip_pool_prefix: "apexmail".into(),
            ses_default_warmup_days: 14,
            ses_configuration_set: None,
            google_client_id: None,
            google_client_secret: None,
            github_client_id: None,
            github_client_secret: None,
            oauth_redirect_base_url: "http://localhost:3000".into(),
            session_secret: "test-session-secret-1234567890ab".into(),
            impersonation_secret: "test-impersonation-secret-12345".into(),
            csrf_secret: "test-csrf-secret-1234567890abcd".into(),
            control_plane_api_key: None,
            sales_autopilot_base_url: "http://localhost:3010".into(),
            internal_service_token: None,
            cp_auth: Default::default(),
            tracking_secret_key: "test-tracking-secret-123456789012".into(),
            billing_company_iban: "EE381010220123456789".into(),
            billing_company_phone: "+3721234567".into(),
            metrics_port: 9090,
            grader_enabled: false,
            grader_rate_limit: 10,
            grader_rate_window_seconds: 60,
            grader_cache_ttl_seconds: 300,
            grader_max_body_size: 1048576,
            placement_enabled: false,
            placement_polling_interval_secs: 60,
            placement_max_polling_attempts: 60,
            placement_max_seeds_per_test: 50,
            placement_max_tests_per_hour: 10,
            placement_imap_timeout_secs: 30,
            placement_encrypt_passwords: false,
            placement_encryption_secret: "test-placement-encryption-secret-32b".into(),
            kiwi_enabled: false,
            kiwi_secret_key: "dev".into(),
            waf_enabled: false,
            waf_enforce: false,
            kiwi_algorithm: kiwicaptcha::PoWAlgorithm::Sha256,
            kiwi_argon_m_kib: 0,
            kiwi_argon2_difficulty_bits: 8,
            kiwi_argon_t: 2,
            kiwi_argon_p: 1,
            kiwi_difficulty_bits: 16,
            kiwi_challenge_ttl_secs: 120,
            kiwi_min_duration_ms: None,
            kiwi_enforce_telemetry: true,
            kiwi_argon2_max_concurrent: 2,
            kiwi_auto_tune: false,
            kiwi_auto_tune_min_bits: 10,
            kiwi_auto_tune_max_bits: 20,
            http_client_timeout_secs: 30,
            internal_tls_enabled: false,
            internal_tls_ca_cert_path: None,
            internal_tls_client_cert_path: None,
            internal_tls_client_key_path: None,
        }
    }

    async fn test_router() -> Router {
        initialize_billing_test_env();

        let database_url = std::env::var("TEST_DATABASE_URL")
            .unwrap_or_else(|_| "postgres://apexmail:apexmail@127.0.0.1:5433/apexmail".into());
        let db = PgPoolOptions::new()
            .max_connections(1)
            .connect_lazy(&database_url)
            .expect("failed to create lazy test database pool");

        // F6: never default to the ambient 6379 (CI pins the same dead-end
        // port when TEST_REDIS_URL is unset; the lazy pool is only used by
        // Redis-tolerant paths and the explicitly gated tests).
        let redis_url =
            std::env::var("TEST_REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:1".into());
        let redis = RedisConfig::from_url(&redis_url)
            .create_pool(Some(deadpool_redis::Runtime::Tokio1))
            .expect("failed to create lazy test redis pool");

        let aws_config = aws_config::defaults(aws_config::BehaviorVersion::latest())
            .region(aws_sdk_sesv2::config::Region::new("us-east-1"))
            .load()
            .await;
        let ses_provider = SesIpProvider::new(
            aws_sdk_sesv2::Client::new(&aws_config),
            db.clone(),
            "apexmail".into(),
            "us-east-1".into(),
        );

        let pools = apexmail_db::pool::PoolPair {
            rw: db.clone(),
            ro: db.clone(),
        };

        build_app(
            AppStateInner::new(
                db,
                pools,
                redis,
                test_config(),
                reqwest::Client::new(),
                ses_provider,
                None,
            )
            .await
            .expect("failed to build app state"),
        )
    }

    fn auth_user(scopes: &[&str], tenant_id: &str) -> AuthUser {
        AuthUser {
            tenant_id: tenant_id.to_string(),
            user_id: Some("user_123".into()),
            api_key_id: None,
            session_id: None,
            scopes: scopes.iter().map(|scope| (*scope).to_string()).collect(),
        }
    }

    #[test]
    fn billing_routes_admin_access_rejects_tenant_only_scope() {
        // NOTE (audit A): this test previously asserted that a non-system
        // tenant holding "*" or "billing:admin" passes the billing-admin gate.
        // That was the vulnerability — every customer tenant owner is granted
        // "*" by scopes_for_role, so they could reach ALL
        // /v1/billing/admin/* handlers (list tenants, apply credits, plan
        // overrides, revenue reports, exports). Platform billing admin now
        // requires the caller to belong to the `system` tenant.
        assert!(
            !has_admin_access(&auth_user(&["*"], "tenant_1")),
            "non-system tenant with wildcard scope must NOT pass the billing-admin gate"
        );
        assert!(
            !has_admin_access(&auth_user(&["billing:admin"], "tenant_1")),
            "non-system tenant with billing:admin scope must NOT pass the gate"
        );
        assert!(!has_admin_access(&auth_user(&["tenant:*"], "tenant_1")));
        assert!(!has_admin_access(&auth_user(
            &["tenant:tenant_1"],
            "tenant_1"
        )));
    }

    #[test]
    fn billing_routes_admin_access_requires_system_tenant_with_admin_scope() {
        // System-tenant admins (platform staff) still pass.
        assert!(has_admin_access(&auth_user(&["*"], "system")));
        assert!(has_admin_access(&auth_user(&["billing:admin"], "system")));
        // Human operators authenticate as the SEEDED system tenant, not the
        // literal sentinel — the gate must accept both.
        assert!(has_admin_access(&auth_user(&["*"], "system_internal_tenant01")));
        // System tenant WITHOUT an admin scope is rejected.
        assert!(!has_admin_access(&auth_user(&["tenant:*"], "system")));
        assert!(!has_admin_access(&auth_user(&["messages:read"], "system")));
        // Wildcard granted to a customer tenant owner is rejected (audit A).
        assert!(!has_admin_access(&auth_user(&["*"], "ten_customer_001")));
    }

    #[test]
    fn billing_routes_admin_guards_return_403_for_customer_tenant_owner() {
        // A customer tenant owner carries scopes ["*"] via scopes_for_role;
        // both guard helpers must produce a 403 Response, not Ok(()).
        let customer_owner = auth_user(&["*"], "ten_customer_001");
        assert!(require_admin_access(&customer_owner).is_err());
        assert!(require_admin_tenant_access(&customer_owner, "ten_customer_001").is_err());

        let platform_admin = auth_user(&["*"], "system");
        assert!(require_admin_access(&platform_admin).is_ok());
        assert!(require_admin_tenant_access(&platform_admin, "ten_customer_001").is_ok());

        // The 403 must not leak tenant details.
        let err = require_admin_access(&customer_owner).unwrap_err();
        assert_eq!(err.status(), StatusCode::FORBIDDEN);
    }

    #[test]
    fn billing_routes_tenant_access_accepts_exact_and_wildcard_scope() {
        assert!(has_tenant_access(
            &auth_user(&["*"], "tenant_1"),
            "tenant_2"
        ));
        assert!(has_tenant_access(
            &auth_user(&["tenant:*"], "tenant_1"),
            "tenant_2"
        ));
        assert!(has_tenant_access(
            &auth_user(&["tenant:tenant_2"], "tenant_1"),
            "tenant_2"
        ));
        assert!(!has_tenant_access(
            &auth_user(&["tenant:tenant_3"], "tenant_1"),
            "tenant_2"
        ));
    }

    #[tokio::test]
    async fn direct_plan_switch_requires_checkout_and_verified_webhook() {
        let (status, body) = response_json(checkout_required_response()).await;

        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(body["code"], "CHECKOUT_REQUIRED");
        assert!(body["error"]
            .as_str()
            .expect("error should be a string")
            .contains("verified Stripe webhook"));
    }

    #[tokio::test]
    async fn direct_subscription_cancellation_requires_billing_portal() {
        let (status, body) = response_json(billing_portal_required_response()).await;

        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(body["code"], "BILLING_PORTAL_REQUIRED");
        assert!(body["error"]
            .as_str()
            .expect("error should be a string")
            .contains("Stripe billing portal"));
    }

    #[test]
    fn billing_routes_realtime_period_label_follows_enforced_key_shape() {
        // F7: the read path delegates key selection to
        // billing_service::usage::enforced_counter_key. Whatever key that
        // returns, the reported period must be the label embedded in the
        // key — cycle-anchored (`:c2026-03`) and calendar (`:2026-03`)
        // shapes both reduce to `2026-03`.
        assert_eq!(
            usage_counter_period_label("meter:rt:tenant_123:emails_sent:c2026-03"),
            "2026-03"
        );
        assert_eq!(
            usage_counter_period_label("meter:rt:tenant_123:api_calls:2026-03"),
            "2026-03"
        );
        // Degenerate key (no period segment): the last segment is the
        // metric, NOT a period — fall back to the current calendar month
        // instead of reporting the metric name as the period.
        let now = Utc::now();
        assert_eq!(
            usage_counter_period_label("meter:rt:tenant_123:emails_sent"),
            format!("{}-{:02}", now.year(), now.month())
        );
    }

    #[test]
    fn billing_routes_usage_cache_key_includes_namespace_and_period() {
        let start = chrono::TimeZone::with_ymd_and_hms(&Utc, 2026, 3, 1, 0, 0, 0)
            .single()
            .expect("valid start");
        let end = chrono::TimeZone::with_ymd_and_hms(&Utc, 2026, 4, 1, 0, 0, 0)
            .single()
            .expect("valid end");

        assert_eq!(
            usage_cache_key("tenant_123", start, end, "summary"),
            format!(
                "billing:usage-query:summary:tenant_123:{}:{}",
                start.timestamp(),
                end.timestamp()
            )
        );
    }

    fn sample_invoice() -> LegacyInvoiceDto {
        let issued_at = chrono::TimeZone::with_ymd_and_hms(&Utc, 2026, 3, 9, 12, 30, 0)
            .single()
            .expect("valid issuedAt");
        let due_at = chrono::TimeZone::with_ymd_and_hms(&Utc, 2026, 4, 8, 12, 30, 0)
            .single()
            .expect("valid dueAt");

        LegacyInvoiceDto {
            id: "inv_test_123".into(),
            tenant_id: "tenant_123".into(),
            stripe_invoice_id: None,
            invoice_number: "2026-TEST-001".into(),
            status: "paid".into(),
            currency: "eur".into(),
            subtotal: 10_000,
            vat_total: 2_200,
            total: 12_200,
            line_items: vec![LegacyInvoiceLineItemDto {
                description: "Migration <Support> & Setup".into(),
                quantity: 2,
                unit_price: 5_000,
                amount: 10_000,
                vat_rate: 22.0,
                vat_amount: 2_200,
            }],
            billing_address: LegacyBillingAddressDto {
                company_name: "Acme <Billing>".into(),
                vat_number: Some("EE123456789".into()),
                address_line1: "Main & First".into(),
                address_line2: Some("Suite > 5".into()),
                city: "Tallinn".into(),
                state: Some("Harju".into()),
                postal_code: "10111".into(),
                country: "FI".into(),
                email: "billing@example.com".into(),
            },
            issued_at,
            due_at,
            paid_at: None,
            period_start: issued_at,
            period_end: due_at,
            purchase_order_number: Some("PO-<123>".into()),
            notes: Some("Handle <carefully> & confirm".into()),
            pdf_url: None,
            xml_url: None,
            created_at: issued_at,
            updated_at: issued_at,
        }
    }

    #[test]
    fn billing_routes_invoice_html_renderer_escapes_values_and_no_reverse_charge_when_vat_charged()
    {
        initialize_billing_test_env();

        let html = render_invoice_html(&sample_invoice(), "testnonce0123456789");

        assert!(html.contains("Invoice 2026-TEST-001"));
        assert!(html.contains("Bel Consulting OÜ"));
        assert!(html.contains("Acme &lt;Billing&gt;"));
        assert!(html.contains("PO: PO-&lt;123&gt;"));
        assert!(html.contains("Handle &lt;carefully&gt; &amp; confirm"));
        // The sample charges 22 % VAT, so the reverse-charge note must NOT
        // appear — printing it on a VAT-charged invoice contradicts the
        // document itself.
        assert!(!html.contains("Reverse charge"));
        assert!(html.contains("€122.00"));
        assert!(html.contains("IBAN: EE381010220123456789"));
        assert!(
            html.contains("<style nonce=\"testnonce0123456789\">"),
            "the style nonce must be stamped on the single <style> element"
        );
    }

    #[test]
    fn billing_routes_invoice_reverse_charge_note_only_when_actually_applied() {
        initialize_billing_test_env();

        // Reverse charge genuinely applied: valid FI VAT number, zero VAT.
        let mut invoice = sample_invoice();
        invoice.billing_address.country = "FI".into();
        invoice.billing_address.vat_number = Some("FI12345678".into());
        invoice.vat_total = 0;
        invoice.total = invoice.subtotal;
        let html = render_invoice_html(&invoice, "testnonce0123456789");
        assert!(html.contains("Reverse charge: VAT to be paid by the recipient"));

        // Invalid VAT number → destination VAT charged → no note, even at 0.
        let mut invoice = sample_invoice();
        invoice.billing_address.country = "FI".into();
        invoice.billing_address.vat_number = Some("1".into());
        invoice.vat_total = 0;
        invoice.total = invoice.subtotal;
        let html = render_invoice_html(&invoice, "testnonce0123456789");
        assert!(!html.contains("Reverse charge"));

        // Estonian buyers are never reverse-charged.
        let mut invoice = sample_invoice();
        invoice.billing_address.country = "EE".into();
        invoice.billing_address.vat_number = Some("EE100591102".into());
        invoice.vat_total = 0;
        invoice.total = invoice.subtotal;
        let html = render_invoice_html(&invoice, "testnonce0123456789");
        assert!(!html.contains("Reverse charge"));
    }

    // ── H-6: document-scoped CSP for the print-to-PDF invoice ─────

    #[test]
    fn billing_routes_invoice_nonce_is_random_and_header_safe() {
        let a = invoice_style_nonce();
        let b = invoice_style_nonce();
        assert_ne!(a, b, "every response must carry a fresh nonce");
        for nonce in [a, b] {
            assert_eq!(nonce.len(), 32, "128 bits as hex");
            assert!(
                nonce.chars().all(|c| c.is_ascii_hexdigit()),
                "CSP-source-safe characters only"
            );
        }
    }

    #[tokio::test]
    async fn billing_routes_invoice_response_csp_permits_exactly_the_nonce_stamped_style() {
        initialize_billing_test_env();

        let response = invoice_html_response(&sample_invoice());
        let csp_owned = response
            .headers()
            .get(header::CONTENT_SECURITY_POLICY)
            .and_then(|value| value.to_str().ok())
            .map(str::to_string)
            .expect("invoice response must carry its own CSP");
        let csp = csp_owned.as_str();

        // The global default (`default-src 'none'` with no style-src) blocked
        // the inline <style>; this document-scoped policy must allow exactly
        // the one nonce-stamped stylesheet and nothing else.
        assert!(csp.starts_with("default-src 'none'"));
        let style_src = csp
            .split(';')
            .map(str::trim)
            .find(|directive| directive.starts_with("style-src"))
            .expect("style-src directive present");
        let nonce = style_src
            .strip_prefix("style-src 'nonce-")
            .and_then(|rest| rest.strip_suffix('\''))
            .expect("nonce-only style-src");
        assert_eq!(nonce.len(), 32);
        assert!(!csp.contains("'unsafe-inline'"), "no blanket inline permit");
        assert!(csp.contains("frame-ancestors 'none'"));

        // The stamped nonce in the document must be the one the CSP allows.
        let body = axum::body::to_bytes(response.into_body(), 64 * 1024)
            .await
            .expect("body readable");
        let html = String::from_utf8_lossy(&body);
        assert!(html.contains(&format!("style nonce=\"{nonce}\"")));
        assert_eq!(
            html.matches("<style").count(),
            1,
            "exactly one style element"
        );
        assert!(
            !html.contains("<script"),
            "no scripts in the invoice document"
        );
    }

    #[test]
    fn billing_routes_invoice_html_escapes_env_configured_iban() {
        // The IBAN comes from BILLING_COMPANY_IBAN (deployment configuration):
        // a stray HTML metacharacter must never break out of the footer text.
        // (Checked via the escaping primitive plus a template pin — mutating
        // the env var here races with parallel tests calling
        // `initialize_billing_test_env`.)
        assert_eq!(
            escape_html("EE38<>&'\"1010"),
            "EE38&lt;&gt;&amp;&#39;&quot;1010"
        );
        let source = include_str!("billing.rs");
        assert!(
            source.contains("bank_details = {"),
            "the IBAN interpolation must stay escaped"
        );
        for field in [
            "invoice_number = escape_html(",
            "bill_to_company = escape_html(",
            "bill_to_line1 = escape_html(",
            "bill_to_email = escape_html(",
        ] {
            assert!(
                source.contains(field),
                "customer-controlled field must stay escaped: {field}"
            );
        }
    }

    #[test]
    fn billing_routes_invoice_xml_renderer_escapes_values_and_includes_payment_fields() {
        initialize_billing_test_env();

        let xml = render_invoice_xml(&sample_invoice());

        assert!(xml.contains("<?xml version=\"1.0\" encoding=\"UTF-8\"?>"));
        assert!(xml.contains("<Name>Bel Consulting OÜ</Name>"));
        assert!(xml.contains("<InvoiceNumber>2026-TEST-001</InvoiceNumber>"));
        assert!(xml.contains("Acme &lt;Billing&gt;"));
        assert!(xml.contains("PO-&lt;123&gt;"));
        assert!(xml.contains("<PayToAccount>EE381010220123456789</PayToAccount>"));
        assert!(xml.contains("<PhoneNumber>+3721234567</PhoneNumber>"));
    }

    #[test]
    fn billing_routes_admin_invoice_queries_cover_current_and_legacy_schemas() {
        assert!(admin_revenue_report_query(false).contains("SUM(vat_total) as total_tax"));
        assert!(admin_revenue_report_query(true).contains("SUM(amount_cents) as total_revenue"));
        assert!(admin_revenue_report_query(true).contains("0::bigint as total_tax"));

        assert!(admin_invoice_export_query(false)
            .contains("i.subtotal, i.vat_total, i.total, i.currency"));
        assert!(admin_invoice_export_query(true).contains("i.amount_cents as subtotal"));
        assert!(admin_invoice_export_query(true).contains("i.due_date as due_at"));
    }

    #[test]
    fn billing_routes_redirect_url_policy_matches_ts_rules() {
        assert!(is_allowed_billing_redirect_url(
            "https://app.apexmail.ee/billing/complete",
            crate::config::Environment::Production,
        ));
        assert!(!is_allowed_billing_redirect_url(
            "https://evil-apexmail.ee/complete",
            crate::config::Environment::Production,
        ));
        assert!(!is_allowed_billing_redirect_url(
            "https://xn--app-9la.apexmail.ee/complete",
            crate::config::Environment::Production,
        ));
        assert!(is_allowed_billing_redirect_url(
            "http://localhost:3000/billing/complete",
            crate::config::Environment::Development,
        ));
        assert!(!is_allowed_billing_redirect_url(
            "http://localhost:3000/billing/complete",
            crate::config::Environment::Production,
        ));
    }

    #[test]
    fn billing_routes_stripe_request_builder_pins_api_version_and_idempotency() {
        let stripe = StripeClient::new(
            reqwest::Client::new(),
            "https://api.stripe.com".into(),
            DEFAULT_STRIPE_API_VERSION.into(),
            "sk_test_123".into(),
        );
        let request = stripe
            .form_request(
                "/v1/customers",
                &[("email", "billing@example.com".to_string())],
                Some("customer_create_tenant_123"),
            )
            .build()
            .expect("request should build");

        assert_eq!(
            request.url().as_str(),
            "https://api.stripe.com/v1/customers"
        );
        assert_eq!(
            request
                .headers()
                .get("stripe-version")
                .expect("stripe version header")
                .to_str()
                .expect("stripe version string"),
            DEFAULT_STRIPE_API_VERSION,
        );
        assert_eq!(
            request
                .headers()
                .get("idempotency-key")
                .expect("idempotency key")
                .to_str()
                .expect("idempotency key string"),
            "customer_create_tenant_123",
        );
        assert!(request.headers().get("authorization").is_some());
    }

    #[tokio::test]
    async fn billing_routes_require_authentication_for_new_public_endpoints() {
        let app = test_router().await;

        for (method, uri) in [
            (Method::GET, "/v1/billing/usage/realtime/emails_sent"),
            (Method::POST, "/v1/billing/alerts"),
            (Method::POST, "/v1/billing/checkout"),
            (Method::POST, "/v1/billing/portal"),
            (Method::GET, "/v1/billing/proration/pro"),
            (Method::GET, "/v1/billing/invoices/inv_test_123/pdf"),
            (Method::GET, "/v1/billing/invoices/inv_test_123/xml"),
        ] {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method(method)
                        .uri(uri)
                        .body(Body::empty())
                        .expect("request"),
                )
                .await
                .expect("response");

            assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "{uri}");
        }
    }

    // ── Audit Log Hash Chain Tests ──────────────────────────────

    #[test]
    fn test_generate_audit_log_id_format() {
        let id = generate_audit_log_id();
        // Should be 26 lowercase hex chars (UUID v4 trimmed)
        assert_eq!(id.len(), 26);
        assert!(id
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit()));
    }

    #[test]
    fn test_compute_audit_log_hash_is_deterministic() {
        let ts = Utc::now();
        let metadata = serde_json::json!({"reason": "test", "source": "unit-test"});

        let hash1 = compute_audit_log_hash(
            "tenant_001",
            "user.created",
            "user",
            Some("u-001"),
            &metadata,
            None,
            ts,
        );
        let hash2 = compute_audit_log_hash(
            "tenant_001",
            "user.created",
            "user",
            Some("u-001"),
            &metadata,
            None,
            ts,
        );

        assert_eq!(hash1, hash2, "same inputs must produce same hash");
    }

    #[test]
    fn test_compute_audit_log_hash_changes_with_tenant_id() {
        let ts = Utc::now();
        let metadata = serde_json::json!({});

        let hash_a = compute_audit_log_hash(
            "tenant_001",
            "user.created",
            "user",
            Some("u-001"),
            &metadata,
            None,
            ts,
        );
        let hash_b = compute_audit_log_hash(
            "tenant_002",
            "user.created",
            "user",
            Some("u-001"),
            &metadata,
            None,
            ts,
        );

        assert_ne!(
            hash_a, hash_b,
            "different tenants must produce different hash"
        );
    }

    #[test]
    fn test_compute_audit_log_hash_changes_with_action() {
        let ts = Utc::now();
        let metadata = serde_json::json!({});

        let hash_create = compute_audit_log_hash(
            "tenant_001",
            "user.created",
            "user",
            Some("u-001"),
            &metadata,
            None,
            ts,
        );
        let hash_delete = compute_audit_log_hash(
            "tenant_001",
            "user.deleted",
            "user",
            Some("u-001"),
            &metadata,
            None,
            ts,
        );

        assert_ne!(
            hash_create, hash_delete,
            "different actions must produce different hash"
        );
    }

    #[test]
    fn test_compute_audit_log_hash_changes_with_metadata() {
        let ts = Utc::now();

        let hash1 = compute_audit_log_hash(
            "tenant_001",
            "plan.change",
            "subscription",
            Some("sub-001"),
            &serde_json::json!({"newPlan": "pro"}),
            None,
            ts,
        );
        let hash2 = compute_audit_log_hash(
            "tenant_001",
            "plan.change",
            "subscription",
            Some("sub-001"),
            &serde_json::json!({"newPlan": "enterprise"}),
            None,
            ts,
        );

        assert_ne!(
            hash1, hash2,
            "different metadata must produce different hash"
        );
    }

    #[test]
    fn test_compute_audit_log_hash_chains_with_previous_hash() {
        let ts = Utc::now();
        let metadata = serde_json::json!({});

        let first_hash = compute_audit_log_hash(
            "tenant_001",
            "user.created",
            "user",
            Some("u-001"),
            &metadata,
            None,
            ts,
        );

        // Second entry in the chain links to the first
        let second_hash = compute_audit_log_hash(
            "tenant_001",
            "user.updated",
            "user",
            Some("u-001"),
            &metadata,
            Some(&first_hash),
            ts,
        );

        assert_ne!(
            second_hash, first_hash,
            "second link must differ from first"
        );

        // If someone tries to insert a fraudulent second entry with no previous_hash, it differs
        let fraudulent_hash = compute_audit_log_hash(
            "tenant_001",
            "user.updated",
            "user",
            Some("u-001"),
            &metadata,
            None,
            ts,
        );
        assert_ne!(
            second_hash, fraudulent_hash,
            "tampered entry (missing prev hash) must differ from legitimate one"
        );
    }

    #[test]
    fn test_compute_audit_log_hash_changes_with_timestamp() {
        let ts1 = Utc::now();
        let ts2 = ts1 + chrono::Duration::seconds(1);
        let metadata = serde_json::json!({});

        let hash1 = compute_audit_log_hash(
            "tenant_001",
            "user.created",
            "user",
            Some("u-001"),
            &metadata,
            None,
            ts1,
        );
        let hash2 = compute_audit_log_hash(
            "tenant_001",
            "user.created",
            "user",
            Some("u-001"),
            &metadata,
            None,
            ts2,
        );

        assert_ne!(
            hash1, hash2,
            "different timestamps must produce different hash"
        );
    }

    #[test]
    fn test_compute_audit_log_hash_output_is_sha256_hex() {
        let ts = Utc::now();
        let metadata = serde_json::json!({});

        let hash = compute_audit_log_hash(
            "tenant_001",
            "action",
            "resource",
            None,
            &metadata,
            None,
            ts,
        );

        // SHA-256 hex output is 64 chars
        assert_eq!(hash.len(), 64, "SHA-256 hex output must be 64 characters");
        assert!(
            hash.chars().all(|c| c.is_ascii_hexdigit()),
            "hash must be hex"
        );
    }

    #[test]
    fn test_compute_audit_log_hash_with_none_resource_id() {
        let ts = Utc::now();
        let metadata = serde_json::json!({});

        // None resource_id should be handled gracefully (uses empty string)
        let hash = compute_audit_log_hash(
            "tenant_001",
            "system.event",
            "system",
            None,
            &metadata,
            None,
            ts,
        );

        assert_eq!(hash.len(), 64);
    }

    #[test]
    fn test_compute_audit_log_hash_long_chain_integrity() {
        // Build a 5-entry hash chain and verify each link is correctly bound
        let ts = Utc::now();
        let _metadata = serde_json::json!({"action_idx": 0});

        let mut prev_hash: Option<String> = None;
        let mut hashes: Vec<String> = Vec::new();

        for i in 0..5 {
            let metadata = serde_json::json!({"action_idx": i});
            let ts_entry = ts + chrono::Duration::seconds(i);
            let hash = compute_audit_log_hash(
                "tenant_001",
                "test.event",
                "test",
                Some(&format!("evt-{i:03}")),
                &metadata,
                prev_hash.as_deref(),
                ts_entry,
            );
            // Verify chain binding: each new hash must incorporate the previous
            if let Some(ref prev) = prev_hash {
                assert_ne!(*prev, hash, "consecutive chain links must differ");
            }
            prev_hash = Some(hash.clone());
            hashes.push(hash);
        }

        // All 5 hashes must be unique
        let mut unique = hashes.clone();
        unique.sort();
        unique.dedup();
        assert_eq!(
            unique.len(),
            5,
            "all chain entries must produce unique hashes"
        );

        // Tamper detection: changing any middle entry breaks forward linkage
        let tampered_metadata = serde_json::json!({"action_idx": 2, "tampered": true});
        let tampered_hash = compute_audit_log_hash(
            "tenant_001",
            "test.event",
            "test",
            Some("evt-002"),
            &tampered_metadata,
            Some(&hashes[1]), // correct prev (links to entry 1)
            ts + chrono::Duration::seconds(2),
        );

        // The tampered hash differs from the original at the same position
        assert_ne!(
            tampered_hash, hashes[2],
            "tampered entry must differ from original"
        );

        // Verifying against wrong prev fails
        let wrong_prev_hash = compute_audit_log_hash(
            "tenant_001",
            "test.event",
            "test",
            Some("evt-002"),
            &serde_json::json!({"action_idx": 2}),
            Some("fake-previous-hash"),
            ts + chrono::Duration::seconds(2),
        );
        assert_ne!(
            wrong_prev_hash, hashes[2],
            "wrong previous hash must produce different hash"
        );
    }
}
