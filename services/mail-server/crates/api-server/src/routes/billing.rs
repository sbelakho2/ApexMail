//! Public billing routes served by api-server.

use axum::extract::{Path, Query, State};
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use billing_common::proration;
use billing_service::{
    config::{BillingConfig, PaygPricing},
    plans,
    types::{BillingInterval, Plan, PlanFeatures},
    usage,
};
use chrono::{Datelike, Months, NaiveTime, Utc};
use deadpool_redis::redis::AsyncCommands;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::error::{success, ApiError, ApiResponse};
use crate::middleware::auth::AuthUser;
use crate::state::AppState;

const MINIMUM_MONTHLY_CHARGE_CENTS: i64 = 0;
const LEGACY_DOWNGRADE_PLAN: &str = "free";
const DEFAULT_BILLING_CURRENCY: &str = "USD";
const DEFAULT_NET_DAYS: i64 = 30;
const USAGE_QUERY_CACHE_TTL_SECONDS: u64 = 30;
const BILLING_COMPANY_NAME: &str = "Bel Consulting OÜ";
const BILLING_COMPANY_TRADING_AS: &str = "ApexMail";
const BILLING_COMPANY_STREET: &str = "Sakala 7-2";
const BILLING_COMPANY_CITY: &str = "Tallinn";
const BILLING_COMPANY_POSTAL_CODE: &str = "10141";
const BILLING_COMPANY_COUNTRY: &str = "Estonia";
const BILLING_COMPANY_REGISTRY_CODE: &str = "16588745";
const BILLING_COMPANY_VAT_NUMBER: &str = "EE102951727";
const BILLING_COMPANY_BILLING_EMAIL: &str = "billing@apexmail.ee";
const BILLING_COMPANY_BANK_NAME: &str = "Swedbank AS";
const BILLING_COMPANY_BANK_BIC: &str = "HABAEE2X";

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
        ((emails_sent as f64 / summary.emails_limit as f64) * 100.0).round() as i64
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
    expires_at: Option<String>,
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
    vat_rate: i32,
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
    "csv".to_string()
}

fn usage_realtime_counter_key(tenant_id: &str, metric: &str, now: chrono::DateTime<Utc>) -> String {
    format!(
        "meter:rt:{tenant_id}:{metric}:{}-{:02}",
        now.year(),
        now.month()
    )
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

fn has_admin_access(auth: &AuthUser) -> bool {
    auth.scopes
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

fn generate_admin_invoice_number(tenant_id: &str) -> String {
    let year = Utc::now().year();
    let tenant_prefix = tenant_id
        .replace('-', "")
        .chars()
        .take(4)
        .collect::<String>()
        .to_uppercase();
    let random_part = Uuid::new_v4()
        .simple()
        .to_string()
        .chars()
        .take(6)
        .collect::<String>()
        .to_uppercase();
    format!("{year}-{tenant_prefix}-{random_part}")
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

fn billing_company_iban() -> String {
    std::env::var("BILLING_COMPANY_IBAN").unwrap_or_else(|_| "UNCONFIGURED".into())
}

fn billing_company_phone() -> String {
    std::env::var("BILLING_COMPANY_PHONE").unwrap_or_else(|_| "UNCONFIGURED".into())
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

fn format_invoice_currency_html(cents: i64) -> String {
    format!("€{:.2}", cents as f64 / 100.0)
}

fn invoice_payment_terms_days(invoice: &LegacyInvoiceDto) -> i64 {
    let diff_ms = invoice
        .due_at
        .signed_duration_since(invoice.issued_at)
        .num_milliseconds();

    proration::ceil_day_count(diff_ms)
}

fn invoice_vat_label(invoice: &LegacyInvoiceDto) -> String {
    let mut vat_rates: Vec<i32> = invoice
        .line_items
        .iter()
        .map(|item| item.vat_rate)
        .collect();
    vat_rates.sort_unstable();
    vat_rates.dedup();

    if vat_rates.len() <= 1 {
        format!("VAT ({}%)", vat_rates.first().copied().unwrap_or(0))
    } else {
        format!(
            "VAT (Mixed: {})",
            vat_rates
                .iter()
                .map(|rate| format!("{rate}%"))
                .collect::<Vec<_>>()
                .join(", ")
        )
    }
}

fn render_invoice_html(invoice: &LegacyInvoiceDto) -> String {
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
    let reverse_charge_note = if invoice.billing_address.vat_number.is_some()
        && invoice.billing_address.country != "EE"
    {
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
            format_invoice_currency_html(item.unit_price),
            item.vat_rate,
            format_invoice_currency_html(item.amount),
        ));
    }

    format!(
        r#"<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>Invoice {invoice_number}</title>
  <style>
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
    <p>{company_name} (trading as {trading_as}) | Reg. {registry_code} | VAT: {company_vat} | IBAN: {company_iban} | BIC: {company_bic}</p>
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
        subtotal = format_invoice_currency_html(invoice.subtotal),
        vat_label = invoice_vat_label(invoice),
        vat_total = format_invoice_currency_html(invoice.vat_total),
        total = format_invoice_currency_html(invoice.total),
        reverse_charge_note = reverse_charge_note,
        notes = notes,
        payment_terms_days = invoice_payment_terms_days(invoice),
        company_iban = escape_html(&billing_company_iban()),
        company_bic = BILLING_COMPANY_BANK_BIC,
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

    let mut item_entries = String::new();
    for (index, item) in invoice.line_items.iter().enumerate() {
        item_entries.push_str(&format!(
            "      <ItemEntry>\n        <RowNo>{}</RowNo>\n        <Description>{}</Description>\n        <ItemDetailInfo>\n          <ItemUnit>PCS</ItemUnit>\n          <ItemAmount>{}</ItemAmount>\n          <ItemPrice>{:.2}</ItemPrice>\n        </ItemDetailInfo>\n        <ItemSum>\n          <Amount>{:.2}</Amount>\n          <VAT>\n            <VATRate>{}</VATRate>\n            <VATSum>{:.2}</VATSum>\n            <SumBeforeVAT>{:.2}</SumBeforeVAT>\n            <SumAfterVAT>{:.2}</SumAfterVAT>\n            <Currency>EUR</Currency>\n          </VAT>\n          <TotalSum>{:.2}</TotalSum>\n        </ItemSum>\n      </ItemEntry>\n",
            index + 1,
            escape_xml(&item.description),
            item.quantity,
            item.unit_price as f64 / 100.0,
            item.amount as f64 / 100.0,
            item.vat_rate,
            item.vat_amount as f64 / 100.0,
            item.amount as f64 / 100.0,
            (item.amount + item.vat_amount) as f64 / 100.0,
            (item.amount + item.vat_amount) as f64 / 100.0,
        ));
    }

    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<E_Invoice xmlns=\"http://www.pangaliit.ee/e-arve/e-arve\">\n  <Header>\n    <Date>{issued_at}</Date>\n    <FileId>{file_id}</FileId>\n    <Version>1.2</Version>\n  </Header>\n  <Invoice>\n    <InvoiceParties>\n      <SellerParty>\n        <Name>{company_name}</Name>\n        <RegNumber>{registry_code}</RegNumber>\n        <VATRegNumber>{company_vat}</VATRegNumber>\n        <ContactData>\n          <LegalAddress>\n            <PostalAddress1>{company_street}</PostalAddress1>\n            <City>{company_city}</City>\n            <PostalCode>{company_postal_code}</PostalCode>\n            <Country>EE</Country>\n          </LegalAddress>\n          <PhoneNumber>{company_phone}</PhoneNumber>\n          <E-mailAddress>{billing_email}</E-mailAddress>\n        </ContactData>\n        <AccountInfo>\n          <AccountNumber>{company_iban}</AccountNumber>\n          <BIC>{company_bic}</BIC>\n          <BankName>{company_bank_name}</BankName>\n        </AccountInfo>\n      </SellerParty>\n      <BuyerParty>\n        <Name>{buyer_name}</Name>\n{buyer_vat_number}        <ContactData>\n          <LegalAddress>\n            <PostalAddress1>{buyer_line1}</PostalAddress1>\n{buyer_address_line_2}            <City>{buyer_city}</City>\n            <PostalCode>{buyer_postal_code}</PostalCode>\n            <Country>{buyer_country}</Country>\n          </LegalAddress>\n          <E-mailAddress>{buyer_email}</E-mailAddress>\n        </ContactData>\n      </BuyerParty>\n    </InvoiceParties>\n    <InvoiceInformation>\n      <Type Type=\"DEB\"/>\n      <InvoiceNumber>{invoice_number}</InvoiceNumber>\n      <InvoiceDate>{issued_at}</InvoiceDate>\n      <DueDate>{due_at}</DueDate>\n      <InvoiceContentCode>SERVICES</InvoiceContentCode>\n      <Currency>EUR</Currency>\n{reference_number}    </InvoiceInformation>\n    <InvoiceSumGroup>\n      <InvoiceSum>{total}</InvoiceSum>\n      <PaidAmount>0.00</PaidAmount>\n      <PayableAmount>{total}</PayableAmount>\n      <Currency>EUR</Currency>\n    </InvoiceSumGroup>\n    <InvoiceItem>\n{item_entries}    </InvoiceItem>\n    <PaymentInfo>\n      <Currency>EUR</Currency>\n      <PaymentDescription>Invoice {invoice_number}</PaymentDescription>\n      <Payable>YES</Payable>\n      <DueDate>{due_at}</DueDate>\n      <PaymentId>{invoice_number}</PaymentId>\n      <PaymentTotalSum>{total}</PaymentTotalSum>\n      <PayerName>{buyer_name}</PayerName>\n      <PayToAccount>{company_iban}</PayToAccount>\n      <PayToBIC>{company_bic}</PayToBIC>\n      <PayToName>{company_name}</PayToName>\n    </PaymentInfo>\n  </Invoice>\n</E_Invoice>",
        issued_at = format_invoice_date(invoice.issued_at),
        file_id = escape_xml(&invoice.id),
        company_name = escape_xml(BILLING_COMPANY_NAME),
        registry_code = BILLING_COMPANY_REGISTRY_CODE,
        company_vat = BILLING_COMPANY_VAT_NUMBER,
        company_street = escape_xml(BILLING_COMPANY_STREET),
        company_city = escape_xml(BILLING_COMPANY_CITY),
        company_postal_code = BILLING_COMPANY_POSTAL_CODE,
        company_phone = escape_xml(&billing_company_phone()),
        billing_email = escape_xml(BILLING_COMPANY_BILLING_EMAIL),
        company_iban = escape_xml(&billing_company_iban()),
        company_bic = BILLING_COMPANY_BANK_BIC,
        company_bank_name = escape_xml(BILLING_COMPANY_BANK_NAME),
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
        total = format!("{:.2}", invoice.total as f64 / 100.0),
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

fn legacy_billing_interval(interval: BillingInterval) -> &'static str {
    match interval {
        BillingInterval::Monthly => "monthly",
        BillingInterval::Yearly => "yearly",
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

    let days_elapsed = proration::ceil_day_count(
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
    let price_divisor = if is_yearly { 12.0 } else { 1.0 };
    let period_divisor = days_in_period as f64 * price_divisor;

    let credit_amount =
        ((current_price_numerator as f64 * days_remaining as f64) / period_divisor).round() as i64;
    let charge_amount =
        ((new_price_numerator as f64 * days_remaining as f64) / period_divisor).round() as i64;
    let net_amount = charge_amount - credit_amount;

    if net_amount > config.max_proration_charge_cents {
        return Err(format!(
            "Proration charge exceeds maximum allowed: ${:.2} > ${:.2}. Please contact support for assistance with this plan change.",
            net_amount as f64 / 100.0,
            config.max_proration_charge_cents as f64 / 100.0,
        ));
    }

    if net_amount < 0 && net_amount.abs() > config.max_proration_credit_cents {
        return Err(format!(
            "Proration credit exceeds maximum allowed: ${:.2} > ${:.2}. Please contact support for assistance with this plan change.",
            net_amount.abs() as f64 / 100.0,
            config.max_proration_credit_cents as f64 / 100.0,
        ));
    }

    let warnings = if net_amount > config.warn_proration_charge_cents {
        Some(vec![format!(
            "This plan change will result in a charge of ${:.2}. Please confirm this is intended.",
            net_amount as f64 / 100.0,
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
            (current_price_numerator as f64 / price_divisor).round() as i64,
            (new_price_numerator as f64 / price_divisor).round() as i64,
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

fn generate_audit_log_id() -> String {
    Uuid::new_v4()
        .simple()
        .to_string()
        .chars()
        .take(26)
        .collect()
}

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

async fn insert_audit_log(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    tenant_id: &str,
    action: &str,
    resource_type: &str,
    resource_id: Option<&str>,
    metadata: serde_json::Value,
    timestamp: chrono::DateTime<Utc>,
) -> Result<(), ApiError> {
    let previous_hash: Option<String> = sqlx::query_scalar(
        "SELECT hash FROM audit_logs WHERE tenant_id = $1 ORDER BY timestamp DESC LIMIT 1",
    )
    .bind(tenant_id)
    .fetch_optional(&mut **tx)
    .await?;

    let hash = compute_audit_log_hash(
        tenant_id,
        action,
        resource_type,
        resource_id,
        &metadata,
        previous_hash.as_deref(),
        timestamp,
    );

    sqlx::query(
        r#"
        INSERT INTO audit_logs (
            id, tenant_id, action, resource_type, resource_id,
            metadata, previous_hash, hash, timestamp
        ) VALUES (
            $1, $2, $3, $4, $5,
            $6, $7, $8, $9
        )
        "#,
    )
    .bind(generate_audit_log_id())
    .bind(tenant_id)
    .bind(action)
    .bind(resource_type)
    .bind(resource_id)
    .bind(metadata)
    .bind(previous_hash)
    .bind(hash)
    .bind(timestamp)
    .execute(&mut **tx)
    .await?;

    Ok(())
}

async fn get_route_subscription(
    pool: &sqlx::PgPool,
    tenant_id: &str,
) -> Result<Option<RouteSubscription>, ApiError> {
    let row: Option<RouteSubscriptionRow> = sqlx::query_as(
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

    Ok(row.map(RouteSubscriptionRow::into_subscription))
}

fn cents_to_usd_string(cents: i64) -> String {
    format!("${:.2}", cents as f64 / 100.0)
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

    let now = Utc::now();
    let period = format!("{}-{:02}", now.year(), now.month());
    let key = usage_realtime_counter_key(&auth.tenant_id, &metric, now);
    let mut conn = state.redis.get().await?;
    let value: Option<i64> = conn.get(&key).await.map_err(ApiError::from)?;

    Ok(billing_success_response(serde_json::json!({
        "metric": metric,
        "count": value.unwrap_or(0),
        "period": period,
    })))
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
    Json(body): Json<OverageEstimateBody>,
) -> Result<Json<ApiResponse<serde_json::Value>>, ApiError> {
    let emails_sent = validate_non_negative(body.emails_sent, "emailsSent")? as i64;
    if body.email_limit < 0 {
        return Err(ApiError::Validation(vec![
            "emailLimit must be non-negative".into(),
        ]));
    }

    let overage_cost_cents = plans::calculate_overage_cost(emails_sent, body.email_limit);

    Ok(billing_success(serde_json::json!({
        "usage": {
            "emailsSent": emails_sent,
            "emailLimit": body.email_limit,
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
    if body.price_id.trim().is_empty() {
        return Ok((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "priceId is required" })),
        )
            .into_response());
    }
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
                ("line_items[0][price]", body.price_id),
                ("line_items[0][quantity]", "1".into()),
                ("mode", "subscription".into()),
                ("success_url", body.success_url),
                ("cancel_url", body.cancel_url),
                (
                    "subscription_data[metadata][tenant_id]",
                    auth.tenant_id.clone(),
                ),
                ("allow_promotion_codes", "true".into()),
                ("billing_address_collection", "required".into()),
                ("tax_id_collection[enabled]", "true".into()),
            ],
            None,
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
                ("customer", stripe_customer_id),
                ("return_url", body.return_url),
            ],
            None,
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

async fn switch_plan(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(body): Json<LegacySwitchPlanBody>,
) -> Result<Response, ApiError> {
    let now = Utc::now();

    if body.plan_name == "payg" {
        let current_subscription = get_route_subscription(&state.db, &auth.tenant_id).await?;
        let effective_date = current_subscription
            .as_ref()
            .map(|subscription| subscription.current_period_end)
            .unwrap_or(now);
        let previous_plan = current_subscription
            .as_ref()
            .map(|subscription| subscription.plan_name.clone())
            .unwrap_or_else(|| "unknown".to_string());

        let mut tx = state.db.begin().await?;

        if current_subscription.is_some() {
            sqlx::query(
                r#"
                UPDATE subscriptions
                SET cancel_at_period_end = true, updated_at = $1
                WHERE tenant_id = $2
                  AND status IN ('active', 'trialing', 'past_due')
                "#,
            )
            .bind(now)
            .bind(&auth.tenant_id)
            .execute(&mut *tx)
            .await?;
        }

        let tenant_update =
            sqlx::query("UPDATE tenants SET plan = 'payg', updated_at = $1 WHERE id = $2")
                .bind(now)
                .bind(&auth.tenant_id)
                .execute(&mut *tx)
                .await?;

        if tenant_update.rows_affected() != 1 {
            return Ok((
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({ "error": "Tenant not found" })),
            )
                .into_response());
        }

        insert_audit_log(
            &mut tx,
            &auth.tenant_id,
            "plan.changed",
            "subscription",
            None,
            serde_json::json!({
                "previousPlan": previous_plan,
                "newPlan": "payg",
                "changeType": "downgrade",
                "effectiveDate": effective_date,
            }),
            now,
        )
        .await?;

        tx.commit().await?;

        return Ok(billing_success_response(serde_json::json!({
            "success": true,
            "message": "Switched to Pay As You Go billing",
            "effectiveDate": effective_date,
        })));
    }

    let subscription = match get_route_subscription(&state.db, &auth.tenant_id).await? {
        Some(subscription) => subscription,
        None => {
            return Ok((
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({ "error": "No active subscription found" })),
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

    let new_plan = match plans::get_plan_by_name(&state.db, &body.plan_name).await? {
        Some(plan) => plan,
        None => {
            return Ok((
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({ "error": "Plan not found" })),
            )
                .into_response())
        }
    };

    let proration = match preview_plan_proration(
        &BillingConfig::default(),
        &current_plan,
        &new_plan,
        &subscription,
    ) {
        Ok(proration) => proration,
        Err(error) => {
            return Ok((
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": error })),
            )
                .into_response())
        }
    };

    let mut tx = state.db.begin().await?;

    let updated_subscription_id: Option<Uuid> = sqlx::query_scalar(
        r#"
        WITH target AS (
            SELECT id
            FROM subscriptions
            WHERE tenant_id = $4
              AND status IN ('active', 'trialing', 'past_due')
            ORDER BY created_at DESC
            LIMIT 1
        )
        UPDATE subscriptions s
        SET plan_name = $1,
            billing_interval = $2,
            updated_at = $3
        FROM target
        WHERE s.id = target.id
        RETURNING s.id
        "#,
    )
    .bind(&body.plan_name)
    .bind(legacy_billing_interval(body.billing_interval))
    .bind(now)
    .bind(&auth.tenant_id)
    .fetch_optional(&mut *tx)
    .await?;

    if updated_subscription_id.is_none() {
        return Ok((
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "No active subscription found" })),
        )
            .into_response());
    }

    sqlx::query("UPDATE tenants SET plan = $1, updated_at = $2 WHERE id = $3")
        .bind(&body.plan_name)
        .bind(now)
        .bind(&auth.tenant_id)
        .execute(&mut *tx)
        .await?;

    insert_audit_log(
        &mut tx,
        &auth.tenant_id,
        "plan.changed",
        "subscription",
        None,
        serde_json::json!({
            "newPlan": body.plan_name,
            "billingInterval": legacy_billing_interval(body.billing_interval),
            "proration": proration,
            "changeType": if proration.net_amount >= 0 { "upgrade" } else { "downgrade" },
        }),
        now,
    )
    .await?;

    tx.commit().await?;

    Ok(billing_success_response(serde_json::json!({
        "success": true,
        "proration": proration,
        "newPlan": body.plan_name,
        "billingInterval": legacy_billing_interval(body.billing_interval),
    })))
}

async fn cancel_subscription_request(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(body): Json<LegacyCancelBody>,
) -> Result<Response, ApiError> {
    let subscription = match get_route_subscription(&state.db, &auth.tenant_id).await? {
        Some(subscription) => subscription,
        None => {
            return Ok((
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({ "error": "No active subscription found" })),
            )
                .into_response())
        }
    };

    let now = Utc::now();
    let effective_date = if body.cancel_immediately {
        now
    } else {
        subscription.current_period_end
    };

    let mut tx = state.db.begin().await?;

    let rows_affected = if body.cancel_immediately {
        sqlx::query(
            r#"
            UPDATE subscriptions
            SET status = 'canceled',
                cancel_at_period_end = false,
                current_period_end = $1,
                updated_at = $1
            WHERE tenant_id = $2
              AND status IN ('active', 'trialing', 'past_due')
            "#,
        )
        .bind(now)
        .bind(&auth.tenant_id)
        .execute(&mut *tx)
        .await?
        .rows_affected()
    } else {
        sqlx::query(
            r#"
            UPDATE subscriptions
            SET cancel_at_period_end = true,
                updated_at = $1
            WHERE tenant_id = $2
              AND status IN ('active', 'trialing', 'past_due')
            "#,
        )
        .bind(now)
        .bind(&auth.tenant_id)
        .execute(&mut *tx)
        .await?
        .rows_affected()
    };

    if rows_affected == 0 {
        return Ok((
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "No active subscription found" })),
        )
            .into_response());
    }

    if body.cancel_immediately {
        sqlx::query("UPDATE tenants SET plan = $1, updated_at = $2 WHERE id = $3")
            .bind(LEGACY_DOWNGRADE_PLAN)
            .bind(now)
            .bind(&auth.tenant_id)
            .execute(&mut *tx)
            .await?;
    }

    insert_audit_log(
        &mut tx,
        &auth.tenant_id,
        "subscription.cancelled",
        "subscription",
        None,
        serde_json::json!({
            "previousPlan": subscription.plan_name,
            "reason": body.reason.unwrap_or_else(|| "not provided".to_string()),
            "feedback": body.feedback,
            "cancelImmediately": body.cancel_immediately,
            "effectiveDate": effective_date,
        }),
        now,
    )
    .await?;

    tx.commit().await?;

    Ok(billing_success_response(serde_json::json!({
        "success": true,
        "message": if body.cancel_immediately {
            "Subscription cancelled immediately"
        } else {
            "Subscription will be cancelled at the end of the billing period"
        },
        "effectiveDate": effective_date,
        "willDowngradeTo": LEGACY_DOWNGRADE_PLAN,
    })))
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
        Some(invoice) => Ok(Html(render_invoice_html(&invoice)).into_response()),
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
        .map_err(|error| match error {
            usage::UsageError::Db(db_error) => ApiError::from(db_error),
            usage::UsageError::Audit(audit_error) => ApiError::Internal(audit_error),
            usage::UsageError::Redis(pool_error) => ApiError::from(pool_error),
            usage::UsageError::RedisCmd(redis_error) => ApiError::from(redis_error),
        })?;

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
                    d.dunning_state,
                    w.balance AS wallet_balance
                FROM tenants t
                LEFT JOIN stripe_subscriptions s ON t.id = s.tenant_id
                LEFT JOIN plans p ON s.plan_id = p.id
                LEFT JOIN dunning_states d ON t.id = d.tenant_id
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
                    d.dunning_state,
                    w.balance AS wallet_balance
                FROM tenants t
                LEFT JOIN stripe_subscriptions s ON t.id = s.tenant_id
                LEFT JOIN plans p ON s.plan_id = p.id
                LEFT JOIN dunning_states d ON t.id = d.tenant_id
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

    let idempotency_key = body.idempotency_key.unwrap_or_else(|| {
        format!(
            "admin_credit_{}_{}_{}_{}",
            admin_actor_id(&auth),
            tenant_id,
            Utc::now().timestamp_millis(),
            Uuid::new_v4().simple(),
        )
    });

    let transaction = sqlx::query_as::<_, LegacyWalletTransactionRow>(
        r#"
        WITH ensure_wallet AS (
            INSERT INTO wallets (tenant_id, balance, reserved, currency, created_at, updated_at)
            VALUES ($2, 0, 0, DEFAULT, NOW(), NOW())
            ON CONFLICT (tenant_id) DO UPDATE SET updated_at = wallets.updated_at
            RETURNING id AS wallet_id, tenant_id
        ),
        updated_wallet AS (
            UPDATE wallets
            SET balance = balance + $1, updated_at = NOW()
            WHERE tenant_id = $2
            RETURNING id AS wallet_id, tenant_id, balance
        ),
        new_transaction AS (
            INSERT INTO wallet_transactions (
                id, tenant_id, wallet_id, type, amount, balance_after, description, reference, metadata, created_at
            )
            SELECT
                gen_random_uuid(),
                tenant_id,
                wallet_id,
                'credit',
                $1,
                balance,
                $3,
                $4,
                $5::jsonb,
                NOW()
            FROM updated_wallet
            RETURNING id::text AS id, tenant_id, type::text AS transaction_type, amount,
                      balance_after AS balance, description, reference, metadata, created_at
        ),
        audit_log AS (
            INSERT INTO audit_logs (id, tenant_id, action, resource_type, resource_id, metadata, created_at)
            SELECT
                gen_random_uuid(),
                nt.tenant_id,
                'wallet.credit',
                'wallet',
                nt.id,
                jsonb_build_object('amount', $1, 'description', $3, 'reference', $4, 'balanceAfter', nt.balance),
                NOW()
            FROM new_transaction nt
            RETURNING id
        )
        SELECT id, tenant_id, transaction_type, amount, balance, description, reference, metadata, created_at
        FROM new_transaction
        "#,
    )
    .bind(body.amount)
    .bind(&tenant_id)
    .bind(format!("Admin credit: {}", body.reason))
    .bind(&idempotency_key)
    .bind(serde_json::json!({
        "reason": body.reason,
        "expiresAt": body.expires_at,
    }))
    .fetch_one(&state.db)
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
    let admin_id = admin_actor_id(&auth);
    let expires_at = body.expires_at.as_deref().and_then(parse_query_date);

    sqlx::query(
        r#"
        INSERT INTO plan_overrides (
            tenant_id, plan_id, reason, admin_id, expires_at, created_at
        ) VALUES ($1, $2, $3, $4, $5, NOW())
        ON CONFLICT (tenant_id) DO UPDATE SET
            plan_id = $2,
            reason = $3,
            admin_id = $4,
            expires_at = $5,
            updated_at = NOW()
        "#,
    )
    .bind(&tenant_id)
    .bind(&body.plan_id)
    .bind(&body.reason)
    .bind(&admin_id)
    .bind(expires_at)
    .execute(&state.db)
    .await?;

    sqlx::query(
        r#"
        INSERT INTO billing_audit_log (
            tenant_id, action, actor_id, actor_type, details, created_at
        ) VALUES ($1, $2, $3, $4, $5, NOW())
        "#,
    )
    .bind(&tenant_id)
    .bind("plan_override")
    .bind(&admin_id)
    .bind("admin")
    .bind(serde_json::json!({
        "planId": body.plan_id,
        "reason": body.reason,
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

    sqlx::query(
        r#"
        INSERT INTO billing_audit_log (
            tenant_id, action, actor_id, actor_type, details, created_at
        ) VALUES ($1, $2, $3, $4, $5, NOW())
        "#,
    )
    .bind(&tenant_id)
    .bind("subscription_status_override")
    .bind(&admin_id)
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

    sqlx::query(
        r#"
        INSERT INTO billing_audit_log (
            tenant_id, action, actor_id, actor_type, details, created_at
        ) VALUES ($1, $2, $3, $4, $5, NOW())
        "#,
    )
    .bind(&tenant_id)
    .bind("dunning_reset")
    .bind(&admin_id)
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

    let invoice_number = generate_admin_invoice_number(&tenant_id);
    let base_line_items: Vec<(String, i64, i64, i64)> = body
        .line_items
        .iter()
        .map(|item| {
            (
                item.description.clone(),
                item.quantity,
                item.unit_price,
                item.quantity * item.unit_price,
            )
        })
        .collect();
    let subtotal: i64 = base_line_items
        .iter()
        .map(|(_, _, _, amount)| *amount)
        .sum();
    let (vat_rate, vat_total) = billing_service::invoices::calculate_vat(
        subtotal,
        &billing_address.country,
        billing_address.vat_number.as_deref(),
    );

    let mut allocated_vat = 0;
    let line_items: Vec<LegacyInvoiceLineItemDto> = base_line_items
        .iter()
        .enumerate()
        .map(|(index, (description, quantity, unit_price, amount))| {
            let vat_amount = if vat_total > 0 && subtotal > 0 {
                if index == base_line_items.len() - 1 {
                    vat_total - allocated_vat
                } else {
                    let value = (vat_total * *amount) / subtotal;
                    allocated_vat += value;
                    value
                }
            } else {
                0
            };

            LegacyInvoiceLineItemDto {
                description: description.clone(),
                quantity: *quantity,
                unit_price: *unit_price,
                amount: *amount,
                vat_rate,
                vat_amount,
            }
        })
        .collect();

    let total = subtotal + vat_total;
    let now = Utc::now();
    let due_at = now + chrono::Duration::days(DEFAULT_NET_DAYS);
    let currency = resolve_tenant_billing_currency(&state, &tenant_id).await;

    let inserted: (String, chrono::DateTime<Utc>, chrono::DateTime<Utc>) = sqlx::query_as(
        r#"
        INSERT INTO invoices (
            id, tenant_id, stripe_invoice_id, invoice_number, status, currency,
            subtotal, vat_total, total, line_items, billing_address,
            issued_at, due_at, period_start, period_end,
            purchase_order_number, notes, created_at, updated_at
        ) VALUES (
            gen_random_uuid(), $1, NULL, $2, 'draft', $3,
            $4, $5, $6, $7, $8,
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

    let report: serde_json::Value = sqlx::query_scalar(
        r#"
        SELECT COALESCE(json_agg(row_to_json(report_row) ORDER BY report_row.month DESC), '[]'::json)
        FROM (
            SELECT
                DATE_TRUNC('month', created_at) as month,
                COUNT(DISTINCT tenant_id) as active_subscriptions,
                SUM(
                    CASE
                        WHEN billing_interval = 'month' THEN amount
                        WHEN billing_interval = 'year' THEN amount / 12
                        ELSE 0
                    END
                ) as mrr
            FROM stripe_subscriptions
            WHERE status = 'active'
            GROUP BY DATE_TRUNC('month', created_at)
            ORDER BY month DESC
            LIMIT 12
        ) report_row
        "#,
    )
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

    let report: serde_json::Value = sqlx::query_scalar(
        r#"
        SELECT COALESCE(json_agg(row_to_json(report_row) ORDER BY report_row.month DESC), '[]'::json)
        FROM (
            WITH churned AS (
                SELECT
                    DATE_TRUNC('month', canceled_at) as month,
                    COUNT(*) as churned_count,
                    SUM(
                        CASE
                            WHEN billing_interval = 'month' THEN amount
                            WHEN billing_interval = 'year' THEN amount / 12
                            ELSE 0
                        END
                    ) as churned_mrr
                FROM stripe_subscriptions
                WHERE status = 'canceled' AND canceled_at IS NOT NULL
                GROUP BY DATE_TRUNC('month', canceled_at)
            ),
            starting AS (
                SELECT
                    c.month,
                    COUNT(DISTINCT s.tenant_id) as starting_count
                FROM churned c
                LEFT JOIN stripe_subscriptions s
                  ON s.status = 'active'
                 AND s.created_at < c.month
                GROUP BY c.month
            )
            SELECT
                c.month,
                c.churned_count,
                c.churned_mrr,
                COALESCE(s.starting_count, 0) as starting_count
            FROM churned c
            LEFT JOIN starting s ON s.month = c.month
            ORDER BY c.month DESC
            LIMIT 12
        ) report_row
        "#,
    )
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
                dunning_state,
                COUNT(*) as tenant_count,
                SUM(amount_owed) as total_owed
            FROM dunning_states
            WHERE dunning_state != 'healthy'
            GROUP BY dunning_state
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
                    s.amount, s.currency, s.billing_interval,
                    s.current_period_start, s.current_period_end,
                    s.created_at, s.canceled_at
                FROM stripe_subscriptions s
                JOIN tenants t ON s.tenant_id = t.id
                JOIN plans p ON s.plan_id = p.id
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
            kiwi_pbkdf2_iterations: 50_000,
            kiwi_argon_t: 2,
            kiwi_argon_p: 1,
            kiwi_difficulty_bits: 16,
            kiwi_challenge_ttl_secs: 120,
            kiwi_min_duration_ms: None,
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

        let redis_url =
            std::env::var("TEST_REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".into());
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
        assert!(has_admin_access(&auth_user(&["*"], "tenant_1")));
        assert!(has_admin_access(&auth_user(&["billing:admin"], "tenant_1")));
        assert!(!has_admin_access(&auth_user(&["tenant:*"], "tenant_1")));
        assert!(!has_admin_access(&auth_user(
            &["tenant:tenant_1"],
            "tenant_1"
        )));
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

    #[test]
    fn billing_routes_realtime_counter_key_uses_month_bucket() {
        let now = chrono::TimeZone::with_ymd_and_hms(&Utc, 2026, 3, 9, 12, 30, 0)
            .single()
            .expect("valid timestamp");
        assert_eq!(
            usage_realtime_counter_key("tenant_123", "emails_sent", now),
            "meter:rt:tenant_123:emails_sent:2026-03"
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
                vat_rate: 22,
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
    fn billing_routes_invoice_html_renderer_escapes_values_and_keeps_reverse_charge_note() {
        initialize_billing_test_env();

        let html = render_invoice_html(&sample_invoice());

        assert!(html.contains("Invoice 2026-TEST-001"));
        assert!(html.contains("Bel Consulting OÜ"));
        assert!(html.contains("Acme &lt;Billing&gt;"));
        assert!(html.contains("PO: PO-&lt;123&gt;"));
        assert!(html.contains("Handle &lt;carefully&gt; &amp; confirm"));
        assert!(html.contains("Reverse charge: VAT to be paid by the recipient"));
        assert!(html.contains("€122.00"));
        assert!(html.contains("IBAN: EE381010220123456789"));
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
