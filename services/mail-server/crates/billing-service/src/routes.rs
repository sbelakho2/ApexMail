//! Axum routes for the billing service.
//!
//! ```text
//! GET /plans – list active plans
//! GET /plans/:name – get plan by name
//! GET /usage – usage summary for current period
//! POST /usage/record – record a metering event
//! GET /invoices – list invoices (paginated)
//! GET /invoices/:id – get invoice by ID
//! GET /subscription – get active subscription
//! GET /quota – check quota status
//! GET /health – liveness probe
//! ```

use std::sync::Arc;
use std::time::Duration;

use axum::{
    extract::{DefaultBodyLimit, Path, Query, State},
    http::StatusCode,
    middleware,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use chrono::Datelike;
use apexmail_lib::{ErrorCode, ErrorEnvelope};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tower_http::timeout::TimeoutLayer;
use uuid::Uuid;
use axum::middleware::Next;
use axum::response::Response;

use crate::{
    config::{BillingConfig, PaygCalculationError, PaygPricing},
    invoices,
    plans,
    subscriptions,
    types::{BillingInterval, MeterEventType, Plan, PlanFeatures, SupportLevel},
    usage,
    AppState,
};

/// Build the full Axum router for billing.
pub fn router(state: Arc<AppState>) -> Router {
    let shared = state.clone();
    Router::new()
    .merge(crate::stripe_webhooks::router())
// Plans
    .route("/plans", get(list_plans).post(create_plan))
    .route("/plans/tenant/current", get(get_current_plan))
    .route("/plans/features/:feature", get(get_plan_feature))
    .route("/plans/tenant/features", get(get_plan_features))
    .route("/plans/tenant/limits", get(get_plan_limits))
    .route("/plans/compare/:planId1/:planId2", get(compare_plans))
    .route("/plans/seed", post(seed_plans))
    .route("/plans/:planId", get(get_plan).patch(update_plan))
    .route("/payg/pricing", get(get_payg_pricing))
    .route("/payg/estimate", post(estimate_payg_cost))
    .route("/payg/usage", get(get_payg_usage))
    .route("/overage/estimate", post(estimate_overage_cost))
    .route("/switch-plan", post(switch_plan))
    .route("/cancel", post(cancel_subscription_request))
    .route("/reports/revenue", get(get_revenue_report))
    .route("/reports/mrr", get(get_mrr_report))
    .route("/reports/churn", get(get_churn_report))
    .route("/reports/dunning", get(get_dunning_report))
    .route("/reports/costs", get(get_cost_report))
    .route("/export", get(export_billing_data))
// Usage
        .route("/usage", get(get_usage))
        .route("/usage/record", post(record_usage))
        .route("/usage/record-checked", post(record_usage_checked))
// Invoices
        .route("/invoices", get(list_invoices))
    .route("/invoices/:id", get(get_invoice))
// Subscription
        .route("/subscription", get(get_subscription))
// Quota
        .route("/quota", get(check_quota))
// Health
        .route("/health", get(health))
        .with_state(state)
        .layer(middleware::from_fn_with_state(shared, require_service_auth))
        .layer(DefaultBodyLimit::max(1024 * 1024)) // 1 MB
        .layer(TimeoutLayer::new(Duration::from_secs(30)))
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

async fn health() -> impl IntoResponse {
    (StatusCode::OK, Json(serde_json::json!({ "status": "ok" })))
}

fn error_response(
    status: StatusCode,
    code: ErrorCode,
    message: impl Into<String>,
) -> Response {
    (status, Json(ErrorEnvelope::new(code, message))).into_response()
}

/// GET /plans
async fn list_plans(
    State(state): State<Arc<AppState>>,
) -> Result<Response, ApiError> {
    let plans = plans::get_active_plans(&state.db).await?;
    let plans: Vec<LegacyPlanDto> = plans.into_iter().map(Into::into).collect();
    Ok(Json(serde_json::json!({ "plans": plans })).into_response())
}

/// GET /plans/:planId
async fn get_plan(
    State(state): State<Arc<AppState>>,
    Path(plan_id): Path<String>,
) -> Result<Response, ApiError> {
    let plan = plans::get_plan_by_name(&state.db, &plan_id).await?;
    match plan {
        Some(plan) => Ok((StatusCode::OK, Json(to_json_value(LegacyPlanDto::from(plan))?)).into_response()),
        None => Ok(error_response(
            StatusCode::NOT_FOUND,
            ErrorCode::NotFound,
            "Plan not found",
        )),
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
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
    support_level: String,
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
            support_level: legacy_support_level(features.support_level).to_string(),
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

impl From<LegacyPlanFeaturesPayload> for PlanFeatures {
    fn from(features: LegacyPlanFeaturesPayload) -> Self {
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
            support_level: parse_legacy_support_level(&features.support_level),
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
    id: Uuid,
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
    created_at: chrono::DateTime<chrono::Utc>,
    updated_at: chrono::DateTime<chrono::Utc>,
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

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct LegacyPlanCreateLimitsInput {
    emails_per_month: i64,
    api_calls_per_minute: i64,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct LegacyPlanPatchLimitsInput {
    emails_per_month: Option<i64>,
    api_calls_per_minute: Option<i64>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct LegacyPlanCreateBody {
    name: String,
    display_name: String,
    description: String,
    price_monthly: i64,
    price_yearly: i64,
    features: LegacyPlanFeaturesPayload,
    limits: LegacyPlanCreateLimitsInput,
    stripe_price_id_monthly: Option<String>,
    stripe_price_id_yearly: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct LegacyPlanPatchBody {
    display_name: Option<String>,
    description: Option<String>,
    price_monthly: Option<i64>,
    price_yearly: Option<i64>,
    features: Option<LegacyPlanFeaturesPayload>,
    limits: Option<LegacyPlanPatchLimitsInput>,
    stripe_price_id_monthly: Option<String>,
    stripe_price_id_yearly: Option<String>,
}

fn legacy_support_level(level: SupportLevel) -> &'static str {
    match level {
        SupportLevel::Community => "community",
        SupportLevel::Email => "email",
        SupportLevel::Priority => "priority",
        SupportLevel::Phone => "phone",
        SupportLevel::Dedicated => "dedicated",
    }
}

fn parse_legacy_support_level(level: &str) -> SupportLevel {
    match level {
        "email" => SupportLevel::Email,
        "priority" => SupportLevel::Priority,
        "phone" => SupportLevel::Phone,
        "dedicated" => SupportLevel::Dedicated,
        _ => SupportLevel::Community,
    }
}

fn legacy_feature_map(features: &LegacyPlanFeaturesPayload) -> serde_json::Map<String, serde_json::Value> {
    serde_json::to_value(features)
        .ok()
        .and_then(|value| value.as_object().cloned())
        .unwrap_or_default()
}

fn truthy_json(value: &serde_json::Value) -> bool {
    match value {
        serde_json::Value::Bool(value) => *value,
        serde_json::Value::Number(value) => value.as_i64().map(|n| n != 0)
            .or_else(|| value.as_u64().map(|n| n != 0))
            .or_else(|| value.as_f64().map(|n| n != 0.0))
            .unwrap_or(false),
        serde_json::Value::String(value) => !value.is_empty(),
        serde_json::Value::Null => false,
        serde_json::Value::Array(value) => !value.is_empty(),
        serde_json::Value::Object(value) => !value.is_empty(),
    }
}

fn feature_has_access(features: &LegacyPlanFeaturesPayload, feature: &str) -> Option<bool> {
    let feature_map = legacy_feature_map(features);
    feature_map.get(feature).map(truthy_json)
}

fn comparison_differences(
    plan1: &LegacyPlanFeaturesPayload,
    plan2: &LegacyPlanFeaturesPayload,
) -> Vec<serde_json::Value> {
    let features1 = legacy_feature_map(plan1);
    let features2 = legacy_feature_map(plan2);
    let mut keys: Vec<String> = features1
        .keys()
        .chain(features2.keys())
        .cloned()
        .collect();
    keys.sort();
    keys.dedup();

    keys.into_iter()
        .filter_map(|feature| {
            let value1 = features1.get(&feature).cloned().unwrap_or(serde_json::Value::Bool(false));
            let value2 = features2.get(&feature).cloned().unwrap_or(serde_json::Value::Bool(false));
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

async fn get_current_plan(
    State(state): State<Arc<AppState>>,
    Query(q): Query<TenantIdQuery>,
) -> Result<Response, ApiError> {
    let plan = plans::get_plan_for_tenant(&state.db, &q.tenant_id).await?;
    match plan {
        Some(plan) => Ok(Json(to_json_value(LegacyPlanLimitsDto::from(&plan))?).into_response()),
        None => Ok(Json(serde_json::Value::Null).into_response()),
    }
}

async fn get_plan_feature(
    State(state): State<Arc<AppState>>,
    Path(feature): Path<String>,
    Query(q): Query<TenantIdQuery>,
) -> Result<Response, ApiError> {
    let plan = plans::get_plan_for_tenant(&state.db, &q.tenant_id).await?;
    let has_access = plan
        .as_ref()
        .map(|plan| feature_has_access(&plan.features.clone().into(), &feature).unwrap_or(false))
        .unwrap_or(false);

    Ok(Json(serde_json::json!({
        "feature": feature,
        "hasAccess": has_access,
    })).into_response())
}

async fn get_plan_features(
    State(state): State<Arc<AppState>>,
    Query(q): Query<TenantIdQuery>,
) -> Result<Response, ApiError> {
    let plan = plans::get_plan_for_tenant(&state.db, &q.tenant_id).await?;
    match plan {
        Some(plan) => Ok(Json(to_json_value(LegacyPlanFeaturesPayload::from(plan.features))?).into_response()),
        None => Ok(Json(serde_json::json!({})).into_response()),
    }
}

async fn get_plan_limits(
    State(state): State<Arc<AppState>>,
    Query(q): Query<TenantIdQuery>,
) -> Result<Response, ApiError> {
    get_current_plan(State(state), Query(q)).await
}

async fn compare_plans(
    State(state): State<Arc<AppState>>,
    Path((plan_id1, plan_id2)): Path<(String, String)>,
) -> Result<Response, ApiError> {
    let plan1 = plans::get_plan_by_name(&state.db, &plan_id1).await?;
    let plan2 = plans::get_plan_by_name(&state.db, &plan_id2).await?;

    match (plan1, plan2) {
        (Some(plan1), Some(plan2)) => {
            let plan1_features = LegacyPlanFeaturesPayload::from(plan1.features.clone());
            let plan2_features = LegacyPlanFeaturesPayload::from(plan2.features.clone());
            Ok(Json(serde_json::json!({
                "plan1": {
                    "id": plan1.id,
                    "name": plan1.name,
                    "priceMonthly": plan1.price_monthly,
                    "features": plan1_features,
                    "limits": {
                        "emailLimit": plan1.email_limit,
                        "apiCallLimit": plan1.api_call_limit,
                    }
                },
                "plan2": {
                    "id": plan2.id,
                    "name": plan2.name,
                    "priceMonthly": plan2.price_monthly,
                    "features": plan2_features,
                    "limits": {
                        "emailLimit": plan2.email_limit,
                        "apiCallLimit": plan2.api_call_limit,
                    }
                },
                "differences": {
                    "priceDifference": plan2.price_monthly - plan1.price_monthly,
                    "featureDifferences": comparison_differences(
                        &LegacyPlanFeaturesPayload::from(plan1.features),
                        &LegacyPlanFeaturesPayload::from(plan2.features),
                    ),
                }
            })).into_response())
        }
        _ => Ok(error_response(
            StatusCode::NOT_FOUND,
            ErrorCode::NotFound,
            "One or both plans not found",
        )),
    }
}

async fn create_plan(
    State(state): State<Arc<AppState>>,
    Json(body): Json<LegacyPlanCreateBody>,
) -> Result<Response, ApiError> {
    let plan = plans::upsert_plan_input(
        &state.db,
        &plans::PlanUpsertInput {
            name: body.name,
            display_name: body.display_name,
            description: body.description,
            price_monthly: body.price_monthly,
            price_yearly: body.price_yearly,
            email_limit: body.limits.emails_per_month,
            api_call_limit: body.limits.api_calls_per_minute,
            sort_order: 0,
            features: body.features.into(),
            stripe_price_id_monthly: body.stripe_price_id_monthly,
            stripe_price_id_yearly: body.stripe_price_id_yearly,
        },
    ).await?;

    Ok((StatusCode::CREATED, Json(to_json_value(LegacyPlanDto::from(plan))?)).into_response())
}

async fn update_plan(
    State(state): State<Arc<AppState>>,
    Path(plan_id): Path<String>,
    Json(body): Json<LegacyPlanPatchBody>,
) -> Result<Response, ApiError> {
    let existing = plans::get_plan_by_name(&state.db, &plan_id).await?;
    let Some(existing) = existing else {
        return Ok(error_response(
            StatusCode::NOT_FOUND,
            ErrorCode::NotFound,
            "Plan not found",
        ));
    };

    let updated = plans::upsert_plan_input(
        &state.db,
        &plans::PlanUpsertInput {
            name: plan_id,
            display_name: body.display_name.unwrap_or(existing.display_name.clone()),
            description: body.description.unwrap_or(existing.description.clone()),
            price_monthly: body.price_monthly.unwrap_or(existing.price_monthly),
            price_yearly: body.price_yearly.unwrap_or(existing.price_yearly),
            email_limit: body
                .limits
                .as_ref()
                .and_then(|limits| limits.emails_per_month)
                .unwrap_or(existing.email_limit),
            api_call_limit: body
                .limits
                .as_ref()
                .and_then(|limits| limits.api_calls_per_minute)
                .unwrap_or(existing.api_call_limit),
            sort_order: existing.sort_order,
            features: body.features.map(Into::into).unwrap_or(existing.features),
            stripe_price_id_monthly: body.stripe_price_id_monthly.or(existing.stripe_price_id_monthly),
            stripe_price_id_yearly: body.stripe_price_id_yearly.or(existing.stripe_price_id_yearly),
        },
    ).await?;

    Ok(Json(to_json_value(LegacyPlanDto::from(updated))?).into_response())
}

async fn seed_plans(
    State(state): State<Arc<AppState>>,
) -> Result<Response, ApiError> {
    for plan in plans::default_plans() {
        plans::upsert_plan(&state.db, &plan).await?;
    }

    Ok(Json(serde_json::json!({ "message": "Default plans seeded" })).into_response())
}

const LEGACY_PAYG_MINIMUM_MONTHLY_CHARGE_CENTS: i64 = 0;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct LegacyPaygEmailTierDto {
    up_to: Option<u64>,
    price_per_email_millicents: i64,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct LegacyPaygApiPricingDto {
    free_calls_per_month: u64,
    price_per_thousand_calls_cents: u64,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct LegacyPaygPricingInfoDto {
    email_pricing: Vec<LegacyPaygEmailTierDto>,
    api_pricing: LegacyPaygApiPricingDto,
    minimum_monthly_charge: i64,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct LegacyPaygPricingDto {
    email_pricing: Vec<LegacyPaygEmailTierDto>,
    api_pricing: LegacyPaygApiPricingDto,
    minimum_monthly_charge_cents: i64,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct LegacyPaygCostDto {
    email_cost_cents: i64,
    api_cost_cents: i64,
    total_cost_cents: i64,
    email_cost_usd: String,
    api_cost_usd: String,
    total_cost_usd: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct LegacyPaygEstimateBody {
    emails_sent: i64,
    #[serde(default)]
    api_calls: i64,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct LegacyOverageEstimateBody {
    emails_sent: i64,
    email_limit: i64,
}

fn cents_to_usd_string(cents: i64) -> String {
    format!("${:.2}", cents as f64 / 100.0)
}

fn legacy_payg_email_pricing(pricing: &PaygPricing) -> Vec<LegacyPaygEmailTierDto> {
    pricing
        .email_tiers
        .iter()
        .map(|tier| LegacyPaygEmailTierDto {
            up_to: if tier.up_to == u64::MAX { None } else { Some(tier.up_to) },
            price_per_email_millicents: tier.price_per_email_millicents,
        })
        .collect()
}

fn legacy_payg_api_pricing(pricing: &PaygPricing) -> LegacyPaygApiPricingDto {
    LegacyPaygApiPricingDto {
        free_calls_per_month: pricing.free_api_calls_per_month,
        price_per_thousand_calls_cents: pricing.price_per_thousand_api_calls,
    }
}

fn legacy_payg_pricing_info(pricing: &PaygPricing) -> LegacyPaygPricingInfoDto {
    LegacyPaygPricingInfoDto {
        email_pricing: legacy_payg_email_pricing(pricing),
        api_pricing: legacy_payg_api_pricing(pricing),
        minimum_monthly_charge: LEGACY_PAYG_MINIMUM_MONTHLY_CHARGE_CENTS,
    }
}

fn legacy_payg_pricing_payload(pricing: &PaygPricing) -> LegacyPaygPricingDto {
    LegacyPaygPricingDto {
        email_pricing: legacy_payg_email_pricing(pricing),
        api_pricing: legacy_payg_api_pricing(pricing),
        minimum_monthly_charge_cents: LEGACY_PAYG_MINIMUM_MONTHLY_CHARGE_CENTS,
    }
}

fn legacy_payg_cost(
    pricing: &PaygPricing,
    emails_sent: u64,
    api_calls: u64,
) -> Result<LegacyPaygCostDto, PaygCalculationError> {
    let (email_cost_cents, api_cost_cents, total_cost_cents) = pricing.calculate(emails_sent, api_calls)?;

    Ok(LegacyPaygCostDto {
        email_cost_cents,
        api_cost_cents,
        total_cost_cents: total_cost_cents.max(LEGACY_PAYG_MINIMUM_MONTHLY_CHARGE_CENTS),
        email_cost_usd: cents_to_usd_string(email_cost_cents),
        api_cost_usd: cents_to_usd_string(api_cost_cents),
        total_cost_usd: cents_to_usd_string(total_cost_cents.max(LEGACY_PAYG_MINIMUM_MONTHLY_CHARGE_CENTS)),
    })
}

fn validate_non_negative(value: i64, field_name: &str) -> Result<u64, Response> {
    if value < 0 {
        return Err(error_response(
            StatusCode::BAD_REQUEST,
            ErrorCode::ValidationError,
            format!("{field_name} must be non-negative"),
        ));
    }

    Ok(value as u64)
}

async fn get_payg_pricing() -> Result<Response, ApiError> {
    let pricing = PaygPricing::default();
    Ok(Json(to_json_value(legacy_payg_pricing_info(&pricing))?).into_response())
}

async fn estimate_payg_cost(
    Json(body): Json<LegacyPaygEstimateBody>,
) -> Result<Response, ApiError> {
    let emails_sent = match validate_non_negative(body.emails_sent, "emailsSent") {
        Ok(value) => value,
        Err(response) => return Ok(response),
    };
    let api_calls = match validate_non_negative(body.api_calls, "apiCalls") {
        Ok(value) => value,
        Err(response) => return Ok(response),
    };

    let pricing = PaygPricing::default();
    let cost = match legacy_payg_cost(&pricing, emails_sent, api_calls) {
        Ok(cost) => cost,
        Err(err) => {
            tracing::warn!(error = %err, emails_sent, api_calls, "rejected PAYG estimate outside supported range");
            return Ok(error_response(
                StatusCode::BAD_REQUEST,
                ErrorCode::InvalidInput,
                err.to_string(),
            ));
        }
    };

    Ok(Json(serde_json::json!({
        "usage": {
            "emailsSent": emails_sent,
            "apiCalls": api_calls,
        },
        "cost": cost,
        "pricing": legacy_payg_pricing_payload(&pricing),
    })).into_response())
}

async fn estimate_overage_cost(
    Json(body): Json<LegacyOverageEstimateBody>,
) -> Result<Response, ApiError> {
    let emails_sent = match validate_non_negative(body.emails_sent, "emailsSent") {
        Ok(value) => value as i64,
        Err(response) => return Ok(response),
    };
    let overage_cost_cents = plans::calculate_overage_cost(emails_sent, body.email_limit);

    Ok(Json(serde_json::json!({
        "usage": {
            "emailsSent": emails_sent,
            "emailLimit": body.email_limit,
        },
        "overageCostCents": overage_cost_cents,
        "overageCostUsd": cents_to_usd_string(overage_cost_cents),
    })).into_response())
}

async fn get_payg_usage(
    State(state): State<Arc<AppState>>,
    Query(q): Query<TenantIdQuery>,
) -> Result<Response, ApiError> {
    let now = chrono::Utc::now();
    let month_start_date = now
        .date_naive()
        .with_day(1)
        .unwrap_or(now.date_naive());
    let period_start = month_start_date
        .and_time(chrono::NaiveTime::MIN)
        .and_utc();
    let period_end = period_start + chrono::Months::new(1);

    let summary = usage::get_usage(&state.db, &q.tenant_id, period_start, period_end).await?;
    let emails_sent = summary.emails_sent.max(0) as u64;
    let api_calls = summary.api_calls.max(0) as u64;
    let pricing = PaygPricing::default();
    let cost = legacy_payg_cost(&pricing, emails_sent, api_calls).map_err(|err| {
        tracing::error!(error = %err, tenant_id = %q.tenant_id, emails_sent, api_calls, "persisted PAYG usage exceeded supported range");
        sqlx::Error::Protocol(err.to_string())
    })?;

    Ok(Json(serde_json::json!({
        "period": {
            "start": summary.period_start.to_rfc3339(),
            "end": summary.period_end.to_rfc3339(),
        },
        "usage": {
            "emailsSent": emails_sent,
            "apiCalls": api_calls,
        },
        "cost": cost,
        "pricing": legacy_payg_pricing_payload(&pricing),
    })).into_response())
}

const MILLISECONDS_PER_DAY: i64 = 86_400_000;
const LEGACY_DOWNGRADE_PLAN: &str = "free";

#[derive(Debug, Clone)]
struct RouteSubscription {
    plan_name: String,
    billing_interval: BillingInterval,
    current_period_start: chrono::DateTime<chrono::Utc>,
    current_period_end: chrono::DateTime<chrono::Utc>,
}

#[derive(sqlx::FromRow)]
struct RouteSubscriptionRow {
    plan_name: String,
    billing_interval: String,
    current_period_start: chrono::DateTime<chrono::Utc>,
    current_period_end: chrono::DateTime<chrono::Utc>,
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
    effective_date: chrono::DateTime<chrono::Utc>,
    explanation: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    warnings: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct LegacySwitchPlanBody {
    plan_name: String,
    #[serde(default = "default_billing_interval")]
    billing_interval: BillingInterval,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct LegacyCancelBody {
    reason: Option<String>,
    feedback: Option<String>,
    #[serde(default)]
    cancel_immediately: bool,
}

fn default_billing_interval() -> BillingInterval {
    BillingInterval::Monthly
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

fn ceil_day_count(duration_ms: i64) -> i64 {
    if duration_ms <= 0 {
        0
    } else {
        (duration_ms + MILLISECONDS_PER_DAY - 1) / MILLISECONDS_PER_DAY
    }
}

fn preview_plan_proration(
    config: &BillingConfig,
    current_plan: &Plan,
    new_plan: &Plan,
    subscription: &RouteSubscription,
) -> Result<LegacyProrationDto, String> {
    let now = chrono::Utc::now();
    let days_in_period = ceil_day_count(
        subscription
            .current_period_end
            .signed_duration_since(subscription.current_period_start)
            .num_milliseconds(),
    );
    if days_in_period <= 0 {
        return Err("Invalid period: daysInPeriod must be greater than 0".to_string());
    }

    let days_elapsed = ceil_day_count(
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
        explanation: build_proration_explanation(
            current_plan,
            new_plan,
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

fn build_proration_explanation(
    current_plan: &Plan,
    new_plan: &Plan,
    current_price: i64,
    new_price: i64,
    days_remaining: i64,
    days_in_period: i64,
    credit_amount: i64,
    charge_amount: i64,
    net_amount: i64,
) -> String {
    let format_currency = |cents: i64| format!("${:.2}", cents.abs() as f64 / 100.0);

    let mut lines = vec![
        format!(
            "Plan change from {} to {}",
            current_plan.display_name, new_plan.display_name
        ),
        String::new(),
        format!(
            "Current period: {} days remaining out of {} days",
            days_remaining, days_in_period
        ),
        String::new(),
        format!(
            "Credit for unused {} time: {}",
            current_plan.display_name,
            format_currency(credit_amount)
        ),
        format!(
            "({} / {} days × {} days)",
            format_currency(current_price),
            days_in_period,
            days_remaining
        ),
        String::new(),
        format!(
            "Charge for {} remaining time: {}",
            new_plan.display_name,
            format_currency(charge_amount)
        ),
        format!(
            "({} / {} days × {} days)",
            format_currency(new_price),
            days_in_period,
            days_remaining
        ),
        String::new(),
    ];

    if net_amount > 0 {
        lines.push(format!("Net charge: {}", format_currency(net_amount)));
    } else if net_amount < 0 {
        lines.push(format!(
            "Net credit: {} (applied to next invoice)",
            format_currency(net_amount)
        ));
    } else {
        lines.push("No additional charge or credit".to_string());
    }

    lines.join("\n")
}

fn generate_audit_log_id() -> String {
    Uuid::new_v4().simple().to_string().chars().take(26).collect()
}

fn compute_audit_log_hash(
    tenant_id: &str,
    action: &str,
    resource_type: &str,
    resource_id: Option<&str>,
    metadata: &serde_json::Value,
    previous_hash: Option<&str>,
    timestamp: chrono::DateTime<chrono::Utc>,
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
    timestamp: chrono::DateTime<chrono::Utc>,
) -> Result<(), ApiError> {
    let previous_hash: Option<String> = sqlx::query_scalar(
        "SELECT hash FROM audit_logs WHERE tenant_id = $1 ORDER BY timestamp DESC LIMIT 1",
    )
    .bind(tenant_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(ApiError::Plans)?;

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
    .await
    .map_err(ApiError::Plans)?;

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
    .await
    .map_err(ApiError::Plans)?;

    Ok(row.map(RouteSubscriptionRow::into_subscription))
}

async fn switch_plan(
    State(state): State<Arc<AppState>>,
    Query(q): Query<TenantIdQuery>,
    Json(body): Json<LegacySwitchPlanBody>,
) -> Result<Response, ApiError> {
    let now = chrono::Utc::now();

    if body.plan_name == "payg" {
        let current_subscription = get_route_subscription(&state.db, &q.tenant_id).await?;
        let effective_date = current_subscription
            .as_ref()
            .map(|subscription| subscription.current_period_end)
            .unwrap_or(now);
        let previous_plan = current_subscription
            .as_ref()
            .map(|subscription| subscription.plan_name.clone())
            .unwrap_or_else(|| "unknown".to_string());

        let mut tx = state.db.begin().await.map_err(ApiError::Plans)?;

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
            .bind(&q.tenant_id)
            .execute(&mut *tx)
            .await
            .map_err(ApiError::Plans)?;
        }

        let tenant_update = sqlx::query("UPDATE tenants SET plan = 'payg', updated_at = $1 WHERE id = $2")
            .bind(now)
            .bind(&q.tenant_id)
            .execute(&mut *tx)
            .await
            .map_err(ApiError::Plans)?;

        if tenant_update.rows_affected() != 1 {
            return Ok(error_response(
                StatusCode::NOT_FOUND,
                ErrorCode::NotFound,
                "Tenant not found",
            ));
        }

        insert_audit_log(
            &mut tx,
            &q.tenant_id,
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
        ).await?;

        tx.commit().await.map_err(ApiError::Plans)?;

        return Ok(Json(serde_json::json!({
            "success": true,
            "message": "Switched to Pay As You Go billing",
            "effectiveDate": effective_date,
        }))
            .into_response());
    }

    let subscription = match get_route_subscription(&state.db, &q.tenant_id).await? {
        Some(subscription) => subscription,
        None => {
            return Ok(error_response(
                StatusCode::NOT_FOUND,
                ErrorCode::NotFound,
                "No active subscription found",
            ))
        }
    };

    let current_plan = match plans::get_plan_by_name(&state.db, &subscription.plan_name).await? {
        Some(plan) => plan,
        None => {
            return Ok(error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                ErrorCode::InternalError,
                "Operation failed",
            ))
        }
    };

    let new_plan = match plans::get_plan_by_name(&state.db, &body.plan_name).await? {
        Some(plan) => plan,
        None => {
            return Ok(error_response(
                StatusCode::NOT_FOUND,
                ErrorCode::NotFound,
                "Plan not found",
            ))
        }
    };

    let proration = match preview_plan_proration(&state.config, &current_plan, &new_plan, &subscription)
    {
        Ok(proration) => proration,
        Err(error) => {
            return Ok(error_response(
                StatusCode::BAD_REQUEST,
                ErrorCode::InvalidInput,
                error,
            ))
        }
    };

    let mut tx = state.db.begin().await.map_err(ApiError::Plans)?;

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
    .bind(&q.tenant_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(ApiError::Plans)?;

    if updated_subscription_id.is_none() {
        return Ok(error_response(
            StatusCode::NOT_FOUND,
            ErrorCode::NotFound,
            "No active subscription found",
        ));
    }

    sqlx::query("UPDATE tenants SET plan = $1, updated_at = $2 WHERE id = $3")
        .bind(&body.plan_name)
        .bind(now)
        .bind(&q.tenant_id)
        .execute(&mut *tx)
        .await
        .map_err(ApiError::Plans)?;

    insert_audit_log(
        &mut tx,
        &q.tenant_id,
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
    ).await?;

    tx.commit().await.map_err(ApiError::Plans)?;

    Ok(Json(serde_json::json!({
        "success": true,
        "proration": proration,
        "newPlan": body.plan_name,
        "billingInterval": legacy_billing_interval(body.billing_interval),
    }))
        .into_response())
}

async fn cancel_subscription_request(
    State(state): State<Arc<AppState>>,
    Query(q): Query<TenantIdQuery>,
    Json(body): Json<LegacyCancelBody>,
) -> Result<Response, ApiError> {
    let subscription = match get_route_subscription(&state.db, &q.tenant_id).await? {
        Some(subscription) => subscription,
        None => {
            return Ok(error_response(
                StatusCode::NOT_FOUND,
                ErrorCode::NotFound,
                "No active subscription found",
            ))
        }
    };

    let now = chrono::Utc::now();
    let effective_date = if body.cancel_immediately {
        now
    } else {
        subscription.current_period_end
    };

    let mut tx = state.db.begin().await.map_err(ApiError::Plans)?;

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
        .bind(&q.tenant_id)
        .execute(&mut *tx)
        .await
        .map_err(ApiError::Plans)?
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
        .bind(&q.tenant_id)
        .execute(&mut *tx)
        .await
        .map_err(ApiError::Plans)?
        .rows_affected()
    };

    if rows_affected == 0 {
        return Ok(error_response(
            StatusCode::NOT_FOUND,
            ErrorCode::NotFound,
            "No active subscription found",
        ));
    }

    if body.cancel_immediately {
        sqlx::query("UPDATE tenants SET plan = $1, updated_at = $2 WHERE id = $3")
            .bind(LEGACY_DOWNGRADE_PLAN)
            .bind(now)
            .bind(&q.tenant_id)
            .execute(&mut *tx)
            .await
            .map_err(ApiError::Plans)?;
    }

    insert_audit_log(
        &mut tx,
        &q.tenant_id,
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
    ).await?;

    tx.commit().await.map_err(ApiError::Plans)?;

    Ok(Json(serde_json::json!({
        "success": true,
        "message": if body.cancel_immediately {
            "Subscription cancelled immediately"
        } else {
            "Subscription will be cancelled at the end of the billing period"
        },
        "effectiveDate": effective_date,
        "willDowngradeTo": LEGACY_DOWNGRADE_PLAN,
    }))
        .into_response())
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct DateRangeQuery {
    start_date: Option<String>,
    end_date: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct BillingExportQuery {
    #[serde(rename = "type")]
    export_type: Option<String>,
    start_date: Option<String>,
    end_date: Option<String>,
    #[serde(default = "default_export_format")]
    format: String,
}

#[derive(Deserialize)]
struct TenantIdQuery {
    tenant_id: String,
}

fn default_export_format() -> String {
    "csv".to_string()
}

fn parse_query_date(value: &str) -> Option<chrono::DateTime<chrono::Utc>> {
    chrono::DateTime::parse_from_rfc3339(value)
        .map(|date| date.with_timezone(&chrono::Utc))
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
        .unwrap_or_else(|_| error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            ErrorCode::InternalError,
            "Operation failed",
        ))
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
            .map(|header| sanitize_csv_value(object.get(header).unwrap_or(&serde_json::Value::Null)))
            .collect::<Vec<_>>();
        csv_rows.push(values.join(","));
    }

    csv_rows.join("\n")
}

fn safe_export_date(value: &str) -> String {
    value.chars().filter(|character| character.is_ascii_digit() || *character == '-').collect()
}

async fn get_revenue_report(
    State(state): State<Arc<AppState>>,
    Query(query): Query<DateRangeQuery>,
) -> Result<Response, ApiError> {
    let (Some(start_date), Some(end_date)) = (query.start_date.as_deref(), query.end_date.as_deref()) else {
        return Ok(error_response(
            StatusCode::BAD_REQUEST,
            ErrorCode::ValidationError,
            "startDate and endDate required",
        ));
    };

    let (Some(start_date), Some(end_date)) = (parse_query_date(start_date), parse_query_date(end_date)) else {
        return Ok(error_response(
            StatusCode::BAD_REQUEST,
            ErrorCode::InvalidInput,
            "Invalid startDate or endDate",
        ));
    };

    let report: serde_json::Value = sqlx::query_scalar(
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
        "#,
    )
    .bind(start_date)
    .bind(end_date)
    .fetch_one(&state.db)
    .await
    .map_err(ApiError::Plans)?;

    Ok(Json(serde_json::json!({ "report": report })).into_response())
}

async fn get_mrr_report(
    State(state): State<Arc<AppState>>,
) -> Result<Response, ApiError> {
    let report: serde_json::Value = sqlx::query_scalar(
        r#"
        SELECT COALESCE(json_agg(row_to_json(report_row) ORDER BY report_row.month DESC), '[]'::json)
        FROM (
            SELECT
                DATE_TRUNC('month', s.created_at) as month,
                COUNT(DISTINCT s.tenant_id) as active_subscriptions,
                SUM(
                    CASE
                        WHEN s.billing_interval = 'monthly' THEN p.price_monthly
                        WHEN s.billing_interval = 'yearly' THEN p.price_yearly / 12
                        ELSE 0
                    END
                ) as mrr
            FROM subscriptions s
            JOIN plans p ON p.name = s.plan_name
            WHERE s.status = 'active'
            GROUP BY DATE_TRUNC('month', s.created_at)
            ORDER BY month DESC
            LIMIT 12
        ) report_row
        "#,
    )
    .fetch_one(&state.db)
    .await
    .map_err(ApiError::Plans)?;

    Ok(Json(serde_json::json!({ "report": report })).into_response())
}

async fn get_churn_report(
    State(state): State<Arc<AppState>>,
) -> Result<Response, ApiError> {
    let report: serde_json::Value = sqlx::query_scalar(
        r#"
        SELECT COALESCE(json_agg(row_to_json(report_row) ORDER BY report_row.month DESC), '[]'::json)
        FROM (
            WITH churned AS (
                SELECT
                    DATE_TRUNC('month', s.updated_at) as month,
                    COUNT(*) as churned_count,
                    SUM(
                        CASE
                            WHEN s.billing_interval = 'monthly' THEN p.price_monthly
                            WHEN s.billing_interval = 'yearly' THEN p.price_yearly / 12
                            ELSE 0
                        END
                    ) as churned_mrr
                FROM subscriptions s
                JOIN plans p ON p.name = s.plan_name
                WHERE s.status = 'canceled'
                GROUP BY DATE_TRUNC('month', s.updated_at)
            ),
            starting AS (
                SELECT
                    c.month,
                    COUNT(DISTINCT s.tenant_id) as starting_count
                FROM churned c
                LEFT JOIN subscriptions s
                  ON s.created_at < c.month
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
    .await
    .map_err(ApiError::Plans)?;

    Ok(Json(serde_json::json!({ "report": report })).into_response())
}

async fn get_dunning_report(
    State(state): State<Arc<AppState>>,
) -> Result<Response, ApiError> {
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
    .await
    .map_err(ApiError::Plans)?;

    Ok(Json(serde_json::json!({ "report": report })).into_response())
}

async fn get_cost_report(
    State(state): State<Arc<AppState>>,
    Query(query): Query<DateRangeQuery>,
) -> Result<Response, ApiError> {
    let (Some(start_date), Some(end_date)) = (query.start_date.as_deref(), query.end_date.as_deref()) else {
        return Ok(error_response(
            StatusCode::BAD_REQUEST,
            ErrorCode::ValidationError,
            "startDate and endDate required",
        ));
    };

    let (Some(start_date), Some(end_date)) = (parse_query_date(start_date), parse_query_date(end_date)) else {
        return Ok(error_response(
            StatusCode::BAD_REQUEST,
            ErrorCode::InvalidInput,
            "Invalid startDate or endDate",
        ));
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
    .await
    .map_err(ApiError::Plans)?;

    Ok(Json(serde_json::json!({ "report": report })).into_response())
}

async fn export_billing_data(
    State(state): State<Arc<AppState>>,
    Query(query): Query<BillingExportQuery>,
) -> Result<Response, ApiError> {
    let (Some(export_type), Some(start_date), Some(end_date)) = (
        query.export_type.as_deref(),
        query.start_date.as_deref(),
        query.end_date.as_deref(),
    ) else {
        return Ok(error_response(
            StatusCode::BAD_REQUEST,
            ErrorCode::ValidationError,
            "type, startDate, and endDate required",
        ));
    };

    let (Some(start_date_parsed), Some(end_date_parsed)) = (parse_query_date(start_date), parse_query_date(end_date)) else {
        return Ok(error_response(
            StatusCode::BAD_REQUEST,
            ErrorCode::InvalidInput,
            "Invalid startDate or endDate",
        ));
    };

    let export_query = match export_type {
        "invoices" => Some(
            r#"
            SELECT COALESCE(json_agg(row_to_json(export_row) ORDER BY export_row.issued_at), '[]'::json)
            FROM (
                SELECT
                    i.invoice_number, i.tenant_id, t.name as tenant_name,
                    NULL::bigint as subtotal,
                    NULL::bigint as tax_amount,
                    i.amount_cents as total,
                    i.currency,
                    i.status,
                    i.created_at as issued_at,
                    i.paid_at,
                    i.due_date
                FROM invoices i
                JOIN tenants t ON i.tenant_id = t.id
                WHERE i.created_at >= $1 AND i.created_at < $2
                ORDER BY i.created_at
            ) export_row
            "#,
        ),
        "subscriptions" => Some(
            r#"
            SELECT COALESCE(json_agg(row_to_json(export_row) ORDER BY export_row.created_at), '[]'::json)
            FROM (
                SELECT
                    s.tenant_id, t.name as tenant_name,
                    s.plan_name, s.status,
                    CASE
                        WHEN s.billing_interval = 'yearly' THEN p.price_yearly
                        ELSE p.price_monthly
                    END as amount,
                    'usd'::text as currency,
                    s.billing_interval,
                    s.current_period_start, s.current_period_end,
                    s.created_at,
                    CASE WHEN s.status = 'canceled' THEN s.updated_at ELSE NULL END as canceled_at
                FROM subscriptions s
                JOIN tenants t ON s.tenant_id = t.id
                JOIN plans p ON s.plan_name = p.name
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
        return Ok(error_response(
            StatusCode::BAD_REQUEST,
            ErrorCode::InvalidInput,
            "Invalid export type",
        ));
    };

    let data: serde_json::Value = sqlx::query_scalar(export_query)
        .bind(start_date_parsed)
        .bind(end_date_parsed)
        .fetch_one(&state.db)
        .await
        .map_err(ApiError::Plans)?;

    if query.format.eq_ignore_ascii_case("json") {
        return Ok(Json(serde_json::json!({ "data": data })).into_response());
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

/// Query params shared by usage + invoice endpoints.
#[derive(Deserialize)]
struct TenantQuery {
    tenant_id: String,
}

/// GET /usage?tenant_id=...
async fn get_usage(
    State(state): State<Arc<AppState>>,
    Query(q): Query<TenantQuery>,
) -> Result<impl IntoResponse, ApiError> {
    let now = chrono::Utc::now();
    let month_start_date = now
        .date_naive()
        .with_day(1)
        .unwrap_or(now.date_naive());
    let period_start = month_start_date
        .and_time(chrono::NaiveTime::MIN)
        .and_utc();
    let period_end = period_start + chrono::Months::new(1);
    let summary = usage::get_usage(&state.db, &q.tenant_id, period_start, period_end).await?;
    Ok(Json(summary))
}

/// POST /usage/record
#[derive(Deserialize)]
struct RecordUsageBody {
    tenant_id: String,
    event_type: MeterEventType,
    #[serde(default = "default_qty")]
    quantity: i64,
    event_id: Option<Uuid>,
    metadata: Option<serde_json::Value>,
}

fn default_qty() -> i64 {
    1
}

async fn record_usage(
    State(state): State<Arc<AppState>>,
    Json(body): Json<RecordUsageBody>,
) -> Result<impl IntoResponse, ApiError> {
    let recorded = usage::record_usage(
        &state.db,
        &state.redis,
        &body.tenant_id,
        body.event_type,
        body.quantity,
        body.event_id,
        body.metadata,
    )
    .await?;
    Ok((
        StatusCode::CREATED,
        Json(serde_json::json!({ "recorded": recorded })),
    ))
}

/// POST /usage/record-checked
/// Atomically check quota and record a metering event in a single operation.
/// Avoids the TOCTOU window of separate `GET /quota` + `POST /usage/record`.
async fn record_usage_checked(
    State(state): State<Arc<AppState>>,
    Json(body): Json<RecordUsageBody>,
) -> Result<impl IntoResponse, ApiError> {
    let result = usage::record_with_quota_check(
        &state.db,
        &state.redis,
        &body.tenant_id,
        body.event_type,
        body.quantity,
        body.event_id,
        body.metadata,
    )
    .await?;
    let status = if result.allowed {
        StatusCode::CREATED
    } else {
        StatusCode::TOO_MANY_REQUESTS
    };
    Ok((status, Json(serde_json::to_value(&result).unwrap_or_default())))
}

/// Query params for invoice listing.
#[derive(Deserialize)]
struct InvoiceListQuery {
    tenant_id: String,
    #[serde(default = "default_limit")]
    limit: i64,
    #[serde(default)]
    offset: i64,
}

fn default_limit() -> i64 {
    50
}

fn clamp_limit(limit: i64, max: i64) -> i64 {
    limit.clamp(1, max)
}

fn clamp_offset(offset: i64, max: i64) -> i64 {
    offset.clamp(0, max)
}

/// GET /invoices?tenant_id=...&limit=...&offset=...
async fn list_invoices(
    State(state): State<Arc<AppState>>,
    Query(q): Query<InvoiceListQuery>,
) -> Result<impl IntoResponse, ApiError> {
    let invoices = invoices::list_invoices(
        &state.db,
        &q.tenant_id,
        clamp_limit(q.limit, 500),
        clamp_offset(q.offset, 100_000),
    )
    .await?;
    Ok(Json(serde_json::json!({ "invoices": invoices })))
}

/// GET /invoices/:id?tenant_id=...
async fn get_invoice(
    State(state): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
    Query(q): Query<TenantQuery>,
) -> Result<impl IntoResponse, ApiError> {
    let invoice = invoices::get_invoice_by_id(&state.db, id).await?;
    match invoice {
        Some(inv) if inv.tenant_id == q.tenant_id => {
            Ok((StatusCode::OK, Json(to_json_value(inv)?)).into_response())
        }
        Some(_) | None => Ok(error_response(
            StatusCode::NOT_FOUND,
            ErrorCode::NotFound,
            "Invoice not found",
        )),
    }
}

/// GET /subscription?tenant_id=...
async fn get_subscription(
    State(state): State<Arc<AppState>>,
    Query(q): Query<TenantQuery>,
) -> Result<impl IntoResponse, ApiError> {
    let sub = subscriptions::get_subscription(&state.db, &q.tenant_id).await?;
    match sub {
        Some(s) => Ok(Json(serde_json::json!({ "subscription": s })).into_response()),
        None => Ok(Json(
            serde_json::json!({ "subscription": null, "message": "No active subscription" }),
        )
        .into_response()),
    }
}

/// GET /quota?tenant_id=...
async fn check_quota(
    State(state): State<Arc<AppState>>,
    Query(q): Query<TenantQuery>,
) -> Result<impl IntoResponse, ApiError> {
    let status = usage::check_quota(&state.db, &state.redis, &q.tenant_id).await?;
    Ok(Json(status))
}

// ---------------------------------------------------------------------------
// Error mapping
// ---------------------------------------------------------------------------

/// Unified API error that maps domain errors → HTTP responses.
#[derive(Debug)]
enum ApiError {
    Plans(sqlx::Error),
    Usage(usage::UsageError),
    Invoice(invoices::InvoiceError),
    Subscription(subscriptions::SubscriptionError),
}

impl From<sqlx::Error> for ApiError {
    fn from(e: sqlx::Error) -> Self {
        Self::Plans(e)
    }
}
impl From<usage::UsageError> for ApiError {
    fn from(e: usage::UsageError) -> Self {
        Self::Usage(e)
    }
}
impl From<invoices::InvoiceError> for ApiError {
    fn from(e: invoices::InvoiceError) -> Self {
        Self::Invoice(e)
    }
}
impl From<subscriptions::SubscriptionError> for ApiError {
    fn from(e: subscriptions::SubscriptionError) -> Self {
        Self::Subscription(e)
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> axum::response::Response {
        let (status, code, message) = match &self {
            ApiError::Plans(sqlx::Error::RowNotFound) => {
                (StatusCode::NOT_FOUND, ErrorCode::NotFound, "plan not found".to_string())
            }
            ApiError::Plans(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                ErrorCode::InternalError,
                "internal server error".to_string(),
            ),
            ApiError::Usage(usage::UsageError::Db(sqlx::Error::RowNotFound)) => {
                (
                    StatusCode::NOT_FOUND,
                    ErrorCode::NotFound,
                    "billing resource not found".to_string(),
                )
            }
            ApiError::Usage(usage::UsageError::Redis(_))
            | ApiError::Usage(usage::UsageError::RedisCmd(_)) => {
                (
                    StatusCode::SERVICE_UNAVAILABLE,
                    ErrorCode::ServiceUnavailable,
                    "billing cache unavailable".to_string(),
                )
            }
            ApiError::Usage(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                ErrorCode::InternalError,
                "internal server error".to_string(),
            ),
            ApiError::Invoice(invoices::InvoiceError::Db(sqlx::Error::RowNotFound)) => {
                (
                    StatusCode::NOT_FOUND,
                    ErrorCode::NotFound,
                    "invoice not found".to_string(),
                )
            }
            ApiError::Invoice(invoices::InvoiceError::NoBillingAddress) => {
                (
                    StatusCode::NOT_FOUND,
                    ErrorCode::NotFound,
                    "billing address not found for tenant".to_string(),
                )
            }
            ApiError::Invoice(invoices::InvoiceError::PdfGeneration(_)) => {
                (
                    StatusCode::SERVICE_UNAVAILABLE,
                    ErrorCode::ServiceUnavailable,
                    "pdf generation unavailable".to_string(),
                )
            }
            ApiError::Invoice(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                ErrorCode::InternalError,
                "internal server error".to_string(),
            ),
            ApiError::Subscription(subscriptions::SubscriptionError::PlanNotFound(name)) => {
                (
                    StatusCode::NOT_FOUND,
                    ErrorCode::NotFound,
                    format!("plan not found: {name}"),
                )
            }
            ApiError::Subscription(subscriptions::SubscriptionError::NotFound) => {
                (
                    StatusCode::NOT_FOUND,
                    ErrorCode::NotFound,
                    "active subscription not found".to_string(),
                )
            }
            ApiError::Subscription(subscriptions::SubscriptionError::Db(sqlx::Error::RowNotFound)) => {
                (
                    StatusCode::NOT_FOUND,
                    ErrorCode::NotFound,
                    "active subscription not found".to_string(),
                )
            }
            ApiError::Subscription(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                ErrorCode::InternalError,
                "internal server error".to_string(),
            ),
        };
        if status.is_server_error() {
            tracing::error!(error = ?self, status = %status, code = %code, "billing API error");
        } else {
            tracing::warn!(error = ?self, status = %status, code = %code, "billing API error");
        }
        error_response(status, code, message)
    }
}

fn to_json_value<T: serde::Serialize>(value: T) -> Result<serde_json::Value, ApiError> {
    serde_json::to_value(value)
        .map_err(|e| ApiError::Plans(sqlx::Error::Decode(Box::new(e))))
}

async fn require_service_auth(
    State(state): State<Arc<AppState>>,
    req: axum::http::Request<axum::body::Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    if matches!(req.uri().path(), "/health" | "/webhooks/stripe") {
        return Ok(next.run(req).await);
    }

    let token = extract_token(req.headers());
    if token.as_deref() == Some(state.config.service_auth_token.as_str())
        && !state.config.service_auth_token.is_empty()
    {
        Ok(next.run(req).await)
    } else {
        Err(StatusCode::UNAUTHORIZED)
    }
}

fn extract_token(headers: &axum::http::HeaderMap) -> Option<String> {
    if let Some(value) = headers.get("x-api-key") {
        return value.to_str().ok().map(|s| s.to_string());
    }
    if let Some(value) = headers.get(axum::http::header::AUTHORIZATION) {
        if let Ok(raw) = value.to_str() {
            let raw = raw.trim();
            if let Some(token) = raw.strip_prefix("Bearer ") {
                return Some(token.to_string());
            }
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::PaygPricing;
    use crate::subscriptions::SubscriptionError;
    use axum::body::{to_bytes, Body};
    use axum::http::Request;
    use deadpool_redis::Config as RedisConfig;
    use sqlx::postgres::PgPoolOptions;
    use tower::ServiceExt;

    async fn response_json(resp: Response) -> (StatusCode, serde_json::Value) {
        let status = resp.status();
        let body = to_bytes(resp.into_body(), usize::MAX)
            .await
            .expect("response body");
        let json = serde_json::from_slice(&body).expect("json body");
        (status, json)
    }

    const LEGACY_PLAN_ROUTE_SURFACE: &[(&str, &str)] = &[
        ("GET", "/plans"),
        ("GET", "/plans/{planId}"),
        ("GET", "/plans/tenant/current"),
        ("GET", "/plans/features/{feature}"),
        ("GET", "/plans/tenant/features"),
        ("GET", "/plans/tenant/limits"),
        ("GET", "/plans/compare/{planId1}/{planId2}"),
        ("POST", "/plans"),
        ("PATCH", "/plans/{planId}"),
        ("POST", "/plans/seed"),
    ];

    const CURRENT_PLAN_ROUTE_SURFACE: &[(&str, &str)] = &[
        ("GET", "/plans"),
        ("GET", "/plans/{planId}"),
        ("GET", "/plans/tenant/current"),
        ("GET", "/plans/features/{feature}"),
        ("GET", "/plans/tenant/features"),
        ("GET", "/plans/tenant/limits"),
        ("GET", "/plans/compare/{planId1}/{planId2}"),
        ("POST", "/plans"),
        ("PATCH", "/plans/{planId}"),
        ("POST", "/plans/seed"),
    ];

    const LEGACY_PAYG_ROUTE_SURFACE: &[(&str, &str)] = &[
        ("GET", "/payg/pricing"),
        ("POST", "/payg/estimate"),
        ("POST", "/overage/estimate"),
        ("GET", "/payg/usage"),
    ];

    const CURRENT_PAYG_ROUTE_SURFACE: &[(&str, &str)] = &[
        ("GET", "/payg/pricing"),
        ("POST", "/payg/estimate"),
        ("POST", "/overage/estimate"),
        ("GET", "/payg/usage"),
    ];

    const LEGACY_TRANSITION_ROUTE_SURFACE: &[(&str, &str)] = &[
        ("POST", "/switch-plan"),
        ("POST", "/cancel"),
    ];

    const CURRENT_TRANSITION_ROUTE_SURFACE: &[(&str, &str)] = &[
        ("POST", "/switch-plan"),
        ("POST", "/cancel"),
    ];

    const LEGACY_ADMIN_REPORT_ROUTE_SURFACE: &[(&str, &str)] = &[
        ("GET", "/reports/revenue"),
        ("GET", "/reports/mrr"),
        ("GET", "/reports/churn"),
        ("GET", "/reports/dunning"),
        ("GET", "/reports/costs"),
        ("GET", "/export"),
    ];

    const CURRENT_ADMIN_REPORT_ROUTE_SURFACE: &[(&str, &str)] = &[
        ("GET", "/reports/revenue"),
        ("GET", "/reports/mrr"),
        ("GET", "/reports/churn"),
        ("GET", "/reports/dunning"),
        ("GET", "/reports/costs"),
        ("GET", "/export"),
    ];

    #[test]
    fn default_qty_is_one() {
        assert_eq!(default_qty(), 1);
    }

    #[test]
    fn default_limit_is_fifty() {
        assert_eq!(default_limit(), 50);
    }

    #[test]
    fn api_error_into_response_plans() {
        let err = ApiError::Plans(sqlx::Error::RowNotFound);
        let resp = err.into_response();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn api_error_uses_structured_error_envelope() {
        let err = ApiError::Plans(sqlx::Error::RowNotFound);
        let (status, json) = response_json(err.into_response()).await;

        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(json["error"]["code"], "NOT_FOUND");
        assert_eq!(json["error"]["message"], "plan not found");
    }

    #[tokio::test]
    async fn internal_api_errors_are_sanitized() {
        let err = ApiError::Plans(sqlx::Error::Protocol("boom".into()));
        let (status, json) = response_json(err.into_response()).await;

        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(json["error"]["code"], "INTERNAL_ERROR");
        assert_eq!(json["error"]["message"], "internal server error");
    }

    #[tokio::test]
    async fn validate_non_negative_returns_structured_validation_error() {
        let response = validate_non_negative(-1, "emailsSent").expect_err("negative values should fail");
        let (status, json) = response_json(response).await;

        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(json["error"]["code"], "VALIDATION_ERROR");
        assert_eq!(json["error"]["message"], "emailsSent must be non-negative");
    }

    #[test]
    fn api_error_into_response_subscription_plan_not_found() {
        let err = ApiError::Subscription(SubscriptionError::PlanNotFound("gold".into()));
        let resp = err.into_response();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn api_error_into_response_usage_redis() {
        let io_error = std::io::Error::other("redis unavailable");
        let redis_error = redis::RedisError::from(io_error);
        let err = ApiError::Usage(usage::UsageError::RedisCmd(redis_error));
        let resp = err.into_response();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[test]
    fn legacy_plan_route_surface_parity() {
        let missing: Vec<String> = LEGACY_PLAN_ROUTE_SURFACE
            .iter()
            .filter(|route| !CURRENT_PLAN_ROUTE_SURFACE.contains(route))
            .map(|(method, path)| format!("{method} {path}"))
            .collect();

        assert!(
            missing.is_empty(),
            "Rust billing-service is missing legacy plan routes: {}",
            missing.join(", ")
        );
    }

    async fn test_router() -> Router {
        let db = PgPoolOptions::new()
            .max_connections(1)
            .connect_lazy("postgres://apexmail:apexmail@127.0.0.1:5433/apexmail")
            .expect("failed to create lazy test database pool");
        let redis = RedisConfig::from_url("redis://127.0.0.1:6379")
            .create_pool(Some(deadpool_redis::Runtime::Tokio1))
            .expect("failed to create lazy test redis pool");

        let mut config = BillingConfig::default();
        config.service_auth_token = "test-service-token".into();

        router(AppState::new(db, redis, config))
    }

    #[tokio::test]
    async fn dynamic_plan_route_requires_service_auth() {
        let app = test_router().await;

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/plans/starter")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn stripe_webhook_route_bypasses_service_auth_and_requires_signature() {
        let app = test_router().await;

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/webhooks/stripe")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"id":"evt_missing_sig"}"#))
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn stripe_webhook_route_rejects_invalid_json_without_service_auth() {
        let app = test_router().await;

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/webhooks/stripe")
                    .header("content-type", "application/json")
                    .header("stripe-signature", "t=1,v1=deadbeef")
                    .body(Body::from("not valid json {{{"))
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn legacy_payg_route_surface_parity() {
        let missing: Vec<String> = LEGACY_PAYG_ROUTE_SURFACE
            .iter()
            .filter(|route| !CURRENT_PAYG_ROUTE_SURFACE.contains(route))
            .map(|(method, path)| format!("{method} {path}"))
            .collect();

        assert!(
            missing.is_empty(),
            "Rust billing-service is missing legacy PAYG routes: {}",
            missing.join(", ")
        );
    }

    #[test]
    fn legacy_payg_pricing_info_matches_ts_contract() {
        let payload = serde_json::to_value(legacy_payg_pricing_info(&PaygPricing::default()))
            .expect("PAYG pricing info should serialize");

        assert_eq!(payload["emailPricing"][0]["upTo"], serde_json::json!(10_000));
        assert_eq!(payload["emailPricing"][3]["upTo"], serde_json::Value::Null);
        assert_eq!(payload["apiPricing"]["freeCallsPerMonth"], serde_json::json!(100_000));
        assert_eq!(payload["apiPricing"]["pricePerThousandCallsCents"], serde_json::json!(10));
        assert_eq!(payload["minimumMonthlyCharge"], serde_json::json!(0));
    }

    #[test]
    fn legacy_payg_cost_matches_ts_contract() {
        let payload = serde_json::to_value(
            legacy_payg_cost(&PaygPricing::default(), 5, 101_000)
                .expect("PAYG cost contract input should calculate"),
        )
            .expect("PAYG cost payload should serialize");

        assert_eq!(payload["emailCostCents"], serde_json::json!(0));
        assert_eq!(payload["apiCostCents"], serde_json::json!(10));
        assert_eq!(payload["totalCostCents"], serde_json::json!(10));
        assert_eq!(payload["emailCostUsd"], serde_json::json!("$0.00"));
        assert_eq!(payload["apiCostUsd"], serde_json::json!("$0.10"));
        assert_eq!(payload["totalCostUsd"], serde_json::json!("$0.10"));
    }

    #[test]
    fn legacy_transition_route_surface_parity() {
        let missing: Vec<String> = LEGACY_TRANSITION_ROUTE_SURFACE
            .iter()
            .filter(|route| !CURRENT_TRANSITION_ROUTE_SURFACE.contains(route))
            .map(|(method, path)| format!("{method} {path}"))
            .collect();

        assert!(
            missing.is_empty(),
            "Rust billing-service is missing legacy transition routes: {}",
            missing.join(", ")
        );
    }

    #[test]
    fn legacy_proration_preview_matches_ts_contract() {
        let now = chrono::Utc::now();
        let current_plan = Plan {
            id: Uuid::new_v4(),
            name: "starter".into(),
            display_name: "Starter".into(),
            description: String::new(),
            price_monthly: 1000,
            price_yearly: 10_800,
            email_limit: 10_000,
            api_call_limit: 100_000,
            features: PlanFeatures::default(),
            stripe_price_id_monthly: None,
            stripe_price_id_yearly: None,
            is_active: true,
            sort_order: 0,
            created_at: now,
            updated_at: now,
        };
        let new_plan = Plan {
            id: Uuid::new_v4(),
            name: "growth".into(),
            display_name: "Growth".into(),
            description: String::new(),
            price_monthly: 2000,
            price_yearly: 21_600,
            email_limit: 50_000,
            api_call_limit: 250_000,
            features: PlanFeatures::default(),
            stripe_price_id_monthly: None,
            stripe_price_id_yearly: None,
            is_active: true,
            sort_order: 1,
            created_at: now,
            updated_at: now,
        };
        let subscription = RouteSubscription {
            plan_name: "starter".into(),
            billing_interval: BillingInterval::Monthly,
            current_period_start: now - chrono::TimeDelta::days(15),
            current_period_end: now + chrono::TimeDelta::days(15),
        };

        let payload = serde_json::to_value(
            preview_plan_proration(&BillingConfig::default(), &current_plan, &new_plan, &subscription)
                .expect("proration preview should succeed"),
        )
        .expect("proration preview should serialize");

        assert_eq!(payload["creditAmount"], serde_json::json!(500));
        assert_eq!(payload["chargeAmount"], serde_json::json!(1000));
        assert_eq!(payload["netAmount"], serde_json::json!(500));
        assert_eq!(payload["currentPlanDaysRemaining"], serde_json::json!(15));
        assert_eq!(payload["newPlanDaysInPeriod"], serde_json::json!(15));
        assert!(payload["explanation"]
            .as_str()
            .expect("explanation should be a string")
            .contains("Plan change from Starter to Growth"));
    }

    #[test]
    fn legacy_admin_report_route_surface_parity() {
        let missing: Vec<String> = LEGACY_ADMIN_REPORT_ROUTE_SURFACE
            .iter()
            .filter(|route| !CURRENT_ADMIN_REPORT_ROUTE_SURFACE.contains(route))
            .map(|(method, path)| format!("{method} {path}"))
            .collect();

        assert!(
            missing.is_empty(),
            "Rust billing-service is missing legacy admin report routes: {}",
            missing.join(", ")
        );
    }

    #[test]
    fn csv_sanitizer_prefixes_formula_like_values() {
        assert_eq!(sanitize_csv_value(&serde_json::json!("=SUM(A1:A2)")), "'=SUM(A1:A2)");
        assert_eq!(sanitize_csv_value(&serde_json::json!("plain")), "plain");
    }
}
