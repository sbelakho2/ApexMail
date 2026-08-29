//! Axum routes for the billing service.
//!
//! ```text
//! GET /plans – list active plans
//! GET /plans/:name – get plan by name
//! GET /usage – usage summary for current period
//! POST /usage/record – record a metering event
//! POST /usage/ingest – batch metering ingest (edge/worker, service auth)
//! GET /usage/reconciliation – reserved-vs-delivered reports
//! GET /proration/preview/:planName – proration preview (deployed config)
//! GET /invoices – list invoices (paginated)
//! GET /invoices/:id – get invoice by ID
//! GET /subscription – get active subscription
//! GET /quota – check quota status
//! GET /health – liveness probe
//! ```

use std::sync::Arc;
use std::time::Duration;

use apexmail_lib::{ErrorCode, ErrorEnvelope};
use axum::middleware::Next;
use axum::response::Response;
use axum::{
    extract::{DefaultBodyLimit, Extension, Path, Query, State},
    http::StatusCode,
    middleware,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use billing_common::proration;
use chrono::Datelike;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tower_http::timeout::TimeoutLayer;
use uuid::Uuid;

use crate::{
    config::{BillingConfig, PaygCalculationError, PaygPricing},
    invoices, plans, subscriptions,
    types::{BillingInterval, MeterEventType, Plan, PlanFeatures, SupportLevel},
    usage, usage_ingest, AppState,
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
        .route(
            "/proration/preview/:planName",
            get(preview_proration_for_tenant),
        )
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
        .route("/usage/ingest", post(ingest_usage))
        .route("/usage/reconciliation", get(get_reconciliation_reports))
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

fn error_response(status: StatusCode, code: ErrorCode, message: impl Into<String>) -> Response {
    (status, Json(ErrorEnvelope::new(code, message))).into_response()
}

/// GET /plans
async fn list_plans(State(state): State<Arc<AppState>>) -> Result<Response, ApiError> {
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
        Some(plan) => Ok((
            StatusCode::OK,
            Json(to_json_value(LegacyPlanDto::from(plan))?),
        )
            .into_response()),
        None => Ok(error_response(
            StatusCode::NOT_FOUND,
            ErrorCode::NotFound,
            "Plan not found",
        )),
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
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
    /// Monthly API call limit (not per-minute). The JSON field serializes as
    /// `apiCallsPerMonth` to accurately reflect that this is a monthly quota,
    /// not a per-minute rate limit.
    api_calls_per_month: i64,
    features: LegacyPlanFeaturesPayload,
}

impl From<&Plan> for LegacyPlanLimitsDto {
    fn from(plan: &Plan) -> Self {
        Self {
            email_limit: plan.email_limit,
            api_calls_per_month: plan.api_call_limit,
            features: plan.features.clone().into(),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct LegacyPlanCreateLimitsInput {
    emails_per_month: i64,
    /// Monthly API call limit (not per-minute). The JSON field serializes as
    /// `apiCallsPerMonth` to accurately reflect that this is a monthly quota,
    /// not a per-minute rate limit.
    api_calls_per_month: i64,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct LegacyPlanPatchLimitsInput {
    emails_per_month: Option<i64>,
    /// Monthly API call limit (not per-minute). The JSON field serializes as
    /// `apiCallsPerMonth` to accurately reflect that this is a monthly quota,
    /// not a per-minute rate limit.
    api_calls_per_month: Option<i64>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
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
#[serde(rename_all = "camelCase", deny_unknown_fields)]
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

fn legacy_feature_map(
    features: &LegacyPlanFeaturesPayload,
) -> serde_json::Map<String, serde_json::Value> {
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
            .map(|n| n != 0)
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

async fn get_current_plan(
    State(state): State<Arc<AppState>>,
    Query(q): Query<TenantIdQuery>,
    Extension(scope): Extension<TenantAuthScope>,
) -> Result<Response, ApiError> {
    if let Err(response) = check_tenant_access(&scope, &q.tenant_id) {
        return Ok(response);
    }
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
    Extension(scope): Extension<TenantAuthScope>,
) -> Result<Response, ApiError> {
    // Fix I8 — this is the only tenant-scoped plan route that previously
    // skipped check_tenant_access, letting a cross-tenant token probe any
    // tenant's feature flags.
    if let Err(response) = check_tenant_access(&scope, &q.tenant_id) {
        return Ok(response);
    }
    let plan = plans::get_plan_for_tenant(&state.db, &q.tenant_id).await?;
    let has_access = plan
        .as_ref()
        .map(|plan| feature_has_access(&plan.features.clone().into(), &feature).unwrap_or(false))
        .unwrap_or(false);

    Ok(Json(serde_json::json!({
        "feature": feature,
        "hasAccess": has_access,
    }))
    .into_response())
}

async fn get_plan_features(
    State(state): State<Arc<AppState>>,
    Query(q): Query<TenantIdQuery>,
) -> Result<Response, ApiError> {
    let plan = plans::get_plan_for_tenant(&state.db, &q.tenant_id).await?;
    match plan {
        Some(plan) => Ok(Json(to_json_value(LegacyPlanFeaturesPayload::from(
            plan.features,
        ))?)
        .into_response()),
        None => Ok(Json(serde_json::json!({})).into_response()),
    }
}

async fn get_plan_limits(
    State(state): State<Arc<AppState>>,
    Query(q): Query<TenantIdQuery>,
    Extension(scope): Extension<TenantAuthScope>,
) -> Result<Response, ApiError> {
    get_current_plan(State(state), Query(q), Extension(scope)).await
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
            }))
            .into_response())
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
    Extension(scope): Extension<TenantAuthScope>,
    Json(body): Json<LegacyPlanCreateBody>,
) -> Result<Response, ApiError> {
    if let Err(response) = require_any_scope(&scope) {
        return Ok(response);
    }
    let plan = plans::upsert_plan_input(
        &state.db,
        &plans::PlanUpsertInput {
            name: body.name,
            display_name: body.display_name,
            description: body.description,
            price_monthly: body.price_monthly,
            price_yearly: body.price_yearly,
            email_limit: body.limits.emails_per_month,
            api_call_limit: body.limits.api_calls_per_month,
            sort_order: 0,
            features: body.features.into(),
            stripe_price_id_monthly: body.stripe_price_id_monthly,
            stripe_price_id_yearly: body.stripe_price_id_yearly,
        },
    )
    .await?;

    Ok((
        StatusCode::CREATED,
        Json(to_json_value(LegacyPlanDto::from(plan))?),
    )
        .into_response())
}

async fn update_plan(
    State(state): State<Arc<AppState>>,
    Path(plan_id): Path<String>,
    Extension(scope): Extension<TenantAuthScope>,
    Json(body): Json<LegacyPlanPatchBody>,
) -> Result<Response, ApiError> {
    if let Err(response) = require_any_scope(&scope) {
        return Ok(response);
    }
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
                .and_then(|limits| limits.api_calls_per_month)
                .unwrap_or(existing.api_call_limit),
            sort_order: existing.sort_order,
            features: body.features.map(Into::into).unwrap_or(existing.features),
            stripe_price_id_monthly: body
                .stripe_price_id_monthly
                .or(existing.stripe_price_id_monthly),
            stripe_price_id_yearly: body
                .stripe_price_id_yearly
                .or(existing.stripe_price_id_yearly),
        },
    )
    .await?;

    Ok(Json(to_json_value(LegacyPlanDto::from(updated))?).into_response())
}

async fn seed_plans(
    State(state): State<Arc<AppState>>,
    Extension(scope): Extension<TenantAuthScope>,
) -> Result<Response, ApiError> {
    if let Err(response) = require_any_scope(&scope) {
        return Ok(response);
    }
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
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct LegacyPaygEstimateBody {
    emails_sent: i64,
    #[serde(default)]
    api_calls: i64,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct LegacyOverageEstimateBody {
    emails_sent: i64,
    email_limit: i64,
    /// Optional tenant for server-side limit recomputation. When present the
    /// client-supplied email_limit is ignored (Fix I13).
    #[serde(default)]
    tenant_id: Option<String>,
}

/// Money display formatting — the only float-tolerated line in the crate's
/// money surface (see the money_invariants gate, audit item 4).
///
/// Renders EUR, not USD: plans are seeded EUR-denominated, checkout creates
/// EUR Stripe prices, invoices carry EE 24% VAT, and the KMD return is
/// EUR-only — no USD amount is ever charged anywhere in the platform. The
/// `$` prefix quoted a currency the billing system never charges to a
/// European customer base. (Field names keep their `*_usd` suffix for API
/// compatibility; the VALUES are EUR.)
pub(crate) fn cents_to_usd_string(cents: i64) -> String {
    format!("€{:.2}", cents as f64 / 100.0)
}

fn legacy_payg_email_pricing(pricing: &PaygPricing) -> Vec<LegacyPaygEmailTierDto> {
    pricing
        .email_tiers
        .iter()
        .map(|tier| LegacyPaygEmailTierDto {
            up_to: if tier.up_to == u64::MAX {
                None
            } else {
                Some(tier.up_to)
            },
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
    let (email_cost_cents, api_cost_cents, total_cost_cents) =
        pricing.calculate(emails_sent, api_calls)?;

    Ok(LegacyPaygCostDto {
        email_cost_cents,
        api_cost_cents,
        total_cost_cents: total_cost_cents.max(LEGACY_PAYG_MINIMUM_MONTHLY_CHARGE_CENTS),
        email_cost_usd: cents_to_usd_string(email_cost_cents),
        api_cost_usd: cents_to_usd_string(api_cost_cents),
        total_cost_usd: cents_to_usd_string(
            total_cost_cents.max(LEGACY_PAYG_MINIMUM_MONTHLY_CHARGE_CENTS),
        ),
    })
}

#[allow(clippy::result_large_err)]
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
    }))
    .into_response())
}

/// Fix I13 companion (pure, unit-tested) — the effective email limit for an
/// overage estimate. A server-resolved plan limit (including `-1` =
/// unlimited) always overrides the client-supplied value; without a plan
/// row (legacy callers that send no tenant) the validated client value
/// stands. The client value must already be non-negative — enforced by
/// `validate_non_negative` before this runs.
fn resolve_overage_email_limit(client_limit: i64, server_limit: Option<i64>) -> i64 {
    server_limit.unwrap_or(client_limit)
}

async fn estimate_overage_cost(
    State(state): State<Arc<AppState>>,
    Extension(scope): Extension<TenantAuthScope>,
    Json(body): Json<LegacyOverageEstimateBody>,
) -> Result<Response, ApiError> {
    let emails_sent = match validate_non_negative(body.emails_sent, "emailsSent") {
        Ok(value) => value as i64,
        Err(response) => return Ok(response),
    };

    // Fix I13 — a negative client-supplied limit used to be passed straight
    // into calculate_overage_cost, where negative means "unlimited". Reject
    // it, and recompute the limit server-side when a tenant is named.
    let client_email_limit = match validate_non_negative(body.email_limit, "emailLimit") {
        Ok(value) => value as i64,
        Err(response) => return Ok(response),
    };

    let mut tenant_access_denied: Option<Response> = None;
    let server_limit = match body.tenant_id.as_deref() {
        Some(tenant_id) => {
            if let Err(response) = check_tenant_access(&scope, tenant_id) {
                tenant_access_denied = Some(response);
                None
            } else {
                plans::get_plan_for_tenant(&state.db, tenant_id)
                    .await?
                    .map(|plan| plan.email_limit)
            }
        }
        None => None,
    };

    if let Some(response) = tenant_access_denied {
        return Ok(response);
    }

    let email_limit = resolve_overage_email_limit(client_email_limit, server_limit);

    // Fix I10 — overage pricing comes from BillingConfig instead of the
    // hardcoded 4/100 in plans.rs (default stays 40 millicents/email).
    let overage_cost_cents = plans::calculate_overage_cost_with_rate(
        emails_sent,
        email_limit,
        state.config.overage_rate_per_email_millicents,
    );

    Ok(Json(serde_json::json!({
        "usage": {
            "emailsSent": emails_sent,
            "emailLimit": email_limit,
        },
        "overageCostCents": overage_cost_cents,
        "overageCostUsd": cents_to_usd_string(overage_cost_cents),
    }))
    .into_response())
}

async fn get_payg_usage(
    State(state): State<Arc<AppState>>,
    Query(q): Query<TenantIdQuery>,
    Extension(scope): Extension<TenantAuthScope>,
) -> Result<Response, ApiError> {
    if let Err(response) = check_tenant_access(&scope, &q.tenant_id) {
        return Ok(response);
    }
    let now = chrono::Utc::now();
    let month_start_date = now.date_naive().with_day(1).unwrap_or(now.date_naive());
    let period_start = month_start_date.and_time(chrono::NaiveTime::MIN).and_utc();
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
    }))
    .into_response())
}

#[derive(Debug, Clone)]
struct RouteSubscription {
    billing_interval: BillingInterval,
    current_period_start: chrono::DateTime<chrono::Utc>,
    current_period_end: chrono::DateTime<chrono::Utc>,
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
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct LegacySwitchPlanBody {
    plan_name: String,
    #[serde(default = "default_billing_interval")]
    billing_interval: BillingInterval,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct LegacyCancelBody {
    reason: Option<String>,
    feedback: Option<String>,
    #[serde(default)]
    cancel_immediately: bool,
}

fn default_billing_interval() -> BillingInterval {
    BillingInterval::Monthly
}

// Replaced by billing_common::proration::{prorated_amount, ceil_day_count}

/// Compute a proration preview against an explicit config. The api-server
/// legacy route used to run this with `BillingConfig::default()` (audit
/// item 3a); the billing-service route below forwards the *deployed*
/// config it already holds in `AppState`.
fn preview_plan_proration(
    config: &BillingConfig,
    current_plan: &Plan,
    new_plan: &Plan,
    subscription: &RouteSubscription,
) -> Result<LegacyProrationDto, String> {
    let now = chrono::Utc::now();
    let days_in_period = proration::ceil_day_count(
        subscription
            .current_period_end
            .signed_duration_since(subscription.current_period_start)
            .num_milliseconds(),
    );
    if days_in_period <= 0 {
        return Err("Invalid period: daysInPeriod must be greater than 0".to_string());
    }

    // Elapsed time floors (floor_day_count): a partial day elapsed has not
    // consumed a whole day. Ceil-ing both elapsed and the period length
    // made days_remaining = ceil(period) - ceil(elapsed) discard up to a
    // full day of unused time on mid-period plan changes.
    let days_elapsed = proration::floor_day_count(
        now.signed_duration_since(subscription.current_period_start)
            .num_milliseconds(),
    );
    let days_remaining = (days_in_period - days_elapsed).max(0);
    let current_period_price = if matches!(subscription.billing_interval, BillingInterval::Yearly) {
        current_plan.price_yearly
    } else {
        current_plan.price_monthly
    };
    let new_period_price = if matches!(subscription.billing_interval, BillingInterval::Yearly) {
        new_plan.price_yearly
    } else {
        new_plan.price_monthly
    };

    let credit_amount =
        proration::prorated_amount(current_period_price, days_remaining, days_in_period)?;
    let charge_amount =
        proration::prorated_amount(new_period_price, days_remaining, days_in_period)?;
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
            current_period_price,
            new_period_price,
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

// ---------------------------------------------------------------------------
// Proration preview (deployed-config aware — audit item 3a)
// ---------------------------------------------------------------------------

/// Subscription shape loaded from `stripe_subscriptions` (migration 071
/// columns) for the proration preview.
#[derive(sqlx::FromRow)]
struct ProrationSubscriptionRow {
    billing_interval: Option<String>,
    billing_cycle_start: Option<chrono::DateTime<chrono::Utc>>,
    billing_cycle_end: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProrationPreviewQuery {
    tenant_id: String,
    /// Overrides the subscription's stored interval (defaults to monthly
    /// when neither is available).
    #[serde(default)]
    billing_interval: Option<BillingInterval>,
}

/// GET/POST /proration/preview/:planName?tenant_id=...
///
/// Unlike the legacy api-server route that computed the preview with
/// `BillingConfig::default()`, this handler uses the deployed
/// configuration the billing service already holds (`state.config`), so
/// the proration charge/credit/warn thresholds match production limits.
async fn preview_proration_for_tenant(
    State(state): State<Arc<AppState>>,
    Extension(scope): Extension<TenantAuthScope>,
    Path(plan_name): Path<String>,
    Query(q): Query<ProrationPreviewQuery>,
) -> Result<Response, ApiError> {
    if let Err(response) = check_tenant_access(&scope, &q.tenant_id) {
        return Ok(response);
    }

    let subscription = sqlx::query_as::<_, ProrationSubscriptionRow>(
        r#"
        SELECT billing_interval, billing_cycle_start, billing_cycle_end
        FROM stripe_subscriptions
        WHERE tenant_id = $1
          AND status IN ('active', 'trialing', 'past_due')
        ORDER BY created_at DESC
        LIMIT 1
        "#,
    )
    .bind(&q.tenant_id)
    .fetch_optional(&state.db)
    .await?;

    let Some(subscription) = subscription else {
        return Ok(error_response(
            StatusCode::BAD_REQUEST,
            ErrorCode::ValidationError,
            "Cannot change plans: subscription status is unknown, must be 'active'",
        ));
    };

    let Some(period_start) = subscription.billing_cycle_start else {
        return Ok(error_response(
            StatusCode::CONFLICT,
            ErrorCode::ValidationError,
            "Subscription billing cycle is unknown; cannot preview proration",
        ));
    };
    let period_end = subscription
        .billing_cycle_end
        .unwrap_or_else(|| period_start + chrono::Months::new(1));

    let interval = q
        .billing_interval
        .unwrap_or(match subscription.billing_interval.as_deref() {
            Some("yearly") => BillingInterval::Yearly,
            _ => BillingInterval::Monthly,
        });

    let current_plan = match plans::get_plan_for_tenant(&state.db, &q.tenant_id).await? {
        Some(plan) => Some(plan),
        // No tenant-plan row (e.g. pre-migration tenant): fall back to the
        // free plan so the preview can still compute.
        None => plans::get_plan_by_name(&state.db, "free")
            .await
            .unwrap_or(None),
    };
    let Some(current_plan) = current_plan else {
        return Ok(error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            ErrorCode::InternalError,
            "Current plan could not be resolved",
        ));
    };

    let Some(new_plan) = plans::get_plan_by_name(&state.db, &plan_name).await? else {
        return Ok(error_response(
            StatusCode::NOT_FOUND,
            ErrorCode::NotFound,
            "New plan not found",
        ));
    };

    let route_subscription = RouteSubscription {
        billing_interval: interval,
        current_period_start: period_start,
        current_period_end: period_end,
    };

    match preview_plan_proration(&state.config, &current_plan, &new_plan, &route_subscription) {
        Ok(preview) => {
            let body = serde_json::to_value(preview).map_err(|error| {
                ApiError::Plans(sqlx::Error::Protocol(format!(
                    "proration preview serialization failed: {error}"
                )))
            })?;
            Ok(Json(body).into_response())
        }
        Err(error) => Ok(error_response(
            StatusCode::BAD_REQUEST,
            ErrorCode::ValidationError,
            error,
        )),
    }
}

/// Generate a 26-character identifier matching the VARCHAR(26) primary-key
/// convention used by tenants/audit/dunning tables (migration 064/087/093).
pub(crate) fn generate_audit_log_id() -> String {
    Uuid::new_v4()
        .simple()
        .to_string()
        .chars()
        .take(26)
        .collect()
}

/// HMAC-SHA256 signature over the audit hash, keyed with the same
/// `AUDIT_SIGNING_KEY` the compliance crate uses for chain verification.
///
/// Fail-closed: when the key is missing the signature is left empty and an
/// error is logged every time, so an unconfigured deployment is loudly
/// visible instead of silently signing with a deterministic public key.
fn audit_log_signature(hash: &str) -> String {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    type HmacSha256 = Hmac<Sha256>;
    let key = match std::env::var("AUDIT_SIGNING_KEY") {
        Ok(key) if !key.trim().is_empty() => key,
        _ => {
            tracing::error!(
                "AUDIT_SIGNING_KEY is not configured; audit-log signature left empty (hash chain unverifiable)"
            );
            return String::new();
        }
    };
    let mut mac = match HmacSha256::new_from_slice(key.as_bytes()) {
        Ok(mac) => mac,
        Err(_) => {
            tracing::error!(
                "AUDIT_SIGNING_KEY could not be parsed; audit-log signature left empty"
            );
            return String::new();
        }
    };
    mac.update(hash.as_bytes());
    hex::encode(mac.finalize().into_bytes())
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

    // Canonical audit_logs schema (compliance): resource + details columns,
    // outcome/hash/previous_hash/signature required. The signature uses the
    // same AUDIT_SIGNING_KEY the compliance crate verifies with, so these
    // rows stay part of the verifiable hash chain.
    let signature = audit_log_signature(&hash);

    sqlx::query(
        r#"
        INSERT INTO audit_logs (
            id, tenant_id, action, resource, resource_id,
            details, outcome, previous_hash, hash, signature, timestamp, created_at
        ) VALUES (
            $1, $2, $3, $4, $5,
            $6, 'success', $7, $8, $9, $10, $10
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
    .bind(signature)
    .bind(timestamp)
    .execute(&mut **tx)
    .await
    .map_err(ApiError::Plans)?;

    Ok(())
}

pub(crate) async fn append_audit_log(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    tenant_id: &str,
    action: &str,
    resource_type: &str,
    resource_id: Option<&str>,
    metadata: serde_json::Value,
    timestamp: chrono::DateTime<chrono::Utc>,
) -> Result<(), String> {
    insert_audit_log(
        tx,
        tenant_id,
        action,
        resource_type,
        resource_id,
        metadata,
        timestamp,
    )
    .await
    .map_err(|error| format!("{error:?}"))
}

/// Plan activation is driven exclusively by verified Stripe webhooks. This
/// legacy internal endpoint remains only to return a clear migration error;
/// mutating subscription and tenant rows here would bypass payment proof.
async fn switch_plan(
    State(_state): State<Arc<AppState>>,
    Query(q): Query<TenantIdQuery>,
    Extension(scope): Extension<TenantAuthScope>,
    Json(body): Json<LegacySwitchPlanBody>,
) -> Result<Response, ApiError> {
    if let Err(response) = check_tenant_access(&scope, &q.tenant_id) {
        return Ok(response);
    }
    let _ = (&body.plan_name, body.billing_interval);

    tracing::warn!(
        tenant_id = %q.tenant_id,
        "rejected direct internal billing plan transition; verified Stripe lifecycle is required"
    );

    Ok(error_response(
        StatusCode::CONFLICT,
        ErrorCode::Conflict,
        "Direct plan changes are disabled. Complete checkout and wait for the verified Stripe webhook before paid access is activated.",
    ))
}

async fn cancel_subscription_request(
    State(_state): State<Arc<AppState>>,
    Query(q): Query<TenantIdQuery>,
    Extension(scope): Extension<TenantAuthScope>,
    Json(body): Json<LegacyCancelBody>,
) -> Result<Response, ApiError> {
    if let Err(response) = check_tenant_access(&scope, &q.tenant_id) {
        return Ok(response);
    }
    let _ = (body.reason, body.feedback, body.cancel_immediately);

    tracing::warn!(
        tenant_id = %q.tenant_id,
        "rejected direct internal subscription cancellation; Stripe lifecycle is required"
    );

    Ok(error_response(
        StatusCode::CONFLICT,
        ErrorCode::Conflict,
        "Direct cancellation is disabled. Use the Stripe billing portal and wait for the verified Stripe webhook before subscription access changes.",
    ))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DateRangeQuery {
    start_date: Option<String>,
    end_date: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct BillingExportQuery {
    #[serde(rename = "type")]
    export_type: Option<String>,
    start_date: Option<String>,
    end_date: Option<String>,
    #[serde(default = "default_export_format")]
    format: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
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
        .unwrap_or_else(|_| {
            error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                ErrorCode::InternalError,
                "Operation failed",
            )
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

async fn get_revenue_report(
    State(state): State<Arc<AppState>>,
    Extension(scope): Extension<TenantAuthScope>,
    Query(query): Query<DateRangeQuery>,
) -> Result<Response, ApiError> {
    if let Err(response) = require_any_scope(&scope) {
        return Ok(response);
    }
    let (Some(start_date), Some(end_date)) =
        (query.start_date.as_deref(), query.end_date.as_deref())
    else {
        return Ok(error_response(
            StatusCode::BAD_REQUEST,
            ErrorCode::ValidationError,
            "startDate and endDate required",
        ));
    };

    let (Some(start_date), Some(end_date)) =
        (parse_query_date(start_date), parse_query_date(end_date))
    else {
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
                SUM(COALESCE(total, amount)) as total_revenue,
                COUNT(*) as invoice_count,
                SUM(COALESCE(vat_total, 0)) as total_tax,
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

/// Fix I9 — normalize a yearly plan price to monthly MRR with round-half-up
/// integer math (equivalent to SQL `ROUND(price_yearly / 12.0)`), so a
/// yearly €25 000 plan counts as 2 083 cents/month instead of being
/// truncated to 2 082.
#[cfg_attr(not(test), allow(dead_code))]
fn yearly_price_to_monthly_mrr(price_yearly: i64) -> i64 {
    (price_yearly + 6) / 12
}

async fn get_mrr_report(
    State(state): State<Arc<AppState>>,
    Extension(scope): Extension<TenantAuthScope>,
) -> Result<Response, ApiError> {
    if let Err(response) = require_any_scope(&scope) {
        return Ok(response);
    }
    // Fix C — MRR is computed from stripe_subscriptions (the table the
    // webhook writers populate) joined via tenants.plan to plans pricing.
    // Fix I9 — yearly prices are normalized with proper rounding and rows
    // are bucketed by the subscription's active month (billing cycle start,
    // falling back to creation), not by raw creation date.
    let report: serde_json::Value = sqlx::query_scalar(
        r#"
        SELECT COALESCE(json_agg(row_to_json(report_row) ORDER BY report_row.month DESC), '[]'::json)
        FROM (
            SELECT
                DATE_TRUNC('month', COALESCE(s.billing_cycle_start, s.created_at)) as month,
                COUNT(DISTINCT s.tenant_id) as active_subscriptions,
                SUM(
                    CASE
                        WHEN s.billing_interval = 'yearly' THEN ROUND(p.price_yearly / 12.0)::bigint
                        ELSE p.price_monthly
                    END
                ) as mrr
            FROM stripe_subscriptions s
            JOIN tenants t ON t.id = s.tenant_id
            JOIN plans p ON p.name = t.plan
            WHERE s.status = 'active'
            GROUP BY DATE_TRUNC('month', COALESCE(s.billing_cycle_start, s.created_at))
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

/// Monthly churn report. `churned_mrr` prices each canceled subscription
/// from its own price snapshot — the subscription's `stripe_price_id`
/// resolved against `plans.stripe_price_id_monthly/yearly` (falling back to
/// the tenant's current plan only while it is still non-free) — because
/// `tenants.plan` is set to `'free'` on cancellation (audit F10): pricing
/// churn from `t.plan` made `churned_mrr` always ≈ 0. Subscriptions with no
/// resolvable price (snapshot missing AND tenant already downgraded to
/// free) are EXCLUDED from `churned_mrr` and reported separately as
/// `churned_mrr_unpriced` so the metric's coverage is explicit.
async fn get_churn_report(
    State(state): State<Arc<AppState>>,
    Extension(scope): Extension<TenantAuthScope>,
) -> Result<Response, ApiError> {
    if let Err(response) = require_any_scope(&scope) {
        return Ok(response);
    }
    // Fix C — churn computed from stripe_subscriptions (join tenants/plans).
    let report: serde_json::Value = sqlx::query_scalar(
        r#"
        SELECT COALESCE(json_agg(row_to_json(report_row) ORDER BY report_row.month DESC), '[]'::json)
        FROM (
            WITH churned AS (
                SELECT
                    DATE_TRUNC('month', COALESCE(s.canceled_at, s.updated_at)) as month,
                    COUNT(*) as churned_count,
                    SUM(
                        CASE
                            WHEN sp.id IS NOT NULL AND s.billing_interval = 'yearly'
                                THEN ROUND(sp.price_yearly / 12.0)::bigint
                            WHEN sp.id IS NOT NULL
                                THEN sp.price_monthly
                            WHEN tp.id IS NOT NULL AND s.billing_interval = 'yearly'
                                THEN ROUND(tp.price_yearly / 12.0)::bigint
                            WHEN tp.id IS NOT NULL
                                THEN tp.price_monthly
                            ELSE NULL
                        END
                    ) as churned_mrr,
                    COUNT(*) FILTER (WHERE sp.id IS NULL AND tp.id IS NULL) as churned_mrr_unpriced
                FROM stripe_subscriptions s
                JOIN tenants t ON t.id = s.tenant_id
                -- Fix F10 — price the CHURNED SUBSCRIPTION, not the tenant's
                -- current plan: subscription cancellation downgrades
                -- tenants.plan to 'free', so the previous
                -- `plans p ON p.name = t.plan` priced all churn at the free
                -- plan (churned_mrr was structurally ~0). Preferred source:
                -- the subscription's own Stripe price snapshot
                -- (stripe_price_id, written when the subscription was
                -- stored and never downgraded). Fallback: the tenant's plan
                -- only while it is still non-free; otherwise the row is
                -- excluded from churned_mrr and counted as unpriced.
                LEFT JOIN plans sp ON s.stripe_price_id IS NOT NULL AND (
                    (s.billing_interval = 'yearly'
                        AND sp.stripe_price_id_yearly = s.stripe_price_id)
                    OR (COALESCE(s.billing_interval, 'monthly') <> 'yearly'
                        AND sp.stripe_price_id_monthly = s.stripe_price_id)
                )
                LEFT JOIN plans tp ON tp.name = t.plan AND t.plan <> 'free'
                WHERE s.status = 'canceled'
                GROUP BY DATE_TRUNC('month', COALESCE(s.canceled_at, s.updated_at))
            ),
            starting AS (
                SELECT
                    c.month,
                    COUNT(DISTINCT s.tenant_id) as starting_count
                FROM churned c
                LEFT JOIN stripe_subscriptions s
                  ON s.created_at < c.month
                GROUP BY c.month
            )
            SELECT
                c.month,
                c.churned_count,
                c.churned_mrr,
                c.churned_mrr_unpriced,
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
    Extension(scope): Extension<TenantAuthScope>,
) -> Result<Response, ApiError> {
    if let Err(response) = require_any_scope(&scope) {
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
    .await
    .map_err(ApiError::Plans)?;

    Ok(Json(serde_json::json!({ "report": report })).into_response())
}

async fn get_cost_report(
    State(state): State<Arc<AppState>>,
    Extension(scope): Extension<TenantAuthScope>,
    Query(query): Query<DateRangeQuery>,
) -> Result<Response, ApiError> {
    if let Err(response) = require_any_scope(&scope) {
        return Ok(response);
    }
    let (Some(start_date), Some(end_date)) =
        (query.start_date.as_deref(), query.end_date.as_deref())
    else {
        return Ok(error_response(
            StatusCode::BAD_REQUEST,
            ErrorCode::ValidationError,
            "startDate and endDate required",
        ));
    };

    let (Some(start_date), Some(end_date)) =
        (parse_query_date(start_date), parse_query_date(end_date))
    else {
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
    Extension(scope): Extension<TenantAuthScope>,
    Query(query): Query<BillingExportQuery>,
) -> Result<Response, ApiError> {
    if let Err(response) = require_any_scope(&scope) {
        return Ok(response);
    }
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

    let (Some(start_date_parsed), Some(end_date_parsed)) =
        (parse_query_date(start_date), parse_query_date(end_date))
    else {
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
                    COALESCE(i.subtotal, i.amount) as subtotal,
                    COALESCE(i.vat_total, 0) as tax_amount,
                    COALESCE(i.total, i.amount) as total,
                    i.currency,
                    i.status,
                    COALESCE(i.issued_at, i.created_at) as issued_at,
                    i.paid_at,
                    i.due_at
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
                    -- Plans are EUR-denominated (checkout creates EUR Stripe
                    -- prices; the KMD return is EUR-only): an accountant
                    -- importing this export must book euros, not dollars.
                    'eur'::text as currency,
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
#[serde(deny_unknown_fields)]
struct TenantQuery {
    tenant_id: String,
}

/// GET /usage?tenant_id=...&tz=Europe/Tallinn
///
/// Fix I15 — the period boundaries default to the historical UTC month, but
/// an explicit IANA `tz` shifts them to local midnight so usage reporting
/// can align with the Tallinn-based VAT periods. (KMD itself always uses
/// Europe/Tallinn; this documented difference remains intentional.)
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UsageQuery {
    tenant_id: String,
    /// Optional IANA timezone name (e.g. "Europe/Tallinn").
    #[serde(default)]
    tz: Option<String>,
}

/// GET /usage?tenant_id=...
async fn get_usage(
    State(state): State<Arc<AppState>>,
    Query(q): Query<UsageQuery>,
    Extension(scope): Extension<TenantAuthScope>,
) -> Result<Response, ApiError> {
    if let Err(response) = check_tenant_access(&scope, &q.tenant_id) {
        return Ok(response);
    }

    let (period_start, period_end) =
        match usage::month_period_for_tz(chrono::Utc::now(), q.tz.as_deref()) {
            Ok(bounds) => bounds,
            Err(error) => {
                return Ok(error_response(
                    StatusCode::BAD_REQUEST,
                    ErrorCode::InvalidInput,
                    error,
                ));
            }
        };

    let summary = usage::get_usage(&state.db, &q.tenant_id, period_start, period_end).await?;
    Ok(Json(summary).into_response())
}

/// POST /usage/record
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
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
    Extension(scope): Extension<TenantAuthScope>,
    Json(body): Json<RecordUsageBody>,
) -> Result<Response, ApiError> {
    if let Err(response) = check_tenant_access(&scope, &body.tenant_id) {
        return Ok(response);
    }
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
    )
        .into_response())
}

/// POST /usage/record-checked
/// Atomically check quota and record a metering event in a single operation.
/// Avoids the TOCTOU window of separate `GET /quota` + `POST /usage/record`.
async fn record_usage_checked(
    State(state): State<Arc<AppState>>,
    Extension(scope): Extension<TenantAuthScope>,
    Json(body): Json<RecordUsageBody>,
) -> Result<Response, ApiError> {
    if let Err(response) = check_tenant_access(&scope, &body.tenant_id) {
        return Ok(response);
    }
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
    Ok((
        status,
        Json(serde_json::to_value(&result).unwrap_or_default()),
    )
        .into_response())
}

/// POST /usage/ingest — batch metering ingest for the edge/worker.
///
/// Service-authenticated (like every route on this router). Intended for
/// event types with no derivable platform source table — notably
/// `api_calls`: the api-server request middleware should POST one event
/// (or a micro-batch) per request with a deterministic `eventId` for
/// idempotency.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct IngestUsageBody {
    events: Vec<usage_ingest::IngestEvent>,
}

async fn ingest_usage(
    State(state): State<Arc<AppState>>,
    Extension(scope): Extension<TenantAuthScope>,
    Json(body): Json<IngestUsageBody>,
) -> Result<Response, ApiError> {
    if body.events.len() > usage_ingest::INGEST_BATCH_LIMIT {
        return Ok(error_response(
            StatusCode::PAYLOAD_TOO_LARGE,
            ErrorCode::ValidationError,
            format!(
                "batch exceeds {} events; split into smaller batches",
                usage_ingest::INGEST_BATCH_LIMIT
            ),
        ));
    }

    // Tenant scoping: a non-service caller may only ingest for tenants it
    // can access; service tokens (scope = service) pass through.
    for event in &body.events {
        if let Err(response) = check_tenant_access(&scope, &event.tenant_id) {
            return Ok(response);
        }
    }

    let result = usage_ingest::ingest_usage_batch(&state.db, &state.redis, &body.events).await;
    let status = if result.rejected == 0 {
        StatusCode::OK
    } else if result.accepted == 0 && result.duplicates == 0 {
        StatusCode::UNPROCESSABLE_ENTITY
    } else {
        StatusCode::MULTI_STATUS
    };
    let body = serde_json::to_value(&result).map_err(|error| {
        ApiError::Plans(sqlx::Error::Protocol(format!(
            "ingest result serialization failed: {error}"
        )))
    })?;
    Ok((status, Json(body)).into_response())
}

/// GET /usage/reconciliation?tenant_id=...&limit=...
/// Lists the daily reserved-vs-delivered reconciliation reports
/// (migration 104) for manual review of overage candidates.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReconciliationQuery {
    tenant_id: String,
    #[serde(default = "default_limit")]
    limit: i64,
    #[serde(default)]
    only_candidates: bool,
}

async fn get_reconciliation_reports(
    State(state): State<Arc<AppState>>,
    Query(q): Query<ReconciliationQuery>,
    Extension(scope): Extension<TenantAuthScope>,
) -> Result<Response, ApiError> {
    if let Err(response) = check_tenant_access(&scope, &q.tenant_id) {
        return Ok(response);
    }

    #[derive(sqlx::FromRow, serde::Serialize)]
    #[serde(rename_all = "camelCase")]
    struct ReconciliationReportRow {
        id: Uuid,
        tenant_id: String,
        period_start: chrono::NaiveDate,
        period_end: chrono::NaiveDate,
        reserved_emails: i64,
        delivered_emails: i64,
        bounced_emails: i64,
        complained_emails: i64,
        unaccounted_emails: i64,
        overage_candidate: bool,
        status: String,
        details: serde_json::Value,
        created_at: chrono::DateTime<chrono::Utc>,
    }

    let reports: Vec<ReconciliationReportRow> = sqlx::query_as(
        r#"
        SELECT id, tenant_id, period_start, period_end,
               reserved_emails, delivered_emails, bounced_emails, complained_emails,
               unaccounted_emails, overage_candidate, status, details, created_at
        FROM billing_reconciliation_reports
        WHERE tenant_id = $1
          AND ($3 = false OR overage_candidate = true)
        ORDER BY period_start DESC
        LIMIT $2
        "#,
    )
    .bind(&q.tenant_id)
    .bind(clamp_limit(q.limit, 200))
    .bind(q.only_candidates)
    .fetch_all(&state.db)
    .await?;

    Ok(Json(serde_json::json!({ "reports": reports })).into_response())
}

/// Query params for invoice listing.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
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
    Extension(scope): Extension<TenantAuthScope>,
) -> Result<Response, ApiError> {
    if let Err(response) = check_tenant_access(&scope, &q.tenant_id) {
        return Ok(response);
    }
    let invoices = invoices::list_invoices(
        &state.db,
        &q.tenant_id,
        clamp_limit(q.limit, 500),
        clamp_offset(q.offset, 100_000),
    )
    .await?;
    Ok(Json(serde_json::json!({ "invoices": invoices })).into_response())
}

/// GET /invoices/:id?tenant_id=...
async fn get_invoice(
    State(state): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
    Query(q): Query<TenantQuery>,
    Extension(scope): Extension<TenantAuthScope>,
) -> Result<impl IntoResponse, ApiError> {
    if let Err(response) = check_tenant_access(&scope, &q.tenant_id) {
        return Ok(response);
    }
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
    Extension(scope): Extension<TenantAuthScope>,
) -> Result<impl IntoResponse, ApiError> {
    if let Err(response) = check_tenant_access(&scope, &q.tenant_id) {
        return Ok(response);
    }
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
    Extension(scope): Extension<TenantAuthScope>,
) -> Result<Response, ApiError> {
    if let Err(response) = check_tenant_access(&scope, &q.tenant_id) {
        return Ok(response);
    }
    let status = usage::check_quota(&state.db, &state.redis, &q.tenant_id).await?;
    Ok(Json(status).into_response())
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
            ApiError::Plans(sqlx::Error::RowNotFound) => (
                StatusCode::NOT_FOUND,
                ErrorCode::NotFound,
                "plan not found".to_string(),
            ),
            ApiError::Plans(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                ErrorCode::InternalError,
                "internal server error".to_string(),
            ),
            ApiError::Usage(usage::UsageError::Db(sqlx::Error::RowNotFound)) => (
                StatusCode::NOT_FOUND,
                ErrorCode::NotFound,
                "billing resource not found".to_string(),
            ),
            ApiError::Usage(usage::UsageError::Redis(_))
            | ApiError::Usage(usage::UsageError::RedisCmd(_)) => (
                StatusCode::SERVICE_UNAVAILABLE,
                ErrorCode::ServiceUnavailable,
                "billing cache unavailable".to_string(),
            ),
            ApiError::Usage(usage::UsageError::InvalidQuantity(quantity)) => (
                StatusCode::BAD_REQUEST,
                ErrorCode::ValidationError,
                format!("quantity must be a positive integer, got {quantity}"),
            ),
            ApiError::Usage(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                ErrorCode::InternalError,
                "internal server error".to_string(),
            ),
            ApiError::Invoice(invoices::InvoiceError::Db(sqlx::Error::RowNotFound)) => (
                StatusCode::NOT_FOUND,
                ErrorCode::NotFound,
                "invoice not found".to_string(),
            ),
            ApiError::Invoice(invoices::InvoiceError::NoBillingAddress) => (
                StatusCode::NOT_FOUND,
                ErrorCode::NotFound,
                "billing address not found for tenant".to_string(),
            ),
            ApiError::Invoice(invoices::InvoiceError::PdfGeneration(_)) => (
                StatusCode::SERVICE_UNAVAILABLE,
                ErrorCode::ServiceUnavailable,
                "pdf generation unavailable".to_string(),
            ),
            ApiError::Invoice(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                ErrorCode::InternalError,
                "internal server error".to_string(),
            ),
            ApiError::Subscription(subscriptions::SubscriptionError::PlanNotFound(name)) => (
                StatusCode::NOT_FOUND,
                ErrorCode::NotFound,
                format!("plan not found: {name}"),
            ),
            ApiError::Subscription(subscriptions::SubscriptionError::NotFound) => (
                StatusCode::NOT_FOUND,
                ErrorCode::NotFound,
                "active subscription not found".to_string(),
            ),
            ApiError::Subscription(subscriptions::SubscriptionError::UsageExceedsPlan {
                plan_name,
                reasons,
            }) => {
                let reason_summary = reasons.join("; ");
                (
                    StatusCode::CONFLICT,
                    ErrorCode::Conflict,
                    format!("cannot change to {plan_name}: {reason_summary}"),
                )
            }
            ApiError::Subscription(subscriptions::SubscriptionError::Db(
                sqlx::Error::RowNotFound,
            )) => (
                StatusCode::NOT_FOUND,
                ErrorCode::NotFound,
                "active subscription not found".to_string(),
            ),
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
    serde_json::to_value(value).map_err(|e| ApiError::Plans(sqlx::Error::Decode(Box::new(e))))
}

/// Scope of authority granted by a service auth token.
#[derive(Clone, Debug)]
enum TenantAuthScope {
    /// Full access to any tenant's data (backward-compatible with original single-token mode).
    Any,
    /// Access restricted to a single named tenant.
    Scoped(String),
}

/// Parse a token value against the configured service auth token.
///
/// Supports two formats:
/// - `"<service_token>"` — full access (`TenantAuthScope::Any`)
/// - `"<tenant_id>:<service_token>"` — tenant-scoped access (`TenantAuthScope::Scoped(...)`)
fn parse_token_scope(token: &str, service_token: &str) -> Option<TenantAuthScope> {
    if service_token.is_empty() {
        return None;
    }
    if token == service_token {
        return Some(TenantAuthScope::Any);
    }
    // Check for tenant-scoped token format: "tenant_id:token"
    if let Some(tenant_id) = token.strip_suffix(&format!(":{}", service_token)) {
        if !tenant_id.is_empty() && !tenant_id.contains(':') {
            return Some(TenantAuthScope::Scoped(tenant_id.to_string()));
        }
    }
    None
}

/// Check that the auth scope allows access to the given tenant_id.
/// Returns `Ok(())` if the scope is `Any` or matches the requested tenant.
/// On failure, returns an HTTP 403 Forbidden response.
#[allow(clippy::result_large_err)]
fn check_tenant_access(scope: &TenantAuthScope, tenant_id: &str) -> Result<(), Response> {
    match scope {
        TenantAuthScope::Any => Ok(()),
        TenantAuthScope::Scoped(scoped) if scoped == tenant_id => Ok(()),
        _ => Err(forbidden_response("not authorized for this tenant")),
    }
}

/// Require a full-access (`Any`) service token. Plan administration, billing
/// reports and exports operate across all tenants, so a tenant-scoped token
/// must not reach them even when it names its own tenant.
#[allow(clippy::result_large_err)]
fn require_any_scope(scope: &TenantAuthScope) -> Result<(), Response> {
    match scope {
        TenantAuthScope::Any => Ok(()),
        TenantAuthScope::Scoped(_) => Err(forbidden_response(
            "tenant-scoped tokens cannot access platform-wide billing endpoints",
        )),
    }
}

fn forbidden_response(message: &str) -> Response {
    (
        StatusCode::FORBIDDEN,
        Json(serde_json::json!({
            "error": {
                "code": "FORBIDDEN",
                "message": message
            }
        })),
    )
        .into_response()
}

async fn require_service_auth(
    State(state): State<Arc<AppState>>,
    mut req: axum::http::Request<axum::body::Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    if matches!(req.uri().path(), "/health" | "/webhooks/stripe") {
        return Ok(next.run(req).await);
    }

    let token = extract_token(req.headers());
    let scope = match token {
        Some(token) => parse_token_scope(&token, &state.config.service_auth_token),
        None => None,
    };

    match scope {
        Some(scope) => {
            req.extensions_mut().insert(scope);
            Ok(next.run(req).await)
        }
        None => Err(StatusCode::UNAUTHORIZED),
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

    const LEGACY_TRANSITION_ROUTE_SURFACE: &[(&str, &str)] =
        &[("POST", "/switch-plan"), ("POST", "/cancel")];

    const CURRENT_TRANSITION_ROUTE_SURFACE: &[(&str, &str)] =
        &[("POST", "/switch-plan"), ("POST", "/cancel")];

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
        let response =
            validate_non_negative(-1, "emailsSent").expect_err("negative values should fail");
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

    async fn test_router_with_config(mut config: BillingConfig) -> Router {
        let db = PgPoolOptions::new()
            .max_connections(1)
            .connect_lazy("postgres://localhost/unused")
            .expect("failed to create lazy test database pool");
        let redis = RedisConfig::from_url("redis://127.0.0.1:6379")
            .create_pool(Some(deadpool_redis::Runtime::Tokio1))
            .expect("failed to create lazy test redis pool");

        config.service_auth_token = "test-service-token".into();

        router(AppState::new(db, redis, config))
    }

    async fn test_router() -> Router {
        test_router_with_config(BillingConfig::default()).await
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

    #[tokio::test]
    async fn stripe_webhook_route_rejects_invalid_signature_before_processing() {
        let config = BillingConfig {
            stripe_webhook_secret: "whsec_test_secret".into(),
            ..Default::default()
        };

        let app = test_router_with_config(config).await;
        let signature = format!("t={},v1=deadbeef", chrono::Utc::now().timestamp());

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/webhooks/stripe")
                    .header("content-type", "application/json")
                    .header("stripe-signature", signature)
                    .body(Body::from(r#"{"id":"evt_bad_sig","type":"checkout.session.completed","data":{"object":{}}}"#))
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

        assert_eq!(
            payload["emailPricing"][0]["upTo"],
            serde_json::json!(10_000)
        );
        assert_eq!(payload["emailPricing"][3]["upTo"], serde_json::Value::Null);
        assert_eq!(
            payload["apiPricing"]["freeCallsPerMonth"],
            serde_json::json!(100_000)
        );
        assert_eq!(
            payload["apiPricing"]["pricePerThousandCallsCents"],
            serde_json::json!(10)
        );
        assert_eq!(payload["minimumMonthlyCharge"], serde_json::json!(0));
    }

    #[test]
    fn legacy_payg_cost_matches_ts_contract() {
        // Audit item 3b: millicents now round HALF-UP to cents (the legacy
        // TS/Node implementation truncated). 5 emails = 500 millicents =
        // exactly half a cent → 1 cent.
        let payload = serde_json::to_value(
            legacy_payg_cost(&PaygPricing::default(), 5, 101_000)
                .expect("PAYG cost contract input should calculate"),
        )
        .expect("PAYG cost payload should serialize");

        assert_eq!(payload["emailCostCents"], serde_json::json!(1));
        assert_eq!(payload["apiCostCents"], serde_json::json!(10));
        assert_eq!(payload["totalCostCents"], serde_json::json!(11));
        assert_eq!(payload["emailCostUsd"], serde_json::json!("€0.01"));
        assert_eq!(payload["apiCostUsd"], serde_json::json!("€0.10"));
        assert_eq!(payload["totalCostUsd"], serde_json::json!("€0.11"));
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
            billing_interval: BillingInterval::Monthly,
            current_period_start: now - chrono::TimeDelta::days(15),
            current_period_end: now + chrono::TimeDelta::days(15),
        };

        let payload = serde_json::to_value(
            preview_plan_proration(
                &BillingConfig::default(),
                &current_plan,
                &new_plan,
                &subscription,
            )
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
    fn yearly_proration_uses_full_year_price_for_remaining_period() {
        let now = chrono::Utc::now();
        let current_plan = Plan {
            id: Uuid::new_v4(),
            name: "starter".into(),
            display_name: "Starter".into(),
            description: String::new(),
            price_monthly: 1000,
            price_yearly: 12_000,
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
            price_yearly: 24_000,
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
        // Use a 365-day period (actual calendar days per proration.rs docs),
        // not a fixed 360-day convention. 182 days elapsed + 183 remaining = 365 total.
        let subscription = RouteSubscription {
            billing_interval: BillingInterval::Yearly,
            current_period_start: now - chrono::TimeDelta::days(182),
            current_period_end: now + chrono::TimeDelta::days(183),
        };

        let payload = serde_json::to_value(
            preview_plan_proration(
                &BillingConfig::default(),
                &current_plan,
                &new_plan,
                &subscription,
            )
            .expect("yearly proration preview should succeed"),
        )
        .expect("yearly proration preview should serialize");

        // With 365-day period and 183 remaining days:
        // credit = (12000 × 183 + 182) / 365 = 6016
        // charge = (24000 × 183 + 182) / 365 = 12033
        // net   = 12033 - 6016 = 6017
        assert_eq!(payload["creditAmount"], serde_json::json!(6016));
        assert_eq!(payload["chargeAmount"], serde_json::json!(12033));
        assert_eq!(payload["netAmount"], serde_json::json!(6017));
        assert!(payload["explanation"]
            .as_str()
            .expect("explanation should be a string")
            .contains("$120.00 / 365 days × 183 days"));
        assert!(payload["explanation"]
            .as_str()
            .expect("explanation should be a string")
            .contains("$240.00 / 365 days × 183 days"));
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
        assert_eq!(
            sanitize_csv_value(&serde_json::json!("=SUM(A1:A2)")),
            "'=SUM(A1:A2)"
        );
        assert_eq!(sanitize_csv_value(&serde_json::json!("plain")), "plain");
    }

    // ------------------------------------------------------------------
    // Fix I9 — yearly → monthly MRR rounding.
    // ------------------------------------------------------------------

    #[test]
    fn yearly_mrr_uses_half_up_rounding() {
        // 25 000 / 12 = 2083.33 → 2 083 (not truncated 2 082).
        assert_eq!(yearly_price_to_monthly_mrr(25_000), 2_083);
        // 24 000 / 12 = exactly 2 000.
        assert_eq!(yearly_price_to_monthly_mrr(24_000), 2_000);
        // 100 / 12 = 8.33 → 8.
        assert_eq!(yearly_price_to_monthly_mrr(100), 8);
        // 6 / 12 = 0.5 → rounds up to 1.
        assert_eq!(yearly_price_to_monthly_mrr(6), 1);
        // Zero stays zero.
        assert_eq!(yearly_price_to_monthly_mrr(0), 0);
    }

    // ------------------------------------------------------------------
    // Fix I8 — /plans/features/:feature must enforce tenant scoping.
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn plan_feature_route_denies_cross_tenant_scoped_token() {
        let app = test_router().await;

        // Token scoped to tenant_a requesting tenant_b's features.
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/plans/features/advancedAnalytics?tenant_id=tenant_b")
                    .header("x-api-key", "tenant_a:test-service-token")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");

        let (status, json) = response_json(response).await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "scoped token must not read another tenant's feature flags (body: {json})"
        );
    }

    // ------------------------------------------------------------------
    // Fix I13 — overage estimate must reject negative limits.
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn overage_estimate_rejects_negative_email_limit() {
        let response =
            validate_non_negative(-1, "emailLimit").expect_err("negative limit must fail");
        let (status, json) = response_json(response).await;

        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(json["error"]["code"], "VALIDATION_ERROR");
        assert_eq!(json["error"]["message"], "emailLimit must be non-negative");
    }

    #[tokio::test]
    async fn overage_estimate_rejects_negative_emails_sent() {
        let response =
            validate_non_negative(-5, "emailsSent").expect_err("negative sent must fail");
        let (status, json) = response_json(response).await;

        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(json["error"]["message"], "emailsSent must be non-negative");
    }

    // ------------------------------------------------------------------
    // Audit item 3c — server-side limit recomputation.
    // ------------------------------------------------------------------

    #[test]
    fn overage_limit_server_side_recompute_overrides_client() {
        // Client claims a 30 000 limit; the tenant's resolved plan says
        // 250 000 — the server value must win so overage is not overstated.
        let limit = resolve_overage_email_limit(30_000, Some(250_000));
        assert_eq!(limit, 250_000);

        let cost = plans::calculate_overage_cost_with_rate(40_000, limit, 40);
        assert_eq!(cost, 0, "40k sent under a 250k plan limit has no overage");

        // …while trusting the client-supplied limit would have charged for
        // 10k phantom overage emails:
        let client_cost = plans::calculate_overage_cost_with_rate(40_000, 30_000, 40);
        assert_eq!(client_cost, 400);
    }

    #[test]
    fn overage_limit_falls_back_to_client_without_plan_row() {
        // Legacy caller with no tenant_id (and no plan row): the validated
        // client value stands.
        assert_eq!(resolve_overage_email_limit(30_000, None), 30_000);
    }

    #[test]
    fn overage_limit_server_side_unlimited_plan_means_zero_overage() {
        // A server-resolved unlimited plan (-1) must zero the overage even
        // when the client claimed a small limit.
        let limit = resolve_overage_email_limit(30_000, Some(-1));
        assert_eq!(
            plans::calculate_overage_cost_with_rate(1_000_000, limit, 40),
            0
        );
    }

    #[test]
    fn overage_limit_server_side_recompute_uses_configured_rate() {
        // The recomputed-limit path charges with the DEPLOYED rate, not the
        // hardcoded default: 1 000 overage emails at 80 millicents = 80 cents.
        let limit = resolve_overage_email_limit(10_000, Some(30_000));
        let cost = plans::calculate_overage_cost_with_rate(31_000, limit, 80);
        assert_eq!(cost, 80);
    }

    // ------------------------------------------------------------------
    // Audit item 3a — proration preview must honor the deployed config.
    // ------------------------------------------------------------------

    fn sample_proration_inputs() -> (Plan, Plan, RouteSubscription) {
        let now = chrono::Utc::now();
        let current_plan = Plan {
            id: Uuid::new_v4(),
            name: "starter".into(),
            display_name: "Starter".into(),
            description: String::new(),
            price_monthly: 1_000,
            price_yearly: 10_000,
            email_limit: 30_000,
            api_call_limit: 300_000,
            features: PlanFeatures::default(),
            stripe_price_id_monthly: None,
            stripe_price_id_yearly: None,
            is_active: true,
            sort_order: 0,
            created_at: now,
            updated_at: now,
        };
        let mut expensive_plan = current_plan.clone();
        expensive_plan.name = "enterprise".into();
        expensive_plan.display_name = "Enterprise".into();
        expensive_plan.price_monthly = 100_000;

        // Mid-period monthly subscription: 15 of 30 days remaining.
        let subscription = RouteSubscription {
            billing_interval: BillingInterval::Monthly,
            current_period_start: now - chrono::Duration::days(15),
            current_period_end: now + chrono::Duration::days(15),
        };
        (current_plan, expensive_plan, subscription)
    }

    #[test]
    fn proration_preview_uses_deployed_config_thresholds() {
        let (current_plan, new_plan, subscription) = sample_proration_inputs();

        // A deployed config with a tiny charge cap must reject what the
        // default config would happily preview — proving the config is
        // forwarded, not defaulted (audit item 3a).
        let tight_config = BillingConfig {
            max_proration_charge_cents: 1_000,
            ..BillingConfig::default()
        };
        let error = preview_plan_proration(&tight_config, &current_plan, &new_plan, &subscription)
            .expect_err("49 500-cent net charge exceeds the 1 000-cent deployed cap");
        assert!(error.contains("exceeds maximum allowed"));

        // The default cap (100 000) accepts the same preview.
        let preview = preview_plan_proration(
            &BillingConfig::default(),
            &current_plan,
            &new_plan,
            &subscription,
        )
        .expect("default caps accept the preview");
        assert_eq!(preview.net_amount, 49_500);
    }

    #[test]
    fn proration_preview_deployed_warn_threshold_emits_warning() {
        let (current_plan, new_plan, subscription) = sample_proration_inputs();

        let config = BillingConfig {
            warn_proration_charge_cents: 10_000,
            ..BillingConfig::default()
        };
        let preview = preview_plan_proration(&config, &current_plan, &new_plan, &subscription)
            .expect("preview must calculate");
        let warnings = preview.warnings.expect("49 500 > 10 000 warn threshold");
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("$495.00"));

        // Default warn threshold (25 000) also fires for this size.
        let preview = preview_plan_proration(
            &BillingConfig::default(),
            &current_plan,
            &new_plan,
            &subscription,
        )
        .expect("preview must calculate");
        assert!(preview.warnings.is_some());
    }

    #[test]
    fn proration_preview_deployed_credit_cap_rejects_large_downgrades() {
        let (current_plan, _new_plan, subscription) = sample_proration_inputs();
        let mut cheap_plan = current_plan.clone();
        cheap_plan.name = "free".into();
        cheap_plan.price_monthly = 0;

        let config = BillingConfig {
            max_proration_credit_cents: 100,
            ..BillingConfig::default()
        };
        let error = preview_plan_proration(&config, &current_plan, &cheap_plan, &subscription)
            .expect_err("500-cent credit exceeds the 100-cent deployed cap");
        assert!(error.contains("credit exceeds maximum allowed"));
    }
}
