//! Axum routes for the billing service.
//!
//! ```text
//! GET  /plans              – list active plans
//! GET  /plans/:name        – get plan by name
//! GET  /usage              – usage summary for current period
//! POST /usage/record       – record a metering event
//! GET  /invoices           – list invoices (paginated)
//! GET  /invoices/:id       – get invoice by ID
//! GET  /subscription       – get active subscription
//! GET  /quota              – check quota status
//! GET  /health             – liveness probe
//! ```

use std::sync::Arc;

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    middleware,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use chrono::Datelike;
use serde::Deserialize;
use uuid::Uuid;
use axum::middleware::Next;
use axum::response::Response;

use crate::{invoices, plans, subscriptions, types::MeterEventType, usage, AppState};

/// Build the full Axum router for billing.
pub fn router(state: Arc<AppState>) -> Router {
    let shared = state.clone();
    Router::new()
        // Plans
        .route("/plans", get(list_plans))
        .route("/plans/{name}", get(get_plan))
        // Usage
        .route("/usage", get(get_usage))
        .route("/usage/record", post(record_usage))
        // Invoices
        .route("/invoices", get(list_invoices))
        .route("/invoices/{id}", get(get_invoice))
        // Subscription
        .route("/subscription", get(get_subscription))
        // Quota
        .route("/quota", get(check_quota))
        // Health
        .route("/health", get(health))
        .with_state(state)
        .layer(middleware::from_fn_with_state(shared, require_service_auth))
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

async fn health() -> impl IntoResponse {
    (StatusCode::OK, Json(serde_json::json!({ "status": "ok" })))
}

/// GET /plans
async fn list_plans(
    State(state): State<Arc<AppState>>,
) -> Result<impl IntoResponse, ApiError> {
    let plans = plans::get_active_plans(&state.db).await?;
    Ok(Json(serde_json::json!({ "plans": plans })))
}

/// GET /plans/:name
async fn get_plan(
    State(state): State<Arc<AppState>>,
    Path(name): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    let plan = plans::get_plan_by_name(&state.db, &name).await?;
    match plan {
        Some(p) => Ok((StatusCode::OK, Json(to_json_value(p)?)).into_response()),
        None => Ok((
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "Plan not found" })),
        )
            .into_response()),
    }
}

/// Query params shared by usage + invoice endpoints.
#[derive(Deserialize)]
struct TenantQuery {
    tenant_id: Uuid,
}

/// GET /usage?tenant_id=...
async fn get_usage(
    State(state): State<Arc<AppState>>,
    Query(q): Query<TenantQuery>,
) -> Result<impl IntoResponse, ApiError> {
    let now = chrono::Utc::now();
    let period_start = now
        .date_naive()
        .with_day(1)
        .and_then(|d| d.and_hms_opt(0, 0, 0))
        .map(|dt| dt.and_utc())
        .unwrap_or_else(|| now.date_naive().and_hms_opt(0, 0, 0).unwrap().and_utc());
    let period_end = period_start + chrono::Months::new(1);
    let summary = usage::get_usage(&state.db, q.tenant_id, period_start, period_end).await?;
    Ok(Json(summary))
}

/// POST /usage/record
#[derive(Deserialize)]
struct RecordUsageBody {
    tenant_id: Uuid,
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
        body.tenant_id,
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

/// Query params for invoice listing.
#[derive(Deserialize)]
struct InvoiceListQuery {
    tenant_id: Uuid,
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
        q.tenant_id,
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
        Some(_) | None => Ok((
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "Invoice not found" })),
        )
            .into_response()),
    }
}

/// GET /subscription?tenant_id=...
async fn get_subscription(
    State(state): State<Arc<AppState>>,
    Query(q): Query<TenantQuery>,
) -> Result<impl IntoResponse, ApiError> {
    let sub = subscriptions::get_subscription(&state.db, q.tenant_id).await?;
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
    let status = usage::check_quota(&state.db, &state.redis, q.tenant_id).await?;
    Ok(Json(status))
}

// ---------------------------------------------------------------------------
// Error mapping
// ---------------------------------------------------------------------------

/// Unified API error that maps domain errors → HTTP responses.
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
        let msg = match &self {
            ApiError::Plans(e) => e.to_string(),
            ApiError::Usage(e) => e.to_string(),
            ApiError::Invoice(e) => e.to_string(),
            ApiError::Subscription(e) => e.to_string(),
        };
        tracing::error!(error = %msg, "billing API error");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": msg })),
        )
            .into_response()
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
    if req.uri().path() == "/health" {
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
        // Just verify the conversion compiles and doesn't panic.
        let err = ApiError::Plans(sqlx::Error::RowNotFound);
        let resp = err.into_response();
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }
}
