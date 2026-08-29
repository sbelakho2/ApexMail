//! HTTP routes — 25+ endpoints for organizations, workspaces, members, quota,
//! rate limiting, encryption, data isolation, and audit.
//!
//! Bearer token auth using constant-time comparison. Health check at GET /health.

use axum::{
    extract::{DefaultBodyLimit, Json, Path, Query, State},
    http::{header, HeaderMap, StatusCode},
    response::IntoResponse,
    routing::{delete, get, post, put},
    Router,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;
use tower_http::timeout::TimeoutLayer;

use crate::audit::AuditService;
use crate::config::{Config, IsolationLevel};
use crate::data_isolation::DataIsolationService;
use crate::encryption::EncryptionService;
use crate::rate_limit::RateLimitService;
use crate::tenant::TenantService;
use crate::types::*;
use apexmail_lib::crypto::timing_safe_compare;

// ─── Shared State ───────────────────────────────────────────────

pub struct AppState {
    pub tenant: TenantService,
    pub isolation: DataIsolationService,
    pub encryption: EncryptionService,
    pub rate_limit: RateLimitService,
    pub audit: AuditService,
    pub config: Config,
}

type S = Arc<AppState>;

// ─── Router ─────────────────────────────────────────────────────

pub fn create_router(state: S) -> Router {
    Router::new()
        // Health
        .route("/health", get(health_check))
        // Organizations
        .route("/organizations", post(org_create))
        .route("/organizations/:org_id", get(org_get))
        .route("/organizations/:org_id", put(org_update))
        .route("/organizations/:org_id/suspend", post(org_suspend))
        // Workspaces
        .route("/organizations/:org_id/workspaces", post(workspace_create))
        .route("/organizations/:org_id/workspaces", get(workspace_list))
        .route("/workspaces/:workspace_id", get(workspace_get))
        .route("/workspaces/:workspace_id", put(workspace_update))
        .route("/workspaces/:workspace_id", delete(workspace_delete))
        // Members
        .route("/workspaces/:workspace_id/members", post(member_add))
        .route(
            "/workspaces/:workspace_id/members/:user_id",
            delete(member_remove),
        )
        .route(
            "/workspaces/:workspace_id/members/:user_id/access",
            get(member_access),
        )
        // Quota
        .route("/workspaces/:workspace_id/quota", get(quota_check))
        .route("/workspaces/:workspace_id/quota", put(quota_update))
        // Rate Limit
        .route(
            "/workspaces/:workspace_id/rate-limit",
            get(rate_limit_status),
        )
        .route(
            "/workspaces/:workspace_id/rate-limit/reset",
            post(rate_limit_reset),
        )
        // Encryption
        .route("/encryption/rotate/:org_id", post(encryption_rotate))
        .route("/encryption/policy", post(encryption_create_policy))
        // Isolation
        .route("/isolation/check-access", post(isolation_check_access))
        .route("/isolation/migrate/:org_id", post(isolation_migrate))
        .route("/isolation/rls/:workspace_id", post(isolation_setup_rls))
        // Audit
        .route("/audit/query", get(audit_query))
        .route("/audit/stats/:org_id", get(audit_stats))
        .route("/audit/export/:org_id", get(audit_export))
        .layer(DefaultBodyLimit::max(1024 * 1024)) // 1 MB
        .layer(TimeoutLayer::new(Duration::from_secs(30)))
        .with_state(state)
}

// ─── Auth ───────────────────────────────────────────────────────

fn verify_bearer(headers: &HeaderMap, config: &Config) -> Result<(), (StatusCode, &'static str)> {
    let auth = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .ok_or((StatusCode::UNAUTHORIZED, "Missing Authorization header"))?;

    let token = auth
        .strip_prefix("Bearer ")
        .ok_or((StatusCode::UNAUTHORIZED, "Invalid Authorization format"))?;

    let accepted = if config.internal_api_keys.is_empty() {
        timing_safe_compare(token, &config.internal_api_key)
    } else {
        config
            .internal_api_keys
            .iter()
            .any(|key| timing_safe_compare(token, key))
    };

    if !accepted {
        return Err((StatusCode::UNAUTHORIZED, "Invalid token"));
    }
    Ok(())
}

fn extract_user_id(headers: &HeaderMap) -> Result<String, (StatusCode, &'static str)> {
    headers
        .get("x-user-id")
        .and_then(|v| v.to_str().ok())
        .map(String::from)
        .ok_or((StatusCode::UNAUTHORIZED, "Missing x-user-id header"))
}

// ─── Tenant Claim Authorization ─────────────────────────────────
//
// This service authenticates callers with a shared internal API token, so
// the bearer token alone proves "some trusted internal service" — never
// *which* tenant the call is for. The trusted edge/gateway is expected to
// strip any client-supplied `x-org-id` header and set its own, derived from
// the authenticated session. When that claim header is present, every
// organization/workspace in the request path MUST belong to the claimed
// organization; a mismatch is a cross-tenant access attempt and gets 403.
// When absent (direct internal service-to-service traffic), the request is
// allowed but logged — deployments that need strict enforcement must front
// this service with the edge.

const ORG_CLAIM_HEADER: &str = "x-org-id";

/// Verify the edge-supplied org claim matches the organization in the path.
fn verify_org_claim(
    headers: &HeaderMap,
    path_org_id: &str,
) -> Result<(), (StatusCode, &'static str)> {
    match headers
        .get(ORG_CLAIM_HEADER)
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
    {
        Some(claim) if claim.eq_ignore_ascii_case(path_org_id) => Ok(()),
        Some(claim) => {
            tracing::warn!(
                claimed_org = %claim,
                path_org = %path_org_id,
                "SECURITY: org claim does not match path — refusing request"
            );
            Err((
                StatusCode::FORBIDDEN,
                "Organization claim does not match requested resource",
            ))
        }
        None => {
            tracing::debug!("No x-org-id claim header on internal call");
            Ok(())
        }
    }
}

/// Verify a workspace-scoped request belongs to the claimed organization.
async fn verify_workspace_org_claim(
    headers: &HeaderMap,
    state: &AppState,
    workspace_id: &str,
) -> Result<(), (StatusCode, &'static str)> {
    let Some(claim) = headers
        .get(ORG_CLAIM_HEADER)
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
    else {
        return Ok(());
    };
    match state.tenant.get_workspace(workspace_id).await {
        Ok(ws) if ws.organization_id.eq_ignore_ascii_case(claim) => Ok(()),
        Ok(ws) => {
            tracing::warn!(
                claimed_org = %claim,
                workspace_org = %ws.organization_id,
                workspace = %workspace_id,
                "SECURITY: workspace belongs to a different org than claimed"
            );
            Err((
                StatusCode::FORBIDDEN,
                "Workspace does not belong to claimed organization",
            ))
        }
        Err(_) => Err((StatusCode::NOT_FOUND, "Workspace not found")),
    }
}

/// Restrict rate-limit resets to the path workspace's OWN enforcement key.
/// Raw caller-supplied keys (e.g. another workspace's key, or the old
/// phantom `workspace:{ws}:api` shape nothing writes) are rejected.
fn resettable_rate_limit_key(
    workspace_id: &str,
    requested: Option<&str>,
) -> Result<(String, &'static str), (StatusCode, &'static str)> {
    let (suffix, prefix) = crate::rate_limit::workspace_api_rate_limit_key_parts(workspace_id);
    let enforcement_key = format!("{prefix}:{suffix}");
    match requested.map(str::trim) {
        None => Ok((suffix, prefix)),
        Some(key) if key == enforcement_key => Ok((suffix, prefix)),
        Some(key) => {
            tracing::warn!(
                key = %key,
                workspace = %workspace_id,
                "SECURITY: refused rate-limit reset for key outside the workspace scope"
            );
            Err((
                StatusCode::FORBIDDEN,
                "Rate-limit key is outside this workspace's scope",
            ))
        }
    }
}

fn err_json(msg: &str) -> Json<serde_json::Value> {
    Json(serde_json::json!({ "error": msg }))
}

fn ok_json(v: serde_json::Value) -> (StatusCode, Json<serde_json::Value>) {
    (StatusCode::OK, Json(v))
}

fn serialize_json<T: Serialize>(
    value: T,
) -> Result<serde_json::Value, (StatusCode, Json<serde_json::Value>)> {
    serde_json::to_value(value).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            err_json(&format!("serialization failed: {e}")),
        )
    })
}

fn clamp_limit(limit: i64, max: i64) -> i64 {
    limit.clamp(1, max)
}

fn clamp_offset(offset: i64) -> i64 {
    offset.clamp(0, 100_000)
}

// ─── Health ─────────────────────────────────────────────────────

async fn health_check() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "status": "ok",
        "service": "isolation",
        "timestamp": chrono::Utc::now().to_rfc3339()
    }))
}

// ─── Organization Handlers ──────────────────────────────────────

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateOrgRequest {
    name: String,
    slug: String,
    billing_email: String,
    plan: Option<String>,
    owner_id: String,
    isolation_level: Option<String>,
}

async fn org_create(
    State(state): State<S>,
    headers: HeaderMap,
    Json(body): Json<CreateOrgRequest>,
) -> impl IntoResponse {
    if let Err(e) = verify_bearer(&headers, &state.config) {
        return (e.0, err_json(e.1));
    }
    let isolation = body
        .isolation_level
        .as_deref()
        .and_then(IsolationLevel::parse)
        .unwrap_or(IsolationLevel::Shared);

    match state
        .tenant
        .create_organization(
            &body.name,
            &body.slug,
            &body.billing_email,
            Some(body.plan.as_deref().unwrap_or("free")),
            Some(isolation),
            &body.owner_id,
        )
        .await
    {
        Ok(org) => match serialize_json(org) {
            Ok(json) => (StatusCode::CREATED, Json(json)),
            Err(err) => err,
        },
        Err(e) => (StatusCode::BAD_REQUEST, err_json(&e.to_string())),
    }
}

async fn org_get(
    State(state): State<S>,
    headers: HeaderMap,
    Path(org_id): Path<String>,
) -> impl IntoResponse {
    if let Err(e) = verify_bearer(&headers, &state.config) {
        return (e.0, err_json(e.1));
    }

    if let Err(e) = verify_org_claim(&headers, &org_id) {
        return (e.0, err_json(e.1));
    }
    match state.tenant.get_organization(&org_id).await {
        Ok(org) => match serialize_json(org) {
            Ok(json) => ok_json(json),
            Err(err) => err,
        },
        Err(e) => (StatusCode::NOT_FOUND, err_json(&e.to_string())),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UpdateOrgRequest {
    name: Option<String>,
    billing_email: Option<String>,
    plan: Option<String>,
    settings: Option<serde_json::Value>,
}

async fn org_update(
    State(state): State<S>,
    headers: HeaderMap,
    Path(org_id): Path<String>,
    Json(body): Json<UpdateOrgRequest>,
) -> impl IntoResponse {
    if let Err(e) = verify_bearer(&headers, &state.config) {
        return (e.0, err_json(e.1));
    }

    if let Err(e) = verify_org_claim(&headers, &org_id) {
        return (e.0, err_json(e.1));
    }
    match state
        .tenant
        .update_organization(
            &org_id,
            body.name.as_deref(),
            body.billing_email.as_deref(),
            body.plan.as_deref(),
            body.settings,
        )
        .await
    {
        Ok(org) => match serialize_json(org) {
            Ok(json) => ok_json(json),
            Err(err) => err,
        },
        Err(e) => (StatusCode::BAD_REQUEST, err_json(&e.to_string())),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SuspendRequest {
    reason: Option<String>,
}

async fn org_suspend(
    State(state): State<S>,
    headers: HeaderMap,
    Path(org_id): Path<String>,
    Json(body): Json<SuspendRequest>,
) -> impl IntoResponse {
    if let Err(e) = verify_bearer(&headers, &state.config) {
        return (e.0, err_json(e.1));
    }

    if let Err(e) = verify_org_claim(&headers, &org_id) {
        return (e.0, err_json(e.1));
    }
    let user_id = match extract_user_id(&headers) {
        Ok(uid) => uid,
        Err(e) => return (e.0, err_json(e.1)),
    };
    match state
        .tenant
        .suspend_organization(
            &org_id,
            body.reason.as_deref().unwrap_or("manual"),
            &user_id,
        )
        .await
    {
        Ok(()) => ok_json(serde_json::json!({ "status": "suspended" })),
        Err(e) => (StatusCode::BAD_REQUEST, err_json(&e.to_string())),
    }
}

// ─── Workspace Handlers ─────────────────────────────────────────

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateWorkspaceRequest {
    name: String,
    slug: String,
}

async fn workspace_create(
    State(state): State<S>,
    headers: HeaderMap,
    Path(org_id): Path<String>,
    Json(body): Json<CreateWorkspaceRequest>,
) -> impl IntoResponse {
    if let Err(e) = verify_bearer(&headers, &state.config) {
        return (e.0, err_json(e.1));
    }

    if let Err(e) = verify_org_claim(&headers, &org_id) {
        return (e.0, err_json(e.1));
    }
    let user_id = match extract_user_id(&headers) {
        Ok(uid) => uid,
        Err(e) => return (e.0, err_json(e.1)),
    };
    match state
        .tenant
        .create_workspace(&org_id, &body.name, &body.slug, &user_id, None)
        .await
    {
        Ok(ws) => match serialize_json(ws) {
            Ok(json) => (StatusCode::CREATED, Json(json)),
            Err(err) => err,
        },
        Err(e) => (StatusCode::BAD_REQUEST, err_json(&e.to_string())),
    }
}

async fn workspace_list(
    State(state): State<S>,
    headers: HeaderMap,
    Path(org_id): Path<String>,
) -> impl IntoResponse {
    if let Err(e) = verify_bearer(&headers, &state.config) {
        return (e.0, err_json(e.1));
    }

    if let Err(e) = verify_org_claim(&headers, &org_id) {
        return (e.0, err_json(e.1));
    }
    match state.tenant.list_workspaces(&org_id).await {
        Ok(workspaces) => match serialize_json(workspaces) {
            Ok(json) => ok_json(json),
            Err(err) => err,
        },
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, err_json(&e.to_string())),
    }
}

async fn workspace_get(
    State(state): State<S>,
    headers: HeaderMap,
    Path(workspace_id): Path<String>,
) -> impl IntoResponse {
    if let Err(e) = verify_bearer(&headers, &state.config) {
        return (e.0, err_json(e.1));
    }
    if let Err(e) = verify_workspace_org_claim(&headers, &state, &workspace_id).await {
        return (e.0, err_json(e.1));
    }
    match state.tenant.get_workspace(&workspace_id).await {
        Ok(ws) => match serialize_json(ws) {
            Ok(json) => ok_json(json),
            Err(err) => err,
        },
        Err(e) => (StatusCode::NOT_FOUND, err_json(&e.to_string())),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UpdateWorkspaceRequest {
    name: Option<String>,
    settings: Option<serde_json::Value>,
}

async fn workspace_update(
    State(state): State<S>,
    headers: HeaderMap,
    Path(workspace_id): Path<String>,
    Json(body): Json<UpdateWorkspaceRequest>,
) -> impl IntoResponse {
    if let Err(e) = verify_bearer(&headers, &state.config) {
        return (e.0, err_json(e.1));
    }
    if let Err(e) = verify_workspace_org_claim(&headers, &state, &workspace_id).await {
        return (e.0, err_json(e.1));
    }
    match state
        .tenant
        .update_workspace(&workspace_id, body.name.as_deref(), body.settings)
        .await
    {
        Ok(ws) => match serialize_json(ws) {
            Ok(json) => ok_json(json),
            Err(err) => err,
        },
        Err(e) => (StatusCode::BAD_REQUEST, err_json(&e.to_string())),
    }
}

async fn workspace_delete(
    State(state): State<S>,
    headers: HeaderMap,
    Path(workspace_id): Path<String>,
) -> impl IntoResponse {
    if let Err(e) = verify_bearer(&headers, &state.config) {
        return (e.0, err_json(e.1));
    }
    if let Err(e) = verify_workspace_org_claim(&headers, &state, &workspace_id).await {
        return (e.0, err_json(e.1));
    }
    let user_id = match extract_user_id(&headers) {
        Ok(uid) => uid,
        Err(e) => return (e.0, err_json(e.1)),
    };
    match state.tenant.delete_workspace(&workspace_id, &user_id).await {
        Ok(()) => ok_json(serde_json::json!({ "status": "deleted" })),
        Err(e) => (StatusCode::BAD_REQUEST, err_json(&e.to_string())),
    }
}

// ─── Member Handlers ────────────────────────────────────────────

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AddMemberRequest {
    user_id: String,
    role: String,
}

async fn member_add(
    State(state): State<S>,
    headers: HeaderMap,
    Path(workspace_id): Path<String>,
    Json(body): Json<AddMemberRequest>,
) -> impl IntoResponse {
    if let Err(e) = verify_bearer(&headers, &state.config) {
        return (e.0, err_json(e.1));
    }
    if let Err(e) = verify_workspace_org_claim(&headers, &state, &workspace_id).await {
        return (e.0, err_json(e.1));
    }
    let user_id = match extract_user_id(&headers) {
        Ok(uid) => uid,
        Err(e) => return (e.0, err_json(e.1)),
    };
    let role = TenantRole::parse(&body.role).unwrap_or(TenantRole::Member);
    match state
        .tenant
        .add_workspace_member(&workspace_id, &body.user_id, &role, &user_id)
        .await
    {
        Ok(()) => (
            StatusCode::CREATED,
            Json(serde_json::json!({ "status": "added" })),
        ),
        Err(e) => (StatusCode::BAD_REQUEST, err_json(&e.to_string())),
    }
}

async fn member_remove(
    State(state): State<S>,
    headers: HeaderMap,
    Path((workspace_id, user_id)): Path<(String, String)>,
) -> impl IntoResponse {
    if let Err(e) = verify_bearer(&headers, &state.config) {
        return (e.0, err_json(e.1));
    }
    if let Err(e) = verify_workspace_org_claim(&headers, &state, &workspace_id).await {
        return (e.0, err_json(e.1));
    }
    match state
        .tenant
        .remove_workspace_member(&workspace_id, &user_id)
        .await
    {
        Ok(()) => ok_json(serde_json::json!({ "status": "removed" })),
        Err(e) => (StatusCode::BAD_REQUEST, err_json(&e.to_string())),
    }
}

async fn member_access(
    State(state): State<S>,
    headers: HeaderMap,
    Path((workspace_id, user_id)): Path<(String, String)>,
) -> impl IntoResponse {
    if let Err(e) = verify_bearer(&headers, &state.config) {
        return (e.0, err_json(e.1));
    }
    if let Err(e) = verify_workspace_org_claim(&headers, &state, &workspace_id).await {
        return (e.0, err_json(e.1));
    }
    match state
        .tenant
        .check_member_access(&workspace_id, &user_id)
        .await
    {
        Ok(access) => match serialize_json(access) {
            Ok(json) => ok_json(json),
            Err(err) => err,
        },
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, err_json(&e.to_string())),
    }
}

// ─── Quota Handlers ─────────────────────────────────────────────

async fn quota_check(
    State(state): State<S>,
    headers: HeaderMap,
    Path(workspace_id): Path<String>,
) -> impl IntoResponse {
    if let Err(e) = verify_bearer(&headers, &state.config) {
        return (e.0, err_json(e.1));
    }
    if let Err(e) = verify_workspace_org_claim(&headers, &state, &workspace_id).await {
        return (e.0, err_json(e.1));
    }
    // Check all quota metrics
    let mut results = serde_json::Map::new();
    for metric in [
        "emails_per_month",
        "storage_bytes",
        "api_requests_per_minute",
        "webhooks_per_month",
        "contacts",
        "templates",
        "domains",
    ] {
        match state.tenant.check_quota(&workspace_id, metric, 1).await {
            Ok(ok) => {
                results.insert(metric.into(), serde_json::json!(ok));
            }
            Err(e) => {
                results.insert(metric.into(), serde_json::json!({"error": e.to_string()}));
            }
        }
    }
    ok_json(serde_json::Value::Object(results))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UpdateQuotaRequest {
    emails_per_month: Option<i64>,
    storage_bytes: Option<i64>,
    api_requests_per_minute: Option<i64>,
    webhooks_per_month: Option<i64>,
    contacts_limit: Option<i64>,
    templates_limit: Option<i64>,
    domains_limit: Option<i64>,
}

async fn quota_update(
    State(state): State<S>,
    headers: HeaderMap,
    Path(workspace_id): Path<String>,
    Json(body): Json<UpdateQuotaRequest>,
) -> impl IntoResponse {
    if let Err(e) = verify_bearer(&headers, &state.config) {
        return (e.0, err_json(e.1));
    }
    if let Err(e) = verify_workspace_org_claim(&headers, &state, &workspace_id).await {
        return (e.0, err_json(e.1));
    }
    let quota = crate::config::QuotaConfig {
        emails_per_month: body.emails_per_month.unwrap_or(50_000),
        storage_bytes: body.storage_bytes.unwrap_or(1_073_741_824),
        api_requests_per_minute: body.api_requests_per_minute.unwrap_or(100),
        webhooks_per_month: body.webhooks_per_month.unwrap_or(10_000),
        contacts_limit: body.contacts_limit.unwrap_or(10_000),
        templates_limit: body.templates_limit.unwrap_or(100),
        domains_limit: body.domains_limit.unwrap_or(10),
    };
    match state.tenant.update_quota(&workspace_id, quota).await {
        Ok(()) => ok_json(serde_json::json!({ "status": "updated" })),
        Err(e) => (StatusCode::BAD_REQUEST, err_json(&e.to_string())),
    }
}

// ─── Rate Limit Handlers ────────────────────────────────────────

async fn rate_limit_status(
    State(state): State<S>,
    headers: HeaderMap,
    Path(workspace_id): Path<String>,
) -> impl IntoResponse {
    if let Err(e) = verify_bearer(&headers, &state.config) {
        return (e.0, err_json(e.1));
    }
    if let Err(e) = verify_workspace_org_claim(&headers, &state, &workspace_id).await {
        return (e.0, err_json(e.1));
    }
    // Read the EXACT key the enforcement path writes (shared key builder in
    // rate_limit.rs) — the old `ratelimit:workspace:{ws}:api` key was a
    // phantom that enforcement never populated.
    let (key, prefix) = crate::rate_limit::workspace_api_rate_limit_key_parts(&workspace_id);
    let config = RateLimitConfig {
        window_ms: 60_000,
        max_requests: 100,
        burst_limit: None,
        key_prefix: Some(prefix.into()),
    };
    match state.rate_limit.get_rate_limit_status(&key, &config).await {
        Ok(result) => match serialize_json(result) {
            Ok(json) => ok_json(json),
            Err(err) => err,
        },
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, err_json(&e.to_string())),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ResetRateLimitRequest {
    key: String,
}

async fn rate_limit_reset(
    State(state): State<S>,
    headers: HeaderMap,
    Path(workspace_id): Path<String>,
    Json(body): Json<ResetRateLimitRequest>,
) -> impl IntoResponse {
    if let Err(e) = verify_bearer(&headers, &state.config) {
        return (e.0, err_json(e.1));
    }
    if let Err(e) = verify_workspace_org_claim(&headers, &state, &workspace_id).await {
        return (e.0, err_json(e.1));
    }
    // Only this workspace's OWN enforcement key may be deleted (built from
    // the path param via the shared key builder); arbitrary caller-supplied
    // keys — including the old phantom `workspace:{ws}:api` shape — are
    // rejected.
    let (key, prefix) = match resettable_rate_limit_key(&workspace_id, Some(&body.key)) {
        Ok(parts) => parts,
        Err(e) => return (e.0, err_json(e.1)),
    };
    match state.rate_limit.reset_rate_limit(&key, Some(prefix)).await {
        Ok(()) => ok_json(serde_json::json!({ "status": "reset" })),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, err_json(&e.to_string())),
    }
}

// ─── Encryption Handlers ────────────────────────────────────────

async fn encryption_rotate(
    State(state): State<S>,
    headers: HeaderMap,
    Path(org_id): Path<String>,
) -> impl IntoResponse {
    if let Err(e) = verify_bearer(&headers, &state.config) {
        return (e.0, err_json(e.1));
    }
    if let Err(e) = verify_org_claim(&headers, &org_id) {
        return (e.0, err_json(e.1));
    }
    match state.encryption.rotate_key(&org_id).await {
        Ok(key) => ok_json(serde_json::json!({
            "status": "rotated",
            "key_id": key.id,
        })),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, err_json(&e.to_string())),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CreatePolicyRequest {
    organization_id: String,
    table_name: String,
    fields: Vec<String>,
    algorithm: Option<String>,
}

async fn encryption_create_policy(
    State(state): State<S>,
    headers: HeaderMap,
    Json(body): Json<CreatePolicyRequest>,
) -> impl IntoResponse {
    if let Err(e) = verify_bearer(&headers, &state.config) {
        return (e.0, err_json(e.1));
    }
    if let Err(e) = verify_org_claim(&headers, &body.organization_id) {
        return (e.0, err_json(e.1));
    }
    if let Err(e) = state.tenant.get_organization(&body.organization_id).await {
        return (StatusCode::NOT_FOUND, err_json(&e.to_string()));
    }

    let policy = EncryptionPolicy {
        id: uuid::Uuid::new_v4().to_string(),
        name: format!("{}_{}_policy", body.organization_id, body.table_name),
        resource: body.table_name.clone(),
        fields: body.fields.clone(),
        algorithm: body
            .algorithm
            .clone()
            .unwrap_or_else(|| "aes-256-gcm".into()),
        key_rotation_days: 90,
        enabled: true,
    };
    match state.encryption.create_policy(policy).await {
        Ok(policy) => match serialize_json(policy) {
            Ok(json) => (StatusCode::CREATED, Json(json)),
            Err(err) => err,
        },
        Err(e) => (StatusCode::BAD_REQUEST, err_json(&e.to_string())),
    }
}

// ─── Isolation Handlers ─────────────────────────────────────────

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CheckAccessRequest {
    query: String,
    organization_id: String,
    workspace_id: String,
    user_id: String,
    resource: String,
    resource_id: String,
}

async fn isolation_check_access(
    State(state): State<S>,
    headers: HeaderMap,
    Json(body): Json<CheckAccessRequest>,
) -> impl IntoResponse {
    if let Err(e) = verify_bearer(&headers, &state.config) {
        return (e.0, err_json(e.1));
    }
    if let Err(e) = verify_org_claim(&headers, &body.organization_id) {
        return (e.0, err_json(e.1));
    }
    let org = match state.tenant.get_organization(&body.organization_id).await {
        Ok(v) => v,
        Err(e) => return (StatusCode::NOT_FOUND, err_json(&e.to_string())),
    };

    let workspace = match state.tenant.get_workspace(&body.workspace_id).await {
        Ok(v) => v,
        Err(e) => return (StatusCode::NOT_FOUND, err_json(&e.to_string())),
    };

    let ctx = IsolationContext {
        organization_id: body.organization_id.clone(),
        workspace_id: body.workspace_id.clone(),
        user_id: body.user_id.clone(),
        isolation_level: org.isolation_level,
        schema_name: workspace.schema_name,
        permissions: vec![],
    };

    let query_valid = state.isolation.validate_query_access(&body.query, &ctx);
    let resource_ok = state
        .isolation
        .check_resource_access(&ctx, &body.resource, &body.resource_id, "read")
        .await
        .unwrap_or(false);

    ok_json(serde_json::json!({
        "query_valid": query_valid,
        "resource_access": resource_ok,
    }))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MigrateRequest {
    target_level: String,
}

async fn isolation_migrate(
    State(state): State<S>,
    headers: HeaderMap,
    Path(org_id): Path<String>,
    Json(body): Json<MigrateRequest>,
) -> impl IntoResponse {
    if let Err(e) = verify_bearer(&headers, &state.config) {
        return (e.0, err_json(e.1));
    }
    if let Err(e) = verify_org_claim(&headers, &org_id) {
        return (e.0, err_json(e.1));
    }
    let target =
        IsolationLevel::parse(&body.target_level).unwrap_or(IsolationLevel::DedicatedSchema);

    // Need current level from org
    let current = match state.tenant.get_organization(&org_id).await {
        Ok(org) => org.isolation_level,
        Err(e) => return (StatusCode::NOT_FOUND, err_json(&e.to_string())),
    };
    match state
        .isolation
        .migrate_isolation_level(&org_id, &current, &target)
        .await
    {
        Ok(()) => ok_json(serde_json::json!({ "status": "migrated" })),
        Err(e) => (StatusCode::BAD_REQUEST, err_json(&e.to_string())),
    }
}

async fn isolation_setup_rls(
    State(state): State<S>,
    headers: HeaderMap,
    Path(workspace_id): Path<String>,
) -> impl IntoResponse {
    if let Err(e) = verify_bearer(&headers, &state.config) {
        return (e.0, err_json(e.1));
    }
    if let Err(e) = verify_workspace_org_claim(&headers, &state, &workspace_id).await {
        return (e.0, err_json(e.1));
    }
    let workspace = match state.tenant.get_workspace(&workspace_id).await {
        Ok(v) => v,
        Err(e) => return (StatusCode::NOT_FOUND, err_json(&e.to_string())),
    };

    let schema = workspace
        .schema_name
        .unwrap_or_else(|| "public".to_string());

    match state.isolation.setup_rls("emails", &schema).await {
        Ok(()) => ok_json(serde_json::json!({ "status": "rls_configured" })),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, err_json(&e.to_string())),
    }
}

// ─── Audit Handlers ─────────────────────────────────────────────

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AuditQueryParams {
    organization_id: String,
    workspace_id: Option<String>,
    severity: Option<String>,
    actor_id: Option<String>,
    resource: Option<String>,
    start_time: Option<String>,
    end_time: Option<String>,
    limit: Option<i64>,
    offset: Option<i64>,
}

async fn audit_query(
    State(state): State<S>,
    headers: HeaderMap,
    Query(params): Query<AuditQueryParams>,
) -> impl IntoResponse {
    if let Err(e) = verify_bearer(&headers, &state.config) {
        return (e.0, err_json(e.1));
    }
    // Same tenant-claim check every sibling handler enforces:without it,
    // /audit/query was the one endpoint where a claimed org could read a
    // different organization's audit trail.
    if let Err(e) = verify_org_claim(&headers, &params.organization_id) {
        return (e.0, err_json(e.1));
    }
    let q = AuditQuery {
        organization_id: params.organization_id,
        workspace_id: params.workspace_id,
        types: None,
        severity: params.severity,
        actor_id: params.actor_id,
        resource: params.resource,
        start_time: params.start_time.and_then(|s| s.parse().ok()),
        end_time: params.end_time.and_then(|s| s.parse().ok()),
        limit: Some(clamp_limit(params.limit.unwrap_or(50), 500)),
        offset: Some(clamp_offset(params.offset.unwrap_or(0))),
    };
    match state.audit.query(&q).await {
        Ok((events, total)) => ok_json(serde_json::json!({
            "events": events,
            "total": total,
            "limit": q.limit.unwrap_or(50),
            "offset": q.offset.unwrap_or(0),
        })),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, err_json(&e.to_string())),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AuditStatsParams {
    days: Option<i64>,
}

async fn audit_stats(
    State(state): State<S>,
    headers: HeaderMap,
    Path(org_id): Path<String>,
    Query(params): Query<AuditStatsParams>,
) -> impl IntoResponse {
    if let Err(e) = verify_bearer(&headers, &state.config) {
        return (e.0, err_json(e.1));
    }
    if let Err(e) = verify_org_claim(&headers, &org_id) {
        return (e.0, err_json(e.1));
    }
    let days = params.days.unwrap_or(30);
    match state.audit.get_stats(&org_id, days).await {
        Ok(stats) => match serialize_json(stats) {
            Ok(json) => ok_json(json),
            Err(err) => err,
        },
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, err_json(&e.to_string())),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AuditExportParams {
    format: Option<String>,
    start_time: Option<String>,
    end_time: Option<String>,
}

async fn audit_export(
    State(state): State<S>,
    headers: HeaderMap,
    Path(org_id): Path<String>,
    Query(params): Query<AuditExportParams>,
) -> axum::response::Response {
    if let Err(e) = verify_bearer(&headers, &state.config) {
        return (e.0, err_json(e.1)).into_response();
    }
    if let Err(e) = verify_org_claim(&headers, &org_id) {
        return (e.0, err_json(e.1)).into_response();
    }
    let q = AuditQuery {
        organization_id: org_id,
        start_time: params.start_time.and_then(|s| s.parse().ok()),
        end_time: params.end_time.and_then(|s| s.parse().ok()),
        limit: Some(10_000),
        ..Default::default()
    };
    let format = params.format.as_deref().unwrap_or("json");
    match state.audit.export(&q, format).await {
        Ok(data) => {
            let ct = if format == "csv" {
                "text/csv"
            } else {
                "application/json"
            };
            (StatusCode::OK, [(header::CONTENT_TYPE, ct)], data).into_response()
        }
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, err_json(&e.to_string())).into_response(),
    }
}

// ─── Tests ──────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shared_timing_safe_compare() {
        assert!(timing_safe_compare("abc", "abc"));
        assert!(!timing_safe_compare("abc", "abd"));
        assert!(!timing_safe_compare("abc", "abcd"));
        assert!(!timing_safe_compare("", "a"));
        assert!(timing_safe_compare("", ""));
    }

    // ── Tenant claim authorization tests ──

    fn claim_headers(claim: Option<&str>) -> HeaderMap {
        let mut h = HeaderMap::new();
        if let Some(c) = claim {
            h.insert(ORG_CLAIM_HEADER, c.parse().unwrap());
        }
        h
    }

    #[test]
    fn test_verify_org_claim_matching() {
        assert!(verify_org_claim(&claim_headers(Some("org-1")), "org-1").is_ok());
        // Case-insensitive comparison.
        assert!(verify_org_claim(&claim_headers(Some("ORG-1")), "org-1").is_ok());
    }

    #[test]
    fn test_verify_org_claim_mismatch_rejected() {
        let err = verify_org_claim(&claim_headers(Some("org-attacker")), "org-victim")
            .expect_err("claim mismatch must be rejected");
        assert_eq!(err.0, StatusCode::FORBIDDEN);
    }

    #[test]
    fn test_verify_org_claim_absent_allows_internal() {
        // No claim header → internal service-to-service traffic is allowed
        // (documented deployment requirement:edge must set/strip the header).
        assert!(verify_org_claim(&claim_headers(None), "org-1").is_ok());
    }

    /// F14 regression:/audit/query takes the organization from QUERY
    /// params rather than the path, and previously skipped the org-claim
    /// check every sibling enforced. The handler now runs the same
    /// verify_org_claim on `params.organization_id` — pin that behavior
    /// for both the mismatch (403) and match (allowed) cases.
    #[test]
    fn test_audit_query_org_claim_enforced() {
        // A claimed org differing from the queried organization_id must be
        // refused exactly like the path-based sibling handlers.
        let err = verify_org_claim(&claim_headers(Some("org-attacker")), "org-victim")
            .expect_err("claim mismatch on /audit/query must be rejected");
        assert_eq!(
            err.0,
            StatusCode::FORBIDDEN,
            "cross-tenant audit query must be refused"
        );

        // Matching claim (case-insensitive, like everywhere else) passes.
        assert!(verify_org_claim(&claim_headers(Some("ORG-1")), "org-1").is_ok());
    }

    #[test]
    fn test_resettable_rate_limit_key_rejects_foreign_keys() {
        // Arbitrary caller keys must be rejected…
        let err = resettable_rate_limit_key("ws-1", Some("workspace:ws-other:api"))
            .expect_err("foreign workspace key must be rejected");
        assert_eq!(err.0, StatusCode::FORBIDDEN);

        let err =
            resettable_rate_limit_key("ws-1", Some("global:admin")).expect_err("raw key rejected");
        assert_eq!(err.0, StatusCode::FORBIDDEN);

        // The OLD phantom key shape (`workspace:{ws}:api`) is not a key the
        // enforcement path ever writes — it must be rejected too, not
        // silently deleted as a no-op.
        let err = resettable_rate_limit_key("ws-1", Some("workspace:ws-1:api"))
            .expect_err("phantom key shape must be rejected");
        assert_eq!(err.0, StatusCode::FORBIDDEN);
    }

    #[test]
    fn test_resettable_rate_limit_key_allows_own_enforcement_key() {
        // Only the workspace's OWN enforcement key is accepted, and it is
        // built from the shared key builder so status/reset can never
        // address a different key than enforcement writes.
        let (suffix, prefix) = resettable_rate_limit_key("ws-1", Some("workspace:api:ws-1:api"))
            .expect("own enforcement key allowed");
        assert_eq!(suffix, "ws-1:api");
        assert_eq!(prefix, "workspace:api");
        // Default (no key supplied) resolves to the same enforcement key.
        let (default_suffix, default_prefix) =
            resettable_rate_limit_key("ws-1", None).expect("default resolves");
        assert_eq!(default_suffix, suffix);
        assert_eq!(default_prefix, prefix);
        // Near-miss keys (foreign workspace inside the enforcement shape)
        // are rejected.
        assert!(resettable_rate_limit_key("ws-1", Some("workspace:api:ws-1-evil:api")).is_err());
        assert!(resettable_rate_limit_key("ws-1", Some("workspace:api:ws-other:api")).is_err());
    }

    /// F11 regression:the status/reset endpoints must address the exact key
    /// the enforcement path writes. Both sides build the key through the
    /// ONE shared builder in rate_limit.rs.
    #[test]
    fn test_status_and_reset_share_enforcement_key() {
        let (suffix, prefix) = crate::rate_limit::workspace_api_rate_limit_key_parts("ws-42");
        let full_key = format!("{prefix}:{suffix}");

        // The key the ENFORCEMENT path writes (check_workspace_quota's
        // api_requests_per_minute branch, built from the same parts)…
        assert_eq!(full_key, "workspace:api:ws-42:api");
        // …is NOT the phantom `ratelimit:workspace:{ws}:api` key the
        // endpoints used to read/delete.
        assert_ne!(full_key, "ratelimit:workspace:ws-42:api");
        // And the workspace config map uses the same prefix for the api
        // limit, keeping every consumer on one key scheme.
        let quota = crate::config::QuotaConfig::default();
        let configs = crate::rate_limit::RateLimitService::get_workspace_rate_limit_configs(&quota);
        assert_eq!(configs["api"].key_prefix.as_deref(), Some(prefix));
    }

    #[test]
    fn test_err_json() {
        let j = err_json("bad request");
        let v: &serde_json::Value = &j;
        assert_eq!(v["error"], "bad request");
    }

    #[test]
    fn test_ok_json() {
        let (code, body) = ok_json(serde_json::json!({"ok": true}));
        assert_eq!(code, StatusCode::OK);
        assert_eq!(body.0["ok"], true);
    }

    #[test]
    fn test_health_returns_ok() {
        // Verify the router builds without panic
        // (actual handler tested in integration)
        let _router: Router<()> = Router::new().route("/health", get(health_check));
    }

    #[test]
    fn test_create_org_request_deserialize() {
        let json = r#"{"name":"Acme","slug":"acme","billing_email":"a@b.com","owner_id":"u1"}"#;
        let req: CreateOrgRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.name, "Acme");
        assert_eq!(req.slug, "acme");
        assert!(req.plan.is_none());
        assert!(req.isolation_level.is_none());
    }

    #[test]
    fn test_create_workspace_request_deserialize() {
        let json = r#"{"name":"Workspace 1","slug":"workspace-1"}"#;
        let req: CreateWorkspaceRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.name, "Workspace 1");
        assert_eq!(req.slug, "workspace-1");
    }

    #[test]
    fn test_add_member_request_deserialize() {
        let json = r#"{"user_id":"u1","role":"admin"}"#;
        let req: AddMemberRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.user_id, "u1");
        assert_eq!(req.role, "admin");
    }

    #[test]
    fn test_check_access_request_deserialize() {
        let json = r#"{"query":"SELECT *","organization_id":"o1","workspace_id":"w1","user_id":"u1","resource":"emails","resource_id":"e1"}"#;
        let req: CheckAccessRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.query, "SELECT *");
        assert_eq!(req.organization_id, "o1");
    }

    #[test]
    fn test_audit_query_params_deserialize() {
        let json = r#"{"organization_id":"o1","limit":100}"#;
        let params: AuditQueryParams = serde_json::from_str(json).unwrap();
        assert_eq!(params.organization_id, "o1");
        assert_eq!(params.limit, Some(100));
        assert!(params.workspace_id.is_none());
    }

    #[test]
    fn test_update_quota_request_deserialize() {
        let json = r#"{"emails_per_month":100000}"#;
        let req: UpdateQuotaRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.emails_per_month, Some(100_000));
        assert!(req.storage_bytes.is_none());
    }
}
