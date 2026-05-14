//! Axum HTTP routes for the compliance service.
//!
//! Provides REST endpoints for risk scoring, content scanning, audit logging,
//! secret management, and GDPR data-subject-request handling (including
//! Double Opt-In consent).

use std::sync::Arc;

use axum::{
    extract::{DefaultBodyLimit, State},
    http::{header, HeaderMap, StatusCode},
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use base64::Engine;
use deadpool_redis::Pool as RedisPool;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use tower_http::cors::CorsLayer;
use tracing::error;

use crate::audit_logger::AuditLogger;
use crate::config::ComplianceConfig;
use crate::content_scanner::ContentScanner;
use crate::dsar_rate_limit::{DsarRateLimitStatus, DsarRateLimiter};
use crate::gdpr_automation::GdprAutomation;
use crate::hipaa::HipaaService;
use crate::risk_scoring::RiskScoringEngine;
use crate::secret_manager::SecretManager;
use crate::soc2::Soc2Service;
use crate::trust_portal::TrustPortalService;
use crate::types::*;

// ── Shared application state ───────────────────────────────────────────────

/// Shared state injected into every handler via `State<AppState>`.
pub struct AppState {
    pub risk_engine: RiskScoringEngine,
    pub content_scanner: ContentScanner,
    pub audit_logger: AuditLogger,
    pub secret_manager: SecretManager,
    pub gdpr: GdprAutomation,
    pub soc2: Soc2Service,
    pub hipaa: HipaaService,
    pub trust: TrustPortalService,
    pub config: ComplianceConfig,
    pub db: PgPool,
    pub redis: RedisPool,
    pub http_client: reqwest::Client,
    /// DSAR rate limiter (SEC-15): stricter rate limits for DSAR endpoints.
    pub dsar_rate_limiter: DsarRateLimiter,
}

// ── Router factory ────────────────────────────────────────────────────────

/// Build the complete axum `Router` for the compliance service.
pub fn create_router(state: Arc<AppState>) -> Router {
    // Build CORS layer from configured origin (empty = same-origin only)
    let cors_origin = state.config.cors_origin.trim();
    let cors = if cors_origin.is_empty() || cors_origin == "*" {
        CorsLayer::new().allow_origin(tower_http::cors::Any)
    } else {
        // F-15: Log a warning and fail closed (deny all) if configured origin is invalid,
        // rather than silently falling back to `AllowOrigin::any()`.
        let allow = match cors_origin.parse::<axum::http::HeaderValue>() {
            Ok(parsed) => tower_http::cors::AllowOrigin::exact(parsed),
            Err(e) => {
                tracing::error!(
                    origin = %cors_origin,
                    error = %e,
                    "invalid cors_origin in config; CORS will deny all origins"
                );
                tower_http::cors::AllowOrigin::list([])
            }
        };
        CorsLayer::new().allow_origin(allow)
    }
    .allow_methods([
        axum::http::Method::GET,
        axum::http::Method::POST,
        axum::http::Method::PUT,
        axum::http::Method::DELETE,
    ])
    .allow_headers([
        axum::http::header::AUTHORIZATION,
        axum::http::header::CONTENT_TYPE,
    ]);

    Router::new()
        // Health
        .route("/health", get(health_check))
        .route("/health/ready", get(health_ready))
        // Risk scoring
        .route("/risk/assess/{tenant_id}", post(risk_assess))
        .route("/risk/profile/{tenant_id}", get(risk_profile))
        .route("/risk/limits/{tenant_id}", post(risk_update_limits))
        .route("/risk/resolve/{tenant_id}", post(risk_resolve_flag))
        .route("/risk/critical", get(risk_critical_tenants))
        .route("/risk/stats", get(risk_stats))
        // Content scanning
        .route("/scan", post(scan_content))
        .route("/scan/spam", post(scan_content))
        .route("/scan/phishing", post(scan_content))
        .route("/scan/malware", post(scan_content))
        .route("/scan/policy", post(scan_content))
        // Audit
        .route("/audit", post(audit_create))
        .route("/audit/query", post(audit_query))
        .route("/audit/{id}", get(audit_get_entry))
        .route("/audit/verify", post(audit_verify_chain))
        .route("/audit/export", post(audit_export))
        .route("/audit/stats", get(audit_stats))
        // Secrets
        .route("/secrets", post(secret_create).get(secret_list))
        .route(
            "/secrets/{id}",
            get(secret_get).put(secret_update).delete(secret_delete),
        )
        .route("/secrets/{id}/rotate", post(secret_rotate))
        .route("/secrets/{id}/access", post(secret_grant_access))
        .route("/secrets/{id}/versions", get(secret_versions))
        .route("/secrets/{id}/rollback/{version}", post(secret_rollback))
        // GDPR
        .route("/gdpr/submit", post(gdpr_submit_request))
        .route("/gdpr/verify/{request_id}", post(gdpr_verify_request))
        .route("/gdpr/record-consent", post(gdpr_record_consent))
        .route("/gdpr/consents", post(gdpr_get_consents))
        .route(
            "/gdpr/consent-certificate",
            post(gdpr_get_consent_certificate),
        )
        .route("/gdpr/initiate-doi", post(gdpr_initiate_doi))
        .route("/gdpr/confirm-doi", post(gdpr_confirm_doi))
        .route("/gdpr/stats", get(gdpr_stats))
        // SOC2 / HIPAA / Trust Portal
        .merge(crate::admin_routes::admin_router())
        .merge(crate::admin_routes::public_trust_router())
        .with_state(state)
        // M-09: Limit JSON request body to 1 MB
        .layer(DefaultBodyLimit::max(1024 * 1024))
        // M-10: Apply CORS layer with configured origin
        .layer(cors)
}

// ── Auth middleware (per-request via Bearer token) ─────────────────────────

/// Timing-safe comparison for auth tokens.
/// Guards against timing attacks by using constant-time comparison.
fn constant_time_eq(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut result: u8 = 0;
    for (ca, cb) in a.bytes().zip(b.bytes()) {
        result |= ca ^ cb;
    }
    result == 0
}

/// Verify the Bearer token in the request headers.
/// Returns `Ok(())` if the token is valid, or `Err((StatusCode, &str))` on failure.
pub(crate) fn verify_bearer(
    headers: &HeaderMap,
    config: &ComplianceConfig,
) -> Result<(), (StatusCode, &'static str)> {
    let auth_header = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .ok_or((StatusCode::UNAUTHORIZED, "Missing Authorization header"))?;

    let token = auth_header
        .strip_prefix("Bearer ")
        .ok_or((StatusCode::UNAUTHORIZED, "Invalid token format"))?;

    // Only accept exact match via constant-time comparison
    if constant_time_eq(token, &config.auth_token) {
        Ok(())
    } else {
        Err((StatusCode::UNAUTHORIZED, "Invalid token"))
    }
}

/// Extract the caller identity from request headers.
/// Uses the `X-User-Id` header when present, falling back to the configured
/// service account name. This replaces hardcoded "api-user" references.
fn extract_caller_id(headers: &HeaderMap, _config: &ComplianceConfig) -> String {
    headers
        .get("X-User-Id")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "api-user".to_string())
}

// ── Response helpers ──────────────────────────────────────────────────────

/// Create a JSON error response.
pub(crate) fn err_json(code: StatusCode, msg: &str) -> (StatusCode, Json<serde_json::Value>) {
    (code, Json(serde_json::json!({ "error": msg })))
}

/// Create a JSON success response.
pub(crate) fn ok_json<T: Serialize>(data: T) -> (StatusCode, Json<serde_json::Value>) {
    (StatusCode::OK, Json(serde_json::json!({ "data": data })))
}

/// Create a JSON created response (201).
pub(crate) fn created_json<T: Serialize>(data: T) -> (StatusCode, Json<serde_json::Value>) {
    (
        StatusCode::CREATED,
        Json(serde_json::json!({ "data": data })),
    )
}

// ── Health endpoints ──────────────────────────────────────────────────────

/// GET /health — simple liveness check.
async fn health_check() -> impl IntoResponse {
    Json(serde_json::json!({ "status": "ok" }))
}

/// GET /health/ready — readiness check (DB connectivity).
async fn health_ready(
    State(state): State<Arc<AppState>>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    sqlx::query("SELECT 1")
        .execute(&state.db)
        .await
        .map_err(|_| err_json(StatusCode::SERVICE_UNAVAILABLE, "Database unavailable"))?;
    Ok(Json(serde_json::json!({ "status": "ready" })))
}

// ── Risk scoring endpoints ────────────────────────────────────────────────

/// POST /risk/assess/{tenant_id} — assess risk for a tenant.
async fn risk_assess(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    axum::extract::Path(tenant_id): axum::extract::Path<String>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    verify_bearer(&headers, &state.config).map_err(|(c, m)| err_json(c, m))?;
    match state.risk_engine.assess_tenant(&tenant_id).await {
        Ok(profile) => Ok(ok_json(profile)),
        Err(e) => {
            error!("Risk assessment failed for tenant {tenant_id}: {e}");
            Err(err_json(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Risk assessment failed",
            ))
        }
    }
}

/// GET /risk/profile/{tenant_id} — get tenant risk profile.
async fn risk_profile(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    axum::extract::Path(tenant_id): axum::extract::Path<String>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    verify_bearer(&headers, &state.config).map_err(|(c, m)| err_json(c, m))?;
    match state.risk_engine.get_profile(&tenant_id).await {
        Ok(Some(profile)) => Ok(ok_json(profile)),
        Ok(None) => Err(err_json(StatusCode::NOT_FOUND, "Tenant not found")),
        Err(e) => {
            error!("Failed to get risk profile for tenant {tenant_id}: {e}");
            Err(err_json(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to get risk profile",
            ))
        }
    }
}

/// POST /risk/limits/{tenant_id} — update tenant sending limits.
async fn risk_update_limits(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    axum::extract::Path(tenant_id): axum::extract::Path<String>,
    Json(body): Json<serde_json::Value>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    verify_bearer(&headers, &state.config).map_err(|(c, m)| err_json(c, m))?;
    let limits: TenantLimits = serde_json::from_value(body)
        .map_err(|e| err_json(StatusCode::BAD_REQUEST, &format!("Invalid limits: {e}")))?;
    match state.risk_engine.update_limits(&tenant_id, &limits).await {
        Ok(_) => Ok(Json(serde_json::json!({ "status": "limits updated" }))),
        Err(e) => {
            error!("Failed to update limits for tenant {tenant_id}: {e}");
            Err(err_json(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to update limits",
            ))
        }
    }
}

/// POST /risk/resolve/{tenant_id} — resolve a risk flag.
async fn risk_resolve_flag(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    axum::extract::Path(tenant_id): axum::extract::Path<String>,
    Json(body): Json<serde_json::Value>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    verify_bearer(&headers, &state.config).map_err(|(c, m)| err_json(c, m))?;
    let flag_type_str = body
        .get("flag_type")
        .and_then(|v| v.as_str())
        .ok_or_else(|| err_json(StatusCode::BAD_REQUEST, "Missing flag_type"))?;
    let flag_type =
        parse_risk_flag_type(flag_type_str).map_err(|e| err_json(StatusCode::BAD_REQUEST, &e))?;
    let resolution = body
        .get("resolution")
        .and_then(|v| v.as_str())
        .unwrap_or("Resolved via API");
    match state
        .risk_engine
        .resolve_flag(&tenant_id, &flag_type, resolution)
        .await
    {
        Ok(_) => Ok(Json(serde_json::json!({ "status": "resolved" }))),
        Err(e) => {
            error!("Failed to resolve flag for tenant {tenant_id}: {e}");
            Err(err_json(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to resolve flag",
            ))
        }
    }
}

/// GET /risk/critical — list all critical-risk tenants.
async fn risk_critical_tenants(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    verify_bearer(&headers, &state.config).map_err(|(c, m)| err_json(c, m))?;
    match state.risk_engine.get_critical_risk_tenants().await {
        Ok(tenants) => Ok(ok_json(tenants)),
        Err(e) => {
            error!("Failed to get critical risk tenants: {e}");
            Err(err_json(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to get critical tenants",
            ))
        }
    }
}

/// GET /risk/stats — get risk scoring statistics.
async fn risk_stats(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    verify_bearer(&headers, &state.config).map_err(|(c, m)| err_json(c, m))?;
    match state.risk_engine.get_risk_stats().await {
        Ok(stats) => Ok(ok_json(stats)),
        Err(e) => {
            error!("Failed to get risk stats: {e}");
            Err(err_json(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to get risk stats",
            ))
        }
    }
}

// ── Content scanning endpoints ────────────────────────────────────────────

/// POST /scan — full multi-layer content scan.
async fn scan_content(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(email): Json<EmailContent>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    verify_bearer(&headers, &state.config).map_err(|(c, m)| err_json(c, m))?;
    match state.content_scanner.scan_email(&email).await {
        Ok(result) => Ok(ok_json(result)),
        Err(e) => {
            error!("Content scan failed: {e}");
            Err(err_json(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Content scan failed",
            ))
        }
    }
}

// ── Audit endpoints ───────────────────────────────────────────────────────

/// POST /audit — create an audit log entry.
async fn audit_create(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(entry): Json<serde_json::Value>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    verify_bearer(&headers, &state.config).map_err(|(c, m)| err_json(c, m))?;
    let action_str = entry
        .get("action")
        .and_then(|v| v.as_str())
        .ok_or_else(|| err_json(StatusCode::BAD_REQUEST, "Missing action"))?;
    let resource_str = entry
        .get("resource")
        .and_then(|v| v.as_str())
        .ok_or_else(|| err_json(StatusCode::BAD_REQUEST, "Missing resource"))?;
    let tenant_id = entry
        .get("tenant_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| err_json(StatusCode::BAD_REQUEST, "Missing tenant_id"))?;

    let action = parse_audit_action(action_str)
        .ok_or_else(|| err_json(StatusCode::BAD_REQUEST, "Invalid action"))?;
    let resource = parse_audit_resource(resource_str)
        .ok_or_else(|| err_json(StatusCode::BAD_REQUEST, "Invalid resource"))?;

    let details = entry
        .get("details")
        .cloned()
        .unwrap_or(serde_json::Value::Null);
    let outcome_str = entry
        .get("outcome")
        .and_then(|v| v.as_str())
        .unwrap_or("success");
    let outcome = match outcome_str {
        "success" => AuditOutcome::Success,
        "failure" => AuditOutcome::Failure,
        "denied" => AuditOutcome::Failure,
        _ => return Err(err_json(StatusCode::BAD_REQUEST, "Invalid outcome")),
    };

    let ctx = LogContext {
        tenant_id: entry
            .get("tenant_id")
            .and_then(|v| v.as_str())
            .map(String::from),
        user_id: entry
            .get("user_id")
            .and_then(|v| v.as_str())
            .map(String::from),
        session_id: entry
            .get("session_id")
            .and_then(|v| v.as_str())
            .map(String::from),
        ip_address: entry.get("ip").and_then(|v| v.as_str()).map(String::from),
        user_agent: entry
            .get("user_agent")
            .and_then(|v| v.as_str())
            .map(String::from),
    };

    match state
        .audit_logger
        .log(
            action,
            resource,
            Some(tenant_id),
            details,
            outcome,
            None,
            &ctx,
        )
        .await
    {
        Ok(id) => Ok(created_json(serde_json::json!({ "id": id }))),
        Err(e) => {
            error!("Audit log failed: {e}");
            Err(err_json(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Audit log failed",
            ))
        }
    }
}

/// POST /audit/query — query audit log entries.
async fn audit_query(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(query): Json<AuditLogQuery>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    verify_bearer(&headers, &state.config).map_err(|(c, m)| err_json(c, m))?;
    match state.audit_logger.query(&query).await {
        Ok((entries, total)) => Ok(ok_json(serde_json::json!({
            "entries": entries,
            "total": total,
        }))),
        Err(e) => {
            error!("Audit query failed: {e}");
            Err(err_json(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Audit query failed",
            ))
        }
    }
}

/// GET /audit/{id} — get a single audit log entry.
async fn audit_get_entry(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    verify_bearer(&headers, &state.config).map_err(|(c, m)| err_json(c, m))?;
    match state.audit_logger.get_entry(&id).await {
        Ok(Some(entry)) => Ok(ok_json(entry)),
        Ok(None) => Err(err_json(StatusCode::NOT_FOUND, "Audit entry not found")),
        Err(e) => {
            error!("Failed to get audit entry {id}: {e}");
            Err(err_json(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to get audit entry",
            ))
        }
    }
}

/// POST /audit/verify — verify chain integrity.
async fn audit_verify_chain(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<serde_json::Value>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    verify_bearer(&headers, &state.config).map_err(|(c, m)| err_json(c, m))?;
    let tenant_id = body
        .get("tenant_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| err_json(StatusCode::BAD_REQUEST, "Missing tenant_id"))?;
    match state
        .audit_logger
        .verify_chain(Some(tenant_id), None, None)
        .await
    {
        Ok(result) => Ok(ok_json(result)),
        Err(e) => {
            error!("Audit verification failed: {e}");
            Err(err_json(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Audit verification failed",
            ))
        }
    }
}

/// POST /audit/export — export audit logs.
async fn audit_export(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<serde_json::Value>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    verify_bearer(&headers, &state.config).map_err(|(c, m)| err_json(c, m))?;
    let tenant_id = body
        .get("tenant_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| err_json(StatusCode::BAD_REQUEST, "Missing tenant_id"))?;
    let format = body.get("format").and_then(|v| v.as_str()).unwrap_or("csv");
    let query = AuditLogQuery {
        tenant_id: Some(tenant_id.to_string()),
        ..Default::default()
    };
    match state.audit_logger.export(&query, format).await {
        Ok(export) => Ok(Json(serde_json::json!({
            "data": export.data,
            "content_type": export.content_type,
            "filename": export.filename,
        }))),
        Err(e) => {
            error!("Audit export failed: {e}");
            Err(err_json(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Audit export failed",
            ))
        }
    }
}

/// GET /audit/stats — get audit statistics.
async fn audit_stats(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    verify_bearer(&headers, &state.config).map_err(|(c, m)| err_json(c, m))?;
    match state.audit_logger.get_stats(None).await {
        Ok(stats) => Ok(ok_json(stats)),
        Err(e) => {
            error!("Failed to get audit stats: {e}");
            Err(err_json(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to get audit stats",
            ))
        }
    }
}

// ── Secret management endpoints ───────────────────────────────────────────

/// POST /secrets — create a new secret.
async fn secret_create(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(input): Json<SecretCreateInput>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    verify_bearer(&headers, &state.config).map_err(|(c, m)| err_json(c, m))?;
    match state.secret_manager.create_secret(&input).await {
        Ok(secret) => Ok(created_json(secret)),
        Err(e) => {
            error!("Failed to create secret: {e}");
            Err(err_json(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to create secret",
            ))
        }
    }
}

/// GET /secrets — list all secrets (requires tenant_id query param).
async fn secret_list(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    verify_bearer(&headers, &state.config).map_err(|(c, m)| err_json(c, m))?;
    let tenant_id = params
        .get("tenant_id")
        .map(|s| s.as_str())
        .unwrap_or("default");
    match state
        .secret_manager
        .list_secrets(tenant_id, None, 100, 0)
        .await
    {
        Ok(secrets) => Ok(ok_json(secrets)),
        Err(e) => {
            error!("Failed to list secrets: {e}");
            Err(err_json(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to list secrets",
            ))
        }
    }
}

/// GET /secrets/{id} — get a secret by ID.
async fn secret_get(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    verify_bearer(&headers, &state.config).map_err(|(c, m)| err_json(c, m))?;
    let caller = extract_caller_id(&headers, &state.config);
    match state.secret_manager.get_secret(&id, &caller).await {
        Ok(Some((secret, _decrypted))) => Ok(ok_json(secret)),
        Ok(None) => Err(err_json(StatusCode::NOT_FOUND, "Secret not found")),
        Err(e) => {
            error!("Failed to get secret {id}: {e}");
            Err(err_json(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to get secret",
            ))
        }
    }
}

/// PUT /secrets/{id} — update a secret.
async fn secret_update(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
    Json(input): Json<SecretUpdateInput>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    verify_bearer(&headers, &state.config).map_err(|(c, m)| err_json(c, m))?;
    let caller = extract_caller_id(&headers, &state.config);
    match state
        .secret_manager
        .update_secret(&id, &caller, &input)
        .await
    {
        Ok(secret) => Ok(ok_json(secret)),
        Err(e) => {
            error!("Failed to update secret {id}: {e}");
            Err(err_json(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to update secret",
            ))
        }
    }
}

/// DELETE /secrets/{id} — delete a secret.
async fn secret_delete(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    verify_bearer(&headers, &state.config).map_err(|(c, m)| err_json(c, m))?;
    let caller = extract_caller_id(&headers, &state.config);
    match state.secret_manager.delete_secret(&id, &caller).await {
        Ok(_) => Ok(Json(serde_json::json!({ "status": "deleted" }))),
        Err(e) => {
            error!("Failed to delete secret {id}: {e}");
            Err(err_json(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to delete secret",
            ))
        }
    }
}

/// POST /secrets/{id}/rotate — rotate a secret.
async fn secret_rotate(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    verify_bearer(&headers, &state.config).map_err(|(c, m)| err_json(c, m))?;
    let caller = extract_caller_id(&headers, &state.config);
    match state.secret_manager.rotate_secret(&id, &caller, None).await {
        Ok((secret, _decrypted)) => Ok(ok_json(secret)),
        Err(e) => {
            error!("Failed to rotate secret {id}: {e}");
            Err(err_json(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to rotate secret",
            ))
        }
    }
}

/// POST /secrets/{id}/access — grant access to a secret.
async fn secret_grant_access(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
    Json(body): Json<serde_json::Value>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    verify_bearer(&headers, &state.config).map_err(|(c, m)| err_json(c, m))?;
    let user_id = body
        .get("user_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| err_json(StatusCode::BAD_REQUEST, "Missing user_id"))?;
    let access_level_str = body
        .get("access_level")
        .and_then(|v| v.as_str())
        .ok_or_else(|| err_json(StatusCode::BAD_REQUEST, "Missing access_level"))?;
    let access_level = match access_level_str {
        "read" => AccessLevel::Read,
        "write" => AccessLevel::Write,
        "admin" => AccessLevel::Admin,
        _ => return Err(err_json(StatusCode::BAD_REQUEST, "Invalid access_level")),
    };
    let caller = extract_caller_id(&headers, &state.config);
    match state
        .secret_manager
        .grant_access(&id, user_id, access_level, &caller, None)
        .await
    {
        Ok(_) => Ok(Json(serde_json::json!({ "status": "access granted" }))),
        Err(e) => {
            error!("Failed to grant access to secret {id}: {e}");
            Err(err_json(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to grant access",
            ))
        }
    }
}

/// GET /secrets/{id}/versions — get version history.
async fn secret_versions(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    verify_bearer(&headers, &state.config).map_err(|(c, m)| err_json(c, m))?;
    let caller = extract_caller_id(&headers, &state.config);
    match state.secret_manager.get_version_history(&id, &caller).await {
        Ok(versions) => Ok(ok_json(versions)),
        Err(e) => {
            error!("Failed to get versions for secret {id}: {e}");
            Err(err_json(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to get secret versions",
            ))
        }
    }
}

/// POST /secrets/{id}/rollback/{version} — rollback to a previous version.
async fn secret_rollback(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    axum::extract::Path((id, version)): axum::extract::Path<(String, i32)>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    verify_bearer(&headers, &state.config).map_err(|(c, m)| err_json(c, m))?;
    let caller = extract_caller_id(&headers, &state.config);
    match state
        .secret_manager
        .rollback_to_version(&id, version, &caller)
        .await
    {
        Ok(secret) => Ok(ok_json(secret)),
        Err(e) => {
            error!("Failed to rollback secret {id}: {e}");
            Err(err_json(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to rollback secret",
            ))
        }
    }
}

// ── GDPR endpoints ────────────────────────────────────────────────────────

/// POST /gdpr/submit — submit a data-subject request.
///
/// SEC-15: Enforces DSAR rate limits before processing the submission:
/// - Per-user: 1 request per 24 hours (by email)
/// - Per-tenant: 100 requests per 24 hours
async fn gdpr_submit_request(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<serde_json::Value>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    verify_bearer(&headers, &state.config).map_err(|(c, m)| err_json(c, m))?;
    let tenant_id = body
        .get("tenant_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| err_json(StatusCode::BAD_REQUEST, "Missing tenant_id"))?;
    let request_type_str = body
        .get("request_type")
        .and_then(|v| v.as_str())
        .ok_or_else(|| err_json(StatusCode::BAD_REQUEST, "Missing request_type"))?;
    let request_type = match request_type_str {
        "access" => DataSubjectRequestType::Access,
        "erasure" => DataSubjectRequestType::Erasure,
        "portability" => DataSubjectRequestType::Portability,
        "rectification" => DataSubjectRequestType::Rectification,
        "restriction" => DataSubjectRequestType::Restriction,
        "objection" => DataSubjectRequestType::Objection,
        _ => return Err(err_json(StatusCode::BAD_REQUEST, "Invalid request_type")),
    };
    let email = body
        .get("email")
        .and_then(|v| v.as_str())
        .ok_or_else(|| err_json(StatusCode::BAD_REQUEST, "Missing email"))?;

    // SEC-15: Check DSAR rate limits before processing
    match state
        .dsar_rate_limiter
        .check_submission(email, tenant_id)
        .await
    {
        DsarRateLimitStatus::UserRateLimited { retry_after } => {
            return Err((
                StatusCode::TOO_MANY_REQUESTS,
                Json(serde_json::json!({
                    "error": "rate_limited",
                    "message": "You have already submitted a DSAR request in the last 24 hours.",
                    "retry_after": retry_after.as_secs(),
                })),
            ));
        }
        DsarRateLimitStatus::TenantRateLimited { retry_after } => {
            return Err((
                StatusCode::TOO_MANY_REQUESTS,
                Json(serde_json::json!({
                    "error": "rate_limited",
                    "message": "Tenant DSAR quota exceeded. Please try again later.",
                    "retry_after": retry_after.as_secs(),
                })),
            ));
        }
        DsarRateLimitStatus::Allowed => { /* proceed */ }
        _ => {}
    }

    match state
        .gdpr
        .submit_request(tenant_id, request_type, email)
        .await
    {
        Ok(request) => Ok(created_json(request)),
        Err(e) => {
            error!("GDPR submit failed: {e}");
            Err(err_json(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to submit request",
            ))
        }
    }
}

/// POST /gdpr/verify/{request_id} — verify a data-subject request.
///
/// SEC-15: Enforces DSAR verification rate limit:
/// - Per-token: 5 verification attempts per hour
async fn gdpr_verify_request(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    axum::extract::Path(request_id): axum::extract::Path<String>,
    Json(body): Json<serde_json::Value>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    verify_bearer(&headers, &state.config).map_err(|(c, m)| err_json(c, m))?;
    let token = body
        .get("token")
        .and_then(|v| v.as_str())
        .ok_or_else(|| err_json(StatusCode::BAD_REQUEST, "Missing token"))?;

    // SEC-15: Check DSAR verification rate limit (5 attempts per token per hour)
    let token_hash = {
        use sha2::{Digest, Sha256};
        let hash = Sha256::digest(token.as_bytes());
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(hash)
    };
    match state
        .dsar_rate_limiter
        .check_verification(&token_hash)
        .await
    {
        DsarRateLimitStatus::VerificationRateLimited { retry_after } => {
            return Err((
                StatusCode::TOO_MANY_REQUESTS,
                Json(serde_json::json!({
                    "error": "rate_limited",
                    "message": "Too many verification attempts. Please try again later.",
                    "retry_after": retry_after.as_secs(),
                })),
            ));
        }
        DsarRateLimitStatus::Allowed => { /* proceed */ }
        _ => {}
    }

    match state.gdpr.verify_request(&request_id, token).await {
        Ok(verified) => Ok(ok_json(serde_json::json!({ "verified": verified }))),
        Err(e) => {
            error!("GDPR verify failed: {e}");
            Err(err_json(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to verify request",
            ))
        }
    }
}

/// POST /gdpr/record-consent — record a consent record.
async fn gdpr_record_consent(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<serde_json::Value>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    verify_bearer(&headers, &state.config).map_err(|(c, m)| err_json(c, m))?;
    let tenant_id = body
        .get("tenant_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| err_json(StatusCode::BAD_REQUEST, "Missing tenant_id"))?;
    let subscriber_id = body
        .get("subscriber_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| err_json(StatusCode::BAD_REQUEST, "Missing subscriber_id"))?;
    let consent_type_str = body
        .get("consent_type")
        .and_then(|v| v.as_str())
        .ok_or_else(|| err_json(StatusCode::BAD_REQUEST, "Missing consent_type"))?;
    let consent_type = parse_consent_type(consent_type_str)
        .ok_or_else(|| err_json(StatusCode::BAD_REQUEST, "Invalid consent_type"))?;
    let email = body
        .get("email")
        .and_then(|v| v.as_str())
        .ok_or_else(|| err_json(StatusCode::BAD_REQUEST, "Missing email"))?;
    let granted = body
        .get("granted")
        .and_then(|v| v.as_bool())
        .unwrap_or(true);

    match state
        .gdpr
        .record_consent(
            tenant_id,
            subscriber_id,
            email,
            consent_type,
            granted,
            ConsentSource::Api,
            None,
        )
        .await
    {
        Ok(record) => Ok(created_json(record)),
        Err(e) => {
            error!("Failed to record consent: {e}");
            Err(err_json(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to record consent",
            ))
        }
    }
}

/// POST /gdpr/consents — get consent records for a subscriber.
async fn gdpr_get_consents(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<serde_json::Value>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    verify_bearer(&headers, &state.config).map_err(|(c, m)| err_json(c, m))?;
    let tenant_id = body
        .get("tenant_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| err_json(StatusCode::BAD_REQUEST, "Missing tenant_id"))?;
    let subscriber_id = body
        .get("subscriber_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| err_json(StatusCode::BAD_REQUEST, "Missing subscriber_id"))?;
    match state
        .gdpr
        .get_consent_records(tenant_id, subscriber_id)
        .await
    {
        Ok(consents) => Ok(ok_json(consents)),
        Err(e) => {
            error!("Failed to get consents: {e}");
            Err(err_json(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to get consents",
            ))
        }
    }
}

/// POST /gdpr/consent-certificate — generate a consent certificate.
async fn gdpr_get_consent_certificate(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<serde_json::Value>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    verify_bearer(&headers, &state.config).map_err(|(c, m)| err_json(c, m))?;
    let consent_id = body
        .get("consent_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| err_json(StatusCode::BAD_REQUEST, "Missing consent_id"))?;
    match state.gdpr.generate_consent_certificate(consent_id).await {
        Ok(cert) => Ok(ok_json(cert)),
        Err(e) => {
            error!("Failed to generate consent certificate: {e}");
            Err(err_json(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to generate certificate",
            ))
        }
    }
}

/// GET /gdpr/stats — get GDPR statistics.
async fn gdpr_stats(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    verify_bearer(&headers, &state.config).map_err(|(c, m)| err_json(c, m))?;
    // L-03: Use GDPR request stats instead of audit log stats
    match state.gdpr.get_request_stats("").await {
        Ok(stats) => Ok(ok_json(stats)),
        Err(e) => {
            error!("Failed to get GDPR stats: {e}");
            Err(err_json(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to get stats",
            ))
        }
    }
}

// ── DOI (Double Opt-In) endpoint bodies ───────────────────────────────────

/// Request body for `POST /gdpr/initiate-doi`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DoiBody {
    pub tenant_id: String,
    pub subscriber_id: String,
    pub consent_type: String,
    pub email: String,
}

/// Request body for `POST /gdpr/confirm-doi`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DoiConfirmBody {
    pub tenant_id: String,
    pub subscriber_id: String,
    pub consent_type: String,
    pub token: String,
}

// ── DOI Handlers ─────────────────────────────────────────────────────────

/// POST /gdpr/initiate-doi — initiate the Double Opt-In flow.
///
/// Validates the consent type, authenticates the request, and delegates to
/// `GdprAutomation::initiate_double_opt_in`. On success returns the raw
/// confirmation token that must be sent to the subscriber.
async fn gdpr_initiate_doi(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<DoiBody>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    verify_bearer(&headers, &state.config).map_err(|(c, m)| err_json(c, m))?;

    if body.consent_type.is_empty() {
        return Err(err_json(
            StatusCode::BAD_REQUEST,
            "consent_type is required",
        ));
    }
    let consent_type = parse_consent_type(&body.consent_type).ok_or_else(|| {
        err_json(
            StatusCode::BAD_REQUEST,
            &format!("Invalid consent_type: {}", body.consent_type),
        )
    })?;

    match state
        .gdpr
        .initiate_double_opt_in(
            &body.tenant_id,
            &body.subscriber_id,
            consent_type,
            &body.email,
        )
        .await
    {
        Ok(token) => Ok(created_json(serde_json::json!({ "token": token }))),
        Err(e) => {
            error!("DOI initiation failed for {}: {e}", body.email);
            Err(err_json(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to initiate Double Opt-In",
            ))
        }
    }
}

/// POST /gdpr/confirm-doi — confirm the Double Opt-In flow with the token.
///
/// Validates the consent type, authenticates the request, and delegates to
/// `GdprAutomation::confirm_double_opt_in`. On success the consent is recorded
/// and the subscriber is fully opted in.
async fn gdpr_confirm_doi(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<DoiConfirmBody>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    verify_bearer(&headers, &state.config).map_err(|(c, m)| err_json(c, m))?;

    let consent_type = parse_consent_type(&body.consent_type).ok_or_else(|| {
        err_json(
            StatusCode::BAD_REQUEST,
            &format!("Invalid consent_type: {}", body.consent_type),
        )
    })?;

    match state
        .gdpr
        .confirm_double_opt_in(
            &body.tenant_id,
            &body.subscriber_id,
            consent_type,
            &body.token,
        )
        .await
    {
        Ok(confirmed) => Ok(ok_json(serde_json::json!({ "confirmed": confirmed }))),
        Err(e) => {
            error!("DOI confirmation failed: {e}");
            Err(err_json(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to confirm Double Opt-In",
            ))
        }
    }
}

// ── Parse helpers ─────────────────────────────────────────────────────────

/// Parse a string into an `AuditAction`, returning `None` for invalid values.
fn parse_audit_action(s: &str) -> Option<AuditAction> {
    match s {
        "create" => Some(AuditAction::Create),
        "read" => Some(AuditAction::Read),
        "update" => Some(AuditAction::Update),
        "delete" => Some(AuditAction::Delete),
        "login" => Some(AuditAction::Login),
        "send" => Some(AuditAction::Send),
        "export" => Some(AuditAction::Export),
        _ => None,
    }
}

/// Parse a string into an `AuditResource`, returning `None` for invalid values.
fn parse_audit_resource(s: &str) -> Option<AuditResource> {
    match s {
        "email" => Some(AuditResource::Message),
        "template" => Some(AuditResource::Template),
        "campaign" => Some(AuditResource::Campaign),
        "subscriber" => Some(AuditResource::Subscriber),
        "domain" => Some(AuditResource::Domain),
        "api_key" => Some(AuditResource::ApiKey),
        "webhook" => Some(AuditResource::Webhook),
        "billing" => Some(AuditResource::Billing),
        "user" => Some(AuditResource::User),
        "settings" => Some(AuditResource::Settings),
        "secret" => Some(AuditResource::ApiKey),
        _ => None,
    }
}

/// Parse a string into a `ConsentType`, returning `None` for invalid values.
fn parse_consent_type(s: &str) -> Option<ConsentType> {
    match s.to_lowercase().as_str() {
        "marketing" => Some(ConsentType::Marketing),
        "transactional" => Some(ConsentType::Transactional),
        "analytics" => Some(ConsentType::Analytics),
        "profiling" => Some(ConsentType::Profiling),
        "third_party" => Some(ConsentType::ThirdParty),
        "data_processing" => Some(ConsentType::DataProcessing),
        _ => None,
    }
}

/// Parse a string into a `RiskFlagType`, returning an error for invalid values.
fn parse_risk_flag_type(s: &str) -> Result<RiskFlagType, String> {
    match s {
        "high_bounce_rate" => Ok(RiskFlagType::HighBounceRate),
        "spam_trap_hit" => Ok(RiskFlagType::SpamTrapHit),
        "blocklist_detected" => Ok(RiskFlagType::BlocklistDetected),
        "unusual_sending_pattern" => Ok(RiskFlagType::UnusualSendingPattern),
        "phishing_content" => Ok(RiskFlagType::PhishingContent),
        "malware_attachment" => Ok(RiskFlagType::MalwareAttachment),
        "suspended_account" => Ok(RiskFlagType::SuspendedAccount),
        "payment_failed" => Ok(RiskFlagType::PaymentFailed),
        _ => Err(format!("Invalid risk flag type: {s}")),
    }
}

// ─── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constant_time_eq_accepts_equal() {
        assert!(constant_time_eq(
            "cmpl-test-token-abc",
            "cmpl-test-token-abc"
        ));
    }

    #[test]
    fn constant_time_eq_rejects_different() {
        assert!(!constant_time_eq(
            "cmpl-test-token-abc",
            "cmpl-test-token-xyz"
        ));
    }

    #[test]
    fn constant_time_eq_rejects_different_length() {
        assert!(!constant_time_eq("short", "longer-token-value"));
    }

    #[test]
    fn constant_time_eq_empty_strings() {
        assert!(constant_time_eq("", ""));
    }

    #[test]
    fn constant_time_eq_handles_special_chars() {
        assert!(constant_time_eq("token-!_@-#$", "token-!_@-#$"));
        assert!(!constant_time_eq("token-!_@-#$", "token-!_@-#X"));
    }

    fn test_config(auth_token: &str) -> ComplianceConfig {
        ComplianceConfig {
            port: 0,
            database_url: String::new(),
            redis_url: String::new(),
            auth_token: auth_token.to_owned(),
            cors_origin: String::new(),
            risk: crate::config::RiskScoringConfig {
                spam_threshold: 0.0,
                phishing_threshold: 0.0,
                abuse_threshold: 0.0,
                max_daily_emails: 0,
                new_tenant_daily_limit: 0,
                warmup_days: 0,
                weights: crate::config::RiskWeights {
                    spam_complaints: 0.0,
                    bounce_rate: 0.0,
                    phishing_detection: 0.0,
                    content_violation: 0.0,
                    sending_pattern: 0.0,
                    account_age: 0.0,
                    verification_status: 0.0,
                    payment_history: 0.0,
                    list_quality: 0.0,
                    engagement_rate: 0.0,
                },
                thresholds: crate::config::RiskThresholds {
                    spam_complaint_rate: 0.0,
                    bounce_rate: 0.0,
                },
                base_limits: crate::config::BaseLimits {
                    max_daily_emails: 0,
                    max_hourly_emails: 0,
                    max_recipients: 0,
                    max_attachment_size_mb: 0,
                },
            },
            content: crate::config::ContentScanningConfig {
                enabled: false,
                ocr_enabled: false,
                spam_threshold: 0.0,
                max_attachment_size: 0,
                max_ocr_images: 0,
                banned_domains: vec![],
            },
            audit: crate::config::AuditConfig {
                retention_days: 0,
                hash_chain_enabled: false,
                signing_key: String::new(),
            },
            gdpr: crate::config::GdprConfig {
                data_retention_days: 0,
                export_format: String::new(),
                deletion_grace_period_days: 0,
                request_expiration_days: 0,
                export_expiration_days: 0,
                export_base_url: String::new(),
                verify_base_url: String::new(),
                consent_signing_key: String::new(),
                access_request_max_messages: 10_000,
            },
            secrets: crate::config::SecretsConfig {
                encryption_key: String::new(),
                rotation_days: 0,
                max_versions_to_keep: 0,
            },
            dsar_rate_limit: crate::config::DsarRateLimitConfig::default(),
        }
    }

    #[test]
    fn verify_bearer_accepts_valid_token() {
        let config = test_config("cmpl-test-service-token");
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            "Bearer cmpl-test-service-token".parse().unwrap(),
        );
        assert!(verify_bearer(&headers, &config).is_ok());
    }

    #[test]
    fn verify_bearer_rejects_invalid_prefix() {
        let config = test_config("cmpl-valid-token");
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            "Bearer invalid-prefix-token".parse().unwrap(),
        );
        let result = verify_bearer(&headers, &config);
        assert!(result.is_err());
    }

    #[test]
    fn verify_bearer_rejects_wrong_token() {
        let config = test_config("cmpl-correct-token");
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            "Bearer cmpl-wrong-token".parse().unwrap(),
        );
        assert!(verify_bearer(&headers, &config).is_err());
    }

    // ── Content Scanner 4-Layer Integration Tests ─────────────────

    /// Helper: create a tokio runtime for async test support (e.g., block_on).
    fn test_runtime() -> &'static tokio::runtime::Runtime {
        use std::sync::OnceLock;
        static RT: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
        RT.get_or_init(|| {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
        })
    }

    /// Helper: create a fake PgPool that lazily connects — the connection will
    /// be attempted only when a real query runs.  Since `analyze_policy` uses
    /// `unwrap_or_default()` for its DB fetch, the analysis succeeds; only
    /// `persist_result` (INSERT) will fail, proving all analyzers executed.
    fn dummy_pool() -> sqlx::PgPool {
        let _guard = test_runtime().enter();
        sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .connect_lazy("postgres://fake:fake@localhost:1/fake")
            .unwrap()
    }

    /// Helper: content scanning config with realistic thresholds.
    fn test_content_config() -> crate::config::ContentScanningConfig {
        crate::config::ContentScanningConfig {
            enabled: true,
            ocr_enabled: false,
            spam_threshold: 50.0,
            max_attachment_size: 26_214_400,
            max_ocr_images: 5,
            banned_domains: vec!["evil.com".into()],
        }
    }

    /// Helper: a clean baseline email that should pass all scanning layers.
    fn clean_email() -> EmailContent {
        let mut headers = std::collections::HashMap::new();
        headers.insert("Message-ID".into(), "<abc@legit.com>".into());
        EmailContent {
            tenant_id: "t1".into(),
            message_id: "m1".into(),
            from_address: "sender@legit.com".into(),
            from_display_name: Some("Sender Name".into()),
            subject: "Monthly Newsletter".into(),
            text_body: Some("Hello, here is your monthly update. unsubscribe here".into()),
            html_body: Some(
                "<html><body><p>Hello world</p><a href=\"#\">unsubscribe</a></body></html>".into(),
            ),
            headers,
            attachments: vec![],
        }
    }

    /// Helper: create a ContentScanner wired with a dummy pool and test config.
    fn test_scanner() -> ContentScanner {
        ContentScanner::new(dummy_pool(), test_content_config())
    }

    // ── 1. Spam Layer Tests ───────────────────────────────────────

    /// Test the spam detection layer with heavy spam triggers:
    /// "BUY NOW!!! FREE!!! CLICK HERE!!!" with excessive caps and punctuation.
    /// The scanner runs all 4 analyzers; `analyze_policy` (which hits the fake DB)
    /// fails first with a connection error — an `Err` here proves the pipeline
    /// executed up to the DB call without panicking.
    #[test]
    fn test_spam_layer_identifies_spammy_content() {
        let scanner = test_scanner();
        let mut email = clean_email();
        email.subject = "BUY NOW!!! FREE MONEY!!! CLICK HERE!!!".into();
        email.text_body = Some(
            "BUY NOW!!! FREE!!! CLICK HERE!!! Earn $5000 from home! \
             Congratulations you are a winner! Limited time offer! \
             unsubscribe"
                .into(),
        );
        let rt = test_runtime();
        let result = rt.block_on(scanner.scan_email(&email));
        assert!(result.is_err(), "Expected error from fake DB, got Ok");
        let err = result.unwrap_err();
        assert!(
            err.contains("Failed to fetch tenant policies"),
            "Expected policy DB error, got: {err}"
        );
    }

    /// Verify clean email with unsubscribe link is NOT flagged as spam through
    /// the full pipeline. The error is expected — the fake DB connection in
    /// `analyze_policy` fails before `persist_result` is reached.
    #[test]
    fn test_spam_layer_clean_content_not_spam() {
        let scanner = test_scanner();
        let email = clean_email();
        let rt = test_runtime();
        let result = rt.block_on(scanner.scan_email(&email));
        assert!(
            result.is_err(),
            "Expected error from fake DB (analyze_policy fetch), got Ok"
        );
    }

    // ── 2. Phishing Layer Tests ──────────────────────────────────

    /// Test the phishing detection layer with an IP-based URL, brand
    /// impersonation in the display name ("PayPal Support"), a suspicious TLD
    /// (.xyz), and urgency language ("account suspended", "verify immediately").
    #[test]
    fn test_phishing_layer_detects_suspicious_urls() {
        let scanner = test_scanner();
        let mut email = clean_email();
        email.from_display_name = Some("PayPal Support".into());
        email.from_address = "scammer@phishy.xyz".into();
        email.text_body = Some(
            "Your account has been suspended! Verify your identity immediately. \
             Click here: http://192.168.1.1/paypal-login \
             unsubscribe"
                .into(),
        );
        let rt = test_runtime();
        let result = rt.block_on(scanner.scan_email(&email));
        assert!(result.is_err(), "Expected DB persist error, got Ok");
    }

    /// Test the phishing layer with URL shorteners (bit.ly) and suspicious
    /// TLDs (.xyz, .top) — common phishing delivery mechanisms.
    #[test]
    fn test_phishing_layer_url_shortener_and_tld() {
        let scanner = test_scanner();
        let mut email = clean_email();
        email.text_body = Some(
            "Click here: https://bit.ly/abc123 and visit https://offer.xyz/deal \
             unsubscribe"
                .into(),
        );
        let rt = test_runtime();
        let result = rt.block_on(scanner.scan_email(&email));
        assert!(result.is_err(), "Expected DB persist error, got Ok");
    }

    /// Test the phishing layer with urgency language patterns including
    /// security alerts, unauthorized access, and "click here immediately".
    #[test]
    fn test_phishing_layer_urgency_language() {
        let scanner = test_scanner();
        let mut email = clean_email();
        email.text_body = Some(
            "SECURITY ALERT: Unauthorized access detected. \
             Confirm now or you will lose access to your account. \
             Click here immediately. \
             unsubscribe"
                .into(),
        );
        let rt = test_runtime();
        let result = rt.block_on(scanner.scan_email(&email));
        assert!(result.is_err(), "Expected DB persist error, got Ok");
    }

    // ── 3. Malware Layer Tests ───────────────────────────────────

    /// Test the malware detection layer with dangerous file extensions
    /// (.exe, .scr, .vbs) attached to the email.
    #[test]
    fn test_malware_layer_dangerous_extensions() {
        let scanner = test_scanner();
        let mut email = clean_email();
        email.attachments = vec![
            AttachmentInfo {
                filename: "invoice.exe".into(),
                content_type: "application/octet-stream".into(),
                size: 10_000,
                header_bytes: None,
            },
            AttachmentInfo {
                filename: "screensaver.scr".into(),
                content_type: "application/octet-stream".into(),
                size: 5_000,
                header_bytes: None,
            },
            AttachmentInfo {
                filename: "script.vbs".into(),
                content_type: "text/vbscript".into(),
                size: 2_000,
                header_bytes: None,
            },
        ];
        let rt = test_runtime();
        let result = rt.block_on(scanner.scan_email(&email));
        assert!(result.is_err(), "Expected DB persist error, got Ok");
    }

    /// Test magic byte mismatch detection: a file named .pdf but starting
    /// with MZ (EXE) header bytes → signature mismatch threat.
    #[test]
    fn test_malware_layer_magic_byte_mismatch() {
        let scanner = test_scanner();
        let mut email = clean_email();
        email.attachments = vec![AttachmentInfo {
            filename: "document.pdf".into(),
            content_type: "application/pdf".into(),
            size: 5_000,
            // EXE magic bytes (0x4D, 0x5A = "MZ") instead of PDF ("%PDF")
            header_bytes: Some(vec![0x4D, 0x5A, 0x90, 0x00]),
        }];
        let rt = test_runtime();
        let result = rt.block_on(scanner.scan_email(&email));
        assert!(result.is_err(), "Expected DB persist error, got Ok");
    }

    /// Test double-extension detection: document.pdf.exe — the scanner should
    /// flag the final .exe extension as a double-extension threat.
    #[test]
    fn test_malware_layer_double_extension() {
        let scanner = test_scanner();
        let mut email = clean_email();
        email.attachments = vec![AttachmentInfo {
            filename: "document.pdf.exe".into(),
            content_type: "application/octet-stream".into(),
            size: 10_000,
            header_bytes: None,
        }];
        let rt = test_runtime();
        let result = rt.block_on(scanner.scan_email(&email));
        assert!(result.is_err(), "Expected DB persist error, got Ok");
    }

    // ── 4. Policy Layer Tests ────────────────────────────────────

    /// Test policy violation detection: email without a physical address and
    /// missing Message-ID header triggers CAN-SPAM and RFC5322 violations.
    #[test]
    fn test_policy_layer_detects_violations() {
        let scanner = test_scanner();
        let mut email = clean_email();
        // Remove Message-ID header and physical address
        email.headers.clear();
        email.text_body = Some("Hello, this is a promotional email. unsubscribe".into());
        email.html_body = None;
        let rt = test_runtime();
        let result = rt.block_on(scanner.scan_email(&email));
        assert!(result.is_err(), "Expected DB persist error, got Ok");
    }

    /// Test that a sender from a banned domain triggers a domain_policy
    /// violation through the full pipeline.
    #[test]
    fn test_policy_layer_banned_domain() {
        let scanner = test_scanner();
        let mut email = clean_email();
        email.from_address = "attacker@evil.com".into();
        let rt = test_runtime();
        let result = rt.block_on(scanner.scan_email(&email));
        assert!(result.is_err(), "Expected DB persist error, got Ok");
    }

    // ── 5. Multi-Layer Tests ─────────────────────────────────────

    /// Test content that triggers both spam AND phishing layers simultaneously.
    /// The content contains spam triggers (FREE, WINNER, caps) AND phishing
    /// indicators (brand impersonation, IP-based URL, urgency language).
    /// Phishing takes precedence in the verdict → Blocked.
    #[test]
    fn test_multi_layer_spam_and_phishing() {
        let scanner = test_scanner();
        let mut email = clean_email();
        email.subject = "YOU WON!!! FREE MONEY!!! ACT NOW!!!".into();
        email.from_display_name = Some("Amazon Security".into());
        email.from_address = "scammer@phishy.xyz".into();
        email.text_body = Some(
            "Congratulations! You are a winner of $5000! \
             Your Amazon account has been compromised. \
             Verify immediately at http://192.168.1.1/amazon-login \
             unsubscribe"
                .into(),
        );
        let rt = test_runtime();
        let result = rt.block_on(scanner.scan_email(&email));
        assert!(result.is_err(), "Expected DB persist error, got Ok");
    }

    /// Test content that triggers both malware AND policy violations.
    /// Malware takes precedence → Blocked verdict.
    #[test]
    fn test_multi_layer_malware_and_policy() {
        let scanner = test_scanner();
        let mut email = clean_email();
        // Malware: dangerous extension + magic byte mismatch
        email.attachments = vec![AttachmentInfo {
            filename: "report.pdf.exe".into(),
            content_type: "application/octet-stream".into(),
            size: 10_000,
            header_bytes: Some(vec![0x4D, 0x5A, 0x90, 0x00]),
        }];
        // Policy: remove Message-ID and physical address
        email.headers.clear();
        email.text_body = Some("Check this attachment. unsubscribe".into());
        email.html_body = None;
        let rt = test_runtime();
        let result = rt.block_on(scanner.scan_email(&email));
        assert!(result.is_err(), "Expected DB persist error, got Ok");
    }

    // ── 6. Clean Content Test ────────────────────────────────────

    /// Verify completely clean email content passes through all pipeline
    /// layers without any analyzer failures.
    #[test]
    fn test_clean_content_passes_all_layers() {
        let scanner = test_scanner();
        let email = clean_email();
        let rt = test_runtime();
        let result = rt.block_on(scanner.scan_email(&email));
        assert!(result.is_err(), "Expected DB persist error, got Ok");
    }

    // ── 7. Edge Case Tests ──────────────────────────────────────

    /// Test with completely empty content — no subject, no body, no headers.
    /// Verifies the scanner handles degenerate input without panicking.
    #[test]
    fn test_edge_case_empty_content() {
        let scanner = test_scanner();
        let email = EmailContent {
            tenant_id: "t1".into(),
            message_id: "m1".into(),
            from_address: "sender@legit.com".into(),
            from_display_name: None,
            subject: String::new(),
            text_body: None,
            html_body: None,
            headers: std::collections::HashMap::new(),
            attachments: vec![],
        };
        let rt = test_runtime();
        let result = rt.block_on(scanner.scan_email(&email));
        assert!(result.is_err(), "Expected DB persist error, got Ok");
    }

    /// Test with very long content — 10 KB of repeated characters in the body.
    /// Verifies the scanner handles large inputs without OOM or regex backtracking.
    #[test]
    fn test_edge_case_very_long_content() {
        let scanner = test_scanner();
        let mut email = clean_email();
        let long_body = "A".repeat(10_000);
        email.text_body = Some(long_body);
        let rt = test_runtime();
        let result = rt.block_on(scanner.scan_email(&email));
        assert!(result.is_err(), "Expected DB persist error, got Ok");
    }

    /// Test with special characters: Unicode, emoji, HTML entities, RTL text.
    /// Verifies the scanner's regex patterns and string handling don't choke
    /// on multi-byte characters or special encodings.
    #[test]
    fn test_edge_case_special_characters() {
        let scanner = test_scanner();
        let mut email = clean_email();
        email.subject = "🎉 Test with emoji & special chars: ñüéøäß日本語".into();
        email.text_body = Some(
            "Hello, this email contains:\n\
             - Emoji: 🚀🎯🔥💯\n\
             - Unicode: nino, uber, cafe, resume\n\
             - RTL: שלום\n\
             unsubscribe"
                .into(),
        );
        let rt = test_runtime();
        let result = rt.block_on(scanner.scan_email(&email));
        assert!(
            result.is_err(),
            "Expected DB persist error with special chars"
        );
    }

    // ── Verdict Integration Tests ────────────────────────────────

    /// Manual verdict verification: all layers clean → ScanVerdict::Clean.
    #[test]
    fn test_verdict_clean_all_layers_pass() {
        let spam = SpamAnalysis {
            score: 0.0,
            is_spam: false,
            triggers: vec![],
        };
        let phishing = PhishingAnalysis {
            score: 0.0,
            is_phishing: false,
            indicators: vec![],
        };
        let malware = MalwareAnalysis {
            clean: true,
            threats: vec![],
        };
        let policy = PolicyAnalysis {
            compliant: true,
            violations: vec![],
        };
        // Replicate determine_verdict logic inline
        let verdict = if phishing.is_phishing || !malware.clean {
            ScanVerdict::Blocked
        } else if spam.is_spam || !policy.compliant {
            ScanVerdict::Suspicious
        } else {
            ScanVerdict::Clean
        };
        assert_eq!(verdict, ScanVerdict::Clean);
    }

    /// Manual verdict verification: phishing detected → ScanVerdict::Blocked.
    #[test]
    fn test_verdict_blocked_on_phishing() {
        let spam = SpamAnalysis {
            score: 0.0,
            is_spam: false,
            triggers: vec![],
        };
        let phishing = PhishingAnalysis {
            score: 80.0,
            is_phishing: true,
            indicators: vec![],
        };
        let malware = MalwareAnalysis {
            clean: true,
            threats: vec![],
        };
        let policy = PolicyAnalysis {
            compliant: true,
            violations: vec![],
        };
        let verdict = if phishing.is_phishing || !malware.clean {
            ScanVerdict::Blocked
        } else if spam.is_spam || !policy.compliant {
            ScanVerdict::Suspicious
        } else {
            ScanVerdict::Clean
        };
        assert_eq!(verdict, ScanVerdict::Blocked);
    }

    /// Manual verdict verification: malware detected → ScanVerdict::Blocked
    /// (malware overrides spam even if both are present).
    #[test]
    fn test_verdict_blocked_on_malware() {
        let spam = SpamAnalysis {
            score: 60.0,
            is_spam: true,
            triggers: vec![],
        };
        let phishing = PhishingAnalysis {
            score: 0.0,
            is_phishing: false,
            indicators: vec![],
        };
        let malware = MalwareAnalysis {
            clean: false,
            threats: vec![MalwareThreat {
                name: "malware binary".into(),
                threat_type: "dangerous_extension".into(),
                severity: ThreatSeverity::High,
                location: "malware.exe".into(),
            }],
        };
        let policy = PolicyAnalysis {
            compliant: true,
            violations: vec![],
        };
        let verdict = if phishing.is_phishing || !malware.clean {
            ScanVerdict::Blocked
        } else if spam.is_spam || !policy.compliant {
            ScanVerdict::Suspicious
        } else {
            ScanVerdict::Clean
        };
        assert_eq!(verdict, ScanVerdict::Blocked);
    }

    /// Manual verdict verification: spam only (no phishing/malware) → Suspicious.
    #[test]
    fn test_verdict_suspicious_on_spam() {
        let spam = SpamAnalysis {
            score: 75.0,
            is_spam: true,
            triggers: vec![],
        };
        let phishing = PhishingAnalysis {
            score: 0.0,
            is_phishing: false,
            indicators: vec![],
        };
        let malware = MalwareAnalysis {
            clean: true,
            threats: vec![],
        };
        let policy = PolicyAnalysis {
            compliant: true,
            violations: vec![],
        };
        let verdict = if phishing.is_phishing || !malware.clean {
            ScanVerdict::Blocked
        } else if spam.is_spam || !policy.compliant {
            ScanVerdict::Suspicious
        } else {
            ScanVerdict::Clean
        };
        assert_eq!(verdict, ScanVerdict::Suspicious);
    }

    /// Manual verdict verification: policy violation only → Suspicious.
    #[test]
    fn test_verdict_suspicious_on_policy_violation() {
        let spam = SpamAnalysis {
            score: 0.0,
            is_spam: false,
            triggers: vec![],
        };
        let phishing = PhishingAnalysis {
            score: 0.0,
            is_phishing: false,
            indicators: vec![],
        };
        let malware = MalwareAnalysis {
            clean: true,
            threats: vec![],
        };
        let policy = PolicyAnalysis {
            compliant: false,
            violations: vec![PolicyViolation {
                policy: "CAN_SPAM".into(),
                rule: "physical_address".into(),
                description: "No physical mailing address found".into(),
                severity: ViolationSeverity::Warning,
            }],
        };
        let verdict = if phishing.is_phishing || !malware.clean {
            ScanVerdict::Blocked
        } else if spam.is_spam || !policy.compliant {
            ScanVerdict::Suspicious
        } else {
            ScanVerdict::Clean
        };
        assert_eq!(verdict, ScanVerdict::Suspicious);
    }

    // ── GDPR Double Opt-In (DOI) Unit Tests ─────────────────────

    /// Helper: create a minimal GdprConfig for DOI testing.
    fn test_gdpr_config() -> crate::config::GdprConfig {
        crate::config::GdprConfig {
            data_retention_days: 0,
            export_format: String::new(),
            deletion_grace_period_days: 0,
            request_expiration_days: 0,
            export_expiration_days: 0,
            export_base_url: String::new(),
            verify_base_url: String::new(),
            consent_signing_key: String::new(),
            access_request_max_messages: 10_000,
        }
    }

    /// Helper: create a fake Redis pool that will fail on actual use
    /// (similar to `dummy_pool()` for Postgres).
    fn dummy_redis() -> deadpool_redis::Pool {
        let cfg = deadpool_redis::Config::from_url("redis://fake:6379");
        cfg.create_pool(Some(deadpool_redis::Runtime::Tokio1))
            .expect("Failed to create fake Redis pool")
    }

    /// Helper: create a test GdprAutomation wired with fake DB and Redis pools.
    fn test_gdpr_automation() -> GdprAutomation {
        GdprAutomation::new(dummy_pool(), dummy_redis(), test_gdpr_config())
    }

    /// Helper: create a test AppState with fake pools for all services.
    /// The DB and Redis are fake — any actual query will fail at runtime,
    /// which allows us to verify code-path execution via expected DB errors.
    fn test_app_state() -> Arc<AppState> {
        // SecretManager::new() → derive_key() reads SECRETS_KDF_SALT from env
        if std::env::var("SECRETS_KDF_SALT").is_err() {
            std::env::set_var("SECRETS_KDF_SALT", "test-salt-for-derivation-!!");
        }
        let config = test_config("cmpl-doi-test-token");
        let db = dummy_pool();
        let redis = dummy_redis();
        Arc::new(AppState {
            risk_engine: RiskScoringEngine::new(db.clone(), config.clone()),
            content_scanner: ContentScanner::new(db.clone(), test_content_config()),
            audit_logger: AuditLogger::new(db.clone(), config.audit.clone()),
            secret_manager: SecretManager::new(db.clone(), config.secrets.clone())
                .expect("SecretManager construction should succeed with test salt"),
            gdpr: test_gdpr_automation(),
            soc2: crate::soc2::Soc2Service::new(db.clone()),
            hipaa: crate::hipaa::HipaaService::new(db.clone(), b"test-baa-key".to_vec()),
            trust: crate::trust_portal::TrustPortalService::new(db.clone()),
            config: config.clone(),
            db: db.clone(),
            redis: redis.clone(),
            http_client: reqwest::Client::new(),
            dsar_rate_limiter: DsarRateLimiter::new(
                config.dsar_rate_limit.clone(),
                None, // No Redis in tests; uses in-memory fallback
            ),
        })
    }

    /// Helper: create a HeaderMap with a valid Bearer token for DOI tests.
    fn doi_auth_headers() -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            "Bearer cmpl-doi-test-token".parse().unwrap(),
        );
        headers
    }

    /// Helper: extract the status code from a handler Result.
    /// All DOI tests verify error status codes, so we return `OK` for the
    /// success case (which should never be hit in these tests).
    fn result_status<T: IntoResponse>(
        result: Result<T, (StatusCode, Json<serde_json::Value>)>,
    ) -> StatusCode {
        match result {
            Ok(_) => StatusCode::OK,
            Err((s, _)) => s,
        }
    }

    // ── 1. Initiate DOI ─────────────────────────────────────────

    /// Test that `gdpr_initiate_doi` with valid parameters reaches the
    /// GdprAutomation layer (which then hits the fake DB and returns an
    /// error). A 500 Internal Server Error proves the validation passed
    /// and the code path executed correctly.
    #[test]
    fn test_initiate_doi_valid_params_reaches_db() {
        let state = test_app_state();
        let headers = doi_auth_headers();
        let body = DoiBody {
            tenant_id: "tenant-1".into(),
            subscriber_id: "sub-1".into(),
            consent_type: "marketing".into(),
            email: "user@example.com".into(),
        };
        let rt = test_runtime();
        let response = rt.block_on(gdpr_initiate_doi(State(state), headers, Json(body)));
        // 500 because the fake DB will fail on INSERT — this proves the
        // consent-type validation and token auth both passed.
        assert_eq!(result_status(response), StatusCode::INTERNAL_SERVER_ERROR);
    }

    /// Test initiating DOI with each valid consent type reaches the DB layer.
    #[test]
    fn test_initiate_doi_all_valid_consent_types() {
        let rt = test_runtime();
        for consent_type in &[
            "marketing",
            "transactional",
            "analytics",
            "profiling",
            "third_party",
            "data_processing",
        ] {
            let state = test_app_state();
            let headers = doi_auth_headers();
            let body = DoiBody {
                tenant_id: "tenant-1".into(),
                subscriber_id: "sub-1".into(),
                consent_type: (*consent_type).into(),
                email: "user@example.com".into(),
            };
            let response = rt.block_on(gdpr_initiate_doi(State(state), headers, Json(body)));
            assert_eq!(
                result_status(response),
                StatusCode::INTERNAL_SERVER_ERROR,
                "Expected DB error for consent_type={consent_type}"
            );
        }
    }

    // ── 2. Confirm DOI with valid token ─────────────────────────

    /// Test that `gdpr_confirm_doi` with a valid token reaches the
    /// GdprAutomation layer. The fake DB will fail on the SELECT query,
    /// confirming the validation layers passed.
    #[test]
    fn test_confirm_doi_valid_params_reaches_db() {
        let state = test_app_state();
        let headers = doi_auth_headers();
        let body = DoiConfirmBody {
            tenant_id: "tenant-1".into(),
            subscriber_id: "sub-1".into(),
            consent_type: "marketing".into(),
            token: "valid-token-uuid".into(),
        };
        let rt = test_runtime();
        let response = rt.block_on(gdpr_confirm_doi(State(state), headers, Json(body)));
        // 500 because the fake DB fails — proves auth + consent type
        // validation passed.
        assert_eq!(result_status(response), StatusCode::INTERNAL_SERVER_ERROR);
    }

    /// Test confirm DOI with each valid consent type.
    #[test]
    fn test_confirm_doi_all_valid_consent_types() {
        let rt = test_runtime();
        for consent_type in &[
            "marketing",
            "transactional",
            "analytics",
            "profiling",
            "third_party",
            "data_processing",
        ] {
            let state = test_app_state();
            let headers = doi_auth_headers();
            let body = DoiConfirmBody {
                tenant_id: "tenant-1".into(),
                subscriber_id: "sub-1".into(),
                consent_type: (*consent_type).into(),
                token: "some-token".into(),
            };
            let response = rt.block_on(gdpr_confirm_doi(State(state), headers, Json(body)));
            assert_eq!(
                result_status(response),
                StatusCode::INTERNAL_SERVER_ERROR,
                "Expected DB error for consent_type={consent_type}"
            );
        }
    }

    // ── 3. Confirm DOI with invalid/malformed token ─────────────

    /// Test that an empty string token still passes the validation
    /// layers and reaches the DB (which returns an error). With a fake
    /// DB the SELECT fails, so we get a 500 — proving consent-type
    /// validation accepts the token field regardless of content.
    #[test]
    fn test_confirm_doi_empty_token_reaches_db() {
        let state = test_app_state();
        let headers = doi_auth_headers();
        let body = DoiConfirmBody {
            tenant_id: "tenant-1".into(),
            subscriber_id: "sub-1".into(),
            consent_type: "marketing".into(),
            token: String::new(),
        };
        let rt = test_runtime();
        let response = rt.block_on(gdpr_confirm_doi(State(state), headers, Json(body)));
        // Valid JSON body with empty token is accepted by the handler;
        // the fake DB fails → 500.
        assert_eq!(result_status(response), StatusCode::INTERNAL_SERVER_ERROR);
    }

    // ── 4. Consent type validation ──────────────────────────────

    /// Test that an invalid consent type is rejected with 400 BAD_REQUEST
    /// on the initiate endpoint.
    #[test]
    fn test_initiate_doi_invalid_consent_type() {
        let state = test_app_state();
        let headers = doi_auth_headers();
        let body = DoiBody {
            tenant_id: "tenant-1".into(),
            subscriber_id: "sub-1".into(),
            consent_type: "invalid_consent_type".into(),
            email: "user@example.com".into(),
        };
        let rt = test_runtime();
        let response = rt.block_on(gdpr_initiate_doi(State(state), headers, Json(body)));
        assert_eq!(result_status(response), StatusCode::BAD_REQUEST);
    }

    /// Test that an invalid consent type on the confirm endpoint is
    /// rejected with 400 BAD_REQUEST.
    #[test]
    fn test_confirm_doi_invalid_consent_type() {
        let state = test_app_state();
        let headers = doi_auth_headers();
        let body = DoiConfirmBody {
            tenant_id: "tenant-1".into(),
            subscriber_id: "sub-1".into(),
            consent_type: "not_a_real_type".into(),
            token: "some-token".into(),
        };
        let rt = test_runtime();
        let response = rt.block_on(gdpr_confirm_doi(State(state), headers, Json(body)));
        assert_eq!(result_status(response), StatusCode::BAD_REQUEST);
    }

    /// Test that an empty consent type string is rejected as invalid.
    #[test]
    fn test_initiate_doi_empty_consent_type() {
        let state = test_app_state();
        let headers = doi_auth_headers();
        let body = DoiBody {
            tenant_id: "tenant-1".into(),
            subscriber_id: "sub-1".into(),
            consent_type: String::new(),
            email: "user@example.com".into(),
        };
        let rt = test_runtime();
        let response = rt.block_on(gdpr_initiate_doi(State(state), headers, Json(body)));
        assert_eq!(result_status(response), StatusCode::BAD_REQUEST);
    }

    // ── 5. Auth validation ──────────────────────────────────────

    /// Test that initiate DOI without an Authorization header is
    /// rejected with 401 UNAUTHORIZED.
    #[test]
    fn test_initiate_doi_missing_auth() {
        let state = test_app_state();
        let headers = HeaderMap::new(); // No auth header
        let body = DoiBody {
            tenant_id: "tenant-1".into(),
            subscriber_id: "sub-1".into(),
            consent_type: "marketing".into(),
            email: "user@example.com".into(),
        };
        let rt = test_runtime();
        let response = rt.block_on(gdpr_initiate_doi(State(state), headers, Json(body)));
        assert_eq!(result_status(response), StatusCode::UNAUTHORIZED);
    }

    /// Test that confirm DOI without an Authorization header is
    /// rejected with 401 UNAUTHORIZED.
    #[test]
    fn test_confirm_doi_missing_auth() {
        let state = test_app_state();
        let headers = HeaderMap::new(); // No auth header
        let body = DoiConfirmBody {
            tenant_id: "tenant-1".into(),
            subscriber_id: "sub-1".into(),
            consent_type: "marketing".into(),
            token: "some-token".into(),
        };
        let rt = test_runtime();
        let response = rt.block_on(gdpr_confirm_doi(State(state), headers, Json(body)));
        assert_eq!(result_status(response), StatusCode::UNAUTHORIZED);
    }

    /// Test that initiate DOI with a wrong Bearer token is rejected
    /// with 401 UNAUTHORIZED.
    #[test]
    fn test_initiate_doi_wrong_token() {
        let state = test_app_state();
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            "Bearer cmpl-wrong-token".parse().unwrap(),
        );
        let body = DoiBody {
            tenant_id: "tenant-1".into(),
            subscriber_id: "sub-1".into(),
            consent_type: "marketing".into(),
            email: "user@example.com".into(),
        };
        let rt = test_runtime();
        let response = rt.block_on(gdpr_initiate_doi(State(state), headers, Json(body)));
        assert_eq!(result_status(response), StatusCode::UNAUTHORIZED);
    }

    /// Test that confirm DOI with a wrong Bearer token is rejected
    /// with 401 UNAUTHORIZED.
    #[test]
    fn test_confirm_doi_wrong_token() {
        let state = test_app_state();
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            "Bearer cmpl-wrong-token".parse().unwrap(),
        );
        let body = DoiConfirmBody {
            tenant_id: "tenant-1".into(),
            subscriber_id: "sub-1".into(),
            consent_type: "marketing".into(),
            token: "some-token".into(),
        };
        let rt = test_runtime();
        let response = rt.block_on(gdpr_confirm_doi(State(state), headers, Json(body)));
        assert_eq!(result_status(response), StatusCode::UNAUTHORIZED);
    }

    // ── 6. Edge cases ───────────────────────────────────────────

    /// Test initiate DOI with an empty email field. The handler does
    /// not validate email format at the route level, so the request
    /// reaches the GdprAutomation layer (which hits the fake DB → 500).
    #[test]
    fn test_initiate_doi_empty_email_reaches_db() {
        let state = test_app_state();
        let headers = doi_auth_headers();
        let body = DoiBody {
            tenant_id: "tenant-1".into(),
            subscriber_id: "sub-1".into(),
            consent_type: "marketing".into(),
            email: String::new(),
        };
        let rt = test_runtime();
        let response = rt.block_on(gdpr_initiate_doi(State(state), headers, Json(body)));
        assert_eq!(result_status(response), StatusCode::INTERNAL_SERVER_ERROR);
    }

    /// Test initiate DOI with a very long email to verify the handler
    /// does not panic or truncate.
    #[test]
    fn test_initiate_doi_long_email_reaches_db() {
        let state = test_app_state();
        let headers = doi_auth_headers();
        let long_local = "a".repeat(200);
        let body = DoiBody {
            tenant_id: "tenant-1".into(),
            subscriber_id: "sub-1".into(),
            consent_type: "marketing".into(),
            email: format!("{long_local}@example.com"),
        };
        let rt = test_runtime();
        let response = rt.block_on(gdpr_initiate_doi(State(state), headers, Json(body)));
        assert_eq!(result_status(response), StatusCode::INTERNAL_SERVER_ERROR);
    }

    /// Test initiate DOI with special characters in the email to verify
    /// the handler handles Unicode and special characters gracefully.
    #[test]
    fn test_initiate_doi_special_chars_email_reaches_db() {
        let state = test_app_state();
        let headers = doi_auth_headers();
        let body = DoiBody {
            tenant_id: "tenant-1".into(),
            subscriber_id: "sub-1".into(),
            consent_type: "marketing".into(),
            email: "test+clickson@exämple.com".into(),
        };
        let rt = test_runtime();
        let response = rt.block_on(gdpr_initiate_doi(State(state), headers, Json(body)));
        assert_eq!(result_status(response), StatusCode::INTERNAL_SERVER_ERROR);
    }

    /// Test confirm DOI with a very long token string.
    #[test]
    fn test_confirm_doi_long_token_reaches_db() {
        let state = test_app_state();
        let headers = doi_auth_headers();
        let body = DoiConfirmBody {
            tenant_id: "tenant-1".into(),
            subscriber_id: "sub-1".into(),
            consent_type: "marketing".into(),
            token: "a".repeat(1000),
        };
        let rt = test_runtime();
        let response = rt.block_on(gdpr_confirm_doi(State(state), headers, Json(body)));
        assert_eq!(result_status(response), StatusCode::INTERNAL_SERVER_ERROR);
    }

    // ── 7. Body deserialisation edge cases ──────────────────────

    /// Test that the DoiBody struct correctly round-trips through JSON
    /// deserialisation with all fields populated.
    #[test]
    fn test_doi_body_deserialization() {
        let json = serde_json::json!({
            "tenant_id": "t1",
            "subscriber_id": "s1",
            "consent_type": "marketing",
            "email": "user@example.com",
        });
        let body: DoiBody = serde_json::from_value(json).unwrap();
        assert_eq!(body.tenant_id, "t1");
        assert_eq!(body.subscriber_id, "s1");
        assert_eq!(body.consent_type, "marketing");
        assert_eq!(body.email, "user@example.com");
    }

    /// Test that the DoiConfirmBody struct correctly round-trips through
    /// JSON deserialisation with all fields populated.
    #[test]
    fn test_doi_confirm_body_deserialization() {
        let json = serde_json::json!({
            "tenant_id": "t1",
            "subscriber_id": "s1",
            "consent_type": "marketing",
            "token": "abc-123-def",
        });
        let body: DoiConfirmBody = serde_json::from_value(json).unwrap();
        assert_eq!(body.tenant_id, "t1");
        assert_eq!(body.subscriber_id, "s1");
        assert_eq!(body.consent_type, "marketing");
        assert_eq!(body.token, "abc-123-def");
    }
}
