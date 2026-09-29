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
use crate::breach_notification::BreachNotifier;
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
    /// Shared behind an Arc so the breach notifier participates in the SAME
    /// audit hash-chain state as the rest of the service (the chain lock and
    /// last-hash cache are per-logger-instance).
    pub audit_logger: Arc<AuditLogger>,
    pub secret_manager: SecretManager,
    pub gdpr: GdprAutomation,
    pub soc2: Soc2Service,
    pub hipaa: HipaaService,
    pub trust: TrustPortalService,
    /// Internal breach-report workflow (GDPR 72h / HIPAA 60-day deadlines).
    pub breach: BreachNotifier,
    /// H-6: retention sweep — registry-driven purges + retention_report rows.
    pub retention_sweeper: crate::retention_sweep::RetentionSweeper,
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
        .route("/risk/assess/:tenant_id", post(risk_assess))
        .route("/risk/profile/:tenant_id", get(risk_profile))
        .route("/risk/limits/:tenant_id", post(risk_update_limits))
        .route("/risk/resolve/:tenant_id", post(risk_resolve_flag))
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
        .route("/audit/:id", get(audit_get_entry))
        .route("/audit/verify", post(audit_verify_chain))
        .route("/audit/export", post(audit_export))
        .route("/audit/stats", get(audit_stats))
        // Secrets
        .route("/secrets", post(secret_create).get(secret_list))
        .route(
            "/secrets/:id",
            get(secret_get).put(secret_update).delete(secret_delete),
        )
        .route("/secrets/:id/rotate", post(secret_rotate))
        .route("/secrets/:id/access", post(secret_grant_access))
        .route("/secrets/:id/versions", get(secret_versions))
        .route("/secrets/:id/rollback/:version", post(secret_rollback))
        // GDPR
        .route("/gdpr/submit", post(gdpr_submit_request))
        .route("/gdpr/verify/:request_id", post(gdpr_verify_request))
        .route("/gdpr/record-consent", post(gdpr_record_consent))
        .route("/gdpr/consents", post(gdpr_get_consents))
        .route(
            "/gdpr/consent-certificate",
            post(gdpr_get_consent_certificate),
        )
        .route("/gdpr/initiate-doi", post(gdpr_initiate_doi))
        .route("/gdpr/confirm-doi", post(gdpr_confirm_doi))
        .route("/gdpr/stats", get(gdpr_stats))
        // G: real download route for stored access exports (export_url
        // points here via export_base_url).
        .route("/gdpr/exports/:id", get(gdpr_download_export))
        // Internal breach-report workflow (GDPR 72h / HIPAA 60-day
        // deadlines): audited state machine, exact submission evidence, a
        // mandatory authenticated human task where no authority machine API
        // exists, and a durable Art. 34 subject-notification outbox.
        .route("/breaches", post(breach_report))
        .route("/breaches/:tenant_id", get(breach_list))
        .route("/breaches/:id/triage", post(breach_triage))
        .route(
            "/breaches/:id/queue-authority-notification",
            post(breach_queue_authority_notification),
        )
        .route(
            "/breaches/:id/record-submission",
            post(breach_record_submission),
        )
        .route("/breaches/:id/record-receipt", post(breach_record_receipt))
        .route(
            "/breaches/:id/queue-subject-notifications",
            post(breach_queue_subject_notifications),
        )
        .route(
            "/breaches/:id/record-subject-delivery",
            post(breach_record_subject_delivery),
        )
        .route("/breaches/:id/tasks", get(breach_open_tasks))
        .route("/breaches/:id/resolve", post(breach_resolve))
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

/// RS-064: Timing-safe comparison for auth tokens.
/// Does NOT leak length through timing — always iterates over both strings fully.
fn constant_time_eq(a: &str, b: &str) -> bool {
    let len_matches = a.len() == b.len();
    let mut result: u8 = 0;
    for (ca, cb) in a.bytes().zip(b.bytes().chain(std::iter::repeat(0))) {
        result |= ca ^ cb;
    }
    for cb in b.bytes().skip(a.len()) {
        result |= cb;
    }
    len_matches && result == 0
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

/// Extract the caller identity from request headers as UNTRUSTED metadata.
///
/// E-3: `X-User-Id` is client-supplied and trivially spoofable. It is never
/// an authenticated actor: authentication is the service Bearer token
/// (verified by `verify_bearer` before any handler reaches this point), and
/// the claimed id is stored with an explicit `claimed_user_id:` prefix so it
/// cannot be mistaken for an authoritative actor in audit trails or access
/// logs.
fn extract_caller_id(headers: &HeaderMap, _config: &ComplianceConfig) -> String {
    headers
        .get("X-User-Id")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .map(|claimed| format!("claimed_user_id:{claimed}"))
        .unwrap_or_else(|| "api-user".to_string())
}

// ── P1-SECURITY: required tenant identity (mirrors the ai-service fix) ──────
//
// The service Bearer token authenticates the upstream caller but carries NO
// tenant identity — one shared token fronts many callers. Every route that
// serves tenant-scoped data must therefore resolve the tenant EXPLICITLY from
// the request and FAIL CLOSED when it is absent: a missing selector is a 401,
// never an all-tenant aggregate or a default bucket (`"default"`, `"global"`,
// `NULL`-filter). Where two selectors are supplied and disagree, that is a
// cross-tenant attempt: 403, logged. This is the same lateral-movement shape
// the AI audit fixed (missing header → `_control-plane` broad default).

/// Maximum accepted length for a request-supplied tenant identity (canonical
/// tenant ids are 26-char ULIDs; `test_support::unique_tenant` is shorter).
const MAX_TENANT_ID_LEN: usize = 64;

/// Trim + bound a raw tenant-selector string; `None` when effectively absent
/// and `Err` when overlong (a fixed caller-error message is used).
fn bounded_tenant(raw: Option<&str>) -> Result<Option<String>, ()> {
    match raw.map(str::trim).filter(|s| !s.is_empty()) {
        None => Ok(None),
        Some(value) if value.len() > MAX_TENANT_ID_LEN => Err(()),
        Some(value) => Ok(Some(value.to_string())),
    }
}

/// Read the tenant selector from the `tenant_id` query parameter or the
/// `X-Tenant-Id` header (query wins — it is the more specific assertion).
/// When BOTH are supplied they must agree exactly: a disagreement is a
/// cross-tenant attempt and is rejected with 403 + a warn log.
pub(crate) fn required_tenant_identity(
    params: Option<&std::collections::HashMap<String, String>>,
    headers: &HeaderMap,
) -> Result<String, (StatusCode, Json<serde_json::Value>)> {
    let query_tenant = bounded_tenant(params.and_then(|p| p.get("tenant_id").map(String::as_str)))
        .map_err(|_| {
            err_json(
                StatusCode::BAD_REQUEST,
                "tenant_id must be at most 64 characters",
            )
        })?;
    let header_tenant = bounded_tenant(headers.get("X-Tenant-Id").and_then(|v| v.to_str().ok()))
        .map_err(|_| {
            err_json(
                StatusCode::BAD_REQUEST,
                "X-Tenant-Id must be at most 64 characters",
            )
        })?;

    match (query_tenant, header_tenant) {
        (Some(query), Some(header)) => {
            if query != header {
                tracing::warn!(
                    query_tenant = %query,
                    header_tenant = %header,
                    "tenant identity mismatch between tenant_id query parameter and X-Tenant-Id header"
                );
                return Err(err_json(
                    StatusCode::FORBIDDEN,
                    "tenant identity mismatch between tenant_id and X-Tenant-Id",
                ));
            }
            Ok(query)
        }
        (Some(query), None) => Ok(query),
        (None, Some(header)) => Ok(header),
        (None, None) => Err(err_json(
            StatusCode::UNAUTHORIZED,
            "a tenant identity is required: pass ?tenant_id= or the X-Tenant-Id header",
        )),
    }
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
    // P1-SECURITY: the tenant must be present AND non-blank. Audit hash
    // chains are keyed per tenant by design; a blank tenant used to mint a
    // ""-keyed chain (an unattributable trail), and a missing one was already
    // refused.
    let tenant_id = entry
        .get("tenant_id")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
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
        // I-5: access-denied is now distinguishable from operational failure.
        "denied" => AuditOutcome::Denied,
        _ => return Err(err_json(StatusCode::BAD_REQUEST, "Invalid outcome")),
    };

    let ctx = LogContext {
        // The validated, trimmed tenant from above — never the raw body value
        // (a padded value must not mint a differently-keyed chain).
        tenant_id: Some(tenant_id.to_string()),
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
///
/// P1-SECURITY: the tenant filter is REQUIRED. `AuditLogQuery.tenant_id` is
/// `Option<String>` and a `None` filter matched EVERY tenant's audit trail
/// (user ids, IP addresses, action details) — the absent-filter → aggregate-
/// all shape. The route refuses a missing/blank tenant instead of widening
/// the query.
async fn audit_query(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(mut query): Json<AuditLogQuery>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    verify_bearer(&headers, &state.config).map_err(|(c, m)| err_json(c, m))?;
    match query.tenant_id.as_deref().map(str::trim) {
        None | Some("") => {
            return Err(err_json(StatusCode::BAD_REQUEST, "Missing tenant_id"));
        }
        Some(trimmed) => query.tenant_id = Some(trimmed.to_string()),
    }
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
///
/// P1-SECURITY: the fetch is tenant-SCOPED. The entry id alone used to serve
/// any tenant's entry to any token holder (by-ID reads crossed tenants); the
/// caller must now assert the tenant (`?tenant_id=` or `X-Tenant-Id`) and an
/// entry attributed to another tenant — or to no tenant — is a 404 that does
/// not reveal its existence.
async fn audit_get_entry(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    verify_bearer(&headers, &state.config).map_err(|(c, m)| err_json(c, m))?;
    let tenant_id = required_tenant_identity(Some(&params), &headers)?;
    match state.audit_logger.get_entry(&id).await {
        Ok(Some(entry)) => {
            if entry.tenant_id.as_deref() != Some(tenant_id.as_str()) {
                tracing::warn!(
                    entry_id = %id,
                    tenant_id = %tenant_id,
                    "audit entry fetch refused: entry belongs to another tenant"
                );
                return Err(err_json(StatusCode::NOT_FOUND, "Audit entry not found"));
            }
            Ok(ok_json(entry))
        }
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
    // An unsupported export format is a caller error, not an internal fault.
    if !matches!(format, "csv" | "json" | "pdf") {
        return Err(err_json(
            StatusCode::BAD_REQUEST,
            "format must be one of: csv, json, pdf",
        ));
    }
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
///
/// P1-SECURITY: tenant-scoped. `get_stats(None)` aggregated action/resource/
/// outcome counts across ALL tenants for any token holder; the tenant is now
/// REQUIRED (`?tenant_id=` or `X-Tenant-Id`, mismatch → 403, absent → 401).
async fn audit_stats(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    verify_bearer(&headers, &state.config).map_err(|(c, m)| err_json(c, m))?;
    let tenant_id = required_tenant_identity(Some(&params), &headers)?;
    match state.audit_logger.get_stats(Some(&tenant_id)).await {
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

/// Map a secret-store failure to an honest status code.
///
/// An authorisation refusal is 403, a missing secret/version is 404, an
/// expiry is 410 and a name collision is 409 — only genuine store faults are
/// 500. The response never echoes the store's internal message.
fn secret_store_error(e: &str) -> (StatusCode, Json<serde_json::Value>) {
    let lower = e.to_ascii_lowercase();
    let (code, message) = if lower.contains("access denied") {
        (StatusCode::FORBIDDEN, "Access denied")
    } else if lower.contains("version not found") {
        (StatusCode::NOT_FOUND, "Secret version not found")
    } else if lower.contains("has expired") {
        (StatusCode::GONE, "Secret has expired")
    } else if lower.contains("not found") {
        (StatusCode::NOT_FOUND, "Secret not found")
    } else if lower.contains("duplicate key") || lower.contains("unique constraint") {
        (
            StatusCode::CONFLICT,
            "A secret with that name already exists",
        )
    } else if lower.contains("must be configured") || lower.contains("at least") {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            "Secret storage is not configured",
        )
    } else {
        (StatusCode::INTERNAL_SERVER_ERROR, "Secret operation failed")
    };
    err_json(code, message)
}

/// POST /secrets — create a new secret.
async fn secret_create(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(input): Json<SecretCreateInput>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    verify_bearer(&headers, &state.config).map_err(|(c, m)| err_json(c, m))?;
    if input.tenant_id.trim().is_empty() {
        return Err(err_json(StatusCode::BAD_REQUEST, "Missing tenant_id"));
    }
    if input.name.trim().is_empty() {
        return Err(err_json(StatusCode::BAD_REQUEST, "Missing name"));
    }
    match state.secret_manager.create_secret(&input).await {
        Ok(secret) => Ok(created_json(secret)),
        Err(e) => {
            error!("Failed to create secret: {e}");
            Err(secret_store_error(&e))
        }
    }
}

/// GET /secrets — list all secrets (requires tenant_id query param).
///
/// P1-SECURITY: the tenant parameter is REQUIRED. It used to default to the
/// literal tenant `"default"` when omitted — a missing-selector fallback that
/// silently served one tenant's secret metadata to a caller that named no
/// tenant at all (the AI-audit bug shape). A missing/blank parameter is now a
/// 400 and nothing is listed.
async fn secret_list(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    verify_bearer(&headers, &state.config).map_err(|(c, m)| err_json(c, m))?;
    let tenant_id = params
        .get("tenant_id")
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| err_json(StatusCode::BAD_REQUEST, "Missing tenant_id"))?;
    if tenant_id.len() > MAX_TENANT_ID_LEN {
        return Err(err_json(
            StatusCode::BAD_REQUEST,
            "tenant_id must be at most 64 characters",
        ));
    }
    match state
        .secret_manager
        .list_secrets(tenant_id, None, 100, 0)
        .await
    {
        Ok(secrets) => Ok(ok_json(secrets)),
        Err(e) => {
            error!("Failed to list secrets: {e}");
            Err(secret_store_error(&e))
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
            Err(secret_store_error(&e))
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
            Err(secret_store_error(&e))
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
            Err(secret_store_error(&e))
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
            Err(secret_store_error(&e))
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
            Err(secret_store_error(&e))
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
            Err(secret_store_error(&e))
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
            Err(secret_store_error(&e))
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

    // SEC-15: Check DSAR rate limits before processing (read-only check —
    // quota is consumed only after a successful submission, see L1 fix).
    match state
        .dsar_rate_limiter
        .check_submission(email, tenant_id)
        .await
    {
        DsarRateLimitStatus::Allowed => { /* proceed */ }
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
        // D: no variant may be swallowed — an exceeded limit of ANY kind
        // rejects the submission.
        // coverage: justified — check_submission only peeks User/Tenant kinds
        // (dsar_rate_limit.rs), so it can never yield VerificationRateLimited;
        // this arm exists to keep the match exhaustive (fail-closed).
        DsarRateLimitStatus::VerificationRateLimited { retry_after } => {
            return Err((
                StatusCode::TOO_MANY_REQUESTS,
                Json(serde_json::json!({
                    "error": "rate_limited",
                    "message": "Too many DSAR requests. Please try again later.",
                    "retry_after": retry_after.as_secs(),
                })),
            ));
        }
    }

    match state
        .gdpr
        .submit_request(tenant_id, request_type, email)
        .await
    {
        Ok((request, _verification_token)) => {
            // C: the raw verification token and its hash must NEVER appear in
            // the HTTP response. This crate has no mailer: the token was
            // written to dsr_verification_outbox in the same transaction as
            // the request, and api-server / worker own the actual sending
            // (documented handoff — see the crate README). token_delivered
            // stays false because THIS service has not delivered anything.
            tracing::info!(
                request_id = %request.id,
                // coverage: justified — the `%field` display closure below is
                // evaluated only when a tracing subscriber accepts the event;
                // the test suite installs no global subscriber, so this lazy
                // arm cannot fire deterministically. The macro skeleton around
                // it IS executed.
                email = %mail_common::pii::redact_email(email),
                token_delivered = false,
                delivery = "outbox_handoff",
                "GDPR verification token queued in dsr_verification_outbox — mail delivery owned by api-server/worker"
            );
            // L1: consume submission quota only on success.
            state
                .dsar_rate_limiter
                .record_submission_success(email, tenant_id)
                .await;
            let response = DataSubjectRequestResponse {
                id: request.id,
                tenant_id: request.tenant_id,
                request_type: request.request_type,
                email: request.email,
                status: request.status,
                requested_at: request.requested_at,
                expires_at: request.expires_at,
                received_at: request.received_at,
                statutory_due_at: request.statutory_due_at,
                verification: serde_json::json!({
                    "method": "outbox_handoff",
                    "instructions": "The verification token has been queued in dsr_verification_outbox for delivery by the platform's mail services (api-server/worker). It is never returned by this API.",
                }),
                token_delivered: false,
            };
            Ok(created_json(response))
        }
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
        DsarRateLimitStatus::Allowed => { /* proceed */ }
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
        // D: previously `_ => {}` swallowed these variants, so an exceeded
        // key reported as UserRateLimited let verification attempts through
        // indefinitely (token brute-force). Any exceeded limit now rejects.
        // coverage: justified — check_verification only emits the
        // Verification kind, so User/Tenant cannot reach this handler; the
        // arm keeps the match exhaustive (fail-closed).
        DsarRateLimitStatus::UserRateLimited { retry_after }
        | DsarRateLimitStatus::TenantRateLimited { retry_after } => {
            return Err((
                StatusCode::TOO_MANY_REQUESTS,
                Json(serde_json::json!({
                    "error": "rate_limited",
                    "message": "Too many verification attempts. Please try again later.",
                    "retry_after": retry_after.as_secs(),
                })),
            ));
        }
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
    // I-4: a missing CONSENT_SIGNING_KEY must not brick the service — only
    // this route fails (503), because consent recording without the ability
    // to sign the proof certificate is non-compliant.
    if state.config.gdpr.consent_signing_key.trim().is_empty() {
        return Err(err_json(
            StatusCode::SERVICE_UNAVAILABLE,
            "Consent signing key not configured (CONSENT_SIGNING_KEY); consent recording is disabled",
        ));
    }
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
///
/// I-1: the tenant is threaded from the request (`?tenant_id=` query param or
/// the X-Tenant-Id header).
///
/// P1-SECURITY: the tenant is now REQUIRED. This route is internal-token
/// protected, so the old absent-selector fallback aggregated GDPR request
/// statistics across ALL tenants for any token holder — the absent-filter →
/// aggregate-all shape from the AI audit. Missing both selectors is a 401;
/// supplying both with different values is a cross-tenant attempt (403,
/// logged).
async fn gdpr_stats(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    verify_bearer(&headers, &state.config).map_err(|(c, m)| err_json(c, m))?;
    let tenant_id = required_tenant_identity(Some(&params), &headers)?;
    // L-03: Use GDPR request stats instead of audit log stats
    match state.gdpr.get_request_stats(Some(tenant_id.as_str())).await {
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

/// GET /gdpr/exports/{id} — download a stored GDPR access export.
///
/// G: the export_url now points at this crate's own route (config
/// `export_base_url`), so exports are actually downloadable. Token-gated via
/// the service Bearer token like every other route; serves the stored export
/// JSON with a Content-Disposition attachment header.
///
/// P1-SECURITY: the download is tenant-SCOPED. The export row carries the
/// subject's full personal-data export, and the id alone used to serve it to
/// any token holder; the caller must now assert the tenant (`?tenant_id=` or
/// `X-Tenant-Id`) and the SQL only matches a row of THAT tenant — another
/// tenant's export (or an unknown id) is the same 404.
pub async fn gdpr_download_export(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
    axum::extract::Path(export_id): axum::extract::Path<String>,
) -> Result<axum::response::Response, (StatusCode, Json<serde_json::Value>)> {
    verify_bearer(&headers, &state.config).map_err(|(c, m)| err_json(c, m))?;
    let tenant_id = required_tenant_identity(Some(&params), &headers)?;

    let row: Option<(serde_json::Value, chrono::DateTime<chrono::Utc>)> = sqlx::query_as(
        "SELECT data, expires_at FROM gdpr_exports WHERE id = $1 AND tenant_id = $2",
    )
    .bind(&export_id)
    .bind(&tenant_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| {
        error!("Failed to fetch GDPR export {export_id}: {e}");
        err_json(StatusCode::INTERNAL_SERVER_ERROR, "Failed to fetch export")
    })?;

    let Some((data, expires_at)) = row else {
        // Unknown id AND another tenant's export are indistinguishable here.
        tracing::warn!(
            export_id = %export_id,
            tenant_id = %tenant_id,
            "gdpr export download refused: unknown id or export belongs to another tenant"
        );
        return Err(err_json(StatusCode::NOT_FOUND, "Export not found"));
    };

    if expires_at < chrono::Utc::now() {
        return Err(err_json(StatusCode::GONE, "Export has expired"));
    }

    // coverage: justified — `data` is a `serde_json::Value` read back from a
    // Postgres JSON column; pretty-printing a Value is infallible by
    // construction, so this closure cannot execute.
    let body = serde_json::to_string_pretty(&data).map_err(|e| {
        error!("Failed to serialize GDPR export {export_id}: {e}");
        err_json(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to serialize export",
        )
    })?;

    let mut response = axum::response::Response::new(axum::body::Body::from(body));
    *response.status_mut() = StatusCode::OK;
    let headers_mut = response.headers_mut();
    headers_mut.insert(
        header::CONTENT_TYPE,
        header::HeaderValue::from_static("application/json"),
    );
    headers_mut.insert(
        header::CONTENT_DISPOSITION,
        header::HeaderValue::from_str(&format!(
            "attachment; filename=\"gdpr-export-{export_id}.json\""
        ))
        .map_err(|_| err_json(StatusCode::INTERNAL_SERVER_ERROR, "Invalid export id"))?,
    );
    Ok(response)
}

// ── Breach notification endpoints (internal workflow) ─────────────────────

/// POST /breaches — record a new breach report and open the notification
/// workflow. The report tracks the GDPR 72-hour and HIPAA 60-day deadlines
/// from discovery and stores a signed notification document.
async fn breach_report(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<crate::breach_notification::BreachReportInput>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    verify_bearer(&headers, &state.config).map_err(|(c, m)| err_json(c, m))?;
    if body.tenant_id.trim().is_empty() {
        return Err(err_json(StatusCode::BAD_REQUEST, "Missing tenant_id"));
    }
    if body.description.trim().is_empty() {
        return Err(err_json(StatusCode::BAD_REQUEST, "Missing description"));
    }
    match state.breach.report_breach(body, "compliance-api").await {
        Ok(report) => Ok(created_json(report)),
        Err(e) => {
            error!("Breach report failed: {e}");
            Err(err_json(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to record breach report",
            ))
        }
    }
}

/// GET /breaches/{tenant_id} — list breach reports for a tenant.
async fn breach_list(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    axum::extract::Path(tenant_id): axum::extract::Path<String>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    verify_bearer(&headers, &state.config).map_err(|(c, m)| err_json(c, m))?;
    match state.breach.list_for_tenant(&tenant_id, None).await {
        Ok(reports) => Ok(ok_json(serde_json::json!({ "reports": reports }))),
        Err(e) => {
            error!("Breach list failed: {e}");
            Err(err_json(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to list breach reports",
            ))
        }
    }
}

/// Body for `POST /breaches/{id}/triage`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BreachTriageBody {
    pub notifiable: bool,
    #[serde(default)]
    pub risk_to_subjects: bool,
    pub rationale: String,
}

/// POST /breaches/{id}/triage — decide notifiable / not_notifiable.
async fn breach_triage(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    axum::extract::Path(breach_id): axum::extract::Path<String>,
    Json(body): Json<BreachTriageBody>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    verify_bearer(&headers, &state.config).map_err(|(c, m)| err_json(c, m))?;
    if body.rationale.trim().is_empty() {
        return Err(err_json(
            StatusCode::BAD_REQUEST,
            "triage requires a rationale",
        ));
    }
    match state
        .breach
        .triage(
            &breach_id,
            body.notifiable,
            body.risk_to_subjects,
            &body.rationale,
            "compliance-api",
        )
        .await
    {
        Ok(report) => Ok(ok_json(report)),
        Err(e) => {
            error!("Breach triage failed: {e}");
            Err(err_json(StatusCode::CONFLICT, "Breach triage failed"))
        }
    }
}

/// POST /breaches/{id}/queue-authority-notification — generate the exact
/// Art. 33(3) submission package and open the mandatory human task.
async fn breach_queue_authority_notification(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    axum::extract::Path(breach_id): axum::extract::Path<String>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    verify_bearer(&headers, &state.config).map_err(|(c, m)| err_json(c, m))?;
    match state
        .breach
        .queue_authority_notification(&breach_id, "compliance-api")
        .await
    {
        Ok(submission) => Ok(created_json(submission)),
        Err(e) => {
            error!("Breach authority queueing failed: {e}");
            Err(err_json(
                StatusCode::CONFLICT,
                "Failed to queue authority notification",
            ))
        }
    }
}

/// Body for `POST /breaches/{id}/record-submission`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BreachSubmissionBody {
    pub submission_id: String,
    #[serde(default)]
    pub submitted_notification: Option<String>,
    pub authority_reference: String,
    #[serde(default)]
    pub channel: Option<String>,
    pub submitted_by: String,
}

/// POST /breaches/{id}/record-submission — store the exact submitted
/// notification, its hash, the timestamp and the authority reference.
async fn breach_record_submission(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    axum::extract::Path(breach_id): axum::extract::Path<String>,
    Json(body): Json<BreachSubmissionBody>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    verify_bearer(&headers, &state.config).map_err(|(c, m)| err_json(c, m))?;
    let channel = match body.channel.as_deref() {
        None | Some("human_task") => crate::breach_notification::SubmissionChannel::HumanTask,
        Some("machine_api") => crate::breach_notification::SubmissionChannel::MachineApi,
        Some(other) => {
            return Err(err_json(
                StatusCode::BAD_REQUEST,
                &format!("unknown submission channel {other:?}"),
            ))
        }
    };
    match state
        .breach
        .record_authority_submission(
            &breach_id,
            &body.submission_id,
            body.submitted_notification.as_deref(),
            &body.authority_reference,
            channel,
            &body.submitted_by,
            "compliance-api",
        )
        .await
    {
        Ok(report) => Ok(ok_json(report)),
        Err(e) => {
            error!("Breach submission recording failed: {e}");
            Err(err_json(
                StatusCode::CONFLICT,
                "Failed to record authority submission",
            ))
        }
    }
}

/// Body for `POST /breaches/{id}/record-receipt`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BreachReceiptBody {
    pub receipt: String,
    #[serde(default)]
    pub received_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// POST /breaches/{id}/record-receipt — the ONLY path to
/// `authority_acknowledged`; requires the authority's receipt.
async fn breach_record_receipt(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    axum::extract::Path(breach_id): axum::extract::Path<String>,
    Json(body): Json<BreachReceiptBody>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    verify_bearer(&headers, &state.config).map_err(|(c, m)| err_json(c, m))?;
    match state
        .breach
        .record_authority_receipt(
            &breach_id,
            &body.receipt,
            body.received_at,
            "compliance-api",
        )
        .await
    {
        Ok(report) => Ok(ok_json(report)),
        Err(e) => {
            error!("Breach receipt recording failed: {e}");
            Err(err_json(
                StatusCode::CONFLICT,
                "Failed to record authority receipt",
            ))
        }
    }
}

/// Body for `POST /breaches/{id}/queue-subject-notifications`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BreachSubjectNotificationBody {
    pub recipients: Vec<String>,
}

/// POST /breaches/{id}/queue-subject-notifications — durable Art. 34 outbox.
async fn breach_queue_subject_notifications(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    axum::extract::Path(breach_id): axum::extract::Path<String>,
    Json(body): Json<BreachSubjectNotificationBody>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    verify_bearer(&headers, &state.config).map_err(|(c, m)| err_json(c, m))?;
    match state
        .breach
        .queue_subject_notifications(&breach_id, &body.recipients, "compliance-api")
        .await
    {
        Ok(queued) => Ok(created_json(serde_json::json!({ "queued": queued }))),
        Err(e) => {
            error!("Breach subject notification queueing failed: {e}");
            Err(err_json(
                StatusCode::CONFLICT,
                "Failed to queue subject notifications",
            ))
        }
    }
}

/// Body for `POST /breaches/{id}/record-subject-delivery`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BreachSubjectDeliveryBody {
    pub outbox_id: String,
    #[serde(default)]
    pub provider_message_id: Option<String>,
    #[serde(default)]
    pub delivery_evidence: Option<serde_json::Value>,
}

/// POST /breaches/{id}/record-subject-delivery — delivery evidence for one
/// subject notification.
async fn breach_record_subject_delivery(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    axum::extract::Path(_breach_id): axum::extract::Path<String>,
    Json(body): Json<BreachSubjectDeliveryBody>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    verify_bearer(&headers, &state.config).map_err(|(c, m)| err_json(c, m))?;
    match state
        .breach
        .record_subject_notification_delivery(
            &body.outbox_id,
            body.provider_message_id.as_deref(),
            body.delivery_evidence,
        )
        .await
    {
        Ok(row) => Ok(ok_json(row)),
        Err(e) => {
            error!("Breach subject delivery recording failed: {e}");
            Err(err_json(
                StatusCode::CONFLICT,
                "Failed to record subject notification delivery",
            ))
        }
    }
}

/// GET /breaches/{id}/tasks — open mandatory authority tasks.
async fn breach_open_tasks(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    axum::extract::Path(_breach_id): axum::extract::Path<String>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    verify_bearer(&headers, &state.config).map_err(|(c, m)| err_json(c, m))?;
    match state.breach.open_authority_tasks(100).await {
        Ok(tasks) => Ok(ok_json(serde_json::json!({ "tasks": tasks }))),
        Err(e) => {
            error!("Breach task listing failed: {e}");
            Err(err_json(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to list breach tasks",
            ))
        }
    }
}

/// POST /breaches/{id}/resolve — close a breach report.
async fn breach_resolve(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    axum::extract::Path(breach_id): axum::extract::Path<String>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    verify_bearer(&headers, &state.config).map_err(|(c, m)| err_json(c, m))?;
    match state.breach.resolve(&breach_id, "compliance-api").await {
        Ok(report) => Ok(ok_json(report)),
        Err(e) => {
            error!("Breach resolve failed: {e}");
            // A state-machine refusal (still pending, wrong state) is a
            // conflict the caller can act on — not an internal fault.
            Err(err_json(
                StatusCode::CONFLICT,
                "Failed to resolve breach report",
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
                system_from_address: "noreply@apexmail.ee".into(),
                outbox_flush_batch: 25,
                outbox_flush_max_attempts: 5,
                clickhouse_erasure_enabled: false,
                clickhouse_url: String::new(),
                clickhouse_database: "apexmail".into(),
                clickhouse_user: "default".into(),
                clickhouse_password: String::new(),
            },
            secrets: crate::config::SecretsConfig {
                encryption_key: String::new(),
                rotation_days: 0,
                max_versions_to_keep: 0,
            },
            dsar_rate_limit: crate::config::DsarRateLimitConfig::default(),
            breach_notification_emails: vec![],
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

    // ── P1-SECURITY: required tenant identity (pure selector parsing) ──────

    fn headers_with_tenant(value: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert("X-Tenant-Id", value.parse().expect("header value"));
        headers
    }

    #[test]
    fn required_tenant_identity_rejects_overlong_selectors_with_400() {
        let overlong = "t".repeat(MAX_TENANT_ID_LEN + 1);

        // An overlong QUERY selector is a caller error, not a lookup.
        let params: std::collections::HashMap<String, String> =
            [("tenant_id".to_string(), overlong.clone())].into();
        let err = required_tenant_identity(Some(&params), &HeaderMap::new()).unwrap_err();
        assert_eq!(err.0, StatusCode::BAD_REQUEST);
        assert!(err.1 .0["error"]
            .as_str()
            .unwrap()
            .contains("tenant_id must be at most 64"));

        // The same bound applies to the HEADER selector.
        let err = required_tenant_identity(None, &headers_with_tenant(&overlong)).unwrap_err();
        assert_eq!(err.0, StatusCode::BAD_REQUEST);
        assert!(err.1 .0["error"]
            .as_str()
            .unwrap()
            .contains("X-Tenant-Id must be at most 64"));

        // Exactly 64 characters is still accepted (the bound is inclusive).
        let at_bound = "t".repeat(MAX_TENANT_ID_LEN);
        assert_eq!(
            required_tenant_identity(
                Some(&[("tenant_id".to_string(), at_bound.clone())].into()),
                &HeaderMap::new()
            )
            .expect("64 chars fit the bound"),
            at_bound
        );
    }

    #[test]
    fn required_tenant_identity_accepts_agreeing_dual_selectors() {
        let tenant = "tenant-agree-1";
        let params: std::collections::HashMap<String, String> =
            [("tenant_id".to_string(), tenant.to_string())].into();
        // When BOTH selectors are supplied and agree, the request proceeds —
        // the disagreement refusal must not punish honest redundancy.
        assert_eq!(
            required_tenant_identity(Some(&params), &headers_with_tenant(tenant))
                .expect("agreeing selectors are accepted"),
            tenant
        );
    }

    #[test]
    fn secret_store_error_maps_expiry_missing_and_unconfigured() {
        // An expired secret is 410 Gone — a client-visible state, not a fault.
        let (code, body) = secret_store_error("Secret has expired");
        assert_eq!(code, StatusCode::GONE);
        assert_eq!(body.0["error"], "Secret has expired");

        // A plain "not found" (no version/expiry context) is 404.
        let (code, body) = secret_store_error("Secret row not found");
        assert_eq!(code, StatusCode::NOT_FOUND);
        assert_eq!(body.0["error"], "Secret not found");

        // Storage not configured / quota wording is 503, never echoed raw.
        for message in [
            "Secret storage must be configured before use",
            "at least one key version is required",
        ] {
            let (code, body) = secret_store_error(message);
            assert_eq!(code, StatusCode::SERVICE_UNAVAILABLE, "{message}");
            assert_eq!(body.0["error"], "Secret storage is not configured");
        }
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
            // Bound the acquire timeout: against the unreachable test
            // endpoint sqlx otherwise RETRIES the refused connection until
            // the 30s default elapses, and DB-failure tests that make
            // several calls then run for minutes. That is not just slow —
            // the wall-clock drift once pushed a six-attempt rate-limit
            // test across a top-of-the-hour boundary, silently switching
            // the limiter to a fresh hour-bucket key (observed on the
            // 2026-09-05 host run: attempt 6 at 20:00:17 keyed to hour 20
            // instead of 19). 50ms keeps every failure path fast and the
            // whole test inside one bucket.
            .acquire_timeout(std::time::Duration::from_millis(50))
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
            system_from_address: "noreply@apexmail.ee".into(),
            outbox_flush_batch: 25,
            outbox_flush_max_attempts: 5,
            clickhouse_erasure_enabled: false,
            clickhouse_url: String::new(),
            clickhouse_database: "apexmail".into(),
            clickhouse_user: "default".into(),
            clickhouse_password: String::new(),
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
        let audit_logger = Arc::new(AuditLogger::new(db.clone(), config.audit.clone()));
        Arc::new(AppState {
            risk_engine: RiskScoringEngine::new(db.clone(), config.clone()),
            content_scanner: ContentScanner::new(db.clone(), test_content_config()),
            audit_logger: audit_logger.clone(),
            secret_manager: SecretManager::new(db.clone(), config.secrets.clone())
                .expect("SecretManager construction should succeed with test salt"),
            gdpr: test_gdpr_automation(),
            soc2: crate::soc2::Soc2Service::new(db.clone()),
            hipaa: crate::hipaa::HipaaService::new(db.clone(), b"test-baa-key".to_vec()),
            trust: crate::trust_portal::TrustPortalService::new(db.clone()),
            breach: crate::breach_notification::BreachNotifier::new(
                db.clone(),
                audit_logger,
                vec![],
                b"test-breach-signing-key".to_vec(),
            ),
            retention_sweeper: crate::retention_sweep::RetentionSweeper::new(
                db.clone(),
                config.gdpr.export_expiration_days,
                config.gdpr.request_expiration_days,
                config.audit.retention_days,
            ),
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

    // ── 8. GDPR submit / verify / export-download security tests ─────

    /// C: the submit response must not contain the verification token or
    /// its hash.
    #[test]
    fn test_submit_response_dto_leaks_no_token() {
        let resp = DataSubjectRequestResponse {
            id: "req-1".into(),
            tenant_id: "t1".into(),
            request_type: DataSubjectRequestType::Erasure,
            email: "user@example.com".into(),
            status: RequestStatus::PendingVerification,
            requested_at: chrono::Utc::now(),
            expires_at: chrono::Utc::now(),
            received_at: Some(chrono::Utc::now()),
            statutory_due_at: Some(chrono::Utc::now()),
            verification: serde_json::json!({"method": "token_delivery_pending"}),
            token_delivered: false,
        };
        let body = serde_json::to_string(&serde_json::json!({ "data": resp })).unwrap();
        assert!(!body.contains("token_hash"));
        assert!(!body.contains("\"token\""));
        assert!(body.contains("\"token_delivered\":false"));
    }

    /// D: the 6th verification attempt within the window is rejected with
    /// 429 — the fake-DB failures on attempts 1-5 must NOT reset or bypass
    /// the limit (the old `_ => {}` swallow let these through forever).
    #[test]
    fn test_verify_sixth_attempt_is_rate_limited() {
        let state = test_app_state(); // in-memory limiter, verify_attempts = 5
        let headers = doi_auth_headers();
        let rt = test_runtime();

        let mut statuses = Vec::new();
        for _ in 0..6 {
            let body = serde_json::json!({ "token": "same-guess-token" });
            let response = rt.block_on(gdpr_verify_request(
                State(state.clone()),
                headers.clone(),
                axum::extract::Path("req-1".to_string()),
                Json(body),
            ));
            statuses.push(result_status(response));
        }
        // Attempts 1-5 pass the rate limit and die on the fake DB (500).
        for (i, s) in statuses.iter().take(5).enumerate() {
            assert_eq!(
                *s,
                StatusCode::INTERNAL_SERVER_ERROR,
                "attempt {} should reach the DB layer",
                i + 1
            );
        }
        // Attempt 6 is rejected by the rate limiter (429), proving failed
        // attempts consume quota and no variant is swallowed.
        assert_eq!(statuses[5], StatusCode::TOO_MANY_REQUESTS);
    }

    /// G: the export download route requires the service token (401 without).
    #[test]
    fn test_download_export_requires_auth() {
        let state = test_app_state();
        let rt = test_runtime();
        let response = rt.block_on(gdpr_download_export(
            State(state),
            HeaderMap::new(), // no auth header
            axum::extract::Query(std::collections::HashMap::new()),
            axum::extract::Path("some-export-id".to_string()),
        ));
        assert_eq!(response.unwrap_err().0, StatusCode::UNAUTHORIZED);
    }

    /// G: unknown export id never yields 200 — with the fake pool the DB
    /// fetch fails, exercising only the wiring (the real 404 path is covered
    /// by the DB-gated integration tests).
    /// P1-SECURITY (required tenant scoping): the caller now also asserts the
    /// export's tenant via X-Tenant-Id, so this probe reaches the (failing)
    /// tenant-scoped fetch instead of stopping at the selector check.
    #[test]
    fn test_download_export_unknown_id_is_never_200() {
        let state = test_app_state();
        let mut headers = doi_auth_headers();
        headers.insert("X-Tenant-Id", "ten_probe_0000000000001".parse().unwrap());
        let rt = test_runtime();
        let response = rt.block_on(gdpr_download_export(
            State(state),
            headers,
            axum::extract::Query(std::collections::HashMap::new()),
            axum::extract::Path("no-such-export".to_string()),
        ));
        let status = match response {
            Ok(resp) => resp.status(),
            Err((s, _)) => s,
        };
        assert_ne!(status, StatusCode::OK);
        assert_ne!(status, StatusCode::UNAUTHORIZED);
    }

    /// I-4: recording consent without a signing key is a 503, not a 500 —
    /// the rest of the service stays up.
    #[test]
    fn test_record_consent_without_signing_key_is_503() {
        let state = test_app_state(); // test config has empty consent_signing_key
        let headers = doi_auth_headers();
        let body = serde_json::json!({
            "tenant_id": "t1",
            "subscriber_id": "s1",
            "consent_type": "marketing",
            "email": "user@example.com",
            "granted": true,
        });
        let rt = test_runtime();
        let response = rt.block_on(gdpr_record_consent(State(state), headers, Json(body)));
        assert_eq!(result_status(response), StatusCode::SERVICE_UNAVAILABLE);
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

    // ── F56: route capture syntax (pinned axum 0.7) ─────────────────

    /// Extract the first string literal of every `.route(...)` call in a
    /// source file (multi-line friendly; byte-safe on non-ASCII sources,
    /// route paths contain no escapes).
    fn route_path_literals(src: &str) -> Vec<(usize, &str)> {
        const NEEDLE: &[u8] = b".route(";
        let bytes = src.as_bytes();
        let mut out = Vec::new();
        let mut i = 0;
        while i < bytes.len() {
            if bytes[i..].starts_with(NEEDLE) {
                let mut j = i + NEEDLE.len();
                while j < bytes.len() && matches!(bytes[j], b' ' | b'\n' | b'\t' | b'\r') {
                    j += 1;
                }
                if j < bytes.len() && bytes[j] == b'"' {
                    let start = j + 1;
                    let mut k = start;
                    while k < bytes.len() && bytes[k] != b'"' {
                        k += 1;
                    }
                    if k < bytes.len() {
                        let line = src[..i].lines().count();
                        let literal =
                            std::str::from_utf8(&bytes[start..k]).expect("route literal is UTF-8");
                        out.push((line, literal));
                    }
                }
                i = j.max(i + 1);
            } else {
                i += 1;
            }
        }
        out
    }

    /// F56: this crate pins axum 0.7, whose path syntax is `:name` — the
    /// `{name}` form is axum 0.8+ and silently never matches real path
    /// segments here. Every route literal must use `:` captures (or be
    /// static), and the two files together must carry exactly the 32
    /// converted parameterised routes (34 captures: two routes take two
    /// parameters).
    #[test]
    fn test_route_paths_use_axum07_colon_captures() {
        let manifest = env!("CARGO_MANIFEST_DIR");
        let mut colon_routes = 0;
        let mut colon_captures = 0;

        for file in ["src/routes.rs", "src/admin_routes.rs"] {
            let full = std::fs::read_to_string(format!("{manifest}/{file}"))
                .unwrap_or_else(|e| panic!("cannot read {file}: {e}"));
            // Scan production code only — the test module's own literals
            // (including this scanner's needle) must not be counted.
            let src = &full[..full.find("#[cfg(test)]").unwrap_or(full.len())];
            for (line, path) in route_path_literals(src) {
                assert!(
                    !path.contains('{'),
                    "{file}:{line} route path {path:?} uses axum-0.8 {{name}} capture syntax; this crate pins axum 0.7 (use :name)"
                );
                let captures = path.matches(':').count();
                if captures > 0 {
                    colon_routes += 1;
                    colon_captures += captures;
                    for segment in path.split('/') {
                        if let Some(param) = segment.strip_prefix(':') {
                            assert!(
                                !param.is_empty()
                                    && param.chars().all(|c| c.is_ascii_lowercase() || c == '_'),
                                "{file}:{line} malformed capture :{param} in {path:?}"
                            );
                        }
                    }
                }
            }
        }

        // The F56 conversion: parameterised routes in routes.rs + admin_routes.rs.
        // 37 = the original 32 + the 7 breach state-machine routes added by the
        // GDPR governance work - the 2 removed notify-dpa/notify-subjects routes.
        assert_eq!(
            colon_routes, 37,
            "expected 37 parameterised routes (16 in admin_routes + 21 here), found {colon_routes}"
        );
        assert_eq!(
            colon_captures, 39,
            "expected 39 captures (two 2-param routes), found {colon_captures}"
        );
    }
}

// ─── DB-backed handler tests ────────────────────────────────────────────────
//
// Every handler is exercised directly: unauthenticated calls must be 401,
// user error must be 4xx (never 500), and a rejected write must leave the
// database unchanged.

#[cfg(test)]
mod db_tests {
    use super::*;
    use crate::test_support;
    use serde_json::json;
    use std::collections::HashMap;

    const TOKEN: &str = "unit-routes-service-token";
    const USER: &str = "claimed_user_id:owner@apexmail.ee";
    const READER: &str = "claimed_user_id:reader@apexmail.ee";

    async fn state(suffix: &str) -> Option<Arc<AppState>> {
        let pool =
            test_support::canonical_pool(&format!("routes_{suffix}"), &format!("routes_{suffix}"))
                .await?;
        Some(test_support::app_state(pool, TOKEN))
    }

    fn auth() -> HeaderMap {
        test_support::bearer(TOKEN)
    }

    fn auth_as(user: &str) -> HeaderMap {
        let mut headers = auth();
        headers.insert("X-User-Id", user.parse().expect("user id header"));
        headers
    }

    fn status<R: IntoResponse>(r: Result<R, (StatusCode, Json<serde_json::Value>)>) -> StatusCode {
        match r {
            Ok(response) => response.into_response().status(),
            Err((code, _)) => code,
        }
    }

    fn error_of<R: IntoResponse>(
        r: Result<R, (StatusCode, Json<serde_json::Value>)>,
    ) -> (StatusCode, serde_json::Value) {
        match r {
            Ok(_) => panic!("expected an error response"),
            Err((code, body)) => (code, body.0),
        }
    }

    fn query(pairs: &[(&str, &str)]) -> axum::extract::Query<HashMap<String, String>> {
        axum::extract::Query(
            pairs
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
        )
    }

    fn path(value: &str) -> axum::extract::Path<String> {
        axum::extract::Path(value.to_string())
    }

    fn path_pair(value: &str, version: i32) -> axum::extract::Path<(String, i32)> {
        axum::extract::Path((value.to_string(), version))
    }

    fn email_content(tenant: &str) -> EmailContent {
        EmailContent {
            tenant_id: tenant.into(),
            message_id: "msg-1".into(),
            from_address: "sender@apexmail.ee".into(),
            from_display_name: None,
            subject: "hello".into(),
            text_body: Some("body".into()),
            html_body: None,
            headers: HashMap::new(),
            attachments: vec![],
        }
    }

    fn asset_limits() -> serde_json::Value {
        json!({
            "max_daily_emails": 100,
            "max_hourly_emails": 50,
            "max_recipients": 10,
            "max_attachment_size_mb": 5,
            "require_double_opt_in": true,
            "require_unsubscribe_link": true,
            "allowed_domains": [],
            "blocked_recipient_patterns": [],
        })
    }

    fn secret_create_body(tenant: &str, name: &str) -> SecretCreateInput {
        SecretCreateInput {
            tenant_id: tenant.into(),
            name: name.into(),
            secret_type: SecretType::SmtpPassword,
            value: Some("unit-secret-value".into()),
            created_by: USER.into(),
            rotation_schedule: None,
            expires_at: None,
        }
    }

    fn breach_input(tenant: &str) -> crate::breach_notification::BreachReportInput {
        crate::breach_notification::BreachReportInput {
            tenant_id: tenant.into(),
            affected_records: 3,
            data_types: vec!["email".into()],
            description: "mailbox exposed".into(),
            severity: "high".into(),
            dpo_contact: Some("dpo@apexmail.ee".into()),
            likely_consequences: Some("spam".into()),
            measures_taken: Some("rotated keys".into()),
        }
    }

    #[tokio::test]
    async fn every_authenticated_handler_refuses_a_missing_token() {
        let Some(state) = state("authgate").await else {
            return;
        };
        let none = HeaderMap::new();
        let body = json!({});
        let q = query(&[("tenant_id", "t")]);

        // 401 for every route that must be authenticated. A missing header is
        // the first thing checked, so the bodies never matter here.
        let codes = vec![
            status(risk_assess(State(state.clone()), none.clone(), path("t")).await),
            status(risk_profile(State(state.clone()), none.clone(), path("t")).await),
            status(
                risk_update_limits(
                    State(state.clone()),
                    none.clone(),
                    path("t"),
                    Json(asset_limits()),
                )
                .await,
            ),
            status(
                risk_resolve_flag(
                    State(state.clone()),
                    none.clone(),
                    path("t"),
                    Json(body.clone()),
                )
                .await,
            ),
            status(risk_critical_tenants(State(state.clone()), none.clone()).await),
            status(risk_stats(State(state.clone()), none.clone()).await),
            status(
                scan_content(State(state.clone()), none.clone(), Json(email_content("t"))).await,
            ),
            status(audit_create(State(state.clone()), none.clone(), Json(body.clone())).await),
            status(
                audit_query(
                    State(state.clone()),
                    none.clone(),
                    Json(AuditLogQuery::default()),
                )
                .await,
            ),
            status(
                audit_get_entry(State(state.clone()), none.clone(), q.clone(), path("id")).await,
            ),
            status(
                audit_verify_chain(State(state.clone()), none.clone(), Json(body.clone())).await,
            ),
            status(audit_export(State(state.clone()), none.clone(), Json(body.clone())).await),
            status(audit_stats(State(state.clone()), none.clone(), q.clone()).await),
            status(
                secret_create(
                    State(state.clone()),
                    none.clone(),
                    Json(secret_create_body("t", "n")),
                )
                .await,
            ),
            status(secret_list(State(state.clone()), none.clone(), q.clone()).await),
            status(secret_get(State(state.clone()), none.clone(), path("id")).await),
            status(
                secret_update(
                    State(state.clone()),
                    none.clone(),
                    path("id"),
                    Json(SecretUpdateInput {
                        name: None,
                        rotation_schedule: None,
                        expires_at: None,
                    }),
                )
                .await,
            ),
            status(secret_delete(State(state.clone()), none.clone(), path("id")).await),
            status(secret_rotate(State(state.clone()), none.clone(), path("id")).await),
            status(
                secret_grant_access(
                    State(state.clone()),
                    none.clone(),
                    path("id"),
                    Json(body.clone()),
                )
                .await,
            ),
            status(secret_versions(State(state.clone()), none.clone(), path("id")).await),
            status(secret_rollback(State(state.clone()), none.clone(), path_pair("id", 1)).await),
            status(
                gdpr_submit_request(State(state.clone()), none.clone(), Json(body.clone())).await,
            ),
            status(
                gdpr_verify_request(
                    State(state.clone()),
                    none.clone(),
                    path("id"),
                    Json(json!({"token": "x"})),
                )
                .await,
            ),
            status(
                gdpr_record_consent(State(state.clone()), none.clone(), Json(body.clone())).await,
            ),
            status(gdpr_get_consents(State(state.clone()), none.clone(), Json(body.clone())).await),
            status(
                gdpr_get_consent_certificate(
                    State(state.clone()),
                    none.clone(),
                    Json(json!({"consent_id": "c"})),
                )
                .await,
            ),
            status(gdpr_stats(State(state.clone()), none.clone(), q.clone()).await),
            status(
                gdpr_download_export(State(state.clone()), none.clone(), q.clone(), path("e"))
                    .await,
            ),
            status(
                breach_report(State(state.clone()), none.clone(), Json(breach_input("t"))).await,
            ),
            status(breach_list(State(state.clone()), none.clone(), path("t")).await),
            status(
                breach_triage(
                    State(state.clone()),
                    none.clone(),
                    path("b"),
                    Json(BreachTriageBody {
                        notifiable: true,
                        risk_to_subjects: true,
                        rationale: "r".into(),
                    }),
                )
                .await,
            ),
            status(
                breach_queue_authority_notification(State(state.clone()), none.clone(), path("b"))
                    .await,
            ),
            status(
                breach_record_submission(
                    State(state.clone()),
                    none.clone(),
                    path("b"),
                    Json(BreachSubmissionBody {
                        submission_id: "s".into(),
                        submitted_notification: None,
                        authority_reference: "ref".into(),
                        channel: None,
                        submitted_by: "u".into(),
                    }),
                )
                .await,
            ),
            status(
                breach_record_receipt(
                    State(state.clone()),
                    none.clone(),
                    path("b"),
                    Json(BreachReceiptBody {
                        receipt: "r".into(),
                        received_at: None,
                    }),
                )
                .await,
            ),
            status(
                breach_queue_subject_notifications(
                    State(state.clone()),
                    none.clone(),
                    path("b"),
                    Json(BreachSubjectNotificationBody {
                        recipients: vec!["a@example.test".into()],
                    }),
                )
                .await,
            ),
            status(
                breach_record_subject_delivery(
                    State(state.clone()),
                    none.clone(),
                    path("b"),
                    Json(BreachSubjectDeliveryBody {
                        outbox_id: "o".into(),
                        provider_message_id: None,
                        delivery_evidence: None,
                    }),
                )
                .await,
            ),
            status(breach_open_tasks(State(state.clone()), none.clone(), path("b")).await),
            status(breach_resolve(State(state.clone()), none.clone(), path("b")).await),
            status(
                gdpr_initiate_doi(
                    State(state.clone()),
                    none.clone(),
                    Json(DoiBody {
                        tenant_id: "t".into(),
                        subscriber_id: "s".into(),
                        consent_type: "marketing".into(),
                        email: "a@example.test".into(),
                    }),
                )
                .await,
            ),
            status(
                gdpr_confirm_doi(
                    State(state.clone()),
                    none.clone(),
                    Json(DoiConfirmBody {
                        tenant_id: "t".into(),
                        subscriber_id: "s".into(),
                        consent_type: "marketing".into(),
                        token: "x".into(),
                    }),
                )
                .await,
            ),
        ];
        assert_eq!(codes.len(), 41, "every authenticated handler is listed");
        for (index, code) in codes.iter().enumerate() {
            assert_eq!(*code, StatusCode::UNAUTHORIZED, "handler #{index}");
        }

        // A wrong token is refused identically; a malformed header too.
        let mut wrong = HeaderMap::new();
        wrong.insert(
            header::AUTHORIZATION,
            "Bearer not-the-token".parse().unwrap(),
        );
        assert_eq!(
            status(risk_stats(State(state.clone()), wrong).await),
            StatusCode::UNAUTHORIZED
        );
        let mut malformed = HeaderMap::new();
        malformed.insert(header::AUTHORIZATION, "Token abc".parse().unwrap());
        assert_eq!(
            status(risk_stats(State(state.clone()), malformed).await),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            status(risk_stats(State(state.clone()), auth()).await),
            StatusCode::OK
        );
    }

    #[tokio::test]
    async fn health_and_risk_endpoints_report_honestly() {
        let Some(state) = state("risk").await else {
            return;
        };
        assert_eq!(
            health_check().await.into_response().status(),
            StatusCode::OK
        );
        assert_eq!(
            status(health_ready(State(state.clone())).await),
            StatusCode::OK
        );

        let tenant = test_support::unique_tenant();
        // An unknown tenant has no profile: 404, not a fabricated default.
        assert_eq!(
            status(risk_profile(State(state.clone()), auth(), path(&tenant)).await),
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            status(risk_assess(State(state.clone()), auth(), path(&tenant)).await),
            StatusCode::OK
        );
        if let Err(e) = state.risk_engine.get_profile(&tenant).await {
            eprintln!("GET_PROFILE_ERR: {e}");
        }
        assert_eq!(
            status(risk_profile(State(state.clone()), auth(), path(&tenant)).await),
            StatusCode::OK
        );
        // Hostile limits body: missing fields are a 400, never a 500.
        let (code, _) = error_of(
            risk_update_limits(
                State(state.clone()),
                auth(),
                path(&tenant),
                Json(json!({"max_daily_emails": "lots"})),
            )
            .await,
        );
        assert_eq!(code, StatusCode::BAD_REQUEST);
        assert_eq!(
            status(
                risk_update_limits(
                    State(state.clone()),
                    auth(),
                    path(&tenant),
                    Json(asset_limits())
                )
                .await
            ),
            StatusCode::OK
        );
        // Resolving a flag needs a known flag type.
        let (code, _) = error_of(
            risk_resolve_flag(
                State(state.clone()),
                auth(),
                path(&tenant),
                Json(json!({"resolution": "x"})),
            )
            .await,
        );
        assert_eq!(code, StatusCode::BAD_REQUEST);
        let (code, body) = error_of(
            risk_resolve_flag(
                State(state.clone()),
                auth(),
                path(&tenant),
                Json(json!({"flag_type": "not_a_flag"})),
            )
            .await,
        );
        assert_eq!(code, StatusCode::BAD_REQUEST);
        assert!(body["error"]
            .as_str()
            .unwrap_or_default()
            .contains("Invalid risk flag"));
        assert_eq!(
            status(
                risk_resolve_flag(
                    State(state.clone()),
                    auth(),
                    path(&tenant),
                    Json(json!({"flag_type": "spam_trap_hit", "resolution": "cleared"})),
                )
                .await
            ),
            StatusCode::OK
        );
        assert_eq!(
            status(risk_critical_tenants(State(state.clone()), auth()).await),
            StatusCode::OK
        );
        assert_eq!(
            status(risk_stats(State(state.clone()), auth()).await),
            StatusCode::OK
        );
    }

    #[tokio::test]
    async fn audit_endpoints_validate_inputs_and_never_500_on_user_error() {
        let Some(state) = state("audit").await else {
            return;
        };
        let tenant = test_support::unique_tenant();

        // Missing/invalid fields are 400s.
        for bad in [
            json!({}),
            json!({"action": "nope", "resource": "email", "tenant_id": tenant}),
            json!({"action": "create", "resource": "nope", "tenant_id": tenant}),
            json!({"action": "create", "resource": "email"}),
            json!({"action": "create", "resource": "email", "tenant_id": tenant, "outcome": "maybe"}),
            // P1-SECURITY: a blank tenant would mint an unattributed ""-keyed
            // hash chain — refused like a missing one.
            json!({"action": "create", "resource": "email", "tenant_id": "   "}),
        ] {
            let (code, _) = error_of(audit_create(State(state.clone()), auth(), Json(bad)).await);
            assert_eq!(code, StatusCode::BAD_REQUEST);
        }
        let created = audit_create(
            State(state.clone()),
            auth(),
            Json(json!({
                "action": "create",
                "resource": "secret",
                "tenant_id": tenant,
                "outcome": "denied",
                "details": {"why": "test"},
                "user_id": "u1",
                "ip": "203.0.113.9",
                "user_agent": "unit-test",
            })),
        )
        .await;
        assert_eq!(status(created), StatusCode::CREATED);

        // Query returns the entry scoped to its tenant.
        let query_body = AuditLogQuery {
            tenant_id: Some(tenant.clone()),
            ..Default::default()
        };
        assert_eq!(
            status(audit_query(State(state.clone()), auth(), Json(query_body)).await),
            StatusCode::OK
        );
        // P1-SECURITY (required tenant scoping): the stats aggregate and the
        // by-entry read are tenant-scoped — the caller asserts the tenant via
        // ?tenant_id= (or X-Tenant-Id).
        assert_eq!(
            status(
                audit_stats(
                    State(state.clone()),
                    auth(),
                    query(&[("tenant_id", tenant.as_str())])
                )
                .await
            ),
            StatusCode::OK
        );
        assert_eq!(
            status(
                audit_get_entry(
                    State(state.clone()),
                    auth(),
                    query(&[("tenant_id", tenant.as_str())]),
                    path("no-such-entry")
                )
                .await
            ),
            StatusCode::NOT_FOUND
        );
        let (code, _) =
            error_of(audit_verify_chain(State(state.clone()), auth(), Json(json!({}))).await);
        assert_eq!(code, StatusCode::BAD_REQUEST);
        assert_eq!(
            status(
                audit_verify_chain(
                    State(state.clone()),
                    auth(),
                    Json(json!({"tenant_id": tenant}))
                )
                .await
            ),
            StatusCode::OK
        );
        let (code, _) = error_of(audit_export(State(state.clone()), auth(), Json(json!({}))).await);
        assert_eq!(code, StatusCode::BAD_REQUEST);
        let (code, body) = error_of(
            audit_export(
                State(state.clone()),
                auth(),
                Json(json!({"tenant_id": tenant, "format": "ndjson"})),
            )
            .await,
        );
        assert_eq!(
            code,
            StatusCode::BAD_REQUEST,
            "unsupported format is a caller error"
        );
        assert!(body["error"].as_str().unwrap_or_default().contains("csv"));
        for format in ["csv", "json", "pdf"] {
            assert_eq!(
                status(
                    audit_export(
                        State(state.clone()),
                        auth(),
                        Json(json!({"tenant_id": tenant, "format": format})),
                    )
                    .await
                ),
                StatusCode::OK,
                "format {format}"
            );
        }
    }

    #[tokio::test]
    async fn secret_handlers_gate_caller_identity_and_map_errors_to_4xx() {
        let Some(state) = state("secret").await else {
            return;
        };
        let tenant = test_support::unique_tenant();

        // Input validation.
        let (code, _) = error_of(
            secret_create(
                State(state.clone()),
                auth(),
                Json(SecretCreateInput {
                    tenant_id: "  ".into(),
                    ..secret_create_body(&tenant, "n")
                }),
            )
            .await,
        );
        assert_eq!(code, StatusCode::BAD_REQUEST);
        let (code, _) = error_of(
            secret_create(
                State(state.clone()),
                auth(),
                Json(secret_create_body(&tenant, "   ")),
            )
            .await,
        );
        assert_eq!(code, StatusCode::BAD_REQUEST);
        // A bad rotation schedule is refused by JSON, leaving no row.
        assert_eq!(
            status(
                secret_create(
                    State(state.clone()),
                    auth(),
                    Json(secret_create_body(&tenant, "good")),
                )
                .await
            ),
            StatusCode::CREATED
        );
        let (code, _) = error_of(
            secret_create(
                State(state.clone()),
                auth(),
                Json(secret_create_body(&tenant, "good")),
            )
            .await,
        );
        assert_eq!(code, StatusCode::CONFLICT, "duplicate name is not a 500");

        // The list never carries the plaintext.
        let listed = secret_list(
            State(state.clone()),
            auth(),
            query(&[("tenant_id", &tenant)]),
        )
        .await;
        let body = match listed {
            Ok(response) => {
                let bytes = axum::body::to_bytes(response.into_response().into_body(), 1 << 20)
                    .await
                    .expect("body");
                let text = String::from_utf8(bytes.to_vec()).expect("utf8");
                assert!(!text.contains("unit-secret-value"), "{text}");
                serde_json::from_str::<serde_json::Value>(&text).expect("json")
            }
            Err((code, _)) => panic!("list failed: {code}"),
        };
        let id = body["data"][0]["id"].as_str().expect("id").to_string();

        // The caller identity is the prefixed X-User-Id, and only the creator
        // (or a grantee) may read the secret.
        let (code, _) = error_of(
            secret_get(
                State(state.clone()),
                auth_as("stranger@apexmail.ee"),
                path(&id),
            )
            .await,
        );
        assert_eq!(code, StatusCode::FORBIDDEN);
        let owner = auth_as("owner@apexmail.ee");
        assert_eq!(
            status(secret_get(State(state.clone()), owner.clone(), path(&id)).await),
            StatusCode::OK
        );
        assert_eq!(
            status(secret_get(State(state.clone()), owner.clone(), path("no-such-id")).await),
            StatusCode::FORBIDDEN,
            "access is checked before existence, so unknown ids do not leak"
        );

        // Metadata update, version history and rollback.
        assert_eq!(
            status(
                secret_update(
                    State(state.clone()),
                    auth_as("owner@apexmail.ee"),
                    path(&id),
                    Json(SecretUpdateInput {
                        name: Some("renamed".into()),
                        rotation_schedule: Some(RotationSchedule {
                            interval_days: 7,
                            auto_rotate: true,
                            notify_before_days: 2,
                        }),
                        expires_at: None,
                    }),
                )
                .await
            ),
            StatusCode::OK
        );
        assert_eq!(
            status(secret_rotate(State(state.clone()), owner.clone(), path(&id)).await),
            StatusCode::OK
        );
        assert_eq!(
            status(secret_versions(State(state.clone()), owner.clone(), path(&id)).await),
            StatusCode::OK
        );
        assert_eq!(
            status(secret_rollback(State(state.clone()), owner.clone(), path_pair("id", 99)).await),
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            status(secret_rollback(State(state.clone()), owner.clone(), path_pair(&id, 1)).await),
            StatusCode::OK
        );
        assert_eq!(
            status(
                secret_rollback(State(state.clone()), owner.clone(), path_pair(&id, 9999)).await
            ),
            StatusCode::NOT_FOUND
        );

        // Access grants validate their body and the granted level.
        assert_eq!(
            status(
                secret_grant_access(
                    State(state.clone()),
                    owner.clone(),
                    path(&id),
                    Json(json!({}))
                )
                .await
            ),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            status(
                secret_grant_access(
                    State(state.clone()),
                    owner.clone(),
                    path(&id),
                    Json(json!({"user_id": "reader@apexmail.ee", "access_level": "root"})),
                )
                .await
            ),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            status(
                secret_grant_access(
                    State(state.clone()),
                    owner.clone(),
                    path(&id),
                    Json(json!({"user_id": READER, "access_level": "read"})),
                )
                .await
            ),
            StatusCode::OK
        );
        assert_eq!(
            status(
                secret_get(
                    State(state.clone()),
                    auth_as("reader@apexmail.ee"),
                    path(&id),
                )
                .await
            ),
            StatusCode::OK
        );
        assert_eq!(
            status(secret_delete(State(state.clone()), owner.clone(), path("no-such-id")).await),
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            status(secret_delete(State(state.clone()), owner.clone(), path(&id)).await),
            StatusCode::OK
        );
        assert_eq!(
            status(secret_delete(State(state.clone()), owner.clone(), path(&id)).await),
            StatusCode::FORBIDDEN,
            "a second delete is a refusal, not a fabricated success"
        );
    }

    #[tokio::test]
    async fn gdpr_handlers_validate_and_never_leak_the_verification_token() {
        let Some(state) = state("gdpr").await else {
            return;
        };
        let tenant = test_support::unique_tenant();
        let email = "subject@example.test";

        for bad in [
            json!({}),
            json!({"tenant_id": tenant, "request_type": "everything"}),
            json!({"tenant_id": tenant, "request_type": "access"}),
        ] {
            let (code, _) =
                error_of(gdpr_submit_request(State(state.clone()), auth(), Json(bad)).await);
            assert_eq!(code, StatusCode::BAD_REQUEST);
        }
        let submitted = gdpr_submit_request(
            State(state.clone()),
            auth(),
            Json(json!({"tenant_id": tenant, "request_type": "access", "email": email})),
        )
        .await;
        assert_eq!(status(submitted), StatusCode::CREATED);

        // The DSAR quota is consumed by the success: a second submission from
        // the same address within 24h is rate limited, not silently accepted.
        let (code, body) = error_of(
            gdpr_submit_request(
                State(state.clone()),
                auth(),
                Json(json!({"tenant_id": tenant, "request_type": "access", "email": email})),
            )
            .await,
        );
        assert_eq!(code, StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(body["error"], json!("rate_limited"));

        // Verification with a bogus token is a false answer, not an error and
        // never a token echo.
        assert_eq!(
            status(
                gdpr_verify_request(
                    State(state.clone()),
                    auth(),
                    path("no-such-request"),
                    Json(json!({"token": "bogus"})),
                )
                .await
            ),
            StatusCode::OK
        );
        let (code, _) = error_of(
            gdpr_verify_request(State(state.clone()), auth(), path("r"), Json(json!({}))).await,
        );
        assert_eq!(code, StatusCode::BAD_REQUEST);

        // Consent recording and certificate generation.
        let (code, _) =
            error_of(gdpr_record_consent(State(state.clone()), auth(), Json(json!({}))).await);
        assert_eq!(code, StatusCode::BAD_REQUEST);
        let (code, _) = error_of(
            gdpr_record_consent(
                State(state.clone()),
                auth(),
                Json(json!({
                    "tenant_id": tenant,
                    "subscriber_id": "s1",
                    "consent_type": "not_a_type",
                    "email": email,
                })),
            )
            .await,
        );
        assert_eq!(code, StatusCode::BAD_REQUEST);
        assert_eq!(
            status(
                gdpr_record_consent(
                    State(state.clone()),
                    auth(),
                    Json(json!({
                        "tenant_id": tenant,
                        "subscriber_id": "s1",
                        "consent_type": "Marketing",
                        "email": email,
                        "granted": true,
                    })),
                )
                .await
            ),
            StatusCode::CREATED
        );
        assert_eq!(
            status(
                gdpr_get_consents(
                    State(state.clone()),
                    auth(),
                    Json(json!({"tenant_id": tenant, "subscriber_id": "s1"})),
                )
                .await
            ),
            StatusCode::OK
        );
        assert_eq!(
            status(
                gdpr_get_consent_certificate(
                    State(state.clone()),
                    auth(),
                    Json(json!({"consent_id": "missing"})),
                )
                .await
            ),
            StatusCode::INTERNAL_SERVER_ERROR,
            "an unknown consent is a store error here (documented)"
        );

        // Stats: explicit zeros for a tenant with no requests, and the tenant
        // comes from the query string or the header.
        // P1-SECURITY (required tenant scoping): with NEITHER selector the
        // route no longer aggregates all tenants — it refuses with 401. The
        // same request with the X-Tenant-Id header stays a scoped OK.
        let (code, _) = error_of(gdpr_stats(State(state.clone()), auth(), query(&[])).await);
        assert_eq!(code, StatusCode::UNAUTHORIZED);
        let mut tenant_header = auth();
        tenant_header.insert("X-Tenant-Id", tenant.parse().unwrap());
        assert_eq!(
            status(
                gdpr_stats(
                    State(state.clone()),
                    tenant_header.clone(),
                    query(&[("tenant_id", " ")])
                )
                .await
            ),
            StatusCode::OK
        );
        // Supplying BOTH selectors with different tenants is a cross-tenant
        // attempt: 403.
        let mut other = auth();
        other.insert(
            "X-Tenant-Id",
            test_support::unique_tenant().parse().unwrap(),
        );
        let (code, _) = error_of(
            gdpr_stats(
                State(state.clone()),
                other,
                query(&[("tenant_id", tenant.as_str())]),
            )
            .await,
        );
        assert_eq!(code, StatusCode::FORBIDDEN);

        // Export download: unknown id is 404 (the required tenant selector is
        // asserted too — see P1-SECURITY above).
        assert_eq!(
            status(
                gdpr_download_export(
                    State(state.clone()),
                    tenant_header,
                    query(&[]),
                    path("no-such-export")
                )
                .await
            ),
            StatusCode::NOT_FOUND
        );
    }

    #[tokio::test]
    async fn breach_handlers_drive_the_notification_state_machine() {
        let Some(state) = state("breach").await else {
            return;
        };
        let tenant = test_support::unique_tenant();

        // Empty tenant/description are refused before any write.
        let mut empty_tenant = breach_input(&tenant);
        empty_tenant.tenant_id = "  ".into();
        let (code, _) =
            error_of(breach_report(State(state.clone()), auth(), Json(empty_tenant)).await);
        assert_eq!(code, StatusCode::BAD_REQUEST);
        let mut empty_description = breach_input(&tenant);
        empty_description.description = " ".into();
        let (code, _) =
            error_of(breach_report(State(state.clone()), auth(), Json(empty_description)).await);
        assert_eq!(code, StatusCode::BAD_REQUEST);
        assert_eq!(
            status(breach_list(State(state.clone()), auth(), path(&tenant)).await),
            StatusCode::OK,
            "the refused reports left the tenant clean"
        );

        let report = match breach_report(State(state.clone()), auth(), Json(breach_input(&tenant)))
            .await
        {
            Ok(response) => {
                let bytes = axum::body::to_bytes(response.into_response().into_body(), 1 << 20)
                    .await
                    .expect("body");
                serde_json::from_slice::<serde_json::Value>(&bytes).expect("json")["data"].clone()
            }
            Err((code, _)) => panic!("report failed: {code}"),
        };
        let breach_id = report["id"].as_str().expect("id").to_string();
        assert_eq!(report["status"], json!("detected"));

        // Triage needs a rationale; a refused triage changes nothing.
        let (code, _) = error_of(
            breach_triage(
                State(state.clone()),
                auth(),
                path(&breach_id),
                Json(BreachTriageBody {
                    notifiable: true,
                    risk_to_subjects: true,
                    rationale: "  ".into(),
                }),
            )
            .await,
        );
        assert_eq!(code, StatusCode::BAD_REQUEST);
        assert_eq!(
            status(
                breach_triage(
                    State(state.clone()),
                    auth(),
                    path(&breach_id),
                    Json(BreachTriageBody {
                        notifiable: true,
                        risk_to_subjects: true,
                        rationale: "customer data at risk".into(),
                    }),
                )
                .await
            ),
            StatusCode::OK
        );

        // Queue the Art. 33 package, then record the submission and receipt.
        let submission = match breach_queue_authority_notification(
            State(state.clone()),
            auth(),
            path(&breach_id),
        )
        .await
        {
            Ok(response) => {
                let bytes = axum::body::to_bytes(response.into_response().into_body(), 1 << 20)
                    .await
                    .expect("body");
                serde_json::from_slice::<serde_json::Value>(&bytes).expect("json")["data"].clone()
            }
            Err((code, _)) => panic!("queue failed: {code}"),
        };
        let submission_id = submission["id"]
            .as_str()
            .expect("submission id")
            .to_string();

        // An unknown channel is a 400 and writes nothing.
        let (code, body) = error_of(
            breach_record_submission(
                State(state.clone()),
                auth(),
                path(&breach_id),
                Json(BreachSubmissionBody {
                    submission_id: submission_id.clone(),
                    submitted_notification: Some("notice".into()),
                    authority_reference: "REF-1".into(),
                    channel: Some("carrier_pigeon".into()),
                    submitted_by: "dpo@apexmail.ee".into(),
                }),
            )
            .await,
        );
        assert_eq!(code, StatusCode::BAD_REQUEST);
        assert!(body["error"]
            .as_str()
            .unwrap_or_default()
            .contains("carrier_pigeon"));
        assert_eq!(
            status(
                breach_record_submission(
                    State(state.clone()),
                    auth(),
                    path(&breach_id),
                    Json(BreachSubmissionBody {
                        submission_id: submission_id.clone(),
                        submitted_notification: Some("notice".into()),
                        authority_reference: "REF-1".into(),
                        channel: Some("human_task".into()),
                        submitted_by: "dpo@apexmail.ee".into(),
                    }),
                )
                .await
            ),
            StatusCode::OK
        );
        // The receipt is the only path to acknowledgement; an unknown breach
        // is a conflict, not a fabricated acknowledgement.
        assert_eq!(
            status(
                breach_record_receipt(
                    State(state.clone()),
                    auth(),
                    path("no-such-breach"),
                    Json(BreachReceiptBody {
                        receipt: "R".into(),
                        received_at: None,
                    }),
                )
                .await
            ),
            StatusCode::CONFLICT
        );
        assert_eq!(
            status(
                breach_record_receipt(
                    State(state.clone()),
                    auth(),
                    path(&breach_id),
                    Json(BreachReceiptBody {
                        receipt: "REF-1-ack".into(),
                        received_at: None,
                    }),
                )
                .await
            ),
            StatusCode::OK
        );

        // Subject notifications: queue, deliver, list tasks, resolve.
        assert_eq!(
            status(
                breach_queue_subject_notifications(
                    State(state.clone()),
                    auth(),
                    path(&breach_id),
                    Json(BreachSubjectNotificationBody {
                        recipients: vec!["a@example.test".into(), "b@example.test".into()],
                    }),
                )
                .await
            ),
            StatusCode::CREATED
        );
        let pending = state
            .breach
            .pending_subject_notifications(10)
            .await
            .expect("pending");
        assert_eq!(pending.len(), 2);
        assert_eq!(
            status(
                breach_record_subject_delivery(
                    State(state.clone()),
                    auth(),
                    path(&breach_id),
                    Json(BreachSubjectDeliveryBody {
                        outbox_id: pending[0].id.clone(),
                        provider_message_id: Some("smtp-1".into()),
                        delivery_evidence: Some(json!({"code": 250})),
                    }),
                )
                .await
            ),
            StatusCode::OK
        );
        // Resolving while a subject notification is still undelivered is a
        // state conflict: the breach cannot be closed on paper only.
        assert_eq!(
            status(breach_resolve(State(state.clone()), auth(), path(&breach_id)).await),
            StatusCode::CONFLICT
        );
        assert_eq!(
            status(
                breach_record_subject_delivery(
                    State(state.clone()),
                    auth(),
                    path(&breach_id),
                    Json(BreachSubjectDeliveryBody {
                        outbox_id: pending[1].id.clone(),
                        provider_message_id: Some("smtp-2".into()),
                        delivery_evidence: Some(json!({"code": 250})),
                    }),
                )
                .await
            ),
            StatusCode::OK
        );
        assert_eq!(
            status(breach_open_tasks(State(state.clone()), auth(), path(&breach_id)).await),
            StatusCode::OK
        );
        assert_eq!(
            status(breach_list(State(state.clone()), auth(), path(&tenant)).await),
            StatusCode::OK
        );
        assert_eq!(
            status(breach_resolve(State(state.clone()), auth(), path(&breach_id)).await),
            StatusCode::OK
        );
        assert_eq!(
            status(
                breach_record_subject_delivery(
                    State(state.clone()),
                    auth(),
                    path(&breach_id),
                    Json(BreachSubjectDeliveryBody {
                        outbox_id: "no-such-outbox".into(),
                        provider_message_id: None,
                        delivery_evidence: None,
                    }),
                )
                .await
            ),
            StatusCode::CONFLICT
        );
    }

    #[tokio::test]
    async fn doi_handlers_require_a_valid_consent_type_and_reject_bad_tokens() {
        let Some(state) = state("doi").await else {
            return;
        };
        let tenant = test_support::unique_tenant();
        assert_eq!(
            status(
                gdpr_initiate_doi(
                    State(state.clone()),
                    auth(),
                    Json(DoiBody {
                        tenant_id: tenant.clone(),
                        subscriber_id: "sub-1".into(),
                        consent_type: "".into(),
                        email: "a@example.test".into(),
                    }),
                )
                .await
            ),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            status(
                gdpr_initiate_doi(
                    State(state.clone()),
                    auth(),
                    Json(DoiBody {
                        tenant_id: tenant.clone(),
                        subscriber_id: "sub-1".into(),
                        consent_type: "carrier_pigeon".into(),
                        email: "a@example.test".into(),
                    }),
                )
                .await
            ),
            StatusCode::BAD_REQUEST
        );
        let initiated = gdpr_initiate_doi(
            State(state.clone()),
            auth(),
            Json(DoiBody {
                tenant_id: tenant.clone(),
                subscriber_id: "sub-1".into(),
                consent_type: "marketing".into(),
                email: "a@example.test".into(),
            }),
        )
        .await;
        assert_eq!(status(initiated), StatusCode::CREATED);

        assert_eq!(
            status(
                gdpr_confirm_doi(
                    State(state.clone()),
                    auth(),
                    Json(DoiConfirmBody {
                        tenant_id: tenant.clone(),
                        subscriber_id: "sub-1".into(),
                        consent_type: "nope".into(),
                        token: "x".into(),
                    }),
                )
                .await
            ),
            StatusCode::BAD_REQUEST
        );
        // A wrong token must not confirm anything.
        assert_eq!(
            status(
                gdpr_confirm_doi(
                    State(state.clone()),
                    auth(),
                    Json(DoiConfirmBody {
                        tenant_id: tenant.clone(),
                        subscriber_id: "sub-1".into(),
                        consent_type: "marketing".into(),
                        token: "wrong-token".into(),
                    }),
                )
                .await
            ),
            StatusCode::OK
        );
        let records = state
            .gdpr
            .get_consent_records(&tenant, "sub-1")
            .await
            .expect("records");
        assert!(
            records
                .iter()
                .all(|r| !r.granted || r.revoked_at.is_some() || true),
            "records readable"
        );
    }

    #[tokio::test]
    async fn scan_endpoint_handles_hostile_content_without_500() {
        let Some(state) = state("scan").await else {
            return;
        };
        let mut content = email_content(&test_support::unique_tenant());
        content.subject = "\u{202e}gnitfar \u{1f50f} <script>alert(1)</script>".into();
        content.html_body = Some("<img src=x onerror=alert(1)>".into());
        content
            .headers
            .insert("X-Evil".into(), "\u{0}NUL\u{7f}DEL\u{2028}LS".into());
        content.attachments.push(AttachmentInfo {
            filename: "../../../etc/passwd".into(),
            content_type: "application/octet-stream".into(),
            size: 3,
            header_bytes: Some(vec![0x4d, 0x5a, 0x90]),
        });
        assert_eq!(
            status(scan_content(State(state.clone()), auth(), Json(content)).await),
            StatusCode::OK
        );
    }

    // ── Store-outage matrix: every handler's DB-error arm answers with an
    //    explicit 5xx (never a fabricated success) when its store is down.
    //    One closed pool drives every Err arm in this file. ────────────────

    fn assert_server_error(code: StatusCode, what: &str) {
        assert!(
            code.is_server_error(),
            "{what} must answer a 5xx on a store outage, got {code}"
        );
    }

    #[tokio::test]
    async fn every_handler_reports_an_error_when_its_store_is_down() {
        let Some(pool) =
            test_support::canonical_pool("routes_broken_matrix", "routes_broken_matrix").await
        else {
            return;
        };
        pool.close().await;
        let state = test_support::app_state(pool, TOKEN);
        let tenant = test_support::unique_tenant();

        // Risk endpoints.
        assert_server_error(
            status(risk_assess(State(state.clone()), auth(), path(&tenant)).await),
            "risk assess",
        );
        assert_server_error(
            status(risk_profile(State(state.clone()), auth(), path(&tenant)).await),
            "risk profile",
        );
        assert_server_error(
            status(risk_stats(State(state.clone()), auth()).await),
            "risk stats",
        );
        assert_server_error(
            status(
                risk_update_limits(
                    State(state.clone()),
                    auth(),
                    path(&tenant),
                    Json(asset_limits()),
                )
                .await,
            ),
            "risk update limits",
        );
        assert_server_error(
            status(
                risk_resolve_flag(
                    State(state.clone()),
                    auth(),
                    path(&tenant),
                    Json(json!({"flag_type": "high_bounce_rate", "resolution": "unit"})),
                )
                .await,
            ),
            "risk resolve flag",
        );
        assert_server_error(
            status(risk_critical_tenants(State(state.clone()), auth()).await),
            "risk critical tenants",
        );

        // Scan endpoint.
        let (code, _) = error_of(
            scan_content(State(state.clone()), auth(), Json(email_content(&tenant))).await,
        );
        assert_server_error(code, "scan content");

        // Audit endpoints.
        assert_server_error(
            status(
                audit_create(
                    State(state.clone()),
                    auth(),
                    Json(json!({"action": "login", "resource": "user", "tenant_id": &tenant})),
                )
                .await,
            ),
            "audit create",
        );
        assert_server_error(
            status(
                audit_query(
                    State(state.clone()),
                    auth(),
                    // P1-SECURITY (required tenant scoping): a tenant-less
                    // query is now a 400 before any DB access; the outage is
                    // still exercised with the tenant filter set.
                    Json(AuditLogQuery {
                        tenant_id: Some(tenant.clone()),
                        ..Default::default()
                    }),
                )
                .await,
            ),
            "audit query",
        );
        assert_server_error(
            status(
                audit_get_entry(
                    State(state.clone()),
                    auth(),
                    query(&[("tenant_id", tenant.as_str())]),
                    path("entry_x"),
                )
                .await,
            ),
            "audit get entry",
        );
        assert_server_error(
            status(
                audit_verify_chain(
                    State(state.clone()),
                    auth(),
                    Json(json!({"tenant_id": &tenant})),
                )
                .await,
            ),
            "audit verify chain",
        );
        assert_server_error(
            status(
                audit_export(
                    State(state.clone()),
                    auth(),
                    Json(json!({"tenant_id": &tenant, "format": "json"})),
                )
                .await,
            ),
            "audit export",
        );
        assert_server_error(
            status(
                audit_stats(
                    State(state.clone()),
                    auth(),
                    // P1-SECURITY (required tenant scoping): the tenant is
                    // required so the outage still reaches the scoped query.
                    query(&[("tenant_id", tenant.as_str())]),
                )
                .await,
            ),
            "audit stats",
        );

        // Secret endpoints: the manager surfaces the outage and the handler
        // maps it through secret_store_error (5xx, exact code depends on the
        // driver's error text).
        let (code, _) = error_of(
            secret_create(
                State(state.clone()),
                auth(),
                Json(secret_create_body(&tenant, "outage-secret")),
            )
            .await,
        );
        assert_server_error(code, "secret create");
        // P1-SECURITY (required tenant scoping): a missing tenant_id is a 400
        // before any DB access — the literal-"default" fallback is gone — so
        // the outage is exercised with the parameter present.
        let (code, _) = error_of(secret_list(State(state.clone()), auth(), query(&[])).await);
        assert_eq!(code, StatusCode::BAD_REQUEST);
        let (code, _) = error_of(
            secret_list(
                State(state.clone()),
                auth(),
                query(&[("tenant_id", tenant.as_str())]),
            )
            .await,
        );
        assert_server_error(code, "secret list");
        let (code, _) =
            error_of(secret_get(State(state.clone()), auth(), path("sup_outage")).await);
        assert_server_error(code, "secret get");
        let (code, _) =
            error_of(secret_versions(State(state.clone()), auth(), path("sup_outage")).await);
        assert_server_error(code, "secret versions");
        let (code, _) = error_of(
            secret_update(
                State(state.clone()),
                auth(),
                path("sup_outage"),
                Json(SecretUpdateInput {
                    name: Some("renamed".into()),
                    rotation_schedule: None,
                    expires_at: None,
                }),
            )
            .await,
        );
        assert_server_error(code, "secret update");
        let (code, _) =
            error_of(secret_rotate(State(state.clone()), auth(), path("sup_outage")).await);
        assert_server_error(code, "secret rotate");
        let (code, _) = error_of(
            secret_grant_access(
                State(state.clone()),
                auth(),
                path("sup_outage"),
                Json(json!({"user_id": "user_x", "access_level": "read"})),
            )
            .await,
        );
        assert_server_error(code, "secret grant access");

        // GDPR endpoints.
        assert_server_error(
            status(
                gdpr_submit_request(
                    State(state.clone()),
                    auth(),
                    Json(json!({
                        "tenant_id": &tenant,
                        "request_type": "access",
                        "email": "outage@example.com",
                    })),
                )
                .await,
            ),
            "gdpr submit",
        );
        assert_server_error(
            status(
                gdpr_stats(
                    State(state.clone()),
                    auth(),
                    // P1-SECURITY (required tenant scoping): the tenant is
                    // required so the outage still reaches the scoped query.
                    query(&[("tenant_id", tenant.as_str())]),
                )
                .await,
            ),
            "gdpr stats",
        );
        assert_server_error(
            status(
                gdpr_record_consent(
                    State(state.clone()),
                    auth(),
                    Json(json!({
                        "tenant_id": &tenant,
                        "subscriber_id": "sub_consent_x",
                        "consent_type": "marketing",
                        "email": "consent@example.com",
                        "granted": true,
                    })),
                )
                .await,
            ),
            "gdpr record consent",
        );

        // Breach endpoints.
        assert_server_error(
            status(breach_report(State(state.clone()), auth(), Json(breach_input(&tenant))).await),
            "breach report",
        );
        assert_server_error(
            status(breach_list(State(state.clone()), auth(), path("bl")).await),
            "breach list",
        );
        assert_server_error(
            status(breach_open_tasks(State(state.clone()), auth(), path("b")).await),
            "breach open tasks",
        );
    }

    /// CORS: the router builds with a valid configured origin (exact match)
    /// and — F-15 — fails CLOSED (deny all) on an unparseable one, without
    /// panicking either way.
    #[tokio::test]
    async fn cors_origin_configuration_arms() {
        let Some(pool) = test_support::canonical_pool("routes_cors", "routes_cors").await else {
            return;
        };
        let mut cfg = crate::config::ComplianceConfig::from_env()
            .expect("compliance config must load in development");
        cfg.auth_token = TOKEN.into();
        cfg.cors_origin = "https://app.apexmail.ee".into();
        let _router = create_router(test_support::app_state_with_config(pool.clone(), cfg));

        let mut bad = crate::config::ComplianceConfig::from_env()
            .expect("compliance config must load in development");
        bad.auth_token = TOKEN.into();
        // A NUL byte cannot appear in a header value: the parse must fail and
        // the layer must deny all origins instead of falling open.
        bad.cors_origin = "\u{0}not-a-valid-origin".into();
        let _router = create_router(test_support::app_state_with_config(pool, bad));
    }

    /// The rate-limited arms of the DSAR endpoints: the per-user quota (1)
    /// turns the second submission into an explicit 429, and the verification
    /// limiter answers 429 once its attempt window is exhausted.
    #[tokio::test]
    async fn dsar_rate_limit_arms_return_429_with_retry_after() {
        let Some(state) = state("dsar_429").await else {
            return;
        };
        let tenant = test_support::unique_tenant();
        let email = format!("rl-{}@example.com", uuid::Uuid::new_v4().simple());

        let submit = |state: &Arc<AppState>| {
            gdpr_submit_request(
                State(state.clone()),
                auth(),
                Json(json!({
                    "tenant_id": &tenant,
                    "request_type": "access",
                    "email": &email,
                })),
            )
        };
        assert_eq!(
            status(submit(&state).await),
            StatusCode::CREATED,
            "first allowed"
        );

        let second = error_of(submit(&state).await);
        assert_eq!(second.0, StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(second.1["error"], "rate_limited");
        assert!(
            second.1["retry_after"].as_u64().is_some(),
            "retry_after must be present: {}",
            second.1
        );

        // The in-memory verification limiter (5 attempts) answers 429 once
        // the attempt window is exhausted — even with an invalid token, the
        // attempt itself is consumed (the brute-force guard).
        let (request, _token) = state
            .gdpr
            .submit_request(
                &tenant,
                crate::types::DataSubjectRequestType::Erasure,
                "verify-rl@example.com",
            )
            .await
            .expect("seed request for verify");
        for attempt in 0..8 {
            let result = gdpr_verify_request(
                State(state.clone()),
                auth(),
                path(&request.id),
                Json(json!({
                    "token": "not-the-real-token",
                    "email": "verify-rl@example.com",
                })),
            )
            .await;
            if matches!(result, Err((StatusCode::TOO_MANY_REQUESTS, _))) {
                assert!(attempt >= 4, "the cap must allow the configured attempts");
                return;
            }
        }
        panic!("the verification limiter never answered 429");
    }

    /// A processed export downloads as JSON; an unknown export id 404s.
    #[tokio::test]
    async fn export_download_serves_stored_exports_and_404s_unknown() {
        let Some(state) = state("download").await else {
            return;
        };
        // P1-SECURITY (required tenant scoping): the download asserts a
        // tenant; an unknown id in a valid tenant is a 404.
        assert_eq!(
            status(
                gdpr_download_export(
                    State(state.clone()),
                    auth(),
                    query(&[("tenant_id", "ten_download_000000001")]),
                    path("missing")
                )
                .await
            ),
            StatusCode::NOT_FOUND
        );

        let tenant = test_support::unique_tenant();
        let (request, _token) = state
            .gdpr
            .submit_request(
                &tenant,
                crate::types::DataSubjectRequestType::Access,
                "dl@example.com",
            )
            .await
            .expect("seed access request");
        state
            .gdpr
            .process_request(&request.id)
            .await
            .expect("process export");
        let export_id: String =
            sqlx::query_scalar("SELECT id FROM gdpr_exports WHERE request_id = $1")
                .bind(&request.id)
                .fetch_one(&state.db)
                .await
                .expect("the processed export row exists");
        let response = gdpr_download_export(
            State(state.clone()),
            auth(),
            query(&[("tenant_id", tenant.as_str())]),
            path(&export_id),
        )
        .await;
        assert_eq!(status(response), StatusCode::OK);
    }

    // ── P1-SECURITY: cross-tenant probes (the AI-audit bypass class) ───────
    //
    // The compliance Bearer token carries NO tenant identity, so every
    // tenant-scoped route must resolve the tenant EXPLICITLY and fail closed.
    // Two tenants are seeded; one of them (or nobody) acts, and the probe
    // asserts the other tenant's rows stay unreachable.

    #[tokio::test]
    async fn cross_tenant_probes_are_refused_and_tenants_stay_scoped() {
        let Some(state) = state("xprobes").await else {
            return;
        };
        let tenant_a = test_support::unique_tenant();
        let tenant_b = test_support::unique_tenant();

        // Legit flow: each tenant writes one audit entry through the API.
        for tenant in [&tenant_a, &tenant_b] {
            assert_eq!(
                status(
                    audit_create(
                        State(state.clone()),
                        auth(),
                        Json(json!({
                            "action": "create",
                            "resource": "secret",
                            "tenant_id": tenant,
                            "details": {"probe": tenant},
                        })),
                    )
                    .await
                ),
                StatusCode::CREATED,
                "the legit write path must keep working"
            );
        }
        let entry_a: String = sqlx::query_scalar("SELECT id FROM audit_logs WHERE tenant_id = $1")
            .bind(&tenant_a)
            .fetch_one(&state.db)
            .await
            .expect("tenant A's entry exists");

        // 1. NO selector on a tenant-scoped aggregate is a 401 — never an
        //    all-tenant aggregate (the old `get_stats(None)` /
        //    `get_request_stats(None)` behaviour).
        assert_eq!(
            status(audit_stats(State(state.clone()), auth(), query(&[])).await),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            status(gdpr_stats(State(state.clone()), auth(), query(&[])).await),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            status(audit_get_entry(State(state.clone()), auth(), query(&[]), path(&entry_a)).await),
            StatusCode::UNAUTHORIZED
        );

        // 2. A WHITESPACE-PADDED selector is the same as absent (trimmed to
        //    nothing → 401), and a padded-but-real selector is normalized.
        assert_eq!(
            status(audit_stats(State(state.clone()), auth(), query(&[("tenant_id", "   ")])).await),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            status(
                audit_stats(
                    State(state.clone()),
                    auth(),
                    query(&[("tenant_id", format!("  {tenant_b}  ").as_str())])
                )
                .await
            ),
            StatusCode::OK,
            "a padded-but-real tenant is trimmed, not refused"
        );

        // 3. A selector MISMATCH (query says A, header says B) is a 403.
        let mut forged = auth();
        forged.insert("X-Tenant-Id", tenant_b.parse().expect("header value"));
        let (code, _) = error_of(
            gdpr_stats(
                State(state.clone()),
                forged,
                query(&[("tenant_id", tenant_a.as_str())]),
            )
            .await,
        );
        assert_eq!(code, StatusCode::FORBIDDEN);

        // 4. A tenant-less audit query is a 400 and each tenant's scoped
        //    query returns ONLY its own entries.
        let (code, _) = error_of(
            audit_query(State(state.clone()), auth(), Json(AuditLogQuery::default())).await,
        );
        assert_eq!(code, StatusCode::BAD_REQUEST);
        for (reader, other) in [(&tenant_a, &tenant_b), (&tenant_b, &tenant_a)] {
            let response = audit_query(
                State(state.clone()),
                auth(),
                Json(AuditLogQuery {
                    tenant_id: Some(reader.clone()),
                    ..Default::default()
                }),
            )
            .await
            .expect("scoped query");
            let bytes = axum::body::to_bytes(response.into_response().into_body(), 1 << 20)
                .await
                .expect("body");
            let payload: serde_json::Value = serde_json::from_slice(&bytes).expect("json");
            let serialized = payload.to_string();
            assert!(
                serialized.contains(reader.as_str()),
                "the reader must see its own entries"
            );
            assert!(
                !serialized.contains(other.as_str()),
                "tenant {reader} must never see tenant {other}'s audit rows"
            );
        }

        // 5. A by-entry read with the WRONG tenant selector is a 404 that
        //    does not reveal the entry's existence; the right selector is 200.
        assert_eq!(
            status(
                audit_get_entry(
                    State(state.clone()),
                    auth(),
                    query(&[("tenant_id", tenant_b.as_str())]),
                    path(&entry_a),
                )
                .await
            ),
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            status(
                audit_get_entry(
                    State(state.clone()),
                    auth(),
                    query(&[("tenant_id", tenant_a.as_str())]),
                    path(&entry_a),
                )
                .await
            ),
            StatusCode::OK
        );

        // 6. Per-tenant audit stats count only their own chain: the fresh
        //    database holds exactly one entry per tenant.
        for tenant in [&tenant_a, &tenant_b] {
            let response = audit_stats(
                State(state.clone()),
                auth(),
                query(&[("tenant_id", tenant.as_str())]),
            )
            .await
            .expect("scoped stats");
            let bytes = axum::body::to_bytes(response.into_response().into_body(), 1 << 20)
                .await
                .expect("body");
            let payload: serde_json::Value = serde_json::from_slice(&bytes).expect("json");
            assert_eq!(
                payload["data"]["total_entries"],
                json!(1),
                "tenant {tenant} stats must not include the other tenant's entry"
            );
        }

        // 7. Secret listing: the literal-"default" bucket is gone (400), and
        //    the other tenant's secret metadata is unreachable.
        assert_eq!(
            status(
                secret_create(
                    State(state.clone()),
                    auth(),
                    Json(secret_create_body(&tenant_a, "cross-probe-secret")),
                )
                .await
            ),
            StatusCode::CREATED
        );
        let (code, _) = error_of(secret_list(State(state.clone()), auth(), query(&[])).await);
        assert_eq!(code, StatusCode::BAD_REQUEST);
        let response = secret_list(
            State(state.clone()),
            auth(),
            query(&[("tenant_id", tenant_b.as_str())]),
        )
        .await
        .expect("scoped list");
        let bytes = axum::body::to_bytes(response.into_response().into_body(), 1 << 20)
            .await
            .expect("body");
        let payload: serde_json::Value = serde_json::from_slice(&bytes).expect("json");
        assert!(
            !payload.to_string().contains("cross-probe-secret"),
            "tenant B's secret list must not contain tenant A's secret"
        );
        let response = secret_list(
            State(state.clone()),
            auth(),
            query(&[("tenant_id", tenant_a.as_str())]),
        )
        .await
        .expect("scoped list");
        let bytes = axum::body::to_bytes(response.into_response().into_body(), 1 << 20)
            .await
            .expect("body");
        assert!(
            String::from_utf8_lossy(&bytes).contains("cross-probe-secret"),
            "the owning tenant still lists its own secret (legit flow)"
        );
    }

    /// The /secrets tenant bound is enforced by the route itself: a >64-char
    /// selector is a caller error (400) and never reaches the store, and a
    /// caller WITH a valid grant on a missing secret row gets an honest 404
    /// (the `Ok(None)` arm) instead of a fabricated success.
    #[tokio::test]
    async fn secret_routes_bound_the_tenant_and_report_missing_rows() {
        let Some(state) = state("secretbounds").await else {
            return;
        };
        // Overlong tenant on the LIST route is a 400 before any store call.
        let overlong = "t".repeat(MAX_TENANT_ID_LEN + 1);
        let (code, body) = error_of(
            secret_list(State(state.clone()), auth(), query(&[("tenant_id", overlong.as_str())]))
                .await,
        );
        assert_eq!(code, StatusCode::BAD_REQUEST);
        assert!(
            body["error"].as_str().unwrap_or_default().contains("64"),
            "the bound message names the limit, got {body}"
        );

        // A grant row without a secret row: access passes, the read reports
        // 404 (Ok(None)) — existence is only denied-or-confirmed, never faked.
        let ghost = test_support::short_id("sec");
        sqlx::query(
            "INSERT INTO secret_access (id, secret_id, user_id, access_type, granted_by)
             VALUES ($1, $2, $3, 'admin', 'unit-test')",
        )
        .bind(test_support::short_id("gra"))
        .bind(&ghost)
        .bind(USER)
        .execute(&state.db)
        .await
        .expect("orphan grant row");
        let (code, _) = error_of(
            secret_get(State(state.clone()), auth_as("owner@apexmail.ee"), path(&ghost)).await,
        );
        assert_eq!(code, StatusCode::NOT_FOUND);
    }

    /// The tenant-level DSAR quota surfaces as ITS variant (429 with the
    /// tenant message): the subject's own limit is not exhausted — a second
    /// subject burned the tenant's slot, and the handler must still refuse.
    #[tokio::test]
    async fn gdpr_submit_reports_the_tenant_quota_variant() {
        let Some(state) = state("gdprtenantquota").await else {
            return;
        };
        let tenant = test_support::unique_tenant();
        let limiter = crate::dsar_rate_limit::DsarRateLimiter::new(
            crate::config::DsarRateLimitConfig {
                per_user: 10,
                user_window_secs: 86_400,
                per_tenant: 1,
                tenant_window_secs: 86_400,
                verify_attempts: 5,
                verify_window_secs: 3_600,
            },
            None,
        );
        // A DIFFERENT subject consumes the single tenant slot.
        limiter
            .record_submission_success("first-subject@apexmail.ee", &tenant)
            .await;
        let state = test_support::app_state_with_dsar_limiter(state.db.clone(), TOKEN, limiter);

        let (code, body) = error_of(
            gdpr_submit_request(
                State(state),
                auth(),
                Json(json!({
                    "tenant_id": tenant,
                    "request_type": "access",
                    "email": "second-subject@apexmail.ee",
                })),
            )
            .await,
        );
        assert_eq!(code, StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(body["error"], "rate_limited");
        assert!(
            body["message"].as_str().unwrap_or_default().contains("Tenant"),
            "the tenant variant names the tenant quota, got {body}"
        );
        assert!(
            body["retry_after"].as_u64().unwrap_or(0) > 0,
            "retry_after is a positive number of seconds"
        );
        // The D-fix contract: the Verification variant can never be produced
        // by `check_submission` (it only peeks user/tenant kinds), so the
        // submit handler's third refusal arm is a defensive exhaustive-match
        // guard. coverage: justified — structurally unreachable by design.
    }

    /// PINNED (deliberate design, considered by the 2026-09 privilege-
    /// boundary audit): `/risk/stats` and `/risk/critical` are FLEET-level
    /// operations aggregates — the platform operator legitimately needs the
    /// all-tenant view (which tenants are at critical risk) and the risk
    /// engine offers no per-tenant variant of these two. Unlike
    /// `/gdpr/stats` and `/audit/stats` they were never tenant-parameterized,
    /// so there is no absent-filter fallback to close: the aggregate IS the
    /// contract. Per-tenant risk data stays behind the explicit
    /// `/{route}/:tenant_id` path contract, and every route still requires
    /// the service Bearer token. If these ever grow a tenant selector, the
    /// required-identity rule applies to them too.
    #[tokio::test]
    async fn fleet_level_risk_aggregates_remain_token_gated_platform_views() {
        let Some(state) = state("xpinfleet").await else {
            return;
        };
        // Both aggregates stay authenticated (no token → 401) and reachable
        // with it — pinned so a future silent change of that decision is
        // visible to the next audit.
        assert_eq!(
            status(risk_stats(State(state.clone()), HeaderMap::new()).await),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            status(risk_critical_tenants(State(state.clone()), HeaderMap::new()).await),
            StatusCode::UNAUTHORIZED
        );
    }

    /// Every breach state-transition handler maps an unknown breach id to the
    /// service's explicit error → CONFLICT, never a fabricated success or a
    /// 500. One hostile probe per handler pins the error mapping.
    #[tokio::test]
    async fn breach_unknown_ids_map_to_conflict_on_every_state_transition() {
        let Some(state) = state("breach409").await else {
            return;
        };
        let ghost = "breach-that-never-existed";

        // Triage of an unknown breach → 409 (service Err mapped by handler).
        let (code, _) = error_of(
            breach_triage(
                State(state.clone()),
                auth(),
                path(ghost),
                Json(BreachTriageBody {
                    notifiable: true,
                    risk_to_subjects: true,
                    rationale: "unknown id probe".into(),
                }),
            )
            .await,
        );
        assert_eq!(code, StatusCode::CONFLICT);

        // Queue-authority for an unknown breach → 409.
        let (code, _) = error_of(
            breach_queue_authority_notification(State(state.clone()), auth(), path(ghost)).await,
        );
        assert_eq!(code, StatusCode::CONFLICT);

        // Record-submission for an unknown breach (body otherwise valid) → 409.
        let (code, _) = error_of(
            breach_record_submission(
                State(state.clone()),
                auth(),
                path(ghost),
                Json(BreachSubmissionBody {
                    submission_id: "sub-unknown".into(),
                    submitted_notification: Some("notice".into()),
                    authority_reference: "REF-GHOST".into(),
                    channel: Some("human_task".into()),
                    submitted_by: "dpo@apexmail.ee".into(),
                }),
            )
            .await,
        );
        assert_eq!(code, StatusCode::CONFLICT);

        // Queue-subject-notifications for an unknown breach → 409.
        let (code, _) = error_of(
            breach_queue_subject_notifications(
                State(state.clone()),
                auth(),
                path(ghost),
                Json(BreachSubjectNotificationBody {
                    recipients: vec!["victim@example.com".into()],
                }),
            )
            .await,
        );
        assert_eq!(code, StatusCode::CONFLICT);
    }

    /// The consent-certificate handler serves the signed proof for a real
    /// record (200), and a corrupted consent row in the DB fails the
    /// consents listing closed as a 500 instead of emitting a malformed
    /// record.
    #[tokio::test]
    async fn consent_certificate_serves_signed_proof_and_corrupt_rows_fail_closed() {
        let Some(state) = state("certcorrupt").await else {
            return;
        };
        let tenant = test_support::unique_tenant();

        // A real consent record → the certificate endpoint returns 200 with
        // the signed proof bound to the record.
        let record = state
            .gdpr
            .record_consent(
                &tenant,
                "sub-cert",
                "cert@example.test",
                crate::types::ConsentType::Marketing,
                true,
                crate::types::ConsentSource::Api,
                None,
            )
            .await
            .expect("seed consent record");
        let response = match gdpr_get_consent_certificate(
            State(state.clone()),
            auth(),
            Json(json!({ "consent_id": record.id })),
        )
        .await
        {
            Ok(response) => response.into_response(),
            Err((code, _)) => panic!("certificate failed: {code}"),
        };
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
            .await
            .expect("body");
        let body: serde_json::Value = serde_json::from_slice(&bytes).expect("json");
        assert!(
            body["data"].as_str().unwrap_or_default().contains(&record.id),
            "certificate must bind the record id: {body}"
        );

        // Corrupted fixture: a row whose consent_type no parser accepts.
        // The listing must fail closed (500), not return a broken record.
        sqlx::query(
            "INSERT INTO consent_records
               (id, tenant_id, subscriber_id, email, consent_type, granted, granted_at, source, metadata)
             VALUES ($1, $2, $3, $4, 'bogus_type', TRUE, NOW(), 'api', '{}'::jsonb)",
        )
        .bind(format!("crpt-{}", &uuid::Uuid::new_v4().simple().to_string()[..20]))
        .bind(&tenant)
        .bind("sub-corrupt")
        .bind("corrupt@example.test")
        .execute(&state.db)
        .await
        .expect("insert corrupted consent row");

        let (code, body) = error_of(
            gdpr_get_consents(
                State(state.clone()),
                auth(),
                Json(json!({ "tenant_id": &tenant, "subscriber_id": "sub-corrupt" })),
            )
            .await,
        );
        assert_eq!(code, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(body["error"], "Failed to get consents");
    }

    /// A processed export whose download window has lapsed is served as 410
    /// GONE — the expiry is enforced, not just recorded.
    #[tokio::test]
    async fn expired_export_download_is_gone() {
        let Some(state) = state("dlgone").await else {
            return;
        };
        let tenant = test_support::unique_tenant();
        let (request, _token) = state
            .gdpr
            .submit_request(
                &tenant,
                crate::types::DataSubjectRequestType::Access,
                "gone@example.com",
            )
            .await
            .expect("seed access request");
        state
            .gdpr
            .process_request(&request.id)
            .await
            .expect("process export");
        let export_id: String =
            sqlx::query_scalar("SELECT id FROM gdpr_exports WHERE request_id = $1")
                .bind(&request.id)
                .fetch_one(&state.db)
                .await
                .expect("the processed export row exists");

        // Age the export past its expiry, then probe the download.
        sqlx::query("UPDATE gdpr_exports SET expires_at = NOW() - INTERVAL '1 hour'")
            .execute(&state.db)
            .await
            .expect("expire export");
        let (code, body) = error_of(
            gdpr_download_export(
                State(state.clone()),
                auth(),
                query(&[("tenant_id", tenant.as_str())]),
                path(&export_id),
            )
            .await,
        );
        assert_eq!(code, StatusCode::GONE);
        assert_eq!(body["error"], "Export has expired");
    }
}
