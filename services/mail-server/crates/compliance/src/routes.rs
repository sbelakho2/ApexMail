//! HTTP routes — 30+ endpoints grouped into Risk, Content Scanning, Audit,
//! Secrets, and GDPR. Bearer token auth with timing-safe comparison.
//! Health check endpoint at GET /health.
//!
//! All endpoints under axum with shared AppState.

use axum::{
    extract::{Json, Path, Query, State},
    http::{header, HeaderMap, StatusCode},
    response::IntoResponse,
    routing::{delete, get, post, put},
    Router,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use chrono::Utc;

use crate::audit_logger::AuditLogger;
use crate::config::ComplianceConfig;
use crate::content_scanner::ContentScanner;
use crate::gdpr_automation::GdprAutomation;
use crate::risk_scoring::RiskScoringEngine;
use crate::secret_manager::SecretManager;
use crate::types::*;

// ─── Shared State ───────────────────────────────────────────────

pub struct AppState {
    pub risk_engine: RiskScoringEngine,
    pub content_scanner: ContentScanner,
    pub audit_logger: AuditLogger,
    pub secret_manager: SecretManager,
    pub gdpr: GdprAutomation,
    pub config: ComplianceConfig,
}

type S = Arc<AppState>;

// ─── Router ─────────────────────────────────────────────────────

pub fn create_router(state: S) -> Router {
    Router::new()
        // Health
        .route("/health", get(health_check))
        // Risk Scoring
        .route("/risk/assess/:tenant_id", post(risk_assess))
        .route("/risk/profile/:tenant_id", get(risk_profile))
        .route("/risk/force-reassess/:tenant_id", post(risk_force_reassess))
        .route("/risk/limits/:tenant_id", put(risk_update_limits))
        .route("/risk/flags/:tenant_id/resolve", post(risk_resolve_flag))
        .route("/risk/critical", get(risk_critical_tenants))
        .route("/risk/stats", get(risk_stats))
        // Content Scanning
        .route("/scan", post(scan_content))
        .route("/scan/spam", post(scan_spam))
        .route("/scan/phishing", post(scan_phishing))
        .route("/scan/malware", post(scan_malware))
        .route("/scan/policy/:tenant_id", post(scan_policy))
        // Audit
        .route("/audit/log", post(audit_create))
        .route("/audit/logs", get(audit_query))
        .route("/audit/verify/:tenant_id", get(audit_verify_chain))
        .route("/audit/export/:tenant_id", get(audit_export))
        .route("/audit/stats/:tenant_id", get(audit_stats))
        .route("/audit/archive", post(audit_archive))
        .route("/audit/webhooks", post(audit_register_webhook))
        // Secrets
        .route("/secrets", post(secret_create))
        .route("/secrets/:secret_id", get(secret_get))
        .route("/secrets/:secret_id", put(secret_update))
        .route("/secrets/:secret_id", delete(secret_delete))
        .route("/secrets/:secret_id/rotate", post(secret_rotate))
        .route("/secrets/:secret_id/access", post(secret_grant_access))
        .route("/secrets/:secret_id/access/:user_id", delete(secret_revoke_access))
        .route("/secrets/:secret_id/versions", get(secret_versions))
        .route("/secrets/:secret_id/rollback/:version", post(secret_rollback))
        .route("/secrets/tenant/:tenant_id", get(secrets_list))
        // GDPR
        .route("/gdpr/request", post(gdpr_submit_request))
        .route("/gdpr/request/:request_id/verify", post(gdpr_verify_request))
        .route("/gdpr/consent", post(gdpr_record_consent))
        .route("/gdpr/consent/:tenant_id/:subscriber_id", get(gdpr_get_consents))
        .route("/gdpr/double-opt-in", post(gdpr_initiate_doi))
        .route("/gdpr/double-opt-in/confirm", post(gdpr_confirm_doi))
        .route("/gdpr/stats/:tenant_id", get(gdpr_stats))
        .with_state(state)
}

// ─── Auth Middleware Helper ─────────────────────────────────────

fn extract_user_id(headers: &HeaderMap) -> Result<String, (StatusCode, &'static str)> {
    headers
        .get("x-user-id")
        .and_then(|v| v.to_str().ok())
        .map(String::from)
        .ok_or((StatusCode::UNAUTHORIZED, "Missing x-user-id header"))
}

fn verify_bearer(
    headers: &HeaderMap,
    config: &ComplianceConfig,
) -> Result<(), (StatusCode, &'static str)> {
    let auth = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .ok_or((StatusCode::UNAUTHORIZED, "Missing Authorization header"))?;

    let token = auth
        .strip_prefix("Bearer ")
        .ok_or((StatusCode::UNAUTHORIZED, "Invalid Authorization format"))?;

    if !constant_time_eq(token, &config.auth_token) {
        return Err((StatusCode::UNAUTHORIZED, "Invalid token"));
    }

    Ok(())
}

fn constant_time_eq(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.bytes().zip(b.bytes()) {
        diff |= x ^ y;
    }
    diff == 0
}

fn err_json(msg: &str) -> Json<serde_json::Value> {
    Json(serde_json::json!({ "error": msg }))
}

// ─── Health ─────────────────────────────────────────────────────

async fn health_check() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "status": "ok",
        "service": "compliance",
        "timestamp": chrono::Utc::now().to_rfc3339()
    }))
}

// ─── Risk Scoring Handlers ──────────────────────────────────────

async fn risk_assess(
    State(state): State<S>,
    headers: HeaderMap,
    Path(tenant_id): Path<String>,
) -> impl IntoResponse {
    if let Err(e) = verify_bearer(&headers, &state.config) {
        return (e.0, err_json(e.1)).into_response();
    }
    match state.risk_engine.assess_tenant(&tenant_id).await {
        Ok(profile) => (StatusCode::OK, Json(serde_json::to_value(&profile).unwrap())).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, err_json(&e)).into_response(),
    }
}

async fn risk_profile(
    State(state): State<S>,
    headers: HeaderMap,
    Path(tenant_id): Path<String>,
) -> impl IntoResponse {
    if let Err(e) = verify_bearer(&headers, &state.config) {
        return (e.0, err_json(e.1)).into_response();
    }
    match state.risk_engine.get_profile(&tenant_id).await {
        Ok(Some(profile)) => (StatusCode::OK, Json(serde_json::to_value(&profile).unwrap())).into_response(),
        Ok(None) => (StatusCode::NOT_FOUND, err_json("Profile not found")).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, err_json(&e)).into_response(),
    }
}

async fn risk_force_reassess(
    State(state): State<S>,
    headers: HeaderMap,
    Path(tenant_id): Path<String>,
) -> impl IntoResponse {
    if let Err(e) = verify_bearer(&headers, &state.config) {
        return (e.0, err_json(e.1)).into_response();
    }
    match state.risk_engine.force_reassessment(&tenant_id).await {
        Ok(profile) => (StatusCode::OK, Json(serde_json::to_value(&profile).unwrap())).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, err_json(&e)).into_response(),
    }
}

#[derive(Deserialize)]
struct UpdateLimitsBody {
    max_daily_emails: Option<i64>,
    max_hourly_emails: Option<i64>,
    max_recipients: Option<i64>,
    max_attachment_size_mb: Option<i64>,
}

async fn risk_update_limits(
    State(state): State<S>,
    headers: HeaderMap,
    Path(tenant_id): Path<String>,
    Json(body): Json<UpdateLimitsBody>,
) -> impl IntoResponse {
    if let Err(e) = verify_bearer(&headers, &state.config) {
        return (e.0, err_json(e.1)).into_response();
    }
    let limits = TenantLimits {
        max_daily_emails: body.max_daily_emails.unwrap_or(10000),
        max_hourly_emails: body.max_hourly_emails.unwrap_or(1000),
        max_recipients: body.max_recipients.unwrap_or(50),
        max_attachment_size_mb: body.max_attachment_size_mb.unwrap_or(25),
        require_double_opt_in: false,
        require_unsubscribe_link: true,
        allowed_domains: vec![],
        blocked_recipient_patterns: vec![],
    };
    match state.risk_engine.update_limits(&tenant_id, &limits).await {
        Ok(()) => (StatusCode::OK, Json(serde_json::json!({"ok": true}))).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, err_json(&e)).into_response(),
    }
}

#[derive(Deserialize)]
struct ResolveFlagBody {
    flag_type: String,
    resolution: String,
}

async fn risk_resolve_flag(
    State(state): State<S>,
    headers: HeaderMap,
    Path(tenant_id): Path<String>,
    Json(body): Json<ResolveFlagBody>,
) -> impl IntoResponse {
    if let Err(e) = verify_bearer(&headers, &state.config) {
        return (e.0, err_json(e.1)).into_response();
    }
    let flag_type = parse_risk_flag_type(&body.flag_type);
    match state
        .risk_engine
        .resolve_flag(
            &tenant_id,
            &flag_type,
            &body.resolution,
        )
        .await
    {
        Ok(()) => (StatusCode::OK, Json(serde_json::json!({"ok": true}))).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, err_json(&e)).into_response(),
    }
}

async fn risk_critical_tenants(
    State(state): State<S>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(e) = verify_bearer(&headers, &state.config) {
        return (e.0, err_json(e.1)).into_response();
    }
    match state.risk_engine.get_critical_risk_tenants().await {
        Ok(tenants) => (StatusCode::OK, Json(serde_json::to_value(&tenants).unwrap())).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, err_json(&e)).into_response(),
    }
}

async fn risk_stats(
    State(state): State<S>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(e) = verify_bearer(&headers, &state.config) {
        return (e.0, err_json(e.1)).into_response();
    }
    match state.risk_engine.get_risk_stats().await {
        Ok(stats) => (StatusCode::OK, Json(stats)).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, err_json(&e)).into_response(),
    }
}

// ─── Content Scanning Handlers ──────────────────────────────────

async fn scan_content(
    State(state): State<S>,
    headers: HeaderMap,
    Json(body): Json<ScanRequest>,
) -> impl IntoResponse {
    if let Err(e) = verify_bearer(&headers, &state.config) {
        return (e.0, err_json(e.1)).into_response();
    }
    match state
        .content_scanner
        .scan_email(&body.content)
        .await
    {
        Ok(result) => (StatusCode::OK, Json(serde_json::to_value(&result).unwrap())).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, err_json(&e)).into_response(),
    }
}

async fn scan_spam(
    State(state): State<S>,
    headers: HeaderMap,
    Json(body): Json<ScanRequest>,
) -> impl IntoResponse {
    if let Err(e) = verify_bearer(&headers, &state.config) {
        return (e.0, err_json(e.1)).into_response();
    }
    match state.content_scanner.scan_email(&body.content).await {
        Ok(result) => (StatusCode::OK, Json(serde_json::to_value(&result.spam).unwrap())).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, err_json(&e)).into_response(),
    }
}

async fn scan_phishing(
    State(state): State<S>,
    headers: HeaderMap,
    Json(body): Json<ScanRequest>,
) -> impl IntoResponse {
    if let Err(e) = verify_bearer(&headers, &state.config) {
        return (e.0, err_json(e.1)).into_response();
    }
    match state.content_scanner.scan_email(&body.content).await {
        Ok(result) => (StatusCode::OK, Json(serde_json::to_value(&result.phishing).unwrap())).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, err_json(&e)).into_response(),
    }
}

async fn scan_malware(
    State(state): State<S>,
    headers: HeaderMap,
    Json(body): Json<ScanRequest>,
) -> impl IntoResponse {
    if let Err(e) = verify_bearer(&headers, &state.config) {
        return (e.0, err_json(e.1)).into_response();
    }
    match state.content_scanner.scan_email(&body.content).await {
        Ok(result) => (StatusCode::OK, Json(serde_json::to_value(&result.malware).unwrap())).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, err_json(&e)).into_response(),
    }
}

async fn scan_policy(
    State(state): State<S>,
    headers: HeaderMap,
    Path(_tenant_id): Path<String>,
    Json(body): Json<ScanRequest>,
) -> impl IntoResponse {
    if let Err(e) = verify_bearer(&headers, &state.config) {
        return (e.0, err_json(e.1)).into_response();
    }
    match state.content_scanner.scan_email(&body.content).await {
        Ok(result) => (StatusCode::OK, Json(serde_json::to_value(&result.policy).unwrap())).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, err_json(&e)).into_response(),
    }
}

#[derive(Deserialize, Serialize)]
struct ScanRequest {
    tenant_id: String,
    content: EmailContent,
    sender_email: Option<String>,
}

// ─── Audit Handlers ─────────────────────────────────────────────

#[derive(Deserialize)]
struct AuditLogBody {
    tenant_id: String,
    user_id: String,
    action: String,
    resource: String,
    resource_id: Option<String>,
    details: Option<serde_json::Value>,
    ip_address: Option<String>,
    user_agent: Option<String>,
    session_id: Option<String>,
}

async fn audit_create(
    State(state): State<S>,
    headers: HeaderMap,
    Json(body): Json<AuditLogBody>,
) -> impl IntoResponse {
    if let Err(e) = verify_bearer(&headers, &state.config) {
        return (e.0, err_json(e.1)).into_response();
    }
    let action = parse_audit_action(&body.action);
    let resource = parse_audit_resource(&body.resource);
    let ctx = LogContext {
        tenant_id: Some(body.tenant_id.clone()),
        user_id: Some(body.user_id.clone()),
        ip_address: body.ip_address,
        user_agent: body.user_agent,
        session_id: body.session_id,
    };
    let details = body.details.unwrap_or(serde_json::json!({}));
    match state
        .audit_logger
        .log(
            action,
            resource,
            body.resource_id.as_deref(),
            details,
            AuditOutcome::Success,
            None,
            &ctx,
        )
        .await
    {
        Ok(entry) => (StatusCode::CREATED, Json(serde_json::to_value(&entry).unwrap())).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, err_json(&e)).into_response(),
    }
}

#[derive(Deserialize)]
struct AuditQueryParams {
    tenant_id: Option<String>,
    user_id: Option<String>,
    action: Option<String>,
    resource: Option<String>,
    limit: Option<i64>,
    offset: Option<i64>,
}

async fn audit_query(
    State(state): State<S>,
    headers: HeaderMap,
    Query(params): Query<AuditQueryParams>,
) -> impl IntoResponse {
    if let Err(e) = verify_bearer(&headers, &state.config) {
        return (e.0, err_json(e.1)).into_response();
    }
    let query = AuditLogQuery {
        tenant_id: params.tenant_id,
        user_id: params.user_id,
        action: params.action.as_deref().map(parse_audit_action),
        resource: params.resource.as_deref().map(parse_audit_resource),
        resource_id: None,
        start_date: None,
        end_date: None,
        outcome: None,
        limit: params.limit,
        offset: params.offset,
    };
    match state.audit_logger.query(&query).await {
        Ok((entries, total)) => {
            let resp = serde_json::json!({"entries": entries, "total": total});
            (StatusCode::OK, Json(resp)).into_response()
        }
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, err_json(&e)).into_response(),
    }
}

async fn audit_verify_chain(
    State(state): State<S>,
    headers: HeaderMap,
    Path(tenant_id): Path<String>,
) -> impl IntoResponse {
    if let Err(e) = verify_bearer(&headers, &state.config) {
        return (e.0, err_json(e.1)).into_response();
    }
    match state.audit_logger.verify_chain(Some(&tenant_id), None, None).await {
        Ok(result) => (StatusCode::OK, Json(serde_json::to_value(&result).unwrap())).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, err_json(&e)).into_response(),
    }
}

#[derive(Deserialize)]
struct ExportParams {
    format: Option<String>,
    limit: Option<i64>,
}

async fn audit_export(
    State(state): State<S>,
    headers: HeaderMap,
    Path(tenant_id): Path<String>,
    Query(params): Query<ExportParams>,
) -> impl IntoResponse {
    if let Err(e) = verify_bearer(&headers, &state.config) {
        return (e.0, err_json(e.1)).into_response();
    }

    // First fetch the entries
    let query = AuditLogQuery {
        tenant_id: Some(tenant_id),
        user_id: None,
        action: None,
        resource: None,
        resource_id: None,
        start_date: None,
        end_date: None,
        outcome: None,
        limit: params.limit,
        offset: None,
    };
    let format = params.format.as_deref().unwrap_or("json");
    match state.audit_logger.export(&query, format).await {
        Ok(result) => {
            let headers = [
                (header::CONTENT_TYPE, result.content_type.clone()),
                (
                    header::CONTENT_DISPOSITION,
                    format!("attachment; filename=\"{}\"", result.filename),
                ),
            ];
            (StatusCode::OK, headers, result.data).into_response()
        }
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, err_json(&e)).into_response(),
    }
}

async fn audit_stats(
    State(state): State<S>,
    headers: HeaderMap,
    Path(tenant_id): Path<String>,
) -> impl IntoResponse {
    if let Err(e) = verify_bearer(&headers, &state.config) {
        return (e.0, err_json(e.1)).into_response();
    }
    match state.audit_logger.get_stats(Some(&tenant_id)).await {
        Ok(stats) => (StatusCode::OK, Json(stats)).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, err_json(&e)).into_response(),
    }
}

#[derive(Deserialize)]
struct ArchiveBody {
    days_threshold: i64,
}

async fn audit_archive(
    State(state): State<S>,
    headers: HeaderMap,
    Json(body): Json<ArchiveBody>,
) -> impl IntoResponse {
    if let Err(e) = verify_bearer(&headers, &state.config) {
        return (e.0, err_json(e.1)).into_response();
    }
    let older_than = Utc::now() - chrono::Duration::days(body.days_threshold);
    match state.audit_logger.archive(older_than).await {
        Ok(count) => (StatusCode::OK, Json(serde_json::json!({"archived": count}))).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, err_json(&e)).into_response(),
    }
}

#[derive(Deserialize)]
struct WebhookBody {
    tenant_id: String,
    url: String,
    events: Vec<String>,
}

async fn audit_register_webhook(
    State(state): State<S>,
    headers: HeaderMap,
    Json(body): Json<WebhookBody>,
) -> impl IntoResponse {
    if let Err(e) = verify_bearer(&headers, &state.config) {
        return (e.0, err_json(e.1)).into_response();
    }
    let actions: Vec<AuditAction> = body.events.iter().map(|s| parse_audit_action(s)).collect();
    match state
        .audit_logger
        .register_webhook(&body.tenant_id, &body.url, &actions)
        .await
    {
        Ok(id) => (StatusCode::CREATED, Json(serde_json::json!({"id": id}))).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, err_json(&e)).into_response(),
    }
}

// ─── Secret Handlers ────────────────────────────────────────────

async fn secret_create(
    State(state): State<S>,
    headers: HeaderMap,
    Json(body): Json<SecretCreateInput>,
) -> impl IntoResponse {
    if let Err(e) = verify_bearer(&headers, &state.config) {
        return (e.0, err_json(e.1)).into_response();
    }
    match state.secret_manager.create_secret(&body).await {
        Ok(secret) => {
            // Return secret without encrypted value for security
            let resp = serde_json::json!({
                "id": secret.id,
                "name": secret.name,
                "type": secret.secret_type.to_string(),
                "version": secret.version,
                "created_at": secret.created_at.to_rfc3339(),
            });
            (StatusCode::CREATED, Json(resp)).into_response()
        }
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, err_json(&e)).into_response(),
    }
}

async fn secret_get(
    State(state): State<S>,
    headers: HeaderMap,
    Path(secret_id): Path<String>,
) -> impl IntoResponse {
    if let Err(e) = verify_bearer(&headers, &state.config) {
        return (e.0, err_json(e.1)).into_response();
    }
    let user_id = match extract_user_id(&headers) {
        Ok(u) => u,
        Err(e) => return (e.0, err_json(e.1)).into_response(),
    };
    match state.secret_manager.get_secret(&secret_id, &user_id).await {
        Ok(Some((secret, value))) => {
            let resp = serde_json::json!({
                "id": secret.id,
                "name": secret.name,
                "type": secret.secret_type.to_string(),
                "value": value,
                "version": secret.version,
            });
            (StatusCode::OK, Json(resp)).into_response()
        }
        Ok(None) => (StatusCode::NOT_FOUND, err_json("Secret not found")).into_response(),
        Err(e) => (StatusCode::FORBIDDEN, err_json(&e)).into_response(),
    }
}

async fn secret_update(
    State(state): State<S>,
    headers: HeaderMap,
    Path(secret_id): Path<String>,
    Json(body): Json<SecretUpdateInput>,
) -> impl IntoResponse {
    if let Err(e) = verify_bearer(&headers, &state.config) {
        return (e.0, err_json(e.1)).into_response();
    }
    let user_id = match extract_user_id(&headers) {
        Ok(u) => u,
        Err(e) => return (e.0, err_json(e.1)).into_response(),
    };
    match state
        .secret_manager
        .update_secret(&secret_id, &user_id, &body)
        .await
    {
        Ok(secret) => (StatusCode::OK, Json(serde_json::json!({"id": secret.id, "name": secret.name}))).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, err_json(&e)).into_response(),
    }
}

async fn secret_delete(
    State(state): State<S>,
    headers: HeaderMap,
    Path(secret_id): Path<String>,
) -> impl IntoResponse {
    if let Err(e) = verify_bearer(&headers, &state.config) {
        return (e.0, err_json(e.1)).into_response();
    }
    let user_id = match extract_user_id(&headers) {
        Ok(u) => u,
        Err(e) => return (e.0, err_json(e.1)).into_response(),
    };
    match state
        .secret_manager
        .delete_secret(&secret_id, &user_id)
        .await
    {
        Ok(()) => (StatusCode::OK, Json(serde_json::json!({"ok": true}))).into_response(),
        Err(e) => (StatusCode::FORBIDDEN, err_json(&e)).into_response(),
    }
}

#[derive(Deserialize)]
struct RotateBody {
    new_value: Option<String>,
}

async fn secret_rotate(
    State(state): State<S>,
    headers: HeaderMap,
    Path(secret_id): Path<String>,
    Json(body): Json<RotateBody>,
) -> impl IntoResponse {
    if let Err(e) = verify_bearer(&headers, &state.config) {
        return (e.0, err_json(e.1)).into_response();
    }
    let user_id = match extract_user_id(&headers) {
        Ok(u) => u,
        Err(e) => return (e.0, err_json(e.1)).into_response(),
    };
    match state
        .secret_manager
        .rotate_secret(&secret_id, &user_id, body.new_value.as_deref())
        .await
    {
        Ok((secret, value)) => {
            let resp = serde_json::json!({
                "id": secret.id,
                "name": secret.name,
                "version": secret.version,
                "value": value,
            });
            (StatusCode::OK, Json(resp)).into_response()
        }
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, err_json(&e)).into_response(),
    }
}

#[derive(Deserialize)]
struct GrantAccessBody {
    user_id: String,
    access_type: String,
    expires_at: Option<chrono::DateTime<chrono::Utc>>,
}

async fn secret_grant_access(
    State(state): State<S>,
    headers: HeaderMap,
    Path(secret_id): Path<String>,
    Json(body): Json<GrantAccessBody>,
) -> impl IntoResponse {
    if let Err(e) = verify_bearer(&headers, &state.config) {
        return (e.0, err_json(e.1)).into_response();
    }
    let granted_by = match extract_user_id(&headers) {
        Ok(u) => u,
        Err(e) => return (e.0, err_json(e.1)).into_response(),
    };
    let access_type = match body.access_type.as_str() {
        "admin" => AccessLevel::Admin,
        "write" => AccessLevel::Write,
        _ => AccessLevel::Read,
    };
    match state
        .secret_manager
        .grant_access(&secret_id, &body.user_id, access_type, &granted_by, body.expires_at)
        .await
    {
        Ok(access) => (StatusCode::CREATED, Json(serde_json::json!({"id": access.id}))).into_response(),
        Err(e) => (StatusCode::FORBIDDEN, err_json(&e)).into_response(),
    }
}

async fn secret_revoke_access(
    State(state): State<S>,
    headers: HeaderMap,
    Path((secret_id, user_id)): Path<(String, String)>,
) -> impl IntoResponse {
    if let Err(e) = verify_bearer(&headers, &state.config) {
        return (e.0, err_json(e.1)).into_response();
    }
    let revoked_by = match extract_user_id(&headers) {
        Ok(u) => u,
        Err(e) => return (e.0, err_json(e.1)).into_response(),
    };
    match state
        .secret_manager
        .revoke_access(&secret_id, &user_id, &revoked_by)
        .await
    {
        Ok(()) => (StatusCode::OK, Json(serde_json::json!({"ok": true}))).into_response(),
        Err(e) => (StatusCode::FORBIDDEN, err_json(&e)).into_response(),
    }
}

async fn secret_versions(
    State(state): State<S>,
    headers: HeaderMap,
    Path(secret_id): Path<String>,
) -> impl IntoResponse {
    if let Err(e) = verify_bearer(&headers, &state.config) {
        return (e.0, err_json(e.1)).into_response();
    }
    let user_id = match extract_user_id(&headers) {
        Ok(u) => u,
        Err(e) => return (e.0, err_json(e.1)).into_response(),
    };
    match state
        .secret_manager
        .get_version_history(&secret_id, &user_id)
        .await
    {
        Ok(versions) => {
            let v: Vec<serde_json::Value> = versions
                .into_iter()
                .map(|(ver, ts)| serde_json::json!({"version": ver, "created_at": ts.to_rfc3339()}))
                .collect();
            (StatusCode::OK, Json(serde_json::json!({"versions": v}))).into_response()
        }
        Err(e) => (StatusCode::FORBIDDEN, err_json(&e)).into_response(),
    }
}

async fn secret_rollback(
    State(state): State<S>,
    headers: HeaderMap,
    Path((secret_id, version)): Path<(String, i32)>,
) -> impl IntoResponse {
    if let Err(e) = verify_bearer(&headers, &state.config) {
        return (e.0, err_json(e.1)).into_response();
    }
    let user_id = match extract_user_id(&headers) {
        Ok(u) => u,
        Err(e) => return (e.0, err_json(e.1)).into_response(),
    };
    match state
        .secret_manager
        .rollback_to_version(&secret_id, version, &user_id)
        .await
    {
        Ok(secret) => (StatusCode::OK, Json(serde_json::json!({"id": secret.id, "version": secret.version}))).into_response(),
        Err(e) => (StatusCode::FORBIDDEN, err_json(&e)).into_response(),
    }
}

#[derive(Deserialize)]
struct ListSecretsQuery {
    #[serde(rename = "type")]
    secret_type: Option<String>,
}

async fn secrets_list(
    State(state): State<S>,
    headers: HeaderMap,
    Path(tenant_id): Path<String>,
    Query(params): Query<ListSecretsQuery>,
) -> impl IntoResponse {
    if let Err(e) = verify_bearer(&headers, &state.config) {
        return (e.0, err_json(e.1)).into_response();
    }
    let st = params.secret_type.and_then(|t| match t.as_str() {
        "api_key" => Some(SecretType::ApiKey),
        "smtp_password" => Some(SecretType::SmtpPassword),
        "webhook_secret" => Some(SecretType::WebhookSecret),
        "encryption_key" => Some(SecretType::EncryptionKey),
        "oauth_token" => Some(SecretType::OauthToken),
        "certificate" => Some(SecretType::Certificate),
        _ => None,
    });
    match state.secret_manager.list_secrets(&tenant_id, st).await {
        Ok(secrets) => {
            let list: Vec<serde_json::Value> = secrets
                .into_iter()
                .map(|s| {
                    serde_json::json!({
                        "id": s.id,
                        "name": s.name,
                        "type": s.secret_type.to_string(),
                        "version": s.version,
                        "created_at": s.created_at.to_rfc3339(),
                    })
                })
                .collect();
            (StatusCode::OK, Json(serde_json::json!({"secrets": list}))).into_response()
        }
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, err_json(&e)).into_response(),
    }
}

// ─── GDPR Handlers ──────────────────────────────────────────────

#[derive(Deserialize)]
struct GdprRequestBody {
    tenant_id: String,
    request_type: String,
    email: String,
}

async fn gdpr_submit_request(
    State(state): State<S>,
    headers: HeaderMap,
    Json(body): Json<GdprRequestBody>,
) -> impl IntoResponse {
    if let Err(e) = verify_bearer(&headers, &state.config) {
        return (e.0, err_json(e.1)).into_response();
    }
    let request_type = match body.request_type.as_str() {
        "access" => DataSubjectRequestType::Access,
        "erasure" => DataSubjectRequestType::Erasure,
        "portability" => DataSubjectRequestType::Portability,
        "rectification" => DataSubjectRequestType::Rectification,
        "restriction" => DataSubjectRequestType::Restriction,
        "objection" => DataSubjectRequestType::Objection,
        _ => return (StatusCode::BAD_REQUEST, err_json("Invalid request type")).into_response(),
    };
    match state
        .gdpr
        .submit_request(&body.tenant_id, request_type, &body.email)
        .await
    {
        Ok((request, token)) => {
            let resp = serde_json::json!({
                "request_id": request.id,
                "verification_token": token,
                "expires_at": request.expires_at.to_rfc3339(),
            });
            (StatusCode::CREATED, Json(resp)).into_response()
        }
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, err_json(&e)).into_response(),
    }
}

#[derive(Deserialize)]
struct VerifyRequestBody {
    token: String,
}

async fn gdpr_verify_request(
    State(state): State<S>,
    headers: HeaderMap,
    Path(request_id): Path<String>,
    Json(body): Json<VerifyRequestBody>,
) -> impl IntoResponse {
    if let Err(e) = verify_bearer(&headers, &state.config) {
        return (e.0, err_json(e.1)).into_response();
    }
    match state.gdpr.verify_request(&request_id, &body.token).await {
        Ok(valid) => {
            if valid {
                (StatusCode::OK, Json(serde_json::json!({"verified": true}))).into_response()
            } else {
                (StatusCode::BAD_REQUEST, err_json("Invalid or expired token")).into_response()
            }
        }
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, err_json(&e)).into_response(),
    }
}

#[derive(Deserialize)]
struct ConsentBody {
    tenant_id: String,
    subscriber_id: String,
    email: String,
    consent_type: String,
    granted: bool,
    source: String,
    ip_address: Option<String>,
}

async fn gdpr_record_consent(
    State(state): State<S>,
    headers: HeaderMap,
    Json(body): Json<ConsentBody>,
) -> impl IntoResponse {
    if let Err(e) = verify_bearer(&headers, &state.config) {
        return (e.0, err_json(e.1)).into_response();
    }
    let consent_type = match body.consent_type.as_str() {
        "marketing" => ConsentType::Marketing,
        "transactional" => ConsentType::Transactional,
        "analytics" => ConsentType::Analytics,
        "profiling" => ConsentType::Profiling,
        "third_party" => ConsentType::ThirdParty,
        "data_processing" => ConsentType::DataProcessing,
        _ => return (StatusCode::BAD_REQUEST, err_json("Invalid consent type")).into_response(),
    };
    let source = match body.source.as_str() {
        "web_form" | "form" => ConsentSource::Form,
        "api" => ConsentSource::Api,
        "import" => ConsentSource::Import,
        "double_opt_in" => ConsentSource::DoubleOptIn,
        "system" => ConsentSource::System,
        "preference_center" => ConsentSource::PreferenceCenter,
        _ => return (StatusCode::BAD_REQUEST, err_json("Invalid source")).into_response(),
    };
    match state
        .gdpr
        .record_consent(
            &body.tenant_id,
            &body.subscriber_id,
            &body.email,
            consent_type,
            body.granted,
            source,
            body.ip_address.as_deref(),
        )
        .await
    {
        Ok(record) => (StatusCode::CREATED, Json(serde_json::json!({"id": record.id, "granted": record.granted}))).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, err_json(&e)).into_response(),
    }
}

async fn gdpr_get_consents(
    State(state): State<S>,
    headers: HeaderMap,
    Path((tenant_id, subscriber_id)): Path<(String, String)>,
) -> impl IntoResponse {
    if let Err(e) = verify_bearer(&headers, &state.config) {
        return (e.0, err_json(e.1)).into_response();
    }
    match state.gdpr.get_consent_records(&tenant_id, &subscriber_id).await {
        Ok(records) => (StatusCode::OK, Json(serde_json::to_value(&records).unwrap())).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, err_json(&e)).into_response(),
    }
}

#[derive(Deserialize)]
struct DoiBody {
    tenant_id: String,
    subscriber_id: String,
    consent_type: String,
    email: String,
}

async fn gdpr_initiate_doi(
    State(state): State<S>,
    headers: HeaderMap,
    Json(body): Json<DoiBody>,
) -> impl IntoResponse {
    if let Err(e) = verify_bearer(&headers, &state.config) {
        return (e.0, err_json(e.1)).into_response();
    }
    let consent_type = match body.consent_type.as_str() {
        "marketing" => ConsentType::Marketing,
        "transactional" => ConsentType::Transactional,
        "analytics" => ConsentType::Analytics,
        "profiling" => ConsentType::Profiling,
        "third_party" => ConsentType::ThirdParty,
        "data_processing" => ConsentType::DataProcessing,
        _ => return (StatusCode::BAD_REQUEST, err_json("Invalid consent type")).into_response(),
    };
    match state
        .gdpr
        .initiate_double_opt_in(&body.tenant_id, &body.subscriber_id, consent_type, &body.email)
        .await
    {
        Ok(token) => (StatusCode::CREATED, Json(serde_json::json!({"token": token}))).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, err_json(&e)).into_response(),
    }
}

#[derive(Deserialize)]
struct DoiConfirmBody {
    tenant_id: String,
    subscriber_id: String,
    consent_type: String,
    token: String,
}

async fn gdpr_confirm_doi(
    State(state): State<S>,
    headers: HeaderMap,
    Json(body): Json<DoiConfirmBody>,
) -> impl IntoResponse {
    if let Err(e) = verify_bearer(&headers, &state.config) {
        return (e.0, err_json(e.1)).into_response();
    }
    let consent_type = match body.consent_type.as_str() {
        "marketing" => ConsentType::Marketing,
        "transactional" => ConsentType::Transactional,
        "analytics" => ConsentType::Analytics,
        "profiling" => ConsentType::Profiling,
        "third_party" => ConsentType::ThirdParty,
        "data_processing" => ConsentType::DataProcessing,
        _ => return (StatusCode::BAD_REQUEST, err_json("Invalid consent type")).into_response(),
    };
    match state
        .gdpr
        .confirm_double_opt_in(&body.tenant_id, &body.subscriber_id, consent_type, &body.token)
        .await
    {
        Ok(valid) => {
            if valid {
                (StatusCode::OK, Json(serde_json::json!({"confirmed": true}))).into_response()
            } else {
                (StatusCode::BAD_REQUEST, err_json("Invalid or expired token")).into_response()
            }
        }
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, err_json(&e)).into_response(),
    }
}

async fn gdpr_stats(
    State(state): State<S>,
    headers: HeaderMap,
    Path(tenant_id): Path<String>,
) -> impl IntoResponse {
    if let Err(e) = verify_bearer(&headers, &state.config) {
        return (e.0, err_json(e.1)).into_response();
    }
    match state.gdpr.get_request_stats(&tenant_id).await {
        Ok(stats) => (StatusCode::OK, Json(stats)).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, err_json(&e)).into_response(),
    }
}

// ─── Helper ─────────────────────────────────────────────────────

fn parse_audit_action(s: &str) -> AuditAction {
    match s {
        "create" => AuditAction::Create,
        "read" => AuditAction::Read,
        "update" => AuditAction::Update,
        "delete" => AuditAction::Delete,
        "login" => AuditAction::Login,
        "logout" => AuditAction::Logout,
        "send" => AuditAction::Send,
        "export" => AuditAction::Export,
        "import" => AuditAction::Import,
        "receive" => AuditAction::Receive,
        "approve" => AuditAction::Approve,
        "reject" => AuditAction::Reject,
        "escalate" => AuditAction::Escalate,
        _ => AuditAction::Configure,
    }
}

fn parse_audit_resource(s: &str) -> AuditResource {
    match s {
        "tenant" => AuditResource::Tenant,
        "user" => AuditResource::User,
        "api_key" => AuditResource::ApiKey,
        "domain" => AuditResource::Domain,
        "template" => AuditResource::Template,
        "campaign" => AuditResource::Campaign,
        "subscriber" => AuditResource::Subscriber,
        "list" => AuditResource::List,
        "webhook" => AuditResource::Webhook,
        "message" => AuditResource::Message,
        "settings" => AuditResource::Settings,
        "billing" => AuditResource::Billing,
        _ => AuditResource::Consent,
    }
}

fn parse_risk_flag_type(s: &str) -> RiskFlagType {
    match s {
        "high_bounce_rate" => RiskFlagType::HighBounceRate,
        "spam_trap_hit" => RiskFlagType::SpamTrapHit,
        "blocklist_detected" => RiskFlagType::BlocklistDetected,
        "unusual_sending_pattern" => RiskFlagType::UnusualSendingPattern,
        "phishing_content" => RiskFlagType::PhishingContent,
        "malware_attachment" => RiskFlagType::MalwareAttachment,
        "suspended_account" => RiskFlagType::SuspendedAccount,
        _ => RiskFlagType::PaymentFailed,
    }
}
