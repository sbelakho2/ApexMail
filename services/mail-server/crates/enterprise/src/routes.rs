use axum::{
    extract::{DefaultBodyLimit, Path, Query, State},
    http::{header::AUTHORIZATION, StatusCode},
    middleware,
    response::IntoResponse,
    routing::{get, post, put, delete},
    Json, Router,
};
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use serde::Deserialize;
use sqlx::PgPool;
use std::sync::Arc;
use std::time::Duration;
use tower_http::timeout::TimeoutLayer;
use uuid::Uuid;

use crate::compliance::ComplianceService;
use crate::config::Config;
use crate::log_streaming::LogStreamingService;
use crate::private_deploy::PrivateDeployService;
use crate::qbr::QBRService;
use crate::sso::SSOService;
use crate::sub_accounts::SubAccountService;
use crate::support::SupportService;
use crate::template_approval::TemplateApprovalService;
use crate::types::SSOConfigureRequest;
use crate::whitelabel::WhiteLabelService;

// ── Shared state ───────────────────────────────────────────────────────

pub struct AppState {
    pub db: PgPool,
    pub config: Config,
    pub sso: SSOService,
    pub compliance: ComplianceService,
    pub log_streaming: LogStreamingService,
    pub private_deploy: PrivateDeployService,
    pub sub_accounts: SubAccountService,
    pub support: SupportService,
    pub templates: TemplateApprovalService,
    pub whitelabel: WhiteLabelService,
    pub qbr: QBRService,
}

impl AppState {
    pub fn new(db: PgPool, config: Config) -> Self {
        Self {
            config: config.clone(),
            sso: SSOService::new(db.clone(), config.clone()),
            compliance: ComplianceService::new(db.clone()),
            log_streaming: LogStreamingService::new(db.clone()),
            private_deploy: PrivateDeployService::new(db.clone()),
            sub_accounts: SubAccountService::new(
                db.clone(),
                config.sub_account.max_sub_accounts,
                config.sub_account.volume_allocation_mode.clone(),
            ),
            support: SupportService::new(db.clone()),
            templates: TemplateApprovalService::new(
                db.clone(),
                config.template.auto_approve_threshold,
                config.template.max_spam_score,
            ),
            whitelabel: WhiteLabelService::new(db.clone()),
            qbr: QBRService::new(db.clone()),
            db,
        }
    }
}

type S = Arc<AppState>;

#[derive(Debug, Deserialize)]
struct JwtClaims {
    #[serde(rename = "exp")]
    _exp: usize,
}

async fn auth_middleware(
    State(state): State<S>,
    req: axum::extract::Request,
    next: middleware::Next,
) -> impl IntoResponse {
    let path = req.uri().path();
    if path == "/health" || path == "/readiness" || path.starts_with("/sso/login/") || path == "/sso/validate" {
        return next.run(req).await;
    }

    let token = req
        .headers()
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));

    let Some(token) = token else {
        return err_json(StatusCode::UNAUTHORIZED, "Missing bearer token").into_response();
    };

    let mut validation = Validation::new(Algorithm::HS256);
    validation.validate_exp = true;

    if jsonwebtoken::decode::<JwtClaims>(
        token,
        &DecodingKey::from_secret(state.config.jwt_secret.as_bytes()),
        &validation,
    )
    .is_err()
    {
        return err_json(StatusCode::UNAUTHORIZED, "Invalid or expired token").into_response();
    }

    next.run(req).await
}

// ── Request body types ─────────────────────────────────────────────────

#[derive(Deserialize)] pub struct PaginationParams { pub limit: Option<i64>, pub offset: Option<i64> }
#[derive(Deserialize)] pub struct StatusFilterParams { pub status: Option<String>, pub priority: Option<String>, pub limit: Option<i64>, pub offset: Option<i64> }
#[derive(Deserialize)] pub struct AuditFilterParams { pub action: Option<String>, pub resource_type: Option<String>, pub limit: Option<i64>, pub offset: Option<i64> }
#[derive(Deserialize)] pub struct DomainQuery { pub domain: Option<String> }
#[derive(Deserialize)] pub struct IndustryQuery { pub industry: Option<String> }

#[derive(Deserialize)]
pub struct ComplianceEnableBody {
    pub tenant_id: Uuid,
    pub frameworks: Vec<String>,
    pub hipaa_enabled: Option<bool>,
}

#[derive(Deserialize)]
pub struct BAABody {
    pub tenant_id: Uuid,
    pub signatory_name: String,
    pub signatory_title: String,
    pub signatory_email: String,
}

#[derive(Deserialize)]
pub struct AuditLogBody {
    pub tenant_id: Uuid,
    pub user_id: Option<String>,
    pub action: String,
    pub resource_type: String,
    pub resource_id: Option<String>,
    pub old_value: Option<serde_json::Value>,
    pub new_value: Option<serde_json::Value>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub session_id: Option<String>,
    pub request_id: Option<String>,
}

#[derive(Deserialize)]
pub struct DataAccessBody {
    pub tenant_id: Uuid,
    pub requester_id: String,
    pub requester_email: String,
    pub request_type: String,
    pub resource_type: Option<String>,
    pub justification: Option<String>,
    pub identifiers: Option<serde_json::Value>,
}

#[derive(Deserialize)]
pub struct DataAccessApproveBody {
    pub approved_by: String,
    pub duration_minutes: i32,
}

#[derive(Deserialize)]
pub struct DataDeletionBody {
    pub tenant_id: Uuid,
    pub requester_id: String,
    pub requester_email: String,
    pub identifiers: Option<serde_json::Value>,
}

#[derive(Deserialize)]
pub struct LogStreamCreateBody {
    pub tenant_id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub destination_type: String,
    pub destination_config: Option<serde_json::Value>,
    pub log_categories: Option<Vec<String>>,
    pub batch_size: Option<i32>,
    pub batch_interval_seconds: Option<i32>,
    pub compression_enabled: Option<bool>,
}

#[derive(Deserialize)]
pub struct LogStreamUpdateBody {
    pub name: Option<String>,
    pub description: Option<String>,
    pub destination_config: Option<serde_json::Value>,
    pub log_categories: Option<Vec<String>>,
}

#[derive(Deserialize)]
pub struct DeployCreateBody {
    pub tenant_id: Uuid,
    pub name: String,
    pub deployment_type: String,
    pub region: Option<String>,
    pub config: Option<serde_json::Value>,
}

#[derive(Deserialize)]
pub struct DedicatedIPBody {
    pub tenant_id: Uuid,
    pub deployment_id: Option<Uuid>,
    pub ip_address: String,
}

#[derive(Deserialize)]
pub struct BYOIPBody {
    pub tenant_id: Uuid,
    pub cidr_block: String,
}

#[derive(Deserialize)]
pub struct BYOIPVerifyBody {
    pub verification_token: String,
}

#[derive(Deserialize)]
pub struct SubAccountCreateBody {
    pub parent_id: Uuid,
    pub name: String,
    pub email: Option<String>,
    pub domain: Option<String>,
    pub plan: Option<String>,
    pub volume_limit: Option<i64>,
    pub inherit_parent_settings: Option<bool>,
}

#[derive(Deserialize)]
pub struct SubAccountUpdateBody {
    pub name: Option<String>,
    pub email: Option<String>,
    pub volume_limit: Option<i64>,
    pub settings: Option<serde_json::Value>,
}

#[derive(Deserialize)]
pub struct SubAccountSuspendBody {
    pub reason: Option<String>,
}

#[derive(Deserialize)]
pub struct ApiKeyCreateBody {
    pub name: String,
    pub permissions: Option<Vec<String>>,
    pub rate_limit: Option<i32>,
}

#[derive(Deserialize)]
pub struct TicketCreateBody {
    pub tenant_id: Uuid,
    pub subject: String,
    pub description: String,
    pub priority: String,
    pub category: String,
    pub contact_email: Option<String>,
}

#[derive(Deserialize)]
pub struct TicketUpdateBody {
    pub status: Option<String>,
    pub priority: Option<String>,
    pub assigned_to: Option<Uuid>,
}

#[derive(Deserialize)]
pub struct CommentBody {
    pub author_id: String,
    pub author_name: String,
    pub author_type: String,
    pub content: String,
    pub is_internal: Option<bool>,
}

#[derive(Deserialize)]
pub struct CommentFilterParams {
    pub include_internal: Option<bool>,
}

#[derive(Deserialize)]
pub struct EscalateBody {
    pub reason: String,
    pub escalated_by: Uuid,
}

#[derive(Deserialize)]
pub struct SatisfactionBody {
    pub rating: i32,
    pub feedback: Option<String>,
}

#[derive(Deserialize)]
pub struct TemplateSubmitBody {
    pub tenant_id: Uuid,
    pub name: String,
    pub subject: String,
    pub html_content: String,
    pub text_content: Option<String>,
    pub submitted_by: String,
}

#[derive(Deserialize)]
pub struct TemplateReviewBody {
    pub reviewed_by: String,
    pub notes: Option<String>,
}

#[derive(Deserialize)]
pub struct TemplateRejectBody {
    pub reviewed_by: String,
    pub reason: String,
}

#[derive(Deserialize)]
pub struct WhiteLabelConfigBody {
    pub tenant_id: Uuid,
    pub company_name: Option<String>,
    pub logo_url: Option<String>,
    pub favicon_url: Option<String>,
    pub primary_color: Option<String>,
    pub secondary_color: Option<String>,
    pub custom_css: Option<String>,
    pub footer_text: Option<String>,
    pub support_email: Option<String>,
    pub support_url: Option<String>,
}

#[derive(Deserialize)]
pub struct DomainAddBody {
    pub tenant_id: Uuid,
    pub domain: String,
    pub domain_type: String,
}

#[derive(Deserialize)]
pub struct EmailTemplateBody {
    pub tenant_id: Uuid,
    pub template_type: String,
    pub subject_template: Option<String>,
    pub html_template: Option<String>,
    pub text_template: Option<String>,
}

#[derive(Deserialize)]
pub struct QBRScheduleBody {
    pub tenant_id: Uuid,
    pub quarter: i32,
    pub year: i32,
    pub scheduled_date: Option<chrono::NaiveDate>,
    pub attendees: Option<serde_json::Value>,
}

#[derive(Deserialize)]
pub struct QBRFeedbackBody {
    pub rating: i32,
    pub feedback_text: Option<String>,
}

#[derive(Deserialize)]
pub struct QBRGoalUpdateBody {
    pub goal_id: Uuid,
    pub current_value: f64,
}

// ── Router ─────────────────────────────────────────────────────────────

/// Create the enterprise API router.
/// # Security Note (#249)
/// This router must be wrapped with authentication middleware before deployment.
pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
// Health (unauthenticated)
        .route("/health", get(health_check))
        .route("/readiness", get(readiness_check))
// SSO
        .route("/sso/configure", post(sso_configure))
        .route("/sso/config/:tenant_id", get(sso_get_config))
        .route("/sso/config/domain/:domain", get(sso_get_config_by_domain))
        .route("/sso/login/saml/:domain", get(sso_saml_login))
        .route("/sso/login/oidc/:domain", get(sso_oidc_login))
        .route("/sso/validate", get(sso_validate_session))
        .route("/sso/cleanup", post(sso_cleanup_sessions))
// Compliance
        .route("/compliance/enable", post(compliance_enable))
        .route("/compliance/config/:tenant_id", get(compliance_get_config))
        .route("/compliance/baa", post(compliance_sign_baa))
        .route("/compliance/zero-retention/:tenant_id", post(compliance_zero_retention))
        .route("/compliance/audit", post(compliance_log_audit))
        .route("/compliance/audit/:tenant_id", get(compliance_get_audit_logs))
        .route("/compliance/data-access", post(compliance_data_access))
        .route("/compliance/data-access/:id/approve", post(compliance_approve_access))
        .route("/compliance/data-deletion", post(compliance_data_deletion))
        .route("/compliance/report/:tenant_id", get(compliance_report))
        .route("/compliance/status/:tenant_id", get(compliance_status))
// Encryption (HIPAA field-level encryption management)
        .route("/compliance/encryption/status/:tenant_id", get(encryption_status))
        .route("/compliance/encryption/encrypt-field", post(encrypt_field))
        .route("/compliance/encryption/decrypt-field", post(decrypt_field))
// Log Streaming
        .route("/log-streams", post(log_stream_create))
        .route("/log-streams/:id", get(log_stream_get))
        .route("/log-streams/:id", put(log_stream_update))
        .route("/log-streams/:id", delete(log_stream_delete))
        .route("/log-streams/tenant/:tenant_id", get(log_stream_list))
        .route("/log-streams/:id/pause", post(log_stream_pause))
        .route("/log-streams/:id/resume", post(log_stream_resume))
        .route("/log-streams/:id/verify", post(log_stream_verify))
        .route("/log-streams/:id/stats", get(log_stream_stats))
// Private Deploy
        .route("/deployments", post(deploy_create))
        .route("/deployments/:id", get(deploy_get))
        .route("/deployments/tenant/:tenant_id", get(deploy_list))
        .route("/deployments/:id/provision", post(deploy_provision))
        .route("/deployments/:id/health", get(deploy_health))
        .route("/ips/allocate", post(ip_allocate))
        .route("/ips/:id", get(ip_get))
        .route("/ips/tenant/:tenant_id", get(ip_list))
        .route("/ips/reputation/:ip_address", get(ip_reputation))
        .route("/ips/byoip", post(byoip_register))
        .route("/ips/byoip/:id/verify", post(byoip_verify))
// Sub-accounts
        .route("/sub-accounts", post(sub_account_create))
        .route("/sub-accounts/:id", get(sub_account_get))
        .route("/sub-accounts/:id", put(sub_account_update))
        .route("/sub-accounts/:id", delete(sub_account_delete))
        .route("/sub-accounts/parent/:parent_id", get(sub_account_list))
        .route("/sub-accounts/:id/suspend", post(sub_account_suspend))
        .route("/sub-accounts/stats/:parent_id", get(sub_account_stats))
        .route("/sub-accounts/:id/api-keys", post(sub_account_api_key))
// Support
        .route("/support/tickets", post(ticket_create))
        .route("/support/tickets/:id", get(ticket_get))
        .route("/support/tickets/:id", put(ticket_update))
        .route("/support/tickets/tenant/:tenant_id", get(ticket_list))
        .route("/support/tickets/:id/comments", post(comment_add))
        .route("/support/tickets/:id/comments", get(comment_list))
        .route("/support/tickets/:id/escalate", post(ticket_escalate))
        .route("/support/tickets/:id/satisfaction", post(ticket_satisfaction))
        .route("/support/metrics/:tenant_id", get(support_metrics))
// Templates
        .route("/templates/submit", post(template_submit))
        .route("/templates/:id", get(template_get))
        .route("/templates/tenant/:tenant_id", get(template_list))
        .route("/templates/:id/approve", post(template_approve))
        .route("/templates/:id/reject", post(template_reject))
        .route("/templates/:id/request-changes", post(template_request_changes))
        .route("/templates/stats/:tenant_id", get(template_stats))
// Whitelabel
        .route("/whitelabel/config", put(whitelabel_update_config))
        .route("/whitelabel/config/:tenant_id", get(whitelabel_get_config))
        .route("/whitelabel/domains", post(whitelabel_add_domain))
        .route("/whitelabel/domains/:id/verify", post(whitelabel_verify_domain))
        .route("/whitelabel/domains/tenant/:tenant_id", get(whitelabel_list_domains))
        .route("/whitelabel/domains/:tenant_id/:id", delete(whitelabel_remove_domain))
        .route("/whitelabel/email-templates", put(whitelabel_update_templates))
        .route("/whitelabel/email-templates/:tenant_id", get(whitelabel_get_templates))
// QBR
        .route("/qbr", post(qbr_schedule))
        .route("/qbr/:id", get(qbr_get))
        .route("/qbr/tenant/:tenant_id", get(qbr_list))
        .route("/qbr/:id/generate", post(qbr_generate))
        .route("/qbr/:id/deliver", post(qbr_deliver))
        .route("/qbr/:id/feedback", post(qbr_feedback))
        .route("/qbr/:id/goals", put(qbr_update_goal))
        .route("/qbr/benchmarks", get(qbr_benchmarks))
// PDF generation (via pdf-renderer service)
        .route("/dpa/:tenant_id/pdf", post(dpa_generate_pdf))
        .route("/qbr/:id/pdf", get(qbr_generate_pdf))
        .route("/compliance/report/:tenant_id/pdf", get(compliance_report_pdf))
        .route_layer(middleware::from_fn_with_state(state.clone(), auth_middleware))
        .with_state(state)
        .layer(DefaultBodyLimit::max(2 * 1024 * 1024)) // 2 MB
        .layer(TimeoutLayer::new(Duration::from_secs(30)))
}

// ── Helpers ────────────────────────────────────────────────────────────

fn ok_json<T: serde::Serialize>(data: T) -> (StatusCode, Json<serde_json::Value>) {
    match serde_json::to_value(&data) {
        Ok(v) => (StatusCode::OK, Json(v)),
        Err(e) => {
            tracing::error!(error = %e, "JSON serialization failed");
            (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": "internal serialization error"})))
        }
    }
}

fn err_json(status: StatusCode, msg: &str) -> (StatusCode, Json<serde_json::Value>) {
    (status, Json(serde_json::json!({"error": msg})))
}

fn clamp_limit(limit: i64, max: i64) -> i64 {
    limit.clamp(1, max)
}

fn clamp_offset(offset: i64) -> i64 {
    offset.clamp(0, 100_000)
}

fn service_result<T: serde::Serialize>(result: Result<crate::types::ApiResult<T>, String>) -> (StatusCode, Json<serde_json::Value>) {
    match result {
        Ok(r) => match serde_json::to_value(&r) {
            Ok(v) => (StatusCode::OK, Json(v)),
            Err(e) => {
                tracing::error!(error = %e, "JSON serialization failed in service_result");
                (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": "internal serialization error"})))
            }
        },
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e}))),
    }
}

// ── Health ─────────────────────────────────────────────────────────────

async fn health_check() -> impl IntoResponse {
    ok_json(serde_json::json!({"status": "ok", "service": "enterprise"}))
}

async fn readiness_check(State(state): State<S>) -> impl IntoResponse {
    match sqlx::query("SELECT 1").execute(&state.db).await {
        Ok(_) => ok_json(serde_json::json!({"status": "ready"})),
        Err(_) => err_json(StatusCode::SERVICE_UNAVAILABLE, "Database not ready"),
    }
}

// ── SSO Handlers ───────────────────────────────────────────────────────

async fn sso_configure(State(state): State<S>, Json(body): Json<SSOConfigureRequest>) -> impl IntoResponse {
    service_result(state.sso.configure(body).await)
}

async fn sso_get_config(State(state): State<S>, Path(tenant_id): Path<Uuid>) -> impl IntoResponse {
    service_result(state.sso.get_configuration(tenant_id).await)
}

async fn sso_get_config_by_domain(State(state): State<S>, Path(domain): Path<String>) -> impl IntoResponse {
    match state.sso.get_config_by_domain(&domain).await {
        Ok(Some(c)) => ok_json(c),
        Ok(None) => err_json(StatusCode::NOT_FOUND, "SSO config not found for domain"),
        Err(e) => err_json(StatusCode::INTERNAL_SERVER_ERROR, &e),
    }
}

async fn sso_saml_login(State(state): State<S>, Path(domain): Path<String>) -> impl IntoResponse {
    service_result(state.sso.initiate_saml_login(&domain).await)
}

async fn sso_oidc_login(State(state): State<S>, Path(domain): Path<String>) -> impl IntoResponse {
    service_result(state.sso.initiate_oidc_login(&domain).await)
}

#[derive(Deserialize)]
pub struct SessionQuery { 
/// Deprecated:Use Authorization header instead
    pub token: Option<String> 
}

/// Validate an SSO session
/// #251:Now accepts token from Authorization header (preferred) or query param (deprecated)
async fn sso_validate_session(
    State(state): State<S>,
    headers: axum::http::HeaderMap,
    Query(q): Query<SessionQuery>
) -> impl IntoResponse {
// #251:Prefer token from Authorization header to avoid URL logging/Referer leaks
    let token = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(|s| s.to_string())
        .or(q.token);
    
    let token = match token {
        Some(t) => t,
        None => return err_json(StatusCode::BAD_REQUEST, "Missing token in Authorization header or query parameter"),
    };
    
// Log warning if using deprecated query parameter
    if headers.get(axum::http::header::AUTHORIZATION).is_none() {
        tracing::warn!("SSO session validation using deprecated query parameter - use Authorization header");
    }
    
    match state.sso.validate_session(&token).await {
        Ok(Some(session)) => ok_json(session),
        Ok(None) => err_json(StatusCode::UNAUTHORIZED, "Invalid or expired session"),
        Err(e) => err_json(StatusCode::INTERNAL_SERVER_ERROR, &e),
    }
}

async fn sso_cleanup_sessions(State(state): State<S>) -> impl IntoResponse {
    match state.sso.cleanup_expired_sessions().await {
        Ok(count) => ok_json(serde_json::json!({"cleaned": count})),
        Err(e) => err_json(StatusCode::INTERNAL_SERVER_ERROR, &e),
    }
}

// ── Compliance Handlers ────────────────────────────────────────────────

async fn compliance_enable(State(state): State<S>, Json(body): Json<ComplianceEnableBody>) -> impl IntoResponse {
    service_result(state.compliance.enable(body.tenant_id, body.frameworks, body.hipaa_enabled.unwrap_or(false)).await)
}

async fn compliance_get_config(State(state): State<S>, Path(tenant_id): Path<Uuid>) -> impl IntoResponse {
    service_result(state.compliance.get_config(tenant_id).await)
}

async fn compliance_sign_baa(State(state): State<S>, Json(body): Json<BAABody>) -> impl IntoResponse {
    service_result(state.compliance.sign_baa(body.tenant_id, &body.signatory_name, &body.signatory_title, &body.signatory_email).await)
}

async fn compliance_zero_retention(State(state): State<S>, Path(tenant_id): Path<Uuid>) -> impl IntoResponse {
    service_result(state.compliance.enable_zero_retention(tenant_id).await)
}

async fn compliance_log_audit(State(state): State<S>, Json(body): Json<AuditLogBody>) -> impl IntoResponse {
    match state.compliance.log_audit(
        body.tenant_id, body.user_id.as_deref(), &body.action, &body.resource_type,
        body.resource_id.as_deref(), body.old_value, body.new_value,
        body.ip_address.as_deref(), body.user_agent.as_deref(),
        body.session_id.as_deref(), body.request_id.as_deref(),
    ).await {
        Ok(()) => ok_json(serde_json::json!({"status": "logged"})),
        Err(e) => err_json(StatusCode::INTERNAL_SERVER_ERROR, &e),
    }
}

async fn compliance_get_audit_logs(State(state): State<S>, Path(tenant_id): Path<Uuid>, Query(q): Query<AuditFilterParams>) -> impl IntoResponse {
    let limit = clamp_limit(q.limit.unwrap_or(50), 200);
    let offset = clamp_offset(q.offset.unwrap_or(0));
    service_result(state.compliance.get_audit_logs(tenant_id, q.action.as_deref(), q.resource_type.as_deref(), limit, offset).await)
}

async fn compliance_data_access(State(state): State<S>, Json(body): Json<DataAccessBody>) -> impl IntoResponse {
    service_result(state.compliance.request_data_access(
        body.tenant_id, &body.requester_id, &body.requester_email,
        &body.request_type, body.resource_type.as_deref(),
        body.justification.as_deref(), body.identifiers,
    ).await)
}

async fn compliance_approve_access(State(state): State<S>, Path(id): Path<Uuid>, Json(body): Json<DataAccessApproveBody>) -> impl IntoResponse {
    service_result(state.compliance.approve_data_access(id, &body.approved_by, body.duration_minutes).await)
}

async fn compliance_data_deletion(State(state): State<S>, Json(body): Json<DataDeletionBody>) -> impl IntoResponse {
    service_result(state.compliance.request_data_deletion(body.tenant_id, &body.requester_id, &body.requester_email, body.identifiers).await)
}

async fn compliance_report(State(state): State<S>, Path(tenant_id): Path<Uuid>) -> impl IntoResponse {
    service_result(state.compliance.generate_report(tenant_id).await)
}

async fn compliance_status(State(state): State<S>, Path(tenant_id): Path<Uuid>) -> impl IntoResponse {
    service_result(state.compliance.get_status(tenant_id).await)
}

// ── Encryption Handlers ────────────────────────────────────────────────

/// Get encryption status for a tenant (key info without revealing key material).
async fn encryption_status(
    State(state): State<S>,
    Path(tenant_id): Path<Uuid>,
) -> impl IntoResponse {
// Check if HIPAA compliance is configured with encryption_at_rest
    let config = match state.compliance.get_config(tenant_id).await {
        Ok(r) => r,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({
            "error": { "code": "INTERNAL_ERROR", "message": e }
        }))).into_response(),
    };

    let status = serde_json::json!({
        "tenant_id": tenant_id,
        "encryption_at_rest": config.data.as_ref().map(|c| c.encryption_at_rest).unwrap_or(false),
        "encryption_in_transit": config.data.as_ref().map(|c| c.encryption_in_transit).unwrap_or(true),
        "phi_fields": crate::field_encryption::PHI_FIELDS,
        "envelope_version": 1,
        "algorithm": "AES-256-GCM",
        "key_wrapping": "AES-256-GCM (envelope encryption)",
    });

    (StatusCode::OK, Json(status)).into_response()
}

#[derive(Debug, Deserialize)]
struct EncryptFieldBody {
    pub tenant_id: Uuid,
    pub field_name: String,
    pub value: String,
}

/// Encrypt a single field value (for testing/migration tooling).
/// In production, encryption happens transparently at the data access layer.
/// This endpoint exists for:/// - Verifying encryption is working correctly after setup.
/// - Batch migration of existing unencrypted PHI data.
async fn encrypt_field(
    State(_state): State<S>,
    Json(body): Json<EncryptFieldBody>,
) -> impl IntoResponse {
// In a real deployment, the KEK would be loaded from a secure key store
// (AWS KMS, HashiCorp Vault, etc.) keyed by tenant_id. For now, we
// demonstrate the encryption API works with a test key.
    let kek = crate::field_encryption::Kek::generate();
    let kek_id_hex = hex::encode(kek.id);
    let kek_hex = hex::encode(&kek.key_bytes());
    let encryptor = crate::field_encryption::FieldEncryptor::new(vec![kek]);

    match encryptor.encrypt(&body.value) {
        Ok(encrypted) => (StatusCode::OK, Json(serde_json::json!({
            "tenant_id": body.tenant_id,
            "field_name": body.field_name,
            "encrypted": true,
            "value": encrypted,
            "is_phi": crate::field_encryption::PHI_FIELDS.contains(&body.field_name.as_str()),
            "kek_id_hex": kek_id_hex,
            "kek_hex": kek_hex,
            "note": "Store the KEK material securely. You will need kek_id_hex and kek_hex to decrypt."
        }))).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({
            "error": { "code": "ENCRYPTION_FAILED", "message": format!("{e}") }
        }))).into_response(),
    }
}

#[derive(Debug, Deserialize)]
struct DecryptFieldBody {
    #[allow(unused)]
    pub tenant_id: Uuid,
    #[allow(unused)]
    pub field_name: String,
    pub value: String,
/// Hex-encoded KEK ID (required for decryption).
    kek_id_hex: String,
/// Hex-encoded KEK (required for decryption). In production, this would come from a key store.
    kek_hex: String,
}

/// Decrypt a single field value (for testing/migration tooling).
async fn decrypt_field(
    State(_state): State<S>,
    Json(body): Json<DecryptFieldBody>,
) -> impl IntoResponse {
    let kek = match crate::field_encryption::Kek::from_hex(&body.kek_id_hex, &body.kek_hex) {
        Ok(k) => k,
        Err(e) => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "error": { "code": "INVALID_KEY", "message": format!("{e}") }
        }))).into_response(),
    };

    let encryptor = crate::field_encryption::FieldEncryptor::new(vec![kek]);

    match encryptor.decrypt(&body.value) {
        Ok(decrypted) => (StatusCode::OK, Json(serde_json::json!({
            "decrypted": true,
            "value": decrypted,
        }))).into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "error": { "code": "DECRYPTION_FAILED", "message": format!("{e}") }
        }))).into_response(),
    }
}

// ── Log Streaming Handlers ─────────────────────────────────────────────

async fn log_stream_create(State(state): State<S>, Json(body): Json<LogStreamCreateBody>) -> impl IntoResponse {
    service_result(state.log_streaming.create(
        body.tenant_id, &body.name, body.description.as_deref(),
        &body.destination_type, body.destination_config,
        body.log_categories, body.batch_size, body.batch_interval_seconds,
        body.compression_enabled.unwrap_or(false),
    ).await)
}

async fn log_stream_get(State(state): State<S>, Path(id): Path<Uuid>) -> impl IntoResponse {
    service_result(state.log_streaming.get(id).await)
}

async fn log_stream_update(State(state): State<S>, Path(id): Path<Uuid>, Json(body): Json<LogStreamUpdateBody>) -> impl IntoResponse {
    service_result(state.log_streaming.update(
        id, body.name.as_deref(), body.description.as_deref(),
        body.destination_config, body.log_categories,
    ).await)
}

async fn log_stream_delete(State(state): State<S>, Path(id): Path<Uuid>) -> impl IntoResponse {
    service_result(state.log_streaming.delete(id).await)
}

async fn log_stream_list(State(state): State<S>, Path(tenant_id): Path<Uuid>) -> impl IntoResponse {
    service_result(state.log_streaming.list(tenant_id).await)
}

async fn log_stream_pause(State(state): State<S>, Path(id): Path<Uuid>) -> impl IntoResponse {
    service_result(state.log_streaming.pause(id).await)
}

async fn log_stream_resume(State(state): State<S>, Path(id): Path<Uuid>) -> impl IntoResponse {
    service_result(state.log_streaming.resume(id).await)
}

async fn log_stream_verify(State(state): State<S>, Path(id): Path<Uuid>) -> impl IntoResponse {
    service_result(state.log_streaming.verify(id).await)
}

async fn log_stream_stats(State(state): State<S>, Path(id): Path<Uuid>) -> impl IntoResponse {
    service_result(state.log_streaming.get_stats(id).await)
}

// ── Private Deploy Handlers ────────────────────────────────────────────

async fn deploy_create(State(state): State<S>, Json(body): Json<DeployCreateBody>) -> impl IntoResponse {
    service_result(state.private_deploy.create(
        body.tenant_id, &body.name, &body.deployment_type,
        body.region.as_deref(), body.config,
    ).await)
}

async fn deploy_get(State(state): State<S>, Path(id): Path<Uuid>) -> impl IntoResponse {
    service_result(state.private_deploy.get(id).await)
}

async fn deploy_list(State(state): State<S>, Path(tenant_id): Path<Uuid>) -> impl IntoResponse {
    service_result(state.private_deploy.list(tenant_id).await)
}

async fn deploy_provision(State(state): State<S>, Path(id): Path<Uuid>) -> impl IntoResponse {
    service_result(state.private_deploy.provision(id).await)
}

async fn deploy_health(State(state): State<S>, Path(id): Path<Uuid>) -> impl IntoResponse {
    service_result(state.private_deploy.health_check(id).await)
}

async fn ip_allocate(State(state): State<S>, Json(body): Json<DedicatedIPBody>) -> impl IntoResponse {
    service_result(state.private_deploy.allocate_dedicated_ip(body.tenant_id, body.deployment_id, &body.ip_address).await)
}

async fn ip_get(State(state): State<S>, Path(id): Path<Uuid>) -> impl IntoResponse {
    service_result(state.private_deploy.get_dedicated_ip(id).await)
}

async fn ip_list(
    State(state): State<S>,
    Path(tenant_id): Path<Uuid>,
    Query(q): Query<PaginationParams>,
) -> impl IntoResponse {
    let limit = clamp_limit(q.limit.unwrap_or(50), 200);
    let offset = clamp_offset(q.offset.unwrap_or(0));
    service_result(state.private_deploy.list_dedicated_ips(tenant_id, limit, offset).await)
}

async fn ip_reputation(State(state): State<S>, Path(ip_address): Path<String>) -> impl IntoResponse {
    service_result(state.private_deploy.get_ip_reputation(&ip_address).await)
}

async fn byoip_register(State(state): State<S>, Json(body): Json<BYOIPBody>) -> impl IntoResponse {
    service_result(state.private_deploy.register_byoip(body.tenant_id, &body.cidr_block).await)
}

async fn byoip_verify(
    State(state): State<S>,
    Path(id): Path<Uuid>,
    Json(body): Json<BYOIPVerifyBody>,
) -> impl IntoResponse {
    service_result(state.private_deploy.verify_byoip(id, &body.verification_token).await)
}

// ── Sub-account Handlers ───────────────────────────────────────────────

async fn sub_account_create(State(state): State<S>, Json(body): Json<SubAccountCreateBody>) -> impl IntoResponse {
    service_result(state.sub_accounts.create(
        body.parent_id, &body.name, body.email.as_deref(),
        body.domain.as_deref(), body.plan.as_deref(),
        body.volume_limit, body.inherit_parent_settings.unwrap_or(true),
    ).await)
}

async fn sub_account_get(State(state): State<S>, Path(id): Path<Uuid>) -> impl IntoResponse {
    service_result(state.sub_accounts.get(id).await)
}

async fn sub_account_update(State(state): State<S>, Path(id): Path<Uuid>, Json(body): Json<SubAccountUpdateBody>) -> impl IntoResponse {
    service_result(state.sub_accounts.update(id, body.name.as_deref(), body.email.as_deref(), body.volume_limit, body.settings).await)
}

async fn sub_account_delete(State(state): State<S>, Path(id): Path<Uuid>) -> impl IntoResponse {
    service_result(state.sub_accounts.delete(id).await)
}

async fn sub_account_list(State(state): State<S>, Path(parent_id): Path<Uuid>, Query(q): Query<StatusFilterParams>) -> impl IntoResponse {
    let limit = clamp_limit(q.limit.unwrap_or(50), 200);
    let offset = clamp_offset(q.offset.unwrap_or(0));
    service_result(state.sub_accounts.list(parent_id, q.status.as_deref(), limit, offset).await)
}

async fn sub_account_suspend(State(state): State<S>, Path(id): Path<Uuid>, Json(body): Json<SubAccountSuspendBody>) -> impl IntoResponse {
    service_result(state.sub_accounts.suspend(id, body.reason.as_deref()).await)
}

async fn sub_account_stats(State(state): State<S>, Path(parent_id): Path<Uuid>) -> impl IntoResponse {
    service_result(state.sub_accounts.get_stats(parent_id).await)
}

async fn sub_account_api_key(State(state): State<S>, Path(id): Path<Uuid>, Json(body): Json<ApiKeyCreateBody>) -> impl IntoResponse {
    service_result(state.sub_accounts.create_api_key(id, &body.name, body.permissions, body.rate_limit).await)
}

// ── Support Handlers ───────────────────────────────────────────────────

async fn ticket_create(State(state): State<S>, Json(body): Json<TicketCreateBody>) -> impl IntoResponse {
    service_result(state.support.create_ticket(
        body.tenant_id, &body.subject, &body.description,
        &body.priority, &body.category, body.contact_email.as_deref(),
    ).await)
}

async fn ticket_get(State(state): State<S>, Path(id): Path<Uuid>) -> impl IntoResponse {
    service_result(state.support.get_ticket(id).await)
}

async fn ticket_update(State(state): State<S>, Path(id): Path<Uuid>, Json(body): Json<TicketUpdateBody>) -> impl IntoResponse {
    service_result(state.support.update_ticket(id, body.status.as_deref(), body.priority.as_deref(), body.assigned_to).await)
}

async fn ticket_list(State(state): State<S>, Path(tenant_id): Path<Uuid>, Query(q): Query<StatusFilterParams>) -> impl IntoResponse {
    let limit = clamp_limit(q.limit.unwrap_or(50), 200);
    let offset = clamp_offset(q.offset.unwrap_or(0));
    service_result(state.support.list_tickets(tenant_id, q.status.as_deref(), q.priority.as_deref(), limit, offset).await)
}

async fn comment_add(State(state): State<S>, Path(ticket_id): Path<Uuid>, Json(body): Json<CommentBody>) -> impl IntoResponse {
    service_result(state.support.add_comment(
        ticket_id, &body.author_id, &body.author_name,
        &body.author_type, &body.content, body.is_internal.unwrap_or(false),
    ).await)
}

async fn comment_list(State(state): State<S>, Path(ticket_id): Path<Uuid>, Query(q): Query<CommentFilterParams>) -> impl IntoResponse {
    service_result(state.support.get_comments(ticket_id, q.include_internal.unwrap_or(false)).await)
}

async fn ticket_escalate(State(state): State<S>, Path(id): Path<Uuid>, Json(body): Json<EscalateBody>) -> impl IntoResponse {
    service_result(state.support.escalate(id, &body.reason, body.escalated_by).await)
}

async fn ticket_satisfaction(State(state): State<S>, Path(id): Path<Uuid>, Json(body): Json<SatisfactionBody>) -> impl IntoResponse {
    service_result(state.support.submit_satisfaction(id, body.rating, body.feedback.as_deref()).await)
}

async fn support_metrics(State(state): State<S>, Path(tenant_id): Path<Uuid>) -> impl IntoResponse {
    service_result(state.support.get_metrics(tenant_id).await)
}

// ── Template Handlers ──────────────────────────────────────────────────

async fn template_submit(State(state): State<S>, Json(body): Json<TemplateSubmitBody>) -> impl IntoResponse {
    service_result(state.templates.submit(
        body.tenant_id, &body.name, &body.subject,
        &body.html_content, body.text_content.as_deref(), &body.submitted_by,
    ).await)
}

async fn template_get(State(state): State<S>, Path(id): Path<Uuid>) -> impl IntoResponse {
    service_result(state.templates.get_submission(id).await)
}

async fn template_list(State(state): State<S>, Path(tenant_id): Path<Uuid>, Query(q): Query<StatusFilterParams>) -> impl IntoResponse {
    let limit = clamp_limit(q.limit.unwrap_or(50), 200);
    let offset = clamp_offset(q.offset.unwrap_or(0));
    service_result(state.templates.list_submissions(tenant_id, q.status.as_deref(), limit, offset).await)
}

async fn template_approve(State(state): State<S>, Path(id): Path<Uuid>, Json(body): Json<TemplateReviewBody>) -> impl IntoResponse {
    service_result(state.templates.approve(id, &body.reviewed_by, body.notes.as_deref()).await)
}

async fn template_reject(State(state): State<S>, Path(id): Path<Uuid>, Json(body): Json<TemplateRejectBody>) -> impl IntoResponse {
    service_result(state.templates.reject(id, &body.reviewed_by, &body.reason).await)
}

async fn template_request_changes(State(state): State<S>, Path(id): Path<Uuid>, Json(body): Json<TemplateReviewBody>) -> impl IntoResponse {
    match &body.notes {
        Some(notes) => service_result(state.templates.request_changes(id, &body.reviewed_by, notes).await),
        None => err_json(StatusCode::BAD_REQUEST, "Notes are required for change requests"),
    }
}

async fn template_stats(State(state): State<S>, Path(tenant_id): Path<Uuid>) -> impl IntoResponse {
    service_result(state.templates.get_stats(tenant_id).await)
}

// ── Whitelabel Handlers ────────────────────────────────────────────────

async fn whitelabel_update_config(State(state): State<S>, Json(body): Json<WhiteLabelConfigBody>) -> impl IntoResponse {
    service_result(state.whitelabel.update_config(
        body.tenant_id, body.company_name.as_deref(), body.logo_url.as_deref(),
        body.favicon_url.as_deref(), body.primary_color.as_deref(),
        body.secondary_color.as_deref(), body.custom_css.as_deref(),
        body.footer_text.as_deref(), body.support_email.as_deref(),
        body.support_url.as_deref(),
    ).await)
}

async fn whitelabel_get_config(State(state): State<S>, Path(tenant_id): Path<Uuid>) -> impl IntoResponse {
    service_result(state.whitelabel.get_config(tenant_id).await)
}

async fn whitelabel_add_domain(State(state): State<S>, Json(body): Json<DomainAddBody>) -> impl IntoResponse {
    service_result(state.whitelabel.add_domain(body.tenant_id, &body.domain, &body.domain_type).await)
}

async fn whitelabel_verify_domain(State(state): State<S>, Path(id): Path<Uuid>) -> impl IntoResponse {
    service_result(state.whitelabel.verify_domain(id).await)
}

async fn whitelabel_list_domains(
    State(state): State<S>,
    Path(tenant_id): Path<Uuid>,
    Query(q): Query<PaginationParams>,
) -> impl IntoResponse {
    let limit = clamp_limit(q.limit.unwrap_or(50), 200);
    let offset = clamp_offset(q.offset.unwrap_or(0));
    service_result(state.whitelabel.list_domains(tenant_id, limit, offset).await)
}

async fn whitelabel_remove_domain(
    State(state): State<S>,
    Path((tenant_id, id)): Path<(Uuid, Uuid)>
) -> impl IntoResponse {
// #250:Now requires tenant_id for ownership verification
    service_result(state.whitelabel.remove_domain(id, tenant_id).await)
}

async fn whitelabel_update_templates(State(state): State<S>, Json(body): Json<EmailTemplateBody>) -> impl IntoResponse {
    service_result(state.whitelabel.update_email_templates(
        body.tenant_id, &body.template_type,
        body.subject_template.as_deref(), body.html_template.as_deref(),
        body.text_template.as_deref(),
    ).await)
}

async fn whitelabel_get_templates(State(state): State<S>, Path(tenant_id): Path<Uuid>) -> impl IntoResponse {
    service_result(state.whitelabel.get_email_templates(tenant_id).await)
}

// ── QBR Handlers ───────────────────────────────────────────────────────

async fn qbr_schedule(State(state): State<S>, Json(body): Json<QBRScheduleBody>) -> impl IntoResponse {
    service_result(state.qbr.schedule(body.tenant_id, body.quarter, body.year, body.scheduled_date, body.attendees).await)
}

async fn qbr_get(State(state): State<S>, Path(id): Path<Uuid>) -> impl IntoResponse {
    service_result(state.qbr.get(id).await)
}

async fn qbr_list(State(state): State<S>, Path(tenant_id): Path<Uuid>, Query(q): Query<PaginationParams>) -> impl IntoResponse {
    let limit = clamp_limit(q.limit.unwrap_or(50), 200);
    let offset = clamp_offset(q.offset.unwrap_or(0));
    service_result(state.qbr.list(tenant_id, limit, offset).await)
}

async fn qbr_generate(State(state): State<S>, Path(id): Path<Uuid>) -> impl IntoResponse {
    service_result(state.qbr.generate(id).await)
}

async fn qbr_deliver(State(state): State<S>, Path(id): Path<Uuid>) -> impl IntoResponse {
    service_result(state.qbr.mark_delivered(id).await)
}

async fn qbr_feedback(State(state): State<S>, Path(id): Path<Uuid>, Json(body): Json<QBRFeedbackBody>) -> impl IntoResponse {
    service_result(state.qbr.submit_feedback(id, body.rating, body.feedback_text.as_deref()).await)
}

async fn qbr_update_goal(State(state): State<S>, Path(id): Path<Uuid>, Json(body): Json<QBRGoalUpdateBody>) -> impl IntoResponse {
    service_result(state.qbr.update_goal(id, body.goal_id, body.current_value).await)
}

async fn qbr_benchmarks(State(state): State<S>, Query(q): Query<IndustryQuery>) -> impl IntoResponse {
    let industry = q.industry.as_deref().unwrap_or("saas");
    service_result(state.qbr.get_benchmarks(industry).await)
}

// ── PDF Generation Handlers (via pdf-renderer service) ─────────────────

static PDF_RENDERER_URL: std::sync::LazyLock<String> = std::sync::LazyLock::new(|| {
    std::env::var("PDF_RENDERER_URL").unwrap_or_else(|_| "http://pdf-renderer:3004".to_string())
});

/// POST /dpa/:tenant_id/pdf — Generate a GDPR Data Processing Agreement PDF
async fn dpa_generate_pdf(
    State(state): State<S>,
    Path(tenant_id): Path<Uuid>,
    Json(body): Json<serde_json::Value>,
) -> impl IntoResponse {
// Fetch compliance config for this tenant
    let status = match state.compliance.get_status(tenant_id).await {
        Ok(s) => s,
        Err(e) => return Err((StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to get compliance status: {e}"))),
    };

    let data = serde_json::json!({
        "company_name": body.get("company_name").and_then(|v| v.as_str()).unwrap_or("ApexMail OÜ"),
        "processor_name": body.get("processor_name").and_then(|v| v.as_str()).unwrap_or(""),
        "effective_date": chrono::Utc::now().format("%Y-%m-%d").to_string(),
        "data_categories": body.get("data_categories").cloned().unwrap_or(serde_json::json!(["Email addresses", "Names", "IP addresses", "Message content"])),
        "processing_purposes": body.get("processing_purposes").cloned().unwrap_or(serde_json::json!(["Transactional email delivery", "Analytics and reporting"])),
        "sub_processors": body.get("sub_processors").cloned().unwrap_or(serde_json::json!([])),
        "retention_days": 90,
        "tenant_id": tenant_id.to_string(),
        "compliance_status": serde_json::to_value(&status)
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("serialization error: {e}")))?,
    });

    let payload = serde_json::json!({
        "template": "dpa",
        "data": data,
    });

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("http client error: {e}")))?;
    let resp = client
        .post(format!("{}/v1/pdf/render", *PDF_RENDERER_URL))
        .json(&payload)
        .send()
        .await
        .map_err(|e| (StatusCode::BAD_GATEWAY, format!("pdf-renderer unreachable: {e}")))?;

    if !resp.status().is_success() {
        let status_code = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err((StatusCode::BAD_GATEWAY, format!("pdf-renderer error {status_code}: {body}")));
    }

    let pdf_bytes = resp
        .bytes()
        .await
        .map_err(|e| (StatusCode::BAD_GATEWAY, format!("pdf-renderer read error: {e}")))?;

    Ok((
        StatusCode::OK,
        [
            (axum::http::header::CONTENT_TYPE, "application/pdf"),
            (axum::http::header::CONTENT_DISPOSITION, "attachment; filename=\"dpa.pdf\""),
        ],
        pdf_bytes,
    ))
}

/// GET /qbr/:id/pdf — Generate a QBR PDF for the given report
async fn qbr_generate_pdf(State(state): State<S>, Path(id): Path<Uuid>) -> impl IntoResponse {
// Fetch the QBR data
    let qbr = match state.qbr.get(id).await {
        Ok(q) => q,
        Err(e) => return Err((StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to get QBR: {e}"))),
    };

    let qbr_json = serde_json::to_value(&qbr)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Serialization error: {e}")))?;

    let payload = serde_json::json!({
        "template": "qbr",
        "data": qbr_json,
    });

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("http client error: {e}")))?;
    let resp = client
        .post(format!("{}/v1/pdf/render", *PDF_RENDERER_URL))
        .json(&payload)
        .send()
        .await
        .map_err(|e| (StatusCode::BAD_GATEWAY, format!("pdf-renderer unreachable: {e}")))?;

    if !resp.status().is_success() {
        let sc = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err((StatusCode::BAD_GATEWAY, format!("pdf-renderer error {sc}: {body}")));
    }

    let pdf_bytes = resp
        .bytes()
        .await
        .map_err(|e| (StatusCode::BAD_GATEWAY, format!("pdf-renderer read error: {e}")))?;

    let content_disposition = format!("attachment; filename=\"qbr-{id}.pdf\"");

    Ok((
        StatusCode::OK,
        [
            (axum::http::header::CONTENT_TYPE.to_string(), "application/pdf".to_string()),
            (axum::http::header::CONTENT_DISPOSITION.to_string(), content_disposition),
        ],
        pdf_bytes,
    ))
}

/// GET /compliance/report/:tenant_id/pdf — Generate a compliance report PDF
async fn compliance_report_pdf(State(state): State<S>, Path(tenant_id): Path<Uuid>) -> impl IntoResponse {
// Fetch compliance report and status
    let report = match state.compliance.generate_report(tenant_id).await {
        Ok(r) => r,
        Err(e) => return Err((StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to generate report: {e}"))),
    };

    let report_json = serde_json::to_value(&report)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Serialization error: {e}")))?;

    let payload = serde_json::json!({
        "template": "compliance_report",
        "data": report_json,
    });

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("http client error: {e}")))?;
    let resp = client
        .post(format!("{}/v1/pdf/render", *PDF_RENDERER_URL))
        .json(&payload)
        .send()
        .await
        .map_err(|e| (StatusCode::BAD_GATEWAY, format!("pdf-renderer unreachable: {e}")))?;

    if !resp.status().is_success() {
        let sc = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err((StatusCode::BAD_GATEWAY, format!("pdf-renderer error {sc}: {body}")));
    }

    let pdf_bytes = resp
        .bytes()
        .await
        .map_err(|e| (StatusCode::BAD_GATEWAY, format!("pdf-renderer read error: {e}")))?;

    Ok((
        StatusCode::OK,
        [
            (axum::http::header::CONTENT_TYPE, "application/pdf"),
            (axum::http::header::CONTENT_DISPOSITION, "attachment; filename=\"compliance-report.pdf\""),
        ],
        pdf_bytes,
    ))
}

// ── Tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_router_builds() {
        let _ = Router::<Arc<AppState>>::new()
            .route("/health", get(health_check));
    }

    #[test]
    fn test_pagination_defaults() {
        let p: PaginationParams = serde_json::from_str("{}").unwrap();
        assert_eq!(p.limit, None);
        assert_eq!(p.offset, None);
    }

    #[test]
    fn test_compliance_body_deserialize() {
        let json = r#"{"tenant_id":"00000000-0000-0000-0000-000000000001","frameworks":["hipaa","soc2"],"hipaa_enabled":true}"#;
        let body: ComplianceEnableBody = serde_json::from_str(json).unwrap();
        assert_eq!(body.frameworks.len(), 2);
        assert_eq!(body.hipaa_enabled, Some(true));
    }

    #[test]
    fn test_log_stream_body_deserialize() {
        let json = r#"{"tenant_id":"00000000-0000-0000-0000-000000000001","name":"test","destination_type":"s3"}"#;
        let body: LogStreamCreateBody = serde_json::from_str(json).unwrap();
        assert_eq!(body.name, "test");
        assert_eq!(body.compression_enabled, None);
    }

    #[test]
    fn test_qbr_schedule_body_deserialize() {
        let json = r#"{"tenant_id":"00000000-0000-0000-0000-000000000001","quarter":1,"year":2024}"#;
        let body: QBRScheduleBody = serde_json::from_str(json).unwrap();
        assert_eq!(body.quarter, 1);
        assert_eq!(body.year, 2024);
        assert_eq!(body.scheduled_date, None);
    }

    #[test]
    fn test_template_submit_body_deserialize() {
        let json = r#"{"tenant_id":"00000000-0000-0000-0000-000000000001","name":"t1","subject":"s","html_content":"<h1>hi</h1>","submitted_by":"user1"}"#;
        let body: TemplateSubmitBody = serde_json::from_str(json).unwrap();
        assert_eq!(body.name, "t1");
        assert_eq!(body.submitted_by, "user1");
    }
}
