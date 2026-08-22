use axum::{
    extract::{DefaultBodyLimit, Path, Query, State},
    http::{
        header::{AUTHORIZATION, CONTENT_TYPE},
        HeaderMap, StatusCode,
    },
    middleware,
    response::{Html, IntoResponse},
    routing::{delete, get, post, put},
    Extension, Json, Router,
};
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use metrics_exporter_prometheus::PrometheusHandle;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use std::sync::Arc;
use std::time::Duration;
use tower_http::timeout::TimeoutLayer;
use uuid::Uuid;

use crate::compliance::ComplianceService;
use crate::config::Config;
use crate::contracts::{
    AmendmentInput, CancelContractInput, ContractService, CreateContractInput, PurchaseOrderInput,
    RenewContractInput, SignContractInput,
};
use crate::log_streaming::LogStreamingService;
use crate::private_deploy::PrivateDeployService;
use crate::qbr::QBRService;
use crate::sso::SSOService;
use crate::sub_accounts::SubAccountService;
use crate::support::SupportService;
use crate::template_approval::TemplateApprovalService;
use crate::types::{
    ApiResult, ContractAdditionalFee, ContractRenewalTerms, SSOConfigureRequest, SSOPublicConfig,
    SubAccount,
};
use crate::whitelabel::WhiteLabelService;

// ── Shared state ───────────────────────────────────────────────────────

pub struct AppState {
    pub db: PgPool,
    pub config: Config,
    pub contracts: ContractService,
    pub sso: SSOService,
    pub compliance: ComplianceService,
    pub log_streaming: LogStreamingService,
    pub private_deploy: PrivateDeployService,
    pub sub_accounts: SubAccountService,
    pub support: SupportService,
    pub templates: TemplateApprovalService,
    pub whitelabel: WhiteLabelService,
    pub qbr: QBRService,
    /// Shared HTTP client with connection pooling — avoids creating a new
    /// reqwest::Client per request (H-04).
    pub http_client: reqwest::Client,
    /// Prometheus recorder handle rendered by the unauthenticated `/metrics`
    /// endpoint for the monitoring network.
    pub metrics_handle: PrometheusHandle,
}

impl AppState {
    pub fn new(db: PgPool, config: Config, metrics_handle: PrometheusHandle) -> Self {
        let http_client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .pool_max_idle_per_host(8)
            .build()
            .expect("Failed to build HTTP client");
        Self {
            config: config.clone(),
            contracts: ContractService::new(db.clone()),
            sso: SSOService::new(db.clone(), config.clone()),
            compliance: ComplianceService::new(db.clone()),
            // Fix H-2: destination-config secrets are encrypted at rest with
            // a purpose-bound KEK derived from the configured stream key.
            log_streaming: LogStreamingService::with_secret_key(
                db.clone(),
                &config.log_stream.encryption_key,
            ),
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
            http_client,
            metrics_handle,
        }
    }
}

type S = Arc<AppState>;

#[derive(Debug, Clone)]
struct AuthContext {
    user_id: String,
    tenant_id: String,
    is_admin: bool,
}

#[derive(Debug, Clone, Deserialize)]
struct JwtClaims {
    sub: String,
    tenant_id: String,
    #[serde(default)]
    admin: bool,
    #[serde(default)]
    #[allow(
        dead_code,
        reason = "validated by jsonwebtoken against config, not read directly"
    )]
    aud: Option<String>,
    #[serde(default)]
    #[allow(
        dead_code,
        reason = "validated by jsonwebtoken against config, not read directly"
    )]
    iss: Option<String>,
    #[serde(rename = "exp")]
    _exp: usize,
}

async fn auth_middleware(
    State(state): State<S>,
    mut req: axum::extract::Request,
    next: middleware::Next,
) -> impl IntoResponse {
    let path = req.uri().path();
    if path == "/health"
        || path == "/readiness"
        || path == "/metrics"
        || path.starts_with("/sso/login/")
        || path == "/sso/validate"
    {
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

    let mut validation = Validation::new(Algorithm::RS256);
    validation.validate_exp = true;
    validation.validate_nbf = true;
    // J-1: when the deployment pins an audience/issuer, tokens that do not
    // match — or omit the pinned claim entirely — are rejected instead of
    // being accepted on signature alone. When nothing is pinned, tokens are
    // not rejected merely for carrying an `aud` claim (jsonwebtoken's
    // default `validate_aud` would otherwise do so).
    if let Some(aud) = state.config.jwt_audience.as_deref() {
        validation.set_audience(&[aud]);
        validation.required_spec_claims.insert("aud".to_string());
    } else {
        validation.validate_aud = false;
    }
    if let Some(iss) = state.config.jwt_issuer.as_deref() {
        validation.set_issuer(&[iss]);
        validation.required_spec_claims.insert("iss".to_string());
    }

    let decoding_key = match DecodingKey::from_rsa_pem(state.config.jwt_public_key_pem.as_bytes()) {
        Ok(key) => key,
        Err(_) => {
            return err_json(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Server configuration error: invalid JWT public key",
            )
            .into_response()
        }
    };

    let claims = match jsonwebtoken::decode::<JwtClaims>(token, &decoding_key, &validation) {
        Ok(token) => token.claims,
        Err(_) => {
            return err_json(StatusCode::UNAUTHORIZED, "Invalid or expired token").into_response()
        }
    };

    req.extensions_mut().insert(AuthContext {
        user_id: claims.sub,
        tenant_id: claims.tenant_id,
        is_admin: claims.admin,
    });

    next.run(req).await
}

// ── Request body types ─────────────────────────────────────────────────

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PaginationParams {
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StatusFilterParams {
    pub status: Option<String>,
    pub priority: Option<String>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

/// Ticket list query: supports keyset pagination via `cursor`
/// (`<rfc3339-created-at>,<ticket-uuid>` of the last row seen) in addition
/// to the classic limit/offset pair, plus a bounded subject search (`q`).
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TicketListParams {
    pub status: Option<String>,
    pub priority: Option<String>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
    pub cursor: Option<String>,
    pub q: Option<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditFilterParams {
    pub action: Option<String>,
    pub resource_type: Option<String>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DomainQuery {
    pub domain: Option<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IndustryQuery {
    pub industry: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ContractCommittedVolumeBody {
    pub emails: i64,
    pub api_calls: i64,
    pub storage: i64,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ContractOverageRatesBody {
    pub emails_per_thousand: i64,
    pub api_calls_per_thousand: i64,
    pub storage_per_gb: i64,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ContractCreateBody {
    pub start_date: chrono::DateTime<chrono::Utc>,
    pub end_date: chrono::DateTime<chrono::Utc>,
    pub base_fee: i64,
    pub committed_volume: ContractCommittedVolumeBody,
    pub overage_rates: ContractOverageRatesBody,
    pub payment_terms: String,
    pub custom_features: Option<Vec<String>>,
    pub allow_purchase_orders: Option<bool>,
    pub dedicated_support: Option<bool>,
    pub custom_sla: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ContractSignBody {
    pub signature_data: String,
    pub signer_name: String,
    pub signer_title: String,
    pub signed_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ContractAmendmentChangesBody {
    pub base_fee: Option<i64>,
    pub committed_volume: Option<ContractCommittedVolumeOptionalBody>,
    pub overage_rates: Option<ContractOverageRatesOptionalBody>,
    pub end_date: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ContractCommittedVolumeOptionalBody {
    pub emails: Option<i64>,
    pub api_calls: Option<i64>,
    pub storage: Option<i64>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ContractOverageRatesOptionalBody {
    pub emails_per_thousand: Option<i64>,
    pub api_calls_per_thousand: Option<i64>,
    pub storage_per_gb: Option<i64>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ContractAmendmentBody {
    pub reason: String,
    pub proposed_changes: ContractAmendmentChangesBody,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ContractCancelBody {
    pub reason: String,
    pub effective_date: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ContractRenewTermsBody {
    pub base_fee: Option<i64>,
    pub committed_volume: Option<ContractCommittedVolumeOptionalBody>,
    pub overage_rates: Option<ContractOverageRatesOptionalBody>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ContractRenewBody {
    pub new_end_date: chrono::DateTime<chrono::Utc>,
    pub new_terms: Option<ContractRenewTermsBody>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PurchaseOrderBody {
    pub po_number: String,
    pub amount: i64,
    pub issued_date: chrono::DateTime<chrono::Utc>,
    pub expiry_date: Option<chrono::DateTime<chrono::Utc>>,
    pub attachment_url: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ComplianceEnableBody {
    pub tenant_id: String,
    pub frameworks: Vec<String>,
    pub hipaa_enabled: Option<bool>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BAABody {
    pub tenant_id: String,
    pub signatory_name: String,
    pub signatory_title: String,
    pub signatory_email: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditLogBody {
    pub tenant_id: String,
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
    pub metadata: Option<serde_json::Value>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DataAccessBody {
    pub tenant_id: String,
    pub requester_id: String,
    pub requester_email: String,
    pub request_type: String,
    pub resource_type: Option<String>,
    pub justification: Option<String>,
    pub identifiers: Option<serde_json::Value>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DataAccessApproveBody {
    pub approved_by: String,
    pub duration_minutes: i32,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DataDeletionBody {
    pub tenant_id: String,
    pub requester_id: String,
    pub requester_email: String,
    pub identifiers: Option<serde_json::Value>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LogStreamCreateBody {
    pub tenant_id: String,
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
#[serde(deny_unknown_fields)]
pub struct LogStreamUpdateBody {
    pub name: Option<String>,
    pub description: Option<String>,
    pub destination_config: Option<serde_json::Value>,
    pub log_categories: Option<Vec<String>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeployCreateBody {
    pub tenant_id: String,
    pub name: String,
    pub deployment_type: String,
    pub region: Option<String>,
    pub config: Option<serde_json::Value>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DedicatedIPBody {
    pub tenant_id: String,
    pub deployment_id: Option<Uuid>,
    pub ip_address: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BYOIPBody {
    pub tenant_id: String,
    pub cidr_block: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BYOIPVerifyBody {
    pub verification_token: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SubAccountCreateBody {
    pub parent_id: String,
    pub name: String,
    pub email: Option<String>,
    pub domain: Option<String>,
    pub plan: Option<String>,
    pub volume_limit: Option<i64>,
    pub inherit_parent_settings: Option<bool>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SubAccountUpdateBody {
    pub name: Option<String>,
    pub email: Option<String>,
    pub volume_limit: Option<i64>,
    pub settings: Option<serde_json::Value>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SubAccountSuspendBody {
    pub reason: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApiKeyCreateBody {
    pub name: String,
    pub permissions: Option<Vec<String>>,
    pub rate_limit: Option<i32>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TicketCreateBody {
    pub tenant_id: String,
    pub subject: String,
    pub description: String,
    pub priority: String,
    pub category: String,
    pub contact_email: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TicketUpdateBody {
    pub status: Option<String>,
    pub priority: Option<String>,
    pub assigned_to: Option<Uuid>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommentBody {
    pub author_id: String,
    pub author_name: String,
    pub author_type: String,
    pub content: String,
    pub is_internal: Option<bool>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommentFilterParams {
    pub include_internal: Option<bool>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EscalateBody {
    pub reason: String,
    pub escalated_by: Uuid,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SatisfactionBody {
    pub rating: i32,
    pub feedback: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TemplateSubmitBody {
    pub tenant_id: String,
    pub name: String,
    pub subject: String,
    pub html_content: String,
    pub text_content: Option<String>,
    pub submitted_by: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TemplateReviewBody {
    pub reviewed_by: String,
    pub notes: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TemplateRejectBody {
    pub reviewed_by: String,
    pub reason: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WhiteLabelConfigBody {
    pub tenant_id: String,
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
#[serde(deny_unknown_fields)]
pub struct DomainAddBody {
    pub tenant_id: String,
    pub domain: String,
    pub domain_type: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EmailTemplateBody {
    pub tenant_id: String,
    pub template_type: String,
    pub subject_template: Option<String>,
    pub html_template: Option<String>,
    pub text_template: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QBRScheduleBody {
    pub tenant_id: String,
    pub quarter: i32,
    pub year: i32,
    pub scheduled_date: Option<chrono::NaiveDate>,
    pub attendees: Option<serde_json::Value>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QBRFeedbackBody {
    pub rating: i32,
    pub feedback_text: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QBRGoalUpdateBody {
    pub goal_id: Uuid,
    pub current_value: f64,
}

// ── Router ─────────────────────────────────────────────────────────────

fn contract_routes() -> Router<S> {
    Router::new()
        .route("/contracts", get(contract_list))
        .route("/contracts", post(contract_create))
        .route("/contracts/:contract_id", get(contract_get))
        .route("/contracts/:contract_id/pdf", get(contract_pdf))
        .route("/contracts/:contract_id/usage", get(contract_usage))
        .route("/contracts/:contract_id/submit", post(contract_submit))
        .route("/contracts/:contract_id/sign", post(contract_sign))
        .route(
            "/contracts/:contract_id/amendments",
            post(contract_amendment),
        )
        .route("/contracts/:contract_id/cancel", post(contract_cancel))
        .route(
            "/contracts/:contract_id/renewal-quote",
            get(contract_renewal_quote),
        )
        .route("/contracts/:contract_id/renew", post(contract_renew))
        .route(
            "/contracts/:contract_id/purchase-orders",
            post(contract_purchase_order),
        )
}

/// Build the CORS layer from the service configuration.
///
/// Fix J-10: the `cors_origins` config was parsed but never attached to the
/// router, so the configured policy was dead. `*` (the non-production
/// default) maps to `Any`; an explicit list maps to an exact-origin allowlist.
fn cors_layer(config: &Config) -> tower_http::cors::CorsLayer {
    use tower_http::cors::CorsLayer;
    let layer = CorsLayer::new();
    if config.cors_origins.iter().any(|origin| origin == "*") {
        layer.allow_origin(tower_http::cors::Any)
    } else {
        let origins: Vec<axum::http::HeaderValue> = config
            .cors_origins
            .iter()
            .filter_map(|origin| origin.parse().ok())
            .collect();
        layer.allow_origin(origins)
    }
}

/// Create the enterprise API router.
/// # Security Note (#249)
/// This router must be wrapped with authentication middleware before deployment.
pub fn router(state: Arc<AppState>) -> Router {
    let cors = cors_layer(&state.config);
    Router::new()
        // Health (unauthenticated)
        .route("/health", get(health_check))
        .route("/readiness", get(readiness_check))
        .route("/metrics", get(metrics))
        .merge(contract_routes())
        .nest("/api/enterprise", contract_routes())
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
        .route(
            "/compliance/zero-retention/:tenant_id",
            post(compliance_zero_retention),
        )
        .route("/compliance/audit", post(compliance_log_audit))
        .route(
            "/compliance/audit/:tenant_id",
            get(compliance_get_audit_logs),
        )
        .route("/compliance/data-access", post(compliance_data_access))
        .route(
            "/compliance/data-access/:id/approve",
            post(compliance_approve_access),
        )
        .route("/compliance/data-deletion", post(compliance_data_deletion))
        .route("/compliance/report/:tenant_id", get(compliance_report))
        .route("/compliance/status/:tenant_id", get(compliance_status))
        // Encryption (HIPAA field-level encryption management)
        .route(
            "/compliance/encryption/status/:tenant_id",
            get(encryption_status),
        )
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
        // Fix J-4: list/revoke endpoints for sub-account API keys
        .route("/sub-accounts/:id/api-keys", get(sub_account_api_keys_list))
        .route(
            "/sub-accounts/:id/api-keys/:key_id/revoke",
            post(sub_account_api_key_revoke),
        )
        // Support
        .route("/support/tickets", post(ticket_create))
        .route("/support/tickets/:id", get(ticket_get))
        .route("/support/tickets/:id", put(ticket_update))
        .route("/support/tickets/tenant/:tenant_id", get(ticket_list))
        .route("/support/tickets/:id/comments", post(comment_add))
        .route("/support/tickets/:id/comments", get(comment_list))
        .route("/support/tickets/:id/escalate", post(ticket_escalate))
        .route(
            "/support/tickets/:id/satisfaction",
            post(ticket_satisfaction),
        )
        .route("/support/metrics/:tenant_id", get(support_metrics))
        // Templates
        .route("/templates/submit", post(template_submit))
        .route("/templates/:id", get(template_get))
        .route("/templates/tenant/:tenant_id", get(template_list))
        .route("/templates/:id/approve", post(template_approve))
        .route("/templates/:id/reject", post(template_reject))
        .route(
            "/templates/:id/request-changes",
            post(template_request_changes),
        )
        .route("/templates/stats/:tenant_id", get(template_stats))
        // Whitelabel
        .route("/whitelabel/config", put(whitelabel_update_config))
        .route("/whitelabel/config/:tenant_id", get(whitelabel_get_config))
        .route("/whitelabel/domains", post(whitelabel_add_domain))
        .route(
            "/whitelabel/domains/:id/verify",
            post(whitelabel_verify_domain),
        )
        .route(
            "/whitelabel/domains/tenant/:tenant_id",
            get(whitelabel_list_domains),
        )
        .route(
            "/whitelabel/domains/:tenant_id/:id",
            delete(whitelabel_remove_domain),
        )
        .route(
            "/whitelabel/email-templates",
            put(whitelabel_update_templates),
        )
        .route(
            "/whitelabel/email-templates/:tenant_id",
            get(whitelabel_get_templates),
        )
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
        .route(
            "/compliance/report/:tenant_id/pdf",
            get(compliance_report_pdf),
        )
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            auth_middleware,
        ))
        .with_state(state)
        .layer(cors)
        .layer(DefaultBodyLimit::max(2 * 1024 * 1024)) // 2 MB
        .layer(TimeoutLayer::new(Duration::from_secs(30)))
}

// ── Helpers ────────────────────────────────────────────────────────────

fn ok_json<T: serde::Serialize>(data: T) -> (StatusCode, Json<serde_json::Value>) {
    match serde_json::to_value(&data) {
        Ok(v) => (StatusCode::OK, Json(v)),
        Err(e) => {
            tracing::error!(error = %e, "JSON serialization failed");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "internal serialization error"})),
            )
        }
    }
}

fn json_status<T: serde::Serialize>(
    status: StatusCode,
    data: T,
) -> (StatusCode, Json<serde_json::Value>) {
    match serde_json::to_value(&data) {
        Ok(v) => (status, Json(v)),
        Err(e) => {
            tracing::error!(error = %e, "JSON serialization failed");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "internal serialization error"})),
            )
        }
    }
}

fn err_json(status: StatusCode, msg: &str) -> (StatusCode, Json<serde_json::Value>) {
    (status, Json(serde_json::json!({"error": msg})))
}

fn resolve_tenant_id(
    headers: &HeaderMap,
    auth: &AuthContext,
) -> Result<String, (StatusCode, Json<serde_json::Value>)> {
    let override_tenant = headers
        .get("x-tenant-id")
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty());

    match override_tenant {
        Some(tenant_id) if auth.is_admin => Ok(tenant_id.to_string()),
        Some(tenant_id) if tenant_id == auth.tenant_id => Ok(auth.tenant_id.clone()),
        Some(_) => Err(err_json(
            StatusCode::FORBIDDEN,
            "Tenant override requires admin access",
        )),
        None => Ok(auth.tenant_id.clone()),
    }
}

/// Verify that the authenticated user owns (or is an admin of) the given tenant.
fn verify_tenant_access(
    auth: &AuthContext,
    tenant_id: &str,
) -> Result<(), (StatusCode, Json<serde_json::Value>)> {
    if auth.is_admin || auth.tenant_id == tenant_id {
        Ok(())
    } else {
        Err(err_json(StatusCode::FORBIDDEN, "Tenant access denied"))
    }
}

fn require_admin(auth: &AuthContext) -> Option<(StatusCode, Json<serde_json::Value>)> {
    if auth.is_admin {
        None
    } else {
        Some(err_json(StatusCode::FORBIDDEN, "Admin access required"))
    }
}

/// Types fetched by ID whose owning tenant must be checked against the
/// authenticated caller before the resource is returned or mutated (fix A:
/// by-ID handlers previously resolved any UUID across tenants).
trait TenantOwned {
    fn owner_tenant_id(&self) -> &str;
}

/// Check a fetched resource against the caller's tenant.
///
/// Mirrors the sibling handlers that already call `verify_tenant_access`:
/// the resource's owner tenant (from the DB) must match the caller's tenant
/// (or the caller must be an admin). `None` means "resource not found" and
/// lets the underlying service result surface its normal NOT_FOUND payload.
async fn guard_resource_tenant<T: TenantOwned + serde::Serialize>(
    auth: &AuthContext,
    result: &Result<crate::types::ApiResult<T>, String>,
) -> Option<(StatusCode, Json<serde_json::Value>)> {
    match result {
        Ok(api_result) => match api_result.data.as_ref() {
            Some(resource) => verify_tenant_access(auth, resource.owner_tenant_id()).err(),
            None => None,
        },
        Err(_) => None,
    }
}

macro_rules! impl_tenant_owned {
    ($($t:ty),* $(,)?) => {
        $(
            impl TenantOwned for $t {
                fn owner_tenant_id(&self) -> &str {
                    &self.tenant_id
                }
            }
        )*
    };
}

impl_tenant_owned!(
    crate::types::DataAccessRequest,
    crate::types::LogStream,
    crate::types::PrivateDeployment,
    crate::types::DedicatedIP,
    crate::types::BYOIPRange,
    crate::types::SupportTicket,
    crate::types::TemplateSubmission,
    crate::types::WhiteLabelDomain,
    crate::types::QuarterlyBusinessReview,
);

fn unwrap_contract_result<T>(
    result: ApiResult<T>,
) -> Result<T, (StatusCode, Json<serde_json::Value>)>
where
    T: serde::Serialize,
{
    match (result.success, result.data, result.error.as_deref()) {
        (true, Some(data), _) => Ok(data),
        (_, _, Some("Contract not found")) => {
            Err(err_json(StatusCode::NOT_FOUND, "Contract not found"))
        }
        (_, _, Some(message)) => Err(err_json(StatusCode::INTERNAL_SERVER_ERROR, message)),
        _ => Err(err_json(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Unexpected contract response",
        )),
    }
}

fn clamp_limit(limit: i64, max: i64) -> i64 {
    limit.clamp(1, max)
}

/// Fix J-8: convert a per-thousand-emails overage rate into the per-email
/// `overage_rate` stored on contracts using proper rounding. The previous
/// integer division (`emails_per_thousand / 10`) silently truncated — a rate
/// of 5 became 0, i.e. free overage.
fn overage_rate_from_per_thousand(emails_per_thousand: i64) -> i64 {
    ((emails_per_thousand as f64) / 10.0).round() as i64
}

fn clamp_offset(offset: i64) -> i64 {
    offset.clamp(0, 100_000)
}

fn service_result<T: serde::Serialize>(
    result: Result<crate::types::ApiResult<T>, String>,
) -> (StatusCode, Json<serde_json::Value>) {
    match result {
        Ok(r) => match serde_json::to_value(&r) {
            Ok(v) => (StatusCode::OK, Json(v)),
            Err(e) => {
                tracing::error!(error = %e, "JSON serialization failed in service_result");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({"error": "internal serialization error"})),
                )
            }
        },
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e})),
        ),
    }
}

/// Support-surface variant of [`service_result`]: the SupportService returns
/// structured error codes (VALIDATION, INVALID_TRANSITION, ALREADY_SUBMITTED,
/// NOT_FOUND) that must surface as real HTTP status codes instead of a 200
/// with `success:false`. The response body still carries the ApiResult JSON,
/// so the client keeps the human-readable error message.
fn support_result<T: serde::Serialize>(
    result: Result<crate::types::ApiResult<T>, String>,
) -> (StatusCode, Json<serde_json::Value>) {
    if let Ok(ref r) = result {
        if !r.success {
            let status = match r.code.as_deref() {
                Some("VALIDATION") => StatusCode::BAD_REQUEST,
                Some("INVALID_TRANSITION") | Some("ALREADY_SUBMITTED") => StatusCode::CONFLICT,
                Some("NOT_FOUND") => StatusCode::NOT_FOUND,
                _ => StatusCode::OK,
            };
            if status != StatusCode::OK {
                let body = serde_json::to_value(r).unwrap_or_else(
                    |_| serde_json::json!({"success": false, "error": "invalid request"}),
                );
                return (status, Json(body));
            }
        }
    }
    service_result(result)
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

/// GET /metrics — Prometheus scrape endpoint.
///
/// Fix H-3: metrics are no longer exposed unauthenticated to any network
/// peer. Access is granted when either:
///   * the peer address is loopback (the monitoring sidecar pattern), or
///   * the request carries the configured `METRICS_TOKEN` bearer token.
async fn metrics(
    State(state): State<S>,
    connect_info: Option<axum::extract::ConnectInfo<std::net::SocketAddr>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let peer_is_loopback = connect_info
        .map(|ci| ci.0.ip().is_loopback())
        .unwrap_or(false);

    let token_ok = state
        .config
        .metrics_token
        .as_deref()
        .and_then(|expected| {
            headers
                .get(AUTHORIZATION)
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.strip_prefix("Bearer "))
                .map(|provided| {
                    // constant-time comparison via HMAC over both values
                    let h = |v: &str| {
                        use sha2::Digest;
                        let mut hasher = sha2::Sha256::new();
                        hasher.update(v.as_bytes());
                        hasher.finalize()
                    };
                    h(provided) == h(expected)
                })
        })
        .unwrap_or(false);

    if !peer_is_loopback && !token_ok {
        return err_json(StatusCode::UNAUTHORIZED, "Metrics access denied").into_response();
    }

    (
        [(CONTENT_TYPE, "text/plain; version=0.0.4; charset=utf-8")],
        state.metrics_handle.render(),
    )
        .into_response()
}

// ── Contract Handlers ──────────────────────────────────────────────────

async fn contract_list(
    State(state): State<S>,
    Extension(auth): Extension<AuthContext>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let tenant_id = match resolve_tenant_id(&headers, &auth) {
        Ok(tenant_id) => tenant_id,
        Err(error) => return error,
    };

    match state.contracts.list_contracts(&tenant_id).await {
        Ok(result) => match unwrap_contract_result(result) {
            Ok(contracts) => json_status(
                StatusCode::OK,
                serde_json::json!({ "contracts": contracts }),
            ),
            Err(error) => error,
        },
        Err(error) => err_json(StatusCode::INTERNAL_SERVER_ERROR, &error),
    }
}

async fn contract_get(
    State(state): State<S>,
    Extension(auth): Extension<AuthContext>,
    headers: HeaderMap,
    Path(contract_id): Path<Uuid>,
) -> impl IntoResponse {
    let tenant_id = match resolve_tenant_id(&headers, &auth) {
        Ok(tenant_id) => tenant_id,
        Err(error) => return error,
    };

    match state.contracts.get_contract(contract_id, &tenant_id).await {
        Ok(result) => match unwrap_contract_result(result) {
            Ok(contract) => json_status(StatusCode::OK, contract),
            Err(error) => error,
        },
        Err(error) => err_json(StatusCode::INTERNAL_SERVER_ERROR, &error),
    }
}

async fn contract_pdf(
    State(state): State<S>,
    Extension(auth): Extension<AuthContext>,
    headers: HeaderMap,
    Path(contract_id): Path<Uuid>,
) -> impl IntoResponse {
    let tenant_id = match resolve_tenant_id(&headers, &auth) {
        Ok(tenant_id) => tenant_id,
        Err(error) => return error.into_response(),
    };

    match state.contracts.get_contract(contract_id, &tenant_id).await {
        Ok(result) => match unwrap_contract_result(result) {
            Ok(contract) => Html(state.contracts.generate_contract_pdf(&contract)).into_response(),
            Err(error) => error.into_response(),
        },
        Err(error) => err_json(StatusCode::INTERNAL_SERVER_ERROR, &error).into_response(),
    }
}

async fn contract_usage(
    State(state): State<S>,
    Extension(auth): Extension<AuthContext>,
    headers: HeaderMap,
    Path(contract_id): Path<Uuid>,
) -> impl IntoResponse {
    let tenant_id = match resolve_tenant_id(&headers, &auth) {
        Ok(tenant_id) => tenant_id,
        Err(error) => return error,
    };

    match state
        .contracts
        .get_contract_usage(&tenant_id, contract_id)
        .await
    {
        Ok(result) => match unwrap_contract_result(result) {
            Ok(usage) => json_status(StatusCode::OK, usage),
            Err(error) => error,
        },
        Err(error) => err_json(StatusCode::INTERNAL_SERVER_ERROR, &error),
    }
}

async fn contract_create(
    State(state): State<S>,
    Extension(auth): Extension<AuthContext>,
    headers: HeaderMap,
    Json(body): Json<ContractCreateBody>,
) -> impl IntoResponse {
    if let Some(error) = require_admin(&auth) {
        return error;
    }

    if body.base_fee < 0
        || body.committed_volume.emails < 0
        || body.committed_volume.api_calls < 0
        || body.committed_volume.storage < 0
        || body.overage_rates.emails_per_thousand < 0
        || body.overage_rates.api_calls_per_thousand < 0
        || body.overage_rates.storage_per_gb < 0
    {
        return err_json(
            StatusCode::BAD_REQUEST,
            "Numeric contract fields must be non-negative",
        );
    }

    let payment_terms_days = match body.payment_terms.as_str() {
        "net30" => 30,
        "net60" => 60,
        _ => {
            return err_json(
                StatusCode::BAD_REQUEST,
                "paymentTerms must be net30 or net60",
            )
        }
    };

    let tenant_id = match resolve_tenant_id(&headers, &auth) {
        Ok(tenant_id) => tenant_id,
        Err(error) => return error,
    };

    let dedicated_support = body.dedicated_support.unwrap_or(false);
    let additional_fees = if dedicated_support {
        vec![ContractAdditionalFee {
            name: "Dedicated Support".to_string(),
            amount: 0,
            frequency: "monthly".to_string(),
        }]
    } else {
        vec![]
    };

    let custom_terms = serde_json::json!({
        "customFeatures": body.custom_features.clone().unwrap_or_default(),
        "allowPurchaseOrders": body.allow_purchase_orders.unwrap_or(false),
        "customSla": body.custom_sla.clone(),
        "apiOveragePerThousand": body.overage_rates.api_calls_per_thousand,
        "storageOveragePerGb": body.overage_rates.storage_per_gb,
    })
    .to_string();

    match state
        .contracts
        .create_contract(CreateContractInput {
            tenant_id: tenant_id.clone(),
            name: format!("Enterprise Contract - {tenant_id}"),
            start_date: body.start_date,
            end_date: body.end_date,
            auto_renew: false,
            base_price: body.base_fee,
            committed_volume: body.committed_volume.emails,
            overage_rate: overage_rate_from_per_thousand(body.overage_rates.emails_per_thousand),
            annual_prepay_discount: 0,
            additional_fees,
            payment_terms_days,
            sla_credit_percentage: 10,
            custom_terms: Some(custom_terms),
            allow_purchase_orders: body.allow_purchase_orders.unwrap_or(false),
            dedicated_support,
            custom_features: body.custom_features.unwrap_or_default(),
            custom_sla: body.custom_sla,
        })
        .await
    {
        Ok(result) => match unwrap_contract_result(result) {
            Ok(contract) => json_status(StatusCode::CREATED, contract),
            Err(error) => error,
        },
        Err(error) => err_json(StatusCode::INTERNAL_SERVER_ERROR, &error),
    }
}

async fn contract_submit(
    State(state): State<S>,
    Extension(auth): Extension<AuthContext>,
    headers: HeaderMap,
    Path(contract_id): Path<Uuid>,
) -> impl IntoResponse {
    let tenant_id = match resolve_tenant_id(&headers, &auth) {
        Ok(tenant_id) => tenant_id,
        Err(error) => return error,
    };

    match state
        .contracts
        .submit_for_signature(&tenant_id, contract_id)
        .await
    {
        Ok(result) => match unwrap_contract_result(result) {
            Ok(contract) => json_status(StatusCode::OK, contract),
            Err(error) => error,
        },
        Err(error) => err_json(StatusCode::INTERNAL_SERVER_ERROR, &error),
    }
}

async fn contract_sign(
    State(state): State<S>,
    Extension(auth): Extension<AuthContext>,
    headers: HeaderMap,
    Path(contract_id): Path<Uuid>,
    Json(body): Json<ContractSignBody>,
) -> impl IntoResponse {
    let tenant_id = match resolve_tenant_id(&headers, &auth) {
        Ok(tenant_id) => tenant_id,
        Err(error) => return error,
    };

    // Fix D: non-admin callers can only record a tenant-side signature —
    // activation and the `tenants.plan` change require the platform-admin
    // counter-signature path below.
    if !auth.is_admin {
        return match state
            .contracts
            .sign_contract(
                &tenant_id,
                contract_id,
                SignContractInput {
                    signature_data: body.signature_data,
                    signer_name: body.signer_name,
                    signer_title: body.signer_title,
                    signed_at: body.signed_at,
                },
            )
            .await
        {
            Ok(result) => match unwrap_contract_result(result) {
                Ok(contract) => json_status(StatusCode::OK, contract),
                Err(error) => error,
            },
            Err(error) => err_json(StatusCode::INTERNAL_SERVER_ERROR, &error),
        };
    }

    // Platform-admin counter-signature: activates the contract and promotes
    // the tenant plan. Requires a tenant signature to already exist.
    match state.contracts.counter_sign_contract(contract_id).await {
        Ok(result) => match unwrap_contract_result(result) {
            Ok(contract) => json_status(StatusCode::OK, contract),
            Err(error) => error,
        },
        Err(error) => err_json(StatusCode::INTERNAL_SERVER_ERROR, &error),
    }
}

async fn contract_amendment(
    State(state): State<S>,
    Extension(auth): Extension<AuthContext>,
    headers: HeaderMap,
    Path(contract_id): Path<Uuid>,
    Json(body): Json<ContractAmendmentBody>,
) -> impl IntoResponse {
    let tenant_id = match resolve_tenant_id(&headers, &auth) {
        Ok(tenant_id) => tenant_id,
        Err(error) => return error,
    };

    let proposed_changes = match serde_json::to_value(&body.proposed_changes) {
        Ok(value) => value,
        Err(error) => {
            return err_json(
                StatusCode::BAD_REQUEST,
                &format!("Invalid amendment payload: {error}"),
            )
        }
    };

    match state
        .contracts
        .request_amendment(
            &tenant_id,
            contract_id,
            AmendmentInput {
                reason: body.reason,
                proposed_changes,
            },
        )
        .await
    {
        Ok(result) => match unwrap_contract_result(result) {
            Ok(amendment) => json_status(StatusCode::CREATED, amendment),
            Err(error) => error,
        },
        Err(error) => err_json(StatusCode::INTERNAL_SERVER_ERROR, &error),
    }
}

async fn contract_cancel(
    State(state): State<S>,
    Extension(auth): Extension<AuthContext>,
    headers: HeaderMap,
    Path(contract_id): Path<Uuid>,
    Json(body): Json<ContractCancelBody>,
) -> impl IntoResponse {
    let tenant_id = match resolve_tenant_id(&headers, &auth) {
        Ok(tenant_id) => tenant_id,
        Err(error) => return error,
    };

    match state
        .contracts
        .cancel_contract(
            &tenant_id,
            contract_id,
            CancelContractInput {
                reason: body.reason,
                effective_date: body.effective_date,
            },
        )
        .await
    {
        Ok(result) => match unwrap_contract_result(result) {
            Ok(contract) => json_status(StatusCode::OK, contract),
            Err(error) => error,
        },
        Err(error) => err_json(StatusCode::INTERNAL_SERVER_ERROR, &error),
    }
}

async fn contract_renewal_quote(
    State(state): State<S>,
    Extension(auth): Extension<AuthContext>,
    headers: HeaderMap,
    Path(contract_id): Path<Uuid>,
) -> impl IntoResponse {
    let tenant_id = match resolve_tenant_id(&headers, &auth) {
        Ok(tenant_id) => tenant_id,
        Err(error) => return error,
    };

    match state
        .contracts
        .get_renewal_quote(&tenant_id, contract_id)
        .await
    {
        Ok(result) => match unwrap_contract_result(result) {
            Ok(quote) => json_status(StatusCode::OK, quote),
            Err(error) => error,
        },
        Err(error) => err_json(StatusCode::INTERNAL_SERVER_ERROR, &error),
    }
}

async fn contract_renew(
    State(state): State<S>,
    Extension(auth): Extension<AuthContext>,
    headers: HeaderMap,
    Path(contract_id): Path<Uuid>,
    Json(body): Json<ContractRenewBody>,
) -> impl IntoResponse {
    let tenant_id = match resolve_tenant_id(&headers, &auth) {
        Ok(tenant_id) => tenant_id,
        Err(error) => return error,
    };

    let new_terms = body.new_terms.map(|terms| ContractRenewalTerms {
        base_fee: terms.base_fee,
        committed_volume: terms.committed_volume.and_then(|volume| volume.emails),
        overage_rate: terms
            .overage_rates
            .and_then(|rates| rates.emails_per_thousand)
            .map(overage_rate_from_per_thousand),
    });

    match state
        .contracts
        .renew_contract(
            &tenant_id,
            contract_id,
            RenewContractInput {
                new_end_date: body.new_end_date,
                new_terms,
            },
        )
        .await
    {
        Ok(result) => match unwrap_contract_result(result) {
            Ok(contract) => json_status(StatusCode::CREATED, contract),
            Err(error) => error,
        },
        Err(error) => err_json(StatusCode::INTERNAL_SERVER_ERROR, &error),
    }
}

async fn contract_purchase_order(
    State(state): State<S>,
    Extension(auth): Extension<AuthContext>,
    headers: HeaderMap,
    Path(contract_id): Path<Uuid>,
    Json(body): Json<PurchaseOrderBody>,
) -> impl IntoResponse {
    let tenant_id = match resolve_tenant_id(&headers, &auth) {
        Ok(tenant_id) => tenant_id,
        Err(error) => return error,
    };

    match state
        .contracts
        .submit_purchase_order(
            &tenant_id,
            contract_id,
            PurchaseOrderInput {
                po_number: body.po_number,
                amount: body.amount,
                issued_date: body.issued_date,
                expiry_date: body.expiry_date,
                attachment_url: body.attachment_url,
            },
        )
        .await
    {
        Ok(result) => match unwrap_contract_result(result) {
            Ok(receipt) => json_status(StatusCode::CREATED, receipt),
            Err(error) => error,
        },
        Err(error) => err_json(StatusCode::INTERNAL_SERVER_ERROR, &error),
    }
}

// ── SSO Handlers ───────────────────────────────────────────────────────

async fn sso_configure(
    State(state): State<S>,
    Extension(auth): Extension<AuthContext>,
    Json(body): Json<SSOConfigureRequest>,
) -> impl IntoResponse {
    if let Err(e) = verify_tenant_access(&auth, &body.tenant_id) {
        return e;
    }
    // The response is sanitized: secrets (encrypted private key / client
    // secret, SAML certificate) never leave the server.
    match state.sso.configure(body).await {
        Ok(r) => match r.data {
            Some(config) => ok_json(SSOPublicConfig::from(config)),
            None => err_json(
                StatusCode::INTERNAL_SERVER_ERROR,
                "SSO configuration failed",
            ),
        },
        Err(e) => err_json(StatusCode::INTERNAL_SERVER_ERROR, &e),
    }
}

async fn sso_get_config(
    State(state): State<S>,
    Extension(auth): Extension<AuthContext>,
    Path(tenant_id): Path<String>,
) -> impl IntoResponse {
    if let Err(e) = verify_tenant_access(&auth, &tenant_id) {
        return e;
    }
    match state.sso.get_configuration(&tenant_id).await {
        Ok(r) => match r.data {
            Some(config) => ok_json(SSOPublicConfig::from(config)),
            None => err_json(StatusCode::NOT_FOUND, "SSO not configured"),
        },
        Err(e) => err_json(StatusCode::INTERNAL_SERVER_ERROR, &e),
    }
}

async fn sso_get_config_by_domain(
    State(state): State<S>,
    Extension(auth): Extension<AuthContext>,
    Path(domain): Path<String>,
) -> impl IntoResponse {
    match state.sso.get_config_by_domain(&domain).await {
        Ok(Some(config)) => {
            // Resolve the tenant that owns the domain, then enforce the same
            // tenant access check the other handlers use.
            if let Err(e) = verify_tenant_access(&auth, &config.tenant_id) {
                return e;
            }
            ok_json(SSOPublicConfig::from(config))
        }
        Ok(None) => err_json(StatusCode::NOT_FOUND, "SSO config not found for domain"),
        Err(e) => err_json(StatusCode::INTERNAL_SERVER_ERROR, &e),
    }
}

/// GET /sso/login/saml/:domain
///
/// Fix G (dead ACS): this service has no SAML Assertion Consumer Service
/// route — the `parse_and_validate_saml_response` / `handle_saml_callback`
/// pair is not wired to any HTTP endpoint, so an IdP could never complete a
/// login started here. Redirecting users to the IdP would strand them at a
/// callback that does not exist. Until a callback route is wired, the login
/// initiation fails fast with 501 instead of pretending SSO works.
async fn sso_saml_login(State(_state): State<S>, Path(_domain): Path<String>) -> impl IntoResponse {
    err_json(
        StatusCode::NOT_IMPLEMENTED,
        "SSO callback not configured: SAML login cannot complete because no ACS endpoint is wired; refusing to redirect to the IdP",
    )
}

/// GET /sso/login/oidc/:domain
///
/// Fix G (dead ACS): same as the SAML login above — there is no OIDC callback
/// route and no authorization-code → token exchange in this service, so the
/// flow can never complete. Fail fast with 501 instead of redirecting.
async fn sso_oidc_login(State(_state): State<S>, Path(_domain): Path<String>) -> impl IntoResponse {
    err_json(
        StatusCode::NOT_IMPLEMENTED,
        "SSO callback not configured: OIDC login cannot complete because no callback/token-exchange endpoint is wired; refusing to redirect to the IdP",
    )
}

/// Validate an SSO session.
/// Requires the session token in the Authorization header.
async fn sso_validate_session(
    State(state): State<S>,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    let token = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(|s| s.to_string());

    let token = match token {
        Some(t) => t,
        None => {
            return err_json(
                StatusCode::BAD_REQUEST,
                "Missing bearer token in Authorization header",
            )
        }
    };

    match state.sso.validate_session(&token).await {
        Ok(Some(session)) => ok_json(session),
        Ok(None) => err_json(StatusCode::UNAUTHORIZED, "Invalid or expired session"),
        Err(e) => err_json(StatusCode::INTERNAL_SERVER_ERROR, &e),
    }
}

/// POST /sso/cleanup — purge expired SSO sessions.
///
/// Fix J-12: this is an administrative maintenance operation; it now requires
/// the admin claim instead of being callable by any authenticated tenant.
async fn sso_cleanup_sessions(
    State(state): State<S>,
    Extension(auth): Extension<AuthContext>,
) -> impl IntoResponse {
    if let Some(e) = require_admin(&auth) {
        return e;
    }
    match state.sso.cleanup_expired_sessions().await {
        Ok(count) => ok_json(serde_json::json!({"cleaned": count})),
        Err(e) => err_json(StatusCode::INTERNAL_SERVER_ERROR, &e),
    }
}

// ── Compliance Handlers ────────────────────────────────────────────────

async fn compliance_enable(
    State(state): State<S>,
    Extension(auth): Extension<AuthContext>,
    Json(body): Json<ComplianceEnableBody>,
) -> impl IntoResponse {
    if let Err(e) = verify_tenant_access(&auth, &body.tenant_id) {
        return e;
    }
    service_result(
        state
            .compliance
            .enable(
                body.tenant_id,
                body.frameworks,
                body.hipaa_enabled.unwrap_or(false),
            )
            .await,
    )
}

async fn compliance_get_config(
    State(state): State<S>,
    Extension(auth): Extension<AuthContext>,
    Path(tenant_id): Path<String>,
) -> impl IntoResponse {
    if let Err(e) = verify_tenant_access(&auth, &tenant_id) {
        return e;
    }
    service_result(state.compliance.get_config(tenant_id).await)
}

async fn compliance_sign_baa(
    State(state): State<S>,
    Extension(auth): Extension<AuthContext>,
    Json(body): Json<BAABody>,
) -> impl IntoResponse {
    if let Err(e) = verify_tenant_access(&auth, &body.tenant_id) {
        return e;
    }
    service_result(
        state
            .compliance
            .sign_baa(
                body.tenant_id,
                &body.signatory_name,
                &body.signatory_title,
                &body.signatory_email,
            )
            .await,
    )
}

async fn compliance_zero_retention(
    State(state): State<S>,
    Extension(auth): Extension<AuthContext>,
    Path(tenant_id): Path<String>,
) -> impl IntoResponse {
    if let Err(e) = verify_tenant_access(&auth, &tenant_id) {
        return e;
    }
    service_result(state.compliance.enable_zero_retention(tenant_id).await)
}

async fn compliance_log_audit(
    State(state): State<S>,
    Extension(auth): Extension<AuthContext>,
    connect_info: Option<axum::extract::ConnectInfo<std::net::SocketAddr>>,
    headers: HeaderMap,
    Json(body): Json<AuditLogBody>,
) -> impl IntoResponse {
    if let Err(e) = verify_tenant_access(&auth, &body.tenant_id) {
        return e;
    }

    // Fix C (audit-log forgery): identity columns are derived by the server
    // and can no longer be forged by clients:
    //   * user_id      — always the authenticated token subject (claims.sub)
    //   * ip_address   — always the connection peer address
    //   * user_agent   — always the request User-Agent header
    // Body-supplied identity fields (user_id / ip_address / user_agent /
    // session_id / request_id) are never persisted as identity; they are
    // preserved under `metadata.client_supplied` for troubleshooting only.
    let user_id = auth.user_id.clone();
    let ip_address = connect_info.map(|ci| ci.0.ip().to_string());
    let user_agent = headers
        .get(axum::http::header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.to_string());

    let mut metadata = body.metadata.unwrap_or_else(|| serde_json::json!({}));
    if !metadata.is_object() {
        metadata = serde_json::json!({ "client_metadata": metadata });
    }
    let client_supplied = serde_json::json!({
        "user_id": body.user_id,
        "ip_address": body.ip_address,
        "user_agent": body.user_agent,
        "session_id": body.session_id,
        "request_id": body.request_id,
    });
    if let Some(obj) = metadata.as_object_mut() {
        obj.insert("client_supplied".to_string(), client_supplied);
    }

    match state
        .compliance
        .log_audit(
            body.tenant_id,
            Some(&user_id),
            &body.action,
            &body.resource_type,
            body.resource_id.as_deref(),
            body.old_value,
            body.new_value,
            ip_address.as_deref(),
            user_agent.as_deref(),
            None, // session_id: server-derived only (not yet available)
            None, // request_id: server-derived only (not yet available)
            Some(metadata),
        )
        .await
    {
        Ok(()) => ok_json(serde_json::json!({"status": "logged"})),
        Err(e) => err_json(StatusCode::INTERNAL_SERVER_ERROR, &e),
    }
}

async fn compliance_get_audit_logs(
    State(state): State<S>,
    Extension(auth): Extension<AuthContext>,
    Path(tenant_id): Path<String>,
    Query(q): Query<AuditFilterParams>,
) -> impl IntoResponse {
    if let Err(e) = verify_tenant_access(&auth, &tenant_id) {
        return e;
    }
    let limit = clamp_limit(q.limit.unwrap_or(50), 200);
    let offset = clamp_offset(q.offset.unwrap_or(0));
    service_result(
        state
            .compliance
            .get_audit_logs(
                tenant_id,
                q.action.as_deref(),
                q.resource_type.as_deref(),
                limit,
                offset,
            )
            .await,
    )
}

async fn compliance_data_access(
    State(state): State<S>,
    Extension(auth): Extension<AuthContext>,
    Json(body): Json<DataAccessBody>,
) -> impl IntoResponse {
    if let Err(e) = verify_tenant_access(&auth, &body.tenant_id) {
        return e;
    }
    service_result(
        state
            .compliance
            .request_data_access(
                body.tenant_id,
                &body.requester_id,
                &body.requester_email,
                &body.request_type,
                body.resource_type.as_deref(),
                body.justification.as_deref(),
                body.identifiers,
            )
            .await,
    )
}

async fn compliance_approve_access(
    State(state): State<S>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<Uuid>,
    Json(body): Json<DataAccessApproveBody>,
) -> impl IntoResponse {
    // Fix A: the data access request must belong to the caller's tenant
    // before it can be approved.
    let existing = state.compliance.get_data_access_request(id).await;
    if let Some(e) = guard_resource_tenant(&auth, &existing).await {
        return e;
    }

    // Fix J-3: the approver identity is derived from the authenticated token
    // claims — the body-supplied `approved_by` is never trusted — and the
    // granted duration is clamped to 1..=1440 minutes (max 24 h).
    let approved_by = auth.user_id.clone();
    let duration_minutes = body.duration_minutes.clamp(1, 1440);

    match state
        .compliance
        .approve_data_access(id, &approved_by, duration_minutes)
        .await
    {
        Ok(mut result) => {
            // J-3: the raw access token is never echoed back to the client;
            // only a non-guessable reference to the grant is returned.
            if let Some(ref mut request) = result.data {
                if request.access_token.is_some() {
                    request.access_token = Some(format!("ref:{}", request.id));
                }
            }
            service_result(Ok(result))
        }
        Err(e) => service_result::<crate::types::DataAccessRequest>(Err(e)),
    }
}

async fn compliance_data_deletion(
    State(state): State<S>,
    Extension(auth): Extension<AuthContext>,
    Json(body): Json<DataDeletionBody>,
) -> impl IntoResponse {
    if let Err(e) = verify_tenant_access(&auth, &body.tenant_id) {
        return e;
    }
    service_result(
        state
            .compliance
            .request_data_deletion(
                body.tenant_id,
                &body.requester_id,
                &body.requester_email,
                body.identifiers,
            )
            .await,
    )
}

async fn compliance_report(
    State(state): State<S>,
    Extension(auth): Extension<AuthContext>,
    Path(tenant_id): Path<String>,
) -> impl IntoResponse {
    if let Err(e) = verify_tenant_access(&auth, &tenant_id) {
        return e;
    }
    service_result(state.compliance.generate_report(tenant_id).await)
}

async fn compliance_status(
    State(state): State<S>,
    Extension(auth): Extension<AuthContext>,
    Path(tenant_id): Path<String>,
) -> impl IntoResponse {
    if let Err(e) = verify_tenant_access(&auth, &tenant_id) {
        return e;
    }
    service_result(state.compliance.get_status(tenant_id).await)
}

// ── Encryption Handlers ────────────────────────────────────────────────

/// Get encryption status for a tenant (key info without revealing key material).
async fn encryption_status(
    State(state): State<S>,
    Extension(auth): Extension<AuthContext>,
    Path(tenant_id): Path<String>,
) -> impl IntoResponse {
    if let Err(e) = verify_tenant_access(&auth, &tenant_id) {
        return e;
    }
    // Check if HIPAA compliance is configured with encryption_at_rest
    let config = match state.compliance.get_config(tenant_id.clone()).await {
        Ok(r) => r,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "error": { "code": "INTERNAL_ERROR", "message": e }
                })),
            );
        }
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

    (StatusCode::OK, Json(status))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct EncryptFieldBody {
    pub tenant_id: String,
    pub field_name: String,
    pub value: String,
}

const ENTERPRISE_FIELD_TOOLING_PURPOSE: &str = "enterprise/routes/field-tooling";

/// AAD that binds a field-tooling ciphertext to a specific tenant.
///
/// Fix B: ciphertexts produced by `encrypt_field` are authenticated with the
/// tenant id as additional authenticated data, so a ciphertext created for
/// tenant A cannot be decrypted through tenant B's context.
fn tenant_binding_aad(tenant_id: &str) -> Vec<u8> {
    format!("enterprise/field-tooling/tenant:{tenant_id}").into_bytes()
}

fn managed_field_encryptor(
    config: &Config,
) -> Result<crate::field_encryption::FieldEncryptor, String> {
    crate::field_encryption::encryptor_from_secret(
        &config.log_stream.encryption_key,
        ENTERPRISE_FIELD_TOOLING_PURPOSE,
    )
    .map_err(|error| format!("server-managed encryption key unavailable: {error}"))
}

/// Encrypt a single field value (for testing/migration tooling).
/// In production, encryption happens transparently at the data access layer.
/// This endpoint exists for:/// - Verifying encryption is working correctly after setup.
/// - Batch migration of existing unencrypted PHI data.
async fn encrypt_field(
    State(state): State<S>,
    Extension(auth): Extension<AuthContext>,
    Json(body): Json<EncryptFieldBody>,
) -> impl IntoResponse {
    if let Err(e) = verify_tenant_access(&auth, &body.tenant_id) {
        return e;
    }
    let encryptor = match managed_field_encryptor(&state.config) {
        Ok(encryptor) => encryptor,
        Err(error) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "error": { "code": "ENCRYPTION_CONFIG_ERROR", "message": error }
                })),
            );
        }
    };

    match encryptor.encrypt_with_aad(&body.value, &tenant_binding_aad(&body.tenant_id)) {
        Ok(encrypted) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "tenant_id": body.tenant_id,
                "field_name": body.field_name,
                "encrypted": true,
                "value": encrypted,
                "is_phi": crate::field_encryption::PHI_FIELDS.contains(&body.field_name.as_str()),
                "key_reference": "server-managed"
            })),
        ),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({
                "error": { "code": "ENCRYPTION_FAILED", "message": format!("{e}") }
            })),
        ),
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DecryptFieldBody {
    pub tenant_id: String,
    #[expect(
        dead_code,
        reason = "field is accepted for encrypted-field migration tooling request compatibility"
    )]
    pub field_name: String,
    pub value: String,
}

/// Decrypt a single field value (for testing/migration tooling).
async fn decrypt_field(
    State(state): State<S>,
    Extension(auth): Extension<AuthContext>,
    Json(body): Json<DecryptFieldBody>,
) -> impl IntoResponse {
    if let Err(e) = verify_tenant_access(&auth, &body.tenant_id) {
        return e;
    }
    let encryptor = match managed_field_encryptor(&state.config) {
        Ok(encryptor) => encryptor,
        Err(error) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "error": { "code": "ENCRYPTION_CONFIG_ERROR", "message": error }
                })),
            );
        }
    };

    // Fix B: decryption is bound to the caller's tenant — a ciphertext that
    // was not encrypted for this tenant (or whose provenance is unknown)
    // is rejected instead of being decrypted with the global KEK.
    match encryptor.decrypt_with_aad(&body.value, &tenant_binding_aad(&body.tenant_id)) {
        Ok(decrypted) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "decrypted": true,
                "value": decrypted,
            })),
        ),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": {
                    "code": "DECRYPTION_FAILED",
                    "message": format!(
                        "ciphertext is not decryptable for this tenant (wrong tenant binding, unknown provenance, or corrupt data): {e}"
                    )
                }
            })),
        ),
    }
}

// ── Log Streaming Handlers ─────────────────────────────────────────────

async fn log_stream_create(
    State(state): State<S>,
    Extension(auth): Extension<AuthContext>,
    Json(body): Json<LogStreamCreateBody>,
) -> impl IntoResponse {
    if let Err(e) = verify_tenant_access(&auth, &body.tenant_id) {
        return e;
    }
    service_result(
        state
            .log_streaming
            .create(
                body.tenant_id,
                &body.name,
                body.description.as_deref(),
                &body.destination_type,
                body.destination_config,
                body.log_categories,
                body.batch_size,
                body.batch_interval_seconds,
                body.compression_enabled.unwrap_or(false),
            )
            .await,
    )
}

async fn log_stream_get(
    State(state): State<S>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<Uuid>,
) -> impl IntoResponse {
    let result = state.log_streaming.get(id).await;
    if let Some(e) = guard_resource_tenant(&auth, &result).await {
        return e;
    }
    service_result(result)
}

async fn log_stream_update(
    State(state): State<S>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<Uuid>,
    Json(body): Json<LogStreamUpdateBody>,
) -> impl IntoResponse {
    let existing = state.log_streaming.get(id).await;
    if let Some(e) = guard_resource_tenant(&auth, &existing).await {
        return e;
    }
    service_result(
        state
            .log_streaming
            .update(
                id,
                body.name.as_deref(),
                body.description.as_deref(),
                body.destination_config,
                body.log_categories,
            )
            .await,
    )
}

async fn log_stream_delete(
    State(state): State<S>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<Uuid>,
) -> impl IntoResponse {
    let existing = state.log_streaming.get(id).await;
    if let Some(e) = guard_resource_tenant(&auth, &existing).await {
        return e;
    }
    service_result(state.log_streaming.delete(id).await)
}

async fn log_stream_list(
    State(state): State<S>,
    Extension(auth): Extension<AuthContext>,
    Path(tenant_id): Path<String>,
) -> impl IntoResponse {
    if let Err(e) = verify_tenant_access(&auth, &tenant_id) {
        return e;
    }
    service_result(state.log_streaming.list(tenant_id).await)
}

async fn log_stream_pause(
    State(state): State<S>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<Uuid>,
) -> impl IntoResponse {
    let existing = state.log_streaming.get(id).await;
    if let Some(e) = guard_resource_tenant(&auth, &existing).await {
        return e;
    }
    service_result(state.log_streaming.pause(id).await)
}

async fn log_stream_resume(
    State(state): State<S>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<Uuid>,
) -> impl IntoResponse {
    let existing = state.log_streaming.get(id).await;
    if let Some(e) = guard_resource_tenant(&auth, &existing).await {
        return e;
    }
    service_result(state.log_streaming.resume(id).await)
}

async fn log_stream_verify(
    State(state): State<S>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<Uuid>,
) -> impl IntoResponse {
    let existing = state.log_streaming.get(id).await;
    if let Some(e) = guard_resource_tenant(&auth, &existing).await {
        return e;
    }
    service_result(state.log_streaming.verify(id).await)
}

async fn log_stream_stats(
    State(state): State<S>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<Uuid>,
) -> impl IntoResponse {
    let existing = state.log_streaming.get(id).await;
    if let Some(e) = guard_resource_tenant(&auth, &existing).await {
        return e;
    }
    service_result(state.log_streaming.get_stats(id).await)
}

// ── Private Deploy Handlers ────────────────────────────────────────────

async fn deploy_create(
    State(state): State<S>,
    Extension(auth): Extension<AuthContext>,
    Json(body): Json<DeployCreateBody>,
) -> impl IntoResponse {
    if let Err(e) = verify_tenant_access(&auth, &body.tenant_id) {
        return e;
    }
    service_result(
        state
            .private_deploy
            .create(
                body.tenant_id,
                &body.name,
                &body.deployment_type,
                body.region.as_deref(),
                body.config,
            )
            .await,
    )
}

async fn deploy_get(
    State(state): State<S>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<Uuid>,
) -> impl IntoResponse {
    let result = state.private_deploy.get(id).await;
    if let Some(e) = guard_resource_tenant(&auth, &result).await {
        return e;
    }
    service_result(result)
}

async fn deploy_list(
    State(state): State<S>,
    Extension(auth): Extension<AuthContext>,
    Path(tenant_id): Path<String>,
) -> impl IntoResponse {
    if let Err(e) = verify_tenant_access(&auth, &tenant_id) {
        return e;
    }
    service_result(state.private_deploy.list(tenant_id).await)
}

async fn deploy_provision(
    State(state): State<S>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<Uuid>,
) -> impl IntoResponse {
    let existing = state.private_deploy.get(id).await;
    if let Some(e) = guard_resource_tenant(&auth, &existing).await {
        return e;
    }
    service_result(state.private_deploy.provision(id).await)
}

async fn deploy_health(
    State(state): State<S>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<Uuid>,
) -> impl IntoResponse {
    let existing = state.private_deploy.get(id).await;
    if let Some(e) = guard_resource_tenant(&auth, &existing).await {
        return e;
    }
    service_result(state.private_deploy.health_check(id).await)
}

async fn ip_allocate(
    State(state): State<S>,
    Extension(auth): Extension<AuthContext>,
    Json(body): Json<DedicatedIPBody>,
) -> impl IntoResponse {
    if let Err(e) = verify_tenant_access(&auth, &body.tenant_id) {
        return e;
    }
    service_result(
        state
            .private_deploy
            .allocate_dedicated_ip(body.tenant_id, body.deployment_id, &body.ip_address)
            .await,
    )
}

async fn ip_get(
    State(state): State<S>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<Uuid>,
) -> impl IntoResponse {
    let result = state.private_deploy.get_dedicated_ip(id).await;
    if let Some(e) = guard_resource_tenant(&auth, &result).await {
        return e;
    }
    service_result(result)
}

async fn ip_list(
    State(state): State<S>,
    Extension(auth): Extension<AuthContext>,
    Path(tenant_id): Path<String>,
    Query(q): Query<PaginationParams>,
) -> impl IntoResponse {
    if let Err(e) = verify_tenant_access(&auth, &tenant_id) {
        return e;
    }
    let limit = clamp_limit(q.limit.unwrap_or(50), 200);
    let offset = clamp_offset(q.offset.unwrap_or(0));
    service_result(
        state
            .private_deploy
            .list_dedicated_ips(tenant_id, limit, offset)
            .await,
    )
}

async fn ip_reputation(
    State(state): State<S>,
    Path(ip_address): Path<String>,
) -> impl IntoResponse {
    service_result(state.private_deploy.get_ip_reputation(&ip_address).await)
}

async fn byoip_register(
    State(state): State<S>,
    Extension(auth): Extension<AuthContext>,
    Json(body): Json<BYOIPBody>,
) -> impl IntoResponse {
    if let Err(e) = verify_tenant_access(&auth, &body.tenant_id) {
        return e;
    }
    service_result(
        state
            .private_deploy
            .register_byoip(body.tenant_id, &body.cidr_block)
            .await,
    )
}

async fn byoip_verify(
    State(state): State<S>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<Uuid>,
    Json(body): Json<BYOIPVerifyBody>,
) -> impl IntoResponse {
    let existing = state.private_deploy.get_byoip(id).await;
    if let Some(e) = guard_resource_tenant(&auth, &existing).await {
        return e;
    }
    service_result(
        state
            .private_deploy
            .verify_byoip(id, &body.verification_token)
            .await,
    )
}

// ── Sub-account Handlers ───────────────────────────────────────────────

async fn sub_account_create(
    State(state): State<S>,
    Extension(auth): Extension<AuthContext>,
    Json(body): Json<SubAccountCreateBody>,
) -> impl IntoResponse {
    if let Err(e) = verify_tenant_access(&auth, &body.parent_id) {
        return e;
    }
    service_result(
        state
            .sub_accounts
            .create(
                body.parent_id,
                &body.name,
                body.email.as_deref(),
                body.domain.as_deref(),
                body.plan.as_deref(),
                body.volume_limit,
                body.inherit_parent_settings.unwrap_or(true),
            )
            .await,
    )
}

async fn sub_account_get(
    State(state): State<S>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<Uuid>,
) -> impl IntoResponse {
    // Fetch sub-account first to verify parent tenant ownership
    let result = state.sub_accounts.get(id).await;
    if let Ok(ref api_result) = result {
        if let Some(ref sub) = api_result.data {
            if let Err(e) = verify_tenant_access(&auth, &sub.parent_id) {
                return e;
            }
        }
    }
    service_result(result)
}

async fn sub_account_update(
    State(state): State<S>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<Uuid>,
    Json(body): Json<SubAccountUpdateBody>,
) -> impl IntoResponse {
    // Verify parent tenant ownership first by looking up the sub-account
    match state.sub_accounts.get(id).await {
        Ok(api_result) => {
            if let Some(ref sub) = api_result.data {
                if let Err(e) = verify_tenant_access(&auth, &sub.parent_id) {
                    return e;
                }
            } else {
                return service_result::<SubAccount>(Ok(api_result));
            }
        }
        Err(e) => return service_result::<SubAccount>(Err(e)),
    }
    service_result(
        state
            .sub_accounts
            .update(
                id,
                body.name.as_deref(),
                body.email.as_deref(),
                body.volume_limit,
                body.settings,
            )
            .await,
    )
}

async fn sub_account_delete(
    State(state): State<S>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<Uuid>,
) -> impl IntoResponse {
    // Verify parent tenant ownership first by looking up the sub-account
    match state.sub_accounts.get(id).await {
        Ok(api_result) => {
            if let Some(ref sub) = api_result.data {
                if let Err(e) = verify_tenant_access(&auth, &sub.parent_id) {
                    return e;
                }
            } else {
                return service_result::<SubAccount>(Ok(api_result));
            }
        }
        Err(e) => return service_result::<SubAccount>(Err(e)),
    }
    service_result(state.sub_accounts.delete(id).await)
}

async fn sub_account_list(
    State(state): State<S>,
    Extension(auth): Extension<AuthContext>,
    Path(parent_id): Path<String>,
    Query(q): Query<StatusFilterParams>,
) -> impl IntoResponse {
    if let Err(e) = verify_tenant_access(&auth, &parent_id) {
        return e;
    }
    let limit = clamp_limit(q.limit.unwrap_or(50), 200);
    let offset = clamp_offset(q.offset.unwrap_or(0));
    service_result(
        state
            .sub_accounts
            .list(parent_id, q.status.as_deref(), limit, offset)
            .await,
    )
}

async fn sub_account_suspend(
    State(state): State<S>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<Uuid>,
    Json(body): Json<SubAccountSuspendBody>,
) -> impl IntoResponse {
    // Verify parent tenant ownership first by looking up the sub-account
    match state.sub_accounts.get(id).await {
        Ok(api_result) => {
            if let Some(ref sub) = api_result.data {
                if let Err(e) = verify_tenant_access(&auth, &sub.parent_id) {
                    return e;
                }
            } else {
                return service_result::<SubAccount>(Ok(api_result));
            }
        }
        Err(e) => return service_result::<SubAccount>(Err(e)),
    }
    service_result(state.sub_accounts.suspend(id, body.reason.as_deref()).await)
}

async fn sub_account_stats(
    State(state): State<S>,
    Extension(auth): Extension<AuthContext>,
    Path(parent_id): Path<String>,
) -> impl IntoResponse {
    if let Err(e) = verify_tenant_access(&auth, &parent_id) {
        return e;
    }
    service_result(state.sub_accounts.get_stats(parent_id).await)
}

async fn sub_account_api_key(
    State(state): State<S>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<Uuid>,
    Json(body): Json<ApiKeyCreateBody>,
) -> impl IntoResponse {
    // Verify parent tenant ownership first by looking up the sub-account
    match state.sub_accounts.get(id).await {
        Ok(api_result) => {
            if let Some(ref sub) = api_result.data {
                if let Err(e) = verify_tenant_access(&auth, &sub.parent_id) {
                    return e;
                }
            } else {
                return service_result::<SubAccount>(Ok(api_result));
            }
        }
        Err(e) => return service_result::<SubAccount>(Err(e)),
    }
    service_result(
        state
            .sub_accounts
            .create_api_key(id, &body.name, body.permissions, body.rate_limit)
            .await,
    )
}

/// GET /sub-accounts/:id/api-keys — list a sub-account's API keys
/// (masked: hashes stripped, fix J-4).
async fn sub_account_api_keys_list(
    State(state): State<S>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<Uuid>,
) -> impl IntoResponse {
    match state.sub_accounts.get(id).await {
        Ok(api_result) => {
            if let Some(ref sub) = api_result.data {
                if let Err(e) = verify_tenant_access(&auth, &sub.parent_id) {
                    return e;
                }
            } else {
                return service_result::<SubAccount>(Ok(api_result));
            }
        }
        Err(e) => return service_result::<SubAccount>(Err(e)),
    }
    service_result(state.sub_accounts.list_api_keys(id).await)
}

/// POST /sub-accounts/:id/api-keys/:key_id/revoke — revoke an API key
/// (fix J-4). Revoked keys fail `SubAccountService::verify_api_key`.
async fn sub_account_api_key_revoke(
    State(state): State<S>,
    Extension(auth): Extension<AuthContext>,
    Path((id, key_id)): Path<(Uuid, Uuid)>,
) -> impl IntoResponse {
    match state.sub_accounts.get(id).await {
        Ok(api_result) => {
            if let Some(ref sub) = api_result.data {
                if let Err(e) = verify_tenant_access(&auth, &sub.parent_id) {
                    return e;
                }
            } else {
                return service_result::<SubAccount>(Ok(api_result));
            }
        }
        Err(e) => return service_result::<SubAccount>(Err(e)),
    }
    service_result(state.sub_accounts.revoke_api_key(id, key_id).await)
}

// ── Support Handlers ───────────────────────────────────────────────────

async fn ticket_create(
    State(state): State<S>,
    Extension(auth): Extension<AuthContext>,
    Json(body): Json<TicketCreateBody>,
) -> impl IntoResponse {
    if let Err(e) = verify_tenant_access(&auth, &body.tenant_id) {
        return e;
    }
    support_result(
        state
            .support
            .create_ticket(
                &body.tenant_id,
                &body.subject,
                &body.description,
                &body.priority,
                &body.category,
                body.contact_email.as_deref(),
            )
            .await,
    )
}

async fn ticket_get(
    State(state): State<S>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<Uuid>,
) -> impl IntoResponse {
    let result = state.support.get_ticket(id).await;
    if let Some(e) = guard_resource_tenant(&auth, &result).await {
        return e;
    }
    support_result(result)
}

async fn ticket_update(
    State(state): State<S>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<Uuid>,
    Json(body): Json<TicketUpdateBody>,
) -> impl IntoResponse {
    let existing = state.support.get_ticket(id).await;
    if let Some(e) = guard_resource_tenant(&auth, &existing).await {
        return e;
    }
    support_result(
        state
            .support
            .update_ticket(
                id,
                body.status.as_deref(),
                body.priority.as_deref(),
                body.assigned_to,
            )
            .await,
    )
}

async fn ticket_list(
    State(state): State<S>,
    Extension(auth): Extension<AuthContext>,
    Path(tenant_id): Path<String>,
    Query(q): Query<TicketListParams>,
) -> impl IntoResponse {
    if let Err(e) = verify_tenant_access(&auth, &tenant_id) {
        return e;
    }
    // Cursor format errors are client errors → 400 with a message.
    let cursor = match q.cursor.as_deref() {
        None => None,
        Some(raw) => match crate::support::TicketCursor::parse(raw) {
            Ok(c) => Some(c),
            Err(message) => {
                return err_json(StatusCode::BAD_REQUEST, &message);
            }
        },
    };
    let limit = clamp_limit(q.limit.unwrap_or(50), 200);
    let offset = clamp_offset(q.offset.unwrap_or(0));
    support_result(
        state
            .support
            .list_tickets_search(
                &tenant_id,
                q.status.as_deref(),
                q.priority.as_deref(),
                limit,
                offset,
                crate::support::TicketListRefinements {
                    cursor,
                    search: q.q.as_deref(),
                },
            )
            .await,
    )
}

async fn comment_add(
    State(state): State<S>,
    Extension(auth): Extension<AuthContext>,
    Path(ticket_id): Path<Uuid>,
    Json(body): Json<CommentBody>,
) -> impl IntoResponse {
    let existing = state.support.get_ticket(ticket_id).await;
    if let Some(e) = guard_resource_tenant(&auth, &existing).await {
        return e;
    }
    support_result(
        state
            .support
            .add_comment(
                ticket_id,
                &body.author_id,
                &body.author_name,
                &body.author_type,
                &body.content,
                body.is_internal.unwrap_or(false),
            )
            .await,
    )
}

async fn comment_list(
    State(state): State<S>,
    Extension(auth): Extension<AuthContext>,
    Path(ticket_id): Path<Uuid>,
    Query(q): Query<CommentFilterParams>,
) -> impl IntoResponse {
    let existing = state.support.get_ticket(ticket_id).await;
    if let Some(e) = guard_resource_tenant(&auth, &existing).await {
        return e;
    }
    support_result(
        state
            .support
            .get_comments(ticket_id, q.include_internal.unwrap_or(false))
            .await,
    )
}

async fn ticket_escalate(
    State(state): State<S>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<Uuid>,
    Json(body): Json<EscalateBody>,
) -> impl IntoResponse {
    let existing = state.support.get_ticket(id).await;
    if let Some(e) = guard_resource_tenant(&auth, &existing).await {
        return e;
    }
    support_result(
        state
            .support
            .escalate(id, &body.reason, body.escalated_by)
            .await,
    )
}

async fn ticket_satisfaction(
    State(state): State<S>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<Uuid>,
    Json(body): Json<SatisfactionBody>,
) -> impl IntoResponse {
    let existing = state.support.get_ticket(id).await;
    if let Some(e) = guard_resource_tenant(&auth, &existing).await {
        return e;
    }
    support_result(
        state
            .support
            .submit_satisfaction(id, body.rating, body.feedback.as_deref())
            .await,
    )
}

async fn support_metrics(
    State(state): State<S>,
    Extension(auth): Extension<AuthContext>,
    Path(tenant_id): Path<String>,
) -> impl IntoResponse {
    if let Err(e) = verify_tenant_access(&auth, &tenant_id) {
        return e;
    }
    support_result(state.support.get_metrics(&tenant_id).await)
}

// ── Template Handlers ──────────────────────────────────────────────────

async fn template_submit(
    State(state): State<S>,
    Extension(auth): Extension<AuthContext>,
    Json(body): Json<TemplateSubmitBody>,
) -> impl IntoResponse {
    if let Err(e) = verify_tenant_access(&auth, &body.tenant_id) {
        return e;
    }
    service_result(
        state
            .templates
            .submit(
                body.tenant_id,
                &body.name,
                &body.subject,
                &body.html_content,
                body.text_content.as_deref(),
                &body.submitted_by,
            )
            .await,
    )
}

async fn template_get(
    State(state): State<S>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<Uuid>,
) -> impl IntoResponse {
    let result = state.templates.get_submission(id).await;
    if let Some(e) = guard_resource_tenant(&auth, &result).await {
        return e;
    }
    service_result(result)
}

async fn template_list(
    State(state): State<S>,
    Extension(auth): Extension<AuthContext>,
    Path(tenant_id): Path<String>,
    Query(q): Query<StatusFilterParams>,
) -> impl IntoResponse {
    if let Err(e) = verify_tenant_access(&auth, &tenant_id) {
        return e;
    }
    let limit = clamp_limit(q.limit.unwrap_or(50), 200);
    let offset = clamp_offset(q.offset.unwrap_or(0));
    service_result(
        state
            .templates
            .list_submissions(tenant_id, q.status.as_deref(), limit, offset)
            .await,
    )
}

/// Approve a template submission.
///
/// Fix A: the submission must belong to the caller's tenant. Fix (role gate):
/// approval is a reviewer action — only callers with the admin/reviewer claim
/// may approve or reject submissions. The reviewer identity is taken from the
/// authenticated claims, not the body.
async fn template_approve(
    State(state): State<S>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<Uuid>,
    Json(body): Json<TemplateReviewBody>,
) -> impl IntoResponse {
    if let Some(e) = require_admin(&auth) {
        return e;
    }
    let existing = state.templates.get_submission(id).await;
    if let Some(e) = guard_resource_tenant(&auth, &existing).await {
        return e;
    }
    service_result(
        state
            .templates
            .approve(id, &auth.user_id, body.notes.as_deref())
            .await,
    )
}

async fn template_reject(
    State(state): State<S>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<Uuid>,
    Json(body): Json<TemplateRejectBody>,
) -> impl IntoResponse {
    if let Some(e) = require_admin(&auth) {
        return e;
    }
    let existing = state.templates.get_submission(id).await;
    if let Some(e) = guard_resource_tenant(&auth, &existing).await {
        return e;
    }
    service_result(
        state
            .templates
            .reject(id, &auth.user_id, &body.reason)
            .await,
    )
}

async fn template_request_changes(
    State(state): State<S>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<Uuid>,
    Json(body): Json<TemplateReviewBody>,
) -> impl IntoResponse {
    if let Some(e) = require_admin(&auth) {
        return e;
    }
    let existing = state.templates.get_submission(id).await;
    if let Some(e) = guard_resource_tenant(&auth, &existing).await {
        return e;
    }
    match &body.notes {
        Some(notes) => service_result(
            state
                .templates
                .request_changes(id, &auth.user_id, notes)
                .await,
        ),
        None => err_json(
            StatusCode::BAD_REQUEST,
            "Notes are required for change requests",
        ),
    }
}

async fn template_stats(
    State(state): State<S>,
    Extension(auth): Extension<AuthContext>,
    Path(tenant_id): Path<String>,
) -> impl IntoResponse {
    if let Err(e) = verify_tenant_access(&auth, &tenant_id) {
        return e;
    }
    service_result(state.templates.get_stats(tenant_id).await)
}

// ── Whitelabel Handlers ────────────────────────────────────────────────

async fn whitelabel_update_config(
    State(state): State<S>,
    Extension(auth): Extension<AuthContext>,
    Json(body): Json<WhiteLabelConfigBody>,
) -> impl IntoResponse {
    if let Err(e) = verify_tenant_access(&auth, &body.tenant_id) {
        return e;
    }
    service_result(
        state
            .whitelabel
            .update_config(
                body.tenant_id,
                body.company_name.as_deref(),
                body.logo_url.as_deref(),
                body.favicon_url.as_deref(),
                body.primary_color.as_deref(),
                body.secondary_color.as_deref(),
                body.custom_css.as_deref(),
                body.footer_text.as_deref(),
                body.support_email.as_deref(),
                body.support_url.as_deref(),
            )
            .await,
    )
}

async fn whitelabel_get_config(
    State(state): State<S>,
    Extension(auth): Extension<AuthContext>,
    Path(tenant_id): Path<String>,
) -> impl IntoResponse {
    if let Err(e) = verify_tenant_access(&auth, &tenant_id) {
        return e;
    }
    service_result(state.whitelabel.get_config(tenant_id).await)
}

async fn whitelabel_add_domain(
    State(state): State<S>,
    Extension(auth): Extension<AuthContext>,
    Json(body): Json<DomainAddBody>,
) -> impl IntoResponse {
    if let Err(e) = verify_tenant_access(&auth, &body.tenant_id) {
        return e;
    }
    service_result(
        state
            .whitelabel
            .add_domain(body.tenant_id, &body.domain, &body.domain_type)
            .await,
    )
}

async fn whitelabel_verify_domain(
    State(state): State<S>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<Uuid>,
) -> impl IntoResponse {
    let existing = state.whitelabel.get_domain(id).await;
    if let Some(e) = guard_resource_tenant(&auth, &existing).await {
        return e;
    }
    service_result(state.whitelabel.verify_domain(id).await)
}

async fn whitelabel_list_domains(
    State(state): State<S>,
    Extension(auth): Extension<AuthContext>,
    Path(tenant_id): Path<String>,
    Query(q): Query<PaginationParams>,
) -> impl IntoResponse {
    if let Err(e) = verify_tenant_access(&auth, &tenant_id) {
        return e;
    }
    let limit = clamp_limit(q.limit.unwrap_or(50), 200);
    let offset = clamp_offset(q.offset.unwrap_or(0));
    service_result(
        state
            .whitelabel
            .list_domains(tenant_id, limit, offset)
            .await,
    )
}

async fn whitelabel_remove_domain(
    State(state): State<S>,
    Extension(auth): Extension<AuthContext>,
    Path((tenant_id, id)): Path<(String, Uuid)>,
) -> impl IntoResponse {
    if let Err(e) = verify_tenant_access(&auth, &tenant_id) {
        return e;
    }
    // #250:Now requires tenant_id for ownership verification
    service_result(state.whitelabel.remove_domain(id, tenant_id).await)
}

async fn whitelabel_update_templates(
    State(state): State<S>,
    Extension(auth): Extension<AuthContext>,
    Json(body): Json<EmailTemplateBody>,
) -> impl IntoResponse {
    if let Err(e) = verify_tenant_access(&auth, &body.tenant_id) {
        return e;
    }
    service_result(
        state
            .whitelabel
            .update_email_templates(
                body.tenant_id,
                &body.template_type,
                body.subject_template.as_deref(),
                body.html_template.as_deref(),
                body.text_template.as_deref(),
            )
            .await,
    )
}

async fn whitelabel_get_templates(
    State(state): State<S>,
    Extension(auth): Extension<AuthContext>,
    Path(tenant_id): Path<String>,
) -> impl IntoResponse {
    if let Err(e) = verify_tenant_access(&auth, &tenant_id) {
        return e;
    }
    service_result(state.whitelabel.get_email_templates(tenant_id).await)
}

// ── QBR Handlers ───────────────────────────────────────────────────────

async fn qbr_schedule(
    State(state): State<S>,
    Extension(auth): Extension<AuthContext>,
    Json(body): Json<QBRScheduleBody>,
) -> impl IntoResponse {
    if let Err(e) = verify_tenant_access(&auth, &body.tenant_id) {
        return e;
    }
    service_result(
        state
            .qbr
            .schedule(
                body.tenant_id,
                body.quarter,
                body.year,
                body.scheduled_date,
                body.attendees,
            )
            .await,
    )
}

async fn qbr_get(
    State(state): State<S>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<Uuid>,
) -> impl IntoResponse {
    let result = state.qbr.get(id).await;
    if let Some(e) = guard_resource_tenant(&auth, &result).await {
        return e;
    }
    service_result(result)
}

async fn qbr_list(
    State(state): State<S>,
    Extension(auth): Extension<AuthContext>,
    Path(tenant_id): Path<String>,
    Query(q): Query<PaginationParams>,
) -> impl IntoResponse {
    if let Err(e) = verify_tenant_access(&auth, &tenant_id) {
        return e;
    }
    let limit = clamp_limit(q.limit.unwrap_or(50), 200);
    let offset = clamp_offset(q.offset.unwrap_or(0));
    service_result(state.qbr.list(tenant_id, limit, offset).await)
}

async fn qbr_generate(
    State(state): State<S>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<Uuid>,
) -> impl IntoResponse {
    let existing = state.qbr.get(id).await;
    if let Some(e) = guard_resource_tenant(&auth, &existing).await {
        return e;
    }
    service_result(state.qbr.generate(id).await)
}

async fn qbr_deliver(
    State(state): State<S>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<Uuid>,
) -> impl IntoResponse {
    let existing = state.qbr.get(id).await;
    if let Some(e) = guard_resource_tenant(&auth, &existing).await {
        return e;
    }
    service_result(state.qbr.mark_delivered(id).await)
}

async fn qbr_feedback(
    State(state): State<S>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<Uuid>,
    Json(body): Json<QBRFeedbackBody>,
) -> impl IntoResponse {
    let existing = state.qbr.get(id).await;
    if let Some(e) = guard_resource_tenant(&auth, &existing).await {
        return e;
    }
    service_result(
        state
            .qbr
            .submit_feedback(id, body.rating, body.feedback_text.as_deref())
            .await,
    )
}

async fn qbr_update_goal(
    State(state): State<S>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<Uuid>,
    Json(body): Json<QBRGoalUpdateBody>,
) -> impl IntoResponse {
    let existing = state.qbr.get(id).await;
    if let Some(e) = guard_resource_tenant(&auth, &existing).await {
        return e;
    }
    service_result(
        state
            .qbr
            .update_goal(id, body.goal_id, body.current_value)
            .await,
    )
}

async fn qbr_benchmarks(
    State(state): State<S>,
    Query(q): Query<IndustryQuery>,
) -> impl IntoResponse {
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
    Extension(auth): Extension<AuthContext>,
    Path(tenant_id): Path<String>,
    Json(body): Json<serde_json::Value>,
) -> impl IntoResponse {
    if auth.tenant_id != tenant_id && !auth.is_admin {
        return Err((StatusCode::FORBIDDEN, "Tenant access denied".to_string()));
    }
    // Fetch compliance config for this tenant
    let status = match state.compliance.get_status(tenant_id.clone()).await {
        Ok(s) => s,
        Err(e) => {
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to get compliance status: {e}"),
            ))
        }
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

    let resp = state
        .http_client
        .post(format!("{}/v1/pdf/render", *PDF_RENDERER_URL))
        .json(&payload)
        .send()
        .await
        .map_err(|e| {
            (
                StatusCode::BAD_GATEWAY,
                format!("pdf-renderer unreachable: {e}"),
            )
        })?;

    if !resp.status().is_success() {
        let status_code = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err((
            StatusCode::BAD_GATEWAY,
            format!("pdf-renderer error {status_code}: {body}"),
        ));
    }

    let pdf_bytes = resp.bytes().await.map_err(|e| {
        (
            StatusCode::BAD_GATEWAY,
            format!("pdf-renderer read error: {e}"),
        )
    })?;

    Ok((
        StatusCode::OK,
        [
            (axum::http::header::CONTENT_TYPE, "application/pdf"),
            (
                axum::http::header::CONTENT_DISPOSITION,
                "attachment; filename=\"dpa.pdf\"",
            ),
        ],
        pdf_bytes,
    ))
}

/// GET /qbr/:id/pdf — Generate a QBR PDF for the given report
async fn qbr_generate_pdf(
    State(state): State<S>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<Uuid>,
) -> impl IntoResponse {
    // Fix A: the QBR must belong to the caller's tenant before rendering.
    let existing = state.qbr.get(id).await;
    if let Some((status, json)) = guard_resource_tenant(&auth, &existing).await {
        let msg = json
            .get("error")
            .and_then(|v| v.as_str())
            .unwrap_or("Tenant access denied")
            .to_string();
        return Err((status, msg));
    }

    // Fetch the QBR data
    let qbr = match state.qbr.get(id).await {
        Ok(q) => q,
        Err(e) => {
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to get QBR: {e}"),
            ))
        }
    };

    let qbr_json = serde_json::to_value(&qbr).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Serialization error: {e}"),
        )
    })?;

    let payload = serde_json::json!({
        "template": "qbr",
        "data": qbr_json,
    });

    let resp = state
        .http_client
        .post(format!("{}/v1/pdf/render", *PDF_RENDERER_URL))
        .json(&payload)
        .send()
        .await
        .map_err(|e| {
            (
                StatusCode::BAD_GATEWAY,
                format!("pdf-renderer unreachable: {e}"),
            )
        })?;

    if !resp.status().is_success() {
        let sc = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err((
            StatusCode::BAD_GATEWAY,
            format!("pdf-renderer error {sc}: {body}"),
        ));
    }

    let pdf_bytes = resp.bytes().await.map_err(|e| {
        (
            StatusCode::BAD_GATEWAY,
            format!("pdf-renderer read error: {e}"),
        )
    })?;

    let content_disposition = format!("attachment; filename=\"qbr-{id}.pdf\"");

    Ok((
        StatusCode::OK,
        [
            (
                axum::http::header::CONTENT_TYPE.to_string(),
                "application/pdf".to_string(),
            ),
            (
                axum::http::header::CONTENT_DISPOSITION.to_string(),
                content_disposition,
            ),
        ],
        pdf_bytes,
    ))
}

/// GET /compliance/report/:tenant_id/pdf — Generate a compliance report PDF
async fn compliance_report_pdf(
    State(state): State<S>,
    Extension(auth): Extension<AuthContext>,
    Path(tenant_id): Path<String>,
) -> impl IntoResponse {
    if auth.tenant_id != tenant_id && !auth.is_admin {
        return Err((StatusCode::FORBIDDEN, "Tenant access denied".to_string()));
    }
    // Fetch compliance report and status
    let report = match state.compliance.generate_report(tenant_id).await {
        Ok(r) => r,
        Err(e) => {
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to generate report: {e}"),
            ))
        }
    };

    let report_json = serde_json::to_value(&report).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Serialization error: {e}"),
        )
    })?;

    let payload = serde_json::json!({
        "template": "compliance_report",
        "data": report_json,
    });

    let resp = state
        .http_client
        .post(format!("{}/v1/pdf/render", *PDF_RENDERER_URL))
        .json(&payload)
        .send()
        .await
        .map_err(|e| {
            (
                StatusCode::BAD_GATEWAY,
                format!("pdf-renderer unreachable: {e}"),
            )
        })?;

    if !resp.status().is_success() {
        let sc = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err((
            StatusCode::BAD_GATEWAY,
            format!("pdf-renderer error {sc}: {body}"),
        ));
    }

    let pdf_bytes = resp.bytes().await.map_err(|e| {
        (
            StatusCode::BAD_GATEWAY,
            format!("pdf-renderer read error: {e}"),
        )
    })?;

    Ok((
        StatusCode::OK,
        [
            (axum::http::header::CONTENT_TYPE, "application/pdf"),
            (
                axum::http::header::CONTENT_DISPOSITION,
                "attachment; filename=\"compliance-report.pdf\"",
            ),
        ],
        pdf_bytes,
    ))
}

// ── Tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::Body, http::Request};
    use metrics_exporter_prometheus::PrometheusBuilder;
    use sqlx::postgres::PgPoolOptions;
    use tower::ServiceExt;

    #[test]
    fn test_router_builds() {
        let _ = Router::<Arc<AppState>>::new().route("/health", get(health_check));
    }

    #[tokio::test]
    async fn contract_routes_exist_at_root_and_legacy_prefix() {
        let pool = PgPoolOptions::new()
            .connect_lazy("postgres://localhost/unused")
            .unwrap();
        let config = Config::from_env().unwrap();
        let recorder = PrometheusBuilder::new().build_recorder();
        let app = router(Arc::new(AppState::new(pool, config, recorder.handle())));

        let root = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/contracts")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(root.status(), StatusCode::UNAUTHORIZED);

        let legacy = app
            .oneshot(
                Request::builder()
                    .uri("/api/enterprise/contracts")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(legacy.status(), StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn overage_rate_from_per_thousand_rounds_instead_of_truncating() {
        // Fix J-8: 5/10 previously truncated to 0 (free overage).
        assert_eq!(overage_rate_from_per_thousand(5), 1);
        assert_eq!(overage_rate_from_per_thousand(15), 2); // 1.5 -> 2, was 1
        assert_eq!(overage_rate_from_per_thousand(14), 1); // 1.4 -> 1
        assert_eq!(overage_rate_from_per_thousand(0), 0);
        assert_eq!(overage_rate_from_per_thousand(100), 10);
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
        let json =
            r#"{"tenant_id":"00000000-0000-0000-0000-000000000001","quarter":1,"year":2024}"#;
        let body: QBRScheduleBody = serde_json::from_str(json).unwrap();
        assert_eq!(body.quarter, 1);
        assert_eq!(body.year, 2024);
        assert_eq!(body.scheduled_date, None);
    }

    #[test]
    fn test_contract_create_body_deserialize() {
        let json = r#"{
          "startDate":"2026-04-01T00:00:00Z",
          "endDate":"2027-04-01T00:00:00Z",
          "baseFee":5000,
          "committedVolume":{"emails":100000,"apiCalls":1000,"storage":50},
          "overageRates":{"emailsPerThousand":15,"apiCallsPerThousand":5,"storagePerGb":1},
          "paymentTerms":"net30",
          "allowPurchaseOrders":true
        }"#;
        let body: ContractCreateBody = serde_json::from_str(json).unwrap();
        assert_eq!(body.base_fee, 5000);
        assert_eq!(body.committed_volume.emails, 100000);
        assert_eq!(body.payment_terms, "net30");
    }

    #[test]
    fn test_template_submit_body_deserialize() {
        let json = r#"{"tenant_id":"00000000-0000-0000-0000-000000000001","name":"t1","subject":"s","html_content":"<h1>hi</h1>","submitted_by":"user1"}"#;
        let body: TemplateSubmitBody = serde_json::from_str(json).unwrap();
        assert_eq!(body.name, "t1");
        assert_eq!(body.submitted_by, "user1");
    }
}
