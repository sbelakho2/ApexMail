use axum::{
    extract::{DefaultBodyLimit, Form, Path, Query, State},
    http::{
        header::{AUTHORIZATION, CONTENT_TYPE, LOCATION},
        HeaderMap, StatusCode,
    },
    middleware,
    response::{Html, IntoResponse, Response},
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
    /// Audit F11: per-IP fixed-window limiter for the unauthenticated SSO
    /// login initiators, whose staging INSERTs are otherwise an unbounded
    /// anonymous DB-row write.
    pub sso_login_limiter: crate::rate_limit::FixedWindowRateLimiter,
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
            sso_login_limiter: crate::rate_limit::FixedWindowRateLimiter::new(
                crate::rate_limit::SSO_LOGIN_MAX_PER_WINDOW,
                crate::rate_limit::SSO_LOGIN_WINDOW_SECS,
            ),
        }
    }
}

type S = Arc<AppState>;

// ── RBAC scopes (audit F8) ─────────────────────────────────────────────
//
// The canonical JWT carries a `scopes` vector minted per role
// (`canonical_scopes_for_role` in sso.rs; `*` for admin/owner). Enterprise
// authorization used to reduce to the binary `admin` claim + tenant
// membership, leaving control-plane mutations available to every tenant
// member. These scope strings gate the security-relevant control-plane
// mutations: a caller passes with the admin claim OR the explicit scope
// (`require_scope`). Scope-issuing for non-admin principals is a jwt-minter
// concern — until a minter hands out e.g. `compliance:write`, the gates
// degrade to admin-only, never wider than before.

/// Compliance control plane: enable frameworks, sign the BAA, enable
/// zero-retention.
pub const SCOPE_COMPLIANCE_WRITE: &str = "compliance:write";
/// Whitelabel configuration writes (branding, `custom_css`, support contacts).
pub const SCOPE_WHITELABEL_WRITE: &str = "whitelabel:write";
/// Log-stream destination CRUD, pause/resume.
pub const SCOPE_LOG_STREAMS_WRITE: &str = "log-streams:write";
/// Dedicated IP allocation.
pub const SCOPE_DEDICATED_IPS_WRITE: &str = "dedicated-ips:write";

#[derive(Debug, Clone)]
struct AuthContext {
    user_id: String,
    tenant_id: String,
    is_admin: bool,
    scopes: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct JwtClaims {
    sub: String,
    tenant_id: String,
    #[serde(default)]
    admin: bool,
    /// Fine-grained authorities minted with the token (audit F8). Absent on
    /// legacy tokens — decoded as empty, which keeps those tokens exactly as
    /// powerful as the old binary model (no wider).
    #[serde(default)]
    scopes: Vec<String>,
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
        // The ACS and OIDC callback are the landing points of the IdP's
        // browser redirects; an IdP never presents our bearer tokens. The
        // domain-less variants serve the configured (domain-less)
        // `SAML_ACS_URL` / `OIDC_REDIRECT_URI` defaults.
        || path == "/sso/acs"
        || path.starts_with("/sso/acs/")
        || path == "/sso/callback/oidc"
        || path.starts_with("/sso/callback/oidc/")
        || path == "/api/sso/saml/callback"
        || path == "/api/sso/oidc/callback"
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
        scopes: claims.scopes,
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
    /// Accepted for wire compatibility but NOT authoritative: the stored
    /// requester is the authenticated caller (audit F3 — separation of
    /// duties is only sound when the filer's identity is server-derived).
    #[allow(dead_code)]
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
    /// Accepted for wire compatibility but NOT authoritative (audit F3 —
    /// see [`DataAccessBody::requester_id`]).
    #[allow(dead_code)]
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
        .route("/sso/acs/:domain", post(sso_saml_acs))
        .route("/sso/acs", post(sso_saml_acs_domain_less))
        .route("/sso/callback/oidc/:domain", get(sso_oidc_callback))
        .route("/sso/callback/oidc", get(sso_oidc_callback_domain_less))
        // The default `SAML_ACS_URL` / `OIDC_REDIRECT_URI` values point at
        // these legacy paths; mount the same handlers so the zero-config
        // defaults are live endpoints too.
        .route("/api/sso/saml/callback", post(sso_saml_acs_domain_less))
        .route("/api/sso/oidc/callback", get(sso_oidc_callback_domain_less))
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
        .route("/sub-accounts/:id/resume", post(sub_account_resume))
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

/// Audit F8 / dogfood F6: require an OPERATOR principal.
///
/// The `admin: true` JWT claim this gate used to require is emitted by NO
/// production credential path: password sessions (`api-server`) and
/// enterprise SSO both mint `scopes = ["*"]` for owner/admin roles and never
/// set `admin`. The gate therefore answered 403 for every real owner session,
/// making `POST /sso/configure` (and its issuer-URL validation) unreachable.
///
/// The operator class is the wildcard scope set — exactly the authority the
/// existing [`require_scope`] already honours — or the legacy `admin` claim
/// for tokens minted outside the canonical minter. Tenant membership is
/// still enforced separately by each handler (`verify_tenant_access`).
fn require_admin(auth: &AuthContext) -> Option<(StatusCode, Json<serde_json::Value>)> {
    if auth.is_admin || auth.scopes.iter().any(|held| held == "*") {
        None
    } else {
        Some(err_json(StatusCode::FORBIDDEN, "Admin access required"))
    }
}

/// Audit F8: require the admin claim OR the explicit scope string. `*` (the
/// admin/owner scope set) grants every scope. `Some(err)` is the 403 to
/// return; `None` authorizes the call.
fn require_scope(auth: &AuthContext, scope: &str) -> Option<(StatusCode, Json<serde_json::Value>)> {
    let granted = auth.is_admin || auth.scopes.iter().any(|held| held == "*" || held == scope);
    if granted {
        None
    } else {
        Some(err_json(
            StatusCode::FORBIDDEN,
            "Admin access or the required scope is missing",
        ))
    }
}

/// Audit F7: emit a SERVER-SIDE audit entry for a security-relevant mutation.
///
/// The enterprise service used to write audit entries only when a client
/// remembered to POST /compliance/audit; the trail for HIPAA/SOC2-relevant
/// control-plane actions must not be optional. Identity columns are
/// server-derived (the same policy `compliance_log_audit` demonstrates): the
/// actor is the authenticated token subject, the ip is the connection peer
/// (absent when the deployment serves without `connect_info`), the
/// user-agent is the request header.
///
/// Best-effort: a failed audit write is logged loudly but never fails the
/// (already authorized and completed) mutation — EXCEPT the PHI-decryption
/// path, which awaits this result and fails closed (see `decrypt_field`).
#[allow(clippy::too_many_arguments)]
async fn audit_server_action(
    state: &AppState,
    tenant_id: &str,
    auth: &AuthContext,
    connect_info: Option<axum::extract::ConnectInfo<std::net::SocketAddr>>,
    headers: &HeaderMap,
    action: &str,
    resource_type: &str,
    resource_id: Option<&str>,
    details: serde_json::Value,
) -> Result<(), String> {
    let ip_address = connect_info.map(|ci| ci.0.ip().to_string());
    let user_agent = headers
        .get(axum::http::header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.to_string());
    state
        .compliance
        .log_audit(
            tenant_id.to_string(),
            Some(&auth.user_id),
            action,
            resource_type,
            resource_id,
            None,
            Some(details),
            ip_address.as_deref(),
            user_agent.as_deref(),
            None,
            None,
            Some(serde_json::json!({
                "emitted_by": "enterprise-server",
                "actor_tenant_id": auth.tenant_id,
            })),
        )
        .await
}

/// Derive the rate-limit key for an unauthenticated request (audit F11): the
/// connection peer when available, else the front-of-list `X-Forwarded-For`
/// entry, else a shared bucket (never "no limit").
fn unauthenticated_client_ip(
    connect_info: Option<axum::extract::ConnectInfo<std::net::SocketAddr>>,
    headers: &HeaderMap,
) -> String {
    if let Some(ci) = connect_info {
        return ci.0.ip().to_string();
    }
    headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|list| list.split(',').next())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .unwrap_or_else(|| "unattributed".to_string())
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

/// Map a structured [`crate::types::ApiResult`] error code onto a real HTTP
/// status.
///
/// NOT_FOUND previously surfaced as HTTP 200 with `{"success":false}` — a
/// lie to any client checking `response.ok`. Codes with no documented HTTP
/// meaning keep the historical 200 (the envelope still describes the
/// outcome), so handlers whose result cannot distinguish a not-found are
/// untouched. `VERIFICATION_FAILED` intentionally stays 200: the check ran
/// successfully and its negative outcome is the payload (pinned by the
/// log-stream SSRF tests), it is not a malformed request.
fn api_result_error_status(code: Option<&str>) -> Option<StatusCode> {
    match code {
        Some("NOT_FOUND") => Some(StatusCode::NOT_FOUND),
        Some("VALIDATION") | Some("INVALID_IP") => Some(StatusCode::BAD_REQUEST),
        Some("INVALID_TRANSITION") | Some("ALREADY_SUBMITTED") => Some(StatusCode::CONFLICT),
        // A provisioning/retry attempted from the wrong state is a CONFLICT
        // (the request is well-formed; the resource is not in a state that
        // permits it) — it was reported as HTTP 200 with success:false.
        Some("INVALID_STATE") => Some(StatusCode::CONFLICT),
        _ => None,
    }
}

fn service_result<T: serde::Serialize>(
    result: Result<crate::types::ApiResult<T>, String>,
) -> (StatusCode, Json<serde_json::Value>) {
    match result {
        Ok(r) => {
            // The envelope (success/data/error/code) is unchanged; only the
            // status line is corrected.
            let status = if r.success {
                StatusCode::OK
            } else {
                api_result_error_status(r.code.as_deref()).unwrap_or(StatusCode::OK)
            };
            match serde_json::to_value(&r) {
                Ok(v) => (status, Json(v)),
                Err(e) => {
                    tracing::error!(error = %e, "JSON serialization failed in service_result");
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(serde_json::json!({"error": "internal serialization error"})),
                    )
                }
            }
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e})),
        ),
    }
}

/// Support-surface variant of [`service_result`]. The SupportService returns
/// structured error codes (VALIDATION, INVALID_TRANSITION,
/// ALREADY_SUBMITTED, NOT_FOUND) that must surface as real HTTP status codes
/// instead of a 200 with `success:false`. The response body still carries
/// the ApiResult JSON, so the client keeps the human-readable error message.
fn support_result<T: serde::Serialize>(
    result: Result<crate::types::ApiResult<T>, String>,
) -> (StatusCode, Json<serde_json::Value>) {
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
    connect_info: Option<axum::extract::ConnectInfo<std::net::SocketAddr>>,
    headers: HeaderMap,
    Path(contract_id): Path<Uuid>,
    Json(body): Json<ContractSignBody>,
) -> impl IntoResponse {
    let tenant_id = match resolve_tenant_id(&headers, &auth) {
        Ok(tenant_id) => tenant_id,
        Err(error) => return error,
    };

    // Audit F7: signer identity for the trail — captured before the body is
    // consumed by the service call.
    let signer_name = body.signer_name.clone();
    let signer_title = body.signer_title.clone();

    // Fix D: non-admin callers can only record a tenant-side signature —
    // activation and the `tenants.plan` change require the platform-admin
    // counter-signature path below.
    if !auth.is_admin {
        let result = state
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
            .await;
        // Audit F7: a contract signature is a binding commercial event.
        if let Some(contract) = result.as_ref().ok().and_then(|r| r.data.as_ref()) {
            if let Err(error) = audit_server_action(
                &state,
                &contract.tenant_id,
                &auth,
                connect_info,
                &headers,
                "contract_signed",
                "contract",
                Some(&contract_id.to_string()),
                serde_json::json!({
                    "signer_name": signer_name,
                    "signer_title": signer_title,
                }),
            )
            .await
            {
                tracing::error!(error = %error, "failed to audit contract_signed");
            }
        }
        return match result {
            Ok(result) => match unwrap_contract_result(result) {
                Ok(contract) => json_status(StatusCode::OK, contract),
                Err(error) => error,
            },
            Err(error) => err_json(StatusCode::INTERNAL_SERVER_ERROR, &error),
        };
    }

    // Platform-admin counter-signature: activates the contract and promotes
    // the tenant plan. Requires a tenant signature to already exist.
    let result = state.contracts.counter_sign_contract(contract_id).await;
    // Audit F7: the counter-signature activates the contract and changes the
    // tenant plan — recorded against the contract owner's trail (the owning
    // tenant comes from the contract; the platform admin is not a member).
    if let Some(contract) = result.as_ref().ok().and_then(|r| r.data.as_ref()) {
        if let Err(error) = audit_server_action(
            &state,
            &contract.tenant_id,
            &auth,
            connect_info,
            &headers,
            "contract_counter_signed",
            "contract",
            Some(&contract_id.to_string()),
            serde_json::json!({ "counter_signed_by": auth.user_id }),
        )
        .await
        {
            tracing::error!(error = %error, "failed to audit contract_counter_signed");
        }
    }
    match result {
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
    connect_info: Option<axum::extract::ConnectInfo<std::net::SocketAddr>>,
    headers: HeaderMap,
    Json(body): Json<SSOConfigureRequest>,
) -> impl IntoResponse {
    // Audit F8 (verifier repair): SSO (re)configuration decides WHO can log
    // in to the tenant — IdP certificate, entity id, SSO URL, enforce_sso.
    // Left to plain tenant membership, any member (a viewer) could repoint
    // the tenant's federation at an IdP they control. This gate is part of
    // the admin-only class the audit records (`sso_configure`,
    // `template_approve`, `sso_cleanup_sessions`, contract counter-sign).
    if let Some(e) = require_admin(&auth) {
        return e;
    }
    if let Err(e) = verify_tenant_access(&auth, &body.tenant_id) {
        return e;
    }
    // Configure-time validation of the tenant-supplied federation inputs:
    // without it, an issuer the egress guard will refuse (plain-HTTP and
    // not allowlisted) is stored happily and then 500s on EVERY unauthenticated
    // login-begin for the domain. Refuse it here with an honest 400.
    // (The resolving half of the guard — private/reserved-address checks —
    // still runs at begin, where DNS can be pinned.)
    if body.provider_type.eq_ignore_ascii_case("oidc") {
        if let Some(issuer) = body.oidc_issuer.as_deref().filter(|s| !s.trim().is_empty()) {
            if let Err(reason) = crate::sso::validate_federation_issuer_url(issuer) {
                return err_json(StatusCode::BAD_REQUEST, &reason);
            }
        }
        // Storing an OIDC client secret requires the deployment's at-rest
        // encryption key. Without it the service errors deep inside secret
        // handling (a raw crypto-error string as a 500); pre-flight it as
        // the deployment-misconfiguration shape instead.
        if body
            .oidc_client_secret
            .as_deref()
            .is_some_and(|s| !s.trim().is_empty())
            && state.config.sso.encryption_key.is_empty()
        {
            return err_json(
                StatusCode::SERVICE_UNAVAILABLE,
                "SSO secret encryption is not configured on this deployment (SSO_ENCRYPTION_KEY is unset); an OIDC client secret cannot be stored",
            );
        }
    }
    // The response is sanitized: secrets (encrypted private key / client
    // secret, SAML certificate) never leave the server.
    match state.sso.configure(body).await {
        Ok(r) => match r.data {
            Some(config) => {
                // Audit F7: an SSO (re)configuration changes who can log in
                // to the tenant — it is recorded server-side with the
                // authenticated actor, never left to the client to report.
                if let Err(error) = audit_server_action(
                    &state,
                    &config.tenant_id,
                    &auth,
                    connect_info,
                    &headers,
                    "sso_configure",
                    "sso_config",
                    Some(&config.tenant_id),
                    serde_json::json!({
                        "provider_type": config.provider_type,
                        "domain": config.domain,
                        "enabled": config.enabled,
                        "enforce_sso": config.enforce_sso,
                        "session_duration_hours": config.session_duration_hours,
                    }),
                )
                .await
                {
                    tracing::error!(error = %error, "failed to audit sso_configure");
                }
                ok_json(SSOPublicConfig::from(config))
            }
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

/// Build the 302 that hands the browser to the IdP.
fn redirect_to(url: &str) -> Response {
    (StatusCode::FOUND, [(LOCATION, url.to_string())]).into_response()
}

/// Map a service-level [`crate::types::ApiResult`] refusal to its status:
/// NOT_FOUND keeps 404, anything else is an authenticated-flow refusal (401).
fn sso_refusal_status(code: Option<&str>) -> StatusCode {
    match code {
        Some("NOT_FOUND") => StatusCode::NOT_FOUND,
        _ => StatusCode::UNAUTHORIZED,
    }
}

/// Turn a minted SSO session into the browser-facing outcome (audit P1-3).
///
/// With the canonical session available, the callback is a REAL login: a 302
/// to the sanitized post-login target with the `am_session` cookie attached
/// — the identical session shape the web login issues. Without it (the
/// deployment has not configured the shared `JWT_PRIVATE_KEY_PEM`), the
/// enterprise session JSON is returned as before so the bearer flow keeps
/// working.
fn sso_session_response(result: crate::types::SSOCallbackResult) -> Response {
    match result.canonical {
        Some(canonical) => {
            let mut response = redirect_to(&canonical.return_to);
            if let Ok(value) = canonical.cookie.parse() {
                response
                    .headers_mut()
                    .append(axum::http::header::SET_COOKIE, value);
            }
            response
        }
        None => ok_json(result).into_response(),
    }
}

/// GET /sso/login/saml/:domain
///
/// SP-initiated SAML, step 1: build the tenant's AuthnRequest and send the
/// browser to its IdP. The IdP posts the signed response back to the ACS
/// (`POST /sso/acs/:domain`), which issues the session. Unknown or disabled
/// domains are refused with 404 instead of a redirect. An optional
/// `?return_to=` query parameter stages the sanitized post-login redirect
/// target with the AuthnRequest.
#[derive(Debug, Deserialize)]
struct SsoLoginQuery {
    return_to: Option<String>,
}

async fn sso_saml_login(
    State(state): State<S>,
    connect_info: Option<axum::extract::ConnectInfo<std::net::SocketAddr>>,
    headers: HeaderMap,
    Path(domain): Path<String>,
    Query(query): Query<SsoLoginQuery>,
) -> impl IntoResponse {
    // Audit F11: the initiator stages a DB row per call and is
    // unauthenticated by protocol — bound the writes per client IP.
    let client_ip = unauthenticated_client_ip(connect_info, &headers);
    if !state.sso_login_limiter.check(&client_ip) {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            "Too many SSO login initiations; retry later",
        )
            .into_response();
    }
    match state
        .sso
        .initiate_saml_login(&domain, query.return_to.as_deref())
        .await
    {
        Ok(result) => match result.data {
            Some(redirect) => redirect_to(&redirect.redirect_url),
            None => err_json(
                sso_refusal_status(result.code.as_deref()),
                result
                    .error
                    .as_deref()
                    .unwrap_or("SAML not configured for domain"),
            )
            .into_response(),
        },
        Err(error) => err_json(StatusCode::INTERNAL_SERVER_ERROR, &error).into_response(),
    }
}

/// GET /sso/login/oidc/:domain
///
/// SP-initiated OIDC, step 1: stage the single-use `state` + PKCE verifier
/// and send the browser to the IdP's DISCOVERED authorization endpoint. The
/// IdP redirects back to `GET /sso/callback/oidc/:domain`, which completes
/// the exchange and issues the session. Unknown or disabled domains are
/// refused with 404.
async fn sso_oidc_login(
    State(state): State<S>,
    connect_info: Option<axum::extract::ConnectInfo<std::net::SocketAddr>>,
    headers: HeaderMap,
    Path(domain): Path<String>,
    Query(query): Query<SsoLoginQuery>,
) -> impl IntoResponse {
    // Audit F11: same staging-write bound as the SAML initiator.
    let client_ip = unauthenticated_client_ip(connect_info, &headers);
    if !state.sso_login_limiter.check(&client_ip) {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            "Too many SSO login initiations; retry later",
        )
            .into_response();
    }
    match state
        .sso
        .initiate_oidc_login(&domain, query.return_to.as_deref())
        .await
    {
        Ok(result) => match result.data {
            Some(redirect) => redirect_to(&redirect.redirect_url),
            None => err_json(
                sso_refusal_status(result.code.as_deref()),
                result
                    .error
                    .as_deref()
                    .unwrap_or("OIDC not configured for domain"),
            )
            .into_response(),
        },
        Err(error) => err_json(StatusCode::INTERNAL_SERVER_ERROR, &error).into_response(),
    }
}

/// The SAML ACS POST body (HTTP-POST binding: the IdP sends url-encoded
/// form fields).
#[derive(Debug, Deserialize)]
struct SamlAcsBody {
    #[serde(rename = "SAMLResponse")]
    saml_response: String,
    #[serde(rename = "RelayState")]
    relay_state: Option<String>,
}

/// Decode the base64 `SAMLResponse` POST field into the XML document.
fn decode_saml_response(encoded: &str) -> Result<String, String> {
    use base64::Engine;
    let clean: String = encoded.chars().filter(|c| !c.is_whitespace()).collect();
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(clean.as_bytes())
        .map_err(|error| format!("SAMLResponse is not valid base64: {error}"))?;
    String::from_utf8(bytes).map_err(|_| "SAMLResponse is not valid UTF-8 XML".to_string())
}

/// POST /sso/acs/:domain — the SAML Assertion Consumer Service, and
/// POST /sso/acs — the same ACS at a configured (domain-less) `SAML_ACS_URL`,
/// where the tenant domain arrives in RelayState.
///
/// Full validation order, all inside the manager: XML-DSig signature against
/// the tenant's configured IdP certificate, success status, issuer ==
/// configured entity_id, audience == configured ACS URL, NotBefore/NotOnOrAfter
/// window, and the per-tenant replay guard. Only a fully validated assertion
/// yields a session.
async fn sso_saml_acs(
    State(state): State<S>,
    Path(domain): Path<String>,
    Form(body): Form<SamlAcsBody>,
) -> impl IntoResponse {
    sso_saml_acs_inner(state, Some(domain), body).await
}

/// The domain-less ACS: `SAML_ACS_URL` need not embed a tenant domain — the
/// domain arrives in RelayState.
async fn sso_saml_acs_domain_less(
    State(state): State<S>,
    Form(body): Form<SamlAcsBody>,
) -> impl IntoResponse {
    sso_saml_acs_inner(state, None, body).await
}

async fn sso_saml_acs_inner(state: S, path_domain: Option<String>, body: SamlAcsBody) -> Response {
    let domain = path_domain
        .or(body.relay_state.clone())
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());
    let Some(domain) = domain else {
        return err_json(
            StatusCode::BAD_REQUEST,
            "SAML ACS requires the tenant domain in the path or RelayState",
        )
        .into_response();
    };
    let saml_xml = match decode_saml_response(&body.saml_response) {
        Ok(saml_xml) => saml_xml,
        Err(reason) => return err_json(StatusCode::BAD_REQUEST, &reason).into_response(),
    };

    let validated = match state
        .sso
        .parse_and_validate_saml_response(&saml_xml, &domain)
        .await
    {
        Ok(validated) => validated,
        Err(reason) => return err_json(StatusCode::UNAUTHORIZED, &reason).into_response(),
    };
    let config = match state.sso.get_config_by_domain(&domain).await {
        Ok(Some(config)) => config,
        Ok(None) => {
            return err_json(StatusCode::UNAUTHORIZED, "SAML not configured for domain")
                .into_response()
        }
        Err(error) => return err_json(StatusCode::INTERNAL_SERVER_ERROR, &error).into_response(),
    };

    // The assertion is trusted here: NameID identifies the user, attributes
    // carry the profile. Audit F2: the asserted email must pass the SAME
    // assurance the OIDC callback enforces (`validate_asserted_email` —
    // valid syntax + belongs to the configured SSO domain). The old
    // `attribute("email").unwrap_or_else(|| name_id)` fallback let an IdP
    // assert `victim@anydomain.com` (or an opaque NameID) straight into
    // `resolve_or_provision_sso_user`, whose first-link fallback binds it to
    // an existing same-tenant account and inherits its role — a JIT
    // account-linking hijack. An opaque NameID is `external_user_id` only
    // and never provisions a `users.email`.
    let attribute = |name: &str| {
        validated
            .attributes
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.clone())
    };
    let email = match attribute("email").as_deref().map(str::trim) {
        Some(raw) if !raw.is_empty() => {
            match crate::sso::validate_asserted_email(raw, &config) {
                Ok(email) => email,
                Err(reason) => {
                    return err_json(StatusCode::UNAUTHORIZED, &reason).into_response()
                }
            }
        }
        _ => {
            return err_json(
                StatusCode::UNAUTHORIZED,
                "The SAML assertion must carry a valid email attribute; the NameID is never used as an email address",
            )
            .into_response()
        }
    };
    // Audit F2 (same bar as OIDC): an IdP that ASSERTS a verification flag
    // must not assert it false. SAML has no standardized verified attribute,
    // so an absent flag is accepted — `asserted_email_flag_is_verified`.
    if !crate::sso::asserted_email_flag_is_verified(attribute("email_verified").as_deref()) {
        return err_json(
            StatusCode::UNAUTHORIZED,
            "The SAML assertion's email_verified flag is false",
        )
        .into_response();
    }
    let display_name = attribute("displayName").or_else(|| attribute("display_name"));
    let groups = {
        let values: Vec<String> = validated
            .attributes
            .iter()
            .filter(|(key, _)| {
                key.eq_ignore_ascii_case("group") || key.eq_ignore_ascii_case("groups")
            })
            .map(|(_, value)| value.clone())
            .collect();
        if values.is_empty() {
            None
        } else {
            Some(serde_json::json!(values))
        }
    };
    let attributes = serde_json::to_value(
        validated
            .attributes
            .iter()
            .cloned()
            .collect::<std::collections::BTreeMap<String, String>>(),
    )
    .ok();
    // The staged AuthnRequest's redirect target was consumed atomically with
    // the InResponseTo correlation.
    let return_to = validated.return_to.clone();

    match state
        .sso
        .handle_saml_callback(
            &config,
            crate::sso::FederationIdentity {
                email: &email,
                display_name: display_name.as_deref(),
                external_user_id: &validated.name_id,
                groups,
                attributes,
            },
            return_to.as_deref(),
        )
        .await
    {
        Ok(result) => match result.data {
            Some(session) => sso_session_response(session),
            None => err_json(
                StatusCode::INTERNAL_SERVER_ERROR,
                result
                    .error
                    .as_deref()
                    .unwrap_or("SSO session issuance failed"),
            )
            .into_response(),
        },
        Err(error) => err_json(StatusCode::INTERNAL_SERVER_ERROR, &error).into_response(),
    }
}

/// The OIDC callback query parameters the IdP appends to the redirect_uri.
#[derive(Debug, Deserialize)]
struct OidcCallbackQuery {
    code: Option<String>,
    state: Option<String>,
}

/// GET /sso/callback/oidc/:domain — the OIDC redirect_uri target, and
/// GET /sso/callback/oidc — the same callback at a configured (domain-less)
/// `OIDC_REDIRECT_URI`, where the tenant domain arrives inside the state.
///
/// Consumes the single-use state, exchanges the authorization code with the
/// persisted PKCE verifier, validates the id_token against the IdP's JWKS,
/// and issues the session.
async fn sso_oidc_callback(
    State(state): State<S>,
    Path(domain): Path<String>,
    Query(query): Query<OidcCallbackQuery>,
) -> impl IntoResponse {
    sso_oidc_callback_inner(state, Some(domain), query).await
}

/// The domain-less OIDC callback: `OIDC_REDIRECT_URI` need not embed a tenant
/// domain — the domain arrives inside the single-use state.
async fn sso_oidc_callback_domain_less(
    State(state): State<S>,
    Query(query): Query<OidcCallbackQuery>,
) -> impl IntoResponse {
    sso_oidc_callback_inner(state, None, query).await
}

async fn sso_oidc_callback_inner(
    state: S,
    path_domain: Option<String>,
    query: OidcCallbackQuery,
) -> Response {
    let code = query
        .code
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());
    let Some(code) = code else {
        return err_json(
            StatusCode::BAD_REQUEST,
            "OIDC callback is missing the authorization code",
        )
        .into_response();
    };
    let oidc_state = query
        .state
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());
    let Some(oidc_state) = oidc_state else {
        return err_json(
            StatusCode::BAD_REQUEST,
            "OIDC callback is missing the state parameter",
        )
        .into_response();
    };
    let path_domain = path_domain
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());

    match state
        .sso
        .complete_oidc_callback(path_domain.as_deref(), &code, &oidc_state, None)
        .await
    {
        Ok(Ok(session)) => ok_json(session).into_response(),
        Ok(Err(reason)) => err_json(StatusCode::UNAUTHORIZED, &reason).into_response(),
        Err(error) => err_json(StatusCode::INTERNAL_SERVER_ERROR, &error).into_response(),
    }
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
    // Audit F8: control-plane mutation — admin or the compliance scope.
    if let Some(e) = require_scope(&auth, SCOPE_COMPLIANCE_WRITE) {
        return e;
    }
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
    connect_info: Option<axum::extract::ConnectInfo<std::net::SocketAddr>>,
    headers: HeaderMap,
    Json(body): Json<BAABody>,
) -> impl IntoResponse {
    // Audit F8: control-plane mutation — admin or the compliance scope.
    if let Some(e) = require_scope(&auth, SCOPE_COMPLIANCE_WRITE) {
        return e;
    }
    if let Err(e) = verify_tenant_access(&auth, &body.tenant_id) {
        return e;
    }
    let result = state
        .compliance
        .sign_baa(
            body.tenant_id.clone(),
            &body.signatory_name,
            &body.signatory_title,
            &body.signatory_email,
        )
        .await;
    // Audit F7: a BAA signature is a contractual HIPAA attestation — the
    // server records who signed, not just the client's optional echo.
    if result.as_ref().ok().and_then(|r| r.data.as_ref()).is_some() {
        if let Err(error) = audit_server_action(
            &state,
            &body.tenant_id,
            &auth,
            connect_info,
            &headers,
            "baa_signed",
            "compliance_config",
            Some(&body.tenant_id),
            serde_json::json!({
                "signatory_name": body.signatory_name,
                "signatory_title": body.signatory_title,
            }),
        )
        .await
        {
            tracing::error!(error = %error, "failed to audit baa_signed");
        }
    }
    service_result(result)
}

async fn compliance_zero_retention(
    State(state): State<S>,
    Extension(auth): Extension<AuthContext>,
    connect_info: Option<axum::extract::ConnectInfo<std::net::SocketAddr>>,
    headers: HeaderMap,
    Path(tenant_id): Path<String>,
) -> impl IntoResponse {
    // Audit F8: control-plane mutation — admin or the compliance scope.
    if let Some(e) = require_scope(&auth, SCOPE_COMPLIANCE_WRITE) {
        return e;
    }
    if let Err(e) = verify_tenant_access(&auth, &tenant_id) {
        return e;
    }
    let result = state
        .compliance
        .enable_zero_retention(tenant_id.clone())
        .await;
    // Audit F7: enabling zero-retention directly changes purge behavior —
    // exactly the kind of action that must be in the tamper-evident trail.
    if result.as_ref().ok().and_then(|r| r.data.as_ref()).is_some() {
        if let Err(error) = audit_server_action(
            &state,
            &tenant_id,
            &auth,
            connect_info,
            &headers,
            "zero_retention_enabled",
            "compliance_config",
            Some(&tenant_id),
            serde_json::json!({ "zero_retention_mode": true }),
        )
        .await
        {
            tracing::error!(error = %error, "failed to audit zero_retention_enabled");
        }
    }
    service_result(result)
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
    // Audit F3 (verifier repair): the STORED requester is the authenticated
    // caller — never the body's `requester_id`. The separation-of-duties
    // check on approval compares the approver against the stored requester,
    // so a body-controlled requester_id ("someone-else") would let a member
    // file a grant and then approve it themselves. The body field stays
    // accepted for wire compatibility but is not authoritative (the same
    // server-derived-identity policy as `approved_by`, fix J-3).
    let requester_id = auth.user_id.clone();
    service_result(
        state
            .compliance
            .request_data_access(
                body.tenant_id,
                &requester_id,
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

    // Audit F3: separation of duties. The requester can never approve their
    // own grant — a tenant member used to be able to file a request and then
    // self-approve it into a time-boxed access token. Only an admin may
    // self-approve (a platform-level exception), everyone else needs a
    // DIFFERENT approver.
    if let Some(request) = existing.ok().and_then(|r| r.data) {
        if !auth.is_admin && request.requester_id == auth.user_id {
            return err_json(
                StatusCode::FORBIDDEN,
                "A data-access request cannot be approved by its requester (separation of duties)",
            );
        }
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
        // Audit F3: the raw access token is returned EXACTLY ONCE — in this
        // approval response, as the approver's handoff to the requester. The
        // database persists only its SHA-256 digest (the SSO bearer-token
        // model), so re-approving a completed request can never mint or
        // recover a usable token, and a DB read cannot leak one.
        Ok(result) => service_result(Ok(result)),
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
    // Audit F3 (verifier repair): same server-derived identity as the
    // data-access filer — the stored requester is the authenticated caller.
    let requester_id = auth.user_id.clone();
    service_result(
        state
            .compliance
            .request_data_deletion(
                body.tenant_id,
                &requester_id,
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
    pub field_name: String,
    pub value: String,
}

/// Decrypt a single field value (for testing/migration tooling).
///
/// Audit F1: this is a PHI-decryption oracle. It now (a) requires the admin
/// claim — tenant membership alone let a low-privilege insider bulk-decrypt
/// every ciphertext of their own tenant, and (b) writes a MANDATORY audit
/// entry per call (actor, field_name, tenant). The audit write happens
/// BEFORE any decryption and its failure fails the call closed: an
/// unauditable decryption must not happen.
async fn decrypt_field(
    State(state): State<S>,
    Extension(auth): Extension<AuthContext>,
    connect_info: Option<axum::extract::ConnectInfo<std::net::SocketAddr>>,
    headers: HeaderMap,
    Json(body): Json<DecryptFieldBody>,
) -> impl IntoResponse {
    if let Some(e) = require_admin(&auth) {
        return e;
    }
    if let Err(e) = verify_tenant_access(&auth, &body.tenant_id) {
        return e;
    }

    // Audit F1: mandatory per-call trail (attempt, outcome-bearing details,
    // never the ciphertext or plaintext). Fail closed on audit errors.
    if let Err(error) = audit_server_action(
        &state,
        &body.tenant_id,
        &auth,
        connect_info,
        &headers,
        "decrypt_field",
        "phi_field",
        Some(&body.tenant_id),
        serde_json::json!({
            "field_name": body.field_name,
            "is_phi_field": crate::field_encryption::PHI_FIELDS
                .contains(&body.field_name.as_str()),
        }),
    )
    .await
    {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({
                "error": {
                    "code": "AUDIT_WRITE_FAILED",
                    "message": format!("the decryption could not be audited; refusing to decrypt: {error}")
                }
            })),
        );
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
    // Audit F8: control-plane mutation — admin or the log-streams scope.
    if let Some(e) = require_scope(&auth, SCOPE_LOG_STREAMS_WRITE) {
        return e;
    }
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
    // Audit F8: control-plane mutation — admin or the log-streams scope.
    if let Some(e) = require_scope(&auth, SCOPE_LOG_STREAMS_WRITE) {
        return e;
    }
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
    // Audit F8: control-plane mutation — admin or the log-streams scope.
    if let Some(e) = require_scope(&auth, SCOPE_LOG_STREAMS_WRITE) {
        return e;
    }
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
    // Audit F8: control-plane mutation — admin or the log-streams scope.
    if let Some(e) = require_scope(&auth, SCOPE_LOG_STREAMS_WRITE) {
        return e;
    }
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
    // Audit F8: control-plane mutation — admin or the log-streams scope.
    if let Some(e) = require_scope(&auth, SCOPE_LOG_STREAMS_WRITE) {
        return e;
    }
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
    // An unknown stream id answered 200 with zeroed statistics, which reads
    // as "this stream delivered nothing" for a stream that does not exist.
    if !matches!(&existing, Ok(api_result) if api_result.data.is_some()) {
        return missing_resource("log stream", id);
    }
    service_result(state.log_streaming.get_stats(id).await)
}

/// 404 in the enterprise envelope shape (`success:false` + `code`) for a
/// resource id that does not exist.
fn missing_resource(what: &str, id: Uuid) -> (StatusCode, Json<serde_json::Value>) {
    (
        StatusCode::NOT_FOUND,
        Json(serde_json::json!({
            "success": false,
            "data": serde_json::Value::Null,
            "error": format!("{what} {id} not found"),
            "code": "NOT_FOUND",
        })),
    )
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
    // Audit F8: control-plane mutation — admin or the dedicated-IPs scope.
    if let Some(e) = require_scope(&auth, SCOPE_DEDICATED_IPS_WRITE) {
        return e;
    }
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

/// A CIDR block must be a syntactically valid NETWORK address: a malformed
/// value (bad syntax, prefix > 32/128, host bits set) is caller error and
/// must be answered with a 4xx — previously it reached the database and
/// surfaced as a 500.
fn is_valid_network_cidr(cidr: &str) -> bool {
    use std::net::IpAddr;
    let Some((address, prefix)) = cidr.trim().split_once('/') else {
        return false;
    };
    let Ok(prefix) = prefix.parse::<u32>() else {
        return false;
    };
    match address.parse::<IpAddr>() {
        Ok(IpAddr::V4(v4)) => {
            if prefix > 32 {
                return false;
            }
            let mask = if prefix == 0 {
                0
            } else {
                u32::MAX << (32 - prefix)
            };
            u32::from(v4) & mask == u32::from(v4)
        }
        Ok(IpAddr::V6(v6)) => {
            if prefix > 128 {
                return false;
            }
            let bits = u128::from(v6);
            let mask = if prefix == 0 {
                0
            } else {
                u128::MAX << (128 - prefix)
            };
            bits & mask == bits
        }
        Err(_) => false,
    }
}

async fn byoip_register(
    State(state): State<S>,
    Extension(auth): Extension<AuthContext>,
    Json(body): Json<BYOIPBody>,
) -> impl IntoResponse {
    if let Err(e) = verify_tenant_access(&auth, &body.tenant_id) {
        return e;
    }
    if !is_valid_network_cidr(&body.cidr_block) {
        return err_json(
            StatusCode::BAD_REQUEST,
            "cidr_block must be a valid network CIDR (network address with host bits clear)",
        );
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

async fn sub_account_resume(
    State(state): State<S>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<Uuid>,
) -> impl IntoResponse {
    // Mirror the suspend handler's parent-tenant ownership check.
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
    service_result(state.sub_accounts.resume(id).await)
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
    connect_info: Option<axum::extract::ConnectInfo<std::net::SocketAddr>>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(body): Json<ApiKeyCreateBody>,
) -> impl IntoResponse {
    // Verify parent tenant ownership first by looking up the sub-account
    let parent_tenant = match state.sub_accounts.get(id).await {
        Ok(api_result) => match api_result.data {
            Some(ref sub) => {
                if let Err(e) = verify_tenant_access(&auth, &sub.parent_id) {
                    return e;
                }
                Some(sub.parent_id.clone())
            }
            None => return service_result::<SubAccount>(Ok(api_result)),
        },
        Err(e) => return service_result::<SubAccount>(Err(e)),
    };
    let result = state
        .sub_accounts
        .create_api_key(id, &body.name, body.permissions, body.rate_limit)
        .await;
    // Audit F7: API-key minting widens who can act as the tenant — recorded
    // server-side. The key material itself is never written to the trail.
    if let Some(parent_tenant) = parent_tenant {
        if result.as_ref().ok().and_then(|r| r.data.as_ref()).is_some() {
            if let Err(error) = audit_server_action(
                &state,
                &parent_tenant,
                &auth,
                connect_info,
                &headers,
                "sub_account_api_key_minted",
                "sub_account_api_key",
                Some(&id.to_string()),
                serde_json::json!({
                    "sub_account_id": id.to_string(),
                    "name": body.name,
                }),
            )
            .await
            {
                tracing::error!(error = %error, "failed to audit sub_account_api_key_minted");
            }
        }
    }
    service_result(result)
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
    // Audit F8: control-plane mutation — admin or the whitelabel scope.
    if let Some(e) = require_scope(&auth, SCOPE_WHITELABEL_WRITE) {
        return e;
    }
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
    // A tenant with no whitelabel configuration must be a 404, not an empty
    // success: "no templates configured yet" and "this tenant has no
    // whitelabel surface" are different answers.
    let configured = state.whitelabel.get_config(tenant_id.clone()).await;
    if !matches!(&configured, Ok(api_result) if api_result.data.is_some()) {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({
                "success": false,
                "data": serde_json::Value::Null,
                "error": format!("no whitelabel configuration for tenant {tenant_id}"),
                "code": "NOT_FOUND",
            })),
        );
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

/// Base URL of the pdf-renderer, read per call (not cached in a `LazyLock`)
/// so tests and operators can re-point it without a process restart. An
/// unset/blank `PDF_RENDERER_URL` means PDF rendering is not configured.
fn pdf_renderer_base_url() -> Option<String> {
    std::env::var("PDF_RENDERER_URL")
        .ok()
        .map(|value| value.trim().trim_end_matches('/').to_string())
        .filter(|value| !value.is_empty())
}

/// Render a PDF through the configured pdf-renderer.
///
/// * unconfigured → 503 with an explicit message (never a misleading 502);
/// * configured but unreachable/erroring → 502 and no partial body;
/// * success → the renderer's bytes verbatim.
async fn render_pdf(
    state: &AppState,
    payload: &serde_json::Value,
) -> Result<axum::body::Bytes, (StatusCode, String)> {
    let Some(base_url) = pdf_renderer_base_url() else {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "PDF rendering is not configured: set PDF_RENDERER_URL to the pdf-renderer base URL"
                .to_string(),
        ));
    };

    let response = state
        .http_client
        .post(format!("{base_url}/v1/pdf/render"))
        .json(payload)
        .send()
        .await
        .map_err(|e| {
            (
                StatusCode::BAD_GATEWAY,
                format!("pdf-renderer unreachable: {e}"),
            )
        })?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err((
            StatusCode::BAD_GATEWAY,
            format!("pdf-renderer error {status}: {body}"),
        ));
    }

    response.bytes().await.map_err(|e| {
        (
            StatusCode::BAD_GATEWAY,
            format!("pdf-renderer read error: {e}"),
        )
    })
}

/// POST /dpa/:tenant_id/pdf — Generate a GDPR Data Processing Agreement PDF
async fn dpa_generate_pdf(
    State(state): State<S>,
    Extension(auth): Extension<AuthContext>,
    connect_info: Option<axum::extract::ConnectInfo<std::net::SocketAddr>>,
    headers: HeaderMap,
    Path(tenant_id): Path<String>,
    Json(body): Json<serde_json::Value>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
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

    let pdf_bytes = render_pdf(&state, &payload).await?;

    // Audit F7: DPA paper trail — a generated (signed-form) DPA document is
    // a compliance attestation artifact; the server records its issuance.
    if let Err(error) = audit_server_action(
        &state,
        &tenant_id,
        &auth,
        connect_info,
        &headers,
        "dpa_document_generated",
        "dpa",
        Some(&tenant_id),
        serde_json::json!({ "template": "dpa" }),
    )
    .await
    {
        tracing::error!(error = %error, "failed to audit dpa_document_generated");
    }

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

    let pdf_bytes = render_pdf(&state, &payload).await?;

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

    let pdf_bytes = render_pdf(&state, &payload).await?;

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

    #[tokio::test]
    async fn sub_account_resume_route_exists_and_requires_auth() {
        // T1 dogfood: suspend had no inverse — POST /sub-accounts/:id/resume
        // must be routed (401 before auth, not 404/405). Sub-account routes
        // live on the main router only (like suspend itself): the
        // /api/enterprise nest carries contract_routes, not these.
        let pool = PgPoolOptions::new()
            .connect_lazy("postgres://localhost/unused")
            .unwrap();
        let config = Config::from_env().unwrap();
        let recorder = PrometheusBuilder::new().build_recorder();
        let app = router(Arc::new(AppState::new(pool, config, recorder.handle())));

        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/sub-accounts/00000000-0000-0000-0000-000000000001/resume")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
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

    // ── helper arms that need deliberately-failing inputs ─────────────

    /// A serializer that always fails: drives the defensive serialization
    /// arms of the response helpers with a genuine serde error.
    struct Unserializable;

    impl serde::Serialize for Unserializable {
        fn serialize<S: serde::Serializer>(&self, _s: S) -> Result<S::Ok, S::Error> {
            Err(serde::ser::Error::custom("no serialization possible"))
        }
    }

    #[test]
    fn response_helpers_report_serialization_failures_as_500() {
        let (status, json) = ok_json(Unserializable);
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(json.0["error"], "internal serialization error");

        let (status, json) = json_status(StatusCode::CREATED, Unserializable);
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(json.0["error"], "internal serialization error");
    }

    #[test]
    fn unwrap_contract_result_maps_every_service_outcome() {
        // Successful data passes through.
        let ok = crate::types::ApiResult::ok(serde_json::json!({"id": 1}));
        assert!(unwrap_contract_result(ok).is_ok());

        // Not-found keeps the 404 envelope...
        let not_found =
            crate::types::ApiResult::<serde_json::Value>::err("Contract not found", "NOT_FOUND");
        let err = unwrap_contract_result(not_found).expect_err("not found");
        assert_eq!(err.0, StatusCode::NOT_FOUND);
        assert_eq!(err.1 .0["error"], "Contract not found");

        // ...any other service message is a 500...
        let failed = crate::types::ApiResult::<serde_json::Value>::err(
            "contracts table missing",
            "INTERNAL",
        );
        let err = unwrap_contract_result(failed).expect_err("failure");
        assert_eq!(err.0, StatusCode::INTERNAL_SERVER_ERROR);

        // ...and an empty ApiResult with no message is an honest 500.
        let empty = crate::types::ApiResult::<serde_json::Value> {
            success: false,
            data: None,
            error: None,
            code: None,
        };
        let err = unwrap_contract_result(empty).expect_err("unexpected shape");
        assert_eq!(err.0, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(err.1 .0["error"], "Unexpected contract response");
    }

    #[test]
    fn network_cidr_validation_rejects_each_malformed_shape() {
        // No slash, bad prefix, bad address.
        assert!(!is_valid_network_cidr("203.0.113.0"));
        assert!(!is_valid_network_cidr("203.0.113.0/xx"));
        assert!(!is_valid_network_cidr("not-an-ip/24"));
        // Prefix too long per family.
        assert!(!is_valid_network_cidr("203.0.113.0/33"));
        assert!(!is_valid_network_cidr("2001:db8::/129"));
        // Host bits set.
        assert!(!is_valid_network_cidr("203.0.113.1/29"));
        assert!(!is_valid_network_cidr("2001:db8::1/64"));
        // Valid networks, including the 0 and max prefixes.
        assert!(is_valid_network_cidr("203.0.113.0/29"));
        assert!(is_valid_network_cidr("203.0.113.9/32"));
        assert!(is_valid_network_cidr("0.0.0.0/0"));
        assert!(is_valid_network_cidr("2001:db8::/32"));
        assert!(is_valid_network_cidr("::/0"));
        assert!(is_valid_network_cidr(" 203.0.113.0/24 ")); // trimmed
    }

    #[test]
    fn cors_layer_builds_from_explicit_origin_lists() {
        let mut config = Config::from_env().unwrap();
        config.cors_origins = vec!["https://app.example.com".to_string()];
        let _layer = cors_layer(&config); // exact-origin allowlist path
        config.cors_origins = vec!["*".to_string()];
        let _layer = cors_layer(&config); // Any path
        config.cors_origins = vec!["not a header value".to_string()];
        let _layer = cors_layer(&config); // unparsable origins are skipped
    }

    #[test]
    fn clamp_limit_bounds_values() {
        assert_eq!(clamp_limit(5, 10), 5);
        assert_eq!(clamp_limit(50, 10), 10);
        assert_eq!(clamp_limit(0, 10), 1);
        assert_eq!(clamp_limit(-3, 10), 1);
    }

    // ═══════════════════════════════════════════════════════════════════
    // SSO end-to-end through the router: both login flows, from the
    // browser-facing initiation through the IdP round-trip to a live
    // session, driven over HTTP with a genuinely signed SAML assertion and
    // a real (loopback) OIDC provider.
    // ═══════════════════════════════════════════════════════════════════

    const JWT_TEST_PRIVATE_PEM: &str = include_str!("../tests/keys/test_rsa_private.pem");
    const JWT_TEST_PUBLIC_PEM: &str = include_str!("../tests/keys/test_rsa_public.pem");
    const OIDC_TEST_KID: &str = "routes-oidc-test-key";

    use crate::sso::tests::{idp, SamlFixture, IDP_CERTIFICATE_PEM, IDP_PRIVATE_KEY_PEM};
    use chrono::{TimeDelta, Utc};

    static SSO_FLOW_IDP_KEY: std::sync::OnceLock<idp::RsaPrivateKey> = std::sync::OnceLock::new();

    fn sso_flow_idp_key() -> &'static idp::RsaPrivateKey {
        SSO_FLOW_IDP_KEY.get_or_init(|| idp::RsaPrivateKey::from_pkcs8_pem(IDP_PRIVATE_KEY_PEM))
    }

    /// A unique tenant id that fits the canonical `VARCHAR(26)` width.
    fn sso_flow_tenant(tag: &str) -> String {
        let unique = Uuid::new_v4().simple().to_string();
        let keep = 26usize.saturating_sub(tag.len() + 1);
        format!("{tag}_{}", &unique[..keep.min(unique.len())])
    }

    /// Seed the tenants row a generated test tenant id needs before the SSO
    /// callback can provision a canonical `users` row
    /// (`users_tenant_id_fkey`).
    async fn seed_sso_flow_tenant(state: &AppState, tenant: &str) {
        sqlx::query(
            "INSERT INTO tenants (id, name, slug, plan, status, settings, metadata, created_at, updated_at)
             VALUES ($1, $2, $3, 'pro', 'active', '{}'::jsonb, '{}'::jsonb, NOW(), NOW())
             ON CONFLICT (id) DO NOTHING",
        )
        .bind(tenant)
        .bind(format!("SSO Flow Tenant {tenant}"))
        .bind(format!("sso-flow-{tenant}"))
        .execute(&state.db)
        .await
        .expect("seed SSO flow tenant");
    }

    /// Provision a canonical database and the real router for the SSO flow
    /// tests. The JWT gate is pointed at the repo's test keypair so admin
    /// tokens can be minted for the authenticated `/sso/configure` call.
    async fn provision_sso_router(tag: &str) -> (Router, Arc<AppState>) {
        if std::env::var("SSO_ENCRYPTION_KEY").is_err() {
            std::env::set_var("SSO_ENCRYPTION_KEY", "sso-routes-coverage-key-0123456789");
        }
        if std::env::var("LOG_STREAM_ENCRYPTION_KEY").is_err() {
            std::env::set_var(
                "LOG_STREAM_ENCRYPTION_KEY",
                "log-stream-routes-coverage-key-0123456789",
            );
        }
        // The federation egress guard (audit P3-9) refuses plaintext and
        // private addresses; the in-process mock IdPs bind 127.0.0.1 over
        // http, so the loopback host is allowlisted for this test process.
        if std::env::var("SSO_FEDERATION_ALLOWLIST").is_err() {
            std::env::set_var("SSO_FEDERATION_ALLOWLIST", "127.0.0.1");
        }
        let pool = migrator::test_support::fresh_canonical_pool(tag, &format!("routes_sso_{tag}"))
            .await
            .expect("provision canonical pool")
            .expect("TEST_DATABASE_URL must be configured for this suite");
        let mut config = Config::from_env().unwrap();
        config.jwt_public_key_pem = JWT_TEST_PUBLIC_PEM.to_string();
        config.jwt_audience = None;
        config.jwt_issuer = None;
        let recorder = PrometheusBuilder::new().build_recorder();
        let state = Arc::new(AppState::new(pool, config, recorder.handle()));
        (router(state.clone()), state)
    }

    /// Mint an admin JWT the router's auth middleware accepts.
    fn mint_sso_admin_token(tenant_id: &str, subject: &str) -> String {
        mint_sso_token(tenant_id, subject, true)
    }

    /// Mint a member (non-admin) JWT the router's auth middleware accepts
    /// (audit F3: the separation-of-duties guard is exercised with a
    /// non-admin principal).
    fn mint_sso_member_token(tenant_id: &str, subject: &str) -> String {
        mint_sso_token(tenant_id, subject, false)
    }

    /// Mint the session a REAL owner login produces (dogfood F6): no `admin`
    /// claim, `scopes = ["*"]` — exactly what the api-server password session
    /// and the enterprise SSO minter (`canonical_scopes_for_role`) emit.
    fn mint_sso_owner_token(tenant_id: &str, subject: &str) -> String {
        mint_sso_token_with_scopes(tenant_id, subject, false, &["*"])
    }

    fn mint_sso_token(tenant_id: &str, subject: &str, admin: bool) -> String {
        mint_sso_token_with_scopes(tenant_id, subject, admin, &[])
    }

    fn mint_sso_token_with_scopes(
        tenant_id: &str,
        subject: &str,
        admin: bool,
        scopes: &[&str],
    ) -> String {
        #[derive(serde::Serialize)]
        struct Claims<'a> {
            sub: &'a str,
            tenant_id: &'a str,
            admin: bool,
            #[serde(skip_serializing_if = "Vec::is_empty")]
            scopes: Vec<String>,
            exp: usize,
        }
        let key = jsonwebtoken::EncodingKey::from_rsa_pem(JWT_TEST_PRIVATE_PEM.as_bytes()).unwrap();
        jsonwebtoken::encode(
            &jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256),
            &Claims {
                sub: subject,
                tenant_id,
                admin,
                scopes: scopes.iter().map(|scope| scope.to_string()).collect(),
                exp: (Utc::now() + TimeDelta::try_hours(1).unwrap()).timestamp() as usize,
            },
            &key,
        )
        .unwrap()
    }

    async fn send_request(app: &Router, request: Request<Body>) -> axum::response::Response {
        app.clone().oneshot(request).await.unwrap()
    }

    async fn get_request(app: &Router, path: &str) -> axum::response::Response {
        send_request(
            app,
            Request::get(path).body(Body::empty()).expect("GET request"),
        )
        .await
    }

    async fn get_bearer(app: &Router, path: &str, token: &str) -> axum::response::Response {
        send_request(
            app,
            Request::get(path)
                .header(AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::empty())
                .expect("GET request"),
        )
        .await
    }

    async fn post_json(
        app: &Router,
        path: &str,
        token: &str,
        body: &serde_json::Value,
    ) -> axum::response::Response {
        send_request(
            app,
            Request::post(path)
                .header(AUTHORIZATION, format!("Bearer {token}"))
                .header(CONTENT_TYPE, "application/json")
                .body(Body::from(body.to_string()))
                .expect("POST request"),
        )
        .await
    }

    async fn post_form(app: &Router, path: &str, form: &str) -> axum::response::Response {
        send_request(
            app,
            Request::post(path)
                .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(form.to_string()))
                .expect("POST request"),
        )
        .await
    }

    async fn response_json(response: axum::response::Response) -> serde_json::Value {
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap_or_default();
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null)
    }

    fn response_header(response: &axum::response::Response, name: &str) -> String {
        response
            .headers()
            .get(name)
            .expect(name)
            .to_str()
            .expect("header value")
            .to_string()
    }

    /// First decoded occurrence of `name` in a URL's query string.
    fn query_param(url: &str, name: &str) -> Option<String> {
        let query = url.split_once('?')?.1;
        for pair in query.split('&') {
            let (key, value) = pair.split_once('=')?;
            if key == name {
                return urlencoding::decode(value).ok().map(|v| v.to_string());
            }
        }
        None
    }

    /// The urlencoded ACS POST body carrying a base64 SAMLResponse.
    fn saml_acs_form(signed_document: &str, relay_state: &str) -> String {
        use base64::Engine;
        format!(
            "SAMLResponse={}&RelayState={}",
            urlencoding::encode(
                &base64::engine::general_purpose::STANDARD.encode(signed_document.as_bytes())
            ),
            urlencoding::encode(relay_state),
        )
    }

    /// The AuthnRequest `ID` attribute from a decoded SAMLRequest document —
    /// the request id the login initiation staged for InResponseTo
    /// correlation (audit P2-6).
    fn authn_request_id(saml_request: &str) -> String {
        let marker = "ID=\"";
        let start = saml_request.find(marker).expect("AuthnRequest ID") + marker.len();
        let end = saml_request[start..].find('"').expect("closing quote") + start;
        saml_request[start..end].to_string()
    }

    /// Stage one SP-initiated AuthnRequest for InResponseTo correlation
    /// (audit P2-6) — the E2E equivalent of the staging `GET
    /// /sso/login/saml/:domain` performs, without minting a new request id.
    async fn stage_saml_authn_request(
        state: &AppState,
        tenant: &str,
        domain: &str,
        request_id: &str,
    ) {
        sqlx::query(
            "INSERT INTO ent_saml_authn_requests (request_id, tenant_id, domain, expires_at)
             VALUES ($1, $2, $3, NOW() + INTERVAL '10 minutes')",
        )
        .bind(request_id)
        .bind(tenant)
        .bind(domain)
        .execute(&state.db)
        .await
        .expect("stage AuthnRequest");
    }

    fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
        haystack
            .windows(needle.len())
            .position(|window| window == needle)
    }

    /// A minimal but REAL OpenID Provider on 127.0.0.1: discovery metadata, a
    /// JWKS holding the test RSA key, and a token endpoint that exchanges any
    /// code for an RS256 id_token signed by that key (or a tampered one when
    /// the `tamper` flag is set). Records every form field of the latest
    /// token request so tests can assert the code + PKCE exchange.
    struct MockOidcIdp {
        issuer: String,
        recorded_form: Arc<std::sync::Mutex<Vec<(String, String)>>>,
        tamper: Arc<std::sync::atomic::AtomicBool>,
    }

    impl MockOidcIdp {
        async fn spawn(
            signing_key: &idp::RsaPrivateKey,
            client_id: &str,
            identity_email: &str,
        ) -> Self {
            use base64::Engine;
            use tokio::io::{AsyncReadExt, AsyncWriteExt};

            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let issuer = format!("http://{}", listener.local_addr().unwrap());

            let jwk_n =
                base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(signing_key.modulus_be());
            let jwk_e =
                base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(signing_key.exponent_be());
            let jwks = serde_json::json!({
                "keys": [{
                    "kty": "RSA",
                    "kid": OIDC_TEST_KID,
                    "use": "sig",
                    "alg": "RS256",
                    "n": jwk_n,
                    "e": jwk_e,
                }]
            })
            .to_string();
            let discovery = serde_json::json!({
                "issuer": issuer,
                // Audit P3-10: a NONSTANDARD authorization endpoint — the
                // flow must take the authorize URL from discovery, never
                // from `{issuer}/authorize`.
                "authorization_endpoint": format!("{issuer}/oidc-auth"),
                "token_endpoint": format!("{issuer}/token"),
                "jwks_uri": format!("{issuer}/jwks.json"),
            })
            .to_string();
            let claims = serde_json::json!({
                "iss": issuer,
                "sub": "oidc-user-routes-1",
                "email": identity_email,
                "name": "Riley Routes",
                "groups": ["engineering", "admins"],
                "aud": client_id,
                "iat": Utc::now().timestamp(),
                "exp": (Utc::now() + TimeDelta::try_minutes(5).unwrap()).timestamp(),
            });
            let valid_id_token = idp::sign_rs256_jwt(OIDC_TEST_KID, &claims, signing_key);
            // A tampered variant: flip the first signature character in place
            // (same length, still parses, fails RS256 verification).
            let mut tampered_id_token = valid_id_token.clone();
            let sig_start = tampered_id_token.rfind('.').unwrap() + 1;
            let first = tampered_id_token.as_bytes()[sig_start] as char;
            let replacement = if first == 'A' { 'B' } else { 'A' };
            tampered_id_token.replace_range(sig_start..sig_start + 1, &replacement.to_string());

            let recorded_form: Arc<std::sync::Mutex<Vec<(String, String)>>> = Arc::default();
            let tamper = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let recorded_task = recorded_form.clone();
            let tamper_task = tamper.clone();
            tokio::spawn(async move {
                loop {
                    let (mut socket, _) = match listener.accept().await {
                        Ok(accepted) => accepted,
                        Err(_) => break,
                    };
                    // Read one HTTP/1.1 request: head, then Content-Length body.
                    let mut buffer: Vec<u8> = Vec::new();
                    let mut chunk = [0u8; 4096];
                    let head_end = loop {
                        match socket.read(&mut chunk).await {
                            Ok(0) | Err(_) => break buffer.len(),
                            Ok(read) => {
                                buffer.extend_from_slice(&chunk[..read]);
                                if let Some(position) = find_subsequence(&buffer, b"\r\n\r\n") {
                                    break position + 4;
                                }
                            }
                        }
                    };
                    let head = String::from_utf8_lossy(&buffer[..head_end]).to_string();
                    let content_length = head
                        .lines()
                        .find_map(|line| {
                            let (name, value) = line.split_once(':')?;
                            if !name.eq_ignore_ascii_case("content-length") {
                                return None;
                            }
                            value.trim().parse::<usize>().ok()
                        })
                        .unwrap_or(0);
                    while buffer.len() < head_end + content_length {
                        match socket.read(&mut chunk).await {
                            Ok(0) | Err(_) => break,
                            Ok(read) => buffer.extend_from_slice(&chunk[..read]),
                        }
                    }
                    let request_line = head.lines().next().unwrap_or_default().to_string();
                    let path = request_line
                        .split_whitespace()
                        .nth(1)
                        .unwrap_or_default()
                        .to_string();
                    let body = String::from_utf8_lossy(&buffer[head_end..]).to_string();

                    let (status, payload) = if path.starts_with("/.well-known/openid-configuration")
                    {
                        ("200 OK", discovery.clone())
                    } else if path.starts_with("/jwks.json") {
                        ("200 OK", jwks.clone())
                    } else if path.starts_with("/token") {
                        let pairs: Vec<(String, String)> = body
                            .split('&')
                            .filter_map(|pair| {
                                let (key, value) = pair.split_once('=')?;
                                Some((
                                    key.to_string(),
                                    urlencoding::decode(value).ok()?.to_string(),
                                ))
                            })
                            .collect();
                        *recorded_task.lock().unwrap() = pairs;
                        let id_token = if tamper_task.load(std::sync::atomic::Ordering::Relaxed) {
                            tampered_id_token.clone()
                        } else {
                            valid_id_token.clone()
                        };
                        (
                            "200 OK",
                            serde_json::json!({
                                "access_token": "mock-access-token",
                                "token_type": "Bearer",
                                "expires_in": 3600,
                                "id_token": id_token,
                            })
                            .to_string(),
                        )
                    } else {
                        (
                            "404 Not Found",
                            serde_json::json!({"error": "not found"}).to_string(),
                        )
                    };

                    let response = format!(
                        "HTTP/1.1 {status}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{payload}",
                        payload.len()
                    );
                    let _ = socket.write_all(response.as_bytes()).await;
                    let _ = socket.flush().await;
                }
            });
            Self {
                issuer,
                recorded_form,
                tamper,
            }
        }

        fn token_request_form(&self) -> Vec<(String, String)> {
            self.recorded_form.lock().unwrap().clone()
        }
    }

    /// Dogfood F6: the configurator must accept the session a real owner
    /// login produces — `scopes = ["*"]`, NO `admin` claim. The old gate
    /// checked only `admin` (which no minter emits) and answered 403 for
    /// every real session, so SSO configuration (and its issuer validation)
    /// was unreachable.
    #[tokio::test]
    async fn sso_configure_accepts_an_owner_session_with_wildcard_scopes() {
        let (app, state) = provision_sso_router("owner_scope").await;
        let tenant = sso_flow_tenant("owner_scope");
        let domain = "owner-scope.routes.example.com";
        seed_sso_flow_tenant(&state, &tenant).await;

        // A real owner session: non-admin claim, wildcard scopes (exactly
        // `canonical_scopes_for_role("owner")`).
        let owner = mint_sso_owner_token(&tenant, "routes-owner");
        let configure = serde_json::json!({
            "tenant_id": tenant,
            "provider_type": "saml",
            "domain": domain,
            "enabled": true,
            "idp_entity_id": "https://idp.routes-owner.example.com/metadata",
            "sso_url": "https://idp.routes-owner.example.com/sso",
            "certificate": IDP_CERTIFICATE_PEM,
            "enforce_sso": false,
            "session_duration_hours": 8,
        });
        let response = post_json(&app, "/sso/configure", &owner, &configure).await;
        assert_eq!(
            response.status(),
            StatusCode::OK,
            "an owner session (scopes [\"*\"], no admin claim) must configure SSO"
        );
        let body = response_json(response).await;
        assert_eq!(body["domain"], domain, "{body}");

        // A member session (scoped authorities, no wildcard) is still
        // refused — the gate did not widen past the operator class.
        let member = mint_sso_token_with_scopes(
            &tenant,
            "routes-viewer",
            false,
            &["messages:read", "domains:read"],
        );
        let refused = post_json(&app, "/sso/configure", &member, &configure).await;
        assert_eq!(refused.status(), StatusCode::FORBIDDEN);
    }

    /// The unit-level contract: admin claim, wildcard scope or nothing.
    #[test]
    fn require_admin_accepts_the_operator_wildcard_scope() {
        fn ctx(is_admin: bool, scopes: &[&str]) -> AuthContext {
            AuthContext {
                user_id: "u".into(),
                tenant_id: "t".into(),
                is_admin,
                scopes: scopes.iter().map(|s| s.to_string()).collect(),
            }
        }
        assert!(require_admin(&ctx(true, &[])).is_none());
        assert!(
            require_admin(&ctx(false, &["*"])).is_none(),
            "the owner/admin scope set is the real operator credential"
        );
        assert!(require_admin(&ctx(false, &["messages:read"])).is_some());
        assert!(require_admin(&ctx(false, &[])).is_some());
    }

    #[tokio::test]
    async fn saml_sso_completes_end_to_end_through_the_router() {
        let (app, state) = provision_sso_router("saml_e2e").await;
        let tag = "saml_e2e";
        let tenant = sso_flow_tenant(tag);
        let domain = "saml-e2e.routes.example.com";
        // The IDP's entity id — what we ACCEPT on responses, never what we
        // send in the AuthnRequest Issuer (audit P2-4).
        let idp_entity_id = "https://idp.routes-saml.example.com/metadata";
        let sso_url = "https://idp.routes-saml.example.com/sso";
        let acs_url = state.config.sso.saml.acs_url.clone();
        let sp_entity_id = state.config.sso.saml.entity_id.clone();
        let admin = mint_sso_admin_token(&tenant, "routes-saml-admin");
        seed_sso_flow_tenant(&state, &tenant).await;

        // Configure the tenant IdP THROUGH the router (admin JWT → handler).
        let configure = serde_json::json!({
            "tenant_id": tenant,
            "provider_type": "saml",
            "domain": domain,
            "enabled": true,
            "idp_entity_id": idp_entity_id,
            "sso_url": sso_url,
            "certificate": IDP_CERTIFICATE_PEM,
            "enforce_sso": true,
            "session_duration_hours": 4,
        });
        let response = post_json(&app, "/sso/configure", &admin, &configure).await;
        assert_eq!(response.status(), StatusCode::OK);

        // 1. Login initiation → 302 to the IdP with AuthnRequest + RelayState.
        let response = get_request(&app, &format!("/sso/login/saml/{domain}")).await;
        assert_eq!(response.status(), StatusCode::FOUND);
        let location = response_header(&response, "location");
        assert!(
            location.starts_with(&format!("{sso_url}?SAMLRequest=")),
            "unexpected redirect: {location}"
        );
        let relay_state = query_param(&location, "RelayState").expect("RelayState");
        assert_eq!(
            relay_state, domain,
            "RelayState carries the tenant domain so the domain-less ACS can resolve it"
        );
        let saml_request = {
            use base64::Engine;
            String::from_utf8(
                base64::engine::general_purpose::STANDARD
                    .decode(
                        query_param(&location, "SAMLRequest")
                            .expect("SAMLRequest")
                            .as_bytes(),
                    )
                    .unwrap(),
            )
            .unwrap()
        };
        assert!(saml_request.contains("AuthnRequest"), "{saml_request}");
        // Audit P2-4: the AuthnRequest Issuer names APEXMAIL (the SP); the
        // IdP's entity id never appears in it.
        assert!(
            saml_request.contains(&sp_entity_id),
            "the SP entity id is the AuthnRequest Issuer: {saml_request}"
        );
        assert!(
            !saml_request.contains(idp_entity_id),
            "the IdP entity id must NOT appear in the AuthnRequest: {saml_request}"
        );
        assert!(saml_request.contains(&acs_url), "{saml_request}");
        let request_id = authn_request_id(&saml_request);
        assert!(request_id.starts_with("_saml_"), "{request_id}");
        // The initiation staged it durably (audit P2-6).
        let staged: Option<String> = sqlx::query_scalar(
            "SELECT tenant_id FROM ent_saml_authn_requests WHERE request_id = $1",
        )
        .bind(&request_id)
        .fetch_optional(&state.db)
        .await
        .expect("staged AuthnRequest");
        assert_eq!(staged.as_deref(), Some(tenant.as_str()));

        // 2. A valid, genuinely signed response → session issued. The
        //    InResponseTo names the staged request from step 1. The asserted
        //    email is IN the configured SSO domain (audit F2: the ACS applies
        //    the OIDC email-domain assurance, so an out-of-domain assertion
        //    is refused).
        let asserted_email = "alice.smith@saml-e2e.routes.example.com";
        let mut signed = SamlFixture::valid(idp_entity_id, &sp_entity_id, &acs_url);
        signed.in_response_to = Some(request_id.clone());
        signed.name_id = asserted_email.to_string();
        signed.attributes = vec![
            ("email".to_string(), asserted_email.to_string()),
            ("group".to_string(), "engineering".to_string()),
        ];
        let form = saml_acs_form(&signed.render(sso_flow_idp_key()), domain);
        let response = post_form(&app, &format!("/sso/acs/{domain}"), &form).await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = response_json(response).await;
        assert_eq!(body["is_new_user"], true, "{body}");
        assert_eq!(body["session"]["email"], asserted_email);
        assert_eq!(
            body["session"]["groups"],
            serde_json::json!(["engineering"])
        );
        let session_token = body["session"]["session_token"]
            .as_str()
            .expect("session token")
            .to_string();
        assert!(!session_token.is_empty());

        // 3. The session validates through /sso/validate.
        let response = get_bearer(&app, "/sso/validate", &session_token).await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = response_json(response).await;
        assert_eq!(body["email"], asserted_email);

        // 4. The same assertion replayed is refused (the correlation stage
        //    is re-inserted so the failure demonstrably lands on the replay
        //    guard, not the one-shot correlation gate).
        stage_saml_authn_request(&state, &tenant, domain, &request_id).await;
        let response = post_form(&app, &format!("/sso/acs/{domain}"), &form).await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let body = response_json(response).await;
        assert!(
            body["error"]
                .as_str()
                .unwrap_or_default()
                .contains("replay rejected"),
            "{body}"
        );

        // 4b. Audit F2 (verifier repair): a SIGNED assertion claiming an
        //     OUT-OF-DOMAIN email — the exact JIT account-linking hijack the
        //     finding describes (`victim@anydomain.com` binds to a same-
        //     tenant local account and inherits its role) — is refused with
        //     401 AFTER the signature validates. Pins the ACS's email gate
        //     wiring end-to-end.
        let mut hijack = SamlFixture::valid(idp_entity_id, &sp_entity_id, &acs_url);
        hijack.in_response_to = Some(format!("_saml_{}", Uuid::new_v4()));
        hijack.name_id = "victim@anydomain.com".to_string();
        hijack.attributes = vec![("email".to_string(), "victim@anydomain.com".to_string())];
        stage_saml_authn_request(
            &state,
            &tenant,
            domain,
            hijack
                .in_response_to
                .as_deref()
                .expect("fixture InResponseTo"),
        )
        .await;
        let response = post_form(
            &app,
            &format!("/sso/acs/{domain}"),
            &saml_acs_form(&hijack.render(sso_flow_idp_key()), domain),
        )
        .await;
        assert_eq!(
            response.status(),
            StatusCode::UNAUTHORIZED,
            "a signed out-of-domain assertion must be refused"
        );
        let body = response_json(response).await;
        assert!(
            body["error"]
                .as_str()
                .unwrap_or_default()
                .contains("does not belong to the configured SSO domain"),
            "{body}"
        );

        // 4c. An assertion with NO email attribute (opaque NameID only) is
        //     refused too — the NameID is an external_user_id, never an
        //     email, and must not fall back into `users.email`.
        let mut opaque = SamlFixture::valid(idp_entity_id, &sp_entity_id, &acs_url);
        opaque.in_response_to = Some(format!("_saml_{}", Uuid::new_v4()));
        opaque.name_id = "opaque-subject-id-9f2c".to_string();
        opaque.attributes = vec![];
        stage_saml_authn_request(
            &state,
            &tenant,
            domain,
            opaque
                .in_response_to
                .as_deref()
                .expect("fixture InResponseTo"),
        )
        .await;
        let response = post_form(
            &app,
            &format!("/sso/acs/{domain}"),
            &saml_acs_form(&opaque.render(sso_flow_idp_key()), domain),
        )
        .await;
        assert_eq!(
            response.status(),
            StatusCode::UNAUTHORIZED,
            "an opaque NameID must never be used as an email"
        );
        let body = response_json(response).await;
        assert!(
            body["error"]
                .as_str()
                .unwrap_or_default()
                .contains("must carry a valid email attribute"),
            "{body}"
        );

        // 5. A tampered (digest-flipped) response is refused at the signature gate.
        let mut tamperable = SamlFixture::valid(idp_entity_id, &sp_entity_id, &acs_url);
        // Audit F2: the untouched twin must still complete (200), so its
        // asserted email is IN the configured SSO domain — the tamper arm
        // itself is refused at the signature gate before any email check.
        tamperable.name_id = asserted_email.to_string();
        tamperable.attributes = vec![("email".to_string(), asserted_email.to_string())];
        let signed_document = tamperable.render(sso_flow_idp_key());
        let marker = "<ds:DigestValue>";
        let position = signed_document
            .find(marker)
            .expect("signed doc has a digest");
        let digest_start = position + marker.len();
        let mut tampered = signed_document.clone();
        let original_char = tampered.as_bytes()[digest_start] as char;
        let replacement = if original_char == 'A' { 'B' } else { 'A' };
        tampered.replace_range(digest_start..digest_start + 1, &replacement.to_string());
        let response = post_form(
            &app,
            &format!("/sso/acs/{domain}"),
            &saml_acs_form(&tampered, domain),
        )
        .await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let body = response_json(response).await;
        assert!(
            body["error"]
                .as_str()
                .unwrap_or_default()
                .contains("signature verification failed"),
            "{body}"
        );
        // The untouched document still validates (the gate is exact) — it
        // correlates against a fresh stage of the same request id.
        stage_saml_authn_request(
            &state,
            &tenant,
            domain,
            tamperable
                .in_response_to
                .as_deref()
                .expect("fixture InResponseTo"),
        )
        .await;
        let response = post_form(
            &app,
            &format!("/sso/acs/{domain}"),
            &saml_acs_form(&signed_document, domain),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);

        // 6. Wrong tenant: a response signed for tenant A's entity id posted
        //    to tenant B's ACS is refused on the Issuer check.
        let tenant_b = sso_flow_tenant(tag);
        let domain_b = "saml-e2e-b.routes.example.com";
        seed_sso_flow_tenant(&state, &tenant_b).await;
        let configure_b = serde_json::json!({
            "tenant_id": tenant_b,
            "provider_type": "saml",
            "domain": domain_b,
            "enabled": true,
            "idp_entity_id": "https://idp.other.example.com/metadata",
            "sso_url": sso_url,
            "certificate": IDP_CERTIFICATE_PEM,
        });
        let admin_b = mint_sso_admin_token(&tenant_b, "routes-saml-admin-b");
        let response = post_json(&app, "/sso/configure", &admin_b, &configure_b).await;
        assert_eq!(response.status(), StatusCode::OK);
        let mut foreign = SamlFixture::valid(idp_entity_id, &sp_entity_id, &acs_url);
        foreign.in_response_to = Some(format!("_saml_{}", Uuid::new_v4()));
        stage_saml_authn_request(
            &state,
            &tenant_b,
            domain_b,
            foreign
                .in_response_to
                .as_deref()
                .expect("fixture InResponseTo"),
        )
        .await;
        let response = post_form(
            &app,
            &format!("/sso/acs/{domain_b}"),
            &saml_acs_form(&foreign.render(sso_flow_idp_key()), domain_b),
        )
        .await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let body = response_json(response).await;
        assert!(
            body["error"]
                .as_str()
                .unwrap_or_default()
                .contains("Issuer does not match"),
            "{body}"
        );

        // 7. An expired assertion is refused.
        let mut expired = SamlFixture::valid(idp_entity_id, &sp_entity_id, &acs_url);
        expired.not_on_or_after = Some(Utc::now() - TimeDelta::try_minutes(30).unwrap());
        expired.not_before = None;
        stage_saml_authn_request(
            &state,
            &tenant,
            domain,
            expired
                .in_response_to
                .as_deref()
                .expect("fixture InResponseTo"),
        )
        .await;
        let response = post_form(
            &app,
            &format!("/sso/acs/{domain}"),
            &saml_acs_form(&expired.render(sso_flow_idp_key()), domain),
        )
        .await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let body = response_json(response).await;
        assert!(
            body["error"]
                .as_str()
                .unwrap_or_default()
                .contains("has expired"),
            "{body}"
        );

        // 8. An unsigned assertion is refused.
        let mut unsigned = SamlFixture::valid(idp_entity_id, &sp_entity_id, &acs_url);
        unsigned.include_signature = false;
        let response = post_form(
            &app,
            &format!("/sso/acs/{domain}"),
            &saml_acs_form(&unsigned.render(sso_flow_idp_key()), domain),
        )
        .await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        // 9. Unknown domains are refused, not redirected.
        let response = get_request(&app, "/sso/login/saml/no-such.routes.example.com").await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        let response = post_form(
            &app,
            "/sso/acs/no-such.routes.example.com",
            &saml_acs_form(&signed.render(sso_flow_idp_key()), domain),
        )
        .await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        // 10. The domain-less ACS (the SAML_ACS_URL default shape) resolves
        //     the tenant domain from RelayState and issues a session.
        let mut domain_less = SamlFixture::valid(idp_entity_id, &sp_entity_id, &acs_url);
        domain_less.in_response_to = Some(format!("_saml_{}", Uuid::new_v4()));
        // Audit F2: the asserted email must be in the configured SSO domain
        // for the ACS to link the session (same bar as step 2).
        domain_less.name_id = asserted_email.to_string();
        domain_less.attributes = vec![("email".to_string(), asserted_email.to_string())];
        stage_saml_authn_request(
            &state,
            &tenant,
            domain,
            domain_less
                .in_response_to
                .as_deref()
                .expect("fixture InResponseTo"),
        )
        .await;
        let response = post_form(
            &app,
            "/sso/acs",
            &saml_acs_form(&domain_less.render(sso_flow_idp_key()), domain),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = response_json(response).await;
        assert_eq!(body["is_new_user"], false, "returning user, {body}");
        // And the RelayState-less POST is an honest 400.
        let response = post_form(
            &app,
            "/sso/acs",
            &format!("SAMLResponse={}", urlencoding::encode("e30=")),
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        // 11. Expiry + cleanup: sessions stop validating and are swept.
        sqlx::query("UPDATE ent_sso_sessions SET expires_at = NOW() - INTERVAL '1 minute' WHERE tenant_id = $1")
            .bind(&tenant)
            .execute(&state.db)
            .await
            .expect("expire sessions");
        let response = get_bearer(&app, "/sso/validate", &session_token).await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let response = post_json(&app, "/sso/cleanup", &admin, &serde_json::json!({})).await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = response_json(response).await;
        let cleaned = body["cleaned"].as_u64().expect("cleaned count");
        assert!(cleaned >= 1, "the expired sessions were swept: {body}");
    }

    #[tokio::test]
    async fn oidc_sso_completes_end_to_end_through_the_router() {
        let (app, state) = provision_sso_router("oidc_e2e").await;
        let tag = "oidc_e2e";
        let tenant = sso_flow_tenant(tag);
        let domain = "oidc-e2e.routes.example.com";
        let client_id = "routes-oidc-client";
        let client_secret = "routes-oidc-secret";
        let admin = mint_sso_admin_token(&tenant, "routes-oidc-admin");
        seed_sso_flow_tenant(&state, &tenant).await;

        let mock = MockOidcIdp::spawn(
            sso_flow_idp_key(),
            client_id,
            "riley@oidc-e2e.routes.example.com",
        )
        .await;

        // Configure the tenant IdP THROUGH the router.
        let configure = serde_json::json!({
            "tenant_id": tenant,
            "provider_type": "oidc",
            "domain": domain,
            "enabled": true,
            "oidc_client_id": client_id,
            "oidc_client_secret": client_secret,
            "oidc_issuer": mock.issuer,
            "enforce_sso": true,
        });
        let response = post_json(&app, "/sso/configure", &admin, &configure).await;
        assert_eq!(response.status(), StatusCode::OK);

        // 1. Login initiation → 302 to the IdP's DISCOVERED authorization
        //    endpoint (nonstandard on the mock — audit P3-10).
        let response = get_request(&app, &format!("/sso/login/oidc/{domain}")).await;
        assert_eq!(response.status(), StatusCode::FOUND);
        let location = response_header(&response, "location");
        assert!(
            location.starts_with(&format!("{}/oidc-auth?", mock.issuer)),
            "unexpected redirect: {location}"
        );
        for expected in [
            "client_id=routes-oidc-client",
            "response_type=code",
            "code_challenge_method=S256",
        ] {
            assert!(
                location.contains(expected),
                "missing {expected}: {location}"
            );
        }
        let login_state = query_param(&location, "state").expect("state");
        let code_challenge = query_param(&location, "code_challenge").expect("code_challenge");
        assert!(!login_state.is_empty() && !code_challenge.is_empty());

        // 2. State + PKCE verifier persisted (durable fallback), and the
        //    challenge in the redirect is exactly sha256(verifier).
        let (verifier, state_domain, state_tenant): (String, String, String) = sqlx::query_as(
            "SELECT code_verifier, domain, tenant_id FROM sso_oidc_state WHERE state = $1",
        )
        .bind(&login_state)
        .fetch_one(&state.db)
        .await
        .expect("staged OIDC state");
        assert_eq!(state_domain, domain);
        assert_eq!(state_tenant, tenant);
        assert!(!verifier.is_empty());
        {
            use base64::Engine;
            use sha2::Digest;
            let mut hasher = sha2::Sha256::new();
            hasher.update(verifier.as_bytes());
            assert_eq!(
                base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(hasher.finalize()),
                code_challenge,
                "the persisted verifier must match the advertised S256 challenge"
            );
        }

        // 3. Callback → the code is exchanged with the verifier and a session
        //    is issued from the validated id_token.
        let callback =
            format!("/sso/callback/oidc/{domain}?code=routes-code-1&state={login_state}");
        let response = get_request(&app, &callback).await;
        let callback_status = response.status();
        let body = response_json(response).await;
        assert_eq!(
            callback_status,
            StatusCode::OK,
            "callback status with body: {body}"
        );
        assert_eq!(body["is_new_user"], true, "callback result: {body}");
        assert_eq!(
            body["session"]["email"],
            "riley@oidc-e2e.routes.example.com"
        );
        assert_eq!(body["session"]["display_name"], "Riley Routes");
        assert_eq!(
            body["session"]["groups"],
            serde_json::json!(["engineering", "admins"])
        );
        let session_token = body["session"]["session_token"]
            .as_str()
            .expect("session token")
            .to_string();

        // The mock saw a proper PKCE code exchange, secret included.
        let form = mock.token_request_form();
        let form_pair = |name: &str| {
            form.iter()
                .find(|(key, _)| key == name)
                .map(|(_, value)| value.clone())
        };
        assert_eq!(
            form_pair("grant_type").as_deref(),
            Some("authorization_code")
        );
        assert_eq!(form_pair("code").as_deref(), Some("routes-code-1"));
        assert_eq!(
            form_pair("code_verifier").as_deref(),
            Some(verifier.as_str())
        );
        assert_eq!(form_pair("client_id").as_deref(), Some(client_id));
        assert_eq!(form_pair("client_secret").as_deref(), Some(client_secret));

        // 4. The session validates through /sso/validate.
        let response = get_bearer(&app, "/sso/validate", &session_token).await;
        assert_eq!(response.status(), StatusCode::OK);

        // 5. The state is single-use: the same callback replays to a refusal.
        let response = get_request(&app, &callback).await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let body = response_json(response).await;
        assert!(
            body["error"]
                .as_str()
                .unwrap_or_default()
                .contains("invalid, expired, or already used"),
            "{body}"
        );

        // 6. A state minted for one domain is refused on another domain's callback.
        let response = get_request(&app, &format!("/sso/login/oidc/{domain}")).await;
        assert_eq!(response.status(), StatusCode::FOUND);
        let location = response_header(&response, "location");
        let second_state = query_param(&location, "state").expect("state");
        let response = get_request(
            &app,
            &format!(
                "/sso/callback/oidc/other.routes.example.com?code=routes-code-2&state={second_state}"
            ),
        )
        .await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let body = response_json(response).await;
        assert!(
            body["error"]
                .as_str()
                .unwrap_or_default()
                .contains("does not belong to this domain"),
            "{body}"
        );

        // 7. A tampered id_token (signature flipped) is refused.
        mock.tamper
            .store(true, std::sync::atomic::Ordering::Relaxed);
        let response = get_request(&app, &format!("/sso/login/oidc/{domain}")).await;
        assert_eq!(response.status(), StatusCode::FOUND);
        let location = response_header(&response, "location");
        let third_state = query_param(&location, "state").expect("state");
        let response = get_request(
            &app,
            &format!("/sso/callback/oidc/{domain}?code=routes-code-3&state={third_state}"),
        )
        .await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let body = response_json(response).await;
        assert!(
            body["error"]
                .as_str()
                .unwrap_or_default()
                .contains("id_token validation failed"),
            "{body}"
        );
        mock.tamper
            .store(false, std::sync::atomic::Ordering::Relaxed);

        // 8. A bogus state is refused before any network call.
        let response = get_request(
            &app,
            &format!("/sso/callback/oidc/{domain}?code=routes-code-4&state=bogus-state"),
        )
        .await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        // 9. Missing code or state are honest 400s.
        let response = get_request(&app, &format!("/sso/callback/oidc/{domain}")).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let response = get_request(&app, &format!("/sso/callback/oidc/{domain}?state=x")).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        // 10. Unconfigured domains refuse login initiation with 404.
        let response = get_request(&app, "/sso/login/oidc/no-such.routes.example.com").await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    // ═════════════════════════════════════════════════════════════════════
    // Audit F3: data-access approval guards — separation of duties, the
    // `AND status = 'pending'` state guard, digest-at-rest and the one-time
    // raw-token handoff.
    // ═════════════════════════════════════════════════════════════════════

    /// Soft-skip variant of [`provision_sso_router`] for the data-access
    /// guards: identical env + JWT wiring, but `None` (skip) when
    /// TEST_DATABASE_URL is not configured.
    async fn provision_data_access_router(tag: &str) -> Option<(Router, Arc<AppState>)> {
        if std::env::var("SSO_ENCRYPTION_KEY").is_err() {
            std::env::set_var("SSO_ENCRYPTION_KEY", "sso-routes-coverage-key-0123456789");
        }
        if std::env::var("LOG_STREAM_ENCRYPTION_KEY").is_err() {
            std::env::set_var(
                "LOG_STREAM_ENCRYPTION_KEY",
                "log-stream-routes-coverage-key-0123456789",
            );
        }
        let pool =
            migrator::test_support::fresh_canonical_pool(tag, &format!("routes_data_access_{tag}"))
                .await
                .expect("provision canonical pool")?;
        let mut config = Config::from_env().unwrap();
        config.jwt_public_key_pem = JWT_TEST_PUBLIC_PEM.to_string();
        config.jwt_audience = None;
        config.jwt_issuer = None;
        let recorder = PrometheusBuilder::new().build_recorder();
        let state = Arc::new(AppState::new(pool, config, recorder.handle()));
        Some((router(state.clone()), state))
    }

    /// Seed one pending data-access request row and return its id.
    async fn seed_pending_data_access(state: &AppState, tenant: &str, requester_id: &str) -> Uuid {
        let id: Uuid = sqlx::query_scalar(
            "INSERT INTO ent_data_access_requests
                 (tenant_id, type, status, requester_id, requester_email)
             VALUES ($1, 'data_access', 'pending', $2, $3) RETURNING id",
        )
        .bind(tenant)
        .bind(requester_id)
        .bind(format!("{requester_id}@data-access.test"))
        .fetch_one(&state.db)
        .await
        .expect("seed pending data-access request");
        id
    }

    async fn seed_data_access_tenant(state: &AppState, tenant: &str) {
        sqlx::query(
            "INSERT INTO tenants (id, name, slug, plan, status, settings, metadata, created_at, updated_at)
             VALUES ($1, $2, $3, 'pro', 'active', '{}'::jsonb, '{}'::jsonb, NOW(), NOW())
             ON CONFLICT (id) DO NOTHING",
        )
        .bind(tenant)
        .bind(format!("Data Access Tenant {tenant}"))
        .bind(format!("data-access-{tenant}"))
        .execute(&state.db)
        .await
        .expect("seed data-access tenant");
    }

    fn approve_body() -> serde_json::Value {
        serde_json::json!({ "approved_by": "ignored-by-j-3", "duration_minutes": 60 })
    }

    /// The requester — a plain tenant member — must NOT be able to approve
    /// their own access request (separation of duties). A different member
    /// of the SAME tenant can. An admin self-approval remains the explicit
    /// platform exception.
    #[tokio::test]
    async fn data_access_requester_cannot_self_approve() {
        let Some((app, state)) = provision_data_access_router("sod").await else {
            eprintln!("skipping: set TEST_DATABASE_URL");
            return;
        };
        let tenant = "da-sod-tenant";
        seed_data_access_tenant(&state, tenant).await;

        // The requester self-approving is a 403 — and the row stays pending.
        let request_id = seed_pending_data_access(&state, tenant, "member-self").await;
        let response = post_json(
            &app,
            &format!("/compliance/data-access/{request_id}/approve"),
            &mint_sso_member_token(tenant, "member-self"),
            &approve_body(),
        )
        .await;
        assert_eq!(
            response.status(),
            StatusCode::FORBIDDEN,
            "a requester must never approve their own grant"
        );
        let status: String =
            sqlx::query_scalar("SELECT status FROM ent_data_access_requests WHERE id = $1")
                .bind(request_id)
                .fetch_one(&state.db)
                .await
                .expect("request row");
        assert_eq!(
            status, "pending",
            "a refused self-approval must not mutate the row"
        );

        // A DIFFERENT member of the same tenant approves successfully.
        let other_request = seed_pending_data_access(&state, tenant, "member-a").await;
        let response = post_json(
            &app,
            &format!("/compliance/data-access/{other_request}/approve"),
            &mint_sso_member_token(tenant, "member-b"),
            &approve_body(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = response_json(response).await;
        assert_eq!(body["success"], serde_json::json!(true));
    }

    /// Audit F3 (verifier repair): the STORED requester is the authenticated
    /// filer — the body's `requester_id` is never authoritative. A member who
    /// files through the route claiming `requester_id: "someone-else"` used
    /// to defeat the separation-of-duties comparison (stored requester ≠
    /// approver) and self-approve into a live grant token.
    #[tokio::test]
    async fn forged_body_requester_id_cannot_enable_self_approval() {
        let Some((app, state)) = provision_data_access_router("forge").await else {
            eprintln!("skipping: set TEST_DATABASE_URL");
            return;
        };
        let tenant = "da-forge-tenant";
        seed_data_access_tenant(&state, tenant).await;

        // The member files THROUGH the route, attributing the request to
        // someone else.
        let response = post_json(
            &app,
            "/compliance/data-access",
            &mint_sso_member_token(tenant, "member-forge"),
            &serde_json::json!({
                "tenant_id": tenant,
                "requester_id": "someone-else",
                "requester_email": "member-forge@data-access.test",
                "request_type": "export",
            }),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = response_json(response).await;
        let request_id = body["data"]["id"].as_str().expect("request id").to_string();

        // The stored requester is the token subject, not the forged value.
        let stored: String =
            sqlx::query_scalar("SELECT requester_id FROM ent_data_access_requests WHERE id = $1")
                .bind(Uuid::parse_str(&request_id).unwrap())
                .fetch_one(&state.db)
                .await
                .expect("request row");
        assert_eq!(
            stored, "member-forge",
            "the stored requester must be server-derived from the token"
        );

        // Self-approval under the forged attribution is therefore refused.
        let response = post_json(
            &app,
            &format!("/compliance/data-access/{request_id}/approve"),
            &mint_sso_member_token(tenant, "member-forge"),
            &approve_body(),
        )
        .await;
        assert_eq!(
            response.status(),
            StatusCode::FORBIDDEN,
            "a forged requester_id must not enable self-approval"
        );
    }

    /// Approval stores ONLY the SHA-256 digest at rest; the raw token rides
    /// the approval response exactly once; reads mask it as `ref:{id}`.
    #[tokio::test]
    async fn data_access_approval_stores_digest_and_returns_raw_once() {
        let Some((_app, state)) = provision_data_access_router("digest").await else {
            eprintln!("skipping: set TEST_DATABASE_URL");
            return;
        };
        let tenant = "da-digest-tenant";
        seed_data_access_tenant(&state, tenant).await;
        let request_id = seed_pending_data_access(&state, tenant, "member-d").await;

        // Approve through the service the route delegates to (the route
        // returns this ApiResult verbatim — the raw token is in `data`).
        let result = state
            .compliance
            .approve_data_access(request_id, "member-e", 60)
            .await
            .expect("approval succeeds");
        let raw_token = result
            .data
            .as_ref()
            .and_then(|r| r.access_token.clone())
            .expect("the approval response carries the raw token ONCE");

        // At rest: only the digest — the raw token never touches the row.
        let stored: String =
            sqlx::query_scalar("SELECT access_token FROM ent_data_access_requests WHERE id = $1")
                .bind(request_id)
                .fetch_one(&state.db)
                .await
                .expect("approved row");
        assert_ne!(
            stored, raw_token,
            "the raw grant token must not be stored verbatim"
        );
        use sha2::Digest as _;
        let mut hasher = sha2::Sha256::new();
        hasher.update(raw_token.as_bytes());
        assert_eq!(
            stored,
            hex::encode(hasher.finalize()),
            "the stored value must be the token's SHA-256 digest"
        );

        // Reads mask the digest as a non-guessable grant reference.
        let read_back = state
            .compliance
            .get_data_access_request(request_id)
            .await
            .expect("read succeeds");
        assert_eq!(
            read_back
                .data
                .as_ref()
                .and_then(|r| r.access_token.as_deref()),
            Some(format!("ref:{request_id}")).as_deref(),
            "reads must never surface token material"
        );
    }

    /// The UPDATE carries `AND status = 'pending'`: an already-approved
    /// request cannot be re-approved to mint a fresh token.
    #[tokio::test]
    async fn completed_data_access_request_cannot_be_reapproved() {
        let Some((_app, state)) = provision_data_access_router("reapprove").await else {
            eprintln!("skipping: set TEST_DATABASE_URL");
            return;
        };
        let tenant = "da-reapprove-tenant";
        seed_data_access_tenant(&state, tenant).await;
        let request_id = seed_pending_data_access(&state, tenant, "member-f").await;

        let first = state
            .compliance
            .approve_data_access(request_id, "admin-1", 60)
            .await
            .expect("the first approval succeeds");
        assert!(first.success, "the first approval is the real one");

        let second = state
            .compliance
            .approve_data_access(request_id, "admin-1", 60)
            .await
            .expect("the guard is a clean ApiResult error, not an infrastructure failure");
        assert!(
            !second.success,
            "a second approval of a completed request must be refused"
        );
        assert_eq!(second.code.as_deref(), Some("INVALID_STATE"));
        // The original grant is untouched (same digest, same expiry).
        let stored: String =
            sqlx::query_scalar("SELECT access_token FROM ent_data_access_requests WHERE id = $1")
                .bind(request_id)
                .fetch_one(&state.db)
                .await
                .expect("approved row");
        use sha2::Digest as _;
        let mut hasher = sha2::Sha256::new();
        hasher.update(
            first
                .data
                .as_ref()
                .and_then(|r| r.access_token.clone())
                .expect("first approval carried the raw token")
                .as_bytes(),
        );
        assert_eq!(stored, hex::encode(hasher.finalize()));
    }
}

/// Compile-time-pattern guard for audit F8 (modeled on api-server's
/// `routes/admin/mod.rs` scope scan): the control-plane routes that must
/// carry an explicit scope are enumerated here together with the scope
/// constant their handler is required to declare. A handler that loses its
/// `require_scope` call — or a new control-plane route added without a
/// scope gate — fails this test, so RBAC regressions are caught by
/// `cargo test`, not by a penetration test.
#[cfg(test)]
mod rbac_scope_guards {
    use super::*;

    /// (handler function name, required scope constant) pairs. The scope is
    /// matched literally inside the extracted handler body.
    fn scoped_handlers() -> Vec<(&'static str, &'static str)> {
        vec![
            ("compliance_enable", "SCOPE_COMPLIANCE_WRITE"),
            ("compliance_sign_baa", "SCOPE_COMPLIANCE_WRITE"),
            ("compliance_zero_retention", "SCOPE_COMPLIANCE_WRITE"),
            ("whitelabel_update_config", "SCOPE_WHITELABEL_WRITE"),
            ("log_stream_create", "SCOPE_LOG_STREAMS_WRITE"),
            ("log_stream_update", "SCOPE_LOG_STREAMS_WRITE"),
            ("log_stream_delete", "SCOPE_LOG_STREAMS_WRITE"),
            ("log_stream_pause", "SCOPE_LOG_STREAMS_WRITE"),
            ("log_stream_resume", "SCOPE_LOG_STREAMS_WRITE"),
            ("ip_allocate", "SCOPE_DEDICATED_IPS_WRITE"),
        ]
    }

    /// Extract the body of `async fn <name>` from the routes source.
    fn handler_body(source: &str, handler: &str) -> Option<String> {
        let marker = format!("async fn {handler}(");
        let start = source.find(&marker)? + marker.len();
        let rest = &source[start..];
        // The body extends to the next top-level `async fn ` (handlers are
        // declared back-to-back in this file).
        let end = rest.find("\nasync fn ").unwrap_or(rest.len());
        Some(rest[..end].to_string())
    }

    #[test]
    fn every_control_plane_handler_declares_its_scope() {
        let source = include_str!("routes.rs");
        let mut failures = Vec::new();
        for (handler, scope) in scoped_handlers() {
            let body = handler_body(source, handler)
                .unwrap_or_else(|| panic!("handler {handler} disappeared from routes.rs"));
            if !body.contains(&format!("require_scope(&auth, {scope})")) {
                failures.push(format!("{handler} must require {scope}"));
            }
        }
        assert!(
            failures.is_empty(),
            "control-plane handlers missing scope gates: {failures:?}"
        );
    }

    #[test]
    fn scope_guards_flag_violations() {
        let source = "async fn good() { require_scope(&auth, SCOPE_COMPLIANCE_WRITE) }\nasync fn evil() { verify_tenant_access(&auth, tenant) }";
        assert!(handler_body(source, "good")
            .expect("good body")
            .contains("require_scope(&auth, SCOPE_COMPLIANCE_WRITE)"));
        assert!(!handler_body(source, "evil")
            .expect("evil body")
            .contains("require_scope(&auth,"));
    }

    /// The PHI-decryption oracle (audit F1) must keep its admin gate and its
    /// mandatory audit emission — the scan pattern pins both.
    #[test]
    fn decrypt_field_keeps_admin_gate_and_audit() {
        let source = include_str!("routes.rs");
        let body = handler_body(source, "decrypt_field")
            .expect("decrypt_field handler disappeared from routes.rs");
        assert!(
            body.contains("require_admin(&auth)"),
            "decrypt_field must require the admin claim"
        );
        assert!(
            body.contains("audit_server_action("),
            "decrypt_field must write its mandatory audit entry"
        );
    }

    /// Audit F8 (verifier repair): SSO (re)configuration decides who can log
    /// in to the tenant — it belongs to the admin-only handler class. A
    /// `require_admin` line silently dropped from `sso_configure` fails here.
    #[test]
    fn sso_configure_requires_admin() {
        let source = include_str!("routes.rs");
        let body = handler_body(source, "sso_configure")
            .expect("sso_configure handler disappeared from routes.rs");
        assert!(
            body.contains("require_admin(&auth)"),
            "sso_configure must require the admin claim"
        );
    }

    /// Audit F7: the enterprise service must emit its OWN server-side audit
    /// entries for security-relevant mutations — SSO (re)configuration and
    /// zero-retention enablement at the minimum (both change who can act or
    /// what is purged), plus the other contractual/key-minting actions the
    /// work order names. A handler that loses its `audit_server_action` call
    /// — or its action literal — fails here.
    #[test]
    fn security_mutations_emit_server_side_audit() {
        let source = include_str!("routes.rs");
        for (handler, action) in [
            ("sso_configure", "sso_configure"),
            ("compliance_zero_retention", "zero_retention_enabled"),
            ("compliance_sign_baa", "baa_signed"),
            ("decrypt_field", "decrypt_field"),
            ("sub_account_api_key", "sub_account_api_key_minted"),
            ("contract_sign", "contract_signed"),
            ("dpa_generate_pdf", "dpa_document_generated"),
        ] {
            let body = handler_body(source, handler)
                .unwrap_or_else(|| panic!("handler {handler} disappeared from routes.rs"));
            assert!(
                body.contains("audit_server_action("),
                "{handler} must emit its server-side audit entry"
            );
            assert!(
                body.contains(&format!("\"{action}\"")),
                "{handler} must record the '{action}' action string"
            );
        }
    }

    /// require_scope semantics: the admin claim passes, the exact scope
    /// passes, the wildcard scope passes, anything else is refused.
    #[test]
    fn require_scope_accepts_admin_exact_and_wildcard_only() {
        fn ctx(is_admin: bool, scopes: &[&str]) -> AuthContext {
            AuthContext {
                user_id: "u".into(),
                tenant_id: "t".into(),
                is_admin,
                scopes: scopes.iter().map(|s| s.to_string()).collect(),
            }
        }
        assert!(require_scope(&ctx(true, &[]), SCOPE_COMPLIANCE_WRITE).is_none());
        assert!(require_scope(
            &ctx(false, &[SCOPE_COMPLIANCE_WRITE]),
            SCOPE_COMPLIANCE_WRITE
        )
        .is_none());
        assert!(require_scope(&ctx(false, &["*"]), SCOPE_LOG_STREAMS_WRITE).is_none());
        assert!(require_scope(&ctx(false, &[]), SCOPE_COMPLIANCE_WRITE).is_some());
        assert!(
            require_scope(
                &ctx(false, &[SCOPE_WHITELABEL_WRITE]),
                SCOPE_COMPLIANCE_WRITE
            )
            .is_some(),
            "an unrelated scope must not satisfy the gate"
        );
    }
}
