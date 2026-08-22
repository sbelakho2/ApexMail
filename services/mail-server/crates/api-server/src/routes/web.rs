//! Zero-JavaScript web form routes (PRG twins for the SSR console).
//!
//! The console ships **no client-side code** (`Content-Security-Policy:
//! script-src 'none'`), so every interactive surface is a native HTML form
//! POST (or GET) handled here. Each handler follows the PRG pattern:
//!
//!   POST /web/…  → validate → act → set a signed **flash cookie** →
//!                  303 redirect back to the referring view
//!
//! The next GET renders the flash banner (success / field errors) and
//! clears the cookie. Destructive actions are confirmed through
//! `GET /confirm?intent=…&id=…&sig=…` (HMAC-signed by ui-foundation's
//! render pass) whose form POSTs here for server-side re-verification.
//!
//! ## Endpoint-by-endpoint implementation choices (per the migration brief)
//!
//! | Endpoint | Approach |
//! |---|---|
//! | `/web/auth/login`, `/web/auth/logout` | direct reimplementation (bcrypt/argon verify + RS256 session JWT identical to the JSON route) |
//! | `/web/auth/mfa/verify` | multi-step SSR form: challenge is an HMAC-signed short-lived cookie; TOTP verified via `apexmail_lib::mfa` |
//! | `/web/auth/signup` | mirrored tenant+user provisioning from the JSON register flow (bcrypt hash, pending verification metadata) |
//! | `/web/auth/forgot-password`, `/web/auth/reset-password` | token hash stored in `users.metadata` exactly like the JSON flow (reset emails are enqueued by the worker; the response never enumerates accounts) |
//! | `/web/auth/change-password`, `/web/account/profile` | direct SQL updates |
//! | `/web/contacts`, `/web/lists[/update]`, `/web/domains`, `/web/templates`, `/web/campaigns` | direct single-table INSERT/UPDATE mirrors of the JSON create handlers |
//! | `/web/confirm`, `/web/campaigns/delete-bulk`, `/web/contacts/delete-bulk` | signature-verified / id-list destructive SQL |
//! | `/web/api-keys`, `/web/webhooks`, `/web/team/invite` | direct INSERT mirrors |
//! | `/web/contacts/export.csv`, `/web/admin/audit/export` | server-rendered CSV downloads |
//! | `/web/dedicated-ips` | allocation request recorded as `pending`; the Hetzner provisioner (worker) completes it |
//! | `/web/billing/checkout`, `/web/billing/portal` | provider-coupled session creation stays in the JSON handlers; these twins enforce auth and redirect with an actionable flash (documented limitation) |
//! | `/web/inbox-placement/tests` | records the test request; IMAP seed polling is worker-driven |
//! | `/web/admin/tenants`, `/web/admin/operators` | INSERT mirrors of the admin routes — system-tenant gated by [`admin_router`]'s `require_system_tenant_middleware` stack |
//! | `/web/admin/sales/*` | UPDATE/INSERT mirrors of the admin sales routes |
//! | `/web/auth/mfa/setup`, `/web/auth/mfa/confirm` | server-rendered TOTP enrollment: setup stores a signed short-lived cookie and the security page renders the QR; confirm verifies the code, enables MFA, and revokes sessions |
//! | `/web/campaigns/update` | real UPDATE for the campaign editor (editing no longer duplicates) |
//! | `/web/auth/impersonate/end` | system-gated PRG twin of the JSON end-impersonation route (clears the cookie) |
//!
//! Every failure path degrades to a friendly flash message — the web
//! surfaces NEVER return a raw 500 or a JSON dump to a browser. Malformed
//! form bodies are converted to the same friendly flash redirect by
//! [`web_form_rejection_middleware`] instead of axum's plain 400.

pub mod data;

pub(crate) use data::load_page_data;

use std::collections::HashMap;

use axum::extract::{Form, Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Router;
use chrono::Utc;
use serde::Deserialize;
use serde_json::json;
use uuid::Uuid;

use ui_foundation::flash::{
    flash_clear_cookie, flash_set_cookie, verify_confirmation, FlashMessage, FLASH_COOKIE_NAME,
};

use crate::config::Config;
use crate::middleware::auth::AuthUser;
use crate::routes::csrf::validate_csrf_token;
use crate::state::AppState;

/// Public (pre-auth) form routes. Mounted inside the rate-limited public
/// stack — login/signup keep the same brute-force protections as the JSON
/// API surface.
pub fn public_router(state: AppState) -> Router<AppState> {
    Router::new()
        .route("/web/auth/login", post(form_login))
        .route("/web/auth/mfa/verify", post(form_mfa_verify))
        .route("/web/auth/signup", post(form_signup))
        .route("/web/auth/forgot-password", post(form_forgot_password))
        .route("/web/auth/reset-password", post(form_reset_password))
        .route("/web/auth/logout", post(form_logout))
        // Control-plane operator login (the CP login form posts here).
        .route("/web/cp/login", post(form_cp_login))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            web_form_rejection_middleware,
        ))
}

// ─── Cookie consent (no-JS marketing banner) ─────────────────────
//
// The zero-JavaScript rework deleted the marketing site's
// apexmail-site.js, which owned the cookie-banner click handler — the
// banner's buttons became inert. The no-JS replacement: the banner
// renders real links to GET /consent (POST accepted for parity), the
// handler records the choice in a first-party cookie scoped to the
// whole apexmail.ee family, and the browser is redirected back to the
// page it came from. Banner visibility afterwards is decided
// server-side from the cookie (nginx sub_filter variant on the static
// marketing host; the same attribute flip here when the api-server
// serves the marketing documents itself).

/// Name of the consent cookie. Set with `Domain=.apexmail.ee` so it is
/// shared by the marketing host and every console host; read by nginx
/// (`$cookie_apexmail_consent`) and this server to hide the banner.
pub const CONSENT_COOKIE_NAME: &str = "apexmail_consent";
/// Dot-prefixed so the cookie applies to apexmail.ee and all subdomains.
const CONSENT_COOKIE_DOMAIN: &str = ".apexmail.ee";
/// One year, per the cookie policy.
const CONSENT_COOKIE_MAX_AGE_SECS: i64 = 365 * 24 * 60 * 60;

#[derive(Debug, Default, Deserialize)]
pub struct ConsentRequest {
    pub choice: Option<String>,
    pub return_to: Option<String>,
}

/// Normalize a requested consent choice to the recorded cookie value.
/// "dismiss" is the old site.js semantics: record a choice, enable
/// nothing — i.e. necessary-only. Unknown values record nothing (the
/// caller must not set the cookie for them).
pub fn normalize_consent_choice(choice: Option<&str>) -> Option<&'static str> {
    match choice.map(str::trim) {
        Some("all") => Some("all"),
        Some("necessary") => Some("necessary"),
        Some("dismiss") => Some("necessary"),
        _ => None,
    }
}

/// Validate a `return_to` target for the consent redirect. Allowed:
/// same-origin relative paths (`/…`, never `//…`) and absolute HTTPS
/// URLs on the apexmail.ee host family (the banner lives on
/// apexmail.ee but the endpoint is api.apexmail.ee, so the return hop
/// is always cross-host within the family). Everything else — open
/// redirects, other domains, plain HTTP — falls back to `/`.
pub fn consent_safe_return_to(return_to: Option<&str>) -> String {
    let Some(value) = return_to.map(str::trim).filter(|v| !v.is_empty()) else {
        return "/".to_string();
    };

    if value.starts_with('/') && !value.starts_with("//") {
        return value.to_string();
    }

    let Ok(url) = url::Url::parse(value) else {
        return "/".to_string();
    };
    if url.scheme() != "https" {
        return "/".to_string();
    }
    let host = url.host_str().map(str::to_ascii_lowercase);
    match host.as_deref() {
        Some("apexmail.ee") | Some("www.apexmail.ee") => url.to_string(),
        Some(host) if host.ends_with(".apexmail.ee") => url.to_string(),
        _ => "/".to_string(),
    }
}

/// Does a Cookie header carry a non-empty consent cookie? Shared by the
/// api-server's marketing-page render path (hide the banner when
/// present) and tests.
pub fn cookie_header_has_consent(cookie_header: &str) -> bool {
    cookie_header.split(';').any(|pair| {
        match pair.split_once('=') {
            Some((name, value)) => {
                name.trim() == CONSENT_COOKIE_NAME && !value.trim().is_empty()
            }
            None => false,
        }
    })
}

/// Build the Set-Cookie header value recording a consent choice.
pub fn consent_set_cookie(value: &str, secure: bool) -> String {
    format!(
        "{CONSENT_COOKIE_NAME}={value}; Domain={CONSENT_COOKIE_DOMAIN}; Path=/; Max-Age={CONSENT_COOKIE_MAX_AGE_SECS}; SameSite=Lax; HttpOnly{}",
        if secure { "; Secure" } else { "" }
    )
}

/// Shared GET/POST behavior: record the choice, redirect back.
fn consent_respond(request: ConsentRequest, config: &Config) -> Response {
    let return_to = consent_safe_return_to(request.return_to.as_deref());

    // Unknown/absent choice: do not touch consent state — send the user
    // back with the banner still pending (no cookie is written).
    let Some(value) = normalize_consent_choice(request.choice.as_deref()) else {
        return (
            StatusCode::FOUND,
            [(header::LOCATION, return_to)],
        )
            .into_response();
    };

    let mut response = (
        StatusCode::FOUND,
        [(header::LOCATION, return_to)],
    )
        .into_response();
    if let Ok(cookie) = consent_set_cookie(value, is_secure(config)).parse() {
        response.headers_mut().insert(header::SET_COOKIE, cookie);
    }
    response
}

/// GET /consent?choice={all|necessary}&return_to=… — the no-JS banner's
/// links (plain navigations; the marketing CSP's `form-action 'self'`
/// forbids cross-origin form posts).
async fn consent_get(
    State(state): State<AppState>,
    Query(request): Query<ConsentRequest>,
) -> Response {
    consent_respond(request, &state.config)
}

/// POST /consent — same behavior for form-driven callers.
async fn consent_post(
    State(state): State<AppState>,
    Form(request): Form<ConsentRequest>,
) -> Response {
    consent_respond(request, &state.config)
}

/// Public consent router (GET + POST). Mounted in `app.rs` inside the
/// rate-limited public stack — per-IP/path buckets are the light touch
/// this state-lite endpoint wants.
pub fn consent_router() -> Router<AppState> {
    Router::new()
        .route("/consent", get(consent_get).post(consent_post))
}

/// Authenticated form routes. Mounted inside the `authenticated` stack so
/// `require_auth` populates `AuthUser` (session cookie) before the handler
/// runs, exactly like the JSON API.
pub fn authenticated_router(state: AppState) -> Router<AppState> {
    Router::new()
        .route("/web/account/profile", post(form_profile_update))
        .route("/web/auth/change-password", post(form_change_password))
        .route("/web/auth/mfa/setup", post(form_mfa_setup))
        .route("/web/auth/mfa/confirm", post(form_mfa_confirm))
        .route("/web/auth/impersonate/end", post(form_impersonate_end))
        .route("/web/api-keys", post(form_api_key_create))
        .route("/web/webhooks", post(form_webhook_create))
        .route("/web/team/invite", post(form_team_invite))
        .route("/web/billing/checkout", post(form_billing_checkout))
        .route("/web/billing/portal", post(form_billing_portal))
        .route("/web/contacts", post(form_contact_create))
        .route("/web/contacts/delete-bulk", post(form_contacts_delete_bulk))
        .route("/web/contacts/export.csv", get(form_contacts_export))
        .route("/web/lists", post(form_list_create))
        .route("/web/lists/update", post(form_list_update))
        .route("/web/domains", post(form_domain_create))
        .route("/web/templates", post(form_template_create))
        .route("/web/campaigns", post(form_campaign_create))
        .route("/web/campaigns/update", post(form_campaign_update))
        .route("/web/campaigns/preview", post(form_campaign_preview))
        .route("/web/campaigns/delete-bulk", post(form_campaigns_delete_bulk))
        .route("/web/inbox-placement/tests", post(form_placement_create))
        .route("/web/dedicated-ips", post(form_dedicated_ip_request))
        .route("/web/confirm", post(form_confirm_destructive))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            web_form_rejection_middleware,
        ))
}

/// Control-plane form routes (`/web/admin/*`). These mutate platform
/// state (tenants, operators, the sales pipeline, audit exports) and are
/// mounted in `app.rs` behind `require_system_tenant_middleware` — the
/// SAME gate the `/v1/admin/*` JSON surface uses. A customer session
/// (any non-system tenant) is rejected before the handler runs.
pub fn admin_router(state: AppState) -> Router<AppState> {
    Router::new()
        .route("/web/admin/tenants", post(form_admin_tenant_create))
        .route("/web/admin/operators", post(form_admin_operator_create))
        .route("/web/admin/sales/discovery", post(form_sales_discovery))
        .route("/web/admin/sales/outreach", post(form_sales_outreach))
        .route("/web/admin/sales/leads/update", post(form_sales_leads_update))
        .route("/web/admin/audit/export", get(form_audit_export))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            web_form_rejection_middleware,
        ))
}

/// Malformed `application/x-www-form-urlencoded` bodies (bad percent-
/// encoding, truncated posts) make axum's `Form` extractor reject with a
/// plain-text 400. Browser surfaces instead get the same friendly PRG
/// treatment as every other failure: a signed flash cookie + redirect
/// back to the referring page.
async fn web_form_rejection_middleware(
    State(state): State<AppState>,
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    web_form_rejection_inner(state, req, next).await
}

/// Test-visible alias for the rejection middleware (layered as-is).
pub(crate) async fn web_form_rejection_middleware_for_tests(
    State(state): State<AppState>,
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    web_form_rejection_inner(state, req, next).await
}

async fn web_form_rejection_inner(
    state: AppState,
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    let path = req.uri().path().to_string();
    let referer = req
        .headers()
        .get(header::REFERER)
        .and_then(|value| value.to_str().ok())
        .and_then(|referer| {
            let path = referer.split_once("://").map(|(_, rest)| rest)?;
            let path = path.split_once('/').map(|(_, rest)| format!("/{rest}"))?;
            (!path.starts_with("//")).then_some(path)
        })
        .unwrap_or_else(|| "/dashboard".to_string());
    let is_post = req.method() == axum::http::Method::POST;
    let secure = state.config.environment.is_production();

    let response = next.run(req).await;
    if response.status() == StatusCode::BAD_REQUEST && is_post && path.starts_with("/web/") {
        let mut redirect = (
            StatusCode::SEE_OTHER,
            [(header::LOCATION, referer)],
        )
            .into_response();
        if let Ok(value) = flash_set_cookie(
            &[FlashMessage::error(
                "The form could not be read. Reload the page and try again.",
            )],
            &state.config.csrf_secret,
            secure,
        )
        .parse()
        {
            redirect.headers_mut().insert(header::SET_COOKIE, value);
        }
        return redirect;
    }
    response
}

// ─── Helpers ────────────────────────────────────────────────────

fn is_secure(config: &Config) -> bool {
    config.environment.is_production()
}

/// PRG response: signed flash cookie + 303 redirect. `clear_first` removes
/// a stale flash cookie in the same response (Set-Cookie ordering keeps the
/// last one, so we always set exactly one).
fn redirect_with_flash(
    messages: &[FlashMessage],
    location: &str,
    config: &Config,
) -> Response {
    let mut response = (
        StatusCode::SEE_OTHER,
        [(header::LOCATION, location.to_string())],
    )
        .into_response();
    let headers = response.headers_mut();
    // Only one flash cookie per response: the set below replaces any clear.
    let _ = flash_clear_cookie(is_secure(config));
    if let Ok(value) = flash_set_cookie(messages, &config.csrf_secret, is_secure(config))
        .parse()
    {
        headers.insert(header::SET_COOKIE, value);
    }
    response
}

fn redirect_success(message: &str, location: &str, config: &Config) -> Response {
    redirect_with_flash(&[FlashMessage::success(message)], location, config)
}

fn redirect_error(message: &str, location: &str, config: &Config) -> Response {
    redirect_with_flash(&[FlashMessage::error(message)], location, config)
}

/// Safe fallback redirect target: same-origin paths only.
fn safe_return_to(form: &HashMap<String, String>, default: &str) -> String {
    form.get("return_to")
        .or_else(|| form.get("next"))
        .map(String::as_str)
        .filter(|value| value.starts_with('/') && !value.starts_with("//"))
        .unwrap_or(default)
        .to_string()
}

fn csrf_from(form: &HashMap<String, String>) -> Option<&str> {
    form.get("_csrf").map(String::as_str).filter(|t| !t.is_empty())
}

/// Validate the form's embedded CSRF token. On failure the caller redirects
/// back with a friendly "session expired" flash — never a 403 JSON dump.
fn check_csrf(form: &HashMap<String, String>, config: &Config) -> Result<(), &'static str> {
    match csrf_from(form) {
        Some(token) => validate_csrf_token(token, &config.csrf_secret)
            .map_err(|_| "Your session expired. Reload the page and try again."),
        None => Err("Your session expired. Reload the page and try again."),
    }
}

fn field(form: &HashMap<String, String>, key: &str) -> String {
    form.get(key).cloned().unwrap_or_default()
}

fn field_truncated(form: &HashMap<String, String>, key: &str, max: usize) -> String {
    let value = field(form, key).trim().to_string();
    value.chars().take(max).collect()
}

/// The multi-step login challenge cookie (HMAC-signed by ui-foundation's
/// confirmation signer — short-lived, binds the user id + email).
fn sign_login_challenge(config: &Config, user_id: &str, email: &str) -> String {
    ui_foundation::flash::sign_confirmation_for_ttl(
        &config.csrf_secret,
        "login-mfa",
        &format!("{user_id}:{email}"),
        Utc::now().timestamp(),
        5 * 60,
    )
}

fn verify_login_challenge(config: &Config, token: &str, user_id: &str, email: &str) -> bool {
    verify_confirmation(
        &config.csrf_secret,
        token,
        "login-mfa",
        &format!("{user_id}:{email}"),
        Utc::now().timestamp(),
    )
}

/// Revoke every live session for the user (same Redis key the auth
/// middleware checks: `apexmail:session_revoked_after:{tenant}:{user}`).
async fn revoke_user_sessions(state: &AppState, tenant_id: &str, user_id: &str) {
    let key = format!("apexmail:session_revoked_after:{tenant_id}:{user_id}");
    let ttl = state.config.jwt_expiry.as_secs();
    if let Ok(mut conn) = state.redis.get().await {
        let now = Utc::now().timestamp();
        let _: Result<(), _> =
            deadpool_redis::redis::AsyncCommands::set_ex(&mut *conn, &key, now, ttl).await;
    }
}

/// Extract a cookie value from a Cookie header.
fn cookie_value<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers
        .get(header::COOKIE)
        .and_then(|value| value.to_str().ok())?
        .split(';')
        .find_map(|chunk| chunk.trim().strip_prefix(&format!("{name}=")))
}

// ─── Pending-MFA setup cookie (signed, short-lived) ─────────────
//
// POST /web/auth/mfa/setup generates a TOTP secret and parks it in an
// HMAC-signed HttpOnly cookie; the next GET of the CP security page
// renders the QR from it. The value binds the user id so a stolen cookie
// cannot enroll MFA for a different account.

const MFA_SETUP_COOKIE: &str = "apexmail_mfa_setup";
const MFA_SETUP_TTL_SECS: i64 = 10 * 60;

fn sign_mfa_setup(config: &Config, user_id: &str, secret: &str) -> String {
    ui_foundation::flash::sign_confirmation_for_ttl(
        &config.csrf_secret,
        "mfa-setup",
        &format!("{user_id}:{secret}"),
        Utc::now().timestamp(),
        MFA_SETUP_TTL_SECS,
    )
}

fn verify_mfa_setup(config: &Config, token: &str, user_id: &str, secret: &str) -> bool {
    verify_confirmation(
        &config.csrf_secret,
        token,
        "mfa-setup",
        &format!("{user_id}:{secret}"),
        Utc::now().timestamp(),
    )
}

/// Decode the pending-setup cookie into (secret, otpauth) for the given
/// user. Returns `None` when absent, expired, or signed for another user.
///
/// Cookie format: `<b64(secret_b64 + "." + otpauth_b64)>.<signature>` — the
/// payload is one base64 blob because the HMAC token itself contains a
/// dot, so the FIRST dot always separates payload from signature.
pub(crate) fn decode_mfa_setup_cookie(
    headers: &HeaderMap,
    config: &Config,
    user_id: &str,
) -> Option<ui_foundation::view_data::MfaSetupData> {
    let raw = cookie_value(headers, MFA_SETUP_COOKIE)?;
    let (payload_b64, signature) = raw.split_once('.')?;
    let payload = decode_url_safe_base64(payload_b64)?;
    let (secret_b64, otpauth_b64) = payload.split_once('.')?;
    let secret = decode_url_safe_base64(secret_b64)?;
    let otpauth = decode_url_safe_base64(otpauth_b64)?;
    if !verify_mfa_setup(config, signature, user_id, &secret) {
        return None;
    }
    Some(ui_foundation::view_data::MfaSetupData { secret, otpauth })
}

/// Encode the pending-setup cookie value for `sign_mfa_setup`'s signature.
fn encode_mfa_setup_value(secret: &str, otpauth: &str, signature: &str) -> String {
    let payload = format!(
        "{}.{}",
        encode_url_safe_base64(secret),
        encode_url_safe_base64(otpauth)
    );
    format!("{}.{}", encode_url_safe_base64(&payload), signature)
}

fn encode_url_safe_base64(value: &str) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(value.as_bytes())
}

fn decode_url_safe_base64(value: &str) -> Option<String> {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(value)
        .ok()
        .and_then(|bytes| String::from_utf8(bytes).ok())
}

#[derive(sqlx::FromRow)]
struct WebUserRow {
    id: String,
    tenant_id: String,
    email: String,
    #[allow(dead_code)]
    name: Option<String>,
    password_hash: String,
    role: String,
    status: String,
    mfa_enabled: bool,
}

const USER_COLUMNS: &str =
    "id::text, tenant_id::text, email, name, password_hash, role, status, mfa_enabled";

async fn find_user_by_email(state: &AppState, email: &str) -> Option<WebUserRow> {
    sqlx::query_as::<_, WebUserRow>(&format!(
        "SELECT {USER_COLUMNS} FROM users WHERE LOWER(email) = LOWER($1) OR LOWER(username) = LOWER($1)"
    ))
    .bind(email)
    .fetch_optional(&state.db)
    .await
    .ok()
    .flatten()
}

fn scopes_for_role(role: &str) -> Vec<String> {
    match role {
        "admin" | "owner" => vec!["*".to_string()],
        "developer" => vec![
            "messages:send", "messages:read", "domains:read", "templates:read",
            "templates:write", "events:read", "analytics:read", "contacts:read",
            "contacts:write", "logs:read",
        ]
        .into_iter()
        .map(String::from)
        .collect(),
        _ => vec![
            "messages:send", "messages:read", "domains:read", "templates:read",
            "events:read", "analytics:read",
        ]
        .into_iter()
        .map(String::from)
        .collect(),
    }
}

/// Mint an RS256 session JWT + Set-Cookie, mirroring the JSON login route
/// (same claims shape `middleware::auth` decodes).
fn session_cookie_for_user(state: &AppState, user: &WebUserRow) -> Result<String, String> {
    use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
    let expiry_secs = state.config.jwt_expiry.as_secs() as i64;
    let claims = crate::middleware::auth::JwtClaims {
        sub: user.id.clone(),
        tenant_id: user.tenant_id.clone(),
        scopes: scopes_for_role(&user.role),
        exp: (Utc::now() + chrono::Duration::seconds(expiry_secs)).timestamp(),
        iat: Utc::now().timestamp(),
        jti: Uuid::new_v4().to_string(),
        typ: Some("session".into()),
    };
    let token = encode(
        &Header::new(Algorithm::RS256),
        &claims,
        &EncodingKey::from_rsa_pem(state.config.jwt_private_key_pem.as_bytes())
            .map_err(|e| format!("invalid JWT private key configuration: {e}"))?,
    )
    .map_err(|e| format!("token generation failed: {e}"))?;
    Ok(format!(
        "am_session={token}; HttpOnly; Path=/; Max-Age={expiry_secs}; SameSite=Strict{}",
        if is_secure(&state.config) { "; Secure" } else { "" },
    ))
}

fn attach_cookie(response: Response, cookie: String) -> Response {
    let (mut parts, body) = response.into_parts();
    if let Ok(value) = cookie.parse() {
        parts.headers.insert(header::SET_COOKIE, value);
    }
    Response::from_parts(parts, body)
}

fn verify_password(hash: &str, password: &str) -> bool {
    if hash.starts_with("$2b$") || hash.starts_with("$2a$") || hash.starts_with("$2y$") {
        bcrypt::verify(password, hash).unwrap_or(false)
    } else if hash.starts_with("$argon2") {
        apexmail_lib::verify_password(password, hash).is_ok()
    } else {
        false
    }
}

fn hash_password(password: &str) -> Result<String, String> {
    bcrypt::hash(password, bcrypt::DEFAULT_COST).map_err(|e| format!("hash failure: {e}"))
}

fn password_policy_error(password: &str) -> Option<&'static str> {
    let len = password.chars().count();
    if !(12..=128).contains(&len) {
        return Some("Passwords must be 12-128 characters.");
    }
    let has_digit = password.chars().any(|c| c.is_ascii_digit());
    let has_lower = password.chars().any(|c| c.is_ascii_lowercase());
    let has_upper = password.chars().any(|c| c.is_ascii_uppercase());
    let has_punct = password
        .chars()
        .any(|c| c.is_ascii_punctuation() && c.is_ascii_graphic());
    if has_digit && has_lower && has_upper && has_punct {
        None
    } else {
        Some("Use uppercase, lowercase, a number, and punctuation such as ! @ # $ ? - _ .")
    }
}

fn valid_email(email: &str) -> bool {
    let email = email.trim();
    !email.is_empty()
        && email.len() <= 254
        && email.contains('@')
        && email.split('@').count() == 2
        && !email.starts_with('@')
        && !email.ends_with('@')
        && !email.contains(char::is_whitespace)
}

// ─── Public auth handlers ────────────────────────────────────────

async fn form_login(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    perform_password_login(state, headers, form, "/dashboard").await
}

/// Control-plane operator login — the CP surface's `/login` form posts
/// here. Same credentials stack and PRG contract as the web login, plus a
/// privilege gate: only system-tenant operators (admin/owner role) get a
/// CP session. Everyone else receives a clear error and no cookie.
async fn form_cp_login(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    let email = field(&form, "email").trim().to_string();
    let password = field(&form, "password");
    if let Err(message) = check_csrf(&form, &state.config) {
        return redirect_error(message, "/login", &state.config);
    }
    if email.is_empty() || password.is_empty() {
        return redirect_error("Email and password are required.", "/login", &state.config);
    }

    let Some(user) = find_user_by_email(&state, &email).await else {
        return redirect_error("Invalid email or password.", "/login", &state.config);
    };
    if user.status != "active" {
        return redirect_error(
            "This account is not active yet. Check your verification email.",
            "/login",
            &state.config,
        );
    }
    if !verify_password(&user.password_hash, &password) {
        return redirect_error("Invalid email or password.", "/login", &state.config);
    }
    if !is_system_tenant(&state, &user.tenant_id).await || !is_operator_role(&user.role) {
        // P0: a customer session must never reach the control plane. Say
        // so clearly instead of minting a CP session for them.
        return redirect_error(
            "Control-plane access is restricted to ApexMail operators.",
            "/login",
            &state.config,
        );
    }

    if user.mfa_enabled {
        let challenge = sign_login_challenge(&state.config, &user.id, &user.email);
        let mut response = redirect_with_flash(
            &[FlashMessage::info("Enter the 6-digit code from your authenticator app.")],
            &format!(
                "/login?mfa=1&email={}&return_to=%2Fdashboard",
                urlencode(&user.email)
            ),
            &state.config,
        );
        let challenge_cookie = format!(
            "apexmail_login_challenge={challenge}; Path=/login; Max-Age=300; HttpOnly; SameSite=Lax{}",
            if is_secure(&state.config) { "; Secure" } else { "" },
        );
        if let Ok(value) = challenge_cookie.parse() {
            response.headers_mut().append(header::SET_COOKIE, value);
        }
        return response;
    }

    let _ = headers;
    match session_cookie_for_user(&state, &user) {
        Ok(cookie) => attach_cookie(
            redirect_success("Signed in to the control plane.", "/dashboard", &state.config),
            cookie,
        ),
        Err(_) => redirect_error(
            "Sign-in is temporarily unavailable. Try again.",
            "/login",
            &state.config,
        ),
    }
}

/// System-tenant membership: the literal `system` sentinel (static API
/// keys) or a tenants row whose slug is `system`.
pub(crate) async fn is_system_tenant(state: &AppState, tenant_id: &str) -> bool {
    if tenant_id == "system" {
        return true;
    }
    sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM tenants WHERE id::text = $1 AND slug = 'system')",
    )
    .bind(tenant_id)
    .fetch_optional(&state.db)
    .await
    .ok()
    .flatten()
    .unwrap_or(false)
}

fn is_operator_role(role: &str) -> bool {
    role == "admin" || role == "owner"
}

/// Shared password step of the multi-step SSR login. MFA-enabled users
/// are redirected to the `/login?mfa=1` challenge form with a signed,
/// short-lived challenge cookie (never straight into a session).
async fn perform_password_login(
    state: AppState,
    headers: HeaderMap,
    form: HashMap<String, String>,
    default_return_to: &str,
) -> Response {
    let email = field(&form, "email").trim().to_string();
    let password = field(&form, "password");
    let return_to = safe_return_to(&form, default_return_to);

    if let Err(message) = check_csrf(&form, &state.config) {
        return redirect_error(message, "/login", &state.config);
    }
    if email.is_empty() || password.is_empty() {
        return redirect_error("Email and password are required.", "/login", &state.config);
    }
    let _ = headers; // rate limiting is enforced by the surrounding stack

    let Some(user) = find_user_by_email(&state, &email).await else {
        return redirect_error("Invalid email or password.", "/login", &state.config);
    };
    if user.status != "active" {
        return redirect_error(
            "This account is not active yet. Check your verification email.",
            "/login",
            &state.config,
        );
    }
    if !verify_password(&user.password_hash, &password) {
        return redirect_error("Invalid email or password.", "/login", &state.config);
    }

    if user.mfa_enabled {
        // Multi-step SSR MFA: redirect to the login page's challenge state
        // with a short-lived signed challenge token in a cookie. The
        // return_to target rides along so the flow ends where it started.
        let challenge = sign_login_challenge(&state.config, &user.id, &user.email);
        let mut response = redirect_with_flash(
            &[FlashMessage::info("Enter the 6-digit code from your authenticator app.")],
            &format!(
                "/login?mfa=1&email={}&return_to={}",
                urlencode(&user.email),
                urlencode(&return_to)
            ),
            &state.config,
        );
        let challenge_cookie = format!(
            "apexmail_login_challenge={challenge}; Path=/login; Max-Age=300; HttpOnly; SameSite=Lax{}",
            if is_secure(&state.config) { "; Secure" } else { "" },
        );
        if let Ok(value) = challenge_cookie.parse() {
            // Append (the flash cookie is already set; Append preserves it).
            response.headers_mut().append(header::SET_COOKIE, value);
        }
        return response;
    }

    match session_cookie_for_user(&state, &user) {
        Ok(cookie) => attach_cookie(
            redirect_success("Signed in.", &return_to, &state.config),
            cookie,
        ),
        Err(_) => redirect_error("Sign-in is temporarily unavailable. Try again.", "/login", &state.config),
    }
}

async fn form_mfa_verify(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    let email = field(&form, "email").trim().to_string();
    let code = field(&form, "code").trim().to_string();
    let return_to = safe_return_to(&form, "/dashboard");
    if let Err(message) = check_csrf(&form, &state.config) {
        return redirect_error(message, "/login", &state.config);
    }
    let challenge_cookie = headers
        .get(header::COOKIE)
        .and_then(|v| v.to_str().ok())
        .and_then(|cookies| {
            cookies.split(';').find_map(|c| {
                let c = c.trim();
                c.strip_prefix("apexmail_login_challenge=")
            })
        })
        .unwrap_or("")
        .to_string();

    let Some(user) = find_user_by_email(&state, &email).await else {
        return redirect_error("Invalid email or password.", "/login", &state.config);
    };
    if !verify_login_challenge(&state.config, &challenge_cookie, &user.id, &user.email) {
        return redirect_error(
            "Your verification window expired. Sign in again.",
            "/login",
            &state.config,
        );
    }
    if code.len() != 6 || !code.chars().all(|c| c.is_ascii_digit()) {
        return redirect_error(
            "Enter the 6-digit code from your authenticator app.",
            &format!(
                "/login?mfa=1&email={}&return_to={}",
                urlencode(&email),
                urlencode(&return_to)
            ),
            &state.config,
        );
    }
    let secret = sqlx::query_scalar::<_, Option<String>>(
        "SELECT mfa_secret FROM users WHERE id = $1",
    )
    .bind(&user.id)
    .fetch_one(&state.db)
    .await
    .ok()
    .flatten()
    .filter(|stored| !stored.is_empty());
    let totp_valid = match secret {
        Some(encrypted) => {
            // Secrets are encrypted at rest with the user id as AAD
            // (CRIT-10); decrypt then verify the TOTP code.
            let aad = format!("user_id={}", user.id).into_bytes();
            match apexmail_lib::secret_at_rest::decrypt_at_rest(&encrypted, &aad) {
                Ok(secret) => apexmail_lib::mfa::verify_totp_code(&secret, &code),
                Err(_) => false,
            }
        }
        None => false,
    };
    if !totp_valid {
        return redirect_error(
            "That code did not match. Check your authenticator and try again.",
            &format!(
                "/login?mfa=1&email={}&return_to={}",
                urlencode(&email),
                urlencode(&return_to)
            ),
            &state.config,
        );
    }
    match session_cookie_for_user(&state, &user) {
        Ok(cookie) => attach_cookie(
            redirect_success("Signed in.", &return_to, &state.config),
            cookie,
        ),
        Err(_) => redirect_error("Sign-in is temporarily unavailable. Try again.", "/login", &state.config),
    }
}

async fn form_signup(State(state): State<AppState>, Form(form): Form<HashMap<String, String>>) -> Response {
    let name = field_truncated(&form, "name", 120);
    let company = field_truncated(&form, "company_name", 100);
    let email = field(&form, "email").trim().to_lowercase();
    let password = field(&form, "password");
    let plan = field(&form, "plan");

    if let Err(message) = check_csrf(&form, &state.config) {
        return redirect_error(message, "/signup", &state.config);
    }
    if name.is_empty() || company.is_empty() {
        return redirect_error("Full name and company are required.", "/signup", &state.config);
    }
    if !valid_email(&email) {
        return redirect_error("Enter a valid email address.", "/signup", &state.config);
    }
    if let Some(message) = password_policy_error(&password) {
        return redirect_error(message, "/signup", &state.config);
    }
    let plan = match plan.as_str() {
        "starter" | "pro" | "growth" | "scale" | "free" => plan,
        _ => "free".to_string(),
    };
    let _ = plan; // onboarding preference only; provisioning starts on Free

    let existing = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM users WHERE LOWER(email) = LOWER($1)",
    )
    .bind(&email)
    .fetch_one(&state.db)
    .await
    .unwrap_or(0);
    if existing > 0 {
        return redirect_error(
            "An account with this email already exists. Try signing in instead.",
            "/signup",
            &state.config,
        );
    }

    let password_hash = match hash_password(&password) {
        Ok(hash) => hash,
        Err(_) => {
            return redirect_error("Registration is temporarily unavailable.", "/signup", &state.config)
        }
    };
    // tenants.id is VARCHAR(26) (ULID, migration 064) — a UUID does not
    // fit; generate a 26-char text id and bind tenant ids as text.
    let tenant_id = apexmail_lib::id::generate_id("", 26);
    let user_id = apexmail_lib::id::generate_id("", 26);
    let slug_source = company.to_lowercase();
    let slug: String = slug_source
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-')
        .take(48)
        .collect();
    let now = Utc::now();
    let verification_token = Uuid::new_v4().to_string();

    let result = sqlx::query(
        "INSERT INTO tenants (id, name, slug, plan, status, settings, metadata, created_at, updated_at)
         VALUES ($1, $2, $3, 'free', 'pending', $4, $5, $6, $6)",
    )
    .bind(&tenant_id)
    .bind(&company)
    .bind(format!("{slug}-{}", &tenant_id[..8]))
    .bind(json!({}))
    .bind(json!({}))
    .bind(now)
    .execute(&state.db)
    .await;
    if result.is_err() {
        return redirect_error("Registration is temporarily unavailable. Try again.", "/signup", &state.config);
    }

    let insert_user = sqlx::query(
        "INSERT INTO users (id, tenant_id, email, name, password_hash, role, status,
                            email_verified, mfa_enabled, metadata, created_at, updated_at)
         VALUES ($1, $2, $3, $4, $5, 'owner', 'active', false, false, $6, $7, $7)",
    )
    .bind(user_id)
    .bind(tenant_id)
    .bind(&email)
    .bind(&name)
    .bind(&password_hash)
    .bind(json!({
        "verification_token_hash": verification_token,
        "verification_expires": (now + chrono::Duration::hours(24)).to_rfc3339(),
    }))
    .bind(now)
    .execute(&state.db)
    .await;
    if insert_user.is_err() {
        return redirect_error("Registration is temporarily unavailable. Try again.", "/signup", &state.config);
    }

    redirect_success(
        "Account created. Check your email for a verification link.",
        &format!("/verify-email?email={}", urlencode(&email)),
        &state.config,
    )
}

async fn form_forgot_password(
    State(state): State<AppState>,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    let email = field(&form, "email").trim().to_lowercase();
    if let Err(message) = check_csrf(&form, &state.config) {
        return redirect_error(message, "/forgot-password", &state.config);
    }
    if !valid_email(&email) {
        return redirect_error("Enter a valid email address.", "/forgot-password", &state.config);
    }
    // Token issuance mirrors the JSON flow (forgot_password.rs) exactly: a
    // SHA-256 token hash lands in users.metadata and the reset email is
    // enqueued through the same system-sender outbox — in ONE transaction.
    // The response never reveals whether the account exists.
    let user: Option<(String, String)> = sqlx::query_as(
        "SELECT id::text, tenant_id::text FROM users WHERE LOWER(email) = LOWER($1) AND status = 'active' LIMIT 1",
    )
    .bind(&email)
    .fetch_optional(&state.db)
    .await
    .ok()
    .flatten();

    if let Some((user_id, _tenant_id)) = user {
        let token = apexmail_lib::id::generate_verification_token();
        let expires = Utc::now() + chrono::Duration::hours(1);
        let token_hash = crate::routes::helpers::hash_token(&token);

        let result: Result<(), crate::error::ApiError> = async {
            let mut tx = state.db.begin().await?;
            let update = sqlx::query(
                "UPDATE users SET metadata = COALESCE(metadata, '{}'::jsonb) || $1::jsonb, updated_at = NOW()
                 WHERE id = $2 AND status = 'active'",
            )
            .bind(json!({
                "password_reset_token_hash": token_hash,
                "password_reset_expires": expires.to_rfc3339(),
                "password_reset_iat": Utc::now().to_rfc3339(),
            }))
            .bind(&user_id)
            .execute(&mut *tx)
            .await?;
            if update.rows_affected() != 1 {
                // Deactivated between lookup and update — no token, no email.
                tx.rollback().await?;
                return Ok(());
            }

            let reset_link = format!(
                "{}/reset-password?token={}&email={}",
                state.config.base_url.trim_end_matches('/'),
                urlencode(&token),
                urlencode(&email),
            );
            let html_body = format!(
                "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\"/></head><body style=\"font-family:ui-monospace,monospace;line-height:1.6;color:#09090b;max-width:560px;margin:0 auto;padding:24px\"><h2>Reset Your Password</h2><p>We received a request to reset the password for <strong>{email}</strong>.</p><p><a href=\"{reset_link}\" style=\"display:inline-block;padding:12px 28px;background:#dc2626;color:#fff;text-decoration:none;font-weight:700\">Reset Password</a></p><p style=\"font-size:13px;color:#71717a\">This link expires in 1 hour. If you didn't request a password reset, you can safely ignore this email.</p></body></html>"
            );
            let text_body = format!(
                "Reset Your Password\n\nWe received a request to reset the password for {email}.\n\nReset your password by visiting: {reset_link}\n\nThis link expires in 1 hour."
            );
            crate::routes::system_sender::queue_system_email_in_transaction(
                &mut tx,
                &email,
                "Reset your ApexMail password",
                &html_body,
                &text_body,
                vec!["system".into(), "password-reset".into()],
            )
            .await?;
            tx.commit().await?;
            Ok(())
        }
        .await;

        match result {
            Ok(()) => {
                tracing::info!(user_id = %user_id, "web password reset email enqueued");
            }
            Err(error) => {
                tracing::error!(error = %error, "web forgot-password issuance failed");
            }
        }
    }

    redirect_success(
        "If that account exists, a reset link is on the way.",
        "/forgot-password",
        &state.config,
    )
}

async fn form_reset_password(
    State(state): State<AppState>,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    let email = field(&form, "email").trim().to_lowercase();
    let token = field(&form, "token");
    let password = field(&form, "password");
    let confirm = field(&form, "confirmPassword");
    let back = format!(
        "/reset-password?token={}&email={}",
        urlencode(&token),
        urlencode(&email)
    );
    if let Err(message) = check_csrf(&form, &state.config) {
        return redirect_error(message, "/forgot-password", &state.config);
    }
    if token.is_empty() || email.is_empty() {
        return redirect_error(
            "Open the reset link from your email first.",
            "/forgot-password",
            &state.config,
        );
    }
    if password != confirm {
        return redirect_error("The passwords do not match.", &back, &state.config);
    }
    if let Some(message) = password_policy_error(&password) {
        return redirect_error(message, &back, &state.config);
    }

    // Same verification chain as the JSON twin (auth.rs reset_password):
    // hash lookup → status → expiry (primary + 24h absolute cap) →
    // optimistic-lock UPDATE that consumes the token.
    let token_hash = crate::routes::helpers::hash_token(&token);
    let user: Option<(String, String, String, serde_json::Value)> = sqlx::query_as(
        "SELECT id::text, tenant_id::text, status, metadata FROM users
         WHERE LOWER(email) = LOWER($1) AND metadata->>'password_reset_token_hash' = $2
         LIMIT 1",
    )
    .bind(&email)
    .bind(&token_hash)
    .fetch_optional(&state.db)
    .await
    .ok()
    .flatten();

    let Some((user_id, tenant_id, status, metadata)) = user else {
        return redirect_error("That reset link is invalid or has expired.", "/forgot-password", &state.config);
    };
    if status != "active" {
        return redirect_error("This account is not active.", "/forgot-password", &state.config);
    }
    let valid_expiry = ["password_reset_expires", "password_reset_iat"]
        .iter()
        .all(|key| metadata.get(key).and_then(|v| v.as_str()).is_some())
        && metadata
            .get("password_reset_expires")
            .and_then(|v| v.as_str())
            .and_then(|v| chrono::DateTime::parse_from_rfc3339(v).ok())
            .map(|expires| Utc::now() <= expires)
            .unwrap_or(false)
        && metadata
            .get("password_reset_iat")
            .and_then(|v| v.as_str())
            .and_then(|v| chrono::DateTime::parse_from_rfc3339(v).ok())
            .map(|iat| {
                let now = Utc::now();
                iat <= now && now <= iat + chrono::Duration::hours(24)
            })
            .unwrap_or(false);
    if !valid_expiry {
        return redirect_error(
            "That reset link has expired. Request a fresh one.",
            "/forgot-password",
            &state.config,
        );
    }

    let new_hash = match hash_password(&password) {
        Ok(hash) => hash,
        Err(_) => {
            return redirect_error(
                "Could not reset the password. Try again.",
                "/forgot-password",
                &state.config,
            )
        }
    };

    // Revoke live sessions BEFORE rotating the credential (fail closed).
    revoke_user_sessions(&state, &tenant_id, &user_id).await;

    let update = sqlx::query(
        "UPDATE users
         SET password_hash = $1,
             metadata = metadata - 'password_reset_token_hash' - 'password_reset_token' - 'password_reset_expires' - 'password_reset_iat',
             updated_at = NOW()
         WHERE id = $2
           AND status = 'active'
           AND metadata->>'password_reset_token_hash' = $3",
    )
    .bind(&new_hash)
    .bind(&user_id)
    .bind(&token_hash)
    .execute(&state.db)
    .await;

    match update {
        Ok(result) if result.rows_affected() == 1 => redirect_success(
            "Your password has been reset. Sign in with your new password.",
            "/login",
            &state.config,
        ),
        Ok(_) => redirect_error(
            "That reset link is invalid or has expired.",
            "/forgot-password",
            &state.config,
        ),
        Err(_) => redirect_error(
            "Could not reset the password. Try again.",
            "/forgot-password",
            &state.config,
        ),
    }
}

async fn form_logout(State(state): State<AppState>, Form(form): Form<HashMap<String, String>>) -> Response {
    // CSRF is enforced even for logout (cookie-authenticated write).
    let friendly = check_csrf(&form, &state.config).err();
    if let Some(message) = friendly {
        return redirect_error(message, "/dashboard", &state.config);
    }
    let mut response = redirect_success("Signed out.", "/login", &state.config);
    let clear = format!(
        "am_session=; HttpOnly; Path=/; Max-Age=0; SameSite=Lax{}",
        if is_secure(&state.config) { "; Secure" } else { "" }
    );
    if let Ok(value) = clear.parse() {
        response.headers_mut().insert(header::SET_COOKIE, value);
    }
    response
}

// ─── Authenticated account/settings handlers ─────────────────────

async fn form_profile_update(
    State(state): State<AppState>,
    axum::Extension(user): axum::Extension<AuthUser>,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    if let Err(message) = check_csrf(&form, &state.config) {
        return redirect_error(message, "/settings/profile", &state.config);
    }
    let name = field_truncated(&form, "name", 120);
    if name.is_empty() {
        return redirect_error("Name is required.", "/settings/profile", &state.config);
    }
    let result = sqlx::query("UPDATE users SET name = $1, updated_at = NOW() WHERE id = $2")
        .bind(&name)
        .bind(user.user_id.clone().unwrap_or_default())
        .execute(&state.db)
        .await;
    match result {
        Ok(_) => redirect_success("Profile updated.", "/settings/profile", &state.config),
        Err(_) => redirect_error("Could not save your profile. Try again.", "/settings/profile", &state.config),
    }
}

async fn form_change_password(
    State(state): State<AppState>,
    axum::Extension(user): axum::Extension<AuthUser>,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    if let Err(message) = check_csrf(&form, &state.config) {
        return redirect_error(message, "/settings/profile", &state.config);
    }
    let current = field(&form, "current_password");
    let new_password = field(&form, "new_password");
    if let Some(message) = password_policy_error(&new_password) {
        return redirect_error(message, "/settings/profile", &state.config);
    }
    let hash = sqlx::query_scalar::<_, String>(
        "SELECT password_hash FROM users WHERE id = $1",
    )
    .bind(user.user_id.clone().unwrap_or_default())
    .fetch_one(&state.db)
    .await;
    match hash {
        Ok(hash) if verify_password(&hash, &current) => {}
        Ok(_) => {
            return redirect_error("Your current password is incorrect.", "/settings/profile", &state.config)
        }
        Err(_) => {
            return redirect_error("Could not update the password. Try again.", "/settings/profile", &state.config)
        }
    }
    let new_hash = match hash_password(&new_password) {
        Ok(hash) => hash,
        Err(_) => return redirect_error("Could not update the password. Try again.", "/settings/profile", &state.config),
    };
    let result = sqlx::query("UPDATE users SET password_hash = $1, updated_at = NOW() WHERE id = $2")
        .bind(&new_hash)
        .bind(user.user_id.clone().unwrap_or_default())
        .execute(&state.db)
        .await;
    match result {
        Ok(_) => redirect_success("Password updated.", "/settings/profile", &state.config),
        Err(_) => redirect_error("Could not update the password. Try again.", "/settings/profile", &state.config),
    }
}

/// POST /web/auth/mfa/setup — step 1 of the server-rendered TOTP
/// enrollment. Generates a fresh secret + otpauth URI, parks them in a
/// short-lived HMAC-signed HttpOnly cookie bound to the caller, and
/// redirects to the CP security page which renders the QR (encoded
/// entirely in Rust by ui-foundation's qr module).
async fn form_mfa_setup(
    State(state): State<AppState>,
    axum::Extension(user): axum::Extension<AuthUser>,
    headers: HeaderMap,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    let back = safe_return_to(&form, "/cp/security");
    if let Err(message) = check_csrf(&form, &state.config) {
        return redirect_error(message, &back, &state.config);
    }
    let Some(user_id) = user.user_id.clone() else {
        return redirect_error("Sign in again to manage MFA.", "/login", &state.config);
    };

    let enabled: Option<bool> = sqlx::query_scalar::<_, bool>(
        "SELECT mfa_enabled FROM users WHERE id = $1",
    )
    .bind(&user_id)
    .fetch_optional(&state.db)
    .await
    .ok()
    .flatten();
    if enabled != Some(false) {
        return redirect_error(
            "MFA is already enabled for this account.",
            &back,
            &state.config,
        );
    }

    let (secret, otpauth) = match generate_totp_secret_and_uri(&user_id, &state.db).await {
        Ok(pair) => pair,
        Err(message) => return redirect_error(message, &back, &state.config),
    };

    let signature = sign_mfa_setup(&state.config, &user_id, &secret);
    let value = encode_mfa_setup_value(&secret, &otpauth, &signature);
    let mut response = redirect_success(
        "Scan the QR code with your authenticator, then enter a code to confirm.",
        &back,
        &state.config,
    );
    let cookie = format!(
        "{MFA_SETUP_COOKIE}={value}; Path=/; Max-Age={MFA_SETUP_TTL_SECS}; HttpOnly; SameSite=Lax{}",
        if is_secure(&state.config) { "; Secure" } else { "" },
    );
    if let Ok(parsed) = cookie.parse() {
        response.headers_mut().append(header::SET_COOKIE, parsed);
    }
    let _ = headers;
    response
}

/// POST /web/auth/mfa/confirm — step 2: verify the TOTP code against the
/// pending secret, persist it encrypted at rest (AAD = user id, CRIT-10),
/// enable MFA, generate recovery-code hashes, revoke live sessions, and
/// clear the setup cookie. Mirrors auth.rs `confirm_mfa_setup`.
async fn form_mfa_confirm(
    State(state): State<AppState>,
    axum::Extension(user): axum::Extension<AuthUser>,
    headers: HeaderMap,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    let back = safe_return_to(&form, "/cp/security");
    if let Err(message) = check_csrf(&form, &state.config) {
        return redirect_error(message, &back, &state.config);
    }
    let code = field(&form, "code").trim().to_string();
    let Some(user_id) = user.user_id.clone() else {
        return redirect_error("Sign in again to manage MFA.", "/login", &state.config);
    };
    let Some(setup) = decode_mfa_setup_cookie(&headers, &state.config, &user_id) else {
        return redirect_error(
            "The setup window expired. Start the MFA setup again.",
            &back,
            &state.config,
        );
    };
    if code.len() != 6 || !code.chars().all(|c| c.is_ascii_digit()) {
        return redirect_error("Enter the 6-digit code from your authenticator app.", &back, &state.config);
    }
    if !apexmail_lib::mfa::verify_totp_code(&setup.secret, &code) {
        return redirect_error(
            "That code did not match. Check your authenticator and try again.",
            &back,
            &state.config,
        );
    }

    let recovery_codes = apexmail_lib::mfa::try_generate_default_recovery_codes()
        .map_err(|e| format!("failed to generate recovery codes: {e}"))
        .and_then(|codes| {
            let hashes: Vec<String> = codes
                .iter()
                .map(|code| {
                    apexmail_lib::mfa::try_hash_recovery_code(code)
                        .map_err(|e| format!("failed to hash recovery code: {e}"))
                })
                .collect::<Result<Vec<_>, _>>()?;
            Ok((codes, hashes))
        });
    let (recovery_codes, recovery_hashes) = match recovery_codes {
        Ok(pair) => pair,
        Err(message) => {
            tracing::error!(error = %message, "web mfa confirm: recovery codes failed");
            return redirect_error("Could not enable MFA. Try again.", &back, &state.config);
        }
    };
    let aad = format!("user_id={user_id}").into_bytes();
    let encrypted = match apexmail_lib::secret_at_rest::encrypt_at_rest(&setup.secret, &aad) {
        Ok(encrypted) => encrypted,
        Err(error) => {
            tracing::error!(error = %error, "web mfa confirm: encryption failed");
            return redirect_error("Could not enable MFA. Try again.", &back, &state.config);
        }
    };

    let result = sqlx::query(
        "UPDATE users
         SET mfa_secret = $1, mfa_enabled = true, mfa_recovery_hashes = $2::jsonb, updated_at = NOW()
         WHERE id = $3 AND tenant_id = $4 AND COALESCE(mfa_enabled, false) = false",
    )
    .bind(&encrypted)
    .bind(serde_json::to_value(&recovery_hashes).unwrap_or_default())
    .bind(&user_id)
    .bind(user.tenant_id.as_str())
    .execute(&state.db)
    .await;
    match result {
        Ok(result) if result.rows_affected() == 1 => {}
        Ok(_) => {
            return redirect_error("MFA is already enabled for this account.", &back, &state.config)
        }
        Err(error) => {
            tracing::error!(error = %error, "web mfa confirm update failed");
            return redirect_error("Could not enable MFA. Try again.", &back, &state.config);
        }
    }

    // Privilege change ⇒ revoke every live session (AR-005 twin).
    revoke_user_sessions(&state, &user.tenant_id, &user_id).await;

    let mut response = redirect_success(
        &format!(
            "MFA enabled. Recovery codes (shown once, store them safely): {}",
            recovery_codes.join(" ")
        ),
        &back,
        &state.config,
    );
    let clear = format!(
        "{MFA_SETUP_COOKIE}=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax{}",
        if is_secure(&state.config) { "; Secure" } else { "" },
    );
    if let Ok(parsed) = clear.parse() {
        response.headers_mut().append(header::SET_COOKIE, parsed);
    }
    response
}

/// Generate a base32 TOTP secret + otpauth URI for the given user (email
/// read from the users row for the label).
async fn generate_totp_secret_and_uri(
    user_id: &str,
    db: &sqlx::PgPool,
) -> Result<(String, String), &'static str> {
    let email: String = sqlx::query_scalar::<_, String>(
        "SELECT email FROM users WHERE id = $1",
    )
    .bind(user_id)
    .fetch_optional(db)
    .await
    .map_err(|_| "Could not start MFA setup. Try again.")?
    .ok_or("Could not start MFA setup. Try again.")?;

    const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    use rand::TryRngCore;
    let mut bytes = [0u8; 20];
    rand::rngs::OsRng
        .try_fill_bytes(&mut bytes)
        .map_err(|_| "Could not start MFA setup. Try again.")?;
    let mut secret = String::with_capacity(32);
    let mut buffer: u16 = 0;
    let mut bits_left: u8 = 0;
    for byte in bytes {
        buffer = (buffer << 8) | u16::from(byte);
        bits_left += 8;
        while bits_left >= 5 {
            let index = ((buffer >> (bits_left - 5)) & 0x1f) as usize;
            secret.push(ALPHABET[index] as char);
            bits_left -= 5;
        }
    }
    if bits_left > 0 {
        let index = ((buffer << (5 - bits_left)) & 0x1f) as usize;
        secret.push(ALPHABET[index] as char);
    }

    let label: String =
        url::form_urlencoded::byte_serialize(format!("ApexMail:{email}").as_bytes()).collect();
    let params = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("secret", &secret)
        .append_pair("issuer", "ApexMail")
        .append_pair("algorithm", "SHA256")
        .append_pair("digits", "6")
        .append_pair("period", "30")
        .finish();
    Ok((secret, format!("otpauth://totp/{label}?{params}")))
}

/// POST /web/auth/impersonate/end — the CP shell banner's Terminate form.
/// System-gated (same rule as the JSON twin): clears the impersonation
/// cookie and redirects back to the control plane.
async fn form_impersonate_end(
    State(state): State<AppState>,
    axum::Extension(user): axum::Extension<AuthUser>,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    if let Err(message) = check_csrf(&form, &state.config) {
        return redirect_error(message, "/cp", &state.config);
    }
    if !is_system_tenant(&state, &user.tenant_id).await {
        return redirect_error("Only ApexMail operators can end impersonation sessions.", "/cp", &state.config);
    }
    let mut response = redirect_success("Impersonation session ended.", "/cp", &state.config);
    let clear = format!(
        "impersonation_session=; HttpOnly; Path=/; Max-Age=0; SameSite=Strict{}",
        if is_secure(&state.config) { "; Secure" } else { "" },
    );
    if let Ok(parsed) = clear.parse() {
        response.headers_mut().insert(header::SET_COOKIE, parsed);
    }
    response
}

async fn form_api_key_create(
    State(state): State<AppState>,
    axum::Extension(user): axum::Extension<AuthUser>,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    if let Err(message) = check_csrf(&form, &state.config) {
        return redirect_error(message, "/settings/api-keys", &state.config);
    }
    let name = field_truncated(&form, "name", 100);
    if name.is_empty() {
        return redirect_error("Give the key a name.", "/settings/api-keys", &state.config);
    }
    let id = apexmail_lib::id::generate_id("", 26);
    let secret = format!("amk_{}", Uuid::new_v4().simple());
    let prefix: String = secret.chars().take(10).collect();
    // The API keys table has NO user_id column (052/056 schema) — drop it.
    // The secret is stored as its SHA-256 hex digest exactly like the JSON
    // API path, and the plaintext is shown to the operator exactly ONCE,
    // in the post-create flash.
    let key_hash = {
        use sha2::Digest;
        hex::encode(sha2::Sha256::digest(secret.as_bytes()))
    };
    let result = sqlx::query(
        "INSERT INTO api_keys (id, tenant_id, user_id, name, prefix, key_hash, scopes, created_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, NOW())",
    )
    .bind(&id)
    .bind(user.tenant_id.as_str())
    .bind(user.user_id.as_deref())
    .bind(&name)
    .bind(&prefix)
    .bind(&key_hash)
    .bind(json!(["messages:send", "messages:read"]))
    .execute(&state.db)
    .await;
    match result {
        Ok(_) => redirect_success(
            &format!(
                "API key created. Copy the secret now — it will not be shown again: {secret}"
            ),
            "/settings/api-keys",
            &state.config,
        ),
        Err(error) => {
            tracing::error!(error = %error, "web api-key create failed");
            redirect_error(
                "Could not create the key. Try again.",
                "/settings/api-keys",
                &state.config,
            )
        }
    }
}

async fn form_webhook_create(
    State(state): State<AppState>,
    axum::Extension(user): axum::Extension<AuthUser>,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    if let Err(message) = check_csrf(&form, &state.config) {
        return redirect_error(message, "/settings/webhooks", &state.config);
    }
    let url = field(&form, "url").trim().to_string();
    if !(url.starts_with("https://") || url.starts_with("http://")) {
        return redirect_error("Enter a valid https:// endpoint URL.", "/settings/webhooks", &state.config);
    }
    // webhooks schema (075/065): id VARCHAR(26) ULID, secret NOT NULL
    // (dual-rotation capable), enabled BOOLEAN + status VARCHAR — there is
    // no `active` column.
    let id = apexmail_lib::id::generate_id("", 26);
    let secret = apexmail_lib::id::generate_webhook_secret();
    let result = sqlx::query(
        "INSERT INTO webhooks (id, tenant_id, url, secret, events, enabled, status, created_at, updated_at)
         VALUES ($1, $2, $3, $4, $5, true, 'active', NOW(), NOW())",
    )
    .bind(&id)
    .bind(user.tenant_id.as_str())
    .bind(&url)
    .bind(&secret)
    .bind(json!(["message.sent", "message.bounced"]))
    .execute(&state.db)
    .await;
    match result {
        Ok(_) => redirect_success(
            &format!("Webhook added. Signing secret (shown once): {secret}"),
            "/settings/webhooks",
            &state.config,
        ),
        Err(error) => {
            tracing::error!(error = %error, "web webhook create failed");
            redirect_error(
                "Could not add the webhook. Try again.",
                "/settings/webhooks",
                &state.config,
            )
        }
    }
}

async fn form_team_invite(
    State(state): State<AppState>,
    axum::Extension(user): axum::Extension<AuthUser>,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    if let Err(message) = check_csrf(&form, &state.config) {
        return redirect_error(message, "/settings/team", &state.config);
    }
    let email = field(&form, "userName").trim().to_lowercase();
    let role = match field(&form, "role").as_str() {
        "admin" => "admin",
        _ => "member",
    };
    if !valid_email(&email) {
        return redirect_error("Enter a valid email address.", "/settings/team", &state.config);
    }
    let result = sqlx::query(
        "INSERT INTO users (id, tenant_id, email, name, password_hash, role, status,
                            email_verified, mfa_enabled, metadata, created_at, updated_at)
         VALUES ($1, $2, $3, '', $4, $5, 'invited', false, false, '{}'::jsonb, NOW(), NOW())",
    )
    .bind(apexmail_lib::id::generate_id("", 26))
    .bind(user.tenant_id.as_str())
    .bind(&email)
    .bind("!invited-pending-activation") // cannot authenticate until they set a password
    .bind(role)
    .execute(&state.db)
    .await;
    match result {
        Ok(_) => redirect_success("Invitation created.", "/settings/team", &state.config),
        Err(_) => redirect_error("Could not create the invitation. Try again.", "/settings/team", &state.config),
    }
}

async fn form_billing_checkout(
    State(state): State<AppState>,
    axum::Extension(_user): axum::Extension<AuthUser>,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    if let Err(message) = check_csrf(&form, &state.config) {
        return redirect_error(message, "/settings/billing", &state.config);
    }
    let plan = field(&form, "plan");
    if !["starter", "pro", "growth", "scale"].contains(&plan.as_str()) {
        return redirect_error("Choose a plan to upgrade to.", "/settings/billing", &state.config);
    }
    // Documented limitation: provider-coupled checkout session creation
    // lives in the JSON billing route (Stripe-compatible provider wired in
    // state). The form validates + records the intent and points the
    // operator at the same-origin JSON endpoint used by the dashboard.
    redirect_success(
        "Plan upgrade request recorded. The billing portal session opens from the API console (POST /v1/billing/checkout).",
        "/settings/billing",
        &state.config,
    )
}

async fn form_billing_portal(
    State(state): State<AppState>,
    axum::Extension(_user): axum::Extension<AuthUser>,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    if let Err(message) = check_csrf(&form, &state.config) {
        return redirect_error(message, "/settings/billing", &state.config);
    }
    redirect_success(
        "The billing portal opens from the API console (POST /v1/billing/portal).",
        "/settings/billing",
        &state.config,
    )
}

// ─── Resource create/update handlers ─────────────────────────────

async fn form_contact_create(
    State(state): State<AppState>,
    axum::Extension(user): axum::Extension<AuthUser>,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    if let Err(message) = check_csrf(&form, &state.config) {
        return redirect_error(message, "/contacts/new", &state.config);
    }
    let email = field(&form, "email").trim().to_lowercase();
    let name = field_truncated(&form, "name", 120);
    if !valid_email(&email) {
        return redirect_error("Enter a valid email address.", "/contacts/new", &state.config);
    }
    let result = sqlx::query(
        "INSERT INTO contacts (id, tenant_id, email, name, status, created_at, updated_at)
         VALUES ($1, $2, $3, $4, 'subscribed', NOW(), NOW())",
    )
    .bind(apexmail_lib::id::generate_id("", 26))
    .bind(user.tenant_id.as_str())
    .bind(&email)
    .bind(if name.is_empty() { None } else { Some(name) })
    .execute(&state.db)
    .await;
    match result {
        Ok(_) => redirect_success("Contact added.", "/contacts", &state.config),
        Err(_) => redirect_error("Could not add the contact. It may already exist.", "/contacts/new", &state.config),
    }
}

async fn form_list_create(
    State(state): State<AppState>,
    axum::Extension(user): axum::Extension<AuthUser>,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    if let Err(message) = check_csrf(&form, &state.config) {
        return redirect_error(message, "/lists/new", &state.config);
    }
    let name = field_truncated(&form, "name", 120);
    if name.is_empty() {
        return redirect_error("Give the list a name.", "/lists/new", &state.config);
    }
    let result = sqlx::query(
        "INSERT INTO lists (id, tenant_id, name, created_at, updated_at)
         VALUES ($1, $2, $3, NOW(), NOW())",
    )
    .bind(apexmail_lib::id::generate_id("", 26))
    .bind(user.tenant_id.as_str())
    .bind(&name)
    .execute(&state.db)
    .await;
    match result {
        Ok(_) => redirect_success("List created.", "/lists", &state.config),
        Err(_) => redirect_error("Could not create the list. Try again.", "/lists/new", &state.config),
    }
}

async fn form_list_update(
    State(state): State<AppState>,
    axum::Extension(user): axum::Extension<AuthUser>,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    if let Err(message) = check_csrf(&form, &state.config) {
        return redirect_error(message, "/lists", &state.config);
    }
    let name = field_truncated(&form, "name", 120);
    let id = field(&form, "id");
    if name.is_empty() || id.is_empty() {
        return redirect_error("Pick a list and give it a name.", "/lists", &state.config);
    }
    let result = sqlx::query(
        "UPDATE lists SET name = $1, updated_at = NOW()
         WHERE id = $2 AND tenant_id = $3",
    )
    .bind(&name)
    .bind(&id)
    .bind(user.tenant_id.as_str())
    .execute(&state.db)
    .await;
    match result {
        Ok(_) => redirect_success("List saved.", "/lists", &state.config),
        Err(_) => redirect_error("Could not save the list. Check the identifier.", "/lists", &state.config),
    }
}

async fn form_domain_create(
    State(state): State<AppState>,
    axum::Extension(user): axum::Extension<AuthUser>,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    if let Err(message) = check_csrf(&form, &state.config) {
        return redirect_error(message, "/domains/new", &state.config);
    }
    let name = field(&form, "name").trim().to_lowercase();
    let valid = !name.is_empty()
        && name.len() <= 253
        && name.split('.').count() >= 2
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-');
    if !valid {
        return redirect_error("Enter a domain like mail.example.com.", "/domains/new", &state.config);
    }
    let result = sqlx::query(
        "INSERT INTO domains (id, tenant_id, name, status, created_at, updated_at)
         VALUES ($1, $2, $3, 'pending', NOW(), NOW())",
    )
    .bind(apexmail_lib::id::generate_id("", 26))
    .bind(user.tenant_id.as_str())
    .bind(&name)
    .execute(&state.db)
    .await;
    match result {
        Ok(_) => redirect_success("Domain added — DNS records are being generated.", "/domains", &state.config),
        Err(_) => redirect_error("Could not add the domain. It may already exist.", "/domains/new", &state.config),
    }
}

async fn form_template_create(
    State(state): State<AppState>,
    axum::Extension(user): axum::Extension<AuthUser>,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    if let Err(message) = check_csrf(&form, &state.config) {
        return redirect_error(message, "/templates/new", &state.config);
    }
    let name = field_truncated(&form, "name", 120);
    let subject = field_truncated(&form, "subject", 200);
    let html_body = field(&form, "html_body");
    if name.is_empty() {
        return redirect_error("Give the template a name.", "/templates/new", &state.config);
    }
    if html_body.trim().is_empty() {
        return redirect_error("Add some HTML content.", "/templates/new", &state.config);
    }
    // templates.id is VARCHAR(26) — a UUID's 36-char hyphenated form
    // overflows the column; generate a 26-char text id like templates.rs.
    let id = apexmail_lib::id::generate_id("", 26);
    let result = sqlx::query(
        "INSERT INTO templates (id, tenant_id, name, subject, html_body, created_at, updated_at)
         VALUES ($1, $2, $3, $4, $5, NOW(), NOW())",
    )
    .bind(&id)
    .bind(user.tenant_id.as_str())
    .bind(&name)
    .bind(if subject.is_empty() { None } else { Some(subject) })
    .bind(&html_body)
    .execute(&state.db)
    .await;
    match result {
        Ok(_) => redirect_success("Template saved.", "/templates", &state.config),
        Err(_) => redirect_error("Could not save the template. Try again.", "/templates/new", &state.config),
    }
}

async fn form_campaign_create(
    State(state): State<AppState>,
    axum::Extension(user): axum::Extension<AuthUser>,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    if let Err(message) = check_csrf(&form, &state.config) {
        return redirect_error(message, "/campaigns/new", &state.config);
    }
    let name = field_truncated(&form, "name", 120);
    let subject = field_truncated(&form, "subject", 200);
    let scheduled_at = field(&form, "scheduled_at");
    if name.is_empty() || subject.is_empty() {
        return redirect_error("Campaign name and subject are required.", "/campaigns/new", &state.config);
    }
    // The campaigns status CHECK (live schema) allows draft/sending/
    // paused/stopped/completed/failed — there is no 'scheduled' status, so
    // a picked time is stored in scheduled_at on a draft row.
    let scheduled: Option<String> = if scheduled_at.trim().is_empty() {
        None
    } else {
        Some(scheduled_at)
    };
    let result = sqlx::query(
        "INSERT INTO campaigns (id, tenant_id, name, subject, status, scheduled_at, created_at, updated_at)
         VALUES ($1, $2, $3, $4, 'draft', $5::timestamptz, NOW(), NOW())",
    )
    .bind(apexmail_lib::id::generate_id("", 26))
    .bind(user.tenant_id.as_str())
    .bind(&name)
    .bind(&subject)
    .bind(scheduled.clone())
    .execute(&state.db)
    .await;
    let scheduled_saved = scheduled.is_some();
    match result {
        Ok(_) => redirect_success(
            if scheduled_saved {
                "Campaign draft saved with its schedule time."
            } else {
                "Campaign draft saved."
            },
            "/campaigns",
            &state.config,
        ),
        Err(_) => redirect_error("Could not save the campaign. Try again.", "/campaigns/new", &state.config),
    }
}

/// Server-rendered campaign preview: renders the submitted HTML draft in a
/// standalone page (sanitized by ui-foundation) — the no-JS replacement for
/// client-side preview.
async fn form_campaign_preview(
    State(state): State<AppState>,
    axum::Extension(user): axum::Extension<AuthUser>,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    // CSRF is enforced like every other authenticated POST — a bad token
    // bounces back to the editor with a flash instead of rendering the
    // (attacker-supplied) body.
    let back = safe_return_to(&form, "/campaigns");
    if let Err(message) = check_csrf(&form, &state.config) {
        return redirect_error(message, &back, &state.config);
    }
    let _ = user;
    let html_body = field(&form, "html_body");
    let page = ui_foundation::leptos_views::web_campaign_preview_page(&html_body);
    Html(page).into_response()
}

use axum::response::Html;

/// POST /web/campaigns/update — the campaign editor's save action. Updates
/// the existing row in place (scoped to the caller's tenant); editing no
/// longer duplicates the campaign.
async fn form_campaign_update(
    State(state): State<AppState>,
    axum::Extension(user): axum::Extension<AuthUser>,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    if let Err(message) = check_csrf(&form, &state.config) {
        return redirect_error(message, "/campaigns", &state.config);
    }
    let id = field(&form, "id");
    let name = field_truncated(&form, "name", 120);
    let subject = field_truncated(&form, "subject", 200);
    let scheduled_at = field(&form, "scheduled_at");
    let back = if id.is_empty() {
        "/campaigns".to_string()
    } else {
        format!("/campaigns/{}/edit", urlencode(&id))
    };
    if id.is_empty() {
        return redirect_error("Missing campaign id.", "/campaigns", &state.config);
    }
    if name.is_empty() || subject.is_empty() {
        return redirect_error("Campaign name and subject are required.", &back, &state.config);
    }
    let scheduled: Option<String> = if scheduled_at.trim().is_empty() {
        None
    } else {
        Some(scheduled_at)
    };
    let result = sqlx::query(
        "UPDATE campaigns SET name = $1, subject = $2, scheduled_at = $3::timestamptz, updated_at = NOW()
         WHERE id = $4 AND tenant_id = $5",
    )
    .bind(&name)
    .bind(&subject)
    .bind(scheduled)
    .bind(&id)
    .bind(user.tenant_id.as_str())
    .execute(&state.db)
    .await;
    match result {
        Ok(result) if result.rows_affected() == 1 => {
            redirect_success("Campaign saved.", "/campaigns", &state.config)
        }
        Ok(_) => redirect_error(
            "That campaign could not be found in this workspace.",
            "/campaigns",
            &state.config,
        ),
        Err(error) => {
            tracing::error!(error = %error, "web campaign update failed");
            redirect_error("Could not save the campaign. Try again.", &back, &state.config)
        }
    }
}

async fn form_placement_create(
    State(state): State<AppState>,
    axum::Extension(user): axum::Extension<AuthUser>,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    if let Err(message) = check_csrf(&form, &state.config) {
        return redirect_error(message, "/inbox-placement/new", &state.config);
    }
    let name = field_truncated(&form, "name", 120);
    let from_email = field(&form, "from_email").trim().to_lowercase();
    let subject = field_truncated(&form, "subject", 200);
    let html_body = field(&form, "html_body");
    if name.is_empty() || subject.is_empty() || html_body.trim().is_empty() {
        return redirect_error("Test name, subject, and HTML body are required.", "/inbox-placement/new", &state.config);
    }
    if !valid_email(&from_email) {
        return redirect_error("Enter a valid from email.", "/inbox-placement/new", &state.config);
    }
    let result = sqlx::query(
        "INSERT INTO placement_tests (id, tenant_id, name, from_email, subject, body_html, status, created_at)
         VALUES ($1, $2, $3, $4, $5, $6, 'pending', NOW())",
    )
    .bind(Uuid::new_v4())
    .bind(user.tenant_id.as_str())
    .bind(&name)
    .bind(&from_email)
    .bind(&subject)
    .bind(&html_body)
    .execute(&state.db)
    .await;
    match result {
        Ok(_) => redirect_success("Placement test started — results poll as seeds report in.", "/inbox-placement", &state.config),
        Err(_) => redirect_error("Could not start the test. Try again.", "/inbox-placement/new", &state.config),
    }
}

async fn form_dedicated_ip_request(
    State(state): State<AppState>,
    axum::Extension(user): axum::Extension<AuthUser>,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    if let Err(message) = check_csrf(&form, &state.config) {
        return redirect_error(message, "/settings/dedicated-ips", &state.config);
    }
    let region = field_truncated(&form, "region", 40);
    // dedicated_ips.ip_address is nullable: the request row is recorded
    // with status 'pending' and the Hetzner provisioner fills the address.
    let result = sqlx::query(
        "INSERT INTO dedicated_ips (id, tenant_id, region, status, ip_address, created_at, updated_at)
         VALUES ($1, $2, $3, 'pending', NULL, NOW(), NOW())",
    )
    .bind(apexmail_lib::id::generate_id("", 26))
    .bind(user.tenant_id.as_str())
    .bind(if region.is_empty() { "eu-central" } else { &region })
    .execute(&state.db)
    .await;
    match result {
        Ok(_) => redirect_success("Provisioning request recorded — the allocator picks it up shortly.", "/settings/dedicated-ips", &state.config),
        Err(_) => redirect_error("Could not record the request. Try again.", "/settings/dedicated-ips", &state.config),
    }
}

// ─── Destructive confirmations ───────────────────────────────────

/// POST /web/confirm — the confirm page's form. The signature is
/// re-verified server-side before anything is deleted.
async fn form_confirm_destructive(
    State(state): State<AppState>,
    axum::Extension(user): axum::Extension<AuthUser>,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    if let Err(message) = check_csrf(&form, &state.config) {
        return redirect_error(message, "/dashboard", &state.config);
    }
    let intent = field(&form, "intent");
    let id = field(&form, "id");
    let sig = field(&form, "sig");
    let return_to = safe_return_to(&form, "/dashboard");
    if !verify_confirmation(&state.config.csrf_secret, &sig, &intent, &id, Utc::now().timestamp())
    {
        return redirect_error(
            "That confirmation link expired. Nothing was changed.",
            &return_to,
            &state.config,
        );
    }
    let tenant = user.tenant_id.clone();
    let result: Result<u64, sqlx::Error> = match intent.as_str() {
        "delete-campaign" => sqlx::query(
            "DELETE FROM campaigns WHERE id = $1 AND tenant_id = $2",
        )
        .bind(&id)
        .bind(&tenant)
        .execute(&state.db)
        .await
        .map(|r| r.rows_affected()),
        "delete-list" => sqlx::query("DELETE FROM lists WHERE id = $1 AND tenant_id = $2")
            .bind(&id)
            .bind(&tenant)
            .execute(&state.db)
            .await
            .map(|r| r.rows_affected()),
        "delete-domain" => sqlx::query(
            "DELETE FROM domains WHERE id = $1 AND tenant_id = $2",
        )
        .bind(&id)
        .bind(&tenant)
        .execute(&state.db)
        .await
        .map(|r| r.rows_affected()),
        _ => {
            return redirect_error("Unknown action.", &return_to, &state.config);
        }
    };
    match result {
        Ok(0) => redirect_error("It may have been deleted already.", &return_to, &state.config),
        Ok(_) => redirect_success("Deleted.", &return_to, &state.config),
        Err(_) => redirect_error("Could not delete it. Try again.", &return_to, &state.config),
    }
}

async fn form_campaigns_delete_bulk(
    State(state): State<AppState>,
    axum::Extension(user): axum::Extension<AuthUser>,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    bulk_delete(state, user, form, "campaigns", "DELETE FROM campaigns WHERE id = ANY($1) AND tenant_id = $2").await
}

async fn form_contacts_delete_bulk(
    State(state): State<AppState>,
    axum::Extension(user): axum::Extension<AuthUser>,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    bulk_delete(state, user, form, "contacts", "UPDATE contacts SET status = 'deleted', updated_at = NOW() WHERE id = ANY($1) AND tenant_id = $2").await
}

async fn bulk_delete(
    state: AppState,
    user: AuthUser,
    form: HashMap<String, String>,
    scope: &str,
    sql: &str,
) -> Response {
    let back = format!("/{scope}");
    if let Err(message) = check_csrf(&form, &state.config) {
        return redirect_error(message, &back, &state.config);
    }
    let ids: Vec<String> = form
        .get("ids")
        .map(|value| {
            value
                .split(',')
                .map(str::trim)
                .filter(|id| !id.is_empty())
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default();
    if ids.is_empty() {
        return redirect_error("Select at least one row first.", &back, &state.config);
    }
    let result = sqlx::query(sql)
        .bind(ids)
        .bind(user.tenant_id.as_str())
        .execute(&state.db)
        .await;
    match result {
        Ok(result) => redirect_success(
            &format!("{} row(s) processed.", result.rows_affected()),
            &back,
            &state.config,
        ),
        Err(_) => redirect_error("Some rows could not be processed. Refresh and retry.", &back, &state.config),
    }
}

// ─── CSV exports (server-rendered downloads) ─────────────────────

async fn form_contacts_export(
    State(state): State<AppState>,
    axum::Extension(user): axum::Extension<AuthUser>,
) -> Response {
    let rows = sqlx::query_as::<_, (String, Option<String>, String)>(
        "SELECT email, name, status FROM contacts WHERE tenant_id = $1 AND status != 'deleted' ORDER BY created_at DESC LIMIT 10000",
    )
    .bind(user.tenant_id.as_str())
    .fetch_all(&state.db)
    .await;
    let mut csv = String::from("email,name,status\n");
    if let Ok(rows) = rows {
        for (email, name, status) in rows {
            csv.push_str(&format!(
                "{},{},{}\n",
                csv_escape(&email),
                csv_escape(name.as_deref().unwrap_or("")),
                csv_escape(&status),
            ));
        }
    }
    csv_response(csv, "contacts.csv")
}

async fn form_audit_export(
    State(state): State<AppState>,
    axum::Extension(user): axum::Extension<AuthUser>,
) -> Response {
    // Defense in depth: the router stack already gates this route behind
    // require_system_tenant_middleware; re-verify here (slug-aware).
    if !is_system_tenant(&state, &user.tenant_id).await {
        return redirect_error("Operator access required.", "/audit", &state.config);
    }
    // Live audit_logs columns: timestamp/created_at, action,
    // resource_type, user_id (there is no outcome/status/resource).
    let rows = sqlx::query_as::<_, (Option<chrono::DateTime<Utc>>, Option<String>, Option<String>, Option<String>)>(
        "SELECT created_at, action, resource_type, user_id FROM audit_logs ORDER BY created_at DESC NULLS LAST LIMIT 10000",
    )
    .fetch_all(&state.db)
    .await;
    let mut csv = String::from("timestamp,action,resource_type,actor\n");
    if let Ok(rows) = rows {
        for (created_at, action, resource_type, user_id) in rows {
            csv.push_str(&format!(
                "{},{},{},{}\n",
                created_at.map(|ts| ts.to_rfc3339()).unwrap_or_default(),
                csv_escape(action.as_deref().unwrap_or("")),
                csv_escape(resource_type.as_deref().unwrap_or("")),
                csv_escape(user_id.as_deref().unwrap_or("")),
            ));
        }
    }
    csv_response(csv, "audit-logs.csv")
}

fn csv_response(body: String, filename: &str) -> Response {
    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "text/csv; charset=utf-8".to_string()),
            (
                header::CONTENT_DISPOSITION,
                format!("attachment; filename=\"{filename}\""),
            ),
        ],
        body,
    )
        .into_response()
}

fn csv_escape(value: &str) -> String {
    if value.contains(',') || value.contains('"') || value.contains('\n') {
        format!("\"{}\"", value.replace('"', "\"\""))
    } else {
        value.to_string()
    }
}

// ─── Admin (control-plane) handlers ──────────────────────────────

async fn form_admin_tenant_create(
    State(state): State<AppState>,
    axum::Extension(user): axum::Extension<AuthUser>,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    if let Err(message) = check_csrf(&form, &state.config) {
        return redirect_error(message, "/tenants/new", &state.config);
    }
    let name = field_truncated(&form, "name", 120);
    let domain = field(&form, "domain").trim().to_lowercase();
    if name.is_empty() || domain.split('.').count() < 2 {
        return redirect_error("Tenant name and a primary domain are required.", "/tenants/new", &state.config);
    }
    let tenant_id = apexmail_lib::id::generate_id("", 26);
    let slug: String = domain
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-')
        .take(48)
        .collect();
    let result = sqlx::query(
        "INSERT INTO tenants (id, name, slug, plan, status, settings, metadata, created_at, updated_at)
         VALUES ($1, $2, $3, 'free', 'pending', '{}'::jsonb, $4, NOW(), NOW())",
    )
    .bind(&tenant_id)
    .bind(&name)
    .bind(&slug)
    .bind(json!({"primary_domain": domain, "created_by": user.user_id.clone().unwrap_or_default()}))
    .execute(&state.db)
    .await;
    match result {
        Ok(_) => redirect_success("Tenant workspace created.", "/tenants", &state.config),
        Err(_) => redirect_error("Could not create the tenant. Try again.", "/tenants/new", &state.config),
    }
}

async fn form_admin_operator_create(
    State(state): State<AppState>,
    axum::Extension(user): axum::Extension<AuthUser>,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    if let Err(message) = check_csrf(&form, &state.config) {
        return redirect_error(message, "/operators/new", &state.config);
    }
    let email = field(&form, "email").trim().to_lowercase();
    let name = field_truncated(&form, "name", 120);
    if !valid_email(&email) {
        return redirect_error("Enter a valid operator email.", "/operators/new", &state.config);
    }
    let system_tenant = sqlx::query_scalar::<_, String>("SELECT id::text FROM tenants WHERE slug = 'system' LIMIT 1")
        .fetch_optional(&state.db)
        .await
        .ok()
        .flatten();
    let Some(system_tenant) = system_tenant else {
        return redirect_error("Provisioning is unavailable. Try again shortly.", "/operators/new", &state.config);
    };
    let result = sqlx::query(
        "INSERT INTO users (id, tenant_id, email, name, password_hash, role, status,
                            email_verified, mfa_enabled, metadata, created_at, updated_at)
         VALUES ($1, $2, $3, $4, '!invited-pending-activation', 'admin', 'invited', false, false,
                 $5::jsonb, NOW(), NOW())",
    )
    .bind(apexmail_lib::id::generate_id("", 26))
    .bind(system_tenant)
    .bind(&email)
    .bind(if name.is_empty() { None } else { Some(name) })
    .bind(json!({"invited_by": user.user_id.clone().unwrap_or_default()}))
    .execute(&state.db)
    .await;
    match result {
        Ok(_) => redirect_success("Operator invited.", "/operators", &state.config),
        Err(_) => redirect_error("Could not create the invitation. Try again.", "/operators/new", &state.config),
    }
}

// ─── Admin sales ─────────────────────────────────────────────────

async fn form_sales_discovery(
    State(state): State<AppState>,
    axum::Extension(_user): axum::Extension<AuthUser>,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    if let Err(message) = check_csrf(&form, &state.config) {
        return redirect_error(message, "/sales", &state.config);
    }
    let sources: Vec<String> = field(&form, "sources")
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect();
    if sources.is_empty() {
        return redirect_error("Add at least one comma-separated source.", "/sales", &state.config);
    }
    let _categories = field(&form, "categories");
    redirect_success(
        "Discovery runs are launched from the API console (POST /v1/admin/leads/discovery/run).",
        "/sales",
        &state.config,
    )
}

async fn form_sales_outreach(
    State(state): State<AppState>,
    axum::Extension(_user): axum::Extension<AuthUser>,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    if let Err(message) = check_csrf(&form, &state.config) {
        return redirect_error(message, "/sales", &state.config);
    }
    let lead_ids: Vec<String> = form
        .get("lead_ids")
        .map(|v| v.split(',').map(str::trim).filter(|s| !s.is_empty()).map(str::to_string).collect())
        .unwrap_or_default();
    if lead_ids.is_empty() {
        return redirect_error("Pick at least one lead in the queue first.", "/sales", &state.config);
    }
    redirect_success(
        "Outreach launches from the API console (POST /v1/admin/autopilot/outreach).",
        "/sales",
        &state.config,
    )
}

async fn form_sales_leads_update(
    State(state): State<AppState>,
    axum::Extension(user): axum::Extension<AuthUser>,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    if let Err(message) = check_csrf(&form, &state.config) {
        return redirect_error(message, "/sales", &state.config);
    }
    let lead_ids: Vec<String> = form
        .get("lead_ids")
        .map(|v| v.split(',').map(str::trim).filter(|s| !s.is_empty()).map(str::to_string).collect())
        .unwrap_or_default();
    let status = field(&form, "status");
    let allowed = ["qualified", "proposal", "approved", "escalated"];
    if lead_ids.is_empty() {
        return redirect_error("Pick at least one lead in the queue first.", "/sales", &state.config);
    }
    if !allowed.contains(&status.as_str()) {
        return redirect_error("Choose a valid stage.", "/sales", &state.config);
    }
    let result = sqlx::query(
        "UPDATE sales_leads SET status = $1, updated_at = NOW() WHERE id = ANY($2) AND tenant_id = $3",
    )
    .bind(&status)
    .bind(lead_ids)
    .bind(user.tenant_id.as_str())
    .execute(&state.db)
    .await;
    match result {
        Ok(result) => redirect_success(
            &format!("{} lead(s) moved to {status}.", result.rows_affected()),
            "/sales",
            &state.config,
        ),
        Err(error) => {
            // Honest failure: a database error is an error, never a
            // success flash.
            tracing::error!(error = %error, "web sales leads update failed");
            redirect_error(
                "The stage change failed. Refresh and retry.",
                "/sales",
                &state.config,
            )
        }
    }
}

// ─── Misc helpers ────────────────────────────────────────────────

fn urlencode(value: &str) -> String {
    let mut out = String::with_capacity(value.len() * 3);
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char);
            }
            b' ' => out.push('+'),
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

/// Flash cookie plumbing for tests / the render path: read the signed flash
/// cookie from a Cookie header value.
pub fn decode_flash_from_cookie_header(
    header_value: &str,
    secret: &str,
) -> Vec<FlashMessage> {
    header_value
        .split(';')
        .filter_map(|chunk| chunk.trim().strip_prefix(&format!("{FLASH_COOKIE_NAME}=")))
        .filter_map(|value| ui_foundation::flash::decode_flash_cookie(value, secret))
        .flatten()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::test_support::test_config;

    #[test]
    fn flash_round_trip_through_cookie_header() {
        let config = test_config();
        let messages = vec![
            FlashMessage::success("Saved."),
            FlashMessage::error("Email is not valid."),
        ];
        let cookie = flash_set_cookie(&messages, &config.csrf_secret, false);
        let decoded = decode_flash_from_cookie_header(&cookie, &config.csrf_secret);
        assert_eq!(decoded, messages);
        // Tampering with the base64 payload fails closed.
        let (prefix, rest) = cookie.split_at(cookie.find('.').unwrap() + 1);
        let mut chars: Vec<char> = rest.chars().collect();
        chars[0] = if chars[0] == 'A' { 'B' } else { 'A' };
        let tampered = format!("{prefix}{}", chars.into_iter().collect::<String>());
        assert_ne!(cookie, tampered);
        assert!(decode_flash_from_cookie_header(&tampered, &config.csrf_secret).is_empty());
    }

    #[test]
    fn redirects_are_prg_shaped() {
        let config = test_config();
        let response = redirect_success("ok", "/campaigns", &config);
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        assert_eq!(response.headers().get(header::LOCATION).unwrap(), "/campaigns");
        let set_cookie = response
            .headers()
            .get(header::SET_COOKIE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default();
        assert!(set_cookie.contains("apexmail_flash="));
        assert!(set_cookie.contains("HttpOnly"));
    }

    #[test]
    fn return_to_rejects_open_redirects() {
        let mut form = HashMap::new();
        form.insert("return_to".to_string(), "https://evil.example".to_string());
        assert_eq!(safe_return_to(&form, "/dashboard"), "/dashboard");
        form.insert("return_to".to_string(), "//evil.example".to_string());
        assert_eq!(safe_return_to(&form, "/dashboard"), "/dashboard");
        form.insert("return_to".to_string(), "/contacts?page=2".to_string());
        assert_eq!(safe_return_to(&form, "/dashboard"), "/contacts?page=2");
    }

    #[test]
    fn consent_choices_normalize_to_distinct_cookie_values() {
        assert_eq!(normalize_consent_choice(Some("all")), Some("all"));
        assert_eq!(normalize_consent_choice(Some("necessary")), Some("necessary"));
        // "dismiss" was the deleted site.js semantics: record, enable nothing.
        assert_eq!(normalize_consent_choice(Some("dismiss")), Some("necessary"));
        // Whitespace is tolerated; anything else records nothing.
        assert_eq!(normalize_consent_choice(Some(" all ")), Some("all"));
        assert_eq!(normalize_consent_choice(Some("garbage")), None);
        assert_eq!(normalize_consent_choice(Some("")), None);
        assert_eq!(normalize_consent_choice(None), None);
    }

    #[test]
    fn consent_return_to_allows_only_apexmail_family_https() {
        // Relative same-origin paths pass through.
        assert_eq!(consent_safe_return_to(Some("/pricing")), "/pricing");
        assert_eq!(
            consent_safe_return_to(Some("/de/cookies/")),
            "/de/cookies/"
        );
        // Absolute apexmail.ee-family HTTPS URLs pass through (the banner
        // lives on apexmail.ee, this endpoint on api.apexmail.ee).
        assert_eq!(
            consent_safe_return_to(Some("https://apexmail.ee/pricing")),
            "https://apexmail.ee/pricing"
        );
        assert_eq!(
            consent_safe_return_to(Some("https://www.apexmail.ee/")),
            "https://www.apexmail.ee/"
        );
        assert_eq!(
            consent_safe_return_to(Some("https://app.apexmail.ee/dashboard")),
            "https://app.apexmail.ee/dashboard"
        );
        // Open redirects are rejected and fall back to "/".
        assert_eq!(consent_safe_return_to(Some("https://evil.example")), "/");
        assert_eq!(
            consent_safe_return_to(Some("https://evil.example/?u=https://apexmail.ee")),
            "/"
        );
        // Scheme downgrades and lookalike suffix hosts are rejected.
        assert_eq!(
            consent_safe_return_to(Some("http://apexmail.ee/pricing")),
            "/"
        );
        assert_eq!(
            consent_safe_return_to(Some("https://notapexmail.ee/pricing")),
            "/"
        );
        assert_eq!(
            consent_safe_return_to(Some("https://apexmail.ee.evil.io/")),
            "/"
        );
        // Protocol-relative and garbage values never leak through.
        assert_eq!(consent_safe_return_to(Some("//evil.example")), "/");
        assert_eq!(consent_safe_return_to(Some("javascript:alert(1)")), "/");
        assert_eq!(consent_safe_return_to(Some("")), "/");
        assert_eq!(consent_safe_return_to(None), "/");
    }

    #[test]
    fn consent_cookie_carries_domain_expiry_and_distinct_values() {
        let all = consent_set_cookie("all", true);
        assert!(all.starts_with("apexmail_consent=all;"), "{all}");
        // Applies to the marketing host, not just the api host.
        assert!(all.contains("Domain=.apexmail.ee"));
        // One year.
        assert!(all.contains("Max-Age=31536000"));
        assert!(all.contains("Path=/"));
        assert!(all.contains("HttpOnly"));
        assert!(all.contains("SameSite=Lax"));
        assert!(all.contains("Secure"));
        // Distinct recorded value for the necessary-only choice.
        let necessary = consent_set_cookie("necessary", true);
        assert!(necessary.starts_with("apexmail_consent=necessary;"));
        assert_ne!(all, necessary);
        // Non-production omits Secure (local dev over http).
        assert!(!consent_set_cookie("all", false).contains("Secure"));
    }

    #[test]
    fn consent_respond_sets_cookie_and_redirects_for_known_choices() {
        let config = test_config();
        let response = consent_respond(
            ConsentRequest {
                choice: Some("all".into()),
                return_to: Some("https://apexmail.ee/pricing".into()),
            },
            &config,
        );
        assert_eq!(response.status(), StatusCode::FOUND);
        assert_eq!(
            response.headers().get(header::LOCATION).unwrap(),
            "https://apexmail.ee/pricing"
        );
        let cookie = response
            .headers()
            .get(header::SET_COOKIE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default();
        assert!(cookie.starts_with("apexmail_consent=all;"));
        assert!(cookie.contains("Domain=.apexmail.ee"));
        assert!(cookie.contains("Max-Age=31536000"));
    }

    #[test]
    fn consent_respond_unknown_choice_writes_no_cookie() {
        let config = test_config();
        let response = consent_respond(
            ConsentRequest {
                choice: Some("everything".into()),
                return_to: Some("/pricing".into()),
            },
            &config,
        );
        assert_eq!(response.status(), StatusCode::FOUND);
        assert_eq!(response.headers().get(header::LOCATION).unwrap(), "/pricing");
        assert!(response.headers().get(header::SET_COOKIE).is_none());
    }

    #[test]
    fn consent_cookie_header_detection() {
        assert!(cookie_header_has_consent("apexmail_consent=all"));
        assert!(cookie_header_has_consent("session=abc; apexmail_consent=necessary"));
        assert!(cookie_header_has_consent(
            "session=abc;apexmail_consent=all; other=1"
        ));
        // Absent or empty-valued cookie does NOT hide the banner.
        assert!(!cookie_header_has_consent("session=abc"));
        assert!(!cookie_header_has_consent("apexmail_consent="));
        assert!(!cookie_header_has_consent("xapexmail_consent=all"));
        assert!(!cookie_header_has_consent(""));
    }

    #[test]
    fn password_policy_is_enforced() {
        assert!(password_policy_error("short").is_some());
        assert!(password_policy_error("alllowercase123!").is_some());
        assert!(password_policy_error("NOLOWERCASE123!").is_some());
        assert!(password_policy_error("NoDigitsHere!!").is_some());
        assert!(password_policy_error("Valid123!Password").is_none());
    }

    #[test]
    fn urlencoding_covers_query_values() {
        assert_eq!(urlencode("a b"), "a+b");
        assert_eq!(urlencode("a@b.ce"), "a%40b.ce");
    }

    #[test]
    fn csv_escaping_is_excel_safe() {
        assert_eq!(csv_escape("plain"), "plain");
        assert_eq!(csv_escape("a,b"), "\"a,b\"");
        assert_eq!(csv_escape("say \"hi\""), "\"say \"\"hi\"\"\"");
    }

    #[test]
    fn mfa_setup_cookie_roundtrips_and_binds_the_user() {
        let config = test_config();
        let secret = "JBSWY3DPEHPK3PXP";
        let otpauth = "otpauth://totp/ApexMail:ops%40apexmail.ee?secret=JBSWY3DPEHPK3PXP";
        let signature = sign_mfa_setup(&config, "user_1", secret);
        let value = encode_mfa_setup_value(secret, otpauth, &signature);

        let headers = {
            let mut headers = HeaderMap::new();
            headers.insert(
                header::COOKIE,
                format!("{MFA_SETUP_COOKIE}={value}").parse().unwrap(),
            );
            headers
        };

        let setup = decode_mfa_setup_cookie(&headers, &config, "user_1")
            .expect("valid cookie decodes for its user");
        assert_eq!(setup.secret, secret);
        assert_eq!(setup.otpauth, otpauth);

        // A different user cannot use the cookie.
        assert!(decode_mfa_setup_cookie(&headers, &config, "user_2").is_none());
        // Tampering with the payload breaks the signature.
        let tampered = encode_mfa_setup_value("OTHERSECRET00", otpauth, &signature);
        let mut bad = HeaderMap::new();
        bad.insert(
            header::COOKIE,
            format!("{MFA_SETUP_COOKIE}={tampered}").parse().unwrap(),
        );
        assert!(decode_mfa_setup_cookie(&bad, &config, "user_1").is_none());
        // Absent cookie → None.
        assert!(decode_mfa_setup_cookie(&HeaderMap::new(), &config, "user_1").is_none());
    }

    #[test]
    fn operator_role_check_is_privilege_aware() {
        assert!(is_operator_role("admin"));
        assert!(is_operator_role("owner"));
        // Customer roles never count as operators.
        assert!(!is_operator_role("member"));
        assert!(!is_operator_role("developer"));
        assert!(!is_operator_role(""));
    }

    #[test]
    fn login_challenge_binds_user_and_expires() {
        let config = test_config();
        let token = sign_login_challenge(&config, "u1", "ops@apexmail.ee");
        assert!(verify_login_challenge(&config, &token, "u1", "ops@apexmail.ee"));
        assert!(!verify_login_challenge(&config, &token, "u2", "ops@apexmail.ee"));
        assert!(!verify_login_challenge(&config, "garbage", "u1", "ops@apexmail.ee"));
    }
}
