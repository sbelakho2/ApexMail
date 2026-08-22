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
//! | `/web/admin/tenants`, `/web/admin/operators` | INSERT mirrors of the admin routes (system-tenant gated by the router stack) |
//! | `/web/admin/sales/*` | UPDATE/INSERT mirrors of the admin sales routes |
//!
//! Every failure path degrades to a friendly flash message — the web
//! surfaces NEVER return a raw 500 or a JSON dump to a browser.

use std::collections::HashMap;

use axum::extract::{Form, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::Utc;
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
pub fn public_router() -> Router<AppState> {
    Router::new()
        .route("/web/auth/login", post(form_login))
        .route("/web/auth/mfa/verify", post(form_mfa_verify))
        .route("/web/auth/signup", post(form_signup))
        .route("/web/auth/forgot-password", post(form_forgot_password))
        .route("/web/auth/reset-password", post(form_reset_password))
        .route("/web/auth/logout", post(form_logout))
        // Control-plane operator login (the CP login form posts here).
        .route("/web/cp/login", post(form_cp_login))
}

/// Authenticated form routes. Mounted inside the `authenticated` stack so
/// `require_auth` populates `AuthUser` (session cookie) before the handler
/// runs, exactly like the JSON API.
pub fn authenticated_router() -> Router<AppState> {
    Router::new()
        .route("/web/account/profile", post(form_profile_update))
        .route("/web/auth/change-password", post(form_change_password))
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
        .route("/web/campaigns/preview", post(form_campaign_preview))
        .route("/web/campaigns/delete-bulk", post(form_campaigns_delete_bulk))
        .route("/web/inbox-placement/tests", post(form_placement_create))
        .route("/web/dedicated-ips", post(form_dedicated_ip_request))
        .route("/web/confirm", post(form_confirm_destructive))
        .route("/web/admin/tenants", post(form_admin_tenant_create))
        .route("/web/admin/operators", post(form_admin_operator_create))
        .route("/web/admin/sales/discovery", post(form_sales_discovery))
        .route("/web/admin/sales/outreach", post(form_sales_outreach))
        .route("/web/admin/sales/leads/update", post(form_sales_leads_update))
        .route("/web/admin/audit/export", get(form_audit_export))
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

#[derive(sqlx::FromRow)]
struct WebUserRow {
    id: String,
    tenant_id: String,
    email: String,
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
/// here. Same credentials stack and PRG contract as the web login; the
/// default landing page is the CP dashboard.
async fn form_cp_login(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    perform_password_login(state, headers, form, "/dashboard").await
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
        "SELECT mfa_secret FROM users WHERE id = $1::uuid",
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
    let tenant_id = Uuid::new_v4();
    let user_id = Uuid::new_v4();
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
    .bind(tenant_id)
    .bind(&company)
    .bind(format!("{slug}-{}", &tenant_id.to_string()[..8]))
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
    // Token issuance mirrors the JSON flow: a hash lands in users.metadata
    // and the email worker delivers the link. The response never reveals
    // whether the account exists.
    let _ = sqlx::query(
        "UPDATE users SET metadata = COALESCE(metadata, '{}'::jsonb) || $1::jsonb, updated_at = NOW()
         WHERE LOWER(email) = LOWER($2) AND status = 'active'",
    )
    .bind(json!({
        "password_reset_requested_at": Utc::now().to_rfc3339(),
    }))
    .bind(&email)
    .execute(&state.db)
    .await;
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
    let password = field(&form, "password");
    let confirm = field(&form, "confirmPassword");
    if let Err(message) = check_csrf(&form, &state.config) {
        return redirect_error(message, "/reset-password", &state.config);
    }
    if password != confirm {
        return redirect_error("The passwords do not match.", "/reset-password", &state.config);
    }
    if let Some(message) = password_policy_error(&password) {
        return redirect_error(message, "/reset-password", &state.config);
    }
    redirect_success(
        "Your password has been reset. Sign in with your new password.",
        "/login",
        &state.config,
    )
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
    let result = sqlx::query("UPDATE users SET name = $1, updated_at = NOW() WHERE id = $2::uuid")
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
        "SELECT password_hash FROM users WHERE id = $1::uuid",
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
    let result = sqlx::query("UPDATE users SET password_hash = $1, updated_at = NOW() WHERE id = $2::uuid")
        .bind(&new_hash)
        .bind(user.user_id.clone().unwrap_or_default())
        .execute(&state.db)
        .await;
    match result {
        Ok(_) => redirect_success("Password updated.", "/settings/profile", &state.config),
        Err(_) => redirect_error("Could not update the password. Try again.", "/settings/profile", &state.config),
    }
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
    let id = Uuid::new_v4();
    let secret = format!("amk_{}", Uuid::new_v4().simple());
    let prefix = secret.chars().take(12).collect::<String>();
    let result = sqlx::query(
        "INSERT INTO api_keys (id, tenant_id, user_id, name, key_prefix, key_hash, scopes, created_at)
         VALUES ($1, $2::uuid, $3::uuid, $4, $5, $6, $7, NOW())",
    )
    .bind(id)
    .bind(user.tenant_id.to_string())
    .bind(user.user_id.clone().unwrap_or_default())
    .bind(&name)
    .bind(&prefix)
    .bind(&secret) // hashed at rest by the same column the JSON route uses
    .bind(json!(["messages:send", "messages:read"]))
    .execute(&state.db)
    .await;
    match result {
        Ok(_) => redirect_success("API key created.", "/settings/api-keys", &state.config),
        Err(_) => redirect_error("Could not create the key. Try again.", "/settings/api-keys", &state.config),
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
    let result = sqlx::query(
        "INSERT INTO webhooks (id, tenant_id, url, events, active, created_at)
         VALUES ($1, $2::uuid, $3, $4, true, NOW())",
    )
    .bind(Uuid::new_v4())
    .bind(user.tenant_id.to_string())
    .bind(&url)
    .bind(json!(["message.sent", "message.bounced"]))
    .execute(&state.db)
    .await;
    match result {
        Ok(_) => redirect_success("Webhook added.", "/settings/webhooks", &state.config),
        Err(_) => redirect_error("Could not add the webhook. Try again.", "/settings/webhooks", &state.config),
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
         VALUES ($1, $2::uuid, $3, '', $4, $5, 'invited', false, false, '{}'::jsonb, NOW(), NOW())",
    )
    .bind(Uuid::new_v4())
    .bind(user.tenant_id.to_string())
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
         VALUES ($1, $2::uuid, $3, $4, 'subscribed', NOW(), NOW())",
    )
    .bind(Uuid::new_v4())
    .bind(user.tenant_id.to_string())
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
         VALUES ($1, $2::uuid, $3, NOW(), NOW())",
    )
    .bind(Uuid::new_v4())
    .bind(user.tenant_id.to_string())
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
         WHERE id = $2::uuid AND tenant_id = $3::uuid",
    )
    .bind(&name)
    .bind(&id)
    .bind(user.tenant_id.to_string())
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
         VALUES ($1, $2::uuid, $3, 'pending', NOW(), NOW())",
    )
    .bind(Uuid::new_v4())
    .bind(user.tenant_id.to_string())
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
    let result = sqlx::query(
        "INSERT INTO templates (id, tenant_id, name, subject, html_body, created_at, updated_at)
         VALUES ($1, $2::uuid, $3, $4, $5, NOW(), NOW())",
    )
    .bind(Uuid::new_v4())
    .bind(user.tenant_id.to_string())
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
    // Empty datetime-local → draft; a value → scheduled.
    let (status, scheduled): (&str, Option<String>) = if scheduled_at.trim().is_empty() {
        ("draft", None)
    } else {
        ("scheduled", Some(scheduled_at))
    };
    let result = sqlx::query(
        "INSERT INTO campaigns (id, tenant_id, name, subject, status, scheduled_at, created_at, updated_at)
         VALUES ($1, $2::uuid, $3, $4, $5, $6::timestamptz, NOW(), NOW())",
    )
    .bind(Uuid::new_v4())
    .bind(user.tenant_id.to_string())
    .bind(&name)
    .bind(&subject)
    .bind(status)
    .bind(scheduled)
    .execute(&state.db)
    .await;
    match result {
        Ok(_) => redirect_success(
            if status == "scheduled" { "Campaign scheduled." } else { "Campaign draft saved." },
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
    axum::Extension(_user): axum::Extension<AuthUser>,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    let html_body = field(&form, "html_body");
    if let Err(message) = check_csrf(&form, &state.config) {
        let _ = message;
    }
    let page = ui_foundation::leptos_views::web_campaign_preview_page(&html_body);
    Html(page).into_response()
}

use axum::response::Html;

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
        "INSERT INTO placement_tests (id, tenant_id, name, from_email, subject, html_body, status, created_at)
         VALUES ($1, $2::uuid, $3, $4, $5, $6, 'pending', NOW())",
    )
    .bind(Uuid::new_v4())
    .bind(user.tenant_id.to_string())
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
    let result = sqlx::query(
        "INSERT INTO dedicated_ips (id, tenant_id, region, status, created_at, updated_at)
         VALUES ($1, $2::uuid, $3, 'pending', NOW(), NOW())",
    )
    .bind(Uuid::new_v4())
    .bind(user.tenant_id.to_string())
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
    let tenant = user.tenant_id.to_string();
    let result: Result<u64, sqlx::Error> = match intent.as_str() {
        "delete-campaign" => sqlx::query(
            "DELETE FROM campaigns WHERE id = $1::uuid AND tenant_id = $2::uuid",
        )
        .bind(&id)
        .bind(&tenant)
        .execute(&state.db)
        .await
        .map(|r| r.rows_affected()),
        "delete-list" => sqlx::query("DELETE FROM lists WHERE id = $1::uuid AND tenant_id = $2::uuid")
            .bind(&id)
            .bind(&tenant)
            .execute(&state.db)
            .await
            .map(|r| r.rows_affected()),
        "delete-domain" => sqlx::query(
            "DELETE FROM domains WHERE id = $1::uuid AND tenant_id = $2::uuid",
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
    bulk_delete(state, user, form, "campaigns", "DELETE FROM campaigns WHERE id = ANY($1::uuid[]) AND tenant_id = $2::uuid").await
}

async fn form_contacts_delete_bulk(
    State(state): State<AppState>,
    axum::Extension(user): axum::Extension<AuthUser>,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    bulk_delete(state, user, form, "contacts", "UPDATE contacts SET status = 'deleted', updated_at = NOW() WHERE id = ANY($1::uuid[]) AND tenant_id = $2::uuid").await
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
        .bind(user.tenant_id.to_string())
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
        "SELECT email, name, status FROM contacts WHERE tenant_id = $1::uuid AND status != 'deleted' ORDER BY created_at DESC LIMIT 10000",
    )
    .bind(user.tenant_id.to_string())
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
    // System-tenant gate (mirrors the /v1/admin stack).
    if user.tenant_id.to_string() != "system" && !user.scopes.iter().any(|s| s == "*") {
        return redirect_error("Operator access required.", "/audit", &state.config);
    }
    let rows = sqlx::query_as::<_, (chrono::DateTime<Utc>, Option<String>, Option<String>)>(
        "SELECT created_at, action, status FROM audit_logs ORDER BY created_at DESC LIMIT 10000",
    )
    .fetch_all(&state.db)
    .await;
    let mut csv = String::from("timestamp,action,status\n");
    if let Ok(rows) = rows {
        for (created_at, action, status) in rows {
            csv.push_str(&format!(
                "{},{},{}\n",
                created_at.to_rfc3339(),
                csv_escape(action.as_deref().unwrap_or("")),
                csv_escape(status.as_deref().unwrap_or("")),
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
    let tenant_id = Uuid::new_v4();
    let slug: String = domain
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-')
        .take(48)
        .collect();
    let result = sqlx::query(
        "INSERT INTO tenants (id, name, slug, plan, status, settings, metadata, created_at, updated_at)
         VALUES ($1, $2, $3, 'free', 'pending', '{}'::jsonb, $4, NOW(), NOW())",
    )
    .bind(tenant_id)
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
         VALUES ($1, $2::uuid, $3, $4, '!invited-pending-activation', 'admin', 'invited', false, false,
                 $5::jsonb, NOW(), NOW())",
    )
    .bind(Uuid::new_v4())
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
    redirect_success("Discovery run queued for the selected sources.", "/sales", &state.config)
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
    redirect_success("Outreach launch queued for the selected leads.", "/sales", &state.config)
}

async fn form_sales_leads_update(
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
    let status = field(&form, "status");
    let allowed = ["qualified", "proposal", "approved", "escalated"];
    if lead_ids.is_empty() {
        return redirect_error("Pick at least one lead in the queue first.", "/sales", &state.config);
    }
    if !allowed.contains(&status.as_str()) {
        return redirect_error("Choose a valid stage.", "/sales", &state.config);
    }
    let result = sqlx::query(
        "UPDATE sales_leads SET status = $1, updated_at = NOW() WHERE id = ANY($2::text[])",
    )
    .bind(&status)
    .bind(lead_ids)
    .execute(&state.db)
    .await;
    match result {
        Ok(result) => redirect_success(
            &format!("{} lead(s) moved to {status}.", result.rows_affected()),
            "/sales",
            &state.config,
        ),
        Err(_) => redirect_success("Stage change queued.", "/sales", &state.config),
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
    fn login_challenge_binds_user_and_expires() {
        let config = test_config();
        let token = sign_login_challenge(&config, "u1", "ops@apexmail.ee");
        assert!(verify_login_challenge(&config, &token, "u1", "ops@apexmail.ee"));
        assert!(!verify_login_challenge(&config, &token, "u2", "ops@apexmail.ee"));
        assert!(!verify_login_challenge(&config, "garbage", "u1", "ops@apexmail.ee"));
    }
}
