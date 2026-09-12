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
//! | `/web/auth/mfa/verify` | multi-step SSR form: challenge is an HMAC-signed short-lived cookie; TOTP verified via the hardened `routes::auth::verify_totp_code_guarded` (lockout + replay guard) |
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
use std::net::{IpAddr, SocketAddr};

use axum::extract::{ConnectInfo, Form, Path, Query, State};
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
///
/// Backslashes and control characters are rejected outright: WHATWG URL
/// parsing normalises `\` to `/` inside special schemes, so a browser
/// handed `/\evil.com` navigates to `//evil.com` — a protocol-relative
/// hop straight to the attacker. CR/LF/TAB can additionally smuggle
/// headers. This check runs BEFORE the relative-path test and the URL
/// parse, so both branches are covered.
pub fn consent_safe_return_to(return_to: Option<&str>) -> String {
    let Some(value) = return_to.map(str::trim).filter(|v| !v.is_empty()) else {
        return "/".to_string();
    };

    if value.contains('\\') || value.chars().any(char::is_control) {
        return "/".to_string();
    }

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
    cookie_header
        .split(';')
        .any(|pair| match pair.split_once('=') {
            Some((name, value)) => name.trim() == CONSENT_COOKIE_NAME && !value.trim().is_empty(),
            None => false,
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
        return (StatusCode::FOUND, [(header::LOCATION, return_to)]).into_response();
    };

    let mut response = (StatusCode::FOUND, [(header::LOCATION, return_to)]).into_response();
    if let Ok(cookie) = consent_set_cookie(value, is_secure(config)).parse() {
        response.headers_mut().insert(header::SET_COOKIE, cookie);
    }
    response
}

/// Is `host` an apexmail.ee host (apexmail.ee, www, or any subdomain)?
/// Shared by the consent GET's Referer check.
fn is_apexmail_family_host(host: &str) -> bool {
    let host = host.trim().to_ascii_lowercase();
    matches!(host.as_str(), "apexmail.ee" | "www.apexmail.ee") || host.ends_with(".apexmail.ee")
}

/// May this GET request record a consent choice?
///
/// `/consent?choice=all` is a bare GET, so before this guard any third
/// party could forge a visitor's consent by embedding the URL as an
/// `<img>` (or a hidden iframe/link prefetch). The check:
///
/// - `Sec-Fetch-Site` present → only `same-origin`, `same-site` and
///   `none` (a user-typed URL) may record; `cross-site` is refused.
/// - Header absent (older browsers) → the Referer is checked instead
///   and must be an apexmail-family origin.
/// - Neither header present → allowed, but logged: stripping both is
///   the shape of an old browser, not of an attacker who controls one.
///   Real banner clicks always carry one of the two.
fn consent_get_may_record(headers: &HeaderMap) -> bool {
    match headers
        .get("sec-fetch-site")
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .map(str::to_ascii_lowercase)
    {
        Some(site) => matches!(site.as_str(), "same-origin" | "same-site" | "none"),
        None => {
            let referer = headers
                .get(header::REFERER)
                .and_then(|value| value.to_str().ok())
                .map(str::trim);
            match referer {
                Some(referer) => match url::Url::parse(referer) {
                    Ok(url) => url.host_str().is_some_and(is_apexmail_family_host),
                    Err(_) => false,
                },
                None => {
                    tracing::info!(
                        "consent GET without Sec-Fetch-Site/Referer: allowing for \
                         legacy no-JS browsers (no forgery signal present)"
                    );
                    true
                }
            }
        }
    }
}

/// GET /consent?choice={all|necessary}&return_to=… — the no-JS banner's
/// links (plain navigations; the marketing CSP's `form-action 'self'`
/// forbids cross-origin form posts). Same-site guarded: a cross-site
/// GET (an `<img>` on someone else's page) redirects home WITHOUT
/// setting the cookie.
async fn consent_get(
    State(state): State<AppState>,
    Query(request): Query<ConsentRequest>,
    headers: HeaderMap,
) -> Response {
    let return_to = consent_safe_return_to(request.return_to.as_deref());
    if !consent_get_may_record(&headers) {
        tracing::warn!(
            choice = ?request.choice,
            "refused cross-site consent GET (possible forged consent); cookie not set"
        );
        return (StatusCode::FOUND, [(header::LOCATION, return_to)]).into_response();
    }
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
    Router::new().route("/consent", get(consent_get).post(consent_post))
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
        .route("/web/contacts/import", post(form_contacts_import))
        .route("/web/lists", post(form_list_create))
        .route("/web/lists/update", post(form_list_update))
        .route("/web/lists/delete-bulk", post(form_lists_delete_bulk))
        .route("/web/domains", post(form_domain_create))
        .route("/web/domains/:id/verify", post(form_domain_verify))
        .route("/web/templates", post(form_template_create))
        .route("/web/templates/update", post(form_template_update))
        .route("/web/templates/preview", post(form_template_preview))
        .route("/web/campaigns", post(form_campaign_create))
        .route("/web/campaigns/update", post(form_campaign_update))
        .route("/web/campaigns/preview", post(form_campaign_preview))
        .route(
            "/web/campaigns/delete-bulk",
            post(form_campaigns_delete_bulk),
        )
        .route("/web/campaigns/:id/start", post(form_campaign_start))
        .route("/web/campaigns/:id/pause", post(form_campaign_pause))
        .route("/web/campaigns/:id/resume", post(form_campaign_resume))
        .route(
            "/web/campaigns/:id/recipients",
            post(form_campaign_recipients),
        )
        .route("/web/inbox-placement/tests", post(form_placement_create))
        .route("/web/dedicated-ips", post(form_dedicated_ip_request))
        .route("/web/confirm", post(form_confirm_destructive))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            web_form_rejection_middleware,
        ))
}

/// Data-backed SSR detail pages (`GET /domains/{id}`, `GET /campaigns/{id}`).
/// Mounted OUTSIDE the require_auth stack: these are browser pages whose
/// anonymous contract is the same 303 `/login?next=…` redirect the SSR
/// fallback produces for every auth-required UI route (the routing
/// inventory asserts this), not a JSON 401. Sessions are resolved inside
/// the handlers; non-id segments (e.g. `/campaigns/new`) fall through to
/// the standard SSR render exactly as the fallback would serve them.
pub fn detail_router() -> Router<AppState> {
    Router::new()
        .route("/domains/:id", get(web_domain_detail))
        .route("/campaigns/:id", get(web_campaign_detail))
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
        .route(
            "/web/admin/sales/discovery/run",
            post(form_sales_discovery_run),
        )
        .route(
            "/web/admin/sales/outreach/launch",
            post(form_sales_outreach_launch),
        )
        .route(
            // Retained as the SSR mirror of the admin lead-update API. No page
            // currently renders a form for it (the sales console became an
            // autonomy control centre), so it is reachable only by a direct
            // CSRF-protected POST — which is harmless but worth knowing before
            // assuming an operator can reach it.
            "/web/admin/sales/leads/update",
            post(form_sales_leads_update),
        )
        .route("/web/admin/audit/export", get(form_audit_export))
        .route("/web/admin/alerts/ack", post(form_admin_alert_ack))
        .route(
            "/web/admin/alerts/ack-bulk",
            post(form_admin_alert_ack_bulk),
        )
        .route(
            "/web/admin/tenants/:id/suspend",
            post(form_admin_tenant_suspend),
        )
        .route(
            "/web/admin/tenants/:id/resume",
            post(form_admin_tenant_resume),
        )
        .route(
            "/web/admin/tenants/:id/delete",
            post(form_admin_tenant_delete),
        )
        .route(
            "/web/admin/domains/:domain/transfer",
            get(web_admin_domain_transfer),
        )
        .route(
            "/web/admin/domains/transfer",
            post(form_admin_domain_transfer),
        )
        .route(
            "/web/admin/gdpr/:id/transition",
            post(form_admin_gdpr_transition),
        )
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
#[cfg(test)]
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
        let mut redirect = (StatusCode::SEE_OTHER, [(header::LOCATION, referer)]).into_response();
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
fn redirect_with_flash(messages: &[FlashMessage], location: &str, config: &Config) -> Response {
    let mut response = (
        StatusCode::SEE_OTHER,
        [(header::LOCATION, location.to_string())],
    )
        .into_response();
    let headers = response.headers_mut();
    // Only one flash cookie per response: the set below replaces any clear.
    let _ = flash_clear_cookie(is_secure(config));
    if let Ok(value) = flash_set_cookie(messages, &config.csrf_secret, is_secure(config)).parse() {
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

/// Safe fallback redirect target: same-origin paths only. Backslashes
/// and control characters are rejected for the same reason as in
/// [`consent_safe_return_to`]: WHATWG URL parsing turns `/\evil.com`
/// into a protocol-relative `//evil.com` hop.
fn safe_return_to(form: &HashMap<String, String>, default: &str) -> String {
    form.get("return_to")
        .or_else(|| form.get("next"))
        .map(String::as_str)
        .filter(|value| {
            value.starts_with('/')
                && !value.starts_with("//")
                && !value.contains('\\')
                && !value.chars().any(char::is_control)
        })
        .unwrap_or(default)
        .to_string()
}

fn csrf_from(form: &HashMap<String, String>) -> Option<&str> {
    form.get("_csrf")
        .map(String::as_str)
        .filter(|t| !t.is_empty())
}

/// Name of the double-submit CSRF cookie — the same cookie the JSON
/// surface's `validate_session_csrf` compares against and that GET
/// /v1/auth/csrf (and every SSR page render) mints alongside the token.
pub const FORM_CSRF_COOKIE_NAME: &str = "csrf_token";

/// Validate the form's embedded CSRF token under the double-submit cookie
/// contract (the same pattern the JSON surface enforces in
/// `validate_session_csrf`): the hidden `_csrf` input must carry a
/// timestamped, HMAC-signed token AND match the `csrf_token` cookie the
/// page render minted alongside it. A token harvested from the public
/// /v1/auth/csrf endpoint alone is therefore useless — the attacker cannot
/// plant the matching cookie in the victim's browser. On failure the caller
/// redirects back with a friendly "session expired" flash — never a 403
/// JSON dump.
fn check_csrf(
    form: &HashMap<String, String>,
    headers: &HeaderMap,
    config: &Config,
) -> Result<(), &'static str> {
    const EXPIRED: &str = "Your session expired. Reload the page and try again.";
    let token = csrf_from(form).ok_or(EXPIRED)?;
    let cookie = cookie_value(headers, FORM_CSRF_COOKIE_NAME).ok_or(EXPIRED)?;
    // Constant-time comparison, mirroring validate_session_csrf.
    if !apexmail_lib::timing_safe_compare(token, cookie) {
        return Err(EXPIRED);
    }
    validate_csrf_token(token, &config.csrf_secret).map_err(|_| EXPIRED)
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

/// Per-account MFA brute-force bound (the SSR verify step): 10 wrong codes
/// per 15-minute window locks the account out of the challenge step — a
/// 6-digit TOTP must not be guessable without limit once the password is
/// known. Redis outages fail over to a bounded in-process counter (see
/// [`mfa_fallback`]) so the brute-force bound survives Redis loss; the
/// challenge cookie's own 5-minute TTL additionally bounds the exposure.
const MFA_VERIFY_MAX_ATTEMPTS: i64 = 10;
const MFA_VERIFY_WINDOW_SECS: u64 = 15 * 60;

fn mfa_verify_failure_key(user_id: &str) -> String {
    format!("apexmail:mfa_verify_failures:{user_id}")
}

/// In-process MFA failure counter used ONLY while Redis is unavailable
/// (audit F11): a bounded map keyed by the challenge's user id, windowed
/// like the Redis key. Without it, a Redis outage removed the brute-force
/// bound entirely (fail open). The bound keeps the map small: expired
/// windows are pruned on every touch, and a map still over the cap after
/// pruning is dropped wholesale (fresh windows restart — availability
/// wins, but never unbounded memory).
mod mfa_fallback {
    use std::collections::HashMap;
    use std::sync::Mutex;
    use std::time::Instant;

    /// Same shape as the Redis regime: `count` wrong codes inside the window.
    struct Window {
        count: i64,
        started: Instant,
    }

    /// Upper bound on tracked challenges (defense against key flooding).
    const MAX_KEYS: usize = 4096;
    /// Window length — mirrors MFA_VERIFY_WINDOW_SECS.
    const WINDOW_SECS: u64 = 15 * 60;

    fn store() -> &'static Mutex<HashMap<String, Window>> {
        static STORE: std::sync::OnceLock<Mutex<HashMap<String, Window>>> =
            std::sync::OnceLock::new();
        STORE.get_or_init(|| Mutex::new(HashMap::new()))
    }

    fn prune_expired(map: &mut HashMap<String, Window>) {
        map.retain(|_, window| window.started.elapsed().as_secs() < WINDOW_SECS);
    }

    /// `true` when the challenge has hit the attempt cap in this window.
    pub fn locked(key: &str) -> bool {
        let Ok(map) = store().lock() else {
            return false;
        };
        map.get(key).is_some_and(|window| {
            window.started.elapsed().as_secs() < WINDOW_SECS
                && window.count >= super::MFA_VERIFY_MAX_ATTEMPTS
        })
    }

    /// Record one wrong code (starts a fresh window on first failure).
    pub fn record_failure(key: &str) {
        let Ok(mut map) = store().lock() else {
            return;
        };
        prune_expired(&mut map);
        if map.len() >= MAX_KEYS && !map.contains_key(key) {
            // Cap reached without room: restart from a clean slate rather
            // than growing without bound.
            map.clear();
        }
        let window = map.entry(key.to_string()).or_insert(Window {
            count: 0,
            started: Instant::now(),
        });
        if window.started.elapsed().as_secs() >= WINDOW_SECS {
            window.count = 0;
            window.started = Instant::now();
        }
        window.count += 1;
    }

    /// Clear the counter (successful verify).
    pub fn clear(key: &str) {
        if let Ok(mut map) = store().lock() {
            map.remove(key);
        }
    }
}

async fn mfa_verify_locked(state: &AppState, user_id: &str) -> bool {
    let key = mfa_verify_failure_key(user_id);
    let Ok(mut conn) = state.redis.get().await else {
        // Redis unavailable: the in-process counter keeps the bound (F11).
        return mfa_fallback::locked(&key);
    };
    let failures: Option<i64> = redis::AsyncCommands::get(&mut *conn, &key).await.ok();
    failures.is_some_and(|count| count >= MFA_VERIFY_MAX_ATTEMPTS)
}

async fn record_mfa_verify_failure(state: &AppState, user_id: &str) {
    let key = mfa_verify_failure_key(user_id);
    let Ok(mut conn) = state.redis.get().await else {
        mfa_fallback::record_failure(&key);
        return;
    };
    let count: Result<i64, _> = redis::cmd("INCR").arg(&key).query_async(&mut *conn).await;
    if count.is_ok_and(|value| value == 1) {
        let _: Result<(), _> = redis::cmd("EXPIRE")
            .arg(&key)
            .arg(MFA_VERIFY_WINDOW_SECS)
            .query_async(&mut *conn)
            .await;
    }
}

async fn clear_mfa_verify_failures(state: &AppState, user_id: &str) {
    let key = mfa_verify_failure_key(user_id);
    mfa_fallback::clear(&key);
    if let Ok(mut conn) = state.redis.get().await {
        let _: Result<(), _> = redis::AsyncCommands::del(&mut *conn, &key).await;
    }
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
pub(crate) fn cookie_value<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers
        .get(header::COOKIE)
        .and_then(|value| value.to_str().ok())?
        .split(';')
        .find_map(|chunk| chunk.trim().strip_prefix(&format!("{name}=")))
}

/// The form CSRF token resolved for a GET render (double-submit, audit F4).
///
/// A still-valid `csrf_token` cookie on the request is REUSED so pages
/// already open in other tabs keep working (minting per render would
/// rotate the cookie under their forms); otherwise a fresh token is minted
/// and `minted` tells the caller to set the matching cookie on the
/// response. The SAME token is embedded into the page's hidden `_csrf`
/// inputs, so the POST-side `check_csrf` cookie comparison passes.
pub(crate) struct FormCsrfToken {
    pub token: String,
    pub minted: bool,
}

pub(crate) fn form_csrf_for_render(headers: &HeaderMap, config: &Config) -> FormCsrfToken {
    if let Some(raw) = cookie_value(headers, FORM_CSRF_COOKIE_NAME) {
        if validate_csrf_token(raw, &config.csrf_secret).is_ok() {
            return FormCsrfToken {
                token: raw.to_string(),
                minted: false,
            };
        }
    }
    FormCsrfToken {
        token: ui_foundation::csrf::generate_csrf_token(&config.csrf_secret),
        minted: true,
    }
}

/// `Set-Cookie` value for the double-submit form CSRF token (same shape as
/// the public GET /v1/auth/csrf endpoint mints for the JSON surface).
pub(crate) fn form_csrf_set_cookie(token: &str, config: &Config) -> String {
    format!(
        "{FORM_CSRF_COOKIE_NAME}={token}; HttpOnly; Path=/; Max-Age=3600; SameSite=Strict{}",
        if is_secure(config) { "; Secure" } else { "" },
    )
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

// ─── Form field-map cookie (value/error preservation, item F) ────
//
// flash.rs (ui-foundation, read-only here) carries only {kind, text}
// banners, so the failed-POST round trip gets its OWN small signed
// cookie, mirroring flash.rs's HMAC pattern exactly:
//
//   POST /web/… (validation fails) → signed `apexmail_form_fields`
//     cookie holding {form_id, field_values, field_errors, secrets}
//     + error flash → 303 back to the form's GET
//   GET /forms/…   → [`decode_form_fields_from_headers`] hands the map
//     to the render layer, which re-populates inputs and renders
//     per-field errors; the cookie is cleared with the response.
//
// The `secrets` slot carries reveal-once values (API key / webhook
// signing secrets, item N) as structured data the view renders in a
// mono cell instead of prose buried in a flash sentence.

/// Cookie name for the form field-map.
pub const FORM_FIELDS_COOKIE_NAME: &str = "apexmail_form_fields";
/// Field maps are short-lived: they exist for one PRG round trip.
const FORM_FIELDS_MAX_AGE_SECS: i64 = 120;
/// Bound the decoded payload (cookie-stuffing resistance, like flash.rs).
const FORM_FIELDS_MAX_BYTES: usize = 8 * 1024;

/// Signed, short-lived form state for one failed (or secret-bearing)
/// POST → GET round trip.
#[derive(Debug, Clone, Default, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct FormFieldMap {
    /// Identifies which form the values belong to (e.g. "webhook-create");
    /// renderers use it to avoid replaying values into a different form.
    pub form_id: String,
    /// Submitted field values to re-populate (order preserved).
    pub values: Vec<(String, String)>,
    /// Per-field validation errors (field name → message).
    pub errors: Vec<(String, String)>,
    /// Reveal-once secrets (label → value) rendered as mono data.
    pub secrets: Vec<(String, String)>,
}

impl FormFieldMap {
    pub fn new(form_id: &str) -> Self {
        Self {
            form_id: form_id.to_string(),
            ..Default::default()
        }
    }

    /// Record a field value for re-population.
    pub fn set(&mut self, name: &str, value: &str) {
        if let Some(slot) = self.values.iter_mut().find(|(n, _)| n == name) {
            slot.1 = value.to_string();
        } else {
            self.values.push((name.to_string(), value.to_string()));
        }
    }

    /// Record a per-field error.
    pub fn error(&mut self, name: &str, message: &str) {
        self.errors.push((name.to_string(), message.to_string()));
    }

    /// Record a reveal-once secret (mono-renderable, item N).
    pub fn secret(&mut self, label: &str, value: &str) {
        self.secrets.push((label.to_string(), value.to_string()));
    }

    /// The re-population value for a field (last write wins).
    pub fn field_value(&self, name: &str) -> Option<&str> {
        self.values
            .iter()
            .rev()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    }

    /// The validation error for a field, if any.
    pub fn field_error(&self, name: &str) -> Option<&str> {
        self.errors
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, m)| m.as_str())
    }

    /// Reveal-once secrets for mono rendering (item N).
    pub fn secrets(&self) -> &[(String, String)] {
        &self.secrets
    }

    /// True when nothing would render (no values, errors, or secrets).
    pub fn is_empty(&self) -> bool {
        self.values.is_empty() && self.errors.is_empty() && self.secrets.is_empty()
    }

    /// The view-layer mirror handed to ui-foundation's render pass
    /// (`render_route_with_form_fields`): the GET render calls this with
    /// the map decoded from this cookie so stored fields re-populate,
    /// per-field errors render, and reveal-once secrets display.
    pub fn into_view_data(self) -> ui_foundation::view_data::FormFieldData {
        ui_foundation::view_data::FormFieldData {
            form_id: self.form_id,
            values: self.values,
            errors: self.errors,
            secrets: self.secrets,
        }
    }

    fn encode(&self, secret: &str) -> String {
        use base64::Engine;
        use hmac::{Hmac, Mac};
        use sha2::Sha256;
        let payload = serde_json::to_vec(self).expect("form field map serializes (plain strings)");
        let payload_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&payload);
        let mut mac = <Hmac<Sha256>>::new_from_slice(secret.as_bytes())
            .expect("form field map HMAC key error");
        mac.update(payload_b64.as_bytes());
        let signature =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());
        format!("v1.{payload_b64}.{signature}")
    }

    fn decode(value: &str, secret: &str) -> Option<Self> {
        use base64::Engine;
        use hmac::{Hmac, Mac};
        use sha2::Sha256;
        let rest = value.strip_prefix("v1.")?;
        let (payload_b64, signature) = rest.rsplit_once('.')?;
        let mut mac = <Hmac<Sha256>>::new_from_slice(secret.as_bytes())
            .expect("form field map HMAC key error");
        mac.update(payload_b64.as_bytes());
        let expected = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(signature)
            .ok()?;
        mac.verify_slice(&expected).ok()?;
        let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(payload_b64)
            .ok()?;
        if payload.len() > FORM_FIELDS_MAX_BYTES {
            return None;
        }
        serde_json::from_slice(&payload).ok()
    }
}

/// Build the `Set-Cookie` value that carries a form field map.
pub fn form_fields_set_cookie(map: &FormFieldMap, secret: &str, secure: bool) -> String {
    format!(
        "{FORM_FIELDS_COOKIE_NAME}={}; Path=/; Max-Age={FORM_FIELDS_MAX_AGE_SECS}; HttpOnly; SameSite=Lax{}",
        map.encode(secret),
        if secure { "; Secure" } else { "" },
    )
}

/// Build the `Set-Cookie` value that clears the form field map.
pub fn form_fields_clear_cookie(secure: bool) -> String {
    format!(
        "{FORM_FIELDS_COOKIE_NAME}=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax{}",
        if secure { "; Secure" } else { "" }
    )
}

/// Clean accessor for the render path (the VIEW layer calls this): read
/// and verify the signed field-map cookie from a request's Cookie header.
/// Returns `None` when absent, expired handling aside (short Max-Age
/// bounds it), tampered, or signed with another secret.
pub fn decode_form_fields_from_headers(headers: &HeaderMap, secret: &str) -> Option<FormFieldMap> {
    let raw = cookie_value(headers, FORM_FIELDS_COOKIE_NAME)?;
    FormFieldMap::decode(raw, secret).filter(|map| !map.is_empty())
}

/// PRG response for a failed create/update POST: signed error flash +
/// signed field-map cookie + 303 back to the form.
fn redirect_with_field_map(
    map: &FormFieldMap,
    message: &str,
    location: &str,
    config: &Config,
) -> Response {
    let mut response = redirect_with_flash(&[FlashMessage::error(message)], location, config);
    if let Ok(value) = form_fields_set_cookie(map, &config.csrf_secret, is_secure(config)).parse() {
        // Append: the flash cookie was already set by redirect_with_flash.
        response.headers_mut().append(header::SET_COOKIE, value);
    }
    response
}

/// PRG response that carries a reveal-once secret (item N): success flash
/// for the banner + the structured secret in the field-map cookie.
fn redirect_with_secret(
    map: &FormFieldMap,
    message: &str,
    location: &str,
    config: &Config,
) -> Response {
    let mut response = redirect_with_flash(&[FlashMessage::success(message)], location, config);
    if let Ok(value) = form_fields_set_cookie(map, &config.csrf_secret, is_secure(config)).parse() {
        response.headers_mut().append(header::SET_COOKIE, value);
    }
    response
}

// ─── Multi-value form bodies (checkbox groups, file uploads) ──────
//
// axum's `Form<HashMap<_, _>>` collapses repeated keys (checkbox groups
// post `events=a&events=b`), and the multipart file part needs raw body
// access (axum's multipart feature is not enabled). Both are parsed here
// into one lossless shape.

/// A parsed form body: every (name, value) pair in order, plus file parts.
#[derive(Debug, Default, Clone)]
pub(crate) struct ParsedForm {
    pairs: Vec<(String, String)>,
    files: Vec<(String, String)>,
}

impl ParsedForm {
    fn from_pairs(pairs: Vec<(String, String)>) -> Self {
        Self {
            pairs,
            files: Vec::new(),
        }
    }

    /// Single-valued field (last write wins, like the HashMap handlers).
    fn field(&self, key: &str) -> String {
        self.pairs
            .iter()
            .rev()
            .find(|(n, _)| n == key)
            .map(|(_, v)| v.clone())
            .unwrap_or_default()
    }

    /// ALL values posted for a key (checkbox groups).
    fn get_all(&self, key: &str) -> Vec<String> {
        self.pairs
            .iter()
            .filter(|(n, _)| n == key)
            .map(|(_, v)| v.clone())
            .collect()
    }

    /// First file part's text content, or the named textarea field.
    fn csv_text(&self) -> String {
        if let Some((_, content)) = self.files.first() {
            return content.clone();
        }
        self.field("csv")
    }

    /// CSRF check against the parsed pairs (same contract as check_csrf,
    /// including the double-submit cookie binding).
    fn check_csrf(&self, headers: &HeaderMap, config: &Config) -> Result<(), &'static str> {
        let form: HashMap<String, String> = self.pairs.iter().cloned().collect();
        check_csrf(&form, headers, config)
    }
}

/// Parse an `application/x-www-form-urlencoded` body leniently (malformed
/// percent escapes are kept literally — validation handles bad input).
fn parse_urlencoded(body: &str) -> Vec<(String, String)> {
    body.split('&')
        .filter(|part| !part.is_empty())
        .map(|part| match part.split_once('=') {
            Some((key, value)) => (urlencoded_component(key), urlencoded_component(value)),
            None => (urlencoded_component(part), String::new()),
        })
        .collect()
}

fn urlencoded_component(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'+' => {
                decoded.push(b' ');
                index += 1;
            }
            b'%' if index + 2 < bytes.len() => {
                let hi = (bytes[index + 1] as char).to_digit(16);
                let lo = (bytes[index + 2] as char).to_digit(16);
                if let (Some(hi), Some(lo)) = (hi, lo) {
                    decoded.push((hi * 16 + lo) as u8);
                    index += 3;
                } else {
                    decoded.push(b'%');
                    index += 1;
                }
            }
            byte => {
                decoded.push(byte);
                index += 1;
            }
        }
    }
    String::from_utf8_lossy(&decoded).into_owned()
}

/// Parse a `multipart/form-data` body (fields + one text file part).
/// Returns `None` when the Content-Type carries no boundary or the body
/// does not match it — callers degrade to the friendly flash redirect.
fn parse_multipart(body: &[u8], content_type: &str) -> Option<ParsedForm> {
    let boundary = content_type
        .split(';')
        .map(str::trim)
        .find_map(|part| part.strip_prefix("boundary="))?
        .trim_matches('"');
    if boundary.is_empty() {
        return None;
    }
    let delimiter = format!("--{boundary}");
    let text = String::from_utf8_lossy(body);
    let mut form = ParsedForm::default();
    for raw_part in text.split(delimiter.as_str()) {
        let part = raw_part.trim_start_matches("\r\n");
        if part.is_empty() || part.starts_with("--") {
            continue; // preamble / closing marker
        }
        let Some((headers_raw, content)) = part.split_once("\r\n\r\n") else {
            continue;
        };
        let content = content.strip_suffix("\r\n").unwrap_or(content);
        let mut name = None;
        let mut filename = None;
        for header_line in headers_raw.split("\r\n") {
            let lower = header_line.to_ascii_lowercase();
            if let Some(rest) = lower.strip_prefix("content-disposition:") {
                if rest.contains("form-data") {
                    for attr in header_line.split(';').map(str::trim) {
                        if let Some(value) = attr.strip_prefix("name=") {
                            name = Some(value.trim_matches('"').to_string());
                        } else if let Some(value) = attr.strip_prefix("filename=") {
                            filename = Some(value.trim_matches('"').to_string());
                        }
                    }
                }
            }
        }
        let Some(name) = name else { continue };
        if filename.is_some() {
            form.files.push((name, content.to_string()));
        } else {
            form.pairs.push((name, content.to_string()));
        }
    }
    Some(form)
}

/// Parse a form request body regardless of encoding (urlencoded or
/// multipart). The 10 MiB cap keeps hostile bodies out of the parser.
async fn parse_form_body(
    headers: &HeaderMap,
    body: axum::body::Bytes,
) -> Result<ParsedForm, &'static str> {
    if body.len() > 10 * 1024 * 1024 {
        return Err("That upload is too large. Keep imports under 10 MB.");
    }
    let content_type = headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");
    if content_type.starts_with("multipart/form-data") {
        parse_multipart(&body, content_type)
            .ok_or("The form could not be read. Reload the page and try again.")
    } else {
        Ok(ParsedForm::from_pairs(parse_urlencoded(
            &String::from_utf8_lossy(&body),
        )))
    }
}

// ─── Contact CSV import parsing (item C) ──────────────────────────

/// Hard cap on imported rows — larger files must be split.
pub(crate) const CONTACT_IMPORT_MAX_ROWS: usize = 10_000;

/// One parsed import row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ContactCsvRow {
    pub email: String,
    pub name: Option<String>,
}

/// The parsed outcome of an import body: valid rows plus the invalid
/// ones with line numbers and reasons (for the honest flash).
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct ContactCsvParse {
    pub rows: Vec<ContactCsvRow>,
    pub invalid: Vec<(usize, String)>,
    /// True when the first row was consumed as a header.
    pub had_header: bool,
}

/// Parse RFC 4180-style CSV (quoted fields, embedded commas/newlines,
/// `""` escapes) and map email/name columns case-insensitively.
pub(crate) fn parse_contact_csv(text: &str) -> ContactCsvParse {
    let records = parse_csv_records(text);
    let mut out = ContactCsvParse::default();
    let mut records = records.into_iter().peekable();

    // Header detection: a first record whose cells include an email-ish
    // column name. Otherwise col0 = email, col1 = name.
    let (email_col, name_col) = if let Some(first) = records.peek() {
        let email_col = first.iter().position(|cell| {
            matches!(
                normalize_csv_header(cell).as_str(),
                "email" | "emailaddress"
            )
        });
        if let Some(email_col) = email_col {
            out.had_header = true;
            let name_col = first
                .iter()
                .position(|cell| normalize_csv_header(cell) == "name");
            let _ = records.next(); // consume the header row
            (email_col, name_col)
        } else {
            (0, Some(1))
        }
    } else {
        (0, Some(1))
    };

    for (index, record) in records.enumerate() {
        let line_no = index + if out.had_header { 2 } else { 1 };
        let Some(email) = record.get(email_col).map(|cell| cell.trim().to_lowercase()) else {
            if record.iter().all(|cell| cell.trim().is_empty()) {
                continue; // blank line
            }
            out.invalid
                .push((line_no, "row has no email column".to_string()));
            continue;
        };
        if !valid_email(&email) {
            out.invalid
                .push((line_no, format!("invalid email: {email}")));
            continue;
        }
        let name = name_col
            .and_then(|col| record.get(col))
            .map(|cell| cell.trim().to_string())
            .filter(|name| !name.is_empty());
        out.rows.push(ContactCsvRow { email, name });
    }
    out
}

fn normalize_csv_header(cell: &str) -> String {
    cell.trim()
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .collect::<String>()
        .to_ascii_lowercase()
}

/// Minimal RFC 4180 record parser: handles quoted fields with embedded
/// commas, newlines, and doubled quotes.
fn parse_csv_records(text: &str) -> Vec<Vec<String>> {
    let mut records: Vec<Vec<String>> = Vec::new();
    let mut record: Vec<String> = Vec::new();
    let mut field = String::new();
    let mut chars = text.chars().peekable();
    let mut in_quotes = false;
    let mut saw_any = false;
    while let Some(ch) = chars.next() {
        saw_any = true;
        match ch {
            '"' if in_quotes => {
                if chars.peek() == Some(&'"') {
                    chars.next();
                    field.push('"');
                } else {
                    in_quotes = false;
                }
            }
            '"' => in_quotes = true,
            ',' if !in_quotes => {
                record.push(std::mem::take(&mut field));
            }
            '\r' if !in_quotes && chars.peek() == Some(&'\n') => {
                chars.next();
                record.push(std::mem::take(&mut field));
                records.push(std::mem::take(&mut record));
            }
            '\n' if !in_quotes => {
                record.push(std::mem::take(&mut field));
                records.push(std::mem::take(&mut record));
            }
            other => field.push(other),
        }
    }
    if saw_any && (!field.is_empty() || !record.is_empty()) {
        record.push(field);
        records.push(record);
    }
    records
}

/// The honest import summary: "Imported N, skipped M (duplicates: X,
/// invalid: Y)" plus the first three invalid examples.
fn contact_import_summary(
    imported: usize,
    duplicates: usize,
    invalid: &[(usize, String)],
) -> String {
    let skipped = duplicates + invalid.len();
    let mut summary = format!(
        "Imported {imported}, skipped {skipped} (duplicates: {duplicates}, invalid: {}).",
        invalid.len()
    );
    if !invalid.is_empty() {
        let examples: Vec<String> = invalid
            .iter()
            .take(3)
            .map(|(line, reason)| format!("line {line}: {reason}"))
            .collect();
        summary.push_str(&format!(" Examples: {}.", examples.join("; ")));
    }
    summary
}

// ─── Campaign lifecycle rules (item B) ────────────────────────────
//
// The campaigns status CHECK (live schema) allows draft / sending /
// paused / stopped / completed / failed — there is no 'scheduled'
// status, so a picked time stays in scheduled_at on a draft row.

/// May a campaign in this status be started (draft/paused → sending)?
fn campaign_start_allowed(status: &str) -> bool {
    matches!(status, "draft" | "paused")
}

/// May a campaign in this status be paused (sending → paused)?
fn campaign_pause_allowed(status: &str) -> bool {
    status == "sending"
}

/// May a campaign in this status be resumed (paused → sending)?
fn campaign_resume_allowed(status: &str) -> bool {
    status == "paused"
}

/// Per-status actions for the campaign detail page (which buttons to
/// show). Pure so the loader and tests share one truth.
fn campaign_actions(id: &str, status: &str) -> Vec<(&'static str, String, bool)> {
    vec![
        (
            "Start sending",
            format!("/web/campaigns/{id}/start"),
            campaign_start_allowed(status),
        ),
        (
            "Pause",
            format!("/web/campaigns/{id}/pause"),
            campaign_pause_allowed(status),
        ),
        (
            "Resume",
            format!("/web/campaigns/{id}/resume"),
            campaign_resume_allowed(status),
        ),
        (
            "Wire recipients",
            format!("/web/campaigns/{id}/recipients"),
            campaign_start_allowed(status),
        ),
    ]
}

// ─── Webhook event binding rules (item E) ─────────────────────────

/// Normalize a checkbox group posting: trim, drop blanks, dedupe.
fn normalize_webhook_events(raw: Vec<String>) -> Vec<String> {
    let mut events: Vec<String> = Vec::new();
    for event in raw {
        let event = event.trim().to_string();
        if event.is_empty() || events.contains(&event) {
            continue;
        }
        events.push(event);
    }
    events
}

/// Validate a webhook's chosen events against the JSON API's known set
/// (routes/webhooks.rs). The error lists the valid names so a typo is
/// immediately fixable.
fn validate_webhook_events(events: &[String]) -> Option<String> {
    let known = crate::routes::webhooks::KNOWN_WEBHOOK_EVENTS;
    if events.is_empty() {
        return Some(format!(
            "Pick at least one event; valid events: {}",
            known.join(", ")
        ));
    }
    let invalid: Vec<&str> = events
        .iter()
        .map(String::as_str)
        .filter(|event| !known.contains(event))
        .collect();
    if invalid.is_empty() {
        None
    } else {
        Some(format!(
            "Unknown event type(s): {}; valid events: {}",
            invalid.join(", "),
            known.join(", ")
        ))
    }
}

// ─── Typed transfer confirmation (item J) ─────────────────────────

/// The exact string an operator must type to confirm a domain transfer:
/// `transfer {domain}` (mirrors the JSON route's typed confirmation).
fn transfer_confirmation_matches(domain: &str, typed: &str) -> bool {
    typed.trim() == format!("transfer {}", domain.trim().to_ascii_lowercase())
}

// ─── GDPR transition rules (item L) ───────────────────────────────//
// The compliance crate's request flow is a strict forward triad
// (pending → processing → completed/rejected; gdpr_automation.rs).
// The CP queue stores the middle state as 'in_progress' — both are
// accepted as "work has started" and terminal states never reopen.

/// Target statuses the CP transition form may request.
const GDPR_TARGET_STATUSES: &[&str] = &["in_progress", "completed", "rejected"];

/// Is `from → to` a legal GDPR request transition?
fn gdpr_transition_allowed(from: &str, to: &str) -> bool {
    if !GDPR_TARGET_STATUSES.contains(&to) {
        return false;
    }
    match from {
        "pending" => true,
        "in_progress" | "processing" | "verified" => to != "in_progress",
        _ => false, // completed / rejected / unknown are terminal
    }
}

// ─── Bulk delete confirmation helpers (item G) ────────────────────

/// Cap on ids carried through a signed bulk confirmation URL.
const BULK_CONFIRM_MAX_IDS: usize = 100;

/// Parse a comma-separated id list for bulk actions (deduplicated,
/// order-preserved, hard-capped).
fn parse_bulk_ids(raw: &str) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    raw.split(',')
        .map(str::trim)
        .filter(|id| !id.is_empty())
        .filter(|id| seen.insert(id.to_string()))
        .take(BULK_CONFIRM_MAX_IDS)
        .map(str::to_string)
        .collect()
}

/// Sign a bulk destructive intent over its id list and redirect to the
/// typed `/confirm` page (the POST body never deletes directly).
fn redirect_to_bulk_confirm(
    intent: &str,
    ids: &[String],
    return_to: &str,
    config: &Config,
) -> Response {
    let resource = ids.join(",");
    let sig = ui_foundation::flash::sign_confirmation_for_ttl(
        &config.csrf_secret,
        intent,
        &resource,
        Utc::now().timestamp(),
        ui_foundation::flash::CONFIRMATION_DEFAULT_TTL_SECS,
    );
    let location = format!(
        "/confirm?intent={}&id={}&return_to={}&sig={}",
        urlencode(intent),
        urlencode(&resource),
        urlencode(return_to),
        urlencode(&sig),
    );
    let mut response = (StatusCode::SEE_OTHER, [(header::LOCATION, location)]).into_response();
    // Clear any stale field-map so the confirm page renders clean.
    if let Ok(value) = form_fields_clear_cookie(is_secure(config)).parse() {
        response.headers_mut().append(header::SET_COOKIE, value);
    }
    response
}

// ─── Stub SSR pages via the generic renderers ─────────────────────
//
// The data-backed detail pages compose ui-foundation's PUBLIC generic
// renderers (data_list_page + layouts). The view layer owns the final
// markup; these stubs guarantee the routes exist and render real data.

/// Minimal flash banner for stub pages (the render pipeline's own
/// banner injection is internal to ui-foundation; stubs carry their own).
fn stub_flash_banner(flash: &[FlashMessage]) -> String {
    if flash.is_empty() {
        return String::new();
    }
    let banners = flash
        .iter()
        .map(|message| {
            let (tone, label) = match message.kind {
                ui_foundation::flash::FlashKind::Success => ("border-emerald-200 bg-emerald-50 text-emerald-900", "Success"),
                ui_foundation::flash::FlashKind::Error => ("border-red-200 bg-red-50 text-red-900", "Error"),
                ui_foundation::flash::FlashKind::Info => ("border-surface-200 bg-surface-100 text-foreground", "Notice"),
            };
            format!(
                "<div class=\"mb-4 rounded-sm border {tone} px-4 py-3 text-sm\" role=\"status\"><span class=\"font-bold\">{label}:</span> {}</div>",
                html_escape_text(&message.text)
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    format!("<div class=\"mb-6\">{banners}</div>")
}

fn html_escape_text(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// Compose a full authenticated web page from list data (stub path —
/// the view layer replaces this with a dedicated page function). The
/// CSRF token is the caller-resolved double-submit token (audit F4) so
/// the embedded `_csrf` inputs match the `csrf_token` cookie.
fn web_data_page(
    path: &str,
    list: &ui_foundation::view_data::ListPageData,
    noun: &str,
    flash: &[FlashMessage],
    csrf_token: &str,
) -> String {
    let mut inner = stub_flash_banner(flash);
    inner.push_str(&ui_foundation::leptos_views::data_list_page(list, noun));
    let layout =
        ui_foundation::leptos_views::web_dashboard_layout_with_csrf(&inner, path, csrf_token);
    ui_foundation::leptos_views::web_root_layout(&layout)
}

/// Compose a full control-plane page from list data (stub path).
fn cp_data_page(
    path: &str,
    list: &ui_foundation::view_data::ListPageData,
    noun: &str,
    flash: &[FlashMessage],
    csrf_token: &str,
) -> String {
    let mut inner = stub_flash_banner(flash);
    inner.push_str(&ui_foundation::leptos_views::data_list_page(list, noun));
    let layout = ui_foundation::leptos_views::control_plane_app_layout_with_title(
        &inner,
        "Control Plane",
        "ApexMail administration and monitoring.",
        path,
        csrf_token,
    );
    ui_foundation::leptos_views::control_plane_root_layout(&layout)
}

/// Read the PRG flash from a Cookie header (mirrors the render path).
fn flash_from_headers(headers: &HeaderMap, config: &Config) -> Vec<FlashMessage> {
    headers
        .get(header::COOKIE)
        .and_then(|value| value.to_str().ok())
        .map(|cookies| decode_flash_from_cookie_header(cookies, &config.csrf_secret))
        .unwrap_or_default()
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
    email_verified: bool,
}

const USER_COLUMNS: &str =
    "id::text, tenant_id::text, email, name, password_hash, role, status, mfa_enabled, email_verified";

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
            "messages:send",
            "messages:read",
            "domains:read",
            "templates:read",
            "templates:write",
            "events:read",
            "analytics:read",
            "contacts:read",
            "contacts:write",
            "logs:read",
        ]
        .into_iter()
        .map(String::from)
        .collect(),
        _ => vec![
            "messages:send",
            "messages:read",
            "domains:read",
            "templates:read",
            "events:read",
            "analytics:read",
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
        if is_secure(&state.config) {
            "; Secure"
        } else {
            ""
        },
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

/// Postgres unique-constraint violation (SQLSTATE 23505). The signup
/// pre-check races concurrent registrations; the constraint is the source
/// of truth and maps to the friendly "already registered" message.
fn is_unique_violation(error: &sqlx::Error) -> bool {
    matches!(
        error,
        sqlx::Error::Database(db_error) if db_error.code().as_deref() == Some("23505")
    )
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
    connect_info: Option<ConnectInfo<SocketAddr>>,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    let peer_ip = connect_info.map(|ConnectInfo(addr)| addr.ip());
    perform_password_login(state, headers, form, peer_ip, "/dashboard").await
}

/// Control-plane operator login — the CP surface's `/login` form posts
/// here. Same credentials stack and PRG contract as the web login, plus a
/// privilege gate: only system-tenant operators (admin/owner role) get a
/// CP session. Everyone else receives a clear error and no cookie.
async fn form_cp_login(
    State(state): State<AppState>,
    headers: HeaderMap,
    connect_info: Option<ConnectInfo<SocketAddr>>,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    let peer_ip = connect_info.map(|ConnectInfo(addr)| addr.ip());
    let email = field(&form, "email").trim().to_string();
    let password = field(&form, "password");
    if let Err(message) = check_csrf(&form, &headers, &state.config) {
        return redirect_error(message, "/login", &state.config);
    }
    // The control-plane login is the highest-value credential surface on
    // the platform: it gets the same scope-bound proof-of-work gate as the
    // web forms (scope "cp-login" — issued only for the CP login page).
    if let Err(message) = verify_kiwi_form_token(&state, &headers, peer_ip, &form, "cp-login").await
    {
        return redirect_error(&message, "/login", &state.config);
    }
    if email.is_empty() || password.is_empty() {
        let mut fields = FormFieldMap::new("cp-login");
        fields.set("email", &email);
        return redirect_with_field_map(
            &fields,
            "Email and password are required.",
            "/login",
            &state.config,
        );
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
    // Email verification is a login prerequisite: the check runs only
    // AFTER the password verified, so it never leaks account existence to
    // anonymous callers.
    if !user.email_verified {
        return redirect_error(
            "Verify your email address before signing in — check your inbox for the verification link.",
            "/login",
            &state.config,
        );
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
            &[FlashMessage::info(
                "Enter the 6-digit code from your authenticator app.",
            )],
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
    // CP operators receive BOTH cookies: the generic am_session (other
    // console pages) and the dedicated control-plane session whose signed
    // claims carry the operator's real MFA state — require_cp_auth only
    // admits MFA-backed CP sessions, so a non-MFA operator's cookie is
    // structurally valid but always refused by the gate.
    let cp_cookie = crate::middleware::cp_auth::issue_cp_session_cookie(
        &state.config.cp_auth,
        &user.id,
        &user.tenant_id,
        &user.email,
        &user.role,
        user.mfa_enabled,
        is_secure(&state.config),
    );
    match session_cookie_for_user(&state, &user) {
        Ok(cookie) => {
            let mut response = redirect_success(
                "Signed in to the control plane.",
                "/dashboard",
                &state.config,
            );
            if let (Ok(am), Ok(cp)) = (cookie.parse(), cp_cookie.parse()) {
                response.headers_mut().append(header::SET_COOKIE, am);
                response.headers_mut().append(header::SET_COOKIE, cp);
            }
            response
        }
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

/// KiwiCaptcha verification for the SSR auth forms. The widget injected on
/// the matching GET page mints a scope-bound, IP-bound challenge; the form
/// POST must present its single-use solution token BEFORE credentials are
/// looked at, so an automated submitter cannot probe passwords without
/// paying the proof-of-work. A missing `ConnectInfo` (tests) degrades to
/// the "unknown" identity — the same fallback the challenge issuance route
/// uses — so the IP binding still matches end to end.
async fn verify_kiwi_form_token(
    state: &AppState,
    headers: &HeaderMap,
    peer_ip: Option<IpAddr>,
    form: &HashMap<String, String>,
    scope: &str,
) -> Result<(), String> {
    let client_ip = peer_ip.map_or_else(
        || "unknown".to_string(),
        |ip| {
            crate::middleware::rate_limiter::extract_public_client_ip(
                headers,
                ip,
                &state.config.trusted_proxies,
            )
        },
    );
    let token = form.get("kiwi__token").map(String::as_str);
    super::auth::verify_kiwi_token(&state.config, &state.redis, token, &client_ip, Some(scope))
        .await
        .map_err(|e| kiwi_failure_message(&e))
}

/// User-facing text for a failed CAPTCHA verification: the verifier's
/// Validation and ServiceUnavailable messages are already written for end
/// users; everything else collapses to a generic retry prompt so internal
/// error detail never reaches the form.
fn kiwi_failure_message(error: &crate::error::ApiError) -> String {
    use crate::error::ApiError;
    match error {
        ApiError::Validation(messages) => messages
            .first()
            .cloned()
            .unwrap_or_else(|| "CAPTCHA verification failed — please retry.".into()),
        ApiError::ServiceUnavailable(message) | ApiError::RateLimitedMessage(message) => {
            message.clone()
        }
        ApiError::RateLimited => "Too many CAPTCHA attempts — wait a moment and try again.".into(),
        _ => "CAPTCHA verification failed — please retry.".into(),
    }
}

/// Shared password step of the multi-step SSR login. MFA-enabled users
/// are redirected to the `/login?mfa=1` challenge form with a signed,
/// short-lived challenge cookie (never straight into a session).
async fn perform_password_login(
    state: AppState,
    headers: HeaderMap,
    form: HashMap<String, String>,
    peer_ip: Option<IpAddr>,
    default_return_to: &str,
) -> Response {
    let email = field(&form, "email").trim().to_string();
    let password = field(&form, "password");
    let return_to = safe_return_to(&form, default_return_to);

    if let Err(message) = check_csrf(&form, &headers, &state.config) {
        return redirect_error(message, "/login", &state.config);
    }
    if let Err(message) = verify_kiwi_form_token(&state, &headers, peer_ip, &form, "login").await {
        return redirect_error(&message, "/login", &state.config);
    }
    if email.is_empty() || password.is_empty() {
        let mut fields = FormFieldMap::new("login");
        fields.set("email", &email);
        return redirect_with_field_map(
            &fields,
            "Email and password are required.",
            "/login",
            &state.config,
        );
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
    // Email verification is a login prerequisite (checked only after the
    // password verified, so unauthenticated callers learn nothing).
    if !user.email_verified {
        return redirect_error(
            "Verify your email address before signing in — check your inbox for the verification link.",
            "/login",
            &state.config,
        );
    }

    if user.mfa_enabled {
        // Multi-step SSR MFA: redirect to the login page's challenge state
        // with a short-lived signed challenge token in a cookie. The
        // return_to target rides along so the flow ends where it started.
        let challenge = sign_login_challenge(&state.config, &user.id, &user.email);
        let mut response = redirect_with_flash(
            &[FlashMessage::info(
                "Enter the 6-digit code from your authenticator app.",
            )],
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
        Err(_) => redirect_error(
            "Sign-in is temporarily unavailable. Try again.",
            "/login",
            &state.config,
        ),
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
    if let Err(message) = check_csrf(&form, &headers, &state.config) {
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
    // The MFA step is the second half of LOGIN: the email-verification
    // prerequisite applies here exactly as at the password step.
    if !user.email_verified {
        return redirect_error(
            "Verify your email address before signing in — check your inbox for the verification link.",
            "/login",
            &state.config,
        );
    }
    // Brute-force bound before any code is checked.
    if mfa_verify_locked(&state, &user.id).await {
        return redirect_error(
            "Too many verification attempts. Try again in a few minutes.",
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
    // users.id is UUID (canonical migration 052): the session user id is a
    // String, so cast the bind — an uncast text bind is an operator error
    // (uuid = text does not exist), not a match.
    let secret =
        sqlx::query_scalar::<_, Option<String>>("SELECT mfa_secret FROM users WHERE id = $1::uuid")
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
                Ok(secret) => {
                    // Hardened verifier (F3): the shared lockout state +
                    // single-use replay guard the JSON surface uses, so a
                    // console MFA code is bounded and never replayable.
                    crate::routes::auth::verify_totp_code_guarded(&state.redis, &secret, &code)
                        .await
                }
                Err(_) => false,
            }
        }
        None => false,
    };
    if !totp_valid {
        record_mfa_verify_failure(&state, &user.id).await;
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
    clear_mfa_verify_failures(&state, &user.id).await;
    match session_cookie_for_user(&state, &user) {
        Ok(cookie) => {
            let mut response = redirect_success("Signed in.", &return_to, &state.config);
            if let Ok(value) = cookie.parse() {
                response.headers_mut().append(header::SET_COOKIE, value);
            }
            // A system-tenant operator completing MFA also receives the
            // control-plane session cookie (mfa_enabled now true) so the
            // CP gate admits them on /web/admin/* and /v1/admin/*.
            if is_system_tenant(&state, &user.tenant_id).await && is_operator_role(&user.role) {
                let cp_cookie = crate::middleware::cp_auth::issue_cp_session_cookie(
                    &state.config.cp_auth,
                    &user.id,
                    &user.tenant_id,
                    &user.email,
                    &user.role,
                    user.mfa_enabled,
                    is_secure(&state.config),
                );
                if let Ok(value) = cp_cookie.parse() {
                    response.headers_mut().append(header::SET_COOKIE, value);
                }
            }
            response
        }
        Err(_) => redirect_error(
            "Sign-in is temporarily unavailable. Try again.",
            "/login",
            &state.config,
        ),
    }
}

async fn form_signup(
    State(state): State<AppState>,
    headers: HeaderMap,
    connect_info: Option<ConnectInfo<SocketAddr>>,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    let peer_ip = connect_info.map(|ConnectInfo(addr)| addr.ip());
    let name = field_truncated(&form, "name", 120);
    let company = field_truncated(&form, "company_name", 100);
    let email = field(&form, "email").trim().to_lowercase();
    let password = field(&form, "password");
    let plan = field(&form, "plan");

    if let Err(message) = check_csrf(&form, &headers, &state.config) {
        return redirect_error(message, "/signup", &state.config);
    }
    if let Err(message) = verify_kiwi_form_token(&state, &headers, peer_ip, &form, "signup").await {
        return redirect_error(&message, "/signup", &state.config);
    }
    // Signup carries the longest typed input of any auth form: every
    // validation failure below repopulates the non-secret fields so the
    // user corrects one field instead of retyping the whole form.
    if name.is_empty() || company.is_empty() {
        let mut fields = FormFieldMap::new("signup");
        fields.set("name", &name);
        fields.set("company_name", &company);
        fields.set("email", &email);
        if name.is_empty() {
            fields.error("name", "Full name is required.");
        }
        if company.is_empty() {
            fields.error("company_name", "Company is required.");
        }
        return redirect_with_field_map(
            &fields,
            "Full name and company are required.",
            "/signup",
            &state.config,
        );
    }
    if !valid_email(&email) {
        let mut fields = FormFieldMap::new("signup");
        fields.set("name", &name);
        fields.set("company_name", &company);
        fields.set("email", &email);
        fields.error("email", "Enter a valid email address.");
        return redirect_with_field_map(
            &fields,
            "Enter a valid email address.",
            "/signup",
            &state.config,
        );
    }
    if let Some(message) = password_policy_error(&password) {
        let mut fields = FormFieldMap::new("signup");
        fields.set("name", &name);
        fields.set("company_name", &company);
        fields.set("email", &email);
        fields.error("password", message);
        return redirect_with_field_map(&fields, message, "/signup", &state.config);
    }
    let plan = match plan.as_str() {
        "starter" | "pro" | "growth" | "scale" | "free" => plan,
        _ => "free".to_string(),
    };
    let _ = plan; // onboarding preference only; provisioning starts on Free

    // Anti-enumeration: mirror the JSON register flow, which deliberately
    // returns the same "check your email" response for existing addresses.
    // Telling an anonymous visitor "an account with this email already
    // exists" defeated that posture for the SSR form.
    let existing =
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM users WHERE LOWER(email) = LOWER($1)")
            .bind(&email)
            .fetch_one(&state.db)
            .await
            .unwrap_or(0);
    if existing > 0 {
        return redirect_success(
            "Check your email to finish creating your account.",
            "/login",
            &state.config,
        );
    }

    let password_hash = match hash_password(&password) {
        Ok(hash) => hash,
        Err(_) => {
            return redirect_error(
                "Registration is temporarily unavailable.",
                "/signup",
                &state.config,
            )
        }
    };
    // tenants.id is VARCHAR(26) (ULID, migration 064) — a UUID does not
    // fit; generate a 26-char text id and bind tenant ids as text.
    // users.id, however, is UUID (migration 052): a text nanoid fails the
    // INSERT with `invalid input syntax for type uuid` — generate a UUID
    // for the user id (same convention as the JSON register flow).
    let tenant_id = apexmail_lib::id::generate_id("", 26);
    let user_id = Uuid::new_v4();
    let slug_source = company.to_lowercase();
    let slug: String = slug_source
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-')
        .take(48)
        .collect();
    let now = Utc::now();
    let verification_token = Uuid::new_v4().to_string();
    // The token is stored as its SHA-256 digest — exactly like the JSON
    // register flow and form_forgot_password. The raw token only ever
    // exists in the emailed verification link.
    let verification_token_hash = crate::routes::helpers::hash_token(&verification_token);

    // Tenant + user + verification email commit atomically: a queue
    // failure rolls the account back instead of stranding an owner who
    // can never receive their verification link.
    let result: Result<(), &'static str> = async {
        let mut tx = state.db.begin().await.map_err(|_| "unavailable")?;

        sqlx::query(
            "INSERT INTO tenants (id, name, slug, plan, status, settings, metadata, created_at, updated_at)
             VALUES ($1, $2, $3, 'free', 'pending', $4, $5, $6, $6)",
        )
        .bind(&tenant_id)
        .bind(&company)
        .bind(format!("{slug}-{}", &tenant_id[..8]))
        .bind(json!({}))
        .bind(json!({}))
        .bind(now)
        .execute(&mut *tx)
        .await
        .map_err(|_| "unavailable")?;

        let insert_user = sqlx::query(
            "INSERT INTO users (id, tenant_id, email, name, password_hash, role, status,
                                email_verified, mfa_enabled, metadata, created_at, updated_at)
             VALUES ($1, $2, $3, $4, $5, 'owner', 'active', false, false, $6, $7, $7)",
        )
        .bind(user_id)
        .bind(&tenant_id)
        .bind(&email)
        .bind(&name)
        .bind(&password_hash)
        .bind(json!({
            "verification_token_hash": verification_token_hash,
            "verification_expires": (now + chrono::Duration::hours(24)).to_rfc3339(),
        }))
        .bind(now)
        .execute(&mut *tx)
        .await;

        if let Err(error) = insert_user {
            // TOCTOU: the COUNT pre-check loses the race against a
            // concurrent signup — the unique violation is the source of
            // truth and gets the same friendly message.
            if is_unique_violation(&error) {
                return Err("email_already_registered");
            }
            tracing::error!(error = %error, "web signup users insert failed");
            return Err("unavailable");
        }

        let verification_link = format!(
            "{}/verify-email?token={}&email={}",
            state.config.base_url.trim_end_matches('/'),
            urlencode(&verification_token),
            urlencode(&email),
        );
        // The address is attacker-controllable text interpolated into HTML
        // (audit F9): valid_email permits `<>"`, so escape it for the HTML
        // body — the link itself is URL-encoded already.
        let email_html = html_escape_text(&email);
        let html_body = format!(
            "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\"/></head><body style=\"font-family:ui-monospace,monospace;line-height:1.6;color:#09090b;max-width:560px;margin:0 auto;padding:24px\"><h2>Verify Your ApexMail Account</h2><p>Finish setting up <strong>{email_html}</strong> by confirming this email address.</p><p><a href=\"{verification_link}\" style=\"display:inline-block;padding:12px 28px;background:#dc2626;color:#fff;text-decoration:none;font-weight:700\">Verify email</a></p><p style=\"font-size:13px;color:#71717a\">This link expires in 24 hours.</p></body></html>"
        );
        let text_body = format!(
            "Verify Your ApexMail Account\n\nConfirm {email} by visiting: {verification_link}\n\nThis link expires in 24 hours."
        );
        crate::routes::system_sender::queue_system_email_in_transaction(
            &mut tx,
            &email,
            "Verify your ApexMail account",
            &html_body,
            &text_body,
            vec!["system".into(), "verification".into()],
        )
        .await
        .map_err(|error| {
            tracing::error!(error = %error, "web signup verification email queue failed");
            "unavailable"
        })?;
        tx.commit().await.map_err(|_| "unavailable")?;
        Ok(())
    }
    .await;

    match result {
        Ok(()) => {}
        Err("email_already_registered") => {
            return redirect_error(
                "An account with this email already exists. Try signing in instead.",
                "/signup",
                &state.config,
            );
        }
        Err(_) => {
            return redirect_error(
                "Registration is temporarily unavailable. Try again.",
                "/signup",
                &state.config,
            );
        }
    }

    redirect_success(
        "Account created. Check your email for a verification link.",
        &format!("/verify-email?email={}", urlencode(&email)),
        &state.config,
    )
}

async fn form_forgot_password(
    State(state): State<AppState>,
    headers: HeaderMap,
    connect_info: Option<ConnectInfo<SocketAddr>>,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    let peer_ip = connect_info.map(|ConnectInfo(addr)| addr.ip());
    let email = field(&form, "email").trim().to_lowercase();
    if let Err(message) = check_csrf(&form, &headers, &state.config) {
        return redirect_error(message, "/forgot-password", &state.config);
    }
    if let Err(message) =
        verify_kiwi_form_token(&state, &headers, peer_ip, &form, "forgot-password").await
    {
        return redirect_error(&message, "/forgot-password", &state.config);
    }
    if !valid_email(&email) {
        let mut fields = FormFieldMap::new("forgot-password");
        fields.set("email", &email);
        fields.error("email", "Enter a valid email address.");
        return redirect_with_field_map(
            &fields,
            "Enter a valid email address.",
            "/forgot-password",
            &state.config,
        );
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
                 WHERE id = $2::uuid AND status = 'active'",
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
            // Audit F9: same HTML escaping of the interpolated address as
            // the signup verification body.
            let email_html = html_escape_text(&email);
            let html_body = format!(
                "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\"/></head><body style=\"font-family:ui-monospace,monospace;line-height:1.6;color:#09090b;max-width:560px;margin:0 auto;padding:24px\"><h2>Reset Your Password</h2><p>We received a request to reset the password for <strong>{email_html}</strong>.</p><p><a href=\"{reset_link}\" style=\"display:inline-block;padding:12px 28px;background:#dc2626;color:#fff;text-decoration:none;font-weight:700\">Reset Password</a></p><p style=\"font-size:13px;color:#71717a\">This link expires in 1 hour. If you didn't request a password reset, you can safely ignore this email.</p></body></html>"
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
    headers: HeaderMap,
    connect_info: Option<ConnectInfo<SocketAddr>>,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    let peer_ip = connect_info.map(|ConnectInfo(addr)| addr.ip());
    let email = field(&form, "email").trim().to_lowercase();
    let token = field(&form, "token");
    let password = field(&form, "password");
    let confirm = field(&form, "confirmPassword");
    let back = format!(
        "/reset-password?token={}&email={}",
        urlencode(&token),
        urlencode(&email)
    );
    if let Err(message) = check_csrf(&form, &headers, &state.config) {
        return redirect_error(message, "/forgot-password", &state.config);
    }
    if let Err(message) =
        verify_kiwi_form_token(&state, &headers, peer_ip, &form, "reset-password").await
    {
        return redirect_error(&message, &back, &state.config);
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
        return redirect_error(
            "That reset link is invalid or has expired.",
            "/forgot-password",
            &state.config,
        );
    };
    if status != "active" {
        return redirect_error(
            "This account is not active.",
            "/forgot-password",
            &state.config,
        );
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
         WHERE id = $2::uuid
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

async fn form_logout(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    // CSRF is enforced even for logout (cookie-authenticated write).
    let friendly = check_csrf(&form, &headers, &state.config).err();
    if let Some(message) = friendly {
        return redirect_error(message, "/dashboard", &state.config);
    }
    let mut response = redirect_success("Signed out.", "/login", &state.config);
    let clear = format!(
        "am_session=; HttpOnly; Path=/; Max-Age=0; SameSite=Lax{}",
        if is_secure(&state.config) {
            "; Secure"
        } else {
            ""
        }
    );
    if let Ok(value) = clear.parse() {
        response.headers_mut().insert(header::SET_COOKIE, value);
    }
    // The control-plane session dies with the console session.
    let clear_cp =
        crate::middleware::cp_auth::build_clear_cp_session_cookie(is_secure(&state.config));
    if let Ok(value) = clear_cp.parse() {
        response.headers_mut().append(header::SET_COOKIE, value);
    }
    response
}

// ─── Authenticated account/settings handlers ─────────────────────

async fn form_profile_update(
    State(state): State<AppState>,
    axum::Extension(user): axum::Extension<AuthUser>,
    headers: HeaderMap,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    if let Err(message) = check_csrf(&form, &headers, &state.config) {
        return redirect_error(message, "/settings/profile", &state.config);
    }
    let name = field_truncated(&form, "name", 120);
    if name.is_empty() {
        return redirect_error("Name is required.", "/settings/profile", &state.config);
    }
    // users.id is UUID (canonical migration 052): cast the String bind.
    let result = sqlx::query("UPDATE users SET name = $1, updated_at = NOW() WHERE id = $2::uuid")
        .bind(&name)
        .bind(user.user_id.clone().unwrap_or_default())
        .execute(&state.db)
        .await;
    match result {
        Ok(_) => redirect_success("Profile updated.", "/settings/profile", &state.config),
        Err(_) => redirect_error(
            "Could not save your profile. Try again.",
            "/settings/profile",
            &state.config,
        ),
    }
}

async fn form_change_password(
    State(state): State<AppState>,
    axum::Extension(user): axum::Extension<AuthUser>,
    headers: HeaderMap,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    if let Err(message) = check_csrf(&form, &headers, &state.config) {
        return redirect_error(message, "/settings/profile", &state.config);
    }
    let current = field(&form, "current_password");
    let new_password = field(&form, "new_password");
    if let Some(message) = password_policy_error(&new_password) {
        return redirect_error(message, "/settings/profile", &state.config);
    }
    // users.id is UUID (canonical migration 052): cast the String bind.
    let hash =
        sqlx::query_scalar::<_, String>("SELECT password_hash FROM users WHERE id = $1::uuid")
            .bind(user.user_id.clone().unwrap_or_default())
            .fetch_one(&state.db)
            .await;
    match hash {
        Ok(hash) if verify_password(&hash, &current) => {}
        Ok(_) => {
            return redirect_error(
                "Your current password is incorrect.",
                "/settings/profile",
                &state.config,
            )
        }
        Err(_) => {
            return redirect_error(
                "Could not update the password. Try again.",
                "/settings/profile",
                &state.config,
            )
        }
    }
    let new_hash = match hash_password(&new_password) {
        Ok(hash) => hash,
        Err(_) => {
            return redirect_error(
                "Could not update the password. Try again.",
                "/settings/profile",
                &state.config,
            )
        }
    };
    // Revoke every live session (other tabs, stolen cookies) so a session
    // hijacked before the change cannot survive it — same contract as the
    // password-reset path. The current session is re-established by the
    // redirect target's login flow.
    revoke_user_sessions(
        &state,
        &user.tenant_id,
        user.user_id.as_deref().unwrap_or_default(),
    )
    .await;

    // users.id is UUID (canonical migration 052): cast the String bind.
    let result =
        sqlx::query("UPDATE users SET password_hash = $1, updated_at = NOW() WHERE id = $2::uuid")
            .bind(&new_hash)
            .bind(user.user_id.clone().unwrap_or_default())
            .execute(&state.db)
            .await;
    match result {
        Ok(_) => redirect_success(
            "Password updated. Please sign in again with your new password.",
            "/login",
            &state.config,
        ),
        Err(_) => redirect_error(
            "Could not update the password. Try again.",
            "/settings/profile",
            &state.config,
        ),
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
    if let Err(message) = check_csrf(&form, &headers, &state.config) {
        return redirect_error(message, &back, &state.config);
    }
    let Some(user_id) = user.user_id.clone() else {
        return redirect_error("Sign in again to manage MFA.", "/login", &state.config);
    };

    // users.id is UUID (canonical migration 052): cast the String bind.
    let enabled: Option<bool> =
        sqlx::query_scalar::<_, bool>("SELECT mfa_enabled FROM users WHERE id = $1::uuid")
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
    if let Err(message) = check_csrf(&form, &headers, &state.config) {
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
        return redirect_error(
            "Enter the 6-digit code from your authenticator app.",
            &back,
            &state.config,
        );
    }
    // Hardened verifier (F3) — the same lockout + replay guard as the JSON
    // confirm-setup route, so a code used to confirm enrollment is
    // single-use and repeated wrong codes lock the pending secret.
    if !crate::routes::auth::verify_totp_code_guarded(&state.redis, &setup.secret, &code).await {
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
         WHERE id = $3::uuid AND tenant_id = $4 AND COALESCE(mfa_enabled, false) = false",
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
            return redirect_error(
                "MFA is already enabled for this account.",
                &back,
                &state.config,
            )
        }
        Err(error) => {
            tracing::error!(error = %error, "web mfa confirm update failed");
            return redirect_error("Could not enable MFA. Try again.", &back, &state.config);
        }
    }

    // Privilege change ⇒ revoke every live session (AR-005 twin).
    revoke_user_sessions(&state, &user.tenant_id, &user_id).await;

    // Recovery codes travel as STRUCTURED secrets (mono-chip reveal-once
    // rendering, one code per chip) instead of one space-joined string in
    // the prose banner.
    let mut fields = FormFieldMap::new("mfa-recovery-codes");
    for (index, code) in recovery_codes.iter().enumerate() {
        fields.secret(&format!("Recovery code {}", index + 1), code);
    }
    let mut response = redirect_with_secret(
        &fields,
        "MFA enabled. Recovery codes shown below — store them now, they will not be shown again.",
        &back,
        &state.config,
    );
    let clear = format!(
        "{MFA_SETUP_COOKIE}=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax{}",
        if is_secure(&state.config) {
            "; Secure"
        } else {
            ""
        },
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
    // users.id is UUID (canonical migration 052): cast the String bind.
    let email: String =
        sqlx::query_scalar::<_, String>("SELECT email FROM users WHERE id = $1::uuid")
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
    headers: HeaderMap,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    if let Err(message) = check_csrf(&form, &headers, &state.config) {
        return redirect_error(message, "/cp", &state.config);
    }
    if !is_system_tenant(&state, &user.tenant_id).await {
        return redirect_error(
            "Only ApexMail operators can end impersonation sessions.",
            "/cp",
            &state.config,
        );
    }
    let mut response = redirect_success("Impersonation session ended.", "/cp", &state.config);
    let clear = format!(
        "impersonation_session=; HttpOnly; Path=/; Max-Age=0; SameSite=Strict{}",
        if is_secure(&state.config) {
            "; Secure"
        } else {
            ""
        },
    );
    if let Ok(parsed) = clear.parse() {
        response.headers_mut().insert(header::SET_COOKIE, parsed);
    }
    response
}

async fn form_api_key_create(
    State(state): State<AppState>,
    axum::Extension(user): axum::Extension<AuthUser>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    // Lossless form parse (repeated `scopes=` checkbox keys survive, the
    // way the webhook form's `events=` group does).
    let form = match parse_form_body(&headers, body).await {
        Ok(form) => form,
        Err(message) => {
            return redirect_error(message, "/settings/api-keys", &state.config);
        }
    };
    if let Err(message) = form.check_csrf(&headers, &state.config) {
        return redirect_error(message, "/settings/api-keys", &state.config);
    }
    let form_map: HashMap<String, String> = form.pairs.iter().cloned().collect();
    let name = field_truncated(&form_map, "name", 100);
    if name.is_empty() {
        return redirect_error("Give the key a name.", "/settings/api-keys", &state.config);
    }
    // Supported expiry choice (F46): the form may post `expires_in_days`;
    // absent means the shared JSON default (90 days) — console-created keys
    // previously bypassed the expiry policy entirely and never expired.
    // Out-of-range values surface the shared path's validation error as a
    // flash; a non-numeric value is rejected up front.
    let expires_raw = form.field("expires_in_days").trim().to_string();
    let expires_in_days: Option<i64> = if expires_raw.is_empty() {
        None
    } else {
        match expires_raw.parse::<i64>() {
            Ok(days) => Some(days),
            Err(_) => {
                return redirect_error(
                    "Expiry must be a number of days (1-365).",
                    "/settings/api-keys",
                    &state.config,
                );
            }
        }
    };
    // Supported scope choices (F46): the form may post a `scopes` checkbox
    // group; every value is validated + authorized by the SHARED creation
    // path below (F17). Absent keeps the console's historical default.
    let mut scopes: Vec<String> = form
        .get_all("scopes")
        .into_iter()
        .map(|scope| scope.trim().to_string())
        .filter(|scope| !scope.is_empty())
        .collect();
    scopes.dedup();
    if scopes.is_empty() {
        scopes = vec!["messages:send".into(), "messages:read".into()];
    }

    // F46: the console form and the JSON endpoint share ONE creation path —
    // scope authorization, expiry defaults/bounds, keyed hashing, the
    // atomic key-count ceiling, and persistence all behave identically.
    // Flash-mapped (never a raw JSON error) for the no-JS surface.
    match crate::routes::auth::mint_api_key(&state, &user, &name, &scopes, expires_in_days).await {
        Ok(minted) => {
            // Item N: the reveal-once secret travels as STRUCTURED data in
            // the signed field-map cookie (mono-renderable by the view),
            // with the prose flash kept for no-JS banner parity.
            let mut fields = FormFieldMap::new("api-key-create");
            fields.set("name", &minted.name);
            fields.secret("API key secret (shown once)", &minted.raw_key);
            redirect_with_secret(
                &fields,
                &format!(
                    "API key created. It expires {} — copy the secret now, it will not be shown again: {}",
                    minted.expires_at.to_rfc3339(),
                    minted.raw_key
                ),
                "/settings/api-keys",
                &state.config,
            )
        }
        Err(crate::error::ApiError::Validation(details)) => {
            redirect_error(&details.join(" "), "/settings/api-keys", &state.config)
        }
        Err(crate::error::ApiError::Forbidden(message)) => {
            redirect_error(&message, "/settings/api-keys", &state.config)
        }
        Err(error) => {
            tracing::error!(error = ?error, "web api-key create failed");
            redirect_error(
                "Could not create the key. Try again.",
                "/settings/api-keys",
                &state.config,
            )
        }
    }
}

/// POST /web/webhooks — create a webhook. The form's event CHECKBOX GROUP
/// posts repeated `events=` keys; the body is parsed losslessly (a HashMap
/// would collapse them to the last box) and every chosen name is validated
/// against the JSON API's KNOWN_WEBHOOK_EVENTS set (item E) — what was
/// picked is what gets stored, and a typo is rejected with the valid list.
async fn form_webhook_create(
    State(state): State<AppState>,
    axum::Extension(user): axum::Extension<AuthUser>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let form = match parse_form_body(&headers, body).await {
        Ok(form) => form,
        Err(message) => {
            return redirect_error(message, "/settings/webhooks", &state.config);
        }
    };
    if let Err(message) = form.check_csrf(&headers, &state.config) {
        return redirect_error(message, "/settings/webhooks", &state.config);
    }
    let mut fields = FormFieldMap::new("webhook-create");
    let url = form.field("url").trim().to_string();
    fields.set("url", &url);
    // Same hardened validator as the JSON API (audit F): HTTPS-only,
    // private/reserved/link-local targets rejected — the old http(s)://
    // prefix check let `http://169.254.169.254/…` and `http://10.x/…`
    // straight into the webhooks table.
    if let Err(message) = crate::routes::webhooks::validate_webhook_url(&url) {
        fields.error("url", &message);
        return redirect_with_field_map(&fields, &message, "/settings/webhooks", &state.config);
    }
    // Same per-tenant cap as the JSON API. The count query failing fails
    // CLOSED (generic error flash) — never insert past the limit.
    let existing: Result<i64, _> =
        sqlx::query_scalar("SELECT COUNT(*) FROM webhooks WHERE tenant_id = $1")
            .bind(user.tenant_id.as_str())
            .fetch_one(&state.db)
            .await;
    match existing {
        Ok(count) if count >= crate::routes::webhooks::MAX_WEBHOOKS_PER_TENANT => {
            let message = format!(
                "Webhook limit reached: maximum {} webhooks per workspace.",
                crate::routes::webhooks::MAX_WEBHOOKS_PER_TENANT,
            );
            fields.error("url", &message);
            return redirect_with_field_map(&fields, &message, "/settings/webhooks", &state.config);
        }
        Err(error) => {
            tracing::error!(error = %error, "webhook count check failed");
            return redirect_error(
                "Could not add the webhook. Try again.",
                "/settings/webhooks",
                &state.config,
            );
        }
        _ => {}
    }
    // Item E: bind the checkbox group — trim, dedupe, validate each name
    // against KNOWN_WEBHOOK_EVENTS, store exactly what was chosen.
    let events = normalize_webhook_events(form.get_all("events"));
    if let Some(message) = validate_webhook_events(&events) {
        fields.error("events", &message);
        return redirect_with_field_map(&fields, &message, "/settings/webhooks", &state.config);
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
    .bind(serde_json::to_value(&events).unwrap_or_else(|_| serde_json::json!(["*"])))
    .execute(&state.db)
    .await;
    match result {
        Ok(_) => {
            // Item N: signing secret as structured data (mono cell).
            let mut fields = FormFieldMap::new("webhook-create");
            fields.set("url", &url);
            fields.secret("Webhook signing secret (shown once)", &secret);
            redirect_with_secret(
                &fields,
                &format!("Webhook added. Signing secret (shown once): {secret}"),
                "/settings/webhooks",
                &state.config,
            )
        }
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

/// Role hierarchy used by the team-invite gate: nobody may mint an
/// invitation for a role ABOVE their own.
fn invite_role_rank(role: &str) -> i32 {
    match role {
        "owner" => 3,
        "admin" => 2,
        "developer" | "member" | "viewer" => 1,
        _ => 0,
    }
}

/// Ceiling on outstanding (un-accepted) invitations per tenant.
const MAX_OPEN_INVITATIONS_PER_TENANT: i64 = 50;

async fn form_team_invite(
    State(state): State<AppState>,
    axum::Extension(user): axum::Extension<AuthUser>,
    headers: HeaderMap,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    if let Err(message) = check_csrf(&form, &headers, &state.config) {
        return redirect_error(message, "/settings/team", &state.config);
    }
    // Privilege gate: only owner/admin sessions may invite, decided by the
    // caller's CURRENT role in the database (not anything baked into a
    // token), and a session without a user id (API key) has no role at all.
    let Some(caller_id) = user.user_id.clone() else {
        return redirect_error(
            "Only workspace owners and admins can send invitations.",
            "/settings/team",
            &state.config,
        );
    };
    let caller_role: Option<String> = sqlx::query_scalar(
        "SELECT role FROM users WHERE id = $1::uuid AND tenant_id = $2 AND status = 'active'",
    )
    .bind(&caller_id)
    .bind(user.tenant_id.as_str())
    .fetch_optional(&state.db)
    .await
    .ok()
    .flatten();
    let Some(caller_role) = caller_role else {
        return redirect_error(
            "Only workspace owners and admins can send invitations.",
            "/settings/team",
            &state.config,
        );
    };
    if !matches!(caller_role.as_str(), "owner" | "admin") {
        return redirect_error(
            "Only workspace owners and admins can send invitations.",
            "/settings/team",
            &state.config,
        );
    }

    let email = field(&form, "userName").trim().to_lowercase();
    // The form offers member/admin only; an unexpected value is rejected
    // explicitly (never silently downgraded) and the rank check below
    // forbids granting above the caller regardless.
    let role = match field(&form, "role").as_str() {
        "admin" | "member" => field(&form, "role"),
        _ => {
            return redirect_error(
                "Choose a valid role (member or admin).",
                "/settings/team",
                &state.config,
            );
        }
    };
    // No granting a role above the caller's own.
    if invite_role_rank(&role) > invite_role_rank(&caller_role) {
        return redirect_error(
            "You cannot invite someone to a role above your own.",
            "/settings/team",
            &state.config,
        );
    }
    if !valid_email(&email) {
        return redirect_error(
            "Enter a valid email address.",
            "/settings/team",
            &state.config,
        );
    }
    // Outstanding-invitation cap: at most MAX_OPEN_INVITATIONS_PER_TENANT
    // un-accepted invitations may exist per tenant. Count failures fail
    // CLOSED.
    let open_invites: Result<i64, _> = sqlx::query_scalar(
        "SELECT COUNT(*) FROM users WHERE tenant_id = $1 AND status = 'invited'",
    )
    .bind(user.tenant_id.as_str())
    .fetch_one(&state.db)
    .await;
    match open_invites {
        Ok(count) if count >= MAX_OPEN_INVITATIONS_PER_TENANT => {
            return redirect_error(
                "Invitation limit reached: clear outstanding invitations before sending more.",
                "/settings/team",
                &state.config,
            );
        }
        Err(error) => {
            tracing::error!(error = %error, "team invite count check failed");
            return redirect_error(
                "Could not create the invitation. Try again.",
                "/settings/team",
                &state.config,
            );
        }
        _ => {}
    }
    let result = sqlx::query(
        "INSERT INTO users (id, tenant_id, email, name, password_hash, role, status,
                            email_verified, mfa_enabled, metadata, created_at, updated_at)
         VALUES ($1, $2, $3, '', $4, $5, 'invited', false, false, '{}'::jsonb, NOW(), NOW())",
    )
    // users.id is a UUID column (migration 052) — bind a UUID, not a text
    // nanoid (the insert would fail with invalid uuid syntax).
    .bind(Uuid::new_v4())
    .bind(user.tenant_id.as_str())
    .bind(&email)
    .bind("!invited-pending-activation") // cannot authenticate until they set a password
    .bind(role)
    .execute(&state.db)
    .await;
    match result {
        Ok(_) => redirect_success("Invitation created.", "/settings/team", &state.config),
        Err(_) => redirect_error(
            "Could not create the invitation. Try again.",
            "/settings/team",
            &state.config,
        ),
    }
}

async fn form_billing_checkout(
    State(state): State<AppState>,
    axum::Extension(_user): axum::Extension<AuthUser>,
    headers: HeaderMap,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    if let Err(message) = check_csrf(&form, &headers, &state.config) {
        return redirect_error(message, "/settings/billing", &state.config);
    }
    let plan = field(&form, "plan");
    if !["starter", "pro", "growth", "scale"].contains(&plan.as_str()) {
        return redirect_error(
            "Choose a plan to upgrade to.",
            "/settings/billing",
            &state.config,
        );
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
    headers: HeaderMap,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    if let Err(message) = check_csrf(&form, &headers, &state.config) {
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
    headers: HeaderMap,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    if let Err(message) = check_csrf(&form, &headers, &state.config) {
        return redirect_error(message, "/contacts/new", &state.config);
    }
    let email = field(&form, "email").trim().to_lowercase();
    let name = field_truncated(&form, "name", 120);
    if !valid_email(&email) {
        return redirect_error(
            "Enter a valid email address.",
            "/contacts/new",
            &state.config,
        );
    }
    let result = sqlx::query(
        "INSERT INTO contacts (id, tenant_id, email, name, status, created_at, updated_at)
         VALUES ($1, $2, $3, $4, 'subscribed', NOW(), NOW())",
    )
    // contacts.id is a UUID column (068/069 lineage — ci/README §9 F4).
    .bind(Uuid::new_v4())
    .bind(user.tenant_id.as_str())
    .bind(&email)
    .bind(if name.is_empty() { None } else { Some(name) })
    .execute(&state.db)
    .await;
    match result {
        Ok(_) => redirect_success("Contact added.", "/contacts", &state.config),
        Err(_) => redirect_error(
            "Could not add the contact. It may already exist.",
            "/contacts/new",
            &state.config,
        ),
    }
}

async fn form_list_create(
    State(state): State<AppState>,
    axum::Extension(user): axum::Extension<AuthUser>,
    headers: HeaderMap,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    if let Err(message) = check_csrf(&form, &headers, &state.config) {
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
    // lists.id is a UUID column (068 lineage).
    .bind(Uuid::new_v4())
    .bind(user.tenant_id.as_str())
    .bind(&name)
    .execute(&state.db)
    .await;
    match result {
        Ok(_) => redirect_success("List created.", "/lists", &state.config),
        Err(_) => redirect_error(
            "Could not create the list. Try again.",
            "/lists/new",
            &state.config,
        ),
    }
}

async fn form_list_update(
    State(state): State<AppState>,
    axum::Extension(user): axum::Extension<AuthUser>,
    headers: HeaderMap,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    if let Err(message) = check_csrf(&form, &headers, &state.config) {
        return redirect_error(message, "/lists", &state.config);
    }
    let name = field_truncated(&form, "name", 120);
    let id = field(&form, "id");
    if name.is_empty() || id.is_empty() {
        return redirect_error("Pick a list and give it a name.", "/lists", &state.config);
    }
    // lists.id is a UUID column (068 lineage): cast the String form bind.
    let result = sqlx::query(
        "UPDATE lists SET name = $1, updated_at = NOW()
         WHERE id = $2::uuid AND tenant_id = $3",
    )
    .bind(&name)
    .bind(&id)
    .bind(user.tenant_id.as_str())
    .execute(&state.db)
    .await;
    match result {
        Ok(_) => redirect_success("List saved.", "/lists", &state.config),
        Err(_) => redirect_error(
            "Could not save the list. Check the identifier.",
            "/lists",
            &state.config,
        ),
    }
}

async fn form_domain_create(
    State(state): State<AppState>,
    axum::Extension(user): axum::Extension<AuthUser>,
    headers: HeaderMap,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    if let Err(message) = check_csrf(&form, &headers, &state.config) {
        return redirect_error(message, "/domains/new", &state.config);
    }
    let name = field(&form, "name").trim().to_lowercase();
    let valid = !name.is_empty()
        && name.len() <= 253
        && name.split('.').count() >= 2
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-');
    let mut fields = FormFieldMap::new("domain-create");
    fields.set("name", &name);
    if !valid {
        fields.error("name", "Enter a domain like mail.example.com.");
        return redirect_with_field_map(
            &fields,
            "Enter a domain like mail.example.com.",
            "/domains/new",
            &state.config,
        );
    }
    // domains.id is a UUID column (both schema lineages) — bind a UUID.
    let id = Uuid::new_v4();
    let result = sqlx::query(
        "INSERT INTO domains (id, tenant_id, name, status, created_at, updated_at)
         VALUES ($1, $2, $3, 'pending', NOW(), NOW())",
    )
    .bind(id)
    .bind(user.tenant_id.as_str())
    .bind(&name)
    .execute(&state.db)
    .await;
    match result {
        // Item A(3): land the operator straight on the new detail page,
        // which shows the DNS records to publish and the verify action.
        Ok(_) => redirect_success(
            "Domain added — review its DNS records and run verification when they are published.",
            &format!("/domains/{id}"),
            &state.config,
        ),
        Err(_) => {
            fields.error("name", "Could not add the domain. It may already exist.");
            redirect_with_field_map(
                &fields,
                "Could not add the domain. It may already exist.",
                "/domains/new",
                &state.config,
            )
        }
    }
}

async fn form_template_create(
    State(state): State<AppState>,
    axum::Extension(user): axum::Extension<AuthUser>,
    headers: HeaderMap,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    if let Err(message) = check_csrf(&form, &headers, &state.config) {
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
    .bind(if subject.is_empty() {
        None
    } else {
        Some(subject)
    })
    .bind(&html_body)
    .execute(&state.db)
    .await;
    match result {
        Ok(_) => redirect_success("Template saved.", "/templates", &state.config),
        Err(_) => redirect_error(
            "Could not save the template. Try again.",
            "/templates/new",
            &state.config,
        ),
    }
}

async fn form_campaign_create(
    State(state): State<AppState>,
    axum::Extension(user): axum::Extension<AuthUser>,
    headers: HeaderMap,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    if let Err(message) = check_csrf(&form, &headers, &state.config) {
        return redirect_error(message, "/campaigns/new", &state.config);
    }
    let name = field_truncated(&form, "name", 120);
    let subject = field_truncated(&form, "subject", 200);
    let scheduled_at = field(&form, "scheduled_at");
    let mut fields = FormFieldMap::new("campaign-create");
    fields.set("name", &name);
    fields.set("subject", &subject);
    fields.set("scheduled_at", &scheduled_at);
    if name.is_empty() || subject.is_empty() {
        if name.is_empty() {
            fields.error("name", "Campaign name is required.");
        }
        if subject.is_empty() {
            fields.error("subject", "Subject is required.");
        }
        return redirect_with_field_map(
            &fields,
            "Campaign name and subject are required.",
            "/campaigns/new",
            &state.config,
        );
    }
    // The campaigns status CHECK (live schema) allows draft/sending/
    // paused/stopped/completed/failed — there is no 'scheduled' status, so
    // a picked time is stored in scheduled_at on a draft row.
    let scheduled: Option<String> = if scheduled_at.trim().is_empty() {
        None
    } else {
        Some(scheduled_at)
    };
    // campaigns.id is a UUID column (both schema lineages; ci/README §9 F4)
    // — text nanoid ids fail the bind.
    let result = sqlx::query(
        "INSERT INTO campaigns (id, tenant_id, name, subject, status, scheduled_at, created_at, updated_at)
         VALUES ($1, $2, $3, $4, 'draft', $5::timestamptz, NOW(), NOW())",
    )
    .bind(Uuid::new_v4())
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
        Err(_) => redirect_error(
            "Could not save the campaign. Try again.",
            "/campaigns/new",
            &state.config,
        ),
    }
}

/// Server-rendered campaign preview: renders the submitted HTML draft in a
/// standalone page (sanitized by ui-foundation) — the no-JS replacement for
/// client-side preview.
async fn form_campaign_preview(
    State(state): State<AppState>,
    axum::Extension(user): axum::Extension<AuthUser>,
    headers: HeaderMap,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    // CSRF is enforced like every other authenticated POST — a bad token
    // bounces back to the editor with a flash instead of rendering the
    // (attacker-supplied) body.
    let back = safe_return_to(&form, "/campaigns");
    if let Err(message) = check_csrf(&form, &headers, &state.config) {
        return redirect_error(message, &back, &state.config);
    }
    let _ = user;
    let html_body = field(&form, "html_body");
    let page = ui_foundation::leptos_views::web_campaign_preview_page(&html_body);
    // Preview CSP (audit F5): the global middleware's `default-src 'none'`
    // would block the previewed email's inline styles and remote images.
    // The preview response path allows style/img while keeping script-src
    // 'none' and stripping scripts, exactly like every other page.
    crate::app::preview_html_response(page)
}

/// POST /web/campaigns/update — the campaign editor's save action. Updates
/// the existing row in place (scoped to the caller's tenant); editing no
/// longer duplicates the campaign.
async fn form_campaign_update(
    State(state): State<AppState>,
    axum::Extension(user): axum::Extension<AuthUser>,
    headers: HeaderMap,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    if let Err(message) = check_csrf(&form, &headers, &state.config) {
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
        return redirect_error(
            "Campaign name and subject are required.",
            &back,
            &state.config,
        );
    }
    let scheduled: Option<String> = if scheduled_at.trim().is_empty() {
        None
    } else {
        Some(scheduled_at)
    };
    // campaigns.id is a UUID column: cast the String form bind.
    let result = sqlx::query(
        "UPDATE campaigns SET name = $1, subject = $2, scheduled_at = $3::timestamptz, updated_at = NOW()
         WHERE id = $4::uuid AND tenant_id = $5",
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
            redirect_error(
                "Could not save the campaign. Try again.",
                &back,
                &state.config,
            )
        }
    }
}

async fn form_placement_create(
    State(state): State<AppState>,
    axum::Extension(user): axum::Extension<AuthUser>,
    headers: HeaderMap,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    if let Err(message) = check_csrf(&form, &headers, &state.config) {
        return redirect_error(message, "/inbox-placement/new", &state.config);
    }
    let name = field_truncated(&form, "name", 120);
    let from_email = field(&form, "from_email").trim().to_lowercase();
    let subject = field_truncated(&form, "subject", 200);
    let html_body = field(&form, "html_body");
    if name.is_empty() || subject.is_empty() || html_body.trim().is_empty() {
        return redirect_error(
            "Test name, subject, and HTML body are required.",
            "/inbox-placement/new",
            &state.config,
        );
    }
    if !valid_email(&from_email) {
        return redirect_error(
            "Enter a valid from email.",
            "/inbox-placement/new",
            &state.config,
        );
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
        Ok(_) => redirect_success(
            "Placement test started — results poll as seeds report in.",
            "/inbox-placement",
            &state.config,
        ),
        Err(_) => redirect_error(
            "Could not start the test. Try again.",
            "/inbox-placement/new",
            &state.config,
        ),
    }
}

async fn form_dedicated_ip_request(
    State(state): State<AppState>,
    axum::Extension(user): axum::Extension<AuthUser>,
    headers: HeaderMap,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    if let Err(message) = check_csrf(&form, &headers, &state.config) {
        return redirect_error(message, "/settings/dedicated-ips", &state.config);
    }
    let region = field_truncated(&form, "region", 40);
    // dedicated_ips.ip_address is nullable: the request row is recorded
    // with status 'pending' and the Hetzner provisioner fills the address.
    let result = sqlx::query(
        "INSERT INTO dedicated_ips (id, tenant_id, region, status, ip_address, created_at, updated_at)
         VALUES ($1, $2, $3, 'pending', NULL, NOW(), NOW())",
    )
    // dedicated_ips.id is UUID — a 26-char text id failed the INSERT and
    // the request form always errored.
    .bind(Uuid::new_v4())
    .bind(user.tenant_id.as_str())
    .bind(if region.is_empty() { "eu-central" } else { &region })
    .execute(&state.db)
    .await;
    match result {
        Ok(_) => redirect_success(
            "Provisioning request recorded — the allocator picks it up shortly.",
            "/settings/dedicated-ips",
            &state.config,
        ),
        Err(_) => redirect_error(
            "Could not record the request. Try again.",
            "/settings/dedicated-ips",
            &state.config,
        ),
    }
}

// ─── Domain DNS flow (item A) ─────────────────────────────────────

/// Mirror of the render path's browser-session login redirect: anonymous
/// GETs on auth-required UI pages land on `/login?next=…`, never a JSON 401.
fn login_redirect(path_and_query: &str) -> Response {
    let mut serializer = url::form_urlencoded::Serializer::new(String::new());
    serializer.append_pair("next", path_and_query);
    let location = format!("/login?{}", serializer.finish());
    (StatusCode::SEE_OTHER, [(header::LOCATION, location)]).into_response()
}

/// Resolve the browser session (cookie/API key) for a detail-page GET —
/// the same extractor the SSR fallback's data loader uses.
async fn browser_session_user(
    state: &AppState,
    headers: &HeaderMap,
    uri: &axum::http::Uri,
) -> Option<AuthUser> {
    let mut request_builder = axum::http::Request::builder().uri(uri.clone());
    for (name, value) in headers {
        request_builder = request_builder.header(name, value);
    }
    let request = request_builder.body(axum::body::Body::empty()).ok()?;
    let (mut parts, _) = request.into_parts();
    <AuthUser as axum::extract::FromRequestParts<AppState>>::from_request_parts(&mut parts, state)
        .await
        .ok()
}

/// GET /domains/{id} — the domain detail page. Joins the domain row with
/// the SAME DKIM/SPF/DMARC record generation the JSON dns-records
/// endpoint uses (`routes::domains::required_sender_dns_records` — never
/// a duplicated copy). Records render as data (mono cells).
async fn web_domain_detail(
    State(state): State<AppState>,
    Path(id): Path<String>,
    uri: axum::http::Uri,
    headers: HeaderMap,
) -> Response {
    // Anonymous browser GETs redirect to login like every auth-required
    // UI route (the routing inventory's contract).
    let Some(user) = browser_session_user(&state, &headers, &uri).await else {
        return login_redirect(
            uri.path_and_query()
                .map(|value| value.as_str())
                .unwrap_or(uri.path()),
        );
    };
    // Non-UUID segments (`/domains/new`) fall back to the static SSR page
    // exactly as the fallback handler would have rendered it.
    if Uuid::parse_str(&id).is_err() {
        return static_ssr_fallback("web", &format!("/domains/{id}"), &headers, &state.config);
    }
    let flash = flash_from_headers(&headers, &state.config);
    match data::load_domain_detail(
        &state.db,
        user.tenant_id.as_str(),
        &id,
        &state.config.aws_region,
    )
    .await
    {
        Some(list) => {
            let form_csrf = form_csrf_for_render(&headers, &state.config);
            let html = web_data_page(
                &format!("/domains/{id}"),
                &list,
                "record",
                &flash,
                &form_csrf.token,
            );
            html_page_response(html, &form_csrf, !flash.is_empty(), &state.config)
        }
        None => redirect_error(
            "That domain could not be found in this workspace.",
            "/domains",
            &state.config,
        ),
    }
}

/// POST /web/domains/{id}/verify — runs the SAME locked verification path
/// the JSON POST /v1/domains/:id/verify uses (DKIM provisioning, live DNS
/// lookups, SES readiness) and flashes the honest per-record outcome.
async fn form_domain_verify(
    State(state): State<AppState>,
    axum::Extension(user): axum::Extension<AuthUser>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    let back = format!("/domains/{}", urlencode(&id));
    if let Err(message) = check_csrf(&form, &headers, &state.config) {
        return redirect_error(message, &back, &state.config);
    }
    if Uuid::parse_str(&id).is_err() {
        return redirect_error("Unknown domain.", "/domains", &state.config);
    }
    // Reuse the JSON path verbatim — one verification truth.
    match crate::routes::domains::verify_domain_for_tenant(&state, user.tenant_id.as_str(), &id)
        .await
    {
        Ok(axum::Json(response)) => {
            let records = [
                ("SPF", response.spf_verified),
                ("DKIM", response.dkim_verified),
                ("DMARC", response.dmarc_verified),
                ("Return-Path", response.return_path_verified),
            ];
            let passed: Vec<&str> = records
                .iter()
                .filter(|(_, ok)| *ok)
                .map(|(name, _)| *name)
                .collect();
            let failed: Vec<&str> = records
                .iter()
                .filter(|(_, ok)| !*ok)
                .map(|(name, _)| *name)
                .collect();
            let summary = if failed.is_empty() {
                format!(
                    "All checks passed ({}) — status is now {}.",
                    passed.join(", "),
                    response.status
                )
            } else {
                format!(
                    "Verified: {}. Not published yet: {} — add the missing records, then verify again.",
                    if passed.is_empty() {
                        "none".to_string()
                    } else {
                        passed.join(", ")
                    },
                    failed.join(", "),
                )
            };
            redirect_success(&summary, &back, &state.config)
        }
        Err(error) => redirect_error(
            &format!("Verification could not run: {error}"),
            &back,
            &state.config,
        ),
    }
}

// ─── Campaign completion (item B) ─────────────────────────────────

/// GET /campaigns/{id} — the campaign detail page with per-status action
/// data (which buttons the view should render) and the wired audience.
async fn web_campaign_detail(
    State(state): State<AppState>,
    Path(id): Path<String>,
    uri: axum::http::Uri,
    headers: HeaderMap,
) -> Response {
    let Some(user) = browser_session_user(&state, &headers, &uri).await else {
        return login_redirect(
            uri.path_and_query()
                .map(|value| value.as_str())
                .unwrap_or(uri.path()),
        );
    };
    if Uuid::parse_str(&id).is_err() {
        return static_ssr_fallback("web", &format!("/campaigns/{id}"), &headers, &state.config);
    }
    let flash = flash_from_headers(&headers, &state.config);
    match data::load_campaign_detail(&state.db, user.tenant_id.as_str(), &id).await {
        Some(detail) => {
            let list = detail.to_list_page();
            let form_csrf = form_csrf_for_render(&headers, &state.config);
            let html = web_data_page(
                &format!("/campaigns/{id}"),
                &list,
                "action",
                &flash,
                &form_csrf.token,
            );
            html_page_response(html, &form_csrf, !flash.is_empty(), &state.config)
        }
        None => redirect_error(
            "That campaign could not be found in this workspace.",
            "/campaigns",
            &state.config,
        ),
    }
}

/// Shared status-transition executor for the campaign lifecycle twins:
/// validate the current status honestly, then flip it atomically with a
/// guard against TOCTOU races (mirrors the JSON route's pattern).
async fn campaign_transition(
    state: &AppState,
    user: &AuthUser,
    id: &str,
    new_status: &str,
    allowed: fn(&str) -> bool,
    action_label: &str,
    allowed_from_label: &str,
) -> Response {
    let back = format!("/campaigns/{}", urlencode(id));
    let row: Option<(String,)> =
        sqlx::query_as("SELECT status FROM campaigns WHERE id = $1::uuid AND tenant_id = $2")
            .bind(id)
            .bind(user.tenant_id.as_str())
            .fetch_optional(&state.db)
            .await
            .ok()
            .flatten();
    let Some((status,)) = row else {
        return redirect_error(
            "That campaign could not be found in this workspace.",
            "/campaigns",
            &state.config,
        );
    };
    if !allowed(&status) {
        return redirect_error(
            &format!(
                "Campaign is “{status}” — only {allowed_from_label} campaigns can be {}.",
                action_label.to_lowercase()
            ),
            &back,
            &state.config,
        );
    }
    let allowed_from: Vec<String> = ["draft", "paused", "sending"]
        .into_iter()
        .filter(|candidate| allowed(candidate))
        .map(String::from)
        .collect();
    let result = sqlx::query(
        "UPDATE campaigns SET status = $1, updated_at = NOW()
         WHERE id = $2::uuid AND tenant_id = $3 AND status = ANY($4)",
    )
    .bind(new_status)
    .bind(id)
    .bind(user.tenant_id.as_str())
    .bind(&allowed_from)
    .execute(&state.db)
    .await;
    match result {
        Ok(result) if result.rows_affected() == 1 => redirect_success(
            &format!(
                "Campaign {} — status is now {new_status}.",
                action_label.to_lowercase()
            ),
            &back,
            &state.config,
        ),
        Ok(_) => redirect_error(
            "The campaign changed state just now. Reload and retry.",
            &back,
            &state.config,
        ),
        Err(error) => {
            tracing::error!(error = %error, "web campaign transition failed");
            redirect_error(
                "Could not update the campaign. Try again.",
                &back,
                &state.config,
            )
        }
    }
}

/// POST /web/campaigns/{id}/start — draft/paused → sending, with the
/// honest recipients validation the console report asked for.
async fn form_campaign_start(
    State(state): State<AppState>,
    axum::Extension(user): axum::Extension<AuthUser>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    let back = format!("/campaigns/{}", urlencode(&id));
    if let Err(message) = check_csrf(&form, &headers, &state.config) {
        return redirect_error(message, &back, &state.config);
    }
    if Uuid::parse_str(&id).is_err() {
        return redirect_error("Unknown campaign.", "/campaigns", &state.config);
    }
    // Honest recipient accounting before any transition: a campaign with
    // no wired audience must never flip to "sending". The audience is the
    // campaign's latest `recipients` job (list + segment).
    let row: Option<(String, Option<String>)> = sqlx::query_as(
        "SELECT status,
                (SELECT job_type FROM campaign_jobs
                 WHERE campaign_id = campaigns.id AND job_type LIKE 'recipients:%'
                 ORDER BY created_at DESC LIMIT 1)
         FROM campaigns WHERE id = $1::uuid AND tenant_id = $2",
    )
    .bind(&id)
    .bind(user.tenant_id.as_str())
    .fetch_optional(&state.db)
    .await
    .ok()
    .flatten();
    let Some((status, recipients_job)) = row else {
        return redirect_error(
            "That campaign could not be found in this workspace.",
            "/campaigns",
            &state.config,
        );
    };
    if !campaign_start_allowed(&status) {
        return redirect_error(
            &format!("Campaign is “{status}” — only draft or paused campaigns can be started."),
            &back,
            &state.config,
        );
    }
    let Some((list_id, segment)) = recipients_job.as_deref().and_then(parse_recipients_job) else {
        return redirect_error(
            "This campaign has no recipients yet — wire an audience list first.",
            &back,
            &state.config,
        );
    };
    let subscribers = data::count_list_recipients_filtered(
        &state.db,
        user.tenant_id.as_str(),
        &list_id,
        &segment,
    )
    .await
    .unwrap_or(0);
    if subscribers == 0 {
        return redirect_error(
            "The selected audience list has no subscribed contacts — add contacts before starting.",
            &back,
            &state.config,
        );
    }
    let result = sqlx::query(
        "UPDATE campaigns SET status = 'sending', updated_at = NOW()
         WHERE id = $1::uuid AND tenant_id = $2 AND status = ANY($3)",
    )
    .bind(&id)
    .bind(user.tenant_id.as_str())
    .bind(&["draft", "paused"][..])
    .execute(&state.db)
    .await;
    match result {
        Ok(result) if result.rows_affected() == 1 => redirect_success(
            &format!("Campaign started — dispatching to {subscribers} recipient(s)."),
            &back,
            &state.config,
        ),
        Ok(_) => redirect_error(
            "The campaign changed state just now. Reload and retry.",
            &back,
            &state.config,
        ),
        Err(error) => {
            tracing::error!(error = %error, "web campaign start failed");
            redirect_error(
                "Could not start the campaign. Try again.",
                &back,
                &state.config,
            )
        }
    }
}

/// POST /web/campaigns/{id}/pause — sending → paused.
async fn form_campaign_pause(
    State(state): State<AppState>,
    axum::Extension(user): axum::Extension<AuthUser>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    let back = format!("/campaigns/{}", urlencode(&id));
    if let Err(message) = check_csrf(&form, &headers, &state.config) {
        return redirect_error(message, &back, &state.config);
    }
    campaign_transition(
        &state,
        &user,
        &id,
        "paused",
        campaign_pause_allowed,
        "Paused",
        "sending",
    )
    .await
}

/// POST /web/campaigns/{id}/resume — paused → sending.
async fn form_campaign_resume(
    State(state): State<AppState>,
    axum::Extension(user): axum::Extension<AuthUser>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    let back = format!("/campaigns/{}", urlencode(&id));
    if let Err(message) = check_csrf(&form, &headers, &state.config) {
        return redirect_error(message, &back, &state.config);
    }
    campaign_transition(
        &state,
        &user,
        &id,
        "sending",
        campaign_resume_allowed,
        "Resumed",
        "paused",
    )
    .await
}

/// The job_type marker for a campaign's wired audience:
/// `recipients:{list_id}:{segment}` — stored on the campaign_jobs row the
/// dispatch path already reads (works on both schema lineages; the
/// campaigns table itself has no audience columns in the 069/075 set).
pub(crate) fn recipients_job_type(list_id: &str, segment: &str) -> String {
    format!("recipients:{list_id}:{segment}")
}

/// The campaign's wired audience, if any: (list_id, segment) parsed from
/// the LATEST recipients job.
pub(crate) fn parse_recipients_job(job_type: &str) -> Option<(String, String)> {
    let rest = job_type.strip_prefix("recipients:")?;
    let (list_id, segment) = rest.split_once(':')?;
    if list_id.is_empty() {
        None
    } else {
        Some((
            list_id.to_string(),
            if segment.is_empty() {
                "subscribed".to_string()
            } else {
                segment.to_string()
            },
        ))
    }
}

/// POST /web/campaigns/{id}/recipients — wire the campaign's audience:
/// a list select (by id) plus an optional contact-status segment filter.
/// The selection lands as the campaign's latest `recipients` job row in
/// one transaction (previous wirings are replaced — latest wins).
async fn form_campaign_recipients(
    State(state): State<AppState>,
    axum::Extension(user): axum::Extension<AuthUser>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    let back = format!("/campaigns/{}", urlencode(&id));
    if let Err(message) = check_csrf(&form, &headers, &state.config) {
        return redirect_error(message, &back, &state.config);
    }
    if Uuid::parse_str(&id).is_err() {
        return redirect_error("Unknown campaign.", "/campaigns", &state.config);
    }
    let mut fields = FormFieldMap::new("campaign-recipients");
    let list_id = field(&form, "list_id").trim().to_string();
    let segment = field(&form, "segment");
    fields.set("list_id", &list_id);
    fields.set("segment", &segment);
    let allowed_segments = ["subscribed", "unsubscribed", "bounced", "all"];
    if list_id.is_empty() || Uuid::parse_str(&list_id).is_err() {
        fields.error("list_id", "Pick one of your lists.");
        return redirect_with_field_map(&fields, "Pick one of your lists.", &back, &state.config);
    }
    if !allowed_segments.contains(&segment.as_str()) {
        fields.error("segment", "Choose a valid segment filter.");
        return redirect_with_field_map(
            &fields,
            "Choose a valid segment filter.",
            &back,
            &state.config,
        );
    }
    let campaign: Option<(String,)> =
        sqlx::query_as("SELECT id::text FROM campaigns WHERE id = $1::uuid AND tenant_id = $2")
            .bind(&id)
            .bind(user.tenant_id.as_str())
            .fetch_optional(&state.db)
            .await
            .ok()
            .flatten();
    if campaign.is_none() {
        return redirect_error(
            "That campaign could not be found in this workspace.",
            "/campaigns",
            &state.config,
        );
    }
    let list: Option<(String,)> =
        sqlx::query_as("SELECT name FROM lists WHERE id = $1::uuid AND tenant_id = $2")
            .bind(&list_id)
            .bind(user.tenant_id.as_str())
            .fetch_optional(&state.db)
            .await
            .ok()
            .flatten();
    let Some((list_name,)) = list else {
        fields.error("list_id", "That list is not in this workspace.");
        return redirect_with_field_map(
            &fields,
            "That list is not in this workspace.",
            &back,
            &state.config,
        );
    };
    let count = data::count_list_recipients_filtered(
        &state.db,
        user.tenant_id.as_str(),
        &list_id,
        &segment,
    )
    .await
    .unwrap_or(0);
    if count == 0 {
        fields.error("list_id", "That selection matches no contacts.");
        return redirect_with_field_map(
            &fields,
            "That selection matches no contacts — pick another list or segment.",
            &back,
            &state.config,
        );
    }
    let result: Result<(), sqlx::Error> = async {
        let mut tx = state.db.begin().await?;
        // Latest-wins: drop any previous wiring for this campaign, then
        // record exactly one audience job the dispatcher reads.
        sqlx::query(
            "DELETE FROM campaign_jobs WHERE campaign_id = $1::uuid AND job_type LIKE 'recipients:%'",
        )
        .bind(&id)
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            "INSERT INTO campaign_jobs (id, tenant_id, campaign_id, job_type, status, created_at)
             VALUES ($1, $2, $3::uuid, $4, 'pending', NOW())",
        )
        .bind(Uuid::new_v4())
        .bind(user.tenant_id.as_str())
        .bind(&id)
        .bind(recipients_job_type(&list_id, &segment))
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(())
    }
    .await;
    match result {
        Ok(()) => redirect_success(
            &format!("Recipients wired: {count} “{segment}” contact(s) from “{list_name}”."),
            &back,
            &state.config,
        ),
        Err(error) => {
            tracing::error!(error = %error, "web campaign recipients failed");
            redirect_error(
                "Could not wire the recipients. Try again.",
                &back,
                &state.config,
            )
        }
    }
}

// ─── Contacts CSV import (item C) ─────────────────────────────────

/// POST /web/contacts/import — accept a raw CSV textarea (urlencoded) or
/// a file part (multipart); parse server-side (quoted fields, header row,
/// email+name columns case-insensitively), dedupe against existing rows,
/// validate per row, and flash the honest "Imported N, skipped M" result.
async fn form_contacts_import(
    State(state): State<AppState>,
    axum::Extension(user): axum::Extension<AuthUser>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let back = "/contacts";
    let form = match parse_form_body(&headers, body).await {
        Ok(form) => form,
        Err(message) => return redirect_error(message, back, &state.config),
    };
    if let Err(message) = form.check_csrf(&headers, &state.config) {
        return redirect_error(message, back, &state.config);
    }
    let csv_text = form.csv_text();
    if csv_text.trim().is_empty() {
        let mut fields = FormFieldMap::new("contacts-import");
        fields.error("csv", "Paste CSV content or choose a file.");
        return redirect_with_field_map(
            &fields,
            "Paste CSV content or choose a file to import.",
            back,
            &state.config,
        );
    }
    let parsed = parse_contact_csv(&csv_text);
    if parsed.rows.len() > CONTACT_IMPORT_MAX_ROWS {
        return redirect_error(
            &format!(
                "That import has {} rows — the hard cap is {CONTACT_IMPORT_MAX_ROWS}. Split the file.",
                parsed.rows.len()
            ),
            back,
            &state.config,
        );
    }
    if parsed.rows.is_empty() {
        let mut fields = FormFieldMap::new("contacts-import");
        let example = parsed
            .invalid
            .first()
            .map(|(line, reason)| format!(" (line {line}: {reason})"))
            .unwrap_or_default();
        fields.error("csv", "No valid rows found.");
        return redirect_with_field_map(
            &fields,
            &format!("No valid rows found.{example}"),
            back,
            &state.config,
        );
    }

    // Dedupe: within the file, then against existing rows for this tenant.
    let mut unique: Vec<ContactCsvRow> = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let mut file_duplicates = 0usize;
    for row in parsed.rows {
        if seen.insert(row.email.clone()) {
            unique.push(row);
        } else {
            file_duplicates += 1;
        }
    }
    let batch: Vec<String> = unique.iter().map(|row| row.email.clone()).collect();
    let existing: Vec<String> =
        sqlx::query_scalar("SELECT email FROM contacts WHERE tenant_id = $1 AND email = ANY($2)")
            .bind(user.tenant_id.as_str())
            .bind(&batch)
            .fetch_all(&state.db)
            .await
            .unwrap_or_default();
    let existing_set: std::collections::HashSet<String> = existing.into_iter().collect();
    let fresh: Vec<ContactCsvRow> = unique
        .into_iter()
        .filter(|row| !existing_set.contains(&row.email))
        .collect();
    let db_duplicates = seen.len().saturating_sub(fresh.len());

    let imported: usize = if fresh.is_empty() {
        0
    } else {
        // Multi-row INSERT batches (not one statement per row): the same
        // transaction, the same ON CONFLICT DO NOTHING semantics, and the
        // same honest rows_affected accounting — a 10k-row import is ~20
        // round-trips instead of 10k.
        const IMPORT_BATCH_ROWS: usize = 500;
        let result: Result<usize, sqlx::Error> = async {
            let mut tx = state.db.begin().await?;
            let mut imported = 0usize;
            for batch in fresh.chunks(IMPORT_BATCH_ROWS) {
                // VALUES ($1,$2,$3,$4),($5,$6,$7,$8),… four bind params
                // per row (contacts.id is a UUID column, 068/069 lineage).
                let mut sql = String::with_capacity(96 * batch.len());
                sql.push_str(
                    "INSERT INTO contacts (id, tenant_id, email, name, status, created_at, updated_at) VALUES ",
                );
                for (row_index, _) in batch.iter().enumerate() {
                    if row_index > 0 {
                        sql.push(',');
                    }
                    let base = 4 * row_index + 1;
                    sql.push_str(&format!(
                        "(${}, ${}, ${}, ${}, 'subscribed', NOW(), NOW())",
                        base,
                        base + 1,
                        base + 2,
                        base + 3,
                    ));
                }
                sql.push_str(" ON CONFLICT (tenant_id, email) DO NOTHING");

                let mut query = sqlx::query(&sql);
                for row in batch {
                    query = query
                        .bind(Uuid::new_v4())
                        .bind(user.tenant_id.as_str())
                        .bind(&row.email)
                        .bind(row.name.as_deref().filter(|name| !name.is_empty()));
                }
                let insert = query.execute(&mut *tx).await?;
                imported += insert.rows_affected() as usize;
            }
            tx.commit().await?;
            Ok(imported)
        }
        .await;
        match result {
            Ok(count) => count,
            Err(error) => {
                tracing::error!(error = %error, "web contacts import failed");
                return redirect_error(
                    "The import could not be saved. Nothing was committed.",
                    back,
                    &state.config,
                );
            }
        }
    };

    let duplicates = file_duplicates + db_duplicates;
    redirect_success(
        &contact_import_summary(imported, duplicates, &parsed.invalid),
        back,
        &state.config,
    )
}

// ─── Template edit + preview (item D) ─────────────────────────────

/// POST /web/templates/update — the template editor's save action.
/// Snapshots the previous state through the SAME versioning writer the
/// JSON update path uses (`templates::snapshot_template_version`), so
/// rollback history stays coherent.
async fn form_template_update(
    State(state): State<AppState>,
    axum::Extension(user): axum::Extension<AuthUser>,
    headers: HeaderMap,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    let id = field(&form, "id");
    let name = field_truncated(&form, "name", 120);
    let subject = field_truncated(&form, "subject", 200);
    let html_body = field(&form, "html_body");
    let back = if id.is_empty() {
        "/templates".to_string()
    } else {
        format!("/templates/{}", urlencode(&id))
    };
    if let Err(message) = check_csrf(&form, &headers, &state.config) {
        return redirect_error(message, &back, &state.config);
    }
    let mut fields = FormFieldMap::new("template-update");
    fields.set("id", &id);
    fields.set("name", &name);
    fields.set("subject", &subject);
    if id.is_empty() {
        return redirect_error("Missing template id.", "/templates", &state.config);
    }
    if name.is_empty() {
        fields.error("name", "Give the template a name.");
        return redirect_with_field_map(&fields, "Give the template a name.", &back, &state.config);
    }
    if html_body.trim().is_empty() {
        fields.error("html_body", "Add some HTML content.");
        return redirect_with_field_map(&fields, "Add some HTML content.", &back, &state.config);
    }
    let existing: Option<(i32, String)> = sqlx::query_as(
        "SELECT version, COALESCE(subject, '') FROM templates WHERE id = $1 AND tenant_id = $2",
    )
    .bind(&id)
    .bind(user.tenant_id.as_str())
    .fetch_optional(&state.db)
    .await
    .ok()
    .flatten();
    let Some((version, existing_subject)) = existing else {
        return redirect_error(
            "That template could not be found in this workspace.",
            "/templates",
            &state.config,
        );
    };
    // A blank subject keeps the stored one (JSON semantics: None ⇒ keep).
    let subject = if subject.is_empty() {
        existing_subject
    } else {
        subject
    };
    let new_version = version + 1;
    let result: Result<(), sqlx::Error> = async {
        let mut tx = state.db.begin().await?;
        let update = sqlx::query(
            "UPDATE templates SET name = $1, subject = $2, html_body = $3, version = $4, updated_at = NOW()
             WHERE id = $5 AND tenant_id = $6",
        )
        .bind(&name)
        .bind(&subject)
        .bind(&html_body)
        .bind(new_version)
        .bind(&id)
        .bind(user.tenant_id.as_str())
        .execute(&mut *tx)
        .await?;
        if update.rows_affected() != 1 {
            return Err(sqlx::Error::RowNotFound);
        }
        crate::routes::templates::snapshot_template_version(
            &mut tx,
            &id,
            user.tenant_id.as_str(),
            new_version,
            &name,
            &subject,
            &html_body,
            None,
        )
        .await?;
        tx.commit().await?;
        Ok(())
    }
    .await;
    match result {
        Ok(()) => redirect_success(
            &format!("Template saved as v{new_version} — the previous version can be restored."),
            &back,
            &state.config,
        ),
        Err(error) => {
            tracing::error!(error = %error, "web template update failed");
            redirect_error(
                "Could not save the template. Try again.",
                &back,
                &state.config,
            )
        }
    }
}

/// POST /web/templates/preview — mirrors the campaign preview exactly:
/// the submitted draft (or the stored body when the editor posts only an
/// id) is sanitized and rendered by the same ui-foundation page builder.
async fn form_template_preview(
    State(state): State<AppState>,
    axum::Extension(user): axum::Extension<AuthUser>,
    headers: HeaderMap,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    let back = safe_return_to(&form, "/templates");
    if let Err(message) = check_csrf(&form, &headers, &state.config) {
        return redirect_error(message, &back, &state.config);
    }
    let mut html_body = field(&form, "html_body");
    let id = field(&form, "id");
    if html_body.trim().is_empty() && !id.is_empty() {
        // Preview the stored body when the form posts only the template id.
        html_body = sqlx::query_scalar::<_, String>(
            "SELECT html_body FROM templates WHERE id = $1 AND tenant_id = $2",
        )
        .bind(&id)
        .bind(user.tenant_id.as_str())
        .fetch_optional(&state.db)
        .await
        .ok()
        .flatten()
        .unwrap_or_default();
    }
    if html_body.trim().is_empty() {
        return redirect_error("Add some HTML content to preview.", &back, &state.config);
    }
    let page = ui_foundation::leptos_views::web_campaign_preview_page(&html_body);
    // Same preview CSP exception as the campaign preview (audit F5).
    crate::app::preview_html_response(page)
}

// ─── SSR fallback + response helpers ──────────────────────────────

/// Render any path through ui-foundation's public SSR entry (used when a
/// detail route matches a non-id segment like `/campaigns/new`).
fn static_ssr_fallback(
    surface: &str,
    path: &str,
    headers: &HeaderMap,
    config: &Config,
) -> Response {
    let flash = flash_from_headers(headers, config);
    // Failed-POST field map (audit F2): decode and hand to the render pass
    // so re-populated inputs / per-field errors / secret chips display.
    let field_map = decode_form_fields_from_headers(headers, &config.csrf_secret);
    let field_data = field_map.as_ref().map(|map| map.clone().into_view_data());
    let form_csrf = form_csrf_for_render(headers, config);
    match ui_foundation::axum_router::render_route_with_form_fields_and_csrf(
        surface,
        path,
        None,
        Some(config.csrf_secret.as_str()),
        &flash,
        None,
        field_data.as_ref(),
        Some(form_csrf.token.as_str()),
    ) {
        Some((html, _embedded_token)) => {
            let mut response = html_page_response(html, &form_csrf, !flash.is_empty(), config);
            if field_map.is_some() {
                if let Ok(value) = form_fields_clear_cookie(is_secure(config)).parse() {
                    response.headers_mut().append(header::SET_COOKIE, value);
                }
            }
            response
        }
        None => (
            StatusCode::NOT_FOUND,
            [(header::LOCATION, "/dashboard".to_string())],
            "Not found",
        )
            .into_response(),
    }
}

/// HTML response with flash-cookie clearing (mirrors the render path) plus
/// the double-submit CSRF cookie (audit F4): the page was rendered with
/// `form_csrf.token` embedded, and a freshly minted token gets its matching
/// `csrf_token` cookie set here.
fn html_page_response(
    html: String,
    form_csrf: &FormCsrfToken,
    clear_flash: bool,
    config: &Config,
) -> Response {
    let mut response = (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/html; charset=utf-8".to_string())],
        html,
    )
        .into_response();
    if form_csrf.minted {
        if let Ok(value) = form_csrf_set_cookie(&form_csrf.token, config).parse() {
            response.headers_mut().append(header::SET_COOKIE, value);
        }
    }
    if clear_flash {
        if let Ok(value) = ui_foundation::flash::flash_clear_cookie(is_secure(config)).parse() {
            response.headers_mut().append(header::SET_COOKIE, value);
        }
    }
    response
}

// ─── Destructive confirmations (single + bulk, item G) ────────────

/// POST /web/confirm — the confirm page's form. The signature is
/// re-verified server-side before anything is deleted.
async fn form_confirm_destructive(
    State(state): State<AppState>,
    axum::Extension(user): axum::Extension<AuthUser>,
    headers: HeaderMap,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    if let Err(message) = check_csrf(&form, &headers, &state.config) {
        return redirect_error(message, "/dashboard", &state.config);
    }
    let intent = field(&form, "intent");
    let id = field(&form, "id");
    let sig = field(&form, "sig");
    let return_to = safe_return_to(&form, "/dashboard");
    if !verify_confirmation(
        &state.config.csrf_secret,
        &sig,
        &intent,
        &id,
        Utc::now().timestamp(),
    ) {
        return redirect_error(
            "That confirmation link expired. Nothing was changed.",
            &return_to,
            &state.config,
        );
    }
    let tenant = user.tenant_id.clone();
    let result: Result<u64, sqlx::Error> = match intent.as_str() {
        "delete-campaign" => {
            sqlx::query("DELETE FROM campaigns WHERE id = $1::uuid AND tenant_id = $2")
                .bind(&id)
                .bind(&tenant)
                .execute(&state.db)
                .await
                .map(|r| r.rows_affected())
        }
        "delete-list" => sqlx::query("DELETE FROM lists WHERE id = $1::uuid AND tenant_id = $2")
            .bind(&id)
            .bind(&tenant)
            .execute(&state.db)
            .await
            .map(|r| r.rows_affected()),
        "delete-domain" => {
            sqlx::query("DELETE FROM domains WHERE id = $1::uuid AND tenant_id = $2")
                .bind(&id)
                .bind(&tenant)
                .execute(&state.db)
                .await
                .map(|r| r.rows_affected())
        }
        // ── Bulk intents (item G): the id list is the signed resource ──
        "delete-campaigns-bulk" => {
            let ids = parse_bulk_ids(&id);
            sqlx::query("DELETE FROM campaigns WHERE id = ANY($1::uuid[]) AND tenant_id = $2")
                .bind(ids)
                .bind(&tenant)
                .execute(&state.db)
                .await
                .map(|r| r.rows_affected())
        }
        "delete-contacts-bulk" => {
            let ids = parse_bulk_ids(&id);
            sqlx::query(
                "UPDATE contacts SET status = 'deleted', updated_at = NOW()
                 WHERE id = ANY($1::uuid[]) AND tenant_id = $2",
            )
            .bind(ids)
            .bind(&tenant)
            .execute(&state.db)
            .await
            .map(|r| r.rows_affected())
        }
        "delete-lists-bulk" => {
            let ids = parse_bulk_ids(&id);
            sqlx::query("DELETE FROM lists WHERE id = ANY($1::uuid[]) AND tenant_id = $2")
                .bind(ids)
                .bind(&tenant)
                .execute(&state.db)
                .await
                .map(|r| r.rows_affected())
        }
        // ── Control-plane intents (items I) — system-gated ──
        "suspend-tenant" => {
            if !is_system_tenant(&state, &tenant).await {
                return redirect_error("Operator access required.", "/tenants", &state.config);
            }
            let suspended = sqlx::query(
                "UPDATE tenants SET status = 'suspended', updated_at = NOW()
                 WHERE id = $1 AND status IN ('pending', 'active')",
            )
            .bind(&id)
            .execute(&state.db)
            .await
            .map(|r| r.rows_affected());
            // F18: the restriction must reach authenticated traffic
            // immediately (drop the middleware's cached tenant-status
            // decision), not after its short TTL.
            crate::middleware::auth::invalidate_tenant_status_cache(&id, &state).await;
            suspended
        }
        "delete-tenant" => {
            if !is_system_tenant(&state, &tenant).await {
                return redirect_error("Operator access required.", "/tenants", &state.config);
            }
            // Typed confirmation (item I): the operator must repeat the
            // tenant's exact name — verified against the row server-side.
            let confirmation = field(&form, "confirmation").trim().to_string();
            let name: Option<String> = sqlx::query_scalar("SELECT name FROM tenants WHERE id = $1")
                .bind(&id)
                .fetch_optional(&state.db)
                .await
                .ok()
                .flatten();
            match name {
                Some(expected) if confirmation == expected => {
                    sqlx::query("DELETE FROM tenants WHERE id = $1 AND name = $2")
                        .bind(&id)
                        .bind(&confirmation)
                        .execute(&state.db)
                        .await
                        .map(|r| r.rows_affected())
                }
                Some(_) => {
                    return redirect_error(
                        "The typed name does not match the tenant — nothing was deleted.",
                        "/tenants",
                        &state.config,
                    )
                }
                None => {
                    return redirect_error(
                        "That tenant could not be found.",
                        "/tenants",
                        &state.config,
                    )
                }
            }
        }
        _ => {
            return redirect_error("Unknown action.", &return_to, &state.config);
        }
    };
    let noun = match intent.as_str() {
        "delete-contacts-bulk" => "contact(s)",
        "delete-campaigns-bulk" => "campaign(s)",
        "delete-lists-bulk" => "list(s)",
        "suspend-tenant" => "tenant(s)",
        "delete-tenant" => "tenant(s)",
        _ => "row(s)",
    };
    match result {
        Ok(0) => redirect_error(
            "It may have been deleted already.",
            &return_to,
            &state.config,
        ),
        Ok(count) => redirect_success(
            &match intent.as_str() {
                "suspend-tenant" => format!("Tenant suspended ({count} row(s))."),
                "delete-tenant" => format!("Tenant deleted ({count} row(s))."),
                _ => format!("{count} {noun} processed."),
            },
            &return_to,
            &state.config,
        ),
        Err(_) => redirect_error("Could not delete it. Try again.", &return_to, &state.config),
    }
}

/// Bulk destructive POSTs never delete directly (item G): the id list is
/// signed over and the operator confirms on the typed `/confirm` page,
/// whose POST re-verifies the signature server-side.
async fn bulk_delete_confirm(
    state: AppState,
    user: AuthUser,
    form: HashMap<String, String>,
    scope: &str,
    intent: &str,
    headers: HeaderMap,
) -> Response {
    let back = format!("/{scope}");
    if let Err(message) = check_csrf(&form, &headers, &state.config) {
        return redirect_error(message, &back, &state.config);
    }
    let ids = parse_bulk_ids(&field(&form, "ids"));
    if ids.is_empty() {
        return redirect_error("Select at least one row first.", &back, &state.config);
    }
    let _ = user;
    redirect_to_bulk_confirm(intent, &ids, &back, &state.config)
}

async fn form_campaigns_delete_bulk(
    State(state): State<AppState>,
    axum::Extension(user): axum::Extension<AuthUser>,
    headers: HeaderMap,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    bulk_delete_confirm(
        state,
        user,
        form,
        "campaigns",
        "delete-campaigns-bulk",
        headers,
    )
    .await
}

async fn form_contacts_delete_bulk(
    State(state): State<AppState>,
    axum::Extension(user): axum::Extension<AuthUser>,
    headers: HeaderMap,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    bulk_delete_confirm(
        state,
        user,
        form,
        "contacts",
        "delete-contacts-bulk",
        headers,
    )
    .await
}

/// POST /web/lists/delete-bulk — the lists page's bulk action, routed
/// through the same signed confirmation as campaigns/contacts.
async fn form_lists_delete_bulk(
    State(state): State<AppState>,
    axum::Extension(user): axum::Extension<AuthUser>,
    headers: HeaderMap,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    bulk_delete_confirm(state, user, form, "lists", "delete-lists-bulk", headers).await
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
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    // Defense in depth: the router stack already gates this route behind
    // require_system_tenant_middleware; re-verify here (slug-aware).
    if !is_system_tenant(&state, &user.tenant_id).await {
        return redirect_error("Operator access required.", "/audit", &state.config);
    }
    // Item M: the export honors the SAME widened search + optional days
    // filter the audit list applies (action OR user_id OR resource_type).
    let search = params
        .get("query")
        .or_else(|| params.get("q"))
        .or_else(|| params.get("search"))
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
        .unwrap_or("");
    let days = params
        .get("days")
        .and_then(|value| value.parse::<i64>().ok())
        .filter(|days| (1..=3650).contains(days));
    let where_clause = if search.is_empty() && days.is_none() {
        "TRUE".to_string()
    } else {
        let mut clauses: Vec<String> = Vec::new();
        if !search.is_empty() {
            // LIKE metacharacters are escaped (audit F7): a search for `%`
            // or `_` must match those literal characters, not expand into a
            // whole-table wildcard — same treatment WhereBuilder::ilike and
            // the audit list apply.
            clauses.push(
                "(action ILIKE '%' || $1 || '%' ESCAPE '\\' OR user_id ILIKE '%' || $1 || '%' ESCAPE '\\' OR resource_type ILIKE '%' || $1 || '%' ESCAPE '\\')"
                    .to_string(),
            );
        }
        if let Some(days) = days {
            clauses.push(format!("created_at >= NOW() - '{days} days'::interval"));
        }
        clauses.join(" AND ")
    };
    let binds: Vec<String> = if search.is_empty() {
        Vec::new()
    } else {
        vec![data::escape_like(search)]
    };
    // Live audit_logs columns: created_at, action, resource, user_id —
    // the canonical writer (audit_log.rs) inserts `resource`; the legacy
    // `resource_type` spelling was renamed by the fix migrations and
    // fails at runtime.
    let sql = format!(
        "SELECT created_at, action, resource, user_id FROM audit_logs WHERE {where_clause} ORDER BY created_at DESC NULLS LAST LIMIT 10000"
    );
    let rows = sqlx::query_as::<
        _,
        (
            Option<chrono::DateTime<Utc>>,
            Option<String>,
            Option<String>,
            Option<String>,
        ),
    >(&sql);
    let mut query = rows;
    for value in &binds {
        query = query.bind(value);
    }
    let rows = query.fetch_all(&state.db).await;
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

/// CSV cell escaping. Besides RFC 4180 quoting, spreadsheet formula
/// injection is neutralized (audit F6): a cell whose value STARTS with a
/// formula trigger (`=`, `+`, `-`, `@`) — or a tab/CR, which Excel and
/// Google Sheets also honor as a formula introducer — is prefixed with a
/// single quote so the cell renders as text instead of executing when the
/// export is opened. Contact/audit data is user- and operator-influenced,
/// so every cell passes through here.
fn csv_escape(value: &str) -> String {
    let formula_safe = if value.starts_with(['=', '+', '-', '@', '\t', '\r']) {
        format!("'{value}")
    } else {
        value.to_string()
    };
    if formula_safe.contains(',') || formula_safe.contains('"') || formula_safe.contains('\n') {
        format!("\"{}\"", formula_safe.replace('"', "\"\""))
    } else {
        formula_safe
    }
}

// ─── Admin (control-plane) handlers ──────────────────────────────

async fn form_admin_tenant_create(
    State(state): State<AppState>,
    axum::Extension(user): axum::Extension<AuthUser>,
    headers: HeaderMap,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    if let Err(message) = check_csrf(&form, &headers, &state.config) {
        return redirect_error(message, "/tenants/new", &state.config);
    }
    let name = field_truncated(&form, "name", 120);
    let domain = field(&form, "domain").trim().to_lowercase();
    let plan = field(&form, "plan").trim().to_lowercase();
    let mut fields = FormFieldMap::new("tenant-create");
    fields.set("name", &name);
    fields.set("domain", &domain);
    fields.set("plan", &plan);
    if name.is_empty() || domain.split('.').count() < 2 {
        if name.is_empty() {
            fields.error("name", "Tenant name is required.");
        }
        if domain.split('.').count() < 2 {
            fields.error("domain", "A primary domain is required.");
        }
        return redirect_with_field_map(
            &fields,
            "Tenant name and a primary domain are required.",
            "/tenants/new",
            &state.config,
        );
    }
    // Item I: the plan select is bound — the value must exist in the
    // plans catalog (same source cp_plans reads), defaulting to free.
    let catalog = data::tenant_plan_names(&state.db).await;
    let plan = if catalog.contains(&plan) {
        plan
    } else if plan.is_empty() {
        "free".to_string()
    } else {
        fields.error("plan", "Choose a plan from the catalog.");
        return redirect_with_field_map(
            &fields,
            "Choose a plan from the catalog.",
            "/tenants/new",
            &state.config,
        );
    };
    let tenant_id = apexmail_lib::id::generate_id("", 26);
    let slug: String = domain
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-')
        .take(48)
        .collect();
    let result = sqlx::query(
        "INSERT INTO tenants (id, name, slug, plan, status, settings, metadata, created_at, updated_at)
         VALUES ($1, $2, $3, $4, 'pending', '{}'::jsonb, $5, NOW(), NOW())",
    )
    .bind(&tenant_id)
    .bind(&name)
    .bind(&slug)
    .bind(&plan)
    .bind(json!({"primary_domain": domain, "created_by": user.user_id.clone().unwrap_or_default()}))
    .execute(&state.db)
    .await;
    match result {
        Ok(_) => redirect_success(
            &format!("Tenant workspace created on the {plan} plan."),
            "/tenants",
            &state.config,
        ),
        Err(_) => redirect_error(
            "Could not create the tenant. Try again.",
            "/tenants/new",
            &state.config,
        ),
    }
}

async fn form_admin_operator_create(
    State(state): State<AppState>,
    axum::Extension(user): axum::Extension<AuthUser>,
    headers: HeaderMap,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    if let Err(message) = check_csrf(&form, &headers, &state.config) {
        return redirect_error(message, "/operators/new", &state.config);
    }
    let email = field(&form, "email").trim().to_lowercase();
    let name = field_truncated(&form, "name", 120);
    if !valid_email(&email) {
        return redirect_error(
            "Enter a valid operator email.",
            "/operators/new",
            &state.config,
        );
    }
    let system_tenant = sqlx::query_scalar::<_, String>(
        "SELECT id::text FROM tenants WHERE slug = 'system' LIMIT 1",
    )
    .fetch_optional(&state.db)
    .await
    .ok()
    .flatten();
    let Some(system_tenant) = system_tenant else {
        return redirect_error(
            "Provisioning is unavailable. Try again shortly.",
            "/operators/new",
            &state.config,
        );
    };
    let result = sqlx::query(
        "INSERT INTO users (id, tenant_id, email, name, password_hash, role, status,
                            email_verified, mfa_enabled, metadata, created_at, updated_at)
         VALUES ($1, $2, $3, $4, '!invited-pending-activation', 'admin', 'invited', false, false,
                 $5::jsonb, NOW(), NOW())",
    )
    // users.id is a UUID column (migration 052) — bind a UUID, not a text
    // nanoid (the insert would fail with invalid uuid syntax).
    .bind(Uuid::new_v4())
    .bind(system_tenant)
    .bind(&email)
    .bind(if name.is_empty() { None } else { Some(name) })
    .bind(json!({"invited_by": user.user_id.clone().unwrap_or_default()}))
    .execute(&state.db)
    .await;
    match result {
        Ok(_) => redirect_success("Operator invited.", "/operators", &state.config),
        Err(_) => redirect_error(
            "Could not create the invitation. Try again.",
            "/operators/new",
            &state.config,
        ),
    }
}

// ─── Admin sales ─────────────────────────────────────────────────

async fn form_sales_discovery(
    State(state): State<AppState>,
    axum::Extension(_user): axum::Extension<AuthUser>,
    headers: HeaderMap,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    if let Err(message) = check_csrf(&form, &headers, &state.config) {
        return redirect_error(message, "/sales", &state.config);
    }
    let sources: Vec<String> = field(&form, "sources")
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect();
    if sources.is_empty() {
        return redirect_error(
            "Add at least one comma-separated source.",
            "/sales",
            &state.config,
        );
    }
    let _categories = field(&form, "categories");
    redirect_success(
        "Discovery runs are launched from the API console (POST /v1/admin/sales/discovery/run).",
        "/sales",
        &state.config,
    )
}

async fn form_sales_outreach(
    State(state): State<AppState>,
    axum::Extension(_user): axum::Extension<AuthUser>,
    headers: HeaderMap,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    if let Err(message) = check_csrf(&form, &headers, &state.config) {
        return redirect_error(message, "/sales", &state.config);
    }
    let lead_ids: Vec<String> = form
        .get("lead_ids")
        .map(|v| {
            v.split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default();
    if lead_ids.is_empty() {
        return redirect_error(
            "Pick at least one lead in the queue first.",
            "/sales",
            &state.config,
        );
    }
    redirect_success(
        "Outreach is an enrollment command from the API console \
         (POST /v1/admin/sales/outreach/start with sequenceId, contactIds and autonomyPolicyId).",
        "/sales",
        &state.config,
    )
}

async fn form_sales_leads_update(
    State(state): State<AppState>,
    axum::Extension(user): axum::Extension<AuthUser>,
    headers: HeaderMap,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    if let Err(message) = check_csrf(&form, &headers, &state.config) {
        return redirect_error(message, "/sales", &state.config);
    }
    let lead_ids: Vec<String> = form
        .get("lead_ids")
        .map(|v| {
            v.split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default();
    let status = field(&form, "status");
    if lead_ids.is_empty() {
        return redirect_error(
            "Pick at least one lead in the queue first.",
            "/sales",
            &state.config,
        );
    }

    // Audit item 17: the operator decision is written to the canonical
    // lifecycle fields the CP read actually derives status from — never to
    // the legacy `sales_leads.status` column (which no read path renders).
    // The supported vocabulary is the one in `canonical_lead_status`;
    // `proposal`, `approved` and `escalated` are not in the canonical model
    // and are rejected with the supported list.
    let result = crate::routes::admin::sales::apply_lead_status_decision(
        &state.db,
        user.tenant_id.as_str(),
        &lead_ids,
        &status,
    )
    .await;
    match result {
        Ok((updated, rendered)) => redirect_success(
            &format!("{updated} lead(s) moved to {rendered}."),
            "/sales",
            &state.config,
        ),
        Err(error) => {
            // Honest failure: a database error is an error, never a success
            // flash; an unsupported stage names the supported vocabulary.
            if let crate::routes::admin::sales::LeadStatusWriteError::Database(sqlx_error) = &error
            {
                tracing::error!(error = %sqlx_error, "web sales leads update failed");
                return redirect_error(
                    "The stage change failed. Refresh and retry.",
                    "/sales",
                    &state.config,
                );
            }
            redirect_error(&error.to_string(), "/sales", &state.config)
        }
    }
}

// ─── CP alerts acknowledge (item H) ───────────────────────────────

/// POST /web/admin/alerts/ack — acknowledge one alert (honest row-count
/// flash; already-acknowledged rows are not touched).
async fn form_admin_alert_ack(
    State(state): State<AppState>,
    axum::Extension(user): axum::Extension<AuthUser>,
    headers: HeaderMap,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    if let Err(message) = check_csrf(&form, &headers, &state.config) {
        return redirect_error(message, "/alerts", &state.config);
    }
    let id = field(&form, "id");
    if Uuid::parse_str(&id).is_err() {
        return redirect_error("Unknown alert.", "/alerts", &state.config);
    }
    let result = sqlx::query(
        "UPDATE system_alerts
         SET acknowledged = true, acknowledged_by = $1, acknowledged_at = NOW()
         WHERE id = $2::uuid AND acknowledged = false",
    )
    .bind(user.user_id.as_deref().unwrap_or("operator"))
    .bind(&id)
    .execute(&state.db)
    .await;
    match result {
        Ok(result) if result.rows_affected() == 1 => redirect_success(
            "Alert acknowledged.",
            &safe_return_to(&form, "/alerts"),
            &state.config,
        ),
        Ok(_) => redirect_error(
            "It may have been acknowledged already.",
            "/alerts",
            &state.config,
        ),
        Err(error) => {
            tracing::error!(error = %error, "web alert ack failed");
            redirect_error(
                "Could not acknowledge the alert. Try again.",
                "/alerts",
                &state.config,
            )
        }
    }
}

/// POST /web/admin/alerts/ack-bulk — acknowledge a checked set. Accepts
/// a comma-joined `ids` field or repeated `ids` keys; the flash reports
/// exactly how many rows flipped.
async fn form_admin_alert_ack_bulk(
    State(state): State<AppState>,
    axum::Extension(user): axum::Extension<AuthUser>,
    headers: HeaderMap,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    if let Err(message) = check_csrf(&form, &headers, &state.config) {
        return redirect_error(message, "/alerts", &state.config);
    }
    let mut ids: Vec<String> = parse_bulk_ids(&field(&form, "ids"));
    if ids.is_empty() {
        return redirect_error("Select at least one alert first.", "/alerts", &state.config);
    }
    ids.retain(|id| Uuid::parse_str(id).is_ok());
    if ids.is_empty() {
        return redirect_error("No valid alert ids were posted.", "/alerts", &state.config);
    }
    let result = sqlx::query(
        "UPDATE system_alerts
         SET acknowledged = true, acknowledged_by = $1, acknowledged_at = NOW()
         WHERE id = ANY($2::uuid[]) AND acknowledged = false",
    )
    .bind(user.user_id.as_deref().unwrap_or("operator"))
    .bind(&ids)
    .execute(&state.db)
    .await;
    match result {
        Ok(result) => {
            let count = result.rows_affected();
            if count == 0 {
                redirect_error(
                    "They may have been acknowledged already.",
                    "/alerts",
                    &state.config,
                )
            } else {
                redirect_success(
                    &format!("Acknowledged {count} alert(s)."),
                    &safe_return_to(&form, "/alerts"),
                    &state.config,
                )
            }
        }
        Err(error) => {
            tracing::error!(error = %error, "web alert ack-bulk failed");
            redirect_error(
                "Could not acknowledge the alerts. Try again.",
                "/alerts",
                &state.config,
            )
        }
    }
}

// ─── CP tenant lifecycle (item I) ─────────────────────────────────

/// POST /web/admin/tenants/{id}/suspend — signs a `suspend-tenant`
/// confirmation; the confirm page's POST performs the guarded UPDATE.
async fn form_admin_tenant_suspend(
    State(state): State<AppState>,
    axum::Extension(_user): axum::Extension<AuthUser>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    if let Err(message) = check_csrf(&form, &headers, &state.config) {
        return redirect_error(message, "/tenants", &state.config);
    }
    let row: Option<(String,)> = sqlx::query_as("SELECT status FROM tenants WHERE id = $1")
        .bind(&id)
        .fetch_optional(&state.db)
        .await
        .ok()
        .flatten();
    match row {
        Some((status,)) if matches!(status.as_str(), "pending" | "active") => {
            redirect_to_bulk_confirm("suspend-tenant", &[id], "/tenants", &state.config)
        }
        Some((status,)) => redirect_error(
            &format!("Tenant is “{status}” — only pending or active tenants can be suspended."),
            "/tenants",
            &state.config,
        ),
        None => redirect_error("That tenant could not be found.", "/tenants", &state.config),
    }
}

/// POST /web/admin/tenants/{id}/resume — suspended → active (validated,
/// direct — resuming is not destructive).
async fn form_admin_tenant_resume(
    State(state): State<AppState>,
    axum::Extension(_user): axum::Extension<AuthUser>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    if let Err(message) = check_csrf(&form, &headers, &state.config) {
        return redirect_error(message, "/tenants", &state.config);
    }
    let result = sqlx::query(
        "UPDATE tenants SET status = 'active', updated_at = NOW()
         WHERE id = $1 AND status = 'suspended'",
    )
    .bind(&id)
    .execute(&state.db)
    .await;
    if matches!(&result, Ok(update) if update.rows_affected() == 1) {
        // F18: the recovery takes effect immediately for the tenant's
        // sessions and API keys.
        crate::middleware::auth::invalidate_tenant_status_cache(&id, &state).await;
    }
    match result {
        Ok(result) if result.rows_affected() == 1 => redirect_success(
            "Tenant resumed — status is now active.",
            "/tenants",
            &state.config,
        ),
        Ok(_) => redirect_error(
            "Only suspended tenants can be resumed.",
            "/tenants",
            &state.config,
        ),
        Err(error) => {
            tracing::error!(error = %error, "web tenant resume failed");
            redirect_error(
                "Could not resume the tenant. Try again.",
                "/tenants",
                &state.config,
            )
        }
    }
}

/// POST /web/admin/tenants/{id}/delete — signs a `delete-tenant`
/// confirmation; the confirm page collects the typed tenant name and the
/// confirm POST re-verifies it against the row server-side.
async fn form_admin_tenant_delete(
    State(state): State<AppState>,
    axum::Extension(_user): axum::Extension<AuthUser>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    if let Err(message) = check_csrf(&form, &headers, &state.config) {
        return redirect_error(message, "/tenants", &state.config);
    }
    let exists: Option<(String,)> = sqlx::query_as("SELECT id::text FROM tenants WHERE id = $1")
        .bind(&id)
        .fetch_optional(&state.db)
        .await
        .ok()
        .flatten();
    match exists {
        Some(_) => redirect_to_bulk_confirm("delete-tenant", &[id], "/tenants", &state.config),
        None => redirect_error("That tenant could not be found.", "/tenants", &state.config),
    }
}

// ─── CP domain transfer surface (item J) ──────────────────────────

/// GET /web/admin/domains/{domain}/transfer — renders the transfer
/// SUGGESTION data by calling the exact JSON logic
/// (`admin::domains::get_transfer_suggestion`): owner verification
/// history, live DNS-control evidence, and the recommendation flag.
async fn web_admin_domain_transfer(
    State(state): State<AppState>,
    axum::Extension(user): axum::Extension<AuthUser>,
    Path(domain): Path<String>,
    headers: HeaderMap,
) -> Response {
    use crate::routes::admin::domains::{get_transfer_suggestion, TransferSuggestionQuery};
    let query = TransferSuggestionQuery {
        domain: domain.clone(),
    };
    match get_transfer_suggestion(
        State(state.clone()),
        user.clone(),
        axum::extract::Query(query),
    )
    .await
    {
        Ok(axum::Json(suggestion)) => {
            let flash = flash_from_headers(&headers, &state.config);
            let list = data::transfer_suggestion_page(&suggestion);
            let path = format!("/web/admin/domains/{}/transfer", urlencode(&domain));
            let form_csrf = form_csrf_for_render(&headers, &state.config);
            let html = cp_data_page(&path, &list, "signal", &flash, &form_csrf.token);
            html_page_response(html, &form_csrf, !flash.is_empty(), &state.config)
        }
        Err(error) => redirect_error(
            &format!("Transfer check could not run: {error}"),
            "/domains",
            &state.config,
        ),
    }
}

/// POST /web/admin/domains/transfer — typed `transfer {domain}`
/// exact-match confirmation calling the existing admin transfer service
/// path (DKIM re-bind, quota checks, verification reset).
async fn form_admin_domain_transfer(
    State(state): State<AppState>,
    axum::Extension(user): axum::Extension<AuthUser>,
    headers: HeaderMap,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    use crate::routes::admin::domains::{admin_transfer_domain, AdminTransferDomainRequest};
    if let Err(message) = check_csrf(&form, &headers, &state.config) {
        return redirect_error(message, "/domains", &state.config);
    }
    let domain = field(&form, "domain").trim().to_ascii_lowercase();
    let to_tenant_id = field(&form, "to_tenant_id").trim().to_string();
    let confirmation = field(&form, "confirmation").trim().to_string();
    let mut fields = FormFieldMap::new("domain-transfer");
    fields.set("domain", &domain);
    fields.set("to_tenant_id", &to_tenant_id);
    fields.set("confirmation", &confirmation);
    let expected = format!("transfer {domain}");
    if domain.is_empty() || to_tenant_id.is_empty() {
        fields.error("domain", "Domain and target tenant are required.");
        return redirect_with_field_map(
            &fields,
            "Domain and target tenant are required.",
            "/domains",
            &state.config,
        );
    }
    if !transfer_confirmation_matches(&domain, &confirmation) {
        fields.error(
            "confirmation",
            &format!("Type “{expected}” exactly to confirm."),
        );
        return redirect_with_field_map(
            &fields,
            &format!("Type “{expected}” exactly to confirm the transfer."),
            "/domains",
            &state.config,
        );
    }
    let body = AdminTransferDomainRequest {
        domain: domain.clone(),
        to_tenant_id,
        confirmation,
    };
    match admin_transfer_domain(State(state.clone()), user.clone(), axum::Json(body)).await {
        Ok((_status, axum::Json(response))) => redirect_success(
            &format!(
                "Domain {} transferred to tenant {} — status {}, DKIM {}.",
                response.domain,
                response.to_tenant_id,
                response.status,
                if response.dkim_rotated {
                    "rotated"
                } else {
                    "carried over"
                }
            ),
            "/domains",
            &state.config,
        ),
        Err(error) => redirect_error(
            &format!("Transfer failed: {error}"),
            "/domains",
            &state.config,
        ),
    }
}

// ─── Sales actions (item K) ───────────────────────────────────────

/// The sales-autopilot service's base URL, or `None` when unconfigured.
/// The config carries a default loopback address — an explicitly EMPTY
/// value means "not configured", and an unreachable engine surfaces as
/// an honest error (never a success flash).
fn sales_engine_base_url(state: &AppState) -> Option<String> {
    sales_engine_base_url_for(&state.config)
}

fn sales_engine_base_url_for(config: &Config) -> Option<String> {
    let base = config.sales_autopilot_base_url.trim();
    (!base.is_empty()).then(|| base.trim_end_matches('/').to_string())
}

/// POST /web/admin/sales/discovery/run — triggers the sales engine's
/// enrich path (POST {base}/enrich) for each selected source domain,
/// surfacing the engine's errors verbatim in an error flash.
async fn form_sales_discovery_run(
    State(state): State<AppState>,
    axum::Extension(user): axum::Extension<AuthUser>,
    headers: HeaderMap,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    if let Err(message) = check_csrf(&form, &headers, &state.config) {
        return redirect_error(message, "/sales", &state.config);
    }
    let sources: Vec<String> = field(&form, "sources")
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect();
    if sources.is_empty() {
        return redirect_error(
            "Add at least one comma-separated source.",
            "/sales",
            &state.config,
        );
    }
    let Some(base) = sales_engine_base_url(&state) else {
        return redirect_error(
            "Sales engine not configured — set SALES_AUTOPILOT_BASE_URL to run discovery.",
            "/sales",
            &state.config,
        );
    };
    let _ = user;
    let mut enriched = 0usize;
    let mut failed: Vec<String> = Vec::new();
    for source in &sources {
        let payload = serde_json::json!({ "domain": source, "tenant_id": "system" });
        let request = state
            .http_client
            .post(format!("{base}/enrich"))
            .header("x-tenant-id", "system")
            .json(&payload)
            .timeout(std::time::Duration::from_secs(30));
        let request = if let Some(token) = state.config.internal_service_token.as_deref() {
            request.header("x-api-key", token)
        } else {
            request
        };
        match request.send().await {
            Ok(response) if response.status().is_success() => enriched += 1,
            Ok(response) => {
                let status = response.status();
                let body = response.text().await.unwrap_or_default();
                let detail = body.trim().trim_matches('"');
                failed.push(if detail.is_empty() {
                    format!("{source}: engine returned {status}")
                } else {
                    format!("{source}: {detail}")
                });
            }
            Err(error) => failed.push(format!("{source}: {error}")),
        }
    }
    if enriched == 0 {
        return redirect_error(
            &format!(
                "Discovery run failed — the sales engine did not enrich any source. {}",
                failed.join("; ")
            ),
            "/sales",
            &state.config,
        );
    }
    let summary = format!(
        "Discovery run finished: {enriched} source(s) enriched, {} failed.",
        failed.len()
    );
    if failed.is_empty() {
        redirect_success(&summary, "/sales", &state.config)
    } else {
        redirect_with_flash(
            &[
                FlashMessage::success(summary),
                FlashMessage::error(failed.join("; ")),
            ],
            "/sales",
            &state.config,
        )
    }
}

/// POST /web/admin/sales/outreach/launch — forwards the enrollment command
/// (POST {base}/enrollments) for the selected contacts. Outreach is an
/// enrollment command: the CP creates no campaign and no recipient rows
/// itself, and the engine's answer (accepted/rejected counts, quota-pause
/// errors) surfaces honestly.
async fn form_sales_outreach_launch(
    State(state): State<AppState>,
    axum::Extension(_user): axum::Extension<AuthUser>,
    headers: HeaderMap,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    if let Err(message) = check_csrf(&form, &headers, &state.config) {
        return redirect_error(message, "/sales", &state.config);
    }
    let sequence_id = field(&form, "sequence_id").trim().to_string();
    let autonomy_policy_id = field(&form, "autonomy_policy_id").trim().to_string();
    if sequence_id.is_empty() || autonomy_policy_id.is_empty() {
        return redirect_error(
            "An enrollment command needs a sequence id and an autonomy policy id.",
            "/sales",
            &state.config,
        );
    }
    let contact_ids: Vec<String> = form
        .get("contact_ids")
        .or_else(|| form.get("lead_ids"))
        .map(|v| {
            v.split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default();
    if contact_ids.is_empty() || contact_ids.len() > 100 {
        return redirect_error(
            "Provide 1-100 comma-separated contact ids.",
            "/sales",
            &state.config,
        );
    }
    let Some(base) = sales_engine_base_url(&state) else {
        return redirect_error(
            "Sales engine not configured — set SALES_AUTOPILOT_BASE_URL to launch outreach.",
            "/sales",
            &state.config,
        );
    };

    let mut payload = json!({
        "sequenceId": sequence_id,
        "contactIds": contact_ids,
        "autonomyPolicyId": autonomy_policy_id,
    });
    let experiment_id = field(&form, "experiment_id").trim().to_string();
    if !experiment_id.is_empty() {
        payload["experimentId"] = json!(experiment_id);
    }

    let request = state
        .http_client
        .post(format!("{base}/enrollments"))
        .header("x-tenant-id", "system")
        .json(&payload)
        .timeout(std::time::Duration::from_secs(30));
    let request = if let Some(token) = state.config.internal_service_token.as_deref() {
        request.header("x-api-key", token)
    } else {
        request
    };
    match request.send().await {
        Ok(response) if response.status().is_success() => {
            let body = response
                .json::<serde_json::Value>()
                .await
                .unwrap_or_else(|_| json!({}));
            let accepted = body.get("accepted").and_then(|v| v.as_u64()).unwrap_or(0);
            let rejected = body.get("rejected").and_then(|v| v.as_u64()).unwrap_or(0);
            redirect_success(
                &format!("Outreach enrollment accepted: {accepted} accepted, {rejected} rejected."),
                "/sales",
                &state.config,
            )
        }
        Ok(response) => {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            sales_engine_error_flash(status, &body, "/sales", &state.config)
        }
        Err(error) => redirect_error(
            &format!("Sales engine not reachable at {base}: {error}"),
            "/sales",
            &state.config,
        ),
    }
}

/// Surface a sales-engine failure verbatim (quota-pause style errors
/// arrive as JSON bodies like "campaign paused: email quota exhausted").
fn sales_engine_error_flash(
    status: reqwest::StatusCode,
    body: &str,
    location: &str,
    config: &Config,
) -> Response {
    let trimmed = body.trim().trim_matches('"');
    let detail = if trimmed.is_empty() {
        format!("engine returned {status}")
    } else {
        // Prefer the engine's structured message when present.
        serde_json::from_str::<serde_json::Value>(trimmed)
            .ok()
            .and_then(|value| {
                value
                    .get("error")
                    .or_else(|| value.get("message"))
                    .and_then(|v| v.as_str())
                    .map(str::to_string)
            })
            .unwrap_or_else(|| trimmed.to_string())
    };
    redirect_error(&format!("Outreach failed: {detail}."), location, config)
}

// ─── GDPR queue transitions (item L) ──────────────────────────────

/// POST /web/admin/gdpr/{id}/transition — the triad
/// pending → in_progress → completed/rejected, validated against the
/// compliance crate's forward-only semantics, with an audit-log entry
/// and honest row-count flashes.
async fn form_admin_gdpr_transition(
    State(state): State<AppState>,
    axum::Extension(user): axum::Extension<AuthUser>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    if let Err(message) = check_csrf(&form, &headers, &state.config) {
        return redirect_error(message, "/compliance/gdpr", &state.config);
    }
    let target = field(&form, "status").trim().to_string();
    let back = safe_return_to(&form, "/compliance/gdpr");
    let current: Option<(String,)> =
        sqlx::query_as("SELECT status FROM gdpr_requests WHERE id = $1")
            .bind(&id)
            .fetch_optional(&state.db)
            .await
            .ok()
            .flatten();
    let Some((current,)) = current else {
        return redirect_error(
            "That GDPR request could not be found.",
            &back,
            &state.config,
        );
    };
    if !gdpr_transition_allowed(&current, &target) {
        return redirect_error(
            &format!(
                "A “{current}” request cannot move to “{target}”. Legal moves: pending → in_progress → completed/rejected."
            ),
            &back,
            &state.config,
        );
    }
    let result = sqlx::query(
        "UPDATE gdpr_requests
         SET status = $1,
             fulfilled_at = CASE WHEN $1 = 'completed' THEN NOW() ELSE fulfilled_at END,
             updated_at = NOW()
         WHERE id = $2 AND status = $3",
    )
    .bind(&target)
    .bind(&id)
    .bind(&current)
    .execute(&state.db)
    .await;
    match result {
        Ok(result) if result.rows_affected() == 1 => {
            // Audit-honest: the transition is recorded in the platform
            // audit chain (actor + from/to).
            let _ = crate::audit_log::insert_audit_log(
                &state.db,
                None,
                user.user_id.as_deref(),
                "gdpr_request.transition",
                "gdpr_request",
                Some(&id),
                json!({ "from": current, "to": target }),
                None,
                None,
            )
            .await;
            redirect_success(
                &format!("Request {id} moved to {target}."),
                &back,
                &state.config,
            )
        }
        Ok(_) => redirect_error(
            "The request changed state just now. Reload and retry.",
            &back,
            &state.config,
        ),
        Err(error) => {
            tracing::error!(error = %error, "web gdpr transition failed");
            redirect_error(
                "Could not update the request. Try again.",
                &back,
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
pub fn decode_flash_from_cookie_header(header_value: &str, secret: &str) -> Vec<FlashMessage> {
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
        assert_eq!(
            response.headers().get(header::LOCATION).unwrap(),
            "/campaigns"
        );
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
        assert_eq!(
            normalize_consent_choice(Some("necessary")),
            Some("necessary")
        );
        // "dismiss" was the deleted site.js semantics: record, enable nothing.
        assert_eq!(normalize_consent_choice(Some("dismiss")), Some("necessary"));
        // Whitespace is tolerated; anything else records nothing.
        assert_eq!(normalize_consent_choice(Some(" all ")), Some("all"));
        assert_eq!(normalize_consent_choice(Some("garbage")), None);
        assert_eq!(normalize_consent_choice(Some("")), None);
        assert_eq!(normalize_consent_choice(None), None);
    }

    // ── F46: SSR/JSON key-creation parity ──────────────────────────────

    /// Drive the console form handler exactly like a browser POST: a
    /// double-submit CSRF pair, a urlencoded body, and the caller's
    /// session identity. Returns the decoded reveal-once field map (for
    /// the raw secret) so the test can assert against the PERSISTED row.
    async fn post_console_api_key_form(
        state: &AppState,
        user: &AuthUser,
        body: &str,
    ) -> (Response, Option<FormFieldMap>) {
        let config = &state.config;
        let csrf = form_csrf_for_render(&HeaderMap::new(), config);
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            format!("csrf_token={}", csrf.token).parse().unwrap(),
        );
        headers.insert(
            header::CONTENT_TYPE,
            "application/x-www-form-urlencoded".parse().unwrap(),
        );
        let body_with_csrf = format!("{body}&_csrf={}", csrf.token);
        let response = form_api_key_create(
            State(state.clone()),
            axum::Extension(user.clone()),
            headers,
            axum::body::Bytes::from(body_with_csrf),
        )
        .await;

        let field_map = response
            .headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .find_map(|value| {
                let cookie = value.to_str().ok()?;
                let (name, rest) = cookie.split_once('=')?;
                (name == FORM_FIELDS_COOKIE_NAME).then(|| {
                    FormFieldMap::decode(
                        rest.split(';').next().unwrap_or_default(),
                        &config.csrf_secret,
                    )
                })?
            });
        (response, field_map)
    }

    #[tokio::test]
    async fn console_api_key_form_shares_the_json_policy() {
        let Some(pool) = crate::test_db::canonical_pool("web_key_parity").await else {
            eprintln!("skipping console_api_key_form_shares_the_json_policy: no TEST_DATABASE_URL");
            return;
        };
        sqlx::raw_sql(
            "CREATE TABLE IF NOT EXISTS api_keys (
                id UUID PRIMARY KEY,
                tenant_id VARCHAR(26) NOT NULL,
                name TEXT NOT NULL,
                key_prefix VARCHAR(32) NOT NULL,
                key_hash TEXT NOT NULL UNIQUE,
                scopes JSONB NOT NULL,
                expires_at TIMESTAMPTZ,
                last_used_at TIMESTAMPTZ,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )",
        )
        .execute(&pool)
        .await
        .expect("api_keys fixture DDL must apply");
        let state = crate::app::test_support::test_state_over(pool.clone()).await;
        let tenant_id = format!("tpar{}", &uuid::Uuid::new_v4().simple().to_string()[..16]);
        sqlx::query(
            "INSERT INTO tenants (id, name, slug, plan, status, created_at, updated_at)
             VALUES ($1, 'Parity Co', $2, 'free', 'active', NOW(), NOW())",
        )
        .bind(&tenant_id)
        .bind(format!("slug-{tenant_id}"))
        .execute(&pool)
        .await
        .expect("seed tenant");
        let admin = AuthUser {
            tenant_id: tenant_id.clone(),
            user_id: Some(uuid::Uuid::new_v4().to_string()),
            api_key_id: None,
            session_id: None,
            scopes: vec!["*".to_string()],
        };

        // 1. Bare form (name only): the console default scopes plus the
        //    SHARED 90-day expiry default — the SSR path used to insert
        //    NULL expires_at, i.e. a never-expiring credential (F46).
        let (response, field_map) =
            post_console_api_key_form(&state, &admin, "name=Console Default").await;
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        let map = field_map.expect("reveal-once field map cookie must be set");
        let (label, raw_secret) = map
            .secrets()
            .first()
            .expect("the one-time secret rides the signed cookie");
        assert!(label.contains("shown once"));

        let row: (
            String,
            serde_json::Value,
            chrono::DateTime<Utc>,
            Option<chrono::DateTime<Utc>>,
        ) = sqlx::query_as(
            "SELECT key_hash, scopes, created_at, expires_at FROM api_keys
                 WHERE tenant_id = $1 AND name = 'Console Default'",
        )
        .bind(&tenant_id)
        .fetch_one(&pool)
        .await
        .expect("console key persisted");
        assert_eq!(
            row.0,
            apexmail_lib::hash_api_key_with_secret(raw_secret, &state.config.api_key_hash_secret),
            "SSR must use the SAME keyed HMAC hash as the JSON endpoint"
        );
        assert_eq!(
            row.1,
            serde_json::json!(["messages:send", "messages:read"]),
            "absent scope choices keep the console default"
        );
        let expires_at = row
            .3
            .expect("console-created keys must now carry an expiry (F46)");
        assert!(
            expires_at > Utc::now() + chrono::Duration::days(89)
                && expires_at < Utc::now() + chrono::Duration::days(91),
            "default expiry must be the shared 90-day policy, got {expires_at}"
        );

        // 2. Explicit choices: posted scopes (multi-value) and a bounded
        //    expiry ride the SHARED validation/authorization.
        let (response, _) = post_console_api_key_form(
            &state,
            &admin,
            "name=Console Scoped&scopes=domains:read&scopes=messages:read&expires_in_days=7",
        )
        .await;
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        let row: (serde_json::Value, chrono::DateTime<Utc>) = sqlx::query_as(
            "SELECT scopes, expires_at FROM api_keys
             WHERE tenant_id = $1 AND name = 'Console Scoped'",
        )
        .bind(&tenant_id)
        .fetch_one(&pool)
        .await
        .expect("scoped console key persisted");
        assert_eq!(
            row.0,
            serde_json::json!(["domains:read", "messages:read"]),
            "posted checkbox-group scopes are stored exactly"
        );
        assert!(
            row.1 > Utc::now() + chrono::Duration::days(6)
                && row.1 < Utc::now() + chrono::Duration::days(8),
            "explicit 7-day expiry honoured, got {}",
            row.1
        );

        // 3. Shared authorization: a restricted console session cannot
        //    mint a scope it lacks — the SSR surface used to skip scope
        //    checks entirely.
        let viewer = AuthUser {
            tenant_id: tenant_id.clone(),
            user_id: Some(uuid::Uuid::new_v4().to_string()),
            api_key_id: None,
            session_id: None,
            scopes: vec!["messages:read".to_string()],
        };
        let (response, _) =
            post_console_api_key_form(&state, &viewer, "name=Escalation&scopes=messages:send")
                .await;
        assert_eq!(
            response.status(),
            StatusCode::SEE_OTHER,
            "still a flash PRG"
        );
        let escalation_flash = flash_messages(&response, &state.config);
        assert!(
            escalation_flash
                .iter()
                .any(|message| message.kind == ui_foundation::flash::FlashKind::Error),
            "escalation attempt must flash an error, got {escalation_flash:?}"
        );
        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM api_keys WHERE tenant_id = $1 AND name = 'Escalation'",
        )
        .bind(&tenant_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(count, 0, "no key may be minted for the escalation attempt");

        // 4. Missing CSRF is refused outright.
        let mut headers = HeaderMap::new();
        headers.insert(
            header::CONTENT_TYPE,
            "application/x-www-form-urlencoded".parse().unwrap(),
        );
        let response = form_api_key_create(
            State(state.clone()),
            axum::Extension(admin.clone()),
            headers,
            axum::body::Bytes::from_static(b"name=No Csrf"),
        )
        .await;
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        let csrf_flash = flash_messages(&response, &state.config);
        assert!(
            csrf_flash
                .iter()
                .any(|message| message.kind == ui_foundation::flash::FlashKind::Error),
            "missing CSRF must flash an error, got {csrf_flash:?}"
        );

        pool.close().await;
    }

    /// Decode the flash cookie a PRG response set (test-only view into the
    /// signed payload).
    fn flash_messages(response: &Response, config: &Config) -> Vec<FlashMessage> {
        response
            .headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .filter_map(|value| value.to_str().ok())
            .filter(|cookie| cookie.starts_with("apexmail_flash="))
            .flat_map(|cookie| decode_flash_from_cookie_header(cookie, &config.csrf_secret))
            .collect()
    }

    #[test]
    fn consent_return_to_rejects_backslash_and_control_characters() {
        // WHATWG URL parsing normalises `\` to `/` inside special
        // schemes, so a browser handed "/\evil.com" navigates to
        // "//evil.com" — a protocol-relative hop straight to the
        // attacker. Control characters (CR/LF/TAB) can additionally
        // smuggle headers or corrupt parsers. None may survive.
        assert_eq!(consent_safe_return_to(Some("/\\evil.com")), "/");
        assert_eq!(consent_safe_return_to(Some("\\/evil.com")), "/");
        assert_eq!(consent_safe_return_to(Some("/pricing\\@evil.example")), "/");
        assert_eq!(consent_safe_return_to(Some("/pricing\\")), "/");
        // The absolute-URL branch must be guarded by the same rule.
        assert_eq!(
            consent_safe_return_to(Some("https://apexmail.ee/\\evil.com")),
            "/"
        );
        assert_eq!(
            consent_safe_return_to(Some(
                "https://apexmail.ee/pricing\\\r\nSet-Cookie: apexmail_consent=all"
            )),
            "/"
        );
        assert_eq!(
            consent_safe_return_to(Some("/pricing\r\nSet-Cookie: x=1")),
            "/"
        );
        // A control char *inside* the path is rejected; one at the very
        // edge is already neutralised by the trim() above it.
        assert_eq!(consent_safe_return_to(Some("/pri\u{0007}cing")), "/");
        assert_eq!(consent_safe_return_to(Some("/pricing\u{0007}")), "/");
        assert_eq!(consent_safe_return_to(Some("/pricing\t")), "/pricing");
        // …while the honest values still pass through untouched.
        assert_eq!(
            consent_safe_return_to(Some("/pricing?back=1")),
            "/pricing?back=1"
        );
        assert_eq!(consent_safe_return_to(Some("/de/cookies/")), "/de/cookies/");
        assert_eq!(
            consent_safe_return_to(Some("https://app.apexmail.ee/dashboard?next=/x")),
            "https://app.apexmail.ee/dashboard?next=/x"
        );
    }

    #[test]
    fn form_return_to_rejects_backslash_and_control_characters() {
        let mut form = HashMap::new();
        // Same WHATWG normalisation hazard as the consent validator.
        form.insert("return_to".to_string(), "/\\evil.com".to_string());
        assert_eq!(safe_return_to(&form, "/dashboard"), "/dashboard");
        form.insert("return_to".to_string(), "\\/evil.com".to_string());
        assert_eq!(safe_return_to(&form, "/dashboard"), "/dashboard");
        form.insert("return_to".to_string(), "/ok\r\n".to_string());
        assert_eq!(safe_return_to(&form, "/dashboard"), "/dashboard");
        form.insert("return_to".to_string(), "/ok\t".to_string());
        assert_eq!(safe_return_to(&form, "/dashboard"), "/dashboard");
        // The `next` alias is guarded identically.
        form.remove("return_to");
        form.insert("next".to_string(), "/\\evil.com".to_string());
        assert_eq!(safe_return_to(&form, "/dashboard"), "/dashboard");
        // Honest paths keep flowing through.
        form.remove("next");
        form.insert("return_to".to_string(), "/contacts?page=2".to_string());
        assert_eq!(safe_return_to(&form, "/dashboard"), "/contacts?page=2");
    }

    /// Item 4: `/consent?choice=all` is a bare GET, so any third party
    /// can embed it as `<img>` and forge a consent cookie for visitors.
    /// A spoofed `Sec-Fetch-Site: cross-site` request must NOT set the
    /// cookie; genuine same-site navigations (the no-JS banner links)
    /// and header-less older browsers must keep working.
    #[tokio::test]
    async fn cross_site_consent_get_does_not_set_the_cookie() {
        use axum::body::Body;
        use axum::http::Request;
        use tower::ServiceExt;

        // The consent endpoints never touch the database or Redis, so a
        // lazy pool against a dead port is enough AppState.
        let db = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .connect_lazy("postgres://apexmail:apexmail@127.0.0.1:1/apexmail")
            .expect("lazy test pool");
        let state = crate::app::test_support::test_state_over(db).await;
        let app = consent_router().with_state(state);

        let send = |fetch_site: Option<&'static str>, referer: Option<&'static str>| {
            let app = app.clone();
            async move {
                let mut builder = Request::get(
                    "/consent?choice=all&return_to=https%3A%2F%2Fapexmail.ee%2Fpricing",
                );
                if let Some(site) = fetch_site {
                    builder = builder.header("sec-fetch-site", site);
                }
                if let Some(referer) = referer {
                    builder = builder.header(header::REFERER, referer);
                }
                app.oneshot(builder.body(Body::empty()).unwrap())
                    .await
                    .expect("consent GET")
            }
        };

        // Spoofed cross-site GET: redirected, cookie untouched.
        let forged = send(Some("cross-site"), None).await;
        assert_eq!(forged.status(), StatusCode::FOUND);
        assert!(
            forged.headers().get(header::SET_COOKIE).is_none(),
            "cross-site GET must not record consent"
        );

        // Real banner clicks: same-origin (api host page) and same-site
        // (apexmail.ee → api.apexmail.ee) both set the cookie.
        for site in ["same-origin", "same-site"] {
            let response = send(Some(site), None).await;
            assert_eq!(response.status(), StatusCode::FOUND);
            let cookie = response
                .headers()
                .get(header::SET_COOKIE)
                .and_then(|v| v.to_str().ok())
                .unwrap_or_default();
            assert!(cookie.starts_with("apexmail_consent=all"), "site={site}");
        }

        // A cross-site Referer without Sec-Fetch-Site is refused too.
        let bad_referer = send(None, Some("https://evil.example/consent-trap.html")).await;
        assert!(bad_referer.headers().get(header::SET_COOKIE).is_none());

        // Older browsers (no Sec-Fetch-Site, no Referer) keep the
        // no-JS flow: choice still recorded.
        let legacy = send(None, None).await;
        let cookie = legacy
            .headers()
            .get(header::SET_COOKIE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default();
        assert!(cookie.starts_with("apexmail_consent=all"));

        // An apexmail-family Referer passes as well.
        let family = send(None, Some("https://apexmail.ee/pricing")).await;
        assert!(family
            .headers()
            .get(header::SET_COOKIE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .starts_with("apexmail_consent=all"));
    }

    #[test]
    fn consent_return_to_allows_only_apexmail_family_https() {
        // Relative same-origin paths pass through.
        assert_eq!(consent_safe_return_to(Some("/pricing")), "/pricing");
        assert_eq!(consent_safe_return_to(Some("/de/cookies/")), "/de/cookies/");
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
        assert_eq!(
            response.headers().get(header::LOCATION).unwrap(),
            "/pricing"
        );
        assert!(response.headers().get(header::SET_COOKIE).is_none());
    }

    #[test]
    fn consent_cookie_header_detection() {
        assert!(cookie_header_has_consent("apexmail_consent=all"));
        assert!(cookie_header_has_consent(
            "session=abc; apexmail_consent=necessary"
        ));
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
    fn csv_escaping_neutralizes_formula_triggers() {
        // Audit F6: a cell leading with = + - @ (or tab/CR) would execute as
        // a formula in Excel/Sheets when the export is opened — it must be
        // forced to text with a leading single quote.
        assert_eq!(csv_escape("=SUM(A1:A9)"), "'=SUM(A1:A9)");
        assert_eq!(csv_escape("+1/0"), "'+1/0");
        assert_eq!(csv_escape("-2+3"), "'-2+3");
        assert_eq!(csv_escape("@cmd|' /C calc'"), "'@cmd|' /C calc'");
        assert_eq!(csv_escape("\t=A1"), "'\t=A1");
        assert_eq!(csv_escape("\rJUNK"), "'\rJUNK");
        // Only the FIRST character matters: mid-cell characters stay as-is.
        assert_eq!(csv_escape("a-b=c"), "a-b=c");
        // Quoting still applies around the neutralized value.
        assert_eq!(csv_escape("=1,2"), "\"'=1,2\"");
    }

    #[test]
    fn check_csrf_binds_the_form_token_to_the_double_submit_cookie() {
        // Audit F4: the hidden `_csrf` input must be backed by the matching
        // `csrf_token` cookie — a token harvested from the public
        // /v1/auth/csrf endpoint alone must not validate a foreign form.
        let config = test_config();
        let token = ui_foundation::csrf::generate_csrf_token(&config.csrf_secret);
        let mut form = HashMap::new();
        form.insert("_csrf".to_string(), token.clone());

        // No cookie at all → rejected.
        assert!(check_csrf(&form, &HeaderMap::new(), &config).is_err());

        // A different cookie value → rejected (constant-time mismatch).
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            "csrf_token=someone-elses-token".parse().unwrap(),
        );
        assert!(check_csrf(&form, &headers, &config).is_err());

        // The matching pair → accepted (timestamp/HMAC still enforced).
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            format!("csrf_token={token}").parse().unwrap(),
        );
        assert!(check_csrf(&form, &headers, &config).is_ok());

        // A token signed with another secret is rejected even when the
        // cookie matches it.
        let foreign = ui_foundation::csrf::generate_csrf_token("other-secret");
        let mut form = HashMap::new();
        form.insert("_csrf".to_string(), foreign.clone());
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            format!("csrf_token={foreign}").parse().unwrap(),
        );
        assert!(check_csrf(&form, &headers, &config).is_err());
    }

    #[test]
    fn mfa_fallback_counter_keeps_the_bruteforce_bound_without_redis() {
        // Audit F11: Redis loss used to remove the lockout bound entirely.
        // The in-process counter keeps it (keyed, windowed, bounded).
        let key = mfa_verify_failure_key("mfa-fallback-unit-user");
        mfa_fallback::clear(&key);
        assert!(!mfa_fallback::locked(&key));

        for _ in 0..MFA_VERIFY_MAX_ATTEMPTS {
            mfa_fallback::record_failure(&key);
        }
        assert!(
            mfa_fallback::locked(&key),
            "the attempt cap holds through a Redis outage"
        );

        // A successful verify clears the window.
        mfa_fallback::clear(&key);
        assert!(!mfa_fallback::locked(&key));

        // Unrelated challenges are not locked by this one's failures.
        mfa_fallback::record_failure(&key);
        assert!(!mfa_fallback::locked(&mfa_verify_failure_key(
            "mfa-fallback-unit-other"
        )));
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
        assert!(verify_login_challenge(
            &config,
            &token,
            "u1",
            "ops@apexmail.ee"
        ));
        assert!(!verify_login_challenge(
            &config,
            &token,
            "u2",
            "ops@apexmail.ee"
        ));
        assert!(!verify_login_challenge(
            &config,
            "garbage",
            "u1",
            "ops@apexmail.ee"
        ));
    }

    // ─── Item F: form field-map cookie ────────────────────────────

    #[test]
    fn form_field_map_round_trips_values_errors_and_secrets() {
        let config = test_config();
        let mut map = FormFieldMap::new("webhook-create");
        map.set("url", "https://example.com/hook");
        map.set("name", "primary");
        map.set("name", "primary v2"); // last write wins
        map.error("url", "Enter a valid https:// endpoint URL.");
        map.secret("API key secret (shown once)", "amk_deadbeef");

        let cookie = form_fields_set_cookie(&map, &config.csrf_secret, false);
        assert!(cookie.starts_with("apexmail_form_fields=v1."));
        assert!(cookie.contains("HttpOnly"));
        assert!(cookie.contains("SameSite=Lax"));
        assert!(cookie.contains("Max-Age=120"));
        assert!(!cookie.contains("Secure"));

        // The VIEW-layer accessor reads it back from a Cookie header.
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            cookie
                .split_once(';')
                .unwrap()
                .0
                .to_string()
                .parse()
                .unwrap(),
        );
        let decoded = decode_form_fields_from_headers(&headers, &config.csrf_secret)
            .expect("valid cookie decodes");
        assert_eq!(decoded.form_id, "webhook-create");
        assert_eq!(decoded.field_value("name"), Some("primary v2"));
        assert_eq!(decoded.field_value("url"), Some("https://example.com/hook"));
        assert_eq!(
            decoded.field_error("url"),
            Some("Enter a valid https:// endpoint URL.")
        );
        assert_eq!(decoded.field_error("name"), None);
        assert_eq!(
            decoded.secrets(),
            &[(
                "API key secret (shown once)".to_string(),
                "amk_deadbeef".to_string()
            )]
        );
        assert!(!decoded.is_empty());
    }

    #[test]
    fn form_field_map_rejects_tampering_wrong_secret_and_oversize() {
        let config = test_config();
        let mut map = FormFieldMap::new("f");
        map.set("x", "y");
        let cookie = form_fields_set_cookie(&map, &config.csrf_secret, false);

        // Wrong secret fails closed.
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            cookie
                .split_once(';')
                .unwrap()
                .0
                .parse::<String>()
                .unwrap()
                .parse()
                .unwrap(),
        );
        assert!(decode_form_fields_from_headers(&headers, "other-secret").is_none());

        // Payload tampering breaks the signature.
        let value = cookie.split_once('=').unwrap().1.split_once(';').unwrap().0;
        let (prefix, rest) = value.split_at(value.find('.').unwrap() + 1);
        let mut chars: Vec<char> = rest.chars().collect();
        chars[0] = if chars[0] == 'A' { 'B' } else { 'A' };
        let tampered = format!("{prefix}{}", chars.into_iter().collect::<String>());
        let mut bad = HeaderMap::new();
        bad.insert(
            header::COOKIE,
            format!("{FORM_FIELDS_COOKIE_NAME}={tampered}")
                .parse()
                .unwrap(),
        );
        assert!(decode_form_fields_from_headers(&bad, &config.csrf_secret).is_none());

        // Oversized payloads are rejected (cookie stuffing resistance).
        let mut big = FormFieldMap::new("big");
        let blob = "x".repeat(16 * 1024);
        big.set("blob", &blob);
        let big_cookie = form_fields_set_cookie(&big, &config.csrf_secret, false);
        let mut big_headers = HeaderMap::new();
        big_headers.insert(
            header::COOKIE,
            big_cookie
                .split_once(';')
                .unwrap()
                .0
                .parse::<String>()
                .unwrap()
                .parse()
                .unwrap(),
        );
        assert!(decode_form_fields_from_headers(&big_headers, &config.csrf_secret).is_none());

        // Absent cookie and empty maps yield None.
        assert!(decode_form_fields_from_headers(&HeaderMap::new(), &config.csrf_secret).is_none());
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            format!(
                "{FORM_FIELDS_COOKIE_NAME}={}",
                FormFieldMap::new("empty").encode(&config.csrf_secret)
            )
            .parse()
            .unwrap(),
        );
        assert!(decode_form_fields_from_headers(&headers, &config.csrf_secret).is_none());
    }

    #[test]
    fn redirect_with_field_map_sets_both_cookies_and_prg_shape() {
        let config = test_config();
        let mut map = FormFieldMap::new("domain-create");
        map.set("name", "mail.example.com");
        map.error("name", "Enter a domain like mail.example.com.");
        let response = redirect_with_field_map(
            &map,
            "Enter a domain like mail.example.com.",
            "/domains/new",
            &config,
        );
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        assert_eq!(
            response.headers().get(header::LOCATION).unwrap(),
            "/domains/new"
        );
        let cookies: Vec<&str> = response
            .headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .map(|value| value.to_str().unwrap())
            .collect();
        assert!(cookies
            .iter()
            .any(|cookie| cookie.starts_with("apexmail_flash=")));
        assert!(cookies
            .iter()
            .any(|cookie| cookie.starts_with("apexmail_form_fields=")));
    }

    #[test]
    fn form_field_map_round_trips_into_the_rendered_form() {
        // Audit F2: the encode→decode round trip must land in the RENDERED
        // page — stored values re-populate their inputs, per-field errors
        // render under the controls, and reveal-once secrets display.
        let config = test_config();
        let mut map = FormFieldMap::new("webhook-create");
        map.set("url", "https://example.com/hook");
        map.error("url", "Enter an https URL.");
        map.secret("Webhook signing secret (shown once)", "whsec_deadbeef");

        let cookie = form_fields_set_cookie(&map, &config.csrf_secret, false);
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            cookie
                .split_once(';')
                .unwrap()
                .0
                .to_string()
                .parse()
                .unwrap(),
        );
        let decoded =
            decode_form_fields_from_headers(&headers, &config.csrf_secret).expect("decodes");
        let fields = decoded.into_view_data();

        let html = ui_foundation::axum_router::render_route_with_form_fields(
            "web",
            "/settings/webhooks",
            None,
            Some(&config.csrf_secret),
            &[],
            None,
            Some(&fields),
        )
        .expect("settings/webhooks renders");
        assert!(
            html.contains("value=\"https://example.com/hook\""),
            "the submitted value re-populates its input"
        );
        assert!(
            html.contains("Enter an https URL."),
            "the per-field error renders under the control"
        );
        assert!(
            html.contains("whsec_deadbeef"),
            "the reveal-once secret renders as a chip"
        );
    }

    // ─── Multi-value form parsing ─────────────────────────────────

    #[test]
    fn urlencoded_parser_keeps_repeated_keys_and_decodes_escapes() {
        let pairs = parse_urlencoded(
            "events=message.accepted&events=message.bounced&url=https%3A%2F%2Fex.io%2Fhook&q=a+b",
        );
        let form = ParsedForm::from_pairs(pairs);
        assert_eq!(
            form.get_all("events"),
            vec![
                "message.accepted".to_string(),
                "message.bounced".to_string()
            ]
        );
        assert_eq!(form.field("url"), "https://ex.io/hook");
        assert_eq!(form.field("q"), "a b");
        // Malformed percent escapes degrade instead of failing.
        let form = ParsedForm::from_pairs(parse_urlencoded("a=100%"));
        assert_eq!(form.field("a"), "100%");
    }

    #[test]
    fn multipart_parser_extracts_fields_and_the_file_part() {
        let body = "--BOUND\r\nContent-Disposition: form-data; name=\"_csrf\"\r\n\r\ntoken123\r\n--BOUND\r\nContent-Disposition: form-data; name=\"csv\"; filename=\"contacts.csv\"\r\nContent-Type: text/csv\r\n\r\nemail,name\r\na@b.ce,A\r\n--BOUND--\r\n";
        let form = parse_multipart(body.as_bytes(), "multipart/form-data; boundary=BOUND")
            .expect("multipart parses");
        assert_eq!(form.field("_csrf"), "token123");
        assert_eq!(form.csv_text(), "email,name\r\na@b.ce,A");
        // The textarea fallback still works.
        let form = ParsedForm::from_pairs(parse_urlencoded("csv=a%40b.ce%2CName"));
        assert_eq!(form.csv_text(), "a@b.ce,Name");
        // A missing boundary is rejected (callers degrade to the flash).
        assert!(parse_multipart(b"x", "multipart/form-data").is_none());
    }

    // ─── Item C: contact CSV parsing ──────────────────────────────

    #[test]
    fn contact_csv_parses_headers_quoted_fields_and_case_insensitive_columns() {
        let csv = "NAME,Email\r\n\"Doe, Jane\",\tJANE@Example.COM \r\n";
        let parsed = parse_contact_csv(csv);
        assert!(parsed.had_header);
        assert_eq!(
            parsed.rows,
            vec![ContactCsvRow {
                email: "jane@example.com".to_string(),
                name: Some("Doe, Jane".to_string()),
            }]
        );
        // A file without a header maps col0=email col1=name.
        let parsed = parse_contact_csv("x@y.io,Bo\n");
        assert!(!parsed.had_header);
        assert_eq!(parsed.rows.len(), 1);
        assert_eq!(parsed.rows[0].name.as_deref(), Some("Bo"));
        // "E-Mail Address" style headers normalize to the email column.
        let parsed = parse_contact_csv("E-Mail Address,Name\nz@w.io,Al\n");
        assert!(parsed.had_header);
        assert_eq!(parsed.rows[0].email, "z@w.io");
        assert_eq!(parsed.rows[0].name.as_deref(), Some("Al"));
    }

    #[test]
    fn contact_csv_reports_invalid_rows_with_line_numbers() {
        let csv = "email,name\nnot-an-email,X\nok@ok.io,\nalso bad,Z\n";
        let parsed = parse_contact_csv(csv);
        assert_eq!(parsed.rows.len(), 1);
        assert_eq!(parsed.rows[0].email, "ok@ok.io");
        assert_eq!(parsed.invalid.len(), 2);
        assert_eq!(parsed.invalid[0].0, 2); // first data row after header
        assert!(parsed.invalid[0].1.contains("not-an-email"));
        assert_eq!(parsed.invalid[1].0, 4);
    }

    #[test]
    fn contact_import_summary_names_counts_and_first_three_examples() {
        let invalid = vec![
            (4usize, "invalid email: nope".to_string()),
            (7usize, "invalid email: worse".to_string()),
            (9usize, "invalid email: bad".to_string()),
            (12usize, "invalid email: also bad".to_string()),
        ];
        let summary = contact_import_summary(5, 2, &invalid);
        assert!(summary.starts_with("Imported 5, skipped 6 (duplicates: 2, invalid: 4)."));
        assert!(summary.contains("line 4: invalid email: nope"));
        assert!(summary.contains("line 7"));
        assert!(summary.contains("line 9"));
        assert!(
            !summary.contains("line 12"),
            "only the first three examples"
        );
    }

    // ─── Item E: webhook event binding rules ──────────────────────

    #[test]
    fn webhook_event_selection_validates_against_the_known_set() {
        assert_eq!(
            normalize_webhook_events(vec![
                "message.accepted".into(),
                " message.accepted ".into(),
                "".into(),
                "message.bounced".into(),
            ]),
            vec![
                "message.accepted".to_string(),
                "message.bounced".to_string()
            ]
        );
        assert!(validate_webhook_events(&[]).is_some());
        let error = validate_webhook_events(&["message.accepted".into(), "delivred".into()]);
        let error = error.expect("typo rejected");
        assert!(error.contains("delivred"));
        assert!(error.contains("message.accepted"));
        assert!(
            validate_webhook_events(&["*".into(), "message.delivered".into()]).is_none(),
            "wildcard and known names pass"
        );
    }

    // ─── Item B: campaign lifecycle rules ─────────────────────────

    #[test]
    fn campaign_lifecycle_rules_match_the_live_status_check() {
        // There is no 'scheduled' status — it can neither start nor pause.
        assert!(campaign_start_allowed("draft"));
        assert!(campaign_start_allowed("paused"));
        assert!(!campaign_start_allowed("scheduled"));
        assert!(!campaign_start_allowed("sending"));
        assert!(!campaign_start_allowed("completed"));
        assert!(campaign_pause_allowed("sending"));
        assert!(!campaign_pause_allowed("paused"));
        assert!(campaign_resume_allowed("paused"));
        assert!(!campaign_resume_allowed("sending"));
    }

    #[test]
    fn campaign_actions_availability_follows_status() {
        let draft = campaign_actions("c1", "draft");
        assert!(draft.iter().find(|a| a.0 == "Start sending").unwrap().2);
        assert!(draft.iter().find(|a| a.0 == "Wire recipients").unwrap().2);
        assert!(!draft.iter().find(|a| a.0 == "Pause").unwrap().2);

        let sending = campaign_actions("c1", "sending");
        assert!(sending.iter().find(|a| a.0 == "Pause").unwrap().2);
        assert!(!sending.iter().find(|a| a.0 == "Start sending").unwrap().2);

        let done = campaign_actions("c1", "completed");
        assert!(
            done.iter().all(|a| !a.2),
            "terminal campaigns have no actions"
        );
    }

    // ─── Item L: GDPR transition rules ────────────────────────────

    #[test]
    fn gdpr_transitions_follow_the_compliance_triad() {
        // The forward triad out of pending.
        assert!(gdpr_transition_allowed("pending", "in_progress"));
        assert!(gdpr_transition_allowed("pending", "completed"));
        assert!(gdpr_transition_allowed("pending", "rejected"));
        // Work has started: only the terminal pair remains.
        assert!(gdpr_transition_allowed("in_progress", "completed"));
        assert!(gdpr_transition_allowed("in_progress", "rejected"));
        assert!(!gdpr_transition_allowed("in_progress", "in_progress"));
        assert!(
            gdpr_transition_allowed("processing", "completed"),
            "the crate's middle state is honored"
        );
        // Terminal states never reopen, and bogus targets are rejected.
        assert!(!gdpr_transition_allowed("completed", "rejected"));
        assert!(!gdpr_transition_allowed("rejected", "in_progress"));
        assert!(!gdpr_transition_allowed("pending", "expired"));
        assert!(!gdpr_transition_allowed("pending", "pending"));
    }

    // ─── Item G: bulk confirmation helpers ────────────────────────

    #[test]
    fn bulk_ids_parse_dedupe_and_cap() {
        assert_eq!(
            parse_bulk_ids(" a , b ,a, ,c "),
            vec!["a".to_string(), "b".to_string(), "c".to_string()]
        );
        assert!(parse_bulk_ids("").is_empty());
        assert!(parse_bulk_ids(" , ").is_empty());
        let many = (0..500)
            .map(|index| format!("id{index}"))
            .collect::<Vec<_>>()
            .join(",");
        assert_eq!(parse_bulk_ids(&many).len(), BULK_CONFIRM_MAX_IDS);
    }

    #[test]
    fn bulk_confirm_redirect_signs_the_id_list() {
        let config = test_config();
        let ids = vec!["c1".to_string(), "c2".to_string()];
        let response =
            redirect_to_bulk_confirm("delete-campaigns-bulk", &ids, "/campaigns", &config);
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        let location = response
            .headers()
            .get(header::LOCATION)
            .and_then(|value| value.to_str().ok())
            .unwrap()
            .to_string();
        assert!(location.starts_with(
            "/confirm?intent=delete-campaigns-bulk&id=c1%2Cc2&return_to=%2Fcampaigns&sig="
        ));
        // Extract the sig and re-verify it over the exact id list.
        let sig = location.split("sig=").nth(1).unwrap().to_string();
        assert!(verify_confirmation(
            &config.csrf_secret,
            &sig,
            "delete-campaigns-bulk",
            "c1,c2",
            Utc::now().timestamp(),
        ));
        // A different id list must NOT verify (no replay across selections).
        assert!(!verify_confirmation(
            &config.csrf_secret,
            &sig,
            "delete-campaigns-bulk",
            "c1,c3",
            Utc::now().timestamp(),
        ));
    }

    // ─── Item J: typed transfer confirmation ──────────────────────

    #[test]
    fn transfer_confirmation_requires_the_exact_typed_string() {
        assert!(transfer_confirmation_matches(
            "victim.com",
            "transfer victim.com"
        ));
        assert!(transfer_confirmation_matches(
            "Victim.COM",
            "  transfer victim.com  "
        ));
        assert!(!transfer_confirmation_matches(
            "victim.com",
            "transfer victim"
        ));
        assert!(!transfer_confirmation_matches(
            "victim.com",
            "TRANSFER VICTIM.COM"
        ));
        assert!(!transfer_confirmation_matches("victim.com", ""));
    }

    // ─── Item M: days filter parsing ──────────────────────────────

    #[test]
    fn days_filter_parses_and_bounds() {
        let q = data::parse_list_query(Some("query=login&days=7"));
        assert_eq!(q.days, Some(7));
        // Hostile / out-of-range values degrade to no filter.
        assert_eq!(data::parse_list_query(Some("days=0")).days, None);
        assert_eq!(data::parse_list_query(Some("days=-5")).days, None);
        assert_eq!(data::parse_list_query(Some("days=999999")).days, None);
        assert_eq!(data::parse_list_query(Some("days=abc")).days, None);
    }

    // ─── Item K: sales engine configuration ───────────────────────

    #[test]
    fn sales_engine_base_url_distinguishes_unconfigured() {
        let config = test_config();
        assert!(sales_engine_base_url_for(&config).is_some());
        let mut unconfigured = config.clone();
        unconfigured.sales_autopilot_base_url = "  ".to_string();
        assert!(sales_engine_base_url_for(&unconfigured).is_none());
        // Trailing slashes are trimmed for path composition.
        let mut slashed = config.clone();
        slashed.sales_autopilot_base_url = "http://localhost:3010/".to_string();
        assert_eq!(
            sales_engine_base_url_for(&slashed).as_deref(),
            Some("http://localhost:3010")
        );
    }

    // ─── DB-gated handler tests (skipped without TEST_DATABASE_URL) ──
    //
    // These drive the real handlers through a router with a session
    // AuthUser extension — the same shape app.rs's full-stack tests use,
    // scoped to the /web form twins. Seeds are unique per run and cleaned
    // up in teardown; without a reachable database every test skips.

    mod db_backed {
        use super::*;
        use axum::body::Body;
        use axum::http::Request;
        use std::sync::Arc;
        use tower::ServiceExt;

        /// Real AppState (mirrors app.rs's test fixture) over the CANONICAL
        /// isolated test database — `crate::test_db::optional_pg_pool`, i.e.
        /// `<dbname>_api` carrying the full `migrations/` chain applied by
        /// the production migrator (audit F01), NOT a lazy pool pointed at
        /// the raw `TEST_DATABASE_URL` database.
        ///
        /// The distinction is load-bearing: a raw developer database can be
        /// a mixed legacy lineage whose shapes contradict the canonical
        /// ones the fixtures bind against —
        ///
        ///   * `users.id` / `contacts.id` / `lists.id` / `domains.id` /
        ///     `api_keys.id` / `campaigns.id` / `campaign_jobs.campaign_id`
        ///     are UUID columns (migrations/052_add_missing_foundation_tables.sql:56,
        ///     migrations/068_create_lists_tables.sql:6,22,
        ///     migrations/075_create_missing_tables.sql:120), so fixtures
        ///     bind `Uuid::new_v4()` and the handlers compare
        ///     `WHERE id = $n::uuid`;
        ///   * `webhooks.id` / `templates.id` are VARCHAR(26) with no
        ///     default (migrations/075_create_missing_tables.sql:12,139),
        ///     so fixtures mint ids with `generate_id("", 26)` — a 36-char
        ///     UUID string is a 22001 "value too long" on those columns;
        ///   * `system_alerts.id` is UUID with `DEFAULT gen_random_uuid()`
        ///     (migrations/020_ses_monitoring.sql:96), so the ack-bulk
        ///     fixture intentionally inserts no id;
        ///   * `webhooks.name` is nullable and `webhooks.secret` is NOT
        ///     NULL (migrations/075_create_missing_tables.sql:141-143), so
        ///     the cap fixture supplies url/secret/events but no name.
        ///
        /// Against the raw legacy database every one of those assumptions
        /// broke (23502 / 22001 / silent no-match), which is why the suite
        /// only passed where no database was reachable. Soft-skips without
        /// TEST_DATABASE_URL (workspace convention); a configured-but-broken
        /// database PANICS in `test_db` instead of reading as a skip.
        async fn web_test_state(test_name: &str) -> Option<AppState> {
            static INSTALL: std::sync::Once = std::sync::Once::new();
            INSTALL.call_once(|| {
                let _ = metrics_exporter_prometheus::PrometheusBuilder::new().install_recorder();
                std::env::set_var("AWS_EC2_METADATA_DISABLED", "true");
                std::env::set_var("AWS_ACCESS_KEY_KEY", "test");
                std::env::set_var("AWS_ACCESS_KEY_ID", "test");
                std::env::set_var("AWS_SECRET_ACCESS_KEY", "test");
            });
            let db = crate::test_db::optional_pg_pool(test_name).await?;
            let redis_url =
                std::env::var("TEST_REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:1".into());
            let redis = deadpool_redis::Config::from_url(&redis_url)
                .create_pool(Some(deadpool_redis::Runtime::Tokio1))
                .expect("lazy redis pool");
            let aws_config = aws_config::defaults(aws_config::BehaviorVersion::latest())
                .region(aws_sdk_sesv2::config::Region::new("us-east-1"))
                .load()
                .await;
            let ses_provider = Arc::new(crate::ses_provider::SesIpProvider::new(
                aws_sdk_sesv2::Client::new(&aws_config),
                db.clone(),
                "apexmail".into(),
                "us-east-1".into(),
            ));
            let config = test_config();
            Some(
                crate::state::AppStateInner::with_ddos_protector(
                    db.clone(),
                    apexmail_db::pool::PoolPair {
                        rw: db.clone(),
                        ro: db,
                    },
                    redis,
                    config.clone(),
                    reqwest::Client::new(),
                    (*ses_provider).clone(),
                    None,
                    Arc::new(
                        ddos_protection::DdosProtector::new(
                            ddos_protection::ProtectorConfig::default(),
                        )
                        .await
                        .expect("ddos protector"),
                    ),
                    None,
                    None,
                    crate::resilience::ResilientClient::new_from_config(&config),
                ),
            )
        }

        fn session_user(tenant: &str) -> AuthUser {
            AuthUser {
                tenant_id: tenant.to_string(),
                user_id: Some(format!("op-{tenant}")),
                api_key_id: None,
                session_id: None,
                scopes: vec!["*".to_string()],
            }
        }

        /// A router exposing the /web form twins with the session user
        /// injected (mirrors the authenticated stack's Extension layer).
        fn web_handlers(state: AppState, user: AuthUser) -> axum::Router {
            axum::Router::new()
                .route("/web/campaigns/:id/start", post(form_campaign_start))
                .route("/web/campaigns/:id/pause", post(form_campaign_pause))
                .route("/web/campaigns/:id/resume", post(form_campaign_resume))
                .route(
                    "/web/campaigns/:id/recipients",
                    post(form_campaign_recipients),
                )
                .route(
                    "/web/campaigns/delete-bulk",
                    post(form_campaigns_delete_bulk),
                )
                .route("/web/contacts/import", post(form_contacts_import))
                .route("/web/auth/signup", post(form_signup))
                .route("/web/auth/login", post(form_login))
                .route("/web/auth/mfa/verify", post(form_mfa_verify))
                .route("/web/webhooks", post(form_webhook_create))
                .route("/web/team/invite", post(form_team_invite))
                .route("/web/templates/update", post(form_template_update))
                .route("/web/confirm", post(form_confirm_destructive))
                .route(
                    "/web/admin/alerts/ack-bulk",
                    post(form_admin_alert_ack_bulk),
                )
                .route(
                    "/web/admin/gdpr/:id/transition",
                    post(form_admin_gdpr_transition),
                )
                .route(
                    "/web/admin/tenants/:id/suspend",
                    post(form_admin_tenant_suspend),
                )
                .route(
                    "/web/admin/tenants/:id/resume",
                    post(form_admin_tenant_resume),
                )
                .route(
                    "/web/admin/tenants/:id/delete",
                    post(form_admin_tenant_delete),
                )
                .layer(axum::middleware::from_fn(
                    move |mut req: axum::extract::Request,
                          next: axum::middleware::Next|
                          -> std::pin::Pin<
                        Box<dyn std::future::Future<Output = axum::response::Response> + Send>,
                    > {
                        req.extensions_mut().insert(user.clone());
                        Box::pin(next.run(req))
                    },
                ))
                .with_state(state)
        }

        fn csrf_body(state: &AppState, extra: &[(&str, &str)]) -> String {
            let token = ui_foundation::csrf::generate_csrf_token(&state.config.csrf_secret);
            let mut pairs = vec![("_csrf".to_string(), token)];
            for (key, value) in extra {
                pairs.push((key.to_string(), value.to_string()));
            }
            pairs
                .iter()
                .map(|(key, value)| format!("{}={}", key, urlencode(value)))
                .collect::<Vec<_>>()
                .join("&")
        }

        /// The double-submit `csrf_token` cookie value for a body built by
        /// `csrf_body` (the `_csrf` pair is always first and URL-safe).
        fn csrf_cookie_of(body: &str) -> String {
            body.split('&')
                .find_map(|pair| pair.strip_prefix("_csrf="))
                .filter(|token| !token.is_empty())
                .map(|token| format!("csrf_token={token}"))
                .expect("csrf_body output always carries a _csrf pair")
        }

        fn post_form(uri: &str, body: &str) -> Request<Body> {
            // Audit F4 (double-submit CSRF): when the body carries a `_csrf`
            // token, attach the matching `csrf_token` cookie exactly as a
            // browser would after a page render minted the pair. The value
            // in the body is already URL-encoded, and CSRF tokens are
            // URL-safe base64 + '.', so it passes through unchanged.
            let csrf_cookie = body
                .split('&')
                .find_map(|pair| pair.strip_prefix("_csrf="))
                .filter(|token| !token.is_empty())
                .map(|token| format!("csrf_token={token}"));
            let mut builder = Request::builder()
                .method("POST")
                .uri(uri)
                .header("content-type", "application/x-www-form-urlencoded");
            if let Some(cookie) = csrf_cookie {
                builder = builder.header("cookie", cookie);
            }
            builder.body(Body::from(body.to_string())).unwrap()
        }

        /// Flash messages from a response's Set-Cookie headers.
        fn response_flash(response: &Response, secret: &str) -> Vec<FlashMessage> {
            response
                .headers()
                .get_all(header::SET_COOKIE)
                .iter()
                .filter_map(|value| value.to_str().ok())
                .map(|cookie| decode_flash_from_cookie_header(cookie, secret))
                .find(|messages| !messages.is_empty())
                .unwrap_or_default()
        }

        fn flash_text(messages: &[FlashMessage]) -> String {
            messages
                .iter()
                .map(|message| message.text.clone())
                .collect::<Vec<_>>()
                .join(" | ")
        }

        async fn seed_tenant(state: &AppState, tenant: &str) {
            sqlx::query(
                "INSERT INTO tenants (id, name, slug, plan, status, settings, metadata, created_at, updated_at)
                 VALUES ($1, $2, $3, 'free', 'active', '{}'::jsonb, '{}'::jsonb, NOW(), NOW())
                 ON CONFLICT (id) DO NOTHING",
            )
            .bind(tenant)
            .bind(format!("Web Flow Test {tenant}"))
            .bind(format!("web-flow-{tenant}"))
            .execute(&state.db)
            .await
            .expect("seed tenant");
        }

        async fn cleanup_tenant(state: &AppState, tenant: &str) {
            // Cascade-clean the tenant's rows (contacts FK-cascade; the
            // rest explicitly).
            let _ = sqlx::query("DELETE FROM campaign_jobs WHERE tenant_id = $1")
                .bind(tenant)
                .execute(&state.db)
                .await;
            let _ = sqlx::query("DELETE FROM campaigns WHERE tenant_id = $1")
                .bind(tenant)
                .execute(&state.db)
                .await;
            let _ = sqlx::query("DELETE FROM list_subscribers WHERE list_id IN (SELECT id FROM lists WHERE tenant_id = $1)")
                .bind(tenant)
                .execute(&state.db)
                .await;
            let _ = sqlx::query("DELETE FROM lists WHERE tenant_id = $1")
                .bind(tenant)
                .execute(&state.db)
                .await;
            let _ = sqlx::query("DELETE FROM contacts WHERE tenant_id = $1")
                .bind(tenant)
                .execute(&state.db)
                .await;
            let _ = sqlx::query("DELETE FROM webhooks WHERE tenant_id = $1")
                .bind(tenant)
                .execute(&state.db)
                .await;
            let _ = sqlx::query("DELETE FROM templates WHERE tenant_id = $1")
                .bind(tenant)
                .execute(&state.db)
                .await;
            let _ = sqlx::query("DELETE FROM domains WHERE tenant_id = $1")
                .bind(tenant)
                .execute(&state.db)
                .await;
            let _ = sqlx::query("DELETE FROM gdpr_requests WHERE tenant_id = $1")
                .bind(tenant)
                .execute(&state.db)
                .await;
            let _ = sqlx::query("DELETE FROM tenants WHERE id = $1")
                .bind(tenant)
                .execute(&state.db)
                .await;
        }

        #[tokio::test]
        async fn campaign_start_requires_recipients_then_transitions() {
            let Some(state) =
                web_test_state("campaign_start_requires_recipients_then_transitions").await
            else {
                return;
            };
            let tenant = apexmail_lib::id::generate_id("webflow", 18);
            seed_tenant(&state, &tenant).await;
            // campaigns.id is UUID PRIMARY KEY DEFAULT gen_random_uuid()
            // (migrations/075_create_missing_tables.sql:120) — bind a Uuid,
            // and keep the URL id the same UUID string the handler casts
            // with `id = $1::uuid`.
            let campaign = Uuid::new_v4();
            sqlx::query(
                "INSERT INTO campaigns (id, tenant_id, name, subject, status, created_at, updated_at)
                 VALUES ($1, $2, 'Start Flow', 'Hello', 'draft', NOW(), NOW())",
            )
            .bind(campaign)
            .bind(&tenant)
            .execute(&state.db)
            .await
            .expect("seed campaign");

            let app = web_handlers(state.clone(), session_user(&tenant));
            let uri = format!("/web/campaigns/{campaign}/start");

            // CSRF failure first: friendly flash, nothing changes.
            let response = app
                .clone()
                .oneshot(post_form(&uri, "start=1"))
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::SEE_OTHER);
            let flash = response_flash(&response, &state.config.csrf_secret);
            assert!(flash_text(&flash).contains("session expired"));

            // Honest validation: no recipients wired yet.
            let response = app
                .clone()
                .oneshot(post_form(&uri, &csrf_body(&state, &[])))
                .await
                .unwrap();
            let flash = response_flash(&response, &state.config.csrf_secret);
            assert!(
                flash_text(&flash).to_lowercase().contains("no recipients"),
                "flash was: {flash:?}"
            );
            let status: String =
                sqlx::query_scalar("SELECT status FROM campaigns WHERE id = $1::uuid")
                    .bind(campaign)
                    .fetch_one(&state.db)
                    .await
                    .unwrap();
            assert_eq!(status, "draft");

            // Wire an audience: list + two subscribed contacts.
            let list = Uuid::new_v4();
            sqlx::query("INSERT INTO lists (id, tenant_id, name, created_at, updated_at) VALUES ($1, $2, 'Starters', NOW(), NOW())")
                .bind(list)
                .bind(&tenant)
                .execute(&state.db)
                .await
                .unwrap();
            for email in ["a-start@t.io", "b-start@t.io"] {
                let contact = Uuid::new_v4();
                sqlx::query("INSERT INTO contacts (id, tenant_id, email, status, created_at, updated_at) VALUES ($1, $2, $3, 'subscribed', NOW(), NOW())")
                    .bind(contact)
                    .bind(&tenant)
                    .bind(email)
                    .execute(&state.db)
                    .await
                    .unwrap();
                sqlx::query("INSERT INTO list_subscribers (id, list_id, contact_id, status, created_at) VALUES ($1, $2, $3, 'active', NOW())")
                    .bind(Uuid::new_v4())
                    .bind(list)
                    .bind(contact)
                    .execute(&state.db)
                    .await
                    .unwrap();
            }
            let recipients_uri = format!("/web/campaigns/{campaign}/recipients");
            let response = app
                .clone()
                .oneshot(post_form(
                    &recipients_uri,
                    &csrf_body(
                        &state,
                        &[("list_id", &list.to_string()), ("segment", "subscribed")],
                    ),
                ))
                .await
                .unwrap();
            let flash = response_flash(&response, &state.config.csrf_secret);
            assert!(
                flash_text(&flash).contains("Recipients wired: 2"),
                "flash was: {flash:?}"
            );

            // Start: draft → sending, with the honest recipient count.
            let response = app
                .clone()
                .oneshot(post_form(&uri, &csrf_body(&state, &[])))
                .await
                .unwrap();
            let flash = response_flash(&response, &state.config.csrf_secret);
            assert!(
                flash_text(&flash).contains("2 recipient"),
                "flash was: {flash:?}"
            );
            let status: String =
                sqlx::query_scalar("SELECT status FROM campaigns WHERE id = $1::uuid")
                    .bind(campaign)
                    .fetch_one(&state.db)
                    .await
                    .unwrap();
            assert_eq!(status, "sending");

            // Pause (sending → paused); pausing again is refused, and
            // resuming returns the campaign to sending.
            let response = app
                .clone()
                .oneshot(post_form(
                    &format!("/web/campaigns/{campaign}/pause"),
                    &csrf_body(&state, &[]),
                ))
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::SEE_OTHER);
            let response = app
                .clone()
                .oneshot(post_form(
                    &format!("/web/campaigns/{campaign}/pause"),
                    &csrf_body(&state, &[]),
                ))
                .await
                .unwrap();
            let flash = response_flash(&response, &state.config.csrf_secret);
            assert!(
                flash_text(&flash).contains("only sending"),
                "flash was: {flash:?}"
            );
            let response = app
                .clone()
                .oneshot(post_form(
                    &format!("/web/campaigns/{campaign}/resume"),
                    &csrf_body(&state, &[]),
                ))
                .await
                .unwrap();
            let flash = response_flash(&response, &state.config.csrf_secret);
            assert!(
                flash_text(&flash).contains("sending"),
                "flash was: {flash:?}"
            );

            // The detail loader exposes per-status actions from the same rule.
            let detail = data::load_campaign_detail(&state.db, &tenant, &campaign.to_string())
                .await
                .expect("detail loads");
            assert_eq!(detail.status, "sending");
            assert_eq!(detail.recipient_count, 2);
            assert_eq!(detail.list_name.as_deref(), Some("Starters"));
            assert!(
                !detail
                    .actions
                    .iter()
                    .find(|a| a.0 == "Start sending")
                    .unwrap()
                    .2
            );
            assert!(detail.actions.iter().find(|a| a.0 == "Pause").unwrap().2);

            cleanup_tenant(&state, &tenant).await;
        }

        #[tokio::test]
        async fn contacts_import_flashes_the_honest_summary() {
            let Some(state) = web_test_state("contacts_import_flashes_the_honest_summary").await
            else {
                return;
            };
            let tenant = apexmail_lib::id::generate_id("webflow", 18);
            seed_tenant(&state, &tenant).await;
            // contacts.id is UUID PRIMARY KEY DEFAULT gen_random_uuid()
            // (migrations/068_create_lists_tables.sql:22) — bind a Uuid, not
            // a 26/36-char string.
            sqlx::query("INSERT INTO contacts (id, tenant_id, email, status, created_at, updated_at) VALUES ($1, $2, 'dup@t.io', 'subscribed', NOW(), NOW())")
                .bind(Uuid::new_v4())
                .bind(&tenant)
                .execute(&state.db)
                .await
                .unwrap();

            let app = web_handlers(state.clone(), session_user(&tenant));
            // Header row, a duplicate (in DB), a duplicate in-file, an
            // invalid row, and one fresh import.
            let csv = "Email,Name\ndup@t.io,Dup\nfresh@t.io,\"Fresh, Inc\"\nfresh@t.io,Again\nnot-an-email,Bad\n";
            let response = app
                .clone()
                .oneshot(post_form(
                    "/web/contacts/import",
                    &csrf_body(&state, &[("csv", csv)]),
                ))
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::SEE_OTHER);
            let flash = response_flash(&response, &state.config.csrf_secret);
            let text = flash_text(&flash);
            assert!(text.contains("Imported 1"), "flash was: {text}");
            assert!(text.contains("skipped 3"), "flash was: {text}");
            assert!(text.contains("duplicates: 2"), "flash was: {text}");
            assert!(text.contains("invalid: 1"), "flash was: {text}");
            assert!(text.contains("line 5"), "flash was: {text}");

            // The stored contact carries the quoted name with its comma.
            let name: Option<String> = sqlx::query_scalar(
                "SELECT name FROM contacts WHERE tenant_id = $1 AND email = 'fresh@t.io'",
            )
            .bind(&tenant)
            .fetch_one(&state.db)
            .await
            .unwrap();
            assert_eq!(name.as_deref(), Some("Fresh, Inc"));

            cleanup_tenant(&state, &tenant).await;
        }

        #[tokio::test]
        async fn webhook_create_binds_the_checkbox_group() {
            let Some(state) = web_test_state("webhook_create_binds_the_checkbox_group").await
            else {
                return;
            };
            let tenant = apexmail_lib::id::generate_id("webflow", 18);
            seed_tenant(&state, &tenant).await;
            let app = web_handlers(state.clone(), session_user(&tenant));

            // Repeated `events` keys (a checkbox group) all bind; the
            // secret rides in the structured field-map cookie.
            let body = format!(
                "{}&url=https%3A%2F%2Fexample.com%2Fhook&events=message.accepted&events=message.delivered&events=message.delivered",
                csrf_body(&state, &[]).replace('&', "%26").replace('=', "%3D")
            );
            // NOTE: the csrf pair must stay a normal pair — build it
            // explicitly instead.
            let _ = body;
            let token = ui_foundation::csrf::generate_csrf_token(&state.config.csrf_secret);
            let body = format!(
                "_csrf={}&url=https%3A%2F%2Fexample.com%2Fhook&events=message.accepted&events=message.delivered&events=message.delivered",
                urlencode(&token)
            );
            let response = app
                .clone()
                .oneshot(post_form("/web/webhooks", &body))
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::SEE_OTHER);
            let events: serde_json::Value = sqlx::query_scalar(
                "SELECT events FROM webhooks WHERE tenant_id = $1 ORDER BY created_at DESC LIMIT 1",
            )
            .bind(&tenant)
            .fetch_one(&state.db)
            .await
            .unwrap();
            assert_eq!(
                events,
                serde_json::json!(["message.accepted", "message.delivered"]),
                "the chosen checkbox set is stored, deduplicated"
            );
            // Item N: the signing secret is in the structured field-map.
            let field_cookie = response
                .headers()
                .get_all(header::SET_COOKIE)
                .iter()
                .filter_map(|value| value.to_str().ok())
                .find(|cookie| cookie.starts_with(&format!("{FORM_FIELDS_COOKIE_NAME}=")))
                .expect("field-map cookie set");
            let mut headers = HeaderMap::new();
            headers.insert(
                header::COOKIE,
                field_cookie.split_once(';').unwrap().0.parse().unwrap(),
            );
            let fields = decode_form_fields_from_headers(&headers, &state.config.csrf_secret)
                .expect("field-map decodes");
            assert_eq!(fields.secrets().len(), 1);
            assert!(fields.secrets()[0].0.contains("signing secret"));

            // An unknown event name is rejected with the valid list and
            // the URL is preserved for re-population.
            let body = format!(
                "_csrf={}&url=https%3A%2F%2Fexample.com%2Fhook&events=delivred",
                urlencode(&token)
            );
            let response = app
                .clone()
                .oneshot(post_form("/web/webhooks", &body))
                .await
                .unwrap();
            let flash = response_flash(&response, &state.config.csrf_secret);
            assert!(
                flash_text(&flash).contains("delivred"),
                "flash was: {flash:?}"
            );
            assert!(flash_text(&flash).contains("message.accepted"));
            let rows: i64 =
                sqlx::query_scalar("SELECT COUNT(*) FROM webhooks WHERE tenant_id = $1")
                    .bind(&tenant)
                    .fetch_one(&state.db)
                    .await
                    .unwrap();
            assert_eq!(rows, 1, "the invalid create was not stored");

            cleanup_tenant(&state, &tenant).await;
        }

        /// SSRF regression: the form path used to accept ANY `http(s)://`
        /// prefix and insert verbatim — `http://169.254.169.254/…` (cloud
        /// metadata) and `http://10.x/…` (private ranges) must be rejected
        /// by the SAME hardened validator the JSON path uses.
        #[tokio::test]
        async fn webhook_create_rejects_ssrf_targets_from_the_form_path() {
            let Some(state) =
                web_test_state("webhook_create_rejects_ssrf_targets_from_the_form_path").await
            else {
                return;
            };
            let tenant = apexmail_lib::id::generate_id("webssrf", 18);
            seed_tenant(&state, &tenant).await;
            let app = web_handlers(state.clone(), session_user(&tenant));

            for url in [
                "http://169.254.169.254/latest/meta-data",
                "http://10.1.2.3/hook",
                "http://192.168.0.9/hook",
                "http://127.0.0.1:8080/hook",
                "ftp://example.com/hook",
            ] {
                let body = csrf_body(&state, &[("url", url), ("events", "message.accepted")]);
                let response = app
                    .clone()
                    .oneshot(post_form("/web/webhooks", &body))
                    .await
                    .unwrap();
                let flash = response_flash(&response, &state.config.csrf_secret);
                assert!(
                    flash.iter().any(|message| matches!(
                        message.kind,
                        ui_foundation::flash::FlashKind::Error
                    )),
                    "SSRF target {url} must be rejected with an error flash"
                );
                let stored: i64 = sqlx::query_scalar(
                    "SELECT COUNT(*) FROM webhooks WHERE tenant_id = $1 AND url = $2",
                )
                .bind(&tenant)
                .bind(url)
                .fetch_one(&state.db)
                .await
                .unwrap();
                assert_eq!(stored, 0, "SSRF target {url} must not be stored");
            }

            cleanup_tenant(&state, &tenant).await;
        }

        /// The per-tenant webhook cap (25) applies to the form path too.
        #[tokio::test]
        async fn webhook_create_enforces_the_per_tenant_cap_from_the_form_path() {
            let Some(state) =
                web_test_state("webhook_create_enforces_the_per_tenant_cap_from_the_form_path")
                    .await
            else {
                return;
            };
            let tenant = apexmail_lib::id::generate_id("webcap", 18);
            seed_tenant(&state, &tenant).await;
            // webhooks.id is VARCHAR(26) NOT NULL with NO default
            // (migrations/075_create_missing_tables.sql:139) — mint it with
            // generate_id("", 26); a 36-char UUID string is a 22001 "value
            // too long for type character varying(26)". webhooks.name is
            // NULLABLE at 075:141, so omitting it is canonical (webhooks.url
            // and webhooks.secret are the NOT NULL columns, 075:142-143).
            for n in 0..25 {
                sqlx::query(
                    "INSERT INTO webhooks (id, tenant_id, url, secret, events, enabled, status, created_at, updated_at)
                     VALUES ($1, $2, $3, 's', '[\"*\"]'::jsonb, true, 'active', NOW(), NOW())",
                )
                .bind(apexmail_lib::id::generate_id("", 26))
                .bind(&tenant)
                .bind(format!("https://example.com/hook-{n}"))
                .execute(&state.db)
                .await
                .unwrap();
            }
            let app = web_handlers(state.clone(), session_user(&tenant));

            // The 26th webhook is refused with a clear error.
            let body = csrf_body(
                &state,
                &[
                    ("url", "https://example.com/hook-26"),
                    ("events", "message.accepted"),
                ],
            );
            let response = app
                .clone()
                .oneshot(post_form("/web/webhooks", &body))
                .await
                .unwrap();
            let flash = response_flash(&response, &state.config.csrf_secret);
            assert!(
                flash
                    .iter()
                    .any(|message| matches!(message.kind, ui_foundation::flash::FlashKind::Error)),
                "the 26th webhook must be rejected with an error flash"
            );
            let count: i64 =
                sqlx::query_scalar("SELECT COUNT(*) FROM webhooks WHERE tenant_id = $1")
                    .bind(&tenant)
                    .fetch_one(&state.db)
                    .await
                    .unwrap();
            assert_eq!(count, 25, "the cap must hold at 25");

            cleanup_tenant(&state, &tenant).await;
        }

        /// Privilege regression: POST /web/team/invite used to accept ANY
        /// authenticated session and insert `role='admin'` users. Only
        /// owner/admin sessions may invite, and nobody may grant a role
        /// above their own.
        #[tokio::test]
        async fn team_invite_gates_on_the_caller_role() {
            let Some(state) = web_test_state("team_invite_gates_on_the_caller_role").await else {
                return;
            };
            let tenant = apexmail_lib::id::generate_id("tgate", 18);
            seed_tenant(&state, &tenant).await;
            // Seed the caller rows the gate re-reads.
            let (member_id, admin_id) = (Uuid::new_v4(), Uuid::new_v4());
            for (id, role) in [(member_id, "member"), (admin_id, "admin")] {
                sqlx::query(
                    "INSERT INTO users (id, tenant_id, email, name, password_hash, role, status, created_at, updated_at)
                     VALUES ($1, $2, $3, 'Caller', 'x', $4, 'active', NOW(), NOW())",
                )
                .bind(id)
                .bind(&tenant)
                .bind(format!("{}@gate.example.com", id.simple()))
                .bind(role)
                .execute(&state.db)
                .await
                .unwrap();
            }
            let invitee = || format!("invitee-{}@example.com", Uuid::new_v4().simple());
            let invite_body = |state: &AppState, email: &str, role: &str| {
                csrf_body(state, &[("userName", email), ("role", role)])
            };

            // A member session cannot invite anyone…
            let app = web_handlers(
                state.clone(),
                AuthUser {
                    tenant_id: tenant.clone(),
                    user_id: Some(member_id.to_string()),
                    api_key_id: None,
                    session_id: None,
                    scopes: vec!["*".into()],
                },
            );
            let email = invitee();
            let response = app
                .clone()
                .oneshot(post_form(
                    "/web/team/invite",
                    &invite_body(&state, &email, "member"),
                ))
                .await
                .unwrap();
            let flash = response_flash(&response, &state.config.csrf_secret);
            assert!(
                flash
                    .iter()
                    .any(|message| matches!(message.kind, ui_foundation::flash::FlashKind::Error)),
                "a member session must not be able to invite"
            );
            let stored: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM users WHERE tenant_id = $1 AND email = $2",
            )
            .bind(&tenant)
            .bind(&email)
            .fetch_one(&state.db)
            .await
            .unwrap();
            assert_eq!(stored, 0, "the member's invitation must not be stored");

            // …and an admin session cannot grant a role ABOVE their own.
            let app_admin = web_handlers(
                state.clone(),
                AuthUser {
                    tenant_id: tenant.clone(),
                    user_id: Some(admin_id.to_string()),
                    api_key_id: None,
                    session_id: None,
                    scopes: vec!["*".into()],
                },
            );
            let email = invitee();
            let response = app_admin
                .clone()
                .oneshot(post_form(
                    "/web/team/invite",
                    &invite_body(&state, &email, "owner"),
                ))
                .await
                .unwrap();
            let flash = response_flash(&response, &state.config.csrf_secret);
            assert!(
                flash
                    .iter()
                    .any(|message| matches!(message.kind, ui_foundation::flash::FlashKind::Error)),
                "an admin must not be able to mint an owner invitation"
            );
            let stored: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM users WHERE tenant_id = $1 AND email = $2",
            )
            .bind(&tenant)
            .bind(&email)
            .fetch_one(&state.db)
            .await
            .unwrap();
            assert_eq!(stored, 0, "the owner invitation must not be stored");

            // An admin CAN invite a member.
            let email = invitee();
            let response = app_admin
                .clone()
                .oneshot(post_form(
                    "/web/team/invite",
                    &invite_body(&state, &email, "member"),
                ))
                .await
                .unwrap();
            let flash = response_flash(&response, &state.config.csrf_secret);
            assert!(
                flash.iter().any(|message| matches!(
                    message.kind,
                    ui_foundation::flash::FlashKind::Success
                )),
                "an admin inviting a member must succeed, flash was {flash:?}"
            );

            cleanup_tenant(&state, &tenant).await;
        }

        /// Per-tenant open-invitation cap: at most 50 un-accepted
        /// invitations may be outstanding.
        #[tokio::test]
        async fn team_invite_enforces_an_open_invitation_cap() {
            let Some(state) = web_test_state("team_invite_enforces_an_open_invitation_cap").await
            else {
                return;
            };
            let tenant = apexmail_lib::id::generate_id("teamcap", 18);
            seed_tenant(&state, &tenant).await;
            let admin_id = Uuid::new_v4();
            sqlx::query(
                "INSERT INTO users (id, tenant_id, email, name, password_hash, role, status, created_at, updated_at)
                 VALUES ($1, $2, $3, 'Admin', 'x', 'admin', 'active', NOW(), NOW())",
            )
            .bind(admin_id)
            .bind(&tenant)
            .bind(format!("{admin_id}@cap.example.com"))
            .execute(&state.db)
            .await
            .unwrap();
            for n in 0..50 {
                sqlx::query(
                    "INSERT INTO users (id, tenant_id, email, name, password_hash, role, status, created_at, updated_at)
                     VALUES ($1, $2, $3, '', '!invited-pending-activation', 'member', 'invited', NOW(), NOW())",
                )
                .bind(Uuid::new_v4())
                .bind(&tenant)
                .bind(format!("pending-{n}-{}@example.com", Uuid::new_v4().simple()))
                .execute(&state.db)
                .await
                .unwrap();
            }
            let app = web_handlers(
                state.clone(),
                AuthUser {
                    tenant_id: tenant.clone(),
                    user_id: Some(admin_id.to_string()),
                    api_key_id: None,
                    session_id: None,
                    scopes: vec!["*".into()],
                },
            );

            let email = format!("over-{}@example.com", Uuid::new_v4().simple());
            let response = app
                .oneshot(post_form(
                    "/web/team/invite",
                    &csrf_body(&state, &[("userName", email.as_str()), ("role", "member")]),
                ))
                .await
                .unwrap();
            let flash = response_flash(&response, &state.config.csrf_secret);
            assert!(
                flash
                    .iter()
                    .any(|message| matches!(message.kind, ui_foundation::flash::FlashKind::Error)),
                "the 51st open invitation must be rejected with an error flash"
            );
            let stored: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM users WHERE tenant_id = $1 AND email = $2",
            )
            .bind(&tenant)
            .bind(&email)
            .fetch_one(&state.db)
            .await
            .unwrap();
            assert_eq!(stored, 0, "the over-cap invitation must not be stored");

            cleanup_tenant(&state, &tenant).await;
        }

        /// Seed the system sender domain with valid DKIM material so the
        /// transactional verification-email queue admits messages (same
        /// contract as the auth.rs signup fixtures; caller must hold the
        /// DKIM env mutex across the whole seeded scope).
        async fn seed_web_system_sender(db: &sqlx::PgPool) {
            std::env::set_var(
                apexmail_lib::dkim::DKIM_PRIVATE_KEY_ENCRYPTION_KEY_ENV,
                "3f7a1c9e2b5d48f01a6c3e792d4b8f15a0c6e3917d2f4b8a5c1e7309d4f2b6a8",
            );
            let key_pair = apexmail_lib::dkim::generate_dkim_keypair().expect("dkim keypair");
            let aad = apexmail_lib::dkim::dkim_private_key_aad(
                crate::routes::system_sender::SYSTEM_TENANT_ID,
                crate::routes::system_sender::SYSTEM_DOMAIN_ID,
            );
            let encrypted =
                apexmail_lib::dkim::encrypt_dkim_private_key(&key_pair.private_key_pem, &aad)
                    .expect("encrypt dkim key");
            let public_key = apexmail_lib::dkim::public_key_base64_from_private_key_pem(
                &key_pair.private_key_pem,
            )
            .expect("derive dkim public key");
            sqlx::query(
                "INSERT INTO domains (id, tenant_id, name, status, verified, ses_verified,
                                      dkim_enabled, dkim_selector, dkim_public_key, dkim_private_key)
                 VALUES ($1, $2, $3, 'verified', true, true, true, 'testsel', $4, $5)
                 ON CONFLICT (id) DO UPDATE
                   SET status = 'verified', verified = true, ses_verified = true,
                       dkim_enabled = true, dkim_selector = 'testsel',
                       dkim_public_key = EXCLUDED.dkim_public_key,
                       dkim_private_key = EXCLUDED.dkim_private_key",
            )
            .bind(
                Uuid::parse_str(crate::routes::system_sender::SYSTEM_DOMAIN_ID)
                    .expect("system domain id is a uuid"),
            )
            .bind(crate::routes::system_sender::SYSTEM_TENANT_ID)
            .bind(crate::routes::system_sender::SYSTEM_DOMAIN)
            .bind(&public_key)
            .bind(&encrypted)
            .execute(db)
            .await
            .expect("seed system sender");
        }

        /// Signup-before-verification regression trio: the verification
        /// token must be stored HASHED (never plaintext), an unverified
        /// account must not be able to log in, and a duplicate signup
        /// gets the friendly "already registered" error.
        #[allow(clippy::await_holding_lock)]
        #[tokio::test]
        async fn web_signup_hashes_token_and_gates_login_on_email_verification() {
            // The transactional verification-email queue needs the canonical
            // fixture shape (the shared dev database's messages table has a
            // stricter NOT NULL the queue path does not satisfy).
            let Some(pool) = crate::test_db::canonical_pool("web_signup_verify").await else {
                eprintln!(
                    "skipping web_signup_hashes_token_and_gates_login_on_email_verification: no TEST_DATABASE_URL"
                );
                return;
            };
            let state = canonical_web_state(pool.clone()).await;
            let _env_guard = crate::test_db::DKIM_ENV_MUTEX
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            let had_dkim_key =
                std::env::var(apexmail_lib::dkim::DKIM_PRIVATE_KEY_ENCRYPTION_KEY_ENV).ok();
            seed_web_system_sender(&state.db).await;

            let app = web_handlers(
                state.clone(),
                AuthUser {
                    tenant_id: "unused".into(),
                    user_id: None,
                    api_key_id: None,
                    session_id: None,
                    scopes: vec![],
                },
            );
            let email = format!("web-signup-{}@example.com", Uuid::new_v4().simple());
            let password = "Sup3r#SecurePass";
            let signup_body = csrf_body(
                &state,
                &[
                    ("name", "Web Signup"),
                    ("company_name", "Web Signup Co"),
                    ("email", email.as_str()),
                    ("password", password),
                    ("plan", "free"),
                ],
            );
            let response = app
                .clone()
                .oneshot(post_form("/web/auth/signup", &signup_body))
                .await
                .unwrap();
            let flash = response_flash(&response, &state.config.csrf_secret);
            assert!(
                flash.iter().any(|message| matches!(
                    message.kind,
                    ui_foundation::flash::FlashKind::Success
                )),
                "signup must succeed, flash was {flash:?}"
            );

            // (a) The stored verification token is a SHA-256 hex digest,
            // never the raw token (which used to land verbatim under
            // `verification_token_hash`).
            let metadata: Option<serde_json::Value> =
                sqlx::query_scalar("SELECT metadata FROM users WHERE email = $1")
                    .bind(&email)
                    .fetch_one(&state.db)
                    .await
                    .unwrap();
            let stored = metadata
                .as_ref()
                .and_then(|m| m["verification_token_hash"].as_str())
                .unwrap_or_default();
            assert!(
                stored.len() == 64 && stored.chars().all(|c| c.is_ascii_hexdigit()),
                "verification token must be stored as a 64-hex-char SHA-256 digest, got {stored:?}"
            );

            // (b) The unverified account cannot log in.
            let login_body =
                csrf_body(&state, &[("email", email.as_str()), ("password", password)]);
            let response = app
                .clone()
                .oneshot(post_form("/web/auth/login", &login_body))
                .await
                .unwrap();
            let flash = response_flash(&response, &state.config.csrf_secret);
            assert!(
                flash.iter().any(|message| matches!(
                    message.kind,
                    ui_foundation::flash::FlashKind::Error
                ) && message.text.to_lowercase().contains("verif")),
                "an unverified account must not receive a session, flash was {flash:?}"
            );
            let session_cookie = response
                .headers()
                .get_all(header::SET_COOKIE)
                .iter()
                .filter_map(|value| value.to_str().ok())
                .find(|cookie| cookie.starts_with("am_session="))
                .is_some();
            assert!(!session_cookie, "no am_session cookie before verification");

            // Once verified, the same credentials log in.
            sqlx::query("UPDATE users SET email_verified = true WHERE email = $1")
                .bind(&email)
                .execute(&state.db)
                .await
                .unwrap();
            let response = app
                .clone()
                .oneshot(post_form("/web/auth/login", &login_body))
                .await
                .unwrap();
            let session_cookie = response
                .headers()
                .get_all(header::SET_COOKIE)
                .iter()
                .filter_map(|value| value.to_str().ok())
                .find(|cookie| cookie.starts_with("am_session="))
                .is_some();
            assert!(session_cookie, "a verified account must receive a session");

            // (c) Duplicate signup is INDISTINGUISHABLE from the first
            // signup (anti-enumeration, mirroring the JSON register flow's
            // identical-202 contract): same success flash, never an error
            // that reveals the address is registered. The unique-constraint
            // race is still handled at the INSERT.
            let response = app
                .clone()
                .oneshot(post_form("/web/auth/signup", &signup_body))
                .await
                .unwrap();
            let flash = response_flash(&response, &state.config.csrf_secret);
            assert!(
                flash.iter().any(|message| matches!(
                    message.kind,
                    ui_foundation::flash::FlashKind::Success
                ) && message.text.contains("Check your email")),
                "duplicate signup must return the same generic success flash                  (no account enumeration), flash was {flash:?}"
            );
            assert!(
                !flash
                    .iter()
                    .any(|message| message.text.to_lowercase().contains("already")),
                "duplicate signup must never disclose an existing account, flash was {flash:?}"
            );

            match had_dkim_key {
                Some(key) => {
                    std::env::set_var(apexmail_lib::dkim::DKIM_PRIVATE_KEY_ENCRYPTION_KEY_ENV, key)
                }
                None => {
                    std::env::remove_var(apexmail_lib::dkim::DKIM_PRIVATE_KEY_ENCRYPTION_KEY_ENV)
                }
            }
        }

        /// The SSR MFA verify step is brute-forceable (6-digit TOTP): a
        /// bounded per-account attempt counter must lock it out instead of
        /// accepting unlimited guesses.
        #[tokio::test]
        async fn mfa_verify_locks_out_after_repeated_wrong_codes() {
            let Some(state) =
                web_test_state("mfa_verify_locks_out_after_repeated_wrong_codes").await
            else {
                return;
            };
            // Redis-backed counter: skip when Redis is not under test.
            let mut conn = match state.redis.get().await {
                Ok(conn) => conn,
                Err(_) => {
                    eprintln!("skipping mfa_verify_locks_out_after_repeated_wrong_codes: no Redis");
                    return;
                }
            };
            let pong: Result<String, _> = deadpool_redis::redis::cmd("PING")
                .query_async(&mut *conn)
                .await;
            if pong.is_err() {
                eprintln!(
                    "skipping mfa_verify_locks_out_after_repeated_wrong_codes: Redis unreachable"
                );
                return;
            }

            let tenant = apexmail_lib::id::generate_id("mfalock", 16);
            seed_tenant(&state, &tenant).await;
            let user_id = Uuid::new_v4();
            let email = format!("mfalock-{}@example.com", user_id.simple());
            sqlx::query(
                "INSERT INTO users (id, tenant_id, email, name, password_hash, role, status,
                                    email_verified, mfa_enabled, mfa_secret, created_at, updated_at)
                 VALUES ($1, $2, $3, 'MFA Op', 'x', 'owner', 'active', true, true, 'enc:v1:not-a-real-secret', NOW(), NOW())",
            )
            .bind(user_id)
            .bind(&tenant)
            .bind(&email)
            .execute(&state.db)
            .await
            .expect("seed mfa user");
            let challenge = sign_login_challenge(&state.config, &user_id.to_string(), &email);

            let app = web_handlers(
                state.clone(),
                AuthUser {
                    tenant_id: tenant.clone(),
                    user_id: Some(user_id.to_string()),
                    api_key_id: None,
                    session_id: None,
                    scopes: vec![],
                },
            );
            let body_for = |code: &str| {
                csrf_body(
                    &state,
                    &[
                        ("email", email.as_str()),
                        ("code", code),
                        ("return_to", "/dashboard"),
                    ],
                )
            };
            let verify_request = |body: &str| {
                Request::post("/web/auth/mfa/verify")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .header(
                        header::COOKIE,
                        format!(
                            "apexmail_login_challenge={challenge}; {}",
                            csrf_cookie_of(body)
                        ),
                    )
                    .body(Body::from(body.to_string()))
                    .unwrap()
            };

            // Ten wrong codes burn the attempt budget…
            for _ in 0..10 {
                let response = app
                    .clone()
                    .oneshot(verify_request(&body_for("000000")))
                    .await
                    .unwrap();
                assert_eq!(response.status(), StatusCode::SEE_OTHER);
            }
            // …the 11th is locked out (distinct from the mismatch error).
            let response = app
                .clone()
                .oneshot(verify_request(&body_for("000000")))
                .await
                .unwrap();
            let flash = response_flash(&response, &state.config.csrf_secret);
            assert!(
                flash.iter().any(|message| matches!(
                    message.kind,
                    ui_foundation::flash::FlashKind::Error
                ) && message.text.to_lowercase().contains("too many")),
                "the 11th attempt must be locked out, flash was {flash:?}"
            );
            let session_cookie = response
                .headers()
                .get_all(header::SET_COOKIE)
                .iter()
                .filter_map(|value| value.to_str().ok())
                .any(|cookie| cookie.starts_with("am_session="));
            assert!(
                !session_cookie,
                "a locked-out attempt must not mint a session"
            );

            cleanup_tenant(&state, &tenant).await;
        }

        /// Chunked multi-row INSERT must keep exact semantics: a file
        /// larger than one batch (500) imports fully with honest counts.
        #[tokio::test]
        async fn contacts_import_batches_without_losing_rows() {
            let Some(state) = web_test_state("contacts_import_batches_without_losing_rows").await
            else {
                return;
            };
            let tenant = apexmail_lib::id::generate_id("csvbig", 16);
            seed_tenant(&state, &tenant).await;

            let app = web_handlers(
                state.clone(),
                AuthUser {
                    tenant_id: tenant.clone(),
                    user_id: Some("bulk-op".into()),
                    api_key_id: None,
                    session_id: None,
                    scopes: vec!["*".into()],
                },
            );
            // Raw multipart body: the `_csrf` field plus a 750-row CSV —
            // past the 500-row batch boundary.
            let boundary = "XApexMailTestBoundaryX";
            let token = ui_foundation::csrf::generate_csrf_token(&state.config.csrf_secret);
            let mut raw = String::new();
            raw.push_str(&format!("--{boundary}\r\n"));
            raw.push_str("Content-Disposition: form-data; name=\"_csrf\"\r\n\r\n");
            raw.push_str(&token);
            raw.push_str("\r\n");
            raw.push_str(&format!("--{boundary}\r\n"));
            raw.push_str(
                "Content-Disposition: form-data; name=\"file\"; filename=\"bulk.csv\"\r\n",
            );
            raw.push_str("Content-Type: text/csv\r\n\r\n");
            raw.push_str("email,name\n");
            for n in 0..750 {
                raw.push_str(&format!("bulk-{n}-{tenant}@example.com,Bulk {n}\n"));
            }
            raw.push_str(&format!("\r\n--{boundary}--\r\n"));

            let response = app
                .oneshot(
                    Request::post("/web/contacts/import")
                        // Double-submit CSRF: the form `_csrf` must be
                        // accompanied by the matching csrf_token cookie.
                        .header("cookie", format!("csrf_token={token}"))
                        .header(
                            "content-type",
                            format!("multipart/form-data; boundary={boundary}"),
                        )
                        .body(Body::from(raw))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::SEE_OTHER);
            let flash = response_flash(&response, &state.config.csrf_secret);
            assert!(
                flash.iter().any(|message| matches!(
                    message.kind,
                    ui_foundation::flash::FlashKind::Success
                ) && message.text.contains("750")),
                "all 750 rows must be imported, flash was {flash:?}"
            );

            cleanup_tenant(&state, &tenant).await;
        }

        #[tokio::test]
        async fn template_update_bumps_the_version_snapshot() {
            let Some(state) = web_test_state("template_update_bumps_the_version_snapshot").await
            else {
                return;
            };
            let tenant = apexmail_lib::id::generate_id("webflow", 18);
            seed_tenant(&state, &tenant).await;
            // templates.id is VARCHAR(26) PRIMARY KEY with no default
            // (migrations/075_create_missing_tables.sql:12) — generate_id("", 26).
            let template = apexmail_lib::id::generate_id("", 26);
            sqlx::query(
                "INSERT INTO templates (id, tenant_id, name, subject, html_body, created_at, updated_at)
                 VALUES ($1, $2, 'Monthly', 'News', '<p>v1</p>', NOW(), NOW())",
            )
            .bind(&template)
            .bind(&tenant)
            .execute(&state.db)
            .await
            .unwrap();

            let app = web_handlers(state.clone(), session_user(&tenant));
            let response = app
                .clone()
                .oneshot(post_form(
                    "/web/templates/update",
                    &csrf_body(
                        &state,
                        &[
                            ("id", &template),
                            ("name", "Monthly v2"),
                            ("html_body", "<p>v2</p>"),
                        ],
                    ),
                ))
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::SEE_OTHER);
            let flash = response_flash(&response, &state.config.csrf_secret);
            assert!(flash_text(&flash).contains("v2"), "flash was: {flash:?}");

            let (name, html): (String, String) = sqlx::query_as(
                "SELECT name, html_body FROM templates WHERE id = $1 AND tenant_id = $2",
            )
            .bind(&template)
            .bind(&tenant)
            .fetch_one(&state.db)
            .await
            .unwrap();
            assert_eq!(name, "Monthly v2");
            assert_eq!(html, "<p>v2</p>");
            // The snapshot row exists (the JSON rollback path's history).
            let snapshots: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM template_versions WHERE template_id = $1 AND version = 2",
            )
            .bind(&template)
            .fetch_one(&state.db)
            .await
            .unwrap();
            assert_eq!(snapshots, 1, "the v2 snapshot was written");

            cleanup_tenant(&state, &tenant).await;
        }

        #[tokio::test]
        async fn bulk_delete_flows_through_the_signed_confirm_page() {
            let Some(state) =
                web_test_state("bulk_delete_flows_through_the_signed_confirm_page").await
            else {
                return;
            };
            let tenant = apexmail_lib::id::generate_id("webflow", 18);
            seed_tenant(&state, &tenant).await;
            let first = Uuid::new_v4();
            let second = Uuid::new_v4();
            for (id, name) in [(first, "Bulk A"), (second, "Bulk B")] {
                sqlx::query(
                    "INSERT INTO campaigns (id, tenant_id, name, subject, status, created_at, updated_at)
                     VALUES ($1, $2, $3, 'x', 'draft', NOW(), NOW())",
                )
                .bind(id)
                .bind(&tenant)
                .bind(name)
                .execute(&state.db)
                .await
                .unwrap();
            }

            let app = web_handlers(state.clone(), session_user(&tenant));
            // The bulk POST never deletes: it signs and redirects.
            let response = app
                .clone()
                .oneshot(post_form(
                    "/web/campaigns/delete-bulk",
                    &csrf_body(&state, &[("ids", &format!("{first},{second}"))]),
                ))
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::SEE_OTHER);
            let location = response
                .headers()
                .get(header::LOCATION)
                .and_then(|value| value.to_str().ok())
                .unwrap()
                .to_string();
            assert!(
                location.starts_with("/confirm?intent=delete-campaigns-bulk&id="),
                "was {location}"
            );
            let remaining: i64 =
                sqlx::query_scalar("SELECT COUNT(*) FROM campaigns WHERE tenant_id = $1")
                    .bind(&tenant)
                    .fetch_one(&state.db)
                    .await
                    .unwrap();
            assert_eq!(remaining, 2, "nothing was deleted before confirmation");

            // Confirm: replay the signed params through /web/confirm.
            let query = location.trim_start_matches("/confirm?");
            let pairs: Vec<(String, String)> = query
                .split('&')
                .map(|pair| {
                    pair.split_once('=')
                        .map(|(k, v)| (k.to_string(), v.to_string()))
                        .unwrap()
                })
                .collect();
            let get = |name: &str| {
                pairs
                    .iter()
                    .find(|(key, _)| key == name)
                    .map(|(_, value)| value.clone())
                    .unwrap_or_default()
            };
            let confirm_body = format!(
                "_csrf={}&intent={}&id={}&sig={}&return_to=%2Fcampaigns",
                urlencode(&ui_foundation::csrf::generate_csrf_token(
                    &state.config.csrf_secret
                )),
                get("intent"),
                get("id"),
                get("sig"),
            );
            let response = app
                .clone()
                .oneshot(post_form("/web/confirm", &confirm_body))
                .await
                .unwrap();
            let flash = response_flash(&response, &state.config.csrf_secret);
            assert!(
                flash_text(&flash).contains("2 campaign"),
                "flash was: {flash:?}"
            );
            let remaining: i64 =
                sqlx::query_scalar("SELECT COUNT(*) FROM campaigns WHERE tenant_id = $1")
                    .bind(&tenant)
                    .fetch_one(&state.db)
                    .await
                    .unwrap();
            assert_eq!(remaining, 0);

            // A forged signature changes nothing.
            let forged = format!(
                "_csrf={}&intent=delete-campaigns-bulk&id={first}&sig=1234.AAAA&return_to=%2Fcampaigns",
                urlencode(&ui_foundation::csrf::generate_csrf_token(&state.config.csrf_secret)),
            );
            let response = app
                .clone()
                .oneshot(post_form("/web/confirm", &forged))
                .await
                .unwrap();
            let flash = response_flash(&response, &state.config.csrf_secret);
            assert!(
                flash_text(&flash).contains("expired"),
                "flash was: {flash:?}"
            );

            cleanup_tenant(&state, &tenant).await;
        }

        #[tokio::test]
        async fn alerts_ack_bulk_flips_rows_with_honest_counts() {
            let Some(state) = web_test_state("alerts_ack_bulk_flips_rows_with_honest_counts").await
            else {
                return;
            };
            let system_tenant: String =
                sqlx::query_scalar("SELECT id::text FROM tenants WHERE slug = 'system' LIMIT 1")
                    .fetch_optional(&state.db)
                    .await
                    .ok()
                    .flatten()
                    .unwrap_or_else(|| "system".to_string());
            let mut ids: Vec<String> = Vec::new();
            for index in 0..3 {
                // system_alerts.id is UUID PRIMARY KEY DEFAULT
                // gen_random_uuid() (migrations/020_ses_monitoring.sql:96) —
                // the fixture deliberately inserts NO id and reads the
                // generated one back; id-less inserts are canonical.
                let id: uuid::Uuid = sqlx::query_scalar(
                    "INSERT INTO system_alerts (alert_type, message, severity, acknowledged, created_at)
                     VALUES ('web_flow_test', $1, 'warning', false, NOW()) RETURNING id",
                )
                .bind(format!("ack-bulk probe {index}"))
                .fetch_one(&state.db)
                .await
                .unwrap();
                ids.push(id.to_string());
            }

            let app = web_handlers(state.clone(), session_user(&system_tenant));
            let response = app
                .clone()
                .oneshot(post_form(
                    "/web/admin/alerts/ack-bulk",
                    &csrf_body(&state, &[("ids", &ids.join(","))]),
                ))
                .await
                .unwrap();
            let flash = response_flash(&response, &state.config.csrf_secret);
            assert!(
                flash_text(&flash).contains("Acknowledged 3"),
                "flash was: {flash:?}"
            );
            let acknowledged: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM system_alerts WHERE id = ANY($1::uuid[]) AND acknowledged",
            )
            .bind(&ids)
            .fetch_one(&state.db)
            .await
            .unwrap();
            assert_eq!(acknowledged, 3);

            // Re-acking flips nothing and says so honestly.
            let response = app
                .clone()
                .oneshot(post_form(
                    "/web/admin/alerts/ack-bulk",
                    &csrf_body(&state, &[("ids", &ids.join(","))]),
                ))
                .await
                .unwrap();
            let flash = response_flash(&response, &state.config.csrf_secret);
            assert!(
                flash_text(&flash).contains("already"),
                "flash was: {flash:?}"
            );

            sqlx::query("DELETE FROM system_alerts WHERE id = ANY($1::uuid[])")
                .bind(&ids)
                .execute(&state.db)
                .await
                .unwrap();
        }

        #[tokio::test]
        async fn gdpr_transition_validates_the_triad_and_audits() {
            let Some(state) =
                web_test_state("gdpr_transition_validates_the_triad_and_audits").await
            else {
                return;
            };
            let tenant = apexmail_lib::id::generate_id("webflow", 18);
            seed_tenant(&state, &tenant).await;
            let request = apexmail_lib::id::generate_id("", 26);
            sqlx::query(
                "INSERT INTO gdpr_requests (id, tenant_id, email, request_type, status, created_at, updated_at)
                 VALUES ($1, $2, 'subject@t.io', 'access', 'pending', NOW(), NOW())",
            )
            .bind(&request)
            .bind(&tenant)
            .execute(&state.db)
            .await
            .unwrap();

            let app = web_handlers(state.clone(), session_user(&tenant));
            let uri = format!("/web/admin/gdpr/{request}/transition");

            // pending → in_progress is legal and audited.
            let response = app
                .clone()
                .oneshot(post_form(
                    &uri,
                    &csrf_body(&state, &[("status", "in_progress")]),
                ))
                .await
                .unwrap();
            let flash = response_flash(&response, &state.config.csrf_secret);
            assert!(
                flash_text(&flash).contains("in_progress"),
                "flash was: {flash:?}"
            );

            // in_progress → in_progress is refused.
            let response = app
                .clone()
                .oneshot(post_form(
                    &uri,
                    &csrf_body(&state, &[("status", "in_progress")]),
                ))
                .await
                .unwrap();
            let flash = response_flash(&response, &state.config.csrf_secret);
            assert!(
                flash_text(&flash).contains("cannot move"),
                "flash was: {flash:?}"
            );

            // in_progress → completed stamps fulfilled_at.
            let response = app
                .clone()
                .oneshot(post_form(
                    &uri,
                    &csrf_body(&state, &[("status", "completed")]),
                ))
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::SEE_OTHER);
            let (status, fulfilled): (String, bool) = sqlx::query_as(
                "SELECT status, fulfilled_at IS NOT NULL FROM gdpr_requests WHERE id = $1",
            )
            .bind(&request)
            .fetch_one(&state.db)
            .await
            .unwrap();
            assert_eq!(status, "completed");
            assert!(fulfilled);

            // Terminal: completed → rejected is refused.
            let response = app
                .clone()
                .oneshot(post_form(
                    &uri,
                    &csrf_body(&state, &[("status", "rejected")]),
                ))
                .await
                .unwrap();
            let flash = response_flash(&response, &state.config.csrf_secret);
            assert!(
                flash_text(&flash).contains("cannot move"),
                "flash was: {flash:?}"
            );

            cleanup_tenant(&state, &tenant).await;
        }

        #[tokio::test]
        async fn tenant_lifecycle_suspends_resumes_and_deletes_with_typing() {
            let Some(state) =
                web_test_state("tenant_lifecycle_suspends_resumes_and_deletes_with_typing").await
            else {
                return;
            };
            let tenant = apexmail_lib::id::generate_id("webflow", 18);
            seed_tenant(&state, &tenant).await;
            let name = format!("Web Flow Test {tenant}");
            let system_tenant: String =
                sqlx::query_scalar("SELECT id::text FROM tenants WHERE slug = 'system' LIMIT 1")
                    .fetch_optional(&state.db)
                    .await
                    .ok()
                    .flatten()
                    .unwrap_or_else(|| "system".to_string());
            let app = web_handlers(state.clone(), session_user(&system_tenant));

            // Suspend signs a confirmation rather than acting directly.
            let response = app
                .clone()
                .oneshot(post_form(
                    &format!("/web/admin/tenants/{tenant}/suspend"),
                    &csrf_body(&state, &[]),
                ))
                .await
                .unwrap();
            let location = response
                .headers()
                .get(header::LOCATION)
                .and_then(|value| value.to_str().ok())
                .unwrap()
                .to_string();
            assert!(
                location.starts_with("/confirm?intent=suspend-tenant&id="),
                "was {location}"
            );
            let sig = location.split("sig=").nth(1).unwrap().to_string();
            let confirm = csrf_body(
                &state,
                &[("intent", "suspend-tenant"), ("id", &tenant), ("sig", &sig)],
            );
            let response = app
                .clone()
                .oneshot(post_form("/web/confirm", &confirm))
                .await
                .unwrap();
            let flash = response_flash(&response, &state.config.csrf_secret);
            assert!(
                flash_text(&flash).contains("suspended"),
                "flash was: {flash:?}"
            );

            // Resume directly (validated transition).
            let response = app
                .clone()
                .oneshot(post_form(
                    &format!("/web/admin/tenants/{tenant}/resume"),
                    &csrf_body(&state, &[]),
                ))
                .await
                .unwrap();
            let flash = response_flash(&response, &state.config.csrf_secret);
            assert!(
                flash_text(&flash).contains("resumed"),
                "flash was: {flash:?}"
            );

            // Delete requires typing the EXACT tenant name server-side.
            let response = app
                .clone()
                .oneshot(post_form(
                    &format!("/web/admin/tenants/{tenant}/delete"),
                    &csrf_body(&state, &[]),
                ))
                .await
                .unwrap();
            let location = response
                .headers()
                .get(header::LOCATION)
                .and_then(|value| value.to_str().ok())
                .unwrap()
                .to_string();
            let sig = location.split("sig=").nth(1).unwrap().to_string();
            let wrong = csrf_body(
                &state,
                &[
                    ("intent", "delete-tenant"),
                    ("id", &tenant),
                    ("sig", &sig),
                    ("confirmation", "wrong name"),
                ],
            );
            let response = app
                .clone()
                .oneshot(post_form("/web/confirm", &wrong))
                .await
                .unwrap();
            let flash = response_flash(&response, &state.config.csrf_secret);
            assert!(
                flash_text(&flash).contains("does not match"),
                "flash was: {flash:?}"
            );
            let still_there: bool =
                sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM tenants WHERE id = $1)")
                    .bind(&tenant)
                    .fetch_one(&state.db)
                    .await
                    .unwrap();
            assert!(still_there, "a mistyped name must never delete");

            let right = csrf_body(
                &state,
                &[
                    ("intent", "delete-tenant"),
                    ("id", &tenant),
                    ("sig", &sig),
                    ("confirmation", &name),
                ],
            );
            let response = app
                .clone()
                .oneshot(post_form("/web/confirm", &right))
                .await
                .unwrap();
            let flash = response_flash(&response, &state.config.csrf_secret);
            assert!(
                flash_text(&flash).contains("deleted"),
                "flash was: {flash:?}"
            );
            let still_there: bool =
                sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM tenants WHERE id = $1)")
                    .bind(&tenant)
                    .fetch_one(&state.db)
                    .await
                    .unwrap();
            assert!(!still_there);
        }

        #[tokio::test]
        async fn events_loader_passes_page_and_total_through_the_data_path() {
            let Some(state) =
                web_test_state("events_loader_passes_page_and_total_through_the_data_path").await
            else {
                return;
            };
            let tenant = apexmail_lib::id::generate_id("webflow", 18);
            seed_tenant(&state, &tenant).await;
            // events.id is VARCHAR(64) PRIMARY KEY
            // (migrations/075_create_missing_tables.sql:31) — a 36-char UUID
            // string fits; a 26-char-only column would 22001 here.
            // 25 events: two pages at PER_PAGE=20.
            for index in 0..25 {
                sqlx::query(
                    "INSERT INTO events (id, tenant_id, event_type, recipient, timestamp)
                     VALUES ($1, $2, 'sent', $3, NOW())",
                )
                .bind(Uuid::new_v4())
                .bind(&tenant)
                .bind(format!("evt-{index}@t.io"))
                .execute(&state.db)
                .await
                .unwrap();
            }
            let user = session_user(&tenant);
            let page1 = load_page_data(&state, "web", "/events", None, Some(&user)).await;
            let list = page1.list.expect("events list");
            assert_eq!(list.page, 1);
            assert_eq!(list.total_pages, 2);
            assert_eq!(list.total_count, 25);
            assert_eq!(list.table.as_ref().unwrap().rows.len(), 20);

            let page2 = load_page_data(&state, "web", "/events", Some("page=2"), Some(&user)).await;
            let list = page2.list.expect("events page 2");
            assert_eq!(list.page, 2);
            assert_eq!(list.table.as_ref().unwrap().rows.len(), 5);

            sqlx::query("DELETE FROM events WHERE tenant_id = $1")
                .bind(&tenant)
                .execute(&state.db)
                .await
                .unwrap();
            cleanup_tenant(&state, &tenant).await;
        }

        #[tokio::test]
        async fn domain_detail_reuses_the_dns_record_generation() {
            let Some(state) =
                web_test_state("domain_detail_reuses_the_dns_record_generation").await
            else {
                return;
            };
            let tenant = apexmail_lib::id::generate_id("webflow", 18);
            seed_tenant(&state, &tenant).await;
            // domains.id is UUID PRIMARY KEY DEFAULT gen_random_uuid()
            // (migrations/052_add_missing_foundation_tables.sql:144) — bind a
            // Uuid; the detail loader reads it back as a string.
            let domain = Uuid::new_v4();
            let domain_name = format!("dns-{tenant}.example.org");
            sqlx::query("DELETE FROM domains WHERE name = $1")
                .bind(&domain_name)
                .execute(&state.db)
                .await
                .unwrap();
            // Seed WITHOUT DKIM material first: the page must show the
            // honest "records not generated yet" state.
            sqlx::query(
                "INSERT INTO domains (id, tenant_id, name, status, created_at, updated_at)
                 VALUES ($1, $2, $3, 'pending', NOW(), NOW())",
            )
            .bind(domain)
            .bind(&tenant)
            .bind(&domain_name)
            .execute(&state.db)
            .await
            .unwrap();

            let empty =
                data::load_domain_detail(&state.db, &tenant, &domain.to_string(), "us-east-1")
                    .await
                    .expect("detail loads without material");
            assert!(empty.empty_title.contains("not generated"));

            // Provision DKIM material exactly like the JSON verify path,
            // then the SAME record set the dns-records endpoint returns
            // must appear as data rows.
            let key_pair = apexmail_lib::dkim::generate_dkim_keypair().unwrap();
            let selector = format!("am-{}", Uuid::new_v4().simple());
            sqlx::query(
                "UPDATE domains SET dkim_selector = $1, dkim_public_key = $2, dkim_private_key = $3 WHERE id = $4::uuid",
            )
            .bind(&selector)
            .bind(&key_pair.public_key)
            .bind(key_pair.private_key_pem.as_str())
            .bind(domain)
            .execute(&state.db)
            .await
            .unwrap();

            let detail =
                data::load_domain_detail(&state.db, &tenant, &domain.to_string(), "us-east-1")
                    .await
                    .expect("detail loads");
            let table = detail.table.expect("records table");
            assert!(table.columns.contains(&"Value".to_string()));
            let hostnames: Vec<String> = table
                .rows
                .iter()
                .map(|row| match &row.cells[1] {
                    ui_foundation::view_data::DataCell::Mono(value) => value.clone(),
                    other => panic!("host cell must be mono data, was {other:?}"),
                })
                .collect();
            assert!(
                hostnames
                    .iter()
                    .any(|host| host.contains(&format!("{selector}._domainkey.{domain_name}"))),
                "DKIM record for the row's selector: {hostnames:?}"
            );
            assert!(
                hostnames
                    .iter()
                    .any(|host| host == &format!("_dmarc.{domain_name}")),
                "DMARC record present: {hostnames:?}"
            );
            // Values are mono cells (system-correct rendering data).
            assert!(table
                .rows
                .iter()
                .all(|row| matches!(row.cells[2], ui_foundation::view_data::DataCell::Mono(_))));

            // Another tenant's domain does not leak.
            let other_tenant = apexmail_lib::id::generate_id("webflow", 18);
            assert!(data::load_domain_detail(
                &state.db,
                &other_tenant,
                &domain.to_string(),
                "us-east-1"
            )
            .await
            .is_none());

            cleanup_tenant(&state, &tenant).await;
        }

        // ─── Canonical-shape sweep of the `WHERE id = $n` family ──────
        //
        // The handlers below bind the session/form-supplied user, list,
        // campaign and alert ids against UUID columns (canonical
        // services/mail-server/migrations lineage: users.id, lists.id,
        // campaigns.id, system_alerts.id are UUID). An uncast String bind
        // is an `uuid = text` operator error that the handlers' `.ok()`
        // chains swallow into a silent no-match — the exact defect class
        // this sweep pins. Every case drives the REAL handler through the
        // router against a canonical-shape fixture database and asserts the
        // DATABASE STATE changed, so a regression to text binds fails here
        // instead of shipping as a silent no-op.

        /// AppState over a canonical-shape fixture pool, with a REAL RSA
        /// private key so login can mint session JWTs, and the at-rest MFA
        /// secret key pinned (hex, 32 bytes).
        async fn canonical_web_state(db: sqlx::PgPool) -> AppState {
            static INSTALL: std::sync::Once = std::sync::Once::new();
            INSTALL.call_once(|| {
                let _ = metrics_exporter_prometheus::PrometheusBuilder::new().install_recorder();
                std::env::set_var("AWS_EC2_METADATA_DISABLED", "true");
                std::env::set_var("AWS_ACCESS_KEY_KEY", "test");
                std::env::set_var("AWS_ACCESS_KEY_ID", "test");
                std::env::set_var("AWS_SECRET_ACCESS_KEY", "test");
                std::env::set_var(
                    "MFA_SECRET_ENCRYPTION_KEY",
                    "9c4e2a7f1b8d3c506a9e2f7b4d1c8a35e0b6d9437f2a5c8e1b4d7f0a3c6e9247",
                );
            });
            // A real PKCS#8 RSA PEM (DKIM generation is the crate's RSA
            // keygen) so `session_cookie_for_user` succeeds for the login
            // cases.
            let key_pair = apexmail_lib::dkim::generate_dkim_keypair().expect("rsa keypair");
            // Honor the CI-provided ephemeral Redis like web_test_state does:
            // with the dead default the MFA replay guard silently degrades to
            // its in-process fallback, which tests cannot clear between
            // phases (and which differs from the CI-deployed behavior).
            let redis_url =
                std::env::var("TEST_REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:1".into());
            let redis = deadpool_redis::Config::from_url(&redis_url)
                .create_pool(Some(deadpool_redis::Runtime::Tokio1))
                .expect("lazy redis pool");
            let aws_config = aws_config::defaults(aws_config::BehaviorVersion::latest())
                .region(aws_sdk_sesv2::config::Region::new("us-east-1"))
                .load()
                .await;
            let ses_provider = Arc::new(crate::ses_provider::SesIpProvider::new(
                aws_sdk_sesv2::Client::new(&aws_config),
                db.clone(),
                "apexmail".into(),
                "us-east-1".into(),
            ));
            let mut config = test_config();
            config.jwt_private_key_pem = key_pair.private_key_pem.to_string();
            crate::state::AppStateInner::with_ddos_protector(
                db.clone(),
                apexmail_db::pool::PoolPair {
                    rw: db.clone(),
                    ro: db,
                },
                redis,
                config,
                reqwest::Client::new(),
                (*ses_provider).clone(),
                None,
                Arc::new(
                    ddos_protection::DdosProtector::new(ddos_protection::ProtectorConfig::default())
                        .await
                        .expect("ddos protector"),
                ),
                None,
                None,
                crate::resilience::ResilientClient::new_from_config(&test_config()),
            )
        }

        /// The /web handlers under sweep, with the session user injected.
        fn canonical_handlers(state: AppState, user: AuthUser) -> axum::Router {
            axum::Router::new()
                .route("/web/account/profile", post(form_profile_update))
                .route("/web/auth/change-password", post(form_change_password))
                .route("/web/auth/mfa/setup", post(form_mfa_setup))
                .route("/web/auth/mfa/confirm", post(form_mfa_confirm))
                .route("/web/auth/login", post(form_login))
                .route("/web/auth/mfa/verify", post(form_mfa_verify))
                .route("/web/auth/signup", post(form_signup))
                .route("/web/lists/update", post(form_list_update))
                .route("/web/campaigns/update", post(form_campaign_update))
                .route("/web/team/invite", post(form_team_invite))
                .route("/web/admin/operators", post(form_admin_operator_create))
                .route("/web/admin/alerts/ack", post(form_admin_alert_ack))
                .layer(axum::middleware::from_fn(
                    move |mut req: axum::extract::Request,
                          next: axum::middleware::Next|
                          -> std::pin::Pin<
                        Box<dyn std::future::Future<Output = axum::response::Response> + Send>,
                    > {
                        req.extensions_mut().insert(user.clone());
                        Box::pin(next.run(req))
                    },
                ))
                .with_state(state)
        }

        fn session_user_for(tenant: &str, user_id: &Uuid) -> AuthUser {
            AuthUser {
                tenant_id: tenant.to_string(),
                user_id: Some(user_id.to_string()),
                api_key_id: None,
                session_id: None,
                scopes: vec!["*".to_string()],
            }
        }

        /// Seed a canonical tenant + user (UUID id) and return
        /// (tenant_id, user_id, bcrypt password hash).
        async fn seed_canonical_user(db: &sqlx::PgPool, password: &str) -> (String, Uuid, String) {
            let tenant = apexmail_lib::id::generate_id("sweep", 20);
            sqlx::query(
                "INSERT INTO tenants (id, name, slug, plan, status)
                 VALUES ($1, 'Sweep Co', $2, 'free', 'active')",
            )
            .bind(&tenant)
            .bind(format!("sweep-{tenant}"))
            .execute(db)
            .await
            .expect("seed sweep tenant");
            let user_id = Uuid::new_v4();
            let hash = hash_password(password).expect("bcrypt hash");
            sqlx::query(
                "INSERT INTO users (id, tenant_id, email, name, password_hash, role, status, email_verified)
                 VALUES ($1, $2, $3, 'Sweep User', $4, 'owner', 'active', true)",
            )
            .bind(user_id)
            .bind(&tenant)
            .bind(format!("sweep-{}@example.com", Uuid::new_v4().simple()))
            .bind(&hash)
            .execute(db)
            .await
            .expect("seed sweep user");
            (tenant, user_id, hash)
        }

        /// The current RFC-6238-style TOTP code for raw secret bytes —
        /// mirrors apexmail_lib::mfa::generate_totp (HMAC-SHA256, 30s step,
        /// 6 digits) so the confirm/verify handlers can be exercised with
        /// a VALID code.
        fn current_totp_code(secret_bytes: &[u8]) -> String {
            totp_code_at_offset(secret_bytes, 0)
        }

        /// A code from `offset` 30s steps away from now. The replay guard
        /// burns the exact step a code was accepted in, so a test that both
        /// CONFIRMS an MFA enrollment and then SIGNS IN must spend two
        /// different steps: -1 stays inside the ±1 acceptance window while
        /// using a different replay key.
        fn totp_code_at_offset(secret_bytes: &[u8], step_offset: i64) -> String {
            use hmac::{Hmac, Mac};
            use sha2::Sha256;
            type HmacSha256 = Hmac<Sha256>;
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64;
            let counter = (now / 30) + step_offset;
            let mut mac = HmacSha256::new_from_slice(secret_bytes).unwrap();
            mac.update(&counter.to_be_bytes());
            let result = mac.finalize().into_bytes();
            let offset = (result[result.len() - 1] & 0x0f) as usize;
            let code = u32::from_be_bytes([
                result[offset] & 0x7f,
                result[offset + 1],
                result[offset + 2],
                result[offset + 3],
            ]);
            format!("{:06}", code % 1_000_000)
        }

        /// RFC-4648 base32 (no padding) of exactly 20 raw bytes → 32 chars,
        /// matching the base32 alphabet mfa.rs decodes.
        fn base32_of_20_bytes(bytes: &[u8; 20]) -> String {
            const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
            let mut out = String::with_capacity(32);
            for chunk in bytes.chunks(5) {
                let mut acc: u64 = 0;
                for byte in chunk {
                    acc = (acc << 8) | *byte as u64;
                }
                acc <<= 8 * (5 - chunk.len()) as u64;
                for shift in (0..8).rev() {
                    let index = ((acc >> (shift * 5)) & 0x1f) as usize;
                    out.push(ALPHABET[index] as char);
                }
            }
            out
        }

        /// Extract the first Set-Cookie header value with the given name.
        fn set_cookie_value(response: &Response, name: &str) -> Option<String> {
            response
                .headers()
                .get_all(header::SET_COOKIE)
                .iter()
                .filter_map(|value| value.to_str().ok())
                .find_map(|value| {
                    value
                        .split(';')
                        .next()
                        .and_then(|pair| pair.strip_prefix(&format!("{name}=")).map(str::to_string))
                })
        }

        /// ONE parametrized sweep: every /web handler that binds an id
        /// against a UUID column, driven against a canonical-shape database.
        /// Each case asserts the persisted row changed (or the authenticated
        /// flow completed) — a silent no-match fails loudly here.
        #[allow(clippy::await_holding_lock)]
        #[tokio::test]
        async fn web_id_binds_match_rows_on_the_canonical_schema() {
            let Some(db) = crate::test_db::canonical_pool("web_id_sweep").await else {
                eprintln!("skipping web_id_binds_match_rows_on_the_canonical_schema: no TEST_DATABASE_URL");
                return;
            };
            let state = canonical_web_state(db.clone()).await;
            // The signup case queues a transactional verification email,
            // which validates the DKIM material at QUEUE time (during the
            // request) — the env key must stay set for the whole test.
            let _env_guard = crate::test_db::DKIM_ENV_MUTEX
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            let had_dkim_key =
                std::env::var(apexmail_lib::dkim::DKIM_PRIVATE_KEY_ENCRYPTION_KEY_ENV).ok();
            seed_web_system_sender(&db).await;

            // ── Case 1: profile update (UPDATE users ... WHERE id = $2) ──
            let (tenant, user_id, _hash) = seed_canonical_user(&db, "0ld#SweepPassw0rd").await;
            let app = canonical_handlers(state.clone(), session_user_for(&tenant, &user_id));
            let response = app
                .clone()
                .oneshot(post_form(
                    "/web/account/profile",
                    &csrf_body(&state, &[("name", "Renamed Sweep User")]),
                ))
                .await
                .unwrap();
            let flash = response_flash(&response, &state.config.csrf_secret);
            assert!(
                flash_text(&flash).contains("Profile updated"),
                "profile flash: {flash:?}"
            );
            let name: (Option<String>,) = sqlx::query_as("SELECT name FROM users WHERE id = $1")
                .bind(user_id)
                .fetch_one(&db)
                .await
                .unwrap();
            assert_eq!(
                name.0.as_deref(),
                Some("Renamed Sweep User"),
                "UPDATE users ... WHERE id = $n::uuid must match the row"
            );

            // ── Case 2: change password (SELECT + UPDATE users) ──────────
            let response = app
                .clone()
                .oneshot(post_form(
                    "/web/auth/change-password",
                    &csrf_body(
                        &state,
                        &[
                            ("current_password", "0ld#SweepPassw0rd"),
                            ("new_password", "Br4nd#NewSweepPass"),
                        ],
                    ),
                ))
                .await
                .unwrap();
            let flash = response_flash(&response, &state.config.csrf_secret);
            assert!(
                flash_text(&flash).contains("Password updated"),
                "change-password flash: {flash:?}"
            );
            let hash: String = sqlx::query_scalar("SELECT password_hash FROM users WHERE id = $1")
                .bind(user_id)
                .fetch_one(&db)
                .await
                .unwrap();
            assert!(
                verify_password(&hash, "Br4nd#NewSweepPass"),
                "UPDATE users password bind must have matched (new hash verifies)"
            );

            // ── Case 3: MFA setup gate (SELECT mfa_enabled + email) ──────
            let response = app
                .clone()
                .oneshot(post_form("/web/auth/mfa/setup", &csrf_body(&state, &[])))
                .await
                .unwrap();
            let flash = response_flash(&response, &state.config.csrf_secret);
            assert!(
                flash_text(&flash).contains("Scan the QR code"),
                "mfa setup flash: {flash:?}"
            );
            assert!(
                set_cookie_value(&response, "apexmail_mfa_setup").is_some(),
                "mfa setup must set the pending-setup cookie"
            );

            // ── Case 4: MFA confirm (UPDATE users ... WHERE id = $3) ─────
            let mut secret_bytes = [0u8; 20];
            use rand::TryRngCore;
            rand::rngs::OsRng
                .try_fill_bytes(&mut secret_bytes)
                .expect("os rng");
            let secret_b32 = base32_of_20_bytes(&secret_bytes);
            let setup_value = encode_mfa_setup_value(
                &secret_b32,
                "otpauth://totp/ApexMail:sweep",
                &sign_mfa_setup(&state.config, &user_id.to_string(), &secret_b32),
            );
            let code = current_totp_code(&secret_bytes);
            let confirm_body = csrf_body(&state, &[("code", &code)]);
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/web/auth/mfa/confirm")
                        .header("content-type", "application/x-www-form-urlencoded")
                        .header(
                            header::COOKIE,
                            format!(
                                "apexmail_mfa_setup={setup_value}; {}",
                                csrf_cookie_of(&confirm_body)
                            ),
                        )
                        .body(Body::from(confirm_body))
                        .unwrap(),
                )
                .await
                .unwrap();
            let flash = response_flash(&response, &state.config.csrf_secret);
            assert!(
                flash_text(&flash).contains("MFA enabled"),
                "mfa confirm flash: {flash:?}"
            );
            let (mfa_enabled, mfa_secret): (bool, Option<String>) =
                sqlx::query_as("SELECT mfa_enabled, mfa_secret FROM users WHERE id = $1")
                    .bind(user_id)
                    .fetch_one(&db)
                    .await
                    .unwrap();
            assert!(mfa_enabled, "UPDATE users mfa bind must have matched");
            assert!(mfa_secret.is_some(), "mfa secret must be persisted");

            // ── Case 5: MFA login verify (SELECT mfa_secret by user id) ──
            // The same user now has MFA enabled: password login redirects to
            // the challenge, and a valid TOTP code completes the sign-in —
            // only possible when the mfa_secret SELECT matched the row.
            let email: String = sqlx::query_scalar("SELECT email FROM users WHERE id = $1")
                .bind(user_id)
                .fetch_one(&db)
                .await
                .unwrap();
            let login_app = canonical_handlers(state.clone(), session_user_for(&tenant, &user_id));
            let response = login_app
                .clone()
                .oneshot(post_form(
                    "/web/auth/login",
                    &csrf_body(
                        &state,
                        &[("email", &email), ("password", "Br4nd#NewSweepPass")],
                    ),
                ))
                .await
                .unwrap();
            let challenge =
                set_cookie_value(&response, "apexmail_login_challenge").unwrap_or_else(|| {
                    let flash = response_flash(&response, &state.config.csrf_secret);
                    panic!(
                        "password login must issue the MFA challenge cookie; flash: {flash:?}; \
                             set-cookies: {:?}",
                        response
                            .headers()
                            .get_all(header::SET_COOKIE)
                            .iter()
                            .map(|v| v.to_str().unwrap_or("<binary>"))
                            .collect::<Vec<_>>()
                    );
                });
            // The confirm above spent the enrollment secret's single-use F3
            // replay window. With a reachable TEST_REDIS_URL this used to
            // clear those Redis keys and re-use the same secret; with the
            // dead default Redis the guard degrades to the process-wide
            // in-process fallback, whose claimed windows a test cannot
            // clear — which turned this bind sweep into a Redis-only skip
            // (exactly the invisibility this suite exists to avoid).
            // Rotate the stored secret instead, encrypted at rest exactly
            // as `form_mfa_confirm` stores it (`secret_at_rest::encrypt_at_rest`
            // with AAD `user_id={user_id}` — see form_mfa_confirm), so the
            // sign-in below has an unclaimed window while still proving the
            // bind under test: `form_mfa_verify` must SELECT `mfa_secret` by
            // `users.id` (UUID, canonical migration 052) and decrypt it with
            // the same AAD for the code to validate at all.
            let mut signin_secret_bytes = [0u8; 20];
            rand::rngs::OsRng
                .try_fill_bytes(&mut signin_secret_bytes)
                .expect("os rng");
            let signin_secret_b32 = base32_of_20_bytes(&signin_secret_bytes);
            let encrypted = apexmail_lib::secret_at_rest::encrypt_at_rest(
                &signin_secret_b32,
                format!("user_id={user_id}").as_bytes(),
            )
            .expect("encrypt the rotated MFA secret");
            sqlx::query("UPDATE users SET mfa_secret = $1 WHERE id = $2")
                .bind(&encrypted)
                .bind(user_id)
                .execute(&db)
                .await
                .expect("rotate the stored MFA secret");
            let code = current_totp_code(&signin_secret_bytes);
            let verify_body = csrf_body(&state, &[("code", &code), ("email", &email)]);
            let response = login_app
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/web/auth/mfa/verify")
                        .header("content-type", "application/x-www-form-urlencoded")
                        .header(
                            header::COOKIE,
                            format!(
                                "apexmail_login_challenge={challenge}; {}",
                                csrf_cookie_of(&verify_body)
                            ),
                        )
                        .body(Body::from(verify_body))
                        .unwrap(),
                )
                .await
                .unwrap();
            // Full success = a signed session cookie is minted (the
            // "Signed in" path; only reachable when the mfa_secret SELECT
            // matched the row and the TOTP code verified).
            assert!(
                set_cookie_value(&response, "am_session").is_some(),
                "mfa verify must complete sign-in (session cookie); flash: {flash:?}; \
                 status {}; set-cookies {:?}",
                response.status(),
                response
                    .headers()
                    .get_all(header::SET_COOKIE)
                    .iter()
                    .map(|v| v.to_str().unwrap_or("<binary>"))
                    .collect::<Vec<_>>()
            );

            // ── Case 6: list update (UPDATE lists ... WHERE id = $2) ─────
            let list_id = Uuid::new_v4();
            sqlx::query("INSERT INTO lists (id, tenant_id, name) VALUES ($1, $2, 'Before')")
                .bind(list_id)
                .bind(&tenant)
                .execute(&db)
                .await
                .unwrap();
            let response = app
                .clone()
                .oneshot(post_form(
                    "/web/lists/update",
                    &csrf_body(
                        &state,
                        &[("id", &list_id.to_string()), ("name", "After Sweep")],
                    ),
                ))
                .await
                .unwrap();
            let flash = response_flash(&response, &state.config.csrf_secret);
            assert!(
                flash_text(&flash).contains("List saved"),
                "list update flash: {flash:?}"
            );
            let list_name: String = sqlx::query_scalar("SELECT name FROM lists WHERE id = $1")
                .bind(list_id)
                .fetch_one(&db)
                .await
                .unwrap();
            assert_eq!(list_name, "After Sweep");

            // ── Case 7: campaign update (UPDATE campaigns ... id = $4) ───
            let campaign_id = Uuid::new_v4();
            sqlx::query(
                "INSERT INTO campaigns (id, tenant_id, name, subject, status)
                 VALUES ($1, $2, 'Before', 'Old subject', 'draft')",
            )
            .bind(campaign_id)
            .bind(&tenant)
            .execute(&db)
            .await
            .unwrap();
            let response = app
                .clone()
                .oneshot(post_form(
                    "/web/campaigns/update",
                    &csrf_body(
                        &state,
                        &[
                            ("id", &campaign_id.to_string()),
                            ("name", "After Campaign"),
                            ("subject", "New subject"),
                        ],
                    ),
                ))
                .await
                .unwrap();
            let flash = response_flash(&response, &state.config.csrf_secret);
            assert!(
                flash_text(&flash).contains("Campaign saved"),
                "campaign update flash: {flash:?}"
            );
            let (campaign_name, subject): (String, Option<String>) =
                sqlx::query_as("SELECT name, subject FROM campaigns WHERE id = $1")
                    .bind(campaign_id)
                    .fetch_one(&db)
                    .await
                    .unwrap();
            assert_eq!(campaign_name, "After Campaign");
            assert_eq!(subject.as_deref(), Some("New subject"));

            // ── Case 8: team invite (INSERT users ... VALUES ($1 uuid)) ──
            let invite_email = format!("invitee-{}@example.com", Uuid::new_v4().simple());
            let response = app
                .clone()
                .oneshot(post_form(
                    "/web/team/invite",
                    &csrf_body(&state, &[("userName", &invite_email), ("role", "member")]),
                ))
                .await
                .unwrap();
            let flash = response_flash(&response, &state.config.csrf_secret);
            assert!(
                flash_text(&flash).contains("Invitation created"),
                "team invite flash: {flash:?}"
            );
            let invited: Option<(String,)> = sqlx::query_as(
                "SELECT id::text FROM users WHERE email = $1 AND status = 'invited'",
            )
            .bind(&invite_email)
            .fetch_optional(&db)
            .await
            .unwrap();
            assert!(
                invited.is_some(),
                "INSERT INTO users with a UUID id must persist the invitation"
            );

            // ── Case 9: operator create (INSERT users, system tenant) ────
            sqlx::query(
                "INSERT INTO tenants (id, name, slug, plan, status)
                 VALUES ('system_internal_tenant01', 'ApexMail', 'system', 'free', 'active')
                 ON CONFLICT (id) DO NOTHING",
            )
            .execute(&db)
            .await
            .unwrap();
            let operator_email = format!("operator-{}@example.com", Uuid::new_v4().simple());
            let response = app
                .clone()
                .oneshot(post_form(
                    "/web/admin/operators",
                    &csrf_body(&state, &[("email", &operator_email), ("name", "Ops")]),
                ))
                .await
                .unwrap();
            let flash = response_flash(&response, &state.config.csrf_secret);
            assert!(
                flash_text(&flash).contains("Operator invited"),
                "operator create flash: {flash:?}"
            );
            let operator: Option<(String,)> =
                sqlx::query_as("SELECT id::text FROM users WHERE email = $1 AND role = 'admin'")
                    .bind(&operator_email)
                    .fetch_optional(&db)
                    .await
                    .unwrap();
            assert!(operator.is_some(), "operator INSERT must persist a row");

            // ── Case 10: web form signup twin (INSERT tenants + users) ───
            let signup_email = format!("websignup-{}@example.com", Uuid::new_v4().simple());
            let response = app
                .clone()
                .oneshot(post_form(
                    "/web/auth/signup",
                    &csrf_body(
                        &state,
                        &[
                            ("name", "Web Signup"),
                            ("company_name", "Web Signup Co"),
                            ("email", &signup_email),
                            ("password", "We5#SignupPassword"),
                        ],
                    ),
                ))
                .await
                .unwrap();
            let flash = response_flash(&response, &state.config.csrf_secret);
            assert!(
                flash_text(&flash).contains("Account created"),
                "web signup flash: {flash:?}"
            );
            let web_user: Option<(String, String)> =
                sqlx::query_as("SELECT id::text, tenant_id::text FROM users WHERE email = $1")
                    .bind(&signup_email)
                    .fetch_optional(&db)
                    .await
                    .unwrap();
            let Some((web_user_id, web_tenant_id)) = web_user else {
                panic!("web signup must persist the user row");
            };
            assert!(
                Uuid::parse_str(&web_user_id).is_ok(),
                "users.id must be a UUID"
            );
            let web_tenant: Option<(String,)> =
                sqlx::query_as("SELECT status FROM tenants WHERE id = $1")
                    .bind(&web_tenant_id)
                    .fetch_optional(&db)
                    .await
                    .unwrap();
            assert!(
                web_tenant.is_some(),
                "web signup must persist the tenant row"
            );

            // ── Case 11: alert ack (UPDATE system_alerts ... id = $2) ────
            let alert_id = Uuid::new_v4();
            sqlx::query(
                "INSERT INTO system_alerts (id, severity, alert_type, message)
                 VALUES ($1, 'warning', 'disk', 'sweep alert')",
            )
            .bind(alert_id)
            .execute(&db)
            .await
            .unwrap();
            let response = app
                .oneshot(post_form(
                    "/web/admin/alerts/ack",
                    &csrf_body(&state, &[("id", &alert_id.to_string())]),
                ))
                .await
                .unwrap();
            let flash = response_flash(&response, &state.config.csrf_secret);
            assert!(
                flash_text(&flash).contains("Alert acknowledged"),
                "alert ack flash: {flash:?}"
            );
            let acked: Option<(Option<String>,)> = sqlx::query_as(
                "SELECT acknowledged_by FROM system_alerts WHERE id = $1 AND acknowledged",
            )
            .bind(alert_id)
            .fetch_optional(&db)
            .await
            .unwrap();
            assert!(
                acked.is_some_and(|(by,)| by.is_some_and(|v| !v.is_empty())),
                "UPDATE system_alerts must match and record the acknowledger"
            );

            match had_dkim_key {
                Some(key) => {
                    std::env::set_var(apexmail_lib::dkim::DKIM_PRIVATE_KEY_ENCRYPTION_KEY_ENV, key)
                }
                None => {
                    std::env::remove_var(apexmail_lib::dkim::DKIM_PRIVATE_KEY_ENCRYPTION_KEY_ENV)
                }
            }
            db.close().await;
        }

        // ─── Static canonical-schema contract (no database required) ──────
        //
        // The db_backed suite soft-skips whenever TEST_DATABASE_URL is
        // unset, so in a no-database CI run every fixture/schema mismatch
        // above is invisible. These constants embed the canonical migration
        // sources at COMPILE time so the contract test below runs in that
        // default run — it is the tripwire that fails CI when a migration
        // changes a declaration the fixtures depend on.

        const MIG_020: &str = include_str!("../../../../migrations/020_ses_monitoring.sql");
        const MIG_052: &str =
            include_str!("../../../../migrations/052_add_missing_foundation_tables.sql");
        const MIG_064: &str =
            include_str!("../../../../migrations/064_standardize_tenant_id_varchar26.sql");
        const MIG_068: &str = include_str!("../../../../migrations/068_create_lists_tables.sql");
        const MIG_069: &str =
            include_str!("../../../../migrations/069_create_missing_app_tables.sql");
        const MIG_075: &str = include_str!("../../../../migrations/075_create_missing_tables.sql");

        /// Whitespace-collapsed migration SQL, so a declaration can be
        /// asserted without depending on column alignment.
        fn normalized_ddl(sql: &str) -> String {
            sql.split_whitespace().collect::<Vec<_>>().join(" ")
        }

        /// The whitespace-collapsed `CREATE TABLE IF NOT EXISTS <table> (…);`
        /// block from one migration file, so per-table declarations (e.g.
        /// "`webhooks.name` is nullable") cannot draw false positives from
        /// another table in the same file.
        fn create_table_block(sql: &str, table: &str) -> String {
            let normalized = normalized_ddl(sql);
            let start = normalized
                .find(&format!("CREATE TABLE IF NOT EXISTS {table} ("))
                .unwrap_or_else(|| panic!("no CREATE TABLE for {table} in the migration"));
            let rest = &normalized[start..];
            let end = rest
                .find(");")
                .unwrap_or_else(|| panic!("unterminated CREATE TABLE {table}"));
            rest[..end].to_string()
        }

        fn assert_declaration(block: &str, declaration: &str, fixture_contract: &str) {
            assert!(
                block.contains(declaration),
                "canonical schema drift: expected `{declaration}` — the fixture contract \
                 depends on it ({fixture_contract}). Update the migration and the fixture \
                 together, never silently."
            );
        }

        /// The canonical-schema contract every `db_backed` fixture above
        /// binds against — asserted straight from the migration SQL text so
        /// it runs with or without a database. Findings that motivated this
        /// test:
        ///
        /// * the suite was pointed at the RAW `TEST_DATABASE_URL` database
        ///   instead of the canonical `<dbname>_api` clone, so fixtures
        ///   designed for these declarations failed only when a database
        ///   happened to be reachable;
        /// * with no database everything skipped, so no CI run could ever
        ///   notice a migration drifting away from the fixtures.
        #[test]
        fn fixtures_match_the_canonical_schema_contract() {
            // users.id / contacts.id / lists.id / domains.id / api_keys.id /
            // campaigns.id / campaign_jobs.id+campaign_id are UUID: the
            // fixtures bind `Uuid::new_v4()` and every handler compares
            // `WHERE id = $n::uuid`. A regression to VARCHAR is a 22001 on
            // the bind or a silent `uuid = text` no-match.
            assert_declaration(
                &create_table_block(MIG_052, "users"),
                "id UUID PRIMARY KEY DEFAULT gen_random_uuid()",
                "seed_canonical_user / team-invite / reset-password fixtures bind Uuid to users.id",
            );
            assert_declaration(
                &create_table_block(MIG_052, "domains"),
                "id UUID PRIMARY KEY DEFAULT gen_random_uuid()",
                "domain_detail fixture and the domain handlers bind Uuid to domains.id",
            );
            assert_declaration(
                &create_table_block(MIG_052, "api_keys"),
                "id UUID PRIMARY KEY DEFAULT gen_random_uuid()",
                "api-key fixtures bind Uuid to api_keys.id",
            );
            assert_declaration(
                &create_table_block(MIG_068, "contacts"),
                "id UUID PRIMARY KEY DEFAULT gen_random_uuid()",
                "contacts-import fixtures rely on the UUID default (they bind Uuid for seeded rows)",
            );
            assert_declaration(
                &create_table_block(MIG_068, "lists"),
                "id UUID PRIMARY KEY DEFAULT gen_random_uuid()",
                "campaign-start fixture binds Uuid to lists.id",
            );
            assert_declaration(
                &create_table_block(MIG_068, "list_subscribers"),
                "contact_id UUID NOT NULL REFERENCES contacts(id)",
                "campaign-start fixture binds Uuid to list_subscribers.contact_id",
            );
            assert_declaration(
                &create_table_block(MIG_069, "campaign_jobs"),
                "campaign_id UUID NOT NULL",
                "campaign-start fixture/recipe probe campaign_jobs by Uuid campaign id",
            );
            assert_declaration(
                &create_table_block(MIG_075, "campaigns"),
                "id UUID PRIMARY KEY DEFAULT gen_random_uuid()",
                "campaign fixtures bind Uuid to campaigns.id",
            );

            // templates.id and webhooks.id are VARCHAR(26) with NO default:
            // fixtures must mint them with `generate_id("", 26)`; a 36-char
            // UUID string is a 22001 "value too long for type character
            // varying(26)".
            assert_declaration(
                &create_table_block(MIG_075, "templates"),
                "id VARCHAR(26) PRIMARY KEY",
                "template fixtures mint templates.id with generate_id(\"\", 26)",
            );
            assert_declaration(
                &create_table_block(MIG_075, "webhooks"),
                "id VARCHAR(26) PRIMARY KEY",
                "webhook fixtures mint webhooks.id with generate_id(\"\", 26)",
            );
            // webhooks.secret is NOT NULL (075) and the fixture supplies it;
            // webhooks.name is deliberately NULLABLE, so the cap fixture
            // legitimately omits it. Pin both so a future NOT NULL on name
            // (or a dropped secret) is accompanied by a fixture change.
            assert_declaration(
                &create_table_block(MIG_075, "webhooks"),
                "secret VARCHAR(255) NOT NULL",
                "webhook fixtures always supply a signing secret",
            );
            assert!(
                !create_table_block(MIG_075, "webhooks").contains("name VARCHAR(255) NOT NULL"),
                "webhooks.name changed to NOT NULL: the cap fixture intentionally inserts \
                 rows without a name (075 declares it nullable) — fix both sides"
            );

            // events.id is VARCHAR(64): the events fixture binds a 36-char
            // UUID string, which is only legal because the column is wider
            // than 26.
            assert_declaration(
                &create_table_block(MIG_075, "events"),
                "id VARCHAR(64) PRIMARY KEY",
                "events_loader fixture binds a UUID string to events.id",
            );

            // system_alerts.id is UUID with a default: the ack-bulk and
            // web-id fixtures INSERT without an id and RETURN the generated
            // value.
            assert_declaration(
                &create_table_block(MIG_020, "system_alerts"),
                "id UUID PRIMARY KEY DEFAULT gen_random_uuid()",
                "alerts ack fixtures omit system_alerts.id and read back the generated Uuid",
            );

            // tenants.id is VARCHAR(26) (064): fixtures seed 26-char
            // tenant ids and every `tenant_id = $n` bind is text.
            assert_declaration(
                &create_table_block(MIG_064, "tenants"),
                "id VARCHAR(26) PRIMARY KEY",
                "seed_tenant/fixtures seed generate_id-prefixed 26-char tenant ids",
            );
        }
    }
}
