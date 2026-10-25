//! Provider compatibility surface, SendGrid, Mailgun, Postmark, Resend.
//!
//! A **pure mapping layer**: every route here translates a provider's send
//! syntax into the canonical [`SendMessageRequest`](crate::routes::messages)
//! and then calls the SAME handler `POST /v1/messages` (and
//! `POST /v1/messages/batch`) the canonical API uses —
//! [`send_message`](crate::routes::messages::send_message) /
//! [`send_batch`](crate::routes::messages::send_batch). No validation,
//! entitlement, suppression, consent, quota, idempotency or queue-insert
//! logic is duplicated or bypassed here: subjects and mailbox parsing, the
//! DKIM-verified sender-domain gate, suppression and consent enforcement,
//! plan entitlements/quotas, the durable idempotency ledger and the
//! `messages` + `email_queue` inserts all run in exactly one place, the
//! canonical handler, so a compat send can never take a shortcut past the
//! gates the canonical API enforces.
//!
//! # Auth model (the `base URL` swap)
//!
//! Each compat route accepts the **ApexMail API key** (`am_live_…` /
//! `am_test_…`) in the header the provider itself uses:
//!
//! | provider | credential carrier |
//! |----------|--------------------|
//! | SendGrid | `Authorization: Bearer <key>` |
//! | Mailgun  | `Authorization: Basic base64("<user>:<key>")` |
//! | Postmark | `X-Postmark-Server-Token: <key>` |
//! | Resend   | `Authorization: Bearer <key>` |
//!
//! The key is resolved through the CANONICAL API-key path
//! (`middleware::auth::authenticate_compat_api_key` → the same hashing,
//! cache, expiry, tenant-binding and tenant-status gates `X-API-Key` rides),
//! and the request needs the same `messages:send` scope
//! `POST /v1/messages` requires. A customer therefore swaps the base URL and
//! keeps their key slot; a bad or missing key is refused in the PROVIDER's
//! own error shape (SendGrid `{"errors":[…]}`,
//! Mailgun `{"message":…}`, Postmark `{"ErrorCode":…,"Message":…}`,
//! Resend `{"statusCode":…,"name":…,"message":…}`).
//!
//! # Layer order
//!
//! The compat routers are mounted on their own stack, mirroring the order the
//! canonical authenticated stack uses (`ddos → auth → rate-limit →
//! handler`), with the provider-shaped credential step in place of the
//! canonical `require_auth` so an auth refusal comes back in the provider's
//! shape. Platform-level protections that run before any credential is known
//! (DDoS load-shedding/challenge, the body-size limits, the 30 s timeout, the
//! `Content-Type` gate) keep the canonical envelope, exactly like nginx's
//! own 429, because they are not provider-contract refusals.
//!
//! # Mapping policy
//!
//! * A provider field that maps cleanly onto a canonical field is mapped
//!   (see each provider module's table).
//! * A provider field that CANNOT be honoured (inline attachments with a
//!   `ContentID`, stored provider templates, per-message tracking toggles,
//!   natural-language schedules, …) is a **named refusal** in the provider's
//!   error shape. Nothing is ever silently dropped: a compat send either
//!   means exactly what the caller wrote, or it is refused with the field
//!   named.
//! * Fields that are an explicit no-op (e.g.
//!   `mail_settings.sandbox_mode.enable = false`) are accepted.
//! * The canonical `category` (the server-owned consent/preference class)
//!   defaults to the canonical default, `marketing`, which means the SAME
//!   consent gate `/v1` applies also refuses a compat marketing send. Two
//!   explicit, opt-in escapes exist: Postmark's `MessageStream`
//!   (`outbound` → `transactional`, `broadcast` → `marketing`) and the
//!   documented `X-ApexMail-Category: <canonical category>` extension header
//!   on all four surfaces (validated by the canonical normalizer).
//!
//! # Response shapes
//!
//! The canonical handler's answer is re-rendered into the provider's own
//! response (SendGrid `202` + `X-Message-Id`, Mailgun
//! `{"id","message"}`, Postmark `{"ErrorCode":0,"MessageID"}` / the batch
//! array, Resend `{"id"}`). The message id in every provider response is the
//! canonical message id, the same id `GET /v1/messages/{id}` serves, so a
//! migrated integration keeps its idempotent retry semantics: a retry that
//! replays from the durable idempotency ledger is re-rendered here through
//! the same path and returns the SAME provider-shaped id.

pub mod mailgun;
pub mod multipart;
pub mod postmark;
pub mod resend;
pub mod sendgrid;

#[cfg(test)]
mod tests;

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::{Json, Router};
use base64::Engine;

use crate::error::ApiError;
use crate::middleware::auth::{require_scopes, AuthUser};
use crate::routes::messages::{send_batch, send_message, BatchSendRequest, SendMessageRequest};
use crate::state::AppState;

/// The compatibility surface's scope gate, identical to `POST /v1/messages`.
pub(crate) const COMPAT_SCOPES: [&str; 1] = ["messages:send"];

/// The provider whose wire contract a route serves. Each value owns its
/// credential carrier, error shape and success shape.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Provider {
    SendGrid,
    Mailgun,
    Postmark,
    Resend,
}

impl Provider {
    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::SendGrid => "sendgrid",
            Self::Mailgun => "mailgun",
            Self::Postmark => "postmark",
            Self::Resend => "resend",
        }
    }
}

// ─── Router assembly ───────────────────────────────────────────

/// The complete compatibility surface, mounted by `build_app` OUTSIDE the
/// canonical authenticated stack: each provider module applies its own
/// provider-shaped credential middleware, and the load-shedding layer wraps
/// the lot exactly like the canonical stack's `ddos → auth` order.
pub fn router(state: AppState) -> Router<AppState> {
    let surface = Router::new()
        .merge(sendgrid::router(state.clone()))
        .merge(mailgun::router(state.clone()))
        .merge(postmark::router(state.clone()))
        .merge(resend::router(state.clone()));

    // Outermost layer last: cheap load-shedding BEFORE any credential work,
    // same position and same middleware as the canonical stack. Errors from
    // here are platform-level (canonical envelope + nginx-style 429), never
    // provider-contract refusals.
    surface.layer(axum::middleware::from_fn_with_state(
        state,
        crate::middleware::ddos::ddos_protection_middleware,
    ))
}

/// Per-provider middleware bundle: provider-shaped credential resolution
/// (replacing the canonical `require_auth`) followed by the canonical
/// per-tenant rate limiter, which needs `AuthUser` in extensions.
pub(crate) fn provider_layers(
    router: Router<AppState>,
    state: AppState,
    provider: Provider,
) -> Router<AppState> {
    router
        .route_layer(axum::middleware::from_fn_with_state(
            state.clone(),
            crate::middleware::rate_limiter::rate_limit_middleware,
        ))
        .route_layer(axum::middleware::from_fn_with_state(
            (state, provider),
            require_provider_auth,
        ))
}

// ─── Provider-shaped authentication ────────────────────────────

/// Provider-shaped credential middleware. Authenticates the provider-native
/// header through the canonical API-key path and inserts the resolved
/// [`AuthUser`] for the handlers (and the rate limiter) exactly like
/// `require_auth` does for `/v1`.
pub(crate) async fn require_provider_auth(
    State((state, provider)): State<(AppState, Provider)>,
    mut req: axum::extract::Request,
    next: Next,
) -> Response {
    match authenticate_provider(provider, req.headers(), &state).await {
        Ok(user) => {
            // Same scope gate as the canonical handler. Checked here too so
            // a key without `messages:send` is refused without touching the
            // database work the canonical handler would do first.
            if let Err(error) = require_scopes(&user, &COMPAT_SCOPES) {
                return provider_error_from_api(provider, &error);
            }
            req.extensions_mut().insert(user);
            next.run(req).await
        }
        Err(refusal) => refusal,
    }
}

/// Resolve the provider's native credential header into an [`AuthUser`].
///
/// * SendGrid / Resend: `Authorization: Bearer <key>`.
/// * Mailgun: `Authorization: Basic base64("<user>:<key>")`, Mailgun's own
///   `api:<key>` form; the username is accepted as-is (Mailgun clients send
///   `api`, and a wrong username cannot grant anything: only the key is
///   authoritative).
/// * Postmark: `X-Postmark-Server-Token: <key>`.
pub(crate) async fn authenticate_provider(
    provider: Provider,
    headers: &HeaderMap,
    state: &AppState,
) -> Result<AuthUser, Response> {
    let key = match provider {
        Provider::SendGrid | Provider::Resend => {
            match bearer_credential(headers) {
                Some(key) => key,
                None => {
                    return Err(provider_unauthorized(
                        provider,
                        "missing authentication: send the ApexMail API key as `Authorization: Bearer <key>`",
                    ))
                }
            }
        }
        Provider::Mailgun => match basic_credential(headers) {
            Some(key) => key,
            None => {
                return Err(provider_unauthorized(
                    provider,
                    "missing authentication: send `Authorization: Basic base64(api:<ApexMail API key>)`",
                ))
            }
        },
        Provider::Postmark => match headers
            .get("x-postmark-server-token")
            .and_then(|value| value.to_str().ok())
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            Some(key) => key.to_string(),
            None => {
                return Err(provider_unauthorized(
                    provider,
                    "missing authentication: send the ApexMail API key as `X-Postmark-Server-Token`",
                ))
            }
        },
    };

    crate::middleware::auth::authenticate_compat_api_key(&key, "/compat", state)
        .await
        .map_err(|error| provider_error_from_api(provider, &error))
}

fn bearer_credential(headers: &HeaderMap) -> Option<String> {
    let raw = headers
        .get(axum::http::header::AUTHORIZATION)?
        .to_str()
        .ok()?;
    let mut parts = raw.splitn(2, ' ');
    let scheme = parts.next()?.trim();
    let token = parts.next().unwrap_or("").trim();
    if scheme.eq_ignore_ascii_case("bearer") && !token.is_empty() {
        Some(token.to_string())
    } else {
        None
    }
}

fn basic_credential(headers: &HeaderMap) -> Option<String> {
    let raw = headers
        .get(axum::http::header::AUTHORIZATION)?
        .to_str()
        .ok()?;
    let mut parts = raw.splitn(2, ' ');
    let scheme = parts.next()?.trim();
    if !scheme.eq_ignore_ascii_case("basic") {
        return None;
    }
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(parts.next().unwrap_or("").trim())
        .ok()?;
    let decoded = String::from_utf8(decoded).ok()?;
    let (user, key) = decoded.split_once(':')?;
    // Mailgun's documented credential is `api:<key>`; the username carries no
    // authority, so only emptiness is refused.
    if user.is_empty() || key.is_empty() {
        return None;
    }
    Some(key.to_string())
}

/// The authenticated identity, inserted by [`require_provider_auth`]. The
/// middleware always runs before these handlers on the compat stack; the
/// fallback refusal keeps the invariant honest if a route is ever mounted
/// without it.
pub(crate) fn request_auth(
    provider: Provider,
    req: &axum::extract::Request,
) -> Result<AuthUser, Response> {
    req.extensions().get::<AuthUser>().cloned().ok_or_else(|| {
        tracing::error!(
            provider = provider.name(),
            "compat route reached without the provider auth middleware"
        );
        provider_error(
            provider,
            StatusCode::INTERNAL_SERVER_ERROR,
            "the compatibility surface is misconfigured on this deployment",
            &[],
        )
    })
}

// ─── Canonical delegation ─────────────────────────────────────

/// The canonical handler's answer, decoded once so each provider module can
/// re-render it in its own shape.
pub(crate) struct CanonicalOutcome {
    pub status: StatusCode,
    pub body: serde_json::Value,
}

impl CanonicalOutcome {
    /// The canonical `data` object (the `MessageResponse` /
    /// `BatchSendResponse` payload), if this outcome is a success.
    pub(crate) fn success_data(&self) -> Option<&serde_json::Value> {
        if !self.status.is_success() {
            return None;
        }
        self.body.get("data")
    }

    /// A refusal's message + per-field details from the canonical error
    /// envelope (`{"error":{"code","message","details"}}`).
    pub(crate) fn refusal(&self) -> (String, Vec<String>) {
        let error = self.body.get("error");
        let message = error
            .and_then(|error| error.get("message"))
            .and_then(|message| message.as_str())
            .unwrap_or("the request was refused by the send path")
            .to_string();
        let details = error
            .and_then(|error| error.get("details"))
            .and_then(|details| details.as_array())
            .map(|details| {
                details
                    .iter()
                    .filter_map(|detail| detail.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default();
        (message, details)
    }
}

/// Decode a canonical handler response into [`CanonicalOutcome`]. A body that
/// is not JSON is an explicit internal error, a compat surface must never
/// synthesize a success out of an unreadable canonical answer.
pub(crate) async fn canonical_outcome(
    provider: Provider,
    response: Response,
) -> Result<CanonicalOutcome, Response> {
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 64 * 1024)
        .await
        .map_err(|error| {
            tracing::error!(provider = provider.name(), error = %error, "canonical send response unreadable");
            provider_error(
                provider,
                StatusCode::INTERNAL_SERVER_ERROR,
                "the send path answered an unreadable response",
                &[],
            )
        })?;
    if bytes.is_empty() {
        return Ok(CanonicalOutcome {
            status,
            body: serde_json::Value::Null,
        });
    }
    let body = serde_json::from_slice(&bytes).map_err(|error| {
        tracing::error!(provider = provider.name(), error = %error, "canonical send response is not JSON");
        provider_error(
            provider,
            StatusCode::INTERNAL_SERVER_ERROR,
            "the send path answered a non-JSON response",
            &[],
        )
    })?;
    Ok(CanonicalOutcome { status, body })
}

/// Render a canonical refusal (status >= 400) in the provider's error shape.
pub(crate) fn provider_error_from_outcome(
    provider: Provider,
    outcome: &CanonicalOutcome,
) -> Response {
    let (message, details) = outcome.refusal();
    provider_error(provider, outcome.status, &message, &details)
}

/// Render a canonical [`ApiError`] in the provider's error shape.
pub(crate) fn provider_error_from_api(provider: Provider, error: &ApiError) -> Response {
    let (status, message, details) = canonical_error_parts(error);
    provider_error(provider, status, &message, &details)
}

/// `ApiError` → (status, message, details). Mirrors `ApiError`'s own HTTP
/// mapping; `Internal` is deliberately flattened to the public message so a
/// provider-shaped error never leaks server internals.
fn canonical_error_parts(error: &ApiError) -> (StatusCode, String, Vec<String>) {
    match error {
        ApiError::BadRequest(message) => (StatusCode::BAD_REQUEST, message.clone(), Vec::new()),
        ApiError::Validation(details) => (
            StatusCode::BAD_REQUEST,
            "validation failed".to_string(),
            details.clone(),
        ),
        ApiError::Unauthorized(message) => (StatusCode::UNAUTHORIZED, message.clone(), Vec::new()),
        ApiError::Forbidden(message) => (StatusCode::FORBIDDEN, message.clone(), Vec::new()),
        ApiError::NotFound(message) => (StatusCode::NOT_FOUND, message.clone(), Vec::new()),
        ApiError::Conflict(message) => (StatusCode::CONFLICT, message.clone(), Vec::new()),
        ApiError::RateLimited | ApiError::RateLimitedMessage(_) | ApiError::RateLimitedIn(_) => (
            StatusCode::TOO_MANY_REQUESTS,
            "too many requests".to_string(),
            Vec::new(),
        ),
        ApiError::PayloadTooLarge(message) => {
            (StatusCode::PAYLOAD_TOO_LARGE, message.clone(), Vec::new())
        }
        ApiError::Timeout => (
            StatusCode::REQUEST_TIMEOUT,
            "request timeout".to_string(),
            Vec::new(),
        ),
        ApiError::ServiceUnavailable(message) => {
            (StatusCode::SERVICE_UNAVAILABLE, message.clone(), Vec::new())
        }
        // `#[non_exhaustive]`: everything else (including `Internal`) is a
        // server-side failure and answers the provider's 5xx shape without
        // echoing the detail.
        other => {
            tracing::error!(error = %other, "canonical send refused with a server error");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal server error".to_string(),
                Vec::new(),
            )
        }
    }
}

/// Render `(status, message, details)` in the provider's own error shape.
///
/// Every refusal this surface produces funnels through here, which also
///
/// * normalizes the 400/422 pair to the provider's own convention
///   (SendGrid/Mailgun answer 400, Postmark/Resend 422); and
/// * tags the response with [`ProviderShapedBody`] so the global
///   request-logger envelope normalizer passes it through verbatim (without
///   the tag, a provider-shaped body would be re-wrapped into the canonical
///   `{"error":{…}}` envelope and no provider SDK could parse it).
pub(crate) fn provider_error(
    provider: Provider,
    status: StatusCode,
    message: &str,
    details: &[String],
) -> Response {
    let status = provider_status(provider, status);
    let mut response = match provider {
        // SendGrid: `{"errors": [{"message", "field", "help"}]}`.
        Provider::SendGrid => {
            let errors: Vec<serde_json::Value> = if details.is_empty() {
                vec![serde_json::json!({
                    "message": message,
                    "field": serde_json::Value::Null,
                    "help": serde_json::Value::Null,
                })]
            } else {
                details
                    .iter()
                    .map(|detail| {
                        serde_json::json!({
                            "message": detail,
                            "field": serde_json::Value::Null,
                            "help": serde_json::Value::Null,
                        })
                    })
                    .collect()
            };
            (status, Json(serde_json::json!({ "errors": errors }))).into_response()
        }
        // Mailgun: `{"message": "..."}`. Mailgun's shape has no per-field
        // slot for the canonical refusal's details, so they are folded into
        // the message, a refusal that dropped them would hide WHICH field or
        // recipient was refused.
        Provider::Mailgun => (
            status,
            Json(serde_json::json!({ "message": fold_details(message, details) })),
        )
            .into_response(),
        // Postmark: `{"ErrorCode": <provider error code>, "Message": "..."}`.
        Provider::Postmark => (
            status,
            Json(serde_json::json!({
                "ErrorCode": postmark_error_code(status),
                "Message": fold_details(message, details),
            })),
        )
            .into_response(),
        // Resend: `{"statusCode", "name", "message"}`.
        Provider::Resend => (
            status,
            Json(serde_json::json!({
                "statusCode": status.as_u16(),
                "name": resend_error_name(status),
                "message": fold_details(message, details),
            })),
        )
            .into_response(),
    };
    response
        .extensions_mut()
        .insert(crate::middleware::request_logger::ProviderShapedBody);
    response
}

/// Fold the canonical refusal's per-field details into a provider shape that
/// carries a single message string (Mailgun `message`, Postmark `Message`,
/// Resend `message`). SendGrid has a dedicated `errors[]` array and renders
/// the details there instead. Without this fold a canonical validation
/// refusal ("validation failed" + the field/recipient list) would reach the
/// caller with the reason dropped.
fn fold_details(message: &str, details: &[String]) -> String {
    if details.is_empty() {
        return message.to_string();
    }
    format!("{message}: {}", details.join("; "))
}

/// The provider's own status for a canonical refusal: only the 400/422
/// validation pair differs between providers (SendGrid and Mailgun document
/// 400 for an unusable request; Postmark and Resend document 422). Every
/// other status (401/403/404/409/413/429/5xx) passes through unchanged.
fn provider_status(provider: Provider, status: StatusCode) -> StatusCode {
    match status {
        StatusCode::UNPROCESSABLE_ENTITY => match provider {
            Provider::SendGrid | Provider::Mailgun => StatusCode::BAD_REQUEST,
            _ => StatusCode::UNPROCESSABLE_ENTITY,
        },
        StatusCode::BAD_REQUEST => match provider {
            Provider::Postmark | Provider::Resend => StatusCode::UNPROCESSABLE_ENTITY,
            _ => StatusCode::BAD_REQUEST,
        },
        other => other,
    }
}

/// Postmark's documented error codes for the refusals this surface produces
/// (422 invalid request, 401 missing/invalid token, 403 inactive token,
/// 429 rate limit, 500 server error).
fn postmark_error_code(status: StatusCode) -> i64 {
    match status {
        StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => 10,
        StatusCode::UNPROCESSABLE_ENTITY | StatusCode::BAD_REQUEST => 422,
        StatusCode::TOO_MANY_REQUESTS => 429,
        StatusCode::NOT_FOUND => 404,
        _ if status.is_server_error() => 500,
        _ => 422,
    }
}

/// Resend's documented error `name` values for the refusals this surface
/// produces.
fn resend_error_name(status: StatusCode) -> &'static str {
    match status {
        StatusCode::UNAUTHORIZED => "invalid_api_key",
        StatusCode::FORBIDDEN => "restricted_api_key",
        StatusCode::NOT_FOUND => "not_found",
        StatusCode::TOO_MANY_REQUESTS => "rate_limit_exceeded",
        StatusCode::UNPROCESSABLE_ENTITY | StatusCode::BAD_REQUEST => "validation_error",
        _ if status.is_server_error() => "internal_server_error",
        _ => "validation_error",
    }
}

/// 401 in the provider's shape (used by credential extraction).
fn provider_unauthorized(provider: Provider, message: &str) -> Response {
    // Resend distinguishes "no key at all" from "bad key"; everything else
    // answers its plain 401 shape.
    if provider == Provider::Resend {
        let mut response = (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({
                "statusCode": 401,
                "name": "missing_api_key",
                "message": message,
            })),
        )
            .into_response();
        response
            .extensions_mut()
            .insert(crate::middleware::request_logger::ProviderShapedBody);
        return response;
    }
    provider_error(provider, StatusCode::UNAUTHORIZED, message, &[])
}

// ─── Canonical request translation helpers ─────────────────────

/// Collect named refusals while mapping; a non-empty list refuses the whole
/// request in the provider's shape (never a partial or lossy mapping).
#[derive(Default)]
pub(crate) struct MappingIssues(Vec<String>);

impl MappingIssues {
    pub(crate) fn push(&mut self, issue: impl Into<String>) {
        self.0.push(issue.into());
    }

    pub(crate) fn into_vec(self) -> Vec<String> {
        self.0
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

// ─── JSON mapping helpers ──────────────────────────────────────
//
// Every accessor takes the borrowed object it reads and records a
// field-named refusal for a wrong type, the mapping layer never coerces.

/// A string member (missing/null → `None`).
pub(crate) fn map_str(
    map: &serde_json::Map<String, serde_json::Value>,
    field: &str,
    issues: &mut MappingIssues,
) -> Option<String> {
    match map.get(field) {
        None | Some(serde_json::Value::Null) => None,
        Some(serde_json::Value::String(text)) => Some(text.clone()),
        Some(other) => {
            issues.push(format!(
                "field '{field}' must be a string (received {})",
                json_type_name(other)
            ));
            None
        }
    }
}

/// A non-empty string the provider documents as required.
pub(crate) fn map_required_str(
    map: &serde_json::Map<String, serde_json::Value>,
    field: &str,
    issues: &mut MappingIssues,
) -> Option<String> {
    match map.get(field) {
        Some(serde_json::Value::String(text)) if !text.trim().is_empty() => Some(text.clone()),
        Some(serde_json::Value::String(_)) | None | Some(serde_json::Value::Null) => {
            issues.push(format!("field '{field}' is required"));
            None
        }
        Some(other) => {
            issues.push(format!(
                "field '{field}' must be a string (received {})",
                json_type_name(other)
            ));
            None
        }
    }
}

/// A list of strings; a bare string is accepted as a one-element list (the
/// form several providers document).
pub(crate) fn map_string_list(
    map: &serde_json::Map<String, serde_json::Value>,
    field: &str,
    issues: &mut MappingIssues,
) -> Option<Vec<String>> {
    match map.get(field) {
        None | Some(serde_json::Value::Null) => None,
        Some(serde_json::Value::String(text)) => Some(vec![text.clone()]),
        Some(serde_json::Value::Array(items)) => {
            let mut out = Vec::with_capacity(items.len());
            for (index, item) in items.iter().enumerate() {
                match item {
                    serde_json::Value::String(text) => out.push(text.clone()),
                    other => issues.push(format!(
                        "field '{field}[{index}]' must be a string (received {})",
                        json_type_name(other)
                    )),
                }
            }
            Some(out)
        }
        Some(other) => {
            issues.push(format!(
                "field '{field}' must be a string or an array of strings (received {})",
                json_type_name(other)
            ));
            None
        }
    }
}

/// An object member.
pub(crate) fn map_object(
    map: &serde_json::Map<String, serde_json::Value>,
    field: &str,
    issues: &mut MappingIssues,
) -> Option<serde_json::Map<String, serde_json::Value>> {
    match map.get(field) {
        None | Some(serde_json::Value::Null) => None,
        Some(serde_json::Value::Object(inner)) => Some(inner.clone()),
        Some(other) => {
            issues.push(format!(
                "field '{field}' must be a JSON object (received {})",
                json_type_name(other)
            ));
            None
        }
    }
}

/// A recipient list: bare addr-spec strings, `"Name <addr>"` strings, or
/// provider address objects (`{"email": …, "name": …}`), all three forms are
/// normalized into the canonical mailbox display form.
pub(crate) fn map_mailbox_list(
    map: &serde_json::Map<String, serde_json::Value>,
    field: &str,
    issues: &mut MappingIssues,
) -> Option<Vec<String>> {
    match map.get(field) {
        None | Some(serde_json::Value::Null) => None,
        Some(serde_json::Value::String(text)) => Some(vec![text.clone()]),
        Some(serde_json::Value::Array(items)) => {
            let mut out = Vec::with_capacity(items.len());
            for (index, item) in items.iter().enumerate() {
                match item {
                    serde_json::Value::String(text) => out.push(text.clone()),
                    serde_json::Value::Object(address) => {
                        let email =
                            map_required_str(address, "email", issues).unwrap_or_default();
                        let name = map_str(address, "name", issues);
                        out.push(mailbox(&email, name.as_deref()));
                    }
                    other => issues.push(format!(
                        "field '{field}[{index}]' must be a mailbox string or an {{email, name}} object (received {})",
                        json_type_name(other)
                    )),
                }
            }
            Some(out)
        }
        Some(other) => {
            issues.push(format!(
                "field '{field}' must be a mailbox string, a mailbox object or an array of them (received {})",
                json_type_name(other)
            ));
            None
        }
    }
}

pub(crate) fn json_type_name(value: &serde_json::Value) -> &'static str {
    match value {
        serde_json::Value::Null => "null",
        serde_json::Value::Bool(_) => "a boolean",
        serde_json::Value::Number(_) => "a number",
        serde_json::Value::String(_) => "a string",
        serde_json::Value::Array(_) => "an array",
        serde_json::Value::Object(_) => "an object",
    }
}

/// `"Name <addr>"` when a display name is present, the bare addr-spec
/// otherwise, the canonical `from`/`reply_to` display form.
pub(crate) fn mailbox(email: &str, name: Option<&str>) -> String {
    match name.map(str::trim).filter(|name| !name.is_empty()) {
        Some(name) => format!("{name} <{email}>"),
        None => email.to_string(),
    }
}

/// A refusal naming a provider field this surface cannot honour. Never a
/// silent drop: the caller's payload means exactly what it says or is
/// refused.
pub(crate) fn unsupported(field: &str, why: &str) -> String {
    format!("field '{field}' is not supported by the ApexMail compatibility surface: {why}")
}

/// Reject every member of `object` that is not in `allowed`.
pub(crate) fn reject_unknown_fields(
    object: &serde_json::Map<String, serde_json::Value>,
    allowed: &[&str],
    prefix: &str,
    issues: &mut MappingIssues,
) {
    for key in object.keys() {
        if !allowed.contains(&key.as_str()) {
            issues.push(unsupported(
                &format!("{prefix}{key}"),
                "this field has no canonical equivalent",
            ));
        }
    }
}

/// Every member of `object` must be a string (SendGrid `custom_args`,
/// provider `headers` maps).
pub(crate) fn string_map(
    object: &serde_json::Map<String, serde_json::Value>,
    field: &str,
    issues: &mut MappingIssues,
) -> serde_json::Map<String, serde_json::Value> {
    let mut out = serde_json::Map::new();
    for (key, value) in object {
        if !value.is_string() {
            issues.push(format!(
                "field '{field}.{key}' must be a string (received {})",
                json_type_name(value)
            ));
            continue;
        }
        out.insert(key.clone(), value.clone());
    }
    out
}

/// Merge one customer object-map into another, refusing a key that appears
/// with two DIFFERENT values (a silent overwrite would lose caller data).
pub(crate) fn merge_maps(
    target: &mut serde_json::Map<String, serde_json::Value>,
    source: serde_json::Map<String, serde_json::Value>,
    left_field: &str,
    right_field: &str,
    issues: &mut MappingIssues,
) {
    for (key, value) in source {
        match target.get(&key) {
            Some(existing) if existing != &value => issues.push(format!(
                "'{key}' is set by both '{left_field}' and '{right_field}' with different values"
            )),
            Some(_) => {}
            None => {
                target.insert(key, value);
            }
        }
    }
}

/// The `X-ApexMail-Category` extension: an explicit, documented opt-in that
/// sets the canonical server-owned `category` (consent/preference class) from
/// a compat request. Validated by the canonical normalizer downstream.
pub(crate) const CATEGORY_HEADER: &str = "x-apexmail-category";

/// A compat request's headers + fully buffered body.
pub(crate) struct CompatRequest {
    pub headers: HeaderMap,
    pub body: Vec<u8>,
}

/// Buffer a compat request body under the SAME documented send-body ceiling
/// the canonical send routes enforce (`MAX_SEND_BODY_BYTES`, mirrored by
/// nginx's `client_max_body_size`). Oversize is the provider's 413 shape.
pub(crate) async fn read_compat_request(
    provider: Provider,
    req: axum::extract::Request,
) -> Result<CompatRequest, Response> {
    let (parts, body) = req.into_parts();
    let bytes = axum::body::to_bytes(body, crate::routes::messages::MAX_SEND_BODY_BYTES)
        .await
        .map_err(|error| {
            tracing::warn!(
                provider = provider.name(),
                error = %error,
                "compat request body rejected by the size limit"
            );
            provider_error(
                provider,
                StatusCode::PAYLOAD_TOO_LARGE,
                "the request body exceeds the maximum accepted size",
                &[],
            )
        })?;
    Ok(CompatRequest {
        headers: parts.headers,
        body: bytes.to_vec(),
    })
}

/// The request's `Content-Type` (media type only, lowercased).
pub(crate) fn content_type(headers: &HeaderMap) -> String {
    headers
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("")
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase()
}

/// The `Idempotency-Key` carried through to the canonical durable ledger on
/// every compat surface (Resend's native header; a documented extension for
/// the others).
pub(crate) fn idempotency_key(headers: &HeaderMap) -> Option<String> {
    headers
        .get("idempotency-key")
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|key| !key.is_empty() && key.len() <= 255)
        .map(str::to_string)
}

pub(crate) fn category_override(headers: &HeaderMap) -> Option<String> {
    headers
        .get(CATEGORY_HEADER)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

/// Dispatch one mapped send onto the canonical handler, the ONLY place the
/// compat surface touches the send path. The `ApiError` is returned unmapped
/// so each provider renders its own error shape.
pub(crate) async fn dispatch_send(
    state: &AppState,
    auth: &AuthUser,
    idempotency: Option<&str>,
    body: SendMessageRequest,
) -> Result<Response, ApiError> {
    let headers = idempotency_headers(idempotency);
    send_message(State(state.clone()), auth.clone(), headers, Json(body)).await
}

/// Dispatch a batch of mapped sends onto the canonical batch handler.
pub(crate) async fn dispatch_batch(
    state: &AppState,
    auth: &AuthUser,
    idempotency: Option<&str>,
    messages: Vec<SendMessageRequest>,
) -> Result<Response, ApiError> {
    let headers = idempotency_headers(idempotency);
    let body = BatchSendRequest { messages };
    send_batch(State(state.clone()), auth.clone(), headers, Json(body)).await
}

fn idempotency_headers(idempotency: Option<&str>) -> HeaderMap {
    let mut headers = HeaderMap::new();
    if let Some(key) = idempotency {
        if let Ok(value) = key.parse() {
            headers.insert("idempotency-key", value);
        }
    }
    headers
}

/// Dispatch + decode in one step: the mapped request goes onto the canonical
/// path and its answer comes back as a [`CanonicalOutcome`] (already
/// provider-shaped on a decode failure).
pub(crate) async fn dispatch_and_decode(
    provider: Provider,
    state: &AppState,
    auth: &AuthUser,
    idempotency: Option<&str>,
    body: SendMessageRequest,
) -> Result<CanonicalOutcome, Response> {
    let response = dispatch_send(state, auth, idempotency, body)
        .await
        .map_err(|error| provider_error_from_api(provider, &error))?;
    canonical_outcome(provider, response).await
}

/// [`dispatch_and_decode`] for a batch.
pub(crate) async fn dispatch_batch_and_decode(
    provider: Provider,
    state: &AppState,
    auth: &AuthUser,
    idempotency: Option<&str>,
    messages: Vec<SendMessageRequest>,
) -> Result<CanonicalOutcome, Response> {
    let response = dispatch_batch(state, auth, idempotency, messages)
        .await
        .map_err(|error| provider_error_from_api(provider, &error))?;
    canonical_outcome(provider, response).await
}

/// The canonical message id from a successful single-send outcome. A success
/// without an id would be a broken canonical contract, refuse rather than
/// invent one.
pub(crate) fn canonical_message_id(
    provider: Provider,
    outcome: &CanonicalOutcome,
) -> Result<String, Response> {
    outcome
        .success_data()
        .and_then(|data| data.get("id"))
        .and_then(|id| id.as_str())
        .map(str::to_string)
        .ok_or_else(|| {
            tracing::error!(
                provider = provider.name(),
                status = %outcome.status,
                "canonical send answered without a message id"
            );
            provider_error(
                provider,
                StatusCode::INTERNAL_SERVER_ERROR,
                "the send path answered without a message id",
                &[],
            )
        })
}
