//! Bearer-token authentication middleware for internal services.
//!
//! Services load a shared secret from `INTERNAL_SERVICE_TOKEN` (or a
//! service-specific override) and reject requests that don't present it
//! via `Authorization:Bearer <token>` or `X-Api-Key:<token>`.

use axum::{
    extract::State,
    http::{header::AUTHORIZATION, HeaderMap, Request, StatusCode},
    middleware::Next,
    response::Response,
};
use std::sync::Arc;
use subtle::ConstantTimeEq;

/// Trait implemented by AppState types that hold an internal auth token.
pub trait HasServiceToken {
    fn service_token(&self) -> &str;
}

/// Axum middleware that rejects requests missing a valid service token.
/// Usage:/// ```ignore
/// .layer(middleware::from_fn_with_state(state, require_service_token::<MyAppState>))
/// ```
pub async fn require_service_token<S: HasServiceToken + Send + Sync + 'static>(
    State(state): State<Arc<S>>,
    req: Request<axum::body::Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    let expected = state.service_token();
    if expected.is_empty() {
// No token configured — deny all for safety
        return Err(StatusCode::UNAUTHORIZED);
    }

    let provided = extract_token(req.headers());
    match provided.as_deref() {
        Some(token) if token.as_bytes().ct_eq(expected.as_bytes()).into() => {
            Ok(next.run(req).await)
        }
        _ => Err(StatusCode::UNAUTHORIZED),
    }
}

fn extract_token(headers: &HeaderMap) -> Option<String> {
// Check X-Api-Key first
    if let Some(value) = headers.get("x-api-key") {
        return value.to_str().ok().map(|s| s.to_string());
    }
// Fall back to Authorization:Bearer <token>
    if let Some(value) = headers.get(AUTHORIZATION) {
        if let Ok(raw) = value.to_str() {
            if let Some(token) = raw.trim().strip_prefix("Bearer ") {
                return Some(token.to_string());
            }
        }
    }
    None
}

/// Load the internal service token from the environment with a fallback.
/// In production, callers should validate the token is strong enough.
pub fn load_service_token(env_key: &str) -> String {
    std::env::var(env_key)
        .or_else(|_| std::env::var("INTERNAL_SERVICE_TOKEN"))
        .unwrap_or_default()
}
