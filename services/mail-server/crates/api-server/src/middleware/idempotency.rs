//! Redis-backed idempotency for mutation endpoints.
//!
//! Key format:`apexmail:idempotency:{tenant_id}:{key}`
//! Stores the full serialised response for 24 h by default.

use axum::body::to_bytes;
use axum::extract::{Request, State};
use axum::http::{HeaderMap, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use deadpool_redis::redis::AsyncCommands;
use serde::{Deserialize, Serialize};

use crate::middleware::auth::AuthUser;
use crate::state::AppState;

const IDEMPOTENCY_HEADER: &str = "idempotency-key";
const MAX_BODY_SIZE: usize = 1024 * 1024; // 1 MiB cached response limit

// ─── Stored response ───────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize)]
struct CachedResponse {
    status: u16,
    headers: Vec<(String, String)>,
    body: String, // base64-encoded
    /// The authenticated principal that created this cached response.
    /// API-key, session, and user identities are all distinct to prevent
    /// same-tenant replay across credentials with the same idempotency key.
    #[serde(default)]
    principal_id: Option<String>,
    /// L-06 compatibility: older cached records stored only user_id.
    user_id: Option<String>,
}

// ─── Middleware ─────────────────────────────────────────────────

/// Axum middleware that implements idempotency semantics.
/// If the request contains an `Idempotency-Key` header the middleware will:
/// 1. Look up the key in Redis. On hit, verify the cached response belongs to
///    the same AuthUser, then return the cached response.
/// 2. On miss, let the request through, capture the response, and store it.
///
/// # Security (L-06)
/// Cached idempotency responses are bound to the concrete AuthUser principal
/// who created them. API-key and session identities are included, so one API
/// key cannot replay another key's response merely because both lack user_id.
pub async fn idempotency_middleware(
    State(state): State<AppState>,
    req: Request,
    next: Next,
) -> Response {
    let idempotency_key = match extract_idempotency_key(req.headers()) {
        Some(k) => k,
        None => return next.run(req).await,
    };

    // Extract the current AuthUser for both tenant binding and user re-validation
    let current_user = req.extensions().get::<AuthUser>().cloned();

    let tenant_id = current_user
        .as_ref()
        .map(|u| u.tenant_id.to_string())
        .unwrap_or_else(|| "global".to_string());

    let cache_key = format!("apexmail:idempotency:{tenant_id}:{idempotency_key}");
    let ttl = state.config.idempotency_ttl_seconds;

    // 1. Check cache — with AuthUser re-validation (L-06)
    if let Some(cached) = lookup_cached(&state, &cache_key).await {
        let user_id_matches = principal_matches(current_user.as_ref(), &cached);

        if !user_id_matches {
            tracing::warn!(
                cache_key,
                "cached idempotent response user_id mismatch — treating as miss (L-06)"
            );
        } else {
            tracing::debug!(cache_key, "returning cached idempotent response");
            return cached_to_response(cached);
        }
    }

    // 2. Execute the real handler
    let response = next.run(req).await;

    // 3. Store the response (with the current user_id for L-06 re-validation)
    store_response(&state, &cache_key, ttl, current_user, response).await
}

// ─── Helpers ───────────────────────────────────────────────────

fn extract_idempotency_key(headers: &HeaderMap) -> Option<String> {
    headers
        .get(IDEMPOTENCY_HEADER)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

async fn lookup_cached(state: &AppState, key: &str) -> Option<CachedResponse> {
    let mut conn = state.redis.get().await.ok()?;
    let json: Option<String> = conn.get(key).await.ok()?;
    json.and_then(|j| serde_json::from_str(&j).ok())
}

fn cached_to_response(cached: CachedResponse) -> Response {
    let status = StatusCode::from_u16(cached.status).unwrap_or(StatusCode::OK);
    let body_bytes =
        base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &cached.body)
            .unwrap_or_default();

    let mut builder = Response::builder().status(status);
    for (k, v) in &cached.headers {
        if let Ok(name) = k.parse::<axum::http::header::HeaderName>() {
            if let Ok(val) = v.parse::<axum::http::HeaderValue>() {
                builder = builder.header(name, val);
            }
        }
    }
    builder
        .body(axum::body::Body::from(body_bytes))
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

async fn store_response(
    state: &AppState,
    cache_key: &str,
    ttl: u64,
    current_user: Option<AuthUser>,
    resp: Response,
) -> Response {
    let (parts, body) = resp.into_parts();

    let body_bytes = match to_bytes(body, MAX_BODY_SIZE).await {
        Ok(b) => b,
        Err(e) => {
            // response instead of returning an empty body.
            tracing::warn!(cache_key, error = %e, "response body too large to cache for idempotency");
            return (
                parts.status,
                axum::Json(serde_json::json!({
                    "error": {
                        "code": "INTERNAL_ERROR",
                        "message": "response too large to cache"
                    }
                })),
            )
                .into_response();
        }
    };

    // L-06: Store the concrete authenticated principal so we can re-validate
    // subsequent requests against the same API key/session/user.
    let principal_id = current_user.as_ref().map(principal_binding);
    let cached = CachedResponse {
        status: parts.status.as_u16(),
        headers: parts
            .headers
            .iter()
            .filter_map(|(k, v)| v.to_str().ok().map(|val| (k.to_string(), val.to_string())))
            .collect(),
        body: base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &body_bytes),
        principal_id,
        user_id: current_user.and_then(|u| u.user_id),
    };

    if let Ok(json) = serde_json::to_string(&cached) {
        if let Ok(mut conn) = state.redis.get().await {
            let _: Result<(), _> = conn.set_ex(cache_key, &json, ttl).await;
        }
    }

    Response::from_parts(parts, axum::body::Body::from(body_bytes))
}

fn principal_binding(user: &AuthUser) -> String {
    if let Some(api_key_id) = user.api_key_id.as_deref() {
        return format!("api_key:{api_key_id}");
    }
    if let Some(session_id) = user.session_id.as_deref() {
        return format!("session:{session_id}");
    }
    if let Some(user_id) = user.user_id.as_deref() {
        return format!("user:{user_id}");
    }
    "anonymous".to_string()
}

fn principal_matches(current_user: Option<&AuthUser>, cached: &CachedResponse) -> bool {
    match (current_user, cached.principal_id.as_deref()) {
        (Some(user), Some(principal_id)) => principal_binding(user) == principal_id,
        (None, Some("anonymous")) => true,
        (None, None) => cached.user_id.is_none(),
        (Some(user), None) => user.user_id.as_deref() == cached.user_id.as_deref(),
        _ => false,
    }
}

// ─── Tests ─────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderMap;

    #[test]
    fn test_extract_idempotency_key_present() {
        let mut headers = HeaderMap::new();
        headers.insert("idempotency-key", "abc-123".parse().unwrap());
        assert_eq!(
            extract_idempotency_key(&headers),
            Some("abc-123".to_string())
        );
    }

    #[test]
    fn test_extract_idempotency_key_missing() {
        let headers = HeaderMap::new();
        assert_eq!(extract_idempotency_key(&headers), None);
    }

    #[test]
    fn test_cached_response_roundtrip() {
        let cached = CachedResponse {
            status: 200,
            headers: vec![("content-type".into(), "application/json".into())],
            body: base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                b"{\"ok\":true}",
            ),
            principal_id: None,
            user_id: None,
        };
        let json = serde_json::to_string(&cached).unwrap();
        let decoded: CachedResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.status, 200);
    }

    #[test]
    fn principal_binding_prefers_api_key_over_missing_user_id() {
        let user = AuthUser {
            tenant_id: "tenant_1".into(),
            user_id: None,
            api_key_id: Some("key_1".into()),
            session_id: None,
            scopes: vec![],
        };
        assert_eq!(principal_binding(&user), "api_key:key_1");
    }

    #[test]
    fn principal_matches_rejects_different_api_keys_without_user_ids() {
        let cached = CachedResponse {
            status: 200,
            headers: vec![],
            body: String::new(),
            principal_id: Some("api_key:key_1".into()),
            user_id: None,
        };
        let current = AuthUser {
            tenant_id: "tenant_1".into(),
            user_id: None,
            api_key_id: Some("key_2".into()),
            session_id: None,
            scopes: vec![],
        };
        assert!(!principal_matches(Some(&current), &cached));
    }

    #[test]
    fn principal_matches_accepts_same_session() {
        let cached = CachedResponse {
            status: 200,
            headers: vec![],
            body: String::new(),
            principal_id: Some("session:sess_1".into()),
            user_id: Some("usr_1".into()),
        };
        let current = AuthUser {
            tenant_id: "tenant_1".into(),
            user_id: Some("usr_1".into()),
            api_key_id: None,
            session_id: Some("sess_1".into()),
            scopes: vec![],
        };
        assert!(principal_matches(Some(&current), &cached));
    }
}
