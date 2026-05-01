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
}

// ─── Middleware ─────────────────────────────────────────────────

/// Axum middleware that implements idempotency semantics.
/// If the request contains an `Idempotency-Key` header the middleware will:/// 1. Look up the key in Redis. On hit, return the cached response.
/// 2. On miss, let the request through, capture the response, and store it.
pub async fn idempotency_middleware(
    State(state): State<AppState>,
    req: Request,
    next: Next,
) -> Response {
    let idempotency_key = match extract_idempotency_key(req.headers()) {
        Some(k) => k,
        None => return next.run(req).await,
    };

    // instead of raw Uuid. Previously always fell through to "global".
    let tenant_id = req
        .extensions()
        .get::<AuthUser>()
        .map(|u| u.tenant_id.to_string())
        .unwrap_or_else(|| "global".to_string());

    let cache_key = format!("apexmail:idempotency:{tenant_id}:{idempotency_key}");
    let ttl = state.config.idempotency_ttl_seconds;

    // 1. Check cache
    if let Some(cached) = lookup_cached(&state, &cache_key).await {
        tracing::debug!(cache_key, "returning cached idempotent response");
        return cached_to_response(cached);
    }

    // 2. Execute the real handler
    let response = next.run(req).await;

    // 3. Store the response
    store_response(&state, &cache_key, ttl, response).await
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

async fn store_response(state: &AppState, cache_key: &str, ttl: u64, resp: Response) -> Response {
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

    let cached = CachedResponse {
        status: parts.status.as_u16(),
        headers: parts
            .headers
            .iter()
            .filter_map(|(k, v)| v.to_str().ok().map(|val| (k.to_string(), val.to_string())))
            .collect(),
        body: base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &body_bytes),
    };

    if let Ok(json) = serde_json::to_string(&cached) {
        if let Ok(mut conn) = state.redis.get().await {
            let _: Result<(), _> = conn.set_ex(cache_key, &json, ttl).await;
        }
    }

    Response::from_parts(parts, axum::body::Body::from(body_bytes))
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
        };
        let json = serde_json::to_string(&cached).unwrap();
        let decoded: CachedResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.status, 200);
    }
}
