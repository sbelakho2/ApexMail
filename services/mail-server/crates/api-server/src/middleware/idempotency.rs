//! Redis-backed idempotency for mutation endpoints.
//!
//! Key format:`apexmail:idempotency:{tenant_id}:{key}`
//! Stores the full serialised response for 24 h by default.

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
/// TTL of the in-flight claim marker. Long enough to cover any handler
/// execution, short enough that a crashed request cannot lock the key for
/// the full cache TTL.
const CLAIM_TTL_SECONDS: u64 = 30;
/// Value stored while a request with this key is executing. Not valid
/// `CachedResponse` JSON, so `lookup_cached` treats it as a miss.
const IN_PROGRESS_MARKER: &str = "in_progress";

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
/// 2. On miss, atomically claim the key (`SET ... NX EX 30`). A concurrent
///    duplicate gets `409 Conflict` + `Retry-After` instead of executing the
///    handler a second time (which would double-send emails).
/// 3. Let the request through, capture the response, and store it (releasing
///    the claim).
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

    // 2. Atomically claim the key. The check-then-execute race above allowed
    //    two concurrent duplicates to both miss the cache and both run the
    //    handler; `SET NX` makes the claim decision in one round-trip.
    let claimed = match claim_in_flight(&state, &cache_key).await {
        ClaimOutcome::Claimed => true,
        ClaimOutcome::RedisUnavailable => {
            // Best-effort only: proceed without a claim, matching the
            // middleware's behaviour when Redis is down for the cache.
            tracing::warn!(cache_key, "idempotency claim unavailable; proceeding unclaimed");
            false
        }
        ClaimOutcome::AlreadyInFlight => {
            // The key exists but is not necessarily in flight: a concurrent
            // request may have finished between our cache lookup and the
            // claim attempt, in which case the key now holds its stored
            // response. Serve that instead of bouncing a legitimate retry.
            if let Some(cached) = lookup_cached(&state, &cache_key).await {
                if principal_matches(current_user.as_ref(), &cached) {
                    tracing::debug!(
                        cache_key,
                        "idempotent response stored during claim race — returning it"
                    );
                    return cached_to_response(cached);
                }
            }
            tracing::warn!(
                cache_key,
                "idempotency key already in flight — rejecting concurrent duplicate"
            );
            return (
                StatusCode::CONFLICT,
                [
                    ("Retry-After", "1"),
                    ("Cache-Control", "no-store"),
                ],
                axum::Json(serde_json::json!({
                    "error": {
                        "code": "CONFLICT",
                        "message": "a request with this Idempotency-Key is already in flight; retry after a short delay"
                    }
                })),
            )
                .into_response();
        }
    };

    // 3. Execute the real handler
    let response = next.run(req).await;

    // 4. Store the response (overwrites — and therefore releases — the claim)
    store_response(&state, &cache_key, ttl, claimed, current_user, response).await
}

// ─── Helpers ───────────────────────────────────────────────────

fn extract_idempotency_key(headers: &HeaderMap) -> Option<String> {
    headers
        .get(IDEMPOTENCY_HEADER)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

enum ClaimOutcome {
    /// The key was claimed by this request.
    Claimed,
    /// Another request holds the claim right now.
    AlreadyInFlight,
    /// Redis is unavailable or errored — idempotency is best-effort, so the
    /// request proceeds unclaimed rather than failing hard.
    RedisUnavailable,
}

/// Atomically claim `key` for the current request.
///
/// `SET key "in_progress" NX EX 30` succeeds only when no other request holds
/// the key, so concurrent duplicates are deduplicated in a single round-trip.
async fn claim_in_flight(state: &AppState, key: &str) -> ClaimOutcome {
    let Ok(mut conn) = state.redis.get().await else {
        return ClaimOutcome::RedisUnavailable;
    };

    let claimed: Result<Option<()>, _> = deadpool_redis::redis::cmd("SET")
        .arg(key)
        .arg(IN_PROGRESS_MARKER)
        .arg("NX")
        .arg("EX")
        .arg(CLAIM_TTL_SECONDS)
        .query_async(&mut *conn)
        .await;

    match claimed {
        Ok(Some(())) => ClaimOutcome::Claimed,
        Ok(None) => ClaimOutcome::AlreadyInFlight,
        Err(error) => {
            tracing::warn!(key, error = %error, "idempotency claim write failed");
            ClaimOutcome::RedisUnavailable
        }
    }
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
    claimed: bool,
    current_user: Option<AuthUser>,
    resp: Response,
) -> Response {
    let (parts, body) = resp.into_parts();

    let cached_status = parts.status.as_u16();

    // Handler failure (5xx): a server error is not an idempotent result —
    // caching it would replay the failure to every retry for the full TTL.
    // Drop the claim instead so the client can re-execute immediately.
    if cached_status >= 500 {
        if claimed {
            release_claim(state, cache_key).await;
        }
        return Response::from_parts(parts, body);
    }

    let cached_headers: Vec<(String, String)> = parts
        .headers
        .iter()
        .filter_map(|(k, v)| {
            v.to_str()
                .ok()
                .map(|val| (k.to_string(), val.to_string()))
        })
        .collect();

    // Tee the body: forward every chunk to the client unchanged while
    // accumulating up to MAX_BODY_SIZE bytes for the idempotency cache.
    // A body larger than the cache limit is streamed through UNcached —
    // a successful response must never be replaced with an error merely
    // because it is too big to cache.
    let (mut tx, rx) =
        futures::channel::mpsc::channel::<Result<bytes::Bytes, std::io::Error>>(16);

    let store_state = state.clone();
    let store_key = cache_key.to_string();
    tokio::spawn(async move {
        use futures::SinkExt;
        use futures::StreamExt;

        let mut stream = body.into_data_stream();
        let mut buffer: Vec<u8> = Vec::new();
        let mut cacheable = true;

        while let Some(chunk) = stream.next().await {
            match chunk {
                Ok(bytes) => {
                    if cacheable && buffer.len() + bytes.len() > MAX_BODY_SIZE {
                        cacheable = false;
                        tracing::warn!(
                            cache_key = %store_key,
                            body_limit = MAX_BODY_SIZE,
                            "response exceeds idempotency cache limit — passing through uncached"
                        );
                    }
                    if cacheable {
                        buffer.extend_from_slice(&bytes);
                    }
                    if tx.send(Ok(bytes)).await.is_err() {
                        // Client dropped the response mid-body; a partial
                        // body must never be cached.
                        cacheable = false;
                        break;
                    }
                }
                Err(body_error) => {
                    cacheable = false;
                    let _ = tx
                        .send(Err(std::io::Error::other(body_error)))
                        .await;
                    break;
                }
            }
        }
        drop(tx);

        if cacheable {
            // L-06: Store the concrete authenticated principal so we can
            // re-validate subsequent requests against the same
            // API key/session/user.
            let principal_id = current_user.as_ref().map(principal_binding);
            let cached = CachedResponse {
                status: cached_status,
                headers: cached_headers,
                body: base64::Engine::encode(
                    &base64::engine::general_purpose::STANDARD,
                    &buffer,
                ),
                principal_id,
                user_id: current_user.as_ref().and_then(|u| u.user_id.clone()),
            };

            if let Ok(json) = serde_json::to_string(&cached) {
                if let Ok(mut conn) = store_state.redis.get().await {
                    let _: Result<(), _> = conn.set_ex(&store_key, &json, ttl).await;
                }
            }
        } else if claimed {
            // The stored response was never written, so release the in-flight
            // claim instead of 409-ing retries for the remaining claim TTL.
            release_claim(&store_state, &store_key).await;
        }
    });

    Response::from_parts(parts, axum::body::Body::from_stream(rx))
}

/// Release an in-flight claim (`DEL key`) so retries can re-execute the
/// handler instead of receiving 409s for the rest of the claim TTL.
async fn release_claim(state: &AppState, cache_key: &str) {
    if let Ok(mut conn) = state.redis.get().await {
        let _: Result<(), _> = conn.del(cache_key).await;
    }
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
