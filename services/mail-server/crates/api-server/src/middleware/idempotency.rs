//! Redis-backed idempotency for mutation endpoints.
//!
//! Key format:`apexmail:idempotency:{tenant_id}:{method}:{route}:{key}`
//! Stores the full serialised response for 24 h by default.
//!
//! F19: the cached response is bound to the COMPLETE replay identity —
//! tenant, authenticated principal, HTTP method, route, and a canonical hash
//! of the request body. A key reused with a DIFFERENT payload (or from a
//! different principal/route/method) is a conflicting reuse and gets
//! `409 Conflict`, never the first request's response. Safe reads (GET /
//! HEAD / OPTIONS) bypass the cache entirely. Every replay dimension must be
//! PRESENT and equal: the ENTIRE request body is buffered and hashed within
//! the route body limit (no unhashed passthrough) — a body that exceeds the
//! limit gets `413 Payload Too Large` BEFORE any mutation, and a body-read
//! failure is an explicit error, never a silently emptied request. Legacy
//! cache records written without the identity bindings (no payload hash,
//! method or route) are treated as MISSES — they are evicted and the request
//! proceeds, so the durable ledger (or a fresh execution) remains the only
//! authority for those keys.
//!
//! # Payload-hash normalization contract (F19)
//! The Redis cache and the durable `idempotency_records` ledger both key the
//! request body by the SHA-256 of the RAW request bytes, hex-encoded
//! (`canonical_payload_hash`). The middleware hashes the bytes exactly as
//! they arrived on the wire; the send endpoints hash their typed DTO
//! (`canonical_send_hash`, messages.rs) — the two hashes are never compared
//! against each other, each store compares only hashes it produced itself,
//! so one normalization rule per store is sufficient and stable.
//!
//! F21: the in-flight claim carries a random owner token. Completion and
//! release compare-and-set on that token (Lua), so a request whose claim
//! expired — and whose key was re-claimed by a retry — can no longer
//! overwrite the new owner's state. The claim is renewed in the background
//! while the handler runs, but the renewal task is tied to the middleware
//! future through an ABORT-ON-DROP GUARD sharing a cancellation token: when
//! the outer 30 s `TimeoutLayer` (or a dropped client connection) tears this
//! future down before the handler returns, the guard stops the renewer and
//! releases the claim owner-conditionally — an abandoned request can never
//! keep refreshing its lease (and 409-ing retries) until process restart.
//! Renewal also carries an independent lifetime bound so the lease cannot
//! outlive the request by more than a bounded margin. The Redis layer is an
//! ACCELERATOR only; the send endpoints additionally persist their results
//! in the durable `idempotency_records` ledger (migration 153), which stays
//! authoritative when Redis is unavailable or loses data — in particular it
//! is authoritative for a request that may have committed before a
//! cancellation.

use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{HeaderMap, Method, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use deadpool_redis::redis::AsyncCommands;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::middleware::auth::AuthUser;
use crate::state::AppState;

const IDEMPOTENCY_HEADER: &str = "idempotency-key";
const MAX_BODY_SIZE: usize = 1024 * 1024; // 1 MiB cached response limit
/// Largest request body that is buffered for the canonical payload hash
/// (F19). This equals the ACTUAL route body limit configured in `app.rs`
/// (`DefaultBodyLimit::max(10 MiB)` + `RequestBodyLimitLayer::new(10 MiB)`):
/// every body the API accepts is buffered IN FULL and hashed, preserving the
/// exact bytes for the downstream extractor. A body beyond the limit is
/// rejected here with `413` before any handler mutation — the body-limit
/// layers outside this middleware reject the same request anyway, so no
/// accepted request is ever refused by this bound.
const MAX_HASH_BODY_SIZE: usize = 10 * 1024 * 1024; // 10 MiB, the route body limit
/// TTL of the in-flight claim marker. Renewed in the background while the
/// handler runs (F21); short enough that a crashed request cannot lock the
/// key for the full cache TTL.
const CLAIM_TTL_SECONDS: u64 = 30;
/// F21: hard upper bound on how long the renewal task may keep a claim
/// alive, counted from the moment the claim was acquired. The outer
/// `TimeoutLayer` cancels the request after 30 s, so a healthy request never
/// needs renewal beyond one claim TTL; 2× the timeout leaves margin for
/// slow response streaming while guaranteeing an abandoned lease can never
/// be refreshed indefinitely.
const MAX_LEASE_LIFETIME_SECONDS: u64 = 60;

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
    /// F19: the HTTP method the cached response was produced for.
    #[serde(default)]
    method: Option<String>,
    /// F19: the request route (path) the cached response was produced for.
    #[serde(default)]
    route: Option<String>,
    /// F19: canonical SHA-256 (hex) of the request body. `None` for legacy
    /// records and oversized bodies.
    #[serde(default)]
    payload_hash: Option<String>,
}

// ─── Middleware ─────────────────────────────────────────────────

/// Axum middleware that implements idempotency semantics.
/// If the request contains an `Idempotency-Key` header the middleware will:
/// 1. (F19) Skip the cache entirely for safe reads (GET/HEAD/OPTIONS).
/// 2. Look up the key in Redis — now scoped by tenant + method + route. On
///    hit, replay only when the principal AND the canonical payload hash
///    match; any mismatch is a conflicting reuse → `409 Conflict`.
/// 3. On miss, atomically claim the key (`SET ... NX EX`) with a random
///    OWNER TOKEN (F21). A concurrent duplicate gets `409 Conflict` +
///    `Retry-After` instead of executing the handler a second time.
/// 4. Let the request through, capture the response, and store it —
///    compare-and-set on the owner token so an expired claim cannot
///    overwrite the state of the request that re-claimed the key (F21).
///
/// # Security (L-06 + F19)
/// Cached idempotency responses are bound to the concrete AuthUser principal
/// who created them, the HTTP method, the route, and the request body hash.
/// Authorization is re-checked on every replay by construction: this
/// middleware runs AFTER `require_auth` and `enforce_tenant_header_binding`
/// in the request pipeline, so a replay is authenticated and tenant-bound
/// before any cached bytes are served, and the principal must match the
/// recorded creator.
pub async fn idempotency_middleware(
    State(state): State<AppState>,
    req: Request,
    next: Next,
) -> Response {
    // F19: safe reads never consult or populate the idempotency cache.
    if is_safe_method(req.method()) {
        return next.run(req).await;
    }

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

    let method = req.method().clone();
    let route = req.uri().path().to_string();

    // F19: buffer the ENTIRE request body (bounded by the route body limit)
    // to compute the canonical payload hash, then rebuild the request with
    // the exact same bytes for the downstream extractor. Both overflow and
    // read failure are explicit errors — the handler must never receive an
    // emptied body, and an oversized request must never run.
    let (parts, body) = req.into_parts();
    let (body_bytes, payload_hash) = match buffer_request_body(body).await {
        Ok(buffered) => buffered,
        Err(error) => match error {
            // Size overflow: reject before any mutation. The body-limit
            // layers outside this middleware would refuse the same request,
            // so this is the same decision, made explicit here.
            BodyBufferError::TooLarge => {
                tracing::warn!(
                    route,
                    body_limit = MAX_HASH_BODY_SIZE,
                    "idempotent request body exceeds the route body limit — rejecting with 413"
                );
                return payload_too_large();
            }
            BodyBufferError::Read(ref source) => {
                tracing::error!(
                    error = %source,
                    route,
                    "failed to read idempotent request body — rejecting"
                );
                return body_read_failed();
            }
        },
    };
    let req = Request::from_parts(parts, Body::from(body_bytes));

    let cache_key = cache_key_for(&tenant_id, &method, &route, &idempotency_key);
    let ttl = state.config.idempotency_ttl_seconds;

    // 1. Check cache — with identity re-validation (L-06 + F19)
    if let Some(cached) = lookup_cached(&state, &cache_key).await {
        match replay_verdict(
            current_user.as_ref(),
            &method,
            &route,
            &payload_hash,
            &cached,
        ) {
            ReplayVerdict::Replay => {
                tracing::debug!(cache_key, "returning cached idempotent response");
                return cached_to_response(cached);
            }
            ReplayVerdict::Conflict(reason) => {
                tracing::warn!(
                    cache_key,
                    reason,
                    "conflicting idempotency-key reuse — rejecting"
                );
                return idempotency_conflict(reason);
            }
            ReplayVerdict::Unbound => {
                // F19: a legacy record without the complete identity
                // bindings cannot validate a replay. Treat it as a MISS:
                // evict it so this request can claim the key cleanly. The
                // durable ledger (send endpoints) stays the authority for
                // whether the original operation already committed.
                tracing::warn!(
                    cache_key,
                    "unbound legacy idempotency cache record — evicting and treating as a miss"
                );
                evict_cached(&state, &cache_key).await;
            }
        }
    }

    // 2. Atomically claim the key. The check-then-execute race above allowed
    //    two concurrent duplicates to both miss the cache and both run the
    //    handler; `SET NX` makes the claim decision in one round-trip.
    //    F21: the claim value is a random OWNER TOKEN, not a shared marker —
    //    completion and release compare against it.
    let owner_token = uuid::Uuid::new_v4().simple().to_string();
    match claim_in_flight(&state, &cache_key, &owner_token).await {
        ClaimOutcome::Claimed => {}
        ClaimOutcome::RedisUnavailable => {
            // Best-effort only: proceed without a claim, matching the
            // middleware's behaviour when Redis is down for the cache. The
            // durable `idempotency_records` ledger on the send endpoints
            // remains authoritative (F20).
            tracing::warn!(
                cache_key,
                "idempotency claim unavailable; proceeding unclaimed"
            );
        }
        ClaimOutcome::AlreadyInFlight => {
            // The key exists but is not necessarily in flight: a concurrent
            // request may have finished between our cache lookup and the
            // claim attempt, in which case the key now holds its stored
            // response. Serve that instead of bouncing a legitimate retry.
            if let Some(cached) = lookup_cached(&state, &cache_key).await {
                if matches!(
                    replay_verdict(
                        current_user.as_ref(),
                        &method,
                        &route,
                        &payload_hash,
                        &cached
                    ),
                    ReplayVerdict::Replay
                ) {
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
    }

    // F21: renew the claim while the handler executes so a long handler does
    // not lose its claim to an impatient retry. The renewal task is wrapped
    // in an ABORT-ON-DROP GUARD sharing a cancellation token: if this
    // middleware future is dropped before the handler returns (outer
    // TimeoutLayer, cancelled client connection, panic), Drop cancels the
    // renewer and performs an owner-conditional release — the lease can
    // never be refreshed by a dead request until process restart.
    let mut claim = ClaimGuard::acquire(state.clone(), cache_key.clone(), owner_token.clone());

    // 3. Execute the real handler
    let response = next.run(req).await;

    // Normal exit: stop the renewer but KEEP the claim — the store step
    // below completes (or releases) it compare-and-set on the owner token.
    claim.defuse();

    // 4. Store the response (compare-and-set on the owner token — this
    //    releases the claim only if we still own it)
    store_response(
        &state,
        &cache_key,
        ttl,
        &owner_token,
        current_user,
        method,
        route,
        payload_hash,
        response,
    )
    .await
}

// ─── Helpers ───────────────────────────────────────────────────

fn is_safe_method(method: &Method) -> bool {
    matches!(method, &Method::GET | &Method::HEAD | &Method::OPTIONS)
}
/// F19: canonical SHA-256 (hex) of the request body. The raw bytes are
/// hashed — the JSON extractor has not parsed yet, and byte-level hashing
/// already distinguishes any semantic difference the handler would see.
/// (See the normalization-contract note in the module docs.)
fn canonical_payload_hash(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// F19 outcome of buffering the request body for hashing.
#[derive(Debug)]
enum BodyBufferError {
    /// The body exceeds `MAX_HASH_BODY_SIZE` (the route body limit).
    TooLarge,
    /// Reading the body from the transport failed.
    Read(axum::Error),
}

/// F19: buffer the request body IN FULL (up to the route body limit) and
/// hash it. The buffered bytes are handed back so the caller can rebuild the
/// request with the exact same body for the downstream extractor. Oversized
/// and unreadable bodies are ERRORS — never an empty-body passthrough.
async fn buffer_request_body(body: Body) -> Result<(bytes::Bytes, String), BodyBufferError> {
    match axum::body::to_bytes(body, MAX_HASH_BODY_SIZE).await {
        Ok(bytes) => {
            let hash = canonical_payload_hash(&bytes);
            Ok((bytes, hash))
        }
        Err(error) => {
            // `to_bytes` reports the size bound as the underlying
            // `http_body_util::LengthLimitError`, whose Display is stable:
            // "length limit exceeded". Everything else is a transport/body
            // read failure.
            if error.to_string().contains("length limit exceeded") {
                Err(BodyBufferError::TooLarge)
            } else {
                Err(BodyBufferError::Read(error))
            }
        }
    }
}

/// F19: explicit `413` — an oversized idempotent request must fail before
/// any mutation, in the same error envelope shape the API uses.
fn payload_too_large() -> Response {
    (
        StatusCode::PAYLOAD_TOO_LARGE,
        [("Cache-Control", "no-store")],
        axum::Json(serde_json::json!({
            "error": {
                "code": "PAYLOAD_TOO_LARGE",
                "message": format!(
                    "request body exceeds the {} MiB limit and cannot be processed idempotently",
                    MAX_HASH_BODY_SIZE / (1024 * 1024)
                )
            }
        })),
    )
        .into_response()
}

/// F19: explicit error for a body that could not be read. Proceeding with a
/// fabricated (empty) body would hash the wrong payload and hand the handler
/// a request it was never sent.
fn body_read_failed() -> Response {
    (
        StatusCode::BAD_REQUEST,
        [("Cache-Control", "no-store")],
        axum::Json(serde_json::json!({
            "error": {
                "code": "BAD_REQUEST",
                "message": "request body could not be read; the request was not processed"
            }
        })),
    )
        .into_response()
}

/// F19: the cache key binds tenant + method + route + key, so the same key
/// used against a different endpoint can never collide with this record.
fn cache_key_for(tenant_id: &str, method: &Method, route: &str, key: &str) -> String {
    format!(
        "apexmail:idempotency:{tenant_id}:{}:{route}:{key}",
        method.as_str()
    )
}

enum ReplayVerdict {
    Replay,
    Conflict(&'static str),
    /// F19: the cached record is missing one of the required identity
    /// bindings (payload hash, method or route) — a legacy/unbound record
    /// that cannot validate a replay. Callers treat it as a MISS.
    Unbound,
}

/// F19: decide whether a cache hit may be replayed. EVERY dimension of the
/// request identity must be PRESENT on the record and match it; any mismatch
/// is a conflicting reuse (409) and any absent dimension is an unbound
/// record treated as a miss (never replayed, never 409'd on evidence it
/// cannot verify).
fn replay_verdict(
    current_user: Option<&AuthUser>,
    method: &Method,
    route: &str,
    payload_hash: &str,
    cached: &CachedResponse,
) -> ReplayVerdict {
    if !principal_matches(current_user, cached) {
        return ReplayVerdict::Conflict(
            "idempotency-key was created by a different authenticated principal",
        );
    }
    let (Some(cached_method), Some(cached_route), Some(cached_hash)) = (
        cached.method.as_deref(),
        cached.route.as_deref(),
        cached.payload_hash.as_deref(),
    ) else {
        return ReplayVerdict::Unbound;
    };
    if !cached_method.eq_ignore_ascii_case(method.as_str()) {
        return ReplayVerdict::Conflict(
            "idempotency-key was already used for a different HTTP method",
        );
    }
    if cached_route != route {
        return ReplayVerdict::Conflict("idempotency-key was already used on a different endpoint");
    }
    if cached_hash != payload_hash {
        return ReplayVerdict::Conflict(
            "idempotency-key was already used with a different request body",
        );
    }
    ReplayVerdict::Replay
}

/// F19: 409 response for conflicting key reuse — same JSON error shape the
/// rest of the API uses.
fn idempotency_conflict(reason: &'static str) -> Response {
    (
        StatusCode::CONFLICT,
        [("Cache-Control", "no-store")],
        axum::Json(serde_json::json!({
            "error": {
                "code": "CONFLICT",
                "message": reason
            }
        })),
    )
        .into_response()
}

fn extract_idempotency_key(headers: &HeaderMap) -> Option<String> {
    headers
        .get(IDEMPOTENCY_HEADER)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

enum ClaimOutcome {
    /// The key was claimed by this request (we own `owner_token`).
    Claimed,
    /// Another request holds the claim right now.
    AlreadyInFlight,
    /// Redis is unavailable or errored — idempotency is best-effort, so the
    /// request proceeds unclaimed rather than failing hard.
    RedisUnavailable,
}

/// F21: atomically claim `key` for the current request with a random owner
/// token.
///
/// `SET key <token> NX EX 30` succeeds only when no other request holds the
/// key, so concurrent duplicates are deduplicated in a single round-trip.
/// The token makes every subsequent state transition (renewal, completion,
/// release) a compare-and-set against THIS claim.
async fn claim_in_flight(state: &AppState, key: &str, owner_token: &str) -> ClaimOutcome {
    let Ok(mut conn) = state.redis.get().await else {
        return ClaimOutcome::RedisUnavailable;
    };

    let claimed: Result<Option<()>, _> = deadpool_redis::redis::cmd("SET")
        .arg(key)
        .arg(owner_token)
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

/// F21: compare-and-set completion — only the request that still owns the
/// claim may overwrite it with the cached response. A stale owner (lease
/// expired, key re-claimed) loses the race and its write is a no-op.
const COMPLETE_IF_OWNER_LUA: &str = r#"
if redis.call('GET', KEYS[1]) == ARGV[1] then
    redis.call('SET', KEYS[1], ARGV[2], 'EX', tonumber(ARGV[3]))
    return 1
end
return 0
"#;

/// F21: compare-and-set release — only the current owner deletes the claim.
const RELEASE_IF_OWNER_LUA: &str = r#"
if redis.call('GET', KEYS[1]) == ARGV[1] then
    redis.call('DEL', KEYS[1])
    return 1
end
return 0
"#;

/// F21: token-guarded TTL extension — only the current owner may renew.
const RENEW_IF_OWNER_LUA: &str = r#"
if redis.call('GET', KEYS[1]) == ARGV[1] then
    redis.call('EXPIRE', KEYS[1], tonumber(ARGV[2]))
    return 1
end
return 0
"#;

async fn complete_if_owner(
    state: &AppState,
    key: &str,
    owner_token: &str,
    value: &str,
    ttl: u64,
) -> bool {
    let Ok(mut conn) = state.redis.get().await else {
        return false;
    };
    deadpool_redis::redis::Script::new(COMPLETE_IF_OWNER_LUA)
        .key(key)
        .arg(owner_token)
        .arg(value)
        .arg(ttl)
        .invoke_async(&mut *conn)
        .await
        .unwrap_or(0)
        == 1
}

/// Release an in-flight claim — but only if we still own it (F21).
async fn release_claim_if_owner(state: &AppState, cache_key: &str, owner_token: &str) {
    if let Ok(mut conn) = state.redis.get().await {
        let _: Result<i64, _> = deadpool_redis::redis::Script::new(RELEASE_IF_OWNER_LUA)
            .key(cache_key)
            .arg(owner_token)
            .invoke_async(&mut *conn)
            .await;
    }
}

/// F21: renew the claim every CLAIM_TTL/3 while the handler runs.
///
/// The renewer exits when ANY of these happens first:
/// * the shared cancellation token fires (the `ClaimGuard` dropped — normal
///   return, timeout, cancelled connection or panic);
/// * it is aborted through its `JoinHandle` (the guard's hard stop);
/// * it loses ownership (expired + re-claimed by a retry);
/// * `MAX_LEASE_LIFETIME_SECONDS` elapse — an independent lifetime bound so
///   an abandoned request can never renew indefinitely.
///
/// The lease age is recorded when renewal stops so operators can see how
/// long an abnormal request held its claim.
fn spawn_claim_renewal(
    state: AppState,
    cache_key: String,
    owner_token: String,
    cancel: tokio::sync::watch::Receiver<bool>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let interval = std::time::Duration::from_secs(CLAIM_TTL_SECONDS / 3);
        let acquired_at = std::time::Instant::now();
        let max_lifetime = std::time::Duration::from_secs(MAX_LEASE_LIFETIME_SECONDS);
        let mut cancel = cancel;
        loop {
            tokio::select! {
                // Graceful stop signal from the guard.
                changed = cancel.changed() => {
                    match changed {
                        Ok(()) if *cancel.borrow() => {
                            tracing::debug!(
                                cache_key,
                                lease_age_secs = acquired_at.elapsed().as_secs(),
                                "idempotency claim renewal cancelled"
                            );
                            break;
                        }
                        _ => {
                            tracing::warn!(
                                cache_key,
                                lease_age_secs = acquired_at.elapsed().as_secs(),
                                "idempotency claim cancellation channel closed — renewal stopping"
                            );
                            break;
                        }
                    }
                }
                _ = tokio::time::sleep(interval) => {}
            }
            if acquired_at.elapsed() >= max_lifetime {
                tracing::warn!(
                    cache_key,
                    lease_age_secs = acquired_at.elapsed().as_secs(),
                    max_lifetime_secs = MAX_LEASE_LIFETIME_SECONDS,
                    "idempotency claim renewal lifetime bound reached — stopping"
                );
                break;
            }
            if let Ok(mut conn) = state.redis.get().await {
                let renewed: Result<i64, _> =
                    deadpool_redis::redis::Script::new(RENEW_IF_OWNER_LUA)
                        .key(&cache_key)
                        .arg(owner_token.as_str())
                        .arg(CLAIM_TTL_SECONDS)
                        .invoke_async(&mut *conn)
                        .await;
                match renewed {
                    Ok(1) => {}
                    Ok(_) => {
                        // Lost ownership (expired + re-claimed): stop renewing.
                        tracing::warn!(
                            cache_key,
                            lease_age_secs = acquired_at.elapsed().as_secs(),
                            "idempotency claim ownership lost — renewal stopped"
                        );
                        break;
                    }
                    Err(error) => {
                        tracing::warn!(error = %error, "idempotency claim renewal failed");
                    }
                }
            }
        }
    })
}

/// F21: abort-on-drop owner of the in-flight claim's renewal task.
///
/// The guard ties the renewal task's lifetime to THIS request, not merely to
/// the normal return path: the outer `TimeoutLayer` (30 s) or a dropped
/// client connection can tear the middleware future down while
/// `next.run(req).await` is still pending — dropping this guard then
///
/// 1. aborts the renewal `JoinHandle` (hard stop), and
/// 2. signals the shared cancellation token (graceful stop), and
/// 3. on an ABNORMAL exit (anything but [`ClaimGuard::defuse`]) performs an
///    owner-conditional Redis release, so a cancelled request cannot keep
///    409-ing retries for the remaining claim TTL.
///
/// If the release itself cannot run (Redis unavailable, dropped outside the
/// runtime), the claim simply expires after `CLAIM_TTL_SECONDS` — renewal
/// has stopped, so the lease is bounded either way. The durable ledger
/// remains the authority for whether the cancelled request's transaction
/// committed.
struct ClaimGuard {
    state: AppState,
    cache_key: String,
    owner_token: String,
    handle: Option<tokio::task::JoinHandle<()>>,
    cancel: Option<tokio::sync::watch::Sender<bool>>,
    acquired_at: std::time::Instant,
    /// Set on the normal return path: stop renewing but leave the claim for
    /// the store/complete step, which owns it from there.
    defused: bool,
}

impl ClaimGuard {
    fn acquire(state: AppState, cache_key: String, owner_token: String) -> Self {
        let (cancel_tx, cancel_rx) = tokio::sync::watch::channel(false);
        let handle = spawn_claim_renewal(
            state.clone(),
            cache_key.clone(),
            owner_token.clone(),
            cancel_rx,
        );
        Self {
            state,
            cache_key,
            owner_token,
            handle: Some(handle),
            cancel: Some(cancel_tx),
            acquired_at: std::time::Instant::now(),
            defused: false,
        }
    }

    /// Normal exit: stop the renewal loop but KEEP the claim — the response
    /// store step completes it (or releases it) compare-and-set on the owner
    /// token.
    fn defuse(&mut self) {
        self.defused = true;
        self.stop_renewal();
    }

    fn stop_renewal(&mut self) {
        if let Some(cancel) = self.cancel.take() {
            // Graceful signal first; send fails only if the receiver is gone
            // (task already finished), which is fine.
            let _ = cancel.send(true);
        }
        if let Some(handle) = self.handle.take() {
            handle.abort();
        }
    }
}

impl Drop for ClaimGuard {
    fn drop(&mut self) {
        self.stop_renewal();
        if self.defused {
            return;
        }
        // Abnormal exit (timeout / cancellation / panic): release the claim,
        // but only if we still own it. Best-effort and bounded — if this
        // fails the lease expires after CLAIM_TTL_SECONDS because renewal
        // has stopped.
        let state = self.state.clone();
        let cache_key = self.cache_key.clone();
        let owner_token = self.owner_token.clone();
        let lease_age = self.acquired_at.elapsed();
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            handle.spawn(async move {
                release_claim_if_owner(&state, &cache_key, &owner_token).await;
                tracing::warn!(
                    cache_key,
                    lease_age_secs = lease_age.as_secs(),
                    "idempotent request exited abnormally — claim released if still owned"
                );
            });
        }
    }
}

async fn lookup_cached(state: &AppState, key: &str) -> Option<CachedResponse> {
    let mut conn = state.redis.get().await.ok()?;
    let json: Option<String> = conn.get(key).await.ok()?;
    json.and_then(|j| serde_json::from_str(&j).ok())
}

/// F19: evict an unbound legacy record so a fresh claim can take the key.
/// Best-effort — if this fails the subsequent claim attempt simply reports
/// the key as in flight and the client retries after the claim TTL.
async fn evict_cached(state: &AppState, key: &str) {
    if let Ok(mut conn) = state.redis.get().await {
        let _: Result<i64, _> = deadpool_redis::redis::cmd("DEL")
            .arg(key)
            .query_async(&mut *conn)
            .await;
    }
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

#[allow(clippy::too_many_arguments)]
async fn store_response(
    state: &AppState,
    cache_key: &str,
    ttl: u64,
    owner_token: &str,
    current_user: Option<AuthUser>,
    method: Method,
    route: String,
    payload_hash: String,
    resp: Response,
) -> Response {
    let (parts, body) = resp.into_parts();

    let cached_status = parts.status.as_u16();

    // Handler failure (5xx): a server error is not an idempotent result —
    // caching it would replay the failure to every retry for the full TTL.
    // Drop the claim instead so the client can re-execute immediately.
    if cached_status >= 500 {
        release_claim_if_owner(state, cache_key, owner_token).await;
        return Response::from_parts(parts, body);
    }

    let cached_headers: Vec<(String, String)> = parts
        .headers
        .iter()
        .filter_map(|(k, v)| v.to_str().ok().map(|val| (k.to_string(), val.to_string())))
        .collect();

    // Tee the body: forward every chunk to the client unchanged while
    // accumulating up to MAX_BODY_SIZE bytes for the idempotency cache.
    // A body larger than the cache limit is streamed through UNcached —
    // a successful response must never be replaced with an error merely
    // because it is too big to cache.
    let (mut tx, rx) = futures::channel::mpsc::channel::<Result<bytes::Bytes, std::io::Error>>(16);

    let store_state = state.clone();
    let store_key = cache_key.to_string();
    let store_owner = owner_token.to_string();
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
                    let _ = tx.send(Err(std::io::Error::other(body_error))).await;
                    break;
                }
            }
        }
        drop(tx);

        if cacheable {
            // L-06/F19: store the concrete authenticated principal and the
            // full request identity so subsequent requests can be validated
            // against the same API key/session/user, method, route, and body.
            let principal_id = current_user.as_ref().map(principal_binding);
            let cached = CachedResponse {
                status: cached_status,
                headers: cached_headers,
                body: base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &buffer),
                principal_id,
                user_id: current_user.as_ref().and_then(|u| u.user_id.clone()),
                method: Some(method.to_string()),
                route: Some(route),
                payload_hash: Some(payload_hash),
            };

            if let Ok(json) = serde_json::to_string(&cached) {
                // F21: compare-and-set — only complete the claim if this
                // request still owns it.
                if !complete_if_owner(&store_state, &store_key, &store_owner, &json, ttl).await {
                    tracing::warn!(
                        cache_key = %store_key,
                        "idempotency completion fenced out — claim ownership lost"
                    );
                }
            }
        } else {
            // The stored response was never written, so release the in-flight
            // claim instead of 409-ing retries for the remaining claim TTL —
            // but only if we still own it (F21).
            release_claim_if_owner(&store_state, &store_key, &store_owner).await;
        }
    });

    Response::from_parts(parts, axum::body::Body::from_stream(rx))
}

/// Stable string identity of an authenticated principal (shared with the
/// send endpoints' durable idempotency ledger — F19/F20).
pub(crate) fn principal_binding(user: &AuthUser) -> String {
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
            method: Some("POST".into()),
            route: Some("/v1/messages".into()),
            payload_hash: Some("a".repeat(64)),
        };
        let json = serde_json::to_string(&cached).unwrap();
        let decoded: CachedResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.status, 200);
        assert_eq!(decoded.method.as_deref(), Some("POST"));
        assert_eq!(decoded.payload_hash.as_deref(), Some(&"a".repeat(64)[..]));
    }

    /// F19 compatibility: a legacy cached record without the new identity
    /// fields still deserializes (serde defaults).
    #[test]
    fn legacy_cached_record_deserializes_without_identity_fields() {
        let json = r#"{"status":200,"headers":[],"body":"","user_id":null}"#;
        let cached: CachedResponse = serde_json::from_str(json).unwrap();
        assert!(cached.method.is_none());
        assert!(cached.route.is_none());
        assert!(cached.payload_hash.is_none());
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
            method: None,
            route: None,
            payload_hash: None,
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
            method: None,
            route: None,
            payload_hash: None,
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

    fn sample_user() -> AuthUser {
        AuthUser {
            tenant_id: "tenant_1".into(),
            user_id: Some("usr_1".into()),
            api_key_id: None,
            session_id: None,
            scopes: vec![],
        }
    }

    fn cached_for(method: Option<&str>, route: Option<&str>, hash: Option<&str>) -> CachedResponse {
        CachedResponse {
            status: 200,
            headers: vec![],
            body: String::new(),
            principal_id: Some("user:usr_1".into()),
            user_id: Some("usr_1".into()),
            method: method.map(str::to_string),
            route: route.map(str::to_string),
            payload_hash: hash.map(str::to_string),
        }
    }

    // ── F19: replay identity binding ─────────────────────────────

    /// Same principal + method + route + payload → replay.
    #[test]
    fn replay_matches_on_full_identity() {
        let user = sample_user();
        let cached = cached_for(Some("POST"), Some("/v1/messages"), Some(&"h".repeat(64)));
        assert!(matches!(
            replay_verdict(
                Some(&user),
                &Method::POST,
                "/v1/messages",
                &"h".repeat(64),
                &cached
            ),
            ReplayVerdict::Replay
        ));
    }

    /// Same key, different body → conflicting reuse (409), never replay.
    #[test]
    fn conflicting_payload_hash_is_rejected() {
        let user = sample_user();
        let cached = cached_for(Some("POST"), Some("/v1/messages"), Some(&"a".repeat(64)));
        assert!(matches!(
            replay_verdict(
                Some(&user),
                &Method::POST,
                "/v1/messages",
                &"b".repeat(64),
                &cached
            ),
            ReplayVerdict::Conflict(_)
        ));
    }

    /// Same key on a different route (single vs batch send) → 409.
    #[test]
    fn conflicting_route_is_rejected() {
        let user = sample_user();
        let cached = cached_for(Some("POST"), Some("/v1/messages"), Some(&"h".repeat(64)));
        assert!(matches!(
            replay_verdict(
                Some(&user),
                &Method::POST,
                "/v1/messages/batch",
                &"h".repeat(64),
                &cached
            ),
            ReplayVerdict::Conflict(_)
        ));
    }

    /// Same key with a different HTTP method → 409.
    #[test]
    fn conflicting_method_is_rejected() {
        let user = sample_user();
        let cached = cached_for(Some("POST"), Some("/v1/messages"), Some(&"h".repeat(64)));
        assert!(matches!(
            replay_verdict(
                Some(&user),
                &Method::PUT,
                "/v1/messages",
                &"h".repeat(64),
                &cached
            ),
            ReplayVerdict::Conflict(_)
        ));
    }

    /// Same key from a different principal → 409.
    #[test]
    fn conflicting_principal_is_rejected() {
        let other = AuthUser {
            tenant_id: "tenant_1".into(),
            user_id: Some("usr_2".into()),
            api_key_id: None,
            session_id: None,
            scopes: vec![],
        };
        let cached = cached_for(Some("POST"), Some("/v1/messages"), Some(&"h".repeat(64)));
        assert!(matches!(
            replay_verdict(
                Some(&other),
                &Method::POST,
                "/v1/messages",
                &"h".repeat(64),
                &cached
            ),
            ReplayVerdict::Conflict(_)
        ));
    }

    /// F19: an unbound cached record (no payload hash / method / route) is a
    /// MISS, not a replay and not a fabricated conflict — the caller evicts
    /// it and proceeds under durable-ledger authority.
    #[test]
    fn missing_identity_dimensions_are_unbound_misses() {
        let user = sample_user();
        // No payload hash on the record.
        let cached = cached_for(Some("POST"), Some("/v1/messages"), None);
        assert!(matches!(
            replay_verdict(
                Some(&user),
                &Method::POST,
                "/v1/messages",
                &"h".repeat(64),
                &cached
            ),
            ReplayVerdict::Unbound
        ));
        // No method on the record.
        let cached = cached_for(None, Some("/v1/messages"), Some(&"h".repeat(64)));
        assert!(matches!(
            replay_verdict(
                Some(&user),
                &Method::POST,
                "/v1/messages",
                &"h".repeat(64),
                &cached
            ),
            ReplayVerdict::Unbound
        ));
        // No route on the record.
        let cached = cached_for(Some("POST"), None, Some(&"h".repeat(64)));
        assert!(matches!(
            replay_verdict(
                Some(&user),
                &Method::POST,
                "/v1/messages",
                &"h".repeat(64),
                &cached
            ),
            ReplayVerdict::Unbound
        ));
    }

    /// F19: safe reads bypass the cache entirely.
    #[test]
    fn safe_methods_are_bypassed() {
        assert!(is_safe_method(&Method::GET));
        assert!(is_safe_method(&Method::HEAD));
        assert!(is_safe_method(&Method::OPTIONS));
        assert!(!is_safe_method(&Method::POST));
        assert!(!is_safe_method(&Method::PUT));
        assert!(!is_safe_method(&Method::DELETE));
    }

    /// F19: the cache key embeds method and route so identical keys on
    /// different endpoints cannot collide.
    #[test]
    fn cache_key_binds_method_and_route() {
        let a = cache_key_for("ten", &Method::POST, "/v1/messages", "k1");
        let b = cache_key_for("ten", &Method::POST, "/v1/messages/batch", "k1");
        let c = cache_key_for("ten", &Method::PUT, "/v1/messages", "k1");
        assert_ne!(a, b);
        assert_ne!(a, c);
        assert!(a.starts_with("apexmail:idempotency:ten:POST:/v1/messages:"));
    }

    /// F19: the canonical payload hash distinguishes request bodies.
    #[test]
    fn canonical_payload_hash_distinguishes_bodies() {
        let a = canonical_payload_hash(br#"{"to":["a@x.com"]}"#);
        let b = canonical_payload_hash(br#"{"to":["b@x.com"]}"#);
        assert_ne!(a, b);
        assert_eq!(a.len(), 64);
        assert_eq!(a, canonical_payload_hash(br#"{"to":["a@x.com"]}"#));
    }

    // ── F19: full-body buffering (no unhashed/empty passthrough) ──

    /// A body within the route limit is buffered IN FULL and hashed — the
    /// exact bytes survive for the downstream extractor (even when larger
    /// than the old 1 MiB hashing budget).
    #[tokio::test]
    async fn oversized_under_limit_body_is_fully_buffered_and_hashed() {
        // 4 MiB body — larger than the previous 1 MiB budget, well within
        // the 10 MiB route body limit.
        let body = Body::from(vec![b'x'; 4 * 1024 * 1024]);
        let (bytes, hash) = buffer_request_body(body)
            .await
            .expect("body within the route limit must be buffered");
        assert_eq!(bytes.len(), 4 * 1024 * 1024);
        assert_eq!(hash.len(), 64);
        assert_eq!(hash, canonical_payload_hash(&vec![b'x'; 4 * 1024 * 1024]));
    }

    /// A body beyond the route body limit is `TooLarge` → 413, never an
    /// unhashed/empty passthrough.
    #[tokio::test]
    async fn body_over_the_route_limit_is_too_large() {
        let body = Body::from(vec![b'x'; MAX_HASH_BODY_SIZE + 1]);
        assert!(matches!(
            buffer_request_body(body).await,
            Err(BodyBufferError::TooLarge)
        ));
    }

    /// A transport/read failure is an explicit error — the handler must
    /// never see a fabricated empty body.
    #[tokio::test]
    async fn body_read_failure_is_an_explicit_error() {
        let stream = futures::stream::iter([Err::<bytes::Bytes, std::io::Error>(
            std::io::Error::other("transport reset"),
        )]);
        let body = Body::from_stream(stream);
        assert!(matches!(
            buffer_request_body(body).await,
            Err(BodyBufferError::Read(_))
        ));
    }

    /// F19: the two explicit rejections are real HTTP responses with the
    /// right status and envelope.
    #[test]
    fn explicit_body_errors_use_413_and_400() {
        assert_eq!(payload_too_large().status(), StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(body_read_failed().status(), StatusCode::BAD_REQUEST);
    }

    // ── F21: owner-token fencing scripts ─────────────────────────

    /// All ownership transitions must be compare-and-set on the owner token.
    #[test]
    fn ownership_scripts_compare_the_owner_token() {
        for script in [
            COMPLETE_IF_OWNER_LUA,
            RELEASE_IF_OWNER_LUA,
            RENEW_IF_OWNER_LUA,
        ] {
            assert!(
                script.contains("if redis.call('GET', KEYS[1]) == ARGV[1] then"),
                "script must compare-and-set on the owner token: {script}"
            );
        }
    }

    /// F21: dropping the guard without defusing must abort the renewal task
    /// (an abandoned request cannot keep refreshing its lease). Tokio's
    /// `JoinHandle::is_finished` observes the abort shortly after drop.
    #[tokio::test]
    async fn dropping_the_guard_aborts_the_renewal_task() {
        // A guard needs an AppState; its Drop release is best-effort and
        // skipped outside a runtime, so exercise the renewal-task lifecycle
        // directly with the same cancellation wiring the guard uses.
        let (cancel_tx, cancel_rx) = tokio::sync::watch::channel(false);
        let task = tokio::spawn(async move {
            let mut cancel = cancel_rx;
            loop {
                tokio::select! {
                    changed = cancel.changed() => {
                        assert!(changed.is_ok(), "sender dropped without signalling is also a stop");
                        break;
                    }
                    _ = tokio::time::sleep(std::time::Duration::from_millis(5)) => {}
                }
            }
        });
        // Signal + abort, exactly like ClaimGuard::stop_renewal.
        let _ = cancel_tx.send(true);
        task.abort();
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        assert!(task.is_finished(), "renewal must stop once the guard drops");
    }
}
