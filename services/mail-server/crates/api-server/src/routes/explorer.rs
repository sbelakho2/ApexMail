//! Public zero-JS API sandbox + pricing calculator (server-driven).
//!
//! The marketing site's API Explorer and Pricing Calculator are plain HTML
//! forms that POST here. This module:
//!
//! 1. lazily provisions a dedicated SANDBOX TENANT (tenant + api key +
//!    example.com verified domain) — a REAL tenant, so every request runs
//!    the REAL v1 handlers with a REAL api key;
//! 2. executes each lane by dispatching IN-PROCESS through the app router
//!    (`build_app` + `tower::ServiceExt::oneshot`) — genuine validation,
//!    idempotency, queue inserts and worker pickup: a send really flows and
//!    delivery is genuinely attempted (the Messages lane shows the full
//!    queued → attempted → bounced lifecycle);
//! 3. guards abuse with a per-IP rate limit (Redis, with a STRICTER
//!    in-process fixed-window emergency limiter engaged while Redis is
//!    unavailable — a cache blip degrades to a local ceiling, never to
//!    unlimited), an 8 KiB body cap, and a recipient policy for the send
//!    lane: every to/cc/bcc address must end in @example.com (RFC 2606
//!    reserved — real delivery attempt, harmless by construction, no relay
//!    potential);
//! 4. renders the full result page via ui_foundation (zero JS anywhere).
//!
//! The calculator computes with `billing_service::plans` — the canonical
//! pricing source — so this surface can never drift from billing.

use axum::{
    extract::{Form, State},
    http::{HeaderName, HeaderValue, Method, Request, StatusCode},
    response::{Html, IntoResponse, Response},
    Router,
};
use serde::Deserialize;
use std::sync::OnceLock;
use tower::ServiceExt;

use crate::state::AppState;

/// HTML body cap for the explorer request textarea.
const MAX_BODY_BYTES: usize = 8 * 1024;
/// Per-IP requests per minute on the public explorer endpoints.
const RATE_LIMIT_PER_MINUTE: i64 = 12;
/// Per-IP requests per minute while Redis is UNAVAILABLE. STRICTER than the
/// distributed limit: a degraded limiter must still bound abuse of this
/// public endpoint (which dispatches through the real router — real DB and
/// message processing), never go unlimited.
const EMERGENCY_RATE_LIMIT_PER_MINUTE: i64 = 6;
/// Fixed window length of the in-process emergency limiter.
const EMERGENCY_WINDOW: std::time::Duration = std::time::Duration::from_secs(60);
/// Beyond this many tracked buckets the emergency limiter opportunistically
/// drops expired windows, so a spoofed-IP flood during a Redis outage cannot
/// grow the map without bound.
const EMERGENCY_PRUNE_THRESHOLD: usize = 10_000;

// ─────────────────────────────────────────────────────────────────────────────
// Sandbox tenancy
// ─────────────────────────────────────────────────────────────────────────────

struct Sandbox {
    api_key: String,
    /// HMAC of [`Sandbox::api_key`] as stored in `api_keys.key_hash` — the
    /// liveness probe that keeps the process cache honest.
    key_hash: String,
}

/// The sandbox tenant id is a fixed 26-char value (VARCHAR(26) per migration
/// 064; charset follows the existing lowercase-alphanumeric nanoid style).
const SANDBOX_TENANT_ID: &str = "sbx0explorer0000000000000x";

/// Advisory-lock key serializing concurrent sandbox provisions ACROSS
/// processes (multi-replica deployments race the same fixed tenant row; the
/// per-process cache below cannot see sibling processes).
const SANDBOX_PROVISION_LOCK: &str = "apexmail:explorer-sandbox-provision";

/// Fix (P1 cold-start race): the previous `OnceLock` + check-revoke-create
/// sequence let two concurrent first requests interleave, and the loser's
/// `OnceLock::set` silently failed — leaving a REVOKED credential in the
/// static sandbox (broken until restart). A cached provision guarantees
/// exactly ONE provision per process: concurrent first requests await the
/// winner's result instead of racing their own.
static SANDBOX: tokio::sync::RwLock<Option<std::sync::Arc<Sandbox>>> =
    tokio::sync::RwLock::const_new(None);

/// Serializes provision attempts within THIS process so a cold-start burst
/// cannot run several DELETE+INSERT rotations back to back (the raw key is
/// un-recoverable from the row — only its hash is stored — so every extra
/// rotation invalidates a key another request just received).
static SANDBOX_PROVISION_MUTEX: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Where the CURRENT sandbox raw key is published for SIBLING processes.
/// `api_keys` keeps only the key's HMAC (hash-only storage), so a cold
/// process cannot recover the live raw key from the row alone — without a
/// shared publication, every cold start would rotate the single row out
/// from under every other replica (the audit-F4 churn the DELETE+INSERT cap
/// fixed within one process). The sandbox key never leaves the server and
/// only dispatches to `example.com`, so a shared Redis cache is a
/// proportionate home for it.
const SANDBOX_KEY_REDIS: &str = "apexmail:explorer:sandbox-key";
/// Refreshed on every provision; expiry only costs one extra rotation.
const SANDBOX_KEY_REDIS_TTL_SECS: u64 = 30 * 24 * 60 * 60;

/// Is the cached sandbox key still the ONE live `api_keys` row? A sibling
/// replica's cold-start provision (or an operator's touch) re-mints the
/// single row — SM3 (audit F4) rotation — which silently invalidates every
/// OTHER process's cached raw key. One indexed probe per anonymous exec
/// keeps the cache self-healing instead of broken-until-restart. A probe
/// that CANNOT be answered (storage outage) is treated as not-live: the
/// provision attempt that follows fails honestly on the same dead storage,
/// so a degraded deployment sees its usual 503/500, never a stale-credential
/// dispatch.
async fn sandbox_key_is_live(state: &AppState, sandbox: &Sandbox) -> bool {
    match sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM api_keys WHERE tenant_id = $1 AND key_hash = $2",
    )
    .bind(SANDBOX_TENANT_ID)
    .bind(&sandbox.key_hash)
    .fetch_one(&state.db)
    .await
    {
        Ok(count) => count > 0,
        Err(error) => {
            tracing::warn!(
                error = %error,
                "sandbox key liveness probe failed — falling through to provision"
            );
            false
        }
    }
}

/// ADOPT the sandbox key a sibling process published in Redis, if it is
/// still the live row. `None` means "no shared publication, or it no longer
/// matches the row — provision".
async fn adopted_shared_sandbox(state: &AppState) -> Option<Sandbox> {
    let raw: String = match state.redis.get().await {
        Ok(mut conn) => match deadpool_redis::redis::cmd("GET")
            .arg(SANDBOX_KEY_REDIS)
            .query_async::<Option<String>>(&mut *conn)
            .await
        {
            Ok(Some(raw)) if !raw.is_empty() => raw,
            Ok(_) => return None,
            Err(error) => {
                tracing::warn!(%error, "sandbox shared-key read failed — falling through to provision");
                return None;
            }
        },
        Err(error) => {
            tracing::warn!(%error, "sandbox shared-key redis unavailable — falling through to provision");
            return None;
        }
    };
    let candidate = Sandbox {
        key_hash: apexmail_lib::hash_api_key_with_secret(&raw, &state.config.api_key_hash_secret),
        api_key: raw,
    };
    if sandbox_key_is_live(state, &candidate).await {
        Some(candidate)
    } else {
        None
    }
}

/// Publish a freshly provisioned sandbox key for sibling processes
/// (best-effort: a failed publish costs the siblings one rotation).
async fn publish_shared_sandbox(state: &AppState, sandbox: &Sandbox) {
    match state.redis.get().await {
        Ok(mut conn) => {
            let result: Result<(), _> = deadpool_redis::redis::AsyncCommands::set_ex(
                &mut *conn,
                SANDBOX_KEY_REDIS,
                &sandbox.api_key,
                SANDBOX_KEY_REDIS_TTL_SECS,
            )
            .await;
            if let Err(error) = result {
                tracing::warn!(%error, "sandbox shared-key publish failed");
            }
        }
        Err(error) => {
            tracing::warn!(%error, "sandbox shared-key publish: redis unavailable");
        }
    }
}

/// Provision (idempotently) and memoize the sandbox tenant + api key.
async fn sandbox(state: &AppState) -> Result<std::sync::Arc<Sandbox>, String> {
    // Fast path 1: a cached key that is still the live row.
    if let Some(cached) = SANDBOX.read().await.clone() {
        if sandbox_key_is_live(state, &cached).await {
            return Ok(cached);
        }
    }
    // Fast path 2: ADOPT the live key a sibling process published, instead
    // of rotating it out from under them.
    if let Some(shared) = adopted_shared_sandbox(state).await {
        let shared = std::sync::Arc::new(shared);
        *SANDBOX.write().await = Some(std::sync::Arc::clone(&shared));
        return Ok(shared);
    }

    // Slow path: provision under the in-process lock, re-checking both
    // caches once acquired (a concurrent awaiter may have published a live
    // key while we waited).
    let _guard = SANDBOX_PROVISION_MUTEX.lock().await;
    if let Some(cached) = SANDBOX.read().await.clone() {
        if sandbox_key_is_live(state, &cached).await {
            return Ok(cached);
        }
    }
    if let Some(shared) = adopted_shared_sandbox(state).await {
        let shared = std::sync::Arc::new(shared);
        *SANDBOX.write().await = Some(std::sync::Arc::clone(&shared));
        return Ok(shared);
    }
    let provisioned = std::sync::Arc::new(provision_sandbox(state).await?);
    *SANDBOX.write().await = Some(std::sync::Arc::clone(&provisioned));
    Ok(provisioned)
}

/// The actual provisioning, run only when no live cached key exists
/// ([`sandbox`] guards it).
///
/// Everything happens in ONE transaction: a transaction-scoped advisory lock
/// serializes racing provisions (cross-process too), and revoke-old +
/// insert-new for the api key is atomic — no interleaving can persist a
/// sandbox whose only keys are revoked.
async fn provision_sandbox(state: &AppState) -> Result<Sandbox, String> {
    let now = chrono::Utc::now();
    let mut tx = state
        .db
        .begin()
        .await
        .map_err(|e| format!("sandbox provision transaction failed: {e}"))?;

    sqlx::query("SELECT pg_advisory_xact_lock(hashtext($1))")
        .bind(SANDBOX_PROVISION_LOCK)
        .execute(&mut *tx)
        .await
        .map_err(|e| format!("sandbox provision lock failed: {e}"))?;

    // Tenant (VARCHAR(26) id, plan-free).
    sqlx::query(
        "INSERT INTO tenants (id, name, plan, status, created_at, updated_at)
         VALUES ($1, 'API Explorer Sandbox', 'free', 'active', $2, $2)
         ON CONFLICT (id) DO NOTHING",
    )
    .bind(SANDBOX_TENANT_ID)
    .bind(now)
    .execute(&mut *tx)
    .await
    .map_err(|e| format!("sandbox tenant provision failed: {e}"))?;

    // Verified example.com domain for the tenant (direct insert mirrors the
    // real create-domain INSERT shape in routes/domains.rs:369, with the
    // verification flags set so the real send path accepts it).
    let existing_domain: Option<String> = sqlx::query_scalar(
        "SELECT name FROM domains WHERE tenant_id = $1 AND name = 'example.com' LIMIT 1",
    )
    .bind(SANDBOX_TENANT_ID)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|e| format!("sandbox domain check failed: {e}"))?;
    if existing_domain.is_none() {
        // Real DKIM keypair, encrypted exactly like the real create-domain
        // handler (routes/domains.rs) — the REAL send path requires
        // dkim_private_key LIKE 'dkim:v1:%' and dkim_enabled to accept a send.
        let domain_id = uuid::Uuid::new_v4();
        let key_pair = apexmail_lib::dkim::generate_dkim_keypair()
            .map_err(|e| format!("sandbox dkim keypair failed: {e}"))?;
        let aad =
            apexmail_lib::dkim::dkim_private_key_aad(SANDBOX_TENANT_ID, &domain_id.to_string());
        let encrypted =
            apexmail_lib::dkim::encrypt_dkim_private_key(&key_pair.private_key_pem, &aad)
                .map_err(|e| format!("sandbox dkim encrypt failed: {e}"))?;
        sqlx::query(
            "INSERT INTO domains (id, tenant_id, name, status, spf_verified, dkim_verified,
             dmarc_verified, return_path_verified, mta_sts_verified, bimi_verified,
             tlsrpt_verified, dkim_selector, dkim_public_key, dkim_private_key, dkim_enabled,
             ses_verified, verified, created_at, updated_at)
             VALUES ($1,$2,'example.com','verified',true,true,true,true,true,true,true,
             'sbx', $4, $5, true, true, true, $3, $3)
             ON CONFLICT DO NOTHING",
        )
        .bind(domain_id)
        .bind(SANDBOX_TENANT_ID)
        .bind(now)
        .bind(&key_pair.public_key)
        .bind(&encrypted)
        .execute(&mut *tx)
        .await
        .map_err(|e| format!("sandbox domain provision failed: {e}"))?;
    }

    // API key: generate fresh only when the tenant has none. SM3 (audit F4):
    // the sandbox key NEVER leaves the server (the explorer dispatches
    // in-process), so rotation reclaims the superseded rows outright — the
    // previous revoke-only rotation left every superseded row in place, and
    // each process restart grew the api_keys table without bound (and
    // bypassed mint_api_key's per-tenant key ceiling with its raw insert).
    // DELETE-then-INSERT in this transaction caps the sandbox tenant at
    // exactly ONE live key row across all processes.
    let raw_key = apexmail_lib::id::generate_api_key(false);
    let key_hash =
        apexmail_lib::hash_api_key_with_secret(&raw_key, &state.config.api_key_hash_secret);
    sqlx::query("DELETE FROM api_keys WHERE tenant_id = $1")
        .bind(SANDBOX_TENANT_ID)
        .execute(&mut *tx)
        .await
        .map_err(|e| format!("sandbox key reclaim failed: {e}"))?;
    let prefix: String = "sbx_".to_string();
    sqlx::query(
        "INSERT INTO api_keys (id, tenant_id, name, key_prefix, key_hash, scopes, expires_at, created_at, updated_at)
         VALUES ($1, $2, 'explorer', $3, $4, $5, NULL, $6, $6)",
    )
    .bind(uuid::Uuid::new_v4())
    .bind(SANDBOX_TENANT_ID)
    .bind(&prefix)
    .bind(&key_hash)
    .bind(serde_json::json!(["*"]))
    .bind(now)
    .execute(&mut *tx)
    .await
    .map_err(|e| format!("sandbox key insert failed: {e}"))?;

    tx.commit()
        .await
        .map_err(|e| format!("sandbox provision commit failed: {e}"))?;

    // Publish the new raw key for sibling processes IMMEDIATELY — the row
    // and the shared publication must move together, or every other
    // replica's liveness probe fails and churns yet another rotation.
    let provisioned = Sandbox {
        api_key: raw_key,
        key_hash,
    };
    publish_shared_sandbox(state, &provisioned).await;
    Ok(provisioned)
}

// ─────────────────────────────────────────────────────────────────────────────
// Rate limiting (public endpoints)
// ─────────────────────────────────────────────────────────────────────────────

/// One fixed-window bucket of the in-process emergency limiter.
struct EmergencyWindow {
    count: i64,
    window_start: std::time::Instant,
}

/// In-process emergency limiter buckets, keyed per-IP.
static EMERGENCY_LIMITER: OnceLock<
    parking_lot::Mutex<std::collections::HashMap<String, EmergencyWindow>>,
> = OnceLock::new();

async fn rate_limit(state: &AppState, ip: &str) -> bool {
    // Fix (P1): Redis unavailability no longer means "allowing". The
    // distributed verdict is used when Redis answers; ONLY on failure does
    // the stricter in-process fixed-window limiter engage — the endpoint
    // dispatches through the real router (real DB/message processing), so a
    // cache blip must degrade to a local ceiling, not to unlimited.
    match redis_rate_limit(state, &format!("explorer_rl:{ip}")).await {
        Ok(allowed) => allowed,
        Err(()) => emergency_allow(ip, std::time::Instant::now()),
    }
}

/// Distributed fixed-window verdict. `Ok(v)` is Redis' answer; `Err(())`
/// means Redis could not be consulted at all (pool exhausted / incr failed).
async fn redis_rate_limit(state: &AppState, key: &str) -> Result<bool, ()> {
    let mut conn = state.redis.get().await.map_err(|e| {
        tracing::warn!(
            error = %e,
            "explorer rate-limit redis unavailable — engaging the in-process emergency limiter"
        );
    })?;
    let (count,): (i64,) = match redis::pipe()
        .atomic()
        .incr(key, 1)
        .expire(key, 60)
        .ignore()
        .query_async(&mut conn)
        .await
    {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(
                error = %e,
                "explorer rate-limit incr failed — engaging the in-process emergency limiter"
            );
            return Err(());
        }
    };
    Ok(count <= RATE_LIMIT_PER_MINUTE)
}

/// In-process fixed-window fallback limiter, engaged ONLY while Redis is
/// unavailable (the same shape as tracking-service's in-process counters).
/// Buckets are keyed per-IP: counters never leak across IPs, and the window
/// is STRICTER than [`RATE_LIMIT_PER_MINUTE`]. The `now` parameter keeps the
/// window logic deterministic under test.
fn emergency_allow(ip: &str, now: std::time::Instant) -> bool {
    let map =
        EMERGENCY_LIMITER.get_or_init(|| parking_lot::Mutex::new(std::collections::HashMap::new()));
    let mut map = map.lock();
    if map.len() > EMERGENCY_PRUNE_THRESHOLD {
        map.retain(|_, w| now.duration_since(w.window_start) < EMERGENCY_WINDOW);
    }
    let window = map.entry(ip.to_string()).or_insert(EmergencyWindow {
        count: 0,
        window_start: now,
    });
    if now.duration_since(window.window_start) >= EMERGENCY_WINDOW {
        window.count = 0;
        window.window_start = now;
    }
    window.count += 1;
    window.count <= EMERGENCY_RATE_LIMIT_PER_MINUTE
}

/// Rate-limit bucket key for a sandbox request. Delegates to the shared
/// trusted-proxy walk (`extract_public_client_ip`): X-Forwarded-For is
/// only honoured when the DIRECT peer is a configured trusted proxy, and
/// then only the rightmost untrusted entry — the raw first-XFF read let
/// any caller pick an arbitrary bucket identity.
fn client_ip(
    req_headers: &axum::http::HeaderMap,
    socket_ip: std::net::IpAddr,
    trusted_proxies: &[String],
) -> String {
    crate::middleware::rate_limiter::extract_public_client_ip(
        req_headers,
        socket_ip,
        trusted_proxies,
    )
}

// ─────────────────────────────────────────────────────────────────────────────
// In-process dispatch through the REAL router
// ─────────────────────────────────────────────────────────────────────────────

static API_ROUTER: OnceLock<Router> = OnceLock::new();

fn api_router(state: &AppState) -> &'static Router {
    API_ROUTER.get_or_init(|| crate::app::build_app(state.clone()))
}

/// Dispatch a request through the real application router and capture the
/// verbatim status + body.
///
/// A 401 on the FIRST attempt with the process-cached sandbox key means the
/// key was rotated out from under this process between its liveness probe
/// and the dispatch (a sibling's cold start re-mints the single row). The
/// process cache is dropped, a fresh key is adopted, and the SAME request
/// is retried exactly once — the explorer's own answer to the audit-F4
/// cross-process rotation window. A second 401 (or a 401 with an unchanged
/// key — a genuine rejection, e.g. the send lane's policy) is surfaced
/// verbatim; nothing retries blind.
async fn dispatch(
    state: &AppState,
    method: Method,
    uri: &str,
    api_key: &str,
    json_body: Option<&str>,
) -> (u16, serde_json::Value) {
    let (status, value) = dispatch_once(state, method.clone(), uri, api_key, json_body).await;
    if status != 401 {
        return (status, value);
    }
    *SANDBOX.write().await = None;
    let fresh = match sandbox(state).await {
        Ok(fresh) if fresh.api_key != api_key => fresh,
        _ => return (status, value),
    };
    dispatch_once(state, method, uri, &fresh.api_key, json_body).await
}

/// One dispatch attempt — the retryable core of [`dispatch`].
async fn dispatch_once(
    state: &AppState,
    method: Method,
    uri: &str,
    api_key: &str,
    json_body: Option<&str>,
) -> (u16, serde_json::Value) {
    let mut builder = Request::builder().method(method).uri(uri).header(
        "x-api-key",
        HeaderValue::from_str(api_key).expect("api key is ascii"),
    );
    if json_body.is_some() {
        builder = builder.header("content-type", "application/json");
    }
    let body = match json_body {
        Some(b) => axum::body::Body::from(b.to_string()),
        None => axum::body::Body::empty(),
    };
    let request = builder.body(body).expect("valid request");
    let response = match api_router(state).clone().oneshot(request).await {
        Ok(r) => r,
        // coverage: justified — axum `Router`'s `Service::Error` is
        // `Infallible`, so `oneshot` can never produce `Err`; the arm pins
        // the honest public response shape should that ever change.
        Err(e) => {
            // Public endpoint: log the detail, return a generic message —
            // the raw in-process dispatch error can carry internal routes
            // and infrastructure detail.
            tracing::error!(error = %e, "explorer dispatch failed");
            return (
                500,
                serde_json::json!({"error": {"code": "internal_error", "message": "The sandbox request could not be processed. Please try again shortly."}}),
            );
        }
    };
    let status = response.status().as_u16();
    let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap_or_default();
    let value = serde_json::from_slice(&bytes).unwrap_or_else(
        |_| serde_json::json!({"raw": String::from_utf8_lossy(&bytes).to_string()}),
    );
    (status, value)
}

// ─────────────────────────────────────────────────────────────────────────────
// Recipient policy (send lane)
// ─────────────────────────────────────────────────────────────────────────────

fn all_recipients_example_com(body: &serde_json::Value) -> Result<(), String> {
    let check = |addr: &str| -> Result<(), String> {
        let lower = addr.trim().to_ascii_lowercase();
        if lower.ends_with("@example.com") {
            Ok(())
        } else {
            Err(format!(
                "recipient {addr:?} is outside the sandbox — explorer recipients must end in @example.com (the RFC 2606 reserved domain)"
            ))
        }
    };
    let check_list = |field: &str| -> Result<(), String> {
        match body.get(field) {
            None | Some(serde_json::Value::Null) => Ok(()),
            Some(serde_json::Value::String(s)) => check(s),
            Some(serde_json::Value::Array(items)) => {
                for item in items {
                    let s = item
                        .as_str()
                        .ok_or_else(|| format!("{field} entries must be strings"))?;
                    check(s)?;
                }
                Ok(())
            }
            Some(_) => Err(format!("{field} must be a string or array of strings")),
        }
    };
    check_list("to")?;
    check_list("cc")?;
    check_list("bcc")?;
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Handlers
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Deserialize, Debug)]
pub struct ExplorerForm {
    #[serde(default)]
    pub lane: String,
    #[serde(default)]
    pub body: String,
}

/// The lane → real-API-request mapping, shared by the public explorer
/// handler and the demo runtime (plan §5.6): one definition of what a lane
/// does, so a demo can never drift from the explorer.
async fn lane_outcome(
    state: &AppState,
    sandbox: &Sandbox,
    lane: &str,
    raw_body: &str,
) -> (&'static str, &'static str, u16, serde_json::Value) {
    match lane {
        "send" => match serde_json::from_str::<serde_json::Value>(raw_body) {
            Err(e) => {
                let body = serde_json::json!({"error": {"code": "invalid_json", "message": format!("{e}")}});
                ("POST", "/v1/messages", 400u16, body)
            }
            Ok(parsed) => match all_recipients_example_com(&parsed) {
                Ok(()) => {
                    // Force from= the sandbox domain when absent (the real
                    // handler enforces ownership of example.com anyway).
                    let mut payload = parsed;
                    if payload
                        .get("from")
                        .and_then(|f| f.as_str())
                        .is_none_or(|f| f.trim().is_empty())
                    {
                        payload["from"] = serde_json::json!("sandbox@example.com");
                    }
                    let json = payload.to_string();
                    let (status, body) = dispatch(
                        state,
                        Method::POST,
                        "/v1/messages",
                        &sandbox.api_key,
                        Some(&json),
                    )
                    .await;
                    ("POST", "/v1/messages", status, body)
                }
                Err(reason) => {
                    let body = serde_json::json!({"error": {"code": "sandbox_recipient_policy", "message": reason}});
                    ("POST", "/v1/messages", 422, body)
                }
            },
        },
        "messages" => {
            let (status, body) = dispatch(
                state,
                Method::GET,
                "/v1/messages?limit=20",
                &sandbox.api_key,
                None,
            )
            .await;
            ("GET", "/v1/messages?limit=20", status, body)
        }
        "domains" => {
            let (status, body) =
                dispatch(state, Method::GET, "/v1/domains", &sandbox.api_key, None).await;
            ("GET", "/v1/domains", status, body)
        }
        "add_domain" => match serde_json::from_str::<serde_json::Value>(raw_body) {
            Err(e) => {
                let body = serde_json::json!({"error": {"code": "invalid_json", "message": format!("{e}")}});
                ("POST", "/v1/domains", 400u16, body)
            }
            Ok(parsed) => {
                if !is_example_com_domain(&parsed) {
                    let body = serde_json::json!({"error": {"code": "sandbox_domain_policy", "message": "The explorer sandbox registers subdomains of example.com only."}});
                    ("POST", "/v1/domains", 422, body)
                } else {
                    let json = parsed.to_string();
                    let (status, body) = dispatch(
                        state,
                        Method::POST,
                        "/v1/domains",
                        &sandbox.api_key,
                        Some(&json),
                    )
                    .await;
                    ("POST", "/v1/domains", status, body)
                }
            }
        },
        other => {
            let body = serde_json::json!({"error": {"code": "unknown_lane", "message": format!("unknown lane {other:?}")}});
            ("POST", "/explorer/exec", 400, body)
        }
    }
}

pub async fn exec(
    State(state): State<AppState>,
    connect_info: Option<axum::extract::ConnectInfo<std::net::SocketAddr>>,
    headers: axum::http::HeaderMap,
    Form(form): Form<ExplorerForm>,
) -> Response {
    // Untrusted direct peer: the socket address IS the client. (Without
    // ConnectInfo — e.g. an exotic service wrapper — bucket on "unknown"
    // rather than trusting headers.)
    let bucket_ip = match connect_info {
        Some(axum::extract::ConnectInfo(addr)) => {
            client_ip(&headers, addr.ip(), &state.config.trusted_proxies)
        }
        None => "unknown".to_string(),
    };
    if !rate_limit(&state, &bucket_ip).await {
        return error_page(
            StatusCode::TOO_MANY_REQUESTS,
            "Too many sandbox requests — try again in a minute.",
        );
    }
    if form.body.len() > MAX_BODY_BYTES {
        return error_page(
            StatusCode::PAYLOAD_TOO_LARGE,
            "Request body exceeds the 8 KiB sandbox limit.",
        );
    }
    let sandbox = match sandbox(&state).await {
        Ok(s) => s,
        Err(e) => {
            // Public endpoint: the provisioning error carries database
            // detail (table names, driver errors) — log it at ERROR and
            // show a generic page instead of propagating it.
            tracing::error!(error = %e, "explorer sandbox provisioning failed");
            return error_page(
                StatusCode::INTERNAL_SERVER_ERROR,
                "The API sandbox is temporarily unavailable. Please try again shortly.",
            );
        }
    };

    let started = std::time::Instant::now();
    let (method, path, status, body) = lane_outcome(&state, &sandbox, &form.lane, &form.body).await;
    let latency = started.elapsed().as_millis();
    let outcome = ui_foundation::explorer::ExplorerOutcome {
        method,
        path,
        status,
        latency_ms: latency,
        body,
        request_body: form.body,
    };
    Html(ui_foundation::explorer::explorer_response_page(&outcome)).into_response()
}

fn is_example_com_domain(body: &serde_json::Value) -> bool {
    match body
        .get("name")
        .or_else(|| body.get("domain"))
        .and_then(|n| n.as_str())
    {
        Some(n) => {
            let lower = n.trim().to_ascii_lowercase();
            lower == "example.com" || lower.ends_with(".example.com")
        }
        None => false,
    }
}

/// Both rate-limit windows on the public explorer surface (the Redis fixed
/// window and the in-process emergency window) are 60 s, so a `429` can
/// honestly advertise `Retry-After: 60` — the same header contract every
/// other `429` on the API honours (error.rs `retry_after_secs`,
/// middleware/rate_limiter.rs). The hand-rolled HTML error pages here bypass
/// `ApiError`, so the header is attached at the page builders.
const RATE_LIMIT_WINDOW_SECS: u64 = 60;

fn retry_after_headers(status: StatusCode) -> axum::http::HeaderMap {
    let mut headers = axum::http::HeaderMap::new();
    if status == StatusCode::TOO_MANY_REQUESTS {
        if let Ok(value) = axum::http::HeaderValue::from_str(&RATE_LIMIT_WINDOW_SECS.to_string()) {
            headers.insert(axum::http::header::RETRY_AFTER, value);
        }
    }
    headers
}

fn error_page(status: StatusCode, message: &str) -> Response {
    let outcome = ui_foundation::explorer::ExplorerOutcome {
        method: "POST",
        path: "/explorer/exec",
        status: status.as_u16(),
        latency_ms: 0,
        body: serde_json::json!({"error": {"message": message}}),
        request_body: String::new(),
    };
    (
        status,
        retry_after_headers(status),
        Html(ui_foundation::explorer::explorer_response_page(&outcome)),
    )
        .into_response()
}

// ─────────────────────────────────────────────────────────────────────────────
// Pricing calculator
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Deserialize, Debug, Default)]
pub struct CalculatorForm {
    #[serde(default = "calc_default_volume")]
    pub volume: i64,
    #[serde(default = "calc_default_peak")]
    pub peak_daily: i64,
    #[serde(default = "calc_default_domains")]
    pub domains: i64,
    #[serde(default = "calc_default_users")]
    pub team_users: i64,
    #[serde(default)]
    pub dedicated_ips: i64,
    #[serde(default)]
    pub support: Option<String>,
    #[serde(default = "calc_default_cycle")]
    pub billing_cycle: String,
}
fn calc_default_cycle() -> String {
    "monthly".to_string()
}
fn calc_default_volume() -> i64 {
    50_000
}
fn calc_default_peak() -> i64 {
    2_500
}
fn calc_default_domains() -> i64 {
    2
}
fn calc_default_users() -> i64 {
    3
}

pub async fn calculate(
    State(_state): State<AppState>,
    Form(form): Form<CalculatorForm>,
) -> Response {
    let form = sanitize_calculator(form);
    let lines = compute_calculator(&form);
    let note = format!(
        "Computed with billing-service plan tables (the same source of truth as invoicing). Estimates assume {} sends/month with a {} peak day; plan switches are prorated.",
        format_int(form.volume),
        format_int(form.peak_daily),
    );
    let mut inputs = vec![
        ("volume".to_string(), format_int(form.volume)),
        ("peak daily".to_string(), format_int(form.peak_daily)),
        ("domains".to_string(), format_int(form.domains)),
        ("team users".to_string(), format_int(form.team_users)),
        ("dedicated IPs".to_string(), format_int(form.dedicated_ips)),
        ("billing".to_string(), form.billing_cycle.clone()),
    ];
    if let Some(s) = form.support.as_deref() {
        inputs.push(("support".to_string(), s.to_string()));
    }
    let ui_lines: Vec<ui_foundation::explorer::CalculatorLine> = lines
        .into_iter()
        .map(|l| ui_foundation::explorer::CalculatorLine {
            label: l.0,
            value: l.1,
            emphasis: l.2,
        })
        .collect();
    Html(ui_foundation::explorer::calculator_response_page(
        &inputs, &ui_lines, &note,
    ))
    .into_response()
}

fn sanitize_calculator(mut f: CalculatorForm) -> CalculatorForm {
    f.volume = f.volume.clamp(0, 100_000_000);
    f.peak_daily = f.peak_daily.clamp(0, 50_000_000);
    f.domains = f.domains.clamp(1, 1_000);
    f.team_users = f.team_users.clamp(1, 5_000);
    f.dedicated_ips = f.dedicated_ips.clamp(0, 100);
    if f.billing_cycle != "annual" {
        f.billing_cycle = "monthly".to_string();
    }
    f
}

/// (label, value, emphasized) rows derived from billing_service::plans.
fn compute_calculator(f: &CalculatorForm) -> Vec<(String, String, bool)> {
    let plans = billing_service::plans::default_plans();
    // Cheapest plan whose included volume fits; overage applies beyond it.
    let mut fitting: Vec<&billing_service::plans::PlanSeed> = plans
        .iter()
        .filter(|p| (p.email_limit >= f.volume || p.name == "free") && p.name != "enterprise")
        .collect();
    fitting.sort_by_key(|p| p.price_monthly);
    let chosen: Option<&billing_service::plans::PlanSeed> = fitting
        .iter()
        .find(|p| p.email_limit >= f.volume)
        .copied()
        .or_else(|| plans.iter().find(|p| p.name == "scale"))
        .or_else(|| plans.iter().find(|p| p.name == "free"));
    let mut rows = Vec::new();
    if let Some(plan) = chosen {
        let limit = plan.email_limit.max(0);
        let base = plan.price_monthly;
        // Quote the plan's CANONICAL catalog overage rate (80/60/35/35) —
        // the flat legacy 40-millicent wrapper understated Pro by 33% and
        // disagreed with the invoice sweep's ladder.
        let overage =
            billing_service::plans::calculate_plan_overage_cost(&plan.name, f.volume, limit);
        rows.push((
            format!("Plan — {}", title(plan.name)),
            format!("€{:.2}", base as f64 / 100.0),
            false,
        ));
        rows.push((
            "Included emails / month".to_string(),
            format_int(limit),
            false,
        ));
        if overage > 0 {
            rows.push((
                "Overage".to_string(),
                format!("€{:.2}", overage as f64 / 100.0),
                false,
            ));
        }
        let total = base + overage;
        // Dedicated IP add-on (2026-09-08 pricing): first managed IP
        // €49/mo, each additional €69/mo — on Pro and above.
        let ip_fee = if f.dedicated_ips > 0 && plan.name != "free" && plan.name != "starter" {
            4_900 + (f.dedicated_ips.saturating_sub(1)) * 6_900
        } else {
            0
        };
        if ip_fee > 0 {
            let ip_label = if f.dedicated_ips == 1 {
                "Dedicated IP (1× €49)".to_string()
            } else {
                format!("Dedicated IPs (1× €49 + {}× €69)", f.dedicated_ips - 1)
            };
            rows.push((ip_label, format!("€{:.2}", ip_fee as f64 / 100.0), false));
        } else if f.dedicated_ips > 0 {
            rows.push((
                "Dedicated IPs".to_string(),
                "available on Pro+".to_string(),
                false,
            ));
        }
        let grand = total + ip_fee;
        if f.billing_cycle == "annual" {
            rows.push((
                "Monthly equivalent".to_string(),
                format!("€{:.2}", grand as f64 / 100.0),
                false,
            ));
            rows.push((
                "Annual total (2 months free)".to_string(),
                format!("€{:.2}", (grand * 10) as f64 / 100.0),
                true,
            ));
        } else {
            rows.push((
                "Monthly total".to_string(),
                format!("€{:.2}", grand as f64 / 100.0),
                true,
            ));
            rows.push((
                "Annual alternative".to_string(),
                format!("€{:.2}", (grand * 10) as f64 / 100.0),
                false,
            ));
        }
        // coverage: justified — `default_plans()` is a static table that
        // always contains "scale" (and "free"), so `chosen` can never be
        // `None`; this arm is the defensive fallback should the plan table
        // ever drift into an empty/enterprise-only state.
    } else {
        rows.push((
            "Plan".to_string(),
            "Contact us — Enterprise".to_string(),
            true,
        ));
    }
    rows.push(("Sending domains".to_string(), format_int(f.domains), false));
    rows.push(("Team users".to_string(), format_int(f.team_users), false));
    rows
}

fn title(s: &str) -> String {
    let mut c = s.chars();
    match c.next() {
        Some(f) => f.to_uppercase().collect::<String>() + c.as_str(),
        None => String::new(),
    }
}

fn format_int(n: i64) -> String {
    let mut s = n.to_string();
    let mut i = s.len() as isize - 3;
    while i > 0 {
        s.insert(i as usize, ',');
        i -= 3;
    }
    s
}

/// ── Demo runtime support (plan §5.6) ────────────────────────────────────────
///
/// The demo sessions API executes REAL machinery; these wrappers expose the
/// explorer's own cores so a demo runs exactly what the public explorer runs,
/// with the same sandbox tenant, the same recipient/domain policies and the
/// same calculator source. The explorer's own handlers keep their per-IP
/// limiter and HTML rendering; the demo path is owner-gated instead.
/// Run one explorer lane and return the verbatim outcome as JSON.
pub(crate) async fn demo_run_lane(
    state: &AppState,
    lane: &str,
    raw_body: &str,
) -> serde_json::Value {
    if raw_body.len() > MAX_BODY_BYTES {
        return serde_json::json!({
            "kind": "explorer_exec",
            "status": 413,
            "error": "Request body exceeds the 8 KiB sandbox limit.",
        });
    }
    let sandbox = match sandbox(state).await {
        Ok(sandbox) => sandbox,
        Err(error) => {
            tracing::error!(error = %error, "demo sandbox provisioning failed");
            return serde_json::json!({
                "kind": "explorer_exec",
                "status": 503,
                "error": "The API sandbox is temporarily unavailable.",
            });
        }
    };
    let (method, path, status, body) = lane_outcome(state, &sandbox, lane, raw_body).await;
    serde_json::json!({
        "kind": "explorer_exec",
        "lane": lane,
        "method": method,
        "path": path,
        "status": status,
        "body": body,
    })
}

/// Grade a domain through the SAME transport-agnostic grader handler the
/// public grader and the `/v1/grader/check` API use.
pub(crate) async fn demo_run_grade(state: &AppState, domain: &str) -> serde_json::Value {
    let domain = clean_domain_input(domain);
    if domain.is_empty() || domain.len() > 253 || !domain.contains('.') {
        return serde_json::json!({
            "kind": "grader",
            "status": 400,
            "error": "Enter a real domain, like yourcompany.com.",
        });
    }
    let Some(gs) = state.grader_state.clone() else {
        return serde_json::json!({
            "kind": "grader",
            "status": 503,
            "error": "The Email Grader is temporarily unavailable.",
        });
    };
    let ip: std::net::IpAddr = "0.0.0.0".parse().expect("static ip literal");
    let (status, axum::Json(value)) = email_grader::routes::check_domain(
        gs,
        ip,
        email_grader::DomainCheckRequest {
            domain: domain.clone(),
            selectors: Vec::new(),
        },
    )
    .await;
    serde_json::json!({
        "kind": "grader",
        "status": status.as_u16(),
        "domain": domain,
        "report": value,
    })
}

/// Compute calculator rows from the canonical pricing source. Params come
/// from the demo script's JSON; unknown or hostile values fall back to the
/// calculator's own defaults via the sanitizer.
pub(crate) fn demo_run_calculator(params: &serde_json::Value) -> Vec<(String, String, bool)> {
    let defaults = CalculatorForm::default();
    let read_i64 = |key: &str, fallback: i64| -> i64 {
        params.get(key).and_then(|v| v.as_i64()).unwrap_or(fallback)
    };
    let form = CalculatorForm {
        volume: read_i64("volume", defaults.volume),
        peak_daily: read_i64("peak_daily", defaults.peak_daily),
        domains: read_i64("domains", defaults.domains),
        team_users: read_i64("team_users", defaults.team_users),
        dedicated_ips: read_i64("dedicated_ips", defaults.dedicated_ips),
        support: params
            .get("support")
            .and_then(|v| v.as_str())
            .map(str::to_string),
        billing_cycle: params
            .get("billing_cycle")
            .and_then(|v| v.as_str())
            .unwrap_or("monthly")
            .to_string(),
    };
    compute_calculator(&sanitize_calculator(form))
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/explorer/exec", axum::routing::post(exec))
        .route("/explorer/calculate", axum::routing::post(calculate))
        .route("/explorer/grade", axum::routing::post(grade_domain))
}

// ─────────────────────────────────────────────────────────────────────────────
// Email Grader (zero-JS form wrapper)
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct GradeDomainForm {
    #[serde(default)]
    pub domain: String,
}

/// Strip the noise users paste into a "your domain" box: schemes, paths,
/// ports, credentials, surrounding dots. Lowercased.
fn clean_domain_input(raw: &str) -> String {
    let mut d = raw.trim().to_ascii_lowercase();
    for scheme in ["https://", "http://"] {
        if let Some(rest) = d.strip_prefix(scheme) {
            d = rest.to_string();
            break;
        }
    }
    // Pasted email / MAIL FROM shape: keep only the host.
    if let Some((_, host)) = d.rsplit_once('@') {
        d = host.to_string();
    }
    for sep in ['/', ':', '?', '#'] {
        if let Some((host, _)) = d.split_once(sep) {
            d = host.to_string();
        }
    }
    d.trim_matches('.').trim().to_string()
}

pub async fn grade_domain(
    State(state): State<AppState>,
    connect_info: Option<axum::extract::ConnectInfo<std::net::SocketAddr>>,
    headers: axum::http::HeaderMap,
    Form(form): Form<GradeDomainForm>,
) -> Response {
    // Same trusted-proxy IP walk and Redis budget as the sandbox lanes.
    let bucket_ip = match connect_info {
        Some(axum::extract::ConnectInfo(addr)) => {
            client_ip(&headers, addr.ip(), &state.config.trusted_proxies)
        }
        None => "unknown".to_string(),
    };
    if !rate_limit(&state, &bucket_ip).await {
        return grader_error_page(
            StatusCode::TOO_MANY_REQUESTS,
            "",
            "RATE_LIMITED",
            "Too many checks — try again in a minute.",
        );
    }
    let domain = clean_domain_input(&form.domain);
    if domain.is_empty()
        || domain.len() > 253
        || !domain.contains('.')
        || domain.chars().any(|c| c.is_whitespace())
    {
        return grader_error_page(
            StatusCode::BAD_REQUEST,
            &domain,
            "INVALID_INPUT",
            "Enter a real domain you send from, like yourcompany.com.",
        );
    }
    let gs = match state.grader_state.clone() {
        Some(s) => s,
        None => {
            return grader_error_page(
                StatusCode::SERVICE_UNAVAILABLE,
                &domain,
                "GRADER_DISABLED",
                "The Email Grader is temporarily unavailable.",
            )
        }
    };
    let client_ip_addr: std::net::IpAddr = bucket_ip
        .parse()
        .unwrap_or_else(|_| "0.0.0.0".parse().expect("static ip literal"));
    // Delegate to the canonical transport-agnostic handler — enabled flag,
    // per-IP engine rate limit, error mapping and scoring all stay in ONE
    // place, identical to the /v1/grader/check JSON API.
    let (status, axum::Json(value)) = email_grader::routes::check_domain(
        gs,
        client_ip_addr,
        email_grader::DomainCheckRequest {
            domain: domain.clone(),
            selectors: Vec::new(),
        },
    )
    .await;
    if status == StatusCode::OK {
        Html(ui_foundation::explorer::grader_response_page(&value)).into_response()
    } else {
        let code = value
            .pointer("/error/code")
            .and_then(|v| v.as_str())
            .unwrap_or("GRADER_ERROR");
        // Public endpoint: the engine's messages are already
        // user-facing (map_grader_error), but never leak anything raw.
        let message = value
            .pointer("/error/message")
            .and_then(|v| v.as_str())
            .unwrap_or("The check could not be completed.");
        grader_error_page(status, &domain, code, message)
    }
}

fn grader_error_page(status: StatusCode, domain: &str, code: &str, message: &str) -> Response {
    (
        status,
        retry_after_headers(status),
        Html(ui_foundation::explorer::grader_error_page(
            domain, code, message,
        )),
    )
        .into_response()
}

// coverage: justified — intentionally dead: exists only so the `HeaderName`
// import stays used (keeps clippy quiet about the unused-headers path); it is
// never called at runtime or from tests.
#[allow(unused)]
fn _header_guard(n: HeaderName) -> HeaderValue {
    HeaderValue::from_static("x")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_ip_ignores_forwarded_for_from_untrusted_peers() {
        // A spoofed X-Forwarded-For from a directly-connected (untrusted)
        // peer must NOT choose the rate-limit bucket: the socket address
        // is the only honest signal when the peer is not a configured
        // proxy.
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            "x-forwarded-for",
            axum::http::HeaderValue::from_static("6.6.6.6, 7.7.7.7"),
        );
        let bucket = client_ip(
            &headers,
            "203.0.113.9:44321"
                .parse::<std::net::SocketAddr>()
                .unwrap()
                .ip(),
            &[],
        );
        assert_eq!(
            bucket, "203.0.113.9",
            "spoofed XFF must not pick the bucket"
        );

        // From a TRUSTED proxy, the rightmost untrusted XFF entry wins.
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            "x-forwarded-for",
            axum::http::HeaderValue::from_static("6.6.6.6, 198.51.100.7"),
        );
        let bucket = client_ip(
            &headers,
            "10.0.0.2:44321"
                .parse::<std::net::SocketAddr>()
                .unwrap()
                .ip(),
            &["10.0.0.0/8".to_string()],
        );
        assert_eq!(bucket, "198.51.100.7");
    }

    #[test]
    fn recipient_policy_accepts_only_example_com() {
        let ok =
            serde_json::json!({"to": ["a@example.com", "B@Example.COM"], "cc": ["c@example.com"]});
        assert!(all_recipients_example_com(&ok).is_ok());
        let bad = serde_json::json!({"to": ["a@evil.com"]});
        assert!(all_recipients_example_com(&bad).is_err());
        let bad_cc = serde_json::json!({"to": ["a@example.com"], "bcc": ["x@gmail.com"]});
        assert!(all_recipients_example_com(&bad_cc).is_err());
        let missing = serde_json::json!({"subject": "hi"});
        assert!(all_recipients_example_com(&missing).is_ok()); // real handler rejects missing to
                                                               // A bare STRING (not an array) is checked by the same policy.
        assert!(all_recipients_example_com(&serde_json::json!({"to": "solo@example.com"})).is_ok());
        assert!(all_recipients_example_com(&serde_json::json!({"to": "solo@evil.com"})).is_err());
    }

    #[test]
    fn domain_policy_rejects_non_example() {
        assert!(is_example_com_domain(
            &serde_json::json!({"name": "shop.example.com"})
        ));
        assert!(is_example_com_domain(
            &serde_json::json!({"name": "example.com"})
        ));
        assert!(!is_example_com_domain(
            &serde_json::json!({"name": "evil.com"})
        ));
        assert!(!is_example_com_domain(
            &serde_json::json!({"name": "evilexample.com"})
        ));
    }

    #[test]
    fn calculator_clamps_and_formats() {
        let f = sanitize_calculator(CalculatorForm {
            volume: -5,
            peak_daily: 10_000_000_000,
            domains: 0,
            dedicated_ips: 0,
            support: None,
            billing_cycle: String::new(),
            team_users: 99_999,
        });
        assert_eq!(f.volume, 0);
        assert_eq!(f.peak_daily, 50_000_000);
        assert_eq!(f.domains, 1);
        assert_eq!(f.team_users, 5_000);
        assert_eq!(format_int(1_234_567), "1,234,567");
    }

    #[test]
    fn dedicated_ip_addon_labels_one_many_and_the_pro_gate() {
        // Pro plan (volume 100k fits pro's 150k, not starter's 50k):
        // exactly ONE dedicated IP gets its single-IP label.
        let pro_one = CalculatorForm {
            volume: 100_000,
            dedicated_ips: 1,
            ..Default::default()
        };
        let rows = compute_calculator(&pro_one);
        let ip_row = rows
            .iter()
            .find(|r| r.0.contains("Dedicated IP"))
            .expect("dedicated ip row");
        assert_eq!(ip_row.0, "Dedicated IP (1× €49)");
        assert_eq!(ip_row.1, "€49.00");

        // Several IPs itemise the first + additional pricing.
        let pro_many = CalculatorForm {
            volume: 100_000,
            dedicated_ips: 3,
            ..Default::default()
        };
        let rows = compute_calculator(&pro_many);
        let ip_row = rows
            .iter()
            .find(|r| r.0.starts_with("Dedicated IPs"))
            .expect("dedicated ips row");
        assert!(ip_row.0.contains("2× €69"), "{:?}", ip_row.0);
        assert_eq!(ip_row.1, "€187.00");

        // On free/starter plans the add-on is explicitly unavailable —
        // never silently priced.
        let free_with_ip = CalculatorForm {
            volume: 1_000,
            dedicated_ips: 1,
            ..Default::default()
        };
        let rows = compute_calculator(&free_with_ip);
        assert!(
            rows.iter()
                .any(|r| r.0 == "Dedicated IPs" && r.1 == "available on Pro+"),
            "{rows:?}"
        );
    }

    /// Regression (F2): the public calculator quotes the CANONICAL catalog
    /// overage ladder, not the legacy flat 40 millicents. At 3M emails the
    /// fallback plan is Business (scale, 2M included, 35 millicents/email):
    /// 1M overage = 35,000 cents = €350.00. The old flat wrapper quoted
    /// €400.00.
    #[test]
    fn calculator_quotes_the_canonical_plan_overage_rate() {
        let f = CalculatorForm {
            volume: 3_000_000,
            peak_daily: 100_000,
            domains: 1,
            team_users: 5,
            ..Default::default()
        };
        let rows = compute_calculator(&f);
        let overage = rows
            .iter()
            .find(|r| r.0 == "Overage")
            .expect("overage row for 1M beyond Business' included volume");
        assert_eq!(overage.1, "€350.00");

        // The plan-aware helper and the catalog agree on the ladder.
        use billing_service::plans::{calculate_plan_overage_cost, plan_overage_rate_millicents};
        assert_eq!(plan_overage_rate_millicents("scale"), Some(35));
        assert_eq!(
            calculate_plan_overage_cost("scale", 3_000_000, 2_000_000),
            35_000
        );
        assert_eq!(
            calculate_plan_overage_cost("pro", 200_000, 150_000),
            3_000,
            "Pro overage is 60 millicents/email (€30 for 50k over)"
        );
    }

    #[test]
    fn calculator_picks_cheapest_fitting_plan() {
        let f = CalculatorForm {
            volume: 40_000,
            peak_daily: 2_000,
            domains: 1,
            team_users: 1,
            ..Default::default()
        };
        let rows = compute_calculator(&f);
        let plan_row = rows
            .iter()
            .find(|r| r.0.starts_with("Plan —"))
            .expect("plan row");
        assert!(
            plan_row.0.contains("Starter") || plan_row.0.contains("Free"),
            "{plan_row:?}"
        );
        let total = rows.iter().find(|r| r.0 == "Monthly total").expect("total");
        assert!(total.1.starts_with("€"));
    }

    #[test]
    fn grade_form_strips_pasted_url_noise() {
        assert_eq!(clean_domain_input("  YourCompany.COM "), "yourcompany.com");
        assert_eq!(
            clean_domain_input("https://yourcompany.com/pricing"),
            "yourcompany.com"
        );
        assert_eq!(
            clean_domain_input("http://user@sub.yourcompany.com:8443/x?q=1"),
            "sub.yourcompany.com"
        );
        assert_eq!(
            clean_domain_input("news@yourcompany.com"),
            "yourcompany.com"
        );
        assert_eq!(clean_domain_input(".yourcompany.com."), "yourcompany.com");
        // Empty stays empty — the handler rejects it with INVALID_INPUT.
        assert_eq!(clean_domain_input("   "), "");
    }

    #[test]
    fn title_capitalises_names_and_handles_the_empty_string() {
        assert_eq!(title("pro"), "Pro");
        assert_eq!(title("free"), "Free");
        // Degenerate input stays a valid empty label (plan names are never
        // empty in billing_service::plans, but the helper is total).
        assert_eq!(title(""), "");
    }

    #[test]
    fn four_twenty_nine_pages_advertise_retry_after_other_statuses_do_not() {
        let limited = error_page(StatusCode::TOO_MANY_REQUESTS, "slow down");
        assert_eq!(
            limited
                .headers()
                .get(axum::http::header::RETRY_AFTER)
                .and_then(|v| v.to_str().ok()),
            Some("60"),
            "the documented 429 Retry-After contract applies to the explorer's HTML pages too"
        );
        let too_large = error_page(StatusCode::PAYLOAD_TOO_LARGE, "big");
        assert!(too_large
            .headers()
            .get(axum::http::header::RETRY_AFTER)
            .is_none());
        // The grader error page honours the same contract.
        let graded = grader_error_page(
            StatusCode::TOO_MANY_REQUESTS,
            "x.com",
            "RATE_LIMITED",
            "slow down",
        );
        assert_eq!(
            graded
                .headers()
                .get(axum::http::header::RETRY_AFTER)
                .and_then(|v| v.to_str().ok()),
            Some("60")
        );
    }
}

// ─── Adversarial sandbox / calculator / grader tests ───────────
//
// The sandbox provisions a REAL DKIM-encrypted domain, so these tests hold
// the process-global `DKIM_ENV_MUTEX` (like admin/domains.rs) and pin the
// test key. They also share ONE runtime + AppState: the explorer dispatches
// through a process-wide cached router (`API_ROUTER`), and a pool created on
// a runtime that has since shut down cannot be driven from a new one — a
// per-test runtime therefore starved the cached router's pool (5 s acquire
// timeout → 500). One long-lived runtime removes that failure mode.

#[cfg(test)]
mod adversarial_tests {
    use super::*;
    use axum::extract::ConnectInfo;
    use std::net::SocketAddr;

    /// Same constant the admin-domain tests use.
    const TEST_DKIM_KEY: &str = "3f7a1c9e2b5d48f01a6c3e792d4b8f15a0c6e3917d2f4b8a5c1e7309d4f2b6a8";

    struct SharedState {
        runtime: tokio::runtime::Runtime,
        state: AppState,
    }

    /// One runtime + AppState for every dispatch test in this module.
    fn shared() -> Option<&'static SharedState> {
        static ONCE: std::sync::OnceLock<Option<SharedState>> = std::sync::OnceLock::new();
        ONCE.get_or_init(|| {
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()
                .expect("shared test runtime");
            // coverage: justified — the `?` fires only when TEST_DATABASE_URL
            // is unset (soft-skip contract); coverage runs are always
            // database-provisioned, so the skip arm stays unmeasured here.
            let pool = runtime.block_on(crate::test_db::optional_pg_pool(
                "adv_explorer_shared_state",
            ))?;
            let state = runtime.block_on(crate::app::test_support::test_state_over(pool));
            Some(SharedState { runtime, state })
        })
        .as_ref()
    }

    /// Serialise on the process-global DKIM env var, pin the test key, run
    /// the body on the shared runtime, and restore the previous value.
    fn with_dkim_env(body: impl FnOnce(AppState) -> futures::future::BoxFuture<'static, ()>) {
        let _guard = crate::test_db::DKIM_ENV_MUTEX
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let previous = std::env::var(apexmail_lib::dkim::DKIM_PRIVATE_KEY_ENCRYPTION_KEY_ENV).ok();
        std::env::set_var(
            apexmail_lib::dkim::DKIM_PRIVATE_KEY_ENCRYPTION_KEY_ENV,
            TEST_DKIM_KEY,
        );
        match shared() {
            Some(shared) => {
                let state = shared.state.clone();
                shared.runtime.block_on(body(state));
            }
            // coverage: justified — same soft-skip contract as `shared()`:
            // only reachable when TEST_DATABASE_URL is unset.
            None => eprintln!("skipping explorer test: set TEST_DATABASE_URL"),
        }
        match previous {
            Some(value) => std::env::set_var(
                apexmail_lib::dkim::DKIM_PRIVATE_KEY_ENCRYPTION_KEY_ENV,
                value,
            ),
            None => std::env::remove_var(apexmail_lib::dkim::DKIM_PRIVATE_KEY_ENCRYPTION_KEY_ENV),
        }
    }

    /// A per-CALL client address so the shared per-IP Redis bucket cannot
    /// leak between test calls (each gets its own 12/min window). The second
    /// octet is PROCESS-unique (audit #12c): every nextest test runs in its
    /// own process against the SHARED test Redis, and the counter below
    /// restarts at 1 in each of them — without the pid seed the first exec
    /// call of every parallel explorer test landed in the SAME
    /// `explorer_rl:198.18.0.1` bucket and the 13th concurrent process was
    /// rate-limited with a 429.
    fn unique_peer() -> Option<ConnectInfo<SocketAddr>> {
        use std::sync::atomic::{AtomicU32, Ordering};
        static NEXT: AtomicU32 = AtomicU32::new(1);
        let n = NEXT.fetch_add(1, Ordering::Relaxed);
        let pid_octet = std::process::id() % 250;
        let addr: SocketAddr = format!("198.18.{pid_octet}.{}:41234", n % 250 + 1)
            .parse()
            .unwrap();
        Some(ConnectInfo(addr))
    }

    /// An exclusive observation window over the SHARED sandbox row (external
    /// audit 2026-10-02 #12c). Every api-server test process shares ONE
    /// database (`<TEST_DATABASE_URL db>_api`, reused, never dropped between
    /// processes) and one Redis publication, and the sandbox tenant id is a
    /// fixed constant — so the single sandbox key row is GLOBAL state that
    /// every concurrently running explorer test legitimately re-mints (that
    /// is exactly what a replica sibling is). A multi-step assertion sequence
    /// therefore races a sibling's `provision_sandbox` unless it holds the
    /// production provision advisory key (`SANDBOX_PROVISION_LOCK`,
    /// transaction-scoped — the same `pg_advisory_xact_lock` the provision
    /// path itself takes) for the window's duration: sibling re-mints BLOCK
    /// until the window closes, and the observations see one stable row.
    ///
    /// The window must NEVER cover a call that can itself provision —
    /// `provision_sandbox` under the window would wait on its own held key
    /// and hang. Calls inside a window are restricted to the cache probes,
    /// the Redis publication seams and reads; see each sandbox test.
    async fn provision_window(state: &AppState) -> sqlx::Transaction<'static, sqlx::Postgres> {
        let mut tx = state
            .db
            .begin()
            .await
            .expect("sandbox provision window transaction");
        sqlx::query("SELECT pg_advisory_xact_lock(hashtext($1))")
            .bind(SANDBOX_PROVISION_LOCK)
            .execute(&mut *tx)
            .await
            .expect("sandbox provision window advisory lock");
        tx
    }

    /// Serializes the two tests that exercise the FIXED "unknown"
    /// rate-limit bucket (requests with no peer address):
    /// `exec_buckets_unknown_peers_and_enforces_the_ceiling_on_them`
    /// fills/exhausts that bucket while `grader_without_connect_info_still_
    /// validates_input` INCRs and DELs it — as parallel nextest processes
    /// they were resetting each other's bucket mid-assertion (audit #12c).
    /// The key is test-only; no production path takes it, so holding it
    /// cannot deadlock anything.
    async fn unknown_bucket_window(state: &AppState) -> sqlx::Transaction<'static, sqlx::Postgres> {
        let mut tx = state
            .db
            .begin()
            .await
            .expect("unknown-bucket window transaction");
        sqlx::query("SELECT pg_advisory_xact_lock(hashtext($1))")
            .bind("apexmail:test:explorer-unknown-bucket")
            .execute(&mut *tx)
            .await
            .expect("unknown-bucket window advisory lock");
        tx
    }

    async fn html(resp: Response) -> String {
        let bytes = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
            .await
            .unwrap();
        String::from_utf8_lossy(&bytes).to_string()
    }

    async fn exec_lane(state: &AppState, lane: &str, body: &str) -> Response {
        exec(
            State(state.clone()),
            unique_peer(),
            axum::http::HeaderMap::new(),
            Form(ExplorerForm {
                lane: lane.to_string(),
                body: body.to_string(),
            }),
        )
        .await
    }

    #[test]
    fn unknown_lane_is_400_and_never_dispatches() {
        with_dkim_env(|state| {
            Box::pin(async move {
                let resp = exec_lane(&state, "drop_tables", "{}").await;
                // The public page always renders 200; the DOCUMENTED refusal
                // is the lane error inside the page.
                assert_eq!(resp.status(), StatusCode::OK);
                let page = html(resp).await;
                assert!(page.contains("unknown_lane"), "page: {page}");
                assert!(!page.contains("internal_error"), "page: {page}");
            })
        });
    }

    #[test]
    fn malformed_json_on_json_lanes_is_400_without_internal_detail() {
        with_dkim_env(|state| {
            Box::pin(async move {
                for lane in ["send", "add_domain"] {
                    let resp = exec_lane(&state, lane, "{not json").await;
                    assert_eq!(resp.status(), StatusCode::OK, "{lane}");
                    let page = html(resp).await;
                    assert!(page.contains("invalid_json"), "{lane}: {page}");
                    assert!(!page.contains("internal_error"), "{lane}: {page}");
                }
            })
        });
    }

    #[test]
    fn send_lane_enforces_the_example_com_recipient_policy() {
        with_dkim_env(|state| {
            Box::pin(async move {
                // cc/bcc attacks and non-string entries.
                for body in [
                    r#"{"to":["victim@real-person.example"]}"#,
                    r#"{"to":["ok@example.com"],"cc":["bad@other.org"]}"#,
                    r#"{"to":["ok@example.com"],"bcc":["bad@other.org"]}"#,
                    r#"{"to":[42]}"#,
                    r#"{"to":{"email":"a@example.com"}}"#,
                ] {
                    let resp = exec_lane(&state, "send", body).await;
                    assert_eq!(resp.status(), StatusCode::OK, "body {body}");
                    let page = html(resp).await;
                    assert!(
                        page.contains("sandbox_recipient_policy"),
                        "body {body}: {page}"
                    );
                    assert!(!page.contains("internal_error"), "body {body}: {page}");
                }
                // A clean example.com payload really dispatches through the router.
                let resp = exec_lane(
                    &state,
                    "send",
                    r#"{"to":["friend@example.com"],"subject":"hi","text":"hello"}"#,
                )
                .await;
                assert_eq!(resp.status(), StatusCode::OK);
                let page = html(resp).await;
                assert!(
                    page.contains("/v1/messages"),
                    "page should render the dispatched route: {page}"
                );
                assert!(!page.contains("internal_error"), "{page}");
            })
        });
    }

    #[test]
    fn add_domain_lane_only_accepts_example_com_subdomains() {
        with_dkim_env(|state| {
            Box::pin(async move {
                for body in [
                    r#"{"name":"evil.com"}"#,
                    r#"{"name":"evilexample.com"}"#,
                    r#"{"domain":"example.com.evil.net"}"#,
                    r#"{}"#,
                ] {
                    let resp = exec_lane(&state, "add_domain", body).await;
                    assert_eq!(resp.status(), StatusCode::OK, "body {body}");
                    let page = html(resp).await;
                    assert!(page.contains("sandbox_domain_policy"), "body {body}");
                    assert!(!page.contains("internal_error"), "body {body}");
                }
                // A legitimate subdomain reaches the real handler (created or
                // already-exists), never a 500.
                let resp = exec_lane(
                    &state,
                    "add_domain",
                    &format!(
                        r#"{{"name":"adv-{}.example.com"}}"#,
                        uuid::Uuid::new_v4().simple()
                    ),
                )
                .await;
                assert_eq!(resp.status(), StatusCode::OK);
                let page = html(resp).await;
                assert!(!page.contains("internal_error"), "{page}");
            })
        });
    }

    #[test]
    fn read_lanes_dispatch_real_get_requests() {
        with_dkim_env(|state| {
            Box::pin(async move {
                for lane in ["messages", "domains"] {
                    let resp = exec_lane(&state, lane, "").await;
                    assert_eq!(resp.status(), StatusCode::OK, "{lane}");
                    let page = html(resp).await;
                    assert!(page.contains("200"), "{lane}: {page}");
                    assert!(!page.contains("internal_error"), "{lane}: {page}");
                }
            })
        });
    }

    #[test]
    fn oversized_textarea_is_413_before_any_provisioning() {
        with_dkim_env(|state| {
            Box::pin(async move {
                let resp = exec_lane(&state, "send", &"x".repeat(MAX_BODY_BYTES + 1)).await;
                assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
            })
        });
    }

    /// SM3 (audit F4): the sandbox key is provisioned ONCE per process and
    /// reused across requests, and the sandbox tenant is capped at exactly
    /// ONE api_keys row — re-provisioning (what a restarted process does)
    /// reclaims the superseded row instead of stockpiling revoked ones.
    ///
    /// Audit #12c: the reuse assertion observes the shared row inside a
    /// [`provision_window`] — a sibling process's legitimate re-mint between
    /// the two calls would otherwise replace the cached key mid-assertion.
    #[test]
    fn sandbox_key_is_cached_per_process_and_capped_at_one_row() {
        with_dkim_env(|state| {
            Box::pin(async move {
                let key_stats = |state: &AppState| {
                    let pool = state.db.clone();
                    async move {
                        let (rows, live): (i64, i64) = sqlx::query_as(
                            "SELECT COUNT(*), COUNT(*) FILTER (WHERE revoked_at IS NULL)
                             FROM api_keys WHERE tenant_id = $1",
                        )
                        .bind(SANDBOX_TENANT_ID)
                        .fetch_one(&pool)
                        .await
                        .expect("sandbox key stats");
                        (rows, live)
                    }
                };

                // The per-process cache hands out the SAME credential on
                // every call — no per-request inserts. The observation runs
                // under the provision window: a sibling re-mint that slips
                // in before the window is simply converged away by the retry.
                for attempt in 0..5u32 {
                    let first = sandbox(&state).await.expect("provision").api_key.clone();
                    let window = provision_window(&state).await;
                    let cached = SANDBOX.read().await.clone();
                    let first_still_live = match cached.as_deref() {
                        Some(cached) => {
                            cached.api_key == first && sandbox_key_is_live(&state, cached).await
                        }
                        None => false,
                    };
                    if !first_still_live {
                        // A sibling re-minted between the provision and the
                        // window: release, let the sandbox state converge on
                        // the sibling's row, and observe again.
                        window.rollback().await.expect("window rollback");
                        tokio::time::sleep(std::time::Duration::from_millis(
                            200 * u64::from(attempt + 1),
                        ))
                        .await;
                        continue;
                    }
                    let second = sandbox(&state).await.expect("cached").api_key.clone();
                    assert_eq!(
                        first, second,
                        "the process-wide cache must reuse the provisioned key"
                    );

                    let (rows, live) = key_stats(&state).await;
                    assert_eq!(rows, 1, "the sandbox tenant carries exactly one key row");
                    assert_eq!(live, 1, "and that row is live");
                    window.rollback().await.expect("window rollback");

                    // A fresh provision (a restarted process's cold cache) must
                    // reclaim the old row: no unbounded growth across restarts,
                    // and the key ceiling the raw insert used to bypass holds.
                    // OUTSIDE the window: this call itself takes the provision
                    // key. Any interleaved sibling provision converges to the
                    // same one-live-row state, so the final stats read is
                    // interleaving-proof without a window.
                    provision_sandbox(&state).await.expect("re-provision");
                    let (rows, live) = key_stats(&state).await;
                    assert_eq!(rows, 1, "superseded rows are deleted on rotation");
                    assert_eq!(live, 1, "exactly one live key survives rotation");
                    return;
                }
                panic!(
                    "a sibling process kept re-minting the sandbox row before the \
                     observation window could be established (5 attempts)"
                );
            })
        });
    }

    /// SM3 (audit F4) self-heal: a SIBLING process's rotation re-mints the
    /// single key row out from under this process's cache (the raw key is
    /// stored hash-only, so the sibling cannot reuse ours — it must mint a
    /// new one). The cache must notice via the liveness probe and hand back
    /// a key that matches the live row — not keep dispatching with the dead
    /// one until restart.
    ///
    /// Audit #12c: the heal observation runs inside [`provision_window`] —
    /// the shared row is global state across parallel test PROCESSES, and an
    /// uncontrolled sibling's re-mint between the heal and the assertions
    /// made this test flake. The window covers only cache probes, the Redis
    /// publication seams and reads: nothing in it can provision (which would
    /// wait on the window's own advisory key).
    #[test]
    fn sandbox_cache_self_heals_when_a_sibling_re_mints_the_key_row() {
        with_dkim_env(|state| {
            Box::pin(async move {
                for attempt in 0..5u32 {
                    let stale = sandbox(&state).await.expect("initial provision");
                    let stale_key = stale.api_key.clone();

                    // A sibling replica's cold cache DELETES + re-mints the row.
                    let sibling = provision_sandbox(&state)
                        .await
                        .expect("sibling re-provision");
                    assert_ne!(
                        sibling.api_key, stale_key,
                        "the sibling minted a fresh raw key"
                    );

                    // Exclusive observation window: hold the production provision
                    // advisory key so no OTHER replica can re-mint the row until
                    // the assertions below are done.
                    let window = provision_window(&state).await;
                    // The window was acquired AFTER the sibling's re-mint: a
                    // rival provision that STARTED earlier but committed later
                    // may own the row by now, which would make the injected
                    // sibling's key stale. The scenario this test pins needs
                    // the sibling's key to BE the live row under the window —
                    // otherwise converge on the winner and re-mint again.
                    if !sandbox_key_is_live(&state, &sibling).await {
                        window
                            .rollback()
                            .await
                            .expect("window rollback on stale sibling");
                        tokio::time::sleep(std::time::Duration::from_millis(
                            200 * u64::from(attempt + 1),
                        ))
                        .await;
                        continue;
                    }
                    // The in-window heal must resolve through the ADOPT path (a
                    // provision here would wait on the window's own key). Re-publish
                    // the sibling's key through the same production seam the
                    // sibling's provision used, then require the publication to be
                    // readable — a Redis outage fails loudly instead of deadlocking.
                    publish_shared_sandbox(&state, &sibling).await;
                    if adopted_shared_sandbox(&state).await.is_none() {
                        window
                            .rollback()
                            .await
                            .expect("window rollback after publication failure");
                        panic!(
                            "the sandbox key publication is unreadable — the self-heal \
                             scenario requires a working TEST_REDIS_URL"
                        );
                    }

                    // This process's NEXT sandbox() call must not serve the
                    // now-dead key: the liveness probe detects the invalidated
                    // row and the shared publication is adopted.
                    let healed = sandbox(&state).await.expect("healed provision");
                    assert_ne!(
                        healed.api_key, stale_key,
                        "the dead cached key must not be served"
                    );

                    let live_hash: String =
                        sqlx::query_scalar("SELECT key_hash FROM api_keys WHERE tenant_id = $1")
                            .bind(SANDBOX_TENANT_ID)
                            .fetch_one(&state.db)
                            .await
                            .expect("the single live sandbox key row");
                    assert_eq!(healed.key_hash, live_hash, "the healed key IS the live row");
                    // And the cache converged: subsequent calls reuse the healed
                    // key instead of rotating again.
                    let again = sandbox(&state).await.expect("cached heal");
                    assert_eq!(again.api_key, healed.api_key, "the heal is memoized");
                    window.rollback().await.expect("window rollback");
                    return;
                }
                panic!(
                    "a rival provision kept winning the row before the observation \
                     window could be established (5 attempts)"
                );
            })
        });
    }

    /// SM3 (audit F4) cross-process adoption: a cold SIBLING process (same
    /// DB + Redis, empty process cache) must ADOPT the live shared key via
    /// the Redis publication instead of rotating it out from under every
    /// other replica.
    ///
    /// Audit #12c: the cold-start observation runs inside a
    /// [`provision_window`]; a sibling's re-mint + re-publication between
    /// this process's provision and its adopt would otherwise replace the
    /// key mid-assertion. The in-window re-publish goes through the same
    /// production seam (`publish_shared_sandbox`) a real provision uses.
    #[test]
    fn sandbox_adopts_the_shared_key_across_processes_without_rotating() {
        with_dkim_env(|state| {
            Box::pin(async move {
                for attempt in 0..5u32 {
                    let first = sandbox(&state).await.expect("initial provision");
                    let first_key = first.api_key.clone();

                    // Exclusive observation window over the shared row.
                    let window = provision_window(&state).await;
                    // `first` must still BE the live row (a sibling may have
                    // re-minted between the provision and the window — then
                    // converge on the sibling's row and observe again).
                    if !sandbox_key_is_live(&state, &first).await {
                        window.rollback().await.expect("window rollback");
                        tokio::time::sleep(std::time::Duration::from_millis(
                            200 * u64::from(attempt + 1),
                        ))
                        .await;
                        continue;
                    }
                    // Re-publish through the production seam so the cold-start
                    // adopt observes exactly this key even when a sibling's
                    // publication overwrote it (publishing takes no advisory
                    // key, so this cannot deadlock the window).
                    publish_shared_sandbox(&state, &first).await;

                    // Simulate the sibling's cold start: same shared DB + Redis,
                    // an empty process cache.
                    *SANDBOX.write().await = None;
                    let adopted = sandbox(&state).await.expect("sibling adopts");
                    assert_eq!(
                        adopted.api_key, first_key,
                        "the cold process must adopt the live shared key, not rotate it"
                    );

                    // Adoption did not churn the row either.
                    let rows: i64 =
                        sqlx::query_scalar("SELECT COUNT(*) FROM api_keys WHERE tenant_id = $1")
                            .bind(SANDBOX_TENANT_ID)
                            .fetch_one(&state.db)
                            .await
                            .expect("sandbox key count");
                    assert_eq!(rows, 1, "adoption rotates nothing");

                    // A third cold process converges on the same key again.
                    *SANDBOX.write().await = None;
                    let third = sandbox(&state).await.expect("third process");
                    assert_eq!(third.api_key, first_key);
                    window.rollback().await.expect("window rollback");
                    return;
                }
                panic!(
                    "a sibling process kept re-minting the sandbox row before the \
                     observation window could be established (5 attempts)"
                );
            })
        });
    }

    #[test]
    fn redis_rate_limit_fails_closed_at_the_bucket_and_the_emergency_limiter_takes_over() {
        with_dkim_env(|state| {
            Box::pin(async move {
                let key = format!("adv_explorer_rl:{}", uuid::Uuid::new_v4());
                for _ in 0..RATE_LIMIT_PER_MINUTE {
                    assert!(
                        // coverage: justified — the closure fires only if
                        // Redis fails during a test asserting Redis health;
                        // a healthy test Redis keeps it at zero.
                        redis_rate_limit(&state, &key)
                            .await
                            .unwrap_or_else(|_| panic!(
                                "redis is healthy: requests within the budget pass"
                            )),
                        "requests within the budget pass"
                    );
                }
                assert!(
                    !redis_rate_limit(&state, &key)
                        .await
                        .expect("redis is healthy: verdict available"),
                    "the 13th request in the window must be refused"
                );
                // Cleanup so a rerun starts clean even before the TTL.
                let mut conn = state.redis.get().await.expect("redis");
                let _: Result<i64, _> = deadpool_redis::redis::cmd("DEL")
                    .arg(&key)
                    .query_async(&mut *conn)
                    .await;

                // Fix (P1 Redis-down = no abuse ceiling): without Redis the
                // distributed limiter can no longer answer (Err) — and the
                // caller engages the in-process emergency limiter instead of
                // allowing. The emergency ceiling is STRICTER than the
                // distributed one.
                let dead = crate::app::test_support::test_state_over_with_config_and_redis(
                    state.db.clone(),
                    crate::app::test_support::test_config(),
                    "redis://127.0.0.1:1",
                )
                .await;
                assert!(
                    redis_rate_limit(&dead, "adv_explorer_dead").await.is_err(),
                    "an unreachable Redis must surface as Err(()) — never as allow"
                );
                let ip = format!("adv-dead-{}", uuid::Uuid::new_v4());
                for _ in 0..EMERGENCY_RATE_LIMIT_PER_MINUTE {
                    assert!(
                        rate_limit(&dead, &ip).await,
                        "the emergency limiter allows up to its (stricter) ceiling"
                    );
                }
                assert!(
                    !rate_limit(&dead, &ip).await,
                    "past the emergency ceiling the request is refused even with Redis down"
                );
                let other = format!("adv-dead-other-{}", uuid::Uuid::new_v4());
                assert!(
                    rate_limit(&dead, &other).await,
                    "a different IP keeps its own emergency bucket"
                );
            })
        });
    }

    #[test]
    fn emergency_limiter_bounds_a_bucket_and_never_leaks_across_ips() {
        let t0 = std::time::Instant::now();
        let ip = format!("emg-{}", uuid::Uuid::new_v4());
        let other = format!("emg-other-{}", uuid::Uuid::new_v4());

        for _ in 0..EMERGENCY_RATE_LIMIT_PER_MINUTE {
            assert!(emergency_allow(&ip, t0), "within the emergency ceiling");
        }
        assert!(
            !emergency_allow(&ip, t0),
            "one request past the emergency ceiling is refused"
        );
        assert!(
            emergency_allow(&other, t0),
            "buckets are per-IP: a fresh IP is unaffected by the exhausted one"
        );

        // A new fixed window resets the bucket.
        let later = t0 + EMERGENCY_WINDOW;
        assert!(
            emergency_allow(&ip, later),
            "the window rollover must reset the per-IP counter"
        );
    }

    #[test]
    fn emergency_limiter_prunes_stale_buckets_when_it_grows_large() {
        let t0 = std::time::Instant::now();
        // Push past the prune threshold with buckets stamped at t0.
        for i in 0..(EMERGENCY_PRUNE_THRESHOLD + 100) {
            emergency_allow(&format!("emg-prune-{i}"), t0);
        }
        // One call from the future: the retain must drop every stale t0 bucket.
        assert!(emergency_allow("emg-prune-trigger", t0 + EMERGENCY_WINDOW));
        let map = EMERGENCY_LIMITER.get().expect("limiter initialized").lock();
        assert!(
            map.len() <= 2,
            // coverage: justified — the format argument is evaluated only
            // when the assertion FAILS; a passing run never measures it.
            "stale buckets must be pruned once the map grows large, got {}",
            map.len()
        );
        assert!(map.contains_key("emg-prune-trigger"));
    }

    /// Fix (P1 cold-start race): concurrent FIRST provisions must end with
    /// exactly ONE live sandbox key, and the provision results must include
    /// that key's plaintext (hash matches the stored hash). Under the old
    /// check→revoke→create→set sequence, racing provisions could persist a
    /// sandbox whose only keys were revoked.
    #[test]
    fn concurrent_provisions_leave_exactly_one_live_key_with_a_matching_plaintext() {
        with_dkim_env(|state| {
            Box::pin(async move {
                let provisions = 8usize;
                let mut handles = Vec::with_capacity(provisions);
                for _ in 0..provisions {
                    let st = state.clone();
                    handles.push(tokio::task::spawn(async move {
                        provision_sandbox(&st).await.expect("provision")
                    }));
                }
                let results = futures::future::join_all(handles).await;
                let plaintexts: Vec<String> = results
                    .into_iter()
                    .map(|r| r.expect("join").api_key)
                    .collect();
                assert_eq!(plaintexts.len(), provisions);

                let live: i64 = sqlx::query_scalar(
                    "SELECT COUNT(*)::bigint FROM api_keys
                     WHERE tenant_id = $1 AND revoked_at IS NULL",
                )
                .bind(SANDBOX_TENANT_ID)
                .fetch_one(&state.db)
                .await
                .expect("count live keys");
                assert_eq!(
                    live, 1,
                    "exactly one live sandbox key must survive racing provisions"
                );

                let stored_hash: String = sqlx::query_scalar(
                    "SELECT key_hash FROM api_keys
                     WHERE tenant_id = $1 AND revoked_at IS NULL",
                )
                .bind(SANDBOX_TENANT_ID)
                .fetch_one(&state.db)
                .await
                .expect("live key hash");
                assert!(
                    plaintexts.iter().any(|k| {
                        apexmail_lib::hash_api_key_with_secret(k, &state.config.api_key_hash_secret)
                            == stored_hash
                    }),
                    "the served plaintext of the surviving provision must match the stored hash"
                );
            })
        });
    }

    /// The process-wide sandbox cache: concurrent first `sandbox()` calls
    /// must NEVER error and NEVER serve a broken/revoked credential (the P1
    /// cold-start race this cache replaced), and the process must CONVERGE
    /// on the live row. Sibling processes legitimately rotate the single
    /// row (each has its own cache), so "identical keys" is not the
    /// invariant — "no caller is left holding a dead credential, and the
    /// cache ends live" is.
    #[test]
    fn concurrent_first_requests_converge_on_a_live_sandbox_key() {
        with_dkim_env(|state| {
            Box::pin(async move {
                let mut handles = Vec::new();
                for _ in 0..4 {
                    let st = state.clone();
                    handles.push(tokio::task::spawn(async move {
                        sandbox(&st).await.expect("sandbox").api_key.clone()
                    }));
                }
                let keys = futures::future::join_all(handles).await;
                let keys: Vec<String> = keys.into_iter().map(|k| k.expect("join")).collect();
                assert!(keys.iter().all(|k| !k.is_empty()), "every caller is served");

                // Convergence: the process cache ends holding the LIVE row's
                // credential (a served key from a superseded epoch must not
                // be what the process keeps). Observed under the provision
                // window (audit #12c): the shared row is global state across
                // parallel test processes, and a sibling's re-mint between
                // the cache read and the row read would fail the comparison.
                for attempt in 0..5u32 {
                    let window = provision_window(&state).await;
                    let cached = SANDBOX.read().await.clone().expect("cache populated");
                    if !sandbox_key_is_live(&state, &cached).await {
                        // A sibling re-minted before the window: converge on
                        // the sibling's row and observe again.
                        window.rollback().await.expect("window rollback");
                        tokio::time::sleep(std::time::Duration::from_millis(
                            200 * u64::from(attempt + 1),
                        ))
                        .await;
                        continue;
                    }
                    let live_hash: Option<String> =
                        sqlx::query_scalar("SELECT key_hash FROM api_keys WHERE tenant_id = $1")
                            .bind(SANDBOX_TENANT_ID)
                            .fetch_optional(&state.db)
                            .await
                            .expect("sandbox key row");
                    assert_eq!(
                        live_hash.as_deref(),
                        Some(cached.key_hash.as_str()),
                        "the process cache converges on the live row"
                    );
                    window.rollback().await.expect("window rollback");
                    return;
                }
                panic!(
                    "a sibling process kept re-minting the sandbox row before the \
                     observation window could be established (5 attempts)"
                );
            })
        });
    }

    #[test]
    fn calculate_renders_clamped_inputs_and_support_line() {
        with_dkim_env(|state| {
            Box::pin(async move {
                let resp = calculate(
                    State(state.clone()),
                    Form(CalculatorForm {
                        volume: i64::MAX,
                        peak_daily: -1,
                        domains: -10,
                        team_users: i64::MIN,
                        dedicated_ips: 3,
                        support: Some("priority".into()),
                        billing_cycle: "annual".into(),
                    }),
                )
                .await;
                assert_eq!(resp.status(), StatusCode::OK);
                let page = html(resp).await;
                assert!(page.contains("priority"), "support line rendered: {page}");
                assert!(page.contains("Annual total"), "annual branch: {page}");
                assert!(page.contains("Dedicated IP"), "ip add-on line: {page}");

                // Serde defaults path (missing fields) and the monthly branch.
                let defaults: CalculatorForm = serde_json::from_value(serde_json::json!({}))
                    .expect("empty form uses the serde defaults");
                let resp = calculate(State(state.clone()), Form(defaults)).await;
                assert_eq!(resp.status(), StatusCode::OK);
                let page = html(resp).await;
                assert!(page.contains("Monthly total"), "{page}");
                assert!(page.contains("50,000"), "{page}");
            })
        });
    }

    #[test]
    fn grader_is_explicitly_disabled_without_state_and_validates_input() {
        with_dkim_env(|state| {
            Box::pin(async move {
                // Too-short / punctuation-only inputs are rejected before any engine.
                for bad in ["", "   ", "nodot", &"x".repeat(254), "has space.com"] {
                    let resp = grade_domain(
                        State(state.clone()),
                        unique_peer(),
                        axum::http::HeaderMap::new(),
                        Form(GradeDomainForm {
                            domain: bad.to_string(),
                        }),
                    )
                    .await;
                    assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "input {bad:?}");
                    let page = html(resp).await;
                    assert!(page.contains("INVALID_INPUT"), "{page}");
                }
                // Valid domain, no grader configured → honest 503 refusal.
                let resp = grade_domain(
                    State(state.clone()),
                    unique_peer(),
                    axum::http::HeaderMap::new(),
                    Form(GradeDomainForm {
                        domain: "example.com".into(),
                    }),
                )
                .await;
                assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
                let page = html(resp).await;
                assert!(page.contains("GRADER_DISABLED"), "{page}");
            })
        });
    }

    #[test]
    fn grader_rate_limit_returns_429_page_for_the_bucket() {
        with_dkim_env(|state| {
            Box::pin(async move {
                let ip = format!("203.0.113.{}", (std::process::id() % 200 + 1).min(254));
                let peer: SocketAddr = format!("{ip}:5555").parse().unwrap();
                // Fill the bucket directly (12/min) then grade once.
                for _ in 0..RATE_LIMIT_PER_MINUTE {
                    assert!(rate_limit(&state, &ip).await);
                }
                let resp = grade_domain(
                    State(state.clone()),
                    Some(ConnectInfo(peer)),
                    axum::http::HeaderMap::new(),
                    Form(GradeDomainForm {
                        domain: "example.com".into(),
                    }),
                )
                .await;
                assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
                let page = html(resp).await;
                assert!(page.contains("RATE_LIMITED"), "{page}");

                let mut conn = state.redis.get().await.expect("redis");
                let _: Result<i64, _> = deadpool_redis::redis::cmd("DEL")
                    .arg(format!("explorer_rl:{ip}"))
                    .query_async(&mut *conn)
                    .await;
            })
        });
    }

    #[test]
    fn example_com_domain_matcher_is_host_boundary_aware() {
        for (json, expected) in [
            (serde_json::json!({"name": "example.com"}), true),
            (serde_json::json!({"domain": "sub.example.com"}), true),
            (serde_json::json!({"name": "notexample.com"}), false),
            (serde_json::json!({"name": "example.com.evil.io"}), false),
            (serde_json::json!({"name": "EXAMPLE.COM"}), true),
            (serde_json::json!({"name": 7}), false),
            (serde_json::json!({}), false),
        ] {
            assert_eq!(is_example_com_domain(&json), expected, "{json}");
        }
    }

    /// The fresh-domain branch of provisioning: with the sandbox's
    /// example.com row removed (under the same advisory lock the
    /// provisioner takes, so no racing process re-inserts it first), a
    /// provision generates a REAL DKIM keypair and re-inserts the verified
    /// domain. The immediately following provision finds the live key and
    /// ROTATES it — still exactly one live key, and the survivor is the
    /// newest provision's plaintext.
    #[test]
    fn provision_inserts_a_missing_domain_and_rotates_a_live_key() {
        with_dkim_env(|state| {
            Box::pin(async move {
                let mut tx = state.db.begin().await.expect("delete tx");
                sqlx::query("SELECT pg_advisory_xact_lock(hashtext($1))")
                    .bind(SANDBOX_PROVISION_LOCK)
                    .execute(&mut *tx)
                    .await
                    .expect("provision lock");
                sqlx::query("DELETE FROM domains WHERE tenant_id = $1 AND name = 'example.com'")
                    .bind(SANDBOX_TENANT_ID)
                    .execute(&mut *tx)
                    .await
                    .expect("delete sandbox domain");
                tx.commit().await.expect("commit delete");

                let first = provision_sandbox(&state).await.expect("first provision");
                let domain: Option<String> = sqlx::query_scalar(
                    "SELECT name FROM domains WHERE tenant_id = $1 AND name = 'example.com' LIMIT 1",
                )
                .bind(SANDBOX_TENANT_ID)
                .fetch_optional(&state.db)
                .await
                .expect("domain query");
                assert_eq!(
                    domain.as_deref(),
                    Some("example.com"),
                    "the provision must re-insert the DKIM-encrypted sandbox domain"
                );
                let dkim_enabled: bool = sqlx::query_scalar(
                    "SELECT dkim_enabled FROM domains WHERE tenant_id = $1 AND name = 'example.com'",
                )
                .bind(SANDBOX_TENANT_ID)
                .fetch_one(&state.db)
                .await
                .expect("dkim flag");
                assert!(dkim_enabled, "the real send path requires dkim_enabled");

                // Second provision: the first left a live key, so this one
                // rotates instead of minting blindly. The rotation's SURVIVOR
                // is then observed under the provision window (audit #12c):
                // a sibling provision between this rotation and the hash
                // comparison would otherwise replace the "newest provision"
                // out from under the assertion. A rival that started earlier
                // and committed later may still own the row when the window
                // is acquired — then converge and rotate again.
                for attempt in 0..5u32 {
                    let second = provision_sandbox(&state).await.expect("second provision");
                    assert_ne!(
                        first.api_key, second.api_key,
                        "rotation mints a fresh credential"
                    );
                    let window = provision_window(&state).await;
                    if !sandbox_key_is_live(&state, &second).await {
                        window
                            .rollback()
                            .await
                            .expect("window rollback on stale rotation");
                        tokio::time::sleep(std::time::Duration::from_millis(
                            200 * u64::from(attempt + 1),
                        ))
                        .await;
                        continue;
                    }
                    let live: i64 = sqlx::query_scalar(
                        "SELECT COUNT(*)::bigint FROM api_keys
                         WHERE tenant_id = $1 AND revoked_at IS NULL",
                    )
                    .bind(SANDBOX_TENANT_ID)
                    .fetch_one(&state.db)
                    .await
                    .expect("count live keys");
                    assert_eq!(live, 1, "rotation must leave exactly one live key");
                    let stored_hash: String = sqlx::query_scalar(
                        "SELECT key_hash FROM api_keys WHERE tenant_id = $1 AND revoked_at IS NULL",
                    )
                    .bind(SANDBOX_TENANT_ID)
                    .fetch_one(&state.db)
                    .await
                    .expect("live key hash");
                    assert_eq!(
                        apexmail_lib::hash_api_key_with_secret(
                            &second.api_key,
                            &state.config.api_key_hash_secret
                        ),
                        stored_hash,
                        "the surviving live key must be the newest provision's"
                    );
                    window.rollback().await.expect("window rollback");
                    return;
                }
                panic!(
                    "a rival provision kept winning the row before the observation \
                     window could be established (5 attempts)"
                );
            })
        });
    }

    /// A Redis peer that accepts TCP but ERRORS every data command: the
    /// pool's connect AND its recycle PING both succeed (PING args are
    /// echoed, as Redis does) while the INCR fails — the limiter must
    /// surface `Err(())` (never a fabricated allow) and the caller must
    /// engage the stricter in-process emergency limiter.
    /// Byte substring search for the RESP-lite stub below.
    fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
        haystack
            .windows(needle.len())
            .position(|window| window == needle)
    }

    /// RESP-lite: answer EVERY command in the chunk — clients pipeline
    /// (deadpool's recycle PING and the INCR can share one TCP write),
    /// so replying to only the first command strands the second and the
    /// client hangs forever. PING echoes its argument (what a real
    /// Redis does and what deadpool's recycle check verifies); every
    /// other command errors.
    fn reply_for(chunk: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut rest = chunk;
        while let Some(dollar) = find(rest, b"$") {
            let after = &rest[dollar + 1..];
            let Some(crlf) = find(after, b"\r\n") else {
                break;
            };
            let Ok(len) = std::str::from_utf8(&after[..crlf])
                .unwrap_or("x")
                .parse::<usize>()
            else {
                break;
            };
            if after.len() < crlf + 2 + len {
                break;
            }
            let arg = &after[crlf + 2..crlf + 2 + len];
            if arg == b"PING" {
                out.extend_from_slice(format!("${}\r\n", arg.len()).as_bytes());
                out.extend_from_slice(arg);
                out.extend_from_slice(b"\r\n");
            } else {
                out.extend_from_slice(b"-ERR fake redis: data commands disabled\r\n");
            }
            rest = &after[crlf + 2 + len..];
        }
        if out.is_empty() {
            out.extend_from_slice(b"-ERR fake redis: data commands disabled\r\n");
        }
        out
    }

    /// Spawn the fake Redis stub on an ephemeral port; returns the port.
    /// Every connection is served on its own thread until the process ends.
    fn spawn_fake_redis() -> u16 {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind fake redis");
        let port = listener.local_addr().expect("local addr").port();
        std::thread::spawn(move || {
            use std::io::{Read, Write};
            for stream in listener.incoming().flatten() {
                std::thread::spawn(move || {
                    let mut sock = stream;
                    let mut buf = [0u8; 4096];
                    while let Ok(n) = sock.read(&mut buf) {
                        if n == 0 {
                            break;
                        }
                        if sock.write_all(&reply_for(&buf[..n])).is_err() {
                            // coverage: justified — fires only when the
                            // client resets the connection between its last
                            // read and this write (a disconnect race); the
                            // deterministic clients below always drain the
                            // reply first.
                            break;
                        }
                    }
                });
            }
        });
        port
    }

    #[test]
    fn redis_increment_failure_degrades_to_the_emergency_limiter() {
        let port = spawn_fake_redis();
        with_dkim_env(|state| {
            Box::pin(async move {
                let erroring = crate::app::test_support::test_state_over_with_config_and_redis(
                    state.db.clone(),
                    crate::app::test_support::test_config(),
                    &format!("redis://127.0.0.1:{port}"),
                )
                .await;
                assert!(
                    redis_rate_limit(&erroring, "adv_explorer_erroring_incr")
                        .await
                        .is_err(),
                    "a failing INCR is Err(()) — never an accidental allow"
                );
                let ip = format!("adv-erroring-{}", uuid::Uuid::new_v4());
                for _ in 0..EMERGENCY_RATE_LIMIT_PER_MINUTE {
                    assert!(
                        rate_limit(&erroring, &ip).await,
                        "the emergency limiter engages while Redis errors"
                    );
                }
                assert!(
                    !rate_limit(&erroring, &ip).await,
                    "the emergency ceiling holds while Redis errors"
                );
            })
        });
    }

    /// The DKIM env-var RESTORE arm of `with_dkim_env`: a value that was set
    /// before the helper runs is captured and put back verbatim (not
    /// removed). The env mutation is serialised on the module's mutex, so
    /// the capture always observes the value this test planted: any sibling
    /// capture/restore section either completed before the mutex let this
    /// test set it, or runs after and itself restores the planted value.
    #[test]
    fn with_dkim_env_restores_a_previously_set_encryption_key() {
        let planted = "previous-key-planted-by-restore-test";
        {
            let _guard = crate::test_db::DKIM_ENV_MUTEX
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            std::env::set_var(
                apexmail_lib::dkim::DKIM_PRIVATE_KEY_ENCRYPTION_KEY_ENV,
                planted,
            );
        }
        with_dkim_env(|_state| Box::pin(async move {}));
        let current = std::env::var(apexmail_lib::dkim::DKIM_PRIVATE_KEY_ENCRYPTION_KEY_ENV)
            .expect("a previously set key must be restored, never removed");
        assert_eq!(current, planted);
        // Leave later tests the pristine (unset) environment.
        {
            let _guard = crate::test_db::DKIM_ENV_MUTEX
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            std::env::remove_var(apexmail_lib::dkim::DKIM_PRIVATE_KEY_ENCRYPTION_KEY_ENV);
        }
    }

    /// Malformed and truncated RESP chunks against the fake Redis stub: a
    /// non-numeric bulk-length prefix and a bulk string cut off mid-payload
    /// must degrade to the stub's error reply — never hang or panic.
    #[test]
    fn fake_redis_stub_degrades_malformed_and_truncated_resp_to_errors() {
        let port = spawn_fake_redis();
        use std::io::{Read, Write};

        // (a) A bulk-string header with a NON-NUMERIC length ($zz): nothing
        // parseable precedes the bail-out, so the stub's generic error reply
        // is all the client gets.
        let mut bad = std::net::TcpStream::connect(("127.0.0.1", port)).expect("connect");
        bad.set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .expect("read timeout");
        bad.write_all(b"*1\r\n$zz\r\n").expect("write bad header");
        let mut reply = [0u8; 128];
        let n = bad.read(&mut reply).expect("read stub error reply");
        assert!(
            reply[..n].starts_with(b"-ERR"),
            // coverage: justified — the format argument is evaluated only
            // when the assertion FAILS; a passing run never measures it.
            "a non-numeric RESP length must error, got {:?}",
            &reply[..n]
        );

        // (b) A parseable command prefix followed by a bulk string whose
        // declared length (5000) far exceeds what was actually sent: the
        // stub errors for the prefix instead of waiting forever.
        let mut partial = std::net::TcpStream::connect(("127.0.0.1", port)).expect("connect");
        partial
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .expect("read timeout");
        let mut truncated = b"*1\r\n$4\r\nINCR\r\n$5000\r\n".to_vec();
        truncated.extend_from_slice(&[b'x'; 64]);
        partial.write_all(&truncated).expect("write truncated bulk");
        let n = partial
            .read(&mut reply)
            .expect("read truncated-bulk error reply");
        assert!(
            reply[..n].starts_with(b"-ERR"),
            // coverage: justified — the format argument is evaluated only
            // when the assertion FAILS; a passing run never measures it.
            "a truncated bulk string must still produce an error reply, got {:?}",
            &reply[..n]
        );
    }

    /// An AppState with the Email Grader ENABLED (real DNS resolver; DNS
    /// failures degrade to low scores, never errors — GraderEngine
    /// assembles a response either way). `rate_limit_max = 0` refuses every
    /// check at the engine's per-IP limiter, deterministically and with no
    /// network at all.
    async fn grader_enabled_state(pool: sqlx::PgPool, engine_rate_limit_max: u32) -> AppState {
        crate::test_db::ensure_aws_test_env();
        let grader_config = email_grader::GraderConfig {
            enabled: true,
            rate_limit_max: engine_rate_limit_max,
            rate_limit_window_seconds: 60,
            cache_ttl_seconds: 0,
            network_timeout_seconds: 1,
            ..email_grader::GraderConfig::default()
        };
        let engine =
            email_grader::GraderEngine::new(grader_config.clone(), None).expect("grader engine");
        let gs = std::sync::Arc::new(
            email_grader::GraderState::new(
                std::sync::Arc::new(engine),
                grader_config,
                pool.clone(),
            )
            .expect("grader state"),
        );
        let config = crate::app::test_support::test_config();
        let redis_url = std::env::var("TEST_REDIS_URL")
            .ok()
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| "redis://127.0.0.1:1".into());
        let redis = deadpool_redis::Config::from_url(redis_url)
            .create_pool(Some(deadpool_redis::Runtime::Tokio1))
            .expect("lazy redis pool");
        let aws_config = aws_config::defaults(aws_config::BehaviorVersion::latest())
            .region(aws_sdk_sesv2::config::Region::new("us-east-1"))
            .load()
            .await;
        let ses_provider = std::sync::Arc::new(crate::ses_provider::SesIpProvider::new(
            aws_sdk_sesv2::Client::new(&aws_config),
            pool.clone(),
            "apexmail".into(),
            "us-east-1".into(),
        ));
        crate::state::AppStateInner::with_ddos_protector(
            pool.clone(),
            apexmail_db::pool::PoolPair {
                rw: pool.clone(),
                ro: pool,
            },
            redis,
            config.clone(),
            reqwest::Client::new(),
            (*ses_provider).clone(),
            None,
            std::sync::Arc::new(
                ddos_protection::DdosProtector::new(ddos_protection::ProtectorConfig::default())
                    .await
                    .expect("ddos protector"),
            ),
            Some(gs),
            None,
            crate::resilience::ResilientClient::new_from_config(&config),
        )
    }

    /// The grader-delegated ERROR branch: the engine's per-IP rate limit
    /// (max = 0) refuses the check, and the explorer must map the JSON error
    /// envelope onto its honest error page — code AND message extracted from
    /// the envelope, never raw engine internals.
    #[test]
    fn grader_engine_refusal_maps_to_the_explorer_error_page() {
        with_dkim_env(|state| {
            Box::pin(async move {
                let grader = grader_enabled_state(state.db.clone(), 0).await;
                let resp = grade_domain(
                    State(grader),
                    unique_peer(),
                    axum::http::HeaderMap::new(),
                    Form(GradeDomainForm {
                        domain: "Example.COM".into(),
                    }),
                )
                .await;
                assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
                let page = html(resp).await;
                assert!(page.contains("RATE_LIMITED"), "{page}");
                assert!(!page.contains("internal_error"), "{page}");
            })
        });
    }

    /// The grader-delegated SUCCESS branch: a clean domain really reaches
    /// the engine and the scored report is rendered as the zero-JS grade
    /// page (the pasted-URL noise has been stripped on the way in).
    #[test]
    fn grader_check_renders_the_scored_report_page() {
        with_dkim_env(|state| {
            Box::pin(async move {
                let grader = grader_enabled_state(state.db.clone(), 100).await;
                let resp = grade_domain(
                    State(grader),
                    unique_peer(),
                    axum::http::HeaderMap::new(),
                    Form(GradeDomainForm {
                        domain: "https://Example.COM".into(),
                    }),
                )
                .await;
                assert_eq!(resp.status(), StatusCode::OK);
                let page = html(resp).await;
                assert!(page.contains("DOMAIN CHECK"), "grade page: {page}");
                assert!(page.contains("example.com"), "cleaned domain: {page}");
            })
        });
    }

    /// A non-JSON upstream response (an HTML page, an empty 404) is passed
    /// through verbatim in the `raw` field instead of being fabricated
    /// into JSON.
    #[test]
    fn non_json_upstream_responses_render_raw() {
        with_dkim_env(|state| {
            Box::pin(async move {
                let (status, body) =
                    dispatch(&state, Method::GET, "/verify-email", "am_probe_key", None).await;
                assert!(
                    body.get("raw").is_some(),
                    "non-JSON body must fall back to the raw string: {status} {body}"
                );
            })
        });
    }

    /// A request with NO peer address buckets on "unknown": once that
    /// shared bucket is exhausted the exec endpoint answers the 429 page;
    /// once freed the very same request flows through the sandbox.
    #[test]
    fn exec_buckets_unknown_peers_and_enforces_the_ceiling_on_them() {
        with_dkim_env(|state| {
            Box::pin(async move {
                let window = unknown_bucket_window(&state).await;
                let no_peer = |state: &AppState| {
                    let state = state.clone();
                    async move {
                        exec(
                            State(state),
                            None,
                            axum::http::HeaderMap::new(),
                            Form(ExplorerForm {
                                lane: "messages".to_string(),
                                body: String::new(),
                            }),
                        )
                        .await
                    }
                };

                del_redis_key(&state, "explorer_rl:unknown").await;
                for _ in 0..RATE_LIMIT_PER_MINUTE {
                    assert!(rate_limit(&state, "unknown").await, "bucket fill");
                }
                let limited = no_peer(&state).await;
                assert_eq!(limited.status(), StatusCode::TOO_MANY_REQUESTS);
                let page = html(limited).await;
                assert!(page.contains("Too many sandbox requests"), "{page}");

                del_redis_key(&state, "explorer_rl:unknown").await;
                let allowed = no_peer(&state).await;
                assert_eq!(allowed.status(), StatusCode::OK);
                let page = html(allowed).await;
                assert!(page.contains("200"), "{page}");
                // Leave the shared bucket clean for sibling processes.
                del_redis_key(&state, "explorer_rl:unknown").await;
                window
                    .rollback()
                    .await
                    .expect("unknown-bucket window rollback");
            })
        });
    }

    async fn del_redis_key(state: &AppState, key: &str) {
        let mut conn = state.redis.get().await.expect("redis");
        let _: Result<i64, _> = deadpool_redis::redis::cmd("DEL")
            .arg(key)
            .query_async(&mut *conn)
            .await;
    }

    /// The FIRST sandbox provision failing (unreachable database) is a
    /// generic 500 page: the provisioning error carries database detail,
    /// which is logged, never rendered.
    #[test]
    fn sandbox_provisioning_failure_is_a_generic_500_page() {
        with_dkim_env(|_state| {
            Box::pin(async move {
                let dead = sqlx::postgres::PgPoolOptions::new()
                    .max_connections(1)
                    .acquire_timeout(std::time::Duration::from_millis(300))
                    .connect_lazy("postgres://apexmail:apexmail@127.0.0.1:1/apexmail")
                    .expect("lazy dead pool");
                let dead_state = crate::app::test_support::test_state_over(dead).await;
                let resp = exec(
                    State(dead_state),
                    unique_peer(),
                    axum::http::HeaderMap::new(),
                    Form(ExplorerForm {
                        lane: "messages".to_string(),
                        body: String::new(),
                    }),
                )
                .await;
                assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
                let page = html(resp).await;
                assert!(page.contains("temporarily unavailable"), "{page}");
                assert!(
                    !page.contains("sandbox provision"),
                    "the raw provisioning error must not reach the page: {page}"
                );
            })
        });
    }

    /// A grader request with no peer address still buckets and validates
    /// (the "unknown" bucket path through grade_domain).
    #[test]
    fn grader_without_connect_info_still_validates_input() {
        with_dkim_env(|state| {
            Box::pin(async move {
                let window = unknown_bucket_window(&state).await;
                del_redis_key(&state, "explorer_rl:unknown").await;
                let resp = grade_domain(
                    State(state.clone()),
                    None,
                    axum::http::HeaderMap::new(),
                    Form(GradeDomainForm {
                        domain: "nodot".to_string(),
                    }),
                )
                .await;
                assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
                let page = html(resp).await;
                assert!(page.contains("INVALID_INPUT"), "{page}");
                del_redis_key(&state, "explorer_rl:unknown").await;
                window
                    .rollback()
                    .await
                    .expect("unknown-bucket window rollback");
            })
        });
    }
}
