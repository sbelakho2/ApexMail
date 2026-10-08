//! Open-tracking pixel endpoints.
//!
//! GET `{pixel_path}/:tracking_id` — canonical pixel URL (path param).
//! GET `/o.gif` — alternative via `?t=` query param.
//!
//! Both endpoints ALWAYS return the transparent GIF (even for invalid tokens)
//! so that email clients display images correctly. Event recording is
//! fire-and-forget in a detached Tokio task — never blocks the response.

use std::net::SocketAddr;
use std::sync::LazyLock;

use axum::{
    extract::{ConnectInfo, Path, Query, State},
    http::HeaderMap,
    response::Response,
};
use serde::Deserialize;
use tokio::sync::Semaphore;
use tracing::{debug, error, info, warn};

use crate::processor::OpenData;
use crate::routes::custom_host::{ensure_token_matches_host, host_scope_or_refuse, HostScope};
use crate::routes::{extract_client_ip, TRANSPARENT_GIF};
use crate::state::AppState;

const PIXEL_CSP: &str = "default-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'; img-src 'self' data:; script-src 'none'; style-src 'none'; object-src 'none'";

/// Bound on concurrently running open-recorder tasks. The pixel endpoint is
/// fire-and-forget, so without a bound a burst of pixel requests spawns an
/// unbounded number of recorder tasks (each holding Redis pool resources).
/// When all permits are taken the excess open is dropped and counted —
/// recording is best-effort by design and must never amplify load.
const MAX_CONCURRENT_OPEN_RECORDERS: usize = 64;

static OPEN_RECORDER_SEMAPHORE: LazyLock<Semaphore> =
    LazyLock::new(|| Semaphore::new(MAX_CONCURRENT_OPEN_RECORDERS));

/// Pre-built response headers for the pixel — computed once; cloned per request.
/// Shared pixel response headers.
fn pixel_response() -> Response {
    let len = TRANSPARENT_GIF.len().to_string();
    axum::http::Response::builder()
        .status(200)
        .header("content-type", "image/gif")
        .header("content-length", len)
        .header(
            "cache-control",
            "no-store, no-cache, must-revalidate, proxy-revalidate",
        )
        .header("pragma", "no-cache")
        .header("expires", "0")
        .header("vary", "*")
        .header("content-security-policy", PIXEL_CSP)
        .header("x-content-type-options", "nosniff")
        .header("x-robots-tag", "noindex, nofollow")
        .body(axum::body::Body::from(TRANSPARENT_GIF))
        .unwrap_or_default()
}

// ── Main pixel route ──────────────────────────────────────────────────────────

pub async fn handle_pixel(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(tracking_id): Path<String>,
) -> Response {
    // Capability wave 2: unconfigured custom hosts are refused by name
    // (never a silent 200-GIF bounce).
    let scope = match host_scope_or_refuse(&state, &headers).await {
        Ok(scope) => scope,
        Err(refusal) => return refusal,
    };
    if let Some(refusal) = record_open(tracking_id, &headers, addr, &state, &scope).await {
        return refusal;
    }
    pixel_response()
}

// ── Alternative `/o.gif?t=...` pixel route ────────────────────────────────────

#[derive(Deserialize)]
pub struct PixelQuery {
    t: Option<String>,
}

pub async fn handle_pixel_gif(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Query(q): Query<PixelQuery>,
) -> Response {
    let scope = match host_scope_or_refuse(&state, &headers).await {
        Ok(scope) => scope,
        Err(refusal) => return refusal,
    };
    if let Some(tid) = q.t {
        if let Some(refusal) = record_open(tid, &headers, addr, &state, &scope).await {
            return refusal;
        }
    }
    pixel_response()
}

// ── Shared open-recording logic ───────────────────────────────────────────────

/// Record one open. `None` means "serve the pixel"; `Some(response)` is the
/// honest refusal for a token that does not belong to the custom host's
/// workspace.
async fn record_open(
    tracking_id: String,
    headers: &HeaderMap,
    addr: SocketAddr,
    state: &AppState,
    scope: &HostScope,
) -> Option<Response> {
    // E-148:Validate length before any decryption attempt.
    if tracking_id.len() < 10 || tracking_id.len() > 4096 {
        debug!(len = tracking_id.len(), "Pixel: invalid trackingId length");
        return None;
    }

    let user_agent = headers
        .get("user-agent")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);

    let ip = extract_client_ip(headers, addr.ip(), state);

    // E-190:Bot check — skip recording for known scanner/proxy UAs.
    let is_bot = state.bot_detector.is_bot(user_agent.as_deref(), Some(&ip));
    if is_bot {
        info!("E-190: Bot detected on open pixel, skipping recording");
        return None;
    }

    let data = match state.codec.decode(&tracking_id) {
        Some(d) => d,
        None => {
            // SM2-F4: the id is percent-decoded UTF-8; a fixed-offset slice
            // used to panic when byte 20 split a multi-byte character.
            warn!(
                id_prefix = crate::token_shape::token_log_prefix(&tracking_id, 20),
                "Pixel: invalid tracking token"
            );
            return None;
        }
    };

    // Capability wave 2: a valid token on a custom tracking host must belong
    // to that host's workspace.
    if let Err(refusal) = ensure_token_matches_host(scope, &data.tenant_id) {
        return Some(refusal);
    }

    let processor = state.processor.clone();
    tokio::spawn(async move {
        // Bound concurrent recorders: a burst of pixels must not spawn an
        // unbounded fleet of tasks each holding pool resources. Excess opens
        // are dropped (counted) — recording is best-effort.
        let permit = match OPEN_RECORDER_SEMAPHORE.try_acquire() {
            Ok(permit) => permit,
            Err(_) => {
                metrics::counter!("apexmail_tracking_open_recorder_dropped_total").increment(1);
                warn!("Open-recorder concurrency limit reached; dropping open event");
                return;
            }
        };
        let _permit = permit;
        if let Err(e) = processor
            .record_open(OpenData {
                tenant_id: data.tenant_id,
                message_id: data.message_id,
                recipient: data.recipient,
                user_agent,
                ip_address: Some(ip),
            })
            .await
        {
            error!(error = %e, "Failed to record open event");
        }
    });
    None
}

#[cfg(test)]
mod adversarial_tests;
