//! Unsubscribe and preferences-center handlers.
//!
//! Unsubscribe endpoints://! POST `{unsub_path}/:token` — RFC 8058 one-click (List-Unsubscribe-Post)
//! GET `{unsub_path}/:token` — Manual:renders the confirmation form (F39:side-effect free)
//! POST `{unsub_path}/:token/confirm` — Manual confirmation form submit (F39:the
//!        only browser-driven path that changes consent; plain HTML form, no JS)
//!
//! Preferences endpoints://! GET `{prefs_path}/:token` — Show preferences form
//! POST `{prefs_path}/:token` — Save preferences
//!
//! F13:unsubscribe attribution comes from the token when it is a v2
//! (message-attributed) token; legacy tokens resolve the latest message
//! addressed to the recipient via the canonical to/cc/bcc JSON arrays, and
//! anything still unresolved is recorded as `"unknown"` — never invented.
//!
//! F37:every token is checked for the base64url ASCII alphabet BEFORE any
//! processing or logging, so hostile multi-byte input can neither panic the
//! handlers nor leak raw token material into logs.
//!
//! F38:the requested consent state is always idempotently persisted; the
//! 24 h dedup key only suppresses duplicate EVENTS, and a dedup key left
//! stale by a resubscribe is reconciled against the durable suppression row.

use std::net::SocketAddr;

use axum::{
    extract::{ConnectInfo, Form, Path, Query, State},
    http::HeaderMap,
    response::{Html, IntoResponse, Redirect, Response},
};
use serde::Deserialize;
use tracing::{error, info, warn};
use uuid::Uuid;

use crate::processor::UnsubscribeData;
use crate::routes::extract_client_ip;
use crate::state::AppState;
use crate::templates::{
    render_confirmation_page, render_error_page, render_preferences_page, render_success_page,
    Category,
};

// ── Token shape validation (F37) ──────────────────────────────────────────────

/// Minimum/maximum accepted token length (bytes). Matches the codec bounds.
const TOKEN_MIN_LEN: usize = 10;
const TOKEN_MAX_LEN: usize = 4096;

/// F37:a unsubscribe/preferences token is ALWAYS `base64url(IV||tag||ct)`
/// produced by [`crate::codec::TrackingCodec`] — a strict ASCII alphabet of
/// `[A-Za-z0-9_-]` with no padding. Anything else (multi-byte Unicode,
/// `+`/`/` standard-base64, `=`, control bytes) can never verify, so it is
/// rejected HERE, before any slicing or logging. This is what makes the
/// handlers panic-free on hostile input: after this check every later
/// `&token[..n]` slice is on an ASCII string where byte indices are char
/// boundaries.
fn is_valid_token_shape(token: &str) -> bool {
    (TOKEN_MIN_LEN..=TOKEN_MAX_LEN).contains(&token.len())
        && token
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// F37:log a rejected token WITHOUT any raw token material — length and
/// charset classification only. (Slicing at a fixed byte offset is exactly
/// how multi-byte input used to panic; even on ASCII, fragments of a
/// bearer-style token do not belong in logs.)
fn log_invalid_token_shape(handler: &str, token: &str) {
    warn!(
        handler,
        len = token.len(),
        is_ascii = token.is_ascii(),
        "Rejected token with invalid shape (not strict base64url ASCII)"
    );
}

// ── POST /u/:token (RFC 8058 one-click) ───────────────────────────────────────

pub async fn handle_unsub_post(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(token): Path<String>,
    body: String,
) -> Response {
    // F37:structure first — a malformed (e.g. multi-byte) token is rejected
    // before it can reach any byte-slicing or verification code.
    if !is_valid_token_shape(&token) {
        log_invalid_token_shape("unsub_post", &token);
        return axum::http::Response::builder()
            .status(400)
            .header("content-type", "application/json")
            .body(axum::body::Body::from(r#"{"error":"Invalid token"}"#))
            .unwrap_or_default();
    }

    // F-210:trim trailing CRLF / whitespace
    let body = body.trim().to_owned();

    let ua = headers
        .get("user-agent")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let ip = extract_client_ip(&headers, addr.ip(), &state);

    info!("One-click unsubscribe request");

    if body != "List-Unsubscribe=One-Click" {
        warn!(body = %body, "Invalid unsubscribe body");
        return axum::http::Response::builder()
            .status(400)
            .header("content-type", "application/json")
            .body(axum::body::Body::from(
                r#"{"error":"Invalid request body"}"#,
            ))
            .unwrap_or_default();
    }

    let data = match state.codec.verify_unsubscribe_token(&token, None) {
        Some(d) => d,
        None => {
            warn!("Unsubscribe POST: invalid or expired token");
            return axum::http::Response::builder()
                .status(400)
                .header("content-type", "application/json")
                .body(axum::body::Body::from(
                    r#"{"error":"Invalid or expired token"}"#,
                ))
                .unwrap_or_default();
        }
    };

    // F13:attribute to the token's message (v2 tokens), else resolve via
    // the canonical recipient arrays, else "unknown" — never invent.
    let message_id = resolve_message_id(&state, &data).await;

    // Dedup per (tenant, recipient) within 24 h:mail clients and MUA
    // auto-retries can fire the one-click POST repeatedly; only the first is
    // recorded (suppression + event + webhook).
    //
    // F1:the key is only CHECKED here and SET after a successful record.
    // Setting it before the recording meant a record_unsubscribe failure
    // (5xx) was followed by the MUA's RFC 8058 auto-retry hitting the dedup
    // key and receiving 200-without-recording — a silently lost
    // unsubscribe. The record-then-mark window allows a concurrent
    // duplicate through; that is acceptable because the compliance-critical
    // suppression writes are idempotent upserts (ON CONFLICT (tenant,email)
    // / (tenant,email,category) DO UPDATE — see
    // `EventProcessor::add_to_suppression_list`).
    //
    // F38:a key that survived a resubscribe is reconciled against the
    // durable suppression row — the short-circuit answers success ONLY when
    // the requested (suppressed) consent state is actually persisted.
    if is_unsub_duplicate(&state, &data.tenant_id, &data.recipient).await {
        info!("One-click unsubscribe duplicate within 24h window — skipping");
        return axum::http::Response::builder()
            .status(200)
            .header("content-type", "application/json")
            .body(axum::body::Body::from(r#"{"success":true}"#))
            .unwrap_or_default();
    }

    if let Err(e) = state
        .processor
        .record_unsubscribe(UnsubscribeData {
            tenant_id: data.tenant_id.clone(),
            message_id,
            recipient: data.recipient.clone(),
            reason: Some("one-click".into()),
            category: None,
            user_agent: ua,
            ip_address: Some(ip),
        })
        .await
    {
        error!(error = %e, "Failed to record unsubscribe");
        return axum::http::Response::builder()
            .status(500)
            .header("content-type", "application/json")
            .body(axum::body::Body::from(r#"{"error":"Internal error"}"#))
            .unwrap_or_default();
    }

    // Recorded successfully — NOW claim the dedup slot so retries within the
    // 24 h window short-circuit above. Best-effort:a Redis failure here only
    // means a duplicate may be re-recorded (idempotent upserts), never a
    // lost one.
    mark_unsub_dedup(&state, &data.tenant_id, &data.recipient).await;

    // Fire-and-forget webhook queue (F-215)
    queue_unsub_webhook_async(&state, &data.tenant_id, &data.recipient, "one-click");

    axum::http::Response::builder()
        .status(200)
        .header("content-type", "application/json")
        .body(axum::body::Body::from(r#"{"success":true}"#))
        .unwrap_or_default()
}

// ── GET /u/:token (manual:confirmation form only, side-effect free) ──────────

#[derive(Deserialize)]
pub struct UnsubQuery {
    /// Legacy deep-link flag (?confirm=1). F39:GET is side-effect free —
    /// the flag no longer mutates consent; the page rendered is the same
    /// POST confirmation form either way.
    #[expect(
        dead_code,
        reason = "accepted for backward compatibility with pre-F39 links"
    )]
    confirm: Option<String>,
}

pub async fn handle_unsub_get(
    State(state): State<AppState>,
    Path(token): Path<String>,
    Query(_q): Query<UnsubQuery>,
) -> Response {
    // F37:shape check before anything else.
    if !is_valid_token_shape(&token) {
        log_invalid_token_shape("unsub_get", &token);
        return Html(render_error_page("Invalid or expired unsubscribe link")).into_response();
    }

    let data = match state.codec.verify_unsubscribe_token(&token, None) {
        Some(d) => d,
        None => {
            return Html(render_error_page("Invalid or expired unsubscribe link")).into_response()
        }
    };

    let unsub_path = &state.config.tracking.unsubscribe_path;

    // F39:this handler is now purely a read:it renders the confirmation
    // form whose submit button POSTs to `{unsub_path}/{token}/confirm`.
    // Consent changes only happen on POST (see `handle_unsub_confirm_post`)
    // — a prefetching MUA or a link scanner can no longer unsubscribe
    // anyone by fetching a URL.
    Html(render_confirmation_page(
        &token,
        &data.recipient,
        unsub_path,
    ))
    .into_response()
}

// ── POST /u/:token/confirm (manual confirmation form, F39) ───────────────────

#[derive(Deserialize, Default)]
pub struct UnsubConfirmForm {
    /// Hidden field from the confirmation page. Any POST to this endpoint
    /// only proceeds when the form actually confirmed the action.
    #[serde(default)]
    confirm: Option<String>,
}

/// F39:the browser-facing confirmation submit. Distinct from the RFC 8058
/// one-click POST (which requires the exact `List-Unsubscribe=One-Click`
/// body) so both contracts stay separate; this one is a plain no-JS HTML
/// form POST (`confirm=true`).
pub async fn handle_unsub_confirm_post(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(token): Path<String>,
    Form(form): Form<UnsubConfirmForm>,
) -> Response {
    if !is_valid_token_shape(&token) {
        log_invalid_token_shape("unsub_confirm_post", &token);
        return Html(render_error_page("Invalid or expired unsubscribe link")).into_response();
    }

    if form.confirm.as_deref() != Some("true") && form.confirm.as_deref() != Some("1") {
        return Html(render_error_page("Invalid confirmation request.")).into_response();
    }

    let data = match state.codec.verify_unsubscribe_token(&token, None) {
        Some(d) => d,
        None => {
            return Html(render_error_page("Invalid or expired unsubscribe link")).into_response()
        }
    };

    let ua = headers
        .get("user-agent")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let ip = extract_client_ip(&headers, addr.ip(), &state);

    // Dedup per (tenant, recipient) within 24 h (double-clicks, retries).
    // F1:check-only here; the key is SET after a successful record (see the
    // one-click POST handler) so a failed record is never swallowed by the
    // dedup window on the user's retry.
    // F38:the durable-state reconciliation makes a stale key (left by an
    // earlier unsubscribe + resubscribe) answer FALSE, so the final choice
    // is always persisted.
    if is_unsub_duplicate(&state, &data.tenant_id, &data.recipient).await {
        info!("Unsubscribe confirm duplicate within 24h window — skipping");
        return Html(render_success_page(&data.recipient)).into_response();
    }

    let message_id = resolve_message_id(&state, &data).await;

    if let Err(e) = state
        .processor
        .record_unsubscribe(UnsubscribeData {
            tenant_id: data.tenant_id.clone(),
            message_id,
            recipient: data.recipient.clone(),
            reason: Some("link-click".into()),
            category: None,
            user_agent: ua,
            ip_address: Some(ip),
        })
        .await
    {
        error!(error = %e, "Failed to record unsubscribe");
        return Html(render_error_page("Something went wrong. Please try again.")).into_response();
    }

    // Recorded successfully — claim the dedup slot (best-effort, F1).
    mark_unsub_dedup(&state, &data.tenant_id, &data.recipient).await;

    queue_unsub_webhook_async(&state, &data.tenant_id, &data.recipient, "link-click");

    Html(render_success_page(&data.recipient)).into_response()
}

// ── GET /p/:token ─────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct PrefsQuery {
    #[expect(
        dead_code,
        reason = "query flag is accepted for confirmation-page UX state"
    )]
    saved: Option<String>,
}

pub async fn handle_prefs_get(
    State(state): State<AppState>,
    Path(token): Path<String>,
    Query(_q): Query<PrefsQuery>,
) -> Response {
    // F37:shape check before any processing.
    if !is_valid_token_shape(&token) {
        log_invalid_token_shape("prefs_get", &token);
        return Html(render_error_page("Invalid or expired preferences link")).into_response();
    }

    let data = match state.codec.verify_preferences_token(&token) {
        Some(d) => d,
        None => {
            return Html(render_error_page("Invalid or expired preferences link")).into_response()
        }
    };

    let email_lc = data.recipient.to_lowercase();
    let prefs_path = &state.config.tracking.preferences_path;

    let (prefs_res, cats_res, sup_res) = match tokio::try_join!(
        sqlx::query_as::<_, (String, bool)>(
            "SELECT category, subscribed FROM subscription_preferences WHERE tenant_id=$1 AND email=$2"
        )
        .bind(&data.tenant_id)
        .bind(&email_lc)
        .fetch_all(&state.db),
        sqlx::query_as::<_, (String, String)>(
            "SELECT name, description FROM email_categories WHERE tenant_id=$1 AND active=true ORDER BY display_order"
        )
        .bind(&data.tenant_id)
        .fetch_all(&state.db),
        sqlx::query_as::<_, (String,)>(
            "SELECT email FROM suppressions WHERE tenant_id=$1 AND email=$2",
        )
        .bind(&data.tenant_id)
        .bind(&email_lc)
        .fetch_optional(&state.db),
    ) {
        Ok(result) => result,
        Err(e) => {
            tracing::error!(error = %e, tenant_id = %data.tenant_id, email = %mail_common::pii::redact_email(&email_lc), "Failed to load preferences data");
            return Html(render_error_page("Unable to load preferences. Please try again.")).into_response();
        }
    };

    let pref_map: std::collections::HashMap<String, bool> = prefs_res.into_iter().collect();

    // Collect into owned strings first, then build Category slices from those.
    let cat_rows: Vec<(String, String)> = cats_res;
    let cats: Vec<OwnedCategory> = cat_rows
        .into_iter()
        .map(|(name, desc)| {
            let subscribed = *pref_map.get(&name).unwrap_or(&true);
            OwnedCategory {
                name,
                description: desc,
                subscribed,
            }
        })
        .collect();

    let cat_refs: Vec<Category<'_>> = cats
        .iter()
        .map(|c| Category {
            name: &c.name,
            description: &c.description,
            subscribed: c.subscribed,
        })
        .collect();

    let globally_unsubscribed = sup_res.is_some();

    Html(render_preferences_page(
        &token,
        &data.recipient,
        prefs_path,
        &cat_refs,
        globally_unsubscribed,
    ))
    .into_response()
}

/// Owned version of `Category` used to hold the strings returned from Postgres.
struct OwnedCategory {
    name: String,
    description: String,
    subscribed: bool,
}

// ── POST /p/:token ────────────────────────────────────────────────────────────

#[derive(Deserialize, Default)]
pub struct PrefsForm {
    unsubscribe_all: Option<String>,
    resubscribe_all: Option<String>,
    #[serde(flatten)]
    categories: std::collections::HashMap<String, String>,
}

pub async fn handle_prefs_post(
    State(state): State<AppState>,
    Path(token): Path<String>,
    Form(form): Form<PrefsForm>,
) -> Response {
    // F37:shape check before any processing.
    if !is_valid_token_shape(&token) {
        log_invalid_token_shape("prefs_post", &token);
        return axum::http::Response::builder()
            .status(400)
            .header("content-type", "application/json")
            .body(axum::body::Body::from(r#"{"error":"Invalid token"}"#))
            .unwrap_or_default();
    }

    let data = match state.codec.verify_preferences_token(&token) {
        Some(d) => d,
        None => {
            return axum::http::Response::builder()
                .status(400)
                .header("content-type", "application/json")
                .body(axum::body::Body::from(
                    r#"{"error":"Invalid or expired token"}"#,
                ))
                .unwrap_or_default();
        }
    };

    let email = data.recipient.to_lowercase();
    let prefs_path = &state.config.tracking.preferences_path;

    // Global unsubscribe
    if form.unsubscribe_all.as_deref() == Some("true") {
        // F54:suppressions.id is VARCHAR(26) — canonical 26-char entity id,
        // same generator the api-server uses (`generate_id("sup", 22)`).
        let sup_id = new_suppression_id();
        if let Err(e) = sqlx::query(r#"
            INSERT INTO suppressions (id, tenant_id, email, reason, subtype, created_at)
            VALUES ($1, $2, $3, 'unsubscribe', 'preferences', NOW())
            ON CONFLICT (tenant_id, email) DO UPDATE SET reason='unsubscribe', subtype='preferences', updated_at=NOW()
        "#)
        .bind(&sup_id).bind(&data.tenant_id).bind(&email)
        .execute(&state.db).await {
            tracing::error!(error = %e, tenant_id = %data.tenant_id, email = %mail_common::pii::redact_email(&email), "CRITICAL: Failed to insert suppression record for unsubscribe");
            return axum::http::Response::builder()
                .status(500)
                .header("content-type", "application/json")
                .body(axum::body::Body::from(r#"{"error":"Failed to save unsubscribe preference. Please try again."}"#))
                .unwrap_or_default();
        }

        // F38:the suppression row IS the durable consent state; the dedup
        // key may now short-circuit duplicate unsubscribe requests because
        // the state it advertises ("suppressed") is actually persisted (the
        // duplicate check reconciles against this row).
        mark_unsub_dedup(&state, &data.tenant_id, &email).await;

        // F55:preferences-center consent changes fan out on the same bus as
        // one-click suppressions, so sending caches invalidate either way.
        state
            .processor
            .publish_suppression_added(&data.tenant_id, &email, None);

        queue_unsub_webhook_async(&state, &data.tenant_id, &email, "preferences-center");
        let redirect_url = format!("{prefs_path}/{token}?saved=1");
        return Redirect::to(&redirect_url).into_response();
    }

    // Resubscribe
    if form.resubscribe_all.as_deref() == Some("true") {
        if let Err(e) = sqlx::query(
            "DELETE FROM suppressions WHERE tenant_id=$1 AND email=$2 AND reason='unsubscribe'",
        )
        .bind(&data.tenant_id)
        .bind(&email)
        .execute(&state.db)
        .await
        {
            tracing::error!(error = %e, tenant_id = %data.tenant_id, email = %mail_common::pii::redact_email(&email), "Failed to delete suppression record for resubscribe");
            return axum::http::Response::builder()
                .status(500)
                .header("content-type", "application/json")
                .body(axum::body::Body::from(
                    r#"{"error":"Failed to save resubscribe preference. Please try again."}"#,
                ))
                .unwrap_or_default();
        }

        // F38:the durable consent state changed back to "subscribed" — the
        // 24 h unsubscribe dedup key MUST NOT survive this transition, or
        // the next unsubscribe would short-circuit as a "duplicate" while
        // no suppression row exists (unsub → resubscribe → unsub lost the
        // final choice). The duplicate check also reconciles against the
        // durable row, so even a failed DEL cannot lose consent.
        clear_unsub_dedup(&state, &data.tenant_id, &email).await;

        // F38/F55:publish the removal so sending caches drop their stale
        // "suppressed" entries instead of waiting out their TTL.
        state
            .processor
            .publish_suppression_removed(&data.tenant_id, &email);

        let redirect_url = format!("{prefs_path}/{token}?saved=1");
        return Redirect::to(&redirect_url).into_response();
    }

    // Update category preferences (B-033:single multi-row INSERT)
    let cats: Vec<(String, bool)> = form
        .categories
        .iter()
        .filter(|(k, _)| k.starts_with("category_"))
        .map(|(k, v)| (k.trim_start_matches("category_").to_owned(), v == "true"))
        .collect();

    if !cats.is_empty() {
        // F9:category names must be the tenant's own active email_categories,
        // and the accepted quantity is capped — otherwise a token holder
        // could write arbitrary junk rows into subscription_preferences in
        // unbounded volume.
        let valid_rows = sqlx::query_as::<_, (String,)>(
            "SELECT name FROM email_categories WHERE tenant_id=$1 AND active=true",
        )
        .bind(&data.tenant_id)
        .fetch_all(&state.db)
        .await;
        let valid: std::collections::HashSet<String> = match valid_rows {
            Ok(rows) => rows.into_iter().map(|(name,)| name).collect(),
            Err(e) => {
                tracing::error!(error = %e, tenant_id = %data.tenant_id, "Failed to load email categories for validation");
                return axum::http::Response::builder()
                    .status(500)
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(
                        r#"{"error":"Failed to save preferences. Please try again."}"#,
                    ))
                    .unwrap_or_default();
            }
        };

        if let Err(msg) = validate_category_preferences(&cats, &valid, MAX_CATEGORY_PREFERENCES) {
            warn!(tenant_id = %data.tenant_id, reason = %msg, "Rejected category preference update");
            return axum::http::Response::builder()
                .status(400)
                .header("content-type", "application/json")
                .body(axum::body::Body::from(format!(
                    r#"{{"error":{}}}"#,
                    serde_json::to_string(&msg)
                        .unwrap_or_else(|_| "\"invalid category preferences\"".into())
                )))
                .unwrap_or_default();
        }

        // #203:Use batch INSERT via sqlx::QueryBuilder instead of N individual INSERTs
        let mut tx = match state.db.begin().await {
            Ok(tx) => tx,
            Err(e) => {
                error!(error = %e, "Failed to begin transaction for preferences");
                return axum::http::Response::builder()
                    .status(500)
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(
                        r#"{"error":"Failed to save preferences. Please try again."}"#,
                    ))
                    .unwrap_or_default();
            }
        };

        // Batch UPSERT all category preferences in a single statement
        // F54:subscription_preferences.id is VARCHAR(26) — canonical 26-char
        // entity ids (generate_id("prf", 22)), NOT the 36-char UUID form.
        let mut builder = sqlx::QueryBuilder::<sqlx::Postgres>::new(
            "INSERT INTO subscription_preferences (id, tenant_id, email, category, subscribed, updated_at) "
        );
        builder.push_values(&cats, |mut b, (cat, subscribed)| {
            b.push_bind(new_preference_id())
                .push_bind(&data.tenant_id)
                .push_bind(&email)
                .push_bind(cat)
                .push_bind(*subscribed)
                .push_unseparated(", NOW()");
        });
        builder.push(
            " ON CONFLICT (tenant_id, email, category) DO UPDATE SET subscribed=EXCLUDED.subscribed, updated_at=NOW()"
        );

        if let Err(e) = builder.build().execute(&mut *tx).await {
            error!(error = %e, "Failed to batch update subscription preferences");
            // tx will be rolled back on drop
            return axum::http::Response::builder()
                .status(500)
                .header("content-type", "application/json")
                .body(axum::body::Body::from(
                    r#"{"error":"Failed to save preferences. Please try again."}"#,
                ))
                .unwrap_or_default();
        }

        if let Err(e) = tx.commit().await {
            tracing::error!(error = %e, tenant_id = %data.tenant_id, email = %mail_common::pii::redact_email(&email), "CRITICAL: Failed to commit subscription preference transaction \u{2014} changes rolled back");
            return axum::http::Response::builder()
                .status(500)
                .header("content-type", "application/json")
                .body(axum::body::Body::from(
                    r#"{"error":"Failed to save preferences. Please try again."}"#,
                ))
                .unwrap_or_default();
        }

        // F55:the committed preference change alters send eligibility — fan
        // out per category so subscribers can invalidate precisely.
        for (cat, subscribed) in &cats {
            state
                .processor
                .publish_preference_changed(&data.tenant_id, &email, cat, *subscribed);
        }
    }

    let redirect_url = format!("{prefs_path}/{token}?saved=1");
    Redirect::to(&redirect_url).into_response()
}

// ── Shared helpers ────────────────────────────────────────────────────────────

/// Dedup key for (tenant, recipient), lower-cased so mixed-case recipients
/// from token payloads collapse to one key.
fn unsub_dedup_key(tenant_id: &str, recipient: &str) -> String {
    format!("unsub:dedup:{}:{}", tenant_id, recipient.to_lowercase())
}

/// Check (GET) whether an unsubscribe for (tenant, recipient) was already
/// recorded within the 24 h window. Fails OPEN on Redis errors — losing
/// dedup is preferable to losing an unsubscribe (compliance-critical); the
/// duplicate record is absorbed by the idempotent suppression upsert.
///
/// F38:a present key alone is NOT trusted as "already unsubscribed": the
/// durable consent state may have changed since (preferences-center
/// resubscribe deletes the suppression row). The key only short-circuits
/// when the requested state — recipient suppressed — is actually persisted
/// in `suppressions`. A key left stale by a resubscribe is cleared and the
/// request re-records, so unsub → resubscribe → unsub always ends
/// suppressed.
async fn is_unsub_duplicate(state: &AppState, tenant_id: &str, recipient: &str) -> bool {
    let key = unsub_dedup_key(tenant_id, recipient);
    let marked = match state.redis.get().await {
        Ok(mut conn) => match redis::cmd("GET")
            .arg(&key)
            .query_async::<Option<String>>(&mut *conn)
            .await
        {
            Ok(v) => v.is_some(),
            Err(e) => {
                warn!(error = %e, "Unsubscribe dedup check failed — recording anyway");
                return false;
            }
        },
        Err(e) => {
            warn!(error = %e, "Unsubscribe dedup Redis pool error — recording anyway");
            return false;
        }
    };
    if !marked {
        return false;
    }

    // Key present — reconcile against the durable consent state (F38).
    // NOTE:select the email (VARCHAR → String), not a bare `1` — PG types
    // the literal as INT4 and decoding it as i64 is a ColumnDecode error.
    let email_lc = recipient.to_lowercase();
    match sqlx::query_as::<_, (String,)>(
        "SELECT email FROM suppressions WHERE tenant_id=$1 AND email=$2 LIMIT 1",
    )
    .bind(tenant_id)
    .bind(&email_lc)
    .fetch_optional(&state.db)
    .await
    {
        Ok(Some(_)) => true,
        Ok(None) => {
            // Stale key (suppression was removed by a resubscribe): clear it
            // so the state and the dedup marker converge, and record again.
            warn!("Unsubscribe dedup key stale (recipient resubscribed since) — clearing and recording again");
            clear_unsub_dedup(state, tenant_id, recipient).await;
            false
        }
        // Fail OPEN (record anyway): the suppression write is an idempotent
        // upsert, so the worst case is a duplicate event — never a lost
        // consent state.
        Err(e) => {
            warn!(error = %e, "Suppression state check failed — recording anyway");
            false
        }
    }
}

/// Claim the 24 h dedup slot (SET NX EX) AFTER the unsubscribe has been
/// successfully recorded (F1). The value names the consent state the key
/// advertises ("suppressed") — see the reconciliation in
/// [`is_unsub_duplicate`]. Best-effort:on Redis failure the worst case
/// is a duplicate record (idempotent upserts), never a lost unsubscribe.
async fn mark_unsub_dedup(state: &AppState, tenant_id: &str, recipient: &str) {
    let key = unsub_dedup_key(tenant_id, recipient);
    match state.redis.get().await {
        Ok(mut conn) => {
            if let Err(e) = redis::cmd("SET")
                .arg(&key)
                .arg("suppressed")
                .arg("EX")
                .arg(86_400u64)
                .arg("NX")
                .query_async::<Option<String>>(&mut *conn)
                .await
            {
                warn!(error = %e, "Unsubscribe dedup mark failed — duplicates may re-record");
            }
        }
        Err(e) => {
            warn!(error = %e, "Unsubscribe dedup Redis pool error — duplicates may re-record");
        }
    }
}

/// F38:drop the dedup slot after a successful RESUBSCRIBE so the next
/// unsubscribe is not swallowed as a "duplicate" while the recipient is no
/// longer suppressed. Best-effort — [`is_unsub_duplicate`] reconciles
/// against the durable suppression row, so a failed DEL cannot lose consent.
async fn clear_unsub_dedup(state: &AppState, tenant_id: &str, recipient: &str) {
    let key = unsub_dedup_key(tenant_id, recipient);
    match state.redis.get().await {
        Ok(mut conn) => {
            if let Err(e) = redis::cmd("DEL")
                .arg(&key)
                .query_async::<()>(&mut *conn)
                .await
            {
                warn!(error = %e, "Unsubscribe dedup clear failed — duplicate check will reconcile against Postgres");
            }
        }
        Err(e) => {
            warn!(error = %e, "Unsubscribe dedup clear Redis pool error — duplicate check will reconcile against Postgres");
        }
    }
}

// ── Message attribution (F13) ─────────────────────────────────────────────────

/// Literal attribution recorded when the originating message cannot be
/// determined — never an invented id (which would silently corrupt
/// per-message unsubscribe counts and webhook payloads).
pub const UNKNOWN_MESSAGE_ID: &str = "unknown";

/// Longest value accepted for `events.message_id` (VARCHAR(64)).
const MAX_EVENT_MESSAGE_ID_LEN: usize = 64;

/// F13:resolve the attribution message id for an unsubscribe request.
///
/// 1. v2 tokens carry the originating message id inside the authenticated
///    envelope — used directly (after a width sanity check).
/// 2. Legacy tokens: latest tenant-scoped message whose CANONICAL recipient
///    arrays (`to_emails` / `cc_emails` / `bcc_emails` JSON) contain the
///    recipient, with `messages.id::text` decoded as text (the column is a
///    UUID; decoding it as a String is a type error in sqlx and used to
///    make the whole query fail silently).
/// 3. Unresolved → [`UNKNOWN_MESSAGE_ID`].
async fn resolve_message_id(state: &AppState, data: &crate::codec::UnsubscribeData) -> String {
    if let Some(mid) = data.message_id.as_deref() {
        if !mid.is_empty() && mid.len() <= MAX_EVENT_MESSAGE_ID_LEN {
            return mid.to_owned();
        }
        warn!("v2 unsubscribe token carried an unusable message id — falling back to recipient resolution");
    }

    let email_lc = data.recipient.to_lowercase();
    match sqlx::query_as::<_, (String,)>(
        r#"
        SELECT id::text FROM messages
        WHERE tenant_id = $1
          AND (
                lower($2) = ANY (SELECT lower(e) FROM jsonb_array_elements_text(COALESCE(to_emails,  '[]'::jsonb)) AS e)
             OR lower($2) = ANY (SELECT lower(e) FROM jsonb_array_elements_text(COALESCE(cc_emails,  '[]'::jsonb)) AS e)
             OR lower($2) = ANY (SELECT lower(e) FROM jsonb_array_elements_text(COALESCE(bcc_emails, '[]'::jsonb)) AS e)
          )
        ORDER BY created_at DESC
        LIMIT 1
        "#,
    )
    .bind(&data.tenant_id)
    .bind(&email_lc)
    .fetch_optional(&state.db)
    .await
    {
        Ok(Some((id,))) => id,
        Ok(None) => UNKNOWN_MESSAGE_ID.to_owned(),
        Err(e) => {
            warn!(
                error = %e,
                tenant_id = %data.tenant_id,
                "Could not resolve originating message for unsubscribe attribution"
            );
            UNKNOWN_MESSAGE_ID.to_owned()
        }
    }
}

/// Queue unsubscribe webhooks for all enabled webhook subscriptions of the tenant.
/// Fire-and-forget:errors are logged but not propagated (F-215).
fn queue_unsub_webhook_async(state: &AppState, tenant_id: &str, email: &str, method: &str) {
    let state = state.clone();
    let tenant_id = tenant_id.to_owned();
    let email = email.to_owned();
    let method = method.to_owned();

    tokio::spawn(async move {
        if let Err(e) = queue_unsub_webhook(&state, &tenant_id, &email, &method).await {
            error!(error = %e, "Failed to queue unsubscribe webhook");
        }
    });
}

async fn queue_unsub_webhook(
    state: &AppState,
    tenant_id: &str,
    email: &str,
    method: &str,
) -> anyhow::Result<()> {
    // Cache webhook IDs per tenant (1-minute TTL).
    let webhook_ids = if let Some(ids) = state.webhook_cache.get(tenant_id).await {
        ids
    } else {
        let rows = sqlx::query_as::<_, (String,)>(
            r#"
            SELECT id FROM webhooks
            WHERE tenant_id=$1 AND enabled=true
              AND (events @> '"recipient.unsubscribed"'::jsonb OR events @> '"*"'::jsonb)
        "#,
        )
        .bind(tenant_id)
        .fetch_all(&state.db)
        .await?;
        let ids: Vec<String> = rows.into_iter().map(|(id,)| id).collect();
        state
            .webhook_cache
            .insert(tenant_id.to_owned(), ids.clone())
            .await;
        ids
    };

    if webhook_ids.is_empty() {
        return Ok(());
    }

    // Batch INSERT all webhook jobs (F-216)
    let mut builder = sqlx::QueryBuilder::<sqlx::Postgres>::new(
        "INSERT INTO webhook_queue (id, webhook_id, tenant_id, event_type, payload, status, attempt, created_at) "
    );
    let payload_val = serde_json::json!({
        "id": new_id("evt"),
        "type": "recipient.unsubscribed",
        "tenantId": tenant_id,
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "data": { "recipient": email, "method": method, "timestamp": chrono::Utc::now().to_rfc3339() },
    });
    let payload_str = payload_val.to_string();

    builder.push_values(&webhook_ids, |mut b, wid| {
        b.push_bind(new_id("whj"))
            .push_bind(wid)
            .push_bind(tenant_id)
            .push_bind("recipient.unsubscribed")
            .push_bind(&payload_str)
            .push_bind("pending")
            .push_bind(1i32)
            .push_unseparated(", NOW()"); // #179:comma must precede NOW
    });
    builder.build().execute(&state.db).await?;
    Ok(())
}

/// F54:26-char entity ids for the VARCHAR(26) PK columns written by these
/// routes — the platform's canonical generator (`apexmail_lib::id::generate_id`),
/// identical to the api-server's `next_suppression_id()`. The legacy
/// `new_id("sup")`/`new_id("prf")` produced 36-char ids that overflowed the
/// columns (SQLSTATE 22001) and failed every insert.
fn new_suppression_id() -> String {
    apexmail_lib::id::generate_id("sup", 22)
}

fn new_preference_id() -> String {
    apexmail_lib::id::generate_id("prf", 22)
}

/// 36-char prefixed UUID id — only for VARCHAR(64)+ columns
/// (`webhook_queue.id` is VARCHAR(64), `events.id` VARCHAR(64)).
fn new_id(prefix: &str) -> String {
    format!("{prefix}_{}", Uuid::new_v4().simple())
}

/// F9:maximum number of category preferences accepted per POST. The tenant's
/// own category list is naturally bounded; anything beyond this is rejected.
const MAX_CATEGORY_PREFERENCES: usize = 50;

/// F9:validate submitted category preferences against the tenant's active
/// categories and the accepted-count cap. Returns a human-readable error
/// naming what was rejected, or `Ok(())`.
fn validate_category_preferences(
    cats: &[(String, bool)],
    valid: &std::collections::HashSet<String>,
    cap: usize,
) -> Result<(), String> {
    if cats.len() > cap {
        return Err(format!(
            "too many category preferences submitted ({ }); maximum is {cap}",
            cats.len()
        ));
    }
    let unknown: Vec<&str> = cats
        .iter()
        .map(|(name, _)| name.as_str())
        .filter(|name| !valid.contains(*name))
        .collect();
    if !unknown.is_empty() {
        return Err(format!(
            "unknown categories rejected: {} (only this tenant's active categories can be set)",
            unknown.join(", ")
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::TrackingCodec;
    use crate::processor::REDIS_WAL_KEY;
    use crate::routes::{build_router, test_support};

    // ── F1:dedup key ──────────────────────────────────────────────────

    #[test]
    fn unsub_dedup_key_is_deterministic_and_case_insensitive() {
        let a = unsub_dedup_key("tenant_1", "User@Example.com");
        assert_eq!(a, "unsub:dedup:tenant_1:user@example.com");
        // Mixed-case token recipients collapse to the same key.
        assert_eq!(a, unsub_dedup_key("tenant_1", "user@example.com"));
        assert_eq!(a, unsub_dedup_key("tenant_1", "USER@EXAMPLE.COM"));
        // Tenant and recipient both scope the key.
        assert_ne!(a, unsub_dedup_key("tenant_2", "User@Example.com"));
        assert_ne!(a, unsub_dedup_key("tenant_1", "other@example.com"));
    }

    // ── F54:26-char ids for VARCHAR(26) columns ───────────────────────

    /// suppressions.id / subscription_preferences.id are VARCHAR(26). The
    /// legacy `new_id("sup")` minted `"sup_" + 32 hex` = 36 chars →
    /// SQLSTATE 22001 on every insert. The canonical generator must produce
    /// exactly 26 chars every time.
    #[test]
    fn suppression_and_preference_ids_fit_varchar26() {
        for _ in 0..100 {
            let sup = new_suppression_id();
            assert_eq!(sup.len(), 26, "suppression id: {sup}");
            assert!(sup.starts_with("sup_"));

            let prf = new_preference_id();
            assert_eq!(prf.len(), 26, "preference id: {prf}");
            assert!(prf.starts_with("prf_"));

            for id in [&sup, &prf] {
                assert!(
                    id.chars()
                        .all(|c| c.is_ascii_digit() || c.is_ascii_lowercase() || c == '_'),
                    "charset: {id}"
                );
            }
        }
    }

    // ── F37:token shape validation (panic-free on hostile input) ──────

    #[test]
    fn token_shape_validator_accepts_real_base64url_tokens() {
        let codec = TrackingCodec::new(test_support::TEST_SECRET);
        let token = codec
            .generate_unsubscribe_token("tenant_1", "user@example.com")
            .expect("token");
        assert!(is_valid_token_shape(&token));
        let v2 = codec
            .generate_unsubscribe_token_with_message(
                "tenant_1",
                "user@example.com",
                "0123456789abcdef0123456789abcdef",
            )
            .expect("token");
        assert!(is_valid_token_shape(&v2));
    }

    #[test]
    fn token_shape_validator_rejects_multibyte_and_hostile_input() {
        // Multi-byte Unicode: a 4-byte emoji at the exact byte offset (20)
        // that the old logging code sliced at. Slicing `&token[..20]` on
        // this string PANICS — the validator must reject it first.
        let mut hostile = String::new();
        for _ in 0..5 {
            hostile.push('😀'); // 4 bytes each
        }
        assert!(!is_valid_token_shape(&hostile));
        assert!(hostile.len() >= 20, "fixture must straddle byte 20");

        // Other multi-byte scripts.
        assert!(!is_valid_token_shape("日本語のトークンです"));
        assert!(!is_valid_token_shape("токен-подпись-123"));

        // Standard-base64 / padding characters are NOT base64url.
        assert!(!is_valid_token_shape("abc+def+ghi+jkl"));
        assert!(!is_valid_token_shape("abc/def/ghi/jkl"));
        assert!(!is_valid_token_shape("abcdefghij=="));

        // Control bytes / whitespace / percent-encoding.
        assert!(!is_valid_token_shape("abcdefghij\n"));
        assert!(!is_valid_token_shape("abcdefgh ij"));
        assert!(!is_valid_token_shape("abcdefghij%20"));

        // Length bounds.
        assert!(!is_valid_token_shape("short"));
        assert!(!is_valid_token_shape(&"a".repeat(TOKEN_MAX_LEN + 1)));
        assert!(is_valid_token_shape(&"a".repeat(TOKEN_MIN_LEN)));
    }

    mod handler {
        use super::*;
        use std::net::SocketAddr;

        async fn server(state: &AppState) -> axum_test::TestServer {
            axum_test::TestServer::new(
                build_router(state.clone()).into_make_service_with_connect_info::<SocketAddr>(),
            )
            .expect("test server")
        }

        fn legacy_token(tenant: &str, recipient: &str) -> String {
            TrackingCodec::new(test_support::TEST_SECRET)
                .generate_unsubscribe_token(tenant, recipient)
                .expect("token")
        }

        fn v2_token(tenant: &str, recipient: &str, message_id: &str) -> String {
            TrackingCodec::new(test_support::TEST_SECRET)
                .generate_unsubscribe_token_with_message(tenant, recipient, message_id)
                .expect("token")
        }

        // ── F37:hostile tokens never panic and never reach verification ──

        /// The exact panic shape from the audit: a multi-byte token whose
        /// byte-20 boundary splits a character. Both the GET and POST
        /// handlers must reject it (400 / error page) WITHOUT panicking —
        /// and the one-click POST rejects it even before the body check.
        #[tokio::test]
        async fn multibyte_tokens_are_rejected_without_panic() {
            let state = test_support::offline_state(&[]);
            let server = server(&state).await;

            let mut hostile = String::new();
            for _ in 0..5 {
                hostile.push('😀');
            }
            assert!(hostile.len() >= 20);

            // GET → error page (200 HTML), no panic.
            let resp = server.get(&format!("/u/{hostile}")).await;
            assert_eq!(resp.status_code().as_u16(), 200);
            assert!(resp.text().contains("Invalid or expired"));

            // GET ?confirm=1 → same rejection, and (F39) no state change.
            let resp = server
                .get(&format!("/u/{hostile}"))
                .add_query_param("confirm", "1")
                .await;
            assert!(resp.text().contains("Invalid or expired"));

            // POST one-click → 400 JSON, no panic.
            let resp = server
                .post(&format!("/u/{hostile}"))
                .text("List-Unsubscribe=One-Click")
                .await;
            assert_eq!(resp.status_code().as_u16(), 400);

            // POST confirm endpoint → error page, no panic.
            let resp = server
                .post(&format!("/u/{hostile}/confirm"))
                .form(&[("confirm", "true")])
                .await;
            assert!(resp.text().contains("Invalid or expired"));

            // Preferences endpoints equally guarded.
            let resp = server.get(&format!("/p/{hostile}")).await;
            assert!(resp.text().contains("Invalid or expired"));
        }

        // ── F39:GET is side-effect free; confirmation is a POST form ──

        /// GET /u/:token renders a confirmation FORM (POST to
        /// /u/:token/confirm) — not a GET link — and ?confirm=1 no longer
        /// mutates anything (it renders the same form).
        #[tokio::test]
        async fn unsub_get_renders_post_form_and_never_mutates() {
            let state = test_support::offline_state(&[]);
            let server = server(&state).await;
            let token = legacy_token("tenant_f39", "f39@example.com");

            for confirm_flag in [false, true] {
                let mut req = server.get(&format!("/u/{token}"));
                if confirm_flag {
                    // The legacy pre-F39 deep link must render the same
                    // side-effect-free confirmation form.
                    req = req.add_query_param("confirm", "1");
                }
                let resp = req.await;
                let body = resp.text();

                // The confirmation is a plain HTML form POST (no-JS friendly).
                assert!(
                    body.contains(&format!(
                        r#"<form method="POST" action="/u/{token}/confirm">"#
                    )),
                    "confirmation must be a POST form, got: {body}"
                );
                assert!(body.contains(r#"<button type="submit""#), "{body}");

                // The legacy GET mutation link must be gone (an <a> whose
                // href ends in the ?confirm=1 flag).
                assert!(
                    !body.contains("?confirm=1\""),
                    "GET link with ?confirm=1 must not be rendered: {body}"
                );

                // Critically: GET must not render the SUCCESS page (that is
                // the observable stand-in for "no consent change happened"
                // without live services).
                assert!(
                    !body.contains("been unsubscribed"),
                    "GET must not report a completed unsubscribe: {body}"
                );
            }
        }

        /// The RFC 8058 one-click contract stays intact: only the exact
        /// `List-Unsubscribe=One-Click` body is accepted by POST /u/:token;
        /// a browser form body ("confirm=true") is NOT.
        #[tokio::test]
        async fn one_click_post_rejects_form_bodies() {
            let state = test_support::offline_state(&[]);
            let server = server(&state).await;
            let token = legacy_token("tenant_f39", "f39@example.com");

            let resp = server
                .post(&format!("/u/{token}"))
                .text("confirm=true")
                .await;
            assert_eq!(
                resp.status_code().as_u16(),
                400,
                "form body must not satisfy the one-click contract"
            );

            // And the confirm endpoint requires its own hidden field.
            let resp = server
                .post(&format!("/u/{token}/confirm"))
                .form(&[("other", "1")])
                .await;
            assert!(
                resp.text().contains("Invalid confirmation request"),
                "{}",
                resp.text()
            );
        }

        // ── Live tests (TEST_REDIS_URL + TEST_DATABASE_URL; soft-skip) ──

        mod live {
            use super::*;
            use std::time::Duration;

            const RECIPIENT: &str = "f13live@example.com";

            fn unique_tenant(label: &str) -> String {
                test_support::unique_tenant(label)
                    .chars()
                    .take(26)
                    .collect::<String>()
            }

            async fn seed_tenant(db: &sqlx::PgPool, tenant: &str) {
                sqlx::query(
                    "INSERT INTO tenants (id, name) VALUES ($1, $1)
                     ON CONFLICT (id) DO NOTHING",
                )
                .bind(tenant)
                .execute(db)
                .await
                .expect("seed tenant");
            }

            async fn seed_message(
                db: &sqlx::PgPool,
                tenant: &str,
                id: &str,
                to: &[&str],
                cc: &[&str],
                bcc: &[&str],
            ) {
                sqlx::query(
                    r#"INSERT INTO messages (id, tenant_id, from_email, to_emails, cc_emails, bcc_emails, subject, status)
                       VALUES ($1::uuid, $2, 'sender@example.com', $3::jsonb, $4::jsonb, $5::jsonb, 'test message', 'sent')
                       ON CONFLICT (id) DO NOTHING"#,
                )
                .bind(id)
                .bind(tenant)
                .bind(serde_json::json!(to))
                .bind(serde_json::json!(cc))
                .bind(serde_json::json!(bcc))
                .execute(db)
                .await
                .expect("seed message");
            }

            async fn suppression_exists(db: &sqlx::PgPool, tenant: &str) -> bool {
                sqlx::query_as::<_, (String,)>(
                    "SELECT email FROM suppressions WHERE tenant_id=$1 AND email=$2 LIMIT 1",
                )
                .bind(tenant)
                .bind(RECIPIENT)
                .fetch_optional(db)
                .await
                .expect("suppression lookup")
                .is_some()
            }

            async fn wal_unsub_events(redis: &deadpool_redis::Pool, tenant: &str) -> Vec<String> {
                let Ok(mut conn) = redis.get().await else {
                    return Vec::new();
                };
                redis::cmd("LRANGE")
                    .arg(REDIS_WAL_KEY)
                    .arg(0)
                    .arg(-1)
                    .query_async::<Vec<String>>(&mut *conn)
                    .await
                    .unwrap_or_default()
                    .into_iter()
                    .filter(|e| e.contains(tenant) && e.contains("unsubscribed"))
                    .collect()
            }

            async fn settle() {
                tokio::time::sleep(Duration::from_millis(300)).await;
            }

            async fn cleanup(db: &sqlx::PgPool, redis: &deadpool_redis::Pool, tenant: &str) {
                let _ = sqlx::query("DELETE FROM tenants WHERE id = $1")
                    .bind(tenant)
                    .execute(db)
                    .await;
                if let Ok(mut conn) = redis.get().await {
                    for entry in wal_unsub_events(redis, tenant).await {
                        let _: Result<(), _> = redis::cmd("LREM")
                            .arg(REDIS_WAL_KEY)
                            .arg(1)
                            .arg(&entry)
                            .query_async(&mut *conn)
                            .await;
                    }
                    let _: Result<(), _> = redis::cmd("DEL")
                        .arg(unsub_dedup_key(tenant, RECIPIENT))
                        .query_async(&mut *conn)
                        .await;
                }
            }

            /// F13:legacy tokens resolve attribution against the canonical
            /// recipient arrays (to/cc/bcc JSON, tenant-scoped, id::text);
            /// v2 tokens use the embedded message id; nothing resolves to
            /// an INVENTED id ("msg_…") — the fallback is exactly
            /// "unknown".
            #[tokio::test]
            async fn unsubscribe_attribution_legacy_v2_and_unknown() {
                let Some((state, redis, db)) = test_support::live_redis_pg_state(&[]).await else {
                    eprintln!("skipping: set TEST_REDIS_URL + TEST_DATABASE_URL to run");
                    return;
                };
                let tenant = unique_tenant("f13attr");
                let server = server(&state).await;
                seed_tenant(&db, &tenant).await;

                // Fresh message ids per run (leftover rows from an earlier
                // failed run must not swallow this run's seeds via
                // ON CONFLICT DO NOTHING).
                let to_old = Uuid::new_v4().to_string();
                let to_new = Uuid::new_v4().to_string();
                let cc_new = Uuid::new_v4().to_string();
                let bcc_new = Uuid::new_v4().to_string();

                // (1) Legacy token: newest message with the recipient in a
                // canonical recipient array — the newest match is the BCC
                // message, so to/cc/bcc are all consulted.
                seed_message(&db, &tenant, &to_old, &[RECIPIENT], &[], &[]).await;
                tokio::time::sleep(Duration::from_millis(30)).await;
                seed_message(&db, &tenant, &to_new, &["other@example.com"], &[], &[]).await;
                tokio::time::sleep(Duration::from_millis(30)).await;
                seed_message(&db, &tenant, &cc_new, &[], &[RECIPIENT], &[]).await;
                tokio::time::sleep(Duration::from_millis(30)).await;
                seed_message(&db, &tenant, &bcc_new, &[], &[], &[RECIPIENT]).await;

                let token = legacy_token(&tenant, RECIPIENT);
                let resp = server
                    .post(&format!("/u/{token}"))
                    .text("List-Unsubscribe=One-Click")
                    .await;
                assert_eq!(resp.status_code().as_u16(), 200, "{}", resp.text());
                settle().await;

                let events = wal_unsub_events(&redis, &tenant).await;
                assert_eq!(events.len(), 1, "got: {events:?}");
                assert!(
                    events[0].contains(&format!(r#""messageId":"{bcc_new}""#)),
                    "must attribute to the NEWEST canonical-recipient message (bcc), got: {}",
                    events[0]
                );

                // (2) v2 token: attribution comes from the token itself —
                // a fresh recipient so the 24 h dedup key from (1) cannot
                // short-circuit the recording.
                let v2_user = "f13v2@example.com";
                let v2_msg = Uuid::new_v4().to_string();
                let v2 = v2_token(&tenant, v2_user, &v2_msg);
                let resp = server
                    .post(&format!("/u/{v2}"))
                    .text("List-Unsubscribe=One-Click")
                    .await;
                assert_eq!(resp.status_code().as_u16(), 200);
                settle().await;

                let events = wal_unsub_events(&redis, &tenant).await;
                let want = format!(r#""messageId":"{v2_msg}""#);
                assert!(
                    events.iter().any(|e| e.contains(&want)),
                    "v2 token attribution must be recorded verbatim, got: {events:?}"
                );

                // (3) Unknown recipient (no message anywhere): "unknown",
                // never an invented "msg_…" id.
                let stranger = "stranger@example.com";
                let token = TrackingCodec::new(test_support::TEST_SECRET)
                    .generate_unsubscribe_token(&tenant, stranger)
                    .expect("token");
                let resp = server
                    .post(&format!("/u/{token}"))
                    .text("List-Unsubscribe=One-Click")
                    .await;
                assert_eq!(resp.status_code().as_u16(), 200);
                settle().await;

                let events = wal_unsub_events(&redis, &tenant).await;
                let stranger_event = events
                    .iter()
                    .find(|e| e.contains(stranger))
                    .expect("stranger event recorded");
                assert!(
                    stranger_event.contains(r#""messageId":"unknown""#),
                    "unresolved attribution must be exactly 'unknown', got: {stranger_event}"
                );
                assert!(
                    !stranger_event.contains(r#""messageId":"msg_"#),
                    "no invented message ids, got: {stranger_event}"
                );

                cleanup(&db, &redis, &tenant).await;
            }

            /// F38:unsubscribe → resubscribe → unsubscribe. The final
            /// choice must survive BOTH the dedup-clearing resubscribe AND
            /// a deliberately stale dedup key (simulating a failed DEL).
            #[tokio::test]
            async fn consent_triple_transition_keeps_final_choice() {
                let Some((state, redis, db)) = test_support::live_redis_pg_state(&[]).await else {
                    eprintln!("skipping: set TEST_REDIS_URL + TEST_DATABASE_URL to run");
                    return;
                };
                let tenant = unique_tenant("f38triple");
                let server = server(&state).await;
                seed_tenant(&db, &tenant).await;

                let unsub_token = legacy_token(&tenant, RECIPIENT);
                let prefs_token = TrackingCodec::new(test_support::TEST_SECRET)
                    .generate_preferences_token(&tenant, RECIPIENT)
                    .expect("prefs token");

                // (1) Unsubscribe → suppressed.
                let resp = server
                    .post(&format!("/u/{unsub_token}"))
                    .text("List-Unsubscribe=One-Click")
                    .await;
                assert_eq!(resp.status_code().as_u16(), 200);
                settle().await;
                assert!(
                    suppression_exists(&db, &tenant).await,
                    "first unsubscribe must persist the suppression"
                );

                // (2) Resubscribe via the preferences center → not
                // suppressed, and the dedup key is cleared.
                let resp = server
                    .post(&format!("/p/{prefs_token}"))
                    .form(&[("resubscribe_all", "true")])
                    .await;
                assert_eq!(resp.status_code().as_u16(), 303, "{}", resp.text());
                assert!(
                    !suppression_exists(&db, &tenant).await,
                    "resubscribe must remove the suppression"
                );

                // Simulate the worst case the durable check defends against:
                // re-create the STALE dedup key exactly as it would have
                // survived a failed DEL (the pre-F38 bug: this key alone
                // made the next unsubscribe a silent no-op).
                {
                    let mut conn = redis.get().await.expect("redis conn");
                    redis::cmd("SET")
                        .arg(unsub_dedup_key(&tenant, RECIPIENT))
                        .arg("suppressed")
                        .arg("EX")
                        .arg(86_400u64)
                        .query_async::<()>(&mut *conn)
                        .await
                        .expect("seed stale dedup key");
                }

                // (3) Unsubscribe again → MUST restore the suppression.
                let resp = server
                    .post(&format!("/u/{unsub_token}"))
                    .text("List-Unsubscribe=One-Click")
                    .await;
                assert_eq!(
                    resp.status_code().as_u16(),
                    200,
                    "stale dedup key must not turn the final unsubscribe into a silent success"
                );
                settle().await;
                assert!(
                    suppression_exists(&db, &tenant).await,
                    "F38:the FINAL consent choice (unsubscribe) must be persisted"
                );

                // The stale key was reconciled (cleared + re-marked).
                {
                    let mut conn = redis.get().await.expect("redis conn");
                    let val: Option<String> = redis::cmd("GET")
                        .arg(unsub_dedup_key(&tenant, RECIPIENT))
                        .query_async(&mut *conn)
                        .await
                        .expect("dedup key read");
                    assert_eq!(val.as_deref(), Some("suppressed"));
                }

                cleanup(&db, &redis, &tenant).await;
            }

            /// F38 (duplicate events are still deduped): a repeat POST with
            /// the suppression intact answers success WITHOUT a second event.
            #[tokio::test]
            async fn duplicate_unsubscribe_still_dedupes_events() {
                let Some((state, redis, db)) = test_support::live_redis_pg_state(&[]).await else {
                    eprintln!("skipping: set TEST_REDIS_URL + TEST_DATABASE_URL to run");
                    return;
                };
                let tenant = unique_tenant("f38dedup");
                let server = server(&state).await;
                seed_tenant(&db, &tenant).await;

                let token = legacy_token(&tenant, RECIPIENT);
                for _ in 0..2 {
                    let resp = server
                        .post(&format!("/u/{token}"))
                        .text("List-Unsubscribe=One-Click")
                        .await;
                    assert_eq!(resp.status_code().as_u16(), 200);
                }
                settle().await;

                let events = wal_unsub_events(&redis, &tenant).await;
                assert_eq!(
                    events.len(),
                    1,
                    "duplicate one-click POST with persisted suppression must not re-record: {events:?}"
                );

                cleanup(&db, &redis, &tenant).await;
            }

            /// F39:GET never mutates; the POST confirm endpoint performs the
            /// manual unsubscribe.
            #[tokio::test]
            async fn manual_unsubscribe_requires_post_confirm() {
                let Some((state, redis, db)) = test_support::live_redis_pg_state(&[]).await else {
                    eprintln!("skipping: set TEST_REDIS_URL + TEST_DATABASE_URL to run");
                    return;
                };
                let tenant = unique_tenant("f39post");
                let server = server(&state).await;
                seed_tenant(&db, &tenant).await;

                let token = legacy_token(&tenant, RECIPIENT);

                // GET — even with the legacy ?confirm=1 flag — records nothing.
                let resp = server.get(&format!("/u/{token}")).await;
                assert!(resp.text().contains("Confirm Unsubscribe"));
                let resp = server
                    .get(&format!("/u/{token}"))
                    .add_query_param("confirm", "1")
                    .await;
                assert!(
                    resp.text().contains("Confirm Unsubscribe"),
                    "GET ?confirm=1 must render the form, not mutate"
                );
                settle().await;
                assert!(
                    !suppression_exists(&db, &tenant).await,
                    "GET must not change consent (F39)"
                );
                assert!(
                    wal_unsub_events(&redis, &tenant).await.is_empty(),
                    "GET must not record events (F39)"
                );

                // POST confirm → unsubscribe happens.
                let resp = server
                    .post(&format!("/u/{token}/confirm"))
                    .form(&[("confirm", "true")])
                    .await;
                assert_eq!(resp.status_code().as_u16(), 200, "{}", resp.text());
                assert!(resp.text().contains("been unsubscribed"));
                settle().await;
                assert!(
                    suppression_exists(&db, &tenant).await,
                    "POST /confirm must persist the suppression"
                );
                assert_eq!(wal_unsub_events(&redis, &tenant).await.len(), 1);

                cleanup(&db, &redis, &tenant).await;
            }
        }
    }

    // ── F9:category preference validation ─────────────────────────────

    fn valid_set() -> std::collections::HashSet<String> {
        ["marketing", "product-updates", "weekly-digest"]
            .into_iter()
            .map(String::from)
            .collect()
    }

    #[test]
    fn category_prefs_accept_known_categories_within_cap() {
        let cats = vec![
            ("marketing".to_string(), true),
            ("weekly-digest".to_string(), false),
        ];
        assert!(validate_category_preferences(&cats, &valid_set(), 50).is_ok());
    }

    #[test]
    fn category_prefs_reject_unknown_names() {
        let cats = vec![
            ("marketing".to_string(), true),
            ("arbitrary-junk".to_string(), true),
        ];
        let err = validate_category_preferences(&cats, &valid_set(), 50).unwrap_err();
        assert!(err.contains("arbitrary-junk"), "{err}");
        assert!(err.contains("unknown categories"), "{err}");
    }

    #[test]
    fn category_prefs_reject_over_cap_quantity() {
        let cats: Vec<(String, bool)> = (0..51)
            .map(|i| ("marketing".to_string(), i % 2 == 0))
            .collect();
        let err = validate_category_preferences(&cats, &valid_set(), 50).unwrap_err();
        assert!(err.contains("maximum is 50"), "{err}");
        // Exactly at the cap passes.
        let at_cap: Vec<(String, bool)> = cats[..50].to_vec();
        assert!(validate_category_preferences(&at_cap, &valid_set(), 50).is_ok());
    }

    #[test]
    fn category_prefs_empty_submission_is_ok() {
        assert!(validate_category_preferences(&[], &valid_set(), 50).is_ok());
    }
}
