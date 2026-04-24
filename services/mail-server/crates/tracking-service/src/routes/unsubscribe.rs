//! Unsubscribe and preferences-center handlers.
//!
//! Unsubscribe endpoints://! POST `{unsub_path}/:token` — RFC 8058 one-click (List-Unsubscribe-Post)
//! GET `{unsub_path}/:token` — Manual (shows confirmation / success page)
//!
//! Preferences endpoints://! GET `{prefs_path}/:token` — Show preferences form
//! POST `{prefs_path}/:token` — Save preferences

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

// ── POST /u/:token (RFC 8058 one-click) ───────────────────────────────────────

pub async fn handle_unsub_post(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(token): Path<String>,
    body: String,
) -> Response {
    if token.len() < 10 || token.len() > 4096 {
        warn!(len = token.len(), "Unsubscribe POST: invalid token length");
        return axum::http::Response::builder()
            .status(400)
            .header("content-type", "application/json")
            .body(axum::body::Body::from(r#"{"error":"Invalid token"}"#))
            .unwrap_or_default();
    }

// F-210:trim trailing CRLF / whitespace
    let body = body.trim().to_owned();

    let ua = headers.get("user-agent").and_then(|v| v.to_str().ok()).map(str::to_owned);
    let ip = extract_client_ip(&headers, addr.ip(), &state);

    info!(token_prefix = &token[..token.len().min(20)], "One-click unsubscribe request");

    if body != "List-Unsubscribe=One-Click" {
        warn!(body = %body, "Invalid unsubscribe body");
        return axum::http::Response::builder()
            .status(400)
            .header("content-type", "application/json")
            .body(axum::body::Body::from(r#"{"error":"Invalid request body"}"#))
            .unwrap_or_default();
    }

    let data = match state.codec.verify_unsubscribe_token(&token, None) {
        Some(d) => d,
        None => {
            warn!("Unsubscribe POST: invalid or expired token");
            return axum::http::Response::builder()
                .status(400)
                .header("content-type", "application/json")
                .body(axum::body::Body::from(r#"{"error":"Invalid or expired token"}"#))
                .unwrap_or_default();
        }
    };

    let message_id = find_latest_message_id(&state, &data.tenant_id, &data.recipient)
        .await
        .unwrap_or_else(|| new_id("msg"));

    if let Err(e) = state.processor.record_unsubscribe(UnsubscribeData {
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

// Fire-and-forget webhook queue (F-215)
    queue_unsub_webhook_async(&state, &data.tenant_id, &data.recipient, "one-click");

    axum::http::Response::builder()
        .status(200)
        .header("content-type", "application/json")
        .body(axum::body::Body::from(r#"{"success":true}"#))
        .unwrap_or_default()
}

// ── GET /u/:token ─────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct UnsubQuery {
    confirm: Option<String>,
}

pub async fn handle_unsub_get(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(token): Path<String>,
    Query(q): Query<UnsubQuery>,
) -> Response {
    if token.len() < 10 || token.len() > 4096 {
        return Html(render_error_page("Invalid or expired unsubscribe link")).into_response();
    }

    let data = match state.codec.verify_unsubscribe_token(&token, None) {
        Some(d) => d,
        None => return Html(render_error_page("Invalid or expired unsubscribe link")).into_response(),
    };

    let unsub_path = &state.config.tracking.unsubscribe_path;

    if q.confirm.as_deref() == Some("1") {
        let ua = headers.get("user-agent").and_then(|v| v.to_str().ok()).map(str::to_owned);
        let ip = extract_client_ip(&headers, addr.ip(), &state);

        let message_id = find_latest_message_id(&state, &data.tenant_id, &data.recipient)
            .await
            .unwrap_or_else(|| new_id("msg"));

        if let Err(e) = state.processor.record_unsubscribe(UnsubscribeData {
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

        queue_unsub_webhook_async(&state, &data.tenant_id, &data.recipient, "link-click");

        return Html(render_success_page(&data.recipient)).into_response();
    }

    Html(render_confirmation_page(&token, &data.recipient, unsub_path)).into_response()
}

// ── GET /p/:token ─────────────────────────────────────────────────────────────

#[derive(Deserialize)]
#[allow(unused)] // `saved` populated by Serde from query params; field used in future confirmation-UX branch
pub struct PrefsQuery {
    saved: Option<String>,
}

pub async fn handle_prefs_get(
    State(state): State<AppState>,
    Path(token): Path<String>,
    Query(_q): Query<PrefsQuery>,
) -> Response {
    if token.len() < 10 || token.len() > 4096 {
        return Html(render_error_page("Invalid or expired preferences link")).into_response();
    }

    let data = match state.codec.verify_preferences_token(&token) {
        Some(d) => d,
        None => return Html(render_error_page("Invalid or expired preferences link")).into_response(),
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
        sqlx::query_as::<_, (i64,)>(
            "SELECT 1 FROM suppressions WHERE tenant_id=$1 AND email=$2"
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
            OwnedCategory { name, description: desc, subscribed }
        })
        .collect();

    let cat_refs: Vec<Category<'_>> = cats
        .iter()
        .map(|c| Category { name: &c.name, description: &c.description, subscribed: c.subscribed })
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
    if token.len() < 10 || token.len() > 4096 {
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
                .body(axum::body::Body::from(r#"{"error":"Invalid or expired token"}"#))
                .unwrap_or_default();
        }
    };

    let email = data.recipient.to_lowercase();
    let prefs_path = &state.config.tracking.preferences_path;

// Global unsubscribe
    if form.unsubscribe_all.as_deref() == Some("true") {
        let sup_id = new_id("sup");
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

        queue_unsub_webhook_async(&state, &data.tenant_id, &email, "preferences-center");
        let redirect_url = format!("{prefs_path}/{token}?saved=1");
        return Redirect::to(&redirect_url).into_response();
    }

// Resubscribe
    if form.resubscribe_all.as_deref() == Some("true") {
        if let Err(e) = sqlx::query(
            "DELETE FROM suppressions WHERE tenant_id=$1 AND email=$2 AND reason='unsubscribe'"
        )
        .bind(&data.tenant_id).bind(&email)
        .execute(&state.db).await {
            tracing::error!(error = %e, tenant_id = %data.tenant_id, email = %mail_common::pii::redact_email(&email), "Failed to delete suppression record for resubscribe");
            return axum::http::Response::builder()
                .status(500)
                .header("content-type", "application/json")
                .body(axum::body::Body::from(r#"{"error":"Failed to save resubscribe preference. Please try again."}"#))
                .unwrap_or_default();
        }

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
// #203:Use batch INSERT via sqlx::QueryBuilder instead of N individual INSERTs
        let mut tx = match state.db.begin().await {
            Ok(tx) => tx,
            Err(e) => {
                error!(error = %e, "Failed to begin transaction for preferences");
                return axum::http::Response::builder()
                    .status(500)
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(r#"{"error":"Failed to save preferences. Please try again."}"#))
                    .unwrap_or_default();
            }
        };

// Batch UPSERT all category preferences in a single statement
        let mut builder = sqlx::QueryBuilder::<sqlx::Postgres>::new(
            "INSERT INTO subscription_preferences (id, tenant_id, email, category, subscribed, updated_at) "
        );
        builder.push_values(&cats, |mut b, (cat, subscribed)| {
            b.push_bind(new_id("prf"))
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
                .body(axum::body::Body::from(r#"{"error":"Failed to save preferences. Please try again."}"#))
                .unwrap_or_default();
        }

        if let Err(e) = tx.commit().await {
            tracing::error!(error = %e, tenant_id = %data.tenant_id, email = %mail_common::pii::redact_email(&email), "CRITICAL: Failed to commit subscription preference transaction \u{2014} changes rolled back");
            return axum::http::Response::builder()
                .status(500)
                .header("content-type", "application/json")
                .body(axum::body::Body::from(r#"{"error":"Failed to save preferences. Please try again."}"#))
                .unwrap_or_default();
        }
    }

    let redirect_url = format!("{prefs_path}/{token}?saved=1");
    Redirect::to(&redirect_url).into_response()
}

// ── Shared helpers ────────────────────────────────────────────────────────────

async fn find_latest_message_id(state: &AppState, tenant_id: &str, recipient: &str) -> Option<String> {
    sqlx::query_as::<_, (String,)>(
        "SELECT id FROM messages WHERE tenant_id=$1 AND to_address=$2 ORDER BY created_at DESC LIMIT 1"
    )
    .bind(tenant_id)
    .bind(recipient)
    .fetch_optional(&state.db)
    .await
    .ok()
    .flatten()
    .map(|(id,)| id)
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
        let rows = sqlx::query_as::<_, (String,)>(r#"
            SELECT id FROM webhooks
            WHERE tenant_id=$1 AND enabled=true
              AND (events @> '"recipient.unsubscribed"'::jsonb OR events @> '"*"'::jsonb)
        "#)
        .bind(tenant_id)
        .fetch_all(&state.db)
        .await?;
        let ids: Vec<String> = rows.into_iter().map(|(id,)| id).collect();
        state.webhook_cache.insert(tenant_id.to_owned(), ids.clone()).await;
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

fn new_id(prefix: &str) -> String {
    format!("{prefix}_{}", Uuid::new_v4().simple())
}
