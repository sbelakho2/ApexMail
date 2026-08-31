//! Customer-facing grounded assistant chat.
//!
//! The api-server is the authenticated control plane for this route: it
//! verifies the user, enforces scopes and rate limits, assembles the
//! tenant-scoped ACCOUNT CONTEXT from its own databases, and forwards the
//! request to ai-service with the shared internal service token. The
//! assistant never authenticates anything itself, and account facts shown to
//! the model are display-only.

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use crate::error::ApiError;
use crate::middleware::auth::{require_scopes, AuthUser};
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/chat", post(chat))
        .route("/chat/history", get(chat_history))
}

#[derive(Debug, Deserialize)]
pub struct ChatBody {
    pub message: String,
    /// Previous turns from the client, oldest first.
    #[serde(default)]
    pub history: Vec<HistoryTurn>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistoryTurn {
    pub role: String,
    pub content: String,
}

#[derive(Debug, Serialize)]
pub struct ChatOut {
    pub answer: String,
    pub citations: serde_json::Value,
    pub escalated: bool,
    pub disclosure: String,
    pub docs_version: String,
}

/// Conversation history cap enforced server-side (the client may send more).
const MAX_HISTORY: usize = 12;
/// Per-user chat rate limit (Redis sliding window), independent of the
/// tenant-wide API bucket: chat is expensive and per-person.
const CHAT_RATE_LIMIT: i64 = 20;
const CHAT_RATE_WINDOW_SECS: i64 = 60;

async fn chat(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(body): Json<ChatBody>,
) -> Result<Json<ChatOut>, ApiError> {
    require_scopes(&auth, &["ai:read"])?;

    let message = body.message.trim().to_string();
    if message.is_empty() {
        return Err(ApiError::Validation(vec![
            "message must not be empty".into()
        ]));
    }
    if message.len() > 4000 {
        return Err(ApiError::Validation(vec![
            "message too long (max 4000 chars)".into(),
        ]));
    }

    // Per-user chat rate limit.
    let user_key = auth
        .user_id
        .clone()
        .unwrap_or_else(|| auth.tenant_id.clone());
    chat_rate_limit(&state, &auth.tenant_id, &user_key).await?;

    let ai_url = state.config.ai_service_base_url.trim().to_string();
    if ai_url.is_empty() {
        return Err(ApiError::Internal(
            "assistant is not configured; contact support@apexmail.ee".into(),
        ));
    }

    // Account context assembled HERE, from tenant-scoped queries — the
    // trusted half of the design. ai-service treats it as display data.
    let account_context = account_context(&state, &auth.tenant_id).await;

    let history: Vec<HistoryTurn> = body
        .history
        .into_iter()
        .take(MAX_HISTORY)
        .filter(|t| matches!(t.role.as_str(), "user" | "assistant") && !t.content.is_empty())
        .collect();

    let payload = serde_json::json!({
        "tenant_id": auth.tenant_id,
        "user_id": user_key,
        "message": message,
        "account_context": account_context,
        "history": history,
    });

    let mut request = state
        .http_client
        .post(format!("{ai_url}/chat"))
        .json(&payload)
        .timeout(std::time::Duration::from_secs(45));
    if let Some(token) = state.config.internal_service_token.as_deref() {
        request = request.header("x-api-key", token);
    }
    // The end user's tenant for ai-service's per-tenant governor.
    request = request.header("x-apexmail-tenant-id", &auth.tenant_id);

    let response = request.send().await.map_err(|e| {
        tracing::warn!(error = %e, tenant_id = %auth.tenant_id, "ai chat: service unreachable");
        ApiError::Internal("assistant unavailable; contact support@apexmail.ee".into())
    })?;

    match response.status() {
        StatusCode::OK => {
            let out: serde_json::Value = response.json().await.map_err(|e| {
                tracing::warn!(error = %e, "ai chat: malformed response");
                ApiError::Internal("assistant returned an invalid response".into())
            })?;
            Ok(Json(ChatOut {
                answer: out["answer"].as_str().unwrap_or_default().to_string(),
                citations: out.get("citations").cloned().unwrap_or_default(),
                escalated: out["escalated"].as_bool().unwrap_or(false),
                disclosure: out["disclosure"]
                    .as_str()
                    .unwrap_or("This assistant is AI-powered. Escalation: support@apexmail.ee.")
                    .to_string(),
                docs_version: out["docs_version"].as_str().unwrap_or_default().to_string(),
            }))
        }
        StatusCode::TOO_MANY_REQUESTS => Err(ApiError::RateLimitedMessage(
            "assistant rate limit reached — please retry in a minute".into(),
        )),
        status => {
            tracing::warn!(status = %status, "ai chat: service error");
            Err(ApiError::Internal(
                "assistant unavailable; contact support@apexmail.ee".into(),
            ))
        }
    }
}

async fn chat_history(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<Json<serde_json::Value>, ApiError> {
    require_scopes(&auth, &["ai:read"])?;

    let ai_url = state.config.ai_service_base_url.trim().to_string();
    if ai_url.is_empty() {
        return Err(ApiError::Internal("assistant is not configured".into()));
    }
    let mut request = state
        .http_client
        .post(format!("{ai_url}/admin/chat/history"))
        .json(&serde_json::json!({ "tenant_id": auth.tenant_id, "limit": 50 }))
        .timeout(std::time::Duration::from_secs(10));
    if let Some(token) = state.config.internal_service_token.as_deref() {
        request = request.header("x-api-key", token);
    }
    let response = request.send().await.map_err(|e| {
        tracing::warn!(error = %e, "ai chat history: service unreachable");
        ApiError::Internal("assistant unavailable".into())
    })?;
    if response.status() != StatusCode::OK {
        return Err(ApiError::Internal("assistant unavailable".into()));
    }
    let out: serde_json::Value = response.json().await.unwrap_or_default();
    Ok(Json(out))
}

/// Tenant-scoped account facts for grounding: plan, quota, recent bounces.
/// Every query filters on the AUTHENTICATED tenant; nothing here trusts the
/// request body.
async fn account_context(state: &AppState, tenant_id: &str) -> serde_json::Value {
    let plan: Option<(String, Option<i64>, Option<i64>)> = sqlx::query_as(
        r#"
        SELECT t.plan, p.email_limit, p.api_call_limit
        FROM tenants t
        LEFT JOIN plan_overrides po
          ON po.tenant_id = t.id AND po.active = true
         AND (po.expires_at IS NULL OR po.expires_at > NOW())
        LEFT JOIN plans p ON p.name = COALESCE(po.plan, t.plan)
        WHERE t.id = $1
        "#,
    )
    .bind(tenant_id)
    .fetch_optional(&state.db)
    .await
    .ok()
    .flatten();

    let usage: Option<(i64,)> = sqlx::query_as(
        "SELECT COALESCE(SUM(quantity), 0)::bigint FROM metering_events \
         WHERE tenant_id = $1 AND event_type = 'emails_sent' \
           AND timestamp >= date_trunc('month', NOW())",
    )
    .bind(tenant_id)
    .fetch_one(&state.db)
    .await
    .ok();

    let bounces: Option<(i64,)> = sqlx::query_as(
        "SELECT COUNT(*) FROM email_queue \
         WHERE tenant_id = $1::uuid AND status = 'bounced' \
           AND created_at > NOW() - INTERVAL '7 days'",
    )
    .bind(tenant_id)
    .fetch_one(&state.db)
    .await
    .ok();

    let domains: Option<(i64,)> = sqlx::query_as(
        "SELECT COUNT(*) FROM domains WHERE tenant_id = $1::uuid AND verified = true",
    )
    .bind(tenant_id)
    .fetch_one(&state.db)
    .await
    .ok();

    serde_json::json!({
        "plan": plan.as_ref().map(|(p, _, _)| p.clone()),
        "monthly_email_limit": plan.as_ref().and_then(|(_, e, _)| *e),
        "emails_sent_this_month": usage.map(|(u,)| u),
        "hard_bounces_last_7d": bounces.map(|(b,)| b),
        "verified_domains": domains.map(|(d,)| d),
    })
}

async fn chat_rate_limit(
    state: &AppState,
    tenant_id: &str,
    user_key: &str,
) -> Result<(), ApiError> {
    let redis_key = format!("apexmail:ai:chat:{tenant_id}:{user_key}");
    let Ok(mut conn) = state.redis.get().await else {
        // Redis unavailable: allow (fail open for chat; the tenant-wide API
        // limiter still applies upstream).
        return Ok(());
    };
    let count: i64 = redis::cmd("INCR")
        .arg(&redis_key)
        .query_async(&mut conn)
        .await
        .unwrap_or(0);
    if count == 1 {
        let _: Result<(), _> = redis::cmd("EXPIRE")
            .arg(&redis_key)
            .arg(CHAT_RATE_WINDOW_SECS)
            .query_async(&mut conn)
            .await;
    }
    if count > CHAT_RATE_LIMIT {
        return Err(ApiError::RateLimitedMessage(
            "assistant rate limit reached — please retry in a minute".into(),
        ));
    }
    Ok(())
}

// Unused-import guard for HeaderMap (kept for future client-IP extraction).
#[allow(dead_code)]
fn _header_guard(_h: &HeaderMap) {}
