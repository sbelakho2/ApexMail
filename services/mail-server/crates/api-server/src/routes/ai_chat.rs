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

/// Feature-flag name managing the customer-facing assistant capability.
/// Default `true`: the capability predates flag evaluation, so absence of a
/// row must preserve today's behaviour; operators disable it per tenant with
/// a `feature_flag_overrides` row (JSON boolean) or globally with an
/// `enabled = false` `feature_flags` row.
pub(crate) const AI_CHAT_FEATURE_FLAG: &str = "ai_chat";

/// Evaluate the assistant capability for the authenticated tenant. Returns
/// 403 (not 404) so a disabled tenant knows the capability exists but is
/// switched off for them.
async fn require_ai_chat_enabled(state: &AppState, tenant_id: &str) -> Result<(), ApiError> {
    if state
        .feature_flags
        .enabled(tenant_id, AI_CHAT_FEATURE_FLAG, true)
        .await?
    {
        return Ok(());
    }
    Err(ApiError::Forbidden(
        "the AI assistant is not enabled for this tenant".into(),
    ))
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

pub(crate) async fn chat(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(body): Json<ChatBody>,
) -> Result<Json<ChatOut>, ApiError> {
    require_scopes(&auth, &["ai:read"])?;
    require_ai_chat_enabled(&state, &auth.tenant_id).await?;

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

pub(crate) async fn chat_history(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<Json<serde_json::Value>, ApiError> {
    require_scopes(&auth, &["ai:read"])?;
    require_ai_chat_enabled(&state, &auth.tenant_id).await?;

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

    // tenants/users/domains/email_queue all carry VARCHAR(26) tenant ids —
    // the previous `$1::uuid` casts made these counts fail (and return nulls
    // via `.ok()`) on every deployment.
    let bounces: Option<(i64,)> = sqlx::query_as(
        "SELECT COUNT(*) FROM email_queue \
         WHERE tenant_id = $1 AND status = 'bounced' \
           AND created_at > NOW() - INTERVAL '7 days'",
    )
    .bind(tenant_id)
    .fetch_one(&state.db)
    .await
    .ok();

    let domains: Option<(i64,)> =
        sqlx::query_as("SELECT COUNT(*) FROM domains WHERE tenant_id = $1 AND verified = true")
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

#[cfg(test)]
mod adversarial_tests {
    use axum::http::StatusCode;

    use crate::app::test_support::adv::AdvEnv;

    /// Minimal in-process ai-service twin: serves /chat and
    /// /admin/chat/history with canned payloads, recording requests.
    async fn start_mock_ai() -> (
        String,
        std::sync::Arc<std::sync::Mutex<Vec<serde_json::Value>>>,
    ) {
        use axum::routing::post;
        let seen: std::sync::Arc<std::sync::Mutex<Vec<serde_json::Value>>> =
            std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let state = seen.clone();
        let app = axum::Router::new()
            .route(
                "/chat",
                post(move |axum::Json(body): axum::Json<serde_json::Value>| async move {
                    state.lock().unwrap().push(body);
                    axum::Json(serde_json::json!({
                        "answer": "Ship the adversarial test.",
                        "citations": [{"title": "ApexMail docs", "url": "https://apexmail.ee/docs"}],
                        "escalated": false,
                        "disclosure": "AI-powered. Escalation: support@apexmail.ee.",
                        "docs_version": "v42",
                    }))
                }),
            )
            .route(
                "/admin/chat/history",
                post(|| async {
                    axum::Json(serde_json::json!({
                        "conversations": [{"id": "c1", "messages": 3}]
                    }))
                }),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base_url = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        (base_url, seen)
    }

    fn ai_config(ai_url: &str) -> crate::config::Config {
        let mut config = crate::app::test_support::test_config();
        config.ai_service_base_url = ai_url.into();
        config
    }

    #[tokio::test]
    async fn chat_requires_scope_feature_message_and_service() {
        let Some(pool) = crate::test_db::canonical_pool("ai_chat_gates").await else {
            return;
        };
        let Some((env, tenant, _user)) = AdvEnv::session(pool.clone(), "owner").await else {
            return;
        };

        // Member-role session lacks ai:read.
        let Some((member, _t, _u)) = AdvEnv::session(pool.clone(), "member").await else {
            return;
        };
        let (status, body) = member.post("/v1/ai/chat", r#"{"message":"hi"}"#).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{body}");

        // Empty message.
        let (status, body) = env.post("/v1/ai/chat", r#"{"message":"   "}"#).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");

        // Over-length message (hostile boundary).
        let long = "x".repeat(4001);
        let (status, body) = env
            .post(
                "/v1/ai/chat",
                &serde_json::json!({ "message": long }).to_string(),
            )
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");

        // Unconfigured assistant (empty URL) is a 500 with a clear code.
        let (unconfigured, _t2) =
            AdvEnv::tenant_with_config(pool.clone(), &["ai:read"], ai_config("")).await;
        let (status, body) = unconfigured
            .post("/v1/ai/chat", r#"{"message":"hi"}"#)
            .await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR, "{body}");
        assert_eq!(body["error"]["code"], "INTERNAL_ERROR");

        // Unreachable assistant (dead port) is likewise a clean 500.
        let (dead, _t3) =
            AdvEnv::tenant_with_config(pool.clone(), &["ai:read"], ai_config("http://127.0.0.1:1"))
                .await;
        let (status, body) = dead.post("/v1/ai/chat", r#"{"message":"hi"}"#).await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR, "{body}");

        // Feature disabled per tenant → 403 naming the capability. Probed on
        // a FRESH env: the flag service caches resolved values per state, so
        // an env that already evaluated the flag would keep its cached
        // `true`. The fresh env points at a dead ai-service so a bypassed
        // gate could never pass silently.
        let (flag_off, flag_off_tenant) =
            AdvEnv::tenant_with_config(pool.clone(), &["ai:read"], ai_config("http://127.0.0.1:1"))
                .await;
        sqlx::query(
            "INSERT INTO feature_flag_overrides (id, flag_key, tenant_id, value, created_at)
             VALUES ($1, 'ai_chat', $2, 'false'::jsonb, NOW())",
        )
        .bind(uuid::Uuid::new_v4())
        .bind(&flag_off_tenant)
        .execute(&pool)
        .await
        .expect("disable flag");
        let (status, body) = flag_off.post("/v1/ai/chat", r#"{"message":"hi"}"#).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
        assert!(body["error"]["message"]
            .as_str()
            .unwrap_or_default()
            .contains("not enabled"));
        let _ = tenant;
    }

    #[tokio::test]
    async fn chat_forwards_tenant_context_and_parses_the_answer() {
        let Some(pool) = crate::test_db::canonical_pool("ai_chat_ok").await else {
            return;
        };
        let (ai_url, seen) = start_mock_ai().await;
        let Some((env, tenant, _user)) = AdvEnv::session(pool.clone(), "owner").await else {
            return;
        };
        // Rebuild the SAME session env but with the mock ai URL — the shared
        // helper builds its own config; drive a tenant API key instead so
        // the URL override rides along.
        let (key_env, key_tenant) =
            AdvEnv::tenant_with_config(pool.clone(), &["ai:read"], ai_config(&ai_url)).await;
        let _ = (env, tenant);

        let (status, body) = key_env
            .post(
                "/v1/ai/chat",
                &serde_json::json!({
                    "message": "How do I verify a domain?",
                    "history": [
                        {"role": "user", "content": "earlier"},
                        {"role": "assistant", "content": "answer"},
                        {"role": "bogus", "content": "dropped"},
                        {"role": "user", "content": ""}
                    ]
                })
                .to_string(),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["answer"], "Ship the adversarial test.");
        assert_eq!(body["docs_version"], "v42");
        assert_eq!(body["escalated"], false);
        assert_eq!(body["citations"][0]["title"], "ApexMail docs");

        // The forwarded payload is tenant-scoped and filters history.
        let forwarded = seen.lock().unwrap()[0].clone();
        assert_eq!(forwarded["tenant_id"], key_tenant.as_str());
        assert_eq!(forwarded["message"], "How do I verify a domain?");
        let history = forwarded["history"].as_array().expect("history");
        assert_eq!(history.len(), 2, "bogus role and empty content dropped");
        assert_eq!(history[0]["role"], "user");
        let context = &forwarded["account_context"];
        assert!(context["plan"].is_string());
        assert!(context["emails_sent_this_month"].is_i64());
    }

    #[tokio::test]
    async fn chat_rate_limit_caps_per_user() {
        if std::env::var("TEST_REDIS_URL")
            .ok()
            .filter(|v| !v.trim().is_empty())
            .is_none()
        {
            eprintln!("skipping: TEST_REDIS_URL unset");
            return;
        }
        let Some(pool) = crate::test_db::canonical_pool("ai_chat_rate").await else {
            return;
        };
        let (ai_url, _seen) = start_mock_ai().await;
        let (env, _tenant) =
            AdvEnv::tenant_with_config(pool, &["ai:read"], ai_config(&ai_url)).await;

        let mut hit_limit = false;
        for i in 0..21 {
            let (status, body) = env
                .post(
                    "/v1/ai/chat",
                    &serde_json::json!({ "message": format!("q{i}") }).to_string(),
                )
                .await;
            if status == StatusCode::TOO_MANY_REQUESTS {
                hit_limit = true;
                assert!(body["error"]["message"]
                    .as_str()
                    .unwrap_or_default()
                    .contains("rate limit"));
                break;
            }
            assert_eq!(status, StatusCode::OK, "request {i}: {body}");
        }
        assert!(hit_limit, "the 21st chat in a minute must be refused");
    }

    #[tokio::test]
    async fn chat_history_proxies_the_service() {
        let Some(pool) = crate::test_db::canonical_pool("ai_chat_history").await else {
            return;
        };
        let (ai_url, _seen) = start_mock_ai().await;
        let (env, _tenant) =
            AdvEnv::tenant_with_config(pool.clone(), &["ai:read"], ai_config(&ai_url)).await;
        let (status, body) = env.get("/v1/ai/chat/history").await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert!(body["conversations"].is_array());

        // Unconfigured / unreachable service arms.
        let (unconfigured, _t) =
            AdvEnv::tenant_with_config(pool.clone(), &["ai:read"], ai_config("")).await;
        let (status, _body) = unconfigured.get("/v1/ai/chat/history").await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        let (dead, _t2) =
            AdvEnv::tenant_with_config(pool, &["ai:read"], ai_config("http://127.0.0.1:1")).await;
        let (status, _body) = dead.get("/v1/ai/chat/history").await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    }
}
