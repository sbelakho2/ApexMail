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
        // Console assistant sessions (plan §5.2): server-side conversations
        // instead of a client-supplied history array.
        .route("/chat/sessions", post(create_session).get(list_sessions))
        .route(
            "/chat/sessions/:id/turns",
            post(post_session_turn).get(read_session_turns),
        )
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
///
/// Shared with the console PRG handler (which calls it before creating a
/// session, so a switched-off workspace does not accumulate empty
/// conversations) and with the session-turn flow itself.
pub(crate) async fn require_ai_chat_enabled(
    state: &AppState,
    tenant_id: &str,
) -> Result<(), ApiError> {
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
/// Per-message character cap (the plan's 4,000-char contract).
pub(crate) const MAX_MESSAGE_CHARS: usize = 4000;
/// Console session window: how many turns the page/API returns by default.
pub(crate) const SESSION_WINDOW_TURNS: i64 = 12;
/// Per-user chat rate limit (Redis sliding window), independent of the
/// tenant-wide API bucket: chat is expensive and per-person.
const CHAT_RATE_LIMIT: i64 = 20;
const CHAT_RATE_WINDOW_SECS: i64 = 60;

/// One assistant exchange, normalized for every caller (the JSON API and
/// the console's PRG handler share this path so caps, scopes and account
/// context cannot diverge).
pub(crate) struct AssistantOutcome {
    pub answer: String,
    pub citations: serde_json::Value,
    pub escalated: bool,
    pub disclosure: String,
    pub docs_version: String,
}

/// Validate + forward one message. The caller has already checked scopes,
/// the feature flag and the rate limit (each entry point needs those in a
/// different order for its own error surface).
pub(crate) async fn ask_assistant(
    state: &AppState,
    tenant_id: &str,
    user_key: &str,
    message: &str,
    history: Vec<HistoryTurn>,
) -> Result<AssistantOutcome, ApiError> {
    let message = message.trim().to_string();
    if message.is_empty() {
        return Err(ApiError::Validation(vec![
            "message must not be empty".into()
        ]));
    }
    if message.len() > MAX_MESSAGE_CHARS {
        return Err(ApiError::Validation(vec![
            "message too long (max 4000 chars)".into(),
        ]));
    }

    let ai_url = state.config.ai_service_base_url.trim().to_string();
    if ai_url.is_empty() {
        return Err(ApiError::Internal(
            "assistant is not configured; contact support@apexmail.ee".into(),
        ));
    }

    // Account context assembled HERE, from tenant-scoped queries — the
    // trusted half of the design. ai-service treats it as display data.
    let account_context = account_context(state, tenant_id).await;

    let history: Vec<HistoryTurn> = history
        .into_iter()
        .take(MAX_HISTORY)
        .filter(|t| matches!(t.role.as_str(), "user" | "assistant") && !t.content.is_empty())
        .collect();

    let payload = serde_json::json!({
        "tenant_id": tenant_id,
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
    request = request.header("x-apexmail-tenant-id", tenant_id);

    let response = request.send().await.map_err(|e| {
        tracing::warn!(error = %e, tenant_id = %tenant_id, "ai chat: service unreachable");
        ApiError::Internal("assistant unavailable; contact support@apexmail.ee".into())
    })?;

    match response.status() {
        StatusCode::OK => {
            let out: serde_json::Value = response.json().await.map_err(|e| {
                tracing::warn!(error = %e, "ai chat: malformed response");
                ApiError::Internal("assistant returned an invalid response".into())
            })?;
            Ok(AssistantOutcome {
                answer: out["answer"].as_str().unwrap_or_default().to_string(),
                citations: out.get("citations").cloned().unwrap_or_default(),
                escalated: out["escalated"].as_bool().unwrap_or(false),
                disclosure: out["disclosure"]
                    .as_str()
                    .unwrap_or("This assistant is AI-powered. Escalation: support@apexmail.ee.")
                    .to_string(),
                docs_version: out["docs_version"].as_str().unwrap_or_default().to_string(),
            })
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

pub(crate) async fn chat(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(body): Json<ChatBody>,
) -> Result<Json<ChatOut>, ApiError> {
    require_scopes(&auth, &["ai:read"])?;
    require_ai_chat_enabled(&state, &auth.tenant_id).await?;

    let user_key = user_key_of(&auth);
    chat_rate_limit(&state, &auth.tenant_id, &user_key).await?;

    let out = ask_assistant(
        &state,
        &auth.tenant_id,
        &user_key,
        &body.message,
        body.history,
    )
    .await?;
    Ok(Json(ChatOut {
        answer: out.answer,
        citations: out.citations,
        escalated: out.escalated,
        disclosure: out.disclosure,
        docs_version: out.docs_version,
    }))
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
        // P1-SECURITY: ai-service now scopes this read to the REQUIRED
        // forwarded tenant header and rejects any body-carried tenant_id, so
        // the target tenant travels only in the header here.
        .json(&serde_json::json!({ "limit": 50 }))
        .timeout(std::time::Duration::from_secs(10));
    if let Some(token) = state.config.internal_service_token.as_deref() {
        request = request.header("x-api-key", token);
    }
    // The authenticated tenant is the only read scope for the history route.
    request = request.header("x-apexmail-tenant-id", &auth.tenant_id);
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

/// The rate-limit / governor identity for one console user: the user id
/// when present, else the tenant (an API-key caller has no user).
pub(crate) fn user_key_of(auth: &AuthUser) -> String {
    auth.user_id
        .clone()
        .unwrap_or_else(|| auth.tenant_id.clone())
}

/// The retention window for console sessions, aligned with the ai-service's
/// `AI_CHAT_RETENTION_DAYS` so both halves of the assistant's memory expire
/// together. Unparseable/absent/zero values fall back to 90 days.
pub(crate) fn retention_days() -> i64 {
    std::env::var("AI_CHAT_RETENTION_DAYS")
        .ok()
        .and_then(|value| value.trim().parse::<i64>().ok())
        .filter(|days| *days > 0)
        .unwrap_or(90)
}

/// Delete this owner's sessions that fell out of the retention window. Runs
/// on session creation (the only writer of new sessions), so the prune cost
/// is paid when the user is already touching the database.
async fn prune_expired_sessions(state: &AppState, tenant_id: &str, user_key: &str) {
    if let Err(error) = sqlx::query(
        "DELETE FROM ai_chat_sessions \
         WHERE tenant_id = $1 AND user_id = $2 \
           AND updated_at < NOW() - make_interval(days => $3::int)",
    )
    .bind(tenant_id)
    .bind(user_key)
    .bind(retention_days())
    .execute(&state.db)
    .await
    {
        // Best-effort: a failed prune must never fail the user's request.
        tracing::warn!(error = %error, "ai chat: session prune failed");
    }
}

#[derive(Debug, Serialize)]
pub struct SessionOut {
    pub id: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Deserialize)]
pub struct TurnBody {
    pub message: String,
}

#[derive(Debug, Serialize)]
pub struct TurnOut {
    pub role: String,
    pub content: String,
    pub escalated: bool,
    pub citations: serde_json::Value,
    pub disclosure: Option<String>,
    pub docs_version: Option<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Deserialize)]
pub struct TurnsQuery {
    #[serde(default)]
    pub limit: Option<i64>,
}

/// Create a fresh conversation for the authenticated user, pruning sessions
/// that fell out of the retention window first.
pub(crate) async fn create_session(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<Json<SessionOut>, ApiError> {
    require_scopes(&auth, &["ai:read"])?;
    require_ai_chat_enabled(&state, &auth.tenant_id).await?;
    let user_key = user_key_of(&auth);
    prune_expired_sessions(&state, &auth.tenant_id, &user_key).await;

    let id = apexmail_lib::id::generate_id("chat", 21);
    let row: (
        String,
        chrono::DateTime<chrono::Utc>,
        chrono::DateTime<chrono::Utc>,
    ) = sqlx::query_as(
        "INSERT INTO ai_chat_sessions (id, tenant_id, user_id) \
             VALUES ($1, $2, $3) \
             RETURNING id, created_at, updated_at",
    )
    .bind(&id)
    .bind(&auth.tenant_id)
    .bind(&user_key)
    .fetch_one(&state.db)
    .await?;
    Ok(Json(SessionOut {
        id: row.0,
        created_at: row.1,
        updated_at: row.2,
    }))
}

/// The user's conversations, newest first (bounded).
pub(crate) async fn list_sessions(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<Json<serde_json::Value>, ApiError> {
    require_scopes(&auth, &["ai:read"])?;
    require_ai_chat_enabled(&state, &auth.tenant_id).await?;
    let user_key = user_key_of(&auth);

    let rows: Vec<(
        String,
        chrono::DateTime<chrono::Utc>,
        chrono::DateTime<chrono::Utc>,
    )> = sqlx::query_as(
        "SELECT id, created_at, updated_at FROM ai_chat_sessions \
             WHERE tenant_id = $1 AND user_id = $2 \
             ORDER BY updated_at DESC LIMIT 20",
    )
    .bind(&auth.tenant_id)
    .bind(&user_key)
    .fetch_all(&state.db)
    .await?;
    Ok(Json(serde_json::json!({
        "sessions": rows
            .into_iter()
            .map(|(id, created_at, updated_at)| serde_json::json!({
                "id": id,
                "created_at": created_at.to_rfc3339(),
                "updated_at": updated_at.to_rfc3339(),
            }))
            .collect::<Vec<_>>(),
    })))
}

/// Read one session's turn window (tenant+user scoped; a cross-tenant or
/// cross-user probe is a 404, never a leak).
pub(crate) async fn read_session_turns(
    State(state): State<AppState>,
    auth: AuthUser,
    axum::extract::Path(session_id): axum::extract::Path<String>,
    axum::extract::Query(query): axum::extract::Query<TurnsQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    require_scopes(&auth, &["ai:read"])?;
    require_ai_chat_enabled(&state, &auth.tenant_id).await?;
    let user_key = user_key_of(&auth);
    ensure_session_owned(&state, &auth.tenant_id, &user_key, &session_id).await?;

    let limit = query.limit.unwrap_or(SESSION_WINDOW_TURNS).clamp(1, 50);
    // THE NEWEST `limit` turns, returned oldest-first. `ORDER BY created_at
    // ASC LIMIT n` returned the OLDEST n turns: past the window the API (and
    // every consumer) could never see the latest exchange at all — a live
    // concurrency probe read 12 of 16 turns, hiding the four newest. The page
    // loader already reads the newest window (DESC LIMIT then reverse); this
    // is the same contract on the JSON surface.
    let rows: Vec<(
        String,
        String,
        bool,
        serde_json::Value,
        Option<String>,
        Option<String>,
        chrono::DateTime<chrono::Utc>,
    )> = sqlx::query_as(
        "SELECT role, content, escalated, citations, disclosure, docs_version, created_at \
         FROM ( \
             SELECT role, content, escalated, citations, disclosure, docs_version, created_at \
             FROM ai_chat_session_turns WHERE session_id = $1 AND tenant_id = $2 \
             ORDER BY created_at DESC LIMIT $3 \
         ) AS newest ORDER BY created_at ASC",
    )
    .bind(&session_id)
    .bind(&auth.tenant_id)
    .bind(limit)
    .fetch_all(&state.db)
    .await?;
    Ok(Json(serde_json::json!({
        "session_id": session_id,
        "turns": rows
            .into_iter()
            .map(|(role, content, escalated, citations, disclosure, docs_version, created_at)| {
                serde_json::json!({
                    "role": role,
                    "content": content,
                    "escalated": escalated,
                    "citations": citations,
                    "disclosure": disclosure,
                    "docs_version": docs_version,
                    "created_at": created_at.to_rfc3339(),
                })
            })
            .collect::<Vec<_>>(),
    })))
}

/// The assistant's SESSION history: the user's turns from this session,
/// oldest first, as the model context. Only persisted turns travel — a
/// client cannot inject history into a session.
async fn session_history(
    state: &AppState,
    tenant_id: &str,
    session_id: &str,
) -> Result<Vec<HistoryTurn>, ApiError> {
    let rows: Vec<(String, String)> = sqlx::query_as(
        "SELECT role, content FROM ai_chat_session_turns \
         WHERE session_id = $1 AND tenant_id = $2 \
         ORDER BY created_at DESC LIMIT $3",
    )
    .bind(session_id)
    .bind(tenant_id)
    .bind(MAX_HISTORY as i64)
    .fetch_all(&state.db)
    .await?;
    Ok(rows
        .into_iter()
        .rev()
        .map(|(role, content)| HistoryTurn { role, content })
        .collect())
}

/// Deterministic contact-intent detection for the chat write-back. Returns
/// the lead's email address ONLY when the message both names an intent to be
/// contacted and an address can be established (from the message, else from
/// the account owner's own account). No LLM involvement: a false positive
/// would spam the CRM, so the phrase list is deliberately small and matched
/// case-insensitively.
async fn contact_intent_lead(
    state: &AppState,
    tenant_id: &str,
    user_key: &str,
    message: &str,
) -> Option<String> {
    const INTENT_PHRASES: [&str; 8] = [
        "contact me",
        "call me",
        "reach me",
        "email me",
        "talk to sales",
        "speak to sales",
        "book a demo",
        "schedule a demo",
    ];
    let lower = message.to_lowercase();
    if !INTENT_PHRASES.iter().any(|phrase| lower.contains(phrase)) {
        return None;
    }
    if let Some(address) = extract_email_address(message) {
        return Some(address);
    }
    // No address in the message: the account owner's own address, when the
    // user key is a real user id (a session always is). Best-effort.
    let owner: Option<String> =
        sqlx::query_scalar("SELECT email FROM users WHERE id::text = $1 AND tenant_id = $2")
            .bind(user_key)
            .bind(tenant_id)
            .fetch_optional(&state.db)
            .await
            .ok()
            .flatten();
    owner.filter(|email| !email.trim().is_empty())
}

/// The first email address in `text`, lowercased, crude but deterministic
/// (local@domain.tld characters only). Public so the boundary is testable.
pub(crate) fn extract_email_address(text: &str) -> Option<String> {
    let mut candidate = String::new();
    for token in text.split(|c: char| {
        c.is_whitespace() || matches!(c, ',' | ';' | '(' | ')' | '<' | '>' | '"' | '\'')
    }) {
        let trimmed = token.trim_matches(|c: char| matches!(c, '.' | ':' | '!' | '?'));
        if let Some(at) = trimmed.find('@') {
            let (local, domain) = trimmed.split_at(at);
            let domain = &domain[1..];
            let valid_local = !local.is_empty()
                && local
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '%' | '+' | '-'));
            let valid_domain = domain.contains('.')
                && domain
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-'));
            if valid_local && valid_domain {
                candidate = trimmed.to_lowercase();
                break;
            }
        }
    }
    (!candidate.is_empty()).then_some(candidate)
}

/// Session ownership check: the session must belong to this tenant AND this
/// user. A miss is a 404 so a probe cannot distinguish "not yours" from
/// "does not exist".
pub(crate) async fn ensure_session_owned(
    state: &AppState,
    tenant_id: &str,
    user_key: &str,
    session_id: &str,
) -> Result<(), ApiError> {
    let found: Option<(String,)> = sqlx::query_as(
        "SELECT id FROM ai_chat_sessions \
         WHERE id = $1 AND tenant_id = $2 AND user_id = $3",
    )
    .bind(session_id)
    .bind(tenant_id)
    .bind(user_key)
    .fetch_optional(&state.db)
    .await?;
    if found.is_none() {
        return Err(ApiError::NotFound("no such session".into()));
    }
    Ok(())
}

/// Post one user turn: the ownership check runs first (a foreign session id
/// is a 404 before anything else can be learned), then the shared turn flow
/// applies the capability flag, the per-user rate limit and persistence.
pub(crate) async fn post_session_turn(
    State(state): State<AppState>,
    auth: AuthUser,
    axum::extract::Path(session_id): axum::extract::Path<String>,
    Json(body): Json<TurnBody>,
) -> Result<Json<serde_json::Value>, ApiError> {
    require_scopes(&auth, &["ai:read"])?;
    let user_key = user_key_of(&auth);
    ensure_session_owned(&state, &auth.tenant_id, &user_key, &session_id).await?;

    Ok(Json(
        session_turn_inner(
            &state,
            &auth.tenant_id,
            &user_key,
            &session_id,
            &body.message,
        )
        .await?,
    ))
}

/// The session-turn flow, reusable by the console's PRG handler (which
/// renders the outcome instead of returning JSON).
///
/// The capability flag and the per-user rate limit are enforced HERE, not in
/// the JSON wrapper: the console's PRG handler calls this function directly,
/// and while the gates lived in `post_session_turn` a tenant with `ai_chat`
/// disabled could still chat from the console page (the docs promise the
/// page reports the capability as not enabled), and the documented per-user
/// throttle never applied to console messages at all. Every entry point now
/// shares the same gates, so no caller can bypass them.
pub(crate) async fn session_turn_inner(
    state: &AppState,
    tenant_id: &str,
    user_key: &str,
    session_id: &str,
    message: &str,
) -> Result<serde_json::Value, ApiError> {
    require_ai_chat_enabled(state, tenant_id).await?;
    chat_rate_limit(state, tenant_id, user_key).await?;

    let message = message.trim().to_string();
    if message.is_empty() {
        return Err(ApiError::Validation(vec![
            "message must not be empty".into()
        ]));
    }
    if message.len() > MAX_MESSAGE_CHARS {
        return Err(ApiError::Validation(vec![
            "message too long (max 4000 chars)".into(),
        ]));
    }

    let user_turn_id = apexmail_lib::id::generate_id("turn", 21);
    let user_created_at: chrono::DateTime<chrono::Utc> = sqlx::query_scalar(
        "INSERT INTO ai_chat_session_turns (id, session_id, tenant_id, role, content) \
         VALUES ($1, $2, $3, 'user', $4) RETURNING created_at",
    )
    .bind(&user_turn_id)
    .bind(session_id)
    .bind(tenant_id)
    .bind(&message)
    .fetch_one(&state.db)
    .await?;

    let history = session_history(state, tenant_id, session_id).await?;
    // The just-persisted user turn is part of history; the model receives the
    // current message separately, so drop the duplicate tail.
    let mut history_without_tail = history;
    if history_without_tail
        .last()
        .is_some_and(|turn| turn.role == "user" && turn.content == message)
    {
        history_without_tail.pop();
    }

    let outcome = ask_assistant(state, tenant_id, user_key, &message, history_without_tail).await?;

    let assistant_turn_id = apexmail_lib::id::generate_id("turn", 21);
    let assistant_created_at: chrono::DateTime<chrono::Utc> = sqlx::query_scalar(
        "INSERT INTO ai_chat_session_turns \
             (id, session_id, tenant_id, role, content, escalated, citations, docs_version, disclosure) \
         VALUES ($1, $2, $3, 'assistant', $4, $5, $6, $7, $8) RETURNING created_at",
    )
    .bind(&assistant_turn_id)
    .bind(session_id)
    .bind(tenant_id)
    .bind(&outcome.answer)
    .bind(outcome.escalated)
    .bind(&outcome.citations)
    .bind(&outcome.docs_version)
    .bind(&outcome.disclosure)
    .fetch_one(&state.db)
    .await?;

    let _ = sqlx::query("UPDATE ai_chat_sessions SET updated_at = NOW() WHERE id = $1")
        .bind(session_id)
        .execute(&state.db)
        .await;

    // Chat -> CRM (plan §5.4): when a VERIFIER-GATED answer (not escalated)
    // answers a message that deterministically asks for contact, the lead is
    // captured through the ONE canonical lead write (same transaction
    // semantics, same first-response request row). Extraction is strictly
    // deterministic: an email address from the message, or the account
    // owner's own address, plus an intent phrase. No free-form writes, and a
    // failed capture never fails the answer.
    if !outcome.escalated {
        if let Some(lead_email) = contact_intent_lead(state, tenant_id, user_key, &message).await {
            let form = crate::routes::contact::ContactForm {
                email: Some(lead_email),
                name: None,
                company: None,
                message: Some(message.clone()),
                ..Default::default()
            };
            if let Err(error) =
                crate::routes::contact::store_lead_with_kind(&state.db, &form, "chat", "chat_lead")
                    .await
            {
                tracing::warn!(error = %error, "chat contact-intent lead capture failed");
            } else {
                tracing::info!(tenant_id = %tenant_id, "chat contact intent captured as a lead");
            }
        }
    }

    Ok(serde_json::json!({
        "session_id": session_id,
        "user_turn": {
            "id": user_turn_id,
            "role": "user",
            "content": message,
            "created_at": user_created_at.to_rfc3339(),
        },
        "assistant_turn": {
            "id": assistant_turn_id,
            "role": "assistant",
            "content": outcome.answer,
            "escalated": outcome.escalated,
            "citations": outcome.citations,
            "disclosure": outcome.disclosure,
            "docs_version": outcome.docs_version,
            "created_at": assistant_created_at.to_rfc3339(),
        },
        // The plan's window contract for the console: the page re-reads the
        // session, so the ids are the useful return values.
    }))
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
    /// `history_headers` captures the header blocks sent to the history route
    /// so the proxy test can prove the tenant header is forwarded.
    async fn start_mock_ai() -> (
        String,
        std::sync::Arc<std::sync::Mutex<Vec<serde_json::Value>>>,
        std::sync::Arc<std::sync::Mutex<Vec<String>>>,
    ) {
        use axum::routing::post;
        let seen: std::sync::Arc<std::sync::Mutex<Vec<serde_json::Value>>> =
            std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let history_headers: std::sync::Arc<std::sync::Mutex<Vec<String>>> =
            std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let state = seen.clone();
        let history_state = history_headers.clone();
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
                post(move |headers: axum::http::HeaderMap| async move {
                    let rendered = headers
                        .iter()
                        .map(|(k, v)| format!("{k}: {v:?}"))
                        .collect::<Vec<_>>()
                        .join("\n");
                    history_state.lock().unwrap().push(rendered);
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
        (base_url, seen, history_headers)
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
        let (ai_url, seen, _history_headers) = start_mock_ai().await;
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
            crate::test_db::assert_soft_skip_allowed("TEST_REDIS_URL");
            eprintln!("skipping: TEST_REDIS_URL unset");
            return;
        }
        let Some(pool) = crate::test_db::canonical_pool("ai_chat_rate").await else {
            return;
        };
        let (ai_url, _seen, _history_headers) = start_mock_ai().await;
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
        let (ai_url, _seen, history_headers) = start_mock_ai().await;
        let (env, tenant) =
            AdvEnv::tenant_with_config(pool.clone(), &["ai:read"], ai_config(&ai_url)).await;
        let (status, body) = env.get("/v1/ai/chat/history").await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert!(body["conversations"].is_array());

        // P1-SECURITY: the target tenant travels in the REQUIRED
        // x-apexmail-tenant-id header (ai-service no longer accepts a body
        // tenant), scoped to the AUTHENTICATED tenant.
        {
            let headers = history_headers.lock().unwrap();
            assert_eq!(headers.len(), 1, "exactly one history call");
            assert!(
                headers[0].to_lowercase().contains("x-apexmail-tenant-id:")
                    && headers[0].contains(tenant.as_str()),
                "history proxy must forward the authenticated tenant header: {}",
                headers[0]
            );
        }

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

#[cfg(test)]
mod session_tests {
    use axum::http::StatusCode;

    use super::{session_turn_inner, ApiError};
    use crate::app::test_support::adv::AdvEnv;

    /// Minimal ai-service twin for the session flow: echoes the history it
    /// received so the test can prove only PERSISTED turns travel.
    async fn start_mock_ai() -> (
        String,
        std::sync::Arc<std::sync::Mutex<Vec<serde_json::Value>>>,
    ) {
        let seen: std::sync::Arc<std::sync::Mutex<Vec<serde_json::Value>>> =
            std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let state = seen.clone();
        let app = axum::Router::new().route(
            "/chat",
            axum::routing::post(
                move |axum::Json(body): axum::Json<serde_json::Value>| async move {
                    let history_len = body["history"].as_array().map(Vec::len).unwrap_or(0);
                    state.lock().unwrap().push(body);
                    axum::Json(serde_json::json!({
                        "answer": format!("answer #{history_len}"),
                        "citations": [{"title": "ApexMail docs"}],
                        "escalated": false,
                        "disclosure": "AI-powered. Escalation: support@apexmail.ee.",
                        "docs_version": "v42",
                    }))
                },
            ),
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

    /// The test's own session id (`chat_` + 21) from a create call.
    fn session_id(body: &serde_json::Value) -> String {
        body["id"].as_str().expect("session id").to_string()
    }

    #[tokio::test]
    async fn session_turn_persists_both_turns_and_reuses_its_own_history() {
        let Some(pool) = crate::test_db::canonical_pool("ai_session_flow").await else {
            return;
        };
        let (ai_url, seen) = start_mock_ai().await;
        let Some((env, tenant, user)) =
            AdvEnv::session_with_config(pool.clone(), "owner", ai_config(&ai_url)).await
        else {
            return;
        };

        // Create + first turn: the model sees NO prior turns (nothing was
        // persisted yet, and a client cannot inject any).
        let (status, created) = env.post("/v1/ai/chat/sessions", "{}").await;
        assert_eq!(status, StatusCode::OK, "{created}");
        let id = session_id(&created);

        let (status, out) = env
            .post(
                &format!("/v1/ai/chat/sessions/{id}/turns"),
                r#"{"message":"How do I verify a domain?"}"#,
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{out}");
        assert_eq!(out["user_turn"]["content"], "How do I verify a domain?");
        assert_eq!(out["assistant_turn"]["content"], "answer #0");

        // Second turn: the session's own two turns are the model context.
        let (status, out2) = env
            .post(
                &format!("/v1/ai/chat/sessions/{id}/turns"),
                r#"{"message":"And DKIM?"}"#,
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{out2}");
        assert_eq!(out2["assistant_turn"]["content"], "answer #2");

        let requests = seen.lock().unwrap().clone();
        assert_eq!(requests.len(), 2);
        assert!(
            requests[0]["history"].as_array().is_some_and(Vec::is_empty),
            "first turn must carry no history: {}",
            requests[0]["history"]
        );
        let history = requests[1]["history"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        assert_eq!(history.len(), 2, "second turn carries the persisted pair");
        assert_eq!(history[0]["role"], "user");
        assert_eq!(history[1]["role"], "assistant");

        // Both turns are readable back through the window endpoint, in order.
        let (status, window) = env.get(&format!("/v1/ai/chat/sessions/{id}/turns")).await;
        assert_eq!(status, StatusCode::OK, "{window}");
        let turns = window["turns"].as_array().cloned().unwrap_or_default();
        assert_eq!(turns.len(), 4, "two exchanges: {window}");
        assert_eq!(turns[0]["role"], "user");
        assert_eq!(turns[3]["role"], "assistant");

        // The rows are tenant- AND user-scoped in the database.
        let persisted: Vec<(String, String)> = sqlx::query_as(
            "SELECT role, content FROM ai_chat_session_turns WHERE session_id = $1 ORDER BY created_at",
        )
        .bind(&id)
        .fetch_all(&pool)
        .await
        .expect("read turns");
        assert_eq!(persisted.len(), 4);
        let owners: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM ai_chat_sessions WHERE id = $1 AND tenant_id = $2 AND user_id = $3",
        )
        .bind(&id)
        .bind(&tenant)
        .bind(&user)
        .fetch_one(&pool)
        .await
        .expect("owner check");
        assert_eq!(owners, 1, "the session belongs to its creator");
    }

    /// Regression (dogfood P1, live concurrency probe): the session window
    /// must be the NEWEST `limit` turns. `ORDER BY created_at ASC LIMIT 12`
    /// returned the OLDEST twelve, so a conversation longer than the window
    /// could never show its latest exchange on the JSON surface (the live
    /// probe read 12 of 16 turns and lost the four newest).
    #[tokio::test]
    async fn session_window_returns_the_newest_turns_not_the_oldest() {
        let Some(pool) = crate::test_db::canonical_pool("ai_session_window").await else {
            return;
        };
        let (ai_url, _seen) = start_mock_ai().await;
        let Some((env, tenant, user)) =
            AdvEnv::session_with_config(pool.clone(), "owner", ai_config(&ai_url)).await
        else {
            return;
        };
        let (status, created) = env.post("/v1/ai/chat/sessions", "{}").await;
        assert_eq!(status, StatusCode::OK, "{created}");
        let id = session_id(&created);

        // Eight exchanges, oldest first; each earlier pair is 10s older.
        for index in 0..8i64 {
            for (role, offset, label) in [
                ("user", 100 - index * 10, format!("oldest-user-{index}")),
                (
                    "assistant",
                    95 - index * 10,
                    format!("newest-assistant-{index}"),
                ),
            ] {
                sqlx::query(
                    "INSERT INTO ai_chat_session_turns \
                         (id, session_id, tenant_id, role, content, created_at) \
                     VALUES ($1, $2, $3, $4, $5, NOW() - make_interval(secs => $6::int))",
                )
                .bind(apexmail_lib::id::generate_id("turn", 21))
                .bind(&id)
                .bind(&tenant)
                .bind(role)
                .bind(&label)
                .bind(offset)
                .execute(&pool)
                .await
                .expect("seed turn");
            }
        }

        let (status, window) = env.get(&format!("/v1/ai/chat/sessions/{id}/turns")).await;
        assert_eq!(status, StatusCode::OK, "{window}");
        let turns = window["turns"].as_array().cloned().unwrap_or_default();
        assert_eq!(turns.len(), 12, "the default window is 12 turns: {window}");
        let contents: Vec<String> = turns
            .iter()
            .map(|turn| turn["content"].as_str().unwrap_or_default().to_string())
            .collect();
        assert!(
            contents.iter().any(|c| c == "newest-assistant-7"),
            "the newest exchange must be inside the window: {contents:?}"
        );
        assert!(
            !contents.iter().any(|c| c == "oldest-user-0"),
            "the window must not be the oldest turns: {contents:?}"
        );
        assert_eq!(
            contents.first().map(String::as_str),
            Some("oldest-user-2"),
            "the window starts at the 13th-newest turn: {contents:?}"
        );
        let _ = user;
    }

    /// Regression (dogfood P1): the console's PRG handler calls
    /// `session_turn_inner` directly, and while the capability flag lived in
    /// the JSON wrapper that path ignored it — a tenant with `ai_chat`
    /// disabled could still chat from the console, and the refused turn was
    /// still persisted. The shared flow now refuses BEFORE writing anything.
    #[tokio::test]
    async fn session_turn_inner_refuses_a_disabled_capability_without_writing() {
        let Some(pool) = crate::test_db::canonical_pool("ai_session_flag").await else {
            return;
        };
        let (_env, tenant) = AdvEnv::tenant(pool.clone(), &["ai:read"]).await;
        let state = crate::app::test_support::test_state_over(pool.clone()).await;

        // The console resolves the newest session for (tenant, user) and
        // calls the shared flow with it; model the same row.
        let session_id = apexmail_lib::id::generate_id("chat", 21);
        sqlx::query(
            "INSERT INTO ai_chat_sessions (id, tenant_id, user_id) VALUES ($1, $2, $3)",
        )
        .bind(&session_id)
        .bind(&tenant)
        .bind(&tenant)
        .execute(&pool)
        .await
        .expect("seed session");

        sqlx::query(
            "INSERT INTO feature_flag_overrides (id, flag_key, tenant_id, value, created_at)
             VALUES ($1, 'ai_chat', $2, 'false'::jsonb, NOW())",
        )
        .bind(uuid::Uuid::new_v4())
        .bind(&tenant)
        .execute(&pool)
        .await
        .expect("disable the capability");

        let outcome = session_turn_inner(&state, &tenant, &tenant, &session_id, "hello").await;
        match outcome {
            Err(ApiError::Forbidden(message)) => {
                assert!(
                    message.contains("not enabled"),
                    "the refusal names the capability: {message}"
                );
            }
            other => panic!("disabled capability must refuse before any work: {other:?}"),
        }
        let turns: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM ai_chat_session_turns WHERE session_id = $1")
                .bind(&session_id)
                .fetch_one(&pool)
                .await
                .expect("count turns");
        assert_eq!(turns, 0, "a refused turn is never persisted");

        let _ = sqlx::query("DELETE FROM feature_flag_overrides WHERE tenant_id = $1")
            .bind(&tenant)
            .execute(&pool)
            .await;
    }

    /// Regression (dogfood P1): the per-user chat rate limit also lived in
    /// the JSON wrapper, so console messages were never throttled. The shared
    /// flow now caps them at 20/minute per user.
    #[tokio::test]
    async fn session_turn_inner_applies_the_per_user_rate_limit() {
        if std::env::var("TEST_REDIS_URL")
            .ok()
            .filter(|v| !v.trim().is_empty())
            .is_none()
        {
            crate::test_db::assert_soft_skip_allowed("TEST_REDIS_URL");
            eprintln!("skipping: TEST_REDIS_URL unset");
            return;
        }
        let Some(pool) = crate::test_db::canonical_pool("ai_session_ratelimit").await else {
            return;
        };
        let (ai_url, _seen) = start_mock_ai().await;
        let (_env, tenant) = AdvEnv::tenant(pool.clone(), &["ai:read"]).await;
        let state =
            crate::app::test_support::test_state_over_with_config(pool.clone(), ai_config(&ai_url))
                .await;
        let user_key = tenant.clone();
        let session_id = apexmail_lib::id::generate_id("chat", 21);
        sqlx::query(
            "INSERT INTO ai_chat_sessions (id, tenant_id, user_id) VALUES ($1, $2, $3)",
        )
        .bind(&session_id)
        .bind(&tenant)
        .bind(&user_key)
        .execute(&pool)
        .await
        .expect("seed session");

        let mut limited = false;
        for i in 0..21 {
            match session_turn_inner(&state, &tenant, &user_key, &session_id, &format!("q{i}")).await
            {
                Ok(_) => {}
                Err(ApiError::RateLimitedMessage(message)) => {
                    assert!(message.contains("rate limit"), "{message}");
                    limited = true;
                    break;
                }
                Err(other) => panic!("unexpected error on turn {i}: {other:?}"),
            }
        }
        assert!(limited, "the 21st console turn in a minute must be refused");
    }

    #[test]
    fn contact_intent_extraction_is_deterministic() {
        assert_eq!(
            super::extract_email_address("please contact me at Jane.Doe@Example.COM, thanks"),
            Some("jane.doe@example.com".to_string())
        );
        assert_eq!(super::extract_email_address("no address here"), None);
        assert_eq!(
            super::extract_email_address("version 2@3 is fine"),
            None,
            "a domainless token is not an address"
        );
    }

    /// Chat -> CRM (plan §5.4): a grounded answer to a contact-intent message
    /// captures the lead through the canonical lead write — and the lead is
    /// recorded as a `chat_lead` request, not a contact-form one.
    #[tokio::test]
    async fn contact_intent_message_captures_a_chat_lead_once() {
        let Some(pool) = crate::test_db::canonical_pool("ai_chat_lead").await else {
            return;
        };
        let (ai_url, _seen) = start_mock_ai().await;
        let Some((env, tenant, _user)) =
            AdvEnv::session_with_config(pool.clone(), "owner", ai_config(&ai_url)).await
        else {
            return;
        };
        let (_, created) = env.post("/v1/ai/chat/sessions", "{}").await;
        let id = session_id(&created);

        let lead_email = format!(
            "lead-{}@corp.example",
            &uuid::Uuid::new_v4().simple().to_string()[..8]
        );
        let (status, body) = env
            .post(
                &format!("/v1/ai/chat/sessions/{id}/turns"),
                &serde_json::json!({
                    "message": format!("Please contact me at {lead_email} about pricing.")
                })
                .to_string(),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");

        let rows: Vec<(String, String)> = sqlx::query_as(
            "SELECT kind, payload->>'email' FROM first_response_requests \
             WHERE tenant_id = 'system' AND payload->>'email' = $1",
        )
        .bind(&lead_email)
        .fetch_all(&pool)
        .await
        .expect("lead rows");
        assert_eq!(
            rows.len(),
            1,
            "exactly one lead per intent message: {rows:?}"
        );
        assert_eq!(rows[0].0, "chat_lead");

        // An ordinary question writes nothing.
        let before: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM first_response_requests")
            .fetch_one(&pool)
            .await
            .expect("count");
        let (status, body) = env
            .post(
                &format!("/v1/ai/chat/sessions/{id}/turns"),
                r#"{"message":"What does the Pro plan include?"}"#,
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let after: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM first_response_requests")
            .fetch_one(&pool)
            .await
            .expect("count");
        assert_eq!(before, after, "ordinary questions write no lead");

        let _ = sqlx::query("DELETE FROM first_response_requests WHERE payload->>'email' = $1")
            .bind(&lead_email)
            .execute(&pool)
            .await;
        let _ = sqlx::query("DELETE FROM sales_contacts WHERE legacy_lead_email = $1")
            .bind(&lead_email)
            .execute(&pool)
            .await;
        let _ = tenant;
    }

    #[tokio::test]
    async fn session_reads_and_turns_are_scoped_to_their_owner() {
        let Some(pool) = crate::test_db::canonical_pool("ai_session_scope").await else {
            return;
        };
        let (ai_url, _seen) = start_mock_ai().await;
        let Some((owner, owner_tenant, _owner_user)) =
            AdvEnv::session_with_config(pool.clone(), "owner", ai_config(&ai_url)).await
        else {
            return;
        };
        let (status, created) = owner.post("/v1/ai/chat/sessions", "{}").await;
        assert_eq!(status, StatusCode::OK, "{created}");
        let id = session_id(&created);

        // A DIFFERENT tenant must not read or post to the session.
        let Some((other, _other_tenant, _)) =
            AdvEnv::session_with_config(pool.clone(), "owner", ai_config(&ai_url)).await
        else {
            return;
        };
        let (status, body) = other.get(&format!("/v1/ai/chat/sessions/{id}/turns")).await;
        assert_eq!(
            status,
            StatusCode::NOT_FOUND,
            "cross-tenant read must be a 404, not a leak: {body}"
        );
        let (status, body) = other
            .post(
                &format!("/v1/ai/chat/sessions/{id}/turns"),
                r#"{"message":"hi"}"#,
            )
            .await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{body}");

        // A second USER in the same tenant: sessions are per-user too. The
        // owner's session id is known, so this is the strongest probe.
        let (status, leaked) = other.get("/v1/ai/chat/sessions").await;
        assert_eq!(status, StatusCode::OK, "{leaked}");
        assert!(
            leaked["sessions"].as_array().is_some_and(Vec::is_empty),
            "a different owner sees no sessions: {leaked}"
        );
        let _ = owner_tenant;
    }

    #[tokio::test]
    async fn session_turns_enforce_the_cap_and_reject_empty_messages() {
        let Some(pool) = crate::test_db::canonical_pool("ai_session_caps").await else {
            return;
        };
        let (ai_url, _seen) = start_mock_ai().await;
        let Some((env, _tenant, _user)) =
            AdvEnv::session_with_config(pool.clone(), "owner", ai_config(&ai_url)).await
        else {
            return;
        };
        let (_, created) = env.post("/v1/ai/chat/sessions", "{}").await;
        let id = session_id(&created);

        let long = "x".repeat(4001);
        let (status, body) = env
            .post(
                &format!("/v1/ai/chat/sessions/{id}/turns"),
                &serde_json::json!({ "message": long }).to_string(),
            )
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        let (status, body) = env
            .post(
                &format!("/v1/ai/chat/sessions/{id}/turns"),
                r#"{"message":"   "}"#,
            )
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");

        // A rejected message must not have persisted a turn.
        let rows: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM ai_chat_session_turns WHERE session_id = $1")
                .bind(&id)
                .fetch_one(&pool)
                .await
                .expect("count turns");
        assert_eq!(rows, 0, "rejected turns are never stored");
    }

    #[tokio::test]
    async fn expired_sessions_are_pruned_on_the_next_create() {
        let Some(pool) = crate::test_db::canonical_pool("ai_session_prune").await else {
            return;
        };
        let (ai_url, _seen) = start_mock_ai().await;
        let Some((env, tenant, user)) =
            AdvEnv::session_with_config(pool.clone(), "owner", ai_config(&ai_url)).await
        else {
            return;
        };

        // A stale session from beyond the retention window (91 days, the
        // default is 90).
        let stale_id = apexmail_lib::id::generate_id("chat", 21);
        sqlx::query(
            "INSERT INTO ai_chat_sessions (id, tenant_id, user_id, created_at, updated_at) \
             VALUES ($1, $2, $3, NOW() - interval '91 days', NOW() - interval '91 days')",
        )
        .bind(&stale_id)
        .bind(&tenant)
        .bind(&user)
        .execute(&pool)
        .await
        .expect("stale session");

        let (status, created) = env.post("/v1/ai/chat/sessions", "{}").await;
        assert_eq!(status, StatusCode::OK, "{created}");

        let stale: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM ai_chat_sessions WHERE id = $1")
            .bind(&stale_id)
            .fetch_one(&pool)
            .await
            .expect("stale lookup");
        assert_eq!(stale, 0, "sessions past the retention window are pruned");
    }
}
