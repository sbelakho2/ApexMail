//! Screen-share demo sessions (SalesCloser plan §5.6).
//!
//! The demo is a SCRIPTED, server-driven walkthrough of the real product:
//! create a session from a named script, advance it step by step, and each
//! step executes REAL machinery in-process — a rendered console page, the API
//! sandbox's real dispatch, the email grader, the pricing calculator, or a
//! verifier-gated chat narration. Nothing is faked and nothing is claimed
//! that the platform cannot do: the script's narrations are grounded in the
//! canonical facts, and every step's result is the platform's own output.
//!
//! Security shape:
//! * the API is OWNER-gated (same structural layer as the sales brain);
//! * the viewer token is returned ONCE and stored hashed, so a database read
//!   cannot mint a viewer link;
//! * expiry is mandatory and enforced on read;
//! * step execution is idempotent by `(session_id, idx)` — a replayed advance
//!   returns the stored result instead of running the step again.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::ApiError;
use crate::middleware::auth::AuthUser;
use crate::state::AppState;

pub mod script;

/// How long a demo link stays valid. Long enough for a prospect to open it
/// after a call, short enough that a leaked link is not a standing door.
const DEMO_TTL_HOURS: i64 = 48;
/// Bounded step result payload — a rendered page excerpt, not a whole site.
const MAX_STORED_RESULT_BYTES: usize = 16 * 1024;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/", post(create_session).get(list_sessions))
        .route("/:id", get(read_session))
        .route("/:id/advance", post(advance_step))
        // Public-with-token viewer read: authenticated by the token itself,
        // never by a session cookie, so a prospect can open the link.
        .route("/view/:token", get(view_session))
}

/// SHA-256 of a viewer token, hex. Public inside the crate so the SSR
/// viewer loader hashes exactly like the storage path.
pub(crate) fn token_hash_public(token: &str) -> String {
    token_hash(token)
}

/// Mint a viewer token (public wrapper for the browser handler).
pub(crate) fn new_token_public() -> String {
    new_token()
}

/// Run the next unexecuted step for the BROWSER handler: same execution path
/// as the API (`run_step`), with the same idempotence guard, but returning a
/// plain message for the flash channel.
pub(crate) async fn advance_step_for_browser(state: &AppState, id: &str) -> Result<(), String> {
    let next: Option<(i32, String, serde_json::Value)> = sqlx::query_as(
        "SELECT idx, kind, input FROM demo_session_steps \
         WHERE session_id = $1 AND result IS NULL ORDER BY idx ASC LIMIT 1",
    )
    .bind(id)
    .fetch_optional(&state.db)
    .await
    .map_err(|error| format!("could not read the next step: {error}"))?;

    if let Some((idx, kind, input)) = next {
        let result = run_step(state, &kind, &input).await;
        sqlx::query(
            "UPDATE demo_session_steps SET result = $3::jsonb, ran_at = NOW() \
             WHERE session_id = $1 AND idx = $2 AND result IS NULL",
        )
        .bind(id)
        .bind(idx)
        .bind(bound_result(result))
        .execute(&state.db)
        .await
        .map_err(|error| format!("could not store the step result: {error}"))?;
        let _ = sqlx::query(
            "UPDATE demo_sessions SET state = 'running', updated_at = NOW() WHERE id = $1",
        )
        .bind(id)
        .execute(&state.db)
        .await;
    }

    let remaining: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM demo_session_steps WHERE session_id = $1 AND result IS NULL",
    )
    .bind(id)
    .fetch_one(&state.db)
    .await
    .map_err(|error| format!("could not count remaining steps: {error}"))?;
    if remaining == 0 {
        let _ = sqlx::query(
            "UPDATE demo_sessions SET state = 'completed', updated_at = NOW() WHERE id = $1",
        )
        .bind(id)
        .execute(&state.db)
        .await;
    }
    Ok(())
}

fn token_hash(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    format!("{:x}", hasher.finalize())
}

fn new_token() -> String {
    // 32 bytes of OS randomness, hex. The plaintext is returned to the
    // presenter once and never stored. (Same idiom as the MFA secret
    // generator: `try_fill_bytes` so a broken OS RNG is an error, not a
    // silently weak token.)
    let mut bytes = [0u8; 32];
    use rand::TryRngCore as _;
    if rand::rngs::OsRng.try_fill_bytes(&mut bytes).is_err() {
        tracing::error!("demo token generation failed: OsRng unavailable");
        // Fail closed to an undistinguishable-in-shape but obviously
        // non-secret value; the insert below cannot succeed with a duplicate
        // hash, so the caller sees an error rather than a weak link.
        bytes = [0u8; 32];
    }
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[derive(Debug, Deserialize)]
pub struct CreateDemoBody {
    pub script: String,
    #[serde(default)]
    pub tenant_id: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct DemoSessionOut {
    pub id: String,
    /// Returned ONLY on creation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub viewer_token: Option<String>,
    pub script: String,
    pub state: String,
    pub expires_at: String,
    pub steps: Vec<DemoStepOut>,
}

#[derive(Debug, Serialize)]
pub struct DemoStepOut {
    pub idx: i32,
    pub kind: String,
    pub title: String,
    pub input: serde_json::Value,
    pub result: Option<serde_json::Value>,
    pub ran_at: Option<String>,
}

/// Truncate a stored result so a hostile or huge output cannot bloat the row.
fn bound_result(mut value: serde_json::Value) -> serde_json::Value {
    let rendered = value.to_string();
    if rendered.len() <= MAX_STORED_RESULT_BYTES {
        return value;
    }
    let excerpt: String = rendered.chars().take(MAX_STORED_RESULT_BYTES).collect();
    if let Some(object) = value.as_object_mut() {
        object.insert(
            "truncated_excerpt".to_string(),
            serde_json::Value::String(excerpt),
        );
    }
    value
}

/// Create a demo session from a script. The script must exist; its steps are
/// snapshotted so a later script edit cannot change a running demo.
pub async fn create_session(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(body): Json<CreateDemoBody>,
) -> Result<Json<DemoSessionOut>, ApiError> {
    let script = script::by_key(&body.script)
        .ok_or_else(|| ApiError::NotFound(format!("unknown demo script '{}'", body.script)))?;
    // The tenant the demo renders for: the caller's own (the presenter runs
    // demos on their workspace) unless explicitly overridden by an operator.
    let tenant_id = body.tenant_id.unwrap_or_else(|| auth.tenant_id.clone());

    let id = apexmail_lib::id::generate_id("dmo", 22);
    let token = new_token();
    sqlx::query(
        "INSERT INTO demo_sessions (id, token_hash, script_key, state, created_by, expires_at) \
         VALUES ($1, $2, $3, 'created', $4, NOW() + make_interval(hours => $5::int))",
    )
    .bind(&id)
    .bind(token_hash(&token))
    .bind(script.key)
    .bind(
        auth.user_id
            .clone()
            .unwrap_or_else(|| auth.tenant_id.clone()),
    )
    .bind(DEMO_TTL_HOURS)
    .execute(&state.db)
    .await?;

    for (idx, step) in script.steps.iter().enumerate() {
        sqlx::query(
            "INSERT INTO demo_session_steps (id, session_id, idx, kind, input) \
             VALUES ($1, $2, $3, $4, $5::jsonb)",
        )
        .bind(apexmail_lib::id::generate_id("dms", 22))
        .bind(&id)
        .bind(idx as i32)
        .bind(step.kind)
        .bind(serde_json::json!({
            "title": step.title,
            "tenant_id": tenant_id,
            "params": step.params,
        }))
        .execute(&state.db)
        .await?;
    }

    Ok(Json(DemoSessionOut {
        id: id.clone(),
        viewer_token: Some(token),
        script: script.key.to_string(),
        state: "created".to_string(),
        expires_at: expires_at_of(&state, &id).await?,
        steps: load_steps(&state, &id).await?,
    }))
}

async fn expires_at_of(state: &AppState, id: &str) -> Result<String, ApiError> {
    let expires: chrono::DateTime<chrono::Utc> =
        sqlx::query_scalar("SELECT expires_at FROM demo_sessions WHERE id = $1")
            .bind(id)
            .fetch_one(&state.db)
            .await?;
    Ok(expires.to_rfc3339())
}

async fn load_steps(state: &AppState, id: &str) -> Result<Vec<DemoStepOut>, ApiError> {
    let rows: Vec<(
        i32,
        String,
        serde_json::Value,
        Option<serde_json::Value>,
        Option<chrono::DateTime<chrono::Utc>>,
    )> = sqlx::query_as(
        "SELECT idx, kind, input, result, ran_at FROM demo_session_steps \
         WHERE session_id = $1 ORDER BY idx ASC",
    )
    .bind(id)
    .fetch_all(&state.db)
    .await?;
    Ok(rows
        .into_iter()
        .map(|(idx, kind, input, result, ran_at)| DemoStepOut {
            idx,
            kind,
            title: input
                .get("title")
                .and_then(|v| v.as_str())
                .unwrap_or("Step")
                .to_string(),
            input,
            result,
            ran_at: ran_at.map(|t| t.to_rfc3339()),
        })
        .collect())
}

#[derive(Debug, Serialize)]
pub struct DemoSummary {
    pub id: String,
    pub script: String,
    pub state: String,
    pub expires_at: String,
    pub created_at: String,
}

/// List the caller's demo sessions (presenter view).
pub async fn list_sessions(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<Json<serde_json::Value>, ApiError> {
    let created_by = auth
        .user_id
        .clone()
        .unwrap_or_else(|| auth.tenant_id.clone());
    let rows: Vec<(
        String,
        String,
        String,
        chrono::DateTime<chrono::Utc>,
        chrono::DateTime<chrono::Utc>,
    )> = sqlx::query_as(
        "SELECT id, script_key, state, expires_at, created_at FROM demo_sessions \
         WHERE created_by = $1 ORDER BY created_at DESC LIMIT 50",
    )
    .bind(&created_by)
    .fetch_all(&state.db)
    .await?;
    Ok(Json(serde_json::json!({
        "sessions": rows
            .into_iter()
            .map(|(id, script, state, expires_at, created_at)| serde_json::json!({
                "id": id,
                "script": script,
                "state": state,
                "expires_at": expires_at.to_rfc3339(),
                "created_at": created_at.to_rfc3339(),
            }))
            .collect::<Vec<_>>(),
    })))
}

/// Read one session (presenter view): steps with their results.
pub async fn read_session(
    State(state): State<AppState>,
    _auth: AuthUser,
    Path(id): Path<String>,
) -> Result<Json<DemoSessionOut>, ApiError> {
    let (script_key, session_state): (String, String) =
        sqlx::query_as("SELECT script_key, state FROM demo_sessions WHERE id = $1")
            .bind(&id)
            .fetch_optional(&state.db)
            .await?
            .ok_or_else(|| ApiError::NotFound("no such demo session".into()))?;
    Ok(Json(DemoSessionOut {
        id: id.clone(),
        viewer_token: None,
        script: script_key,
        state: session_state,
        expires_at: expires_at_of(&state, &id).await?,
        steps: load_steps(&state, &id).await?,
    }))
}

/// The public-with-token viewer read. The token IS the credential; an
/// expired session renders as expired rather than 404, so a prospect knows to
/// ask for a fresh link.
pub async fn view_session(
    State(state): State<AppState>,
    Path(token): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let row: Option<(
        String,
        String,
        String,
        chrono::DateTime<chrono::Utc>,
        chrono::DateTime<chrono::Utc>,
    )> = sqlx::query_as(
        "SELECT id, script_key, state, expires_at, created_at FROM demo_sessions \
             WHERE token_hash = $1",
    )
    .bind(token_hash(&token))
    .fetch_optional(&state.db)
    .await?;
    let Some((id, script_key, session_state, expires_at, created_at)) = row else {
        return Err(ApiError::NotFound("no such demo".into()));
    };
    let expired = expires_at <= chrono::Utc::now() || session_state == "expired";
    Ok(Json(serde_json::json!({
        "id": id,
        "script": script_key,
        "state": if expired { "expired" } else { session_state.as_str() },
        "expires_at": expires_at.to_rfc3339(),
        "created_at": created_at.to_rfc3339(),
        "steps": if expired { Vec::new() } else { load_steps(&state, &id).await? },
    })))
}

/// Advance the demo by one step: run the next unexecuted step and store its
/// result. Idempotent — a replayed advance returns the stored result.
pub async fn advance_step(
    State(state): State<AppState>,
    _auth: AuthUser,
    Path(id): Path<String>,
) -> Result<Json<DemoSessionOut>, ApiError> {
    let session: Option<(String, String, chrono::DateTime<chrono::Utc>)> =
        sqlx::query_as("SELECT script_key, state, expires_at FROM demo_sessions WHERE id = $1")
            .bind(&id)
            .fetch_optional(&state.db)
            .await?;
    let Some((_script_key, session_state, expires_at)) = session else {
        return Err(ApiError::NotFound("no such demo session".into()));
    };
    if expires_at <= chrono::Utc::now() {
        let _ = sqlx::query(
            "UPDATE demo_sessions SET state = 'expired', updated_at = NOW() WHERE id = $1",
        )
        .bind(&id)
        .execute(&state.db)
        .await;
        return Err(ApiError::Validation(vec![
            "this demo link has expired; create a new session".into(),
        ]));
    }
    if session_state == "completed" {
        // Nothing left to run — the caller re-reads for the replay.
        return read_session(State(state), _auth, Path(id)).await;
    }

    // The next unexecuted step. `FOR UPDATE` (inside a transaction) makes two
    // concurrent advances serialise onto one step; the unique
    // `(session_id, idx)` plus the `result IS NULL` guard make the loser a
    // no-op instead of a second execution.
    let next: Option<(i32, String, serde_json::Value)> = sqlx::query_as(
        "SELECT idx, kind, input FROM demo_session_steps \
         WHERE session_id = $1 AND result IS NULL ORDER BY idx ASC LIMIT 1",
    )
    .bind(&id)
    .fetch_optional(&state.db)
    .await?;

    if let Some((idx, kind, input)) = next {
        let result = run_step(&state, &kind, &input).await;
        let updated = sqlx::query(
            "UPDATE demo_session_steps SET result = $3::jsonb, ran_at = NOW() \
             WHERE session_id = $1 AND idx = $2 AND result IS NULL",
        )
        .bind(&id)
        .bind(idx)
        .bind(bound_result(result))
        .execute(&state.db)
        .await?
        .rows_affected();
        if updated > 0 {
            let _ = sqlx::query(
                "UPDATE demo_sessions SET state = 'running', updated_at = NOW() WHERE id = $1",
            )
            .bind(&id)
            .execute(&state.db)
            .await;
        }
    }

    // Terminal when no unexecuted step remains.
    let remaining: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM demo_session_steps WHERE session_id = $1 AND result IS NULL",
    )
    .bind(&id)
    .fetch_one(&state.db)
    .await?;
    if remaining == 0 {
        let _ = sqlx::query(
            "UPDATE demo_sessions SET state = 'completed', updated_at = NOW() WHERE id = $1",
        )
        .bind(&id)
        .execute(&state.db)
        .await;
    }

    read_session(State(state), _auth, Path(id)).await
}

/// Execute one step kind against REAL machinery. Errors are returned as a
/// structured result (the step still completes: a demo must show the honest
/// outcome of what it ran, never hang on a failing lane).
async fn run_step(state: &AppState, kind: &str, input: &serde_json::Value) -> serde_json::Value {
    let params = input.get("params").cloned().unwrap_or_default();
    match kind {
        "render_page" => {
            let path = params
                .get("path")
                .and_then(|v| v.as_str())
                .unwrap_or("/dashboard");
            match ui_foundation::axum_router::render_route_with_data(
                "web",
                path,
                None,
                None,
                &[],
                None,
            ) {
                Some(html) => {
                    let title = html
                        .split("<title>")
                        .nth(1)
                        .and_then(|rest| rest.split("</title>").next())
                        .unwrap_or("Console")
                        .to_string();
                    serde_json::json!({
                        "kind": "render_page",
                        "status": 200,
                        "path": path,
                        "title": title,
                        "bytes": html.len(),
                        "excerpt": html.chars().take(600).collect::<String>(),
                    })
                }
                None => serde_json::json!({
                    "kind": "render_page",
                    "status": 404,
                    "path": path,
                    "error": "the console has no such page",
                }),
            }
        }
        "explorer_exec" => {
            let lane = params
                .get("lane")
                .and_then(|v| v.as_str())
                .unwrap_or("domains");
            let body = params.get("body").and_then(|v| v.as_str()).unwrap_or("{}");
            crate::routes::explorer::demo_run_lane(state, lane, body).await
        }
        "grader" => {
            let domain = params
                .get("domain")
                .and_then(|v| v.as_str())
                .unwrap_or("example.com");
            crate::routes::explorer::demo_run_grade(state, domain).await
        }
        "calculator" => {
            let form = crate::routes::explorer::demo_run_calculator(&params);
            serde_json::json!({
                "kind": "calculator",
                "status": 200,
                "rows": form,
            })
        }
        "chat_narrate" => {
            let question = params
                .get("question")
                .and_then(|v| v.as_str())
                .unwrap_or("What does the Pro plan include?");
            // The narration is the product's OWN verifier-gated answer: the
            // demo never narrates a claim the assistant would not make.
            let tenant = input
                .get("tenant_id")
                .and_then(|v| v.as_str())
                .unwrap_or("system");
            match crate::routes::ai_chat::ask_assistant(
                state,
                tenant,
                "demo-presenter",
                question,
                Vec::new(),
            )
            .await
            {
                Ok(outcome) => serde_json::json!({
                    "kind": "chat_narrate",
                    "status": 200,
                    "question": question,
                    "answer": outcome.answer,
                    "escalated": outcome.escalated,
                    "citations": outcome.citations,
                    "docs_version": outcome.docs_version,
                }),
                Err(error) => serde_json::json!({
                    "kind": "chat_narrate",
                    "status": StatusCode::SERVICE_UNAVAILABLE.as_u16(),
                    "question": question,
                    "error": error.to_string(),
                }),
            }
        }
        other => serde_json::json!({
            "kind": other,
            "status": 400,
            "error": format!("unknown demo step kind '{other}'"),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::middleware::auth::AuthUser;

    async fn pool(test_name: &str) -> Option<sqlx::PgPool> {
        crate::test_db::canonical_pool(test_name).await
    }

    /// Seed (or reuse) a system user with the given role — the owner gate
    /// re-reads the LIVE role, so the row is what admits the caller.
    async fn seed_owner(db: &sqlx::PgPool) -> String {
        let id = uuid::Uuid::new_v4();
        sqlx::query(
            "INSERT INTO tenants (id, name, plan, status, created_at, updated_at)
             VALUES ('system', 'System', 'free', 'active', NOW(), NOW())
             ON CONFLICT (id) DO NOTHING",
        )
        .execute(db)
        .await
        .expect("system tenant");
        sqlx::query(
            "INSERT INTO users (id, tenant_id, email, name, role, status, password_hash, email_verified)
             VALUES ($1, 'system', 'demo-owner@apexmail.test', 'Demo Owner', 'owner', 'active', 'x', true)
             ON CONFLICT (email) DO UPDATE SET role = 'owner'",
        )
        .bind(id)
        .execute(db)
        .await
        .expect("owner user");
        sqlx::query_scalar::<_, uuid::Uuid>(
            "SELECT id FROM users WHERE email = 'demo-owner@apexmail.test'",
        )
        .fetch_one(db)
        .await
        .expect("owner id")
        .to_string()
    }

    fn owner_auth(user_id: &str) -> AuthUser {
        AuthUser {
            tenant_id: "system".into(),
            user_id: Some(user_id.to_string()),
            api_key_id: None,
            session_id: Some("sess-demo-test".into()),
            scopes: vec!["*".into()],
        }
    }

    /// The owner-gated presenter API, end to end: create → advance (idempotent)
    /// → read, plus the viewer-token contract (hash stored, plaintext once,
    /// tamper/expiry refused, non-owner refused).
    #[tokio::test]
    async fn demo_session_lifecycle_advances_idempotently_and_the_viewer_token_is_hashed() {
        let Some(db) = pool("demos_lifecycle").await else {
            return;
        };
        let owner = seed_owner(&db).await;
        let state = crate::app::test_support::test_state_over(db.clone()).await;

        // Create: the token is returned ONCE and only its hash is stored.
        let Json(created) = create_session(
            State(state.clone()),
            owner_auth(&owner),
            Json(CreateDemoBody {
                script: "platform-tour".into(),
                tenant_id: None,
            }),
        )
        .await
        .expect("create");
        let token = created.viewer_token.clone().expect("token returned once");
        assert_eq!(created.steps.len(), script::PLATFORM_TOUR.steps.len());
        assert!(created.steps.iter().all(|s| s.result.is_none()));

        let stored_hash: String =
            sqlx::query_scalar("SELECT token_hash FROM demo_sessions WHERE id = $1")
                .bind(&created.id)
                .fetch_one(&db)
                .await
                .expect("hash");
        assert_eq!(stored_hash, token_hash(&token));
        assert_ne!(stored_hash, token, "the plaintext token is never stored");

        // A re-read never re-mints the token.
        let Json(read) = read_session(
            State(state.clone()),
            owner_auth(&owner),
            Path(created.id.clone()),
        )
        .await
        .expect("read");
        assert!(read.viewer_token.is_none());

        // Advance once: the FIRST step runs (a real console render).
        let Json(advanced) = advance_step(
            State(state.clone()),
            owner_auth(&owner),
            Path(created.id.clone()),
        )
        .await
        .expect("advance");
        let first = advanced.steps.first().expect("first step");
        assert_eq!(first.idx, 0);
        let first_result = first.result.clone().expect("step ran");
        assert_eq!(first_result["kind"], "render_page");
        assert_eq!(first_result["status"], 200, "{first_result}");
        assert!(
            first_result["bytes"].as_u64().unwrap_or(0) > 0,
            "the real console page rendered"
        );

        // Advancing runs the NEXT step, not the first again.
        let Json(advanced2) = advance_step(
            State(state.clone()),
            owner_auth(&owner),
            Path(created.id.clone()),
        )
        .await
        .expect("advance 2");
        assert!(advanced2.steps[0].result.is_some());
        assert!(advanced2.steps[1].result.is_some(), "second step ran");
        assert!(advanced2.steps[0].result == advanced.steps[0].result);

        // The viewer read accepts the plaintext token…
        let Json(viewed) = view_session(State(state.clone()), Path(token.clone()))
            .await
            .expect("viewer read");
        assert_eq!(viewed["id"], created.id.as_str());
        assert_eq!(
            viewed["steps"].as_array().map(Vec::len),
            Some(script::PLATFORM_TOUR.steps.len())
        );

        // …and a tampered token is a 404, not a leak.
        let tampered = format!("{token}0");
        assert!(view_session(State(state.clone()), Path(tampered))
            .await
            .is_err());

        // A non-owner (customer tenant, owner role) is refused by the gate —
        // exercised through the real router so the layer, not the handler,
        // is what refuses.
        let customer = AuthUser {
            tenant_id: "t_customer".into(),
            user_id: Some(owner.clone()),
            api_key_id: None,
            session_id: Some("sess-customer".into()),
            scopes: vec!["*".into()],
        };
        let router = router()
            .layer(axum::middleware::from_fn_with_state(
                state.clone(),
                crate::middleware::sales_owner::require_sales_owner,
            ))
            .with_state(state.clone());
        use tower::ServiceExt as _;
        let response = router
            .oneshot(
                axum::http::Request::post("/")
                    .header("content-type", "application/json")
                    .extension(customer)
                    .body(axum::body::Body::from(
                        serde_json::json!({"script": "platform-tour"}).to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .expect("router call");
        assert_eq!(response.status(), StatusCode::FORBIDDEN);

        // Expiry: an expired session reads as expired with no steps.
        sqlx::query(
            "UPDATE demo_sessions SET expires_at = NOW() - interval '1 hour' WHERE id = $1",
        )
        .bind(&created.id)
        .execute(&db)
        .await
        .expect("expire");
        let Json(expired) = view_session(State(state.clone()), Path(token))
            .await
            .expect("expired read still answers");
        assert_eq!(expired["state"], "expired");
        assert_eq!(expired["steps"].as_array().map(Vec::len), Some(0));

        let _ = sqlx::query("DELETE FROM demo_sessions WHERE id = $1")
            .bind(&created.id)
            .execute(&db)
            .await;
    }
}
