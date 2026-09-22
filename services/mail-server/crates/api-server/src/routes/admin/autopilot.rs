//! Autopilot control endpoints — a thin proxy to the sales-autopilot service.
//!
//! The control plane owns no sales brain. There is no worker loop, no
//! qualification threshold and no lead-status mutation here: the canonical
//! sales-autopilot service (`SALES_AUTOPILOT_BASE_URL`) is the only place that
//! thinks, decides and acts. This module exposes the operator
//! control surface over that service's `/control/*` API, forwarding the
//! internal service token (`x-api-key`) plus the `x-tenant-id` header.
//!
//! Mutating calls are audit-logged (`resource_type = "sales_autopilot"`) with
//! the upstream status. When the service is not configured the handlers fail
//! closed with `ServiceUnavailable` — the CP never fabricates a payload and
//! never falls back to local writes.

use std::time::Duration;

use axum::body::{Body, Bytes};
use axum::extract::{Path, State};
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::Response;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::json;

use crate::error::ApiError;
use crate::middleware::auth::AuthUser;
use crate::state::AppState;

/// Upstream calls are bounded: a hung sales-autopilot must not pin a CP
/// request slot forever.
const PROXY_TIMEOUT_SECS: u64 = 30;

/// The autonomy levels the canonical `sales_autonomy_state.mode` column
/// accepts (migration 200).
const AUTONOMY_MODES: [&str; 5] = [
    "disabled",
    "shadow",
    "assisted",
    "approval_required",
    "autonomous_guarded",
];

const REVIEW_OUTCOMES: [&str; 2] = ["approved", "rejected"];

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/overview", get(get_overview))
        .route("/decisions", get(get_decisions))
        .route("/exceptions", get(get_exceptions))
        .route("/actions", get(get_actions))
        .route("/mode", post(post_mode))
        .route("/pause", post(post_pause))
        .route("/resume", post(post_resume))
        .route("/kill-switch", post(post_kill_switch))
        .route("/decisions/:id/review", post(post_decision_review))
        .route("/actions/:id/replay", post(post_action_replay))
}

// ──────────────────────────────────────────
// Proxy plumbing
// ──────────────────────────────────────────

/// The configured sales-autopilot base URL, or a fail-closed error. An empty
/// value is "not configured" — the CP has no local autopilot to fall back to.
fn sales_autopilot_base_url(state: &AppState) -> Result<String, ApiError> {
    let base = state
        .config
        .sales_autopilot_base_url
        .trim()
        .trim_end_matches('/');
    if base.is_empty() {
        return Err(ApiError::ServiceUnavailable(
            "sales-autopilot is not configured (SALES_AUTOPILOT_BASE_URL is empty); \
             the control plane has no local autopilot"
                .into(),
        ));
    }
    Ok(base.to_string())
}

fn with_internal_service_auth(
    request: reqwest::RequestBuilder,
    state: &AppState,
) -> reqwest::RequestBuilder {
    if let Some(token) = state.config.internal_service_token.as_deref() {
        request.header("x-api-key", token)
    } else {
        request
    }
}

/// A buffered upstream response, forwarded to the caller verbatim (status,
/// content type and body) so the admin surface never rewrites service errors.
struct UpstreamResponse {
    status: StatusCode,
    content_type: Option<HeaderValue>,
    body: Bytes,
}

impl UpstreamResponse {
    fn status_u16(&self) -> u16 {
        self.status.as_u16()
    }

    fn into_axum_response(self) -> Response {
        let mut response = Response::new(Body::from(self.body));
        *response.status_mut() = self.status;
        if let Some(content_type) = self.content_type {
            response
                .headers_mut()
                .insert(header::CONTENT_TYPE, content_type);
        }
        response
    }
}

async fn proxy_request(
    state: &AppState,
    method: reqwest::Method,
    path: &str,
    body: Option<serde_json::Value>,
) -> Result<UpstreamResponse, ApiError> {
    let base = sales_autopilot_base_url(state)?;
    let mut request = state
        .http_client
        .request(method, format!("{base}{path}"))
        .header("x-tenant-id", "system")
        .timeout(Duration::from_secs(PROXY_TIMEOUT_SECS));
    request = with_internal_service_auth(request, state);
    if let Some(payload) = body {
        request = request.json(&payload);
    }

    let response = request.send().await.map_err(|error| {
        tracing::error!(error = %error, path, "sales-autopilot proxy request failed");
        ApiError::ServiceUnavailable(format!("sales-autopilot is unreachable at {base}"))
    })?;

    let status =
        StatusCode::from_u16(response.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
    let content_type = response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|value| HeaderValue::from_bytes(value.as_bytes()).ok());
    let body = response.bytes().await.map_err(|error| {
        tracing::error!(error = %error, path, "failed to read the sales-autopilot response");
        ApiError::ServiceUnavailable("sales-autopilot returned an unreadable response".into())
    })?;

    Ok(UpstreamResponse {
        status,
        content_type,
        body,
    })
}

async fn proxy_control_get(state: &AppState, path: &str) -> Result<Response, ApiError> {
    Ok(proxy_request(state, reqwest::Method::GET, path, None)
        .await?
        .into_axum_response())
}

/// Proxy a mutating control call and audit-log it. The audit entry is written
/// whether the upstream call succeeded or not — an attempted autonomy change
/// is always recorded.
async fn proxy_control_mutation(
    state: &AppState,
    auth: &AuthUser,
    method: reqwest::Method,
    path: &str,
    payload: serde_json::Value,
    audit_action: &str,
) -> Result<Response, ApiError> {
    let result = proxy_request(state, method, path, Some(payload.clone())).await;
    let upstream_status = result.as_ref().ok().map(UpstreamResponse::status_u16);

    log_autopilot_audit(
        &state.db,
        Some(auth.tenant_id.as_str()),
        auth.user_id.as_deref(),
        audit_action,
        json!({
            "request": payload,
            "upstreamStatus": upstream_status,
        }),
    )
    .await;

    result.map(UpstreamResponse::into_axum_response)
}

async fn log_autopilot_audit(
    db: &sqlx::PgPool,
    tenant_id: Option<&str>,
    user_id: Option<&str>,
    action: &str,
    metadata: serde_json::Value,
) {
    crate::audit_log::insert_audit_log_best_effort(
        db,
        tenant_id,
        user_id,
        action,
        "sales_autopilot",
        None,
        metadata,
        None,
        None,
    )
    .await;
}

/// Path ids are composed into the upstream URL, so only conservative
/// identifiers (UUIDs / nanoids) are accepted.
fn validate_path_id(id: &str) -> Result<(), ApiError> {
    let safe = !id.is_empty()
        && id.len() <= 64
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_');
    if safe {
        Ok(())
    } else {
        Err(ApiError::Validation(vec!["invalid id".into()]))
    }
}

// ──────────────────────────────────────────
// Request bodies
// ──────────────────────────────────────────

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ModeRequest {
    pub mode: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct KillSwitchRequest {
    pub engaged: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct DecisionReviewRequest {
    pub outcome: String,
    #[serde(default)]
    pub note: Option<String>,
}

// ──────────────────────────────────────────
// Read endpoints
// ──────────────────────────────────────────

async fn get_overview(State(state): State<AppState>, auth: AuthUser) -> Result<Response, ApiError> {
    crate::middleware::auth::require_scopes(&auth, &["*"])?;
    crate::middleware::auth::require_system_tenant(&state, &auth).await?;

    proxy_control_get(&state, "/control/overview").await
}

async fn get_decisions(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<Response, ApiError> {
    crate::middleware::auth::require_scopes(&auth, &["*"])?;
    crate::middleware::auth::require_system_tenant(&state, &auth).await?;

    proxy_control_get(&state, "/control/decisions").await
}

async fn get_exceptions(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<Response, ApiError> {
    crate::middleware::auth::require_scopes(&auth, &["*"])?;
    crate::middleware::auth::require_system_tenant(&state, &auth).await?;

    proxy_control_get(&state, "/control/exceptions").await
}

async fn get_actions(State(state): State<AppState>, auth: AuthUser) -> Result<Response, ApiError> {
    crate::middleware::auth::require_scopes(&auth, &["*"])?;
    crate::middleware::auth::require_system_tenant(&state, &auth).await?;

    proxy_control_get(&state, "/control/actions").await
}

// ──────────────────────────────────────────
// Mutations
// ──────────────────────────────────────────

async fn post_mode(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(body): Json<ModeRequest>,
) -> Result<Response, ApiError> {
    crate::middleware::auth::require_scopes(&auth, &["*"])?;
    crate::middleware::auth::require_system_tenant(&state, &auth).await?;

    if !AUTONOMY_MODES.contains(&body.mode.as_str()) {
        return Err(ApiError::Validation(vec![format!(
            "mode must be one of: {}",
            AUTONOMY_MODES.join(", ")
        )]));
    }

    proxy_control_mutation(
        &state,
        &auth,
        reqwest::Method::POST,
        "/control/mode",
        json!({ "mode": body.mode }),
        "control_plane.autopilot.mode_changed",
    )
    .await
}

async fn post_pause(State(state): State<AppState>, auth: AuthUser) -> Result<Response, ApiError> {
    crate::middleware::auth::require_scopes(&auth, &["*"])?;
    crate::middleware::auth::require_system_tenant(&state, &auth).await?;

    proxy_control_mutation(
        &state,
        &auth,
        reqwest::Method::POST,
        "/control/pause",
        json!({}),
        "control_plane.autopilot.paused",
    )
    .await
}

async fn post_resume(State(state): State<AppState>, auth: AuthUser) -> Result<Response, ApiError> {
    crate::middleware::auth::require_scopes(&auth, &["*"])?;
    crate::middleware::auth::require_system_tenant(&state, &auth).await?;

    proxy_control_mutation(
        &state,
        &auth,
        reqwest::Method::POST,
        "/control/resume",
        json!({}),
        "control_plane.autopilot.resumed",
    )
    .await
}

async fn post_kill_switch(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(body): Json<KillSwitchRequest>,
) -> Result<Response, ApiError> {
    crate::middleware::auth::require_scopes(&auth, &["*"])?;
    crate::middleware::auth::require_system_tenant(&state, &auth).await?;

    proxy_control_mutation(
        &state,
        &auth,
        reqwest::Method::POST,
        "/control/kill-switch",
        json!({ "engaged": body.engaged }),
        "control_plane.autopilot.kill_switch_changed",
    )
    .await
}

async fn post_decision_review(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<String>,
    Json(body): Json<DecisionReviewRequest>,
) -> Result<Response, ApiError> {
    crate::middleware::auth::require_scopes(&auth, &["*"])?;
    crate::middleware::auth::require_system_tenant(&state, &auth).await?;
    validate_path_id(&id)?;

    if !REVIEW_OUTCOMES.contains(&body.outcome.as_str()) {
        return Err(ApiError::Validation(vec![
            "outcome must be either 'approved' or 'rejected'".into(),
        ]));
    }

    let mut payload = json!({ "outcome": body.outcome });
    if let Some(note) = body.note.as_deref() {
        payload["note"] = json!(note);
    }

    proxy_control_mutation(
        &state,
        &auth,
        reqwest::Method::POST,
        &format!("/control/decisions/{id}/review"),
        payload,
        "control_plane.autopilot.decision_reviewed",
    )
    .await
}

async fn post_action_replay(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    crate::middleware::auth::require_scopes(&auth, &["*"])?;
    crate::middleware::auth::require_system_tenant(&state, &auth).await?;
    validate_path_id(&id)?;

    proxy_control_mutation(
        &state,
        &auth,
        reqwest::Method::POST,
        &format!("/control/actions/{id}/replay"),
        json!({}),
        "control_plane.autopilot.action_replayed",
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::test_support::{test_config, test_state_over_with_config};
    use axum::body::Body;
    use axum::http::Request;
    use sqlx::postgres::PgPoolOptions;
    use tower::ServiceExt;

    /// A router exposing the handlers at their production paths over a real
    /// (lazily connected) AppState. Routes are registered directly rather than
    /// with `nest` because nesting strips the URI prefix, and the
    /// control-plane static API key path guard inspects the full path.
    async fn test_app_with_config(mut config: crate::config::Config) -> Router {
        config.control_plane_api_key = Some("test-cp-key".into());
        let db = PgPoolOptions::new()
            .max_connections(1)
            .connect_lazy("postgres://apexmail:apexmail@127.0.0.1:1/apexmail")
            .expect("lazy test pool");
        let state = test_state_over_with_config(db, config).await;
        Router::new()
            .route("/v1/admin/autopilot/overview", get(get_overview))
            .route("/v1/admin/autopilot/mode", post(post_mode))
            .route(
                "/v1/admin/autopilot/decisions/:id/review",
                post(post_decision_review),
            )
            .with_state(state)
    }

    fn cp_request(method: &str, path: &str, body: Option<serde_json::Value>) -> Request<Body> {
        let builder = Request::builder()
            .method(method)
            .uri(path)
            .header("host", "localhost")
            .header("x-api-key", "test-cp-key");
        match body {
            Some(payload) => builder
                .header("content-type", "application/json")
                .body(Body::from(payload.to_string()))
                .unwrap(),
            None => builder.body(Body::empty()).unwrap(),
        }
    }

    /// The task's core invariant: no worker, no local lead qualification, no
    /// legacy candidate-id helper survives in this module. Fragments are
    /// assembled at runtime so the test source itself does not contain the
    /// forbidden strings it scans for.
    #[test]
    fn legacy_local_autopilot_brain_is_gone() {
        let source = include_str!("autopilot.rs");
        let forbidden = [
            ["PENDING", "APPROVAL", "SCORE"].join("_"),
            ["AUTOPILOT", "POLL", "INTERVAL", "SECS"].join("_"),
            ["process", "autopilot", "cycle"].join("_"),
            ["run", "autopilot", "worker"].join("_"),
            ["ensure", "autopilot", "worker", "running"].join("_"),
            ["stop", "autopilot", "worker"].join("_"),
            ["ensure", "autopilot", "state", "table"].join("_"),
            ["extract", "candidate", "id"].join("_"),
            ["tokio", "::", "spawn"].concat(),
            ["sales", "autopilot", "state"].join("_"),
            ["UPDATE", "sales", "leads"].join(" "),
            ["drip", "campaigns"].join("_"),
        ];
        for fragment in forbidden {
            assert!(
                !source.contains(&fragment),
                "autopilot.rs must not contain the removed local-brain artifact `{fragment}`"
            );
        }
    }

    #[test]
    fn autonomy_modes_match_the_canonical_check_constraint() {
        assert_eq!(
            AUTONOMY_MODES,
            [
                "disabled",
                "shadow",
                "assisted",
                "approval_required",
                "autonomous_guarded"
            ]
        );
    }

    #[tokio::test]
    async fn overview_fails_closed_when_the_service_is_unconfigured() {
        let mut config = test_config();
        config.sales_autopilot_base_url = "  ".into();
        let app = test_app_with_config(config).await;

        let response = app
            .oneshot(cp_request("GET", "/v1/admin/autopilot/overview", None))
            .await
            .unwrap();

        let status = response.status();
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(
            status,
            StatusCode::SERVICE_UNAVAILABLE,
            "body: {}",
            String::from_utf8_lossy(&body)
        );
    }

    #[tokio::test]
    async fn mutating_control_fails_closed_when_the_service_is_unconfigured() {
        let mut config = test_config();
        config.sales_autopilot_base_url = String::new();
        let app = test_app_with_config(config).await;

        let response = app
            .oneshot(cp_request(
                "POST",
                "/v1/admin/autopilot/mode",
                Some(json!({ "mode": "shadow" })),
            ))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn invalid_mode_is_rejected_before_any_upstream_call() {
        let app = test_app_with_config(test_config()).await;

        let response = app
            .oneshot(cp_request(
                "POST",
                "/v1/admin/autopilot/mode",
                Some(json!({ "mode": "full_send" })),
            ))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn invalid_review_outcome_is_rejected() {
        let app = test_app_with_config(test_config()).await;

        let response = app
            .oneshot(cp_request(
                "POST",
                "/v1/admin/autopilot/decisions/11111111-1111-1111-1111-111111111111/review",
                Some(json!({ "outcome": "maybe" })),
            ))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    // ── Coverage residuals: the live proxy surface ────────────────

    fn system_admin() -> AuthUser {
        AuthUser {
            tenant_id: "system".into(),
            user_id: Some("usr_autopilot_cov".into()),
            api_key_id: None,
            session_id: None,
            scopes: vec!["*".into()],
        }
    }

    /// A real canonical-pool state with the proxy pointed at `base_url`
    /// and the internal service token armed, so the audit writes land.
    /// The pool is returned too so assertions can read the audit table.
    async fn state_with_engine(
        db_suffix: &str,
        base_url: &str,
        token: Option<&str>,
    ) -> Option<(AppState, sqlx::PgPool)> {
        let pool = crate::test_db::canonical_pool(db_suffix).await?;
        let mut config = test_config();
        config.sales_autopilot_base_url = base_url.to_string();
        config.internal_service_token = token.map(str::to_string);
        let state =
            crate::app::test_support::test_state_over_with_config(pool.clone(), config).await;
        Some((state, pool))
    }

    async fn autopilot_audit_rows(pool: &sqlx::PgPool, action: &str) -> Vec<(String, i64)> {
        sqlx::query_as(
            "SELECT details->>'upstreamStatus', COUNT(*)::bigint FROM audit_logs
             WHERE action = $1 GROUP BY 1",
        )
        .bind(action)
        .fetch_all(pool)
        .await
        .expect("read autopilot audit rows")
    }

    /// A loopback sales-autopilot double that echoes the received request
    /// (method, path, headers, body) back as JSON.
    async fn start_mock_autopilot() -> String {
        use axum::extract::Request;

        async fn echo(request: Request) -> Response {
            let method = request.method().to_string();
            let path = request.uri().path().to_string();
            let api_key = request
                .headers()
                .get("x-api-key")
                .and_then(|v| v.to_str().ok())
                .map(str::to_string);
            let tenant = request
                .headers()
                .get("x-tenant-id")
                .and_then(|v| v.to_str().ok())
                .map(str::to_string);
            let bytes = axum::body::to_bytes(request.into_body(), 1024 * 1024)
                .await
                .unwrap_or_default();
            let body: serde_json::Value =
                serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
            axum::response::IntoResponse::into_response((
                StatusCode::OK,
                Json(json!({
                    "method": method,
                    "path": path,
                    "apiKey": api_key,
                    "tenant": tenant,
                    "body": body,
                })),
            ))
        }

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind mock autopilot");
        let base = format!("http://{}", listener.local_addr().unwrap());
        let handle = tokio::runtime::Handle::try_current().expect("test runtime");
        handle.spawn(async move {
            let _ = axum::serve(listener, Router::new().fallback(echo)).await;
        });
        base
    }

    #[tokio::test]
    async fn proxy_forwards_every_control_surface_and_audits_mutations() {
        let base = start_mock_autopilot().await;
        let Some((state, pool)) =
            state_with_engine("autopilot_proxy_all", &base, Some("internal-secret")).await
        else {
            return;
        };
        let admin = system_admin();

        // The four read endpoints forward the upstream JSON verbatim.
        for (path, upstream) in [
            ("/control/overview", "/control/overview"),
            ("/control/decisions", "/control/decisions"),
            ("/control/exceptions", "/control/exceptions"),
            ("/control/actions", "/control/actions"),
        ] {
            let response = proxy_control_get(&state, path).await.expect("GET forwards");
            assert!(response.status().is_success(), "{path}");
            let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap();
            let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(body["path"], upstream, "upstream path is preserved");
            assert_eq!(body["apiKey"], "internal-secret");
            assert_eq!(body["tenant"], "system");
        }

        // Mode change: the validated mode is forwarded and audited.
        let response = post_mode(
            State(state.clone()),
            admin.clone(),
            Json(ModeRequest {
                mode: "autonomous_guarded".into(),
            }),
        )
        .await
        .expect("mode forwards");
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(body["path"], "/control/mode");
        assert_eq!(body["body"]["mode"], "autonomous_guarded");

        // Pause / resume / kill-switch.
        assert_eq!(
            post_pause(State(state.clone()), admin.clone())
                .await
                .expect("pause")
                .status(),
            StatusCode::OK
        );
        assert_eq!(
            post_resume(State(state.clone()), admin.clone())
                .await
                .expect("resume")
                .status(),
            StatusCode::OK
        );
        let response = post_kill_switch(
            State(state.clone()),
            admin.clone(),
            Json(KillSwitchRequest { engaged: true }),
        )
        .await
        .expect("kill switch");
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(body["body"]["engaged"], true);

        // Decision review: the outcome and optional note ride the payload.
        let response = post_decision_review(
            State(state.clone()),
            admin.clone(),
            Path("dec-123".into()),
            Json(DecisionReviewRequest {
                outcome: "approved".into(),
                note: Some("looks safe".into()),
            }),
        )
        .await
        .expect("review forwards");
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(body["body"]["outcome"], "approved");
        assert_eq!(body["body"]["note"], "looks safe");

        // Without a note the payload carries only the outcome.
        let response = post_decision_review(
            State(state.clone()),
            admin.clone(),
            Path("dec-124".into()),
            Json(DecisionReviewRequest {
                outcome: "rejected".into(),
                note: None,
            }),
        )
        .await
        .expect("review without note");
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(body["body"]["note"], serde_json::Value::Null);

        // Action replay over the same proxy plumbing.
        let response =
            post_action_replay(State(state.clone()), admin.clone(), Path("act-1_2".into()))
                .await
                .expect("replay forwards");
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(body["path"], "/control/actions/act-1_2/replay");

        // Every mutation left an audit row carrying the upstream status.
        let mut audited_mutations = 0;
        for action in [
            "control_plane.autopilot.mode_changed",
            "control_plane.autopilot.paused",
            "control_plane.autopilot.resumed",
            "control_plane.autopilot.kill_switch_changed",
            "control_plane.autopilot.decision_reviewed",
            "control_plane.autopilot.action_replayed",
        ] {
            let rows = autopilot_audit_rows(&pool, action).await;
            assert!(!rows.is_empty(), "{action} must be audited");
            assert!(
                rows.iter().all(|(status, _)| status == "200"),
                "{action} rows carry the upstream status, got {rows:?}"
            );
            audited_mutations += rows.iter().map(|(_, n)| n).sum::<i64>();
        }
        assert!(audited_mutations >= 6);
        pool.close().await;
    }

    #[tokio::test]
    async fn proxy_upstream_failures_are_honest_5xxs() {
        // Connection refused: a closed loopback port fails fast and the
        // proxy maps it to ServiceUnavailable.
        let Some((state, _pool)) =
            state_with_engine("autopilot_proxy_dead", "http://127.0.0.1:9", None).await
        else {
            return;
        };
        let result = proxy_control_get(&state, "/control/overview").await;
        assert!(
            matches!(result, Err(ApiError::ServiceUnavailable(_))),
            "unreachable upstream must be a 503, got {result:?}"
        );

        // The internal token header is omitted entirely when unconfigured —
        // this call proves that arm (no token configured above).
        let result = proxy_request(&state, reqwest::Method::GET, "/control/overview", None).await;
        assert!(
            matches!(result, Err(ApiError::ServiceUnavailable(_))),
            "dead upstream cannot yield a response"
        );

        // A truncated upstream body (headers promise more bytes than are
        // sent, then the socket closes) is an unreadable response → 503.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind truncating upstream");
        let addr = listener.local_addr().unwrap();
        let handle = tokio::runtime::Handle::try_current().expect("test runtime");
        handle.spawn(async move {
            loop {
                let Ok((mut socket, _)) = listener.accept().await else {
                    return;
                };
                // Consume the request first: closing with unread received
                // data would send an RST (a connect-class failure) instead
                // of the FIN that truncates the body.
                let mut request = [0u8; 1024];
                let _ = tokio::io::AsyncReadExt::read(&mut socket, &mut request).await;
                let _ = socket
                    .try_write(
                        b"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\n\
                          content-length: 100\r\n\r\n{\"partial\":",
                    )
                    .map(|_| ());
                // Drop → FIN without the promised body.
            }
        });
        let Some((state, pool)) =
            state_with_engine("autopilot_proxy_trunc", &format!("http://{addr}"), None).await
        else {
            return;
        };
        let result = proxy_request(&state, reqwest::Method::GET, "/control/overview", None).await;
        assert!(
            matches!(&result, Err(ApiError::ServiceUnavailable(message))
                if message.contains("unreadable")),
            "truncated upstream body must map to the unreadable-response 503"
        );
        pool.close().await;
    }

    /// Upstream error statuses and content types are forwarded verbatim —
    /// the CP never rewrites a service error.
    #[tokio::test]
    async fn proxy_forwards_upstream_error_status_and_content_type() {
        use axum::extract::Request;

        async fn broken(_request: Request) -> Response {
            axum::response::IntoResponse::into_response((
                StatusCode::SERVICE_UNAVAILABLE,
                [(header::CONTENT_TYPE, "text/plain")],
                "engine on fire".to_string(),
            ))
        }

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind 503 upstream");
        let addr = listener.local_addr().unwrap();
        let handle = tokio::runtime::Handle::try_current().expect("test runtime");
        handle.spawn(async move {
            let _ = axum::serve(listener, Router::new().fallback(broken)).await;
        });
        let Some((state, pool)) =
            state_with_engine("autopilot_proxy_503", &format!("http://{addr}"), None).await
        else {
            return;
        };
        let admin = system_admin();

        let response = post_pause(State(state.clone()), admin)
            .await
            .expect("pause forwards");
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            response
                .headers()
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok()),
            Some("text/plain"),
            "the upstream content type is preserved"
        );
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(&bytes[..], b"engine on fire");

        // The audit entry recorded the attempted change and the upstream
        // status even though the call failed.
        let rows = autopilot_audit_rows(&pool, "control_plane.autopilot.paused").await;
        assert!(
            rows.iter().any(|(status, _)| status == "503"),
            "the attempted pause is audited with the upstream 503, got {rows:?}"
        );
        pool.close().await;
    }

    /// Path ids are confined to conservative identifier characters.
    #[tokio::test]
    async fn decision_review_refuses_unsafe_path_ids_before_any_upstream_call() {
        // A configured-but-dead engine: a pass would surface as 503 and
        // only the validation arm yields 400.
        let Some((state, pool)) =
            state_with_engine("autopilot_proxy_ids", "http://127.0.0.1:9", None).await
        else {
            return;
        };
        let admin = system_admin();
        for evil in ["../escape", "with space", "", "id;drop", "üñî"] {
            let result = post_decision_review(
                State(state.clone()),
                admin.clone(),
                Path(evil.to_string()),
                Json(DecisionReviewRequest {
                    outcome: "approved".into(),
                    note: None,
                }),
            )
            .await;
            assert!(
                matches!(&result, Err(ApiError::Validation(_))),
                "id {evil:?} must be refused, got {result:?}"
            );
        }
        let result = post_action_replay(State(state.clone()), admin, Path("%2e%2e".into())).await;
        assert!(matches!(result, Err(ApiError::Validation(_))));
        pool.close().await;
    }
}
