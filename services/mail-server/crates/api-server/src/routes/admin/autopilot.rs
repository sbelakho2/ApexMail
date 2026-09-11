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
}
