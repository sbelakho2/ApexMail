//! Operational control plane for the platform's own sender domain.
//!
//! This endpoint deliberately exposes only DNS instructions and readiness; the

use axum::extract::State;
use axum::routing::{get, post};
use axum::{Json, Router};

use crate::error::ApiError;
use crate::middleware::auth::{require_scopes, require_system_tenant, AuthUser};
use crate::routes::domains::{
    bootstrap_system_sender, system_sender_status, verify_domain_for_tenant, SystemSenderStatus,
};
use crate::routes::system_sender::{SYSTEM_DOMAIN_ID, SYSTEM_TENANT_ID};
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/", get(status))
        .route("/bootstrap", post(bootstrap))
        .route("/verify", post(verify))
}

/// Actor-attributed audit for platform-sender control mutations (P2-2):
/// bootstrapping/verifying the platform's own sending domain changes what
/// mail the platform can sign and send — the operator who ordered it must
/// be on record.
async fn log_system_sender_audit(
    state: &AppState,
    auth: &AuthUser,
    action: &str,
    metadata: serde_json::Value,
) {
    crate::audit_log::insert_audit_log_best_effort_with_env(
        &state.db,
        state.config.environment.is_production(),
        Some(auth.tenant_id.as_str()),
        auth.user_id.as_deref(),
        action,
        "system_sender",
        Some(SYSTEM_DOMAIN_ID),
        metadata,
        None,
        None,
    )
    .await;
}

async fn status(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<Json<SystemSenderStatus>, ApiError> {
    require_scopes(&auth, &["*"])?;
    require_system_tenant(&state, &auth).await?;
    Ok(Json(system_sender_status(&state).await?))
}

async fn bootstrap(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<Json<SystemSenderStatus>, ApiError> {
    require_scopes(&auth, &["*"])?;
    require_system_tenant(&state, &auth).await?;
    let bootstrapped = bootstrap_system_sender(&state).await?;
    log_system_sender_audit(
        &state,
        &auth,
        "control_plane.system_sender.bootstrapped",
        serde_json::json!({ "domainId": bootstrapped.id }),
    )
    .await;
    Ok(Json(bootstrapped))
}

async fn verify(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<Json<SystemSenderStatus>, ApiError> {
    require_scopes(&auth, &["*"])?;
    require_system_tenant(&state, &auth).await?;
    let current_status = system_sender_status(&state).await?;
    let _verification =
        verify_domain_for_tenant(&state, SYSTEM_TENANT_ID, &current_status.id).await?;
    let verified = system_sender_status(&state).await?;
    log_system_sender_audit(
        &state,
        &auth,
        "control_plane.system_sender.verified",
        serde_json::json!({ "domainId": verified.id, "status": verified.status }),
    )
    .await;
    Ok(Json(verified))
}
