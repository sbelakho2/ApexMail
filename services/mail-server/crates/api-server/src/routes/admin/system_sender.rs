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
use crate::routes::system_sender::SYSTEM_TENANT_ID;
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/", get(status))
        .route("/bootstrap", post(bootstrap))
        .route("/verify", post(verify))
}

async fn status(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<Json<SystemSenderStatus>, ApiError> {
    require_scopes(&auth, &["*"])?;
    require_system_tenant(&auth)?;
    Ok(Json(system_sender_status(&state).await?))
}

async fn bootstrap(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<Json<SystemSenderStatus>, ApiError> {
    require_scopes(&auth, &["*"])?;
    require_system_tenant(&auth)?;
    Ok(Json(bootstrap_system_sender(&state).await?))
}

async fn verify(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<Json<SystemSenderStatus>, ApiError> {
    require_scopes(&auth, &["*"])?;
    require_system_tenant(&auth)?;
    let current_status = system_sender_status(&state).await?;
    let _verification =
        verify_domain_for_tenant(&state, SYSTEM_TENANT_ID, &current_status.id).await?;
    Ok(Json(system_sender_status(&state).await?))
}
