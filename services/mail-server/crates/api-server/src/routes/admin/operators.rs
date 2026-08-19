//! Admin operator management — list, create, and manage control-plane operators.
//!
//! Operators are users with the `admin` or `owner` role. This module provides
//! the API endpoints backing the control-plane Operators UI.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;

use crate::error::ApiError;
use crate::middleware::auth::{require_scopes, require_system_tenant, AuthUser};
use crate::state::AppState;

/// Only these roles may be assigned to a control-plane operator.
const VALID_OPERATOR_ROLES: &[&str] = &["admin", "owner"];

pub fn router() -> Router<AppState> {
    Router::new()
        .route(
            "/",
            axum::routing::get(list_operators).post(create_operator),
        )
        .route("/:id", axum::routing::delete(delete_operator))
}

#[derive(Debug, Serialize, FromRow)]
pub struct OperatorRow {
    pub id: String,
    pub email: String,
    pub role: String,
    pub mfa_enabled: bool,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Deserialize)]
pub struct CreateOperatorRequest {
    pub email: String,
    pub name: Option<String>,
    pub role: Option<String>,
}

async fn list_operators(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<Json<Vec<OperatorRow>>, ApiError> {
    require_scopes(&auth, &["*"])?;
    require_system_tenant(&auth)?;
    let rows = sqlx::query_as::<_, OperatorRow>(
        "SELECT id, email, role, \
         COALESCE(mfa_enabled, false) AS mfa_enabled, created_at \
         FROM users WHERE role IN ('admin', 'owner') ORDER BY created_at DESC",
    )
    .fetch_all(&state.db)
    .await
    .map_err(|e| ApiError::Internal(format!("Failed to list operators: {e}")))?;
    Ok(Json(rows))
}

async fn create_operator(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(body): Json<CreateOperatorRequest>,
) -> Result<StatusCode, ApiError> {
    require_scopes(&auth, &["*"])?;
    require_system_tenant(&auth)?;
    let role = body.role.as_deref().unwrap_or("admin");
    // Reject arbitrary role strings — only admin/owner may be assigned.
    if !VALID_OPERATOR_ROLES.contains(&role) {
        return Err(ApiError::Validation(vec![format!(
            "invalid role: {role} (allowed: admin, owner)"
        )]));
    }
    let id = apexmail_lib::id::generate_id("usr", 16);
    let temp_password = apexmail_lib::id::generate_id("tmp", 24);
    let password_hash =
        bcrypt::hash(&temp_password, 10).map_err(|e| ApiError::Internal(format!("bcrypt: {e}")))?;
    sqlx::query(
        "INSERT INTO users (id, tenant_id, email, name, password_hash, role, mfa_enabled, created_at, updated_at) \
         VALUES ($1, $2, $3, $4, $5, $6, false, NOW(), NOW())",
    )
    .bind(&id)
    .bind(&auth.tenant_id)
    .bind(&body.email)
    .bind(body.name.as_deref().unwrap_or(""))
    .bind(&password_hash)
    .bind(role)
    .execute(&state.db)
    .await
    .map_err(|e| ApiError::Internal(format!("Failed to create operator: {e}")))?;
    tracing::info!(operator_id = %id, operator_email = %body.email, "Operator created");
    Ok(StatusCode::CREATED)
}

async fn delete_operator(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<String>,
) -> Result<StatusCode, ApiError> {
    require_scopes(&auth, &["*"])?;
    require_system_tenant(&auth)?;
    // users.id is VARCHAR(26) (ULID-like), not UUID — bind as text, no ::uuid cast.
    let result = sqlx::query("DELETE FROM users WHERE id = $1 AND role IN ('admin', 'owner')")
        .bind(&id)
        .execute(&state.db)
        .await
        .map_err(|e| ApiError::Internal(format!("Failed to delete operator: {e}")))?;
    if result.rows_affected() == 0 {
        return Err(ApiError::NotFound("Operator not found".into()));
    }
    Ok(StatusCode::NO_CONTENT)
}
