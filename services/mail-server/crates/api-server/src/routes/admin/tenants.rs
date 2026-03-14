//! Tenant management endpoints.
//!
//! Migrated from: apps/control-plane/src/app/api/tenants/route.ts

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::routing::get;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::ApiError;
use crate::middleware::auth::AuthUser;
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/", get(list_tenants).patch(update_tenant).delete(delete_tenant))
}

// ─── Types ─────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct ListTenantsQuery {
    #[serde(default = "default_limit")]
    pub limit: i64,
    #[serde(default)]
    pub offset: i64,
}

fn default_limit() -> i64 { 50 }

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct TenantRow {
    pub id: Uuid,
    pub name: String,
    pub slug: String,
    pub plan: String,
    pub status: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateTenantRequest {
    pub id: Uuid,
    #[serde(default)]
    pub action: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub plan: Option<String>,
    #[serde(default)]
    pub status: Option<String>,
}

// ─── Handlers ──────────────────────────────────────────────────

async fn list_tenants(
    State(state): State<AppState>,
    auth: AuthUser,
    Query(params): Query<ListTenantsQuery>,
) -> Result<Json<Vec<TenantRow>>, ApiError> {
    crate::middleware::auth::require_scopes(&auth, &["*"])?;

    let limit = params.limit.clamp(1, 200);
    let offset = params.offset.max(0);

    let rows = sqlx::query_as::<_, TenantRow>(
        "SELECT id, name, slug, plan, status, created_at, updated_at
         FROM tenants ORDER BY created_at DESC LIMIT $1 OFFSET $2",
    )
    .bind(limit)
    .bind(offset)
    .fetch_all(&state.db)
    .await?;

    Ok(Json(rows))
}

async fn update_tenant(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(body): Json<UpdateTenantRequest>,
) -> Result<StatusCode, ApiError> {
    crate::middleware::auth::require_scopes(&auth, &["*"])?;
    let id = body.id;

    // Handle suspend/unsuspend action
    if let Some(action) = &body.action {
        let new_status = match action.as_str() {
            "suspend" => "suspended",
            "unsuspend" => "active",
            _ => return Err(ApiError::Validation(vec![format!("unknown action: {action}")])),
        };

        sqlx::query("UPDATE tenants SET status = $1, updated_at = NOW() WHERE id = $2")
            .bind(new_status)
            .bind(id)
            .execute(&state.db)
            .await?;

        // Audit log
        log_tenant_audit(&state, action, id).await;
        return Ok(StatusCode::OK);
    }

    // Direct field updates
    if let Some(name) = &body.name {
        sqlx::query("UPDATE tenants SET name = $1, updated_at = NOW() WHERE id = $2")
            .bind(name)
            .bind(id)
            .execute(&state.db)
            .await?;
    }
    if let Some(plan) = &body.plan {
        sqlx::query("UPDATE tenants SET plan = $1, updated_at = NOW() WHERE id = $2")
            .bind(plan)
            .bind(id)
            .execute(&state.db)
            .await?;
    }
    if let Some(status) = &body.status {
        sqlx::query("UPDATE tenants SET status = $1, updated_at = NOW() WHERE id = $2")
            .bind(status)
            .bind(id)
            .execute(&state.db)
            .await?;
    }

    Ok(StatusCode::OK)
}

#[derive(Debug, Deserialize)]
pub struct DeleteTenantRequest {
    pub id: Uuid,
}

async fn delete_tenant(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(body): Json<DeleteTenantRequest>,
) -> Result<StatusCode, ApiError> {
    crate::middleware::auth::require_scopes(&auth, &["*"])?;
    let id = body.id;

    let result = sqlx::query("DELETE FROM tenants WHERE id = $1")
        .bind(id)
        .execute(&state.db)
        .await?;

    if result.rows_affected() == 0 {
        return Err(ApiError::NotFound("tenant not found".into()));
    }

    log_tenant_audit(&state, "tenant_deleted", id).await;
    Ok(StatusCode::NO_CONTENT)
}

async fn log_tenant_audit(state: &AppState, action: &str, tenant_id: Uuid) {
    if let Err(e) = sqlx::query(
        "INSERT INTO audit_logs (timestamp, action, resource_type, resource_id, tenant_id, metadata)
         VALUES (NOW(), $1, 'tenant', $2, $2, '{}'::jsonb)",
    )
    .bind(action)
    .bind(tenant_id.to_string())
    .execute(&state.db)
    .await
    {
        tracing::warn!(tenant_id = %tenant_id, action = %action, error = %e, "Failed to write tenant audit log");
    }
}
