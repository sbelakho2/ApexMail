//! Tenant management endpoints.
//!

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::routing::get;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::PgPool;

use crate::error::ApiError;
use crate::middleware::auth::AuthUser;
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new().route(
        "/",
        get(list_tenants).patch(update_tenant).delete(delete_tenant),
    )
}

// ─── Types ─────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ListTenantsQuery {
    #[serde(default = "default_limit")]
    pub limit: i64,
    #[serde(default)]
    pub offset: i64,
}

fn default_limit() -> i64 {
    50
}

const TENANT_SCOPED_TABLES_QUERY: &str = "
    SELECT DISTINCT columns.table_name
    FROM information_schema.columns AS columns
    JOIN information_schema.tables AS tables
      ON tables.table_schema = columns.table_schema
     AND tables.table_name = columns.table_name
    WHERE columns.table_schema = 'public'
      AND columns.column_name = 'tenant_id'
      AND columns.table_name <> 'tenants'
      AND tables.table_type = 'BASE TABLE'
    ORDER BY columns.table_name
";

pub async fn delete_tenant_records(db: &PgPool, tenant_id: &str) -> Result<bool, sqlx::Error> {
    let mut transaction = db.begin().await?;
    let mut pending_tables = sqlx::query_scalar::<_, String>(TENANT_SCOPED_TABLES_QUERY)
        .fetch_all(&mut *transaction)
        .await?;

    while !pending_tables.is_empty() {
        let pending_count = pending_tables.len();
        let mut blocked_tables = Vec::new();

        for table_name in pending_tables {
            let delete_query = format!(
                "DELETE FROM {} WHERE tenant_id::text = $1",
                quote_identifier(&table_name)
            );

            match sqlx::query(&delete_query)
                .bind(tenant_id)
                .execute(&mut *transaction)
                .await
            {
                Ok(_) => {}
                Err(error) if is_foreign_key_violation(&error) => blocked_tables.push(table_name),
                Err(error) => return Err(error),
            }
        }

        if blocked_tables.len() == pending_count {
            return Err(sqlx::Error::Protocol(format!(
                "could not resolve tenant cleanup order for tables: {}",
                blocked_tables.join(", ")
            )));
        }

        pending_tables = blocked_tables;
    }

    let result = sqlx::query("DELETE FROM tenants WHERE id = $1")
        .bind(tenant_id)
        .execute(&mut *transaction)
        .await?;

    transaction.commit().await?;
    Ok(result.rows_affected() > 0)
}

fn quote_identifier(identifier: &str) -> String {
    format!("\"{}\"", identifier.replace('"', "\"\""))
}

fn is_foreign_key_violation(error: &sqlx::Error) -> bool {
    matches!(
        error,
        sqlx::Error::Database(database_error)
            if database_error.code().as_deref() == Some("23503")
    )
}

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct TenantRow {
    pub id: String,
    pub name: String,
    pub slug: String,
    pub plan: String,
    pub status: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateTenantRequest {
    pub id: String,
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
            _ => {
                return Err(ApiError::Validation(vec![format!(
                    "unknown action: {action}"
                )]))
            }
        };

        sqlx::query("UPDATE tenants SET status = $1, updated_at = NOW() WHERE id = $2")
            .bind(new_status)
            .bind(&id)
            .execute(&state.db)
            .await?;

        // Audit log
        log_tenant_audit(&state, action, Some(&id)).await;
        return Ok(StatusCode::OK);
    }

    // Direct field updates
    if let Some(name) = &body.name {
        sqlx::query("UPDATE tenants SET name = $1, updated_at = NOW() WHERE id = $2")
            .bind(name)
            .bind(&id)
            .execute(&state.db)
            .await?;
    }
    if let Some(plan) = &body.plan {
        sqlx::query("UPDATE tenants SET plan = $1, updated_at = NOW() WHERE id = $2")
            .bind(plan)
            .bind(&id)
            .execute(&state.db)
            .await?;
    }
    if let Some(status) = &body.status {
        sqlx::query("UPDATE tenants SET status = $1, updated_at = NOW() WHERE id = $2")
            .bind(status)
            .bind(&id)
            .execute(&state.db)
            .await?;
    }

    Ok(StatusCode::OK)
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeleteTenantRequest {
    pub id: String,
    pub confirmation: String,
}

fn expected_delete_confirmation(tenant_id: &str) -> String {
    format!("DELETE {tenant_id}")
}

fn validate_delete_confirmation(tenant_id: &str, confirmation: &str) -> Result<(), ApiError> {
    let expected = expected_delete_confirmation(tenant_id);
    if confirmation.trim() != expected {
        return Err(ApiError::Validation(vec![format!(
            "confirmation must match '{expected}'"
        )]));
    }

    Ok(())
}

async fn delete_tenant(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(body): Json<DeleteTenantRequest>,
) -> Result<StatusCode, ApiError> {
    crate::middleware::auth::require_scopes(&auth, &["*"])?;
    validate_delete_confirmation(&body.id, &body.confirmation)?;
    let deleted = delete_tenant_records(&state.db, &body.id).await?;

    if !deleted {
        return Err(ApiError::NotFound("tenant not found".into()));
    }

    log_tenant_audit(&state, "tenant_deleted", None).await;
    Ok(StatusCode::NO_CONTENT)
}

async fn log_tenant_audit(state: &AppState, action: &str, tenant_id: Option<&str>) {
    let resource_id = tenant_id;
    let metadata = if tenant_id.is_some() {
        json!({})
    } else {
        json!({"redacted": true})
    };

    crate::audit_log::insert_audit_log_best_effort(
        &state.db,
        tenant_id,
        None,
        action,
        "tenant",
        resource_id,
        metadata,
        None,
        None,
    )
    .await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn delete_confirmation_requires_exact_tenant_phrase() {
        validate_delete_confirmation("tenant_123", "DELETE tenant_123")
            .expect("matching confirmation should be accepted");
    }

    #[test]
    fn delete_confirmation_rejects_missing_prefix() {
        assert!(matches!(
            validate_delete_confirmation("tenant_123", "tenant_123"),
            Err(ApiError::Validation(_))
        ));
    }

    #[test]
    fn delete_confirmation_rejects_other_tenant_ids() {
        assert!(matches!(
            validate_delete_confirmation("tenant_123", "DELETE tenant_456"),
            Err(ApiError::Validation(_))
        ));
    }
}
