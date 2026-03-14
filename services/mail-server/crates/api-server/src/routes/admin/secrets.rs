//! Secrets management endpoints.
//!
//! Migrated from: apps/control-plane/src/app/api/secrets/route.ts

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::routing::get;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use crate::error::ApiError;
use crate::middleware::auth::AuthUser;
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new().route("/", get(list_secrets).post(create_secret).patch(update_secret).delete(delete_secret))
}

#[derive(Debug, Serialize, sqlx::FromRow)]
struct SecretRow {
    id: String,
    name: String,
    #[sqlx(rename = "type")]
    secret_type: String,
    description: String,
    rotation_policy: String,
    status: String,
    access_count: i64,
    last_accessed: Option<chrono::DateTime<chrono::Utc>>,
    last_rotated: chrono::DateTime<chrono::Utc>,
    expires_at: Option<chrono::DateTime<chrono::Utc>>,
    created_at: chrono::DateTime<chrono::Utc>,
    updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SecretResponse {
    pub id: String,
    pub name: String,
    #[serde(rename = "type")]
    pub secret_type: String,
    pub description: String,
    pub rotation_policy: String,
    pub status: String,
    pub access_count: i64,
    pub last_accessed: Option<String>,
    pub last_rotated: String,
    pub expires_at: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

impl From<SecretRow> for SecretResponse {
    fn from(r: SecretRow) -> Self {
        Self {
            id: r.id,
            name: r.name,
            secret_type: r.secret_type,
            description: r.description,
            rotation_policy: r.rotation_policy,
            status: r.status,
            access_count: r.access_count,
            last_accessed: r.last_accessed.map(|t| t.to_rfc3339()),
            last_rotated: r.last_rotated.to_rfc3339(),
            expires_at: r.expires_at.map(|t| t.to_rfc3339()),
            created_at: r.created_at.to_rfc3339(),
            updated_at: r.updated_at.to_rfc3339(),
        }
    }
}

async fn log_secret_audit(db: &sqlx::PgPool, action: &str, secret_id: &str, metadata: serde_json::Value) {
    if let Err(e) = sqlx::query(
        "INSERT INTO audit_logs (timestamp, action, resource_type, resource_id, metadata)
         VALUES (NOW(), $1, 'secret', $2, $3::jsonb)",
    )
    .bind(action)
    .bind(secret_id)
    .bind(metadata)
    .execute(db)
    .await
    {
        tracing::warn!(secret_id = %secret_id, action = %action, error = %e, "Failed to write secret audit log");
    }
}

async fn list_secrets(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<Json<Vec<SecretResponse>>, ApiError> {
    crate::middleware::auth::require_scopes(&auth, &["*"])?;

    let rows = sqlx::query_as::<_, SecretRow>(
        "SELECT id, name, type, description, rotation_policy, status,
                access_count, last_accessed, last_rotated, expires_at,
                created_at, updated_at
         FROM secrets ORDER BY created_at DESC",
    )
    .fetch_all(&state.db)
    .await?;

    Ok(Json(rows.into_iter().map(SecretResponse::from).collect()))
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateSecretRequest {
    pub name: String,
    #[serde(rename = "type")]
    pub secret_type: String,
    #[serde(default)]
    pub description: String,
    #[serde(default = "default_rotation")]
    pub rotation_policy: String,
}

fn default_rotation() -> String {
    "manual".into()
}

async fn create_secret(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(body): Json<CreateSecretRequest>,
) -> Result<(StatusCode, Json<SecretResponse>), ApiError> {
    crate::middleware::auth::require_scopes(&auth, &["*"])?;

    // Validate name
    if body.name.is_empty() || body.name.len() > 100 {
        return Err(ApiError::Validation(vec!["Name must be 1-100 characters".into()]));
    }
    if !body.name.chars().all(|c| c.is_alphanumeric() || c == '_' || c == '-') {
        return Err(ApiError::Validation(vec![
            "Name must contain only alphanumeric characters, underscores, and hyphens".into(),
        ]));
    }

    let allowed_types = ["api_key", "oauth_secret", "encryption_key", "signing_key", "custom"];
    if !allowed_types.contains(&body.secret_type.as_str()) {
        return Err(ApiError::Validation(vec!["Invalid secret type".into()]));
    }

    let allowed_policies = ["manual", "daily", "weekly", "monthly"];
    if !allowed_policies.contains(&body.rotation_policy.as_str()) {
        return Err(ApiError::Validation(vec!["Invalid rotation policy".into()]));
    }

    let row = sqlx::query_as::<_, SecretRow>(
        "INSERT INTO secrets (name, type, description, rotation_policy, status)
         VALUES ($1, $2, $3, $4, 'active')
         RETURNING id, name, type, description, rotation_policy, status,
                   access_count, last_accessed, last_rotated, expires_at,
                   created_at, updated_at",
    )
    .bind(&body.name)
    .bind(&body.secret_type)
    .bind(&body.description)
    .bind(&body.rotation_policy)
    .fetch_one(&state.db)
    .await?;

    log_secret_audit(
        &state.db,
        "control_plane.secret.created",
        &row.id,
        serde_json::json!({ "type": body.secret_type, "name": body.name }),
    )
    .await;

    Ok((StatusCode::CREATED, Json(SecretResponse::from(row))))
}

#[derive(Debug, Deserialize)]
pub struct UpdateSecretRequest {
    pub id: String,
    pub action: String,
}

async fn update_secret(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(body): Json<UpdateSecretRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    crate::middleware::auth::require_scopes(&auth, &["*"])?;

    match body.action.as_str() {
        "rotate" => {
            let result = sqlx::query_scalar::<_, chrono::DateTime<chrono::Utc>>(
                "UPDATE secrets SET last_rotated = NOW(), status = 'active', updated_at = NOW()
                 WHERE id = $1 RETURNING last_rotated",
            )
            .bind(&body.id)
            .fetch_optional(&state.db)
            .await?;

            match result {
                Some(last_rotated) => {
                    log_secret_audit(
                        &state.db,
                        "control_plane.secret.rotated",
                        &body.id,
                        serde_json::json!({}),
                    )
                    .await;
                    Ok(Json(serde_json::json!({
                        "success": true,
                        "message": format!("Secret {} rotated", body.id),
                        "lastRotated": last_rotated.to_rfc3339(),
                        "status": "active"
                    })))
                }
                None => Err(ApiError::NotFound("Secret not found".into())),
            }
        }
        "revoke" => {
            let result = sqlx::query(
                "UPDATE secrets SET status = 'revoked', updated_at = NOW()
                 WHERE id = $1 RETURNING id",
            )
            .bind(&body.id)
            .fetch_optional(&state.db)
            .await?;

            if result.is_none() {
                return Err(ApiError::NotFound("Secret not found".into()));
            }

            log_secret_audit(
                &state.db,
                "control_plane.secret.revoked",
                &body.id,
                serde_json::json!({}),
            )
            .await;

            Ok(Json(serde_json::json!({
                "success": true,
                "message": format!("Secret {} revoked", body.id),
                "status": "revoked"
            })))
        }
        _ => Err(ApiError::Validation(vec!["Invalid action".into()])),
    }
}

#[derive(Debug, Deserialize)]
pub struct DeleteSecretQuery {
    pub id: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct DeleteSecretBody {
    pub id: Option<String>,
}

async fn delete_secret(
    State(state): State<AppState>,
    auth: AuthUser,
    Query(query): Query<DeleteSecretQuery>,
    body: Option<Json<DeleteSecretBody>>,
) -> Result<Json<serde_json::Value>, ApiError> {
    crate::middleware::auth::require_scopes(&auth, &["*"])?;

    let id = body
        .and_then(|b| b.id.clone())
        .or(query.id)
        .ok_or_else(|| ApiError::Validation(vec!["Secret ID is required".into()]))?;

    let result = sqlx::query("DELETE FROM secrets WHERE id = $1 RETURNING id")
        .bind(&id)
        .fetch_optional(&state.db)
        .await?;

    if result.is_none() {
        return Err(ApiError::NotFound("Secret not found".into()));
    }

    log_secret_audit(
        &state.db,
        "control_plane.secret.deleted",
        &id,
        serde_json::json!({}),
    )
    .await;

    Ok(Json(serde_json::json!({
        "success": true,
        "message": format!("Secret {} deleted", id)
    })))
}
