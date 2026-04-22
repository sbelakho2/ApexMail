//! Feature flag management endpoints.
//!
//! Migrated from:apps/control-plane/src/app/api/features/route.ts

use axum::extract::State;
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
        .route("/", get(list_features).post(create_feature).patch(update_feature))
}

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct FeatureFlag {
    pub id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub enabled: bool,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Serialize)]
pub struct FeaturesResponse {
    pub flags: Vec<FeatureFlag>,
    pub overrides: Vec<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
pub struct CreateFeatureRequest {
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub enabled: bool,
}

#[derive(Debug, Deserialize)]
pub struct UpdateFeatureRequest {
    pub id: Uuid,
    #[serde(default)]
    pub enabled: Option<bool>,
    #[serde(default)]
    pub description: Option<String>,
}

async fn list_features(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<Json<FeaturesResponse>, ApiError> {
    crate::middleware::auth::require_scopes(&auth, &["*"])?;

    let flags = sqlx::query_as::<_, FeatureFlag>(
        "SELECT id, name, description, enabled, created_at, updated_at
         FROM feature_flags ORDER BY name ASC",
    )
    .fetch_all(&state.db)
    .await
    ?;

    let overrides: Vec<serde_json::Value> = sqlx::query_scalar(
        "SELECT row_to_json(fo) FROM feature_flag_overrides fo ORDER BY created_at DESC",
    )
    .fetch_all(&state.db)
    .await
    ?;

    Ok(Json(FeaturesResponse { flags, overrides }))
}

async fn create_feature(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(body): Json<CreateFeatureRequest>,
) -> Result<(StatusCode, Json<FeatureFlag>), ApiError> {
    crate::middleware::auth::require_scopes(&auth, &["*"])?;

    if body.name.is_empty() || body.name.len() > 100 {
        return Err(ApiError::Validation(vec!["name must be 1-100 characters".into()]));
    }

    let id = Uuid::new_v4();
    let now = chrono::Utc::now();

    sqlx::query(
        "INSERT INTO feature_flags (id, name, description, enabled, created_at, updated_at)
         VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(id)
    .bind(&body.name)
    .bind(&body.description)
    .bind(body.enabled)
    .bind(now)
    .bind(now)
    .execute(&state.db)
    .await?;

    Ok((
        StatusCode::CREATED,
        Json(FeatureFlag {
            id,
            name: body.name,
            description: body.description,
            enabled: body.enabled,
            created_at: now,
            updated_at: now,
        }),
    ))
}

async fn update_feature(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(body): Json<UpdateFeatureRequest>,
) -> Result<StatusCode, ApiError> {
    crate::middleware::auth::require_scopes(&auth, &["*"])?;
    let id = body.id;

    if let Some(enabled) = body.enabled {
        sqlx::query("UPDATE feature_flags SET enabled = $1, updated_at = NOW() WHERE id = $2")
            .bind(enabled)
            .bind(id)
            .execute(&state.db)
            .await?;
    }
    if let Some(desc) = &body.description {
        sqlx::query("UPDATE feature_flags SET description = $1, updated_at = NOW() WHERE id = $2")
            .bind(desc)
            .bind(id)
            .execute(&state.db)
            .await?;
    }

    Ok(StatusCode::OK)
}
