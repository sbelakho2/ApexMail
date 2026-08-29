//! Feature flag management endpoints.
//!

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::routing::get;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use serde_json::json;
use uuid::Uuid;

use crate::error::ApiError;
use crate::middleware::auth::AuthUser;
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new().route(
        "/",
        get(list_features)
            .post(create_feature)
            .patch(update_feature),
    )
}

async fn log_feature_audit(
    db: &sqlx::PgPool,
    action: &str,
    feature_id: Uuid,
    metadata: serde_json::Value,
) {
    crate::audit_log::insert_audit_log_best_effort(
        db,
        None,
        None,
        action,
        "feature_flag",
        Some(&feature_id.to_string()),
        metadata,
        None,
        None,
    )
    .await;
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
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FeatureListQuery {
    #[serde(default = "default_limit")]
    pub limit: i64,
    #[serde(default)]
    pub offset: i64,
}

fn default_limit() -> i64 {
    50
}

fn build_list_features_sql() -> &'static str {
    "SELECT id, name, description, enabled, created_at, updated_at
     FROM feature_flags ORDER BY name ASC
     LIMIT $1 OFFSET $2"
}

fn build_list_feature_overrides_sql() -> &'static str {
    "SELECT row_to_json(fo) FROM feature_flag_overrides fo ORDER BY created_at DESC
     LIMIT $1 OFFSET $2"
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateFeatureRequest {
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub enabled: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateFeatureRequest {
    pub id: Uuid,
    #[serde(default)]
    pub enabled: Option<bool>,
    #[serde(default)]
    pub description: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BatchUpdateFeatureRequest {
    pub updates: Vec<UpdateFeatureRequest>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum FeatureUpdatePayload {
    Single(UpdateFeatureRequest),
    Batch(BatchUpdateFeatureRequest),
}

fn normalize_feature_updates(
    payload: FeatureUpdatePayload,
) -> Result<Vec<UpdateFeatureRequest>, ApiError> {
    let updates = match payload {
        FeatureUpdatePayload::Single(update) => vec![update],
        FeatureUpdatePayload::Batch(batch) => batch.updates,
    };

    if updates.is_empty() {
        return Err(ApiError::Validation(vec![
            "at least one feature update is required".into(),
        ]));
    }

    Ok(updates)
}

async fn list_features(
    State(state): State<AppState>,
    auth: AuthUser,
    Query(params): Query<FeatureListQuery>,
) -> Result<Json<FeaturesResponse>, ApiError> {
    crate::middleware::auth::require_scopes(&auth, &["*"])?;
    crate::middleware::auth::require_system_tenant(&state, &auth).await?;

    let limit = params.limit.clamp(1, 200);
    let offset = params.offset.max(0);

    let flags = sqlx::query_as::<_, FeatureFlag>(build_list_features_sql())
        .bind(limit)
        .bind(offset)
        .fetch_all(&state.db)
        .await?;

    let overrides: Vec<serde_json::Value> = sqlx::query_scalar(build_list_feature_overrides_sql())
        .bind(limit)
        .bind(offset)
        .fetch_all(&state.db)
        .await?;

    Ok(Json(FeaturesResponse { flags, overrides }))
}

async fn create_feature(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(body): Json<CreateFeatureRequest>,
) -> Result<(StatusCode, Json<FeatureFlag>), ApiError> {
    crate::middleware::auth::require_scopes(&auth, &["*"])?;
    crate::middleware::auth::require_system_tenant(&state, &auth).await?;

    if body.name.is_empty() || body.name.len() > 100 {
        return Err(ApiError::Validation(vec![
            "name must be 1-100 characters".into()
        ]));
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

    log_feature_audit(
        &state.db,
        "control_plane.feature.created",
        id,
        json!({
            "name": body.name,
            "enabled": body.enabled,
            "description": body.description,
        }),
    )
    .await;

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
    Json(body): Json<FeatureUpdatePayload>,
) -> Result<StatusCode, ApiError> {
    crate::middleware::auth::require_scopes(&auth, &["*"])?;
    crate::middleware::auth::require_system_tenant(&state, &auth).await?;
    for update in normalize_feature_updates(body)? {
        let id = update.id;
        let mut changes = serde_json::Map::new();

        if let Some(enabled) = update.enabled {
            sqlx::query("UPDATE feature_flags SET enabled = $1, updated_at = NOW() WHERE id = $2")
                .bind(enabled)
                .bind(id)
                .execute(&state.db)
                .await?;
            changes.insert("enabled".into(), json!(enabled));
        }
        if let Some(desc) = &update.description {
            sqlx::query(
                "UPDATE feature_flags SET description = $1, updated_at = NOW() WHERE id = $2",
            )
            .bind(desc)
            .bind(id)
            .execute(&state.db)
            .await?;
            changes.insert("description".into(), json!(desc));
        }

        if !changes.is_empty() {
            log_feature_audit(
                &state.db,
                "control_plane.feature.updated",
                id,
                serde_json::Value::Object(changes),
            )
            .await;
        }
    }

    Ok(StatusCode::OK)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_list_features_sql_paginates_results() {
        let sql = build_list_features_sql();

        assert!(sql.contains("LIMIT $1 OFFSET $2"));
    }

    #[test]
    fn build_list_feature_overrides_sql_paginates_results() {
        let sql = build_list_feature_overrides_sql();

        assert!(sql.contains("LIMIT $1 OFFSET $2"));
    }

    #[test]
    fn normalize_feature_updates_accepts_batch_payloads() {
        let payload = FeatureUpdatePayload::Batch(BatchUpdateFeatureRequest {
            updates: vec![UpdateFeatureRequest {
                id: Uuid::nil(),
                enabled: Some(true),
                description: None,
            }],
        });

        let updates = normalize_feature_updates(payload).expect("batch payload should normalize");

        assert_eq!(updates.len(), 1);
        assert_eq!(updates[0].id, Uuid::nil());
        assert_eq!(updates[0].enabled, Some(true));
    }
}
