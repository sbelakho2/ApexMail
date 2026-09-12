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

/// Actor-attributed feature-flag audit (P2-2): flag flips change platform
/// behaviour — the entry must record which operator did it, not `None`.
async fn log_feature_audit(
    state: &AppState,
    auth: &AuthUser,
    action: &str,
    feature_id: Uuid,
    metadata: serde_json::Value,
) {
    crate::audit_log::insert_audit_log_best_effort_with_env(
        &state.db,
        state.config.environment.is_production(),
        Some(auth.tenant_id.as_str()),
        auth.user_id.as_deref(),
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

    // A new row can change the resolved value for every tenant (a previously
    // unknown flag fell back to the caller default); drop cached entries now
    // so the create takes effect without waiting for the TTL.
    state.feature_flags.invalidate(&body.name);

    log_feature_audit(
        &state,
        &auth,
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

/// One statement per flag: COALESCE leaves omitted fields untouched,
/// `RETURNING id, name` makes a missing flag observable (rows-affected was
/// never checked, so updating a nonexistent UUID reported success), and the
/// whole batch runs in ONE transaction so a mid-batch failure cannot leave a
/// partial result. The name is returned so the runtime evaluation cache can
/// be invalidated for exactly the flipped flag.
const UPDATE_FEATURE_SQL: &str = "UPDATE feature_flags
     SET enabled = COALESCE($1, enabled),
         description = COALESCE($2, description),
         updated_at = NOW()
     WHERE id = $3
     RETURNING id, name";

pub(crate) async fn update_feature(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(body): Json<FeatureUpdatePayload>,
) -> Result<StatusCode, ApiError> {
    crate::middleware::auth::require_scopes(&auth, &["*"])?;
    crate::middleware::auth::require_system_tenant(&state, &auth).await?;

    let updates = normalize_feature_updates(body)?;

    let mut tx = state.db.begin().await?;
    let mut applied: Vec<(Uuid, String, serde_json::Value)> = Vec::new();

    for update in updates {
        let id = update.id;
        let updated: Option<(Uuid, String)> =
            sqlx::query_as::<_, (Uuid, String)>(UPDATE_FEATURE_SQL)
                .bind(update.enabled)
                .bind(update.description.as_deref())
                .bind(id)
                .fetch_optional(&mut *tx)
                .await?;

        let Some((updated_id, flag_name)) = updated else {
            // Dropping `tx` without commit rolls the whole batch back:
            // preceding flags in this batch keep their old values.
            return Err(ApiError::NotFound(format!("feature flag {id} not found")));
        };

        let mut changes = serde_json::Map::new();
        if let Some(enabled) = update.enabled {
            changes.insert("enabled".into(), json!(enabled));
        }
        if let Some(desc) = &update.description {
            changes.insert("description".into(), json!(desc));
        }
        applied.push((updated_id, flag_name, serde_json::Value::Object(changes)));
    }

    tx.commit().await?;

    // Invalidate only AFTER commit: a rolled-back batch must not evict a
    // cache entry that still reflects the committed database state.
    for (_, flag_name, _) in &applied {
        state.feature_flags.invalidate(flag_name);
    }

    // Audit only AFTER commit: a rolled-back batch must not leave
    // "updated" audit records for changes that never landed.
    for (id, _, changes) in applied {
        if changes.as_object().is_some_and(|fields| !fields.is_empty()) {
            log_feature_audit(&state, &auth, "control_plane.feature.updated", id, changes).await;
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

    /// Fix 8: one set-based statement per flag with COALESCE (omitted fields
    /// stay untouched) and RETURNING id (a missing flag is observable).
    #[test]
    fn batch_update_statement_is_coalesced_and_returns_the_id() {
        assert!(UPDATE_FEATURE_SQL.contains("COALESCE($1, enabled)"));
        assert!(UPDATE_FEATURE_SQL.contains("COALESCE($2, description)"));
        assert!(UPDATE_FEATURE_SQL.contains("RETURNING id"));
    }

    fn admin_auth() -> AuthUser {
        AuthUser {
            tenant_id: "system".into(),
            user_id: None,
            api_key_id: Some("test-static-key".into()),
            session_id: None,
            scopes: vec!["*".into()],
        }
    }

    async fn seed_flag(db: &sqlx::PgPool, enabled: bool) -> Uuid {
        let id = Uuid::new_v4();
        let name = format!("flag-{}", Uuid::new_v4().simple());
        sqlx::query(
            "INSERT INTO feature_flags (id, name, description, enabled, created_at, updated_at)
             VALUES ($1, $2, 'seed', $3, NOW(), NOW())",
        )
        .bind(id)
        .bind(&name)
        .bind(enabled)
        .execute(db)
        .await
        .expect("seed feature flag");
        id
    }

    /// Fix 8 (missing-id): updating a nonexistent UUID must be a 404, not a
    /// silent success.
    #[tokio::test]
    async fn update_of_missing_flag_returns_not_found() {
        let Some(pool) = crate::test_db::canonical_pool("features_missing_id").await else {
            return;
        };
        let state = crate::app::test_support::test_state_over(pool).await;

        let result = update_feature(
            State(state),
            admin_auth(),
            Json(FeatureUpdatePayload::Single(UpdateFeatureRequest {
                id: Uuid::new_v4(),
                enabled: Some(true),
                description: None,
            })),
        )
        .await;

        assert!(
            matches!(result, Err(ApiError::NotFound(_))),
            "a nonexistent feature id must surface as 404"
        );
    }

    /// Fix 8 (partial failure): when a later id in the batch is missing, the
    /// earlier update must roll back — never a partially applied batch.
    #[tokio::test]
    async fn batch_update_rolls_back_on_a_missing_id() {
        let Some(pool) = crate::test_db::canonical_pool("features_batch_rollback").await else {
            return;
        };
        let state = crate::app::test_support::test_state_over(pool.clone()).await;
        let existing = seed_flag(&pool, false).await;
        let missing = Uuid::new_v4();

        let result = update_feature(
            State(state),
            admin_auth(),
            Json(FeatureUpdatePayload::Batch(BatchUpdateFeatureRequest {
                updates: vec![
                    UpdateFeatureRequest {
                        id: existing,
                        enabled: Some(true),
                        description: None,
                    },
                    UpdateFeatureRequest {
                        id: missing,
                        enabled: Some(true),
                        description: None,
                    },
                ],
            })),
        )
        .await;
        assert!(matches!(result, Err(ApiError::NotFound(_))));

        let enabled: bool = sqlx::query_scalar("SELECT enabled FROM feature_flags WHERE id = $1")
            .bind(existing)
            .fetch_one(&pool)
            .await
            .expect("read flag");
        assert!(
            !enabled,
            "the preceding update must be rolled back with the failed batch"
        );

        // The rolled-back batch leaves no "updated" audit record.
        let audits: i64 = sqlx::query_scalar(
            "SELECT COUNT(*)::bigint FROM audit_logs
             WHERE action = 'control_plane.feature.updated' AND resource_id = $1",
        )
        .bind(existing.to_string())
        .fetch_one(&pool)
        .await
        .expect("read audit log");
        assert_eq!(
            audits, 0,
            "rolled-back changes must not be audited as applied"
        );
    }
}
