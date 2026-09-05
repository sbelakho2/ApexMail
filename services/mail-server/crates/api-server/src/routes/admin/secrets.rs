//! Secrets management endpoints.
//!
//! Aligned with the canonical secrets schema (migration 038):
//! secrets(id, tenant_id, name, type, encrypted_value, version,
//! rotation_schedule, last_rotated_at, next_rotation_at, created_by,
//! created_at, updated_at, expires_at) + secrets_archive + secret_versions.
//! The previous implementation targeted columns (description, rotation_policy,
//! status, access_count, last_accessed) that never existed on production.

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::routing::get;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use crate::error::ApiError;
use crate::middleware::auth::AuthUser;
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new().route(
        "/",
        get(list_secrets)
            .post(create_secret)
            .patch(update_secret)
            .delete(delete_secret),
    )
}

#[derive(Debug, Serialize, sqlx::FromRow)]
struct SecretRow {
    id: String,
    name: String,
    #[sqlx(rename = "type")]
    secret_type: String,
    description: Option<String>,
    rotation_policy: String,
    /// The canonical schema (migration 038) has no lifecycle `status`
    /// column — revoked secrets leave this table for `secrets_archive`.
    /// `None` is the honest value; the previous `'active'` literal asserted
    /// a fact nothing in the database backs.
    status: Option<String>,
    /// No access counter exists on the canonical table — `None`, never a
    /// fabricated zero that reads as "never accessed but tracked".
    access_count: Option<i64>,
    last_accessed: Option<chrono::DateTime<chrono::Utc>>,
    last_rotated: Option<chrono::DateTime<chrono::Utc>>,
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
    pub description: Option<String>,
    pub rotation_policy: String,
    pub status: Option<String>,
    pub access_count: Option<i64>,
    pub last_accessed: Option<String>,
    pub last_rotated: Option<String>,
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
            last_rotated: r.last_rotated.map(|t| t.to_rfc3339()),
            expires_at: r.expires_at.map(|t| t.to_rfc3339()),
            created_at: r.created_at.to_rfc3339(),
            updated_at: r.updated_at.to_rfc3339(),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SecretListQuery {
    #[serde(default = "default_limit")]
    pub limit: i64,
    #[serde(default)]
    pub offset: i64,
}

fn default_limit() -> i64 {
    50
}

/// Canonical list query: `description` comes from the stored
/// `rotation_schedule` JSONB (where create_secret puts it); the fields the
/// canonical table does not carry (`status`, `access_count`,
/// `last_accessed`) surface as honest SQL NULLs — never fabricated
/// constants that assert facts the database cannot back.
fn build_list_secrets_sql() -> &'static str {
    // RS-050: Scoped by tenant_id to prevent cross-tenant secret exposure.
    "SELECT id, name, type,
            rotation_schedule->>'description' AS description,
            COALESCE(rotation_schedule->>'policy', 'manual') AS rotation_policy,
            NULL::text AS status,
            NULL::bigint AS access_count,
            NULL::timestamptz AS last_accessed,
            last_rotated_at AS last_rotated, expires_at,
            created_at, updated_at
     FROM secrets WHERE tenant_id = $3
     ORDER BY created_at DESC
     LIMIT $1 OFFSET $2"
}

/// Actor-attributed secret audit (P2-2): secret lifecycle mutations record
/// the acting operator's tenant AND user id, not `None, None`.
async fn log_secret_audit(
    state: &AppState,
    auth: &AuthUser,
    action: &str,
    secret_id: &str,
    metadata: serde_json::Value,
) {
    crate::audit_log::insert_audit_log_best_effort_with_env(
        &state.db,
        state.config.environment.is_production(),
        Some(auth.tenant_id.as_str()),
        auth.user_id.as_deref(),
        action,
        "secret",
        Some(secret_id),
        metadata,
        None,
        None,
    )
    .await;
}

async fn list_secrets(
    State(state): State<AppState>,
    auth: AuthUser,
    Query(params): Query<SecretListQuery>,
) -> Result<Json<Vec<SecretResponse>>, ApiError> {
    crate::middleware::auth::require_scopes(&auth, &["*"])?;

    let limit = params.limit.clamp(1, 200);
    let offset = params.offset.max(0);

    // RS-050: Bind tenant_id from authenticated session, not user input.
    let rows = sqlx::query_as::<_, SecretRow>(build_list_secrets_sql())
        .bind(limit)
        .bind(offset)
        .bind(&auth.tenant_id)
        .fetch_all(&state.db)
        .await?;

    Ok(Json(rows.into_iter().map(SecretResponse::from).collect()))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
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

/// Rotation interval per policy, used to compute `next_rotation_at`.
fn next_rotation_offset(policy: &str) -> Option<chrono::Duration> {
    match policy {
        "daily" => Some(chrono::Duration::days(1)),
        "weekly" => Some(chrono::Duration::weeks(1)),
        "monthly" => Some(chrono::Duration::days(30)),
        _ => None,
    }
}

fn generate_secret_value() -> String {
    use rand::RngCore;
    let mut buf = [0u8; 32];
    rand::rng().fill_bytes(&mut buf);
    hex::encode(buf)
}

async fn create_secret(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(body): Json<CreateSecretRequest>,
) -> Result<(StatusCode, Json<SecretResponse>), ApiError> {
    crate::middleware::auth::require_scopes(&auth, &["*"])?;

    // Validate name
    if body.name.is_empty() || body.name.len() > 100 {
        return Err(ApiError::Validation(vec![
            "Name must be 1-100 characters".into()
        ]));
    }
    if !body
        .name
        .chars()
        .all(|c| c.is_alphanumeric() || c == '_' || c == '-')
    {
        return Err(ApiError::Validation(vec![
            "Name must contain only alphanumeric characters, underscores, and hyphens".into(),
        ]));
    }

    let allowed_types = [
        "api_key",
        "oauth_secret",
        "encryption_key",
        "signing_key",
        "custom",
    ];
    if !allowed_types.contains(&body.secret_type.as_str()) {
        return Err(ApiError::Validation(vec!["Invalid secret type".into()]));
    }

    let allowed_policies = ["manual", "daily", "weekly", "monthly"];
    if !allowed_policies.contains(&body.rotation_policy.as_str()) {
        return Err(ApiError::Validation(vec!["Invalid rotation policy".into()]));
    }

    let id = apexmail_lib::id::generate_id("sec", 22);
    let created_by = auth.user_id.clone().unwrap_or_else(|| "system".to_string());
    // Production refuses the plaintext fallback LOUDLY (audit P1): an unset
    // encryption key used to silently store `plain:`-marked secrets —
    // at-rest protection that exists only in the label. Non-production
    // keeps the marked fallback with a warning so local flows stay usable.
    let encrypted_value =
        match apexmail_lib::secret_at_rest::encrypt_at_rest(&generate_secret_value(), b"apexmail.secrets") {
            Ok(encrypted) => encrypted,
            Err(error) => {
                if state.config.environment.is_production() {
                    tracing::error!(
                        error = %error,
                        "secret encryption key unset in production — refusing plaintext fallback"
                    );
                    return Err(ApiError::Internal(
                        "secret encryption is not configured; refusing to store plaintext".into(),
                    ));
                }
                tracing::warn!(
                    error = %error,
                    "secret encryption key unset (non-production) — storing plaintext-marked secret"
                );
                format!("plain:{}", generate_secret_value())
            }
        };
    let next_rotation_at =
        next_rotation_offset(&body.rotation_policy).map(|d| chrono::Utc::now() + d);
    let rotation_schedule =
        serde_json::json!({ "policy": body.rotation_policy, "description": body.description });

    // RS-050: Include tenant_id from authenticated session in INSERT. The
    // RETURNING shape mirrors the honest list query (no fabricated columns).
    let row = sqlx::query_as::<_, SecretRow>(
        "INSERT INTO secrets (
            id, tenant_id, name, type, encrypted_value, version, rotation_schedule,
            last_rotated_at, next_rotation_at, created_by, created_at, updated_at
         ) VALUES ($1, $2, $3, $4, $5, 1, $6, NOW(), $7, $8, NOW(), NOW())
         RETURNING id, name, type,
                   rotation_schedule->>'description' AS description,
                   COALESCE(rotation_schedule->>'policy', 'manual') AS rotation_policy,
                   NULL::text AS status,
                   NULL::bigint AS access_count,
                   NULL::timestamptz AS last_accessed,
                   last_rotated_at AS last_rotated, expires_at,
                   created_at, updated_at",
    )
    .bind(&id)
    .bind(&auth.tenant_id)
    .bind(&body.name)
    .bind(&body.secret_type)
    .bind(&encrypted_value)
    .bind(&rotation_schedule)
    .bind(next_rotation_at)
    .bind(&created_by)
    .fetch_one(&state.db)
    .await?;

    log_secret_audit(
        &state,
        &auth,
        "control_plane.secret.created",
        &row.id,
        serde_json::json!({ "type": body.secret_type, "name": body.name }),
    )
    .await;

    Ok((StatusCode::CREATED, Json(SecretResponse::from(row))))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
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
            // RS-050: Scope rotate by tenant_id to prevent cross-tenant modification.
            let row: Option<(String, chrono::DateTime<chrono::Utc>)> = sqlx::query_as(
                    r#"
                    WITH rotated AS (
                        UPDATE secrets
                        SET version = version + 1,
                            last_rotated_at = NOW(),
                            next_rotation_at = CASE COALESCE(rotation_schedule->>'policy', 'manual')
                                WHEN 'daily' THEN NOW() + INTERVAL '1 day'
                                WHEN 'weekly' THEN NOW() + INTERVAL '7 days'
                                WHEN 'monthly' THEN NOW() + INTERVAL '30 days'
                                ELSE NULL END,
                            updated_at = NOW()
                        WHERE id = $1 AND tenant_id = $2
                        RETURNING id, version, encrypted_value, last_rotated_at
                    ),
                    snapshot AS (
                        INSERT INTO secret_versions (secret_id, version, encrypted_value, created_at)
                        SELECT id, version, encrypted_value, NOW() FROM rotated
                        ON CONFLICT (secret_id, version) DO NOTHING
                    )
                    SELECT id, last_rotated_at FROM rotated
                    "#,
                )
                .bind(&body.id)
                .bind(&auth.tenant_id)
                .fetch_optional(&state.db)
                .await?;

            match row {
                Some((id, last_rotated)) => {
                    log_secret_audit(
                        &state,
                        &auth,
                        "control_plane.secret.rotated",
                        &body.id,
                        serde_json::json!({}),
                    )
                    .await;
                    Ok(Json(serde_json::json!({
                        "success": true,
                        "message": format!("Secret {id} rotated"),
                        "lastRotated": last_rotated.to_rfc3339(),
                        "status": "active"
                    })))
                }
                None => Err(ApiError::NotFound("Secret not found".into())),
            }
        }
        "revoke" => archive_and_delete(&state, &auth, &body.id, "revoked").await,
        _ => Err(ApiError::Validation(vec!["Invalid action".into()])),
    }
}

/// Canonical lifecycle: archived copies move to `secrets_archive`, the live
/// row is removed (the canonical schema has no `status` column).
async fn archive_and_delete(
    state: &AppState,
    auth: &AuthUser,
    id: &str,
    reason: &str,
) -> Result<Json<serde_json::Value>, ApiError> {
    let mut tx = state.db.begin().await?;

    let row: Option<String> = sqlx::query_scalar(
        r#"
        WITH archived AS (
            INSERT INTO secrets_archive
            SELECT * FROM secrets WHERE id = $1 AND tenant_id = $2
            RETURNING id
        )
        SELECT id FROM archived
        "#,
    )
    .bind(id)
    .bind(&auth.tenant_id)
    .fetch_optional(&mut *tx)
    .await?;

    if row.is_none() {
        tx.rollback().await?;
        return Err(ApiError::NotFound("Secret not found".into()));
    }

    sqlx::query("DELETE FROM secrets WHERE id = $1 AND tenant_id = $2")
        .bind(id)
        .bind(&auth.tenant_id)
        .execute(&mut *tx)
        .await?;

    tx.commit().await?;

    log_secret_audit(
        state,
        auth,
        &format!("control_plane.secret.{reason}"),
        id,
        serde_json::json!({}),
    )
    .await;

    Ok(Json(serde_json::json!({
        "success": true,
        "message": format!("Secret {id} {reason}"),
        "status": reason
    })))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeleteSecretQuery {
    pub id: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
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

    archive_and_delete(&state, &auth, &id, "deleted").await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_list_secrets_sql_paginates_results() {
        let sql = build_list_secrets_sql();

        assert!(sql.contains("LIMIT $1 OFFSET $2"));
        assert!(
            sql.contains("WHERE tenant_id = $3"),
            "list_secrets must scope by tenant_id"
        );
    }

    #[test]
    fn rotation_offset_matches_policies() {
        assert_eq!(
            next_rotation_offset("daily"),
            Some(chrono::Duration::days(1))
        );
        assert_eq!(
            next_rotation_offset("weekly"),
            Some(chrono::Duration::weeks(1))
        );
        assert_eq!(
            next_rotation_offset("monthly"),
            Some(chrono::Duration::days(30))
        );
        assert_eq!(next_rotation_offset("manual"), None);
    }
}
