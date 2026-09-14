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

/// Secrets are unique per (tenant_id, name): a duplicate is an honest 409,
/// never a database 500.
fn map_secret_write_error(error: sqlx::Error) -> ApiError {
    if let sqlx::Error::Database(ref db_error) = error {
        if db_error.code().as_deref() == Some("23505") {
            return ApiError::Conflict("a secret with this name already exists".into());
        }
    }
    ApiError::from(error)
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
    let encrypted_value = match apexmail_lib::secret_at_rest::encrypt_at_rest(
        &generate_secret_value(),
        b"apexmail.secrets",
    ) {
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
    .await
    .map_err(map_secret_write_error)?;

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

// ─── Adversarial secret-vault tests ────────────────────────────

#[cfg(test)]
mod adversarial_tests {
    use super::*;

    fn auth_for(tenant: &str, scopes: &[&str]) -> AuthUser {
        AuthUser {
            tenant_id: tenant.to_string(),
            user_id: Some("usr_adv_secrets_0001".into()),
            api_key_id: None,
            session_id: None,
            scopes: scopes.iter().map(|s| s.to_string()).collect(),
        }
    }

    async fn state_and_pool(name: &str) -> Option<(AppState, sqlx::PgPool)> {
        let pool = crate::test_db::optional_pg_pool(name).await?;
        let state = crate::app::test_support::test_state_over(pool.clone()).await;
        Some((state, pool))
    }

    async fn seed_tenant(pool: &sqlx::PgPool, tenant: &str) {
        sqlx::query(
            "INSERT INTO tenants (id, name, plan, status, created_at, updated_at)
             VALUES ($1, 'secrets adversarial', 'free', 'active', NOW(), NOW())
             ON CONFLICT (id) DO NOTHING",
        )
        .bind(tenant)
        .execute(pool)
        .await
        .expect("seed tenant");
    }

    async fn cleanup(pool: &sqlx::PgPool, tenant: &str) {
        sqlx::query("DELETE FROM secret_versions WHERE secret_id IN (SELECT id FROM secrets WHERE tenant_id = $1)")
            .bind(tenant)
            .execute(pool)
            .await
            .ok();
        sqlx::query("DELETE FROM secrets WHERE tenant_id = $1")
            .bind(tenant)
            .execute(pool)
            .await
            .expect("cleanup secrets");
        sqlx::query("DELETE FROM secrets_archive WHERE tenant_id = $1")
            .bind(tenant)
            .execute(pool)
            .await
            .expect("cleanup archive");
        sqlx::query("DELETE FROM tenants WHERE id = $1")
            .bind(tenant)
            .execute(pool)
            .await
            .expect("cleanup tenant");
    }

    #[test]
    fn generated_secret_values_are_unique_hex_and_never_echoed_by_the_type() {
        let a = generate_secret_value();
        let b = generate_secret_value();
        assert_eq!(a.len(), 64);
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(a, b, "each secret gets fresh entropy");
        // The response type carries NO value/plaintext field at all.
        let response = SecretResponse {
            id: "sec_1".into(),
            name: "n".into(),
            secret_type: "api_key".into(),
            description: None,
            rotation_policy: "manual".into(),
            status: None,
            access_count: None,
            last_accessed: None,
            last_rotated: None,
            expires_at: None,
            created_at: "2026-01-01T00:00:00Z".into(),
            updated_at: "2026-01-01T00:00:00Z".into(),
        };
        let json = serde_json::to_value(&response).unwrap();
        for forbidden in ["value", "secret", "encryptedValue", "plaintext"] {
            assert!(
                json.get(forbidden).is_none(),
                "{forbidden} must never be serialized"
            );
        }
    }

    #[test]
    fn rotation_policies_move_next_rotation_or_stay_none() {
        assert_eq!(next_rotation_offset("manual"), None);
        assert_eq!(next_rotation_offset("yearly"), None);
        assert_eq!(next_rotation_offset(""), None);
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
    }

    #[tokio::test]
    async fn create_list_rotate_archive_with_tenant_isolation_and_redaction() {
        let Some((state, pool)) = state_and_pool("adv_secrets_crud").await else {
            return;
        };
        let tenant_a = apexmail_lib::id::generate_id("", 26);
        let tenant_b = apexmail_lib::id::generate_id("", 26);
        seed_tenant(&pool, &tenant_a).await;
        seed_tenant(&pool, &tenant_b).await;
        let tag = uuid::Uuid::new_v4().simple().to_string();
        let name = format!("adv-key-{tag}");

        // Validation: name shape, type, policy.
        for (bad_name, bad_type, bad_policy) in [
            ("", "api_key", "manual"),
            (&"x".repeat(101), "api_key", "manual"),
            ("has space", "api_key", "manual"),
            ("semi;colon", "api_key", "manual"),
            ("ok", "not_a_type", "manual"),
            ("ok", "api_key", "hourly"),
        ] {
            let resp = create_secret(
                State(state.clone()),
                auth_for(&tenant_a, &["*"]),
                Json(CreateSecretRequest {
                    name: bad_name.to_string(),
                    secret_type: bad_type.to_string(),
                    description: String::new(),
                    rotation_policy: bad_policy.to_string(),
                }),
            )
            .await;
            assert!(
                matches!(resp, Err(ApiError::Validation(_))),
                "({bad_name:?},{bad_type:?},{bad_policy:?}) must be refused"
            );
        }

        let (status, Json(created)) = create_secret(
            State(state.clone()),
            auth_for(&tenant_a, &["*"]),
            Json(CreateSecretRequest {
                name: name.clone(),
                secret_type: "api_key".into(),
                description: "adv fixture".into(),
                rotation_policy: "monthly".into(),
            }),
        )
        .await
        .expect("create secret");
        assert_eq!(status, StatusCode::CREATED);
        assert_eq!(created.name, name);
        assert_eq!(created.rotation_policy, "monthly");
        assert_eq!(created.description.as_deref(), Some("adv fixture"));
        assert!(created.status.is_none(), "no fabricated lifecycle status");
        assert!(created.access_count.is_none(), "no fabricated access count");
        // The generated plaintext never appears in any response.
        let response_json = serde_json::to_string(&created).unwrap();
        let stored_value: String =
            sqlx::query_scalar("SELECT encrypted_value FROM secrets WHERE id = $1")
                .bind(&created.id)
                .fetch_one(&pool)
                .await
                .expect("stored value");
        assert!(!response_json.contains(&stored_value));

        // Duplicate names for one tenant are an honest 409.
        let duplicate = create_secret(
            State(state.clone()),
            auth_for(&tenant_a, &["*"]),
            Json(CreateSecretRequest {
                name: name.clone(),
                secret_type: "api_key".into(),
                description: String::new(),
                rotation_policy: "manual".into(),
            }),
        )
        .await;
        assert!(
            matches!(duplicate, Err(ApiError::Conflict(_))),
            "duplicate secret name must conflict, got {duplicate:?}"
        );

        // The SAME name under another tenant is allowed (per-tenant uniqueness).
        let (_, Json(other)) = create_secret(
            State(state.clone()),
            auth_for(&tenant_b, &["*"]),
            Json(CreateSecretRequest {
                name: name.clone(),
                secret_type: "custom".into(),
                description: String::new(),
                rotation_policy: "manual".into(),
            }),
        )
        .await
        .expect("other tenant same name");

        // Listing is scoped: tenant A never sees tenant B's secret.
        let Json(list_a) = list_secrets(
            State(state.clone()),
            auth_for(&tenant_a, &["*"]),
            Query(SecretListQuery {
                limit: 200,
                offset: 0,
            }),
        )
        .await
        .expect("list a");
        assert!(list_a.iter().any(|s| s.id == created.id));
        assert!(
            list_a.iter().all(|s| s.id != other.id),
            "cross-tenant secret leaked"
        );
        // Pagination clamps are honoured.
        let Json(clamped) = list_secrets(
            State(state.clone()),
            auth_for(&tenant_a, &["*"]),
            Query(SecretListQuery {
                limit: i64::MIN,
                offset: -5,
            }),
        )
        .await
        .expect("clamped list");
        assert!(clamped.len() <= 1);

        // Rotate: version snapshot lands in secret_versions.
        let Json(rotated) = update_secret(
            State(state.clone()),
            auth_for(&tenant_a, &["*"]),
            Json(UpdateSecretRequest {
                id: created.id.clone(),
                action: "rotate".into(),
            }),
        )
        .await
        .expect("rotate");
        assert_eq!(rotated["success"], true);
        let (version,): (i32,) = sqlx::query_as("SELECT version FROM secrets WHERE id = $1")
            .bind(&created.id)
            .fetch_one(&pool)
            .await
            .expect("version");
        assert_eq!(version, 2);
        let snapshots: i64 =
            sqlx::query_scalar("SELECT COUNT(*)::bigint FROM secret_versions WHERE secret_id = $1")
                .bind(&created.id)
                .fetch_one(&pool)
                .await
                .expect("snapshots");
        assert!(snapshots >= 1);

        // Invalid action and cross-tenant rotation.
        assert!(matches!(
            update_secret(
                State(state.clone()),
                auth_for(&tenant_a, &["*"]),
                Json(UpdateSecretRequest {
                    id: created.id.clone(),
                    action: "explode".into()
                })
            )
            .await,
            Err(ApiError::Validation(_))
        ));
        let cross_rotate = update_secret(
            State(state.clone()),
            auth_for(&tenant_b, &["*"]),
            Json(UpdateSecretRequest {
                id: created.id.clone(),
                action: "rotate".into(),
            }),
        )
        .await;
        assert!(matches!(cross_rotate, Err(ApiError::NotFound(_))));

        // Revoke archives AND removes the live row; a second revoke is 404.
        let Json(revoked) = update_secret(
            State(state.clone()),
            auth_for(&tenant_a, &["*"]),
            Json(UpdateSecretRequest {
                id: created.id.clone(),
                action: "revoke".into(),
            }),
        )
        .await
        .expect("revoke");
        assert_eq!(revoked["status"], "revoked");
        let live: i64 = sqlx::query_scalar("SELECT COUNT(*)::bigint FROM secrets WHERE id = $1")
            .bind(&created.id)
            .fetch_one(&pool)
            .await
            .expect("live count");
        assert_eq!(live, 0);
        let archived: i64 =
            sqlx::query_scalar("SELECT COUNT(*)::bigint FROM secrets_archive WHERE id = $1")
                .bind(&created.id)
                .fetch_one(&pool)
                .await
                .expect("archive count");
        assert_eq!(archived, 1);
        assert!(matches!(
            update_secret(
                State(state.clone()),
                auth_for(&tenant_a, &["*"]),
                Json(UpdateSecretRequest {
                    id: created.id.clone(),
                    action: "revoke".into()
                })
            )
            .await,
            Err(ApiError::NotFound(_))
        ));

        // Delete via query param and via body; missing id is a validation error.
        let Json(deleted) = delete_secret(
            State(state.clone()),
            auth_for(&tenant_b, &["*"]),
            Query(DeleteSecretQuery {
                id: Some(other.id.clone()),
            }),
            None,
        )
        .await
        .expect("delete by query");
        assert_eq!(deleted["status"], "deleted");
        assert!(matches!(
            delete_secret(
                State(state.clone()),
                auth_for(&tenant_b, &["*"]),
                Query(DeleteSecretQuery { id: None }),
                None
            )
            .await,
            Err(ApiError::Validation(_))
        ));
        let (_, Json(extra)) = create_secret(
            State(state.clone()),
            auth_for(&tenant_b, &["*"]),
            Json(CreateSecretRequest {
                name: format!("body-delete-{tag}"),
                secret_type: "custom".into(),
                description: String::new(),
                rotation_policy: "manual".into(),
            }),
        )
        .await
        .expect("create for body delete");
        let Json(body_deleted) = delete_secret(
            State(state.clone()),
            auth_for(&tenant_b, &["*"]),
            Query(DeleteSecretQuery { id: None }),
            Some(Json(DeleteSecretBody {
                id: Some(extra.id.clone()),
            })),
        )
        .await
        .expect("delete by body");
        assert_eq!(body_deleted["success"], true);

        // Scope gate.
        assert!(matches!(
            list_secrets(
                State(state.clone()),
                auth_for(&tenant_a, &[]),
                Query(SecretListQuery {
                    limit: 10,
                    offset: 0
                })
            )
            .await,
            Err(ApiError::Forbidden(_))
        ));

        cleanup(&pool, &tenant_a).await;
        cleanup(&pool, &tenant_b).await;
    }

    #[test]
    fn unknown_fields_are_refused_on_secret_payloads() {
        assert!(serde_json::from_str::<CreateSecretRequest>(
            r#"{"name":"n","type":"api_key","tenantId":"other"}"#
        )
        .is_err());
        assert!(serde_json::from_str::<UpdateSecretRequest>(
            r#"{"id":"x","action":"rotate","extra":1}"#
        )
        .is_err());
        assert!(serde_json::from_str::<SecretListQuery>(r#"{"limit":1,"evil":true}"#).is_err());
        assert!(serde_json::from_str::<DeleteSecretQuery>(r#"{"id":"x","evil":1}"#).is_err());
    }
}
