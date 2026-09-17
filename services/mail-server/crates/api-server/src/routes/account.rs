//! Account management routes:profile, delete account.

use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::{delete, get};
use axum::{Json, Router};
use chrono::Utc;
use serde::{Deserialize, Serialize};

use crate::error::ApiError;
use crate::middleware::auth::{invalidate_tenant_user_status_cache, AuthUser};
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/profile", get(get_profile))
        .route("/", delete(delete_account))
}

// ─── Request / Response types ──────────────────────────────────

#[derive(Debug, Serialize)]
pub struct ProfileResponse {
    pub user_id: String,
    pub tenant_id: String,
    pub email: String,
    pub name: Option<String>,
    pub role: String,
    pub created_at: chrono::DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeleteAccountRequest {
    /// Current password for verification
    pub password: String,
    /// Confirmation phrase (e.g., "DELETE MY ACCOUNT")
    pub confirmation: String,
    /// Optional reason for leaving
    pub reason: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct DeleteAccountResponse {
    pub success: bool,
    pub message: String,
    pub deletion_scheduled_at: chrono::DateTime<Utc>,
}

// ─── Get profile handler ───────────────────────────────────────

async fn get_profile(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<Json<ProfileResponse>, ApiError> {
    let row: Option<(
        String,
        String,
        String,
        Option<String>,
        String,
        chrono::DateTime<Utc>,
    )> = sqlx::query_as(
        "SELECT id::text, tenant_id, email, name, role, created_at 
             FROM users WHERE id = $1::uuid",
    )
    .bind(&auth.user_id)
    .fetch_optional(&state.db)
    .await?;

    match row {
        Some((user_id, tenant_id, email, name, role, created_at)) => Ok(Json(ProfileResponse {
            user_id,
            tenant_id,
            email,
            name,
            role,
            created_at,
        })),
        None => Err(ApiError::NotFound("user not found".into())),
    }
}

// ─── Delete account handler ────────────────────────────────────

/// Verify a password against a stored hash on the dual scheme the login
/// path accepts (mirrors `verify_password_or_log` in routes/auth.rs, which
/// is module-private): Argon2id for current hashes, bcrypt for legacy
/// ones. The plain `verify_password` used here before only understood
/// Argon2id, so any account with a legacy bcrypt hash could NEVER delete
/// its own account (always "invalid password").
fn verify_password_dual_scheme(
    password: &str,
    hash: &str,
    subject: &str,
) -> Result<bool, ApiError> {
    let result = if hash.starts_with("$2a$") || hash.starts_with("$2b$") || hash.starts_with("$2y$")
    {
        bcrypt::verify(password, hash).map_err(|error| error.to_string())
    } else if hash.starts_with("$argon2") {
        apexmail_lib::verify_password(password, hash).map_err(|error| error.to_string())
    } else {
        let prefix: String = hash.chars().take(10).collect();
        tracing::error!(
            hash_prefix = %prefix,
            subject = %subject,
            "unknown password hash scheme — rejecting account deletion"
        );
        return Err(ApiError::Internal(
            "password verification is unavailable for this account".into(),
        ));
    };

    match result {
        Ok(valid) => Ok(valid),
        Err(error) => {
            tracing::error!(
                error = %error,
                subject = %subject,
                "password verification failed during account deletion"
            );
            Err(ApiError::Internal(
                "password verification is temporarily unavailable".into(),
            ))
        }
    }
}

async fn delete_account(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(body): Json<DeleteAccountRequest>,
) -> Result<(StatusCode, Json<DeleteAccountResponse>), ApiError> {
    // Only owners can delete accounts (require wildcard / full scope)
    crate::middleware::auth::require_scopes(&auth, &["*"])?;

    // Validate confirmation phrase
    if body.confirmation.trim().to_uppercase() != "DELETE MY ACCOUNT" {
        return Err(ApiError::Validation(vec![
            "confirmation phrase must be 'DELETE MY ACCOUNT'".into(),
        ]));
    }

    // Verify password
    let user: Option<(String,)> =
        sqlx::query_as("SELECT password_hash FROM users WHERE id = $1::uuid AND tenant_id = $2")
            .bind(&auth.user_id)
            .bind(&auth.tenant_id)
            .fetch_optional(&state.db)
            .await?;

    let (password_hash,) = user.ok_or_else(|| ApiError::NotFound("user not found".into()))?;

    let password_valid = verify_password_dual_scheme(
        &body.password,
        &password_hash,
        &auth.user_id.clone().unwrap_or_default(),
    )?;

    if !password_valid {
        return Err(ApiError::Unauthorized("invalid password".into()));
    }

    let now = Utc::now();
    // Schedule deletion for 30 days from now (grace period for recovery)
    let deletion_at = now + chrono::Duration::days(30);

    // Mark tenant for deletion
    sqlx::query(
        "UPDATE tenants SET 
            status = 'pending_deletion',
            metadata = jsonb_set(
                COALESCE(metadata, '{}'::jsonb),
                '{deletion_scheduled_at}',
                to_jsonb($2::text)
            ),
            updated_at = NOW()
         WHERE id = $1",
    )
    .bind(&auth.tenant_id)
    .bind(deletion_at.to_rfc3339())
    .execute(&state.db)
    .await?;

    // Deactivate all users in tenant
    sqlx::query("UPDATE users SET status = 'disabled', updated_at = NOW() WHERE tenant_id = $1")
        .bind(&auth.tenant_id)
        .execute(&state.db)
        .await?;

    invalidate_tenant_user_status_cache(&auth.tenant_id, &state).await;

    // Audit log
    crate::audit_log::insert_audit_log(
        &state.db,
        Some(&auth.tenant_id),
        auth.user_id.as_deref(),
        "account.deletion_scheduled",
        "account",
        None,
        serde_json::json!({
            "reason": body.reason,
            "deletion_scheduled_at": deletion_at.to_rfc3339(),
            "initiated_by": auth.user_id,
        }),
        None,
        None,
    )
    .await?;

    tracing::info!(
        tenant_id = %auth.tenant_id,
        user_id = ?auth.user_id,
        deletion_at = %deletion_at,
        "Account deletion scheduled"
    );

    Ok((
        StatusCode::OK,
        Json(DeleteAccountResponse {
            success: true,
            message: "Account deletion scheduled. You have 30 days to cancel this request.".into(),
            deletion_scheduled_at: deletion_at,
        }),
    ))
}

#[cfg(test)]
mod adversarial_tests {
    use super::*;
    use axum::http::StatusCode;

    use crate::app::test_support::adv::AdvEnv;

    const SESSION_PASSWORD: &str = "correct horse battery staple";

    // ── verify_password_dual_scheme (unit, hash-scheme matrix) ──

    #[test]
    fn dual_scheme_accepts_bcrypt_and_argon2id_hashes() {
        // bcrypt ($2a$/$2b$/$2y$ prefixes) — the legacy scheme.
        let bcrypt_hash = bcrypt::hash(SESSION_PASSWORD, 4).expect("bcrypt hash");
        assert!(verify_password_dual_scheme(SESSION_PASSWORD, &bcrypt_hash, "unit").unwrap());
        assert!(!verify_password_dual_scheme("wrong", &bcrypt_hash, "unit").unwrap());
        // Argon2id — the current scheme.
        let argon_hash = apexmail_lib::hash_password(SESSION_PASSWORD).expect("argon2 hash");
        assert!(verify_password_dual_scheme(SESSION_PASSWORD, &argon_hash, "unit").unwrap());
        assert!(!verify_password_dual_scheme("wrong", &argon_hash, "unit").unwrap());
    }

    #[test]
    fn dual_scheme_rejects_unknown_hash_scheme_with_internal_error() {
        let error = verify_password_dual_scheme("pw", "$scrypt$notsupported", "unit")
            .expect_err("unknown scheme must be an error");
        assert!(matches!(error, ApiError::Internal(message) if message.contains("unavailable")));
        // Truncated garbage (no recognisable prefix) hits the same arm.
        let error = verify_password_dual_scheme("pw", "plaintext?", "unit")
            .expect_err("garbage hash must be an error");
        assert!(matches!(error, ApiError::Internal(_)));
    }

    #[test]
    fn dual_scheme_maps_corrupt_hash_to_internal_error() {
        // A bcrypt-PREFIXED but malformed hash makes bcrypt::verify itself
        // error — that must surface as Internal, never as "invalid password".
        let error = verify_password_dual_scheme("pw", "$2a$notavalidhash", "unit")
            .expect_err("corrupt bcrypt hash must be an error");
        assert!(
            matches!(error, ApiError::Internal(message) if message.contains("temporarily unavailable"))
        );
        // A malformed argon2 PHC string is an honest password MISMATCH
        // (Ok(false)), not an infrastructure error — only true verifier
        // failures map to Internal.
        assert!(!verify_password_dual_scheme("pw", "$argon2id$garbage", "unit").unwrap());
    }

    // ── GET /v1/account/profile ───────────────────────────────

    #[tokio::test]
    async fn profile_returns_the_live_user_row_for_a_session() {
        let Some(pool) = crate::test_db::canonical_pool("acct_profile_ok").await else {
            return;
        };
        let Some((env, tenant_id, user_id)) = AdvEnv::session(pool.clone(), "owner").await else {
            return;
        };

        let (status, body) = env.get("/v1/account/profile").await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["user_id"], user_id.as_str());
        assert_eq!(body["tenant_id"], tenant_id.as_str());
        assert_eq!(body["role"], "owner");
        assert_eq!(body["email"], format!("sess-{user_id}@example.com"));
        assert_eq!(body["name"], "Adversarial Session");
    }

    #[tokio::test]
    async fn profile_requires_authentication() {
        let Some(pool) = crate::test_db::canonical_pool("acct_profile_anon").await else {
            return;
        };
        let Some((env, _t, _u)) = AdvEnv::session(pool, "owner").await else {
            return;
        };
        // Strip the credential by issuing the request with a bogus one.
        let mut anonymous = env;
        anonymous.credential = "definitely-not-a-credential".into();
        let (status, body) = anonymous.get("/v1/account/profile").await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    }

    #[tokio::test]
    async fn profile_for_an_api_key_identity_has_no_user_row() {
        // API keys carry no user_id: the profile lookup binds NULL and must
        // answer 404 (an API key has no human profile), not 500.
        let Some(pool) = crate::test_db::canonical_pool("acct_profile_apikey").await else {
            return;
        };
        let (env, _tenant) = AdvEnv::tenant(pool, &["*"]).await;
        let (status, body) = env.get("/v1/account/profile").await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
        assert_eq!(body["error"]["message"], "user not found");
    }

    // ── DELETE /v1/account ─────────────────────────────────────

    #[tokio::test]
    async fn delete_account_schedules_deletion_and_disables_the_tenant() {
        let Some(pool) = crate::test_db::canonical_pool("acct_delete_ok").await else {
            return;
        };
        let Some((env, tenant_id, user_id)) = AdvEnv::session(pool.clone(), "owner").await else {
            return;
        };
        let pool = env.pool.clone();

        let (status, body) = env
            .send_json(
                axum::http::Method::DELETE,
                "/v1/account",
                Some(
                    &serde_json::json!({
                        "password": SESSION_PASSWORD,
                        "confirmation": "DELETE MY ACCOUNT",
                        "reason": "adversarial test"
                    })
                    .to_string(),
                ),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["success"], true);
        assert_eq!(
            body["message"].as_str().map(str::to_string),
            Some("Account deletion scheduled. You have 30 days to cancel this request.".into())
        );
        let scheduled: chrono::DateTime<chrono::Utc> = body["deletion_scheduled_at"]
            .as_str()
            .expect("scheduled at")
            .parse()
            .expect("scheduled at parses");

        // Database effects: tenant pending_deletion with the metadata
        // marker, users disabled, and an audit row attributed to the caller.
        let (tenant_status, metadata): (String, serde_json::Value) = sqlx::query_as(
            "SELECT status, COALESCE(metadata, '{}'::jsonb) FROM tenants WHERE id = $1",
        )
        .bind(&tenant_id)
        .fetch_one(&pool)
        .await
        .expect("tenant row");
        assert_eq!(tenant_status, "pending_deletion");
        let stored_scheduled: chrono::DateTime<chrono::Utc> = metadata["deletion_scheduled_at"]
            .as_str()
            .expect("metadata carries the schedule")
            .parse()
            .expect("stored schedule parses");
        assert_eq!(stored_scheduled, scheduled);
        // The grace period is 30 days out.
        assert!(scheduled > chrono::Utc::now() + chrono::Duration::days(29));

        let user_status: String =
            sqlx::query_scalar("SELECT status FROM users WHERE id = $1::uuid AND tenant_id = $2")
                .bind(&user_id)
                .bind(&tenant_id)
                .fetch_one(&pool)
                .await
                .expect("user row");
        assert_eq!(user_status, "disabled");

        let (action, actor): (String, Option<String>) = sqlx::query_as(
            "SELECT action, user_id FROM audit_logs WHERE tenant_id = $1 AND action = 'account.deletion_scheduled'",
        )
        .bind(&tenant_id)
        .fetch_one(&pool)
        .await
        .expect("audit row");
        assert_eq!(action, "account.deletion_scheduled");
        assert_eq!(actor.as_deref(), Some(user_id.as_str()));

        // A disabled user's session no longer authenticates (status gate).
        let (status, body) = env.get("/v1/account/profile").await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    }

    #[tokio::test]
    async fn delete_account_rejects_wrong_confirmation_phrase() {
        let Some(pool) = crate::test_db::canonical_pool("acct_delete_confirm").await else {
            return;
        };
        let Some((env, _t, _u)) = AdvEnv::session(pool, "owner").await else {
            return;
        };
        let (status, body) = env
            .send_json(
                axum::http::Method::DELETE,
                "/v1/account",
                Some(
                    &serde_json::json!({
                        "password": SESSION_PASSWORD,
                        "confirmation": "delete my account please",
                    })
                    .to_string(),
                ),
            )
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        // Case-insensitive match is accepted by design (trim + uppercase).
        let (status, _) = env
            .send_json(
                axum::http::Method::DELETE,
                "/v1/account",
                Some(
                    &serde_json::json!({
                        "password": SESSION_PASSWORD,
                        "confirmation": "  delete my account  ",
                    })
                    .to_string(),
                ),
            )
            .await;
        assert_eq!(status, StatusCode::OK);
    }

    #[tokio::test]
    async fn delete_account_rejects_wrong_password_without_side_effects() {
        let Some(pool) = crate::test_db::canonical_pool("acct_delete_pw").await else {
            return;
        };
        let Some((env, tenant_id, _u)) = AdvEnv::session(pool.clone(), "owner").await else {
            return;
        };
        let (status, body) = env
            .send_json(
                axum::http::Method::DELETE,
                "/v1/account",
                Some(
                    &serde_json::json!({
                        "password": "not-the-password",
                        "confirmation": "DELETE MY ACCOUNT",
                    })
                    .to_string(),
                ),
            )
            .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
        let tenant_status: String = sqlx::query_scalar("SELECT status FROM tenants WHERE id = $1")
            .bind(&tenant_id)
            .fetch_one(&pool)
            .await
            .expect("tenant row");
        assert_eq!(tenant_status, "active", "no side effects on refusal");
    }

    #[tokio::test]
    async fn delete_account_requires_wildcard_scope() {
        // A member-role session (no "*" grant) is refused by the scope gate.
        let Some(pool) = crate::test_db::canonical_pool("acct_delete_scope").await else {
            return;
        };
        let Some((env, _t, _u)) = AdvEnv::session(pool, "member").await else {
            return;
        };
        let (status, body) = env
            .send_json(
                axum::http::Method::DELETE,
                "/v1/account",
                Some(
                    &serde_json::json!({
                        "password": SESSION_PASSWORD,
                        "confirmation": "DELETE MY ACCOUNT",
                    })
                    .to_string(),
                ),
            )
            .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    }

    #[tokio::test]
    async fn delete_account_for_an_api_key_identity_is_user_not_found() {
        let Some(pool) = crate::test_db::canonical_pool("acct_delete_apikey").await else {
            return;
        };
        let (env, _tenant) = AdvEnv::tenant(pool, &["*"]).await;
        let (status, body) = env
            .send_json(
                axum::http::Method::DELETE,
                "/v1/account",
                Some(
                    &serde_json::json!({
                        "password": "x",
                        "confirmation": "DELETE MY ACCOUNT",
                    })
                    .to_string(),
                ),
            )
            .await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
    }

    #[tokio::test]
    async fn delete_account_rejects_unknown_body_fields() {
        let Some(pool) = crate::test_db::canonical_pool("acct_delete_unknown").await else {
            return;
        };
        let Some((env, _t, _u)) = AdvEnv::session(pool, "owner").await else {
            return;
        };
        let (status, _body) = env
            .send_json(
                axum::http::Method::DELETE,
                "/v1/account",
                Some(r#"{"password":"x","confirmation":"DELETE MY ACCOUNT","extra":true}"#),
            )
            .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    }
}
