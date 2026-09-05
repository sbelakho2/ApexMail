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
fn verify_password_dual_scheme(password: &str, hash: &str, subject: &str) -> Result<bool, ApiError> {
    let result = if hash.starts_with("$2a$") || hash.starts_with("$2b$") || hash.starts_with("$2y$") {
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
