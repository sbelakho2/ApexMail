//! Account management routes:profile, delete account, deletion cancellation.

use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use chrono::Utc;
use serde::{Deserialize, Serialize};

use crate::error::ApiError;
use crate::middleware::auth::{
    invalidate_tenant_status_cache, invalidate_tenant_user_status_cache, AuthUser,
};
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/profile", get(get_profile))
        .route("/", delete(delete_account))
        // SM3 (audit F1): the cancellation half of the deletion lifecycle.
        .route("/deletion/cancel", post(cancel_account_deletion))
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
    // Schedule deletion for the 30-day grace period (recovery window; the
    // sweeper executes what is not cancelled — see DELETION_GRACE_DAYS).
    let deletion_at = now + chrono::Duration::days(DELETION_GRACE_DAYS);

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

    // Both auth caches must drop their stale verdicts immediately (mirrors
    // the cancellation path): the tenant-status cache (the F1
    // pending_deletion gate reads it) and every user-status entry
    // (disabled) for the tenant.
    invalidate_tenant_status_cache(&auth.tenant_id, &state).await;
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

// ─── Deletion cancellation (SM3 audit F1) ──────────────────────

/// Grace period between scheduling and executing a deletion. MUST stay in
/// sync with the schedule `delete_account` writes (30 days) — the promise in
/// its response message and the sweeper's eligibility window are both keyed
/// to it.
const DELETION_GRACE_DAYS: i64 = 30;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CancelDeletionRequest {
    /// Current password for verification: cancelling an erasure request is
    /// as consequential as scheduling it, so a stolen session alone must
    /// not suffice to resurrect the account.
    pub password: String,
}

#[derive(Debug, Serialize)]
pub struct CancelDeletionResponse {
    pub success: bool,
    pub message: String,
}

/// `POST /v1/account/deletion/cancel` — undo a scheduled deletion inside the
/// 30-day grace period.
///
/// The deletion schedule (`delete_account`) disables every user and marks
/// the tenant `pending_deletion`; the paired auth carve-outs
/// (`is_deletion_cancellation_request` in `middleware::auth`, for both the
/// tenant-status and user-status gates) are what make this route the ONLY
/// authenticated surface such a workspace can still reach. The handler then
/// re-verifies every fact server-side: wildcard scope, a human (user)
/// identity, password proof, and a live `pending_deletion` row taken under
/// `FOR UPDATE` so a concurrent cancellation or sweeper run cannot double
/// apply.
async fn cancel_account_deletion(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(body): Json<CancelDeletionRequest>,
) -> Result<Json<CancelDeletionResponse>, ApiError> {
    // Same capability bar as the deletion itself (wildcard / full scope).
    crate::middleware::auth::require_scopes(&auth, &["*"])?;

    // Only a human identity may cancel: an API key has no user row and no
    // password to present.
    let user_id = auth
        .user_id
        .clone()
        .ok_or_else(|| ApiError::Unauthorized("user authentication required".into()))?;

    // Verify the password BEFORE taking the row lock (same dual-scheme
    // acceptance as `delete_account`).
    let user: Option<(String,)> =
        sqlx::query_as("SELECT password_hash FROM users WHERE id = $1::uuid AND tenant_id = $2")
            .bind(&user_id)
            .bind(&auth.tenant_id)
            .fetch_optional(&state.db)
            .await?;
    let (password_hash,) = user.ok_or_else(|| ApiError::NotFound("user not found".into()))?;
    if !verify_password_dual_scheme(&body.password, &password_hash, &user_id)? {
        return Err(ApiError::Unauthorized("invalid password".into()));
    }

    // One transaction: re-check the tenant is STILL pending deletion, then
    // restore it and its users atomically. A concurrent cancellation or an
    // already-running sweeper purge serializes on the FOR UPDATE lock.
    let mut tx = state.db.begin().await?;
    let tenant: Option<(String, Option<String>)> = sqlx::query_as(
        "SELECT status, metadata->>'deletion_scheduled_at'
             FROM tenants WHERE id = $1 FOR UPDATE",
    )
    .bind(&auth.tenant_id)
    .fetch_optional(&mut *tx)
    .await?;

    let Some((status, _scheduled_at)) = tenant else {
        return Err(ApiError::NotFound("workspace no longer exists".into()));
    };
    if status != "pending_deletion" {
        return Err(ApiError::Conflict(
            "no account deletion is pending for this workspace".into(),
        ));
    }

    sqlx::query(
        "UPDATE tenants SET
            status = 'active',
            metadata = COALESCE(metadata, '{}'::jsonb) - 'deletion_scheduled_at',
            updated_at = NOW()
         WHERE id = $1",
    )
    .bind(&auth.tenant_id)
    .execute(&mut *tx)
    .await?;

    // The schedule disabled EVERY user in the tenant; cancellation restores
    // every user in the tenant (the disabled state carried no per-user
    // distinction to preserve — the blanket disable destroyed it).
    sqlx::query("UPDATE users SET status = 'active', updated_at = NOW() WHERE tenant_id = $1")
        .bind(&auth.tenant_id)
        .execute(&mut *tx)
        .await?;

    tx.commit().await?;

    // Both auth caches must drop their stale verdicts immediately: the
    // tenant-status cache (pending_deletion) and every user-status entry
    // (disabled) for the tenant.
    invalidate_tenant_status_cache(&auth.tenant_id, &state).await;
    invalidate_tenant_user_status_cache(&auth.tenant_id, &state).await;

    crate::audit_log::insert_audit_log(
        &state.db,
        Some(&auth.tenant_id),
        Some(&user_id),
        "account.deletion_cancelled",
        "account",
        None,
        serde_json::json!({
            "cancelled_by": user_id,
        }),
        None,
        None,
    )
    .await?;

    tracing::info!(
        tenant_id = %auth.tenant_id,
        user_id = %user_id,
        "Account deletion cancelled inside the grace period"
    );

    Ok(Json(CancelDeletionResponse {
        success: true,
        message: "Account deletion cancelled. Your workspace has been restored.".into(),
    }))
}

// ─── Deletion retention sweeper (SM3 audit F1) ─────────────────

/// Is a scheduled deletion due for execution? `scheduled_at` is the
/// RFC3339 `tenants.metadata->>'deletion_scheduled_at'` value written by
/// [`delete_account`]. A missing or corrupt timestamp is NEVER due: an
/// unreadable schedule must park the tenant for operator review, never
/// trigger an irreversible purge on a guess.
fn deletion_due(scheduled_at: Option<&str>, now: chrono::DateTime<Utc>) -> bool {
    let Some(raw) = scheduled_at else {
        return false;
    };
    match chrono::DateTime::parse_from_rfc3339(raw) {
        Ok(scheduled) => chrono::DateTime::<Utc>::from(scheduled) <= now,
        Err(_) => false,
    }
}

/// Execute every account deletion whose 30-day grace period has elapsed.
///
/// This is the half of the deletion lifecycle the erasure promise was
/// missing: `delete_account` schedules, this sweeper actually purges —
/// reusing the control-plane's reflection-driven purge
/// (`routes::admin::tenants::delete_tenant_records`, the SAME machinery the
/// GDPR/admin tenant deletion uses: actor-attributed audit entry first,
/// evidence tables (`audit_logs`, `cp_access_log`, `secrets_archive`)
/// preserved, tenant row deleted last — all in one transaction).
///
/// Preconditions are honoured exactly like an operator-issued deletion: a
/// legal hold or an active retention obligation parks the erasure (logged;
/// the next sweep re-evaluates) — evidence preservation outranks the purge.
/// Per-tenant failures are logged and skipped so one bad tenant cannot stop
/// the sweep. Spawned from `bin/server.rs` alongside the process heartbeat
/// (`pub`: the binary is a separate crate).
pub async fn sweep_due_account_deletions(
    db: &sqlx::PgPool,
    is_production: bool,
) -> Result<usize, sqlx::Error> {
    let due: Vec<(String, Option<String>)> = sqlx::query_as(
        "SELECT id, metadata->>'deletion_scheduled_at'
             FROM tenants WHERE status = 'pending_deletion'",
    )
    .fetch_all(db)
    .await?;

    let now = Utc::now();
    let mut swept = 0usize;
    for (tenant_id, scheduled_at) in due {
        if !deletion_due(scheduled_at.as_deref(), now) {
            continue;
        }

        if let Err(error) =
            crate::routes::admin::tenants::check_tenant_deletion_preconditions(db, &tenant_id).await
        {
            match error {
                ApiError::Forbidden(reason) => tracing::warn!(
                    tenant_id = %tenant_id,
                    reason = %reason,
                    "deletion sweeper: grace period elapsed but the tenant is parked \
                     (legal hold / retention obligation) — skipping"
                ),
                other => tracing::error!(
                    tenant_id = %tenant_id,
                    error = ?other,
                    "deletion sweeper: precondition check failed — skipping"
                ),
            }
            continue;
        }

        // The actor is the platform executing the user's erasure request.
        match crate::routes::admin::tenants::delete_tenant_records(
            db,
            &tenant_id,
            "system",
            None,
            is_production,
        )
        .await
        {
            Ok(true) => {
                swept += 1;
                tracing::info!(
                    tenant_id = %tenant_id,
                    grace_days = DELETION_GRACE_DAYS,
                    "deletion sweeper: purged tenant past its erasure grace period"
                );
            }
            Ok(false) => tracing::warn!(
                tenant_id = %tenant_id,
                "deletion sweeper: tenant vanished before the purge"
            ),
            Err(error) => tracing::error!(
                tenant_id = %tenant_id,
                error = %error,
                "deletion sweeper: purge failed — will retry on the next sweep"
            ),
        }
    }

    Ok(swept)
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

    // ── POST /v1/account/deletion/cancel (SM3 audit F1) ────────

    #[tokio::test]
    async fn scheduled_deletion_can_be_cancelled_inside_the_grace_period() {
        let Some(pool) = crate::test_db::canonical_pool("acct_cancel_ok").await else {
            return;
        };
        let Some((env, tenant_id, user_id)) = AdvEnv::session(pool.clone(), "owner").await else {
            return;
        };

        // Schedule the deletion (the F1 lockout): tenant pending_deletion,
        // every user disabled, session useless on ordinary routes.
        let (status, _body) = env
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
        assert_eq!(status, StatusCode::OK);

        // The recovery carve-out admits EXACTLY the cancellation route —
        // every other authenticated surface stays locked out.
        let (status, _body) = env.get("/v1/account/profile").await;
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "disabled user + pending_deletion tenant must not read ordinary routes"
        );

        // A wrong password refuses WITHOUT undoing the schedule.
        let (status, body) = env
            .post(
                "/v1/account/deletion/cancel",
                r#"{"password":"not-the-password"}"#,
            )
            .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
        let tenant_status: String = sqlx::query_scalar("SELECT status FROM tenants WHERE id = $1")
            .bind(&tenant_id)
            .fetch_one(&pool)
            .await
            .expect("tenant row");
        assert_eq!(
            tenant_status, "pending_deletion",
            "wrong password is a no-op"
        );

        // The right password cancels: tenant restored, users restored.
        let (status, body) = env
            .post(
                "/v1/account/deletion/cancel",
                &serde_json::json!({ "password": SESSION_PASSWORD }).to_string(),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["success"], true);

        let (tenant_status, metadata): (String, serde_json::Value) = sqlx::query_as(
            "SELECT status, COALESCE(metadata, '{}'::jsonb) FROM tenants WHERE id = $1",
        )
        .bind(&tenant_id)
        .fetch_one(&pool)
        .await
        .expect("tenant row");
        assert_eq!(
            tenant_status, "active",
            "cancellation restores the workspace"
        );
        assert!(
            metadata.get("deletion_scheduled_at").is_none(),
            "the schedule marker is removed: {metadata}"
        );

        let user_status: String =
            sqlx::query_scalar("SELECT status FROM users WHERE id = $1::uuid AND tenant_id = $2")
                .bind(&user_id)
                .bind(&tenant_id)
                .fetch_one(&pool)
                .await
                .expect("user row");
        assert_eq!(user_status, "active", "cancellation restores the users");

        // An attributed audit row records the cancellation.
        let (action, actor): (String, Option<String>) = sqlx::query_as(
            "SELECT action, user_id FROM audit_logs
             WHERE tenant_id = $1 AND action = 'account.deletion_cancelled'",
        )
        .bind(&tenant_id)
        .fetch_one(&pool)
        .await
        .expect("audit row");
        assert_eq!(action, "account.deletion_cancelled");
        assert_eq!(actor.as_deref(), Some(user_id.as_str()));

        // And the workspace is usable again.
        let (status, _body) = env.get("/v1/account/profile").await;
        assert_eq!(
            status,
            StatusCode::OK,
            "the session works after cancellation"
        );
    }

    #[tokio::test]
    async fn cancellation_without_a_pending_deletion_conflicts() {
        let Some(pool) = crate::test_db::canonical_pool("acct_cancel_conflict").await else {
            return;
        };
        let Some((env, tenant_id, _u)) = AdvEnv::session(pool.clone(), "owner").await else {
            return;
        };
        let (status, body) = env
            .post(
                "/v1/account/deletion/cancel",
                &serde_json::json!({ "password": SESSION_PASSWORD }).to_string(),
            )
            .await;
        assert_eq!(status, StatusCode::CONFLICT, "{body}");
        let tenant_status: String = sqlx::query_scalar("SELECT status FROM tenants WHERE id = $1")
            .bind(&tenant_id)
            .fetch_one(&pool)
            .await
            .expect("tenant row");
        assert_eq!(tenant_status, "active");
    }

    #[tokio::test]
    async fn cancellation_requires_a_wildcard_scope() {
        // A member-role session (no "*" grant) is refused by the same
        // capability bar the deletion itself enforces.
        let Some(pool) = crate::test_db::canonical_pool("acct_cancel_scope").await else {
            return;
        };
        let Some((env, _t, _u)) = AdvEnv::session(pool, "member").await else {
            return;
        };
        let (status, _body) = env
            .post(
                "/v1/account/deletion/cancel",
                &serde_json::json!({ "password": SESSION_PASSWORD }).to_string(),
            )
            .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn cancellation_rejects_unknown_body_fields() {
        let Some(pool) = crate::test_db::canonical_pool("acct_cancel_unknown").await else {
            return;
        };
        let Some((env, _t, _u)) = AdvEnv::session(pool, "owner").await else {
            return;
        };
        let (status, _body) = env
            .post(
                "/v1/account/deletion/cancel",
                r#"{"password":"x","extra":true}"#,
            )
            .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    }

    // ── Retention sweeper (SM3 audit F1) ───────────────────────

    /// Seed a `pending_deletion` tenant carrying a deletion schedule. Uses
    /// ON CONFLICT so a reused fixture database converges to the wanted row.
    async fn seed_pending_deletion_tenant(
        pool: &sqlx::PgPool,
        tenant_id: &str,
        scheduled_at: Option<chrono::DateTime<chrono::Utc>>,
        legal_hold: bool,
    ) {
        let metadata = match scheduled_at {
            Some(at) => serde_json::json!({ "deletion_scheduled_at": at.to_rfc3339() }),
            None => serde_json::json!({ "deletion_scheduled_at": "not-a-timestamp" }),
        };
        sqlx::query(
            "INSERT INTO tenants (id, name, slug, plan, status, legal_hold, metadata, created_at, updated_at)
             VALUES ($1, $2, $3, 'free', 'pending_deletion', $4, $5, NOW(), NOW())
             ON CONFLICT (id) DO UPDATE SET
                status = 'pending_deletion',
                legal_hold = EXCLUDED.legal_hold,
                metadata = EXCLUDED.metadata",
        )
        .bind(tenant_id)
        .bind(format!("sweeper {tenant_id}"))
        .bind(format!("sweeper-{tenant_id}"))
        .bind(legal_hold)
        .bind(&metadata)
        .execute(pool)
        .await
        .expect("seed pending_deletion tenant");
    }

    #[tokio::test]
    async fn sweeper_purges_only_due_tenants_and_honours_preconditions() {
        let Some(pool) = crate::test_db::canonical_pool("acct_sweeper_matrix").await else {
            return;
        };

        let due = format!(
            "swp-due-{}",
            &uuid::Uuid::new_v4().simple().to_string()[..8]
        );
        let future = format!(
            "swp-fut-{}",
            &uuid::Uuid::new_v4().simple().to_string()[..8]
        );
        let corrupt = format!(
            "swp-cor-{}",
            &uuid::Uuid::new_v4().simple().to_string()[..8]
        );
        let held = format!(
            "swp-hld-{}",
            &uuid::Uuid::new_v4().simple().to_string()[..8]
        );

        seed_pending_deletion_tenant(
            &pool,
            &due,
            Some(chrono::Utc::now() - chrono::Duration::days(1)),
            false,
        )
        .await;
        seed_pending_deletion_tenant(
            &pool,
            &future,
            Some(chrono::Utc::now() + chrono::Duration::days(10)),
            false,
        )
        .await;
        // Unreadable schedule: never due (fail-safe).
        seed_pending_deletion_tenant(&pool, &corrupt, None, false).await;
        // Due, but under legal hold: evidence preservation parks the purge.
        seed_pending_deletion_tenant(
            &pool,
            &held,
            Some(chrono::Utc::now() - chrono::Duration::days(2)),
            true,
        )
        .await;

        let swept = super::sweep_due_account_deletions(&pool, false)
            .await
            .expect("sweep runs");

        let tenant_exists = |id: &str| {
            let pool = pool.clone();
            let id = id.to_string();
            async move {
                sqlx::query_scalar::<_, bool>("SELECT EXISTS(SELECT 1 FROM tenants WHERE id = $1)")
                    .bind(&id)
                    .fetch_one(&pool)
                    .await
                    .expect("tenant probe")
            }
        };
        assert!(!tenant_exists(&due).await, "a due tenant must be purged");
        assert!(tenant_exists(&future).await, "a future schedule is kept");
        assert!(
            tenant_exists(&corrupt).await,
            "an unreadable schedule is never a purge trigger"
        );
        assert!(tenant_exists(&held).await, "a legal hold parks the erasure");
        assert_eq!(swept, 1, "exactly the one eligible tenant was swept");

        // The purge is audited (the machinery's non-optional audit entry).
        let audited: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM audit_logs
             WHERE action = 'control_plane.tenant.deleted'
               AND resource_id = $1)",
        )
        .bind(&due)
        .fetch_one(&pool)
        .await
        .expect("audit probe");
        assert!(audited, "the sweeper's purge must be auditable");
    }

    #[test]
    fn deletion_due_is_true_only_for_parseable_past_schedules() {
        let now = chrono::Utc::now();
        // Past schedule: due.
        assert!(super::deletion_due(
            Some(&(now - chrono::Duration::hours(1)).to_rfc3339()),
            now
        ));
        // Boundary: a schedule due EXACTLY now executes (<=).
        assert!(super::deletion_due(Some(&now.to_rfc3339()), now));
        // Future schedule: not due.
        assert!(!super::deletion_due(
            Some(&(now + chrono::Duration::days(1)).to_rfc3339()),
            now
        ));
        // Missing metadata key: never due.
        assert!(!super::deletion_due(None, now));
        // Corrupt timestamp: never due (fail-safe — no purge on a guess).
        assert!(!super::deletion_due(Some("not-a-timestamp"), now));
        assert!(!super::deletion_due(Some(""), now));
    }
}
