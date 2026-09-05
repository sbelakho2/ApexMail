//! Admin operator management — list, create, and manage control-plane operators.
//!
//! Operators are users with the `admin` or `owner` role. This module provides
//! the API endpoints backing the control-plane Operators UI.
//!
//! Scoping invariants (audit P1-1/P1-2): every query is filtered by the
//! CALLER's tenant — an operator of one tenant must never list, create, or
//! delete operators of another. Deletion additionally refuses self-deletion
//! and the destruction of a tenant's last remaining owner, and both
//! mutations write actor-attributed audit entries.

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;

use crate::error::ApiError;
use crate::middleware::auth::{require_scopes, require_system_tenant, AuthUser};
use crate::state::AppState;

/// Only these roles may be assigned to a control-plane operator.
const VALID_OPERATOR_ROLES: &[&str] = &["admin", "owner"];

pub fn router() -> Router<AppState> {
    Router::new()
        .route(
            "/",
            axum::routing::get(list_operators).post(create_operator),
        )
        .route("/:id", axum::routing::delete(delete_operator))
}

#[derive(Debug, Serialize, FromRow)]
pub struct OperatorRow {
    pub id: String,
    pub email: String,
    pub role: String,
    pub mfa_enabled: bool,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Deserialize)]
pub struct CreateOperatorRequest {
    pub email: String,
    pub name: Option<String>,
    pub role: Option<String>,
}

/// 201 body for operator creation. `tempPassword` is the ONLY place the
/// generated password ever appears: it is hashed for storage and discarded
/// server-side, so the client must display it once — it cannot be recovered.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateOperatorResponse {
    pub id: String,
    pub email: String,
    pub role: String,
    pub temp_password: String,
}

#[derive(Debug, Deserialize)]
pub struct DeleteOperatorQuery {
    /// Cross-tenant or fat-fingered deletes are irreversible; the caller
    /// must echo `?confirm=true` to prove intent.
    pub confirm: Option<String>,
}

/// Structural email gate for operator creation — full RFC validation is not
/// the point here; rejecting missing-@/empty-parts/whitespace/oversized
/// input before it reaches the UNIQUE index is.
fn is_plausible_email(email: &str) -> bool {
    let email = email.trim();
    if !(3..=320).contains(&email.len()) {
        return false;
    }
    if email.chars().any(char::is_whitespace) {
        return false;
    }
    match email.split_once('@') {
        Some((local, domain)) => {
            !local.is_empty()
                && domain.contains('.')
                && !domain.starts_with('.')
                && !domain.ends_with('.')
                && !domain.starts_with('@')
        }
        None => false,
    }
}

fn is_unique_violation(error: &sqlx::Error) -> bool {
    matches!(
        error,
        sqlx::Error::Database(db) if db.code().as_deref() == Some("23505")
    )
}

/// Actor-attributed audit entry for operator lifecycle mutations (P2-2):
/// the acting operator's tenant AND user id — an operator deletion without
/// attribution is exactly the evidence gap the audit chain exists to close.
async fn log_operator_audit(
    state: &AppState,
    auth: &AuthUser,
    action: &str,
    target_id: &str,
    metadata: serde_json::Value,
) {
    crate::audit_log::insert_audit_log_best_effort_with_env(
        &state.db,
        state.config.environment.is_production(),
        Some(auth.tenant_id.as_str()),
        auth.user_id.as_deref(),
        action,
        "operator",
        Some(target_id),
        metadata,
        None,
        None,
    )
    .await;
}

async fn list_operators(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<Json<Vec<OperatorRow>>, ApiError> {
    require_scopes(&auth, &["*"])?;
    require_system_tenant(&state, &auth).await?;
    // P1-1: tenant-scoped — the previous unscoped query listed every
    // tenant's admins/owners to any operator.
    let rows = sqlx::query_as::<_, OperatorRow>(
        "SELECT id, email, role, \
         COALESCE(mfa_enabled, false) AS mfa_enabled, created_at \
         FROM users WHERE tenant_id = $1 AND role IN ('admin', 'owner') \
         ORDER BY created_at DESC",
    )
    .bind(&auth.tenant_id)
    .fetch_all(&state.db)
    .await
    .map_err(|_| ApiError::Internal("Failed to list operators".into()))?;
    Ok(Json(rows))
}

async fn create_operator(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(body): Json<CreateOperatorRequest>,
) -> Result<(StatusCode, Json<CreateOperatorResponse>), ApiError> {
    require_scopes(&auth, &["*"])?;
    require_system_tenant(&state, &auth).await?;

    let role = body.role.as_deref().unwrap_or("admin");
    // Reject arbitrary role strings — only admin/owner may be assigned.
    if !VALID_OPERATOR_ROLES.contains(&role) {
        return Err(ApiError::Validation(vec![format!(
            "invalid role: {role} (allowed: admin, owner)"
        )]));
    }

    let email = body.email.trim().to_lowercase();
    if !is_plausible_email(&email) {
        return Err(ApiError::Validation(vec![
            "email must be a valid address (local@domain.tld)".into(),
        ]));
    }

    let id = apexmail_lib::id::generate_id("usr", 16);
    let temp_password = apexmail_lib::id::generate_id("tmp", 24);
    let password_hash = bcrypt::hash(&temp_password, 10)
        .map_err(|_| ApiError::Internal("failed to hash operator password".into()))?;

    // P1-2: the temp password is returned exactly once in the 201 body
    // (hashed at rest, never recoverable) — previously it was discarded and
    // the created operator could never log in. Duplicate email is a 409;
    // every other DB error maps to a generic Internal so no raw driver
    // detail leaks into the console.
    sqlx::query(
        "INSERT INTO users (id, tenant_id, email, name, password_hash, role, mfa_enabled, created_at, updated_at) \
         VALUES ($1, $2, $3, $4, $5, $6, false, NOW(), NOW())",
    )
    .bind(&id)
    .bind(&auth.tenant_id)
    .bind(&email)
    .bind(body.name.as_deref().unwrap_or(""))
    .bind(&password_hash)
    .bind(role)
    .execute(&state.db)
    .await
    .map_err(|e| {
        if is_unique_violation(&e) {
            ApiError::Conflict("an operator with this email already exists".into())
        } else {
            tracing::error!(operator_id = %id, error = %e, "operator insert failed");
            ApiError::Internal("Failed to create operator".into())
        }
    })?;

    log_operator_audit(
        &state,
        &auth,
        "control_plane.operator.created",
        &id,
        serde_json::json!({ "email": email, "role": role }),
    )
    .await;

    tracing::info!(operator_id = %id, operator_email = %email, "Operator created");
    Ok((
        StatusCode::CREATED,
        Json(CreateOperatorResponse {
            id,
            email,
            role: role.to_string(),
            temp_password,
        }),
    ))
}

async fn delete_operator(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<String>,
    Query(query): Query<DeleteOperatorQuery>,
) -> Result<StatusCode, ApiError> {
    require_scopes(&auth, &["*"])?;
    require_system_tenant(&state, &auth).await?;

    // Irreversible mutation: demand an explicit confirmation echo.
    if query.confirm.as_deref() != Some("true") {
        return Err(ApiError::Validation(vec![
            "pass ?confirm=true to delete an operator".into(),
        ]));
    }

    // Self-deletion is refused: it silently drops the last credential holder
    // and produces an audit entry whose actor was just destroyed.
    if auth.user_id.as_deref() == Some(id.as_str()) {
        return Err(ApiError::Validation(vec![
            "operators cannot delete their own account".into(),
        ]));
    }

    // users.id is VARCHAR(26) (ULID-like), not UUID — bind as text, no ::uuid cast.
    let mut tx = state
        .db
        .begin()
        .await
        .map_err(|_| ApiError::Internal("failed to begin deletion".into()))?;

    // P1-1: tenant-scoped lookup (FOR UPDATE closes the count/delete race);
    // a foreign tenant's operator id resolves to 404, never to a delete.
    let target: Option<(String, String)> = sqlx::query_as(
        "SELECT id, role FROM users \
         WHERE id = $1 AND tenant_id = $2 AND role IN ('admin', 'owner') FOR UPDATE",
    )
    .bind(&id)
    .bind(&auth.tenant_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|_| ApiError::Internal("failed to load operator".into()))?;
    let Some((_, target_role)) = target else {
        return Err(ApiError::NotFound("Operator not found".into()));
    };

    // Guard the tenant's LAST owner: deleting it orphans the tenant with no
    // role able to manage it (including appointing a successor).
    let owner_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE tenant_id = $1 AND role = 'owner'")
            .bind(&auth.tenant_id)
            .fetch_one(&mut *tx)
            .await
            .map_err(|_| ApiError::Internal("failed to count owners".into()))?;
    if target_role == "owner" && owner_count <= 1 {
        return Err(ApiError::Validation(vec![
            "cannot delete the last owner of this tenant — appoint another owner first".into(),
        ]));
    }

    sqlx::query(
        "DELETE FROM users WHERE id = $1 AND tenant_id = $2 AND role IN ('admin', 'owner')",
    )
    .bind(&id)
    .bind(&auth.tenant_id)
    .execute(&mut *tx)
    .await
    .map_err(|e| {
        tracing::error!(operator_id = %id, error = %e, "operator delete failed");
        ApiError::Internal("Failed to delete operator".into())
    })?;

    tx.commit()
        .await
        .map_err(|_| ApiError::Internal("failed to commit deletion".into()))?;

    log_operator_audit(
        &state,
        &auth,
        "control_plane.operator.deleted",
        &id,
        serde_json::json!({ "confirm": true }),
    )
    .await;

    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plausible_email_accepts_normal_addresses() {
        for ok in ["ops@apexmail.ee", "a.b+c@sub.example.co.uk"] {
            assert!(is_plausible_email(ok), "{ok} should be accepted");
        }
    }

    #[test]
    fn plausible_email_rejects_malformed_addresses() {
        for bad in [
            "",
            "   ",
            "noat",
            "@example.com",
            "user@",
            "user@nodot",
            "user @example.com",
            "a".repeat(321).as_str(),
        ] {
            assert!(!is_plausible_email(bad), "{bad:?} should be rejected");
        }
    }

    #[test]
    fn operator_emails_are_normalized_before_validation() {
        // The handler trims + lowercases before the plausible check; the
        // validator itself must accept the normalized form.
        let normalized = "  Ops@ApexMail.ee ".trim().to_lowercase();
        assert!(is_plausible_email(&normalized));
        assert_eq!(normalized, "ops@apexmail.ee");
    }
}
