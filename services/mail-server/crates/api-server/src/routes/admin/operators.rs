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
        "SELECT id::text AS id, email, role, \
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

    // users.id is a UUID on the canonical schema (migration 052): the
    // previous ULID-style string id made every INSERT fail with 22P02 and
    // the route answer 500.
    let id = uuid::Uuid::new_v4();
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
    .bind(id)
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
        &id.to_string(),
        serde_json::json!({ "email": email, "role": role }),
    )
    .await;

    tracing::info!(operator_id = %id, operator_email = %email, "Operator created");
    Ok((
        StatusCode::CREATED,
        Json(CreateOperatorResponse {
            id: id.to_string(),
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

    // users.id is a UUID: parse the path parameter so malformed ids are a
    // 400 instead of a database cast error, and the lookup bind is typed.
    let id = uuid::Uuid::parse_str(id.trim())
        .map_err(|_| ApiError::Validation(vec!["operator id must be a UUID".into()]))?;
    let mut tx = state
        .db
        .begin()
        .await
        .map_err(|_| ApiError::Internal("failed to begin deletion".into()))?;

    // P1-1: tenant-scoped lookup (FOR UPDATE closes the count/delete race);
    // a foreign tenant's operator id resolves to 404, never to a delete.
    // id::text: users.id is a UUID and the row decodes String (the bare
    // column made every lookup fail the type check and surface as 500).
    let target: Option<(String, String)> = sqlx::query_as(
        "SELECT id::text AS id, role FROM users \
         WHERE id = $1 AND tenant_id = $2 AND role IN ('admin', 'owner') FOR UPDATE",
    )
    .bind(id)
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
    .bind(id)
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
        &id.to_string(),
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

#[cfg(test)]
mod adversarial_tests {
    use super::{delete_operator, DeleteOperatorQuery};
    use axum::extract::{Path, Query, State};
    use axum::http::StatusCode;

    use crate::app::test_support::adv::AdvEnv;

    #[tokio::test]
    async fn operator_lifecycle_create_list_delete_with_audits() {
        let Some(pool) = crate::test_db::canonical_pool("ops_lifecycle").await else {
            return;
        };
        let env = AdvEnv::admin(pool.clone()).await;
        // The machine credential carries the literal `system` tenant, and
        // users.tenant_id has an FK to tenants — provision the sentinel row.
        sqlx::query(
            "INSERT INTO tenants (id, name, slug, plan, status)
             VALUES ('system', 'System Sentinel', 'system-sentinel', 'enterprise', 'active')
             ON CONFLICT (id) DO NOTHING",
        )
        .execute(&pool)
        .await
        .expect("seed system tenant");

        // Create (the bug this wave's failing test exposed: the UUID id).
        let email = format!(
            "new-op-{}@example.com",
            &uuid::Uuid::new_v4().simple().to_string()[..8]
        );
        let (status, body) = env
            .post(
                "/v1/admin/operators",
                &serde_json::json!({ "email": format!("  {email} ").to_uppercase(), "name": "New Op", "role": "admin" })
                    .to_string(),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
        assert_eq!(body["email"], email.to_lowercase());
        assert_eq!(body["role"], "admin");
        let temp_password = body["tempPassword"]
            .as_str()
            .expect("temp password")
            .to_string();
        assert!(
            temp_password.len() >= 20,
            "the one-time password is strong enough"
        );
        let new_id = body["id"].as_str().expect("id").to_string();
        assert!(
            uuid::Uuid::parse_str(&new_id).is_ok(),
            "canonical users.id is a UUID"
        );

        // The stored hash verifies against the returned one-time password and
        // is NOT the plaintext.
        let stored_hash: String =
            sqlx::query_scalar("SELECT password_hash FROM users WHERE id = $1::uuid")
                .bind(&new_id)
                .fetch_one(&pool)
                .await
                .expect("row");
        assert_ne!(stored_hash, temp_password);
        assert!(bcrypt::verify(&temp_password, &stored_hash).expect("verify"));

        // Duplicate email is a 409 naming the conflict.
        let (status, body) = env
            .post(
                "/v1/admin/operators",
                &serde_json::json!({ "email": email, "role": "admin" }).to_string(),
            )
            .await;
        assert_eq!(status, StatusCode::CONFLICT, "{body}");

        // List shows the new operator (tenant-scoped to the system tenant).
        let (status, body) = env.get("/v1/admin/operators").await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let items = body.as_array().expect("array");
        assert!(items.iter().any(|o| o["id"] == new_id.as_str()));
        let listed = items.iter().find(|o| o["id"] == new_id.as_str()).unwrap();
        assert_eq!(listed["email"], email.to_lowercase());
        assert_eq!(listed["role"], "admin");
        assert_eq!(listed["mfa_enabled"], false);

        // Creation audit is actor-attributed to the machine key's tenant.
        let (action, resource): (String, String) = sqlx::query_as(
            "SELECT action, resource_id FROM audit_logs \
             WHERE action = 'control_plane.operator.created' AND resource_id = $1",
        )
        .bind(&new_id)
        .fetch_one(&pool)
        .await
        .expect("create audit");
        assert_eq!(action, "control_plane.operator.created");
        assert_eq!(resource, new_id);

        // Delete without confirm is a 400.
        let (status, body) = env.delete(&format!("/v1/admin/operators/{new_id}")).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        // confirm=false likewise.
        let (status, _body) = env
            .delete(&format!("/v1/admin/operators/{new_id}?confirm=false"))
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);

        // With confirm: 204, row gone, deletion audited.
        let (status, _body) = env
            .delete(&format!("/v1/admin/operators/{new_id}?confirm=true"))
            .await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        let remaining: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE id = $1::uuid")
            .bind(&new_id)
            .fetch_one(&pool)
            .await
            .expect("count");
        assert_eq!(remaining, 0);
        let (action,): (String,) = sqlx::query_as(
            "SELECT action FROM audit_logs \
             WHERE action = 'control_plane.operator.deleted' AND resource_id = $1",
        )
        .bind(&new_id)
        .fetch_one(&pool)
        .await
        .expect("delete audit");
        assert_eq!(action, "control_plane.operator.deleted");
    }

    #[tokio::test]
    async fn operator_create_validation_refusals() {
        let Some(pool) = crate::test_db::canonical_pool("ops_refusals").await else {
            return;
        };
        let env = AdvEnv::admin(pool).await;

        // Only admin/owner are assignable.
        let (status, body) = env
            .post(
                "/v1/admin/operators",
                &serde_json::json!({ "email": "ok@example.com", "role": "superuser" }).to_string(),
            )
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        let details = body["error"]["details"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        assert!(
            details
                .iter()
                .any(|d| d.as_str().is_some_and(|d| d.contains("admin, owner"))),
            "{body}"
        );

        // Implausible emails never reach the UNIQUE index.
        for email in ["", "noat", "@example.com", "user@", "user @example.com"] {
            let (status, _body) = env
                .post(
                    "/v1/admin/operators",
                    &serde_json::json!({ "email": email }).to_string(),
                )
                .await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{email}");
        }
    }

    #[tokio::test]
    async fn operator_delete_guards_self_last_owner_and_foreign_ids() {
        let Some(pool) = crate::test_db::canonical_pool("ops_guards").await else {
            return;
        };
        let env = AdvEnv::admin(pool.clone()).await;
        let system_tenant = "system";
        sqlx::query(
            "INSERT INTO tenants (id, name, slug, plan, status)
             VALUES ('system', 'System Sentinel', 'system-sentinel', 'enterprise', 'active')
             ON CONFLICT (id) DO NOTHING",
        )
        .execute(&pool)
        .await
        .expect("seed system tenant");

        // Foreign tenant's operator id: opaque 404 via the tenant-scoped
        // lookup (P1-1).
        let (other_env, other_tenant) = AdvEnv::tenant(pool.clone(), &["*"]).await;
        let foreign_id = uuid::Uuid::new_v4();
        sqlx::query(
            "INSERT INTO users (id, tenant_id, email, name, password_hash, role, status)
             VALUES ($1, $2, 'foreign@example.com', 'Foreign', 'x', 'admin', 'active')",
        )
        .bind(foreign_id)
        .bind(&other_tenant)
        .execute(&pool)
        .await
        .expect("seed foreign operator");
        let (status, _body) = env
            .delete(&format!("/v1/admin/operators/{foreign_id}?confirm=true"))
            .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        let _ = other_env;

        // Two owners in the system tenant: the second one is deletable once
        // another owner remains.
        let owner_a = uuid::Uuid::new_v4();
        let owner_b = uuid::Uuid::new_v4();
        for (id, email) in [
            (owner_a, "owner-a@example.com"),
            (owner_b, "owner-b@example.com"),
        ] {
            sqlx::query(
                "INSERT INTO users (id, tenant_id, email, name, password_hash, role, status)
                 VALUES ($1, $2, $3, 'Owner', 'x', 'owner', 'active')",
            )
            .bind(id)
            .bind(system_tenant)
            .bind(email)
            .execute(&pool)
            .await
            .expect("seed owner");
        }

        // Demote owner_b's peer so owner_a is the LAST owner: deleting it is
        // refused with the appoint-successor message.
        sqlx::query("UPDATE users SET role = 'admin' WHERE id = $1::uuid")
            .bind(owner_b)
            .execute(&pool)
            .await
            .expect("demote peer");
        let (status, body) = env
            .delete(&format!("/v1/admin/operators/{owner_a}?confirm=true"))
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert!(body["error"]["details"]
            .as_array()
            .is_some_and(|details| details
                .iter()
                .any(|d| d.as_str().is_some_and(|d| d.contains("last owner")))));

        // Promote the peer back: the delete succeeds (admin targets are
        // always deletable when an owner remains).
        sqlx::query("UPDATE users SET role = 'owner' WHERE id = $1::uuid")
            .bind(owner_b)
            .execute(&pool)
            .await
            .expect("re-promote peer");
        let (status, _body) = env
            .delete(&format!("/v1/admin/operators/{owner_a}?confirm=true"))
            .await;
        assert_eq!(status, StatusCode::NO_CONTENT);

        // Self-deletion: the CP-session gate means a machine key can never
        // carry a user_id, so this arm is driven by a direct handler call
        // with an operator identity — the router-level gates above are
        // already proven by the other tests.
        let state = crate::app::test_support::test_state_over(pool.clone()).await;
        let operator_auth = crate::middleware::auth::AuthUser {
            tenant_id: system_tenant.into(),
            user_id: Some(owner_b.to_string()),
            api_key_id: None,
            session_id: None,
            scopes: vec!["*".into()],
        };
        let error = delete_operator(
            State(state),
            operator_auth,
            Path(owner_b.to_string()),
            Query(DeleteOperatorQuery {
                confirm: Some("true".into()),
            }),
        )
        .await
        .expect_err("self-deletion must be refused");
        assert!(matches!(
            &error,
            crate::error::ApiError::Validation(messages)
                if messages.iter().any(|m| m.contains("own account"))
        ));

        // Malformed (non-UUID) id is a 400, not a database cast error.
        let (status, _body) = env
            .delete("/v1/admin/operators/not-a-uuid?confirm=true")
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn operators_require_system_tenant_and_wildcard_scope() {
        let Some(pool) = crate::test_db::canonical_pool("ops_scope").await else {
            return;
        };
        let key =
            crate::app::test_support::seed_api_key_for(&pool, "system", &["operators:read"]).await;
        let scoped = AdvEnv::over(pool.clone(), key).await;
        let (status, body) = scoped.get("/v1/admin/operators").await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{body}");

        let (customer, _tenant) = AdvEnv::tenant(pool, &["*"]).await;
        let (status, body) = customer.get("/v1/admin/operators").await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    }
}
