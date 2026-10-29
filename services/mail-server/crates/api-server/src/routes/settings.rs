//! Self-service workspace settings: SMTP credential message-class management.
//!
//! External audit 6 remediation #6. Migration 272 gave every `users` row a
//! server-owned `message_class` (CHECK `marketing`/`transactional`/`service`,
//! default `marketing`) — the send category the MTA submission path stamps on
//! everything AUTHenticated with that credential. Until this module nothing
//! but SQL could change it, so onboarding 100 transactional senders meant 100
//! database/operator edits.
//!
//! * `GET /v1/settings/smtp-credentials` — the caller's OWN tenant's
//!   SMTP-capable users (the submission AUTH path authenticates `users` rows;
//!   a row is an SMTP credential exactly when it carries a password, which is
//!   what `password_hash IS NOT NULL` encodes). Tenant-pinned by the
//!   authenticated principal, never by a request parameter.
//! * `PATCH /v1/settings/smtp-credentials/:id/message-class` — set the class
//!   of ONE of the caller's own credentials. Body
//!   `{"messageClass": "marketing"|"transactional"|"service"}`; any other
//!   value (or extra field) is a 422 before a row is touched. A credential of
//!   another tenant is an indistinguishable 404. The change and its
//!   hash-chained audit entry commit in ONE transaction: an unauditable class
//!   change (a consent-exempt `transactional`/`service` grant is exactly what
//!   the audit trail exists for) must not happen.
//!
//! Both handlers require the wildcard scope, i.e. the tenant's owner/admin
//! role: migration 272 deliberately exposes the column as "an explicit,
//! admin-gated choice", and no narrower mintable scope exists for it (the
//! API-key scope registry lives in `routes::auth`, outside this module). The
//! control-plane twin — an operator changing ANY tenant's credential at
//! `PATCH /v1/admin/tenants/:tenant_id/smtp-credentials/:id/message-class` —
//! lives in `routes::admin::tenants` and shares this module's
//! [`apply_message_class_change`] core, so the two surfaces can never drift.

use axum::extract::{Path, State};
use axum::routing::{get, patch};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use crate::error::ApiError;
use crate::middleware::auth::{require_scopes, AuthUser};
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/smtp-credentials", get(list_smtp_credentials))
        .route(
            "/smtp-credentials/:id/message-class",
            patch(update_smtp_credential_message_class),
        )
}

// ─── Types ─────────────────────────────────────────────────────

/// One SMTP credential row as the settings surface presents it. The
/// `users` row IS the credential (migration 272 / the MTA submission AUTH
/// path); `email` is the username it authenticates with.
#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct SmtpCredentialRow {
    pub id: String,
    pub email: String,
    pub message_class: String,
    pub status: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

/// The message-class vocabulary, exactly the migration 272 CHECK constraint
/// and the canonical `message_category` constants the queue's admission
/// policy shares (`apexmail_lib::email_headers::message_category`).
/// Deserialization is STRICT lowercase: `"MARKETING"`, `"Marketing"` and
/// `"banana"` all fail the request as a 422 before any row is read, so the
/// only values that can reach the UPDATE are values the CHECK admits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MessageClass {
    Marketing,
    Transactional,
    Service,
}

impl MessageClass {
    pub(crate) fn as_str(self) -> &'static str {
        use apexmail_lib::email_headers::message_category;
        match self {
            MessageClass::Marketing => message_category::MARKETING,
            MessageClass::Transactional => message_category::TRANSACTIONAL,
            MessageClass::Service => message_category::SERVICE,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateMessageClassRequest {
    #[serde(rename = "messageClass")]
    pub message_class: MessageClass,
}

/// Which surface asked for the change: picks the audit action and details
/// tag, nothing else (guards live with each surface's handler).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MessageClassSurface {
    /// `/v1/settings/...`, the tenant's own owner/admin.
    SelfService,
    /// `/v1/admin/tenants/:tenant_id/...`, a system-tenant operator.
    ControlPlane,
}

impl MessageClassSurface {
    fn audit_action(self) -> &'static str {
        match self {
            MessageClassSurface::SelfService => "smtp_credential.message_class_updated",
            MessageClassSurface::ControlPlane => {
                "control_plane.smtp_credential.message_class_updated"
            }
        }
    }

    fn details_tag(self) -> &'static str {
        match self {
            MessageClassSurface::SelfService => "self_service",
            MessageClassSurface::ControlPlane => "control_plane",
        }
    }
}

/// The credential projection both the list and patch handlers return.
const CREDENTIAL_COLUMNS: &str = "id::text AS id, email, message_class, status, created_at";

/// Reject an id that cannot be a `users.id` (uuid) as a plain 404: an
/// unparseable id matches no row, and the 404 shape keeps it
/// indistinguishable from another tenant's credential.
pub(crate) fn parse_credential_id(raw: &str) -> Result<uuid::Uuid, ApiError> {
    uuid::Uuid::parse_str(raw).map_err(|_| ApiError::NotFound("smtp credential not found".into()))
}

// ─── Handlers ──────────────────────────────────────────────────

async fn list_smtp_credentials(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<Json<Vec<SmtpCredentialRow>>, ApiError> {
    require_scopes(&auth, &["*"])?;

    let rows = sqlx::query_as::<_, SmtpCredentialRow>(&format!(
        "SELECT {CREDENTIAL_COLUMNS} \
         FROM users \
         WHERE tenant_id = $1 AND password_hash IS NOT NULL \
         ORDER BY created_at, id"
    ))
    .bind(&auth.tenant_id)
    .fetch_all(&state.db)
    .await?;

    Ok(Json(rows))
}

async fn update_smtp_credential_message_class(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<String>,
    Json(body): Json<UpdateMessageClassRequest>,
) -> Result<Json<SmtpCredentialRow>, ApiError> {
    require_scopes(&auth, &["*"])?;

    let credential_id = parse_credential_id(&id)?;
    let row = apply_message_class_change(
        &state,
        &auth.tenant_id,
        credential_id,
        body.message_class,
        MessageClassSurface::SelfService,
        auth.user_id.as_deref(),
    )
    .await?;

    Ok(Json(row))
}

// ─── Shared mutation core ──────────────────────────────────────

/// Change one credential's `message_class`, shared verbatim by the
/// self-service (`/v1/settings/...`) and control-plane
/// (`/v1/admin/tenants/:tenant_id/...`) surfaces so their validation,
/// tenant pinning, persistence and audit semantics cannot drift.
///
/// `tenant_id` is the tenant that OWNS the credential — the authenticated
/// principal's tenant on the self-service path, the path parameter on the
/// admin path; either way the UPDATE can only ever touch a row of that
/// tenant, and a credential that does not exist there is an honest 404.
///
/// One transaction: row lock → UPDATE … RETURNING → hash-chained audit
/// entry (see `audit_log::insert_audit_log_in_tx_with_env`, the same
/// transactional-audit contract as the tenant deletion machinery). An audit
/// failure aborts the class change, never the reverse. Returns the updated
/// row for the response body.
pub(crate) async fn apply_message_class_change(
    state: &AppState,
    tenant_id: &str,
    credential_id: uuid::Uuid,
    new_class: MessageClass,
    surface: MessageClassSurface,
    actor_user_id: Option<&str>,
) -> Result<SmtpCredentialRow, ApiError> {
    let mut tx = state.db.begin().await?;

    // Lock and load the current row first: the audit details must carry the
    // PREVIOUS class, and the 404 must come before any write.
    let existing: Option<SmtpCredentialRow> = sqlx::query_as(&format!(
        "SELECT {CREDENTIAL_COLUMNS} \
         FROM users WHERE id = $1 AND tenant_id = $2 FOR UPDATE"
    ))
    .bind(credential_id)
    .bind(tenant_id)
    .fetch_optional(&mut *tx)
    .await?;
    let existing =
        existing.ok_or_else(|| ApiError::NotFound("smtp credential not found".into()))?;

    let updated: SmtpCredentialRow = sqlx::query_as(&format!(
        "UPDATE users SET message_class = $1, updated_at = NOW() \
         WHERE id = $2 AND tenant_id = $3 \
         RETURNING {CREDENTIAL_COLUMNS}"
    ))
    .bind(new_class.as_str())
    .bind(credential_id)
    .bind(tenant_id)
    .fetch_one(&mut *tx)
    .await?;

    crate::audit_log::insert_audit_log_in_tx_with_env(
        &mut tx,
        state.config.environment.is_production(),
        Some(tenant_id),
        actor_user_id,
        surface.audit_action(),
        "smtp_credential",
        Some(&updated.id),
        serde_json::json!({
            "credential_id": updated.id,
            "credential_email": updated.email,
            "previous_message_class": existing.message_class,
            "new_message_class": new_class.as_str(),
            "surface": surface.details_tag(),
        }),
        None,
        None,
        chrono::Utc::now(),
    )
    .await?;

    tx.commit().await?;

    tracing::info!(
        tenant_id = %tenant_id,
        credential_id = %updated.id,
        previous_message_class = %existing.message_class,
        new_message_class = new_class.as_str(),
        surface = surface.details_tag(),
        "SMTP credential message class updated"
    );

    Ok(updated)
}

// ─── Tests ─────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::test_support::adv::AdvEnv;
    use axum::http::{Method, StatusCode};

    /// Seed an SMTP-capable user (a password-bearing `users` row) in
    /// `tenant_id`, returning its uuid string. Mirrors the session seeder's
    /// canonical INSERT, with a globally-unique email (users.email UNIQUE).
    async fn seed_smtp_user(pool: &sqlx::PgPool, tenant_id: &str) -> String {
        let id = uuid::Uuid::new_v4();
        sqlx::query(
            "INSERT INTO users (id, tenant_id, email, name, password_hash, role, status, email_verified)
             VALUES ($1::uuid, $2, $3, 'SMTP Credential', $4, 'member', 'active', true)",
        )
        .bind(id)
        .bind(tenant_id)
        .bind(format!("smtp-{id}@example.com"))
        .bind(apexmail_lib::hash_password("correct horse battery staple").expect("hash password"))
        .execute(pool)
        .await
        .expect("seed smtp credential user");
        id.to_string()
    }

    #[test]
    fn message_class_deserializes_exactly_the_check_vocabulary() {
        for valid in ["marketing", "transactional", "service"] {
            let parsed: UpdateMessageClassRequest =
                serde_json::from_str(&format!("{{\"messageClass\":\"{valid}\"}}"))
                    .unwrap_or_else(|error| panic!("{valid} must parse: {error}"));
            assert_eq!(parsed.message_class.as_str(), valid);
        }
        // Case and vocabulary drift never reach the UPDATE: strict lowercase,
        // the exact CHECK values.
        for invalid in ["MARKETING", "Transactional", "banana", "", "notifications"] {
            let result: Result<UpdateMessageClassRequest, _> =
                serde_json::from_str(&format!("{{\"messageClass\":\"{invalid}\"}}"));
            assert!(result.is_err(), "{invalid} must be rejected");
        }
        // Unknown fields are rejected too (deny_unknown_fields).
        assert!(serde_json::from_str::<UpdateMessageClassRequest>(
            r#"{"messageClass":"service","extra":true}"#
        )
        .is_err());
    }

    /// GET lists the caller's OWN credentials only — another tenant's
    /// credential (and password-less users) never appear.
    #[tokio::test]
    async fn listing_is_tenant_pinned_to_the_authenticated_principal() {
        let Some(pool) = crate::test_db::canonical_pool("smtp_class_list").await else {
            return;
        };
        let Some((env, tenant_id, session_user)) = AdvEnv::session(pool.clone(), "owner").await
        else {
            return;
        };
        let extra_credential = seed_smtp_user(&pool, &tenant_id).await;

        // A second tenant with its own credential must be invisible.
        let (_env_b, tenant_b) = AdvEnv::tenant(pool.clone(), &["*"]).await;
        let foreign_credential = seed_smtp_user(&pool, &tenant_b).await;

        let (status, body) = env.get("/v1/settings/smtp-credentials").await;
        assert_eq!(status, StatusCode::OK, "{body}");

        let rows = body.as_array().expect("credential array");
        let ids: Vec<&str> = rows
            .iter()
            .map(|row| row["id"].as_str().expect("id string"))
            .collect();
        assert!(
            ids.contains(&session_user.as_str()),
            "the session's own credential is listed"
        );
        assert!(
            ids.contains(&extra_credential.as_str()),
            "a second own credential is listed"
        );
        assert!(
            !ids.contains(&foreign_credential.as_str()),
            "another tenant's credential must never be listed"
        );
        for row in rows {
            // Every row carries the full projection, marketing until changed.
            assert_eq!(row["message_class"], "marketing");
            assert!(row["email"].as_str().is_some());
            assert!(row["status"].as_str().is_some());
            assert!(row["created_at"].as_str().is_some());
        }
    }

    /// PATCH persists the new class (SELECT round-trip), returns the updated
    /// row, and writes an attributed audit entry.
    #[tokio::test]
    async fn patch_persists_the_class_and_writes_an_attributed_audit_row() {
        let Some(pool) = crate::test_db::canonical_pool("smtp_class_patch").await else {
            return;
        };
        let Some((env, tenant_id, user_id)) = AdvEnv::session(pool.clone(), "owner").await else {
            return;
        };
        let credential = seed_smtp_user(&pool, &tenant_id).await;

        let (status, body) = env
            .send_json(
                Method::PATCH,
                &format!("/v1/settings/smtp-credentials/{credential}/message-class"),
                Some(r#"{"messageClass":"transactional"}"#),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["id"], credential.as_str());
        assert_eq!(body["message_class"], "transactional");

        // The class actually persists (SELECT round-trip, not just the echo).
        let stored: String = sqlx::query_scalar(
            "SELECT message_class FROM users WHERE id = $1::uuid AND tenant_id = $2",
        )
        .bind(&credential)
        .bind(&tenant_id)
        .fetch_one(&pool)
        .await
        .expect("stored class");
        assert_eq!(stored, "transactional");

        // And the change is audit-logged with the acting user and both
        // classes (previous → new).
        let (action, actor, details): (String, Option<String>, serde_json::Value) = sqlx::query_as(
            "SELECT action, user_id, details FROM audit_logs \
             WHERE tenant_id = $1 AND action = 'smtp_credential.message_class_updated'",
        )
        .bind(&tenant_id)
        .fetch_one(&pool)
        .await
        .expect("audit row");
        assert_eq!(action, "smtp_credential.message_class_updated");
        assert_eq!(actor.as_deref(), Some(user_id.as_str()));
        assert_eq!(details["previous_message_class"], "marketing");
        assert_eq!(details["new_message_class"], "transactional");
        assert_eq!(details["surface"], "self_service");
    }

    /// Tenant A's PATCH on tenant B's credential is an indistinguishable 404
    /// and leaves B's class untouched.
    #[tokio::test]
    async fn tenant_a_cannot_mutate_tenant_bs_credential() {
        let Some(pool) = crate::test_db::canonical_pool("smtp_class_isolation").await else {
            return;
        };
        let Some((env_a, _tenant_a, _user_a)) = AdvEnv::session(pool.clone(), "owner").await else {
            return;
        };
        let (_env_b, tenant_b) = AdvEnv::tenant(pool.clone(), &["*"]).await;
        let foreign_credential = seed_smtp_user(&pool, &tenant_b).await;

        let (status, body) = env_a
            .send_json(
                Method::PATCH,
                &format!("/v1/settings/smtp-credentials/{foreign_credential}/message-class"),
                Some(r#"{"messageClass":"service"}"#),
            )
            .await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{body}");

        let stored: String = sqlx::query_scalar(
            "SELECT message_class FROM users WHERE id = $1::uuid AND tenant_id = $2",
        )
        .bind(&foreign_credential)
        .bind(&tenant_b)
        .fetch_one(&pool)
        .await
        .expect("stored class");
        assert_eq!(
            stored, "marketing",
            "a refused cross-tenant PATCH must not write"
        );
    }

    /// An invalid class value is a 422 (the Json extractor's data rejection)
    /// and never reaches the database.
    #[tokio::test]
    async fn invalid_class_values_are_a_422_without_side_effects() {
        let Some(pool) = crate::test_db::canonical_pool("smtp_class_422").await else {
            return;
        };
        let Some((env, tenant_id, _user)) = AdvEnv::session(pool.clone(), "owner").await else {
            return;
        };
        let credential = seed_smtp_user(&pool, &tenant_id).await;

        for bad_body in [
            r#"{"messageClass":"banana"}"#,
            r#"{"messageClass":"MARKETING"}"#,
            r#"{"messageClass":"transactional","extra":true}"#,
        ] {
            let (status, _body) = env
                .send_json(
                    Method::PATCH,
                    &format!("/v1/settings/smtp-credentials/{credential}/message-class"),
                    Some(bad_body),
                )
                .await;
            assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{bad_body}");
        }

        let stored: String = sqlx::query_scalar(
            "SELECT message_class FROM users WHERE id = $1::uuid AND tenant_id = $2",
        )
        .bind(&credential)
        .bind(&tenant_id)
        .fetch_one(&pool)
        .await
        .expect("stored class");
        assert_eq!(stored, "marketing", "a 422 must never change the class");
    }

    /// The surface is admin-gated per migration 272: a member-role session
    /// (no wildcard scope) can neither list nor change classes.
    #[tokio::test]
    async fn member_role_sessions_cannot_read_or_change_classes() {
        let Some(pool) = crate::test_db::canonical_pool("smtp_class_scope").await else {
            return;
        };
        let Some((env, tenant_id, _user_id)) = AdvEnv::session(pool.clone(), "member").await else {
            return;
        };
        let credential = seed_smtp_user(&pool, &tenant_id).await;

        let (status, body) = env.get("/v1/settings/smtp-credentials").await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{body}");

        let (status, body) = env
            .send_json(
                Method::PATCH,
                &format!("/v1/settings/smtp-credentials/{credential}/message-class"),
                Some(r#"{"messageClass":"service"}"#),
            )
            .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{body}");

        let stored: String = sqlx::query_scalar(
            "SELECT message_class FROM users WHERE id = $1::uuid AND tenant_id = $2",
        )
        .bind(&credential)
        .bind(&tenant_id)
        .fetch_one(&pool)
        .await
        .expect("stored class");
        assert_eq!(stored, "marketing");
    }
}
