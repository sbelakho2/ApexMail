//! Mailbox provisioning (operator surface).
//!
//! Mailboxes are the RECEIVING side of the mail plane: `mail_accounts` rows
//! are what the MTA's inbound directory resolves (`PgMailboxDirectory`) and
//! what IMAP authenticates against (via mailstore). Before this module the
//! only way to create one was SQL — inbound reception and IMAP shipped with
//! no provisioning surface at all.
//!
//! Provisioning is atomic: the account row AND its INBOX folder are written
//! in ONE transaction, so a mailbox can never exist half-created (the DF-8
//! dogfood hit exactly that: inbound delivery failed with "mailstore has no
//! Inbox for the account" against a hand-seeded account row).

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use serde_json::json;
use uuid::Uuid;

use crate::error::ApiError;
use crate::middleware::auth::AuthUser;
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/", get(list_mailboxes).post(create_mailbox))
        .route("/:id/suspend", post(suspend_mailbox))
        .route("/:id/resume", post(resume_mailbox))
        .route("/:id", axum::routing::delete(delete_mailbox))
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CreateMailboxRequest {
    pub email: String,
    /// Initial password (min 15 chars, same policy as console signup: the
    /// mailstore verify path checks Argon2 against this hash).
    pub password: String,
    #[serde(default)]
    pub display_name: Option<String>,
    /// Per-mailbox quota in bytes (default 1 GiB).
    #[serde(default)]
    pub quota_bytes: Option<i64>,
}

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct MailboxRow {
    pub id: Uuid,
    pub email: String,
    pub domain: String,
    pub display_name: Option<String>,
    pub quota_bytes: i64,
    pub used_bytes: i64,
    pub is_active: bool,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub inbox_provisioned: bool,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MailboxListQuery {
    #[serde(default)]
    pub domain: Option<String>,
    #[serde(default = "default_limit")]
    pub limit: i64,
}

fn default_limit() -> i64 {
    100
}

const MAILBOX_SELECT: &str = "SELECT a.id, a.email, a.domain, a.display_name, a.quota_bytes, \
        a.used_bytes, a.is_active, a.created_at, \
        EXISTS (SELECT 1 FROM mail_mailboxes m WHERE m.account_id = a.id AND m.mailbox_type = 'inbox') AS inbox_provisioned \
     FROM mail_accounts a";

/// Operator gate: mailbox provisioning is a platform-operator action (the
/// receiving plane is shared infrastructure). Tenant owners reach their
/// mailboxes through the console; this surface is the control plane's.
async fn require_operator(state: &AppState, auth: &AuthUser) -> Result<(), ApiError> {
    crate::middleware::auth::require_system_tenant(state, auth).await
}

/// Validate one create request and normalize its pieces. Pure (no DB) so
/// the bounds are unit-testable without a database.
fn validate_create(body: &CreateMailboxRequest) -> Result<(String, String, i64), ApiError> {
    let email = body.email.trim().to_lowercase();
    let Some((_, domain)) = email.split_once('@') else {
        return Err(ApiError::Validation(vec![
            "email must be a full address (local@domain)".into(),
        ]));
    };
    let domain = domain.to_string();
    if email.len() > 320 || domain.is_empty() || domain.contains(char::is_whitespace) {
        return Err(ApiError::Validation(vec![
            "email must be a valid address of at most 320 characters".into(),
        ]));
    }
    if body.password.chars().count() < 15 || body.password.chars().count() > 128 {
        return Err(ApiError::Validation(vec![
            "password must be 15-128 characters".into(),
        ]));
    }
    let quota_bytes = body.quota_bytes.unwrap_or(1_073_741_824);
    if quota_bytes <= 0 {
        return Err(ApiError::Validation(vec![
            "quotaBytes must be positive".into()
        ]));
    }
    Ok((email, domain, quota_bytes))
}

/// The provisioning core: the domain must be platform-managed; the account
/// row AND its INBOX folder are written in ONE transaction (a mailbox can
/// never exist half-created); an existing mailbox is an honest 409.
async fn provision_mailbox(
    pool: &sqlx::PgPool,
    email: &str,
    domain: &str,
    password: &str,
    display_name: Option<&str>,
    quota_bytes: i64,
) -> Result<Uuid, ApiError> {
    let domain_managed: Option<bool> =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM domains WHERE LOWER(name) = $1)")
            .bind(domain)
            .fetch_one(pool)
            .await?;
    if !domain_managed.unwrap_or(false) {
        return Err(ApiError::Validation(vec![format!(
            "domain '{domain}' is not a platform-managed domain"
        )]));
    }

    let password_hash = apexmail_lib::crypto::hash_password(password)
        .map_err(|e| ApiError::Internal(format!("password hash failed: {e}")))?;

    let mut tx = pool.begin().await?;

    // Idempotence guard: provisioning an existing mailbox is an honest 409
    // (never a silent overwrite of credentials).
    let exists: Option<bool> =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM mail_accounts WHERE LOWER(email) = $1)")
            .bind(email)
            .fetch_one(&mut *tx)
            .await?;
    if exists.unwrap_or(false) {
        return Err(ApiError::Conflict("mailbox already exists".into()));
    }

    let account_id: Uuid = sqlx::query_scalar(
        "INSERT INTO mail_accounts (email, domain, password_hash, display_name, quota_bytes) \
         VALUES ($1, $2, $3, $4, $5) RETURNING id",
    )
    .bind(email)
    .bind(domain)
    .bind(&password_hash)
    .bind(display_name.unwrap_or(""))
    .bind(quota_bytes)
    .fetch_one(&mut *tx)
    .await?;

    // The INBOX is part of the mailbox: the same transaction that creates
    // the account creates its inbox folder (inbound delivery and IMAP both
    // require it).
    sqlx::query(
        "INSERT INTO mail_mailboxes (account_id, name, mailbox_type) VALUES ($1, 'INBOX', 'inbox') \
         ON CONFLICT (account_id, name, COALESCE(parent_id, '00000000-0000-0000-0000-000000000000'::uuid)) DO NOTHING",
    )
    .bind(account_id)
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;
    Ok(account_id)
}

async fn create_mailbox(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(body): Json<CreateMailboxRequest>,
) -> Result<(StatusCode, Json<MailboxRow>), ApiError> {
    require_operator(&state, &auth).await?;

    let (email, domain, quota_bytes) = validate_create(&body)?;
    let account_id = provision_mailbox(
        &state.db,
        &email,
        &domain,
        &body.password,
        body.display_name.as_deref(),
        quota_bytes,
    )
    .await?;

    crate::audit_log::insert_audit_log_best_effort_with_env(
        &state.db,
        state.config.environment.is_production(),
        Some(auth.tenant_id.as_str()),
        auth.user_id.as_deref(),
        "mailbox.provisioned",
        "mailbox",
        Some(&account_id.to_string()),
        json!({ "email": email, "domain": domain, "quota_bytes": quota_bytes }),
        None,
        None,
    )
    .await;

    let row: MailboxRow = sqlx::query_as(&format!("{MAILBOX_SELECT} WHERE a.id = $1"))
        .bind(account_id)
        .fetch_one(&state.db)
        .await?;
    Ok((StatusCode::CREATED, Json(row)))
}

async fn list_mailboxes(
    State(state): State<AppState>,
    auth: AuthUser,
    Query(params): Query<MailboxListQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    require_operator(&state, &auth).await?;
    let limit = params.limit.clamp(1, 500);
    let rows: Vec<MailboxRow> = sqlx::query_as(&format!(
        "{MAILBOX_SELECT} WHERE ($1::text IS NULL OR a.domain = $1) \
         ORDER BY a.created_at DESC LIMIT $2"
    ))
    .bind(params.domain.as_deref())
    .bind(limit)
    .fetch_all(&state.db)
    .await?;
    Ok(Json(json!({ "data": rows, "error": null })))
}

async fn set_active(
    state: &AppState,
    auth: &AuthUser,
    id: &str,
    active: bool,
) -> Result<Json<MailboxRow>, ApiError> {
    require_operator(state, auth).await?;
    let uuid = Uuid::parse_str(id).map_err(|_| ApiError::NotFound("mailbox not found".into()))?;
    let updated: Option<MailboxRow> = sqlx::query_as(
        "UPDATE mail_accounts SET is_active = $2, updated_at = NOW() WHERE id = $1 \
         RETURNING id, email, domain, display_name, quota_bytes, used_bytes, is_active, created_at, \
           EXISTS (SELECT 1 FROM mail_mailboxes m WHERE m.account_id = mail_accounts.id AND m.mailbox_type = 'inbox') AS inbox_provisioned",
    )
    .bind(uuid)
    .bind(active)
    .fetch_optional(&state.db)
    .await?;
    let Some(row) = updated else {
        return Err(ApiError::NotFound("mailbox not found".into()));
    };
    crate::audit_log::insert_audit_log_best_effort_with_env(
        &state.db,
        state.config.environment.is_production(),
        Some(auth.tenant_id.as_str()),
        auth.user_id.as_deref(),
        if active {
            "mailbox.resumed"
        } else {
            "mailbox.suspended"
        },
        "mailbox",
        Some(&uuid.to_string()),
        json!({ "email": row.email }),
        None,
        None,
    )
    .await;
    Ok(Json(row))
}

async fn suspend_mailbox(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<String>,
) -> Result<Json<MailboxRow>, ApiError> {
    set_active(&state, &auth, &id, false).await
}

async fn resume_mailbox(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<String>,
) -> Result<Json<MailboxRow>, ApiError> {
    set_active(&state, &auth, &id, true).await
}

async fn delete_mailbox(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<String>,
) -> Result<StatusCode, ApiError> {
    require_operator(&state, &auth).await?;
    let uuid = Uuid::parse_str(&id).map_err(|_| ApiError::NotFound("mailbox not found".into()))?;
    // Received mail is retained: deleting the ACCOUNT stops delivery and
    // login; the stored messages stay addressable for compliance windows.
    let result = sqlx::query("DELETE FROM mail_accounts WHERE id = $1")
        .bind(uuid)
        .execute(&state.db)
        .await?;
    if result.rows_affected() == 0 {
        return Err(ApiError::NotFound("mailbox not found".into()));
    }
    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn body(email: &str, password: &str) -> CreateMailboxRequest {
        CreateMailboxRequest {
            email: email.into(),
            password: password.into(),
            display_name: None,
            quota_bytes: None,
        }
    }

    #[test]
    fn validation_bounds_are_enforced() {
        // Password 15-128 characters (the console signup policy).
        assert!(validate_create(&body("a@b.test", "short")).is_err());
        assert!(validate_create(&body("a@b.test", &"x".repeat(15))).is_ok());
        assert!(validate_create(&body("a@b.test", &"x".repeat(129))).is_err());
        // Full address required.
        assert!(validate_create(&body("no-at-sign", &"x".repeat(15))).is_err());
        assert!(validate_create(&body("a@", &"x".repeat(15))).is_err());
        // Quota must be positive.
        let mut negative = body("a@b.test", &"x".repeat(15));
        negative.quota_bytes = Some(-1);
        assert!(validate_create(&negative).is_err());
        // Defaults: 1 GiB quota, normalized lowercase email.
        let (email, domain, quota) =
            validate_create(&body("Mixed@Case.Test", &"x".repeat(15))).unwrap();
        assert_eq!(email, "mixed@case.test");
        assert_eq!(domain, "case.test");
        assert_eq!(quota, 1_073_741_824);
    }

    async fn pool(test_name: &str) -> Option<sqlx::PgPool> {
        match migrator::test_support::fresh_canonical_pool("admin_mailboxes", test_name).await {
            Ok(pool) => pool,
            Err(error) => panic!("{}", error.panic_message()),
        }
    }

    async fn seed_domain(pool: &sqlx::PgPool, tenant: &str, domain: &str) {
        sqlx::query(
            "INSERT INTO tenants (id, name, slug) VALUES ($1, 'mailbox test', $1) \
             ON CONFLICT (id) DO NOTHING",
        )
        .bind(tenant)
        .execute(pool)
        .await
        .expect("seed tenant");
        sqlx::query(
            "INSERT INTO domains (id, tenant_id, name, status, verified) \
             VALUES (gen_random_uuid(), $1, $2, 'verified', true)",
        )
        .bind(tenant)
        .bind(domain)
        .execute(pool)
        .await
        .expect("seed domain");
    }

    #[tokio::test]
    async fn provisioning_is_atomic_account_plus_inbox_and_conflicts_are_honest() {
        #[rustfmt::skip]
        let Some(pool) = pool("provision_atomic").await else { return };
        let suffix = uuid::Uuid::new_v4().simple().to_string();
        let domain = format!("mbx{}.test", &suffix[..12]);
        let tenant = format!("t{}", &suffix[..25]);
        seed_domain(&pool, &tenant, &domain).await;

        let email = format!("box@{domain}");
        let id = provision_mailbox(
            &pool,
            &email,
            &domain,
            "correct horse battery",
            Some("Box"),
            2048,
        )
        .await
        .expect("provision");

        // The account AND its INBOX exist (the DF-8 half-created failure).
        let (active, inbox): (bool, bool) = sqlx::query_as(
            "SELECT a.is_active, \
                EXISTS (SELECT 1 FROM mail_mailboxes m WHERE m.account_id = a.id AND m.mailbox_type = 'inbox') \
             FROM mail_accounts a WHERE a.id = $1",
        )
        .bind(id)
        .fetch_one(&pool)
        .await
        .expect("read back");
        assert!(active, "fresh mailbox is active");
        assert!(inbox, "INBOX provisioned in the same transaction");

        // An unmanaged domain is refused before any write.
        let rogue = provision_mailbox(
            &pool,
            "x@not-managed.test",
            "not-managed.test",
            "correct horse battery",
            None,
            1024,
        )
        .await;
        assert!(matches!(rogue, Err(ApiError::Validation(_))));

        // Re-provisioning is an honest 409 (credentials never silently
        // overwritten).
        let dup =
            provision_mailbox(&pool, &email, &domain, "correct horse battery", None, 1024).await;
        assert!(matches!(dup, Err(ApiError::Conflict(_))));

        // Suspend/resume toggles is_active (the inbound directory and IMAP
        // both refuse inactive accounts).
        sqlx::query("UPDATE mail_accounts SET is_active = false WHERE id = $1")
            .bind(id)
            .execute(&pool)
            .await
            .expect("suspend");
        let active: bool = sqlx::query_scalar("SELECT is_active FROM mail_accounts WHERE id = $1")
            .bind(id)
            .fetch_one(&pool)
            .await
            .expect("read");
        assert!(!active);
    }
}
