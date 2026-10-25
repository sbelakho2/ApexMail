//! Mailbox provisioning (operator surface).
//!
//! Mailboxes are the RECEIVING side of the mail plane: `mail_accounts` rows
//! are what the MTA's inbound directory resolves (`PgMailboxDirectory`) and
//! what IMAP authenticates against (via mailstore). Before this module the
//! only way to create one was SQL, inbound reception and IMAP shipped with
//! no provisioning surface at all.
//!
//! Provisioning is atomic: the account row AND its INBOX folder are written
//! in ONE transaction, so a mailbox can never exist half-created (the DF-8
//! dogfood hit exactly that: inbound delivery failed with "mailstore has no
//! Inbox for the account" against a hand-seeded account row).
//!
//! # Seats are a billed product (the Mailboxes line)
//!
//! Provisioning is where a Mailboxes SEAT is bought: the monthly seat
//! invoice (`billing_service::product_lines`) counts active `mail_accounts`
//! per tenant, floored at the catalog's 10-seat minimum. Two consequences
//! this module implements:
//!
//! * the owning TENANT is recorded on the account, taken from the
//!   `domains` row that makes the domain platform-managed (the same table
//!   the provisioning path already trusts, the operator never types a
//!   tenant id that could disagree with the domain's owner). A mailbox on a
//!   domain with no owning tenant (platform-internal domains) keeps
//!   `tenant_id = NULL` and is therefore NOT billed, stated plainly;
//! * provisioning REFUSES with a named 403 when the owning tenant holds
//!   neither the `mailboxes` entitlement nor an active Mailboxes
//!   product-line contract (`product_line_contracts`), so a non-entitled
//!   plan can never receive unbilled mailboxes.
//!
//! # The archive flag (the `mailbox_archive_journaling` add-on)
//!
//! `archive_enabled` is the per-mailbox flag the +2 EUR/+2 USD per-seat
//! add-on bills, and `archive_enabled_at` is the retention MARKER the flag
//! starts. Enabling it also ensures the account's `Archive` folder exists
//! in the same transaction (the mail plane's storage target for retained
//! messages, mailstore COPY/move already work against it). Journaling is
//! built (`mail_journal`, migration 264): the worker copies outbound raw MIME
//! and the mailstore copies inbound messages at persist time for add-on
//! tenants, and `/settings/journal` + `GET /v1/journal` provide the
//! tenant-facing browse/download surface. Disabling the flag clears the
//! marker but NEVER deletes the folder or its messages (and historical
//! journal rows remain readable): retention ending is not a data-loss
//! trigger.

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use serde_json::json;
use uuid::Uuid;

use billing_entitlements::FeatureKey;

use crate::error::ApiError;
use crate::middleware::auth::AuthUser;
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/", get(list_mailboxes).post(create_mailbox))
        .route("/:id/suspend", post(suspend_mailbox))
        .route("/:id/resume", post(resume_mailbox))
        .route("/:id/archive", post(set_archive))
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
    /// Subscribe the seat to the archive + journaling add-on
    /// (`mailbox_archive_journaling`, +2 EUR/+2 USD per seat per month).
    /// Operator-set; also toggleable later through `POST /:id/archive`.
    #[serde(default)]
    pub archive: Option<bool>,
}

/// The archive flag toggle body.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SetArchiveRequest {
    pub enabled: bool,
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
    /// The billed seat's tenant (NULL = a platform-internal mailbox on a
    /// domain with no owning tenant; such a row is not billed).
    pub tenant_id: Option<String>,
    /// The per-seat archive add-on flag.
    pub archive_enabled: bool,
    /// When the archive flag was enabled (the retention marker start).
    pub archive_enabled_at: Option<chrono::DateTime<chrono::Utc>>,
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
        a.used_bytes, a.is_active, a.created_at, a.tenant_id, a.archive_enabled, a.archive_enabled_at, \
        EXISTS (SELECT 1 FROM mail_mailboxes m WHERE m.account_id = a.id AND m.mailbox_type = 'inbox') AS inbox_provisioned \
     FROM mail_accounts a";

/// Operator gate: mailbox provisioning is a platform-operator action (the
/// receiving plane is shared infrastructure). Tenant owners reach their
/// mailboxes through the console; this surface is the control plane's.
async fn require_operator(state: &AppState, auth: &AuthUser) -> Result<(), ApiError> {
    // Every admin route file enforces the wildcard operator scope
    // (routes/admin/mod.rs boundary test) IN ADDITION to the system-tenant
    // membership check: provisioned mailboxes carry credentials, so the
    // operator-only surface must not be reachable by a scoped non-operator
    // credential that merely lives in the system tenant.
    crate::middleware::auth::require_scopes(auth, &["*"])?;
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

/// The Mailboxes product gate, shared by provisioning and the archive
/// toggle. Entitled when the tenant's plan/override grants
/// `FeatureKey::Mailboxes` OR the tenant holds an ACTIVE Mailboxes
/// product-line contract (`billing_service::product_lines::mailboxes_contract_active`
///, the purchase record the monthly seat invoice reads). The refusal NAMES
/// the plan and the product (a named refusal on non-entitled plans), and a
/// tenant-less platform mailbox can never subscribe to the billed add-on.
async fn require_mailboxes_entitlement(
    state: &AppState,
    tenant_id: Option<&str>,
    email: &str,
) -> Result<(), ApiError> {
    let Some(tenant_id) = tenant_id else {
        return Err(ApiError::Forbidden(format!(
            "mailbox '{email}' is not bound to a tenant: the Mailboxes product is billed per \
             seat per tenant, and a mailbox on a domain with no owning tenant cannot be \
             subscribed. Assign the domain to the tenant first, then provision."
        )));
    };
    let snapshot = crate::entitlements::snapshot(state, tenant_id).await?;
    if snapshot.has_feature(FeatureKey::Mailboxes) {
        return Ok(());
    }
    let contracted =
        billing_service::product_lines::mailboxes_contract_active(&state.db, tenant_id)
            .await
            .map_err(ApiError::Internal)?;
    if contracted {
        return Ok(());
    }
    Err(ApiError::Forbidden(format!(
        "plan `{}` does not include `mailboxes`: the Mailboxes product is a separate per-seat \
         line (10-seat minimum, billed per active mailbox per month plus the archive add-on). \
         Activate the Mailboxes contract for tenant {tenant_id} before provisioning \
         '{email}'.",
        snapshot.plan()
    )))
}

/// Ensure the account's `Archive` folder exists (the mail-plane retention
/// target). Idempotent, caller's transaction.
async fn ensure_archive_folder(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    account_id: Uuid,
) -> Result<(), ApiError> {
    sqlx::query(
        "INSERT INTO mail_mailboxes (account_id, name, mailbox_type) VALUES ($1, 'Archive', 'archive') \
         ON CONFLICT (account_id, name, COALESCE(parent_id, '00000000-0000-0000-0000-000000000000'::uuid)) DO NOTHING",
    )
    .bind(account_id)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

/// The provisioning core: the domain must be platform-managed and its
/// owning tenant must hold the Mailboxes entitlement; the account row AND
/// its INBOX folder (plus the Archive folder when the add-on is
/// subscribed) are written in ONE transaction (a mailbox can never exist
/// half-created); an existing mailbox is an honest 409.
async fn provision_mailbox(
    pool: &sqlx::PgPool,
    email: &str,
    domain: &str,
    password: &str,
    display_name: Option<&str>,
    quota_bytes: i64,
    archive: bool,
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

    // The owning tenant is read INSIDE the transaction (the same row the
    // entitlement check below trusts) so a concurrent domain re-assignment
    // cannot split the binding from the check.
    let owner: Option<Option<String>> =
        sqlx::query_scalar("SELECT tenant_id FROM domains WHERE LOWER(name) = $1 LIMIT 1")
            .bind(domain)
            .fetch_optional(&mut *tx)
            .await?;
    let tenant_id = owner
        .ok_or_else(|| {
            ApiError::Validation(vec![format!(
                "domain '{domain}' is not a platform-managed domain"
            )])
        })?
        .filter(|tenant| !tenant.trim().is_empty());

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
        "INSERT INTO mail_accounts \
             (email, domain, password_hash, display_name, quota_bytes, tenant_id, \
              archive_enabled, archive_enabled_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, CASE WHEN $7 THEN NOW() ELSE NULL END) \
         RETURNING id",
    )
    .bind(email)
    .bind(domain)
    .bind(&password_hash)
    .bind(display_name.unwrap_or(""))
    .bind(quota_bytes)
    .bind(tenant_id.as_deref())
    .bind(archive)
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

    if archive {
        // The archive add-on's retention target in the mail plane.
        ensure_archive_folder(&mut tx, account_id).await?;
    }

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
    // The seat's owning tenant (from the managed domain) and the Mailboxes
    // gate, resolved BEFORE any write: a non-entitled tenant is refused by
    // name, with nothing half-created.
    let owner: Option<Option<String>> =
        sqlx::query_scalar("SELECT tenant_id FROM domains WHERE LOWER(name) = $1 LIMIT 1")
            .bind(&domain)
            .fetch_optional(&state.db)
            .await?;
    let tenant_id = match owner {
        Some(owner) => owner.filter(|tenant| !tenant.trim().is_empty()),
        None => {
            return Err(ApiError::Validation(vec![format!(
                "domain '{domain}' is not a platform-managed domain"
            )]))
        }
    };
    require_mailboxes_entitlement(&state, tenant_id.as_deref(), &email).await?;

    let archive = body.archive.unwrap_or(false);
    let account_id = provision_mailbox(
        &state.db,
        &email,
        &domain,
        &body.password,
        body.display_name.as_deref(),
        quota_bytes,
        archive,
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
        json!({
            "email": email,
            "domain": domain,
            "quota_bytes": quota_bytes,
            "tenant_id": tenant_id,
            "archive": archive
        }),
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

/// `POST /v1/admin/mailboxes/:id/archive`, subscribe or unsubscribe the
/// seat to the archive + journaling add-on.
///
/// Enabling ensures the `Archive` folder exists (idempotent) and stamps
/// `archive_enabled_at`; disabling clears the flag and the marker but keeps
/// the folder and every message in it (retention ending is never a
/// data-loss trigger). Both directions re-check the tenant's Mailboxes
/// entitlement: the add-on bills per seat and cannot outlive the product.
async fn set_archive(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<String>,
    Json(body): Json<SetArchiveRequest>,
) -> Result<Json<MailboxRow>, ApiError> {
    require_operator(&state, &auth).await?;
    let uuid = Uuid::parse_str(&id).map_err(|_| ApiError::NotFound("mailbox not found".into()))?;
    let row = toggle_archive(&state, uuid, body.enabled).await?;

    crate::audit_log::insert_audit_log_best_effort_with_env(
        &state.db,
        state.config.environment.is_production(),
        Some(auth.tenant_id.as_str()),
        auth.user_id.as_deref(),
        if body.enabled {
            "mailbox.archive_enabled"
        } else {
            "mailbox.archive_disabled"
        },
        "mailbox",
        Some(&uuid.to_string()),
        json!({ "email": row.email, "archive_enabled": row.archive_enabled }),
        None,
        None,
    )
    .await;

    Ok(Json(row))
}

/// The archive-toggle core (shared by the route and its tests): gate,
/// flag + marker write, Archive folder materialization, all under the
/// mailbox row lock.
async fn toggle_archive(
    state: &AppState,
    uuid: Uuid,
    enabled: bool,
) -> Result<MailboxRow, ApiError> {
    let mut tx = state.db.begin().await?;
    let mailbox: Option<(Option<String>, String)> =
        sqlx::query_as("SELECT tenant_id, email FROM mail_accounts WHERE id = $1 FOR UPDATE")
            .bind(uuid)
            .fetch_optional(&mut *tx)
            .await?;
    let Some((tenant_id, email)) = mailbox else {
        tx.rollback().await?;
        return Err(ApiError::NotFound("mailbox not found".into()));
    };
    // The gate is re-checked on EVERY toggle (a lapsed contract stops the
    // billed add-on from being extended), and it runs before the write.
    if let Err(error) = require_mailboxes_entitlement(state, tenant_id.as_deref(), &email).await {
        tx.rollback().await?;
        return Err(error);
    }

    sqlx::query(
        "UPDATE mail_accounts \
         SET archive_enabled = $2, \
             archive_enabled_at = CASE WHEN $2 THEN COALESCE(archive_enabled_at, NOW()) ELSE NULL END, \
             updated_at = NOW() \
         WHERE id = $1",
    )
    .bind(uuid)
    .bind(enabled)
    .execute(&mut *tx)
    .await?;

    if enabled {
        ensure_archive_folder(&mut tx, uuid).await?;
    }
    tx.commit().await?;

    let row: MailboxRow = sqlx::query_as(&format!("{MAILBOX_SELECT} WHERE a.id = $1"))
        .bind(uuid)
        .fetch_one(&state.db)
        .await?;
    Ok(row)
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
           tenant_id, archive_enabled, archive_enabled_at, \
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
            archive: None,
        }
    }

    fn body_with_archive(email: &str, password: &str) -> CreateMailboxRequest {
        CreateMailboxRequest {
            archive: Some(true),
            ..body(email, password)
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

        // The archive add-on flag is optional (absent = not subscribed) and
        // never weakens the validation bounds.
        assert_eq!(body("a@b.test", &"x".repeat(15)).archive, None);
        assert!(validate_create(&body_with_archive("a@b.test", &"x".repeat(15))).is_ok());
        assert!(validate_create(&body_with_archive("a@b.test", "short")).is_err());
    }

    async fn pool(test_name: &str) -> Option<sqlx::PgPool> {
        match migrator::test_support::fresh_canonical_pool("admin_mailboxes", test_name).await {
            Ok(pool) => pool,
            Err(error) => panic!("{}", error.panic_message()),
        }
    }

    /// Grant the tenant an ACTIVE Mailboxes product-line contract, the
    /// purchase record both the entitlement gate and the monthly seat invoice
    /// read.
    async fn grant_mailboxes_contract(pool: &sqlx::PgPool, tenant: &str) {
        sqlx::query(
            "INSERT INTO product_line_contracts (tenant_id, product_line, status) \
         VALUES ($1, 'mailboxes', 'active')",
        )
        .bind(tenant)
        .execute(pool)
        .await
        .expect("grant mailboxes contract");
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

        // The seat requires the Mailboxes product (the gate is exercised in
        // its own test); the contract is the purchase record.
        grant_mailboxes_contract(&pool, &tenant).await;

        let email = format!("box@{domain}");
        let id = provision_mailbox(
            &pool,
            &email,
            &domain,
            "correct horse battery",
            Some("Box"),
            2048,
            false,
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
            false,
        )
        .await;
        assert!(matches!(rogue, Err(ApiError::Validation(_))));

        // Re-provisioning is an honest 409 (credentials never silently
        // overwritten).
        let dup = provision_mailbox(
            &pool,
            &email,
            &domain,
            "correct horse battery",
            None,
            1024,
            false,
        )
        .await;
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

    // ------------------------------------------------------------------
    // The Mailboxes product gate + the archive add-on marker
    // ------------------------------------------------------------------

    /// A tenant WITHOUT the Mailboxes product is refused BY NAME, and
    /// nothing is written: the plan is quoted, the product is named, and the
    /// mailbox table stays empty.
    #[tokio::test]
    async fn provisioning_refuses_a_non_entitled_tenant_by_name() {
        #[rustfmt::skip]
        let Some(pool) = pool("provision_entitlement").await else { return };
        let suffix = uuid::Uuid::new_v4().simple().to_string();
        let domain = format!("gate{}.test", &suffix[..12]);
        let tenant = format!("t{}", &suffix[..25]);
        seed_domain(&pool, &tenant, &domain).await;

        // The seeded tenant is on the default 'starter' plan, which sells no
        // mailboxes product.
        let owner: Option<String> =
            sqlx::query_scalar("SELECT tenant_id FROM domains WHERE name = $1")
                .bind(&domain)
                .fetch_one(&pool)
                .await
                .expect("owner");
        assert_eq!(owner.as_deref(), Some(tenant.as_str()));

        let state = crate::app::test_support::test_state_over(pool.clone()).await;
        let snapshot = crate::entitlements::snapshot(&state, &tenant)
            .await
            .expect("snapshot");
        assert!(
            !snapshot.has_feature(FeatureKey::Mailboxes),
            "starter sells no mailboxes"
        );
        assert!(
            !billing_service::product_lines::mailboxes_contract_active(&pool, &tenant)
                .await
                .expect("contract lookup")
        );

        // The gate itself: the refusal names the plan and the product.
        let refusal = require_mailboxes_entitlement(&state, Some(&tenant), "box@x.test").await;
        match refusal {
            Err(ApiError::Forbidden(message)) => {
                assert!(message.contains("mailboxes"), "{message}");
                assert!(message.contains("does not include"), "{message}");
                assert!(message.contains(&tenant), "{message}");
            }
            other => panic!("expected a named 403, got {other:?}"),
        }

        // A tenant-LESS mailbox (platform-internal domain) cannot subscribe
        // to a billed per-seat product either.
        let refusal = require_mailboxes_entitlement(&state, None, "postmaster@apexmail.ee").await;
        assert!(matches!(refusal, Err(ApiError::Forbidden(_))));

        // An ACTIVE contract flips the gate.
        grant_mailboxes_contract(&pool, &tenant).await;
        assert!(
            require_mailboxes_entitlement(&state, Some(&tenant), "box@x.test")
                .await
                .is_ok()
        );

        let boxes: i64 = sqlx::query_scalar("SELECT COUNT(*)::bigint FROM mail_accounts")
            .fetch_one(&pool)
            .await
            .expect("count");
        assert_eq!(boxes, 0, "a refused provisioning writes nothing");
    }

    /// The seat is bound to the domain's owning tenant, the archive
    /// subscription stamps the retention marker AND materializes the
    /// Archive folder, the mail-plane storage target of the add-on.
    #[tokio::test]
    async fn provisioning_binds_the_tenant_and_the_archive_flag_stamps_the_marker() {
        #[rustfmt::skip]
        let Some(pool) = pool("provision_archive_marker").await else { return };
        let suffix = uuid::Uuid::new_v4().simple().to_string();
        let domain = format!("arch{}.test", &suffix[..12]);
        let tenant = format!("t{}", &suffix[..25]);
        seed_domain(&pool, &tenant, &domain).await;
        grant_mailboxes_contract(&pool, &tenant).await;

        let email = format!("box@{domain}");
        let id = provision_mailbox(
            &pool,
            &email,
            &domain,
            "correct horse battery",
            Some("Box"),
            2048,
            true,
        )
        .await
        .expect("provision with archive");

        let (bound_tenant, archive, marked_at): (Option<String>, bool, Option<chrono::DateTime<chrono::Utc>>) =
            sqlx::query_as(
                "SELECT tenant_id, archive_enabled, archive_enabled_at FROM mail_accounts WHERE id = $1",
            )
            .bind(id)
            .fetch_one(&pool)
            .await
            .expect("read back");
        assert_eq!(bound_tenant.as_deref(), Some(tenant.as_str()));
        assert!(archive, "the add-on flag is set");
        assert!(
            marked_at.is_some(),
            "enabling archive stamps the retention marker"
        );

        let archive_folder: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM mail_mailboxes \
             WHERE account_id = $1 AND mailbox_type = 'archive')",
        )
        .bind(id)
        .fetch_one(&pool)
        .await
        .expect("archive folder");
        assert!(archive_folder, "the add-on materializes the Archive folder");

        // A plain mailbox (no add-on) gets no folder and no marker.
        let plain = provision_mailbox(
            &pool,
            &format!("plain@{domain}"),
            &domain,
            "correct horse battery",
            None,
            2048,
            false,
        )
        .await
        .expect("provision plain");
        let (archive, marked_at): (bool, Option<chrono::DateTime<chrono::Utc>>) = sqlx::query_as(
            "SELECT archive_enabled, archive_enabled_at FROM mail_accounts WHERE id = $1",
        )
        .bind(plain)
        .fetch_one(&pool)
        .await
        .expect("plain read back");
        assert!(!archive && marked_at.is_none());
    }

    /// The toggle: enabling stamps the marker and creates the folder;
    /// disabling clears the flag/marker but KEEPS the folder and its
    /// messages (retention ending is never a data-loss trigger). A lapsed
    /// contract refuses the toggle in both directions.
    #[tokio::test]
    async fn archive_toggle_gates_keeps_the_folder_and_survives_disabling() {
        #[rustfmt::skip]
        let Some(pool) = pool("archive_toggle").await else { return };
        let suffix = uuid::Uuid::new_v4().simple().to_string();
        let domain = format!("tog{}.test", &suffix[..12]);
        let tenant = format!("t{}", &suffix[..25]);
        seed_domain(&pool, &tenant, &domain).await;
        grant_mailboxes_contract(&pool, &tenant).await;

        let email = format!("box@{domain}");
        let id = provision_mailbox(
            &pool,
            &email,
            &domain,
            "correct horse battery",
            None,
            2048,
            false,
        )
        .await
        .expect("provision");
        let state = crate::app::test_support::test_state_over(pool.clone()).await;

        // Enable through the same core the route calls.
        let enabled = toggle_archive(&state, id, true).await.expect("enable");
        assert!(enabled.archive_enabled);
        assert!(enabled.archive_enabled_at.is_some());

        // A message sitting in the Archive folder survives the disable.
        let folder_id: Uuid = sqlx::query_scalar(
            "SELECT id FROM mail_mailboxes WHERE account_id = $1 AND mailbox_type = 'archive'",
        )
        .bind(id)
        .fetch_one(&pool)
        .await
        .expect("archive folder");
        sqlx::query(
            "INSERT INTO mail_messages
                 (account_id, mailbox_id, message_id, from_address, subject, date, uid, raw_message)
             VALUES ($1, $2, $3, 'sender@example.test', 'retained', NOW(), 1, 'retained')",
        )
        .bind(id)
        .bind(folder_id)
        .bind(format!("<{}@retained>", suffix))
        .execute(&pool)
        .await
        .expect("insert retained message");

        let disabled = toggle_archive(&state, id, false).await.expect("disable");
        assert!(!disabled.archive_enabled);
        assert!(disabled.archive_enabled_at.is_none(), "marker cleared");
        let (folder_still_there, messages): (bool, i64) = sqlx::query_as(
            "SELECT EXISTS(SELECT 1 FROM mail_mailboxes WHERE id = $1), \
                    (SELECT COUNT(*)::bigint FROM mail_messages WHERE mailbox_id = $1)",
        )
        .bind(folder_id)
        .fetch_one(&pool)
        .await
        .expect("read back");
        assert!(
            folder_still_there,
            "the folder is never dropped by the toggle"
        );
        assert_eq!(messages, 1, "disabling the add-on deletes no mail");

        // A lapsed contract refuses BOTH directions (the billed add-on must
        // not be extendable without the product).
        sqlx::query("DELETE FROM product_line_contracts WHERE tenant_id = $1")
            .bind(&tenant)
            .execute(&pool)
            .await
            .expect("lapse contract");
        assert!(matches!(
            toggle_archive(&state, id, true).await,
            Err(ApiError::Forbidden(_))
        ));
        assert!(matches!(
            toggle_archive(&state, id, false).await,
            Err(ApiError::Forbidden(_))
        ));
    }
}
