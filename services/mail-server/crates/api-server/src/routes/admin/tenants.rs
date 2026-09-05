//! Tenant management endpoints.
//!

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::routing::get;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::PgPool;

use crate::error::ApiError;
use crate::middleware::auth::AuthUser;
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route(
            "/",
            get(list_tenants).patch(update_tenant).delete(delete_tenant),
        )
        // Domain squatting remediation (audit M-9): transfer a squatted
        // domain to its verified owner. Composed here (rather than a separate
        // nest in app.rs) so it is reachable through the single
        // `/v1/admin/tenants` nest.
        .nest("/domains", super::domains::router())
}

// ─── Types ─────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ListTenantsQuery {
    #[serde(default = "default_limit")]
    pub limit: i64,
    #[serde(default)]
    pub offset: i64,
}

fn default_limit() -> i64 {
    50
}

const TENANT_SCOPED_TABLES_QUERY: &str = "
    SELECT DISTINCT columns.table_name
    FROM information_schema.columns AS columns
    JOIN information_schema.tables AS tables
      ON tables.table_schema = columns.table_schema
     AND tables.table_name = columns.table_name
    WHERE columns.table_schema = 'public'
      AND columns.column_name = 'tenant_id'
      AND columns.table_name <> 'tenants'
      AND columns.table_name NOT IN ('audit_logs', 'cp_access_log', 'secrets_archive')
      AND tables.table_type = 'BASE TABLE'
    ORDER BY columns.table_name
";

/// Evidence tables a tenant deletion must NEVER touch (P1-6). Their rows
/// outlive the tenant: `audit_logs` is the hash-chained compliance record
/// (destroying it is evidence spoliation), `cp_access_log` records who did
/// what in the control plane, and `secrets_archive` holds revoked/rotated
/// secret versions the retention policies still owe. Retention of these is
/// governed by the compliance retention sweep (crates/compliance), not by
/// tenant lifecycle.
const TENANT_DELETION_EVIDENCE_TABLES: [&str; 3] =
    ["audit_logs", "cp_access_log", "secrets_archive"];

/// Pre-deletion obligations check (P1-6), mirroring the compliance
/// retention sweeper's semantics (crates/compliance/src/retention_sweep.rs):
///
/// - `tenants.legal_hold` (migration 121): a held tenant is excluded from
///   every purge — deleting its data is evidence spoliation, so deletion is
///   refused outright.
/// - `tenants.retention_days` (migration 121): a per-tenant retention
///   override obliges the platform to keep the tenant's records for N days.
///   The sweeper keeps rows while `age(row) < retention_days`; a wholesale
///   delete would destroy rows of ANY age, so deletion is refused until the
///   tenant's last-activity anchor (`GREATEST(created_at, updated_at)`) has
///   aged past the window. Rows written after the anchor only extend the
///   obligation, making this the cheap conservative bound; operators who
///   must delete sooner must first clear the override (itself an audited
///   tenant edit).
///
/// Pre-121 databases (no `legal_hold`/`retention_days` columns) degrade the
/// same way the sweeper does: no hold, no override, deletion may proceed.
async fn check_tenant_deletion_preconditions(db: &PgPool, tenant_id: &str) -> Result<(), ApiError> {
    #[derive(sqlx::FromRow)]
    struct TenantObligations {
        legal_hold: bool,
        retention_days: Option<i32>,
        anchor: chrono::DateTime<chrono::Utc>,
    }

    let obligations: Option<TenantObligations> = match sqlx::query_as(
        "SELECT legal_hold, retention_days, GREATEST(created_at, updated_at) AS anchor \
         FROM tenants WHERE id = $1",
    )
    .bind(tenant_id)
    .fetch_optional(db)
    .await
    {
        Ok(row) => row,
        // Pre-121 columns missing: degrade honestly (sweeper parity).
        Err(error) if is_missing_column(&error) => {
            sqlx::query_as(
                "SELECT false AS legal_hold, NULL::int AS retention_days, \
                 GREATEST(created_at, updated_at) AS anchor \
                 FROM tenants WHERE id = $1",
            )
            .bind(tenant_id)
            .fetch_optional(db)
            .await
            .map_err(|_| ApiError::Internal("failed to load tenant obligations".into()))?
        }
        Err(_) => return Err(ApiError::Internal("failed to load tenant obligations".into())),
    };

    let Some(obligations) = obligations else {
        return Err(ApiError::NotFound("tenant not found".into()));
    };

    if obligations.legal_hold {
        return Err(ApiError::Forbidden(
            "tenant is under legal hold — its records must not be deleted".into(),
        ));
    }

    if let Some(days) = obligations.retention_days.filter(|days| *days > 0) {
        let cutoff = obligations.anchor + chrono::Duration::days(i64::from(days));
        if chrono::Utc::now() < cutoff {
            return Err(ApiError::Forbidden(format!(
                "tenant has a {days}-day retention obligation active until {} — \
                 clear tenants.retention_days before deleting",
                cutoff.to_rfc3339()
            )));
        }
    }

    Ok(())
}

fn is_missing_column(error: &sqlx::Error) -> bool {
    matches!(
        error,
        sqlx::Error::Database(db) if db.message().contains("does not exist")
    )
}

/// Delete every tenant-scoped row and the tenant itself, in one transaction.
///
/// Ordering invariant (P1-6): the actor-attributed audit entry is written
/// FIRST, inside the transaction — a failed audit write aborts the deletion
/// (an unauditable tenant deletion must not happen), and the entry itself
/// survives because `audit_logs` is excluded from the reflection-driven
/// delete list via [`TENANT_DELETION_EVIDENCE_TABLES`].
pub async fn delete_tenant_records(
    db: &PgPool,
    tenant_id: &str,
    actor_tenant_id: &str,
    actor_user_id: Option<&str>,
    is_production: bool,
) -> Result<bool, sqlx::Error> {
    let mut transaction = db.begin().await?;

    // Non-optional audit: propagate failures — never delete a tenant
    // without leaving evidence of who ordered it.
    crate::audit_log::insert_audit_log_in_tx_with_env(
        &mut transaction,
        is_production,
        Some(actor_tenant_id),
        actor_user_id,
        "control_plane.tenant.deleted",
        "tenant",
        Some(tenant_id),
        json!({
            "deletedTenantId": tenant_id,
            "evidenceTablesPreserved": TENANT_DELETION_EVIDENCE_TABLES,
        }),
        None,
        None,
        chrono::Utc::now(),
    )
    .await?;

    let mut pending_tables = sqlx::query_scalar::<_, String>(TENANT_SCOPED_TABLES_QUERY)
        .fetch_all(&mut *transaction)
        .await?;

    while !pending_tables.is_empty() {
        let pending_count = pending_tables.len();
        let mut blocked_tables = Vec::new();

        for table_name in pending_tables {
            let delete_query = format!(
                "DELETE FROM {} WHERE tenant_id::text = $1",
                quote_identifier(&table_name)
            );

            match sqlx::query(&delete_query)
                .bind(tenant_id)
                .execute(&mut *transaction)
                .await
            {
                Ok(_) => {}
                Err(error) if is_foreign_key_violation(&error) => blocked_tables.push(table_name),
                Err(error) => return Err(error),
            }
        }

        if blocked_tables.len() == pending_count {
            return Err(sqlx::Error::Protocol(format!(
                "could not resolve tenant cleanup order for tables: {}",
                blocked_tables.join(", ")
            )));
        }

        pending_tables = blocked_tables;
    }

    let result = sqlx::query("DELETE FROM tenants WHERE id = $1")
        .bind(tenant_id)
        .execute(&mut *transaction)
        .await?;

    transaction.commit().await?;
    Ok(result.rows_affected() > 0)
}

fn quote_identifier(identifier: &str) -> String {
    format!("\"{}\"", identifier.replace('"', "\"\""))
}

fn is_foreign_key_violation(error: &sqlx::Error) -> bool {
    matches!(
        error,
        sqlx::Error::Database(database_error)
            if database_error.code().as_deref() == Some("23503")
    )
}

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct TenantRow {
    pub id: String,
    pub name: String,
    pub slug: String,
    pub plan: String,
    pub status: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateTenantRequest {
    pub id: String,
    #[serde(default)]
    pub action: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub plan: Option<String>,
    #[serde(default)]
    pub status: Option<String>,
}

/// Tenant lifecycle statuses the generic editor may write. The suspend
/// action path and the billing subscription override keep their own
/// (different) allowlists — this one guards the direct PATCH field.
const TENANT_ALLOWED_STATUSES: [&str; 3] = ["active", "suspended", "pending"];

fn validate_generic_tenant_update(body: &UpdateTenantRequest) -> Result<(), ApiError> {
    // Tenant plan changes are entitlement-bearing. They must go through the
    // dedicated billing admin override endpoint, which validates the plan and
    // records the override reason/audit trail. This generic tenant editor must
    // never grant a paid plan from an arbitrary request field.
    if body.plan.is_some() {
        return Err(ApiError::Validation(vec![
            "plan updates must use the audited billing plan-override endpoint".to_string(),
        ]));
    }
    // The status field is allowlisted exactly like the action path: an
    // arbitrary string must never reach the UPDATE verbatim.
    if let Some(status) = body.status.as_deref() {
        if !TENANT_ALLOWED_STATUSES.contains(&status) {
            return Err(ApiError::Validation(vec![format!(
                "invalid status '{status}': must be one of {}",
                TENANT_ALLOWED_STATUSES.join(", "),
            )]));
        }
    }

    Ok(())
}

// ─── Handlers ──────────────────────────────────────────────────

async fn list_tenants(
    State(state): State<AppState>,
    auth: AuthUser,
    Query(params): Query<ListTenantsQuery>,
) -> Result<Json<Vec<TenantRow>>, ApiError> {
    crate::middleware::auth::require_scopes(&auth, &["*"])?;
    crate::middleware::auth::require_system_tenant(&state, &auth).await?;

    let limit = params.limit.clamp(1, 200);
    let offset = params.offset.max(0);

    let rows = sqlx::query_as::<_, TenantRow>(
        "SELECT id, name, slug, plan, status, created_at, updated_at
         FROM tenants ORDER BY created_at DESC LIMIT $1 OFFSET $2",
    )
    .bind(limit)
    .bind(offset)
    .fetch_all(&state.db)
    .await?;

    Ok(Json(rows))
}

async fn update_tenant(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(body): Json<UpdateTenantRequest>,
) -> Result<StatusCode, ApiError> {
    crate::middleware::auth::require_scopes(&auth, &["*"])?;
    // Per-handler system-tenant double-check (the router-level gate is
    // defense in depth; every admin handler re-asserts it like audit.rs).
    crate::middleware::auth::require_system_tenant(&state, &auth).await?;
    validate_generic_tenant_update(&body)?;
    let id = body.id;

    // Handle suspend/unsuspend action
    if let Some(action) = &body.action {
        let new_status = match action.as_str() {
            "suspend" => "suspended",
            "unsuspend" => "active",
            _ => {
                return Err(ApiError::Validation(vec![format!(
                    "unknown action: {action}"
                )]))
            }
        };

        // rows_affected distinguishes a no-op edit from a missing tenant:
        // silently 200-ing on an unknown id hides typos from the operator.
        let result =
            sqlx::query("UPDATE tenants SET status = $1, updated_at = NOW() WHERE id = $2")
                .bind(new_status)
                .bind(&id)
                .execute(&state.db)
                .await?;
        if result.rows_affected() == 0 {
            return Err(ApiError::NotFound("tenant not found".into()));
        }

        // Audit log
        log_tenant_audit(&state, &auth, action, Some(&id)).await;
        return Ok(StatusCode::OK);
    }

    // Direct field updates — audited like every other control-plane
    // mutation (the action path above always was). One transaction: a name
    // update succeeding while the status update fails must not leave a
    // half-applied edit; rows_affected gates the 404.
    let mut tx = state.db.begin().await?;
    let mut changed = false;
    let mut rows_affected: u64 = 0;
    if let Some(name) = &body.name {
        rows_affected += sqlx::query("UPDATE tenants SET name = $1, updated_at = NOW() WHERE id = $2")
            .bind(name)
            .bind(&id)
            .execute(&mut *tx)
            .await?
            .rows_affected();
        changed = true;
    }
    if let Some(status) = &body.status {
        rows_affected += sqlx::query(
            "UPDATE tenants SET status = $1, updated_at = NOW() WHERE id = $2",
        )
        .bind(status)
        .bind(&id)
        .execute(&mut *tx)
        .await?
        .rows_affected();
        changed = true;
    }

    if rows_affected == 0 {
        tx.rollback().await?;
        return Err(ApiError::NotFound("tenant not found".into()));
    }
    tx.commit().await?;

    if changed {
        log_tenant_audit(&state, &auth, "tenant_edited", Some(&id)).await;
    }

    Ok(StatusCode::OK)
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeleteTenantRequest {
    pub id: String,
    pub confirmation: String,
}

fn expected_delete_confirmation(tenant_id: &str) -> String {
    format!("DELETE {tenant_id}")
}

fn validate_delete_confirmation(tenant_id: &str, confirmation: &str) -> Result<(), ApiError> {
    let expected = expected_delete_confirmation(tenant_id);
    if confirmation.trim() != expected {
        return Err(ApiError::Validation(vec![format!(
            "confirmation must match '{expected}'"
        )]));
    }

    Ok(())
}

async fn delete_tenant(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(body): Json<DeleteTenantRequest>,
) -> Result<StatusCode, ApiError> {
    crate::middleware::auth::require_scopes(&auth, &["*"])?;
    crate::middleware::auth::require_system_tenant(&state, &auth).await?;
    validate_delete_confirmation(&body.id, &body.confirmation)?;

    // P1-6: legal hold and retention obligations are checked BEFORE any
    // row is touched; the evidence-preserving deletion itself writes its
    // audit entry transactionally (see delete_tenant_records).
    check_tenant_deletion_preconditions(&state.db, &body.id).await?;

    let deleted = delete_tenant_records(
        &state.db,
        &body.id,
        &auth.tenant_id,
        auth.user_id.as_deref(),
        state.config.environment.is_production(),
    )
    .await
    .map_err(|_| ApiError::Internal("tenant deletion failed".into()))?;

    if !deleted {
        return Err(ApiError::NotFound("tenant not found".into()));
    }

    Ok(StatusCode::NO_CONTENT)
}

/// Actor-attributed tenant audit (P2-2): the acting operator's tenant AND
/// user id land in every entry — `user_id: None` left control-plane
/// mutations recorded as "someone did this, unknown who".
async fn log_tenant_audit(state: &AppState, auth: &AuthUser, action: &str, tenant_id: Option<&str>) {
    let resource_id = tenant_id;
    let metadata = if tenant_id.is_some() {
        json!({})
    } else {
        json!({"redacted": true})
    };

    crate::audit_log::insert_audit_log_best_effort_with_env(
        &state.db,
        state.config.environment.is_production(),
        tenant_id,
        auth.user_id.as_deref(),
        action,
        "tenant",
        resource_id,
        metadata,
        None,
        None,
    )
    .await;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// P1-6 source pin: the reflection-driven delete list must never gain a
    /// clause that lets evidence tables back in.
    #[test]
    fn tenant_deletion_never_targets_evidence_tables() {
        for table in TENANT_DELETION_EVIDENCE_TABLES {
            assert!(
                TENANT_SCOPED_TABLES_QUERY.contains(&format!("'{table}'")),
                "evidence table {table} must be excluded from the delete list"
            );
        }
        assert!(TENANT_SCOPED_TABLES_QUERY.contains("NOT IN"));
    }

    #[test]
    fn delete_confirmation_requires_exact_tenant_phrase() {
        validate_delete_confirmation("tenant_123", "DELETE tenant_123")
            .expect("matching confirmation should be accepted");
    }

    #[test]
    fn delete_confirmation_rejects_missing_prefix() {
        assert!(matches!(
            validate_delete_confirmation("tenant_123", "tenant_123"),
            Err(ApiError::Validation(_))
        ));
    }

    #[test]
    fn delete_confirmation_rejects_other_tenant_ids() {
        assert!(matches!(
            validate_delete_confirmation("tenant_123", "DELETE tenant_456"),
            Err(ApiError::Validation(_))
        ));
    }

    #[test]
    fn generic_tenant_update_rejects_entitlement_bearing_plan_field() {
        let request = UpdateTenantRequest {
            id: "tenant_123".into(),
            action: None,
            name: None,
            plan: Some("enterprise".into()),
            status: None,
        };

        assert!(matches!(
            validate_generic_tenant_update(&request),
            Err(ApiError::Validation(errors))
                if errors == ["plan updates must use the audited billing plan-override endpoint"]
        ));
    }

    #[test]
    fn generic_tenant_update_allows_non_entitlement_fields() {
        let request = UpdateTenantRequest {
            id: "tenant_123".into(),
            action: None,
            name: Some("Renamed tenant".into()),
            plan: None,
            status: Some("active".into()),
        };

        validate_generic_tenant_update(&request)
            .expect("non-entitlement tenant fields should remain available");
    }

    #[test]
    fn generic_tenant_update_rejects_statuses_outside_the_allowlist() {
        for bogus in ["superuser-backdoor", "ACTIVE", "", "deleted"] {
            let request = UpdateTenantRequest {
                id: "tenant_123".into(),
                action: None,
                name: None,
                plan: None,
                status: Some(bogus.into()),
            };
            assert!(
                validate_generic_tenant_update(&request).is_err(),
                "status {bogus:?} must be rejected, not written verbatim"
            );
        }
    }

    #[test]
    fn generic_tenant_update_accepts_allowlisted_statuses() {
        for allowed in ["active", "suspended", "pending"] {
            let request = UpdateTenantRequest {
                id: "tenant_123".into(),
                action: None,
                name: None,
                plan: None,
                status: Some(allowed.into()),
            };
            validate_generic_tenant_update(&request)
                .unwrap_or_else(|error| panic!("status {allowed:?} should be accepted: {error:?}"));
        }
    }

    /// Handler-level regression: direct name/status edits must (a) stay
    /// system-tenant-gated per handler, (b) only write allowlisted
    /// statuses, and (c) land in the audit trail like every other
    /// control-plane mutation.
    #[tokio::test]
    async fn update_tenant_whitelists_status_gates_tenant_and_audits() {
        let Some(pool) = crate::test_db::canonical_pool("admin_tenants_patch").await else {
            eprintln!("skipping update_tenant_whitelists_status_gates_tenant_and_audits: no TEST_DATABASE_URL");
            return;
        };
        sqlx::raw_sql(
            "CREATE TABLE IF NOT EXISTS audit_logs (
                id TEXT PRIMARY KEY,
                tenant_id TEXT,
                user_id TEXT,
                session_id TEXT,
                action TEXT NOT NULL,
                resource TEXT NOT NULL,
                resource_id TEXT,
                details JSONB NOT NULL DEFAULT '{}'::jsonb,
                ip_address TEXT,
                user_agent TEXT,
                outcome TEXT NOT NULL,
                error_message TEXT,
                timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                hash TEXT NOT NULL,
                previous_hash TEXT,
                signature TEXT NOT NULL,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )",
        )
        .execute(&pool)
        .await
        .expect("audit_logs fixture DDL must apply");
        sqlx::raw_sql(
            "CREATE TABLE IF NOT EXISTS audit_chain_head (
                chain_id    TEXT        PRIMARY KEY,
                head_hash   TEXT        NOT NULL,
                prev_hash   TEXT,
                head_seq    BIGINT      NOT NULL DEFAULT 1,
                updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )",
        )
        .execute(&pool)
        .await
        .expect("audit_chain_head fixture DDL must apply");
        let tenant_id = format!("tpatch{}", &uuid::Uuid::new_v4().simple().to_string()[..12]);
        sqlx::query(
            "INSERT INTO tenants (id, name, slug, plan, status) VALUES ($1, 'Patch Co', $2, 'free', 'active')",
        )
        .bind(&tenant_id)
        .bind(format!("slug-{tenant_id}"))
        .execute(&pool)
        .await
        .expect("seed tenant");

        let state = crate::app::test_support::test_state_over(pool.clone()).await;

        // (a) A customer-tenant caller — even holding the wildcard scope —
        // is refused by the per-handler gate.
        let customer = AuthUser {
            tenant_id: "01HCUSTOMERTENANT0abcdefgh".into(),
            user_id: None,
            api_key_id: None,
            session_id: None,
            scopes: vec!["*".into()],
        };
        let response = update_tenant(
            State(state.clone()),
            customer,
            Json(UpdateTenantRequest {
                id: tenant_id.clone(),
                action: None,
                name: Some("Hostile Rename".into()),
                plan: None,
                status: None,
            }),
        )
        .await;
        assert!(response.is_err(), "customer sessions must be refused");

        // (b) A system operator cannot write an arbitrary status.
        let system_operator = AuthUser {
            tenant_id: "system".into(),
            user_id: None,
            api_key_id: None,
            session_id: None,
            scopes: vec!["*".into()],
        };
        let response = update_tenant(
            State(state.clone()),
            system_operator.clone(),
            Json(UpdateTenantRequest {
                id: tenant_id.clone(),
                action: None,
                name: None,
                plan: None,
                status: Some("entropy-bypass".into()),
            }),
        )
        .await;
        assert!(
            response.is_err(),
            "an allowlist-external status must be rejected, not stored"
        );

        // (c) A legitimate direct edit applies AND is audited.
        update_tenant(
            State(state.clone()),
            system_operator,
            Json(UpdateTenantRequest {
                id: tenant_id.clone(),
                action: None,
                name: Some("Renamed Co".into()),
                plan: None,
                status: Some("suspended".into()),
            }),
        )
        .await
        .expect("allowlisted direct edit must succeed");
        let (name, status): (String, String) =
            sqlx::query_as("SELECT name, status FROM tenants WHERE id = $1")
                .bind(&tenant_id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(name, "Renamed Co");
        assert_eq!(status, "suspended");
        let audited: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM audit_logs WHERE resource = 'tenant' AND resource_id = $1",
        )
        .bind(&tenant_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert!(audited >= 1, "direct name/status edits must be audited");
    }
}
