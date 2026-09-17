//! GDPR request management endpoints.
//!

use axum::extract::{Query, State};
use axum::routing::get;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::error::ApiError;
use crate::middleware::auth::AuthUser;
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new().route("/", get(list_gdpr_requests).patch(update_gdpr_request))
}

fn build_gdpr_audit_metadata(body: &UpdateGdprRequest) -> serde_json::Value {
    json!({
        "status": body.status,
        "evidenceProvided": body.evidence.as_deref().is_some_and(|e| !e.trim().is_empty()),
    })
}

/// Audit with full actor attribution (P2-2): the operator's tenant AND user
/// id must land in the entry — an unattributed GDPR status change is
/// unverifiable the moment it matters legally.
async fn log_gdpr_audit(
    state: &AppState,
    auth: &AuthUser,
    request_id: &str,
    metadata: serde_json::Value,
) {
    crate::audit_log::insert_audit_log_best_effort_with_env(
        &state.db,
        state.config.environment.is_production(),
        Some(auth.tenant_id.as_str()),
        auth.user_id.as_deref(),
        "control_plane.gdpr.request_updated",
        "gdpr_request",
        Some(request_id),
        metadata,
        None,
        None,
    )
    .await;
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GdprListQuery {
    #[serde(default = "default_limit")]
    pub limit: i64,
    #[serde(default)]
    pub offset: i64,
}

fn default_limit() -> i64 {
    50
}

#[derive(Debug, Serialize, sqlx::FromRow)]
struct GdprRequestRow {
    id: String,
    request_type: String,
    status: String,
    email: String,
    tenant_id: String,
    tenant_name: String,
    created_at: chrono::DateTime<chrono::Utc>,
    fulfilled_at: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GdprRequestResponse {
    pub id: String,
    #[serde(rename = "type")]
    pub request_type: String,
    pub status: String,
    pub email: String,
    pub tenant_id: String,
    pub tenant_name: String,
    pub created_at: String,
    pub completed_at: Option<String>,
}

async fn list_gdpr_requests(
    State(state): State<AppState>,
    auth: AuthUser,
    Query(params): Query<GdprListQuery>,
) -> Result<Json<Vec<GdprRequestResponse>>, ApiError> {
    crate::middleware::auth::require_scopes(&auth, &["*"])?;

    let limit = params.limit.clamp(1, 200);
    let offset = params.offset.max(0);
    // Slug-aware system-tenant resolution (audit F1): human operators belong
    // to `system_internal_tenant01`, not the literal `system` sentinel — the
    // literal comparison silently scoped this console to an empty tenant.
    let tenant_scoped = !crate::routes::web::is_system_tenant(&state, &auth.tenant_id).await;

    // Check if table exists
    let exists: (bool,) = sqlx::query_as("SELECT to_regclass('public.gdpr_requests') IS NOT NULL")
        .fetch_one(&state.db)
        .await?;

    if !exists.0 {
        return Ok(Json(vec![]));
    }

    let rows = if tenant_scoped {
        sqlx::query_as::<_, GdprRequestRow>(
            "SELECT g.id, g.request_type, g.status, g.email, g.tenant_id,
                COALESCE(t.name, g.tenant_id) as tenant_name,
                g.created_at, g.fulfilled_at
         FROM gdpr_requests g
         LEFT JOIN tenants t ON t.id = g.tenant_id
         WHERE g.tenant_id = $3
         ORDER BY g.created_at DESC
         LIMIT $1 OFFSET $2",
        )
        .bind(limit)
        .bind(offset)
        .bind(&auth.tenant_id)
        .fetch_all(&state.db)
        .await?
    } else {
        sqlx::query_as::<_, GdprRequestRow>(
            "SELECT g.id, g.request_type, g.status, g.email, g.tenant_id,
                COALESCE(t.name, g.tenant_id) as tenant_name,
                g.created_at, g.fulfilled_at
         FROM gdpr_requests g
         LEFT JOIN tenants t ON t.id = g.tenant_id
         ORDER BY g.created_at DESC
         LIMIT $1 OFFSET $2",
        )
        .bind(limit)
        .bind(offset)
        .fetch_all(&state.db)
        .await?
    };

    let response: Vec<GdprRequestResponse> = rows
        .into_iter()
        .map(|r| GdprRequestResponse {
            id: r.id,
            request_type: r.request_type,
            status: r.status,
            email: r.email,
            tenant_id: r.tenant_id,
            tenant_name: r.tenant_name,
            created_at: r.created_at.to_rfc3339(),
            completed_at: r.fulfilled_at.map(|t| t.to_rfc3339()),
        })
        .collect();

    Ok(Json(response))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateGdprRequest {
    pub id: String,
    pub status: String,
    /// Operator-supplied proof of execution. Required to complete an
    /// erasure request (e.g. erasure job reference, verifier note); export
    /// requests additionally require a materialized `gdpr_exports` artifact.
    #[serde(default)]
    pub evidence: Option<String>,
}

/// A completed GDPR request must point at executed work, never an
/// operator's say-so (P1-5): an export needs a materialized artifact row
/// (`gdpr_exports.request_id`, migration 038 — the download the data
/// subject receives), an erasure needs a non-empty evidence note tying the
/// completion to the compliance erasure path. Returns Ok(()) only when the
/// request may legally transition to `completed`.
async fn ensure_completion_is_evidenced(
    state: &AppState,
    request: &GdprRequestRow,
    evidence: Option<&str>,
) -> Result<(), ApiError> {
    let has_evidence = evidence.is_some_and(|e| !e.trim().is_empty());
    match request.request_type.as_str() {
        "export" | "access" => {
            let has_artifact: Option<bool> = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM gdpr_exports WHERE request_id = $1)",
            )
            .bind(&request.id)
            .fetch_optional(&state.db)
            .await?
            .flatten();
            if !has_artifact.unwrap_or(false) {
                return Err(ApiError::Validation(vec![
                    "export requests can only be completed after the export artifact has been generated (gdpr_exports row missing)".into(),
                ]));
            }
            // An artifact without any operator evidence still leaves the
            // completion unattributed — require both.
            if !has_evidence {
                return Err(ApiError::Validation(vec![
                    "completing a request requires non-empty evidence".into(),
                ]));
            }
        }
        // Erasure and any unrecognized type: fail safe — demand evidence.
        _ => {
            if !has_evidence {
                return Err(ApiError::Validation(vec![
                    "completing an erasure request requires non-empty evidence (erasure job reference or compliance note)".into(),
                ]));
            }
        }
    }
    Ok(())
}

async fn update_gdpr_request(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(body): Json<UpdateGdprRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    crate::middleware::auth::require_scopes(&auth, &["*"])?;

    let allowed = ["pending", "verified", "processing", "completed", "rejected"];
    if !allowed.contains(&body.status.as_str()) {
        return Err(ApiError::Validation(vec!["Invalid status".into()]));
    }

    let tenant_scoped = !crate::routes::web::is_system_tenant(&state, &auth.tenant_id).await;

    // Fetch the request first: completion gating needs its type, and a
    // tenant-scoped operator must not learn anything about foreign requests.
    let request: Option<GdprRequestRow> = if tenant_scoped {
        sqlx::query_as::<_, GdprRequestRow>(
            "SELECT g.id, g.request_type, g.status, g.email, g.tenant_id,
                COALESCE(t.name, g.tenant_id) as tenant_name,
                g.created_at, g.fulfilled_at
         FROM gdpr_requests g
         LEFT JOIN tenants t ON t.id = g.tenant_id
         WHERE g.id = $1 AND g.tenant_id = $2",
        )
        .bind(&body.id)
        .bind(&auth.tenant_id)
        .fetch_optional(&state.db)
        .await?
    } else {
        sqlx::query_as::<_, GdprRequestRow>(
            "SELECT g.id, g.request_type, g.status, g.email, g.tenant_id,
                COALESCE(t.name, g.tenant_id) as tenant_name,
                g.created_at, g.fulfilled_at
         FROM gdpr_requests g
         LEFT JOIN tenants t ON t.id = g.tenant_id
         WHERE g.id = $1",
        )
        .bind(&body.id)
        .fetch_optional(&state.db)
        .await?
    };
    let request = request.ok_or_else(|| ApiError::NotFound("gdpr request not found".into()))?;

    // P1-5: `fulfilled_at` is legal evidence of execution. It is written
    // ONLY after the completion gates below pass — never on the operator's
    // say-so.
    if body.status == "completed" {
        ensure_completion_is_evidenced(&state, &request, body.evidence.as_deref()).await?;
    }

    let result = if tenant_scoped {
        sqlx::query(
            "UPDATE gdpr_requests
         SET status = $2,
             fulfilled_at = CASE WHEN $2 = 'completed' THEN NOW() ELSE fulfilled_at END
         WHERE id = $1 AND tenant_id = $3",
        )
        .bind(&body.id)
        .bind(&body.status)
        .bind(&auth.tenant_id)
        .execute(&state.db)
        .await?
    } else {
        sqlx::query(
            "UPDATE gdpr_requests
         SET status = $2,
             fulfilled_at = CASE WHEN $2 = 'completed' THEN NOW() ELSE fulfilled_at END
         WHERE id = $1",
        )
        .bind(&body.id)
        .bind(&body.status)
        .execute(&state.db)
        .await?
    };

    if result.rows_affected() == 0 {
        return Err(ApiError::NotFound("gdpr request not found".into()));
    }

    log_gdpr_audit(&state, &auth, &body.id, build_gdpr_audit_metadata(&body)).await;

    Ok(Json(serde_json::json!({ "success": true })))
}

// ─── Adversarial handler tests (canonical schema, per-test databases) ──────

#[cfg(test)]
mod adversarial_tests {
    use super::*;
    use axum::extract::{Query, State};
    use serde_json::json;

    /// System-tenant machine identity (literal `system` sentinel) — the
    /// platform-staff view of every tenant's requests.
    fn system_auth() -> AuthUser {
        AuthUser {
            tenant_id: "system".into(),
            user_id: None,
            api_key_id: None,
            session_id: None,
            scopes: vec!["*".into()],
        }
    }

    /// A customer tenant operator with the wildcard scope: authenticated and
    /// authorized on the surface, but scoped to their OWN tenant only.
    fn tenant_auth(tenant_id: &str) -> AuthUser {
        AuthUser {
            tenant_id: tenant_id.into(),
            user_id: Some("00000000-0000-0000-0000-0000000000aa".into()),
            api_key_id: None,
            session_id: None,
            scopes: vec!["*".into()],
        }
    }

    async fn seed_tenant(pool: &sqlx::PgPool, id: &str) {
        sqlx::query(
            "INSERT INTO tenants (id, name, plan, status, created_at, updated_at)
             VALUES ($1, $2, 'free', 'active', NOW(), NOW())",
        )
        .bind(id)
        .bind(format!("gdpr-tenant-{id}"))
        .execute(pool)
        .await
        .expect("seed tenant");
    }

    async fn seed_request(
        pool: &sqlx::PgPool,
        id: &str,
        tenant_id: &str,
        request_type: &str,
        status: &str,
    ) {
        sqlx::query(
            "INSERT INTO gdpr_requests (id, tenant_id, email, request_type, status, created_at, updated_at)
             VALUES ($1, $2, $3, $4, $5, NOW(), NOW())",
        )
        .bind(id)
        .bind(tenant_id)
        .bind(format!("subject-{id}@example.com"))
        .bind(request_type)
        .bind(status)
        .execute(pool)
        .await
        .expect("seed gdpr request");
    }

    async fn request_status(
        pool: &sqlx::PgPool,
        id: &str,
    ) -> (String, Option<chrono::DateTime<chrono::Utc>>) {
        sqlx::query_as("SELECT status, fulfilled_at FROM gdpr_requests WHERE id = $1")
            .bind(id)
            .fetch_one(pool)
            .await
            .expect("gdpr request row")
    }

    #[tokio::test]
    async fn list_reports_empty_dataset_for_system_operator_on_fresh_schema() {
        let Some(pool) = crate::test_db::canonical_pool("gdpr_list_empty").await else {
            eprintln!("skipping: set TEST_DATABASE_URL to run DB-backed test");
            return;
        };
        let state = crate::app::test_support::test_state_over(pool.clone()).await;

        let Json(rows) = list_gdpr_requests(
            State(state),
            system_auth(),
            Query(GdprListQuery {
                limit: 50,
                offset: 0,
            }),
        )
        .await
        .expect("empty list must succeed");

        assert!(rows.is_empty(), "no requests seeded — must be empty");
        pool.close().await;
    }

    /// Customer wildcard keys NEVER reach this admin route's data: the scope
    /// gate refuses before any query runs.
    #[tokio::test]
    async fn list_refuses_operator_without_wildcard_scope() {
        let Some(pool) = crate::test_db::canonical_pool("gdpr_scope_gate").await else {
            eprintln!("skipping: set TEST_DATABASE_URL to run DB-backed test");
            return;
        };
        let state = crate::app::test_support::test_state_over(pool.clone()).await;
        let mut underprivileged = system_auth();
        underprivileged.scopes = vec!["suppressions:read".into()];

        let err = list_gdpr_requests(
            State(state),
            underprivileged,
            Query(GdprListQuery {
                limit: 50,
                offset: 0,
            }),
        )
        .await
        .expect_err("non-wildcard scope must be refused");
        assert!(
            matches!(err, ApiError::Forbidden(ref message) if message.contains("*")),
            "expected wildcard-scope refusal, got {err:?}"
        );
        pool.close().await;
    }

    #[tokio::test]
    async fn system_operator_sees_all_tenants_tenant_operator_sees_only_own() {
        let Some(pool) = crate::test_db::canonical_pool("gdpr_scoping").await else {
            eprintln!("skipping: set TEST_DATABASE_URL to run DB-backed test");
            return;
        };
        let state = crate::app::test_support::test_state_over(pool.clone()).await;
        seed_tenant(&pool, "ten_gdpr_alpha_0001").await;
        seed_tenant(&pool, "ten_gdpr_beta_0002").await;
        seed_request(
            &pool,
            "gdpr_req_alpha_000001",
            "ten_gdpr_alpha_0001",
            "erasure",
            "pending",
        )
        .await;
        seed_request(
            &pool,
            "gdpr_req_beta_000002",
            "ten_gdpr_beta_0002",
            "export",
            "pending",
        )
        .await;

        // System operator: every tenant's requests, newest first, with names.
        let Json(system_rows) = list_gdpr_requests(
            State(state.clone()),
            system_auth(),
            Query(GdprListQuery {
                limit: 50,
                offset: 0,
            }),
        )
        .await
        .expect("system list");
        assert_eq!(system_rows.len(), 2, "system sees both tenants");
        assert!(system_rows
            .iter()
            .any(|r| r.tenant_id == "ten_gdpr_alpha_0001"));
        assert!(system_rows
            .iter()
            .any(|r| r.tenant_id == "ten_gdpr_beta_0002"));
        assert!(
            system_rows
                .iter()
                .all(|r| r.tenant_name.starts_with("gdpr-tenant-")),
            "tenant names resolve through the join"
        );

        // Tenant operator: ONLY their own tenant — no cross-tenant oracle.
        let Json(tenant_rows) = list_gdpr_requests(
            State(state.clone()),
            tenant_auth("ten_gdpr_alpha_0001"),
            Query(GdprListQuery {
                limit: 50,
                offset: 0,
            }),
        )
        .await
        .expect("tenant list");
        assert_eq!(tenant_rows.len(), 1, "tenant operator sees only their rows");
        assert_eq!(tenant_rows[0].id, "gdpr_req_alpha_000001");
        assert_eq!(tenant_rows[0].request_type, "erasure");
        assert_eq!(
            serde_json::to_value(&tenant_rows[0]).unwrap()["type"],
            serde_json::Value::String("erasure".into()),
            "the response field is serialized as `type`"
        );
        assert_eq!(tenant_rows[0].status, "pending");
        assert!(tenant_rows[0].completed_at.is_none());

        // Pagination: offset past the single row hides it.
        let Json(paged) = list_gdpr_requests(
            State(state),
            tenant_auth("ten_gdpr_alpha_0001"),
            Query(GdprListQuery {
                limit: 50,
                offset: 1,
            }),
        )
        .await
        .expect("paged list");
        assert!(paged.is_empty(), "offset skips the row");
        pool.close().await;
    }

    /// A database without the gdpr_requests table (store missing) reports an
    /// EMPTY list — never a 500, never a data-shaped error.
    #[tokio::test]
    async fn list_returns_empty_when_the_store_table_is_missing() {
        let Some(pool) = gdpr_storeless_pool("gdpr_no_table").await else {
            eprintln!("skipping: set TEST_DATABASE_URL to run DB-backed test");
            return;
        };
        let state = crate::app::test_support::test_state_over(pool.clone()).await;
        let Json(rows) = list_gdpr_requests(
            State(state),
            system_auth(),
            Query(GdprListQuery {
                limit: 50,
                offset: 0,
            }),
        )
        .await
        .expect("missing store degrades to an empty list");
        assert!(rows.is_empty());
        pool.close().await;
    }

    /// Minimal per-test database WITHOUT gdpr_requests/gdpr_exports (only the
    /// tables is_system_tenant and the handler's probes touch).
    async fn gdpr_storeless_pool(db_suffix: &str) -> Option<sqlx::PgPool> {
        let database_url = std::env::var("TEST_DATABASE_URL")
            .ok()
            .filter(|value| !value.trim().is_empty())?;
        let (server_part, db_part) = database_url.rsplit_once('/')?;
        let db_only = db_part.split('?').next().unwrap_or(db_part);
        let isolated_db = format!("{db_only}_api_gdpr_nostore_{db_suffix}");
        let isolated_url = format!("{server_part}/{isolated_db}");
        let admin_url = format!("{server_part}/postgres");

        let admin = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .acquire_timeout(std::time::Duration::from_secs(3))
            .connect(&admin_url)
            .await
            .ok()?;
        let _ = sqlx::query(&format!(
            r#"DROP DATABASE IF EXISTS "{isolated_db}" WITH (FORCE)"#
        ))
        .execute(&admin)
        .await;
        let created = sqlx::query(&format!(r#"CREATE DATABASE "{isolated_db}""#))
            .execute(&admin)
            .await;
        admin.close().await;
        created.ok()?;

        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(4)
            .acquire_timeout(std::time::Duration::from_secs(5))
            .connect(&isolated_url)
            .await
            .ok()?;
        sqlx::query(
            "CREATE TABLE tenants (id TEXT PRIMARY KEY, slug TEXT, name TEXT, status TEXT)",
        )
        .execute(&pool)
        .await
        .ok()?;
        Some(pool)
    }

    #[tokio::test]
    async fn update_rejects_unknown_status_and_unknown_request() {
        let Some(pool) = crate::test_db::canonical_pool("gdpr_update_validation").await else {
            eprintln!("skipping: set TEST_DATABASE_URL to run DB-backed test");
            return;
        };
        let state = crate::app::test_support::test_state_over(pool.clone()).await;
        seed_tenant(&pool, "ten_gdpr_gamma_003").await;
        seed_request(
            &pool,
            "gdpr_req_gamma_000003",
            "ten_gdpr_gamma_003",
            "erasure",
            "pending",
        )
        .await;

        // Hostile status strings are refused outright.
        for status in ["completed; DROP TABLE", "", "COMPLETED", "archived"] {
            let err = update_gdpr_request(
                State(state.clone()),
                system_auth(),
                Json(UpdateGdprRequest {
                    id: "gdpr_req_gamma_000003".into(),
                    status: status.into(),
                    evidence: None,
                }),
            )
            .await
            .expect_err("invalid status must be refused");
            assert!(
                matches!(err, ApiError::Validation(_)),
                "status {status:?} must be a 400, got {err:?}"
            );
        }

        // Unknown request id → 404, nothing leaked.
        let err = update_gdpr_request(
            State(state.clone()),
            system_auth(),
            Json(UpdateGdprRequest {
                id: "gdpr_req_does_not_exist".into(),
                status: "verified".into(),
                evidence: None,
            }),
        )
        .await
        .expect_err("unknown id");
        assert!(matches!(err, ApiError::NotFound(_)));

        // All five allowed statuses are accepted vocabulary-wise.
        for status in ["pending", "verified", "processing", "rejected"] {
            let updated = update_gdpr_request(
                State(state.clone()),
                system_auth(),
                Json(UpdateGdprRequest {
                    id: "gdpr_req_gamma_000003".into(),
                    status: status.into(),
                    evidence: None,
                }),
            )
            .await
            .unwrap_or_else(|e| panic!("status {status} must be accepted: {e:?}"));
            assert_eq!(updated.0["success"], true, "status {status} body");
        }
        let (status, fulfilled_at) = request_status(&pool, "gdpr_req_gamma_000003").await;
        assert_eq!(status, "rejected");
        assert!(
            fulfilled_at.is_none(),
            "non-complete transitions never write fulfilled_at"
        );
        pool.close().await;
    }

    /// Cross-tenant refusal is a 404 indistinguishable from a missing id — a
    /// tenant operator learns nothing about foreign requests.
    #[tokio::test]
    async fn update_refuses_cross_tenant_request_with_404() {
        let Some(pool) = crate::test_db::canonical_pool("gdpr_cross_tenant").await else {
            eprintln!("skipping: set TEST_DATABASE_URL to run DB-backed test");
            return;
        };
        let state = crate::app::test_support::test_state_over(pool.clone()).await;
        seed_tenant(&pool, "ten_gdpr_victim_004").await;
        seed_tenant(&pool, "ten_gdpr_other_005").await;
        seed_request(
            &pool,
            "gdpr_req_victim_000004",
            "ten_gdpr_victim_004",
            "erasure",
            "pending",
        )
        .await;

        let err = update_gdpr_request(
            State(state),
            tenant_auth("ten_gdpr_other_005"),
            Json(UpdateGdprRequest {
                id: "gdpr_req_victim_000004".into(),
                status: "verified".into(),
                evidence: None,
            }),
        )
        .await
        .expect_err("foreign request must not resolve");
        assert!(
            matches!(err, ApiError::NotFound(ref message) if message.contains("not found")),
            "cross-tenant refusal must be a plain 404, got {err:?}"
        );

        // The row is untouched.
        assert_eq!(
            request_status(&pool, "gdpr_req_victim_000004").await.0,
            "pending"
        );
        pool.close().await;
    }

    /// P1-5 completion gating: an export needs BOTH a materialized artifact
    /// row AND non-empty evidence; an erasure needs evidence. Whitespace-only
    /// evidence is empty evidence.
    #[tokio::test]
    async fn completion_requires_evidence_and_export_artifact() {
        let Some(pool) = crate::test_db::canonical_pool("gdpr_completion_gate").await else {
            eprintln!("skipping: set TEST_DATABASE_URL to run DB-backed test");
            return;
        };
        let state = crate::app::test_support::test_state_over(pool.clone()).await;
        seed_tenant(&pool, "ten_gdpr_gate_000006").await;
        seed_request(
            &pool,
            "gdpr_req_export_0006",
            "ten_gdpr_gate_000006",
            "export",
            "processing",
        )
        .await;
        seed_request(
            &pool,
            "gdpr_req_access_0007",
            "ten_gdpr_gate_000006",
            "access",
            "processing",
        )
        .await;
        seed_request(
            &pool,
            "gdpr_req_erase_0008",
            "ten_gdpr_gate_000006",
            "erasure",
            "processing",
        )
        .await;

        // Export without an artifact: refused even WITH evidence.
        let err = update_gdpr_request(
            State(state.clone()),
            system_auth(),
            Json(UpdateGdprRequest {
                id: "gdpr_req_export_0006".into(),
                status: "completed".into(),
                evidence: Some("export job #42".into()),
            }),
        )
        .await
        .expect_err("no artifact");
        assert!(
            matches!(err, ApiError::Validation(ref messages)
                if messages.iter().any(|m| m.contains("gdpr_exports"))),
            "the refusal must name the missing artifact: {err:?}"
        );

        // Artifact now exists, but no evidence: still refused (unattributed).
        sqlx::query(
            "INSERT INTO gdpr_exports (id, request_id, tenant_id, email, data, expires_at)
             VALUES ('exp_1', 'gdpr_req_export_0006', 'ten_gdpr_gate_000006', 'x@example.com', '{}', NOW() + INTERVAL '7 days')",
        )
        .execute(&pool)
        .await
        .expect("seed export artifact");
        let err = update_gdpr_request(
            State(state.clone()),
            system_auth(),
            Json(UpdateGdprRequest {
                id: "gdpr_req_export_0006".into(),
                status: "completed".into(),
                evidence: None,
            }),
        )
        .await
        .expect_err("artifact without evidence");
        assert!(
            matches!(err, ApiError::Validation(ref messages)
                if messages.iter().any(|m| m.contains("evidence"))),
            "expected evidence refusal: {err:?}"
        );

        // Whitespace-only evidence is empty evidence.
        let err = update_gdpr_request(
            State(state.clone()),
            system_auth(),
            Json(UpdateGdprRequest {
                id: "gdpr_req_export_0006".into(),
                status: "completed".into(),
                evidence: Some("   ".into()),
            }),
        )
        .await
        .expect_err("blank evidence");
        assert!(matches!(err, ApiError::Validation(_)));

        // Artifact + real evidence: completion succeeds and stamps fulfilled_at.
        let completed = update_gdpr_request(
            State(state.clone()),
            system_auth(),
            Json(UpdateGdprRequest {
                id: "gdpr_req_export_0006".into(),
                status: "completed".into(),
                evidence: Some("export job #42".into()),
            }),
        )
        .await
        .expect("evidenced export completion");
        assert_eq!(completed.0["success"], true);
        let (status, fulfilled_at) = request_status(&pool, "gdpr_req_export_0006").await;
        assert_eq!(status, "completed");
        assert!(fulfilled_at.is_some(), "completion stamps fulfilled_at");

        // `access` rides the same artifact gate as `export`.
        let err = update_gdpr_request(
            State(state.clone()),
            system_auth(),
            Json(UpdateGdprRequest {
                id: "gdpr_req_access_0007".into(),
                status: "completed".into(),
                evidence: Some("access log".into()),
            }),
        )
        .await
        .expect_err("access without artifact");
        assert!(matches!(err, ApiError::Validation(_)));

        // Erasure without evidence: refused.
        let err = update_gdpr_request(
            State(state.clone()),
            system_auth(),
            Json(UpdateGdprRequest {
                id: "gdpr_req_erase_0008".into(),
                status: "completed".into(),
                evidence: None,
            }),
        )
        .await
        .expect_err("erasure without evidence");
        assert!(
            matches!(err, ApiError::Validation(ref messages)
                if messages.iter().any(|m| m.contains("erasure"))),
            "expected erasure refusal: {err:?}"
        );

        // Erasure with an erasure-job reference: completes.
        let completed = update_gdpr_request(
            State(state.clone()),
            system_auth(),
            Json(UpdateGdprRequest {
                id: "gdpr_req_erase_0008".into(),
                status: "completed".into(),
                evidence: Some("erasure job #7 (compliance)".into()),
            }),
        )
        .await
        .expect("evidenced erasure completion");
        assert_eq!(completed.0["success"], true);
        let (status, fulfilled_at) = request_status(&pool, "gdpr_req_erase_0008").await;
        assert_eq!(status, "completed");
        assert!(fulfilled_at.is_some());
        pool.close().await;
    }

    /// P2-2: every mutation lands an actor-attributed audit entry (operator
    /// tenant + user id + request id + evidence flag).
    #[tokio::test]
    async fn completion_writes_actor_attributed_audit_entry() {
        let Some(pool) = crate::test_db::canonical_pool("gdpr_audit").await else {
            eprintln!("skipping: set TEST_DATABASE_URL to run DB-backed test");
            return;
        };
        let state = crate::app::test_support::test_state_over(pool.clone()).await;
        seed_tenant(&pool, "ten_gdpr_audit_0009").await;
        seed_request(
            &pool,
            "gdpr_req_audit_000009",
            "ten_gdpr_audit_0009",
            "erasure",
            "processing",
        )
        .await;

        let mut operator = tenant_auth("ten_gdpr_audit_0009");
        operator.user_id = Some("00000000-0000-0000-0000-0000000000cc".into());
        let completed = update_gdpr_request(
            State(state),
            operator,
            Json(UpdateGdprRequest {
                id: "gdpr_req_audit_000009".into(),
                status: "completed".into(),
                evidence: Some("erasure ref E-1".into()),
            }),
        )
        .await
        .expect("audited completion");
        assert_eq!(completed.0["success"], true);

        let (actor_tenant, actor_user, resource_id): (String, String, String) = sqlx::query_as(
            "SELECT tenant_id, user_id, resource_id FROM audit_logs
             WHERE action = 'control_plane.gdpr.request_updated' AND resource_id = $1",
        )
        .bind("gdpr_req_audit_000009")
        .fetch_one(&pool)
        .await
        .expect("audit entry must exist");
        assert_eq!(actor_tenant, "ten_gdpr_audit_0009");
        assert_eq!(actor_user, "00000000-0000-0000-0000-0000000000cc");
        assert_eq!(resource_id, "gdpr_req_audit_000009");
        pool.close().await;
    }

    /// The audit metadata builder flags blank vs present evidence — the
    /// difference an auditor relies on.
    #[test]
    fn audit_metadata_distinguishes_blank_from_present_evidence() {
        let with = build_gdpr_audit_metadata(&UpdateGdprRequest {
            id: "r".into(),
            status: "completed".into(),
            evidence: Some("ref".into()),
        });
        assert_eq!(with["status"], json!("completed"));
        assert_eq!(with["evidenceProvided"], json!(true));

        let blank = build_gdpr_audit_metadata(&UpdateGdprRequest {
            id: "r".into(),
            status: "pending".into(),
            evidence: Some("   ".into()),
        });
        assert_eq!(blank["evidenceProvided"], json!(false));

        let none = build_gdpr_audit_metadata(&UpdateGdprRequest {
            id: "r".into(),
            status: "pending".into(),
            evidence: None,
        });
        assert_eq!(none["evidenceProvided"], json!(false));
    }
}
