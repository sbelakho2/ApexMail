//! Admin billing abuse review — the operator surface for the
//! `billing-service` abuse machinery (audit F09 / wave G).
//!
//! `billing_service::maintenance` owns the canonical writers
//! (`record_abuse_report`, `review_abuse_report`, `resolve_abuse_report`,
//! `impose_tenant_restriction`, `clear_tenant_restriction`) and the abuse
//! hold that keeps a tenant's sending/recovery blocked until every open
//! report is resolved. Until this module existed, every caller was a test:
//! no operator could record, review or resolve a report, and the
//! `tenant_restrictions` abuse row could only be created through that dead
//! path.
//!
//! The router is nested under the control-plane (`/v1/admin/*`) admin router
//! in `app.rs`, so the system-tenant gate and the CP session policy are
//! enforced structurally (not per handler). The reviewer identity is the
//! authenticated operator (`AuthUser.user_id`; machine credentials are
//! attributed as `system`).
//!
//! Routes:
//! * `GET    /v1/admin/billing/abuse/reports`                 — review queue
//! * `POST   /v1/admin/billing/abuse/reports`                 — record a report
//! * `POST   /v1/admin/billing/abuse/reports/:id/review`      — transition
//! * `POST   /v1/admin/billing/abuse/reports/:id/resolve`     — resolve
//! * `POST   /v1/admin/billing/abuse/restrictions`            — impose
//! * `DELETE /v1/admin/billing/abuse/restrictions/:tenant_id/:kind` — clear

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::json;

use crate::error::ApiError;
use crate::middleware::auth::AuthUser;
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/reports", get(list_reports).post(record_report))
        .route("/reports/:id/review", post(review_report))
        .route("/reports/:id/resolve", post(resolve_report))
        .route("/restrictions", post(impose_restriction))
        .route("/restrictions/:tenant_id/:kind", axum::routing::delete(clear_restriction))
}

// ── Helpers ────────────────────────────────────────────────────

/// The billing-service state the canonical abuse writers take. Redis is not
/// consulted by the abuse functions, but the shared struct is the only
/// constructor their signatures accept.
fn billing_state(state: &AppState) -> std::sync::Arc<billing_service::AppState> {
    billing_service::AppState::new(
        state.db.clone(),
        state.redis.clone(),
        billing_service::config::BillingConfig::default(),
    )
}

/// The authenticated reviewer recorded on transitions. `abuse_reports.reviewed_by`
/// is VARCHAR(26): machine credentials have no user id and are attributed as
/// the literal `system` (the same sentinel the auth middleware uses).
fn reviewer(auth: &AuthUser) -> String {
    auth.user_id.clone().unwrap_or_else(|| "system".to_string())
}

/// Classify a billing-service error string into the right HTTP shape. The
/// writers return plain strings; the two operator-actionable classes are
/// "not found" and a refused lifecycle transition, everything else is
/// infrastructure.
fn map_abuse_error(error: String) -> ApiError {
    if error.contains("not found") {
        ApiError::NotFound(error)
    } else if error.contains("Unauthorized abuse report transition") {
        ApiError::Validation(vec![error])
    } else {
        ApiError::Internal(error)
    }
}

/// Attributed audit entry for an abuse-review mutation (best-effort).
async fn audit_abuse(
    state: &AppState,
    auth: &AuthUser,
    action: &str,
    resource_id: &str,
    details: serde_json::Value,
) {
    crate::audit_log::insert_audit_log_best_effort_with_env(
        &state.db,
        state.config.environment.is_production(),
        Some(auth.tenant_id.as_str()),
        auth.user_id.as_deref(),
        action,
        "abuse_report",
        Some(resource_id),
        details,
        None,
        None,
    )
    .await;
}

fn validate_tenant_key(tenant_id: &str) -> Result<(), ApiError> {
    if tenant_id.is_empty() || tenant_id.len() > 26 {
        return Err(ApiError::BadRequest(
            "tenantId must be 1..=26 characters".into(),
        ));
    }
    if !tenant_id
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err(ApiError::BadRequest(
            "tenantId must be lowercase alphanumeric plus '-'/'_'".into(),
        ));
    }
    Ok(())
}

// ── Request/response shapes ────────────────────────────────────

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ListReportsQuery {
    #[serde(default)]
    pub tenant_id: Option<String>,
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub limit: Option<i64>,
}

const ABUSE_STATUSES: [&str; 5] = ["open", "investigating", "confirmed", "dismissed", "resolved"];

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecordReportBody {
    #[serde(rename = "tenantId")]
    pub tenant_id: String,
    #[serde(rename = "reportType")]
    pub report_type: String,
    #[serde(default)]
    pub source: Option<String>,
    #[serde(default)]
    pub details: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewReportBody {
    pub status: String,
    #[serde(default)]
    pub notes: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResolveReportBody {
    #[serde(default)]
    pub notes: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImposeRestrictionBody {
    #[serde(rename = "tenantId")]
    pub tenant_id: String,
    pub kind: String,
    pub reason: String,
}

const RESTRICTION_KINDS: [&str; 4] = ["billing", "administrative", "verification", "abuse"];

#[derive(Debug, Deserialize)]
pub struct ClearRestrictionQuery {
    #[serde(default)]
    pub reason: Option<String>,
}

// ── Handlers ───────────────────────────────────────────────────

/// `GET /v1/admin/billing/abuse/reports` — the review queue (tenant/status
/// filters, bounded).
async fn list_reports(
    State(state): State<AppState>,
    auth: AuthUser,
    Query(params): Query<ListReportsQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let _ = &auth;
    let limit = params.limit.unwrap_or(50).clamp(1, 200);
    if let Some(tenant_id) = params.tenant_id.as_deref() {
        validate_tenant_key(tenant_id)?;
    }
    if let Some(status) = params.status.as_deref() {
        if !ABUSE_STATUSES.contains(&status) {
            return Err(ApiError::BadRequest(format!(
                "status must be one of: {}",
                ABUSE_STATUSES.join(", ")
            )));
        }
    }

    let rows: Vec<(
        uuid::Uuid,
        String,
        String,
        Option<String>,
        String,
        serde_json::Value,
        chrono::DateTime<chrono::Utc>,
        Option<chrono::DateTime<chrono::Utc>>,
        Option<String>,
    )> = sqlx::query_as(
        "SELECT id, tenant_id, report_type, source, status::text, COALESCE(details, '{}'::jsonb), \
                created_at, reviewed_at, reviewed_by \
         FROM abuse_reports \
         WHERE ($1::text IS NULL OR tenant_id = $1) \
           AND ($2::text IS NULL OR status::text = $2) \
         ORDER BY created_at DESC LIMIT $3",
    )
    .bind(params.tenant_id.as_deref())
    .bind(params.status.as_deref())
    .bind(limit)
    .fetch_all(&state.db)
    .await?;

    let reports: Vec<serde_json::Value> = rows
        .into_iter()
        .map(
            |(id, tenant_id, report_type, source, status, details, created_at, reviewed_at, reviewed_by)| {
                json!({
                    "id": id,
                    "tenantId": tenant_id,
                    "reportType": report_type,
                    "source": source,
                    "status": status,
                    "details": details,
                    "createdAt": created_at,
                    "reviewedAt": reviewed_at,
                    "reviewedBy": reviewed_by,
                })
            },
        )
        .collect();
    Ok(Json(json!({ "reports": reports })))
}

/// `POST /v1/admin/billing/abuse/reports` — record an `open` report.
async fn record_report(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(body): Json<RecordReportBody>,
) -> Result<(StatusCode, Json<serde_json::Value>), ApiError> {
    validate_tenant_key(&body.tenant_id)?;
    if body.report_type.trim().is_empty() || body.report_type.chars().count() > 64 {
        return Err(ApiError::BadRequest(
            "reportType must be 1..=64 characters".into(),
        ));
    }
    let details = match body.details.unwrap_or_else(|| json!({})) {
        value @ serde_json::Value::Object(_) => value,
        _ => return Err(ApiError::BadRequest("details must be a JSON object".into())),
    };

    let billing = billing_state(&state);
    let id = billing_service::maintenance::record_abuse_report(
        &billing,
        &body.tenant_id,
        &body.report_type,
        body.source.as_deref(),
        details,
    )
    .await
    .map_err(map_abuse_error)?;

    audit_abuse(
        &state,
        &auth,
        "billing.abuse_report_recorded",
        &id.to_string(),
        json!({ "tenantId": body.tenant_id, "reportType": body.report_type }),
    )
    .await;
    Ok((
        StatusCode::CREATED,
        Json(json!({ "id": id, "status": "open" })),
    ))
}

/// `POST /v1/admin/billing/abuse/reports/:id/review` — audited lifecycle
/// transition (open → investigating → confirmed/dismissed/resolved).
async fn review_report(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<String>,
    Json(body): Json<ReviewReportBody>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let id = uuid::Uuid::parse_str(&id)
        .map_err(|_| ApiError::BadRequest("report id must be a UUID".into()))?;
    if !ABUSE_STATUSES.contains(&body.status.as_str()) {
        return Err(ApiError::BadRequest(format!(
            "status must be one of: {}",
            ABUSE_STATUSES.join(", ")
        )));
    }
    let notes = body.notes.as_deref().unwrap_or("");

    let reviewer = reviewer(&auth);
    billing_service::maintenance::review_abuse_report(
        &state.db,
        id,
        &body.status,
        &reviewer,
        notes,
    )
    .await
    .map_err(map_abuse_error)?;

    audit_abuse(
        &state,
        &auth,
        "billing.abuse_report_reviewed",
        &id.to_string(),
        json!({ "status": body.status, "notes": notes }),
    )
    .await;
    Ok(Json(json!({ "id": id, "status": body.status })))
}

/// `POST /v1/admin/billing/abuse/reports/:id/resolve` — terminal resolution
/// (also clears the tenant's abuse restriction).
async fn resolve_report(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<String>,
    Json(body): Json<ResolveReportBody>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let id = uuid::Uuid::parse_str(&id)
        .map_err(|_| ApiError::BadRequest("report id must be a UUID".into()))?;
    let notes = body.notes.as_deref().unwrap_or("");
    let reviewer = reviewer(&auth);
    billing_service::maintenance::resolve_abuse_report(&state.db, id, &reviewer, notes)
        .await
        .map_err(map_abuse_error)?;
    audit_abuse(
        &state,
        &auth,
        "billing.abuse_report_resolved",
        &id.to_string(),
        json!({ "notes": notes }),
    )
    .await;
    Ok(Json(json!({ "id": id, "status": "resolved" })))
}

/// `POST /v1/admin/billing/abuse/restrictions` — impose an administrative
/// restriction (abuse/administrative/billing/verification).
async fn impose_restriction(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(body): Json<ImposeRestrictionBody>,
) -> Result<(StatusCode, Json<serde_json::Value>), ApiError> {
    validate_tenant_key(&body.tenant_id)?;
    if !RESTRICTION_KINDS.contains(&body.kind.as_str()) {
        return Err(ApiError::BadRequest(format!(
            "kind must be one of: {}",
            RESTRICTION_KINDS.join(", ")
        )));
    }
    if body.reason.trim().is_empty() {
        return Err(ApiError::BadRequest("reason must not be empty".into()));
    }
    let actor = reviewer(&auth);
    billing_service::maintenance::impose_tenant_restriction(
        &state.db,
        &body.tenant_id,
        &body.kind,
        &body.reason,
        "admin",
        Some(&actor),
    )
    .await
    .map_err(map_abuse_error)?;
    audit_abuse(
        &state,
        &auth,
        "billing.tenant_restriction_imposed",
        &body.tenant_id,
        json!({ "kind": body.kind, "reason": body.reason }),
    )
    .await;
    Ok((
        StatusCode::CREATED,
        Json(json!({ "tenantId": body.tenant_id, "kind": body.kind, "cleared": false })),
    ))
}

/// `DELETE /v1/admin/billing/abuse/restrictions/:tenant_id/:kind` — clear one
/// restriction with the operator's reason.
async fn clear_restriction(
    State(state): State<AppState>,
    auth: AuthUser,
    Path((tenant_id, kind)): Path<(String, String)>,
    Query(params): Query<ClearRestrictionQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    validate_tenant_key(&tenant_id)?;
    if !RESTRICTION_KINDS.contains(&kind.as_str()) {
        return Err(ApiError::BadRequest(format!(
            "kind must be one of: {}",
            RESTRICTION_KINDS.join(", ")
        )));
    }
    let reason = params.reason.unwrap_or_else(|| "operator cleared".to_string());
    let cleared_by = reviewer(&auth);
    let cleared = billing_service::maintenance::clear_tenant_restriction(
        &state.db,
        &tenant_id,
        &kind,
        &cleared_by,
        &reason,
    )
    .await
    .map_err(map_abuse_error)?;
    audit_abuse(
        &state,
        &auth,
        "billing.tenant_restriction_cleared",
        &tenant_id,
        json!({ "kind": kind, "cleared": cleared, "reason": reason }),
    )
    .await;
    Ok(Json(
        json!({ "tenantId": tenant_id, "kind": kind, "cleared": cleared }),
    ))
}

#[cfg(test)]
mod adversarial_tests {
    use super::*;
    use crate::app::test_support::adv::AdvEnv;

    /// End-to-end operator workflow through the REAL router: record → review
    /// → the abuse hold blocks → resolve → the hold is gone. Gated by the
    /// control-plane system-tenant middleware like every `/v1/admin/*` route.
    #[tokio::test]
    async fn abuse_review_lifecycle_over_the_admin_router() {
        let Some(pool) = crate::test_db::canonical_pool("admin_billing_abuse").await else {
            return;
        };
        let env = AdvEnv::admin(pool.clone()).await;
        let tenant = apexmail_lib::id::generate_id("abt", 20);
        sqlx::query(
            "INSERT INTO tenants (id, name, slug, plan, status, created_at, updated_at) \
             VALUES ($1, 'Abuse Target', $2, 'free', 'active', NOW(), NOW())",
        )
        .bind(&tenant)
        .bind(format!("slug-{tenant}"))
        .execute(&pool)
        .await
        .expect("seed tenant");

        // Record.
        let (status, body) = env
            .post(
                "/v1/admin/billing/abuse/reports",
                &json!({
                    "tenantId": tenant,
                    "reportType": "spam_complaint",
                    "source": "postmaster",
                    "details": { "complaints": 42 }
                })
                .to_string(),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
        assert_eq!(body["status"], "open");
        let report_id = body["id"].as_str().expect("id").to_string();

        // The review queue shows it.
        let (status, body) = env
            .get(&format!("/v1/admin/billing/abuse/reports?tenant_id={tenant}"))
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let reports = body["reports"].as_array().expect("reports");
        assert_eq!(reports.len(), 1, "{body}");
        assert_eq!(reports[0]["status"], "open");

        // An illegal transition (open -> confirmed) is refused as a 400.
        let (status, body) = env
            .post(
                &format!("/v1/admin/billing/abuse/reports/{report_id}/review"),
                &json!({ "status": "confirmed" }).to_string(),
            )
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");

        // Legal transition: open -> investigating, then -> confirmed. The
        // confirmed report imposes the abuse restriction.
        for next in ["investigating", "confirmed"] {
            let (status, body) = env
                .post(
                    &format!("/v1/admin/billing/abuse/reports/{report_id}/review"),
                    &json!({ "status": next, "notes": "reviewed by test" }).to_string(),
                )
                .await;
            assert_eq!(status, StatusCode::OK, "{body}");
            assert_eq!(body["status"], next);
        }
        let billing = billing_service::AppState::new(
            pool.clone(),
            env_state_redis(&pool).await,
            billing_service::config::BillingConfig::default(),
        );
        assert!(
            billing_service::maintenance::tenant_has_open_abuse_hold(&billing, &tenant)
                .await
                .expect("hold check"),
            "a confirmed report must hold the tenant"
        );
        let active_kind: Option<String> = sqlx::query_scalar(
            "SELECT kind FROM tenant_restrictions \
             WHERE tenant_id = $1 AND kind = 'abuse' AND cleared_at IS NULL",
        )
        .bind(&tenant)
        .fetch_optional(&pool)
        .await
        .expect("restriction row");
        assert_eq!(active_kind.as_deref(), Some("abuse"));

        // Resolve → the restriction is cleared and the hold is gone.
        let (status, body) = env
            .post(
                &format!("/v1/admin/billing/abuse/reports/{report_id}/resolve"),
                &json!({ "notes": "remediated" }).to_string(),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["status"], "resolved");
        assert!(
            !billing_service::maintenance::tenant_has_open_abuse_hold(&billing, &tenant)
                .await
                .expect("hold check"),
            "a resolved report must release the hold"
        );

        // Both mutations are attributed in the audit chain.
        let audited: i64 = sqlx::query_scalar(
            "SELECT COUNT(*)::bigint FROM audit_logs \
             WHERE resource_id = $1 AND action LIKE 'billing.abuse_report_%'",
        )
        .bind(&report_id)
        .fetch_one(&pool)
        .await
        .expect("audit count");
        assert!(audited >= 4, "record/review/resolve entries: {audited}");
    }

    /// Manual restriction impose + clear is the operator's independent lever.
    #[tokio::test]
    async fn manual_restriction_impose_and_clear() {
        let Some(pool) = crate::test_db::canonical_pool("admin_billing_restrictions").await else {
            return;
        };
        let env = AdvEnv::admin(pool.clone()).await;
        let tenant = apexmail_lib::id::generate_id("abr", 20);
        sqlx::query(
            "INSERT INTO tenants (id, name, slug, plan, status, created_at, updated_at) \
             VALUES ($1, 'Restricted Target', $2, 'free', 'active', NOW(), NOW())",
        )
        .bind(&tenant)
        .bind(format!("slug-{tenant}"))
        .execute(&pool)
        .await
        .expect("seed tenant");

        let (status, body) = env
            .post(
                "/v1/admin/billing/abuse/restrictions",
                &json!({ "tenantId": tenant, "kind": "administrative", "reason": "manual review" })
                    .to_string(),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{body}");

        let (status, body) = env
            .delete(&format!(
                "/v1/admin/billing/abuse/restrictions/{tenant}/administrative?reason=cleared+by+test"
            ))
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["cleared"], true);

        // Clearing again reports the honest "nothing active".
        let (status, body) = env
            .delete(&format!(
                "/v1/admin/billing/abuse/restrictions/{tenant}/administrative"
            ))
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["cleared"], false);
    }

    /// A customer (non-system tenant) credential must never reach the abuse
    /// surface — the system-tenant gate rejects it before the handler.
    #[tokio::test]
    async fn abuse_surface_is_control_plane_only() {
        let Some(pool) = crate::test_db::canonical_pool("admin_billing_abuse_gate").await else {
            return;
        };
        let (env, tenant) = AdvEnv::tenant(pool.clone(), &["*"]).await;
        let (status, _body) = env
            .get("/v1/admin/billing/abuse/reports")
            .await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "a tenant wildcard scope must not reach the control plane"
        );

        // The same wildcard key works on its own tenant surface — the gate is
        // about the /v1/admin prefix, not the credential itself.
        let (status, _body) = env.get("/v1/contacts/counts").await;
        assert!(status != StatusCode::FORBIDDEN, "customer surface still served");
        let _ = tenant;
    }

    /// Test helper: the shared billing AppState only needs any Redis pool for
    /// the abuse paths; the dead pool is never consulted by them.
    async fn env_state_redis(_pool: &sqlx::PgPool) -> deadpool_redis::Pool {
        let url = std::env::var("TEST_REDIS_URL")
            .ok()
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| "redis://127.0.0.1:1".into());
        deadpool_redis::Config::from_url(&url)
            .create_pool(Some(deadpool_redis::Runtime::Tokio1))
            .expect("lazy redis pool")
    }
}
