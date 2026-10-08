//! Custom retention editing (+ `max_retention_days` enforcement).
//!
//! `custom_retention` is RuntimeEnforced and this module is the customer
//! surface behind it: the plan's `max_retention_days` is the enforced
//! ceiling and `tenants.retention_days` (migration 121) is the per-tenant
//! override.
//!
//! * `GET /v1/retention` — the tenant's current setting, the plan ceiling and
//!   whether the custom-retention capability is granted (`retention:read`).
//! * `PUT /v1/retention` — set the per-tenant retention override. Requires
//!   the `custom_retention` entitlement (Growth and above per
//!   docs/pricing.md) and `retention:write`; the value must be at least the
//!   1-day legal minimum and at most the plan's `max_retention_days` — both
//!   refusals name the bound, and the capacity gate names the plan/limit
//!   (`retention:write`).
//! * `DELETE /v1/retention` — clear the override (plan-tier defaults apply);
//!   cleanup is deliberately not entitlement-gated.
//!
//! The retention sweep (`compliance/src/retention_sweep.rs`) is the enforcer:
//! it reads this column, never deletes beyond the plan ceiling, never below a
//! category legal minimum, and still excludes tenants on legal hold.

use axum::extract::State;
use axum::routing::get;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use billing_entitlements::{CapacityKey, FeatureKey};

use crate::error::ApiError;
use crate::middleware::auth::{require_scopes, AuthUser};
use crate::state::AppState;

/// The legal minimum for a tenant-wide retention override. The sweep's
/// registry refuses values below every mapped category's
/// `minimum_customer_selectable_days` (events: RET-007 is 1 day), so a
/// tenant-wide value below 1 would silently fall back to defaults instead of
/// taking effect — refuse it up front with the named reason.
pub const MINIMUM_RETENTION_DAYS: i64 = 1;

pub fn router() -> Router<AppState> {
    Router::new().route(
        "/",
        get(get_retention)
            .put(update_retention)
            .delete(reset_retention),
    )
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateRetentionRequest {
    pub retention_days: i64,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct RetentionSettingsResponse {
    pub plan: String,
    /// The plan's `max_retention_days` — the enforced ceiling.
    pub plan_max_retention_days: i64,
    /// The tenant override; null means plan-tier defaults apply.
    pub configured_retention_days: Option<i64>,
    /// The value the sweep will apply to the stores it owns (equal to the
    /// configured override; null when no override is set).
    pub effective_retention_days: Option<i64>,
    /// The lowest acceptable override (legal minimum).
    pub minimum_retention_days: i64,
    /// Whether this plan may edit retention at all (`custom_retention`).
    pub custom_retention_granted: bool,
}

/// Pure validation shared by the handler and its tests. `ceiling` is the
/// plan's `max_retention_days`.
pub(crate) fn validate_retention_update(requested: i64, ceiling: i64) -> Result<(), ApiError> {
    if requested < MINIMUM_RETENTION_DAYS {
        return Err(ApiError::Validation(vec![format!(
            "retention_days {requested} is below the legal minimum of {MINIMUM_RETENTION_DAYS} day(s) — regulated records must not be deleted sooner"
        )]));
    }
    if ceiling >= 0 && requested > ceiling {
        return Err(ApiError::Forbidden(format!(
            "your plan allows at most {ceiling} retention days (requested {requested}) — upgrade to raise the ceiling"
        )));
    }
    Ok(())
}

async fn configured_retention(state: &AppState, tenant_id: &str) -> Result<Option<i64>, ApiError> {
    let row: Option<(Option<i32>,)> =
        sqlx::query_as("SELECT retention_days FROM tenants WHERE id = $1")
            .bind(tenant_id)
            .fetch_optional(&state.db)
            .await?;
    Ok(row
        .ok_or_else(|| ApiError::NotFound("tenant not found".into()))?
        .0
        .map(i64::from))
}

async fn retention_response(
    state: &AppState,
    tenant_id: &str,
    configured: Option<i64>,
) -> Result<RetentionSettingsResponse, ApiError> {
    let snapshot = crate::entitlements::snapshot(state, tenant_id).await?;
    let ceiling = snapshot.capacity(CapacityKey::RetentionDays);
    Ok(RetentionSettingsResponse {
        plan: snapshot.plan().to_string(),
        plan_max_retention_days: ceiling,
        configured_retention_days: configured,
        effective_retention_days: configured,
        minimum_retention_days: MINIMUM_RETENTION_DAYS,
        custom_retention_granted: snapshot.has_feature(FeatureKey::CustomRetention),
    })
}

async fn get_retention(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<Json<RetentionSettingsResponse>, ApiError> {
    require_scopes(&auth, &["retention:read"])?;
    let configured = configured_retention(&state, &auth.tenant_id).await?;
    Ok(Json(
        retention_response(&state, &auth.tenant_id, configured).await?,
    ))
}

async fn update_retention(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(body): Json<UpdateRetentionRequest>,
) -> Result<Json<RetentionSettingsResponse>, ApiError> {
    require_scopes(&auth, &["retention:write"])?;
    // The capability gate: Growth and above per docs/pricing.md, through the
    // canonical entitlement gate.
    let snapshot = crate::entitlements::require_feature(
        &state,
        &auth.tenant_id,
        FeatureKey::CustomRetention,
    )
    .await?;
    let ceiling = snapshot.capacity(CapacityKey::RetentionDays);
    // Named 400/403 bounds check (legal minimum + plan ceiling).
    validate_retention_update(body.retention_days, ceiling)?;
    // Authoritative capacity gate (override-aware; names the plan + limit).
    crate::entitlements::gate_capacity(
        &snapshot,
        CapacityKey::RetentionDays,
        body.retention_days,
    )?;

    let previous = configured_retention(&state, &auth.tenant_id).await?;
    sqlx::query("UPDATE tenants SET retention_days = $1, updated_at = NOW() WHERE id = $2")
        .bind(i32::try_from(body.retention_days).map_err(|_| {
            ApiError::Validation(vec![format!(
                "retention_days {} is out of range",
                body.retention_days
            )])
        })?)
        .bind(&auth.tenant_id)
        .execute(&state.db)
        .await?;

    audit(
        &state,
        &auth.tenant_id,
        "retention.updated",
        serde_json::json!({
            "previous_retention_days": previous,
            "retention_days": body.retention_days,
            "plan_max_retention_days": ceiling,
        }),
    )
    .await;

    info!(
        tenant_id = %auth.tenant_id,
        retention_days = body.retention_days,
        "tenant retention override updated"
    );
    Ok(Json(
        retention_response(&state, &auth.tenant_id, Some(body.retention_days)).await?,
    ))
}

async fn reset_retention(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<Json<RetentionSettingsResponse>, ApiError> {
    // Cleanup is deliberately not entitlement-gated: a tenant who downgraded
    // must be able to return to plan-tier defaults.
    require_scopes(&auth, &["retention:write"])?;
    let previous = configured_retention(&state, &auth.tenant_id).await?;
    sqlx::query("UPDATE tenants SET retention_days = NULL, updated_at = NOW() WHERE id = $1")
        .bind(&auth.tenant_id)
        .execute(&state.db)
        .await?;
    audit(
        &state,
        &auth.tenant_id,
        "retention.reset",
        serde_json::json!({ "previous_retention_days": previous }),
    )
    .await;
    Ok(Json(
        retention_response(&state, &auth.tenant_id, None).await?,
    ))
}

async fn audit(state: &AppState, tenant_id: &str, action: &str, details: serde_json::Value) {
    if let Err(error) = crate::audit_log::insert_audit_log_with_env(
        &state.db,
        state.config.environment.is_production(),
        Some(tenant_id),
        None,
        action,
        "retention",
        Some(tenant_id),
        details,
        None,
        None,
    )
    .await
    {
        warn!(tenant_id = %tenant_id, action, error = %error, "failed to write retention audit log");
    }
}

// ─── Tests ─────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::test_support::adv::AdvEnv;
    use axum::http::Method;

    async fn put(
        env: &AdvEnv,
        uri: &str,
        body: &str,
    ) -> (axum::http::StatusCode, serde_json::Value) {
        env.send_json(Method::PUT, uri, Some(body)).await
    }

    /// Pure validation: below the legal minimum is a 400, above the ceiling a
    /// named 403 — the boundary values themselves are accepted.
    #[test]
    fn retention_bounds_are_validated_with_named_reasons() {
        assert!(validate_retention_update(1, 90).is_ok());
        assert!(validate_retention_update(90, 90).is_ok());

        let above = validate_retention_update(91, 90).expect_err("91 > 90");
        match above {
            ApiError::Forbidden(message) => {
                assert!(message.contains("90"), "{message}");
                assert!(message.contains("91"), "{message}");
            }
            other => panic!("expected Forbidden, got {other:?}"),
        }

        let below = validate_retention_update(0, 90).expect_err("0 < minimum");
        assert!(matches!(below, ApiError::Validation(_)), "{below:?}");

        // Unlimited (-1) never refuses for the ceiling.
        assert!(validate_retention_update(9_999, -1).is_ok());
    }

    /// Read is available without the capability; editing without the
    /// entitlement is refused with the named plan reason (the canonical
    /// RuntimeEnforced gate, no transitional seam).
    #[tokio::test]
    async fn editing_requires_the_custom_retention_entitlement_but_read_does_not() {
        let Some(pool) = crate::test_db::canonical_pool("ret_gate").await else {
            return;
        };
        let (env, _tenant) =
            AdvEnv::tenant(pool.clone(), &["retention:read", "retention:write"]).await;

        let (status, body) = env.get("/v1/retention").await;
        assert_eq!(status, axum::http::StatusCode::OK, "{body}");
        assert_eq!(body["custom_retention_granted"], false);
        assert_eq!(body["configured_retention_days"], serde_json::Value::Null);

        let (status, body) = put(&env, "/v1/retention", r#"{"retention_days":5}"#).await;
        assert_eq!(
            status,
            axum::http::StatusCode::FORBIDDEN,
            "an unentitled tenant must be refused, got {status} {body}"
        );
        let message = body["error"]["message"].as_str().unwrap_or_default();
        assert!(
            message.contains("custom_retention") || message.contains("plan"),
            "the refusal must name the capability/plan: {message}"
        );
    }

    /// Put the tenant on the REAL Growth `plans` row — the canonical
    /// RuntimeEnforced row the entitlement gate reads: `custom_retention`
    /// granted with a `max_retention_days` ceiling of 90 (the seed's
    /// `..PlanFeatures::default()` fields a partial JSON would corrupt).
    async fn seed_entitled_growth(pool: &sqlx::PgPool, tenant: &str) {
        let features = serde_json::to_value(
            &billing_service::plans::builtin_plan_seed(Some("growth")).features,
        )
        .expect("plan features JSON");
        sqlx::query(
            "INSERT INTO plans (name, display_name, features) VALUES ('growth', 'Growth', $1) \
             ON CONFLICT (name) DO UPDATE SET features = EXCLUDED.features",
        )
        .bind(&features)
        .execute(pool)
        .await
        .expect("seed growth plan");
        sqlx::query("UPDATE tenants SET plan = 'growth' WHERE id = $1")
            .bind(tenant)
            .execute(pool)
            .await
            .expect("plan to growth");
    }

    /// Within/over the ceiling, honest read-back, reset, and tenant
    /// isolation of the write (another tenant's row is never touched).
    #[tokio::test]
    async fn retention_edit_respects_the_plan_ceiling_and_tenant_isolation() {
        let Some(pool) = crate::test_db::canonical_pool("ret_edit").await else {
            return;
        };
        let (env, tenant) =
            AdvEnv::tenant(pool.clone(), &["retention:read", "retention:write"]).await;
        seed_entitled_growth(&pool, &tenant).await;

        let (status, read) = env.get("/v1/retention").await;
        assert_eq!(status, axum::http::StatusCode::OK, "{read}");
        assert_eq!(read["plan"], "growth");
        assert_eq!(read["plan_max_retention_days"], 90);
        // `custom_retention` is RuntimeEnforced and the Growth seed grants
        // it, so the presentation boolean is true and the 200 below proves
        // the same gate admitted the write.
        assert_eq!(read["custom_retention_granted"], true);

        let (status, body) = put(&env, "/v1/retention", r#"{"retention_days":45}"#).await;
        assert_eq!(status, axum::http::StatusCode::OK, "{body}");
        assert_eq!(body["configured_retention_days"], 45);
        assert_eq!(body["effective_retention_days"], 45);

        let stored: Option<i32> =
            sqlx::query_scalar("SELECT retention_days FROM tenants WHERE id = $1")
                .bind(&tenant)
                .fetch_one(&pool)
                .await
                .expect("stored value");
        assert_eq!(stored, Some(45));

        // Over the ceiling: named refusal, stored value unchanged.
        let (status, body) = put(&env, "/v1/retention", r#"{"retention_days":91}"#).await;
        assert_eq!(status, axum::http::StatusCode::FORBIDDEN, "{body}");
        assert!(
            body["error"]["message"]
                .as_str()
                .unwrap_or_default()
                .contains("90"),
            "{body}"
        );
        let still: Option<i32> =
            sqlx::query_scalar("SELECT retention_days FROM tenants WHERE id = $1")
                .bind(&tenant)
                .fetch_one(&pool)
                .await
                .expect("stored value");
        assert_eq!(still, Some(45));

        // Below the legal minimum: named 400, unchanged.
        let (status, body) = put(&env, "/v1/retention", r#"{"retention_days":0}"#).await;
        assert_eq!(status, axum::http::StatusCode::BAD_REQUEST, "{body}");

        // A second entitled tenant's write never touches the first row.
        let (other_env, other) =
            AdvEnv::tenant(pool.clone(), &["retention:read", "retention:write"]).await;
        seed_entitled_growth(&pool, &other).await;
        let (status, _) = put(&other_env, "/v1/retention", r#"{"retention_days":60}"#).await;
        assert_eq!(status, axum::http::StatusCode::OK);
        let first_still: Option<i32> =
            sqlx::query_scalar("SELECT retention_days FROM tenants WHERE id = $1")
                .bind(&tenant)
                .fetch_one(&pool)
                .await
                .expect("stored value");
        assert_eq!(first_still, Some(45), "cross-tenant write must not leak");

        // Reset returns to plan defaults (and is not entitlement-gated).
        let (status, body) = env.delete("/v1/retention").await;
        assert_eq!(status, axum::http::StatusCode::OK, "{body}");
        assert_eq!(body["configured_retention_days"], serde_json::Value::Null);

        // Mutations are audit-logged.
        let audits: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM audit_logs WHERE tenant_id = $1 \
             AND action IN ('retention.updated','retention.reset')",
        )
        .bind(&tenant)
        .fetch_one(&pool)
        .await
        .expect("audit probe");
        assert!(
            audits >= 2,
            "expected update+reset audit rows, got {audits}"
        );
    }
}
