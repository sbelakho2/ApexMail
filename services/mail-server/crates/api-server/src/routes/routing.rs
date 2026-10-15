//! Tenant delivery-routing mode (`global` | `eu_only`) and the EU-only
//! activation gate.
//!
//! The mode is a tenant FACT stored in the tenant settings JSON
//! (`tenants.settings.routingMode`), read through the shared typed reader
//! [`mail_common::RoutingMode`] so this surface and the worker that enforces
//! the mode cannot disagree:
//!
//! * `global` (default, and always selectable) — the historical routing: a
//!   selected dedicated IP rides ApexMail's own relay MTA, everything else
//!   the shared pool.
//! * `eu_only` — every send must leave through ApexMail's OWN MTAs; the
//!   shared third-party transport (SES) is forbidden and an unavailable
//!   own-MTA route HOLDS the message (the worker enforces this; see
//!   `worker-processors`' `handle_eu_only_hold`).
//!
//! Entitlement mapping (docs/pricing.md, platform-catalog):
//!
//! * INCLUDED on Enterprise Cloud (and the Compliance contract line) — the
//!   plan's `eu_only_routing` feature flag;
//! * sold as the `eu_only_routing` add-on on self-serve Pro and above
//!   (€149/$165 per month). There is no generic add-on table in the billing
//!   runtime, so the purchased add-on is recorded as
//!   `settings.addons.euOnlyRouting = true` (set by billing on purchase,
//!   cleared on cancel; see `mail_common::routing_mode`).
//!
//! Activating `eu_only` requires one of the two grants; without either the
//! request is refused with a named 4xx. Deactivating (back to `global`) is
//! deliberately NOT gated — a tenant whose add-on lapsed must always be able
//! to return to the default mode, exactly like retention cleanup.
//!
//! Routes:
//! * `GET /v1/routing` — current mode + entitlement state (`routing:read`);
//! * `PUT /v1/routing` — set the mode (`routing:write`); `eu_only` is
//!   entitlement-gated, an invalid mode is a named 400.

use axum::extract::State;
use axum::routing::get;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use sqlx::Row;
use tracing::{info, warn};

use billing_entitlements::FeatureKey;
use mail_common::{eu_only_addon_enabled, RoutingMode, ROUTING_MODE_SETTINGS_KEY};

use crate::error::ApiError;
use crate::middleware::auth::{require_scopes, AuthUser};
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new().route("/", get(get_routing).put(update_routing))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateRoutingModeRequest {
    /// `global` (default) or `eu_only`; case-insensitive, canonicalized on
    /// write.
    pub mode: String,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct RoutingSettingsResponse {
    pub plan: String,
    /// `global` | `eu_only` — the ACTIVE mode the worker executes.
    pub mode: String,
    /// Whether the current tenant may activate EU-only routing (plan grant
    /// OR the purchased add-on).
    pub eu_only_granted: bool,
    /// The plan itself includes EU-only routing (Enterprise Cloud / the
    /// Compliance contract line).
    pub eu_only_included_in_plan: bool,
    /// The self-serve `eu_only_routing` add-on is recorded on this tenant.
    pub eu_only_addon_purchased: bool,
}

/// Pure enum validation shared by the handler and its tests. Trims and
/// canonicalizes case (the same normalization the shared reader applies on
/// read), and refuses anything else with a named 400 listing the allowed
/// values.
pub(crate) fn parse_routing_mode(mode: &str) -> Result<RoutingMode, ApiError> {
    RoutingMode::parse(mode).ok_or_else(|| {
        ApiError::Validation(vec![format!(
            "mode `{mode}` is not a routing mode; allowed values: {}",
            RoutingMode::ALL
                .iter()
                .map(|mode| format!("`{}`", mode.as_str()))
                .collect::<Vec<_>>()
                .join(", ")
        )])
    })
}

/// The tenant's stored settings object (or `{}` when the row has no settings
/// — the column is `NOT NULL DEFAULT '{}'`, so this is belt and braces).
async fn tenant_settings(state: &AppState, tenant_id: &str) -> Result<serde_json::Value, ApiError> {
    let row = sqlx::query("SELECT settings FROM tenants WHERE id = $1")
        .bind(tenant_id)
        .fetch_optional(&state.db)
        .await?;
    let Some(row) = row else {
        return Err(ApiError::NotFound("tenant not found".into()));
    };
    let settings: Option<serde_json::Value> = row.try_get("settings")?;
    Ok(settings.unwrap_or_else(|| serde_json::json!({})))
}

fn response(
    plan: &str,
    settings: &serde_json::Value,
    snapshot: &billing_entitlements::EntitlementSnapshot,
) -> RoutingSettingsResponse {
    let included = snapshot.has_feature(FeatureKey::EuOnlyRouting);
    let addon = eu_only_addon_enabled(settings);
    RoutingSettingsResponse {
        plan: plan.to_string(),
        mode: RoutingMode::from_settings_json(settings)
            .as_str()
            .to_string(),
        eu_only_granted: included || addon,
        eu_only_included_in_plan: included,
        eu_only_addon_purchased: addon,
    }
}

async fn get_routing(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<Json<RoutingSettingsResponse>, ApiError> {
    require_scopes(&auth, &["routing:read"])?;
    let settings = tenant_settings(&state, &auth.tenant_id).await?;
    let snapshot = crate::entitlements::snapshot(&state, &auth.tenant_id).await?;
    Ok(Json(response(snapshot.plan(), &settings, &snapshot)))
}

async fn update_routing(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(body): Json<UpdateRoutingModeRequest>,
) -> Result<Json<RoutingSettingsResponse>, ApiError> {
    require_scopes(&auth, &["routing:write"])?;
    let requested = parse_routing_mode(&body.mode)?;
    let settings = tenant_settings(&state, &auth.tenant_id).await?;
    let mut snapshot = crate::entitlements::snapshot(&state, &auth.tenant_id).await?;

    if requested.is_eu_only() {
        // The purchased self-serve add-on is a per-tenant GRANT on top of the
        // plan; express it through the snapshot's override channel so the
        // canonical `require_feature` gate below performs the check (the
        // plan's own `eu_only_routing` flag — Enterprise Cloud / the
        // Compliance contract line — is already in the snapshot).
        if eu_only_addon_enabled(&settings) {
            snapshot.apply_override(
                FeatureKey::EuOnlyRouting.as_str(),
                &serde_json::Value::Bool(true),
            );
        }
        snapshot
            .require_feature(FeatureKey::EuOnlyRouting)
            .map_err(|error| {
                ApiError::Forbidden(format!(
                    "EU-only routing requires the add-on on this plan ({error}); purchase the \
                 `eu_only_routing` add-on (EUR 149/month, $165/month on Pro and above) or \
                 contact sales about the Compliance contract line"
                ))
            })?;
    }

    let previous = RoutingMode::from_settings_json(&settings);
    // Canonical value written under the documented settings key; the reader
    // treats an absent key as `global`, so writing the default explicitly is
    // still the honest operator-visible state.
    sqlx::query(
        "UPDATE tenants SET settings = jsonb_set(COALESCE(settings, '{}'::jsonb), \
         ARRAY[$2::text], to_jsonb($3::text), true), updated_at = NOW() WHERE id = $1",
    )
    .bind(&auth.tenant_id)
    .bind(ROUTING_MODE_SETTINGS_KEY)
    .bind(requested.as_str())
    .execute(&state.db)
    .await?;

    audit(
        &state,
        &auth.tenant_id,
        "routing.mode_updated",
        serde_json::json!({
            "previous_mode": previous.as_str(),
            "mode": requested.as_str(),
            "eu_only_included_in_plan": snapshot.has_feature(FeatureKey::EuOnlyRouting),
        }),
    )
    .await;

    info!(
        tenant_id = %auth.tenant_id,
        previous_mode = previous.as_str(),
        mode = requested.as_str(),
        "tenant routing mode updated"
    );

    let updated = tenant_settings(&state, &auth.tenant_id).await?;
    Ok(Json(response(snapshot.plan(), &updated, &snapshot)))
}

async fn audit(state: &AppState, tenant_id: &str, action: &str, details: serde_json::Value) {
    if let Err(error) = crate::audit_log::insert_audit_log_with_env(
        &state.db,
        state.config.environment.is_production(),
        Some(tenant_id),
        None,
        action,
        "routing",
        Some(tenant_id),
        details,
        None,
        None,
    )
    .await
    {
        warn!(tenant_id = %tenant_id, action, error = %error, "failed to write routing audit log");
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

    async fn stored_settings(pool: &sqlx::PgPool, tenant: &str) -> serde_json::Value {
        sqlx::query_scalar("SELECT settings FROM tenants WHERE id = $1")
            .bind(tenant)
            .fetch_one(pool)
            .await
            .expect("settings")
    }

    /// Pure enum validation: the two canonical values (case-insensitively)
    /// parse; anything else is a named 400 listing the allowed values.
    #[test]
    fn routing_mode_enum_is_validated_with_named_reasons() {
        assert_eq!(
            parse_routing_mode("global").expect("global"),
            RoutingMode::Global
        );
        assert_eq!(
            parse_routing_mode("eu_only").expect("eu_only"),
            RoutingMode::EuOnly
        );
        assert_eq!(
            parse_routing_mode("  EU_ONLY ").expect("case-insensitive"),
            RoutingMode::EuOnly
        );

        for invalid in ["eu-only", "", "eu only", "ses", "true"] {
            let error = parse_routing_mode(invalid).expect_err(invalid);
            match error {
                ApiError::Validation(messages) => {
                    let message = messages.join(" ");
                    assert!(message.contains("`global`"), "{message}");
                    assert!(message.contains("`eu_only`"), "{message}");
                    assert!(message.contains(invalid), "{message}");
                }
                other => panic!("expected 400 Validation for `{invalid}`, got {other:?}"),
            }
        }
    }

    /// Default is `global`, and an unentitled tenant is refused a `eu_only`
    /// activation with the named add-on message; the stored settings are
    /// untouched by the refusal.
    #[tokio::test]
    async fn eu_only_activation_requires_the_add_on_and_defaults_to_global() {
        let Some(pool) = crate::test_db::canonical_pool("routing_gate").await else {
            return;
        };
        let (env, tenant) = AdvEnv::tenant(pool.clone(), &["routing:read", "routing:write"]).await;

        let (status, body) = env.get("/v1/routing").await;
        assert_eq!(status, axum::http::StatusCode::OK, "{body}");
        assert_eq!(body["mode"], "global", "the default mode is global");
        assert_eq!(body["eu_only_granted"], false);
        assert_eq!(body["eu_only_addon_purchased"], false);

        let (status, body) = put(&env, "/v1/routing", r#"{"mode":"eu_only"}"#).await;
        assert_eq!(
            status,
            axum::http::StatusCode::FORBIDDEN,
            "an unentitled tenant must be refused, got {status} {body}"
        );
        let message = body["error"]["message"].as_str().unwrap_or_default();
        assert!(
            message.contains("requires the add-on on this plan"),
            "the refusal must name the add-on: {message}"
        );
        assert!(
            message.contains("eu_only_routing"),
            "the refusal must name the add-on id: {message}"
        );
        assert_eq!(
            stored_settings(&pool, &tenant).await.get("routingMode"),
            None,
            "a refused activation must not write the mode"
        );

        // Invalid enum: named 400, and still nothing written.
        let (status, body) = put(&env, "/v1/routing", r#"{"mode":"eu-only"}"#).await;
        assert_eq!(status, axum::http::StatusCode::BAD_REQUEST, "{body}");
        // `ApiError::Validation` carries the per-field messages in
        // `error.details` (the envelope keeps `message` generic).
        let details = body["error"]["details"].to_string();
        assert!(
            details.contains("`global`") && details.contains("`eu_only`"),
            "{body}"
        );
        assert!(details.contains("eu-only"), "{body}");
        assert_eq!(
            stored_settings(&pool, &tenant).await.get("routingMode"),
            None,
            "a rejected value must not write the mode"
        );

        pool.close().await;
    }

    /// The purchased add-on flag activates EU-only routing, persists the
    /// canonical value, is audit-logged, and `global` (downgrade) is never
    /// gated.
    #[tokio::test]
    async fn addon_flag_activates_eu_only_and_global_is_always_allowed() {
        let Some(pool) = crate::test_db::canonical_pool("routing_addon").await else {
            return;
        };
        let (env, tenant) = AdvEnv::tenant(pool.clone(), &["routing:read", "routing:write"]).await;
        sqlx::query(
            "UPDATE tenants SET settings = jsonb_set(COALESCE(settings, '{}'::jsonb), \
             '{addons}', '{\"euOnlyRouting\": true}'::jsonb, true) WHERE id = $1",
        )
        .bind(&tenant)
        .execute(&pool)
        .await
        .expect("record purchased add-on");

        let (status, body) = env.get("/v1/routing").await;
        assert_eq!(status, axum::http::StatusCode::OK, "{body}");
        assert_eq!(body["eu_only_addon_purchased"], true);
        assert_eq!(body["eu_only_granted"], true);
        assert_eq!(body["eu_only_included_in_plan"], false);

        let (status, body) = put(&env, "/v1/routing", r#"{"mode":"eu_only"}"#).await;
        assert_eq!(status, axum::http::StatusCode::OK, "{body}");
        assert_eq!(body["mode"], "eu_only");

        let settings = stored_settings(&pool, &tenant).await;
        assert_eq!(settings["routingMode"], "eu_only", "{settings}");
        assert_eq!(
            settings["addons"]["euOnlyRouting"], true,
            "the add-on flag survives the mode write: {settings}"
        );

        // The worker's reader sees exactly the mode the API wrote.
        assert_eq!(
            RoutingMode::from_settings_json(&settings),
            RoutingMode::EuOnly
        );

        // Back to global: allowed with no entitlement at all.
        let (status, body) = put(&env, "/v1/routing", r#"{"mode":"global"}"#).await;
        assert_eq!(status, axum::http::StatusCode::OK, "{body}");
        assert_eq!(body["mode"], "global");
        assert_eq!(
            stored_settings(&pool, &tenant).await["routingMode"],
            "global"
        );

        // Both writes are audit-logged.
        let audits: i64 = sqlx::query_scalar(
            "SELECT COUNT(*)::bigint FROM audit_logs \
             WHERE tenant_id = $1 AND action = 'routing.mode_updated'",
        )
        .bind(&tenant)
        .fetch_one(&pool)
        .await
        .expect("audit probe");
        assert_eq!(audits, 2, "expected both mode writes to be audited");

        pool.close().await;
    }

    /// Put the tenant on the REAL Enterprise Cloud `plans` row — the plan
    /// whose seed INCLUDES `eu_only_routing`, so activation needs no add-on.
    async fn seed_enterprise_plan(pool: &sqlx::PgPool, tenant: &str) {
        let features = serde_json::to_value(
            &billing_service::plans::builtin_plan_seed(Some("enterprise")).features,
        )
        .expect("plan features JSON");
        sqlx::query(
            "INSERT INTO plans (name, display_name, features) VALUES ('enterprise', 'Enterprise Cloud', $1) \
             ON CONFLICT (name) DO UPDATE SET features = EXCLUDED.features",
        )
        .bind(&features)
        .execute(pool)
        .await
        .expect("seed enterprise plan");
        sqlx::query("UPDATE tenants SET plan = 'enterprise' WHERE id = $1")
            .bind(tenant)
            .execute(pool)
            .await
            .expect("plan to enterprise");
    }

    /// Enterprise Cloud includes EU-only routing: activation succeeds with no
    /// add-on, and the response says so. A second tenant's settings are never
    /// touched by the write.
    #[tokio::test]
    async fn enterprise_plan_includes_eu_only_routing_without_the_addon() {
        let Some(pool) = crate::test_db::canonical_pool("routing_enterprise").await else {
            return;
        };
        let (env, tenant) = AdvEnv::tenant(pool.clone(), &["routing:read", "routing:write"]).await;
        seed_enterprise_plan(&pool, &tenant).await;
        let (other_env, other) =
            AdvEnv::tenant(pool.clone(), &["routing:read", "routing:write"]).await;

        let (status, body) = env.get("/v1/routing").await;
        assert_eq!(status, axum::http::StatusCode::OK, "{body}");
        assert_eq!(body["plan"], "enterprise");
        assert_eq!(body["eu_only_included_in_plan"], true);
        assert_eq!(body["eu_only_granted"], true);
        assert_eq!(body["mode"], "global");

        let (status, body) = put(&env, "/v1/routing", r#"{"mode":"eu_only"}"#).await;
        assert_eq!(status, axum::http::StatusCode::OK, "{body}");
        assert_eq!(body["mode"], "eu_only");

        // Tenant isolation: the other tenant's settings are untouched.
        assert_eq!(
            stored_settings(&pool, &other).await.get("routingMode"),
            None,
            "a routing write must never leak into another tenant's settings"
        );
        let (status, other_read) = other_env.get("/v1/routing").await;
        assert_eq!(status, axum::http::StatusCode::OK, "{other_read}");
        assert_eq!(other_read["mode"], "global");

        pool.close().await;
    }
}
