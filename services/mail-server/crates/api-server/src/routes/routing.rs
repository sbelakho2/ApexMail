//! Tenant delivery-routing mode (`global` | `eu_only`) and the EU-only
//! activation gate.
//!
//! The mode is a tenant FACT stored in the tenant settings JSON
//! (`tenants.settings.routingMode`), read through the shared typed reader
//! [`mail_common::RoutingMode`] so this surface and the worker that enforces
//! the mode cannot disagree:
//!
//! * `global` (default, and always selectable), the historical routing: a
//!   selected dedicated IP rides ApexMail's own relay MTA, everything else
//!   the shared pool.
//! * `eu_only`, every send must leave through ApexMail's OWN MTAs; the
//!   shared third-party transport (SES) is forbidden and an unavailable
//!   own-MTA route HOLDS the message (the worker enforces this; see
//!   `worker-processors`' `handle_eu_only_hold`).
//!
//! Entitlement mapping (docs/pricing.md, platform-catalog):
//!
//! * INCLUDED on Enterprise Cloud (and the Compliance contract line), the
//!   plan's `eu_only_routing` feature flag;
//! * sold as the `eu_only_routing` add-on on self-serve Pro and above
//!   (€149/$165 per month). There is no generic add-on table in the billing
//!   runtime, so the purchased add-on is recorded as
//!   `settings.addons.euOnlyRouting = true` (set by billing on purchase,
//!   cleared on cancel; see `mail_common::routing_mode`).
//!
//! Activating `eu_only` requires one of the two grants; without either the
//! request is refused with a named 4xx. Deactivating (back to `global`) is
//! deliberately NOT gated, a tenant whose add-on lapsed must always be able
//! to return to the default mode, exactly like retention cleanup.
//!
//! Routes:
//! * `GET /v1/routing`, current mode + entitlement state (`routing:read`);
//! * `PUT /v1/routing`, set the mode (`routing:write`); `eu_only` is
//!   entitlement-gated, an invalid mode is a named 400.
//!
//! # Public receipt verification (B3, "the proof is signed per message")
//!
//! The DELIVERY acceptance ledger signs one Ed25519 receipt per accepted
//! message (`mail_common::routing_receipt`, migration 255). Two routes make
//! that proof verifiable by ANYONE, with no account and no shared secret:
//!
//! * `GET /v1/routing/receipts/public-key`, the published Ed25519 public
//!   key + its fingerprint (`key_id`), or 503 when this deployment publishes
//!   no key (never a fabricated one);
//! * `POST /v1/routing/receipts/verify`, `{payload, signature}` (plus an
//!   optional `public_key` to verify against a key snapshot instead of the
//!   deployment's) → a determinate `valid: true|false` verdict.
//!
//! Both are mounted OUTSIDE the authenticated stack (the public rate-limited
//! router in `app::build_app`), because a proof only the issuer can check is
//! not a proof.

use axum::extract::State;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
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

/// The PUBLIC (unauthenticated) receipt-verification surface. Mounted by
/// `app::build_app` on the public rate-limited router under
/// `/v1/routing/receipts`, deliberately separate from [`router`], which
/// rides the authenticated stack.
pub fn public_receipts_router() -> Router<AppState> {
    Router::new()
        .route("/public-key", get(receipt_public_key))
        .route("/verify", post(receipt_verify))
}

/// Maximum canonical payload accepted by the verify endpoint (bytes). The
/// documented payload is a handful of short lines; anything larger is not a
/// receipt (the endpoint is public and anonymous).
const MAX_RECEIPT_PAYLOAD_BYTES: usize = 4 * 1024;

/// The published verification material.
#[derive(Debug, Serialize)]
pub struct ReceiptPublicKeyResponse {
    /// Signature scheme, always `ed25519`.
    pub scheme: &'static str,
    /// `hex(sha256(public_key))[..16]`, stable across key rotations of other
    /// keys; recorded next to every stored signature.
    pub key_id: String,
    /// Base64 (standard, no padding) of the 32-byte Ed25519 public key.
    pub public_key_base64: String,
    /// Lowercase hex of the same key.
    pub public_key_hex: String,
    /// The endpoint that verifies a presented (payload, signature) pair.
    pub verify_url: &'static str,
    /// The canonical payload format the signature covers.
    pub payload_format: &'static str,
}

/// Build the public-key response from a resolved public key (pure, the
/// HTTP handler only resolves the key and calls this).
pub fn receipt_public_key_response(public_key: &[u8; 32]) -> ReceiptPublicKeyResponse {
    ReceiptPublicKeyResponse {
        scheme: mail_common::routing_receipt::RECEIPT_SIGNATURE_SCHEME,
        key_id: mail_common::routing_receipt::key_id_for(public_key),
        public_key_base64: base64_no_pad(public_key),
        public_key_hex: public_key.iter().map(|b| format!("{b:02x}")).collect(),
        verify_url: "/v1/routing/receipts/verify",
        payload_format: "apexmail-routing-receipt/v1, LF-delimited fields: message_id,                          tenant_id, transport, accepted_at, actual_source_ip (only when the                          transport reported one); the exact bytes are signed as-is",
    }
}

fn base64_no_pad(bytes: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD_NO_PAD.encode(bytes)
}

/// `GET /v1/routing/receipts/public-key`, public, no auth.
///
/// Fail-closed: with no key configured this answers 503 with a named error
/// and NO key material, a fabricated or empty key would make every
/// subsequent verification a lie.
async fn receipt_public_key() -> Response {
    match mail_common::routing_receipt::verification_key_from_env() {
        Ok(Some(public_key)) => (
            axum::http::StatusCode::OK,
            Json(serde_json::to_value(receipt_public_key_response(&public_key)).unwrap_or(
                serde_json::json!({"error": "serialization"}),
            )),
        )
            .into_response(),
        Ok(None) => (
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({
                "code": "receipt_public_key_unavailable",
                "error": format!(
                    "this deployment publishes no routing-receipt verification key; set {}                      (the public key) or {} on the api-server",
                    mail_common::routing_receipt::RECEIPT_PUBLIC_KEY_ENV,
                    mail_common::routing_receipt::RECEIPT_SIGNING_KEY_ENV,
                ),
            })),
        )
            .into_response(),
        Err(error) => (
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({
                "code": "receipt_public_key_invalid",
                "error": format!("the configured receipt verification key is unusable: {error}"),
            })),
        )
            .into_response(),
    }
}

/// The verify request: the canonical payload + the signature exactly as
/// stored/exported from the ledger row.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifyReceiptRequest {
    /// The canonical payload bytes, UTF-8 (stored verbatim on the ledger).
    pub payload: String,
    /// Base64 (standard/URL-safe, padding optional) or hex of the 64-byte
    /// Ed25519 signature.
    pub signature: String,
    /// Optional: verify against THIS key instead of the deployment's (a
    /// third party checking a key snapshot, or a rotation-time audit).
    pub public_key: Option<String>,
}

/// Split the canonical payload into its fields, refusing anything that is
/// not a version-1 receipt (a valid signature over an unrelated blob is not
/// a routing receipt).
pub fn parse_receipt_payload(payload: &str) -> Result<Vec<(String, String)>, String> {
    let mut lines = payload.lines();
    if lines.next() != Some(mail_common::routing_receipt::RECEIPT_PAYLOAD_VERSION) {
        return Err(format!(
            "payload does not start with `{}`",
            mail_common::routing_receipt::RECEIPT_PAYLOAD_VERSION
        ));
    }
    let mut fields = Vec::new();
    for line in lines {
        let (key, value) = line
            .split_once('=')
            .ok_or_else(|| format!("payload line `{line}` is not `key=value`"))?;
        const ALLOWED: [&str; 5] = [
            "message_id",
            "tenant_id",
            "transport",
            "accepted_at",
            "actual_source_ip",
        ];
        if !ALLOWED.contains(&key) {
            return Err(format!("unknown payload field `{key}`"));
        }
        fields.push((key.to_string(), value.to_string()));
    }
    Ok(fields)
}

/// `POST /v1/routing/receipts/verify`, public, no auth, stateless:
/// `{payload, signature}` (+ optional `public_key`) → `{valid, ...}`.
///
/// A VALID verdict is a determinate cryptographic statement; an INVALID one
/// is returned as HTTP 200 with `valid: false` and a reason (the signature
/// was checked and did not hold, that is the answer, not a request error).
/// Malformed INPUT (oversized payload, non-receipt payload shape, bad
/// encodings) is a named 400; a deployment with no verification key is a
/// named 503 (fail closed, never `valid: true` by absence of a key).
async fn receipt_verify(Json(body): Json<VerifyReceiptRequest>) -> Response {
    let bad_request = |reason: &str| {
        (
            axum::http::StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "code": "invalid_receipt_request",
                "error": reason,
            })),
        )
            .into_response()
    };

    if body.payload.len() > MAX_RECEIPT_PAYLOAD_BYTES {
        return bad_request("payload exceeds the documented receipt size");
    }
    if body.payload.is_empty() {
        return bad_request("payload is empty");
    }
    let fields = match parse_receipt_payload(&body.payload) {
        Ok(fields) => fields,
        Err(reason) => return bad_request(&reason),
    };

    // Presented key (third-party/rotation audit) or the deployment's key.
    let (public_key, source) = match body.public_key.as_deref() {
        Some(raw) => match mail_common::routing_receipt::parse_public_key(raw) {
            Ok(key) => (key, "presented"),
            Err(error) => return bad_request(&format!("public_key: {error}")),
        },
        None => match mail_common::routing_receipt::verification_key_from_env() {
            Ok(Some(key)) => (key, "deployment"),
            Ok(None) => {
                return (
                    axum::http::StatusCode::SERVICE_UNAVAILABLE,
                    Json(serde_json::json!({
                        "code": "receipt_verification_key_unavailable",
                        "error": "this deployment publishes no verification key; pass the published public key as `public_key` to verify offline",
                    })),
                )
                    .into_response()
            }
            Err(error) => return bad_request(&format!("deployment key unusable: {error}")),
        },
    };

    let verdict =
        mail_common::routing_receipt::verify_payload(&body.payload, &body.signature, &public_key);
    let mut response = serde_json::json!({
        "valid": verdict.is_ok(),
        "scheme": mail_common::routing_receipt::RECEIPT_SIGNATURE_SCHEME,
        "key_id": mail_common::routing_receipt::key_id_for(&public_key),
        "public_key_source": source,
        "checked_at": chrono::Utc::now().to_rfc3339(),
        "fields": fields
            .iter()
            .map(|(key, value)| (key.clone(), serde_json::Value::String(value.clone())))
            .collect::<serde_json::Map<_, _>>(),
    });
    if let Err(error) = verdict {
        response["reason"] = serde_json::Value::String(error.to_string());
    }
    (axum::http::StatusCode::OK, Json(response)).into_response()
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
    /// `global` | `eu_only`, the ACTIVE mode the worker executes.
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
///, the column is `NOT NULL DEFAULT '{}'`, so this is belt and braces).
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
        // plan's own `eu_only_routing` flag, Enterprise Cloud / the
        // Compliance contract line, is already in the snapshot).
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

    /// Put the tenant on the REAL Enterprise Cloud `plans` row, the plan
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

    // ── B3: the PUBLIC receipt-verification surface ──────────────────────

    /// Serializes tests that mutate the receipt-key env vars.
    static RECEIPT_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// Run `body` with the receipt key env vars set as given, restoring the
    /// previous state afterwards (the same convention the worker tests use).
    /// ASYNC on purpose: the env must still be in place while the request
    /// future runs, a sync helper would restore the vars before the handler
    /// ever read them (the bug this signature exists to prevent).
    // The env lock is held ACROSS the request on purpose: the vars must stay
    // in place while the handler runs (two receipts tests serializing on one
    // lock; no nested locking, so the guard cannot deadlock).
    #[allow(clippy::await_holding_lock)]
    async fn with_receipt_env<F, Fut, T>(vars: &[(&str, Option<&str>)], body: F) -> T
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = T>,
    {
        let _guard = RECEIPT_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let names = [
            mail_common::routing_receipt::RECEIPT_PUBLIC_KEY_ENV,
            mail_common::routing_receipt::RECEIPT_SIGNING_KEY_ENV,
        ];
        let saved: Vec<(&str, Option<std::ffi::OsString>)> = names
            .iter()
            .map(|name| (*name, std::env::var_os(name)))
            .collect();
        for name in names {
            std::env::remove_var(name);
        }
        for (name, value) in vars {
            match value {
                Some(value) => std::env::set_var(name, value),
                None => std::env::remove_var(name),
            }
        }
        let out = body().await;
        for (name, value) in saved {
            match value {
                Some(previous) => std::env::set_var(name, previous),
                None => std::env::remove_var(name),
            }
        }
        out
    }

    /// The independent signer for these tests: the test HOLDS the seed and
    /// signs through the shared canonical-payload helper, exactly like an
    /// external party would. Nothing here uses the api-server's own code to
    /// produce the signature.
    fn independent_signer(seed_byte: u8) -> mail_common::routing_receipt::RoutingReceiptSigner {
        mail_common::routing_receipt::RoutingReceiptSigner::from_seed(&[seed_byte; 32])
            .expect("deterministic test signer")
    }

    fn receipt_payload() -> String {
        mail_common::routing_receipt::canonical_payload(
            &mail_common::routing_receipt::RoutingReceiptFields {
                message_id: "msg-public-1",
                tenant_id: "tenant-public",
                transport: "dedicated",
                accepted_at: "2026-10-15T09:30:00.123+00:00",
                actual_source_ip: Some("203.0.113.9"),
            },
        )
        .expect("payload")
    }

    /// `GET /v1/routing/receipts/public-key` is public (no credential needed)
    /// and publishes the key a third party must use; with no key configured
    /// it answers 503, never a fabricated key.
    #[tokio::test]
    async fn public_receipt_key_endpoint_is_open_and_fail_closed() {
        let Some(pool) = crate::test_db::canonical_pool("receipt_pubkey").await else {
            return;
        };
        let (env, _tenant) = AdvEnv::tenant(pool.clone(), &[]).await;

        // Fail closed: no key configured.
        let (status, body) = with_receipt_env(&[], || async {
            env.get("/v1/routing/receipts/public-key").await
        })
        .await;
        assert_eq!(
            status,
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            "{body}"
        );
        assert_eq!(body["error"]["code"], "receipt_public_key_unavailable");
        assert!(
            body["public_key_base64"].is_null(),
            "no key material may be fabricated: {body}"
        );

        // Configured: the published key is exactly the signer's public half.
        let signer = independent_signer(0x11);
        let (status, body) = with_receipt_env(
            &[(RECEIPT_PUBLIC_KEY_ENV, Some(&signer.public_key_hex()))],
            || async { env.get("/v1/routing/receipts/public-key").await },
        )
        .await;
        assert_eq!(status, axum::http::StatusCode::OK, "{body}");
        assert_eq!(body["scheme"], "ed25519");
        assert_eq!(body["public_key_hex"], signer.public_key_hex());
        assert_eq!(body["public_key_base64"], signer.public_key_base64());
        assert_eq!(body["key_id"], signer.key_id());
        assert_eq!(body["verify_url"], "/v1/routing/receipts/verify");

        pool.close().await;
    }

    /// The verify endpoint accepts an EXTERNALLY produced signature (the test
    /// holds the private key), returns a determinate verdict, catches
    /// tampering, and 400s malformed input, all without a credential.
    #[tokio::test]
    async fn public_receipt_verify_accepts_external_signatures_and_refuses_tampering() {
        let Some(pool) = crate::test_db::canonical_pool("receipt_verify").await else {
            return;
        };
        let (env, _tenant) = AdvEnv::tenant(pool.clone(), &[]).await;
        let signer = independent_signer(0x22);
        let signed = signer
            .sign_fields(&mail_common::routing_receipt::RoutingReceiptFields {
                message_id: "msg-public-2",
                tenant_id: "tenant-public",
                transport: "ses-shared",
                accepted_at: "2026-10-15T10:00:00.5+00:00",
                actual_source_ip: None,
            })
            .expect("sign");
        let body = serde_json::json!({
            "payload": signed.payload,
            "signature": signed.signature,
        })
        .to_string();

        // Deployment key configured; the caller sends no credential.
        let (status, verdict) = with_receipt_env(
            &[(RECEIPT_PUBLIC_KEY_ENV, Some(&signer.public_key_hex()))],
            || async {
                env.send_json(
                    axum::http::Method::POST,
                    "/v1/routing/receipts/verify",
                    Some(&body),
                )
                .await
            },
        )
        .await;
        assert_eq!(status, axum::http::StatusCode::OK, "{verdict}");
        assert_eq!(verdict["valid"], true, "{verdict}");
        assert_eq!(verdict["key_id"], signer.key_id());
        assert_eq!(verdict["public_key_source"], "deployment");
        assert_eq!(verdict["fields"]["message_id"], "msg-public-2");

        // Tampered payload: a determinate `valid: false` (not a 4xx) with a
        // reason, the signature was checked and did not hold.
        let tampered = serde_json::json!({
            "payload": signed.payload.replace("tenant-public", "tenant-other"),
            "signature": signed.signature,
        })
        .to_string();
        let (status, verdict) = with_receipt_env(
            &[(RECEIPT_PUBLIC_KEY_ENV, Some(&signer.public_key_hex()))],
            || async {
                env.send_json(
                    axum::http::Method::POST,
                    "/v1/routing/receipts/verify",
                    Some(&tampered),
                )
                .await
            },
        )
        .await;
        assert_eq!(status, axum::http::StatusCode::OK, "{verdict}");
        assert_eq!(verdict["valid"], false, "{verdict}");
        assert!(verdict["reason"]
            .as_str()
            .unwrap()
            .contains("does not verify"));

        // A payload that is not a receipt is malformed input (400), and a
        // deployment with no key answers 503 rather than `valid: true`.
        let (status, verdict) = with_receipt_env(&[], || async {
            env.send_json(
                axum::http::Method::POST,
                "/v1/routing/receipts/verify",
                Some(r#"{"payload":"not-a-receipt","signature":"AAAA"}"#),
            )
            .await
        })
        .await;
        assert_eq!(status, axum::http::StatusCode::BAD_REQUEST, "{verdict}");
        assert_eq!(verdict["error"]["code"], "invalid_receipt_request");

        let (status, verdict) = with_receipt_env(&[], || async {
            env.send_json(
                axum::http::Method::POST,
                "/v1/routing/receipts/verify",
                Some(&body),
            )
            .await
        })
        .await;
        assert_eq!(
            status,
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            "{verdict}"
        );
        assert_eq!(
            verdict["error"]["code"],
            "receipt_verification_key_unavailable"
        );

        // An auditor can verify against a PRESENTED key snapshot with no
        // deployment key at all (the offline-verification contract).
        let presented = serde_json::json!({
            "payload": signed.payload,
            "signature": signed.signature,
            "public_key": signer.public_key_base64(),
        })
        .to_string();
        let (status, verdict) = with_receipt_env(&[], || async {
            env.send_json(
                axum::http::Method::POST,
                "/v1/routing/receipts/verify",
                Some(&presented),
            )
            .await
        })
        .await;
        assert_eq!(status, axum::http::StatusCode::OK, "{verdict}");
        assert_eq!(verdict["valid"], true, "{verdict}");
        assert_eq!(verdict["public_key_source"], "presented");

        pool.close().await;
    }

    use mail_common::routing_receipt::{RECEIPT_PUBLIC_KEY_ENV, RECEIPT_SIGNING_KEY_ENV};

    /// The pure payload parser refuses non-receipt shapes (pinned so the
    /// endpoint's 400 cannot silently widen into "verify anything").
    #[test]
    fn receipt_payload_parser_pins_the_canonical_shape() {
        let fields = parse_receipt_payload(&receipt_payload()).expect("canonical parses");
        assert_eq!(fields.len(), 5);
        assert_eq!(
            fields[0],
            ("message_id".to_string(), "msg-public-1".to_string())
        );

        for bad in [
            "",
            "other-version
message_id=x",
            // a line that is not key=value
            &format!(
                "{}\nmessage_id",
                mail_common::routing_receipt::RECEIPT_PAYLOAD_VERSION
            ),
            // an unrecognized field (the shape cannot widen silently)
            &format!(
                "{}\nrogue_field=x",
                mail_common::routing_receipt::RECEIPT_PAYLOAD_VERSION
            ),
        ] {
            assert!(parse_receipt_payload(bad).is_err(), "must refuse: {bad:?}");
        }
        // The signing-key env is only a fallback and must not be required.
        assert!(!RECEIPT_SIGNING_KEY_ENV.is_empty());
    }
}
