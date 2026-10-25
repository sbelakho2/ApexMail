//! WP F12/F9, the reply auto-send PROMOTION surface (owner-only).
//!
//! The operating model: autonomy moves only through the promotion gates in
//! WP F12, and promoting autonomy is an owner act. This module is that act for
//! the reply pipeline: a per-`(tenant, reply class)` enablement row
//! (`reply_autosend_grants`, migration 259) that may be switched ON only
//!
//!   * by a live OWNER, the structural `require_sales_owner` layer around
//!     `/v1/admin/autopilot` admits only a human control-plane session of the
//!     system tenant whose live `users.role` is exactly `owner`, and the gate
//!     function itself re-verifies that role inside the write transaction
//!     (`OwnerActor::verify`), so an agent path or a machine credential
//!     reaching this module by any route still cannot enable anything;
//!   * with RECORDED EVIDENCE, the class's approvals are counted live from
//!     `audit_logs` (the rows the approval transaction writes) and the
//!     window's complaints/opt-outs from `sales_reply_classifications`;
//!     an unsatisfied bar refuses the enablement with the numbers;
//!   * default OFF, no row means no autonomy, and a read can never create
//!     one.
//!
//! Revocation is the per-class kill switch: it flips `enabled` back to FALSE
//! and keeps the row (the captured evidence stays on record). Both mutations
//! write their actor-attributed audit row INSIDE the same transaction as the
//! grant change, a promotion either happens fully on record or not at all.

use axum::extract::{Query, State};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;

use sales_autopilot::reply_autosend::{self, EvidenceReport, LowRiskClass, OwnerActor};
use sales_autopilot::types::SalesError;

use crate::error::ApiError;
use crate::middleware::auth::{require_scopes, require_system_tenant, AuthUser};
use crate::state::AppState;

/// The audited actions for the two mutations.
pub const ENABLED_AUDIT_ACTION: &str = "control_plane.autopilot.reply_autosend_enabled";
pub const REVOKED_AUDIT_ACTION: &str = "control_plane.autopilot.reply_autosend_revoked";

pub fn router() -> Router<AppState> {
    // Mounted INSIDE the `/v1/admin/autopilot` router, under the same
    // structural `require_sales_owner` layer as every other autonomy control.
    Router::new()
        .route("/reply-autosend", get(get_promotion_status))
        .route("/reply-autosend/enable", post(post_enable))
        .route("/reply-autosend/revoke", post(post_revoke))
}

/// Map the engine's error taxonomy onto the CP's HTTP contract.
fn map_sales_error(error: SalesError) -> ApiError {
    match error {
        SalesError::Unauthorized(message) => ApiError::Forbidden(message),
        SalesError::InvalidInput(message) => ApiError::Validation(vec![message]),
        SalesError::Database(message) => {
            tracing::error!(error = %message, "reply autosend promotion storage failure");
            ApiError::Internal("could not update the reply auto-send promotion".into())
        }
        other => ApiError::Internal(format!("reply autosend: {other}")),
    }
}

#[derive(Debug, Deserialize)]
pub struct TenantQuery {
    /// The routed tenant whose reply classes are being promoted.
    pub tenant: String,
}

/// The promotion status: every canonical class with its grant row (or the
/// fail-closed default) and the live evidence that would be required.
#[derive(Debug, serde::Serialize)]
struct PromotionEntry {
    reply_class: String,
    enabled: bool,
    enabled_by: Option<String>,
    enabled_at: Option<String>,
    disabled_by: Option<String>,
    disabled_at: Option<String>,
    evidence: EvidenceReport,
}

async fn get_promotion_status(
    State(state): State<AppState>,
    auth: AuthUser,
    Query(query): Query<TenantQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    require_scopes(&auth, &["*"])?;
    require_system_tenant(&state, &auth).await?;
    let tenant = validate_tenant(&query.tenant)?;

    let mut conn = state.db.acquire().await?;
    let status = reply_autosend::promotion_status(&mut conn, &tenant)
        .await
        .map_err(map_sales_error)?;

    let entries: Vec<PromotionEntry> = status
        .into_iter()
        .map(|(grant, evidence)| PromotionEntry {
            reply_class: grant.reply_class.as_str().to_string(),
            enabled: grant.enabled,
            enabled_by: grant.enabled_by,
            enabled_at: grant.enabled_at.map(|at| at.to_rfc3339()),
            disabled_by: grant.disabled_by,
            disabled_at: grant.disabled_at.map(|at| at.to_rfc3339()),
            evidence,
        })
        .collect();

    Ok(Json(serde_json::json!({
        "tenantId": tenant,
        "classes": entries,
    })))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EnableRequest {
    pub tenant_id: String,
    pub reply_class: String,
    #[serde(default)]
    pub required_approvals: Option<i64>,
    #[serde(default)]
    pub window_days: Option<i64>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RevokeRequest {
    pub tenant_id: String,
    pub reply_class: String,
}

/// Promote one `(tenant, reply class)` to autonomous sending, an owner act,
/// backed by the class's recorded approvals at this instant.
async fn post_enable(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(body): Json<EnableRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    require_scopes(&auth, &["*"])?;
    require_system_tenant(&state, &auth).await?;
    let tenant = validate_tenant(&body.tenant_id)?;
    let class = parse_class(&body.reply_class)?;
    let required = body
        .required_approvals
        .unwrap_or(reply_autosend::DEFAULT_REQUIRED_APPROVALS);
    let window = body
        .window_days
        .unwrap_or(reply_autosend::DEFAULT_EVIDENCE_WINDOW_DAYS);

    // The owner gate already ran structurally; the actor id it proved is what
    // the grant records, and the gate function re-verifies the live role
    // inside this transaction before anything is written.
    let owner_user_id = auth.user_id.clone().ok_or_else(|| {
        ApiError::Forbidden("promoting autonomy requires a signed-in owner".into())
    })?;

    let mut tx = state.db.begin().await?;
    let actor = OwnerActor::verify(&mut tx, &owner_user_id)
        .await
        .map_err(map_sales_error)?;
    let evidence = reply_autosend::enable(&mut tx, &tenant, class, &actor, required, window)
        .await
        .map_err(map_sales_error)?;

    crate::audit_log::insert_audit_log_in_tx_with_env(
        &mut tx,
        state.config.environment.is_production(),
        Some(auth.tenant_id.as_str()),
        auth.user_id.as_deref(),
        ENABLED_AUDIT_ACTION,
        "reply_autosend_grant",
        Some(&format!("{tenant}:{}", class.as_str())),
        serde_json::json!({
            "tenantId": tenant,
            "replyClass": class.as_str(),
            "evidence": evidence,
        }),
        None,
        None,
        chrono::Utc::now(),
    )
    .await?;
    tx.commit().await?;

    tracing::info!(
        owner = %owner_user_id,
        tenant_id = %tenant,
        reply_class = %class,
        approvals = evidence.approved_and_sent,
        "reply class promoted to autonomous sending"
    );
    Ok(Json(serde_json::json!({
        "enabled": true,
        "tenantId": tenant,
        "replyClass": class.as_str(),
        "evidence": evidence,
    })))
}

/// Revoke one class (the per-class kill switch). Idempotent; the row and its
/// evidence snapshot stay on record.
async fn post_revoke(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(body): Json<RevokeRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    require_scopes(&auth, &["*"])?;
    require_system_tenant(&state, &auth).await?;
    let tenant = validate_tenant(&body.tenant_id)?;
    let class = parse_class(&body.reply_class)?;
    let owner_user_id = auth.user_id.clone().ok_or_else(|| {
        ApiError::Forbidden("revoking autonomy requires a signed-in owner".into())
    })?;

    let mut tx = state.db.begin().await?;
    let actor = OwnerActor::verify(&mut tx, &owner_user_id)
        .await
        .map_err(map_sales_error)?;
    let changed = reply_autosend::revoke(&mut tx, &tenant, class, &actor)
        .await
        .map_err(map_sales_error)?;

    crate::audit_log::insert_audit_log_in_tx_with_env(
        &mut tx,
        state.config.environment.is_production(),
        Some(auth.tenant_id.as_str()),
        auth.user_id.as_deref(),
        REVOKED_AUDIT_ACTION,
        "reply_autosend_grant",
        Some(&format!("{tenant}:{}", class.as_str())),
        serde_json::json!({
            "tenantId": tenant,
            "replyClass": class.as_str(),
            "changed": changed,
        }),
        None,
        None,
        chrono::Utc::now(),
    )
    .await?;
    tx.commit().await?;

    Ok(Json(serde_json::json!({
        "revoked": true,
        "changed": changed,
        "tenantId": tenant,
        "replyClass": class.as_str(),
    })))
}

/// Tenant ids are composed into audit details and grant rows: conservative
/// identifiers only.
fn validate_tenant(tenant: &str) -> Result<String, ApiError> {
    let trimmed = tenant.trim();
    let safe = !trimmed.is_empty()
        && trimmed.len() <= 64
        && trimmed
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_');
    if safe {
        Ok(trimmed.to_string())
    } else {
        Err(ApiError::Validation(vec!["invalid tenant id".into()]))
    }
}

/// Parse the class against the canonical set; unknown classes fail closed.
fn parse_class(raw: &str) -> Result<LowRiskClass, ApiError> {
    // The wire value must be exact: the persisted-string parser is forgiving
    // (a stored value may carry incidental whitespace), but a request that
    // names a class is refused rather than silently normalised.
    if raw.trim() != raw {
        return Err(ApiError::Validation(vec![
            "replyClass must be the exact canonical string (no surrounding whitespace)".into(),
        ]));
    }
    LowRiskClass::parse(raw).ok_or_else(|| {
        ApiError::Validation(vec![format!(
            "replyClass must be one of: {}",
            LowRiskClass::ALL
                .iter()
                .map(|class| class.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        )])
    })
}

#[cfg(test)]
mod promotion_tests {
    use super::*;
    use crate::app::test_support::adv::AdvEnv;
    use crate::app::test_support::test_state_over;
    use crate::routes::system_sender::{SYSTEM_DOMAIN, SYSTEM_DOMAIN_ID, SYSTEM_TENANT_ID};

    fn owner_auth(user_id: &str) -> AuthUser {
        AuthUser {
            tenant_id: "system".into(),
            user_id: Some(user_id.to_string()),
            api_key_id: None,
            session_id: Some("sess-f9-owner".into()),
            scopes: vec!["*".into()],
        }
    }

    async fn seed_user(pool: &sqlx::PgPool, email: &str, role: &str) -> String {
        sqlx::query(
            "INSERT INTO tenants (id, name, plan, status, created_at, updated_at) \
             VALUES ('system', 'System', 'free', 'active', NOW(), NOW()) \
             ON CONFLICT (id) DO NOTHING",
        )
        .execute(pool)
        .await
        .expect("seed system tenant");
        let id = uuid::Uuid::new_v4().to_string();
        sqlx::query(
            "INSERT INTO users (id, tenant_id, email, name, role, status, password_hash, email_verified) \
             VALUES ($1::uuid, 'system', $2, 'F9 Promotion Actor', $3, 'active', 'x', true) \
             ON CONFLICT (email) DO UPDATE SET role = EXCLUDED.role, id = EXCLUDED.id",
        )
        .bind(&id)
        .bind(email)
        .bind(role)
        .execute(pool)
        .await
        .expect("seed user");
        sqlx::query_scalar::<_, uuid::Uuid>("SELECT id FROM users WHERE email = $1")
            .bind(email)
            .fetch_one(pool)
            .await
            .expect("user id")
            .to_string()
    }

    async fn seed_system_sender(db: &sqlx::PgPool) {
        let key_pair = apexmail_lib::dkim::generate_dkim_keypair()
            .expect("test DKIM keypair generation must not fail");
        let aad = apexmail_lib::dkim::dkim_private_key_aad(SYSTEM_TENANT_ID, SYSTEM_DOMAIN_ID);
        let encrypted =
            apexmail_lib::dkim::encrypt_dkim_private_key(&key_pair.private_key_pem, &aad)
                .expect("test DKIM private key encryption must not fail");
        let public_key =
            apexmail_lib::dkim::public_key_base64_from_private_key_pem(&key_pair.private_key_pem)
                .expect("test DKIM public key derivation must not fail");
        sqlx::query(
            "INSERT INTO domains (id, tenant_id, name, status, verified, ses_verified,
                                  dkim_enabled, dkim_selector, dkim_public_key, dkim_private_key)
             VALUES ($1, $2, $3, 'verified', true, true, true, 'testsel', $4, $5)
             ON CONFLICT (tenant_id, lower(name)) DO UPDATE
               SET status = 'verified', verified = true, ses_verified = true,
                   dkim_enabled = true, dkim_selector = 'testsel',
                   dkim_public_key = EXCLUDED.dkim_public_key,
                   dkim_private_key = EXCLUDED.dkim_private_key",
        )
        .bind(uuid::Uuid::parse_str(SYSTEM_DOMAIN_ID).expect("system domain id"))
        .bind(SYSTEM_TENANT_ID)
        .bind(SYSTEM_DOMAIN)
        .bind(&public_key)
        .bind(&encrypted)
        .execute(db)
        .await
        .expect("seed system sender");
    }

    async fn grant_marketing_consent(pool: &sqlx::PgPool, tenant: &str, recipient: &str) {
        sqlx::query(
            "INSERT INTO consent_records \
                 (id, tenant_id, subscriber_id, email, consent_type, granted, granted_at, source) \
             VALUES ($1, $2, $3, $4, 'marketing', true, NOW(), 'f9-promotion-test') \
             ON CONFLICT (tenant_id, subscriber_id, consent_type) DO UPDATE SET \
                 granted = true, granted_at = NOW(), revoked_at = NULL, email = EXCLUDED.email",
        )
        .bind(uuid::Uuid::new_v4().to_string())
        .bind(tenant)
        .bind(format!(
            "sub-{tenant}-{}",
            &uuid::Uuid::new_v4().simple().to_string()[..8]
        ))
        .bind(recipient)
        .execute(pool)
        .await
        .expect("grant marketing consent");
    }

    async fn seed_scheduling_draft(pool: &sqlx::PgPool, id: &str, tenant: &str, recipient: &str) {
        sqlx::query(
            "INSERT INTO inbound_messages \
                 (id, tenant_id, from_email, subject, ai_response, pending_approval, \
                  is_verp_reply, received_at, classification, classification_confidence, \
                  processed, processed_at) \
             VALUES ($1, $2, $3, 'Re: demo', \
                     'Thursday 10:00 works for us, shall I send an invite?', \
                     true, false, NOW(), 'meeting_request', 0.95, true, NOW())",
        )
        .bind(id)
        .bind(tenant)
        .bind(recipient)
        .execute(pool)
        .await
        .expect("seed scheduling draft");
    }

    /// The promotion surface rides the owner-gated autopilot nest: the merge
    /// happens INSIDE the `.nest("/v1/admin/autopilot", …)` chunk that carries
    /// the `require_sales_owner` layer. Pinned structurally so a future
    /// refactor cannot quietly move the autonomy-promotion routes out of the
    /// owner boundary.
    #[test]
    fn promotion_routes_are_inside_the_owner_gated_autopilot_nest() {
        let source = include_str!("../../app.rs");
        let production = source.split("#[cfg(test)]").next().expect("production");
        let autopilot_chunk = production
            .split(".nest(")
            .find(|chunk| chunk.trim_start().starts_with("\"/v1/admin/autopilot\""))
            .expect("the owner-gated autopilot nest exists");
        assert!(
            autopilot_chunk.contains("reply_autosend::router()"),
            "the promotion router must be merged into the owner-gated autopilot nest"
        );
        assert!(
            autopilot_chunk.contains("require_sales_owner"),
            "the autopilot nest must keep its structural owner layer"
        );
    }

    /// Layer-level proof: with the owner gate as the only layer, a machine
    /// admin (the credential that passes every other `/v1/admin/*` gate) is
    /// refused on the promotion routes, and an anonymous probe never reaches
    /// them.
    #[tokio::test]
    async fn machine_and_anonymous_callers_never_reach_the_promotion_routes() {
        use axum::body::Body;
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;

        let db = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .connect_lazy("postgres://apexmail:apexmail@127.0.0.1:1/apexmail")
            .expect("lazy pool");
        let state = test_state_over(db).await;
        let router = crate::routes::admin::reply_autosend::router()
            .route_layer(axum::middleware::from_fn_with_state(
                state.clone(),
                crate::middleware::sales_owner::require_sales_owner,
            ))
            .with_state(state);

        let machine = crate::middleware::auth::AuthUser {
            tenant_id: "system".into(),
            user_id: None,
            api_key_id: Some("cp-machine-key".into()),
            session_id: None,
            scopes: vec!["*".into()],
        };
        for (path, method) in [
            ("/reply-autosend?tenant=ten_x", "GET"),
            ("/reply-autosend/enable", "POST"),
            ("/reply-autosend/revoke", "POST"),
        ] {
            let response = router
                .clone()
                .oneshot(
                    Request::builder()
                        .method(method)
                        .uri(path)
                        .header("content-type", "application/json")
                        .extension(machine.clone())
                        .body(Body::from("{}"))
                        .expect("request"),
                )
                .await
                .expect("oneshot");
            assert_eq!(
                response.status(),
                StatusCode::FORBIDDEN,
                "machine credential must be refused on {method} {path}"
            );
        }

        let response = router
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/reply-autosend/enable")
                    .header("content-type", "application/json")
                    .body(Body::from("{}"))
                    .expect("request"),
            )
            .await
            .expect("oneshot");
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    /// The evidence bar can only be satisfied by REAL recorded approvals:
    /// ten drafts released through the actual approval endpoint become the ten
    /// approvals that let the owner promote the class. Before them the
    /// enablement is refused (with the numbers), after them it succeeds and
    /// the captured evidence rides both the grant row and the audit record.
    #[test]
    fn real_recorded_approvals_are_the_only_evidence_that_promotes_a_class() {
        let _dkim_guard = crate::test_db::DKIM_ENV_MUTEX
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        std::env::set_var(
            apexmail_lib::dkim::DKIM_PRIVATE_KEY_ENCRYPTION_KEY_ENV,
            "3f7a1c9e2b5d48f01a6c3e792d4b8f15a0c6e3917d2f4b8a5c1e7309d4f2b6a8",
        );
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        runtime.block_on(async {
            let Some(pool) = crate::test_db::canonical_pool("f9_promotion").await else {
                return;
            };
            seed_system_sender(&pool).await;
            let env = AdvEnv::admin(pool.clone()).await;
            let tenant = format!(
                "ten_f9promo-{}",
                &uuid::Uuid::new_v4().simple().to_string()[..11]
            );
            let recipient = format!(
                "lead-{}@corp.example",
                &uuid::Uuid::new_v4().simple().to_string()[..8]
            );
            grant_marketing_consent(&pool, &tenant, &recipient).await;
            sqlx::query(
                "INSERT INTO sales_autonomy_state (tenant_id, mode) VALUES ($1, 'autonomous_guarded')",
            )
            .bind(&tenant)
            .execute(&pool)
            .await
            .expect("autonomy state");

            let admin = seed_user(&pool, "f9-promo-admin@apexmail.test", "admin").await;
            let owner = seed_user(&pool, "f9-promo-owner@apexmail.test", "owner").await;
            let state = test_state_over(pool.clone()).await;

            let enable = |actor: String, required: Option<i64>| {
                let state = state.clone();
                let tenant = tenant.clone();
                async move {
                    post_enable(
                        State(state),
                        owner_auth(&actor),
                        Json(EnableRequest {
                            tenant_id: tenant,
                            reply_class: "scheduling".into(),
                            required_approvals: required,
                            window_days: Some(30),
                        }),
                    )
                    .await
                }
            };

            // A live system ADMIN is not the owner: refused, nothing written.
            let refused = enable(admin.clone(), Some(10)).await;
            assert!(
                matches!(refused, Err(ApiError::Forbidden(_))),
                "an admin must not promote autonomy: {refused:?}"
            );
            let rows: i64 =
                sqlx::query_scalar("SELECT COUNT(*) FROM reply_autosend_grants")
                    .fetch_one(&pool)
                    .await
                    .expect("grant count");
            assert_eq!(rows, 0, "the refused promotion wrote nothing");

            // The owner, with no recorded approvals: refused with the numbers.
            let refused = enable(owner.clone(), Some(10)).await;
            match refused {
                Err(ApiError::Validation(messages)) => {
                    let joined = messages.join("; ");
                    assert!(
                        joined.contains("evidence not satisfied"),
                        "the refusal must name the evidence bar: {joined}"
                    );
                }
                other => panic!("expected the evidence refusal, got {other:?}"),
            }

            // Ten REAL approvals, driven through the human endpoint.
            for _ in 0..10 {
                let id = format!("inb_{}", &uuid::Uuid::new_v4().simple().to_string()[..22]);
                seed_scheduling_draft(&pool, &id, &tenant, &recipient).await;
                let (status, body) = env
                    .post(&format!("/v1/admin/ai/drafts/{id}/approve"), "{}")
                    .await;
                assert_eq!(status, axum::http::StatusCode::OK, "{body}");
            }

            // The owner now promotes the class: the evidence is derived from
            // those ten approval rows.
            let Json(body) = enable(owner.clone(), Some(10))
                .await
                .expect("the owner promotes with real evidence");
            assert_eq!(body["enabled"], true, "{body}");
            assert_eq!(body["replyClass"], "scheduling");
            assert_eq!(body["evidence"]["approved_and_sent"], 10, "{body}");
            assert_eq!(body["evidence"]["complaints_or_optouts"], 0, "{body}");
            assert_eq!(body["evidence"]["satisfied"], true, "{body}");

            let grant: (bool, Option<String>, serde_json::Value) = sqlx::query_as(
                "SELECT enabled, enabled_by, evidence_snapshot FROM reply_autosend_grants \
                 WHERE tenant_id = $1 AND reply_class = 'scheduling'",
            )
            .bind(&tenant)
            .fetch_one(&pool)
            .await
            .expect("grant row");
            assert!(grant.0);
            assert_eq!(grant.1.as_deref(), Some(owner.as_str()));
            assert_eq!(grant.2["approved_and_sent"], 10);

            // The promotion left its own actor-attributed audit record.
            let audit: (Option<String>, serde_json::Value) = sqlx::query_as(
                "SELECT user_id, details FROM audit_logs WHERE action = $1",
            )
            .bind(ENABLED_AUDIT_ACTION)
            .fetch_one(&pool)
            .await
            .expect("enable audit row");
            assert_eq!(audit.0.as_deref(), Some(owner.as_str()));
            assert_eq!(audit.1["tenantId"], tenant.as_str());
            assert_eq!(audit.1["evidence"]["approved_and_sent"], 10);

            // The status surface reports every class, defaulting the unpromoted
            // ones to OFF.
            let Json(status) = get_promotion_status(
                State(state.clone()),
                owner_auth(&owner),
                Query(TenantQuery {
                    tenant: tenant.clone(),
                }),
            )
            .await
            .expect("status");
            let classes = status["classes"].as_array().expect("classes").len();
            assert_eq!(classes, LowRiskClass::ALL.len());
            assert_eq!(status["classes"][0]["reply_class"], "acknowledgement");
            let scheduling = status["classes"]
                .as_array()
                .expect("classes")
                .iter()
                .find(|entry| entry["reply_class"] == "scheduling")
                .expect("scheduling entry");
            assert_eq!(scheduling["enabled"], true);
            let acknowledgement = status["classes"]
                .as_array()
                .expect("classes")
                .iter()
                .find(|entry| entry["reply_class"] == "acknowledgement")
                .expect("acknowledgement entry");
            assert_eq!(acknowledgement["enabled"], false, "default OFF");

            // Revocation: the per-class kill switch, audited.
            let Json(revoked) = post_revoke(
                State(state.clone()),
                owner_auth(&owner),
                Json(RevokeRequest {
                    tenant_id: tenant.clone(),
                    reply_class: "scheduling".into(),
                }),
            )
            .await
            .expect("revoke");
            assert_eq!(revoked["revoked"], true);
            assert_eq!(revoked["changed"], true);
            let grant: (bool, Option<String>) = sqlx::query_as(
                "SELECT enabled, disabled_by FROM reply_autosend_grants \
                 WHERE tenant_id = $1 AND reply_class = 'scheduling'",
            )
            .bind(&tenant)
            .fetch_one(&pool)
            .await
            .expect("grant row after revoke");
            assert!(!grant.0, "revocation switches the class off");
            assert_eq!(grant.1.as_deref(), Some(owner.as_str()));
            let revoke_audit: i64 =
                sqlx::query_scalar("SELECT COUNT(*) FROM audit_logs WHERE action = $1")
                    .bind(REVOKED_AUDIT_ACTION)
                    .fetch_one(&pool)
                    .await
                    .expect("revoke audit count");
            assert_eq!(revoke_audit, 1);

            // Unknown classes and malformed tenants are refused before any
            // storage work.
            for bad in ["autonomous_full", "", "scheduling "] {
                let refused = post_enable(
                    State(state.clone()),
                    owner_auth(&owner),
                    Json(EnableRequest {
                        tenant_id: tenant.clone(),
                        reply_class: bad.into(),
                        required_approvals: Some(10),
                        window_days: Some(30),
                    }),
                )
                .await;
                assert!(
                    matches!(refused, Err(ApiError::Validation(_))),
                    "class {bad:?} must be refused: {refused:?}"
                );
            }

            pool.close().await;
        });
    }
}
