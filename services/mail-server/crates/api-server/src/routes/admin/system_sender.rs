//! Operational control plane for the platform's own sender domain.
//!
//! This endpoint deliberately exposes only DNS instructions and readiness; the

use axum::extract::State;
use axum::routing::{get, post};
use axum::{Json, Router};

use crate::error::ApiError;
use crate::middleware::auth::{require_scopes, require_system_tenant, AuthUser};
use crate::routes::domains::{
    bootstrap_system_sender, system_sender_status, verify_domain_for_tenant_with_dns,
    SystemSenderStatus,
};
use crate::routes::system_sender::{SYSTEM_DOMAIN_ID, SYSTEM_TENANT_ID};
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/", get(status))
        .route("/bootstrap", post(bootstrap))
        .route("/verify", post(verify))
}

/// Actor-attributed audit for platform-sender control mutations (P2-2):
/// bootstrapping/verifying the platform's own sending domain changes what
/// mail the platform can sign and send — the operator who ordered it must
/// be on record.
async fn log_system_sender_audit(
    state: &AppState,
    auth: &AuthUser,
    action: &str,
    metadata: serde_json::Value,
) {
    crate::audit_log::insert_audit_log_best_effort_with_env(
        &state.db,
        state.config.environment.is_production(),
        Some(auth.tenant_id.as_str()),
        auth.user_id.as_deref(),
        action,
        "system_sender",
        Some(SYSTEM_DOMAIN_ID),
        metadata,
        None,
        None,
    )
    .await;
}

async fn status(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<Json<SystemSenderStatus>, ApiError> {
    require_scopes(&auth, &["*"])?;
    require_system_tenant(&state, &auth).await?;
    Ok(Json(system_sender_status(&state).await?))
}

async fn bootstrap(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<Json<SystemSenderStatus>, ApiError> {
    require_scopes(&auth, &["*"])?;
    require_system_tenant(&state, &auth).await?;
    let bootstrapped = bootstrap_system_sender(&state).await?;
    log_system_sender_audit(
        &state,
        &auth,
        "control_plane.system_sender.bootstrapped",
        serde_json::json!({ "domainId": bootstrapped.id }),
    )
    .await;
    Ok(Json(bootstrapped))
}

async fn verify(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<Json<SystemSenderStatus>, ApiError> {
    require_scopes(&auth, &["*"])?;
    require_system_tenant(&state, &auth).await?;
    let dns = crate::routes::domains::global_dns_lookup()?;
    verify_system_sender_with_dns(&state, &auth, dns).await
}

/// The verify route's core, with the DNS transport injected. Production
/// resolves the process-wide resolver (see [`verify`]); tests substitute a
/// deterministic backend so no adversarial route test performs real DNS I/O.
async fn verify_system_sender_with_dns<D: crate::routes::domains::VerificationDns>(
    state: &AppState,
    auth: &AuthUser,
    dns: &D,
) -> Result<Json<SystemSenderStatus>, ApiError> {
    let current_status = system_sender_status(state).await?;
    let _verification =
        verify_domain_for_tenant_with_dns(state, SYSTEM_TENANT_ID, &current_status.id, dns).await?;
    let verified = system_sender_status(state).await?;
    log_system_sender_audit(
        state,
        auth,
        "control_plane.system_sender.verified",
        serde_json::json!({ "domainId": verified.id, "status": verified.status }),
    )
    .await;
    Ok(Json(verified))
}

#[cfg(test)]
mod adversarial_tests {
    use super::*;
    use axum::http::StatusCode;

    use crate::app::test_support::adv::AdvEnv;

    /// All-DNS-failing backend: no SPF, no MX, no DKIM, no DMARC — the
    /// honest observation for an unverified platform sender, with zero
    /// network I/O.
    struct EmptyDns;

    impl crate::routes::domains::VerificationDns for EmptyDns {
        async fn lookup_spf(&self, _host: &str) -> Result<Option<dns_resolver::SpfRecord>, String> {
            Ok(None)
        }
        async fn lookup_mx(&self, _host: &str) -> Result<Vec<dns_resolver::MxRecord>, String> {
            Ok(Vec::new())
        }
        async fn lookup_dkim(
            &self,
            _selector: &str,
            _domain: &str,
        ) -> Result<Option<dns_resolver::DkimRecord>, String> {
            Ok(None)
        }
        async fn lookup_dmarc(
            &self,
            _domain: &str,
        ) -> Result<Option<dns_resolver::DmarcPolicy>, String> {
            Ok(None)
        }
    }

    const DKIM_TEST_KEY: &str = "3f7a1c9e2b5d48f01a6c3e792d4b8f15a0c6e3917d2f4b8a5c1e7309d4f2b6a8";

    /// The DKIM key env is process-global; hold the shared mutex and restore.
    struct DkimEnvGuard {
        previous: Option<String>,
        _guard: std::sync::MutexGuard<'static, ()>,
    }

    impl Drop for DkimEnvGuard {
        fn drop(&mut self) {
            match self.previous.take() {
                Some(value) => std::env::set_var(
                    apexmail_lib::dkim::DKIM_PRIVATE_KEY_ENCRYPTION_KEY_ENV,
                    value,
                ),
                None => {
                    std::env::remove_var(apexmail_lib::dkim::DKIM_PRIVATE_KEY_ENCRYPTION_KEY_ENV)
                }
            }
        }
    }

    fn lock_dkim_env() -> DkimEnvGuard {
        let guard = crate::test_db::DKIM_ENV_MUTEX
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let previous = std::env::var(apexmail_lib::dkim::DKIM_PRIVATE_KEY_ENCRYPTION_KEY_ENV).ok();
        std::env::set_var(
            apexmail_lib::dkim::DKIM_PRIVATE_KEY_ENCRYPTION_KEY_ENV,
            DKIM_TEST_KEY,
        );
        DkimEnvGuard {
            previous,
            _guard: guard,
        }
    }

    #[tokio::test]
    async fn status_before_bootstrap_is_service_unavailable() {
        let Some(pool) = crate::test_db::canonical_pool("syssender_absent").await else {
            return;
        };
        let env = AdvEnv::admin(pool.clone()).await;

        // The canonical seed already provisions the sender: status answers
        // 200 for it before any operator action in THIS deployment.
        let (status, body) = env.get("/v1/admin/system-sender").await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["id"], crate::routes::system_sender::SYSTEM_DOMAIN_ID);
        assert_eq!(body["domain"], "apexmail.ee");

        // With the domain row gone (never bootstrapped / removed), the
        // status route must say ServiceUnavailable and name the bootstrap
        // operation — never a raw 500.
        sqlx::query("DELETE FROM domains WHERE id = $1")
            .bind(uuid::Uuid::parse_str(crate::routes::system_sender::SYSTEM_DOMAIN_ID).unwrap())
            .execute(&pool)
            .await
            .expect("delete system domain");
        let (status, body) = env.get("/v1/admin/system-sender").await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
        assert!(body["error"]["message"]
            .as_str()
            .unwrap_or_default()
            .contains("bootstrap"));
    }

    #[tokio::test]
    async fn bootstrap_provisions_the_system_sender_and_is_idempotent() {
        let Some(pool) = crate::test_db::canonical_pool("syssender_boot").await else {
            return;
        };
        let _env_guard = lock_dkim_env();
        let env = AdvEnv::admin(pool.clone()).await;

        let (status, body) = env.post("/v1/admin/system-sender/bootstrap", "{}").await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["id"], crate::routes::system_sender::SYSTEM_DOMAIN_ID);
        assert_eq!(body["status"], "pending");
        assert_eq!(body["ready"], false);

        // The tenant row is the seeded system tenant (slug-aware identity).
        let (name, slug): (String, String) =
            sqlx::query_as("SELECT name, slug FROM tenants WHERE id = $1")
                .bind(crate::routes::system_sender::SYSTEM_TENANT_ID)
                .fetch_one(&pool)
                .await
                .expect("system tenant");
        assert_eq!(name, "ApexMail System");
        assert_eq!(slug, "system");

        // Second bootstrap converges without duplicating anything.
        let (status, body) = env.post("/v1/admin/system-sender/bootstrap", "{}").await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let domains: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM domains WHERE tenant_id = $1")
            .bind(crate::routes::system_sender::SYSTEM_TENANT_ID)
            .fetch_one(&pool)
            .await
            .expect("count");
        assert_eq!(domains, 1, "bootstrap must not duplicate the sender domain");

        // Status now answers 200 with the same identity.
        let (status, body) = env.get("/v1/admin/system-sender").await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["id"], crate::routes::system_sender::SYSTEM_DOMAIN_ID);
        // DNS instructions are present once DKIM material exists.
        assert!(!body["records"].as_array().unwrap_or(&Vec::new()).is_empty());

        // The mutation landed an actor-attributed audit entry.
        let action: String = sqlx::query_scalar(
            "SELECT action FROM audit_logs WHERE action = 'control_plane.system_sender.bootstrapped'",
        )
        .fetch_one(&pool)
        .await
        .expect("bootstrap audit row");
        assert_eq!(action, "control_plane.system_sender.bootstrapped");
    }

    #[tokio::test]
    async fn verify_with_empty_dns_reports_the_unverified_sender() {
        let Some(pool) = crate::test_db::canonical_pool("syssender_verify").await else {
            return;
        };
        let _env_guard = lock_dkim_env();
        let state = crate::app::test_support::test_state_over(pool.clone()).await;
        bootstrap_system_sender(&state)
            .await
            .expect("bootstrap for verify test");

        let auth = crate::middleware::auth::AuthUser {
            tenant_id: "system".into(),
            user_id: None,
            api_key_id: None,
            session_id: None,
            scopes: vec!["*".into()],
        };
        let verified = verify_system_sender_with_dns(&state, &auth, &EmptyDns)
            .await
            .expect("verify completes with empty DNS");
        // No records observed → still pending, never ready.
        assert_eq!(verified.status, "pending");
        assert!(!verified.ready);

        let action: String = sqlx::query_scalar(
            "SELECT action FROM audit_logs WHERE action = 'control_plane.system_sender.verified'",
        )
        .fetch_one(&pool)
        .await
        .expect("verify audit row");
        assert_eq!(action, "control_plane.system_sender.verified");
    }

    #[tokio::test]
    async fn all_routes_require_the_wildcard_scope() {
        let Some(pool) = crate::test_db::canonical_pool("syssender_scope").await else {
            return;
        };
        let _env_guard = lock_dkim_env();
        let key =
            crate::app::test_support::seed_api_key_for(&pool, "system", &["domains:read"]).await;
        let env = AdvEnv::over(pool.clone(), key).await;
        for uri in [
            "/v1/admin/system-sender",
            "/v1/admin/system-sender/bootstrap",
        ] {
            let (status, body) = env.get(uri).await;
            if uri.ends_with("bootstrap") {
                // POST below; the GET variant is a 405 on the real router.
                continue;
            }
            assert_eq!(status, StatusCode::FORBIDDEN, "{uri}: {body}");
        }
        let (status, body) = env.post("/v1/admin/system-sender/bootstrap", "{}").await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    }

    #[tokio::test]
    async fn all_routes_reject_customer_tenants() {
        let Some(pool) = crate::test_db::canonical_pool("syssender_tenant").await else {
            return;
        };
        let (env, _tenant) = AdvEnv::tenant(pool, &["*"]).await;
        let (status, body) = env.get("/v1/admin/system-sender").await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
        let (status, body) = env.post("/v1/admin/system-sender/bootstrap", "{}").await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    }
}
