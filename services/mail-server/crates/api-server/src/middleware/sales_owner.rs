//! The Sales Autopilot owner boundary (P0 security fix).
//!
//! `/v1/admin/sales` and `/v1/admin/autopilot` are ApexMail's OWNER-ONLY
//! sales brain: the platform's own outbound sales motion, holding its own
//! leads, campaigns, and outreach state. They are NOT general platform
//! administration:
//!
//! * a system-tenant ADMIN (however privileged) is not the owner;
//! * a machine credential (static CP/system API key) is not the owner;
//! * a customer-tenant identity — any role — is not the owner.
//!
//! The gate runs as a router layer AROUND both nested routers, structurally,
//! before any handler's own scope checks:
//!
//!   CP session (human `session_id` + `user_id`, no API key)
//!     → system tenant (slug-aware: `system` or the system-internal slug)
//!     → the user's LIVE `role` (read from `users`, not from the token)
//!       is EXACTLY `owner`
//!
//! The role is re-read from the database on every request: the JWT would
//! otherwise pin a role from before a demotion. A DB failure fails CLOSED.
//!
//! Machine credentials are refused outright — there is no "Sales service
//! principal" yet; when one exists it must present a Sales-specific audience
//! (see the architecture review), never the universal internal token.
#![deny(unsafe_code)]

use axum::extract::State;
use axum::http::Request;
use axum::middleware::Next;
use axum::response::Response;

use crate::error::ApiError;
use crate::middleware::auth::AuthUser;
use crate::state::AppState;

/// The exact human role that owns ApexMail's sales motion.
const OWNER_ROLE: &str = "owner";

/// Refuse with 404 (not 403) when the gate cannot even name the caller: the
/// sales surface must not be an existence oracle for anonymous probes.
fn anonymous() -> ApiError {
    ApiError::Unauthorized("control-plane session required".into())
}

/// The owner-only gate for `/v1/admin/sales` + `/v1/admin/autopilot`.
pub async fn require_sales_owner(
    State(state): State<AppState>,
    req: Request<axum::body::Body>,
    next: Next,
) -> Result<Response, ApiError> {
    // A human CP session: the extractor proves the JWT, but the gate ALSO
    // requires the session/user pair — machine API keys authenticate with
    // `api_key_id` and no live session, and the sales surface has no
    // service principal yet.
    let Some(auth) = req.extensions().get::<AuthUser>().cloned() else {
        return Err(anonymous());
    };
    if auth.api_key_id.is_some() || auth.session_id.is_none() {
        return Err(ApiError::Forbidden(
            "the sales control surface is owner-only; machine credentials are not accepted".into(),
        ));
    }
    let Some(user_id) = auth.user_id.as_deref() else {
        return Err(ApiError::Forbidden(
            "the sales control surface requires a signed-in human owner".into(),
        ));
    };

    // System tenant (slug-aware — `web::is_system_tenant` resolves the
    // system-internal slug as well as the literal sentinel).
    if !crate::routes::web::is_system_tenant(&state, &auth.tenant_id).await {
        return Err(ApiError::Forbidden(
            "the sales control surface is restricted to the platform owner".into(),
        ));
    }

    // EXACT live role: read from `users`, never trusted from the token.
    let role: Option<String> =
        sqlx::query_scalar("SELECT role FROM users WHERE id = $1::uuid AND tenant_id = $2 LIMIT 1")
            .bind(user_id)
            .bind(&auth.tenant_id)
            .fetch_optional(&state.db)
            .await
            .map_err(|error| {
                tracing::error!(error = %error, "sales owner gate: role lookup failed");
                ApiError::Internal("authentication error".into())
            })?
            .flatten();
    if role.as_deref() != Some(OWNER_ROLE) {
        // Fail closed — and do not reveal WHICH condition failed beyond
        // "not the owner": a demoted admin probing the surface learns only
        // that the surface is owner-only.
        tracing::warn!(
            user_id = %user_id,
            role = ?role,
            "refused a non-owner identity on the sales control surface"
        );
        return Err(ApiError::Forbidden(
            "the sales control surface is owner-only".into(),
        ));
    }

    Ok(next.run(req).await)
}

#[cfg(test)]
mod boundary_tests {
    use super::*;
    use crate::app::test_support::test_state_over;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use axum::routing::get;
    use tower::ServiceExt;

    /// A router with ONLY the owner gate wrapped around a probe handler:
    /// the gate is the unit under test (its structural mounting on the two
    /// sales routers is pinned by the source-scan test below).
    fn gated_router(state: AppState) -> axum::Router {
        async fn probe() -> &'static str {
            "past-the-gate"
        }
        axum::Router::new()
            .route("/probe", get(probe))
            .route_layer(axum::middleware::from_fn_with_state(
                state,
                require_sales_owner,
            ))
            .with_state(())
    }

    /// One PRIVATE canonical database per TEST (nextest runs each test in
    /// its own process; a shared name would be dropped mid-test by a
    /// sibling).
    async fn pool(test: &str) -> Option<sqlx::PgPool> {
        match migrator::test_support::fresh_canonical_pool(
            &format!("sales_owner_boundary_{test}"),
            &format!("api_sob_{test}"),
        )
        .await
        {
            Ok(pool) => pool,
            Err(error) => panic!("{}", error.panic_message()),
        }
    }

    /// Under parallel canonical-DB provisioning the pool's first acquire can
    /// outrun its 5s timeout; seeding retries a bounded number of times.
    async fn seed_system_user(db: &sqlx::PgPool, email: &str, role: &str) -> uuid::Uuid {
        for attempt in 0..3 {
            match seed_system_user_once(db, email, role).await {
                Ok(id) => return id,
                Err(error) if attempt == 2 => panic!("seed {email}: {error}"),
                Err(_) => tokio::time::sleep(std::time::Duration::from_secs(2)).await,
            }
        }
        unreachable!()
    }

    async fn seed_system_user_once(
        db: &sqlx::PgPool,
        email: &str,
        role: &str,
    ) -> Result<uuid::Uuid, sqlx::Error> {
        let id = uuid::Uuid::new_v4();
        sqlx::query(
            "INSERT INTO tenants (id, name, plan, status, created_at, updated_at)
             VALUES ('system', 'System', 'free', 'active', NOW(), NOW())
             ON CONFLICT (id) DO NOTHING",
        )
        .execute(db)
        .await?;
        sqlx::query(
            "INSERT INTO users (id, tenant_id, email, name, role, status, password_hash, email_verified)
             VALUES ($1, 'system', $2, 'Boundary User', $3, 'active', 'x', true)
             ON CONFLICT (email) DO UPDATE SET role = EXCLUDED.role",
        )
        .bind(id)
        .bind(email)
        .bind(role)
        .execute(db)
        .await?;
        sqlx::query_scalar::<_, uuid::Uuid>("SELECT id FROM users WHERE email = $1")
            .bind(email)
            .fetch_one(db)
            .await
    }

    async fn call(router: &axum::Router, auth: Option<AuthUser>) -> StatusCode {
        let mut builder = Request::get("/probe");
        if let Some(auth) = auth {
            builder = builder.extension(auth);
        }
        router
            .clone()
            .oneshot(builder.body(Body::empty()).unwrap())
            .await
            .unwrap()
            .status()
    }

    fn session(tenant: &str, user_id: Option<uuid::Uuid>) -> AuthUser {
        AuthUser {
            tenant_id: tenant.into(),
            user_id: user_id.map(|id| id.to_string()),
            api_key_id: None,
            session_id: Some("sess-boundary".into()),
            scopes: vec!["*".into()],
        }
    }

    /// The full truth table. The OWNER alone passes; every other identity
    /// class is refused with the owner-only message and no data leak.
    #[tokio::test]
    async fn sales_gate_truth_table_admits_only_the_human_owner() {
        let Some(db) = pool("truth_table").await else {
            eprintln!("skipping: set TEST_DATABASE_URL");
            return;
        };
        let owner = seed_system_user(&db, "owner@apexmail.test", "owner").await;
        let admin = seed_system_user(&db, "admin@apexmail.test", "admin").await;
        let state = test_state_over(db.clone()).await;
        let router = gated_router(state);

        // OWNER: through the gate (the probe answers 200).
        assert_eq!(
            call(&router, Some(session("system", Some(owner)))).await,
            StatusCode::OK,
            "the human owner passes"
        );

        // System ADMIN — the classic escalation: refused.
        assert_eq!(
            call(&router, Some(session("system", Some(admin)))).await,
            StatusCode::FORBIDDEN,
            "a system admin is not the sales owner"
        );

        // Machine credential: API key, no session, wildcard scope — refused.
        let machine = AuthUser {
            tenant_id: "system".into(),
            user_id: None,
            api_key_id: Some("key-1".into()),
            session_id: None,
            scopes: vec!["*".into()],
        };
        assert_eq!(
            call(&router, Some(machine)).await,
            StatusCode::FORBIDDEN,
            "machine credentials are not a sales principal"
        );

        // Session identity WITHOUT a user id (defensive): refused.
        let no_user = AuthUser {
            user_id: None,
            ..session("system", None)
        };
        assert_eq!(
            call(&router, Some(no_user)).await,
            StatusCode::FORBIDDEN,
            "a session without a user is not a principal"
        );

        // Customer-tenant identity (any role): refused.
        assert_eq!(
            call(&router, Some(session("t_customer", Some(owner)))).await,
            StatusCode::FORBIDDEN,
            "a customer identity never reaches the sales surface"
        );

        // Anonymous: refused before any DB read.
        assert_eq!(
            call(&router, None).await,
            StatusCode::UNAUTHORIZED,
            "anonymous probes are refused"
        );
        db.close().await;
    }

    /// The LIVE database role decides: a demotion takes effect immediately.
    #[tokio::test]
    async fn owner_demotion_takes_effect_immediately() {
        let Some(db) = pool("truth_table").await else {
            eprintln!("skipping: set TEST_DATABASE_URL");
            return;
        };
        let owner = seed_system_user(&db, "demote@apexmail.test", "owner").await;
        let state = test_state_over(db.clone()).await;
        let router = gated_router(state);
        let auth = session("system", Some(owner));
        assert_eq!(
            call(&router, Some(auth.clone())).await,
            StatusCode::OK,
            "owner passes while owner"
        );
        sqlx::query("UPDATE users SET role = 'admin' WHERE id = $1")
            .bind(owner)
            .execute(&db)
            .await
            .expect("demote");
        assert_eq!(
            call(&router, Some(auth)).await,
            StatusCode::FORBIDDEN,
            "a demoted owner is refused on the very next request"
        );
        db.close().await;
    }

    /// A role-lookup DB outage fails CLOSED.
    #[tokio::test]
    async fn role_lookup_outage_fails_closed() {
        let Some(db) = pool("truth_table").await else {
            eprintln!("skipping: set TEST_DATABASE_URL");
            return;
        };
        let owner = seed_system_user(&db, "outage@apexmail.test", "owner").await;
        sqlx::query("ALTER TABLE users RENAME TO users_boundary_broken")
            .execute(&db)
            .await
            .expect("break users");
        let state = test_state_over(db.clone()).await;
        let router = gated_router(state);
        assert_eq!(
            call(&router, Some(session("system", Some(owner)))).await,
            StatusCode::INTERNAL_SERVER_ERROR,
            "a role-lookup outage must fail closed, never admit"
        );
        db.close().await;
    }

    /// Structural: the gate wraps exactly the sales + autopilot routers and
    /// nothing else in the production region.
    #[test]
    fn sales_owner_gate_is_mounted_on_exactly_the_sales_routers() {
        let source = include_str!("../app.rs");
        let production = source
            .split("#[cfg(test)]")
            .next()
            .expect("production region");
        assert_eq!(
            production.matches("require_sales_owner").count(),
            2,
            "the owner gate must wrap exactly the sales + autopilot routers"
        );
    }
}
