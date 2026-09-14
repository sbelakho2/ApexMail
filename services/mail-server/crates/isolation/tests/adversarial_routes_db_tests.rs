//! Adversarial, DB- and Redis-backed integration tests for the isolation
//! service: tenant separation on every storage path, fail-closed encryption
//! and policy engines, audit hash-chain integrity, per-tenant rate limiting
//! and honest 4xx behaviour on the HTTP surface.
//!
//! Harness convention (workspace): the canonical schema is provisioned with
//! `migrator::test_support::fresh_canonical_pool`; a configured provisioning
//! failure panics, an unset `TEST_DATABASE_URL` soft-skips. Redis is taken
//! from `TEST_REDIS_URL` (unset → soft skip) and keys are namespaced with
//! per-test UUIDs so parallel tests cannot interfere.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::Router;
use deadpool_redis::Pool as RedisPool;
use isolation::audit::AuditService;
use isolation::config::{Config, IsolationLevel, QuotaConfig, SecurityConfig};
use isolation::data_isolation::DataIsolationService;
use isolation::encryption::EncryptionService;
use isolation::rate_limit::RateLimitService;
use isolation::routes::{create_router, AppState};
use isolation::tenant::TenantService;
use isolation::types::*;
use sqlx::PgPool;
use std::sync::Arc;
use tower::ServiceExt;
use zeroize::Zeroizing;

const INTERNAL_KEY: &str = "isolation-adversarial-internal-key";
const MASTER_KEY: &str = "adversarial-master-key-32-bytes!!";

/// One process-wide multi-thread runtime so the shared Postgres pool's
/// connections are never bound to a per-test runtime that shuts down.
fn test_runtime() -> &'static tokio::runtime::Runtime {
    use std::sync::OnceLock;
    static RT: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
    RT.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(4)
            .enable_all()
            .build()
            .expect("build test runtime")
    })
}

fn run<F: std::future::Future>(future: F) -> F::Output {
    test_runtime().block_on(future)
}

static SHARED: tokio::sync::OnceCell<Option<Harness>> = tokio::sync::OnceCell::const_new();

struct Harness {
    db: PgPool,
    redis: RedisPool,
    config: Config,
}

async fn harness() -> Option<&'static Harness> {
    SHARED
        .get_or_init(|| async { build_harness().await })
        .await
        .as_ref()
}

async fn build_harness() -> Option<Harness> {
    // `shared_canonical_db`: under nextest EVERY test runs in its own
    // PROCESS, so the process-wide `SHARED` OnceCell does not make these tests
    // share one harness — each one provisions. The destructive
    // `fresh_canonical_pool` DROPs and re-creates the same database name in
    // every process, so the tests were dropping each other's database
    // mid-run. The shared variant creates-if-absent under a cluster advisory
    // lock and reuses the existing complete canonical database.
    // A PRIVATE database PER PROCESS, like the HA suite: these tests assert
    // properties of the WHOLE table (the audit hash chain's integrity and
    // truncation detection), which only hold when nothing else is writing.
    // The suffix carries the pid, so each nextest process drops and
    // re-creates only its own database — race-free, and exclusive.
    let db = match migrator::test_support::fresh_canonical_pool(
        "isolation_adversarial",
        &format!("iso_routes_p{}", std::process::id()),
    )
    .await
    {
        Ok(db) => db,
        Err(error) => panic!("{}", error.panic_message()),
    };
    // Ok(None) only when TEST_DATABASE_URL is unset — soft-skip.
    let db = db?;
    let redis_url = std::env::var("TEST_REDIS_URL").ok()?;
    let redis = deadpool_redis::Config::from_url(redis_url)
        .create_pool(None)
        .expect("valid redis pool config");

    // A workspace-tenanted `emails` table is the table the RLS route names;
    // the canonical chain has no such relation (the isolation service owns
    // it in deployments that use the shared table).
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS emails (
            id TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
            workspace_id TEXT NOT NULL,
            subject TEXT,
            body TEXT,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )",
    )
    .execute(&db)
    .await
    .expect("create isolation-owned emails table");

    let mut config = Config::from_env();
    config.internal_api_key = INTERNAL_KEY.into();
    config.internal_api_keys = vec![INTERNAL_KEY.into()];
    config.security = security_config();
    Some(Harness { db, redis, config })
}

fn security_config() -> SecurityConfig {
    SecurityConfig {
        encryption_key: Zeroizing::new(MASTER_KEY.into()),
        data_key_rotation_days: 90,
        audit_retention_days: 365,
        session_timeout_minutes: 30,
    }
}

impl Harness {
    fn tenant(&self) -> TenantService {
        TenantService::new(self.db.clone(), self.config.clone())
    }

    fn audit(&self) -> AuditService {
        AuditService::new(self.db.clone(), self.config.security.clone())
    }

    fn rate_limit(&self) -> RateLimitService {
        RateLimitService::new(self.redis.clone())
    }

    fn encryption(&self) -> EncryptionService {
        EncryptionService::new(self.db.clone(), self.config.security.clone())
    }

    async fn isolation(&self) -> DataIsolationService {
        let mut service = DataIsolationService::new(self.db.clone());
        service.initialize().await.expect("policy load");
        service
    }

    async fn app(&self) -> Router {
        let isolation = self.isolation().await;
        self.app_with_isolation(isolation).await
    }

    async fn app_with_isolation(&self, isolation: DataIsolationService) -> Router {
        let state = Arc::new(AppState {
            tenant: self.tenant(),
            isolation,
            encryption: self.encryption(),
            rate_limit: self.rate_limit(),
            audit: self.audit(),
            config: self.config.clone(),
        });
        create_router(state)
    }
}

async fn call(
    app: &Router,
    method: &str,
    path: &str,
    token: Option<&str>,
    user: Option<&str>,
    claim: Option<&str>,
    body: Option<serde_json::Value>,
) -> (StatusCode, serde_json::Value) {
    let mut builder = Request::builder().method(method).uri(path);
    if let Some(token) = token {
        builder = builder.header("authorization", format!("Bearer {token}"));
    }
    if let Some(user) = user {
        builder = builder.header("x-user-id", user);
    }
    if let Some(claim) = claim {
        builder = builder.header("x-org-id", claim);
    }
    let request = match body {
        Some(value) => builder
            .header("content-type", "application/json")
            .body(Body::from(value.to_string()))
            .expect("request body"),
        None => builder.body(Body::empty()).expect("empty request"),
    };
    let response = app.clone().oneshot(request).await.expect("router response");
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap_or_default();
    let json = if bytes.is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null)
    };
    (status, json)
}

fn unique(prefix: &str) -> String {
    format!("{prefix}-{}", uuid::Uuid::new_v4().simple())
}

/// Create an organization through the real router and return its id.
async fn create_org(app: &Router, isolation_level: Option<&str>) -> String {
    let slug = unique("org");
    let body = serde_json::json!({
        "name": "Adversarial Org",
        "slug": slug,
        "billing_email": "billing@example.com",
        "owner_id": "owner-1",
        "isolation_level": isolation_level,
    });
    let (status, json) = call(
        app,
        "POST",
        "/organizations",
        Some(INTERNAL_KEY),
        None,
        None,
        Some(body),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "create org: {json}");
    json["id"].as_str().expect("org id").to_string()
}

async fn create_workspace(app: &Router, org_id: &str, slug: &str) -> String {
    let (status, json) = call(
        app,
        "POST",
        &format!("/organizations/{org_id}/workspaces"),
        Some(INTERNAL_KEY),
        Some("user-1"),
        None,
        Some(serde_json::json!({"name": "WS", "slug": slug})),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "create workspace: {json}");
    json["id"].as_str().expect("workspace id").to_string()
}

// ── Auth / claim gates ──────────────────────────────────────────────────

#[test]
fn health_is_open_but_every_tenant_route_requires_bearer() {
    run(async {
        let Some(h) = harness().await else { return };
        let app = h.app().await;

        let (status, _) = call(&app, "GET", "/health", None, None, None, None).await;
        assert_eq!(status, StatusCode::OK);

        // No token → 401 on every mutating/read tenant route, and nothing is
        // written.
        for (method, path) in [
            ("POST", "/organizations"),
            ("GET", "/organizations/anything"),
            ("PUT", "/organizations/anything"),
            ("POST", "/organizations/anything/suspend"),
            ("GET", "/organizations/anything/workspaces"),
            ("GET", "/workspaces/anything"),
            ("PUT", "/workspaces/anything"),
            ("DELETE", "/workspaces/anything"),
            ("POST", "/workspaces/anything/members"),
            ("GET", "/workspaces/anything/quota"),
            ("GET", "/workspaces/anything/rate-limit"),
            ("POST", "/workspaces/anything/rate-limit/reset"),
            ("POST", "/encryption/rotate/anything"),
            ("POST", "/isolation/check-access"),
            ("POST", "/isolation/migrate/anything"),
            ("POST", "/isolation/rls/anything"),
            ("GET", "/audit/query?organization_id=anything"),
            ("GET", "/audit/stats/anything"),
            ("GET", "/audit/export/anything"),
        ] {
            // JSON extractors run before the handler, so a body-carrying
            // method needs a parseable body to reach the auth check.
            let body = matches!(method, "POST" | "PUT").then(|| serde_json::json!({}));
            let (status, _) = call(&app, method, path, None, None, None, body).await;
            assert_eq!(
                status,
                StatusCode::UNAUTHORIZED,
                "{method} {path} without a bearer token must be 401"
            );
        }

        // Wrong token → 401; wrong scheme → 401.
        let (status, _) = call(
            &app,
            "GET",
            "/organizations/anything",
            Some("not-the-key"),
            None,
            None,
            None,
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        let builder = Request::builder()
            .method("GET")
            .uri("/organizations/anything")
            .header("authorization", "Basic dXNlcjpwYXNz");
        let response = app
            .clone()
            .oneshot(builder.body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        // A missing token must not create an organization. The slug is unique
        // so concurrent tests cannot perturb the count.
        let ghost_slug = unique("ghost");
        let (status, _) = call(
            &app,
            "POST",
            "/organizations",
            None,
            None,
            None,
            Some(serde_json::json!({
                "name": "Ghost", "slug": ghost_slug,
                "billing_email": "g@example.com", "owner_id": "o"
            })),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        let created: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM iso_organizations WHERE slug = $1")
                .bind(&ghost_slug)
                .fetch_one(&h.db)
                .await
                .unwrap();
        assert_eq!(created, 0, "a rejected write must change nothing");
    });
}

#[test]
fn org_claim_mismatch_blocks_cross_tenant_reads_and_writes() {
    run(async {
        let Some(h) = harness().await else { return };
        let app = h.app().await;

        let org_a = create_org(&app, None).await;
        let org_b = create_org(&app, None).await;
        let ws_b = create_workspace(&app, &org_b, &unique("ws")).await;

        // Claim A reading org B → 403.
        let (status, _) = call(
            &app,
            "GET",
            &format!("/organizations/{org_b}"),
            Some(INTERNAL_KEY),
            None,
            Some(&org_a),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "cross-org read must be 403");

        // Claim A renaming org B → 403 and the row is untouched.
        let (status, _) = call(
            &app,
            "PUT",
            &format!("/organizations/{org_b}"),
            Some(INTERNAL_KEY),
            None,
            Some(&org_a),
            Some(serde_json::json!({"name": "hijacked"})),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        let name: String = sqlx::query_scalar("SELECT name FROM iso_organizations WHERE id = $1")
            .bind(&org_b)
            .fetch_one(&h.db)
            .await
            .unwrap();
        assert_ne!(name, "hijacked", "rejected write must not apply");

        // Claim A suspending org B → 403, status unchanged.
        let (status, _) = call(
            &app,
            "POST",
            &format!("/organizations/{org_b}/suspend"),
            Some(INTERNAL_KEY),
            Some("attacker"),
            Some(&org_a),
            Some(serde_json::json!({"reason": "pwned"})),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        let status_b: String =
            sqlx::query_scalar("SELECT status FROM iso_organizations WHERE id = $1")
                .bind(&org_b)
                .fetch_one(&h.db)
                .await
                .unwrap();
        assert_eq!(status_b, "active");

        // Claim A reading/updating workspace B → 403; no member row is created.
        for (method, path, body) in [
            ("GET", format!("/workspaces/{ws_b}"), None),
            (
                "PUT",
                format!("/workspaces/{ws_b}"),
                Some(serde_json::json!({"name": "stolen"})),
            ),
            ("DELETE", format!("/workspaces/{ws_b}"), None),
            (
                "POST",
                format!("/workspaces/{ws_b}/members"),
                Some(serde_json::json!({"user_id": "intruder", "role": "admin"})),
            ),
            ("GET", format!("/workspaces/{ws_b}/quota"), None),
            ("GET", format!("/workspaces/{ws_b}/rate-limit"), None),
            ("POST", format!("/isolation/rls/{ws_b}"), None),
        ] {
            let (status, _) = call(
                &app,
                method,
                &path,
                Some(INTERNAL_KEY),
                Some("attacker"),
                Some(&org_a),
                body,
            )
            .await;
            assert_eq!(
                status,
                StatusCode::FORBIDDEN,
                "{method} {path} with a foreign org claim must be 403"
            );
        }
        let intruder: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM iso_workspace_members WHERE workspace_id = $1 AND user_id = 'intruder'",
        )
        .bind(&ws_b)
        .fetch_one(&h.db)
        .await
        .unwrap();
        assert_eq!(intruder, 0, "forbidden member add must not write a row");

        // The matching claim (case-insensitive) succeeds.
        let (status, _) = call(
            &app,
            "GET",
            &format!("/organizations/{org_b}"),
            Some(INTERNAL_KEY),
            None,
            Some(&org_b.to_uppercase()),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        // Unknown workspace with a claim → 404 (never a leak of another org's row).
        let (status, _) = call(
            &app,
            "GET",
            &format!("/workspaces/{}", unique("missing")),
            Some(INTERNAL_KEY),
            None,
            Some(&org_a),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    });
}

// ── Organization / workspace lifecycle ──────────────────────────────────

#[test]
fn organization_lifecycle_duplicate_slug_and_suspend_cascade() {
    run(async {
        let Some(h) = harness().await else { return };
        let app = h.app().await;

        let org = create_org(&app, None).await;

        // Duplicate slug → 400, and only one row exists.
        let slug: String = sqlx::query_scalar("SELECT slug FROM iso_organizations WHERE id = $1")
            .bind(&org)
            .fetch_one(&h.db)
            .await
            .unwrap();
        let (status, json) = call(
            &app,
            "POST",
            "/organizations",
            Some(INTERNAL_KEY),
            None,
            None,
            Some(serde_json::json!({
                "name": "Dup", "slug": slug,
                "billing_email": "d@example.com", "owner_id": "o"
            })),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "duplicate slug: {json}");

        // Unknown isolation level falls back to shared (never fails open to a
        // dedicated schema).
        let org2 = create_org(&app, Some("not-a-level")).await;
        let level: String =
            sqlx::query_scalar("SELECT isolation_level FROM iso_organizations WHERE id = $1")
                .bind(&org2)
                .fetch_one(&h.db)
                .await
                .unwrap();
        assert_eq!(level, "shared");

        // Malformed JSON / unknown fields → 4xx, never 500.
        let mut builder = Request::builder()
            .method("POST")
            .uri("/organizations")
            .header("authorization", format!("Bearer {INTERNAL_KEY}"))
            .header("content-type", "application/json");
        let response = app
            .clone()
            .oneshot(builder.body(Body::from("{not json")).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        builder = Request::builder()
            .method("POST")
            .uri("/organizations")
            .header("authorization", format!("Bearer {INTERNAL_KEY}"))
            .header("content-type", "application/json");
        let response = app
        .clone()
        .oneshot(
            builder
                .body(Body::from(
                    r#"{"name":"X","slug":"x","billing_email":"x@y.z","owner_id":"o","injected":1}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);

        // Update then read reflects the write (cache invalidated).
        let (status, json) = call(
            &app,
            "PUT",
            &format!("/organizations/{org}"),
            Some(INTERNAL_KEY),
            None,
            Some(&org),
            Some(serde_json::json!({"plan": "enterprise", "name": "Renamed"})),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{json}");
        let (status, json) = call(
            &app,
            "GET",
            &format!("/organizations/{org}"),
            Some(INTERNAL_KEY),
            None,
            Some(&org),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["plan"], "enterprise");
        assert_eq!(json["name"], "Renamed");

        // Suspend cascades to workspaces and stamps the audit metadata.
        let ws = create_workspace(&app, &org, &unique("ws")).await;
        let (status, _) = call(
            &app,
            "POST",
            &format!("/organizations/{org}/suspend"),
            Some(INTERNAL_KEY),
            Some("admin-1"),
            Some(&org),
            Some(serde_json::json!({"reason": "fraud"})),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let metadata: serde_json::Value =
            sqlx::query_scalar("SELECT metadata FROM iso_organizations WHERE id = $1")
                .bind(&org)
                .fetch_one(&h.db)
                .await
                .unwrap();
        assert_eq!(metadata["suspended_reason"], "fraud");
        assert_eq!(metadata["suspended_by"], "admin-1");
        let ws_status: String =
            sqlx::query_scalar("SELECT status FROM iso_workspaces WHERE id = $1")
                .bind(&ws)
                .fetch_one(&h.db)
                .await
                .unwrap();
        assert_eq!(ws_status, "suspended");

        // Suspend without x-user-id → 401 and no state change.
        let org3 = create_org(&app, None).await;
        let (status, _) = call(
            &app,
            "POST",
            &format!("/organizations/{org3}/suspend"),
            Some(INTERNAL_KEY),
            None,
            Some(&org3),
            Some(serde_json::json!({})),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        let status3: String =
            sqlx::query_scalar("SELECT status FROM iso_organizations WHERE id = $1")
                .bind(&org3)
                .fetch_one(&h.db)
                .await
                .unwrap();
        assert_eq!(status3, "active");
    });
}

#[test]
fn workspace_lifecycle_slug_scope_and_soft_delete_queue() {
    run(async {
        let Some(h) = harness().await else { return };
        let app = h.app().await;

        let org_a = create_org(&app, None).await;
        let org_b = create_org(&app, None).await;
        let slug = unique("shared-slug");

        let ws_a = create_workspace(&app, &org_a, &slug).await;
        // Same slug in a DIFFERENT org is allowed (uniqueness is per org).
        let ws_b = create_workspace(&app, &org_b, &slug).await;
        assert_ne!(ws_a, ws_b);

        // Duplicate slug in the same org → 400 and no second row.
        let (status, _) = call(
            &app,
            "POST",
            &format!("/organizations/{org_a}/workspaces"),
            Some(INTERNAL_KEY),
            Some("user-1"),
            None,
            Some(serde_json::json!({"name": "Dup", "slug": slug})),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        let count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM iso_workspaces WHERE organization_id = $1")
                .bind(&org_a)
                .fetch_one(&h.db)
                .await
                .unwrap();
        assert_eq!(count, 1);

        // List only returns this org's live workspaces.
        let ws_a2 = create_workspace(&app, &org_a, &unique("ws2")).await;
        let (status, json) = call(
            &app,
            "GET",
            &format!("/organizations/{org_a}/workspaces"),
            Some(INTERNAL_KEY),
            None,
            None,
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let listed: Vec<String> = json
            .as_array()
            .expect("workspace list")
            .iter()
            .filter_map(|w| w["id"].as_str().map(str::to_string))
            .collect();
        assert!(listed.contains(&ws_a) && listed.contains(&ws_a2));
        assert!(!listed.contains(&ws_b), "org B's workspace must not leak");

        // Unknown org for workspace listing → 404, not an empty-200 that hides
        // typos or probes.
        let missing_org = unique("no-org");
        let (status, json) = call(
            &app,
            "GET",
            &format!("/organizations/{missing_org}"),
            Some(INTERNAL_KEY),
            None,
            Some(&missing_org),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert!(json["error"].as_str().is_some());

        // Update + soft delete: deleted workspaces disappear from lists and get a
        // cleanup-queue row.
        let (status, json) = call(
            &app,
            "PUT",
            &format!("/workspaces/{ws_a2}"),
            Some(INTERNAL_KEY),
            None,
            None,
            Some(serde_json::json!({"name": "Renamed WS"})),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{json}");
        assert_eq!(json["name"], "Renamed WS");

        let (status, _) = call(
            &app,
            "DELETE",
            &format!("/workspaces/{ws_a2}"),
            Some(INTERNAL_KEY),
            Some("deleter"),
            None,
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let queued: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM iso_cleanup_queue WHERE workspace_id = $1")
                .bind(&ws_a2)
                .fetch_one(&h.db)
                .await
                .unwrap();
        assert_eq!(queued, 1, "soft delete must enqueue cleanup");
        let (_, json) = call(
            &app,
            "GET",
            &format!("/organizations/{org_a}/workspaces"),
            Some(INTERNAL_KEY),
            None,
            None,
            None,
        )
        .await;
        assert!(!json
            .as_array()
            .unwrap()
            .iter()
            .any(|w| w["id"] == ws_a2.as_str()));
        // Soft-deleted workspace is still readable by id (status deleted) but the
        // slug is free again for a new workspace.
        let (status, json) = call(
            &app,
            "GET",
            &format!("/workspaces/{ws_a2}"),
            Some(INTERNAL_KEY),
            None,
            None,
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["status"], "deleted");
    });
}

#[test]
fn workspace_membership_is_upserted_and_removable() {
    run(async {
        let Some(h) = harness().await else { return };
        let app = h.app().await;
        let org = create_org(&app, None).await;
        let ws = create_workspace(&app, &org, &unique("ws")).await;

        // Missing x-user-id (inviter) → 401.
        let (status, _) = call(
            &app,
            "POST",
            &format!("/workspaces/{ws}/members"),
            Some(INTERNAL_KEY),
            None,
            None,
            Some(serde_json::json!({"user_id": "u-2", "role": "admin"})),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);

        let (status, _) = call(
            &app,
            "POST",
            &format!("/workspaces/{ws}/members"),
            Some(INTERNAL_KEY),
            Some("inviter"),
            None,
            Some(serde_json::json!({"user_id": "u-2", "role": "admin"})),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);

        let (status, json) = call(
            &app,
            "GET",
            &format!("/workspaces/{ws}/members/u-2/access"),
            Some(INTERNAL_KEY),
            None,
            None,
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["has_access"], true);
        assert_eq!(json["role"], "admin");

        // Re-adding upserts the role (no duplicate rows).
        let (status, _) = call(
            &app,
            "POST",
            &format!("/workspaces/{ws}/members"),
            Some(INTERNAL_KEY),
            Some("inviter"),
            None,
            Some(serde_json::json!({"user_id": "u-2", "role": "viewer"})),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        let rows: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM iso_workspace_members WHERE workspace_id = $1 AND user_id = 'u-2'",
    )
    .bind(&ws)
    .fetch_one(&h.db)
    .await
    .unwrap();
        assert_eq!(rows, 1, "membership upsert must not duplicate");
        let role: String = sqlx::query_scalar(
            "SELECT role FROM iso_workspace_members WHERE workspace_id = $1 AND user_id = 'u-2'",
        )
        .bind(&ws)
        .fetch_one(&h.db)
        .await
        .unwrap();
        assert_eq!(role, "viewer");

        // An unrecognised role falls back to the least-privileged member (never
        // silently to admin).
        let (status, _) = call(
            &app,
            "POST",
            &format!("/workspaces/{ws}/members"),
            Some(INTERNAL_KEY),
            Some("inviter"),
            None,
            Some(serde_json::json!({"user_id": "u-3", "role": "super-duper-admin"})),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        let role: String = sqlx::query_scalar(
            "SELECT role FROM iso_workspace_members WHERE workspace_id = $1 AND user_id = 'u-3'",
        )
        .bind(&ws)
        .fetch_one(&h.db)
        .await
        .unwrap();
        assert_eq!(role, "member");

        // Remove → access denied, including for a foreign workspace probe.
        let (status, _) = call(
            &app,
            "DELETE",
            &format!("/workspaces/{ws}/members/u-2"),
            Some(INTERNAL_KEY),
            None,
            None,
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let (_, json) = call(
            &app,
            "GET",
            &format!("/workspaces/{ws}/members/u-2/access"),
            Some(INTERNAL_KEY),
            None,
            None,
            None,
        )
        .await;
        assert_eq!(json["has_access"], false);
        assert!(json["role"].is_null());

        // Unknown workspace member lookup stays within the known schema.
        let (status, _) = call(
            &app,
            "GET",
            &format!("/workspaces/{ws}/members/never-added/access"),
            Some(INTERNAL_KEY),
            None,
            None,
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
    });
}

// ── Quota ───────────────────────────────────────────────────────────────

#[test]
fn quota_boundaries_and_atomic_usage_increments_are_per_workspace() {
    run(async {
        let Some(h) = harness().await else { return };
        let app = h.app().await;
        let org = create_org(&app, None).await;
        let ws = create_workspace(&app, &org, &unique("ws")).await;
        let other = create_workspace(&app, &org, &unique("ws")).await;

        // Set a tight quota through the route.
        let (status, _) = call(
            &app,
            "PUT",
            &format!("/workspaces/{ws}/quota"),
            Some(INTERNAL_KEY),
            None,
            None,
            Some(serde_json::json!({
                "emails_per_month": 10,
                "contacts_limit": 2,
            })),
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        let (status, json) = call(
            &app,
            "GET",
            &format!("/workspaces/{ws}/quota"),
            Some(INTERNAL_KEY),
            None,
            None,
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["emails_per_month"], true);
        assert_eq!(json["contacts"], true);
        assert_eq!(json["templates"], true);

        // Boundary: usage + amount <= limit. 9 + 1 allowed, 10 + 1 refused.
        let tenant = h.tenant();
        for _ in 0..9 {
            tenant
                .increment_usage(&ws, "emails_sent_this_month", 1)
                .await
                .unwrap();
        }
        assert!(tenant
            .check_quota(&ws, "emails_per_month", 1)
            .await
            .unwrap());
        tenant
            .increment_usage(&ws, "emails_sent_this_month", 1)
            .await
            .unwrap();
        assert!(!tenant
            .check_quota(&ws, "emails_per_month", 1)
            .await
            .unwrap());
        assert!(tenant
            .check_quota(&ws, "emails_per_month", 0)
            .await
            .unwrap());

        // Concurrent increments are not lost (atomic jsonb_set).
        let mut handles = Vec::new();
        for _ in 0..8 {
            let tenant_ref = h.tenant();
            let ws_id = ws.clone();
            handles.push(tokio::spawn(async move {
                tenant_ref
                    .increment_usage(&ws_id, "emails_sent_this_month", 1)
                    .await
                    .unwrap();
            }));
        }
        for handle in handles {
            handle.await.unwrap();
        }
        let used: i64 = sqlx::query_scalar(
            "SELECT (usage->>'emails_sent_this_month')::bigint FROM iso_workspaces WHERE id = $1",
        )
        .bind(&ws)
        .fetch_one(&h.db)
        .await
        .unwrap();
        assert_eq!(used, 18, "8 concurrent increments must all land");

        // The other workspace's usage is untouched (per-tenant accounting).
        let other_used: i64 = sqlx::query_scalar(
            "SELECT (usage->>'emails_sent_this_month')::bigint FROM iso_workspaces WHERE id = $1",
        )
        .bind(&other)
        .fetch_one(&h.db)
        .await
        .unwrap();
        assert_eq!(other_used, 0);

        // Unknown metrics are refused, not silently dropped. `emails_per_month`
        // is a QUOTA metric, not a usage field: incrementing it must be refused.
        assert!(tenant
            .increment_usage(&ws, "emails_per_month", 1)
            .await
            .is_err());
        assert!(tenant
            .increment_usage(&ws, "workspace_id = $1", 1)
            .await
            .is_err());
        assert!(tenant.check_quota(&ws, "leaked_metric", 1).await.is_err());
        // Unknown workspace is an error, not a default allow.
        assert!(tenant
            .check_quota("no-such-ws", "emails_per_month", 0)
            .await
            .is_err());
    });
}

// ── Rate limiting ───────────────────────────────────────────────────────

#[test]
fn rate_limits_are_per_tenant_and_reset_is_scope_locked() {
    run(async {
        let Some(h) = harness().await else { return };
        let app = h.app().await;
        let org = create_org(&app, None).await;
        let ws_a = create_workspace(&app, &org, &unique("rl")).await;
        let ws_b = create_workspace(&app, &org, &unique("rl")).await;
        let rate = h.rate_limit();

        let quota = QuotaConfig {
            api_requests_per_minute: 3,
            ..QuotaConfig::default()
        };

        // Third request allowed, fourth refused.
        for i in 0..3 {
            let result = rate
                .check_workspace_quota(&ws_a, "api_requests_per_minute", &quota, 1)
                .await
                .expect("redis reachable");
            assert!(result.allowed, "request {i} within quota must pass");
        }
        let denied = rate
            .check_workspace_quota(&ws_a, "api_requests_per_minute", &quota, 1)
            .await
            .expect("redis reachable");
        assert!(!denied.allowed, "request 4 must be rate limited");
        assert_eq!(denied.retry_after, Some(60));

        // Tenant B is unaffected by tenant A's exhausted window.
        let b_first = rate
            .check_workspace_quota(&ws_b, "api_requests_per_minute", &quota, 1)
            .await
            .unwrap();
        assert!(b_first.allowed, "rate limits must be per-tenant");

        // Status endpoint reads the SAME key enforcement wrote.
        let (status, json) = call(
            &app,
            "GET",
            &format!("/workspaces/{ws_a}/rate-limit"),
            Some(INTERNAL_KEY),
            None,
            None,
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{json}");
        // The status endpoint's informational window is 100 req/min; enforcement
        // wrote 3 entries into the SAME key, so 97 remain.
        assert_eq!(json["remaining"], 97);

        // Reset with a foreign key is refused and does not clear A's window.
        let (status, _) = call(
            &app,
            "POST",
            &format!("/workspaces/{ws_a}/rate-limit/reset"),
            Some(INTERNAL_KEY),
            None,
            None,
            Some(serde_json::json!({"key": format!("workspace:api:{ws_b}:api")})),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        let still_denied = rate
            .check_workspace_quota(&ws_a, "api_requests_per_minute", &quota, 1)
            .await
            .unwrap();
        assert!(
            !still_denied.allowed,
            "foreign reset must not clear the key"
        );

        // Own key → reset works.
        let (status, _) = call(
            &app,
            "POST",
            &format!("/workspaces/{ws_a}/rate-limit/reset"),
            Some(INTERNAL_KEY),
            None,
            None,
            Some(serde_json::json!({"key": format!("workspace:api:{ws_a}:api")})),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let after_reset = rate
            .check_workspace_quota(&ws_a, "api_requests_per_minute", &quota, 1)
            .await
            .unwrap();
        assert!(after_reset.allowed, "own reset must clear the window");

        // Token bucket and resource limits behave per workspace too.
        let bucket = TokenBucketConfig {
            capacity: 2,
            refill_rate: 1.0,
            refill_interval_ms: 60_000,
        };
        assert!(
            rate.check_token_bucket(&unique("bucket-a"), &bucket, 1)
                .await
                .unwrap()
                .allowed
        );
        // Resource counters are namespaced per workspace and clamp at the limit.
        let resource_quota = QuotaConfig {
            contacts_limit: 2,
            ..QuotaConfig::default()
        };
        let resource_ws = unique("resource-ws");
        assert!(
            rate.check_workspace_quota(&resource_ws, "contacts", &resource_quota, 1)
                .await
                .unwrap()
                .allowed
        );
        assert!(
            !rate
                .check_workspace_quota(&resource_ws, "contacts", &resource_quota, 2)
                .await
                .unwrap()
                .allowed
        );
        assert!(
            rate.check_workspace_quota(&unique("other-ws"), "contacts", &resource_quota, 2)
                .await
                .unwrap()
                .allowed
        );
    });
}

#[test]
fn rate_limiter_unavailable_fails_closed() {
    run(async {
        let Some(h) = harness().await else { return };
        // Point at a dead port: the limiter must error, never return "allowed".
        let dead = deadpool_redis::Config::from_url("redis://127.0.0.1:1")
            .create_pool(None)
            .expect("pool config");
        let rate = RateLimitService::new(dead);
        let quota = QuotaConfig::default();

        let result = rate
            .check_workspace_quota("ws-dead", "api_requests_per_minute", &quota, 1)
            .await;
        assert!(result.is_err(), "an unavailable limiter must fail closed");
        assert!(rate
            .check_rate_limit(
                "k",
                &RateLimitConfig {
                    window_ms: 1000,
                    max_requests: 1,
                    burst_limit: None,
                    key_prefix: None,
                }
            )
            .await
            .is_err());

        // HTTP surface: the status endpoint returns 5xx, not an `allowed: true`.
        let state = Arc::new(AppState {
            tenant: h.tenant(),
            isolation: h.isolation().await,
            encryption: h.encryption(),
            rate_limit: RateLimitService::new(
                deadpool_redis::Config::from_url("redis://127.0.0.1:1")
                    .create_pool(None)
                    .unwrap(),
            ),
            audit: h.audit(),
            config: h.config.clone(),
        });
        let app = create_router(state);
        let (status, json) = call(
            &app,
            "GET",
            &format!("/workspaces/{}/rate-limit", unique("ws")),
            Some(INTERNAL_KEY),
            None,
            None,
            None,
        )
        .await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert!(json.get("allowed").is_none());
    });
}

// ── Encryption ──────────────────────────────────────────────────────────

#[test]
fn encryption_round_trip_is_tenant_bound_and_rejects_tampering() {
    run(async {
        let Some(h) = harness().await else { return };
        let app = h.app().await;
        let org_a = create_org(&app, None).await;
        let org_b = create_org(&app, None).await;

        let encryption = h.encryption();
        encryption.initialize().await.expect("encryption init");

        let field = encryption
            .encrypt(&org_a, "top-secret-value")
            .await
            .expect("encrypt");
        assert_ne!(field.ciphertext, "top-secret-value");
        assert_eq!(field.algorithm, "aes-256-gcm");
        let plain = encryption
            .decrypt(&field, &org_a)
            .await
            .expect("decrypt own ciphertext");
        assert_eq!(plain, "top-secret-value");

        // Cross-tenant decryption is refused by key ownership.
        let error = encryption
            .decrypt(&field, &org_b)
            .await
            .expect_err("cross-tenant decrypt must fail");
        assert!(
            error.to_string().contains("does not belong"),
            "unexpected error: {error}"
        );

        // Every single-field tamper is detected by AEAD.
        let tamper = |mutate: &dyn Fn(&mut EncryptedField)| {
            let mut t = field.clone();
            mutate(&mut t);
            t
        };
        for tampered in [
            tamper(&|f| {
                let mut bytes = base64_decode(&f.ciphertext);
                *bytes.last_mut().unwrap() ^= 0x01;
                f.ciphertext = base64_encode(&bytes);
            }),
            tamper(&|f| {
                let mut bytes = base64_decode(&f.iv);
                bytes[0] ^= 0xFF;
                f.iv = base64_encode(&bytes);
            }),
            tamper(&|f| {
                let mut bytes = base64_decode(&f.auth_tag);
                bytes[0] ^= 0xFF;
                f.auth_tag = base64_encode(&bytes);
            }),
            tamper(&|f| f.ciphertext = base64_encode(b"short")),
            tamper(&|f| f.auth_tag = "not-base64!!".into()),
            tamper(&|f| f.iv = "AAAA".into()),
        ] {
            assert!(
                encryption.decrypt(&tampered, &org_a).await.is_err(),
                "tampered ciphertext must fail closed"
            );
        }

        // Splicing another tenant's key_id onto the ciphertext is refused.
        let other_field = encryption.encrypt(&org_b, "b-value").await.unwrap();
        let mut spliced = field.clone();
        spliced.key_id = other_field.key_id.clone();
        assert!(encryption.decrypt(&spliced, &org_a).await.is_err());

        // Unknown key id is an error, not a fallback to another key.
        let mut unknown = field.clone();
        unknown.key_id = uuid::Uuid::new_v4().to_string();
        assert!(encryption.decrypt(&unknown, &org_a).await.is_err());

        // A different master key cannot read the ciphertext.
        let foreign = EncryptionService::new(
            h.db.clone(),
            SecurityConfig {
                encryption_key: Zeroizing::new("a-completely-different-master-key".into()),
                ..security_config()
            },
        );
        assert!(foreign.decrypt(&field, &org_a).await.is_err());

        // A MISSING master key refuses outright: no plaintext passthrough.
        let missing = EncryptionService::new(
            h.db.clone(),
            SecurityConfig {
                encryption_key: Zeroizing::new(String::new()),
                ..security_config()
            },
        );
        assert!(
            missing.encrypt(&org_a, "must-not-be-stored").await.is_err(),
            "an unconfigured master key must refuse to encrypt"
        );
        assert!(
            missing.decrypt(&field, &org_a).await.is_err(),
            "an unconfigured master key must refuse to decrypt"
        );

        // Key rotation: the route rotates, old ciphertext stays decryptable and
        // new ciphertext uses the new key.
        let (status, json) = call(
            &app,
            "POST",
            &format!("/encryption/rotate/{org_a}"),
            Some(INTERNAL_KEY),
            None,
            Some(&org_a),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{json}");
        let new_key_id = json["key_id"].as_str().expect("rotated key id");
        assert_ne!(new_key_id, field.key_id);
        let still_plain = encryption.decrypt(&field, &org_a).await.unwrap();
        assert_eq!(still_plain, "top-secret-value");

        // Rotation of a foreign org under a mismatching claim is refused.
        let (status, _) = call(
            &app,
            "POST",
            &format!("/encryption/rotate/{org_b}"),
            Some(INTERNAL_KEY),
            None,
            Some(&org_a),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);

        // Policy-driven object encryption: only configured fields are wrapped,
        // and policy creation for an unknown org → 404.
        let (status, _) = call(
            &app,
            "POST",
            "/encryption/policy",
            Some(INTERNAL_KEY),
            None,
            None,
            Some(serde_json::json!({
                "organization_id": unique("missing-org"),
                "table_name": unique("table"),
                "fields": ["email"]
            })),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);

        let resource = unique("contacts");
        let (status, json) = call(
            &app,
            "POST",
            "/encryption/policy",
            Some(INTERNAL_KEY),
            None,
            None,
            Some(serde_json::json!({
                "organization_id": org_a,
                "table_name": resource,
                "fields": ["email"]
            })),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{json}");

        let encryption = h.encryption();
        encryption.initialize().await.unwrap();
        let object = serde_json::json!({"email": "a@b.c", "name": "visible"});
        let encrypted_object = encryption
            .encrypt_object(&org_a, &resource, &object)
            .await
            .unwrap();
        assert!(encrypted_object["email"]["ciphertext"].is_string());
        assert_eq!(encrypted_object["name"], "visible");
        let decrypted_object = encryption
            .decrypt_object(&resource, &encrypted_object, &org_a)
            .await
            .unwrap();
        assert_eq!(decrypted_object["email"], "a@b.c");
        // The other tenant cannot unwrap the object.
        assert!(encryption
            .decrypt_object(&resource, &encrypted_object, &org_b)
            .await
            .is_err());
    });
}

fn base64_decode(value: &str) -> Vec<u8> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(value)
        .expect("valid base64")
}

fn base64_encode(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

// ── Audit ───────────────────────────────────────────────────────────────

#[test]
fn audit_chain_detects_tamper_fork_and_truncation() {
    run(async {
        let Some(h) = harness().await else { return };
        let app = h.app().await;
        let org = create_org(&app, None).await;
        let ws = create_workspace(&app, &org, &unique("ws")).await;

        let audit = h.audit();
        for i in 0..3 {
            let event = audit.create_event(
                &org,
                Some(&ws),
                AuditEventType::DataRead,
                AuditSeverity::Info,
                "actor-1",
                "user",
                Some("emails"),
                None,
                &format!("read-{i}"),
                serde_json::json!({"seq": i}),
            );
            audit.log(event).await.expect("buffer event");
        }
        // Critical events force an immediate flush of the whole buffer.
        audit
            .log(audit.create_event(
                &org,
                None,
                AuditEventType::SecurityAccessDenied,
                AuditSeverity::Critical,
                "actor-2",
                "system",
                None,
                None,
                "denied",
                serde_json::json!({"seq": "critical"}),
            ))
            .await
            .expect("flush critical");

        let result = audit
            .verify_hash_chain(&org, None, None)
            .await
            .expect("verify");
        assert!(result.valid, "freshly written chain must verify");
        assert_eq!(result.entries_checked, 4);
        assert!(result.broken_at.is_none());

        // Reordering rows in time (tampered created_at) does not break the
        // hash-linked traversal — the chain is order independent by design.
        sqlx::query("UPDATE iso_audit_logs SET created_at = created_at + interval '1 hour' WHERE organization_id = $1 AND action = 'read-0'")
        .bind(&org)
        .execute(&h.db)
        .await
        .unwrap();
        assert!(
            audit
                .verify_hash_chain(&org, None, None)
                .await
                .unwrap()
                .valid
        );

        // Tampering with a row body without re-signing is detected.
        sqlx::query("UPDATE iso_audit_logs SET details = '{\"seq\":\"forged\"}' WHERE organization_id = $1 AND action = 'read-1'")
        .bind(&org)
        .execute(&h.db)
        .await
        .unwrap();
        let tampered = audit.verify_hash_chain(&org, None, None).await.unwrap();
        assert!(!tampered.valid, "tampered row must invalidate the chain");
        assert!(tampered.broken_at.is_some());
        // Restore the row.
        sqlx::query("UPDATE iso_audit_logs SET details = '{\"seq\":1}' WHERE organization_id = $1 AND action = 'read-1'")
        .bind(&org)
        .execute(&h.db)
        .await
        .unwrap();
        assert!(
            audit
                .verify_hash_chain(&org, None, None)
                .await
                .unwrap()
                .valid
        );

        // Splicing a wrong previous_hash (chain re-parenting / fork) is detected.
        let original_prev: String = sqlx::query_scalar(
        "SELECT metadata->>'previous_hash' FROM iso_audit_logs WHERE organization_id=$1 AND action='read-2'",
    )
    .bind(&org)
    .fetch_one(&h.db)
    .await
    .unwrap();
        sqlx::query("UPDATE iso_audit_logs SET metadata = jsonb_set(metadata, '{previous_hash}', '\"forged-parent\"') WHERE organization_id=$1 AND action='read-2'")
        .bind(&org)
        .execute(&h.db)
        .await
        .unwrap();
        assert!(
            !audit
                .verify_hash_chain(&org, None, None)
                .await
                .unwrap()
                .valid,
            "re-parented row must invalidate the chain"
        );
        sqlx::query("UPDATE iso_audit_logs SET metadata = jsonb_set(metadata, '{previous_hash}', $2::jsonb) WHERE organization_id=$1 AND action='read-2'")
        .bind(&org)
        .bind(serde_json::json!(original_prev).to_string())
        .execute(&h.db)
        .await
        .unwrap();
        assert!(
            audit
                .verify_hash_chain(&org, None, None)
                .await
                .unwrap()
                .valid
        );

        // Deleting an interior row (truncation) breaks the links and is detected.
        sqlx::query("DELETE FROM iso_audit_logs WHERE organization_id=$1 AND action='read-1'")
            .bind(&org)
            .execute(&h.db)
            .await
            .unwrap();
        let truncated = audit.verify_hash_chain(&org, None, None).await.unwrap();
        assert!(
            !truncated.valid,
            "a deleted interior row must be reported as a broken chain"
        );
        // Windowed verification (explicit start) still tolerates the boundary:
        // rows whose parent lies before the window are legitimate start points.
        let windowed = audit
            .verify_hash_chain(
                &org,
                Some(chrono::Utc::now() - chrono::Duration::hours(1)),
                None,
            )
            .await
            .unwrap();
        assert!(windowed.entries_checked <= 3);

        // The chain of an organization the caller cannot see is separate.
        let other = create_org(&app, None).await;
        let other_result = audit.verify_hash_chain(&other, None, None).await.unwrap();
        assert!(other_result.valid);
        assert_eq!(other_result.entries_checked, 0);

        // Per-tenant query is scoped: org B never sees org A's events.
        let query = AuditQuery {
            organization_id: org.clone(),
            limit: Some(2),
            ..Default::default()
        };
        let (events, total) = audit.query(&query).await.unwrap();
        assert_eq!(total, 3);
        assert_eq!(events.len(), 2);
        assert!(events.iter().all(|e| e.organization_id == org));

        // Retention cleanup only removes rows older than the window.
        sqlx::query("UPDATE iso_audit_logs SET created_at = NOW() - INTERVAL '400 days' WHERE organization_id=$1 AND action='read-0'")
        .bind(&org)
        .execute(&h.db)
        .await
        .unwrap();
        let deleted = audit.cleanup().await.unwrap();
        assert_eq!(deleted, 1, "only the out-of-retention row is purged");
    });
}

#[test]
fn audit_query_filters_pagination_and_exports_are_org_scoped() {
    run(async {
        let Some(h) = harness().await else { return };
        let app = h.app().await;
        let org_a = create_org(&app, None).await;
        let org_b = create_org(&app, None).await;
        let ws = create_workspace(&app, &org_a, &unique("ws")).await;

        let audit = h.audit();
        for (actor, severity) in [
            ("alice", AuditSeverity::Info),
            ("bob", AuditSeverity::Warning),
            ("alice", AuditSeverity::Critical),
        ] {
            audit
                .log(audit.create_event(
                    &org_a,
                    Some(&ws),
                    AuditEventType::DataRead,
                    severity,
                    actor,
                    "user",
                    Some("contacts"),
                    None,
                    "read",
                    serde_json::json!({}),
                ))
                .await
                .unwrap();
        }
        audit
            .log(audit.create_event(
                &org_b,
                None,
                AuditEventType::DataRead,
                AuditSeverity::Info,
                "alice",
                "user",
                Some("contacts"),
                None,
                "read",
                serde_json::json!({}),
            ))
            .await
            .unwrap();
        audit.flush().await.unwrap();

        // Filters narrow within the organization only.
        let filtered = AuditQuery {
            organization_id: org_a.clone(),
            severity: Some("critical".into()),
            actor_id: Some("alice".into()),
            resource: Some("contacts".into()),
            workspace_id: Some(ws.clone()),
            limit: Some(100),
            ..Default::default()
        };
        let (events, total) = audit.query(&filtered).await.unwrap();
        assert_eq!(total, 1);
        assert_eq!(events[0].severity, AuditSeverity::Critical);

        // Unknown severity is a literal filter, never "no filter".
        let unknown = AuditQuery {
            organization_id: org_a.clone(),
            severity: Some("fatal".into()),
            ..Default::default()
        };
        assert_eq!(audit.query(&unknown).await.unwrap().1, 0);

        // Route clamps pagination and reports the effective window.
        let (status, json) = call(
            &app,
            "GET",
            &format!("/audit/query?organization_id={org_a}&limit=100000&offset=-7"),
            Some(INTERNAL_KEY),
            None,
            Some(&org_a),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{json}");
        assert_eq!(json["limit"], 500);
        assert_eq!(json["offset"], 0);
        assert_eq!(json["total"], 3);

        let (status, json) = call(
            &app,
            "GET",
            &format!("/audit/query?organization_id={org_a}&limit=0"),
            Some(INTERNAL_KEY),
            None,
            Some(&org_a),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["limit"], 1);

        // A claimed org can never read another org's trail.
        let (status, _) = call(
            &app,
            "GET",
            &format!("/audit/query?organization_id={org_b}"),
            Some(INTERNAL_KEY),
            None,
            Some(&org_a),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);

        // Stats are tenant-scoped.
        let (status, json) = call(
            &app,
            "GET",
            &format!("/audit/stats/{org_a}?days=1"),
            Some(INTERNAL_KEY),
            None,
            Some(&org_a),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{json}");
        assert_eq!(json["total_events"], 3);
        assert!(json["by_type"].is_object() || json["by_type"].is_array());
        assert!(json["top_actors"].is_array());

        // CSV and JSON exports carry the tenant's own rows only.
        let (status, _) = call(
            &app,
            "GET",
            &format!("/audit/export/{org_a}?format=csv"),
            Some(INTERNAL_KEY),
            None,
            Some(&org_a),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let (status, _) = call(
            &app,
            "GET",
            &format!("/audit/export/{org_a}?format=json"),
            Some(INTERNAL_KEY),
            None,
            Some(&org_a),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        // Cross-tenant export is refused.
        let (status, _) = call(
            &app,
            "GET",
            &format!("/audit/export/{org_b}?format=csv"),
            Some(INTERNAL_KEY),
            None,
            Some(&org_a),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);

        // Export helper directly: CSV has a header and JSON is an array.
        let export_query = AuditQuery {
            organization_id: org_a.clone(),
            ..Default::default()
        };
        let csv = audit.export(&export_query, "csv").await.unwrap();
        assert!(csv.starts_with("id,organization_id"));
        assert!(!csv.contains(&org_b), "export must not leak another tenant");
        let json = audit.export(&export_query, "json").await.unwrap();
        assert!(json.trim_start().starts_with('['));
    });
}

// ── Access policy engine / query validation ─────────────────────────────

#[test]
fn access_policy_engine_fails_closed_and_enforces_ownership() {
    run(async {
        let Some(h) = harness().await else { return };
        let app = h.app().await;
        let org_a = create_org(&app, None).await;
        let org_b = create_org(&app, None).await;
        let ws_a = create_workspace(&app, &org_a, &unique("ws")).await;
        let ws_b = create_workspace(&app, &org_b, &unique("ws")).await;

        // A service that never loaded policies must deny everything.
        let unloaded = DataIsolationService::new(h.db.clone());
        let ctx = IsolationContext {
            organization_id: org_a.clone(),
            workspace_id: ws_a.clone(),
            user_id: "user-1".into(),
            isolation_level: IsolationLevel::Shared,
            schema_name: None,
            permissions: vec![],
        };
        assert!(
            !unloaded.validate_query_access("SELECT * FROM emails WHERE workspace_id = $1", &ctx)
        );
        assert!(!unloaded
            .check_resource_access(&ctx, "email", "whatever", "read")
            .await
            .unwrap());

        // Seed rows owned by workspace A in the isolation-owned emails table and
        // a deny policy for the email resource.
        sqlx::query("INSERT INTO emails (id, workspace_id, subject) VALUES ('row-a', $1, 'a')")
            .bind(&ws_a)
            .execute(&h.db)
            .await
            .unwrap();
        sqlx::query("INSERT INTO emails (id, workspace_id, subject) VALUES ('row-b', $1, 'b')")
            .bind(&ws_b)
            .execute(&h.db)
            .await
            .unwrap();
        sqlx::query(
            "INSERT INTO iso_access_policies (id, name, resource, conditions, actions, effect) \
         VALUES ($1, 'deny email reads', 'email', '[]', '[\"read\"]', 'deny')",
        )
        .bind(unique("pol"))
        .execute(&h.db)
        .await
        .unwrap();

        let isolation = h.isolation().await;
        // Own row is still denied by the policy — and the denial is audited.
        assert!(!isolation
            .check_resource_access(&ctx, "email", "row-a", "read")
            .await
            .unwrap());
        // A foreign row is denied too.
        assert!(!isolation
            .check_resource_access(&ctx, "email", "row-b", "read")
            .await
            .unwrap());
        let denied: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM iso_access_attempts WHERE organization_id = $1 AND allowed = false",
    )
    .bind(&org_a)
    .fetch_one(&h.db)
    .await
    .unwrap();
        assert_eq!(denied, 2, "every denied decision must be audited");

        // An action the policy does not cover is evaluated against that action's
        // own rules: no `update` policy exists, so the documented default allow
        // applies (the deny above is scoped to `read`).
        assert!(isolation
            .check_resource_access(&ctx, "email", "row-a", "update")
            .await
            .unwrap());

        // Query validation: blocked constructs and unscoped tenanted tables.
        for query in [
            "SELECT * FROM emails",
            "SELECT * FROM emails WHERE subject = 'x' /* workspace_id = $1 */",
            "SELECT * FROM information_schema.tables",
            "SELECT set_config('search_path','public',false)",
            "UPDATE emails SET subject = $1",
            "SELECT * FROM contacts c JOIN emails e ON true",
        ] {
            assert!(
                !isolation.validate_query_access(query, &ctx),
                "query must be refused: {query}"
            );
        }
        for query in [
            "SELECT * FROM emails WHERE workspace_id = $1",
            "SELECT * FROM emails WHERE organization_id = $1",
            "SELECT * FROM emails WHERE workspace_id = ?",
            "SELECT * FROM iso_organizations WHERE id = $1",
            "SELECT * FROM contacts WHERE workspace_id = $1",
        ] {
            assert!(
                isolation.validate_query_access(query, &ctx),
                "query must be allowed: {query}"
            );
        }

        // Route surface mirrors the engine and stays honest under a foreign claim.
        let resource = format!("resource-{}", uuid::Uuid::new_v4().simple());
        let (status, json) = call(
            &app,
            "POST",
            "/isolation/check-access",
            Some(INTERNAL_KEY),
            None,
            Some(&org_a),
            Some(serde_json::json!({
                "query": "SELECT * FROM emails",
                "organization_id": org_a,
                "workspace_id": ws_a,
                "user_id": "user-1",
                "resource": resource,
                "resource_id": "row-a",
            })),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{json}");
        assert_eq!(json["query_valid"], false);
        assert_eq!(json["resource_access"], false);

        let (status, _) = call(
            &app,
            "POST",
            "/isolation/check-access",
            Some(INTERNAL_KEY),
            None,
            Some(&org_b),
            Some(serde_json::json!({
                "query": "SELECT * FROM emails WHERE workspace_id = $1",
                "organization_id": org_a,
                "workspace_id": ws_a,
                "user_id": "user-1",
                "resource": "email",
                "resource_id": "row-a",
            })),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);

        // Unknown org/workspace → 404, not a default-allow response.
        let (status, _) = call(
            &app,
            "POST",
            "/isolation/check-access",
            Some(INTERNAL_KEY),
            None,
            None,
            Some(serde_json::json!({
                "query": "SELECT 1",
                "organization_id": unique("nope"),
                "workspace_id": ws_a,
                "user_id": "u",
                "resource": "email",
                "resource_id": "x",
            })),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    });
}

// ── Tenant service limits / dedicated schema / RLS ──────────────────────

#[test]
fn tenant_limits_dedicated_schema_and_suspension_are_enforced() {
    run(async {
        let Some(h) = harness().await else { return };
        let tenant = h.tenant();

        // Workspace limit from config.
        let mut limited_config = h.config.clone();
        limited_config.tenant.max_workspaces_per_org = 1;
        limited_config.tenant.max_users_per_workspace = 1;
        let limited = TenantService::new(h.db.clone(), limited_config);
        let org = limited
            .create_organization(
                "Limited",
                &unique("lim"),
                "b@example.com",
                None,
                None,
                "owner",
            )
            .await
            .unwrap();
        limited
            .create_workspace(&org.id, "One", &unique("ws"), "creator", None)
            .await
            .unwrap();
        let second = limited
            .create_workspace(&org.id, "Two", &unique("ws"), "creator", None)
            .await;
        assert!(second.is_err(), "workspace cap must be enforced");

        let ws = limited.list_workspaces(&org.id).await.unwrap().remove(0);
        // The creator is automatically an admin member, filling the 1-member cap.
        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM iso_workspace_members WHERE workspace_id = $1",
        )
        .bind(&ws.id)
        .fetch_one(&h.db)
        .await
        .unwrap();
        assert_eq!(count, 1, "workspace creator must be a member");
        // Re-adding the same member is an upsert (no cap violation)…
        limited
            .add_workspace_member(&ws.id, "creator", &TenantRole::Owner, "inviter")
            .await
            .unwrap();
        let role: String = sqlx::query_scalar(
            "SELECT role FROM iso_workspace_members WHERE workspace_id=$1 AND user_id='creator'",
        )
        .bind(&ws.id)
        .fetch_one(&h.db)
        .await
        .unwrap();
        assert_eq!(role, "owner");
        // …while a genuinely new member exceeds the configured cap.
        assert!(limited
            .add_workspace_member(&ws.id, "u-2", &TenantRole::Member, "inviter")
            .await
            .is_err());

        // Dedicated-schema isolation level provisions the schema and its tables.
        let dedicated = tenant
            .create_organization(
                "Dedicated",
                &unique("ded"),
                "b@example.com",
                Some("enterprise"),
                Some(IsolationLevel::DedicatedSchema),
                "owner",
            )
            .await
            .unwrap();
        let schema = dedicated
            .schema_name
            .clone()
            .expect("dedicated org must carry a schema");
        assert!(schema.starts_with("org_"));
        let ws_dedicated = tenant
            .create_workspace(&dedicated.id, "Ded", &unique("ws"), "creator", None)
            .await
            .unwrap();
        let ws_schema = ws_dedicated.schema_name.clone().expect("workspace schema");
        let exists: Option<String> = sqlx::query_scalar(&format!(
            "SELECT to_regclass('\"{}\".emails')::text",
            ws_schema.replace('"', "")
        ))
        .fetch_one(&h.db)
        .await
        .unwrap();
        assert!(exists.is_some(), "workspace schema must contain emails");

        // Slug is globally unique, isolation level is persisted.
        let dup = tenant
            .create_organization("Dup", &dedicated.slug, "b@example.com", None, None, "owner")
            .await;
        assert!(dup.is_err());
        let fetched = tenant.get_organization(&dedicated.id).await.unwrap();
        assert_eq!(fetched.isolation_level, IsolationLevel::DedicatedSchema);

        // Quota update + cache invalidation.
        let quota = QuotaConfig {
            emails_per_month: 7,
            ..QuotaConfig::default()
        };
        tenant.update_quota(&ws_dedicated.id, quota).await.unwrap();
        let fetched = tenant.get_workspace(&ws_dedicated.id).await.unwrap();
        assert_eq!(fetched.quota.emails_per_month, 7);
        assert!(tenant
            .check_quota(&ws_dedicated.id, "emails_per_month", 7)
            .await
            .unwrap());
        assert!(!tenant
            .check_quota(&ws_dedicated.id, "emails_per_month", 8)
            .await
            .unwrap());
    });
}

#[test]
fn rls_route_is_idempotent_and_scopes_policies_to_workspace() {
    run(async {
        let Some(h) = harness().await else { return };
        // The RLS DDL is applied to the workspace's OWN schema (a workspace
        // that has been given a dedicated schema), never to the shared public
        // tables other concurrent tests use.
        let tenant = h.tenant();
        let org = tenant
            .create_organization(
                "RLS org",
                &unique("rls-org"),
                "b@example.com",
                None,
                None,
                "owner",
            )
            .await
            .unwrap();
        let ws = tenant
            .create_workspace(&org.id, "RLS ws", &unique("rls-ws"), "creator", None)
            .await
            .unwrap();
        let schema = format!("rls_{}", uuid::Uuid::new_v4().simple());
        sqlx::query(&format!("CREATE SCHEMA \"{schema}\""))
            .execute(&h.db)
            .await
            .unwrap();
        sqlx::query(&format!(
            "CREATE TABLE \"{schema}\".emails (id TEXT PRIMARY KEY, workspace_id TEXT NOT NULL, subject TEXT)"
        ))
        .execute(&h.db)
        .await
        .unwrap();
        sqlx::query("UPDATE iso_workspaces SET schema_name = $1 WHERE id = $2")
            .bind(&schema)
            .bind(&ws.id)
            .execute(&h.db)
            .await
            .unwrap();
        // Fresh app: no stale cached workspace snapshot from create_workspace.
        let app = h.app().await;

        // First setup creates the four workspace-isolation policies.
        let (status, json) = call(
            &app,
            "POST",
            &format!("/isolation/rls/{}", ws.id),
            Some(INTERNAL_KEY),
            None,
            None,
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{json}");
        let policies: Vec<(String,)> = sqlx::query_as(
            "SELECT policyname FROM pg_policies WHERE schemaname=$1 AND tablename='emails' ORDER BY policyname",
        )
        .bind(&schema)
        .fetch_all(&h.db)
        .await
        .unwrap();
        let names: Vec<String> = policies.into_iter().map(|(n,)| n).collect();
        for expected in [
            "workspace_isolation_select",
            "workspace_isolation_insert",
            "workspace_isolation_update",
            "workspace_isolation_delete",
        ] {
            assert!(names.contains(&expected.to_string()), "missing {expected}");
        }

        // Re-running the setup is idempotent (2xx), not a 500.
        let (status, _) = call(
            &app,
            "POST",
            &format!("/isolation/rls/{}", ws.id),
            Some(INTERNAL_KEY),
            None,
            None,
            None,
        )
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "re-running RLS setup must be an honest 2xx"
        );

        // Unknown workspace is a 404.
        let (status, _) = call(
            &app,
            "POST",
            &format!("/isolation/rls/{}", unique("ghost")),
            Some(INTERNAL_KEY),
            None,
            None,
            None,
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);

        // RLS DDL is fail-closed on hostile identifiers, even when called
        // directly with attacker-controlled names.
        let isolation = h.isolation().await;
        assert!(isolation
            .setup_rls("emails; DROP TABLE emails", "public")
            .await
            .is_err());
        assert!(isolation
            .setup_rls("emails", "public\"; DROP SCHEMA public CASCADE; --")
            .await
            .is_err());
    });
}

#[test]
fn isolation_migration_route_reports_unsupported_paths_as_4xx() {
    run(async {
        let Some(h) = harness().await else { return };
        let app = h.app().await;
        let org = create_org(&app, None).await;

        // Same-to-same is an unsupported migration path → 400, no state change.
        let (status, json) = call(
            &app,
            "POST",
            &format!("/isolation/migrate/{org}"),
            Some(INTERNAL_KEY),
            None,
            Some(&org),
            Some(serde_json::json!({"target_level": "shared"})),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{json}");
        let level: String =
            sqlx::query_scalar("SELECT isolation_level FROM iso_organizations WHERE id=$1")
                .bind(&org)
                .fetch_one(&h.db)
                .await
                .unwrap();
        assert_eq!(level, "shared");

        // Migration against the canonical schema's non-tenanted public tables
        // fails honestly (400), and the workspace row is left untouched.
        let ws = create_workspace(&app, &org, &unique("ws")).await;
        let (status, json) = call(
            &app,
            "POST",
            &format!("/isolation/migrate/{org}"),
            Some(INTERNAL_KEY),
            None,
            Some(&org),
            Some(serde_json::json!({"target_level": "dedicated_schema"})),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{json}");
        // The 4xx body must be DIAGNOSABLE: it names every missing
        // table/column and the migration each one would need.
        // This harness creates its own tenanted `public.emails`, so the four
        // canonical non-tenanted tables are the gaps here (the canonical-chain
        // refusal test covers the missing `public.emails` too).
        let message = json["error"].as_str().expect("error body");
        for needle in [
            "public.contacts",
            "public.templates",
            "public.campaigns",
            "public.webhooks",
            "workspace_id",
            "075_create_missing_tables.sql",
        ] {
            assert!(
                message.contains(needle),
                "migration refusal must name {needle:?}: {message}"
            );
        }
        let schema_name: Option<String> =
            sqlx::query_scalar("SELECT schema_name FROM iso_workspaces WHERE id=$1")
                .bind(&ws)
                .fetch_one(&h.db)
                .await
                .unwrap();
        assert!(
            schema_name.is_none(),
            "failed migration must not half-apply"
        );

        // Unknown org → 404 (the claim matches the path so the miss is
        // attributable to the resource, not to a claim mismatch).
        let ghost = unique("ghost");
        let (status, _) = call(
            &app,
            "POST",
            &format!("/isolation/migrate/{ghost}"),
            Some(INTERNAL_KEY),
            None,
            Some(&ghost),
            Some(serde_json::json!({"target_level": "dedicated_schema"})),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    });
}
