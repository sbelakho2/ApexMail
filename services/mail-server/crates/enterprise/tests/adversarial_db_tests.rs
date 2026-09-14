//! Adversarial, DB-backed integration tests for the enterprise service:
//! JWT/tenant gates, contract lifecycle, support ticket state machine + SLA,
//! compliance (audit trail, BAA, data-access clamping), log streaming (SSRF +
//! secret masking), private deployments / dedicated IPs / BYOIP, sub-account
//! API-key lifecycle, template approval, white-label domains and QBRs.
//!
//! Harness convention (workspace): the canonical schema is provisioned with
//! `migrator::test_support::fresh_canonical_pool`; a configured provisioning
//! failure panics, an unset `TEST_DATABASE_URL` soft-skips.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::Router;
use enterprise::config::Config;
use enterprise::routes::{router, AppState};
use metrics_exporter_prometheus::PrometheusBuilder;
use sqlx::PgPool;
use std::sync::Arc;
use tower::ServiceExt;
use uuid::Uuid;

const TEST_PRIVATE_PEM: &str = include_str!("keys/test_rsa_private.pem");
const TEST_PUBLIC_PEM: &str = include_str!("keys/test_rsa_public.pem");

static SHARED: tokio::sync::OnceCell<Option<Harness>> = tokio::sync::OnceCell::const_new();
static RT: std::sync::OnceLock<tokio::runtime::Runtime> = std::sync::OnceLock::new();

fn test_runtime() -> &'static tokio::runtime::Runtime {
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

struct Harness {
    app: Router,
    db: PgPool,
    tenant_a: String,
    tenant_b: String,
    admin_a: String,
    user_a: String,
    admin_token: String,
    token_a: String,
    token_b: String,
}

async fn harness() -> Option<&'static Harness> {
    SHARED
        .get_or_init(|| async { build_harness().await })
        .await
        .as_ref()
}

async fn build_harness() -> Option<Harness> {
    // `shared_canonical_db`, NOT `fresh_canonical_pool`: this suite's tests all
    // share ONE database for the whole process (the `SHARED` OnceCell builds
    // the harness once), and `fresh_canonical_pool` DROPS and re-creates its
    // database on every call — under a parallel runner a second caller could
    // drop the database the first caller was connecting to, which is exactly
    // the observed `clone-connect: database "…_enterprise_core" does not exist`
    // failure. The shared variant creates-if-absent under a cluster advisory
    // lock and REUSES an existing complete canonical database.
    let base_url = std::env::var("ENTERPRISE_TEST_DATABASE_URL")
        .or_else(|_| std::env::var("TEST_DATABASE_URL"))
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())?;
    let (server_part, db_part) = base_url.rsplit_once('/')?;
    let db_only = db_part.split('?').next().unwrap_or(db_part);
    let db = match migrator::test_support::shared_canonical_db(
        &format!("{server_part}/{db_only}"),
        &format!("{db_only}_enterprise_core"),
    )
    .await
    {
        Ok(db) => db,
        Err(error) => panic!("{}", error.panic_message()),
    };
    let db = db?;

    let mut config = Config::from_env().expect("Config::from_env");
    config.jwt_public_key_pem = TEST_PUBLIC_PEM.to_string();
    config.jwt_audience = None;
    config.jwt_issuer = None;
    config.metrics_token = None;
    config.log_stream.encryption_key = "adversarial-log-stream-secret-key".to_string();

    let tenant_a = format!("t{}", &Uuid::new_v4().simple().to_string()[..25]);
    let tenant_b = format!("s{}", &Uuid::new_v4().simple().to_string()[..25]);
    let user_a = format!("user-a-{}", Uuid::new_v4().simple());
    let admin_a = format!("admin-a-{}", Uuid::new_v4().simple());
    for (id, name) in [(&tenant_a, "Adversarial A"), (&tenant_b, "Adversarial B")] {
        sqlx::query(
            "INSERT INTO tenants (id, name, slug, plan, status, settings, metadata, created_at, updated_at) \
             VALUES ($1, $2, $1, 'free', 'active', '{}'::jsonb, '{}'::jsonb, NOW(), NOW()) \
             ON CONFLICT (id) DO NOTHING",
        )
        .bind(id)
        .bind(name)
        .execute(&db)
        .await
        .expect("seed tenant");
    }

    let recorder = PrometheusBuilder::new().build_recorder();
    let app = router(Arc::new(AppState::new(
        db.clone(),
        config,
        recorder.handle(),
    )));

    let admin_token = mint_token(&tenant_a, &admin_a, true);
    let token_a = mint_token(&tenant_a, &user_a, false);
    let token_b = mint_token(&tenant_b, "user-b-subject", false);
    Some(Harness {
        app,
        db,
        tenant_a,
        tenant_b,
        admin_a,
        user_a,
        admin_token,
        token_a,
        token_b,
    })
}

fn mint_token(tenant: &str, subject: &str, admin: bool) -> String {
    #[derive(serde::Serialize)]
    struct Claims<'a> {
        sub: &'a str,
        tenant_id: &'a str,
        admin: bool,
        exp: usize,
    }
    let claims = Claims {
        sub: subject,
        tenant_id: tenant,
        admin,
        exp: (chrono::Utc::now() + chrono::Duration::hours(1)).timestamp() as usize,
    };
    let key = jsonwebtoken::EncodingKey::from_rsa_pem(TEST_PRIVATE_PEM.as_bytes()).unwrap();
    jsonwebtoken::encode(
        &jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256),
        &claims,
        &key,
    )
    .unwrap()
}

async fn call(
    app: &Router,
    method: &str,
    path: &str,
    token: Option<&str>,
    body: Option<serde_json::Value>,
) -> (StatusCode, serde_json::Value) {
    let mut builder = Request::builder().method(method).uri(path);
    if let Some(token) = token {
        builder = builder.header("authorization", format!("Bearer {token}"));
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

/// A camelCase contract-create body (the contract DTOs rename all fields).
fn contract_body() -> serde_json::Value {
    let now = chrono::Utc::now();
    serde_json::json!({
        "startDate": now,
        "endDate": now + chrono::Duration::days(365),
        "baseFee": 12_000,
        "committedVolume": {"emails": 1_000_000, "apiCalls": 50_000, "storage": 500},
        "overageRates": {"emailsPerThousand": 5, "apiCallsPerThousand": 2, "storagePerGb": 1},
        "paymentTerms": "net30",
        "customFeatures": ["priority-routing"],
        "allowPurchaseOrders": true,
        "dedicatedSupport": true
    })
}

// ── JWT / tenant gates ──────────────────────────────────────────────────

#[test]
fn jwt_and_tenant_gates_reject_unauthenticated_and_cross_tenant_calls() {
    run(async {
        let Some(h) = harness().await else { return };
        let app = h.app.clone();

        // Liveness stays open; every other route needs a valid RS256 token.
        let (status, _) = call(&app, "GET", "/health", None, None).await;
        assert_eq!(status, StatusCode::OK);
        let (status, _) = call(&app, "GET", "/readiness", None, None).await;
        assert_eq!(status, StatusCode::OK);

        for (method, path) in [
            ("GET", "/contracts"),
            ("POST", "/contracts"),
            ("GET", "/compliance/config/x"),
            ("GET", "/log-streams/tenant/x"),
            ("POST", "/deployments"),
            ("GET", "/support/tickets/tenant/x"),
            ("POST", "/templates/submit"),
            ("GET", "/whitelabel/config/x"),
            ("GET", "/qbr/tenant/x"),
            ("GET", "/sub-accounts/parent/x"),
            ("POST", "/compliance/audit"),
        ] {
            let body = matches!(method, "POST" | "PUT").then(|| serde_json::json!({}));
            let (status, _) = call(&app, method, path, None, body).await;
            assert_eq!(status, StatusCode::UNAUTHORIZED, "{method} {path} no token");
        }

        // A garbage / unsigned token is rejected.
        let (status, _) = call(&app, "GET", "/contracts", Some("not-a-jwt"), None).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);

        // Tenant A cannot read tenant B's configuration.
        let (status, _) = call(
            &app,
            "GET",
            &format!("/compliance/config/{}", h.tenant_b),
            Some(&h.token_a),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "cross-tenant read");
        let (status, _) = call(
            &app,
            "GET",
            &format!("/log-streams/tenant/{}", h.tenant_b),
            Some(&h.token_a),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        let (status, _) = call(
            &app,
            "POST",
            "/compliance/audit",
            Some(&h.token_a),
            Some(serde_json::json!({
                "tenant_id": h.tenant_b,
                "action": "forged",
                "resource_type": "tenant"
            })),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        let forged: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM ent_compliance_audit_logs WHERE tenant_id=$1 AND action='forged'",
        )
        .bind(&h.tenant_b)
        .fetch_one(&h.db)
        .await
        .unwrap();
        assert_eq!(forged, 0, "a refused audit write must not persist");

        // A non-admin cannot override the tenant via header; an admin can.
        let (status, _) = call_with_header(
            &app,
            "GET",
            "/contracts",
            Some(&h.token_a),
            "x-tenant-id",
            &h.tenant_b,
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        let (status, _) = call_with_header(
            &app,
            "GET",
            "/contracts",
            Some(&h.admin_token),
            "x-tenant-id",
            &h.tenant_b,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "admin override allowed");

        // Non-admin-only routes refuse a plain tenant token.
        let (status, _) = call(
            &app,
            "POST",
            "/contracts",
            Some(&h.token_a),
            Some(contract_body()),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "contract create is admin-only"
        );
        let (status, _) = call(&app, "POST", "/sso/cleanup", Some(&h.token_a), None).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "sso cleanup is admin-only");
    });
}

async fn call_with_header(
    app: &Router,
    method: &str,
    path: &str,
    token: Option<&str>,
    header: &str,
    value: &str,
) -> (StatusCode, serde_json::Value) {
    let mut builder = Request::builder()
        .method(method)
        .uri(path)
        .header(header, value);
    if let Some(token) = token {
        builder = builder.header("authorization", format!("Bearer {token}"));
    }
    let response = app
        .clone()
        .oneshot(builder.body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap_or_default();
    let json = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    (status, json)
}

// ── Contracts ───────────────────────────────────────────────────────────

#[test]
fn contract_lifecycle_enforces_admin_role_and_tenant_ownership() {
    run(async {
        let Some(h) = harness().await else { return };
        let app = h.app.clone();
        let admin = h.admin_token.clone();
        let tenant = h.tenant_a.clone();

        // Validation before persistence.
        let (status, json) = call(
            &app,
            "POST",
            "/contracts",
            Some(&admin),
            Some(serde_json::json!({
                "startDate": chrono::Utc::now(),
                "endDate": chrono::Utc::now() + chrono::Duration::days(30),
                "baseFee": -1,
                "committedVolume": {"emails": 1, "apiCalls": 1, "storage": 1},
                "overageRates": {"emailsPerThousand": 1, "apiCallsPerThousand": 1, "storagePerGb": 1},
                "paymentTerms": "net30"
            })),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "negative fee: {json}");
        let (status, _) = call(
            &app,
            "POST",
            "/contracts",
            Some(&admin),
            Some(serde_json::json!({
                "startDate": chrono::Utc::now(),
                "endDate": chrono::Utc::now() + chrono::Duration::days(30),
                "baseFee": 1,
                "committedVolume": {"emails": 1, "apiCalls": 1, "storage": 1},
                "overageRates": {"emailsPerThousand": 1, "apiCallsPerThousand": 1, "storagePerGb": 1},
                "paymentTerms": "net45"
            })),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "bad payment terms");
        let count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM enterprise_contracts WHERE tenant_id=$1")
                .bind(&tenant)
                .fetch_one(&h.db)
                .await
                .unwrap();
        assert_eq!(count, 0, "rejected contracts must not persist");

        // Create → list → get → usage → pdf.
        let (status, json) = call(
            &app,
            "POST",
            "/contracts",
            Some(&admin),
            Some(contract_body()),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{json}");
        let id = json["id"].as_str().expect("contract id").to_string();

        let (status, json) = call(&app, "GET", "/contracts", Some(&h.token_a), None).await;
        assert_eq!(status, StatusCode::OK);
        assert!(json["contracts"]
            .as_array()
            .unwrap()
            .iter()
            .any(|c| c["id"] == id.as_str()));

        let (status, json) = call(
            &app,
            "GET",
            &format!("/contracts/{id}"),
            Some(&h.token_a),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{json}");
        assert_eq!(json["tenantId"], tenant);

        let (status, _) = call(
            &app,
            "GET",
            &format!("/contracts/{id}/usage"),
            Some(&h.token_a),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let (status, _) = call(
            &app,
            "GET",
            &format!("/contracts/{id}/pdf"),
            Some(&h.token_a),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        // Another tenant cannot see or act on the contract: the lookup is
        // scoped by the TOKEN's tenant, so it is indistinguishable from an
        // unknown id (404 — no existence oracle).
        let (status, _) = call(
            &app,
            "GET",
            &format!("/contracts/{id}"),
            Some(&h.token_b),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        let (status, _) = call(
            &app,
            "POST",
            &format!("/contracts/{id}/sign"),
            Some(&h.token_b),
            Some(serde_json::json!({
                "signatureData": "attacker", "signerName": "Eve", "signerTitle": "CEO",
                "signedAt": chrono::Utc::now()
            })),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);

        // Submit → tenant signature (non-admin) → admin counter-signature.
        let (status, json) = call(
            &app,
            "POST",
            &format!("/contracts/{id}/submit"),
            Some(&h.token_a),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{json}");
        let (status, json) = call(
            &app,
            "POST",
            &format!("/contracts/{id}/sign"),
            Some(&h.token_a),
            Some(serde_json::json!({
                "signatureData": "tenant-sig", "signerName": "Alice", "signerTitle": "COO",
                "signedAt": chrono::Utc::now()
            })),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{json}");
        assert_eq!(
            json["status"], "pending_signature",
            "non-admin cannot activate"
        );
        // The admin counter-signature ignores the body's contents, but the
        // extractor still requires the full sign DTO.
        let (status, json) = call(
            &app,
            "POST",
            &format!("/contracts/{id}/sign"),
            Some(&admin),
            Some(serde_json::json!({
                "signatureData": "counter-sig", "signerName": "Platform", "signerTitle": "ApexMail",
                "signedAt": chrono::Utc::now()
            })),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{json}");
        assert_eq!(json["status"], "active");
        let plan: String = sqlx::query_scalar("SELECT plan FROM tenants WHERE id=$1")
            .bind(&tenant)
            .fetch_one(&h.db)
            .await
            .unwrap();
        assert_eq!(plan, "enterprise", "counter-signature promotes the plan");

        // Amendment, purchase order, renewal quote + renewal, cancellation.
        let (status, json) = call(
            &app,
            "POST",
            &format!("/contracts/{id}/amendments"),
            Some(&h.token_a),
            Some(serde_json::json!({
                "reason": "growth",
                "proposedChanges": {"baseFee": 20_000}
            })),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{json}");

        let (status, json) = call(
            &app,
            "POST",
            &format!("/contracts/{id}/purchase-orders"),
            Some(&h.token_a),
            Some(serde_json::json!({
                "poNumber": "PO-1",
                "amount": 500,
                "issuedDate": chrono::Utc::now()
            })),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{json}");

        let (status, _) = call(
            &app,
            "GET",
            &format!("/contracts/{id}/renewal-quote"),
            Some(&h.token_a),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        let (status, json) = call(
            &app,
            "POST",
            &format!("/contracts/{id}/renew"),
            Some(&h.token_a),
            Some(serde_json::json!({
                "newEndDate": chrono::Utc::now() + chrono::Duration::days(730),
                "newTerms": {"baseFee": 30_000}
            })),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{json}");

        let (status, _) = call(
            &app,
            "POST",
            &format!("/contracts/{id}/cancel"),
            Some(&h.token_a),
            Some(serde_json::json!({"reason": "adversarial test"})),
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        // Unknown contract ids are 404/honest, never a phantom success.
        let missing = Uuid::new_v4();
        let (status, _) = call(
            &app,
            "GET",
            &format!("/contracts/{missing}"),
            Some(&h.token_a),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        let (status, json) = call(
            &app,
            "POST",
            &format!("/contracts/{missing}/submit"),
            Some(&h.token_a),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{json}");
    });
}

// ── Support ─────────────────────────────────────────────────────────────

#[test]
fn support_ticket_state_machine_sla_and_tenant_isolation() {
    run(async {
        let Some(h) = harness().await else { return };
        let app = h.app.clone();
        let tenant = h.tenant_a.clone();

        // Validation errors are honest 400s.
        let (status, _) = call(
            &app,
            "POST",
            "/support/tickets",
            Some(&h.token_a),
            Some(serde_json::json!({
                "tenant_id": tenant, "subject": "", "description": "x",
                "priority": "high", "category": "billing"
            })),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        let (status, _) = call(
            &app,
            "POST",
            "/support/tickets",
            Some(&h.token_a),
            Some(serde_json::json!({
                "tenant_id": tenant, "subject": "bad priority", "description": "x",
                "priority": "urgent", "category": "billing"
            })),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);

        // Create: critical priority gets the tightest SLA deadline.
        let (status, json) = call(
            &app,
            "POST",
            "/support/tickets",
            Some(&h.token_a),
            Some(serde_json::json!({
                "tenant_id": tenant, "subject": "production down", "description": "everything is on fire",
                "priority": "critical", "category": "technical"
            })),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{json}");
        assert_eq!(json["success"], true, "{json}");
        let id = json["data"]["id"].as_str().expect("ticket id").to_string();
        let first_response: chrono::DateTime<chrono::Utc> = json["data"]["sla_first_response_due"]
            .as_str()
            .unwrap()
            .parse()
            .unwrap();
        let resolution: chrono::DateTime<chrono::Utc> = json["data"]["sla_resolution_due"]
            .as_str()
            .unwrap()
            .parse()
            .unwrap();
        assert!(first_response < resolution, "SLA ordering");
        assert!(
            resolution - first_response >= chrono::Duration::minutes(30),
            "critical SLA must be tight: {first_response} .. {resolution}"
        );

        // Tenant B cannot read it.
        let (status, _) = call(
            &app,
            "GET",
            &format!("/support/tickets/{id}"),
            Some(&h.token_b),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);

        // Legal transition open → pending, illegal resolved → open is fine but
        // closed → escalated is refused.
        let (status, json) = call(
            &app,
            "PUT",
            &format!("/support/tickets/{id}"),
            Some(&h.token_a),
            Some(serde_json::json!({"status": "open"})),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{json}");
        let (status, _) = call(
            &app,
            "PUT",
            &format!("/support/tickets/{id}"),
            Some(&h.token_a),
            Some(serde_json::json!({"status": "not_a_status"})),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);

        // Comments: public accepted while open, internal notes accepted, and a
        // closed ticket refuses public comments but not internal notes.
        let (status, json) = call(
            &app,
            "POST",
            &format!("/support/tickets/{id}/comments"),
            Some(&h.token_a),
            Some(serde_json::json!({
                "author_id": h.user_a.clone(), "author_name": "Alice", "author_type": "customer",
                "content": "any update?"
            })),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{json}");
        let (status, _) = call(
            &app,
            "GET",
            &format!("/support/tickets/{id}/comments"),
            Some(&h.token_a),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        // Escalation while open works; the ticket moves to escalated.
        let (status, json) = call(
            &app,
            "POST",
            &format!("/support/tickets/{id}/escalate"),
            Some(&h.token_a),
            Some(serde_json::json!({
                "reason": "stuck", "escalated_by": Uuid::new_v4()
            })),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{json}");
        assert_eq!(json["data"]["status"], "escalated", "{json}");

        // Close it, then a public comment is refused while internal notes
        // remain possible.
        let (status, json) = call(
            &app,
            "PUT",
            &format!("/support/tickets/{id}"),
            Some(&h.token_a),
            Some(serde_json::json!({"status": "closed"})),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{json}");
        let (status, _) = call(
            &app,
            "POST",
            &format!("/support/tickets/{id}/comments"),
            Some(&h.token_a),
            Some(serde_json::json!({
                "author_id": h.user_a.clone(), "author_name": "Alice", "author_type": "customer",
                "content": "one more thing", "is_internal": false
            })),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT, "public comment on closed");
        let (status, _) = call(
            &app,
            "POST",
            &format!("/support/tickets/{id}/comments"),
            Some(&h.token_a),
            Some(serde_json::json!({
                "author_id": h.user_a.clone(), "author_name": "Alice", "author_type": "agent",
                "content": "internal audit note", "is_internal": true
            })),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "internal note on closed");
        // Escalation of a closed ticket is refused.
        let (status, _) = call(
            &app,
            "POST",
            &format!("/support/tickets/{id}/escalate"),
            Some(&h.token_a),
            Some(serde_json::json!({
                "reason": "late", "escalated_by": Uuid::new_v4()
            })),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT, "closed cannot escalate");

        // Satisfaction is write-once (409 on replay).
        let (status, _) = call(
            &app,
            "POST",
            &format!("/support/tickets/{id}/satisfaction"),
            Some(&h.token_a),
            Some(serde_json::json!({"rating": 5, "feedback": "great"})),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let (status, json) = call(
            &app,
            "POST",
            &format!("/support/tickets/{id}/satisfaction"),
            Some(&h.token_a),
            Some(serde_json::json!({"rating": 1, "feedback": "too late"})),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT, "rating is immutable: {json}");
        let rating: i32 =
            sqlx::query_scalar("SELECT satisfaction_rating FROM ent_support_tickets WHERE id=$1")
                .bind(Uuid::parse_str(&id).unwrap())
                .fetch_one(&h.db)
                .await
                .unwrap();
        assert_eq!(rating, 5, "the first rating survives");

        // Listing: malformed cursor is a 400; filters/page clamps work; the
        // list is tenant-scoped.
        let (status, _) = call(
            &app,
            "GET",
            &format!("/support/tickets/tenant/{tenant}?cursor=not-a-cursor"),
            Some(&h.token_a),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        let (status, json) = call(
            &app,
            "GET",
            &format!("/support/tickets/tenant/{tenant}?limit=100000&status=closed&q=production"),
            Some(&h.token_a),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["success"], true);

        // Metrics + support metrics are tenant-scoped.
        let (status, json) = call(
            &app,
            "GET",
            &format!("/support/metrics/{tenant}"),
            Some(&h.token_a),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert!(
            json["data"]["total_tickets"].as_i64().unwrap_or(0) >= 1,
            "{json}"
        );
        let (status, _) = call(
            &app,
            "GET",
            &format!("/support/metrics/{}", h.tenant_b),
            Some(&h.token_a),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
    });
}

// ── Compliance ──────────────────────────────────────────────────────────

#[test]
fn compliance_audit_identity_baa_and_data_access_are_fail_closed() {
    run(async {
        let Some(h) = harness().await else { return };
        let app = h.app.clone();
        let tenant = h.tenant_a.clone();

        // Enable compliance for the tenant.
        let (status, json) = call(
            &app,
            "POST",
            "/compliance/enable",
            Some(&h.token_a),
            Some(serde_json::json!({
                "tenant_id": tenant, "frameworks": ["soc2", "hipaa"], "hipaa_enabled": true
            })),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{json}");
        assert_eq!(json["success"], true, "{json}");

        let (status, json) = call(
            &app,
            "GET",
            &format!("/compliance/config/{tenant}"),
            Some(&h.token_a),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert!(
            json["data"]["enabled_frameworks"]
                .as_array()
                .unwrap()
                .iter()
                .any(|f| f == "hipaa"),
            "hipaa must be enabled: {json}"
        );

        // BAA signing is recorded with the signatory.
        let (status, json) = call(
            &app,
            "POST",
            "/compliance/baa",
            Some(&h.token_a),
            Some(serde_json::json!({
                "tenant_id": tenant,
                "signatory_name": "Alice",
                "signatory_title": "COO",
                "signatory_email": "alice@example.com"
            })),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{json}");

        // Audit log identity is server-derived: the body-supplied user_id is
        // NOT stored as the actor.
        let (status, json) = call(
            &app,
            "POST",
            "/compliance/audit",
            Some(&h.token_a),
            Some(serde_json::json!({
                "tenant_id": tenant,
                "user_id": "forged-actor",
                "ip_address": "10.0.0.1",
                "action": "phi.read",
                "resource_type": "patient_record",
                "resource_id": "rec-1"
            })),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{json}");
        let actor: String = sqlx::query_scalar(
            "SELECT user_id FROM ent_compliance_audit_logs WHERE tenant_id=$1 AND action='phi.read' ORDER BY created_at DESC LIMIT 1",
        )
        .bind(&tenant)
        .fetch_one(&h.db)
        .await
        .unwrap();
        assert_eq!(actor, h.user_a, "actor must be the token subject");
        let metadata: serde_json::Value = sqlx::query_scalar(
            "SELECT metadata FROM ent_compliance_audit_logs WHERE tenant_id=$1 AND action='phi.read' ORDER BY created_at DESC LIMIT 1",
        )
        .bind(&tenant)
        .fetch_one(&h.db)
        .await
        .unwrap();
        assert_eq!(metadata["client_supplied"]["user_id"], "forged-actor");

        let (status, json) = call(
            &app,
            "GET",
            &format!("/compliance/audit/{tenant}?limit=5000"),
            Some(&h.token_a),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["success"], true);

        // Data access request → approval clamps the duration and derives the
        // approver identity from the token (never the body).
        let (status, json) = call(
            &app,
            "POST",
            "/compliance/data-access",
            Some(&h.token_a),
            Some(serde_json::json!({
                "tenant_id": tenant,
                "requester_id": h.user_a.clone(),
                "requester_email": "alice@example.com",
                "request_type": "export",
                "resource_type": "contacts",
                "justification": "adversarial test"
            })),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{json}");
        let request_id = json["data"]["id"].as_str().expect("request id").to_string();

        let (status, json) = call(
            &app,
            "POST",
            &format!("/compliance/data-access/{request_id}/approve"),
            Some(&h.admin_token),
            Some(serde_json::json!({
                "approved_by": "forged-approver",
                "duration_minutes": 100_000
            })),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{json}");
        let (approved_by, minutes): (String, i32) = sqlx::query_as(
            "SELECT approved_by, duration_minutes FROM ent_data_access_requests WHERE id=$1",
        )
        .bind(Uuid::parse_str(&request_id).unwrap())
        .fetch_one(&h.db)
        .await
        .unwrap();
        assert_eq!(approved_by, h.admin_a, "approver is derived from the token");
        assert_eq!(minutes, 1440, "duration is clamped to 24h");
        assert_ne!(
            json["data"]["access_token"].as_str(),
            Some("forged-approver"),
            "no raw token echo"
        );

        // Data deletion request + report + status.
        let (status, _) = call(
            &app,
            "POST",
            "/compliance/data-deletion",
            Some(&h.token_a),
            Some(serde_json::json!({
                "tenant_id": tenant,
                "requester_id": h.user_a.clone(),
                "requester_email": "alice@example.com",
                "identifiers": {"emails": ["a@example.com"]}
            })),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let (status, _) = call(
            &app,
            "GET",
            &format!("/compliance/report/{tenant}"),
            Some(&h.token_a),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let (status, _) = call(
            &app,
            "GET",
            &format!("/compliance/status/{tenant}"),
            Some(&h.token_a),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        // Field tooling: ciphertext is tenant-bound — decrypting through
        // another tenant's context is refused.
        let (status, json) = call(
            &app,
            "POST",
            "/compliance/encryption/encrypt-field",
            Some(&h.token_a),
            Some(serde_json::json!({
                "tenant_id": tenant, "field_name": "phone", "value": "+1-555-0100"
            })),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{json}");
        assert_eq!(json["is_phi"], true, "phone is a PHI field: {json}");
        let ciphertext = json["value"].as_str().unwrap().to_string();
        assert!(
            !ciphertext.contains("+1-555-0100"),
            "plaintext must not echo"
        );

        let (status, json) = call(
            &app,
            "POST",
            "/compliance/encryption/decrypt-field",
            Some(&h.token_a),
            Some(serde_json::json!({
                "tenant_id": tenant, "field_name": "phone", "value": ciphertext
            })),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{json}");
        assert_eq!(json["value"], "+1-555-0100");

        let (status, _) = call(
            &app,
            "POST",
            "/compliance/encryption/decrypt-field",
            Some(&h.token_b),
            Some(serde_json::json!({
                "tenant_id": h.tenant_b, "field_name": "phone", "value": ciphertext
            })),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "cross-tenant AAD must fail closed"
        );

        // Cross-tenant data-access approval is refused.
        let (status, _) = call(
            &app,
            "POST",
            &format!("/compliance/data-access/{request_id}/approve"),
            Some(&h.token_b),
            Some(serde_json::json!({"approved_by": "eve", "duration_minutes": 10})),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
    });
}

// ── Log streaming ───────────────────────────────────────────────────────

#[test]
fn log_streaming_secrets_are_masked_and_ssrf_is_refused() {
    run(async {
        let Some(h) = harness().await else { return };
        let app = h.app.clone();
        let tenant = h.tenant_a.clone();

        // An unknown destination type is stored but must NEVER verify: the
        // verify endpoint refuses to claim success for a type it cannot test.
        let (status, json) = call(
            &app,
            "POST",
            "/log-streams",
            Some(&h.token_a),
            Some(serde_json::json!({
                "tenant_id": tenant, "name": "bad", "destination_type": "carrier-pigeon",
                "destination_config": {"url": "https://example.com"}
            })),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{json}");
        let pigeon_id = json["data"]["id"].as_str().expect("stream id").to_string();
        let (status, json) = call(
            &app,
            "POST",
            &format!("/log-streams/{pigeon_id}/verify"),
            Some(&h.token_a),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{json}");
        assert_eq!(json["data"]["verified"], false, "unknown type: {json}");
        let _ = call(
            &app,
            "DELETE",
            &format!("/log-streams/{pigeon_id}"),
            Some(&h.token_a),
            None,
        )
        .await;

        let (status, json) = call(
            &app,
            "POST",
            "/log-streams",
            Some(&h.token_a),
            Some(serde_json::json!({
                "tenant_id": tenant,
                "name": "adv webhook",
                "destination_type": "webhook",
                "destination_config": {
                    "url": "https://hooks.example.com/apex",
                    "secret": "super-secret-token",
                    "token": "another-secret"
                }
            })),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{json}");
        assert_eq!(json["success"], true, "{json}");
        let id = json["data"]["id"].as_str().expect("stream id").to_string();
        // The response masks secrets.
        let body = json.to_string();
        assert!(
            !body.contains("super-secret-token"),
            "secret leaked: {body}"
        );
        assert!(!body.contains("another-secret"), "secret leaked: {body}");

        // The secret is encrypted at rest, not stored in the clear.
        let stored: String =
            sqlx::query_scalar("SELECT destination_config::text FROM ent_log_streams WHERE id=$1")
                .bind(Uuid::parse_str(&id).unwrap())
                .fetch_one(&h.db)
                .await
                .unwrap();
        assert!(
            !stored.contains("super-secret-token"),
            "at-rest leak: {stored}"
        );

        // Get/list/update/pause/resume/stats round-trips stay tenant-scoped.
        let (status, json) = call(
            &app,
            "GET",
            &format!("/log-streams/{id}"),
            Some(&h.token_a),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{json}");
        let (status, _) = call(
            &app,
            "GET",
            &format!("/log-streams/{id}"),
            Some(&h.token_b),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        let (status, _) = call(
            &app,
            "PUT",
            &format!("/log-streams/{id}"),
            Some(&h.token_a),
            Some(serde_json::json!({"name": "renamed"})),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let (status, _) = call(
            &app,
            "POST",
            &format!("/log-streams/{id}/pause"),
            Some(&h.token_a),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let (status, _) = call(
            &app,
            "POST",
            &format!("/log-streams/{id}/resume"),
            Some(&h.token_a),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let (status, _) = call(
            &app,
            "GET",
            &format!("/log-streams/{id}/stats"),
            Some(&h.token_a),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let (status, json) = call(
            &app,
            "GET",
            &format!("/log-streams/tenant/{tenant}"),
            Some(&h.token_a),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert!(json["data"]
            .as_array()
            .unwrap()
            .iter()
            .any(|s| s["id"] == id.as_str()));

        // SSRF: verifying a webhook pinned to a private/metadata address must
        // be refused — no outbound request is made.
        for private_url in [
            "https://127.0.0.1:9/hook",
            "https://169.254.169.254/latest/meta-data/",
            "https://10.0.0.1/hook",
            "https://[::1]/hook",
        ] {
            let (status, json) = call(
                &app,
                "POST",
                "/log-streams",
                Some(&h.token_a),
                Some(serde_json::json!({
                    "tenant_id": tenant,
                    "name": format!("ssrf {private_url}"),
                    "destination_type": "webhook",
                    "destination_config": {"url": private_url}
                })),
            )
            .await;
            assert_eq!(status, StatusCode::OK, "{json}");
            if json["success"] != true {
                continue;
            }
            let ssrf_id = json["data"]["id"].as_str().unwrap().to_string();
            let (status, json) = call(
                &app,
                "POST",
                &format!("/log-streams/{ssrf_id}/verify"),
                Some(&h.token_a),
                None,
            )
            .await;
            assert_eq!(status, StatusCode::OK, "{json}");
            assert_eq!(
                json["success"], false,
                "private destination must not verify: {json}"
            );
            // The refusal is a structured VERIFICATION_FAILED (the guard
            // either blocks the resolved private address or the resolution
            // itself fails) — never a success.
            assert_eq!(json["code"], "VERIFICATION_FAILED", "{json}");
            let _ = call(
                &app,
                "DELETE",
                &format!("/log-streams/{ssrf_id}"),
                Some(&h.token_a),
                None,
            )
            .await;
        }

        // Cleanup.
        let (status, _) = call(
            &app,
            "DELETE",
            &format!("/log-streams/{id}"),
            Some(&h.token_a),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let (status, _) = call(
            &app,
            "GET",
            &format!("/log-streams/{id}"),
            Some(&h.token_a),
            None,
        )
        .await;
        assert!(status.is_success() || status == StatusCode::NOT_FOUND);
    });
}

// ── Private deployments / IPs ───────────────────────────────────────────

#[test]
fn private_deploy_ip_pool_and_byoip_are_validated() {
    run(async {
        let Some(h) = harness().await else { return };
        let app = h.app.clone();
        let tenant = h.tenant_a.clone();

        let (status, json) = call(
            &app,
            "POST",
            "/deployments",
            Some(&h.token_a),
            Some(serde_json::json!({
                "tenant_id": tenant, "name": "adv-dedicated",
                "deployment_type": "dedicated", "region": "eu-west-1"
            })),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{json}");
        assert_eq!(json["success"], true, "{json}");
        let deployment_id = json["data"]["id"]
            .as_str()
            .expect("deployment id")
            .to_string();

        let (status, _) = call(
            &app,
            "GET",
            &format!("/deployments/{deployment_id}"),
            Some(&h.token_a),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let (status, _) = call(
            &app,
            "GET",
            &format!("/deployments/{deployment_id}"),
            Some(&h.token_b),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        let (status, _) = call(
            &app,
            "GET",
            &format!("/deployments/tenant/{tenant}"),
            Some(&h.token_a),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let (status, _) = call(
            &app,
            "POST",
            &format!("/deployments/{deployment_id}/provision"),
            Some(&h.token_a),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let (status, _) = call(
            &app,
            "GET",
            &format!("/deployments/{deployment_id}/health"),
            Some(&h.token_a),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        // Dedicated IP allocation is validated against the pool.
        let octet = (Uuid::new_v4().as_u128() % 100) as u8 + 100;
        let pool_ip = format!("198.51.100.{octet}");
        sqlx::query("DELETE FROM ent_dedicated_ips WHERE ip_address = $1::inet")
            .bind(&pool_ip)
            .execute(&h.db)
            .await
            .unwrap();
        sqlx::query("DELETE FROM ip_pool_available WHERE ip_address = $1::inet")
            .bind(&pool_ip)
            .execute(&h.db)
            .await
            .unwrap();
        sqlx::query("INSERT INTO ip_pool_available (ip_address, region, status) VALUES ($1::inet, 'eu', 'available')")
            .bind(&pool_ip)
            .execute(&h.db)
            .await
            .unwrap();

        let (status, json) = call(
            &app,
            "POST",
            "/ips/allocate",
            Some(&h.token_a),
            Some(serde_json::json!({
                "tenant_id": tenant, "ip_address": "203.0.113.250"
            })),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{json}");
        assert_eq!(json["success"], false, "off-pool IP must be refused");
        assert_eq!(json["code"], "IP_NOT_IN_POOL");

        let (status, json) = call(
            &app,
            "POST",
            "/ips/allocate",
            Some(&h.token_a),
            Some(serde_json::json!({
                "tenant_id": tenant, "deployment_id": deployment_id, "ip_address": pool_ip
            })),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{json}");
        assert_eq!(json["success"], true, "{json}");
        let ip_id = json["data"]["id"].as_str().expect("ip id").to_string();
        let (status, _) = call(
            &app,
            "GET",
            &format!("/ips/{ip_id}"),
            Some(&h.token_a),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        // Cross-tenant IP reads are refused.
        let (status, _) = call(
            &app,
            "GET",
            &format!("/ips/{ip_id}"),
            Some(&h.token_b),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        let (status, _) = call(
            &app,
            "GET",
            &format!("/ips/tenant/{tenant}?limit=0&offset=-1"),
            Some(&h.token_a),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        // Reputation for an address with no dedicated-IP row is a NOT_FOUND
        // result: real 404 with the not-found envelope (never a fake score).
        let (status, json) = call(
            &app,
            "GET",
            "/ips/reputation/203.0.113.7",
            Some(&h.token_a),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{json}");
        assert_eq!(json["code"], "NOT_FOUND");

        // BYOIP: malformed CIDRs are client errors (4xx), never 500.
        for bad_cidr in [
            "not-a-cidr",
            "203.0.113.10/28",
            "203.0.113.0/33",
            "10.0.0.0/",
        ] {
            let (status, json) = call(
                &app,
                "POST",
                "/ips/byoip",
                Some(&h.token_a),
                Some(serde_json::json!({"tenant_id": tenant, "cidr_block": bad_cidr})),
            )
            .await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{bad_cidr}: {json}");
        }
        // BYOIP: registration issues a token; a wrong token never verifies.
        let network = (Uuid::new_v4().as_u128() % 32) as u8 * 8;
        let cidr = format!("203.0.113.{network}/29");
        let (status, json) = call(
            &app,
            "POST",
            "/ips/byoip",
            Some(&h.token_a),
            Some(serde_json::json!({"tenant_id": tenant, "cidr_block": cidr})),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{json}");
        assert_eq!(json["success"], true, "{json}");
        let range_id = json["data"]["id"].as_str().expect("range id").to_string();
        let (status, json) = call(
            &app,
            "POST",
            &format!("/ips/byoip/{range_id}/verify"),
            Some(&h.token_a),
            Some(serde_json::json!({"verification_token": "wrong-token"})),
        )
        .await;
        // A failed verification is a STATE conflict (409), not a 200 with
        // success:false — the earlier version of this assertion pinned the
        // status lie the service_result mapping was fixed to remove.
        assert_eq!(status, StatusCode::CONFLICT, "{json}");
        assert_ne!(json["success"], true, "wrong token must not verify: {json}");
    });
}

// ── Sub-accounts ────────────────────────────────────────────────────────

#[test]
fn sub_accounts_and_api_keys_enforce_lifecycle_and_tenant_bounds() {
    run(async {
        let Some(h) = harness().await else { return };
        let app = h.app.clone();
        let tenant = h.tenant_a.clone();

        let (status, json) = call(
            &app,
            "POST",
            "/sub-accounts",
            Some(&h.token_a),
            Some(serde_json::json!({
                "parent_id": tenant, "name": "Adv Sub", "email": "sub@example.com",
                "plan": "starter", "volume_limit": 1000
            })),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{json}");
        assert_eq!(json["success"], true, "{json}");
        let sub_id = json["data"]["id"].as_str().expect("sub id").to_string();

        let (status, _) = call(
            &app,
            "GET",
            &format!("/sub-accounts/{sub_id}"),
            Some(&h.token_a),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let (status, _) = call(
            &app,
            "GET",
            &format!("/sub-accounts/{sub_id}"),
            Some(&h.token_b),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "cross-parent read refused");
        let (status, _) = call(
            &app,
            "PUT",
            &format!("/sub-accounts/{sub_id}"),
            Some(&h.token_a),
            Some(serde_json::json!({"name": "Renamed Sub", "volume_limit": 2000})),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let (status, _) = call(
            &app,
            "GET",
            &format!("/sub-accounts/parent/{tenant}?status=active"),
            Some(&h.token_a),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let (status, _) = call(
            &app,
            "GET",
            &format!("/sub-accounts/stats/{tenant}"),
            Some(&h.token_a),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        // API key lifecycle: the raw key is returned once, list is masked, and
        // revocation invalidates verification.
        let (status, json) = call(
            &app,
            "POST",
            &format!("/sub-accounts/{sub_id}/api-keys"),
            Some(&h.token_a),
            Some(serde_json::json!({"name": "adv key", "permissions": ["send"]})),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{json}");
        assert_eq!(json["success"], true, "{json}");
        let raw_key = json["data"]["key"].as_str().expect("raw key").to_string();
        let key_id = json["data"]["id"].as_str().expect("key id").to_string();

        let (status, json) = call(
            &app,
            "GET",
            &format!("/sub-accounts/{sub_id}/api-keys"),
            Some(&h.token_a),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let listed = json["data"].as_array().unwrap();
        assert!(listed.iter().any(|k| k["id"] == key_id.as_str()));
        assert!(
            !json.to_string().contains(&raw_key),
            "raw key must not be listed"
        );

        let (status, _) = call(
            &app,
            "POST",
            &format!("/sub-accounts/{sub_id}/api-keys/{key_id}/revoke"),
            Some(&h.token_a),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let revoked: bool =
            sqlx::query_scalar("SELECT revoked FROM ent_sub_account_api_keys WHERE id=$1")
                .bind(Uuid::parse_str(&key_id).unwrap())
                .fetch_one(&h.db)
                .await
                .unwrap();
        assert!(revoked, "revocation must be persisted");

        // Suspension then deletion; the sub-account is gone afterwards.
        let (status, _) = call(
            &app,
            "POST",
            &format!("/sub-accounts/{sub_id}/suspend"),
            Some(&h.token_a),
            Some(serde_json::json!({"reason": "adversarial"})),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let (status, _) = call(
            &app,
            "DELETE",
            &format!("/sub-accounts/{sub_id}"),
            Some(&h.token_a),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let (status, json) = call(
            &app,
            "GET",
            &format!("/sub-accounts/{sub_id}"),
            Some(&h.token_a),
            None,
        )
        .await;
        assert_eq!(
            status,
            StatusCode::NOT_FOUND,
            "a not-found result is a real 404: {json}"
        );
        assert_eq!(json["success"], false, "deleted sub-account is not found");
    });
}

// ── Templates / white-label / QBR ───────────────────────────────────────

#[test]
fn templates_whitelabel_and_qbr_flows_are_tenant_scoped() {
    run(async {
        let Some(h) = harness().await else { return };
        let app = h.app.clone();
        let tenant = h.tenant_a.clone();

        // Templates: submit → get → list → admin review.
        let (status, json) = call(
            &app,
            "POST",
            "/templates/submit",
            Some(&h.token_a),
            Some(serde_json::json!({
                "tenant_id": tenant, "name": "Adv Template", "subject": "Hello",
                "html_content": "<h1>Hi</h1>", "submitted_by": h.user_a.clone()
            })),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{json}");
        assert_eq!(json["success"], true, "{json}");
        let template_id = json["data"]["id"]
            .as_str()
            .expect("template id")
            .to_string();
        let (status, _) = call(
            &app,
            "GET",
            &format!("/templates/{template_id}"),
            Some(&h.token_a),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let (status, _) = call(
            &app,
            "GET",
            &format!("/templates/{template_id}"),
            Some(&h.token_b),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        let (status, _) = call(
            &app,
            "GET",
            &format!("/templates/tenant/{tenant}?limit=1000"),
            Some(&h.token_a),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        // Approve requires admin.
        let (status, _) = call(
            &app,
            "POST",
            &format!("/templates/{template_id}/approve"),
            Some(&h.token_a),
            Some(serde_json::json!({"reviewed_by": h.user_a.clone()})),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        let (status, _) = call(
            &app,
            "POST",
            &format!("/templates/{template_id}/approve"),
            Some(&h.admin_token),
            Some(serde_json::json!({"reviewed_by": h.admin_a.clone(), "notes": "ok"})),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let (status, _) = call(
            &app,
            "GET",
            &format!("/templates/stats/{tenant}"),
            Some(&h.token_a),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        // White-label config + domain add; verification uses the injectable
        // lookup so no real DNS is needed.
        let (status, _) = call(
            &app,
            "PUT",
            "/whitelabel/config",
            Some(&h.token_a),
            Some(serde_json::json!({
                "tenant_id": tenant, "company_name": "Adv Corp", "primary_color": "#123456"
            })),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let (status, json) = call(
            &app,
            "GET",
            &format!("/whitelabel/config/{tenant}"),
            Some(&h.token_a),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["data"]["company_name"], "Adv Corp", "{json}");
        let (status, _) = call(
            &app,
            "GET",
            &format!("/whitelabel/config/{tenant}"),
            Some(&h.token_b),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);

        let domain = format!("adv-{}.example.com", Uuid::new_v4().simple());
        let (status, json) = call(
            &app,
            "POST",
            "/whitelabel/domains",
            Some(&h.token_a),
            Some(serde_json::json!({
                "tenant_id": tenant, "domain": domain, "domain_type": "tracking"
            })),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{json}");
        let domain_id: Uuid = json["data"]["id"].as_str().unwrap().parse().unwrap();
        let token = json["data"]["verification_token"]
            .as_str()
            .unwrap()
            .to_string();
        let service = enterprise::whitelabel::WhiteLabelService::new(h.db.clone());
        let failed = service
            .verify_domain_with_lookup(domain_id, |_| async { Ok(vec!["v=spf1".to_string()]) })
            .await
            .unwrap();
        assert_eq!(failed.data.unwrap().verification_status, "failed");
        let verified = service
            .verify_domain_with_lookup(domain_id, move |_| {
                let record = format!("apexmail-verification={token}");
                async move { Ok(vec![record]) }
            })
            .await
            .unwrap();
        assert_eq!(verified.data.unwrap().verification_status, "verified");

        // QBR: schedule → get → list → generate → deliver → feedback → goals →
        // benchmarks → pdf → DPA pdf.
        let (status, json) = call(
            &app,
            "POST",
            "/qbr",
            Some(&h.token_a),
            Some(serde_json::json!({
                "tenant_id": tenant, "quarter": 3, "year": 2026,
                "attendees": [{"name": "Alice"}]
            })),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{json}");
        assert_eq!(json["success"], true, "{json}");
        let qbr_id = json["data"]["id"].as_str().expect("qbr id").to_string();
        let (status, _) = call(
            &app,
            "GET",
            &format!("/qbr/{qbr_id}"),
            Some(&h.token_a),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let (status, _) = call(
            &app,
            "GET",
            &format!("/qbr/{qbr_id}"),
            Some(&h.token_b),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        let (status, _) = call(
            &app,
            "GET",
            &format!("/qbr/tenant/{tenant}"),
            Some(&h.token_a),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let (status, _) = call(
            &app,
            "POST",
            &format!("/qbr/{qbr_id}/generate"),
            Some(&h.token_a),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let (status, _) = call(
            &app,
            "POST",
            &format!("/qbr/{qbr_id}/deliver"),
            Some(&h.token_a),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let (status, _) = call(
            &app,
            "POST",
            &format!("/qbr/{qbr_id}/feedback"),
            Some(&h.token_a),
            Some(serde_json::json!({"rating": 5, "feedback_text": "solid"})),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let (status, _) = call(&app, "GET", "/qbr/benchmarks", Some(&h.token_a), None).await;
        assert_eq!(status, StatusCode::OK);
        // NOTE: /qbr/:id/pdf and /dpa/:tenant_id/pdf are exercised by
        // `pdf_routes_require_a_configured_and_reachable_renderer` against an
        // in-process mock renderer (PDF_RENDERER_URL is read per call).
    });
}

// ── SSO routes + SAML rejections ────────────────────────────────────────

#[test]
fn sso_routes_and_saml_validation_reject_unsigned_and_mismatched_responses() {
    run(async {
        let Some(h) = harness().await else { return };
        let app = h.app.clone();
        let tenant = h.tenant_a.clone();
        let domain = format!("sso-{}.example.com", Uuid::new_v4().simple());

        // Malformed SSO configuration is rejected honestly.
        let (status, _) = call(
            &app,
            "POST",
            "/sso/configure",
            Some(&h.token_a),
            Some(serde_json::json!({"tenant_id": tenant, "provider_type": "saml"})),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);

        // The login-initiation endpoints fail fast (no ACS wired).
        let (status, _) = call(
            &app,
            "GET",
            &format!("/sso/login/saml/{domain}"),
            None,
            None,
        )
        .await;
        assert_eq!(status, StatusCode::NOT_IMPLEMENTED);
        let (status, _) = call(
            &app,
            "GET",
            &format!("/sso/login/oidc/{domain}"),
            None,
            None,
        )
        .await;
        assert_eq!(status, StatusCode::NOT_IMPLEMENTED);

        // Configuring with a certificate that is not a valid X.509 PEM must
        // not silently enable signature-less validation.
        let (status, json) = call(
            &app,
            "POST",
            "/sso/configure",
            Some(&h.token_a),
            Some(serde_json::json!({
                "tenant_id": tenant,
                "provider_type": "saml",
                "domain": domain,
                "enabled": true,
                "entity_id": "urn:adv:idp",
                "sso_url": "https://idp.example.com/sso",
                "certificate": "not-a-certificate"
            })),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{json}");

        let (status, json) = call(
            &app,
            "GET",
            &format!("/sso/config/{tenant}"),
            Some(&h.token_a),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{json}");
        // The SAML certificate is never echoed back to clients.
        assert!(!json.to_string().contains("not-a-certificate"), "{json}");
        let (status, _) = call(
            &app,
            "GET",
            &format!("/sso/config/{tenant}"),
            Some(&h.token_b),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        let (status, _) = call(
            &app,
            "GET",
            &format!("/sso/config/domain/{domain}"),
            Some(&h.token_b),
            None,
        )
        .await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "domain resolves to its tenant"
        );

        // An unsigned SAML response is rejected outright (signature first).
        let unsigned = format!(
            r#"<?xml version="1.0"?>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_r1" Version="2.0" IssueInstant="{now}">
  <saml:Issuer>urn:adv:idp</saml:Issuer>
  <samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>
  <saml:Assertion ID="_a1" IssueInstant="{now}">
    <saml:Issuer>urn:adv:idp</saml:Issuer>
    <saml:Subject><saml:NameID>victim@example.com</saml:NameID></saml:Subject>
    <saml:Conditions NotOnOrAfter="{later}">
      <saml:AudienceRestriction><saml:Audience>https://apexmail.ee/api/sso/saml/callback</saml:Audience></saml:AudienceRestriction>
    </saml:Conditions>
  </saml:Assertion>
</samlp:Response>"#,
            now = chrono::Utc::now().to_rfc3339(),
            later = (chrono::Utc::now() + chrono::Duration::hours(1)).to_rfc3339(),
        );
        let sso = enterprise::sso::SSOService::new(h.db.clone(), {
            let mut config = Config::from_env().expect("config");
            config.jwt_public_key_pem = TEST_PUBLIC_PEM.to_string();
            config
        });
        let error = match sso
            .parse_and_validate_saml_response(&unsigned, &domain)
            .await
        {
            Ok(_) => panic!("unsigned SAML response must be rejected"),
            Err(error) => error,
        };
        let lower = error.to_lowercase();
        assert!(
            lower.contains("signature") || lower.contains("cert"),
            "unexpected rejection reason: {error}"
        );

        // Entity-expansion (billion laughs) input is never expanded: quick-xml
        // does not resolve entities and the signature check precedes parsing.
        let xxe = format!(
            r#"<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY a "aaaa"><!ENTITY b "&a;&a;&a;&a;">]>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_r2" Version="2.0" IssueInstant="{now}">
  <saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">&b;</saml:Issuer>
</samlp:Response>"#,
            now = chrono::Utc::now().to_rfc3339(),
        );
        assert!(sso
            .parse_and_validate_saml_response(&xxe, &domain)
            .await
            .is_err());

        // Session validation endpoints behave honestly.
        let (status, _) = call(&app, "GET", "/sso/validate", None, None).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "missing bearer session");
        let (status, _) = call(&app, "GET", "/sso/validate", Some("garbage-session"), None).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        let (status, json) = call(&app, "POST", "/sso/cleanup", Some(&h.admin_token), None).await;
        assert_eq!(status, StatusCode::OK);
        assert!(json["cleaned"].is_number());

        // A session created for a configured SSO config validates and then can
        // be cleaned up when expired.
        let callback = sso
            .handle_saml_callback(
                &tenant,
                "alice@sso.example.com",
                Some("Alice"),
                "ext-1",
                None,
                None,
            )
            .await
            .expect("callback")
            .data
            .expect("session");
        let (status, _) = call(
            &app,
            "GET",
            "/sso/validate",
            Some(&callback.session.session_token),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        sqlx::query("UPDATE ent_sso_sessions SET expires_at = NOW() - INTERVAL '1 hour' WHERE session_token=$1")
            .bind(&callback.session.session_token)
            .execute(&h.db)
            .await
            .unwrap();
        let cleaned = sso.cleanup_expired_sessions().await.unwrap();
        assert!(cleaned >= 1);
        let (status, _) = call(
            &app,
            "GET",
            "/sso/validate",
            Some(&callback.session.session_token),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "expired session refused");
    });
}

// ── HTTP status honesty ────────────────────────────────────────────────

/// A NOT_FOUND service result must surface as HTTP 404 — not as HTTP 200
/// with `{"success":false}`, which lies to any client checking
/// `response.ok`. The ApiResult envelope itself is unchanged (`success`,
/// `error`, `code` still present).
#[test]
fn not_found_service_results_become_404_with_the_same_envelope() {
    run(async {
        let Some(h) = harness().await else { return };
        let app = h.app.clone();
        // A dedicated tenant with no compliance/white-label/... rows yet.
        let tenant = format!("n{}", &Uuid::new_v4().simple().to_string()[..25]);
        sqlx::query(
            "INSERT INTO tenants (id, name, slug, plan, status, settings, metadata, created_at, updated_at) \
             VALUES ($1, $1, $1, 'free', 'active', '{}'::jsonb, '{}'::jsonb, NOW(), NOW()) \
             ON CONFLICT (id) DO NOTHING",
        )
        .bind(&tenant)
        .execute(&h.db)
        .await
        .expect("seed not-found tenant");
        let token = mint_token(&tenant, "not-found-user", false);
        let admin = mint_token(&tenant, "not-found-admin", true);
        let missing = Uuid::new_v4();

        // Routes whose service result cannot distinguish "not found" are
        // intentionally unchanged (per the fix scope): `/log-streams/:id/stats`
        // returns `success:true` with zeroed stats for any id,
        // `/deployments/:id/provision` reports INVALID_STATE ("not found or
        // not pending"), `/whitelabel/email-templates/:tenant` returns an
        // empty successful list, and log-stream `verify`'s VERIFICATION_FAILED
        // is a completed negative check (pinned at 200 by the SSRF test).
        let cases: Vec<(&str, String, Option<serde_json::Value>, bool)> = vec![
            ("GET", format!("/compliance/config/{tenant}"), None, false),
            ("GET", format!("/compliance/report/{tenant}"), None, false),
            (
                "POST",
                format!("/compliance/data-access/{missing}/approve"),
                Some(serde_json::json!({
                    "approved_by": "probe", "duration_minutes": 5
                })),
                false,
            ),
            ("GET", format!("/log-streams/{missing}"), None, false),
            ("POST", format!("/log-streams/{missing}/pause"), None, false),
            (
                "POST",
                format!("/log-streams/{missing}/resume"),
                None,
                false,
            ),
            (
                "POST",
                format!("/log-streams/{missing}/verify"),
                None,
                false,
            ),
            (
                "PUT",
                format!("/log-streams/{missing}"),
                Some(serde_json::json!({})),
                false,
            ),
            ("DELETE", format!("/log-streams/{missing}"), None, false),
            ("GET", format!("/deployments/{missing}"), None, false),
            ("GET", format!("/ips/{missing}"), None, false),
            ("GET", format!("/sub-accounts/{missing}"), None, false),
            (
                "PUT",
                format!("/sub-accounts/{missing}"),
                Some(serde_json::json!({})),
                false,
            ),
            (
                "POST",
                format!("/sub-accounts/{missing}/suspend"),
                Some(serde_json::json!({})),
                false,
            ),
            ("DELETE", format!("/sub-accounts/{missing}"), None, false),
            (
                "GET",
                format!("/sub-accounts/{missing}/api-keys"),
                None,
                false,
            ),
            (
                "POST",
                format!("/sub-accounts/{missing}/api-keys/{}/revoke", Uuid::new_v4()),
                None,
                false,
            ),
            ("GET", format!("/templates/{missing}"), None, false),
            (
                "POST",
                format!("/templates/{missing}/approve"),
                Some(serde_json::json!({"reviewed_by": "probe"})),
                true,
            ),
            (
                "POST",
                format!("/templates/{missing}/reject"),
                Some(serde_json::json!({"reviewed_by": "probe", "reason": "probe"})),
                true,
            ),
            (
                "POST",
                format!("/templates/{missing}/request-changes"),
                Some(serde_json::json!({"reviewed_by": "probe", "notes": "probe"})),
                true,
            ),
            ("GET", format!("/whitelabel/config/{tenant}"), None, false),
            (
                "POST",
                format!("/whitelabel/domains/{missing}/verify"),
                None,
                false,
            ),
            (
                "DELETE",
                format!("/whitelabel/domains/{tenant}/{missing}"),
                None,
                false,
            ),
            ("GET", format!("/qbr/{missing}"), None, false),
            ("POST", format!("/qbr/{missing}/generate"), None, false),
            ("POST", format!("/qbr/{missing}/deliver"), None, false),
            (
                "POST",
                format!("/qbr/{missing}/feedback"),
                Some(serde_json::json!({"rating": 4})),
                false,
            ),
            (
                "PUT",
                format!("/qbr/{missing}/goals"),
                Some(serde_json::json!({
                    "goal_id": Uuid::new_v4(), "current_value": 1.0
                })),
                false,
            ),
        ];

        for (method, path, body, use_admin) in cases {
            let caller = if use_admin { &admin } else { &token };
            let (status, json) = call(&app, method, &path, Some(caller), body).await;
            assert_eq!(status, StatusCode::NOT_FOUND, "{method} {path}: {json}");
            // The envelope keeps its shape and fields.
            assert_eq!(json["success"], false, "{method} {path}: {json}");
            assert!(
                json["error"].is_string(),
                "{method} {path} must keep the error message: {json}"
            );
            assert_eq!(json["code"], "NOT_FOUND", "{method} {path}: {json}");
        }

        // INVALID_IP is a client validation failure: real 400, same envelope.
        let (status, json) = call(
            &app,
            "POST",
            "/ips/allocate",
            Some(&token),
            Some(serde_json::json!({
                "tenant_id": tenant, "ip_address": "not-an-ip"
            })),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{json}");
        assert_eq!(json["success"], false);
        assert_eq!(json["code"], "INVALID_IP");
    });
}

/// Raw-response variant of [`call`] for binary payloads (PDF bytes).
async fn call_raw(
    app: &Router,
    method: &str,
    path: &str,
    token: Option<&str>,
    body: Option<serde_json::Value>,
) -> (StatusCode, Option<String>, Vec<u8>) {
    let mut builder = Request::builder().method(method).uri(path);
    if let Some(token) = token {
        builder = builder.header("authorization", format!("Bearer {token}"));
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
    let content_type = response
        .headers()
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .map(str::to_string);
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap_or_default()
        .to_vec();
    (status, content_type, bytes)
}

/// `PDF_RENDERER_URL` is read per call. Unconfigured rendering is a precise
/// 503 (not a misleading 502 gateway error), a configured-but-unreachable
/// renderer is a loud 502 with no partial write, and a reachable renderer's
/// bytes are returned verbatim with the PDF content type.
#[test]
fn pdf_routes_require_a_configured_and_reachable_renderer() {
    run(async {
        let Some(h) = harness().await else { return };
        let app = h.app.clone();

        // A QBR the caller's tenant owns, for the happy-path render.
        let qbr = enterprise::qbr::QBRService::new(h.db.clone())
            .schedule(h.tenant_a.clone(), 1, 2026, None, None)
            .await
            .expect("schedule QBR")
            .data
            .expect("scheduled QBR");
        let dpa_path = format!("/dpa/{}/pdf", h.tenant_a);

        // Phase 1: unconfigured → precise 503, NOT a 502 gateway error.
        std::env::remove_var("PDF_RENDERER_URL");
        let (status, content_type, body) = call_raw(
            &app,
            "POST",
            &dpa_path,
            Some(&h.token_a),
            Some(serde_json::json!({})),
        )
        .await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body:?}");
        assert_ne!(content_type.as_deref(), Some("application/pdf"));
        let text = String::from_utf8_lossy(&body);
        assert!(
            text.contains("not configured") && text.contains("PDF_RENDERER_URL"),
            "operator must be told exactly what is missing: {text}"
        );

        // Phase 2: configured + unreachable → loud 502, no partial write.
        let dead_port = {
            let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).expect("bind probe");
            listener.local_addr().expect("probe addr").port()
        };
        std::env::set_var("PDF_RENDERER_URL", format!("http://127.0.0.1:{dead_port}"));
        let (status, content_type, body) = call_raw(
            &app,
            "POST",
            &dpa_path,
            Some(&h.token_a),
            Some(serde_json::json!({})),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_GATEWAY, "{body:?}");
        assert!(
            String::from_utf8_lossy(&body).contains("unreachable"),
            "failure must name the renderer: {:?}",
            String::from_utf8_lossy(&body)
        );
        assert!(!body.starts_with(b"%PDF"), "no partial write on failure");
        assert_ne!(content_type.as_deref(), Some("application/pdf"));

        // Phase 3: configured + reachable in-process mock → real bytes.
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("bind mock renderer");
        let addr = listener.local_addr().expect("mock addr");
        let mock_pdf = b"%PDF-1.4 in-process mock".to_vec();
        let mock = Router::new().route(
            "/v1/pdf/render",
            axum::routing::post({
                let mock_pdf = mock_pdf.clone();
                move || {
                    let pdf = mock_pdf.clone();
                    async move { ([(axum::http::header::CONTENT_TYPE, "application/pdf")], pdf) }
                }
            }),
        );
        let server = tokio::spawn(async move {
            let _ = axum::serve(listener, mock).await;
        });
        std::env::set_var("PDF_RENDERER_URL", format!("http://{addr}"));

        let (status, content_type, body) = call_raw(
            &app,
            "GET",
            &format!("/qbr/{}/pdf", qbr.id),
            Some(&h.token_a),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body:?}");
        assert_eq!(content_type.as_deref(), Some("application/pdf"));
        assert_eq!(body, mock_pdf, "the renderer bytes are returned verbatim");

        // The DPA path shares the same renderer plumbing.
        let (status, content_type, body) = call_raw(
            &app,
            "POST",
            &dpa_path,
            Some(&h.token_a),
            Some(serde_json::json!({})),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body:?}");
        assert_eq!(content_type.as_deref(), Some("application/pdf"));
        assert_eq!(body, mock_pdf);

        server.abort();
        std::env::remove_var("PDF_RENDERER_URL");
    });
}

/// SAML assertions must be replay-protected (per tenant) and tolerate a
/// bounded clock-skew window on NotBefore/NotOnOrAfter. Both are enforced by
/// [`SSOService::validate_saml_assertion_claims`], which
/// `parse_and_validate_saml_response` calls after the XML signature, issuer,
/// audience and NameID checks have passed.
#[test]
fn saml_assertion_replay_and_clock_skew_are_enforced() {
    run(async {
        let Some(h) = harness().await else { return };
        let sso = enterprise::sso::SSOService::new(
            h.db.clone(),
            Config::from_env().expect("Config::from_env"),
        );
        let tenant = format!("z{}", &Uuid::new_v4().simple().to_string()[..25]);
        let other_tenant = format!("y{}", &Uuid::new_v4().simple().to_string()[..25]);
        let now = chrono::Utc::now();
        let in_5_min = now + chrono::TimeDelta::try_minutes(5).unwrap();
        let new_id = || format!("_assertion_{}", Uuid::new_v4().simple());

        // Replay: the same assertion id is consumed exactly once.
        let replay_id = new_id();
        sso.validate_saml_assertion_claims(&tenant, &replay_id, None, Some(in_5_min), now)
            .await
            .expect("first use of an assertion id is accepted");
        let error = sso
            .validate_saml_assertion_claims(&tenant, &replay_id, None, Some(in_5_min), now)
            .await
            .expect_err("a replayed assertion must be refused");
        assert!(
            error.to_lowercase().contains("replay") || error.contains("already"),
            "replay refusal must say so: {error}"
        );

        // The replay store is scoped to the configured tenant: the same id is
        // still fresh for another tenant.
        sso.validate_saml_assertion_claims(&other_tenant, &replay_id, None, Some(in_5_min), now)
            .await
            .expect("replay ids are tenant-scoped");

        // NotBefore: 60s of skew is tolerated, 10 minutes is not.
        sso.validate_saml_assertion_claims(
            &tenant,
            &new_id(),
            Some(now + chrono::TimeDelta::try_seconds(60).unwrap()),
            Some(in_5_min),
            now,
        )
        .await
        .expect("NotBefore 60s in the future is within the skew window");
        let error = sso
            .validate_saml_assertion_claims(
                &tenant,
                &new_id(),
                Some(now + chrono::TimeDelta::try_minutes(10).unwrap()),
                Some(in_5_min),
                now,
            )
            .await
            .expect_err("NotBefore 10 minutes in the future must be refused");
        assert!(
            error.contains("not yet valid") || error.contains("NotBefore"),
            "NotBefore refusal must say so: {error}"
        );

        // NotOnOrAfter: 60s in the past is tolerated (skew), 10 minutes is not.
        sso.validate_saml_assertion_claims(
            &tenant,
            &new_id(),
            None,
            Some(now - chrono::TimeDelta::try_seconds(60).unwrap()),
            now,
        )
        .await
        .expect("NotOnOrAfter 60s in the past is within the skew window");
        let error = sso
            .validate_saml_assertion_claims(
                &tenant,
                &new_id(),
                None,
                Some(now - chrono::TimeDelta::try_minutes(10).unwrap()),
                now,
            )
            .await
            .expect_err("NotOnOrAfter 10 minutes in the past must be refused");
        assert!(
            error.contains("expired") || error.contains("NotOnOrAfter"),
            "expiry refusal must say so: {error}"
        );

        // An assertion with no ID cannot be replay-protected → fail closed.
        let error = sso
            .validate_saml_assertion_claims(&tenant, "", None, Some(in_5_min), now)
            .await
            .expect_err("an id-less assertion must be refused");
        assert!(
            error.contains("ID") || error.to_lowercase().contains("missing"),
            "id-less refusal must say so: {error}"
        );
    });
}
