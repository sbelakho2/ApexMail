//! Security regression tests for the enterprise service.
//!
//! These tests exercise the HTTP surface end-to-end against a real Postgres
//! instance when one is available. The target database is taken from
//! `ENTERPRISE_TEST_DATABASE_URL` (F6: no localhost default — an ambient
//! brew/compose postgres on 5432 must not be probed implicitly; CI points
//! the variable at an ephemeral container). When the variable is unset or
//! the database is unreachable the tests **skip** (print a SKIP notice
//! and return) so `cargo test` stays green in environments without Postgres.
//!
//! Schema bootstrap: the repo migrations that create the enterprise tables
//! (022, 023, 043, 092) are executed idempotently against the target DB, plus
//! a minimal `tenants` table when absent.

use axum::{
    body::Body,
    http::{Request, StatusCode},
    Router,
};
use metrics_exporter_prometheus::PrometheusBuilder;
use sqlx::PgPool;
use std::sync::Arc;
use tower::ServiceExt;
use uuid::Uuid;

use enterprise::config::Config;
use enterprise::routes::{router, AppState};

const TEST_PRIVATE_PEM: &str = include_str!("keys/test_rsa_private.pem");
const TEST_PUBLIC_PEM: &str = include_str!("keys/test_rsa_public.pem");

// ── Harness ─────────────────────────────────────────────────────────────────

struct TestApp {
    app: Router,
    db: PgPool,
    tenant_a: String,
    tenant_b: String,
    /// UUID-shaped tenant ids for the tables whose tenant_id columns are
    /// UUID (ent_private_deployments / ent_dedicated_ips / ent_byoip_ranges).
    uuid_tenant_a: String,
    uuid_tenant_b: String,
}

impl TestApp {
    fn token(&self, tenant: &str, admin: bool) -> String {
        mint_token(tenant, admin, None, None)
    }

    fn token_with(tenant: &str, admin: bool, aud: Option<&str>, iss: Option<&str>) -> String {
        mint_token(tenant, admin, aud, iss)
    }

    async fn get(&self, path: &str, token: &str) -> (StatusCode, serde_json::Value) {
        self.request(reqwest::Method::GET, path, token, None).await
    }

    async fn post(
        &self,
        path: &str,
        token: &str,
        body: Option<serde_json::Value>,
    ) -> (StatusCode, serde_json::Value) {
        self.request(reqwest::Method::POST, path, token, body).await
    }

    async fn put(
        &self,
        path: &str,
        token: &str,
        body: Option<serde_json::Value>,
    ) -> (StatusCode, serde_json::Value) {
        self.request(reqwest::Method::PUT, path, token, body).await
    }

    async fn request(
        &self,
        method: reqwest::Method,
        path: &str,
        token: &str,
        body: Option<serde_json::Value>,
    ) -> (StatusCode, serde_json::Value) {
        let mut builder = Request::builder()
            .method(method.as_str())
            .uri(path)
            .header("authorization", format!("Bearer {token}"));
        let request = if let Some(body) = body {
            builder = builder.header("content-type", "application/json");
            builder.body(Body::from(body.to_string())).unwrap()
        } else {
            builder.body(Body::empty()).unwrap()
        };
        let response = self.app.clone().oneshot(request).await.unwrap();
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
}

fn mint_token(tenant: &str, admin: bool, aud: Option<&str>, iss: Option<&str>) -> String {
    #[derive(serde::Serialize)]
    struct Claims<'a> {
        sub: &'a str,
        tenant_id: &'a str,
        admin: bool,
        #[serde(skip_serializing_if = "Option::is_none")]
        aud: Option<&'a str>,
        #[serde(skip_serializing_if = "Option::is_none")]
        iss: Option<&'a str>,
        exp: usize,
    }
    let claims = Claims {
        sub: "user-test-subject",
        tenant_id: tenant,
        admin,
        aud,
        iss,
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

const EXTRA_DDL: &str = r#"
CREATE TABLE IF NOT EXISTS tenants (
    id VARCHAR(26) PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    slug VARCHAR(100) NOT NULL DEFAULT '',
    plan VARCHAR(50) NOT NULL DEFAULT 'free',
    status VARCHAR(20) NOT NULL DEFAULT 'active',
    settings JSONB NOT NULL DEFAULT '{}',
    metadata JSONB NOT NULL DEFAULT '{}',
    legal_hold BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
"#;

async fn try_setup() -> Option<TestApp> {
    // F6: no localhost default — an ambient brew/compose postgres on 5432
    // must not be probed implicitly (CI points this variable at an ephemeral
    // container; unset means skip).
    let url = std::env::var("ENTERPRISE_TEST_DATABASE_URL").ok()?;

    let db = match tokio::time::timeout(
        std::time::Duration::from_secs(3),
        sqlx::postgres::PgPoolOptions::new()
            .max_connections(5)
            .connect(&url),
    )
    .await
    {
        Ok(Ok(pool)) => pool,
        _ => {
            eprintln!("SKIP: test database unavailable at {url}");
            return None;
        }
    };

    // Bootstrap schema: run the enterprise migrations idempotently.
    let manifest = env!("CARGO_MANIFEST_DIR");
    for migration in [
        "022_enterprise_billing_contracts.sql",
        "023_enterprise_support_sso.sql",
        "043_enterprise_private_deploy.sql",
        "092_enterprise_missing_tables.sql",
    ] {
        let path = format!("{manifest}/../../migrations/{migration}");
        let Ok(sql) = tokio::fs::read_to_string(&path).await else {
            eprintln!("SKIP: migration file missing: {path}");
            return None;
        };
        // Statements are separated by semicolons; the migrations use plain
        // SQL (plus DO $$ blocks which must stay whole). Execute statement by
        // statement, ignoring "already exists" style errors (idempotency).
        execute_loose(&db, &sql).await;
    }
    execute_loose(&db, EXTRA_DDL).await;

    let mut config = Config::from_env().expect("Config::from_env");
    config.jwt_public_key_pem = TEST_PUBLIC_PEM.to_string();
    config.jwt_audience = None; // default harness: no pinning
    config.jwt_issuer = None;
    config.metrics_token = None;
    config.log_stream.encryption_key = "test-log-stream-secret-key".to_string();

    let recorder = PrometheusBuilder::new().build_recorder();
    let state = Arc::new(AppState::new(db.clone(), config, recorder.handle()));
    let app = router(state);

    Some(TestApp {
        app,
        db,
        tenant_a: format!("t{}", &Uuid::new_v4().simple().to_string()[..25]),
        tenant_b: format!("t{}", &Uuid::new_v4().simple().to_string()[..25]),
        uuid_tenant_a: Uuid::new_v4().to_string(),
        uuid_tenant_b: Uuid::new_v4().to_string(),
    })
}

/// Execute semi-colon separated SQL, tolerating errors (idempotent bootstrap).
async fn execute_loose(db: &PgPool, sql: &str) {
    // Split on ";" but keep $$ .. $$ blocks intact.
    let mut statements: Vec<String> = Vec::new();
    let mut current = String::new();
    let mut dollar_depth = 0usize;
    let mut chars = sql.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '$' {
            let is_dollar_tag_start = chars.peek() == Some(&'$');
            if is_dollar_tag_start {
                chars.next();
                if dollar_depth == 0 {
                    dollar_depth = 1;
                    current.push_str("$$");
                    continue;
                } else {
                    dollar_depth = 0;
                    current.push_str("$$");
                    continue;
                }
            }
            current.push('$');
            continue;
        }
        if c == ';' && dollar_depth == 0 {
            statements.push(current.clone());
            current.clear();
        } else {
            current.push(c);
        }
    }
    if !current.trim().is_empty() {
        statements.push(current);
    }
    for statement in statements {
        let statement = statement.trim();
        if statement.is_empty() || statement.starts_with("--") {
            continue;
        }
        let _: Result<_, _> = sqlx::query(statement).execute(db).await;
    }
}

async fn setup() -> Option<TestApp> {
    try_setup().await
}

/// Skip gracefully when the optional test database is not reachable.
fn skip_notice(test: &str) {
    eprintln!("SKIP [{test}]: no test database available");
}

// ── Fix A: cross-tenant by-ID access ────────────────────────────────────────

#[tokio::test]
async fn cross_tenant_by_id_handlers_are_blocked() {
    let Some(app) = setup().await else {
        skip_notice("test");
        return;
    };
    let a = app.token(&app.tenant_a, false);
    let b = app.token(&app.tenant_b, false);

    // Seed one resource of each vulnerable type as tenant A.
    let (status, stream) = app
        .post(
            "/log-streams",
            &a,
            Some(serde_json::json!({
                "tenant_id": app.tenant_a,
                "name": "a-stream",
                "destination_type": "webhook",
                "destination_config": {"url": "https://example.com/hook"}
            })),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "seed log stream failed: {stream}");
    let stream_id = stream["data"]["id"].as_str().unwrap().to_string();

    let uuid_a = app.token(&app.uuid_tenant_a, false);
    let uuid_b = app.token(&app.uuid_tenant_b, false);
    let (status, deployment) = app
        .post(
            "/deployments",
            &uuid_a,
            Some(serde_json::json!({
                "tenant_id": app.uuid_tenant_a,
                "name": "a-deploy",
                "deployment_type": "dedicated"
            })),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "seed deployment failed: {deployment}");
    let deploy_id = deployment["data"]["id"].as_str().unwrap().to_string();

    let (status, ticket) = app
        .post(
            "/support/tickets",
            &a,
            Some(serde_json::json!({
                "tenant_id": app.tenant_a,
                "subject": "s", "description": "d",
                "priority": "medium", "category": "general"
            })),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "seed ticket failed: {ticket}");
    let ticket_id = ticket["data"]["id"].as_str().unwrap().to_string();

    let (status, template) = app
        .post(
            "/templates/submit",
            &a,
            Some(serde_json::json!({
                "tenant_id": app.tenant_a, "name": "t", "subject": "s",
                "html_content": "<p>hi</p>", "submitted_by": "user1"
            })),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "seed template failed: {template}");
    let template_id = template["data"]["id"].as_str().unwrap().to_string();

    let (status, domain) = app
        .post(
            "/whitelabel/domains",
            &a,
            Some(serde_json::json!({
                "tenant_id": app.tenant_a, "domain": "cross-tenant-test.example.com",
                "domain_type": "tracking"
            })),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "seed domain failed: {domain}");
    let domain_id = domain["data"]["id"].as_str().unwrap().to_string();

    let (status, qbr) = app
        .post(
            "/qbr",
            &a,
            Some(serde_json::json!({"tenant_id": app.tenant_a, "quarter": 1, "year": 2026})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "seed qbr failed: {qbr}");
    let qbr_id = qbr["data"]["id"].as_str().unwrap().to_string();

    let (status, access_req) = app
        .post(
            "/compliance/data-access",
            &a,
            Some(serde_json::json!({
                "tenant_id": app.tenant_a, "requester_id": "r1",
                "requester_email": "r@example.com", "request_type": "access"
            })),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "seed data access failed: {access_req}");
    let access_id = access_req["data"]["id"].as_str().unwrap().to_string();

    // Tenant B probing each resource by UUID must be denied (403), and the
    // mutations must not change anything.
    for (path, token) in [
        (format!("/log-streams/{stream_id}"), b.clone()),
        (format!("/deployments/{deploy_id}"), uuid_b.clone()),
        (format!("/support/tickets/{ticket_id}"), b.clone()),
        (format!("/templates/{template_id}"), b.clone()),
        (format!("/qbr/{qbr_id}"), b.clone()),
    ] {
        let (status, body) = app.get(&path, &token).await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "GET {path} as tenant B should be 403, got {status}: {body}"
        );
    }

    // Verify endpoints (POST) are denied cross-tenant too.
    let (status, body) = app
        .post(&format!("/whitelabel/domains/{domain_id}/verify"), &b, None)
        .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "verify as tenant B should be 403, got {status}: {body}"
    );

    // Mutations as tenant B are denied and have no effect.
    let (status, _) = app
        .post(
            &format!("/log-streams/{stream_id}/pause"),
            &b,
            None,
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "pause as B must be 403");
    let row: Option<String> =
        sqlx::query_scalar("SELECT status FROM ent_log_streams WHERE id = $1")
            .bind(stream_id.parse::<Uuid>().unwrap())
            .fetch_one(&app.db)
            .await
            .unwrap();
    assert_eq!(row.as_deref(), Some("active"), "pause must not mutate");

    let (status, _) = app
        .put(
            &format!("/support/tickets/{ticket_id}"),
            &b,
            Some(serde_json::json!({"status": "resolved"})),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "ticket update as B must be 403");
    let ticket_status: Option<String> =
        sqlx::query_scalar("SELECT status FROM ent_support_tickets WHERE id = $1")
            .bind(ticket_id.parse::<Uuid>().unwrap())
            .fetch_one(&app.db)
            .await
            .unwrap();
    assert_eq!(ticket_status.as_deref(), Some("open"));

    // Approving tenant A's data access request as tenant B is denied.
    let (status, _) = app
        .post(
            &format!("/compliance/data-access/{access_id}/approve"),
            &b,
            Some(serde_json::json!({"approved_by": "attacker", "duration_minutes": 60})),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // Happy path: the owner still gets 200.
    for (path, token) in [
        (format!("/log-streams/{stream_id}"), a.clone()),
        (format!("/deployments/{deploy_id}"), uuid_a.clone()),
        (format!("/support/tickets/{ticket_id}"), a.clone()),
        (format!("/templates/{template_id}"), a.clone()),
        (format!("/qbr/{qbr_id}"), a.clone()),
    ] {
        let (status, body) = app.get(&path, &token).await;
        assert_eq!(status, StatusCode::OK, "GET {path} as owner: {body}");
    }
}

#[tokio::test]
async fn template_approve_reject_require_admin() {
    let Some(app) = setup().await else {
        skip_notice("test");
        return;
    };
    let a = app.token(&app.tenant_a, false);
    let admin = app.token(&app.tenant_a, true);

    let (_, template) = app
        .post(
            "/templates/submit",
            &a,
            Some(serde_json::json!({
                "tenant_id": app.tenant_a, "name": "t", "subject": "s",
                "html_content": "<p>x</p>", "submitted_by": "user1"
            })),
        )
        .await;
    let id = template["data"]["id"].as_str().unwrap().to_string();

    // Non-admin reviewer cannot approve or reject even their own tenant's
    // submission.
    let bodies = [
        (
            format!("/templates/{id}/approve"),
            serde_json::json!({"reviewed_by": "self"}),
        ),
        (
            format!("/templates/{id}/reject"),
            serde_json::json!({"reviewed_by": "self", "reason": "r"}),
        ),
    ];
    for (path, body_json) in bodies {
        let (status, body) = app.post(&path, &a, Some(body_json)).await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "non-admin {path} must be 403, got {status}: {body}"
        );
    }
    let db_status: String = sqlx::query_scalar(
        "SELECT status FROM ent_template_submissions WHERE id = $1",
    )
    .bind(id.parse::<Uuid>().unwrap())
    .fetch_one(&app.db)
    .await
    .unwrap();
    assert_eq!(db_status, "pending", "no mutation may occur");

    // Admin (reviewer) can approve; reviewer identity comes from claims.
    let (status, body) = app
        .post(
            &format!("/templates/{id}/approve"),
            &admin,
            Some(serde_json::json!({"reviewed_by": "ignored", "notes": null})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "admin approve should succeed: {body}");
    let reviewed_by: Option<String> = sqlx::query_scalar(
        "SELECT reviewed_by FROM ent_template_submissions WHERE id = $1",
    )
    .bind(id.parse::<Uuid>().unwrap())
    .fetch_one(&app.db)
    .await
    .unwrap();
    assert_eq!(
        reviewed_by.as_deref(),
        Some("user-test-subject"),
        "reviewer must be derived from token claims"
    );
}

// ── Fix B: cross-tenant decryption oracle ───────────────────────────────────

#[tokio::test]
async fn decrypt_field_is_tenant_bound() {
    let Some(app) = setup().await else {
        skip_notice("test");
        return;
    };
    let a = app.token(&app.tenant_a, false);
    let b = app.token(&app.tenant_b, false);

    let (status, encrypted) = app
        .post(
            "/compliance/encryption/encrypt-field",
            &a,
            Some(serde_json::json!({
                "tenant_id": app.tenant_a, "field_name": "email", "value": "phi@example.com"
            })),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{encrypted}");
    let ciphertext = encrypted["value"].as_str().unwrap().to_string();
    assert!(ciphertext.starts_with("ENC:v1:"));

    // Tenant B submitting tenant A's ciphertext is rejected with 400.
    let (status, body) = app
        .post(
            "/compliance/encryption/decrypt-field",
            &b,
            Some(serde_json::json!({
                "tenant_id": app.tenant_b, "field_name": "email", "value": ciphertext
            })),
        )
        .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "cross-tenant decrypt must 400, got {status}: {body}"
    );

    // The owner decrypts their own ciphertext.
    let (status, body) = app
        .post(
            "/compliance/encryption/decrypt-field",
            &a,
            Some(serde_json::json!({
                "tenant_id": app.tenant_a, "field_name": "email", "value": ciphertext
            })),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["value"], "phi@example.com");

    // Unknown provenance (plaintext value) is rejected.
    let (status, _) = app
        .post(
            "/compliance/encryption/decrypt-field",
            &a,
            Some(serde_json::json!({
                "tenant_id": app.tenant_a, "field_name": "email", "value": "not-a-ciphertext"
            })),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "plaintext must be rejected");
}

// ── Fix C: audit log identity ───────────────────────────────────────────────

#[tokio::test]
async fn audit_log_identity_is_server_derived() {
    let Some(app) = setup().await else {
        skip_notice("test");
        return;
    };
    let a = app.token(&app.tenant_a, false);

    let (status, body) = app
        .post(
            "/compliance/audit",
            &a,
            Some(serde_json::json!({
                "tenant_id": app.tenant_a,
                "user_id": "forged-user-id",
                "action": "view_record",
                "resource_type": "phi",
                "resource_id": "abc",
                "ip_address": "1.2.3.4",
                "session_id": "forged-session",
                "request_id": "forged-request"
            })),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let row: (Option<String>, Option<String>) = sqlx::query_as(
        "SELECT user_id, ip_address FROM ent_compliance_audit_logs \
         WHERE tenant_id = $1 AND action = 'view_record' ORDER BY created_at DESC LIMIT 1",
    )
    .bind(&app.tenant_a)
    .fetch_one(&app.db)
    .await
    .unwrap();

    // user_id comes from the authenticated token, not the body.
    assert_eq!(row.0.as_deref(), Some("user-test-subject"));
    // ip_address is never the body-supplied value.
    assert_ne!(row.1.as_deref(), Some("1.2.3.4"));

    // Body-supplied identity survives only as non-authoritative metadata.
    let metadata: Option<serde_json::Value> = sqlx::query_scalar(
        "SELECT metadata FROM ent_compliance_audit_logs \
         WHERE tenant_id = $1 AND action = 'view_record' ORDER BY created_at DESC LIMIT 1",
    )
    .bind(&app.tenant_a)
    .fetch_one(&app.db)
    .await
    .unwrap();
    let metadata = metadata.expect("metadata present");
    assert_eq!(
        metadata["client_supplied"]["user_id"], "forged-user-id",
        "client-supplied identity must be preserved only as metadata"
    );
}

// ── Fix D: contract self-execution ──────────────────────────────────────────

#[tokio::test]
async fn tenant_self_signature_does_not_activate_or_promote_plan() {
    let Some(app) = setup().await else {
        skip_notice("test");
        return;
    };
    let admin = app.token(&app.tenant_a, true);
    let member = app.token(&app.tenant_a, false);

    sqlx::query("INSERT INTO tenants (id, name) VALUES ($1, 'Test Tenant A')")
        .bind(&app.tenant_a)
        .execute(&app.db)
        .await
        .unwrap();

    let start = chrono::Utc::now() - chrono::Duration::days(1);
    let end = chrono::Utc::now() + chrono::Duration::days(365);
    let (status, created) = app
        .post(
            "/contracts",
            &admin,
            Some(serde_json::json!({
                "startDate": start.to_rfc3339(), "endDate": end.to_rfc3339(),
                "baseFee": 5000,
                "committedVolume": {"emails": 100000, "apiCalls": 1000, "storage": 50},
                "overageRates": {"emailsPerThousand": 15, "apiCallsPerThousand": 5, "storagePerGb": 1},
                "paymentTerms": "net30"
            })),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    let contract_id = created["id"].as_str().unwrap().to_string();

    let (status, _) = app
        .post(&format!("/contracts/{contract_id}/submit"), &member, None)
        .await;
    assert_eq!(status, StatusCode::OK);

    // Tenant self-service signature: any signature_data string.
    let (status, signed) = app
        .post(
            &format!("/contracts/{contract_id}/sign"),
            &member,
            Some(serde_json::json!({
                "signatureData": "totally-unverified-scribble",
                "signerName": "Self Server", "signerTitle": "CEO",
                "signedAt": chrono::Utc::now().to_rfc3339()
            })),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{signed}");
    assert_ne!(
        signed["status"], "active",
        "self-signature must NOT activate the contract: {signed}"
    );

    let plan: String = sqlx::query_scalar("SELECT plan FROM tenants WHERE id = $1")
        .bind(&app.tenant_a)
        .fetch_one(&app.db)
        .await
        .unwrap();
    assert_eq!(plan, "free", "self-signature must NOT touch tenants.plan");

    // Platform-admin counter-signature activates and promotes the plan.
    let (status, countersigned) = app
        .post(
            &format!("/contracts/{contract_id}/sign"),
            &admin,
            Some(serde_json::json!({
                "signatureData": "platform-countersign",
                "signerName": "Platform", "signerTitle": "Admin",
                "signedAt": chrono::Utc::now().to_rfc3339()
            })),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{countersigned}");
    assert_eq!(countersigned["status"], "active");

    let plan: String = sqlx::query_scalar("SELECT plan FROM tenants WHERE id = $1")
        .bind(&app.tenant_a)
        .fetch_one(&app.db)
        .await
        .unwrap();
    assert_eq!(plan, "enterprise", "admin counter-sign promotes the plan");
}

// ── Fix E: whitelabel TXT verification ──────────────────────────────────────

#[tokio::test]
async fn whitelabel_domain_requires_txt_token() {
    let Some(app) = setup().await else {
        skip_notice("test");
        return;
    };
    let a = app.token(&app.tenant_a, false);

    let (status, domain) = app
        .post(
            "/whitelabel/domains",
            &a,
            Some(serde_json::json!({
                "tenant_id": app.tenant_a,
                "domain": format!("txt-verify-{}.example.com", Uuid::new_v4().simple()),
                "domain_type": "tracking"
            })),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{domain}");
    let id = domain["data"]["id"].as_str().unwrap().to_string();
    let token = domain["data"]["verification_token"]
        .as_str()
        .expect("a verification token must be issued")
        .to_string();
    assert!(token.len() >= 32, "token must be crypto-random, got {token}");
    // The TXT record instructions are part of the response.
    let records = domain["data"]["dns_records"].as_array().unwrap();
    assert!(
        records
            .iter()
            .any(|r| r["record_type"] == "TXT" && r["value"]
                .as_str()
                .is_some_and(|v| v.contains(&token))),
        "dns_records must include the TXT verification record"
    );

    // Real DNS: the test domain resolves nowhere, and even a resolvable
    // domain without our TXT token must NOT verify. Use the service-level
    // injectable lookup to prove both branches deterministically.
    let service = enterprise::whitelabel::WhiteLabelService::new(app.db.clone());
    let id_uuid: Uuid = id.parse().unwrap();

    // Wrong TXT records (or none): not verified.
    let result = service
        .verify_domain_with_lookup(id_uuid, |_| async {
            Ok(vec!["v=spf1 include:spf.apexmail.io ~all".to_string()])
        })
        .await
        .unwrap();
    assert_eq!(
        result.data.unwrap().verification_status,
        "failed",
        "domain without matching TXT token must not verify"
    );

    // Correct TXT record: verified.
    let result = service
        .verify_domain_with_lookup(id_uuid, move |_| {
            let expected = format!("apexmail-verification={token}");
            async move { Ok(vec![expected]) }
        })
        .await
        .unwrap();
    assert_eq!(result.data.unwrap().verification_status, "verified");
}

// ── Fix H-2/H-3: secrets at rest, masked responses, metrics auth ────────────

#[tokio::test]
async fn log_stream_secrets_encrypted_at_rest_and_masked() {
    let Some(app) = setup().await else {
        skip_notice("test");
        return;
    };
    let a = app.token(&app.tenant_a, false);

    let (status, stream) = app
        .post(
            "/log-streams",
            &a,
            Some(serde_json::json!({
                "tenant_id": app.tenant_a,
                "name": "splunk-stream",
                "destination_type": "splunk",
                "destination_config": {"url": "https://input.example.com:8088", "token": "super-secret-hec-token-1234"}
            })),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{stream}");
    let id = stream["data"]["id"].as_str().unwrap().to_string();

    // At rest: the token column holds ciphertext, not the plaintext.
    let stored: serde_json::Value =
        sqlx::query_scalar("SELECT destination_config FROM ent_log_streams WHERE id = $1")
            .bind(id.parse::<Uuid>().unwrap())
            .fetch_one(&app.db)
            .await
            .unwrap();
    let stored_token = stored["token"].as_str().unwrap();
    assert!(
        stored_token.starts_with("ENC:v1:"),
        "secret must be encrypted at rest, got {stored_token}"
    );
    assert!(!stored_token.contains("super-secret"));

    // GET by ID: masked (last-4 only).
    let (status, fetched) = app.get(&format!("/log-streams/{id}"), &a).await;
    assert_eq!(status, StatusCode::OK);
    let masked = fetched["data"]["destination_config"]["token"].as_str().unwrap();
    assert!(masked.starts_with("****"), "response must mask secret: {masked}");
    assert!(masked.ends_with("1234"));

    // LIST: masked too.
    let (status, listed) = app
        .get(&format!("/log-streams/tenant/{}", app.tenant_a), &a)
        .await;
    assert_eq!(status, StatusCode::OK);
    let entries = listed["data"].as_array().unwrap();
    let entry = entries
        .iter()
        .find(|e| e["id"].as_str() == Some(id.as_str()))
        .expect("stream in list");
    assert!(entry["destination_config"]["token"]
        .as_str()
        .unwrap()
        .starts_with("****"));
}

#[tokio::test]
async fn unknown_log_stream_type_verify_is_not_verified() {
    let Some(app) = setup().await else {
        skip_notice("test");
        return;
    };
    let a = app.token(&app.tenant_a, false);
    let (status, stream) = app
        .post(
            "/log-streams",
            &a,
            Some(serde_json::json!({
                "tenant_id": app.tenant_a, "name": "weird",
                "destination_type": "carrier-pigeon"
            })),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{stream}");
    let id = stream["data"]["id"].as_str().unwrap();

    let (status, body) = app
        .post(&format!("/log-streams/{id}/verify"), &a, None)
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        body["data"]["verified"], false,
        "unknown destination type must not auto-verify: {body}"
    );
    assert!(body["data"]["reason"]
        .as_str()
        .is_some_and(|r| r.contains("unsupported destination type")));
}

#[tokio::test]
async fn metrics_endpoint_requires_auth_or_loopback() {
    let Some(app) = setup().await else {
        skip_notice("test");
        return;
    };

    // oneshot has no ConnectInfo → the peer is NOT loopback → 401 without a
    // valid metrics token.
    let response = app
        .app
        .clone()
        .oneshot(Request::get("/metrics").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    // With the deployment metrics token configured, the bearer grants access.
    let mut config = Config::from_env().unwrap();
    config.jwt_public_key_pem = TEST_PUBLIC_PEM.to_string();
    config.metrics_token = Some("metrics-secret".to_string());
    config.log_stream.encryption_key = "test-log-stream-secret-key".to_string();
    let recorder = PrometheusBuilder::new().build_recorder();
    let state = Arc::new(AppState::new(app.db.clone(), config, recorder.handle()));
    let authed_app = router(state);
    let response = authed_app
        .clone()
        .oneshot(
            Request::get("/metrics")
                .header("authorization", "Bearer metrics-secret")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    // Wrong token is still rejected.
    let response = authed_app
        .oneshot(
            Request::get("/metrics")
                .header("authorization", "Bearer wrong")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

// ── Fix H-1: delivery primitives are live ───────────────────────────────────

#[tokio::test]
async fn log_stream_delivery_primitives_record_and_report() {
    let Some(app) = setup().await else {
        skip_notice("test");
        return;
    };
    let a = app.token(&app.tenant_a, false);

    let (status, stream) = app
        .post(
            "/log-streams",
            &a,
            Some(serde_json::json!({
                "tenant_id": app.tenant_a,
                "name": "delivery-stream",
                "destination_type": "webhook",
                "destination_config": {"url": "https://example.com/hook"}
            })),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{stream}");
    let id: Uuid = stream["data"]["id"].as_str().unwrap().parse().unwrap();

    let service = enterprise::log_streaming::LogStreamingService::new(app.db.clone());
    // record_delivery (previously dead) writes the batch ledger...
    service
        .record_delivery(id, "batch-001", 5, 1024, 12, true, None)
        .await
        .unwrap();
    service
        .record_delivery(id, "batch-002", 0, 0, 5, false, Some("boom"))
        .await
        .unwrap();
    // ...and get_stats reports it.
    let stats = service.get_stats(id).await.unwrap().data.unwrap();
    assert_eq!(stats.total_deliveries, 2);
    assert_eq!(stats.total_events, 5);
    assert_eq!(stats.total_bytes, 1024);
    assert!((stats.success_rate - 50.0).abs() < 0.01, "{}", stats.success_rate);

    // get_active_streams (previously dead) surfaces the stream for the
    // background delivery loop.
    let active = service.get_active_streams().await.unwrap();
    assert!(active.iter().any(|st| st.id == id));
}

// ── Fix J-10: CORS layer is attached from config ────────────────────────────

#[tokio::test]
async fn cors_policy_is_enforced_from_config() {
    let Some(app) = setup().await else {
        skip_notice("test");
        return;
    };
    // Default dev config allows "*" — a preflight/request with any Origin
    // must be answered with an Access-Control-Allow-Origin header, proving
    // the previously-dead cors_origins config is actually attached.
    let response = app
        .app
        .clone()
        .oneshot(
            Request::get("/health")
                .header("origin", "https://some-app.example.com")
                .header("access-control-request-method", "GET")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let allow_origin = response
        .headers()
        .get("access-control-allow-origin")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    assert!(
        response
            .headers()
            .contains_key(axum::http::header::HeaderName::from_static(
                "access-control-allow-origin"
            )),
        "CORS layer must be attached (J-10)"
    );
    assert!(!allow_origin.is_empty());
}

// ── Fix G: SSO honest 501 ───────────────────────────────────────────────────

#[tokio::test]
async fn sso_login_returns_501_without_callback_wiring() {
    let Some(app) = setup().await else {
        skip_notice("test");
        return;
    };
    for path in ["/sso/login/saml/example.com", "/sso/login/oidc/example.com"] {
        let response = app
            .app
            .clone()
            .oneshot(Request::get(path).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            StatusCode::NOT_IMPLEMENTED,
            "{path} must not redirect to an IdP with no ACS wired"
        );
    }
}

// ── Fix J: mediums ──────────────────────────────────────────────────────────

#[tokio::test]
async fn jwt_audience_issuer_are_enforced_when_configured() {
    let Some(app) = setup().await else {
        skip_notice("test");
        return;
    };

    // Build a second app with pinned audience/issuer.
    let mut config = Config::from_env().unwrap();
    config.jwt_public_key_pem = TEST_PUBLIC_PEM.to_string();
    config.jwt_audience = Some("apexmail-enterprise".to_string());
    config.jwt_issuer = Some("apexmail-issuer".to_string());
    config.log_stream.encryption_key = "test-log-stream-secret-key".to_string();
    let recorder = PrometheusBuilder::new().build_recorder();
    let state = Arc::new(AppState::new(app.db.clone(), config, recorder.handle()));
    let pinned_app = router(state);

    let call = |token: &str| {
        let app = pinned_app.clone();
        let request = Request::get("/contracts")
            .header("authorization", format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap();
        async move { app.oneshot(request).await.unwrap().status() }
    };

    // Correct aud/iss → passes auth (handler then runs; contracts GET works).
    let good = TestApp::token_with(&app.tenant_a, false, Some("apexmail-enterprise"), Some("apexmail-issuer"));
    assert_eq!(call(&good).await, StatusCode::OK);

    // Wrong audience → rejected.
    let wrong_aud = TestApp::token_with(&app.tenant_a, false, Some("other-audience"), Some("apexmail-issuer"));
    assert_eq!(call(&wrong_aud).await, StatusCode::UNAUTHORIZED);

    // Wrong issuer → rejected.
    let wrong_iss = TestApp::token_with(&app.tenant_a, false, Some("apexmail-enterprise"), Some("evil-issuer"));
    assert_eq!(call(&wrong_iss).await, StatusCode::UNAUTHORIZED);

    // No audience at all → rejected when pinned.
    let no_aud = TestApp::token_with(&app.tenant_a, false, None, Some("apexmail-issuer"));
    assert_eq!(call(&no_aud).await, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn compliance_reenable_preserves_signed_attestations() {
    let Some(app) = setup().await else {
        skip_notice("test");
        return;
    };
    let a = app.token(&app.tenant_a, false);

    let (status, _) = app
        .post(
            "/compliance/enable",
            &a,
            Some(serde_json::json!({"tenant_id": app.tenant_a, "frameworks": ["hipaa"]})),
        )
        .await;
    assert_eq!(status, StatusCode::OK);

    let (status, _) = app
        .post(
            "/compliance/baa",
            &a,
            Some(serde_json::json!({
                "tenant_id": app.tenant_a, "signatory_name": "Dr. A",
                "signatory_title": "CMO", "signatory_email": "a@clinic.example"
            })),
        )
        .await;
    assert_eq!(status, StatusCode::OK);

    // Re-enabling frameworks must not reset the BAA/zero-retention state.
    let (status, _) = app
        .post(
            "/compliance/enable",
            &a,
            Some(serde_json::json!({"tenant_id": app.tenant_a, "frameworks": ["soc2"]})),
        )
        .await;
    assert_eq!(status, StatusCode::OK);

    let (baa_signed, signatory): (bool, Option<String>) = sqlx::query_as(
        "SELECT baa_signed, baa_signatory_name FROM ent_compliance_configs WHERE tenant_id = $1",
    )
    .bind(&app.tenant_a)
    .fetch_one(&app.db)
    .await
    .unwrap();
    assert!(baa_signed, "re-enabling must preserve baa_signed");
    assert_eq!(signatory.as_deref(), Some("Dr. A"));
}

#[tokio::test]
async fn data_access_approval_derives_approver_and_clamps_duration() {
    let Some(app) = setup().await else {
        skip_notice("test");
        return;
    };
    let a = app.token(&app.tenant_a, false);

    let (_, req) = app
        .post(
            "/compliance/data-access",
            &a,
            Some(serde_json::json!({
                "tenant_id": app.tenant_a, "requester_id": "r1",
                "requester_email": "r@example.com", "request_type": "access"
            })),
        )
        .await;
    let id = req["data"]["id"].as_str().unwrap().to_string();

    let (status, body) = app
        .post(
            &format!("/compliance/data-access/{id}/approve"),
            &a,
            Some(serde_json::json!({"approved_by": "forged-approver", "duration_minutes": 99999})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let (approved_by, duration): (Option<String>, Option<i32>) = sqlx::query_as(
        "SELECT approved_by, duration_minutes FROM ent_data_access_requests WHERE id = $1",
    )
    .bind(id.parse::<Uuid>().unwrap())
    .fetch_one(&app.db)
    .await
    .unwrap();
    assert_eq!(
        approved_by.as_deref(),
        Some("user-test-subject"),
        "approver must come from token claims"
    );
    assert_eq!(duration, Some(1440), "duration must clamp to 1440 min");

    // The raw access token must not be echoed.
    let token_in_response = body["data"]["access_token"].as_str().unwrap_or("");
    assert!(
        token_in_response.starts_with("ref:") || body["data"]["access_token"].is_null(),
        "raw access_token must not be returned: {}",
        body["data"]["access_token"]
    );
}

#[tokio::test]
async fn sla_math_counts_all_tickets_in_denominator() {
    let Some(app) = setup().await else {
        skip_notice("test");
        return;
    };
    let a = app.token(&app.tenant_a, false);

    // Ticket 1: answered within SLA.
    let (_, t1) = app
        .post(
            "/support/tickets",
            &a,
            Some(serde_json::json!({
                "tenant_id": app.tenant_a, "subject": "s1", "description": "d",
                "priority": "high", "category": "general"
            })),
        )
        .await;
    let t1_id = t1["data"]["id"].as_str().unwrap().to_string();
    // Ticket 2: never answered.
    let (_, t2) = app
        .post(
            "/support/tickets",
            &a,
            Some(serde_json::json!({
                "tenant_id": app.tenant_a, "subject": "s2", "description": "d",
                "priority": "high", "category": "general"
            })),
        )
        .await;
    let t2_id = t2["data"]["id"].as_str().unwrap().to_string();

    // Staff-facing status transition stamps first_response_at on t1.
    let (status, _) = app
        .put(
            &format!("/support/tickets/{t1_id}"),
            &a,
            Some(serde_json::json!({"status": "open"})),
        )
        .await;
    assert_eq!(status, StatusCode::OK);

    // A customer-side transition must NOT fabricate a first response.
    let (status, _) = app
        .put(
            &format!("/support/tickets/{t2_id}"),
            &a,
            Some(serde_json::json!({"status": "waiting_customer"})),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let fr: Option<chrono::DateTime<chrono::Utc>> = sqlx::query_scalar(
        "SELECT first_response_at FROM ent_support_tickets WHERE id = $1",
    )
    .bind(t2_id.parse::<Uuid>().unwrap())
    .fetch_one(&app.db)
    .await
    .unwrap();
    assert!(fr.is_none(), "waiting_customer must not set first_response_at");

    // SLA denominator = all tickets: 1 answered of 2 → 50%.
    let (_, metrics) = app
        .get(&format!("/support/metrics/{}", app.tenant_a), &a)
        .await;
    let rate = metrics["data"]["sla_compliance_rate"].as_f64().unwrap();
    assert!(
        (rate - 50.0).abs() < 0.01,
        "SLA compliance must count unanswered tickets (1/2 = 50%), got {rate}"
    );
}

#[tokio::test]
async fn ip_allocation_validated_against_pool() {
    let Some(app) = setup().await else {
        skip_notice("test");
        return;
    };
    // This family uses UUID-shaped tenant ids (ip_pool_available.allocated_to
    // is a UUID column).
    let tenant_a = Uuid::new_v4().to_string();
    let a = app.token(&tenant_a, false);

    let octet_a = (Uuid::new_v4().as_u128() % 100) as u8 + 100; // 100..199
    let octet_b = octet_a + 1;
    let pool_ip = format!("198.51.100.{octet_a}");
    let taken_ip = format!("198.51.100.{octet_b}");
    // Clean up any rows from a previous run (documentation-range addresses
    // are only ever inserted by this test).
    sqlx::query("DELETE FROM ent_dedicated_ips WHERE ip_address = ANY($1::inet[])")
        .bind(vec![pool_ip.clone(), taken_ip.clone()])
        .execute(&app.db)
        .await
        .unwrap();
    sqlx::query("DELETE FROM ip_pool_available WHERE ip_address = ANY($1::inet[])")
        .bind(vec![pool_ip.clone(), taken_ip.clone()])
        .execute(&app.db)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO ip_pool_available (ip_address, region, status) \
         VALUES ($1::inet, 'eu', 'available'), ($2::inet, 'eu', 'allocated')",
    )
    .bind(&pool_ip)
    .bind(&taken_ip)
    .execute(&app.db)
    .await
    .unwrap();

    // Not in the pool → rejected.
    let (status, body) = app
        .post(
            "/ips/allocate",
            &a,
            Some(serde_json::json!({"tenant_id": tenant_a, "ip_address": "203.0.113.99"})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "service result envelope: {body}");
    assert_eq!(body["success"], false, "non-pool IP must be rejected: {body}");
    assert_eq!(body["code"], "IP_NOT_IN_POOL");

    // In the pool but already allocated → rejected as collision.
    let (status, body) = app
        .post(
            "/ips/allocate",
            &a,
            Some(serde_json::json!({"tenant_id": tenant_a, "ip_address": taken_ip})),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["success"], false);
    assert_eq!(body["code"], "IP_NOT_AVAILABLE");

    // Available pool IP → allocated successfully.
    let (status, body) = app
        .post(
            "/ips/allocate",
            &a,
            Some(serde_json::json!({"tenant_id": tenant_a, "ip_address": pool_ip})),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(
        body["data"]["ip_address"].as_str().unwrap().starts_with(&pool_ip),
        "allocated IP should be {pool_ip}: {}",
        body["data"]["ip_address"]
    );

    // Second allocation of the same IP now collides.
    let (status, body) = app
        .post(
            "/ips/allocate",
            &a,
            Some(serde_json::json!({"tenant_id": tenant_a, "ip_address": pool_ip})),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["success"], false, "double allocation must collide: {body}");
}

#[tokio::test]
async fn sub_account_api_key_lifecycle_enforces_revocation() {
    let Some(app) = setup().await else {
        skip_notice("test");
        return;
    };
    let a = app.token(&app.tenant_a, false);
    let b = app.token(&app.tenant_b, false);

    let (_, sub) = app
        .post(
            "/sub-accounts",
            &a,
            Some(serde_json::json!({"parent_id": app.tenant_a, "name": "Child Co"})),
        )
        .await;
    let sub_id: Uuid = sub["data"]["id"].as_str().unwrap().parse().unwrap();

    let (_, key) = app
        .post(
            &format!("/sub-accounts/{sub_id}/api-keys"),
            &a,
            Some(serde_json::json!({"name": "prod"})),
        )
        .await;
    let key_id: Uuid = key["data"]["id"].as_str().unwrap().parse().unwrap();
    let raw_key = key["data"]["key"].as_str().unwrap().to_string();

    // Listing is tenant-guarded and never returns hashes.
    let (status, listed) = app
        .get(&format!("/sub-accounts/{sub_id}/api-keys"), &a)
        .await;
    assert_eq!(status, StatusCode::OK, "{listed}");
    let keys = listed["data"].as_array().unwrap();
    assert!(keys.iter().all(|k| k["key_hash"].as_str() == Some("")));

    let (status, _) = app
        .get(&format!("/sub-accounts/{sub_id}/api-keys"), &b)
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "cross-tenant list must 403");

    // verify_api_key accepts the key before revocation, rejects after.
    let service = enterprise::sub_accounts::SubAccountService::new(
        app.db.clone(),
        10,
        enterprise::config::VolumeAllocationMode::Fixed,
    );
    assert!(service.verify_api_key(&raw_key).await.unwrap().is_some());
    // Cross-tenant revoke is denied.
    let (status, _) = app
        .post(
            &format!("/sub-accounts/{sub_id}/api-keys/{key_id}/revoke"),
            &b,
            None,
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    let (status, _) = app
        .post(
            &format!("/sub-accounts/{sub_id}/api-keys/{key_id}/revoke"),
            &a,
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        service.verify_api_key(&raw_key).await.unwrap().is_none(),
        "revoked key must fail verification"
    );
}

#[tokio::test]
async fn sso_cleanup_requires_admin() {
    let Some(app) = setup().await else {
        skip_notice("test");
        return;
    };
    let member = app.token(&app.tenant_a, false);
    let admin = app.token(&app.tenant_a, true);

    let (status, _) = app.post("/sso/cleanup", &member, None).await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    let (status, body) = app.post("/sso/cleanup", &admin, None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

#[test]
fn debug_jwt_roundtrip() {
    #[derive(serde::Serialize, serde::Deserialize, Debug)]
    struct Claims {
        sub: String,
        tenant_id: String,
        admin: bool,
        exp: usize,
    }
    let key = jsonwebtoken::EncodingKey::from_rsa_pem(TEST_PRIVATE_PEM.as_bytes()).unwrap();
    let token = jsonwebtoken::encode(
        &jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256),
        &Claims { sub: "u".into(), tenant_id: "t".into(), admin: false, exp: 9999999999 },
        &key,
    )
    .unwrap();
    let dk = jsonwebtoken::DecodingKey::from_rsa_pem(TEST_PUBLIC_PEM.as_bytes()).unwrap();
    let mut v = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::RS256);
    v.validate_exp = true;
    v.validate_nbf = true;
    match jsonwebtoken::decode::<Claims>(&token, &dk, &v) {
        Ok(c) => println!("DECODED OK: {:?}", c.claims),
        Err(e) => println!("DECODE ERR: {e}"),
    }
}
