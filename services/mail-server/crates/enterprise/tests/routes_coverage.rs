//! Handler-arm coverage for the enterprise routes: database-failure arms,
//! cross-tenant guards, not-found envelopes, the metrics gate, BYOIP CIDR
//! validation and the pdf-renderer proxy (503/502/success).
//!
//! Harness convention: the canonical schema is provisioned with
//! `migrator::test_support::shared_canonical_db`; a configured provisioning
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
    admin_token: String,
    token_a: String,
    token_b: String,
}

fn ensure_trace_sink() {
    static INSTALLED: std::sync::OnceLock<()> = std::sync::OnceLock::new();
    if INSTALLED.set(()).is_ok() {
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::TRACE)
            .with_writer(std::io::sink)
            .finish();
        let _ = tracing::subscriber::set_global_default(subscriber);
    }
}

async fn harness() -> Option<&'static Harness> {
    ensure_trace_sink();
    SHARED
        .get_or_init(|| async { build_harness().await })
        .await
        .as_ref()
}

async fn build_harness() -> Option<Harness> {
    let base_url = std::env::var("ENTERPRISE_TEST_DATABASE_URL")
        .or_else(|_| std::env::var("TEST_DATABASE_URL"))
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())?;
    let (server_part, db_part) = base_url.rsplit_once('/')?;
    let db_only = db_part.split('?').next().unwrap_or(db_part);
    let db = match migrator::test_support::shared_canonical_db(
        &format!("{server_part}/{db_only}"),
        &format!("{db_only}_enterprise_routes_cov"),
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

    let tenant_a = format!("r{}", &Uuid::new_v4().simple().to_string()[..25]);
    let tenant_b = format!("q{}", &Uuid::new_v4().simple().to_string()[..25]);
    for (id, name) in [(&tenant_a, "RoutesCov A"), (&tenant_b, "RoutesCov B")] {
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

    let admin_token = mint_token(&tenant_a, "routes-cov-admin", true);
    let token_a = mint_token(&tenant_a, "routes-cov-user-a", false);
    let token_b = mint_token(&tenant_b, "routes-cov-user-b", false);
    Some(Harness {
        app,
        db,
        tenant_a,
        tenant_b,
        admin_token,
        token_a,
        token_b,
    })
}

/// A router whose database never connects: every service call fails, which
/// deterministically drives the handlers' error arms without touching data.
fn broken_app() -> Router {
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(std::time::Duration::from_millis(250))
        .connect_lazy("postgresql://127.0.0.1:5432/enterprise_no_such_db_cov")
        .expect("lazy pool");
    let mut config = Config::from_env().expect("Config::from_env");
    config.jwt_public_key_pem = TEST_PUBLIC_PEM.to_string();
    config.jwt_audience = None;
    config.jwt_issuer = None;
    let recorder = PrometheusBuilder::new().build_recorder();
    router(Arc::new(AppState::new(pool, config, recorder.handle())))
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
    call_with_headers(app, method, path, token, body, &[]).await
}

async fn call_with_headers(
    app: &Router,
    method: &str,
    path: &str,
    token: Option<&str>,
    body: Option<serde_json::Value>,
    headers: &[(&str, String)],
) -> (StatusCode, serde_json::Value) {
    let mut builder = Request::builder().method(method).uri(path);
    if let Some(token) = token {
        builder = builder.header("authorization", format!("Bearer {token}"));
    }
    for (name, value) in headers {
        builder = builder.header(*name, value.clone());
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

fn contract_body(_tenant: &str) -> serde_json::Value {
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

// ── Metrics gate + readiness ─────────────────────────────────────────────

#[test]
fn metrics_gate_requires_loopback_or_token_and_readiness_reports_the_database() {
    run(async {
        let Some(h) = harness().await else { return };
        let app = h.app.clone();

        // The harness app has NO metrics token: access is denied outright.
        let (status, json) = call(&app, "GET", "/metrics", None, None).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{json}");
        let (status, _) = call(&app, "GET", "/metrics", Some(&h.token_a), None).await;
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "user tokens grant nothing"
        );

        // A token-configured app accepts exactly that bearer token.
        let mut config = Config::from_env().expect("Config::from_env");
        config.jwt_public_key_pem = TEST_PUBLIC_PEM.to_string();
        config.jwt_audience = None;
        config.jwt_issuer = None;
        config.metrics_token = Some("cov-metrics-token".to_string());
        let recorder = PrometheusBuilder::new().build_recorder();
        let gated = router(Arc::new(AppState::new(
            h.db.clone(),
            config,
            recorder.handle(),
        )));
        let (status, _) = call(&gated, "GET", "/metrics", Some("wrong-token"), None).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "wrong token denied");
        let (status, _) = call(&gated, "GET", "/metrics", Some("cov-metrics-token"), None).await;
        assert_eq!(status, StatusCode::OK, "the exact token is accepted");

        // Readiness reports the live database...
        let (status, json) = call(&app, "GET", "/readiness", None, None).await;
        assert_eq!(status, StatusCode::OK, "{json}");
        assert_eq!(json["status"], "ready");

        // ...and 503 when the database is gone.
        let broken = broken_app();
        let (status, json) = call(&broken, "GET", "/readiness", None, None).await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{json}");
    });
}

// ── Database-failure arms across every surface ───────────────────────────

#[test]
fn database_failures_surface_as_handler_errors_on_every_endpoint() {
    run(async {
        let Some(h) = harness().await else { return };
        let admin = h.admin_token.clone();
        let app = broken_app();
        let missing = Uuid::new_v4();

        // (method, path, body) — bodies satisfy the Json extractors so each
        // request actually REACHES the handler's service calls.
        let endpoints: Vec<(&str, String, Option<serde_json::Value>)> = vec![
            ("GET", "/contracts".into(), None),
            (
                "POST",
                "/contracts".into(),
                Some(contract_body(&h.tenant_a)),
            ),
            ("GET", format!("/contracts/{missing}"), None),
            ("GET", format!("/contracts/{missing}/usage"), None),
            ("GET", format!("/contracts/{missing}/pdf"), None),
            ("POST", format!("/contracts/{missing}/submit"), None),
            (
                "POST",
                format!("/contracts/{missing}/sign"),
                Some(serde_json::json!({
                    "signatureData": "cov", "signerName": "Cov", "signerTitle": "QA",
                    "signedAt": chrono::Utc::now()
                })),
            ),
            (
                "POST",
                format!("/contracts/{missing}/amendments"),
                Some(serde_json::json!({
                    "reason": "cov",
                    "proposedChanges": {"baseFee": 20_000}
                })),
            ),
            (
                "POST",
                format!("/contracts/{missing}/purchase-orders"),
                Some(serde_json::json!({
                    "poNumber": "PO-COV",
                    "amount": 500,
                    "issuedDate": chrono::Utc::now()
                })),
            ),
            (
                "POST",
                format!("/contracts/{missing}/cancel"),
                Some(serde_json::json!({"reason": "cov"})),
            ),
            ("GET", format!("/contracts/{missing}/renewal-quote"), None),
            (
                "POST",
                format!("/contracts/{missing}/renew"),
                Some(serde_json::json!({
                    "newEndDate": chrono::Utc::now() + chrono::Duration::days(730),
                    "newTerms": {"baseFee": 30_000}
                })),
            ),
            ("GET", "/sso/config/x".into(), None),
            ("GET", "/sso/config/domain/x.example.com".into(), None),
            ("GET", "/sso/login/saml/x.example.com".into(), None),
            ("GET", "/sso/login/oidc/x.example.com".into(), None),
            ("GET", "/sso/validate".into(), None),
            ("POST", "/sso/cleanup".into(), None),
            (
                "POST",
                "/compliance/enable".into(),
                Some(serde_json::json!({"tenant_id": h.tenant_a, "frameworks": ["soc2"]})),
            ),
            ("GET", format!("/compliance/config/{}", h.tenant_a), None),
            (
                "POST",
                "/compliance/baa".into(),
                Some(
                    serde_json::json!({"tenant_id": h.tenant_a, "signatory_name": "a", "signatory_title": "b", "signatory_email": "a@b.c"}),
                ),
            ),
            (
                "POST",
                format!("/compliance/zero-retention/{}", h.tenant_a),
                Some(serde_json::json!({"enabled": true})),
            ),
            (
                "POST",
                "/compliance/audit".into(),
                Some(
                    serde_json::json!({"tenant_id": h.tenant_a, "action": "a", "resource_type": "tenant"}),
                ),
            ),
            ("GET", format!("/compliance/audit/{}", h.tenant_a), None),
            (
                "POST",
                "/compliance/data-access".into(),
                Some(
                    serde_json::json!({"tenant_id": h.tenant_a, "requester_id": "u1", "requester_email": "u@x.com", "request_type": "export", "resource_type": "contacts", "justification": "cov"}),
                ),
            ),
            (
                "POST",
                format!("/compliance/data-access/{missing}/approve"),
                Some(serde_json::json!({"approved_by": "probe", "duration_minutes": 5})),
            ),
            (
                "POST",
                "/compliance/data-deletion".into(),
                Some(
                    serde_json::json!({"tenant_id": h.tenant_a, "requester_id": "u1", "requester_email": "u@x.com"}),
                ),
            ),
            ("GET", format!("/compliance/report/{}", h.tenant_a), None),
            ("GET", format!("/compliance/status/{}", h.tenant_a), None),
            (
                "GET",
                format!("/compliance/encryption/status/{}", h.tenant_a),
                None,
            ),
            (
                "POST",
                "/compliance/encryption/encrypt-field".into(),
                Some(
                    serde_json::json!({"tenant_id": h.tenant_a, "field_name": "notes", "value": "v"}),
                ),
            ),
            (
                "POST",
                "/compliance/encryption/decrypt-field".into(),
                Some(
                    serde_json::json!({"tenant_id": h.tenant_a, "field_name": "notes", "value": "v"}),
                ),
            ),
            (
                "POST",
                "/log-streams".into(),
                Some(
                    serde_json::json!({"tenant_id": h.tenant_a, "name": "n", "destination_type": "webhook", "destination_config": {"url": "https://hooks.example.com/x"}}),
                ),
            ),
            ("GET", format!("/log-streams/{missing}"), None),
            (
                "PUT",
                format!("/log-streams/{missing}"),
                Some(serde_json::json!({"name": "renamed"})),
            ),
            ("GET", format!("/log-streams/tenant/{}", h.tenant_a), None),
            ("POST", format!("/log-streams/{missing}/pause"), None),
            ("POST", format!("/log-streams/{missing}/resume"), None),
            ("POST", format!("/log-streams/{missing}/verify"), None),
            ("GET", format!("/log-streams/{missing}/stats"), None),
            (
                "POST",
                "/deployments".into(),
                Some(
                    serde_json::json!({"tenant_id": h.tenant_a, "name": "d", "deployment_type": "dedicated", "region": "eu-west-1"}),
                ),
            ),
            ("GET", format!("/deployments/{missing}"), None),
            ("GET", format!("/deployments/tenant/{}", h.tenant_a), None),
            ("POST", format!("/deployments/{missing}/provision"), None),
            ("GET", format!("/deployments/{missing}/health"), None),
            (
                "POST",
                "/ips/allocate".into(),
                Some(serde_json::json!({"tenant_id": h.tenant_a, "ip_address": "203.0.113.10"})),
            ),
            ("GET", format!("/ips/{missing}"), None),
            ("GET", format!("/ips/tenant/{}", h.tenant_a), None),
            ("GET", "/ips/reputation/203.0.113.7".into(), None),
            (
                "POST",
                "/sub-accounts".into(),
                Some(serde_json::json!({"parent_id": h.tenant_a, "name": "sub"})),
            ),
            ("GET", format!("/sub-accounts/{missing}"), None),
            ("GET", format!("/sub-accounts/parent/{}", h.tenant_a), None),
            (
                "POST",
                format!("/sub-accounts/{missing}/suspend"),
                Some(serde_json::json!({"reason": "r"})),
            ),
            ("GET", format!("/sub-accounts/stats/{}", h.tenant_a), None),
            (
                "POST",
                "/support/tickets".into(),
                Some(
                    serde_json::json!({"tenant_id": h.tenant_a, "subject": "s", "description": "d", "priority": "high", "category": "billing"}),
                ),
            ),
            ("GET", format!("/support/tickets/{missing}"), None),
            (
                "PUT",
                format!("/support/tickets/{missing}"),
                Some(serde_json::json!({"status": "open"})),
            ),
            (
                "GET",
                format!("/support/tickets/tenant/{}", h.tenant_a),
                None,
            ),
            (
                "POST",
                format!("/support/tickets/{missing}/comments"),
                Some(
                    serde_json::json!({"author_id": "a", "author_name": "A", "author_type": "agent", "content": "m"}),
                ),
            ),
            ("GET", format!("/support/tickets/{missing}/comments"), None),
            (
                "POST",
                format!("/support/tickets/{missing}/escalate"),
                Some(
                    serde_json::json!({"reason": "r", "escalated_by": "00000000-0000-4000-8000-000000000001"}),
                ),
            ),
            (
                "POST",
                format!("/support/tickets/{missing}/satisfaction"),
                Some(serde_json::json!({"rating": 5, "feedback": "ok"})),
            ),
            ("GET", format!("/support/metrics/{}", h.tenant_a), None),
            (
                "POST",
                "/templates/submit".into(),
                Some(
                    serde_json::json!({"tenant_id": h.tenant_a, "name": "t", "subject": "s", "html_content": "<p>hi</p>", "submitted_by": "u"}),
                ),
            ),
            ("GET", format!("/templates/{missing}"), None),
            ("GET", format!("/templates/tenant/{}", h.tenant_a), None),
            (
                "POST",
                format!("/templates/{missing}/approve"),
                Some(serde_json::json!({"reviewed_by": "adm", "notes": "n"})),
            ),
            (
                "POST",
                format!("/templates/{missing}/reject"),
                Some(serde_json::json!({"reviewed_by": "adm", "reason": "r"})),
            ),
            (
                "POST",
                format!("/templates/{missing}/request-changes"),
                Some(serde_json::json!({"reviewed_by": "adm", "notes": "n"})),
            ),
            ("GET", format!("/templates/stats/{}", h.tenant_a), None),
            (
                "PUT",
                "/whitelabel/config".into(),
                Some(
                    serde_json::json!({"tenant_id": h.tenant_a, "company_name": "Brand", "primary_color": "#112233"}),
                ),
            ),
            ("GET", format!("/whitelabel/config/{}", h.tenant_a), None),
            (
                "POST",
                "/whitelabel/domains".into(),
                Some(
                    serde_json::json!({"tenant_id": h.tenant_a, "domain": "mail.example.com", "domain_type": "marketing"}),
                ),
            ),
            (
                "POST",
                format!("/whitelabel/domains/{missing}/verify"),
                None,
            ),
            (
                "GET",
                format!("/whitelabel/domains/tenant/{}", h.tenant_a),
                None,
            ),
            (
                "GET",
                format!("/whitelabel/email-templates/{}", h.tenant_a),
                None,
            ),
            (
                "POST",
                "/qbr".into(),
                Some(serde_json::json!({"tenant_id": h.tenant_a, "quarter": 1, "year": 2026})),
            ),
            ("GET", format!("/qbr/{missing}"), None),
            ("GET", format!("/qbr/tenant/{}", h.tenant_a), None),
            ("POST", format!("/qbr/{missing}/generate"), None),
            (
                "POST",
                format!("/qbr/{missing}/deliver"),
                Some(serde_json::json!({"delivered_to": ["a@b.c"]})),
            ),
            (
                "POST",
                format!("/qbr/{missing}/feedback"),
                Some(serde_json::json!({"rating": 4, "feedback_text": "ok"})),
            ),
            (
                "PUT",
                format!("/qbr/{missing}/goals"),
                Some(
                    serde_json::json!({"goal_id": "00000000-0000-4000-8000-000000000001", "current_value": 1.5}),
                ),
            ),
            ("GET", "/qbr/benchmarks".into(), None),
        ];

        for (method, path, body) in endpoints {
            let (status, json) = call(&app, method, &path, Some(&admin), body).await;
            assert!(
                status.is_server_error() || status == StatusCode::NOT_FOUND,
                "{method} {path}: expected a failure arm, got {status}: {json}"
            );
        }
    });
}

// ── Cross-tenant guards and not-found envelopes ──────────────────────────

#[test]
fn cross_tenant_overrides_and_foreign_resources_are_rejected() {
    run(async {
        let Some(h) = harness().await else { return };
        let app = h.app.clone();

        // A non-admin may not impersonate another tenant via x-tenant-id...
        for path in [
            "/contracts",
            "/support/metrics/x-should-not-matter",
            format!("/compliance/config/{}", h.tenant_a).as_str(),
        ] {
            let (status, json) = call_with_headers(
                &app,
                "GET",
                path,
                Some(&h.token_b),
                None,
                &[("x-tenant-id", h.tenant_a.clone())],
            )
            .await;
            assert_eq!(
                status,
                StatusCode::FORBIDDEN,
                "x-tenant-id override must be admin-only: {path} {json}"
            );
        }

        // ...while an admin override is accepted (not 403).
        let (status, _) = call_with_headers(
            &app,
            "GET",
            &format!("/compliance/config/{}", h.tenant_b),
            Some(&h.admin_token),
            None,
            &[("x-tenant-id", h.tenant_a.clone())],
        )
        .await;
        assert_ne!(status, StatusCode::FORBIDDEN, "admin override is accepted");

        // Foreign path-tenant resources are a 403 for user tokens.
        let (status, _) = call(
            &app,
            "GET",
            &format!("/compliance/status/{}", h.tenant_b),
            Some(&h.token_a),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);

        // Missing resources produce the enterprise 404 envelope.
        let missing = Uuid::new_v4();
        for (method, path) in [
            ("GET", format!("/log-streams/{missing}")),
            ("GET", format!("/deployments/{missing}")),
            ("GET", format!("/ips/{missing}")),
            ("GET", format!("/sub-accounts/{missing}")),
            ("GET", format!("/support/tickets/{missing}")),
            ("GET", format!("/templates/{missing}")),
            ("GET", format!("/qbr/{missing}")),
        ] {
            let (status, json) = call(&app, method, &path, Some(&h.token_a), None).await;
            assert_eq!(status, StatusCode::NOT_FOUND, "{method} {path}: {json}");
            assert_eq!(json["success"], false, "{json}");
            assert_eq!(json["code"], "NOT_FOUND", "{json}");
        }

        // A tenant with no whitelabel configuration gets a 404 — not an
        // empty success — from the email-templates listing.
        let (status, json) = call(
            &app,
            "GET",
            &format!("/whitelabel/email-templates/{}", h.tenant_b),
            Some(&h.token_b),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{json}");
        assert_eq!(json["code"], "NOT_FOUND", "{json}");
    });
}

// ── BYOIP CIDR validation ────────────────────────────────────────────────

#[test]
fn byoip_rejects_malformed_cidr_blocks_with_a_client_error() {
    run(async {
        let Some(h) = harness().await else { return };
        let app = h.app.clone();
        let tenant = h.tenant_a.clone();

        for bad_cidr in [
            "203.0.113.0",    // no prefix
            "203.0.113.0/xx", // non-numeric prefix
            "203.0.113.0/33", // v4 prefix too long
            "203.0.113.1/29", // host bits set
            "2001:db8::/129", // v6 prefix too long
            "2001:db8::1/64", // v6 host bits set
            "not-an-ip/24",   // bad address
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

        // The boundary prefixes stay valid: /32 and /0.
        for ok_cidr in ["203.0.113.9/32", "0.0.0.0/0", "2001:db8::/128", "::/0"] {
            let (status, json) = call(
                &app,
                "POST",
                "/ips/byoip",
                Some(&h.token_a),
                Some(serde_json::json!({"tenant_id": tenant, "cidr_block": ok_cidr})),
            )
            .await;
            assert!(
                status.is_success() || status == StatusCode::INTERNAL_SERVER_ERROR,
                "{ok_cidr} is a valid network: {status} {json}"
            );
        }
    });
}

// ── PDF proxy: 503 unconfigured, 502 broken, 200 success ─────────────────

/// A loopback PDF-renderer stand-in answering on `POST /v1/pdf/render`.
enum PdfRenderer {
    Succeed,
    Fail,
}

async fn spawn_pdf_mock(mode: PdfRenderer) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                break;
            };
            use tokio::io::AsyncReadExt;
            use tokio::io::AsyncWriteExt;
            // Drain the request before answering so the client's write
            // always completes (avoids RST-before-response races).
            let mut buf = vec![0u8; 8192];
            let _ = socket.read(&mut buf).await;
            let (status, content_type, body): (&str, &str, Vec<u8>) = match mode {
                PdfRenderer::Succeed => ("200 OK", "application/pdf", b"%PDF-1.4 cov".to_vec()),
                PdfRenderer::Fail => ("500 Internal Server Error", "text/plain", b"boom".to_vec()),
            };
            let head = format!(
                "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            let _ = socket.write_all(head.as_bytes()).await;
            let _ = socket.write_all(&body).await;
            let _ = socket.flush().await;
        }
    });
    format!("http://{addr}")
}

#[test]
fn pdf_endpoints_degrade_honestly_when_rendering_is_unconfigured_or_broken() {
    run(async {
        let Some(h) = harness().await else { return };
        let app = h.app.clone();
        let tenant = h.tenant_a.clone();
        std::env::remove_var("PDF_RENDERER_URL");

        // Unconfigured → 503 with the explicit setup message.
        let (status, json) = call(
            &app,
            "GET",
            &format!("/compliance/report/{tenant}/pdf"),
            Some(&h.admin_token),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{json}");

        // Point the renderer at a dead local port → 502 unreachable.
        std::env::set_var("PDF_RENDERER_URL", "http://127.0.0.1:1");
        let (status, _) = call(
            &app,
            "GET",
            &format!("/compliance/report/{tenant}/pdf"),
            Some(&h.admin_token),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::BAD_GATEWAY);
        std::env::remove_var("PDF_RENDERER_URL");

        // A foreign tenant may not render someone else's compliance report.
        let (status, _) = call(
            &app,
            "GET",
            &format!("/compliance/report/{}/pdf", h.tenant_b),
            Some(&h.token_a),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
    });
}

#[test]
fn qbr_pdf_renders_through_the_configured_renderer() {
    run(async {
        let Some(h) = harness().await else { return };
        let app = h.app.clone();
        let tenant = h.tenant_a.clone();

        // Schedule a real QBR to render.
        let (status, json) = call(
            &app,
            "POST",
            "/qbr",
            Some(&h.token_a),
            Some(serde_json::json!({"tenant_id": tenant, "quarter": 2, "year": 2026})),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{json}");
        let qbr_id = json["data"]["id"].as_str().expect("qbr id").to_string();

        // Foreign user: the tenant guard fires before any rendering.
        std::env::set_var("PDF_RENDERER_URL", "http://127.0.0.1:1");
        let (status, _) = call(
            &app,
            "GET",
            &format!("/qbr/{qbr_id}/pdf"),
            Some(&h.token_b),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);

        // Broken renderer (unreachable port) → 502.
        let (status, _) = call(
            &app,
            "GET",
            &format!("/qbr/{qbr_id}/pdf"),
            Some(&h.token_a),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::BAD_GATEWAY);

        // Renderer answering HTTP 500 → also a 502, from the status arm.
        let failing = spawn_pdf_mock(PdfRenderer::Fail).await;
        std::env::set_var("PDF_RENDERER_URL", &failing);
        let (status, _) = call(
            &app,
            "GET",
            &format!("/qbr/{qbr_id}/pdf"),
            Some(&h.token_a),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::BAD_GATEWAY, "renderer 500 → 502");

        // Working renderer → the bytes come back as a PDF attachment.
        let base = spawn_pdf_mock(PdfRenderer::Succeed).await;
        std::env::set_var("PDF_RENDERER_URL", &base);
        let (status, _) = call(
            &app,
            "GET",
            &format!("/qbr/{qbr_id}/pdf"),
            Some(&h.token_a),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "qbr pdf renders");
        std::env::remove_var("PDF_RENDERER_URL");
    });
}
