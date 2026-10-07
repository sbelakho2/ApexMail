//! HTTP route integration tests for each service.
//!
//! Uses `tower::ServiceExt::oneshot` to drive Axum routers without any
//! external dependencies (no DB, no Redis, no network).

use axum::body::Body;
use axum::http::{Request, StatusCode};
use std::sync::Arc;
use tower::ServiceExt;

// ═══════════════════════════════════════════════════════════════════════════
// Helper — read response body as JSON
// ═══════════════════════════════════════════════════════════════════════════

async fn body_json(resp: axum::http::Response<Body>) -> serde_json::Value {
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

// ═══════════════════════════════════════════════════════════════════════════
// DevEx service (5 tests)
// ═══════════════════════════════════════════════════════════════════════════

mod devex {
    use super::*;
    use devex_service::config::DevExConfig;
    use devex_service::routes::{build_router, AppState};
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn app() -> axum::Router {
        // SM12 F17: the credential is INJECTED into the state instead of
        // mutating the process-global environment (the old set_var raced
        // sibling threads under plain `cargo test`, where every test runs
        // in one process). Same injection pattern the devex in-crate and
        // AI-module tests use.
        let mut state = AppState::from_config(DevExConfig::default()).expect("devex state");
        state.service_auth =
            devex_service::auth::ServiceAuth::resolve(Some("test-key"), None, false)
                .expect("dedicated test credential resolves");
        build_router(state)
    }

    /// A local webhook sink: axum bound to an ephemeral loopback port that
    /// counts every received request (SM12 F5 — replaces httpbin.org).
    async fn spawn_webhook_sink() -> (String, Arc<AtomicUsize>) {
        let hits = Arc::new(AtomicUsize::new(0));
        let hits_for_handler = Arc::clone(&hits);
        let sink = axum::Router::new().route(
            "/hook",
            axum::routing::post(move || async move {
                hits_for_handler.fetch_add(1, Ordering::SeqCst);
                axum::http::StatusCode::OK
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind loopback sink");
        let addr = listener.local_addr().expect("sink local addr");
        tokio::spawn(async move {
            axum::serve(listener, sink)
                .await
                .expect("webhook sink server");
        });
        (format!("http://{addr}/hook"), hits)
    }

    async fn post_webhook_test(url: &str, event_type: &str) -> axum::http::Response<Body> {
        let body = serde_json::json!({ "url": url, "event_type": event_type });
        app()
            .oneshot(
                Request::post("/webhooks/test")
                    .header("x-api-key", "test-key")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn health_returns_200() {
        let resp = app()
            .oneshot(Request::get("/health").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let json = body_json(resp).await;
        assert_eq!(json["status"], "healthy");
    }

    #[tokio::test]
    async fn sdks_returns_five_entries() {
        let resp = app()
            .oneshot(
                Request::get("/sdks")
                    .header("x-api-key", "test-key")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let json = body_json(resp).await;
        assert_eq!(json["sdks"].as_array().unwrap().len(), 5);
    }

    /// SM12 F5: the route must deliver a PRECISE verdict against a local
    /// axum sink, not accept any 200-or-500 outcome against httpbin.org.
    /// A loopback target is refused by the production SSRF guard — and the
    /// sink must have received NOTHING (the guard blocks before any
    /// connection). If the guard is unwired, the sink receives the POST,
    /// the route answers 200, and both assertions fail.
    #[tokio::test]
    async fn webhook_test_route_blocks_private_target_before_any_delivery() {
        let (sink_url, sink_hits) = spawn_webhook_sink().await;
        let resp = post_webhook_test(&sink_url, "message.delivered").await;

        assert_eq!(
            resp.status(),
            StatusCode::INTERNAL_SERVER_ERROR,
            "a loopback webhook target must be refused, not delivered"
        );
        let json = body_json(resp).await;
        let error = json["error"].as_str().unwrap_or_default();
        assert!(
            error.contains("private/internal"),
            "the refusal must name the SSRF guard, got: {error}"
        );
        assert_eq!(
            sink_hits.load(Ordering::SeqCst),
            0,
            "the SSRF guard must stop the outbound POST before any request reaches the sink"
        );
    }

    /// The DNS-resolution failure arm delivers its own precise verdict.
    /// `.invalid` is guaranteed non-resolvable (RFC 2606): with a resolver
    /// it is NXDOMAIN, without one the lookup errors — both surface as the
    /// same "could not be resolved" refusal, so this is network-independent.
    #[tokio::test]
    async fn webhook_test_route_reports_unresolvable_hosts_precisely() {
        let host = format!("cold-{}.invalid", uuid::Uuid::new_v4().simple());
        let resp = post_webhook_test(&format!("https://{host}/hook"), "message.delivered").await;

        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let json = body_json(resp).await;
        let error = json["error"].as_str().unwrap_or_default();
        assert!(
            error.contains("could not be resolved"),
            "an unresolvable host must produce the DNS-refusal verdict, got: {error}"
        );
    }

    #[tokio::test]
    async fn webhook_test_route_refuses_non_http_schemes() {
        let resp = post_webhook_test("ftp://example.com/hook", "message.delivered").await;
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let json = body_json(resp).await;
        let error = json["error"].as_str().unwrap_or_default();
        assert!(
            error.contains("Only http/https"),
            "non-http schemes must be refused by the URL validator, got: {error}"
        );
    }

    /// The signature the tester stamps onto delivered webhooks is real
    /// HMAC (t=,v1= scheme): it verifies for the configured secret, fails
    /// for a tampered body, and fails for a different secret.
    #[tokio::test]
    async fn webhook_tester_signature_round_trips() {
        use devex_service::webhook_tester::WebhookTester;

        let tester = WebhookTester::new(vec!["whsec_integration_test_secret".into()])
            .expect("signing secret configured");
        let payload = WebhookTester::build_test_payload("message.delivered");
        let body = serde_json::to_vec(&payload).unwrap();

        let signature = tester.sign_payload(&body);
        assert!(
            signature.starts_with("t=") && signature.contains(",v1="),
            "the signature header must use the t=,v1= scheme, got: {signature}"
        );
        assert!(
            tester.verify_signature(&body, &signature),
            "the signed payload must verify against the configured secret"
        );

        let mut tampered = body.clone();
        tampered[0] ^= 0xff;
        assert!(
            !tester.verify_signature(&tampered, &signature),
            "a tampered body must fail signature verification"
        );

        let other = WebhookTester::new(vec!["whsec_other_secret".into()]).expect("secret");
        assert!(
            !other.verify_signature(&body, &signature),
            "a different secret must not verify the signature"
        );
    }

    #[tokio::test]
    async fn versions_returns_current_version() {
        let resp = app()
            .oneshot(
                Request::get("/versions")
                    .header("x-api-key", "test-key")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let json = body_json(resp).await;
        assert_eq!(json["current"], "2024-01");
        assert!(json["versions"].as_array().unwrap().len() >= 5);
    }

    #[tokio::test]
    async fn onboarding_checklist_returns_200() {
        let resp = app()
            .oneshot(
                Request::get("/onboarding/checklist")
                    .header("x-api-key", "test-key")
                    .header("x-tenant-id", "system") // batch fix: sales-autopilot serves the system tenant only
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Observability service (4 tests)
// ═══════════════════════════════════════════════════════════════════════════

mod observability {
    use super::*;
    use observability_service::alerting::AlertManager;
    use observability_service::log_aggregator::LogAggregator;
    use observability_service::metrics_collector::MetricsCollector;
    use observability_service::routes::{router, AppState};
    use observability_service::slo::SloMonitor;
    use observability_service::trace_collector::TraceCollector;

    fn app() -> (axum::Router, Arc<MetricsCollector>) {
        let metrics = Arc::new(MetricsCollector::new(vec![0.1, 0.5, 1.0]));
        let state = AppState::new(
            metrics.clone(),
            Arc::new(TraceCollector::new()),
            Arc::new(LogAggregator::new()),
            Arc::new(AlertManager::new()),
            Arc::new(SloMonitor::new()),
            "test-key".into(),
        );
        (router(state), metrics)
    }

    #[tokio::test]
    async fn health_returns_ok() {
        let (app, _) = app();
        let resp = app
            .oneshot(Request::get("/health").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let json = body_json(resp).await;
        assert_eq!(json["status"], "ok");
    }

    #[tokio::test]
    async fn metrics_summary_returns_recorded_metrics() {
        let (app, metrics) = app();
        metrics.record_counter("test_counter", 42.0, "test");

        let resp = app
            .oneshot(
                Request::get("/metrics/summary")
                    .header("x-api-key", "test-key")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let json = body_json(resp).await;
        let arr = json.as_array().unwrap();
        assert!(!arr.is_empty());
        assert!(arr.iter().any(|m| m["name"] == "test_counter"));
    }

    #[tokio::test]
    async fn alerts_list_empty_initially() {
        let (app, _) = app();
        let resp = app
            .oneshot(
                Request::get("/alerts")
                    .header("x-api-key", "test-key")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let json = body_json(resp).await;
        assert!(json.as_array().unwrap().is_empty());
    }

    #[tokio::test]
    async fn slos_list_returns_200() {
        let (app, _) = app();
        let resp = app
            .oneshot(
                Request::get("/slos")
                    .header("x-api-key", "test-key")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Sales-autopilot service (4 tests)
// ═══════════════════════════════════════════════════════════════════════════

mod sales {
    use super::*;
    use sales_autopilot::calendar::CalendarService;
    use sales_autopilot::campaigns::CampaignManager;
    use sales_autopilot::crm::CrmBackend;
    use sales_autopilot::enrichment::EnrichmentService;
    use sales_autopilot::inbox::InboxManager;
    use sales_autopilot::routes::{initialize_schema, router, AppState};
    use sqlx::postgres::PgPoolOptions;

    fn app() -> axum::Router {
        let db = PgPoolOptions::new()
            .max_connections(1)
            .acquire_timeout(std::time::Duration::from_millis(100))
            .connect_lazy("postgres://localhost/unused")
            .expect("lazy pool");
        // Use the repo's deterministic dead-end port (the same one
        // api-server's lazy test pools pin) so the rate limiter falls back
        // to its in-memory limiter. 16379 is the WORKING test Redis
        // elsewhere since the 2026-10-07 fold: pointing here used to mean
        // "dead port" and became NOAUTH -> 500 once a live Redis answered.
        let redis = deadpool_redis::Config::from_url("redis://127.0.0.1:1")
            .create_pool(Some(deadpool_redis::Runtime::Tokio1))
            .expect("Redis pool");
        router(AppState {
            config: Default::default(),
            db: db.clone(),
            redis,
            dispatcher: None,
            crm: CrmBackend::postgres(db.clone()),
            enrichment: EnrichmentService::mock(),
            campaigns: CampaignManager::new(10, db.clone()),
            calendar: CalendarService::new(db.clone()),
            inbox: InboxManager::new(db.clone()),
            // The planner requires an intelligence provider and a knowledge
            // base. The offline provider is the honest default here: it is what
            // an unconfigured deployment gets, and it keeps the send path
            // working without an AI service.
            intelligence: std::sync::Arc::new(
                sales_autopilot::intelligence::OfflineIntelligence::new(),
            ),
            strategist: std::sync::Arc::new(
                sales_autopilot::personalization::MessageStrategist::new(
                    db.clone(),
                    sales_autopilot::knowledge::SalesKnowledgeBase::canonical(),
                ),
            ),
            service_token: "test-key".into(),
            rate_limit_fallback: std::sync::Arc::new(parking_lot::Mutex::new(
                std::collections::HashMap::new(),
            )),
        })
    }

    /// Dedicated canonical database for the sales route tests. Provisioning
    /// goes through the REAL production migrator (audit F01), exactly like
    /// `crates/sales-autopilot/tests/common/mod.rs`; `initialize_schema` only
    /// VERIFIES the schema now, so runtime DDL is never the schema source.
    const SALES_ROUTES_DB: &str = "apexmail_integration_routes";

    /// Provisioning runs exactly once per test PROCESS; each test then gets a
    /// FRESH pool (a sqlx pool is bound to the runtime that created it —
    /// sharing one across `#[tokio::test]` runtimes deadlocks). SM12c: the
    /// hand-copied `test_database_url`/`database_url_for`/INIT block is
    /// replaced by the shared `migrator::test_support` helpers.
    static INIT: tokio::sync::OnceCell<bool> = tokio::sync::OnceCell::const_new();

    async fn app_with_test_db(test_name: &str) -> Option<axum::Router> {
        let ready = INIT
            .get_or_init(|| async {
                match migrator::test_support::provision_shared_canonical_db(SALES_ROUTES_DB).await {
                    Some(db) => {
                        // Post-migration assertion: the canonical chain must
                        // have produced the sales schema this suite exercises.
                        initialize_schema(&db).await.unwrap_or_else(|error| {
                            panic!(
                                "canonical test database `{SALES_ROUTES_DB}` does not carry the \
                                 sales schema this build expects: {error}"
                            )
                        });
                        db.close().await;
                        true
                    }
                    // None = TEST_DATABASE_URL unset/blank (soft-skip gate
                    // already applied inside the helper).
                    None => {
                        eprintln!(
                            "skipping {test_name}: set TEST_DATABASE_URL to run DB-backed test"
                        );
                        false
                    }
                }
            })
            .await;
        if !ready {
            return None;
        }

        let base_url = migrator::test_support::test_database_url()?;
        let db = migrator::test_support::connect_pool(&migrator::test_support::database_url_for(
            &base_url,
            SALES_ROUTES_DB,
        ))
        .await;

        let crm = CrmBackend::postgres(db.clone());
        crm.initialize()
            .await
            .unwrap_or_else(|error| panic!("failed to verify CRM schema for {test_name}: {error}"));

        // Use the repo's deterministic dead-end port (the same one
        // api-server's lazy test pools pin) so the rate limiter falls back
        // to its in-memory limiter. 16379 is the WORKING test Redis
        // elsewhere since the 2026-10-07 fold: pointing here used to mean
        // "dead port" and became NOAUTH -> 500 once a live Redis answered.
        let redis = deadpool_redis::Config::from_url("redis://127.0.0.1:1")
            .create_pool(Some(deadpool_redis::Runtime::Tokio1))
            .expect("Redis pool");
        Some(router(AppState {
            config: Default::default(),
            db: db.clone(),
            redis,
            dispatcher: None,
            crm,
            enrichment: EnrichmentService::mock(),
            campaigns: CampaignManager::new(10, db.clone()),
            calendar: CalendarService::new(db.clone()),
            inbox: InboxManager::new(db.clone()),
            // The planner requires an intelligence provider and a knowledge
            // base. The offline provider is the honest default here: it is what
            // an unconfigured deployment gets, and it keeps the send path
            // working without an AI service.
            intelligence: std::sync::Arc::new(
                sales_autopilot::intelligence::OfflineIntelligence::new(),
            ),
            strategist: std::sync::Arc::new(
                sales_autopilot::personalization::MessageStrategist::new(
                    db.clone(),
                    sales_autopilot::knowledge::SalesKnowledgeBase::canonical(),
                ),
            ),
            service_token: "test-key".into(),
            rate_limit_fallback: std::sync::Arc::new(parking_lot::Mutex::new(
                std::collections::HashMap::new(),
            )),
        }))
    }

    #[tokio::test]
    async fn health_reports_degraded_without_db() {
        // SM12c rename: this asserts the DELIBERATE degraded answer the
        // service gives without a database (503 + "degraded") — the old
        // `health_returns_200` name lied about what it pins.
        let resp = app()
            .oneshot(Request::get("/health").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
        let json = body_json(resp).await;
        assert_eq!(json["status"], "degraded");
    }

    #[tokio::test]
    async fn create_lead_returns_ok() {
        let Some(app) = app_with_test_db("create_lead_returns_ok").await else {
            return;
        };
        // Unique per run: the route tests share the (persistent)
        // TEST_DATABASE_URL and sales_leads enforces
        // UNIQUE(tenant_id, lower(contact_email)) — a fixed address 409s on
        // every suite re-run against the same database.
        let email = format!("alice-{}@acme.com", uuid::Uuid::new_v4().simple());
        let submitted_email = email.clone();
        let body = serde_json::json!({
            "email": email,
            "name": "Alice Smith",
            "company": "Acme Corp"
        });
        let resp = app
            .oneshot(
                Request::post("/leads")
                    .header("x-api-key", "test-key")
                    .header("x-tenant-id", "system") // batch fix: sales-autopilot serves the system tenant only
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let json = body_json(resp).await;
        // SM12 F6: assert against the SUBMITTED email — the previous line
        // compared `json["email"]` to itself (always true).
        assert_eq!(
            json["email"].as_str().unwrap_or(""),
            submitted_email,
            "created lead echoes the submitted email, got: {json}"
        );
    }

    #[tokio::test]
    async fn list_leads_returns_200() {
        let Some(app) = app_with_test_db("list_leads_returns_200").await else {
            return;
        };
        let resp = app
            .oneshot(
                Request::get("/leads")
                    .header("x-api-key", "test-key")
                    .header("x-tenant-id", "system") // batch fix: sales-autopilot serves the system tenant only
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn enrich_returns_company_data() {
        let body = serde_json::json!({ "email": "bob@beta.io" });
        let resp = app()
            .oneshot(
                Request::post("/enrich")
                    .header("x-api-key", "test-key")
                    .header("x-tenant-id", "system") // batch fix: sales-autopilot serves the system tenant only
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = resp.status();
        let body_bytes = axum::body::to_bytes(resp.into_body(), 65536).await.unwrap();
        let body_str = String::from_utf8_lossy(&body_bytes);
        assert_eq!(status, StatusCode::OK, "body: {body_str}");
        let json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
        assert!(json["name"].is_string());
        assert!(json["industry"].is_string());
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// AI service (4 tests)
// ═══════════════════════════════════════════════════════════════════════════

mod ai {
    use super::*;
    use ai_service::config::AiConfig;
    use ai_service::routes::{build_router, AppState};

    async fn app() -> axum::Router {
        // SM12 F17: config INJECTION instead of `std::env::set_var`. The
        // previous harness assumed nextest's one-process-per-test isolation;
        // under plain `cargo test` the concurrent set_var/read is a data
        // race. Both credentials now arrive through AiConfig/from_config —
        // the same pattern the AI module's in-crate tests use.
        let state = AppState::from_config(
            AiConfig {
                ai_admin_token: "test-ai-admin-key".into(),
                ..AiConfig::default()
            },
            "test-key".into(),
        )
        .await
        .expect("ai state from injected config");
        build_router(std::sync::Arc::new(state))
    }

    #[tokio::test]
    async fn health_returns_200() {
        let resp = app()
            .await
            .oneshot(Request::get("/health").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let json = body_json(resp).await;
        assert_eq!(json["status"], "ok");
    }

    #[tokio::test]
    async fn content_score_returns_score() {
        let body = serde_json::json!({ "subject": "🔥 Limited time offer today!" });
        let resp = app()
            .await
            .oneshot(
                Request::post("/content/score")
                    .header("x-api-key", "test-key")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let json = body_json(resp).await;
        assert!(json["success"].as_bool().unwrap());
    }

    #[tokio::test]
    async fn models_route_returns_runtime_status() {
        let resp = app()
            .await
            .oneshot(
                Request::get("/models")
                    .header("x-api-key", "test-key")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let json = body_json(resp).await;
        assert_eq!(json["success"], true);
        assert_eq!(json["data"]["runtime_enabled"], false);
        assert!(json["data"]["models"].is_array());
    }

    #[tokio::test]
    async fn predict_route_rejects_invalid_requests() {
        // Predict is exposed but must reject a malformed/empty request with a
        // client error (400/422) instead of reaching the LLM provider or
        // returning 404.
        let resp = app()
            .await
            .oneshot(
                Request::post("/predict")
                    .header("x-api-key", "test-key")
                    .header("content-type", "application/json")
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert!(resp.status().is_client_error(), "status: {}", resp.status());
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Billing service — plan-seed smoke only (SM12c: the CANONICAL default-plan
// assertions live in functional-tests functional_billing.rs; the deep
// per-feature/per-tier duplicates this module used to carry were removed so
// there is one source of truth. The HTTP-level billing behaviour (invoice
// creation, subscription override, wallet credit with idempotency keys) is
// covered DB-backed in concurrency_tests.rs — audit SM12 F16b.)
// ═══════════════════════════════════════════════════════════════════════════

mod billing {
    use billing_service::plans::default_plans;

    #[test]
    fn default_plans_seed_the_documented_tiers() {
        let plans = default_plans();
        let names: Vec<&str> = plans.iter().map(|p| p.name).collect();
        assert!(names.contains(&"free"));
        assert!(names.contains(&"starter"));
        assert!(names.contains(&"pro"));
        assert!(names.contains(&"enterprise"));
    }
}
