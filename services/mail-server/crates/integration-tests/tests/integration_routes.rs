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

    fn app() -> axum::Router {
        let mut state = AppState::from_config(DevExConfig::default()).expect("devex state");
        state.service_token = "test-key".into();
        build_router(state)
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

    #[tokio::test]
    async fn webhook_test_endpoint_accepts_post() {
        let body = serde_json::json!({
            "url": "https://httpbin.org/post",
            "event_type": "email.delivered"
        });
        let resp = app()
            .oneshot(
                Request::post("/webhooks/test")
                    .header("x-api-key", "test-key")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        // The handler tries to actually POST to the URL, and will fail in tests
        // (no network). We just verify the route exists and returns a response.
        // Either 200 (if network is available) or 500 (network error) is fine.
        assert!(
            resp.status() == StatusCode::OK || resp.status() == StatusCode::INTERNAL_SERVER_ERROR
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
                    .header("x-tenant-id", "tenant-test")
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
// Ops service (4 tests)
// ═══════════════════════════════════════════════════════════════════════════

mod ops {
    use super::*;
    use dashmap::DashMap;
    use ops_service::health::HealthChecker;
    use ops_service::incidents::IncidentManager;
    use ops_service::routes::{router, AppState};
    use ops_service::slo::SloTracker;
    use ops_service::warmup::IpWarmupManager;

    async fn app() -> axum::Router {
        let db = sqlx::PgPool::connect_lazy("postgres://localhost/unused")
            .expect("Failed to create lazy test database pool");

        router(AppState {
            db: db.clone(),
            health: HealthChecker::new(100),
            incidents: IncidentManager::new_ephemeral(),
            slo: SloTracker::new(),
            warmup: IpWarmupManager::new_ephemeral(),
            api_key: "test-key".into(),
            trust_cache: Arc::new(DashMap::new()),
        })
    }

    #[tokio::test]
    async fn health_checks_returns_200() {
        let resp = app()
            .await
            .oneshot(
                Request::get("/health/checks")
                    .header("x-api-key", "test-key")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let json = body_json(resp).await;
        assert!(json["checks"].is_array());
    }

    #[tokio::test]
    async fn status_page_returns_200() {
        let resp = app()
            .await
            .oneshot(
                Request::get("/status")
                    .header("x-api-key", "test-key")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn slos_list_returns_200() {
        let resp = app()
            .await
            .oneshot(
                Request::get("/slos")
                    .header("x-api-key", "test-key")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let json = body_json(resp).await;
        assert!(json["slos"].is_array());
    }

    #[tokio::test]
    async fn create_incident_returns_created() {
        let body = serde_json::json!({
            "title": "Integration test incident",
            "severity": "P3",
            "affected_services": ["api-server"]
        });
        let resp = app()
            .await
            .oneshot(
                Request::post("/incidents")
                    .header("x-api-key", "test-key")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Sales-autopilot service (4 tests)
// ═══════════════════════════════════════════════════════════════════════════

mod sales {
    use super::*;
    use sales_autopilot::calendar::CalendarService;
    use sales_autopilot::campaigns::CampaignManager;
    use sales_autopilot::crm::CrmService;
    use sales_autopilot::enrichment::EnrichmentService;
    use sales_autopilot::inbox::InboxManager;
    use sales_autopilot::routes::{router, AppState};
    use sqlx::postgres::PgPoolOptions;

    fn app() -> axum::Router {
        let db = PgPoolOptions::new()
            .max_connections(1)
            .acquire_timeout(std::time::Duration::from_millis(100))
            .connect_lazy("postgres://localhost/unused")
            .expect("lazy pool");
        router(AppState {
            db,
            crm: CrmService::new(),
            enrichment: EnrichmentService::new("http://mock"),
            campaigns: CampaignManager::new(10),
            calendar: CalendarService::new(),
            inbox: InboxManager::new(),
            service_token: "test-key".into(),
        })
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
    async fn create_lead_returns_ok() {
        let body = serde_json::json!({
            "email": "alice@acme.com",
            "name": "Alice Smith",
            "company": "Acme Corp"
        });
        let resp = app()
            .oneshot(
                Request::post("/leads")
                    .header("x-api-key", "test-key")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let json = body_json(resp).await;
        assert_eq!(json["email"], "alice@acme.com");
    }

    #[tokio::test]
    async fn list_leads_returns_200() {
        let resp = app()
            .oneshot(
                Request::get("/leads")
                    .header("x-api-key", "test-key")
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
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let json = body_json(resp).await;
        assert!(json["name"].is_string());
        assert!(json["industry"].is_string());
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// AI service (4 tests)
// ═══════════════════════════════════════════════════════════════════════════

mod ai {
    use super::*;
    use ai_service::routes::{build_router, default_app_state};
    use ai_service::types::{Model, ModelStatus, ModelType};

    fn app() -> axum::Router {
        let mut state = default_app_state();
        Arc::get_mut(&mut state)
            .expect("exclusive app state")
            .service_token = "test-key".into();
        state.inference.register_model(Model {
            id: "test-model".into(),
            name: "integration-test".into(),
            version: "1.0".into(),
            model_type: ModelType::Classification,
            accuracy: 0.92,
            trained_at: chrono::Utc::now(),
            status: ModelStatus::Ready,
        });
        build_router(state)
    }

    #[tokio::test]
    async fn health_returns_200() {
        let resp = app()
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
    async fn predict_with_registered_model() {
        let body = serde_json::json!({
            "model_id": "test-model",
            "input": { "features": [1, 2, 3] }
        });
        let resp = app()
            .oneshot(
                Request::post("/predict")
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
    async fn list_models_returns_registered_model() {
        let resp = app()
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
        assert!(json["success"].as_bool().unwrap());
        let models = json["data"].as_array().unwrap();
        assert!(models.iter().any(|m| m["id"] == "test-model"));
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Billing service — routes require DB/Redis state; test plan seed logic only
// (5 tests)
// ═══════════════════════════════════════════════════════════════════════════

mod billing {
    use billing_service::plans::default_plans;

    #[test]
    fn default_plans_contains_expected_tiers() {
        let plans = default_plans();
        let names: Vec<&str> = plans.iter().map(|p| p.name).collect();
        assert!(names.contains(&"free"));
        assert!(names.contains(&"starter"));
        assert!(names.contains(&"pro"));
        assert!(names.contains(&"enterprise"));
    }

    #[test]
    fn free_plan_has_zero_price() {
        let plans = default_plans();
        let free = plans.iter().find(|p| p.name == "free").unwrap();
        assert_eq!(free.price_monthly, 0);
        assert_eq!(free.price_yearly, 0);
    }

    #[test]
    fn enterprise_plan_has_all_features() {
        let plans = default_plans();
        let ent = plans.iter().find(|p| p.name == "enterprise").unwrap();
        assert!(ent.features.sso_enabled);
        assert!(ent.features.dedicated_ip);
        assert!(ent.features.audit_logs);
    }

    #[test]
    fn plans_sorted_by_sort_order() {
        let plans = default_plans();
        for w in plans.windows(2) {
            assert!(w[0].sort_order <= w[1].sort_order);
        }
    }

    #[test]
    fn all_plans_have_positive_limits() {
        let plans = default_plans();
        for p in &plans {
            // -1 means unlimited, otherwise must be positive
            assert!(
                p.email_limit > 0 || p.email_limit == -1,
                "{} email_limit",
                p.name
            );
            assert!(
                p.api_call_limit > 0 || p.api_call_limit == -1,
                "{} api_call_limit",
                p.name
            );
        }
    }
}
