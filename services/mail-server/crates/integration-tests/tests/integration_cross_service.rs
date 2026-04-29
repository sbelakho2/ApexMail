//! Cross-service integration tests.
//!
//! Verifies that types and logic from different crates compose correctly
//! without requiring external services.

// ═══════════════════════════════════════════════════════════════════════════
// 1. Billing plans can be validated against plan feature flags
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn billing_plans_feature_compatibility() {
    use billing_service::plans::default_plans;

    let plans = default_plans();
    let free = plans.iter().find(|p| p.name == "free").unwrap();
    let enterprise = plans.iter().find(|p| p.name == "enterprise").unwrap();

// Free plan should NOT have SSO; enterprise SHOULD
    assert!(!free.features.sso_enabled);
    assert!(enterprise.features.sso_enabled);

// Free plan has limited team members (1); enterprise has unlimited (-1)
    assert_eq!(free.features.max_team_members, 1);
    assert_eq!(enterprise.features.max_team_members, -1); // -1 = unlimited

// API access should be available on both
    assert!(free.features.api_access);
    assert!(enterprise.features.api_access);
}

// ═══════════════════════════════════════════════════════════════════════════
// 2. Pattern matcher + compliance risk scoring types composability
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn pattern_matcher_and_compliance_risk_scoring() {
    use compliance::types::RiskLevel;
    use pattern_matcher::{Rule, RuleCategory, RuleSet, Severity};

// Build a rule set with spam patterns
    let rules = vec![
        Rule::new("free money", "SPAM-001", RuleCategory::Spam, Severity::High, 8),
        Rule::new(
            "verify your account",
            "PHISH-001",
            RuleCategory::Phishing,
            Severity::Critical,
            10,
        ),
    ];
    let ruleset = RuleSet::new(rules);

// Evaluate against suspicious content
    let text = "Claim your free money now and verify your account!";
    let matches = ruleset.evaluate(text);
    assert_eq!(matches.len(), 2);

    let total_score = ruleset.total_score(text);
    assert!(total_score >= 18.0); // 8 + 10

// Map score to compliance risk level
    let risk = RiskLevel::from_score(total_score);
    assert!(risk == RiskLevel::Low || risk == RiskLevel::Medium);

// Verify critical detection
    assert!(ruleset.has_critical(text));
}

// ═══════════════════════════════════════════════════════════════════════════
// 3. Template renderer types + API server template routes logic
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn template_types_compose_with_api_types() {
// Verify template-renderer types serialize correctly for API consumption
    use template_renderer::types::{RenderMetadata, RenderResult};

    let result = RenderResult {
        html: "<h1>Hello {{name}}</h1>".into(),
        plaintext: Some("Hello {{name}}".into()),
        subject: Some("Welcome, {{name}}!".into()),
        metadata: RenderMetadata {
            render_time_ms: 5,
            html_size_bytes: 23,
            plaintext_size_bytes: Some(14),
            cached: false,
        },
    };

    let json = serde_json::to_value(&result).unwrap();
    assert!(json["html"].is_string());
    assert!(json["metadata"]["render_time_ms"].is_number());
    assert!(!json["metadata"]["cached"].as_bool().unwrap());
}

// ═══════════════════════════════════════════════════════════════════════════
// 4. AI content scoring integrated with sales-autopilot campaigns
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn ai_content_score_with_sales_campaign() {
    use ai_service::content::ContentOptimizer;
    use sales_autopilot::campaigns::CampaignManager;

    let optimizer = ContentOptimizer::new();
    let campaigns = CampaignManager::new(10);

// Create a campaign
    let campaign = campaigns
        .create_campaign(
            "tenant-a".into(),
            "Q1 Outreach".into(),
            "tmpl-001".into(),
            "all-leads".into(),
        )
        .unwrap();
    assert_eq!(campaign.name, "Q1 Outreach");

// Score candidate subject lines for the campaign
    let subjects = vec![
        "🔥 Limited time offer today!",
        "Hi {{name}}, quick question",
        "ENTER NOW AND WIN FREE STUFF",
        "Your weekly product update",
    ];

    let scores: Vec<u32> = subjects
        .iter()
        .map(|s| optimizer.score_subject_line(s))
        .collect();

// Personalised subject should score well
    let personalized_idx = 1;
    assert!(scores[personalized_idx] > 0);

// All scores should be within valid range
    for &score in &scores {
        assert!(score <= 100);
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// 5. Rate limiter + API-server rate limiting logic
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn rate_limiter_decision_types() {
    use apexmail_rate_limiter::{GovernorLimiter, RateLimitConfig};

    let config = RateLimitConfig::new(100).with_burst(10);
    let limiter = GovernorLimiter::new(&config);

// First request should be allowed
    let decision = limiter.check();
    assert!(decision.is_allowed());
    assert!(decision.remaining() > 0);

// Batch check
    let batch = limiter.check_n(5);
    assert!(batch.is_allowed());
}

// ═══════════════════════════════════════════════════════════════════════════
// 6. Observability metrics from ops service health checks
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn observability_metrics_from_ops_health_checks() {
    use observability_service::metrics_collector::MetricsCollector;
    use ops_service::health::HealthChecker;
    use ops_service::types::{HealthCheck, ServiceStatus};

    let metrics = MetricsCollector::new(vec![10.0, 50.0, 100.0, 500.0]);
    let checker = HealthChecker::new(100);

// Simulate health check results from ops service
    checker.record_check(HealthCheck {
        service: "api-server".into(),
        status: ServiceStatus::Operational,
        latency_ms: 12,
        timestamp: chrono::Utc::now(),
    });
    checker.record_check(HealthCheck {
        service: "billing".into(),
        status: ServiceStatus::Degraded,
        latency_ms: 450,
        timestamp: chrono::Utc::now(),
    });

// Record health check latencies in observability metrics
    let checks = checker.latest_checks();
    for check in &checks {
        metrics.record_histogram(
            "health_check_latency_ms",
            check.latency_ms as f64,
            "Health check latency",
        );
        if check.status != ServiceStatus::Operational {
            metrics.record_counter("health_check_degraded", 1.0, "Degraded checks");
        }
    }

    let summary = metrics.get_summary();
    assert!(summary.len() >= 1);
}

// ═══════════════════════════════════════════════════════════════════════════
// 7. Enterprise SSO types with API server auth types
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn enterprise_sso_types_serialize_correctly() {
    use enterprise::types::SSOConfigureRequest;

// Verify SSO types can round-trip through JSON (API compat)
    let req = SSOConfigureRequest {
        tenant_id: uuid::Uuid::new_v4().to_string(),
        provider_type: "saml".into(),
        domain: "acme.com".into(),
        enabled: Some(true),
        entity_id: Some("https://acme.com/saml".into()),
        sso_url: Some("https://idp.acme.com/sso".into()),
        certificate: Some("MIIC...".into()),
        oidc_client_id: None,
        oidc_client_secret: None,
        oidc_issuer: None,
        attribute_mapping: Some(serde_json::json!({"email": "user.email"})),
        enforce_sso: Some(false),
        session_duration_hours: Some(8),
    };

    let json = serde_json::to_value(&req).unwrap();
    assert_eq!(json["provider_type"], "saml");
    assert_eq!(json["domain"], "acme.com");

// Deserialize back
    let req2: SSOConfigureRequest = serde_json::from_value(json).unwrap();
    assert_eq!(req2.provider_type, "saml");
    assert_eq!(req2.tenant_id, req.tenant_id);
}

// ═══════════════════════════════════════════════════════════════════════════
// 8. Analytics types with billing usage tracking
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn analytics_types_with_billing_usage() {
    use analytics::types::{AnalyticsQuery, DeliverabilityMetrics};
    use billing_service::types::PlanFeatures;

// Verify analytics types work with billing plan features
    let query = AnalyticsQuery {
        tenant_id: "tenant-123".into(),
        start_date: chrono::Utc::now() - chrono::Duration::days(30),
        end_date: chrono::Utc::now(),
        event_types: Some(vec!["delivered".into(), "opened".into()]),
        group_by: Some("day".into()),
        dimensions: None,
        limit: Some(100),
    };
    let json = serde_json::to_value(&query).unwrap();
    assert_eq!(json["tenant_id"], "tenant-123");

    let features = PlanFeatures {
        advanced_analytics: true,
        send_time_optimization: true,
        ab_testing: true,
        ..PlanFeatures::default()
    };

// Gate analytics features based on plan
    assert!(features.advanced_analytics);
    assert!(features.send_time_optimization);

// Deliverability metrics type check
    let metrics = DeliverabilityMetrics {
        delivery_rate: 0.98,
        bounce_rate: 0.02,
        complaint_rate: 0.001,
        open_rate: 0.35,
        click_rate: 0.12,
        unsubscribe_rate: 0.005,
    };
    let mj = serde_json::to_value(&metrics).unwrap();
    assert!(mj["delivery_rate"].as_f64().unwrap() > 0.9);
}

// ═══════════════════════════════════════════════════════════════════════════
// 9. DevEx webhook signing verified by api-server webhook types
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn devex_webhook_signing_verification() {
    use devex_service::webhook_tester::WebhookTester;

    let secret = "whsec_test_secret_123";
    let tester = WebhookTester::new(secret.to_string()).expect("webhook tester");

// Build a test payload
    let payload = WebhookTester::build_test_payload("email.delivered");
    assert_eq!(payload["type"], "email.delivered");
    assert!(payload["test"].as_bool().unwrap());
    assert!(payload["data"]["email_id"].is_string());

// Sign the payload
    let body = serde_json::to_vec(&payload).unwrap();
    let signature = tester.sign_payload(&body);

// Signature format:t=<timestamp>,v1=<hex>
    assert!(signature.starts_with("t="));
    assert!(signature.contains(",v1="));

// Verify the signature with the same secret
    let verified = WebhookTester::verify_signature(secret, &body, &signature);
    assert!(verified);

// Verify fails with wrong secret
    let wrong = WebhookTester::verify_signature("wrong_secret", &body, &signature);
    assert!(!wrong);
}

// ═══════════════════════════════════════════════════════════════════════════
// 10. Billing quota check with rate limiting
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn billing_quota_with_rate_limiting() {
    use billing_service::plans::default_plans;
    use apexmail_rate_limiter::GovernorLimiter;

    let plans = default_plans();
    let free_plan = plans.iter().find(|p| p.name == "free").unwrap();
    let pro_plan = plans.iter().find(|p| p.name == "pro").unwrap();

// Free plan:lower rate limit
    let free_rps = (free_plan.api_call_limit as f64 / 86400.0).max(1.0) as u32;
    let free_limiter = GovernorLimiter::from_params(free_rps, free_rps * 2);

// Pro plan:higher rate limit
    let pro_rps = (pro_plan.api_call_limit as f64 / 86400.0).max(1.0) as u32;
    let pro_limiter = GovernorLimiter::from_params(pro_rps, pro_rps * 2);

// Pro plan should have higher burst capacity
    assert!(pro_rps >= free_rps);

// Both should allow initial requests
    assert!(free_limiter.check().is_allowed());
    assert!(pro_limiter.check().is_allowed());
}
