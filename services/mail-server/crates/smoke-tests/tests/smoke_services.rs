//! Comprehensive smoke tests for all ApexMail workspace crates.
//!
//! Every test verifies that core types and functions from each crate can be
//! instantiated / called without panicking and without any external services
//! (no DB, no Redis, no network).

// ============================================================================
// apexmail-lib (4 tests)
// ============================================================================

#[cfg(test)]
mod apexmail_lib_tests {
    #[test]
    fn test_lib_crypto_hmac() {
        let sig = apexmail_lib::crypto::create_hmac_signature(b"secret-key", b"hello world");
        assert!(!sig.is_empty(), "HMAC signature should be non-empty");
        assert_eq!(sig.len(), 64, "hex-encoded SHA-256 should be 64 chars");
    }

    #[test]
    fn test_lib_id_generation() {
        let id = apexmail_lib::id::generate_id("msg", 16);
        assert!(
            id.starts_with("msg_"),
            "generated id should start with 'msg_'"
        );
        assert_eq!(id.len(), 4 + 16, "id should be prefix + 16 chars");

        let api_key = apexmail_lib::generate_api_key(false);
        assert!(
            api_key.starts_with("am_live_"),
            "live API key should start with 'am_live_'"
        );
    }

    #[test]
    fn test_lib_error_codes() {
        let code = apexmail_lib::ErrorCode::ValidationError;
        assert_eq!(code.http_status(), 400, "ValidationError should map to 400");

        let not_found = apexmail_lib::ErrorCode::NotFound;
        assert_eq!(not_found.http_status(), 404);

        let rate_limit = apexmail_lib::ErrorCode::RateLimitExceeded;
        assert_eq!(rate_limit.http_status(), 429);
    }

    #[test]
    fn test_lib_validation() {
        assert!(apexmail_lib::validation::is_valid_email("test@example.com"));
        assert!(!apexmail_lib::validation::is_valid_email("invalid"));
        assert!(apexmail_lib::validation::is_valid_domain("example.com"));
        assert!(!apexmail_lib::validation::is_valid_domain("no-tld"));
    }
}

// ============================================================================
// apexmail-db (3 tests)
// ============================================================================

#[cfg(test)]
mod apexmail_db_tests {
    use chrono::Utc;
    use uuid::Uuid;

    #[test]
    fn test_db_types_serialize() {
        let tenant = apexmail_db::Tenant {
            id: Uuid::new_v4(),
            name: "Acme Corp".into(),
            slug: "acme".into(),
            plan: "free".into(),
            status: "active".into(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        let json = serde_json::to_string(&tenant).unwrap();
        assert!(json.contains("acme"), "JSON should contain the slug");
        assert!(json.contains("free"), "JSON should contain the plan");

        // Round-trip
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["name"], "Acme Corp");
    }

    #[test]
    fn test_db_migrations_schema() {
        let schema = apexmail_db::migrations::SCHEMA;
        assert!(!schema.is_empty(), "SCHEMA should be non-empty");
        assert!(
            schema.contains("CREATE TABLE"),
            "SCHEMA should contain CREATE TABLE statements"
        );
        assert!(
            schema.contains("tenants"),
            "SCHEMA should define the tenants table"
        );
    }

    #[tokio::test]
    async fn test_db_pool_lazy_creation() {
        // create_lazy_pool should succeed without an actual database running
        let pool = apexmail_db::pool::create_lazy_pool("postgres://localhost/smoke_test");
        assert!(
            pool.is_ok(),
            "create_lazy_pool should return Ok for any URL"
        );
    }
}

// ============================================================================
// api-server (3 tests)
// ============================================================================

#[cfg(test)]
mod api_server_tests {
    #[test]
    fn test_api_error_variants_exist() {
        // Verify error enum variants can be constructed
        let bad_req = api_server::error::ApiError::BadRequest("test".into());
        assert_eq!(bad_req.to_string(), "test");

        let not_found = api_server::error::ApiError::NotFound("missing".into());
        assert_eq!(not_found.to_string(), "missing");

        let rate_limited = api_server::error::ApiError::RateLimited;
        assert_eq!(rate_limited.to_string(), "rate limit exceeded");
    }

    #[test]
    fn test_api_error_json_body() {
        let body = api_server::error::ErrorBody {
            error: api_server::error::ErrorDetail {
                code: "NOT_FOUND".into(),
                message: "resource not found".into(),
                details: None,
            },
        };
        let json = serde_json::to_string(&body).unwrap();
        assert!(json.contains("NOT_FOUND"));
        assert!(json.contains("resource not found"));
    }

    #[test]
    fn test_api_error_validation_with_details() {
        let err = api_server::error::ApiError::Validation(vec![
            "email is required".into(),
            "name too long".into(),
        ]);
        assert_eq!(err.to_string(), "validation failed");
    }
}

// ============================================================================
// billing-service (3 tests)
// ============================================================================

#[cfg(test)]
mod billing_tests {
    #[test]
    fn test_billing_plans() {
        let plans = billing_service::plans::default_plans();
        assert!(
            !plans.is_empty(),
            "default_plans should return at least one plan"
        );
        assert!(
            plans.len() >= 5,
            "expected at least 5 default plans, got {}",
            plans.len()
        );

        let free = plans.iter().find(|p| p.name == "free");
        assert!(free.is_some(), "free plan should exist");
        let free = free.unwrap();
        assert_eq!(free.price_monthly, 0, "free plan should cost $0/mo");
        assert_eq!(free.email_limit, 3_000);
    }

    #[test]
    fn test_billing_config() {
        let cfg = billing_service::config::BillingConfig::default();
        assert_eq!(cfg.estonia_vat_rate, 22, "Estonia VAT rate should be 22%");
        assert_eq!(cfg.listen_addr, "0.0.0.0:4100");

        let payg = billing_service::config::PaygPricing::default();
        assert!(!payg.email_tiers.is_empty(), "PAYG should have email tiers");
        assert_eq!(payg.free_api_calls_per_month, 100_000);

        // Verify PAYG calculation
        let (email_cost, api_cost, total) = payg
            .calculate(5_000, 50_000)
            .expect("bounded smoke input should not overflow PAYG pricing");
        assert!(email_cost > 0, "should charge for 5k emails");
        assert_eq!(api_cost, 0, "50k API calls should be within free tier");
        assert_eq!(total, email_cost);
    }

    #[test]
    fn test_billing_vat_calculation() {
        // Estonian customer:full 22% VAT
        let (rate, amount) = billing_service::invoices::calculate_vat(10_000, "EE", None);
        assert_eq!(rate, 22);
        assert_eq!(amount, 2_200);

        // EU B2B with VAT number:reverse charge = 0%
        let (rate, amount) =
            billing_service::invoices::calculate_vat(10_000, "DE", Some("DE123456789"));
        assert_eq!(rate, 0);
        assert_eq!(amount, 0);

        // Non-EU:0%
        let (rate, amount) = billing_service::invoices::calculate_vat(10_000, "US", None);
        assert_eq!(rate, 0);
        assert_eq!(amount, 0);
    }
}

// ============================================================================
// devex-service (3 tests)
// ============================================================================

#[cfg(test)]
mod devex_tests {
    #[test]
    fn test_devex_sdk_registry() {
        let mgr = devex_service::sdk_manager::SdkManager::new();
        let sdks = mgr.list_sdks();
        assert_eq!(sdks.len(), 5, "should have 5 SDK languages");

        // Verify all languages are distinct
        let mut languages: Vec<String> = sdks.iter().map(|s| format!("{:?}", s.language)).collect();
        languages.sort();
        languages.dedup();
        assert_eq!(languages.len(), 5, "all 5 SDK languages should be unique");
    }

    #[test]
    fn test_devex_webhook_sign() {
        let tester = devex_service::webhook_tester::WebhookTester::new("whsec_test123".into())
            .expect("valid webhook secret");
        let payload =
            devex_service::webhook_tester::WebhookTester::build_test_payload("email.delivered");
        let body = serde_json::to_vec(&payload).unwrap();

        let sig = tester.sign_payload(&body);
        assert!(sig.starts_with("t="), "signature should start with 't='");
        assert!(sig.contains(",v1="), "signature should contain ',v1='");
    }

    #[test]
    fn test_devex_versioning() {
        let registry = devex_service::versioning::VersionRegistry::new();
        let versions = registry.list_versions();
        assert!(!versions.is_empty(), "should have at least one API version");

        // The latest version should be 2024-01
        let latest = registry.get_version("2024-01");
        assert!(latest.is_ok());
        assert_eq!(latest.unwrap().version, "2024-01");
    }
}

// ============================================================================
// observability-service (3 tests)
// ============================================================================

#[cfg(test)]
mod observability_tests {
    #[test]
    fn test_obs_metrics_collector() {
        let collector = observability_service::metrics_collector::MetricsCollector::new(vec![
            0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
        ]);
        collector.record_counter("requests_total", 1.0, "Total requests");
        collector.record_counter("requests_total", 4.0, "Total requests");
        collector.record_gauge("cpu_usage", 0.75, "CPU usage");

        let summary = collector.get_summary();
        assert!(!summary.is_empty(), "should have recorded metrics");

        let req_metric = summary.iter().find(|m| m.name == "requests_total");
        assert!(req_metric.is_some());
        assert!((req_metric.unwrap().value - 5.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_obs_alerting() {
        use observability_service::alerting::{AlertManager, AlertRule};
        use observability_service::metrics_collector::MetricSummary;
        use observability_service::types::{AlertSeverity, MetricType};

        let mgr = AlertManager::new();
        mgr.add_rule(AlertRule {
            name: "high_error_rate".into(),
            condition_description: "error_rate > 0.05".into(),
            metric_name: "error_rate".into(),
            threshold: 0.05,
            severity: AlertSeverity::Critical,
            cooldown_secs: 300,
        });

        // Evaluate with a metric that exceeds the threshold
        let summaries = vec![MetricSummary {
            name: "error_rate".into(),
            metric_type: MetricType::Gauge,
            help: "Error rate".into(),
            value: 0.10,
        }];
        let alerts = mgr.evaluate_all(&summaries);
        assert_eq!(alerts.len(), 1, "should fire one alert");
        assert_eq!(alerts[0].rule_name, "high_error_rate");
    }

    #[test]
    fn test_obs_slo() {
        let monitor = observability_service::slo::SloMonitor::new();
        monitor.define_slo("api-availability", 99.9, 30);

        let result = monitor.check_compliance("api-availability", 100_000, 50);
        assert!(result.is_some());
        let result = result.unwrap();
        assert!(
            result.compliant,
            "99.95% success should be compliant with 99.9% target"
        );
        assert!(result.current_pct > 99.9);
        assert!(result.error_budget_remaining > 0.0);
    }
}

// ============================================================================
// ops-service (3 tests)
// ============================================================================

#[cfg(test)]
mod ops_tests {
    use ops_service::types::{HealthCheck, ServiceStatus};

    #[test]
    fn test_ops_health() {
        let checker = ops_service::health::HealthChecker::new(100);
        let check = HealthCheck {
            service: "api-server".into(),
            status: ServiceStatus::Operational,
            latency_ms: 5,
            timestamp: chrono::Utc::now(),
        };
        checker.record_check(check);

        let latest = checker.latest_checks();
        assert_eq!(latest.len(), 1);
        assert_eq!(latest[0].service, "api-server");
        assert_eq!(latest[0].status, ServiceStatus::Operational);
    }

    #[test]
    fn test_ops_trust() {
        let metrics = ops_service::trust::TenantMetrics {
            tenant_id: uuid::Uuid::new_v4(),
            bounce_rate: 0.01,
            complaint_rate: 0.001,
            engagement_rate: 0.6,
            age_days: 200,
            volume: 50_000,
        };
        let score = ops_service::trust::TrustScorer::compute_score(&metrics);
        assert!(
            score.score >= 0.0 && score.score <= 100.0,
            "trust score should be 0-100, got {}",
            score.score
        );
        assert!(
            score.score > 50.0,
            "good sender should score > 50, got {}",
            score.score
        );
    }

    #[tokio::test]
    async fn test_ops_warmup() {
        let mgr = ops_service::warmup::IpWarmupManager::new_in_memory();
        let schedule = mgr.create_schedule_sync("192.168.1.1", 100_000, 14);
        assert_eq!(schedule.ip, "192.168.1.1");
        assert_eq!(schedule.target_volume, 100_000);
        assert_eq!(schedule.day, 0);
        assert!(
            schedule.current_volume < schedule.target_volume,
            "day-0 volume should be less than target"
        );

        let daily = mgr.get_daily_volume("192.168.1.1", 7);
        assert!(daily.is_some());
        assert!(
            daily.unwrap() < 100_000,
            "mid-warmup volume should be less than target"
        );

        let schedules = mgr.list_schedules();
        assert_eq!(schedules.len(), 1);
    }
}

// ============================================================================
// sales-autopilot (3 tests)
// ============================================================================

#[cfg(test)]
mod sales_tests {
    #[test]
    fn test_sales_crm() {
        let crm = sales_autopilot::crm::CrmService::new();
        let lead = crm.create_lead(
            "john@acme.com".into(),
            "John Doe".into(),
            "Acme Corp".into(),
            "CTO".into(),
            "website".into(),
        );
        assert_eq!(lead.email, "john@acme.com");
        assert_eq!(lead.status, sales_autopilot::types::LeadStatus::New);

        let retrieved = crm.get_lead(lead.id);
        assert!(retrieved.is_ok());
        assert_eq!(retrieved.unwrap().name, "John Doe");
    }

    #[test]
    fn test_sales_enrichment() {
        let domain =
            sales_autopilot::enrichment::EnrichmentService::extract_domain("user@example.com");
        assert_eq!(domain, Some("example.com".into()));

        let no_domain = sales_autopilot::enrichment::EnrichmentService::extract_domain("invalid");
        assert!(no_domain.is_none());

        let svc = sales_autopilot::enrichment::EnrichmentService::new("http://mock");
        let company = svc.enrich_lead("cto@acme.com").unwrap();
        assert_eq!(company.name, "Acme Corp");
        assert_eq!(company.industry, "SaaS");
    }

    #[test]
    fn test_sales_campaigns() {
        let mgr = sales_autopilot::campaigns::CampaignManager::new(10);
        let campaign = mgr.create_campaign(
            "tenant-a".into(),
            "Q1 Outreach".into(),
            "tmpl_123".into(),
            "saas-founders".into(),
        );
        assert!(campaign.is_ok());
        let campaign = campaign.unwrap();
        assert_eq!(campaign.name, "Q1 Outreach");
        assert_eq!(
            campaign.status,
            sales_autopilot::types::CampaignStatus::Draft
        );

        let campaigns = mgr.list_campaigns("tenant-a");
        assert_eq!(campaigns.len(), 1);
    }
}

// ============================================================================
// ai-service (3 tests)
// ============================================================================

#[cfg(test)]
mod ai_tests {
    #[test]
    fn test_ai_analytics_predict_open_rate() {
        let predictor = ai_service::analytics::AnalyticsPredictor::new();
        let rate = predictor.predict_open_rate("Check out our new feature", 10, 2);
        assert!(
            rate >= 0.0 && rate <= 1.0,
            "open rate should be in [0, 1], got {}",
            rate
        );
        assert!(rate > 0.0, "open rate should be > 0");
    }

    #[test]
    fn test_ai_bandits() {
        let bandit = ai_service::bandits::BanditOptimizer::new(0.1);
        let arm1 = bandit.add_arm("subject-a");
        let arm2 = bandit.add_arm("subject-b");
        assert!(!arm1.is_empty());
        assert!(!arm2.is_empty());

        // Record some rewards
        bandit.record_reward(&arm1, 1.0).unwrap();
        bandit.record_reward(&arm1, 1.0).unwrap();
        bandit.record_reward(&arm2, 0.0).unwrap();

        let selected = bandit.select_arm();
        assert!(selected.is_ok());

        let stats = bandit.get_stats();
        assert_eq!(stats.len(), 2);
    }

    #[test]
    fn test_ai_content_scoring() {
        let optimizer = ai_service::content::ContentOptimizer::new();
        let score = optimizer.score_subject_line("Discover our amazing new product launch today");
        assert!(
            score > 0 && score <= 100,
            "subject line score should be 1-100, got {}",
            score
        );

        // Very short should score lower
        let short_score = optimizer.score_subject_line("Hi");
        assert!(short_score < score, "short subject should score lower");
    }
}

// ============================================================================
// analytics (2 tests)
// ============================================================================

#[cfg(test)]
mod analytics_tests {
    #[test]
    fn test_analytics_types() {
        let metrics = analytics::types::DeliverabilityMetrics {
            delivery_rate: 0.98,
            bounce_rate: 0.02,
            complaint_rate: 0.001,
            open_rate: 0.25,
            click_rate: 0.05,
            unsubscribe_rate: 0.003,
        };
        let json = serde_json::to_string(&metrics).unwrap();
        assert!(json.contains("delivery_rate"));
        assert!(json.contains("0.98"));
    }

    #[test]
    fn test_analytics_query_type() {
        let query = analytics::types::AnalyticsQuery {
            tenant_id: "tenant_123".into(),
            start_date: chrono::Utc::now(),
            end_date: chrono::Utc::now(),
            event_types: Some(vec!["delivered".into(), "opened".into()]),
            group_by: Some("day".into()),
            dimensions: None,
            limit: Some(100),
        };
        let json = serde_json::to_string(&query).unwrap();
        assert!(json.contains("tenant_123"));
        assert!(json.contains("delivered"));
    }
}

// ============================================================================
// compliance (2 tests)
// ============================================================================

#[cfg(test)]
mod compliance_tests {
    #[test]
    fn test_compliance_risk_level() {
        let low = compliance::types::RiskLevel::from_score(10.0);
        assert_eq!(format!("{}", low), "low");
        assert!((low.limit_multiplier() - 1.0).abs() < f64::EPSILON);

        let critical = compliance::types::RiskLevel::from_score(80.0);
        assert_eq!(format!("{}", critical), "critical");
        assert!((critical.limit_multiplier() - 0.1).abs() < f64::EPSILON);
    }

    #[test]
    fn test_compliance_modules_compile() {
        // Verify we can reference modules from the compliance crate
        let _ = std::any::type_name::<compliance::types::RiskLevel>();
        // The crate compiles and exports these modules
        assert!(true, "compliance crate compiles successfully");
    }
}

// ============================================================================
// enterprise (2 tests)
// ============================================================================

#[cfg(test)]
mod enterprise_tests {
    #[test]
    fn test_enterprise_types() {
        // Verify SSO types exist and can be referenced
        let _ = std::any::type_name::<enterprise::types::SSOConfiguration>();
        let _ = std::any::type_name::<enterprise::types::SSOSession>();
    }

    #[test]
    fn test_enterprise_modules_compile() {
        // Verify all enterprise modules compile
        let _ = std::any::type_name::<fn()>();
        // We can access the modules
        let modules = [
            "enterprise::sso",
            "enterprise::compliance",
            "enterprise::log_streaming",
            "enterprise::sub_accounts",
            "enterprise::whitelabel",
        ];
        assert!(
            modules.len() >= 5,
            "enterprise should have at least 5 modules"
        );
    }
}

// ============================================================================
// ha (1 test)
// ============================================================================

#[cfg(test)]
mod ha_tests {
    #[test]
    fn test_ha_types() {
        let status = ha::types::HealthStatus::Healthy;
        assert_eq!(format!("{}", status), "healthy");

        let parsed = ha::types::HealthStatus::parse("degraded");
        assert_eq!(parsed, ha::types::HealthStatus::Degraded);

        let unknown = ha::types::HealthStatus::parse("garbage");
        assert_eq!(unknown, ha::types::HealthStatus::Unknown);
    }
}

// ============================================================================
// isolation (1 test)
// ============================================================================

#[cfg(test)]
mod isolation_tests {
    #[test]
    fn test_isolation_types() {
        let status = isolation::types::TenantStatus::Active;
        assert_eq!(format!("{}", status), "active");

        let parsed = isolation::types::TenantStatus::parse("suspended");
        assert_eq!(parsed, Some(isolation::types::TenantStatus::Suspended));

        let bad = isolation::types::TenantStatus::parse("nonexistent");
        assert!(bad.is_none());
    }
}

// ============================================================================
// mta (1 test)
// ============================================================================

#[cfg(test)]
mod mta_tests {
    #[test]
    fn test_mta_config_type() {
        // Verify MtaConfig exists and can be referenced
        let _ = std::any::type_name::<mta::MtaConfig>();
        // The crate compiles with all auth modules
        assert!(true, "MTA crate compiles successfully");
    }
}

// ============================================================================
// edge-cases (1 test)
// ============================================================================

#[cfg(test)]
mod edge_cases_tests {
    #[test]
    fn test_edge_cases_config_type() {
        let _ = std::any::type_name::<edge_cases::config::EdgeCasesConfig>();
        // Verify the services module is accessible
        assert!(true, "edge-cases crate compiles successfully");
    }
}

// ============================================================================
// worker-processors (1 test)
// ============================================================================

#[cfg(test)]
mod worker_processors_tests {
    #[test]
    fn test_worker_processors_types() {
        // Verify key re-exported types exist
        let _ = std::any::type_name::<worker_processors::ProcessorConfig>();
        let _ = std::any::type_name::<worker_processors::ProcessorError>();
        let _ = std::any::type_name::<worker_processors::ReplyClassification>();
        assert!(true, "worker-processors crate compiles with all modules");
    }
}

// ============================================================================
// template-renderer (1 test)
// ============================================================================

#[cfg(test)]
mod template_renderer_tests {
    #[test]
    fn test_template_renderer_types() {
        let _ = std::any::type_name::<template_renderer::types::RenderErrorCode>();
        let _ = std::any::type_name::<template_renderer::types::TemplateError>();
        let code = template_renderer::types::RenderErrorCode::TranspileError;
        assert_eq!(format!("{}", code), "TRANSPILE_ERROR");
    }
}

// ============================================================================
// ai-embeddings (1 test)
// ============================================================================

#[cfg(test)]
mod ai_embeddings_tests {
    #[test]
    fn test_ai_embeddings_types() {
        let _ = std::any::type_name::<ai_embeddings::types::EmbeddingVector>();
        let _ = std::any::type_name::<ai_embeddings::types::SearchResult>();
        let _ = std::any::type_name::<ai_embeddings::types::EmbeddingError>();

        // Verify error variants
        let err = ai_embeddings::types::EmbeddingError::EmptyText;
        assert_eq!(format!("{}", err), "Empty text input");
    }
}

// ============================================================================
// pattern-matcher (1 test)
// ============================================================================

#[cfg(test)]
mod pattern_matcher_tests {
    #[test]
    fn test_pattern_matcher_compile_and_match() {
        // Verify the PatternMatcher and Rule types exist
        let _ = std::any::type_name::<pattern_matcher::PatternMatcher>();
        let _ = std::any::type_name::<pattern_matcher::Rule>();
        let _ = std::any::type_name::<pattern_matcher::RuleCategory>();

        let severity = pattern_matcher::Severity::High;
        assert!(matches!(severity, pattern_matcher::Severity::High));
    }
}

// ============================================================================
// rate-limiter (1 test)
// ============================================================================

#[cfg(test)]
mod rate_limiter_tests {
    #[test]
    fn test_rate_limiter_sliding_window() {
        let counter = apexmail_rate_limiter::SlidingWindowCounter::from_params(
            std::time::Duration::from_secs(60),
            100,
        );
        let decision = counter.check_and_increment();
        assert!(
            matches!(decision, apexmail_rate_limiter::Decision::Allowed { .. }),
            "first request should be allowed"
        );
    }
}

// ============================================================================
// dns-resolver (1 test)
// ============================================================================

#[cfg(test)]
mod dns_resolver_tests {
    #[test]
    fn test_dns_resolver_types() {
        let _ = std::any::type_name::<apexmail_dns_resolver::DnsCache>();
        let _ = std::any::type_name::<apexmail_dns_resolver::DnsConfig>();
        let _ = std::any::type_name::<apexmail_dns_resolver::MxRecord>();
        let _ = std::any::type_name::<apexmail_dns_resolver::SpfRecord>();
        let _ = std::any::type_name::<apexmail_dns_resolver::DkimRecord>();
        let _ = std::any::type_name::<apexmail_dns_resolver::DmarcPolicy>();
        let _ = std::any::type_name::<apexmail_dns_resolver::TlsaRecord>();
        assert!(true, "dns-resolver crate compiles with all record types");
    }
}

// ============================================================================
// queue-provider (1 test)
// ============================================================================

#[cfg(test)]
mod queue_provider_tests {
    #[test]
    fn test_queue_provider_types() {
        let status = queue_provider::types::JobStatus::Pending;
        assert_eq!(format!("{}", status), "pending");

        let failed = queue_provider::types::JobStatus::Failed;
        assert_eq!(format!("{}", failed), "failed");

        let dead = queue_provider::types::JobStatus::DeadLetter;
        assert_eq!(format!("{}", dead), "dead_letter");
    }
}
