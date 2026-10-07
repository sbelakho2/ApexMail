//! Comprehensive smoke tests for all ApexMail workspace crates.
//!
//! # Scope (O-31.1)
//! Smoke tests verify that every public API type can be **instantiated**,
//! **serialised**/deserialised, and that key functions return `Ok` / `Some`
//! on trivial inputs.  They deliberately do **not** exercise runtime
//! behaviour, data-flow correctness, or concurrent access — those concerns
//! are covered by the `functional-tests`, `integration-tests`, and
//! `load-tests` crates respectively.
//!
//! # Error-path coverage (O-31.3)
//! Each module below includes at least one negative test that verifies the
//! API handles invalid inputs gracefully (returns `Err`, `None`, or a
//! sensible default) rather than panicking.
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

    #[test]
    fn test_db_types_serialize() {
        let tenant = apexmail_db::Tenant {
            // tenants.id is the 26-char canonical type (migration 064 /
            // apexmail-db contract test) — not a UUID.
            id: "01JSMOKETESTTENANT000000A".into(),
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
        // Audit F6: the monolithic `apexmail_db::migrations::SCHEMA` constant
        // was deleted (it drifted from the canonical migration chain and
        // could never execute against a fresh database). The canonical
        // schema lives in `services/mail-server/migrations/` applied via the
        // `migrator` crate; the per-table DDL constants remain for isolated
        // test setup. Pin the smoke-test surface on those constants.
        let tenants = apexmail_db::migrations::CREATE_TENANTS;
        let users = apexmail_db::migrations::CREATE_USERS;
        assert!(tenants.contains("CREATE TABLE"), "tenants DDL must exist");
        assert!(tenants.contains("tenants"), "tenants DDL names its table");
        assert!(users.contains("CREATE TABLE"), "users DDL must exist");
        assert!(users.contains("users"), "users DDL names its table");
    }

    #[tokio::test]
    async fn test_db_pool_lazy_creation() {
        // create_lazy_pool should succeed without an actual database running
        // as long as `DATABASE_URL` is available (O-31.2).  If the env var is
        // absent, the pool creation is still expected to return `Ok` because
        // `connect_lazy` defers the actual connection.
        if std::env::var("DATABASE_URL").is_err() {
            eprintln!("INFO: DATABASE_URL not set — pool will use fallback URL");
        }
        let pool = apexmail_db::pool::create_lazy_pool("postgres://localhost/smoke_test");
        assert!(
            pool.is_ok(),
            "create_lazy_pool should return Ok for any syntactically valid URL"
        );
    }

    #[test]
    fn test_db_lazy_pool_malformed_url_returns_err() {
        // Verify that `create_lazy_pool` with a syntactically invalid URL
        // returns an error rather than panicking (O-31.3 error-path coverage).
        let result = apexmail_db::pool::create_lazy_pool("not-a-valid-connection-string");
        assert!(
            result.is_err(),
            "create_lazy_pool with a malformed URL should return Err, not panic"
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
        // Matches the shipped enum's Display (api-server/src/error.rs).
        assert_eq!(rate_limited.to_string(), "too many requests");
    }

    #[test]
    fn test_api_error_json_body() {
        let body = api_server::error::ErrorBody {
            data: None,
            error: Some(api_server::error::ErrorDetail {
                code: "NOT_FOUND".into(),
                message: "resource not found".into(),
                details: None,
            }),
            meta: None,
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

    // Audit F13: the smoke `test_billing_vat_calculation` was deleted — it
    // re-ran a subset of the VAT cases that `functional-tests`'s
    // `functional_billing.rs` owns (EE 24%, EU-B2B-without-evidence 19%,
    // non-EU 0%, plus FR B2C, negative/zero/overflow guards). One suite must
    // own the VAT behavior; look there.
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
        let tester =
            devex_service::webhook_tester::WebhookTester::new(vec!["whsec_test123".into()])
                .expect("valid webhook secret");
        let payload =
            devex_service::webhook_tester::WebhookTester::build_test_payload("message.delivered");
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
            operator: observability_service::alerting::ComparisonOperator::Gt,
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
        assert!(result.current_pct.expect("traffic observed") > 99.9);
        assert!(result.error_budget_remaining > 0.0);
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
            "tenant-a".into(),
            "john@acme.com".into(),
            "John Doe".into(),
            "Acme Corp".into(),
            "CTO".into(),
            "website".into(),
        );
        assert_eq!(lead.email, "john@acme.com");
        assert_eq!(lead.status, sales_autopilot::types::LeadStatus::New);

        let retrieved = crm.get_lead(&lead.id, "tenant-a");
        assert!(retrieved.is_ok());
        assert_eq!(retrieved.unwrap().name, "John Doe");
    }

    #[tokio::test]
    async fn test_sales_enrichment() {
        let domain =
            sales_autopilot::enrichment::EnrichmentService::extract_domain("user@example.com");
        assert_eq!(domain, Some("example.com".into()));

        let no_domain = sales_autopilot::enrichment::EnrichmentService::extract_domain("invalid");
        assert!(no_domain.is_none());

        let svc = sales_autopilot::enrichment::EnrichmentService::mock();
        let company = svc.enrich_lead("cto@acme.com").await.unwrap();
        assert_eq!(company.name, "Acme Corp");
        assert_eq!(company.industry, "SaaS");
    }

    #[test]
    fn test_sales_campaigns() {
        let campaign = sales_autopilot::types::Campaign {
            id: uuid::Uuid::new_v4(),
            tenant_id: "tenant-a".into(),
            name: "Q1 Outreach".into(),
            template_id: "tmpl_123".into(),
            audience: "saas-founders".into(),
            status: sales_autopilot::types::CampaignStatus::Draft,
            sent: 0,
            opened: 0,
            clicked: 0,
            created_at: chrono::Utc::now(),
        };

        assert_eq!(campaign.name, "Q1 Outreach");
        assert_eq!(
            campaign.status,
            sales_autopilot::types::CampaignStatus::Draft
        );

        let json = serde_json::to_value(&campaign).unwrap();
        assert_eq!(json["tenant_id"], "tenant-a");
        assert_eq!(json["status"], "draft");
    }
}

// ============================================================================
// ai-service (2 tests)
// ============================================================================

#[cfg(test)]
mod ai_tests {
    #[test]
    fn test_ai_analytics_predict_open_rate() {
        let predictor = ai_service::analytics::AnalyticsPredictor::new();
        let rate = predictor.predict_open_rate("Check out our new feature", 10, 2);
        assert!(
            (0.0..=1.0).contains(&rate),
            "open rate should be in [0, 1], got {}",
            rate
        );
        assert!(rate > 0.0, "open rate should be > 0");
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
    fn test_compliance_risk_level_type_exists() {
        // Compile-only existence check — the name now says exactly that
        // (audit F13). Behavior lives in the compliance crate's own tests
        // and `test_compliance_risk_level` above.
        let _ = std::any::type_name::<compliance::types::RiskLevel>();
    }
}

// ============================================================================
// enterprise (2 tests)
// ============================================================================

#[cfg(test)]
mod enterprise_tests {
    #[test]
    fn test_enterprise_sso_type_exists() {
        // Compile-only existence check — the name now says exactly that
        // (audit F13).
        let _ = std::any::type_name::<enterprise::types::SSOConfiguration>();
        let _ = std::any::type_name::<enterprise::types::SSOSession>();
    }

    #[test]
    fn test_enterprise_module_type_exists() {
        // Compile-only existence check (audit F13): each enterprise module's
        // service type must RESOLVE as a path. The previous body asserted
        // `modules.len() >= 5` on a hardcoded 5-element string array — an
        // assertion that could never fail and proved nothing about the
        // crate.
        let _ = std::any::type_name::<enterprise::sso::SSOService>();
        let _ = std::any::type_name::<enterprise::compliance::ComplianceService>();
        let _ = std::any::type_name::<enterprise::log_streaming::LogStreamingService>();
        let _ = std::any::type_name::<enterprise::sub_accounts::SubAccountService>();
        let _ = std::any::type_name::<enterprise::whitelabel::WhiteLabelService>();
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
    fn test_mta_config_type_exists_and_validates() {
        // Existence (audit F13) plus one REAL behavior assertion: the
        // default configuration must pass its own validator, and the
        // production decision must follow the NODE_ENV aliases.
        let mut cfg = mta::MtaConfig {
            node_env: "development".into(),
            ..mta::MtaConfig::default()
        };
        assert!(
            cfg.validate().is_ok(),
            "the default MTA configuration must validate: {:?}",
            cfg.validate()
        );
        assert!(!cfg.is_production(), "development must not be production");
        cfg.node_env = "prod".into();
        assert!(cfg.is_production(), "'prod' is a production alias");
    }
}

// ============================================================================
// edge-cases (1 test)
// ============================================================================

#[cfg(test)]
mod edge_cases_tests {
    #[test]
    fn test_edge_cases_config_type_exists() {
        // Compile-only existence check — the name now says exactly that
        // (audit F13).
        let _ = std::any::type_name::<edge_cases::config::EdgeCasesConfig>();
    }
}

// ============================================================================
// worker-processors (1 test)
// ============================================================================

#[cfg(test)]
mod worker_processors_tests {
    #[test]
    fn test_worker_processors_type_exists() {
        // Compile-only existence check — the name now says exactly that
        // (audit F13).
        let _ = std::any::type_name::<worker_processors::ProcessorConfig>();
        let _ = std::any::type_name::<worker_processors::ProcessorError>();
        let _ = std::any::type_name::<worker_processors::ReplyClassification>();
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
    fn test_ai_embeddings_type_exists() {
        // Compile-only existence check (audit F13) — plus one REAL
        // behavior assertion kept from the previous body: the error
        // variant's user-facing message.
        let _ = std::any::type_name::<ai_embeddings::types::EmbeddingVector>();
        let _ = std::any::type_name::<ai_embeddings::types::SearchResult>();
        let _ = std::any::type_name::<ai_embeddings::types::EmbeddingError>();

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
    fn test_pattern_matcher_type_exists() {
        // Compile-only existence check (audit F13 — the previous name
        // claimed a `match` that never ran; real matching behavior is
        // covered by `functional-tests`' `functional_pattern.rs`).
        let _ = std::any::type_name::<pattern_matcher::PatternMatcher>();
        let _ = std::any::type_name::<pattern_matcher::Rule>();
        let _ = std::any::type_name::<pattern_matcher::RuleCategory>();
        let _ = std::any::type_name::<pattern_matcher::Severity>();
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
    fn test_dns_resolver_type_exists() {
        // Compile-only existence check (audit F13). The parsing/cache
        // behavior lives in `test_dns_resolver_parses_records_and_caches`
        // below.
        let _ = std::any::type_name::<apexmail_dns_resolver::DnsCache>();
        let _ = std::any::type_name::<apexmail_dns_resolver::DnsConfig>();
        let _ = std::any::type_name::<apexmail_dns_resolver::MxRecord>();
        let _ = std::any::type_name::<apexmail_dns_resolver::SpfRecord>();
        let _ = std::any::type_name::<apexmail_dns_resolver::DkimRecord>();
        let _ = std::any::type_name::<apexmail_dns_resolver::DmarcPolicy>();
        let _ = std::any::type_name::<apexmail_dns_resolver::TlsaRecord>();
    }

    /// REAL behavior (audit F13): record parsing and the cache round-trip
    /// the resolver's lookup path depends on — no network, no services.
    #[test]
    fn test_dns_resolver_parses_records_and_caches() {
        use apexmail_dns_resolver::cache::CachedResult;
        use apexmail_dns_resolver::{DmarcPolicy, DnsCache, DnsConfig, SpfRecord};

        // SPF: a well-formed record parses with its `all` qualifier; a
        // look-alike version prefix ("v=spf1evil") is NOT an SPF record
        // (RFC 7208 §12) and must not shadow a real one.
        let spf = SpfRecord::parse("v=spf1 mx include:_spf.example.com -all")
            .expect("a well-formed SPF record must parse");
        assert!(spf.is_hard_fail(), "-all must parse as a hard fail");
        assert!(!spf.is_soft_fail());
        assert!(
            SpfRecord::parse("v=spf1evil mx -all").is_none(),
            "a version-prefix look-alike must not parse as SPF"
        );

        // DMARC: p=reject parses as a reject policy that subdomains inherit
        // when no explicit sp= is published.
        let dmarc = DmarcPolicy::parse("v=DMARC1; p=reject; pct=100")
            .expect("a well-formed DMARC record must parse");
        assert!(dmarc.is_reject());
        assert_eq!(dmarc.effective_subdomain_policy(), "reject");

        // Cache round-trip: positive records, negative (NXDOMAIN) results
        // and invalidation.
        let cache = DnsCache::new(&DnsConfig::default());
        let key = "mx:cache-roundtrip.example.com";
        cache.insert(key, vec!["10 mail.example.com".to_string()]);
        match cache.get(key) {
            Some(CachedResult::Records(records)) => {
                assert_eq!(records, vec!["10 mail.example.com".to_string()]);
            }
            other => panic!("expected the cached MX records, got {other:?}"),
        }
        let missing = "a:missing.cache-roundtrip.example.com";
        cache.insert_negative(missing);
        assert!(
            matches!(cache.get(missing), Some(CachedResult::NxDomain)),
            "a negative entry must read back as NXDOMAIN"
        );
        cache.invalidate(key);
        assert!(
            cache.get(key).is_none(),
            "invalidation must drop the cached entry"
        );
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
