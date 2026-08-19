//! Multi-step data flow integration tests.
//!
//! Each test simulates a realistic end-to-end pipeline that spans multiple
//! service crates, exercising them in sequence without external dependencies.

// ═══════════════════════════════════════════════════════════════════════════
// 1. Sales pipeline:create lead → enrich → score → campaign
// ═══════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn sales_pipeline_lead_to_campaign() {
    use ai_service::content::ContentOptimizer;
    use sales_autopilot::crm::CrmService;
    use sales_autopilot::enrichment::EnrichmentService;
    use sales_autopilot::types::{Campaign, CampaignStatus};

    let crm = CrmService::new();
    let enricher = EnrichmentService::mock();
    let optimizer = ContentOptimizer::new();

    // Step 1:Create a lead
    let lead = crm.create_lead(
        "tenant-a".into(),
        "alice@acme.com".into(),
        "Alice VP".into(),
        "Acme Corp".into(),
        "VP Engineering".into(),
        "product_hunt".into(),
    );
    assert_eq!(lead.email, "alice@acme.com");

    // Step 2:Enrich the lead
    let company = enricher.enrich_lead(&lead.email).await.unwrap();
    assert_eq!(company.domain, "acme.com");
    assert_eq!(company.industry, "SaaS");

    // Step 3:Score a subject line for the outreach
    let score = optimizer.score_subject_line("Hi Alice, quick question about Acme's email infra");
    assert!(score > 0);
    assert!(score <= 100);

    // Step 4:Compose a campaign targeting this lead
    let campaign = Campaign {
        id: uuid::Uuid::new_v4(),
        tenant_id: "tenant-a".into(),
        name: "Acme Outreach Q1".into(),
        template_id: "tmpl-acme".into(),
        audience: format!("lead_id={}", lead.id),
        status: CampaignStatus::Draft,
        sent: 0,
        opened: 0,
        clicked: 0,
        created_at: chrono::Utc::now(),
    };
    assert_eq!(campaign.name, "Acme Outreach Q1");
}

// ═══════════════════════════════════════════════════════════════════════════
// 2. Billing pipeline:plans → quota hierarchy validation
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn billing_plan_quota_hierarchy() {
    use billing_service::plans::default_plans;

    let plans = default_plans();

    // Collect (sort_order, email_limit) pairs
    let mut limits: Vec<(i32, i64)> = plans
        .iter()
        .filter(|p| p.email_limit > 0) // exclude unlimited (-1)
        .map(|p| (p.sort_order, p.email_limit))
        .collect();
    limits.sort_by_key(|&(order, _)| order);

    // Higher-tier plans should have higher or equal limits
    for w in limits.windows(2) {
        assert!(
            w[1].1 >= w[0].1,
            "Plan at order {} has lower limit than order {}",
            w[1].0,
            w[0].0
        );
    }

    // Verify specific plans
    let free = plans.iter().find(|p| p.name == "free").unwrap();
    let starter = plans.iter().find(|p| p.name == "starter").unwrap();
    assert!(starter.email_limit > free.email_limit);
    assert!(starter.price_monthly > free.price_monthly);
}

// ═══════════════════════════════════════════════════════════════════════════
// 3. Deterministic content helper behavior
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn deterministic_content_helpers_have_explicit_semantics() {
    use ai_service::content::ContentOptimizer;
    use ai_service::sto::SendTimeOptimizer;

    let content = ContentOptimizer::new();
    let score = content.score_subject_line("Your account update is ready today");
    assert!(score <= 100);

    let send_time = SendTimeOptimizer::new()
        .find_optimal_time(&[(9, 1, 0.3), (10, 2, 0.9), (15, 3, 0.5)])
        .expect("nonempty engagement data selects an existing slot");
    assert_eq!((send_time.hour, send_time.day_of_week), (10, 2));
}

// ═══════════════════════════════════════════════════════════════════════════
// 4. Observability pipeline:create alert rule → evaluate → acknowledge
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn observability_alert_pipeline() {
    use observability_service::alerting::{AlertManager, AlertRule, ComparisonOperator};
    use observability_service::metrics_collector::{MetricSummary, MetricsCollector};
    use observability_service::types::{AlertSeverity, AlertStatus};

    let alert_mgr = AlertManager::new();
    let metrics = MetricsCollector::new(vec![0.1, 0.5, 1.0]);

    // Step 1:Define an alert rule
    alert_mgr.add_rule(AlertRule {
        name: "high_error_rate".into(),
        condition_description: "error_rate > 0.05".into(),
        metric_name: "error_rate".into(),
        operator: ComparisonOperator::Gt,
        threshold: 0.05,
        severity: AlertSeverity::Critical,
        cooldown_secs: 0,
    });

    // Step 2:Record metrics that exceed threshold
    metrics.record_gauge("error_rate", 0.12, "Error rate");

    // Step 3:Evaluate alert rules against metric summaries
    let summaries = metrics.get_summary();
    let alert_summaries: Vec<MetricSummary> = summaries
        .iter()
        .map(|s| MetricSummary {
            name: s.name.clone(),
            metric_type: s.metric_type,
            help: s.help.clone(),
            value: s.value,
        })
        .collect();
    let fired = alert_mgr.evaluate_all(&alert_summaries);
    assert_eq!(fired.len(), 1);
    assert_eq!(fired[0].rule_name, "high_error_rate");
    assert_eq!(fired[0].status, AlertStatus::Firing);

    // Step 4:Acknowledge the alert
    let alert_id = fired[0].id.clone();
    assert!(alert_mgr.acknowledge(&alert_id));
    assert!(alert_mgr.list_active_alerts().is_empty());
}

// ═══════════════════════════════════════════════════════════════════════════
// 6. AI content loop:score → suggest → re-score
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn ai_content_score_improve_rescore() {
    use ai_service::content::ContentOptimizer;

    let opt = ContentOptimizer::new();

    // Step 1:Score a short, weak subject
    let original = "Hi";
    let score1 = opt.score_subject_line(original);

    // Step 2:Get suggestions
    let suggestions = opt.suggest_improvements(original);
    assert!(
        !suggestions.is_empty(),
        "Should have improvement suggestions for short subject"
    );

    // Step 3:Use the first suggestion and re-score
    let improved = &suggestions[0].suggested;
    let score2 = opt.score_subject_line(improved);

    // Improved subject should generally score better (longer, more descriptive)
    assert!(
        score2 >= score1,
        "Improved subject '{}' (score {}) should score >= original '{}' (score {})",
        improved,
        score2,
        original,
        score1
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// 7. Compliance pipeline:add rules → match → get severity
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn compliance_pattern_matching_pipeline() {
    use pattern_matcher::{Rule, RuleCategory, RuleSet, Severity};

    // Step 1:Define spam/phishing rules
    let rules = vec![
        Rule::new(
            "buy now",
            "SPAM-001",
            RuleCategory::Spam,
            Severity::Medium,
            5,
        ),
        Rule::new(
            "free money",
            "SPAM-002",
            RuleCategory::Spam,
            Severity::High,
            8,
        ),
        Rule::new(
            "verify your account",
            "PHISH-001",
            RuleCategory::Phishing,
            Severity::Critical,
            10,
        ),
        Rule::new(
            "click here immediately",
            "PHISH-002",
            RuleCategory::Phishing,
            Severity::Critical,
            9,
        ),
    ];
    let ruleset = RuleSet::new(rules);
    assert_eq!(ruleset.rule_count(), 4);

    // Step 2:Evaluate an email body
    let email_body = "Dear user, buy now to get free money! Verify your account.";
    let matches = ruleset.evaluate(email_body);
    assert_eq!(matches.len(), 3); // buy now, free money, verify your account

    // Step 3:Check total severity score
    let total = ruleset.total_score(email_body);
    assert!((total - 23.0).abs() < f64::EPSILON); // 5 + 8 + 10

    // Step 4:Verify critical detection triggers blocking
    assert!(ruleset.has_critical(email_body));

    // Step 5:Clean email passes
    let clean = "Hello, here is your weekly newsletter update.";
    assert!(ruleset.evaluate(clean).is_empty());
    assert!(!ruleset.has_critical(clean));
}

// ═══════════════════════════════════════════════════════════════════════════
