//! Stress tests — push data structures to large volumes and verify correctness.

use ai_service::bandits::BanditOptimizer;
use observability_service::metrics_collector::MetricsCollector;
use ops_service::health::HealthChecker;
use ops_service::types::{HealthCheck, ServiceStatus};
use pattern_matcher::rules::{Rule, RuleCategory, RuleSet, Severity};
use sales_autopilot::campaigns::CampaignManager;
use sales_autopilot::crm::CrmService;

// ---------------------------------------------------------------------------
// 1. Stress CRM — 10 000 leads
// ---------------------------------------------------------------------------

#[test]
fn test_stress_crm_many_leads() {
    let crm = CrmService::new();
    let mut lead_ids = Vec::with_capacity(10_000);

    for i in 0..10_000 {
        let lead = crm.create_lead(
            format!("lead{i}@stress.test"),
            format!("Lead {i}"),
            format!("Company {}", i % 100),
            "Tester".into(),
            "stress".into(),
        );
        lead_ids.push(lead.id);
    }

// Verify all are retrievable
    for id in &lead_ids {
        assert!(crm.get_lead(*id).is_ok(), "lead {id} not found");
    }

    let all = crm.list_leads(None, None);
    assert_eq!(all.len(), 10_000);
}

// ---------------------------------------------------------------------------
// 2. Stress campaign manager — 1 000 campaigns
// ---------------------------------------------------------------------------

#[test]
fn test_stress_campaign_manager() {
// Set max_campaigns high enough so we don't hit the active limit
// (campaigns are created in Draft status, so max is for Active ones)
    let mgr = CampaignManager::new(10_000);
    let mut campaign_ids = Vec::with_capacity(1_000);

    for i in 0..1_000 {
        let c = mgr
            .create_campaign(
                format!("Campaign {i}"),
                format!("tmpl_{i}"),
                format!("audience_{}", i % 10),
            )
            .unwrap();
        campaign_ids.push(c.id);
    }

    let all = mgr.list_campaigns();
    assert_eq!(all.len(), 1_000);
}

// ---------------------------------------------------------------------------
// 3. Stress metrics collector — 100 000 data points
// ---------------------------------------------------------------------------

#[test]
fn test_stress_metrics_collector() {
    let collector = MetricsCollector::new(vec![
        0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
    ]);

    for i in 0..100_000u64 {
        collector.record_counter(
            &format!("stress_counter_{}", i % 100),
            1.0,
            "stress test counter",
        );
    }

    let summary = collector.get_summary();
    assert!(!summary.is_empty());

// Each of the 100 counter names should have been incremented 1 000 times
    for m in &summary {
        assert!((m.value - 1_000.0).abs() < 1.0, "counter {} has value {}", m.name, m.value);
    }
}

// ---------------------------------------------------------------------------
// 4. Stress pattern rules — 1 000 rules, match against text
// ---------------------------------------------------------------------------

#[test]
fn test_stress_pattern_rules() {
    let rules: Vec<Rule> = (0..1_000)
        .map(|i| {
            Rule::new(
                format!("pattern{i}"),
                format!("RULE-{i:04}"),
                RuleCategory::Spam,
                Severity::Medium,
                i as u32 % 10,
            )
        })
        .collect();

    let ruleset = RuleSet::new(rules);
    assert_eq!(ruleset.rule_count(), 1_000);

// Text containing a handful of patterns
    let text = "This text has pattern0 and pattern500 and pattern999 in it";
    let matches = ruleset.evaluate(text);
    assert!(matches.len() >= 3, "expected at least 3 matches, got {}", matches.len());

// Verify no panic on large input
    let large_text = "clean ".repeat(10_000);
    let _ = ruleset.evaluate(&large_text);
}

// ---------------------------------------------------------------------------
// 5. Stress health checker — 1 000 services
// ---------------------------------------------------------------------------

#[test]
fn test_stress_health_checker() {
    let checker = HealthChecker::new(100);

    for i in 0..1_000 {
        checker.record_check(HealthCheck {
            service: format!("svc-{i}"),
            status: if i % 10 == 0 {
                ServiceStatus::Degraded
            } else {
                ServiceStatus::Operational
            },
            latency_ms: i as u64,
            timestamp: chrono::Utc::now(),
        });
    }

    let latest = checker.latest_checks();
    assert_eq!(latest.len(), 1_000);

// Verify individual service history
    let hist = checker.get_history("svc-0", 10);
    assert_eq!(hist.len(), 1);
    assert_eq!(hist[0].status, ServiceStatus::Degraded);
}

// ---------------------------------------------------------------------------
// 6. Stress bandit — 1 000 arms, record rewards, verify selection
// ---------------------------------------------------------------------------

#[test]
fn test_stress_bandit_many_arms() {
    let bandit = BanditOptimizer::new(0.1);
    let mut arm_ids = Vec::with_capacity(1_000);

    for i in 0..1_000 {
        let id = bandit.add_arm(&format!("variant-{i}"));
        arm_ids.push(id);
    }

// Record rewards for each arm
    for (i, id) in arm_ids.iter().enumerate() {
        let reward = if i % 2 == 0 { 1.0 } else { 0.0 };
        bandit.record_reward(id, reward).unwrap();
    }

    let stats = bandit.get_stats();
    assert_eq!(stats.len(), 1_000);

// Selection should still work with many arms
    for _ in 0..100 {
        let selected = bandit.select_arm().unwrap();
        assert!(arm_ids.contains(&selected));
    }
}
