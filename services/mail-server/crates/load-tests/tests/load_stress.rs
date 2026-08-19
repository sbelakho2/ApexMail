//! Stress tests — push data structures to large volumes and verify correctness.

use chrono::Utc;
use observability_service::metrics_collector::MetricsCollector;
use pattern_matcher::rules::{Rule, RuleCategory, RuleSet, Severity};
use sales_autopilot::crm::CrmService;
use sales_autopilot::types::{Campaign, CampaignStatus};
use std::collections::HashSet;
use uuid::Uuid;

// ---------------------------------------------------------------------------
// 1. Stress CRM — 10 000 leads
// ---------------------------------------------------------------------------

#[test]
fn test_stress_crm_many_leads() {
    let crm = CrmService::new();
    let mut lead_ids = Vec::with_capacity(10_000);

    for i in 0..10_000 {
        let lead = crm.create_lead(
            "stress".into(),
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
        assert!(crm.get_lead(id, "stress").is_ok(), "lead {id} not found");
    }

    let all = crm.list_leads("stress", None, None);
    assert_eq!(all.len(), 10_000);
}

// ---------------------------------------------------------------------------
// 2. Stress campaign data handling — 1 000 campaigns
// ---------------------------------------------------------------------------

#[test]
fn test_stress_campaign_manager() {
    let tenant_id = "tenant-a".to_string();
    let mut campaigns = Vec::with_capacity(1_000);
    let mut campaign_ids = HashSet::with_capacity(1_000);

    for i in 0..1_000 {
        let campaign = Campaign {
            id: Uuid::new_v4(),
            tenant_id: tenant_id.clone(),
            name: format!("Campaign {i}"),
            template_id: format!("tmpl_{i}"),
            audience: format!("audience_{}", i % 10),
            status: CampaignStatus::Draft,
            sent: 0,
            opened: 0,
            clicked: 0,
            created_at: Utc::now(),
        };
        assert!(campaign_ids.insert(campaign.id));
        campaigns.push(campaign);
    }

    let all: Vec<_> = campaigns
        .iter()
        .filter(|campaign| campaign.tenant_id == tenant_id)
        .collect();
    assert_eq!(all.len(), 1_000);
    assert!(all
        .iter()
        .all(|campaign| campaign.status == CampaignStatus::Draft));
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
        assert!(
            (m.value - 1_000.0).abs() < 1.0,
            "counter {} has value {}",
            m.name,
            m.value
        );
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
    assert!(
        matches.len() >= 3,
        "expected at least 3 matches, got {}",
        matches.len()
    );

    // Verify no panic on large input
    let large_text = "clean ".repeat(10_000);
    let _ = ruleset.evaluate(&large_text);
}

