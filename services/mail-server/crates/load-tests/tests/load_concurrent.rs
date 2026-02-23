//! Concurrent access tests — tokio tasks sharing data structures via Arc.

use std::collections::HashSet;
use std::sync::Arc;

use ai_service::bandits::BanditOptimizer;
use apexmail_lib::{create_hmac_signature, generate_id};
use apexmail_lib::validation::is_valid_email;
use observability_service::metrics_collector::MetricsCollector;
use ops_service::health::HealthChecker;
use ops_service::types::{HealthCheck, ServiceStatus};
use pattern_matcher::matcher::build_matcher;
use sales_autopilot::crm::CrmService;

// ---------------------------------------------------------------------------
// 1. Concurrent ID generation — 100 tasks × 100 IDs, all unique
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_concurrent_id_generation() {
    let mut handles = Vec::new();
    for _ in 0..100 {
        handles.push(tokio::spawn(async move {
            let mut ids = Vec::with_capacity(100);
            for _ in 0..100 {
                ids.push(generate_id("lt", 20));
            }
            ids
        }));
    }

    let mut all_ids = HashSet::new();
    for h in handles {
        let ids = h.await.unwrap();
        for id in ids {
            assert!(all_ids.insert(id), "duplicate ID detected");
        }
    }
    assert_eq!(all_ids.len(), 10_000);
}

// ---------------------------------------------------------------------------
// 2. Concurrent email validation — 1 000 tasks
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_concurrent_email_validation() {
    let mut handles = Vec::new();
    for i in 0..1_000 {
        handles.push(tokio::spawn(async move {
            let valid = format!("user{}@example.com", i);
            let invalid = format!("bad-{}", i);
            assert!(is_valid_email(&valid), "expected valid: {valid}");
            assert!(!is_valid_email(&invalid), "expected invalid: {invalid}");
        }));
    }
    for h in handles {
        h.await.unwrap();
    }
}

// ---------------------------------------------------------------------------
// 3. Concurrent HMAC — 100 tasks, same key, same result
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_concurrent_hmac() {
    let key = b"shared-secret-key";
    let data = b"deterministic payload";
    let expected = create_hmac_signature(key, data);

    let mut handles = Vec::new();
    for _ in 0..100 {
        let exp = expected.clone();
        handles.push(tokio::spawn(async move {
            let sig = create_hmac_signature(b"shared-secret-key", b"deterministic payload");
            assert_eq!(sig, exp);
        }));
    }
    for h in handles {
        h.await.unwrap();
    }
}

// ---------------------------------------------------------------------------
// 4. Concurrent lead scoring — 100 tasks on shared CrmService
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_concurrent_lead_scoring() {
    let crm = Arc::new(CrmService::new());
    let mut handles = Vec::new();

    for i in 0..100 {
        let crm = Arc::clone(&crm);
        handles.push(tokio::spawn(async move {
            let email = format!("lead{}@acme.com", i);
            let lead = crm.create_lead(
                email,
                format!("Lead {i}"),
                "Acme".into(),
                "Engineer".into(),
                "load-test".into(),
            );
            // score_lead is a static method
            let score = CrmService::score_lead(0.5, 0.5, 0.5);
            assert_eq!(score, 50);
            lead
        }));
    }

    for h in handles {
        h.await.unwrap();
    }

    let all = crm.list_leads(None, None);
    assert_eq!(all.len(), 100);
}

// ---------------------------------------------------------------------------
// 5. Concurrent metric recording — 100 tasks on shared MetricsCollector
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_concurrent_metric_recording() {
    let collector = Arc::new(MetricsCollector::new(vec![
        0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
    ]));
    let mut handles = Vec::new();

    for i in 0..100 {
        let c = Arc::clone(&collector);
        handles.push(tokio::spawn(async move {
            c.record_counter("load_test_counter", 1.0, "load test counter");
            c.record_histogram("load_test_hist", i as f64, "load test histogram");
            c.record_gauge("load_test_gauge", i as f64, "load test gauge");
        }));
    }

    for h in handles {
        h.await.unwrap();
    }

    let summary = collector.get_summary();
    assert!(!summary.is_empty(), "metrics should have been recorded");

    // The counter should have been incremented 100 times
    let counter = summary.iter().find(|m| m.name == "load_test_counter");
    assert!(counter.is_some());
    assert!((counter.unwrap().value - 100.0).abs() < 1.0);
}

// ---------------------------------------------------------------------------
// 6. Concurrent health checks — 50 tasks on shared HealthChecker
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_concurrent_health_checks() {
    let checker = Arc::new(HealthChecker::new(1000));
    let mut handles = Vec::new();

    for i in 0..50 {
        let ch = Arc::clone(&checker);
        handles.push(tokio::spawn(async move {
            let svc_name = format!("svc-{i}");
            ch.record_check(HealthCheck {
                service: svc_name.clone(),
                status: ServiceStatus::Operational,
                latency_ms: i as u64,
                timestamp: chrono::Utc::now(),
            });
            let hist = ch.get_history(&svc_name, 10);
            assert!(!hist.is_empty());
        }));
    }

    for h in handles {
        h.await.unwrap();
    }

    let latest = checker.latest_checks();
    assert_eq!(latest.len(), 50);
}

// ---------------------------------------------------------------------------
// 7. Concurrent bandit selection — 100 tasks on shared BanditOptimizer
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_concurrent_bandit_selection() {
    let bandit = Arc::new(BanditOptimizer::new(0.3));

    // Register some arms upfront
    let arm_ids: Vec<String> = (0..5).map(|i| bandit.add_arm(&format!("arm-{i}"))).collect();

    // Seed some rewards so selection has data
    for id in &arm_ids {
        bandit.record_reward(id, 1.0).unwrap();
    }

    let mut handles = Vec::new();
    for _ in 0..100 {
        let b = Arc::clone(&bandit);
        let ids = arm_ids.clone();
        handles.push(tokio::spawn(async move {
            let selected = b.select_arm().unwrap();
            assert!(ids.contains(&selected));
        }));
    }

    for h in handles {
        h.await.unwrap();
    }
}

// ---------------------------------------------------------------------------
// 8. Concurrent pattern matching — 50 tasks on shared PatternMatcher
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_concurrent_pattern_matching() {
    let matcher = Arc::new(build_matcher(vec![
        ("spam", "category:spam"),
        ("phishing", "category:phishing"),
        ("malware", "category:malware"),
        ("bot", "category:bot"),
    ]));

    let mut handles = Vec::new();
    for i in 0..50 {
        let m = Arc::clone(&matcher);
        handles.push(tokio::spawn(async move {
            let text = if i % 2 == 0 {
                "this is spam content with phishing link"
            } else {
                "clean message with no bad words"
            };
            let results = m.find_all(text);
            if i % 2 == 0 {
                assert!(results.len() >= 2, "expected at least 2 matches");
            } else {
                assert!(results.is_empty(), "expected no matches");
            }
        }));
    }

    for h in handles {
        h.await.unwrap();
    }
}
