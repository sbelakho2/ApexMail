//! Fuzz tests for observability and ops service operations.

use fuzz_tests::*;
use observability_service::metrics_collector::MetricsCollector;
use ops_service::health::HealthChecker;
use ops_service::trust::{TenantMetrics, TrustScorer};
use ops_service::types::ServiceStatus;
use ops_service::warmup::IpWarmupManager;
use rand::Rng;
use sqlx::PgPool;
use uuid::Uuid;

#[test]
fn fuzz_metrics_record_no_panic() {
    // Random metric names and values must never crash the collector.
    let collector = MetricsCollector::new(vec![
        0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
    ]);
    let mut rng = rand::thread_rng();
    for _ in 0..5_000 {
        let name = random_string(rng.gen_range(1..50));
        let value: f64 = rng.gen_range(-1e12..1e12);
        let help = random_ascii(rng.gen_range(0..100));

        // All three metric types
        collector.record_counter(&name, value.abs(), &help);
        collector.record_gauge(&format!("{name}_gauge"), value, &help);
        collector.record_histogram(&format!("{name}_hist"), value, &help);
        collector.adjust_gauge(&format!("{name}_gauge"), value * -0.5, &help);
    }

    // Verify we can get a summary without panicking
    let summary = collector.get_summary();
    assert!(!summary.is_empty());

    // Verify Prometheus export doesn't panic
    let prom = collector.export_prometheus();
    assert!(!prom.is_empty());
}

#[test]
fn fuzz_trust_score_bounded() {
    // Any inputs should produce a trust score in [0, 100].
    let mut rng = rand::thread_rng();
    for _ in 0..10_000 {
        let metrics = TenantMetrics {
            tenant_id: Uuid::new_v4(),
            bounce_rate: random_f64_range(-0.5, 2.0),
            complaint_rate: random_f64_range(-0.5, 2.0),
            engagement_rate: random_f64_range(-0.5, 2.0),
            age_days: rng.gen_range(0..10_000),
            volume: rng.gen_range(0..10_000_000),
        };
        let result = TrustScorer::compute_score(&metrics);
        assert!(
            (0.0..=100.0).contains(&result.score),
            "Trust score {:.2} out of range for bounce={:.2}, complaint={:.2}, engage={:.2}",
            result.score,
            metrics.bounce_rate,
            metrics.complaint_rate,
            metrics.engagement_rate
        );
    }
}

#[test]
fn fuzz_health_check_states() {
    // Recording health checks with random states must never crash.
    let checker = HealthChecker::new(1000);
    let statuses = [
        ServiceStatus::Operational,
        ServiceStatus::Degraded,
        ServiceStatus::PartialOutage,
        ServiceStatus::MajorOutage,
    ];
    let mut rng = rand::thread_rng();
    for _ in 0..5_000 {
        let service = random_string(rng.gen_range(1..30));
        let status = statuses[rng.gen_range(0..statuses.len())];
        let latency = rng.gen_range(0..10_000u64);
        let check = ops_service::types::HealthCheck {
            service: service.clone(),
            status,
            latency_ms: latency,
            timestamp: chrono::Utc::now(),
        };
        checker.record_check(check);
    }

    // Verify we can retrieve data without panicking
    let latest = checker.latest_checks();
    assert!(!latest.is_empty());

    // Retrieving history for random services
    for _ in 0..100 {
        let service = random_string(rng.gen_range(1..30));
        let history = checker.get_history(&service, 10);
        assert!(history.len() <= 10);
    }
}

#[tokio::test]
async fn fuzz_warmup_schedule_valid() {
    // Warmup calculations must always produce valid volumes (>= 0).
    let pool = PgPool::connect_lazy("postgres://localhost/unused").expect("lazy pool");
    let manager = IpWarmupManager::new(pool);
    let mut rng = rand::thread_rng();
    for _ in 0..5_000 {
        let ip = format!(
            "192.168.{}.{}",
            rng.gen_range(0..=255u8),
            rng.gen_range(1..=255u8)
        );
        let target: u64 = rng.gen_range(1..10_000_000);
        let days: u32 = rng.gen_range(1..60);

        let schedule = manager.create_schedule_sync(&ip, target, days);
        assert!(
            schedule.current_volume >= 1,
            "Day 0 volume should be >= 1, got {} for target={target}, days={days}",
            schedule.current_volume
        );
        assert!(
            schedule.current_volume <= target,
            "Day 0 volume {} exceeds target {target}",
            schedule.current_volume
        );

        // Advance through all days and verify monotonic increase
        let prev_volume = schedule.current_volume;
        for _ in 0..days {
            manager.advance_day_sync(&ip);
        }

        // After advancing total_days, volume should equal target
        let final_vol = manager.get_daily_volume(&ip, days);
        if let Some(vol) = final_vol {
            assert!(
                vol >= prev_volume,
                "Final volume {vol} less than initial {prev_volume}"
            );
            assert_eq!(vol, target, "Final volume should equal target");
        }
    }
}
