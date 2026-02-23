//! Service-layer performance tests (observability, ops, devex).

use std::time::{Duration, Instant};

use devex_service::sdk_manager::SdkManager;
use devex_service::types::SdkLanguage;
use observability_service::metrics_collector::MetricsCollector;
use ops_service::health::HealthChecker;
use ops_service::trust::{TenantMetrics, TrustScorer};
use uuid::Uuid;

#[test]
fn test_metrics_recording_throughput() {
    let iterations = 100_000;
    let collector = MetricsCollector::new(vec![
        0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
    ]);

    let start = Instant::now();
    for i in 0..iterations {
        match i % 3 {
            0 => collector.record_counter(
                "http_requests_total",
                1.0,
                "Total HTTP requests",
            ),
            1 => collector.record_histogram(
                "http_request_duration_seconds",
                0.042,
                "Request duration",
            ),
            _ => collector.record_gauge(
                "active_connections",
                (i % 500) as f64,
                "Active connections",
            ),
        }
    }
    let elapsed = start.elapsed();

    println!(
        "Metrics recording throughput: {} ops in {:?} ({:.0} ops/sec)",
        iterations,
        elapsed,
        iterations as f64 / elapsed.as_secs_f64()
    );
    assert!(
        elapsed < Duration::from_secs(1),
        "100,000 metric recordings took {:?}, expected < 1s",
        elapsed
    );
}

#[test]
fn test_health_check_throughput() {
    use chrono::Utc;
    use ops_service::types::{HealthCheck, ServiceStatus};

    let iterations = 100_000;
    let checker = HealthChecker::new(1000);

    let services = ["api", "smtp", "worker", "billing", "tracking"];
    let statuses = [
        ServiceStatus::Operational,
        ServiceStatus::Degraded,
        ServiceStatus::Operational,
        ServiceStatus::Operational,
        ServiceStatus::Operational,
    ];

    let start = Instant::now();
    for i in 0..iterations {
        let svc = services[i % services.len()];
        let status = statuses[i % statuses.len()];
        checker.record_check(HealthCheck {
            service: svc.to_string(),
            status,
            latency_ms: (i % 200) as u64,
            timestamp: Utc::now(),
        });
    }
    let elapsed = start.elapsed();

    println!(
        "Health check recording throughput: {} ops in {:?} ({:.0} ops/sec)",
        iterations,
        elapsed,
        iterations as f64 / elapsed.as_secs_f64()
    );
    assert!(
        elapsed < Duration::from_secs(1),
        "100,000 health check recordings took {:?}, expected < 1s",
        elapsed
    );
}

#[test]
fn test_trust_score_throughput() {
    let iterations = 100_000;

    let start = Instant::now();
    for i in 0..iterations {
        let metrics = TenantMetrics {
            tenant_id: Uuid::nil(),
            bounce_rate: (i % 20) as f64 / 200.0,
            complaint_rate: (i % 10) as f64 / 1000.0,
            engagement_rate: 0.3 + (i % 50) as f64 / 100.0,
            age_days: 30 + (i % 400) as u64,
            volume: 1_000 + (i % 100_000) as u64,
        };
        let _ = TrustScorer::compute_score(&metrics);
    }
    let elapsed = start.elapsed();

    println!(
        "Trust score throughput: {} ops in {:?} ({:.0} ops/sec)",
        iterations,
        elapsed,
        iterations as f64 / elapsed.as_secs_f64()
    );
    assert!(
        elapsed < Duration::from_secs(1),
        "100,000 trust score calculations took {:?}, expected < 1s",
        elapsed
    );
}

#[test]
fn test_sdk_registry_lookup_throughput() {
    let iterations = 100_000;
    let manager = SdkManager::new();
    let languages = SdkLanguage::all();

    let start = Instant::now();
    for i in 0..iterations {
        let lang = languages[i % languages.len()];
        let _ = manager.get_sdk_info(lang);
    }
    let elapsed = start.elapsed();

    println!(
        "SDK registry lookup throughput: {} ops in {:?} ({:.0} ops/sec)",
        iterations,
        elapsed,
        iterations as f64 / elapsed.as_secs_f64()
    );
    assert!(
        elapsed < Duration::from_millis(500),
        "100,000 SDK lookups took {:?}, expected < 500ms",
        elapsed
    );
}
