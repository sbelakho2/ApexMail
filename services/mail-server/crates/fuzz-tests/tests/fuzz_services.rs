//! Fuzz tests for observability and ops service operations.

use fuzz_tests::*;
use observability_service::metrics_collector::MetricsCollector;
use rand::Rng;

#[test]
fn fuzz_metrics_record_no_panic() {
    // Random metric names and values must never crash the collector.
    let collector = MetricsCollector::new(vec![
        0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
    ]);
    let mut rng = rand::rng();
    for _ in 0..5_000 {
        let name = random_string(rng.random_range(1..50));
        let value: f64 = rng.random_range(-1e12..1e12);
        let help = random_ascii(rng.random_range(0..100));

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
