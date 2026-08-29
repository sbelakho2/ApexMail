//! Service-layer performance tests (observability, ops, devex).
//!
//! Each test measures both **throughput** (ops/sec) and **latency percentiles**
//! (p50, p90, p99) to ensure in-memory operations complete within acceptable
//! time bounds. Thresholds are tuned for in-memory operations:
//!
//! | Metric  | Threshold | Rationale |
//! |---------|-----------|----------|
//! | p50     | < 1 ms    | Median latency for hot-path in-memory ops |
//! | p90     | < 5 ms    | Tail latency under scheduler noise |
//! | p99     | < 50 ms   | Worst-case outlier (GC pause, preemption) |

use std::time::{Duration, Instant};

use devex_service::sdk_manager::SdkManager;
use devex_service::types::SdkLanguage;
use observability_service::metrics_collector::MetricsCollector;
mod budget;

// ─── Latency percentile helper ───────────────────────────────────

/// Collected latency samples for percentile analysis.
struct LatencySamples {
    samples: Vec<f64>, // individual durations in milliseconds
}

impl LatencySamples {
    fn with_capacity(cap: usize) -> Self {
        Self {
            samples: Vec::with_capacity(cap),
        }
    }

    fn record(&mut self, duration: Duration) {
        self.samples.push(duration.as_secs_f64() * 1_000.0); // ms
    }

    /// Compute a percentile value (0.0 – 1.0).
    fn percentile(&self, p: f64) -> f64 {
        if self.samples.is_empty() {
            return 0.0;
        }
        let mut sorted = self.samples.clone();
        sorted.sort_unstable_by(|a, b| a.partial_cmp(b).unwrap());
        let idx = ((sorted.len() as f64) * p).ceil() as usize - 1;
        let idx = idx.clamp(0, sorted.len() - 1);
        sorted[idx]
    }

    fn p50(&self) -> f64 {
        self.percentile(0.50)
    }
    fn p90(&self) -> f64 {
        self.percentile(0.90)
    }
    fn p99(&self) -> f64 {
        self.percentile(0.99)
    }

    /// Assert latency percentiles are within the given thresholds (ms).
    fn assert_latency(&self, label: &str, p50_max: f64, p90_max: f64, p99_max: f64) {
        let p50 = self.p50();
        let p90 = self.p90();
        let p99 = self.p99();
        eprintln!(
            "  [{label}] p50={p50:.3}ms  p90={p90:.3}ms  p99={p99:.3}ms  (samples={})",
            self.samples.len()
        );
        assert!(
            p50 <= p50_max,
            "[{label}] p50 latency {p50:.3}ms exceeds {p50_max}ms"
        );
        assert!(
            p90 <= p90_max,
            "[{label}] p90 latency {p90:.3}ms exceeds {p90_max}ms"
        );
        assert!(
            p99 <= p99_max,
            "[{label}] p99 latency {p99:.3}ms exceeds {p99_max}ms"
        );
    }
}

#[test]
fn test_metrics_recording_throughput() {
    let iterations = 100_000;
    let collector = MetricsCollector::new(vec![
        0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
    ]);

    let mut latencies = LatencySamples::with_capacity(iterations / 100);
    let start = Instant::now();
    for i in 0..iterations {
        let op_start = Instant::now();
        match i % 3 {
            0 => collector.record_counter("http_requests_total", 1.0, "Total HTTP requests"),
            1 => collector.record_histogram(
                "http_request_duration_seconds",
                0.042,
                "Request duration",
            ),
            _ => {
                collector.record_gauge("active_connections", (i % 500) as f64, "Active connections")
            }
        }
        // Sample every 100th operation for latency measurement
        if i % 100 == 0 {
            latencies.record(op_start.elapsed());
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
        elapsed < budget::from_secs(1),
        "100,000 metric recordings took {:?}, expected < 1s",
        elapsed
    );
    latencies.assert_latency("metrics_recording", 1.0, 5.0, 50.0);
}

#[test]
fn test_sdk_registry_lookup_throughput() {
    let iterations = 100_000;
    let manager = SdkManager::new();
    let languages = SdkLanguage::all();

    let mut latencies = LatencySamples::with_capacity(iterations / 100);
    let start = Instant::now();
    for i in 0..iterations {
        let op_start = Instant::now();
        let lang = languages[i % languages.len()];
        let _ = manager.get_sdk_info(lang);
        // Sample every 100th operation for latency measurement
        if i % 100 == 0 {
            latencies.record(op_start.elapsed());
        }
    }
    let elapsed = start.elapsed();

    println!(
        "SDK registry lookup throughput: {} ops in {:?} ({:.0} ops/sec)",
        iterations,
        elapsed,
        iterations as f64 / elapsed.as_secs_f64()
    );
    assert!(
        elapsed < budget::from_millis(500),
        "100,000 SDK lookups took {:?}, expected < 500ms",
        elapsed
    );
    latencies.assert_latency("sdk_registry_lookup", 1.0, 5.0, 50.0);
}
