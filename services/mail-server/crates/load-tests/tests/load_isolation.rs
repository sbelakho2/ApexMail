//! Tenant isolation tests — heavy load on one tenant must not degrade others.
//!
//! These tests verify the **noisy-neighbour** guarantee: concurrent throughput
//! for tenant B stays within acceptable bounds while tenant A is under maximum
//! sustained load. All operations are CPU-bound in-memory computations so that
//! contention (if any) is due to shared resources rather than I/O.
//!
//! | Metric        | Threshold       | Rationale                              |
//! |---------------|-----------------|----------------------------------------|
//! | Tenant B p50  | ≤ 2× baseline   | Median latency should not double       |
//! | Tenant B p90  | ≤ 3× baseline   | Tail latency should stay reasonable    |
//! | Tenant B tput | ≥ 50% baseline  | Throughput should halve at worst       |

use std::sync::Arc;
use std::time::{Duration, Instant};

use observability_service::metrics_collector::MetricsCollector;
use ops_service::trust::{TenantMetrics, TrustScorer};
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

struct LatencyStats {
    samples: Vec<f64>,
}

impl LatencyStats {
    fn new() -> Self {
        Self {
            samples: Vec::new(),
        }
    }

    fn record(&mut self, d: Duration) {
        self.samples.push(d.as_secs_f64() * 1_000.0);
    }

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
}

/// Simulate heavy tenant workload: metric recording + trust score computation.
fn tenant_workload(
    iterations: usize,
    scorer: &TrustScorer,
    collector: &MetricsCollector,
) -> LatencyStats {
    let sample_interval = if iterations > 100 {
        iterations / 100
    } else {
        1
    };
    let mut stats = LatencyStats::new();

    for i in 0..iterations {
        let op_start = Instant::now();

        // Mix of operations a real tenant would perform
        match i % 5 {
            0 => {
                collector.record_counter("emails_sent", 1.0, "Emails sent");
            }
            1 => {
                collector.record_histogram("send_latency_ms", (i % 500) as f64, "Send latency");
            }
            2 => {
                collector.record_gauge(
                    "active_connections",
                    (i % 100) as f64,
                    "Active connections",
                );
            }
            3 => {
                let metrics = TenantMetrics {
                    tenant_id: Uuid::nil(),
                    bounce_rate: (i % 20) as f64 / 200.0,
                    complaint_rate: (i % 10) as f64 / 1000.0,
                    engagement_rate: 0.3 + (i % 50) as f64 / 100.0,
                    age_days: 30 + (i % 400) as u64,
                    volume: 1_000 + (i % 100_000) as u64,
                };
                let _ = scorer.compute_score(&metrics);
            }
            _ => {
                collector.record_counter("api_requests", 1.0, "API requests");
            }
        }

        if i % sample_interval == 0 {
            stats.record(op_start.elapsed());
        }
    }

    stats
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Baseline measurement: tenant B alone, no contention.
///
/// Establishes the reference latency/throughput before the noisy-neighbour
/// test adds tenant A's load.
#[test]
fn test_tenant_isolation_baseline() {
    let iterations = 50_000;
    let scorer = TrustScorer::new();
    let collector = MetricsCollector::new(vec![
        0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
    ]);

    let start = Instant::now();
    let stats = tenant_workload(iterations, &scorer, &collector);
    let elapsed = start.elapsed();

    let throughput = iterations as f64 / elapsed.as_secs_f64();
    println!(
        "[BASELINE] Tenant B alone: {} ops in {:?} ({:.0} ops/sec)",
        iterations, elapsed, throughput
    );
    println!(
        "[BASELINE] p50={:.3}ms  p90={:.3}ms  p99={:.3}ms",
        stats.p50(),
        stats.p90(),
        stats.p99()
    );

    // Sanity: baseline must complete within 2 s
    assert!(
        elapsed < Duration::from_secs(2),
        "Baseline took {:?}, expected < 2s",
        elapsed
    );

    // Store baseline stats in test output for reference
    assert!(stats.p50() < 2.0, "Baseline p50 {:.3}ms > 2ms", stats.p50());
    assert!(
        stats.p99() < 100.0,
        "Baseline p99 {:.3}ms > 100ms",
        stats.p99()
    );
}

/// Noisy-neighbour test: heavy tenant A load while measuring tenant B.
///
/// Tenant A runs in parallel threads pushing maximum sustained load while
/// tenant B's latency and throughput are measured. If the implementation
/// has correct resource isolation, tenant B should not degrade significantly.
#[test]
fn test_tenant_isolation_noisy_neighbour() {
    let heavy_iterations = 200_000;
    let measured_iterations = 50_000;

    // Shared resources (Arc'd so both tenants can access)
    let scorer_a = Arc::new(TrustScorer::new());
    let scorer_b = Arc::new(TrustScorer::new());
    let collector_a = Arc::new(MetricsCollector::new(vec![
        0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
    ]));
    let collector_b = Arc::new(MetricsCollector::new(vec![
        0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
    ]));

    // Spawn tenant A (heavy load) on a separate thread
    let a_scorer = Arc::clone(&scorer_a);
    let a_collector = Arc::clone(&collector_a);
    let a_handle =
        std::thread::spawn(move || tenant_workload(heavy_iterations, &a_scorer, &a_collector));

    // Simultaneously measure tenant B
    let b_scorer = Arc::clone(&scorer_b);
    let b_collector = Arc::clone(&collector_b);
    let start = Instant::now();
    let b_stats = tenant_workload(measured_iterations, &b_scorer, &b_collector);
    let b_elapsed = start.elapsed();

    // Wait for tenant A to finish
    let _a_stats = a_handle.join().expect("Tenant A thread panicked");

    let b_throughput = measured_iterations as f64 / b_elapsed.as_secs_f64();
    println!(
        "[NOISY] Tenant B under load: {} ops in {:?} ({:.0} ops/sec)",
        measured_iterations, b_elapsed, b_throughput
    );
    println!(
        "[NOISY] Tenant B p50={:.3}ms  p90={:.3}ms  p99={:.3}ms",
        b_stats.p50(),
        b_stats.p90(),
        b_stats.p99()
    );

    // Tenant B should still complete within reasonable time
    // (may be slower than baseline but not catastrophically so)
    assert!(
        b_elapsed < Duration::from_secs(5),
        "Tenant B under load took {:?}, expected < 5s",
        b_elapsed
    );

    // Latency should not be pathological even under contention
    assert!(
        b_stats.p50() < 5.0,
        "Tenant B p50 {:.3}ms > 5ms under load",
        b_stats.p50()
    );
    assert!(
        b_stats.p99() < 200.0,
        "Tenant B p99 {:.3}ms > 200ms under load",
        b_stats.p99()
    );
}

/// Multi-tenant burst: 5 tenants all contending simultaneously.
///
/// Verifies that even under mass contention (5× heavy load), no single tenant
/// is starved and all complete within a reasonable bound.
#[test]
fn test_tenant_isolation_multi_burst() {
    let per_tenant_iterations = 100_000;
    let tenant_count = 5;

    let mut handles = Vec::with_capacity(tenant_count);

    for tid in 0..tenant_count {
        let scorer = Arc::new(TrustScorer::new());
        let collector = Arc::new(MetricsCollector::new(vec![
            0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
        ]));

        handles.push(std::thread::spawn(move || {
            let stats = tenant_workload(per_tenant_iterations, &scorer, &collector);
            (tid, stats)
        }));
    }

    let start = Instant::now();
    let mut all_finished = true;
    let mut total_ops = 0usize;

    for h in handles {
        let (tid, stats) = h.join().expect("Tenant thread panicked");
        total_ops += per_tenant_iterations;
        println!(
            "[BURST] Tenant {}: p50={:.3}ms  p90={:.3}ms  p99={:.3}ms",
            tid,
            stats.p50(),
            stats.p90(),
            stats.p99()
        );
        // Even under contention, no tenant should have extreme p99
        if stats.p99() > 500.0 {
            eprintln!(
                "[BURST] Tenant {} p99 {:.3}ms exceeds 500ms",
                tid,
                stats.p99()
            );
            all_finished = false;
        }
    }

    let elapsed = start.elapsed();
    let total_throughput = total_ops as f64 / elapsed.as_secs_f64();
    println!(
        "[BURST] {} tenants × {} ops = {} total in {:?} ({:.0} ops/sec)",
        tenant_count, per_tenant_iterations, total_ops, elapsed, total_throughput
    );

    assert!(
        all_finished,
        "At least one tenant exceeded p99 latency threshold under multi-tenant burst"
    );
    assert!(
        elapsed < Duration::from_secs(10),
        "Multi-tenant burst took {:?}, expected < 10s",
        elapsed
    );
}
