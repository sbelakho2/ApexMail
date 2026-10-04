//! Tenant isolation tests — heavy load on one tenant must not degrade others.
//!
//! Implemented for audit finding SM12 F4 (the file used to contain only this
//! doc comment and zero `#[test]`s). The noisy-neighbour guarantee is now
//! exercised against the REAL production machinery, in-process:
//!
//! * [`apexmail_rate_limiter::KeyedRateLimiter`] — the per-key governor map
//!   production API limiting actually uses — with one key per tenant, and
//! * [`observability_service::metrics_collector::MetricsCollector`] — the
//!   shared in-memory analytics aggregation both tenants write into.
//!
//! Tenant A hammers its own key at maximum sustainable rate while tenant B
//! runs a measured workload. Because the limiter keeps per-key governor
//! state, tenant A's hammering must never touch tenant B's budget, and the
//! shared structures must not degrade B's latency or throughput beyond the
//! documented bounds.
//!
//! | Metric        | Threshold       | Rationale                              |
//! |---------------|-----------------|----------------------------------------|
//! | Tenant B p50  | ≤ 2× baseline   | Median latency should not double       |
//! | Tenant B p90  | ≤ 3× baseline   | Tail latency should stay reasonable    |
//! | Tenant B tput | ≥ 50% baseline  | Throughput should halve at worst       |
//!
//! Scheduler-noise slack: on a loaded CI host the OS may deschedule B's
//! thread for milliseconds regardless of tenant isolation. The documented
//! RATIOS remain the bound; each is additionally floored by a small
//! ABSOLUTE term (2 µs on p50, 10 µs on p90) so a sub-microsecond baseline
//! cannot turn one scheduler tick into a false failure. The bounds these
//! tests enforce are therefore `ratio × baseline + slack`.
//!
//! The test additionally asserts the isolation actually HAPPENED: tenant A
//! must have been denied by the limiter (its own budget saturated) and its
//! denials must not have leaked into B's budget, and the shared metrics
//! aggregation must show EXACTLY the ops each tenant recorded.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use apexmail_rate_limiter::KeyedRateLimiter;
use observability_service::metrics_collector::MetricsCollector;

const TENANT_A: &str = "tenant-noisy-a";
const TENANT_B: &str = "tenant-quiet-b";

/// Measured workload size for tenant B (baseline AND noisy phases).
const TENANT_B_OPS: usize = 4_000;

/// A p50 at or below this many nanoseconds is treated as "effectively
/// instant" for the ratio floor — see the module doc on scheduler slack.
const P50_ABSOLUTE_SLACK: Duration = Duration::from_micros(2);
const P90_ABSOLUTE_SLACK: Duration = Duration::from_micros(10);

/// One measured tenant workload: drive the shared limiter with the tenant's
/// key and record every op into the shared analytics aggregation (one metric
/// name per tenant so the integrity check can attribute ops exactly).
/// Returns per-op latencies and the number of ops the limiter ALLOWED.
fn measured_workload(
    limiter: &KeyedRateLimiter,
    collector: &MetricsCollector,
    tenant_key: &str,
    ops: usize,
) -> (Vec<Duration>, usize) {
    let metric = format!("isolation::{tenant_key}");
    let mut latencies = Vec::with_capacity(ops);
    let mut allowed = 0usize;
    for _ in 0..ops {
        let start = Instant::now();
        let decision = limiter.check(tenant_key);
        collector.record_counter(&metric, 1.0, "noisy-neighbour probe");
        latencies.push(start.elapsed());
        if decision.is_allowed() {
            allowed += 1;
        }
    }
    (latencies, allowed)
}

fn percentile(sorted: &[Duration], p: f64) -> Duration {
    assert!(!sorted.is_empty(), "percentile of empty samples");
    let idx = (((sorted.len() - 1) as f64) * p).round() as usize;
    sorted[idx.min(sorted.len() - 1)]
}

fn throughput(ops: usize, elapsed: Duration) -> f64 {
    ops as f64 / elapsed.as_secs_f64()
}

/// The documented noisy-neighbour guarantee (SM12 F4).
///
/// Phase 0: warm both keys (lazy-init and cache-fill costs must not pollute
/// the baseline). Phase 1: measure tenant B ALONE (baseline). Phase 2:
/// tenant A hammers its own key on another thread while B repeats the same
/// measured workload. B's latency/throughput must stay within the doc
/// bounds, A must be throttled by its own budget, and the shared analytics
/// aggregation must have exactly counted each tenant's ops.
#[test]
fn noisy_neighbour_tenant_b_stays_within_documented_bounds() {
    // Budget design (per key, both tenants share the config):
    // * burst 20 000 — covers tenant B's ENTIRE test allowance (500 warm-up
    //   + 4 000 baseline + 4 000 noisy = 8 500) with margin, so the
    //   "B is denied" assertion can only ever fire on REAL cross-tenant
    //   leakage, never on B outrunning its own burst;
    // * refill 10 rps — negligible within a test's lifetime, so once
    //   tenant A's key is drained it STAYS drained (deterministic), and a
    //   hammering tenant can never ride the refill.
    let limiter = Arc::new(KeyedRateLimiter::from_params(10, 20_000, 1_000));
    let collector = Arc::new(MetricsCollector::new(vec![1.0, 10.0, 100.0]));

    // ── Phase 0: warm-up (discarded) ────────────────────────────────────
    measured_workload(&limiter, &collector, TENANT_B, 500);
    measured_workload(&limiter, &collector, TENANT_A, 500);

    // ── Phase 1: tenant B baseline, nobody else is running ──────────────
    let t0 = Instant::now();
    let (base_latencies, base_allowed) =
        measured_workload(&limiter, &collector, TENANT_B, TENANT_B_OPS);
    let base_tput = throughput(TENANT_B_OPS, t0.elapsed());
    let mut sorted_base = base_latencies;
    sorted_base.sort();
    let base_p50 = percentile(&sorted_base, 0.50);
    let base_p90 = percentile(&sorted_base, 0.90);
    println!(
        "baseline: p50={:?} p90={:?} tput={:.0} ops/s allowed={}/{}",
        base_p50, base_p90, base_tput, base_allowed, TENANT_B_OPS
    );
    assert_eq!(
        base_allowed, TENANT_B_OPS,
        "tenant B must not exhaust its own generous budget in the baseline phase"
    );

    // ── Phase 2: drain tenant A's budget, then hammer ───────────────────
    // Worst-case noisy neighbour: A is at ZERO budget before the hammer
    // starts. This makes the isolation proof deterministic — the denials
    // below cannot depend on how fast the hammer loop runs on this host.
    let mut a_drained = false;
    for _ in 0..(3 * 20_000) {
        if limiter.check(TENANT_A).is_denied() {
            a_drained = true;
            break;
        }
    }
    assert!(
        a_drained,
        "tenant A's key did not exhaust after 60 000 checks against a 20 000 burst — per-key accounting is broken"
    );

    let stop = Arc::new(AtomicBool::new(false));
    let noisy_limiter = Arc::clone(&limiter);
    let noisy_collector = Arc::clone(&collector);
    let stop_a = Arc::clone(&stop);
    let hammer = std::thread::spawn(move || {
        let mut ops = 0u64;
        while !stop_a.load(Ordering::Relaxed) {
            // Maximum-rate loop on A's OWN drained key: the limiter must
            // deny — that denial is the isolation proof.
            let _ = noisy_limiter.check(TENANT_A);
            noisy_collector.record_counter(&format!("isolation::{TENANT_A}"), 1.0, "noisy tenant");
            ops += 1;
        }
        ops
    });

    // Give A a moment to reach full hammering speed before B starts.
    std::thread::sleep(Duration::from_millis(20));

    let t1 = Instant::now();
    let (noisy_latencies, noisy_allowed) =
        measured_workload(&limiter, &collector, TENANT_B, TENANT_B_OPS);
    let noisy_tput = throughput(TENANT_B_OPS, t1.elapsed());

    stop.store(true, Ordering::Relaxed);
    let a_ops = hammer.join().expect("tenant A hammer thread panicked");

    let mut sorted_noisy = noisy_latencies;
    sorted_noisy.sort();
    let noisy_p50 = percentile(&sorted_noisy, 0.50);
    let noisy_p90 = percentile(&sorted_noisy, 0.90);

    println!(
        "noisy:    p50={:?} p90={:?} tput={:.0} ops/s allowed={}/{} (A performed {} ops)",
        noisy_p50, noisy_p90, noisy_tput, noisy_allowed, TENANT_B_OPS, a_ops
    );

    // ── Documented bounds (ratios × baseline, with the scheduler-noise
    //    floors documented in the module header) ─────────────────────────
    let p50_bound = base_p50.mul_f64(2.0) + P50_ABSOLUTE_SLACK;
    let p90_bound = base_p90.mul_f64(3.0) + P90_ABSOLUTE_SLACK;
    assert!(
        noisy_p50 <= p50_bound,
        "tenant B p50 {:?} exceeds 2× baseline {:?} (+ {:?} slack) under tenant A load — noisy neighbour",
        noisy_p50,
        base_p50,
        P50_ABSOLUTE_SLACK
    );
    assert!(
        noisy_p90 <= p90_bound,
        "tenant B p90 {:?} exceeds 3× baseline {:?} (+ {:?} slack) under tenant A load — noisy neighbour",
        noisy_p90,
        base_p90,
        P90_ABSOLUTE_SLACK
    );
    assert!(
        noisy_tput >= base_tput * 0.5,
        "tenant B throughput {:.0} ops/s fell below 50% of baseline {:.0} ops/s — noisy neighbour",
        noisy_tput,
        base_tput
    );

    // ── Isolation actually happened ─────────────────────────────────────
    // A started the hammer phase with a fully drained key (asserted above),
    // the 10 rps refill cannot quench a hot loop, and B is asserted
    // all-allowed below — so every global denial belongs to A, and any
    // B denial would prove cross-tenant leakage.
    assert!(
        limiter.total_denied() > 0,
        "a drained tenant A was never denied — per-key accounting is not enforcing budgets"
    );
    // Tenant B stayed under its own budget: every B op in the noisy phase
    // was admitted (its whole allowance fits the 20 000 burst).
    assert_eq!(
        noisy_allowed, TENANT_B_OPS,
        "tenant B was denied while under its own budget — tenant A's load leaked into B's key"
    );

    // ── Shared analytics aggregation integrity ──────────────────────────
    // Every tenant's ops were counted exactly — concurrent writers on the
    // shared collector must not lose or double-count increments. Tenant B
    // recorded warm-up + baseline + noisy under its own metric name.
    let summary = collector.get_summary();
    let metric_for = |name: &str| {
        summary
            .iter()
            .filter(|m| m.name == name)
            .map(|m| m.value)
            .sum::<f64>()
    };
    let b_recorded = metric_for(&format!("isolation::{TENANT_B}"));
    let b_ops_total = 500 + 2 * TENANT_B_OPS;
    assert!(
        (b_recorded - b_ops_total as f64).abs() < 1.0,
        "shared aggregation lost tenant B increments: expected {}, counted {}",
        b_ops_total,
        b_recorded
    );
    // Tenant A: warm-up + every hammer op (the drain loop bypasses the
    // collector), counted under its own metric name.
    let a_recorded = metric_for(&format!("isolation::{TENANT_A}"));
    let a_ops_total = 500 + a_ops;
    assert!(
        (a_recorded - a_ops_total as f64).abs() < 1.0,
        "shared aggregation mis-counted tenant A: expected {}, counted {}",
        a_ops_total,
        a_recorded
    );
}
