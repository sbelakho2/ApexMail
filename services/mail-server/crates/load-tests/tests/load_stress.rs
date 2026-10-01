//! Stress tests — push REAL production code to large volumes and verify correctness.
//!
//! SM12 F10: the old `test_stress_campaign_manager` built 1,000 `Campaign`
//! structs in a local `Vec`, filtered them by `tenant_id` and asserted the
//! count — exercising `Vec::filter`, not any manager, dispatch, or
//! enrollment. It is replaced by:
//!
//! * `test_stress_queue_fair_dispatch_claim_loop` — the REAL
//!   `queue_provider::FairQueueScheduler` (the fair-scheduling pass of the
//!   queue claim loop) driven at 100k jobs through a claim → schedule →
//!   dispatch → release-back loop;
//! * `test_stress_webhook_dispatch_logic` — the REAL webhook dispatch-side
//!   logic that is callable in-process (the retry ladder, delivery-result
//!   retryability policy, and payload truncation from
//!   `worker_processors::webhook::types`), driven at volume with invariant
//!   assertions. The full `WebhookProcessor` dispatch loop itself needs a
//!   live Postgres + Redis (it polls `webhook_jobs` via SKIP LOCKED), which
//!   is out of scope for a hermetic in-process load crate — the HTTP-level
//!   dispatcher is covered by the k6 suite.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

use chrono::Utc;
use observability_service::metrics_collector::MetricsCollector;
use pattern_matcher::rules::{Rule, RuleCategory, RuleSet, Severity};
use queue_provider::scheduler::FairQueueScheduler;
use queue_provider::types::{Job, JobStatus};
use sales_autopilot::crm::CrmService;
use uuid::Uuid;
use worker_processors::webhook::{truncate_payload, WebhookDeliveryResult, WebhookJob};

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
// 2. Stress the queue claim loop — 100 000 jobs through the REAL
//    FairQueueScheduler with release-back (SM12 F10)
// ---------------------------------------------------------------------------

fn make_job(tenant_id: Uuid, seq: usize) -> Job {
    Job {
        id: Uuid::new_v4(),
        tenant_id,
        queue: "stress".to_string(),
        payload: serde_json::json!({ "seq": seq }),
        status: JobStatus::Pending,
        attempts: 0,
        max_attempts: 3,
        priority: 0,
        scheduled_at: Utc::now(),
        started_at: None,
        completed_at: None,
        failed_at: None,
        error_message: None,
        visibility_timeout: 300,
        lease_token: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

#[test]
fn test_stress_queue_fair_dispatch_claim_loop() {
    const TENANTS: usize = 10;
    const TOTAL_JOBS: usize = 100_000;
    const BATCH_SIZE: usize = 500;

    let scheduler = FairQueueScheduler::default_scheduler(); // 30% max share
    let tenants: Vec<Uuid> = (0..TENANTS).map(|_| Uuid::new_v4()).collect();

    // Round-robin tenant assignment — the fair-share cap (ceil(30% of 500)
    // = 150 per tenant per pass) must hold for EVERY pass regardless.
    let pending: VecDeque<Job> = (0..TOTAL_JOBS)
        .map(|i| make_job(tenants[i % TENANTS], i))
        .collect();

    let mut pending = pending;
    let mut dispatched_total = 0usize;
    let mut passes = 0u64;
    let per_tenant_cap = ((BATCH_SIZE as f64) * 0.30).ceil() as usize;

    let start = Instant::now();
    while !pending.is_empty() {
        // "Dequeue" a batch (the scheduler consumes it — jobs are under
        // lease at this point, mirroring PostgresQueueProvider::dequeue).
        let batch: Vec<Job> = pending
            .drain(..BATCH_SIZE.min(pending.len()))
            .collect();
        let outcome = scheduler.schedule(batch, BATCH_SIZE);
        passes += 1;

        // Fairness invariant: no tenant exceeds its share of THIS pass.
        let dist = scheduler.tenant_distribution(&outcome.selected);
        for (tenant, count) in &dist {
            assert!(
                *count <= per_tenant_cap,
                "pass {passes}: tenant {tenant} got {count} dispatches, cap is {per_tenant_cap}"
            );
        }

        dispatched_total += outcome.selected.len();

        // Release the deferred jobs back to the FRONT of the pending queue
        // (they were claimed under lease and must not vanish — the exact
        // release-back the production caller must perform).
        for job in outcome.deferred.into_iter().rev() {
            pending.push_front(job);
        }

        // Progress guarantee: a non-empty pending queue always dispatches
        // at least one job (per-tenant caps are positive), so this loop
        // terminates. If a scheduler regression broke that, fail fast.
        if passes > 4 * TOTAL_JOBS as u64 {
            panic!(
                "claim loop made no progress after {} passes with {} jobs pending",
                passes,
                pending.len()
            );
        }
    }
    let elapsed = start.elapsed();

    // Correctness: every single job was dispatched exactly once — the old
    // Vec-filter test could never catch a scheduler that drops jobs.
    assert_eq!(
        dispatched_total, TOTAL_JOBS,
        "claim loop dispatched {dispatched_total} of {TOTAL_JOBS} jobs — lost work"
    );
    assert!(pending.is_empty(), "pending queue must drain completely");

    // Throughput floor for the stress volume (conservative CI floor; the
    // scheduler is an in-memory partition pass — hundreds of k jobs/sec).
    let jobs_per_sec = TOTAL_JOBS as f64 / elapsed.as_secs_f64();
    println!(
        "claim loop: {TOTAL_JOBS} jobs in {passes} passes, {elapsed:?} ({jobs_per_sec:.0} jobs/s)"
    );
    assert!(
        elapsed < Duration::from_secs(30),
        "100k-job claim loop took {elapsed:?} — scheduler throughput collapsed"
    );
    assert!(
        jobs_per_sec > 5_000.0,
        "scheduler throughput {jobs_per_sec:.0} jobs/s below the 5k/s stress floor"
    );
}

// ---------------------------------------------------------------------------
// 3. Stress webhook dispatch-side logic — 50 000 jobs through the REAL
//    retry ladder, retryability policy, and payload truncation (SM12 F10)
// ---------------------------------------------------------------------------

fn make_webhook_job(attempt: i32) -> WebhookJob {
    WebhookJob {
        id: format!("job-{attempt}"),
        webhook_id: "wh-1".into(),
        tenant_id: "tenant-1".into(),
        event_type: "email.delivered".into(),
        payload: serde_json::json!({}),
        url: "https://hooks.example.test/target".into(),
        secret: "whsec_stress".into(),
        headers: None,
        attempt,
        max_retries: 9,
        retry_delay: 0,
        backoff_multiplier: 1.0,
        created_at: Utc::now(),
        claim_token: None,
    }
}

#[test]
fn test_stress_webhook_dispatch_logic() {
    // The documented fixed retry ladder (worker_processors webhook types):
    // after attempt N (1-based), wait LADDER[N-1]; attempt ≥ 9 repeats the
    // last rung (exhaustion is scheduling, not a longer wait).
    const LADDER: [i64; 9] = [
        30_000, 120_000, 600_000, 1_800_000, 3_600_000, 10_800_000, 21_600_000, 43_200_000,
        86_400_000,
    ];

    let start = Instant::now();
    for i in 0..50_000u64 {
        let attempt = (i % 14) as i32 + 1; // 1..=14 — includes exhaustion territory
        let job = make_webhook_job(attempt);

        // Real retry-ladder computation for every job.
        let delay = job.next_retry_delay_ms();
        let expected = LADDER[(attempt.max(1) as usize).clamp(1, LADDER.len()) - 1];
        assert_eq!(
            delay, expected,
            "attempt {attempt}: wrong retry rung (got {delay}, want {expected})"
        );

        // Real delivery-result classification for the four outcome shapes.
        let ok = WebhookDeliveryResult::success(200, 12, None);
        assert!(!ok.is_retryable(), "2xx must not retry");
        let server = WebhookDeliveryResult::failure(Some(503), 5, "unavailable".into(), None, None);
        assert!(server.is_retryable(), "5xx must retry");
        let throttled =
            WebhookDeliveryResult::failure(Some(429), 5, "rate limited".into(), None, None);
        assert!(throttled.is_retryable(), "429 must retry");
        let network = WebhookDeliveryResult::failure(None, 0, "dial error".into(), None, None);
        assert!(network.is_retryable(), "network errors must retry");
        let gone = WebhookDeliveryResult::failure(Some(410), 3, "gone".into(), None, None);
        assert!(!gone.is_retryable(), "permanent 4xx must not retry");

        // Every 10th job also pays real payload truncation (a 100 KB
        // template body through the size-bounded truncator).
        if i % 10 == 0 {
            let payload = serde_json::json!({
                "html": "x".repeat(100_000),
                "meta": { "seq": i, "tenant": "tenant-1" },
            });
            let truncated = truncate_payload(&payload, 1_024);
            let serialized = serde_json::to_string(&truncated)
                .expect("serializing a serde_json::Value cannot fail");
            assert!(
                serialized.len() <= 1_024,
                "truncated payload is {} bytes, must fit 1024",
                serialized.len()
            );
            assert!(
                truncated.get("meta").is_some(),
                "truncation must preserve small fields"
            );
        }
    }
    let elapsed = start.elapsed();

    println!(
        "webhook dispatch logic: 50,000 jobs (5,000 truncations) in {elapsed:?}"
    );
    assert!(
        elapsed < Duration::from_secs(30),
        "webhook dispatch logic stress took {elapsed:?} — collapsed"
    );
}

// ---------------------------------------------------------------------------
// 4. Stress metrics collector — 100 000 data points
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
// 5. Stress pattern rules — 1 000 rules, match against text
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
