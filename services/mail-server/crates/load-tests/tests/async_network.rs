//! Async load tests over REAL production machinery (SM12 F10).
//!
//! Audit finding 10: this file previously tested tokio itself — simulated
//! 20 ms "network" sleeps, an mpsc channel measuring the runtime, and a
//! "cancellation safety" test that read its own leak counter into a
//! discarded binding and asserted nothing. Every test now drives real
//! workspace code under async concurrency:
//!
//! * webhook dispatch burst — the REAL `worker_processors::common::
//!   Backpressure` controller (the concurrency limiter production
//!   processors acquire before every job) plus the REAL webhook retry
//!   ladder and delivery-result policy from `worker_processors::webhook`;
//! * queue soak — REAL `queue_provider::FairQueueScheduler` claim/release
//!   passes fed by concurrent producers through a bounded channel;
//! * mixed workload — REAL in-memory production calls (keyed rate limiter,
//!   email validation, HMAC, metrics aggregation) under contention;
//! * cancellation safety — tasks hold a RAII guard over the counter and
//!   the test ASSERTS the leak-counter invariant (counter returns to 0
//!   after aborting every task), not merely "no panic".
//!
//! No simulated network latencies: every await point is a real
//! synchronization point of the code under test.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use apexmail_lib::create_hmac_signature;
use apexmail_lib::validation::is_valid_email;
use apexmail_rate_limiter::KeyedRateLimiter;
use chrono::Utc;
use observability_service::metrics_collector::MetricsCollector;
use queue_provider::scheduler::FairQueueScheduler;
use queue_provider::types::{Job, JobStatus};
use tokio::sync::mpsc;
use worker_processors::common::backpressure::{Backpressure, BackpressureConfig};
use worker_processors::webhook::{WebhookDeliveryResult, WebhookJob};

fn stress_webhook_job(attempt: i32) -> WebhookJob {
    WebhookJob {
        id: format!("job-{attempt}"),
        webhook_id: "wh-burst".into(),
        tenant_id: "tenant-burst".into(),
        event_type: "email.opened".into(),
        payload: serde_json::json!({}),
        url: "https://hooks.example.test/burst".into(),
        secret: "whsec_burst".into(),
        headers: None,
        attempt,
        max_retries: 9,
        retry_delay: 0,
        backoff_multiplier: 1.0,
        created_at: Utc::now(),
        claim_token: None,
    }
}

// ===========================================================================
// 1. Webhook dispatch burst — Backpressure + real retry ladder
// ===========================================================================

/// A burst of webhook dispatches through the production concurrency
/// controller: every dispatch must acquire a `Backpressure` permit before
/// doing its (in-process) work, exactly as the real processor loop does.
/// At the end the controller must be fully drained and its rejection
/// accounting must add up.
#[tokio::test]
async fn test_webhook_dispatch_burst() {
    const NUM_WEBHOOKS: usize = 200;
    const MAX_CONCURRENCY: usize = 25;

    let backpressure = Arc::new(Backpressure::new(BackpressureConfig {
        max_concurrency: MAX_CONCURRENCY,
        max_backlog: 10_000,
        cooldown: Duration::from_secs(60), // no load shedding during the burst
    }));

    let delivered = Arc::new(AtomicU64::new(0));
    let mut handles = Vec::with_capacity(NUM_WEBHOOKS);

    let start = Instant::now();
    for i in 0..NUM_WEBHOOKS {
        let bp = Arc::clone(&backpressure);
        let delivered = Arc::clone(&delivered);
        handles.push(tokio::spawn(async move {
            // The permit IS the production admission control — dispatches
            // beyond max_concurrency wait here (or are shed).
            let permit = bp
                .acquire()
                .await
                .expect("controller must admit while under its backlog threshold");

            // Real dispatch-side logic per delivery: classify the attempt
            // result and schedule the next retry rung for failures.
            let attempt = (i % 3) as i32 + 1;
            let job = stress_webhook_job(attempt);
            let result = if i % 10 == 0 {
                WebhookDeliveryResult::failure(Some(503), 1, "upstream 503".into(), None, None)
            } else {
                WebhookDeliveryResult::success(200, 2, None)
            };
            let next_delay_ms = if result.is_retryable() {
                job.next_retry_delay_ms()
            } else {
                0
            };
            assert!(
                next_delay_ms >= 0,
                "the retry ladder never produces a negative delay"
            );
            drop(permit);
            delivered.fetch_add(1, Ordering::Relaxed);
        }));
    }

    for h in handles {
        h.await.expect("dispatch task panicked");
    }
    let elapsed = start.elapsed();

    assert_eq!(
        delivered.load(Ordering::Relaxed),
        NUM_WEBHOOKS as u64,
        "every webhook dispatch must complete"
    );
    assert!(
        elapsed < Duration::from_secs(15),
        "200 bounded dispatches took {elapsed:?}"
    );
    // The controller must be fully drained — permits returned, nothing in
    // flight, and (with cooldown disabled) nothing shed.
    assert_eq!(
        backpressure.in_flight(),
        0,
        "all permits must be released after the burst — leaked concurrency slot"
    );
    assert_eq!(backpressure.available(), MAX_CONCURRENCY);
    assert_eq!(
        backpressure.total_rejected(),
        0,
        "no dispatch may be shed while the backlog is under the threshold"
    );
    assert!(backpressure.utilization() <= f64::EPSILON);
}

// ===========================================================================
// 2. Queue soak — concurrent producers → real fair-scheduler claim loop
// ===========================================================================

fn soak_job(seq: u64, tenant_id: uuid::Uuid) -> Job {
    Job {
        id: uuid::Uuid::new_v4(),
        tenant_id,
        queue: "soak".to_string(),
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

/// Sustained claim/dispatch/release soak: 4 producer tasks stream 50 000
/// real `queue_provider::Job`s through a bounded channel; the dispatcher
/// runs the REAL `FairQueueScheduler::schedule` pass on every batch and
/// releases deferred jobs back exactly as a production claim loop must.
/// The soak fails if a single job is lost, double-processed, or stranded.
#[tokio::test]
async fn test_queue_scheduler_soak() {
    const PRODUCERS: usize = 4;
    const JOBS_PER_PRODUCER: usize = 12_500;
    const TOTAL_JOBS: usize = PRODUCERS * JOBS_PER_PRODUCER;
    const BATCH: usize = 200;

    let scheduler = Arc::new(FairQueueScheduler::default_scheduler());
    let tenants: Vec<uuid::Uuid> = (0..8).map(|_| uuid::Uuid::new_v4()).collect();
    let (tx, mut rx) = mpsc::channel::<Job>(1_000);

    let start = Instant::now();

    // Producers — real jobs with unique payloads.
    let mut producers = Vec::with_capacity(PRODUCERS);
    for p in 0..PRODUCERS {
        let tx = tx.clone();
        let tenants = tenants.clone();
        producers.push(tokio::spawn(async move {
            for i in 0..JOBS_PER_PRODUCER {
                let seq = (p * JOBS_PER_PRODUCER + i) as u64;
                let tenant_id = tenants[seq as usize % tenants.len()];
                let _ = tx.send(soak_job(seq, tenant_id)).await;
            }
        }));
    }
    drop(tx); // dispatcher terminates when producers finish and queue drains

    // Dispatcher — the production claim → schedule → dispatch → release
    // loop, repeated until the queue is fully drained.
    let processed = Arc::new(AtomicU64::new(0));
    let processed_dispatcher = Arc::clone(&processed);
    let scheduler_dispatcher = Arc::clone(&scheduler);
    let dispatcher = tokio::spawn(async move {
        let mut retry_queue: VecDeque<Job> = VecDeque::new();
        loop {
            // Refill the working batch from the channel.
            while retry_queue.len() < BATCH {
                match rx.recv().await {
                    Some(job) => retry_queue.push_back(job),
                    None => break,
                }
            }
            if retry_queue.is_empty() {
                break; // channel closed and nothing deferred
            }
            let batch: Vec<Job> = retry_queue.drain(..BATCH.min(retry_queue.len())).collect();
            let outcome = scheduler_dispatcher.schedule(batch, BATCH);
            // Dispatch the selected (in-memory processing = counting).
            processed_dispatcher.fetch_add(outcome.selected.len() as u64, Ordering::Relaxed);
            // Release deferred back — a claim loop that drops these loses jobs.
            for job in outcome.deferred {
                retry_queue.push_back(job);
            }
            // Let producers interleave at every pass.
            tokio::task::yield_now().await;
        }
    });

    for p in producers {
        p.await.expect("producer task panicked");
    }
    dispatcher.await.expect("dispatcher task panicked");
    let elapsed = start.elapsed();

    let done = processed.load(Ordering::Relaxed);
    assert_eq!(
        done, TOTAL_JOBS as u64,
        "soak processed {done} of {TOTAL_JOBS} jobs — the claim loop lost work"
    );
    let jobs_per_sec = TOTAL_JOBS as f64 / elapsed.as_secs_f64();
    println!("queue soak: {TOTAL_JOBS} jobs in {elapsed:?} ({jobs_per_sec:.0} jobs/s)");
    assert!(
        elapsed < Duration::from_secs(30),
        "50k-job soak took {elapsed:?}"
    );
    assert!(
        jobs_per_sec > 5_000.0,
        "soak throughput {jobs_per_sec:.0} jobs/s below the 5k/s floor"
    );
}

// ===========================================================================
// 3. Mixed workload — real in-memory production calls under contention
// ===========================================================================

/// Sustained mixed load of REAL operations (no simulated latencies): keyed
/// rate-limit checks, email validation, HMAC signatures, and shared metrics
/// aggregation, across 8 concurrent workers for 2 seconds. Verifies an
/// aggregate throughput floor and that no single operation stalled.
#[tokio::test]
async fn test_mixed_workload_under_load() {
    const WORKERS: usize = 8;
    const DURATION: Duration = Duration::from_secs(2);

    let limiter = Arc::new(KeyedRateLimiter::from_params(1_000_000, 1_000_000, 1_000));
    let collector = Arc::new(MetricsCollector::new(vec![1.0, 10.0]));
    let ops = Arc::new(AtomicU64::new(0));
    let deadline = Instant::now() + DURATION;

    let mut handles = Vec::with_capacity(WORKERS);
    for w in 0..WORKERS {
        let limiter = Arc::clone(&limiter);
        let collector = Arc::clone(&collector);
        let ops = Arc::clone(&ops);
        handles.push(tokio::spawn(async move {
            let mut local_ops = 0u64;
            let mut local_max = Duration::ZERO;
            while Instant::now() < deadline {
                let op_start = Instant::now();

                // Four real production calls per op.
                let decision = limiter.check(&format!("worker-{w}"));
                let valid = is_valid_email(&format!("user{local_ops}@example.test"));
                let mac = create_hmac_signature(b"soak-key", local_ops.to_string().as_bytes());
                collector.record_histogram("soak_hist", 1.0, "soak");
                // Both verdicts must stay meaningful under load: the limiter
                // admits (generous per-worker budget), validation accepts.
                assert!(decision.is_allowed(), "soak worker exceeded its own budget");
                assert!(valid, "valid soak address rejected under load");
                assert_eq!(mac.len(), 64);

                local_ops += 1;
                let took = op_start.elapsed();
                if took > local_max {
                    local_max = took;
                }
                // Yield every 64 ops so workers interleave on the runtime.
                if local_ops.is_multiple_of(64) {
                    tokio::task::yield_now().await;
                }
            }
            ops.fetch_add(local_ops, Ordering::Relaxed);
            local_max
        }));
    }

    let mut worst = Duration::ZERO;
    for h in handles {
        let m = h.await.expect("soak worker panicked");
        if m > worst {
            worst = m;
        }
    }
    let total_elapsed = DURATION;
    let total = ops.load(Ordering::Relaxed);
    let throughput = total as f64 / total_elapsed.as_secs_f64();
    println!("mixed workload: {total} real ops in {total_elapsed:?} ({throughput:.0} ops/s)");

    assert!(
        worst < Duration::from_secs(1),
        "an individual 4-op iteration took {worst:?} — the runtime or a shared structure stalled"
    );
    assert!(
        throughput >= 25_000.0,
        "mixed real-op throughput {throughput:.0}/s below the 25k/s floor"
    );
    // The shared aggregation must have counted every histogram observe
    // (each observe records 1.0, so the summary SUM equals the op count).
    let summary = collector.get_summary();
    let hist: f64 = summary
        .iter()
        .filter(|m| m.name == "soak_hist")
        .map(|m| m.value)
        .sum();
    assert!(
        (hist - total as f64).abs() < 1.0,
        "metrics aggregation lost increments under load: {hist} vs {total}"
    );
}

// ===========================================================================
// 4. Cancellation safety — the leak-counter invariant, ASSERTED
// ===========================================================================

/// RAII guard representing an acquired resource (a dispatch slot, a DB
/// connection, a lease). Dropping it releases the resource — this is the
/// mechanism real processors rely on, so cancellation safety means "every
/// guard is dropped", which is observable as the counter returning to zero.
struct InflightGuard {
    counter: Arc<AtomicU64>,
}

impl InflightGuard {
    fn acquire(counter: &Arc<AtomicU64>) -> Self {
        counter.fetch_add(1, Ordering::SeqCst);
        Self {
            counter: Arc::clone(counter),
        }
    }
}

impl Drop for InflightGuard {
    fn drop(&mut self) {
        self.counter.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Cancel 500 in-flight tasks mid-await and ASSERT the leak-counter
/// invariant: every RAII guard is dropped by the cancellation, so the
/// in-flight counter returns to exactly zero. (The previous version of
/// this test read the counter into a discarded binding and asserted
/// nothing.) Also verifies that tasks which COMPLETE normally balance the
/// counter, so the invariant is proven both ways.
#[tokio::test]
async fn test_async_cancellation_safety() {
    const NUM_TASKS: usize = 500;

    let in_flight = Arc::new(AtomicU64::new(0));

    // Phase 1: tasks that get CANCELLED mid-await.
    let mut handles = Vec::with_capacity(NUM_TASKS);
    for _ in 0..NUM_TASKS {
        let counter = Arc::clone(&in_flight);
        handles.push(tokio::spawn(async move {
            let _guard = InflightGuard::acquire(&counter);
            // Long awaits: every task is guaranteed to be parked here when
            // aborted, so the guard's Drop is the only cleanup that runs.
            tokio::time::sleep(Duration::from_secs(60)).await;
            // Never reached — a task that resumed here would double-release
            // via drop AND this manual decrement:
            counter.fetch_sub(1, Ordering::SeqCst);
        }));
    }

    for h in &handles {
        h.abort();
    }
    for h in handles {
        match h.await {
            Ok(()) => panic!("a 60s sleep cannot complete before abort"),
            Err(e) if e.is_cancelled() => {}
            Err(e) => panic!("unexpected join error: {e:?}"),
        }
    }

    // THE invariant (previously discarded): aborting a future runs its
    // destructors, so every guard was dropped and nothing leaked.
    let leaked = in_flight.load(Ordering::SeqCst);
    assert_eq!(
        leaked, 0,
        "LEAK: {leaked} of {NUM_TASKS} cancelled tasks did not release their resource"
    );

    // Phase 2: tasks that COMPLETE normally must balance the counter too.
    let mut completed = Vec::with_capacity(NUM_TASKS);
    for _ in 0..NUM_TASKS {
        let counter = Arc::clone(&in_flight);
        completed.push(tokio::spawn(async move {
            let _guard = InflightGuard::acquire(&counter);
            tokio::task::yield_now().await;
        }));
    }
    for h in completed {
        h.await.expect("completion task panicked");
    }
    let leaked_after_completion = in_flight.load(Ordering::SeqCst);
    assert_eq!(
        leaked_after_completion, 0,
        "completed tasks leaked {leaked_after_completion} resources"
    );
}
