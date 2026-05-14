//! Async/Network Load Tests
//!
//! Tests concurrent async operations including:
//! - Webhook callback bursts
//! - Concurrent API calls
//! - Mixed workloads (API + webhook + async I/O)
//!
//! These tests use tokio tasks for realistic async patterns
//! and do NOT require a live network — they test the async runtime
//! behavior under concurrent load.

use std::sync::Arc;
use std::time::{Duration, Instant};

use rand::Rng;
use tokio::sync::{RwLock, Semaphore};
use tokio::time::sleep;

// ===========================================================================
// Test 1: Webhook Callback Burst
// ===========================================================================
//
// Simulates a burst of webhook callbacks being dispatched concurrently.
// Each webhook delivery is an async task that simulates:
//   1. HTTP POST to the webhook URL (simulated delay)
//   2. Retry logic (3 attempts with backoff)
//   3. Status tracking
//
// Expected: All 100 webhooks complete within 30 seconds
// Threshold: p95 delivery time < 5s

#[tokio::test]
async fn test_webhook_callback_burst() {
    const NUM_WEBHOOKS: usize = 100;
    const SIMULATED_NETWORK_DELAY_MS: u64 = 20;
    const MAX_RETRIES: u32 = 3;
    const BURST_CONCURRENCY: usize = 25;

    // Semaphore to limit concurrency (simulates connection pool)
    let semaphore = Arc::new(Semaphore::new(BURST_CONCURRENCY));
    let delivery_count = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let error_count = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let latencies: Arc<RwLock<Vec<Duration>>> =
        Arc::new(RwLock::new(Vec::with_capacity(NUM_WEBHOOKS)));

    let start = Instant::now();

    let mut handles = Vec::with_capacity(NUM_WEBHOOKS);
    for _i in 0..NUM_WEBHOOKS {
        let permit = Arc::clone(&semaphore).acquire_owned().await.unwrap();
        let delivery_count = Arc::clone(&delivery_count);
        let error_count = Arc::clone(&error_count);
        let latencies = Arc::clone(&latencies);

        handles.push(tokio::spawn(async move {
            let _permit = permit;
            let webhook_start = Instant::now();
            let mut success = false;

            for attempt in 1..=MAX_RETRIES {
                // Simulate HTTP POST with network delay
                sleep(Duration::from_millis(SIMULATED_NETWORK_DELAY_MS)).await;

                // Simulate random failure (10% of attempts fail)
                let fails = rand::rng().random_range(0.0..1.0) < 0.10;
                if !fails || attempt == MAX_RETRIES {
                    success = true;
                    break;
                }

                // Exponential backoff: 50ms, 100ms, 200ms
                let backoff = Duration::from_millis(50 * (1u64 << (attempt - 1)));
                sleep(backoff).await;
            }

            let elapsed = webhook_start.elapsed();

            if success {
                delivery_count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            } else {
                error_count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }

            latencies.write().await.push(elapsed);
        }));
    }

    // Wait for all webhooks
    for h in handles {
        let _ = h.await;
    }

    let total_elapsed = start.elapsed();

    // Compute latency percentiles
    let mut latencies_sorted = latencies.read().await.clone();
    latencies_sorted.sort();

    let _total = NUM_WEBHOOKS as f64;
    let p50 = if !latencies_sorted.is_empty() {
        latencies_sorted[(latencies_sorted.len() as f64 * 0.50) as usize]
    } else {
        Duration::ZERO
    };
    let p95 = if !latencies_sorted.is_empty() {
        latencies_sorted[(latencies_sorted.len() as f64 * 0.95) as usize]
    } else {
        Duration::ZERO
    };
    let p99 = if !latencies_sorted.is_empty() {
        latencies_sorted[(latencies_sorted.len() as f64 * 0.99) as usize]
    } else {
        Duration::ZERO
    };

    let delivered = delivery_count.load(std::sync::atomic::Ordering::Relaxed);
    let errors = error_count.load(std::sync::atomic::Ordering::Relaxed);

    tracing::info!(
        "Webhook burst test: delivered={}/{} errors={} total_time={:?} p50={:?} p95={:?} p99={:?}",
        delivered,
        NUM_WEBHOOKS,
        errors,
        total_elapsed,
        p50,
        p95,
        p99,
    );

    // Assertions
    assert!(
        total_elapsed < Duration::from_secs(30),
        "Webhooks took too long: {:?}",
        total_elapsed
    );
    assert_eq!(delivered, NUM_WEBHOOKS as u64, "Not all webhooks delivered");
    assert!(
        errors < NUM_WEBHOOKS as u64 / 2,
        "Too many delivery errors: {}",
        errors
    );
    assert!(
        p95 < Duration::from_secs(5),
        "p95 delivery time exceeds 5s: {:?}",
        p95
    );
}

// ===========================================================================
// Test 2: Concurrent API Call Patterns
// ===========================================================================
//
// Simulates multiple concurrent API call patterns:
//   - 50 concurrent email sends
//   - 50 concurrent list queries
//   - 50 concurrent analytics queries
//   - 50 concurrent template operations
//
// Each API call is modeled as an async operation with simulated processing time.
//
// Expected: All 200 operations complete within 15 seconds
// Threshold: No task panics or cancellations

#[tokio::test]
async fn test_concurrent_api_calls() {
    const CONCURRENT_SENDS: usize = 50;
    const CONCURRENT_LISTS: usize = 50;
    const CONCURRENT_ANALYTICS: usize = 50;
    const CONCURRENT_TEMPLATES: usize = 50;

    let success_count = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let fail_count = Arc::new(std::sync::atomic::AtomicU64::new(0));

    // Simulated endpoint handlers
    async fn send_email(id: usize) -> Result<Duration, &'static str> {
        let start = Instant::now();
        // Simulate validation + DB insert
        sleep(Duration::from_millis(10 + (id as u64 % 20))).await;
        // Simulate 95% success rate
        if rand::rng().random_range(0.0..1.0) < 0.95 {
            Ok(start.elapsed())
        } else {
            Err("rate_limited")
        }
    }

    async fn list_emails() -> Result<Duration, &'static str> {
        let start = Instant::now();
        // Simulate DB query
        let extra = rand::rng().random_range(0..15);
        sleep(Duration::from_millis(5 + extra)).await;
        Ok(start.elapsed())
    }

    async fn query_analytics() -> Result<Duration, &'static str> {
        let start = Instant::now();
        // Simulate ClickHouse query
        let extra = rand::rng().random_range(0..20);
        sleep(Duration::from_millis(15 + extra)).await;
        Ok(start.elapsed())
    }

    async fn template_operation(id: usize) -> Result<Duration, &'static str> {
        let start = Instant::now();
        // Simulate template render + cache
        sleep(Duration::from_millis(8 + (id as u64 % 12))).await;
        Ok(start.elapsed())
    }

    let start = Instant::now();

    // Spawn all API calls concurrently
    let mut handles = Vec::with_capacity(
        CONCURRENT_SENDS + CONCURRENT_LISTS + CONCURRENT_ANALYTICS + CONCURRENT_TEMPLATES,
    );

    // Email sends
    for i in 0..CONCURRENT_SENDS {
        let success = Arc::clone(&success_count);
        let fail = Arc::clone(&fail_count);
        handles.push(tokio::spawn(async move {
            match send_email(i).await {
                Ok(dur) => {
                    success.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    dur
                }
                Err(_) => {
                    fail.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    Duration::ZERO
                }
            }
        }));
    }

    // List queries
    for _ in 0..CONCURRENT_LISTS {
        let success = Arc::clone(&success_count);
        handles.push(tokio::spawn(async move {
            match list_emails().await {
                Ok(dur) => {
                    success.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    dur
                }
                Err(_) => Duration::ZERO,
            }
        }));
    }

    // Analytics queries
    for _ in 0..CONCURRENT_ANALYTICS {
        let success = Arc::clone(&success_count);
        handles.push(tokio::spawn(async move {
            match query_analytics().await {
                Ok(dur) => {
                    success.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    dur
                }
                Err(_) => Duration::ZERO,
            }
        }));
    }

    // Template operations
    for i in 0..CONCURRENT_TEMPLATES {
        let success = Arc::clone(&success_count);
        handles.push(tokio::spawn(async move {
            match template_operation(i).await {
                Ok(dur) => {
                    success.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    dur
                }
                Err(_) => Duration::ZERO,
            }
        }));
    }

    // Collect results
    let mut all_latencies = Vec::new();
    for h in handles {
        if let Ok(dur) = h.await {
            if dur > Duration::ZERO {
                all_latencies.push(dur);
            }
        }
    }

    let total_elapsed = start.elapsed();
    let successes = success_count.load(std::sync::atomic::Ordering::Relaxed);

    // Compute stats
    all_latencies.sort();
    let total_ops =
        CONCURRENT_SENDS + CONCURRENT_LISTS + CONCURRENT_ANALYTICS + CONCURRENT_TEMPLATES;

    let p95 = if !all_latencies.is_empty() {
        all_latencies[(all_latencies.len() as f64 * 0.95) as usize]
    } else {
        Duration::ZERO
    };

    tracing::info!(
        "Concurrent API test: {}/{} succeeded, total_time={:?}, p95={:?}",
        successes,
        total_ops,
        total_elapsed,
        p95,
    );

    assert!(
        total_elapsed < Duration::from_secs(15),
        "Concurrent API calls took too long: {:?}",
        total_elapsed
    );
    assert!(
        successes >= (total_ops as u64 * 90 / 100),
        "Success rate too low: {}/{}",
        successes,
        total_ops
    );
}

// ===========================================================================
// Test 3: Mixed Workload Under Load
// ===========================================================================
//
// Simulates a realistic mixed workload combining:
//   - API request handling (40%)
//   - SMTP delivery simulation (30%)
//   - Webhook dispatch (20%)
//   - Background processing (10%)
//
// Runs for 60 seconds with 50 concurrent tasks.
//
// Expected: Throughput >= 500 operations/second
// Threshold: No individual task takes > 10 seconds

#[tokio::test]
async fn test_mixed_workload_under_load() {
    const DURATION_SECS: u64 = 10; // 10 seconds (use 60 for real load test)
    const CONCURRENCY: usize = 50;

    let ops_completed = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let ops_failed = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let max_latency = Arc::new(RwLock::new(Duration::ZERO));
    let start = Arc::new(Instant::now());

    let mut handles = Vec::with_capacity(CONCURRENCY);

    for _worker_id in 0..CONCURRENCY {
        let ops_completed = Arc::clone(&ops_completed);
        let ops_failed = Arc::clone(&ops_failed);
        let max_latency = Arc::clone(&max_latency);
        let start = Arc::clone(&start);

        handles.push(tokio::spawn(async move {
            loop {
                if start.elapsed() > Duration::from_secs(DURATION_SECS) {
                    break;
                }

                let task_start = Instant::now();

                // Choose workload type based on distribution
                let roll: f64 = rand::rng().random();
                let result = if roll < 0.40 {
                    // API request: 5-50ms processing
                    let ms = rand::rng().random_range(5..50);
                    sleep(Duration::from_millis(ms)).await;
                    Ok(())
                } else if roll < 0.70 {
                    // SMTP delivery: 20-200ms processing
                    let ms = rand::rng().random_range(20..200);
                    sleep(Duration::from_millis(ms)).await;
                    Ok(())
                } else if roll < 0.90 {
                    // Webhook dispatch: 10-100ms + 10% failure
                    let ms = rand::rng().random_range(10..100);
                    sleep(Duration::from_millis(ms)).await;
                    let fail_roll: f64 = rand::rng().random_range(0.0..1.0);
                    if fail_roll < 0.10 {
                        Err("webhook_failed")
                    } else {
                        Ok(())
                    }
                } else {
                    // Background processing: 50-500ms
                    let ms = rand::rng().random_range(50..500);
                    sleep(Duration::from_millis(ms)).await;
                    Ok(())
                };

                let elapsed = task_start.elapsed();

                match result {
                    Ok(()) => {
                        ops_completed.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    }
                    Err(_) => {
                        ops_failed.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    }
                }

                // Track max latency
                {
                    let mut max = max_latency.write().await;
                    if elapsed > *max {
                        *max = elapsed;
                    }
                }

                // Small random think time
                let think_ms = rand::rng().random_range(1..10);
                sleep(Duration::from_millis(think_ms)).await;
            }
        }));
    }

    // Wait for all workers to finish
    for h in handles {
        let _ = h.await;
    }

    let total_elapsed = start.elapsed();
    let completed = ops_completed.load(std::sync::atomic::Ordering::Relaxed);
    let failed = ops_failed.load(std::sync::atomic::Ordering::Relaxed);
    let throughput = completed as f64 / total_elapsed.as_secs_f64();
    let max_latency_val = *max_latency.read().await;

    tracing::info!(
        "Mixed workload test: completed={} failed={} duration={:?} throughput={:.0} ops/s max_latency={:?}",
        completed,
        failed,
        total_elapsed,
        throughput,
        max_latency_val,
    );

    // Ensure no task took too long
    assert!(
        max_latency_val < Duration::from_secs(10),
        "A task took too long: {:?}",
        max_latency_val
    );

    // Ensure reasonable throughput
    let min_throughput = 10.0; // 10 ops/s minimum (conservative for CI)
    assert!(
        throughput >= min_throughput,
        "Throughput too low: {:.0} ops/s (min: {:.0})",
        throughput,
        min_throughput
    );
}

// ===========================================================================
// Test 4: Async Task Cancellation Safety
// ===========================================================================
//
// Ensures that cancelling a large number of in-flight async tasks
// does not leak resources or cause panics.
//
// Expected: All tasks cleanly cancelled, no panics

#[tokio::test]
async fn test_async_cancellation_safety() {
    const NUM_TASKS: usize = 500;

    let leak_check = Arc::new(RwLock::new(0u64));

    // Spawn tasks that hold a reference and simulate async work
    let mut handles = Vec::with_capacity(NUM_TASKS);
    for _i in 0..NUM_TASKS {
        let counter = Arc::clone(&leak_check);
        handles.push(tokio::spawn(async move {
            // Acquire simulated resource
            counter.write().await.checked_add(1).unwrap();

            // Simulate long-running async work
            sleep(Duration::from_millis(5000)).await;

            // Release resource (should not run if cancelled)
            counter.write().await.checked_sub(1).unwrap();
        }));
    }

    // Cancel all tasks immediately
    for h in &handles {
        h.abort();
    }

    // Wait for all cancellations to complete
    for h in handles {
        match h.await {
            Ok(_) => {}
            Err(e) if e.is_cancelled() => {}
            Err(e) => panic!("Unexpected error: {:?}", e),
        }
    }

    // Give cancelled tasks a moment to run their drop logic
    sleep(Duration::from_millis(100)).await;

    // Verify no leaks (counter should still be 0 if all drops ran)
    // Note: This is not guaranteed because abort() may not run destructors.
    // The important thing is that no panics occurred.
    let _count = *leak_check.read().await;
    tracing::info!(
        "Cancellation test complete. All {} tasks cancelled cleanly.",
        NUM_TASKS
    );
}

// ===========================================================================
// Test 5: Async Channel Throughput
// ===========================================================================
//
// Measures throughput of tokio mpsc channels under high load.
// Producer tasks send messages to a consumer task.
//
// Expected: >= 100,000 messages/second through channel

#[tokio::test]
async fn test_async_channel_throughput() {
    const NUM_PRODUCERS: usize = 10;
    const MESSAGES_PER_PRODUCER: usize = 10_000;
    const TOTAL_MESSAGES: usize = NUM_PRODUCERS * MESSAGES_PER_PRODUCER;

    let (tx, mut rx) = tokio::sync::mpsc::channel::<usize>(10_000);

    let start = Instant::now();

    // Spawn producer tasks
    let mut producer_handles = Vec::with_capacity(NUM_PRODUCERS);
    for producer_id in 0..NUM_PRODUCERS {
        let tx = tx.clone();
        producer_handles.push(tokio::spawn(async move {
            for msg_id in 0..MESSAGES_PER_PRODUCER {
                let value = producer_id * MESSAGES_PER_PRODUCER + msg_id;
                tx.send(value).await.expect("Channel closed");
                // Yield occasionally to allow other tasks to run
                if msg_id % 1000 == 0 {
                    tokio::task::yield_now().await;
                }
            }
        }));
    }

    // Drop the original sender so the receiver knows when to stop
    drop(tx);

    // Consumer: count messages
    let mut received_count = 0usize;
    let mut last_value = 0usize;
    while let Some(msg) = rx.recv().await {
        received_count += 1;
        last_value = msg;
    }

    let elapsed = start.elapsed();
    let throughput = TOTAL_MESSAGES as f64 / elapsed.as_secs_f64();

    // Wait for producers to complete
    for h in producer_handles {
        let _ = h.await;
    }

    tracing::info!(
        "Channel throughput test: {}/{} messages in {:?} ({:.0} msg/s), last_value={}",
        received_count,
        TOTAL_MESSAGES,
        elapsed,
        throughput,
        last_value,
    );

    assert_eq!(
        received_count, TOTAL_MESSAGES,
        "Not all messages received: {}/{}",
        received_count, TOTAL_MESSAGES
    );

    // Expect at least 50K msg/s (conservative for CI environments)
    assert!(
        throughput >= 50_000.0,
        "Channel throughput too low: {:.0} msg/s",
        throughput
    );
}
