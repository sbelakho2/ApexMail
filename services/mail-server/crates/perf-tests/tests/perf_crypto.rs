//! Crypto & core library performance tests.
//!
//! # Hardware baseline (O-30.2)
//! These tests are calibrated for CI runners with at least 2 CPU cores and
//! 4 GB RAM.  Budgets may need adjustment on constrained or shared hosts.
//! Run `lscpu` / `sysctl -n machdep.cpu.brand_string` on macOS to record
//! the baseline before comparing results across environments.
//!
//! # Test naming (O-30.3)
//! All tests carry a `_throughput` suffix to make their performance-test
//! nature explicit.  Some may also use a `perf_` prefix where appropriate.

use std::time::Instant;

use apexmail_lib::crypto::create_hmac_signature;
use apexmail_lib::error_codes::ErrorCode;
use apexmail_lib::id::generate_id;
use apexmail_lib::time::parse_duration;
use apexmail_lib::validation::is_valid_email;
mod budget;

#[test]
fn test_hmac_throughput() {
    let iterations = 10_000;
    let key = b"perf-test-secret-key-1234567890";
    let data = b"benchmark payload for hmac signature creation";

    let start = Instant::now();
    for _ in 0..iterations {
        let _ = create_hmac_signature(key, data);
    }
    let elapsed = start.elapsed();

    println!(
        "HMAC throughput: {} ops in {:?} ({:.0} ops/sec)",
        iterations,
        elapsed,
        iterations as f64 / elapsed.as_secs_f64()
    );
    assert!(
        elapsed < budget::from_secs(1),
        "10,000 HMAC operations took {:?}, expected < 1s",
        elapsed
    );
}

#[test]
fn test_id_generation_throughput() {
    let iterations = 100_000;

    let start = Instant::now();
    for _ in 0..iterations {
        let _ = generate_id("msg", 16);
    }
    let elapsed = start.elapsed();

    println!(
        "ID generation throughput: {} ops in {:?} ({:.0} ops/sec)",
        iterations,
        elapsed,
        iterations as f64 / elapsed.as_secs_f64()
    );
    assert!(
        elapsed < budget::from_secs(5),
        "100,000 ID generations took {:?}, expected < 5s",
        elapsed
    );
}

#[test]
fn test_email_validation_throughput() {
    let iterations = 100_000;
    let emails = [
        "user@example.com",
        "test+tag@sub.domain.co.uk",
        "invalid-no-at",
        "a@b.cc",
        "",
        "spaces in@email.com",
        "valid.person@company.org",
    ];

    let start = Instant::now();
    for i in 0..iterations {
        let email = emails[i % emails.len()];
        let _ = is_valid_email(email);
    }
    let elapsed = start.elapsed();

    println!(
        "Email validation throughput: {} ops in {:?} ({:.0} ops/sec)",
        iterations,
        elapsed,
        iterations as f64 / elapsed.as_secs_f64()
    );
    assert!(
        elapsed < budget::from_secs(1),
        "100,000 email validations took {:?}, expected < 1s",
        elapsed
    );
}

#[test]
fn test_time_parsing_throughput() {
    let iterations = 100_000;
    let durations = ["30s", "5m", "24h", "7d", "120s", "15m", "48h"];

    let start = Instant::now();
    for i in 0..iterations {
        let d = durations[i % durations.len()];
        let _ = parse_duration(d);
    }
    let elapsed = start.elapsed();

    println!(
        "Time parsing throughput: {} ops in {:?} ({:.0} ops/sec)",
        iterations,
        elapsed,
        iterations as f64 / elapsed.as_secs_f64()
    );
    assert!(
        elapsed < budget::from_millis(500),
        "100,000 duration parses took {:?}, expected < 500ms",
        elapsed
    );
}

/// Multi-threaded HMAC throughput (O-30.1).
/// Spawns 4 threads that each compute 10 000 HMACs, verifying that the total
/// wall-clock time stays within a reasonable budget even under parallelism.
#[test]
fn perf_hmac_parallel_throughput() {
    const THREADS: usize = 4;
    const ITERS_PER_THREAD: usize = 10_000;
    let key = b"perf-test-secret-key-1234567890";
    let data = b"benchmark payload for parallel hmac";

    let start = std::time::Instant::now();
    let handles: Vec<_> = (0..THREADS)
        .map(|_| {
            std::thread::spawn(move || {
                for _ in 0..ITERS_PER_THREAD {
                    let _ = create_hmac_signature(key, data);
                }
            })
        })
        .collect();
    for h in handles {
        h.join().expect("perf thread panicked");
    }
    let elapsed = start.elapsed();

    println!(
        "Parallel HMAC throughput: {} threads × {} ops = {} total in {:?} ({:.0} ops/sec)",
        THREADS,
        ITERS_PER_THREAD,
        THREADS * ITERS_PER_THREAD,
        elapsed,
        (THREADS * ITERS_PER_THREAD) as f64 / elapsed.as_secs_f64()
    );
    assert!(
        elapsed < budget::from_secs(5),
        "Parallel HMAC took too long: {:?} > 5s",
        elapsed
    );
}

#[test]
fn test_error_code_mapping_throughput() {
    let iterations = 1_000_000;
    let codes = [
        ErrorCode::Unauthorized,
        ErrorCode::Forbidden,
        ErrorCode::NotFound,
        ErrorCode::RateLimitExceeded,
        ErrorCode::InternalError,
        ErrorCode::ValidationError,
        ErrorCode::PayloadTooLarge,
        ErrorCode::QuotaExceeded,
        ErrorCode::DomainNotVerified,
        ErrorCode::TokenExpired,
    ];

    let start = Instant::now();
    for i in 0..iterations {
        let code = codes[i % codes.len()];
        let _ = code.http_status();
        let _ = code.to_string();
    }
    let elapsed = start.elapsed();

    println!(
        "Error code mapping throughput: {} ops in {:?} ({:.0} ops/sec)",
        iterations,
        elapsed,
        iterations as f64 / elapsed.as_secs_f64()
    );
    assert!(
        elapsed < budget::from_secs(1),
        "1,000,000 error code mappings took {:?}, expected < 1s",
        elapsed
    );
}
