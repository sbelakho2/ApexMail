//! Crypto & core library performance tests.

use std::time::{Duration, Instant};

use apexmail_lib::crypto::create_hmac_signature;
use apexmail_lib::error_codes::ErrorCode;
use apexmail_lib::id::generate_id;
use apexmail_lib::time::parse_duration;
use apexmail_lib::validation::is_valid_email;

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
        elapsed < Duration::from_secs(1),
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
        elapsed < Duration::from_secs(5),
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
        elapsed < Duration::from_secs(1),
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
        elapsed < Duration::from_millis(500),
        "100,000 duration parses took {:?}, expected < 500ms",
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
        elapsed < Duration::from_secs(1),
        "1,000,000 error code mappings took {:?}, expected < 1s",
        elapsed
    );
}
