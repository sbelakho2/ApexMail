//! # Stress & Performance Tests for DDoS Protection System
//!
//! Tests throughput, latency, and correctness under load for all new modules.
//! Uses wall-clock timing to measure performance characteristics.

use ddos_protection::{
    adaptive::{AdaptiveConfig, AdaptiveRateLimiter, TrafficObservation},
    bot_detection::SessionBehavior,
    config::ProtectorConfig,
    middleware::{extract_client_ip, RequestContextBuilder},
    reputation::ReputationScore,
    smtp_protection::*,
    DdosProtector,
};
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

fn hash_ep(path: &str) -> u64 {
    let mut h = DefaultHasher::new();
    path.hash(&mut h);
    h.finish()
}

// ═══════════════════════════════════════════════════════════════
// PERF 1:SMTP command parsing throughput
// ═══════════════════════════════════════════════════════════════

#[test]
fn stress_smtp_command_parsing_throughput() {
    let commands = [
        "EHLO mail.example.com",
        "HELO mail.example.com",
        "MAIL FROM:<sender@example.com>",
        "RCPT TO:<recipient@example.com>",
        "DATA",
        "RSET",
        "NOOP",
        "QUIT",
        "HELP",
        "STARTTLS",
        "AUTH PLAIN dGVzdA==",
        "VRFY user@example.com",
    ];

    let iterations = 100_000;
    let start = Instant::now();

    for i in 0..iterations {
        let cmd = commands[i % commands.len()];
        let _ = parse_smtp_command(cmd);
    }

    let elapsed = start.elapsed();
    let ops_per_sec = iterations as f64 / elapsed.as_secs_f64();

    eprintln!(
        "SMTP parsing: {} ops in {:.2?} = {:.0} ops/sec",
        iterations, elapsed, ops_per_sec
    );

    // Should parse at least 100K commands per second
    assert!(
        ops_per_sec > 100_000.0,
        "SMTP parsing too slow: {:.0} ops/sec",
        ops_per_sec
    );
}

// ═══════════════════════════════════════════════════════════════
// PERF 2:SMTP state machine throughput
// ═══════════════════════════════════════════════════════════════

#[test]
fn stress_smtp_state_machine_throughput() {
    let iterations = 10_000;
    let start = Instant::now();

    for _ in 0..iterations {
        let config = SmtpProtectionConfig::default();
        let mut prot = SmtpConnectionProtection::new("192.168.1.1".parse().unwrap(), 50, config);

        // Complete one full SMTP session
        let _ = prot.process_command("EHLO test.com");
        let _ = prot.process_command("MAIL FROM:<a@b.com>");
        let _ = prot.process_command("RCPT TO:<c@d.com>");
        let _ = prot.process_command("RCPT TO:<e@f.com>");
        let _ = prot.process_command("DATA");
        let _ = prot.record_data(1024);
        let _ = prot.process_command("QUIT");
    }

    let elapsed = start.elapsed();
    let sessions_per_sec = iterations as f64 / elapsed.as_secs_f64();

    eprintln!(
        "SMTP sessions: {} in {:.2?} = {:.0} sessions/sec",
        iterations, elapsed, sessions_per_sec
    );

    assert!(
        sessions_per_sec > 10_000.0,
        "SMTP session processing too slow: {:.0}/sec",
        sessions_per_sec
    );
}

// ═══════════════════════════════════════════════════════════════
// PERF 3:Connection tracker concurrent registration throughput
// ═══════════════════════════════════════════════════════════════

#[test]
fn stress_connection_tracker_throughput() {
    let config = SmtpProtectionConfig {
        max_connections_per_ip: 1_000_000,
        conn_rate_per_minute: 1_000_000,
        ..SmtpProtectionConfig::default()
    };
    let tracker = SmtpConnectionTracker::new(config);

    let iterations = 50_000;
    let start = Instant::now();

    for i in 0..iterations {
        let ip = IpAddr::from([
            10,
            ((i >> 16) & 0xFF) as u8,
            ((i >> 8) & 0xFF) as u8,
            (i & 0xFF) as u8,
        ]);
        let _ = tracker.register_connection(ip);
    }

    let elapsed = start.elapsed();
    let ops_per_sec = iterations as f64 / elapsed.as_secs_f64();

    eprintln!(
        "Connection registration: {} ops in {:.2?} = {:.0} ops/sec",
        iterations, elapsed, ops_per_sec
    );

    assert!(
        ops_per_sec > 50_000.0,
        "Connection registration too slow: {:.0}/sec",
        ops_per_sec
    );
}

// ═══════════════════════════════════════════════════════════════
// PERF 4:Adaptive rate limiter update throughput
// ═══════════════════════════════════════════════════════════════

#[test]
fn stress_adaptive_limiter_update_throughput() {
    let config = AdaptiveConfig {
        baseline_window: Duration::from_secs(5), // Short window so old entries get cleaned
        ..AdaptiveConfig::default()
    };
    let limiter = AdaptiveRateLimiter::new(config);

    let iterations = 5_000;
    let start = Instant::now();

    for i in 0..iterations {
        limiter.update(TrafficObservation {
            timestamp: Instant::now(),
            requests_per_second: 100.0 + (i as f64 % 50.0),
            error_rate: 0.01,
            latency_p99_ms: 30.0 + (i as f64 % 20.0),
            cpu_usage: 0.3,
        });
    }

    let elapsed = start.elapsed();
    let ops_per_sec = iterations as f64 / elapsed.as_secs_f64();

    eprintln!(
        "Adaptive update: {} ops in {:.2?} = {:.0} ops/sec",
        iterations, elapsed, ops_per_sec
    );

    // Debug builds are ~10-20x slower than release; 1000 ops/sec is reasonable
    assert!(
        ops_per_sec > 1_000.0,
        "Adaptive update too slow: {:.0}/sec",
        ops_per_sec
    );
}

// ═══════════════════════════════════════════════════════════════
// PERF 5:Bot detection analysis throughput
// ═══════════════════════════════════════════════════════════════

#[test]
fn stress_bot_detection_analysis_throughput() {
    let endpoints: Vec<u64> = (0..20).map(|i| hash_ep(&format!("/api/ep{}", i))).collect();

    let iterations = 10_000;
    let start = Instant::now();

    for i in 0..iterations {
        let mut behavior = SessionBehavior::new(100);

        // Record 50 requests
        for j in 0..50 {
            let ep = endpoints[(i + j) % endpoints.len()];
            behavior.record_request(ep, "GET", j % 10 == 0);
        }

        // Run analysis
        let _assessment = behavior.analyze();
    }

    let elapsed = start.elapsed();
    let ops_per_sec = iterations as f64 / elapsed.as_secs_f64();

    eprintln!(
        "Bot detection (50 req sessions): {} sessions in {:.2?} = {:.0} sessions/sec",
        iterations, elapsed, ops_per_sec
    );

    assert!(
        ops_per_sec > 5_000.0,
        "Bot detection too slow: {:.0}/sec",
        ops_per_sec
    );
}

// ═══════════════════════════════════════════════════════════════
// PERF 6:IP extraction throughput
// ═══════════════════════════════════════════════════════════════

#[test]
fn stress_ip_extraction_throughput() {
    let iterations = 500_000;
    let direct: IpAddr = "127.0.0.1".parse().unwrap();
    let start = Instant::now();

    for i in 0..iterations {
        let xff = format!("10.0.{}.{}, 192.168.1.1", (i >> 8) & 0xFF, i & 0xFF);
        let _ = extract_client_ip(None, Some(&xff), None, direct);
    }

    let elapsed = start.elapsed();
    let ops_per_sec = iterations as f64 / elapsed.as_secs_f64();

    eprintln!(
        "IP extraction: {} ops in {:.2?} = {:.0} ops/sec",
        iterations, elapsed, ops_per_sec
    );

    assert!(
        ops_per_sec > 500_000.0,
        "IP extraction too slow: {:.0}/sec",
        ops_per_sec
    );
}

// ═══════════════════════════════════════════════════════════════
// PERF 7:RequestContextBuilder throughput
// ═══════════════════════════════════════════════════════════════

#[test]
fn stress_request_context_builder_throughput() {
    let iterations = 100_000;
    let start = Instant::now();

    for i in 0..iterations {
        let ip = IpAddr::from([10, 0, ((i >> 8) & 0xFF) as u8, (i & 0xFF) as u8]);
        let _ctx = RequestContextBuilder::new(ip, "/v1/messages/send", "POST")
            .tls_fingerprint("t13d1517h2_8daaf6152771_e5627efa2ab1")
            .h2_fingerprint("settings|frame|prio")
            .user_agent("ApexMail-SDK/1.0")
            .body_size(4096)
            .tenant_id("tenant-xyz")
            .api_key_id("key_live_abc")
            .build();
    }

    let elapsed = start.elapsed();
    let ops_per_sec = iterations as f64 / elapsed.as_secs_f64();

    eprintln!(
        "Context builder: {} ops in {:.2?} = {:.0} ops/sec",
        iterations, elapsed, ops_per_sec
    );

    assert!(
        ops_per_sec > 200_000.0,
        "Context builder too slow: {:.0}/sec",
        ops_per_sec
    );
}

// ═══════════════════════════════════════════════════════════════
// PERF 8:Reputation scoring throughput
// ═══════════════════════════════════════════════════════════════

#[test]
fn stress_reputation_scoring_throughput() {
    let iterations = 500_000;
    let start = Instant::now();

    let mut rep = ReputationScore::default();
    for i in 0..iterations {
        match i % 6 {
            0 => rep.record_request(),
            1 => rep.record_challenge_passed(),
            2 => rep.record_challenge_failed(),
            3 => rep.record_rate_limit(),
            4 => rep.record_blocked(),
            5 => rep.decay_toward_neutral(1),
            _ => unreachable!(),
        }
    }

    let elapsed = start.elapsed();
    let ops_per_sec = iterations as f64 / elapsed.as_secs_f64();

    eprintln!(
        "Reputation scoring: {} ops in {:.2?} = {:.0} ops/sec",
        iterations, elapsed, ops_per_sec
    );

    assert!(
        ops_per_sec > 1_000_000.0,
        "Reputation scoring too slow: {:.0}/sec",
        ops_per_sec
    );
}

// ═══════════════════════════════════════════════════════════════
// PERF 9:Full protector evaluation throughput
// ═══════════════════════════════════════════════════════════════

#[tokio::test]
async fn stress_protector_evaluation_throughput() {
    let config = ProtectorConfig::default();
    let protector = DdosProtector::new(config).await.unwrap();

    let iterations = 10_000;
    let start = Instant::now();

    for i in 0..iterations {
        let ip = IpAddr::from([10, 0, ((i >> 8) & 0xFF) as u8, (i & 0xFF) as u8]);
        let ctx = RequestContextBuilder::new(ip, "/v1/health", "GET")
            .user_agent("TestAgent")
            .build();
        let _decision = protector.evaluate(&ctx).await;
    }

    let elapsed = start.elapsed();
    let ops_per_sec = iterations as f64 / elapsed.as_secs_f64();

    eprintln!(
        "Protector evaluation: {} ops in {:.2?} = {:.0} ops/sec",
        iterations, elapsed, ops_per_sec
    );

    // Absolute floor on an otherwise-idle host; under a full-workspace CI
    // run (every crate's tests in parallel) the CPU is shared, so the gate
    // degrades to a contention-aware floor instead of failing spuriously.
    let load_avg = std::fs::read_to_string("/proc/loadavg")
        .ok()
        .and_then(|load| {
            load.split_whitespace()
                .next()
                .and_then(|one| one.parse::<f64>().ok())
        })
        .unwrap_or(0.0);
    let floor = if load_avg > 2.0 { 2_500.0 } else { 5_000.0 };
    assert!(
        ops_per_sec > floor,
        "Protector evaluation too slow: {:.0}/sec (load avg {load_avg}, floor {floor})",
        ops_per_sec
    );
}

// ═══════════════════════════════════════════════════════════════
// PERF 10:Concurrent connection tracker under contention
// ═══════════════════════════════════════════════════════════════

#[test]
fn stress_connection_tracker_contention() {
    let config = SmtpProtectionConfig {
        max_connections_per_ip: 100_000,
        conn_rate_per_minute: 1_000_000,
        ..SmtpProtectionConfig::default()
    };
    let tracker = Arc::new(SmtpConnectionTracker::new(config));

    let iterations_per_thread = 10_000;
    let num_threads = 4;

    let start = Instant::now();
    let mut handles = Vec::new();

    for thread_id in 0..num_threads {
        let tracker = tracker.clone();
        handles.push(std::thread::spawn(move || {
            for i in 0..iterations_per_thread {
                let ip = IpAddr::from([
                    (thread_id + 1) as u8,
                    0,
                    ((i >> 8) & 0xFF) as u8,
                    (i & 0xFF) as u8,
                ]);

                let _ = tracker.register_connection(ip);
                // Don't unregister — just measure registration throughput
            }
        }));
    }

    for h in handles {
        h.join().unwrap();
    }

    let elapsed = start.elapsed();
    let total_ops = (iterations_per_thread * num_threads) as f64;
    let ops_per_sec = total_ops / elapsed.as_secs_f64();

    eprintln!(
        "Concurrent connection tracker ({} threads): {} ops in {:.2?} = {:.0} ops/sec",
        num_threads, total_ops as u64, elapsed, ops_per_sec
    );

    assert!(
        ops_per_sec > 20_000.0,
        "Concurrent tracker too slow: {:.0}/sec",
        ops_per_sec
    );
}

// ═══════════════════════════════════════════════════════════════
// PERF 11:Adaptive limiter under sustained high-frequency updates
// ═══════════════════════════════════════════════════════════════

#[test]
fn stress_adaptive_limiter_high_frequency() {
    let config = AdaptiveConfig {
        baseline_window: Duration::from_secs(5), // Short window to limit queue size
        ..AdaptiveConfig::default()
    };
    let limiter = Arc::new(AdaptiveRateLimiter::new(config));

    let iterations = 5_000;
    let start = Instant::now();

    // Simulate rapid-fire observations (as if from multiple threads feeding into one limiter)
    for i in 0..iterations {
        let rps = if i % 1000 < 50 {
            5000.0 // Occasional spike
        } else {
            100.0 + (i as f64 % 30.0)
        };

        limiter.update(TrafficObservation {
            timestamp: Instant::now(),
            requests_per_second: rps,
            error_rate: 0.01,
            latency_p99_ms: 30.0,
            cpu_usage: 0.3,
        });
    }

    let elapsed = start.elapsed();
    let ops_per_sec = iterations as f64 / elapsed.as_secs_f64();

    eprintln!(
        "Adaptive high-freq: {} updates in {:.2?} = {:.0} updates/sec",
        iterations, elapsed, ops_per_sec
    );

    // Debug builds are slower; 1000 ops/sec is reasonable
    assert!(
        ops_per_sec > 1_000.0,
        "Adaptive limiter too slow under high frequency: {:.0}/sec",
        ops_per_sec
    );

    // Verify it's still in a consistent state
    let threshold = limiter.current_threshold();
    assert!(threshold > 0, "Threshold should be positive after updates");
}

// ═══════════════════════════════════════════════════════════════
// PERF 12:Bot detection with large session windows
// ═══════════════════════════════════════════════════════════════

#[test]
fn stress_bot_detection_large_windows() {
    let endpoints: Vec<u64> = (0..50).map(|i| hash_ep(&format!("/api/ep{}", i))).collect();

    let iterations = 1_000;
    let window_size = 500;
    let start = Instant::now();

    for i in 0..iterations {
        let mut behavior = SessionBehavior::new(window_size);

        // Fill the window
        for j in 0..window_size {
            let ep = endpoints[(i + j) % endpoints.len()];
            behavior.record_request(ep, "GET", j % 15 == 0);
        }

        let assessment = behavior.analyze();
        assert!(assessment.has_sufficient_data);
    }

    let elapsed = start.elapsed();
    let ops_per_sec = iterations as f64 / elapsed.as_secs_f64();

    eprintln!(
        "Bot detection (window={}): {} sessions in {:.2?} = {:.0} sessions/sec",
        window_size, iterations, elapsed, ops_per_sec
    );

    assert!(
        ops_per_sec > 100.0,
        "Bot detection too slow with large windows: {:.0}/sec",
        ops_per_sec
    );
}

// ═══════════════════════════════════════════════════════════════
// PERF 13:Sequence entropy computation scaling
// ═══════════════════════════════════════════════════════════════

#[test]
fn stress_sequence_entropy_scaling() {
    let sizes = [10, 50, 100, 200, 500];
    let endpoints: Vec<u64> = (0..30).map(|i| hash_ep(&format!("/ep{}", i))).collect();

    for &size in &sizes {
        let iterations = 2000;
        let start = Instant::now();

        for i in 0..iterations {
            let mut behavior = SessionBehavior::new(size);
            for j in 0..size {
                let ep = endpoints[(i + j) % endpoints.len()];
                behavior.record_request(ep, "GET", false);
            }
            let _ = behavior.sequence_entropy();
        }

        let elapsed = start.elapsed();
        let ops_per_sec = iterations as f64 / elapsed.as_secs_f64();

        eprintln!(
            "  Entropy (window={}): {} ops in {:.2?} = {:.0} ops/sec",
            size, iterations, elapsed, ops_per_sec
        );
    }
}
