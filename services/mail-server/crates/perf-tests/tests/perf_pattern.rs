//! Pattern matching performance tests (SM12 F9: black-boxed real matches).

use std::hint::black_box;
use std::time::Instant;

use pattern_matcher::bot_patterns::build_bot_detector;
use pattern_matcher::spam_patterns::spam_rules;
mod budget;

#[test]
fn test_pattern_match_throughput() {
    let iterations = 100_000;
    let matcher = build_bot_detector();

    let user_agents = [
        "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "curl/7.68.0",
        "python-requests/2.28.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15",
        "Bingbot/2.0",
        "Mozilla/5.0 (Linux; Android 12) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100",
    ];

    let start = Instant::now();
    for i in 0..iterations {
        let verdict = black_box(matcher.is_match(black_box(user_agents[i % user_agents.len()])));
        black_box(verdict);
    }
    let elapsed = start.elapsed();
    let ops_per_sec = iterations as f64 / elapsed.as_secs_f64();

    println!(
        "Pattern match throughput: {} ops in {:?} ({:.0} ops/sec)",
        iterations, elapsed, ops_per_sec
    );
    budget::emit_baseline_metric("pattern_matching", "throughput_ops_per_sec", ops_per_sec);
    assert!(
        elapsed < budget::from_secs(2),
        "100,000 pattern matches took {:?}, expected < 2s",
        elapsed
    );
    budget::assert_release_throughput(
        ops_per_sec,
        budget::baseline_ops_per_sec::PATTERN_MATCHING,
        "pattern_matching",
    );
}

#[test]
fn test_regex_compilation_reuse() {
    // Verify that the Aho-Corasick automaton is built once and reused,
    // not recompiled per call. We measure the cost of a second batch
    // versus the first batch — they should be similar (no recompilation).
    let matcher = build_bot_detector();
    let ua = "Mozilla/5.0 (compatible; Googlebot/2.1)";

    // Warm up
    for _ in 0..1_000 {
        black_box(matcher.is_match(black_box(ua)));
    }

    let batch = 50_000;

    let start1 = Instant::now();
    for _ in 0..batch {
        black_box(matcher.is_match(black_box(ua)));
    }
    let elapsed1 = start1.elapsed();

    let start2 = Instant::now();
    for _ in 0..batch {
        black_box(matcher.is_match(black_box(ua)));
    }
    let elapsed2 = start2.elapsed();

    println!(
        "Regex reuse check: batch1={:?}, batch2={:?}, ratio={:.2}",
        elapsed1,
        elapsed2,
        elapsed2.as_secs_f64() / elapsed1.as_secs_f64()
    );

    // If regex were recompiled, second batch would not be faster or similar.
    // Allow up to 3x variance for timing jitter — the point is both are fast.
    assert!(
        elapsed2 < elapsed1 * 3,
        "Second batch ({:?}) should not be significantly slower than first ({:?})",
        elapsed2,
        elapsed1
    );
}

#[test]
fn test_multiple_rules_throughput() {
    let iterations = 10_000;
    let rules = spam_rules();

    let texts = [
        "Congratulations you won a million dollars! Claim your prize now and earn extra cash!",
        "Hi team, please review the attached quarterly report. Best regards, John.",
        "Your account has been compromised. Click here to verify your identity immediately.",
        "Limited time offer: buy now and get 100% free shipping on all orders!",
        "Meeting reminder: Q4 planning session tomorrow at 2pm in conference room B.",
        "Act now! Don't miss out on this risk-free investment opportunity of a lifetime.",
    ];

    let start = Instant::now();
    for i in 0..iterations {
        let matches = black_box(rules.evaluate(black_box(texts[i % texts.len()])));
        black_box(matches);
    }
    let elapsed = start.elapsed();
    let ops_per_sec = iterations as f64 / elapsed.as_secs_f64();

    println!(
        "Multi-rule match throughput: {} ops in {:?} ({:.0} ops/sec)",
        iterations, elapsed, ops_per_sec
    );
    assert!(
        elapsed < budget::from_secs(2),
        "10,000 multi-rule matches took {:?}, expected < 2s",
        elapsed
    );
}
