//! Fuzz tests for the pattern-matcher crate.

use fuzz_tests::*;
use pattern_matcher::matcher::{build_matcher, PatternMatcher};
use pattern_matcher::rules::{Rule, RuleCategory, RuleSet, Severity};
use rand::Rng;

#[test]
fn fuzz_pattern_match_no_panic() {
// Random patterns and random texts must never crash the Aho-Corasick matcher.
    let mut rng = rand::thread_rng();

// Build a matcher with random patterns
    let num_patterns = rng.gen_range(1..50);
    let patterns: Vec<(String, String)> = (0..num_patterns)
        .map(|i| {
            let pat_len = rng.gen_range(1..20);
            (random_ascii(pat_len), format!("label_{i}"))
        })
        .collect();
    let matcher = PatternMatcher::new(patterns);

// Run against random texts
    for _ in 0..5_000 {
        let text_len = rng.gen_range(0..500);
        let text = random_ascii(text_len);
        let _ = matcher.find_all(&text);
        let _ = matcher.is_match(&text);
        let _ = matcher.count_matches(&text);
        let _ = matcher.find_first(&text);
    }

// Unicode texts
    for _ in 0..1_000 {
        let text = random_unicode(rng.gen_range(0..300));
        let _ = matcher.find_all(&text);
        let _ = matcher.is_match(&text);
    }

// Empty text
    let _ = matcher.find_all("");
    let _ = matcher.is_match("");
}

#[test]
fn fuzz_severity_always_valid() {
// Build a RuleSet with all severity levels and verify matched severity is valid.
    let rules = vec![
        Rule::new("spam", "r1", RuleCategory::Spam, Severity::Low, 10),
        Rule::new("phishing", "r2", RuleCategory::Phishing, Severity::High, 50),
        Rule::new("malware", "r3", RuleCategory::Malware, Severity::Critical, 90),
        Rule::new("bot", "r4", RuleCategory::BotDetection, Severity::Medium, 30),
    ];
    let ruleset = RuleSet::new(rules);
    let valid_severities = [Severity::Low, Severity::Medium, Severity::High, Severity::Critical];

    let mut rng = rand::thread_rng();
    for _ in 0..5_000 {
        let text = random_ascii(rng.gen_range(0..200));
        let matches = ruleset.evaluate(&text);
        for m in &matches {
            assert!(
                valid_severities.contains(&m.severity),
                "Invalid severity: {:?}",
                m.severity
            );
            assert!(m.score >= 0.0, "Score should be non-negative");
        }
    }
}

#[test]
fn fuzz_empty_rules_returns_empty() {
// Matching with zero rules must always return an empty result.
    let ruleset = RuleSet::new(vec![]);
    let mut rng = rand::thread_rng();
    for _ in 0..1_000 {
        let text = random_ascii(rng.gen_range(0..500));
        let matches = ruleset.evaluate(&text);
        assert!(
            matches.is_empty(),
            "Empty ruleset should produce no matches, got {}",
            matches.len()
        );
    }
// Also with a matcher
    let matcher = build_matcher(vec![]);
    for _ in 0..1_000 {
        let text = random_ascii(rng.gen_range(0..500));
        assert!(!matcher.is_match(&text));
        assert_eq!(matcher.find_all(&text).len(), 0);
    }
}
