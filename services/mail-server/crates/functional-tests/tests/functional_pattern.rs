//! Functional tests for pattern-matcher: PatternMatcher and RuleSet.

use pattern_matcher::matcher::build_matcher;
use pattern_matcher::rules::{Rule, RuleCategory, RuleSet, Severity};

fn spam_rules() -> Vec<Rule> {
    vec![
        Rule {
            id: "SPAM-001".into(),
            pattern: "buy now".into(),
            category: RuleCategory::Spam,
            severity: Severity::Medium,
            score: 3.0,
            description: "Spam: buy now".into(),
        },
        Rule {
            id: "SPAM-002".into(),
            pattern: "free money".into(),
            category: RuleCategory::Spam,
            severity: Severity::High,
            score: 5.0,
            description: "Spam: free money".into(),
        },
        Rule {
            id: "PHISH-001".into(),
            pattern: "verify your account".into(),
            category: RuleCategory::Phishing,
            severity: Severity::Critical,
            score: 10.0,
            description: "Phishing: account verification".into(),
        },
    ]
}

// ── Exact match ────────────────────────────────────────────────

#[test]
fn exact_match_single_pattern() {
    let matcher = build_matcher(vec![("googlebot", "bot:google")]);
    let results = matcher.find_all("Mozilla/5.0 (compatible; Googlebot/2.1)");
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].label, "bot:google");
}

// ── Case-insensitive matching ──────────────────────────────────

#[test]
fn case_insensitive_matching() {
    let matcher = build_matcher(vec![("hello world", "greeting")]);
    assert!(matcher.is_match("HELLO WORLD"));
    assert!(matcher.is_match("Hello World"));
    assert!(matcher.is_match("hello world"));
}

// ── Severity scoring via RuleSet ───────────────────────────────

#[test]
fn ruleset_total_score() {
    let rs = RuleSet::new(spam_rules());
    // "buy now and free money" should match SPAM-001 (3) + SPAM-002 (5) = 8
    let score = rs.total_score("Buy now and get free money!");
    assert!((score - 8.0).abs() < f64::EPSILON, "expected 8.0, got {}", score);
}

// ── Multiple rules on same input ───────────────────────────────

#[test]
fn multiple_rules_applied_to_same_input() {
    let rs = RuleSet::new(spam_rules());
    let matches = rs.evaluate("Buy now and get free money!");
    assert_eq!(matches.len(), 2);
    let ids: Vec<&str> = matches.iter().map(|m| m.rule_id.as_str()).collect();
    assert!(ids.contains(&"SPAM-001"));
    assert!(ids.contains(&"SPAM-002"));
}

// ── No match returns empty ─────────────────────────────────────

#[test]
fn no_match_returns_empty() {
    let rs = RuleSet::new(spam_rules());
    let matches = rs.evaluate("This is a perfectly normal message.");
    assert!(matches.is_empty());
}

// ── Has critical ───────────────────────────────────────────────

#[test]
fn has_critical_detects_phishing() {
    let rs = RuleSet::new(spam_rules());
    assert!(rs.has_critical("Please verify your account"));
    assert!(!rs.has_critical("Buy now!"));
}
