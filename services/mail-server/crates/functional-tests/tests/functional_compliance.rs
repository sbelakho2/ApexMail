//! Functional tests for compliance types — risk scoring business logic.
//! The full RiskScoringEngine requires a PgPool, so we test the pure
//! functions and types that don't need a database.

use compliance::types::*;

// ── RiskLevel from score ───────────────────────────────────────

#[test]
fn risk_level_from_score_thresholds() {
    assert_eq!(RiskLevel::from_score(0.0), RiskLevel::Low);
    assert_eq!(RiskLevel::from_score(24.9), RiskLevel::Low);
    assert_eq!(RiskLevel::from_score(25.0), RiskLevel::Medium);
    assert_eq!(RiskLevel::from_score(49.9), RiskLevel::Medium);
    assert_eq!(RiskLevel::from_score(50.0), RiskLevel::High);
    assert_eq!(RiskLevel::from_score(74.9), RiskLevel::High);
    assert_eq!(RiskLevel::from_score(75.0), RiskLevel::Critical);
    assert_eq!(RiskLevel::from_score(100.0), RiskLevel::Critical);
}

#[test]
fn risk_level_limit_multiplier() {
    assert!((RiskLevel::Low.limit_multiplier() - 1.0).abs() < f64::EPSILON);
    assert!((RiskLevel::Medium.limit_multiplier() - 0.75).abs() < f64::EPSILON);
    assert!((RiskLevel::High.limit_multiplier() - 0.5).abs() < f64::EPSILON);
    assert!((RiskLevel::Critical.limit_multiplier() - 0.1).abs() < f64::EPSILON);
}

#[test]
fn risk_level_reassessment_cadence() {
    assert_eq!(RiskLevel::Low.reassessment_secs(), 86_400); // 24h
    assert_eq!(RiskLevel::Medium.reassessment_secs(), 21_600); // 6h
    assert_eq!(RiskLevel::High.reassessment_secs(), 3_600); // 1h
    assert_eq!(RiskLevel::Critical.reassessment_secs(), 900); // 15m
}

#[test]
fn risk_level_display() {
    assert_eq!(RiskLevel::Low.to_string(), "low");
    assert_eq!(RiskLevel::Medium.to_string(), "medium");
    assert_eq!(RiskLevel::High.to_string(), "high");
    assert_eq!(RiskLevel::Critical.to_string(), "critical");
}

#[test]
fn scan_verdict_display() {
    assert_eq!(ScanVerdict::Clean.to_string(), "clean");
    assert_eq!(ScanVerdict::Suspicious.to_string(), "suspicious");
    assert_eq!(ScanVerdict::Blocked.to_string(), "blocked");
}
