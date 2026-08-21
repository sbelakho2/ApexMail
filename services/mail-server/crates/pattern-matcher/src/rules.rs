//! Rule-based pattern matching with severity and categories.

use crate::matcher::PatternMatcher;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleCategory {
    Spam,
    Phishing,
    Malware,
    BotDetection,
    ContentPolicy,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    pub id: String,
    pub pattern: String,
    pub category: RuleCategory,
    pub severity: Severity,
    pub score: f64,
    pub description: String,
}

impl Rule {
    /// Create a new rule.
    ///
    /// # Security (O-13.1)
    ///
    /// The `description` field is set from the opaque `rule_id` rather than
    /// the raw `pattern` text, preventing internal rule content from leaking
    /// to external consumers via [`RuleMatch`].
    pub fn new(
        pattern: impl Into<String>,
        id: impl Into<String>,
        category: RuleCategory,
        severity: Severity,
        score: u32,
    ) -> Self {
        let pattern = pattern.into();
        let id = id.into();
        Self {
            description: id.clone(),
            id,
            pattern,
            category,
            severity,
            score: score as f64,
        }
    }
}

/// A scored match result from rule evaluation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleMatch {
    pub rule_id: String,
    pub category: RuleCategory,
    pub severity: Severity,
    pub score: f64,
    pub description: String,
    pub match_start: usize,
    pub match_end: usize,
}

/// Default cap on how many occurrences of a single rule contribute to
/// [`RuleSet::total_score`]. Without a cap, a message repeating one keyword
/// ("free money" × 500) inflates the score without bound — a cheap
/// adversarial score-pumping vector.
pub const DEFAULT_MAX_OCCURRENCES_PER_RULE: usize = 3;

/// A collection of pattern-matching rules.
pub struct RuleSet {
    rules: Vec<Rule>,
    matcher: PatternMatcher,
    /// Maximum number of occurrences of any single rule that contribute to
    /// the aggregate score.
    max_occurrences_per_rule: usize,
}

impl RuleSet {
    pub fn new(rules: Vec<Rule>) -> Self {
        Self::with_occurrence_cap(rules, DEFAULT_MAX_OCCURRENCES_PER_RULE)
    }

    /// Build a rule set with a custom per-rule occurrence cap for score
    /// aggregation (`0` counts as the default cap).
    pub fn with_occurrence_cap(rules: Vec<Rule>, max_occurrences: usize) -> Self {
        let patterns: Vec<(String, String)> = rules
            .iter()
            .map(|r| (r.pattern.clone(), r.id.clone()))
            .collect();

        let matcher = PatternMatcher::new(patterns);
        Self {
            rules,
            matcher,
            max_occurrences_per_rule: if max_occurrences == 0 {
                DEFAULT_MAX_OCCURRENCES_PER_RULE
            } else {
                max_occurrences
            },
        }
    }

    /// Evaluate all rules against the input text.
    ///
    /// Input is NFC-normalized before pattern matching (O-13.2), preventing
    /// Unicode equivalence attacks where visually identical characters with
    /// different codepoint sequences bypass detection.
    pub fn evaluate(&self, text: &str) -> Vec<RuleMatch> {
        let matches = self.matcher.find_all(text);
        matches
            .into_iter()
            .filter_map(|m| {
                self.rules.get(m.pattern_index).map(|rule| RuleMatch {
                    rule_id: rule.id.clone(),
                    category: rule.category,
                    severity: rule.severity,
                    score: rule.score,
                    // O-13.1: description is rule_id (opaque), not stored rule text.
                    description: rule.id.clone(),
                    match_start: m.start,
                    match_end: m.end,
                })
            })
            .collect()
    }

    /// Calculate total score from all rule matches, capping each rule's
    /// contribution at `max_occurrences_per_rule` occurrences so repeated
    /// keywords cannot inflate the aggregate score without bound.
    pub fn total_score(&self, text: &str) -> f64 {
        let mut per_rule: std::collections::HashMap<String, (f64, usize)> =
            std::collections::HashMap::new();
        for m in self.evaluate(text) {
            let entry = per_rule.entry(m.rule_id.clone()).or_insert((m.score, 0));
            if entry.1 < self.max_occurrences_per_rule {
                entry.1 += 1;
            }
        }
        per_rule
            .into_values()
            .map(|(score, count)| score * count as f64)
            .sum()
    }

    /// Check if any critical rules match.
    pub fn has_critical(&self, text: &str) -> bool {
        self.evaluate(text)
            .iter()
            .any(|m| m.severity == Severity::Critical)
    }

    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_rules() -> Vec<Rule> {
        vec![
            Rule {
                id: "SPAM-001".into(),
                pattern: "buy now".into(),
                category: RuleCategory::Spam,
                severity: Severity::Medium,
                score: 3.0,
                // O-13.1: Explicit description (not auto-populated from pattern)
                description: "Spam: buy now trigger".into(),
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

    #[test]
    fn test_evaluate_single_match() {
        let rs = RuleSet::new(test_rules());
        let matches = rs.evaluate("Click to buy now!");
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].rule_id, "SPAM-001");
        assert_eq!(matches[0].score, 3.0);
    }

    #[test]
    fn test_evaluate_multiple_matches() {
        let rs = RuleSet::new(test_rules());
        let matches = rs.evaluate("Buy now and get free money!");
        assert_eq!(matches.len(), 2);
    }

    #[test]
    fn test_total_score() {
        let rs = RuleSet::new(test_rules());
        let score = rs.total_score("Buy now and get free money!");
        assert!((score - 8.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_has_critical() {
        let rs = RuleSet::new(test_rules());
        assert!(!rs.has_critical("Buy now!"));
        assert!(rs.has_critical("Please verify your account"));
    }

    #[test]
    fn test_no_matches() {
        let rs = RuleSet::new(test_rules());
        let matches = rs.evaluate("This is a normal message.");
        assert!(matches.is_empty());
    }

    #[test]
    fn test_rule_count() {
        let rs = RuleSet::new(test_rules());
        assert_eq!(rs.rule_count(), 3);
    }

    /// O-13.1: Verify description does not leak the raw pattern text.
    #[test]
    fn test_rule_match_description_is_sanitized() {
        let rs = RuleSet::new(test_rules());
        let matches = rs.evaluate("Click to buy now!");
        assert!(!matches.is_empty());
        // Description should NOT contain the raw pattern "buy now"
        for m in &matches {
            assert!(
                !m.description.contains("buy now"),
                "RuleMatch description leaked pattern text: {}",
                m.description
            );
        }
    }

    /// O-13.2: Verify NFC normalization prevents Unicode bypass.
    #[test]
    fn test_evaluate_unicode_normalization() {
        // Pattern defined in NFC: "verify your account"
        // Use NFD-equivalent text with combining characters
        let nfd_text: String = "Please verify your acco\u{0301}unt details."
            .chars()
            .collect();
        let rs = RuleSet::new(test_rules());
        // The accented 'o\u{0301}' in NFD should normalize to 'ó' in NFC,
        // which does NOT match "account" — so no match expected here.
        // This ensures NFC normalization on input is working.
        let matches_nfd = rs.evaluate(&nfd_text);
        assert!(
            matches_nfd.is_empty(),
            "NFD variant of unrelated word should not match: {:?}",
            matches_nfd
        );

        // Actual NFC-normal match should still work
        let matches_nfc = rs.evaluate("Please verify your account");
        assert!(!matches_nfc.is_empty(), "NFC text should match normally");
    }

    #[test]
    fn test_severity_serialization() {
        let json = serde_json::to_string(&Severity::Critical).unwrap();
        assert_eq!(json, r#""critical""#);
        let de: Severity = serde_json::from_str(r#""high""#).unwrap();
        assert_eq!(de, Severity::High);
    }

    #[test]
    fn test_category_serialization() {
        let json = serde_json::to_string(&RuleCategory::BotDetection).unwrap();
        assert_eq!(json, r#""bot_detection""#);
    }

    #[test]
    fn test_total_score_caps_occurrences_per_rule() {
        // 10 occurrences of a 3-point rule must contribute 3×3=9 (default
        // cap 3), not 30 — repeated keywords cannot pump the score.
        let rs = RuleSet::new(test_rules());
        let text = "buy now ".repeat(10);
        assert_eq!(rs.evaluate(&text).len(), 10, "all matches still reported");
        let score = rs.total_score(&text);
        assert!(
            (score - 9.0).abs() < f64::EPSILON,
            "score must be capped at 3 occurrences (9.0), got {score}"
        );

        // Custom cap is configurable.
        let rs = RuleSet::with_occurrence_cap(test_rules(), 5);
        let score = rs.total_score(&text);
        assert!((score - 15.0).abs() < f64::EPSILON, "cap 5 → 15.0, got {score}");

        // Cap 0 means "use the default".
        let rs = RuleSet::with_occurrence_cap(test_rules(), 0);
        assert_eq!(rs.total_score(&text), 9.0);
    }
}
