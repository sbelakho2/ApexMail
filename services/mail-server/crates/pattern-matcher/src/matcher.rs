//! Core pattern matcher using Aho-Corasick automaton.

use aho_corasick::{AhoCorasick, AhoCorasickBuilder, MatchKind};
use serde::{Deserialize, Serialize};

/// Result of a pattern match.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatchResult {
    pub pattern_index: usize,
    pub pattern: String,
    pub start: usize,
    pub end: usize,
    pub label: String,
}

/// High-performance multi-pattern matcher.
///
/// Uses Aho-Corasick automaton for O(n) matching over any number of patterns.
/// Immune to ReDoS by construction (no backtracking).
pub struct PatternMatcher {
    automaton: Option<AhoCorasick>,
    patterns: Vec<PatternEntry>,
}

#[derive(Debug, Clone)]
struct PatternEntry {
    pattern: String,
    label: String,
}

impl PatternMatcher {
    /// Build a matcher from labeled pattern strings.
    /// Returns `None` if the patterns are invalid (e.g., too many or conflicting).
    pub fn new(patterns: Vec<(String, String)>) -> Self {
        let entries: Vec<PatternEntry> = patterns
            .iter()
            .map(|(p, l)| PatternEntry {
                pattern: p.clone(),
                label: l.clone(),
            })
            .collect();

        let automaton = match AhoCorasickBuilder::new()
            .ascii_case_insensitive(true)
            .match_kind(MatchKind::LeftmostLongest)
            .build(patterns.iter().map(|(p, _)| p.as_str()))
        {
            Ok(automaton) => Some(automaton),
            Err(e) => {
                tracing::error!(
                    error = %e,
                    "Failed to build Aho-Corasick automaton from config patterns; using empty matcher"
                );
                None
            }
        };

        Self {
            automaton,
            patterns: entries,
        }
    }

    /// Find all matches in the input text.
    pub fn find_all(&self, text: &str) -> Vec<MatchResult> {
        let Some(automaton) = self.automaton.as_ref() else {
            return Vec::new();
        };

        automaton
            .find_iter(text)
            .map(|m| {
                let entry = &self.patterns[m.pattern().as_usize()];
                MatchResult {
                    pattern_index: m.pattern().as_usize(),
                    pattern: entry.pattern.clone(),
                    start: m.start(),
                    end: m.end(),
                    label: entry.label.clone(),
                }
            })
            .collect()
    }

    /// Check if any pattern matches.
    pub fn is_match(&self, text: &str) -> bool {
        self.automaton
            .as_ref()
            .map(|a| a.is_match(text))
            .unwrap_or(false)
    }

    /// Count total matches.
    pub fn count_matches(&self, text: &str) -> usize {
        self.automaton
            .as_ref()
            .map(|a| a.find_iter(text).count())
            .unwrap_or(0)
    }

    /// Find first match only.
    pub fn find_first(&self, text: &str) -> Option<MatchResult> {
        self.automaton.as_ref()?.find(text).map(|m| {
            let entry = &self.patterns[m.pattern().as_usize()];
            MatchResult {
                pattern_index: m.pattern().as_usize(),
                pattern: entry.pattern.clone(),
                start: m.start(),
                end: m.end(),
                label: entry.label.clone(),
            }
        })
    }

    /// Number of patterns in the automaton.
    pub fn pattern_count(&self) -> usize {
        self.patterns.len()
    }
}

/// Build a PatternMatcher from a list of (pattern, label) pairs.
pub fn build_matcher(patterns: Vec<(&str, &str)>) -> PatternMatcher {
    PatternMatcher::new(
        patterns
            .into_iter()
            .map(|(p, l)| (p.to_string(), l.to_string()))
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_matcher() -> PatternMatcher {
        build_matcher(vec![
            ("googlebot", "bot:google"),
            ("bingbot", "bot:bing"),
            ("yahoo", "bot:yahoo"),
            ("curl/", "tool:curl"),
            ("wget/", "tool:wget"),
            ("python-requests", "tool:python"),
        ])
    }

    #[test]
    fn test_find_all_single() {
        let matcher = test_matcher();
        let results = matcher.find_all("Mozilla/5.0 (compatible; Googlebot/2.1)");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].label, "bot:google");
    }

    #[test]
    fn test_find_all_multiple() {
        let matcher = test_matcher();
        let results = matcher.find_all("googlebot and bingbot are both bots");
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn test_case_insensitive() {
        let matcher = test_matcher();
        assert!(matcher.is_match("GOOGLEBOT"));
        assert!(matcher.is_match("Googlebot"));
        assert!(matcher.is_match("googlebot"));
    }

    #[test]
    fn test_no_match() {
        let matcher = test_matcher();
        assert!(!matcher.is_match("Mozilla/5.0 (normal browser)"));
        assert_eq!(matcher.count_matches("normal text"), 0);
    }

    #[test]
    fn test_count_matches() {
        let matcher = test_matcher();
        assert_eq!(matcher.count_matches("googlebot bingbot yahoo"), 3);
    }

    #[test]
    fn test_find_first() {
        let matcher = test_matcher();
        let first = matcher.find_first("use curl/ or wget/ to fetch").unwrap();
        assert_eq!(first.label, "tool:curl");
    }

    #[test]
    fn test_find_first_none() {
        let matcher = test_matcher();
        assert!(matcher.find_first("nothing here").is_none());
    }

    #[test]
    fn test_pattern_count() {
        let matcher = test_matcher();
        assert_eq!(matcher.pattern_count(), 6);
    }

    #[test]
    fn test_match_result_positions() {
        let matcher = build_matcher(vec![("hello", "greeting")]);
        let results = matcher.find_all("say hello world");
        assert_eq!(results[0].start, 4);
        assert_eq!(results[0].end, 9);
    }

    #[test]
    fn test_empty_input() {
        let matcher = test_matcher();
        assert!(!matcher.is_match(""));
        assert_eq!(matcher.find_all("").len(), 0);
    }

    #[test]
    fn test_match_result_serialization() {
        let r = MatchResult {
            pattern_index: 0,
            pattern: "test".into(),
            start: 0,
            end: 4,
            label: "test_label".into(),
        };
        let json = serde_json::to_string(&r).unwrap();
        let de: MatchResult = serde_json::from_str(&json).unwrap();
        assert_eq!(de.label, "test_label");
    }
}
