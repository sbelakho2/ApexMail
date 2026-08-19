//! Core pattern matcher using Aho-Corasick automaton.
//!
//! # Security
//!
//! - **O-13.1 (Error message sanitization):** `MatchResult` exposes only an
//!   opaque identifier (`pat-{index}`) instead of the raw pattern text, preventing
//!   internal rule content from leaking to external consumers.
//! - **O-13.2 (Unicode NFC normalization):** All input text is normalized to
//!   Unicode Normalization Form C (NFC) before matching, preventing Unicode
//!   equivalence attacks where visually identical characters with different
//!   codepoint sequences bypass pattern detection. Match offsets refer to the
//!   NFC-normalized text — see [`MatchResult::normalized`] for when they are
//!   also valid for the original input.

use aho_corasick::{AhoCorasick, AhoCorasickBuilder, MatchKind};
use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use unicode_normalization::UnicodeNormalization;

/// Result of a pattern match.
///
/// Only exposes an opaque identifier (`pat-{index}`) rather than the raw
/// pattern text, preventing internal rule content from leaking (O-13.1).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatchResult {
    pub pattern_index: usize,
    /// Opaque identifier that replaces the raw pattern text (O-13.1).
    /// Format: `"pat-{index}"` — does NOT reveal the actual matched pattern.
    pub opaque_id: String,
    /// Byte offset of the match start.
    ///
    /// # Offsets coordinate system (O-13.2)
    /// Offsets refer to the **NFC-normalized** form of the input text. See
    /// [`Self::normalized`] — when it is `false` the normalization was an
    /// identity transform and these offsets are also valid for slicing the
    /// original input text.
    pub start: usize,
    /// Byte offset (exclusive) of the match end — same coordinate system as
    /// [`Self::start`].
    pub end: usize,
    /// Whether NFC normalization changed the input text before matching.
    ///
    /// * `false` — normalization was an identity transform (e.g. ASCII or
    ///   already-NFC input): `start`/`end` are byte offsets into the
    ///   original input and are safe to use for slicing it.
    /// * `true` — the text changed under NFC (e.g. NFD input where
    ///   `e` + U+0301 becomes `é`): `start`/`end` refer to the normalized
    ///   copy ONLY. They MUST NOT be used to slice the original text, whose
    ///   byte layout may differ.
    pub normalized: bool,
    pub label: String,
}

impl MatchResult {
    /// Build a sanitized [`MatchResult`] with an opaque pattern identifier.
    fn new(pattern_index: usize, start: usize, end: usize, label: &str, normalized: bool) -> Self {
        Self {
            pattern_index,
            opaque_id: format!("pat-{pattern_index}"),
            start,
            end,
            normalized,
            label: label.to_string(),
        }
    }
}

/// High-performance multi-pattern matcher.
/// Uses Aho-Corasick automaton for O(n) matching over any number of patterns.
/// Immune to ReDoS by construction (no backtracking).
pub struct PatternMatcher {
    automaton: Option<AhoCorasick>,
    patterns: Vec<PatternEntry>,
}

#[derive(Debug, Clone)]
struct PatternEntry {
    label: String,
}

impl PatternMatcher {
    /// Build a matcher from labeled pattern strings.
    /// Returns `None` if the patterns are invalid (e.g., too many or conflicting).
    pub fn new(patterns: Vec<(String, String)>) -> Self {
        let entries: Vec<PatternEntry> = patterns
            .iter()
            .map(|(_, l)| PatternEntry { label: l.clone() })
            .collect();

        let automaton = match AhoCorasickBuilder::new()
            .ascii_case_insensitive(true)
            .match_kind(MatchKind::LeftmostLongest)
            .build(patterns.iter().map(|(p, _)| p.as_str()))
        {
            Ok(automaton) => Some(automaton),
            Err(e) => {
                // O-13.1: Log the error for diagnostics but do NOT expose it
                // to external callers via return values.
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

    /// Normalize input text to Unicode NFC form (O-13.2).
    ///
    /// This prevents Unicode equivalence attacks where visually identical
    /// characters (e.g., `é` as U+00E9 vs. U+0065 U+0301) bypass pattern
    /// matching by using a different normalization form.
    ///
    /// Returns a borrowed `Cow` when normalization is an identity transform
    /// (ASCII or already-NFC input) — in that case match offsets computed on
    /// the returned text are also valid for the original input. When an
    /// owned `Cow` is returned the text changed and offsets refer to the
    /// normalized copy only.
    fn normalize(text: &str) -> Cow<'_, str> {
        // Fast path: ASCII input is already in NFC — no copy needed.
        if text.is_ascii() {
            return Cow::Borrowed(text);
        }
        let normalized: String = text.nfc().collect();
        if normalized == text {
            return Cow::Borrowed(text);
        }
        Cow::Owned(normalized)
    }

    /// Find all matches in the input text.
    /// Input is NFC-normalized before matching (O-13.2); see
    /// [`MatchResult::normalized`] for the offset coordinate system.
    pub fn find_all(&self, text: &str) -> Vec<MatchResult> {
        let Some(automaton) = self.automaton.as_ref() else {
            return Vec::new();
        };

        let normalized = Self::normalize(text);
        let offsets_are_normalized = matches!(normalized, Cow::Owned(_));

        automaton
            .find_iter(normalized.as_ref())
            .map(|m| {
                let entry = &self.patterns[m.pattern().as_usize()];
                MatchResult::new(
                    m.pattern().as_usize(),
                    m.start(),
                    m.end(),
                    &entry.label,
                    offsets_are_normalized,
                )
            })
            .collect()
    }

    /// Check if any pattern matches.
    /// Input is NFC-normalized before matching (O-13.2).
    pub fn is_match(&self, text: &str) -> bool {
        self.automaton
            .as_ref()
            .map(|a| {
                let normalized = Self::normalize(text);
                a.is_match(normalized.as_ref())
            })
            .unwrap_or(false)
    }

    /// Count total matches.
    /// Input is NFC-normalized before matching (O-13.2).
    pub fn count_matches(&self, text: &str) -> usize {
        self.automaton
            .as_ref()
            .map(|a| {
                let normalized = Self::normalize(text);
                a.find_iter(normalized.as_ref()).count()
            })
            .unwrap_or(0)
    }

    /// Find first match only.
    /// Input is NFC-normalized before matching (O-13.2); see
    /// [`MatchResult::normalized`] for the offset coordinate system.
    pub fn find_first(&self, text: &str) -> Option<MatchResult> {
        let normalized = Self::normalize(text);
        let offsets_are_normalized = matches!(normalized, Cow::Owned(_));
        self.automaton.as_ref()?.find(normalized.as_ref()).map(|m| {
            let entry = &self.patterns[m.pattern().as_usize()];
            MatchResult::new(
                m.pattern().as_usize(),
                m.start(),
                m.end(),
                &entry.label,
                offsets_are_normalized,
            )
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
        // O-13.1: Verify opaque ID does not leak pattern content
        assert_eq!(results[0].opaque_id, "pat-0");
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
        // ASCII input: normalization is identity, offsets are valid for the
        // original text.
        assert!(!results[0].normalized);
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
            opaque_id: "pat-0".into(),
            start: 0,
            end: 4,
            normalized: false,
            label: "test_label".into(),
        };
        let json = serde_json::to_string(&r).unwrap();
        let de: MatchResult = serde_json::from_str(&json).unwrap();
        assert_eq!(de.label, "test_label");
        assert_eq!(de.opaque_id, "pat-0");
        assert!(!de.normalized);
    }

    /// O-13.2: Verify NFC normalization prevents Unicode equivalence bypass.
    #[test]
    fn test_nfc_normalization() {
        // "café" in NFD: 'e' (U+0065) + combining acute accent (U+0301)
        let nfd: String = "cafe\u{0301}".chars().collect();
        // Pattern is "café" in NFC: 'é' as single codepoint U+00E9
        let matcher = build_matcher(vec![("café", "accented")]);

        // Should match NFD input after NFC normalization
        assert!(matcher.is_match(&nfd));
        assert_eq!(matcher.count_matches(&nfd), 1);

        // MatchResult positions refer to NFC-normalized text; NFD input
        // changes under normalization, so consumers must NOT use these
        // offsets to slice the original input.
        let results = matcher.find_all(&nfd);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].label, "accented");
        assert!(results[0].normalized);
    }

    /// O-13.2 offsets contract: already-NFC input keeps offsets valid for
    /// the original text (`normalized == false`).
    #[test]
    fn test_nfc_input_offsets_valid_for_original() {
        let matcher = build_matcher(vec![("café", "accented")]);
        let nfc = "café"; // é as single codepoint U+00E9 — already NFC
        let results = matcher.find_all(nfc);
        assert_eq!(results.len(), 1);
        assert!(!results[0].normalized);
        // Offsets slice the ORIGINAL input safely.
        assert_eq!(&nfc[results[0].start..results[0].end], "café");
    }

    /// O-13.2: Verify mixed normalization forms all match.
    #[test]
    fn test_mixed_normalization_forms() {
        // Pattern in NFC
        let matcher = build_matcher(vec![("über cool", "umlaut")]);

        // NFD: u\u{0308}ber cool
        let nfd: String = "u\u{0308}ber cool".chars().collect();
        assert!(matcher.is_match(&nfd), "NFD input should match NFC pattern");

        // NFC: über cool (single ü codepoint)
        let nfc: String = "\u{00FC}ber cool".chars().collect();
        assert!(matcher.is_match(&nfc), "NFC input should match NFC pattern");

        // Mixed: u\u{0308}ber cool + some non-normalized chars
        let mixed: String = "u\u{0308}ber cool".chars().collect();
        assert!(
            matcher.is_match(&mixed),
            "Mixed input should match NFC pattern"
        );
    }
}
