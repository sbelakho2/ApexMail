//! Content optimisation — subject-line scoring, improvement suggestions, A/B test
//! winner selection, and HTML-to-text preview generation.

use crate::types::{ContentSuggestion, ImprovementType};

/// Content scoring and optimisation engine.
pub struct ContentOptimizer;

impl Default for ContentOptimizer {
    fn default() -> Self {
        Self::new()
    }
}

impl ContentOptimizer {
    pub fn new() -> Self {
        Self
    }

    /// Score a subject line from 0 to 100 based on heuristics:/// length (25 pts), word count (20 pts), urgency keywords (20 pts),
    /// personalisation tokens (20 pts), emoji presence (15 pts).
    pub fn score_subject_line(&self, text: &str) -> u32 {
        let mut score: u32 = 0;
        let len = text.len();
        let word_count = text.split_whitespace().count();
        let lower = text.to_lowercase();

        // Length — sweet spot 30-60 chars
        score += if (30..=60).contains(&len) {
            25
        } else if (20..=80).contains(&len) {
            15
        } else {
            5
        };

        // Word count — 4-9 words ideal
        score += if (4..=9).contains(&word_count) {
            20
        } else if (2..=12).contains(&word_count) {
            12
        } else {
            5
        };

        // Urgency keywords
        let urgency_words = [
            "now",
            "today",
            "limited",
            "last chance",
            "hurry",
            "expires",
            "don't miss",
            "urgent",
        ];
        let urgency_hits = urgency_words.iter().filter(|w| lower.contains(**w)).count();
        score += (urgency_hits as u32 * 10).min(20);

        // Personalisation tokens
        if text.contains("{{") || text.contains("{name}") || text.contains("{first_name}") {
            score += 20;
        }

        // Emoji presence
        if text.chars().any(|c| {
            let n = c as u32;
            (0x1F600..=0x1F64F).contains(&n)
                || (0x1F300..=0x1F5FF).contains(&n)
                || (0x1F680..=0x1F6FF).contains(&n)
                || (0x2600..=0x26FF).contains(&n)
                || (0x2700..=0x27BF).contains(&n)
                || (0x1F900..=0x1F9FF).contains(&n)
        }) {
            score += 15;
        }

        score.min(100)
    }

    /// Generate improvement suggestions for a subject line.
    pub fn suggest_improvements(&self, text: &str) -> Vec<ContentSuggestion> {
        let mut suggestions = Vec::new();
        let len = text.len();
        let lower = text.to_lowercase();

        if len > 60 {
            let words: Vec<&str> = text.split_whitespace().collect();
            let shorter = words.iter().take(7).copied().collect::<Vec<_>>().join(" ");
            suggestions.push(ContentSuggestion::new(
                text,
                &shorter,
                ImprovementType::SubjectLine,
                0.75,
            ));
        }

        if len < 20 {
            let expanded = format!("Discover: {} — learn more today", text);
            suggestions.push(ContentSuggestion::new(
                text,
                &expanded,
                ImprovementType::SubjectLine,
                0.6,
            ));
        }

        if !text.contains("{{") && !text.contains("{name}") {
            let personalised = format!("{{{{name}}}}, {}", text.to_lowercase());
            suggestions.push(ContentSuggestion::new(
                text,
                &personalised,
                ImprovementType::Personalization,
                0.8,
            ));
        }

        let has_urgency = ["now", "today", "limited", "hurry"]
            .iter()
            .any(|w| lower.contains(w));
        if !has_urgency {
            let urgent_version = format!("{} — act now!", text);
            suggestions.push(ContentSuggestion::new(
                text,
                &urgent_version,
                ImprovementType::Cta,
                0.65,
            ));
        }

        suggestions
    }

    /// Pick the winning variant from A/B test results.
    /// Each entry is `(variant_name, metric_value)`. Returns the variant
    /// with the highest metric along with its value. Returns `None` if empty.
    pub fn ab_test_winner<'a>(&self, variants: &'a [(String, f64)]) -> Option<(&'a str, f64)> {
        variants
            .iter()
            .max_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal))
            .map(|(name, val)| (name.as_str(), *val))
    }

    /// Generate a plain-text preview from HTML email content.
    /// Strips tags and collapses whitespace.
    pub fn generate_preview(&self, html: &str) -> String {
        let mut out = String::with_capacity(html.len());
        let mut in_tag = false;
        let mut last_was_space = false;

        for ch in html.chars() {
            match ch {
                '<' => {
                    in_tag = true;
                }
                '>' => {
                    in_tag = false;
                    // Insert space after closing tag
                    if !last_was_space {
                        out.push(' ');
                        last_was_space = true;
                    }
                }
                _ if in_tag => {}
                _ => {
                    if ch.is_whitespace() {
                        if !last_was_space {
                            out.push(' ');
                            last_was_space = true;
                        }
                    } else {
                        out.push(ch);
                        last_was_space = false;
                    }
                }
            }
        }

        out.trim().to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_score_subject_line_good() {
        let c = ContentOptimizer::new();
        // Good subject:right length, urgency, emoji
        let score = c.score_subject_line("🔥 Don't miss our limited sale today!");
        assert!(score >= 50, "expected >= 50, got {score}");
    }

    #[test]
    fn test_suggest_improvements_short_text() {
        let c = ContentOptimizer::new();
        let suggestions = c.suggest_improvements("Big sale");
        assert!(!suggestions.is_empty());
        // Should suggest expansion and personalisation at minimum
        let types: Vec<_> = suggestions.iter().map(|s| s.improvement_type).collect();
        assert!(
            types.contains(&ImprovementType::SubjectLine)
                || types.contains(&ImprovementType::Personalization)
        );
    }

    #[test]
    fn test_ab_test_winner_selects_best() {
        let c = ContentOptimizer::new();
        let variants = vec![
            ("Variant A".to_string(), 0.12),
            ("Variant B".to_string(), 0.18),
            ("Variant C".to_string(), 0.15),
        ];
        let (name, val) = c.ab_test_winner(&variants).unwrap();
        assert_eq!(name, "Variant B");
        assert!((val - 0.18).abs() < f64::EPSILON);
    }

    #[test]
    fn test_generate_preview_strips_html() {
        let c = ContentOptimizer::new();
        let html = "<html><body><h1>Welcome</h1><p>Hello <b>world</b>!</p></body></html>";
        let preview = c.generate_preview(html);
        assert!(preview.contains("Welcome"));
        assert!(preview.contains("Hello"));
        assert!(preview.contains("world"));
        assert!(!preview.contains("<"));
    }
}
