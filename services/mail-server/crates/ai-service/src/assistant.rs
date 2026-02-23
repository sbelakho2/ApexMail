//! AI Assistant — subject line suggestions, content improvement, sentiment, summarisation.

use crate::types::{ContentSuggestion, ImprovementType};

/// AI-powered assistant for email content tasks.
pub struct AiAssistant;

impl Default for AiAssistant {
    fn default() -> Self {
        Self::new()
    }
}

impl AiAssistant {
    pub fn new() -> Self {
        Self
    }

    /// Generate subject line suggestions for a topic with a given tone.
    ///
    /// `tone` can be "urgent", "friendly", "formal", "curious", "playful".
    pub fn suggest_subject_lines(&self, topic: &str, tone: &str, count: usize) -> Vec<String> {
        let templates: Vec<Box<dyn Fn(&str) -> String>> = match tone {
            "urgent" => vec![
                Box::new(|t: &str| format!("🔥 {t} — Act Now!")),
                Box::new(|t: &str| format!("Last chance: {t}")),
                Box::new(|t: &str| format!("⏰ Don't miss out on {t}")),
                Box::new(|t: &str| format!("Limited time: {t} expires soon")),
                Box::new(|t: &str| format!("Hurry — {t} won't last")),
            ],
            "friendly" => vec![
                Box::new(|t: &str| format!("Hey! Check out {t} 🎉")),
                Box::new(|t: &str| format!("We think you'll love {t}")),
                Box::new(|t: &str| format!("Good news about {t}!")),
                Box::new(|t: &str| format!("You're going to enjoy {t}")),
                Box::new(|t: &str| format!("Something exciting about {t}")),
            ],
            "formal" => vec![
                Box::new(|t: &str| format!("Introducing: {t}")),
                Box::new(|t: &str| format!("An important update regarding {t}")),
                Box::new(|t: &str| format!("Your guide to {t}")),
                Box::new(|t: &str| format!("{t}: What you need to know")),
                Box::new(|t: &str| format!("Professional insights on {t}")),
            ],
            "curious" => vec![
                Box::new(|t: &str| format!("The secret to {t} revealed")),
                Box::new(|t: &str| format!("What nobody tells you about {t}")),
                Box::new(|t: &str| format!("Why {t} matters more than you think")),
                Box::new(|t: &str| format!("Discover the truth about {t}")),
                Box::new(|t: &str| format!("Have you heard about {t}?")),
            ],
            _ => vec![
                Box::new(|t: &str| format!("{t} — a quick update")),
                Box::new(|t: &str| format!("All about {t}")),
                Box::new(|t: &str| format!("Here's what's new with {t}")),
                Box::new(|t: &str| format!("Explore {t} today")),
                Box::new(|t: &str| format!("{t}: tips and insights")),
            ],
        };

        templates
            .iter()
            .take(count)
            .map(|f| f(topic))
            .collect()
    }

    /// Suggest improvements for a piece of email content.
    pub fn improve_content(&self, text: &str) -> ContentSuggestion {
        let mut suggested = text.to_string();
        let mut improvement = ImprovementType::SubjectLine;
        let mut confidence = 0.7;

        // Simple rule-based improvements
        if !text.contains("{{name}}") && !text.contains("{name}") {
            suggested = format!("Hi {{{{name}}}}, {}", text);
            improvement = ImprovementType::Personalization;
            confidence = 0.8;
        } else if text.len() > 80 {
            // Trim to a punchier version
            let words: Vec<&str> = text.split_whitespace().collect();
            let half = words.len() / 2;
            suggested = words[..half.max(5)].join(" ") + "...";
            improvement = ImprovementType::SubjectLine;
            confidence = 0.65;
        }

        ContentSuggestion::new(text, &suggested, improvement, confidence)
    }

    /// Keyword-based sentiment analysis returning a score in \[-1.0, 1.0\].
    pub fn analyze_sentiment(&self, text: &str) -> f64 {
        let lower = text.to_lowercase();
        let positive = [
            "love", "great", "amazing", "excellent", "awesome", "fantastic",
            "wonderful", "happy", "good", "best", "perfect", "thank",
            "beautiful", "enjoy", "exciting", "free", "win",
        ];
        let negative = [
            "hate", "bad", "terrible", "awful", "worst", "horrible",
            "angry", "sad", "poor", "disappointed", "spam", "annoy",
            "unsubscribe", "complaint", "refund", "cancel", "problem",
        ];

        let mut score = 0.0f64;
        for word in lower.split_whitespace() {
            let clean: String = word.chars().filter(|c| c.is_alphanumeric()).collect();
            if positive.contains(&clean.as_str()) {
                score += 1.0;
            }
            if negative.contains(&clean.as_str()) {
                score -= 1.0;
            }
        }

        // Normalise: map to [-1, 1] via tanh-like sigmoid
        let word_count = lower.split_whitespace().count().max(1) as f64;
        let normed = score / word_count.sqrt();
        normed.clamp(-1.0, 1.0)
    }

    /// Summarise text to at most `max_words` words using extractive summarisation.
    pub fn summarize(&self, text: &str, max_words: usize) -> String {
        if max_words == 0 {
            return String::new();
        }
        let words: Vec<&str> = text.split_whitespace().collect();
        if words.len() <= max_words {
            return text.to_string();
        }
        // Pick first `max_words` words (extractive lead summary).
        let mut summary: String = words[..max_words].join(" ");
        if !summary.ends_with('.') {
            summary.push_str("...");
        }
        summary
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_suggest_subject_lines_count() {
        let a = AiAssistant::new();
        let lines = a.suggest_subject_lines("product launch", "urgent", 3);
        assert_eq!(lines.len(), 3);
        assert!(lines[0].contains("product launch"));
    }

    #[test]
    fn test_improve_content_adds_personalization() {
        let a = AiAssistant::new();
        let s = a.improve_content("Check out our sale!");
        assert!(s.suggested.contains("{{name}}"));
        assert_eq!(s.improvement_type, ImprovementType::Personalization);
    }

    #[test]
    fn test_sentiment_positive_and_negative() {
        let a = AiAssistant::new();
        let pos = a.analyze_sentiment("I love this amazing product, it is truly excellent");
        let neg = a.analyze_sentiment("This is terrible and awful, I hate spam");
        assert!(pos > 0.0, "positive sentiment {pos} should be > 0");
        assert!(neg < 0.0, "negative sentiment {neg} should be < 0");
    }

    #[test]
    fn test_summarize_truncation() {
        let a = AiAssistant::new();
        let text = "The quick brown fox jumps over the lazy dog and runs away";
        let summary = a.summarize(text, 5);
        let word_count = summary.split_whitespace().count();
        // 5 words + possible "..." appended to last word
        assert!(word_count <= 6, "summary has {word_count} words");
    }
}
