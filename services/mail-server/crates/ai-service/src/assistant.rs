//! AI Assistant — subject line suggestions, content improvement, sentiment, summarisation.

use crate::types::{ContentSuggestion, ImprovementType};

type TemplateFn = fn(&str) -> String;

fn urgent_0(t: &str) -> String {
    format!("🔥 {t} — Act Now!")
}
fn urgent_1(t: &str) -> String {
    format!("Last chance: {t}")
}
fn urgent_2(t: &str) -> String {
    format!("⏰ Don't miss out on {t}")
}
fn urgent_3(t: &str) -> String {
    format!("Limited time: {t} expires soon")
}
fn urgent_4(t: &str) -> String {
    format!("Hurry — {t} won't last")
}

fn friendly_0(t: &str) -> String {
    format!("Hey! Check out {t} 🎉")
}
fn friendly_1(t: &str) -> String {
    format!("We think you'll love {t}")
}
fn friendly_2(t: &str) -> String {
    format!("Good news about {t}!")
}
fn friendly_3(t: &str) -> String {
    format!("You're going to enjoy {t}")
}
fn friendly_4(t: &str) -> String {
    format!("Something exciting about {t}")
}

fn formal_0(t: &str) -> String {
    format!("Introducing: {t}")
}
fn formal_1(t: &str) -> String {
    format!("An important update regarding {t}")
}
fn formal_2(t: &str) -> String {
    format!("Your guide to {t}")
}
fn formal_3(t: &str) -> String {
    format!("{t}: What you need to know")
}
fn formal_4(t: &str) -> String {
    format!("Professional insights on {t}")
}

fn curious_0(t: &str) -> String {
    format!("The secret to {t} revealed")
}
fn curious_1(t: &str) -> String {
    format!("What nobody tells you about {t}")
}
fn curious_2(t: &str) -> String {
    format!("Why {t} matters more than you think")
}
fn curious_3(t: &str) -> String {
    format!("Discover the truth about {t}")
}
fn curious_4(t: &str) -> String {
    format!("Have you heard about {t}?")
}

fn neutral_0(t: &str) -> String {
    format!("{t} — a quick update")
}
fn neutral_1(t: &str) -> String {
    format!("All about {t}")
}
fn neutral_2(t: &str) -> String {
    format!("Here's what's new with {t}")
}
fn neutral_3(t: &str) -> String {
    format!("Explore {t} today")
}
fn neutral_4(t: &str) -> String {
    format!("{t}: tips and insights")
}

const URGENT_TEMPLATES: &[TemplateFn] = &[urgent_0, urgent_1, urgent_2, urgent_3, urgent_4];
const FRIENDLY_TEMPLATES: &[TemplateFn] =
    &[friendly_0, friendly_1, friendly_2, friendly_3, friendly_4];
const FORMAL_TEMPLATES: &[TemplateFn] = &[formal_0, formal_1, formal_2, formal_3, formal_4];
const CURIOUS_TEMPLATES: &[TemplateFn] = &[curious_0, curious_1, curious_2, curious_3, curious_4];
const NEUTRAL_TEMPLATES: &[TemplateFn] = &[neutral_0, neutral_1, neutral_2, neutral_3, neutral_4];

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
    /// `tone` can be "urgent", "friendly", "formal", "curious", "playful".
    pub fn suggest_subject_lines(&self, topic: &str, tone: &str, count: usize) -> Vec<String> {
        let templates: &[TemplateFn] = match tone {
            "urgent" => URGENT_TEMPLATES,
            "friendly" => FRIENDLY_TEMPLATES,
            "formal" => FORMAL_TEMPLATES,
            "curious" => CURIOUS_TEMPLATES,
            _ => NEUTRAL_TEMPLATES,
        };

        templates.iter().take(count).map(|f| f(topic)).collect()
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
            "love",
            "great",
            "amazing",
            "excellent",
            "awesome",
            "fantastic",
            "wonderful",
            "happy",
            "good",
            "best",
            "perfect",
            "thank",
            "beautiful",
            "enjoy",
            "exciting",
            "free",
            "win",
        ];
        let negative = [
            "hate",
            "bad",
            "terrible",
            "awful",
            "worst",
            "horrible",
            "angry",
            "sad",
            "poor",
            "disappointed",
            "spam",
            "annoy",
            "unsubscribe",
            "complaint",
            "refund",
            "cancel",
            "problem",
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

        // Normalise:map to [-1, 1] via tanh-like sigmoid
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
