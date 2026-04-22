//! Subject line analyzer – tokenization, category classification, scoring.

use regex::Regex;
use std::sync::LazyLock;
use tracing::warn;

use crate::types::*;

/// Scoring weights.
const WEIGHT_LENGTH: f64 = 0.20;
const WEIGHT_URGENCY: f64 = 0.15;
const WEIGHT_PERSONALIZATION: f64 = 0.20;
const WEIGHT_CLARITY: f64 = 0.25;
const WEIGHT_ANTI_SPAM: f64 = 0.20;

/// Optimal subject line length range.
static OPTIMAL_MIN_LEN: LazyLock<usize> = LazyLock::new(|| {
    std::env::var("ANALYTICS_SUBJECT_OPTIMAL_MIN_LEN")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(30)
});
static OPTIMAL_MAX_LEN: LazyLock<usize> = LazyLock::new(|| {
    std::env::var("ANALYTICS_SUBJECT_OPTIMAL_MAX_LEN")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(60)
});

/// Baseline open rate (industry average ~20%).
const BASELINE_OPEN_RATE: f64 = 0.20;

static URGENCY_WORDS: LazyLock<Vec<&'static str>> = LazyLock::new(|| {
    vec![
        "urgent", "hurry", "limited", "now", "today", "act", "expires",
        "deadline", "last chance", "final", "don't miss", "ending",
    ]
});
static EXCLUSIVITY_WORDS: LazyLock<Vec<&'static str>> = LazyLock::new(|| {
    vec![
        "exclusive", "vip", "invitation", "private", "members only",
        "insider", "selected", "elite",
    ]
});
static BENEFIT_WORDS: LazyLock<Vec<&'static str>> = LazyLock::new(|| {
    vec![
        "free", "save", "discount", "bonus", "reward", "earn", "win",
        "upgrade", "benefit", "value", "deal",
    ]
});
static CURIOSITY_WORDS: LazyLock<Vec<&'static str>> = LazyLock::new(|| {
    vec![
        "secret", "reveal", "discover", "surprising", "unexpected",
        "hidden", "mystery", "unlock",
    ]
});
static SOCIAL_PROOF_WORDS: LazyLock<Vec<&'static str>> = LazyLock::new(|| {
    vec![
        "popular", "trending", "everyone", "best-selling", "top rated",
        "customer favorite", "most loved", "recommended",
    ]
});
static PERSONALIZATION_PATTERNS: LazyLock<Vec<&'static str>> = LazyLock::new(|| {
    vec!["{first_name}", "{name}", "{company}", "you", "your"]
});
static SPAM_TOKENS: LazyLock<Vec<&'static str>> = LazyLock::new(|| {
    vec![
        "buy now", "click here", "act now", "limited time",
        "100%", "free!!!", "!!!", "$$", "winner", "congrats",
        "guarantee", "no obligation", "risk free", "dear friend",
        "make money", "cash bonus", "double your",
    ]
});
static SPAM_BIGRAMS: LazyLock<Vec<&'static str>> = LazyLock::new(|| {
    vec!["buy now", "act now", "click here", "free offer", "risk free", "no cost"]
});
static EMOJI_RE: LazyLock<Option<Regex>> = LazyLock::new(|| {
    compile_regex(r"[\p{Emoji_Presentation}\p{Emoji}\u{200d}\u{fe0f}]")
});

fn compile_regex(pattern: &str) -> Option<Regex> {
    match Regex::new(pattern) {
        Ok(regex) => Some(regex),
        Err(e) => {
            warn!(pattern = %pattern, error = %e, "Invalid regex pattern; disabling matcher");
            None
        }
    }
}

pub struct SubjectLineAnalyzer;

impl SubjectLineAnalyzer {
    pub fn new() -> Self {
        Self
    }

/// Analyze a subject line and return scored results.
    pub fn analyze(&self, subject: &str) -> SubjectLineScore {
        let lower = subject.to_lowercase();
        let tokens = tokenize(&lower);

        let token_analyses = classify_tokens(&tokens);

        let length_score = score_length(subject.len());
        let urgency_score = category_presence_score(&tokens, &URGENCY_WORDS);
        let personalization_score = personalization_check(subject);
        let clarity_score = score_clarity(subject);
        let spam_score = spam_check(&lower);
        let anti_spam_score = 100.0 - spam_score;

        let overall = length_score * WEIGHT_LENGTH
            + urgency_score * WEIGHT_URGENCY
            + personalization_score * WEIGHT_PERSONALIZATION
            + clarity_score * WEIGHT_CLARITY
            + anti_spam_score * WEIGHT_ANTI_SPAM;

        let predicted_open_rate = BASELINE_OPEN_RATE * (0.5 + overall / 100.0);

        let emoji_count = count_emojis(subject);

        SubjectLineScore {
            overall_score: overall.clamp(0.0, 100.0),
            length_score,
            urgency_score,
            personalization_score,
            clarity_score,
            spam_score,
            predicted_open_rate,
            token_analysis: token_analyses,
            emoji_count,
            word_count: tokens.len(),
        }
    }
}

/// Tokenize subject line into words.
pub fn tokenize(text: &str) -> Vec<String> {
    text.split_whitespace()
        .map(|w| w.trim_matches(|c: char| !c.is_alphanumeric() && c != '{' && c != '}'))
        .filter(|w| !w.is_empty())
        .map(String::from)
        .collect()
}

/// Classify tokens into categories.
pub fn classify_tokens(tokens: &[String]) -> Vec<TokenAnalysis> {
    tokens
        .iter()
        .map(|token| {
            let lower = token.to_lowercase();
            let category = if URGENCY_WORDS.iter().any(|w| lower.contains(w)) {
                TokenCategory::Urgency
            } else if EXCLUSIVITY_WORDS.iter().any(|w| lower.contains(w)) {
                TokenCategory::Exclusivity
            } else if BENEFIT_WORDS.iter().any(|w| lower.contains(w)) {
                TokenCategory::Benefit
            } else if CURIOSITY_WORDS.iter().any(|w| lower.contains(w)) {
                TokenCategory::Curiosity
            } else if SOCIAL_PROOF_WORDS.iter().any(|w| lower.contains(w)) {
                TokenCategory::SocialProof
            } else if PERSONALIZATION_PATTERNS.iter().any(|p| lower.contains(p)) {
                TokenCategory::Personalization
            } else {
                TokenCategory::Neutral
            };

            let _is_question = token.contains('?');
            let _is_number = token.chars().all(|c| c.is_ascii_digit());
            let _has_emoji = EMOJI_RE
                .as_ref()
                .map_or(false, |regex| regex.is_match(token));

            TokenAnalysis {
                token: token.clone(),
                category,
                sentiment: if BENEFIT_WORDS.iter().any(|w| lower.contains(w)) {
                    0.5
                } else if SPAM_TOKENS.iter().any(|w| lower.contains(w)) {
                    -0.5
                } else {
                    0.0
                },
                lift: compute_token_lift(&lower),
            }
        })
        .collect()
}

/// Score based on subject line length.
pub fn score_length(len: usize) -> f64 {
    if len >= *OPTIMAL_MIN_LEN && len <= *OPTIMAL_MAX_LEN {
        100.0
    } else if len < *OPTIMAL_MIN_LEN {
        (len as f64 / *OPTIMAL_MIN_LEN as f64) * 100.0
    } else {
        let excess = len - *OPTIMAL_MAX_LEN;
        (100.0 - excess as f64 * 2.0).max(20.0)
    }
}

/// Check for personalization patterns.
pub fn personalization_check(subject: &str) -> f64 {
    let lower = subject.to_lowercase();
    let mut score: f64 = 0.0;
    for p in PERSONALIZATION_PATTERNS.iter() {
        if lower.contains(p) {
            score += 25.0;
        }
    }
    score.min(100.0)
}

/// Score clarity:penalize all caps, excessive punctuation.
pub fn score_clarity(subject: &str) -> f64 {
    let mut score = 100.0;

// Penalize ALL CAPS
    let upper_ratio = subject.chars().filter(|c| c.is_uppercase()).count() as f64
        / subject.len().max(1) as f64;
    if upper_ratio > 0.5 {
        score -= 30.0;
    }

// Penalize excessive punctuation
    let punct_count = subject.chars().filter(|c| *c == '!' || *c == '?').count();
    if punct_count > 2 {
        score -= (punct_count as f64 - 2.0) * 10.0;
    }

// Penalize very short subjects
    if subject.len() < 10 {
        score -= 20.0;
    }

    score.max(0.0)
}

/// Spam score:check for spam tokens and bigrams.
pub fn spam_check(lower: &str) -> f64 {
    let mut spam_hits = 0.0;

    for token in &*SPAM_TOKENS {
        if lower.contains(token) {
            spam_hits += 1.0;
        }
    }

    for bigram in &*SPAM_BIGRAMS {
        if lower.contains(bigram) {
            spam_hits += 0.5;
        }
    }

// Also check for excessive caps or special chars
    if lower.contains("!!!") {
        spam_hits += 2.0;
    }
    if lower.contains("$$$") || lower.contains("$$") {
        spam_hits += 2.0;
    }

    (spam_hits * 15.0_f64).min(100.0)
}

/// Category presence score.
fn category_presence_score(tokens: &[String], word_list: &[&str]) -> f64 {
    let count = tokens
        .iter()
        .filter(|t| word_list.iter().any(|w| t.contains(w)))
        .count();
    ((count as f64) * 33.0).min(100.0)
}

/// Compute per-token "lift" – simplified heuristic.
fn compute_token_lift(token: &str) -> f64 {
    if BENEFIT_WORDS.iter().any(|w| token.contains(w)) {
        0.15
    } else if URGENCY_WORDS.iter().any(|w| token.contains(w)) {
        0.10
    } else if CURIOSITY_WORDS.iter().any(|w| token.contains(w)) {
        0.12
    } else if EXCLUSIVITY_WORDS.iter().any(|w| token.contains(w)) {
        0.08
    } else {
        0.0
    }
}

/// Count emoji characters.
fn count_emojis(s: &str) -> usize {
    EMOJI_RE
        .as_ref()
        .map_or(0, |regex| regex.find_iter(s).count())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tokenize() {
        let tokens = tokenize("hello world! this is a test");
        assert_eq!(tokens.len(), 6);
        assert_eq!(tokens[0], "hello");
    }

    #[test]
    fn test_score_length_optimal() {
        assert!((score_length(40) - 100.0).abs() < 0.01);
        assert!((score_length(50) - 100.0).abs() < 0.01);
    }

    #[test]
    fn test_score_length_short() {
        let score = score_length(15);
        assert!(score < 100.0);
        assert!(score > 0.0);
    }

    #[test]
    fn test_score_length_long() {
        let score = score_length(80);
        assert!(score < 100.0);
    }

    #[test]
    fn test_clarity_all_caps() {
        let score = score_clarity("BUY NOW FREE MONEY");
        assert!(score < 80.0);
    }

    #[test]
    fn test_clarity_good_subject() {
        let score = score_clarity("Your weekly newsletter is here");
        assert!(score >= 80.0);
    }

    #[test]
    fn test_spam_check_clean() {
        let score = spam_check("your weekly newsletter is ready");
        assert!(score < 15.0);
    }

    #[test]
    fn test_spam_check_spammy() {
        let score = spam_check("buy now!!! click here for free $$$ risk free guarantee");
        assert!(score > 50.0);
    }

    #[test]
    fn test_personalization_with_name() {
        let score = personalization_check("Hey {first_name}, check your deals");
        assert!(score >= 25.0);
    }

    #[test]
    fn test_personalization_with_you() {
        let score = personalization_check("Something special for you today");
        assert!(score >= 25.0);
    }

    #[test]
    fn test_full_analysis() {
        let analyzer = SubjectLineAnalyzer::new();
        let result = analyzer.analyze("Your exclusive weekly newsletter is ready");
        assert!(result.overall_score > 0.0);
        assert!(result.predicted_open_rate > 0.0);
        assert!(result.word_count > 0);
    }

    #[test]
    fn test_classify_urgency_token() {
        let tokens = vec!["urgent".to_string()];
        let analyses = classify_tokens(&tokens);
        assert!(matches!(analyses[0].category, TokenCategory::Urgency));
    }

    #[test]
    fn test_classify_benefit_token() {
        let tokens = vec!["free".to_string()];
        let analyses = classify_tokens(&tokens);
        assert!(matches!(analyses[0].category, TokenCategory::Benefit));
        assert!(analyses[0].lift > 0.0);
    }

    #[test]
    fn test_predicted_open_rate_range() {
        let analyzer = SubjectLineAnalyzer::new();
        let result = analyzer.analyze("Your exclusive weekly newsletter is ready");
// Should be between 10% and 30% for a decent subject
        assert!(result.predicted_open_rate > 0.10);
        assert!(result.predicted_open_rate < 0.40);
    }
}
