//! Naive Bayes spam classifier with online learning
//!
//! Uses a multinomial Naive Bayes model with Laplace smoothing.
//! Supports online (incremental) training without needing to
//! retrain from scratch.

use std::collections::HashMap;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};

/// Trained Bayesian classifier model
#[derive(Debug, Serialize, Deserialize)]
pub struct BayesianModel {
    /// Word frequencies in spam
    spam_words: HashMap<String, u64>,
    /// Word frequencies in ham
    ham_words: HashMap<String, u64>,
    /// Total spam messages seen
    spam_count: u64,
    /// Total ham messages seen
    ham_count: u64,
    /// Total words in spam corpus
    spam_total_words: u64,
    /// Total words in ham corpus
    ham_total_words: u64,
    /// Vocabulary size (unique words)
    vocab_size: u64,
}

impl Default for BayesianModel {
    fn default() -> Self {
        Self {
            spam_words: HashMap::new(),
            ham_words: HashMap::new(),
            spam_count: 0,
            ham_count: 0,
            spam_total_words: 0,
            ham_total_words: 0,
            vocab_size: 0,
        }
    }
}

impl BayesianModel {
    /// Create a new empty model
    pub fn new() -> Self {
        Self::default()
    }

    /// Train with a spam message
    pub fn train_spam(&mut self, text: &str) {
        self.spam_count += 1;
        for word in tokenize(text) {
            let entry = self.spam_words.entry(word.clone()).or_insert(0);
            *entry += 1;
            self.spam_total_words += 1;
            // Update vocab
            if !self.ham_words.contains_key(&word) && self.spam_words.get(&word) == Some(&1) {
                self.vocab_size += 1;
            }
        }
    }

    /// Train with a ham (legitimate) message
    pub fn train_ham(&mut self, text: &str) {
        self.ham_count += 1;
        for word in tokenize(text) {
            let entry = self.ham_words.entry(word.clone()).or_insert(0);
            *entry += 1;
            self.ham_total_words += 1;
            if !self.spam_words.contains_key(&word) && self.ham_words.get(&word) == Some(&1) {
                self.vocab_size += 1;
            }
        }
    }

    /// Classify text. Returns probability of being spam (0.0 - 1.0).
    pub fn classify(&self, text: &str) -> f64 {
        if self.spam_count == 0 || self.ham_count == 0 {
            return 0.5; // Not enough training data
        }

        let total = (self.spam_count + self.ham_count) as f64;
        let p_spam = self.spam_count as f64 / total;
        let p_ham = self.ham_count as f64 / total;

        let mut log_spam = p_spam.ln();
        let mut log_ham = p_ham.ln();

        let vocab = (self.vocab_size.max(1)) as f64;

        for word in tokenize(text) {
            // Laplace smoothing
            let spam_freq = *self.spam_words.get(&word).unwrap_or(&0) as f64;
            let ham_freq = *self.ham_words.get(&word).unwrap_or(&0) as f64;

            log_spam += ((spam_freq + 1.0) / (self.spam_total_words as f64 + vocab)).ln();
            log_ham += ((ham_freq + 1.0) / (self.ham_total_words as f64 + vocab)).ln();
        }

        // Convert log probabilities to probability using log-sum-exp
        let max_log = log_spam.max(log_ham);
        let spam_exp = (log_spam - max_log).exp();
        let ham_exp = (log_ham - max_log).exp();

        spam_exp / (spam_exp + ham_exp)
    }

    /// Total training samples
    pub fn total_samples(&self) -> u64 {
        self.spam_count + self.ham_count
    }
}

/// Thread-safe classifier wrapper
pub struct BayesianClassifier {
    model: RwLock<BayesianModel>,
}

impl BayesianClassifier {
    /// Create with an initial model
    pub fn new(model: BayesianModel) -> Self {
        Self {
            model: RwLock::new(model),
        }
    }

    /// Classify text
    pub fn classify(&self, text: &str) -> f64 {
        self.model.read().classify(text)
    }

    /// Online training: learn from a spam sample
    pub fn learn_spam(&self, text: &str) {
        self.model.write().train_spam(text);
    }

    /// Online training: learn from a ham sample
    pub fn learn_ham(&self, text: &str) {
        self.model.write().train_ham(text);
    }

    /// Export model for persistence
    pub fn export_model(&self) -> BayesianModel {
        let guard = self.model.read();
        BayesianModel {
            spam_words: guard.spam_words.clone(),
            ham_words: guard.ham_words.clone(),
            spam_count: guard.spam_count,
            ham_count: guard.ham_count,
            spam_total_words: guard.spam_total_words,
            ham_total_words: guard.ham_total_words,
            vocab_size: guard.vocab_size,
        }
    }
}

/// Tokenize text into words (lowercased, alphanumeric only, 3+ chars)
fn tokenize(text: &str) -> Vec<String> {
    text.split(|c: char| !c.is_alphanumeric())
        .filter(|w| w.len() >= 3)
        .map(|w| w.to_lowercase())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bayesian_basic() {
        let mut model = BayesianModel::new();

        // Train with spam
        for _ in 0..50 {
            model.train_spam("buy cheap viagra pills now free offer limited time");
            model.train_spam("congratulations you won the lottery claim your prize");
            model.train_spam("make money fast work from home guaranteed income");
        }

        // Train with ham
        for _ in 0..50 {
            model.train_ham("meeting scheduled for tomorrow at 10am in conference room");
            model.train_ham("please review the attached quarterly report for Q3");
            model.train_ham("the project deadline has been extended to next Friday");
        }

        // Test classification
        let spam_prob = model.classify("buy cheap pills now free money");
        assert!(spam_prob > 0.7, "Expected spam probability > 0.7, got {}", spam_prob);

        let ham_prob = model.classify("please review the attached report for the meeting");
        assert!(ham_prob < 0.3, "Expected ham probability (spam_prob < 0.3), got {}", ham_prob);
    }

    #[test]
    fn test_tokenizer() {
        let tokens = tokenize("Hello, World! This is a test-message.");
        assert!(tokens.contains(&"hello".to_string()));
        assert!(tokens.contains(&"world".to_string()));
        assert!(tokens.contains(&"test".to_string()));
        assert!(tokens.contains(&"message".to_string()));
        // "is" and "a" should be filtered (< 3 chars)
        assert!(!tokens.contains(&"is".to_string()));
        assert!(!tokens.contains(&"a".to_string()));
    }

    #[test]
    fn test_empty_model() {
        let model = BayesianModel::new();
        let prob = model.classify("anything");
        assert!((prob - 0.5).abs() < f64::EPSILON);
    }
}
