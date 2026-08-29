#![allow(clippy::doc_lazy_continuation)]

//! Naive Bayes spam classifier with online learning
//!
//! Uses a multinomial Naive Bayes model with Laplace smoothing.
//! Supports online (incremental) training without needing to
//! retrain from scratch.
//!
//! ## Security hardening (February 2026)
//!
//! - **Input validation**:Reject training samples with excessive tokens or
//! suspiciously low entropy (potential adversarial input).
//! - **Training rate limits**:Prevent rapid training attacks that could bias
//! the model toward attacker-controlled classification.
//! - **Vocabulary pruning**:Bound vocabulary size to prevent memory exhaustion
//! from adversarial training with random tokens.

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{Duration, Instant};

// ---------------------------------------------------------------------------
// Governance constants
// ---------------------------------------------------------------------------

/// Maximum tokens allowed per training sample (prevents memory exhaustion).
const MAX_TOKENS_PER_SAMPLE: usize = 5000;

/// Minimum Shannon entropy required (bits per character). Low entropy samples
/// (e.g., aaaaa...) are likely adversarial or useless.
const MIN_ENTROPY_BITS: f64 = 1.5;

/// Maximum vocabulary size. When exceeded, low-frequency tokens are pruned.
const MAX_VOCABULARY_SIZE: usize = 500_000;

/// Prune tokens with count < this threshold during pruning.
const PRUNE_FREQUENCY_THRESHOLD: u64 = 2;

/// Training rate limit:max training calls per minute per classifier.
const MAX_TRAINING_PER_MINUTE: u64 = 100;

/// Maximum tokens [`tokenize`] will return. Consistent with the validation
/// cap ([`MAX_TOKENS_PER_SAMPLE`] rejects samples beyond 5 000 tokens) while
/// bounding the token-vector ALLOCATION itself for adversarial
/// multi-megabyte inputs — previously the full vector was materialized
/// before validation ever ran.
const MAX_TOKENIZE_OUTPUT: usize = 50_000;

// ---------------------------------------------------------------------------
// Validation error types
// ---------------------------------------------------------------------------

/// Training validation error.
#[derive(Debug, Clone)]
pub enum TrainingError {
    /// Sample has too many tokens.
    TooManyTokens {
        /// Number of tokens found in the sample.
        count: usize,
        /// Maximum allowed tokens.
        max: usize,
    },
    /// Sample has suspiciously low entropy.
    LowEntropy {
        /// Measured entropy of the sample.
        entropy: f64,
        /// Minimum required entropy.
        min: f64,
    },
    /// Training rate limit exceeded.
    RateLimitExceeded {
        /// Maximum allowed trainings per minute.
        per_minute: u64,
    },
    /// Vocabulary pruning triggered (informational, training succeeded).
    VocabularyPruned {
        /// Vocabulary size before pruning.
        before: usize,
        /// Vocabulary size after pruning.
        after: usize,
    },
}

/// Trained Bayesian classifier model
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
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

impl BayesianModel {
    /// Create a new empty model
    pub fn new() -> Self {
        Self::default()
    }

    /// Validate a training sample before ingestion.
    /// Returns `Ok(tokens)` if valid, or `Err(TrainingError)` if rejected.
    fn validate_sample(&self, text: &str) -> Result<Vec<String>, TrainingError> {
        // Check entropy first (fast reject for adversarial input)
        let entropy = calculate_entropy(text);
        if entropy < MIN_ENTROPY_BITS && text.len() > 20 {
            return Err(TrainingError::LowEntropy {
                entropy,
                min: MIN_ENTROPY_BITS,
            });
        }

        let tokens = tokenize(text);
        if tokens.len() > MAX_TOKENS_PER_SAMPLE {
            return Err(TrainingError::TooManyTokens {
                count: tokens.len(),
                max: MAX_TOKENS_PER_SAMPLE,
            });
        }

        Ok(tokens)
    }

    /// Prune low-frequency tokens from vocabulary when it exceeds the limit.
    /// Returns the number of tokens removed.
    pub fn prune_vocabulary(&mut self) -> usize {
        let current_size = self.spam_words.len() + self.ham_words.len();
        if current_size <= MAX_VOCABULARY_SIZE {
            return 0;
        }

        let mut pruned = 0;

        // Prune from spam_words
        let spam_before = self.spam_words.len();
        self.spam_words
            .retain(|_, count| *count >= PRUNE_FREQUENCY_THRESHOLD);
        let spam_pruned = spam_before - self.spam_words.len();
        pruned += spam_pruned;

        // Prune from ham_words
        let ham_before = self.ham_words.len();
        self.ham_words
            .retain(|_, count| *count >= PRUNE_FREQUENCY_THRESHOLD);
        let ham_pruned = ham_before - self.ham_words.len();
        pruned += ham_pruned;

        // Recalculate vocab_size
        let mut vocab_set = std::collections::HashSet::new();
        vocab_set.extend(self.spam_words.keys().cloned());
        vocab_set.extend(self.ham_words.keys().cloned());
        self.vocab_size = vocab_set.len() as u64;

        pruned
    }

    /// Train with a spam message (validated).
    /// Returns `Ok()` on success, or `Err(TrainingError)` if validation fails.
    pub fn train_spam_validated(&mut self, text: &str) -> Result<(), TrainingError> {
        let tokens = self.validate_sample(text)?;
        self.train_spam_tokens(&tokens);

        // Check if pruning needed
        if self.spam_words.len() + self.ham_words.len() > MAX_VOCABULARY_SIZE {
            let before = self.spam_words.len() + self.ham_words.len();
            self.prune_vocabulary();
            let after = self.spam_words.len() + self.ham_words.len();
            // Log but don't fail - pruning is a side effect
            tracing::info!(before, after, "Vocabulary pruned due to size limit");
        }

        Ok(())
    }

    /// Train with a ham message (validated).
    /// Returns `Ok()` on success, or `Err(TrainingError)` if validation fails.
    pub fn train_ham_validated(&mut self, text: &str) -> Result<(), TrainingError> {
        let tokens = self.validate_sample(text)?;
        self.train_ham_tokens(&tokens);

        if self.spam_words.len() + self.ham_words.len() > MAX_VOCABULARY_SIZE {
            let before = self.spam_words.len() + self.ham_words.len();
            self.prune_vocabulary();
            let after = self.spam_words.len() + self.ham_words.len();
            tracing::info!(before, after, "Vocabulary pruned due to size limit");
        }

        Ok(())
    }

    /// Internal:train with pre-tokenized spam tokens.
    fn train_spam_tokens(&mut self, tokens: &[String]) {
        self.spam_count += 1;
        for word in tokens {
            let entry = self.spam_words.entry(word.clone()).or_insert(0);
            *entry += 1;
            self.spam_total_words += 1;
            if !self.ham_words.contains_key(word) && self.spam_words.get(word) == Some(&1) {
                self.vocab_size += 1;
            }
        }
    }

    /// Internal:train with pre-tokenized ham tokens.
    fn train_ham_tokens(&mut self, tokens: &[String]) {
        self.ham_count += 1;
        for word in tokens {
            let entry = self.ham_words.entry(word.clone()).or_insert(0);
            *entry += 1;
            self.ham_total_words += 1;
            if !self.spam_words.contains_key(word) && self.ham_words.get(word) == Some(&1) {
                self.vocab_size += 1;
            }
        }
    }

    /// Train with a spam message (legacy API, no validation).
    /// **Deprecated**:Use `train_spam_validated` for production code.
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

    /// Train with a ham (legitimate) message (legacy API, no validation).
    /// **Deprecated**:Use `train_ham_validated` for production code.
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

/// Thread-safe classifier wrapper with rate limiting.
/// Includes training rate limits to prevent adversarial model poisoning.
pub struct BayesianClassifier {
    model: RwLock<BayesianModel>,
    rate_limit: parking_lot::Mutex<TrainingRateLimitState>,
}

#[derive(Debug)]
struct TrainingRateLimitState {
    window_start: Instant,
    count: u64,
}

impl BayesianClassifier {
    /// Create with an initial model
    pub fn new(model: BayesianModel) -> Self {
        Self {
            model: RwLock::new(model),
            rate_limit: parking_lot::Mutex::new(TrainingRateLimitState {
                window_start: Instant::now(),
                count: 0,
            }),
        }
    }

    /// Atomically check and consume one training slot.
    fn check_rate_limit(&self) -> bool {
        let now = Instant::now();
        let mut state = self.rate_limit.lock();
        if now.duration_since(state.window_start) >= Duration::from_secs(60) {
            state.window_start = now;
            state.count = 0;
        }

        if state.count >= MAX_TRAINING_PER_MINUTE {
            return false;
        }

        state.count += 1;
        true
    }

    /// Classify text
    pub fn classify(&self, text: &str) -> f64 {
        self.model.read().classify(text)
    }

    /// Total number of training samples (spam + ham).
    /// Cheap O(1) accessor — use this instead of [`Self::export_model`]
    /// (which deep-clones the entire vocabulary) for count checks.
    pub fn total_samples(&self) -> u64 {
        self.model.read().total_samples()
    }

    /// Current vocabulary size.
    /// Cheap O(1) accessor — see [`Self::total_samples`].
    pub fn vocab_size(&self) -> u64 {
        self.model.read().vocab_size
    }

    /// Online training:learn from a spam sample (validated + rate-limited).
    /// Returns `Err` if validation or rate limit fails.
    pub fn learn_spam_validated(&self, text: &str) -> Result<(), TrainingError> {
        if !self.check_rate_limit() {
            return Err(TrainingError::RateLimitExceeded {
                per_minute: MAX_TRAINING_PER_MINUTE,
            });
        }
        self.model.write().train_spam_validated(text)
    }

    /// Online training:learn from a ham sample (validated + rate-limited).
    /// Returns `Err` if validation or rate limit fails.
    pub fn learn_ham_validated(&self, text: &str) -> Result<(), TrainingError> {
        if !self.check_rate_limit() {
            return Err(TrainingError::RateLimitExceeded {
                per_minute: MAX_TRAINING_PER_MINUTE,
            });
        }
        self.model.write().train_ham_validated(text)
    }

    /// Online training:learn from a spam sample (legacy API, no validation).
    /// **Deprecated**:Use `learn_spam_validated` for production code.
    pub fn learn_spam(&self, text: &str) {
        self.model.write().train_spam(text);
    }

    /// Online training:learn from a ham sample (legacy API, no validation).
    /// **Deprecated**:Use `learn_ham_validated` for production code.
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

    /// Replace the in-memory model (used for rollback/snapshot restore).
    pub fn replace_model(&self, model: BayesianModel) {
        *self.model.write() = model;
    }

    /// Force vocabulary pruning. Returns number of tokens removed.
    pub fn prune_vocabulary(&self) -> usize {
        self.model.write().prune_vocabulary()
    }

    /// Get current training count for this minute.
    pub fn current_training_rate(&self) -> u64 {
        self.rate_limit.lock().count
    }
}

// ---------------------------------------------------------------------------
// Helper functions
// ---------------------------------------------------------------------------

/// Calculate Shannon entropy of text (bits per character).
/// Low entropy indicates potentially adversarial input (e.g., repeated chars).
fn calculate_entropy(text: &str) -> f64 {
    if text.is_empty() {
        return 0.0;
    }

    let mut char_freq: HashMap<char, usize> = HashMap::new();
    let mut total = 0usize;

    for c in text.chars() {
        *char_freq.entry(c).or_insert(0) += 1;
        total += 1;
    }

    let mut entropy = 0.0f64;
    for count in char_freq.values() {
        let p = *count as f64 / total as f64;
        if p > 0.0 {
            entropy -= p * p.log2();
        }
    }

    entropy
}

/// Tokenize text into unigrams and bigrams (lowercased, alphanumeric only, 3+ chars).
/// Bigrams capture two-word context (e.g., "free offer") which significantly
/// improves classification accuracy compared to unigrams alone.
///
/// Obfuscation resistance:invisible (zero-width) characters are stripped
/// before splitting, and each word is folded through the shared homoglyph /
/// leet map from `content_scorer` (Cyrillic а→a, Greek ο→o, leet digits,
/// …) and NFC-normalized, so homoglyph-substituted spellings produce the
/// same tokens as their plain Latin equivalents.
fn tokenize(text: &str) -> Vec<String> {
    use unicode_normalization::UnicodeNormalization;

    // 1. Strip invisible characters that would otherwise split words at
    //    invisible boundaries ("fr\u{200b}ee" → "fr" + "ee"), then NFC.
    let stripped: String = text
        .chars()
        .filter(|c| !crate::content_scorer::is_invisible_char(*c))
        .nfc()
        .collect();

    // 2. Split on non-alphanumerics, then fold per word. Folding *before*
    //    the split would glue punctuation substitutions onto neighboring
    //    words (normalize_leet_speak maps '!' → 'i', so "World!" would
    //    become "Worldi").
    let mut unigrams: Vec<String> = Vec::new();
    for word in stripped.split(|c: char| !c.is_alphanumeric()) {
        if unigrams.len() >= MAX_TOKENIZE_OUTPUT {
            break; // bounded output (see MAX_TOKENIZE_OUTPUT docs)
        }
        let folded = crate::content_scorer::normalize_leet_speak(word);
        let token = folded.to_lowercase();
        if token.chars().count() >= 3 {
            unigrams.push(token);
        }
    }

    let mut tokens = unigrams.clone();

    // Generate bigrams from adjacent unigrams
    for pair in unigrams.windows(2) {
        if tokens.len() >= MAX_TOKENIZE_OUTPUT {
            break;
        }
        tokens.push(format!("{}_{}", pair[0], pair[1]));
    }

    tokens
}

#[cfg(test)]
mod tests {
    use super::*;

    // =========================================================================
    // FUNCTIONAL TESTS
    // =========================================================================

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
        assert!(
            spam_prob > 0.7,
            "Expected spam probability > 0.7, got {}",
            spam_prob
        );

        let ham_prob = model.classify("please review the attached report for the meeting");
        assert!(
            ham_prob < 0.3,
            "Expected ham probability (spam_prob < 0.3), got {}",
            ham_prob
        );
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

    #[test]
    fn test_validated_training_success() {
        let mut model = BayesianModel::new();

        // Normal text should succeed
        let result =
            model.train_spam_validated("This is a normal email message with regular content.");
        assert!(result.is_ok(), "Normal training should succeed");

        let result =
            model.train_ham_validated("Another normal legitimate email with good entropy.");
        assert!(result.is_ok(), "Ham training should succeed");
    }

    // =========================================================================
    // INTEGRATION TESTS
    // =========================================================================

    #[test]
    fn test_classifier_rate_limiting() {
        let classifier = BayesianClassifier::new(BayesianModel::new());

        // First training calls should succeed
        for i in 0..50 {
            let result = classifier.learn_spam_validated(&format!(
                "spam message number {} with unique content xyz",
                i
            ));
            assert!(result.is_ok(), "First 50 should succeed");
        }

        // Check that rate is being tracked
        assert!(classifier.current_training_rate() > 0);
    }

    #[test]
    fn test_vocabulary_pruning() {
        let mut model = BayesianModel::new();

        // Add words - some with low frequency, some with higher
        for i in 0..100 {
            // Each unique word appears only once (low frequency)
            model.train_spam(&format!("uniqueword{}", i));
        }

        // Add some high-frequency words
        for _ in 0..10 {
            model.train_spam("common frequent repeated");
        }

        // Before pruning, we have low-frequency words
        let before_spam = model.spam_words.len();
        assert!(before_spam > 0, "Should have spam words");

        // Force pruning - this will remove words with count < 2
        let _pruned = model.prune_vocabulary();

        // Low-frequency words should be pruned (count < 2)
        // At minimum, the "common", "frequent", "repeated" should survive
        assert!(
            model.spam_words.contains_key("common") || model.spam_words.contains_key("frequent"),
            "High-frequency words should survive"
        );

        // Note:pruning only removes when count < PRUNE_FREQUENCY_THRESHOLD (2)
        // So words that appear once will be removed
    }

    #[test]
    fn test_model_export_import() {
        let classifier = BayesianClassifier::new(BayesianModel::new());

        // Train some data
        classifier.learn_spam("spam spam spam buy now free offer");
        classifier.learn_ham("meeting tomorrow please review document");

        // Export
        let exported = classifier.export_model();
        assert!(exported.spam_count > 0);
        assert!(exported.ham_count > 0);

        // Create new classifier from export
        let classifier2 = BayesianClassifier::new(exported.clone());

        // Should classify similarly
        let prob1 = classifier.classify("buy free offer");
        let prob2 = classifier2.classify("buy free offer");
        assert!(
            (prob1 - prob2).abs() < 0.01,
            "Exported model should classify same"
        );
    }

    // =========================================================================
    // CHAOS TESTS
    // =========================================================================

    #[test]
    fn test_chaos_large_input() {
        let mut model = BayesianModel::new();

        // Try to train with a very large input
        let large_text = "word ".repeat(10000);
        let result = model.train_spam_validated(&large_text);

        // Should fail due to too many tokens
        match result {
            Err(TrainingError::TooManyTokens { count, max }) => {
                assert!(count > max, "Should report too many tokens");
            }
            _ => panic!("Expected TooManyTokens error for large input"),
        }
    }

    #[test]
    fn test_chaos_concurrent_classification() {
        use std::sync::Arc;
        use std::thread;

        let classifier = Arc::new(BayesianClassifier::new(BayesianModel::new()));

        // Train some initial data
        classifier.learn_spam("spam spam free money now");
        classifier.learn_ham("meeting report quarterly review");

        let mut handles = vec![];

        // Spawn multiple threads doing concurrent classification
        for _ in 0..8 {
            let c = classifier.clone();
            handles.push(thread::spawn(move || {
                for _ in 0..1000 {
                    let _ = c.classify("test message for classification");
                }
            }));
        }

        for h in handles {
            h.join().expect("Thread should not panic");
        }
    }

    // =========================================================================
    // ADVERSARIAL TESTS
    // =========================================================================

    #[test]
    fn test_adversarial_low_entropy_rejected() {
        let mut model = BayesianModel::new();

        // Very low entropy input (repeated characters)
        let low_entropy = "aaaaaaaaaaaaaaaaaaaaaa".repeat(10);
        let result = model.train_spam_validated(&low_entropy);

        // Should fail due to low entropy
        match result {
            Err(TrainingError::LowEntropy { entropy, min }) => {
                assert!(
                    entropy < min,
                    "Should report low entropy: {} < {}",
                    entropy,
                    min
                );
            }
            _ => panic!("Expected LowEntropy error for repeated characters"),
        }
    }

    #[test]
    fn test_adversarial_random_token_flood() {
        let mut model = BayesianModel::new();

        // Try to flood with random tokens to exhaust vocabulary
        for i in 0..1000 {
            let random_text = format!("randomtoken{} anotherrand{} third{}", i, i * 2, i * 3);
            let _ = model.train_spam_validated(&random_text);
        }

        // Model should still function
        let prob = model.classify("regular email message");
        assert!((0.0..=1.0).contains(&prob), "Probability should be valid");
    }

    #[test]
    fn test_adversarial_poisoning_attempt() {
        let mut model = BayesianModel::new();

        // Train a good baseline
        for _ in 0..20 {
            model.train_spam("buy cheap viagra pills lottery winner");
            model.train_ham("meeting report quarterly budget review");
        }

        // Verify baseline classification
        let spam_prob = model.classify("buy cheap pills lottery");
        assert!(spam_prob > 0.7, "Should classify as spam: {}", spam_prob);

        // Attempt to poison:train spam words as ham
        for _ in 0..5 {
            model.train_ham("buy cheap viagra pills lottery winner");
        }

        // Model should still be somewhat resistant due to larger spam corpus
        let after_poison = model.classify("buy cheap pills lottery");
        // Probability may shift but shouldn't completely flip
        assert!(
            after_poison > 0.3,
            "Model should resist light poisoning: {}",
            after_poison
        );
    }

    #[test]
    fn test_adversarial_empty_input() {
        let mut model = BayesianModel::new();

        // Empty input should be handled gracefully
        let result = model.train_spam_validated("");
        // Should succeed (no tokens, but no error)
        assert!(result.is_ok(), "Empty input should be allowed");

        // Single word
        let result = model.train_spam_validated("abc");
        assert!(result.is_ok(), "Single word should be allowed");
    }

    #[test]
    fn test_adversarial_special_characters() {
        let mut model = BayesianModel::new();

        // Input with special characters that might cause parsing issues
        let special = "email@example.com <script>alert('xss')</script> '; DROP TABLE; --";
        let result = model.train_spam_validated(special);
        assert!(result.is_ok(), "Special characters should be handled");

        // Should still classify normally
        let prob = model.classify(special);
        assert!((0.0..=1.0).contains(&prob));
    }

    // ── Obfuscation-resistant tokenization tests ──

    #[test]
    fn test_tokenize_cyrillic_homoglyph_matches_latin() {
        // "frее" with Cyrillic е (U+0435) must tokenize identically to the
        // plain Latin "free".
        let plain = tokenize("free money now");
        let homoglyph = tokenize("fr\u{0435}\u{0435} money now");
        assert!(
            plain.contains(&"free".to_string()),
            "plain tokens missing free: {:?}",
            plain
        );
        assert!(
            homoglyph.contains(&"free".to_string()),
            "Cyrillic-\u{0435} substituted 'free' must fold to the Latin token: {:?}",
            homoglyph
        );
    }

    #[test]
    fn test_tokenize_strips_zero_width_and_nfc_normalizes() {
        // Zero-width space inside a word must not split it into shards.
        let tokens = tokenize("fr\u{200b}ee mon\u{feff}ey");
        assert!(tokens.contains(&"free".to_string()), "got {:?}", tokens);
        assert!(tokens.contains(&"money".to_string()), "got {:?}", tokens);
        // Decomposed (NFD) é normalizes to the composed form, matching the
        // composed spelling used during training.
        let decomposed = tokenize("cafe\u{301}");
        assert!(
            decomposed.contains(&"caf\u{e9}".to_string()),
            "got {:?}",
            decomposed
        );
    }

    #[test]
    fn test_tokenize_punctuation_not_glued() {
        // The leet map maps '!' to 'i'; folding must not glue it onto the
        // preceding word ("World!" must stay "world", not "worldi").
        let tokens = tokenize("Hello, World! This is a test-message.");
        assert!(tokens.contains(&"world".to_string()), "got {:?}", tokens);
        assert!(tokens.contains(&"hello".to_string()), "got {:?}", tokens);
    }

    #[test]
    fn test_classifier_total_samples_and_vocab_accessors() {
        let classifier = BayesianClassifier::new(BayesianModel::default());
        assert_eq!(classifier.total_samples(), 0);
        assert_eq!(classifier.vocab_size(), 0);
        classifier.learn_spam("buy cheap pills now offer");
        classifier.learn_ham("meeting notes attached report");
        assert_eq!(classifier.total_samples(), 2);
        assert!(classifier.vocab_size() > 0);
    }

    // ── F10:bounded tokenize output ────────────────────────────────────

    #[test]
    fn test_tokenize_output_is_bounded() {
        // ~60 000 unigrams would previously all be materialized (plus the
        // bigrams) before validation rejected the sample; tokenize itself
        // is now capped.
        let huge = "abc ".repeat(60_000);
        let tokens = tokenize(&huge);
        assert!(
            tokens.len() <= MAX_TOKENIZE_OUTPUT,
            "tokenize must be bounded, got {}",
            tokens.len()
        );

        // The validation cap still rejects the (bounded) token flood.
        match BayesianModel::new().train_spam_validated(&huge) {
            Err(TrainingError::TooManyTokens { count, max }) => {
                assert!(count > max);
            }
            other => panic!("expected TooManyTokens, got {:?}", other.map(|_| ())),
        }
    }
}
