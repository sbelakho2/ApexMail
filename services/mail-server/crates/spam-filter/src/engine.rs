//! Spam filter engine — orchestrates all analyzers
//!
//! Combines Bayesian classification, content scoring, header analysis,
//! and URL analysis into a single composite spam verdict.

use crate::bayesian::{BayesianClassifier, BayesianModel};
use crate::config::SpamConfig;
use crate::content_scorer::{self, ContentScore};
use crate::header_analyzer::{self, EmailHeaders, HeaderScore};
use crate::url_analyzer::{self, UrlScore};

/// Composite spam verdict
#[derive(Debug, Clone)]
pub struct SpamVerdict {
    /// Final composite score (higher = more likely spam)
    pub score: f64,
    /// Classification decision
    pub classification: SpamClass,
    /// Bayesian probability (0.0 = ham, 1.0 = spam)
    pub bayesian_probability: f64,
    /// Header analysis result
    pub header_score: HeaderScore,
    /// Content analysis result
    pub content_score: ContentScore,
    /// URL analysis result
    pub url_score: UrlScore,
}

/// Spam classification
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpamClass {
    /// Legitimate email
    Ham,
    /// Probable spam (flag/quarantine)
    Spam,
    /// Definite spam (reject)
    Reject,
}

impl std::fmt::Display for SpamClass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SpamClass::Ham => write!(f, "HAM"),
            SpamClass::Spam => write!(f, "SPAM"),
            SpamClass::Reject => write!(f, "REJECT"),
        }
    }
}

/// The spam filter engine
pub struct SpamEngine {
    config: SpamConfig,
    bayesian: BayesianClassifier,
}

impl SpamEngine {
    /// Create a new spam engine with default config
    pub fn new() -> Self {
        Self {
            config: SpamConfig::default(),
            bayesian: BayesianClassifier::new(BayesianModel::default()),
        }
    }

    /// Create with custom config
    pub fn with_config(config: SpamConfig) -> Self {
        Self {
            config,
            bayesian: BayesianClassifier::new(BayesianModel::default()),
        }
    }

    /// Get a reference to the Bayesian classifier for training
    pub fn bayesian(&self) -> &BayesianClassifier {
        &self.bayesian
    }

    /// Analyze an email and produce a composite verdict
    pub fn analyze(
        &self,
        body: &str,
        headers: &[(String, String)],
        auth_results: Option<&str>,
    ) -> SpamVerdict {
        // 1. Bayesian classification
        let bayesian_prob = self.bayesian.classify(body);

        // 2. Header analysis
        let email_headers = EmailHeaders {
            headers,
            auth_results,
        };
        let header_result = header_analyzer::analyze_headers(&email_headers);

        // 3. Content scoring
        let content_result = content_scorer::score_content(body);

        // 4. URL analysis
        let url_result = url_analyzer::analyze_urls(body);

        // 5. Composite scoring with configurable weights
        let composite = (bayesian_prob * 10.0 * self.config.bayesian_weight)
            + (header_result.score * self.config.header_weight)
            + (content_result.score * self.config.content_weight)
            + (url_result.score * self.config.url_weight);

        // 6. Classify
        let classification = if composite >= self.config.reject_threshold {
            SpamClass::Reject
        } else if composite >= self.config.spam_threshold {
            SpamClass::Spam
        } else {
            SpamClass::Ham
        };

        SpamVerdict {
            score: composite,
            classification,
            bayesian_probability: bayesian_prob,
            header_score: header_result,
            content_score: content_result,
            url_score: url_result,
        }
    }

    /// Train the Bayesian classifier with a spam sample
    pub fn train_spam(&self, text: &str) {
        self.bayesian.learn_spam(text);
    }

    /// Train the Bayesian classifier with a ham sample
    pub fn train_ham(&self, text: &str) {
        self.bayesian.learn_ham(text);
    }
}

impl Default for SpamEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn trained_engine() -> SpamEngine {
        let engine = SpamEngine::new();
        // Train with some spam
        for _ in 0..10 {
            engine.train_spam("Buy viagra now! Million dollars free lottery winner act now");
            engine.train_spam("Nigerian prince needs your help wire transfer urgently");
            engine.train_spam("You have won congratulations claim your prize immediately");
        }
        // Train with some ham
        for _ in 0..10 {
            engine.train_ham("Hi team, please review the quarterly report attached");
            engine.train_ham("Meeting scheduled for Tuesday at 3pm in conference room B");
            engine.train_ham("The deployment pipeline is passing all tests now");
        }
        engine
    }

    #[test]
    fn test_obvious_spam() {
        let engine = trained_engine();
        let headers = vec![
            ("From".into(), "scammer@evil.tk".into()),
            ("Reply-To".into(), "money@different.com".into()),
        ];
        let body = "Congratulations! You have won a million dollars! \
                     Click here: https://bit.ly/scam to wire transfer now! \
                     Act now! Limited time! Urgent!!!!!!!";

        let verdict = engine.analyze(body, &headers, Some("spf=fail; dkim=fail"));
        assert!(matches!(verdict.classification, SpamClass::Spam | SpamClass::Reject),
            "Expected Spam or Reject, got {:?}", verdict.classification);
        assert!(verdict.score > 5.0, "Spam score: {}", verdict.score);
    }

    #[test]
    fn test_clean_email() {
        let engine = trained_engine();
        let headers = vec![
            ("From".into(), "alice@company.com".into()),
            ("Message-ID".into(), "<abc123@company.com>".into()),
            ("Date".into(), "Mon, 1 Jan 2024 00:00:00 +0000".into()),
            ("Received".into(), "from mx.company.com by mx2.company.com".into()),
        ];
        let body = "Hi Bob, I wanted to follow up on the project timeline we discussed. \
                     Can you send me the updated schedule by end of day? Thanks.";

        let verdict = engine.analyze(body, &headers, Some("spf=pass; dkim=pass; dmarc=pass"));
        assert_eq!(verdict.classification, SpamClass::Ham);
    }

    #[test]
    fn test_phishing_email() {
        let engine = trained_engine();
        let headers = vec![
            ("From".into(), "security@bank-secure.tk".into()),
        ];
        let body = "Your account has been suspended. Verify your account immediately. \
                     Click here to login: http://192.168.1.50/bank/login \
                     Update your payment information to restore access. \
                     data:text/html;base64,PHNjcmlwdD4=";

        let verdict = engine.analyze(body, &headers, Some("spf=fail; dkim=none; dmarc=fail"));
        assert!(verdict.score > 5.0, "Phishing score: {}", verdict.score);
    }

    #[test]
    fn test_spam_class_display() {
        assert_eq!(SpamClass::Ham.to_string(), "HAM");
        assert_eq!(SpamClass::Spam.to_string(), "SPAM");
        assert_eq!(SpamClass::Reject.to_string(), "REJECT");
    }
}
