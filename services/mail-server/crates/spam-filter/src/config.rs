//! Spam filter configuration

use serde::{Deserialize, Serialize};

/// Spam filter configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SpamConfig {
    /// Score threshold below which email is considered ham (clean)
    pub ham_threshold: f64,
    /// Score threshold above which email is considered spam
    pub spam_threshold: f64,
    /// Score threshold above which email is rejected outright
    pub reject_threshold: f64,
    /// Enable Bayesian classifier
    pub enable_bayesian: bool,
    /// Enable header analysis
    pub enable_header_analysis: bool,
    /// Enable URL analysis
    pub enable_url_analysis: bool,
    /// Enable content pattern scoring
    pub enable_content_scoring: bool,
    /// Weight for Bayesian score (0.0-1.0)
    pub bayesian_weight: f64,
    /// Weight for header analysis score
    pub header_weight: f64,
    /// Weight for URL analysis score
    pub url_weight: f64,
    /// Weight for content pattern score
    pub content_weight: f64,
    /// Maximum URLs to analyze per email
    pub max_urls_to_analyze: usize,
    /// Dangerous attachment extensions
    pub dangerous_extensions: Vec<String>,
    /// Known URL shortener domains (configurable list)
    pub url_shorteners: Vec<String>,
    /// Require review workflow for training samples
    pub enable_guarded_training: bool,
    /// Maximum pending reviewed samples held in queue
    pub max_pending_training_samples: usize,
    /// Number of observations required before drift monitoring emits alerts
    pub min_samples_for_drift: usize,
    /// Drift alert threshold for moving average probability delta
    pub drift_alert_delta: f64,
    /// Custom phrase blocklists per category (key:category name, value:phrases)
    pub custom_phrase_blocklists: Vec<CustomPhraseList>,
    /// Minimum total Bayesian training samples before Bayesian weight is applied.
    /// Below this threshold, Bayesian probability is treated as 0.5 (neutral)
    /// to avoid unreliable classifications from under-trained models.
    pub min_training_samples: u64,
}

/// A customer-specific phrase blocklist for industry-specific spam vocabulary
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CustomPhraseList {
    /// Category name for the phrase list (e.g., "financial", "healthcare")
    pub category: String,
    /// Phrases in this list
    pub phrases: Vec<String>,
    /// Score weight for matches in this list (default 1.0)
    pub weight: f64,
}

impl Default for SpamConfig {
    fn default() -> Self {
        Self {
            ham_threshold: 3.0,
            spam_threshold: 6.0,
            reject_threshold: 10.0,
            enable_bayesian: true,
            enable_header_analysis: true,
            enable_url_analysis: true,
            enable_content_scoring: true,
            bayesian_weight: 0.3,
            header_weight: 0.25,
            url_weight: 0.25,
            content_weight: 0.2,
            max_urls_to_analyze: 50,
            enable_guarded_training: false,
            max_pending_training_samples: 5000,
            min_samples_for_drift: 100,
            drift_alert_delta: 0.15,
            dangerous_extensions: vec![
                "exe".into(),
                "scr".into(),
                "com".into(),
                "bat".into(),
                "cmd".into(),
                "pif".into(),
                "vbs".into(),
                "vbe".into(),
                "js".into(),
                "jse".into(),
                "wsf".into(),
                "wsh".into(),
                "ps1".into(),
                "msi".into(),
                "msp".into(),
                "jar".into(),
                "dll".into(),
                "cpl".into(),
                "hta".into(),
                "inf".into(),
                "reg".into(),
                "rgs".into(),
                "sct".into(),
                "shb".into(),
            ],
            url_shorteners: vec![
                // Major/popular URL shorteners
                "bit.ly".into(),
                "tinyurl.com".into(),
                "t.co".into(),
                "goo.gl".into(),
                "ow.ly".into(),
                "is.gd".into(),
                "buff.ly".into(),
                "rebrand.ly".into(),
                "bl.ink".into(),
                "short.io".into(),
                "cutt.ly".into(),
                "rb.gy".into(),
                "v.gd".into(),
                "shorte.st".into(),
                "adf.ly".into(),
                // Additional shorteners often used in spam
                "tiny.cc".into(),
                "clck.ru".into(),
                "x.co".into(),
                "lnkd.in".into(),
                "fb.me".into(),
                "youtu.be".into(),
                "soo.gd".into(),
                "s.id".into(),
                "rotf.lol".into(),
                "shorturl.at".into(),
                "1url.com".into(),
                "hyperurl.co".into(),
            ],
            custom_phrase_blocklists: Vec::new(),
            min_training_samples: 200,
        }
    }
}
