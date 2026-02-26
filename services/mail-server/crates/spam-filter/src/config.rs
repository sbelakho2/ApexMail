//! Spam filter configuration

use serde::{Deserialize, Serialize};

/// Spam filter configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
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
            dangerous_extensions: vec![
                "exe".into(), "scr".into(), "com".into(), "bat".into(),
                "cmd".into(), "pif".into(), "vbs".into(), "vbe".into(),
                "js".into(), "jse".into(), "wsf".into(), "wsh".into(),
                "ps1".into(), "msi".into(), "msp".into(), "jar".into(),
                "dll".into(), "cpl".into(), "hta".into(), "inf".into(),
                "reg".into(), "rgs".into(), "sct".into(), "shb".into(),
            ],
        }
    }
}
