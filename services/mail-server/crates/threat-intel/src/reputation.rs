//! Reputation scoring — composite multi-source scoring

use serde::{Deserialize, Serialize};

/// Reputation verdict for an IP or domain
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReputationScore {
    /// The subject (IP or domain)
    pub subject: String,
    /// Composite reputation score (0.0 = clean, 10.0 = maximum threat)
    pub score: f64,
    /// Individual source scores
    pub sources: Vec<SourceScore>,
    /// Classification
    pub classification: ReputationClass,
}

/// Score from a single intelligence source
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceScore {
    /// Source name
    pub source: String,
    /// Score from this source (0.0 - 10.0)
    pub score: f64,
    /// Category
    pub category: String,
}

/// Reputation classification
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReputationClass {
    /// Clean / no known threats
    Clean,
    /// Suspicious (some indicators)
    Suspicious,
    /// Known malicious
    Malicious,
}

impl std::fmt::Display for ReputationClass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReputationClass::Clean => write!(f, "CLEAN"),
            ReputationClass::Suspicious => write!(f, "SUSPICIOUS"),
            ReputationClass::Malicious => write!(f, "MALICIOUS"),
        }
    }
}

/// Compute composite reputation from multiple source scores
pub fn compute_reputation(
    subject: &str,
    sources: Vec<SourceScore>,
    flag_threshold: f64,
    block_threshold: f64,
) -> ReputationScore {
    // Weighted average with maximum emphasis
    let max_score = sources.iter().map(|s| s.score).fold(0.0f64, f64::max);
    let avg_score = if sources.is_empty() {
        0.0
    } else {
        sources.iter().map(|s| s.score).sum::<f64>() / sources.len() as f64
    };

    // Composite: 70% max + 30% average (emphasize worst source)
    let composite = max_score * 0.7 + avg_score * 0.3;

    let classification = if composite >= block_threshold {
        ReputationClass::Malicious
    } else if composite >= flag_threshold {
        ReputationClass::Suspicious
    } else {
        ReputationClass::Clean
    };

    ReputationScore {
        subject: subject.into(),
        score: composite,
        sources,
        classification,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_clean_reputation() {
        let rep = compute_reputation("1.2.3.4", vec![], 4.0, 7.0);
        assert_eq!(rep.classification, ReputationClass::Clean);
        assert!(rep.score < 0.01);
    }

    #[test]
    fn test_malicious_reputation() {
        let sources = vec![
            SourceScore { source: "Spamhaus".into(), score: 9.0, category: "hijacked".into() },
            SourceScore { source: "AbuseIPDB".into(), score: 8.0, category: "spam".into() },
        ];
        let rep = compute_reputation("1.2.3.4", sources, 4.0, 7.0);
        assert_eq!(rep.classification, ReputationClass::Malicious);
        assert!(rep.score > 7.0);
    }

    #[test]
    fn test_suspicious_reputation() {
        let sources = vec![
            SourceScore { source: "Feed1".into(), score: 5.0, category: "scanner".into() },
        ];
        let rep = compute_reputation("1.2.3.4", sources, 4.0, 7.0);
        assert_eq!(rep.classification, ReputationClass::Suspicious);
    }

    #[test]
    fn test_worst_source_emphasis() {
        // One very bad source + one clean source
        let sources = vec![
            SourceScore { source: "Bad".into(), score: 10.0, category: "malware".into() },
            SourceScore { source: "Good".into(), score: 0.0, category: "none".into() },
        ];
        let rep = compute_reputation("x", sources, 4.0, 7.0);
        // 70% of 10 + 30% of 5 = 8.5 → Malicious
        assert_eq!(rep.classification, ReputationClass::Malicious);
    }
}
