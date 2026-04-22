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

/// Compute composite reputation from multiple source scores.
/// Uses a 70% max + 30% average formula to emphasize the worst source while
/// still accounting for consensus.
/// For a trust-weighted variant that factors in per-source trust scores, see
/// [`compute_reputation_weighted`].
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

// Composite:70% max + 30% average (emphasize worst source)
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

/// Trust-weighted composite reputation scoring.
/// Instead of treating all sources equally, each source's contribution is
/// scaled by its trust factor (0.0–10.0). A source with `trust = 10.0`
/// contributes its full score, while a source with `trust = 5.0` contributes
/// half. This prevents low-quality feeds from inflating the composite.
/// Formula:/// ```text
/// weighted_avg = Σ(score_i × trust_i) / Σ(trust_i)
/// max_score = max(score_i × trust_i / 10.0)
/// composite = 0.6 × max_score + 0.4 × weighted_avg
/// ```
pub fn compute_reputation_weighted(
    subject: &str,
    sources: Vec<SourceScore>,
    trust_scores: &[f64],
    flag_threshold: f64,
    block_threshold: f64,
) -> ReputationScore {
    if sources.is_empty() {
        return ReputationScore {
            subject: subject.into(),
            score: 0.0,
            sources,
            classification: ReputationClass::Clean,
        };
    }

    let mut sum_weighted = 0.0f64;
    let mut sum_trust = 0.0f64;
    let mut max_score = 0.0f64;

    for (i, src) in sources.iter().enumerate() {
        let trust = trust_scores.get(i).copied().unwrap_or(5.0).clamp(0.0, 10.0);
        let trust_factor = trust / 10.0;
        let weighted = src.score * trust_factor;
        sum_weighted += src.score * trust;
        sum_trust += trust;
        if weighted > max_score {
            max_score = weighted;
        }
    }

    let weighted_avg = if sum_trust > 0.0 { sum_weighted / sum_trust } else { 0.0 };
// 60% worst-trust-adjusted + 40% trust-weighted average
    let composite = (max_score * 0.6 + weighted_avg * 0.4).min(10.0);

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

    #[test]
    fn test_weighted_low_trust_dampens_score() {
// Source reports 10.0 (max threat) but trust is only 2.0/10
        let sources = vec![
            SourceScore { source: "LowTrust".into(), score: 10.0, category: "spam".into() },
        ];
        let rep = compute_reputation_weighted("1.2.3.4", sources, &[2.0], 4.0, 7.0);
// max_score = 10.0 * (2.0/10.0) = 2.0
// weighted_avg = (10.0 * 2.0) / 2.0 = 10.0
// composite = 0.6*2.0 + 0.4*10.0 = 1.2 + 4.0 = 5.2 → Suspicious, not Malicious
        assert_eq!(rep.classification, ReputationClass::Suspicious);
        assert!(rep.score < 7.0);
    }

    #[test]
    fn test_weighted_high_trust_preserves_score() {
        let sources = vec![
            SourceScore { source: "Spamhaus".into(), score: 9.0, category: "hijacked".into() },
        ];
        let rep = compute_reputation_weighted("1.2.3.4", sources, &[9.5], 4.0, 7.0);
// Trust 9.5/10 = nearly full → score preserved close to 9.0
        assert_eq!(rep.classification, ReputationClass::Malicious);
    }

    #[test]
    fn test_weighted_empty_sources() {
        let rep = compute_reputation_weighted("x", vec![], &[], 4.0, 7.0);
        assert_eq!(rep.classification, ReputationClass::Clean);
        assert!(rep.score < 0.01);
    }
}
