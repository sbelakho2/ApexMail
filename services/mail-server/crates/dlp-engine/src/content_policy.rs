//! Content policy scanning — confidentiality markers, classification labels
//!
//! Detects organizational sensitivity markers in outbound email content://! - "CONFIDENTIAL", "INTERNAL ONLY", "DO NOT DISTRIBUTE"
//! - Custom keyword lists configured by policy
//! - Classification banners

use aho_corasick::AhoCorasick;

/// Content policy match
#[derive(Debug, Clone)]
pub struct PolicyMatch {
/// Matched keyword/phrase
    pub keyword: String,
/// Risk score
    pub risk: f64,
/// Byte offset
    pub offset: usize,
}

/// Scan content against confidentiality keywords
pub fn scan_content_policy(text: &str, keywords: &[String]) -> Vec<PolicyMatch> {
    if keywords.is_empty() {
        return Vec::new();
    }

    let ac = match AhoCorasick::builder()
        .ascii_case_insensitive(true)
        .build(keywords)
    {
        Ok(ac) => ac,
        Err(_) => return Vec::new(),
    };

    let mut matches = Vec::new();
    let mut seen = std::collections::HashSet::new();

    for mat in ac.find_iter(text) {
        let idx = mat.pattern().as_usize();
        if idx < keywords.len() && seen.insert(idx) {
// Assign risk based on keyword severity
            let keyword = &keywords[idx];
            let risk = classify_keyword_risk(keyword);
            matches.push(PolicyMatch {
                keyword: keyword.clone(),
                risk,
                offset: mat.start(),
            });
        }
    }

    matches
}

/// Classify risk based on keyword
fn classify_keyword_risk(keyword: &str) -> f64 {
    let lower = keyword.to_lowercase();
    if lower.contains("top secret") || lower.contains("classified") {
        8.0
    } else if lower.contains("confidential") || lower.contains("restricted") || lower.contains("privileged") {
        6.0
    } else if lower.contains("internal") || lower.contains("proprietary") || lower.contains("trade secret") {
        4.0
    } else if lower.contains("do not distribute") || lower.contains("attorney") {
        5.0
    } else {
        3.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_confidential_detection() {
        let keywords = vec!["confidential".into(), "internal only".into()];
        let text = "This document is CONFIDENTIAL and for Internal Only distribution.";
        let matches = scan_content_policy(text, &keywords);
        assert_eq!(matches.len(), 2);
    }

    #[test]
    fn test_no_matches() {
        let keywords = vec!["confidential".into(), "top secret".into()];
        let text = "Hey team, the meeting is moved to 3pm tomorrow.";
        let matches = scan_content_policy(text, &keywords);
        assert!(matches.is_empty());
    }

    #[test]
    fn test_risk_classification() {
        assert!(classify_keyword_risk("top secret") > classify_keyword_risk("internal only"));
        assert!(classify_keyword_risk("confidential") > classify_keyword_risk("internal only"));
    }

    #[test]
    fn test_empty_keywords() {
        let matches = scan_content_policy("some text", &[]);
        assert!(matches.is_empty());
    }

    #[test]
    fn test_deduplication() {
        let keywords = vec!["secret".into()];
        let text = "This is secret and that is also secret and everything is secret.";
        let matches = scan_content_policy(text, &keywords);
        assert_eq!(matches.len(), 1, "Should deduplicate same keyword");
    }
}
