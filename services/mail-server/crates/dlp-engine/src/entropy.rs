//! Shannon entropy analysis for detecting secrets, API keys, and tokens
//!
//! High-entropy strings in email bodies or attachments may indicate:
//! - API keys / secret tokens
//! - Encryption keys
//! - Passwords
//! - Base64-encoded sensitive data

use std::collections::HashMap;

/// Result of entropy analysis
#[derive(Debug, Clone)]
pub struct EntropyResult {
    /// High-entropy tokens found
    pub findings: Vec<EntropyFinding>,
    /// Total risk from entropy analysis
    pub risk_score: f64,
}

/// A high-entropy token
#[derive(Debug, Clone)]
pub struct EntropyFinding {
    /// The token (truncated for safety)
    pub token_preview: String,
    /// Shannon entropy value
    pub entropy: f64,
    /// Token length
    pub length: usize,
    /// Risk score
    pub risk: f64,
    /// Byte offset in source text
    pub offset: usize,
}

/// Calculate Shannon entropy of a string (bits per character)
pub fn shannon_entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }

    let mut freq: HashMap<char, usize> = HashMap::new();
    let len = s.len() as f64;

    for c in s.chars() {
        *freq.entry(c).or_insert(0) += 1;
    }

    let mut entropy = 0.0;
    for &count in freq.values() {
        let p = count as f64 / len;
        if p > 0.0 {
            entropy -= p * p.log2();
        }
    }

    entropy
}

/// Scan text for high-entropy tokens (potential secrets)
///
/// Tokenizes text by whitespace and punctuation, then checks each token.
pub fn scan_entropy(text: &str, threshold: f64, min_length: usize) -> EntropyResult {
    let mut findings = Vec::new();
    let mut total_risk = 0.0;

    // Tokenize by whitespace and common delimiters
    let mut offset = 0;
    for segment in text.split(|c: char| c.is_whitespace() || c == '"' || c == '\'' || c == ',' || c == ';') {
        let trimmed = segment.trim_matches(|c: char| !c.is_alphanumeric() && c != '-' && c != '_' && c != '=' && c != '+' && c != '/');

        if trimmed.len() >= min_length {
            let entropy = shannon_entropy(trimmed);
            if entropy >= threshold {
                // Check if it looks like a common high-entropy pattern (base64, hex, etc.)
                let is_likely_secret = looks_like_secret(trimmed);
                if is_likely_secret {
                    let risk = if entropy > 5.5 { 6.0 } else if entropy > 5.0 { 4.0 } else { 2.0 };
                    let preview = if trimmed.len() > 12 {
                        format!("{}...{}", &trimmed[..6], &trimmed[trimmed.len()-4..])
                    } else {
                        trimmed.to_string()
                    };

                    findings.push(EntropyFinding {
                        token_preview: preview,
                        entropy,
                        length: trimmed.len(),
                        risk,
                        offset: offset + text[offset..].find(trimmed).unwrap_or(0),
                    });
                    total_risk += risk;
                }
            }
        }

        offset += segment.len() + 1; // +1 for delimiter
    }

    EntropyResult {
        findings,
        risk_score: total_risk,
    }
}

/// Heuristic: does a token look like a secret/key?
fn looks_like_secret(token: &str) -> bool {
    // Must have mixed case or digits+letters
    let has_upper = token.chars().any(|c| c.is_ascii_uppercase());
    let has_lower = token.chars().any(|c| c.is_ascii_lowercase());
    let has_digit = token.chars().any(|c| c.is_ascii_digit());

    // Common patterns for secrets
    let mixed = (has_upper && has_lower) || (has_digit && (has_upper || has_lower));

    // Check for known key prefixes
    let key_prefixes = [
        "sk_", "pk_", "api_", "key_", "token_", "secret_",
        "AKIA", /* AWS */ "ghp_", "gho_", /* GitHub */
        "xox", /* Slack */ "sk-", /* OpenAI */
    ];

    let has_key_prefix = key_prefixes.iter().any(|p| token.starts_with(p));

    // Base64-like pattern (letters + digits + /+=)
    let base64_chars = token.chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '+' || *c == '/' || *c == '=')
        .count();
    let is_base64_like = base64_chars as f64 / token.len() as f64 > 0.95;

    // Hex-like pattern
    let hex_chars = token.chars()
        .filter(|c| c.is_ascii_hexdigit())
        .count();
    let is_hex_like = hex_chars == token.len() && token.len() >= 32;

    has_key_prefix || (mixed && (is_base64_like || is_hex_like))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_entropy_uniform() {
        // "aaaa" has zero entropy
        assert!(shannon_entropy("aaaa") < 0.01);
    }

    #[test]
    fn test_entropy_max() {
        // Equal distribution of many characters = high entropy
        let chars: String = (b'a'..=b'z').chain(b'0'..=b'9')
            .map(|b| b as char)
            .collect();
        let entropy = shannon_entropy(&chars);
        assert!(entropy > 4.0, "High diversity = high entropy: {}", entropy);
    }

    #[test]
    fn test_entropy_api_key() {
        let key = "sk_test_4eC39HqLyjWDarjtT1zdp7dc";
        let entropy = shannon_entropy(key);
        assert!(entropy > 4.0, "API key entropy: {}", entropy);
    }

    #[test]
    fn test_detect_api_key() {
        let text = "Here is the API key: sk_test_4eC39HqLyjWDarjtT1zdp7dc please keep safe";
        let result = scan_entropy(text, 4.0, 20);
        assert!(!result.findings.is_empty(), "Should detect API key");
    }

    #[test]
    fn test_detect_aws_key() {
        let text = "AWS key: AKIAIOSFODNN7EXAMPLE1234567890abcdef";
        let result = scan_entropy(text, 4.0, 20);
        assert!(!result.findings.is_empty(), "Should detect AWS key pattern");
    }

    #[test]
    fn test_normal_text_no_secrets() {
        let text = "Please review the quarterly report and send feedback by Friday.";
        let result = scan_entropy(text, 4.5, 20);
        assert!(result.findings.is_empty(), "Normal text shouldn't trigger: {:?}",
            result.findings.iter().map(|f| &f.token_preview).collect::<Vec<_>>());
    }

    #[test]
    fn test_looks_like_secret() {
        assert!(looks_like_secret("sk_test_4eC39HqLyjWDarjtT1zdp7dc"));
        assert!(looks_like_secret("AKIAIOSFODNN7EXAMPLE1234567890abcdef"));
        assert!(!looks_like_secret("hello"));
        assert!(!looks_like_secret("the quick brown fox jumps"));
    }
}
