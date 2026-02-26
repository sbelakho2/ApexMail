//! URL analysis for spam/phishing detection
//!
//! Checks:
//! - Known URL shortener services
//! - IDN homograph attacks (mixed-script detection)
//! - Suspicious TLDs
//! - IP-address URLs
//! - Excessive URL count
//! - Data URI schemes and javascript: URIs

use std::collections::HashSet;
use std::sync::OnceLock;

/// Result of URL analysis
#[derive(Debug, Clone)]
pub struct UrlScore {
    /// Total penalty from URL inspection
    pub score: f64,
    /// Individual findings
    pub findings: Vec<UrlFinding>,
    /// Count of distinct URLs found
    pub url_count: usize,
}

/// A single URL finding
#[derive(Debug, Clone)]
pub struct UrlFinding {
    /// Finding identifier
    pub id: &'static str,
    /// Description
    pub description: String,
    /// Penalty
    pub penalty: f64,
}

fn suspicious_tlds() -> &'static HashSet<&'static str> {
    static INSTANCE: OnceLock<HashSet<&'static str>> = OnceLock::new();
    INSTANCE.get_or_init(|| {
        [
            "tk", "ml", "ga", "cf", "gq",  // Free TLDs abused by spam
            "buzz", "top", "xyz", "club", "icu", "cam", "rest",
            "surf", "monster", "click", "link", "fit",
        ].into_iter().collect()
    })
}

fn url_shorteners() -> &'static HashSet<&'static str> {
    static INSTANCE: OnceLock<HashSet<&'static str>> = OnceLock::new();
    INSTANCE.get_or_init(|| {
        [
            "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
            "is.gd", "buff.ly", "rebrand.ly", "bl.ink", "short.io",
            "cutt.ly", "rb.gy", "v.gd", "shorte.st", "adf.ly",
        ].into_iter().collect()
    })
}

/// Extract URLs from text (simple extraction, not a full parser)
pub fn extract_urls(text: &str) -> Vec<String> {
    let mut urls = Vec::new();
    // Match http(s):// URLs
    let mut remaining = text;
    loop {
        let http_pos = remaining.find("http://");
        let https_pos = remaining.find("https://");
        let start = match (http_pos, https_pos) {
            (Some(a), Some(b)) => a.min(b),
            (Some(a), None) => a,
            (None, Some(b)) => b,
            (None, None) => break,
        };
        let url_start = &remaining[start..];
        let end = url_start
            .find(|c: char| c.is_whitespace() || c == '"' || c == '\'' || c == '>' || c == ')' || c == ']')
            .unwrap_or(url_start.len());
        let url = &url_start[..end];
        if url.len() > 10 {
            urls.push(url.to_string());
        }
        remaining = &remaining[start + end..];
    }
    urls
}

/// Analyze URLs found in email body for spam/phishing indicators
pub fn analyze_urls(body: &str) -> UrlScore {
    let mut findings = Vec::new();
    let urls = extract_urls(body);
    let url_count = urls.len();

    // 1. Excessive URLs
    if url_count > 15 {
        findings.push(UrlFinding {
            id: "EXCESSIVE_URLS",
            description: format!("{} URLs in message", url_count),
            penalty: 2.0,
        });
    }

    for url_str in &urls {
        // Parse host from URL
        let host = extract_host(url_str);
        let host_lower = host.to_lowercase();

        // 2. URL shorteners
        if url_shorteners().contains(host_lower.as_str()) {
            findings.push(UrlFinding {
                id: "URL_SHORTENER",
                description: format!("URL shortener used: {}", host_lower),
                penalty: 1.5,
            });
        }

        // 3. IP-address URL (http://192.168.1.1/...)
        if is_ip_address(&host_lower) {
            findings.push(UrlFinding {
                id: "IP_URL",
                description: format!("URL uses IP address: {}", host_lower),
                penalty: 3.0,
            });
        }

        // 4. Suspicious TLD
        if let Some(tld) = extract_tld(&host_lower) {
            if suspicious_tlds().contains(tld) {
                findings.push(UrlFinding {
                    id: "SUSPICIOUS_TLD",
                    description: format!("Suspicious TLD: .{}", tld),
                    penalty: 1.5,
                });
            }
        }

        // 5. IDN homograph detection (mixed scripts)
        if has_mixed_scripts(&host_lower) {
            findings.push(UrlFinding {
                id: "IDN_HOMOGRAPH",
                description: format!("Possible IDN homograph attack in: {}", host_lower),
                penalty: 4.0,
            });
        }

        // 6. Extremely long URL (data exfiltration / obfuscation)
        if url_str.len() > 500 {
            findings.push(UrlFinding {
                id: "VERY_LONG_URL",
                description: format!("URL length: {} chars", url_str.len()),
                penalty: 1.5,
            });
        }

        // 7. Port in URL (http://example.com:8080)
        if host_lower.contains(':') && !host_lower.starts_with('[') {
            findings.push(UrlFinding {
                id: "URL_WITH_PORT",
                description: format!("Non-standard port in URL: {}", host_lower),
                penalty: 1.0,
            });
        }
    }

    // 8. data: or javascript: URIs
    let lower_body = body.to_lowercase();
    if lower_body.contains("data:text/html") || lower_body.contains("data:application") {
        findings.push(UrlFinding {
            id: "DATA_URI",
            description: "Data URI found in message".into(),
            penalty: 3.0,
        });
    }
    if lower_body.contains("javascript:") {
        findings.push(UrlFinding {
            id: "JAVASCRIPT_URI",
            description: "javascript: URI found in message".into(),
            penalty: 4.0,
        });
    }

    let total_score: f64 = findings.iter().map(|f| f.penalty).sum();
    UrlScore {
        score: total_score,
        findings,
        url_count,
    }
}

fn extract_host(url: &str) -> String {
    let without_scheme = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
        .unwrap_or(url);
    let host_end = without_scheme.find('/').unwrap_or(without_scheme.len());
    let host_with_port = &without_scheme[..host_end];
    // Strip userinfo (user:pass@)
    let host = host_with_port
        .rfind('@')
        .map(|i| &host_with_port[i + 1..])
        .unwrap_or(host_with_port);
    host.to_string()
}

fn extract_tld(host: &str) -> Option<&str> {
    // Remove port if present
    let h = host.split(':').next().unwrap_or(host);
    h.rsplit('.').next()
}

fn is_ip_address(host: &str) -> bool {
    let h = host.split(':').next().unwrap_or(host);
    // IPv4 check
    h.split('.').all(|part| part.parse::<u8>().is_ok()) && h.split('.').count() == 4
}

fn has_mixed_scripts(host: &str) -> bool {
    let mut has_latin = false;
    let mut has_cyrillic = false;
    let mut has_greek = false;

    for c in host.chars() {
        if c.is_ascii_alphanumeric() || c == '.' || c == '-' {
            has_latin = true;
            continue;
        }
        // Check Unicode blocks for Cyrillic (U+0400-U+04FF)
        if ('\u{0400}'..='\u{04FF}').contains(&c) {
            has_cyrillic = true;
        }
        // Check for Greek (U+0370-U+03FF)
        if ('\u{0370}'..='\u{03FF}').contains(&c) {
            has_greek = true;
        }
    }

    (has_latin && has_cyrillic) || (has_latin && has_greek) || (has_cyrillic && has_greek)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_urls() {
        let text = "Visit https://example.com/page and http://evil.tk/phish for info";
        let urls = extract_urls(text);
        assert_eq!(urls.len(), 2);
        assert!(urls[0].contains("example.com"));
        assert!(urls[1].contains("evil.tk"));
    }

    #[test]
    fn test_url_shortener_detection() {
        let body = "Click here: https://bit.ly/abc123 to claim";
        let result = analyze_urls(body);
        assert!(result.findings.iter().any(|f| f.id == "URL_SHORTENER"));
    }

    #[test]
    fn test_ip_address_url() {
        let body = "Login at http://192.168.1.100/admin";
        let result = analyze_urls(body);
        assert!(result.findings.iter().any(|f| f.id == "IP_URL"));
    }

    #[test]
    fn test_suspicious_tld() {
        let body = "Visit https://free-stuff.tk/claim now!";
        let result = analyze_urls(body);
        assert!(result.findings.iter().any(|f| f.id == "SUSPICIOUS_TLD"));
    }

    #[test]
    fn test_data_uri() {
        let body = "Check this: data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==";
        let result = analyze_urls(body);
        assert!(result.findings.iter().any(|f| f.id == "DATA_URI"));
    }

    #[test]
    fn test_clean_urls() {
        let body = "Visit https://www.google.com for searching and https://github.com for code";
        let result = analyze_urls(body);
        assert!(result.score < 1.0, "Clean URLs scored {}", result.score);
    }

    #[test]
    fn test_mixed_scripts() {
        // Cyrillic 'а' mixed with Latin
        assert!(has_mixed_scripts("exаmple.com"));
        // Pure ASCII
        assert!(!has_mixed_scripts("example.com"));
    }
}
