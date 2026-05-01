//! URL analysis for spam/phishing detection
//!
//! Checks://! - Known URL shortener services
//! - IDN homograph attacks (mixed-script detection)
//! - Suspicious TLDs
//! - IP-address URLs
//! - Excessive URL count
//! - Data URI schemes and javascript:URIs

use std::collections::HashSet;
use std::sync::OnceLock;

/// Maximum number of HTTP redirects to follow during URL detonation.
const MAX_REDIRECT_HOPS: usize = 10;

/// Timeout per redirect hop in seconds.
#[cfg(feature = "phishing")]
const REDIRECT_TIMEOUT_SECS: u64 = 5;

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
            "tk", "ml", "ga", "cf", "gq", // Free TLDs abused by spam
            "buzz", "top", "xyz", "club", "icu", "cam", "rest", "surf", "monster", "click", "link",
            "fit",
        ]
        .into_iter()
        .collect()
    })
}

fn url_shorteners() -> &'static HashSet<&'static str> {
    static INSTANCE: OnceLock<HashSet<&'static str>> = OnceLock::new();
    INSTANCE.get_or_init(|| {
        [
            "bit.ly",
            "tinyurl.com",
            "t.co",
            "goo.gl",
            "ow.ly",
            "is.gd",
            "buff.ly",
            "rebrand.ly",
            "bl.ink",
            "short.io",
            "cutt.ly",
            "rb.gy",
            "v.gd",
            "shorte.st",
            "adf.ly",
        ]
        .into_iter()
        .collect()
    })
}

/// Check if a host matches any URL shortener in the provided list (config-driven)
fn is_url_shortener_in_config(host: &str, shorteners: &[String]) -> bool {
    shorteners.iter().any(|s| s.eq_ignore_ascii_case(host))
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
            .find(|c: char| {
                c.is_whitespace() || c == '"' || c == '\'' || c == '>' || c == ')' || c == ']'
            })
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
    // Use default static list (backward compatible)
    analyze_urls_with_shorteners(body, None)
}

/// Analyze URLs with a configurable URL shortener list
/// If `shorteners` is None, uses the default static list
pub fn analyze_urls_with_shorteners(body: &str, shorteners: Option<&[String]>) -> UrlScore {
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

        // 2. URL shorteners (use config list if provided, else default)
        let is_shortener = match shorteners {
            Some(list) => is_url_shortener_in_config(&host_lower, list),
            None => url_shorteners().contains(host_lower.as_str()),
        };
        if is_shortener {
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

    // 8. data:or javascript:URIs
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

// ---------------------------------------------------------------------------
// URL Detonation — follow redirects to reveal the final landing URL
// ---------------------------------------------------------------------------

/// Result of detonating (following redirects on) a single URL.
#[derive(Debug, Clone)]
pub struct DetonationResult {
    /// The original URL that was submitted.
    pub original_url: String,
    /// The final URL after following all redirects.
    pub final_url: String,
    /// Ordered list of intermediate URLs traversed.
    pub redirect_chain: Vec<String>,
    /// Number of redirect hops taken.
    pub hops: usize,
    /// Whether the resolution was truncated because we hit `MAX_REDIRECT_HOPS`.
    pub truncated: bool,
    /// Error message if resolution failed at some point.
    pub error: Option<String>,
}

/// Result of detonating all URLs found in a message body.
#[derive(Debug, Clone)]
pub struct DetonationReport {
    /// Per-URL results.
    pub results: Vec<DetonationResult>,
    /// Additional findings generated from detonation (e.g. a shortener
    /// resolves to a suspicious TLD).
    pub findings: Vec<UrlFinding>,
    /// Aggregate penalty from detonation-specific findings.
    pub score: f64,
}

/// Follow HTTP redirects for a single URL and return the chain.
/// This uses a HEAD-only request with no cookies and a 5-second timeout per
/// hop. The `reqwest` client is configured with `redirect::Policy::none`
/// so that we can manually track each hop and enforce our own limit.
/// When the `phishing` feature is **not** enabled, this always returns an
/// error result without making any network calls.
pub async fn detonate_url(url: &str) -> DetonationResult {
    #[cfg(feature = "phishing")]
    {
        detonate_url_impl(url).await
    }
    #[cfg(not(feature = "phishing"))]
    {
        DetonationResult {
            original_url: url.to_string(),
            final_url: url.to_string(),
            redirect_chain: Vec::new(),
            hops: 0,
            truncated: false,
            error: Some("URL detonation requires the `phishing` feature".into()),
        }
    }
}

#[cfg(feature = "phishing")]
async fn detonate_url_impl(url: &str) -> DetonationResult {
    use std::time::Duration;

    let client = match reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(REDIRECT_TIMEOUT_SECS))
        .user_agent("Mozilla/5.0 (compatible; ApexMail-UrlScanner/1.0)")
        .danger_accept_invalid_certs(false)
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            return DetonationResult {
                original_url: url.to_string(),
                final_url: url.to_string(),
                redirect_chain: Vec::new(),
                hops: 0,
                truncated: false,
                error: Some(format!("Failed to create HTTP client: {e}")),
            };
        }
    };

    let mut current = url.to_string();
    let mut chain: Vec<String> = Vec::new();
    let mut hops = 0usize;
    let mut truncated = false;

    loop {
        if hops >= MAX_REDIRECT_HOPS {
            truncated = true;
            break;
        }

        let resp = match client.head(&current).send().await {
            Ok(r) => r,
            Err(e) => {
                return DetonationResult {
                    original_url: url.to_string(),
                    final_url: current,
                    redirect_chain: chain,
                    hops,
                    truncated: false,
                    error: Some(format!("Request failed at hop {hops}: {e}")),
                };
            }
        };

        let status = resp.status();
        if status.is_redirection() {
            if let Some(loc) = resp.headers().get("location") {
                let next = match loc.to_str() {
                    Ok(s) => {
                        // Handle relative redirects
                        if s.starts_with("http://") || s.starts_with("https://") {
                            s.to_string()
                        } else if let Ok(base) = url::Url::parse(&current) {
                            base.join(s)
                                .map(|u| u.to_string())
                                .unwrap_or_else(|_| s.to_string())
                        } else {
                            s.to_string()
                        }
                    }
                    Err(_) => break,
                };
                chain.push(current.clone());
                current = next;
                hops += 1;
            } else {
                break; // redirect without Location header
            }
        } else {
            break; // non-redirect status — we've arrived
        }
    }

    DetonationResult {
        original_url: url.to_string(),
        final_url: current,
        redirect_chain: chain,
        hops,
        truncated,
        error: None,
    }
}

/// Detonate **all** URLs found in the message body and produce a report with
/// additional findings.
/// For each URL shortener or redirect, the final resolved URL is also checked
/// against our suspicious-TLD list, IP-address heuristic, and IDN homograph
/// detector.
pub async fn detonate_urls(body: &str) -> DetonationReport {
    let urls = extract_urls(body);
    let mut results = Vec::with_capacity(urls.len());
    let mut findings = Vec::new();

    for url_str in &urls {
        let result = detonate_url(url_str).await;

        // If the final URL differs from the original, run our checks on the
        // resolved destination.
        if result.final_url != result.original_url && result.error.is_none() {
            let resolved_host = extract_host(&result.final_url);
            let resolved_lower = resolved_host.to_lowercase();

            // Check resolved TLD
            if let Some(tld) = extract_tld(&resolved_lower) {
                if suspicious_tlds().contains(tld) {
                    findings.push(UrlFinding {
                        id: "DETONATION_SUSPICIOUS_TLD",
                        description: format!(
                            "Redirect chain resolves to suspicious TLD .{}: {} -> {}",
                            tld, result.original_url, result.final_url
                        ),
                        penalty: 3.0,
                    });
                }
            }

            // Check resolved IP address URL
            if is_ip_address(&resolved_lower) {
                findings.push(UrlFinding {
                    id: "DETONATION_IP_URL",
                    description: format!(
                        "Redirect chain resolves to IP address: {} -> {}",
                        result.original_url, result.final_url
                    ),
                    penalty: 4.0,
                });
            }

            // Check resolved IDN homograph
            if has_mixed_scripts(&resolved_lower) {
                findings.push(UrlFinding {
                    id: "DETONATION_IDN_HOMOGRAPH",
                    description: format!(
                        "Redirect chain resolves to homograph URL: {} -> {}",
                        result.original_url, result.final_url
                    ),
                    penalty: 5.0,
                });
            }

            // Excessive redirect hops
            if result.hops > 3 {
                findings.push(UrlFinding {
                    id: "DETONATION_EXCESSIVE_HOPS",
                    description: format!(
                        "{} redirect hops from {} to {}",
                        result.hops, result.original_url, result.final_url
                    ),
                    penalty: 1.5,
                });
            }

            if result.truncated {
                findings.push(UrlFinding {
                    id: "DETONATION_TRUNCATED",
                    description: format!(
                        "Redirect chain exceeded {} hops — possible redirect loop: {}",
                        MAX_REDIRECT_HOPS, result.original_url
                    ),
                    penalty: 3.0,
                });
            }
        }

        results.push(result);
    }

    let score: f64 = findings.iter().map(|f| f.penalty).sum();
    DetonationReport {
        results,
        findings,
        score,
    }
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

    #[tokio::test]
    async fn test_detonate_url_no_phishing_feature() {
        // Without the phishing feature, detonation returns a noop result
        let result = detonate_url("https://bit.ly/abc123").await;
        assert_eq!(result.original_url, "https://bit.ly/abc123");
        // When phishing feature is off, we get an error result
        #[cfg(not(feature = "phishing"))]
        assert!(result.error.is_some());
    }

    #[tokio::test]
    async fn test_detonate_urls_empty_body() {
        let report = detonate_urls("No URLs here at all").await;
        assert!(report.results.is_empty());
        assert_eq!(report.score, 0.0);
    }

    #[test]
    fn test_detonation_result_structure() {
        let result = DetonationResult {
            original_url: "https://bit.ly/test".into(),
            final_url: "https://evil.tk/phish".into(),
            redirect_chain: vec!["https://bit.ly/test".into()],
            hops: 1,
            truncated: false,
            error: None,
        };
        assert_eq!(result.hops, 1);
        assert!(!result.truncated);
        assert!(result.error.is_none());
    }

    #[test]
    fn test_max_redirect_hops_constant() {
        assert!(
            MAX_REDIRECT_HOPS >= 5,
            "Should allow at least 5 redirect hops"
        );
        assert!(
            MAX_REDIRECT_HOPS <= 20,
            "Should cap redirect hops to avoid infinite loops"
        );
    }
}
