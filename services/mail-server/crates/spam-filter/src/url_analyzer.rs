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

/// Find the first occurrence of an ASCII `needle` in `haystack[from..]`,
/// comparing case-insensitively, and return the byte offset relative to the
/// start of `haystack`.
///
/// Because the needle is pure ASCII, a match can only start and end on UTF-8
/// char boundaries (continuation bytes are >= 0x80 and never match ASCII), so
/// the returned offset is always safe for slicing `haystack`.
fn find_ignore_ascii_case(haystack: &str, needle: &str, from: usize) -> Option<usize> {
    let h = haystack.as_bytes();
    let n = needle.as_bytes();
    if n.is_empty() || h.len() < n.len() {
        return None;
    }
    let last_start = h.len() - n.len();
    let mut i = from;
    while i <= last_start {
        if h[i..i + n.len()].eq_ignore_ascii_case(n) {
            return Some(i);
        }
        i += 1;
    }
    None
}

/// Extract URLs from text (simple extraction, not a full parser).
///
/// Scheme prefixes such as `HTTP://` and `HTTPS://` are matched
/// case-insensitively — email clients routinely render mixed-case schemes as
/// clickable links. The match is performed directly on the original text (no
/// lowercased copy), so all byte offsets share a single coordinate system and
/// remain valid even when the text contains characters whose lowercased form
/// has a different UTF-8 length (e.g. `ẞ` U+1E9E → `ß`, or `İ` U+0130).
/// The extracted URL preserves the original casing for downstream analysis.
pub fn extract_urls(text: &str) -> Vec<String> {
    let mut urls = Vec::new();
    let mut offset = 0;
    loop {
        // Case-insensitive scheme detection on the ORIGINAL text — never mix
        // offsets computed against a transformed copy with slices of `text`.
        let http_pos = find_ignore_ascii_case(text, "http://", offset);
        let https_pos = find_ignore_ascii_case(text, "https://", offset);
        let start = match (http_pos, https_pos) {
            (Some(a), Some(b)) => a.min(b),
            (Some(a), None) => a,
            (None, Some(b)) => b,
            (None, None) => break,
        };
        let url_remaining = &text[start..];
        let end = url_remaining
            .find(|c: char| {
                c.is_whitespace() || c == '"' || c == '\'' || c == '>' || c == ')' || c == ']'
            })
            .unwrap_or(url_remaining.len());
        let url = &text[start..start + end];
        if url.len() > 10 {
            urls.push(url.to_string());
        }
        offset = start + end;
        if offset >= text.len() {
            break;
        }
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
    // Case-insensitive scheme strip:schemes are case-insensitive per RFC
    // 3986 (`HTTPS://`, `HtTp://` …), and `extract_urls` preserves the
    // original casing, so a lowercase-only strip missed uppercase URLs
    // entirely (host stayed "HTTPS://BIT.LY" and never matched a shortener).
    let without_scheme = if url.len() >= 8 && url[..8].eq_ignore_ascii_case("https://") {
        &url[8..]
    } else if url.len() >= 7 && url[..7].eq_ignore_ascii_case("http://") {
        &url[7..]
    } else {
        url
    };
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
    // Decode punycode (xn--…) labels to their Unicode form before classifying
    // scripts; otherwise IDN homograph attacks ("xn--pple-43d.com" containing
    // a Cyrillic 'а') are scanned as ASCII and pass the mixed-script check.
    let host_owned = host.split(':').next().unwrap_or(host).to_string();
    let decoded = idna::domain_to_unicode(&host_owned).0;
    let host = decoded.as_str();

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

    (has_greek || has_cyrillic) && has_latin || has_cyrillic && has_greek
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
///
/// # SSRF protection
/// Every hop (the initial URL *and* each `Location` redirect) must resolve
/// to a public address:private, loopback, link-local (including the cloud
/// metadata range 169.254.0.0/16), ULA and other reserved ranges are
/// refused before any request is made. Detonations are additionally bounded
/// by a shared concurrency semaphore and a shared pooled HTTP client.
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

/// Maximum number of URL detonations allowed to run concurrently.
pub const MAX_CONCURRENT_DETONATIONS: usize = 16;

#[cfg(feature = "phishing")]
fn detonation_semaphore() -> &'static tokio::sync::Semaphore {
    static SEM: std::sync::OnceLock<tokio::sync::Semaphore> = std::sync::OnceLock::new();
    SEM.get_or_init(|| tokio::sync::Semaphore::new(MAX_CONCURRENT_DETONATIONS))
}

/// Shared pooled HTTP client for detonations (connection reuse instead of a
/// fresh client — and fresh connection pool — per URL).
#[cfg(feature = "phishing")]
fn shared_detonation_client() -> &'static reqwest::Client {
    static CLIENT: std::sync::OnceLock<reqwest::Client> = std::sync::OnceLock::new();
    CLIENT.get_or_init(|| {
        reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(std::time::Duration::from_secs(REDIRECT_TIMEOUT_SECS))
            .user_agent("Mozilla/5.0 (compatible; ApexMail-UrlScanner/1.0)")
            .danger_accept_invalid_certs(false)
            .build()
            .expect("failed to build shared URL detonation client")
    })
}

/// Whether an IP address is private, loopback, link-local (this covers the
/// cloud metadata service at 169.254.169.254), ULA, or otherwise reserved.
/// Such addresses must never be reached by URL detonation (SSRF guard).
pub fn ip_is_private_or_reserved(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => {
            let o = v4.octets();
            v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_multicast()
                || v4.is_unspecified()
                || v4.is_documentation()
                || (o[0] == 100 && (64..=127).contains(&o[1])) // 100.64.0.0/10 CGNAT
                || o[0] == 0 // 0.0.0.0/8 "this network"
                || o[0] >= 240 // 240.0.0.0/4 reserved
        }
        std::net::IpAddr::V6(v6) => {
            let s = v6.segments();
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || (s[0] & 0xfe00) == 0xfc00 // fc00::/7 unique-local
                || (s[0] & 0xffc0) == 0xfe80 // fe80::/10 link-local
                || (s[0] == 0x2001 && (s[1] & 0xfff0) == 0x0db8) // 2001:db8::/32 doc
                || (s[0] == 0x64 && s[1] == 0xff9b) // 64:ff9b::/96 NAT64
        }
    }
}

/// SSRF pre-flight check for a URL:IP literals are checked directly;
/// hostnames must resolve, and *any* resolved address in a private/reserved
/// range blocks the detonation. Resolution failure also blocks (fail-closed).
#[cfg(feature = "phishing")]
async fn url_blocked_by_ssrf_guard(url_str: &str) -> Option<String> {
    let parsed = match url::Url::parse(url_str) {
        Ok(u) => u,
        Err(e) => return Some(format!("invalid URL: {e}")),
    };
    let host = match parsed.host() {
        Some(url::Host::Domain(d)) => d.to_string(),
        Some(url::Host::Ipv4(v4)) => {
            return if ip_is_private_or_reserved(std::net::IpAddr::V4(v4)) {
                Some(format!("SSRF guard:private/reserved IP literal {v4}"))
            } else {
                None
            };
        }
        Some(url::Host::Ipv6(v6)) => {
            return if ip_is_private_or_reserved(std::net::IpAddr::V6(v6)) {
                Some(format!("SSRF guard:private/reserved IP literal {v6}"))
            } else {
                None
            };
        }
        None => return Some("SSRF guard:URL has no host".into()),
    };
    let port = parsed.port_or_known_default().unwrap_or(80);

    // Resolve via getaddrinfo on the blocking pool (async-safe).
    let host_for_resolve = host.clone();
    let addrs = tokio::task::spawn_blocking(move || {
        use std::net::ToSocketAddrs;
        (host_for_resolve.as_str(), port)
            .to_socket_addrs()
            .map(|it| it.collect::<Vec<_>>())
    })
    .await;

    match addrs {
        Ok(Ok(socks)) if !socks.is_empty() => {
            for sock in socks {
                if ip_is_private_or_reserved(sock.ip()) {
                    return Some(format!(
                        "SSRF guard:host {host} resolves to private/reserved address {}",
                        sock.ip()
                    ));
                }
            }
            None
        }
        _ => Some(format!(
            "SSRF guard:host {host} could not be resolved (fail-closed)"
        )),
    }
}

#[cfg(feature = "phishing")]
async fn detonate_url_impl(url: &str) -> DetonationResult {
    // Bound concurrent detonations system-wide.
    let _permit = detonation_semaphore()
        .acquire()
        .await
        .expect("detonation semaphore is never closed");

    let client = shared_detonation_client();

    let mut current = url.to_string();
    let mut chain: Vec<String> = Vec::new();
    let mut hops = 0usize;
    let mut truncated = false;

    loop {
        if hops >= MAX_REDIRECT_HOPS {
            truncated = true;
            break;
        }

        // SSRF pre-flight on every hop (initial URL and each redirect).
        if let Some(reason) = url_blocked_by_ssrf_guard(&current).await {
            return DetonationResult {
                original_url: url.to_string(),
                final_url: current,
                redirect_chain: chain,
                hops,
                truncated: false,
                error: Some(reason),
            };
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

    /// Regression: `to_lowercase()` changes byte lengths for some characters
    /// (ẞ U+1E9E → ß shrinks 3→2 bytes). The old implementation computed
    /// offsets on the lowercased copy and used them to slice the original
    /// text, which panicked. Extraction must work entirely in original-text
    /// coordinates.
    #[test]
    fn test_extract_urls_after_shrinking_lowercase_chars() {
        let urls = extract_urls("ẞáhttps://example.com/x");
        assert_eq!(urls, vec!["https://example.com/x".to_string()]);
    }

    /// Regression: İ U+0130 lowercases to `i` + combining dot (2→3 bytes),
    /// which skewed offsets the other way.
    #[test]
    fn test_extract_urls_after_expanding_lowercase_chars() {
        let urls = extract_urls("İhttps://x.com");
        assert_eq!(urls, vec!["https://x.com".to_string()]);
    }

    #[test]
    fn test_extract_urls_uppercase_scheme_preserved() {
        let urls = extract_urls("URL HTTPS://EXAMPLE.COM");
        assert_eq!(urls, vec!["HTTPS://EXAMPLE.COM".to_string()]);
    }

    #[test]
    fn test_extract_urls_after_multibyte_emoji() {
        let urls = extract_urls("🎉🎊 https://example.com/party and 🚀http://foo.bar/x");
        assert_eq!(
            urls,
            vec![
                "https://example.com/party".to_string(),
                "http://foo.bar/x".to_string(),
            ]
        );
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
        const _: () = assert!(
            MAX_REDIRECT_HOPS >= 5,
            "Should allow at least 5 redirect hops"
        );
        const _: () = assert!(
            MAX_REDIRECT_HOPS <= 20,
            "Should cap redirect hops to avoid infinite loops"
        );
    }

    // ── Security-fix regression tests ──

    #[test]
    fn test_uppercase_scheme_url_analyzed() {
        // Scheme stripping in extract_host is case-insensitive now, so an
        // uppercase shortener URL must produce the URL_SHORTENER finding.
        let score = analyze_urls("Check HTTPS://BIT.LY/X now");
        assert!(
            score.findings.iter().any(|f| f.id == "URL_SHORTENER"),
            "uppercase-scheme shortener URL must be analyzed: {:?}",
            score.findings
        );
    }

    #[test]
    fn test_extract_host_mixed_case_scheme() {
        assert_eq!(extract_host("HtTpS://Example.COM/path"), "Example.COM");
        assert_eq!(extract_host("HTTPS://bit.ly/x"), "bit.ly");
        assert_eq!(extract_host("http://plain.example/"), "plain.example");
    }

    #[test]
    fn test_ip_is_private_or_reserved_matrix() {
        let parse = |s: &str| s.parse::<std::net::IpAddr>().unwrap();
        for blocked in [
            "127.0.0.1",
            "10.0.0.1",
            "192.168.1.1",
            "172.16.0.1",
            "169.254.169.254", // cloud metadata
            "0.0.0.0",
            "240.0.0.1",
            "100.64.0.1",
            "::1",
            "fc00::1",
            "fd12:3456::1",
            "fe80::1",
        ] {
            assert!(
                ip_is_private_or_reserved(parse(blocked)),
                "{blocked} must be blocked by the SSRF guard"
            );
        }
        for allowed in ["8.8.8.8", "1.1.1.1", "93.184.216.34", "2606:4700:4700::1111"] {
            assert!(
                !ip_is_private_or_reserved(parse(allowed)),
                "{allowed} is public and must not be blocked"
            );
        }
    }

    #[cfg(feature = "phishing")]
    #[tokio::test]
    async fn test_detonate_refuses_private_and_metadata_ips() {
        for url in [
            "http://127.0.0.1:8080/admin",
            "http://169.254.169.254/latest/meta-data/",
            "http://10.1.2.3/internal",
            "http://[::1]/x",
        ] {
            let result = detonate_url(url).await;
            assert!(
                result.error.as_deref().is_some_and(|e| e.contains("SSRF guard")),
                "detonation of {url} must be blocked by the SSRF guard, got {:?}",
                result.error
            );
            assert_eq!(result.hops, 0, "no request must be made for {url}");
        }
    }

    #[cfg(feature = "phishing")]
    #[test]
    fn test_detonation_concurrency_cap_defined() {
        assert!(
            MAX_CONCURRENT_DETONATIONS > 0 && MAX_CONCURRENT_DETONATIONS <= 64,
            "detonation concurrency must be bounded and sane"
        );
    }
}
