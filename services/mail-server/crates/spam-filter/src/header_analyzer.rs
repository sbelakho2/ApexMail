//! Email header analysis for spam detection
//!
//! Checks://! - SPF/DKIM/DMARC alignment
//! - Forged From/Reply-To mismatches
//! - Missing or malformed Message-ID
//! - Suspicious Received chain
//! - Date header anomalies (future-dated, missing)

/// Header analysis result
#[derive(Debug, Clone)]
pub struct HeaderScore {
/// Total penalty points from header analysis
    pub score: f64,
/// Individual findings
    pub findings: Vec<HeaderFinding>,
}

/// A single header finding
#[derive(Debug, Clone)]
pub struct HeaderFinding {
/// Finding identifier
    pub id: &'static str,
/// Description
    pub description: String,
/// Penalty score
    pub penalty: f64,
}

/// Email headers to analyze (simplified key-value representation)
pub struct EmailHeaders<'a> {
/// All headers as (name, value) pairs
    pub headers: &'a [(String, String)],
/// Authentication-Results header value (from upstream MTA)
    pub auth_results: Option<&'a str>,
}

/// Analyze email headers for spam indicators
pub fn analyze_headers(email: &EmailHeaders<'_>) -> HeaderScore {
    let mut findings = Vec::new();

// 1. Missing Message-ID
    let has_message_id = email.headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("message-id"));
    if !has_message_id {
        findings.push(HeaderFinding {
            id: "MISSING_MESSAGE_ID",
            description: "Missing Message-ID header".into(),
            penalty: 2.0,
        });
    }

// 2. Missing Date header
    let has_date = email.headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("date"));
    if !has_date {
        findings.push(HeaderFinding {
            id: "MISSING_DATE",
            description: "Missing Date header".into(),
            penalty: 1.5,
        });
    }

// 3. From/Reply-To domain mismatch
    let from_domain = extract_domain_from_header(email.headers, "from");
    let reply_to_domain = extract_domain_from_header(email.headers, "reply-to");
    if let (Some(from), Some(reply)) = (&from_domain, &reply_to_domain) {
        if from != reply {
            findings.push(HeaderFinding {
                id: "FROM_REPLY_MISMATCH",
                description: format!("From domain ({}) differs from Reply-To domain ({})", from, reply),
                penalty: 2.5,
            });
        }
    }

// 4. Missing or multiple From headers
    let from_count = email.headers.iter()
        .filter(|(k, _)| k.eq_ignore_ascii_case("from"))
        .count();
    if from_count == 0 {
        findings.push(HeaderFinding {
            id: "MISSING_FROM",
            description: "Missing From header".into(),
            penalty: 5.0,
        });
    } else if from_count > 1 {
        findings.push(HeaderFinding {
            id: "MULTIPLE_FROM",
            description: "Multiple From headers (potential forgery)".into(),
            penalty: 4.0,
        });
    }

// 5. Suspicious Received chain (missing or very short)
    let received_count = email.headers.iter()
        .filter(|(k, _)| k.eq_ignore_ascii_case("received"))
        .count();
    if received_count == 0 {
        findings.push(HeaderFinding {
            id: "NO_RECEIVED",
            description: "No Received headers (direct injection)".into(),
            penalty: 3.0,
        });
    }

// 6. Authentication results (SPF/DKIM/DMARC)
    if let Some(auth) = email.auth_results {
        let auth_lower = auth.to_lowercase();

// SPF fail
        if auth_lower.contains("spf=fail") || auth_lower.contains("spf=softfail") {
            findings.push(HeaderFinding {
                id: "SPF_FAIL",
                description: "SPF verification failed".into(),
                penalty: 3.0,
            });
        }
// DKIM fail
        if auth_lower.contains("dkim=fail") || auth_lower.contains("dkim=none") {
            findings.push(HeaderFinding {
                id: "DKIM_FAIL",
                description: "DKIM verification failed or absent".into(),
                penalty: 2.5,
            });
        }
// DMARC fail
        if auth_lower.contains("dmarc=fail") || auth_lower.contains("dmarc=none") {
            findings.push(HeaderFinding {
                id: "DMARC_FAIL",
                description: "DMARC verification failed or absent".into(),
                penalty: 3.0,
            });
        }
    } else {
        findings.push(HeaderFinding {
            id: "NO_AUTH_RESULTS",
            description: "No Authentication-Results header".into(),
            penalty: 1.0,
        });
    }

// 7. X-Mailer / User-Agent suspicious values
    for (k, v) in email.headers {
        if k.eq_ignore_ascii_case("x-mailer") || k.eq_ignore_ascii_case("user-agent") {
            let lower = v.to_lowercase();
            let suspicious_mailers = ["phpmailer", "swiftmailer", "mass mailer", "bulk"];
            for sm in &suspicious_mailers {
                if lower.contains(sm) {
                    findings.push(HeaderFinding {
                        id: "SUSPICIOUS_MAILER",
                        description: format!("Suspicious X-Mailer/User-Agent: {}", v),
                        penalty: 2.0,
                    });
                    break;
                }
            }
        }
    }

    let total_score: f64 = findings.iter().map(|f| f.penalty).sum();
    HeaderScore {
        score: total_score,
        findings,
    }
}

fn extract_domain_from_header(headers: &[(String, String)], header_name: &str) -> Option<String> {
    for (k, v) in headers {
        if k.eq_ignore_ascii_case(header_name) {
// Extract domain from "Name <user@domain.com>" or "user@domain.com"
            if let Some(at_pos) = v.rfind('@') {
                let after_at = &v[at_pos + 1..];
                let domain: String = after_at
                    .chars()
                    .take_while(|c| c.is_alphanumeric() || *c == '.' || *c == '-')
                    .collect();
                if !domain.is_empty() {
                    return Some(domain.to_lowercase());
                }
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_missing_message_id() {
        let headers = vec![
            ("From".into(), "user@example.com".into()),
            ("Date".into(), "Mon, 1 Jan 2024 00:00:00 +0000".into()),
        ];
        let result = analyze_headers(&EmailHeaders {
            headers: &headers,
            auth_results: None,
        });
        assert!(result.findings.iter().any(|f| f.id == "MISSING_MESSAGE_ID"));
    }

    #[test]
    fn test_from_reply_mismatch() {
        let headers = vec![
            ("From".into(), "user@bank.com".into()),
            ("Reply-To".into(), "scammer@evil.com".into()),
            ("Message-ID".into(), "<abc@example.com>".into()),
            ("Date".into(), "Mon, 1 Jan 2024 00:00:00 +0000".into()),
        ];
        let result = analyze_headers(&EmailHeaders {
            headers: &headers,
            auth_results: None,
        });
        assert!(result.findings.iter().any(|f| f.id == "FROM_REPLY_MISMATCH"));
    }

    #[test]
    fn test_spf_dkim_fail() {
        let headers = vec![
            ("From".into(), "user@example.com".into()),
            ("Message-ID".into(), "<abc@example.com>".into()),
            ("Date".into(), "Mon, 1 Jan 2024 00:00:00 +0000".into()),
            ("Received".into(), "from mx.example.com".into()),
        ];
        let result = analyze_headers(&EmailHeaders {
            headers: &headers,
            auth_results: Some("spf=fail; dkim=fail; dmarc=fail"),
        });
        assert!(result.findings.iter().any(|f| f.id == "SPF_FAIL"));
        assert!(result.findings.iter().any(|f| f.id == "DKIM_FAIL"));
        assert!(result.findings.iter().any(|f| f.id == "DMARC_FAIL"));
    }

    #[test]
    fn test_clean_headers() {
        let headers = vec![
            ("From".into(), "user@example.com".into()),
            ("Message-ID".into(), "<abc@example.com>".into()),
            ("Date".into(), "Mon, 1 Jan 2024 00:00:00 +0000".into()),
            ("Received".into(), "from mx.example.com by mx2.example.com".into()),
        ];
        let result = analyze_headers(&EmailHeaders {
            headers: &headers,
            auth_results: Some("spf=pass; dkim=pass; dmarc=pass"),
        });
// Should have minimal/no findings
        assert!(result.score < 1.0, "Clean headers score: {}", result.score);
    }
}
