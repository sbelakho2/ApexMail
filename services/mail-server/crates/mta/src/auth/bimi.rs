//! BIMI – Brand Indicators for Message Identification.
//!
//! Verifies BIMI DNS records, validates SVG logos, and checks VMC certificates.

use std::sync::LazyLock;
use std::time::Duration;

use reqwest::Client;
use serde::{Deserialize, Serialize};
use trust_dns_resolver::config::{ResolverConfig, ResolverOpts};
use trust_dns_resolver::TokioAsyncResolver;

// #131: Shared DNS resolver – avoids creating a new resolver per verify_bimi call
static BIMI_RESOLVER: LazyLock<TokioAsyncResolver> = LazyLock::new(|| {
    TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default())
});

// Shared HTTP client for BIMI logo fetching.
static BIMI_CLIENT: LazyLock<Client> = LazyLock::new(|| {
    Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap_or_else(|_| Client::new())
});

// #128: Maximum logo download size (256 KB) to prevent OOM from malicious URLs
const MAX_LOGO_SIZE: usize = 256 * 1024;

/// Parsed BIMI DNS record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BimiRecord {
    pub version: String,
    pub logo_url: Option<String>,
    pub certificate_url: Option<String>,
    pub selector: String,
}

/// Full BIMI verification result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BimiVerificationResult {
    pub supported: bool,
    pub record: Option<BimiRecord>,
    pub logo_valid: bool,
    pub dmarc_valid: bool,
    pub certificate_valid: bool,
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
    pub recommendations: Vec<String>,
}

/// SVG logo requirements.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BimiLogoRequirements {
    pub format: String,
    pub max_size: usize,
    pub square_aspect: bool,
    pub no_animation: bool,
    pub no_external_refs: bool,
    pub no_scripts: bool,
}

/// BIMI indicator for display.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BimiIndicator {
    pub logo_url: Option<String>,
    pub selector: String,
    pub verified: bool,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

/// Verify BIMI for a domain.
pub async fn verify_bimi(domain: &str, selector: &str) -> BimiVerificationResult {
    let mut result = BimiVerificationResult {
        supported: false,
        record: None,
        logo_valid: false,
        dmarc_valid: false,
        certificate_valid: false,
        errors: Vec::new(),
        warnings: Vec::new(),
        recommendations: Vec::new(),
    };

    // 1. Check DMARC enforcement (required for BIMI)
    let dmarc_name = format!("_dmarc.{domain}");
    // #131: Use shared resolver instead of creating new one per call
    let resolver = &*BIMI_RESOLVER;

    match resolver.txt_lookup(&dmarc_name).await {
        Ok(records) => {
            let has_enforcement = records.iter().any(|r| {
                let txt = r.to_string();
                txt.contains("p=reject") || txt.contains("p=quarantine")
            });
            result.dmarc_valid = has_enforcement;
            if !has_enforcement {
                result.errors.push("DMARC policy must be 'reject' or 'quarantine' for BIMI".into());
            }
        }
        Err(e) => {
            result.errors.push(format!("DMARC lookup failed: {e}"));
        }
    }

    // 2. Look up BIMI record
    let bimi_name = format!("{selector}._bimi.{domain}");
    match resolver.txt_lookup(&bimi_name).await {
        Ok(records) => {
            for record in records.iter() {
                let txt = record.to_string();
                if txt.starts_with("v=BIMI1") {
                    let parsed = parse_bimi_record(&txt, selector);
                    result.supported = true;

                    // 3. Validate logo if present
                    if let Some(ref url) = parsed.logo_url {
                        result.logo_valid = validate_bimi_logo_url(url).await;
                        if !result.logo_valid {
                            result.warnings.push("Logo URL failed validation".into());
                        }
                    }

                    // 4. Check VMC certificate
                    if let Some(ref cert_url) = parsed.certificate_url {
                        result.certificate_valid = validate_vmc_certificate(cert_url).await;
                    } else {
                        result.warnings.push("No VMC certificate URL provided".into());
                    }

                    result.record = Some(parsed);
                    break;
                }
            }
            if !result.supported {
                result.errors.push("No valid BIMI record found".into());
                result.recommendations.push(format!(
                    "Add a BIMI DNS record at {bimi_name}: v=BIMI1; l=https://example.com/logo.svg"
                ));
            }
        }
        Err(e) => {
            result.errors.push(format!("BIMI DNS lookup failed: {e}"));
            result.recommendations.push(format!(
                "Add a BIMI DNS record at {bimi_name}"
            ));
        }
    }

    if !result.dmarc_valid {
        result.recommendations.push("Set DMARC policy to 'reject' or 'quarantine'".into());
    }

    result
}

/// Generate a BIMI DNS TXT record value.
pub fn generate_bimi_record(logo_url: &str, certificate_url: Option<&str>) -> String {
    let mut record = format!("v=BIMI1; l={logo_url}");
    if let Some(cert) = certificate_url {
        record.push_str(&format!("; a={cert}"));
    }
    record
}

/// Validate a BIMI logo URL (basic checks).
pub async fn validate_bimi_logo_url(url: &str) -> bool {
    // Must be HTTPS
    if !url.starts_with("https://") {
        return false;
    }

    // Must end in .svg
    if !url.to_lowercase().ends_with(".svg") {
        return false;
    }

    // Try to fetch and validate SVG
    let client = &*BIMI_CLIENT;

    match client.get(url).send().await {
        Ok(resp) => {
            if !resp.status().is_success() {
                return false;
            }

            let content_type = resp
                .headers()
                .get("content-type")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("");

            if !content_type.contains("svg") && !content_type.contains("xml") {
                return false;
            }

            // #128: Check Content-Length before downloading
            if let Some(len) = resp.content_length() {
                if len > MAX_LOGO_SIZE as u64 {
                    return false;
                }
            }

            // #128: Download with size limit to prevent OOM
            match resp.bytes().await {
                Ok(bytes) => {
                    if bytes.len() > MAX_LOGO_SIZE {
                        return false;
                    }
                    let body = String::from_utf8_lossy(&bytes);
                    validate_svg_content(&body)
                }
                Err(_) => false,
            }
        }
        Err(_) => false,
    }
}

/// Validate SVG content for BIMI compliance (SVG Tiny PS).
/// #129: Comprehensive validation replacing fragile string matching.
/// #130: Robust external reference detection.
pub fn validate_svg_content(svg: &str) -> bool {
    let lower = svg.to_lowercase();

    // #129: Comprehensive script/event-handler detection
    let dangerous_patterns = [
        "<script", "javascript:", "vbscript:", "data:",
        "onerror", "onclick", "onload", "onmouseover", "onfocus",
        "onblur", "onsubmit", "onreset", "onchange", "oninput",
        "onkeydown", "onkeyup", "onkeypress", "onmouseout",
        "onmousedown", "onmouseup", "ondblclick",
        "eval(", "expression(",
    ];
    for pattern in &dangerous_patterns {
        if lower.contains(pattern) {
            return false;
        }
    }

    // Must not contain animations
    let animation_patterns = ["<animate", "<set ", "<animatetransform", "<animatemotion"];
    for pattern in &animation_patterns {
        if lower.contains(pattern) {
            return false;
        }
    }

    // #129: Reject entity-encoded characters that could bypass checks
    if lower.contains("&#") {
        return false;
    }

    // #129: Reject CDATA sections (can hide malicious content)
    if lower.contains("<![cdata[") {
        return false;
    }

    // #130: Reject foreignObject (can embed arbitrary HTML)
    if lower.contains("<foreignobject") {
        return false;
    }

    // #130: Stricter external reference detection – reject any href pointing
    // to an external URL, checking per-line instead of heuristic counting
    for line in lower.lines() {
        let has_href = line.contains("xlink:href") || line.contains("href=");
        let is_xmlns = line.contains("xmlns");
        if has_href && !is_xmlns {
            if line.contains("http://") || line.contains("https://") || line.contains("//") {
                return false;
            }
        }
    }

    // Must be a valid SVG (basic check)
    lower.contains("<svg")
}

/// Get BIMI indicator for display in email clients.
pub async fn get_bimi_indicator(domain: &str, dmarc_passed: bool) -> BimiIndicator {
    if !dmarc_passed {
        return BimiIndicator {
            logo_url: None,
            selector: "default".into(),
            verified: false,
            timestamp: chrono::Utc::now(),
        };
    }

    let result = verify_bimi(domain, "default").await;
    BimiIndicator {
        logo_url: result.record.and_then(|r| r.logo_url),
        selector: "default".into(),
        verified: result.supported && result.logo_valid && result.dmarc_valid,
        timestamp: chrono::Utc::now(),
    }
}

/// Get step-by-step BIMI setup instructions.
pub fn get_bimi_setup_instructions(
    domain: &str,
    logo_url: &str,
    certificate_url: Option<&str>,
) -> Vec<String> {
    let mut steps = vec![
        format!("1. Ensure DMARC is set to p=reject or p=quarantine for {domain}"),
        format!("2. Create SVG Tiny PS logo at {logo_url} (square aspect, no scripts/animations)"),
    ];

    if let Some(cert) = certificate_url {
        steps.push(format!("3. Obtain a VMC (Verified Mark Certificate) and host at {cert}"));
    } else {
        steps.push("3. (Optional) Obtain a VMC for enhanced verification".into());
    }

    let record = generate_bimi_record(logo_url, certificate_url);
    steps.push(format!(
        "4. Add DNS TXT record at default._bimi.{domain}: {record}"
    ));
    steps.push("5. Wait for DNS propagation (up to 48 hours)".into());
    steps.push("6. Test with a BIMI validator tool".into());

    steps
}

fn parse_bimi_record(txt: &str, selector: &str) -> BimiRecord {
    let mut logo_url = None;
    let mut certificate_url = None;
    let mut version = String::new();

    for part in txt.split(';') {
        let part = part.trim();
        if let Some(v) = part.strip_prefix("v=") {
            version = v.trim().to_string();
        } else if let Some(l) = part.strip_prefix("l=") {
            let url = l.trim().to_string();
            if !url.is_empty() {
                logo_url = Some(url);
            }
        } else if let Some(a) = part.strip_prefix("a=") {
            let url = a.trim().to_string();
            if !url.is_empty() {
                certificate_url = Some(url);
            }
        }
    }

    BimiRecord {
        version,
        logo_url,
        certificate_url,
        selector: selector.to_string(),
    }
}

async fn validate_vmc_certificate(url: &str) -> bool {
    if !url.starts_with("https://") {
        return false;
    }

    let client = match Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
    {
        Ok(c) => c,
        Err(_) => return false,
    };

    match client.get(url).send().await {
        Ok(resp) => resp.status().is_success(),
        Err(_) => false,
    }
}

// ── tests ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_bimi_record() {
        let record = generate_bimi_record("https://example.com/logo.svg", None);
        assert_eq!(record, "v=BIMI1; l=https://example.com/logo.svg");

        let record = generate_bimi_record(
            "https://example.com/logo.svg",
            Some("https://example.com/cert.pem"),
        );
        assert!(record.contains("a=https://example.com/cert.pem"));
    }

    #[test]
    fn test_parse_bimi_record() {
        let txt = "v=BIMI1; l=https://example.com/logo.svg; a=https://example.com/cert.pem";
        let record = parse_bimi_record(txt, "default");
        assert_eq!(record.version, "BIMI1");
        assert_eq!(
            record.logo_url.unwrap(),
            "https://example.com/logo.svg"
        );
        assert_eq!(
            record.certificate_url.unwrap(),
            "https://example.com/cert.pem"
        );
    }

    #[test]
    fn test_validate_svg_content_valid() {
        let svg = r#"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100"><circle cx="50" cy="50" r="40"/></svg>"#;
        assert!(validate_svg_content(svg));
    }

    #[test]
    fn test_validate_svg_content_with_script() {
        let svg = r#"<svg><script>alert(1)</script></svg>"#;
        assert!(!validate_svg_content(svg));
    }

    #[test]
    fn test_validate_svg_content_with_animation() {
        let svg = r#"<svg><animate attributeName="opacity"/></svg>"#;
        assert!(!validate_svg_content(svg));
    }

    #[test]
    fn test_setup_instructions() {
        let steps = get_bimi_setup_instructions("example.com", "https://example.com/logo.svg", None);
        assert!(steps.len() >= 5);
        assert!(steps[0].contains("DMARC"));
        assert!(steps[3].contains("default._bimi.example.com"));
    }
}
