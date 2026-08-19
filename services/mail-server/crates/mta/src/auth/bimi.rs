//! BIMI – Brand Indicators for Message Identification.
//!
//! Verifies BIMI DNS records, validates SVG logos, and checks VMC certificates.

use std::io::Cursor;
use std::sync::LazyLock;
use std::time::Duration;

use quick_xml::events::Event;
use quick_xml::Reader;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use trust_dns_resolver::config::{ResolverConfig, ResolverOpts};
use trust_dns_resolver::TokioAsyncResolver;
use x509_parser::prelude::*;

// #131:Shared DNS resolver – avoids creating a new resolver per verify_bimi call
static BIMI_RESOLVER: LazyLock<TokioAsyncResolver> =
    LazyLock::new(|| TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default()));

// Shared HTTP client for BIMI logo fetching.
static BIMI_CLIENT: LazyLock<Option<Client>> = LazyLock::new(|| {
    Client::builder()
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(10))
        .build()
        .ok()
});

// #128:Maximum logo download size (256 KB) to prevent OOM from malicious URLs
const MAX_LOGO_SIZE: usize = 256 * 1024;
const MAX_CERT_SIZE: usize = 512 * 1024;
const VMC_BRAND_INDICATOR_EKU_OID: &str = "1.3.6.1.5.5.7.3.31";

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
    // #131:Use shared resolver instead of creating new one per call
    let resolver = &*BIMI_RESOLVER;

    match resolver.txt_lookup(&dmarc_name).await {
        Ok(records) => {
            let has_enforcement = records.iter().any(|r| {
                let txt = r.to_string();
                txt.contains("p=reject") || txt.contains("p=quarantine")
            });
            result.dmarc_valid = has_enforcement;
            if !has_enforcement {
                result
                    .errors
                    .push("DMARC policy must be 'reject' or 'quarantine' for BIMI".into());
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
                        result
                            .warnings
                            .push("No VMC certificate URL provided".into());
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
            result
                .recommendations
                .push(format!("Add a BIMI DNS record at {bimi_name}"));
        }
    }

    if !result.dmarc_valid {
        result
            .recommendations
            .push("Set DMARC policy to 'reject' or 'quarantine'".into());
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
    let Some(client) = BIMI_CLIENT.as_ref() else {
        return false;
    };

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

            if !is_bimi_svg_content_type(content_type) {
                return false;
            }

            // #128:Check Content-Length before downloading
            if let Some(len) = resp.content_length() {
                if len > MAX_LOGO_SIZE as u64 {
                    return false;
                }
            }

            // #128:Download with size limit to prevent OOM
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

/// Allowed SVG element names (SVG Tiny PS 1.2 subset).
const ALLOWED_SVG_ELEMENTS: &[&str] = &[
    "a",
    "animate",
    "animatecolor",
    "animatemotion",
    "animatetransform",
    "circle",
    "clippath",
    "defs",
    "desc",
    "ellipse",
    "filter",
    "font",
    "font-face",
    "font-face-name",
    "font-face-src",
    "font-face-uri",
    "foreignobject",
    "g",
    "glyph",
    "glyphref",
    "hkern",
    "image",
    "line",
    "lineargradient",
    "marker",
    "mask",
    "metadata",
    "missing-glyph",
    "mpath",
    "path",
    "pattern",
    "polygon",
    "polyline",
    "radialgradient",
    "rect",
    "script",
    "set",
    "solidcolor",
    "stop",
    "style",
    "svg",
    "switch",
    "symbol",
    "text",
    "textpath",
    "title",
    "tref",
    "tspan",
    "use",
    "view",
    "vkern",
];

/// Validate SVG content for BIMI compliance (SVG Tiny PS).
/// #129:Comprehensive validation replacing fragile string matching.
/// #130:Robust external reference detection.
pub fn validate_svg_content(svg: &str) -> bool {
    let mut reader = Reader::from_str(svg);
    reader.config_mut().trim_text(true);

    let mut saw_svg_root = false;
    let mut has_svg_namespace = false;

    loop {
        match reader.read_event() {
            Ok(Event::Start(tag)) | Ok(Event::Empty(tag)) => {
                let name = String::from_utf8_lossy(tag.name().as_ref()).to_lowercase();

                // Check element is in the SVG allowlist
                if !ALLOWED_SVG_ELEMENTS.contains(&name.as_str()) {
                    return false;
                }

                if name == "svg" {
                    saw_svg_root = true;
                }

                // Reject dangerous elements even if in allowlist
                if matches!(
                    name.as_str(),
                    "script" | "foreignobject" | "animate" | "set"
                ) {
                    return false;
                }

                for attr in tag.attributes().with_checks(true) {
                    let attr = match attr {
                        Ok(a) => a,
                        Err(_) => return false,
                    };

                    let key = String::from_utf8_lossy(attr.key.as_ref()).to_lowercase();
                    let value = String::from_utf8_lossy(attr.value.as_ref()).to_lowercase();

                    // Check for SVG namespace on root element
                    if name == "svg" && key == "xmlns" && value == "http://www.w3.org/2000/svg" {
                        has_svg_namespace = true;
                    }

                    if key.starts_with("on") {
                        return false;
                    }

                    if value.contains("javascript:")
                        || value.contains("vbscript:")
                        || value.contains("data:")
                        || value.contains("expression(")
                        || value.contains("eval(")
                    {
                        return false;
                    }

                    if (key == "href" || key == "xlink:href")
                        && (value.contains("http://")
                            || value.contains("https://")
                            || value.starts_with("//"))
                    {
                        return false;
                    }
                }
            }
            Ok(Event::DocType(_)) | Ok(Event::CData(_)) => {
                return false;
            }
            Ok(Event::Eof) => break,
            Ok(_) => {}
            Err(_) => return false,
        }
    }

    saw_svg_root && has_svg_namespace
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
        steps.push(format!(
            "3. Obtain a VMC (Verified Mark Certificate) and host at {cert}"
        ));
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

fn is_bimi_svg_content_type(content_type: &str) -> bool {
    content_type
        .split(';')
        .next()
        .map(str::trim)
        .map(str::to_ascii_lowercase)
        .as_deref()
        == Some("image/svg+xml")
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

    let response = match client.get(url).send().await {
        Ok(resp) => resp,
        Err(_) => return false,
    };

    if !response.status().is_success() {
        return false;
    }

    if let Some(len) = response.content_length() {
        if len > MAX_CERT_SIZE as u64 {
            return false;
        }
    }

    let bytes = match response.bytes().await {
        Ok(b) => b,
        Err(_) => return false,
    };

    if bytes.len() > MAX_CERT_SIZE {
        return false;
    }

    let cert_chain = match parse_vmc_cert_chain(&bytes) {
        Some(chain) => chain,
        None => return false,
    };

    verify_x509_chain(&cert_chain, &pinned_vmc_ca_certs())
}

/// Parse the `VMC_CA_PEMS` environment variable: a comma-separated list of
/// PEM-encoded CA certificates that are allowed as self-signed trust anchors
/// for VMC chain validation. Empty (unset) ⇒ no self-signed roots accepted.
fn pinned_vmc_ca_certs() -> Vec<Vec<u8>> {
    let Ok(pems) = std::env::var("VMC_CA_PEMS") else {
        return Vec::new();
    };
    parse_pinned_ca_pems(&pems)
}

/// Split a raw `VMC_CA_PEMS` value into DER certificates.
fn parse_pinned_ca_pems(raw: &str) -> Vec<Vec<u8>> {
    let mut certs = Vec::new();
    for pem in raw.split(',').filter(|p| !p.trim().is_empty()) {
        let mut cursor = Cursor::new(pem.trim().as_bytes());
        for cert in rustls_pemfile::certs(&mut cursor).filter_map(Result::ok) {
            certs.push(cert.to_vec());
        }
    }
    certs
}

fn parse_vmc_cert_chain(raw: &[u8]) -> Option<Vec<Vec<u8>>> {
    let mut cursor = Cursor::new(raw);
    let mut certs = rustls_pemfile::certs(&mut cursor)
        .filter_map(Result::ok)
        .map(|cert| cert.to_vec())
        .collect::<Vec<_>>();

    if certs.is_empty() {
        certs.push(raw.to_vec());
    }

    Some(certs)
}

/// Cryptographically verify a VMC certificate chain (RFC 5280-style path
/// validation for the BIMI VMC use case):
///
/// * every certificate is parsed and its validity dates checked;
/// * the leaf carries the VMC Brand Indicator EKU;
/// * every issuer has BasicConstraints CA:TRUE and KeyUsage keyCertSign;
/// * each certificate's signature is verified with its issuer's public key;
/// * the root must be self-signed, cryptographically self-consistent, and
///   pinned in the configured trust set (`VMC_CA_PEMS`); an unpinned
///   self-signed root is rejected.
///
/// Any error (parse failure, unsupported algorithm, missing CA constraints,
/// failed signature) yields `false` — verification fails closed.
fn verify_x509_chain(chain_der: &[Vec<u8>], pinned_ca_der: &[Vec<u8>]) -> bool {
    if chain_der.is_empty() {
        return false;
    }

    let mut chain = Vec::with_capacity(chain_der.len());
    for der in chain_der {
        let parsed = match X509Certificate::from_der(der) {
            Ok((_, cert)) => cert,
            Err(_) => return false,
        };

        let now = ASN1Time::now();
        if !parsed.validity().is_valid_at(now) {
            return false;
        }

        chain.push(parsed);
    }

    let Some(leaf) = chain.first() else {
        return false;
    };
    if !certificate_has_vmc_purpose(leaf) {
        return false;
    }

    // Verify every non-root certificate: issuer name equality, issuer CA
    // constraints, and the cryptographic signature of this cert by the issuer.
    for idx in 0..(chain.len().saturating_sub(1)) {
        let cert = &chain[idx];
        let issuer = &chain[idx + 1];
        if cert.issuer() != issuer.subject() {
            return false;
        }
        if !certificate_is_ca(issuer) {
            return false;
        }
        if cert.verify_signature(Some(issuer.public_key())).is_err() {
            return false;
        }
    }

    let root = match chain.last() {
        Some(c) => c,
        None => return false,
    };

    // The trust anchor must be a self-signed certificate pinned in the
    // configurable trust set. Any other root (unpinned self-signed, or a
    // certificate whose issuer is not part of the presented chain) is
    // rejected — fail closed.
    if root.issuer() != root.subject() {
        return false;
    }
    // Self-signature consistency (RFC 5280 §3.6.2.1): the root must verify
    // against its own public key when it claims to be self-signed.
    if root.verify_signature(Some(root.public_key())).is_err() {
        return false;
    }
    pinned_ca_der
        .iter()
        .any(|pinned| pinned.as_slice() == chain_der.last().map(Vec::as_slice).unwrap_or(&[]))
}

/// BasicConstraints CA:TRUE AND KeyUsage keyCertSign (RFC 5280 §4.2.1.3/4.2.1.9).
fn certificate_is_ca(cert: &X509Certificate<'_>) -> bool {
    let mut basic_ca = false;
    let mut key_cert_sign = false;
    for extension in cert.extensions() {
        match extension.parsed_extension() {
            ParsedExtension::BasicConstraints(bc) => basic_ca = bc.ca,
            ParsedExtension::KeyUsage(ku) => key_cert_sign = ku.key_cert_sign(),
            _ => {}
        }
    }
    basic_ca && key_cert_sign
}

fn certificate_has_vmc_purpose(cert: &X509Certificate<'_>) -> bool {
    cert.extensions().iter().any(|extension| {
        if let ParsedExtension::ExtendedKeyUsage(eku) = extension.parsed_extension() {
            eku.other
                .iter()
                .any(|oid| is_vmc_brand_indicator_oid(&oid.to_id_string()))
        } else {
            false
        }
    })
}

fn is_vmc_brand_indicator_oid(oid: &str) -> bool {
    oid == VMC_BRAND_INDICATOR_EKU_OID
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
        assert_eq!(record.logo_url.unwrap(), "https://example.com/logo.svg");
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
    fn test_bimi_svg_content_type_must_be_image_svg_xml() {
        assert!(is_bimi_svg_content_type("image/svg+xml"));
        assert!(is_bimi_svg_content_type("image/svg+xml; charset=utf-8"));
        assert!(!is_bimi_svg_content_type("application/xml"));
        assert!(!is_bimi_svg_content_type("text/xml"));
        assert!(!is_bimi_svg_content_type("image/png"));
        assert!(!is_bimi_svg_content_type(""));
    }

    #[test]
    fn test_vmc_brand_indicator_oid_must_match_exactly() {
        assert!(is_vmc_brand_indicator_oid("1.3.6.1.5.5.7.3.31"));
        assert!(!is_vmc_brand_indicator_oid("1.3.6.1.5.5.7.3.1"));
        assert!(!is_vmc_brand_indicator_oid("2.5.29.37.0"));
    }

    #[test]
    fn test_setup_instructions() {
        let steps =
            get_bimi_setup_instructions("example.com", "https://example.com/logo.svg", None);
        assert!(steps.len() >= 5);
        assert!(steps[0].contains("DMARC"));
        assert!(steps[3].contains("default._bimi.example.com"));
    }

    // ── FIX-E (C5): VMC chain cryptographic verification ───────────────────

    const VMC_EKU_OID: [u64; 9] = [1, 3, 6, 1, 5, 5, 7, 3, 31];

    fn vmc_leaf_params(san: &str) -> rcgen::CertificateParams {
        let mut params = rcgen::CertificateParams::new(vec![san.to_string()]).unwrap();
        params.extended_key_usages =
            vec![rcgen::ExtendedKeyUsagePurpose::Other(VMC_EKU_OID.to_vec())];
        params
    }

    fn test_ca(san: &str) -> (rcgen::Certificate, rcgen::KeyPair) {
        let mut params = rcgen::CertificateParams::new(vec![san.to_string()]).unwrap();
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params.key_usages = vec![
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::DigitalSignature,
            rcgen::KeyUsagePurpose::CrlSign,
        ];
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = params.self_signed(&key).unwrap();
        (cert, key)
    }

    #[test]
    fn test_vmc_self_signed_chain_rejected_without_pin() {
        // (a) A self-signed chain with the VMC EKU must NOT validate unless the
        // root is pinned in the trust set.
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = vmc_leaf_params("vmc.example.com")
            .self_signed(&key)
            .unwrap();
        let chain = vec![cert.der().to_vec()];

        assert!(
            !verify_x509_chain(&chain, &[]),
            "self-signed VMC chain must be rejected when the root is not pinned"
        );
    }

    #[test]
    fn test_vmc_self_signed_chain_passes_when_pinned() {
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = vmc_leaf_params("vmc.example.com")
            .self_signed(&key)
            .unwrap();
        let der = cert.der().to_vec();

        assert!(
            verify_x509_chain(&[der.clone()], &[der]),
            "pinned self-signed root must validate"
        );
    }

    #[test]
    fn test_vmc_ca_signed_chain_passes() {
        // (b) A leaf signed by a proper CA (CA:TRUE + keyCertSign) validates.
        let (ca_cert, ca_key) = test_ca("VMC CA");
        let ca_der = ca_cert.der().to_vec();
        let leaf_key = rcgen::KeyPair::generate().unwrap();
        let leaf = vmc_leaf_params("vmc.example.com")
            .signed_by(&leaf_key, &ca_cert, &ca_key)
            .unwrap();

        let chain = vec![leaf.der().to_vec(), ca_der.clone()];
        assert!(
            verify_x509_chain(&chain, &[ca_der]),
            "CA-signed VMC chain must validate"
        );
    }

    #[test]
    fn test_vmc_non_ca_issuer_fails() {
        // (c) An issuer without CA:TRUE / keyCertSign must be rejected.
        let issuer_key = rcgen::KeyPair::generate().unwrap();
        let mut issuer_params =
            rcgen::CertificateParams::new(vec!["issuer.example.com".to_string()]).unwrap();
        issuer_params.is_ca = rcgen::IsCa::ExplicitNoCa;
        issuer_params.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature];
        let issuer = issuer_params.self_signed(&issuer_key).unwrap();

        let leaf_key = rcgen::KeyPair::generate().unwrap();
        let leaf = vmc_leaf_params("vmc.example.com")
            .signed_by(&leaf_key, &issuer, &issuer_key)
            .unwrap();

        let chain = vec![leaf.der().to_vec(), issuer.der().to_vec()];
        assert!(
            !verify_x509_chain(&chain, &[]),
            "a non-CA issuer must fail chain validation"
        );
    }

    #[test]
    fn test_vmc_tampered_leaf_fails() {
        // (d) Tampering with the leaf's signature must fail verification.
        let (ca_cert, ca_key) = test_ca("VMC CA");
        let ca_der = ca_cert.der().to_vec();
        let leaf_key = rcgen::KeyPair::generate().unwrap();
        let leaf = vmc_leaf_params("vmc.example.com")
            .signed_by(&leaf_key, &ca_cert, &ca_key)
            .unwrap();
        let leaf_der = leaf.der().to_vec();

        let (_, parsed) = X509Certificate::from_der(&leaf_der).unwrap();
        let sig_offset = parsed.signature_value.data.as_ptr() as usize - leaf_der.as_ptr() as usize;
        let mut tampered = leaf_der.clone();
        tampered[sig_offset + 3] ^= 0x01;

        let chain = vec![tampered, ca_der.clone()];
        assert!(
            !verify_x509_chain(&chain, &[ca_der]),
            "a tampered leaf must fail signature verification"
        );
    }

    #[test]
    fn test_vmc_incomplete_chain_fails() {
        // A chain whose root is not self-signed (missing trust anchor) fails closed.
        let (_ca_cert, ca_key) = test_ca("VMC CA");
        let (super_ca, super_key) = test_ca("Super CA");
        let ca_cert = {
            let mut params = rcgen::CertificateParams::new(vec!["VMC CA".to_string()]).unwrap();
            params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
            params.key_usages = vec![
                rcgen::KeyUsagePurpose::KeyCertSign,
                rcgen::KeyUsagePurpose::DigitalSignature,
            ];
            params.signed_by(&ca_key, &super_ca, &super_key).unwrap()
        };
        let leaf_key = rcgen::KeyPair::generate().unwrap();
        let leaf = vmc_leaf_params("vmc.example.com")
            .signed_by(&leaf_key, &ca_cert, &ca_key)
            .unwrap();

        // The chain stops at an intermediate — no trust anchor present.
        let chain = vec![leaf.der().to_vec(), ca_cert.der().to_vec()];
        let _ = &ca_cert;
        assert!(!verify_x509_chain(&chain, &[]));
    }

    #[test]
    fn test_parse_pinned_ca_pems() {
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = vmc_leaf_params("pin.example.com")
            .self_signed(&key)
            .unwrap();
        let pem = cert.pem();
        let parsed = parse_pinned_ca_pems(&pem);
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0], cert.der().to_vec());

        // Empty / unset-like values produce an empty trust set.
        assert!(parse_pinned_ca_pems("").is_empty());
        assert!(parse_pinned_ca_pems("  ,  ").is_empty());
    }
}
