//! BIMI – Brand Indicators for Message Identification.
//!
//! Verifies BIMI DNS records, validates SVG logos, and checks VMC certificates.
//!
//! MAINTAINED-BUT-NOT-WIRED (F-16): BIMI verification is a RECEIVER-side
//! display feature consumed by the end-user mail client, not the SMTP
//! transport; this MTA stores inbound mail for IMAP retrieval and never
//! renders brand indicators, so nothing calls into this module beyond its
//! own unit tests. The direct-MX sender / future receiver hardening tracked
//! as finding F-16 owns the decision of where verification plugs in.
//! Do not delete: tracked for the F-16 direct-MX work.

use std::io::Cursor;
use std::sync::LazyLock;
use std::time::Duration;

use quick_xml::events::Event;
use quick_xml::Reader;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use trust_dns_resolver::{Resolver, TokioResolver};
use x509_parser::prelude::*;

// #131:Shared DNS resolver – avoids creating a new resolver per verify_bimi call.
// trust-dns 0.26: TokioAsyncResolver::tokio is gone; build a TokioResolver
// (builder defaults already equal ResolverOpts::default()).
static BIMI_RESOLVER: LazyLock<TokioResolver> = LazyLock::new(|| {
    Resolver::builder_tokio()
        .expect("system resolver configuration is always buildable")
        .build()
        .expect("system resolver configuration is always buildable")
});

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

/// Verify BIMI for a domain (shared production resolver, shared logo
/// client).
pub async fn verify_bimi(domain: &str, selector: &str) -> BimiVerificationResult {
    verify_bimi_with(&BIMI_RESOLVER, BIMI_CLIENT.as_ref(), domain, selector).await
}

/// Verify BIMI for a domain against an explicit resolver and HTTP client.
/// `None` fails every fetch-dependent validation closed (the shared client
/// could not be built). Tests point both at loopback mocks; production
/// callers use [`verify_bimi`].
pub async fn verify_bimi_with(
    resolver: &TokioResolver,
    client: Option<&Client>,
    domain: &str,
    selector: &str,
) -> BimiVerificationResult {
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
    match resolver.txt_lookup(&dmarc_name).await {
        Ok(lookup) => {
            let has_enforcement = txt_record_strings(&lookup)
                .into_iter()
                .any(|txt| txt.contains("p=reject") || txt.contains("p=quarantine"));
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
        Ok(lookup) => {
            for txt in txt_record_strings(&lookup) {
                if txt.starts_with("v=BIMI1") {
                    let parsed = parse_bimi_record(&txt, selector);
                    result.supported = true;

                    // 3. Validate logo if present
                    if let Some(ref url) = parsed.logo_url {
                        result.logo_valid = match client {
                            Some(c) => validate_bimi_logo_url_with(c, url).await,
                            None => false,
                        };
                        if !result.logo_valid {
                            result.warnings.push("Logo URL failed validation".into());
                        }
                    }

                    // 4. Check VMC certificate
                    if let Some(ref cert_url) = parsed.certificate_url {
                        result.certificate_valid = match client {
                            Some(c) => validate_vmc_certificate_with(c, cert_url).await,
                            None => false,
                        };
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

/// Validate a BIMI logo URL (basic checks) with the shared production
/// client.
pub async fn validate_bimi_logo_url(url: &str) -> bool {
    // Try to fetch and validate SVG
    let Some(client) = BIMI_CLIENT.as_ref() else {
        return false;
    };
    validate_bimi_logo_url_with(client, url).await
}

/// Validate a BIMI logo URL with an explicit HTTP client (tests inject a
/// loopback-trusting client; the wire checks are identical).
pub async fn validate_bimi_logo_url_with(client: &Client, url: &str) -> bool {
    // Must be HTTPS
    if !url.starts_with("https://") {
        return false;
    }

    // Must end in .svg
    if !url.to_lowercase().ends_with(".svg") {
        return false;
    }

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

/// Get BIMI indicator for display in email clients (shared production
/// resolver and client).
pub async fn get_bimi_indicator(domain: &str, dmarc_passed: bool) -> BimiIndicator {
    get_bimi_indicator_with(&BIMI_RESOLVER, BIMI_CLIENT.as_ref(), domain, dmarc_passed).await
}

/// Indicator computation against an explicit resolver and client (tests
/// inject loopback mocks).
pub async fn get_bimi_indicator_with(
    resolver: &TokioResolver,
    client: Option<&Client>,
    domain: &str,
    dmarc_passed: bool,
) -> BimiIndicator {
    if !dmarc_passed {
        return BimiIndicator {
            logo_url: None,
            selector: "default".into(),
            verified: false,
            timestamp: chrono::Utc::now(),
        };
    }

    let result = verify_bimi_with(resolver, client, domain, "default").await;
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

/// Flatten a TXT lookup into one String per TXT record.
///
/// trust-dns 0.26 removed typed lookup iteration; `txt_lookup` now returns raw
/// records. Each record's character-string chunks are joined without a
/// separator (mirroring apexmail-dns-resolver's migrated TXT handling).
fn txt_record_strings(lookup: &trust_dns_resolver::lookup::Lookup) -> Vec<String> {
    lookup
        .answers()
        .iter()
        .filter_map(|record| match &record.data {
            trust_dns_resolver::proto::rr::RData::TXT(txt) => Some(
                txt.txt_data
                    .iter()
                    .map(|d| String::from_utf8_lossy(d).to_string())
                    .collect::<Vec<_>>()
                    .join(""),
            ),
            _ => None,
        })
        .collect()
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

/// Validate a VMC certificate URL with an explicit HTTP client (tests
/// inject a loopback-trusting client; the wire checks are identical).
async fn validate_vmc_certificate_with(client: &Client, url: &str) -> bool {
    if !url.starts_with("https://") {
        return false;
    }

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
    // An empty download is no chain at all (the caller answers false without
    // attempting to parse zero bytes as a certificate).
    if raw.is_empty() {
        return None;
    }
    let mut cursor = Cursor::new(raw);
    let mut certs = rustls_pemfile::certs(&mut cursor)
        .filter_map(Result::ok)
        .map(|cert| cert.to_vec())
        .collect::<Vec<_>>();

    if certs.is_empty() {
        // Not PEM: treat the payload as one DER certificate.
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

    pub(super) fn vmc_leaf_params(san: &str) -> rcgen::CertificateParams {
        let mut params = rcgen::CertificateParams::new(vec![san.to_string()]).unwrap();
        params.extended_key_usages =
            vec![rcgen::ExtendedKeyUsagePurpose::Other(VMC_EKU_OID.to_vec())];
        params
    }

    pub(super) fn test_ca(san: &str) -> (rcgen::Certificate, rcgen::KeyPair) {
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
            verify_x509_chain(std::slice::from_ref(&der), std::slice::from_ref(&der)),
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

#[cfg(test)]
mod adversarial_svg_tests {
    //! BIMI SVG sanitisation is a security boundary (SVG is scriptable): every
    //! dangerous construct must be refused, and only a namespaced <svg> root
    //! with allow-listed elements may pass.

    use super::*;

    const VALID: &str = r#"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100"><circle cx="50" cy="50" r="40"/></svg>"#;

    #[test]
    fn valid_bimi_svg_passes() {
        assert!(validate_svg_content(VALID));
    }

    #[test]
    fn non_svg_root_or_missing_namespace_is_refused() {
        assert!(!validate_svg_content("<html><body>hi</body></html>"));
        assert!(!validate_svg_content(r#"<svg viewBox="0 0 1 1"></svg>"#));
        assert!(!validate_svg_content(""));
        assert!(!validate_svg_content("not xml at all <"));
    }

    #[test]
    fn dangerous_elements_and_doctypes_are_refused() {
        for body in [
            r#"<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>"#,
            r#"<svg xmlns="http://www.w3.org/2000/svg"><foreignObject><body/></foreignObject></svg>"#,
            r#"<svg xmlns="http://www.w3.org/2000/svg"><animate/></svg>"#,
            r#"<svg xmlns="http://www.w3.org/2000/svg"><set/></svg>"#,
            r#"<!DOCTYPE svg [<!ENTITY x SYSTEM "file:///etc/passwd">]><svg xmlns="http://www.w3.org/2000/svg"/> "#,
        ] {
            assert!(
                !validate_svg_content(body),
                "dangerous SVG must be refused: {body}"
            );
        }
    }

    #[test]
    fn event_handlers_and_script_urls_are_refused() {
        for body in [
            r#"<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)"/>"#,
            r#"<svg xmlns="http://www.w3.org/2000/svg"><a href="javascript:alert(1)"/></svg>"#,
            r#"<svg xmlns="http://www.w3.org/2000/svg"><a xlink:href="vbscript:msgbox"/></svg>"#,
            r#"<svg xmlns="http://www.w3.org/2000/svg"><image href="data:image/png;base64,AAAA"/></svg>"#,
            r#"<svg xmlns="http://www.w3.org/2000/svg"><rect fill="expression(alert(1))"/></svg>"#,
            r#"<svg xmlns="http://www.w3.org/2000/svg"><a href="eval(1)"/></svg>"#,
        ] {
            assert!(
                !validate_svg_content(body),
                "scriptable SVG must be refused: {body}"
            );
        }
    }

    #[test]
    fn remote_references_are_refused_but_local_fragments_pass() {
        for body in [
            r#"<svg xmlns="http://www.w3.org/2000/svg"><image href="http://evil.test/x.png"/></svg>"#,
            r#"<svg xmlns="http://www.w3.org/2000/svg"><image href="https://evil.test/x.png"/></svg>"#,
            r#"<svg xmlns="http://www.w3.org/2000/svg"><image href="//evil.test/x.png"/></svg>"#,
        ] {
            assert!(
                !validate_svg_content(body),
                "remote references must be refused: {body}"
            );
        }
        // A same-document fragment is not a remote fetch.
        assert!(validate_svg_content(
            r##"<svg xmlns="http://www.w3.org/2000/svg"><use href="#local"/></svg>"##
        ));
    }

    #[tokio::test]
    async fn logo_url_must_be_https_svg_before_any_fetch() {
        // Non-HTTPS and non-SVG URLs are refused without touching the network.
        assert!(!validate_bimi_logo_url("http://cdn.example/logo.svg").await);
        assert!(!validate_bimi_logo_url("https://cdn.example/logo.png").await);
        assert!(!validate_bimi_logo_url("ftp://cdn.example/logo.svg").await);
        assert!(!validate_bimi_logo_url("").await);
    }

    #[tokio::test]
    async fn dmarc_failed_indicator_is_never_verified() {
        let indicator = get_bimi_indicator("example.com", false).await;
        assert!(!indicator.verified);
        assert!(indicator.logo_url.is_none());
    }
}

#[cfg(test)]
mod verify_bimi_wire_tests {
    //! Full `verify_bimi_with` / validator coverage against a loopback UDP
    //! DNS mock and a loopback TLS HTTP mock: the real resolver wire path,
    //! the real HTTPS fetch path, and hostile record/logo/cert payloads.

    use super::super::test_dns::{DnsAnswer, MockDns};
    use super::tests::{test_ca, vmc_leaf_params};
    use super::*;

    use std::collections::HashMap;
    use std::sync::Arc;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    static ENV_LOCK: std::sync::LazyLock<tokio::sync::Mutex<()>> =
        std::sync::LazyLock::new(|| tokio::sync::Mutex::new(()));

    const VALID_SVG: &str = "<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"64\" height=\"64\"><rect width=\"64\" height=\"64\" fill=\"blue\"/></svg>";

    /// One loopback HTTPS route: (status, content-type, body).
    type Route = (u16, &'static str, Vec<u8>);

    /// Minimal HTTPS server over tokio-rustls with the repo test fixture
    /// certificate; requests are answered from a path-keyed table.
    async fn https_server(routes: HashMap<String, Route>) -> (u16, tokio::task::JoinHandle<()>) {
        let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();
        let cert_pem = std::fs::read(format!(
            "{}/tests/fixtures/cert.pem",
            env!("CARGO_MANIFEST_DIR")
        ))
        .unwrap();
        let key_pem = std::fs::read(format!(
            "{}/tests/fixtures/key.pem",
            env!("CARGO_MANIFEST_DIR")
        ))
        .unwrap();
        let certs: Vec<_> = rustls_pemfile::certs(&mut std::io::BufReader::new(&cert_pem[..]))
            .collect::<Result<_, _>>()
            .unwrap();
        let key = rustls_pemfile::private_key(&mut std::io::BufReader::new(&key_pem[..]))
            .unwrap()
            .unwrap();
        let config = tokio_rustls::rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));

        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .unwrap();
        let port = listener.local_addr().unwrap().port();
        let routes = Arc::new(routes);
        let handle = tokio::spawn(async move {
            loop {
                let Ok((socket, _)) = listener.accept().await else {
                    return;
                };
                let Ok(mut tls) = acceptor.accept(socket).await else {
                    continue;
                };
                let routes = routes.clone();
                tokio::spawn(async move {
                    let mut buf = [0u8; 8192];
                    let n = tls.read(&mut buf).await.unwrap_or(0);
                    let head = String::from_utf8_lossy(&buf[..n]);
                    let path = head.split(' ').nth(1).unwrap_or("/").to_string();
                    let (status, ctype, body) = routes.get(&path).cloned().unwrap_or((
                        404,
                        "text/plain",
                        b"missing".to_vec(),
                    ));
                    let response = format!(
                        "HTTP/1.1 {status} X\r\ncontent-type: {ctype}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                        body.len()
                    );
                    let _ = tls.write_all(response.as_bytes()).await;
                    let _ = tls.write_all(&body).await;
                    let _ = tls.shutdown().await;
                });
            }
        });
        (port, handle)
    }

    fn trusting_client() -> reqwest::Client {
        reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .timeout(std::time::Duration::from_secs(5))
            .build()
            .unwrap()
    }

    fn txt(strings: Vec<&str>) -> DnsAnswer {
        DnsAnswer::Txt(strings.into_iter().map(|s| vec![s.to_string()]).collect())
    }

    #[tokio::test]
    async fn verify_bimi_full_success_path_over_dns_and_https() {
        let _guard = ENV_LOCK.lock().await;

        // A CA-signed VMC chain whose root is pinned via VMC_CA_PEMS.
        let (ca_cert, ca_key) = test_ca("VMC Wire CA");
        let leaf_key = rcgen::KeyPair::generate().unwrap();
        let leaf = vmc_leaf_params("brand.example")
            .signed_by(&leaf_key, &ca_cert, &ca_key)
            .unwrap();
        let mut chain_pem = String::new();
        use std::fmt::Write as _;
        let b64 = |der: &[u8]| {
            use base64::Engine as _;
            base64::engine::general_purpose::STANDARD.encode(der)
        };
        for der in [leaf.der(), ca_cert.der()] {
            let enc = b64(der);
            let _ = writeln!(chain_pem, "-----BEGIN CERTIFICATE-----");
            for chunk in enc.as_bytes().chunks(64) {
                let _ = writeln!(chain_pem, "{}", std::str::from_utf8(chunk).unwrap());
            }
            let _ = writeln!(chain_pem, "-----END CERTIFICATE-----");
        }
        let ca_pem_b64 = b64(ca_cert.der());
        let mut ca_pem = String::from("-----BEGIN CERTIFICATE-----\n");
        for chunk in ca_pem_b64.as_bytes().chunks(64) {
            ca_pem.push_str(std::str::from_utf8(chunk).unwrap());
            ca_pem.push('\n');
        }
        ca_pem.push_str("-----END CERTIFICATE-----\n");
        std::env::set_var("VMC_CA_PEMS", &ca_pem);

        let mut routes: HashMap<String, Route> = HashMap::new();
        routes.insert(
            "/logo.svg".into(),
            (200, "image/svg+xml", VALID_SVG.as_bytes().to_vec()),
        );
        routes.insert(
            "/vmc.pem".into(),
            (200, "application/x-pem-file", chain_pem.into_bytes()),
        );
        let (port, server) = https_server(routes).await;

        let bimi_txt = format!(
            "v=BIMI1; l=https://127.0.0.1:{port}/logo.svg; a=https://127.0.0.1:{port}/vmc.pem"
        );
        let mut rules: HashMap<&'static str, DnsAnswer> = HashMap::new();
        rules.insert(
            "_dmarc.brand.example",
            txt(vec!["v=DMARC1; p=reject; rua=mailto:d@brand.example"]),
        );
        rules.insert("default._bimi.brand.example", txt(vec![&bimi_txt]));
        let dns = MockDns::start(rules).await;

        let result = verify_bimi_with(
            &dns.resolver,
            Some(&trusting_client()),
            "brand.example",
            "default",
        )
        .await;
        assert!(
            result.supported,
            "errors: {:?} warnings: {:?}",
            result.errors, result.warnings
        );
        assert!(result.dmarc_valid);
        assert!(result.logo_valid, "warnings: {:?}", result.warnings);
        assert!(result.certificate_valid);
        assert!(result.errors.is_empty());
        let record = result.record.expect("record parsed");
        assert_eq!(record.version, "BIMI1");
        assert_eq!(
            record.logo_url.as_deref(),
            Some(format!("https://127.0.0.1:{port}/logo.svg").as_str())
        );

        // The display indicator composes the same guarantees.
        let indicator = get_bimi_indicator_with(
            &dns.resolver,
            Some(&trusting_client()),
            "brand.example",
            true,
        )
        .await;
        assert!(indicator.verified);
        assert!(indicator.logo_url.is_some());

        dns.stop();
        server.abort();
        std::env::remove_var("VMC_CA_PEMS");
    }

    #[tokio::test]
    async fn verify_bimi_reports_each_dns_failure_mode_exactly() {
        let _guard = ENV_LOCK.lock().await;
        std::env::remove_var("VMC_CA_PEMS");

        // DMARC NXDOMAIN + BIMI NXDOMAIN.
        let dns = MockDns::start(HashMap::new()).await;
        let result = verify_bimi_with(
            &dns.resolver,
            Some(&trusting_client()),
            "nx.example",
            "default",
        )
        .await;
        assert!(result
            .errors
            .iter()
            .any(|e| e.contains("DMARC lookup failed")));
        assert!(result
            .errors
            .iter()
            .any(|e| e.contains("BIMI DNS lookup failed")));
        assert!(
            result
                .recommendations
                .iter()
                .any(|r| r.contains("Add a BIMI DNS record at default._bimi.nx.example")),
            "{:?}",
            result.recommendations
        );
        assert!(
            result
                .recommendations
                .iter()
                .any(|r| r.contains("Set DMARC policy")),
            "{:?}",
            result.recommendations
        );
        dns.stop();

        // DMARC exists but p=none; BIMI TXT exists but is not v=BIMI1.
        let mut rules: HashMap<&'static str, DnsAnswer> = HashMap::new();
        rules.insert("_dmarc.weak.example", txt(vec!["v=DMARC1; p=none"]));
        rules.insert("default._bimi.weak.example", txt(vec!["v=spf1 -all"]));
        let dns = MockDns::start(rules).await;
        let result = verify_bimi_with(
            &dns.resolver,
            Some(&trusting_client()),
            "weak.example",
            "default",
        )
        .await;
        assert!(
            result
                .errors
                .iter()
                .any(|e| e.contains("must be 'reject' or 'quarantine'")),
            "{:?}",
            result.errors
        );
        assert!(
            result
                .errors
                .iter()
                .any(|e| e.contains("No valid BIMI record found")),
            "{:?}",
            result.errors
        );
        assert!(
            result
                .recommendations
                .iter()
                .any(|r| r.contains("v=BIMI1; l=https://example.com/logo.svg")),
            "{:?}",
            result.recommendations
        );
        assert!(!result.supported);
        dns.stop();

        // DMARC SERVFAIL must be surfaced, not silently treated as "no
        // enforcement".
        let mut rules: HashMap<&'static str, DnsAnswer> = HashMap::new();
        rules.insert("_dmarc.broken.example", DnsAnswer::Servfail);
        let dns = MockDns::start(rules).await;
        let result = verify_bimi_with(
            &dns.resolver,
            Some(&trusting_client()),
            "broken.example",
            "default",
        )
        .await;
        assert!(result
            .errors
            .iter()
            .any(|e| e.contains("DMARC lookup failed")));
        dns.stop();
    }

    #[tokio::test]
    async fn verify_bimi_handles_record_variants_and_bad_logo_urls() {
        let _guard = ENV_LOCK.lock().await;
        std::env::remove_var("VMC_CA_PEMS");

        // l= is not https / not .svg -> logo invalid + warning; no a= ->
        // "No VMC certificate URL" warning.
        let mut rules: HashMap<&'static str, DnsAnswer> = HashMap::new();
        rules.insert("_dmarc.h1.example", txt(vec!["v=DMARC1; p=quarantine"]));
        rules.insert(
            "sel._bimi.h1.example",
            txt(vec!["v=BIMI1; l=http://cleartext.example/logo.svg"]),
        );
        let dns = MockDns::start(rules).await;
        let result =
            verify_bimi_with(&dns.resolver, Some(&trusting_client()), "h1.example", "sel").await;
        assert!(result.supported);
        assert!(!result.logo_valid);
        assert!(
            result
                .warnings
                .iter()
                .any(|w| w.contains("Logo URL failed validation")),
            "{:?}",
            result.warnings
        );
        assert!(
            result
                .warnings
                .iter()
                .any(|w| w.contains("No VMC certificate URL provided")),
            "{:?}",
            result.warnings
        );
        dns.stop();

        // Unreachable cert URL fails closed without aborting verification.
        let mut rules: HashMap<&'static str, DnsAnswer> = HashMap::new();
        rules.insert("_dmarc.h2.example", txt(vec!["v=DMARC1; p=reject"]));
        rules.insert(
            "sel._bimi.h2.example",
            txt(vec!["v=BIMI1; a=https://127.0.0.1:1/vmc.pem"]),
        );
        let dns = MockDns::start(rules).await;
        let result =
            verify_bimi_with(&dns.resolver, Some(&trusting_client()), "h2.example", "sel").await;
        assert!(result.supported);
        assert!(!result.certificate_valid);
        dns.stop();

        // Multi-chunk TXT strings are joined without a separator before the
        // v=BIMI1 scan (real DNS character-string semantics).
        let mut rules: HashMap<&'static str, DnsAnswer> = HashMap::new();
        rules.insert("_dmarc.chunk.example", txt(vec!["v=DMARC1; p=reject"]));
        rules.insert(
            "sel._bimi.chunk.example",
            DnsAnswer::Txt(vec![vec![
                "v=BIMI1".to_string(),
                "; l=https://127.0.0.1:1/l.svg".to_string(),
            ]]),
        );
        let dns = MockDns::start(rules).await;
        let result = verify_bimi_with(
            &dns.resolver,
            Some(&trusting_client()),
            "chunk.example",
            "sel",
        )
        .await;
        assert!(
            result.supported,
            "chunked TXT must reassemble: {:?}",
            result.errors
        );
        assert!(result.record.expect("record").logo_url.is_some());
        dns.stop();

        // Client=None: every fetch-dependent validation fails closed while
        // the record still parses.
        let mut rules: HashMap<&'static str, DnsAnswer> = HashMap::new();
        rules.insert("_dmarc.h3.example", txt(vec!["v=DMARC1; p=reject"]));
        rules.insert(
            "sel._bimi.h3.example",
            txt(vec![
                "v=BIMI1; l=https://127.0.0.1:1/l.svg; a=https://127.0.0.1:1/c.pem",
            ]),
        );
        let dns = MockDns::start(rules).await;
        let result = verify_bimi_with(&dns.resolver, None, "h3.example", "sel").await;
        assert!(result.supported);
        assert!(!result.logo_valid);
        assert!(!result.certificate_valid);
        dns.stop();
    }

    #[tokio::test]
    async fn logo_url_validation_rejects_every_hostile_download() {
        let _guard = ENV_LOCK.lock().await;
        std::env::remove_var("VMC_CA_PEMS");
        let client = trusting_client();

        // Scheme and extension gates fire before any network I/O.
        assert!(!validate_bimi_logo_url_with(&client, "http://127.0.0.1/logo.svg").await);
        assert!(!validate_bimi_logo_url_with(&client, "https://127.0.0.1/logo.png").await);
        assert!(!validate_bimi_logo_url_with(&client, "ftp://127.0.0.1/logo.svg").await);
        // Connection refused fails closed.
        assert!(
            !validate_bimi_logo_url_with(&client, "https://127.0.0.1:1/logo.svg").await,
            "unreachable logo host must fail"
        );

        let mut routes: HashMap<String, Route> = HashMap::new();
        routes.insert(
            "/good.svg".into(),
            (200, "image/svg+xml", VALID_SVG.as_bytes().to_vec()),
        );
        routes.insert(
            "/html.svg".into(),
            (200, "text/html", VALID_SVG.as_bytes().to_vec()),
        );
        routes.insert(
            "/scripty.svg".into(),
            (
                200,
                "image/svg+xml",
                b"<svg xmlns=\"http://www.w3.org/2000/svg\"><script>alert(1)</script></svg>"
                    .to_vec(),
            ),
        );
        routes.insert("/missing.svg".into(), (404, "text/plain", b"gone".to_vec()));
        routes.insert(
            "/huge.svg".into(),
            (200, "image/svg+xml", vec![b'<'; MAX_LOGO_SIZE + 1]),
        );
        let (port, server) = https_server(routes).await;

        assert!(
            validate_bimi_logo_url_with(&client, &format!("https://127.0.0.1:{port}/good.svg"))
                .await,
            "a compliant SVG must validate"
        );
        assert!(
            !validate_bimi_logo_url_with(&client, &format!("https://127.0.0.1:{port}/html.svg"))
                .await,
            "a non-SVG content type must fail"
        );
        assert!(
            !validate_bimi_logo_url_with(&client, &format!("https://127.0.0.1:{port}/scripty.svg"))
                .await,
            "a scripted SVG must fail content validation"
        );
        assert!(
            !validate_bimi_logo_url_with(&client, &format!("https://127.0.0.1:{port}/missing.svg"))
                .await,
            "a 404 must fail"
        );
        assert!(
            !validate_bimi_logo_url_with(&client, &format!("https://127.0.0.1:{port}/huge.svg"))
                .await,
            "an oversized download must fail (content-length gate)"
        );
        server.abort();
    }

    #[tokio::test]
    async fn vmc_certificate_validation_rejects_every_hostile_download() {
        let _guard = ENV_LOCK.lock().await;
        std::env::remove_var("VMC_CA_PEMS");
        let client = trusting_client();

        assert!(!validate_vmc_certificate_with(&client, "http://127.0.0.1/vmc.pem").await);
        assert!(
            !validate_vmc_certificate_with(&client, "https://127.0.0.1:1/vmc.pem").await,
            "unreachable cert host must fail"
        );

        let (ca_cert, ca_key) = test_ca("VMC Reject CA");
        let leaf_key = rcgen::KeyPair::generate().unwrap();
        let leaf = vmc_leaf_params("reject.example")
            .signed_by(&leaf_key, &ca_cert, &ca_key)
            .unwrap();
        use base64::Engine as _;
        use std::fmt::Write as _;
        let mut chain_pem = String::new();
        for der in [leaf.der(), ca_cert.der()] {
            let _ = writeln!(chain_pem, "-----BEGIN CERTIFICATE-----");
            let enc = base64::engine::general_purpose::STANDARD.encode(der);
            for chunk in enc.as_bytes().chunks(64) {
                let _ = writeln!(chain_pem, "{}", std::str::from_utf8(chunk).unwrap());
            }
            let _ = writeln!(chain_pem, "-----END CERTIFICATE-----");
        }

        let mut routes: HashMap<String, Route> = HashMap::new();
        routes.insert(
            "/vmc.pem".into(),
            (200, "application/x-pem-file", chain_pem.into_bytes()),
        );
        routes.insert(
            "/empty.pem".into(),
            (200, "application/x-pem-file", Vec::new()),
        );
        routes.insert(
            "/garbage.pem".into(),
            (200, "application/x-pem-file", b"not a cert".to_vec()),
        );
        routes.insert("/missing.pem".into(), (404, "text/plain", b"gone".to_vec()));
        routes.insert(
            "/huge.pem".into(),
            (200, "application/x-pem-file", vec![b'x'; MAX_CERT_SIZE + 1]),
        );
        let (port, server) = https_server(routes).await;
        let base = format!("https://127.0.0.1:{port}");

        assert!(
            !validate_vmc_certificate_with(&client, &format!("{base}/vmc.pem")).await,
            "a valid chain whose root is NOT pinned must fail closed"
        );
        assert!(
            !validate_vmc_certificate_with(&client, &format!("{base}/empty.pem")).await,
            "an empty download is no chain"
        );
        assert!(
            !validate_vmc_certificate_with(&client, &format!("{base}/garbage.pem")).await,
            "garbage bytes must fail DER parsing"
        );
        assert!(
            !validate_vmc_certificate_with(&client, &format!("{base}/missing.pem")).await,
            "a 404 must fail"
        );
        assert!(
            !validate_vmc_certificate_with(&client, &format!("{base}/huge.pem")).await,
            "an oversized certificate download must fail"
        );

        // Pinning the same CA flips the valid chain to accepted.
        let mut ca_pem = String::from("-----BEGIN CERTIFICATE-----\n");
        let enc = base64::engine::general_purpose::STANDARD.encode(ca_cert.der());
        for chunk in enc.as_bytes().chunks(64) {
            ca_pem.push_str(std::str::from_utf8(chunk).unwrap());
            ca_pem.push('\n');
        }
        ca_pem.push_str("-----END CERTIFICATE-----\n");
        std::env::set_var("VMC_CA_PEMS", &ca_pem);
        assert!(
            validate_vmc_certificate_with(&client, &format!("{base}/vmc.pem")).await,
            "the pinned CA-signed chain must validate"
        );
        std::env::remove_var("VMC_CA_PEMS");
        server.abort();
    }

    #[tokio::test]
    async fn indicator_refuses_without_dmarc() {
        let _guard = ENV_LOCK.lock().await;
        std::env::remove_var("VMC_CA_PEMS");
        let dns = MockDns::start(HashMap::new()).await;
        let indicator = get_bimi_indicator_with(
            &dns.resolver,
            Some(&trusting_client()),
            "anything.example",
            false,
        )
        .await;
        assert!(!indicator.verified);
        assert_eq!(indicator.logo_url, None);
        assert_eq!(indicator.selector, "default");
        dns.stop();
    }

    #[tokio::test]
    async fn txt_record_strings_joins_chunks_without_separators() {
        let mut rules: HashMap<&'static str, DnsAnswer> = HashMap::new();
        rules.insert(
            "chunk.test",
            DnsAnswer::Txt(vec![
                vec!["v=BIMI1".to_string(), "; l=https://x/l.svg".to_string()],
                vec!["second record".to_string()],
            ]),
        );
        let dns = MockDns::start(rules).await;
        let lookup = dns.resolver.txt_lookup("chunk.test").await.expect("lookup");
        let strings = txt_record_strings(&lookup);
        assert_eq!(
            strings,
            vec![
                "v=BIMI1; l=https://x/l.svg".to_string(),
                "second record".to_string()
            ],
            "each TXT record's character-strings concatenate; records stay separate"
        );
        dns.stop();
    }
}
