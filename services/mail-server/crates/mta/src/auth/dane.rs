//! DANE – DNS‑Based Authentication of Named Entities (RFC 6698 / 7671).
//!
//! TLSA record lookup, generation, and certificate validation.

use std::sync::LazyLock;
use std::time::{Duration, Instant};

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use std::future::Future;
use moka::sync::Cache;
use x509_parser::prelude::FromDer;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha512};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use tracing::warn;

use crate::config::DnsConfig;

// #132:Multiple DoH providers for TLSA lookups – avoids single point of trust
const DOH_PROVIDERS: &[&str] = &[
    "https://cloudflare-dns.com/dns-query",
    "https://dns.google/resolve",
];

// #133:TLSA record cache with bounded capacity.
// TTL is enforced at lookup time using the config-provided value so that
// the cache respects the operator-configured tlsa_cache_ttl_secs.
// O-1.4:Changed from fixed 300s TTL to runtime-configurable staleness check.
static TLSA_CACHE: LazyLock<Cache<String, CachedTlsaRecords>> =
    LazyLock::new(|| Cache::builder().max_capacity(1_000).build());

/// Reusable HTTP client for DoH lookups.
static DOH_CLIENT: LazyLock<Option<Client>> = LazyLock::new(|| {
    Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .ok()
});

/// Cached TLSA records with a timestamp for configurable TTL enforcement.
#[derive(Clone)]
struct CachedTlsaRecords {
    records: Vec<TlsaRecord>,
    fetched_at: Instant,
}

/// Parsed TLSA record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsaRecord {
    /// 0 = PKIX-TA, 1 = PKIX-EE, 2 = DANE-TA, 3 = DANE-EE
    pub usage: u8,
    /// 0 = Full certificate, 1 = SubjectPublicKeyInfo
    pub selector: u8,
    /// 0 = Exact, 1 = SHA-256, 2 = SHA-512
    pub matching_type: u8,
    /// Hex‑encoded association data.
    pub certificate_association_data: String,
}

/// Full DANE verification result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaneVerificationResult {
    pub supported: bool,
    pub mode: DaneMode,
    pub tlsa_records: Vec<TlsaRecord>,
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
    pub recommendations: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DaneMode {
    DaneEe,
    DaneTa,
    Pkix,
    None,
}

/// Result from generating a TLSA record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaneRecordGenerationResult {
    pub record: TlsaRecord,
    pub dns_record: String,
    pub errors: Vec<String>,
    pub recommendations: Vec<String>,
}

/// Verify DANE for a domain + port using DNS‑over‑HTTPS.
/// #132:Tries multiple DoH providers with fallback. #133:Caches results.
///
/// `dns_config` controls whether DNSSEC validation is enforced (AD flag check)
/// and provides the TLSA cache TTL for staleness control.
pub async fn verify_dane(
    domain: &str,
    port: u16,
    protocol: &str,
    dns_config: &DnsConfig,
) -> DaneVerificationResult {
    verify_dane_with_fetcher(
        domain,
        port,
        protocol,
        dns_config,
        |d, p| fetch_remote_cert_chain(d, p),
    )
    .await
}

/// Same as [`verify_dane`] but with an injectable certificate-chain fetcher
/// (hermetic testing).
async fn verify_dane_with_fetcher<F, Fut>(
    domain: &str,
    port: u16,
    protocol: &str,
    dns_config: &DnsConfig,
    fetch_chain: F,
) -> DaneVerificationResult
where
    F: Fn(String, u16) -> Fut,
    Fut: Future<Output = anyhow::Result<Vec<Vec<u8>>>>,
{
    let mut result = DaneVerificationResult {
        supported: false,
        mode: DaneMode::None,
        tlsa_records: Vec::new(),
        errors: Vec::new(),
        warnings: Vec::new(),
        recommendations: Vec::new(),
    };

    let name = format!("_{port}._{protocol}.{domain}");

    // O-1.4:Check TLSA cache with configurable TTL enforcement
    let cached_records: Option<Vec<TlsaRecord>> = if let Some(cached) = TLSA_CACHE.get(&name) {
        let ttl = Duration::from_secs(dns_config.tlsa_cache_ttl_secs);
        if cached.fetched_at.elapsed() < ttl {
            Some(cached.records.clone())
        } else {
            // Stale entry — evict and re-fetch
            TLSA_CACHE.invalidate(name.as_str());
            None
        }
    } else {
        None
    };

    if let Some(records) = cached_records {
        // #E-006: A cache hit is NOT a validation result. The live certificate
        // must be fetched and matched against the cached TLSA records again —
        // a stale record set must never flip `supported` to true on its own.
        return match fetch_chain(domain.to_string(), port).await {
            Ok(chain) => evaluate_tlsa_records(&chain, &records, domain),
            Err(e) => {
                result.warnings.push(format!(
                    "Could not fetch target TLS certificate for DANE validation: {e}"
                ));
                result.tlsa_records = records;
                result.recommendations.push(
                    "TLSA cache entry could not be re-validated against the live certificate"
                        .into(),
                );
                result
            }
        };
    }

    let Some(client) = DOH_CLIENT.as_ref() else {
        result.errors.push("DoH HTTP client unavailable".into());
        result
            .recommendations
            .push("Ensure DANE client configuration is valid".into());
        return result;
    };

    // #132:Try multiple DoH providers with fallback
    let mut doh_body: Option<serde_json::Value> = None;
    for provider in DOH_PROVIDERS {
        let doh_url = format!("{provider}?name={name}&type=TLSA");

        let resp = match client
            .get(&doh_url)
            .header("Accept", "application/dns-json")
            .send()
            .await
        {
            Ok(r) => r,
            Err(e) => {
                warn!(provider, error = %e, "DoH request failed, trying next");
                continue;
            }
        };

        if !resp.status().is_success() {
            warn!(provider, status = %resp.status(), "DoH provider returned HTTP error, trying next");
            continue;
        }

        match resp.json::<serde_json::Value>().await {
            Ok(v) => {
                if doh_response_should_try_next(&v) {
                    warn!(provider, status = ?v.get("Status"), "DoH provider returned transient DNS status, trying next");
                    continue;
                }
                doh_body = Some(v);
                break;
            }
            Err(e) => {
                warn!(provider, error = %e, "DoH parse failed, trying next");
                continue;
            }
        }
    }

    let body = match doh_body {
        Some(b) => b,
        None => {
            result
                .errors
                .push("All DoH providers failed for TLSA lookup".into());
            result
                .recommendations
                .push("Ensure DANE TLSA records are published".into());
            return result;
        }
    };

    // Check AD flag (DNSSEC authenticated) — only enforced when dnssec_enabled is true
    if dns_config.dnssec_enabled {
        let ad = body.get("AD").and_then(|v| v.as_bool()).unwrap_or(false);
        if !ad {
            result
                .errors
                .push("DNSSEC validation not confirmed (AD flag not set)".into());
            result.recommendations.push(
                "Enable DNSSEC and ensure validated resolver sets AD for TLSA lookups".into(),
            );
            return result;
        }
    }

    // Parse TLSA answers, keeping only records with known usage/selector/matching-type.
    // Unknown values are ignored (RFC 7671 §3): they must never set supported=true.
    let mut records = Vec::new();
    if let Some(answers) = body.get("Answer").and_then(|v| v.as_array()) {
        for answer in answers {
            let rtype = answer.get("type").and_then(|v| v.as_u64()).unwrap_or(0);
            if rtype != 52 {
                // 52 = TLSA
                continue;
            }
            if let Some(data) = answer.get("data").and_then(|v| v.as_str()) {
                if let Some(record) = parse_tlsa_data(data) {
                    if record.usage <= 3 && record.selector <= 1 && record.matching_type <= 2 {
                        records.push(record);
                    }
                }
            }
        }
    }

    if records.is_empty() {
        result
            .recommendations
            .push(format!("Add TLSA record at {name} for DANE support"));
        TLSA_CACHE.insert(
            name,
            CachedTlsaRecords {
                records: Vec::new(),
                fetched_at: Instant::now(),
            },
        );
        return result;
    }

    // #E-006: Fetch the live certificate chain and evaluate the records
    // against it — supported=true only when a record actually matches.
    match fetch_chain(domain.to_string(), port).await {
        Ok(chain) => {
            result = evaluate_tlsa_records(&chain, &records, domain);
        }
        Err(e) => {
            result.warnings.push(format!(
                "Could not fetch target TLS certificate for DANE validation: {e}"
            ));
            result.tlsa_records = records.clone();
        }
    }

    // O-1.4:Cache the records with a timestamp for configurable TTL enforcement
    TLSA_CACHE.insert(
        name,
        CachedTlsaRecords {
            records,
            fetched_at: Instant::now(),
        },
    );

    result
}

/// Evaluate a set of TLSA records against a live certificate chain.
/// Records with unknown usage/selector/matching-type are ignored and never
/// set `supported`; `supported` requires at least one record to match.
fn evaluate_tlsa_records(chain: &[Vec<u8>], records: &[TlsaRecord], domain: &str) -> DaneVerificationResult {
    let mut result = DaneVerificationResult {
        supported: false,
        mode: DaneMode::None,
        tlsa_records: Vec::new(),
        errors: Vec::new(),
        warnings: Vec::new(),
        recommendations: Vec::new(),
    };

    for record in records {
        if record.usage > 3 || record.selector > 1 || record.matching_type > 2 {
            continue;
        }
        result.tlsa_records.push(record.clone());
        match record.usage {
            3 => {
                if result.mode != DaneMode::DaneTa {
                    result.mode = DaneMode::DaneEe;
                }
            }
            2 => result.mode = DaneMode::DaneTa,
            0 | 1 => {
                if result.mode == DaneMode::None {
                    result.mode = DaneMode::Pkix;
                }
            }
            _ => {}
        }
    }

    if result.tlsa_records.is_empty() {
        result
            .recommendations
            .push("No usable TLSA records (unknown usage/selector/matching-type)".into());
        return result;
    }

    let matches_tlsa = result
        .tlsa_records
        .iter()
        .any(|record| validate_chain_against_tlsa(chain, record, domain));
    if !matches_tlsa {
        result
            .errors
            .push("TLSA records do not match the target server certificate".into());
    } else {
        result.supported = true;
    }
    result
}

/// Generate a TLSA record from a PEM‑encoded certificate.
pub fn generate_tlsa_record(
    cert_pem: &str,
    domain: &str,
    port: u16,
    protocol: &str,
    usage: u8,
    selector: u8,
    matching_type: u8,
) -> DaneRecordGenerationResult {
    let mut errors = Vec::new();
    let mut recommendations = Vec::new();

    // Extract DER from PEM
    let der = match extract_der_from_pem(cert_pem) {
        Some(d) => d,
        None => {
            errors.push("Failed to parse PEM certificate".into());
            return DaneRecordGenerationResult {
                record: TlsaRecord {
                    usage,
                    selector,
                    matching_type,
                    certificate_association_data: String::new(),
                },
                dns_record: String::new(),
                errors,
                recommendations,
            };
        }
    };

    // Compute association data honouring the selector (RFC 6698 §2.1):
    // selector 0 = full certificate DER, selector 1 = SubjectPublicKeyInfo.
    let data = match (selector, matching_type) {
        (0, _) => Ok(der),
        (1, _) => x509_parser::prelude::X509Certificate::from_der(&der)
            .map(|(_, cert)| cert.public_key().raw.to_vec())
            .map_err(|e| format!("Failed to parse certificate for SPKI extraction: {e}")),
        _ => Err(format!("Unsupported selector: {selector}")),
    };

    let data = match data {
        Ok(d) => d,
        Err(e) => {
            errors.push(e);
            return DaneRecordGenerationResult {
                record: TlsaRecord {
                    usage,
                    selector,
                    matching_type,
                    certificate_association_data: String::new(),
                },
                dns_record: String::new(),
                errors,
                recommendations,
            };
        }
    };

    // Compute association data
    let data = match matching_type {
        0 => hex::encode(&data),
        1 => {
            let hash = Sha256::digest(&data);
            hex::encode(hash)
        }
        2 => {
            let hash = Sha512::digest(&data);
            hex::encode(hash)
        }
        _ => {
            errors.push(format!("Unsupported matching type: {matching_type}"));
            String::new()
        }
    };

    let name = format!("_{port}._{protocol}.{domain}");
    let dns_record = format!("{name} IN TLSA {usage} {selector} {matching_type} {data}");

    if usage > 3 {
        errors.push(format!("Unsupported usage: {usage}"));
    } else if usage == 3 {
        recommendations
            .push("DANE-EE (usage=3) requires DNSSEC to be enabled on the domain".into());
    }

    DaneRecordGenerationResult {
        record: TlsaRecord {
            usage,
            selector,
            matching_type,
            certificate_association_data: data,
        },
        dns_record,
        errors,
        recommendations,
    }
}

/// Validate a certificate (DER) against a TLSA record.
///
/// `record.usage` is honoured (RFC 7671): DANE-EE (3) only requires the digest
/// match; DANE-TA (2) additionally requires the certificate to anchor a valid
/// signature chain; PKIX-TA/PKIX-EE (0/1) additionally require full PKIX
/// validation, which cannot be performed without a chain and server name, so
/// single-certificate validation always fails closed for usages 0/1.
pub fn validate_certificate_against_tlsa(cert_der: &[u8], record: &TlsaRecord) -> bool {
    validate_chain_against_tlsa(&[cert_der.to_vec()], record, "")
}

/// Validate a certificate chain (leaf first) against a TLSA record
/// (RFC 6698 selectors/usage, RFC 7671 §3).
pub fn validate_chain_against_tlsa(chain: &[Vec<u8>], record: &TlsaRecord, domain: &str) -> bool {
    if chain.is_empty() {
        return false;
    }
    // Unknown usage/selector/matching-type values must not match anything.
    if record.usage > 3 || record.selector > 1 || record.matching_type > 2 {
        return false;
    }
    match record.usage {
        // DANE-EE: association data matches the leaf certificate.
        3 => cert_matches(&chain[0], record),
        // DANE-TA: a chain certificate matches AND the leaf chains to it.
        2 => match chain.iter().position(|der| cert_matches(der, record)) {
            Some(anchor_idx) => chain_signatures_valid(chain, anchor_idx),
            None => false,
        },
        // PKIX-EE: leaf matches AND the chain validates against public roots.
        1 => pkix_chain_valid(chain, domain) && cert_matches(&chain[0], record),
        // PKIX-TA: a chain certificate matches AND the chain validates.
        0 => pkix_chain_valid(chain, domain) && chain.iter().any(|der| cert_matches(der, record)),
        _ => false,
    }
}

/// Compute the association data for a certificate according to the TLSA
/// selector/matching-type and compare it (case-insensitively) with the record.
fn cert_matches(cert_der: &[u8], record: &TlsaRecord) -> bool {
    let data: Vec<u8> = match record.selector {
        // Selector 0: the full certificate DER.
        0 => cert_der.to_vec(),
        // Selector 1: the SubjectPublicKeyInfo DER (RFC 6698 §2.1.2).
        1 => {
            let Ok((_, cert)) = x509_parser::prelude::X509Certificate::from_der(cert_der) else {
                return false;
            };
            cert.public_key().raw.to_vec()
        }
        _ => return false,
    };
    let computed = match record.matching_type {
        0 => hex::encode(data),
        1 => hex::encode(Sha256::digest(&data)),
        2 => hex::encode(Sha512::digest(&data)),
        _ => return false,
    };
    computed.eq_ignore_ascii_case(&record.certificate_association_data)
}

/// Verify the cryptographic signature of each certificate up to the anchor.
fn chain_signatures_valid(chain_der: &[Vec<u8>], anchor_idx: usize) -> bool {
    let mut chain = Vec::with_capacity(chain_der.len());
    for der in chain_der {
        let Ok((_, cert)) = x509_parser::prelude::X509Certificate::from_der(der) else {
            return false;
        };
        chain.push(cert);
    }
    for i in 0..anchor_idx {
        let issuer_key = chain[i + 1].public_key();
        if chain[i].verify_signature(Some(issuer_key)).is_err() {
            return false;
        }
    }
    true
}

/// Full PKIX chain validation against the bundled public roots (webpki-roots).
fn pkix_chain_valid(chain_der: &[Vec<u8>], domain: &str) -> bool {
    use rustls::client::danger::ServerCertVerifier;
    use rustls::pki_types::{CertificateDer, ServerName, UnixTime};

    let Some(leaf) = chain_der.first() else {
        return false;
    };
    let Ok(server_name) = ServerName::try_from(domain.to_string()) else {
        return false;
    };

    let mut root_store = rustls::RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let Ok(verifier) = rustls::client::WebPkiServerVerifier::builder(std::sync::Arc::new(root_store))
        .build()
    else {
        return false;
    };

    let end_entity = CertificateDer::from(leaf.clone());
    let intermediates: Vec<CertificateDer> = chain_der[1..]
        .iter()
        .map(|der| CertificateDer::from(der.clone()))
        .collect();

    verifier
        .verify_server_cert(&end_entity, &intermediates, &server_name, &[], UnixTime::now())
        .is_ok()
}

/// Describe a TLSA record in human‑readable form.
pub fn describe_tlsa_record(record: &TlsaRecord) -> String {
    let usage_str = match record.usage {
        0 => "PKIX-TA (CA constraint)",
        1 => "PKIX-EE (Service certificate constraint)",
        2 => "DANE-TA (Trust anchor assertion)",
        3 => "DANE-EE (Domain-issued certificate)",
        _ => "Unknown usage",
    };
    let selector_str = match record.selector {
        0 => "Full certificate",
        1 => "SubjectPublicKeyInfo",
        _ => "Unknown selector",
    };
    let matching_str = match record.matching_type {
        0 => "Exact match",
        1 => "SHA-256",
        2 => "SHA-512",
        _ => "Unknown matching type",
    };
    format!(
        "Usage: {usage_str} ({u}), Selector: {selector_str} ({s}), Matching: {matching_str} ({m}), Data: {d:.32}...",
        u = record.usage,
        s = record.selector,
        m = record.matching_type,
        d = record.certificate_association_data,
    )
}

// ── internal ───────────────────────────────────────────────────────────────────

fn parse_tlsa_data(data: &str) -> Option<TlsaRecord> {
    let parts: Vec<&str> = data.splitn(4, ' ').collect();
    if parts.len() < 4 {
        return None;
    }
    Some(TlsaRecord {
        usage: parts[0].parse().ok()?,
        selector: parts[1].parse().ok()?,
        matching_type: parts[2].parse().ok()?,
        certificate_association_data: parts[3].replace(' ', ""),
    })
}

fn doh_response_should_try_next(body: &serde_json::Value) -> bool {
    match body.get("Status").and_then(|value| value.as_u64()) {
        Some(0) | Some(3) | None => false,
        Some(_) => true,
    }
}

fn extract_der_from_pem(pem: &str) -> Option<Vec<u8>> {
    let mut inside_certificate = false;
    let mut found_end = false;
    let mut b64 = String::new();

    for line in pem.lines() {
        let trimmed = line.trim();

        if trimmed == "-----BEGIN CERTIFICATE-----" {
            inside_certificate = true;
            continue;
        }

        if trimmed == "-----END CERTIFICATE-----" {
            found_end = true;
            break;
        }

        if inside_certificate {
            b64.push_str(trimmed);
        }
    }

    if !inside_certificate || !found_end || b64.is_empty() {
        return None;
    }

    B64.decode(&b64).ok()
}

/// Fetch the full peer certificate chain (leaf first) over TLS.
async fn fetch_remote_cert_chain(domain: String, port: u16) -> anyhow::Result<Vec<Vec<u8>>> {
    let addr = format!("{domain}:{port}");
    let tcp = timeout(Duration::from_secs(10), TcpStream::connect(&addr))
        .await
        .map_err(|_| anyhow::anyhow!("TCP connect timeout to {addr}"))??;

    let mut root_store = tokio_rustls::rustls::RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let config = tokio_rustls::rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    let connector = TlsConnector::from(std::sync::Arc::new(config));

    let server_name = tokio_rustls::rustls::pki_types::ServerName::try_from(domain.to_string())
        .map_err(|e| anyhow::anyhow!("Invalid TLS server name {domain}: {e}"))?;

    let tls_stream = timeout(Duration::from_secs(10), connector.connect(server_name, tcp))
        .await
        .map_err(|_| anyhow::anyhow!("TLS handshake timeout to {addr}"))??;

    let (_, conn) = tls_stream.get_ref();
    let certs = conn
        .peer_certificates()
        .ok_or_else(|| anyhow::anyhow!("No peer certificates from {addr}"))?;

    Ok(certs.iter().map(|c| c.to_vec()).collect())
}

// ── tests ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use x509_parser::prelude::FromDer;

    fn test_cert_pem(san: &str) -> String {
        let params = rcgen::CertificateParams::new(vec![san.to_string()]).unwrap();
        let key_pair = rcgen::KeyPair::generate().unwrap();
        let cert = params.self_signed(&key_pair).unwrap();
        cert.pem()
    }

    #[test]
    fn test_parse_tlsa_data() {
        let data = "3 1 1 abc123def456";
        let record = parse_tlsa_data(data).unwrap();
        assert_eq!(record.usage, 3);
        assert_eq!(record.selector, 1);
        assert_eq!(record.matching_type, 1);
        assert_eq!(record.certificate_association_data, "abc123def456");
    }

    #[test]
    fn test_generate_tlsa_record_sha256() {
        let pem = test_cert_pem("example.com");
        let result = generate_tlsa_record(&pem, "example.com", 25, "tcp", 3, 1, 1);
        assert!(result.errors.is_empty(), "errors: {:?}", result.errors);
        assert!(!result.record.certificate_association_data.is_empty());
        assert!(result.dns_record.contains("_25._tcp.example.com"));
        assert!(result.dns_record.contains("IN TLSA 3 1 1"));
    }

    #[test]
    fn test_validate_certificate_against_tlsa() {
        let cert_der = b"test certificate data";
        let hash = hex::encode(Sha256::digest(cert_der));
        let record = TlsaRecord {
            usage: 3,
            selector: 0,
            matching_type: 1,
            certificate_association_data: hash,
        };
        assert!(validate_certificate_against_tlsa(cert_der, &record));
    }

    #[test]
    fn test_describe_tlsa_record() {
        let record = TlsaRecord {
            usage: 3,
            selector: 1,
            matching_type: 1,
            certificate_association_data: "abc123".into(),
        };
        let desc = describe_tlsa_record(&record);
        assert!(desc.contains("DANE-EE"));
        assert!(desc.contains("SHA-256"));
    }

    #[test]
    fn test_extract_der_from_pem() {
        let pem = " -----BEGIN CERTIFICATE-----\nYWJj\n-----END CERTIFICATE-----";
        let der = extract_der_from_pem(pem).unwrap();
        assert_eq!(der, b"abc");
    }

    #[test]
    fn test_doh_response_fallback_only_for_transient_dns_status() {
        assert!(!doh_response_should_try_next(
            &serde_json::json!({ "Status": 0 })
        ));
        assert!(!doh_response_should_try_next(
            &serde_json::json!({ "Status": 3 })
        ));
        assert!(!doh_response_should_try_next(&serde_json::json!({})));
        assert!(doh_response_should_try_next(
            &serde_json::json!({ "Status": 2 })
        ));
        assert!(doh_response_should_try_next(
            &serde_json::json!({ "Status": 5 })
        ));
    }

    // ── FIX-D (H13): selector/usage/matching-type handling ─────────────────

    #[test]
    fn test_generate_tlsa_selector1_hashes_spki_not_full_der() {
        let pem = test_cert_pem("example.com");
        let der = extract_der_from_pem(&pem).unwrap();
        let (_, cert) = x509_parser::prelude::X509Certificate::from_der(&der).unwrap();
        let expected = hex::encode(Sha256::digest(cert.public_key().raw));

        let result = generate_tlsa_record(&pem, "example.com", 25, "tcp", 3, 1, 1);
        assert!(
            result.errors.is_empty(),
            "errors: {:?}",
            result.errors
        );
        assert_eq!(
            result.record.certificate_association_data, expected,
            "selector=1 must hash the SubjectPublicKeyInfo, not the full certificate"
        );
        assert_ne!(
            result.record.certificate_association_data,
            hex::encode(Sha256::digest(&der)),
            "selector=1 must NOT be the full-certificate hash"
        );
    }

    #[test]
    fn test_tlsa_selector1_record_matches_cert() {
        let pem = test_cert_pem("example.com");
        let der = extract_der_from_pem(&pem).unwrap();
        let result = generate_tlsa_record(&pem, "example.com", 25, "tcp", 3, 1, 1);
        assert!(validate_certificate_against_tlsa(&der, &result.record));
        // The SPKI-derived record must not match when hashing the full DER.
        assert_ne!(
            result.record.certificate_association_data,
            hex::encode(Sha256::digest(&der))
        );
    }

    #[test]
    fn test_tlsa_tampered_cert_fails() {
        let pem = test_cert_pem("example.com");
        let der = extract_der_from_pem(&pem).unwrap();
        let result = generate_tlsa_record(&pem, "example.com", 25, "tcp", 3, 1, 1);
        // Flip one byte INSIDE the SubjectPublicKeyInfo key material.
        let (_, cert) = x509_parser::prelude::X509Certificate::from_der(&der).unwrap();
        let spki_offset = cert.public_key().raw.as_ptr() as usize - der.as_ptr() as usize;
        let mut tampered = der.clone();
        tampered[spki_offset + 8] ^= 0x01;
        assert_ne!(tampered, der);
        assert!(!validate_certificate_against_tlsa(&tampered, &result.record));
    }

    #[test]
    fn test_tlsa_usage1_cert_not_chainable_fails() {
        // usage=1 (PKIX-EE): a self-signed cert not chainable to a public
        // trust store must fail even though the digest matches.
        let pem = test_cert_pem("example.com");
        let der = extract_der_from_pem(&pem).unwrap();
        let result = generate_tlsa_record(&pem, "example.com", 25, "tcp", 1, 0, 1);
        assert!(
            !validate_certificate_against_tlsa(&der, &result.record),
            "usage=1 must require PKIX chain validation"
        );
    }

    #[test]
    fn test_tlsa_unknown_usage_255_not_supported() {
        let pem = test_cert_pem("example.com");
        let der = extract_der_from_pem(&pem).unwrap();
        let record = TlsaRecord {
            usage: 255,
            selector: 0,
            matching_type: 1,
            certificate_association_data: hex::encode(Sha256::digest(&der)),
        };
        assert!(
            !validate_certificate_against_tlsa(&der, &record),
            "unknown usage must not be treated as supported"
        );
    }

    #[test]
    fn test_tlsa_dane_ta_matches_ca_signed_chain() {
        // DANE-TA (usage=2): leaf chained to a matching anchor certificate.
        let ca_params = rcgen::CertificateParams::new(vec!["ca.example.com".to_string()]).unwrap();
        let mut ca_params = ca_params;
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::DigitalSignature,
        ];
        let ca_key = rcgen::KeyPair::generate().unwrap();
        let ca_cert = ca_params.self_signed(&ca_key).unwrap();
        let ca_pem = ca_cert.pem();

        let leaf_params =
            rcgen::CertificateParams::new(vec!["mail.example.com".to_string()]).unwrap();
        let leaf_key = rcgen::KeyPair::generate().unwrap();
        let leaf_cert = leaf_params.signed_by(&leaf_key, &ca_cert, &ca_key).unwrap();

        let chain = vec![leaf_cert.der().to_vec(), ca_cert.der().to_vec()];

        // Anchor = CA cert, usage 2, selector 0, matching SHA-256.
        let ca_der = ca_cert.der().to_vec();
        let record = TlsaRecord {
            usage: 2,
            selector: 0,
            matching_type: 1,
            certificate_association_data: hex::encode(Sha256::digest(&ca_der)),
        };
        assert!(validate_chain_against_tlsa(&chain, &record, "mail.example.com"));

        // A record matching an unrelated cert must fail.
        let other_pem = test_cert_pem("other.example.com");
        let other_der = extract_der_from_pem(&other_pem).unwrap();
        let unrelated = TlsaRecord {
            usage: 2,
            selector: 0,
            matching_type: 1,
            certificate_association_data: hex::encode(Sha256::digest(&other_der)),
        };
        assert!(!validate_chain_against_tlsa(&chain, &unrelated, "mail.example.com"));

        // generation from the CA PEM must produce a matching record
        let generated = generate_tlsa_record(&ca_pem, "example.com", 25, "tcp", 2, 0, 1);
        assert!(
            generated.errors.is_empty(),
            "errors: {:?}",
            generated.errors
        );
        assert!(validate_chain_against_tlsa(
            &chain,
            &generated.record,
            "mail.example.com"
        ));
    }

    #[test]
    fn test_tlsa_unknown_selector_and_matching_type_not_supported() {
        let pem = test_cert_pem("example.com");
        let der = extract_der_from_pem(&pem).unwrap();
        let record = TlsaRecord {
            usage: 3,
            selector: 9,
            matching_type: 1,
            certificate_association_data: hex::encode(Sha256::digest(&der)),
        };
        assert!(!validate_certificate_against_tlsa(&der, &record));
        let record = TlsaRecord {
            usage: 3,
            selector: 0,
            matching_type: 9,
            certificate_association_data: hex::encode(Sha256::digest(&der)),
        };
        assert!(!validate_certificate_against_tlsa(&der, &record));
    }

    // ── FIX-D (H13c): cache hit must re-validate the live certificate ──────

    #[tokio::test]
    async fn test_dane_cache_hit_does_not_report_supported_without_match() {
        let cert_a = test_cert_pem("example.com");
        let _der_a = extract_der_from_pem(&cert_a).unwrap();
        let der_b = extract_der_from_pem(&test_cert_pem("other.example")).unwrap();

        let record = generate_tlsa_record(&cert_a, "example.com", 25, "tcp", 3, 1, 1).record;
        let name = "_25._tcp.example.com";
        TLSA_CACHE.insert(
            name.to_string(),
            CachedTlsaRecords {
                records: vec![record],
                fetched_at: Instant::now(),
            },
        );

        let config = DnsConfig {
            dnssec_enabled: false,
            tlsa_cache_ttl_secs: 300,
        };

        // A fresh cache entry exists, but the live certificate (returned by
        // the fetcher) does NOT match the cached TLSA records. The cache hit
        // must NOT report supported.
        let result = verify_dane_with_fetcher(
            "example.com",
            25,
            "tcp",
            &config,
            move |_d: String, _p: u16| {
                let der = der_b.clone();
                async move { Ok(vec![der]) }
            },
        )
        .await;
        assert!(
            !result.supported,
            "cache hit must re-validate the live certificate; got supported={}",
            result.supported
        );

        // Clean up the static cache for other tests.
        TLSA_CACHE.invalidate(name);
    }

    #[tokio::test]
    async fn test_dane_cache_hit_still_passes_when_cert_matches() {
        let cert_a = test_cert_pem("example.com");
        let der_a = extract_der_from_pem(&cert_a).unwrap();
        let _ = &der_a;
        let record = generate_tlsa_record(&cert_a, "example.com", 25, "tcp", 3, 1, 1).record;
        let name = "_25._tcp.matching.example.com";
        TLSA_CACHE.insert(
            name.to_string(),
            CachedTlsaRecords {
                records: vec![record],
                fetched_at: Instant::now(),
            },
        );

        let config = DnsConfig {
            dnssec_enabled: false,
            tlsa_cache_ttl_secs: 300,
        };
        let result = verify_dane_with_fetcher(
            "matching.example.com",
            25,
            "tcp",
            &config,
            move |_d: String, _p: u16| {
                let der = der_a.clone();
                async move { Ok(vec![der]) }
            },
        )
        .await;
        assert!(result.supported, "matching live cert must still pass on cache hits");
        TLSA_CACHE.invalidate(name);
    }
}
