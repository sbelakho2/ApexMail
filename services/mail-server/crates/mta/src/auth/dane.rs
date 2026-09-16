//! DANE – DNS‑Based Authentication of Named Entities (RFC 6698 / 7671).
//!
//! TLSA record lookup, generation, and certificate validation.
//!
//! MAINTAINED-BUT-NOT-WIRED (F-16): no SMTP session path performs
//! TLSA-validated outbound connections yet — DANE applies when the direct-MX
//! sender (tracked as finding F-16) opens TLS to a peer MX and must verify
//! its certificate against the TLSA RRset instead of a WebPKI CA. This
//! module is exercised only by its own unit tests until that sender lands.
//! Do not delete: the direct-MX sender (see F-16) builds on this code.

use std::sync::LazyLock;
use std::time::{Duration, Instant};

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use moka::sync::Cache;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha512};
use std::future::Future;
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use tracing::warn;
use x509_parser::prelude::FromDer;

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
    verify_dane_full(
        domain,
        port,
        protocol,
        dns_config,
        DOH_PROVIDERS,
        DOH_CLIENT.as_ref(),
        fetch_remote_cert_chain,
    )
    .await
}

/// Same as [`verify_dane`] but with an injectable certificate-chain fetcher
/// (hermetic testing; production DoH endpoints and client).
#[cfg(test)]
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
    verify_dane_full(
        domain,
        port,
        protocol,
        dns_config,
        DOH_PROVIDERS,
        DOH_CLIENT.as_ref(),
        fetch_chain,
    )
    .await
}

/// Full DANE verification with every network touchpoint injected: the DoH
/// endpoint list, the HTTP client, and the certificate-chain fetcher.
/// Tests point all of them at loopback mocks; production callers use
/// [`verify_dane`] / [`verify_dane_with_fetcher`].
async fn verify_dane_full<F, Fut>(
    domain: &str,
    port: u16,
    protocol: &str,
    dns_config: &DnsConfig,
    doh_providers: &[&str],
    doh_client: Option<&Client>,
    mut fetch_chain: F,
) -> DaneVerificationResult
where
    F: FnMut(String, u16) -> Fut,
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

    let Some(client) = doh_client else {
        result.errors.push("DoH HTTP client unavailable".into());
        result
            .recommendations
            .push("Ensure DANE client configuration is valid".into());
        return result;
    };

    // #132:Try multiple DoH providers with fallback
    let mut doh_body: Option<serde_json::Value> = None;
    for provider in doh_providers {
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
fn evaluate_tlsa_records(
    chain: &[Vec<u8>],
    records: &[TlsaRecord],
    domain: &str,
) -> DaneVerificationResult {
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
            0 | 1 if result.mode == DaneMode::None => {
                result.mode = DaneMode::Pkix;
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

    let Ok(verifier) =
        rustls::client::WebPkiServerVerifier::builder(std::sync::Arc::new(root_store)).build()
    else {
        return false;
    };

    let end_entity = CertificateDer::from(leaf.clone());
    let intermediates: Vec<CertificateDer> = chain_der[1..]
        .iter()
        .map(|der| CertificateDer::from(der.clone()))
        .collect();

    verifier
        .verify_server_cert(
            &end_entity,
            &intermediates,
            &server_name,
            &[],
            UnixTime::now(),
        )
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

/// Fetch the full peer certificate chain (leaf first) over TLS, validated
/// against the bundled WebPKI roots.
async fn fetch_remote_cert_chain(domain: String, port: u16) -> anyhow::Result<Vec<Vec<u8>>> {
    let mut root_store = tokio_rustls::rustls::RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    fetch_remote_cert_chain_with_roots(domain, port, root_store).await
}

/// Fetch the peer certificate chain validated against an explicit trust
/// store (tests pin a loopback CA; production uses the WebPKI roots).
async fn fetch_remote_cert_chain_with_roots(
    domain: String,
    port: u16,
    root_store: tokio_rustls::rustls::RootCertStore,
) -> anyhow::Result<Vec<Vec<u8>>> {
    fetch_remote_cert_chain_with_timeouts(
        domain,
        port,
        root_store,
        Duration::from_secs(10),
        Duration::from_secs(10),
    )
    .await
}

/// The fetch with explicit deadlines (production uses the 10s defaults;
/// tests inject short ones to drive the timeout arms deterministically).
async fn fetch_remote_cert_chain_with_timeouts(
    domain: String,
    port: u16,
    root_store: tokio_rustls::rustls::RootCertStore,
    connect_timeout: Duration,
    handshake_timeout: Duration,
) -> anyhow::Result<Vec<Vec<u8>>> {
    // Validate the peer name BEFORE opening the connection: a peer that
    // cannot be named (invalid DNS name / IP literal) can never be
    // authenticated, so there is no point connecting first.
    let server_name = tokio_rustls::rustls::pki_types::ServerName::try_from(domain.to_string())
        .map_err(|e| anyhow::anyhow!("Invalid TLS server name {domain}: {e}"))?;
    let addr = format!("{domain}:{port}");
    let tcp = timeout(connect_timeout, TcpStream::connect(&addr))
        .await
        .map_err(|_| anyhow::anyhow!("TCP connect timeout to {addr}"))??;

    let config = tokio_rustls::rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    let connector = TlsConnector::from(std::sync::Arc::new(config));

    let tls_stream = timeout(handshake_timeout, connector.connect(server_name, tcp))
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

    pub(super) fn test_cert_pem(san: &str) -> String {
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
        assert!(result.errors.is_empty(), "errors: {:?}", result.errors);
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
        assert!(!validate_certificate_against_tlsa(
            &tampered,
            &result.record
        ));
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
        assert!(validate_chain_against_tlsa(
            &chain,
            &record,
            "mail.example.com"
        ));

        // A record matching an unrelated cert must fail.
        let other_pem = test_cert_pem("other.example.com");
        let other_der = extract_der_from_pem(&other_pem).unwrap();
        let unrelated = TlsaRecord {
            usage: 2,
            selector: 0,
            matching_type: 1,
            certificate_association_data: hex::encode(Sha256::digest(&other_der)),
        };
        assert!(!validate_chain_against_tlsa(
            &chain,
            &unrelated,
            "mail.example.com"
        ));

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
        assert!(
            result.supported,
            "matching live cert must still pass on cache hits"
        );
        TLSA_CACHE.invalidate(name);
    }
}

#[cfg(test)]
mod adversarial_tests {
    //! Fail-closed coverage for DANE/TLSA decisions that the wire path does
    //! not reach (F-16 keeps the module unwired): every invalid selector,
    //! matching type, chain shape and policy input must return `false` /
    //! `supported = false`, never a permissive default.

    use super::*;

    fn cert_der(san: &str) -> Vec<u8> {
        let params = rcgen::CertificateParams::new(vec![san.to_string()]).unwrap();
        let key_pair = rcgen::KeyPair::generate().unwrap();
        params.self_signed(&key_pair).unwrap().der().to_vec()
    }

    fn pem_of(der: &[u8]) -> String {
        use base64::Engine as _;
        format!(
            "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
            B64.encode(der)
        )
    }

    // ── TLSA generation: invalid input never produces a usable record ─────

    #[test]
    fn generate_tlsa_rejects_malformed_pem_and_unknown_parameters() {
        // No PEM blocks at all.
        let result = generate_tlsa_record("not a pem", "example.com", 25, "tcp", 3, 1, 1);
        assert!(result.record.certificate_association_data.is_empty());
        assert!(result.dns_record.is_empty());
        assert!(result
            .errors
            .iter()
            .any(|e| e.contains("Failed to parse PEM")));

        let pem = pem_of(&cert_der("example.com"));

        // Unsupported selector (RFC 6698 only defines 0/1).
        let result = generate_tlsa_record(&pem, "example.com", 25, "tcp", 3, 2, 1);
        assert!(result
            .errors
            .iter()
            .any(|e| e.contains("Unsupported selector")));
        assert!(result.record.certificate_association_data.is_empty());

        // Unsupported matching type.
        let result = generate_tlsa_record(&pem, "example.com", 25, "tcp", 3, 0, 9);
        assert!(result
            .errors
            .iter()
            .any(|e| e.contains("Unsupported matching type")));

        // Unsupported usage still yields the association data but is flagged.
        let result = generate_tlsa_record(&pem, "example.com", 25, "tcp", 255, 0, 1);
        assert!(result
            .errors
            .iter()
            .any(|e| e.contains("Unsupported usage")));

        // usage=3 warns about the DNSSEC prerequisite.
        let result = generate_tlsa_record(&pem, "example.com", 25, "tcp", 3, 0, 1);
        assert!(result.recommendations.iter().any(|r| r.contains("DNSSEC")));
    }

    #[test]
    fn generate_tlsa_selector1_or_2_and_matching_types_are_exact() {
        let der = cert_der("example.com");
        let pem = pem_of(&der);
        let (_, cert) = x509_parser::prelude::X509Certificate::from_der(&der).unwrap();

        // matching_type 0 = exact association data, no hashing.
        let exact = generate_tlsa_record(&pem, "example.com", 25, "tcp", 3, 0, 0);
        assert_eq!(exact.record.certificate_association_data, hex::encode(&der));

        // matching_type 2 = SHA-512 over the SPKI for selector 1.
        let sha512 = generate_tlsa_record(&pem, "example.com", 25, "tcp", 3, 1, 2);
        assert_eq!(
            sha512.record.certificate_association_data,
            hex::encode(Sha512::digest(cert.public_key().raw))
        );
    }

    #[test]
    fn describe_tlsa_record_names_unknown_values() {
        let record = TlsaRecord {
            usage: 9,
            selector: 9,
            matching_type: 9,
            certificate_association_data: "00".into(),
        };
        let desc = describe_tlsa_record(&record);
        assert!(desc.contains("Unknown usage"));
        assert!(desc.contains("Unknown selector"));
        assert!(desc.contains("Unknown matching type"));
    }

    #[test]
    fn parse_tlsa_data_rejects_incomplete_or_non_numeric_answers() {
        assert!(parse_tlsa_data("3 1 1").is_none(), "too few fields");
        assert!(parse_tlsa_data("x 1 1 abcd").is_none(), "non-numeric usage");
        assert!(
            parse_tlsa_data("3 y 1 abcd").is_none(),
            "non-numeric selector"
        );
        assert!(
            parse_tlsa_data("3 1 z abcd").is_none(),
            "non-numeric matching"
        );
        // Association data whitespace is stripped (DoH answers chunk it).
        let record = parse_tlsa_data("3 1 1 ab cd ef").unwrap();
        assert_eq!(record.certificate_association_data, "abcdef");
    }

    #[test]
    fn extract_der_from_pem_requires_both_delimiters_and_payload() {
        assert!(extract_der_from_pem("-----BEGIN CERTIFICATE-----\nYWJj").is_none());
        assert!(extract_der_from_pem("YWJj\n-----END CERTIFICATE-----").is_none());
        assert!(
            extract_der_from_pem("-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----")
                .is_none()
        );
        assert!(extract_der_from_pem(
            "-----BEGIN CERTIFICATE-----\n!!!\n-----END CERTIFICATE-----"
        )
        .is_none());
    }

    // ── chain validation: fail closed on every malformed shape ───────────

    #[test]
    fn empty_chains_and_unknown_parameters_never_match() {
        let der = cert_der("example.com");
        let matches_any = TlsaRecord {
            usage: 3,
            selector: 0,
            matching_type: 1,
            certificate_association_data: hex::encode(Sha256::digest(&der)),
        };
        assert!(!validate_chain_against_tlsa(
            &[],
            &matches_any,
            "example.com"
        ));
        assert!(!validate_certificate_against_tlsa(&[], &matches_any));

        // Unknown usage/selector/matching-type never match even with a
        // correct digest.
        for (usage, selector, matching) in [(4u8, 0u8, 1u8), (3, 2, 1), (3, 0, 3)] {
            let record = TlsaRecord {
                usage,
                selector,
                matching_type: matching,
                certificate_association_data: hex::encode(Sha256::digest(&der)),
            };
            assert!(
                !validate_chain_against_tlsa(std::slice::from_ref(&der), &record, "example.com"),
                "usage={usage} selector={selector} matching={matching} must not match"
            );
        }

        // A syntactically invalid certificate can never match selector 1.
        let record = TlsaRecord {
            usage: 3,
            selector: 1,
            matching_type: 1,
            certificate_association_data: hex::encode(Sha256::digest(b"junk")),
        };
        assert!(!validate_chain_against_tlsa(
            &[b"junk".to_vec()],
            &record,
            "e"
        ));
    }

    #[test]
    fn dane_ta_requires_a_valid_signature_chain_to_the_matching_anchor() {
        // Anchor matches, but the leaf is NOT signed by it: fail closed.
        let ca_params = {
            let mut p = rcgen::CertificateParams::new(vec!["ca.example".to_string()]).unwrap();
            p.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
            p
        };
        let ca_key = rcgen::KeyPair::generate().unwrap();
        let ca_cert = ca_params.self_signed(&ca_key).unwrap();
        let unrelated_key = rcgen::KeyPair::generate().unwrap();
        let unrelated_leaf = rcgen::CertificateParams::new(vec!["mail.example".to_string()])
            .unwrap()
            .self_signed(&unrelated_key)
            .unwrap();

        let chain = vec![unrelated_leaf.der().to_vec(), ca_cert.der().to_vec()];
        let record = TlsaRecord {
            usage: 2,
            selector: 0,
            matching_type: 1,
            certificate_association_data: hex::encode(Sha256::digest(ca_cert.der())),
        };
        assert!(
            !validate_chain_against_tlsa(&chain, &record, "mail.example"),
            "DANE-TA must verify the signature chain, not just the anchor digest"
        );

        // A garbage certificate in the chain is rejected outright.
        let garbage = vec![b"not a certificate".to_vec(), ca_cert.der().to_vec()];
        assert!(!validate_chain_against_tlsa(
            &garbage,
            &record,
            "mail.example"
        ));
    }

    #[test]
    fn pkix_usages_fail_closed_without_a_publicly_trusted_chain() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let der = cert_der("example.com");
        for usage in [0u8, 1u8] {
            let record = TlsaRecord {
                usage,
                selector: 0,
                matching_type: 1,
                certificate_association_data: hex::encode(Sha256::digest(&der)),
            };
            assert!(
                !validate_certificate_against_tlsa(&der, &record),
                "PKIX usage {usage} must require real PKIX validation (self-signed must fail)"
            );
        }
        // An invalid server name can never validate a PKIX chain.
        assert!(!pkix_chain_valid(std::slice::from_ref(&der), ""));
        assert!(!pkix_chain_valid(&[], "example.com"));
    }

    #[test]
    fn tlsa_modes_are_reported_without_escalating_support() {
        // `pkix_chain_valid` builds a rustls WebPki verifier; the process-wide
        // provider must be installed explicitly (the workspace enables both
        // ring and aws-lc-rs, so rustls cannot choose on its own).
        let _ = rustls::crypto::ring::default_provider().install_default();
        let der = cert_der("example.com");
        let matching = TlsaRecord {
            usage: 3,
            selector: 0,
            matching_type: 1,
            certificate_association_data: hex::encode(Sha256::digest(&der)),
        };
        let result = evaluate_tlsa_records(
            std::slice::from_ref(&der),
            std::slice::from_ref(&matching),
            "example.com",
        );
        assert!(result.supported);
        assert_eq!(result.mode, DaneMode::DaneEe);

        // DANE-TA followed by DANE-EE keeps the DANE-TA mode.
        let ta = TlsaRecord {
            usage: 2,
            selector: 0,
            matching_type: 1,
            certificate_association_data: hex::encode(Sha256::digest(&der)),
        };
        let result = evaluate_tlsa_records(
            std::slice::from_ref(&der),
            &[ta, matching.clone()],
            "example.com",
        );
        assert_eq!(result.mode, DaneMode::DaneTa);
        assert!(result.supported);

        // PKIX modes are reported but never supported on a self-signed input.
        for usage in [0u8, 1u8] {
            let pkix = TlsaRecord {
                usage,
                selector: 0,
                matching_type: 1,
                certificate_association_data: hex::encode(Sha256::digest(&der)),
            };
            let result = evaluate_tlsa_records(std::slice::from_ref(&der), &[pkix], "example.com");
            assert_eq!(result.mode, DaneMode::Pkix);
            assert!(!result.supported);
        }

        // Only unknown records: recommendation, no support, no error storm.
        let unknown = TlsaRecord {
            usage: 9,
            selector: 9,
            matching_type: 9,
            certificate_association_data: "00".into(),
        };
        let result = evaluate_tlsa_records(std::slice::from_ref(&der), &[unknown], "example.com");
        assert!(!result.supported);
        assert!(result
            .recommendations
            .iter()
            .any(|r| r.contains("No usable TLSA records")));
    }

    // ── cache: hits re-validate the LIVE certificate ───────────────────────

    #[tokio::test]
    async fn cache_hit_with_failing_chain_fetch_reports_no_support() {
        let cert = cert_der("cachefail.example.com");
        let record =
            generate_tlsa_record(&pem_of(&cert), "cachefail.example.com", 25, "tcp", 3, 0, 1)
                .record;
        let name = "_25._tcp.cachefail.example.com";
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
            "cachefail.example.com",
            25,
            "tcp",
            &config,
            move |_d: String, _p: u16| async move { Err(anyhow::anyhow!("unreachable peer")) },
        )
        .await;
        assert!(
            !result.supported,
            "an unverifiable live certificate must never report DANE support"
        );
        assert!(result
            .warnings
            .iter()
            .any(|w| w.contains("Could not fetch target TLS certificate")));
        assert!(result
            .recommendations
            .iter()
            .any(|r| r.contains("re-validated")));
        TLSA_CACHE.invalidate(name);
    }
}

#[cfg(test)]
mod dane_wire_tests {
    //! `verify_dane_full` against a loopback DoH JSON endpoint and a
    //! loopback TLS server whose CA is pinned into the fetcher: the whole
    //! DoH → TLSA-parse → live-cert-fetch → match pipeline with hostile
    //! DNS answers and failure isolation between providers.

    use super::tests::test_cert_pem;
    use super::*;
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn dns_config(dnssec: bool) -> DnsConfig {
        DnsConfig {
            dnssec_enabled: dnssec,
            tlsa_cache_ttl_secs: 300,
        }
    }

    /// Loopback JSON-over-HTTP DoH endpoint. Answers `?name=...` GETs from a
    /// map of qname → JSON body; a body of `null` answers HTTP 500; counts hits.
    async fn doh_endpoint(
        answers: HashMap<String, Option<serde_json::Value>>,
    ) -> (String, Arc<AtomicUsize>, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .unwrap();
        let port = listener.local_addr().unwrap().port();
        let answers = Arc::new(answers);
        let hits = Arc::new(AtomicUsize::new(0));
        let hits_srv = hits.clone();
        let handle = tokio::spawn(async move {
            loop {
                let Ok((mut socket, _)) = listener.accept().await else {
                    return;
                };
                let answers = answers.clone();
                let hits = hits_srv.clone();
                tokio::spawn(async move {
                    let mut buf = [0u8; 8192];
                    let n = socket.read(&mut buf).await.unwrap_or(0);
                    let head = String::from_utf8_lossy(&buf[..n]);
                    hits.fetch_add(1, Ordering::SeqCst);
                    let qname = head
                        .split(&['?', ' ', '&'][..])
                        .find(|part| part.starts_with("name="))
                        .and_then(|p| p.strip_prefix("name="))
                        .map(|p| p.split('&').next().unwrap_or(p).to_string())
                        .unwrap_or_default();
                    let (status, body) = match answers.get(&qname) {
                        Some(Some(value)) => (200u16, value.to_string()),
                        Some(None) => (500, "upstream down".to_string()),
                        None => (
                            200,
                            serde_json::json!({ "Status": 0, "Answer": [] }).to_string(),
                        ),
                    };
                    let response = format!(
                        "HTTP/1.1 {status} X\r\ncontent-type: application/dns-json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = socket.write_all(response.as_bytes()).await;
                    let _ = socket.shutdown().await;
                });
            }
        });
        (format!("http://127.0.0.1:{port}/dns-query"), hits, handle)
    }

    fn http_client() -> reqwest::Client {
        reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap()
    }

    fn cert_and_key() -> (
        rcgen::Certificate,
        rcgen::KeyPair,
        rcgen::Certificate,
        rcgen::KeyPair,
    ) {
        let mut ca = rcgen::CertificateParams::new(vec!["dane-ca.test".to_string()]).unwrap();
        ca.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        ca.key_usages = vec![
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::DigitalSignature,
        ];
        let ca_key = rcgen::KeyPair::generate().unwrap();
        let ca_cert = ca.self_signed(&ca_key).unwrap();

        let leaf = rcgen::CertificateParams::new(vec!["mail.dane.test".to_string()]).unwrap();
        let leaf_key = rcgen::KeyPair::generate().unwrap();
        let leaf_cert = leaf.signed_by(&leaf_key, &ca_cert, &ca_key).unwrap();
        (leaf_cert, leaf_key, ca_cert, ca_key)
    }

    fn cert_and_key_with_san(
        san: &str,
    ) -> (
        rcgen::Certificate,
        rcgen::KeyPair,
        rcgen::Certificate,
        rcgen::KeyPair,
    ) {
        let mut ca = rcgen::CertificateParams::new(vec!["dane-ca.test".to_string()]).unwrap();
        ca.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        ca.key_usages = vec![
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::DigitalSignature,
        ];
        let ca_key = rcgen::KeyPair::generate().unwrap();
        let ca_cert = ca.self_signed(&ca_key).unwrap();

        let leaf = rcgen::CertificateParams::new(vec![san.to_string()]).unwrap();
        let leaf_key = rcgen::KeyPair::generate().unwrap();
        let leaf_cert = leaf.signed_by(&leaf_key, &ca_cert, &ca_key).unwrap();
        (leaf_cert, leaf_key, ca_cert, ca_key)
    }

    /// A loopback TLS server presenting `leaf -> ca` in that order.
    async fn tls_server(
        leaf: &rcgen::Certificate,
        leaf_key: &rcgen::KeyPair,
        ca: &rcgen::Certificate,
    ) -> (u16, tokio::task::JoinHandle<()>) {
        let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();
        let mut chain_pem = leaf.pem();
        chain_pem.push_str(&ca.pem());
        let certs: Vec<_> =
            rustls_pemfile::certs(&mut std::io::BufReader::new(chain_pem.as_bytes()))
                .collect::<Result<_, _>>()
                .unwrap();
        let key = rustls_pemfile::private_key(&mut std::io::BufReader::new(
            leaf_key.serialize_pem().as_bytes(),
        ))
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
        let handle = tokio::spawn(async move {
            loop {
                let Ok((socket, _)) = listener.accept().await else {
                    return;
                };
                let Ok(mut tls) = acceptor.accept(socket).await else {
                    continue;
                };
                tokio::spawn(async move {
                    let mut buf = [0u8; 1024];
                    let _ = tls.read(&mut buf).await;
                    let _ = tls.write_all(b"bye").await;
                    let _ = tls.shutdown().await;
                });
            }
        });
        (port, handle)
    }

    fn root_store_with(ca: &rcgen::Certificate) -> tokio_rustls::rustls::RootCertStore {
        let mut roots = tokio_rustls::rustls::RootCertStore::empty();
        roots
            .add(ca.der().clone())
            .expect("the test CA is a valid certificate");
        roots
    }

    fn tlsa_answer(data: &str) -> serde_json::Value {
        serde_json::json!({
            "Status": 0,
            "AD": true,
            "Answer": [
                { "name": "_25._tcp.dane.test", "type": 52, "TTL": 60, "data": data }
            ]
        })
    }

    async fn verify(
        _providers: &[&str],
        answers: HashMap<String, Option<serde_json::Value>>,
        dnssec: bool,
        chain: anyhow::Result<Vec<Vec<u8>>>,
    ) -> DaneVerificationResult {
        let (url, _hits, _server) = doh_endpoint(answers).await;
        let leaked: &'static str = Box::leak(url.into_boxed_str());
        let providers = [leaked];
        let client = http_client();
        let chain_storage = std::sync::Arc::new(tokio::sync::Mutex::new(Some(chain)));
        verify_dane_full(
            "dane.test",
            25,
            "tcp",
            &dns_config(dnssec),
            &providers,
            Some(&client),
            move |_d: String, _p: u16| {
                let chain_storage = chain_storage.clone();
                async move {
                    chain_storage
                        .lock()
                        .await
                        .take()
                        .expect("fetcher invoked exactly once")
                }
            },
        )
        .await
    }

    #[tokio::test]
    async fn dane_supported_when_tlsa_matches_the_live_leaf() {
        TLSA_CACHE.invalidate_all();
        let (leaf, _leaf_key, _ca, _ca_key) = cert_and_key();
        let der = leaf.der().to_vec();
        let tlsa = generate_tlsa_record(&leaf.pem(), "dane.test", 25, "tcp", 3, 0, 1);
        assert!(tlsa.errors.is_empty(), "{:?}", tlsa.errors);

        let mut answers: HashMap<String, Option<serde_json::Value>> = HashMap::new();
        answers.insert(
            "_25._tcp.dane.test".into(),
            Some(tlsa_answer(&format!(
                "3 0 1 {}",
                tlsa.record.certificate_association_data
            ))),
        );
        let result = verify(&[], answers, false, Ok(vec![der])).await;
        assert!(
            result.supported,
            "errors: {:?} warnings: {:?}",
            result.errors, result.warnings
        );
        assert_eq!(result.mode, DaneMode::DaneEe);
        assert_eq!(result.tlsa_records.len(), 1);
        TLSA_CACHE.invalidate_all();
    }

    #[tokio::test]
    async fn dane_unsupported_when_records_do_not_match() {
        TLSA_CACHE.invalidate_all();
        let (_leaf, _lk, other_ca, _ok) = cert_and_key();
        let other_tlsa = generate_tlsa_record(&other_ca.pem(), "dane.test", 25, "tcp", 3, 0, 1);
        let (leaf, _leaf_key, _ca2, _ck2) = cert_and_key();

        let mut answers: HashMap<String, Option<serde_json::Value>> = HashMap::new();
        answers.insert(
            "_25._tcp.dane.test".into(),
            Some(tlsa_answer(&format!(
                "3 0 1 {}",
                other_tlsa.record.certificate_association_data
            ))),
        );
        let result = verify(&[], answers, false, Ok(vec![leaf.der().to_vec()])).await;
        assert!(!result.supported);
        assert!(
            result
                .errors
                .iter()
                .any(|e| e.contains("do not match the target server certificate")),
            "{:?}",
            result.errors
        );
        TLSA_CACHE.invalidate_all();
    }

    #[tokio::test]
    async fn dane_dnssec_requires_the_ad_flag() {
        TLSA_CACHE.invalidate_all();
        let (leaf, _lk, _ca, _ck) = cert_and_key();
        let tlsa = generate_tlsa_record(&leaf.pem(), "dane.test", 25, "tcp", 3, 0, 1);
        let mut no_ad = tlsa_answer(&format!(
            "3 0 1 {}",
            tlsa.record.certificate_association_data
        ));
        no_ad["AD"] = serde_json::json!(false);

        let mut answers: HashMap<String, Option<serde_json::Value>> = HashMap::new();
        answers.insert("_25._tcp.dane.test".into(), Some(no_ad));
        let result = verify(&[], answers, true, Ok(vec![leaf.der().to_vec()])).await;
        assert!(!result.supported);
        assert!(
            result
                .errors
                .iter()
                .any(|e| e.contains("DNSSEC validation not confirmed")),
            "{:?}",
            result.errors
        );
        TLSA_CACHE.invalidate_all();
    }

    #[tokio::test]
    async fn dane_unknown_and_garbage_answers_are_filtered_not_fatal() {
        TLSA_CACHE.invalidate_all();
        let (leaf, _lk, _ca, _ck) = cert_and_key();
        let tlsa = generate_tlsa_record(&leaf.pem(), "dane.test", 25, "tcp", 3, 0, 1);

        // Unknown usage (9) + wrong RR type (A) + malformed data + the one
        // good record: only the good one survives; supported flips true.
        let mixed = serde_json::json!({
            "Status": 0,
            "Answer": [
                { "name": "_25._tcp.dane.test", "type": 52, "data": "9 0 1 abcd" },
                { "name": "_25._tcp.dane.test", "type": 1,  "data": "203.0.113.9" },
                { "name": "_25._tcp.dane.test", "type": 52, "data": "garbage" },
                { "name": "_25._tcp.dane.test", "type": 52, "data": format!("3 0 1 {}", tlsa.record.certificate_association_data) },
            ]
        });
        let mut answers: HashMap<String, Option<serde_json::Value>> = HashMap::new();
        answers.insert("_25._tcp.dane.test".into(), Some(mixed));
        let result = verify(&[], answers, false, Ok(vec![leaf.der().to_vec()])).await;
        assert!(result.supported, "{:?}", result.errors);
        assert_eq!(
            result.tlsa_records.len(),
            1,
            "only the usable record survives"
        );
        TLSA_CACHE.invalidate_all();

        // No usable answers at all -> recommendation, never an error.
        let empty = serde_json::json!({ "Status": 0, "Answer": [] });
        let mut answers: HashMap<String, Option<serde_json::Value>> = HashMap::new();
        answers.insert("_25._tcp.dane.test".into(), Some(empty));
        let result = verify(&[], answers, false, Ok(vec![b"x".to_vec()])).await;
        assert!(!result.supported);
        assert!(result.errors.is_empty());
        assert!(
            result
                .recommendations
                .iter()
                .any(|r| r.contains("Add TLSA record at _25._tcp.dane.test")),
            "{:?}",
            result.recommendations
        );
        TLSA_CACHE.invalidate_all();
    }

    #[tokio::test]
    async fn dane_fetch_failure_is_a_warning_not_a_verdict() {
        TLSA_CACHE.invalidate_all();
        let (leaf, _lk, _ca, _ck) = cert_and_key();
        let tlsa = generate_tlsa_record(&leaf.pem(), "dane.test", 25, "tcp", 3, 0, 1);
        let mut answers: HashMap<String, Option<serde_json::Value>> = HashMap::new();
        answers.insert(
            "_25._tcp.dane.test".into(),
            Some(tlsa_answer(&format!(
                "3 0 1 {}",
                tlsa.record.certificate_association_data
            ))),
        );
        let result = verify(
            &[],
            answers,
            false,
            Err(anyhow::anyhow!("connection refused")),
        )
        .await;
        assert!(!result.supported);
        assert!(
            result
                .warnings
                .iter()
                .any(|w| w.contains("Could not fetch target TLS certificate")),
            "{:?}",
            result.warnings
        );
        assert_eq!(result.tlsa_records.len(), 1, "records still reported");
        TLSA_CACHE.invalidate_all();
    }

    #[tokio::test]
    async fn dane_provider_failover_and_total_failure() {
        TLSA_CACHE.invalidate_all();
        // One DoH provider erroring (HTTP 500) is skipped: provide a second
        // that answers.
        let mut primary: HashMap<String, Option<serde_json::Value>> = HashMap::new();
        primary.insert("_25._tcp.dane.test".into(), None); // 500
        let (url1_owned, hits1, _s1) = doh_endpoint(primary).await;
        let (leaf, _lk, _ca, _ck) = cert_and_key();
        let tlsa = generate_tlsa_record(&leaf.pem(), "dane.test", 25, "tcp", 3, 0, 1);
        let mut secondary: HashMap<String, Option<serde_json::Value>> = HashMap::new();
        secondary.insert(
            "_25._tcp.dane.test".into(),
            Some(tlsa_answer(&format!(
                "3 0 1 {}",
                tlsa.record.certificate_association_data
            ))),
        );
        let (url2, _hits2, _s2) = doh_endpoint(secondary).await;
        let providers: [&'static str; 2] = [
            Box::leak(url1_owned.into_boxed_str()),
            Box::leak(url2.into_boxed_str()),
        ];
        let client = http_client();
        let der = leaf.der().to_vec();
        let result = verify_dane_full(
            "dane.test",
            25,
            "tcp",
            &dns_config(false),
            &providers,
            Some(&client),
            move |_d: String, _p: u16| {
                let der = der.clone();
                async move { Ok(vec![der]) }
            },
        )
        .await;
        assert!(
            result.supported,
            "failover to the healthy provider: {:?}",
            result.errors
        );
        assert!(hits1.load(Ordering::SeqCst) >= 1);
        TLSA_CACHE.invalidate_all();

        // ALL providers failing is a hard error.
        let mut dead: HashMap<String, Option<serde_json::Value>> = HashMap::new();
        dead.insert("_25._tcp.dane.test".into(), None);
        let (url, _hits, _s) = doh_endpoint(dead).await;
        let dead_providers: [&'static str; 1] = [Box::leak(url.into_boxed_str())];
        let der = leaf.der().to_vec();
        let result = verify_dane_full(
            "dane.test",
            25,
            "tcp",
            &dns_config(false),
            &dead_providers,
            Some(&client),
            move |_d: String, _p: u16| {
                let der = der.clone();
                async move { Ok(vec![der]) }
            },
        )
        .await;
        assert!(!result.supported);
        assert!(
            result
                .errors
                .iter()
                .any(|e| e.contains("All DoH providers failed")),
            "{:?}",
            result.errors
        );
        TLSA_CACHE.invalidate_all();
    }

    #[tokio::test]
    async fn dane_transient_dns_status_fails_over_but_nxdomain_does_not() {
        TLSA_CACHE.invalidate_all();
        let (leaf, _lk, _ca, _ck) = cert_and_key();
        let tlsa = generate_tlsa_record(&leaf.pem(), "dane.test", 25, "tcp", 3, 0, 1);
        let client = http_client();
        let der = leaf.der().to_vec();

        // Status 2 (SERVFAIL) on provider 1 -> try provider 2.
        let transient = serde_json::json!({ "Status": 2 });
        let mut a1: HashMap<String, Option<serde_json::Value>> = HashMap::new();
        a1.insert("_25._tcp.dane.test".into(), Some(transient));
        let (url1_owned, hits1, _s1) = doh_endpoint(a1).await;
        let mut a2: HashMap<String, Option<serde_json::Value>> = HashMap::new();
        a2.insert(
            "_25._tcp.dane.test".into(),
            Some(tlsa_answer(&format!(
                "3 0 1 {}",
                tlsa.record.certificate_association_data
            ))),
        );
        let (url2, _h2, _s2) = doh_endpoint(a2).await;
        let providers: [&'static str; 2] = [
            Box::leak(url1_owned.into_boxed_str()),
            Box::leak(url2.into_boxed_str()),
        ];
        let result = verify_dane_full(
            "dane.test",
            25,
            "tcp",
            &dns_config(false),
            &providers,
            Some(&client),
            move |_d: String, _p: u16| {
                let der = der.clone();
                async move { Ok(vec![der]) }
            },
        )
        .await;
        assert!(result.supported, "{:?}", result.errors);
        assert_eq!(
            hits1.load(Ordering::SeqCst),
            1,
            "the transient provider was consulted"
        );
        TLSA_CACHE.invalidate_all();

        // Status 3 (NXDOMAIN) is DETERMINATE: it must NOT fail over to the
        // next provider (an NXDOMAIN from one resolver is authoritative).
        let nxdomain = serde_json::json!({ "Status": 3, "Answer": [] });
        let mut a1: HashMap<String, Option<serde_json::Value>> = HashMap::new();
        a1.insert("_25._tcp.dane.test".into(), Some(nxdomain));
        let (url1_owned, hits1, _s1) = doh_endpoint(a1).await;
        let (url2, hits2, _s2) = doh_endpoint(HashMap::new()).await;
        let providers: [&'static str; 2] = [
            Box::leak(url1_owned.into_boxed_str()),
            Box::leak(url2.into_boxed_str()),
        ];
        let der = leaf.der().to_vec();
        let result = verify_dane_full(
            "dane.test",
            25,
            "tcp",
            &dns_config(false),
            &providers,
            Some(&client),
            move |_d: String, _p: u16| {
                let der = der.clone();
                async move { Ok(vec![der]) }
            },
        )
        .await;
        assert!(!result.supported);
        assert_eq!(hits1.load(Ordering::SeqCst), 1);
        assert_eq!(
            hits2.load(Ordering::SeqCst),
            0,
            "NXDOMAIN must not trigger failover"
        );
        TLSA_CACHE.invalidate_all();
    }

    #[tokio::test]
    async fn dane_reports_a_missing_doh_client() {
        TLSA_CACHE.invalidate_all();
        let result = verify_dane_full(
            "dane.test",
            25,
            "tcp",
            &dns_config(false),
            &[],
            None,
            |_d: String, _p: u16| async { Ok(vec![b"x".to_vec()]) },
        )
        .await;
        assert!(!result.supported);
        assert!(
            result
                .errors
                .iter()
                .any(|e| e.contains("DoH HTTP client unavailable")),
            "{:?}",
            result.errors
        );
    }

    #[tokio::test]
    async fn dane_fetches_the_live_chain_over_pinned_tls() {
        TLSA_CACHE.invalidate_all();
        let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();
        // The leaf carries the IP SAN the fetch connects by.
        let (leaf, leaf_key, ca, _ca_key) = cert_and_key_with_san("127.0.0.1");
        let (port, server) = tls_server(&leaf, &leaf_key, &ca).await;

        let tlsa = generate_tlsa_record(&leaf.pem(), "dane.test", 25, "tcp", 3, 0, 1);
        let mut answers: HashMap<String, Option<serde_json::Value>> = HashMap::new();
        answers.insert(
            "_25._tcp.dane.test".into(),
            Some(tlsa_answer(&format!(
                "3 0 1 {}",
                tlsa.record.certificate_association_data
            ))),
        );
        let (url, _hits, _doh) = doh_endpoint(answers).await;
        let _providers: [&'static str; 1] = [Box::leak(url.into_boxed_str())];
        let _client = http_client();

        // 127.0.0.1 has no DNS name: the leaf SAN does not matter for DANE
        // usage 3, only the digest does.
        let chain =
            fetch_remote_cert_chain_with_roots("127.0.0.1".to_string(), port, root_store_with(&ca))
                .await
                .expect("live fetch against the pinned root");
        assert_eq!(chain.len(), 2, "leaf + ca presented");
        let result = evaluate_tlsa_records(&chain, &[tlsa.record], "dane.test");
        assert!(result.supported, "{:?}", result.errors);
        server.abort();
        TLSA_CACHE.invalidate_all();
    }

    #[tokio::test]
    async fn remote_chain_fetch_times_out_on_a_stalled_handshake() {
        let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();
        // Accept the TCP connection but never complete the TLS handshake:
        // the (short, injected) handshake deadline must fire.
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .unwrap();
        let port = listener.local_addr().unwrap().port();
        let stall = tokio::spawn(async move {
            // Hold the accepted socket OPEN without ever handshaking.
            let held = listener.accept().await;
            std::future::pending::<()>().await;
            drop(held);
        });
        let roots = tokio_rustls::rustls::RootCertStore::empty();
        let error = fetch_remote_cert_chain_with_timeouts(
            "127.0.0.1".to_string(),
            port,
            roots,
            Duration::from_secs(2),
            Duration::from_millis(200),
        )
        .await
        .expect_err("a stalled handshake must time out");
        assert!(
            error.to_string().contains("TLS handshake timeout"),
            "{error}"
        );
        stall.abort();
    }

    #[tokio::test]
    async fn remote_chain_fetch_enforces_the_connect_deadline() {
        let roots = tokio_rustls::rustls::RootCertStore::empty();
        // 203.0.113.1 is TEST-NET (never routable): a short injected connect
        // deadline makes the TCP phase fail with the timeout error rather
        // than hanging for the OS-level timeout.
        let error = fetch_remote_cert_chain_with_timeouts(
            "203.0.113.1".to_string(),
            25,
            roots,
            Duration::from_millis(200),
            Duration::from_secs(2),
        )
        .await
        .expect_err("an unroutable peer must hit the connect deadline");
        assert!(error.to_string().contains("TCP connect timeout"), "{error}");
    }

    #[tokio::test]
    async fn remote_chain_fetch_fails_fast_on_a_refused_connection() {
        let roots = tokio_rustls::rustls::RootCertStore::empty();
        let error = fetch_remote_cert_chain_with_roots("127.0.0.1".to_string(), 1, roots)
            .await
            .expect_err("connection refused must surface");
        assert!(
            !error.to_string().contains("timeout"),
            "a refused port is an immediate error, not a timeout: {error}"
        );
    }

    #[tokio::test]
    async fn remote_chain_fetch_rejects_an_invalid_server_name() {
        let roots = tokio_rustls::rustls::RootCertStore::empty();
        // A name that cannot be a DNS/IP identity fails before any connect.
        let error = fetch_remote_cert_chain_with_roots("bad name".to_string(), 25, roots)
            .await
            .expect_err("invalid server name");
        assert!(
            error.to_string().contains("Invalid TLS server name"),
            "{error}"
        );
    }

    #[test]
    fn generate_tlsa_record_rejects_hostile_inputs() {
        // Not a PEM at all.
        let result = generate_tlsa_record("definitely not pem", "d.test", 25, "tcp", 3, 0, 1);
        assert!(result
            .errors
            .iter()
            .any(|e| e.contains("Failed to parse PEM")));
        assert!(result.dns_record.is_empty());

        // Unsupported selector.
        let pem = test_cert_pem("x.example");
        let result = generate_tlsa_record(&pem, "d.test", 25, "tcp", 3, 9, 1);
        assert!(result
            .errors
            .iter()
            .any(|e| e.contains("Unsupported selector")));

        // Unsupported matching type: reported, data empty.
        let result = generate_tlsa_record(&pem, "d.test", 25, "tcp", 3, 0, 7);
        assert!(result
            .errors
            .iter()
            .any(|e| e.contains("Unsupported matching type")));
        assert!(result.record.certificate_association_data.is_empty());

        // Unsupported usage still produces a record but flags the error.
        let result = generate_tlsa_record(&pem, "d.test", 25, "tcp", 7, 0, 1);
        assert!(result
            .errors
            .iter()
            .any(|e| e.contains("Unsupported usage")));

        // Usage 3 earns the DNSSEC recommendation.
        let result = generate_tlsa_record(&pem, "d.test", 25, "tcp", 3, 0, 1);
        assert!(result.recommendations.iter().any(|r| r.contains("DNSSEC")));

        // Matching types 0 and 2 both produce association data.
        for m in [0u8, 2u8] {
            let result = generate_tlsa_record(&pem, "d.test", 25, "tcp", 3, 0, m);
            assert!(result.errors.is_empty());
            assert!(!result.record.certificate_association_data.is_empty());
        }
    }

    #[test]
    fn extract_der_from_pem_rejects_truncated_and_hostile_pems() {
        assert_eq!(extract_der_from_pem("no markers at all"), None);
        assert_eq!(
            extract_der_from_pem("-----BEGIN CERTIFICATE-----\nnever ends"),
            None
        );
        // Empty payload between the markers.
        assert_eq!(
            extract_der_from_pem("-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----"),
            None
        );
        // Invalid base64 payload.
        assert_eq!(
            extract_der_from_pem("-----BEGIN CERTIFICATE-----\n!!!!\n-----END CERTIFICATE-----"),
            None
        );
    }

    #[test]
    fn parse_tlsa_data_rejects_malformed_records() {
        assert!(parse_tlsa_data("3 1").is_none());
        assert!(parse_tlsa_data("three 1 1 abc").is_none());
        assert!(parse_tlsa_data("3 one 1 abc").is_none());
        assert!(parse_tlsa_data("3 1 one abc").is_none());
        // Whitespace inside the digest is stripped.
        let rec = parse_tlsa_data("3 1 1 ab cd").unwrap();
        assert_eq!(rec.certificate_association_data, "abcd");
    }

    #[test]
    fn describe_tlsa_record_covers_unknown_values() {
        let rec = TlsaRecord {
            usage: 9,
            selector: 9,
            matching_type: 9,
            certificate_association_data: "ff".into(),
        };
        let desc = describe_tlsa_record(&rec);
        assert!(desc.contains("Unknown usage"));
        assert!(desc.contains("Unknown selector"));
        assert!(desc.contains("Unknown matching type"));
        assert!(desc.contains("ff"));
    }

    #[test]
    fn evaluate_tlsa_records_mode_precedence_and_unknown_filtering() {
        let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();
        let (leaf, _lk, _ca, _ck) = cert_and_key();
        let der = leaf.der().to_vec();
        let leaf_matching = |usage: u8| TlsaRecord {
            usage,
            selector: 0,
            matching_type: 1,
            certificate_association_data: hex::encode(Sha256::digest(&der)),
        };
        // DANE-TA beats DANE-EE when both are present.
        let result = evaluate_tlsa_records(
            std::slice::from_ref(&der),
            &[leaf_matching(3), leaf_matching(2)],
            "d.test",
        );
        assert_eq!(result.mode, DaneMode::DaneTa);
        // PKIX usages set the Pkix mode only from None.
        let result =
            evaluate_tlsa_records(std::slice::from_ref(&der), &[leaf_matching(1)], "d.test");
        assert_eq!(result.mode, DaneMode::Pkix);
        // Unknown triples are filtered out entirely.
        let unknown = TlsaRecord {
            usage: 4,
            selector: 0,
            matching_type: 1,
            certificate_association_data: "ab".into(),
        };
        let result = evaluate_tlsa_records(std::slice::from_ref(&der), &[unknown], "d.test");
        assert!(result.tlsa_records.is_empty());
        assert!(result
            .recommendations
            .iter()
            .any(|r| r.contains("No usable TLSA records")));
        // Empty chain never matches.
        let result = evaluate_tlsa_records(&[], &[leaf_matching(3)], "d.test");
        assert!(!result.supported);
    }
}
