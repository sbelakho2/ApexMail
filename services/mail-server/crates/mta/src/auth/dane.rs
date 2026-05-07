//! DANE – DNS‑Based Authentication of Named Entities (RFC 6698 / 7671).
//!
//! TLSA record lookup, generation, and certificate validation.

use std::sync::LazyLock;
use std::time::{Duration, Instant};

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use moka::sync::Cache;
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
    if let Some(cached) = TLSA_CACHE.get(&name) {
        let ttl = Duration::from_secs(dns_config.tlsa_cache_ttl_secs);
        if cached.fetched_at.elapsed() < ttl {
            if !cached.records.is_empty() {
                result.supported = true;
                for record in &cached.records {
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
                result.tlsa_records = cached.records.clone();
            }
            return result;
        }
        // Stale entry — evict and re-fetch
        TLSA_CACHE.invalidate(&name);
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

    // Parse TLSA answers
    if let Some(answers) = body.get("Answer").and_then(|v| v.as_array()) {
        for answer in answers {
            let rtype = answer.get("type").and_then(|v| v.as_u64()).unwrap_or(0);
            if rtype != 52 {
                // 52 = TLSA
                continue;
            }
            if let Some(data) = answer.get("data").and_then(|v| v.as_str()) {
                if let Some(record) = parse_tlsa_data(data) {
                    result.supported = true;
                    // Determine mode from usage
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
                    result.tlsa_records.push(record);
                }
            }
        }
    }

    if !result.supported {
        result
            .recommendations
            .push(format!("Add TLSA record at {name} for DANE support"));
    } else {
        match fetch_remote_leaf_certificate(domain, port).await {
            Ok(cert_der) => {
                let matches_tlsa = result
                    .tlsa_records
                    .iter()
                    .any(|record| validate_certificate_against_tlsa(&cert_der, record));

                if !matches_tlsa {
                    result
                        .errors
                        .push("TLSA records do not match the target server certificate".into());
                    result.supported = false;
                }
            }
            Err(e) => {
                result.warnings.push(format!(
                    "Could not fetch target TLS certificate for DANE validation: {e}"
                ));
                result.supported = false;
            }
        }
    }

    // O-1.4:Cache the result with a timestamp for configurable TTL enforcement
    TLSA_CACHE.insert(
        name,
        CachedTlsaRecords {
            records: result.tlsa_records.clone(),
            fetched_at: Instant::now(),
        },
    );

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

    // Compute association data
    let data = match matching_type {
        0 => hex::encode(&der),
        1 => {
            let hash = Sha256::digest(&der);
            hex::encode(hash)
        }
        2 => {
            let hash = Sha512::digest(&der);
            hex::encode(hash)
        }
        _ => {
            errors.push(format!("Unsupported matching type: {matching_type}"));
            String::new()
        }
    };

    let name = format!("_{port}._{protocol}.{domain}");
    let dns_record = format!("{name} IN TLSA {usage} {selector} {matching_type} {data}");

    if usage == 3 {
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
pub fn validate_certificate_against_tlsa(cert_der: &[u8], record: &TlsaRecord) -> bool {
    let computed = match record.matching_type {
        0 => hex::encode(cert_der),
        1 => hex::encode(Sha256::digest(cert_der)),
        2 => hex::encode(Sha512::digest(cert_der)),
        _ => return false,
    };
    computed.to_lowercase() == record.certificate_association_data.to_lowercase()
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

async fn fetch_remote_leaf_certificate(domain: &str, port: u16) -> anyhow::Result<Vec<u8>> {
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

    let leaf = certs
        .first()
        .ok_or_else(|| anyhow::anyhow!("Missing leaf certificate from {addr}"))?;

    Ok(leaf.to_vec())
}

// ── tests ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

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
        let pem =
            " -----BEGIN CERTIFICATE-----\nMIIBkTCB+wIJALRiMLAh4EEAMA0G\n-----END CERTIFICATE-----";
        let result = generate_tlsa_record(pem, "example.com", 25, "tcp", 3, 1, 1);
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
}
