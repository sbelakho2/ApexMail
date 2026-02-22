//! DANE – DNS‑Based Authentication of Named Entities (RFC 6698 / 7671).
//!
//! TLSA record lookup, generation, and certificate validation.

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha512};
use tracing::{debug, warn};

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

/// Verify DANE for a domain + port using DNS‑over‑HTTPS (Cloudflare).
pub async fn verify_dane(domain: &str, port: u16, protocol: &str) -> DaneVerificationResult {
    let mut result = DaneVerificationResult {
        supported: false,
        mode: DaneMode::None,
        tlsa_records: Vec::new(),
        errors: Vec::new(),
        warnings: Vec::new(),
        recommendations: Vec::new(),
    };

    let name = format!("_{port}._{protocol}.{domain}");

    // Use Cloudflare DoH for TLSA lookup (most stub resolvers don't support TLSA)
    let doh_url = format!(
        "https://cloudflare-dns.com/dns-query?name={name}&type=TLSA"
    );

    let client = match Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            result.errors.push(format!("HTTP client init failed: {e}"));
            return result;
        }
    };

    let resp = match client
        .get(&doh_url)
        .header("Accept", "application/dns-json")
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => {
            result.errors.push(format!("DoH request failed: {e}"));
            result.recommendations.push("Ensure DANE TLSA records are published".into());
            return result;
        }
    };

    let body: serde_json::Value = match resp.json().await {
        Ok(v) => v,
        Err(e) => {
            result.errors.push(format!("DoH parse failed: {e}"));
            return result;
        }
    };

    // Check AD flag (DNSSEC authenticated)
    let ad = body.get("AD").and_then(|v| v.as_bool()).unwrap_or(false);
    if !ad {
        result.warnings.push("DNSSEC validation not confirmed (AD flag not set)".into());
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
        result.recommendations.push(format!(
            "Add TLSA record at {name} for DANE support"
        ));
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
        recommendations.push("DANE-EE (usage=3) requires DNSSEC to be enabled on the domain".into());
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

fn extract_der_from_pem(pem: &str) -> Option<Vec<u8>> {
    let begin = "-----BEGIN CERTIFICATE-----";
    let end = "-----END CERTIFICATE-----";
    let start = pem.find(begin)? + begin.len();
    let stop = pem.find(end)?;
    let b64: String = pem[start..stop].chars().filter(|c| !c.is_whitespace()).collect();
    B64.decode(&b64).ok()
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
        let pem = "-----BEGIN CERTIFICATE-----\nMIIBkTCB+wIJALRiMLAh4EEAMA0G\n-----END CERTIFICATE-----";
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
        let pem = "-----BEGIN CERTIFICATE-----\nYWJj\n-----END CERTIFICATE-----";
        let der = extract_der_from_pem(pem).unwrap();
        assert_eq!(der, b"abc");
    }
}
