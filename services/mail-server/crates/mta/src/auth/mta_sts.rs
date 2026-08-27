//! MTA‑STS – SMTP MTA Strict Transport Security (RFC 8461) + TLSRPT (RFC 8460).
//!
//! MAINTAINED-BUT-NOT-WIRED (F-16): nothing in the inbound SMTP path calls
//! into this module — it is exercised only by its own unit tests. MTA-STS
//! policy enforcement belongs on the OUTBOUND direct-MX sender (a sending
//! MTA fetching the recipient domain's policy before connecting), which is
//! tracked as finding F-16; the inbound receiver role only publishes DNS.
//! Do not delete: the direct-MX sender (see F-16) builds on this code.

use std::sync::LazyLock;

use reqwest::Client;
use serde::{Deserialize, Serialize};
use tracing::debug;
use trust_dns_resolver::{Resolver, TokioResolver};

// #134:Shared DNS resolver – avoids creating a new resolver per verification call.
// trust-dns 0.26: TokioAsyncResolver::tokio is gone; build a TokioResolver
// (builder defaults already equal ResolverOpts::default()).
static MTA_STS_RESOLVER: LazyLock<TokioResolver> = LazyLock::new(|| {
    Resolver::builder_tokio()
        .expect("system resolver configuration is always buildable")
        .build()
        .expect("system resolver configuration is always buildable")
});

// #135:Shared HTTP client with timeout – avoids per-call TLS handshake overhead
static MTA_STS_CLIENT: LazyLock<Option<Client>> = LazyLock::new(|| {
    Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .ok()
});

/// MTA‑STS mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MtaStsMode {
    Enforce,
    Testing,
    None,
}

/// Parsed MTA‑STS policy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MtaStsPolicy {
    pub version: String,
    pub mode: MtaStsMode,
    pub mx: Vec<String>,
    pub max_age: u64,
}

/// MTA‑STS DNS record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MtaStsRecord {
    pub version: String,
    pub id: String,
}

/// Full MTA‑STS verification result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MtaStsVerificationResult {
    pub supported: bool,
    pub mode: MtaStsMode,
    pub policy: Option<MtaStsPolicy>,
    pub dns_record: Option<MtaStsRecord>,
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
    pub recommendations: Vec<String>,
}

/// TLSRPT record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsRptRecord {
    pub version: String,
    pub rua: Vec<String>,
}

/// Verify MTA‑STS for a domain.
pub async fn verify_mta_sts(domain: &str) -> MtaStsVerificationResult {
    let mut result = MtaStsVerificationResult {
        supported: false,
        mode: MtaStsMode::None,
        policy: None,
        dns_record: None,
        errors: Vec::new(),
        warnings: Vec::new(),
        recommendations: Vec::new(),
    };

    // #134:Use shared resolver instead of creating new one per call
    let resolver = &*MTA_STS_RESOLVER;

    // 1. Check DNS TXT record at _mta-sts.<domain>
    let sts_name = format!("_mta-sts.{domain}");
    match resolver.txt_lookup(&sts_name).await {
        Ok(lookup) => {
            for txt in txt_record_strings(&lookup) {
                if txt.starts_with("v=STSv1") {
                    result.dns_record = Some(parse_sts_dns_record(&txt));
                    result.supported = true;
                    break;
                }
            }
        }
        Err(e) => {
            debug!(domain, error = %e, "MTA-STS DNS lookup failed");
        }
    }

    if !result.supported {
        result.recommendations.push(format!(
            "Add DNS TXT at _mta-sts.{domain}: v=STSv1; id=<unique-id>"
        ));
        return result;
    }

    // 2. Fetch policy from https://mta-sts.<domain>/.well-known/mta-sts.txt
    let policy_url = format!("https://mta-sts.{domain}/.well-known/mta-sts.txt");
    // #135:Use shared HTTP client instead of creating a new one per call
    let Some(client) = MTA_STS_CLIENT.as_ref() else {
        result
            .errors
            .push("MTA-STS HTTP client unavailable".to_string());
        return result;
    };

    match client.get(&policy_url).send().await {
        Ok(resp) => {
            if !resp.status().is_success() {
                result
                    .errors
                    .push(format!("Policy fetch failed with status {}", resp.status()));
                return result;
            }
            match resp.text().await {
                Ok(body) => {
                    let policy = parse_mta_sts_policy(&body);
                    result.mode = policy.mode;
                    result.policy = Some(policy);
                }
                Err(e) => {
                    result.errors.push(format!("Policy body read failed: {e}"));
                }
            }
        }
        Err(e) => {
            result.errors.push(format!("Policy fetch failed: {e}"));
            result
                .recommendations
                .push(format!("Host MTA-STS policy at {policy_url}"));
        }
    }

    result
}

/// Generate MTA‑STS DNS record value.
pub fn generate_mta_sts_dns_record(policy_id: &str) -> String {
    format!("v=STSv1; id={policy_id}")
}

/// Generate MTA‑STS policy file content.
pub fn generate_mta_sts_policy(mx_hosts: &[&str], mode: MtaStsMode, max_age: u64) -> String {
    let mode_str = match mode {
        MtaStsMode::Enforce => "enforce",
        MtaStsMode::Testing => "testing",
        MtaStsMode::None => "none",
    };
    let mut lines = vec!["version: STSv1".to_string(), format!("mode: {mode_str}")];
    for mx in mx_hosts {
        lines.push(format!("mx: {mx}"));
    }
    lines.push(format!("max_age: {max_age}"));
    lines.join("\n")
}

/// Generate TLSRPT DNS record value.
pub fn generate_tlsrpt_record(reporting_emails: &[&str]) -> String {
    let rua = reporting_emails
        .iter()
        .map(|e| format!("mailto:{e}"))
        .collect::<Vec<_>>()
        .join(",");
    format!("v=TLSRPTv1; rua={rua}")
}

/// Verify TLSRPT record for a domain.
pub async fn verify_tlsrpt(domain: &str) -> Option<TlsRptRecord> {
    // #134:Use shared resolver
    let resolver = &*MTA_STS_RESOLVER;

    let name = format!("_smtp._tls.{domain}");
    let lookup = resolver.txt_lookup(&name).await.ok()?;

    for txt in txt_record_strings(&lookup) {
        if txt.starts_with("v=TLSRPTv1") {
            return Some(parse_tlsrpt_record(&txt));
        }
    }
    None
}

// ── parsers ────────────────────────────────────────────────────────────────────

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

fn parse_sts_dns_record(txt: &str) -> MtaStsRecord {
    let mut version = String::new();
    let mut id = String::new();
    for part in txt.split(';') {
        let part = part.trim();
        if let Some(v) = part.strip_prefix("v=") {
            version = v.trim().into();
        } else if let Some(i) = part.strip_prefix("id=") {
            id = i.trim().into();
        }
    }
    MtaStsRecord { version, id }
}

fn parse_mta_sts_policy(body: &str) -> MtaStsPolicy {
    let mut version = String::new();
    let mut mode = MtaStsMode::None;
    let mut mx = Vec::new();
    let mut max_age = 0u64;

    for line in body.lines() {
        let line = line.trim();
        if let Some(v) = line.strip_prefix("version:") {
            version = v.trim().into();
        } else if let Some(m) = line.strip_prefix("mode:") {
            mode = match m.trim() {
                "enforce" => MtaStsMode::Enforce,
                "testing" => MtaStsMode::Testing,
                _ => MtaStsMode::None,
            };
        } else if let Some(h) = line.strip_prefix("mx:") {
            mx.push(h.trim().to_string());
        } else if let Some(a) = line.strip_prefix("max_age:") {
            max_age = a.trim().parse().unwrap_or(0);
        }
    }

    MtaStsPolicy {
        version,
        mode,
        mx,
        max_age,
    }
}

fn parse_tlsrpt_record(txt: &str) -> TlsRptRecord {
    let mut version = String::new();
    let mut rua = Vec::new();
    for part in txt.split(';') {
        let part = part.trim();
        if let Some(v) = part.strip_prefix("v=") {
            version = v.trim().into();
        } else if let Some(r) = part.strip_prefix("rua=") {
            for addr in r.split(',') {
                rua.push(addr.trim().to_string());
            }
        }
    }
    TlsRptRecord { version, rua }
}

// ── tests ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_dns_record() {
        let record = generate_mta_sts_dns_record("20250101T000000");
        assert_eq!(record, "v=STSv1; id=20250101T000000");
    }

    #[test]
    fn test_generate_policy() {
        let policy = generate_mta_sts_policy(
            &["mx1.example.com", "mx2.example.com"],
            MtaStsMode::Enforce,
            604800,
        );
        assert!(policy.contains("version: STSv1"));
        assert!(policy.contains("mode: enforce"));
        assert!(policy.contains("mx: mx1.example.com"));
        assert!(policy.contains("mx: mx2.example.com"));
        assert!(policy.contains("max_age: 604800"));
    }

    #[test]
    fn test_generate_tlsrpt_record() {
        let record = generate_tlsrpt_record(&["tls@example.com", "admin@example.com"]);
        assert!(record.contains("v=TLSRPTv1"));
        assert!(record.contains("mailto:tls@example.com"));
        assert!(record.contains("mailto:admin@example.com"));
    }

    #[test]
    fn test_parse_sts_dns_record() {
        let record = parse_sts_dns_record("v=STSv1; id=20250101");
        assert_eq!(record.version, "STSv1");
        assert_eq!(record.id, "20250101");
    }

    #[test]
    fn test_parse_mta_sts_policy() {
        let body = "version: STSv1\nmode: enforce\nmx: mx1.example.com\nmx: mx2.example.com\nmax_age: 604800";
        let policy = parse_mta_sts_policy(body);
        assert_eq!(policy.mode, MtaStsMode::Enforce);
        assert_eq!(policy.mx.len(), 2);
        assert_eq!(policy.max_age, 604800);
    }

    #[test]
    fn test_parse_tlsrpt_record() {
        let record = parse_tlsrpt_record("v=TLSRPTv1; rua=mailto:tls@example.com");
        assert_eq!(record.version, "TLSRPTv1");
        assert_eq!(record.rua.len(), 1);
        assert!(record.rua[0].contains("tls@example.com"));
    }
}
