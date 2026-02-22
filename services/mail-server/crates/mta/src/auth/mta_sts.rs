//! MTA‑STS – SMTP MTA Strict Transport Security (RFC 8461) + TLSRPT (RFC 8460).

use reqwest::Client;
use serde::{Deserialize, Serialize};
use tracing::{debug, warn};
use trust_dns_resolver::config::{ResolverConfig, ResolverOpts};
use trust_dns_resolver::TokioAsyncResolver;

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

    let resolver = TokioAsyncResolver::tokio(
        ResolverConfig::default(),
        ResolverOpts::default(),
    );

    // 1. Check DNS TXT record at _mta-sts.<domain>
    let sts_name = format!("_mta-sts.{domain}");
    match resolver.txt_lookup(&sts_name).await {
        Ok(records) => {
            for record in records.iter() {
                let txt = record.to_string();
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

    match client.get(&policy_url).send().await {
        Ok(resp) => {
            if !resp.status().is_success() {
                result.errors.push(format!(
                    "Policy fetch failed with status {}",
                    resp.status()
                ));
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
            result.recommendations.push(format!(
                "Host MTA-STS policy at {policy_url}"
            ));
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
    let mut lines = vec![
        "version: STSv1".to_string(),
        format!("mode: {mode_str}"),
    ];
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
    let resolver = TokioAsyncResolver::tokio(
        ResolverConfig::default(),
        ResolverOpts::default(),
    );

    let name = format!("_smtp._tls.{domain}");
    let records = resolver.txt_lookup(&name).await.ok()?;

    for record in records.iter() {
        let txt = record.to_string();
        if txt.starts_with("v=TLSRPTv1") {
            return Some(parse_tlsrpt_record(&txt));
        }
    }
    None
}

// ── parsers ────────────────────────────────────────────────────────────────────

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
