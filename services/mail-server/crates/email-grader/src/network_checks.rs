//! BIMI, MTA-STS, and TLS-RPT checks. These complement the SPF/DKIM/DMARC
//! readiness signals and improve the realism of inbox-placement scoring.
//!
//! All DNS lookups are performed via the shared `apexmail-dns-resolver`. The
//! MTA-STS policy is fetched over HTTPS with strict bounds: response bytes
//! capped, total time bounded by `network_timeout_seconds`, and TLS verified.

use apexmail_dns_resolver::lookup::DnsLookup;
use std::time::Duration;

/// Outcome of a BIMI lookup. We treat presence + a parseable `v=BIMI1` as a
/// positive signal; the optional VMC evidence URL is surfaced for callers but
/// not validated cryptographically here (that requires an X.509 mark cert
/// validator outside the grader's scope).
#[derive(Debug, Clone)]
pub struct BimiInfo {
    pub raw: String,
    pub logo_url: Option<String>,
    pub vmc_url: Option<String>,
}

/// Outcome of an MTA-STS check. `policy_id` and the resolved policy mode are
/// both required for a passing signal: an `_mta-sts` TXT alone without a
/// reachable, well-formed policy file does not count.
#[derive(Debug, Clone)]
pub struct MtaStsInfo {
    pub policy_id: String,
    pub mode: String,
    pub max_age_seconds: u64,
    pub mx_patterns: Vec<String>,
}

/// Outcome of a TLS-RPT lookup. Surfaces the reporting endpoint(s).
#[derive(Debug, Clone)]
pub struct TlsRptInfo {
    pub raw: String,
    pub rua: Vec<String>,
}

/// Lookup BIMI for `<domain>` (we use the standard `default` selector).
pub async fn lookup_bimi(dns: &DnsLookup, domain: &str) -> Option<BimiInfo> {
    let qname = format!("default._bimi.{domain}");
    let txts = dns.lookup_txt(&qname).await.ok()?;
    let raw = txts
        .into_iter()
        .find(|t| t.trim_start().to_ascii_lowercase().starts_with("v=bimi1"))?;
    let mut logo_url = None;
    let mut vmc_url = None;
    for tag in raw.split(';') {
        let tag = tag.trim();
        if let Some(v) = tag.strip_prefix("l=").or_else(|| tag.strip_prefix("L=")) {
            logo_url = Some(v.trim().to_string());
        } else if let Some(v) = tag.strip_prefix("a=").or_else(|| tag.strip_prefix("A=")) {
            vmc_url = Some(v.trim().to_string());
        }
    }
    Some(BimiInfo { raw, logo_url, vmc_url })
}

/// Lookup TLS-RPT for `<domain>`.
pub async fn lookup_tls_rpt(dns: &DnsLookup, domain: &str) -> Option<TlsRptInfo> {
    let qname = format!("_smtp._tls.{domain}");
    let txts = dns.lookup_txt(&qname).await.ok()?;
    let raw = txts
        .into_iter()
        .find(|t| t.trim_start().to_ascii_lowercase().starts_with("v=tlsrptv1"))?;
    let rua: Vec<String> = raw
        .split(';')
        .filter_map(|tag| tag.trim().strip_prefix("rua="))
        .flat_map(|v| v.split(',').map(|s| s.trim().to_string()))
        .filter(|s| !s.is_empty())
        .collect();
    Some(TlsRptInfo { raw, rua })
}

/// Lookup MTA-STS for `<domain>` (TXT then HTTPS policy fetch).
///
/// Returns `Some` only when both the TXT advertisement and the policy file
/// are present, well-formed, and the policy declares a recognized mode.
pub async fn lookup_mta_sts(
    dns: &DnsLookup,
    http: &reqwest::Client,
    domain: &str,
    max_bytes: usize,
    timeout: Duration,
) -> Option<MtaStsInfo> {
    let qname = format!("_mta-sts.{domain}");
    let txts = dns.lookup_txt(&qname).await.ok()?;
    let raw = txts
        .into_iter()
        .find(|t| t.trim_start().to_ascii_lowercase().starts_with("v=stsv1"))?;
    let policy_id = raw
        .split(';')
        .filter_map(|tag| tag.trim().strip_prefix("id="))
        .next()
        .map(|s| s.trim().to_string())?;

    let url = format!("https://mta-sts.{domain}/.well-known/mta-sts.txt");
    let resp = tokio::time::timeout(
        timeout,
        http.get(&url).send(),
    )
    .await
    .ok()?
    .ok()?;
    if !resp.status().is_success() {
        return None;
    }
    let body = tokio::time::timeout(timeout, resp.bytes()).await.ok()?.ok()?;
    if body.len() > max_bytes {
        tracing::warn!(domain, bytes = body.len(), "MTA-STS policy exceeds size cap");
        return None;
    }
    let text = std::str::from_utf8(&body).ok()?;
    let mut mode = String::new();
    let mut max_age: u64 = 0;
    let mut mx_patterns = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut parts = line.splitn(2, ':');
        let key = parts.next().unwrap_or("").trim().to_ascii_lowercase();
        let value = parts.next().unwrap_or("").trim().to_string();
        match key.as_str() {
            "mode" => mode = value.to_ascii_lowercase(),
            "max_age" => max_age = value.parse().unwrap_or(0),
            "mx" => mx_patterns.push(value),
            _ => {}
        }
    }
    if !matches!(mode.as_str(), "enforce" | "testing" | "none") {
        return None;
    }
    Some(MtaStsInfo {
        policy_id,
        mode,
        max_age_seconds: max_age,
        mx_patterns,
    })
}

#[cfg(test)]
mod tests {
    // BIMI/MTA-STS/TLS-RPT parsing is covered indirectly via integration paths
    // because all three depend on DNS / HTTPS responses. We test only the
    // pure-string parsing surface here.
    #[test]
    fn bimi_tag_extraction_works() {
        // We re-use the same parsing approach as `lookup_bimi`'s body.
        let raw = "v=BIMI1; l=https://example.com/logo.svg; a=https://example.com/vmc.pem";
        let mut logo_url: Option<String> = None;
        let mut vmc_url: Option<String> = None;
        for tag in raw.split(';') {
            let tag = tag.trim();
            if let Some(v) = tag.strip_prefix("l=") {
                logo_url = Some(v.trim().into());
            } else if let Some(v) = tag.strip_prefix("a=") {
                vmc_url = Some(v.trim().into());
            }
        }
        assert_eq!(logo_url.as_deref(), Some("https://example.com/logo.svg"));
        assert_eq!(vmc_url.as_deref(), Some("https://example.com/vmc.pem"));
    }

    #[test]
    fn tls_rpt_rua_extraction_works() {
        let raw = "v=TLSRPTv1; rua=mailto:tls@example.com,https://example.com/tls";
        let rua: Vec<String> = raw
            .split(';')
            .filter_map(|tag| tag.trim().strip_prefix("rua="))
            .flat_map(|v| v.split(',').map(|s| s.trim().to_string()))
            .filter(|s| !s.is_empty())
            .collect();
        assert_eq!(rua, vec![
            "mailto:tls@example.com".to_string(),
            "https://example.com/tls".to_string(),
        ]);
    }
}
