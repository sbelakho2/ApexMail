//! BIMI, MTA-STS, and TLS-RPT checks. These complement the SPF/DKIM/DMARC
//! readiness signals and improve the realism of inbox-placement scoring.
//!
//! All DNS lookups are performed via the shared `apexmail-dns-resolver`. The
//! MTA-STS policy fetch is SSRF-hardened (mirrors the worker's
//! `webhook/ssrf.rs`): the user-supplied domain is validated syntactically,
//! `mta-sts.<domain>` is resolved up front and every resolved IP is checked
//! against the private/reserved blocklist, the connection is pinned to those
//! validated IPs, redirects are disabled, and response bytes/time are capped.

use apexmail_dns_resolver::lookup::DnsLookup;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
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
    Some(BimiInfo {
        raw,
        logo_url,
        vmc_url,
    })
}

/// Lookup TLS-RPT for `<domain>`.
pub async fn lookup_tls_rpt(dns: &DnsLookup, domain: &str) -> Option<TlsRptInfo> {
    let qname = format!("_smtp._tls.{domain}");
    let txts = dns.lookup_txt(&qname).await.ok()?;
    let raw = txts.into_iter().find(|t| {
        t.trim_start()
            .to_ascii_lowercase()
            .starts_with("v=tlsrptv1")
    })?;
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
///
/// # SSRF hardening
///
/// `<domain>` is user-supplied, so before any socket is opened we:
/// 1. reject syntactically unsafe domains (IP literals, dotless, non-LDH);
/// 2. resolve `mta-sts.<domain>` ourselves and reject the target if ANY
///    resolved IP is private/loopback/link-local/reserved (the worker's
///    `webhook/ssrf.rs` blocklist, including cloud-metadata and CGNAT);
/// 3. pin the HTTP client to exactly those validated IPs (`resolve_to_addrs`)
///    so a DNS rebinding between check and connect cannot redirect the fetch;
/// 4. disable redirects and keep the existing size/timeout caps.
pub async fn lookup_mta_sts(
    dns: &DnsLookup,
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

    // (1) syntactic validation of the (user-supplied) domain.
    if let Err(reason) = validate_mta_sts_domain(domain) {
        tracing::warn!(domain, reason, "MTA-STS fetch rejected: unsafe domain");
        return None;
    }

    // (2) resolve first, reject private/reserved targets.
    let host = format!("mta-sts.{domain}");
    let ips = resolve_mta_sts_ips(dns, &host).await;
    if !mta_sts_target_ips_are_safe(&ips) {
        tracing::warn!(
            domain,
            ?ips,
            "MTA-STS fetch rejected: host resolves to private/reserved or no address"
        );
        return None;
    }

    // (3) pinned client: connect only to the addresses we just validated.
    let addrs: Vec<SocketAddr> = ips.iter().map(|ip| SocketAddr::new(*ip, 443)).collect();
    let pinned = reqwest::Client::builder()
        .user_agent("ApexMail-Grader/1.0")
        .timeout(timeout)
        // (4) redirects off: a redirect could bounce us anywhere.
        .redirect(reqwest::redirect::Policy::none())
        .resolve_to_addrs(&host, &addrs)
        .build()
        .map_err(|e| tracing::warn!(error = %e, "MTA-STS pinned client build failed"))
        .ok()?;

    let url = format!("https://{host}/.well-known/mta-sts.txt");
    let resp = tokio::time::timeout(timeout, pinned.get(&url).send())
        .await
        .ok()?
        .ok()?;
    if !resp.status().is_success() {
        return None;
    }
    let body = tokio::time::timeout(timeout, resp.bytes())
        .await
        .ok()?
        .ok()?;
    if body.len() > max_bytes {
        tracing::warn!(
            domain,
            bytes = body.len(),
            "MTA-STS policy exceeds size cap"
        );
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

// ─── SSRF hardening helpers (mirror of worker-processors webhook/ssrf.rs) ──

/// Syntactic validation of a user-supplied MTA-STS domain: LDH labels only,
/// at least two labels (no dotless hosts), length bounds, and no IP literals
/// (including all-numeric TLDs like `2130706433`).
pub(crate) fn validate_mta_sts_domain(domain: &str) -> Result<(), &'static str> {
    if domain.is_empty() {
        return Err("empty domain");
    }
    if domain.len() > 253 {
        return Err("domain exceeds 253 chars");
    }
    if domain.parse::<Ipv4Addr>().is_ok() {
        return Err("IPv4 literal domain");
    }
    // Anything IPv6-ish contains ':' which LDH rejects below; the parse is a
    // belt-and-braces check for bracketed forms.
    if domain.contains(':') || domain.contains('[') {
        return Err("IPv6 literal / bracketed host");
    }

    let labels: Vec<&str> = domain.split('.').collect();
    if labels.len() < 2 {
        return Err("dotless domain");
    }
    for label in &labels {
        if label.is_empty() || label.len() > 63 {
            return Err("invalid label length");
        }
        let mut chars = label.chars();
        let first = chars.next().expect("non-empty checked above");
        if !first.is_ascii_alphanumeric() || !label.ends_with(|c: char| c.is_ascii_alphanumeric()) {
            return Err("label must start and end with alphanumeric");
        }
        if !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            return Err("label contains non-LDH characters");
        }
        // An all-numeric final label is an IP-literal shape (or a numeric
        // TLD): reject so `1.2.3.4`-style and `com.123` never reach a fetch.
        if label.chars().all(|c| c.is_ascii_digit()) {
            return Err("all-numeric label (IP-literal shape)");
        }
    }
    Ok(())
}

/// Resolve the A + AAAA records for the MTA-STS policy host. Lookup errors
/// are flattened to "no addresses" — the caller then refuses to fetch.
async fn resolve_mta_sts_ips(dns: &DnsLookup, host: &str) -> Vec<IpAddr> {
    let (a, aaaa) = tokio::join!(dns.lookup_a(host), dns.lookup_aaaa(host));
    let parse = |records: Result<Vec<String>, _>| {
        records
            .unwrap_or_default()
            .iter()
            .filter_map(|r| r.parse::<IpAddr>().ok())
            .collect::<Vec<IpAddr>>()
    };
    let mut ips = parse(a);
    ips.extend(parse(aaaa));
    ips
}

/// The fetch proceeds only when the resolution is non-empty and every
/// resolved address is public.
pub(crate) fn mta_sts_target_ips_are_safe(ips: &[IpAddr]) -> bool {
    !ips.is_empty() && ips.iter().all(|ip| !is_private_ip(ip))
}

/// Check if an IP address is private/internal (worker webhook/ssrf.rs list).
pub(crate) fn is_private_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => is_private_ipv4(ip),
        IpAddr::V6(ip) => is_private_ipv6(ip),
    }
}

/// Check if an IPv4 address is private/internal.
fn is_private_ipv4(ip: &Ipv4Addr) -> bool {
    let o = ip.octets();

    // Loopback:127.0.0.0/8
    if o[0] == 127 {
        return true;
    }
    // Private:10.0.0.0/8
    if o[0] == 10 {
        return true;
    }
    // Private:172.16.0.0/12
    if o[0] == 172 && (o[1] >= 16 && o[1] <= 31) {
        return true;
    }
    // Private:192.168.0.0/16
    if o[0] == 192 && o[1] == 168 {
        return true;
    }
    // Link-local:169.254.0.0/16 (includes cloud metadata endpoints)
    if o[0] == 169 && o[1] == 254 {
        return true;
    }
    // Broadcast/unspecified
    if ip.is_broadcast() || ip.is_unspecified() {
        return true;
    }
    // Documentation:192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24
    if (o[0] == 192 && o[1] == 0 && o[2] == 2)
        || (o[0] == 198 && o[1] == 51 && o[2] == 100)
        || (o[0] == 203 && o[1] == 0 && o[2] == 113)
    {
        return true;
    }
    // Carrier-grade NAT:100.64.0.0/10
    if o[0] == 100 && (o[1] >= 64 && o[1] <= 127) {
        return true;
    }

    false
}

/// Check if an IPv6 address is private/internal, including IPv4-derived
/// forms (6to4, Teredo, IPv4-compatible, IPv4-mapped).
fn is_private_ipv6(ip: &Ipv6Addr) -> bool {
    if ip.is_loopback() || ip.is_unspecified() {
        return true;
    }

    let s = ip.segments();

    // Link-local:fe80::/10
    if s[0] & 0xffc0 == 0xfe80 {
        return true;
    }
    // Unique local:fc00::/7
    if s[0] & 0xfe00 == 0xfc00 {
        return true;
    }
    // Site-local (deprecated):fec0::/10
    if s[0] & 0xffc0 == 0xfec0 {
        return true;
    }
    // 6to4:2002::/16 — embedded IPv4 in segments 1-2
    if s[0] == 0x2002 {
        let embedded = Ipv4Addr::new(
            (s[1] >> 8) as u8,
            (s[1] & 0xff) as u8,
            (s[2] >> 8) as u8,
            (s[2] & 0xff) as u8,
        );
        if is_private_ipv4(&embedded) {
            return true;
        }
    }
    // Teredo:2001:0000::/32 — embedded IPv4 in the last 32 bits (XORed)
    if s[0] == 0x2001 && s[1] == 0x0000 {
        let embedded = Ipv4Addr::new(
            (s[6] >> 8) as u8 ^ 0xff,
            (s[6] & 0xff) as u8 ^ 0xff,
            (s[7] >> 8) as u8 ^ 0xff,
            (s[7] & 0xff) as u8 ^ 0xff,
        );
        if is_private_ipv4(&embedded) {
            return true;
        }
    }
    // IPv4-compatible (deprecated):::x/96
    if s[0..5] == [0, 0, 0, 0, 0] && s[5] == 0 {
        let embedded = Ipv4Addr::new(
            (s[6] >> 8) as u8,
            (s[6] & 0xff) as u8,
            (s[7] >> 8) as u8,
            (s[7] & 0xff) as u8,
        );
        if is_private_ipv4(&embedded) {
            return true;
        }
    }
    // IPv4-mapped addresses:check the embedded IPv4
    if let Some(ipv4) = ip.to_ipv4_mapped() {
        return is_private_ipv4(&ipv4);
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    // BIMI/MTA-STS/TLS-RPT parsing is covered indirectly via integration paths
    // because all three depend on DNS / HTTPS responses. We test only the
    // pure-string parsing surface here.

    // ── SSRF hardening (mirror of the worker's webhook/ssrf.rs) ────────

    #[test]
    fn mta_sts_domain_validation_rejects_ip_literals_and_dotless() {
        // IPv4 literals (even decimal/octal-ish forms via all-numeric TLD).
        for bad in [
            "127.0.0.1",
            "10.1.2.3",
            "192.168.0.1",
            "169.254.169.254",
            "8.8.8.8",
            "0.0.0.0",
            "255.255.255.255",
            "[::1]",
            "::1",
            "2130706433", // dotless + all-numeric
        ] {
            assert!(
                validate_mta_sts_domain(bad).is_err(),
                "IP-literal/dotless domain must be rejected: {bad}"
            );
        }

        // Dotless / malformed hostnames.
        for bad in ["localhost", "", "exa mple.com", "-bad.com", "bad-.com"] {
            assert!(validate_mta_sts_domain(bad).is_err(), "must reject {bad:?}");
        }

        // Well-formed public LDH domains pass.
        for good in [
            "example.com",
            "gmail.com",
            "mail.example.co.uk",
            "a-b.example.org",
        ] {
            assert!(validate_mta_sts_domain(good).is_ok(), "must accept {good}");
        }

        // Labels must be LDH only.
        assert!(validate_mta_sts_domain("under_score.example.com").is_err());
        assert!(validate_mta_sts_domain("example.com\n.mta-sts").is_err());
    }

    #[test]
    fn mta_sts_ip_guard_rejects_private_and_reserved_ranges() {
        // Everything the worker's SSRF guard blocks (webhook/ssrf.rs).
        let rejected = [
            Ipv4Addr::new(127, 0, 0, 1),       // loopback
            Ipv4Addr::new(10, 0, 0, 1),        // 10/8
            Ipv4Addr::new(172, 16, 0, 1),      // 172.16/12
            Ipv4Addr::new(192, 168, 1, 1),     // 192.168/16
            Ipv4Addr::new(169, 254, 169, 254), // link-local / cloud metadata
            Ipv4Addr::new(0, 0, 0, 0),         // unspecified
            Ipv4Addr::new(255, 255, 255, 255), // broadcast
            Ipv4Addr::new(192, 0, 2, 1),       // TEST-NET-1
            Ipv4Addr::new(198, 51, 100, 1),    // TEST-NET-2
            Ipv4Addr::new(203, 0, 113, 1),     // TEST-NET-3
            Ipv4Addr::new(100, 64, 0, 1),      // CGNAT 100.64/10
            Ipv4Addr::new(100, 127, 255, 254), // CGNAT top edge
        ];
        for ip in rejected {
            assert!(is_private_ip(&IpAddr::V4(ip)), "must reject {ip}");
        }

        let rejected_v6 = [
            Ipv6Addr::LOCALHOST,
            Ipv6Addr::UNSPECIFIED,
            Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1), // link-local
            Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 1), // unique local
            Ipv6Addr::new(0x2002, 0x0a00, 0x0001, 0, 0, 0, 0, 1), // 6to4 embedding 10.0.0.1
        ];
        for ip in rejected_v6 {
            assert!(is_private_ip(&IpAddr::V6(ip)), "must reject {ip}");
        }

        // IPv4-mapped IPv6 of a private address.
        let mapped = Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0xc0a8, 0x0101); // ::ffff:192.168.1.1
        assert!(is_private_ip(&IpAddr::V6(mapped)));

        // Public addresses pass.
        let allowed = [
            IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
            IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
            IpAddr::V6(Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888)),
        ];
        for ip in allowed {
            assert!(!is_private_ip(&ip), "must allow {ip}");
        }
    }

    #[test]
    fn mta_sts_resolved_target_ips_gate() {
        // The exact predicate the fetch path applies to the resolved set.
        let ok = mta_sts_target_ips_are_safe(&[
            IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
            IpAddr::V6(Ipv6Addr::new(
                0x2607, 0xf8b0, 0x4005, 0x805, 0, 0, 0, 0x200e,
            )),
        ]);
        assert!(ok, "all-public resolution must pass");

        // Any private IP in the set vetoes the fetch (rebinding-style mix).
        assert!(!mta_sts_target_ips_are_safe(&[
            IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
        ]));
        assert!(!mta_sts_target_ips_are_safe(&[IpAddr::V4(Ipv4Addr::new(
            169, 254, 169, 254
        ))]));
        assert!(!mta_sts_target_ips_are_safe(&[IpAddr::V4(Ipv4Addr::new(
            10, 1, 2, 3
        ))]));
        // Empty resolution (NXDOMAIN) must not fall through to a fetch.
        assert!(!mta_sts_target_ips_are_safe(&[]));
    }

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
        assert_eq!(
            rua,
            vec![
                "mailto:tls@example.com".to_string(),
                "https://example.com/tls".to_string(),
            ]
        );
    }
}
