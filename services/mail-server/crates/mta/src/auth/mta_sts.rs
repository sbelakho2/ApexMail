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

/// Verify MTA‑STS for a domain (delegates to the injected-seam variant).
/// Verify MTA-STS for a domain (shared production resolver/client, RFC 8461
/// policy URL).
pub async fn verify_mta_sts(domain: &str) -> MtaStsVerificationResult {
    verify_mta_sts_with(
        &MTA_STS_RESOLVER,
        MTA_STS_CLIENT.as_ref(),
        domain,
        &format!("https://mta-sts.{domain}/.well-known/mta-sts.txt"),
    )
    .await
}

/// Verify MTA-STS against an explicit resolver, HTTP client and policy URL
/// (tests point all three at loopback mocks; production callers use
/// [`verify_mta_sts`]).
pub async fn verify_mta_sts_with(
    resolver: &TokioResolver,
    client: Option<&Client>,
    domain: &str,
    policy_url: &str,
) -> MtaStsVerificationResult {
    let mut result = MtaStsVerificationResult {
        supported: false,
        mode: MtaStsMode::None,
        policy: None,
        dns_record: None,
        errors: Vec::new(),
        warnings: Vec::new(),
        recommendations: Vec::new(),
    };

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

    // 2. Fetch the policy from the well-known URL.
    let Some(client) = client else {
        result
            .errors
            .push("MTA-STS HTTP client unavailable".to_string());
        return result;
    };

    match client.get(policy_url).send().await {
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

/// Verify TLSRPT record for a domain (shared production resolver).
pub async fn verify_tlsrpt(domain: &str) -> Option<TlsRptRecord> {
    verify_tlsrpt_with(&MTA_STS_RESOLVER, domain).await
}

/// Verify TLSRPT against an explicit resolver (tests inject a loopback
/// mock).
pub async fn verify_tlsrpt_with(resolver: &TokioResolver, domain: &str) -> Option<TlsRptRecord> {
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

#[cfg(test)]
mod verify_wire_tests {
    //! `verify_mta_sts_with` / `verify_tlsrpt_with` against a loopback UDP
    //! DNS mock and a loopback HTTP policy host: the real resolver wire path
    //! plus every policy-fetch failure mode, with hostile record bodies.

    use super::super::test_dns::{DnsAnswer, MockDns};
    use super::*;

    use std::collections::HashMap;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    const ENFORCE_POLICY: &str =
        "version: STSv1\nmode: enforce\nmx: mx1.sts.example\nmx: mx2.sts.example\nmax_age: 604800";

    /// Minimal loopback HTTP server: answers every GET from a path-keyed
    /// table of (status, body).
    async fn http_server(
        routes: HashMap<String, (u16, String)>,
    ) -> (u16, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .unwrap();
        let port = listener.local_addr().unwrap().port();
        let routes = Arc::new(routes);
        let handle = tokio::spawn(async move {
            loop {
                let Ok((mut socket, _)) = listener.accept().await else {
                    return;
                };
                let routes = routes.clone();
                tokio::spawn(async move {
                    let mut buf = [0u8; 4096];
                    let n = socket.read(&mut buf).await.unwrap_or(0);
                    let head = String::from_utf8_lossy(&buf[..n]);
                    let path = head.split(' ').nth(1).unwrap_or("/").to_string();
                    let (status, body) = routes
                        .get(&path)
                        .cloned()
                        .unwrap_or((404, "missing".to_string()));
                    let response = format!(
                        "HTTP/1.1 {status} X\r\ncontent-type: text/plain\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = socket.write_all(response.as_bytes()).await;
                    let _ = socket.shutdown().await;
                });
            }
        });
        (port, handle)
    }

    fn txt(strings: Vec<&str>) -> DnsAnswer {
        DnsAnswer::Txt(strings.into_iter().map(|s| vec![s.to_string()]).collect())
    }

    fn client() -> reqwest::Client {
        reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .build()
            .unwrap()
    }

    #[tokio::test]
    async fn verify_mta_sts_enforce_policy_end_to_end() {
        let mut routes: HashMap<String, (u16, String)> = HashMap::new();
        routes.insert(
            "/.well-known/mta-sts.txt".into(),
            (200, ENFORCE_POLICY.into()),
        );
        let (port, server) = http_server(routes).await;

        let mut rules: HashMap<&'static str, DnsAnswer> = HashMap::new();
        rules.insert("_mta-sts.sts.example", txt(vec!["v=STSv1; id=20260101"]));
        let dns = MockDns::start(rules).await;

        let result = verify_mta_sts_with(
            &dns.resolver,
            Some(&client()),
            "sts.example",
            &format!("http://127.0.0.1:{port}/.well-known/mta-sts.txt"),
        )
        .await;
        assert!(result.supported, "errors: {:?}", result.errors);
        assert_eq!(result.mode, MtaStsMode::Enforce);
        assert!(result.errors.is_empty());
        let record = result.dns_record.expect("dns record parsed");
        assert_eq!(record.version, "STSv1");
        assert_eq!(record.id, "20260101");
        let policy = result.policy.expect("policy parsed");
        assert_eq!(policy.version, "STSv1");
        assert_eq!(policy.mx, vec!["mx1.sts.example", "mx2.sts.example"]);
        assert_eq!(policy.max_age, 604800);
        dns.stop();
        server.abort();
    }

    #[tokio::test]
    async fn verify_mta_sts_policy_mode_and_max_age_edges() {
        // Unknown mode -> MtaStsMode::None; unparseable max_age -> 0; the
        // record is still surfaced.
        let mut routes: HashMap<String, (u16, String)> = HashMap::new();
        routes.insert(
            "/.well-known/mta-sts.txt".into(),
            (200, "version: STSv1\nmode: banana\nmax_age: soon".into()),
        );
        let (port, server) = http_server(routes).await;
        let mut rules: HashMap<&'static str, DnsAnswer> = HashMap::new();
        rules.insert("_mta-sts.mode.example", txt(vec!["v=STSv1; id=x"]));
        let dns = MockDns::start(rules).await;
        let result = verify_mta_sts_with(
            &dns.resolver,
            Some(&client()),
            "mode.example",
            &format!("http://127.0.0.1:{port}/.well-known/mta-sts.txt"),
        )
        .await;
        assert!(result.supported);
        assert_eq!(result.mode, MtaStsMode::None);
        assert_eq!(result.policy.expect("policy").max_age, 0);
        dns.stop();
        server.abort();

        // `testing` mode parses to MtaStsMode::Testing.
        let mut routes: HashMap<String, (u16, String)> = HashMap::new();
        routes.insert("/p".into(), (200, "mode: testing".into()));
        let (port, server) = http_server(routes).await;
        let mut rules: HashMap<&'static str, DnsAnswer> = HashMap::new();
        rules.insert("_mta-sts.testing.example", txt(vec!["v=STSv1; id=y"]));
        let dns = MockDns::start(rules).await;
        let result = verify_mta_sts_with(
            &dns.resolver,
            Some(&client()),
            "testing.example",
            &format!("http://127.0.0.1:{port}/p"),
        )
        .await;
        assert_eq!(result.mode, MtaStsMode::Testing);
        dns.stop();
        server.abort();
    }

    #[tokio::test]
    async fn verify_mta_sts_reports_missing_records_and_lookups() {
        // An NXDOMAIN answer: recommendation + not supported (a determinate
        // negative, distinct from a resolver failure).
        let mut rules: HashMap<&'static str, DnsAnswer> = HashMap::new();
        rules.insert("_mta-sts.absent.example", DnsAnswer::Nxdomain);
        let dns = MockDns::start(rules).await;
        let result = verify_mta_sts_with(
            &dns.resolver,
            Some(&client()),
            "absent.example",
            "http://127.0.0.1:1/policy",
        )
        .await;
        assert!(!result.supported);
        assert!(
            result
                .recommendations
                .iter()
                .any(|r| r.contains("Add DNS TXT at _mta-sts.absent.example")),
            "{:?}",
            result.recommendations
        );
        assert!(result.policy.is_none());
        dns.stop();

        // DNS SERVFAIL must not be read as "no record" silently (the debug
        // arm) and must not claim support.
        let mut rules: HashMap<&'static str, DnsAnswer> = HashMap::new();
        rules.insert("_mta-sts.broken.example", DnsAnswer::Servfail);
        let dns = MockDns::start(rules).await;
        let result = verify_mta_sts_with(
            &dns.resolver,
            Some(&client()),
            "broken.example",
            "http://127.0.0.1:1/policy",
        )
        .await;
        assert!(!result.supported);
        assert!(result.dns_record.is_none());
        dns.stop();

        // A TXT record that is NOT v=STSv1 does not enable support (a
        // hostile SPF record must not be treated as an STS record).
        let mut rules: HashMap<&'static str, DnsAnswer> = HashMap::new();
        rules.insert("_mta-sts.spf.example", txt(vec!["v=spf1 -all"]));
        let dns = MockDns::start(rules).await;
        let result = verify_mta_sts_with(
            &dns.resolver,
            Some(&client()),
            "spf.example",
            "http://127.0.0.1:1/policy",
        )
        .await;
        assert!(!result.supported);
        dns.stop();
    }

    #[tokio::test]
    async fn verify_mta_sts_policy_fetch_failure_modes() {
        // HTTP error status surfaces with the status code.
        let mut routes: HashMap<String, (u16, String)> = HashMap::new();
        routes.insert("/p".into(), (500, "boom".into()));
        let (port, server) = http_server(routes).await;
        let mut rules: HashMap<&'static str, DnsAnswer> = HashMap::new();
        rules.insert("_mta-sts.http.example", txt(vec!["v=STSv1; id=z"]));
        let dns = MockDns::start(rules).await;
        let result = verify_mta_sts_with(
            &dns.resolver,
            Some(&client()),
            "http.example",
            &format!("http://127.0.0.1:{port}/p"),
        )
        .await;
        assert!(result.supported);
        assert!(
            result
                .errors
                .iter()
                .any(|e| e.contains("Policy fetch failed with status 500")),
            "{:?}",
            result.errors
        );
        assert!(result.policy.is_none());
        dns.stop();
        server.abort();

        // Connection refused: error + host-the-policy recommendation.
        let mut rules: HashMap<&'static str, DnsAnswer> = HashMap::new();
        rules.insert("_mta-sts.dead.example", txt(vec!["v=STSv1; id=z"]));
        let dns = MockDns::start(rules).await;
        let result = verify_mta_sts_with(
            &dns.resolver,
            Some(&client()),
            "dead.example",
            "http://127.0.0.1:1/policy",
        )
        .await;
        assert!(result.supported);
        assert!(result
            .errors
            .iter()
            .any(|e| e.contains("Policy fetch failed")));
        assert!(
            result
                .recommendations
                .iter()
                .any(|r| r.contains("Host MTA-STS policy at")),
            "{:?}",
            result.recommendations
        );
        dns.stop();

        // No HTTP client at all: hard error, fail closed.
        let mut rules: HashMap<&'static str, DnsAnswer> = HashMap::new();
        rules.insert("_mta-sts.dead.example", txt(vec!["v=STSv1; id=z"]));
        let dns = MockDns::start(rules).await;
        let result = verify_mta_sts_with(&dns.resolver, None, "dead.example", "http://x/p").await;
        assert!(result.supported);
        assert!(
            result
                .errors
                .iter()
                .any(|e| e.contains("MTA-STS HTTP client unavailable")),
            "{:?}",
            result.errors
        );
        dns.stop();
    }

    #[tokio::test]
    async fn verify_tlsrpt_parses_multi_address_records_and_rejects_absent() {
        let mut rules: HashMap<&'static str, DnsAnswer> = HashMap::new();
        rules.insert(
            "_smtp._tls.rpt.example",
            txt(vec![
                "v=TLSRPTv1; rua=mailto:a@x.example, mailto:b@x.example",
            ]),
        );
        rules.insert("_smtp._tls.other.example", txt(vec!["v=spf1 -all"]));
        let dns = MockDns::start(rules).await;

        let record = verify_tlsrpt_with(&dns.resolver, "rpt.example")
            .await
            .expect("TLSRPT record");
        assert_eq!(record.version, "TLSRPTv1");
        assert_eq!(
            record.rua,
            vec![
                "mailto:a@x.example".to_string(),
                "mailto:b@x.example".to_string()
            ],
            "comma-separated rua entries are split and trimmed"
        );

        // A non-TLSRPT TXT is not a report record.
        assert!(verify_tlsrpt_with(&dns.resolver, "other.example")
            .await
            .is_none());
        // No record at all -> None.
        assert!(verify_tlsrpt_with(&dns.resolver, "absent.example")
            .await
            .is_none());
        dns.stop();
    }

    #[tokio::test]
    async fn txt_record_strings_joins_chunks_and_skips_non_txt() {
        let mut rules: HashMap<&'static str, DnsAnswer> = HashMap::new();
        rules.insert(
            "chunky.test",
            DnsAnswer::Txt(vec![
                vec!["v=STSv1".to_string(), "; id=chunked".to_string()],
                vec!["second".to_string()],
            ]),
        );
        let dns = MockDns::start(rules).await;
        let lookup = dns
            .resolver
            .txt_lookup("chunky.test")
            .await
            .expect("lookup");
        assert_eq!(
            txt_record_strings(&lookup),
            vec!["v=STSv1; id=chunked".to_string(), "second".to_string()]
        );
        dns.stop();
    }

    #[tokio::test]
    async fn generated_policy_round_trips_through_the_parser() {
        for mode in [MtaStsMode::Enforce, MtaStsMode::Testing, MtaStsMode::None] {
            let body = generate_mta_sts_policy(&["mx.a.example", "mx.b.example"], mode, 3600);
            let parsed = parse_mta_sts_policy(&body);
            assert_eq!(parsed.mode, mode, "round-trip for {mode:?}");
            assert_eq!(parsed.version, "STSv1");
            assert_eq!(parsed.mx.len(), 2);
            assert_eq!(parsed.max_age, 3600);
        }
        // Unknown selector lines and blank lines are ignored.
        let parsed = parse_mta_sts_policy("\n\nnonsense: yes\nversion: STSv1\n");
        assert_eq!(parsed.version, "STSv1");
        assert_eq!(parsed.mode, MtaStsMode::None);
        assert!(parsed.mx.is_empty());
        assert_eq!(parsed.max_age, 0);
    }

    /// The policy host is contacted exactly once per verification (no retry
    /// storm behind one verification call).
    #[tokio::test]
    async fn policy_host_is_fetched_once_per_verification() {
        let hits = Arc::new(AtomicUsize::new(0));
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .unwrap();
        let port = listener.local_addr().unwrap().port();
        let hits_server = hits.clone();
        let server = tokio::spawn(async move {
            loop {
                let Ok((mut socket, _)) = listener.accept().await else {
                    return;
                };
                let hits = hits_server.clone();
                tokio::spawn(async move {
                    let mut buf = [0u8; 4096];
                    let _ = socket.read(&mut buf).await;
                    hits.fetch_add(1, Ordering::SeqCst);
                    let body = ENFORCE_POLICY;
                    let response = format!(
                        "HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = socket.write_all(response.as_bytes()).await;
                    let _ = socket.shutdown().await;
                });
            }
        });
        let mut rules: HashMap<&'static str, DnsAnswer> = HashMap::new();
        rules.insert("_mta-sts.once.example", txt(vec!["v=STSv1; id=1"]));
        let dns = MockDns::start(rules).await;
        let result = verify_mta_sts_with(
            &dns.resolver,
            Some(&client()),
            "once.example",
            &format!("http://127.0.0.1:{port}/policy"),
        )
        .await;
        assert!(result.supported);
        assert_eq!(result.mode, MtaStsMode::Enforce);
        assert_eq!(hits.load(Ordering::SeqCst), 1);
        dns.stop();
        server.abort();
    }
}
