//! # DDoS Protection Middleware for Axum
//!
//! Integrates the DDoS protection system with the Axum HTTP framework.

use std::net::IpAddr;
use std::sync::Arc;

use crate::{DdosProtector, ProtectionDecision, RequestContext};

/// State wrapper for the DDoS protector in Axum
#[derive(Clone)]
pub struct DdosMiddlewareState {
    /// The DDoS protector instance
    pub protector: Arc<DdosProtector>,
}

/// Extract a `RequestContext` from request metadata.
/// In a real Axum integration, this would read from `axum::extract::ConnectInfo`,
/// headers, etc. Here we provide a builder pattern for constructing it.
pub struct RequestContextBuilder {
    ip: IpAddr,
    path: String,
    method: String,
    tls_fingerprint: Option<String>,
    h2_fingerprint: Option<String>,
    user_agent: Option<String>,
    body_size: usize,
    tenant_id: Option<String>,
    api_key_id: Option<String>,
}

impl RequestContextBuilder {
    /// Create a new builder with required fields
    pub fn new(ip: IpAddr, path: &str, method: &str) -> Self {
        Self {
            ip,
            path: path.to_string(),
            method: method.to_string(),
            tls_fingerprint: None,
            h2_fingerprint: None,
            user_agent: None,
            body_size: 0,
            tenant_id: None,
            api_key_id: None,
        }
    }

    /// Set TLS fingerprint
    pub fn tls_fingerprint(mut self, fp: &str) -> Self {
        self.tls_fingerprint = Some(fp.to_string());
        self
    }

    /// Set HTTP/2 fingerprint
    pub fn h2_fingerprint(mut self, fp: &str) -> Self {
        self.h2_fingerprint = Some(fp.to_string());
        self
    }

    /// Set User-Agent
    pub fn user_agent(mut self, ua: &str) -> Self {
        self.user_agent = Some(ua.to_string());
        self
    }

    /// Set request body size
    pub fn body_size(mut self, size: usize) -> Self {
        self.body_size = size;
        self
    }

    /// Set tenant ID
    pub fn tenant_id(mut self, id: &str) -> Self {
        self.tenant_id = Some(id.to_string());
        self
    }

    /// Set API key ID
    pub fn api_key_id(mut self, id: &str) -> Self {
        self.api_key_id = Some(id.to_string());
        self
    }

    /// Build the `RequestContext`
    pub fn build(self) -> RequestContext {
        RequestContext {
            ip: self.ip,
            path: self.path,
            method: self.method,
            tls_fingerprint: self.tls_fingerprint,
            h2_fingerprint: self.h2_fingerprint,
            user_agent: self.user_agent,
            body_size: self.body_size,
            tenant_id: self.tenant_id,
            api_key_id: self.api_key_id,
        }
    }
}

/// Result of DDoS middleware evaluation
#[derive(Debug, Clone)]
pub enum MiddlewareAction {
    /// Allow the request through
    Allow,
    /// Challenge the client (return challenge response)
    Challenge {
        /// HTTP status to return (typically 429 or 403)
        status: u16,
        /// Response body (JSON with challenge)
        body: String,
    },
    /// Rate limit the request
    RateLimit {
        /// HTTP status (429)
        status: u16,
        /// Retry-After header value in seconds
        retry_after_secs: u64,
    },
    /// Block the request
    Block {
        /// HTTP status (403)
        status: u16,
    },
}

/// Evaluate a request through the DDoS protection system and return
/// the appropriate middleware action.
pub async fn evaluate_request(protector: &DdosProtector, ctx: &RequestContext) -> MiddlewareAction {
    match protector.evaluate(ctx).await {
        ProtectionDecision::Allow => MiddlewareAction::Allow,

        ProtectionDecision::Challenge(challenge) => {
            let body = format!(
                r#"{{"challenge_type":"{}","message":"Challenge required"}}"#,
                match &challenge {
                    crate::decision::Challenge::Js(_) => "js",
                    crate::decision::Challenge::Pow(_) => "pow",
                    crate::decision::Challenge::Cookie(_) => "cookie",
                    crate::decision::Challenge::Captcha(_) => "captcha",
                    crate::decision::Challenge::None => "none",
                    crate::decision::Challenge::Blocked => "blocked",
                }
            );
            MiddlewareAction::Challenge { status: 429, body }
        }

        ProtectionDecision::RateLimit { retry_after } => MiddlewareAction::RateLimit {
            status: 429,
            retry_after_secs: retry_after.as_secs(),
        },

        ProtectionDecision::Block => MiddlewareAction::Block { status: 403 },
    }
}

/// IP extraction helper — extracts the client IP securely.
///
/// SECURITY MODEL (mirrors `api-server`'s `extract_public_client_ip`):
///
/// * The socket peer address is the client identity UNLESS the peer itself
///   is a configured trusted proxy (see [`TrustedProxyList`]).
/// * Forwarded headers (`X-Forwarded-For`, `X-Real-IP`, `CF-Connecting-IP`)
///   are client-controlled and therefore only honored when received
///   directly from a trusted proxy.
/// * For `X-Forwarded-For` behind a trusted proxy chain, the RIGHTMOST
///   entry that is not itself a trusted proxy is used. Leftmost entries
///   are trivially spoofable
///   (`X-Forwarded-For: 1.2.3.4, real-client, trusted-proxy`).
/// * With an empty trusted list (the default) headers are NEVER trusted —
///   a direct client sending `X-Real-IP`/`X-Forwarded-For` is identified by
///   its socket address.
///
/// Priority when the peer is a trusted proxy:
/// 1. `X-Forwarded-For` — rightmost untrusted entry
/// 2. `X-Real-IP`
/// 3. `CF-Connecting-IP` (Cloudflare)
/// 4. The proxy's own address
pub fn extract_client_ip_trusted(
    x_real_ip: Option<&str>,
    x_forwarded_for: Option<&str>,
    cf_connecting_ip: Option<&str>,
    direct_ip: IpAddr,
    trusted: &TrustedProxyList,
) -> IpAddr {
    let direct_ip = normalise_ip(direct_ip);

    // The socket peer is the identity unless it is a configured proxy.
    if !trusted.contains(direct_ip) {
        return direct_ip;
    }

    // Peer is a trusted proxy: walk XFF right-to-left. The rightmost entry
    // was appended by the closest proxy, so the first untrusted address
    // from the right is the real client IP.
    if let Some(xff) = x_forwarded_for {
        for part in xff.split(',').rev() {
            if let Ok(ip) = part.trim().parse::<IpAddr>() {
                let ip = normalise_ip(ip);
                if !trusted.contains(ip) {
                    return ip;
                }
            }
        }
        // All XFF entries were trusted proxies (multi-hop internal chain) —
        // fall through to the single-value headers.
    }

    if let Some(ip_str) = x_real_ip {
        if let Ok(ip) = ip_str.trim().parse::<IpAddr>() {
            return normalise_ip(ip);
        }
    }

    if let Some(ip_str) = cf_connecting_ip {
        if let Ok(ip) = ip_str.trim().parse::<IpAddr>() {
            return normalise_ip(ip);
        }
    }

    direct_ip
}

/// Backward-compatible 4-argument wrapper around
/// [`extract_client_ip_trusted`].
///
/// Uses the process-wide trusted-proxy configuration (env
/// `DDOS_TRUSTED_PROXIES`, default empty — headers are never trusted).
/// Previously this function honored `X-Real-IP` and the LEFTMOST
/// `X-Forwarded-For` entry unconditionally, which allowed any client to
/// spoof its identity for reputation, session tracking and blocklisting.
pub fn extract_client_ip(
    x_real_ip: Option<&str>,
    x_forwarded_for: Option<&str>,
    cf_connecting_ip: Option<&str>,
    direct_ip: IpAddr,
) -> IpAddr {
    static TRUSTED: once_cell::sync::Lazy<TrustedProxyList> =
        once_cell::sync::Lazy::new(TrustedProxyList::from_env);
    extract_client_ip_trusted(
        x_real_ip,
        x_forwarded_for,
        cf_connecting_ip,
        direct_ip,
        &TRUSTED,
    )
}

/// Process-wide trusted proxy configuration for [`extract_client_ip`].
///
/// Parsed once from the `DDOS_TRUSTED_PROXIES` environment variable:
/// a comma-separated list of IPs or CIDR networks
/// (e.g. `10.0.0.0/8,192.168.1.5,fd00::/8`). Default: empty — forwarded
/// headers are never trusted.
#[derive(Debug, Clone, Default)]
pub struct TrustedProxyList {
    networks: Vec<CidrNetwork>,
}

#[derive(Debug, Clone, Copy)]
enum CidrNetwork {
    V4 { net: u32, prefix: u8 },
    V6 { net: u128, prefix: u8 },
}

impl TrustedProxyList {
    /// Parse a trusted proxy list from raw entries (IPs or CIDR networks).
    /// Invalid entries are ignored with a warning.
    pub fn parse<'a, I>(entries: I) -> Self
    where
        I: IntoIterator<Item = &'a str>,
    {
        let mut networks = Vec::new();
        for entry in entries {
            let trimmed = entry.trim();
            if trimmed.is_empty() {
                continue;
            }
            if let Some(net) = CidrNetwork::parse(trimmed) {
                networks.push(net);
            } else {
                tracing::warn!(value = %trimmed, "Ignoring invalid DDOS_TRUSTED_PROXIES entry");
            }
        }
        Self { networks }
    }

    /// Load from the `DDOS_TRUSTED_PROXIES` environment variable.
    pub fn from_env() -> Self {
        match std::env::var("DDOS_TRUSTED_PROXIES") {
            Ok(val) => Self::parse(val.split(',')),
            Err(_) => Self::default(),
        }
    }

    /// True when no proxies are configured — forwarded headers are never
    /// trusted and the socket peer is always the client identity.
    pub fn is_empty(&self) -> bool {
        self.networks.is_empty()
    }

    /// Whether `ip` belongs to one of the trusted proxy networks.
    pub fn contains(&self, ip: IpAddr) -> bool {
        let ip = normalise_ip(ip);
        self.networks.iter().any(|net| net.contains(ip))
    }
}

impl CidrNetwork {
    fn parse(s: &str) -> Option<Self> {
        let (addr_str, prefix_str) = match s.split_once('/') {
            Some((a, p)) => (a, Some(p)),
            None => (s, None),
        };
        match addr_str.parse::<IpAddr>().ok()? {
            IpAddr::V4(v4) => {
                let prefix = match prefix_str {
                    Some(p) => {
                        let p = p.parse::<u8>().ok()?;
                        if p > 32 {
                            return None;
                        }
                        p
                    }
                    None => 32, // bare IP = /32
                };
                Some(CidrNetwork::V4 {
                    net: u32::from(v4),
                    prefix,
                })
            }
            IpAddr::V6(v6) => {
                let prefix = match prefix_str {
                    Some(p) => {
                        let p = p.parse::<u8>().ok()?;
                        if p > 128 {
                            return None;
                        }
                        p
                    }
                    None => 128, // bare IP = /128
                };
                Some(CidrNetwork::V6 {
                    net: u128::from(v6),
                    prefix,
                })
            }
        }
    }

    fn contains(&self, ip: IpAddr) -> bool {
        match (self, ip) {
            (CidrNetwork::V4 { net, prefix }, IpAddr::V4(v4)) => {
                mask_match(u64::from(u32::from(v4)), u64::from(*net), *prefix, 32)
            }
            (CidrNetwork::V6 { net, prefix }, IpAddr::V6(v6)) => {
                mask_match(u128::from(v6), *net, *prefix, 128)
            }
            _ => false,
        }
    }
}

fn mask_match<T>(ip: T, net: T, prefix: u8, width: u8) -> bool
where
    T: std::ops::Shr<u8, Output = T> + PartialEq + Copy,
{
    if prefix == 0 {
        return true;
    }
    let shift = width - prefix;
    (ip >> shift) == (net >> shift)
}

/// Map IPv4-mapped IPv6 addresses (`::ffff:a.b.c.d`) back to IPv4 so that
/// dual-stack listeners produce one canonical identity per client.
fn normalise_ip(ip: IpAddr) -> IpAddr {
    if let IpAddr::V6(v6) = ip {
        if let Some(v4) = v6.to_ipv4_mapped() {
            return IpAddr::V4(v4);
        }
    }
    ip
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn test_request_context_builder() {
        let ctx = RequestContextBuilder::new(
            "1.2.3.4".parse().expect("hardcoded test IP"),
            "/api/health",
            "GET",
        )
        .user_agent("Mozilla/5.0")
        .tenant_id("tenant-123")
        .body_size(1024)
        .build();

        assert_eq!(
            ctx.ip,
            "1.2.3.4".parse::<IpAddr>().expect("hardcoded test IP")
        );
        assert_eq!(ctx.path, "/api/health");
        assert_eq!(ctx.method, "GET");
        assert_eq!(ctx.user_agent.as_deref(), Some("Mozilla/5.0"));
        assert_eq!(ctx.tenant_id.as_deref(), Some("tenant-123"));
        assert_eq!(ctx.body_size, 1024);
    }

    // NOTE: the following tests were updated as part of the IP-spoofing
    // security fix. They previously asserted the VULNERABLE behavior
    // (X-Real-IP / leftmost XFF trusted unconditionally) which allowed any
    // client to forge its identity for reputation, sessions and blocklists.

    fn ip(s: &str) -> IpAddr {
        s.parse().expect("hardcoded test IP")
    }

    #[test]
    fn test_extract_client_ip_ignores_headers_from_untrusted_peer() {
        // A DIRECT client sending spoofed X-Real-Ip / XFF / CF headers must
        // be identified by its socket address.
        let direct = ip("203.0.113.99");
        assert_eq!(extract_client_ip(Some("10.0.0.1"), None, None, direct), direct);
        assert_eq!(
            extract_client_ip(None, Some("10.0.0.2, 10.0.0.3"), None, direct),
            direct
        );
        assert_eq!(extract_client_ip(None, None, Some("10.0.0.4"), direct), direct);
        assert_eq!(
            extract_client_ip(
                Some("10.0.0.1"),
                Some("10.0.0.2, 10.0.0.3"),
                Some("10.0.0.4"),
                direct
            ),
            direct
        );
    }

    #[test]
    fn test_extract_client_ip_empty_trusted_list_never_trusts_headers() {
        // Explicit empty trusted list: headers are never honored.
        let trusted = TrustedProxyList::parse([]);
        let direct = ip("198.51.100.7");
        let result = extract_client_ip_trusted(
            Some("1.2.3.4"),
            Some("1.2.3.4, 5.6.7.8"),
            Some("9.9.9.9"),
            direct,
            &trusted,
        );
        assert_eq!(result, direct);
        assert!(trusted.is_empty());
    }

    #[test]
    fn test_trusted_proxy_3hop_xff_returns_client() {
        // Chain: client → proxy2 → proxy1 → server.
        // XFF as appended by proxies: "client, proxy2, proxy1".
        let trusted = TrustedProxyList::parse(["10.0.0.0/8"]);
        let proxy1 = ip("10.0.0.1"); // our direct peer
        let result = extract_client_ip_trusted(
            None,
            Some("203.0.113.50, 10.0.0.2, 10.0.0.1"),
            None,
            proxy1,
            &trusted,
        );
        assert_eq!(result, ip("203.0.113.50"), "rightmost untrusted entry is the client");
    }

    #[test]
    fn test_untrusted_proxy_sending_xff_returns_proxy_ip() {
        // A random host that is NOT a configured proxy sends XFF — the
        // proxy's own address is the identity.
        let trusted = TrustedProxyList::parse(["10.0.0.0/8"]);
        let peer = ip("192.0.2.66");
        let result =
            extract_client_ip_trusted(None, Some("1.2.3.4, 5.6.7.8"), None, peer, &trusted);
        assert_eq!(result, peer);
    }

    #[test]
    fn test_xff_leftmost_spoofed_entries_ignored() {
        // Attacker-controlled leftmost entries must never be selected.
        let trusted = TrustedProxyList::parse(["10.0.0.0/8"]);
        let proxy = ip("10.0.0.1");
        let result = extract_client_ip_trusted(
            None,
            Some("6.6.6.6, 203.0.113.50, 10.0.0.1"),
            None,
            proxy,
            &trusted,
        );
        assert_eq!(result, ip("203.0.113.50"));
    }

    #[test]
    fn test_all_trusted_xff_falls_back_to_x_real_ip() {
        // Internal multi-hop chain where every XFF hop is trusted.
        let trusted = TrustedProxyList::parse(["10.0.0.0/8"]);
        let proxy = ip("10.0.0.1");
        let result = extract_client_ip_trusted(
            Some("203.0.113.77"),
            Some("10.0.0.2, 10.0.0.3"),
            None,
            proxy,
            &trusted,
        );
        assert_eq!(result, ip("203.0.113.77"));
    }

    #[test]
    fn test_trusted_proxy_invalid_headers_fall_back_to_peer() {
        let trusted = TrustedProxyList::parse(["10.0.0.0/8"]);
        let proxy = ip("10.0.0.1");
        let result = extract_client_ip_trusted(
            Some("not-an-ip"),
            Some("also-not-valid"),
            Some("nope"),
            proxy,
            &trusted,
        );
        assert_eq!(result, proxy);
    }

    #[test]
    fn test_trusted_proxy_list_cidr_matching() {
        let trusted = TrustedProxyList::parse(["10.0.0.0/8", "192.168.1.5", "fd00::/8"]);
        assert!(trusted.contains(ip("10.1.2.3")));
        assert!(trusted.contains(ip("10.255.255.255")));
        assert!(trusted.contains(ip("192.168.1.5")));
        assert!(!trusted.contains(ip("192.168.1.6")), "bare IP is /32");
        assert!(trusted.contains(ip("fd00::1")));
        assert!(!trusted.contains(ip("fe80::1")));
        assert!(!trusted.contains(ip("203.0.113.1")));
        // IPv4-mapped IPv6 normalizes to IPv4 before matching
        assert!(trusted.contains(ip("::ffff:10.1.2.3")));
        assert!(!trusted.is_empty());
    }

    #[test]
    fn test_trusted_proxy_list_invalid_entries_ignored() {
        let trusted = TrustedProxyList::parse(["not-a-cidr", "", "10.0.0.0/8"]);
        assert!(!trusted.is_empty());
        assert!(trusted.contains(ip("10.0.0.9")));
        assert!(!trusted.contains(ip("11.0.0.1")));
    }

    #[test]
    fn test_extract_client_ip_fallback_to_direct() {
        let direct: IpAddr = "192.168.1.1".parse().expect("hardcoded test IP");
        let result = extract_client_ip(None, None, None, direct);
        assert_eq!(result, direct);
    }

    #[tokio::test]
    async fn test_evaluate_request_allow() {
        let config = crate::config::ProtectorConfig::default();
        let protector = DdosProtector::new(config)
            .await
            .expect("test should succeed");
        let ctx = RequestContextBuilder::new(
            "1.2.3.4".parse().expect("hardcoded test IP"),
            "/health",
            "GET",
        )
        .build();

        let action = evaluate_request(&protector, &ctx).await;
        assert!(matches!(action, MiddlewareAction::Allow));
    }

    #[tokio::test]
    async fn test_evaluate_request_block() {
        let config = crate::config::ProtectorConfig::default();
        let protector = DdosProtector::new(config)
            .await
            .expect("test should succeed");

        let ip: IpAddr = "10.0.0.99".parse().expect("hardcoded test IP");
        protector.block_ip(ip, Duration::from_secs(300), "test".to_string());

        let ctx = RequestContextBuilder::new(ip, "/api/data", "GET").build();
        let action = evaluate_request(&protector, &ctx).await;
        assert!(matches!(action, MiddlewareAction::Block { status: 403 }));
    }
}
