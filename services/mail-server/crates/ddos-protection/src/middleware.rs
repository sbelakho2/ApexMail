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

/// Well-known redemption path for DDoS PoW challenges (audit F3c). A client
/// that received a 429 with a challenge may either POST here or retry the
/// original request with the id/solution headers below.
pub const DDOS_VERIFY_PATH: &str = "/__ddos/verify";

/// Header carrying the challenge id on a redemption retry.
pub const CHALLENGE_ID_HEADER: &str = "x-ddos-challenge-id";

/// Header carrying the PoW solution (nonce) on a redemption retry.
pub const CHALLENGE_SOLUTION_HEADER: &str = "x-ddos-challenge-solution";

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
    challenge_id: Option<String>,
    challenge_solution: Option<u64>,
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
            challenge_id: None,
            challenge_solution: None,
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

    /// Attach a challenge solution for redemption (audit F3c): the id from
    /// the issued challenge and the nonce the client solved.
    pub fn challenge_solution(mut self, challenge_id: &str, nonce: u64) -> Self {
        self.challenge_id = Some(challenge_id.to_string());
        self.challenge_solution = Some(nonce);
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
            challenge_id: self.challenge_id,
            challenge_solution: self.challenge_solution,
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
///
/// Redemption path (audit F3c): when the request context carries a challenge
/// id + solution (from [`CHALLENGE_ID_HEADER`]/[`CHALLENGE_SOLUTION_HEADER`]
/// on a retry, or a `POST` to [`DDOS_VERIFY_PATH`]), the solution is
/// verified against the server-side issuance registry — never against
/// client-claimed parameters. A valid solution marks the challenge solved
/// (short allow-TTL), credits the client's reputation, and the request is
/// re-evaluated; while the allow-TTL is active a re-evaluation that still
/// asks for a challenge is let through.
///
/// Wiring dependency: callers (e.g. an HTTP framework middleware) must
/// populate `ctx.challenge_id`/`ctx.challenge_solution` from the request
/// headers for this path to engage; without them evaluation proceeds
/// normally (challenge → 429 with serialized parameters).
pub async fn evaluate_request(protector: &DdosProtector, ctx: &RequestContext) -> MiddlewareAction {
    // Challenge redemption (audit F3c). Works both for retries of the
    // original request with headers and for the well-known verify path.
    #[cfg(feature = "challenges")]
    if let (Some(challenge_id), Some(nonce)) = (&ctx.challenge_id, ctx.challenge_solution) {
        let result = protector.verify_pow(&ctx.ip, challenge_id, nonce);
        if result.valid {
            // Solved: re-evaluate the request. The reputation credit from
            // verify_pow normally lets it through; if the (slow-recovering)
            // reputation still asks for a challenge, the solved-marker's
            // allow-TTL redeems it.
            return match protector.evaluate(ctx).await {
                ProtectionDecision::Allow => MiddlewareAction::Allow,
                ProtectionDecision::Challenge(_) if protector.pow_allow_active(challenge_id) => {
                    if let Some(metric) = crate::metrics::REQUESTS_TOTAL.as_ref() {
                        metric.with_label_values(&["challenged", "redeemed"]).inc();
                    }
                    MiddlewareAction::Allow
                }
                ProtectionDecision::Challenge(challenge) => challenge_action(&challenge),
                ProtectionDecision::RateLimit { retry_after } => MiddlewareAction::RateLimit {
                    status: 429,
                    retry_after_secs: retry_after.as_secs(),
                },
                ProtectionDecision::Block => MiddlewareAction::Block { status: 403 },
            };
        }
        // Invalid/unknown/replayed solution: fall through to normal
        // evaluation (the client will simply be challenged again).
    }

    match protector.evaluate(ctx).await {
        ProtectionDecision::Allow => MiddlewareAction::Allow,

        ProtectionDecision::Challenge(challenge) => challenge_action(&challenge),

        ProtectionDecision::RateLimit { retry_after } => MiddlewareAction::RateLimit {
            status: 429,
            retry_after_secs: retry_after.as_secs(),
        },

        ProtectionDecision::Block => MiddlewareAction::Block { status: 403 },
    }
}

/// Serialize a challenge into the 429 JSON body (audit F3b).
///
/// PoW challenges include the full parameter set (prefix/data, difficulty,
/// expiry, id, signature) plus redemption instructions, so a legitimate
/// client has everything needed to solve and redeem. The signature lets
/// clients (and intermediates) detect parameter tampering; the server never
/// trusts these values back on verification.
fn challenge_action(challenge: &crate::decision::Challenge) -> MiddlewareAction {
    match challenge {
        crate::decision::Challenge::Pow(pow) => MiddlewareAction::Challenge {
            status: 429,
            body: serde_json::json!({
                "challenge_type": "pow",
                "message": "Challenge required",
                "challenge": {
                    "id": pow.id,
                    "algorithm": "sha256",
                    "data": pow.data,
                    "difficulty": pow.difficulty,
                    "expires_at": pow.expires_at,
                    "signature": pow.signature,
                    "hash_format": "sha256(\"<data>:<nonce>\") with <difficulty> leading zero bits"
                },
                "redeem": {
                    "path": DDOS_VERIFY_PATH,
                    "method": "POST",
                    "challenge_id_header": CHALLENGE_ID_HEADER,
                    "solution_header": CHALLENGE_SOLUTION_HEADER
                }
            })
            .to_string(),
        },
        other => MiddlewareAction::Challenge {
            status: 429,
            body: serde_json::json!({
                "challenge_type": challenge_type_label(other),
                "message": "Challenge required",
            })
            .to_string(),
        },
    }
}

fn challenge_type_label(challenge: &crate::decision::Challenge) -> &'static str {
    match challenge {
        crate::decision::Challenge::Js(_) => "js",
        crate::decision::Challenge::Pow(_) => "pow",
        crate::decision::Challenge::Cookie(_) => "cookie",
        crate::decision::Challenge::Captcha(_) => "captcha",
        crate::decision::Challenge::None => "none",
        crate::decision::Challenge::Blocked => "blocked",
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
        assert_eq!(
            extract_client_ip(Some("10.0.0.1"), None, None, direct),
            direct
        );
        assert_eq!(
            extract_client_ip(None, Some("10.0.0.2, 10.0.0.3"), None, direct),
            direct
        );
        assert_eq!(
            extract_client_ip(None, None, Some("10.0.0.4"), direct),
            direct
        );
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
        assert_eq!(
            result,
            ip("203.0.113.50"),
            "rightmost untrusted entry is the client"
        );
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

    // ── Audit F3:challenge serialization & redemption path ──────────

    /// Brute-force a nonce with `difficulty` leading zero bits over
    /// `sha256("<data>:<nonce>")` (test helper).
    #[cfg(feature = "challenges")]
    fn solve_pow(data: &str, difficulty: u8) -> u64 {
        use sha2::{Digest, Sha256};
        for nonce in 0..10_000_000u64 {
            let input = format!("{data}:{nonce}");
            let hash = Sha256::digest(input.as_bytes());
            let required_bytes = (difficulty / 8) as usize;
            let remaining_bits = difficulty % 8;
            if hash[..required_bytes].iter().all(|b| *b == 0)
                && (remaining_bits == 0 || hash[required_bytes] << remaining_bits == 0)
            {
                return nonce;
            }
        }
        panic!("no nonce found");
    }

    #[cfg(feature = "challenges")]
    #[tokio::test]
    async fn test_challenge_body_serializes_signed_params() {
        // Force the reputation-challenge path (fresh score 50 < 90).
        let config = crate::config::ProtectorConfig {
            challenge_threshold: 90,
            ..crate::config::ProtectorConfig::default()
        };
        let protector = DdosProtector::new(config)
            .await
            .expect("test should succeed");

        let ctx = RequestContextBuilder::new(
            "203.0.113.90".parse().expect("hardcoded test IP"),
            "/api/data",
            "GET",
        )
        .build();

        match evaluate_request(&protector, &ctx).await {
            MiddlewareAction::Challenge { status, body } => {
                assert_eq!(status, 429);
                let json: serde_json::Value =
                    serde_json::from_str(&body).expect("body is valid JSON");
                let challenge = &json["challenge"];
                assert_eq!(json["challenge_type"], "pow");
                assert!(challenge["id"].as_str().is_some_and(|s| !s.is_empty()));
                assert!(challenge["data"].as_str().is_some_and(|s| !s.is_empty()));
                assert!(challenge["difficulty"].as_u64().is_some_and(|d| d >= 8));
                assert!(challenge["expires_at"].as_u64().is_some());
                assert!(
                    challenge["signature"]
                        .as_str()
                        .is_some_and(|s| !s.is_empty()),
                    "429 body must carry the server signature"
                );
                assert_eq!(json["redeem"]["path"], "/__ddos/verify");
                assert_eq!(json["redeem"]["challenge_id_header"], CHALLENGE_ID_HEADER);
                assert_eq!(json["redeem"]["solution_header"], CHALLENGE_SOLUTION_HEADER);
            }
            other => panic!("expected challenge action, got {other:?}"),
        }
    }

    #[cfg(feature = "challenges")]
    #[tokio::test]
    async fn test_solved_challenge_redeems_the_request() {
        let config = crate::config::ProtectorConfig {
            challenge_threshold: 90,
            ..crate::config::ProtectorConfig::default()
        };
        let protector = DdosProtector::new(config)
            .await
            .expect("test should succeed");

        let client_ip: IpAddr = "203.0.113.91".parse().expect("hardcoded test IP");

        // 1. Client is challenged and receives the serialized parameters.
        let challenge = match evaluate_request(
            &protector,
            &RequestContextBuilder::new(client_ip, "/api/data", "GET").build(),
        )
        .await
        {
            MiddlewareAction::Challenge { body, .. } => {
                let json: serde_json::Value =
                    serde_json::from_str(&body).expect("challenge body is JSON");
                let id = json["challenge"]["id"].as_str().expect("id").to_string();
                let data = json["challenge"]["data"]
                    .as_str()
                    .expect("data")
                    .to_string();
                let difficulty = json["challenge"]["difficulty"]
                    .as_u64()
                    .expect("difficulty") as u8;
                (id, data, difficulty)
            }
            other => panic!("expected challenge, got {other:?}"),
        };

        // 2. Client solves with the SERVER-issued parameters and retries
        //    the original request with the redemption headers.
        let nonce = solve_pow(&challenge.1, challenge.2);
        let redeemed_ctx = RequestContextBuilder::new(client_ip, "/api/data", "GET")
            .challenge_solution(&challenge.0, nonce)
            .build();
        let action = evaluate_request(&protector, &redeemed_ctx).await;
        assert!(
            matches!(action, MiddlewareAction::Allow),
            "a correctly solved server-issued challenge must redeem the request, got {action:?}"
        );

        // 3. The same (id, nonce) cannot be replayed by a second client:
        //    verification hits the replay cache, and the untarnished second
        //    IP falls back to a fresh challenge instead of being redeemed.
        let second_ip: IpAddr = "203.0.113.93".parse().expect("hardcoded test IP");
        let replay_ctx = RequestContextBuilder::new(second_ip, "/api/data", "GET")
            .challenge_solution(&challenge.0, nonce)
            .build();
        let action = evaluate_request(&protector, &replay_ctx).await;
        assert!(
            matches!(action, MiddlewareAction::Challenge { .. }),
            "replayed solution must not redeem a second time, got {action:?}"
        );
    }

    #[cfg(feature = "challenges")]
    #[tokio::test]
    async fn test_forged_redemption_is_rejected() {
        let config = crate::config::ProtectorConfig {
            challenge_threshold: 90,
            ..crate::config::ProtectorConfig::default()
        };
        let protector = DdosProtector::new(config)
            .await
            .expect("test should succeed");

        let client_ip: IpAddr = "203.0.113.92".parse().expect("hardcoded test IP");

        // A client that never received a challenge presents a made-up id and
        // nonce; it must NOT be allowed through.
        let forged_ctx = RequestContextBuilder::new(client_ip, "/api/data", "GET")
            .challenge_solution("fabricated-challenge-id", 0)
            .build();
        let action = evaluate_request(&protector, &forged_ctx).await;
        assert!(
            matches!(action, MiddlewareAction::Challenge { .. }),
            "forged redemption must fall through to a fresh challenge, got {action:?}"
        );
    }
}
