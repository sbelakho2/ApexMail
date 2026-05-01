//! SSRF protection — DNS validation and private IP blocking.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::LazyLock;
use std::time::Duration;

use moka::sync::Cache;
use trust_dns_resolver::config::{ResolverConfig, ResolverOpts};
use trust_dns_resolver::TokioAsyncResolver;
use url::Url;

use super::types::{dns_cache_max_entries, dns_cache_ttl_secs, BLOCKED_HOSTNAMES};
use crate::common::{ProcessorError, ProcessorResult};

/// A webhook target that has passed SSRF checks and has a pinned set of resolved IPs.
#[derive(Debug, Clone)]
pub struct ResolvedWebhookTarget {
    pub host: String,
    pub port: u16,
    pub resolved_ips: Vec<IpAddr>,
    pub host_is_ip: bool,
}

/// DNS resolver with caching and SSRF protection.
pub struct SsrfValidator {
    resolver: TokioAsyncResolver,
    cache: Cache<String, Vec<IpAddr>>,
    extra_blocked_hosts: Vec<String>,
}

static SSRF_RESOLVER: LazyLock<TokioAsyncResolver> =
    LazyLock::new(|| TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default()));

impl SsrfValidator {
    /// Create a new SSRF validator.
    pub fn new() -> ProcessorResult<Self> {
        let resolver = SSRF_RESOLVER.clone();

        let cache = Cache::builder()
            .max_capacity(dns_cache_max_entries())
            .time_to_live(Duration::from_secs(dns_cache_ttl_secs()))
            .build();

        // Load extra blocked hosts from environment
        let extra_blocked_hosts = std::env::var("WEBHOOK_BLOCKED_HOSTS")
            .unwrap_or_default()
            .split(',')
            .map(|s| s.trim().to_lowercase())
            .filter(|s| !s.is_empty())
            .collect();

        Ok(Self {
            resolver,
            cache,
            extra_blocked_hosts,
        })
    }

    /// Validate a URL for safe webhook delivery.
    pub async fn validate_url(&self, url_str: &str) -> ProcessorResult<()> {
        self.validate_and_resolve_url(url_str).await.map(|_| ())
    }

    /// Validate a URL for safe webhook delivery and return a pinned resolution result.
    pub async fn validate_and_resolve_url(
        &self,
        url_str: &str,
    ) -> ProcessorResult<ResolvedWebhookTarget> {
        let url =
            Url::parse(url_str).map_err(|e| ProcessorError::Job(format!("Invalid URL: {}", e)))?;

        let allow_http = std::env::var("ALLOW_WEBHOOK_HTTP").is_ok();
        if url.scheme() == "http" && !allow_http {
            return Err(ProcessorError::Job(
                "Webhook URL must use HTTPS (set ALLOW_WEBHOOK_HTTP to allow HTTP in non-production)".to_string()
            ));
        }
        if url.scheme() != "https" && url.scheme() != "http" {
            return Err(ProcessorError::Job(format!(
                "Invalid scheme: {}",
                url.scheme()
            )));
        }

        let port = url
            .port_or_known_default()
            .ok_or_else(|| ProcessorError::Job("URL has no known port for scheme".to_string()))?;

        let hostname = url
            .host_str()
            .ok_or_else(|| ProcessorError::Job("URL has no host".to_string()))?
            .to_lowercase();

        // Check blocked hostnames
        if self.is_blocked_hostname(&hostname) {
            return Err(ProcessorError::Job(
                "URL points to internal/localhost address".to_string(),
            ));
        }

        // If hostname is an IP, check directly
        if let Ok(ip) = hostname.parse::<IpAddr>() {
            if is_private_ip(&ip) {
                return Err(ProcessorError::Job(format!(
                    "URL resolves to private IP: {}",
                    ip
                )));
            }
            return Ok(ResolvedWebhookTarget {
                host: hostname,
                port,
                resolved_ips: vec![ip],
                host_is_ip: true,
            });
        }

        // Resolve hostname and check all IPs
        let ips = self.resolve_hostname(&hostname).await?;

        if ips.is_empty() {
            return Err(ProcessorError::Job(
                "URL hostname could not be resolved".to_string(),
            ));
        }

        for ip in &ips {
            if is_private_ip(ip) {
                return Err(ProcessorError::Job(format!(
                    "URL resolves to private IP: {}",
                    ip
                )));
            }
        }

        Ok(ResolvedWebhookTarget {
            host: hostname,
            port,
            resolved_ips: ips,
            host_is_ip: false,
        })
    }

    /// Check if hostname is in the blocklist.
    fn is_blocked_hostname(&self, hostname: &str) -> bool {
        let hostname_lower = hostname.to_lowercase();

        // Check static blocklist
        for blocked in BLOCKED_HOSTNAMES {
            if hostname_lower == *blocked || hostname_lower.ends_with(&format!(".{}", blocked)) {
                return true;
            }
        }

        // Check extra blocked hosts
        for blocked in &self.extra_blocked_hosts {
            if hostname_lower == *blocked || hostname_lower.ends_with(&format!(".{}", blocked)) {
                return true;
            }
        }

        false
    }

    /// Resolve hostname to IP addresses with caching.
    /// resolve again independently. To fully mitigate, use reqwest with connect_timeout
    /// and the resolved IPs directly, or configure a custom DNS resolver. For now we rely
    /// on short cache TTL and assume DNS rebinding attacks are unlikely in our threat model.
    async fn resolve_hostname(&self, hostname: &str) -> ProcessorResult<Vec<IpAddr>> {
        // Check cache first
        if let Some(ips) = self.cache.get(hostname) {
            return Ok(ips);
        }

        // Resolve IPv4
        let mut ips = Vec::new();

        if let Ok(response) = self.resolver.ipv4_lookup(hostname).await {
            ips.extend(response.iter().map(|ip| IpAddr::V4(ip.0)));
        }

        // Resolve IPv6
        if let Ok(response) = self.resolver.ipv6_lookup(hostname).await {
            ips.extend(response.iter().map(|ip| IpAddr::V6(ip.0)));
        }

        // Cache the result
        self.cache.insert(hostname.to_string(), ips.clone());

        Ok(ips)
    }
}

impl Default for SsrfValidator {
    fn default() -> Self {
        Self::new().unwrap_or_else(|e| {
            tracing::error!(
                "Failed to create default SSRF validator: {}. Using fallback.",
                e
            );
            Self {
                resolver: SSRF_RESOLVER.clone(),
                cache: Cache::builder()
                    .max_capacity(dns_cache_max_entries())
                    .time_to_live(Duration::from_secs(dns_cache_ttl_secs()))
                    .build(),
                extra_blocked_hosts: Vec::new(),
            }
        })
    }
}

/// Check if an IP address is private/internal.
pub fn is_private_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => is_private_ipv4(ip),
        IpAddr::V6(ip) => is_private_ipv6(ip),
    }
}

/// Check if an IPv4 address is private/internal.
fn is_private_ipv4(ip: &Ipv4Addr) -> bool {
    let octets = ip.octets();

    // Loopback:127.0.0.0/8
    if octets[0] == 127 {
        return true;
    }

    // Private:10.0.0.0/8
    if octets[0] == 10 {
        return true;
    }

    // Private:172.16.0.0/12
    if octets[0] == 172 && (octets[1] >= 16 && octets[1] <= 31) {
        return true;
    }

    // Private:192.168.0.0/16
    if octets[0] == 192 && octets[1] == 168 {
        return true;
    }

    // Link-local:169.254.0.0/16 (includes AWS metadata)
    if octets[0] == 169 && octets[1] == 254 {
        return true;
    }

    // Broadcast/unspecified
    if ip.is_broadcast() || ip.is_unspecified() {
        return true;
    }

    // Documentation:192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24
    if (octets[0] == 192 && octets[1] == 0 && octets[2] == 2)
        || (octets[0] == 198 && octets[1] == 51 && octets[2] == 100)
        || (octets[0] == 203 && octets[1] == 0 && octets[2] == 113)
    {
        return true;
    }

    // Carrier-grade NAT:100.64.0.0/10
    if octets[0] == 100 && (octets[1] >= 64 && octets[1] <= 127) {
        return true;
    }

    false
}

/// Check if an IPv6 address is private/internal.
fn is_private_ipv6(ip: &Ipv6Addr) -> bool {
    // Loopback:::1
    if ip.is_loopback() {
        return true;
    }

    // Unspecified::
    if ip.is_unspecified() {
        return true;
    }

    let segments = ip.segments();

    // Link-local:fe80::/10
    if segments[0] & 0xffc0 == 0xfe80 {
        return true;
    }

    // Unique local:fc00::/7
    if segments[0] & 0xfe00 == 0xfc00 {
        return true;
    }

    // Site-local (deprecated):fec0::/10
    if segments[0] & 0xffc0 == 0xfec0 {
        return true;
    }

    // 6to4:2002::/16 - embeds IPv4 in bytes 2-5
    if segments[0] == 0x2002 {
        let embedded_ipv4 = Ipv4Addr::new(
            (segments[1] >> 8) as u8,
            (segments[1] & 0xff) as u8,
            (segments[2] >> 8) as u8,
            (segments[2] & 0xff) as u8,
        );
        if is_private_ipv4(&embedded_ipv4) {
            return true;
        }
    }

    // Teredo:2001:0000::/32 - embeds IPv4 in last 32 bits (XORed with 0xffffffff)
    if segments[0] == 0x2001 && segments[1] == 0x0000 {
        let embedded_ipv4 = Ipv4Addr::new(
            (segments[6] >> 8) as u8 ^ 0xff,
            (segments[6] & 0xff) as u8 ^ 0xff,
            (segments[7] >> 8) as u8 ^ 0xff,
            (segments[7] & 0xff) as u8 ^ 0xff,
        );
        if is_private_ipv4(&embedded_ipv4) {
            return true;
        }
    }

    // IPv4-compatible (deprecated):::ffff:0:0/96 and ::/96
    // Check if lower 32 bits are a private IPv4
    if segments[0..5] == [0, 0, 0, 0, 0] && segments[5] == 0 {
        let embedded_ipv4 = Ipv4Addr::new(
            (segments[6] >> 8) as u8,
            (segments[6] & 0xff) as u8,
            (segments[7] >> 8) as u8,
            (segments[7] & 0xff) as u8,
        );
        if is_private_ipv4(&embedded_ipv4) {
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

    #[test]
    fn test_private_ipv4() {
        // Private ranges
        assert!(is_private_ip(&IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))));
        assert!(is_private_ip(&IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
        assert!(is_private_ip(&IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1))));
        assert!(is_private_ip(&IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))));
        assert!(is_private_ip(&IpAddr::V4(Ipv4Addr::new(
            169, 254, 169, 254
        ))));

        // Public
        assert!(!is_private_ip(&IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
        assert!(!is_private_ip(&IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))));
    }

    #[test]
    fn test_private_ipv6() {
        // Loopback
        assert!(is_private_ip(&IpAddr::V6(Ipv6Addr::LOCALHOST)));

        // Unspecified
        assert!(is_private_ip(&IpAddr::V6(Ipv6Addr::UNSPECIFIED)));

        // Link-local (fe80::)
        assert!(is_private_ip(&IpAddr::V6(Ipv6Addr::new(
            0xfe80, 0, 0, 0, 0, 0, 0, 1
        ))));

        // Unique local (fc00::)
        assert!(is_private_ip(&IpAddr::V6(Ipv6Addr::new(
            0xfc00, 0, 0, 0, 0, 0, 0, 1
        ))));

        // Public
        assert!(!is_private_ip(&IpAddr::V6(Ipv6Addr::new(
            0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888
        ))));
    }

    #[test]
    fn test_blocked_hostname() {
        let validator = SsrfValidator::new().unwrap();

        assert!(validator.is_blocked_hostname("localhost"));
        assert!(validator.is_blocked_hostname("127.0.0.1"));
        assert!(validator.is_blocked_hostname("metadata.google.internal"));
        assert!(validator.is_blocked_hostname("kubernetes.default"));

        assert!(!validator.is_blocked_hostname("example.com"));
        assert!(!validator.is_blocked_hostname("api.stripe.com"));
    }

    #[tokio::test]
    async fn test_validate_and_resolve_url_public_ip_target() {
        let validator = SsrfValidator::new().unwrap();
        let resolved = validator
            .validate_and_resolve_url("https://8.8.8.8/webhook")
            .await
            .unwrap();

        assert_eq!(resolved.host, "8.8.8.8");
        assert_eq!(resolved.port, 443);
        assert!(resolved.host_is_ip);
        assert_eq!(
            resolved.resolved_ips,
            vec![IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))]
        );
    }

    #[tokio::test]
    async fn test_validate_and_resolve_url_blocks_private_ip_target() {
        let validator = SsrfValidator::new().unwrap();
        let err = validator
            .validate_and_resolve_url("https://127.0.0.1/webhook")
            .await
            .unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("private IP") || msg.contains("internal/localhost"),
            "unexpected error message: {msg}"
        );
    }
}
