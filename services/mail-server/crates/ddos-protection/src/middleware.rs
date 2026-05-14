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

/// IP extraction helper — extracts client IP from forwarded headers or direct connection.
/// Priority:/// 1. `X-Real-IP` header
/// 2. `X-Forwarded-For` (first IP)
/// 3. `CF-Connecting-IP` (Cloudflare)
/// 4. Direct connection IP
pub fn extract_client_ip(
    x_real_ip: Option<&str>,
    x_forwarded_for: Option<&str>,
    cf_connecting_ip: Option<&str>,
    direct_ip: IpAddr,
) -> IpAddr {
    // X-Real-IP
    if let Some(ip_str) = x_real_ip {
        if let Ok(ip) = ip_str.trim().parse::<IpAddr>() {
            return ip;
        }
    }

    // X-Forwarded-For (first entry)
    if let Some(xff) = x_forwarded_for {
        if let Some(first) = xff.split(',').next() {
            if let Ok(ip) = first.trim().parse::<IpAddr>() {
                return ip;
            }
        }
    }

    // CF-Connecting-IP
    if let Some(ip_str) = cf_connecting_ip {
        if let Ok(ip) = ip_str.trim().parse::<IpAddr>() {
            return ip;
        }
    }

    direct_ip
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

    #[test]
    fn test_extract_client_ip_x_real_ip() {
        let direct: IpAddr = "127.0.0.1".parse().expect("hardcoded test IP");
        let result = extract_client_ip(Some("10.0.0.1"), None, None, direct);
        assert_eq!(
            result,
            "10.0.0.1".parse::<IpAddr>().expect("hardcoded test IP")
        );
    }

    #[test]
    fn test_extract_client_ip_xff_first() {
        let direct: IpAddr = "127.0.0.1".parse().expect("hardcoded test IP");
        let result = extract_client_ip(None, Some("10.0.0.2, 10.0.0.3"), None, direct);
        assert_eq!(
            result,
            "10.0.0.2".parse::<IpAddr>().expect("hardcoded test IP")
        );
    }

    #[test]
    fn test_extract_client_ip_cf() {
        let direct: IpAddr = "127.0.0.1".parse().expect("hardcoded test IP");
        let result = extract_client_ip(None, None, Some("10.0.0.4"), direct);
        assert_eq!(
            result,
            "10.0.0.4".parse::<IpAddr>().expect("hardcoded test IP")
        );
    }

    #[test]
    fn test_extract_client_ip_fallback_to_direct() {
        let direct: IpAddr = "192.168.1.1".parse().expect("hardcoded test IP");
        let result = extract_client_ip(None, None, None, direct);
        assert_eq!(
            result,
            "192.168.1.1".parse::<IpAddr>().expect("hardcoded test IP")
        );
    }

    #[test]
    fn test_extract_client_ip_priority_order() {
        let direct: IpAddr = "127.0.0.1".parse().expect("hardcoded test IP");
        // X-Real-IP takes priority over XFF
        let result = extract_client_ip(
            Some("10.0.0.1"),
            Some("10.0.0.2, 10.0.0.3"),
            Some("10.0.0.4"),
            direct,
        );
        assert_eq!(
            result,
            "10.0.0.1".parse::<IpAddr>().expect("hardcoded test IP")
        );
    }

    #[test]
    fn test_extract_client_ip_invalid_x_real_ip_falls_through() {
        let direct: IpAddr = "127.0.0.1".parse().expect("hardcoded test IP");
        let result = extract_client_ip(Some("not-an-ip"), Some("10.0.0.2"), None, direct);
        assert_eq!(
            result,
            "10.0.0.2".parse::<IpAddr>().expect("hardcoded test IP")
        );
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
