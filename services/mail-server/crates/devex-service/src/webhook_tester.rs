//! Webhook testing — send test payloads, verify HMAC-SHA256 signatures.
//!
//! Provides test-related webhook helpers.
//!
//! # G.4 — SSRF protection
//!
//! Hostname-only checks can be bypassed by a DNS name that resolves to a
//! private address (or rebinds after validation). This module mirrors the
//! in-repo correct pattern (`worker-processors/src/webhook/ssrf.rs`):
//! resolve the hostname, reject ANY private/reserved IP in the answer set,
//! and PIN the connection to the validated IP via
//! `reqwest::ClientBuilder::resolve` so DNS rebinding cannot swap the
//! address between validation and connection.

use chrono::Utc;
use hmac::{Hmac, Mac};
use mail_common::is_private_or_reserved_host;
use sha2::Sha256;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use uuid::Uuid;

use crate::types::{DevExError, WebhookTestResult};
use tracing::warn;

type HmacSha256 = Hmac<Sha256>;

/// Webhook tester — sends test payloads and validates signatures.
///
/// # O-20.2 — Signing secret rotation
/// The tester now holds a list of active signing secrets (`signing_secrets`).
/// The **first** secret is used for signing new payloads; **all** secrets are
/// accepted during verification. This enables zero‑downtime key rotation:
/// 1. Add new secret to `Vec` head — all new signatures use the new key.
/// 2. Wait for in‑flight payloads signed with the old key to be verified.
/// 3. Remove old secret from `Vec`.
#[derive(Debug, Clone)]
pub struct WebhookTester {
    /// Ordered list of active signing secrets (first = active signing key).
    signing_secrets: Vec<String>,
}

impl WebhookTester {
    /// Create a new tester with one or more signing secrets.
    /// The **first** secret is used for signing; all are accepted for verification.
    ///
    /// Returns an error if the list is empty.
    ///
    /// G.4: the tester no longer holds a shared HTTP client — each send
    /// builds a client PINNED to the SSRF-validated resolved IP.
    pub fn new(signing_secrets: Vec<String>) -> Result<Self, DevExError> {
        if signing_secrets.is_empty() {
            return Err(DevExError::WebhookError(
                "At least one webhook signing secret is required".into(),
            ));
        }

        Ok(Self { signing_secrets })
    }

    /// Build a test webhook payload for a given event type.
    pub fn build_test_payload(event_type: &str) -> serde_json::Value {
        let now = Utc::now();
        serde_json::json!({
            "id": format!("evt_{}", Uuid::new_v4()),
            "type": event_type,
            "created_at": now.to_rfc3339(),
            "data": {
                "email_id": format!("msg_{}", Uuid::new_v4()),
                "to": "test@example.com",
                "from": "sender@apexmail.ee",
                "subject": "Test webhook payload",
                "status": "delivered",
                "timestamp": now.to_rfc3339()
            },
            "test": true
        })
    }

    /// Compute HMAC-SHA256 signature for a payload body.
    /// Uses the **first** active signing secret (`self.signing_secrets[0]`).
    pub fn sign_payload(&self, body: &[u8]) -> String {
        let timestamp = Utc::now().timestamp();
        let signed_content = format!("{}.{}", timestamp, String::from_utf8_lossy(body));

        // O-20.2: Use the primary (first) secret for signing
        let active_secret = &self.signing_secrets[0];
        let mut mac = match HmacSha256::new_from_slice(active_secret.as_bytes()) {
            Ok(mac) => mac,
            Err(e) => {
                warn!(error = %e, "Failed to initialize webhook HMAC signer");
                return format!("t={},v1=invalid", timestamp);
            }
        };
        mac.update(signed_content.as_bytes());
        let result = mac.finalize();
        let sig = hex::encode(result.into_bytes());

        format!("t={},v1={}", timestamp, sig)
    }

    /// Verify that a signature header is valid for the given body and **any**
    /// of the configured signing secrets (supports rotation).
    ///
    /// O-20.2: Tries each secret in `self.signing_secrets`. Returns `true` if
    /// any secret produces a matching signature.
    pub fn verify_signature(&self, body: &[u8], signature_header: &str) -> bool {
        // Parse "t=<ts>,v1=<hex>"
        let parts: Vec<&str> = signature_header.split(',').collect();
        let timestamp = parts
            .iter()
            .find_map(|p| p.strip_prefix("t="))
            .unwrap_or("");
        let provided_sig = parts
            .iter()
            .find_map(|p| p.strip_prefix("v1="))
            .unwrap_or("");

        if timestamp.is_empty() || provided_sig.is_empty() {
            return false;
        }

        let signed_content = format!("{}.{}", timestamp, String::from_utf8_lossy(body));

        // O-20.2: Try every active secret (rotation support)
        self.signing_secrets.iter().any(|secret| {
            let Ok(mut mac) = HmacSha256::new_from_slice(secret.as_bytes()) else {
                return false;
            };
            mac.update(signed_content.as_bytes());
            let expected = hex::encode(mac.finalize().into_bytes());
            constant_time_eq(expected.as_bytes(), provided_sig.as_bytes())
        })
    }

    /// Send a test webhook to the given URL.
    pub async fn send_test_webhook(
        &self,
        url: &str,
        event_type: &str,
    ) -> Result<WebhookTestResult, DevExError> {
        // SSRF protection:only allow https (or http) with public hostnames
        let parsed = url::Url::parse(url)
            .map_err(|_| DevExError::Validation("Invalid webhook URL".into()))?;

        match parsed.scheme() {
            "https" | "http" => {}
            _ => {
                return Err(DevExError::Validation(
                    "Only http/https URLs are allowed".into(),
                ))
            }
        }

        // Block requests to private/internal networks
        let host = if let Some(host) = parsed.host_str() {
            if is_private_or_reserved_host(host) {
                return Err(DevExError::Validation(
                    "Webhook URLs pointing to private/internal networks are not allowed".into(),
                ));
            }
            host.to_string()
        } else {
            return Err(DevExError::Validation(
                "Webhook URL must have a host".into(),
            ));
        };
        let port = parsed.port_or_known_default().unwrap_or(80);

        // G.4: resolving guard — resolve, reject private/reserved answers,
        // and pin the connection to the validated address.
        let resolved = resolve_host(&host, port).await?;
        validate_resolved_addrs(&host, &resolved)?;

        let payload = Self::build_test_payload(event_type);
        let body = serde_json::to_vec(&payload)?;
        let signature = self.sign_payload(&body);

        let start = std::time::Instant::now();

        // Pin: a per-request client bound to the validated IP so the HTTP
        // stack cannot re-resolve the hostname (DNS rebinding). Test
        // webhooks are infrequent, so per-request client construction is
        // acceptable.
        let pinned_client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .resolve(&host, resolved[0])
            .build()
            .map_err(|e| DevExError::WebhookError(format!("HTTP client: {e}")))?;

        let result = pinned_client
            .post(url)
            .header("Content-Type", "application/json")
            .header("X-Webhook-Signature", &signature)
            .header("X-Webhook-Id", Uuid::new_v4().to_string())
            .header("X-Webhook-Timestamp", Utc::now().timestamp().to_string())
            .header("User-Agent", "ApexMail-Webhook/1.0")
            .body(body)
            .send()
            .await;

        let latency_ms = start.elapsed().as_millis() as u64;

        match result {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let resp_body = resp.text().await.ok();
                Ok(WebhookTestResult {
                    id: Uuid::new_v4().to_string(),
                    url: url.to_string(),
                    success: (200..300).contains(&status),
                    status_code: Some(status),
                    response_body: resp_body,
                    latency_ms,
                    signature_valid: true,
                    timestamp: Utc::now(),
                })
            }
            Err(e) => Ok(WebhookTestResult {
                id: Uuid::new_v4().to_string(),
                url: url.to_string(),
                success: false,
                status_code: None,
                response_body: Some(e.to_string()),
                latency_ms,
                signature_valid: true,
                timestamp: Utc::now(),
            }),
        }
    }
}

// ── G.4: resolving SSRF guard (mirrors worker-processors/src/webhook/ssrf.rs) ──

/// Resolve `host:port` off the async runtime (std DNS + /etc/hosts).
async fn resolve_host(host: &str, port: u16) -> Result<Vec<SocketAddr>, DevExError> {
    let host = host.to_string();
    tokio::task::spawn_blocking(move || {
        use std::net::ToSocketAddrs;
        (host.as_str(), port)
            .to_socket_addrs()
            .map(|iter| iter.collect::<Vec<_>>())
            .map_err(|e| {
                DevExError::Validation(format!("Webhook host could not be resolved: {e}"))
            })
    })
    .await
    .map_err(|e| DevExError::WebhookError(format!("DNS resolution task failed: {e}")))?
}

/// Reject when ANY resolved address is private/reserved — a name that
/// resolves to even one internal IP is treated as internal (attackers
/// control which answer the connector picks).
fn validate_resolved_addrs(host: &str, addrs: &[SocketAddr]) -> Result<(), DevExError> {
    if addrs.is_empty() {
        return Err(DevExError::Validation(
            "Webhook host could not be resolved".into(),
        ));
    }
    for addr in addrs {
        if is_private_ip(&addr.ip()) {
            return Err(DevExError::Validation(format!(
                "Webhook URL resolves to a private/internal IP: {} (via {host})",
                addr.ip()
            )));
        }
    }
    Ok(())
}

/// Check if an IP address is private/internal (same coverage as
/// worker-processors/src/webhook/ssrf.rs::is_private_ip).
pub fn is_private_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => is_private_ipv4(ip),
        IpAddr::V6(ip) => is_private_ipv6(ip),
    }
}

fn is_private_ipv4(ip: &Ipv4Addr) -> bool {
    let o = ip.octets();
    // Loopback 127.0.0.0/8, private 10/8, 172.16/12, 192.168/16,
    // link-local (incl. cloud metadata) 169.254/16, CGNAT 100.64/10,
    // documentation ranges, broadcast/unspecified.
    o[0] == 127
        || o[0] == 10
        || (o[0] == 172 && (16..=31).contains(&o[1]))
        || (o[0] == 192 && o[1] == 168)
        || (o[0] == 169 && o[1] == 254)
        || (o[0] == 100 && (64..=127).contains(&o[1]))
        || (o[0] == 192 && o[1] == 0 && o[2] == 2)
        || (o[0] == 198 && o[1] == 51 && o[2] == 100)
        || (o[0] == 203 && o[1] == 0 && o[2] == 113)
        || ip.is_broadcast()
        || ip.is_unspecified()
}

fn is_private_ipv6(ip: &Ipv6Addr) -> bool {
    if ip.is_loopback() || ip.is_unspecified() {
        return true;
    }
    let s = ip.segments();
    // Link-local fe80::/10, unique-local fc00::/7, deprecated site-local fec0::/10.
    if s[0] & 0xffc0 == 0xfe80 || s[0] & 0xfe00 == 0xfc00 || s[0] & 0xffc0 == 0xfec0 {
        return true;
    }
    // 6to4 (2002::/16) and Teredo (2001:0::/32) embed IPv4 — inspect it.
    if s[0] == 0x2002 {
        let embedded = Ipv4Addr::new((s[1] >> 8) as u8, (s[1] & 0xff) as u8, (s[2] >> 8) as u8, (s[2] & 0xff) as u8);
        if is_private_ipv4(&embedded) {
            return true;
        }
    }
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
    // IPv4-mapped addresses.
    if let Some(v4) = ip.to_ipv4_mapped() {
        return is_private_ipv4(&v4);
    }
    false
}

/// RS-064: Constant-time byte comparison that does NOT leak length through timing.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    let len_matches = a.len() == b.len();
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter().chain(std::iter::repeat(&0))) {
        diff |= x ^ y;
    }
    for y in b.iter().skip(a.len()) {
        diff |= *y;
    }
    len_matches && diff == 0
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_test_payload_structure() {
        let payload = WebhookTester::build_test_payload("email.delivered");
        assert_eq!(payload["type"], "email.delivered");
        assert_eq!(payload["test"], true);
        assert!(payload["id"].as_str().unwrap().starts_with("evt_"));
        assert!(payload["data"]["email_id"]
            .as_str()
            .unwrap()
            .starts_with("msg_"));
    }

    #[test]
    fn test_sign_and_verify() {
        let secrets = vec!["whsec_test_secret_12345".to_string()];
        let tester = WebhookTester::new(secrets.clone());
        assert!(tester.is_ok());
        let tester = tester.unwrap();
        let body = b"{\"type\":\"email.delivered\"}";
        let sig = tester.sign_payload(body);

        assert!(sig.starts_with("t="));
        assert!(sig.contains(",v1="));
        assert!(tester.verify_signature(body, &sig));
    }

    #[test]
    fn test_verify_wrong_secret_fails() {
        let secrets = vec!["correct_secret".to_string()];
        let tester = WebhookTester::new(secrets).unwrap();
        let body = b"{}";
        let sig = tester.sign_payload(body);

        // Create a tester with only a different secret
        let wrong_tester = WebhookTester::new(vec!["wrong_secret".to_string()]).unwrap();
        assert!(!wrong_tester.verify_signature(body, &sig));
    }

    #[test]
    fn test_verify_malformed_header() {
        let secrets = vec!["secret".to_string()];
        let tester = WebhookTester::new(secrets).unwrap();
        assert!(!tester.verify_signature(b"body", "garbage"));
        assert!(!tester.verify_signature(b"body", ""));
        assert!(!tester.verify_signature(b"body", "t=,v1="));
    }

    #[test]
    fn test_verify_with_rotated_secret() {
        // Simulate rotation: old key still works for verification
        let old_secret = "old_secret_key".to_string();
        let new_secret = "new_secret_key".to_string();
        // New key is first (active for signing), old key is second (still accepted)
        let tester = WebhookTester::new(vec![new_secret.clone(), old_secret.clone()]).unwrap();
        let body = b"{\"type\":\"email.delivered\"}";
        let sig = tester.sign_payload(body);

        // Verify with the new primary secret should work
        assert!(tester.verify_signature(body, &sig));

        // A tester with ONLY the old secret should still verify the signature
        // (but in reality the signature was created with new_secret, so old_secret alone won't work)
        // Actually let's test the rotation path: we verify that the WebhookTester
        // with both secrets can verify payloads signed by either secret.
        let old_only_tester = WebhookTester::new(vec![old_secret.clone()]).unwrap();
        let old_sig = old_only_tester.sign_payload(body);
        assert!(
            tester.verify_signature(body, &old_sig),
            "rotated tester must verify payloads signed with old secret"
        );
    }

    #[test]
    fn test_empty_secrets_rejected() {
        let result = WebhookTester::new(vec![]);
        assert!(result.is_err());
    }

    #[test]
    fn test_shared_ssrf_classifier_blocks_localhost_and_ipv6_link_local() {
        assert!(is_private_or_reserved_host("localhost"));
        assert!(is_private_or_reserved_host("127.0.0.1"));
        assert!(is_private_or_reserved_host("fe80::1"));
        assert!(!is_private_or_reserved_host("hooks.apexmail.ee"));
    }

    // ── G.4: resolving SSRF guard tests ────────────────────────────────

    fn addr(ip: &str) -> SocketAddr {
        SocketAddr::new(ip.parse().unwrap(), 443)
    }

    #[test]
    fn private_resolving_addresses_are_rejected() {
        for ip in [
            "127.0.0.1",
            "10.1.2.3",
            "172.16.0.9",
            "192.168.1.1",
            "169.254.169.254", // cloud metadata
            "100.64.0.1",      // CGNAT
            "::1",
            "fe80::1",
            "fc00::1",
            "::ffff:127.0.0.1", // IPv4-mapped
        ] {
            let err = validate_resolved_addrs("evil.example", &[addr(ip)])
                .expect_err("private/resolved target must be rejected");
            assert!(
                matches!(err, DevExError::Validation(_)),
                "expected Validation error for {ip}"
            );
        }
        // ANY private answer in the set rejects the whole set.
        assert!(validate_resolved_addrs(
            "mixed.example",
            &[addr("8.8.8.8"), addr("10.0.0.5")]
        )
        .is_err());
    }

    #[test]
    fn public_resolving_addresses_pass() {
        assert!(validate_resolved_addrs("ok.example", &[addr("8.8.8.8")]).is_ok());
        assert!(validate_resolved_addrs(
            "ok.example",
            &[addr("1.1.1.1"), addr("2606:4700:4700::1111")]
        )
        .is_ok());
        // Empty answer set is a resolution failure, not a pass.
        assert!(validate_resolved_addrs("empty.example", &[]).is_err());
    }

    /// A hostname that RESOLVES to loopback (works offline via /etc/hosts)
    /// must be rejected by the resolving guard — the hostname-only check
    /// cannot catch this class.
    #[tokio::test]
    async fn loopback_resolving_hostname_is_rejected() {
        let addrs = resolve_host("localhost", 443).await.unwrap();
        assert!(!addrs.is_empty());
        let err = validate_resolved_addrs("localhost", &addrs)
            .expect_err("localhost resolves to loopback — must be rejected");
        assert!(matches!(err, DevExError::Validation(_)));
    }

    /// Direct IP-literal private targets are rejected end-to-end before any
    /// HTTP request is attempted.
    #[tokio::test]
    async fn send_test_webhook_rejects_private_target() {
        let tester = WebhookTester::new(vec!["whsec_test".to_string()]).unwrap();
        for url in [
            "http://127.0.0.1:8080/hook",
            "http://10.0.0.1/hook",
            "http://[::1]:8080/hook",
        ] {
            let err = tester
                .send_test_webhook(url, "email.delivered")
                .await
                .expect_err("private target must be rejected before sending");
            assert!(
                matches!(err, DevExError::Validation(_)),
                "expected Validation error for {url}, got {err:?}"
            );
        }
    }

    /// A public hostname passes the resolving guard (network-dependent —
    /// skipped when DNS is unavailable in the test environment).
    #[tokio::test]
    async fn send_test_webhook_allows_public_target() {
        let addrs = match resolve_host("example.com", 443).await {
            Ok(addrs) if !addrs.is_empty() => addrs,
            _ => {
                eprintln!("skipping: DNS unavailable in test environment");
                return;
            }
        };
        assert!(validate_resolved_addrs("example.com", &addrs).is_ok());
    }
}
