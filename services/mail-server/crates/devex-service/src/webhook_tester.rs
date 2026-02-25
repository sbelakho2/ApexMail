//! Webhook testing — send test payloads, verify HMAC-SHA256 signatures.
//!
//! Mirrors the TypeScript `WebhookService` test-related helpers.

use chrono::Utc;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::net::IpAddr;
use uuid::Uuid;

use crate::types::{DevExError, WebhookTestResult};

type HmacSha256 = Hmac<Sha256>;

/// Webhook tester — sends test payloads and validates signatures.
#[derive(Debug, Clone)]
pub struct WebhookTester {
    http: reqwest::Client,
    signing_secret: String,
}

impl WebhookTester {
    /// Create a new tester with the given signing secret.
    pub fn new(signing_secret: String) -> Self {
        Self {
            http: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(10))
                .build()
                .expect("reqwest client"),
            signing_secret,
        }
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
    pub fn sign_payload(&self, body: &[u8]) -> String {
        let timestamp = Utc::now().timestamp();
        let signed_content = format!("{}.{}", timestamp, String::from_utf8_lossy(body));

        let mut mac =
            HmacSha256::new_from_slice(self.signing_secret.as_bytes()).expect("HMAC key length");
        mac.update(signed_content.as_bytes());
        let result = mac.finalize();
        let sig = hex::encode(result.into_bytes());

        format!("t={},v1={}", timestamp, sig)
    }

    /// Verify that a signature header is valid for the given body + secret.
    pub fn verify_signature(secret: &str, body: &[u8], signature_header: &str) -> bool {
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

        let Ok(mut mac) = HmacSha256::new_from_slice(secret.as_bytes()) else {
            return false;
        };
        mac.update(signed_content.as_bytes());
        let expected = hex::encode(mac.finalize().into_bytes());

        // Constant-time comparison to prevent timing attacks.
        constant_time_eq(expected.as_bytes(), provided_sig.as_bytes())
    }

    /// Send a test webhook to the given URL.
    pub async fn send_test_webhook(
        &self,
        url: &str,
        event_type: &str,
    ) -> Result<WebhookTestResult, DevExError> {
        // SSRF protection: only allow https (or http) with public hostnames
        let parsed = url::Url::parse(url)
            .map_err(|_| DevExError::Validation("Invalid webhook URL".into()))?;

        match parsed.scheme() {
            "https" | "http" => {}
            _ => return Err(DevExError::Validation("Only http/https URLs are allowed".into())),
        }

        // Block requests to private/internal networks
        if let Some(host) = parsed.host_str() {
            if is_private_host(host) {
                return Err(DevExError::Validation(
                    "Webhook URLs pointing to private/internal networks are not allowed".into(),
                ));
            }
        } else {
            return Err(DevExError::Validation("Webhook URL must have a host".into()));
        }

        let payload = Self::build_test_payload(event_type);
        let body = serde_json::to_vec(&payload)?;
        let signature = self.sign_payload(&body);

        let start = std::time::Instant::now();

        let result = self
            .http
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

/// Constant-time byte comparison.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

fn is_private_host(host: &str) -> bool {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return is_private_ip(ip);
    }

    let lower = host.to_lowercase();
    lower == "localhost"
        || lower == "::1"
        || lower == "[::1]"
        || lower == "0.0.0.0"
        || lower.ends_with(".local")
        || lower.ends_with(".internal")
        || lower == "metadata.google.internal"
}

fn is_private_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_unspecified()
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unique_local()
                || v6.is_unicast_link_local()
                || v6.is_unspecified()
        }
    }
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
        assert!(payload["data"]["email_id"].as_str().unwrap().starts_with("msg_"));
    }

    #[test]
    fn test_sign_and_verify() {
        let secret = "whsec_test_secret_12345";
        let tester = WebhookTester::new(secret.to_string());
        let body = b"{\"type\":\"email.delivered\"}";
        let sig = tester.sign_payload(body);

        // The signature should start with "t=" and contain "v1="
        assert!(sig.starts_with("t="));
        assert!(sig.contains(",v1="));

        // Verify with the same secret should succeed
        assert!(WebhookTester::verify_signature(secret, body, &sig));
    }

    #[test]
    fn test_verify_wrong_secret_fails() {
        let tester = WebhookTester::new("correct_secret".to_string());
        let body = b"{}";
        let sig = tester.sign_payload(body);

        assert!(!WebhookTester::verify_signature("wrong_secret", body, &sig));
    }

    #[test]
    fn test_verify_malformed_header() {
        assert!(!WebhookTester::verify_signature(
            "secret",
            b"body",
            "garbage"
        ));
        assert!(!WebhookTester::verify_signature("secret", b"body", ""));
        assert!(!WebhookTester::verify_signature(
            "secret",
            b"body",
            "t=,v1="
        ));
    }
}
