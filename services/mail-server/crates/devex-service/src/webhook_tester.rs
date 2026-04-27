//! Webhook testing — send test payloads, verify HMAC-SHA256 signatures.
//!
//! Provides test-related webhook helpers.

use chrono::Utc;
use hmac::{Hmac, Mac};
use mail_common::is_private_or_reserved_host;
use sha2::Sha256;
use uuid::Uuid;

use crate::types::{DevExError, WebhookTestResult};
use tracing::warn;

type HmacSha256 = Hmac<Sha256>;

/// Webhook tester — sends test payloads and validates signatures.
#[derive(Debug, Clone)]
pub struct WebhookTester {
    http: reqwest::Client,
    signing_secret: String,
}

impl WebhookTester {
/// Create a new tester with the given signing secret.
    pub fn new(signing_secret: String) -> Result<Self, DevExError> {
        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .map_err(|e| DevExError::WebhookError(format!("HTTP client: {e}")))?;

        Ok(Self { http, signing_secret })
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

        let mut mac = match HmacSha256::new_from_slice(self.signing_secret.as_bytes()) {
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
// SSRF protection:only allow https (or http) with public hostnames
        let parsed = url::Url::parse(url)
            .map_err(|_| DevExError::Validation("Invalid webhook URL".into()))?;

        match parsed.scheme() {
            "https" | "http" => {}
            _ => return Err(DevExError::Validation("Only http/https URLs are allowed".into())),
        }

// Block requests to private/internal networks
        if let Some(host) = parsed.host_str() {
            if is_private_or_reserved_host(host) {
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
        assert!(tester.is_ok());
        let body = b"{\"type\":\"email.delivered\"}";
        let sig = tester
            .as_ref()
            .map(|t| t.sign_payload(body))
            .unwrap_or_default();

        assert!(sig.starts_with("t="));
        assert!(sig.contains(",v1="));
        assert!(WebhookTester::verify_signature(secret, body, &sig));
    }

    #[test]
    fn test_verify_wrong_secret_fails() {
        let tester = WebhookTester::new("correct_secret".to_string());
        assert!(tester.is_ok());
        let body = b"{}";
        let sig = tester
            .as_ref()
            .map(|t| t.sign_payload(body))
            .unwrap_or_default();

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

    #[test]
    fn test_shared_ssrf_classifier_blocks_localhost_and_ipv6_link_local() {
        assert!(is_private_or_reserved_host("localhost"));
        assert!(is_private_or_reserved_host("127.0.0.1"));
        assert!(is_private_or_reserved_host("fe80::1"));
        assert!(!is_private_or_reserved_host("hooks.apexmail.ee"));
    }
}
