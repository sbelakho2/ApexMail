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
    http: reqwest::Client,
    /// Ordered list of active signing secrets (first = active signing key).
    signing_secrets: Vec<String>,
}

impl WebhookTester {
    /// Create a new tester with one or more signing secrets.
    /// The **first** secret is used for signing; all are accepted for verification.
    ///
    /// Returns an error if the list is empty.
    pub fn new(signing_secrets: Vec<String>) -> Result<Self, DevExError> {
        if signing_secrets.is_empty() {
            return Err(DevExError::WebhookError(
                "At least one webhook signing secret is required".into(),
            ));
        }
        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .map_err(|e| DevExError::WebhookError(format!("HTTP client: {e}")))?;

        Ok(Self {
            http,
            signing_secrets,
        })
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
        if let Some(host) = parsed.host_str() {
            if is_private_or_reserved_host(host) {
                return Err(DevExError::Validation(
                    "Webhook URLs pointing to private/internal networks are not allowed".into(),
                ));
            }
        } else {
            return Err(DevExError::Validation(
                "Webhook URL must have a host".into(),
            ));
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
}
