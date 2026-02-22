//! Tracking pixel and link rewriting.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::sync::LazyLock;

use super::types::EmailJob;
use crate::common::TrackingConfig;

/// Tracking payload encoded in URLs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrackingPayload {
    /// Message ID.
    #[serde(rename = "m")]
    pub message_id: String,
    /// Tenant ID.
    #[serde(rename = "t")]
    pub tenant_id: String,
    /// Recipient email (hashed for privacy).
    #[serde(rename = "r")]
    pub recipient_hash: String,
    /// Original URL (for click tracking).
    #[serde(rename = "u", skip_serializing_if = "Option::is_none")]
    pub original_url: Option<String>,
    /// Campaign ID.
    #[serde(rename = "c", skip_serializing_if = "Option::is_none")]
    pub campaign_id: Option<String>,
}

/// Regex for matching href attributes in HTML.
static HREF_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"href\s*=\s*["']([^"']+)["']"#).expect("Invalid href regex")
});

/// Encode a tracking payload to a URL-safe string.
pub fn encode_tracking_id(payload: &TrackingPayload) -> String {
    let json = serde_json::to_string(payload).unwrap_or_default();
    URL_SAFE_NO_PAD.encode(json.as_bytes())
}

/// Decode a tracking ID back to its payload.
pub fn decode_tracking_id(encoded: &str) -> Option<TrackingPayload> {
    let bytes = URL_SAFE_NO_PAD.decode(encoded).ok()?;
    serde_json::from_slice(&bytes).ok()
}

/// Hash an email address for privacy-preserving tracking.
fn hash_email(email: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(email.as_bytes());
    let result = hasher.finalize();
    // Use first 8 bytes encoded as hex (16 chars) for compactness
    hex::encode(&result[..8])
}

/// Add an invisible tracking pixel to HTML content.
pub fn add_tracking_pixel(html: &str, job: &EmailJob, config: &TrackingConfig) -> String {
    let payload = TrackingPayload {
        message_id: job.message_id.clone(),
        tenant_id: job.tenant_id.clone(),
        recipient_hash: hash_email(&job.to),
        original_url: None,
        campaign_id: job.campaign_id.clone(),
    };

    let tracking_id = encode_tracking_id(&payload);
    let pixel_url = format!(
        "{}{}/{}",
        config.base_url, config.open_pixel_path, tracking_id
    );

    // Insert pixel before closing </body> tag, or append if no </body>
    let pixel_html = format!(
        r#"<img src="{}" width="1" height="1" style="display:none" alt="" />"#,
        pixel_url
    );

    if let Some(pos) = html.to_lowercase().rfind("</body>") {
        let mut result = html.to_string();
        result.insert_str(pos, &pixel_html);
        result
    } else {
        format!("{}{}", html, pixel_html)
    }
}

/// Rewrite links in HTML content for click tracking.
pub fn rewrite_links(html: &str, job: &EmailJob, config: &TrackingConfig) -> String {
    HREF_REGEX
        .replace_all(html, |caps: &regex::Captures| {
            let original_url = caps.get(1).map(|m| m.as_str()).unwrap_or("");

            // Skip mailto:, tel:, and internal links
            if original_url.starts_with("mailto:")
                || original_url.starts_with("tel:")
                || original_url.starts_with("#")
                || original_url.starts_with("{{")
            {
                return caps[0].to_string();
            }

            // Skip unsubscribe links (they should work directly)
            if original_url.contains("unsubscribe") || original_url.contains("opt-out") {
                return caps[0].to_string();
            }

            let payload = TrackingPayload {
                message_id: job.message_id.clone(),
                tenant_id: job.tenant_id.clone(),
                recipient_hash: hash_email(&job.to),
                original_url: Some(original_url.to_string()),
                campaign_id: job.campaign_id.clone(),
            };

            let tracking_id = encode_tracking_id(&payload);
            let tracked_url = format!(
                "{}{}/{}",
                config.base_url, config.click_redirect_path, tracking_id
            );

            format!(r#"href="{}""#, tracked_url)
        })
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_decode_tracking_id() {
        let payload = TrackingPayload {
            message_id: "msg_123".to_string(),
            tenant_id: "ten_456".to_string(),
            recipient_hash: "abc123".to_string(),
            original_url: Some("https://example.com".to_string()),
            campaign_id: Some("camp_789".to_string()),
        };

        let encoded = encode_tracking_id(&payload);
        let decoded = decode_tracking_id(&encoded).expect("decode failed");

        assert_eq!(decoded.message_id, payload.message_id);
        assert_eq!(decoded.tenant_id, payload.tenant_id);
        assert_eq!(decoded.original_url, payload.original_url);
    }

    #[test]
    fn test_add_tracking_pixel() {
        let html = "<html><body><p>Hello</p></body></html>";
        let job = EmailJob {
            id: "job_1".to_string(),
            message_id: "msg_1".to_string(),
            tenant_id: "ten_1".to_string(),
            domain_id: "dom_1".to_string(),
            from: "sender@example.com".to_string(),
            to: "recipient@example.com".to_string(),
            subject: "Test".to_string(),
            html: Some(html.to_string()),
            text: None,
            headers: None,
            attachments: None,
            campaign_id: None,
            tags: None,
            metadata: None,
            scheduled_at: None,
            attempt: 1,
            created_at: chrono::Utc::now(),
        };
        let config = TrackingConfig {
            enabled: true,
            base_url: "https://track.example.com".to_string(),
            open_pixel_path: "/o".to_string(),
            click_redirect_path: "/c".to_string(),
        };

        let result = add_tracking_pixel(html, &job, &config);
        assert!(result.contains("https://track.example.com/o/"));
        assert!(result.contains(r#"width="1" height="1""#));
    }

    #[test]
    fn test_rewrite_links() {
        let html = r#"<a href="https://example.com/page">Click here</a>"#;
        let job = EmailJob {
            id: "job_1".to_string(),
            message_id: "msg_1".to_string(),
            tenant_id: "ten_1".to_string(),
            domain_id: "dom_1".to_string(),
            from: "sender@example.com".to_string(),
            to: "recipient@example.com".to_string(),
            subject: "Test".to_string(),
            html: Some(html.to_string()),
            text: None,
            headers: None,
            attachments: None,
            campaign_id: None,
            tags: None,
            metadata: None,
            scheduled_at: None,
            attempt: 1,
            created_at: chrono::Utc::now(),
        };
        let config = TrackingConfig {
            enabled: true,
            base_url: "https://track.example.com".to_string(),
            open_pixel_path: "/o".to_string(),
            click_redirect_path: "/c".to_string(),
        };

        let result = rewrite_links(html, &job, &config);
        assert!(result.contains("https://track.example.com/c/"));
        assert!(!result.contains("https://example.com/page"));
    }

    #[test]
    fn test_skip_mailto_links() {
        let html = r#"<a href="mailto:test@example.com">Email us</a>"#;
        let job = EmailJob {
            id: "job_1".to_string(),
            message_id: "msg_1".to_string(),
            tenant_id: "ten_1".to_string(),
            domain_id: "dom_1".to_string(),
            from: "sender@example.com".to_string(),
            to: "recipient@example.com".to_string(),
            subject: "Test".to_string(),
            html: Some(html.to_string()),
            text: None,
            headers: None,
            attachments: None,
            campaign_id: None,
            tags: None,
            metadata: None,
            scheduled_at: None,
            attempt: 1,
            created_at: chrono::Utc::now(),
        };
        let config = TrackingConfig {
            enabled: true,
            base_url: "https://track.example.com".to_string(),
            open_pixel_path: "/o".to_string(),
            click_redirect_path: "/c".to_string(),
        };

        let result = rewrite_links(html, &job, &config);
        // mailto links should not be rewritten
        assert!(result.contains("mailto:test@example.com"));
    }
}
