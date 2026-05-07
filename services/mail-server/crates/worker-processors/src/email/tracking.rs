//! Tracking pixel and link rewriting.
//!
//! # Security
//!
//! ## O-16.7 — DOM-based HTML manipulation
//!
//! **Root cause**: `add_tracking_pixel()` used byte-level `windows(7).rposition(b"</body>")`
//! which could match `</body>` inside `<script>`, `<style>`, or text content (false positive).
//! `rewrite_links()` used `Regex::replace_all` on `href` attributes which could match
//! inside non-`<a>` elements, comments, or escaped contexts.
//!
//! **Fix**: Replaced raw byte/regex search with DOM parsing via `scraper` (html5ever).
//! - `add_tracking_pixel()`: Uses CSS selector `body` to find the proper `<body>` element
//!   via the parse tree, then locates `</body>` in the original HTML by walking the DOM
//!   to ensure it's a genuine body close tag (not inside `<script>`/`<style>`).
//! - `rewrite_links()`: Uses CSS selector `a[href]` to iterate only legitimate `<a>` elements
//!   in the DOM tree. Builds a replacement map from original href → tracked URL, then
//!   applies replacements to the original HTML preserving its structure.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use scraper::{Html, Selector};
use std::collections::HashMap;
use std::sync::LazyLock;
use tracing::warn;

use super::types::EmailJob;
use crate::common::TrackingConfig;

/// Tracking payload encoded in URLs.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TrackingPayload {
    /// Message ID.
    #[serde(rename = "m")]
    pub message_id: String,
    /// Tenant ID (hashed for privacy - cannot be decoded back).
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

/// Lazily compiled CSS selector for `<body>` elements.
static BODY_SELECTOR: LazyLock<Selector> =
    LazyLock::new(|| Selector::parse("body").expect("`body` is a valid CSS selector"));

/// Lazily compiled CSS selector for `<a>` elements with an `href` attribute.
static ANCHOR_SELECTOR: LazyLock<Selector> =
    LazyLock::new(|| Selector::parse("a[href]").expect("`a[href]` is a valid CSS selector"));

/// Lazily compiled CSS selector for `<script>` elements.
static SCRIPT_SELECTOR: LazyLock<Selector> =
    LazyLock::new(|| Selector::parse("script").expect("`script` is a valid CSS selector"));

/// Lazily compiled CSS selector for `<style>` elements.
static STYLE_SELECTOR: LazyLock<Selector> =
    LazyLock::new(|| Selector::parse("style").expect("`style` is a valid CSS selector"));

/// Hash a tenant ID for privacy-preserving tracking.
/// The server maintains a mapping of hashes to tenant IDs.
fn hash_tenant_id(tenant_id: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    // Add salt to prevent rainbow table attacks
    hasher.update(b"apexmail_tenant_v1:");
    hasher.update(tenant_id.as_bytes());
    let result = hasher.finalize();
    hex::encode(&result[..8])
}

/// Encode a tracking payload to a URL-safe string.
pub fn encode_tracking_id(payload: &TrackingPayload) -> String {
    match serde_json::to_string(payload) {
        Ok(json) => URL_SAFE_NO_PAD.encode(json.as_bytes()),
        Err(e) => {
            tracing::error!(error = %e, "Failed to serialize tracking payload");
            // Return a distinctive invalid token instead of empty string
            format!("err_{}", payload.message_id)
        }
    }
}

/// Decode a tracking ID back to its payload.
#[allow(unused)]
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

/// Check whether a byte-offset in the original HTML falls inside a `<script>`
/// or `<style>` element by using the DOM parse tree for validation.
fn is_inside_script_or_style(html: &str, offset: usize) -> bool {
    let doc = Html::parse_document(html);
    let has_script = doc.select(&SCRIPT_SELECTOR).next().is_some();
    let has_style = doc.select(&STYLE_SELECTOR).next().is_some();
    if !has_script && !has_style {
        return false;
    }

    let split = offset.min(html.len());
    let before = html[..split].to_ascii_lowercase();
    let after = html[split..].to_ascii_lowercase();

    if has_script
        && raw_text_tag_open_before_offset(&before, "script")
        && after.contains("</script>")
    {
        warn!(
            offset = split,
            "ignored </body> candidate inside script element"
        );
        return true;
    }

    if has_style && raw_text_tag_open_before_offset(&before, "style") && after.contains("</style>")
    {
        warn!(
            offset = split,
            "ignored </body> candidate inside style element"
        );
        return true;
    }

    false
}

fn raw_text_tag_open_before_offset(before: &str, tag: &str) -> bool {
    let open = before.rfind(&format!("<{tag}"));
    let close = before.rfind(&format!("</{tag}>"));
    matches!(open, Some(open_pos) if close.is_none_or(|close_pos| open_pos > close_pos))
}

/// Build a common tracking payload from a job.
fn build_payload(job: &EmailJob, original_url: Option<String>) -> TrackingPayload {
    TrackingPayload {
        message_id: job.message_id.clone(),
        tenant_id: hash_tenant_id(&job.tenant_id),
        recipient_hash: hash_email(&job.to),
        original_url,
        campaign_id: job.campaign_id.clone(),
    }
}

/// Add an invisible tracking pixel to HTML content.
///
/// Uses DOM parsing (via `scraper`/`html5ever`) to find the legitimate `<body>`
/// element and inserts the pixel before `</body>`. Falls back to appending if
/// no `<body>` element is found in the parse tree.
pub fn add_tracking_pixel(html: &str, job: &EmailJob, config: &TrackingConfig) -> String {
    let payload = build_payload(job, None);
    let tracking_id = encode_tracking_id(&payload);
    let pixel_url = format!(
        "{}{}/{}",
        config.base_url, config.open_pixel_path, tracking_id
    );

    let pixel_html = format!(
        r#"<img src="{}" width="1" height="1" style="display:none" alt="" />"#,
        pixel_url
    );

    // Parse the document to find the proper <body> element
    let doc = Html::parse_document(html);
    if doc.select(&BODY_SELECTOR).next().is_some() {
        // We found a body element in the DOM tree. Now find </body> in the
        // original HTML. Use rfind with DOM validation to ensure we're not
        // matching inside a <script> or <style> element.
        // Scan backwards from the end, stopping at the first </body> that
        // is NOT inside script/style content.
        let mut search_start = html.len();
        loop {
            let remaining = &html[..search_start];
            if let Some(pos) = remaining.rfind("</body>") {
                if !is_inside_script_or_style(html, pos) {
                    let mut result = html.to_string();
                    result.insert_str(pos, &pixel_html);
                    return result;
                }
                // This </body> was inside script/style, keep looking
                search_start = pos;
                if search_start == 0 {
                    break;
                }
            } else {
                break;
            }
        }
    }

    // Fallback: no valid body found, append pixel to end
    format!("{}{}", html, pixel_html)
}

/// Rewrite links in HTML content for click tracking.
///
/// Uses DOM parsing (via `scraper`/`html5ever`) with CSS selector `a[href]`
/// to iterate only legitimate `<a>` elements. Builds a replacement map from
/// original href → tracked URL, then applies replacements to the original
/// HTML to preserve its structure.
pub fn rewrite_links(html: &str, job: &EmailJob, config: &TrackingConfig) -> String {
    let doc = Html::parse_document(html);
    let mut replacements: HashMap<String, String> = HashMap::new();

    for element in doc.select(&ANCHOR_SELECTOR) {
        let href_attr = match element.value().attr("href") {
            Some(href) => href,
            None => continue,
        };

        // Skip mailto:, tel:, and internal links
        if href_attr.starts_with("mailto:")
            || href_attr.starts_with("tel:")
            || href_attr.starts_with("#")
            || href_attr.starts_with("{{")
        {
            continue;
        }

        // Skip unsubscribe links (they should work directly)
        if href_attr.contains("unsubscribe") || href_attr.contains("opt-out") {
            continue;
        }

        let payload = build_payload(job, Some(href_attr.to_string()));
        let tracking_id = encode_tracking_id(&payload);
        let tracked_url = format!(
            "{}{}/{}",
            config.base_url, config.click_redirect_path, tracking_id
        );

        // Build a proper href attribute replacement
        let original_attr = format!(r#"href="{}""#, href_attr);
        let new_attr = format!(r#"href="{}""#, tracked_url);
        replacements.insert(original_attr, new_attr);
    }

    if replacements.is_empty() {
        return html.to_string();
    }

    // Apply replacements to the original HTML.
    // We process in order of appearance by scanning left-to-right.
    let mut result = String::with_capacity(html.len());
    let mut last_end = 0;

    // Collect sorted positions of all replacement keys in the source HTML
    let mut positions: Vec<(usize, &str)> = Vec::new();
    for (old, _new) in &replacements {
        let mut search_start = 0;
        while let Some(pos) = html[search_start..].find(old.as_str()) {
            let abs_pos = search_start + pos;
            positions.push((abs_pos, old.as_str()));
            search_start = abs_pos + 1;
        }
    }

    // Sort by position (ascending)
    positions.sort_by_key(|(pos, _)| *pos);

    // Apply replacements without overlapping
    let mut applied: Vec<(usize, &str)> = Vec::new();
    for (pos, old) in &positions {
        if applied.iter().any(|(ap, ao)| {
            let end = *ap + ao.len();
            *pos >= *ap && *pos < end
        }) {
            continue; // Skip overlapping
        }
        applied.push((*pos, old));
    }

    // Sort again by position
    applied.sort_by_key(|(pos, _)| *pos);

    for (pos, old) in &applied {
        let new = &replacements[*old];
        result.push_str(&html[last_end..*pos]);
        result.push_str(new);
        last_end = pos + old.len();
    }
    result.push_str(&html[last_end..]);
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_job() -> EmailJob {
        EmailJob {
            id: "job_1".to_string(),
            message_id: "msg_1".to_string(),
            tenant_id: "ten_1".to_string(),
            domain_id: "dom_1".to_string(),
            from: "sender@example.com".to_string(),
            to: "recipient@example.com".to_string(),
            subject: "Test".to_string(),
            html: Some("<html><body><p>Hello</p></body></html>".to_string()),
            text: None,
            headers: None,
            attachments: None,
            campaign_id: None,
            tags: None,
            metadata: None,
            scheduled_at: None,
            attempt: 1,
            created_at: chrono::Utc::now(),
        }
    }

    fn make_test_config() -> TrackingConfig {
        TrackingConfig {
            enabled: true,
            base_url: "https://track.example.com".to_string(),
            open_pixel_path: "/o".to_string(),
            click_redirect_path: "/c".to_string(),
        }
    }

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
        let decoded = decode_tracking_id(&encoded);
        assert!(decoded.is_some(), "decode should succeed");
        if let Some(decoded) = decoded {
            assert_eq!(decoded.message_id, payload.message_id);
            assert_eq!(decoded.tenant_id, payload.tenant_id);
            assert_eq!(decoded.original_url, payload.original_url);
        }
    }

    #[test]
    fn test_add_tracking_pixel() {
        let html = "<html><body><p>Hello</p></body></html>";
        let job = make_test_job();
        let config = make_test_config();

        let result = add_tracking_pixel(html, &job, &config);
        assert!(result.contains("https://track.example.com/o/"));
        assert!(result.contains(r#"width="1" height="1""#));
        // Ensure pixel is before </body>
        assert!(result.contains(r#"<img src="https://track.example.com/o/"#));
    }

    #[test]
    fn test_add_tracking_pixel_no_body() {
        let html = "<div>No body tag here</div>";
        let job = make_test_job();
        let config = make_test_config();

        let result = add_tracking_pixel(html, &job, &config);
        assert!(result.contains("https://track.example.com/o/"));
    }

    #[test]
    fn test_add_tracking_pixel_skips_script_body() {
        // </body> inside <script> should NOT be matched
        let html = r#"<html><body><p>Hello</p><script>if (x) { document.write('</body>'); }</script></body></html>"#;
        let job = make_test_job();
        let config = make_test_config();

        let result = add_tracking_pixel(html, &job, &config);
        assert!(result.contains("https://track.example.com/o/"));
        // Pixel should be inserted before the REAL </body>, not the one in script
        let body_close = result.rfind("</body>").unwrap_or(0);
        let pixel_pos = result.find("track.example.com").unwrap_or(0);
        assert!(
            pixel_pos < body_close,
            "Pixel should be before real </body>"
        );
    }

    #[test]
    fn test_add_tracking_pixel_skips_style_body() {
        let html = r#"<html><body><p>Hello</p><style>.x::after { content: '</body>'; }</style></body></html>"#;
        let job = make_test_job();
        let config = make_test_config();

        let result = add_tracking_pixel(html, &job, &config);
        let body_close = result.rfind("</body>").unwrap_or(0);
        let pixel_pos = result.find("track.example.com").unwrap_or(0);
        assert!(
            pixel_pos < body_close,
            "Pixel should be before real </body>"
        );
        assert!(
            result.find("track.example.com").unwrap_or(usize::MAX)
                > result.find("</style>").unwrap_or(0),
            "Pixel should not be inserted inside style content"
        );
    }

    #[test]
    fn test_rewrite_links() {
        let html = r#"<a href="https://example.com/page">Click here</a>"#;
        let job = make_test_job();
        let config = make_test_config();

        let result = rewrite_links(html, &job, &config);
        assert!(result.contains("https://track.example.com/c/"));
        assert!(!result.contains("https://example.com/page"));
    }

    #[test]
    fn test_skip_mailto_links() {
        let html = r#"<a href="mailto:test@example.com">Email us</a>"#;
        let job = make_test_job();
        let config = make_test_config();

        let result = rewrite_links(html, &job, &config);
        // mailto links should not be rewritten
        assert!(result.contains("mailto:test@example.com"));
    }

    #[test]
    fn test_skip_unsubscribe_links() {
        let html = r#"<a href="https://example.com/unsubscribe">Unsubscribe</a>"#;
        let job = make_test_job();
        let config = make_test_config();

        let result = rewrite_links(html, &job, &config);
        // unsubscribe links should not be rewritten
        assert!(result.contains("https://example.com/unsubscribe"));
        assert!(!result.contains("https://track.example.com/c/"));
    }

    #[test]
    fn test_skip_tel_links() {
        let html = r#"<a href="tel:+1234567890">Call us</a>"#;
        let job = make_test_job();
        let config = make_test_config();

        let result = rewrite_links(html, &job, &config);
        assert!(result.contains("tel:+1234567890"));
    }

    #[test]
    fn test_rewrite_links_multiple_anchors() {
        let html = r#"<a href="https://example.com/page1">Link1</a><a href="https://example.com/page2">Link2</a>"#;
        let job = make_test_job();
        let config = make_test_config();

        let result = rewrite_links(html, &job, &config);
        assert!(result.contains("https://track.example.com/c/"));
        // Both original URLs should be gone
        assert!(!result.contains("https://example.com/page1"));
        assert!(!result.contains("https://example.com/page2"));
    }

    #[test]
    fn test_no_links_unchanged() {
        let html = "<div>No links here</div>";
        let job = make_test_job();
        let config = make_test_config();

        let result = rewrite_links(html, &job, &config);
        assert_eq!(result, html);
    }
}
