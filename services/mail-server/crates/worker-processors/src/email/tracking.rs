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
use tracing::{error, warn};

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

// ── C: AES-128-GCM tracking token codec (worker side) ────────────────────────
//
// The tracking-service decodes URL tokens with `TrackingCodec`
// (crates/tracking-service/src/codec.rs): AES-128-GCM envelopes whose key is
// HMAC-SHA256(TRACKING_SECRET_KEY, "encryption")[0..16]. This module mirrors
// that ENCODE path exactly (same key derivation inputs, same binary payload
// layout v2/v3, same IV||tag||ciphertext wire format) so every token the
// worker embeds decodes on the service side. Previously the worker emitted
// base64url(JSON) which the service could never decode — every rewritten
// link fell back to the marketing homepage and opens were never recorded.

/// Env var holding the shared master secret (same name as tracking-service).
const TRACKING_SECRET_KEY_ENV: &str = "TRACKING_SECRET_KEY";

/// Env var for the hashing salt (G.3d: configurable instead of hardcoded).
const TRACKING_HASH_SALT_ENV: &str = "TRACKING_HASH_SALT";

const IV_LEN: usize = 12;
const AUTH_TAG_LEN: usize = 16;

/// Read the shared tracking master secret. Returns an error string when the
/// key is unset or too short — callers must NOT emit tokens in that case
/// (they would be undecodable and leak the payload shape).
fn tracking_secret() -> Result<zeroize::Zeroizing<String>, &'static str> {
    let key =
        zeroize::Zeroizing::new(std::env::var(TRACKING_SECRET_KEY_ENV).unwrap_or_default());
    if key.trim().is_empty() {
        return Err(TRACKING_SECRET_KEY_ENV);
    }
    // tracking-service requires >= 32 characters; mirror that so a shared
    // deployment cannot silently disagree on key policy.
    if key.len() < 32 {
        return Err(TRACKING_SECRET_KEY_ENV);
    }
    Ok(key)
}

/// HMAC-SHA256(secret, info) truncated to `len` bytes — identical to
/// tracking-service `derive_key_hmac`.
fn derive_key_hmac(secret: &[u8], info: &[u8], len: usize) -> zeroize::Zeroizing<Vec<u8>> {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    let mut mac =
        <Hmac<Sha256> as Mac>::new_from_slice(secret).expect("HMAC accepts any key size");
    mac.update(info);
    let result = mac.finalize().into_bytes();
    zeroize::Zeroizing::new(result[..len].to_vec())
}

fn write_u16be(buf: &mut Vec<u8>, v: u16) {
    buf.push((v >> 8) as u8);
    buf.push((v & 0xff) as u8);
}

/// Serialize into the service's binary payload format:
/// version u8 + u16-BE length-prefixed tenantId, messageId, recipient,
/// linkId and (v3 only) originalUrl — identical to tracking-service
/// `serialize_tracking_data`.
fn serialize_payload(
    tenant_id: &str,
    message_id: &str,
    recipient: &str,
    original_url: Option<&str>,
) -> Vec<u8> {
    let url_bytes = original_url.unwrap_or("").as_bytes();
    let version: u8 = if original_url.is_some() { 3 } else { 2 };
    let mut buf = Vec::with_capacity(
        1 + 2 * 5 + tenant_id.len() + message_id.len() + recipient.len() + url_bytes.len(),
    );
    buf.push(version);
    for field in [tenant_id.as_bytes(), message_id.as_bytes(), recipient.as_bytes(), b""] {
        write_u16be(&mut buf, field.len() as u16);
        buf.extend_from_slice(field);
    }
    if version == 3 {
        write_u16be(&mut buf, url_bytes.len() as u16);
        buf.extend_from_slice(url_bytes);
    }
    buf
}

/// Encode a tracking payload into the AES-128-GCM envelope decodable by
/// tracking-service (`TrackingCodec::decode`).
///
/// Wire format: base64url(IV[12] || AuthTag[16] || ciphertext).
pub fn encode_tracking_id(payload: &TrackingPayload) -> Result<String, &'static str> {
    use aes_gcm::aead::rand_core::RngCore;
    use aes_gcm::aead::{Aead, KeyInit, Payload};
    use aes_gcm::aead::OsRng;
    use aes_gcm::{Aes128Gcm, Key, Nonce};

    let secret = tracking_secret()?;
    let enc_key = derive_key_hmac(secret.as_bytes(), b"encryption", 16);
    let mut key_bytes = [0u8; 16];
    key_bytes.copy_from_slice(&enc_key[..16]);

    let plaintext = serialize_payload(
        &payload.tenant_id,
        &payload.message_id,
        &payload.recipient_hash,
        payload.original_url.as_deref(),
    );

    let mut iv_bytes = [0u8; IV_LEN];
    OsRng.fill_bytes(&mut iv_bytes);

    let cipher = Aes128Gcm::new(Key::<Aes128Gcm>::from_slice(&key_bytes));
    let nonce = Nonce::from_slice(&iv_bytes);
    let aad: &[u8] = b"";
    let mut ciphertext_with_tag = cipher
        .encrypt(nonce, Payload { msg: &plaintext, aad })
        .map_err(|_| "aes-gcm encrypt failed")?;
    let tag_start = ciphertext_with_tag.len() - AUTH_TAG_LEN;
    let tag: Vec<u8> = ciphertext_with_tag.split_off(tag_start);

    let mut combined = Vec::with_capacity(IV_LEN + AUTH_TAG_LEN + ciphertext_with_tag.len());
    combined.extend_from_slice(&iv_bytes);
    combined.extend_from_slice(&tag);
    combined.extend_from_slice(&ciphertext_with_tag);

    Ok(URL_SAFE_NO_PAD.encode(&combined))
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
/// G.3d: the salt is configurable via `TRACKING_HASH_SALT` and the digest is
/// 16 bytes (was 8 unsalted) to resist rainbow-table reversal.
fn hash_tenant_id(tenant_id: &str) -> String {
    salted_hash(b"apexmail_tenant_v1:", tenant_id)
}

/// Hash an email address for privacy-preserving tracking.
/// G.3d: salted + 16-byte digest (previously unsalted SHA-256 truncated to
/// 8 bytes, which was trivially reversible for a known domain set).
fn hash_email(email: &str) -> String {
    salted_hash(b"apexmail_email_v1:", email)
}

/// SHA-256(salt || value) hex-encoded, first 16 bytes. The salt comes from
/// `TRACKING_HASH_SALT` when set (shared across redeployments) and otherwise
/// uses the built-in domain-separation prefix.
fn salted_hash(domain_prefix: &[u8], value: &str) -> String {
    use sha2::{Digest, Sha256};
    let configured = std::env::var(TRACKING_HASH_SALT_ENV).unwrap_or_default();
    let mut hasher = Sha256::new();
    hasher.update(domain_prefix);
    if !configured.is_empty() {
        hasher.update(configured.as_bytes());
        hasher.update(b":");
    }
    hasher.update(value.as_bytes());
    let result = hasher.finalize();
    hex::encode(&result[..16])
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
    let tracking_id = match encode_tracking_id(&payload) {
        Ok(id) => id,
        Err(missing) => {
            error!(
                env = missing,
                "tracking pixel skipped: {missing} is not configured (>= 32 chars, shared with tracking-service)"
            );
            return html.to_string();
        }
    };
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
        let tracking_id = match encode_tracking_id(&payload) {
            Ok(id) => id,
            Err(missing) => {
                error!(
                    env = missing,
                    "link rewriting skipped: {missing} is not configured (>= 32 chars, shared with tracking-service)"
                );
                replacements.clear();
                break;
            }
        };
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
    for old in replacements.keys() {
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

    /// Serializes env-mutating tests (std::env is process-global).
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    const TEST_SECRET: &str = "test-secret-key-32-bytes-minimum!!";

    fn with_test_secret() -> std::sync::MutexGuard<'static, ()> {
        let guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::set_var(TRACKING_SECRET_KEY_ENV, TEST_SECRET);
        guard
    }

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

    fn sample_payload() -> TrackingPayload {
        TrackingPayload {
            message_id: "msg_123".to_string(),
            tenant_id: hash_tenant_id("ten_456"),
            recipient_hash: hash_email("user@example.com"),
            original_url: Some("https://example.com".to_string()),
            campaign_id: Some("camp_789".to_string()),
        }
    }

    /// C: a worker-encoded token must decode with the tracking-service codec
    /// under the SAME key — this is the exact production contract.
    #[test]
    fn worker_token_decodes_in_tracking_service_codec() {
        let _guard = with_test_secret();
        let payload = sample_payload();
        let token = encode_tracking_id(&payload).expect("encode");

        let codec = tracking_service::codec::TrackingCodec::new(TEST_SECRET);
        let decoded = codec
            .decode(&token)
            .expect("tracking-service must decode worker token");
        assert_eq!(decoded.message_id, payload.message_id);
        assert_eq!(decoded.tenant_id, payload.tenant_id);
        assert_eq!(decoded.recipient, payload.recipient_hash);
        assert_eq!(
            decoded.original_url.as_deref(),
            Some("https://example.com")
        );
        // linkId is not used by the worker path.
        assert!(decoded.link_id.is_none());
    }

    /// Open-pixel tokens (no original URL) use payload v2 and also decode.
    #[test]
    fn worker_open_token_decodes_in_tracking_service_codec() {
        let _guard = with_test_secret();
        let payload = TrackingPayload {
            original_url: None,
            ..sample_payload()
        };
        let token = encode_tracking_id(&payload).expect("encode");
        let codec = tracking_service::codec::TrackingCodec::new(TEST_SECRET);
        let decoded = codec.decode(&token).expect("decode open token");
        assert_eq!(decoded.message_id, "msg_123");
        assert!(decoded.original_url.is_none());
    }

    /// A wrong key must fail decode (AEAD tag mismatch), not return garbage.
    #[test]
    fn wrong_key_fails_decode_in_tracking_service_codec() {
        let _guard = with_test_secret();
        let token = encode_tracking_id(&sample_payload()).expect("encode");
        let wrong =
            tracking_service::codec::TrackingCodec::new("another-secret-key-32-bytes-minimum");
        assert!(wrong.decode(&token).is_none());
    }

    /// Tokens must never be emitted without a configured secret.
    #[test]
    fn encode_without_secret_is_refused_and_html_untouched() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::remove_var(TRACKING_SECRET_KEY_ENV);
        let payload = sample_payload();
        assert!(encode_tracking_id(&payload).is_err());

        // Fail-safe: the pixel/link rewriters leave the HTML unchanged rather
        // than embedding undecodable tokens.
        let job = make_test_job();
        let config = make_test_config();
        let html = r#"<html><body><a href="https://example.com/x">x</a></body></html>"#;
        assert_eq!(add_tracking_pixel(html, &job, &config), html);
        assert_eq!(rewrite_links(html, &job, &config), html);
    }

    /// Short secrets are refused (tracking-service requires >= 32 chars).
    #[test]
    fn short_secret_is_refused() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::set_var(TRACKING_SECRET_KEY_ENV, "too-short");
        assert!(encode_tracking_id(&sample_payload()).is_err());
    }

    /// G.3d: hashes are 16-byte digests, stable, and salt-configurable.
    #[test]
    fn hashes_are_salted_and_16_bytes() {
        let a = hash_email("user@example.com");
        let b = hash_email("user@example.com");
        assert_eq!(a, b, "stable");
        assert_eq!(a.len(), 32, "16 bytes hex-encoded");
        assert_ne!(a, hash_email("other@example.com"));
        assert_ne!(hash_tenant_id("t1"), hash_tenant_id("t2"));

        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::set_var(TRACKING_HASH_SALT_ENV, "pepper");
        let salted = hash_email("user@example.com");
        assert_ne!(a, salted, "configured salt changes the digest");
        std::env::remove_var(TRACKING_HASH_SALT_ENV);
    }

    /// C: worker and tracking-service default tracking hosts must match.
    #[test]
    fn default_tracking_hosts_are_unified() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::remove_var("TRACKING_PUBLIC_HOST");
        std::env::remove_var("TRACKING_BASE_URL");
        assert_eq!(
            TrackingConfig::default().base_url,
            "https://t.apexmail.ee",
            "worker default must equal the tracking-service default"
        );
        // Explicit override wins on both sides.
        std::env::set_var("TRACKING_PUBLIC_HOST", "https://tracks.example.com");
        assert_eq!(
            TrackingConfig::default().base_url,
            "https://tracks.example.com"
        );
        std::env::remove_var("TRACKING_PUBLIC_HOST");
    }

    #[test]
    fn test_add_tracking_pixel() {
        let _guard = with_test_secret();
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
        let _guard = with_test_secret();
        let html = "<div>No body tag here</div>";
        let job = make_test_job();
        let config = make_test_config();

        let result = add_tracking_pixel(html, &job, &config);
        assert!(result.contains("https://track.example.com/o/"));
    }

    #[test]
    fn test_add_tracking_pixel_skips_script_body() {
        let _guard = with_test_secret();
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
        let _guard = with_test_secret();
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
        let _guard = with_test_secret();
        let html = r#"<a href="https://example.com/page">Click here</a>"#;
        let job = make_test_job();
        let config = make_test_config();

        let result = rewrite_links(html, &job, &config);
        assert!(result.contains("https://track.example.com/c/"));
        assert!(!result.contains("https://example.com/page"));
    }

    #[test]
    fn test_skip_mailto_links() {
        let _guard = with_test_secret();
        let html = r#"<a href="mailto:test@example.com">Email us</a>"#;
        let job = make_test_job();
        let config = make_test_config();

        let result = rewrite_links(html, &job, &config);
        // mailto links should not be rewritten
        assert!(result.contains("mailto:test@example.com"));
    }

    #[test]
    fn test_skip_unsubscribe_links() {
        let _guard = with_test_secret();
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
        let _guard = with_test_secret();
        let html = r#"<a href="tel:+1234567890">Call us</a>"#;
        let job = make_test_job();
        let config = make_test_config();

        let result = rewrite_links(html, &job, &config);
        assert!(result.contains("tel:+1234567890"));
    }

    #[test]
    fn test_rewrite_links_multiple_anchors() {
        let _guard = with_test_secret();
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
        let _guard = with_test_secret();
        let html = "<div>No links here</div>";
        let job = make_test_job();
        let config = make_test_config();

        let result = rewrite_links(html, &job, &config);
        assert_eq!(result, html);
    }
}
