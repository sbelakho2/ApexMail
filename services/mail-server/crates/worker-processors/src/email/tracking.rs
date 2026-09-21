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

const IV_LEN: usize = 12;
const AUTH_TAG_LEN: usize = 16;

/// Read the shared tracking master secret. Returns an error string when the
/// key is unset or too short — callers must NOT emit tokens in that case
/// (they would be undecodable and leak the payload shape).
fn tracking_secret() -> Result<zeroize::Zeroizing<String>, &'static str> {
    let key = zeroize::Zeroizing::new(std::env::var(TRACKING_SECRET_KEY_ENV).unwrap_or_default());
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
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(secret).expect("HMAC accepts any key size");
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
    for field in [
        tenant_id.as_bytes(),
        message_id.as_bytes(),
        recipient.as_bytes(),
        b"",
    ] {
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
    use aes_gcm::aead::OsRng;
    use aes_gcm::aead::{Aead, KeyInit, Payload};
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
        .encrypt(
            nonce,
            Payload {
                msg: &plaintext,
                aad,
            },
        )
        .map_err(|_| "aes-gcm encrypt failed")?;
    let tag_start = ciphertext_with_tag.len() - AUTH_TAG_LEN;
    let tag: Vec<u8> = ciphertext_with_tag.split_off(tag_start);

    let mut combined = Vec::with_capacity(IV_LEN + AUTH_TAG_LEN + ciphertext_with_tag.len());
    combined.extend_from_slice(&iv_bytes);
    combined.extend_from_slice(&tag);
    combined.extend_from_slice(&ciphertext_with_tag);

    Ok(URL_SAFE_NO_PAD.encode(&combined))
}

// ── F13: server-owned unsubscribe link (v2 token) ────────────────────────────

/// F13: build the unsubscribe identity/link for ONE outgoing copy, using the
/// tracking-service's v2 token codec (`generate_unsubscribe_token_with_message`)
/// with SERVER-OWNED identity — the persisted tenant id, the originating
/// message id, and this copy's envelope recipient. The token's
/// authenticated envelope IS the persisted attribution: activating the link
/// later names exactly this message even after a newer send to the same
/// recipient (the legacy latest-message lookup could misattribute).
///
/// * Returns `None` (and the send proceeds unchanged) when the shared
///   `TRACKING_SECRET_KEY` is not configured — suppression NEVER depends on
///   attribution success; the recipient's unsubscribe still works through
///   the legacy token paths.
/// * The URL feeds the `List-Unsubscribe` header (plus
///   `List-Unsubscribe-Post: Yes` — the tracking-service serves RFC 8058
///   one-click POST on the same route) and `{{unsubscribe_url}}`
///   placeholders in the caller's HTML/text bodies.
/// * The sales-autopilot unsubscribe format is deliberately separate and is
///   not touched here.
pub fn unsubscribe_link(job: &EmailJob, config: &TrackingConfig) -> Option<(String, String)> {
    let secret = config.secret_key.as_ref()?;
    let codec = tracking_service::codec::TrackingCodec::new(secret);
    let token = codec
        .generate_unsubscribe_token_with_message(&job.tenant_id, &job.to, &job.message_id)
        .ok()?;
    let base = config.base_url.trim_end_matches('/');
    let path = config.unsubscribe_path.trim_end_matches('/');
    let url = format!("{base}{path}/{token}");
    Some((token, url))
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
        // RAW identifiers (see build_payload_carries_raw_identifiers): the
        // token is AES-128-GCM encrypted; hashing here broke the
        // tracking-service's domain authorization, tenant attribution, and
        // one-click suppression. Analytics pseudonymization happens at
        // ClickHouse ingest via recipient_for_analytics.
        tenant_id: job.tenant_id.clone(),
        recipient_hash: job.to.clone(),
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
/// to decide WHICH links are trackable (only real anchors, minus
/// mailto/tel/anchor/template/unsubscribe hrefs). The rewrite is then
/// applied to the ORIGINAL HTML in a SINGLE left-to-right scan (see
/// [`rewrite_href_spans`]) keyed by the href VALUE, so every attribute
/// spelling resolves — double-quoted, single-quoted, unquoted, and
/// entity-encoded (`&amp;`) — preserving the document's structure. The
/// previous implementation substring-searched the whole document once per
/// replacement key and only ever matched the double-quoted DOM-decoded
/// spelling, silently losing analytics for the rest.
pub fn rewrite_links(html: &str, job: &EmailJob, config: &TrackingConfig) -> String {
    let doc = Html::parse_document(html);
    // href VALUE (entity-decoded) → tracked URL. Keyed by value so the
    // single raw scan can match any quoting/encoding of that value.
    let mut tracked_by_value: HashMap<String, String> = HashMap::new();

    for element in doc.select(&ANCHOR_SELECTOR) {
        // The `a[href]` selector guarantees the attribute exists.
        let href_attr = element
            .value()
            .attr("href")
            .expect("a[href] selects only anchors carrying an href");

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
                tracked_by_value.clear();
                break;
            }
        };
        let tracked_url = format!(
            "{}{}/{}",
            config.base_url, config.click_redirect_path, tracking_id
        );

        tracked_by_value.insert(href_attr.to_string(), tracked_url);
    }

    if tracked_by_value.is_empty() {
        return html.to_string();
    }

    rewrite_href_spans(html, &tracked_by_value)
}

/// Decode the handful of entities that can legally appear inside an href
/// attribute value (`&amp;` overwhelmingly; the rest for completeness) to
/// its DOM value, so a raw `?a=1&amp;b=2` matches the decoded `?a=1&b=2`
/// the DOM pass indexed.
fn decode_href_entities(value: &str) -> String {
    if !value.contains('&') {
        return value.to_string();
    }
    value
        .replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
}

/// One span of the original document to replace: `[start, end)` → text.
struct HrefSpan {
    start: usize,
    end: usize,
    replacement: String,
}

/// Single left-to-right scan of `html` for `href=` (case-insensitive),
/// resolving the attribute value under ANY quoting style and replacing the
/// whole attribute with the double-quoted tracked URL when the
/// (entity-decoded) value is in `tracked_by_value`.
///
/// Invariants:
/// * ONE pass, O(hrefs) map lookups — no per-key full-document scans.
/// * Spans are emitted in document order and never overlap (each starts at
///   a distinct `href=` occurrence and ends before the next scan position).
/// * ASCII lowercasing is byte-length preserving, so indices found in the
///   lowercased copy address the original string exactly.
fn rewrite_href_spans(html: &str, tracked_by_value: &HashMap<String, String>) -> String {
    let lower = html.to_ascii_lowercase();
    let mut spans: Vec<HrefSpan> = Vec::new();
    let mut search_from = 0usize;
    const NEEDLE: &str = "href=";

    while let Some(rel) = lower[search_from..].find(NEEDLE) {
        let attr_start = search_from + rel;
        let mut cursor = attr_start + NEEDLE.len();
        search_from = cursor;
        // HTML allows ASCII whitespace between `=` and the value.
        let bytes = html.as_bytes();
        while cursor < bytes.len() && (bytes[cursor] == b' ' || bytes[cursor] == b'\t') {
            cursor += 1;
        }
        let Some((value_start, quote)) = next_value_boundary(bytes, cursor) else {
            continue;
        };
        let value_end = match quote {
            Some(q) => match html[value_start..].find(q) {
                Some(rel_end) => value_start + rel_end,
                None => continue, // unterminated quote — leave untouched
            },
            // Unquoted values end at the first whitespace or `>`.
            None => {
                let mut end = value_start;
                while end < bytes.len()
                    && bytes[end] != b' '
                    && bytes[end] != b'\t'
                    && bytes[end] != b'\r'
                    && bytes[end] != b'\n'
                    && bytes[end] != b'>'
                {
                    end += 1;
                }
                end
            }
        };
        search_from = search_from.max(value_end);

        let raw_value = &html[value_start..value_end];
        let decoded = decode_href_entities(raw_value);
        let Some(tracked) = tracked_by_value.get(&decoded) else {
            continue;
        };
        spans.push(HrefSpan {
            start: attr_start,
            end: value_end,
            replacement: format!("href=\"{tracked}\""),
        });
    }

    if spans.is_empty() {
        return html.to_string();
    }

    let mut result = String::with_capacity(html.len());
    let mut last_end = 0usize;
    for span in spans {
        result.push_str(&html[last_end..span.start]);
        result.push_str(&span.replacement);
        last_end = span.end;
    }
    result.push_str(&html[last_end..]);
    result
}

/// Boundary of the attribute value after `href=` (+ optional whitespace):
/// returns the byte index where the value starts and the quoting
/// character, if any.
fn next_value_boundary(bytes: &[u8], at: usize) -> Option<(usize, Option<char>)> {
    match bytes.get(at)? {
        b'"' => Some((at + 1, Some('"'))),
        b'\'' => Some((at + 1, Some('\''))),
        _ if at < bytes.len() => Some((at, None)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Serializes env-mutating tests against every other module in this
    /// crate (std::env is process-global; see `crate::test_support`).
    use crate::test_support::ENV_LOCK;
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
            message_category: "marketing".to_string(),
            tags: None,
            metadata: None,
            sales_step_execution_id: None,
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
            unsubscribe_path: "/u".to_string(),
            secret_key: None,
        }
    }

    fn sample_payload() -> TrackingPayload {
        TrackingPayload {
            message_id: "msg_123".to_string(),
            tenant_id: "ten_456".to_string(),
            recipient_hash: "user@example.com".to_string(),
            original_url: Some("https://example.com".to_string()),
            campaign_id: Some("camp_789".to_string()),
        }
    }

    /// The payload carries RAW tenant and recipient identifiers. The token
    /// is AES-128-GCM encrypted (confidentiality is the cipher's job), and
    /// the tracking-service consumes tenant_id directly for redirect-domain
    /// authorization (domains.tenant_id) and the recipient for suppression
    /// — a hashed value made every click fall back and every unsubscribe
    /// suppress a hash no sender ever matches. Analytics privacy is applied
    /// at ingest (recipient_for_analytics), not in the token.
    #[test]
    fn build_payload_carries_raw_identifiers() {
        let mut job = make_test_job();
        job.message_id = "msg_raw".to_string();
        job.tenant_id = "01JRAW_TENANT_ID_000001".to_string();
        job.to = "real@example.com".to_string();
        let payload = build_payload(&job, None);
        assert_eq!(payload.tenant_id, "01JRAW_TENANT_ID_000001");
        assert_eq!(payload.recipient_hash, "real@example.com");
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
        assert_eq!(decoded.original_url.as_deref(), Some("https://example.com"));
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

#[cfg(test)]
mod adversarial_rewrite_tests {
    //! DOM-guided rewriting against hostile markup: script/style bodies
    //! containing decoy `</body>` tags, and every attribute spelling the
    //! single-scan rewriter must (or must not) touch.

    use super::*;
    use crate::test_support::ENV_LOCK;

    const TEST_SECRET: &str = "test-secret-key-32-bytes-minimum!!";

    fn job() -> EmailJob {
        EmailJob {
            id: "job_rw".to_string(),
            message_id: "msg_rw".to_string(),
            tenant_id: "ten_rw".to_string(),
            domain_id: "dom_rw".to_string(),
            from: "sender@example.com".to_string(),
            to: "recipient@example.com".to_string(),
            subject: "Test".to_string(),
            html: None,
            text: None,
            headers: None,
            attachments: None,
            campaign_id: None,
            message_category: "marketing".to_string(),
            tags: None,
            metadata: None,
            sales_step_execution_id: None,
            scheduled_at: None,
            attempt: 1,
            created_at: chrono::Utc::now(),
        }
    }

    fn config() -> TrackingConfig {
        TrackingConfig {
            enabled: true,
            base_url: "https://track.example.com".to_string(),
            open_pixel_path: "/o".to_string(),
            click_redirect_path: "/c".to_string(),
            unsubscribe_path: "/u".to_string(),
            secret_key: None,
        }
    }

    fn with_secret<T>(body: impl FnOnce() -> T) -> T {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::set_var(TRACKING_SECRET_KEY_ENV, TEST_SECRET);
        body()
    }

    /// A decoy `</body>` inside a `<script>` string must not receive the
    /// pixel; the REAL closing body tag does.
    #[test]
    fn decoy_body_tags_inside_script_and_style_are_skipped() {
        with_secret(|| {
            let html = "<html><body><script>var x = '</body>';</script>\
                        <style>/* </body> */</style><p>hi</p></body></html>";
            let tracked = add_tracking_pixel(html, &job(), &config());
            let real_close = tracked.rfind("</body>").expect("real body close");
            let pixel = tracked
                .find("track.example.com/o/")
                .expect("pixel inserted");
            assert!(
                pixel < real_close,
                "the pixel must land before the real </body>, not inside script/style"
            );
            // Both decoys survive untouched inside their elements.
            assert!(tracked.contains("<script>var x = '</body>';</script>"));
            assert!(tracked.contains("<style>/* </body> */</style>"));
        });
    }

    /// Every legal attribute spelling is rewritten under a single scan.
    #[test]
    fn every_href_quoting_style_is_rewritten() {
        with_secret(|| {
            let html = "<html><body>\
                <a href=\"https://example.com/a\">a</a>\
                <a href='https://example.com/b'>b</a>\
                <a href=https://example.com/c>c</a>\
                <a HREF=\"https://example.com/d\">d</a>\
                <a href= \"https://example.com/f\">f</a>\
                <a href=\"https://example.com/e?x=1&amp;y=2\">e</a>\
                </body></html>";
            let tracked = rewrite_links(html, &job(), &config());
            assert_eq!(
                tracked.matches("https://track.example.com/c/").count(),
                6,
                "all six spellings must be tracked: {tracked}"
            );
            for original in ["a", "b", "c", "d", "e", "f"] {
                assert!(
                    !tracked.contains(&format!("https://example.com/{original}")),
                    "href {original} was not rewritten: {tracked}"
                );
            }
            assert!(
                !tracked.contains("&amp;"),
                "the raw attribute is replaced wholesale (no stale entity): {tracked}"
            );
        });
    }

    /// Unterminated quotes and non-trackable schemes are left byte-exact.
    #[test]
    fn hostile_and_excluded_hrefs_are_left_untouched() {
        with_secret(|| {
            let unterminated = "<a href=\"https://example.com/x>broken</a>";
            assert_eq!(
                rewrite_links(unterminated, &job(), &config()),
                unterminated,
                "an unterminated quote must not be rewritten"
            );

            let html = "<html><body>\
                <a href=\"mailto:a@b.c\">m</a>\
                <a href=\"tel:+123\">t</a>\
                <a href=\"#anchor\">a</a>\
                <a href=\"{{unsubscribe_url}}\">u</a>\
                <a href=\"https://x.example/unsubscribe?u=1\">s</a>\
                </body></html>";
            assert_eq!(
                rewrite_links(html, &job(), &config()),
                html,
                "excluded schemes and unsubscribe targets stay direct"
            );
        });
    }

    /// Without the shared secret nothing is rewritten — no unsigned token is
    /// ever emitted into customer HTML.
    #[test]
    fn missing_secret_leaves_every_href_direct() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::remove_var(TRACKING_SECRET_KEY_ENV);
        let html = "<a href=\"https://example.com/a\">a</a>";
        assert_eq!(rewrite_links(html, &job(), &config()), html);
        let html_with_pixel = "<html><body><p>hi</p></body></html>";
        assert_eq!(
            add_tracking_pixel(html_with_pixel, &job(), &config()),
            html_with_pixel,
            "no pixel without the secret"
        );
    }
}

#[cfg(test)]
mod coverage_arms {
    //! Adversarial batch 2: pixel placement around script/style bodies, link
    //! rewriting quoting forms, and tracking/unsubscribe gating arms.

    use super::*;
    use crate::test_support::ENV_LOCK;

    fn cfg() -> TrackingConfig {
        TrackingConfig {
            enabled: true,
            base_url: "https://track.example.com".into(),
            open_pixel_path: "/o".into(),
            click_redirect_path: "/c".into(),
            unsubscribe_path: "/u".into(),
            secret_key: Some(zeroize::Zeroizing::new(
                "unit-test-secret-0123456789abcdef0123".to_string(),
            )),
        }
    }

    /// The pixel encoder reads the process-global TRACKING_SECRET_KEY.
    fn with_tracking_secret(body: impl FnOnce()) {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::set_var("TRACKING_SECRET_KEY", "k".repeat(40));
        body();
        std::env::remove_var("TRACKING_SECRET_KEY");
    }

    fn job() -> EmailJob {
        EmailJob {
            id: "q-1".into(),
            message_id: "m-1".into(),
            tenant_id: "t-1".into(),
            domain_id: "d-1".into(),
            from: "s@example.com".into(),
            to: "r@example.com".into(),
            subject: "s".into(),
            html: None,
            text: None,
            headers: None,
            attachments: None,
            campaign_id: None,
            message_category: "marketing".into(),
            tags: None,
            metadata: None,
            sales_step_execution_id: None,
            scheduled_at: None,
            attempt: 0,
            created_at: chrono::Utc::now(),
        }
    }

    #[test]
    fn pixel_placement_ignores_body_tags_inside_script_or_style() {
        with_tracking_secret(pixel_placement_assertions);
    }

    fn pixel_placement_assertions() {
        let job = job();
        let config = cfg();
        // A `</body>` inside a <script> string must be ignored; the pixel
        // lands at the REAL </body>.
        let html = "<html><body>x<script>var s='</body>';</script><a href=\"https://a.test/1\">1</a></body></html>";
        let out = add_tracking_pixel(html, &job, &config);
        let pixel_pos = out.find("/o/").expect("pixel present");
        let script_pos = out.find("var s=").expect("script present");
        assert!(
            pixel_pos > script_pos,
            "pixel must be after the script: {out}"
        );
        // No valid </body> anywhere: appended to the end.
        let out = add_tracking_pixel("<p>no body tag</p>", &job, &config);
        assert!(
            out.ends_with("</p>") || out.contains("/o/"),
            "fallback appends the pixel: {out}"
        );
        let _ = add_tracking_pixel("", &job, &config);
    }

    #[test]
    fn link_rewriting_handles_all_href_quoting_forms() {
        with_tracking_secret(link_rewriting_assertions);
    }

    fn link_rewriting_assertions() {
        let job = job();
        let config = cfg();
        let html = concat!(
            "<a href=\"https://a.test/1\">q1</a>",
            "<a href='https://a.test/2'>s1</a>",
            "<a href=https://a.test/3>u1</a>",
            "<a href=\"https://a.test/4>unterminated</a>",
            "<a href=\"mailto:x@a.test\">m</a>",
            "<a href=\"#anchor\">a</a>",
        );
        let out = rewrite_links(html, &job, &config);
        assert!(out.contains("https://track.example.com/c/"), "{out}");
        // The same tracked URL for repeated links is consistent.
        assert!(
            out.matches("https://track.example.com/c/").count() >= 3,
            "{out}"
        );
        // mailto and anchors untouched.
        assert!(out.contains("mailto:x@a.test"), "{out}");
        assert!(out.contains("#anchor"), "{out}");
        // A value whose quote only terminates at the NEXT attribute's quote
        // is one anchor per the HTML5 parse (browsers see the same merged
        // attribute value) — the rewrite is consistent with that parse.
        assert!(
            out.matches("https://track.example.com/c/").count() >= 4,
            "all four DOM anchors are rewritten: {out}"
        );
        // Empty input round-trips.
        assert_eq!(rewrite_links("", &job, &config), "");
    }

    #[test]
    fn unsubscribe_link_requires_a_secret_and_builds_the_url() {
        with_tracking_secret(|| {
            let job = job();
            let mut config = cfg();
            // Without the shared secret there is no authenticated link.
            config.secret_key = None;
            assert!(unsubscribe_link(&job, &config).is_none());
            // With it: (token, url).
            let (token, url) = unsubscribe_link(&job, &cfg()).expect("token + url");
            assert!(!token.is_empty(), "token is the v2 codec payload");
            assert!(
                url.starts_with("https://track.example.com/u/"),
                "url points at the unsubscribe path: {url}"
            );
            assert!(url.ends_with(&token), "url carries the token: {url}");
        });
    }
}

#[cfg(test)]
mod adversarial_batch {
    //! Pixel/link rewrite adversarial arms: raw-text `<script>`/`<style>`
    //! `</body>` decoys, the backward-scan walk, and raw-scan href edge
    //! cases (dangling `href=`, unterminated quotes, unmatched values).

    use super::*;
    use crate::test_support::ENV_LOCK;
    use chrono::Utc;
    use zeroize::Zeroizing;

    const SECRET: &str = "adversarial-tracking-secret-32-bytes!";

    fn tracking_config() -> TrackingConfig {
        TrackingConfig {
            enabled: true,
            base_url: "https://t.example".into(),
            open_pixel_path: "/o".into(),
            click_redirect_path: "/c".into(),
            unsubscribe_path: "/u".into(),
            secret_key: Some(Zeroizing::new(SECRET.to_string())),
        }
    }

    fn job() -> EmailJob {
        EmailJob {
            id: "tj".into(),
            message_id: "tm".into(),
            tenant_id: "tt".into(),
            domain_id: "td".into(),
            from: "s@example.com".into(),
            to: "r@example.com".into(),
            subject: "s".into(),
            html: None,
            text: None,
            headers: None,
            attachments: None,
            campaign_id: None,
            message_category: "marketing".into(),
            tags: None,
            metadata: None,
            sales_step_execution_id: None,
            scheduled_at: None,
            attempt: 0,
            created_at: Utc::now(),
        }
    }

    /// The pixel must not be injected before a `</body>` that lives inside a
    /// `<script>` raw-text element: the scan skips it and falls back to
    /// appending at the very end.
    #[test]
    fn pixel_skips_the_body_candidate_inside_a_script() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::set_var(TRACKING_SECRET_KEY_ENV, SECRET);
        let html = r#"<html><body>Hi<script>document.write("</body>");</script></body>"#;
        let out = add_tracking_pixel(html, &job(), &tracking_config());
        let pixel = out
            .find(r#"<img src="#)
            .expect("the pixel must be present in the output");
        let decoy = out
            .find(r#"document.write("</body>")"#)
            .expect("the in-script decoy must survive verbatim");
        assert!(
            pixel > decoy,
            "the pixel must land AFTER the in-script decoy, not inside it"
        );
        std::env::remove_var(TRACKING_SECRET_KEY_ENV);
    }

    /// Same contract for `<style>` raw-text decoys.
    #[test]
    fn pixel_skips_the_body_candidate_inside_a_style() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::set_var(TRACKING_SECRET_KEY_ENV, SECRET);
        let html = r#"<html><body>Hi<style>div::after{content:"</body>"}</style></body>"#;
        let out = add_tracking_pixel(html, &job(), &tracking_config());
        let pixel = out
            .find(r#"<img src="#)
            .expect("the pixel must be present in the output");
        let decoy = out
            .find(r#"content:"</body>""#)
            .expect("the in-style decoy must survive verbatim");
        assert!(
            pixel > decoy,
            "the pixel must land AFTER the in-style decoy"
        );
        std::env::remove_var(TRACKING_SECRET_KEY_ENV);
    }

    /// Multiple in-raw-text decoys: the scan walks backwards through ALL of
    /// them and only ever injects before a genuine `</body>` — or appends.
    #[test]
    fn pixel_walks_back_through_every_raw_text_decoy() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::set_var(TRACKING_SECRET_KEY_ENV, SECRET);
        let html = r#"<html><body>A<script>a("</body></body>")</script>B</body>"#;
        let out = add_tracking_pixel(html, &job(), &tracking_config());
        // The two decoys live INSIDE the script; the pixel must never land
        // between them (which would terminate the script element early).
        let script = out
            .find("<script>")
            .and_then(|s| out.find("</script>").map(|e| (s, e)))
            .expect("script present");
        let pixel_at = out.find(r#"<img src="#).expect("pixel present");
        assert!(
            pixel_at < script.0 || pixel_at > script.1,
            "the pixel must not be injected inside the script element"
        );
        std::env::remove_var(TRACKING_SECRET_KEY_ENV);
    }

    /// The raw `href=` scan is resilient to malformed neighbours: a dangling
    /// `href=` at the end of the document and an unterminated quote are left
    /// untouched while the genuine anchor is still rewritten.
    #[test]
    fn rewrite_survives_a_dangling_href_and_an_unterminated_quote() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::set_var(TRACKING_SECRET_KEY_ENV, SECRET);
        let config = tracking_config();
        let html =
            r#"<a href="https://x.test/a">go</a> and <a href="https://x.test/a>broken</a>href="#;
        let out = rewrite_links(html, &job(), &config);
        // The well-formed anchor is rewritten.
        assert!(
            out.contains(r#"href="https://t.example/c/"#),
            "the valid anchor must be rewritten: {out}"
        );
        // The unterminated quote is left exactly as it was.
        assert!(
            out.contains(r#"<a href="https://x.test/a>broken</a>"#),
            "an unterminated quote must be left untouched: {out}"
        );
        // The trailing `href=` marker survives verbatim.
        assert!(
            out.ends_with("href="),
            "a dangling href= must survive: {out}"
        );
        std::env::remove_var(TRACKING_SECRET_KEY_ENV);
    }

    /// Values absent from the document never produce a replacement: the raw
    /// scan returns the input byte-for-byte.
    #[test]
    fn rewrite_href_spans_is_identity_when_nothing_matches() {
        let mut tracked = HashMap::new();
        tracked.insert(
            "https://nowhere.test/x".to_string(),
            "https://t.example/c/z".to_string(),
        );
        let html = r#"<a href="https://x.test/a">go</a>"#;
        assert_eq!(rewrite_href_spans(html, &tracked), html);
    }
}

#[cfg(test)]
mod residual_arms {
    //! The decoy-walk and raw-scan guards: a `</body>` decoy as the LAST
    //! candidate (the backwards scan must skip it inside script/style and
    //! keep walking), and a document ending on a dangling `href=`.

    use super::*;
    use crate::test_support::ENV_LOCK;

    const SECRET: &str = "residual-tracking-secret-32-bytes!";

    fn job() -> EmailJob {
        EmailJob {
            id: "ra-j".into(),
            message_id: "ra-m".into(),
            tenant_id: "ra-t".into(),
            domain_id: "ra-d".into(),
            from: "s@example.com".into(),
            to: "r@example.com".into(),
            subject: "s".into(),
            html: None,
            text: None,
            headers: None,
            attachments: None,
            campaign_id: None,
            message_category: "marketing".into(),
            tags: None,
            metadata: None,
            sales_step_execution_id: None,
            scheduled_at: None,
            attempt: 0,
            created_at: chrono::Utc::now(),
        }
    }

    fn config() -> TrackingConfig {
        TrackingConfig {
            enabled: true,
            base_url: "https://t.example".into(),
            open_pixel_path: "/o".into(),
            click_redirect_path: "/c".into(),
            unsubscribe_path: "/u".into(),
            secret_key: Some(zeroize::Zeroizing::new(SECRET.to_string())),
        }
    }

    /// The LAST `</body>` candidate lives INSIDE a script: the backwards
    /// scan must skip it (logging the skip) and keep walking — the pixel
    /// never lands inside the script.
    #[test]
    fn pixel_skips_a_trailing_body_decoy_inside_script() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::set_var(TRACKING_SECRET_KEY_ENV, SECRET);
        let html = r#"<html><body>Hi<script>var end = "</body>";</script>"#;
        let out = add_tracking_pixel(html, &job(), &config());
        let pixel = out.find(r#"<img src="#).expect("pixel appended");
        let script_close = out.find("</script>").expect("script preserved");
        assert!(
            pixel > script_close,
            "the pixel must not land inside the script element: {out}"
        );
        std::env::remove_var(TRACKING_SECRET_KEY_ENV);
    }

    /// Same for a trailing style decoy.
    #[test]
    fn pixel_skips_a_trailing_body_decoy_inside_style() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::set_var(TRACKING_SECRET_KEY_ENV, SECRET);
        let html = r#"<html><body>Hi<style>p::after{content:"</body>"}</style>"#;
        let out = add_tracking_pixel(html, &job(), &config());
        let pixel = out.find(r#"<img src="#).expect("pixel appended");
        let style_close = out.find("</style>").expect("style preserved");
        assert!(
            pixel > style_close,
            "the pixel must not land inside the style element: {out}"
        );
        std::env::remove_var(TRACKING_SECRET_KEY_ENV);
    }

    /// A document ending exactly on a dangling `href=` has no value to
    /// read: the raw scan skips it instead of panicking.
    #[test]
    fn rewrite_scan_survives_an_href_equal_at_eof() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::set_var(TRACKING_SECRET_KEY_ENV, SECRET);
        let html = r#"<a href="https://x.test/a">go</a>href="#;
        let out = rewrite_links(html, &job(), &config());
        assert!(
            out.ends_with("href="),
            "the dangling marker survives: {out}"
        );
        std::env::remove_var(TRACKING_SECRET_KEY_ENV);
    }
}
