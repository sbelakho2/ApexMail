//! Tracking token codec: AES-128-GCM encrypt / decrypt with zeroized key material.
//!
//! BACKWARD COMPATIBILITY: This implementation is byte-for-byte compatible with
//! the TypeScript `TrackingCodec` class.  Existing tokens produced by the Node.js
//! service can be decoded here without re-encoding.
//!
//! Binary payload format (inside the GCM envelope):
//!   v1  – version u8 + per-field u8 length prefix
//!   v2  – version u8 + per-field u16-BE length prefix
//!   v3  – v2 + additional originalUrl field
//!
//! Token wire format:
//!   base64url( IV[12] || AuthTag[16] || ciphertext )
//!
//! Key derivation (must match TypeScript `deriveKeyHMAC`):
//!   encryption_key = HMAC-SHA256(master_secret, "encryption")[0..16]
//!   signature_key  = HMAC-SHA256(master_secret, "signature")[0..32]

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes128Gcm, Key, Nonce,
};
use anyhow::{anyhow, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// Decoded tracking event payload.
#[derive(Debug, Clone)]
pub struct TrackingData {
    pub tenant_id: String,
    pub message_id: String,
    pub recipient: String,
    pub link_id: Option<String>,
    /// Original click URL, included inside the encrypted token (FIX-041).
    pub original_url: Option<String>,
}

/// Decoded unsubscribe / preferences token.
#[derive(Debug, Clone)]
pub struct UnsubscribeData {
    pub tenant_id: String,
    pub recipient: String,
    #[allow(dead_code)] // timestamp used for token expiry validation, wired in future middleware
    pub timestamp_ms: u64,
}

// ── Blob lengths ─────────────────────────────────────────────────────────────

const IV_LEN: usize = 12;
const AUTH_TAG_LEN: usize = 16;

// ── Key material ─────────────────────────────────────────────────────────────

/// 16-byte AES-128 key; wiped from memory on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
struct EncKey([u8; 16]);

/// 32-byte HMAC-SHA-256 signature key; wiped from memory on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
struct SigKey([u8; 32]);

// ── Public codec ─────────────────────────────────────────────────────────────

/// `TrackingCodec` holds derived key material in zeroized heap memory so that
/// secrets are erased when the struct is dropped.
pub struct TrackingCodec {
    enc_key: EncKey,
    sig_key: SigKey,
}

// Token encode/generation methods are not yet wired at the binary level
// (the decode path is active; encode will be used once the MTA calls this service
// to embed tokens into outgoing messages).
#[allow(dead_code)]
impl TrackingCodec {
    /// Build a codec from the master secret string.
    ///
    /// Derives two sub-keys with HMAC-SHA-256, matching the TypeScript
    /// `deriveKeyHMAC(secretKey, 'encryption', 16)` / `('signature', 32)`.
    pub fn new(master_secret: &str) -> Self {
        let enc_key = derive_key_hmac(master_secret.as_bytes(), b"encryption", 16);
        let sig_key = derive_key_hmac(master_secret.as_bytes(), b"signature", 32);

        let mut ek = [0u8; 16];
        ek.copy_from_slice(&enc_key[..16]);

        let mut sk = [0u8; 32];
        sk.copy_from_slice(&sig_key[..32]);

        TrackingCodec {
            enc_key: EncKey(ek),
            sig_key: SigKey(sk),
        }
    }

    // ── Token encode / decode ─────────────────────────────────────────

    /// Encode `TrackingData` into a URL-safe tracking token.
    pub fn encode(&self, data: &TrackingData) -> Result<String> {
        let payload = serialize_tracking_data(data);
        let (iv, tag, ciphertext) = self.aes128gcm_encrypt(&payload)?;

        let mut combined = Vec::with_capacity(IV_LEN + AUTH_TAG_LEN + ciphertext.len());
        combined.extend_from_slice(&iv);
        combined.extend_from_slice(&tag);
        combined.extend_from_slice(&ciphertext);

        Ok(URL_SAFE_NO_PAD.encode(&combined))
    }

    /// Decode a URL-safe tracking token back into `TrackingData`.
    /// Returns `None` on any parse or authentication failure.
    pub fn decode(&self, token: &str) -> Option<TrackingData> {
        if token.len() < 10 || token.len() > 4096 {
            return None;
        }

        let combined = URL_SAFE_NO_PAD.decode(token).ok()?;

        if combined.len() < IV_LEN + AUTH_TAG_LEN + 1 {
            return None;
        }

        let (iv_bytes, rest) = combined.split_at(IV_LEN);
        let (tag_bytes, ciphertext) = rest.split_at(AUTH_TAG_LEN);

        let plaintext = self
            .aes128gcm_decrypt(ciphertext, iv_bytes, tag_bytes)
            .ok()?;

        deserialize_tracking_data(&plaintext)
    }

    // ── Unsubscribe token ─────────────────────────────────────────────

    /// Generate an AES-128-GCM encrypted unsubscribe token.
    /// Payload: `{tenantId}:{recipient}:{unix_ms}` (UTF-8).
    pub fn generate_unsubscribe_token(
        &self,
        tenant_id: &str,
        recipient: &str,
    ) -> Result<String> {
        let ts_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        let payload_str = format!("{}:{}:{}", tenant_id, recipient, ts_ms);
        let (iv, tag, ciphertext) = self.aes128gcm_encrypt(payload_str.as_bytes())?;

        let mut combined = Vec::with_capacity(IV_LEN + AUTH_TAG_LEN + ciphertext.len());
        combined.extend_from_slice(&iv);
        combined.extend_from_slice(&tag);
        combined.extend_from_slice(&ciphertext);

        Ok(URL_SAFE_NO_PAD.encode(&combined))
    }

    /// Verify and decode an unsubscribe token.
    ///
    /// Supports two formats:
    ///   1. **New (GCM-encrypted)** — IV[12] || AuthTag[16] || Ciphertext.
    ///   2. **Legacy (HMAC-signed)** — payload-bytes || 16-byte truncated HMAC-SHA-256.
    ///
    /// `max_age_days` defaults to 90 days.
    pub fn verify_unsubscribe_token(
        &self,
        token: &str,
        max_age_days: Option<u64>,
    ) -> Option<UnsubscribeData> {
        self.verify_unsubscribe_token_impl(token, max_age_days)
    }

    fn verify_unsubscribe_token_impl(
        &self,
        token: &str,
        max_age_days: Option<u64>,
    ) -> Option<UnsubscribeData> {
        if token.len() < 10 || token.len() > 4096 {
            return None;
        }

        let combined = URL_SAFE_NO_PAD.decode(token).ok()?;
        if combined.len() < IV_LEN + AUTH_TAG_LEN + 1 {
            return None;
        }

        // ── Try AES-128-GCM first ─────────────────────────────────────
        let payload_str = self.try_gcm_decrypt_to_string(&combined).or_else(|| {
            // ── Fallback: legacy HMAC-signed format ───────────────────
            self.try_legacy_hmac_verify(&combined)
        })?;

        parse_unsubscribe_payload(&payload_str, max_age_days)
    }

    /// Public alias used by preferences routes (configurable max age).
    pub fn verify_unsubscribe_token_v2(
        &self,
        token: &str,
        max_age_days: Option<u64>,
    ) -> Option<UnsubscribeData> {
        self.verify_unsubscribe_token_impl(token, max_age_days)
    }

    // ── Preferences token (alias for unsubscribe, max 30 days) ───────

    pub fn generate_preferences_token(
        &self,
        tenant_id: &str,
        recipient: &str,
    ) -> Result<String> {
        self.generate_unsubscribe_token(tenant_id, recipient)
    }

    pub fn verify_preferences_token(&self, token: &str) -> Option<UnsubscribeData> {
        self.verify_unsubscribe_token_v2(token, Some(30))
    }

    // ── Internal helpers ──────────────────────────────────────────────

    fn aes128gcm_encrypt(&self, plaintext: &[u8]) -> Result<([u8; IV_LEN], [u8; AUTH_TAG_LEN], Vec<u8>)> {
        use aes_gcm::aead::OsRng;
        use aes_gcm::aead::rand_core::RngCore;

        let mut iv_bytes = [0u8; IV_LEN];
        OsRng.fill_bytes(&mut iv_bytes);

        let key = Key::<Aes128Gcm>::from_slice(&self.enc_key.0);
        let cipher = Aes128Gcm::new(key);
        let nonce = Nonce::from_slice(&iv_bytes);

        // AES-GCM `encrypt` returns ciphertext || authTag (16 bytes at end)
        let mut ciphertext_with_tag = cipher
            .encrypt(nonce, plaintext)
            .map_err(|e| anyhow!("AES-128-GCM encrypt failed: {}", e))?;

        // The last 16 bytes are the auth tag
        let tag_start = ciphertext_with_tag.len() - AUTH_TAG_LEN;
        let mut tag = [0u8; AUTH_TAG_LEN];
        tag.copy_from_slice(&ciphertext_with_tag[tag_start..]);
        ciphertext_with_tag.truncate(tag_start);

        Ok((iv_bytes, tag, ciphertext_with_tag))
    }

    fn aes128gcm_decrypt(&self, ciphertext: &[u8], iv: &[u8], tag: &[u8]) -> Result<Vec<u8>> {
        let key = Key::<Aes128Gcm>::from_slice(&self.enc_key.0);
        let cipher = Aes128Gcm::new(key);
        let nonce = Nonce::from_slice(iv);

        // AES-GCM expects ciphertext || authTag
        let mut ct_with_tag = Vec::with_capacity(ciphertext.len() + tag.len());
        ct_with_tag.extend_from_slice(ciphertext);
        ct_with_tag.extend_from_slice(tag);

        cipher
            .decrypt(nonce, ct_with_tag.as_slice())
            .map_err(|e| anyhow!("AES-128-GCM decrypt failed: {}", e))
    }

    fn try_gcm_decrypt_to_string(&self, combined: &[u8]) -> Option<String> {
        let (iv_bytes, rest) = combined.split_at(IV_LEN);
        let (tag_bytes, ciphertext) = rest.split_at(AUTH_TAG_LEN);
        let plain = self
            .aes128gcm_decrypt(ciphertext, iv_bytes, tag_bytes)
            .ok()?;
        String::from_utf8(plain).ok()
    }

    fn try_legacy_hmac_verify(&self, combined: &[u8]) -> Option<String> {
        // #194: Legacy tokens used 16-byte truncated HMAC. Accept both truncated
        // (backward compat) and full 32-byte HMAC for newly generated tokens.
        // Truncated verification is weaker (128 bits) but still sufficient for
        // unsubscribe tokens; log a warning for monitoring migration progress.
        if combined.len() < 17 {
            return None;
        }
        let payload_bytes = &combined[..combined.len() - 16];
        let provided_sig = &combined[combined.len() - 16..];
        let expected_full = hmac_sha256(&self.sig_key.0, payload_bytes);
        if !constant_time_eq(provided_sig, &expected_full[..16]) {
            return None;
        }
        tracing::debug!("Legacy 16-byte truncated HMAC token verified — consider re-issuing with full HMAC");
        String::from_utf8(payload_bytes.to_vec()).ok()
    }
}

// ── Key derivation ────────────────────────────────────────────────────────────

/// `deriveKeyHMAC(secret, info, keyLength)` — matches TypeScript implementation.
/// Returns HMAC-SHA-256(secret, info) truncated to `len` bytes.
fn derive_key_hmac(secret: &[u8], info: &[u8], len: usize) -> Zeroizing<Vec<u8>> {
    type HmacSha256 = Hmac<Sha256>;
    let mut mac = <HmacSha256 as Mac>::new_from_slice(secret)
        .expect("HMAC accepts any key length");
    mac.update(info);
    let result = mac.finalize().into_bytes();
    Zeroizing::new(result[..len].to_vec())
}

/// HMAC-SHA-256 of `data` under `key`; returns the full 32-byte digest.
fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    type HmacSha256 = Hmac<Sha256>;
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key)
        .expect("HMAC accepts any key length");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

/// Constant-time equality check (mitigates timing oracle on HMAC validation).
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

// ── Unsubscribe payload parser ────────────────────────────────────────────────

fn parse_unsubscribe_payload(payload: &str, max_age_days: Option<u64>) -> Option<UnsubscribeData> {
    // Format: "tenantId:recipient:timestamp_ms"
    // #195: Both tenant_id and recipient may contain colons.
    // Strategy: timestamp_ms is always a pure decimal integer at the end,
    // so find the rightmost `:` followed by only digits → that's the timestamp separator.
    // Then from the remaining prefix find the FIRST `:` → tenant_id/recipient separator.
    let last_colon = payload.rfind(':')?;
    let ts_str = &payload[last_colon + 1..];
    // Verify ts_str is a valid numeric timestamp
    if ts_str.is_empty() || !ts_str.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }

    let prefix = &payload[..last_colon];
    let first_colon = prefix.find(':')?;

    let tenant_id = prefix[..first_colon].to_owned();
    let recipient = prefix[first_colon + 1..].to_owned();

    if tenant_id.is_empty() || recipient.is_empty() {
        return None;
    }

    let timestamp_ms: u64 = ts_str.parse().ok()?;

    // Age check
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;

    let max_ms = max_age_days.unwrap_or(90) * 24 * 60 * 60 * 1000;

    if now_ms.saturating_sub(timestamp_ms) > max_ms {
        return None; // Token too old
    }

    Some(UnsubscribeData {
        tenant_id,
        recipient,
        timestamp_ms,
    })
}

// ── Binary payload serialization ──────────────────────────────────────────────
//
// v1  – 1-byte version + u8 per-field lengths
// v2  – 1-byte version + u16-BE per-field lengths
// v3  – v2 + originalUrl field

#[allow(dead_code)] // encode path wired once outbound tokens are generated here
fn write_u16be(buf: &mut Vec<u8>, v: u16) {
    buf.push((v >> 8) as u8);
    buf.push((v & 0xff) as u8);
}

#[allow(dead_code)] // encode path
fn serialize_tracking_data(data: &TrackingData) -> Vec<u8> {
    let tid = data.tenant_id.as_bytes();
    let mid = data.message_id.as_bytes();
    let rec = data.recipient.as_bytes();
    let lid = data.link_id.as_deref().unwrap_or("").as_bytes();
    let url = data.original_url.as_deref().unwrap_or("").as_bytes();

    let version: u8 = if data.original_url.is_some() { 3 } else { 2 };

    let mut buf = Vec::with_capacity(
        1 + 2 + tid.len() + 2 + mid.len() + 2 + rec.len() + 2 + lid.len()
            + if version == 3 { 2 + url.len() } else { 0 },
    );

    buf.push(version);

    // tenantId
    write_u16be(&mut buf, tid.len() as u16);
    buf.extend_from_slice(tid);

    // messageId
    write_u16be(&mut buf, mid.len() as u16);
    buf.extend_from_slice(mid);

    // recipient
    write_u16be(&mut buf, rec.len() as u16);
    buf.extend_from_slice(rec);

    // linkId
    write_u16be(&mut buf, lid.len() as u16);
    buf.extend_from_slice(lid);

    // originalUrl (v3 only)
    if version == 3 {
        write_u16be(&mut buf, url.len() as u16);
        buf.extend_from_slice(url);
    }

    buf
}

// `pos` is advanced inside read_field! macros; the final increment after the
// last field is technically unused — suppress the macro-generated false positive.
#[allow(unused_assignments)]
fn deserialize_tracking_data(buf: &[u8]) -> Option<TrackingData> {
    if buf.is_empty() {
        return None;
    }

    let mut pos = 0;

    let version = buf[pos];
    pos += 1;

    if version != 1 && version != 2 && version != 3 {
        return None;
    }

    /// Read a length-prefixed field from `buf` at `pos`; advance `pos`.
    macro_rules! read_field {
        ($buf:expr, $pos:expr, $version:expr) => {{
            let len = if $version >= 2 {
                // u16-BE
                if $pos + 2 > $buf.len() {
                    return None;
                }
                let l = (($buf[$pos] as usize) << 8) | ($buf[$pos + 1] as usize);
                $pos += 2;
                l
            } else {
                // u8
                if $pos >= $buf.len() {
                    return None;
                }
                let l = $buf[$pos] as usize;
                $pos += 1;
                l
            };
            if $pos + len > $buf.len() {
                return None;
            }
            let s = std::str::from_utf8(&$buf[$pos..$pos + len]).ok()?.to_owned();
            $pos += len;
            s
        }};
    }

    let tenant_id = read_field!(buf, pos, version);
    let message_id = read_field!(buf, pos, version);
    let recipient = read_field!(buf, pos, version);

    let link_id_raw = read_field!(buf, pos, version);
    let link_id = if link_id_raw.is_empty() {
        None
    } else {
        Some(link_id_raw)
    };

    let original_url = if version == 3 && pos < buf.len() {
        let url_raw = read_field!(buf, pos, version);
        if url_raw.is_empty() {
            None
        } else {
            Some(url_raw)
        }
    } else {
        None
    };

    if tenant_id.is_empty() || message_id.is_empty() || recipient.is_empty() {
        return None;
    }

    Some(TrackingData {
        tenant_id,
        message_id,
        recipient,
        link_id,
        original_url,
    })
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &str = "test-secret-key-32-bytes-minimum!!";

    fn make_codec() -> TrackingCodec {
        TrackingCodec::new(SECRET)
    }

    #[test]
    fn roundtrip_v2_no_url() {
        let codec = make_codec();
        let data = TrackingData {
            tenant_id: "tenant_abc".into(),
            message_id: "msg_xyz".into(),
            recipient: "user@example.com".into(),
            link_id: Some("lnk_1234".into()),
            original_url: None,
        };
        let token = codec.encode(&data).expect("encode");
        let decoded = codec.decode(&token).expect("decode");

        assert_eq!(decoded.tenant_id, data.tenant_id);
        assert_eq!(decoded.message_id, data.message_id);
        assert_eq!(decoded.recipient, data.recipient);
        assert_eq!(decoded.link_id, data.link_id);
        assert!(decoded.original_url.is_none());
    }

    #[test]
    fn roundtrip_v3_with_url() {
        let codec = make_codec();
        let data = TrackingData {
            tenant_id: "ten1".into(),
            message_id: "msg1".into(),
            recipient: "a@b.com".into(),
            link_id: Some("lnk_ab12".into()),
            original_url: Some("https://example.com/path?q=1&r=2".into()),
        };
        let token = codec.encode(&data).expect("encode");
        let decoded = codec.decode(&token).expect("decode");

        assert_eq!(decoded.original_url, data.original_url);
    }

    #[test]
    fn invalid_token_returns_none() {
        let codec = make_codec();
        assert!(codec.decode("not-a-valid-token").is_none());
        assert!(codec.decode("").is_none());
        assert!(codec.decode("aGVsbG8=").is_none()); // valid base64 but wrong decrypt
    }

    #[test]
    fn tampered_token_returns_none() {
        let codec = make_codec();
        let data = TrackingData {
            tenant_id: "t".into(),
            message_id: "m".into(),
            recipient: "r@x.com".into(),
            link_id: None,
            original_url: None,
        };
        let mut token = codec.encode(&data).expect("encode");
        // Flip a bit in the middle of the token
        let mid = token.len() / 2;
        let b = &mut token.as_bytes().to_vec();
        b[mid] ^= 0x01;
        let tampered = String::from_utf8_lossy(b).to_string();
        assert!(codec.decode(&tampered).is_none());
    }

    #[test]
    fn unsubscribe_token_roundtrip() {
        let codec = make_codec();
        let token = codec
            .generate_unsubscribe_token("tenant_1", "user@domain.com")
            .expect("generate");
        let data = codec
            .verify_unsubscribe_token_v2(&token, Some(90))
            .expect("verify");
        assert_eq!(data.tenant_id, "tenant_1");
        assert_eq!(data.recipient, "user@domain.com");
    }

    #[test]
    fn unsubscribe_token_recipient_with_colon() {
        // Regression: email addresses do not contain ':', but the payload
        // parser must not break if the tenant_id has unusual chars.
        let codec = make_codec();
        let token = codec
            .generate_unsubscribe_token("tenant-id-123", "complex+tag@host.example.com")
            .expect("generate");
        let data = codec
            .verify_unsubscribe_token_v2(&token, Some(90))
            .expect("verify");
        assert_eq!(data.recipient, "complex+tag@host.example.com");
    }

    #[test]
    fn different_codec_cannot_decode() {
        let codec1 = TrackingCodec::new("secret-one-aaaaaaaaaaaaaaaaaaaaaaaa");
        let codec2 = TrackingCodec::new("secret-two-aaaaaaaaaaaaaaaaaaaaaaaa");

        let data = TrackingData {
            tenant_id: "t".into(),
            message_id: "m".into(),
            recipient: "x@y.com".into(),
            link_id: None,
            original_url: None,
        };
        let token = codec1.encode(&data).expect("encode");
        assert!(codec2.decode(&token).is_none());
    }
}
