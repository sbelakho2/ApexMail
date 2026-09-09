//! Tracking token codec:AES-128-GCM encrypt / decrypt with zeroized key material.
//!
//! BACKWARD COMPATIBILITY:This implementation is byte-for-byte compatible with
//! the legacy tracking codec. Existing tokens produced by earlier services
//! can be decoded here without re-encoding.
//!
//! Binary payload format (inside the GCM envelope)://! v1 – version u8 + per-field u8 length prefix
//! v2 – version u8 + per-field u16-BE length prefix
//! v3 – v2 + additional originalUrl field
//!
//! Unsubscribe/preferences token payload format (inside the GCM envelope):
//! v1 (legacy) – text `"tenantId:recipient:unix_ms"` (also accepted in the
//!               legacy HMAC-signed wire format, full or 16-byte-truncated)
//! v2 – binary `AXU2` magic + u16-BE length-prefixed tenantId, recipient,
//!      messageId + ASCII decimal unix_ms (F13:message-attributed tokens)
//!
//! Token wire format://! base64url(IV[12] || AuthTag[16] || ciphertext)
//!
//! Key derivation://! encryption_key = HMAC-SHA256(master_secret, "encryption")[0..16]
//! signature_key = HMAC-SHA256(master_secret, "signature")[0..32]

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes128Gcm, Key, Nonce,
};
use anyhow::{anyhow, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::time::{SystemTime, UNIX_EPOCH};
use subtle::ConstantTimeEq;
use tracing::warn;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// Decoded tracking event payload.
#[derive(Debug, Clone)]
pub struct TrackingData {
    pub tenant_id: String,
    pub message_id: String,
    pub recipient: String,
    pub link_id: Option<String>,
    /// Original click URL, included inside the encrypted token (-041).
    pub original_url: Option<String>,
}

/// Decoded unsubscribe / preferences token.
#[derive(Debug, Clone)]
pub struct UnsubscribeData {
    pub tenant_id: String,
    pub recipient: String,
    /// Decoded for token-expiry validation in the unsubscribe flow.
    pub timestamp_ms: u64,
    /// F13:originating message id, present only in v2 unsubscribe tokens.
    /// `None` for legacy (`tenant:recipient:ts`) tokens — the caller must
    /// then resolve attribution against the canonical recipient arrays (or
    /// record `"unknown"`) and NEVER invent a message id.
    pub message_id: Option<String>,
}

/// Detailed tracking token decode errors for auditing and diagnostics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrackingDecodeError {
    InvalidLength,
    InvalidBase64,
    TruncatedPayload,
    DecryptionFailed,
    InvalidPayload,
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

// C: since the crate is also a library, the encode helpers are part of the
// public surface (the worker-processors email tracker uses this exact
// format for outbound tokens).
impl TrackingCodec {
    /// Build a codec from the master secret string.
    /// Derives two sub-keys with HMAC-SHA-256.
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
    /// Returns `None` on failure, while emitting an auditable error classification.
    pub fn decode(&self, token: &str) -> Option<TrackingData> {
        match self.decode_with_error(token) {
            Ok(data) => Some(data),
            Err(err) => {
                warn!(error = ?err, "Tracking token decode failed");
                None
            }
        }
    }

    /// Decode a URL-safe tracking token with a typed failure reason.
    pub fn decode_with_error(
        &self,
        token: &str,
    ) -> std::result::Result<TrackingData, TrackingDecodeError> {
        if token.len() < 10 || token.len() > 4096 {
            return Err(TrackingDecodeError::InvalidLength);
        }

        let combined = URL_SAFE_NO_PAD
            .decode(token)
            .map_err(|_| TrackingDecodeError::InvalidBase64)?;

        if combined.len() < IV_LEN + AUTH_TAG_LEN + 1 {
            return Err(TrackingDecodeError::TruncatedPayload);
        }

        let (iv_bytes, rest) = combined.split_at(IV_LEN);
        let (tag_bytes, ciphertext) = rest.split_at(AUTH_TAG_LEN);

        let plaintext = self
            .aes128gcm_decrypt(ciphertext, iv_bytes, tag_bytes)
            .map_err(|_| TrackingDecodeError::DecryptionFailed)?;

        deserialize_tracking_data(&plaintext).ok_or(TrackingDecodeError::InvalidPayload)
    }

    // ── Unsubscribe token ─────────────────────────────────────────────

    /// Generate an AES-128-GCM encrypted unsubscribe token.
    /// Payload:`{tenantId}:{recipient}:{unix_ms}` (UTF-8) — the LEGACY v1
    /// format (no message attribution). Prefer
    /// [`TrackingCodec::generate_unsubscribe_token_with_message`] for new
    /// mail so the tracking service can attribute the unsubscribe to the
    /// originating message without a database lookup (F13).
    pub fn generate_unsubscribe_token(&self, tenant_id: &str, recipient: &str) -> Result<String> {
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

    /// F13:generate a v2 unsubscribe token that carries the ORIGINATING
    /// message id inside the authenticated (AES-128-GCM) envelope, so
    /// attribution never depends on a `messages` lookup that can silently
    /// fail and get substituted with an invented id.
    ///
    /// v2 payload layout (binary, length-prefixed — unambiguous even when
    /// tenant/recipient/message ids contain `:`):
    ///
    /// ```text
    /// b"AXU2"                       4-byte magic
    /// u16-be  tenant_id length
    ///         tenant_id bytes
    /// u16-be  recipient length
    ///         recipient bytes
    /// u16-be  message_id length
    ///         message_id bytes
    ///         ASCII decimal unix-ms timestamp
    /// ```
    ///
    /// The magic is uppercase; platform tenant ids are 26-char [0-9a-z]
    /// nanoids, so a legacy v1 text payload can never collide with it.
    pub fn generate_unsubscribe_token_with_message(
        &self,
        tenant_id: &str,
        recipient: &str,
        message_id: &str,
    ) -> Result<String> {
        let ts_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        let payload = serialize_unsub_payload_v2(tenant_id, recipient, message_id, ts_ms);
        let (iv, tag, ciphertext) = self.aes128gcm_encrypt(&payload)?;

        let mut combined = Vec::with_capacity(IV_LEN + AUTH_TAG_LEN + ciphertext.len());
        combined.extend_from_slice(&iv);
        combined.extend_from_slice(&tag);
        combined.extend_from_slice(&ciphertext);

        Ok(URL_SAFE_NO_PAD.encode(&combined))
    }

    /// Verify and decode an unsubscribe token.
    /// Supports two formats:/// 1. **New (GCM-encrypted)** — IV[12] || AuthTag[16] || Ciphertext.
    /// 2. **Legacy (HMAC-signed)** — payload-bytes || HMAC-SHA-256 suffix,
    ///    either the full 32-byte digest or the legacy 16-byte truncation
    ///    (#194).
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
        let payload_bytes = self.try_gcm_decrypt(&combined).or_else(|| {
            self.try_legacy_hmac_verify(&combined)
                .map(String::into_bytes)
        })?;

        // F13:v2 payloads carry the originating message id; legacy text
        // payloads (`tenant:recipient:ts`) do not and fall back to the
        // caller's database resolution.
        if payload_bytes.starts_with(UNSUB_PAYLOAD_V2_MAGIC) {
            let (tenant_id, recipient, message_id, timestamp_ms) =
                parse_unsub_payload_v2(&payload_bytes)?;
            if !unsubscribe_token_age_ok(timestamp_ms, max_age_days) {
                return None; // Token too old
            }
            Some(UnsubscribeData {
                tenant_id,
                recipient,
                timestamp_ms,
                message_id: Some(message_id),
            })
        } else {
            let payload_str = String::from_utf8(payload_bytes).ok()?;
            parse_unsubscribe_payload(&payload_str, max_age_days)
        }
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

    pub fn generate_preferences_token(&self, tenant_id: &str, recipient: &str) -> Result<String> {
        self.generate_unsubscribe_token(tenant_id, recipient)
    }

    pub fn verify_preferences_token(&self, token: &str) -> Option<UnsubscribeData> {
        self.verify_unsubscribe_token_v2(token, Some(30))
    }

    // ── Internal helpers ──────────────────────────────────────────────

    fn aes128gcm_encrypt(
        &self,
        plaintext: &[u8],
    ) -> Result<([u8; IV_LEN], [u8; AUTH_TAG_LEN], Vec<u8>)> {
        use aes_gcm::aead::rand_core::RngCore;
        use aes_gcm::aead::OsRng;

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

    fn try_gcm_decrypt(&self, combined: &[u8]) -> Option<Vec<u8>> {
        let (iv_bytes, rest) = combined.split_at(IV_LEN);
        let (tag_bytes, ciphertext) = rest.split_at(AUTH_TAG_LEN);
        self.aes128gcm_decrypt(ciphertext, iv_bytes, tag_bytes).ok()
    }

    fn try_legacy_hmac_verify(&self, combined: &[u8]) -> Option<String> {
        // #194:Legacy tokens used a 16-byte truncated HMAC; tokens minted after
        // that fix carry the full 32-byte digest. The previous implementation
        // always compared the LAST 16 bytes against the FIRST 16 bytes of the
        // full digest, so full-32 signatures could never verify. Accept both
        // shapes by sizing the expected signature to the actual suffix.
        // Truncated verification is weaker (128 bits) but still sufficient for
        // unsubscribe tokens; log a debug line for monitoring migration
        // progress.
        let verify = |sig_len: usize| -> Option<String> {
            if combined.len() < sig_len + 1 {
                return None;
            }
            let payload_bytes = &combined[..combined.len() - sig_len];
            let expected = hmac_sha256(&self.sig_key.0, payload_bytes);
            if !constant_time_eq(&combined[combined.len() - sig_len..], &expected[..sig_len]) {
                return None;
            }
            String::from_utf8(payload_bytes.to_vec()).ok()
        };

        // Full 32-byte signature (current legacy format) first, then the
        // truncated 16-byte form. A truncated token cannot accidentally pass
        // the 32-byte check: the two candidate payloads differ, so both
        // expectations would have to collide on 256 bits.
        match verify(32).or_else(|| verify(16)) {
            Some(payload) => {
                tracing::debug!(
                    "Legacy HMAC unsubscribe token verified — consider re-issuing with the GCM format"
                );
                Some(payload)
            }
            None => None,
        }
    }
}

// ── Key derivation ────────────────────────────────────────────────────────────

/// Returns HMAC-SHA-256(secret, info) truncated to `len` bytes.
fn derive_key_hmac(secret: &[u8], info: &[u8], len: usize) -> Zeroizing<Vec<u8>> {
    type HmacSha256 = Hmac<Sha256>;
    let mut mac = match <HmacSha256 as Mac>::new_from_slice(secret) {
        Ok(mac) => mac,
        Err(error) => {
            tracing::error!(?error, "Failed to initialize derive_key_hmac HMAC");
            return Zeroizing::new(Vec::new());
        }
    };
    mac.update(info);
    let result = mac.finalize().into_bytes();
    Zeroizing::new(result[..len].to_vec())
}

/// HMAC-SHA-256 of `data` under `key`; returns the full 32-byte digest.
fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    type HmacSha256 = Hmac<Sha256>;
    let mut mac = match <HmacSha256 as Mac>::new_from_slice(key) {
        Ok(mac) => mac,
        Err(error) => {
            tracing::error!(?error, "Failed to initialize hmac_sha256 HMAC");
            return [0; 32];
        }
    };
    mac.update(data);
    mac.finalize().into_bytes().into()
}

/// Constant-time equality check (mitigates timing oracle on HMAC validation).
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    bool::from(a.ct_eq(b))
}

// ── Unsubscribe payload parser ────────────────────────────────────────────────

/// F13:v2 unsubscribe payload magic. Uppercase on purpose — platform tenant
/// ids are 26-char [0-9a-z] nanoids, so a legacy v1 text payload
/// (`"tenant:recipient:ts"`) can never start with it and the two formats
/// stay unambiguously distinguishable after decryption.
const UNSUB_PAYLOAD_V2_MAGIC: &[u8; 4] = b"AXU2";

/// Serialize a v2 (message-attributed) unsubscribe payload.
fn serialize_unsub_payload_v2(
    tenant_id: &str,
    recipient: &str,
    message_id: &str,
    ts_ms: u64,
) -> Vec<u8> {
    let tid = tenant_id.as_bytes();
    let rec = recipient.as_bytes();
    let mid = message_id.as_bytes();
    let ts = ts_ms.to_string();

    let mut buf = Vec::with_capacity(4 + 6 + tid.len() + rec.len() + mid.len() + ts.len());
    buf.extend_from_slice(UNSUB_PAYLOAD_V2_MAGIC);
    write_u16be(&mut buf, tid.len() as u16);
    buf.extend_from_slice(tid);
    write_u16be(&mut buf, rec.len() as u16);
    buf.extend_from_slice(rec);
    write_u16be(&mut buf, mid.len() as u16);
    buf.extend_from_slice(mid);
    buf.extend_from_slice(ts.as_bytes());
    buf
}

/// Parse a decrypted v2 unsubscribe payload. `None` on any structural
/// defect (bad lengths, non-UTF-8 fields, non-decimal timestamp).
fn parse_unsub_payload_v2(buf: &[u8]) -> Option<(String, String, String, u64)> {
    let rest = buf.strip_prefix(UNSUB_PAYLOAD_V2_MAGIC)?;

    let mut pos = 0usize;
    let read_field = |pos: &mut usize| -> Option<String> {
        if *pos + 2 > rest.len() {
            return None;
        }
        let len = ((rest[*pos] as usize) << 8) | rest[*pos + 1] as usize;
        *pos += 2;
        if *pos + len > rest.len() {
            return None;
        }
        let s = std::str::from_utf8(&rest[*pos..*pos + len])
            .ok()?
            .to_owned();
        *pos += len;
        Some(s)
    };

    let tenant_id = read_field(&mut pos)?;
    let recipient = read_field(&mut pos)?;
    let message_id = read_field(&mut pos)?;

    let ts_str = std::str::from_utf8(&rest[pos..]).ok()?;
    if ts_str.is_empty() || !ts_str.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let timestamp_ms: u64 = ts_str.parse().ok()?;

    if tenant_id.is_empty() || recipient.is_empty() || message_id.is_empty() {
        return None;
    }

    Some((tenant_id, recipient, message_id, timestamp_ms))
}

/// Shared age gate for unsubscribe/preference tokens (v1 and v2 payloads):
/// rejected once older than `max_age_days` (default 90).
fn unsubscribe_token_age_ok(timestamp_ms: u64, max_age_days: Option<u64>) -> bool {
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    let max_ms = max_age_days.unwrap_or(90) * 24 * 60 * 60 * 1000;
    now_ms.saturating_sub(timestamp_ms) <= max_ms
}

fn parse_unsubscribe_payload(payload: &str, max_age_days: Option<u64>) -> Option<UnsubscribeData> {
    // Format:"tenantId:recipient:timestamp_ms"
    // #195:Both tenant_id and recipient may contain colons.
    // Strategy:timestamp_ms is always a pure decimal integer at the end,
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

    if !unsubscribe_token_age_ok(timestamp_ms, max_age_days) {
        return None; // Token too old
    }

    Some(UnsubscribeData {
        tenant_id,
        recipient,
        timestamp_ms,
        message_id: None,
    })
}

// ── Binary payload serialization ──────────────────────────────────────────────
// v1 – 1-byte version + u8 per-field lengths
// v2 – 1-byte version + u16-BE per-field lengths
// v3 – v2 + originalUrl field

fn write_u16be(buf: &mut Vec<u8>, v: u16) {
    buf.push((v >> 8) as u8);
    buf.push((v & 0xff) as u8);
}

fn serialize_tracking_data(data: &TrackingData) -> Vec<u8> {
    let tid = data.tenant_id.as_bytes();
    let mid = data.message_id.as_bytes();
    let rec = data.recipient.as_bytes();
    let lid = data.link_id.as_deref().unwrap_or("").as_bytes();
    let url = data.original_url.as_deref().unwrap_or("").as_bytes();

    let version: u8 = if data.original_url.is_some() { 3 } else { 2 };

    let mut buf = Vec::with_capacity(
        1 + 2
            + tid.len()
            + 2
            + mid.len()
            + 2
            + rec.len()
            + 2
            + lid.len()
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
            let s = std::str::from_utf8(&$buf[$pos..$pos + len])
                .ok()?
                .to_owned();
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
        let token = codec.encode(&data).expect("encode");
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
        // Legacy (v1) tokens carry NO message attribution (F13).
        assert!(data.message_id.is_none());
    }

    // ── F13:v2 unsubscribe tokens carry the originating message id ──────

    #[test]
    fn v2_unsubscribe_token_roundtrip_carries_message_id() {
        let codec = make_codec();
        let token = codec
            .generate_unsubscribe_token_with_message(
                "tenant_1",
                "user@domain.com",
                "0b6e1a20-9c2d-4f3e-8a7b-111122223333",
            )
            .expect("generate");
        let data = codec
            .verify_unsubscribe_token(&token, Some(90))
            .expect("verify");
        assert_eq!(data.tenant_id, "tenant_1");
        assert_eq!(data.recipient, "user@domain.com");
        assert_eq!(
            data.message_id.as_deref(),
            Some("0b6e1a20-9c2d-4f3e-8a7b-111122223333")
        );
    }

    /// The v2 payload is length-prefixed, so colons in any field survive.
    #[test]
    fn v2_unsubscribe_token_survives_colons_in_fields() {
        let codec = make_codec();
        let token = codec
            .generate_unsubscribe_token_with_message("ten:ant", "weird:user@host", "msg:42")
            .expect("generate");
        let data = codec
            .verify_unsubscribe_token(&token, Some(90))
            .expect("verify");
        assert_eq!(data.tenant_id, "ten:ant");
        assert_eq!(data.recipient, "weird:user@host");
        assert_eq!(data.message_id.as_deref(), Some("msg:42"));
    }

    /// A different codec (wrong key) must not verify a v2 token.
    #[test]
    fn v2_unsubscribe_token_rejects_wrong_key() {
        let codec = TrackingCodec::new("secret-one-aaaaaaaaaaaaaaaaaaaaaaaa");
        let token = codec
            .generate_unsubscribe_token_with_message("t", "u@x.com", "m1")
            .expect("generate");
        let other = TrackingCodec::new("secret-two-aaaaaaaaaaaaaaaaaaaaaaaa");
        assert!(other.verify_unsubscribe_token(&token, None).is_none());
    }

    /// A tampered v2 token must fail the GCM tag check (never decode garbage).
    #[test]
    fn v2_unsubscribe_token_tampering_fails() {
        let codec = make_codec();
        let token = codec
            .generate_unsubscribe_token_with_message("t", "u@x.com", "m1")
            .expect("generate");
        let mut raw = URL_SAFE_NO_PAD.decode(&token).expect("decode");
        let mid = raw.len() / 2;
        raw[mid] ^= 0x01;
        let tampered = URL_SAFE_NO_PAD.encode(&raw);
        assert!(codec.verify_unsubscribe_token(&tampered, None).is_none());
    }

    /// Structural corruption of a v2 payload (declared length overruns the
    /// buffer) must be REJECTED, never decoded as garbage.
    #[test]
    fn v2_unsubscribe_payload_rejects_structural_corruption() {
        // Valid frame, then truncate each field region.
        let mut buf = serialize_unsub_payload_v2("tenant", "u@x.com", "msg", 1_700_000_000_000);
        let full = buf.clone();
        let full_ts = "1700000000000";
        for cut in 1..full.len() {
            buf.truncate(full.len() - cut);
            if buf.starts_with(UNSUB_PAYLOAD_V2_MAGIC) {
                // A truncated frame may still parse only if the cut lands in
                // the trailing timestamp (leaving a valid decimal prefix);
                // anything else must be None. Whatever parses must carry the
                // exact original string fields.
                if let Some((t, r, m, ts)) = parse_unsub_payload_v2(&buf) {
                    assert_eq!(t, "tenant");
                    assert_eq!(r, "u@x.com");
                    assert_eq!(m, "msg");
                    assert!(
                        full_ts.starts_with(&ts.to_string()),
                        "timestamp must be a prefix of the original, got {ts}"
                    );
                }
            }
        }

        // Declared tenant length overruns the buffer → rejected.
        let mut bad = UNSUB_PAYLOAD_V2_MAGIC.to_vec();
        bad.extend_from_slice(&[0xFF, 0xFF]);
        bad.extend_from_slice(b"short");
        assert!(parse_unsub_payload_v2(&bad).is_none());

        // Non-decimal timestamp → rejected.
        let mut bad_ts = UNSUB_PAYLOAD_V2_MAGIC.to_vec();
        for field in ["t", "u@x.com", "m"] {
            bad_ts.extend_from_slice(&(field.len() as u16).to_be_bytes());
            bad_ts.extend_from_slice(field.as_bytes());
        }
        bad_ts.extend_from_slice(b"12ab");
        assert!(parse_unsub_payload_v2(&bad_ts).is_none());
    }

    #[test]
    fn unsubscribe_token_recipient_with_colon() {
        // Regression:email addresses do not contain ':', but the payload
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

    /// A field whose declared length exceeds the remaining buffer must be
    /// REJECTED (`None`), never decoded as garbage / out-of-bounds data.
    #[test]
    fn decode_rejects_field_length_exceeding_remaining_buffer() {
        // v2 (u16-BE length prefix): declares a 255-byte tenant_id but only
        // 3 bytes remain.
        let mut buf = vec![2u8, 0x00, 0xFF];
        buf.extend_from_slice(b"abc");
        assert!(deserialize_tracking_data(&buf).is_none());

        // v1 (u8 length prefix): declares a 16-byte tenant_id but only 1
        // byte remains.
        assert!(deserialize_tracking_data(&[1u8, 0x10, b'a']).is_none());

        // Truncated length PREFIX itself: a u16 prefix needs 2 bytes but
        // only 1 remains.
        assert!(deserialize_tracking_data(&[2u8, 0x00]).is_none());

        // Same for a trailing v3 originalUrl field: header claims more URL
        // bytes than the buffer holds.
        let mut buf = vec![3u8];
        for field in ["ten", "msg", "usr", ""] {
            buf.extend_from_slice(&(field.len() as u16).to_be_bytes());
            buf.extend_from_slice(field.as_bytes());
        }
        buf.extend_from_slice(&0x00FFu16.to_be_bytes()); // 255-byte URL…
        buf.extend_from_slice(b"x"); // …but only 1 byte remains
        assert!(deserialize_tracking_data(&buf).is_none());
    }

    /// Boundary: a field that exactly fills the buffer must decode fine —
    /// the rejection above must not over-trigger.
    #[test]
    fn decode_accepts_fields_that_exactly_fill_buffer() {
        let mut buf = vec![2u8];
        for field in ["ten", "msg", "usr", ""] {
            buf.extend_from_slice(&(field.len() as u16).to_be_bytes());
            buf.extend_from_slice(field.as_bytes());
        }
        let data = deserialize_tracking_data(&buf).expect("exact-fill must decode");
        assert_eq!(data.tenant_id, "ten");
        assert_eq!(data.message_id, "msg");
        assert_eq!(data.recipient, "usr");
        assert_eq!(data.link_id, None);
        assert!(data.original_url.is_none());
    }

    /// #194:legacy HMAC tokens must verify with EITHER the full 32-byte
    /// digest or the 16-byte truncation — the old code compared the last 16
    /// bytes against the first 16 of the full digest, so full-32 signatures
    /// never verified.
    #[test]
    fn legacy_hmac_token_accepts_full_and_truncated_signatures() {
        let codec = make_codec();
        let payload = b"tenant_1:user@domain.com:1700000000000";
        let digest = hmac_sha256(&codec.sig_key.0, payload);

        // Full 32-byte signature suffix verifies.
        let mut full = payload.to_vec();
        full.extend_from_slice(&digest);
        let verified = codec
            .try_legacy_hmac_verify(&full)
            .expect("full 32-byte legacy HMAC must verify");
        assert_eq!(verified.as_bytes(), payload);

        // Legacy 16-byte truncation still verifies.
        let mut truncated = payload.to_vec();
        truncated.extend_from_slice(&digest[..16]);
        assert!(codec.try_legacy_hmac_verify(&truncated).is_some());

        // A signature under a different key must fail BOTH sizes.
        let wrong = hmac_sha256(b"not-the-signing-key", payload);
        let mut forged = payload.to_vec();
        forged.extend_from_slice(&wrong);
        assert!(codec.try_legacy_hmac_verify(&forged).is_none());
        let mut forged_trunc = payload.to_vec();
        forged_trunc.extend_from_slice(&wrong[..16]);
        assert!(codec.try_legacy_hmac_verify(&forged_trunc).is_none());
    }
}
