//! Field-level encryption for sensitive secrets stored in the database
//! (mfa_secret, OAuth tokens, …).
//!
//! # Format
//!
//! On-disk encoding is `enc:v1:<base64(version || nonce || ciphertext+tag)>`.
//! The leading sentinel allows callers to detect whether a stored value is
//! already encrypted, supporting forward migration from plaintext.
//!
//! # Key management
//!
//! The encryption key is read from `MFA_SECRET_ENCRYPTION_KEY` (32-byte
//! hex). It is cached in a `OnceLock` so we only pay the parse cost once
//! per process.
//!
//! When the key is **unset**:
//! - `encrypt_at_rest` returns the plaintext unchanged and logs a one-time
//!   warning so existing deployments do not break instantly.
//! - `decrypt_at_rest` accepts both encrypted and plaintext inputs.
//!
//! When the key **is** set, encryption always wraps new writes; reads
//! transparently handle legacy plaintext rows so the database can be
//! migrated incrementally.

use std::sync::{Once, OnceLock};

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use rand::rngs::OsRng;
use rand::TryRngCore;
use thiserror::Error;
use zeroize::Zeroize;

const ENVELOPE_VERSION_V1: u8 = 1;
const NONCE_SIZE: usize = 12;
const TAG_SIZE: usize = 16;
const KEY_SIZE: usize = 32;
const PREFIX: &str = "enc:v1:";
const ENV_VAR: &str = "MFA_SECRET_ENCRYPTION_KEY";

#[derive(Debug, Error)]
pub enum SecretEncryptionError {
    #[error("encryption key not configured")]
    KeyMissing,
    #[error("invalid encrypted envelope: {0}")]
    InvalidEnvelope(&'static str),
    #[error("decryption failed (tampered, wrong key, or AAD mismatch)")]
    DecryptionFailed,
    #[error("base64 decode failed: {0}")]
    Base64(#[from] base64::DecodeError),
    #[error("hex decode failed for {ENV_VAR}: {0}")]
    Hex(#[from] hex::FromHexError),
    #[error("RNG failure: {0}")]
    Rng(String),
}

fn key_cell() -> &'static OnceLock<Option<[u8; KEY_SIZE]>> {
    static CELL: OnceLock<Option<[u8; KEY_SIZE]>> = OnceLock::new();
    &CELL
}

fn warn_once_missing() {
    static WARN: Once = Once::new();
    WARN.call_once(|| {
        tracing::warn!(
            env_var = ENV_VAR,
            "{ENV_VAR} is not set — secrets at rest are stored as plaintext. \
             Configure a 32-byte hex-encoded key to enable encryption."
        );
    });
}

/// Load the master key from the environment, caching the result.
/// Returns `Ok(None)` if the env var is unset (callers should treat as
/// plaintext mode).
fn load_key() -> Result<Option<[u8; KEY_SIZE]>, SecretEncryptionError> {
    if let Some(slot) = key_cell().get() {
        return Ok(*slot);
    }

    let parsed = match std::env::var(ENV_VAR) {
        Ok(hex_str) if !hex_str.is_empty() => {
            let bytes = hex::decode(hex_str.trim())?;
            if bytes.len() != KEY_SIZE {
                return Err(SecretEncryptionError::InvalidEnvelope(
                    "MFA_SECRET_ENCRYPTION_KEY must decode to 32 bytes",
                ));
            }
            let mut key = [0u8; KEY_SIZE];
            key.copy_from_slice(&bytes);
            Some(key)
        }
        _ => None,
    };

    let _ = key_cell().set(parsed);
    Ok(*key_cell().get().unwrap_or(&None))
}

/// Encrypt `plaintext` for at-rest storage.
///
/// Returns `enc:v1:<base64>` when an encryption key is configured. If the
/// key is unset, returns the plaintext unchanged (with a one-time warn).
/// `aad` is bound into the GCM tag — pass a stable scope identifier such
/// as `format!("user={user_id}")` so a ciphertext cannot be relocated.
pub fn encrypt_at_rest(plaintext: &str, aad: &[u8]) -> Result<String, SecretEncryptionError> {
    let key = match load_key()? {
        Some(k) => k,
        None => {
            warn_once_missing();
            return Ok(plaintext.to_string());
        }
    };

    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|_| SecretEncryptionError::InvalidEnvelope("cipher init failed"))?;

    let mut nonce_bytes = [0u8; NONCE_SIZE];
    OsRng
        .try_fill_bytes(&mut nonce_bytes)
        .map_err(|e| SecretEncryptionError::Rng(e.to_string()))?;
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(
            nonce,
            Payload {
                msg: plaintext.as_bytes(),
                aad,
            },
        )
        .map_err(|_| SecretEncryptionError::DecryptionFailed)?;

    let mut envelope = Vec::with_capacity(1 + NONCE_SIZE + ciphertext.len());
    envelope.push(ENVELOPE_VERSION_V1);
    envelope.extend_from_slice(&nonce_bytes);
    envelope.extend_from_slice(&ciphertext);

    let mut key_zero = key;
    key_zero.zeroize();

    Ok(format!("{PREFIX}{}", B64.encode(envelope)))
}

/// Decrypt `stored` back to plaintext.
///
/// Transparently accepts both the `enc:v1:<base64>` envelope and legacy
/// plaintext values (so a database can be migrated row-by-row). Pass the
/// same `aad` used at encryption time.
pub fn decrypt_at_rest(stored: &str, aad: &[u8]) -> Result<String, SecretEncryptionError> {
    let Some(b64) = stored.strip_prefix(PREFIX) else {
        // Legacy plaintext: pass through.
        return Ok(stored.to_string());
    };

    let key = load_key()?.ok_or(SecretEncryptionError::KeyMissing)?;

    let envelope = B64.decode(b64.as_bytes())?;
    if envelope.is_empty() || envelope[0] != ENVELOPE_VERSION_V1 {
        return Err(SecretEncryptionError::InvalidEnvelope(
            "unknown envelope version",
        ));
    }
    if envelope.len() < 1 + NONCE_SIZE + TAG_SIZE {
        return Err(SecretEncryptionError::InvalidEnvelope(
            "envelope shorter than minimum length",
        ));
    }

    let (nonce_bytes, ciphertext) = envelope[1..].split_at(NONCE_SIZE);
    let nonce = Nonce::from_slice(nonce_bytes);

    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|_| SecretEncryptionError::InvalidEnvelope("cipher init failed"))?;

    let plaintext = cipher
        .decrypt(
            nonce,
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| SecretEncryptionError::DecryptionFailed)?;

    let mut key_zero = key;
    key_zero.zeroize();

    String::from_utf8(plaintext)
        .map_err(|_| SecretEncryptionError::InvalidEnvelope("plaintext is not UTF-8"))
}

/// Whether the value is in the encrypted envelope format.
pub fn is_encrypted(value: &str) -> bool {
    value.starts_with(PREFIX)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Single combined test: the key cache is process-global `OnceLock`, so
    /// we can only initialize it once per test binary. We exercise all
    /// behaviors here under one resolved key.
    #[test]
    fn test_secret_at_rest_behaviors() {
        // Force-populate the key cache to a deterministic 32-byte value.
        let mut key = [0u8; KEY_SIZE];
        let decoded =
            hex::decode("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff")
                .unwrap();
        key.copy_from_slice(&decoded);
        let _ = key_cell().set(Some(key));

        // 1. Roundtrip with AAD succeeds.
        let aad_good = b"user=u1";
        let enc = encrypt_at_rest("topsecret-totp", aad_good).unwrap();
        assert!(enc.starts_with(PREFIX));
        assert_eq!(decrypt_at_rest(&enc, aad_good).unwrap(), "topsecret-totp");

        // 2. AAD mismatch is rejected (relocation defense).
        let aad_bad = b"user=u2";
        assert!(decrypt_at_rest(&enc, aad_bad).is_err());

        // 3. Legacy plaintext passes through transparently on decrypt.
        let plain = "raw-base32-secret";
        assert_eq!(decrypt_at_rest(plain, aad_good).unwrap(), plain);

        // 4. Format detection helper.
        assert!(is_encrypted("enc:v1:abc"));
        assert!(!is_encrypted("plain"));

        // 5. Tamper detection: flipping the last byte of the envelope must fail.
        let mut bytes = B64
            .decode(enc.strip_prefix(PREFIX).unwrap().as_bytes())
            .unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 0x01;
        let tampered = format!("{PREFIX}{}", B64.encode(&bytes));
        assert!(decrypt_at_rest(&tampered, aad_good).is_err());
    }
}
