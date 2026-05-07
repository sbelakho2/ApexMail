//! AES-256-GCM envelope encryption for sensitive grader fields.
//!
//! The master key is provided as a 32-byte base64-encoded value via
//! `GraderConfig::encryption_master_key_base64`. Each ciphertext is stored
//! as `v1:<nonce_b64>:<ct_b64>` so the format is self-describing and key
//! rotation can be added later by bumping the version tag.
//!
//! When `encrypt_stored_content` is `true` and no key is configured, the
//! engine refuses to start — there are no silent fallbacks.

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use rand::RngCore;

/// Errors raised by the crypto layer.
#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("encryption master key is not configured")]
    MissingKey,
    #[error("encryption master key has invalid length (expected 32 bytes, got {0})")]
    InvalidKeyLength(usize),
    #[error("encryption master key is not valid base64: {0}")]
    InvalidKeyEncoding(String),
    #[error("ciphertext is malformed")]
    MalformedCiphertext,
    #[error("decryption failed (wrong key, tampered ciphertext, or unsupported version)")]
    DecryptionFailed,
    #[error("encryption failed: {0}")]
    EncryptionFailed(String),
}

/// Wrapper around an Aes256Gcm cipher. Cheap to clone.
#[derive(Clone)]
pub struct Cipher {
    inner: Aes256Gcm,
}

impl Cipher {
    /// Construct from a base64-encoded 32-byte key.
    pub fn from_base64_key(b64: &str) -> Result<Self, CryptoError> {
        let raw = B64
            .decode(b64.trim())
            .map_err(|e| CryptoError::InvalidKeyEncoding(e.to_string()))?;
        if raw.len() != 32 {
            return Err(CryptoError::InvalidKeyLength(raw.len()));
        }
        let key = Key::<Aes256Gcm>::from_slice(&raw);
        Ok(Self { inner: Aes256Gcm::new(key) })
    }

    /// Encrypt `plaintext` and return the canonical `v1:<nonce>:<ct>` form.
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<String, CryptoError> {
        let mut nonce_bytes = [0u8; 12];
        rand::rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ct = self
            .inner
            .encrypt(nonce, plaintext)
            .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?;
        Ok(format!(
            "v1:{}:{}",
            B64.encode(nonce_bytes),
            B64.encode(ct)
        ))
    }

    /// Decrypt a `v1:<nonce>:<ct>` blob.
    pub fn decrypt(&self, blob: &str) -> Result<Vec<u8>, CryptoError> {
        let mut parts = blob.splitn(3, ':');
        let version = parts.next().ok_or(CryptoError::MalformedCiphertext)?;
        let nonce_b64 = parts.next().ok_or(CryptoError::MalformedCiphertext)?;
        let ct_b64 = parts.next().ok_or(CryptoError::MalformedCiphertext)?;
        if version != "v1" {
            return Err(CryptoError::MalformedCiphertext);
        }
        let nonce_bytes = B64
            .decode(nonce_b64)
            .map_err(|_| CryptoError::MalformedCiphertext)?;
        if nonce_bytes.len() != 12 {
            return Err(CryptoError::MalformedCiphertext);
        }
        let ct = B64
            .decode(ct_b64)
            .map_err(|_| CryptoError::MalformedCiphertext)?;
        let nonce = Nonce::from_slice(&nonce_bytes);
        self.inner.decrypt(nonce, ct.as_ref()).map_err(|_| CryptoError::DecryptionFailed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> String {
        B64.encode([7u8; 32])
    }

    #[test]
    fn round_trip() {
        let c = Cipher::from_base64_key(&test_key()).unwrap();
        let blob = c.encrypt(b"hello, grader").unwrap();
        assert!(blob.starts_with("v1:"));
        let pt = c.decrypt(&blob).unwrap();
        assert_eq!(pt, b"hello, grader");
    }

    #[test]
    fn rejects_wrong_key_length() {
        let bad = B64.encode([1u8; 16]);
        assert!(matches!(
            Cipher::from_base64_key(&bad),
            Err(CryptoError::InvalidKeyLength(16))
        ));
    }

    #[test]
    fn detects_tampering() {
        let c = Cipher::from_base64_key(&test_key()).unwrap();
        let mut blob = c.encrypt(b"abc").unwrap();
        // Flip one byte in the ciphertext segment.
        let flip_at = blob.len() - 4;
        let ch = blob.as_bytes()[flip_at];
        let new = if ch == b'A' { b'B' } else { b'A' };
        unsafe { blob.as_bytes_mut()[flip_at] = new; }
        assert!(c.decrypt(&blob).is_err());
    }

    #[test]
    fn rejects_unknown_version() {
        let c = Cipher::from_base64_key(&test_key()).unwrap();
        let blob = c.encrypt(b"x").unwrap();
        let v2 = blob.replacen("v1:", "v2:", 1);
        assert!(matches!(c.decrypt(&v2), Err(CryptoError::MalformedCiphertext)));
    }

    #[test]
    fn rejects_truncated_blob() {
        let c = Cipher::from_base64_key(&test_key()).unwrap();
        assert!(matches!(c.decrypt("v1:short"), Err(CryptoError::MalformedCiphertext)));
    }
}
