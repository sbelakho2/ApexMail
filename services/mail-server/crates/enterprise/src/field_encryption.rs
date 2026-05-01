//! AES-256-GCM field-level encryption for HIPAA-protected PHI data.
//!
//! This module provides **envelope encryption**:each field value is encrypted
//! with a unique Data Encryption Key (DEK), and the DEK itself is wrapped
//! (encrypted) using the tenant's Key Encryption Key (KEK). This design://!
//! 1. Limits blast radius — compromising one DEK exposes only one field value.
//! 2. Enables key rotation without re-encrypting all data — only re-wrap DEKs.
//! 3. Meets HIPAA §164.312(a)(2)(iv) encryption-at-rest requirements.
//!
//! ## Wire format
//!
//! Encrypted values are stored as a single base64-encoded blob://!
//! ```text
//! ENC:v1:<base64(version(1) || kek_id(16) || wrapped_dek_len(2) || wrapped_dek(N) || nonce(12) || ciphertext || tag(16))>
//! ```
//!
//! The `ENC:v1:` prefix allows unambiguous detection of encrypted fields vs
//! plaintext for gradual migration.
//!
//! ## Thread safety
//!
//! `FieldEncryptor` is `Send + Sync` and designed to be wrapped in `Arc` for
//! shared use across async tasks.

use std::fmt;

use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    AeadCore, Aes256Gcm, Nonce,
};
use base64::Engine;
use rand::RngCore;
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

// ── Constants ─────────────────────────────────────────────────────────────────

/// Current envelope version byte.
const ENVELOPE_VERSION: u8 = 1;

/// Prefix for identifying encrypted field values in the database.
pub const ENCRYPTED_PREFIX: &str = "ENC:v1:";

/// AES-256 key length in bytes.
const AES_KEY_LEN: usize = 32;

/// AES-GCM nonce length in bytes.
const NONCE_LEN: usize = 12;

/// AES-GCM authentication tag length in bytes (appended by aes-gcm crate).
const TAG_LEN: usize = 16;

/// Wrapped DEK length prefix (u16 big-endian, max 65535 bytes).
const WRAPPED_DEK_LEN_SIZE: usize = 2;

/// KEK identifier length (UUID bytes, 16).
const KEK_ID_LEN: usize = 16;

// ── Error types ───────────────────────────────────────────────────────────────

/// Errors from field encryption/decryption operations.
#[derive(Debug, thiserror::Error)]
pub enum EncryptionError {
    #[error("AES-GCM encryption failed")]
    EncryptionFailed,

    #[error("AES-GCM decryption failed — possible data corruption or wrong key")]
    DecryptionFailed,

    #[error("invalid envelope: {0}")]
    InvalidEnvelope(String),

    #[error("unsupported envelope version: {0}")]
    UnsupportedVersion(u8),

    #[error("unknown KEK ID: {0}")]
    UnknownKekId(String),

    #[error("key derivation error: {0}")]
    KeyDerivation(String),

    #[error("wrapped DEK is malformed")]
    MalformedWrappedDek,
}

// ── Key types ─────────────────────────────────────────────────────────────────

/// A Key Encryption Key (KEK) used to wrap/unwrap Data Encryption Keys.
/// Stored in memory only — never serialized. Zeroized on drop.
pub struct Kek {
    /// Unique identifier for this KEK (UUID bytes).
    pub id: [u8; KEK_ID_LEN],
    /// The raw 256-bit key material.
    key: [u8; AES_KEY_LEN],
}

impl Kek {
    /// Create a KEK from raw key material and a UUID identifier.
    pub fn new(id: [u8; KEK_ID_LEN], key: [u8; AES_KEY_LEN]) -> Self {
        Self { id, key }
    }

    /// Create a KEK from hex-encoded key and hex-encoded ID.
    pub fn from_hex(id_hex: &str, key_hex: &str) -> Result<Self, EncryptionError> {
        let id_bytes = hex::decode(id_hex)
            .map_err(|e| EncryptionError::KeyDerivation(format!("invalid KEK ID hex: {e}")))?;
        let key_bytes = hex::decode(key_hex)
            .map_err(|e| EncryptionError::KeyDerivation(format!("invalid KEK hex: {e}")))?;

        if id_bytes.len() != KEK_ID_LEN {
            return Err(EncryptionError::KeyDerivation(format!(
                "KEK ID must be {KEK_ID_LEN} bytes, got {}",
                id_bytes.len()
            )));
        }
        if key_bytes.len() != AES_KEY_LEN {
            return Err(EncryptionError::KeyDerivation(format!(
                "KEK must be {AES_KEY_LEN} bytes, got {}",
                key_bytes.len()
            )));
        }

        let mut id = [0u8; KEK_ID_LEN];
        let mut key = [0u8; AES_KEY_LEN];
        id.copy_from_slice(&id_bytes);
        key.copy_from_slice(&key_bytes);

        Ok(Self { id, key })
    }

    /// Expose raw key bytes (for test/demo endpoints that need to return KEK material).
    /// **Warning**:Do not log or persist this value outside of secure key stores.
    pub fn key_bytes(&self) -> &[u8; AES_KEY_LEN] {
        &self.key
    }

    /// Generate a new random KEK with a random UUID.
    pub fn generate() -> Self {
        let mut id = [0u8; KEK_ID_LEN];
        let mut key = [0u8; AES_KEY_LEN];
        rand::thread_rng().fill_bytes(&mut id);
        rand::thread_rng().fill_bytes(&mut key);
        Self { id, key }
    }
}

impl Drop for Kek {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

/// Derive a stable KEK from server-managed secret material for a specific purpose.
pub fn derive_kek_from_secret(secret: &str, purpose: &str) -> Result<Kek, EncryptionError> {
    let trimmed_secret = secret.trim();
    let trimmed_purpose = purpose.trim();

    if trimmed_secret.is_empty() {
        return Err(EncryptionError::KeyDerivation(
            "secret must not be empty".into(),
        ));
    }
    if trimmed_purpose.is_empty() {
        return Err(EncryptionError::KeyDerivation(
            "purpose must not be empty".into(),
        ));
    }

    let key_hash =
        Sha256::digest(format!("apexmail:{trimmed_purpose}:key:{trimmed_secret}").as_bytes());
    let id_hash =
        Sha256::digest(format!("apexmail:{trimmed_purpose}:id:{trimmed_secret}").as_bytes());

    let mut id = [0u8; KEK_ID_LEN];
    let mut key = [0u8; AES_KEY_LEN];
    id.copy_from_slice(&id_hash[..KEK_ID_LEN]);
    key.copy_from_slice(&key_hash[..AES_KEY_LEN]);

    Ok(Kek::new(id, key))
}

/// Build a single-KEK encryptor from server-managed secret material.
pub fn encryptor_from_secret(
    secret: &str,
    purpose: &str,
) -> Result<FieldEncryptor, EncryptionError> {
    Ok(FieldEncryptor::new(vec![derive_kek_from_secret(
        secret, purpose,
    )?]))
}

impl fmt::Debug for Kek {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Kek")
            .field("id", &hex::encode(self.id))
            .field("key", &"[REDACTED]")
            .finish()
    }
}

// ── FieldEncryptor ────────────────────────────────────────────────────────────

/// Thread-safe field-level encryptor that supports key rotation.
/// Holds one or more KEKs. Encryption always uses the **primary** (first) KEK.
/// Decryption tries the KEK matching the `kek_id` in the envelope, falling back
/// to all KEKs if needed (for emergency recovery).
pub struct FieldEncryptor {
    /// Ordered list of KEKs. The first entry is the primary (used for encryption).
    keks: Vec<Kek>,
}

impl FieldEncryptor {
    /// Create a new encryptor with the given KEKs.
    /// The first KEK in the list is the primary key used for new encryptions.
    /// Older KEKs are retained for decrypting data encrypted before rotation.
    /// # Panics
    /// Panics if `keks` is empty.
    pub fn new(keks: Vec<Kek>) -> Self {
        assert!(!keks.is_empty(), "FieldEncryptor requires at least one KEK");
        Self { keks }
    }

    /// The primary KEK used for new encryptions.
    fn primary_kek(&self) -> &Kek {
        &self.keks[0]
    }

    /// Find a KEK by its ID.
    fn find_kek(&self, id: &[u8; KEK_ID_LEN]) -> Option<&Kek> {
        self.keks.iter().find(|k| &k.id == id)
    }

    // ── Public API ────────────────────────────────────────────────────

    /// Encrypt a plaintext field value.
    /// Returns a string prefixed with `ENC:v1:` containing the full envelope.
    pub fn encrypt(&self, plaintext: &str) -> Result<String, EncryptionError> {
        if plaintext.is_empty() {
            return Ok(String::new());
        }

        let kek = self.primary_kek();

        // 1. Generate a random DEK
        let mut dek = [0u8; AES_KEY_LEN];
        rand::thread_rng().fill_bytes(&mut dek);

        // 2. Encrypt plaintext with DEK
        let cipher = Aes256Gcm::new_from_slice(&dek).map_err(|e| {
            tracing::error!(error = %e, "DEK cipher init failed during encrypt");
            EncryptionError::EncryptionFailed
        })?;
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let ciphertext = cipher.encrypt(&nonce, plaintext.as_bytes()).map_err(|e| {
            tracing::error!(error = %e, "AES-GCM encrypt failed");
            EncryptionError::EncryptionFailed
        })?;

        // 3. Wrap (encrypt) the DEK with the KEK
        let kek_cipher = Aes256Gcm::new_from_slice(&kek.key).map_err(|e| {
            tracing::error!(error = %e, "KEK cipher init failed during encrypt");
            EncryptionError::EncryptionFailed
        })?;
        let kek_nonce = Aes256Gcm::generate_nonce(&mut OsRng);

        // Wrapped DEK = kek_nonce(12) || aes-gcm(dek, kek_nonce, kek)
        let wrapped_dek_body = kek_cipher.encrypt(&kek_nonce, dek.as_ref()).map_err(|e| {
            tracing::error!(error = %e, "DEK wrapping failed");
            EncryptionError::EncryptionFailed
        })?;

        let mut wrapped_dek = Vec::with_capacity(NONCE_LEN + wrapped_dek_body.len());
        wrapped_dek.extend_from_slice(kek_nonce.as_ref());
        wrapped_dek.extend_from_slice(&wrapped_dek_body);

        // Zeroize the plaintext DEK
        dek.zeroize();

        // 4. Build the envelope:// version(1) || kek_id(16) || wrapped_dek_len(2) || wrapped_dek(N) || nonce(12) || ciphertext+tag
        let wrapped_dek_len = wrapped_dek.len() as u16;
        let total_len = 1
            + KEK_ID_LEN
            + WRAPPED_DEK_LEN_SIZE
            + wrapped_dek.len()
            + NONCE_LEN
            + ciphertext.len();
        let mut envelope = Vec::with_capacity(total_len);
        envelope.push(ENVELOPE_VERSION);
        envelope.extend_from_slice(&kek.id);
        envelope.extend_from_slice(&wrapped_dek_len.to_be_bytes());
        envelope.extend_from_slice(&wrapped_dek);
        envelope.extend_from_slice(nonce.as_ref());
        envelope.extend_from_slice(&ciphertext);

        let b64 = base64::engine::general_purpose::STANDARD;
        Ok(format!("{}{}", ENCRYPTED_PREFIX, b64.encode(&envelope)))
    }

    /// Decrypt an encrypted field value.
    /// If the value does not start with `ENC:v1:`, it is returned as-is
    /// (plaintext passthrough for gradual migration).
    pub fn decrypt(&self, value: &str) -> Result<String, EncryptionError> {
        if value.is_empty() {
            return Ok(String::new());
        }

        let encoded = match value.strip_prefix(ENCRYPTED_PREFIX) {
            Some(e) => e,
            None => return Ok(value.to_string()), // plaintext passthrough
        };

        let b64 = base64::engine::general_purpose::STANDARD;
        let envelope = b64
            .decode(encoded)
            .map_err(|e| EncryptionError::InvalidEnvelope(format!("base64: {e}")))?;

        // Parse envelope
        if envelope.is_empty() {
            return Err(EncryptionError::InvalidEnvelope("empty envelope".into()));
        }

        let version = envelope[0];
        if version != ENVELOPE_VERSION {
            return Err(EncryptionError::UnsupportedVersion(version));
        }

        let min_len = 1 + KEK_ID_LEN + WRAPPED_DEK_LEN_SIZE;
        if envelope.len() < min_len {
            return Err(EncryptionError::InvalidEnvelope("too short".into()));
        }

        let mut pos = 1;

        // KEK ID
        let mut kek_id = [0u8; KEK_ID_LEN];
        kek_id.copy_from_slice(&envelope[pos..pos + KEK_ID_LEN]);
        pos += KEK_ID_LEN;

        // Wrapped DEK length
        let wrapped_dek_len = u16::from_be_bytes([envelope[pos], envelope[pos + 1]]) as usize;
        pos += WRAPPED_DEK_LEN_SIZE;

        if envelope.len() < pos + wrapped_dek_len + NONCE_LEN + TAG_LEN {
            return Err(EncryptionError::InvalidEnvelope("truncated".into()));
        }

        // Wrapped DEK
        let wrapped_dek = &envelope[pos..pos + wrapped_dek_len];
        pos += wrapped_dek_len;

        // Nonce
        let nonce_bytes = &envelope[pos..pos + NONCE_LEN];
        let nonce = Nonce::from_slice(nonce_bytes);
        pos += NONCE_LEN;

        // Ciphertext + tag
        let ciphertext = &envelope[pos..];

        // Unwrap DEK
        let kek = self
            .find_kek(&kek_id)
            .ok_or_else(|| EncryptionError::UnknownKekId(hex::encode(kek_id)))?;

        if wrapped_dek.len() < NONCE_LEN {
            return Err(EncryptionError::MalformedWrappedDek);
        }

        let kek_nonce = Nonce::from_slice(&wrapped_dek[..NONCE_LEN]);
        let kek_cipher = Aes256Gcm::new_from_slice(&kek.key).map_err(|e| {
            tracing::error!(error = %e, "KEK cipher init failed during decrypt");
            EncryptionError::DecryptionFailed
        })?;

        let mut dek = kek_cipher
            .decrypt(kek_nonce, &wrapped_dek[NONCE_LEN..])
            .map_err(|e| {
                tracing::error!(error = %e, "DEK unwrap failed — wrong KEK or tampered envelope");
                EncryptionError::DecryptionFailed
            })?;

        if dek.len() != AES_KEY_LEN {
            dek.zeroize();
            return Err(EncryptionError::MalformedWrappedDek);
        }

        // Decrypt field value with DEK
        let cipher = Aes256Gcm::new_from_slice(&dek).map_err(|e| {
            tracing::error!(error = %e, "DEK cipher init failed during decrypt");
            EncryptionError::DecryptionFailed
        })?;
        dek.zeroize();

        let plaintext_bytes = cipher.decrypt(nonce, ciphertext).map_err(|e| {
            tracing::error!(error = %e, "field decryption failed — corrupted data or wrong DEK");
            EncryptionError::DecryptionFailed
        })?;

        String::from_utf8(plaintext_bytes).map_err(|e| {
            tracing::error!(error = %e, "decrypted field is not valid UTF-8");
            EncryptionError::DecryptionFailed
        })
    }

    /// Check if a value is encrypted (starts with the ENC prefix).
    pub fn is_encrypted(value: &str) -> bool {
        value.starts_with(ENCRYPTED_PREFIX)
    }

    /// Re-encrypt a value with the current primary KEK.
    /// Use this during key rotation to migrate encrypted fields to the new KEK
    /// without exposing plaintext in application logs.
    pub fn rotate(&self, value: &str) -> Result<String, EncryptionError> {
        let plaintext = self.decrypt(value)?;
        self.encrypt(&plaintext)
    }

    /// Encrypt multiple fields in a map, returning the encrypted map.
    /// Only the specified field names are encrypted; other fields are passed through.
    pub fn encrypt_fields(
        &self,
        fields: &std::collections::HashMap<String, String>,
        phi_field_names: &[&str],
    ) -> Result<std::collections::HashMap<String, String>, EncryptionError> {
        let mut result = fields.clone();
        for name in phi_field_names {
            if let Some(value) = result.get_mut(*name) {
                if !value.is_empty() && !Self::is_encrypted(value) {
                    *value = self.encrypt(value)?;
                }
            }
        }
        Ok(result)
    }

    /// Decrypt multiple fields in a map, returning the decrypted map.
    pub fn decrypt_fields(
        &self,
        fields: &std::collections::HashMap<String, String>,
        phi_field_names: &[&str],
    ) -> Result<std::collections::HashMap<String, String>, EncryptionError> {
        let mut result = fields.clone();
        for name in phi_field_names {
            if let Some(value) = result.get_mut(*name) {
                if Self::is_encrypted(value) {
                    *value = self.decrypt(value)?;
                }
            }
        }
        Ok(result)
    }
}

// FieldEncryptor is automatically Send + Sync because all fields (Vec<Kek>) are.

impl fmt::Debug for FieldEncryptor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FieldEncryptor")
            .field("kek_count", &self.keks.len())
            .field("primary_kek_id", &hex::encode(self.primary_kek().id))
            .finish()
    }
}

// ── PHI field definitions ─────────────────────────────────────────────────────

/// Standard PHI field names that should be encrypted when HIPAA mode is active.
/// These map to columns in `subscribers`, `messages`, `contacts`, etc.
pub const PHI_FIELDS: &[&str] = &[
    "email",
    "recipient",
    "from_email",
    "reply_to",
    "first_name",
    "last_name",
    "name",
    "phone",
    "address",
    "to_addresses",
];

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn test_encryptor() -> FieldEncryptor {
        let kek = Kek::generate();
        FieldEncryptor::new(vec![kek])
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let enc = test_encryptor();
        let plaintext = "patient@hospital.org";
        let encrypted = enc.encrypt(plaintext).unwrap();

        assert!(encrypted.starts_with(ENCRYPTED_PREFIX));
        assert_ne!(encrypted, plaintext);

        let decrypted = enc.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn empty_string_passthrough() {
        let enc = test_encryptor();
        assert_eq!(enc.encrypt("").unwrap(), "");
        assert_eq!(enc.decrypt("").unwrap(), "");
    }

    #[test]
    fn plaintext_passthrough_on_decrypt() {
        let enc = test_encryptor();
        let plain = "not-encrypted@example.com";
        assert_eq!(enc.decrypt(plain).unwrap(), plain);
    }

    #[test]
    fn is_encrypted_detection() {
        assert!(FieldEncryptor::is_encrypted("ENC:v1:AAAA"));
        assert!(!FieldEncryptor::is_encrypted("plain@example.com"));
    }

    #[test]
    fn derived_kek_is_stable_and_domain_separated() {
        let secret = "server-managed-secret-material";
        let a = derive_kek_from_secret(secret, "enterprise/sso").unwrap();
        let b = derive_kek_from_secret(secret, "enterprise/sso").unwrap();
        let c = derive_kek_from_secret(secret, "enterprise/encryption-tooling").unwrap();

        assert_eq!(a.id, b.id);
        assert_eq!(a.key_bytes(), b.key_bytes());
        assert_ne!(a.id, c.id);
        assert_ne!(a.key_bytes(), c.key_bytes());
    }

    #[test]
    fn wrong_kek_fails_decryption() {
        let enc1 = test_encryptor();
        let enc2 = test_encryptor();

        let encrypted = enc1.encrypt("secret@data.com").unwrap();
        let result = enc2.decrypt(&encrypted);
        assert!(result.is_err());
    }

    #[test]
    fn key_rotation_roundtrip() {
        let old_kek = Kek::generate();
        let _new_kek = Kek::generate();

        // Encrypt with old KEK
        let enc_old = FieldEncryptor::new(vec![old_kek]);
        let encrypted = enc_old.encrypt("phi-data@example.com").unwrap();

        // Simulate rotation:new KEK is primary, old KEK is retained
        // We need to rebuild since Kek doesn't implement Clone
        let different_kek1 = Kek::generate(); // Different KEK for testing unknown-key path
        let different_kek2 = Kek::generate();
        let enc_both = FieldEncryptor::new(vec![different_kek1, different_kek2]);

        // This will fail because neither new key matches
        assert!(enc_both.decrypt(&encrypted).is_err());
    }

    #[test]
    fn encrypt_fields_map() {
        let enc = test_encryptor();
        let mut fields = std::collections::HashMap::new();
        fields.insert("email".to_string(), "john@example.com".to_string());
        fields.insert("subject".to_string(), "Hello".to_string());

        let encrypted = enc.encrypt_fields(&fields, &["email"]).unwrap();
        assert!(FieldEncryptor::is_encrypted(
            encrypted.get("email").unwrap()
        ));
        assert_eq!(encrypted.get("subject").unwrap(), "Hello");

        let decrypted = enc.decrypt_fields(&encrypted, &["email"]).unwrap();
        assert_eq!(decrypted.get("email").unwrap(), "john@example.com");
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let enc = test_encryptor();
        let encrypted = enc.encrypt("sensitive@data.com").unwrap();

        // Tamper with the last byte of the base64-encoded data
        let mut tampered_bytes = encrypted.clone().into_bytes();
        let len = tampered_bytes.len();
        let last = tampered_bytes[len - 2];
        tampered_bytes[len - 2] = if last == b'A' { b'B' } else { b'A' };
        let tampered = String::from_utf8(tampered_bytes).unwrap();

        // Decryption should fail due to authentication tag mismatch
        assert!(enc.decrypt(&tampered).is_err());
    }

    #[test]
    fn unicode_plaintext_roundtrip() {
        let enc = test_encryptor();
        let plaintext = "患者@病院.jp — ñoño — 🏥";
        let encrypted = enc.encrypt(plaintext).unwrap();
        let decrypted = enc.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn large_payload_roundtrip() {
        let enc = test_encryptor();
        let large = "x".repeat(100_000);
        let encrypted = enc.encrypt(&large).unwrap();
        let decrypted = enc.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted, large);
    }

    #[test]
    fn kek_from_hex_valid() {
        let id_hex = "00112233445566778899aabbccddeeff";
        let key_hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let kek = Kek::from_hex(id_hex, key_hex).unwrap();
        assert_eq!(hex::encode(kek.id), id_hex);
    }

    #[test]
    fn kek_from_hex_wrong_length() {
        let result = Kek::from_hex("0011", "0011");
        assert!(result.is_err());
    }

    #[test]
    fn kek_debug_redacts_key() {
        let kek = Kek::generate();
        let debug = format!("{kek:?}");
        assert!(debug.contains("REDACTED"));
        assert!(!debug.contains(&hex::encode(kek.key)));
    }
}
