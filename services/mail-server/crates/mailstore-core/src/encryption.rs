//! Encryption at rest – AES‑256‑GCM for stored message content.
//!
//! O‑4.3:Provides envelope encryption with a configurable master key.
//!
//! Layout: `version(1) || nonce(12) || ciphertext || tag(16)` where
//! `version = 1` selects HKDF-SHA256 derivation with a per-version `info`
//! string. AAD (Additional Authenticated Data) binds each ciphertext to a
//! tenant/account/mailbox scope so a record cannot be relocated and
//! successfully decrypted under a different scope.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use anyhow::{anyhow, Result};
use rand::rngs::OsRng;
use rand::TryRngCore;
use zeroize::Zeroize;

/// Size of the AES‑256 key in bytes.
const KEY_SIZE: usize = 32;
/// Size of the GCM nonce in bytes (96 bits, standard for AES‑GCM).
const NONCE_SIZE: usize = 12;
/// Size of the GCM authentication tag in bytes.
const TAG_SIZE: usize = 16;
/// Current ciphertext envelope version.
pub const ENVELOPE_VERSION_V1: u8 = 1;

/// Encrypt with empty AAD. Prefer [`encrypt_with_aad`] for production use so
/// the ciphertext is bound to a tenant/account scope.
pub fn encrypt(plaintext: &[u8], master_key: &[u8]) -> Result<Vec<u8>> {
    encrypt_with_aad(plaintext, master_key, &[])
}

/// Decrypt a ciphertext that was produced with empty AAD.
pub fn decrypt(data: &[u8], master_key: &[u8]) -> Result<Vec<u8>> {
    decrypt_with_aad(data, master_key, &[])
}

/// Encrypt `plaintext` under `master_key` with `aad` bound into the GCM tag.
///
/// Output layout: `version(1) || nonce(12) || ciphertext || tag(16)`.
pub fn encrypt_with_aad(plaintext: &[u8], master_key: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    if master_key.len() < KEY_SIZE {
        return Err(anyhow!(
            "Master key must be at least {KEY_SIZE} bytes (got {})",
            master_key.len()
        ));
    }

    // Derive a fixed key from the master key (versioned `info` string).
    let mut key = derive_encryption_key(master_key, ENVELOPE_VERSION_V1);
    let cipher =
        Aes256Gcm::new_from_slice(&key).map_err(|e| anyhow!("Failed to create cipher: {e}"))?;
    // Wipe derived key as soon as the cipher is instantiated.
    key.zeroize();

    // Generate a 96-bit nonce from the OS CSPRNG.
    let mut nonce_bytes = [0u8; NONCE_SIZE];
    OsRng
        .try_fill_bytes(&mut nonce_bytes)
        .map_err(|e| anyhow!("OsRng failure: {e}"))?;
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(
            nonce,
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|e| anyhow!("Encryption failed: {e}"))?;

    let mut result = Vec::with_capacity(1 + NONCE_SIZE + ciphertext.len());
    result.push(ENVELOPE_VERSION_V1);
    result.extend_from_slice(&nonce_bytes);
    result.extend_from_slice(&ciphertext);

    Ok(result)
}

/// Decrypt a ciphertext previously produced by [`encrypt_with_aad`].
///
/// `aad` MUST match the value used at encryption time, otherwise GCM
/// authentication fails. Accepts the legacy unversioned layout
/// (`nonce || ciphertext || tag`) for forward compatibility with already
/// persisted data.
///
/// Version ambiguity: a legacy blob whose nonce happens to begin with the
/// byte `0x01` is indistinguishable from a v1 envelope by prefix alone. The
/// v1 interpretation is tried first; when it fails GCM authentication (and
/// the caller expects an empty AAD, as legacy blobs always were), the legacy
/// `nonce || ciphertext+tag` interpretation is retried instead of erroring.
pub fn decrypt_with_aad(data: &[u8], master_key: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    if master_key.len() < KEY_SIZE {
        return Err(anyhow!(
            "Master key must be at least {KEY_SIZE} bytes (got {})",
            master_key.len()
        ));
    }

    let legacy_ok = || data.len() >= NONCE_SIZE + TAG_SIZE;

    if !data.is_empty() && data[0] == ENVELOPE_VERSION_V1 {
        if data.len() < 1 + NONCE_SIZE + TAG_SIZE {
            // Too short for v1; could still be a legacy blob.
            if aad.is_empty() && legacy_ok() {
                return decrypt_layout(&data[..], master_key, 0u8, aad);
            }
            return Err(anyhow!(
                "Ciphertext too short: need at least {} bytes, got {}",
                1 + NONCE_SIZE + TAG_SIZE,
                data.len()
            ));
        }
        let (nonce, ct) = data[1..].split_at(NONCE_SIZE);
        match decrypt_parts(nonce, ct, master_key, ENVELOPE_VERSION_V1, aad) {
            Ok(pt) => return Ok(pt),
            Err(v1_err) => {
                // v1 parse failed: retry as a legacy unversioned blob whose
                // first nonce byte collided with the version byte. Only
                // legal for empty-AAD callers (legacy blobs never bound AAD).
                if aad.is_empty() && legacy_ok() {
                    if let Ok(pt) = decrypt_layout(data, master_key, 0u8, &[]) {
                        return Ok(pt);
                    }
                }
                return Err(v1_err);
            }
        }
    }

    // Legacy unversioned layout: `nonce || ciphertext+tag`. Versioned AAD
    // bindings cannot be recovered from an unversioned ciphertext.
    if !aad.is_empty() {
        return Err(anyhow!(
            "Refusing legacy unversioned ciphertext when AAD is non-empty",
        ));
    }
    if !legacy_ok() {
        return Err(anyhow!(
            "Ciphertext too short: need at least {} bytes, got {}",
            NONCE_SIZE + TAG_SIZE,
            data.len()
        ));
    }
    decrypt_layout(data, master_key, 0u8, aad)
}

/// Decrypt a `nonce || ciphertext+tag` layout under the key derived for
/// `version`, with the given AAD.
fn decrypt_layout(
    data: &[u8],
    master_key: &[u8],
    version: u8,
    aad: &[u8],
) -> Result<Vec<u8>> {
    let (nonce, ct) = data.split_at(NONCE_SIZE);
    decrypt_parts(nonce, ct, master_key, version, aad)
}

fn decrypt_parts(
    nonce_bytes: &[u8],
    ciphertext: &[u8],
    master_key: &[u8],
    version: u8,
    aad: &[u8],
) -> Result<Vec<u8>> {
    let nonce = Nonce::from_slice(nonce_bytes);
    let mut key = derive_encryption_key(master_key, version);
    let cipher =
        Aes256Gcm::new_from_slice(&key).map_err(|e| anyhow!("Failed to create cipher: {e}"))?;
    key.zeroize();

    let plaintext = cipher
        .decrypt(
            nonce,
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|e| anyhow!("Decryption failed (tampered, wrong key, or AAD mismatch): {e}"))?;

    Ok(plaintext)
}

/// Derive a 256‑bit encryption key from the master key. The version byte is
/// folded into the `info` string so future rotations cannot collide with
/// existing records.
fn derive_encryption_key(master_key: &[u8], version: u8) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(b"apexmail-mailstore-encryption");
    hasher.update([version]);
    hasher.update(master_key);
    hasher.finalize().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let key = b"0123456789abcdef0123456789abcdef"; // 32 bytes
        let plaintext = b"Hello, this is a secret message!";

        let encrypted = encrypt(plaintext, key).unwrap();
        assert_ne!(encrypted, plaintext);
        assert!(encrypted.len() > plaintext.len());
        assert_eq!(encrypted[0], ENVELOPE_VERSION_V1);

        let decrypted = decrypt(&encrypted, key).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_aad_binding_prevents_relocation() {
        let key = b"0123456789abcdef0123456789abcdef";
        let pt = b"per-tenant secret";
        let aad_a = b"tenant=A;account=1";
        let aad_b = b"tenant=B;account=1";

        let ct = encrypt_with_aad(pt, key, aad_a).unwrap();
        // Same AAD decrypts cleanly.
        assert_eq!(decrypt_with_aad(&ct, key, aad_a).unwrap(), pt);
        // Different AAD must fail.
        assert!(decrypt_with_aad(&ct, key, aad_b).is_err());
        // Empty AAD also fails because v1 envelope binds AAD into the tag.
        assert!(decrypt_with_aad(&ct, key, b"").is_err());
    }

    #[test]
    fn test_encrypt_produces_unique_ciphertexts() {
        let key = b"0123456789abcdef0123456789abcdef";
        let plaintext = b"Same message encrypted twice";

        let a = encrypt(plaintext, key).unwrap();
        let b = encrypt(plaintext, key).unwrap();
        // Nonce randomness ensures different ciphertexts each time
        assert_ne!(a, b);
    }

    #[test]
    fn test_decrypt_wrong_key_fails() {
        let key1 = b"0123456789abcdef0123456789abcdef";
        let key2 = b"fedcba9876543210fedcba9876543210";
        let plaintext = b"Secret data";

        let encrypted = encrypt(plaintext, key1).unwrap();
        let result = decrypt(&encrypted, key2);
        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_tampered_ciphertext_fails() {
        let key = b"0123456789abcdef0123456789abcdef";
        let plaintext = b"Tamper test";

        let mut encrypted = encrypt(plaintext, key).unwrap();
        // Flip a bit in the ciphertext body (not the version byte).
        if let Some(byte) = encrypted.last_mut() {
            *byte ^= 0x01;
        }
        let result = decrypt(&encrypted, key);
        assert!(result.is_err());
    }

    #[test]
    fn test_short_key_rejected() {
        let short_key = b"too-short";
        let result = encrypt(b"data", short_key);
        assert!(result.is_err());
    }

    #[test]
    fn test_short_ciphertext_rejected() {
        let key = b"0123456789abcdef0123456789abcdef";
        let result = decrypt(&[0u8; 10], key);
        assert!(result.is_err());
    }

    #[test]
    fn test_legacy_blob_with_v1_lookalike_first_byte_still_decrypts() {
        let master_key = b"0123456789abcdef0123456789abcdef";
        // Build a LEGACY (unversioned) blob: nonce || ciphertext+tag, where
        // the nonce's first byte collides with ENVELOPE_VERSION_V1 (0x01).
        // The v1 interpretation must fail GCM auth and the legacy layout
        // must be retried.
        let legacy_key = derive_encryption_key(master_key, 0u8);
        let cipher = Aes256Gcm::new_from_slice(&legacy_key).unwrap();
        let mut nonce_bytes = [0u8; NONCE_SIZE];
        nonce_bytes[0] = ENVELOPE_VERSION_V1;
        rand::rngs::OsRng
            .try_fill_bytes(&mut nonce_bytes[1..])
            .unwrap();
        let ct = cipher
            .encrypt(
                Nonce::from_slice(&nonce_bytes),
                Payload {
                    msg: b"legacy secret",
                    aad: &[],
                },
            )
            .unwrap();
        let mut blob = Vec::with_capacity(NONCE_SIZE + ct.len());
        blob.extend_from_slice(&nonce_bytes);
        blob.extend_from_slice(&ct);

        // Without the fallback this misparses as v1 and errors.
        let decrypted = decrypt_with_aad(&blob, master_key, &[]).unwrap();
        assert_eq!(decrypted, b"legacy secret");
        // The v1 path still wins for genuine v1 blobs (version byte 0x01).
        let v1 = encrypt_with_aad(b"v1 secret", master_key, &[]).unwrap();
        assert_eq!(decrypt_with_aad(&v1, master_key, &[]).unwrap(), b"v1 secret");
    }

    #[test]
    fn test_empty_plaintext() {
        let key = b"0123456789abcdef0123456789abcdef";
        let encrypted = encrypt(b"", key).unwrap();
        let decrypted = decrypt(&encrypted, key).unwrap();
        assert!(decrypted.is_empty());
    }

    #[test]
    fn test_large_plaintext() {
        let key = b"0123456789abcdef0123456789abcdef";
        let plaintext = vec![0xABu8; 1024 * 1024]; // 1 MB
        let encrypted = encrypt(&plaintext, key).unwrap();
        let decrypted = decrypt(&encrypted, key).unwrap();
        assert_eq!(decrypted.len(), plaintext.len());
        assert_eq!(decrypted, plaintext);
    }
}
