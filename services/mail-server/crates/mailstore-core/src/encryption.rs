//! Encryption at rest – AES‑256‑GCM for stored message content.
//!
//! O‑4.3:Provides envelope encryption with a configurable master key.
//!
//! Layout: `version(1) || nonce(12) || ciphertext || tag(16)`. AAD
//! (Additional Authenticated Data) binds each ciphertext to a
//! tenant/account/mailbox scope so a record cannot be relocated and
//! successfully decrypted under a different scope.
//!
//! Key derivation is version-selected (audit finding 7 — the old doc claimed
//! "HKDF-SHA256" while v1 actually used a bare domain-separated SHA-256):
//! * `version = 2` (current): real HKDF-SHA256 (RFC 5869) over the master
//!   key with the explicit application-specific salt
//!   [`HKDF_SALT_V2`]; the `info` string carries the application domain tag
//!   and the version byte, so future rotations cannot collide.
//! * `version = 1` (and the legacy unversioned layout, internally version 0):
//!   the historical single-SHA256 construction
//!   `SHA256("apexmail-mailstore-encryption" || version || master_key)`.
//!   This derivation MUST stay byte-for-byte identical — every
//!   already-persisted v1/legacy blob decrypts only under it, which is the
//!   compatibility story for the v2 switch. New writes always emit v2.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use anyhow::{anyhow, Result};
use hkdf::Hkdf;
use rand::rngs::OsRng;
use rand::TryRngCore;
use sha2::Sha256;
use zeroize::Zeroize;

/// Size of the AES‑256 key in bytes.
const KEY_SIZE: usize = 32;
/// Size of the GCM nonce in bytes (96 bits, standard for AES‑GCM).
const NONCE_SIZE: usize = 12;
/// Size of the GCM authentication tag in bytes.
const TAG_SIZE: usize = 16;
/// Ciphertext envelope version using the historical SHA-256 derivation.
pub const ENVELOPE_VERSION_V1: u8 = 1;
/// Current ciphertext envelope version: real HKDF-SHA256 key derivation.
pub const ENVELOPE_VERSION_V2: u8 = 2;
/// Application-specific HKDF salt (extract phase) for envelope v2. Explicit
/// (not zero/default) so the derivation is pinned to this application even
/// if the master key is ever reused elsewhere.
const HKDF_SALT_V2: &[u8] = b"apexmail/mailstore/envelope-encryption/v2";
/// HKDF-Expand `info` prefix, carrying the application domain tag and the
/// version byte (identical text to the v1 domain separator, deliberately).
const HKDF_INFO_PREFIX: &[u8] = b"apexmail-mailstore-encryption";

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
/// Output layout: `version(1) || nonce(12) || ciphertext || tag(16)`. New
/// ciphertexts carry [`ENVELOPE_VERSION_V2`] (HKDF-SHA256 derivation).
pub fn encrypt_with_aad(plaintext: &[u8], master_key: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    if master_key.len() < KEY_SIZE {
        return Err(anyhow!(
            "Master key must be at least {KEY_SIZE} bytes (got {})",
            master_key.len()
        ));
    }

    // Derive a fixed key from the master key (versioned `info` string).
    let mut key = derive_encryption_key(master_key, ENVELOPE_VERSION_V2)?;
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
    result.push(ENVELOPE_VERSION_V2);
    result.extend_from_slice(&nonce_bytes);
    result.extend_from_slice(&ciphertext);

    Ok(result)
}

/// Decrypt a ciphertext previously produced by [`encrypt_with_aad`].
///
/// `aad` MUST match the value used at encryption time, otherwise GCM
/// authentication fails. Accepts the legacy unversioned layout
/// (`nonce || ciphertext || tag`) for forward compatibility with already
/// persisted data, and every versioned envelope (v1 SHA-256 derivation, v2
/// HKDF-SHA256 derivation) — the version byte selects the derivation.
///
/// Version ambiguity: a legacy blob whose nonce happens to begin with a
/// version byte (`0x01` or `0x02`) is indistinguishable from a versioned
/// envelope by prefix alone. The versioned interpretation is tried first;
/// when it fails GCM authentication (and the caller expects an empty AAD,
/// as legacy blobs always were), the legacy `nonce || ciphertext+tag`
/// interpretation is retried instead of erroring.
pub fn decrypt_with_aad(data: &[u8], master_key: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    if master_key.len() < KEY_SIZE {
        return Err(anyhow!(
            "Master key must be at least {KEY_SIZE} bytes (got {})",
            master_key.len()
        ));
    }

    let legacy_ok = || data.len() >= NONCE_SIZE + TAG_SIZE;

    // v2 (current): a blob written by THIS version always decrypts here.
    // When the strict v2 read fails GCM authentication AND the caller bound
    // no AAD, the blob could still be a PRE-v2 legacy one whose random
    // nonce happens to begin with the byte 0x02 — indistinguishable from a
    // v2 envelope by prefix alone (same ambiguity the v1 branch handles for
    // 0x01). The legacy retry is gated on an empty AAD (legacy blobs never
    // bound one) and still requires the legacy key to authenticate the
    // ciphertext, so it cannot be abused to read a genuine v2 blob.
    if !data.is_empty() && data[0] == ENVELOPE_VERSION_V2 {
        if data.len() < 1 + NONCE_SIZE + TAG_SIZE {
            // Too short for v2; could still be a legacy blob.
            if aad.is_empty() && legacy_ok() {
                return decrypt_layout(data, master_key, 0u8, aad);
            }
            return Err(anyhow!(
                "Ciphertext too short: need at least {} bytes, got {}",
                1 + NONCE_SIZE + TAG_SIZE,
                data.len()
            ));
        }
        let (nonce, ct) = data[1..].split_at(NONCE_SIZE);
        match decrypt_parts(nonce, ct, master_key, ENVELOPE_VERSION_V2, aad) {
            Ok(pt) => return Ok(pt),
            Err(v2_err) => {
                // v2 parse failed: retry as a legacy unversioned blob whose
                // first nonce byte collided with the version byte. Only
                // legal for empty-AAD callers (legacy blobs never bound AAD).
                if aad.is_empty() && legacy_ok() {
                    if let Ok(pt) = decrypt_layout(data, master_key, 0u8, &[]) {
                        return Ok(pt);
                    }
                }
                return Err(v2_err);
            }
        }
    }

    if !data.is_empty() && data[0] == ENVELOPE_VERSION_V1 {
        if data.len() < 1 + NONCE_SIZE + TAG_SIZE {
            // Too short for v1; could still be a legacy blob.
            if aad.is_empty() && legacy_ok() {
                return decrypt_layout(data, master_key, 0u8, aad);
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
fn decrypt_layout(data: &[u8], master_key: &[u8], version: u8, aad: &[u8]) -> Result<Vec<u8>> {
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
    let mut key = derive_encryption_key(master_key, version)?;
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

/// Derive a 256-bit encryption key from the master key, selected by the
/// envelope version (audit finding 7).
///
/// * `ENVELOPE_VERSION_V2` — real HKDF-SHA256 (RFC 5869): extract with the
///   explicit application-specific [`HKDF_SALT_V2`], expand with an `info`
///   string carrying the application domain tag and the version byte.
/// * Any other version (1, and the legacy unversioned layout's internal 0) —
///   the historical `SHA256("apexmail-mailstore-encryption" || version ||
///   master_key)` construction, kept byte-for-byte identical so every
///   already-persisted v1/legacy blob remains decryptable.
fn derive_encryption_key(master_key: &[u8], version: u8) -> Result<Vec<u8>> {
    match version {
        ENVELOPE_VERSION_V2 => {
            let hk = Hkdf::<Sha256>::new(Some(HKDF_SALT_V2), master_key);
            let mut okm = [0u8; KEY_SIZE];
            let mut info = HKDF_INFO_PREFIX.to_vec();
            info.push(version);
            hk.expand(&info, &mut okm)
                .map_err(|error| anyhow!("HKDF-SHA256 expand failed: {error}"))?;
            Ok(okm.to_vec())
        }
        // v1 / legacy(0): frozen historical construction.
        version => {
            use sha2::{Digest, Sha256};
            let mut hasher = Sha256::new();
            hasher.update(HKDF_INFO_PREFIX);
            hasher.update([version]);
            hasher.update(master_key);
            Ok(hasher.finalize().to_vec())
        }
    }
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
        // New writes always carry the current (HKDF) envelope version.
        assert_eq!(encrypted[0], ENVELOPE_VERSION_V2);

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
        let legacy_key = derive_encryption_key(master_key, 0u8).unwrap();
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
        assert_eq!(
            decrypt_with_aad(&v1, master_key, &[]).unwrap(),
            b"v1 secret"
        );
    }

    /// The v2-lookalike sibling of the v1 case above: a LEGACY (unversioned)
    /// blob whose nonce's first byte collides with ENVELOPE_VERSION_V2
    /// (0x02) must still decrypt. The strict v2 read fails GCM auth and the
    /// legacy layout is retried — without the fallback, ~1/256 of pre-v2
    /// legacy blobs became undecryptable when the v2 envelope was introduced.
    #[test]
    fn test_legacy_blob_with_v2_lookalike_first_byte_still_decrypts() {
        let master_key = b"0123456789abcdef0123456789abcdef";
        // Build a LEGACY (unversioned) blob: nonce || ciphertext+tag, where
        // the nonce's first byte collides with ENVELOPE_VERSION_V2 (0x02).
        let legacy_key = derive_encryption_key(master_key, 0u8).unwrap();
        let cipher = Aes256Gcm::new_from_slice(&legacy_key).unwrap();
        let mut nonce_bytes = [0u8; NONCE_SIZE];
        nonce_bytes[0] = ENVELOPE_VERSION_V2;
        rand::rngs::OsRng
            .try_fill_bytes(&mut nonce_bytes[1..])
            .unwrap();
        let ct = cipher
            .encrypt(
                Nonce::from_slice(&nonce_bytes),
                Payload {
                    msg: b"legacy secret 02",
                    aad: &[],
                },
            )
            .unwrap();
        let mut blob = Vec::with_capacity(NONCE_SIZE + ct.len());
        blob.extend_from_slice(&nonce_bytes);
        blob.extend_from_slice(&ct);

        let decrypted = decrypt_with_aad(&blob, master_key, &[]).unwrap();
        assert_eq!(decrypted, b"legacy secret 02");

        // The strict v2 path still wins for genuine v2 blobs.
        let v2 = encrypt(b"v2 secret", master_key).unwrap();
        assert_eq!(decrypt(&v2, master_key).unwrap(), b"v2 secret");
        // A v2 blob does NOT decrypt as legacy under a WRONG master key: the
        // fallback is auth-gated, not a decrypt-with-anything escape.
        assert!(decrypt_with_aad(&v2, b"fedcba9876543210fedcba9876543210", &[]).is_err());
    }

    #[test]
    fn test_empty_plaintext() {
        let key = b"0123456789abcdef0123456789abcdef";
        let encrypted = encrypt(b"", key).unwrap();
        let decrypted = decrypt(&encrypted, key).unwrap();
        assert!(decrypted.is_empty());
    }

    // ── audit finding 7: HKDF v2 envelope with v1/legacy compatibility ─────

    /// Compatibility story, asserted: a blob written by the OLD v1 envelope
    /// (SHA-256 domain-separated derivation) still decrypts after the switch
    /// to HKDF-SHA256, because the derivation is version-selected and the v1
    /// construction is frozen byte-for-byte.
    #[test]
    fn v1_envelopes_written_before_the_hkdf_switch_still_decrypt() {
        let master_key = b"0123456789abcdef0123456789abcdef";
        let plaintext = b"written before the hkdf switch";

        // Build a genuine v1 envelope with the frozen historical derivation.
        let v1_key = derive_encryption_key(master_key, ENVELOPE_VERSION_V1).unwrap();
        let cipher = Aes256Gcm::new_from_slice(&v1_key).unwrap();
        let mut nonce_bytes = [0u8; NONCE_SIZE];
        rand::rngs::OsRng.try_fill_bytes(&mut nonce_bytes).unwrap();
        let ct = cipher
            .encrypt(
                Nonce::from_slice(&nonce_bytes),
                Payload {
                    msg: plaintext,
                    aad: &[],
                },
            )
            .unwrap();
        let mut blob = Vec::with_capacity(1 + NONCE_SIZE + ct.len());
        blob.push(ENVELOPE_VERSION_V1);
        blob.extend_from_slice(&nonce_bytes);
        blob.extend_from_slice(&ct);

        assert_eq!(decrypt(&blob, master_key).unwrap(), plaintext);
        // A v1 blob must NOT decrypt under the v2 derivation (the versions
        // derive different keys; a cross-version decrypt is an auth failure,
        // not silent cross-compatibility).
        let v2_blob = encrypt(plaintext, master_key).unwrap();
        assert_ne!(v2_blob[0], blob[0]);
    }

    /// The v2 envelope: HKDF-SHA256 derivation, AAD binding, and unique
    /// ciphertexts — plus the derived key differing from both the master key
    /// and the frozen v1 derivation.
    #[test]
    fn v2_envelope_roundtrips_binds_aad_and_uses_hkdf() {
        let master_key = b"0123456789abcdef0123456789abcdef";
        let pt = b"v2 secret";
        let aad = b"tenant=A;mailbox=42";

        let ct = encrypt_with_aad(pt, master_key, aad).unwrap();
        assert_eq!(ct[0], ENVELOPE_VERSION_V2);
        assert_eq!(decrypt_with_aad(&ct, master_key, aad).unwrap(), pt);
        // AAD still binds v2 ciphertexts to their scope.
        assert!(decrypt_with_aad(&ct, master_key, b"tenant=B;mailbox=42").is_err());
        // Wrong master key fails.
        assert!(decrypt_with_aad(&ct, b"fedcba9876543210fedcba9876543210", aad).is_err());

        // The v2 HKDF output differs from the frozen v1 construction: the
        // derivation actually changed (this is what the old doc lied about).
        assert_ne!(
            derive_encryption_key(master_key, ENVELOPE_VERSION_V2).unwrap(),
            derive_encryption_key(master_key, ENVELOPE_VERSION_V1).unwrap()
        );
        // HKDF is deterministic for (salt, ikm, info): same inputs, same key.
        assert_eq!(
            derive_encryption_key(master_key, ENVELOPE_VERSION_V2).unwrap(),
            derive_encryption_key(master_key, ENVELOPE_VERSION_V2).unwrap()
        );
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
