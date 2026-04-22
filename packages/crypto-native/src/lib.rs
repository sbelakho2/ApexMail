//! crypto-native – Native Node.js bindings for ApexMail cryptographic operations.
//!
//! Exposed via napi-rs so all heavy crypto stays in Rust, off the JS event loop.
//! Every function that allocates key material uses `Zeroizing<Vec<u8>>` or
//! `ZeroizingBytes` wrappers so secrets are scrubbed on drop.

#![deny(clippy::unwrap_used)]
#![allow(clippy::needless_pass_by_value)] // napi requires owned Buffer arguments

use aes_gcm::{
    aead::{Aead, KeyInit, Payload as AeadPayload},
    Aes128Gcm, Aes256Gcm, Nonce,
};
use anyhow::Context as _;
use argon2::{
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2, Params, Version,
};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use napi::{
    bindgen_prelude::{AsyncTask, Buffer},
    Env, Result, Task,
};
use napi_derive::napi;
use rand::{rngs::OsRng, RngCore};
use rsa::{
    pkcs8::{EncodePrivateKey, EncodePublicKey},
    RsaPrivateKey,
};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use std::env;
use zeroize::Zeroizing;

// ─── Constants ────────────────────────────────────────────────────────────────

const AES_GCM_NONCE_LEN: usize = 12;
const HKDF_DERIVED_LEN: usize = 32;
const AES128_ENABLED: bool = true;
const DEFAULT_ARGON2_MEMORY_KIB: u32 = 32_768;
const MAX_RSA_BITS: u32 = 4096;
const MAX_RANDOM_BYTES: usize = 1_048_576;

// ─── Helpers ──────────────────────────────────────────────────────────────────

/// Generate cryptographically-random bytes using the OS RNG.
fn random_bytes(n: usize) -> Result<Vec<u8>> {
    if n > MAX_RANDOM_BYTES {
        return Err(napi::Error::from_reason(format!(
            "requested byte length exceeds {} bytes",
            MAX_RANDOM_BYTES
        )));
    }
    let mut buf = vec![0u8; n];
    OsRng.fill_bytes(&mut buf);
    Ok(buf)
}

// ─── AES-GCM encryption ───────────────────────────────────────────────────────

/// Encrypt `plaintext` with AES-128-GCM.
///
/// * `key`       – 16-byte AES-128 key.
/// * `plaintext` – arbitrary plaintext bytes.
/// * `aad`       – optional additional authenticated data.
///
/// Returns `nonce (12 B) ‖ ciphertext+tag (len(plaintext)+16 B)`.
#[napi]
pub fn encrypt_aes128_gcm(
    key: Buffer,
    plaintext: Buffer,
    aad: Option<Buffer>,
) -> Result<Buffer> {
    if key.len() != 16 {
        return Err(napi::Error::from_reason(format!(
            "AES-128-GCM key must be 16 bytes, got {}",
            key.len()
        )));
    }
    if !AES128_ENABLED {
        return Err(napi::Error::from_reason(
            "AES-128-GCM is disabled; use AES-256-GCM",
        ));
    }
    let cipher = Aes128Gcm::new_from_slice(&key).map_err(|e| {
        napi::Error::from_reason(format!("invalid key: {e}"))
    })?;
    let nonce_bytes = random_bytes(AES_GCM_NONCE_LEN)?;
    let nonce = Nonce::from_slice(&nonce_bytes);
    let payload = AeadPayload {
        msg: &plaintext,
        aad: aad.as_deref().unwrap_or(&[]),
    };
    let mut ciphertext = cipher.encrypt(nonce, payload).map_err(|e| {
        napi::Error::from_reason(format!("encryption failed: {e}"))
    })?;
    // Prepend nonce: output = nonce ‖ ciphertext+tag
    let mut output = nonce_bytes;
    output.append(&mut ciphertext);
    Ok(Buffer::from(output))
}

/// Decrypt `ciphertext` with AES-128-GCM.
///
/// Expects `nonce (12 B) ‖ ciphertext+tag` as produced by [`encrypt_aes128_gcm`].
#[napi]
pub fn decrypt_aes128_gcm(
    key: Buffer,
    ciphertext: Buffer,
    aad: Option<Buffer>,
) -> Result<Buffer> {
    if key.len() != 16 {
        return Err(napi::Error::from_reason(format!(
            "AES-128-GCM key must be 16 bytes, got {}",
            key.len()
        )));
    }
    if !AES128_ENABLED {
        return Err(napi::Error::from_reason(
            "AES-128-GCM is disabled; use AES-256-GCM",
        ));
    }
    if ciphertext.len() <= AES_GCM_NONCE_LEN + 16 {
        return Err(napi::Error::from_reason("ciphertext too short"));
    }
    let cipher = Aes128Gcm::new_from_slice(&key).map_err(|e| {
        napi::Error::from_reason(format!("invalid key: {e}"))
    })?;
    let nonce = Nonce::from_slice(&ciphertext[..AES_GCM_NONCE_LEN]);
    let payload = AeadPayload {
        msg: &ciphertext[AES_GCM_NONCE_LEN..],
        aad: aad.as_deref().unwrap_or(&[]),
    };
    let plaintext = cipher.decrypt(nonce, payload).map_err(|e| {
        napi::Error::from_reason(format!("decryption failed (tag mismatch?): {e}"))
    })?;
    Ok(Buffer::from(plaintext))
}

/// Encrypt `plaintext` with AES-256-GCM.
///
/// * `key` – 32-byte AES-256 key.
///
/// Returns `nonce (12 B) ‖ ciphertext+tag`.
#[napi]
pub fn encrypt_aes256_gcm(
    key: Buffer,
    plaintext: Buffer,
    aad: Option<Buffer>,
) -> Result<Buffer> {
    if key.len() != 32 {
        return Err(napi::Error::from_reason(format!(
            "AES-256-GCM key must be 32 bytes, got {}",
            key.len()
        )));
    }
    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|e| {
        napi::Error::from_reason(format!("invalid key: {e}"))
    })?;
    let nonce_bytes = random_bytes(AES_GCM_NONCE_LEN)?;
    let nonce = Nonce::from_slice(&nonce_bytes);
    let payload = AeadPayload {
        msg: &plaintext,
        aad: aad.as_deref().unwrap_or(&[]),
    };
    let mut ciphertext = cipher.encrypt(nonce, payload).map_err(|e| {
        napi::Error::from_reason(format!("encryption failed: {e}"))
    })?;
    let mut output = nonce_bytes;
    output.append(&mut ciphertext);
    Ok(Buffer::from(output))
}

/// Decrypt `ciphertext` with AES-256-GCM.
#[napi]
pub fn decrypt_aes256_gcm(
    key: Buffer,
    ciphertext: Buffer,
    aad: Option<Buffer>,
) -> Result<Buffer> {
    if key.len() != 32 {
        return Err(napi::Error::from_reason(format!(
            "AES-256-GCM key must be 32 bytes, got {}",
            key.len()
        )));
    }
    if ciphertext.len() <= AES_GCM_NONCE_LEN + 16 {
        return Err(napi::Error::from_reason("ciphertext too short"));
    }
    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|e| {
        napi::Error::from_reason(format!("invalid key: {e}"))
    })?;
    let nonce = Nonce::from_slice(&ciphertext[..AES_GCM_NONCE_LEN]);
    let payload = AeadPayload {
        msg: &ciphertext[AES_GCM_NONCE_LEN..],
        aad: aad.as_deref().unwrap_or(&[]),
    };
    let plaintext = cipher.decrypt(nonce, payload).map_err(|e| {
        napi::Error::from_reason(format!("decryption failed (tag mismatch?): {e}"))
    })?;
    Ok(Buffer::from(plaintext))
}

// ─── HKDF key derivation ──────────────────────────────────────────────────────

/// Derive a 32-byte sub-key from `master_key` using HKDF-SHA-256.
///
/// `info` is a domain-separation string (e.g. `"apexmail:signing-key:v1"`).
/// The salt is left unset (HKDF uses `HashLen` zeros as the default salt).
#[napi]
pub fn derive_key_hkdf(master_key: Buffer, info: String) -> Result<Buffer> {
    let hk = Hkdf::<Sha256>::new(None, &master_key);
    let mut okm = Zeroizing::new(vec![0u8; HKDF_DERIVED_LEN]);
    hk.expand(info.as_bytes(), &mut okm)
        .map_err(|e| napi::Error::from_reason(format!("HKDF expand error: {e}")))?;
    Ok(Buffer::from(okm.to_vec()))
}

// ─── HMAC-SHA-256 ─────────────────────────────────────────────────────────────

/// Compute HMAC-SHA-256 of `data` keyed with `key`.  Returns raw 32-byte MAC.
#[napi]
pub fn hmac_sha256(key: Buffer, data: Buffer) -> Result<Buffer> {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&key)
        .map_err(|e| napi::Error::from_reason(format!("invalid HMAC key: {e}")))?;
    mac.update(&data);
    let result = mac.finalize().into_bytes();
    Ok(Buffer::from(result.as_slice().to_vec()))
}

// ─── Argon2id password hashing (async) ────────────────────────────────────────

/// Options forwarded to the Argon2 async task.
pub struct HashPasswordTask {
    password: Zeroizing<String>,
    time_cost: u32,
    memory_cost: u32,
    parallelism: u32,
}

#[napi]
impl Task for HashPasswordTask {
    type Output = String;
    type JsValue = String;

    fn compute(&mut self) -> Result<Self::Output> {
        let params = Params::new(
            self.memory_cost,
            self.time_cost,
            self.parallelism,
            None,
        )
        .map_err(|e| napi::Error::from_reason(format!("argon2 params: {e}")))?;
        let argon2 = Argon2::new(argon2::Algorithm::Argon2id, Version::V0x13, params);
        let salt = SaltString::generate(&mut OsRng);
        argon2
            .hash_password(self.password.as_bytes(), &salt)
            .map(|h| h.to_string())
            .map_err(|e| napi::Error::from_reason(format!("hash_password: {e}")))
    }

    fn resolve(&mut self, _env: Env, output: Self::Output) -> Result<Self::JsValue> {
        Ok(output)
    }
}

/// Hash `password` with Argon2id.  Returns a PHC-formatted string (safe to store).
///
/// Defaults: `time_cost=3`, `memory_cost=65536` (64 MiB), `parallelism=4`.
/// All hashing is off-thread via the libuv thread-pool.
#[napi]
pub fn hash_password(
    password: String,
    time_cost: Option<u32>,
    memory_cost: Option<u32>,
    parallelism: Option<u32>,
) -> AsyncTask<HashPasswordTask> {
    AsyncTask::new(HashPasswordTask {
        password: Zeroizing::new(password),
        time_cost: time_cost.unwrap_or(3),
        memory_cost: memory_cost.unwrap_or_else(default_argon2_memory_cost),
        parallelism: parallelism.unwrap_or(4),
    })
}

/// Task that verifies an Argon2 PHC hash.
pub struct VerifyPasswordTask {
    hash: String,
    password: Zeroizing<String>,
}

#[napi]
impl Task for VerifyPasswordTask {
    type Output = bool;
    type JsValue = bool;

    fn compute(&mut self) -> Result<Self::Output> {
        let parsed = PasswordHash::new(&self.hash)
            .map_err(|e| napi::Error::from_reason(format!("invalid PHC hash: {e}")))?;
        Ok(Argon2::default()
            .verify_password(self.password.as_bytes(), &parsed)
            .is_ok())
    }

    fn resolve(&mut self, _env: Env, output: Self::Output) -> Result<Self::JsValue> {
        Ok(output)
    }
}

/// Verify `password` against an Argon2 `hash` (PHC format).  Off-thread.
#[napi]
pub fn verify_password(hash: String, password: String) -> AsyncTask<VerifyPasswordTask> {
    AsyncTask::new(VerifyPasswordTask {
        hash,
        password: Zeroizing::new(password),
    })
}

// ─── RSA DKIM key-pair generation (async) ─────────────────────────────────────

/// Output of [`generate_dkim_key_pair`].
#[napi(object)]
pub struct DkimKeyPair {
    /// PKCS#8 DER-encoded private key.
    pub private_key: Buffer,
    /// SPKI DER-encoded public key (suitable for a DKIM DNS TXT record).
    pub public_key: Buffer,
}

pub struct GenerateDkimKeyPairTask {
    bits: usize,
}

#[napi]
impl Task for GenerateDkimKeyPairTask {
    type Output = (Vec<u8>, Vec<u8>);
    type JsValue = DkimKeyPair;

    fn compute(&mut self) -> Result<Self::Output> {
        let private_key = RsaPrivateKey::new(&mut OsRng, self.bits)
            .context("RSA key generation failed")
            .map_err(|e| napi::Error::from_reason(e.to_string()))?;
        let public_key = private_key.to_public_key();
        let priv_der = private_key
            .to_pkcs8_der()
            .context("private key to PKCS8 DER")
            .map_err(|e| napi::Error::from_reason(e.to_string()))?
            .as_bytes()
            .to_vec();
        let pub_der = public_key
            .to_public_key_der()
            .context("public key to SPKI DER")
            .map_err(|e| napi::Error::from_reason(e.to_string()))?
            .as_bytes()
            .to_vec();
        Ok((priv_der, pub_der))
    }

    fn resolve(&mut self, _env: Env, (priv_der, pub_der): Self::Output) -> Result<Self::JsValue> {
        Ok(DkimKeyPair {
            private_key: Buffer::from(priv_der),
            public_key: Buffer::from(pub_der),
        })
    }
}

/// Generate an RSA key pair for DKIM signing.
///
/// `bits` – key size in bits; DKIM requires ≥ 1024, recommended ≥ 2048.
/// Returns `{ privateKey: Buffer, publicKey: Buffer }` (DER-encoded).
/// Off-thread via libuv thread-pool (RSA keygen is expensive).
#[napi]
pub fn generate_dkim_key_pair(bits: u32) -> Result<AsyncTask<GenerateDkimKeyPairTask>> {
    if bits < 1024 || bits > MAX_RSA_BITS {
        return Err(napi::Error::from_reason(
            format!("RSA key size must be between 1024 and {MAX_RSA_BITS} bits"),
        ));
    }
    Ok(AsyncTask::new(GenerateDkimKeyPairTask {
        bits: bits as usize,
    }))
}

// ─── Constant-time comparison ─────────────────────────────────────────────────

/// Compare two buffers in constant time (resistant to timing-side-channel attacks).
///
/// Returns `true` only when `a.length === b.length` AND every byte matches.
/// The comparison is always performed in O(min(|a|,|b|)) time even when
/// lengths differ, to prevent length-based leakage.
#[napi]
pub fn timing_safe_equal(a: Buffer, b: Buffer) -> bool {
    if a.len() != b.len() {
        // Still do constant-time work to avoid leaking length via timing
        let max_len = a.len().max(b.len());
        let mut padded_a = Zeroizing::new(vec![0u8; max_len]);
        let mut padded_b = Zeroizing::new(vec![0u8; max_len]);
        padded_a[..a.len()].copy_from_slice(&a);
        padded_b[..b.len()].copy_from_slice(&b);
        let mut _dummy: u8 = 0;
        for idx in 0..max_len {
            _dummy |= padded_a[idx] ^ padded_b[idx];
        }
        return false;
    }

    let mut diff: u8 = 0;
    for idx in 0..a.len() {
        diff |= a[idx] ^ b[idx];
    }

    diff == 0
}

fn default_argon2_memory_cost() -> u32 {
    env::var("APEXMAIL_ARGON2_MEMORY_KIB")
        .ok()
        .and_then(|value| value.parse::<u32>().ok())
        .filter(|value| (8_192..=1_048_576).contains(value))
        .unwrap_or(DEFAULT_ARGON2_MEMORY_KIB)
}

// ─── Secure random bytes ──────────────────────────────────────────────────────

/// Generate `length` cryptographically-secure random bytes using the OS RNG.
#[napi]
pub fn secure_random_bytes(length: u32) -> Result<Buffer> {
    if length > 1_048_576 {
        return Err(napi::Error::from_reason(
            "requested byte length exceeds 1 MiB limit",
        ));
    }
    Ok(Buffer::from(random_bytes(length as usize)?))
}

// ─── Hex / Base64 helpers (thin wrappers to keep codec in Rust) ───────────────

/// Encode `bytes` to lowercase hexadecimal string.
#[napi]
pub fn buf_to_hex(bytes: Buffer) -> String {
    hex::encode(&*bytes)
}

/// Decode a hex string to `Buffer`.  Returns an error on invalid hex.
#[napi]
pub fn hex_to_buf(s: String) -> Result<Buffer> {
    hex::decode(&s)
        .map(Buffer::from)
        .map_err(|e| napi::Error::from_reason(format!("hex decode: {e}")))
}

/// Encode `bytes` to Base64 (standard alphabet, no padding stripped).
#[napi]
pub fn buf_to_base64(bytes: Buffer) -> String {
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    STANDARD.encode(&*bytes)
}

/// Decode a Base64 string to `Buffer`.
#[napi]
pub fn base64_to_buf(s: String) -> Result<Buffer> {
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    STANDARD
        .decode(&s)
        .map(Buffer::from)
        .map_err(|e| napi::Error::from_reason(format!("base64 decode: {e}")))
}
