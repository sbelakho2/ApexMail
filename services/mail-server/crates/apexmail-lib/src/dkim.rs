//! Shared DKIM provisioning primitives.
//!
//! Customer-domain signing uses a unique 2048-bit RSA key pair. The public
//! half is stored as the DNS `p=` value; the private half is encrypted before
//! it is persisted and can be converted to the compact base64 form required by
//! Amazon SES Bring Your Own DKIM (BYODKIM).

use std::sync::Once;

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use rand::rngs::OsRng;
use rand::TryRngCore;
use rsa::pkcs1::DecodeRsaPrivateKey;
use rsa::pkcs8::{DecodePrivateKey, EncodePrivateKey, EncodePublicKey, LineEnding};
use rsa::traits::PublicKeyParts;
use rsa::{RsaPrivateKey, RsaPublicKey};
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

const MIN_DKIM_RSA_BITS: usize = 2048;
const DKIM_PRIVATE_KEY_ENVELOPE_PREFIX: &str = "dkim:v1:";
const DKIM_PRIVATE_KEY_ENVELOPE_VERSION: u8 = 1;
const AES_GCM_NONCE_SIZE: usize = 12;
const AES_GCM_TAG_SIZE: usize = 16;
const AES_256_KEY_SIZE: usize = 32;

/// Environment variable holding the 32-byte, hex-encoded key used to encrypt
/// per-domain DKIM private keys. The API and SMTP worker must use the same
/// value. Unlike general legacy secret storage, new DKIM keys never fall back
/// to plaintext storage when this value is absent.
pub const DKIM_PRIVATE_KEY_ENCRYPTION_KEY_ENV: &str = "DKIM_PRIVATE_KEY_ENCRYPTION_KEY";

/// A generated RSA DKIM key pair.
pub struct DkimKeyPair {
    /// PKCS#8 PEM private key. This is deliberately zeroized when dropped.
    pub private_key_pem: Zeroizing<String>,
    /// Base64-encoded SubjectPublicKeyInfo DER, suitable for the DNS `p=` tag.
    pub public_key: String,
}

impl std::fmt::Debug for DkimKeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DkimKeyPair")
            .field("private_key_pem", &"[REDACTED]")
            .field("public_key", &self.public_key)
            .finish()
    }
}

#[derive(Debug, Error)]
pub enum DkimKeyError {
    #[error("failed to generate DKIM RSA key")]
    KeyGeneration,
    #[error("invalid DKIM RSA private key")]
    InvalidPrivateKey,
    #[error("DKIM RSA private key is below the 2048-bit minimum")]
    WeakPrivateKey,
    #[error("failed to encode DKIM key material")]
    KeyEncoding,
    #[error("{DKIM_PRIVATE_KEY_ENCRYPTION_KEY_ENV} is not configured")]
    EncryptionKeyMissing,
    #[error("{DKIM_PRIVATE_KEY_ENCRYPTION_KEY_ENV} must be 32 bytes of hexadecimal")]
    InvalidEncryptionKey,
    #[error("DKIM private-key envelope is invalid")]
    InvalidEnvelope,
    #[error("DKIM private-key decryption failed")]
    DecryptionFailed,
    #[error("failed to generate a DKIM private-key nonce")]
    NonceGeneration,
}

/// Generate a 2048-bit RSA key pair for a customer domain.
pub fn generate_dkim_keypair() -> Result<DkimKeyPair, DkimKeyError> {
    let mut rng = rsa::rand_core::OsRng;
    let private_key =
        RsaPrivateKey::new(&mut rng, MIN_DKIM_RSA_BITS).map_err(|_| DkimKeyError::KeyGeneration)?;
    let public_key = public_key_base64_from_private_key(&private_key)?;
    let private_key_pem = private_key
        .to_pkcs8_pem(LineEnding::LF)
        .map_err(|_| DkimKeyError::KeyEncoding)?;

    Ok(DkimKeyPair {
        private_key_pem: Zeroizing::new(private_key_pem.to_string()),
        public_key,
    })
}

/// Format the canonical DNS TXT record value for a DKIM public key.
pub fn dkim_txt_record_value(public_key: &str) -> String {
    format!(
        "v=DKIM1; k=rsa; p={}",
        normalize_dkim_public_key(public_key)
    )
}

/// Remove harmless DNS/PEM formatting from a DKIM public key before comparing
/// it with the authoritative, stored base64 value.
pub fn normalize_dkim_public_key(public_key: &str) -> String {
    public_key
        .chars()
        .filter(|character| !character.is_ascii_whitespace() && *character != '"')
        .collect()
}

/// Compare two DKIM public-key representations after normalizing DNS quoting
/// and whitespace.
pub fn dkim_public_keys_match(expected: &str, actual: &str) -> bool {
    !expected.trim().is_empty()
        && normalize_dkim_public_key(expected) == normalize_dkim_public_key(actual)
}

/// Derive the DNS public key value from a PEM-encoded private key.
pub fn public_key_base64_from_private_key_pem(
    private_key_pem: &str,
) -> Result<String, DkimKeyError> {
    let private_key = parse_private_key(private_key_pem)?;
    public_key_base64_from_private_key(&private_key)
}

/// Convert a PEM-encoded RSA private key to the compact PKCS#8 DER base64
/// representation expected by SES BYODKIM APIs.
pub fn ses_private_key_base64_from_pem(private_key_pem: &str) -> Result<String, DkimKeyError> {
    let private_key = parse_private_key(private_key_pem)?;
    let encoded = private_key
        .to_pkcs8_der()
        .map_err(|_| DkimKeyError::KeyEncoding)?;
    Ok(BASE64.encode(encoded.as_bytes()))
}

/// Encrypt a new DKIM private key for database storage.
///
/// The caller supplies stable associated data, normally composed from the
/// tenant and domain IDs, so a ciphertext cannot be copied to another domain
/// row and remain valid.
pub fn encrypt_dkim_private_key(plaintext: &str, aad: &[u8]) -> Result<String, DkimKeyError> {
    if plaintext.trim().is_empty() {
        return Err(DkimKeyError::InvalidPrivateKey);
    }

    let key = Zeroizing::new(load_encryption_key()?);
    let cipher =
        Aes256Gcm::new_from_slice(&*key).map_err(|_| DkimKeyError::InvalidEncryptionKey)?;

    let mut nonce_bytes = [0u8; AES_GCM_NONCE_SIZE];
    OsRng
        .try_fill_bytes(&mut nonce_bytes)
        .map_err(|_| DkimKeyError::NonceGeneration)?;
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(
            nonce,
            Payload {
                msg: plaintext.as_bytes(),
                aad,
            },
        )
        .map_err(|_| DkimKeyError::DecryptionFailed)?;

    let mut envelope = Vec::with_capacity(1 + AES_GCM_NONCE_SIZE + ciphertext.len());
    envelope.push(DKIM_PRIVATE_KEY_ENVELOPE_VERSION);
    envelope.extend_from_slice(&nonce_bytes);
    envelope.extend_from_slice(&ciphertext);

    Ok(format!(
        "{DKIM_PRIVATE_KEY_ENVELOPE_PREFIX}{}",
        BASE64.encode(envelope)
    ))
}

/// Decrypt a stored DKIM private key.
///
/// Legacy plaintext rows remain readable solely to support a controlled
/// migration: provisioning and verification re-encrypt them before accepting
/// new sends. New writes always use [`encrypt_dkim_private_key`].
pub fn decrypt_dkim_private_key(
    stored: &str,
    aad: &[u8],
) -> Result<Zeroizing<String>, DkimKeyError> {
    let Some(encoded) = stored.strip_prefix(DKIM_PRIVATE_KEY_ENVELOPE_PREFIX) else {
        warn_legacy_private_key_once();
        return Ok(Zeroizing::new(stored.to_string()));
    };

    let key = Zeroizing::new(load_encryption_key()?);
    let envelope = BASE64
        .decode(encoded.as_bytes())
        .map_err(|_| DkimKeyError::InvalidEnvelope)?;
    if envelope.len() < 1 + AES_GCM_NONCE_SIZE + AES_GCM_TAG_SIZE
        || envelope.first().copied() != Some(DKIM_PRIVATE_KEY_ENVELOPE_VERSION)
    {
        return Err(DkimKeyError::InvalidEnvelope);
    }

    let (nonce_bytes, ciphertext) = envelope[1..].split_at(AES_GCM_NONCE_SIZE);
    let cipher =
        Aes256Gcm::new_from_slice(&*key).map_err(|_| DkimKeyError::InvalidEncryptionKey)?;
    let plaintext = cipher
        .decrypt(
            Nonce::from_slice(nonce_bytes),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| DkimKeyError::DecryptionFailed)?;

    String::from_utf8(plaintext)
        .map(Zeroizing::new)
        .map_err(|_| DkimKeyError::InvalidEnvelope)
}

/// Whether the persisted value uses the encrypted DKIM envelope format.
pub fn is_encrypted_dkim_private_key(value: &str) -> bool {
    value.starts_with(DKIM_PRIVATE_KEY_ENVELOPE_PREFIX)
}

/// Build the stable associated data used for a domain's encrypted private key.
/// Keeping this format in the shared crate prevents the API writer and worker
/// reader from accepting copied ciphertext under mismatched tenant/domain IDs.
pub fn dkim_private_key_aad(tenant_id: &str, domain_id: &str) -> Vec<u8> {
    format!("apexmail:dkim:v1:tenant={tenant_id};domain={domain_id}").into_bytes()
}

fn parse_private_key(private_key_pem: &str) -> Result<RsaPrivateKey, DkimKeyError> {
    let private_key = RsaPrivateKey::from_pkcs8_pem(private_key_pem)
        .or_else(|_| RsaPrivateKey::from_pkcs1_pem(private_key_pem))
        .map_err(|_| DkimKeyError::InvalidPrivateKey)?;

    if private_key.n().bits() < MIN_DKIM_RSA_BITS {
        return Err(DkimKeyError::WeakPrivateKey);
    }

    Ok(private_key)
}

fn public_key_base64_from_private_key(private_key: &RsaPrivateKey) -> Result<String, DkimKeyError> {
    let public_key = RsaPublicKey::from(private_key);
    let encoded = public_key
        .to_public_key_der()
        .map_err(|_| DkimKeyError::KeyEncoding)?;
    Ok(BASE64.encode(encoded.as_bytes()))
}

fn load_encryption_key() -> Result<[u8; AES_256_KEY_SIZE], DkimKeyError> {
    let encoded = std::env::var(DKIM_PRIVATE_KEY_ENCRYPTION_KEY_ENV)
        .map_err(|_| DkimKeyError::EncryptionKeyMissing)?;
    let mut decoded =
        hex::decode(encoded.trim()).map_err(|_| DkimKeyError::InvalidEncryptionKey)?;
    if decoded.len() != AES_256_KEY_SIZE {
        decoded.zeroize();
        return Err(DkimKeyError::InvalidEncryptionKey);
    }

    let mut key = [0u8; AES_256_KEY_SIZE];
    key.copy_from_slice(&decoded);
    decoded.zeroize();
    Ok(key)
}

fn warn_legacy_private_key_once() {
    static WARN: Once = Once::new();
    WARN.call_once(|| {
        tracing::warn!(
            "legacy plaintext DKIM key encountered; re-verify the domain to migrate it to encrypted storage"
        );
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    static ENV_LOCK: Mutex<()> = Mutex::new(());
    const TEST_KEY: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

    #[test]
    fn generated_pair_has_matching_public_dns_value() {
        let pair = generate_dkim_keypair().unwrap();
        let derived = public_key_base64_from_private_key_pem(&pair.private_key_pem).unwrap();

        assert!(dkim_public_keys_match(&pair.public_key, &derived));
        assert!(dkim_txt_record_value(&pair.public_key).starts_with("v=DKIM1; k=rsa; p="));
    }

    #[test]
    fn ses_private_key_conversion_returns_compact_base64() {
        let pair = generate_dkim_keypair().unwrap();
        let encoded = ses_private_key_base64_from_pem(&pair.private_key_pem).unwrap();

        assert!(!encoded.contains("BEGIN"));
        assert!(BASE64.decode(encoded).is_ok());
    }

    #[test]
    fn encrypted_private_key_round_trips_with_matching_aad() {
        let _lock = ENV_LOCK.lock().unwrap();
        let previous = std::env::var(DKIM_PRIVATE_KEY_ENCRYPTION_KEY_ENV).ok();
        std::env::set_var(DKIM_PRIVATE_KEY_ENCRYPTION_KEY_ENV, TEST_KEY);

        let encrypted = encrypt_dkim_private_key("private key", b"tenant=t1;domain=d1").unwrap();
        assert!(is_encrypted_dkim_private_key(&encrypted));
        assert_eq!(
            decrypt_dkim_private_key(&encrypted, b"tenant=t1;domain=d1")
                .unwrap()
                .as_str(),
            "private key"
        );
        assert!(decrypt_dkim_private_key(&encrypted, b"tenant=t2;domain=d1").is_err());

        match previous {
            Some(value) => std::env::set_var(DKIM_PRIVATE_KEY_ENCRYPTION_KEY_ENV, value),
            None => std::env::remove_var(DKIM_PRIVATE_KEY_ENCRYPTION_KEY_ENV),
        }
    }

    /// E: new DKIM-key writes NEVER fall back to plaintext storage — a
    /// missing key is a typed error. Legacy plaintext rows remain readable
    /// (documented migration path in `decrypt_dkim_private_key`).
    #[test]
    fn encryption_without_key_never_writes_plaintext() {
        let _lock = ENV_LOCK.lock().unwrap();
        let previous = std::env::var(DKIM_PRIVATE_KEY_ENCRYPTION_KEY_ENV).ok();
        std::env::remove_var(DKIM_PRIVATE_KEY_ENCRYPTION_KEY_ENV);

        let err = encrypt_dkim_private_key("private key", b"tenant=t1;domain=d1")
            .expect_err("missing key must fail closed");
        assert!(matches!(err, DkimKeyError::EncryptionKeyMissing));
        // Legacy plaintext rows stay readable for a controlled migration.
        assert_eq!(
            decrypt_dkim_private_key("legacy-plaintext-key", b"tenant=t1;domain=d1")
                .unwrap()
                .as_str(),
            "legacy-plaintext-key"
        );

        match previous {
            Some(value) => std::env::set_var(DKIM_PRIVATE_KEY_ENCRYPTION_KEY_ENV, value),
            None => std::env::remove_var(DKIM_PRIVATE_KEY_ENCRYPTION_KEY_ENV),
        }
    }

    #[test]
    fn normalizing_dns_key_ignores_quotes_and_whitespace() {
        assert!(dkim_public_keys_match("MIIB IjAN", "\"MIIB\" \nIjAN",));
    }

    #[test]
    fn associated_data_is_bound_to_both_tenant_and_domain() {
        assert_ne!(
            dkim_private_key_aad("tenant-a", "domain-a"),
            dkim_private_key_aad("tenant-b", "domain-a")
        );
        assert_ne!(
            dkim_private_key_aad("tenant-a", "domain-a"),
            dkim_private_key_aad("tenant-a", "domain-b")
        );
    }
}
