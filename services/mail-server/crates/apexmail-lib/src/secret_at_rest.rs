//! Field-level encryption for sensitive secrets stored in the database
//! (mfa_secret, OAuth tokens, …).
//!
//! # Format
//!
//! On-disk encodings:
//! - Encrypted: `enc:v1:<base64(version || nonce || ciphertext+tag)>`.
//! - Dev fallback plaintext: `plain:v1:<plaintext>` — a machine-readable
//!   marker distinguishing deliberately-unencrypted values from legacy rows.
//! - Legacy plaintext: no prefix at all (see Read compatibility below).
//!
//! The leading sentinels allow callers to detect whether a stored value is
//! already encrypted, supporting forward migration from plaintext.
//!
//! # Key management
//!
//! The encryption key is read from `MFA_SECRET_ENCRYPTION_KEY` (32-byte
//! hex). It is cached for the process lifetime so we only pay the parse cost
//! once.
//!
//! Resolution order (E — fail-closed hardening):
//! 1. `MFA_SECRET_ENCRYPTION_KEY` set → always used; new writes encrypted.
//! 2. Production with the key unset → **error** (`KeyMissing`). Secrets are
//!    never silently stored as plaintext in production.
//! 3. Development with the key unset → an ephemeral 32-byte key is generated
//!    and persisted to a cache file under the data dir (env override
//!    `MFA_SECRET_ENCRYPTION_KEY_FILE`) so restarts can still decrypt.
//! 4. Development, cache file not writable → plaintext with the `plain:v1:`
//!    marker and a loud per-process warning.
//!
//! Reads are always compatible: `decrypt_at_rest` accepts `enc:v1:`
//! envelopes, `plain:v1:` marked values, and legacy no-prefix plaintext.
//! Use [`migrate_at_rest`] on read paths to re-encrypt legacy rows when the
//! writer has a key available.

use std::sync::{Mutex, Once};

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use rand::rngs::OsRng;
use rand::TryRngCore;
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

const ENVELOPE_VERSION_V1: u8 = 1;
const NONCE_SIZE: usize = 12;
const TAG_SIZE: usize = 16;
const KEY_SIZE: usize = 32;
const PREFIX: &str = "enc:v1:";
/// E: marker for values deliberately stored as plaintext by the development
/// fallback (no persistable key). Lets decrypt distinguish "known plaintext"
/// from encrypted envelopes without attempting a decryption.
const PLAIN_MARKER: &str = "plain:v1:";
const ENV_VAR: &str = "MFA_SECRET_ENCRYPTION_KEY";
/// E: optional explicit path for the development ephemeral-key cache file.
const KEY_FILE_ENV: &str = "MFA_SECRET_ENCRYPTION_KEY_FILE";
/// Cache file name (under the first writable data dir).
const KEY_FILE_NAME: &str = "apexmail-secret-at-rest.key";

#[derive(Debug, Error)]
pub enum SecretEncryptionError {
    #[error("encryption key not configured")]
    KeyMissing,
    #[error("{ENV_VAR} is required in production — refusing to store secrets as plaintext")]
    KeyMissingProduction,
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

/// How the process resolved its at-rest key material.
#[derive(Debug, Clone, PartialEq, Eq)]
enum KeySource {
    /// Explicit env configuration (production-supported).
    Env,
    /// Development ephemeral key persisted to a cache file.
    EphemeralPersisted,
    /// Development ephemeral key in memory only (values written as marked
    /// plaintext instead, since restarts could not decrypt them).
    EphemeralMemory,
    /// No key material at all: production refuses writes; dev writes marked
    /// plaintext.
    None,
}

struct KeyState {
    key: Option<[u8; KEY_SIZE]>,
    source: KeySource,
}

fn key_cell() -> &'static Mutex<KeyState> {
    static CELL: Mutex<KeyState> = Mutex::new(KeyState {
        key: None,
        source: KeySource::None,
    });
    &CELL
}

fn warn_once_dev_plaintext() {
    static WARN: Once = Once::new();
    WARN.call_once(|| {
        tracing::warn!(
            env_var = ENV_VAR,
            "{ENV_VAR} is not set and no cache file could be written — secrets at rest are \
             stored as MARKED PLAINTEXT ({PLAIN_MARKER}...) for this process only. Configure a \
             32-byte hex key to enable encryption."
        );
    });
}

fn is_production_env() -> bool {
    for var in ["NODE_ENV", "ENVIRONMENT", "APP_ENV"] {
        let value = std::env::var(var).unwrap_or_default();
        if value.eq_ignore_ascii_case("production") || value.eq_ignore_ascii_case("prod") {
            return true;
        }
    }
    false
}

/// Candidate directories for the development ephemeral-key cache file, in
/// order of preference.
fn key_file_candidates() -> Vec<std::path::PathBuf> {
    let mut dirs: Vec<std::path::PathBuf> = Vec::new();
    if let Ok(explicit) = std::env::var(KEY_FILE_ENV) {
        dirs.push(explicit.into());
        return dirs;
    }
    for var in ["APEXMAIL_DATA_DIR", "DATA_DIR", "XDG_CACHE_HOME"] {
        if let Ok(dir) = std::env::var(var) {
            if !dir.trim().is_empty() {
                dirs.push(std::path::Path::new(&dir).join("apexmail"));
            }
        }
    }
    if let Ok(home) = std::env::var("HOME") {
        dirs.push(
            std::path::Path::new(&home)
                .join(".cache")
                .join("apexmail"),
        );
    }
    dirs.push(std::path::PathBuf::from("/tmp/apexmail"));
    dirs.into_iter()
        .map(|dir| dir.join(KEY_FILE_NAME))
        .collect()
}

fn write_private_file(path: &std::path::Path, bytes: &[u8]) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    use std::io::Write;
    file.write_all(bytes)
}

/// Resolve (and cache) the process key material per the module docs.
fn resolve_key_state() -> KeyState {
    // 1. Explicit env configuration.
    match std::env::var(ENV_VAR) {
        Ok(hex_str) if !hex_str.trim().is_empty() => {
            let bytes = hex::decode(hex_str.trim());
            match bytes {
                Ok(bytes) if bytes.len() == KEY_SIZE => {
                    let mut key = [0u8; KEY_SIZE];
                    key.copy_from_slice(&bytes);
                    return KeyState {
                        key: Some(key),
                        source: KeySource::Env,
                    };
                }
                Ok(_) => {
                    tracing::error!(
                        env_var = ENV_VAR,
                        "{ENV_VAR} must decode to 32 bytes — encryption disabled until fixed"
                    );
                }
                Err(e) => {
                    tracing::error!(error = %e, env_var = ENV_VAR, "invalid hex key");
                }
            }
        }
        _ => {}
    }

    // 2. Production requires explicit configuration.
    if is_production_env() {
        return KeyState {
            key: None,
            source: KeySource::None,
        };
    }

    // 3/4. Development: reuse the persisted ephemeral key, or create one.
    for path in key_file_candidates() {
        if let Ok(existing) = std::fs::read_to_string(&path) {
            let trimmed = existing.trim();
            if let Ok(bytes) = hex::decode(trimmed) {
                if bytes.len() == KEY_SIZE {
                    let mut key = [0u8; KEY_SIZE];
                    key.copy_from_slice(&bytes);
                    tracing::warn!(
                        cache_file = %path.display(),
                        "using a DEVELOPMENT ephemeral at-rest key from the cache file — set \
                         {ENV_VAR} for stable production encryption"
                    );
                    return KeyState {
                        key: Some(key),
                        source: KeySource::EphemeralPersisted,
                    };
                }
            }
        }
        // Not found — try to create it.
        let mut key = [0u8; KEY_SIZE];
        if OsRng.try_fill_bytes(&mut key).is_ok() {
            let hex_key = hex::encode(key);
            if write_private_file(&path, hex_key.as_bytes()).is_ok() {
                tracing::warn!(
                    cache_file = %path.display(),
                    "generated a DEVELOPMENT ephemeral at-rest key (persisted) — set {ENV_VAR} \
                     for stable production encryption"
                );
                return KeyState {
                    key: Some(key),
                    source: KeySource::EphemeralPersisted,
                };
            }
        }
        key.zeroize();
    }

    warn_once_dev_plaintext();
    KeyState {
        key: None,
        source: KeySource::EphemeralMemory,
    }
}

/// Snapshot the resolved key (cloned bytes are zeroized on drop).
fn load_key() -> Result<Option<Zeroizing<[u8; KEY_SIZE]>>, SecretEncryptionError> {
    let mut state = key_cell().lock().unwrap_or_else(|e| e.into_inner());
    if state.source == KeySource::None {
        *state = resolve_key_state();
    }
    if state.source == KeySource::None && is_production_env() {
        // Re-check production on every call: a key that was missing at first
        // resolution must fail closed in production.
        return Err(SecretEncryptionError::KeyMissingProduction);
    }
    Ok(state.key.map(|k| Zeroizing::new(k)))
}

/// True when at-rest encryption is active for new writes.
pub fn encryption_available() -> bool {
    matches!(load_key(), Ok(Some(_)))
}

/// Encrypt `plaintext` for at-rest storage.
///
/// Returns `enc:v1:<base64>` when an encryption key is available. In
/// production a missing key is a typed error (never silent plaintext). In
/// development without a persistable key the plaintext is returned wrapped
/// in the `plain:v1:` marker with a per-process warning. `aad` is bound into
/// the GCM tag — pass a stable scope identifier such as
/// `format!("user={user_id}")` so a ciphertext cannot be relocated.
pub fn encrypt_at_rest(plaintext: &str, aad: &[u8]) -> Result<String, SecretEncryptionError> {
    let key = match load_key()? {
        Some(key) => key,
        None => {
            // Development-only fallback (production errors in load_key).
            warn_once_dev_plaintext();
            return Ok(format!("{PLAIN_MARKER}{plaintext}"));
        }
    };

    let cipher = Aes256Gcm::new_from_slice(key.as_slice())
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

    Ok(format!("{PREFIX}{}", B64.encode(envelope)))
}

/// Decrypt `stored` back to plaintext.
///
/// Transparently accepts the `enc:v1:<base64>` envelope, `plain:v1:` marked
/// values, and legacy unmarked plaintext (so a database can be migrated
/// row-by-row). Pass the same `aad` used at encryption time. A malformed or
/// tampered envelope fails closed with a typed error — never silently
/// returns garbage.
pub fn decrypt_at_rest(stored: &str, aad: &[u8]) -> Result<String, SecretEncryptionError> {
    if let Some(plaintext) = stored.strip_prefix(PLAIN_MARKER) {
        return Ok(plaintext.to_string());
    }
    let Some(b64) = stored.strip_prefix(PREFIX) else {
        // Legacy unmarked plaintext: pass through.
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

    let cipher = Aes256Gcm::new_from_slice(key.as_slice())
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

    String::from_utf8(plaintext)
        .map_err(|_| SecretEncryptionError::InvalidEnvelope("plaintext is not UTF-8"))
}

/// E: read-migration helper. Given a stored value, returns `Some(encrypted)`
/// when the value is plaintext (legacy unmarked or `plain:v1:` marked) AND
/// encryption is currently available — the writer should persist the
/// returned envelope. Returns `None` when the value is already encrypted or
/// no key is available.
pub fn migrate_at_rest(
    stored: &str,
    aad: &[u8],
) -> Result<Option<String>, SecretEncryptionError> {
    if is_encrypted(stored) {
        return Ok(None);
    }
    if !encryption_available() {
        return Ok(None);
    }
    let plaintext = decrypt_at_rest(stored, aad)?;
    Ok(Some(encrypt_at_rest(&plaintext, aad)?))
}

/// Whether the value is in the encrypted envelope format.
pub fn is_encrypted(value: &str) -> bool {
    value.starts_with(PREFIX)
}

/// Whether the value carries the development plaintext marker.
pub fn is_marked_plaintext(value: &str) -> bool {
    value.starts_with(PLAIN_MARKER)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Serialize key-state mutations (the cache is process-global).
    static KEY_LOCK: Mutex<()> = Mutex::new(());
    const TEST_KEY_HEX: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

    fn force_key_state(hex: Option<&str>, source: KeySource) {
        let mut state = key_cell().lock().unwrap_or_else(|e| e.into_inner());
        match hex {
            Some(hex) => {
                let decoded = hex::decode(hex).unwrap();
                let mut key = [0u8; KEY_SIZE];
                key.copy_from_slice(&decoded);
                state.key = Some(key);
                state.source = source;
            }
            None => {
                state.key = None;
                state.source = source;
            }
        }
    }

    fn force_key(hex: &str) {
        force_key_state(Some(hex), KeySource::Env);
    }

    #[test]
    fn test_secret_at_rest_behaviors() {
        let _guard = KEY_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        force_key(TEST_KEY_HEX);

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
        let err = decrypt_at_rest(&tampered, aad_good).unwrap_err();
        // Wrong-key/tamper failures are TYPED, never silently-garbage output.
        assert!(matches!(
            err,
            SecretEncryptionError::DecryptionFailed | SecretEncryptionError::Base64(_)
        ));
    }

    #[test]
    fn legacy_plaintext_round_trips_through_new_encrypt_and_back() {
        let _guard = KEY_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        force_key(TEST_KEY_HEX);
        let aad = b"user=u9";

        // A legacy row (no marker) decrypts transparently...
        let legacy = "JBSWY3DPEHPK3PXP";
        assert_eq!(decrypt_at_rest(legacy, aad).unwrap(), legacy);
        // ...migrates to an encrypted envelope...
        let migrated = migrate_at_rest(legacy, aad).unwrap().expect("should migrate");
        assert!(is_encrypted(&migrated));
        assert_ne!(migrated, legacy);
        // ...and the envelope decrypts to the original secret.
        assert_eq!(decrypt_at_rest(&migrated, aad).unwrap(), legacy);
        // Already-encrypted values are left alone.
        assert_eq!(migrate_at_rest(&migrated, aad).unwrap(), None);
    }

    #[test]
    fn marked_plaintext_is_distinguishable_and_migrates() {
        let _guard = KEY_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        force_key(TEST_KEY_HEX);
        let aad = b"user=u3";

        let marked = format!("{PLAIN_MARKER}dev-secret");
        assert!(is_marked_plaintext(&marked));
        assert!(!is_encrypted(&marked));
        // Decrypt strips the marker and returns the payload.
        assert_eq!(decrypt_at_rest(&marked, aad).unwrap(), "dev-secret");
        // Migration re-encrypts marked plaintext too.
        let migrated = migrate_at_rest(&marked, aad).unwrap().unwrap();
        assert!(is_encrypted(&migrated));
        assert_eq!(decrypt_at_rest(&migrated, aad).unwrap(), "dev-secret");
    }

    #[test]
    fn no_key_dev_writes_marked_plaintext_and_migrates_later() {
        let _guard = KEY_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        // Simulate the dev no-key mode (production errors instead — covered
        // below). EphemeralMemory = "no persistable key" dev mode.
        force_key_state(None, KeySource::EphemeralMemory);
        let saved = std::env::var("NODE_ENV").ok();
        std::env::set_var("NODE_ENV", "development");
        let aad = b"user=u4";
        let stored = encrypt_at_rest("dev-only", aad).unwrap();
        match saved {
            Some(v) => std::env::set_var("NODE_ENV", v),
            None => std::env::remove_var("NODE_ENV"),
        }
        assert!(is_marked_plaintext(&stored), "got {stored:?}");
        assert_eq!(decrypt_at_rest(&stored, aad).unwrap(), "dev-only");

        // Once a key becomes available the row migrates.
        force_key(TEST_KEY_HEX);
        let migrated = migrate_at_rest(&stored, aad).unwrap().unwrap();
        assert!(is_encrypted(&migrated));
        assert_eq!(decrypt_at_rest(&migrated, aad).unwrap(), "dev-only");
    }

    #[test]
    fn missing_key_in_production_fails_closed() {
        let _guard = KEY_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        force_key_state(None, KeySource::None);
        let saved = std::env::var("NODE_ENV").ok();
        std::env::set_var("NODE_ENV", "production");
        let result = encrypt_at_rest("prod-secret", b"user=u5");
        match saved {
            Some(v) => std::env::set_var("NODE_ENV", v),
            None => std::env::remove_var("NODE_ENV"),
        }
        let err = result.expect_err("production must refuse plaintext writes");
        assert!(matches!(err, SecretEncryptionError::KeyMissingProduction));
    }

    #[test]
    fn wrong_key_fails_closed_with_typed_error() {
        let _guard = KEY_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        force_key(TEST_KEY_HEX);
        let enc = encrypt_at_rest("secret-value", b"user=u6").unwrap();
        force_key("ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100");
        let err = decrypt_at_rest(&enc, b"user=u6").unwrap_err();
        assert!(matches!(err, SecretEncryptionError::DecryptionFailed));
    }
}
