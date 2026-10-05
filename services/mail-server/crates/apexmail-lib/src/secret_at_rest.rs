//! Field-level encryption for sensitive secrets stored in the database
//! (mfa_secret, OAuth tokens, …).
//!
//! # Format
//!
//! On-disk encodings:
//! - Encrypted (current): `enc:v2:<keyid>:<base64(version || nonce || ciphertext+tag)>`
//!   where `keyid` is an 8-hex-char digest of the key material (first 4 bytes
//!   of SHA-256 over the 32-byte key) — see "Key rotation" below.
//! - Encrypted (legacy): `enc:v1:<base64(version || nonce || ciphertext+tag)>`.
//!   Still decrypted transparently; reads lazily migrate it to `enc:v2:`.
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
//! # Key rotation (FX-2)
//!
//! A single static key made rotation a brick: every `enc:v1:` envelope
//! decrypts ONLY with the current key, so swapping
//! `MFA_SECRET_ENCRYPTION_KEY` made every enrolled account undecryptable at
//! login — permanently, and with no recovery path.
//!
//! The fix is key-id versioned envelopes plus an OPTIONAL previous-key
//! list:
//!
//! - New writes are always `enc:v2:<keyid-of-current-key>:…`.
//! - `MFA_SECRET_ENCRYPTION_KEY_PREVIOUS` holds the key material that was
//!   current BEFORE the rotation (and, additively, keys before that).
//!   Format: comma-separated entries, each either
//!   - `<keyid>:<32-byte hex key>` — the key id MAY be spelled out, in which
//!     case it must equal the digest of the key material (a mismatched entry
//!     is rejected at parse with an error log and can never match an
//!     envelope — fail closed), or
//!   - `<32-byte hex key>` — the key id is computed from the material.
//! - `decrypt_at_rest` resolves `enc:v2:` envelopes by key-id lookup across
//!   current + previous keys; legacy `enc:v1:` envelopes (which carry no key
//!   id) try the current key and then each previous key. A keyid with no
//!   configured key fails closed with [`SecretEncryptionError::UnknownKeyId`];
//!   a keyid whose configured material does not decrypt (collision/mismatch)
//!   fails closed with `DecryptionFailed` — never garbage output.
//! - [`migrate_at_rest`] re-encrypts on read: any successful decrypt under a
//!   NON-current key (or any legacy `enc:v1:` / plaintext row) is returned
//!   as a fresh `enc:v2:` envelope under the CURRENT key, so a rotation
//!   converges lazily without a bulk rewrite job. Production without a key
//!   still refuses to write (`KeyMissingProduction`) exactly as before.
//!
//! Rollout safety: with no `MFA_SECRET_ENCRYPTION_KEY_PREVIOUS` configured
//! the behavior for existing `enc:v1:` rows is byte-identical to the
//! pre-rotation code (decrypt with the current key).
//!
//! Reads are always compatible: `decrypt_at_rest` accepts `enc:v2:` and
//! `enc:v1:` envelopes, `plain:v1:` marked values, and legacy no-prefix
//! plaintext. Use [`migrate_at_rest`] on read paths to re-encrypt stale
//! rows to the current key.

use std::sync::{Mutex, Once};

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use rand::rngs::OsRng;
use rand::TryRngCore;
use sha2::Digest;
use thiserror::Error;
use zeroize::Zeroize;

const ENVELOPE_VERSION_V1: u8 = 1;
const ENVELOPE_VERSION_V2: u8 = 2;
const NONCE_SIZE: usize = 12;
const TAG_SIZE: usize = 16;
const KEY_SIZE: usize = 32;
const PREFIX: &str = "enc:v1:";
const PREFIX_V2: &str = "enc:v2:";
/// Length of the hex key id stamped into `enc:v2:` envelopes (first 4 bytes
/// of SHA-256 over the key material — 32 bits of digest is ample to
/// distinguish a handful of operator-configured keys; the envelope remains
/// authenticated by the GCM tag either way).
const KEY_ID_HEX_LEN: usize = 8;
/// E: optional list of predecessor keys accepted for decrypting envelopes
/// written under an earlier `MFA_SECRET_ENCRYPTION_KEY` (rotation support).
const PREVIOUS_ENV_VAR: &str = "MFA_SECRET_ENCRYPTION_KEY_PREVIOUS";
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
    #[error("encrypted envelope references key id `{0}` which is not configured (rotated out or wrong key)")]
    UnknownKeyId(String),
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

/// A key plus its precomputed envelope key id. Clones (snapshots handed to
/// encrypt/decrypt calls) zeroize their key bytes on drop.
struct KeyMaterial {
    key_id: String,
    key: [u8; KEY_SIZE],
}

impl KeyMaterial {
    fn from_key(key: [u8; KEY_SIZE]) -> Self {
        Self {
            key_id: key_id_hex(&key),
            key,
        }
    }
}

impl Drop for KeyMaterial {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

struct KeyState {
    current: Option<KeyMaterial>,
    source: KeySource,
    /// Predecessor keys (`MFA_SECRET_ENCRYPTION_KEY_PREVIOUS`), oldest
    /// rotation depth last; consulted ONLY for decryption.
    previous: Vec<KeyMaterial>,
}

fn key_cell() -> &'static Mutex<KeyState> {
    static CELL: Mutex<KeyState> = Mutex::new(KeyState {
        current: None,
        source: KeySource::None,
        previous: Vec::new(),
    });
    &CELL
}

/// 8-hex-char digest of the key material (first 4 bytes of SHA-256).
fn key_id_hex(key: &[u8; KEY_SIZE]) -> String {
    let digest = sha2::Sha256::digest(key);
    hex::encode(&digest[..KEY_ID_HEX_LEN / 2])
}

/// Parse one entry of `MFA_SECRET_ENCRYPTION_KEY_PREVIOUS`. Accepted shapes:
/// `<keyid>:<hexkey>` (declared id must equal the material's digest) or a
/// bare `<hexkey>` (id computed). Malformed entries return `None` with an
/// error log — they can never silently match an envelope.
fn parse_previous_entry(raw: &str) -> Option<KeyMaterial> {
    let entry = raw.trim();
    if entry.is_empty() {
        return None;
    }
    let (declared_id, hex_key) = match entry.split_once(':') {
        Some((id, key)) => (Some(id.trim()), key.trim()),
        None => (None, entry),
    };
    let bytes = match hex::decode(hex_key) {
        Ok(bytes) if bytes.len() == KEY_SIZE => bytes,
        Ok(_) => {
            tracing::error!(
                env_var = PREVIOUS_ENV_VAR,
                "{PREVIOUS_ENV_VAR} entries must decode to 32 bytes — entry ignored"
            );
            return None;
        }
        Err(e) => {
            tracing::error!(
                error = %e,
                env_var = PREVIOUS_ENV_VAR,
                "invalid hex in {PREVIOUS_ENV_VAR} entry — entry ignored"
            );
            return None;
        }
    };
    let mut key = [0u8; KEY_SIZE];
    key.copy_from_slice(&bytes);
    let material = KeyMaterial::from_key(key);
    if let Some(declared) = declared_id {
        if !declared.eq_ignore_ascii_case(&material.key_id) {
            // Fail closed: a declared id that the material does not hash to
            // is an operator typo. The entry is dropped so it can never
            // "match" an envelope it was not meant for; envelopes stamped
            // with the declared (wrong) id resolve to UnknownKeyId.
            tracing::error!(
                env_var = PREVIOUS_ENV_VAR,
                declared_key_id = %declared,
                computed_key_id = %material.key_id,
                "{PREVIOUS_ENV_VAR} entry declares a key id that does not match its key \
                 material — entry ignored"
            );
            return None;
        }
    }
    Some(material)
}

fn parse_previous_env(value: &str) -> Vec<KeyMaterial> {
    value.split(',').filter_map(parse_previous_entry).collect()
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
        dirs.push(std::path::Path::new(&home).join(".cache").join("apexmail"));
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
    let mut current = None;
    match std::env::var(ENV_VAR) {
        Ok(hex_str) if !hex_str.trim().is_empty() => {
            let bytes = hex::decode(hex_str.trim());
            match bytes {
                Ok(bytes) if bytes.len() == KEY_SIZE => {
                    let mut key = [0u8; KEY_SIZE];
                    key.copy_from_slice(&bytes);
                    current = Some(KeyMaterial::from_key(key));
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

    // Optional predecessor keys (rotation): parsed independently of the
    // current key so a rotation can also be staged BEFORE the current key
    // env is updated.
    let previous = match std::env::var(PREVIOUS_ENV_VAR) {
        Ok(value) if !value.trim().is_empty() => parse_previous_env(&value),
        _ => Vec::new(),
    };

    if current.is_some() {
        return KeyState {
            current,
            source: KeySource::Env,
            previous,
        };
    }

    // 2. Production requires explicit configuration.
    if is_production_env() {
        return KeyState {
            current: None,
            source: KeySource::None,
            previous,
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
                        current: Some(KeyMaterial::from_key(key)),
                        source: KeySource::EphemeralPersisted,
                        previous,
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
                    current: Some(KeyMaterial::from_key(key)),
                    source: KeySource::EphemeralPersisted,
                    previous,
                };
            }
        }
        key.zeroize();
    }

    warn_once_dev_plaintext();
    KeyState {
        current: None,
        source: KeySource::EphemeralMemory,
        previous,
    }
}

/// Snapshot the resolved keys. Snapshots are plain clones; their key bytes
/// are zeroized on drop via `KeyMaterial: Drop`.
struct ResolvedKeys {
    current: Option<KeyMaterial>,
    previous: Vec<KeyMaterial>,
}

fn load_keys() -> Result<ResolvedKeys, SecretEncryptionError> {
    let mut state = key_cell().lock().unwrap_or_else(|e| e.into_inner());
    if state.source == KeySource::None {
        *state = resolve_key_state();
    }
    if state.source == KeySource::None && is_production_env() {
        // Re-check production on every call: a key that was missing at first
        // resolution must fail closed in production.
        return Err(SecretEncryptionError::KeyMissingProduction);
    }
    Ok(ResolvedKeys {
        current: state.current.as_ref().map(|k| KeyMaterial {
            key_id: k.key_id.clone(),
            key: k.key,
        }),
        previous: state
            .previous
            .iter()
            .map(|k| KeyMaterial {
                key_id: k.key_id.clone(),
                key: k.key,
            })
            .collect(),
    })
}

/// Snapshot of just the current key (legacy shape used by the encrypt path).
fn load_key() -> Result<Option<KeyMaterial>, SecretEncryptionError> {
    Ok(load_keys()?.current)
}

/// The envelope key id of the CURRENT key, when one is configured.
pub fn current_key_id() -> Result<Option<String>, SecretEncryptionError> {
    Ok(load_keys()?.current.map(|k| k.key_id.clone()))
}

/// True when at-rest encryption is active for new writes.
pub fn encryption_available() -> bool {
    matches!(load_key(), Ok(Some(_)))
}

/// Build the `enc:v2:` envelope for `ciphertext` under `material`.
fn v2_envelope(material: &KeyMaterial, envelope: &[u8]) -> String {
    format!("{PREFIX_V2}{}:{}", material.key_id, B64.encode(envelope))
}

/// Seal `plaintext` under `material` and wrap it in an `enc:v2:` envelope.
fn encrypt_with(
    material: &KeyMaterial,
    plaintext: &str,
    aad: &[u8],
) -> Result<String, SecretEncryptionError> {
    let cipher = Aes256Gcm::new_from_slice(material.key.as_slice())
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
    envelope.push(ENVELOPE_VERSION_V2);
    envelope.extend_from_slice(&nonce_bytes);
    envelope.extend_from_slice(&ciphertext);

    Ok(v2_envelope(material, &envelope))
}

/// Open a raw (version || nonce || ct+tag) envelope with `material`.
fn decrypt_with(
    material: &KeyMaterial,
    expect_version: u8,
    envelope: &[u8],
    aad: &[u8],
) -> Result<String, SecretEncryptionError> {
    if envelope.is_empty() || envelope[0] != expect_version {
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

    let cipher = Aes256Gcm::new_from_slice(material.key.as_slice())
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

/// Encrypt `plaintext` for at-rest storage.
///
/// Returns an `enc:v2:<keyid>:<base64>` envelope under the CURRENT key when
/// one is available. In production a missing key is a typed error (never
/// silent plaintext). In development without a persistable key the plaintext
/// is returned wrapped in the `plain:v1:` marker with a per-process warning.
/// `aad` is bound into the GCM tag — pass a stable scope identifier such as
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

    encrypt_with(&key, plaintext, aad)
}

/// Decrypt an `enc:v1:` legacy envelope: no key id is stamped, so try the
/// current key and then each previous key. All candidates failing is a
/// typed failure — never garbage output.
fn decrypt_v1(
    stored_b64: &str,
    keys: &ResolvedKeys,
    aad: &[u8],
) -> Result<String, SecretEncryptionError> {
    let envelope = B64.decode(stored_b64.as_bytes())?;

    let mut candidates: Vec<&KeyMaterial> = Vec::new();
    if let Some(current) = &keys.current {
        candidates.push(current);
    }
    for previous in &keys.previous {
        candidates.push(previous);
    }
    if candidates.is_empty() {
        return Err(SecretEncryptionError::KeyMissing);
    }

    // GCM authentication makes a wrong-key attempt fail closed, so trying
    // candidates in order leaks nothing beyond "none matched".
    let mut last_err = SecretEncryptionError::DecryptionFailed;
    for material in candidates {
        match decrypt_with(material, ENVELOPE_VERSION_V1, &envelope, aad) {
            Ok(plaintext) => return Ok(plaintext),
            Err(e) => last_err = e,
        }
    }
    Err(last_err)
}

/// Decrypt an `enc:v2:` envelope by key-id lookup across current + previous
/// keys. Unknown key id → [`SecretEncryptionError::UnknownKeyId`]; a matching
/// id whose material fails authentication (collision/mismatch) →
/// `DecryptionFailed`. Both fail closed.
fn decrypt_v2(
    key_id: &str,
    stored_b64: &str,
    keys: &ResolvedKeys,
    aad: &[u8],
) -> Result<String, SecretEncryptionError> {
    if key_id.len() != KEY_ID_HEX_LEN || !key_id.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(SecretEncryptionError::InvalidEnvelope("malformed key id"));
    }

    let envelope = B64.decode(stored_b64.as_bytes())?;

    let mut candidates: Vec<&KeyMaterial> = Vec::new();
    if let Some(current) = &keys.current {
        if current.key_id.eq_ignore_ascii_case(key_id) {
            candidates.push(current);
        }
    }
    for previous in &keys.previous {
        if previous.key_id.eq_ignore_ascii_case(key_id) {
            candidates.push(previous);
        }
    }
    if candidates.is_empty() {
        return Err(SecretEncryptionError::UnknownKeyId(key_id.to_string()));
    }

    let mut last_err = SecretEncryptionError::DecryptionFailed;
    for material in candidates {
        match decrypt_with(material, ENVELOPE_VERSION_V2, &envelope, aad) {
            Ok(plaintext) => return Ok(plaintext),
            Err(e) => last_err = e,
        }
    }
    Err(last_err)
}

/// Decrypt `stored` back to plaintext.
///
/// Transparently accepts the `enc:v2:<keyid>:<base64>` and legacy
/// `enc:v1:<base64>` envelopes, `plain:v1:` marked values, and legacy
/// unmarked plaintext (so a database can be migrated row-by-row). Pass the
/// same `aad` used at encryption time. A malformed or tampered envelope, an
/// unknown key id, or a wrong key fails closed with a typed error — never
/// silently returns garbage.
pub fn decrypt_at_rest(stored: &str, aad: &[u8]) -> Result<String, SecretEncryptionError> {
    if let Some(plaintext) = stored.strip_prefix(PLAIN_MARKER) {
        return Ok(plaintext.to_string());
    }
    if let Some(rest) = stored.strip_prefix(PREFIX_V2) {
        let Some((key_id, b64)) = rest.split_once(':') else {
            return Err(SecretEncryptionError::InvalidEnvelope(
                "v2 envelope is missing its key id",
            ));
        };
        let keys = load_keys()?;
        return decrypt_v2(key_id, b64, &keys, aad);
    }
    let Some(b64) = stored.strip_prefix(PREFIX) else {
        // Legacy unmarked plaintext: pass through.
        return Ok(stored.to_string());
    };

    let keys = load_keys()?;
    decrypt_v1(b64, &keys, aad)
}

/// E: read-migration helper. Given a stored value, returns `Some(encrypted)`
/// when the value should be re-encrypted under the CURRENT key:
///   - plaintext rows (legacy unmarked or `plain:v1:` marked),
///   - legacy `enc:v1:` envelopes (key-id-less format), and
///   - `enc:v2:` envelopes whose key id is NOT the current key's (a row last
///     written under a since-rotated key — lazy rotation on read).
///
/// Returns `None` when the value is already an `enc:v2:` envelope under the
/// current key or no current key is available. The writer should persist the
/// returned envelope.
pub fn migrate_at_rest(stored: &str, aad: &[u8]) -> Result<Option<String>, SecretEncryptionError> {
    if let Some(rest) = stored.strip_prefix(PREFIX_V2) {
        let Some((key_id, b64)) = rest.split_once(':') else {
            return Err(SecretEncryptionError::InvalidEnvelope(
                "v2 envelope is missing its key id",
            ));
        };
        let keys = load_keys()?;
        let Some(current) = &keys.current else {
            return Ok(None);
        };
        if current.key_id.eq_ignore_ascii_case(key_id) {
            // Already sealed under the current key.
            return Ok(None);
        }
        let plaintext = decrypt_v2(key_id, b64, &keys, aad)?;
        return Ok(Some(encrypt_with(current, &plaintext, aad)?));
    }

    if !encryption_available() {
        return Ok(None);
    }

    let plaintext = if is_encrypted(stored) {
        // Legacy `enc:v1:` envelope: decrypt (current or previous key), then
        // re-encrypt under the current key so the format converges to v2.
        let b64 = stored.strip_prefix(PREFIX).expect("checked above");
        let keys = load_keys()?;
        decrypt_v1(b64, &keys, aad)?
    } else {
        decrypt_at_rest(stored, aad)?
    };
    Ok(Some(encrypt_at_rest(&plaintext, aad)?))
}

/// Whether the value is in an encrypted envelope format (v1 or v2).
pub fn is_encrypted(value: &str) -> bool {
    value.starts_with(PREFIX) || value.starts_with(PREFIX_V2)
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
    const KEY_B_HEX: &str = "1100110011001100110011001100110011001100110011001100110011001100";
    const KEY_C_HEX: &str = "feedfacefeedfacefeedfacefeedfacefeedfacefeedfacefeedfacefeedface";

    fn force_key_state(hex: Option<&str>, source: KeySource) {
        force_keys_state(hex, &[], source);
    }

    /// Force the current key AND the previous-key list (rotation scenarios).
    fn force_keys_state(current_hex: Option<&str>, previous_hex: &[&str], source: KeySource) {
        let mut state = key_cell().lock().unwrap_or_else(|e| e.into_inner());
        state.current = current_hex.map(|hex| {
            let decoded = hex::decode(hex).unwrap();
            let mut key = [0u8; KEY_SIZE];
            key.copy_from_slice(&decoded);
            KeyMaterial::from_key(key)
        });
        state.previous = previous_hex
            .iter()
            .map(|hex| {
                let decoded = hex::decode(hex).unwrap();
                let mut key = [0u8; KEY_SIZE];
                key.copy_from_slice(&decoded);
                KeyMaterial::from_key(key)
            })
            .collect();
        state.source = source;
    }

    fn force_key(hex: &str) {
        force_key_state(Some(hex), KeySource::Env);
    }

    fn force_keys(current_hex: &str, previous_hex: &[&str]) {
        force_keys_state(Some(current_hex), previous_hex, KeySource::Env);
    }

    fn parse_v2_envelope(stored: &str) -> (String, Vec<u8>) {
        let rest = stored.strip_prefix(PREFIX_V2).expect("envelope must be v2");
        let (key_id, b64) = rest.split_once(':').expect("key id separator");
        (key_id.to_string(), B64.decode(b64).unwrap())
    }

    /// Hand-seal a LEGACY `enc:v1:` envelope under `key_hex` (what every row
    /// written before the v2 format looks like).
    fn seal_legacy_v1(key_hex: &str, plaintext: &str, aad: &[u8]) -> String {
        let decoded = hex::decode(key_hex).unwrap();
        let mut key = [0u8; KEY_SIZE];
        key.copy_from_slice(&decoded);
        let cipher = Aes256Gcm::new_from_slice(&key).unwrap();
        let nonce_bytes = [7u8; NONCE_SIZE];
        let ciphertext = cipher
            .encrypt(
                Nonce::from_slice(&nonce_bytes),
                Payload {
                    msg: plaintext.as_bytes(),
                    aad,
                },
            )
            .unwrap();
        let mut envelope = Vec::with_capacity(1 + NONCE_SIZE + ciphertext.len());
        envelope.push(ENVELOPE_VERSION_V1);
        envelope.extend_from_slice(&nonce_bytes);
        envelope.extend_from_slice(&ciphertext);
        format!("{PREFIX}{}", B64.encode(envelope))
    }

    #[test]
    fn test_secret_at_rest_behaviors() {
        let _guard = KEY_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        force_key(TEST_KEY_HEX);

        // 1. Roundtrip with AAD succeeds — and lands in the v2 format.
        let aad_good = b"user=u1";
        let enc = encrypt_at_rest("topsecret-totp", aad_good).unwrap();
        let (key_id, _) = parse_v2_envelope(&enc);
        assert_eq!(
            key_id,
            key_id_hex(&hex::decode(TEST_KEY_HEX).unwrap().try_into().unwrap())
        );
        assert_eq!(decrypt_at_rest(&enc, aad_good).unwrap(), "topsecret-totp");

        // 2. AAD mismatch is rejected (relocation defense).
        let aad_bad = b"user=u2";
        assert!(decrypt_at_rest(&enc, aad_bad).is_err());

        // 3. Legacy plaintext passes through transparently on decrypt.
        let plain = "raw-base32-secret";
        assert_eq!(decrypt_at_rest(plain, aad_good).unwrap(), plain);

        // 4. Format detection helper.
        assert!(is_encrypted("enc:v1:abc"));
        assert!(is_encrypted(&enc));
        assert!(!is_encrypted("plain"));

        // 5. Tamper detection: flipping the last byte of the envelope must fail.
        let (_, mut bytes) = parse_v2_envelope(&enc);
        let last = bytes.len() - 1;
        bytes[last] ^= 0x01;
        let tampered = format!("{PREFIX_V2}{}:{}", key_id, B64.encode(&bytes));
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
        let migrated = migrate_at_rest(legacy, aad)
            .unwrap()
            .expect("should migrate");
        assert!(is_encrypted(&migrated));
        assert_ne!(migrated, legacy);
        // ...and the envelope decrypts to the original secret.
        assert_eq!(decrypt_at_rest(&migrated, aad).unwrap(), legacy);
        // Already-migrated (current-key v2) values are left alone.
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
        // Without the old key configured this is the honest "unknown key id"
        // failure — the exact brick the rotation support removes.
        let err = decrypt_at_rest(&enc, b"user=u6").unwrap_err();
        assert!(matches!(err, SecretEncryptionError::UnknownKeyId(_)));
    }

    // ── FX-2: key-id versioned envelopes + rotation ─────────────────────

    #[test]
    fn v2_round_trip_stamps_the_current_key_id() {
        let _guard = KEY_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        force_key(TEST_KEY_HEX);
        let aad = b"user=r1";

        let enc = encrypt_at_rest("v2-secret", aad).unwrap();
        let (key_id, envelope) = parse_v2_envelope(&enc);
        assert_eq!(key_id.len(), KEY_ID_HEX_LEN);
        assert_eq!(envelope[0], ENVELOPE_VERSION_V2);
        assert_eq!(current_key_id().unwrap().as_deref(), Some(key_id.as_str()));
        assert_eq!(decrypt_at_rest(&enc, aad).unwrap(), "v2-secret");

        // AAD is still bound per-user on v2 envelopes.
        assert!(decrypt_at_rest(&enc, b"user=other").is_err());
    }

    #[test]
    fn legacy_v1_envelopes_keep_decrypting_with_current_key_only() {
        let _guard = KEY_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let aad = b"user=v1";
        let legacy = seal_legacy_v1(TEST_KEY_HEX, "pre-rotation secret", aad);

        // No previous keys configured — the pre-FX-2 rollout shape.
        force_key(TEST_KEY_HEX);
        assert_eq!(
            decrypt_at_rest(&legacy, aad).unwrap(),
            "pre-rotation secret"
        );
        // The lazy hook upgrades the row to v2-current on read.
        let migrated = migrate_at_rest(&legacy, aad).unwrap().expect("migrate");
        assert!(migrated.starts_with(PREFIX_V2));
        assert_eq!(
            decrypt_at_rest(&migrated, aad).unwrap(),
            "pre-rotation secret"
        );
        // Converged: migrating again is a no-op.
        assert_eq!(migrate_at_rest(&migrated, aad).unwrap(), None);

        // v1 rows must still decrypt when the current key is wrong BUT the
        // right key is configured as a previous key.
        force_keys(KEY_B_HEX, &[TEST_KEY_HEX]);
        assert_eq!(
            decrypt_at_rest(&legacy, aad).unwrap(),
            "pre-rotation secret"
        );
    }

    #[test]
    fn rotation_encrypt_a_decrypt_b_with_previous_a_and_migrates() {
        let _guard = KEY_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let aad = b"user=rot";

        // Phase 1: key A is current; the row is written.
        force_key(TEST_KEY_HEX);
        let enc_a = encrypt_at_rest("rotate-me", aad).unwrap();
        let (id_a, _) = parse_v2_envelope(&enc_a);

        // Phase 2: operator rotates to key B with PREVIOUS=A.
        force_keys(KEY_B_HEX, &[TEST_KEY_HEX]);
        // The A-envelope still decrypts (by key id), ...
        assert_eq!(decrypt_at_rest(&enc_a, aad).unwrap(), "rotate-me");
        // ... and the read hook lazily re-encrypts it under B.
        let migrated = migrate_at_rest(&enc_a, aad)
            .unwrap()
            .expect("rotate on read");
        let (id_b, _) = parse_v2_envelope(&migrated);
        assert_ne!(id_a, id_b);
        assert_eq!(
            id_b,
            key_id_hex(&hex::decode(KEY_B_HEX).unwrap().try_into().unwrap())
        );
        assert_eq!(decrypt_at_rest(&migrated, aad).unwrap(), "rotate-me");
        // Converged under B: no further migration.
        assert_eq!(migrate_at_rest(&migrated, aad).unwrap(), None);

        // New writes under B carry B's key id.
        let fresh = encrypt_at_rest("post-rotation", aad).unwrap();
        let (id, _) = parse_v2_envelope(&fresh);
        assert_eq!(id, id_b);
    }

    #[test]
    fn decrypt_with_neither_key_fails_closed() {
        let _guard = KEY_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        force_key(TEST_KEY_HEX);
        let aad = b"user=brick";
        let enc = encrypt_at_rest("gone", aad).unwrap();

        // Rotate to a key with NO predecessor configured.
        force_key(KEY_C_HEX);
        let err = decrypt_at_rest(&enc, aad).unwrap_err();
        assert!(
            matches!(err, SecretEncryptionError::UnknownKeyId(ref id) if id != &current_key_id().unwrap().unwrap()),
            "expected UnknownKeyId, got {err}"
        );

        // A legacy v1 envelope under a fully-unknown key fails with the
        // typed wrong-key error (no key id to name, still fail-closed).
        let legacy = seal_legacy_v1(TEST_KEY_HEX, "old", aad);
        let err = decrypt_at_rest(&legacy, aad).unwrap_err();
        assert!(matches!(err, SecretEncryptionError::DecryptionFailed));
    }

    #[test]
    fn key_id_mismatch_and_collision_fail_closed() {
        let _guard = KEY_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        force_key(TEST_KEY_HEX);
        let aad = b"user=coll";

        // A v2 envelope whose key id names NO configured key.
        let forged = format!(
            "{PREFIX_V2}deadbeef:{}",
            B64.encode(vec![ENVELOPE_VERSION_V2; 1 + NONCE_SIZE + TAG_SIZE])
        );
        let err = decrypt_at_rest(&forged, aad).unwrap_err();
        assert!(matches!(err, SecretEncryptionError::UnknownKeyId(id) if id == "deadbeef"));

        // A previous-key entry whose DECLARED id does not match its material
        // is rejected at parse and can never resolve an envelope.
        force_keys_state(Some(TEST_KEY_HEX), &[], KeySource::Env);
        let enc = encrypt_at_rest("guarded", aad).unwrap();
        let (real_id, _) = parse_v2_envelope(&enc);
        assert_ne!(real_id, "00000000");
        // Simulate the operator typo through the env parser directly.
        let wrong_label = format!("00000000:{TEST_KEY_HEX}");
        assert!(parse_previous_entry(&wrong_label).is_none());
        let right_label = format!("{}:{}", real_id, TEST_KEY_HEX);
        let parsed = parse_previous_entry(&right_label).expect("correct label parses");
        assert_eq!(parsed.key_id, real_id);
        // Bare-hex form computes the id from the material.
        let parsed_bare = parse_previous_entry(TEST_KEY_HEX).expect("bare hex parses");
        assert_eq!(parsed_bare.key_id, real_id);

        // A key id that resolves to a configured key whose material does NOT
        // authenticate the envelope (digest collision / relabeled key) fails
        // closed with DecryptionFailed — never garbage output. The envelope
        // was sealed under A; C's id is stamped on it instead: the lookup
        // finds C, GCM refuses the wrong key.
        let enc = encrypt_at_rest("guarded", aad).unwrap();
        let (_, b64) = {
            let rest = enc.strip_prefix(PREFIX_V2).unwrap();
            let (_, b64) = rest.split_once(':').unwrap();
            ((), b64.to_string())
        };
        let id_c = key_id_hex(&hex::decode(KEY_C_HEX).unwrap().try_into().unwrap());
        let relabeled = format!("{PREFIX_V2}{id_c}:{b64}");
        force_keys(KEY_B_HEX, &[KEY_C_HEX]);
        let err = decrypt_at_rest(&relabeled, aad).unwrap_err();
        assert!(matches!(err, SecretEncryptionError::DecryptionFailed));
    }

    #[test]
    fn malformed_v2_envelopes_fail_closed() {
        let _guard = KEY_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        force_key(TEST_KEY_HEX);
        let aad = b"user=mal";

        // Missing key id segment.
        assert!(matches!(
            decrypt_at_rest("enc:v2:abcdef", aad),
            Err(SecretEncryptionError::InvalidEnvelope(_))
        ));
        // Malformed key id (wrong length).
        assert!(matches!(
            decrypt_at_rest("enc:v2:abc:AAAA", aad),
            Err(SecretEncryptionError::InvalidEnvelope(_))
        ));
        // Wrong inner version byte.
        let (id, mut envelope) = {
            let enc = encrypt_at_rest("x", aad).unwrap();
            parse_v2_envelope(&enc)
        };
        envelope[0] = ENVELOPE_VERSION_V1;
        let wrong_inner = format!("{PREFIX_V2}{id}:{}", B64.encode(envelope));
        assert!(matches!(
            decrypt_at_rest(&wrong_inner, aad),
            Err(SecretEncryptionError::InvalidEnvelope(_))
        ));
    }

    #[test]
    fn previous_env_parsing_accepts_pairs_and_bare_hex() {
        let _guard = KEY_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let id_a = key_id_hex(&hex::decode(TEST_KEY_HEX).unwrap().try_into().unwrap());
        let entries = format!(" {id_a}:{TEST_KEY_HEX} , {KEY_B_HEX} ,,, broken:zz , {KEY_C_HEX} ");
        let parsed = parse_previous_env(&entries);
        // `broken:zz` is dropped (invalid hex); the three valid entries stay,
        // in order.
        assert_eq!(parsed.len(), 3);
        assert_eq!(parsed[0].key_id, id_a);
        assert_eq!(
            parsed[1].key_id,
            key_id_hex(&hex::decode(KEY_B_HEX).unwrap().try_into().unwrap())
        );
    }
}
