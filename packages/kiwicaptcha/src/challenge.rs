//! Challenge issuance for KiwiCaptcha.
//!
//! A challenge is an HMAC-signed, nonce-stamped, IP-bound token that the client
//! must fold into a SHA-256 proof-of-work. The signature binds the challenge
//! to the server's secret key (so clients cannot forge challenges), the issuing
//! time (for TTL enforcement), the client IP hash (for replay-across-clients
//! prevention), and the scope (so a login challenge can't be used for signup).
//!
//! This module is pure (no I/O): it produces an [`IssuedChallenge`] and a
//! [`ChallengeRecord`] (the server-side state to persist in Redis). The caller
//! is responsible for storing the record keyed by nonce.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use hmac::{Hmac, Mac};
use rand::{thread_rng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::token::IssuedChallenge;

type HmacSha256 = Hmac<Sha256>;

/// The signed payload embedded inside a challenge string.
///
/// This is what gets HMAC-signed and base64-encoded into
/// [`IssuedChallenge::challenge`]. The verifier reconstructs this from the
/// nonce + the stored [`ChallengeRecord`] and re-checks the signature.
#[derive(Debug, Clone)]
pub struct ChallengePayload {
    /// 32 random bytes, base64-encoded. Acts as the single-use token id.
    pub nonce: String,
    /// The auth scope this challenge is valid for (e.g. "login", "signup").
    pub scope: String,
    /// SHA-256 of the client IP (hex). Prevents relay attacks.
    pub ip_hash: String,
    /// Unix timestamp (seconds) when the challenge was issued.
    pub issued_at: u64,
}

/// Server-side state persisted in Redis, keyed by `kcaptcha:{nonce}`.
///
/// Stored alongside (but separately from) the signed challenge string sent to
/// the client. The verifier reads this to check TTL, IP binding, and to mark
/// the challenge consumed (single-use).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChallengeRecord {
    pub nonce: String,
    pub scope: String,
    pub ip_hash: String,
    pub issued_at: u64,
    pub expires_at: u64,
    /// The difficulty parameters this challenge was issued with, so a
    /// difficulty downgrade attack (client claims a lower target_bits) is
    /// rejected — the server always verifies against the parameters it issued.
    pub m_kib: u32,
    pub t: u32,
    pub p: u32,
    pub target_bits: u32,
    /// The salt and prefix bound to this challenge.
    pub salt: String,
    pub prefix: String,
    /// The signed challenge string (`base64(payload).signature`) — stored so the
    /// verifier can re-check the HMAC without re-parsing the prefix.
    pub challenge: String,
}

/// Configuration for the challenge issuer. Mirrors the server config block but
/// kept as a plain struct so this crate has no dependency on the api-server
/// config types.
#[derive(Debug, Clone)]
pub struct ChallengeConfig {
    /// HMAC secret key (server-side). Challenges signed with this key cannot
    /// be verified by a server using a different key.
    pub secret_key: String,
    /// Reserved difficulty parameter (kept for struct/wire stability).
    pub m_kib: u32,
    /// Reserved difficulty parameter (kept for struct stability).
    pub t: u32,
    /// Reserved difficulty parameter (kept for struct stability).
    pub p: u32,
    /// Required leading zero bits in the SHA-256 output (difficulty).
    pub target_bits: u32,
    /// Challenge lifetime in seconds.
    pub ttl_secs: u64,
    /// When enabled, `target_bits` is automatically adjusted based on active
    /// solver load: higher load -> higher difficulty; idle -> lower difficulty.
    pub auto_tune: bool,
    /// Minimum target bits when auto-tuning is idle (no load).
    pub auto_tune_min_bits: u32,
    /// Maximum target bits when auto-tuning is under peak load.
    pub auto_tune_max_bits: u32,
}

impl ChallengeConfig {
    /// Compute the adjusted target bits based on current active solver count.
    /// When `auto_tune` is disabled, returns the static `target_bits`.
    /// Otherwise linearly interpolates between `auto_tune_min_bits` (0 active)
    /// and `auto_tune_max_bits` (50+ active solvers).
    pub fn tuned_target_bits(&self, active_solves: u64) -> u32 {
        if !self.auto_tune {
            return self.target_bits;
        }
        let load = (active_solves as f64 / 50.0).min(1.0);
        let range = self.auto_tune_max_bits.saturating_sub(self.auto_tune_min_bits) as f64;
        let adjusted = self.auto_tune_min_bits as f64 + load * range;
        adjusted as u32
    }
}

/// Hash a client IP address for embedding in the challenge (privacy-preserving:
/// we never store the raw IP, only its salted SHA-256 hex digest).
///
/// The `salt` prevents identical IPs from producing identical hashes across
/// deployments that use different secret keys.
pub fn hash_ip(ip: &str, salt: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(salt.as_bytes());
    hasher.update(ip.as_bytes());
    hex::encode(&hasher.finalize())
}

/// The signed challenge string is `base64(payload_fields || "." || hmac)`.
/// The verifier reconstructs the payload from the nonce + stored record and
/// re-checks. We sign a canonical string so the binding is unambiguous.
fn canonical_signing_input(payload: &ChallengePayload) -> String {
    format!(
        "{}|{}|{}|{}",
        payload.nonce, payload.scope, payload.ip_hash, payload.issued_at
    )
}

/// Sign the payload with the secret key, returning a hex HMAC tag.
pub fn sign_payload(payload: &ChallengePayload, secret_key: &str) -> Result<String, SignError> {
    let mut mac =
        HmacSha256::new_from_slice(secret_key.as_bytes()).map_err(|_| SignError::KeyTooShort)?;
    mac.update(canonical_signing_input(payload).as_bytes());
    Ok(hex::encode(&mac.finalize().into_bytes()))
}

/// Verify that a signature matches the payload under the given key.
pub fn verify_signature(
    payload: &ChallengePayload,
    signature: &str,
    secret_key: &str,
) -> Result<bool, SignError> {
    let expected = sign_payload(payload, secret_key)?;
    Ok(hmac_ct_eq(&expected, signature))
}

/// Constant-time string comparison. Even if lengths differ, the comparison
/// still iterates over `min(a.len(), b.len())` bytes using XOR accumulation
/// so the timing is proportional to the shorter input — not short-circuited.
fn hmac_ct_eq(a: &str, b: &str) -> bool {
    let mut diff: u8 = 0;
    let min_len = a.len().min(b.len());
    for (x, y) in a.bytes().take(min_len).zip(b.bytes().take(min_len)) {
        diff |= x ^ y;
    }
    if a.len() != b.len() {
        diff |= 1;
    }
    diff == 0
}

/// The result of issuing a challenge: the client-facing [`IssuedChallenge`] and
/// the server-side [`ChallengeRecord`] to persist.
#[derive(Debug, Clone)]
pub struct Issued {
    pub challenge: IssuedChallenge,
    pub record: ChallengeRecord,
}

/// In-memory challenge cache that reduces Redis writes when the same client
/// (identified by IP hash + scope) re-requests within a 1-second window.
///
/// Entries older than 1 second are automatically pruned on `get` and `prune`.
pub struct ChallengeCache {
    entries: HashMap<String, (Issued, Instant)>,
}

impl ChallengeCache {
    pub fn new() -> Self {
        ChallengeCache {
            entries: HashMap::new(),
        }
    }

    fn cache_key(ip_hash: &str, scope: &str) -> String {
        format!("{ip_hash}|{scope}")
    }

    pub fn get(&self, ip_hash: &str, scope: &str) -> Option<&Issued> {
        let key = Self::cache_key(ip_hash, scope);
        self.entries.get(&key).and_then(|(issued, ts)| {
            if ts.elapsed() < Duration::from_secs(1) {
                Some(issued)
            } else {
                None
            }
        })
    }

    pub fn put(&mut self, ip_hash: &str, scope: &str, issued: Issued) {
        let key = Self::cache_key(ip_hash, scope);
        self.entries.insert(key, (issued, Instant::now()));
    }

    pub fn prune(&mut self) {
        self.entries
            .retain(|_, (_, ts)| ts.elapsed() < Duration::from_secs(1));
    }
}

impl Default for ChallengeCache {
    fn default() -> Self {
        Self::new()
    }
}

/// Issue a new challenge.
///
/// - `config` — difficulty + secret key.
/// - `scope` — the auth flow ("login", "signup", "forgot-password", etc.).
/// - `client_ip` — the client's IP address (hashed before storage).
/// - `now_unix` — current Unix timestamp (injected for testability).
/// - `active_solves` — current number of active solvers (for auto-tuning).
pub fn issue_challenge(
    config: &ChallengeConfig,
    scope: &str,
    client_ip: &str,
    now_unix: u64,
    active_solves: u64,
) -> Result<Issued, SignError> {
    if scope.contains('|') {
        return Err(SignError::InvalidScope);
    }
    // 32-byte nonce.
    let mut nonce_bytes = [0u8; 32];
    thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = B64.encode(nonce_bytes);

    // 16-byte salt.
    let mut salt_bytes = [0u8; 16];
    thread_rng().fill_bytes(&mut salt_bytes);
    let salt = B64.encode(salt_bytes);

    let ip_hash = hash_ip(client_ip, &config.secret_key);
    let target_bits = config.tuned_target_bits(active_solves);

    let payload = ChallengePayload {
        nonce: nonce.clone(),
        scope: scope.to_string(),
        ip_hash: ip_hash.clone(),
        issued_at: now_unix,
    };
    let signature = sign_payload(&payload, &config.secret_key)?;

    // The challenge string the client folds into SHA-256: it contains the
    // signed payload so a client cannot tamper with nonce/scope/ip/issued_at
    // without invalidating the signature.
    let challenge = format!("{}.{}", B64.encode(canonical_signing_input(&payload)), signature);

    // The prefix binds the client's counter input to this exact challenge.
    let prefix = format!("{challenge}|{salt}|");

    let expires_at = now_unix.saturating_add(config.ttl_secs);

    let record = ChallengeRecord {
        nonce: nonce.clone(),
        scope: scope.to_string(),
        ip_hash,
        issued_at: now_unix,
        expires_at,
        m_kib: config.m_kib,
        t: config.t,
        p: config.p,
        target_bits,
        salt: salt.clone(),
        prefix: prefix.clone(),
        challenge: challenge.clone(),
    };

    let challenge_token = IssuedChallenge {
        nonce: nonce.clone(),
        challenge,
        salt,
        m_kib: config.m_kib,
        t: config.t,
        p: config.p,
        target_bits,
        ttl_secs: config.ttl_secs,
        prefix,
    };

    Ok(Issued {
        challenge: challenge_token,
        record,
    })
}

/// Reconstruct a [`ChallengePayload`] from a stored record, for signature
/// re-verification during solution validation.
pub fn payload_from_record(record: &ChallengeRecord) -> ChallengePayload {
    ChallengePayload {
        nonce: record.nonce.clone(),
        scope: record.scope.clone(),
        ip_hash: record.ip_hash.clone(),
        issued_at: record.issued_at,
    }
}

#[derive(Debug, thiserror::Error)]
pub enum SignError {
    #[error("HMAC secret key is too short")]
    KeyTooShort,
    #[error("scope contains invalid character '|'")]
    InvalidScope,
}

// Minimal hex encode/decode to avoid pulling in a `hex` crate dependency —
// HMAC outputs and IP hashes are the only consumers.
mod hex {
    pub fn encode(bytes: &[u8]) -> String {
        let mut s = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            s.push_str(&format!("{b:02x}"));
        }
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn issued_challenge_has_correct_difficulty() {
        let config = ChallengeConfig {
            secret_key: "super-secret-key".into(),
            m_kib: 65_536,
            t: 2,
            p: 1,
            target_bits: 18,
            ttl_secs: 120,
            auto_tune: false,
            auto_tune_min_bits: 10,
            auto_tune_max_bits: 24,
        };
        let issued = issue_challenge(&config, "login", "1.2.3.4", 1_000_000, 0).unwrap();
        assert_eq!(issued.challenge.m_kib, 65_536);
        assert_eq!(issued.challenge.t, 2);
        assert_eq!(issued.challenge.p, 1);
        assert_eq!(issued.challenge.target_bits, 18);
        assert_eq!(issued.challenge.ttl_secs, 120);
        assert!(!issued.challenge.challenge.is_empty());
        assert!(!issued.challenge.salt.is_empty());
        assert!(!issued.challenge.nonce.is_empty());
        // The nonce in the IssuedChallenge should match the record nonce.
        assert_eq!(issued.challenge.nonce, issued.record.nonce);
        assert!(issued.challenge.prefix.starts_with(&issued.challenge.challenge));
        // Record expiry = issued + ttl.
        assert_eq!(issued.record.expires_at, 1_000_120);
        // IP is hashed, not stored raw.
        assert_ne!(issued.record.ip_hash, "1.2.3.4");
    }

    #[test]
    fn signatures_verify_round_trip() {
        let payload = ChallengePayload {
            nonce: "n".into(),
            scope: "login".into(),
            ip_hash: hash_ip("9.9.9.9", "key"),
            issued_at: 123,
        };
        let sig = sign_payload(&payload, "key").unwrap();
        assert!(verify_signature(&payload, &sig, "key").unwrap());
        assert!(!verify_signature(&payload, &sig, "wrong-key").unwrap());
        // Tampering with the nonce breaks the signature.
        let mut tampered = payload.clone();
        tampered.nonce = "x".into();
        assert!(!verify_signature(&tampered, &sig, "key").unwrap());
    }

    #[test]
    fn each_challenge_has_unique_nonce() {
        let config = ChallengeConfig {
            secret_key: "test-key".into(),
            m_kib: 65_536,
            t: 2,
            p: 1,
            target_bits: 18,
            ttl_secs: 120,
            auto_tune: false,
            auto_tune_min_bits: 10,
            auto_tune_max_bits: 24,
        };
        let a = issue_challenge(&config, "login", "1.1.1.1", 1, 0).unwrap();
        let b = issue_challenge(&config, "login", "1.1.1.1", 1, 0).unwrap();
        assert_ne!(a.record.nonce, b.record.nonce);
    }

    #[test]
    fn auto_tune_adjusts_target_bits() {
        let config = ChallengeConfig {
            secret_key: "test-key".into(),
            m_kib: 65_536,
            t: 2,
            p: 1,
            target_bits: 18,
            ttl_secs: 120,
            auto_tune: true,
            auto_tune_min_bits: 10,
            auto_tune_max_bits: 24,
        };
        // Idle — should be at min.
        let idle = issue_challenge(&config, "login", "1.1.1.1", 1, 0).unwrap();
        assert_eq!(idle.challenge.target_bits, 10);
        // Moderate load — roughly midway.
        let mid = issue_challenge(&config, "login", "1.1.1.1", 1, 25).unwrap();
        assert!(mid.challenge.target_bits >= 16 && mid.challenge.target_bits <= 18);
        // Peak load — should be at max.
        let peak = issue_challenge(&config, "login", "1.1.1.1", 1, 50).unwrap();
        assert_eq!(peak.challenge.target_bits, 24);
    }

    #[test]
    fn challenge_cache_hit_returns_same_challenge() {
        let config = ChallengeConfig {
            secret_key: "test-key".into(),
            m_kib: 65_536,
            t: 2,
            p: 1,
            target_bits: 18,
            ttl_secs: 120,
            auto_tune: false,
            auto_tune_min_bits: 10,
            auto_tune_max_bits: 24,
        };
        let issued = issue_challenge(&config, "login", "1.1.1.1", 1, 0).unwrap();
        let mut cache = ChallengeCache::new();
        cache.put("hash1", "login", issued.clone());
        let cached = cache.get("hash1", "login").unwrap();
        assert_eq!(cached.challenge.nonce, issued.challenge.nonce);
        assert_eq!(cached.challenge.challenge, issued.challenge.challenge);
    }

    #[test]
    fn challenge_cache_miss_on_different_scope() {
        let config = ChallengeConfig {
            secret_key: "test-key".into(),
            m_kib: 65_536,
            t: 2,
            p: 1,
            target_bits: 18,
            ttl_secs: 120,
            auto_tune: false,
            auto_tune_min_bits: 10,
            auto_tune_max_bits: 24,
        };
        let issued = issue_challenge(&config, "login", "1.1.1.1", 1, 0).unwrap();
        let mut cache = ChallengeCache::new();
        cache.put("hash1", "login", issued);
        assert!(cache.get("hash1", "signup").is_none());
    }
}
