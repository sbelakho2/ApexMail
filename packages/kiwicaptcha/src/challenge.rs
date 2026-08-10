//! Challenge issuance for KiwiCaptcha.
//!
//! A challenge is an HMAC-signed, nonce-stamped, IP-bound token that the client
//! must fold into a proof-of-work. The signature binds the challenge
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

/// The proof-of-work algorithm a challenge uses.
///
/// The algorithm is decided at issuance time and carried explicitly on both
/// the wire (`IssuedChallenge.algorithm`) and the stored record
/// (`ChallengeRecord.algorithm`), so the solver and the verifier can never
/// disagree about which computation to perform — a numeric `m_kib` flag was
/// previously used as an implicit mode switch, which broke every challenge
/// once the two sides interpreted it differently.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PoWAlgorithm {
    /// Classic CPU-bound SHA-256 PoW: fast to verify, difficulty up to
    /// [`SOLVER_MAX_TARGET_BITS`].
    Sha256,
    /// Memory-hard Argon2id PoW: ASIC/GPU resistant, difficulty capped at
    /// [`SOLVER_MAX_ARGON2_TARGET_BITS`] because every hash is expensive.
    Argon2id,
}

impl PoWAlgorithm {
    pub fn as_str(&self) -> &'static str {
        match self {
            PoWAlgorithm::Sha256 => "sha256",
            PoWAlgorithm::Argon2id => "argon2id",
        }
    }
}

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
    /// The proof-of-work algorithm this challenge was issued with. A mode
    /// switch based on a numeric flag is rejected by design — the verifier
    /// only ever computes what the record says.
    pub algorithm: PoWAlgorithm,
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
    /// The minimum plausible solve time in milliseconds for the issued
    /// difficulty, computed at issuance from the algorithm and target bits.
    /// Solutions reporting less than this are physically implausible and
    /// rejected. An override (e.g. operator tuning) replaces the computed
    /// value; 0 disables the check.
    pub min_duration_ms: u64,
}

/// Configuration for the challenge issuer. Mirrors the server config block but
/// kept as a plain struct so this crate has no dependency on the api-server
/// config types.
#[derive(Debug, Clone)]
pub struct ChallengeConfig {
    /// HMAC secret key (server-side). Challenges signed with this key cannot
    /// be verified by a server using a different key.
    pub secret_key: String,
    /// The proof-of-work algorithm to issue. If [`PoWAlgorithm::Sha256`], the
    /// memory-hard parameters below are ignored and `target_bits` is used.
    pub algorithm: PoWAlgorithm,
    /// Memory cost in KiB for Argon2id challenges (ignored for SHA-256).
    /// Must satisfy `m_kib >= 8 * p` (Argon2 minimum) and be browser-solvable.
    pub m_kib: u32,
    /// Time cost for Argon2id challenges.
    pub t: u32,
    /// Parallelism for Argon2id challenges.
    pub p: u32,
    /// Required leading zero bits in the hash output. For SHA-256 this is the
    /// primary difficulty; for Argon2id the effective difficulty is
    /// `argon2_target_bits` (see below) because every Argon2 hash is ~1000x
    /// more expensive than SHA-256.
    pub target_bits: u32,
    /// Difficulty (leading zero bits) for Argon2id challenges. Clamped to
    /// [`SOLVER_MAX_ARGON2_TARGET_BITS`] so the widget can always finish.
    pub argon2_target_bits: u32,
    /// Challenge lifetime in seconds.
    pub ttl_secs: u64,
    /// Minimum plausible solve time in ms. When `Some`, it replaces the
    /// difficulty-derived minimum for every issued challenge; `None` means
    /// derive it from the algorithm + difficulty. `Some(0)` disables the check.
    pub min_duration_ms: Option<u64>,
    /// When enabled, `target_bits` is automatically adjusted based on active
    /// solver load: higher load -> higher difficulty; idle -> lower difficulty.
    /// Only applies to SHA-256 challenges; Argon2id difficulty is static.
    pub auto_tune: bool,
    /// Minimum target bits when auto-tuning is idle (no load).
    pub auto_tune_min_bits: u32,
    /// Maximum target bits when auto-tuning is under peak load.
    pub auto_tune_max_bits: u32,
}

impl ChallengeConfig {
    /// Compute the adjusted SHA-256 target bits based on current active solver
    /// count. When `auto_tune` is disabled, returns the static `target_bits`.
    /// Otherwise linearly interpolates between `auto_tune_min_bits` (0 active)
    /// and `auto_tune_max_bits` (50+ active solvers).
    ///
    /// The result is clamped to [`SOLVER_MAX_TARGET_BITS`] so the issued
    /// difficulty always stays within what the browser solver can finish.
    pub fn tuned_target_bits(&self, active_solves: u64) -> u32 {
        // Both bounds are clamped to the solver ceiling; the upper bound is
        // re-raised to at least the lower bound so the interpolation range
        // never inverts under misconfiguration.
        let min_bits = self.auto_tune_min_bits.min(SOLVER_MAX_TARGET_BITS);
        let max_bits = self
            .auto_tune_max_bits
            .min(SOLVER_MAX_TARGET_BITS)
            .max(min_bits);
        if !self.auto_tune {
            return self.target_bits.clamp(min_bits, max_bits);
        }
        let load = (active_solves as f64 / 50.0).min(1.0);
        let range = max_bits.saturating_sub(min_bits) as f64;
        let adjusted = min_bits as f64 + load * range;
        adjusted as u32
    }

    /// The effective difficulty for the configured algorithm.
    pub fn effective_target_bits(&self, active_solves: u64) -> u32 {
        match self.algorithm {
            PoWAlgorithm::Sha256 => self.tuned_target_bits(active_solves),
            PoWAlgorithm::Argon2id => self.argon2_target_bits.min(SOLVER_MAX_ARGON2_TARGET_BITS),
        }
    }

    /// Derive the minimum plausible solve time (ms) for the issued difficulty.
    ///
    /// The floor is set so it only rejects solutions that arrive faster than
    /// any real device could compute the work:
    /// - SHA-256: assumes up to 5e9 hashes/sec (beyond any browser; catches
    ///   hardware-accelerated/precomputed solves) with an absolute 5 ms floor.
    /// - Argon2id: assumes up to 5e5 hashes/sec (memory-hard; the wasm solver
    ///   manages ~1e3-1e4/s), floor 50 ms.
    pub fn min_duration_ms_for(&self, target_bits: u32) -> u64 {
        let expected_hashes = 1u64 << target_bits.min(32);
        match self.algorithm {
            PoWAlgorithm::Sha256 => {
                let ms = (expected_hashes as f64 / 5e9 * 1000.0).ceil() as u64;
                ms.max(5)
            }
            PoWAlgorithm::Argon2id => {
                let ms = (expected_hashes as f64 / 5e5 * 1000.0).ceil() as u64;
                ms.max(50)
            }
        }
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
/// Entries older than 1 second are pruned lazily on every `get` and `put`,
/// so the map never accumulates stale entries (bounded by the number of
/// distinct IP+scope pairs seen within the 1-second window).
pub struct ChallengeCache {
    entries: HashMap<String, (Issued, Instant)>,
    /// Fresh entries survive up to this age before being pruned.
    ttl: Duration,
}

/// Maximum difficulty the in-browser SHA-256 solver can reliably complete.
///
/// The widget solver (`packages/kiwicaptcha/src/widget.rs`) caps its search
/// at `MAX = 5_000_000` hashes. At `n` target bits the expected work is
/// `2^n` hashes; at 20 bits that is ~1.05M (P(solve) ≈ 99.1% within the cap),
/// while at 24 bits it is ~16.7M (P(solve) ≈ 25.9% — ~74% of users would
/// fail). Difficulty is therefore clamped to this ceiling so the auto-tuner
/// can never issue a challenge the widget cannot solve.
pub const SOLVER_MAX_TARGET_BITS: u32 = 20;

/// Maximum difficulty for Argon2id challenges.
///
/// Every Argon2id hash is memory-hard and costs tens of milliseconds in the
/// browser (vs ~nanoseconds for SHA-256), so the difficulty must be far lower.
/// At 10 bits the expected work is 1024 hashes (~10-60 s at 8-64 MiB memory),
/// which is the practical ceiling for an interactive widget.
pub const SOLVER_MAX_ARGON2_TARGET_BITS: u32 = 10;

/// Hard upper bound on Argon2id memory cost (KiB) that a browser widget can be
/// expected to allocate. 64 MiB keeps the WASM heap (and the server's verify
/// memory) within reason while still being memory-hard against ASICs/GPUs.
pub const SOLVER_MAX_ARGON2_M_KIB: u32 = 65536;

/// Expected hashes a browser solver can attempt per second (SHA-256, WASM).
/// Used to derive the per-challenge minimum solve duration.
pub const SHA256_SOLVER_HASHES_PER_SEC: f64 = 5e9;

/// Expected hashes per second for the Argon2id wasm solver at moderate memory
/// (8-64 MiB). Used to derive the per-challenge minimum solve duration.
pub const ARGON2_SOLVER_HASHES_PER_SEC: f64 = 5e5;

impl ChallengeCache {
    pub fn new() -> Self {
        ChallengeCache {
            entries: HashMap::new(),
            ttl: Duration::from_secs(1),
        }
    }

    /// A `ChallengeCache` with a custom entry lifetime (for tests).
    fn with_ttl(ttl: Duration) -> Self {
        ChallengeCache {
            entries: HashMap::new(),
            ttl,
        }
    }

    fn cache_key(ip_hash: &str, scope: &str) -> String {
        format!("{ip_hash}|{scope}")
    }

    fn is_fresh(&self, ts: &Instant) -> bool {
        ts.elapsed() < self.ttl
    }

    pub fn get(&mut self, ip_hash: &str, scope: &str) -> Option<&Issued> {
        let key = Self::cache_key(ip_hash, scope);
        if let Some((_, ts)) = self.entries.get(&key) {
            if self.is_fresh(ts) {
                return self.entries.get(&key).map(|(issued, _)| issued);
            }
            // Stale entry: remove it now so the map stays self-pruning.
            self.entries.remove(&key);
        }
        None
    }

    pub fn put(&mut self, ip_hash: &str, scope: &str, issued: Issued) {
        // Opportunistic pruning keeps the map bounded when many distinct
        // clients request challenges in quick succession.
        if self.entries.len() >= 256 {
            self.prune();
        }
        let key = Self::cache_key(ip_hash, scope);
        self.entries.insert(key, (issued, Instant::now()));
    }

    pub fn prune(&mut self) {
        // Capture `now` once to avoid borrowing `self` immutably inside the
        // retain closure while `self.entries` is borrowed mutably (E0502 on
        // newer rustc versions).
        let ttl = self.ttl;
        self.entries
            .retain(|_, (_, ts)| ts.elapsed() < ttl);
    }

    /// Number of cached entries (for tests/metrics).
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
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
    let algorithm = config.algorithm;
    let target_bits = config.effective_target_bits(active_solves);
    // Argon2id minimum memory is 8 * p KiB; reject configurations that could
    // never produce a valid hash instead of failing every verification later.
    if algorithm == PoWAlgorithm::Argon2id && config.m_kib < 8 * config.p {
        return Err(SignError::InvalidArgon2Params);
    }

    let payload = ChallengePayload {
        nonce: nonce.clone(),
        scope: scope.to_string(),
        ip_hash: ip_hash.clone(),
        issued_at: now_unix,
    };
    let signature = sign_payload(&payload, &config.secret_key)?;

    // The challenge string the client folds into the hash: it contains the
    // signed payload so a client cannot tamper with nonce/scope/ip/issued_at
    // without invalidating the signature.
    let challenge = format!("{}.{}", B64.encode(canonical_signing_input(&payload)), signature);

    // The prefix binds the client's counter input to this exact challenge.
    let prefix = format!("{challenge}|{salt}|");

    let expires_at = now_unix.saturating_add(config.ttl_secs);

    // Minimum plausible solve duration: derived from the issued difficulty, or
    // replaced by an operator override (Some(0) disables the check).
    let min_duration_ms = config
        .min_duration_ms
        .unwrap_or_else(|| config.min_duration_ms_for(target_bits));

    let record = ChallengeRecord {
        nonce: nonce.clone(),
        scope: scope.to_string(),
        ip_hash,
        issued_at: now_unix,
        expires_at,
        algorithm,
        m_kib: config.m_kib,
        t: config.t,
        p: config.p,
        target_bits,
        salt: salt.clone(),
        prefix: prefix.clone(),
        challenge: challenge.clone(),
        min_duration_ms,
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
        algorithm,
        min_duration_ms,
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
    #[error("Argon2id parameters are invalid (m_kib must be >= 8 * p)")]
    InvalidArgon2Params,
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
            algorithm: PoWAlgorithm::Sha256,
            m_kib: 65_536,
            argon2_target_bits: 8,
            min_duration_ms: None,
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
            algorithm: PoWAlgorithm::Sha256,
            m_kib: 65_536,
            t: 2,
            p: 1,
            target_bits: 18,
            argon2_target_bits: 8,
            min_duration_ms: None,
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
            algorithm: PoWAlgorithm::Sha256,
            m_kib: 65_536,
            t: 2,
            p: 1,
            target_bits: 18,
            argon2_target_bits: 8,
            min_duration_ms: None,
            ttl_secs: 120,
            auto_tune: true,
            auto_tune_min_bits: 10,
            auto_tune_max_bits: 24,
        };
        // Idle — should be at min.
        let idle = issue_challenge(&config, "login", "1.1.1.1", 1, 0).unwrap();
        assert_eq!(idle.challenge.target_bits, 10);
        // Moderate load — roughly midway between min and the solver ceiling.
        let mid = issue_challenge(&config, "login", "1.1.1.1", 1, 25).unwrap();
        assert!(mid.challenge.target_bits >= 14 && mid.challenge.target_bits <= 16);
        // Peak load — clamped to SOLVER_MAX_TARGET_BITS (not 24), because the
        // browser solver's 5M-hash cap would fail ~74% of solves at 24 bits.
        let peak = issue_challenge(&config, "login", "1.1.1.1", 1, 50).unwrap();
        assert_eq!(peak.challenge.target_bits, SOLVER_MAX_TARGET_BITS);
    }

    #[test]
    fn auto_tune_never_exceeds_solver_cap_even_without_tuning() {
        let config = ChallengeConfig {
            secret_key: "test-key".into(),
            algorithm: PoWAlgorithm::Sha256,
            m_kib: 65_536,
            t: 2,
            p: 1,
            target_bits: 24,
            argon2_target_bits: 8,
            min_duration_ms: None,
            ttl_secs: 120,
            auto_tune: false,
            auto_tune_min_bits: 10,
            auto_tune_max_bits: 24,
        };
        let issued = issue_challenge(&config, "login", "1.1.1.1", 1, 0).unwrap();
        assert_eq!(issued.challenge.target_bits, SOLVER_MAX_TARGET_BITS);
        assert_eq!(issued.record.target_bits, SOLVER_MAX_TARGET_BITS);
    }

    #[test]
    fn challenge_cache_prunes_stale_entries_on_get() {
        let mut cache = ChallengeCache::with_ttl(Duration::from_millis(20));
        let issued = issue_challenge(
            &ChallengeConfig {
                secret_key: "test-key".into(),
                algorithm: PoWAlgorithm::Sha256,
                m_kib: 65_536,
                argon2_target_bits: 8,
                min_duration_ms: None,
                t: 2,
                p: 1,
                target_bits: 18,
                ttl_secs: 120,
                auto_tune: false,
                auto_tune_min_bits: 10,
                auto_tune_max_bits: 24,
            },
            "login",
            "1.1.1.1",
            1,
            0,
        )
        .unwrap();
        cache.put("hash1", "login", issued);
        assert_eq!(cache.len(), 1);
        // Within the TTL the entry is served…
        assert!(cache.get("hash1", "login").is_some());
        assert_eq!(cache.len(), 1, "fresh entry must survive get");
        // …and once stale it is removed (pruned) on access.
        std::thread::sleep(Duration::from_millis(40));
        assert!(cache.get("hash1", "login").is_none());
        assert_eq!(cache.len(), 0, "stale entry must be pruned by get");
    }

    #[test]
    fn challenge_cache_put_prunes_expired_entries() {
        let mut cache = ChallengeCache::with_ttl(Duration::from_millis(20));
        let config = ChallengeConfig {
            secret_key: "test-key".into(),
            algorithm: PoWAlgorithm::Sha256,
            m_kib: 65_536,
            t: 2,
            p: 1,
            target_bits: 18,
            argon2_target_bits: 8,
            min_duration_ms: None,
            ttl_secs: 120,
            auto_tune: false,
            auto_tune_min_bits: 10,
            auto_tune_max_bits: 24,
        };
        let issued = issue_challenge(&config, "login", "1.1.1.1", 1, 0).unwrap();
        cache.put("old", "login", issued);
        std::thread::sleep(Duration::from_millis(40));
        let issued2 = issue_challenge(&config, "signup", "1.1.1.1", 1, 0).unwrap();
        cache.put("new", "signup", issued2);
        // The expired "old" entry must not linger after put.
        assert!(cache.get("old", "login").is_none());
        assert!(cache.get("new", "signup").is_some());
    }

    #[test]
    fn challenge_cache_hit_returns_same_challenge() {
        let config = ChallengeConfig {
            secret_key: "test-key".into(),
            algorithm: PoWAlgorithm::Sha256,
            m_kib: 65_536,
            t: 2,
            p: 1,
            target_bits: 18,
            argon2_target_bits: 8,
            min_duration_ms: None,
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
            algorithm: PoWAlgorithm::Sha256,
            m_kib: 65_536,
            t: 2,
            p: 1,
            target_bits: 18,
            argon2_target_bits: 8,
            min_duration_ms: None,
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
