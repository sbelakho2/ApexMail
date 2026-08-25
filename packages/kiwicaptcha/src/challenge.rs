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
use std::net::IpAddr;
use std::time::{Duration, Instant};

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use hmac::{Hmac, Mac};
/// OS-backed cryptographic randomness for all security identities
/// (nonce, Argon salt, request bindings, lease ids). Failures are
/// propagated — challenge creation must fail rather than fall back to a
/// weak generator.
pub fn security_random<const N: usize>() -> Result<[u8; N], getrandom::Error> {
    let mut buf = [0u8; N];
    getrandom::getrandom(&mut buf)?;
    Ok(buf)
}
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::keys::DerivedKeys;
use crate::profile::{ChallengeProfile, ProfileError};
use crate::token::IssuedChallenge;
use crate::verify::RequestBindingExpectation;

type HmacSha256 = Hmac<Sha256>;

/// The proof-of-work algorithm a challenge uses.
///
/// The algorithm is decided at issuance time and carried explicitly on both
/// the wire (`IssuedChallenge.algorithm`) and the stored record
/// (`ChallengeRecord.algorithm`), so the solver and the verifier can never
/// disagree about which computation to perform — a numeric mode flag would
/// leave room for the two sides to interpret it differently.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PoWAlgorithm {
    /// Classic CPU-bound SHA-256 PoW: extremely cheap server verification,
    /// difficulty up to the solver's target-bits ceiling.
    Sha256,
    /// Memory-hard Argon2id PoW: increases the cost of massively parallel and
    /// specialized solving, difficulty capped at the argon2 solver target
    /// ceiling because every hash is expensive.
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

/// The signed payload embedded inside a challenge string (protocol v1).
///
/// This is what gets HMAC-signed and base64-encoded into
/// [`IssuedChallenge::challenge`] for `protocol_version == 1` records. The
/// verifier reconstructs this from the nonce + the stored [`ChallengeRecord`]
/// and re-checks the signature. Protocol v2 records sign the full parameter
/// set instead (see [`ChallengeRecord`]); this struct's `ip_hash` field holds
/// the same slot (legacy v1 name) but v2 records use `binding_tag`.
#[derive(Debug, Clone)]
pub struct ChallengePayload {
    /// 32 random bytes, base64-encoded. Acts as the single-use token id.
    pub nonce: String,
    /// The auth scope this challenge is valid for (e.g. "login", "signup").
    pub scope: String,
    /// Legacy v1 binding value (SHA-256 of the client IP, hex) — for v2
    /// records this slot carries the nonce-bound `binding_tag` instead.
    pub ip_hash: String,
    /// Unix timestamp (seconds) when the challenge was issued.
    pub issued_at: u64,
}

/// Whether a challenge is bound to the issuing client IP.
///
/// When [`BindingMode::Bound`], the record's `binding_tag` is a nonce-bound
/// HMAC over the canonical IP bytes (no stable IP-derived identifier: the tag
/// changes with every nonce). When [`BindingMode::None`], the record's
/// `binding_tag` is empty and verification skips the binding check entirely.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BindingMode {
    /// Bind the challenge to the issuing client IP (nonce-bound HMAC tag).
    Bound,
    /// No binding: `binding_tag = ""`, verification skips the check.
    None,
}

/// Server-side state persisted in Redis, keyed by `kcaptcha:{nonce}`.
///
/// Stored alongside (but separately from) the signed challenge string sent to
/// the client. The verifier reads this to check TTL, IP binding, and to mark
/// the challenge consumed (single-use).
///
/// # Cross-language record interchange
///
/// The serde JSON of this struct is the cross-language storage schema; PHP's
/// `ChallengeRecord::toArray()` emits identical keys (nonce, scope,
/// binding_tag, issued_at, expires_at, algorithm 'sha256'|'argon2id', m_kib,
/// t, p, target_bits, salt, prefix, challenge, min_duration_ms, issued_at_ns,
/// attempts_used optional, protocol_version, region, policy_version,
/// request_binding, issuer, kid, hostname). Both languages write and
/// read this exact shape, so a record persisted by PHP can be verified by
/// Rust and vice versa.
///
/// # Protocol versions
///
/// - `protocol_version == 1` (legacy): signed with the v1 canonical input
///   `nonce|scope|ip_hash|issued_at`; `binding_tag` carries the legacy
///   `hash_ip` value (the sha256 digest of secret and ip) and reads the legacy `ip_hash` JSON
///   key via serde alias. Kept verifiable for the migration window (max TTL).
/// - `protocol_version == 2` (current): signed with the v2 full-parameter
///   canonical input and a nonce-bound `binding_tag`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChallengeRecord {
    pub nonce: String,
    pub scope: String,
    /// Nonce-bound IP binding tag (hex HMAC over canonical IP bytes) for v2
    /// records; legacy `hash_ip` value for v1 records. Empty when binding is
    /// disabled (`BindingMode::None`) — verification then skips the check.
    /// The JSON key is `binding_tag`; `ip_hash` is accepted on read for
    /// legacy stored records.
    #[serde(alias = "ip_hash")]
    pub binding_tag: String,
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
    /// The signed challenge string — `base64(payload)` plus `.signature` —
    /// stored so the verifier can re-check the HMAC without re-parsing the
    /// prefix.
    pub challenge: String,
    /// The minimum plausible solve time in milliseconds for the issued
    /// difficulty, computed at issuance from the algorithm and target bits.
    /// The floor is a timing-anomaly heuristic, not a proof of human
    /// behavior: proof-of-work is probabilistic (a valid solution can occur
    /// at counter 0) and a fast bot can wait before submitting, so the floor
    /// only rejects solves that arrive faster than the theoretical minimum
    /// (measured server-side from issuance to receipt). An override (e.g.
    /// operator tuning) replaces the computed value; 0 disables the check.
    pub min_duration_ms: u64,
    /// High-resolution (epoch microseconds, not nanoseconds) server-side
    /// issuance timestamp from `SystemTime::now`, in microseconds.
    /// This is used to enforce the minimum-duration check with
    /// a SERVER-measured elapsed time — the client-reported duration is
    /// forgeable and is only used as telemetry. It is server-side state only
    /// (never signed into the canonical payload, never sent to the client);
    /// a zero value is rejected as malformed (`MissingIssuedAtNs`) — there is
    /// no fallback to the attacker-controlled client duration; the verifier
    /// is strict.
    /// The name keeps the `_ns` suffix for backward compatibility
    /// with stored records; the unit is microseconds and is shared with PHP
    /// (`ChallengeRecord` JSON interchange).
    #[serde(default)]
    pub issued_at_ns: u64,
    /// Number of verification attempts already made against this challenge
    /// (server-side only, incremented by `verify_solution`). Used with
    /// `VerifyContext::max_attempts` to bound the cost of wrong candidates.
    #[serde(default)]
    pub attempts_used: u32,
    /// Protocol version: 1 = legacy v1 canonical signing + legacy `ip_hash`
    /// binding; 2 = v2 full-parameter signing + nonce-bound `binding_tag`.
    /// New records are issued with 2; 1 is the serde default so stored
    /// pre-v2 records keep verifying during the migration window (max TTL).
    #[serde(default = "default_protocol_version")]
    pub protocol_version: u8,
    /// Region the challenge was issued for. It is an authenticated field of
    /// the v2 canonical payload (`...|min_duration_ms|region|policy_version|
    /// ...` is the signed input), so it is recoverable from the
    /// client-visible challenge (base64 of the canonical payload) — it is
    /// simply not separately exposed as a top-level response property. The
    /// JSON key is always present for v2 records — `null` when the challenge
    /// is region-unbound — for byte parity with the PHP `toArray()` key set.
    /// Absent in legacy stored records: `#[serde(default)]`.
    #[serde(default)]
    pub region: Option<String>,
    /// Security-policy epoch that authorized this challenge (signed). On
    /// redemption the current security policy version must match — bumping
    /// it (origin/action-policy changes, emergency revocation, compromised
    /// tenant) immediately invalidates outstanding challenges. Cosmetic
    /// configuration changes must NOT bump it.
    #[serde(default = "default_policy_version")]
    pub policy_version: u32,
    /// Application-supplied transaction binding: a random nonce the host
    /// application generates and must present again on the final protected
    /// POST — turning a Kiwi result from "permission to perform action X
    /// somewhere" into "permission to continue this transaction".
    #[serde(default)]
    pub request_binding: Option<String>,
    /// Deployment identity of the issuing application (e.g. "auth-gateway",
    /// "signup-eu-1"). Signed into the v2 canonical payload (the
    /// field before the final `kid`) so a challenge minted for one audience
    /// cannot be redeemed in front of another verifier; a verifier configured
    /// with an expected issuer rejects records whose issuer differs — or that
    /// carry no issuer at all (fail closed). The JSON key is always present
    /// for v2 records — `null` when unset — for byte parity with the PHP
    /// `toArray()` key set. Absent in legacy stored records:
    /// `#[serde(default)]`.
    #[serde(default)]
    pub issuer: Option<String>,
    /// Server-side issuance metadata: the Host the challenge was
    /// issued for, when the issuing application provides it. Used by the
    /// provider-compatible Siteverify response (`hostname` field); never
    /// signed into the canonical payload and never sent to the client. The
    /// JSON key is always present — `null` when unset — for byte parity
    /// with the PHP `toArray()` key set. Absent in legacy stored
    /// records: `#[serde(default)]`.
    #[serde(default)]
    pub hostname: Option<String>,
    /// Key identifier of the signing secret this challenge was issued with.
    /// The final v2 canonical field (`|<kid>` after the issuer);
    /// a verifier configured with a `secrets_by_kid` map selects the signing
    /// secret by this id and rejects unknown ids with
    /// [`crate::verify::VerifyError::UnknownKid`] — plus the forward guard: a
    /// record whose kid exceeds the verifier's newest configured kid is
    /// rejected even if the key were somehow known, so future-keyed
    /// challenges never verify on older nodes. The JSON key is always
    /// present (default 1), so records stored without a key id
    /// keep verifying unchanged. Shared with the PHP core.
    #[serde(default = "default_kid")]
    pub kid: u32,
}

fn default_kid() -> u32 {
    1
}

fn default_policy_version() -> u32 {
    1
}

fn default_protocol_version() -> u8 {
    1
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
    /// Must satisfy `8 * p <= m_kib <= 65536` (the Argon2 minimum and the
    /// browser-wasm memory ceiling) and be browser-solvable.
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
    /// Difficulty (leading zero bits) for Argon2id challenges. Must be
    /// 1..=10 — 0 and values above the ceiling
    /// are rejected at issuance (the value is also defensively clamped in
    /// [`ChallengeConfig::effective_target_bits`] so the widget can always
    /// finish).
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
    /// Whether issued challenges are bound to the client IP
    /// ([`BindingMode::Bound`]) or not ([`BindingMode::None`], which stores an
    /// empty `binding_tag` and skips the binding check at verification).
    pub binding_mode: BindingMode,
    /// Security-policy epoch stamped into every issued challenge. The
    /// verifier rejects records whose policy_version differs from the
    /// configured current version (see the record field docs).
    pub policy_version: u32,
    /// Region the issued challenge is bound to (e.g. "eu", "us-east-1").
    /// Carried on the record's `region` key (always present in the record
    /// JSON, `null` when `None`) and enforced by a verifier configured with
    /// an expected region ([`VerifyError::WrongRegion`]). An authenticated
    /// canonical v2 parameter: signed into the challenge and therefore
    /// client-decodable from its canonical payload — but never separately
    /// exposed as a top-level response property.
    pub region: Option<String>,
    /// Issuer identity stamped into every issued challenge: a
    /// stable deployment string (e.g. "auth-gateway") signed as the v2
    /// canonical field before the final `kid`. A verifier configured with an
    /// expected issuer rejects records with a different — or missing —
    /// issuer ([`VerifyError::WrongIssuer`]).
    pub issuer: Option<String>,
    /// Key identifier of the signing secret. Stamped into every
    /// issued record and signed as the final v2 canonical field (`|<kid>`),
    /// so the verifier can rotate secrets: it picks the signing secret by
    /// this id from its `secrets_by_kid` map. Default 1. Must be >= 1.
    pub kid: u32,
}

impl ChallengeConfig {
    /// Compute the adjusted SHA-256 target bits based on current active solver
    /// count. When `auto_tune` is disabled, auto-tune bounds have NO effect —
    /// only the solver ceiling applies (`target_bits` capped at
    /// the solver maximum); a configured `target_bits` below the
    /// tuning bounds stays as-is. Otherwise linearly interpolates between
    /// `auto_tune_min_bits` (0 active) and `auto_tune_max_bits` (50+ active
    /// solvers).
    ///
    /// The result is clamped to the solver maximum so the issued
    /// difficulty always stays within what the browser solver can finish.
    pub fn tuned_target_bits(&self, active_solves: u64) -> u32 {
        if !self.auto_tune {
            return self.target_bits.min(SOLVER_MAX_TARGET_BITS);
        }
        // Both bounds are clamped to the solver ceiling; the upper bound is
        // re-raised to at least the lower bound so the interpolation range
        // never inverts under misconfiguration.
        let min_bits = self.auto_tune_min_bits.min(SOLVER_MAX_TARGET_BITS);
        let max_bits = self
            .auto_tune_max_bits
            .min(SOLVER_MAX_TARGET_BITS)
            .max(min_bits);
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
    /// The floor is a timing-anomaly heuristic: PoW is probabilistic (a valid
    /// solution can occur at counter 0) and a fast bot can wait before
    /// submitting, so the floor only rejects solves that arrive faster than
    /// the theoretical minimum, as measured by the server clock:
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

/// Compute the nonce-bound IP binding tag for a challenge.
///
/// `tag` is the hex encoding of `HMAC-SHA256(K_ip_bind, "kiwicaptcha/ip-bind/v2\\0" || nonce ||
/// "\\0" || family || canonical_ip_bytes)` where `family` is a single byte
/// `0x04` (IPv4) or `0x06` (IPv6), `canonical_ip_bytes` is the inet_pton
/// byte sequence with IPv4-mapped IPv6 addresses (`::ffff:a.b.c.d`) normalized
/// to 4-byte IPv4, and `K_ip_bind` is the HKDF-derived IP-binding purpose key
/// (see [`crate::keys::DerivedKeys`]; never the master secret
/// itself).
///
/// The tag is **nonce-bound**: the same IP produces a different tag for every
/// challenge, so the record creates no stable IP-derived identifier. An
/// unparsable IP string is rejected with [`SignError::InvalidIp`].
pub fn binding_tag(nonce: &str, ip: &str, secret: &str) -> Result<String, SignError> {
    if secret.len() < 16 {
        return Err(SignError::KeyTooShort);
    }
    let addr: IpAddr = ip.parse().map_err(|_| SignError::InvalidIp)?;
    let (family, canonical_bytes) = match addr {
        IpAddr::V4(v4) => (0x04u8, v4.octets().to_vec()),
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(mapped) => (0x04u8, mapped.octets().to_vec()),
            None => (0x06u8, v6.octets().to_vec()),
        },
    };
    let derived = DerivedKeys::from_master(secret, None);
    let key = derived.ip_bind_key();
    let mut mac = HmacSha256::new_from_slice(key).map_err(|_| SignError::KeyTooShort)?;
    mac.update(b"kiwicaptcha/ip-bind/v2");
    mac.update(&[0]);
    mac.update(nonce.as_bytes());
    mac.update(&[0]);
    mac.update(&[family]);
    mac.update(&canonical_bytes);
    Ok(hex::encode(&mac.finalize().into_bytes()))
}

/// The canonical current-time value for the `now_ns` parameter: epoch
/// microseconds (despite the `_ns` name).
///
/// This is the unit Rust and PHP share in the `issued_at_ns` record field,
/// so both sides must feed it the same way: the system clock's microseconds
/// since the Unix epoch.
pub fn now_epoch_micros() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_micros() as u64)
        .unwrap_or(0)
}

/// Whether `s` is a conforming identifier: non-empty and every
/// byte in `[A-Za-z0-9._:-]`, at most `max_len` bytes.
///
/// This is the narrow alphabet shared with the PHP core for `scope`,
/// `issuer`, `region` and `request_binding` — anything else (Unicode,
/// spaces, `|`, control bytes, the empty string) is rejected at issuance
/// ([`SignError`]) and by `validate_record`
/// ([`crate::verify::VerifyError::MalformedRecord`]).
pub(crate) fn valid_identifier(s: &str, max_len: usize) -> bool {
    !s.is_empty()
        && s.len() <= max_len
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b':' | b'-'))
}

/// The signed challenge string is `base64(canonical) || "." || hex(hmac)`.
/// The verifier reconstructs the canonical input from the nonce + stored
/// record and re-checks. We sign a canonical string so the binding is
/// unambiguous.
///
/// Protocol v1 canonical input (legacy records, `protocol_version == 1`):
/// `nonce|scope|ip_hash|issued_at`.
fn canonical_signing_input(payload: &ChallengePayload) -> String {
    format!(
        "{}|{}|{}|{}",
        payload.nonce, payload.scope, payload.ip_hash, payload.issued_at
    )
}

/// Protocol v2 canonical input (`protocol_version == 2`): the full parameter
/// set so no issuance parameter can be tampered with without breaking the
/// signature:
/// `v2|nonce|scope|binding_tag|issued_at|expires_at|algorithm|m_kib|t|p|target_bits|salt|min_duration_ms|region|policy_version|request_binding|issuer|kid`.
/// `region`, `request_binding` and `issuer` render as the empty segment when
/// unset; `kid` is the final field, appended after the issuer.
pub(crate) fn canonical_signing_input_v2(record: &ChallengeRecord) -> String {
    format!(
        "v2|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}",
        record.nonce,
        record.scope,
        record.binding_tag,
        record.issued_at,
        record.expires_at,
        record.algorithm.as_str(),
        record.m_kib,
        record.t,
        record.p,
        record.target_bits,
        record.salt,
        record.min_duration_ms,
        record.region.as_deref().unwrap_or(""),
        record.policy_version,
        record.request_binding.as_deref().unwrap_or(""),
        record.issuer.as_deref().unwrap_or(""),
        record.kid
    )
}

/// Sign a canonical input with the secret key, returning a hex HMAC tag
/// (protocol v1 legacy path — the master key is used directly; v2 records use
/// the HKDF-derived challenge key via [`sign_canonical_v2`]).
///
/// The secret key must be at least 16 bytes (the same minimum the PHP
/// implementation enforces); 32 random bytes is the recommended size. Shorter
/// keys are rejected with [`SignError::KeyTooShort`] before any hashing.
fn sign_canonical(canonical: &str, secret_key: &str) -> Result<String, SignError> {
    if secret_key.len() < 16 {
        return Err(SignError::KeyTooShort);
    }
    let mut mac =
        HmacSha256::new_from_slice(secret_key.as_bytes()).map_err(|_| SignError::KeyTooShort)?;
    mac.update(canonical.as_bytes());
    Ok(hex::encode(&mac.finalize().into_bytes()))
}

/// Sign a canonical input with the HKDF-derived challenge-signing purpose key
/// (`K_challenge` — protocol v2). The master secret is never used
/// directly as the signing key.
pub(crate) fn sign_canonical_v2(canonical: &str, secret_key: &str) -> Result<String, SignError> {
    if secret_key.len() < 16 {
        return Err(SignError::KeyTooShort);
    }
    let derived = DerivedKeys::from_master(secret_key, None);
    let key = derived.challenge_key();
    let mut mac = HmacSha256::new_from_slice(key).map_err(|_| SignError::KeyTooShort)?;
    mac.update(canonical.as_bytes());
    Ok(hex::encode(&mac.finalize().into_bytes()))
}

/// Sign the payload with the secret key, returning a hex HMAC tag
/// (protocol v1 canonical input; see [`ChallengePayload`]).
///
/// The secret key must be at least 16 bytes (the same minimum the PHP
/// implementation enforces); 32 random bytes is the recommended size. Shorter
/// keys are rejected with [`SignError::KeyTooShort`] before any hashing.
pub fn sign_payload(payload: &ChallengePayload, secret_key: &str) -> Result<String, SignError> {
    sign_canonical(&canonical_signing_input(payload), secret_key)
}

/// Verify that a signature matches the payload under the given key.
///
/// The key minimum from [`sign_payload`] (16 bytes) applies here too — a key
/// too short to have ever signed a valid challenge is rejected up front. The
/// comparison itself is done in constant time: the hex signature is decoded
/// to bytes and checked with `Mac::verify_slice`, which never short-circuits
/// on a mismatching prefix and processes the full tag regardless of the
/// inputs' relationship to the expected value.
pub fn verify_signature(
    payload: &ChallengePayload,
    signature: &str,
    secret_key: &str,
) -> Result<bool, SignError> {
    verify_canonical(&canonical_signing_input(payload), signature, secret_key)
}

/// Verify a signature over the protocol v2 canonical input of a record.
///
/// Same constant-time guarantee as [`verify_signature`]. The signature is
/// checked against the HKDF-derived challenge-signing key (`K_challenge`),
/// never the master secret directly.
pub fn verify_signature_v2(
    record: &ChallengeRecord,
    signature: &str,
    secret_key: &str,
) -> Result<bool, SignError> {
    verify_canonical_v2(&canonical_signing_input_v2(record), signature, secret_key)
}

fn verify_canonical(canonical: &str, signature: &str, secret_key: &str) -> Result<bool, SignError> {
    if secret_key.len() < 16 {
        return Err(SignError::KeyTooShort);
    }
    // The HMAC-SHA256 tag is exactly 64 hex characters — a
    // longer signature is rejected before any hex::decode allocation
    // (attacker-written oversized signature bytes never drive a decode
    // buffer).
    if signature.len() != 64 {
        return Ok(false);
    }
    let signature_bytes = match hex::decode(signature) {
        Some(bytes) => bytes,
        None => return Ok(false), // malformed signature can never match
    };
    let mut mac =
        HmacSha256::new_from_slice(secret_key.as_bytes()).map_err(|_| SignError::KeyTooShort)?;
    mac.update(canonical.as_bytes());
    Ok(mac.verify_slice(&signature_bytes).is_ok())
}

/// Verify a canonical input against the HKDF-derived challenge key (protocol
/// v2). Same constant-time guarantee as [`verify_canonical`].
fn verify_canonical_v2(
    canonical: &str,
    signature: &str,
    secret_key: &str,
) -> Result<bool, SignError> {
    if secret_key.len() < 16 {
        return Err(SignError::KeyTooShort);
    }
    // Exact 64-hex-char signature pre-bound before any
    // hex::decode allocation.
    if signature.len() != 64 {
        return Ok(false);
    }
    let signature_bytes = match hex::decode(signature) {
        Some(bytes) => bytes,
        None => return Ok(false), // malformed signature can never match
    };
    let derived = DerivedKeys::from_master(secret_key, None);
    let key = derived.challenge_key();
    let mut mac = HmacSha256::new_from_slice(key).map_err(|_| SignError::KeyTooShort)?;
    mac.update(canonical.as_bytes());
    Ok(mac.verify_slice(&signature_bytes).is_ok())
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
/// `2^n` hashes; at 20 bits that is ~1.05M (solve probability ≈ 99.1% within
/// the cap), while at 24 bits it is ~16.7M (solve probability ≈ 25.9% —
/// ~74% of users would fail). Difficulty is therefore clamped to this
/// ceiling so the auto-tuner can never issue a challenge the widget cannot
/// solve.
pub const SOLVER_MAX_TARGET_BITS: u32 = 20;

/// Hard floor on the difficulty (`target_bits`) the verifier accepts in a
/// signed record: 0 would accept a trivially-solvable challenge.
/// Shared with the PHP core.
pub const MIN_DIFFICULTY: u32 = 1;
/// Hard ceiling on the difficulty (`target_bits`) the verifier accepts in a
/// signed record: above the solver ceiling no legitimate widget
/// can finish. Applied to both algorithms by `validate_record` — Argon2id
/// issuance stays stricter at the argon2 solver ceiling, exactly like
/// the t=7..=16 verifier-vs-issuer split. Shared with the PHP core.
pub const MAX_DIFFICULTY: u32 = 20;

/// The maximum counter value any solver may legitimately produce (the widget
/// caps its search at 5M hashes, both WASM and the pure-JS fallback).
/// [`crate::token::SolutionToken::decode`] rejects counters above this bound,
/// and `verify_solution` accepts only solutions the solvers could produce.
pub const SOLVER_MAX_HASHES: u64 = 5_000_000;

/// Maximum challenge lifetime (seconds) a record may claim. Records with
/// `expires_at - issued_at` above this are malformed (they could otherwise
/// pin expensive server state for an unbounded window).
pub const MAX_TTL_SECS: u64 = 300;

/// Maximum tolerated clock skew (seconds) between the issuer and verifier
/// clocks. The TTL check rejects challenges whose `issued_at` is
/// more than this far in the future relative to the verifier's current time
/// — a future-issued challenge beyond the skew is a time-domain anomaly and
/// invalid. Shared with the PHP core.
pub const MAX_CLOCK_SKEW_SECS: u64 = 60;

/// Maximum Argon2id time cost at issuance (browser-solver policy): the
/// browser solver caps at 6, so higher values would be unsolvable for
/// legit clients and issuance refuses them. Distinct from the verifier's
/// structural ceiling of 16: `validate_record` accepts
/// signed records with t in 7..=16, but no KiwiCaptcha issuer mints them.
pub const MAX_ARGON_T: u32 = 6;

/// Maximum difficulty for Argon2id challenges.
///
/// Every Argon2id hash is memory-hard and costs tens of milliseconds in the
/// browser (vs ~nanoseconds for SHA-256), so the difficulty must be far lower.
/// At 10 bits the expected work is 1024 hashes (~10-60 s at 8-64 MiB memory),
/// which is the practical ceiling for an interactive widget.
pub const SOLVER_MAX_ARGON2_TARGET_BITS: u32 = 10;

/// Hard upper bound on Argon2id memory cost (KiB) that a browser widget can be
/// expected to allocate. 64 MiB keeps the WASM heap (and the server's verify
/// memory) within reason while still being memory-hard against specialized
/// hardware.
pub const SOLVER_MAX_ARGON2_M_KIB: u32 = 65536;

/// Hard floor on the Argon2id memory cost (KiB) the verifier accepts in a
/// signed record. Below this the record is malformed —
/// verification never runs a memory-hard computation with implausible
/// parameters. Shared with the PHP core.
pub const MIN_ARGON_MEMORY_KIB: u32 = 8;
/// Hard ceiling on the Argon2id memory cost (KiB) the verifier accepts in a
/// signed record. Matches the solver's argon2 memory ceiling; above it
/// the record is malformed before any allocation. Shared with the PHP core.
pub const MAX_ARGON_MEMORY_KIB: u32 = SOLVER_MAX_ARGON2_M_KIB;
/// Hard floor on the Argon2id time cost the verifier accepts in a signed
/// record: `t < 3` is not libsodium-representable. Shared with
/// the PHP core.
pub const MIN_ARGON_TIME: u32 = 3;
/// Hard ceiling on the Argon2id time cost the verifier accepts in a signed
/// record: above 16 the memory-hard computation is unbounded.
/// Shared with the PHP core.
pub const MAX_ARGON_TIME: u32 = 16;
/// Hard floor on the Argon2id parallelism the verifier accepts in a signed
/// record.
pub const MIN_PARALLELISM: u32 = 1;
/// Hard ceiling on the Argon2id parallelism the verifier accepts in a signed
/// record.
pub const MAX_PARALLELISM: u32 = 4;

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

    /// A `ChallengeCache` with a custom entry lifetime (tests only).
    #[cfg(test)]
    fn with_ttl_for_test(ttl: Duration) -> Self {
        ChallengeCache {
            entries: HashMap::new(),
            ttl,
        }
    }

    /// Deterministically age every cached entry (tests only) — replaces
    /// `thread::sleep`-based expiry tests, which are flaky under CI load
    /// (a preemption longer than a tiny test TTL makes a "fresh" assertion
    /// fail nondeterministically).
    #[cfg(test)]
    fn age_entries_for_test(&mut self, by: Duration) {
        for (_, ts) in self.entries.values_mut() {
            *ts = ts.checked_sub(by).unwrap_or(*ts);
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
        self.entries.retain(|_, (_, ts)| ts.elapsed() < ttl);
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
/// - `scope` — the auth flow ("login", "signup", "forgot-password", etc.);
///   must be 1..=128 bytes of `[A-Za-z0-9._:-]` — anything else
///   is rejected with [`SignError::InvalidScope`].
/// - `client_ip` — the client's IP address (hashed before storage).
/// - `now_unix` — current Unix timestamp in seconds (injected for
///   testability); used for the signed payload, TTL, and the client-facing
///   challenge.
/// - `now_ns` — high-resolution issuance timestamp in epoch microseconds
///   (see [`now_epoch_micros`]; the field name keeps the `_ns`
///   suffix but the unit is microseconds, shared with PHP), used exclusively
///   for server-side minimum-duration enforcement.
/// - `active_solves` — current number of active solvers (for auto-tuning).
/// - `request_binding` — the application-supplied transaction binding;
///   when set, must be 1..=128 bytes of `[A-Za-z0-9._:-]`
///   — anything else is rejected with
///   [`SignError::InvalidIdentifier`]. `config.region` (<= 64 bytes) and
///   `config.issuer` (<= 128 bytes) are validated the same way.
///
/// # Deployment note (aggregate DoS)
///
/// Per-nonce attempt caps ([`VerifyContext::max_attempts`]) bound repeated
/// verification of **one** challenge; they do not bound the aggregate memory
/// of concurrent verifications. Deployments must additionally rate-limit
/// challenge issuance and cap concurrent Argon2id verification (e.g. a
/// semaphore sized to the available memory), otherwise an attacker who mints
/// many challenges can still drive unbounded aggregate memory-hard work.
#[allow(clippy::too_many_arguments)]
pub fn issue_challenge(
    config: &ChallengeConfig,
    scope: &str,
    client_ip: &str,
    now_unix: u64,
    now_ns: u64,
    active_solves: u64,
    request_binding: Option<&str>,
) -> Result<Issued, SignError> {
    if !valid_identifier(scope, 128) {
        return Err(SignError::InvalidScope);
    }
    // issuer/region/request_binding share the narrow identifier
    // alphabet; a non-conforming value must never be minted into a record
    // (the verifier would reject it as malformed — and Unicode/space
    // identifiers would break the canonical payload's byte-contract).
    if let Some(issuer) = &config.issuer {
        if !valid_identifier(issuer, 128) {
            return Err(SignError::InvalidIdentifier);
        }
    }
    if let Some(region) = &config.region {
        if !valid_identifier(region, 64) {
            return Err(SignError::InvalidIdentifier);
        }
    }
    if let Some(binding) = request_binding {
        if !valid_identifier(binding, 128) {
            return Err(SignError::InvalidIdentifier);
        }
    }
    // 32-byte nonce.
    let mut nonce_bytes = [0u8; 32];
    nonce_bytes.copy_from_slice(&security_random::<32>().map_err(|_| SignError::Rng)?);
    let nonce = B64.encode(nonce_bytes);

    // 16-byte salt.
    let mut salt_bytes = [0u8; 16];
    salt_bytes.copy_from_slice(&security_random::<16>().map_err(|_| SignError::Rng)?);
    let salt = B64.encode(salt_bytes);

    let algorithm = config.algorithm;
    let target_bits = config.effective_target_bits(active_solves);
    // SHA-256 difficulty must be 1..=20: 0 would mint a
    // trivially-solvable challenge and anything above the solver ceiling can
    // never be solved by the widget. (Argon2id target bits are validated in
    // the block below.)
    if algorithm == PoWAlgorithm::Sha256
        && (target_bits == 0 || target_bits > SOLVER_MAX_TARGET_BITS)
    {
        return Err(SignError::InvalidDifficulty);
    }
    // Argon2id minimum memory is 8 * p KiB; reject configurations that could
    // never produce a valid hash instead of failing every verification later.
    // PHP/libsodium verification additionally cannot represent t < 3 or
    // p != 1, so those are rejected at issuance too — otherwise a challenge
    // could be issued successfully and then always fail PHP verification
    // (cross-language parity requirement). Issuance must never mint a record
    // the verifier would reject: m_kib above the browser-wasm memory
    // ceiling (64 MiB) is refused, t above the issuance ceiling is refused
    // (validate_record rejects it), and argon2_target_bits must be within
    // the argon2 solver range (0 is silently clamped to 1 by
    // effective_target_bits today — reject it).
    if algorithm == PoWAlgorithm::Argon2id {
        if config.m_kib < 8 * config.p {
            return Err(SignError::InvalidArgon2Params);
        }
        if config.m_kib > SOLVER_MAX_ARGON2_M_KIB {
            return Err(SignError::InvalidArgon2Params);
        }
        if config.t < 3 || config.p != 1 || config.t > MAX_ARGON_T {
            return Err(SignError::InvalidArgon2Params);
        }
        if config.argon2_target_bits == 0
            || config.argon2_target_bits > SOLVER_MAX_ARGON2_TARGET_BITS
        {
            return Err(SignError::InvalidArgon2Params);
        }
    }

    // Issuance must never mint a record the verifier would reject: the
    // verifier's validate_record rejects any lifetime above the TTL cap
    // (300 s), so a longer configured TTL is refused here, not at
    // verification time.
    if config.ttl_secs == 0 || config.ttl_secs > MAX_TTL_SECS {
        return Err(SignError::InvalidTtl);
    }
    // min_duration_ms must be < ttl*1000: a floor at or above the TTL makes
    // every submission either TooFast or Expired — no valid solution time
    // exists (verification checks expiry before the floor).
    if let Some(ms) = config.min_duration_ms {
        if ms >= config.ttl_secs.saturating_mul(1000) {
            return Err(SignError::InvalidMinDuration);
        }
    }

    // Static difficulty must be valid as configured — clamping is NOT
    // acceptable for parity with PHP (which rejects target_bits > 20 at
    // construction). Auto-tune may still normalize its bounds at runtime,
    // but a static configuration is validated here.
    if algorithm == PoWAlgorithm::Sha256
        && (config.target_bits == 0 || config.target_bits > SOLVER_MAX_TARGET_BITS)
    {
        return Err(SignError::InvalidDifficulty);
    }

    // Nonce-bound IP binding tag (v2) — or empty when binding is disabled.
    let binding = match config.binding_mode {
        BindingMode::Bound => binding_tag(&nonce, client_ip, &config.secret_key)?,
        BindingMode::None => String::new(),
    };

    let expires_at = now_unix.saturating_add(config.ttl_secs);

    // Minimum plausible solve duration: derived from the issued difficulty, or
    // replaced by an operator override, where `Some(0)` disables the check.
    let min_duration_ms = config
        .min_duration_ms
        .unwrap_or_else(|| config.min_duration_ms_for(target_bits));

    // Protocol v2: sign the full-parameter canonical input so no issuance
    // parameter (algorithm, difficulty, TTL, salt, …) can be tampered with
    // without breaking the signature. The challenge string is
    // `base64(canonical).hex_tag` — same structure as v1. The signature is
    // computed with the HKDF-derived challenge key, never the
    // master secret directly.
    let mut record = ChallengeRecord {
        nonce: nonce.clone(),
        scope: scope.to_string(),
        binding_tag: binding.clone(),
        hostname: None,
        issued_at: now_unix,
        expires_at,
        algorithm,
        m_kib: config.m_kib,
        t: config.t,
        p: config.p,
        target_bits,
        salt: salt.clone(),
        prefix: String::new(),    // computed below once the challenge is signed
        challenge: String::new(), // computed below
        min_duration_ms,
        issued_at_ns: now_ns,
        attempts_used: 0,
        protocol_version: 2,
        region: config.region.clone(),
        policy_version: config.policy_version,
        request_binding: request_binding.map(str::to_string),
        issuer: config.issuer.clone(),
        kid: config.kid,
    };
    let canonical = canonical_signing_input_v2(&record);
    let signature = sign_canonical_v2(&canonical, &config.secret_key)?;
    let challenge = format!("{}.{}", B64.encode(&canonical), signature);
    record.challenge = challenge.clone();
    // The prefix binds the client's counter input to this exact challenge.
    record.prefix = format!("{challenge}|{salt}|");

    let challenge_token = IssuedChallenge {
        nonce: nonce.clone(),
        challenge,
        salt,
        m_kib: config.m_kib,
        t: config.t,
        p: config.p,
        target_bits,
        ttl_secs: config.ttl_secs,
        prefix: record.prefix.clone(),
        algorithm,
        min_duration_ms,
    };

    Ok(Issued {
        challenge: challenge_token,
        record,
    })
}

/// Issue a challenge from an adaptive-risk difficulty profile.
///
/// Builds a clone of `config` (the caller's config is never mutated):
/// `algorithm`, `m_kib`, `t`, `p`, and `target_bits` come from the profile,
/// and `argon2_target_bits` equals the profile's `target_bits` for Argon2id
/// profiles (SHA-256 profiles leave it as configured). `ttl_secs`,
/// `min_duration_ms`, auto-tuning, and `binding_mode` stay owned by `config`.
///
/// The profile is validated first ([`ChallengeProfile::validate`]);
/// an invalid profile is rejected before anything is issued. Delegates to
/// [`issue_challenge`], so the wire format, signing, and storage are
/// identical to a regular issue — only the parameters differ.
#[allow(clippy::too_many_arguments)]
pub fn issue_challenge_with_profile(
    config: &ChallengeConfig,
    scope: &str,
    client_ip: &str,
    now_unix: u64,
    now_ns: u64,
    active_solves: u64,
    profile: &ChallengeProfile,
    request_binding: Option<&str>,
) -> Result<Issued, SignError> {
    profile.validate().map_err(|e| match e {
        ProfileError::InvalidShaTargetBits(_) => SignError::InvalidDifficulty,
        _ => SignError::InvalidArgon2Params,
    })?;

    let mut effective = config.clone();
    effective.algorithm = profile.algorithm;
    effective.target_bits = profile.target_bits as u32;
    if profile.algorithm == PoWAlgorithm::Argon2id {
        effective.m_kib = profile.m_kib;
        effective.t = profile.t;
        effective.p = profile.p;
        effective.argon2_target_bits = profile.target_bits as u32;
    }
    issue_challenge(
        &effective,
        scope,
        client_ip,
        now_unix,
        now_ns,
        active_solves,
        request_binding,
    )
}

/// Reconstruct a [`ChallengePayload`] from a stored record, for signature
/// re-verification during solution validation.
pub fn payload_from_record(record: &ChallengeRecord) -> ChallengePayload {
    ChallengePayload {
        nonce: record.nonce.clone(),
        scope: record.scope.clone(),
        ip_hash: record.binding_tag.clone(),
        issued_at: record.issued_at,
    }
}

#[derive(Debug, thiserror::Error)]
pub enum SignError {
    /// The HMAC secret key must be at least 16 bytes (the PHP implementation
    /// enforces the same minimum); 32 random bytes is the recommended size.
    #[error("HMAC secret key is too short (minimum 16 bytes; 32 random bytes recommended)")]
    KeyTooShort,
    /// The OS cryptographic random source failed — challenge creation MUST
    /// fail rather than fall back to a weak generator.
    #[error("OS cryptographic randomness unavailable")]
    Rng,
    /// The auth scope must be 1..=128 bytes of `[A-Za-z0-9._:-]` (
    /// `|` is outside the alphabet, so a scope can never smuggle a canonical
    /// separator into the signed payload).
    #[error("scope must be 1..=128 bytes of [A-Za-z0-9._:-]")]
    InvalidScope,
    /// Issuer, region or request_binding must be non-empty and match the
    /// narrow identifier alphabet `[A-Za-z0-9._:-]` with the
    /// length caps: issuer <= 128 bytes, request_binding <= 128 bytes,
    /// region <= 64 bytes.
    #[error("issuer/region/request_binding must be non-empty and match [A-Za-z0-9._:-] with the length caps (issuer 128, request_binding 128, region 64)")]
    InvalidIdentifier,
    #[error("Argon2id parameters are invalid (m_kib must be >= 8 * p and <= SOLVER_MAX_ARGON2_M_KIB; for PHP/libsodium cross-verification t must be >= 3 and p == 1 and <= MAX_ARGON_T; argon2_target_bits must be 1..=SOLVER_MAX_ARGON2_TARGET_BITS)")]
    InvalidArgon2Params,
    /// The client IP string could not be parsed as an IPv4 or IPv6 address
    /// (raised by [`binding_tag`] when a nonce-bound binding tag is computed).
    #[error("client IP is not a valid IPv4 or IPv6 address")]
    InvalidIp,
    /// SHA-256 difficulty must be within the solver ceiling — 0 would
    /// mint a trivially-solvable challenge and values above the ceiling can
    /// never be solved by the widget.
    #[error("SHA-256 difficulty must be 1..=SOLVER_MAX_TARGET_BITS (20)")]
    InvalidDifficulty,
    #[error("challenge TTL must be 1..=MAX_TTL_SECS (300) — the verifier rejects longer lifetimes as malformed")]
    InvalidTtl,
    #[error("min_duration_ms must be < ttl_secs * 1000 — a floor at or above the TTL leaves no acceptable submission time")]
    InvalidMinDuration,
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

    /// Decode a hex string (lower- or upper-case) into bytes, or `None` if it
    /// has an odd length or contains a non-hex character.
    pub fn decode(s: &str) -> Option<Vec<u8>> {
        if !s.len().is_multiple_of(2) {
            return None;
        }
        let mut out = Vec::with_capacity(s.len() / 2);
        let mut high = None;
        for c in s.bytes() {
            let nibble = match c {
                b'0'..=b'9' => c - b'0',
                b'a'..=b'f' => c - b'a' + 10,
                b'A'..=b'F' => c - b'A' + 10,
                _ => return None,
            };
            match high.take() {
                Some(h) => out.push((h << 4) | nibble),
                None => high = Some(nibble),
            }
        }
        Some(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Test "now_ns" values are epoch microseconds (1_700_000_000_000_000 µs
    // ≈ 2023-11-14 UTC) — the unit the crate shares with PHP, see
    // [`now_epoch_micros`].

    #[test]
    fn issued_challenge_has_correct_difficulty() {
        let config = ChallengeConfig {
            secret_key: "super-secret-key".into(),
            kid: 1,
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
            binding_mode: BindingMode::Bound,
            region: None,
            issuer: None,

            policy_version: 1,
        };
        let issued = issue_challenge(
            &config,
            "login",
            "1.2.3.4",
            1_000_000,
            1_700_000_000_000_000,
            0,
            None,
        )
        .unwrap();
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
        assert!(issued
            .challenge
            .prefix
            .starts_with(&issued.challenge.challenge));
        // Record expiry = issued + ttl.
        assert_eq!(issued.record.expires_at, 1_000_120);
        // IP is bound via a nonce-bound HMAC tag, not stored raw.
        assert_ne!(issued.record.binding_tag, "1.2.3.4");
    }

    #[test]
    fn signatures_verify_round_trip() {
        let key = "this-is-a-16-byte-key";
        let payload = ChallengePayload {
            nonce: "n".into(),
            scope: "login".into(),
            ip_hash: hash_ip("9.9.9.9", key),
            issued_at: 123,
        };
        let sig = sign_payload(&payload, key).unwrap();
        assert!(verify_signature(&payload, &sig, key).unwrap());
        assert!(!verify_signature(&payload, &sig, "wrong-key-16-bytes").unwrap());
        // Tampering with the nonce breaks the signature.
        let mut tampered = payload.clone();
        tampered.nonce = "x".into();
        assert!(!verify_signature(&tampered, &sig, key).unwrap());
    }

    #[test]
    fn short_secret_key_is_rejected_before_signing() {
        let payload = ChallengePayload {
            nonce: "n".into(),
            scope: "login".into(),
            ip_hash: hash_ip("9.9.9.9", "key"),
            issued_at: 123,
        };
        for key in ["", "x", "0123456789abcde"] {
            // 0, 1 and 15 bytes — all below the 16-byte minimum.
            assert!(
                matches!(sign_payload(&payload, key), Err(SignError::KeyTooShort)),
                "key {key:?} must be rejected"
            );
            assert!(
                matches!(
                    verify_signature(&payload, "abc", key),
                    Err(SignError::KeyTooShort)
                ),
                "key {key:?} must be rejected"
            );
        }
        // Exactly 16 bytes is the minimum — accepted.
        let key16 = "0123456789abcdef";
        assert!(sign_payload(&payload, key16).is_ok());
        // 32 random bytes (recommended) — accepted.
        let key32 = "0123456789abcdef0123456789abcdef";
        assert!(sign_payload(&payload, key32).is_ok());
    }

    #[test]
    fn verify_signature_rejects_malformed_hex() {
        let payload = ChallengePayload {
            nonce: "n".into(),
            scope: "login".into(),
            ip_hash: hash_ip("9.9.9.9", "key"),
            issued_at: 123,
        };
        // A valid tag must verify…
        let sig = sign_payload(&payload, "this-is-a-16-byte-key").unwrap();
        assert!(verify_signature(&payload, &sig, "this-is-a-16-byte-key").unwrap());
        // …and an undecodable "signature" must be a mismatch, never an error.
        assert!(!verify_signature(&payload, "not-hex!", "this-is-a-16-byte-key").unwrap());
        assert!(!verify_signature(&payload, "abc", "this-is-a-16-byte-key").unwrap());
    }

    #[test]
    fn oversized_signature_is_rejected_before_hex_decode() {
        // The HMAC-SHA256 tag is exactly 64 hex characters — a
        // longer signature is rejected as a mismatch before any hex::decode
        // allocation (an attacker-written megabyte "signature" never drives
        // a decode buffer), on both the v1 and v2 canonical paths.
        let key = "0123456789abcdef0123456789abcdef";
        let payload = ChallengePayload {
            nonce: "n".into(),
            scope: "login".into(),
            ip_hash: hash_ip("9.9.9.9", key),
            issued_at: 123,
        };
        for len in [65usize, 128, 1_000_000] {
            let sig = "a".repeat(len);
            assert!(
                !verify_signature(&payload, &sig, key).unwrap(),
                "a {len}-char signature must not verify"
            );
        }
        let record = issue_challenge(
            &ChallengeConfig {
                secret_key: key.into(),
                kid: 1,
                algorithm: PoWAlgorithm::Sha256,
                m_kib: 0,
                t: 1,
                p: 1,
                target_bits: 4,
                argon2_target_bits: 4,
                ttl_secs: 120,
                min_duration_ms: None,
                auto_tune: false,
                auto_tune_min_bits: 8,
                auto_tune_max_bits: 20,
                binding_mode: BindingMode::Bound,
                region: None,
                issuer: None,
                policy_version: 1,
            },
            "login",
            "1.2.3.4",
            1_000_000,
            1_700_000_000_000_000,
            0,
            None,
        )
        .unwrap()
        .record;
        assert!(
            !verify_signature_v2(&record, &"b".repeat(1_000_000), key).unwrap(),
            "an oversized v2 signature must be rejected before hex decode"
        );
        assert!(
            verify_signature_v2(&record, &"b".repeat(64), key).is_ok_and(|ok| !ok),
            "a 64-char wrong signature is a plain mismatch"
        );
    }

    #[test]
    fn hex_decode_round_trips() {
        assert_eq!(hex::decode("").unwrap(), Vec::<u8>::new());
        assert_eq!(hex::decode("00ff").unwrap(), vec![0x00, 0xff]);
        assert_eq!(hex::decode("00FF").unwrap(), vec![0x00, 0xff]);
        assert_eq!(
            hex::decode(&hex::encode(b"kiwi")).unwrap(),
            b"kiwi".to_vec()
        );
        assert!(hex::decode("0").is_none(), "odd length must fail");
        assert!(hex::decode("0g").is_none(), "non-hex char must fail");
    }

    #[test]
    fn scope_length_ceiling_is_enforced() {
        let config = ChallengeConfig {
            secret_key: "0123456789abcdef0123456789abcdef".into(),
            kid: 1,
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
            binding_mode: BindingMode::Bound,
            region: None,
            issuer: None,

            policy_version: 1,
        };
        // Empty scope and 129-byte scope must be rejected…
        assert!(
            matches!(
                issue_challenge(&config, "", "1.2.3.4", 1, 1_700_000_000_000_000, 0, None),
                Err(SignError::InvalidScope)
            ),
            "empty scope must be rejected"
        );
        let long_scope = "s".repeat(129);
        assert!(
            matches!(
                issue_challenge(
                    &config,
                    &long_scope,
                    "1.2.3.4",
                    1,
                    1_700_000_000_000_000,
                    0,
                    None
                ),
                Err(SignError::InvalidScope)
            ),
            "129-byte scope must be rejected"
        );
        // …while the 128-byte boundary is accepted.
        let boundary_scope = "s".repeat(128);
        assert!(issue_challenge(
            &config,
            &boundary_scope,
            "1.2.3.4",
            1,
            1_700_000_000_000_000,
            0,
            None
        )
        .is_ok());
        // The '|' separator is still rejected within the allowed length.
        assert!(issue_challenge(
            &config,
            "login|admin",
            "1.2.3.4",
            1,
            1_700_000_000_000_000,
            0,
            None
        )
        .is_err());
    }

    #[test]
    fn each_challenge_has_unique_nonce() {
        let config = ChallengeConfig {
            secret_key: "test-key-16-bytes!".into(),
            kid: 1,
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
            binding_mode: BindingMode::Bound,
            region: None,
            issuer: None,

            policy_version: 1,
        };
        let a = issue_challenge(
            &config,
            "login",
            "1.1.1.1",
            1,
            1_700_000_000_000_000,
            0,
            None,
        )
        .unwrap();
        let b = issue_challenge(
            &config,
            "login",
            "1.1.1.1",
            1,
            1_700_000_000_000_000,
            0,
            None,
        )
        .unwrap();
        assert_ne!(a.record.nonce, b.record.nonce);
    }

    #[test]
    fn auto_tune_adjusts_target_bits() {
        let config = ChallengeConfig {
            secret_key: "test-key-16-bytes!".into(),
            kid: 1,
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
            binding_mode: BindingMode::Bound,
            region: None,
            issuer: None,

            policy_version: 1,
        };
        // Idle — should be at min.
        let idle = issue_challenge(
            &config,
            "login",
            "1.1.1.1",
            1,
            1_700_000_000_000_000,
            0,
            None,
        )
        .unwrap();
        assert_eq!(idle.challenge.target_bits, 10);
        // Moderate load — roughly midway between min and the solver ceiling.
        let mid = issue_challenge(&config, "login", "1.1.1.1", 1, 1000000000, 25, None).unwrap();
        assert!(mid.challenge.target_bits >= 14 && mid.challenge.target_bits <= 16);
        // Peak load — clamped to the solver ceiling (not 24), because the
        // browser solver's 5M-hash cap would fail ~74% of solves at 24 bits.
        let peak = issue_challenge(&config, "login", "1.1.1.1", 1, 1000000000, 50, None).unwrap();
        assert_eq!(peak.challenge.target_bits, SOLVER_MAX_TARGET_BITS);
    }

    #[test]
    fn static_target_bits_above_solver_cap_rejected_at_issuance() {
        // PHP rejects target_bits > 20 at construction; Rust must NOT clamp
        // a static configuration — issuance rejects it (parity).
        let config = ChallengeConfig {
            secret_key: "test-key-16-bytes!".into(),
            kid: 1,
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
            binding_mode: BindingMode::Bound,
            region: None,
            issuer: None,

            policy_version: 1,
        };
        assert!(
            issue_challenge(
                &config,
                "login",
                "1.1.1.1",
                1,
                1_700_000_000_000_000,
                0,
                None
            )
            .is_err(),
            "a STATIC target_bits above the solver cap must be rejected, not clamped (PHP parity)"
        );
    }

    #[test]
    fn auto_tune_disabled_ignores_tuning_bounds() {
        // With auto_tune off, the tuning bounds must have NO effect: only the
        // solver ceiling caps target_bits. A target_bits below the tuning min
        // stays as-is — it is never raised to the tuning bound.
        let config = ChallengeConfig {
            secret_key: "test-key-16-bytes!".into(),
            kid: 1,
            algorithm: PoWAlgorithm::Sha256,
            m_kib: 65_536,
            t: 2,
            p: 1,
            target_bits: 8,
            argon2_target_bits: 8,
            min_duration_ms: None,
            ttl_secs: 120,
            auto_tune: false,
            auto_tune_min_bits: 10,
            auto_tune_max_bits: 20,
            binding_mode: BindingMode::Bound,
            region: None,
            issuer: None,

            policy_version: 1,
        };
        assert_eq!(config.tuned_target_bits(0), 8);
        // The solver ceiling still applies when disabled.
        let high = ChallengeConfig {
            target_bits: 24,
            ..config
        };
        assert_eq!(high.tuned_target_bits(0), SOLVER_MAX_TARGET_BITS);
    }

    #[test]
    fn challenge_cache_prunes_stale_entries_on_get() {
        let mut cache = ChallengeCache::with_ttl_for_test(Duration::from_secs(60));
        let issued = issue_challenge(
            &ChallengeConfig {
                secret_key: "test-key-16-bytes!".into(),
                kid: 1,
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
                binding_mode: BindingMode::Bound,
                region: None,
                issuer: None,

                policy_version: 1,
            },
            "login",
            "1.1.1.1",
            1,
            1_000_000_000,
            0,
            None,
        )
        .unwrap();
        cache.put("hash1", "login", issued);
        assert_eq!(cache.len(), 1);
        // Within the TTL the entry is served…
        assert!(cache.get("hash1", "login").is_some());
        assert_eq!(cache.len(), 1, "fresh entry must survive get");
        // …and once stale it is removed (pruned) on access. Aging is
        // deterministic (no sleeps): 61s > 60s TTL.
        cache.age_entries_for_test(Duration::from_secs(61));
        assert!(cache.get("hash1", "login").is_none());
        assert_eq!(cache.len(), 0, "stale entry must be pruned by get");
    }

    #[test]
    fn challenge_cache_put_prunes_expired_entries() {
        let mut cache = ChallengeCache::with_ttl_for_test(Duration::from_secs(60));
        let config = ChallengeConfig {
            secret_key: "test-key-16-bytes!".into(),
            kid: 1,
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
            binding_mode: BindingMode::Bound,
            region: None,
            issuer: None,

            policy_version: 1,
        };
        let issued = issue_challenge(
            &config,
            "login",
            "1.1.1.1",
            1,
            1_700_000_000_000_000,
            0,
            None,
        )
        .unwrap();
        cache.put("old", "login", issued);
        cache.age_entries_for_test(Duration::from_secs(61));
        let issued2 = issue_challenge(
            &config,
            "signup",
            "1.1.1.1",
            1,
            1_700_000_000_000_000,
            0,
            None,
        )
        .unwrap();
        cache.put("new", "signup", issued2);
        // The expired "old" entry must not linger after put.
        assert!(cache.get("old", "login").is_none());
        assert!(cache.get("new", "signup").is_some());
    }

    #[test]
    fn challenge_cache_hit_returns_same_challenge() {
        let config = ChallengeConfig {
            secret_key: "test-key-16-bytes!".into(),
            kid: 1,
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
            binding_mode: BindingMode::Bound,
            region: None,
            issuer: None,

            policy_version: 1,
        };
        let issued = issue_challenge(
            &config,
            "login",
            "1.1.1.1",
            1,
            1_700_000_000_000_000,
            0,
            None,
        )
        .unwrap();
        let mut cache = ChallengeCache::new();
        cache.put("hash1", "login", issued.clone());
        let cached = cache.get("hash1", "login").unwrap();
        assert_eq!(cached.challenge.nonce, issued.challenge.nonce);
        assert_eq!(cached.challenge.challenge, issued.challenge.challenge);
    }

    #[test]
    fn challenge_cache_miss_on_different_scope() {
        let config = ChallengeConfig {
            secret_key: "test-key-16-bytes!".into(),
            kid: 1,
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
            binding_mode: BindingMode::Bound,
            region: None,
            issuer: None,

            policy_version: 1,
        };
        let issued = issue_challenge(
            &config,
            "login",
            "1.1.1.1",
            1,
            1_700_000_000_000_000,
            0,
            None,
        )
        .unwrap();
        let mut cache = ChallengeCache::new();
        cache.put("hash1", "login", issued);
        assert!(cache.get("hash1", "signup").is_none());
    }

    fn profile_base_config() -> ChallengeConfig {
        ChallengeConfig {
            secret_key: "test-key-16-bytes!".into(),
            kid: 1,
            algorithm: PoWAlgorithm::Sha256,
            m_kib: 0,
            t: 1,
            p: 1,
            target_bits: 8,
            argon2_target_bits: 8,
            min_duration_ms: None,
            ttl_secs: 120,
            auto_tune: false,
            auto_tune_min_bits: 10,
            auto_tune_max_bits: 24,
            binding_mode: BindingMode::Bound,
            region: None,
            issuer: None,

            policy_version: 1,
        }
    }

    #[test]
    fn issue_with_profile_sha_overrides_difficulty() {
        for bits in [16u8, 20] {
            let issued = issue_challenge_with_profile(
                &profile_base_config(),
                "login",
                "1.2.3.4",
                1_000_000,
                1_700_000_000_000_000,
                0,
                &ChallengeProfile::sha(bits),
                None,
            )
            .unwrap();
            assert_eq!(issued.challenge.algorithm, PoWAlgorithm::Sha256);
            assert_eq!(issued.challenge.target_bits, bits as u32);
            assert_eq!(issued.challenge.m_kib, 0);
            assert_eq!(issued.record.target_bits, bits as u32);
            // Profile issuance keeps the config's TTL/min-duration policy.
            assert_eq!(issued.challenge.ttl_secs, 120);
            assert_eq!(issued.record.min_duration_ms, 5);
        }
    }

    #[test]
    fn issue_with_profile_sha_solves_and_verifies() {
        let config = profile_base_config();
        for bits in [16u8, 20] {
            let issued = issue_challenge_with_profile(
                &config,
                "login",
                "1.2.3.4",
                1_000_000,
                1_700_000_000_000_000,
                0,
                &ChallengeProfile::sha(bits),
                None,
            )
            .unwrap();
            let mut record = issued.record.clone();
            // Retry on an unlucky solve that exceeds the solver cap (an
            // issue that burned the PHP sha-20 profile test too): the
            // counter is deterministic per challenge, so a fresh challenge
            // resamples it.
            let counter = loop {
                match crate::verify::solve_for_test(&record) {
                    Some(c) if c <= SOLVER_MAX_HASHES => break c,
                    _ => {
                        let reissued = crate::challenge::issue_challenge_with_profile(
                            &config,
                            "login",
                            "1.2.3.4",
                            1_000_001,
                            1_700_000_000_000_000,
                            0,
                            &ChallengeProfile::sha(bits),
                            None,
                        )
                        .unwrap();
                        record = reissued.record;
                    }
                }
            };
            let mut ctx = crate::verify::VerifyContext {
                record: &mut record,
                secret_key: "test-key-16-bytes!",
                secrets_by_kid: None,
                revoked_kids: None,
                counter,
                duration_ms: 5000,
                now_unix: 1_000_001,
                now_ns: 1_700_000_005_000_000,
                min_duration_ms: 0,
                expected_scope: None,
            expected_request_binding: RequestBindingExpectation::Unenforced,
                client_ip: Some("1.2.3.4"),
                expected_region: None,
                expected_issuer: None,
                expected_policy_version: None,
                telemetry: None,
                enforce_telemetry: false,
                max_attempts: 0,
                accept_legacy_v1: false,
            };
            assert!(
                matches!(
                    crate::verify::verify_solution(&mut ctx),
                    crate::verify::VerifyOutcome::Valid { .. }
                ),
                "sha({bits}) profile must verify"
            );
        }
    }

    #[test]
    fn issue_with_profile_argon16_solves_and_verifies() {
        let issued = issue_challenge_with_profile(
            &profile_base_config(),
            "login",
            "1.2.3.4",
            1_000_000,
            1_700_000_000_000_000,
            0,
            &ChallengeProfile::argon16(),
            None,
        )
        .unwrap();
        assert_eq!(issued.challenge.algorithm, PoWAlgorithm::Argon2id);
        assert_eq!(issued.challenge.target_bits, 1);
        assert_eq!(issued.challenge.m_kib, 16 * 1024);
        assert_eq!(issued.challenge.t, 3);
        assert_eq!(issued.challenge.p, 1);
        assert_eq!(issued.record.target_bits, 1);

        let mut record = issued.record.clone();
        let counter = crate::verify::solve_for_test(&record).expect("argon solve finds a counter");
        let mut ctx = crate::verify::VerifyContext {
            record: &mut record,
            secret_key: "test-key-16-bytes!",
            secrets_by_kid: None,
            revoked_kids: None,
            counter,
            duration_ms: 5000,
            now_unix: 1_000_001,
            now_ns: 1_700_000_005_000_000,
            min_duration_ms: 0,
            expected_scope: None,
            expected_request_binding: RequestBindingExpectation::Unenforced,
            client_ip: Some("1.2.3.4"),
            expected_region: None,
            expected_issuer: None,
            expected_policy_version: None,
            telemetry: None,
            enforce_telemetry: false,
            max_attempts: 0,
            accept_legacy_v1: false,
        };
        assert!(matches!(
            crate::verify::verify_solution(&mut ctx),
            crate::verify::VerifyOutcome::Valid { .. }
        ));
    }

    #[test]
    fn issue_carries_region_on_the_record() {
        let base = profile_base_config();
        let with_region = ChallengeConfig {
            region: Some("eu-west-1".into()),
            ..base.clone()
        };
        let issued = issue_challenge(
            &with_region,
            "login",
            "1.2.3.4",
            1_000_000,
            1_700_000_000_000_000,
            0,
            None,
        )
        .unwrap();
        assert_eq!(issued.record.region.as_deref(), Some("eu-west-1"));

        let unbound = issue_challenge(
            &base,
            "login",
            "1.2.3.4",
            1_000_000,
            1_700_000_000_000_000,
            0,
            None,
        )
        .unwrap();
        assert_eq!(unbound.record.region, None);
        // The JSON key is always present (null when unbound) — PHP toArray()
        // parity, 23 keys.
        let value = serde_json::to_value(&issued.record).unwrap();
        assert_eq!(value["region"], "eu-west-1");
        let unbound_value = serde_json::to_value(&unbound.record).unwrap();
        assert_eq!(unbound_value["region"], serde_json::Value::Null);
        assert!(unbound_value.as_object().unwrap().contains_key("region"));
    }

    #[test]
    fn issue_carries_issuer_on_the_record() {
        let base = profile_base_config();
        let with_issuer = ChallengeConfig {
            issuer: Some("auth-gw-eu".into()),
            ..base.clone()
        };
        let issued = issue_challenge(
            &with_issuer,
            "login",
            "1.2.3.4",
            1_000_000,
            1_700_000_000_000_000,
            0,
            None,
        )
        .unwrap();
        assert_eq!(issued.record.issuer.as_deref(), Some("auth-gw-eu"));

        let unbound = issue_challenge(
            &base,
            "login",
            "1.2.3.4",
            1_000_000,
            1_700_000_000_000_000,
            0,
            None,
        )
        .unwrap();
        assert_eq!(unbound.record.issuer, None);
        // The JSON key is always present (null when unbound) — PHP toArray()
        // parity, 23 keys.
        let value = serde_json::to_value(&issued.record).unwrap();
        assert_eq!(value["issuer"], "auth-gw-eu");
        let unbound_value = serde_json::to_value(&unbound.record).unwrap();
        assert_eq!(unbound_value["issuer"], serde_json::Value::Null);
        assert!(unbound_value.as_object().unwrap().contains_key("issuer"));

        // The issuer is the v2 canonical field before the final kid:
        // appended after request_binding, empty when unset; the canonical
        // always ends with `|<kid>`.
        let canonical = crate::challenge::canonical_signing_input_v2(&issued.record);
        assert!(
            canonical.ends_with("|auth-gw-eu|1"),
            "canonical: {canonical}"
        );
        let unbound_canonical = crate::challenge::canonical_signing_input_v2(&unbound.record);
        assert!(
            unbound_canonical.ends_with("||1"),
            "unbound issuer renders as the empty segment before the final kid: {unbound_canonical}"
        );
        // The record's signature covers the issuer: tampering with it breaks
        // the v2 signature (the canonical is signed, so the issuer cannot be
        // swapped without the secret).
        let mut tampered = issued.record.clone();
        tampered.issuer = Some("evil-issuer".into());
        let signature = issued
            .record
            .challenge
            .rsplit_once('.')
            .map(|(_, sig)| sig)
            .unwrap();
        assert!(
            !crate::challenge::verify_signature_v2(&tampered, signature, "test-key-16-bytes!")
                .unwrap()
        );
    }

    #[test]
    fn issuance_enforces_the_narrow_identifier_alphabet() {
        // scope/issuer/region/request_binding must match
        // [A-Za-z0-9._:-]+ with the length caps — issuance refuses to mint
        // a record the verifier would declare malformed.
        let base = profile_base_config();

        // Scope: Unicode and spaces are rejected (InvalidScope); the
        // `|` separator is outside the alphabet entirely.
        for bad_scope in ["логин", "log in", "login|admin", ""] {
            assert!(
                matches!(
                    issue_challenge(
                        &base,
                        bad_scope,
                        "1.2.3.4",
                        1,
                        1_700_000_000_000_000,
                        0,
                        None
                    ),
                    Err(SignError::InvalidScope)
                ),
                "scope {bad_scope:?} must be rejected at issuance"
            );
        }
        // Scope: 129 bytes rejected, 128 accepted (existing boundary kept).
        assert!(matches!(
            issue_challenge(
                &base,
                &"s".repeat(129),
                "1.2.3.4",
                1,
                1_700_000_000_000_000,
                0,
                None
            ),
            Err(SignError::InvalidScope)
        ));
        assert!(issue_challenge(
            &base,
            &"s".repeat(128),
            "1.2.3.4",
            1,
            1_700_000_000_000_000,
            0,
            None
        )
        .is_ok());

        // Issuer: Unicode, spaces, empty, and > 128 bytes are rejected.
        for bad_issuer in [
            Some("auth-gw-ü"),
            Some("auth gw"),
            Some(""),
            Some(&"i".repeat(129)),
        ] {
            let config = ChallengeConfig {
                issuer: bad_issuer.map(str::to_string),
                ..base.clone()
            };
            assert!(
                matches!(
                    issue_challenge(
                        &config,
                        "login",
                        "1.2.3.4",
                        1,
                        1_700_000_000_000_000,
                        0,
                        None
                    ),
                    Err(SignError::InvalidIdentifier)
                ),
                "issuer {bad_issuer:?} must be rejected at issuance"
            );
        }
        // Issuer: 128 bytes accepted.
        let config = ChallengeConfig {
            issuer: Some("i".repeat(128)),
            ..base.clone()
        };
        assert!(issue_challenge(
            &config,
            "login",
            "1.2.3.4",
            1,
            1_700_000_000_000_000,
            0,
            None
        )
        .is_ok());

        // Region: Unicode, spaces, and > 64 bytes are rejected.
        for bad_region in [
            Some("eu-ü"),
            Some("eu west"),
            Some(""),
            Some(&"r".repeat(65)),
        ] {
            let config = ChallengeConfig {
                region: bad_region.map(str::to_string),
                ..base.clone()
            };
            assert!(
                matches!(
                    issue_challenge(
                        &config,
                        "login",
                        "1.2.3.4",
                        1,
                        1_700_000_000_000_000,
                        0,
                        None
                    ),
                    Err(SignError::InvalidIdentifier)
                ),
                "region {bad_region:?} must be rejected at issuance"
            );
        }
        // Region: 64 bytes accepted.
        let config = ChallengeConfig {
            region: Some("r".repeat(64)),
            ..base.clone()
        };
        assert!(issue_challenge(
            &config,
            "login",
            "1.2.3.4",
            1,
            1_700_000_000_000_000,
            0,
            None
        )
        .is_ok());

        // request_binding: Unicode, spaces, empty, and > 128 bytes rejected.
        for bad_binding in [
            Some("交易"),
            Some("req id"),
            Some(""),
            Some(&"b".repeat(129)),
        ] {
            assert!(
                matches!(
                    issue_challenge(
                        &base,
                        "login",
                        "1.2.3.4",
                        1,
                        1_700_000_000_000_000,
                        0,
                        bad_binding
                    ),
                    Err(SignError::InvalidIdentifier)
                ),
                "request_binding {bad_binding:?} must be rejected at issuance"
            );
        }
        // request_binding: 128 bytes accepted.
        assert!(issue_challenge(
            &base,
            "login",
            "1.2.3.4",
            1,
            1_700_000_000_000_000,
            0,
            Some(&"b".repeat(128))
        )
        .is_ok());

        // The full allowed alphabet passes end to end.
        let config = ChallengeConfig {
            issuer: Some("auth-gw:eu-1._a".into()),
            region: Some("eu-west-1".into()),
            ..base.clone()
        };
        let issued = issue_challenge(
            &config,
            "login",
            "1.2.3.4",
            1,
            1_700_000_000_000_000,
            0,
            Some("req_1:abc.de-2"),
        )
        .unwrap();
        assert_eq!(issued.record.issuer.as_deref(), Some("auth-gw:eu-1._a"));
        assert_eq!(issued.record.region.as_deref(), Some("eu-west-1"));
        assert_eq!(
            issued.record.request_binding.as_deref(),
            Some("req_1:abc.de-2")
        );
    }

    #[test]
    fn issuance_stamps_and_signs_the_kid() {
        // config.kid is stamped on the record and signed as the
        // final canonical field — the record JSON carries it and
        // the signed challenge string embeds it byte-exactly.
        let base = profile_base_config();
        let with_kid = ChallengeConfig {
            kid: 5,
            ..base.clone()
        };
        let issued = issue_challenge(
            &with_kid,
            "login",
            "1.2.3.4",
            1_000_000,
            1_700_000_000_000_000,
            0,
            None,
        )
        .unwrap();
        assert_eq!(issued.record.kid, 5);
        let canonical = crate::challenge::canonical_signing_input_v2(&issued.record);
        assert!(
            canonical.ends_with("|5"),
            "the kid must be the FINAL canonical field: {canonical}"
        );
        // The challenge's base64 half is byte-exactly the canonical.
        let b64 = issued.record.challenge.split('.').next().unwrap();
        assert_eq!(B64.decode(b64).unwrap(), canonical.as_bytes());

        // The record JSON always carries kid (default 1 when unset).
        let value = serde_json::to_value(&issued.record).unwrap();
        assert_eq!(value["kid"], 5);
        let default_kid = issue_challenge(
            &base,
            "login",
            "1.2.3.4",
            1_000_000,
            1_700_000_000_000_000,
            0,
            None,
        )
        .unwrap();
        assert_eq!(default_kid.record.kid, 1, "default kid is 1");
        let value = serde_json::to_value(&default_kid.record).unwrap();
        assert_eq!(value["kid"], 1);
        // A record JSON without the kid key deserializes with kid = 1.
        let mut no_kid = value;
        no_kid.as_object_mut().unwrap().remove("kid");
        let decoded: ChallengeRecord = serde_json::from_value(no_kid).unwrap();
        assert_eq!(decoded.kid, 1, "missing kid must default to 1");
    }

    #[test]
    fn issue_with_profile_rejects_floor_violating_argon_profiles() {
        // The issuer refuses profiles with m_kib below 8, t below
        // 3, or p != 1 — a profile must never mint a challenge the verifier
        // would reject.
        let config = profile_base_config();
        for profile in [
            ChallengeProfile {
                algorithm: PoWAlgorithm::Argon2id,
                target_bits: 1,
                m_kib: 1, // below the memory minimum
                t: 3,
                p: 1,
            },
            ChallengeProfile {
                algorithm: PoWAlgorithm::Argon2id,
                target_bits: 1,
                m_kib: 16 * 1024,
                t: 2, // below the time minimum (3)
                p: 1,
            },
            ChallengeProfile {
                algorithm: PoWAlgorithm::Argon2id,
                target_bits: 1,
                m_kib: 65_536 + 1, // above the 64 MiB ceiling
                t: 3,
                p: 1,
            },
            ChallengeProfile {
                algorithm: PoWAlgorithm::Argon2id,
                target_bits: 1,
                m_kib: 16 * 1024,
                t: 3,
                p: 2, // != 1
            },
        ] {
            assert!(
                matches!(
                    issue_challenge_with_profile(
                        &config,
                        "login",
                        "1.2.3.4",
                        1_000_000,
                        1_700_000_000_000_000,
                        0,
                        &profile,
                        None
                    ),
                    Err(SignError::InvalidArgon2Params)
                ),
                "profile {profile:?} must be refused at issuance"
            );
        }
    }

    #[test]
    fn issue_with_profile_does_not_mutate_config() {
        let config = profile_base_config();
        issue_challenge_with_profile(
            &config,
            "login",
            "1.2.3.4",
            1_000_000,
            1_700_000_000_000_000,
            0,
            &ChallengeProfile::sha(16),
            None,
        )
        .unwrap();
        assert_eq!(
            config.target_bits, 8,
            "the caller's config must not be mutated"
        );
        assert_eq!(config.algorithm, PoWAlgorithm::Sha256);
    }

    #[test]
    fn issue_with_profile_rejects_invalid_profiles() {
        let config = profile_base_config();
        // SHA-256 out of range -> InvalidDifficulty.
        assert!(matches!(
            issue_challenge_with_profile(
                &config,
                "login",
                "1.2.3.4",
                1_000_000,
                1_700_000_000_000_000,
                0,
                &ChallengeProfile::sha(21),
                None
            ),
            Err(SignError::InvalidDifficulty)
        ));
        assert!(matches!(
            issue_challenge_with_profile(
                &config,
                "login",
                "1.2.3.4",
                1_000_000,
                1_700_000_000_000_000,
                0,
                &ChallengeProfile::sha(0),
                None
            ),
            Err(SignError::InvalidDifficulty)
        ));
        // Argon2id out of range -> InvalidArgon2Params (t=7, m_kib=7,
        // target 11, p=2, m_kib above ceiling).
        for profile in [
            ChallengeProfile {
                algorithm: PoWAlgorithm::Argon2id,
                target_bits: 1,
                m_kib: 16 * 1024,
                t: 7,
                p: 1,
            },
            ChallengeProfile {
                algorithm: PoWAlgorithm::Argon2id,
                target_bits: 1,
                m_kib: 7,
                t: 3,
                p: 1,
            },
            ChallengeProfile {
                algorithm: PoWAlgorithm::Argon2id,
                target_bits: 11,
                m_kib: 16 * 1024,
                t: 3,
                p: 1,
            },
            ChallengeProfile {
                algorithm: PoWAlgorithm::Argon2id,
                target_bits: 1,
                m_kib: 65_536 + 1,
                t: 3,
                p: 1,
            },
            ChallengeProfile {
                algorithm: PoWAlgorithm::Argon2id,
                target_bits: 1,
                m_kib: 16 * 1024,
                t: 3,
                p: 2,
            },
        ] {
            assert!(
                matches!(
                    issue_challenge_with_profile(
                        &config,
                        "login",
                        "1.2.3.4",
                        1_000_000,
                        1_700_000_000_000_000,
                        0,
                        &profile,
                        None
                    ),
                    Err(SignError::InvalidArgon2Params)
                ),
                "profile {profile:?} must be rejected"
            );
        }
    }
}
