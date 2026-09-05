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
use std::fmt;
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
    /// The optional sequential time-lock proof (Rivest-Shamir-Wagner):
    /// the client performs T sequential modular squarings over a 2048-bit
    /// composite, and the server verifies instantly through the
    /// factorization trapdoor. Issued only when the operator configures
    /// the modulus secrets and selects the algorithm.
    Rsw,
}

impl PoWAlgorithm {
    pub fn as_str(&self) -> &'static str {
        match self {
            PoWAlgorithm::Sha256 => "sha256",
            PoWAlgorithm::Argon2id => "argon2id",
            PoWAlgorithm::Rsw => "rsw",
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
/// - `protocol_version == 2` (current, unarmed): signed with the v2
///   full-parameter canonical input and a nonce-bound `binding_tag` —
///   byte-identical to the pre-decoy record format.
/// - `protocol_version == 3` (decoy-capable): the v2 canonical base plus
///   the `|decoy_field` segment appended after `kid`. The decoy is
///   mandatory on v3 — a v3 record without a decoy is rejected by
///   validation, so a stored version flip (a signed v2 record re-versioned
///   to 3) can never verify: the authenticated canonical shape itself
///   establishes the protocol capability. A v2 record carrying a
///   `decoy_field` is rejected by validation too — the v2 canonical never
///   includes the segment, so v2 => no decoy and v3 => decoy present is
///   the total grammar.
/// - `protocol_version == 4` (execution-capable): the decoy-capable
///   canonical plus the `|execution_version|execution_commitment`
///   segments appended after the decoy (or after `kid` when no decoy is
///   armed). The execution segments are mandatory on v4 and present iff
///   the record carries an execution program — the signed commitment is
///   the exact mirror of the stored program (absent <=> absent, present
///   <=> present, SHA256(stored program) == commitment, constant-time).
///   A v4 record without the execution triplet and a v2/v3 record
///   carrying any execution field are both rejected by validation, so a
///   stored version flip can never change the effective protocol and a
///   stripped, substituted or injected program always invalidates the
///   challenge. An old verifier rejects version 4 as unknown.
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
    /// binding; 2 = v2 full-parameter signing + nonce-bound `binding_tag`
    /// (the unarmed issuance format, byte-identical to the pre-decoy
    /// records); 3 = the decoy-capable canonical — the v2 18-field base
    /// plus the `|decoy_field` segment appended after `kid`, with the
    /// decoy mandatory on v3. New records are issued with 3 when a decoy
    /// is armed and 2 otherwise; 1 is the serde default so stored pre-v2
    /// records keep verifying during the migration window (max TTL). The
    /// protocol-vs-decoy grammar is total and validated: a v2 record
    /// carrying a `decoy_field` AND a v3 record without one are both
    /// rejected as malformed, so the protocol capability is fully
    /// inferable from the authenticated canonical shape — a stored
    /// version flip can never change the effective protocol.
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
    /// The server-issued decoy (honeypot) form-field name armed for this
    /// challenge, drawn from the combinatorial grammar (see
    /// [`DECOY_GRAMMAR_SLOT1_QUALIFIER`]). `None` = no decoy armed (the
    /// default, and the shape every pre-decoy record carries). The name is
    /// an authenticated canonical field of protocol v3 — the final segment
    /// `|<decoy_field>`, appended after the `kid` (the canonical signing
    /// input, documented below) — so a stored/tampered record cannot
    /// change or drop it without breaking the signature.
    ///
    /// Wire compatibility: unarmed records are byte-identical to the
    /// pre-decoy format — the JSON key is absent when `None`
    /// (`skip_serializing_if`), so pre-decoy writers and readers keep
    /// their exact byte format. A decoy-armed record is protocol v3 and
    /// requires a v3-capable verifier: an old verifier rejects version 3
    /// as unknown, so the capability is always inferable from
    /// `protocol_version` — a v2 record carrying `decoy_field` is
    /// rejected explicitly by validation, and a v3 record without a decoy
    /// is rejected too (the decoy is mandatory on v3).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decoy_field: Option<String>,
    /// The ExecutionChallengeV1 program (base64 of the bytecode blob, see
    /// [`crate::execution`]) armed for this challenge; `None` = no
    /// execution dimension (the legacy shape — the JSON key is absent
    /// when `None`, byte-identical to the pre-execution wire format).
    /// The program is never sent in the challenge payload (it rides the
    /// challenge response for the driver). Its integrity is bound by the
    /// execution commitment, an authenticated protocol v4 canonical
    /// segment (SHA-256 of this stored program, see
    /// `execution_commitment`): a substituted or stripped program breaks
    /// the signature, and a stored program whose hash does not match the
    /// signed commitment is rejected before any execution work.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub execution_program: Option<String>,
    /// The execution-dimension protocol version: the canonical numeric
    /// byte within the register 1..=MAX_EXECUTION_VERSION (u8 on the
    /// wire, rendered as decimal in the canonical input). Authenticated
    /// as the `|execution_version` protocol v4 canonical segment. Present
    /// iff the record carries an execution program; the JSON key is
    /// absent when `None`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub execution_version: Option<u8>,
    /// The authenticated mirror of the stored execution program: hex
    /// SHA-256 of the program's base64 wire string (64 lowercase hex),
    /// the final `|execution_commitment` protocol v4 canonical segment.
    /// Present iff the record carries an execution program; the JSON key
    /// is absent when `None`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub execution_commitment: Option<String>,
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
///
/// `Debug` is implemented manually: the derived formatter would print the
/// live secrets (the HMAC `secret_key`, the execution `execution_key` and the
/// rsw `rsw_lambda`) into logs, so the manual impl prints the same field set
/// with only the secret values replaced by `"<redacted>"`.
#[derive(Clone)]
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
    /// The ExecutionChallengeV1 keyed-PRF key (min 16 bytes), see
    /// [`crate::execution`]. `None` (the default) = execution challenges
    /// are never issued: issuance with the execution surface armed
    /// refuses (the generator errors), so a deployment cannot arm the
    /// dimension without the key. The key never leaves the server: it
    /// only feeds the program generator; the browser digest uses the
    /// program blob itself as its content-derived key.
    pub execution_key: Option<String>,
    /// The rsw modulus n = p*q as canonical standard base64 of exactly
    /// 256 bytes (top bit set, odd), the public half of the time-lock
    /// trapdoor. Generate the pair with the shipped tools/rsw-keygen
    /// binary and record its rsw_modulus_n_sha256 fingerprint; the
    /// shared decode refuses a weak or probable-prime modulus.
    /// Required when the algorithm is [`PoWAlgorithm::Rsw`]; ignored
    /// otherwise. `None` (the default) = the rsw algorithm is not
    /// configured.
    pub rsw_modulus_n: Option<String>,
    /// The rsw secret lambda = lcm(p-1, q-1) as canonical standard
    /// base64 of 1..=256 even bytes, the trapdoor that lets the server
    /// verify without the T squarings. It is the secret trapdoor:
    /// never persist it beside client material. A lambda that fails
    /// the deterministic trapdoor consistency spot-check against the
    /// modulus is refused by the shared decode. Required when the
    /// algorithm is
    /// [`PoWAlgorithm::Rsw`]; ignored otherwise. Never stored on the
    /// record and never sent to the client.
    pub rsw_lambda: Option<String>,
    /// The rsw sequential-squaring cost T (default 75,000; validated
    /// to 10,000..=300,000 when the algorithm is [`PoWAlgorithm::Rsw`]).
    /// The client performs T sequential modular squarings; the server
    /// verifies instantly through lambda.
    pub rsw_t: u32,
}

impl fmt::Debug for ChallengeConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ChallengeConfig")
            .field("secret_key", &"<redacted>")
            .field("algorithm", &self.algorithm)
            .field("m_kib", &self.m_kib)
            .field("t", &self.t)
            .field("p", &self.p)
            .field("target_bits", &self.target_bits)
            .field("argon2_target_bits", &self.argon2_target_bits)
            .field("ttl_secs", &self.ttl_secs)
            .field("min_duration_ms", &self.min_duration_ms)
            .field("auto_tune", &self.auto_tune)
            .field("auto_tune_min_bits", &self.auto_tune_min_bits)
            .field("auto_tune_max_bits", &self.auto_tune_max_bits)
            .field("binding_mode", &self.binding_mode)
            .field("policy_version", &self.policy_version)
            .field("region", &self.region)
            .field("issuer", &self.issuer)
            .field("kid", &self.kid)
            .field(
                "execution_key",
                &self.execution_key.as_ref().map(|_| "<redacted>"),
            )
            .field("rsw_modulus_n", &self.rsw_modulus_n)
            .field(
                "rsw_lambda",
                &self.rsw_lambda.as_ref().map(|_| "<redacted>"),
            )
            .field("rsw_t", &self.rsw_t)
            .finish()
    }
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
            // RSW has no leading-zero target: the canonical always
            // renders the field, so issuance pins the protocol floor.
            PoWAlgorithm::Rsw => RSW_TARGET_BITS_PIN,
        }
    }

    /// The minimum plausible solve time (ms) for the rsw sequential
    /// cost: even a native-optimized squarer cannot finish T 2048-bit
    /// squarings below `T / RSW_SOLVER_SQUARINGS_PER_SEC` seconds (the
    /// browser BigInt solver is slower), so a faster receipt is a
    /// timing anomaly. The 50 ms absolute floor mirrors the Argon2id
    /// rule.
    pub fn rsw_min_duration_ms(&self) -> u64 {
        let ms = (self.rsw_t as f64 / RSW_SOLVER_SQUARINGS_PER_SEC * 1000.0).ceil() as u64;
        ms.max(50)
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
            PoWAlgorithm::Rsw => self.rsw_min_duration_ms(),
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
/// to 4-byte IPv4, and `K_ip_bind` is the `HKDF`-derived IP-binding purpose key
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
    binding_tag_with_keys(nonce, ip, &DerivedKeys::from_master(secret, None))
}

/// The nonce-bound IP binding tag computed with an already derived
/// IP-binding key — the cached-`HKDF` seam for the production verifier,
/// which derives the purpose keys once per key id (see
/// [`crate::keys::DerivedKeys`]) instead of re-running `HKDF` on every
/// check. Identical output to [`binding_tag`] for the same master secret.
pub(crate) fn binding_tag_with_keys(
    nonce: &str,
    ip: &str,
    derived: &DerivedKeys,
) -> Result<String, SignError> {
    let addr: IpAddr = ip.parse().map_err(|_| SignError::InvalidIp)?;
    let (family, canonical_bytes) = match addr {
        IpAddr::V4(v4) => (0x04u8, v4.octets().to_vec()),
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(mapped) => (0x04u8, mapped.octets().to_vec()),
            None => (0x06u8, v6.octets().to_vec()),
        },
    };
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

/// Protocol v2/v3/v4 canonical input: the full parameter
/// set so no issuance parameter can be tampered with without breaking the
/// signature:
/// `v2|nonce|scope|binding_tag|issued_at|expires_at|algorithm|m_kib|t|p|target_bits|salt|min_duration_ms|region|policy_version|request_binding|issuer|kid`.
/// `region`, `request_binding` and `issuer` render as the empty segment when
/// unset; `kid` is the final field, appended after the issuer.
///
/// # The decoy-field extension (protocol v3)
///
/// When the issuer arms a decoy (honeypot) form field
/// (`issue_challenge_with_decoy`), the field name is appended as ONE extra
/// final segment after the `kid`:
///
/// ```text
/// v2|nonce|scope|binding_tag|issued_at|expires_at|algorithm|m_kib|t|p|
///   target_bits|salt|min_duration_ms|region|policy_version|request_binding|
///   issuer|kid|decoy_field
/// ```
///
/// - `decoy_field` is the literal armed decoy name (e.g.
///   `billing_address_line_a3f9c21d8e5b7401`): a grammar prefix drawn
///   from the combinatorial vocabularies ([`DECOY_GRAMMAR_SLOT1_QUALIFIER`],
///   [`DECOY_GRAMMAR_SLOT2_CATEGORY`] and
///   [`DECOY_GRAMMAR_SLOT3_FORM`]) plus the 16-hex `CSPRNG` suffix, so it
///   can never contain the `|` separator (the alphabet is `[a-z_0-9]`;
///   validation accepts `[A-Za-z0-9_-]` only, 1..=64 bytes).
/// - The segment is appended only when a decoy is armed, and an armed
///   record is issued as `protocol_version == 3` (or 4 when the execution
///   dimension is armed too). `None` renders
///   nothing extra — the canonical string is byte-identical to the
///   pre-extension format and the record stays `protocol_version == 2`,
///   so unarmed records and cross-language records keep verifying
///   unchanged across the upgrade.
/// - The grammar is total: v2 => no decoy segment, v3 => decoy segment
///   present. Validation enforces both directions, so the protocol
///   capability is fully inferable from the authenticated canonical
///   shape — a stored version flip (a signed v2 record re-versioned to
///   3) keeps the plain 18-field canonical and is rejected as
///   malformed, and a v2 record carrying `decoy_field` is rejected too
///   (an old verifier rejects version 3 as unknown — the capability
///   becomes inferable from `protocol_version`, which is the point).
/// - PHP parity (exact recipe for the PHP core): build the same 18-field
///   base string, then append `'|' . $decoyField` if and only if the record
///   carries a non-null `decoy_field`; sign/HMAC-verify the result with the
///   `HKDF`-derived challenge key (`K_challenge`) exactly as before. The
///   stored record JSON carries the optional string key `decoy_field`
///   (absent when null — not a JSON `null` key); the client-facing
///   challenge response carries the optional key `decoy_field` with the
///   same value.
///
/// # The execution-commitment extension (protocol v4)
///
/// When the issuer arms the ExecutionChallengeV1 dimension
/// (`issue_challenge_with_execution`), the execution version and the
/// program commitment are appended as two more final segments after the
/// decoy segment (or after the `kid` when no decoy is armed):
///
/// ```text
/// v2|nonce|scope|binding_tag|issued_at|expires_at|algorithm|m_kib|t|p|
///   target_bits|salt|min_duration_ms|region|policy_version|request_binding|
///   issuer|kid[|decoy_field]|execution_version|execution_commitment
/// ```
///
/// - `execution_version` is the canonical numeric byte carrying the
///   program's execution grammar version, 1..=MAX_EXECUTION_VERSION
///   when armed (decimal on the wire; never `|`-capable).
/// - `execution_commitment` is the hex SHA-256 of the stored program's
///   base64 wire string: 64 lowercase hex characters, never
///   `|`-capable.
/// - The segments are appended only when the record carries an execution
///   program, and the protocol-vs-execution grammar is total: v2/v3 =>
///   no execution, v4 => execution present. The signed commitment is
///   therefore the exact mirror of the stored program: a
///   stored/tampered record cannot strip, substitute or inject a program
///   without breaking the signature (the equivalence is additionally
///   enforced by the verifier's SHA256(stored program) == commitment
///   check).
/// - Wire compatibility: unarmed and decoy-only records are byte-identical
///   in both directions; execution-armed records are protocol v4 and
///   require a v4-capable verifier (an old verifier rejects version 4 as
///   unknown).
///
/// The canonical signing input of a record — public so cross-language
/// tests and integrations can pin the byte-exact reconstruction against
/// the client-visible challenge string (the PHP mirror exposes the same
/// helper as `Issuer::canonicalPayload()`).
pub fn canonical_signing_input_v2(record: &ChallengeRecord) -> String {
    let base = format!(
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
    );
    let mut canonical = match record.decoy_field.as_deref() {
        Some(decoy) => format!("{base}|{decoy}"),
        None => base,
    };
    // The execution commitment segments are appended only when the
    // record carries an execution program — and only as the exact pair.
    // The issuer always sets both; the verifier's structural gate
    // rejects a record carrying exactly one, so the canonical
    // reconstruction is byte-exact in both languages.
    if let Some(version) = record.execution_version {
        canonical.push('|');
        canonical.push_str(&version.to_string());
        canonical.push('|');
        canonical.push_str(record.execution_commitment.as_deref().unwrap_or(""));
    }
    canonical
}

/// The authenticated execution commitment of a stored program: hex
/// SHA-256 of the program's base64 wire string, 64 lowercase hex
/// characters. This is the value signed into the protocol v4 canonical
/// (the final `|execution_commitment` segment), so the verifier's
/// constant-time equivalence check
/// `SHA256(stored program) == signed commitment` is byte-exact in both
/// languages. Mirrors the PHP `Issuer::executionCommitment`.
pub fn execution_commitment(program_b64: &str) -> String {
    hex::encode(&Sha256::digest(program_b64.as_bytes()))
}

/// Sign a canonical input with the secret key, returning a hex HMAC tag
/// (protocol v1 legacy path — the master key is used directly; v2 records use
/// the `HKDF`-derived challenge key via [`sign_canonical_v2`]).
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

/// Sign a canonical input with the `HKDF`-derived challenge-signing purpose key
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
/// checked against the `HKDF`-derived challenge-signing key (`K_challenge`),
/// never the master secret directly.
pub fn verify_signature_v2(
    record: &ChallengeRecord,
    signature: &str,
    secret_key: &str,
) -> Result<bool, SignError> {
    verify_canonical_v2(&canonical_signing_input_v2(record), signature, secret_key)
}

/// Verify a v2 signature with an already derived challenge-signing key —
/// the cached-`HKDF` seam for the production verifier (the purpose keys are
/// derived once per key id, see [`crate::keys::DerivedKeys`]). Identical
/// verdicts to [`verify_signature_v2`] for the same master secret; same
/// constant-time guarantee (the full HMAC tag is processed regardless of
/// the inputs' relationship to the expected value).
#[cfg(feature = "redis")] // the production verifier (redis_verify) is the sole consumer
pub(crate) fn verify_signature_v2_with_keys(
    record: &ChallengeRecord,
    signature: &str,
    derived: &DerivedKeys,
) -> Result<bool, SignError> {
    verify_canonical_v2_with_keys(&canonical_signing_input_v2(record), signature, derived)
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

/// Verify a canonical input against the `HKDF`-derived challenge key (protocol
/// v2). Same constant-time guarantee as [`verify_canonical`].
fn verify_canonical_v2(
    canonical: &str,
    signature: &str,
    secret_key: &str,
) -> Result<bool, SignError> {
    if secret_key.len() < 16 {
        return Err(SignError::KeyTooShort);
    }
    verify_canonical_v2_with_keys(
        canonical,
        signature,
        &DerivedKeys::from_master(secret_key, None),
    )
}

/// The v2 canonical-input verification core operating on derived keys —
/// shared by [`verify_canonical_v2`] (deriving) and
/// [`verify_signature_v2_with_keys`] (cached).
fn verify_canonical_v2_with_keys(
    canonical: &str,
    signature: &str,
    derived: &DerivedKeys,
) -> Result<bool, SignError> {
    // Exact 64-hex-char signature pre-bound before any
    // hex::decode allocation.
    if signature.len() != 64 {
        return Ok(false);
    }
    let signature_bytes = match hex::decode(signature) {
        Some(bytes) => bytes,
        None => return Ok(false), // malformed signature can never match
    };
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
/// and the map is HARD-bounded: a `put` that would exceed the maximum
/// evicts the least-recently-used entry, so 256 is a real memory maximum regardless of
/// how many distinct IP+scope pairs arrive within a window.
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

/// The binary's maximum challenge protocol version, mirrored by the PHP
/// core (`ChallengeRecord::MAX_PROTOCOL_VERSION`) and the extension's
/// readiness probe (KiwiHealthController): 4 since the execution-capable
/// canonical (protocol v4) landed — armed issuance writes version 4 and
/// the verifier accepts versions 1..=4. A central security-policy floor
/// above this means the binary cannot verify the challenges the fleet
/// now issues.
pub const MAX_PROTOCOL_VERSION: u8 = 4;

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

/// The floor for the rsw sequential-squaring cost T. Below it the
/// challenge would finish too fast to carry meaningful sequential cost,
/// so issuance refuses the value. Shared with the PHP core.
pub const MIN_RSW_T: u32 = 10_000;

/// The ceiling for the rsw sequential-squaring cost T. The bound is a
/// protocol ceiling, not a device-performance claim: it keeps a
/// legitimate solve inside the challenge lifetime on the slowest
/// supported device while the sequential cost stays material. The
/// per-deployment T choice must be derived from measurements on the
/// worst device a deployment supports, and the qualification state
/// must be documented; the client-performance lab measures the rsw
/// rungs and documents the release-gate procedure
/// (tools/client-perf/README.md). Shared with the PHP core.
pub const MAX_RSW_T: u32 = 300_000;

/// The default rsw sequential-squaring cost T. Shared with the PHP core.
pub const DEFAULT_RSW_T: u32 = 75_000;

/// The rsw canonical target_bits pin. The v2 canonical always carries a
/// target_bits value within the uniform protocol bounds 1..=20, and rsw
/// has no leading-zero target, so issuance pins the protocol floor. The
/// rsw proof check never reads the field. Shared with the PHP core.
pub const RSW_TARGET_BITS_PIN: u32 = 1;

/// Expected squarings a browser solver can complete per second (native
/// BigInt 2048-bit modmul). Used to derive the per-challenge minimum
/// solve duration; the bound is generous, since a specialized native
/// implementation stays far below the assumed rate.
pub const RSW_SOLVER_SQUARINGS_PER_SEC: f64 = 5e6;

/// Expected hashes a browser solver can attempt per second (SHA-256, WASM).
/// Used to derive the per-challenge minimum solve duration.
pub const SHA256_SOLVER_HASHES_PER_SEC: f64 = 5e9;

/// The combinatorial decoy-name grammar, the server-side naming space for
/// decoy (honeypot) form fields. When a deployment arms the decoy surface
/// ([`issue_challenge_with_decoy`]), the issuer draws one lowercase word
/// per slot (`CSPRNG`) and joins them with '_' to form the grammar prefix
/// {slot1}_{slot2}_{slot3}, e.g. `secondary_contact_phone` or
/// `billing_company_url`. The three position-specific vocabularies below
/// are shared verbatim with the PHP
/// `Issuer::DECOY_GRAMMAR_SLOT1_QUALIFIER` / `_SLOT2_CATEGORY` /
/// `_SLOT3_FORM` (same words, same order). The pick itself is never
/// coordinated between the languages: the issuing core signs whatever it
/// picked, and verification validates alphabet plus canonical, never the
/// name.
///
/// The armed name is the prefix plus a per-issuance random suffix:
/// {slot1}_{slot2}_{slot3}_{suffix} with a 16-lowercase-hex suffix drawn
/// from 8 [`security_random`] bytes (see [`compose_decoy_prefix`] and
/// [`decoy_name_suffix`]), e.g.
/// `billing_address_line_a3f9c21d8e5b7401`. The suffix is the collision
/// disambiguator: an application field whose name equals a grammar prefix
/// (a plausible real field name, e.g. `billing_address_line`) can still
/// collide with an armed name only when it also equals the per-issuance
/// 64-bit suffix. The accidental-match probability for a given issued
/// name is 2^-64, so a forced collision is a deliberate act, never an
/// accident.
///
/// Prefix space size: `SLOT1`.len() * `SLOT2`.len() * `SLOT3`.len() =
/// 32 * 29 * 30 = 27,840 distinct prefixes. Each triple joins to a
/// unique string because '_' cannot occur inside a word. The prefix is
/// `[a-z_]+` of at most 30 bytes (the longest word is 10 bytes); the
/// armed name adds 1 + 16 bytes for the '_' + suffix, at most 47 bytes.
/// Every armed name is a subset of the `[A-Za-z0-9_-]{1,64}` shape the
/// widget driver and the validation accept. No name can ever smuggle the
/// `|` canonical-payload separator.
/// The legacy 10-name pool words (company_website, fax_number, ...) all
/// remain present as vocabulary entries, but the `SELECTION` is
/// combinatorial: a fixed 10-name pool is log2(10) ~ 3.32 bits of
/// enumerable space, the grammar prefix space is log2(27,840) ~ 14.8
/// bits, and the armed name space is 27,840 * 2^64, so two consecutive
/// challenges share a full name with probability ~2^-64.
pub const DECOY_GRAMMAR_SLOT1_QUALIFIER: &[&str] = &[
    "secondary",
    "alternate",
    "billing",
    "office",
    "personal",
    "company",
    "home",
    "backup",
    "department",
    "business",
    "primary",
    "work",
    "emergency",
    "mobile",
    "regional",
    "corporate",
    "team",
    "project",
    "default",
    "temporary",
    "external",
    "internal",
    "private",
    "shared",
    "general",
    "local",
    "main",
    "national",
    "seasonal",
    "guest",
    "middle",
    "assistant",
];

/// The slot-2 vocabulary (the category slot) of the decoy-name grammar,
/// see [`DECOY_GRAMMAR_SLOT1_QUALIFIER`]. The word `company` appears in
/// both slot 1 and slot 2 on purpose: `billing_company_url` and
/// `company_billing_url` are both plausible optional field names.
pub const DECOY_GRAMMAR_SLOT2_CATEGORY: &[&str] = &[
    "contact",
    "address",
    "phone",
    "email",
    "website",
    "fax",
    "company",
    "account",
    "profile",
    "order",
    "invoice",
    "support",
    "service",
    "sales",
    "location",
    "region",
    "branch",
    "division",
    "directory",
    "registry",
    "record",
    "file",
    "entry",
    "channel",
    "portal",
    "platform",
    "list",
    "archive",
    "history",
];

/// The slot-3 vocabulary (the form slot) of the decoy-name grammar, see
/// [`DECOY_GRAMMAR_SLOT1_QUALIFIER`].
pub const DECOY_GRAMMAR_SLOT3_FORM: &[&str] = &[
    "phone",
    "url",
    "number",
    "line",
    "code",
    "name",
    "extension",
    "email",
    "address",
    "link",
    "id",
    "key",
    "value",
    "info",
    "details",
    "notes",
    "lookup",
    "search",
    "query",
    "reference",
    "alias",
    "handle",
    "username",
    "label",
    "tag",
    "entry",
    "record",
    "index",
    "field",
    "form",
];

/// Whether `s` is a conforming decoy (honeypot) field name: 1..=64 bytes of
/// `[A-Za-z0-9_-]` — the exact shape the widget driver validates before
/// rendering the hidden input. The alphabet excludes `|`, so a decoy name
/// can never alter the structure of the v2 canonical signing input.
pub(crate) fn valid_decoy_field_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

/// The combinatorial prefix space size, `SLOT1`.len() * `SLOT2`.len() *
/// `SLOT3`.len().
pub const fn decoy_grammar_space_size() -> usize {
    DECOY_GRAMMAR_SLOT1_QUALIFIER.len()
        * DECOY_GRAMMAR_SLOT2_CATEGORY.len()
        * DECOY_GRAMMAR_SLOT3_FORM.len()
}

/// Whether `name` is a grammar prefix: three underscore-joined
/// vocabulary words, each from its position-specific list, within the
/// `[A-Za-z0-9_-]{1,64}` validation shape.
pub fn is_grammar_decoy_prefix(name: &str) -> bool {
    if !valid_decoy_field_name(name) {
        return false;
    }
    let mut parts = name.split('_');
    let (Some(s1), Some(s2), Some(s3), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return false;
    };
    DECOY_GRAMMAR_SLOT1_QUALIFIER.contains(&s1)
        && DECOY_GRAMMAR_SLOT2_CATEGORY.contains(&s2)
        && DECOY_GRAMMAR_SLOT3_FORM.contains(&s3)
}

/// Whether `name` is an armed decoy name: a grammar prefix
/// ([`is_grammar_decoy_prefix`]) plus '_' plus the 16 lowercase hex
/// suffix characters, within the `[A-Za-z0-9_-]{1,64}` validation shape.
pub fn is_grammar_decoy_name(name: &str) -> bool {
    if !valid_decoy_field_name(name) {
        return false;
    }
    let mut parts = name.split('_');
    let (Some(s1), Some(s2), Some(s3), Some(suffix), None) = (
        parts.next(),
        parts.next(),
        parts.next(),
        parts.next(),
        parts.next(),
    ) else {
        return false;
    };
    DECOY_GRAMMAR_SLOT1_QUALIFIER.contains(&s1)
        && DECOY_GRAMMAR_SLOT2_CATEGORY.contains(&s2)
        && DECOY_GRAMMAR_SLOT3_FORM.contains(&s3)
        && suffix.len() == 16
        && suffix
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// The deterministic grammar prefix for the given vocabulary indices,
/// {slot1}_{slot2}_{slot3}. Pure and public so tests can enumerate the
/// prefix space, pin the vocabularies, and run fixed-seed collision
/// statistics without touching the `CSPRNG`.
pub fn compose_decoy_prefix(slot1: usize, slot2: usize, slot3: usize) -> String {
    format!(
        "{}_{}_{}",
        DECOY_GRAMMAR_SLOT1_QUALIFIER[slot1],
        DECOY_GRAMMAR_SLOT2_CATEGORY[slot2],
        DECOY_GRAMMAR_SLOT3_FORM[slot3]
    )
}

/// The per-issuance random suffix of an armed decoy name: 16 lowercase
/// hex characters drawn from 8 bytes of the `CSPRNG`, 64 random bits.
/// The suffix is the collision disambiguator of the armed name space: a
/// grammar prefix alone is a plausible real field name, so only the
/// suffix makes an armed name unguessable and accidental collision
/// impossible. Mirrors the PHP `Issuer::decoyNameSuffix`.
fn decoy_name_suffix() -> Result<String, SignError> {
    let bytes = security_random::<8>().map_err(|_| SignError::Rng)?;
    Ok(hex::encode(&bytes))
}

/// Pick a random armed decoy field name with the `CSPRNG` (never a
/// weak/insecure fallback — an RNG failure propagates to the caller as
/// [`SignError::Rng`], exactly like the nonce/salt draws): a grammar
/// prefix (each slot draws an unbiased index via rejection sampling)
/// plus the fresh 16-hex suffix.
fn pick_decoy_field() -> Result<String, SignError> {
    Ok(format!(
        "{}_{}",
        compose_decoy_prefix(
            pick_decoy_slot_index(DECOY_GRAMMAR_SLOT1_QUALIFIER.len())?,
            pick_decoy_slot_index(DECOY_GRAMMAR_SLOT2_CATEGORY.len())?,
            pick_decoy_slot_index(DECOY_GRAMMAR_SLOT3_FORM.len())?,
        ),
        decoy_name_suffix()?,
    ))
}

/// One unbiased vocabulary index draw: rejection sampling over a single
/// `CSPRNG` byte, so every word in the vocabulary has exactly equal
/// probability (a plain modulo of a byte would bias vocabularies whose
/// length does not divide 256).
fn pick_decoy_slot_index(vocab_len: usize) -> Result<usize, SignError> {
    let limit = 256 - (256 % vocab_len);
    loop {
        let byte = security_random::<1>().map_err(|_| SignError::Rng)?[0];
        if (byte as usize) < limit {
            return Ok(byte as usize % vocab_len);
        }
    }
}

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
        // Hard bound: pruning removes only expired entries, so a burst
        // of distinct fresh keys inside one TTL window could otherwise
        // grow the map without limit. After the prune, the map is still
        // over the maximum: evict the least-recently-used entry (the linear scan is
        // acceptable at the 256-entry scale; a cache miss is already the
        // cheaper alternative to a fresh issuance, and the bound is what
        // matters: 256 is a real maximum, not a per-second rate).
        if self.entries.len() >= 256 {
            let oldest = self
                .entries
                .iter()
                .min_by_key(|(_, (_, ts))| *ts)
                .map(|(k, _)| k.clone());
            if let Some(oldest_key) = oldest {
                self.entries.remove(&oldest_key);
            }
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
    issue_challenge_inner(
        config,
        scope,
        client_ip,
        now_unix,
        now_ns,
        active_solves,
        request_binding,
        false,
        false,
        None,
        None,
    )
}

/// Issue a challenge with the decoy (honeypot) surface armed — the
/// issuance-side switch of the risk engine's honeypot/decoy signals
/// (`DecoyFieldSubmitted`, `honeypot_hit`). Identical to
/// [`issue_challenge`] in every other respect (same wire format, same
/// signing, same storage); when `arm_decoy_field` is true the issuer picks
/// a fresh armed name, a grammar prefix plus a fresh 16-hex `CSPRNG`
/// suffix (see [`DECOY_GRAMMAR_SLOT1_QUALIFIER`], `CSPRNG`; a fresh
/// independent pick per issuance — the suffix gives every issuance its
/// own 64 random bits, so the probability that two consecutive
/// challenges share a full name is ~2^-64, and accidental collision
/// with any other name, application fields included, is
/// cryptographically impossible), sets it on the client-facing
/// [`IssuedChallenge::decoy_field`] (the widget driver renders the hidden
/// input from that key) AND on the stored record's authenticated
/// `decoy_field`, signed into the canonical input as the final
/// `|<decoy_field>` segment — a client cannot strip or swap the decoy
/// without breaking the signature the verifier re-checks. An armed
/// issuance writes `protocol_version == 3` (the decoy-capable canonical);
/// `false` behaves exactly like [`issue_challenge`] (no decoy,
/// `protocol_version == 2`, byte-identical canonical string).
#[allow(clippy::too_many_arguments)]
pub fn issue_challenge_with_decoy(
    config: &ChallengeConfig,
    scope: &str,
    client_ip: &str,
    now_unix: u64,
    now_ns: u64,
    active_solves: u64,
    request_binding: Option<&str>,
    arm_decoy_field: bool,
) -> Result<Issued, SignError> {
    issue_challenge_inner(
        config,
        scope,
        client_ip,
        now_unix,
        now_ns,
        active_solves,
        request_binding,
        arm_decoy_field,
        false,
        None,
        None,
    )
}

/// Issue a challenge with the ExecutionChallengeV1 dimension armed —
/// the browser-execution surface of the adaptive-risk layer: when
/// `arm_execution` is true the issuer mints a deterministic bytecode
/// program from the challenge context (nonce, scope, action, version)
/// via [`crate::execution::generate`], stamps it on the stored record's
/// `execution_program` AND the client-facing
/// [`IssuedChallenge::execution_program`] (base64, omitted when
/// unarmed). The driver runs the program in its sandboxed ephemeral
/// interpreter and presents the resulting execution digest with the
/// solution token; the verifier recomputes the expected digest from the
/// stored program and rejects a mismatch with the deterministic
/// `ExecutionMismatch`. The dimension is supplementary evidence only —
/// never the sole acceptance boundary; the PoW proof and the record
/// state machinery still gate.
///
/// Arming requires the configured `execution_key` (see
/// [`ChallengeConfig::execution_key`]); arming without the key refuses
/// with [`SignError::ExecutionKeyNotConfigured`]. `execution_action` is
/// the provider-style action of the request (1..32 chars of
/// `[A-Za-z0-9._:-]`, default "default") and `execution_version` the
/// dimension protocol version, the canonical numeric byte (default 1,
/// the live grammar range 1..=MAX_EXECUTION_VERSION; passed as a u8,
/// never a string that is parsed). Both are embedded in the program and
/// bound by the commitment.
///
/// An armed issuance writes `protocol_version == 4`: the stored record
/// carries `execution_program` plus the authenticated
/// `execution_version` and `execution_commitment` (hex SHA-256 of the
/// program) signed into the canonical input as the final
/// `|execution_version|execution_commitment` segments — stripping,
/// substituting or injecting a program always breaks the signature.
#[allow(clippy::too_many_arguments)]
pub fn issue_challenge_with_execution(
    config: &ChallengeConfig,
    scope: &str,
    client_ip: &str,
    now_unix: u64,
    now_ns: u64,
    active_solves: u64,
    request_binding: Option<&str>,
    arm_execution: bool,
    execution_action: Option<&str>,
    execution_version: Option<u8>,
    arm_decoy_field: bool,
) -> Result<Issued, SignError> {
    issue_challenge_inner(
        config,
        scope,
        client_ip,
        now_unix,
        now_ns,
        active_solves,
        request_binding,
        arm_decoy_field,
        arm_execution,
        execution_action,
        execution_version,
    )
}

/// The shared issuance body (see the [`issue_challenge`] contract).
#[allow(clippy::too_many_arguments)]
fn issue_challenge_inner(
    config: &ChallengeConfig,
    scope: &str,
    client_ip: &str,
    now_unix: u64,
    now_ns: u64,
    active_solves: u64,
    request_binding: Option<&str>,
    arm_decoy_field: bool,
    arm_execution: bool,
    execution_action: Option<&str>,
    execution_version: Option<u8>,
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
    // The rsw algorithm is opt-in and requires the full trapdoor
    // configuration: the modulus and lambda are mandatory and valid
    // (validated by the shared RswTrapdoor decode), and the sequential
    // cost T must sit within the issuance bounds. With any other
    // algorithm the rsw fields are inert and unvalidated, so the
    // default deployment never touches them.
    if algorithm == PoWAlgorithm::Rsw {
        let (Some(modulus), Some(lambda)) = (
            config.rsw_modulus_n.as_deref(),
            config.rsw_lambda.as_deref(),
        ) else {
            return Err(SignError::InvalidRswParams);
        };
        if crate::rsw::RswTrapdoor::new(modulus, lambda).is_err() {
            return Err(SignError::InvalidRswParams);
        }
        if config.rsw_t < MIN_RSW_T || config.rsw_t > MAX_RSW_T {
            return Err(SignError::InvalidRswParams);
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

    // Protocol v2/v3: sign the full-parameter canonical input so no
    // issuance parameter (algorithm, difficulty, TTL, salt, …) can be
    // tampered with without breaking the signature. The challenge string
    // is `base64(canonical).hex_tag` — same structure as v1. The signature
    // is computed with the `HKDF`-derived challenge key, never the
    // master secret directly.
    //
    // The decoy (honeypot) field name, when armed, is picked before the
    // canonical input is built: it is an authenticated issuance parameter
    // (the `|<decoy_field>` segment), signed like every other, and the
    // record is issued as protocol v3.
    let decoy_field: Option<String> = if arm_decoy_field {
        Some(pick_decoy_field()?)
    } else {
        None
    };
    // The rsw canonical parameter mapping: the fixed v2 slots carry the
    // time-lock's knobs, since no canonical segment changes. The
    // sequential-squaring cost T rides the time-cost slot t; the memory
    // slot m_kib is 0, the parallelism slot p is 1, and the difficulty
    // slot carries the rsw target_bits pin (RSW_TARGET_BITS_PIN, the
    // protocol floor) because the canonical always renders the field
    // and rsw has no leading-zero target. The verifier's rsw path reads
    // t and never consults the other slots. Any other algorithm keeps
    // the exact historical parameter mapping.
    let is_rsw = algorithm == PoWAlgorithm::Rsw;
    let record_m_kib = if is_rsw { 0 } else { config.m_kib };
    let record_t = if is_rsw { config.rsw_t } else { config.t };
    let record_p = if is_rsw { 1 } else { config.p };
    // The ExecutionChallengeV1 program, minted from the challenge
    // context once the nonce exists (the program binds the nonce), and
    // before the canonical input is built: the commitment segments are
    // part of the signed canonical and the commitment is a function of
    // the program. Arming without the configured execution_key is a
    // misconfiguration and refuses the issuance: the execution
    // dimension can never be armed by accident.
    let execution_program: Option<String> = if arm_execution {
        match &config.execution_key {
            None => return Err(SignError::ExecutionKeyNotConfigured),
            Some(key) => {
                let version = execution_version.unwrap_or(1);
                Some(
                    crate::execution::generate(
                        key.as_bytes(),
                        &nonce,
                        scope,
                        execution_action.unwrap_or("default"),
                        version,
                    )
                    .map_err(|e| match e {
                        crate::execution::GenerateError::KeyTooShort => {
                            SignError::ExecutionKeyNotConfigured
                        }
                        crate::execution::GenerateError::InvalidAction => {
                            SignError::InvalidIdentifier
                        }
                        crate::execution::GenerateError::InvalidVersion => {
                            SignError::InvalidIdentifier
                        }
                        crate::execution::GenerateError::InvalidScope => {
                            SignError::InvalidIdentifier
                        }
                    })?,
                )
            }
        }
    } else {
        None
    };
    // The authenticated commitment is the hex SHA-256 of the stored
    // program's base64 wire string — the exact mirror of the stored
    // program, signed into the canonical below.
    let execution_commitment: Option<String> =
        execution_program.as_deref().map(execution_commitment);
    let mut record = ChallengeRecord {
        nonce: nonce.clone(),
        scope: scope.to_string(),
        binding_tag: binding.clone(),
        hostname: None,
        issued_at: now_unix,
        expires_at,
        algorithm,
        m_kib: record_m_kib,
        t: record_t,
        p: record_p,
        target_bits,
        salt: salt.clone(),
        prefix: String::new(),    // computed below once the challenge is signed
        challenge: String::new(), // computed below
        min_duration_ms,
        issued_at_ns: now_ns,
        attempts_used: 0,
        // Armed issuance writes protocol v4 (the execution-capable
        // canonical, signed with the execution commitment segments when
        // the dimension is armed); decoy-only issuance writes protocol
        // v3 (the decoy-capable canonical); unarmed issuance stays v2,
        // byte-identical to the pre-decoy format.
        protocol_version: if execution_program.is_some() {
            4
        } else if arm_decoy_field {
            3
        } else {
            2
        },
        region: config.region.clone(),
        policy_version: config.policy_version,
        request_binding: request_binding.map(str::to_string),
        issuer: config.issuer.clone(),
        kid: config.kid,
        decoy_field: decoy_field.clone(),
        execution_program: execution_program.clone(),
        // The authenticated v4 execution triplet: the version and the
        // commitment ride the stored record exactly as they were signed
        // (never recomputed), so the equivalence between the signed
        // canonical and the stored program is preserved byte-for-byte
        // through storage round-trips.
        execution_version: execution_program
            .as_ref()
            .map(|_| execution_version.unwrap_or(1)),
        execution_commitment: execution_commitment.clone(),
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
        m_kib: record_m_kib,
        t: record_t,
        p: record_p,
        target_bits,
        ttl_secs: config.ttl_secs,
        prefix: record.prefix.clone(),
        algorithm,
        min_duration_ms,
        decoy_field,
        execution_program,
        // The rsw modulus rides the client-facing response (the solver
        // squares modulo n); lambda never leaves the server.
        rsw_modulus: if is_rsw {
            config.rsw_modulus_n.clone()
        } else {
            None
        },
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
    /// Execution challenges were armed for this issuance but no
    /// `execution_key` is configured — the execution dimension can never
    /// be armed by accident.
    #[error("execution challenges are armed but no execution_key is configured")]
    ExecutionKeyNotConfigured,
    /// The rsw algorithm was selected without the full trapdoor
    /// configuration: the modulus and lambda are mandatory, valid
    /// (canonical base64 of the documented shapes) and within the
    /// issuance bounds, and T must sit within 10,000..=300,000.
    #[error("the rsw algorithm requires a valid rsw_modulus_n and rsw_lambda trapdoor pair with rsw_t within 10_000..=300_000")]
    InvalidRswParams,
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
    use crate::verify::RequestBindingExpectation;
    use rand::rngs::StdRng;
    use rand::{Rng, SeedableRng};

    // Test "now_ns" values are epoch microseconds (1_700_000_000_000_000 µs
    // ≈ 2023-11-14 UTC) — the unit the crate shares with PHP, see
    // [`now_epoch_micros`].

    #[test]
    fn issued_challenge_has_correct_difficulty() {
        let config = ChallengeConfig {
            secret_key: "super-secret-key".into(),
            kid: 1,
            execution_key: None,
            rsw_modulus_n: None,
            rsw_lambda: None,
            rsw_t: crate::challenge::DEFAULT_RSW_T,
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
                execution_key: None,
                rsw_modulus_n: None,
                rsw_lambda: None,
                rsw_t: crate::challenge::DEFAULT_RSW_T,
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
            execution_key: None,
            rsw_modulus_n: None,
            rsw_lambda: None,
            rsw_t: crate::challenge::DEFAULT_RSW_T,
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
            execution_key: None,
            rsw_modulus_n: None,
            rsw_lambda: None,
            rsw_t: crate::challenge::DEFAULT_RSW_T,
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
            execution_key: None,
            rsw_modulus_n: None,
            rsw_lambda: None,
            rsw_t: crate::challenge::DEFAULT_RSW_T,
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
            execution_key: None,
            rsw_modulus_n: None,
            rsw_lambda: None,
            rsw_t: crate::challenge::DEFAULT_RSW_T,
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
            execution_key: None,
            rsw_modulus_n: None,
            rsw_lambda: None,
            rsw_t: crate::challenge::DEFAULT_RSW_T,
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
                execution_key: None,
                rsw_modulus_n: None,
                rsw_lambda: None,
                rsw_t: crate::challenge::DEFAULT_RSW_T,
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
    fn challenge_cache_is_hard_bounded_even_with_all_fresh_entries() {
        // The finding: pruning removes only expired entries, so
        // a burst of distinct fresh keys inside one window could
        // grow the map without limit. The hard bound evicts
        // the least-recently-used entry after the prune, so 256 is a real maximum.
        let mut cache = ChallengeCache::with_ttl_for_test(Duration::from_secs(60));
        let config = ChallengeConfig {
            secret_key: "test-key-16-bytes!".into(),
            kid: 1,
            execution_key: None,
            rsw_modulus_n: None,
            rsw_lambda: None,
            rsw_t: crate::challenge::DEFAULT_RSW_T,
            algorithm: PoWAlgorithm::Sha256,
            m_kib: 65_536,
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
            argon2_target_bits: 8,
            min_duration_ms: None,
        };
        // 300 distinct fresh keys — far beyond the 256 maximum.
        for i in 0..300 {
            let issued = issue_challenge(
                &config,
                "login",
                "1.2.3.4",
                1_800_000_000,
                1_800_000_000_000,
                0,
                None,
            )
            .unwrap();
            cache.put(&format!("hash-{i}"), "login", issued);
        }
        assert_eq!(
            cache.len(),
            256,
            "the cache is HARD-bounded at 256 even when every entry is fresh"
        );
    }

    #[test]
    fn challenge_cache_put_prunes_expired_entries() {
        let mut cache = ChallengeCache::with_ttl_for_test(Duration::from_secs(60));
        let config = ChallengeConfig {
            secret_key: "test-key-16-bytes!".into(),
            kid: 1,
            execution_key: None,
            rsw_modulus_n: None,
            rsw_lambda: None,
            rsw_t: crate::challenge::DEFAULT_RSW_T,
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
            execution_key: None,
            rsw_modulus_n: None,
            rsw_lambda: None,
            rsw_t: crate::challenge::DEFAULT_RSW_T,
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
            execution_key: None,
            rsw_modulus_n: None,
            rsw_lambda: None,
            rsw_t: crate::challenge::DEFAULT_RSW_T,
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
            execution_key: None,
            rsw_modulus_n: None,
            rsw_lambda: None,
            rsw_t: crate::challenge::DEFAULT_RSW_T,
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

    /// The rsw fixture issuance config: the shared test modulus and
    /// lambda with the smallest allowed sequential cost (fast solves).
    fn rsw_config(t: u32) -> ChallengeConfig {
        ChallengeConfig {
            secret_key: "test-key-16-bytes!".into(),
            kid: 1,
            execution_key: None,
            rsw_modulus_n: Some(crate::rsw::fixtures::MODULUS_N_B64.into()),
            rsw_lambda: Some(crate::rsw::fixtures::LAMBDA_B64.into()),
            rsw_t: t,
            algorithm: PoWAlgorithm::Rsw,
            m_kib: 0,
            t: 1,
            p: 1,
            target_bits: 8,
            argon2_target_bits: 8,
            min_duration_ms: Some(0),
            ttl_secs: 120,
            auto_tune: false,
            auto_tune_min_bits: 8,
            auto_tune_max_bits: 20,
            binding_mode: BindingMode::Bound,
            region: None,
            issuer: None,
            policy_version: 1,
        }
    }

    // ── rsw (sequential time-lock) issuance ───────────────────────────

    #[test]
    fn rsw_issuance_carries_the_canonical_parameter_mapping() {
        let issued = issue_challenge(
            &rsw_config(MIN_RSW_T),
            "login",
            "1.2.3.4",
            1_000_000,
            1_700_000_000_000_000,
            0,
            None,
        )
        .unwrap();
        // The canonical v2 slots carry the time-lock knobs: T rides the
        // time-cost slot, m_kib is 0, p is 1, and target_bits is pinned
        // to the protocol floor (rsw has no leading-zero target).
        assert_eq!(issued.record.algorithm, PoWAlgorithm::Rsw);
        assert_eq!(issued.record.t, MIN_RSW_T);
        assert_eq!(issued.record.m_kib, 0);
        assert_eq!(issued.record.p, 1);
        assert_eq!(issued.record.target_bits, RSW_TARGET_BITS_PIN);
        assert_eq!(issued.challenge.t, MIN_RSW_T);
        assert_eq!(
            issued.challenge.rsw_modulus.as_deref(),
            Some(crate::rsw::fixtures::MODULUS_N_B64),
            "the modulus rides the client-facing response"
        );
        assert_eq!(
            issued.record.protocol_version, 2,
            "rsw issuance stays protocol v2"
        );
        assert_eq!(
            issued.record.decoy_field, None,
            "rsw issuance never arms the decoy surface"
        );
        // The canonical payload really says rsw in the algorithm slot:
        // the challenge is base64 of the signed canonical, so decode the
        // payload half before matching the segment structure.
        let payload = String::from_utf8(
            base64::engine::general_purpose::STANDARD
                .decode(issued.record.challenge.split('.').next().unwrap())
                .unwrap(),
        )
        .unwrap();
        assert!(payload.contains("|rsw|0|10000|1|1|"), "{payload}");
        // A sha256 issuance never carries the modulus on the wire.
        let sha_issued = issue_challenge(
            &profile_base_config(),
            "login",
            "1.2.3.4",
            1_000_000,
            1_700_000_000_000_000,
            0,
            None,
        )
        .unwrap();
        assert_eq!(sha_issued.challenge.rsw_modulus, None);
        let sha_json = serde_json::to_value(&sha_issued.challenge).unwrap();
        assert!(
            sha_json.get("rsw_modulus").is_none(),
            "the key is absent unless the challenge is rsw"
        );
        let rsw_json = serde_json::to_value(&issued.challenge).unwrap();
        assert!(
            rsw_json.get("rsw_modulus").is_some(),
            "an rsw challenge carries the modulus"
        );
    }

    #[test]
    fn rsw_min_duration_floor_derives_from_t() {
        let mut min_t = rsw_config(MIN_RSW_T);
        min_t.min_duration_ms = None;
        let issued = issue_challenge(
            &min_t,
            "login",
            "1.2.3.4",
            1_000_000,
            1_700_000_000_000_000,
            0,
            None,
        )
        .unwrap();
        assert_eq!(
            issued.record.min_duration_ms, 50,
            "the 50 ms absolute floor applies at the smallest T"
        );
        let mut max_t = rsw_config(MAX_RSW_T);
        max_t.min_duration_ms = None;
        let issued = issue_challenge(
            &max_t,
            "login",
            "1.2.3.4",
            1_000_000,
            1_700_000_000_000_000,
            0,
            None,
        )
        .unwrap();
        assert_eq!(
            issued.record.min_duration_ms, 60,
            "T=300,000 derives ceil(300000 / 5e6 * 1000) = 60 ms"
        );
        // An operator override still wins over the derived floor.
        let mut overridden = rsw_config(MAX_RSW_T);
        overridden.min_duration_ms = Some(1234);
        let issued = issue_challenge(
            &overridden,
            "login",
            "1.2.3.4",
            1_000_000,
            1_700_000_000_000_000,
            0,
            None,
        )
        .unwrap();
        assert_eq!(issued.record.min_duration_ms, 1234);
    }

    #[test]
    fn rsw_issuance_requires_the_full_trapdoor() {
        let mut missing = rsw_config(MIN_RSW_T);
        missing.rsw_lambda = None;
        assert!(matches!(
            issue_challenge(
                &missing,
                "login",
                "1.2.3.4",
                1_000_000,
                1_700_000_000_000_000,
                0,
                None
            )
            .unwrap_err(),
            SignError::InvalidRswParams
        ));
        let mut missing_modulus = rsw_config(MIN_RSW_T);
        missing_modulus.rsw_modulus_n = None;
        assert!(matches!(
            issue_challenge(
                &missing_modulus,
                "login",
                "1.2.3.4",
                1_000_000,
                1_700_000_000_000_000,
                0,
                None
            )
            .unwrap_err(),
            SignError::InvalidRswParams
        ));
        let mut malformed = rsw_config(MIN_RSW_T);
        malformed.rsw_modulus_n = Some("not-base64!".into());
        assert!(matches!(
            issue_challenge(
                &malformed,
                "login",
                "1.2.3.4",
                1_000_000,
                1_700_000_000_000_000,
                0,
                None
            )
            .unwrap_err(),
            SignError::InvalidRswParams
        ));
        // A zero modulus lacks the top bit and the odd parity: the shared
        // shape validation refuses it at issuance.
        let mut bad_shape = rsw_config(MIN_RSW_T);
        bad_shape.rsw_modulus_n =
            Some(base64::engine::general_purpose::STANDARD.encode([0u8; 256]));
        assert!(matches!(
            issue_challenge(
                &bad_shape,
                "login",
                "1.2.3.4",
                1_000_000,
                1_700_000_000_000_000,
                0,
                None
            )
            .unwrap_err(),
            SignError::InvalidRswParams
        ));
    }

    #[test]
    fn rsw_issuance_rejects_weak_or_inconsistent_trapdoor_material() {
        use num_bigint::BigUint;
        let modulus_b64 = |value: &BigUint| {
            let bytes = value.to_bytes_be();
            let mut padded = vec![0u8; 256 - bytes.len()];
            padded.extend_from_slice(&bytes);
            base64::engine::general_purpose::STANDARD.encode(&padded)
        };
        let reject = |config: &ChallengeConfig| {
            assert!(matches!(
                issue_challenge(
                    config,
                    "login",
                    "1.2.3.4",
                    1_000_000,
                    1_700_000_000_000_000,
                    0,
                    None
                )
                .unwrap_err(),
                SignError::InvalidRswParams
            ));
        };
        let fixture = crate::rsw::fixtures::LAMBDA_B64;

        // A modulus divisible by the small prime 3, shaped exactly like
        // a genuine 2048-bit modulus.
        let mut weak = rsw_config(MIN_RSW_T);
        let factor_three =
            BigUint::from(3u8) * ((BigUint::from(1u8) << 2046usize) + BigUint::from(1u8));
        weak.rsw_modulus_n = Some(modulus_b64(&factor_three));
        reject(&weak);

        // A real 2048-bit probable prime as the modulus.
        let mut prime = rsw_config(MIN_RSW_T);
        prime.rsw_modulus_n = Some(
            "3QB709I66Q8Ivp2P5RtgD4+ci38dHuAuXfzGL4KtCk34UGX9uOG1FgNV92B9BcVS1iX4JCYdqN9cHg62sqEWx+p0fn7rUCuPYZSFpnwcWpVjHMbigzz2wjWt2mhkqLtbgZ/+nar/ptQu7aHKOrQYVAppYf0txmfwtnUbHSWpyMZhUv10JSnNPRuPL6wrb0cH8TjHex2W90islc3qPAwi9lAZdtX/+OepFBLDkmjnE4yi2SyBZ75kHWn+ve7nXg0352zbPtL3gos658lJsVVdt3IbqeVf1I9wnViRYpIS+EYHK5olWm3+sOxwZfbixlgLh0p3JafQoCnZpkF2j+9Gzw=="
                .into(),
        );
        reject(&prime);

        // The fixture lambda shifted by two: even and correctly shaped,
        // but no longer a multiple of the Carmichael value.
        let mut shifted_lambda = rsw_config(MIN_RSW_T);
        let lambda = BigUint::from_bytes_be(
            &base64::engine::general_purpose::STANDARD
                .decode(fixture)
                .expect("the fixture lambda is base64"),
        );
        let shifted = (&lambda - BigUint::from(2u8)).to_bytes_be();
        shifted_lambda.rsw_lambda =
            Some(base64::engine::general_purpose::STANDARD.encode(&shifted));
        reject(&shifted_lambda);
    }

    #[test]
    fn rsw_issuance_validates_t_bounds() {
        for t in [MIN_RSW_T - 1, MAX_RSW_T + 1, 0] {
            let config = rsw_config(t);
            assert!(matches!(
                issue_challenge(
                    &config,
                    "login",
                    "1.2.3.4",
                    1_000_000,
                    1_700_000_000_000_000,
                    0,
                    None
                )
                .unwrap_err(),
                SignError::InvalidRswParams
            ));
        }
        // The rsw fields are inert for sha256: garbage is carried, never
        // validated, and the sha challenge issues normally.
        let mut sha = profile_base_config();
        sha.rsw_modulus_n = Some("garbage".into());
        sha.rsw_lambda = Some("garbage".into());
        sha.rsw_t = 1;
        let issued = issue_challenge(
            &sha,
            "login",
            "1.2.3.4",
            1_000_000,
            1_700_000_000_000_000,
            0,
            None,
        )
        .unwrap();
        assert_eq!(issued.record.algorithm, PoWAlgorithm::Sha256);
        assert_eq!(issued.challenge.rsw_modulus, None);
    }

    // ── decoy (honeypot) field issuance ──────────────────────────────

    #[test]
    fn decoy_field_issuance_arms_a_signed_armed_name() {
        // Armed: the client-facing token and the stored record both carry
        // the armed name (a grammar prefix plus the 16-hex suffix, at
        // most 47 bytes), the record is issued as protocol v3 (the
        // decoy-capable canonical), the canonical input ends with the
        // `|<name>` segment, and the signature verifies over that exact
        // extended input.
        let issued = issue_challenge_with_decoy(
            &profile_base_config(),
            "login",
            "1.2.3.4",
            1_000_000,
            1_700_000_000_000_000,
            0,
            None,
            true,
        )
        .unwrap();
        let decoy = issued.challenge.decoy_field.clone().expect("decoy armed");
        assert!(
            is_grammar_decoy_name(&decoy),
            "the decoy name must be a grammar prefix plus suffix (got {decoy})"
        );
        assert!(
            is_grammar_decoy_prefix(&decoy[..decoy.len() - 17]),
            "the name must start with a grammar prefix"
        );
        assert!(valid_decoy_field_name(&decoy));
        assert!(
            decoy.len() <= 47,
            "the armed name (prefix + suffix) must be at most 47 bytes (got {})",
            decoy.len()
        );
        assert_eq!(issued.record.decoy_field.as_deref(), Some(decoy.as_str()));
        assert_eq!(
            issued.record.protocol_version, 3,
            "an armed issuance writes protocol v3 (the decoy-capable canonical)"
        );

        let canonical = canonical_signing_input_v2(&issued.record);
        assert!(
            canonical.ends_with(&format!("|{decoy}")),
            "the decoy name must be the FINAL canonical segment: {canonical}"
        );
        assert_eq!(
            canonical.split('|').count(),
            19,
            "v3 canonical input: the 18-field v2 base + the decoy segment"
        );
        // The signature covers the extended input (verifies as issued).
        let sig = crate::verify::signature_from_challenge(&issued.record);
        assert!(verify_signature_v2(&issued.record, sig, "test-key-16-bytes!").unwrap());
        // The client-decodable challenge string carries it too (the
        // canonical payload IS the pre-image of the challenge base64).
        let (payload, _sig) = issued
            .record
            .challenge
            .rsplit_once('.')
            .expect("challenge is base64.signature");
        let decoded = B64.decode(payload).expect("challenge payload decodes");
        assert!(String::from_utf8_lossy(&decoded).ends_with(&decoy));

        // Two armed issuances pick independently (a fresh `CSPRNG` draw per
        // challenge; across a handful of issuances at least two names
        // appear — the picks must not collapse to a constant).
        let mut seen = std::collections::HashSet::new();
        for i in 0..40u64 {
            let issued = issue_challenge_with_decoy(
                &profile_base_config(),
                "login",
                "1.2.3.4",
                1_000_000 + i,
                1_700_000_000_000_000 + i * 1_000,
                0,
                None,
                true,
            )
            .unwrap();
            seen.insert(issued.challenge.decoy_field.clone().unwrap());
            if seen.len() >= 2 {
                break;
            }
        }
        assert!(
            seen.len() >= 2,
            "per-issuance decoy picks must vary across challenges"
        );
    }

    #[test]
    fn decoy_grammar_prefix_space_is_large_and_every_prefix_valid() {
        // The combinatorial prefix space: `SLOT1` * `SLOT2` * `SLOT3` =
        // 32 * 29 * 30 = 27,840 distinct prefixes (each triple joins to a
        // unique string), thousands+, and every member complies with the
        // `[A-Za-z0-9_-]{1,64}` validation shape the widget driver and
        // the stored-record validator accept (the longest prefix is 30
        // bytes; the armed name adds 17 more).
        let space = decoy_grammar_space_size();
        assert_eq!(space, 27_840);
        assert!(
            space > 1_000,
            "the grammar prefix space must be thousands+ (got {space})"
        );
        let mut all: Vec<String> = Vec::with_capacity(space);
        for s1 in DECOY_GRAMMAR_SLOT1_QUALIFIER {
            for s2 in DECOY_GRAMMAR_SLOT2_CATEGORY {
                for s3 in DECOY_GRAMMAR_SLOT3_FORM {
                    let name = format!("{s1}_{s2}_{s3}");
                    assert!(
                        valid_decoy_field_name(&name),
                        "{name} must comply with the validation alphabet"
                    );
                    assert!(
                        name.len() <= 64,
                        "{name} must be at most 64 bytes (got {})",
                        name.len()
                    );
                    assert!(is_grammar_decoy_prefix(&name));
                    all.push(name);
                }
            }
        }
        all.sort();
        all.dedup();
        assert_eq!(
            all.len(),
            space,
            "every triple must compose a unique prefix"
        );

        // A 20,000-draw sample (seeded, deterministic) must not collapse
        // into a small distinct set — the effective prefix space is the
        // grammar space, not an accidentally tiny subset.
        let mut rng = StdRng::seed_from_u64(42);
        let mut drawn = std::collections::HashSet::new();
        for _ in 0..20_000 {
            let idx = rng.gen_range(0..space);
            drawn.insert(compose_decoy_prefix(
                idx / (29 * 30),
                (idx % (29 * 30)) / 30,
                idx % 30,
            ));
        }
        assert!(
            drawn.len() > 1_000,
            "20,000 draws must hit more than 1,000 distinct prefixes (got {})",
            drawn.len()
        );
    }

    #[test]
    fn decoy_grammar_consecutive_draw_collisions_are_bounded() {
        // Fixed-seed statistical test: 10,000 consecutive pairs drawn
        // uniformly from the 27,840-prefix space. The expected number of
        // equal consecutive pairs is ~10,000 / 27,840 ~ 0.36. The bound
        // is set at < 2 collisions, i.e. a deterministic pass at the
        // ~1/N collision probability per pair. The full armed-name
        // collision probability is 2^-64 per pair (the suffix), so the
        // prefix-space statistic pins the grammar half only.
        let space = decoy_grammar_space_size();
        let mut rng = StdRng::seed_from_u64(7);
        let mut collisions = 0u32;
        let mut previous: Option<String> = None;
        for _ in 0..10_000 {
            let idx = rng.gen_range(0..space);
            let current = compose_decoy_prefix(idx / (29 * 30), (idx % (29 * 30)) / 30, idx % 30);
            if previous.as_deref() == Some(current.as_str()) {
                collisions += 1;
            }
            previous = Some(current);
        }
        assert!(
            collisions < 2,
            "10,000 consecutive pairs must collide < 2 times (got {collisions})"
        );
    }

    #[test]
    fn decoy_name_suffix_is_16_lowercase_hex_from_8_random_bytes() {
        // The suffix generator: exactly 16 lowercase hex characters, the
        // hex of 8 `CSPRNG` bytes — the 64 random bits that make an
        // armed name unguessable and accidental collision impossible.
        let suffix = decoy_name_suffix().unwrap();
        assert_eq!(suffix.len(), 16, "the suffix must be 16 hex chars");
        assert!(
            suffix
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
            "the suffix must be lowercase hex (got {suffix})"
        );

        // Two consecutive draws must differ: a fresh draw per call, so
        // identical suffixes across a handful of draws would indicate a
        // broken RNG, not a collision.
        let mut seen = std::collections::HashSet::new();
        for _ in 0..20 {
            seen.insert(decoy_name_suffix().unwrap());
            if seen.len() >= 2 {
                break;
            }
        }
        assert!(seen.len() >= 2, "consecutive suffixes must vary");
    }

    #[test]
    fn two_consecutive_armed_names_differ_in_the_suffix() {
        // The statistical core of the collision guarantee: 40 consecutive
        // armed compositions carry 40 distinct 64-bit suffixes (2^-64 per
        // pair), every composed name complies with the full validation
        // shape, and the armed name stays under the 64-byte bound (at
        // most 47 bytes).
        let mut seen_suffixes = std::collections::HashSet::new();
        for _ in 0..40 {
            let name = compose_decoy_prefix(0, 0, 0) + "_" + &decoy_name_suffix().unwrap();
            assert!(
                is_grammar_decoy_name(&name),
                "{name} must be an armed grammar name"
            );
            assert!(
                valid_decoy_field_name(&name),
                "{name} must comply with the [A-Za-z0-9_-]{{1,64}} validation shape"
            );
            assert!(
                name.len() <= 47,
                "{name} must be at most 47 bytes (the 64-byte validation bound)"
            );
            seen_suffixes.insert(name[name.len() - 16..].to_string());
        }
        assert_eq!(
            seen_suffixes.len(),
            40,
            "40 consecutive armed compositions must carry 40 distinct 64-bit suffixes"
        );
    }

    #[test]
    fn decoy_grammar_vocabularies_are_pinned_and_bounded() {
        // The vocabularies are position-specific, lowercase-only words of
        // 2..=10 bytes, and the longest composed name stays well under
        // the 64-byte validation bound.
        for (vocab, lo, hi) in [
            (DECOY_GRAMMAR_SLOT1_QUALIFIER, 25, 35),
            (DECOY_GRAMMAR_SLOT2_CATEGORY, 25, 35),
            (DECOY_GRAMMAR_SLOT3_FORM, 25, 35),
        ] {
            assert!(
                vocab.len() >= lo && vocab.len() <= hi,
                "each vocabulary must hold 25-35 words (got {})",
                vocab.len()
            );
            for w in vocab {
                assert!(
                    (2..=10).contains(&w.len()) && w.bytes().all(|b| b.is_ascii_lowercase()),
                    "vocabulary words must be lowercase [a-z]{{2,10}} (got {w})"
                );
            }
        }
        // The legacy 10-name pool words all remain generatable vocabulary
        // entries (the words stay; only the enumerable `SELECTION` is gone).
        for legacy in [
            "company",
            "fax",
            "number",
            "secondary",
            "phone",
            "office",
            "extension",
            "alternate",
            "email",
            "home",
            "address",
            "line",
            "middle",
            "name",
            "assistant",
            "department",
            "code",
            "backup",
            "website",
        ] {
            assert!(
                DECOY_GRAMMAR_SLOT1_QUALIFIER.contains(&legacy)
                    || DECOY_GRAMMAR_SLOT2_CATEGORY.contains(&legacy)
                    || DECOY_GRAMMAR_SLOT3_FORM.contains(&legacy),
                "the legacy pool word {legacy} must remain a vocabulary entry"
            );
        }
        assert!(is_grammar_decoy_prefix("secondary_contact_phone"));
        assert!(is_grammar_decoy_prefix("billing_company_url"));
        assert!(!is_grammar_decoy_prefix("secondary_contact"));
        assert!(!is_grammar_decoy_prefix("secondary_contact_phone_extra"));
        assert!(!is_grammar_decoy_prefix("Secondary_Contact_Phone"));
        assert!(!is_grammar_decoy_prefix("company|website"));
        // The full armed shape: a prefix plus the 16-hex suffix. A bare
        // prefix is a plausible real field name, so only the suffix makes
        // an armed name; a prefix without it is not an armed name.
        assert!(is_grammar_decoy_name(
            "secondary_contact_phone_a3f9c21d8e5b7401"
        ));
        assert!(is_grammar_decoy_name(
            "billing_address_line_0000000000000000"
        ));
        assert!(!is_grammar_decoy_name("secondary_contact_phone"));
        assert!(!is_grammar_decoy_name(
            "secondary_contact_phone_000000000000000"
        ));
        assert!(!is_grammar_decoy_name(
            "secondary_contact_phone_00000000000000000"
        ));
        assert!(!is_grammar_decoy_name(
            "secondary_contact_phone_ABCDEF0123456789"
        ));
        assert!(!is_grammar_decoy_name(
            "secondary_contact_phone_000000000000000g"
        ));
        assert!(!is_grammar_decoy_name(
            "secondary_contact_phone_extra_0000000000000000"
        ));
    }

    #[test]
    fn decoy_field_disabled_keeps_the_old_wire_and_canonical_format() {
        // The plain path (and the explicit false arm) issues NO decoy and
        // stays protocol v2: the canonical string keeps the exact
        // pre-extension shape (18 fields, kid last — byte-identical), and
        // neither JSON surface carries the key.
        for issued in [
            issue_challenge(
                &profile_base_config(),
                "login",
                "1.2.3.4",
                1_000_000,
                1_700_000_000_000_000,
                0,
                None,
            )
            .unwrap(),
            issue_challenge_with_decoy(
                &profile_base_config(),
                "login",
                "1.2.3.4",
                1_000_000,
                1_700_000_000_000_000,
                0,
                None,
                false,
            )
            .unwrap(),
        ] {
            assert!(issued.challenge.decoy_field.is_none());
            assert!(issued.record.decoy_field.is_none());
            assert_eq!(
                issued.record.protocol_version, 2,
                "an unarmed issuance stays protocol v2, byte-identical to the pre-decoy format"
            );
            let canonical = canonical_signing_input_v2(&issued.record);
            assert_eq!(
                canonical.split('|').count(),
                18,
                "the base v2 canonical input stays 18 fields (no decoy segment)"
            );
            assert!(
                canonical.ends_with(&issued.record.kid.to_string()),
                "kid stays the final field when no decoy is armed"
            );
            let record_json = serde_json::to_value(&issued.record).unwrap();
            assert!(
                record_json.get("decoy_field").is_none(),
                "the record key is absent when no decoy is armed (old byte format)"
            );
            let challenge_json = serde_json::to_value(&issued.challenge).unwrap();
            assert!(challenge_json.get("decoy_field").is_none());
        }
    }

    #[test]
    fn decoy_field_serde_round_trips_both_ways() {
        // Record: absent key → None (old payload), present key → Some, and
        // None never serializes the key.
        let armed = issue_challenge_with_decoy(
            &profile_base_config(),
            "login",
            "1.2.3.4",
            1_000_000,
            1_700_000_000_000_000,
            0,
            None,
            true,
        )
        .unwrap();
        let json = serde_json::to_string(&armed.record).unwrap();
        assert!(json.contains("\"decoy_field\""));
        let back: ChallengeRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(back.decoy_field, armed.record.decoy_field);

        let mut plain = armed.record.clone();
        plain.decoy_field = None;
        let plain_json = serde_json::to_string(&plain).unwrap();
        assert!(!plain_json.contains("decoy_field"));
        let plain_back: ChallengeRecord = serde_json::from_str(&plain_json).unwrap();
        assert!(plain_back.decoy_field.is_none());

        // IssuedChallenge: same two-way wire compatibility.
        let cj = serde_json::to_string(&armed.challenge).unwrap();
        assert!(cj.contains("\"decoy_field\""));
        let cback: crate::token::IssuedChallenge = serde_json::from_str(&cj).unwrap();
        assert_eq!(cback.decoy_field, armed.challenge.decoy_field);
        let mut cplain = armed.challenge.clone();
        cplain.decoy_field = None;
        let cplain_json = serde_json::to_string(&cplain).unwrap();
        assert!(!cplain_json.contains("decoy_field"));
        let cplain_back: crate::token::IssuedChallenge =
            serde_json::from_str(&cplain_json).unwrap();
        assert!(cplain_back.decoy_field.is_none());
    }

    #[test]
    fn decoy_field_is_covered_by_the_signature() {
        // Any change to the authenticated decoy name breaks the signature:
        // renaming it, stripping it from an armed record, or splicing one
        // onto an unarmed record all fail the v2 verification.
        let armed = issue_challenge_with_decoy(
            &profile_base_config(),
            "login",
            "1.2.3.4",
            1_000_000,
            1_700_000_000_000_000,
            0,
            None,
            true,
        )
        .unwrap();
        let sig = crate::verify::signature_from_challenge(&armed.record);
        let secret = "test-key-16-bytes!";
        assert!(verify_signature_v2(&armed.record, sig, secret).unwrap());

        // Renamed to a different grammar name (same shape, different pick).
        let mut renamed = armed.record.clone();
        let renamed_name = if renamed.decoy_field.as_deref() == Some("secondary_contact_phone") {
            "billing_company_url"
        } else {
            "secondary_contact_phone"
        };
        renamed.decoy_field = Some(renamed_name.to_string());
        assert!(!verify_signature_v2(&renamed, sig, secret).unwrap());

        // Stripped (the client-cannot-remove-it property).
        let mut stripped = armed.record.clone();
        stripped.decoy_field = None;
        assert!(!verify_signature_v2(&stripped, sig, secret).unwrap());

        // Spliced onto an unarmed, unsigned-for-decoy record.
        let plain = issue_challenge(
            &profile_base_config(),
            "login",
            "1.2.3.4",
            1_000_000,
            1_700_000_000_000_000,
            0,
            None,
        )
        .unwrap();
        let plain_sig = crate::verify::signature_from_challenge(&plain.record);
        let mut spliced = plain.record.clone();
        spliced.decoy_field = Some("secondary_contact_phone".to_string());
        assert!(!verify_signature_v2(&spliced, plain_sig, secret).unwrap());
    }

    #[test]
    fn validate_record_rejects_a_non_conforming_decoy_name() {
        // The stored-record validator enforces the issuer's decoy alphabet
        // ([A-Za-z0-9_-], 1..=64): the separator `|`, an identifier-shaped
        // `.` and an over-long name are all malformed — none can alter the
        // canonical segment structure.
        let armed = issue_challenge_with_decoy(
            &profile_base_config(),
            "login",
            "1.2.3.4",
            1_000_000,
            1_700_000_000_000_000,
            0,
            None,
            true,
        )
        .unwrap();
        for bad in ["company|website", "company.website", &"x".repeat(65), ""] {
            let mut record = armed.record.clone();
            record.decoy_field = Some(bad.to_string());
            assert_eq!(
                crate::verify::validate_record(&record).unwrap_err(),
                crate::verify::VerifyError::MalformedRecord,
                "decoy name {bad:?} must be malformed"
            );
        }
        // The armed record itself stays valid.
        assert!(crate::verify::validate_record(&armed.record).is_ok());
    }

    #[test]
    fn decoy_armed_challenge_verifies_end_to_end() {
        // A full verify_solution pass on a decoy-armed record: the decoy
        // is transparent to the solver/verifier (it only widens the signed
        // input).
        let issued = issue_challenge_with_decoy(
            &profile_base_config(),
            "login",
            "1.2.3.4",
            1_000_000,
            1_700_000_000_000_000,
            0,
            None,
            true,
        )
        .unwrap();
        let mut record = issued.record;
        let counter = crate::verify::solve_for_test(&record).unwrap();
        let mut ctx = crate::verify::VerifyContext {
            record: &mut record,
            secret_key: "test-key-16-bytes!",
            secrets_by_kid: None,
            revoked_kids: None,
            counter,
            duration_ms: 5000,
            now_unix: Some(&mut || 1_000_001),
            now_ns: 1_700_000_005_000_000,
            min_duration_ms: 0,
            expected_scope: None,
            expected_request_binding: RequestBindingExpectation::Unenforced,
            client_ip: Some("1.2.3.4"),
            execution_digest: None,
            execution_trace: None,
            expected_region: None,
            expected_issuer: None,
            expected_policy_version: None,
            telemetry: None,
            enforce_telemetry: false,
            max_attempts: 0,
            accept_legacy_v1: false,
            rsw_proof: None,
            rsw_modulus_n: None,
            rsw_lambda: None,
        };
        assert!(
            matches!(
                crate::verify::verify_solution(&mut ctx),
                crate::verify::VerifyOutcome::Valid { .. }
            ),
            "a decoy-armed challenge must verify normally"
        );
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
                now_unix: Some(&mut || 1_000_001),
                now_ns: 1_700_000_005_000_000,
                min_duration_ms: 0,
                expected_scope: None,
                expected_request_binding: RequestBindingExpectation::Unenforced,
                client_ip: Some("1.2.3.4"),
                execution_digest: None,
                execution_trace: None,
                expected_region: None,
                expected_issuer: None,
                expected_policy_version: None,
                telemetry: None,
                enforce_telemetry: false,
                max_attempts: 0,
                accept_legacy_v1: false,
                rsw_proof: None,
                rsw_modulus_n: None,
                rsw_lambda: None,
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
            now_unix: Some(&mut || 1_000_001),
            now_ns: 1_700_000_005_000_000,
            min_duration_ms: 0,
            expected_scope: None,
            expected_request_binding: RequestBindingExpectation::Unenforced,
            client_ip: Some("1.2.3.4"),
            execution_digest: None,
            execution_trace: None,
            expected_region: None,
            expected_issuer: None,
            expected_policy_version: None,
            telemetry: None,
            enforce_telemetry: false,
            max_attempts: 0,
            accept_legacy_v1: false,
            rsw_proof: None,
            rsw_modulus_n: None,
            rsw_lambda: None,
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
            execution_key: None,
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

    // ── secret redaction in the Debug shape ─────────────────────────

    #[test]
    fn config_debug_redacts_secrets_but_keeps_the_public_shape() {
        let secret = "debug-master-secret-0123456789abcdef";
        let execution = "debug-execution-key-0123456789abcdef";
        let mut config = rsw_config(MIN_RSW_T);
        config.secret_key = secret.into();
        config.execution_key = Some(execution.into());
        let debug = format!("{config:?}");

        // None of the live secret byte strings may print.
        assert!(!debug.contains(secret));
        assert!(!debug.contains(execution));
        assert!(!debug.contains(crate::rsw::fixtures::LAMBDA_B64));
        // The rsw modulus is public material and prints as itself.
        assert!(debug.contains(crate::rsw::fixtures::MODULUS_N_B64));
        // Every secret slot prints the redaction marker, and the
        // non-secret fields keep their exact values.
        assert_eq!(debug.matches("<redacted>").count(), 3);
        assert!(debug.contains("ChallengeConfig { secret_key: \"<redacted>\""));
        assert!(debug.contains("execution_key: Some(\"<redacted>\")"));
        assert!(debug.contains("rsw_lambda: Some(\"<redacted>\")"));
        assert!(debug.contains("algorithm: Rsw"));
        assert!(debug.contains("rsw_t: "));
        assert!(debug.contains("kid: 1"));
    }

    #[test]
    fn config_debug_none_variants_print_none_not_redacted() {
        let secret = "debug-master-secret-0123456789abcdef";
        let mut config = profile_base_config();
        config.secret_key = secret.into();
        let debug = format!("{config:?}");

        assert!(!debug.contains(secret));
        assert_eq!(debug.matches("<redacted>").count(), 1);
        assert!(debug.contains("execution_key: None"));
        assert!(debug.contains("rsw_lambda: None"));
        assert!(debug.contains("rsw_modulus_n: None"));
    }
}
