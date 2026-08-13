//! Risk event kinds, fixed by the cross-language risk-v1 contract.
//!
//! Values 1..14 are authoritative and MUST NOT be renumbered: they are the
//! event identifiers passed into the canonical state script (`risk.lua`) and
//! must be byte-identical across the PHP and Rust implementations.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::RiskError;

/// The fixed risk event kinds of the risk-v1 contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
#[serde(rename_all = "snake_case")]
pub enum RiskEventKind {
    PreIssue = 1,
    ChallengeIssued = 2,
    SolveSuccess = 3,
    InvalidProof = 4,
    MalformedToken = 5,
    ExpiredChallenge = 6,
    ReplayAttempt = 7,
    ProtectedActionSuccess = 8,
    ProtectedActionFailure = 9,
    AuthenticationSuccess = 10,
    AuthenticationFailure = 11,
    ConfirmedLegitimate = 12,
    ConfirmedAbuse = 13,
    RateLimitHit = 14,
}

impl RiskEventKind {
    /// All fourteen kinds, in contract value order.
    pub const ALL: [RiskEventKind; 14] = [
        RiskEventKind::PreIssue,
        RiskEventKind::ChallengeIssued,
        RiskEventKind::SolveSuccess,
        RiskEventKind::InvalidProof,
        RiskEventKind::MalformedToken,
        RiskEventKind::ExpiredChallenge,
        RiskEventKind::ReplayAttempt,
        RiskEventKind::ProtectedActionSuccess,
        RiskEventKind::ProtectedActionFailure,
        RiskEventKind::AuthenticationSuccess,
        RiskEventKind::AuthenticationFailure,
        RiskEventKind::ConfirmedLegitimate,
        RiskEventKind::ConfirmedAbuse,
        RiskEventKind::RateLimitHit,
    ];

    /// The contract integer value (1..14), as passed to the Lua script.
    pub fn as_u8(self) -> u8 {
        self as u8
    }

    /// Inverse of [`RiskEventKind::as_u8`]; `None` for values outside 1..14.
    pub fn from_u8(value: u8) -> Option<RiskEventKind> {
        match value {
            1 => Some(RiskEventKind::PreIssue),
            2 => Some(RiskEventKind::ChallengeIssued),
            3 => Some(RiskEventKind::SolveSuccess),
            4 => Some(RiskEventKind::InvalidProof),
            5 => Some(RiskEventKind::MalformedToken),
            6 => Some(RiskEventKind::ExpiredChallenge),
            7 => Some(RiskEventKind::ReplayAttempt),
            8 => Some(RiskEventKind::ProtectedActionSuccess),
            9 => Some(RiskEventKind::ProtectedActionFailure),
            10 => Some(RiskEventKind::AuthenticationSuccess),
            11 => Some(RiskEventKind::AuthenticationFailure),
            12 => Some(RiskEventKind::ConfirmedLegitimate),
            13 => Some(RiskEventKind::ConfirmedAbuse),
            14 => Some(RiskEventKind::RateLimitHit),
            _ => None,
        }
    }
}

/// One immutable observation applied atomically to the risk state.
///
/// Source/subnet identities are EPOCH-scoped hex pseudonyms (32 hex chars)
/// from the identity factory: `source_id` is the current-epoch id,
/// `source_id_prev`/`source_id_next` are the SAME source HMAC'd with the
/// epoch-1/epoch+1 windows (the store's ±1 keys must never reuse the
/// current-epoch pseudonym). `session_id`/`principal_id` are 128-bit
/// pseudonyms, or `None` when the request carries no session/principal.
/// `event_id` is the dedupe key (16 random bytes in hex; `''` disables
/// dedupe) — an identical event_id never double-increments the state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RiskObservation {
    pub event: RiskEventKind,
    pub scope: u32,
    /// Source epoch window (seconds / source epoch secs).
    pub source_epoch: i64,
    /// Source pseudonym hex for epoch-1, current, epoch+1.
    pub source_id_prev: String,
    pub source_id: String,
    pub source_id_next: String,
    /// Subnet epoch window (seconds / subnet epoch secs).
    pub subnet_epoch: i64,
    /// Subnet pseudonym hex for epoch-1, current, epoch+1.
    pub subnet_id_prev: String,
    pub subnet_id: String,
    pub subnet_id_next: String,
    pub session_id: Option<[u8; 16]>,
    pub principal_id: Option<[u8; 16]>,
    /// Dedupe key: 16 random bytes in hex (32 chars); `''` = dedupe
    /// disabled.
    pub event_id: String,
    /// Classifier-derived network risk (0..1000), side-channel into the
    /// Lua's reserved `network_risk` slot.
    pub network_risk: u16,
    /// Server clock, epoch milliseconds.
    pub now_ms: u64,
}

impl RiskObservation {
    /// Generates a fresh 16-byte dedupe id in hex.
    pub fn new_event_id() -> String {
        let mut bytes = [0u8; 16];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut bytes);
        hex::encode(bytes)
    }
}

/// Hard limit on caller-supplied idempotency keys (bytes), shared with PHP.
pub const MAX_IDEMPOTENCY_KEY_BYTES: usize = 4096;

/// Canonical idempotency-key prefix, shared with PHP. Every caller key is
/// hashed with this prefix so a caller-controlled suffix can never collide
/// with the engine's own random 32-hex event ids.
const IDEMPOTENCY_PREFIX: &[u8] = b"kiwi-risk-event-v1\0";

/// Normalizes a caller idempotency key into the canonical `event_id`
/// representation BEFORE it becomes a Redis key suffix (byte-identical with
/// PHP):
///
/// - `None` or empty → a fresh random 16-byte hex id
///   ([`RiskObservation::new_event_id`]);
/// - more than [`MAX_IDEMPOTENCY_KEY_BYTES`] bytes →
///   [`RiskError::InvalidIdempotencyKey`];
/// - otherwise → lowercase hex of
///   `sha256("kiwi-risk-event-v1\0" + key)` (64 hex chars).
pub fn normalize_idempotency_key(key: Option<&str>) -> Result<String, RiskError> {
    let Some(key) = key.filter(|k| !k.is_empty()) else {
        return Ok(RiskObservation::new_event_id());
    };
    if key.len() > MAX_IDEMPOTENCY_KEY_BYTES {
        return Err(RiskError::InvalidIdempotencyKey(key.len()));
    }
    let mut hasher = Sha256::new();
    hasher.update(IDEMPOTENCY_PREFIX);
    hasher.update(key.as_bytes());
    Ok(hex::encode(hasher.finalize()))
}

impl Default for RiskObservation {
    fn default() -> Self {
        RiskObservation {
            event: RiskEventKind::PreIssue,
            scope: 0,
            source_epoch: 0,
            source_id_prev: "0".repeat(32),
            source_id: "0".repeat(32),
            source_id_next: "0".repeat(32),
            subnet_epoch: 0,
            subnet_id_prev: "0".repeat(32),
            subnet_id: "0".repeat(32),
            subnet_id_next: "0".repeat(32),
            session_id: None,
            principal_id: None,
            event_id: String::new(),
            network_risk: 0,
            now_ms: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn contract_values_are_stable() {
        let expected = [
            (1, "pre_issue"),
            (2, "challenge_issued"),
            (3, "solve_success"),
            (4, "invalid_proof"),
            (5, "malformed_token"),
            (6, "expired_challenge"),
            (7, "replay_attempt"),
            (8, "protected_action_success"),
            (9, "protected_action_failure"),
            (10, "authentication_success"),
            (11, "authentication_failure"),
            (12, "confirmed_legitimate"),
            (13, "confirmed_abuse"),
            (14, "rate_limit_hit"),
        ];
        for (i, (value, name)) in expected.iter().enumerate() {
            let kind = RiskEventKind::ALL[i];
            assert_eq!(kind.as_u8(), *value);
            assert_eq!(RiskEventKind::from_u8(*value), Some(kind));
            assert_eq!(serde_json::to_value(kind).unwrap(), serde_json::json!(name));
        }
        assert_eq!(RiskEventKind::from_u8(0), None);
        assert_eq!(RiskEventKind::from_u8(15), None);
    }

    #[test]
    fn observation_defaults_to_pre_issue() {
        let o = RiskObservation::default();
        assert_eq!(o.event, RiskEventKind::PreIssue);
        assert_eq!(o.scope, 0);
        assert_eq!(o.source_epoch, 0);
        assert_eq!(o.source_id.len(), 32);
        assert_eq!(o.session_id, None);
        assert_eq!(o.network_risk, 0);
        assert_eq!(o.event_id, "");
    }

    #[test]
    fn new_event_id_is_32_hex_chars() {
        let a = RiskObservation::new_event_id();
        let b = RiskObservation::new_event_id();
        assert_eq!(a.len(), 32);
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(a, b);
    }

    #[test]
    fn idempotency_normalization_hashes_verbatim_keys() {
        let normalized = normalize_idempotency_key(Some("verbatim-key")).unwrap();
        assert_eq!(normalized.len(), 64, "sha256 hex of a verbatim key");
        assert!(normalized.chars().all(|c| c.is_ascii_hexdigit()));
        assert!(
            normalized.chars().all(|c| !c.is_ascii_uppercase()),
            "the hash is lowercase hex"
        );

        let mut hasher = Sha256::new();
        hasher.update(b"kiwi-risk-event-v1\0");
        hasher.update(b"verbatim-key");
        assert_eq!(normalized, hex::encode(hasher.finalize()));

        // Deterministic: the same key maps to the same id (dedupe works).
        assert_eq!(
            normalize_idempotency_key(Some("verbatim-key")).unwrap(),
            normalized
        );
        // Different keys map to different ids.
        assert_ne!(
            normalize_idempotency_key(Some("other-key")).unwrap(),
            normalized
        );
        // Keys with an embedded NUL still hash as-is.
        let mut with_nul = String::from("a");
        with_nul.push('\0');
        with_nul.push('b');
        assert_eq!(
            normalize_idempotency_key(Some(&with_nul)).unwrap().len(),
            64
        );
    }

    #[test]
    fn idempotency_normalization_rejects_keys_over_4096_bytes() {
        let long = "x".repeat(MAX_IDEMPOTENCY_KEY_BYTES + 1);
        assert_eq!(
            normalize_idempotency_key(Some(&long)),
            Err(RiskError::InvalidIdempotencyKey(
                MAX_IDEMPOTENCY_KEY_BYTES + 1
            ))
        );
        // Exactly the limit is accepted.
        let ok = "x".repeat(MAX_IDEMPOTENCY_KEY_BYTES);
        assert_eq!(normalize_idempotency_key(Some(&ok)).unwrap().len(), 64);
    }

    #[test]
    fn idempotency_normalization_none_or_empty_draws_random_ids() {
        for key in [None, Some("")] {
            let a = normalize_idempotency_key(key).unwrap();
            let b = normalize_idempotency_key(key).unwrap();
            assert_eq!(a.len(), 32, "null/empty keys draw a random 16-byte id");
            assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
            assert_ne!(a, b, "null/empty keys must never reuse an id");
        }
    }
}
