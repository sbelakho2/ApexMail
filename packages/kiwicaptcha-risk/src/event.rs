//! Risk event kinds, fixed by the cross-language risk-v1 contract.
//!
//! Values 1..17 are authoritative and MUST NOT be renumbered: they are the
//! event identifiers passed into the canonical state script (`risk.lua`) and
//! must be byte-identical across the PHP and Rust implementations.
//!
//! Values 18..20 are the ADDITIVE risk-v2 surface: honeypot/decoy evidence
//! kinds. They ride the same observation path (idempotency domain separation,
//! dedupe receipt) but the state script treats them as no-ops (like
//! `RiskDenied`) — the honeypot signal itself is scored from the risk-v2
//! context, never from accumulated state.

use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

use crate::RiskError;

type HmacSha256 = Hmac<Sha256>;

/// The fixed risk event kinds of the risk-v1 contract (1..17) plus the
/// additive risk-v2 honeypot/decoy kinds (18..20).
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
    SourceRateLimitHit = 15,
    GlobalCapacityHit = 16,
    RiskDenied = 17,
    /// Risk-v2: a server-issued honeypot trap was filled by the client.
    HoneypotTriggered = 18,
    /// Risk-v2: a decoy (honeypot) endpoint was touched.
    DecoyEndpointTouched = 19,
    /// Risk-v2: a server-issued decoy form field was submitted.
    DecoyFieldSubmitted = 20,
}

impl RiskEventKind {
    /// All twenty kinds, in contract value order (17 risk-v1 + 3 risk-v2).
    pub const ALL: [RiskEventKind; 20] = [
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
        RiskEventKind::SourceRateLimitHit,
        RiskEventKind::GlobalCapacityHit,
        RiskEventKind::RiskDenied,
        RiskEventKind::HoneypotTriggered,
        RiskEventKind::DecoyEndpointTouched,
        RiskEventKind::DecoyFieldSubmitted,
    ];

    /// The contract integer value (1..20), as passed to the Lua script.
    pub fn as_u8(self) -> u8 {
        self as u8
    }

    /// Inverse of [`RiskEventKind::as_u8`]; `None` for values outside 1..20.
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
            15 => Some(RiskEventKind::SourceRateLimitHit),
            16 => Some(RiskEventKind::GlobalCapacityHit),
            17 => Some(RiskEventKind::RiskDenied),
            18 => Some(RiskEventKind::HoneypotTriggered),
            19 => Some(RiskEventKind::DecoyEndpointTouched),
            20 => Some(RiskEventKind::DecoyFieldSubmitted),
            _ => None,
        }
    }

    /// True for the three risk-v2 honeypot/decoy evidence kinds.
    ///
    /// The honeypot signal in the risk-v2 context is derived from ANY of
    /// these kinds (probabilistic evidence — never a security gate).
    pub fn is_honeypot(self) -> bool {
        matches!(
            self,
            RiskEventKind::HoneypotTriggered
                | RiskEventKind::DecoyEndpointTouched
                | RiskEventKind::DecoyFieldSubmitted
        )
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

/// Normalizes a caller idempotency key into the canonical `event_id`
/// representation BEFORE it becomes a Redis key suffix (byte-identical with
/// PHP):
///
/// - `None` or empty → a fresh random 16-byte hex id
///   ([`RiskObservation::new_event_id`]);
/// - more than [`MAX_IDEMPOTENCY_KEY_BYTES`] bytes →
///   [`RiskError::InvalidIdempotencyKey`];
/// - otherwise → lowercase hex of
///   `HMAC-SHA256(event_key, pack('N', scope) . chr(event) . key)` (64 hex
///   chars; `pack('N', scope)` is the scope as a big-endian u32, `chr(event)`
///   is the event value as ONE byte).
///
/// The scope + event domain separation means the same caller key produces a
/// different `event_id` per scope AND per event kind, so a retry of one
/// event can never collide with a different event reusing the same key.
pub fn normalize_idempotency_key(
    key: Option<&str>,
    scope: u32,
    event: RiskEventKind,
    event_key: &[u8; 32],
) -> Result<String, RiskError> {
    let Some(key) = key.filter(|k| !k.is_empty()) else {
        return Ok(RiskObservation::new_event_id());
    };
    if key.len() > MAX_IDEMPOTENCY_KEY_BYTES {
        return Err(RiskError::InvalidIdempotencyKey(key.len()));
    }
    let mut mac = HmacSha256::new_from_slice(event_key).expect("HMAC accepts any key length");
    mac.update(&scope.to_be_bytes());
    mac.update(&[event.as_u8()]);
    mac.update(key.as_bytes());
    Ok(hex::encode(mac.finalize().into_bytes()))
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
    use crate::keys::RiskKeys;

    /// The event key for the parity master (0x42 * 32), derived exactly like
    /// PHP's `hash_hkdf('sha256', master, 32, 'event', 'kiwicaptcha-risk-v1')`
    /// (see the parity anchors in `keys.rs`).
    fn event_key() -> [u8; 32] {
        RiskKeys::from_master(&[0x42; 32]).event
    }

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
            (15, "source_rate_limit_hit"),
            (16, "global_capacity_hit"),
            (17, "risk_denied"),
            // Risk-v2 honeypot/decoy kinds (additive surface).
            (18, "honeypot_triggered"),
            (19, "decoy_endpoint_touched"),
            (20, "decoy_field_submitted"),
        ];
        for (i, (value, name)) in expected.iter().enumerate() {
            let kind = RiskEventKind::ALL[i];
            assert_eq!(kind.as_u8(), *value);
            assert_eq!(RiskEventKind::from_u8(*value), Some(kind));
            assert_eq!(serde_json::to_value(kind).unwrap(), serde_json::json!(name));
        }
        assert_eq!(RiskEventKind::from_u8(0), None);
        assert_eq!(RiskEventKind::from_u8(21), None);
        assert_eq!(RiskEventKind::from_u8(255), None);
    }

    #[test]
    fn honeypot_kinds_are_detected() {
        for kind in [
            RiskEventKind::HoneypotTriggered,
            RiskEventKind::DecoyEndpointTouched,
            RiskEventKind::DecoyFieldSubmitted,
        ] {
            assert!(kind.is_honeypot(), "{kind:?} must be a honeypot kind");
        }
        for kind in [
            RiskEventKind::PreIssue,
            RiskEventKind::ReplayAttempt,
            RiskEventKind::RiskDenied,
        ] {
            assert!(!kind.is_honeypot(), "{kind:?} must not be a honeypot kind");
        }
        // The v1 contract values are untouched: 17 kinds keep their exact
        // values and the v2 kinds extend the range without renumbering.
        assert_eq!(RiskEventKind::RiskDenied.as_u8(), 17);
        assert_eq!(RiskEventKind::HoneypotTriggered.as_u8(), 18);
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
    fn idempotency_normalization_hmacs_scope_event_and_key() {
        let key = event_key();
        // Anchored vectors computed with the PHP mirror:
        //   hash_hmac('sha256', pack('N', scope) . chr(event) . $key, $eventKey)
        // in lowercase hex.
        assert_eq!(
            normalize_idempotency_key(Some("deadbeef"), 1, RiskEventKind::PreIssue, &key).unwrap(),
            "7008f1bb5b5c101905cf521c037660f105a85e759e67779eb4dcca211b70e0c8"
        );
        assert_eq!(
            normalize_idempotency_key(
                Some("verbatim-key"),
                0x1234_5678,
                RiskEventKind::RateLimitHit,
                &key
            )
            .unwrap(),
            "6430ec7bcc4289d3b8c5a3ead06056b191a647b6a30cd5f64d50aac7e54923b5"
        );

        // The byte shape is `pack('N', scope) . chr(event) . key` under the
        // event key: recompute the HMAC inline and compare.
        let mut mac = HmacSha256::new_from_slice(&key).unwrap();
        mac.update(&1u32.to_be_bytes());
        mac.update(&[RiskEventKind::PreIssue.as_u8()]);
        mac.update(b"deadbeef");
        assert_eq!(
            normalize_idempotency_key(Some("deadbeef"), 1, RiskEventKind::PreIssue, &key).unwrap(),
            hex::encode(mac.finalize().into_bytes())
        );

        // Deterministic: the same key/scope/event maps to the same id.
        let normalized =
            normalize_idempotency_key(Some("deadbeef"), 1, RiskEventKind::PreIssue, &key).unwrap();
        assert_eq!(
            normalize_idempotency_key(Some("deadbeef"), 1, RiskEventKind::PreIssue, &key).unwrap(),
            normalized
        );
        // Different keys map to different ids.
        assert_ne!(
            normalize_idempotency_key(Some("other-key"), 1, RiskEventKind::PreIssue, &key).unwrap(),
            normalized
        );
        // DOMAIN SEPARATION: the same caller key must never collide across
        // scopes or event kinds.
        assert_ne!(
            normalize_idempotency_key(Some("deadbeef"), 2, RiskEventKind::PreIssue, &key).unwrap(),
            normalized,
            "scope must separate the dedupe domain"
        );
        assert_ne!(
            normalize_idempotency_key(Some("deadbeef"), 1, RiskEventKind::ChallengeIssued, &key)
                .unwrap(),
            normalized,
            "event kind must separate the dedupe domain"
        );
        // The new events ride the same domain separation.
        assert_ne!(
            normalize_idempotency_key(Some("deadbeef"), 1, RiskEventKind::RiskDenied, &key)
                .unwrap(),
            normalized
        );
        assert_ne!(
            normalize_idempotency_key(Some("deadbeef"), 1, RiskEventKind::SourceRateLimitHit, &key)
                .unwrap(),
            normalized
        );
        // Keys with an embedded NUL still hash as-is.
        let mut with_nul = String::from("a");
        with_nul.push('\0');
        with_nul.push('b');
        assert_eq!(
            normalize_idempotency_key(Some(&with_nul), 1, RiskEventKind::PreIssue, &key)
                .unwrap()
                .len(),
            64
        );
    }

    #[test]
    fn idempotency_normalization_rejects_keys_over_4096_bytes() {
        let key = event_key();
        let long = "x".repeat(MAX_IDEMPOTENCY_KEY_BYTES + 1);
        assert_eq!(
            normalize_idempotency_key(Some(&long), 1, RiskEventKind::PreIssue, &key),
            Err(RiskError::InvalidIdempotencyKey(
                MAX_IDEMPOTENCY_KEY_BYTES + 1
            ))
        );
        // Exactly the limit is accepted.
        let ok = "x".repeat(MAX_IDEMPOTENCY_KEY_BYTES);
        assert_eq!(
            normalize_idempotency_key(Some(&ok), 1, RiskEventKind::PreIssue, &key)
                .unwrap()
                .len(),
            64
        );
    }

    #[test]
    fn idempotency_normalization_none_or_empty_draws_random_ids() {
        let key = event_key();
        for key_in in [None, Some("")] {
            let a = normalize_idempotency_key(key_in, 1, RiskEventKind::PreIssue, &key).unwrap();
            let b = normalize_idempotency_key(key_in, 1, RiskEventKind::PreIssue, &key).unwrap();
            assert_eq!(a.len(), 32, "null/empty keys draw a random 16-byte id");
            assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
            assert_ne!(a, b, "null/empty keys must never reuse an id");
        }
    }
}
