//! Shared helpers for the kiwicaptcha-risk integration tests.
//!
//! Every Redis-backed test here is hermetic: it skips (prints a notice and
//! returns) unless `RISK_REDIS_URL` is set, so the suite is green without
//! any infrastructure.
#![allow(dead_code)]

use kiwicaptcha_risk::event::{RiskEventKind, RiskObservation};
use kiwicaptcha_risk::signals::SignalVector;
use rand::RngCore;

/// Fixed clock (epoch ms): no decay between same-ts events.
pub const T0: u64 = 1_700_000_000_000;

/// Deterministic LCG matching the 10k parity stream (verified first value
/// 291): `x_{n+1} = (x_n * 6364136223846793005 + 1442695040888963407)
/// mod 2^64`, `value = (x >> 11) % 1001`.
pub fn lcg_next(state: &mut u64) -> u16 {
    *state = state
        .wrapping_mul(6364136223846793005u64)
        .wrapping_add(1442695040888963407u64);
    ((*state >> 11) % 1001) as u16
}

/// A full 13-field `SignalVector` from the LCG stream (contract order).
pub fn vector(state: &mut u64) -> SignalVector {
    SignalVector {
        source_fast: lcg_next(state),
        source_slow: lcg_next(state),
        subnet_fast: lcg_next(state),
        issue_debt: lcg_next(state),
        bad_proof: lcg_next(state),
        malformed: lcg_next(state),
        replay: lcg_next(state),
        action_failure: lcg_next(state),
        scope_switch: lcg_next(state),
        global_pressure: lcg_next(state),
        network_risk: lcg_next(state),
        trust_credit: lcg_next(state),
        principal_credit: lcg_next(state),
    }
}

/// event_id from a u64 (bytes 0..8 = big-endian n, rest zeroed).
pub fn event_id(n: u64) -> [u8; 16] {
    let mut out = [0u8; 16];
    out[..8].copy_from_slice(&n.to_be_bytes());
    out
}

/// `tcp://` predis-style URLs are normalized to `redis://`; `None` when
/// `RISK_REDIS_URL` is unset or empty (the caller skips).
pub fn redis_url() -> Option<String> {
    match std::env::var("RISK_REDIS_URL") {
        Ok(url) if !url.is_empty() => Some(if let Some(rest) = url.strip_prefix("tcp://") {
            format!("redis://{rest}")
        } else {
            url
        }),
        _ => None,
    }
}

/// Fresh per-test namespace (the store's hash tag is `{kiwi:<ns>}`).
pub fn unique_namespace(prefix: &str) -> String {
    let mut suffix = [0u8; 4];
    rand::thread_rng().fill_bytes(&mut suffix);
    format!("{prefix}{}", hex::encode(suffix))
}

/// A PreIssue observation with the given pseudonyms at the fixed clock.
#[allow(clippy::too_many_arguments)]
pub fn observation(
    event: RiskEventKind,
    scope: u16,
    source_id: [u8; 16],
    subnet_id: [u8; 16],
    session_id: Option<[u8; 16]>,
    principal_id: Option<[u8; 16]>,
    event_id: [u8; 16],
    now_ms: u64,
) -> RiskObservation {
    RiskObservation {
        event,
        scope,
        source_id,
        subnet_id,
        session_id,
        principal_id,
        event_id,
        network_risk: 0,
        now_ms,
    }
}
