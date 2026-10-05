//! Canonical audit hash-chain primitives — the ONE shared implementation of
//! the `audit_logs` row-hash payload, row hash and chain signature.
//!
//! Platform byte contract (DF-5 finding C): an `audit_logs` row's `hash` is
//! SHA-256 over the 7-segment pipe payload
//!
//! ```text
//! tenant|user|action|resource|resource_id|details|timestamp
//! ```
//!
//! where a NULL `tenant_id`/`user_id`/`resource_id` contributes the EMPTY
//! string (the segment itself is never dropped), `details` is the compact
//! serde_json serialization, and `timestamp` is `to_rfc3339()` of the
//! microsecond-truncated instant (Postgres TIMESTAMPTZ stores exactly
//! microseconds, so hashing more precision than the row stores would make
//! every hash unre-derivable). The `previous_hash` chain link is NOT part of
//! the row hash; it is covered by the HMAC-SHA256 signature over
//! `previous_hash|hash`, keyed with `AUDIT_SIGNING_KEY`.
//!
//! Every writer (api-server `audit_log`, billing-service, compliance
//! `audit_logger`) and every verifier MUST hash through this module so any
//! stored row re-derives byte-exactly. Writers that previously folded
//! non-canonical fields (id, session, ip, outcome, …) or the chain link into
//! the row hash forked re-derivation: live dogfood DF-5c measured 0/40
//! compliance-written rows matching this formula.

use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;

/// Build the canonical 7-segment audit row-hash payload. `None` segments
/// contribute the EMPTY string — the segment separator stays, so the payload
/// always splits into exactly 7 fields.
pub fn audit_hash_payload(
    tenant_id: Option<&str>,
    user_id: Option<&str>,
    action: &str,
    resource: &str,
    resource_id: Option<&str>,
    details: &serde_json::Value,
    timestamp: DateTime<Utc>,
) -> String {
    format!(
        "{}|{}|{}|{}|{}|{}|{}",
        tenant_id.unwrap_or_default(),
        user_id.unwrap_or_default(),
        action,
        resource,
        resource_id.unwrap_or_default(),
        details,
        timestamp.to_rfc3339(),
    )
}

/// SHA-256 hex digest of one canonical audit row-hash payload.
pub fn audit_row_hash(payload: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(payload.as_bytes());
    hex::encode(hasher.finalize())
}

/// Convenience: hash one row's canonical columns in a single call.
pub fn audit_hash(
    tenant_id: Option<&str>,
    user_id: Option<&str>,
    action: &str,
    resource: &str,
    resource_id: Option<&str>,
    details: &serde_json::Value,
    timestamp: DateTime<Utc>,
) -> String {
    audit_row_hash(&audit_hash_payload(
        tenant_id,
        user_id,
        action,
        resource,
        resource_id,
        details,
        timestamp,
    ))
}

/// HMAC-SHA256 signature over the chain LINK (`previous_hash|hash`), keyed
/// with the deployment's `AUDIT_SIGNING_KEY`. The chain's first entry signs
/// the empty `previous_hash`. An unusable key is an `Err` — callers decide
/// their own fail-closed policy (production must refuse to sign with a
/// publicly-known fallback key).
pub fn audit_log_signature(
    previous_hash: Option<&str>,
    hash: &str,
    signing_key: &str,
) -> Result<String, String> {
    let mut mac = HmacSha256::new_from_slice(signing_key.as_bytes())
        .map_err(|e| format!("audit HMAC init failed: {e}"))?;
    mac.update(previous_hash.unwrap_or_default().as_bytes());
    mac.update(b"|");
    mac.update(hash.as_bytes());
    Ok(hex::encode(mac.finalize().into_bytes()))
}

/// Postgres `timestamptz` stores microseconds; `Utc::now()` carries
/// nanoseconds. Hash and store the SAME microsecond-truncated instant so the
/// stored row's hash stays re-derivable from its own columns.
pub fn truncate_timestamp_to_micros(ts: DateTime<Utc>) -> DateTime<Utc> {
    let nanos = ts.timestamp_subsec_nanos();
    if nanos.is_multiple_of(1_000) {
        return ts;
    }
    let micros = ts.timestamp_micros();
    match DateTime::from_timestamp_micros(micros) {
        Some(truncated) => truncated,
        // Out-of-range instants cannot occur for `Utc::now()`; fall back to
        // the original value rather than inventing a different timestamp.
        None => ts,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn ts() -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2026-10-04T23:00:53.250028Z")
            .expect("fixed timestamp")
            .with_timezone(&Utc)
    }

    /// The byte contract every writer and verifier shares: exactly 7 pipe
    /// segments, empty (never absent) for NULL ids, compact JSON details,
    /// rfc3339 timestamp.
    #[test]
    fn payload_is_the_canonical_seven_segment_shape() {
        let payload = audit_hash_payload(
            Some("ten_test26chars123456789ab"),
            Some("usr_test26chars123456789ab"),
            "login",
            "auth",
            Some("res_123"),
            &json!({"quantity": 1}),
            ts(),
        );
        let segments: Vec<&str> = payload.split('|').collect();
        assert_eq!(segments.len(), 7);
        assert_eq!(segments[0], "ten_test26chars123456789ab");
        assert_eq!(segments[1], "usr_test26chars123456789ab");
        assert_eq!(segments[2], "login");
        assert_eq!(segments[3], "auth");
        assert_eq!(segments[4], "res_123");
        assert_eq!(segments[5], "{\"quantity\":1}");
        assert_eq!(segments[6], "2026-10-04T23:00:53.250028+00:00");
    }

    /// NULL segments contribute the EMPTY string — never a dropped segment
    /// (DF-7c: a 6-field payload is unre-derivable for every verifier).
    #[test]
    fn null_segments_are_empty_never_absent() {
        let payload = audit_hash_payload(
            None,
            None,
            "billing.x",
            "metering_event",
            None,
            &json!({}),
            ts(),
        );
        let segments: Vec<&str> = payload.split('|').collect();
        assert_eq!(segments.len(), 7, "machine rows keep all 7 segments");
        assert_eq!((segments[0], segments[1], segments[4]), ("", "", ""));
    }

    /// A hand-built known vector, independent of the builder: the hash of the
    /// exact documented payload string.
    #[test]
    fn row_hash_matches_an_independently_built_sha256() {
        let payload = "t1|u1|login|auth||{\"a\":1}|2026-10-04T23:00:53.250028+00:00";
        let expected: String = {
            use sha2::Digest;
            format!("{:x}", Sha256::digest(payload.as_bytes()))
        };
        assert_eq!(audit_row_hash(payload), expected);
        assert_eq!(
            audit_hash(
                Some("t1"),
                Some("u1"),
                "login",
                "auth",
                None,
                &json!({"a":1}),
                ts(),
            ),
            expected
        );
    }

    #[test]
    fn signature_covers_the_chain_link_deterministically() {
        let sig = audit_log_signature(Some("prev"), "hash", "key-0123456789").expect("signs");
        assert_eq!(sig.len(), 64, "HMAC-SHA256 hex");
        assert_eq!(
            sig,
            audit_log_signature(Some("prev"), "hash", "key-0123456789").expect("deterministic")
        );
        assert_ne!(
            sig,
            audit_log_signature(Some("other-prev"), "hash", "key-0123456789").expect("signs"),
            "the previous hash is covered by the signature"
        );
        // The chain root signs the empty previous hash — a distinct value.
        assert_ne!(
            sig,
            audit_log_signature(None, "hash", "key-0123456789").expect("signs"),
        );
    }

    #[test]
    fn truncation_yields_pg_round_trippable_instants() {
        let nanosecond = DateTime::parse_from_rfc3339("2026-10-04T23:00:53.250028451Z")
            .expect("nanosecond timestamp")
            .with_timezone(&Utc);
        let truncated = truncate_timestamp_to_micros(nanosecond);
        assert_eq!(
            truncated.to_rfc3339(),
            "2026-10-04T23:00:53.250028+00:00",
            "sub-microsecond digits are dropped, never preserved"
        );
        assert!(truncated.timestamp_subsec_nanos().is_multiple_of(1_000));
        // Already-truncated instants pass through untouched.
        assert_eq!(truncate_timestamp_to_micros(truncated), truncated);
    }
}
