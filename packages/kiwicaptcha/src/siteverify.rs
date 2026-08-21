//! Provider-compatible Siteverify helper.
//!
//! Incumbent captcha backends call a provider "siteverify" endpoint with
//! `response` + `secret` (+ optional `remoteip`) and expect provider-shaped
//! JSON: `success`, `challenge_ts`, `hostname`, `error-codes`. This module
//! provides the response DTO and the mapping from the core verify outcome —
//! the same atomic verifier the native path uses; there is no second
//! verification implementation, and the deterministic consumed-result
//! machinery makes safe verification retries free.
//!
//! Server-side contract (documented in the security guide): the compatibility
//! secret authenticates server-to-server use. `remoteip` is only honored
//! after the caller presented the secret; a browser never sees it. The
//! verifier itself remains authoritative (TTL, scope/region/issuer/policy
//! expectations, nonce-bound IP binding, timing floor, Argon ceilings,
//! atomic single-use consumption).

use serde::Serialize;

use crate::challenge::ChallengeRecord;
use crate::verify::{VerifyError, VerifyOutcome};

/// The provider-shaped Siteverify JSON (reCAPTCHA-compatible vocabulary).
#[derive(Debug, Serialize, PartialEq)]
pub struct SiteverifyResponse {
    pub success: bool,
    pub challenge_ts: Option<String>,
    pub hostname: Option<String>,
    #[serde(rename = "error-codes")]
    pub error_codes: Vec<String>,
}

/// Build the provider-shaped response from the core outcome and (for a
/// valid outcome) the consumed record's server-side metadata. `record`
/// comes from the storage lookup by the outcome's nonce — the consumed
/// record is retained until TTL, so its `issued_at`/`hostname` are
/// available after verification.
pub fn siteverify_response(
    outcome: &VerifyOutcome,
    record: Option<&ChallengeRecord>,
) -> SiteverifyResponse {
    match outcome {
        VerifyOutcome::Valid { .. } => SiteverifyResponse {
            success: true,
            challenge_ts: record.map(|r| format_unix_ts(r.issued_at)),
            hostname: record.and_then(|r| r.hostname.clone()),
            error_codes: Vec::new(),
        },
        VerifyOutcome::Invalid(reason) => SiteverifyResponse {
            success: false,
            challenge_ts: None,
            hostname: None,
            error_codes: vec![map_error(reason)],
        },
    }
}

/// Provider-style error codes (reCAPTCHA-compatible vocabulary); the
/// precise core reason stays in the server logs.
///
/// exhaustive by contract: every [`VerifyError`] variant is matched with no
/// wildcard, so adding a variant fails the build until its provider
/// semantics are decided here:
/// - `Expired` — an already-validated token past its lifetime:
///   `timeout-or-duplicate`;
/// - `AlreadyConsumed` — a proven-duplicate use of a retained token whose
///   success is not replayable for this caller: `timeout-or-duplicate`
///   (the provider duplicate vocabulary);
/// - retryable SERVER-side conditions (`StorageUnavailable`,
///   `ConsumeIndeterminate`, `CapacityExceeded`, `AdmissionUnavailable`):
///   `internal-error`. `ConsumeIndeterminate` is retryable in a mapper
///   with no proven-duplicate context: the atomic consume's response was
///   lost, so the token may still be redeemable — an idempotent caller
///   retries, and a non-idempotent caller treats the token as unknown;
/// - everything else — an invalid solution, challenge, or identity
///   (`BadSignature`, `TooFast`, `IpMismatch`, `MissingClientIp`,
///   `CounterTooLarge`, `WrongScope`, `RequestBindingMismatch`,
///   `WrongRegion`, `WrongIssuer`, `WrongPolicyVersion`, `UnknownKid`,
///   `TooManyAttempts`, `InsufficientWork`, `MalformedRecord`,
///   `UnsupportedArgon2Params`, `BotDetected`, `MalformedToken`,
///   `RecordNotFound`): `invalid-input-response`.
fn map_error(reason: &VerifyError) -> String {
    match reason {
        VerifyError::Expired | VerifyError::AlreadyConsumed => "timeout-or-duplicate".into(),
        VerifyError::StorageUnavailable
        | VerifyError::ConsumeIndeterminate
        | VerifyError::CapacityExceeded
        | VerifyError::AdmissionUnavailable => "internal-error".into(),
        VerifyError::BadSignature
        | VerifyError::TooFast
        | VerifyError::IpMismatch
        | VerifyError::MissingClientIp
        | VerifyError::CounterTooLarge
        | VerifyError::WrongScope
        | VerifyError::RequestBindingMismatch
        | VerifyError::WrongRegion
        | VerifyError::WrongIssuer
        | VerifyError::WrongPolicyVersion
        | VerifyError::UnknownKid
        | VerifyError::TooManyAttempts
        | VerifyError::InsufficientWork
        | VerifyError::MalformedRecord
        | VerifyError::UnsupportedArgon2Params
        | VerifyError::BotDetected
        | VerifyError::MalformedToken
        | VerifyError::RecordNotFound => "invalid-input-response".into(),
    }
}

fn format_unix_ts(secs: u64) -> String {
    // RFC 3339 UTC ("2026-08-15T12:00:00Z") without pulling in chrono.
    let days = secs / 86_400;
    let secs_of_day = secs % 86_400;
    let (y, m, d) = civil_from_days(days);
    let (hh, mm, ss) = (
        secs_of_day / 3600,
        (secs_of_day % 3600) / 60,
        secs_of_day % 60,
    );
    format!("{y:04}-{m:02}-{d:02}T{hh:02}:{mm:02}:{ss:02}Z")
}

/// Howard Hinnant's civil-from-days algorithm (days since 1970-01-01).
fn civil_from_days(z: u64) -> (u64, u64, u64) {
    let z = z as i64 + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (if m <= 2 { y + 1 } else { y } as u64, m as u64, d as u64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::verify::VerifyOutcome;

    #[test]
    fn formats_unix_ts_as_rfc3339() {
        assert_eq!(format_unix_ts(0), "1970-01-01T00:00:00Z");
        assert_eq!(format_unix_ts(1_752_632_400), "2025-07-16T02:20:00Z");
    }

    /// Every variant of the core VerifyError enum must map to its exact
    /// provider string — the table below is the single source of truth and
    /// `map_error` itself is exhaustive (no wildcard), so a new variant
    /// fails compilation until its provider semantics are decided here AND
    /// in the match.
    #[test]
    fn maps_every_core_reason_to_its_exact_provider_code() {
        let cases: &[(VerifyError, &str)] = &[
            // Already-validated token past its lifetime, or a proven
            // duplicate whose retained success is not replayable for this
            // caller.
            (VerifyError::Expired, "timeout-or-duplicate"),
            (VerifyError::AlreadyConsumed, "timeout-or-duplicate"),
            // Retryable server-side conditions (no proven-duplicate
            // context in a mapper).
            (VerifyError::StorageUnavailable, "internal-error"),
            (VerifyError::ConsumeIndeterminate, "internal-error"),
            (VerifyError::CapacityExceeded, "internal-error"),
            (VerifyError::AdmissionUnavailable, "internal-error"),
            // Invalid solution / challenge / identity.
            (VerifyError::BadSignature, "invalid-input-response"),
            (VerifyError::TooFast, "invalid-input-response"),
            (VerifyError::IpMismatch, "invalid-input-response"),
            (VerifyError::MissingClientIp, "invalid-input-response"),
            (VerifyError::CounterTooLarge, "invalid-input-response"),
            (VerifyError::WrongScope, "invalid-input-response"),
            (
                VerifyError::RequestBindingMismatch,
                "invalid-input-response",
            ),
            (VerifyError::WrongRegion, "invalid-input-response"),
            (VerifyError::WrongIssuer, "invalid-input-response"),
            (VerifyError::WrongPolicyVersion, "invalid-input-response"),
            (VerifyError::UnknownKid, "invalid-input-response"),
            (VerifyError::TooManyAttempts, "invalid-input-response"),
            (VerifyError::InsufficientWork, "invalid-input-response"),
            (VerifyError::MalformedRecord, "invalid-input-response"),
            (VerifyError::BotDetected, "invalid-input-response"),
            (VerifyError::MalformedToken, "invalid-input-response"),
            (VerifyError::RecordNotFound, "invalid-input-response"),
        ];
        assert_eq!(
            cases.len(),
            23,
            "the table must cover EVERY VerifyError variant"
        );
        for (reason, expected) in cases {
            assert_eq!(
                map_error(reason),
                *expected,
                "variant {reason:?} must map to {expected:?}"
            );
        }
    }

    #[test]
    fn valid_outcome_emits_the_provider_shape() {
        let mut record = crate::challenge::ChallengeRecord {
            nonce: "n".into(),
            scope: "login".into(),
            binding_tag: "tag".into(),
            hostname: Some("login.example".into()),
            issued_at: 1_752_632_400,
            expires_at: 1_752_632_520,
            algorithm: crate::challenge::PoWAlgorithm::Sha256,
            m_kib: 0,
            t: 1,
            p: 1,
            target_bits: 8,
            salt: "s".into(),
            prefix: "p".into(),
            challenge: "c".into(),
            min_duration_ms: 0,
            issued_at_ns: 0,
            attempts_used: 0,
            protocol_version: 2,
            region: None,
            policy_version: 1,
            request_binding: None,
            issuer: None,
            kid: 1,
        };
        let _ = &mut record;
        let resp = siteverify_response(
            &VerifyOutcome::Valid {
                nonce: "n".into(),
                request_binding: None,
                from_stored_result: false,
            },
            Some(&record),
        );
        assert!(resp.success);
        assert_eq!(resp.hostname.as_deref(), Some("login.example"));
        assert_eq!(resp.challenge_ts.as_deref(), Some("2025-07-16T02:20:00Z"));
        assert!(resp.error_codes.is_empty());
    }
}
