//! Provider-compatible Siteverify helper.
//!
//! Incumbent captcha backends call a provider "siteverify" endpoint with
//! `response` + `secret` (+ optional `remoteip`) and expect provider-shaped
//! JSON: `success`, `challenge_ts`, `hostname`, `action`, `cdata`,
//! `error-codes`. This module
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
    /// The action bound to the challenge at issuance (reCAPTCHA v3
    /// vocabulary), echoed from server-side metadata, never from the
    /// verification request. Always present in the emitted JSON — an
    /// explicit null when no metadata store recorded one, the same shape
    /// the PHP provider response (`SiteVerifyController::canonicalSuccess`)
    /// always carries.
    pub action: Option<String>,
    /// The cdata bound to the challenge at issuance, echoed from
    /// server-side metadata, never from the verification request. Always
    /// present in the emitted JSON as an explicit null when unknown (PHP
    /// parity: both keys are emitted on every response).
    pub cdata: Option<String>,
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
    siteverify_response_with_metadata(outcome, record, None, None)
}

/// Build the provider-shaped response with the server-side metadata the
/// caller resolved (the PHP SiteVerifyController's metadata store
/// mirror): `action` and `cdata` are issued with the challenge, never
/// echoed from the verification request, and are always emitted — null
/// when the metadata store recorded none (PHP parity).
pub fn siteverify_response_with_metadata(
    outcome: &VerifyOutcome,
    record: Option<&ChallengeRecord>,
    action: Option<&str>,
    cdata: Option<&str>,
) -> SiteverifyResponse {
    match outcome {
        VerifyOutcome::Valid { .. } => SiteverifyResponse {
            success: true,
            challenge_ts: record.map(|r| format_unix_ts(r.issued_at)),
            hostname: record.and_then(|r| r.hostname.clone()),
            action: action.map(str::to_string),
            cdata: cdata.map(str::to_string),
            error_codes: Vec::new(),
        },
        VerifyOutcome::Invalid(reason) => SiteverifyResponse {
            success: false,
            challenge_ts: None,
            hostname: None,
            action: None,
            cdata: None,
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
///   `UnsupportedArgon2Params`, `UnsupportedRswParams`, `BotDetected`,
///   `MalformedToken`, `RecordNotFound`, `ExecutionMismatch`):
///   `invalid-input-response`.
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
        | VerifyError::UnsupportedRswParams
        | VerifyError::BotDetected
        | VerifyError::MalformedToken
        | VerifyError::RecordNotFound
        | VerifyError::ExecutionMismatch => "invalid-input-response".into(),
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
    fn success_response_echoes_the_issued_action_and_cdata_metadata() {
        // action/cdata are bound at issuance and echoed from the
        // server-side metadata, never from the verification request; the
        // PHP provider response carries the same fields — as explicit
        // nulls when unknown, never as absent keys.
        let outcome = VerifyOutcome::Invalid(crate::verify::VerifyError::BadSignature);
        let without = siteverify_response(&outcome, None);
        assert_eq!(without.action, None);
        assert_eq!(without.cdata, None);
        let json = serde_json::to_value(&without).unwrap();
        assert_eq!(json["action"], serde_json::Value::Null);
        assert_eq!(json["cdata"], serde_json::Value::Null);
        assert_eq!(
            json["error-codes"],
            serde_json::json!(["invalid-input-response"])
        );

        let record = crate::challenge::ChallengeRecord {
            nonce: "n".into(),
            scope: "login".into(),
            binding_tag: "b".into(),
            issued_at: 1_700_000_000,
            expires_at: 1_700_000_120,
            algorithm: crate::challenge::PoWAlgorithm::Sha256,
            m_kib: 0,
            t: 1,
            p: 1,
            target_bits: 8,
            salt: "c2FsdA==".into(),
            prefix: String::new(),
            challenge: String::new(),
            min_duration_ms: 0,
            issued_at_ns: 0,
            attempts_used: 0,
            protocol_version: 2,
            region: None,
            policy_version: 1,
            request_binding: None,
            issuer: None,
            kid: 1,
            execution_program: None,
            execution_version: None,
            execution_commitment: None,
            hostname: None,
            decoy_field: None,
            rsw_modulus_sha256: None,
            server_mac: None,
        };
        let outcome = VerifyOutcome::Valid {
            nonce: "n".into(),
            request_binding: None,
            from_stored_result: false,
            solve_duration_ms: Some(10),
        };
        let with = siteverify_response_with_metadata(
            &outcome,
            Some(&record),
            Some("login"),
            Some("cdata-1"),
        );
        assert_eq!(with.action.as_deref(), Some("login"));
        assert_eq!(with.cdata.as_deref(), Some("cdata-1"));
        let json = serde_json::to_value(&with).unwrap();
        assert_eq!(json["action"], "login");
        assert_eq!(json["cdata"], "cdata-1");

        // A valid outcome without resolved metadata emits the same keys as
        // explicit nulls — the PHP canonicalSuccess shape.
        let without_metadata = siteverify_response(&outcome, Some(&record));
        let json = serde_json::to_value(&without_metadata).unwrap();
        assert_eq!(json["success"], true);
        assert_eq!(json["action"], serde_json::Value::Null);
        assert_eq!(json["cdata"], serde_json::Value::Null);
        assert_eq!(json["error-codes"], serde_json::json!([]));
    }

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
            (
                VerifyError::UnsupportedArgon2Params,
                "invalid-input-response",
            ),
            (VerifyError::UnsupportedRswParams, "invalid-input-response"),
            (VerifyError::BotDetected, "invalid-input-response"),
            (VerifyError::MalformedToken, "invalid-input-response"),
            (VerifyError::RecordNotFound, "invalid-input-response"),
            (VerifyError::ExecutionMismatch, "invalid-input-response"),
        ];
        assert_eq!(
            cases.len(),
            26,
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
            decoy_field: None,
            execution_program: None,
            execution_version: None,
            execution_commitment: None,
            rsw_modulus_sha256: None,
            server_mac: None,
        };
        let _ = &mut record;
        let resp = siteverify_response(
            &VerifyOutcome::Valid {
                nonce: "n".into(),
                request_binding: None,
                from_stored_result: false,
                solve_duration_ms: None,
            },
            Some(&record),
        );
        assert!(resp.success);
        assert_eq!(resp.hostname.as_deref(), Some("login.example"));
        assert_eq!(resp.challenge_ts.as_deref(), Some("2025-07-16T02:20:00Z"));
        assert!(resp.error_codes.is_empty());
        // The full emitted provider shape: both metadata keys always
        // present, null when unknown — never absent (PHP parity).
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(
            json,
            serde_json::json!({
                "success": true,
                "challenge_ts": "2025-07-16T02:20:00Z",
                "hostname": "login.example",
                "action": null,
                "cdata": null,
                "error-codes": [],
            })
        );

        // The Invalid arm pins the same key set with its provider code.
        let invalid = siteverify_response(&VerifyOutcome::Invalid(VerifyError::Expired), None);
        assert_eq!(
            serde_json::to_value(&invalid).unwrap(),
            serde_json::json!({
                "success": false,
                "challenge_ts": null,
                "hostname": null,
                "action": null,
                "cdata": null,
                "error-codes": ["timeout-or-duplicate"],
            })
        );
    }
}
