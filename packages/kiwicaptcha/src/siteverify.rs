//! Provider-compatible Siteverify helper (round 24).
//!
//! Incumbent CAPTCHA backends call a provider "siteverify" endpoint with
//! `response` + `secret` (+ optional `remoteip`) and expect provider-shaped
//! JSON: `success`, `challenge_ts`, `hostname`, `error-codes`. This module
//! provides the response DTO and the mapping from the CORE verify outcome —
//! the SAME atomic verifier the native path uses; there is no second
//! verification implementation, and the deterministic consumed-result
//! machinery makes safe verification retries free.
//!
//! Server-side contract (documented in SECURITY.md): the compatibility
//! secret authenticates SERVER-TO-SERVER use. `remoteip` is only honored
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
/// record is RETAINED until TTL, so its `issued_at`/`hostname` are
/// available after verification.
pub fn siteverify_response(outcome: &VerifyOutcome, record: Option<&ChallengeRecord>) -> SiteverifyResponse {
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
fn map_error(reason: &VerifyError) -> String {
    match reason {
        VerifyError::Expired | VerifyError::ConsumeIndeterminate => "timeout-or-duplicate".into(),
        VerifyError::BadSignature
        | VerifyError::MalformedRecord
        | VerifyError::MalformedToken
        | VerifyError::RecordNotFound
        | VerifyError::UnknownKid
        | VerifyError::WrongScope
        | VerifyError::IpMismatch
        | VerifyError::MissingClientIp
        | VerifyError::WrongRegion
        | VerifyError::WrongIssuer
        | VerifyError::WrongPolicyVersion => "invalid-input-response".into(),
        _ => "bad-request".into(),
    }
}

fn format_unix_ts(secs: u64) -> String {
    // RFC 3339 UTC ("2026-08-15T12:00:00Z") without pulling in chrono.
    let days = secs / 86_400;
    let secs_of_day = secs % 86_400;
    let (y, m, d) = civil_from_days(days);
    let (hh, mm, ss) = (secs_of_day / 3600, (secs_of_day % 3600) / 60, secs_of_day % 60);
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

    #[test]
    fn maps_core_reasons_to_provider_codes() {
        assert_eq!(map_error(&VerifyError::Expired), "timeout-or-duplicate");
        assert_eq!(map_error(&VerifyError::ConsumeIndeterminate), "timeout-or-duplicate");
        assert_eq!(map_error(&VerifyError::WrongScope), "invalid-input-response");
        assert_eq!(map_error(&VerifyError::TooFast), "bad-request");
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
        let resp = siteverify_response(&VerifyOutcome::Valid { nonce: "n".into(), request_binding: None }, Some(&record));
        assert!(resp.success);
        assert_eq!(resp.hostname.as_deref(), Some("login.example"));
        assert_eq!(resp.challenge_ts.as_deref(), Some("2025-07-16T02:20:00Z"));
        assert!(resp.error_codes.is_empty());
    }
}
