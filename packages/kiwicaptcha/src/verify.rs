//! Proof-of-work verification for KiwiCaptcha.
//!
//! Given a stored [`ChallengeRecord`] and a client-submitted counter, this
//! module re-derives the hash (`SHA-256(prefix || counter || salt)` or
//! `Argon2id(prefix || counter, salt)` per the record's algorithm) and checks
//! that the raw output has at least `target_bits` leading zero bits.
//!
//! Because the computation is driven by the record's explicit algorithm and
//! difficulty, the verifier always performs exactly the work the issuer
//! configured — the client cannot downgrade difficulty or switch modes.

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use sha2::{Digest, Sha256};
use argon2::{Argon2, Algorithm, Version, Params};

use crate::challenge::{payload_from_record, verify_signature, ChallengeRecord, PoWAlgorithm};

/// Compute the hash for the given record + counter.
///
/// The computation is driven by the challenge's explicit [`PoWAlgorithm`],
/// never by a numeric heuristic:
/// 1. [`PoWAlgorithm::Sha256`] — `SHA-256(prefix || counter || salt)`
/// 2. [`PoWAlgorithm::Argon2id`] — `Argon2id(prefix || counter, salt)` with
///    the record's m_kib/t/p parameters.
fn derive_hash(record: &ChallengeRecord, counter: u64) -> Result<[u8; 32], VerifyError> {
    let salt = B64
        .decode(&record.salt)
        .map_err(|_| VerifyError::MalformedRecord)?;

    match record.algorithm {
        PoWAlgorithm::Argon2id => {
            // Reject implausible parameters up front: the verifier must never
            // run a memory-hard computation with impossible parameters, and
            // the minimum (m_kib >= 8 * p) is enforced at issuance too.
            if record.m_kib < 8 * record.p || record.m_kib > crate::challenge::SOLVER_MAX_ARGON2_M_KIB {
                return Err(VerifyError::MalformedRecord);
            }
            let params = Params::new(record.m_kib, record.t, record.p, Some(32))
                .map_err(|_| VerifyError::MalformedRecord)?;
            let hasher = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
            let password = format!("{}{}", record.prefix, counter);
            let mut output = [0u8; 32];
            hasher
                .hash_password_into(password.as_bytes(), &salt, &mut output)
                .map_err(|_| VerifyError::InsufficientWork)?;
            Ok(output)
        }
        PoWAlgorithm::Sha256 => {
            let input = format!("{}{}", record.prefix, counter);
            let mut hasher = Sha256::new();
            hasher.update(input.as_bytes());
            hasher.update(&salt);
            let result = hasher.finalize();
            let mut out = [0u8; 32];
            out.copy_from_slice(&result);
            Ok(out)
        }
    }
}

/// Count the number of leading zero bits in a byte slice (big-endian bit order).
fn leading_zero_bits(hash: &[u8]) -> u32 {
    let mut count = 0u32;
    for &byte in hash {
        if byte == 0 {
            count += 8;
        } else {
            count += byte.leading_zeros();
            break;
        }
    }
    count
}

/// The context for verifying a single solution.
pub struct VerifyContext<'a> {
    /// The stored challenge record (looked up from Redis by nonce).
    pub record: &'a ChallengeRecord,
    /// The HMAC secret key (to re-verify the challenge signature).
    pub secret_key: &'a str,
    /// The client's claimed counter.
    pub counter: u64,
    /// The client's reported solve duration in milliseconds.
    pub duration_ms: u64,
    /// The current Unix timestamp (for TTL check).
    pub now_unix: u64,
    /// The minimum acceptable solve duration in milliseconds. A solve arriving
    /// faster than the theoretical minimum is rejected as infeasible.
    pub min_duration_ms: u64,
    /// Expected auth scope. If [`Some`], the solution is rejected if the
    /// challenge was issued for a different scope (prevents cross-scope replay).
    pub expected_scope: Option<&'a str>,
}

/// Outcome of a verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyOutcome {
    /// The solution is valid. The caller should mark the challenge consumed.
    Valid,
    /// The solution is invalid; the reason explains why.
    Invalid(VerifyError),
}

/// Reasons a solution can be rejected.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum VerifyError {
    #[error("challenge signature is invalid")]
    BadSignature,
    #[error("challenge has expired")]
    Expired,
    #[error("solution arrived faster than the theoretical minimum")]
    TooFast,
    #[error("proof-of-work hash does not meet the difficulty target")]
    InsufficientWork,
    #[error("stored challenge record is malformed")]
    MalformedRecord,
    #[error("automated or headless client detected via telemetry")]
    BotDetected,
}

/// Verify a solution against its stored challenge record.
///
/// This performs the full server-side check:
/// 1. Re-verify the HMAC signature (defends against forged records).
/// 2. Check the TTL (defends against stale challenges).
/// 3. Check the minimum duration (defends against impossibly-fast solves).
/// 4. Re-derive the SHA-256 hash and check leading zero bits (the actual PoW).
pub fn verify_solution(ctx: &VerifyContext<'_>) -> VerifyOutcome {
    // 1. Signature re-check.
    let payload = payload_from_record(ctx.record);
    match verify_signature(&payload, signature_from_challenge(ctx.record), ctx.secret_key) {
        Ok(true) => {}
        Ok(false) => return VerifyOutcome::Invalid(VerifyError::BadSignature),
        Err(_) => return VerifyOutcome::Invalid(VerifyError::BadSignature),
    }

    // 2. TTL.
    if ctx.now_unix >= ctx.record.expires_at {
        return VerifyOutcome::Invalid(VerifyError::Expired);
    }

    // 2b. Scope validation: reject if the challenge was issued for a different
    //     auth flow (e.g. a login challenge used on /signup).
    if let Some(expected) = ctx.expected_scope {
        if ctx.record.scope != expected {
            return VerifyOutcome::Invalid(VerifyError::BadSignature);
        }
    }

    // 3. Minimum duration (only enforced for non-trivial difficulties; a 0
    //    min_duration_ms disables this check, useful in tests). The floor is
    //    per-challenge: it was derived at issuance from the algorithm and
    //    difficulty so it can never conflict with the solver (e.g. auto-tuned
    //    low difficulty or a fast WASM solver both stay above their floor).
    let floor = ctx.min_duration_ms.max(ctx.record.min_duration_ms);
    if floor > 0 && ctx.duration_ms < floor {
        return VerifyOutcome::Invalid(VerifyError::TooFast);
    }

    // 4. Re-derive and check leading zero bits.
    let hash = match derive_hash(ctx.record, ctx.counter) {
        Ok(h) => h,
        Err(e) => return VerifyOutcome::Invalid(e),
    };

    if leading_zero_bits(&hash) >= ctx.record.target_bits {
        VerifyOutcome::Valid
    } else {
        VerifyOutcome::Invalid(VerifyError::InsufficientWork)
    }
}

/// Extract the embedded signature from the stored challenge string.
///
/// The challenge is `base64(payload).signature` (the base64 payload contains no
/// dots, so `rsplit_once('.')` reliably isolates the hex HMAC signature).
fn signature_from_challenge(record: &ChallengeRecord) -> &str {
    record
        .challenge
        .rsplit_once('.')
        .map(|(_, sig)| sig)
        .unwrap_or("")
}

/// Convenience: produce a *valid* counter for a record (used by tests and by a
/// server-side solver for the dev-bypass path). This brute-forces until the
/// difficulty target is met.
pub fn solve_for_test(record: &ChallengeRecord) -> Option<u64> {
    for counter in 0..u64::MAX {
        if let Ok(hash) = derive_hash(record, counter) {
            if leading_zero_bits(&hash) >= record.target_bits {
                return Some(counter);
            }
        }
    }
    None
}

/// SHA-256 helper used by the telemetry risk scorer (kept here to centralize
/// hashing deps).
pub fn sha256_hex(input: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    let result = hasher.finalize();
    result.iter().map(|b| format!("{b:02x}")).collect()
}

/// Score telemetry data for bot detection. Returns `true` if the client
/// appears to be automated/headless and should be rejected.
///
/// Hard rejection signals:
/// - `webdriver` flag is set (Chrome DevTools Protocol / Selenium).
/// - Solve completes in >30s with zero mouse/key events (headless solver).
/// - Solve takes >120s total (well beyond the ~30s expected for targetBits=14).
///
/// Soft signals (logged but NOT rejected):
/// - `hardwareConcurrency=0` AND `deviceMemory=0` (likely headless browser).
/// - `plugins.length=0` AND `hardwareConcurrency=0` (likely headless).
pub fn score_telemetry(telemetry: &serde_json::Value, duration_ms: u64) -> bool {
    let wd = telemetry.get("wd").and_then(|v| v.as_bool()).unwrap_or(false);
    if wd {
        return true;
    }

    let me = telemetry.get("me").and_then(|v| v.as_u64()).unwrap_or(0);
    let ke = telemetry.get("ke").and_then(|v| v.as_u64()).unwrap_or(0);
    let hc = telemetry.get("hc").and_then(|v| v.as_u64()).unwrap_or(0);
    let dm = telemetry.get("dm").and_then(|v| v.as_u64()).unwrap_or(0);
    let pl = telemetry.get("pl").and_then(|v| v.as_u64()).unwrap_or(0);

    // Hard rejection signals:
    // 1. Solve completes in >30s with zero mouse/key events (headless solver).
    if duration_ms > 30_000 && me == 0 && ke == 0 {
        tracing::warn!(
            duration_ms,
            me,
            ke,
            "KiwiCaptcha: bot suspected — solve took >30s with zero interaction"
        );
        return true;
    }

    // 2. Solve takes >300s total (well beyond expected). Increased from 120s to allow for very slow devices.
    if duration_ms > 300_000 {
        tracing::warn!(
            duration_ms,
            "KiwiCaptcha: bot suspected — solve took >300s"
        );
        return true;
    }

    // 3. Entropy check: if there are interactions, check for timing variance.
    //    Bots often simulate events with perfectly uniform intervals.
    //
    //    This check is deliberately conservative:
    //    - It only considers *discrete* events (the widget records pointerdown,
    //      non-repeat keydown, wheel, and click — never coalesced mousemove or
    //      OS key auto-repeat), so a uniform interval across 24+ discrete
    //      human events is not something a person can produce.
    //    - The coefficient of variation must be near zero (< 2%) AND the mean
    //      interval must be ≥ 8 ms, so a burst of sub-frame events (which can
    //      round to identical millisecond timestamps) is never misclassified.
    if let Some(et) = telemetry.get("et").and_then(|v| v.as_array()) {
        if et.len() >= 24 {
            let mut diffs = Vec::with_capacity(et.len() - 1);
            for i in 1..et.len() {
                if let (Some(t1), Some(t0)) = (et[i].as_u64(), et[i - 1].as_u64()) {
                    if t1 >= t0 {
                        diffs.push(t1 - t0);
                    }
                }
            }

            if diffs.len() >= 23 {
                let mut sum: u64 = 0;
                for &d in &diffs {
                    sum += d;
                }
                let mean = sum as f64 / diffs.len() as f64;
                if mean >= 8.0 {
                    let variance: f64 = diffs
                        .iter()
                        .map(|&d| {
                            let diff = d as f64 - mean;
                            diff * diff
                        })
                        .sum::<f64>()
                        / diffs.len() as f64;
                    let cv = variance.sqrt() / mean;
                    if cv < 0.02 {
                        tracing::warn!(
                            cv,
                            mean,
                            n = diffs.len(),
                            "KiwiCaptcha: bot suspected — near-zero timing variance in discrete events"
                        );
                        return true;
                    }
                }
            }
        }
    }

    // Soft signals (logged but NOT rejected):
    if hc == 0 && dm == 0 {
        tracing::info!(
            hc,
            dm,
            "KiwiCaptcha: possible headless client (hc=0, dm=0) — soft signal, not rejected"
        );
    }

    if hc == 0 && pl == 0 {
        tracing::info!(
            hc,
            pl,
            "KiwiCaptcha: possible headless client (hc=0, pl=0) — soft signal, not rejected"
        );
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::challenge::{hash_ip, issue_challenge, ChallengeConfig, PoWAlgorithm};

    fn make_record(target_bits: u32) -> ChallengeRecord {
        let config = ChallengeConfig {
            secret_key: "test-key".into(),
            algorithm: PoWAlgorithm::Sha256,
            m_kib: 100,
            t: 1,
            p: 1,
            target_bits,
            argon2_target_bits: 8,
            ttl_secs: 120,
            min_duration_ms: None,
            auto_tune: false,
            auto_tune_min_bits: 8,
            auto_tune_max_bits: 24,
        };
        let issued = issue_challenge(&config, "login", "1.2.3.4", 1_000_000, 0).unwrap();
        issued.record
    }

    fn make_argon2_record(target_bits: u32, m_kib: u32) -> ChallengeRecord {
        let config = ChallengeConfig {
            secret_key: "test-key".into(),
            algorithm: PoWAlgorithm::Argon2id,
            m_kib,
            t: 1,
            p: 1,
            target_bits,
            argon2_target_bits: target_bits,
            ttl_secs: 120,
            min_duration_ms: None,
            auto_tune: false,
            auto_tune_min_bits: 8,
            auto_tune_max_bits: 24,
        };
        let issued = issue_challenge(&config, "login", "1.2.3.4", 1_000_000, 0).unwrap();
        issued.record
    }

    fn verify(record: &ChallengeRecord, counter: u64, duration_ms: u64) -> VerifyOutcome {
        let ctx = VerifyContext {
            record,
            secret_key: "test-key",
            counter,
            duration_ms,
            now_unix: 1_000_001,
            min_duration_ms: 0,
            expected_scope: None,
        };
        verify_solution(&ctx)
    }

    #[test]
    fn valid_solution_is_accepted() {
        let record = make_record(8); // 8 bits — fast solve
        let counter = solve_for_test(&record).expect("solver finds a counter");
        assert_eq!(verify(&record, counter, 5000), VerifyOutcome::Valid);
    }

    #[test]
    fn argon2_solution_is_accepted() {
        let record = make_argon2_record(4, 128); // low bits, small memory for tests
        let counter = solve_for_test(&record).expect("solver finds an argon2 counter");
        assert_eq!(verify(&record, counter, 5000), VerifyOutcome::Valid);
    }

    #[test]
    fn argon2_issuance_rejects_invalid_memory_params() {
        // m_kib < 8 * p must fail at issuance, not at verification time.
        let config = ChallengeConfig {
            secret_key: "test-key".into(),
            algorithm: PoWAlgorithm::Argon2id,
            m_kib: 4,
            t: 1,
            p: 1,
            target_bits: 4,
            argon2_target_bits: 4,
            ttl_secs: 120,
            min_duration_ms: None,
            auto_tune: false,
            auto_tune_min_bits: 8,
            auto_tune_max_bits: 24,
        };
        assert!(issue_challenge(&config, "login", "1.2.3.4", 1_000_000, 0).is_err());
    }

    #[test]
    fn wrong_counter_is_rejected() {
        let record = make_record(8);
        // Find a valid counter, then use a different one.
        let valid = solve_for_test(&record).unwrap();
        let bad = if valid == 0 { 1 } else { 0 };
        assert_eq!(
            verify(&record, bad, 5000),
            VerifyOutcome::Invalid(VerifyError::InsufficientWork)
        );
    }

    #[test]
    fn expired_challenge_is_rejected() {
        let record = make_record(8);
        let counter = solve_for_test(&record).unwrap();
        let ctx = VerifyContext {
            record: &record,
            secret_key: "test-key",
            counter,
            duration_ms: 5000,
            now_unix: 1_000_000 + 121, // past TTL
            min_duration_ms: 0,
            expected_scope: None,
        };
        assert_eq!(
            verify_solution(&ctx),
            VerifyOutcome::Invalid(VerifyError::Expired)
        );
    }

    #[test]
    fn too_fast_solution_is_rejected() {
        let record = make_record(20); // high difficulty => non-trivial floor
        let counter = solve_for_test(&record).unwrap();
        let floor = record.min_duration_ms.max(1);
        let ctx = VerifyContext {
            record: &record,
            secret_key: "test-key",
            counter,
            duration_ms: floor - 1, // below the issued floor
            now_unix: 1_000_001,
            min_duration_ms: 0,
            expected_scope: None,
        };
        assert_eq!(
            verify_solution(&ctx),
            VerifyOutcome::Invalid(VerifyError::TooFast)
        );
    }

    #[test]
    fn issued_min_duration_is_floor_for_derived_difficulty() {
        // The floor is derived at issuance from the algorithm + difficulty:
        // it is always positive, scales with difficulty, and Argon2id
        // (memory-hard) floors are far above SHA-256 floors at equal bits.
        let low = make_record(10);
        let high = make_record(20);
        assert!(low.min_duration_ms > 0);
        assert!(high.min_duration_ms >= low.min_duration_ms);
        let argon = make_argon2_record(10, 128);
        assert!(argon.min_duration_ms > low.min_duration_ms);
    }

    #[test]
    fn bad_secret_key_rejects() {
        let record = make_record(8);
        let counter = solve_for_test(&record).unwrap();
        let ctx = VerifyContext {
            record: &record,
            secret_key: "WRONG-KEY",
            counter,
            duration_ms: 5000,
            now_unix: 1_000_001,
            min_duration_ms: 0,
            expected_scope: None,
        };
        assert_eq!(
            verify_solution(&ctx),
            VerifyOutcome::Invalid(VerifyError::BadSignature)
        );
    }

    #[test]
    fn leading_zero_bits_counts_correctly() {
        assert_eq!(leading_zero_bits(&[0u8, 0xFF]), 8);
        assert_eq!(leading_zero_bits(&[0u8, 0x0F]), 12);
        assert_eq!(leading_zero_bits(&[0x00, 0x00, 0x01]), 23);
        assert_eq!(leading_zero_bits(&[0xFF]), 0);
        assert_eq!(leading_zero_bits(&[]), 0);
    }

    #[test]
    fn telemetry_bot_detection_works() {
        use serde_json::json;

        // Normal user: irregular discrete-event timings (jittered pointerdowns)
        let t1 = json!({
            "wd": false,
            "me": 50,
            "ke": 10,
            "et": [100, 187, 296, 412, 531, 640, 772, 881, 990, 1107, 1221, 1330, 1449, 1561, 1670, 1788, 1899, 2012, 2124, 2233, 2348, 2461, 2577, 2688, 2801, 2913]
        });
        assert!(!score_telemetry(&t1, 5000));

        // Webdriver rejection
        let t2 = json!({"wd": true});
        assert!(score_telemetry(&t2, 5000));

        // Too slow rejection
        assert!(score_telemetry(&t1, 301_000));

        // Zero interaction long solve rejection
        let t3 = json!({"wd": false, "me": 0, "ke": 0});
        assert!(score_telemetry(&t3, 31_000));

        // Bot simulation rejection: 24+ discrete events at perfectly uniform
        // intervals (CV ~ 0, mean >= 8ms).
        let uniform: Vec<u64> = (0..30).map(|i| 100 + i * 100).collect();
        let t4 = json!({
            "wd": false,
            "me": 20,
            "ke": 0,
            "et": uniform
        });
        assert!(score_telemetry(&t4, 5000));

        // Human-like jittered timing must NOT be rejected even with many events.
        let jittered: Vec<u64> = (0..30).map(|i| i * 97 + (i * 7 % 13)).collect();
        let t5 = json!({
            "wd": false,
            "me": 20,
            "ke": 0,
            "et": jittered
        });
        assert!(!score_telemetry(&t5, 5000));

        // Sub-frame events (1-2ms diffs) must NOT be rejected: coalesced events
        // can round to identical millisecond timestamps.
        let subframe: Vec<u64> = (0..30).map(|i| i * 2).collect();
        let t6 = json!({
            "wd": false,
            "me": 20,
            "ke": 0,
            "et": subframe
        });
        assert!(!score_telemetry(&t6, 5000));

        // Sparse human events (mean interval > 8ms, high variance) pass.
        let sparse: Vec<u64> = (0..30).map(|i| i * 143 + (i * 11 % 37)).collect();
        let t7 = json!({
            "wd": false,
            "me": 20,
            "ke": 0,
            "et": sparse
        });
        assert!(!score_telemetry(&t7, 5000));
    }

    // ── Aggressive bot-detection suite ────────────────────────────────────

    #[test]
    fn telemetry_rejects_precise_keyboard_autorepeat_patterns() {
        // A headless solver that "types" with exact 30ms OS auto-repeat timing.
        use serde_json::json;
        let uniform_30ms: Vec<u64> = (0..30).map(|i| 100 + i * 30).collect();
        let t = json!({
            "wd": false, "me": 0, "ke": 30, "et": uniform_30ms
        });
        assert!(score_telemetry(&t, 4000), "uniform 30ms discrete events must be rejected");
    }

    #[test]
    fn telemetry_rejects_exact_60hz_pointer_timestamps() {
        // Mouse-move replay at exactly 16.67ms (display refresh) with zero jitter.
        use serde_json::json;
        let uniform_16ms: Vec<u64> = (0..30).map(|i| 500 + i * 17).collect();
        let t = json!({
            "wd": false, "me": 30, "ke": 0, "et": uniform_16ms
        });
        assert!(score_telemetry(&t, 4000), "exact 16-17ms discrete intervals must be rejected");
    }

    #[test]
    fn telemetry_accepts_human_jitter_at_many_scales() {
        use serde_json::json;
        // Human click intervals vary 5-30%; none of these should reject.
        let cases: Vec<Vec<u64>> = vec![
            (0..30).map(|i| i * 87 + (i * i % 23)).collect(),      // fast typist
            (0..30).map(|i| i * 145 + (i * 3 % 31)).collect(),     // slow reader
            (0..30).map(|i| i * 64 + (i * 7 % 11)).collect(),      // burst clicking
            (0..30).map(|i| i * 203 + (i % 5) * 17).collect(),     // sparse + jitter
        ];
        for (i, et) in cases.iter().enumerate() {
            let t = json!({ "wd": false, "me": 20, "ke": 5, "et": et });
            assert!(
                !score_telemetry(&t, 5000),
                "human-like timing case {i} must not be rejected"
            );
        }
    }

    #[test]
    fn telemetry_rejects_webdriver_combined_with_normal_timing() {
        // A bot that fakes human timing but leaves webdriver=true.
        use serde_json::json;
        let jittered: Vec<u64> = (0..30).map(|i| i * 97 + (i * 7 % 13)).collect();
        let t = json!({ "wd": true, "me": 20, "ke": 0, "et": jittered });
        assert!(score_telemetry(&t, 5000));
    }

    #[test]
    fn telemetry_rejects_long_headless_solve_without_interaction() {
        use serde_json::json;
        let t = json!({ "wd": false, "me": 0, "ke": 0, "et": [] });
        assert!(score_telemetry(&t, 31_000));
        assert!(score_telemetry(&t, 301_000));
        // A normal-duration solve with no interaction is fine (users may not
        // touch the page while it auto-solves).
        assert!(!score_telemetry(&t, 4000));
    }

    #[test]
    fn telemetry_accepts_mobile_touch_users() {
        // Mobile users have no mouse/keyboard events — pointer/touch events
        // feed `me`, so a slow mobile solve with touch interaction must pass.
        use serde_json::json;
        let jittered: Vec<u64> = (0..30).map(|i| i * 122 + (i * 5 % 19)).collect();
        let t = json!({ "wd": false, "me": 12, "ke": 0, "et": jittered });
        assert!(!score_telemetry(&t, 25_000));
    }

    #[test]
    fn telemetry_ignores_sparse_or_absent_event_timings() {
        use serde_json::json;
        // Fewer than 24 events: entropy check must not fire.
        let few: Vec<u64> = (0..10).map(|i| 100 + i * 100).collect();
        let t = json!({ "wd": false, "me": 5, "ke": 0, "et": few });
        assert!(!score_telemetry(&t, 5000));
        // No events at all.
        let none = json!({ "wd": false, "me": 0, "ke": 0, "et": [] });
        assert!(!score_telemetry(&none, 5000));
    }

    // ── Aggressive verification suite ─────────────────────────────────────

    #[test]
    fn verify_rejects_counter_beyond_solver_cap() {
        // The solver caps at MAX_SHA_HASHES (5M); a counter beyond that is
        // either a bot or an invalid solution — it must still verify the hash
        // correctly (a huge counter is just a different preimage).
        let record = make_record(4); // low difficulty: counter found quickly
        let counter = solve_for_test(&record).unwrap();
        let huge = counter + 5_000_001;
        // Huge counter is virtually certain to NOT meet the target.
        let outcome = verify(&record, huge, 5000);
        assert_eq!(outcome, VerifyOutcome::Invalid(VerifyError::InsufficientWork));
    }

    #[test]
    fn verify_rejects_tampered_challenge_string() {
        let mut record = make_record(8);
        let counter = solve_for_test(&record).unwrap();
        // Tamper with the stored challenge string (simulates a client that
        // modified the signed payload).
        record.challenge.push_str("00");
        assert_eq!(
            verify(&record, counter, 5000),
            VerifyOutcome::Invalid(VerifyError::BadSignature)
        );
    }

    #[test]
    fn verify_rejects_wrong_scope() {
        let record = make_record(8);
        let counter = solve_for_test(&record).unwrap();
        let ctx = VerifyContext {
            record: &record,
            secret_key: "test-key",
            counter,
            duration_ms: 5000,
            now_unix: 1_000_001,
            min_duration_ms: 0,
            expected_scope: Some("signup"),
        };
        assert_eq!(
            verify_solution(&ctx),
            VerifyOutcome::Invalid(VerifyError::BadSignature)
        );
    }

    #[test]
    fn verify_rejects_expired_exactly_at_ttl_boundary() {
        let record = make_record(8);
        let counter = solve_for_test(&record).unwrap();
        let ctx = VerifyContext {
            record: &record,
            secret_key: "test-key",
            counter,
            duration_ms: 5000,
            now_unix: record.expires_at, // exactly at expiry
            min_duration_ms: 0,
            expected_scope: None,
        };
        assert_eq!(
            verify_solution(&ctx),
            VerifyOutcome::Invalid(VerifyError::Expired)
        );
    }

    #[test]
    fn verify_accepts_exactly_at_ttl_boundary_minus_one() {
        let record = make_record(8);
        let counter = solve_for_test(&record).unwrap();
        let ctx = VerifyContext {
            record: &record,
            secret_key: "test-key",
            counter,
            duration_ms: 5000,
            now_unix: record.expires_at - 1,
            min_duration_ms: 0,
            expected_scope: None,
        };
        assert_eq!(verify_solution(&ctx), VerifyOutcome::Valid);
    }

    #[test]
    fn verify_rejects_wrong_ip_binding_at_verify_level() {
        // IP binding is enforced in the api-server route (auth.rs), but the
        // record stores the ip_hash — ensure the hash function is stable and
        // distinct for different IPs.
        let h1 = hash_ip("1.2.3.4", "salt");
        let h2 = hash_ip("1.2.3.5", "salt");
        let h3 = hash_ip("1.2.3.4", "salt");
        assert_ne!(h1, h2, "different IPs must hash differently");
        assert_eq!(h1, h3, "same IP must hash identically");
        assert_eq!(h1.len(), 64, "sha256 hex output");
    }

    #[test]
    fn verify_argon2_mode_rejects_wrong_algorithm_hash() {
        // A challenge issued as Argon2id must NOT accept a SHA-256 solution
        // counter and vice versa — the algorithm is part of the contract.
        let sha_record = make_record(8);
        let argon_record = make_argon2_record(8, 128);
        let sha_counter = solve_for_test(&sha_record).unwrap();
        // Feed the SHA counter into the Argon2 record: hashes differ.
        assert_eq!(
            verify(&argon_record, sha_counter, 5000),
            VerifyOutcome::Invalid(VerifyError::InsufficientWork)
        );
    }

    #[test]
    fn verify_argon2_memory_ceiling_rejects_absurd_params() {
        // m_kib above the browser-solvable ceiling must be rejected up front,
        // not run (a memory-hard hash with 4 TiB would OOM the server).
        // Solve with sane params first (fast), then verify against the
        // absurd-params record: MalformedRecord must fire before hashing.
        let sane = make_argon2_record(4, 128);
        let counter = solve_for_test(&sane).unwrap();
        let mut absurd = sane.clone();
        absurd.m_kib = crate::challenge::SOLVER_MAX_ARGON2_M_KIB + 1;
        assert_eq!(
            verify(&absurd, counter, 5000),
            VerifyOutcome::Invalid(VerifyError::MalformedRecord)
        );
    }

    #[test]
    fn verify_duration_floor_is_per_challenge() {
        // The record's own floor is authoritative when ctx.min_duration_ms is 0.
        let record = make_record(20);
        let counter = solve_for_test(&record).unwrap();
        let ctx = VerifyContext {
            record: &record,
            secret_key: "test-key",
            counter,
            duration_ms: record.min_duration_ms + 1,
            now_unix: 1_000_001,
            min_duration_ms: 0,
            expected_scope: None,
        };
        assert_eq!(verify_solution(&ctx), VerifyOutcome::Valid);
        let ctx_fast = VerifyContext {
            record: &record,
            secret_key: "test-key",
            counter,
            duration_ms: record.min_duration_ms - 1,
            now_unix: 1_000_001,
            min_duration_ms: 0,
            expected_scope: None,
        };
        assert_eq!(
            verify_solution(&ctx_fast),
            VerifyOutcome::Invalid(VerifyError::TooFast)
        );
    }

    #[test]
    fn verify_accepts_full_difficulty_range() {
        // Every difficulty from 0 to the solver cap must issue and verify.
        for bits in [0u32, 1, 4, 8, 12, 16, 20] {
            let record = make_record(bits);
            let counter = solve_for_test(&record).expect("solver finds counter");
            let outcome = verify(&record, counter, 5000);
            assert_eq!(
                outcome,
                VerifyOutcome::Valid,
                "difficulty {bits} bits must verify"
            );
        }
    }

    #[test]
    fn sha256_hex_matches_reference() {
        // RFC 6234 test vector for SHA-256("abc").
        assert_eq!(
            sha256_hex("abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}
