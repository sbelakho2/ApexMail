//! # Property-Based Tests (SM12 F2 — retargeted at production types)
//!
//! Every `proptest!` block in this file exercises REAL workspace crates:
//!
//! | Module                    | Production type under test                                   |
//! |---------------------------|--------------------------------------------------------------|
//! | `rate_limiter_properties` | `apexmail_rate_limiter::SlidingWindowCounter`                |
//! | `circuit_breaker_props`   | `worker_processors::common::circuit_breaker::CircuitBreaker` |
//! | `crypto_properties`       | `apexmail_lib::crypto` (HMAC-SHA256, SHA-256, timing cmp)    |
//! | `aead_properties`         | `apexmail_lib::secret_at_rest` (AES-256-GCM at-rest crypto)  |
//! | `validation_properties`   | `apexmail_lib::validation` (RFC 5322 email, domain, NUL)     |
//!
//! Audit finding 2: this suite previously declared `PropertyRateLimiter`,
//! `PropertyCircuitBreaker`, `xor_encrypt`, a local `is_valid_email`,
//! `DefaultHasher`, and a toy `BoundedQueue` INSIDE the test file — all 23
//! properties exercised those toys, so a regression in the real rate
//! limiter or circuit breaker could never fail a test here. The toys are
//! gone:
//!
//! * the `DefaultHasher` module tested the Rust standard library — deleted
//!   (no production counterpart);
//! * the `BoundedQueue` module had no production counterpart either
//!   (`queue-provider` is Postgres-backed, `worker-processors::common`
//!   ships `Backpressure` — a permit semaphore, not a queue) — deleted per
//!   the audit directive; its invariants (bounded concurrency, no leaked
//!   permits) are covered against the real `Backpressure` in the
//!   load-tests crate instead.
//! * the SQL-sanitization property had no production counterpart
//!   (production uses parameterized queries) — deleted.

use proptest::prelude::*;

// ===========================================================================
// 1. RATE LIMITER — real apexmail_rate_limiter::SlidingWindowCounter
// ===========================================================================

mod rate_limiter_properties {
    use super::*;
    use apexmail_rate_limiter::SlidingWindowCounter;
    use std::time::Duration;

    /// A window far longer than any test run: the fill/limit properties
    /// below must hold with NO rollover in play. Rollover has its own
    /// dedicated property further down.
    const NO_ROLLOVER: Duration = Duration::from_secs(3600);

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(256))]

    /// Property: the limiter admits EXACTLY `limit` requests and then
    /// denies, for ANY limit — the contract every caller relies on.
        #[test]
        fn allows_exactly_limit_requests(limit in 1u64..300) {
            let counter = SlidingWindowCounter::from_params(NO_ROLLOVER, limit);

            for i in 0..limit {
                let decision = counter.check_and_increment();
                prop_assert!(
                    decision.is_allowed(),
                    "request {} of limit {} must be allowed, got {:?}",
                    i + 1,
                    limit,
                    decision
                );
            }

            prop_assert!(
                counter.check_and_increment().is_denied(),
                "request {} must be denied (limit={})",
                limit + 1,
                limit
            );
        }

    /// Property: a denial always carries a positive retry_after — a caller
    /// honoring it must never busy-loop on a zero wait.
        #[test]
        fn denied_decision_carries_positive_retry_after(limit in 1u64..100) {
            let counter = SlidingWindowCounter::from_params(NO_ROLLOVER, limit);
            for _ in 0..limit {
                counter.check_and_increment();
            }

            let denied = counter.check_and_increment();
            let retry_after = denied
                .retry_after()
                .expect("a denied decision carries retry_after");
            prop_assert!(
                retry_after > Duration::ZERO,
                "retry_after must be positive, got {:?}",
                retry_after
            );
        }

    /// Property: `remaining` never exceeds the limit and never goes
    /// negative (u64 saturating); an allowed decision always leaves
    /// remaining ≤ limit−1 because the request itself consumed budget.
        #[test]
        fn remaining_stays_within_limit(limit in 1u64..100, checks in 1u64..200) {
            let counter = SlidingWindowCounter::from_params(NO_ROLLOVER, limit);

            for _ in 0..checks {
                let decision = counter.check_and_increment();
                if decision.is_allowed() {
                    prop_assert!(
                        decision.remaining() < limit,
                        "allowed decision reported remaining {} > limit-1 {}",
                        decision.remaining(),
                        limit - 1
                    );
                }
            }
        }

    /// Property: the reported count matches admitted events exactly inside
    /// a fresh window (monotonic time, no rotation): the counter must be
    /// exact accounting, not an estimate that drifts upward.
        #[test]
        fn current_count_matches_admissions(limit in 1u64..100, admitted in 1u64..100) {
            let counter = SlidingWindowCounter::from_params(NO_ROLLOVER, limit);
            let expected = admitted.min(limit);

            for _ in 0..admitted {
                counter.check_and_increment();
            }

            prop_assert_eq!(
                counter.current_count(),
                expected,
                "count must equal the number of admitted events in a fresh window"
            );
        }

    /// Property: limit=0 denies EVERYTHING — a misconfigured limit must
    /// fail closed, never open.
        #[test]
        fn limit_zero_denies_everything(requests in 1u64..50) {
            let counter = SlidingWindowCounter::from_params(NO_ROLLOVER, 0);
            for _ in 0..requests {
                prop_assert!(
                    counter.check_and_increment().is_denied(),
                    "limit=0 must deny every request"
                );
            }
        }

    /// Property: reset restores full capacity — an operator clearing a
    /// limiter must get a budget identical to a fresh instance.
        #[test]
        fn reset_restores_full_capacity(limit in 1u64..100, exhaust in 1u64..100) {
            let counter = SlidingWindowCounter::from_params(NO_ROLLOVER, limit);
            for _ in 0..exhaust.min(limit) {
                counter.check_and_increment();
            }

            counter.reset();
            prop_assert_eq!(counter.current_count(), 0, "reset must zero the count");

            for i in 0..limit {
                prop_assert!(
                    counter.check_and_increment().is_allowed(),
                    "after reset, request {} of {} must be allowed",
                    i + 1,
                    limit
                );
            }
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(8))]

    /// Property (window rollover): after 2+ idle windows the budget resets
    /// completely — old events age out and the client is admitted again.
    /// Short real-time windows (40–80 ms) keep the property fast; the
    /// proptest case count is capped because each case sleeps.
        #[test]
        fn window_rollover_restores_budget(window_ms in 40u64..80) {
            let window = Duration::from_millis(window_ms);
            let counter = SlidingWindowCounter::from_params(window, 2);

            assert!(counter.check_and_increment().is_allowed());
            assert!(counter.check_and_increment().is_allowed());
            assert!(
                counter.check_and_increment().is_denied(),
                "exhausted window must deny"
            );

            // Idle for 2 full windows: maybe_rotate resets everything.
            std::thread::sleep(window * 2 + Duration::from_millis(20));

            prop_assert!(
                counter.check_and_increment().is_allowed(),
                "after 2 idle windows the budget must fully reset"
            );
        }
    }
}

// ===========================================================================
// 2. CIRCUIT BREAKER — real worker_processors CircuitBreaker
// ===========================================================================

mod circuit_breaker_props {
    use super::*;
    use std::time::Duration;
    use worker_processors::common::circuit_breaker::{
        CircuitBreaker, CircuitBreakerConfig, CircuitState,
    };

    /// Failure-window long enough that sequential in-test failures never
    /// roll over (the breaker resets its count only across a window gap).
    const NO_WINDOW_RESET: Duration = Duration::from_secs(3600);

    fn breaker(
        failure_threshold: u32,
        success_threshold: u32,
        open_duration: Duration,
    ) -> CircuitBreaker {
        CircuitBreaker::new(CircuitBreakerConfig {
            failure_threshold,
            success_threshold,
            open_duration,
            window_duration: NO_WINDOW_RESET,
        })
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]

    /// Property: the circuit opens at EXACTLY the threshold-th failure and
    /// not before, for ANY threshold.
        #[test]
        fn opens_at_threshold(threshold in 1u32..25) {
            let cb = breaker(threshold, 1, Duration::from_secs(3600));

            for i in 0..(threshold - 1) {
                cb.record_failure();
                prop_assert_eq!(
                    cb.state(),
                    CircuitState::Closed,
                    "failure {} of threshold {} must keep the circuit closed",
                    i + 1,
                    threshold
                );
                prop_assert!(cb.is_allowed(), "closed circuit admits requests");
            }

            cb.record_failure();
            prop_assert_eq!(cb.state(), CircuitState::Open, "must open at the threshold");
            prop_assert!(!cb.is_allowed(), "open circuit rejects requests");
        }

    /// Property: extra failures while open never close the circuit, and a
    /// success recorded while open (a straggler) cannot close it either.
        #[test]
        fn open_stays_open_despite_extra_events(threshold in 1u32..10, extra in 1u32..20) {
            let cb = breaker(threshold, 3, Duration::from_secs(3600));
            for _ in 0..threshold {
                cb.record_failure();
            }
            prop_assert_eq!(cb.state(), CircuitState::Open);

            for _ in 0..extra {
                cb.record_failure();
                cb.record_success();
                prop_assert_eq!(
                    cb.state(),
                    CircuitState::Open,
                    "neither failures nor straggler successes may close an open circuit"
                );
            }
        }

    /// Property: after `open_duration` elapses the next check transitions
    /// the breaker to half-open and admits the probe.
        #[test]
        fn probe_admitted_after_open_duration(open_ms in 5u64..20) {
            let cb = breaker(1, 2, Duration::from_millis(open_ms));
            cb.record_failure();
            prop_assert_eq!(cb.state(), CircuitState::Open);
            prop_assert!(!cb.is_allowed(), "the open window is not over yet");

            std::thread::sleep(Duration::from_millis(open_ms) + Duration::from_millis(8));

            prop_assert!(cb.is_allowed(), "the probe must be admitted");
            prop_assert_eq!(cb.state(), CircuitState::HalfOpen);
            // Half-open stays permissive for further probes.
            prop_assert!(cb.is_allowed());
        }

    /// Property: ANY failure while half-open reopens the circuit — a
    /// half-open probe must never be allowed to fail silently.
        #[test]
        fn half_open_failure_reopens(open_ms in 5u64..15) {
            let cb = breaker(1, 5, Duration::from_millis(open_ms));
            cb.record_failure();
            std::thread::sleep(Duration::from_millis(open_ms) + Duration::from_millis(8));
            assert!(cb.is_allowed());
            prop_assert_eq!(cb.state(), CircuitState::HalfOpen);

            cb.record_failure();
            prop_assert_eq!(cb.state(), CircuitState::Open, "a half-open failure must reopen");
            prop_assert!(!cb.is_allowed());
        }

    /// Property: `success_threshold` consecutive successes in half-open
    /// close the circuit, and a CLOSED breaker that just recovered needs a
    /// FULL new threshold of failures to reopen (the failure count was
    /// reset — recovery must not be a one-failure relapse).
        #[test]
        fn half_open_successes_close_and_rearm(
            threshold in 2u32..10,
            recovery in 1u32..5,
            extra_successes in 0u32..3,
            open_ms in 5u64..15,
        ) {
            let cb = breaker(threshold, recovery, Duration::from_millis(open_ms));
            // Open the circuit with the FULL failure threshold first — a
            // partial failure count keeps it closed.
            for _ in 0..threshold {
                cb.record_failure();
            }
            assert_eq!(cb.state(), CircuitState::Open);
            std::thread::sleep(Duration::from_millis(open_ms) + Duration::from_millis(8));
            assert!(cb.is_allowed());

            for i in 0..recovery {
                cb.record_success();
                let expected = if i + 1 < recovery {
                    CircuitState::HalfOpen
                } else {
                    CircuitState::Closed
                };
                prop_assert_eq!(
                    cb.state(),
                    expected,
                    "success {} of {} — circuit must be {:?}",
                    i + 1,
                    recovery,
                    expected
                );
            }

            // Surplus successes in the closed state are harmless.
            for _ in 0..extra_successes {
                cb.record_success();
            }
            prop_assert_eq!(cb.state(), CircuitState::Closed);
            prop_assert!(cb.is_allowed());

            // Re-armed: the failure count was reset on close, so a single
            // failure is below the (≥2) threshold — no instant relapse.
            cb.record_failure();
            prop_assert_eq!(
                cb.state(),
                CircuitState::Closed,
                "a freshly recovered breaker needs a full new failure threshold"
            );
        }

    /// Property: reset returns any state to Closed and admits immediately.
        #[test]
        fn reset_closes_any_state(threshold in 1u32..10) {
            let cb = breaker(threshold, 1, Duration::from_secs(3600));
            for _ in 0..threshold {
                cb.record_failure();
            }
            prop_assert_eq!(cb.state(), CircuitState::Open);

            cb.reset();
            prop_assert_eq!(cb.state(), CircuitState::Closed);
            prop_assert!(cb.is_allowed(), "a reset breaker must admit requests");
        }
    }
}

// ===========================================================================
// 3. CRYPTO — real apexmail_lib::crypto (HMAC-SHA256 / SHA-256)
// ===========================================================================

mod crypto_properties {
    use super::*;
    use apexmail_lib::crypto::{
        create_hmac_signature, create_hmac_signature_base64, hash_api_key, timing_safe_compare,
    };

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(512))]

    /// Property: HMAC is deterministic and full-length for ANY key/message
    /// — including the empty key, which the historical code path silently
    /// turned into an empty signature string.
        #[test]
        fn hmac_deterministic_and_full_length(
            key in prop::collection::vec(any::<u8>(), 0..128),
            msg in prop::collection::vec(any::<u8>(), 0..1024),
        ) {
            let sig1 = create_hmac_signature(&key, &msg);
            let sig2 = create_hmac_signature(&key, &msg);
            prop_assert_eq!(sig1.len(), 64, "hex HMAC-SHA256 is 64 chars");
            prop_assert_eq!(sig1, sig2, "HMAC must be deterministic");

            let b64_1 = create_hmac_signature_base64(&key, &msg);
            let b64_2 = create_hmac_signature_base64(&key, &msg);
            prop_assert_eq!(b64_1.len(), 44, "base64 HMAC-SHA256 is 44 chars");
            prop_assert_eq!(b64_1, b64_2, "base64 HMAC must be deterministic");
        }

    /// Property (MAC tamper detection): flipping ANY single bit of the
    /// message must change the signature. A verifier comparing with the
    /// production timing-safe comparator must reject every such forgery.
    /// (A 256-bit MAC colliding on a one-bit flip has probability ~2^-256
    /// — a failure here is a broken MAC, not bad luck.)
        #[test]
        fn hmac_detects_single_bit_flips(
            key in prop::collection::vec(any::<u8>(), 1..64),
            msg in prop::collection::vec(any::<u8>(), 1..512),
            bit_index in 0usize..4096,
        ) {
            let sig = create_hmac_signature(&key, &msg);

            let mut tampered = msg.clone();
            let idx = bit_index % (tampered.len() * 8);
            tampered[idx / 8] ^= 1u8 << (idx % 8);

            let forged = create_hmac_signature(&key, &tampered);
            prop_assert_ne!(
                &sig, &forged,
                "a one-bit message flip must produce a different MAC"
            );
            prop_assert!(
                !timing_safe_compare(&sig, &forged),
                "the timing-safe verifier must reject the forged signature"
            );
        }

    /// Property: the timing-safe comparator is a proper equality oracle —
    /// true iff the strings are byte-identical, so webhook signature
    /// verification cannot be talked past by prefix matches.
        #[test]
        fn timing_safe_compare_is_equality(
            a in "[a-zA-Z0-9._~/=+]{1,64}",
            flip in 0usize..64,
        ) {
            prop_assert!(
                timing_safe_compare(&a, &a),
                "identical strings must compare equal: {a:?}"
            );
            prop_assert!(timing_safe_compare("", ""), "empty == empty");
            prop_assert!(
                !timing_safe_compare(&a, ""),
                "a non-empty string never equals the empty string"
            );

            // Flip one ASCII character — the comparator must differ.
            let mut b = a.clone();
            let pos = flip % b.len();
            let original = b.as_bytes()[pos];
            b.replace_range(pos..pos + 1, if original == b'x' { "y" } else { "x" });
            prop_assert!(
                !timing_safe_compare(&a, &b),
                "a modified string must not compare equal\n a={a:?}\n b={b:?}"
            );
        }

    /// Property: SHA-256 API-key hashing is deterministic, full-length hex,
    /// and injective enough that distinct keys produce distinct hashes.
        #[test]
        fn api_key_hash_deterministic_and_distinct(
            key1 in "[a-zA-Z0-9_]{8,64}",
            key2 in "[a-zA-Z0-9_]{8,64}",
        ) {
            let h1a = hash_api_key(&key1);
            let h1b = hash_api_key(&key1);
            prop_assert_eq!(&h1a, &h1b, "hash must be deterministic");
            prop_assert_eq!(h1a.len(), 64, "SHA-256 hex is 64 chars");
            prop_assert!(
                h1a.chars().all(|c| c.is_ascii_hexdigit()),
                "hash must be lowercase-free hex"
            );

            if key1 != key2 {
                prop_assert_ne!(
                    h1a,
                    hash_api_key(&key2),
                    "distinct keys produced colliding hashes (SHA-256 broken?)"
                );
            }
        }
    }
}

// ===========================================================================
// 4. AEAD — real apexmail_lib::secret_at_rest (AES-256-GCM)
// ===========================================================================

mod aead_properties {
    use super::*;
    use std::sync::{Mutex, OnceLock};

    /// The at-rest key cache is process-global; serialize the property and
    /// pin the key through the same env var production reads. (CI runs
    /// nextest — one process per test — so this cannot race other tests.)
    fn test_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    fn pin_key() {
        std::env::set_var(
            "MFA_SECRET_ENCRYPTION_KEY",
            "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
        );
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]

    /// Property: encrypt→decrypt is the identity for ANY plaintext + AAD
    /// scope, and the envelope is detected as encrypted.
        #[test]
        fn encrypt_decrypt_round_trip(
            plaintext in "[ -~]{0,512}",
            aad in prop::collection::vec(any::<u8>(), 0..64),
        ) {
            let _guard = test_lock().lock().unwrap_or_else(|e| e.into_inner());
            pin_key();

            let envelope = apexmail_lib::secret_at_rest::encrypt_at_rest(&plaintext, &aad)
                .expect("pinned 32-byte hex key must encrypt");
            prop_assert!(
                apexmail_lib::secret_at_rest::is_encrypted(&envelope),
                "envelope must carry the enc:v1: prefix: {envelope}"
            );

            let recovered = apexmail_lib::secret_at_rest::decrypt_at_rest(&envelope, &aad)
                .expect("round trip with the same AAD must decrypt");
            prop_assert_eq!(recovered, plaintext, "decryption must recover the plaintext");
        }

    /// Property (AEAD tamper detection): flipping any byte of the envelope
    /// must fail the decryption closed with a TYPED error — never garbage
    /// output, never a panic.
        #[test]
        fn envelope_tamper_fails_closed(
            plaintext in "[ -~]{8,256}",
            aad in prop::collection::vec(any::<u8>(), 0..32),
            byte_index in 0usize..4096,
        ) {
            use base64::Engine as _;
            let _guard = test_lock().lock().unwrap_or_else(|e| e.into_inner());
            pin_key();

            let envelope = apexmail_lib::secret_at_rest::encrypt_at_rest(&plaintext, &aad)
                .expect("encryption with the pinned key");
            let b64 = envelope
                .strip_prefix("enc:v1:")
                .expect("is_encrypted shape checked by the round-trip property");

            let mut bytes = base64::engine::general_purpose::STANDARD
                .decode(b64)
                .expect("our own envelope must be valid base64");
            let idx = byte_index % bytes.len();
            bytes[idx] ^= 0x01;
            let tampered = format!("enc:v1:{}", base64::engine::general_purpose::STANDARD.encode(&bytes));

            let err = apexmail_lib::secret_at_rest::decrypt_at_rest(&tampered, &aad)
                .expect_err("a tampered envelope must NOT decrypt");
            // Every failure shape is TYPED and fail-closed: a flipped
            // version byte is InvalidEnvelope, a mangled payload/tag is
            // DecryptionFailed, corrupted base64 is Base64 — never silent
            // garbage output, never a panic.
            prop_assert!(
                matches!(
                    err,
                    apexmail_lib::secret_at_rest::SecretEncryptionError::DecryptionFailed
                        | apexmail_lib::secret_at_rest::SecretEncryptionError::Base64(_)
                        | apexmail_lib::secret_at_rest::SecretEncryptionError::InvalidEnvelope(_)
                ),
                "tamper must fail with a typed error, got {err:?}"
            );
        }

    /// Property: an AAD scope mismatch must be rejected — a ciphertext
    /// cannot be relocated from one tenant/user scope to another.
        #[test]
        fn aad_mismatch_is_rejected(
            plaintext in "[ -~]{4,128}",
            aad_good in prop::collection::vec(any::<u8>(), 1..32),
            aad_bad in prop::collection::vec(any::<u8>(), 1..32),
        ) {
            let _guard = test_lock().lock().unwrap_or_else(|e| e.into_inner());
            pin_key();
            if aad_good == aad_bad {
                return Ok(());
            }

            let envelope = apexmail_lib::secret_at_rest::encrypt_at_rest(&plaintext, &aad_good)
                .expect("encryption with the pinned key");
            let err = apexmail_lib::secret_at_rest::decrypt_at_rest(&envelope, &aad_bad)
                .expect_err("a different AAD scope must not decrypt");
            prop_assert!(
                matches!(
                    err,
                    apexmail_lib::secret_at_rest::SecretEncryptionError::DecryptionFailed
                ),
                "AAD mismatch must be a typed decryption failure, got {err:?}"
            );
        }
    }
}

// ===========================================================================
// 5. INPUT VALIDATION — real apexmail_lib::validation
// ===========================================================================

mod validation_properties {
    use super::*;
    use apexmail_lib::validation::{
        has_null_bytes, is_valid_domain, is_valid_email, is_valid_uuid, sanitize_string,
    };

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(512))]

    /// Property: a syntactically well-formed address (RFC 5322 atom local
    /// part, single-label domain + alphabetic TLD) is ACCEPTED by the
    /// production validator. A validator that returned constant false
    /// fails this; the old local copy passing it proved nothing.
    /// The dot-free local-part alphabet sidesteps the validator's
    /// consecutive-dot rule so the property stays about STRUCTURE.
        #[test]
        fn valid_email_structure(
            local in "[a-z0-9]([a-z0-9_%+-]{0,18}[a-z0-9])?",
            domain in "[a-z0-9]([a-z0-9-]{0,10}[a-z0-9])?",
            tld in "[a-z]{2,6}",
        ) {
            let email = format!("{}@{}.{}", local, domain, tld);
            prop_assert!(
                is_valid_email(&email),
                "'{email}' must be valid (local={local}, domain={domain}, tld={tld})"
            );
        }

    /// Property: an address with NO unquoted '@' is rejected.
        #[test]
        fn missing_at_invalid(local in "[a-z]{1,20}", domain in "[a-z]{1,20}") {
            let invalid = format!("{}{}", local, domain);
            prop_assert!(!is_valid_email(&invalid), "'{invalid}' has no @ — must be invalid");
        }

    /// Property: two unquoted '@'s make the address invalid (the first @
    /// splits, and a domain may not contain '@').
        #[test]
        fn multiple_at_invalid(p1 in "[a-z]{1,10}", p2 in "[a-z]{1,10}", p3 in "[a-z]{1,10}") {
            let invalid = format!("{}@{}@{}", p1, p2, p3);
            prop_assert!(!is_valid_email(&invalid), "'{invalid}' has two @ — must be invalid");
        }

    /// Property: the RFC 5321 length cap (254) is enforced by the real
    /// validator — well-formed 63-char labels stack the address across the
    /// boundary and acceptance flips to rejection exactly there.
        #[test]
        fn length_cap_enforced(labels in 1usize..4) {
            // local ≤ 64 octets (the validator's own cap), every label a
            // legal 63-char atom: only TOTAL length changes with `labels`.
            // email length = 64·labels + 68 → crosses the 254 cap at 3.
            let local = "a".repeat(64);
            let label = "b".repeat(63);
            let domain = (0..labels)
                .map(|_| label.as_str())
                .collect::<Vec<_>>()
                .join(".")
                + ".com";
            let email = format!("{}@{}", local, domain);
            if email.len() <= 254 {
                prop_assert!(
                    is_valid_email(&email),
                    "'{email}' (len {}) is within the 254 cap — must be valid",
                    email.len()
                );
            } else {
                prop_assert!(
                    !is_valid_email(&email),
                    "'{email}' (len {}) exceeds the 254 cap — must be invalid",
                    email.len()
                );
            }
        }

    /// Property: control characters in an unquoted local part are rejected
    /// — header injection via email fields must never validate.
        #[test]
        fn control_chars_rejected(
            prefix in "[a-z]{1,8}",
            suffix in "[a-z]{1,8}",
            ctrl in 1u8..0x20,
        ) {
            let with_nul = format!("{}\u{0}{}", prefix, suffix);
            prop_assert!(!is_valid_email(&with_nul), "NUL in local part must be rejected");

            let with_ctrl = format!("{}{}{}", prefix, ctrl as char, suffix);
            prop_assert!(
                !is_valid_email(&with_ctrl),
                "control char 0x{:02x} in local part must be rejected: {with_ctrl:?}",
                ctrl
            );
        }

    /// Property: null-byte detection never misses a NUL and never fires on
    /// NUL-free input.
        #[test]
        fn null_byte_detection_is_exact(
            prefix in "[ -~]{0,40}",
            suffix in "[ -~]{0,40}",
        ) {
            let with_null = format!("{}\0{}", prefix, suffix);
            prop_assert!(has_null_bytes(&with_null), "NUL must be detected: {with_null:?}");
            prop_assert!(!has_null_bytes(&prefix), "clean prefix must not trigger");
        }

    /// Property: sanitize removes every NUL (and the literal \\u0000 text)
    /// — the production counterpart of detection, used before storage.
        #[test]
        fn sanitize_removes_nulls(
            input in prop::collection::vec(
                prop::char::range('\u{0}', '\u{7e}'),
                0..80,
            )
            .prop_map(|chars| chars.into_iter().collect::<String>()),
        ) {
            let sanitized = sanitize_string(&input);
            prop_assert!(
                !has_null_bytes(&sanitized),
                "sanitized output still contains NUL: {sanitized:?}"
            );
            prop_assert!(!sanitized.contains("\\u0000"), "literal escape must be removed too");
            if !input.contains('\0') && !input.contains("\\u0000") {
                prop_assert_eq!(sanitized, input, "clean input must pass through unchanged");
            }
        }

    /// Property: UUID validation accepts exactly the canonical 36-char hex
    /// form and rejects single-character corruptions.
        #[test]
        fn uuid_validation_is_canonical(corrupt in 0usize..36, hex_char in "[g-zG-Z]") {
            let valid = "550e8400-e29b-41d4-a716-446655440000";
            prop_assert!(is_valid_uuid(valid), "canonical UUID must be valid");

            let mut broken = valid.to_string();
            broken.replace_range(corrupt..corrupt + 1, &hex_char);
            prop_assert!(
                !is_valid_uuid(&broken),
                "corrupted UUID must be invalid: {broken}"
            );
        }

    /// Property: domain validation rejects missing TLDs and leading
    /// hyphens/dots, accepts well-formed names.
        #[test]
        fn domain_validation(label in "[a-z0-9]([a-z0-9-]{0,10}[a-z0-9])?", tld in "[a-z]{2,6}") {
            prop_assert!(is_valid_domain(&format!("{}.{}", label, tld)), "'{}.{}' must be valid", label, tld);
            prop_assert!(!is_valid_domain(&label), "a bare label without TLD must be invalid");
            prop_assert!(!is_valid_domain(&format!("-{}.{}", label, tld)), "leading hyphen must be invalid");
            prop_assert!(!is_valid_domain(&format!(".{}.{}", label, tld)), "leading dot must be invalid");
        }
    }
}
