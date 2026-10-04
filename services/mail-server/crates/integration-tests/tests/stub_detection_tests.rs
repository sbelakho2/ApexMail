//! # Stub and Bug Detection Tests (audit SM12 F1 rewrite)
//!
//! The original suite verified toy reimplementations defined inside this file
//! (a hand-rolled rate limiter, an XOR "cipher", a stdlib `AtomicU64`) — the
//! file whose job was catching stubs was itself the largest stub in the repo.
//!
//! Every test below now exercises REAL workspace production code:
//! - `apexmail_rate_limiter` — `SlidingWindowCounter` window semantics
//! - `worker_processors::common::CircuitBreaker` — trip / half-open race / close
//! - `apexmail_lib::crypto` — HMAC-SHA256 + Argon2id + hash-version detection
//! - `apexmail_lib::validation` — RFC 5322 email / domain / null-byte guards
//! - `apexmail_rate_limiter::RedisLimiter` — the bounded-connect timeout path
//!
//! Modules from the old file with NO hermetic production counterpart (the
//! toy `HealthChecker`, `AuditLog`, `GracefulShutdown`, and the literal-vs-
//! literal "security header" strings) were deleted: the real surfaces they
//! gestured at are covered by the owning crates (api-server in-crate header
//! tests, observability wiring tests, schema-contract suites).

use std::sync::Arc;
use std::time::{Duration, Instant};

// ===========================================================================
// 1. RATE LIMITING — real SlidingWindowCounter window semantics
// ===========================================================================

/// The rate limiter must actually admit up to the limit, deny beyond it,
/// age old events out on window rollover, and keep `peek` non-mutating.
/// A stubbed/holed counter fails every assertion here.
#[cfg(test)]
mod rate_limiter_real_tests {
    use super::*;
    use apexmail_rate_limiter::SlidingWindowCounter;

    #[test]
    fn sliding_window_admits_to_limit_then_denies_with_retry_after() {
        let counter = SlidingWindowCounter::from_params(Duration::from_secs(60), 5);

        for i in 1..=5 {
            let decision = counter.check_and_increment();
            assert!(
                decision.is_allowed(),
                "request {i} within the limit must be allowed"
            );
        }

        let sixth = counter.check_and_increment();
        assert!(
            sixth.is_denied(),
            "request 6 over the limit MUST be denied — a pass-through limiter is a stub"
        );
        let retry_after = sixth
            .retry_after()
            .expect("a denied decision must carry retry_after");
        assert!(
            retry_after > Duration::ZERO,
            "retry_after must be positive, got {retry_after:?}"
        );
    }

    #[test]
    fn sliding_window_rolls_over_and_readmits_after_events_age_out() {
        let window = Duration::from_millis(80);
        let counter = SlidingWindowCounter::from_params(window, 2);

        assert!(counter.check_and_increment().is_allowed());
        assert!(counter.check_and_increment().is_allowed());
        assert!(
            counter.check_and_increment().is_denied(),
            "exhausted window must deny"
        );

        // Idle past 2 full windows: `maybe_rotate` must fully reset —
        // a counter that never expires events (a stub) stays denied forever.
        std::thread::sleep(window * 2 + Duration::from_millis(30));
        assert!(
            counter.check_and_increment().is_allowed(),
            "after 2 idle windows the budget must fully reset (window rollover)"
        );
    }

    #[test]
    fn sliding_window_peek_does_not_consume_budget() {
        let counter = SlidingWindowCounter::from_params(Duration::from_secs(60), 2);
        assert!(counter.check_and_increment().is_allowed());

        let before = counter.current_count();
        for _ in 0..10 {
            let peeked = counter.peek();
            assert!(
                peeked.is_allowed(),
                "one admitted event must leave headroom"
            );
        }
        assert_eq!(
            counter.current_count(),
            before,
            "peek must be read-only — a peek that consumes budget over-throttles"
        );
        // And the reserved budget is still spendable after all the peeks.
        assert!(
            counter.check_and_increment().is_allowed(),
            "budget consumed by peek is a lost update"
        );
    }

    #[test]
    fn sliding_window_count_tracks_admitted_events_only() {
        let counter = SlidingWindowCounter::from_params(Duration::from_secs(60), 3);
        for _ in 0..3 {
            counter.check_and_increment();
        }
        counter.check_and_increment(); // denied — must NOT be counted
        assert_eq!(
            counter.current_count(),
            3,
            "denied requests must not inflate the window count"
        );
        assert_eq!(counter.limit(), 3, "limit() must echo the configuration");
    }
}

// ===========================================================================
// 2. RATE LIMITING UNDER CONTENTION — no lost updates on real shared state
// ===========================================================================

/// The old `concurrency_bug_tests` module verified stdlib `AtomicU64` —
/// i.e. the standard library. This replaces it with the real question: does
/// the PRODUCTION counter lose updates under thread contention?
#[cfg(test)]
mod rate_limiter_contention_tests {
    use super::*;
    use apexmail_rate_limiter::SlidingWindowCounter;

    #[test]
    fn concurrent_admissions_never_exceed_the_limit() {
        // A 60 s window cannot rotate during the burst, so the admission
        // count is deterministic: exactly `limit` of 1_000 racing attempts.
        let counter = Arc::new(SlidingWindowCounter::from_params(
            Duration::from_secs(60),
            50,
        ));

        let handles: Vec<_> = (0..10)
            .map(|_| {
                let c = Arc::clone(&counter);
                std::thread::spawn(move || {
                    let mut allowed = 0u32;
                    for _ in 0..100 {
                        if c.check_and_increment().is_allowed() {
                            allowed += 1;
                        }
                    }
                    allowed
                })
            })
            .collect();

        let total_allowed: u32 = handles.into_iter().map(|h| h.join().unwrap()).sum();
        assert_eq!(
            total_allowed, 50,
            "contention must admit EXACTLY the limit — fewer is a lost update, more is over-admission"
        );
        assert_eq!(
            counter.current_count(),
            50,
            "the window count must reflect exactly the admitted events"
        );
    }
}

// ===========================================================================
// 3. CIRCUIT BREAKER — real trip / half-open race / close state machine
// ===========================================================================

/// `worker_processors::common::CircuitBreaker` must open at the threshold,
/// block while open, admit probes through half-open after `open_duration`,
/// close after `success_threshold` half-open successes, and RE-OPEN on any
/// half-open failure. Includes the half-open RACE: many threads probing the
/// breaker at the same instant must all be admitted without tearing state.
#[cfg(test)]
mod circuit_breaker_real_tests {
    use super::*;
    use worker_processors::common::{CircuitBreaker, CircuitBreakerConfig, CircuitState};

    fn breaker(open_ms: u64, success_threshold: u32) -> CircuitBreaker {
        CircuitBreaker::new(CircuitBreakerConfig {
            failure_threshold: 1,
            open_duration: Duration::from_millis(open_ms),
            success_threshold,
            window_duration: Duration::from_secs(60),
        })
    }

    #[test]
    fn circuit_opens_at_threshold_and_blocks_every_probe_while_open() {
        let cb = breaker(60_000, 3);
        assert_eq!(cb.state(), CircuitState::Closed);
        assert!(cb.is_allowed(), "must start closed");

        cb.record_failure();
        assert_eq!(cb.state(), CircuitState::Open, "threshold=1 must trip");
        for _ in 0..10 {
            assert!(
                !cb.is_allowed(),
                "an OPEN circuit must block ALL requests — a breaker that never blocks is a stub"
            );
        }
    }

    #[test]
    fn circuit_closes_after_half_open_successes() {
        let cb = breaker(20, 2);
        cb.record_failure();
        assert_eq!(cb.state(), CircuitState::Open);

        std::thread::sleep(Duration::from_millis(35));
        assert!(
            cb.is_allowed(),
            "probe after open_duration must be admitted"
        );
        assert_eq!(cb.state(), CircuitState::HalfOpen);

        cb.record_success();
        assert_eq!(
            cb.state(),
            CircuitState::HalfOpen,
            "one success is not enough"
        );
        cb.record_success();
        assert_eq!(
            cb.state(),
            CircuitState::Closed,
            "success_threshold half-open successes must close the circuit"
        );
        assert!(cb.is_allowed());
    }

    #[test]
    fn half_open_failure_reopens_immediately() {
        let cb = breaker(20, 3);
        cb.record_failure();
        std::thread::sleep(Duration::from_millis(35));
        assert!(cb.is_allowed(), "probe admitted into half-open");
        assert_eq!(cb.state(), CircuitState::HalfOpen);

        cb.record_failure();
        assert_eq!(
            cb.state(),
            CircuitState::Open,
            "half-open failure must re-open"
        );
        assert!(
            !cb.is_allowed(),
            "a re-opened circuit blocks again for a full open_duration"
        );
    }

    /// The RACE: 8 threads hit `is_allowed` at the exact moment the open
    /// window expires. Every probe must be admitted (half-open is permissive)
    /// and the state machine must land in HalfOpen without denying any racer —
    /// a broken transition (e.g. read-Open/deny while another thread rotates)
    /// shows up as a denied racer.
    #[test]
    fn half_open_transition_is_race_safe_for_concurrent_probes() {
        let cb = Arc::new(breaker(40, 8));
        cb.record_failure();
        assert_eq!(cb.state(), CircuitState::Open);
        std::thread::sleep(Duration::from_millis(55));

        let handles: Vec<_> = (0..8)
            .map(|_| {
                let b = Arc::clone(&cb);
                std::thread::spawn(move || b.is_allowed())
            })
            .collect();
        let admissions: Vec<bool> = handles.into_iter().map(|h| h.join().unwrap()).collect();

        assert!(
            admissions.iter().all(|allowed| *allowed),
            "every probe after the open window must be admitted, got {admissions:?}"
        );
        let state = cb.state();
        assert!(
            state == CircuitState::HalfOpen || state == CircuitState::Closed,
            "post-race state must be HalfOpen or Closed, never torn back to blocking Open: {state:?}"
        );

        // Drain the success threshold: the breaker must close cleanly.
        for _ in 0..8 {
            cb.record_success();
        }
        assert_eq!(cb.state(), CircuitState::Closed);
        assert!(cb.is_allowed());
    }
}

// ===========================================================================
// 4. CRYPTO — real HMAC-SHA256 / Argon2id round-trips (apexmail_lib::crypto)
// ===========================================================================

/// The old module "encrypted" with XOR and compared the result to itself.
/// These tests pin the REAL cryptographic contracts: deterministic HMAC,
/// key sensitivity, Argon2id verify round-trips, hash-version detection and
/// constant-time comparison semantics.
#[cfg(test)]
mod crypto_real_tests {
    use apexmail_lib::crypto::{
        create_hmac_signature, detect_api_key_hash_version, hash_api_key, hash_api_key_argon2,
        hash_api_key_with_secret, timing_safe_compare, verify_api_key_hash, ApiKeyHashVersion,
    };

    #[test]
    fn hmac_signature_is_deterministic_key_sensitive_and_differs_from_plaintext() {
        let key = b"webhook-signing-secret";
        let data = b"secret api key payload";

        let sig = create_hmac_signature(key, data);
        assert_ne!(
            sig.as_bytes(),
            data,
            "an HMAC that equals its input is not a signature"
        );
        assert_eq!(
            sig,
            create_hmac_signature(key, data),
            "HMAC must be deterministic for verification to work"
        );
        assert_ne!(
            sig,
            create_hmac_signature(b"a-different-secret", data),
            "a different key MUST produce a different signature"
        );
        assert_ne!(
            sig,
            create_hmac_signature(key, b"tampered payload"),
            "a tampered payload MUST produce a different signature"
        );
        // The documented relationship: hash_api_key_with_secret is
        // HMAC(secret, key-as-data) — the credential path and the webhook
        // path share one primitive.
        assert_eq!(
            hash_api_key_with_secret("am_live_key", "server-secret"),
            create_hmac_signature(b"server-secret", b"am_live_key"),
            "hash_api_key_with_secret must stay HMAC(server_secret, key)"
        );
    }

    #[test]
    fn argon2_api_key_hash_round_trips_and_rejects_wrong_keys() {
        let key = "am_test_key_roundtrip_123";
        let hash = hash_api_key_argon2(key).expect("argon2 hash");

        assert!(
            hash.starts_with("$argon2id$"),
            "the stored hash must be a self-describing argon2id PHC string"
        );
        assert_ne!(
            hash,
            hash_api_key_argon2(key).expect("second hash"),
            "each hash must carry a fresh random salt"
        );
        assert!(
            verify_api_key_hash(key, &hash).expect("verify runs"),
            "the right key must verify"
        );
        assert!(
            !verify_api_key_hash("am_wrong_key", &hash).expect("verify runs"),
            "a wrong key must NOT verify"
        );
        // A tampered PHC body must not verify as true either.
        let tampered = format!("{}X", &hash[..hash.len() - 1]);
        assert!(
            !verify_api_key_hash(key, &tampered).unwrap_or(false),
            "a corrupted hash must never verify"
        );
    }

    #[test]
    fn hash_version_detection_classifies_each_scheme() {
        assert_eq!(
            detect_api_key_hash_version(&hash_api_key_argon2("k").expect("hash")),
            ApiKeyHashVersion::Argon2id
        );
        assert_eq!(
            detect_api_key_hash_version(&hash_api_key_with_secret("k", "s")),
            ApiKeyHashVersion::HmacSha256,
            "64-hex digests classify as the actively-written HMAC scheme"
        );
        assert_eq!(
            detect_api_key_hash_version(&hash_api_key("k")),
            ApiKeyHashVersion::HmacSha256,
            "plain SHA-256 shares the 64-hex shape (documented heuristic)"
        );
        assert_eq!(
            detect_api_key_hash_version("not-a-hash"),
            ApiKeyHashVersion::Unknown
        );
    }

    #[test]
    fn timing_safe_compare_accepts_only_exact_matches() {
        assert!(timing_safe_compare("same", "same"));
        assert!(!timing_safe_compare("same", "same "));
        assert!(
            !timing_safe_compare("same", "sane"),
            "one byte must flip it"
        );
        assert!(!timing_safe_compare("short", "shorter-than-short"));
        assert!(!timing_safe_compare("", "nonempty"));
    }
}

// ===========================================================================
// 5. INPUT VALIDATION — real apexmail_lib::validation guards
// ===========================================================================

/// The old module validated a hand-written `contains('@')` predicate. These
/// tests exercise the production RFC 5322 validator, including the CRLF/NUL
/// header-injection refusals.
#[cfg(test)]
mod validation_real_tests {
    use apexmail_lib::validation::{
        has_null_bytes, is_valid_domain, is_valid_email, sanitize_string,
    };

    #[test]
    fn email_validator_accepts_documented_valid_shapes() {
        for good in [
            "user@example.com",
            "first.last@sub.domain.co.uk",
            "user+tag@example.com",
            r#""quoted user"@example.com"#,
            "user@[192.168.1.1]",
            "test@müller.de",
        ] {
            assert!(
                is_valid_email(good),
                "{good} is a documented-valid address and must be accepted"
            );
        }
    }

    #[test]
    fn email_validator_rejects_injection_and_malformed_shapes() {
        for bad in [
            "",
            "no-at-sign",
            "@no-local.com",
            "missing@domain",
            ".leading-dot@example.com",
            "trailing-dot.@example.com",
            "double..dot@example.com",
            // Header-injection payloads: CR/LF must never survive validation.
            "\"x\nBcc: a@b.c\"@example.com",
            "x\nBcc: a@b.c@example.com",
            "\"a\0b\"@example.com",
        ] {
            assert!(
                !is_valid_email(bad),
                "{bad:?} must be REJECTED — accepting it is a security regression"
            );
        }
    }

    #[test]
    fn domain_validator_enforces_tld_and_label_rules() {
        assert!(is_valid_domain("example.com"));
        assert!(is_valid_domain("sub.example.co.uk"));
        assert!(!is_valid_domain("no-tld"));
        assert!(!is_valid_domain("-leading.com"));
        assert!(!is_valid_domain(""));
    }

    #[test]
    fn null_byte_detection_and_sanitization_round_trip() {
        assert!(has_null_bytes("hello\0world"));
        assert!(!has_null_bytes("normal string"));
        // The documented #235 semantics: the ESCAPE SEQUENCE is not a NUL.
        assert!(!has_null_bytes("literal \\u0000 text"));

        assert_eq!(sanitize_string("hello\0world"), "helloworld");
        assert_eq!(sanitize_string("clean"), "clean");
        assert!(
            !has_null_bytes(&sanitize_string("a\0b")),
            "sanitized output is NUL-free"
        );
    }
}

// ===========================================================================
// 6. TIMEOUT ENFORCEMENT — real bounded-connect behavior (RedisLimiter)
// ===========================================================================

/// The old module tested tokio's own `timeout` combinator. The real question:
/// does production code actually BOUND its network dependency? `RedisLimiter::
/// connect` documents a bounded 2 s attempt that must yield `None` (in-memory
/// fallback) instead of hanging or panicking when Redis is unreachable.
#[cfg(test)]
mod timeout_real_tests {
    use super::*;
    use apexmail_rate_limiter::{RateLimitConfig, RedisLimiter};

    #[tokio::test]
    async fn redis_connect_to_dead_port_is_bounded_and_falls_back() {
        let config = RateLimitConfig::new(10).with_burst(5);
        let start = Instant::now();

        let limiter = RedisLimiter::connect(&config, "redis://127.0.0.1:1").await;

        let elapsed = start.elapsed();
        assert!(
            limiter.is_none(),
            "an unreachable Redis must yield None (in-memory fallback), not a limiter"
        );
        assert!(
            elapsed < Duration::from_secs(5),
            "the connect attempt must be bounded, took {elapsed:?}"
        );
    }

    #[tokio::test]
    async fn fallback_limiter_still_enforces_after_failed_connect() {
        // The post-timeout surface: the keyed in-memory fallback enforces
        // limits even with no Redis behind it.
        let config = RateLimitConfig::new(10).with_burst(1);
        let limiter = RedisLimiter::fallback_only(&config);
        assert!(limiter.is_in_fallback());
        assert!(limiter.check().await.is_allowed());
        assert!(
            limiter.check().await.is_denied(),
            "the fallback must keep enforcing the limit, not fail open"
        );
    }
}
