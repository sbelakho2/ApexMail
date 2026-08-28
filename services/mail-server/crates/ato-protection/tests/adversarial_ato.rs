//! Adversarial ATO (Account Takeover) protection tests.
//!
//! Designed to catch regressions in://! - TLS fingerprint risk integration (P1 — was never wired into evaluate)
//! - FIFO eviction of UserTlsHistory (was non-deterministic HashSet-based)
//! - Impossible travel detection
//! - Failed-attempt lockout

use ato_protection::engine::{AtoAction, AtoEngine};
use ato_protection::session::LoginEvent;
use ato_protection::tls_fingerprint::TlsFingerprint;
use chrono::Utc;

fn make_event(user: &str, ip: &str, lat: f64, lon: f64) -> LoginEvent {
    LoginEvent {
        user_id: user.into(),
        ip_address: ip.into(),
        user_agent: "Mozilla/5.0 (Test)".into(),
        latitude: Some(lat),
        longitude: Some(lon),
        timestamp: Utc::now(),
        success: true,
        tls_fingerprint: None,
        device_fingerprint: None,
    }
}

// ── TLS Fingerprint integration (P1 regression) ──────────────────────────────

/// Bot-like TLS fingerprint (old TLS, few ciphers) must raise risk score.
/// Regression:before fix, TlsFingerprintTracker was never called in evaluate.
#[test]
fn test_bot_tls_fingerprint_raises_risk_regression() {
    let engine = AtoEngine::new();
    let bot_fp = TlsFingerprint::from_client_hello(
        0x0301,            // TLS 1.0
        &[0x002f, 0x0035], // 2 ciphers only
        &[0x0000],         // 1 extension
        &[],
        &[],
    );
    let mut event = make_event("alice", "1.2.3.4", 40.71, -74.01);
    event.tls_fingerprint = Some(bot_fp);

    let verdict = engine.evaluate(&event);
    assert!(
        verdict.risk_score > 0.0,
        "Bot-like TLS fingerprint must contribute to risk. Got {}",
        verdict.risk_score
    );
    assert!(
        verdict.factors.iter().any(|f| f.id == "TLS_FINGERPRINT"),
        "TLS_FINGERPRINT factor must appear. Factors: {:?}",
        verdict.factors.iter().map(|f| f.id).collect::<Vec<_>>()
    );
}

/// Switching from modern browser TLS to bot TLS is high risk.
#[test]
fn test_tls_stack_switch_modern_to_bot_high_risk() {
    let engine = AtoEngine::new();

    // Login 1:modern TLS stack
    let modern_fp = TlsFingerprint::from_client_hello(
        0x0304, // TLS 1.3
        &[
            0x1301, 0x1302, 0x1303, 0xc02b, 0xc02c, 0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035,
        ],
        &[
            0x0000, 0x0005, 0x000a, 0x000b, 0x000d, 0x0023, 0x0010, 0x0017,
        ],
        &[0x0403, 0x0503, 0x0603],
        &["h2", "http/1.1"],
    );
    let mut ev1 = make_event("bob", "5.5.5.1", 51.51, -0.13);
    ev1.tls_fingerprint = Some(modern_fp);
    engine.evaluate(&ev1);

    // Login 2:bot TLS stack (attacker replay with different TLS library)
    let bot_fp = TlsFingerprint::from_client_hello(0x0301, &[0x002f, 0x0035], &[0x0000], &[], &[]);
    let mut ev2 = make_event("bob", "5.5.5.1", 51.51, -0.13);
    ev2.tls_fingerprint = Some(bot_fp);
    let verdict = engine.evaluate(&ev2);

    assert!(
        verdict.risk_score > 2.0,
        "Modern→bot TLS switch must produce high risk, got {}",
        verdict.risk_score
    );
}

/// Second login with the SAME TLS fingerprint must NOT add extra risk.
#[test]
fn test_known_tls_fingerprint_zero_added_risk() {
    let engine = AtoEngine::new();
    // Use a non-bot fingerprint:t12 with >= 5 ciphers and >= 3 extensions
    // so that looks_like_bot returns false and the second (known) login adds 0 risk.
    let fp = TlsFingerprint::from_client_hello(
        0x0303, // TLS 1.2
        &[
            0x1301, 0x1302, 0xc02b, 0xc02c, 0xc02f, 0xc030, 0x002f, 0x0035,
        ], // 8 ciphers
        &[0x0000, 0xff01, 0x000a, 0x000b, 0x0023], // 5 extensions (SNI + others)
        &[0x0401],
        &["h2"],
    );
    assert!(
        !fp.looks_like_bot(),
        "test fingerprint must not look like a bot"
    );

    let mut ev1 = make_event("carol", "6.6.6.6", 48.86, 2.35);
    ev1.tls_fingerprint = Some(fp.clone());
    engine.evaluate(&ev1); // establishes baseline

    let mut ev2 = make_event("carol", "6.6.6.6", 48.86, 2.35);
    ev2.tls_fingerprint = Some(fp.clone());
    let verdict = engine.evaluate(&ev2);

    let tls_risk: f64 = verdict
        .factors
        .iter()
        .filter(|f| f.id == "TLS_FINGERPRINT")
        .map(|f| f.risk)
        .sum();
    assert_eq!(
        tls_risk, 0.0,
        "Known non-bot fingerprint must not add risk, got {}",
        tls_risk
    );
}

// ── FIFO eviction (P1 non-determinism fix) ────────────────────────────────────

/// FIFO eviction:oldest fingerprint is always evicted first (not random).
/// Regression:old code used HashSet::iter.next which is not insertion-ordered.
#[test]
fn test_tls_history_fifo_eviction_deterministic() {
    use ato_protection::tls_fingerprint::UserTlsHistory;

    let mut history = UserTlsHistory::new(3);

    let fps: Vec<TlsFingerprint> = (0..5)
        .map(|i| TlsFingerprint::from_ja4_string(&format!("fp_unique_{}", i)))
        .collect();

    // Fill to capacity:fp[0], fp[1], fp[2]
    assert!(history.record(&fps[0]));
    assert!(history.record(&fps[1]));
    assert!(history.record(&fps[2]));
    assert_eq!(history.len(), 3);

    // 4th entry → should evict fp[0] (oldest)
    history.record(&fps[3]);
    assert!(
        !history.is_known(&fps[0]),
        "FIFO: fp[0] must be evicted first"
    );
    assert!(history.is_known(&fps[1]));
    assert!(history.is_known(&fps[2]));
    assert!(history.is_known(&fps[3]));
    assert_eq!(history.len(), 3);

    // 5th entry → should evict fp[1] (second oldest)
    history.record(&fps[4]);
    assert!(
        !history.is_known(&fps[1]),
        "FIFO: fp[1] must be evicted second"
    );
    assert!(history.is_known(&fps[2]));
    assert!(history.is_known(&fps[3]));
    assert!(history.is_known(&fps[4]));
    assert_eq!(history.len(), 3);
}

/// Recording a DUPLICATE fingerprint must NOT increase history size.
#[test]
fn test_tls_history_duplicate_not_double_counted() {
    use ato_protection::tls_fingerprint::UserTlsHistory;

    let mut history = UserTlsHistory::new(5);
    let fp = TlsFingerprint::from_ja4_string("t13_same_fp");

    assert!(
        history.record(&fp),
        "First record() must return is_new=true"
    );
    assert!(
        !history.record(&fp),
        "Second record() of same fp must return is_new=false"
    );
    assert_eq!(history.len(), 1, "Duplicate must not increase size");
}

// ── Impossible travel ─────────────────────────────────────────────────────────

#[test]
fn test_impossible_travel_nyc_to_tokyo() {
    let engine = AtoEngine::new();
    // NYC one hour before Tokyo — genuinely impossible (~10,850 km/h).
    // A same-second Tokyo login is clock-skew/PoP jitter and is
    // deliberately skipped by the geo tolerance rules.
    let mut nyc = make_event("dave", "1.1.1.1", 40.71, -74.01);
    nyc.timestamp = Utc::now() - chrono::Duration::hours(1);
    engine.evaluate(&nyc);
    let verdict = engine.evaluate(&make_event("dave", "2.2.2.2", 35.68, 139.69)); // Tokyo
    assert!(
        verdict.impossible_travel,
        "NYC → Tokyo must be impossible travel"
    );
    assert!(
        verdict.risk_score >= 5.0,
        "Impossible travel must have high risk, got {}",
        verdict.risk_score
    );
}

#[test]
fn test_nearby_logins_are_not_impossible() {
    let engine = AtoEngine::new();
    // NYC to Newark (same metro area, ~15km apart).
    // Set ev2 timestamp 30 minutes later — easily drivable at 30 km/h.
    // Without an elapsed-time gap, speed = ∞ and even 1m travel looks impossible.
    let mut ev1 = make_event("frank", "1.1.1.1", 40.7128, -74.0059); // NYC
    ev1.timestamp = Utc::now() - chrono::Duration::minutes(30);
    engine.evaluate(&ev1);

    let ev2 = make_event("frank", "1.1.1.2", 40.7357, -74.1724); // Newark, 30 min later
    let verdict = engine.evaluate(&ev2);
    assert!(
        !verdict.impossible_travel,
        "Nearby city travel (15 km / 30 min) must NOT be impossible"
    );
}

// ── Failed-attempt lockout ─────────────────────────────────────────────────────

#[test]
fn test_lockout_after_five_failures() {
    let engine = AtoEngine::new();
    for _ in 0..6 {
        let mut e = make_event("grace", "9.9.9.9", 0.0, 0.0);
        e.success = false;
        engine.evaluate(&e);
    }
    let verdict = engine.evaluate(&make_event("grace", "9.9.9.9", 0.0, 0.0));
    // The lockout now fires ON the threshold-crossing attempt, so this
    // sequence escalates to RequireCaptcha (stronger than Block).
    assert!(
        matches!(verdict.action, AtoAction::Block | AtoAction::RequireCaptcha),
        "Must be locked out after 6 failures, got {:?} (risk={})",
        verdict.action,
        verdict.risk_score
    );
}

#[test]
fn test_single_failure_not_blocked() {
    let engine = AtoEngine::new();
    let mut e = make_event("henry", "7.7.7.7", 0.0, 0.0);
    e.success = false;
    engine.evaluate(&e);

    let verdict = engine.evaluate(&make_event("henry", "7.7.7.7", 0.0, 0.0));
    assert_ne!(
        verdict.action,
        AtoAction::Block,
        "Single failure must NOT block"
    );
}
