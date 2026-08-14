//! Redis concurrency guarantees (real Redis, skipped unless RISK_REDIS_URL):
//! the canonical Lua script runs atomically, so concurrent observations with
//! unique event_ids never lose increments, concurrent duplicates increment
//! exactly once (duplicates are no-ops returning the current signals with
//! `is_duplicate`), TTL expiry is honored (no state resurrection), and the
//! global level hysteresis window holds.
//!
//! Every subtest uses its own fresh namespace (the store takes the
//! namespace in its constructor), so parallel subtests never share state.

mod common;

use std::sync::{Arc, Barrier};
use std::thread;
use std::time::Duration;

use kiwicaptcha_risk::action::RiskAction;
use kiwicaptcha_risk::event::RiskEventKind;
use kiwicaptcha_risk::policy::RiskPolicy;
use kiwicaptcha_risk::redis::{RedisRiskStateStore, DEFAULT_SATURATIONS};
use kiwicaptcha_risk::resources::ResourcePressure;
use kiwicaptcha_risk::score::{score as compute_score, RiskWeights};
use kiwicaptcha_risk::signals::SignalVector;
use kiwicaptcha_risk::store::{Observed, RiskStateStore, RiskStoreError};
use serde_json::json;

const HUNDRED: usize = 100;

fn client() -> redis::Client {
    redis::Client::open(common::redis_url().expect("RISK_REDIS_URL set")).expect("url parses")
}

/// Store with contract defaults on a fresh namespace.
fn store() -> RedisRiskStateStore {
    RedisRiskStateStore::new(client(), &common::unique_namespace("conc"))
        // Audit round 17: relaxed test timeouts (the 10 ms production
        // command timeout flaked the storm tests under CI load).
        .with_io_timeouts(2_000, 2_000)
}

/// Store with explicit knobs on a fresh namespace.
fn store_with(
    state_ttl_secs: u64,
    hysteresis_ms: u64,
    saturations: [u32; 11],
) -> RedisRiskStateStore {
    RedisRiskStateStore::with_options(
        client(),
        &common::unique_namespace("conc"),
        state_ttl_secs,
        60,
        hysteresis_ms,
        1800,
        86_400,
        kiwicaptcha_risk::redis::DEFAULT_OUTCOME_TTL_SECS,
        saturations,
    )
    .with_io_timeouts(2_000, 2_000) // audit round 17: CI-jitter-proof test timeouts
}

/// The Redis server clock in milliseconds (the store's rate-limit clock).
fn redis_now_ms() -> u64 {
    let mut conn = client().get_connection().expect("connection");
    let t: Vec<i64> = redis::cmd("TIME").query(&mut conn).expect("TIME");
    (t[0] * 1000 + t[1] / 1000) as u64
}

/// Audit round 17: wait until the REDIS CLOCK reaches `target_ms`,
/// polling it instead of wall-clock sleeping. A CI scheduling pause can
/// only make us wait LONGER — an observation is never pushed across a
/// timing boundary by assuming wall-clock sleep == Redis execution time.
/// Generous 30 s ceiling so a stalled server fails loudly, not hangingly.
fn wait_until_redis_ms(target_ms: u64) {
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    while redis_now_ms() < target_ms {
        if std::time::Instant::now() > deadline {
            panic!("Redis clock did not reach {target_ms} ms within 30 s");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// Runs `count` concurrent observations sharing the given pseudonyms and
/// event kind; returns every Result in thread order.
#[allow(clippy::too_many_arguments)]
fn storm(
    store: &RedisRiskStateStore,
    event: RiskEventKind,
    scope: u32,
    count: usize,
    source_id: String,
    subnet_id: String,
    event_id: fn(u64) -> String,
    now_ms: u64,
) -> Vec<Result<Observed, RiskStoreError>> {
    thread::scope(|s| {
        let handles: Vec<_> = (0..count)
            .map(|i| {
                let source_id = source_id.clone();
                let subnet_id = subnet_id.clone();
                s.spawn(move || {
                    store.observe(&common::observation(
                        event,
                        scope,
                        source_id,
                        subnet_id,
                        None,
                        None,
                        event_id(i as u64),
                        now_ms,
                    ))
                })
            })
            .collect();
        handles
            .into_iter()
            .map(|h| h.join().expect("thread"))
            .collect()
    })
}

/// A single observation with a fresh event_id AFTER a storm: its vector
/// reflects the COMPLETE storm state (thread replies are per-execution
/// snapshots, so they cannot be trusted as the final state).
fn probe(
    store: &RedisRiskStateStore,
    source_id: String,
    subnet_id: String,
    now_ms: u64,
) -> Observed {
    store
        .observe(&common::observation(
            RiskEventKind::PreIssue,
            0,
            source_id,
            subnet_id,
            None,
            None,
            common::event_id(0xFFFF),
            now_ms,
        ))
        .expect("probe observes the post-storm state")
}

#[test]
fn hundred_concurrent_source_events_lose_nothing() {
    let Some(_url) = common::redis_url() else {
        eprintln!("skipping redis concurrency test: RISK_REDIS_URL not set");
        return;
    };
    let store = store();
    let source = hex::encode([0xAA; 16]);
    // Same source pseudonym for all 100 threads, unique event_ids.
    let results = storm(
        &store,
        RiskEventKind::PreIssue,
        0,
        HUNDRED,
        source.clone(),
        hex::encode([0xBB; 16]),
        common::event_id,
        common::T0,
    );
    assert_eq!(results.len(), HUNDRED);
    assert!(results.iter().all(|r| r.is_ok()));

    // 100 * 1000 raw = 100_000 >= src_fast saturation 8000: exactly 1000.
    let final_vector = probe(&store, source, hex::encode([0xBB; 16]), common::T0).vector;
    assert_eq!(
        final_vector.source_fast, 1000,
        "lost source_fast increments"
    );
    assert_eq!(
        final_vector.source_slow, 1000,
        "lost source_slow increments"
    );
}

#[test]
fn hundred_concurrent_source_events_non_saturated_exact() {
    let Some(_url) = common::redis_url() else {
        eprintln!("skipping redis concurrency test: RISK_REDIS_URL not set");
        return;
    };
    // Huge saturations (10M) keep the channel far from saturation:
    // 100 * 1000 raw = 100_000 -> normalize(100_000, 10_000_000) = 10.
    // A single lost increment would read 99_000 -> 9.
    let mut sats = DEFAULT_SATURATIONS;
    sats[0] = 10_000_000; // src_fast
    sats[1] = 10_000_000; // src_slow
    let store = store_with(1800, 60_000, sats);

    let results = storm(
        &store,
        RiskEventKind::PreIssue,
        0,
        HUNDRED,
        hex::encode([0xAA; 16]),
        hex::encode([0xBB; 16]),
        common::event_id,
        common::T0,
    );
    assert!(results.iter().all(|r| r.is_ok()));
    let final_vector = probe(
        &store,
        hex::encode([0xAA; 16]),
        hex::encode([0xBB; 16]),
        common::T0,
    )
    .vector;
    assert_eq!(final_vector.source_fast, 10);
    assert_eq!(final_vector.source_slow, 10);
}

#[test]
fn hundred_concurrent_subnet_events_lose_nothing() {
    let Some(_url) = common::redis_url() else {
        eprintln!("skipping redis concurrency test: RISK_REDIS_URL not set");
        return;
    };
    let store = store();
    // All 100 threads hit the SAME subnet pseudonym (the shared /24 masked
    // network); the source id is irrelevant to the subnet channel.
    let results = storm(
        &store,
        RiskEventKind::PreIssue,
        0,
        HUNDRED,
        hex::encode([0xAA; 16]),
        hex::encode([0xBB; 16]),
        common::event_id,
        common::T0,
    );
    assert!(results.iter().all(|r| r.is_ok()));
    let final_vector = probe(
        &store,
        hex::encode([0xAA; 16]),
        hex::encode([0xBB; 16]),
        common::T0,
    )
    .vector;
    assert_eq!(
        final_vector.subnet_fast, 1000,
        "lost subnet_fast increments"
    );
}

#[test]
fn hundred_concurrent_global_events_reach_top_without_negatives() {
    let Some(_url) = common::redis_url() else {
        eprintln!("skipping redis concurrency test: RISK_REDIS_URL not set");
        return;
    };
    let store = store();
    // The global hash is namespace-wide: every thread hits the SAME key.
    let results = storm(
        &store,
        RiskEventKind::PreIssue,
        0,
        HUNDRED,
        hex::encode([0xAA; 16]),
        hex::encode([0xBB; 16]),
        common::event_id,
        common::T0,
    );
    assert_eq!(results.len(), HUNDRED);

    // The post-storm probe reflects the full storm: level 4, every counter
    // a normalized 0..=1000 value (a negative counter would wrap and fail).
    let final_vector = probe(
        &store,
        hex::encode([0xAA; 16]),
        hex::encode([0xBB; 16]),
        common::T0,
    )
    .vector;
    assert_eq!(
        store.last_global_level(),
        4,
        "global pressure must reach the top"
    );
    assert_eq!(final_vector.global_pressure, 1000);
    let values = [
        final_vector.source_fast,
        final_vector.source_slow,
        final_vector.subnet_fast,
        final_vector.issue_debt,
        final_vector.bad_proof,
        final_vector.malformed,
        final_vector.replay,
        final_vector.action_failure,
        final_vector.scope_switch,
        final_vector.global_pressure,
        final_vector.network_risk,
        final_vector.trust_credit,
        final_vector.principal_credit,
    ];
    for value in values {
        assert!(
            (0..=1000).contains(&value),
            "counter out of range: {value} (negative would wrap)"
        );
    }
}

#[test]
fn no_expired_state_resurrection_after_ttl() {
    let Some(_url) = common::redis_url() else {
        eprintln!("skipping redis concurrency test: RISK_REDIS_URL not set");
        return;
    };
    // Tiny state TTL (2 s): after it passes, a new event must start from a
    // FRESH state, not the pre-expiry counters.
    let store = store_with(2, 60_000, DEFAULT_SATURATIONS);

    for i in 0..HUNDRED {
        store
            .observe(&common::observation(
                RiskEventKind::PreIssue,
                0,
                hex::encode([0xAA; 16]),
                hex::encode([0xBB; 16]),
                None,
                None,
                common::event_id(i as u64),
                common::T0,
            ))
            .expect("observe");
    }
    // The source counters are saturated at 1000 while the key lives.
    assert_eq!(store.last_global_level(), 4);

    // Audit round 17: wait for the REDIS clock (which stamps the key's
    // TTL) to pass 3 s — comfortably beyond the 2 s state TTL — instead
    // of wall-clock sleeping. Polling makes the expiry deterministic
    // under any scheduling jitter.
    let ttl_start = redis_now_ms();
    wait_until_redis_ms(ttl_start + 3_000);

    // A new event at T0+4 s: if the old key had resurrected, rf would be
    // ~99_000 (normalized 990). A fresh key yields exactly 125.
    let fresh = store
        .observe(&common::observation(
            RiskEventKind::PreIssue,
            0,
            hex::encode([0xAA; 16]),
            hex::encode([0xBB; 16]),
            None,
            None,
            common::event_id(0xDEAD),
            common::T0 + 4_000,
        ))
        .expect("observe");
    assert_eq!(
        fresh.vector.source_fast, 125,
        "expired state must not resurrect (got {}, expected the fresh single-event value 125)",
        fresh.vector.source_fast
    );
}

#[test]
fn source_rate_limit_hit_is_source_session_only() {
    let Some(_url) = common::redis_url() else {
        eprintln!("skipping redis concurrency test: RISK_REDIS_URL not set");
        return;
    };
    // Event 15 (SourceRateLimitHit) must add bad pressure to source/session
    // ONLY — never subnet, global, or principal state (a per-source limit
    // is not deployment overload and must not raise the global attack
    // level for all visitors).
    let store = store();

    let feedback = store
        .observe(&common::observation(
            RiskEventKind::SourceRateLimitHit,
            0,
            hex::encode([0xAA; 16]),
            hex::encode([0xBB; 16]),
            Some([0x0F; 16]),
            None,
            common::event_id(0x7B1),
            common::T0,
        ))
        .expect("observe event 15");
    // src.bad + 3000 (sat 4000) and sess.bad + 3000 surface as bad_proof.
    assert_eq!(
        feedback.vector.bad_proof, 750,
        "source/session bad pressure must surface"
    );
    // Feedback is NOT velocity: no rf/rs anywhere.
    assert_eq!(feedback.vector.source_fast, 0);
    assert_eq!(feedback.vector.source_slow, 0);
    assert_eq!(feedback.vector.subnet_fast, 0);
    // Global state must be untouched: no bad, no level.
    assert_eq!(feedback.vector.global_pressure, 0);
    assert_eq!(store.last_global_level(), 0);

    // Control: a PreIssue DOES raise global pressure.
    let preissue = store
        .observe(&common::observation(
            RiskEventKind::PreIssue,
            0,
            hex::encode([0xAA; 16]),
            hex::encode([0xBB; 16]),
            Some([0x0F; 16]),
            None,
            common::event_id(0x7B2),
            common::T0,
        ))
        .expect("observe PreIssue");
    assert!(preissue.vector.global_pressure > 0);
}

#[test]
fn global_level_enters_hysteresis_hold_after_storm() {
    let Some(_url) = common::redis_url() else {
        eprintln!("skipping redis concurrency test: RISK_REDIS_URL not set");
        return;
    };
    // A SHORT hysteresis window (2 s) and sat_global 11_000: 5 concurrent
    // events ratchet gp to 10000 -> normalized 909 -> level 4 and arm the
    // cooldown. The rate-limit clock is Redis TIME, so the hold and the
    // drop after the window are exercised with REAL ~1 s / ~2.1 s sleeps.
    let mut sats = DEFAULT_SATURATIONS;
    sats[8] = 11_000; // sat_global (ARGV[16])
    let store = store_with(1800, 2000, sats);
    let mut conn = client().get_connection().expect("connection");
    let t: Vec<i64> = redis::cmd("TIME").query(&mut conn).expect("TIME");
    let t0 = (t[0] * 1000 + t[1] / 1000) as u64;
    let source = hex::encode([0xAA; 16]);
    let subnet = hex::encode([0xBB; 16]);
    let results = storm(
        &store,
        RiskEventKind::PreIssue,
        2,
        5,
        source.clone(),
        subnet.clone(),
        common::event_id,
        common::T0,
    );
    assert!(results.iter().all(|r| r.is_ok()));
    // A settle RiskDenied probe (no pressure added) reads the ratcheted
    // level deterministically and arms the deadline at ratchet + 2 s.
    let probe = |id: u64| {
        let mut o = common::observation(
            RiskEventKind::PreIssue,
            2,
            source.clone(),
            subnet.clone(),
            None,
            None,
            common::event_id(id),
            common::T0,
        );
        o.event = RiskEventKind::RiskDenied;
        o
    };
    store.observe(&probe(99)).expect("settle observe");
    assert_eq!(store.last_global_level(), 4);
    let cool = store.last_cooldown_until_ms();
    assert!(
        cool > t0 + 2_000 && cool <= t0 + 7_000,
        "the 2 s cooldown must be armed at the ratchet time + 2000"
    );

    // Inside the window: poll the Redis clock to ~1 s past the ratchet
    // (the deadline is ratchet + 2000 ms), then probe REPEATEDLY while the
    // server clock stays inside the window (audit round 18: every
    // iteration asserts the hold — a scheduling pause can only mean fewer
    // iterations, never a skipped assertion, and each probe carries a
    // unique event id so the dedupe never swallows one).
    wait_until_redis_ms(cool - 1_000);
    let mut hold_probe_id = 100u64;
    loop {
        let now = redis_now_ms();
        if now >= cool {
            break;
        }
        store.observe(&probe(hold_probe_id)).expect("hold observe");
        hold_probe_id += 2; // keep ids distinct from the drop probe below
        assert_eq!(
            store.last_global_level(),
            4,
            "level holds inside the window"
        );
        assert_eq!(
            store.last_cooldown_until_ms(),
            cool,
            "the hold keeps the deadline"
        );
        std::thread::sleep(Duration::from_millis(25));
    }

    // After the window: poll the Redis clock to ~1.1 s past the deadline
    // (~3.1 s past the ratchet). The drop assertion is valid for ANY
    // elapsed >= ~2.1 s (decay only moves gp further below the exit
    // threshold), so overshoot is harmless.
    wait_until_redis_ms(cool + 1_100);
    store.observe(&probe(101)).expect("drop observe");
    assert_eq!(
        store.last_global_level(),
        3,
        "level must drop to the target after the hysteresis window"
    );
    assert_eq!(store.last_cooldown_until_ms(), 0);
}

#[test]
fn duplicate_event_id_increments_exactly_once_across_threads() {
    let Some(_url) = common::redis_url() else {
        eprintln!("skipping redis concurrency test: RISK_REDIS_URL not set");
        return;
    };
    let storm_store = Arc::new(store());
    let duplicate_id = common::event_id(77);

    // 100 REAL threads race the SAME event_id from a common barrier: the
    // Lua's GET-then-SET dedupe is atomic, so exactly ONE call may
    // increment; the rest are duplicate no-ops that return the CURRENT
    // signals with is_duplicate=true. (Audit round 19: the previous
    // version ran the loop sequentially and proved only sequential
    // dedupe; the named concurrency property is now actually exercised.)
    let barrier = Arc::new(Barrier::new(HUNDRED));
    let results: Vec<_> = (0..HUNDRED)
        .map(|_| {
            let barrier = barrier.clone();
            let store = storm_store.clone();
            let id = duplicate_id.clone();
            std::thread::spawn(move || {
                barrier.wait();
                store
                    .observe(&common::observation(
                        RiskEventKind::PreIssue,
                        0,
                        hex::encode([0xAA; 16]),
                        hex::encode([0xBB; 16]),
                        None,
                        None,
                        id,
                        common::T0,
                    ))
                    .expect("duplicates never error")
            })
        })
        .collect::<Vec<_>>();

    let mut winners = 0;
    let mut dups = 0;
    for handle in results {
        let observed = handle.join().expect("thread panicked");
        if observed.is_duplicate {
            dups += 1;
        } else {
            winners += 1;
            assert_eq!(
                observed.vector.source_fast, 125,
                "the winner sees a fresh single increment"
            );
        }
        // Every caller sees ~ONE event worth of current signals: duplicates
        // are no-ops, not errors (the rf channel leaks 250/s of REAL time,
        // so the floor may drop a unit on slow runners).
        assert!(
            (100..=125).contains(&observed.vector.source_fast),
            "duplicate callers must see ~125, got {}",
            observed.vector.source_fast
        );
    }
    assert_eq!(
        winners, 1,
        "exactly one increment for 100 identical event_ids racing concurrently"
    );
    assert_eq!(dups, HUNDRED - 1);

    // Control: a fresh namespace with a single event, and a distinct event
    // on the storm namespace. Both prove the storm state moved by exactly
    // one unit (single event -> 125; storm + 1 -> 250 = 2 * 125).
    let control = store();
    let control_vector = control
        .observe(&common::observation(
            RiskEventKind::PreIssue,
            0,
            hex::encode([0xAA; 16]),
            hex::encode([0xBB; 16]),
            None,
            None,
            common::event_id(78),
            common::T0,
        ))
        .expect("observe");
    assert_eq!(control_vector.vector.source_fast, 125);

    let after = storm_store
        .observe(&common::observation(
            RiskEventKind::PreIssue,
            0,
            hex::encode([0xAA; 16]),
            hex::encode([0xBB; 16]),
            None,
            None,
            common::event_id(78),
            common::T0,
        ))
        .expect("observe");
    // The storm moved the state by exactly ONE unit (two events in total,
    // minus the small real-elapsed decay; a double-increment storm would
    // read ~375+ and 100 increments would saturate at 1000).
    assert!(
        (200..=250).contains(&after.vector.source_fast),
        "the storm must have moved the state by exactly one unit (got {})",
        after.vector.source_fast
    );
}

/// Contract-default policy snapshot for the AUDIT #88 decision assertions.
fn audit_policy() -> RiskPolicy {
    RiskPolicy::from_config(
        3,
        &json!({
            "version": 3,
            "weights": {
                "source_fast": 190, "source_slow": 110, "subnet_fast": 80,
                "issue_debt": 150, "bad_proof": 220, "malformed": 260,
                "replay": 320, "action_failure": 120, "scope_switch": 60,
                "global_pressure": 170, "network_risk": 100,
                "trust_credit": 130, "principal_credit": 100
            },
            "scopes": {
                "1": { "base_risk": 100, "minimum": "allow", "post_solve_check": true, "degraded": "sha20" }
            },
            "global_floors": { "0": "allow", "1": "sha16", "2": "sha18", "3": "sha20", "4": "sha20" }
        }),
    )
    .expect("audit policy parses")
}

/// AUDIT #88 (b) — POISONED SOURCE ABSOLUTE CAP: hundreds of invalid
/// proofs (plus request velocity and replay pressure) saturate the
/// channels; the score clamps at 1000 and the policy action reaches Deny —
/// but NEVER exceeds either, so there is no unbounded punishment mode.
#[test]
fn poisoned_source_reaches_the_cap_but_never_exceeds_it() {
    let Some(_url) = common::redis_url() else {
        eprintln!("skipping redis concurrency test: RISK_REDIS_URL not set");
        return;
    };
    let store = store();
    let source = hex::encode([0xAA; 16]);
    let subnet = hex::encode([0xBB; 16]);
    let weights = RiskWeights::default();
    let policy = audit_policy();

    let mut max_score = 0u16;
    let mut n = 0u64;
    let mut observe = |event: RiskEventKind| {
        let observed = store
            .observe(&common::observation(
                event,
                0,
                source.clone(),
                subnet.clone(),
                None,
                None,
                common::event_id(n),
                common::T0,
            ))
            .expect("observe");
        n += 1;
        max_score = max_score.max(compute_score(100, &observed.vector, &weights));
    };
    // 100 request velocity + 300 invalid proofs + 200 replay attempts:
    // rf/rs/bad/rep/global all saturate -> the score MUST clamp at 1000.
    for _ in 0..100 {
        observe(RiskEventKind::PreIssue);
    }
    for _ in 0..300 {
        observe(RiskEventKind::InvalidProof);
    }
    for _ in 0..200 {
        observe(RiskEventKind::ReplayAttempt);
    }
    assert!(
        max_score <= 1000,
        "the score must never exceed the 0..1000 cap while poisoning"
    );

    let final_vector = probe(&store, source, subnet, common::T0).vector;
    let score = compute_score(100, &final_vector, &weights);
    assert_eq!(
        score, 1000,
        "a fully poisoned source must reach the cap exactly"
    );
    for value in [
        final_vector.source_fast,
        final_vector.source_slow,
        final_vector.subnet_fast,
        final_vector.issue_debt,
        final_vector.bad_proof,
        final_vector.malformed,
        final_vector.replay,
        final_vector.action_failure,
        final_vector.scope_switch,
        final_vector.global_pressure,
        final_vector.network_risk,
        final_vector.trust_credit,
        final_vector.principal_credit,
    ] {
        assert!(value <= 1000, "signal must stay bounded at 1000");
    }

    // The band action at the cap is the ladder top (Deny) — no action
    // exists above it.
    let decision = policy.decide(
        1,
        score,
        &SignalVector::zero(),
        &ResourcePressure::default(),
        0,
        common::T0,
        0,
    );
    assert_eq!(
        decision.action,
        RiskAction::Deny,
        "the cap action is the ladder top (Deny)"
    );
    assert_eq!(decision.action.rank(), RiskAction::Deny.rank());
}

/// AUDIT #88 (c) — /64-STYLE NETWORK AGGREGATE WEAK PER-SIGNAL EFFECT:
/// many bad proofs across many IPs in ONE network saturate the shared
/// network channel, but the network signal stays bounded at 1000 and the
/// exact-IP signals of a single attacker dominate its score.
#[test]
fn network_aggregate_rises_bounded_while_exact_ip_dominates() {
    let Some(_url) = common::redis_url() else {
        eprintln!("skipping redis concurrency test: RISK_REDIS_URL not set");
        return;
    };
    let store = store();
    let subnet = hex::encode([0xBB; 16]);
    let weights = RiskWeights::default();

    // 200 distinct sources (IPs) in one network: each sends one request
    // with one invalid proof into the SHARED subnet pseudonym.
    let mut n = 0u64;
    for ip in 1..=200u32 {
        let source = hex::encode([ip as u8; 16]);
        store
            .observe(&common::observation(
                RiskEventKind::PreIssue,
                0,
                source.clone(),
                subnet.clone(),
                None,
                None,
                common::event_id(n),
                common::T0,
            ))
            .expect("observe");
        n += 1;
        store
            .observe(&common::observation(
                RiskEventKind::InvalidProof,
                0,
                source,
                subnet.clone(),
                None,
                None,
                common::event_id(n),
                common::T0,
            ))
            .expect("observe");
        n += 1;
    }

    // One attacker's exact-IP signals: 1 request + 1 bad proof (the probe
    // adds one more request to its own source).
    let attacker = probe(&store, hex::encode([1u8; 16]), subnet, common::T0).vector;
    let subnet_fast = attacker.subnet_fast; // shared network velocity, 200+ requests
    assert_eq!(subnet_fast, 1000, "the network aggregate saturates at 1000");
    assert!(
        subnet_fast <= 1000,
        "the network signal must stay bounded at 1000"
    );
    assert!(
        subnet_fast > 0,
        "many bad proofs across the network DO raise the shared signal"
    );

    let exact_ip = compute_score(
        0,
        &SignalVector {
            source_fast: attacker.source_fast,
            source_slow: attacker.source_slow,
            bad_proof: attacker.bad_proof,
            ..Default::default()
        },
        &weights,
    );
    let network_only = compute_score(
        0,
        &SignalVector {
            subnet_fast,
            ..Default::default()
        },
        &weights,
    );
    assert!(
        exact_ip > network_only,
        "the exact-IP signals ({exact_ip}) must dominate the network aggregate signal ({network_only}) even at network saturation"
    );
    assert!(
        exact_ip + network_only <= 1000,
        "even combined the attacker's score is bounded"
    );
}
