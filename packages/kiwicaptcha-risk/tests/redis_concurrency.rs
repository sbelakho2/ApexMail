//! Redis concurrency guarantees (real Redis, skipped unless RISK_REDIS_URL):
//! the canonical Lua script runs atomically, so concurrent observations with
//! unique event_ids never lose increments, concurrent duplicates increment
//! exactly once, TTL expiry is honored (no state resurrection), and the
//! global level hysteresis window holds.
//!
//! Every subtest uses its own fresh namespace (the store takes the
//! namespace in its constructor), so parallel subtests never share state.

mod common;

use std::thread;
use std::time::Duration;

use kiwicaptcha_risk::event::RiskEventKind;
use kiwicaptcha_risk::redis::{RedisRiskStateStore, DEFAULT_SATURATIONS};
use kiwicaptcha_risk::signals::SignalVector;
use kiwicaptcha_risk::store::{RiskStateStore, RiskStoreError};

const HUNDRED: usize = 100;

fn client() -> redis::Client {
    redis::Client::open(common::redis_url().expect("RISK_REDIS_URL set")).expect("url parses")
}

/// Store with contract defaults on a fresh namespace.
fn store() -> RedisRiskStateStore {
    RedisRiskStateStore::new(client(), &common::unique_namespace("conc"))
}

/// Store with explicit knobs on a fresh namespace.
fn store_with(
    state_ttl_secs: u64,
    hysteresis_ms: u64,
    saturations: [u32; 10],
) -> RedisRiskStateStore {
    RedisRiskStateStore::with_options(
        client(),
        &common::unique_namespace("conc"),
        900,
        900,
        state_ttl_secs,
        60,
        hysteresis_ms,
        saturations,
    )
}

/// Runs `count` concurrent observations sharing the given pseudonyms and
/// event kind; returns every Result in thread order.
#[allow(clippy::too_many_arguments)]
fn storm(
    store: &RedisRiskStateStore,
    event: RiskEventKind,
    scope: u16,
    count: usize,
    source_id: [u8; 16],
    subnet_id: [u8; 16],
    event_id: fn(u64) -> [u8; 16],
    now_ms: u64,
) -> Vec<Result<SignalVector, RiskStoreError>> {
    thread::scope(|s| {
        let handles: Vec<_> = (0..count)
            .map(|i| {
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
    source_id: [u8; 16],
    subnet_id: [u8; 16],
    now_ms: u64,
) -> SignalVector {
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
    let source = [0xAA; 16];
    // Same source pseudonym for all 100 threads, unique event_ids.
    let results = storm(
        &store,
        RiskEventKind::PreIssue,
        0,
        HUNDRED,
        source,
        [0xBB; 16],
        common::event_id,
        common::T0,
    );
    assert_eq!(results.len(), HUNDRED);
    assert!(results.iter().all(|r| r.is_ok()));

    // 100 * 1000 raw = 100_000 >= src_fast saturation 8000: exactly 1000.
    let final_vector = probe(&store, source, [0xBB; 16], common::T0);
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
        [0xAA; 16],
        [0xBB; 16],
        common::event_id,
        common::T0,
    );
    assert!(results.iter().all(|r| r.is_ok()));
    let final_vector = probe(&store, [0xAA; 16], [0xBB; 16], common::T0);
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
        [0xAA; 16],
        [0xBB; 16],
        common::event_id,
        common::T0,
    );
    assert!(results.iter().all(|r| r.is_ok()));
    let final_vector = probe(&store, [0xAA; 16], [0xBB; 16], common::T0);
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
        [0xAA; 16],
        [0xBB; 16],
        common::event_id,
        common::T0,
    );
    assert_eq!(results.len(), HUNDRED);

    // The post-storm probe reflects the full storm: level 4, every counter
    // a normalized 0..=1000 value (a negative counter would wrap and fail).
    let final_vector = probe(&store, [0xAA; 16], [0xBB; 16], common::T0);
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
                [0xAA; 16],
                [0xBB; 16],
                None,
                None,
                common::event_id(i as u64),
                common::T0,
            ))
            .expect("observe");
    }
    // The source counters are saturated at 1000 while the key lives.
    assert_eq!(store.last_global_level(), 4);

    thread::sleep(Duration::from_secs(3)); // > state TTL of 2 s

    // A new event at T0+4 s: if the old key had resurrected, rf would be
    // ~99_000 (normalized 990). A fresh key yields exactly 125.
    let fresh = store
        .observe(&common::observation(
            RiskEventKind::PreIssue,
            0,
            [0xAA; 16],
            [0xBB; 16],
            None,
            None,
            common::event_id(0xDEAD),
            common::T0 + 4_000,
        ))
        .expect("observe");
    assert_eq!(
        fresh.source_fast, 125,
        "expired state must not resurrect (got {}, expected the fresh single-event value 125)",
        fresh.source_fast
    );
}

#[test]
fn global_level_enters_hysteresis_hold_after_storm() {
    let Some(_url) = common::redis_url() else {
        eprintln!("skipping redis concurrency test: RISK_REDIS_URL not set");
        return;
    };
    let store = store();
    // Scope-2 events: 4 concurrent events ratchet gp to 8000 -> level 3 and
    // arm the cooldown window (the Lua overloads the global `scope` field
    // with the event scope, so the level also honours the event scope).
    let results = storm(
        &store,
        RiskEventKind::PreIssue,
        2,
        4,
        [0xAA; 16],
        [0xBB; 16],
        common::event_id,
        common::T0,
    );
    assert!(results.iter().all(|r| r.is_ok()));
    assert_eq!(store.last_global_level(), 3);
    assert_eq!(store.last_cooldown_until_ms(), common::T0 + 60_000);

    // t0+51s: pressure decayed below the level's target, but the unexpired
    // hysteresis window must HOLD the level (2 from the event scope).
    store
        .observe(&common::observation(
            RiskEventKind::PreIssue,
            2,
            [0xAA; 16],
            [0xBB; 16],
            None,
            None,
            common::event_id(9),
            common::T0 + 51_000,
        ))
        .expect("observe");
    assert_eq!(
        store.last_global_level(),
        2,
        "hysteresis must hold the level inside the window"
    );
    assert_eq!(store.last_cooldown_until_ms(), common::T0 + 60_000);

    // t0+76s: the window passed; the level must drop and the window close.
    store
        .observe(&common::observation(
            RiskEventKind::PreIssue,
            2,
            [0xAA; 16],
            [0xBB; 16],
            None,
            None,
            common::event_id(10),
            common::T0 + 76_000,
        ))
        .expect("observe");
    assert_eq!(store.last_global_level(), 1);
    assert_eq!(store.last_cooldown_until_ms(), 0);
}

#[test]
fn duplicate_event_id_increments_exactly_once_across_threads() {
    let Some(_url) = common::redis_url() else {
        eprintln!("skipping redis concurrency test: RISK_REDIS_URL not set");
        return;
    };
    let storm_store = store();
    let duplicate_id = common::event_id(77);

    // 100 threads race with the SAME event_id: the Lua's GET-then-SET dedupe
    // is atomic, so exactly ONE call may increment; the rest must surface as
    // DuplicateEvent (no-ops that leave the state untouched).
    let mut ok = 0;
    let mut dup = 0;
    for _ in 0..HUNDRED {
        match storm_store.observe(&common::observation(
            RiskEventKind::PreIssue,
            0,
            [0xAA; 16],
            [0xBB; 16],
            None,
            None,
            duplicate_id,
            common::T0,
        )) {
            Ok(vector) => {
                ok += 1;
                assert_eq!(vector.source_fast, 125, "winner sees a single increment");
            }
            Err(RiskStoreError::DuplicateEvent) => dup += 1,
            Err(other) => panic!("unexpected error: {other}"),
        }
    }
    assert_eq!(ok, 1, "exactly one increment for 100 identical event_ids");
    assert_eq!(dup, HUNDRED - 1);

    // Control: a fresh namespace with a single event, and a distinct event
    // on the storm namespace. Both prove the storm state moved by exactly
    // one unit (single event -> 125; storm + 1 -> 250 = 2 * 125).
    let control = store();
    let control_vector = control
        .observe(&common::observation(
            RiskEventKind::PreIssue,
            0,
            [0xAA; 16],
            [0xBB; 16],
            None,
            None,
            common::event_id(78),
            common::T0,
        ))
        .expect("observe");
    assert_eq!(control_vector.source_fast, 125);

    let after = storm_store
        .observe(&common::observation(
            RiskEventKind::PreIssue,
            0,
            [0xAA; 16],
            [0xBB; 16],
            None,
            None,
            common::event_id(78),
            common::T0,
        ))
        .expect("observe");
    assert_eq!(
        after.source_fast,
        2 * control_vector.source_fast,
        "the storm must have moved the state by exactly one unit"
    );
}
