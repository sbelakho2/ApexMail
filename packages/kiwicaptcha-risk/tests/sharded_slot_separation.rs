//! The single-slot hot path is gone (the H7 done-when), proven against
//! two throwaway redis-server stand-ins on their own ports:
//!
//! 1. the level-transition script and the session keys land on
//!    separate endpoints (separate cluster slots; the stand-in rule is
//!    slot modulo the endpoint list);
//! 2. the transition runs once per merge window on its own slot, never
//!    per assessment: the per-port EVALSHA budget of a measured run
//!    matches the exact routed expectation, which a per-assessment
//!    hysteresis call would exceed it by one call per assessment;
//! 3. the session tag records live on the session family's slot, the
//!    hysteresis hash on the shared tag's slot, and neither ever
//!    appears on the other server.
//!
//! The harness is self-contained: it spawns its own redis-server
//! processes on free ports and shuts every one down with a nosave final
//! write. The RISK_REDIS_URLS override (comma separated, at least two
//! endpoints) hands over external stand-ins instead, which the harness
//! never shuts down. Without either source the suite skips, so the
//! regular run needs no infrastructure.

mod common;

use std::time::Duration;

use kiwicaptcha_risk::event::RiskEventKind;
use kiwicaptcha_risk::sharded::{ShardedOptions, ShardedRedisRiskStateStore};
use kiwicaptcha_risk::store::RiskStateStore;

const MEASURED_ASSESSMENTS: u64 = 40;

fn observation(i: u64) -> kiwicaptcha_risk::event::RiskObservation {
    let mut o = common::observation(
        RiskEventKind::PreIssue,
        0,
        format!("{:0>32}", "aa"),
        format!("{:0>32}", "bb"),
        None,
        None,
        common::event_id(i),
        common::T0,
    );
    o.network_risk = 0;
    o
}

/// Searches a namespace and session pseudonym whose session tag record
/// and hysteresis hash route to separate stand-ins (the two-key slot
/// separation the done-when requires), then proves the placement and
/// the once-per-window transition budget.
#[test]
fn level_transition_lands_on_a_different_slot_than_the_session_keys() {
    let Some(servers) = common::shard_standins(2) else {
        eprintln!(
            "skipping the slot-separation suite: set RISK_REDIS_URLS to at least two comma-separated endpoints or install redis-server"
        );
        return;
    };
    let urls: Vec<String> = servers.iter().map(|s| s.url().to_string()).collect();
    let options = ShardedOptions {
        connection_timeout_ms: 2_000,
        command_timeout_ms: 2_000,
        ..ShardedOptions::default()
    };

    // Search: the session ctx record's endpoint must differ from the
    // hysteresis hash's endpoint.
    let (namespace, session_hex) = {
        let mut found = None;
        for seed in 0..256u16 {
            let namespace = format!("slotsep{seed:02x}{}", common::unique_namespace(""));
            let session_hex = format!("{:0>32}", "5c");
            let store = ShardedRedisRiskStateStore::connect(&urls, &namespace, options.clone())
                .expect("probe store");
            let session_endpoint =
                store.endpoint_for_key(&kiwicaptcha_risk::keyspace::session_tag_key(
                    store.namespace(),
                    "ctx",
                    &session_hex,
                ));
            let hyst_endpoint = store.endpoint_for_key(
                &kiwicaptcha_risk::keyspace::hysteresis_key(store.namespace()),
            );
            drop(store);
            if session_endpoint != hyst_endpoint {
                found = Some((namespace, session_hex));
                break;
            }
        }
        found.expect("a namespace with the two keys on different stand-ins exists within 256 seeds")
    };

    let store =
        ShardedRedisRiskStateStore::connect(&urls, &namespace, options).expect("sharded store");
    let ns = store.namespace().to_string();
    let hyst_key = kiwicaptcha_risk::keyspace::hysteresis_key(&ns);
    let session_key = kiwicaptcha_risk::keyspace::session_tag_key(&ns, "ctx", &session_hex);
    let hyst_endpoint = store.endpoint_for_key(&hyst_key);
    let session_endpoint = store.endpoint_for_key(&session_key);
    assert_ne!(
        hyst_endpoint, session_endpoint,
        "the two keys must route to different stand-ins"
    );

    // The routed endpoint of every EVALSHA unit of one assessment: six
    // identity invocations (fixed ids, fixed routing) plus the event's
    // scope shard (varies with the event id).
    let identity_units_on = |endpoint: usize| -> u64 {
        let mut count = 0u64;
        for dimension in [
            kiwicaptcha_risk::keyspace::ShardedDimension::Source,
            kiwicaptcha_risk::keyspace::ShardedDimension::Subnet,
        ] {
            for epoch in [-1i64, 0, 1] {
                let hex_id = match (dimension, epoch) {
                    (kiwicaptcha_risk::keyspace::ShardedDimension::Source, -1) => {
                        common::epoch_ids(0xAA, common::T0).1
                    }
                    (kiwicaptcha_risk::keyspace::ShardedDimension::Source, 0) => {
                        format!("{:0>32}", "aa")
                    }
                    (kiwicaptcha_risk::keyspace::ShardedDimension::Source, 1) => {
                        common::epoch_ids(0xAA, common::T0).3
                    }
                    (kiwicaptcha_risk::keyspace::ShardedDimension::Subnet, -1) => {
                        common::epoch_ids(0xBB, common::T0).1
                    }
                    (kiwicaptcha_risk::keyspace::ShardedDimension::Subnet, 0) => {
                        format!("{:0>32}", "bb")
                    }
                    (kiwicaptcha_risk::keyspace::ShardedDimension::Subnet, 1) => {
                        common::epoch_ids(0xBB, common::T0).3
                    }
                    _ => unreachable!(),
                };
                let key = kiwicaptcha_risk::keyspace::identity_state_key(
                    &ns,
                    dimension,
                    Some(common::epoch_ids(0xAA, common::T0).0 + epoch),
                    &hex_id,
                );
                if store.endpoint_for_key(&key) == endpoint {
                    count += 1;
                }
            }
        }
        count
    };
    let scope_units_on = |endpoint: usize| -> u64 {
        (0..MEASURED_ASSESSMENTS)
            .map(|i| {
                let shard = kiwicaptcha_risk::keyspace::scope_shard(
                    &common::event_id(100 + i),
                    format!("{:0>32}", "aa").as_bytes(),
                );
                let key = kiwicaptcha_risk::keyspace::scope_shard_key(&ns, "global", shard);
                u64::from(store.endpoint_for_key(&key) == endpoint)
            })
            .sum()
    };
    // The merge refresh reads all 16 scope shards plus the one
    // level-transition invocation on the hysteresis slot.
    let refresh_scope_units_on = |endpoint: usize| -> u64 {
        (0..16u8)
            .map(|shard| {
                let key = kiwicaptcha_risk::keyspace::scope_shard_key(&ns, "global", shard);
                u64::from(store.endpoint_for_key(&key) == endpoint)
            })
            .sum()
    };

    // Warm-up: one assessment (loads the scripts, runs the first merge
    // refresh) plus one inside the window. The hysteresis hash and the
    // session record must exist, each only on its own server.
    store.observe(&observation(1)).expect("warm-up 1");
    store.observe(&observation(2)).expect("warm-up 2");
    assert!(
        servers[hyst_endpoint].exists(&hyst_key),
        "the merge refresh created the hysteresis hash on its own server"
    );
    assert!(
        !servers[session_endpoint].exists(&hyst_key),
        "the hysteresis hash must never appear on the session server"
    );
    // The warm-up carried no presented tag; present one now so the
    // session record exists on the session server.
    let warm_tags = common::observation(
        RiskEventKind::PreIssue,
        0,
        format!("{:0>32}", "aa"),
        format!("{:0>32}", "bb"),
        Some(hex::decode(&session_hex).unwrap().try_into().unwrap()),
        None,
        common::event_id(3),
        common::T0,
    );
    let _ = store
        .assess_v2(&warm_tags, Some("tag"), None, None)
        .expect("warm-up 3");
    assert!(
        servers[session_endpoint].exists(&session_key),
        "the session tag record lives on the session family's server"
    );
    assert!(
        !servers[hyst_endpoint].exists(&session_key),
        "the session tag record must never appear on the hysteresis server"
    );

    // The measured run: force the merge gate stale, reset both command
    // budgets, then run the measured assessment count. The first
    // triggers the refresh (16 scope reads and one transition), the
    // rest ride the window. A per-assessment transition would add one
    // EVALSHA per assessment on the hysteresis endpoint.
    std::thread::sleep(kiwicaptcha_risk::keyspace::MERGE_STALENESS + Duration::from_millis(150));
    servers[0].reset_stats();
    servers[1].reset_stats();
    for i in 0..MEASURED_ASSESSMENTS {
        store.observe(&observation(100 + i)).expect("assessment");
    }

    let expected = |endpoint: usize| -> u64 {
        identity_units_on(endpoint) * MEASURED_ASSESSMENTS
            + scope_units_on(endpoint)
            + refresh_scope_units_on(endpoint)
            + u64::from(endpoint == hyst_endpoint)
    };
    let actual: Vec<u64> = servers
        .iter()
        .map(common::RedisStandin::evalsha_calls)
        .collect();
    for (endpoint, server) in servers.iter().enumerate() {
        assert_eq!(
            actual[endpoint],
            expected(endpoint),
            "server {endpoint} ({}): the EVALSHA budget must match the routed expectation exactly (a per-assessment level transition would add one call per assessment)",
            server.url(),
        );
    }
}
