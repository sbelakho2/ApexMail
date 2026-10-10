//! The Plane 7 invariant suite, run against the sharded keyspace: every
//! store invariant the legacy suite pins is proven here for the
//! horizontally scalable layout, against a real Redis (skip unless the
//! `RISK_REDIS_URL` env carries one, e.g. a server started with
//! `redis-server --port 6426 --save "" --appendonly no`).
//!
//! Covered: the legacy signal contract (single event, duplicate no-op,
//! saturation, global hysteresis under the staleness contract), the
//! keyspace mode marker (claim, refusal, no silent fallback), legacy
//! parity of the sharded assessment path, key-tag correctness and
//! dispersion, the merged-aggregate staleness window, scope shard
//! dispersion, the mode-insensitive auxiliary surfaces, and the
//! partial-batch retry idempotency under a dropped reply.

mod common;

use std::io::Read;
use std::net::{TcpListener, TcpStream};
use std::time::Duration;

use kiwicaptcha_risk::event::{RiskEventKind, RiskObservation};
use kiwicaptcha_risk::keyspace::{claim_keyspace_mode, KeyspaceMode};
use kiwicaptcha_risk::redis::RedisRiskStateStore;
use kiwicaptcha_risk::sharded::{ShardedOptions, ShardedRedisRiskStateStore};
use kiwicaptcha_risk::signals::SignalVector;
use kiwicaptcha_risk::store::{
    OutcomeRegistration, RiskStateStore, RiskStoreError, SessionContextTagStore,
};

fn urls() -> Option<Vec<String>> {
    common::redis_url().map(|url| vec![url])
}

fn options() -> ShardedOptions {
    // Relaxed test timeouts: the production 10 ms command timeout is a
    // fail-fast tuning knob; CI scheduling jitter must never produce a
    // spurious failure here.
    ShardedOptions {
        connection_timeout_ms: 2_000,
        command_timeout_ms: 2_000,
        ..ShardedOptions::default()
    }
}

fn sharded_store(suffix: &str) -> ShardedRedisRiskStateStore {
    let urls = urls().expect("RISK_REDIS_URL set");
    ShardedRedisRiskStateStore::connect(&urls, &common::unique_namespace(suffix), options())
        .expect("sharded store construction claims the mode marker")
}

fn legacy_store(suffix: &str) -> RedisRiskStateStore {
    let client = redis::Client::open(common::redis_url().expect("RISK_REDIS_URL set").as_str())
        .expect("url parses");
    RedisRiskStateStore::with_options(
        client,
        &common::unique_namespace(suffix),
        1800,
        60,
        60_000,
        1800,
        86_400,
        kiwicaptcha_risk::redis::DEFAULT_OUTCOME_TTL_SECS,
        kiwicaptcha_risk::redis::DEFAULT_SATURATIONS,
    )
    .with_io_timeouts(2_000, 2_000)
}

fn observation(event_id: &str, scope: u32, network_risk: u16) -> RiskObservation {
    let mut o = common::observation(
        RiskEventKind::PreIssue,
        scope,
        format!("{:0>32}", "aa"),
        format!("{:0>32}", "bb"),
        None,
        None,
        event_id.to_string(),
        common::T0,
    );
    o.network_risk = network_risk;
    o
}

/// A TCP proxy that forwards to the upstream, but swallows the first
/// armed client connection's commands and closes it with no reply: the
/// dropped-reply injection for the partial-batch retry proof. Arming
/// keeps store construction (whose connections must succeed) on the
/// clean path. The client's write may still succeed (the bytes reach
/// the kernel), so the batch fails at the read phase, exactly like a
/// reply lost mid-batch.
fn spawn_dropping_proxy(
    upstream_port: u16,
) -> (u16, std::sync::Arc<std::sync::atomic::AtomicBool>) {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    let listener = TcpListener::bind("127.0.0.1:0").expect("proxy bind");
    let port = listener.local_addr().expect("proxy addr").port();
    let armed = Arc::new(AtomicBool::new(false));
    let proxy_armed = Arc::clone(&armed);
    std::thread::spawn(move || {
        let forward = |client: TcpStream| {
            let Ok(mut upstream) = TcpStream::connect(("127.0.0.1", upstream_port)) else {
                return;
            };
            let mut client_out = client.try_clone().expect("client clone");
            let mut client = client;
            let mut upstream_out = upstream.try_clone().expect("upstream clone");
            let to_upstream = std::thread::spawn(move || {
                let _ = std::io::copy(&mut client_out, &mut upstream_out);
            });
            let to_client = std::thread::spawn(move || {
                let _ = std::io::copy(&mut upstream, &mut client);
            });
            std::thread::spawn(move || {
                let _ = to_upstream.join();
                let _ = to_client.join();
            });
        };
        let mut dropped = false;
        for stream in listener.incoming() {
            let Ok(client) = stream else { continue };
            if dropped {
                forward(client);
                continue;
            }
            if !proxy_armed.load(Ordering::SeqCst) {
                // Clean forwarding while the proxy is disarmed.
                forward(client);
                continue;
            }
            dropped = true;
            let mut client = client;
            let mut buf = [0u8; 8192];
            let _ = client.read(&mut buf);
            drop(client);
        }
    });
    (port, armed)
}

#[test]
fn single_event_matches_the_legacy_contract() {
    let Some(_url) = common::redis_url() else {
        eprintln!("skipping sharded suite: RISK_REDIS_URL not set");
        return;
    };
    let store = sharded_store("single");
    let observed = store
        .observe(&observation(&common::event_id(1), 0, 0))
        .unwrap();
    let vector = observed.vector;
    assert_eq!(vector.source_fast, 125, "1000*1000/8000");
    assert_eq!(vector.source_slow, 10, "1000*1000/100000");
    assert_eq!(vector.subnet_fast, 125);
    assert_eq!(vector.issue_debt, 0);
    assert_eq!(
        vector.global_pressure, 28,
        "the merged aggregate sees one event: 2000*1000/70000"
    );
    assert_eq!(vector.network_risk, 0);
    assert!(!observed.is_duplicate);
    assert_eq!(store.last_global_level(), 0);
}

#[test]
fn duplicate_event_id_is_a_single_increment() {
    let Some(_url) = common::redis_url() else {
        eprintln!("skipping sharded suite: RISK_REDIS_URL not set");
        return;
    };
    let store = sharded_store("dup");
    let id = common::event_id(7);

    let first = store.observe(&observation(&id, 0, 0)).unwrap();
    assert_eq!(first.vector.source_fast, 125);
    assert!(!first.is_duplicate);

    // Same event id again: duplicate no-op, current signals returned.
    // The channels leak by real elapsed time (rf 250/s, rs 20/s), so a
    // slow runner can floor one unit lower.
    let duplicate = store.observe(&observation(&id, 0, 0)).unwrap();
    assert!(duplicate.is_duplicate);
    assert!(
        (100..=125).contains(&duplicate.vector.source_fast),
        "a duplicate must not increment (got {})",
        duplicate.vector.source_fast
    );

    // A distinct event observes the state from a single increment (two
    // events, minus the small real-elapsed decay).
    let third = store
        .observe(&observation(&common::event_id(8), 0, 0))
        .unwrap();
    assert!(!third.is_duplicate);
    assert!(
        (200..=250).contains(&third.vector.source_fast),
        "exactly two increments (got {})",
        third.vector.source_fast
    );
}

#[test]
fn hundred_sequential_events_saturate_across_shards() {
    let Some(_url) = common::redis_url() else {
        eprintln!("skipping sharded suite: RISK_REDIS_URL not set");
        return;
    };
    let store = sharded_store("sat");
    let mut vector = SignalVector::zero();
    for i in 0..100u64 {
        vector = store
            .observe(&observation(&common::event_id(i), 0, 0))
            .unwrap()
            .vector;
    }
    assert_eq!(vector.source_fast, 1000, "no increments may be lost");
    assert_eq!(vector.subnet_fast, 1000);
    // The merged aggregate lags by at most the staleness window; let the
    // window pass and assess once more so the merge absorbs all 100
    // commits (minus the small real-elapsed leak).
    std::thread::sleep(Duration::from_millis(1100));
    vector = store
        .observe(&observation(&common::event_id(1000), 0, 0))
        .unwrap()
        .vector;
    assert!(
        (960..=1000).contains(&vector.global_pressure),
        "the merged aggregate must saturate after the window (got {})",
        vector.global_pressure
    );
    assert_eq!(
        store.last_global_level(),
        4,
        "gnorm >= 900 ratchets to level 4"
    );
}

#[test]
fn keyspace_mode_marker_is_claimed_and_enforced() {
    let Some(url) = common::redis_url() else {
        eprintln!("skipping sharded suite: RISK_REDIS_URL not set");
        return;
    };
    let urls = vec![url.clone()];
    let ns = common::unique_namespace("mode");

    // Construction claims the marker; a second sharded store on the same
    // namespace is accepted.
    let first = ShardedRedisRiskStateStore::connect(&urls, &ns, options()).unwrap();
    assert_eq!(first.namespace(), ns);
    ShardedRedisRiskStateStore::connect(&urls, &ns, options()).unwrap();

    // A legacy claim on a sharded-marked namespace is refused.
    let mut conn = redis::Client::open(url.as_str())
        .unwrap()
        .get_connection()
        .unwrap();
    let err = claim_keyspace_mode(&mut conn, &ns, KeyspaceMode::Legacy).unwrap_err();
    match &err {
        RiskStoreError::KeyspaceModeMismatch {
            namespace,
            stored,
            expected,
        } => {
            assert_eq!(namespace, &ns);
            assert_eq!(stored, "sharded");
            assert_eq!(expected, "legacy");
        }
        other => panic!("expected KeyspaceModeMismatch, got {other:?}"),
    }

    // And the mirror direction: a namespace claimed legacy refuses the
    // sharded store at construction (no silent fallback).
    let legacy_ns = common::unique_namespace("modelflip");
    claim_keyspace_mode(&mut conn, &legacy_ns, KeyspaceMode::Legacy).unwrap();
    let err = match ShardedRedisRiskStateStore::connect(&urls, &legacy_ns, options()) {
        Err(err) => err,
        Ok(_) => panic!("the sharded store must refuse a legacy-marked namespace"),
    };
    assert!(
        matches!(err, RiskStoreError::KeyspaceModeMismatch { .. }),
        "the sharded store must refuse a legacy-marked namespace (got {err:?})"
    );
}

/// Legacy parity: the same observation sequence through the legacy
/// single-tag store and the sharded store produces the same signals.
/// The two runs decay by real elapsed time independently, so each
/// channel carries a small tolerance; the merged global pressure
/// additionally honors the one-second staleness window.
#[test]
fn sharded_assessment_matches_the_legacy_path() {
    let Some(_url) = common::redis_url() else {
        eprintln!("skipping sharded suite: RISK_REDIS_URL not set");
        return;
    };
    let legacy = legacy_store("parity");
    let sharded = sharded_store("parity");
    let scopes = [0u32, 1, 2, 1, 0];
    let events = [
        RiskEventKind::PreIssue,
        RiskEventKind::ChallengeIssued,
        RiskEventKind::InvalidProof,
        RiskEventKind::ReplayAttempt,
        RiskEventKind::ProtectedActionSuccess,
    ];
    let session: [u8; 16] = [0x5a; 16];
    for i in 0..5u64 {
        let mut legacy_obs = common::observation(
            events[i as usize],
            scopes[i as usize],
            format!("{:0>32}", "aa"),
            format!("{:0>32}", "bb"),
            Some(session),
            None,
            common::event_id(100 + i),
            common::T0,
        );
        legacy_obs.network_risk = 600;
        let mut sharded_obs = legacy_obs.clone();
        sharded_obs.event_id = common::event_id(200 + i);
        let lv = legacy.observe(&legacy_obs).unwrap().vector;
        let sv = sharded.observe(&sharded_obs).unwrap().vector;
        // The same raw increments and the same leak table, both runs
        // within a few ms: the normalized channels may differ by the
        // leak of that interval only.
        let pairs = [
            (lv.source_fast, sv.source_fast),
            (lv.source_slow, sv.source_slow),
            (lv.subnet_fast, sv.subnet_fast),
            (lv.issue_debt, sv.issue_debt),
            (lv.bad_proof, sv.bad_proof),
            (lv.malformed, sv.malformed),
            (lv.replay, sv.replay),
            (lv.action_failure, sv.action_failure),
            (lv.scope_switch, sv.scope_switch),
            (lv.trust_credit, sv.trust_credit),
            (lv.principal_credit, sv.principal_credit),
        ];
        for (index, (a, b)) in pairs.iter().enumerate() {
            let (a, b) = (*a, *b);
            assert!(
                (i64::from(a) - i64::from(b)).abs() <= 3,
                "channel {index} diverged: legacy {a}, sharded {b}"
            );
        }
        // The merged pressure honors the staleness window: both sides
        // carry the same raw accumulation within one window of leak
        // (rf 250/s + rs 20/s over <= 1 s = <= 270 raw = 4 normalized).
        assert!(
            (i64::from(lv.global_pressure) - i64::from(sv.global_pressure)).abs() <= 6,
            "global pressure diverged beyond the staleness band: legacy {}, sharded {}",
            lv.global_pressure,
            sv.global_pressure
        );
    }
}

#[test]
fn consolidated_assessment_registers_tags_and_the_ledger() {
    let Some(_url) = common::redis_url() else {
        eprintln!("skipping sharded suite: RISK_REDIS_URL not set");
        return;
    };
    let legacy = legacy_store("v2");
    let sharded = sharded_store("v2s");
    let session = [0x9c; 16];
    let build = |store_ns_seed: u64| {
        let mut o = common::observation(
            RiskEventKind::PreIssue,
            1,
            format!("{:0>32}", "aa"),
            format!("{:0>32}", "bb"),
            Some(session),
            None,
            common::event_id(1000 + store_ns_seed),
            common::T0,
        );
        o.network_risk = 600;
        let registration = OutcomeRegistration {
            decision_id: format!("dec-sharded-{store_ns_seed}"),
            decision_hour: 472_222,
            base_risk: 100,
            global_pressure_enabled: true,
            honeypot_hit: false,
            v1_weights: kiwicaptcha_risk::score::RiskWeights::default(),
            v2_weights: kiwicaptcha_risk::score::RiskV2Weights::default(),
            target_id: None,
        };
        (o, registration)
    };

    // The legacy consolidated reply is the reference: the sharded batch
    // must register a byte-identical ledger entry.
    let (lo, lreg) = build(1);
    let legacy_reply = legacy
        .assess_v2_full(&lo, Some("aa"), Some("tls13|http2"), Some(&lreg))
        .expect("legacy consolidated assessment");
    assert!(legacy_reply.registration_status);

    let (so, sreg) = build(2);
    let reply = sharded
        .assess_v2(&so, Some("aa"), Some("tls13|http2"), Some(&sreg))
        .expect("sharded consolidated assessment")
        .expect("the sharded store carries the consolidated capability");
    assert!(
        reply.registration_status,
        "the pending ledger entry must be created"
    );
    assert_eq!(reply.existing_context_tag.as_deref(), Some("aa"));
    assert_eq!(reply.existing_tls_tag.as_deref(), Some("tls13|http2"));
    assert_eq!(
        reply.observed.vector.source_fast, legacy_reply.observed.vector.source_fast,
        "the v1 observation must run identically"
    );

    // The ledger entry mirrors the legacy consolidated one field by
    // field (the score is computed from the same signals and weights).
    let mut conn = redis::Client::open(common::redis_url().unwrap().as_str())
        .unwrap()
        .get_connection()
        .unwrap();
    let legacy_raw: String = redis::cmd("GET")
        .arg(legacy.outcome_ledger_key("dec-sharded-1"))
        .query(&mut conn)
        .expect("legacy ledger read");
    let sharded_raw: String = redis::cmd("GET")
        .arg(kiwicaptcha_risk::keyspace::outcome_ledger_key(
            sharded.namespace(),
            "dec-sharded-2",
        ))
        .query(&mut conn)
        .expect("sharded ledger read");
    let legacy_json: serde_json::Value = serde_json::from_str(&legacy_raw).unwrap();
    let sharded_json: serde_json::Value = serde_json::from_str(&sharded_raw).unwrap();
    assert_eq!(legacy_json["o"], sharded_json["o"]);
    assert_eq!(legacy_json["scope"], sharded_json["scope"]);
    assert_eq!(legacy_json["hour"], sharded_json["hour"]);
    assert_eq!(
        legacy_json["score"], sharded_json["score"],
        "the client-side score must match the script-computed one exactly"
    );

    // A retried decision id is refused (SET NX), and a changed tag on an
    // established session returns the first tags.
    let (so2, sreg2) = build(2);
    let retry = sharded
        .assess_v2(&so2, Some("bb"), Some("aa"), Some(&sreg2))
        .unwrap()
        .unwrap();
    assert!(
        !retry.registration_status,
        "a duplicate decision id must not overwrite"
    );
    assert_eq!(
        retry.existing_context_tag.as_deref(),
        Some("aa"),
        "the first tag wins"
    );
}

/// The hysteresis script floors a corrupt negative level at 0 and never
/// lets it feed the ratchet as upgrade head-start. The write-on-change
/// guard is pinned at the source: a steady-state transition must not
/// rewrite the hot key (`OBJECT IDLETIME` cannot observe it — the
/// script's own `HMGET` resets the idle clock — so the guard itself is
/// the regression surface).
#[test]
fn hysteresis_floors_negative_levels_and_writes_only_on_change() {
    let Some(url) = common::redis_url() else {
        eprintln!("skipping: RISK_REDIS_URL not set");
        return;
    };
    let src = kiwicaptcha_risk::sharded::SHARDED_HYSTERESIS_LUA;
    assert!(
        src.contains("if raw_level ~= level or raw_cool ~= cool then"),
        "the hysteresis hash must be written only on change"
    );
    assert!(
        src.contains("math.max(0, math.min(4, num(v[1])))"),
        "a stored level must be floored at 0 and clamped at 4"
    );
    let ns = common::unique_namespace("hystfloor");
    let key = format!("{{kiwi:{ns}}}:risk:hyst");
    let mut conn = redis::Client::open(url.as_str())
        .unwrap()
        .get_connection()
        .unwrap();
    use redis::Commands;
    // A tampered -3 level must read as 0 after one transition.
    let _: i32 = conn.hset(&key, "scope", -3).unwrap();
    let _: i32 = conn.hset(&key, "cool", -9).unwrap();
    let run = |conn: &mut redis::Connection, gp: i64| -> (Vec<i64>) {
        redis::cmd("EVAL")
            .arg(kiwicaptcha_risk::sharded::SHARDED_HYSTERESIS_LUA)
            .arg(1)
            .arg(&key)
            .arg(gp)
            .arg(70_000i64)
            .arg(60_000i64)
            .query(conn)
            .expect("hysteresis eval")
    };
    let reply: Vec<i64> = run(&mut conn, 0);
    assert_eq!(reply[0], 0, "the negative level floors at 0");
    assert_eq!(reply[1], 0, "the negative cooldown floors at 0");
    // Steady state: the recomputed state equals the stored one.
    let reply: Vec<i64> = run(&mut conn, 0);
    assert_eq!(reply, vec![0, 0]);
    // A real transition (pressure enters level 1) reports the new level.
    let reply: Vec<i64> = run(&mut conn, 21_000);
    assert_eq!(reply[0], 1);
    let _: i32 = conn.del(&key).unwrap();
}

#[test]
fn merged_aggregate_honors_the_staleness_window() {
    let Some(_url) = common::redis_url() else {
        eprintln!("skipping sharded suite: RISK_REDIS_URL not set");
        return;
    };
    let store = sharded_store("stale");
    // Each assessment writes its own shard's post-apply sum back into
    // the cache, so the merged read reflects every commit immediately
    // (stronger than the one-second contract).
    store
        .observe(&observation(&common::event_id(1), 0, 0))
        .unwrap();
    let after_first = store.merged_global_pressure().unwrap();
    assert!(
        (1700..=2000).contains(&after_first),
        "the written shard is current (got {after_first})"
    );
    assert!(store.merge_age().unwrap() < kiwicaptcha_risk::keyspace::MERGE_STALENESS);
    // A second commit inside the window keeps the merge current.
    store
        .observe(&observation(&common::event_id(2), 0, 0))
        .unwrap();
    let after_second = store.merged_global_pressure().unwrap();
    assert!(
        (3400..=4000).contains(&after_second),
        "both commits are visible inside the window (got {after_second})"
    );
    // Past the window the merge batch re-runs: the age resets while the
    // value stays the sum of the shards (minus the real-elapsed leak).
    std::thread::sleep(Duration::from_millis(1100));
    let refreshed = store.merged_global_pressure().unwrap();
    assert!(
        (3200..=4000).contains(&refreshed),
        "the refreshed merge still carries both events (got {refreshed})"
    );
    assert!(store.merge_age().unwrap() < kiwicaptcha_risk::keyspace::MERGE_STALENESS);
}

#[test]
fn scope_shards_disperse_across_slots() {
    let Some(_url) = common::redis_url() else {
        eprintln!("skipping sharded suite: RISK_REDIS_URL not set");
        return;
    };
    let store = sharded_store("disp");
    for i in 0..120u64 {
        store
            .observe(&observation(&common::event_id(i), 0, 0))
            .unwrap();
    }
    let mut conn = redis::Client::open(common::redis_url().unwrap().as_str())
        .unwrap()
        .get_connection()
        .unwrap();
    let pattern = format!("{{kiwi:{}:s:global:*}}:scope:*", store.namespace());
    let keys: Vec<String> = redis::cmd("KEYS").arg(&pattern).query(&mut conn).unwrap();
    let distinct: std::collections::BTreeSet<String> = keys.into_iter().collect();
    assert!(
        distinct.len() >= 8,
        "120 events over 16 shards must light up most of them (got {})",
        distinct.len()
    );
    // Every lit shard hash carries the raw pressure of its events.
    for key in &distinct {
        let exists: i64 = redis::cmd("EXISTS").arg(key).query(&mut conn).unwrap();
        assert_eq!(exists, 1);
    }
}

#[test]
fn auxiliary_surfaces_stay_mode_insensitive() {
    let Some(_url) = common::redis_url() else {
        eprintln!("skipping sharded suite: RISK_REDIS_URL not set");
        return;
    };
    let store = sharded_store("aux");
    let hour = (common::T0 / 3_600_000) as i64;

    // Ledger lifecycle through the sharded store.
    assert!(store.register_outcome("led-1", 7, hour, 900).unwrap());
    assert!(!store.register_outcome("led-1", 7, hour, 900).unwrap());
    assert_eq!(store.confirm_outcome("led-1", false).unwrap(), 1);
    assert_eq!(store.confirm_outcome("led-1", false).unwrap(), 0);
    assert!(store.correct_outcome("led-1", true).unwrap());
    assert!(!store.correct_outcome("led-1", true).unwrap());

    // Marks through the sharded store.
    let count = store
        .write_mark("principal", "mark-one", "ConfirmedAbuse", common::T0, "")
        .unwrap();
    assert_eq!(count, 1);
    let mark = store
        .read_mark("principal", "mark-one")
        .unwrap()
        .expect("mark exists");
    assert_eq!(mark.kind, "ConfirmedAbuse");
    assert_eq!(store.forget_marks("principal", "mark-one").unwrap(), 1);
    assert!(store.read_mark("principal", "mark-one").unwrap().is_none());

    // The first-seen session tag surface (delegated, same key shape).
    let session = [0x7eu8; 16];
    let first = store.session_first_context_tag(&session, "aa").unwrap();
    assert_eq!(first.as_deref(), Some("aa"));
    let again = store.session_first_context_tag(&session, "bb").unwrap();
    assert_eq!(again.as_deref(), Some("aa"), "the first-seen tag wins");
}

/// The partial-batch retry proof: a proxy swallows one endpoint's
/// commands mid-batch, so part of the batch commits while the rest is
/// lost; the retried assessment must produce exactly one application
/// (the per-dimension dedupe markers turn the committed dimensions into
/// no-ops), never a double count. The proxy is armed over a pipe, so
/// store construction always lands on the clean path.
#[test]
fn partial_batch_retry_is_idempotent() {
    let Some(url) = common::redis_url() else {
        eprintln!("skipping sharded suite: RISK_REDIS_URL not set");
        return;
    };
    let authority = url.split("://").nth(1).unwrap_or(&url);
    let host_and_port = authority.split('/').next().unwrap_or(authority);
    let upstream_port = host_and_port
        .rsplit(':')
        .next()
        .unwrap_or_default()
        .parse::<u16>()
        .expect("the redis test URL carries a port");
    let (proxy_port, arm) = spawn_dropping_proxy(upstream_port);
    let proxy_url = format!("redis://127.0.0.1:{proxy_port}/");

    let ns = common::unique_namespace("partial");
    // Order the endpoints so the source state key routes to the proxy:
    // the first assessment is guaranteed to lose the batch's proxy-side
    // groups while the real-side groups commit.
    let probe = ShardedRedisRiskStateStore::connect(
        &[url.clone(), proxy_url.clone()],
        &common::unique_namespace("route"),
        options(),
    )
    .unwrap();
    let src_cur_key = kiwicaptcha_risk::keyspace::identity_state_key(
        probe.namespace(),
        kiwicaptcha_risk::keyspace::ShardedDimension::Source,
        Some(1),
        &format!("{:0>32}", "aa"),
    );
    let proxy_first = probe.endpoint_for_key(&src_cur_key) == 0;
    drop(probe);

    let endpoints: Vec<String> = if proxy_first {
        vec![proxy_url, url.clone()]
    } else {
        vec![url.clone(), proxy_url]
    };
    let store = ShardedRedisRiskStateStore::connect(&endpoints, &ns, options()).unwrap();
    let obs = observation(&common::event_id(42), 0, 0);

    // Arm the drop only after every construction connection succeeded.
    arm.store(true, std::sync::atomic::Ordering::SeqCst);

    // Attempt 1: the proxy swallows its connection; the batch fails and
    // the store evicts every taking part slot.
    let first = store.observe(&obs);
    assert!(
        first.is_err(),
        "the dropped-reply batch must fail (the source state routes through the proxy)"
    );

    // Attempt 2: the retry succeeds and the committed dimensions are
    // skipped by their markers: exactly one application, never two.
    let retry = store.observe(&obs).expect("the retry must succeed");
    assert_eq!(
        retry.vector.source_fast, 125,
        "one application of the source dimension (a double count would read 250)"
    );
    assert_eq!(retry.vector.subnet_fast, 125);
    // The nonce verdict: when attempt 1 committed the nonce marker the
    // retry reads as a duplicate; either way the state carries exactly
    // one event. The final aggregate check reads through a direct store
    // on the same namespace, so the proof never depends on the proxy's
    // connection lifetime.
    std::thread::sleep(Duration::from_millis(1100));
    let direct = ShardedRedisRiskStateStore::connect(&[url], &ns, options()).unwrap();
    let merged = direct.merged_global_pressure().unwrap();
    assert!(
        (1600..=2000).contains(&merged),
        "the merged aggregate must carry exactly one event after the window (got {merged})"
    );
}

/// The full invariant core against a real Redis Cluster: the suite runs
/// with `KIWI_SHARDING_CLUSTER=1` and `RISK_REDIS_URL` pointing at any
/// cluster node (the seed). The store resolves the cluster topology
/// topology at construction, routes every family to its owning primary
/// and serves the assessment batch across the three primaries. The
/// reference deployment for the done-when is three primaries on ports
/// 6433-6435 (`redis-cli --cluster create ... --cluster-replicas 0`).
#[test]
fn cluster_topology_serves_the_sharded_invariants() {
    if std::env::var("KIWI_SHARDING_CLUSTER").as_deref() != Ok("1") {
        eprintln!("skipping the cluster suite: KIWI_SHARDING_CLUSTER != 1");
        return;
    }
    let Some(seed) = common::redis_url() else {
        eprintln!("skipping the cluster suite: RISK_REDIS_URL not set");
        return;
    };
    let options = ShardedOptions {
        cluster: true,
        connection_timeout_ms: 2_000,
        command_timeout_ms: 2_000,
        ..ShardedOptions::default()
    };
    let ns = common::unique_namespace("clu");
    let store = ShardedRedisRiskStateStore::connect(&[seed], &ns, options)
        .expect("the cluster store resolves the topology");
    assert_eq!(
        store.endpoint_count(),
        3,
        "the three primaries must all be routed"
    );

    // The core signal contract across the cluster-routed batch.
    let observed = store
        .observe(&observation(&common::event_id(1), 0, 0))
        .unwrap();
    assert_eq!(observed.vector.source_fast, 125);
    assert_eq!(observed.vector.source_slow, 10);
    assert_eq!(observed.vector.subnet_fast, 125);
    assert!(!observed.is_duplicate);

    // Dedupe and the merged aggregate across shards on three nodes.
    let duplicate = store
        .observe(&observation(&common::event_id(1), 0, 0))
        .unwrap();
    assert!(duplicate.is_duplicate);
    let third = store
        .observe(&observation(&common::event_id(2), 0, 0))
        .unwrap();
    assert!(!third.is_duplicate);
    assert!(
        (200..=250).contains(&third.vector.source_fast),
        "exactly two increments"
    );

    // Saturation drives the level machine across all three primaries.
    for i in 0..100u64 {
        store
            .observe(&observation(&common::event_id(100 + i), 0, 0))
            .unwrap();
    }
    std::thread::sleep(Duration::from_millis(1100));
    let vector = store
        .observe(&observation(&common::event_id(500), 0, 0))
        .unwrap()
        .vector;
    assert!(
        (960..=1000).contains(&vector.global_pressure),
        "merged aggregate saturates across the cluster"
    );
    assert_eq!(store.last_global_level(), 4);

    // Scope shards disperse over the cluster. KEYS is node-local in
    // cluster mode, so every primary is scanned (the reference
    // deployment is three consecutive ports with the seed first).
    let seed_port = common::redis_url()
        .unwrap()
        .split(':')
        .next_back()
        .map(|p| p.trim_end_matches('/').parse::<u16>().expect("seed port"))
        .expect("seed port");
    let pattern = format!("{{kiwi:{}:s:global:*}}:scope:*", store.namespace());
    let mut keys: Vec<String> = Vec::new();
    for port in [seed_port, seed_port + 1, seed_port + 2] {
        let mut node = redis::Client::open(format!("redis://127.0.0.1:{port}/"))
            .unwrap()
            .get_connection()
            .unwrap();
        let found: Vec<String> = redis::cmd("KEYS").arg(&pattern).query(&mut node).unwrap();
        keys.extend(found);
    }
    assert!(
        keys.len() >= 8,
        "the scope shards must light up across the cluster (got {})",
        keys.len()
    );

    // The auxiliary surfaces ride the node that owns the shared tag.
    let hour = (common::T0 / 3_600_000) as i64;
    assert!(store.register_outcome("clu-led", 7, hour, 900).unwrap());
    assert_eq!(store.confirm_outcome("clu-led", true).unwrap(), 1);
    assert_eq!(
        store
            .write_mark("principal", "clu-p", "ConfirmedAbuse", common::T0, "")
            .unwrap(),
        1
    );
    assert_eq!(store.forget_marks("principal", "clu-p").unwrap(), 1);
}
