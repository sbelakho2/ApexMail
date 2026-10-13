//! Target-account protection in the decision path (the H2 done-when):
//! a login assessment that resolves a target through the wired resolver
//! reads the target's failure state, feeds it into scoring as the
//! target_failure_pressure and target_spread signals, and hands the
//! resolved pseudonym to the marks stage, whose attacked-target rule
//! maps an attacked account to exactly the interactive step-up.
//!
//! Proven over both store layouts: the classic consolidated script
//! (the target family rides the assessment atomically) and the sharded
//! batch (the target read rides the main batch, the failure write its
//! second phase). The outcome bridge (an AuthenticationFailure outcome
//! reported against a target handle) is the write path for failures
//! observed outside the assessment itself.

mod common;

use std::sync::Arc;

use kiwicaptcha_risk::action::RiskAction;
use kiwicaptcha_risk::context::{RiskContext, RiskV2Context};
use kiwicaptcha_risk::event::RiskEventKind;
use kiwicaptcha_risk::keys::RiskKeys;
use kiwicaptcha_risk::marks::{StoreMarksReader, TARGET_ATTACK_THRESHOLD};
use kiwicaptcha_risk::network::CidrNetworkClassifier;
use kiwicaptcha_risk::network::NetworkFlags;
use kiwicaptcha_risk::outcomes::{KiwiOutcomes, Outcome, OutcomeHandle};
use kiwicaptcha_risk::policy::{RiskPolicy, RiskReason};
use kiwicaptcha_risk::resources::ResourcePressure;
use kiwicaptcha_risk::store::RiskStateStore;
use kiwicaptcha_risk::target::FormFieldTargetResolver;
use kiwicaptcha_risk::RiskEngine;
use serde_json::json;
use std::collections::HashMap;

fn policy() -> Arc<RiskPolicy> {
    Arc::new(
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
        .expect("config parses"),
    )
}

fn resolver() -> Arc<FormFieldTargetResolver> {
    let mut map = HashMap::new();
    map.insert(1u32, "username".to_string());
    Arc::new(FormFieldTargetResolver::new(map))
}

fn login_ctx<'a>(target_fields: &'a [(&'a str, &'a str)]) -> RiskContext<'a> {
    RiskContext::new(
        1,
        "198.51.100.23".parse().unwrap(),
        None,
        None,
        RiskEventKind::PreIssue,
        NetworkFlags::default(),
        ResourcePressure::default(),
    )
    .with_target_fields(target_fields)
}

fn failure_ctx<'a>(ip: &str, target_fields: &'a [(&'a str, &'a str)]) -> RiskContext<'a> {
    RiskContext::new(
        1,
        ip.parse().unwrap(),
        None,
        None,
        RiskEventKind::AuthenticationFailure,
        NetworkFlags::default(),
        ResourcePressure::default(),
    )
    .with_target_fields(target_fields)
}

/// A clean login against a fresh target stays the plain allow: no
/// failures anywhere, no target signal, no step-up.
#[test]
fn clean_login_against_a_fresh_target_stays_allow() {
    let Some(url) = common::redis_url() else {
        eprintln!("skipping: RISK_REDIS_URL not set");
        return;
    };
    let namespace = common::unique_namespace("tgtclean");
    let client = redis::Client::open(url.as_str()).expect("url parses");
    let store = kiwicaptcha_risk::redis::RedisRiskStateStore::new(client, &namespace)
        .with_io_timeouts(2_000, 2_000);
    let marks_store = kiwicaptcha_risk::redis::RedisRiskStateStore::new(
        redis::Client::open(url.as_str()).unwrap(),
        &namespace,
    )
    .with_io_timeouts(2_000, 2_000);
    let engine = RiskEngine::new(
        store,
        CidrNetworkClassifier::from_entries(vec![]),
        policy(),
        RiskKeys::from_master(&[0x42; 32]),
    )
    .with_target_resolver(resolver())
    .with_marks_reader(Arc::new(StoreMarksReader::new(Arc::new(marks_store))));

    let fields = [("username", "victim@example.com")];
    let decision = engine
        .reassess_v2(login_ctx(&fields), &RiskV2Context::default(), None, None)
        .expect("assessment");
    assert_eq!(decision.action, RiskAction::Allow);
    assert!(!decision.has_reason(RiskReason::TargetUnderAttack));
}

/// N accumulated failures against one target escalate the target's next
/// login to the interactive step-up: the failure assessments record the
/// leaky counter through the consolidated target block, the marks stage
/// compiles the attacked-target record from the live state, and rule 3
/// maps it to exactly StepUp (never a lockout).
#[test]
fn accumulated_target_failures_step_the_next_login_up() {
    let Some(url) = common::redis_url() else {
        eprintln!("skipping: RISK_REDIS_URL not set");
        return;
    };
    let namespace = common::unique_namespace("tgtfail");
    let build_store = || {
        kiwicaptcha_risk::redis::RedisRiskStateStore::new(
            redis::Client::open(url.as_str()).unwrap(),
            &namespace,
        )
        .with_io_timeouts(2_000, 2_000)
    };
    let store = build_store();
    let marks_store = build_store();
    let engine = RiskEngine::new(
        store,
        CidrNetworkClassifier::from_entries(vec![]),
        policy(),
        RiskKeys::from_master(&[0x42; 32]),
    )
    .with_target_resolver(resolver())
    .with_marks_reader(Arc::new(StoreMarksReader::new(Arc::new(marks_store))));

    let fields = [("username", "victim@example.com")];

    // The attacker hammers the login form: every attempt is an
    // AuthenticationFailure observation whose assessment records one
    // leaky-bucket failure against the target (fresh event ids, no
    // duplicates, distinct sources feeding the spread).
    for i in 0..TARGET_ATTACK_THRESHOLD {
        let ip = format!("203.0.113.{i}");
        let decision = engine
            .reassess_v2(
                failure_ctx(&ip, &fields),
                &RiskV2Context::default(),
                Some(format!("stuffing-attempt-{i}")),
                None,
            )
            .expect("failure assessment");
        // The target stage may already step an attempt up once the
        // counter reaches the threshold (the fifth attempt sees its own
        // fifth failure), but it never denies an attacker attempt here.
        assert_ne!(
            decision.action,
            RiskAction::Deny,
            "attempt {i} must not be denied ({:?})",
            decision.action
        );
        if i == 0 {
            assert!(
                decision.action.rank() < RiskAction::StepUp.rank(),
                "the first attempt rides the plain evidence ladder ({:?})",
                decision.action
            );
        }
    }

    // The victim's clean login is now the interactive step-up with the
    // target-under-attack reason, and the numeric score carries the
    // saturated target-failure pressure (never a lockout).
    let decision = engine
        .reassess_v2(login_ctx(&fields), &RiskV2Context::default(), None, None)
        .expect("victim login");
    assert_eq!(
        decision.action,
        RiskAction::StepUp,
        "an attacked target's login must step up ({:?})",
        decision.action
    );
    assert!(
        decision.has_reason(RiskReason::TargetUnderAttack),
        "the step-up carries the target-under-attack reason ({:?})",
        decision.reasons
    );
}

/// A target whose failure spray exceeds the spread threshold raises the
/// numeric decision: the outcome bridge stores the failures with their
/// distinct source/asn spread elements, and the next assessment's
/// consolidated reply carries the spread into score_v2 through the
/// existing signal-evaluation path.
#[test]
fn wide_target_spread_raises_the_numeric_decision() {
    let Some(url) = common::redis_url() else {
        eprintln!("skipping: RISK_REDIS_URL not set");
        return;
    };
    let namespace = common::unique_namespace("tgtspread");
    let build_store = || {
        kiwicaptcha_risk::redis::RedisRiskStateStore::new(
            redis::Client::open(url.as_str()).unwrap(),
            &namespace,
        )
        .with_io_timeouts(2_000, 2_000)
    };
    let store = build_store();
    let outcomes_store = build_store();
    let engine = RiskEngine::new(
        store,
        CidrNetworkClassifier::from_entries(vec![]),
        policy(),
        RiskKeys::from_master(&[0x42; 32]),
    )
    .with_target_resolver(resolver());
    let outcomes = KiwiOutcomes::new(&engine, &outcomes_store);

    let fields = [("username", "sprayed@example.com")];
    let target_id = engine
        .resolve_target_id(1, &fields)
        .expect("the resolver resolves the sprayed target");

    // The control login before any failure: the plain base score.
    let control = engine
        .reassess_v2(login_ctx(&fields), &RiskV2Context::default(), None, None)
        .expect("control login");

    // The outcome bridge reports the spray: distinct attacker networks,
    // one authentication failure each, far beyond the spread threshold.
    for i in 0..24u32 {
        let octet = 10 + (i / 250);
        let ip = format!("198.51.{}.{}", octet, 30 + i);
        let ctx = RiskContext::new(
            1,
            ip.parse().unwrap(),
            None,
            None,
            RiskEventKind::AuthenticationFailure,
            NetworkFlags::default(),
            ResourcePressure::default(),
        );
        outcomes
            .report(
                Outcome::AuthenticationFailure,
                &OutcomeHandle::target(&target_id).expect("target handle"),
                Some(format!("spray-{i}")),
                Some(ctx),
            )
            .expect("the bridge stores the failure");
    }

    // The next login carries the saturated spread signal: strictly above
    // the control score, through the same signal-evaluation path.
    let decision = engine
        .reassess_v2(login_ctx(&fields), &RiskV2Context::default(), None, None)
        .expect("post-spray login");
    assert!(
        decision.score > control.score,
        "the sprayed target's login must outscore the control ({} vs {})",
        decision.score,
        control.score
    );
}

/// The sharded layout maintains the same target dimension: the read
/// rides the assessment batch, a failure observation writes through the
/// second phase, the outcome bridge lands on the target family slot,
/// and the consolidated reply feeds the score exactly like the classic
/// layout.
#[test]
fn sharded_store_maintains_the_target_dimension() {
    let Some(url) = common::redis_url() else {
        eprintln!("skipping: RISK_REDIS_URL not set");
        return;
    };
    let namespace = common::unique_namespace("tgtsharded");
    let store = kiwicaptcha_risk::sharded::ShardedRedisRiskStateStore::connect(
        std::slice::from_ref(&url),
        &namespace,
        kiwicaptcha_risk::sharded::ShardedOptions {
            connection_timeout_ms: 2_000,
            command_timeout_ms: 2_000,
            ..kiwicaptcha_risk::sharded::ShardedOptions::default()
        },
    )
    .expect("sharded store");

    let target_id = format!("{:0>64}", "5e2a");
    let registration = |decision_id: String| kiwicaptcha_risk::store::OutcomeRegistration {
        decision_id,
        decision_hour: 1,
        base_risk: 100,
        global_pressure_enabled: true,
        honeypot_hit: false,
        v1_weights: kiwicaptcha_risk::score::RiskWeights::default(),
        v2_weights: kiwicaptcha_risk::score::RiskV2Weights::default(),
        target_id: Some(target_id.clone()),
        target_source_element: String::new(),
        target_asn_element: String::new(),
    };
    let observation = |event, n: u64| {
        let mut o = common::observation(
            event,
            1,
            format!("{:0>32}", "aa"),
            format!("{:0>32}", "bb"),
            None,
            None,
            common::event_id(n),
            common::T0,
        );
        o.network_risk = 0;
        o
    };

    // Five failure observations against the target: each assessment's
    // second phase records one leaky-bucket failure.
    for n in 1..=u64::from(TARGET_ATTACK_THRESHOLD) {
        let reply = store
            .assess_v2(
                &observation(RiskEventKind::AuthenticationFailure, n),
                None,
                None,
                Some(&registration(format!("sharded-decision-{n}"))),
            )
            .expect("sharded consolidated assessment")
            .expect("consolidated capability");
        assert_eq!(
            reply.target_failures,
            u32::try_from(n).expect("in band"),
            "failure {n} must be recorded by the assessment"
        );
    }

    // A non-failure assessment still reads the live state back.
    let reply = store
        .assess_v2(
            &observation(RiskEventKind::PreIssue, 6),
            None,
            None,
            Some(&registration("sharded-decision-6".to_string())),
        )
        .expect("sharded consolidated assessment")
        .expect("consolidated capability");
    assert!(reply.target_failures >= 5, "the counter persists");

    // The outcome bridge lands on the same target family: the spread
    // grows through the sharded store's own routed ops.
    store
        .register_target_failure(&target_id, "source-element", "asn-element")
        .expect("bridge failure");
    let state = store.read_target_state(&target_id).expect("target state");
    assert_eq!(state.spread_sources, 1);
    assert_eq!(state.spread_asns, 1);
    assert!(state.fails >= 5);

    // The state lives on the target family's own tag: the sharded
    // keyspace builder's keys exist (each family slot stays owned by
    // the routed dispatch of the sharded store).
    let mut conn = redis::Client::open(url.as_str())
        .unwrap()
        .get_connection()
        .unwrap();
    use redis::Commands;
    let keys = kiwicaptcha_risk::keyspace::target_state_keys(
        &namespace,
        &target_id,
        kiwicaptcha_risk::keyspace::KeyspaceMode::Sharded,
    );
    for key in &keys {
        let exists: i64 = conn.exists(key).expect("exists");
        assert_eq!(exists, 1, "target key {key} must exist");
    }
}
