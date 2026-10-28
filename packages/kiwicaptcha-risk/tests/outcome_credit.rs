//! Outcome credit under real Redis, both store layouts.
//!
//! The transitions of the credit path a retry, a redelivery or two
//! racing workers can reach: the pending ledger registration folded into
//! the consolidated assessment, the retried target-failure report and
//! the step-up trust credit on the sharded identity tables.
//!
//! The invariants: the ledger score equals the score of the decision the
//! caller received, one report event id books one target failure, and a
//! step-up completion credits the same trust in every keyspace layout.
//!
//! Every test skips (prints a notice and returns) unless the Redis test
//! URL is set, like the sibling lanes.

mod common;

use std::collections::HashMap;
use std::sync::Arc;
use std::thread;

use kiwicaptcha_risk::context::{RiskContext, RiskV2Context};
use kiwicaptcha_risk::event::RiskEventKind;
use kiwicaptcha_risk::keys::RiskKeys;
use kiwicaptcha_risk::network::NetworkFlags;
use kiwicaptcha_risk::outcomes::{KiwiOutcomes, Outcome, OutcomeHandle};
use kiwicaptcha_risk::policy::{RiskPolicy, RiskReason};
use kiwicaptcha_risk::redis::RedisRiskStateStore;
use kiwicaptcha_risk::resources::ResourcePressure;
use kiwicaptcha_risk::store::RiskStateStore;
use kiwicaptcha_risk::target::FormFieldTargetResolver;
use kiwicaptcha_risk::RiskEngine;
use serde_json::json;

const TARGET_FIELD: &str = "username";
const TARGET_VALUE: &str = "victim@example.com";
const TARGET_PSEUDONYM: &str = "5e2a9b4c1d7f38e6a0b5c9d2e4f6a813";

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
    map.insert(1u32, TARGET_FIELD.to_string());
    Arc::new(FormFieldTargetResolver::new(map))
}

fn target_fields<'a>() -> [(&'a str, &'a str); 1] {
    [(TARGET_FIELD, TARGET_VALUE)]
}

fn context<'a>(
    event: RiskEventKind,
    ip: &'a str,
    fields: &'a [(&'a str, &'a str)],
) -> RiskContext<'a> {
    RiskContext::new(
        1,
        ip.parse().unwrap(),
        None,
        None,
        event,
        NetworkFlags::default(),
        ResourcePressure::default(),
    )
    .with_target_fields(fields)
}

fn redis_store(url: &str, namespace: &str) -> RedisRiskStateStore {
    RedisRiskStateStore::new(redis::Client::open(url).expect("url parses"), namespace)
        .with_io_timeouts(2_000, 2_000)
}

fn engine(store: RedisRiskStateStore) -> RiskEngine<RedisRiskStateStore> {
    RiskEngine::new(store, policy(), RiskKeys::from_master(&[0x42; 32]))
        .with_target_resolver(resolver())
}

/// Reads one ledger entry as raw JSON, or None when the key is absent.
fn ledger_entry(url: &str, key: &str) -> Option<serde_json::Value> {
    let client = redis::Client::open(url).expect("url parses");
    let mut conn = client.get_connection().expect("connection");
    let raw: Option<String> = redis::cmd("GET").arg(key).query(&mut conn).expect("GET");
    raw.map(|text| serde_json::from_str(&text).expect("ledger JSON"))
}

/// The consolidated ledger score is the score of the decision the caller
/// received, on the classic and on the sharded layout, with and without
/// a risk-v2 context. A v1 assessment applies no v2 evidence factor, so
/// its ledger must carry no target, honeypot or tag contribution.
#[test]
fn the_consolidated_ledger_score_is_the_decision_score() {
    let Some(url) = common::redis_url() else {
        eprintln!("skipping: RISK_REDIS_URL not set");
        return;
    };
    let namespace = common::unique_namespace("occredit");
    let store = redis_store(&url, &namespace);
    let engine = engine(redis_store(&url, &namespace));

    // Seed two recorded failures against the target, so a live pressure
    // and spread ride the assessment's reply.
    let target = engine
        .resolve_target_id(1, &target_fields())
        .expect("target resolves");
    store
        .register_target_failure(&target, "seed-source-1", "seed-asn-1")
        .expect("seeded failure");
    store
        .register_target_failure(&target, "seed-source-2", "seed-asn-2")
        .expect("seeded failure");

    for (label, decision) in [
        (
            "target failure event",
            engine
                .assess_pre_issue(
                    context(
                        RiskEventKind::AuthenticationFailure,
                        "198.51.100.23",
                        &target_fields(),
                    ),
                    None,
                )
                .expect("assessment"),
        ),
        (
            "pre-issue with a live target",
            engine
                .assess_pre_issue(
                    context(RiskEventKind::PreIssue, "198.51.100.24", &target_fields()),
                    None,
                )
                .expect("assessment"),
        ),
        (
            "honeypot event",
            engine
                .assess_pre_issue(
                    context(
                        RiskEventKind::HoneypotTriggered,
                        "198.51.100.25",
                        &target_fields(),
                    ),
                    None,
                )
                .expect("assessment"),
        ),
        (
            "risk-v2 context",
            engine
                .assess_pre_issue_v2(
                    context(RiskEventKind::PreIssue, "198.51.100.26", &target_fields()),
                    &RiskV2Context::default(),
                    None,
                    None,
                )
                .expect("assessment"),
        ),
    ] {
        let key = store.outcome_ledger_key(&decision.decision_id);
        let ledger = ledger_entry(&url, &key).unwrap_or_else(|| panic!("{label}: ledger exists"));
        assert_eq!(ledger["o"], "P", "{label}: the entry is pending");
        assert_eq!(
            ledger["score"].as_u64(),
            Some(u64::from(decision.score)),
            "{label}: the ledger score must equal the decision score"
        );
    }
}

/// One report event id books one target failure: redeliveries racing on
/// the same idempotency key cannot inflate the leaky counter.
#[test]
fn a_retried_target_failure_report_books_one_failure() {
    let Some(url) = common::redis_url() else {
        eprintln!("skipping: RISK_REDIS_URL not set");
        return;
    };
    let namespace = common::unique_namespace("occredit");
    let store = redis_store(&url, &namespace);
    let engine = engine(redis_store(&url, &namespace));
    let handle = OutcomeHandle::target(TARGET_PSEUDONYM).expect("target handle");

    // The facade is built inside each worker: the trait object form is
    // not shareable across threads, the store and the engine are.
    let shared_engine = &engine;
    let shared_store = &store;
    let shared_handle = &handle;
    thread::scope(|scope| {
        let mut handles = Vec::new();
        for _ in 0..8 {
            handles.push(scope.spawn(move || {
                let fields = target_fields();
                let outcomes = KiwiOutcomes::new(
                    shared_engine,
                    shared_store as &dyn kiwicaptcha_risk::outcomes::OutcomeMarksStore,
                );
                outcomes
                    .report(
                        Outcome::AuthenticationFailure,
                        shared_handle,
                        Some("webhook-delivery-1".to_string()),
                        Some(context(
                            RiskEventKind::AuthenticationFailure,
                            "198.51.100.31",
                            &fields,
                        )),
                    )
                    .expect("report")
            }));
        }
        for handle in handles {
            let receipt = handle.join().expect("worker");
            assert!(
                receipt.channel_booked,
                "the report books the mapped channel"
            );
        }
    });

    let state = RiskStateStore::read_target_state(&store, TARGET_PSEUDONYM).expect("target state");
    assert_eq!(
        state.fails, 1,
        "eight concurrent deliveries of one report book one target failure"
    );
}

/// A step-up completion credits trust on the sharded identity tables
/// exactly like the classic script, and never fails the batch.
#[test]
fn a_sharded_step_up_completion_credits_trust() {
    let Some(url) = common::redis_url() else {
        eprintln!("skipping: RISK_REDIS_URL not set");
        return;
    };

    let namespace = common::unique_namespace("occredit");
    let sharded = kiwicaptcha_risk::sharded::ShardedRedisRiskStateStore::connect(
        std::slice::from_ref(&url),
        &namespace,
        kiwicaptcha_risk::sharded::ShardedOptions {
            connection_timeout_ms: 2_000,
            command_timeout_ms: 2_000,
            ..kiwicaptcha_risk::sharded::ShardedOptions::default()
        },
    )
    .expect("sharded store");

    // One identity per worker, so each reply is exact: a fresh source
    // and principal answer the first credit of their own state.
    let observation = |n: u64, event_id: String| {
        common::observation(
            RiskEventKind::StepUpCompleted,
            1,
            format!("{:0>32x}", n + 1),
            format!("{:0>32x}", n + 100),
            None,
            Some([n as u8 + 1; 16]),
            event_id,
            common::T0,
        )
    };

    thread::scope(|scope| {
        let mut handles = Vec::new();
        let shared = &sharded;
        for n in 0..4u64 {
            let operation = observation(n, common::event_id(2_000 + n));
            handles.push(scope.spawn(move || {
                shared
                    .observe(&operation)
                    .expect("sharded step-up observation")
            }));
        }
        for handle in handles {
            let observed = handle.join().expect("worker");
            assert_eq!(
                observed.vector.trust_credit, 80,
                "a sharded step-up credits the source/session trust"
            );
            assert_eq!(
                observed.vector.principal_credit, 200,
                "a sharded step-up credits the principal trust"
            );
        }
    });

    // The classic layout answers the identical signal slots, so the two
    // keyspaces can never disagree about what a completed step-up is
    // worth.
    let classic = redis_store(&url, &common::unique_namespace("occredit"));
    let observed = classic
        .observe(&observation(9, common::event_id(3_000)))
        .expect("classic step-up observation");
    assert_eq!(observed.vector.trust_credit, 80, "classic trust credit");
    assert_eq!(
        observed.vector.principal_credit, 200,
        "classic principal credit"
    );

    // The raced credit left no poisoned state behind: an assessment on
    // the sharded namespace is not degraded.
    let decision = engine(redis_store(&url, &namespace))
        .assess_pre_issue(context(RiskEventKind::PreIssue, "198.51.100.41", &[]), None)
        .expect("assessment after the race");
    assert!(
        !decision.has_reason(RiskReason::CapacityPressure),
        "a sharded assessment after the raced credit is not degraded ({:?})",
        decision.action
    );
    assert!(decision.score > 0, "the assessment scores normally");
}
