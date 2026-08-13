//! AUDIT #34 — TRUST-BOUNDARY PROPERTY TEST (mirror of the PHP
//! RiskPropertyTest).
//!
//! The SignalVector carries NO client-visible fields: every one of its 13
//! fields is server-derived (the risk-v1.lua state channels and the
//! classifier's network-risk side channel), so "perturbing client-
//! controlled inputs of a vector" is impossible — the vector-level
//! property holds trivially (monotonicity of every field is already
//! covered by fuzz.rs). The REAL boundary is the engine: RiskContext
//! fields (scope, source_ip, session_id, principal_id, idempotency key,
//! event) are client-visible.
//!
//! The invariant: for IDENTICAL server state, assess() with client-
//! supplied session/principal/idempotency fields NEVER yields a score
//! lower than the same assessment without them. Subtlety: different IPs
//! produce different pseudonyms with different state, so the property is
//! constrained to IDENTICAL server state — fresh keys per iteration (two
//! FRESH namespaces: baseline vs varied, bit-identical empty state). With
//! empty state the Lua's aggregation (risk-v1.lua: source/session/
//! principal dimensions MAX into the signal channels — they never
//! subtract) leaves every signal unchanged when a fresh session/principal
//! is added, so the invariant must hold; the 500 randomized iterations
//! below pin it.
//!
//! Redis-gated (skipped unless RISK_REDIS_URL is set).

mod common;

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use kiwicaptcha_risk::context::RiskContext;
use kiwicaptcha_risk::event::RiskEventKind;
use kiwicaptcha_risk::keys::RiskKeys;
use kiwicaptcha_risk::network::NetworkFlags;
use kiwicaptcha_risk::policy::RiskPolicy;
use kiwicaptcha_risk::redis::RedisRiskStateStore;
use kiwicaptcha_risk::resources::ResourcePressure;
use kiwicaptcha_risk::score::{score, RiskWeights};
use kiwicaptcha_risk::RiskEngine;

const ITERATIONS: usize = 500;

fn policy() -> Arc<RiskPolicy> {
    Arc::new(
        RiskPolicy::from_config(
            3,
            &serde_json::json!({
                "version": 3,
                "weights": {
                    "source_fast": 190, "source_slow": 110, "subnet_fast": 80,
                    "issue_debt": 150, "bad_proof": 220, "malformed": 260,
                    "replay": 320, "action_failure": 120, "scope_switch": 60,
                    "global_pressure": 170, "network_risk": 100,
                    "trust_credit": 130, "principal_credit": 100
                },
                "scopes": {
                    "1": { "base_risk": 100, "minimum": "allow", "post_solve_check": true, "degraded": "sha20" },
                    "2": { "base_risk": 200, "minimum": "allow", "post_solve_check": true, "degraded": "sha20" },
                    "3": { "base_risk": 300, "minimum": "allow", "post_solve_check": true, "degraded": "sha20" }
                },
                "global_floors": { "0": "allow", "1": "sha16", "2": "sha18", "3": "sha20", "4": "sha20" }
            }),
        )
        .expect("config parses")
    )
}

fn keys() -> RiskKeys {
    RiskKeys::from_master(&[0x42; 32])
}

fn client() -> redis::Client {
    redis::Client::open(common::redis_url().expect("RISK_REDIS_URL set")).expect("url parses")
}

fn random_ip(state: &mut u64) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(
        (1 + common::lcg_next(state) % 254) as u8,
        (common::lcg_next(state) % 256) as u8,
        (common::lcg_next(state) % 256) as u8,
        (1 + common::lcg_next(state) % 254) as u8,
    ))
}

/// Client-supplied identity value (None a quarter of the time).
fn random_value(state: &mut u64, prefix: &str) -> Option<Vec<u8>> {
    if common::lcg_next(state).is_multiple_of(4) {
        return None;
    }
    Some(
        format!(
            "{prefix}-{}-{}-{}",
            common::lcg_next(state),
            common::lcg_next(state),
            common::lcg_next(state)
        )
        .into_bytes(),
    )
}

fn context<'a>(
    scope: u32,
    ip: IpAddr,
    session: Option<&'a [u8]>,
    principal: Option<&'a [u8]>,
) -> RiskContext<'a> {
    RiskContext::new(
        scope,
        ip,
        session,
        principal,
        RiskEventKind::PreIssue,
        NetworkFlags::default(),
        ResourcePressure::default(),
    )
}

/// Vector-level property (documented, holds trivially): the 13-field
/// SignalVector is the server-derived contract set and the scorer is a
/// pure function of it.
#[test]
fn signal_vector_has_no_client_controlled_fields() {
    let weights = RiskWeights::default();
    let mut state = 42u64;
    let vector = common::vector(&mut state);
    // Identical vectors score identically (pure function).
    assert_eq!(score(100, &vector, &weights), score(100, &vector, &weights));
    // Field set is exactly the contract's 13 server-derived fields.
    let json = serde_json::to_value(vector).expect("serializes");
    let object = json.as_object().expect("object");
    assert_eq!(object.len(), 13);
}

/// Engine-level trust-boundary invariant, 500 randomized iterations
/// against real Redis (skipped without RISK_REDIS_URL).
#[test]
fn client_supplied_identity_fields_never_lower_the_score() {
    let Some(_url) = common::redis_url() else {
        eprintln!("skipping trust-boundary property test: RISK_REDIS_URL not set");
        return;
    };
    let client = client();
    let mut state = 42u64;

    for i in 0..ITERATIONS {
        let scope = 1 + (common::lcg_next(&mut state) % 3) as u32;
        let ip = random_ip(&mut state);
        let session = random_value(&mut state, "sess");
        let principal = random_value(&mut state, "prin");
        let idem = random_value(&mut state, "idem");

        // Two FRESH namespaces = bit-identical EMPTY server state: the
        // score is a pure function of the state, and the varied context
        // differs from the baseline ONLY in the client-supplied fields.
        let baseline_store =
            RedisRiskStateStore::new(client.clone(), &common::unique_namespace("propb"));
        let varied_store =
            RedisRiskStateStore::new(client.clone(), &common::unique_namespace("propv"));
        let baseline_engine = RiskEngine::new(
            baseline_store,
            kiwicaptcha_risk::network::CidrNetworkClassifier::from_entries(Vec::new()),
            policy(),
            keys(),
        );
        let varied_engine = RiskEngine::new(
            varied_store,
            kiwicaptcha_risk::network::CidrNetworkClassifier::from_entries(Vec::new()),
            policy(),
            keys(),
        );

        let baseline = baseline_engine
            .assess_pre_issue(context(scope, ip, None, None), None)
            .expect("baseline assessment");
        let varied = varied_engine
            .assess_pre_issue(
                context(scope, ip, session.as_deref(), principal.as_deref()),
                idem.as_ref()
                    .map(|v| String::from_utf8(v.clone()).expect("utf8")),
            )
            .expect("varied assessment");

        assert!(
            varied.score >= baseline.score,
            "iteration {i}: client-supplied identity fields lowered the score from {} to {} \
             (scope={scope} ip={ip} session={session:?} principal={principal:?} idempotency={idem:?})",
            baseline.score,
            varied.score
        );
    }
}
