//! The explanation privacy contract (change.md 3.8.3): a decision
//! explanation carries contributor and dimension names only, never a
//! pseudonym value, a raw identifier or any derived hex. Hermetic (an
//! in-memory store; no Redis is contacted).

use std::net::IpAddr;
use std::sync::Arc;

use kiwicaptcha_risk::asn::AsnDataset;
use kiwicaptcha_risk::context::RiskContext;
use kiwicaptcha_risk::event::{RiskEventKind, RiskObservation};
use kiwicaptcha_risk::explanation::DecisionExplanation;
use kiwicaptcha_risk::identity::RiskIdentityFactory;
use kiwicaptcha_risk::identity_vector::{IdentityVector, IdentityVectorInput, DIMENSIONS};
use kiwicaptcha_risk::keys::RiskKeys;
use kiwicaptcha_risk::network::NetworkFlags;
use kiwicaptcha_risk::policy::RiskPolicy;
use kiwicaptcha_risk::signals::SignalVector;
use kiwicaptcha_risk::store::{
    Observed, RiskStateStore, RiskStoreError, SessionContextTagStore, SessionTlsTagStore,
};
use kiwicaptcha_risk::RiskEngine;

/// A raw-input canary set: if any of these strings ever appears in a
/// serialized explanation, the names-only contract is broken.
const CANARY_IP: &str = "203.0.113.27";
const CANARY_COOKIE_HEX: &str = "5ae1a4b8c0d1e2f30011223344556677";
const CANARY_PRINCIPAL: &str = "principal-canary-42";
const CANARY_AGENT: &str = "agent-canary-7";
const CANARY_TARGET: &str = "canary.user+leak@gmail.com";

struct HotStore;

impl RiskStateStore for HotStore {
    fn observe(&self, _o: &RiskObservation) -> Result<Observed, RiskStoreError> {
        Ok(Observed {
            vector: SignalVector {
                source_fast: 900,
                replay: 800,
                ..Default::default()
            },
            global_level: 0,
            cooldown_until_ms: 0,
            is_duplicate: false,
        })
    }
    fn register_outcome(
        &self,
        _decision_id: &str,
        _scope: u32,
        _decision_hour: i64,
        _score: u32,
    ) -> Result<bool, RiskStoreError> {
        Ok(true)
    }
    fn confirm_outcome(&self, _decision_id: &str, _legitimate: bool) -> Result<u8, RiskStoreError> {
        Ok(0)
    }
    fn correct_outcome(
        &self,
        _decision_id: &str,
        _legitimate: bool,
    ) -> Result<bool, RiskStoreError> {
        Ok(false)
    }
}

impl SessionContextTagStore for HotStore {}
impl SessionTlsTagStore for HotStore {}

#[derive(Default)]
struct NoRiskClassifier;

impl kiwicaptcha_risk::network::NetworkClassifier for NoRiskClassifier {
    fn classify(&self, _ip: IpAddr) -> NetworkFlags {
        NetworkFlags::default()
    }
}

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
                    "1": { "base_risk": 100, "minimum": "allow", "post_solve_check": false, "degraded": "sha20" }
                },
                "global_floors": { "0": "allow", "1": "sha16", "2": "sha18", "3": "sha20", "4": "sha20" }
            }),
        )
        .expect("config parses"),
    )
}

fn dataset() -> AsnDataset {
    AsnDataset::open(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../protocol/asn/sample-asn.tsv"),
    )
    .expect("sample dataset opens")
}

/// The canary identity vector of the request: every raw input and every
/// derived pseudonym that must stay out of the explanation.
fn canary_vector() -> (IdentityVector, Vec<String>) {
    let dataset = dataset();
    let factory = RiskIdentityFactory::new(RiskKeys::from_master(&[0x42; 32]));
    let cookie = hex::decode(CANARY_COOKIE_HEX).expect("hex cookie");
    let cookie: [u8; 16] = cookie.try_into().expect("16 cookie bytes");
    let descriptor = IdentityVectorInput {
        client_ip: CANARY_IP.parse().unwrap(),
        session_cookie: Some(&cookie),
        principal_id: Some(CANARY_PRINCIPAL.as_bytes()),
        agent_key_id: Some(CANARY_AGENT),
        target_normalized: Some("canary.user@gmail.com"),
        asn_dataset: &dataset,
        now_unix_secs: 1_700_000_000,
    };
    let vector = IdentityVector::derive(&descriptor, &factory);
    let mut values: Vec<String> = DIMENSIONS
        .iter()
        .filter_map(|name| vector.dimension(name).map(str::to_string))
        .collect();
    values.push(CANARY_TARGET.split('@').next().unwrap().to_string());
    (vector, values)
}

#[test]
fn serialized_explanations_never_carry_pseudonym_values_or_raw_inputs() {
    let (identity, forbidden_values) = canary_vector();

    // The engine surface: assess the canary request and serialize the
    // explained result.
    let engine = RiskEngine::new(
        HotStore,
        NoRiskClassifier,
        policy(),
        RiskKeys::from_master(&[0x42; 32]),
    );
    let cookie = hex::decode(CANARY_COOKIE_HEX).expect("hex cookie");
    let cookie: [u8; 16] = cookie.try_into().expect("16 cookie bytes");
    let ctx = RiskContext {
        scope: 1,
        source_ip: CANARY_IP.parse().unwrap(),
        session_id: Some(&cookie),
        principal_id: Some(CANARY_PRINCIPAL.as_bytes()),
        event: RiskEventKind::PreIssue,
        network_flags: NetworkFlags::default(),
        resources: Default::default(),
    };
    let explained = engine
        .assess_pre_issue_with_explanation(ctx, None)
        .expect("assessment succeeds");
    let serialized = serde_json::to_string(&explained).expect("serializes");
    eprintln!("explained decision: {serialized}");

    // Dimension names must appear (the involved dimensions), while no
    // dimension value and no raw input may.
    for name in explained.explanation().dimensions() {
        assert!(DIMENSIONS.contains(name), "unknown dimension name {name}");
    }
    assert!(serialized.contains("\"dimensions\":[\"source\""));
    for forbidden in &forbidden_values {
        assert!(
            !serialized.contains(forbidden.as_str()),
            "privacy hole: the serialized explanation carries {forbidden}"
        );
    }
    assert!(!serialized.contains(CANARY_IP));
    assert!(!serialized.contains(CANARY_COOKIE_HEX));
    assert!(!serialized.contains(CANARY_PRINCIPAL));
    assert!(!serialized.contains(CANARY_AGENT));
    assert!(!serialized.contains(CANARY_TARGET));
    // Hot signals produce named contributors: the reason surface works.
    assert!(!explained.explanation().reasons().is_empty());
    assert!(!explained.explanation().is_empty());

    // The composed full surface (every dimension name, a price rung
    // name) stays names-only for the identity vector's own dimensions.
    let full = DecisionExplanation::for_decision(
        explained.decision(),
        &identity.present_dimensions(),
        Some("sha20"),
    );
    let full_json = serde_json::to_string(&full).expect("serializes");
    for forbidden in &forbidden_values {
        assert!(
            !full_json.contains(forbidden.as_str()),
            "privacy hole: the composed explanation carries {forbidden}"
        );
    }
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&full_json).unwrap()["dimensions"],
        serde_json::json!([
            "source",
            "subnet",
            "asn",
            "session",
            "principal",
            "target",
            "agent"
        ]),
        "the composed explanation names every dimension in contract order"
    );
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&full_json).unwrap()["price_rung"],
        "sha20"
    );
}

#[test]
fn the_default_explanation_is_names_only_and_empty() {
    let empty = DecisionExplanation::empty();
    assert!(empty.is_empty());
    let json = serde_json::to_string(&empty).expect("serializes");
    assert_eq!(
        json,
        "{\"action\":\"allow\",\"reasons\":[],\"dimensions\":[],\"price_rung\":null}"
    );
}
