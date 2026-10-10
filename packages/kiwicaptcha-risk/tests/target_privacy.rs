//! Privacy scanner for the target dimension: a canary raw identifier
//! rides the resolver, the normalization pipeline and the engine
//! assessment, and the scan proves it exists nowhere except inside the
//! caller's own call frame.
//!
//! Emission surfaces scanned hermetically: every observation the engine
//! hands the state store (serialized whole, the exact material the store
//! forwards into the Redis script argv and keys) and the engine metrics
//! snapshot. The crate writes no logs and carries no logger, so those
//! surfaces are the complete emission boundary. With `RISK_REDIS_URL`
//! set the scan additionally applies the observation through the real
//! Redis store and scans the persisted state, mirroring `privacy.rs`.
//!
//! The stored and derived material is only the HMAC: the engine's target
//! side channel returns 64 lowercase hex chars, and neither the raw
//! canary nor its normalized form appears in any scanned surface.

mod common;

use std::net::IpAddr;
use std::sync::{Arc, Mutex};

use kiwicaptcha_risk::context::RiskContext;
use kiwicaptcha_risk::event::RiskEventKind;
use kiwicaptcha_risk::identity::RiskIdentityFactory;
use kiwicaptcha_risk::keys::RiskKeys;
use kiwicaptcha_risk::network::{CidrNetworkClassifier, NetworkFlags};
use kiwicaptcha_risk::policy::RiskPolicy;
use kiwicaptcha_risk::resources::ResourcePressure;
use kiwicaptcha_risk::store::{
    Observed, RiskStateStore, RiskStoreError, SessionContextTagStore, SessionTlsTagStore,
};
use kiwicaptcha_risk::target::{normalize_target, FormFieldTargetResolver};
use kiwicaptcha_risk::RiskEngine;

const CANARY: &str = "canary.target.7f3a@gmail.com";
const CANARY_FULLWIDTH: &str = "ｃａｎａｒｙ.target.7f3a+news@gmail.com";

/// Store spy: records every observation serialized whole, plus a blob of
/// every other store-call string (ledger ids, hours, scores), so the
/// scan covers the complete material the engine hands the backend. The
/// records live behind a shared handle, so the engine owns its store and
/// the test still reads what was recorded.
#[derive(Clone)]
struct CapturingTargetStore(Arc<Captured>);

struct Captured {
    observations: Mutex<Vec<String>>,
    calls: Mutex<Vec<String>>,
}

impl CapturingTargetStore {
    fn new() -> CapturingTargetStore {
        CapturingTargetStore(Arc::new(Captured {
            observations: Mutex::new(Vec::new()),
            calls: Mutex::new(Vec::new()),
        }))
    }

    fn observations(&self) -> Vec<String> {
        self.0.observations.lock().unwrap().clone()
    }

    fn blob(&self) -> String {
        let observations = self.0.observations.lock().unwrap();
        let calls = self.0.calls.lock().unwrap();
        let mut blob = observations.join("\n");
        blob.push('\n');
        blob.push_str(&calls.join("\n"));
        blob
    }
}

impl RiskStateStore for CapturingTargetStore {
    fn observe(
        &self,
        o: &kiwicaptcha_risk::event::RiskObservation,
    ) -> Result<Observed, RiskStoreError> {
        let serialized = serde_json::to_string(o).expect("the observation serializes");
        self.0.observations.lock().unwrap().push(serialized);
        Ok(Observed {
            vector: kiwicaptcha_risk::signals::SignalVector::zero(),
            global_level: 0,
            cooldown_until_ms: 0,
            is_duplicate: false,
        })
    }

    fn register_outcome(
        &self,
        decision_id: &str,
        scope: u32,
        decision_hour: i64,
        score: u32,
    ) -> Result<bool, RiskStoreError> {
        self.0.calls.lock().unwrap().push(format!(
            "register {decision_id} {scope} {decision_hour} {score}"
        ));
        Ok(true)
    }

    fn confirm_outcome(&self, decision_id: &str, legitimate: bool) -> Result<u8, RiskStoreError> {
        self.0
            .calls
            .lock()
            .unwrap()
            .push(format!("confirm {decision_id} {legitimate}"));
        Ok(1)
    }

    fn correct_outcome(&self, decision_id: &str, legitimate: bool) -> Result<bool, RiskStoreError> {
        self.0
            .calls
            .lock()
            .unwrap()
            .push(format!("correct {decision_id} {legitimate}"));
        Ok(true)
    }
}

// The spy declares no session-first-tag record surface: the default
// capability methods report `Ok(None)`, like a v1 store.
impl SessionContextTagStore for CapturingTargetStore {}
impl SessionTlsTagStore for CapturingTargetStore {}

fn policy() -> Arc<RiskPolicy> {
    let weights: serde_json::Value = serde_json::from_str(
        r#"{"source_fast":190,"source_slow":110,"subnet_fast":80,"issue_debt":150,
            "bad_proof":220,"malformed":260,"replay":320,"action_failure":120,
            "scope_switch":60,"global_pressure":170,"network_risk":100,
            "trust_credit":130,"principal_credit":100}"#,
    )
    .expect("weights parse");
    Arc::new(
        RiskPolicy::from_config(
            3,
            &serde_json::json!({
                "version": 3,
                "weights": weights,
                "scopes": {
                    "1": { "base_risk": 100, "minimum": "allow", "post_solve_check": true, "degraded": "sha20" }
                },
                "global_floors": { "0": "allow", "1": "sha16", "2": "sha18", "3": "sha20", "4": "sha20" }
            }),
        )
        .expect("config parses"),
    )
}

fn context() -> RiskContext<'static> {
    RiskContext {
        scope: 1,
        source_ip: "203.0.113.77".parse::<IpAddr>().unwrap(),
        session_id: None,
        principal_id: None,
        event: RiskEventKind::PreIssue,
        network_flags: NetworkFlags::default(),
        resources: ResourcePressure {
            argon_capacity: 1000,
            issuance_capacity: 1000,
        },
    }
}

#[test]
fn canary_never_reaches_store_calls_logs_or_metrics() {
    let store = CapturingTargetStore::new();
    let classifier = CidrNetworkClassifier::from_entries(vec![]);
    let mut field_names = std::collections::HashMap::new();
    field_names.insert(1u32, "email".to_string());
    let engine = RiskEngine::new(
        store.clone(),
        classifier,
        policy(),
        RiskKeys::from_master(&[0x42; 32]),
    )
    .with_target_resolver(Arc::new(FormFieldTargetResolver::new(field_names)));

    // The engine path and the target side channel run for the same
    // request: the assessment hands the store its observation while the
    // resolver derives the target pseudonym beside it.
    let ctx = context();
    let decision = engine
        .assess_pre_issue(ctx, None)
        .expect("the assessment decides");
    assert!(decision.score <= 1000);
    let fields = [("email", CANARY), ("password", "not-the-canary")];
    let target_id = engine.resolve_target_id(1, &fields).expect("a target id");

    // The derived material is only the HMAC: 64 lowercase hex chars,
    // free of the canary in raw and normalized form.
    assert_eq!(target_id.len(), 64);
    assert!(
        target_id.bytes().all(|b| b.is_ascii_hexdigit()),
        "the target pseudonym must be 64 lowercase hex chars"
    );
    let normalized = normalize_target(CANARY);
    assert!(!target_id.contains(CANARY));
    assert!(!target_id.contains(&normalized));

    // The store received real observation traffic (the scan is
    // meaningful), and neither the raw canary nor its normalized form is
    // in any material the engine handed the backend.
    let blob = store.blob();
    assert!(
        !store.observations().is_empty(),
        "the assessment must have reached the store"
    );
    assert!(
        !blob.contains(CANARY),
        "the raw canary leaked into store-call material"
    );
    assert!(
        !blob.contains(normalized.as_str()),
        "the normalized canary leaked into store-call material"
    );
    assert!(!blob.contains(CANARY_FULLWIDTH));

    // A fullwidth spelling of the same mailbox collapses onto the same
    // target through the engine side channel.
    assert_eq!(
        engine.resolve_target_id(1, &[("email", CANARY_FULLWIDTH)]),
        Some(target_id.clone())
    );

    // A scope without a configured field carries no target dimension.
    assert_eq!(engine.resolve_target_id(7, &fields), None);

    // The metrics snapshot carries low-cardinality labels only.
    let metrics_blob = format!("{:?}", engine.metrics().snapshot());
    assert!(
        !metrics_blob.contains(CANARY),
        "the raw canary leaked into metrics"
    );
    assert!(
        !metrics_blob.contains(normalized.as_str()),
        "the normalized canary leaked into metrics"
    );

    // An engine without a resolver carries no target dimension at all.
    let bare = RiskEngine::new(
        CapturingTargetStore::new(),
        CidrNetworkClassifier::from_entries(vec![]),
        policy(),
        RiskKeys::from_master(&[0x42; 32]),
    );
    assert_eq!(bare.resolve_target_id(1, &fields), None);

    // The pipeline HMAC equals the identity factory derivation: one
    // derivation path, not two.
    let factory = RiskIdentityFactory::new(RiskKeys::from_master(&[0x42; 32]));
    assert_eq!(target_id, factory.target_id(&normalized));

    // With a live backend, apply the captured observation through the
    // real store and scan the persisted state: the canary family exists
    // nowhere in Redis either.
    if common::redis_url().is_some() {
        apply_and_scan_redis(&store);
    } else {
        eprintln!("skipping the live-Redis target scan: RISK_REDIS_URL not set");
    }
}

/// Live-backend leg (mirrors privacy.rs): the observation the engine
/// built for the canary request is applied through the real store and
/// the namespace state is scanned for the canary family.
fn apply_and_scan_redis(store: &CapturingTargetStore) {
    use kiwicaptcha_risk::redis::RedisRiskStateStore;
    use redis::Commands;
    let client =
        redis::Client::open(common::redis_url().expect("RISK_REDIS_URL set")).expect("url parses");
    let risk_store =
        RedisRiskStateStore::new(client.clone(), &common::unique_namespace("tgt-privacy"));
    let ns = risk_store.namespace().to_string();

    let observations = store.observations();
    assert!(
        !observations.is_empty(),
        "the engine recorded its observation"
    );
    for serialized in observations.iter() {
        let observation: kiwicaptcha_risk::event::RiskObservation =
            serde_json::from_str(serialized).expect("the recorded observation reparses");
        risk_store
            .observe(&observation)
            .expect("observation applies");
    }

    // Scan the namespace and pull every key, field name and value, the
    // same walk privacy.rs performs.
    let mut conn = client.get_connection().expect("connection");
    let pattern = format!("{{kiwi:{ns}}}:*");
    let scanned: Vec<String> = conn.scan_match(pattern).expect("scan").collect();
    assert!(!scanned.is_empty(), "scan must find the issued keys");

    let mut blob = String::new();
    let mut read_conn = client.get_connection().expect("connection");
    for key in &scanned {
        blob.push_str(key);
        blob.push('\n');
        let kind: String = redis::cmd("TYPE")
            .arg(key)
            .query(&mut read_conn)
            .expect("type");
        match kind.as_str() {
            "hash" => {
                let fields: Vec<String> = redis::cmd("HGETALL")
                    .arg(key)
                    .query(&mut read_conn)
                    .expect("hgetall");
                blob.push_str(&fields.join("\n"));
            }
            "string" => {
                let value: Option<String> = redis::cmd("GET")
                    .arg(key)
                    .query(&mut read_conn)
                    .expect("get");
                if let Some(value) = value {
                    blob.push_str(&value);
                }
            }
            other => panic!("unexpected key type {other} for {key}"),
        }
        blob.push('\n');
    }

    let normalized = normalize_target(CANARY);
    for raw in [CANARY, CANARY_FULLWIDTH, normalized.as_str()] {
        assert!(
            !blob.contains(raw),
            "raw {raw:?} leaked into Redis keys/values/metadata"
        );
    }
}
