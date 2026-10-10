//! The shared quarantine vectors (protocol/risk-v1/quarantine-vectors.json):
//! the PHP mirror and this implementation must resolve every vector to
//! the identical action, quarantine flag, retry hint and ordered reason
//! list. The vectors pin the quarantine selection of the marks stage and
//! its severity-monotonic precedence (change.md 1.3 and 3.3.4), so a
//! divergent core fails one of these assertions in whichever core
//! drifted. `RISK_QUARANTINE_VECTORS_PATH` overrides the corpus
//! location.

use kiwicaptcha_risk::marks;
use kiwicaptcha_risk::outcomes::{MarkDimension, MarkRecord};
use kiwicaptcha_risk::policy::RiskPolicy;
use kiwicaptcha_risk::quarantine;
use kiwicaptcha_risk::resources::ResourcePressure;
use kiwicaptcha_risk::signals::SignalVector;

fn vectors_path() -> String {
    std::env::var("RISK_QUARANTINE_VECTORS_PATH").unwrap_or_else(|_| {
        concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../protocol/risk-v1/quarantine-vectors.json"
        )
        .to_string()
    })
}

#[test]
fn every_shared_vector_matches_exactly() {
    let path = vectors_path();
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("quarantine vectors not readable at {path}: {e}"));
    let vectors: serde_json::Value = serde_json::from_str(&raw).expect("vectors parse");
    assert_eq!(vectors["version"], 1);
    let policy = RiskPolicy::from_config(3, &vectors["policy"]).expect("policy parses");
    let ttl = vectors["mark_ttl_ms"].as_u64().expect("ttl");

    let rows = vectors["vectors"].as_array().expect("vectors array");
    assert!(!rows.is_empty());
    for vector in rows {
        let why = vector["why"].as_str().unwrap_or("vector");
        // Sparse signal objects default their missing fields to zero,
        // exactly like the PHP SignalVector::fromArray reader.
        let mut signals_value = serde_json::json!({
            "source_fast": 0, "source_slow": 0, "subnet_fast": 0,
            "issue_debt": 0, "bad_proof": 0, "malformed": 0,
            "replay": 0, "action_failure": 0, "scope_switch": 0,
            "global_pressure": 0, "network_risk": 0,
            "trust_credit": 0, "principal_credit": 0
        });
        if let Some(fields) = vector["signals"].as_object() {
            for (field, value) in fields {
                signals_value[field] = value.clone();
            }
        }
        let signals: SignalVector = serde_json::from_value(signals_value).expect("signals parse");
        let resources = ResourcePressure {
            argon_capacity: vector["argon_capacity"].as_u64().expect("argon") as u16,
            issuance_capacity: vector["issuance_capacity"].as_u64().expect("issuance") as u16,
        };
        let now = vector["now_ms"].as_u64().expect("now");
        let plain = policy.decide(
            vector["scope"].as_u64().expect("scope") as u32,
            vector["score"].as_u64().expect("score") as u16,
            &signals,
            &resources,
            vector["global_level"].as_u64().expect("level") as u8,
            now,
            0,
        );
        let mut own = Vec::new();
        for (dimension, record) in vector["own_marks"].as_object().expect("own marks object") {
            let dimension = MarkDimension::from_key(dimension).expect("known dimension");
            own.push((dimension, record_from_json(record)));
        }
        let target = vector
            .get("target_mark")
            .filter(|record| !record.is_null())
            .map(record_from_json);
        let view = marks::MarksView::from_parts(own, target);
        let out = marks::apply(
            plain,
            &view,
            vector["corroborated"].as_bool().expect("corroborated flag"),
            now,
            ttl,
            &resources,
            true,
        );
        assert_eq!(
            vector["expected_action"].as_str().expect("action"),
            out.action.as_str(),
            "action mismatch: {why}"
        );
        assert_eq!(
            vector["expected_quarantined"]
                .as_bool()
                .expect("quarantined"),
            out.quarantined,
            "quarantine mismatch: {why}"
        );
        let expected_retry = match vector.get("expected_retry_after_ms") {
            None | Some(serde_json::Value::Null) => None,
            Some(v) => Some(v.as_u64().expect("retry") as u32),
        };
        assert_eq!(expected_retry, out.retry_after_ms, "retry mismatch: {why}");
        let expected_reasons: Vec<&str> = vector["expected_reasons"]
            .as_array()
            .expect("reasons")
            .iter()
            .map(|r| r.as_str().expect("reason"))
            .collect();
        let actual: Vec<&str> = out.reasons.iter().flatten().map(|r| r.as_str()).collect();
        assert_eq!(expected_reasons, actual, "reasons mismatch: {why}");
    }
}

/// The metrics disposition label: the quarantine disposition counts as
/// its own label while the wire action stays allow.
#[test]
fn disposition_label_counts_quarantine_as_its_own_action() {
    let clean = sample_decision(false);
    assert_eq!(clean.disposition_label(), "allow");
    assert!(!clean.quarantined);
    let held = sample_decision(true);
    assert_eq!(held.disposition_label(), "quarantine");
    // The wire action is untouched: quarantine is indistinguishable from
    // allow on every challenge-bearing surface.
    assert_eq!(held.action.as_str(), "allow");
    assert_eq!(
        serde_json::to_value(&held).unwrap()["quarantined"],
        serde_json::json!(true)
    );
    assert_eq!(
        serde_json::to_value(&clean).unwrap()["quarantined"],
        serde_json::json!(false)
    );
}

/// The severity-monotonic precedence drop: a composed stage that raises
/// the action above Allow drops the flag, an inert stage keeps it.
#[test]
fn escalation_drops_the_quarantine_and_inertia_keeps_it() {
    let held = sample_decision(true);
    let raised = held.clone().without_quarantine();
    assert!(!raised.quarantined);
    assert_eq!(raised.action, held.action);
    assert_eq!(raised.decision_id, held.decision_id);
    // The quarantine decision invariant in both cores: the flag rides
    // the Allow action only.
    assert_eq!(held.action, kiwicaptcha_risk::action::RiskAction::Allow);
    // The selection helpers agree with the stage on the corpus shapes.
    let view = marks::MarksView::from_parts(
        vec![(
            MarkDimension::Session,
            MarkRecord {
                kind: quarantine::SPAM_MARK_KIND.to_string(),
                last_kind: quarantine::SPAM_MARK_KIND.to_string(),
                count: 1,
                first_ms: 1_700_000_000_000,
                last_ms: 1_700_000_000_000,
            },
        )],
        None,
    );
    assert!(quarantine::selects(
        &view,
        false,
        1_700_000_000_000,
        7_776_000_000
    ));
    assert!(!quarantine::selects(
        &view,
        true,
        1_700_000_000_000,
        7_776_000_000
    ));
}

/// End-to-end through the engine: the wired marks reader quarantines the
/// marked identity, the decision metrics count the disposition as its
/// own label, and a live decoy escalation raises the rung and drops the
/// flag with it.
#[test]
fn engine_emits_the_quarantine_disposition_and_its_metric_label() {
    use kiwicaptcha_risk::keys::RiskKeys;
    use kiwicaptcha_risk::network::CidrNetworkClassifier;
    use kiwicaptcha_risk::RiskEngine;
    use std::sync::Arc;

    struct MarkedReader;
    impl marks::MarksReader for MarkedReader {
        fn request_marks(
            &self,
            _request: &marks::MarksRequest,
        ) -> Result<marks::MarksView, kiwicaptcha_risk::RiskError> {
            Ok(marks::MarksView::from_parts(
                vec![(
                    MarkDimension::Session,
                    MarkRecord {
                        kind: quarantine::SPAM_MARK_KIND.to_string(),
                        last_kind: quarantine::SPAM_MARK_KIND.to_string(),
                        count: 1,
                        first_ms: 1,
                        last_ms: 1,
                    },
                )],
                None,
            ))
        }

        fn mark_ttl_ms(&self) -> u64 {
            u64::MAX
        }
    }

    struct FixedEscalation(bool);
    impl kiwicaptcha_risk::escalation::DecoyEscalationReader for FixedEscalation {
        fn escalation_live(&self, _session: Option<&str>) -> bool {
            self.0
        }
    }

    // The minimal in-memory store: the zero vector, no cooldowns.
    #[derive(Default)]
    struct ZeroStore;
    impl kiwicaptcha_risk::store::RiskStateStore for ZeroStore {
        fn observe(
            &self,
            _o: &kiwicaptcha_risk::event::RiskObservation,
        ) -> Result<kiwicaptcha_risk::store::Observed, kiwicaptcha_risk::store::RiskStoreError>
        {
            Ok(kiwicaptcha_risk::store::Observed {
                vector: SignalVector::zero(),
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
        ) -> Result<bool, kiwicaptcha_risk::store::RiskStoreError> {
            Ok(true)
        }
        fn confirm_outcome(
            &self,
            _decision_id: &str,
            _legitimate: bool,
        ) -> Result<u8, kiwicaptcha_risk::store::RiskStoreError> {
            Ok(0)
        }
        fn correct_outcome(
            &self,
            _decision_id: &str,
            _legitimate: bool,
        ) -> Result<bool, kiwicaptcha_risk::store::RiskStoreError> {
            Ok(true)
        }
    }
    impl kiwicaptcha_risk::store::SessionContextTagStore for ZeroStore {}
    impl kiwicaptcha_risk::store::SessionTlsTagStore for ZeroStore {}

    fn risk_engine(live_decoy: bool) -> RiskEngine<ZeroStore, CidrNetworkClassifier> {
        let policy_json = serde_json::json!({
            "version": 3,
            "weights": {},
            "scopes": {
                "1": { "base_risk": 100, "minimum": "allow", "post_solve_check": true, "degraded": "sha20" }
            },
            "global_floors": { "0": "allow", "1": "sha16", "2": "sha18", "3": "sha20", "4": "sha20" }
        });
        let mut engine = RiskEngine::new(
            ZeroStore,
            CidrNetworkClassifier::from_entries(vec![]),
            Arc::new(RiskPolicy::from_config(3, &policy_json).expect("policy parses")),
            RiskKeys::from_master(&[0x42; 32]),
        )
        .with_marks_reader(Arc::new(MarkedReader));
        if live_decoy {
            engine = engine.with_decoy_escalation(Arc::new(FixedEscalation(true)));
        }
        engine
    }

    let held = {
        let ctx = engine_context();
        risk_engine(false).assess_pre_issue(ctx, None).unwrap()
    };
    assert!(held.quarantined, "the marked identity quarantines");
    assert_eq!(held.action.as_str(), "allow", "the rung never moves");
    assert!(held.has_reason(kiwicaptcha_risk::policy::RiskReason::SpamMarkQuarantine));

    // The decision metric counts the disposition as its own label.
    let engine = risk_engine(false);
    let ctx = engine_context();
    let _ = engine.assess_pre_issue(ctx, None).unwrap();
    let snapshot = engine.metrics().snapshot();
    assert!(
        snapshot
            .iter()
            .any(|(name, _)| name.contains("decisions:1:quarantine:")),
        "the quarantine disposition counts as its own label: {snapshot:?}"
    );

    // A live decoy escalation raises the rung one step and the
    // quarantine disposition drops with it (severity wins).
    let raised = {
        let ctx = engine_context();
        risk_engine(true).assess_pre_issue(ctx, None).unwrap()
    };
    assert!(!raised.quarantined, "the raised action outranks quarantine");
    assert_eq!(raised.action.as_str(), "sha16");
    assert!(raised.has_reason(kiwicaptcha_risk::policy::RiskReason::DecoyEscalation));
}

fn engine_context<'a>() -> kiwicaptcha_risk::context::RiskContext<'a> {
    kiwicaptcha_risk::context::RiskContext {
        scope: 1,
        source_ip: "198.51.100.7".parse().unwrap(),
        session_id: None,
        principal_id: None,
        event: kiwicaptcha_risk::event::RiskEventKind::PreIssue,
        network_flags: Default::default(),
        resources: Default::default(),
    }
}

fn sample_decision(quarantined: bool) -> kiwicaptcha_risk::RiskDecision {
    kiwicaptcha_risk::RiskDecision {
        score: 100,
        action: kiwicaptcha_risk::action::RiskAction::Allow,
        reasons: [None, None, None, None],
        policy_version: 3,
        model_revision: kiwicaptcha_risk::RISK_MODEL_REVISION,
        global_level: 0,
        retry_after_ms: None,
        band: 1,
        decision_id: "0f1e2d3c4b5a69788796a5b4c3d2e1f0".to_string(),
        quarantined,
    }
}

fn record_from_json(record: &serde_json::Value) -> MarkRecord {
    let kind = record["kind"].as_str().expect("kind").to_string();
    MarkRecord {
        last_kind: record
            .get("last_kind")
            .and_then(|v| v.as_str())
            .unwrap_or(&kind)
            .to_string(),
        kind,
        count: record["count"].as_i64().expect("count"),
        first_ms: record["first_ms"].as_i64().expect("first"),
        last_ms: record["last_ms"].as_i64().expect("last"),
    }
}
