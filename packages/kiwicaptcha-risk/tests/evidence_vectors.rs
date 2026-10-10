//! Shared evidence vectors (protocol/telemetry-v1/evidence-vectors.json):
//! both cores must resolve every vector identically. The corpus pins the
//! telemetry-v1 schema acceptance, the human-band and agent-evidence
//! corpora, the solve-anomaly reference table, the composed stage and
//! the decoy-escalation raise. `RISK_EVIDENCE_VECTORS_PATH` overrides
//! the corpus location; `RISK_P1_TABLE_PATH` overrides the reference
//! table.

use kiwicaptcha_risk::action::RiskAction;
use kiwicaptcha_risk::escalation;
use kiwicaptcha_risk::evidence::{
    self, interaction_anomaly, solve_anomaly, EvidenceConsts, EvidenceInputs, TelemetryPayloadV1,
    EVIDENCE_CONSTS_TABLE, EVIDENCE_P1_MS,
};
use kiwicaptcha_risk::policy::RiskPolicy;
use kiwicaptcha_risk::resources::ResourcePressure;
use kiwicaptcha_risk::signals::SignalVector;
use serde_json::{json, Value};

const VECTORS_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../protocol/telemetry-v1/evidence-vectors.json"
);
const P1_TABLE_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../protocol/telemetry-v1/client-perf-p1.json"
);
const T0: u64 = 1_700_000_000_000;

fn load_corpus() -> Value {
    let path =
        std::env::var("RISK_EVIDENCE_VECTORS_PATH").unwrap_or_else(|_| VECTORS_PATH.to_string());
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("evidence vectors not readable at {path}: {e}"));
    serde_json::from_str(&raw).expect("valid json")
}

/// The JSON shape of the consts table (the mirror of the PHP
/// `EvidenceModel::CONSTS` keys).
fn consts_as_json(consts: &EvidenceConsts) -> Value {
    json!({
        "version": consts.version,
        "score_saturation": consts.score_saturation,
        "sample_cap": consts.sample_cap,
        "entropy_max": consts.entropy_max,
        "entropy_min_samples": consts.entropy_min_samples,
        "entropy_weight": consts.entropy_weight,
        "focus_weight": consts.focus_weight,
        "paste_weight": consts.paste_weight,
        "paste_volume_floor": consts.paste_volume_floor,
        "paste_ratio_edge": consts.paste_ratio_edge,
        "paste_anomaly_value": consts.paste_anomaly_value,
        "human_band_edge": consts.human_band_edge,
        "agent_evidence_edge": consts.agent_evidence_edge,
        "interaction_weight": consts.interaction_weight,
        "solve_weight": consts.solve_weight,
        "solve_ratio_saturation_mille": consts.solve_ratio_saturation_mille,
        "band_edges": consts.band_edges,
        "max_solve_ms": consts.max_solve_ms,
    })
}

#[test]
fn corpus_consts_equal_the_compiled_table() {
    let corpus = load_corpus();
    assert_eq!(corpus["schema"], "kiwicaptcha.evidence-vectors/1");
    let compiled = consts_as_json(&EVIDENCE_CONSTS_TABLE);
    for (key, value) in compiled.as_object().expect("compiled consts") {
        assert_eq!(
            &corpus["consts"][key.as_str()],
            value,
            "the corpus consts value for {key} must equal the compiled table"
        );
    }
    // The no-dead-rule invariant: the entropy rule's minimum-sample
    // count equals the payload cap.
    assert_eq!(
        corpus["consts"]["entropy_min_samples"], corpus["consts"]["sample_cap"],
        "the entropy rule must stay exactly reachable at the payload cap"
    );
}

#[test]
fn compiled_p1_table_equals_the_published_file() {
    let path = std::env::var("RISK_P1_TABLE_PATH").unwrap_or_else(|_| P1_TABLE_PATH.to_string());
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("p1 table not readable at {path}: {e}"));
    let table: Value = serde_json::from_str(&raw).expect("valid json");
    assert_eq!(table["schema"], "kiwicaptcha.client-perf-p1/1");
    let published = table["reference_ms"].as_object().expect("reference_ms");
    let compiled: std::collections::HashMap<&str, u64> = EVIDENCE_P1_MS.iter().copied().collect();
    assert_eq!(
        published.len(),
        compiled.len(),
        "the published and compiled tables must cover the same rungs"
    );
    for (key, value) in published {
        let ms = value
            .as_u64()
            .unwrap_or_else(|| panic!("{key} must be a u64"));
        assert_eq!(
            compiled.get(key.as_str()),
            Some(&ms),
            "the compiled reference for {key} must equal the published table"
        );
    }
}

#[test]
fn interaction_vectors_match_exactly() {
    let corpus = load_corpus();
    let human_edge = corpus["consts"]["human_band_edge"].as_u64().expect("edge") as u16;
    let agent_edge = corpus["consts"]["agent_evidence_edge"]
        .as_u64()
        .expect("edge") as u16;
    let vectors = corpus["interaction_vectors"].as_array().expect("vectors");
    assert!(!vectors.is_empty());
    for vector in vectors {
        let name = vector["name"].as_str().expect("name");
        let raw = serde_json::to_string(&vector["payload"]).expect("payload text");
        let parsed = TelemetryPayloadV1::parse(&raw)
            .unwrap_or_else(|| panic!("{name}: the corpus payload must parse"));
        let anomaly = interaction_anomaly(Some(&parsed))
            .unwrap_or_else(|| panic!("{name}: a valid payload always scores"));
        assert_eq!(
            anomaly,
            vector["expected"].as_u64().expect("expected") as u16,
            "{name}: interaction anomaly mismatch"
        );
        match vector["band"].as_str().expect("band") {
            "human" => assert!(
                anomaly <= human_edge,
                "{name}: human-band payload {anomaly} exceeded the human edge {human_edge}"
            ),
            "agent" => assert!(
                anomaly >= agent_edge,
                "{name}: agent payload {anomaly} fell below the evidence edge {agent_edge}"
            ),
            other => panic!("{name}: unknown band {other}"),
        }
    }
}

#[test]
fn invalid_payloads_reject_and_score_neutral() {
    let corpus = load_corpus();
    let vectors = corpus["invalid_payloads"].as_array().expect("vectors");
    assert!(!vectors.is_empty());
    for vector in vectors {
        let name = vector["name"].as_str().expect("name");
        let raw = serde_json::to_string(&vector["payload"]).expect("payload text");
        let parsed = TelemetryPayloadV1::parse(&raw);
        assert!(parsed.is_none(), "{name}: expected a schema reject");
        assert_eq!(
            interaction_anomaly(parsed.as_ref()),
            None,
            "{name}: a rejected payload must score neutral-unknown"
        );
        assert_eq!(
            interaction_anomaly(None),
            None,
            "{name}: the absent payload must score neutral-unknown"
        );
    }
}

#[test]
fn solve_vectors_match_exactly() {
    let corpus = load_corpus();
    let vectors = corpus["solve_vectors"].as_array().expect("vectors");
    assert!(!vectors.is_empty());
    for vector in vectors {
        let name = vector["name"].as_str().expect("name");
        let solve_ms = vector["solve_ms"].as_u64();
        let rung = vector["rung"].as_str();
        let expected = vector["expected"].as_u64().expect("expected") as u16;
        assert_eq!(
            solve_anomaly(solve_ms, rung),
            expected,
            "{name}: solve anomaly mismatch"
        );
    }
}

fn policy() -> RiskPolicy {
    let corpus = load_corpus();
    RiskPolicy::from_config(3, &corpus["stage"]["policy"]).expect("corpus policy parses")
}

fn stage_inputs(
    interaction: Option<u16>,
    solve_ms: Option<u64>,
    rung: Option<&str>,
) -> EvidenceInputs {
    EvidenceInputs {
        interaction,
        solve: match (solve_ms, rung) {
            (Some(_), Some(_)) => Some(solve_anomaly(solve_ms, rung)),
            _ => None,
        },
    }
}

#[test]
fn stage_vectors_match_exactly() {
    let corpus = load_corpus();
    let vectors = corpus["stage"]["vectors"].as_array().expect("vectors");
    assert!(!vectors.is_empty());
    let resources = ResourcePressure::default();
    for vector in vectors {
        let name = vector["name"].as_str().expect("name");
        let score = vector["score"].as_u64().expect("score") as u16;
        let interaction = vector["interaction"].as_u64().map(|v| v as u16);
        let inputs = stage_inputs(
            interaction,
            vector["solve_ms"].as_u64(),
            vector["rung"].as_str(),
        );
        let plain = policy().decide(1, score, &SignalVector::zero(), &resources, 0, T0, 0);
        let out = evidence::apply(plain, &inputs, &resources);
        assert_eq!(
            out.action.as_str(),
            vector["expected_action"].as_str().expect("action"),
            "{name}: stage action mismatch"
        );
        let expected_reasons: Vec<String> = vector["expected_stage_reasons"]
            .as_array()
            .expect("stage reasons")
            .iter()
            .map(|r| r.as_str().expect("reason").to_string())
            .collect();
        let actual: Vec<String> = out
            .reasons_vec()
            .iter()
            .map(|r| r.as_str().to_string())
            .collect();
        assert!(
            actual.starts_with(&expected_reasons),
            "{name}: stage reasons {actual:?} must start with {expected_reasons:?}"
        );
    }
}

#[test]
fn decoy_escalation_vectors_match_exactly() {
    let corpus = load_corpus();
    let vectors = corpus["decoy_escalation"]["vectors"]
        .as_array()
        .expect("vectors");
    assert!(!vectors.is_empty());
    let resources = ResourcePressure::default();
    for vector in vectors {
        let name = vector["name"].as_str().expect("name");
        let score = vector["score"].as_u64().expect("score") as u16;
        let plain = policy().decide(1, score, &SignalVector::zero(), &resources, 0, T0, 0);
        assert_eq!(
            plain.action.as_str(),
            vector["plain_action"].as_str().expect("plain action"),
            "{name}: the plain action must match before the raise"
        );
        let out = escalation::apply(plain, true);
        assert_eq!(
            out.action.as_str(),
            vector["expected_action"].as_str().expect("expected action"),
            "{name}: decoy escalation mismatch"
        );
        // The raise never deepens a deny: an escalation, never a block.
        if out.action == RiskAction::Deny {
            assert_eq!(out.action.as_str(), "deny");
        }
    }
}

#[test]
fn engine_path_composes_the_stages_when_wired() {
    use kiwicaptcha_risk::context::RiskContext;
    use kiwicaptcha_risk::context::RiskV2Context;
    use kiwicaptcha_risk::event::{RiskEventKind, RiskObservation};
    use kiwicaptcha_risk::keys::RiskKeys;
    use kiwicaptcha_risk::network::CidrNetworkClassifier;
    use kiwicaptcha_risk::store::{Observed, RiskStateStore, RiskStoreError};
    use kiwicaptcha_risk::RiskEngine;
    use std::net::IpAddr;

    // The minimal in-memory store: the zero vector, no cooldowns.
    #[derive(Default)]
    struct ZeroStore;
    impl RiskStateStore for ZeroStore {
        fn observe(&self, _o: &RiskObservation) -> Result<Observed, RiskStoreError> {
            Ok(Observed {
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
        ) -> Result<bool, RiskStoreError> {
            Err(RiskStoreError::BackendUnavailable("stub".to_string()))
        }
        fn confirm_outcome(
            &self,
            _decision_id: &str,
            _legitimate: bool,
        ) -> Result<u8, RiskStoreError> {
            Err(RiskStoreError::BackendUnavailable("stub".to_string()))
        }
        fn correct_outcome(
            &self,
            _decision_id: &str,
            _legitimate: bool,
        ) -> Result<bool, RiskStoreError> {
            Err(RiskStoreError::BackendUnavailable("stub".to_string()))
        }
    }
    impl kiwicaptcha_risk::store::SessionContextTagStore for ZeroStore {}
    impl kiwicaptcha_risk::store::SessionTlsTagStore for ZeroStore {}

    // The decoy-escalation reader: live for one session id, else not.
    struct FixedReader(bool);
    impl escalation::DecoyEscalationReader for FixedReader {
        fn escalation_live(&self, _session: Option<&str>) -> bool {
            self.0
        }
    }

    fn v2_evidence() -> RiskV2Context {
        RiskV2Context {
            telemetry_payload: Some(
                r#"{"v":1,"ec":{"fo":0,"ke":16,"pa":0,"po":0,"fm":16},"qe":0,"ft":1,"pt":0,"n":32}"#
                    .to_string(),
            ),
            solve_ms: Some(100),
            solve_rung: Some("sha18".to_string()),
            ..Default::default()
        }
    }

    fn engine(wired: bool) -> RiskEngine<ZeroStore, CidrNetworkClassifier> {
        let mut engine = RiskEngine::new(
            ZeroStore,
            CidrNetworkClassifier::from_entries(vec![]),
            std::sync::Arc::new(policy()),
            RiskKeys::from_master(&[0x42; 32]),
        );
        if wired {
            engine = engine.with_decoy_escalation(std::sync::Arc::new(FixedReader(true)));
        }
        engine
    }

    fn assess(
        engine: &RiskEngine<ZeroStore, CidrNetworkClassifier>,
    ) -> kiwicaptcha_risk::RiskDecision {
        engine
            .assess_pre_issue_v2(
                RiskContext {
                    scope: 1,
                    source_ip: "198.51.100.7".parse::<IpAddr>().unwrap(),
                    session_id: None,
                    principal_id: None,
                    event: RiskEventKind::PreIssue,
                    network_flags: kiwicaptcha_risk::network::NetworkFlags::default(),
                    resources: ResourcePressure::default(),
                },
                &v2_evidence(),
                None,
                None,
            )
            .expect("assessment")
    }

    // The evidence stage composes in the plain v2 path: the agent-shaped
    // payload raises the rung.
    let unwired = assess(&engine(false));
    assert_eq!(unwired.action, RiskAction::Sha16);
    assert!(unwired.has_reason(kiwicaptcha_risk::policy::RiskReason::InteractionAnomaly));

    // The decoy escalation raises its one rung on a clean v2 path: a
    // live record turns a plain allow into a priced rung.
    let decoy_engine = engine(true);
    let decoy_only = decoy_engine
        .assess_pre_issue_v2(
            RiskContext {
                scope: 1,
                source_ip: "198.51.100.7".parse::<IpAddr>().unwrap(),
                session_id: None,
                principal_id: None,
                event: RiskEventKind::PreIssue,
                network_flags: kiwicaptcha_risk::network::NetworkFlags::default(),
                resources: ResourcePressure::default(),
            },
            &RiskV2Context::default(),
            None,
            None,
        )
        .expect("decoy assessment");
    assert_eq!(decoy_only.action, RiskAction::Sha16);
    assert!(decoy_only.has_reason(kiwicaptcha_risk::policy::RiskReason::DecoyEscalation));

    // With both stages live the raises compose: the action never drops
    // and both stage reasons are recorded.
    let wired = assess(&engine(true));
    assert!(wired.action.rank() >= unwired.action.rank());
    assert!(wired.has_reason(kiwicaptcha_risk::policy::RiskReason::InteractionAnomaly));
    assert!(wired.has_reason(kiwicaptcha_risk::policy::RiskReason::DecoyEscalation));

    // A v2 context without evidence keeps the unwired path byte-identical.
    let plain_engine = engine(false);
    let plain = plain_engine
        .assess_pre_issue_v2(
            RiskContext {
                scope: 1,
                source_ip: "198.51.100.7".parse::<IpAddr>().unwrap(),
                session_id: None,
                principal_id: None,
                event: RiskEventKind::PreIssue,
                network_flags: kiwicaptcha_risk::network::NetworkFlags::default(),
                resources: ResourcePressure::default(),
            },
            &RiskV2Context::default(),
            None,
            None,
        )
        .expect("plain assessment");
    assert_eq!(plain.action, RiskAction::Allow);
    assert!(!plain.has_reason(kiwicaptcha_risk::policy::RiskReason::InteractionAnomaly));
}
