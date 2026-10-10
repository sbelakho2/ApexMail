//! Shared hysteresis edge-fallback vectors (protocol/risk-v1/
//! hysteresis-vectors.json): the PHP `ScopeActionHysteresis` and this
//! crate must select the identical action for every step. Each step is
//! independent — the client's last action in the scope is seeded from the
//! recorded `previous`, then `select(score)` runs with the plain mapping
//! and must return the recorded `expected`. Pure — no Redis needed.

use kiwicaptcha_risk::action::RiskAction;
use kiwicaptcha_risk::hysteresis::ScopeActionHysteresis;

const VECTORS_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../protocol/risk-v1/hysteresis-vectors.json"
);
const T0: u64 = 1_700_000_000_000;

/// Case names are the PHP enum case names (`StepUp` carries the wire value
/// `step_up`, so a plain lowercase mapping is not enough).
fn action_by_case_name(name: &str) -> RiskAction {
    match name {
        "Allow" => RiskAction::Allow,
        "Sha16" => RiskAction::Sha16,
        "Sha18" => RiskAction::Sha18,
        "Sha20" => RiskAction::Sha20,
        "Argon16" => RiskAction::Argon16,
        "Argon32" => RiskAction::Argon32,
        "Argon64" => RiskAction::Argon64,
        "StepUp" => RiskAction::StepUp,
        "Deny" => RiskAction::Deny,
        other => panic!("unknown action name {other:?}"),
    }
}

/// A score whose plain mapping is `action` — used to seed the entry the
/// way a real request would (the stored action is score-selected).
fn seed_score(action: RiskAction) -> u16 {
    (0..=1000u16)
        .find(|&score| RiskAction::action_for_score(score) == action)
        .unwrap_or_else(|| panic!("no score maps to {action:?}"))
}

#[test]
fn shared_hysteresis_edge_fallback_vectors_match_php() {
    let raw = std::fs::read_to_string(VECTORS_PATH)
        .unwrap_or_else(|e| panic!("cannot read {VECTORS_PATH}: {e}"));
    let value: serde_json::Value = serde_json::from_str(&raw).expect("valid json");
    let vectors = value
        .get("vectors")
        .expect("the hysteresis vectors must be recorded")
        .as_array()
        .expect("hysteresis vectors array")
        .clone();
    assert!(!vectors.is_empty(), "hysteresis vectors must not be empty");

    let mut steps = 0usize;
    for vector in &vectors {
        let client = vector["client"].as_str().expect("client").as_bytes();
        for step in vector["steps"].as_array().expect("steps") {
            let scope = step["scope"].as_u64().expect("scope") as u32;
            let score = step["score"].as_u64().expect("score") as u16;
            let previous = action_by_case_name(step["previous"].as_str().expect("previous"));
            let expected = action_by_case_name(step["expected"].as_str().expect("expected"));

            // Each step is independent: seed the previous action, then
            // select at the recorded score one tick later.
            let h = ScopeActionHysteresis::new();
            let seed = seed_score(previous);
            assert_eq!(
                h.select(scope, client, seed, RiskAction::action_for_score(seed), T0),
                previous,
                "the seed step must store the recorded previous action"
            );
            assert_eq!(
                h.select(
                    scope,
                    client,
                    score,
                    RiskAction::action_for_score(score),
                    T0 + 1
                ),
                expected,
                "client {client:?} scope {scope} score {score} previous {previous:?}"
            );
            steps += 1;
        }
    }
    // Both done-when pins and the coverage families must be present.
    assert!(steps >= 15, "the vector families must stay comprehensive");
}
