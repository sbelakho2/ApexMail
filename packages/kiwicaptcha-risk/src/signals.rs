//! The 13 fixed-point signal fields (each 0..1000), in the EXACT contract
//! order, plus the fixed-point normalizer used by the state script.

use serde::{Deserialize, Serialize};

/// The 13 signal fields in the exact contract order:
///
/// `source_fast, source_slow, subnet_fast, issue_debt, bad_proof, malformed,
/// replay, action_failure, scope_switch, global_pressure, network_risk,
/// trust_credit, principal_credit`
///
/// JSON keys are the snake_case field names (identical to `fixtures.json`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct SignalVector {
    pub source_fast: u16,
    pub source_slow: u16,
    pub subnet_fast: u16,
    pub issue_debt: u16,
    pub bad_proof: u16,
    pub malformed: u16,
    pub replay: u16,
    pub action_failure: u16,
    pub scope_switch: u16,
    pub global_pressure: u16,
    pub network_risk: u16,
    pub trust_credit: u16,
    pub principal_credit: u16,
}

/// The contract field order as JSON keys (mirrors `fixtures.json`).
pub const CONTRACT_FIELD_ORDER: [&str; 13] = [
    "source_fast",
    "source_slow",
    "subnet_fast",
    "issue_debt",
    "bad_proof",
    "malformed",
    "replay",
    "action_failure",
    "scope_switch",
    "global_pressure",
    "network_risk",
    "trust_credit",
    "principal_credit",
];

impl SignalVector {
    /// All-zero vector.
    pub fn zero() -> SignalVector {
        SignalVector::default()
    }
}

/// Fixed-point normalization `floor(value * 1000 / saturation)`, clamped to
/// 1000. Mirrors the Lua `normalize`; a non-positive saturation yields 0.
pub fn normalize(value: u32, saturation: u32) -> u16 {
    if saturation == 0 {
        return 0;
    }
    let scaled = (value as u64) * 1000 / (saturation as u64);
    scaled.min(1000) as u16
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_matches_lua_semantics() {
        assert_eq!(normalize(1000, 8000), 125); // 1000*1000/8000
        assert_eq!(normalize(1000, 100000), 10);
        assert_eq!(normalize(2000, 70000), 28);
        assert_eq!(normalize(0, 8000), 0);
        assert_eq!(normalize(10000, 8000), 1000); // clamped
        assert_eq!(normalize(1000, 0), 0); // no saturation -> 0
    }

    #[test]
    fn field_order_matches_contract() {
        assert_eq!(
            CONTRACT_FIELD_ORDER,
            [
                "source_fast",
                "source_slow",
                "subnet_fast",
                "issue_debt",
                "bad_proof",
                "malformed",
                "replay",
                "action_failure",
                "scope_switch",
                "global_pressure",
                "network_risk",
                "trust_credit",
                "principal_credit"
            ]
        );
    }

    #[test]
    fn serde_round_trip_snake_case() {
        let v = SignalVector {
            source_fast: 1,
            trust_credit: 2,
            ..Default::default()
        };
        let json = serde_json::to_value(v).unwrap();
        assert_eq!(json["source_fast"], 1);
        assert_eq!(json["trust_credit"], 2);
        assert_eq!(json["principal_credit"], 0);
        let back: SignalVector = serde_json::from_value(json).unwrap();
        assert_eq!(back, v);
    }
}
