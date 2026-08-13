//! Immutable policy snapshot used to turn a risk score into an action.
//!
//! Configuration shape (JSON, mirrors the PHP package):
//!
//! ```json
//! {
//!   "version": 3,
//!   "weights": { "source_fast": 190, "...": "..." },
//!   "scopes": {
//!     "1": { "base_risk": 100, "minimum": "allow",
//!            "post_solve_check": true, "degraded": "sha20" }
//!   },
//!   "global_floors": { "1": "sha16", "2": "sha18", "3": "sha20", "4": "sha20" }
//! }
//! ```
//!
//! The `hash` is sha256 of the canonical JSON of the whole config
//! (recursively key-sorted with PHP-compatible ordering and escaping), so
//! both implementations derive the identical hash for the identical config.

use std::collections::HashMap;

use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::action::RiskAction;
use crate::hysteresis::ScopeActionHysteresis;
use crate::resources::ResourcePressure;
use crate::score::RiskWeights;
use crate::signals::SignalVector;
use crate::RiskDecision;

/// Internal risk reasons, fixed by the cross-language risk-v1 contract.
///
/// The top 3-4 reasons are attached to an internal [`super::lib::RiskDecision`];
/// they are never exposed to the client.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskReason {
    SourceBurst,
    SourceSustained,
    NetworkBurst,
    ChallengeDebt,
    InvalidProofs,
    MalformedTraffic,
    ReplayTraffic,
    ActionFailures,
    ScopeHopping,
    GlobalAttack,
    LocalNetworkRisk,
    CapacityPressure,
    HardRateLimit,
    Cooldown,
}

impl RiskReason {
    /// Wire string value (matches the serde representation).
    pub fn as_str(self) -> &'static str {
        match self {
            RiskReason::SourceBurst => "source_burst",
            RiskReason::SourceSustained => "source_sustained",
            RiskReason::NetworkBurst => "network_burst",
            RiskReason::ChallengeDebt => "challenge_debt",
            RiskReason::InvalidProofs => "invalid_proofs",
            RiskReason::MalformedTraffic => "malformed_traffic",
            RiskReason::ReplayTraffic => "replay_traffic",
            RiskReason::ActionFailures => "action_failures",
            RiskReason::ScopeHopping => "scope_hopping",
            RiskReason::GlobalAttack => "global_attack",
            RiskReason::LocalNetworkRisk => "local_network_risk",
            RiskReason::CapacityPressure => "capacity_pressure",
            RiskReason::HardRateLimit => "hard_rate_limit",
            RiskReason::Cooldown => "cooldown",
        }
    }
}

/// Policy error raised by [`RiskPolicy::from_config`].
#[derive(Debug, Error)]
pub enum PolicyError {
    #[error("policy config requires an int \"version\"")]
    InvalidVersion,
    #[error("policy config version {config} does not match the requested version {requested}")]
    VersionMismatch { requested: u32, config: i64 },
    #[error("policy config requires a \"weights\" object")]
    InvalidWeights,
    #[error("policy config requires a \"scopes\" object")]
    InvalidScopes,
    #[error("scope {0} requires base_risk, minimum, post_solve_check and degraded")]
    InvalidScope(String),
    #[error("scope {0} base_risk must be an integer within 0..1000")]
    InvalidBaseRisk(String),
    #[error("scope id {0} must be within 1..=4294967295 (0 is rejected)")]
    InvalidScopeId(String),
    #[error("weight values must be within 0..1000")]
    InvalidWeightValue,
    #[error("invalid action string: {0}")]
    InvalidAction(String),
    #[error(
        "global_floors must have exactly 5 entries (levels 0..4) with level 0 = \"allow\": {0}"
    )]
    InvalidGlobalFloors(String),
}

/// Per-scope policy settings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct ScopePolicy {
    pub base_risk: u16,
    pub minimum: RiskAction,
    pub post_solve_check: bool,
    pub degraded: RiskAction,
}

/// Immutable policy snapshot.
#[derive(Debug, Clone)]
pub struct RiskPolicy {
    pub version: u32,
    /// sha256 of the canonical JSON of the full config.
    pub hash: [u8; 32],
    pub weights: RiskWeights,
    pub scopes: HashMap<u32, ScopePolicy>,
    /// Global pressure level 0..4 -> minimum action floor. Level 0 has no
    /// floor (Allow).
    pub global_floors: [RiskAction; 5],
}

impl RiskPolicy {
    pub const DEFAULT_GLOBAL_FLOORS: [RiskAction; 5] = [
        RiskAction::Allow,
        RiskAction::Sha16,
        RiskAction::Sha18,
        RiskAction::Sha20,
        RiskAction::Sha20,
    ];

    /// Parses a policy config and computes the canonical-config hash.
    ///
    /// Invariants: the config `version` MUST equal the requested version;
    /// every scope id must be within 1..=u32::MAX (0 rejected); every
    /// `base_risk` must be an integer within 0..=1000 (no silent cast);
    /// `global_floors` must have EXACTLY 5 entries (levels 0..4) with
    /// level 0 = Allow and levels 1..4 valid actions.
    pub fn from_config(version: u32, config: &Value) -> Result<RiskPolicy, PolicyError> {
        let config_version = config
            .get("version")
            .ok_or(PolicyError::InvalidVersion)?
            .as_i64()
            .ok_or(PolicyError::InvalidVersion)?;
        if config_version != version as i64 {
            return Err(PolicyError::VersionMismatch {
                requested: version,
                config: config_version,
            });
        }
        let weights_value = config
            .get("weights")
            .ok_or(PolicyError::InvalidWeights)?
            .clone();
        let weights: RiskWeights =
            serde_json::from_value(weights_value).map_err(|_| PolicyError::InvalidWeights)?;
        for weight in [
            weights.source_fast,
            weights.source_slow,
            weights.subnet_fast,
            weights.issue_debt,
            weights.bad_proof,
            weights.malformed,
            weights.replay,
            weights.action_failure,
            weights.scope_switch,
            weights.global_pressure,
            weights.network_risk,
            weights.trust_credit,
            weights.principal_credit,
        ] {
            if weight > 1000 {
                return Err(PolicyError::InvalidWeightValue);
            }
        }

        let scopes_value = config.get("scopes").ok_or(PolicyError::InvalidScopes)?;
        let scopes_obj = scopes_value.as_object().ok_or(PolicyError::InvalidScopes)?;
        let mut scopes = HashMap::new();
        for (key, spec) in scopes_obj {
            let scope: u32 = key
                .parse()
                .map_err(|_| PolicyError::InvalidScopeId(key.clone()))?;
            if scope == 0 {
                return Err(PolicyError::InvalidScopeId(key.clone()));
            }
            let spec_obj = spec
                .as_object()
                .ok_or_else(|| PolicyError::InvalidScope(key.clone()))?;
            let required = ["base_risk", "minimum", "post_solve_check", "degraded"];
            for field in required {
                if !spec_obj.contains_key(field) {
                    return Err(PolicyError::InvalidScope(key.clone()));
                }
            }
            let base_risk_value = spec["base_risk"]
                .as_u64()
                .ok_or_else(|| PolicyError::InvalidBaseRisk(key.clone()))?;
            if base_risk_value > 1000 {
                return Err(PolicyError::InvalidBaseRisk(key.clone()));
            }
            let base_risk = base_risk_value as u16;
            let minimum = parse_action(&spec["minimum"])?;
            let post_solve_check = spec["post_solve_check"]
                .as_bool()
                .ok_or_else(|| PolicyError::InvalidScope(key.clone()))?;
            let degraded = parse_action(&spec["degraded"])?;
            scopes.insert(
                scope,
                ScopePolicy {
                    base_risk,
                    minimum,
                    post_solve_check,
                    degraded,
                },
            );
        }

        let mut floors = Self::DEFAULT_GLOBAL_FLOORS;
        match config.get("global_floors") {
            None => {
                return Err(PolicyError::InvalidGlobalFloors(
                    "global_floors is required".to_string(),
                ));
            }
            Some(floors_value) => {
                let obj = floors_value
                    .as_object()
                    .ok_or_else(|| PolicyError::InvalidGlobalFloors("not an object".to_string()))?;
                if obj.len() != 5 {
                    return Err(PolicyError::InvalidGlobalFloors(format!(
                        "expected 5 entries, got {}",
                        obj.len()
                    )));
                }
                for (key, action) in obj {
                    let level: u8 = key.parse().map_err(|_| {
                        PolicyError::InvalidGlobalFloors(format!("bad level {key}"))
                    })?;
                    if level > 4 {
                        return Err(PolicyError::InvalidGlobalFloors(format!(
                            "level {level} out of range 0..4"
                        )));
                    }
                    let parsed = parse_action(action)?;
                    if level == 0 && parsed != RiskAction::Allow {
                        return Err(PolicyError::InvalidGlobalFloors(
                            "level 0 must be \"allow\"".to_string(),
                        ));
                    }
                    floors[level as usize] = parsed;
                }
            }
        }

        let hash: [u8; 32] = Sha256::digest(canonical_json(config).as_bytes()).into();

        Ok(RiskPolicy {
            version,
            hash,
            weights,
            scopes,
            global_floors: floors,
        })
    }

    /// Base risk for a scope (default 100).
    pub fn base_risk(&self, scope: u32) -> u16 {
        self.scopes.get(&scope).map_or(100, |s| s.base_risk)
    }

    /// Minimum action for a scope (default Allow).
    pub fn minimum(&self, scope: u32) -> RiskAction {
        self.scopes
            .get(&scope)
            .map_or(RiskAction::Allow, |s| s.minimum)
    }

    /// Full decision: band action, clamped to the scope minimum and the
    /// global floor, then hard overrides with reasons.
    ///
    /// Convenience wrapper without the scope-action hysteresis map (the
    /// plain band mapping — byte-identical with the pre-audit-#95
    /// behavior); the engine uses
    /// [`RiskPolicy::decide_with_hysteresis`].
    #[allow(clippy::too_many_arguments)]
    pub fn decide(
        &self,
        scope: u32,
        score: u16,
        s: &SignalVector,
        r: &ResourcePressure,
        global_level: u8,
        now_ms: u64,
        cooldown_until_ms: u64,
    ) -> RiskDecision {
        self.decide_with_hysteresis(
            scope,
            score,
            s,
            r,
            global_level,
            now_ms,
            cooldown_until_ms,
            None,
        )
    }

    /// Full decision: band action (with enter/exit hysteresis when the
    /// engine's per-process scope map is passed), clamped to the scope
    /// minimum and the global floor, then hard overrides with reasons.
    ///
    /// Argon re-escalation order: `action = strongest(band, minimum,
    /// floor)` FIRST; THEN, when the FINAL action is Argon and the argon
    /// capacity is below 300, the action steps UP to `StepUp` — the
    /// capacity check is LAST, so floors/minimum can never reintroduce
    /// Argon after a demotion.
    ///
    /// Hysteresis (audit #95): with `hysteresis` the band selection uses
    /// the scope's previous action — escalate to the next band only at its
    /// ENTER threshold (upper + 10), de-escalate only below its EXIT
    /// threshold (lower − 10); fresh scopes and StepUp/Deny use the plain
    /// mapping. The map stores the SCORE-selected action, so hard
    /// overrides never poison the profile. `None` keeps the plain band
    /// mapping.
    #[allow(clippy::too_many_arguments)]
    pub fn decide_with_hysteresis(
        &self,
        scope: u32,
        score: u16,
        s: &SignalVector,
        r: &ResourcePressure,
        global_level: u8,
        now_ms: u64,
        cooldown_until_ms: u64,
        hysteresis: Option<&ScopeActionHysteresis>,
    ) -> RiskDecision {
        let plain = RiskAction::action_for_score(score);
        let band_action = hysteresis.map_or(plain, |h| h.select(scope, score, plain, now_ms));
        let minimum = self.minimum(scope);
        let floor = self.global_floors[(global_level as usize).min(4)];
        let mut action = strongest(band_action, minimum, floor);

        let mut reasons: Vec<RiskReason> = Vec::new();
        let mut deny = false;
        let mut retry_after_ms = None;

        if s.replay >= 700 {
            reasons.push(RiskReason::ReplayTraffic);
            deny = true;
        }
        if s.malformed >= 800 {
            reasons.push(RiskReason::MalformedTraffic);
            deny = true;
        }
        if s.source_fast >= 950 {
            reasons.push(RiskReason::HardRateLimit);
            deny = true;
        }
        if r.issuance_capacity < 100 {
            reasons.push(RiskReason::CapacityPressure);
            deny = true;
        }
        if s.network_risk >= 900 {
            reasons.push(RiskReason::LocalNetworkRisk);
            deny = true;
        }
        // The cooldown_until value from the store is the GLOBAL hysteresis
        // hold marker (the level-until deadline), NOT a per-source denial
        // window — treating it as such would deny every request while the
        // global level is merely elevated. Cooldown denial applies only at
        // EMERGENCY level, where the global controller intends a temporary
        // admission stop.
        if cooldown_until_ms > 0 && now_ms < cooldown_until_ms && global_level >= 4 {
            reasons.push(RiskReason::Cooldown);
            deny = true;
            retry_after_ms = Some((cooldown_until_ms - now_ms) as u32);
        }

        if deny {
            action = RiskAction::Deny;
        } else if action.is_argon() && r.argon_capacity < 300 {
            // Capacity check LAST: the FINAL action is Argon and the
            // backend cannot serve memory-hard work — re-escalate to the
            // interactive step-up flow instead of weakening the guard.
            action = RiskAction::StepUp;
            reasons.push(RiskReason::CapacityPressure);
        }

        // Deduplicate in priority order, cap at 4.
        let mut seen = std::collections::HashSet::new();
        reasons.retain(|r| seen.insert(*r));
        reasons.truncate(4);
        let mut out = [None; 4];
        for (i, r) in reasons.iter().enumerate() {
            out[i] = Some(*r);
        }

        RiskDecision {
            score,
            action,
            reasons: out,
            policy_version: self.version,
            global_level,
            retry_after_ms,
            band: (score.clamp(0, 1000) / 100) as u8,
            decision_id: String::new(),
        }
    }

    /// Degraded decision (state backend unavailable): the scope's degraded
    /// action clamped to at least the scope minimum AND the global floor of
    /// the store's last known level (`global_floors[min(level, 4)]`;
    /// level 0 = Allow). Never fails open below the minimum or the floor.
    pub fn degraded_decision(&self, scope: u32, global_level: u8) -> RiskDecision {
        let degraded = self
            .scopes
            .get(&scope)
            .map_or(RiskAction::Allow, |s| s.degraded);
        let floor = self.global_floors[(global_level as usize).min(4)];
        let action = strongest(degraded, self.minimum(scope), floor);

        RiskDecision {
            score: 0,
            action,
            reasons: [Some(RiskReason::CapacityPressure), None, None, None],
            policy_version: self.version,
            global_level,
            retry_after_ms: None,
            band: 0,
            decision_id: String::new(),
        }
    }
}

fn strongest(a: RiskAction, b: RiskAction, c: RiskAction) -> RiskAction {
    let mut best = a;
    if b.rank() > best.rank() {
        best = b;
    }
    if c.rank() > best.rank() {
        best = c;
    }
    best
}

fn parse_action(value: &Value) -> Result<RiskAction, PolicyError> {
    let s = value
        .as_str()
        .ok_or_else(|| PolicyError::InvalidAction(value.to_string()))?;
    serde_json::from_value(Value::String(s.to_string()))
        .map_err(|_| PolicyError::InvalidAction(s.to_string()))
}

/// PHP-compatible canonical JSON: recursively key-sorted (numeric keys
/// numerically, string keys byte-wise), no whitespace, no slash or unicode
/// escaping, PHP-style short escapes for control characters. Both
/// implementations therefore produce byte-identical hashes.
pub fn canonical_json(value: &Value) -> String {
    match value {
        Value::Null => "null".to_string(),
        Value::Bool(b) => b.to_string(),
        Value::Number(n) => n.to_string(),
        Value::String(s) => escape_json_string(s),
        Value::Array(items) => {
            let inner: Vec<String> = items.iter().map(canonical_json).collect();
            format!("[{}]", inner.join(","))
        }
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            sort_json_keys(&mut keys);
            let inner: Vec<String> = keys
                .iter()
                .map(|k| format!("{}:{}", escape_json_string(k), canonical_json(&map[*k])))
                .collect();
            format!("{{{}}}", inner.join(","))
        }
    }
}

/// PHP `ksort` semantics: all keys parseable as integers sort numerically
/// (1, 2, 10), otherwise byte-wise lexicographic.
fn sort_json_keys(keys: &mut Vec<&String>) {
    if keys.iter().all(|k| k.parse::<u64>().is_ok()) {
        keys.sort_by_key(|k| k.parse::<u64>().unwrap());
    } else {
        keys.sort();
    }
}

/// PHP `json_encode` default string escaping (JSON_UNESCAPED_SLASHES |
/// JSON_UNESCAPED_UNICODE semantics).
fn escape_json_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{08}' => out.push_str("\\b"),
            '\t' => out.push_str("\\t"),
            '\n' => out.push_str("\\n"),
            '\u{0c}' => out.push_str("\\f"),
            '\r' => out.push_str("\\r"),
            c if (c as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn config() -> Value {
        json!({
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
                "2": { "base_risk": 150, "minimum": "sha16", "post_solve_check": true, "degraded": "sha20" },
                "3": { "base_risk": 200, "minimum": "argon32", "post_solve_check": true, "degraded": "argon16" }
            },
            "global_floors": { "0": "allow", "1": "sha16", "2": "sha18", "3": "sha20", "4": "sha20" }
        })
    }

    fn healthy() -> ResourcePressure {
        ResourcePressure::default()
    }

    fn zero_vector() -> SignalVector {
        SignalVector::zero()
    }

    fn policy() -> RiskPolicy {
        RiskPolicy::from_config(3, &config()).expect("config parses")
    }

    #[test]
    fn from_config_and_hash() {
        let p = policy();
        assert_eq!(p.version, 3);
        assert_eq!(p.hash.len(), 32);
        // The hash is sha256 of the canonical JSON of the full config.
        assert_eq!(
            Sha256::digest(canonical_json(&config()).as_bytes()).as_slice(),
            &p.hash[..]
        );
        assert_eq!(p.base_risk(1), 100);
        assert_eq!(p.base_risk(2), 150);
        assert_eq!(p.base_risk(999), 100);
        assert_eq!(p.minimum(1), RiskAction::Allow);
        assert_eq!(p.minimum(2), RiskAction::Sha16);
        assert_eq!(p.minimum(999), RiskAction::Allow);
        assert_eq!(p.global_floors, RiskPolicy::DEFAULT_GLOBAL_FLOORS);
    }

    #[test]
    fn canonical_json_matches_expected_encoding() {
        // key order: scopes numeric-sorted (1, 2, 10); strings escaped.
        let v = json!({"b": 1, "a": [1, 2], "s": "x\ny"});
        assert_eq!(canonical_json(&v), r#"{"a":[1,2],"b":1,"s":"x\ny"}"#);
        let scoped = json!({"10": 1, "2": 2, "1": 3});
        assert_eq!(canonical_json(&scoped), r#"{"1":3,"2":2,"10":1}"#);
    }

    #[test]
    fn scope_minimum_never_violated() {
        let p = policy();
        for scope in [1u32, 2, 3] {
            for score in (0..=1000).step_by(25) {
                let d = p.decide(
                    scope,
                    score,
                    &zero_vector(),
                    &healthy(),
                    0,
                    1_700_000_000_000,
                    0,
                );
                assert!(
                    d.action.rank() >= p.minimum(scope).rank(),
                    "scope {scope} score {score} violated its minimum"
                );
            }
        }
    }

    #[test]
    fn global_floor_never_violated() {
        let p = policy();
        for level in 1..=4u8 {
            let floor = p.global_floors[level as usize];
            for score in (0..=1000).step_by(25) {
                let d = p.decide(
                    1,
                    score,
                    &zero_vector(),
                    &healthy(),
                    level,
                    1_700_000_000_000,
                    0,
                );
                assert!(
                    d.action.rank() >= floor.rank(),
                    "global level {level} score {score} violated floor {floor:?}"
                );
            }
        }
    }

    #[test]
    fn band_action_applied() {
        let p = policy();
        let d = p.decide(1, 500, &zero_vector(), &healthy(), 0, 1_700_000_000_000, 0);
        assert_eq!(d.action, RiskAction::Sha20);
        assert_eq!(d.score, 500);
        assert_eq!(d.band, 5);
    }

    #[test]
    fn replay_hard_override() {
        let p = policy();
        let d = p.decide(
            1,
            0,
            &SignalVector {
                replay: 700,
                ..Default::default()
            },
            &healthy(),
            0,
            1_700_000_000_000,
            0,
        );
        assert_eq!(d.action, RiskAction::Deny);
        assert!(d.has_reason(RiskReason::ReplayTraffic));

        let d = p.decide(
            1,
            0,
            &SignalVector {
                replay: 699,
                ..Default::default()
            },
            &healthy(),
            0,
            1_700_000_000_000,
            0,
        );
        assert_ne!(d.action, RiskAction::Deny);
    }

    #[test]
    fn malformed_hard_override() {
        let p = policy();
        let d = p.decide(
            1,
            0,
            &SignalVector {
                malformed: 800,
                ..Default::default()
            },
            &healthy(),
            0,
            1_700_000_000_000,
            0,
        );
        assert_eq!(d.action, RiskAction::Deny);
        assert!(d.has_reason(RiskReason::MalformedTraffic));

        let d = p.decide(
            1,
            0,
            &SignalVector {
                malformed: 799,
                ..Default::default()
            },
            &healthy(),
            0,
            1_700_000_000_000,
            0,
        );
        assert_ne!(d.action, RiskAction::Deny);
    }

    #[test]
    fn source_fast_hard_override() {
        let p = policy();
        let d = p.decide(
            1,
            0,
            &SignalVector {
                source_fast: 950,
                ..Default::default()
            },
            &healthy(),
            0,
            1_700_000_000_000,
            0,
        );
        assert_eq!(d.action, RiskAction::Deny);
        assert!(d.has_reason(RiskReason::HardRateLimit));

        let d = p.decide(
            1,
            0,
            &SignalVector {
                source_fast: 949,
                ..Default::default()
            },
            &healthy(),
            0,
            1_700_000_000_000,
            0,
        );
        assert_ne!(d.action, RiskAction::Deny);
    }

    #[test]
    fn issuance_capacity_override() {
        let p = policy();
        let d = p.decide(
            1,
            0,
            &zero_vector(),
            &ResourcePressure {
                issuance_capacity: 99,
                ..Default::default()
            },
            0,
            1_700_000_000_000,
            0,
        );
        assert_eq!(d.action, RiskAction::Deny);
        assert!(d.has_reason(RiskReason::CapacityPressure));

        let d = p.decide(
            1,
            0,
            &zero_vector(),
            &ResourcePressure {
                issuance_capacity: 100,
                ..Default::default()
            },
            0,
            1_700_000_000_000,
            0,
        );
        assert_ne!(d.action, RiskAction::Deny);
    }

    #[test]
    fn argon_step_up_on_low_argon_capacity() {
        let p = policy();
        let d = p.decide(
            1,
            600,
            &zero_vector(),
            &ResourcePressure {
                argon_capacity: 299,
                ..Default::default()
            },
            0,
            1_700_000_000_000,
            0,
        );
        assert_eq!(d.action, RiskAction::StepUp);
        assert!(d.has_reason(RiskReason::CapacityPressure));

        let d = p.decide(
            1,
            600,
            &zero_vector(),
            &ResourcePressure {
                argon_capacity: 300,
                ..Default::default()
            },
            0,
            1_700_000_000_000,
            0,
        );
        assert_eq!(d.action, RiskAction::Argon16);
        assert!(!d.has_reason(RiskReason::CapacityPressure));
    }

    #[test]
    fn floors_or_minimum_never_reintroduce_argon() {
        // Score 600 -> Argon16; global floor 4 is Sha20 (rank 3 < 4) so the
        // strongest() is still Argon16. With argon capacity exhausted the
        // FINAL action must StepUp — a subsequent floor/minimum clamp must
        // not resurrect Argon.
        let p = policy();
        let d = p.decide(
            1,
            600,
            &zero_vector(),
            &ResourcePressure {
                argon_capacity: 100,
                ..Default::default()
            },
            4,
            1_700_000_000_000,
            0,
        );
        assert_eq!(d.action, RiskAction::StepUp);
        assert!(d.has_reason(RiskReason::CapacityPressure));

        // Scope 3 minimum is argon32: even the minimum alone cannot keep
        // Argon when the backend cannot serve it.
        let d = p.decide(
            3,
            100,
            &zero_vector(),
            &ResourcePressure {
                argon_capacity: 50,
                ..Default::default()
            },
            0,
            1_700_000_000_000,
            0,
        );
        assert_eq!(d.action, RiskAction::StepUp);
    }

    #[test]
    fn network_risk_override() {
        let p = policy();
        let d = p.decide(
            1,
            0,
            &SignalVector {
                network_risk: 900,
                ..Default::default()
            },
            &healthy(),
            0,
            1_700_000_000_000,
            0,
        );
        assert_eq!(d.action, RiskAction::Deny);
        assert!(d.has_reason(RiskReason::LocalNetworkRisk));

        let d = p.decide(
            1,
            0,
            &SignalVector {
                network_risk: 899,
                ..Default::default()
            },
            &healthy(),
            0,
            1_700_000_000_000,
            0,
        );
        assert_ne!(d.action, RiskAction::Deny);
    }

    #[test]
    fn cooldown_override_only_at_emergency_level() {
        let p = policy();
        let now = 1_700_000_000_000;
        // Elevated-but-non-emergency level: the hysteresis hold is a LEVEL
        // marker, NOT a per-source denial window — no deny.
        let d = p.decide(1, 0, &zero_vector(), &healthy(), 2, now, now + 5000);
        assert_ne!(
            d.action,
            RiskAction::Deny,
            "level-2 hysteresis hold must not deny"
        );
        assert_eq!(d.retry_after_ms, None);
        // Emergency level with a future hold -> Cooldown deny.
        let d = p.decide(1, 0, &zero_vector(), &healthy(), 4, now, now + 5000);
        assert_eq!(d.action, RiskAction::Deny);
        assert!(d.has_reason(RiskReason::Cooldown));
        assert_eq!(d.retry_after_ms, Some(5000));
        // Hold expired -> no deny.
        let d = p.decide(1, 0, &zero_vector(), &healthy(), 4, now, now);
        assert_ne!(d.action, RiskAction::Deny);
        assert_eq!(d.retry_after_ms, None);
    }

    #[test]
    fn multiple_reasons_capped_at_four() {
        let p = policy();
        let vector = SignalVector {
            replay: 700,
            malformed: 800,
            source_fast: 950,
            network_risk: 900,
            ..Default::default()
        };
        let now = 1_700_000_000_000;
        let d = p.decide(
            1,
            0,
            &vector,
            &ResourcePressure {
                issuance_capacity: 50,
                ..Default::default()
            },
            0,
            now,
            now + 1000,
        );
        assert_eq!(d.action, RiskAction::Deny);
        let reasons = d.reasons_vec();
        assert!(reasons.len() <= 4);
        // deduped
        let mut unique = std::collections::HashSet::new();
        for r in &reasons {
            assert!(unique.insert(*r), "duplicate reason {r:?}");
        }
    }

    #[test]
    fn degraded_clamped_to_minimum() {
        let p = policy();
        // scope 3: degraded argon16 (4) clamped to minimum argon32 (5)
        let d = p.degraded_decision(3, 0);
        assert_eq!(d.action, RiskAction::Argon32);
        assert!(d.has_reason(RiskReason::CapacityPressure));
        assert_eq!(d.score, 0);

        // scope 2: degraded sha20 (3) >= minimum sha16 (1)
        let d = p.degraded_decision(2, 0);
        assert_eq!(d.action, RiskAction::Sha20);

        // unknown scope degrades to allow
        let d = p.degraded_decision(999, 0);
        assert_eq!(d.action, RiskAction::Allow);
    }

    #[test]
    fn degraded_uses_last_known_level_floor() {
        let p = policy();
        // scope 2: degraded sha20 (3), minimum sha16 (1). The floor only
        // matters when it is STRONGER than the degraded action: at level 4
        // (floor sha20) and level 0 (allow) the result stays Sha20.
        assert_eq!(p.degraded_decision(2, 0).action, RiskAction::Sha20);
        assert_eq!(p.degraded_decision(2, 4).action, RiskAction::Sha20);

        // A scope whose degraded action is Allow: the last known global
        // floor must lift it (level 4 -> Sha20); at level 0 -> Allow.
        let weak = RiskPolicy::from_config(
            3,
            &json!({
                "version": 3,
                "weights": { "source_fast": 1, "source_slow": 1, "subnet_fast": 1,
                             "issue_debt": 1, "bad_proof": 1, "malformed": 1,
                             "replay": 1, "action_failure": 1, "scope_switch": 1,
                             "global_pressure": 1, "network_risk": 1,
                             "trust_credit": 1, "principal_credit": 1 },
                "scopes": {
                    "4": { "base_risk": 100, "minimum": "allow", "post_solve_check": true, "degraded": "allow" }
                },
                "global_floors": { "0": "allow", "1": "sha16", "2": "sha18", "3": "sha20", "4": "sha20" }
            }),
        )
        .expect("config parses");
        assert_eq!(weak.degraded_decision(4, 0).action, RiskAction::Allow);
        assert_eq!(weak.degraded_decision(4, 1).action, RiskAction::Sha16);
        assert_eq!(weak.degraded_decision(4, 2).action, RiskAction::Sha18);
        assert_eq!(weak.degraded_decision(4, 4).action, RiskAction::Sha20);
    }

    #[test]
    fn config_version_mismatch_is_rejected() {
        let mut cfg = config();
        cfg["version"] = json!(4);
        assert!(matches!(
            RiskPolicy::from_config(3, &cfg),
            Err(PolicyError::VersionMismatch {
                requested: 3,
                config: 4
            })
        ));
        // The requested version must also be an int in the config.
        cfg["version"] = json!("3");
        assert!(matches!(
            RiskPolicy::from_config(3, &cfg),
            Err(PolicyError::InvalidVersion)
        ));
    }

    #[test]
    fn base_risk_out_of_range_is_rejected() {
        let mut cfg = config();
        cfg["scopes"]["1"]["base_risk"] = json!(1001);
        assert!(matches!(
            RiskPolicy::from_config(3, &cfg),
            Err(PolicyError::InvalidBaseRisk(_))
        ));
        // Non-integer base_risk is rejected too (no silent cast).
        let mut cfg = config();
        cfg["scopes"]["1"]["base_risk"] = json!("100");
        assert!(matches!(
            RiskPolicy::from_config(3, &cfg),
            Err(PolicyError::InvalidBaseRisk(_))
        ));
    }

    #[test]
    fn scope_id_zero_is_rejected() {
        let mut cfg = config();
        cfg["scopes"]["0"] = cfg["scopes"]["1"].clone();
        assert!(matches!(
            RiskPolicy::from_config(3, &cfg),
            Err(PolicyError::InvalidScopeId(_))
        ));
    }

    #[test]
    fn global_floors_require_exactly_five_entries() {
        // Missing "0" -> rejected.
        let mut cfg = config();
        cfg["global_floors"] = json!({ "1": "sha16", "2": "sha18", "3": "sha20", "4": "sha20" });
        assert!(matches!(
            RiskPolicy::from_config(3, &cfg),
            Err(PolicyError::InvalidGlobalFloors(_))
        ));
        // Level 0 != allow -> rejected.
        let mut cfg = config();
        cfg["global_floors"]["0"] = json!("sha16");
        assert!(matches!(
            RiskPolicy::from_config(3, &cfg),
            Err(PolicyError::InvalidGlobalFloors(_))
        ));
        // Missing entry -> rejected.
        let mut cfg = config();
        cfg["global_floors"].as_object_mut().unwrap().remove("4");
        assert!(matches!(
            RiskPolicy::from_config(3, &cfg),
            Err(PolicyError::InvalidGlobalFloors(_))
        ));
    }

    #[test]
    fn degraded_global_level_passthrough() {
        let p = policy();
        assert_eq!(p.degraded_decision(1, 3).global_level, 3);
        assert_eq!(p.degraded_decision(1, 0).global_level, 0);
        assert_eq!(p.degraded_decision(1, 3).policy_version, 3);
    }

    #[test]
    fn decision_json_serialization() {
        let p = policy();
        let d = p.decide(1, 500, &zero_vector(), &healthy(), 2, 1_700_000_000_000, 0);
        let json = serde_json::to_value(&d).unwrap();
        assert_eq!(json["score"], 500);
        assert_eq!(json["action"], "sha20");
        assert_eq!(json["policy_version"], 3);
        assert_eq!(json["global_level"], 2);
        assert_eq!(json["retry_after_ms"], Value::Null);
        assert_eq!(json["band"], 5);
        assert!(json["reasons"].is_array());
    }

    /// AUDIT #95 — the policy-level wiring: an oscillating boundary score
    /// (449/451/449…) with the engine's hysteresis map yields a STABLE
    /// action (no flip-flop), while the plain `decide` (no map) keeps the
    /// pre-audit mapping.
    #[test]
    fn hysteresis_stabilizes_oscillating_boundary_scores() {
        let p = policy();
        let h = ScopeActionHysteresis::new();
        let now = 1_700_000_000_000;
        let mut actions = Vec::new();
        for (i, score) in [449u16, 451, 449, 451, 449, 451].iter().enumerate() {
            let d = p.decide_with_hysteresis(
                1,
                *score,
                &zero_vector(),
                &healthy(),
                0,
                now + i as u64,
                0,
                Some(&h),
            );
            actions.push(d.action);
        }
        assert_eq!(
            actions,
            vec![RiskAction::Sha18; 6],
            "an oscillating boundary score must not flip the challenge profile"
        );

        // The plain decide (no map) still flips at the boundary: the
        // hysteresis is only active on the engine's decision path.
        assert_eq!(
            p.decide(1, 449, &zero_vector(), &healthy(), 0, now, 0)
                .action,
            RiskAction::Sha18
        );
        assert_eq!(
            p.decide(1, 451, &zero_vector(), &healthy(), 0, now, 0)
                .action,
            RiskAction::Sha20
        );
    }

    /// AUDIT #95 — hysteresis never violates the scope minimum or the
    /// global floor (the clamps apply AFTER the band selection).
    #[test]
    fn hysteresis_never_violates_minimum_or_floor() {
        let p = policy();
        for scope in [1u32, 2, 3] {
            let h = ScopeActionHysteresis::new();
            let mut now = 1_700_000_000_000;
            for score in (0..=1000u16).step_by(25) {
                let d = p.decide_with_hysteresis(
                    scope,
                    score,
                    &zero_vector(),
                    &healthy(),
                    0,
                    now,
                    0,
                    Some(&h),
                );
                assert!(
                    d.action.rank() >= p.minimum(scope).rank(),
                    "scope {scope} score {score} violated its minimum"
                );
                let d = p.decide_with_hysteresis(
                    scope,
                    score,
                    &zero_vector(),
                    &healthy(),
                    3,
                    now + 1,
                    0,
                    Some(&h),
                );
                assert!(
                    d.action.rank() >= RiskAction::Sha20.rank(),
                    "scope {scope} score {score} violated the global floor"
                );
                now += 2;
            }
        }
    }
}
