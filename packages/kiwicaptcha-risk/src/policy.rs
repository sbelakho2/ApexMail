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
//!
//! `policy_version` (the config's `version`, stamped on every decision):
//! bump it whenever the operator policy materially changes. A model
//! revision that materially affects security — e.g. changes how scores
//! are computed or how calibration moves the bias — requires a
//! `policy_version` bump too, so the decision's `policy_version` always
//! pins down both the operator policy AND the security-relevant model
//! generation it was computed under.

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
    MarkedIdentity,
    CorroboratedAbuse,
    TargetUnderAttack,
    PricedEscalation,
    InteractionAnomaly,
    SolveAnomaly,
    DecoyEscalation,
    SpamMarkQuarantine,
    NovelNetwork,
    BreachedCredential,
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
            RiskReason::MarkedIdentity => "marked_identity",
            RiskReason::CorroboratedAbuse => "corroborated_abuse",
            RiskReason::TargetUnderAttack => "target_under_attack",
            RiskReason::PricedEscalation => "priced_escalation",
            RiskReason::InteractionAnomaly => "interaction_anomaly",
            RiskReason::SolveAnomaly => "solve_anomaly",
            RiskReason::DecoyEscalation => "decoy_escalation",
            RiskReason::SpamMarkQuarantine => "spam_mark_quarantine",
            RiskReason::NovelNetwork => "novel_network",
            RiskReason::BreachedCredential => "breached_credential",
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
    /// The row applied to every scope the config does not list: a
    /// conservative default (base risk 100, minimum sha20, degraded
    /// sha20) unless the config overrides it with a `default_scope`
    /// object shaped exactly like a scope row. Unconfigured scopes must
    /// never degrade to Allow: a scope the operator forgot to list would
    /// otherwise be the weakest hole in the policy.
    pub default_scope: ScopePolicy,
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
    /// `global_floors` must have exactly 5 entries (levels 0..4) with
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
            // The canonical grammar both languages share: a u32 spelled
            // as [1-9][0-9]* — no leading zeros, no sign, no trailing
            // garbage. "01" and "+1" are configuration errors exactly
            // like the PHP parser's non-integer keys, never silently
            // parsed onto scope 1.
            if key.is_empty()
                || !key
                    .bytes()
                    .next()
                    .is_some_and(|b| b.is_ascii_digit() && b != b'0')
                || !key.bytes().all(|b| b.is_ascii_digit())
            {
                return Err(PolicyError::InvalidScopeId(key.clone()));
            }
            let scope: u32 = key
                .parse()
                .map_err(|_| PolicyError::InvalidScopeId(key.clone()))?;
            if scope == 0 {
                return Err(PolicyError::InvalidScopeId(key.clone()));
            }
            let parsed = parse_scope_row(spec, key)?;
            scopes.insert(scope, parsed);
        }

        // The unconfigured-scope row: optional, but shaped exactly like a
        // scope row. The default is deliberately NOT Allow on any axis.
        let default_scope = match config.get("default_scope") {
            Some(value) => parse_scope_row(value, "default_scope")?,
            None => ScopePolicy {
                base_risk: 100,
                minimum: RiskAction::Sha20,
                post_solve_check: false,
                degraded: RiskAction::Sha20,
            },
        };

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
                // The canonical key grammar: the level keys are exactly the
                // five literal spellings "0".."4". Generic integer parsing
                // would accept non-canonical spellings ("01", "+1") and
                // could map two distinct JSON keys onto one logical level,
                // leaving another level at its built-in default — exactly
                // the PHP/Rust parser divergence the scope-key grammar
                // already closes. Every logical level must be declared
                // exactly once.
                let mut seen = [false; 5];
                for (key, action) in obj {
                    let level = match key.as_str() {
                        "0" => 0usize,
                        "1" => 1,
                        "2" => 2,
                        "3" => 3,
                        "4" => 4,
                        _ => {
                            return Err(PolicyError::InvalidGlobalFloors(format!(
                                "bad level {key}"
                            )));
                        }
                    };
                    if seen[level] {
                        return Err(PolicyError::InvalidGlobalFloors(format!(
                            "duplicate level {level}"
                        )));
                    }
                    seen[level] = true;
                    let parsed = parse_action(action)?;
                    if level == 0 && parsed != RiskAction::Allow {
                        return Err(PolicyError::InvalidGlobalFloors(
                            "level 0 must be \"allow\"".to_string(),
                        ));
                    }
                    floors[level] = parsed;
                }
                if seen.iter().any(|declared| !declared) {
                    return Err(PolicyError::InvalidGlobalFloors(
                        "global_floors must declare every level 0..=4".to_string(),
                    ));
                }
            }
        }

        let hash: [u8; 32] = Sha256::digest(canonical_json(config).as_bytes()).into();

        Ok(RiskPolicy {
            version,
            hash,
            weights,
            scopes,
            default_scope,
            global_floors: floors,
        })
    }

    /// Base risk for a scope: the scope row, else the conservative
    /// `default_scope` row.
    pub fn base_risk(&self, scope: u32) -> u16 {
        self.scopes
            .get(&scope)
            .map_or(self.default_scope.base_risk, |s| s.base_risk)
    }

    /// Minimum action for a scope: the scope row, else `default_scope`.
    pub fn minimum(&self, scope: u32) -> RiskAction {
        self.scopes
            .get(&scope)
            .map_or(self.default_scope.minimum, |s| s.minimum)
    }

    /// Full decision: band action, clamped to the scope minimum and the
    /// global floor, then hard overrides with reasons.
    ///
    /// Convenience wrapper without the scope-action hysteresis map (the
    /// plain band mapping); the engine uses
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
            &[],
        )
    }

    /// Full decision: band action (with enter/exit hysteresis when the
    /// engine's per-client map is passed), clamped to the scope
    /// minimum and the global floor, then hard overrides with reasons.
    ///
    /// Argon re-escalation order: `action = strongest(band, minimum,
    /// floor)` first; then, when the final action is Argon and the argon
    /// capacity is below 300, the action steps UP to `StepUp` — the
    /// capacity check is last, so floors/minimum can never reintroduce
    /// Argon after a demotion.
    ///
    /// Hysteresis: with `hysteresis` the band selection uses the
    /// `(scope, client)` entry named by `client` — the session pseudonym
    /// when present, else the source pseudonym. The selection escalates to
    /// the next band only at its enter threshold (upper + 10), de-escalates
    /// only below its exit threshold (lower − 10), and jumps straight to
    /// the plain action when the score clears the target band margin.
    /// Fresh keys and StepUp/Deny use the plain mapping. The map stores the
    /// SCORE-selected action, so hard overrides never poison the profile.
    /// `None` keeps the plain band mapping.
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
        client: &[u8],
    ) -> RiskDecision {
        let plain = RiskAction::action_for_score(score);
        let band_action =
            hysteresis.map_or(plain, |h| h.select(scope, client, score, plain, now_ms));
        let minimum = self.minimum(scope);
        let floor = self.global_floors[(global_level as usize).min(4)];
        let mut action = strongest(band_action, minimum, floor);

        let mut reasons: Vec<RiskReason> = Vec::new();
        let mut deny = false;
        let mut retry_after_ms = None;
        let mut velocity_floor: Option<RiskAction> = None;

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
            // Velocity alone must not hard-deny: a shared IPv4 address
            // (cgnat, an office, a campus) can exceed the saturation from
            // legitimate volume, and the history is shed with the /64
            // source identity so a single abusive host cannot speak for
            // the aggregate. Deny only when another hard signal
            // corroborates the source; otherwise floor the action at
            // Argon32 (the strongest non-interactive band) and let the
            // score/capacity logic decide — the argon-capacity check
            // below still re-escalates a saturated backend to StepUp.
            if s.bad_proof >= 300 || s.malformed >= 300 || s.replay >= 300 {
                deny = true;
            } else {
                velocity_floor = Some(RiskAction::Argon32);
            }
        }
        if r.issuance_capacity < 100 {
            reasons.push(RiskReason::CapacityPressure);
            deny = true;
        }
        if s.network_risk >= 900 {
            reasons.push(RiskReason::LocalNetworkRisk);
            deny = true;
        }
        // The cooldown_until value from the store is the global hysteresis
        // hold marker (the level-until deadline), NOT a per-source denial
        // window — treating it as such would deny every request while the
        // global level is merely elevated. Cooldown denial applies only at
        // emergency level, where the global controller intends a temporary
        // admission stop.
        if cooldown_until_ms > 0 && now_ms < cooldown_until_ms && global_level >= 4 {
            reasons.push(RiskReason::Cooldown);
            deny = true;
            // The retry hint is the u32 wire field: saturate at the ceiling
            // instead of wrapping a long hold into a much earlier retry (the
            // PHP mirror saturates identically).
            retry_after_ms = Some((cooldown_until_ms - now_ms).min(u32::MAX as u64) as u32);
        }

        if deny {
            action = RiskAction::Deny;
        } else if let Some(floor_action) = velocity_floor {
            action = strongest(action, floor_action, action);
            if action.is_argon() && r.argon_capacity < 300 {
                action = RiskAction::StepUp;
                reasons.push(RiskReason::CapacityPressure);
            }
        } else if action.is_argon() && r.argon_capacity < 300 {
            // Capacity check last: the final action is Argon and the
            // backend cannot serve memory-hard work — re-escalate to the
            // interactive step-up flow instead of weakening the guard.
            action = RiskAction::StepUp;
            reasons.push(RiskReason::CapacityPressure);
        }

        // The weighted top contributors, appended exactly like the PHP
        // decision assembles them: hard-policy reasons first, then the
        // contributor list, then one dedupe pass and the 4-entry cap. The
        // two languages must surface the identical ordered reason list for
        // identical inputs (the shared reason vectors pin it).
        reasons.extend(contributor_reasons(s, &self.weights));

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
            model_revision: crate::RISK_MODEL_REVISION,
            global_level,
            retry_after_ms,
            band: (score.clamp(0, 1000) / 100) as u8,
            decision_id: String::new(),
            quarantined: false,
        }
    }

    /// Degraded decision (state backend unavailable): the scope's degraded
    /// action clamped to at least the scope minimum AND the global floor of
    /// the store's last known level — `global_floors[min(level, 4)]`;
    /// level 0 = Allow. Never fails open below the minimum or the floor.
    pub fn degraded_decision(&self, scope: u32, global_level: u8) -> RiskDecision {
        let degraded = self
            .scopes
            .get(&scope)
            .map_or(self.default_scope.degraded, |s| s.degraded);
        let floor = self.global_floors[(global_level as usize).min(4)];
        let action = strongest(degraded, self.minimum(scope), floor);

        RiskDecision {
            score: 0,
            action,
            reasons: [Some(RiskReason::CapacityPressure), None, None, None],
            policy_version: self.version,
            model_revision: crate::RISK_MODEL_REVISION,
            global_level,
            retry_after_ms: None,
            band: 0,
            decision_id: String::new(),
            quarantined: false,
        }
    }
}

/// Top contributors: for the 11 positive signals in `SignalVector`
/// order, contribution = (value * weight) / 1000 (integer division);
/// contributions > 0 are kept in `SignalVector` order, then sorted by
/// contribution descending (stable, so ties keep the `SignalVector`
/// order). Mirrors the PHP `RiskPolicy::contributorReasons()` exactly,
/// including the tie order, because the reason list is part of the
/// cross-language decision contract.
fn contributor_reasons(s: &SignalVector, w: &RiskWeights) -> Vec<RiskReason> {
    let pairs = [
        (s.source_fast, w.source_fast, RiskReason::SourceBurst),
        (s.source_slow, w.source_slow, RiskReason::SourceSustained),
        (s.subnet_fast, w.subnet_fast, RiskReason::NetworkBurst),
        (s.issue_debt, w.issue_debt, RiskReason::ChallengeDebt),
        (s.bad_proof, w.bad_proof, RiskReason::InvalidProofs),
        (s.malformed, w.malformed, RiskReason::MalformedTraffic),
        (s.replay, w.replay, RiskReason::ReplayTraffic),
        (
            s.action_failure,
            w.action_failure,
            RiskReason::ActionFailures,
        ),
        (s.scope_switch, w.scope_switch, RiskReason::ScopeHopping),
        (
            s.global_pressure,
            w.global_pressure,
            RiskReason::GlobalAttack,
        ),
        (s.network_risk, w.network_risk, RiskReason::LocalNetworkRisk),
    ];
    let mut contributions: Vec<(RiskReason, u32)> = Vec::new();
    for (value, weight, reason) in pairs {
        let contribution = (u32::from(value) * u32::from(weight)) / 1000;
        if contribution > 0 {
            contributions.push((reason, contribution));
        }
    }
    contributions.sort_by_key(|entry| std::cmp::Reverse(entry.1));

    contributions
        .into_iter()
        .map(|(reason, _)| reason)
        .collect()
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

/// Parses one scope row (a configured scope or `default_scope`): every
/// field is required, `base_risk` must be an integer within 0..=1000 (a
/// float or string is a configuration error, never a silent cast) and the
/// actions are the exact literal strings.
fn parse_scope_row(spec: &Value, label: &str) -> Result<ScopePolicy, PolicyError> {
    let spec_obj = spec
        .as_object()
        .ok_or_else(|| PolicyError::InvalidScope(label.to_string()))?;
    let required = ["base_risk", "minimum", "post_solve_check", "degraded"];
    for field in required {
        if !spec_obj.contains_key(field) {
            return Err(PolicyError::InvalidScope(label.to_string()));
        }
    }
    let base_risk_value = spec["base_risk"]
        .as_u64()
        .ok_or_else(|| PolicyError::InvalidBaseRisk(label.to_string()))?;
    if base_risk_value > 1000 {
        return Err(PolicyError::InvalidBaseRisk(label.to_string()));
    }
    Ok(ScopePolicy {
        base_risk: base_risk_value as u16,
        minimum: parse_action(&spec["minimum"])?,
        post_solve_check: spec["post_solve_check"]
            .as_bool()
            .ok_or_else(|| PolicyError::InvalidScope(label.to_string()))?,
        degraded: parse_action(&spec["degraded"])?,
    })
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

/// PHP `json_encode` default string escaping — unescaped slashes,
/// unescaped unicode semantics.
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
mod malformed_vectors {
    use super::*;

    /// The shared malformed-policy vectors (protocol/risk-v1/fixtures.json):
    /// every spelling both languages must reject under the identical
    /// canonical grammar — [1-9][0-9]* within u32 — plus literal-boolean
    /// post_solve_check flags.
    #[test]
    fn shared_malformed_scope_keys_and_flags_are_rejected() {
        let raw = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../protocol/risk-v1/fixtures.json"
        ))
        .expect("the shared fixtures must load");
        let value: serde_json::Value = serde_json::from_str(&raw).expect("valid json");
        let vectors = value
            .get("malformed_policy_vectors")
            .expect("the malformed-policy vectors must be recorded");

        let scope_row = serde_json::json!({
            "base_risk": 100, "minimum": "sha20", "post_solve_check": false, "degraded": "sha20"
        });
        for entry in vectors["malformed_policy_scopes"]
            .as_array()
            .expect("scope vectors")
        {
            let key = entry["key"].as_str().expect("the key is a string");
            let mut scopes = serde_json::Map::new();
            scopes.insert(key.to_string(), scope_row.clone());
            let mut config = serde_json::json!({
                "version": 3,
                "global_floors": { "0": "allow", "1": "sha16", "2": "sha18", "3": "sha20", "4": "sha20" },
                "weights": {},
            });
            config
                .as_object_mut()
                .expect("config object")
                .insert("scopes".into(), Value::Object(scopes));
            let err = RiskPolicy::from_config(3, &config)
                .err()
                .unwrap_or_else(|| panic!("the malformed scope key {key} must be rejected"));
            assert!(
                matches!(err, PolicyError::InvalidScopeId(_)),
                "the malformed key {key} fails the canonical-grammar rejection: {err}"
            );
        }

        for entry in vectors["malformed_policy_flags"]
            .as_array()
            .expect("flag vectors")
        {
            let flag = entry["value"].clone();
            let config = serde_json::json!({
                "version": 3,
                "global_floors": { "0": "allow", "1": "sha16", "2": "sha18", "3": "sha20", "4": "sha20" },
                "weights": {},
                "scopes": { "1": {
                    "base_risk": 100, "minimum": "sha20", "post_solve_check": flag, "degraded": "sha20"
                }}
            });
            let err = RiskPolicy::from_config(3, &config)
                .err()
                .unwrap_or_else(|| panic!("the malformed flag {flag} must be rejected"));
            assert!(
                matches!(err, PolicyError::InvalidScope(_)),
                "the malformed flag {flag} fails the literal-boolean rejection: {err}"
            );
        }

        // The shared reason vectors: identical inputs must surface the
        // identical ordered reason list in PHP and Rust, including the
        // contributor ordering and the stable tie order.
        let raw = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../protocol/risk-v1/fixtures.json"
        ))
        .expect("the shared fixtures must load");
        let fixtures: serde_json::Value = serde_json::from_str(&raw).expect("valid json");
        let reason_vectors = fixtures["reason_vectors"]
            .as_array()
            .expect("reason vectors");
        assert!(!reason_vectors.is_empty());
        for vector in reason_vectors {
            let config = serde_json::json!({
                "version": 3,
                "weights": vector["weights"].clone(),
                "scopes": { "1": {
                    "base_risk": 100, "minimum": "allow", "post_solve_check": false, "degraded": "allow"
                }},
                "global_floors": {"0": "allow", "1": "allow", "2": "allow", "3": "allow", "4": "allow"},
            });
            let policy = RiskPolicy::from_config(3, &config).expect("the vector policy builds");
            let signals: crate::signals::SignalVector =
                serde_json::from_value(vector["signals"].clone())
                    .expect("the vector signals parse");
            let pressure = crate::resources::ResourcePressure {
                argon_capacity: vector["argon_capacity"].as_u64().expect("argon") as u16,
                issuance_capacity: vector["issuance_capacity"].as_u64().expect("issuance") as u16,
            };
            let decision = policy.decide(
                1,
                vector["score"].as_u64().expect("score") as u16,
                &signals,
                &pressure,
                vector["global_level"].as_u64().expect("level") as u8,
                1_700_000_000_000,
                0,
            );
            let actual: Vec<&str> = decision
                .reasons
                .iter()
                .flatten()
                .map(|reason| reason.as_str())
                .collect();
            let expected: Vec<&str> = vector["expected_reasons"]
                .as_array()
                .expect("expected reasons")
                .iter()
                .map(|reason| reason.as_str().expect("reason"))
                .collect();
            assert_eq!(
                expected,
                actual,
                "reason vector mismatch: {}",
                vector["why"].as_str().unwrap_or("")
            );
            if let Some(expected_action) = vector.get("expected_action").and_then(|v| v.as_str()) {
                assert_eq!(
                    expected_action,
                    decision.action.as_str(),
                    "action vector mismatch: {}",
                    vector["why"].as_str().unwrap_or("")
                );
            }
        }

        // The shared malformed global-floor values: an integer,
        // boolean, array or object action is rejected exactly like the
        // PHP parser's literal-string requirement — one shared
        // acceptance set for the two policy readers.
        for entry in vectors["malformed_global_floor_values"]
            .as_array()
            .expect("global-floor value vectors")
        {
            let level = entry["level"].as_str().expect("level");
            let why = entry["why"].as_str().unwrap_or("malformed action");
            let mut floors = serde_json::Map::new();
            for canonical in ["0", "1", "2", "3", "4"] {
                floors.insert(canonical.to_string(), serde_json::json!("sha20"));
            }
            floors.insert("0".to_string(), serde_json::json!("allow"));
            floors.insert(level.to_string(), entry["value"].clone());
            let config = serde_json::json!({
                "version": 3,
                "global_floors": floors,
                "weights": {},
                "scopes": { "1": {
                    "base_risk": 100, "minimum": "sha20", "post_solve_check": false, "degraded": "sha20"
                }}
            });
            let err = RiskPolicy::from_config(3, &config).err().unwrap_or_else(|| {
                panic!("the malformed global floor action at level {level} must be rejected: {why}")
            });
            assert!(
                matches!(
                    err,
                    PolicyError::InvalidGlobalFloors(_) | PolicyError::InvalidAction(_)
                ),
                "the malformed action at level {level} fails the literal-string rejection: {err}"
            );
        }

        // The shared malformed global-floor sets: the level keys are
        // exactly the five canonical spellings "0".."4", each declared
        // exactly once. A non-canonical spelling ("01", "+1", "04") must
        // never be parsed onto a logical level, and a five-member object
        // that repeats one logical level leaves another level absent —
        // both are configuration errors in Rust exactly like the PHP
        // parser's non-integer-key rejection.
        for entry in vectors["malformed_global_floor_sets"]
            .as_array()
            .expect("global-floor vectors")
        {
            let floors = entry["floors"].clone();
            let why = entry["why"].as_str().unwrap_or("malformed floors");
            let config = serde_json::json!({
                "version": 3,
                "global_floors": floors,
                "weights": {},
                "scopes": { "1": {
                    "base_risk": 100, "minimum": "sha20", "post_solve_check": false, "degraded": "sha20"
                }}
            });
            let err = RiskPolicy::from_config(3, &config)
                .err()
                .unwrap_or_else(|| {
                    panic!("the malformed global_floors {floors} must be rejected: {why}")
                });
            assert!(
                matches!(err, PolicyError::InvalidGlobalFloors(_)),
                "the malformed global_floors {floors} fails the canonical-level rejection: {err}"
            );
        }
    }
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
        // Unconfigured scopes use the conservative default_scope row
        // (sha20 minimum / sha20 degraded), never Allow.
        assert_eq!(p.minimum(999), RiskAction::Sha20);
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
        // Velocity alone must not hard-deny a shared address: the reason
        // is recorded and the action is floored at the strongest
        // non-interactive band.
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
        assert_eq!(d.action, RiskAction::Argon32);
        assert!(d.has_reason(RiskReason::HardRateLimit));

        // Corroboration (another hard signal at its floor) restores the
        // hard deny.
        let d = p.decide(
            1,
            0,
            &SignalVector {
                source_fast: 950,
                bad_proof: 300,
                ..Default::default()
            },
            &healthy(),
            0,
            1_700_000_000_000,
            0,
        );
        assert_eq!(d.action, RiskAction::Deny);
        assert!(d.has_reason(RiskReason::HardRateLimit));

        // A saturated backend re-escalates the velocity floor to the
        // interactive step-up flow instead of weakening it.
        let d = p.decide(
            1,
            0,
            &SignalVector {
                source_fast: 950,
                ..Default::default()
            },
            &ResourcePressure {
                issuance_capacity: 1000,
                argon_capacity: 0,
            },
            0,
            1_700_000_000_000,
            0,
        );
        assert_eq!(d.action, RiskAction::StepUp);
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
        // final action must StepUp — a subsequent floor/minimum clamp must
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
        // Elevated-but-non-emergency level: the hysteresis hold is a level
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

        // unknown scope degrades to the conservative default_scope row
        let d = p.degraded_decision(999, 0);
        assert_eq!(d.action, RiskAction::Sha20);
    }

    #[test]
    fn degraded_uses_last_known_level_floor() {
        let p = policy();
        // scope 2: degraded sha20 (3), minimum sha16 (1). The floor only
        // matters when it is stronger than the degraded action: at level 4
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
        // The degraded decision carries the model revision too.
        assert_eq!(
            p.degraded_decision(1, 3).model_revision,
            crate::RISK_MODEL_REVISION
        );
    }

    #[test]
    fn decision_json_serialization() {
        let p = policy();
        let d = p.decide(1, 500, &zero_vector(), &healthy(), 2, 1_700_000_000_000, 0);
        let json = serde_json::to_value(&d).unwrap();
        assert_eq!(json["score"], 500);
        assert_eq!(json["action"], "sha20");
        assert_eq!(json["policy_version"], 3);
        // The revision is exposed in the public JSON (bounded).
        assert_eq!(json["model_revision"], 17);
        assert_eq!(json["global_level"], 2);
        assert_eq!(json["retry_after_ms"], Value::Null);
        assert_eq!(json["band"], 5);
        assert!(json["reasons"].is_array());
    }

    /// The revision constant is a shared cross-language value.
    #[test]
    fn model_revision_constant_is_seventeen() {
        assert_eq!(crate::RISK_MODEL_REVISION, 17);
    }

    /// Policy-level wiring: an oscillating boundary score
    /// (449/451/449…) with the engine's hysteresis map yields a stable
    /// action (no flip-flop), while the plain `decide` (no map) keeps the
    /// plain band mapping.
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
                b"client",
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

    /// Hysteresis never violates the scope minimum or the
    /// global floor (the clamps apply after the band selection).
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
                    b"client",
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
                    b"client",
                );
                assert!(
                    d.action.rank() >= RiskAction::Sha20.rank(),
                    "scope {scope} score {score} violated the global floor"
                );
                now += 2;
            }
        }
    }

    /// Hysteresis on the decision path is keyed per client: a bot burst
    /// does not leak into another client's memory.
    #[test]
    fn hysteresis_is_keyed_per_client() {
        let p = policy();
        let h = ScopeActionHysteresis::new();
        let now = 1_700_000_000_000;
        let legit = p.decide_with_hysteresis(
            1,
            100,
            &zero_vector(),
            &healthy(),
            0,
            now,
            0,
            Some(&h),
            b"legit",
        );
        assert_eq!(legit.action, RiskAction::Allow);
        // The bot's own key jumps straight to Argon64.
        let bot = p.decide_with_hysteresis(
            1,
            900,
            &zero_vector(),
            &healthy(),
            0,
            now + 1,
            0,
            Some(&h),
            b"bot",
        );
        assert_eq!(bot.action, RiskAction::Argon64);
        // A client with no history keeps the plain mapping.
        let fresh = p.decide_with_hysteresis(
            1,
            100,
            &zero_vector(),
            &healthy(),
            0,
            now + 2,
            0,
            Some(&h),
            b"fresh",
        );
        assert_eq!(fresh.action, RiskAction::Allow);
    }
}
