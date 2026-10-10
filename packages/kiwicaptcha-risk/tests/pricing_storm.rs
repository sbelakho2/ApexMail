//! The change.md 3.3.2 done-when simulator: a level-4 global-pressure
//! storm composed through the real engine with the pricing stage wired.
//!
//! The storm drives the global-pressure plumbing exactly the way the
//! state script does (risk-v1.lua): 32 back-to-back PreIssue events each
//! add 2000 raw pressure (rf 1000 + rs 1000), the raw total 64000
//! normalizes against the 70000 saturation to 914, and 914 clears the
//! level-4 enter threshold of the script's ratchet. The scenario is
//! deterministic and policy-layer only: a store stub replays the
//! storm-normalized vector and the ratcheted level, no sleeps and no
//! real backend.
//!
//! Done-when (the solve-time proxy at rung granularity): the trusted
//! session's priced rung moves at most one rung versus its calm
//! baseline, while the unproven storm sessions land at the full
//! escalation (an argon rung or stronger). The plain policy's global
//! floor keeps composing underneath: the trusted session's final action
//! at level 4 stays at the operator's floor because the price may only
//! raise, never lower.

use std::sync::{Arc, Mutex};

use kiwicaptcha_risk::action::RiskAction;
use kiwicaptcha_risk::context::RiskContext;
use kiwicaptcha_risk::event::{RiskEventKind, RiskObservation};
use kiwicaptcha_risk::keys::RiskKeys;
use kiwicaptcha_risk::network::{CidrNetworkClassifier, NetworkFlags};
use kiwicaptcha_risk::policy::{RiskPolicy, RiskReason};
use kiwicaptcha_risk::pricing::{
    PriceContextSource, PriceInputs, PriceModel, PriceRequest, ValueClass,
};
use kiwicaptcha_risk::resources::ResourcePressure;
use kiwicaptcha_risk::signals::SignalVector;
use kiwicaptcha_risk::store::{
    Observed, RiskStateStore, RiskStoreError, SessionContextTagStore, SessionTlsTagStore,
};
use kiwicaptcha_risk::{RiskEngine, RiskError};
use serde_json::json;

/// The storm size of the Redis store tests: 32 PreIssue events.
const STORM_EVENTS: u32 = 32;
/// Raw pressure one PreIssue adds (rf 1000 + rs 1000), per risk-v1.lua.
const RAW_PER_EVENT: u32 = 2_000;
/// The global-pressure saturation (the Lua argv normalizer).
const GLOBAL_SATURATION: u32 = 70_000;
/// The state script's level enter thresholds (risk-v1.lua).
const ENTER: [u16; 4] = [300, 550, 750, 900];

/// The script's `normalize(gp, saturation)` in pure integer math.
fn normalize_global(raw: u32) -> u16 {
    ((raw * 1000) / GLOBAL_SATURATION).min(1000) as u16
}

/// The script's ratchet: the highest level whose enter threshold the
/// normalized pressure clears.
fn target_level(gnorm: u16) -> u8 {
    (1..=4u8)
        .rev()
        .find(|level| gnorm >= ENTER[usize::from(*level - 1)])
        .unwrap_or(0)
}

/// Replays one scenario vector and level on every observation.
#[derive(Clone)]
struct ScenarioStore {
    vector: SignalVector,
    level: u8,
}

impl RiskStateStore for ScenarioStore {
    fn observe(&self, _o: &RiskObservation) -> Result<Observed, RiskStoreError> {
        Ok(Observed {
            vector: self.vector,
            global_level: self.level,
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
        Ok(1)
    }
    fn correct_outcome(
        &self,
        _decision_id: &str,
        _legitimate: bool,
    ) -> Result<bool, RiskStoreError> {
        Ok(true)
    }
}

impl SessionContextTagStore for ScenarioStore {}
impl SessionTlsTagStore for ScenarioStore {}

/// A price-context source answering fixed inputs, recording the requests
/// it saw (the marks-reader wiring-test pattern).
struct FixedSource {
    class: ValueClass,
    trust: u32,
    requests: Mutex<Vec<PriceRequest>>,
}

impl FixedSource {
    fn new(class: ValueClass, trust: u32) -> FixedSource {
        FixedSource {
            class,
            trust,
            requests: Mutex::new(Vec::new()),
        }
    }
}

impl PriceContextSource for FixedSource {
    fn price_inputs(&self, request: &PriceRequest) -> Result<PriceInputs, RiskError> {
        self.requests.lock().unwrap().push(request.clone());
        Ok(PriceInputs {
            value_class: self.class,
            bucket_trust: self.trust,
        })
    }
}

/// A source whose backend always fails: the engine must price
/// fail-closed as an unproven identity.
struct UnreadableSource;

impl PriceContextSource for UnreadableSource {
    fn price_inputs(&self, _request: &PriceRequest) -> Result<PriceInputs, RiskError> {
        Err(RiskError::Store("pricing surface unreadable".to_string()))
    }
}

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

fn keys() -> RiskKeys {
    RiskKeys::from_master(&[0x6bu8; 32])
}

fn engine(
    store: ScenarioStore,
    source: Option<Arc<FixedSource>>,
) -> RiskEngine<ScenarioStore, CidrNetworkClassifier> {
    let mut engine = RiskEngine::new(
        store,
        CidrNetworkClassifier::from_entries(Vec::new()),
        policy(),
        keys(),
    );
    if let Some(source) = source {
        engine = engine.with_price_context(source);
    }
    engine
}

fn ctx(session: &[u8; 16]) -> RiskContext<'_> {
    RiskContext::new(
        1,
        "203.0.113.27".parse().unwrap(),
        Some(session),
        None,
        RiskEventKind::PreIssue,
        NetworkFlags::default(),
        ResourcePressure::default(),
    )
}

/// The storm normalization and ratchet mirror the state script: 32
/// events of 2000 raw reach 914 normalized, which enters level 4.
#[test]
fn storm_drives_the_global_level_to_4_through_the_plumbing() {
    let raw = STORM_EVENTS * RAW_PER_EVENT;
    assert_eq!(raw, 64_000);
    let gnorm = normalize_global(raw);
    assert_eq!(gnorm, 914);
    assert_eq!(target_level(gnorm), 4);
    // every lower enter threshold clears on the way up, and calm does not
    assert_eq!(target_level(299), 0);
    assert_eq!(target_level(300), 1);
    assert_eq!(target_level(550), 2);
    assert_eq!(target_level(750), 3);
    assert_eq!(target_level(900), 4);
}

/// The done-when: under the level-4 storm the trusted session's priced
/// rung moves at most one rung versus its calm baseline, while the
/// unproven storm sessions land at the full escalation.
#[test]
fn l4_storm_prices_trusted_within_one_rung_and_escalates_untrusted() {
    let trusted_session = [0x42u8; 16];
    let storm_bot = [0x07u8; 16];

    // The trusted session's own signals: full bucket credit (raw 10000
    // normalizes to the 1000 trust signal) and nothing else.
    let calm_trusted_vector = SignalVector {
        trust_credit: 1000,
        ..Default::default()
    };
    // The storm bot's own signals: invalid proofs plus its own velocity,
    // on top of the storm's global pressure.
    let storm_bot_vector = SignalVector {
        bad_proof: 900,
        source_fast: 800,
        global_pressure: 914,
        ..Default::default()
    };
    let trusted_storm_vector = SignalVector {
        trust_credit: 1000,
        global_pressure: 914,
        ..Default::default()
    };

    // Calm baseline: level 0, clean signals.
    let calm = engine(
        ScenarioStore {
            vector: calm_trusted_vector,
            level: 0,
        },
        Some(Arc::new(FixedSource::new(ValueClass::Standard, 10_000))),
    );
    let calm_decision = calm.assess_pre_issue(ctx(&trusted_session), None).unwrap();
    assert_eq!(calm_decision.action, RiskAction::Allow);
    assert_eq!(
        calm_decision.score, 0,
        "the trust credit repays the base risk"
    );
    let calm_priced = PriceModel::price(
        calm_decision.score,
        ValueClass::Standard,
        10_000,
        calm_trusted_vector.global_pressure,
    );
    assert_eq!(calm_priced, RiskAction::Allow);

    // Storm: level 4 through the plumbing, the same trusted session.
    let storm = engine(
        ScenarioStore {
            vector: trusted_storm_vector,
            level: target_level(normalize_global(STORM_EVENTS * RAW_PER_EVENT)),
        },
        Some(Arc::new(FixedSource::new(ValueClass::Standard, 10_000))),
    );
    let storm_decision = storm.assess_pre_issue(ctx(&trusted_session), None).unwrap();
    assert_eq!(storm_decision.global_level, 4);
    // base 100 + weighted(914, 170) - weighted(1000, 130) = 125
    assert_eq!(storm_decision.score, 125);
    let storm_priced = PriceModel::price(
        storm_decision.score,
        ValueClass::Standard,
        10_000,
        trusted_storm_vector.global_pressure,
    );
    assert_eq!(storm_priced, RiskAction::Sha16);
    assert!(
        storm_priced.rank() - calm_priced.rank() <= 1,
        "the trusted session's priced rung moved {} rungs under the storm",
        storm_priced.rank() - calm_priced.rank()
    );
    // The composed action keeps the operator's level-4 floor (sha20):
    // the priced rung sha16 stays below it, and the price never lowers.
    assert_eq!(storm_decision.action, RiskAction::Sha20);

    // The unproven storm session: full escalation through the engine.
    let bot_engine = engine(
        ScenarioStore {
            vector: storm_bot_vector,
            level: 4,
        },
        Some(Arc::new(FixedSource::new(ValueClass::Standard, 0))),
    );
    let bot_decision = bot_engine.assess_pre_issue(ctx(&storm_bot), None).unwrap();
    assert_eq!(bot_decision.global_level, 4);
    // base 100 + 198 + 152 + 155 = 605 through the real scorer
    assert_eq!(bot_decision.score, 605);
    assert!(
        bot_decision.action.rank() >= RiskAction::Argon16.rank(),
        "the unproven storm session must land at the full escalation, got {:?}",
        bot_decision.action
    );
    // 605 + the full 914-pressure ramp = 902 work: the priced rung is the
    // interactive step-up, past the whole argon regime.
    assert_eq!(bot_decision.action, RiskAction::StepUp);
    assert!(bot_decision.has_reason(RiskReason::PricedEscalation));
}

/// The wiring is opt-in: the identical request through the unwired
/// engine keeps the plain decision, the wired engine's priced rung
/// raises it, and the source receives the derived pseudonym (32 hex
/// chars), never the raw cookie bytes. An unreadable source prices
/// fail-closed as an unproven identity.
#[test]
fn price_context_wiring_is_opt_in_and_fail_closed() {
    // A transient pressure signal without the ratcheted level proves the
    // stage reads the observed global-pressure signal as its pressure.
    let pressured = SignalVector {
        global_pressure: 914,
        ..Default::default()
    };
    let session = [0x99u8; 16];

    let unwired = engine(
        ScenarioStore {
            vector: pressured,
            level: 0,
        },
        None,
    );
    let plain = unwired.assess_pre_issue(ctx(&session), None).unwrap();
    // base 100 + weighted(914, 170) = 255 -> sha16 band
    assert_eq!(plain.score, 255);
    assert_eq!(plain.action, RiskAction::Sha16);
    assert!(!plain.has_reason(RiskReason::PricedEscalation));

    let source = Arc::new(FixedSource::new(ValueClass::Standard, 0));
    let wired = engine(
        ScenarioStore {
            vector: pressured,
            level: 0,
        },
        Some(source.clone()),
    );
    let priced = wired.assess_pre_issue(ctx(&session), None).unwrap();
    // 255 + the full 914-pressure ramp = 552 -> sha20
    assert_eq!(priced.action, RiskAction::Sha20);
    assert!(priced.has_reason(RiskReason::PricedEscalation));

    // The engine handed the source the derived session pseudonym.
    let requests = source.requests.lock().unwrap();
    assert_eq!(requests.len(), 1);
    let seen = requests[0].session.as_deref().expect("session present");
    assert_eq!(seen.len(), 32);
    assert!(seen.bytes().all(|b| b.is_ascii_hexdigit()));
    assert_ne!(seen, hex::encode(session));

    // An unreadable source prices the same request fail-closed: zero
    // credit, full ramp (identical action to the wired leg above).
    let fail_closed = RiskEngine::new(
        ScenarioStore {
            vector: pressured,
            level: 0,
        },
        CidrNetworkClassifier::from_entries(Vec::new()),
        policy(),
        keys(),
    )
    .with_price_context(Arc::new(UnreadableSource));
    let closed = fail_closed.assess_pre_issue(ctx(&session), None).unwrap();
    assert_eq!(closed.action, RiskAction::Sha20);
    assert!(closed.has_reason(RiskReason::PricedEscalation));
}
