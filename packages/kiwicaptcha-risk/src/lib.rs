//! KiwiCaptcha Adaptive Risk Engine (risk-v1 protocol).
//!
//! One pipeline turns a [`RiskContext`] into a [`RiskDecision`]:
//! emergency cap (one per-process window; the distributed Redis source
//! limiter handles per-source limits) → observation (epoch-scoped ephemeral
//! pseudonyms) → circuit breaker → state store (canonical Lua via evalsha)
//! → scorer (with calibration bias) → policy → top contributor reasons.
//! Backend failure degrades instead of failing the request.
//!
//! # Risk-v2 design note
//!
//! Detection produces probabilistic evidence; the risk engine scores that
//! evidence; the score maps to a decision action — Allow, Sha16, Sha18,
//! Sha20, Argon16, Argon32, Argon64, StepUp or Deny. The cryptographic
//! verifier (the proof/result-token boundary) never decides proof validity
//! from probabilistic evidence: evidence only ever moves the risk
//! aggregate, and the verifier only ever validates cryptographic proof.
//! The risk-v2 surfaces (honeypot/decoy evidence, session client-context
//! consistency, trusted-edge TLS consistency) are additive: they feed the
//! same multi-factor scorer as bounded fixed-point factors, never a gate,
//! and never weaken or bypass the risk-v1 state contract.

pub mod action;
pub mod breaker;
pub mod calibration;
pub mod context;
pub mod event;
pub mod hysteresis;
pub mod identity;
pub mod keys;
pub mod metrics;
pub mod network;
pub mod policy;
pub mod profile;
pub mod redis;
pub mod resources;
pub mod score;
pub mod signals;
pub mod store;

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use rand::{thread_rng, RngCore};
use serde::ser::{Serialize, SerializeStruct, Serializer};
use thiserror::Error;

use crate::action::RiskAction;
use crate::calibration::CalibrationStore;
use crate::context::{RiskContext, RiskV2Context};
use crate::event::{normalize_idempotency_key, RiskEventKind, RiskObservation};
use crate::identity::RiskIdentityFactory;
use crate::keys::RiskKeys;
use crate::metrics::Metrics;
use crate::network::NetworkClassifier;
use crate::policy::{RiskPolicy, RiskReason};
use crate::score::score as compute_score;
use crate::score::RiskV2Weights;
use crate::signals::SignalVector;
use crate::store::{
    Observed, OutcomeRegistration, RiskStateStore, SessionContextTagStore, SessionTlsTagStore,
};

/// Engine-level input error.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum RiskError {
    /// The caller idempotency key exceeds the 4096-byte contract limit.
    #[error("idempotency key must not exceed 4096 bytes (got {0})")]
    InvalidIdempotencyKey(usize),
    /// A confirmed outcome requires the decision_id of the assessed
    /// decision.
    #[error("confirmed outcomes require the decision_id of the assessed decision")]
    EmptyDecisionId,
    /// The calibration backend could not be reached; the confirm was not
    /// applied (callers treat calibration as best-effort).
    #[error("calibration backend failure: {0}")]
    Calibration(String),
    /// The risk state backend could not serve the always-on outcome
    /// ledger operation (register/confirm/correct without calibration).
    #[error("risk state backend failure: {0}")]
    Store(String),
    /// `record_feedback` takes non-confirmation events only: confirmed
    /// outcomes must go through
    /// [`RiskEngine::confirmed_legitimate`]/[`RiskEngine::confirmed_abuse`]
    /// (the wrappers guarantee the decision_id the ledger confirmation
    /// requires).
    #[error("confirmed outcomes must be recorded via confirmed_legitimate/confirmed_abuse (record_feedback takes non-confirmation events only)")]
    ConfirmationApiRequired,
}

/// The risk model generation implemented by this package.
///
/// Monotonically increasing (never reset). 17 is the current model
/// generation: 16 prior generations covered the fixed-point score
/// contract, class-normalized calibration, the random-sample resolution
/// gate, the outcome ledger and the rate-of-change clamp; this revision
/// adds the non-finite guards and the local-limiter warm-up
/// ramp to the model's behavior surface.
///
/// Every [`RiskDecision`] carries the revision it was computed under
/// (`model_revision`, exposed in the decision's public JSON — bounded,
/// unlike the internal `decision_id`), so consumers can detect mixed-model
/// fleets during a rollout. A model revision that materially affects
/// security requires a `policy_version` bump in the operator policy
/// snapshot (see [`crate::policy::RiskPolicy`]).
pub const RISK_MODEL_REVISION: u32 = 17;

/// Immutable risk decision produced by the engine.
///
/// Reasons are internal only (never exposed to the client) and capped at 4
/// (policy overrides first, then top contributor reasons). `decision_id`
/// identifies the decision for outcome calibration (see
/// [`RiskEngine::record_feedback`]); `model_revision` is the
/// current model revision generation the decision was computed under
/// (public JSON, bounded).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RiskDecision {
    pub score: u16,
    pub action: RiskAction,
    pub reasons: [Option<RiskReason>; 4],
    pub policy_version: u32,
    pub model_revision: u32,
    pub global_level: u8,
    pub retry_after_ms: Option<u32>,
    pub band: u8,
    /// Random 16-byte hex id; every decision registers under it — the
    /// always-on outcome ledger (and, with calibration attached, the
    /// calibration receipt) for ConfirmedLegitimate/ConfirmedAbuse.
    pub decision_id: String,
}

impl RiskDecision {
    /// True when the decision carries the given reason.
    pub fn has_reason(&self, reason: RiskReason) -> bool {
        self.reasons.contains(&Some(reason))
    }

    /// The present reasons, in priority order (at most 4).
    pub fn reasons_vec(&self) -> Vec<RiskReason> {
        self.reasons.iter().flatten().copied().collect()
    }
}

impl Serialize for RiskDecision {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let reasons: Vec<&str> = self.reasons.iter().flatten().map(|r| r.as_str()).collect();
        let mut state = serializer.serialize_struct("RiskDecision", 8)?;
        state.serialize_field("score", &self.score)?;
        state.serialize_field("action", self.action.as_str())?;
        state.serialize_field("reasons", &reasons)?;
        state.serialize_field("policy_version", &self.policy_version)?;
        state.serialize_field("model_revision", &self.model_revision)?;
        state.serialize_field("global_level", &self.global_level)?;
        state.serialize_field("retry_after_ms", &self.retry_after_ms)?;
        state.serialize_field("band", &self.band)?;
        state.end()
    }
}

/// Receipt of one recorded feedback event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventReceipt {
    /// The event_id (idempotency key or a random 16-byte hex id) that was
    /// applied.
    pub event_id: String,
    /// True when the event_id was already applied: the state was NOT
    /// mutated and `signals` are the current ones.
    pub is_duplicate: bool,
    /// The resulting signal vector.
    pub signals: SignalVector,
}

/// Raw saturation values passed to the Lua script, in its argv order
/// (src_fast, src_slow, issue, bad, mal, rep, action, switch, global,
/// trust, principal). The defaults mirror the PHP implementation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Saturations {
    pub src_fast: u32,
    pub src_slow: u32,
    pub issue: u32,
    pub bad: u32,
    pub mal: u32,
    pub rep: u32,
    pub action: u32,
    pub switch: u32,
    pub global: u32,
    pub trust: u32,
    pub principal: u32,
}

impl Default for Saturations {
    fn default() -> Saturations {
        Saturations {
            src_fast: 8000,
            src_slow: 100000,
            issue: 6000,
            bad: 4000,
            mal: 3000,
            rep: 2000,
            action: 6000,
            switch: 10000,
            global: 70000,
            trust: 10000,
            principal: 10000,
        }
    }
}

impl Saturations {
    /// The saturations in the Lua argv order (indices 8..18).
    pub fn to_arg_order(&self) -> [u32; 11] {
        [
            self.src_fast,
            self.src_slow,
            self.issue,
            self.bad,
            self.mal,
            self.rep,
            self.action,
            self.switch,
            self.global,
            self.trust,
            self.principal,
        ]
    }
}

/// In-process emergency guard: a fixed-window cap of `process_per_second`
/// observations per second per process (default 10000), enforced before any
/// state backend is touched.
///
/// This is deliberately a per-process cap (a `VecDeque` of timestamps in
/// this process's memory); no cross-process synchronization is performed.
/// It is the last line of defense when the Redis/state controls fail — it
/// bounds how much work one process can push at a degraded backend so a
/// burst cannot saturate this process's Redis connection. Per-source (and
/// per-identity) throttling belongs to the distributed keyed layer: the
/// Redis source velocity channels (`source_fast`/`source_slow` in risk-v1)
/// and the policy's per-source overrides. When the window is saturated the
/// engine denies immediately (HardRateLimit) instead of spending time/state
/// on the request.
///
/// Warm-up ramp: after every restart/autoscale the process
/// must not start with a full burst — the effective cap ramps linearly
/// from a floor of `max(1, process_per_second / 10)` to the full cap over
/// the first `warmup_ramp_secs` seconds of the process's life:
///
/// ```text
/// effective_cap = process_per_second × min(1, elapsed / ramp), floored
///                 at max(1, process_per_second / 10)
/// ```
///
/// `elapsed` is measured from `start` on the monotonic `Instant` clock, so
/// the ramp is immune to wall-clock jumps. `warmup_ramp_secs = 0` disables
/// the ramp (full cap from the first call — the pre-ramp behavior). The
/// ramp only lowers the admission rate during startup; the distributed
/// keyed limits remain authoritative — it never raises any limit beyond
/// the configured `process_per_second`.
pub struct ProcessEmergencyCap {
    process_per_second: u64,
    warmup_ramp_secs: f64,
    stamps: Mutex<VecDeque<f64>>,
    start: Instant,
}

impl Default for ProcessEmergencyCap {
    fn default() -> ProcessEmergencyCap {
        ProcessEmergencyCap::new()
    }
}

impl ProcessEmergencyCap {
    pub const DEFAULT_PROCESS_PER_SECOND: u64 = 10_000;
    /// Default warm-up ramp length in seconds.
    pub const DEFAULT_WARMUP_RAMP_SECS: f64 = 10.0;

    /// Builds a cap with the default rate (10000 admissions per second,
    /// per process) and the default warm-up ramp (10 s).
    pub fn new() -> ProcessEmergencyCap {
        ProcessEmergencyCap::with_capacity(Self::DEFAULT_PROCESS_PER_SECOND)
    }

    /// Builds a cap with an explicit admissions-per-second rate and the
    /// default 10 s warm-up ramp.
    ///
    /// # Panics
    ///
    /// Panics if `process_per_second < 1`.
    pub fn with_capacity(process_per_second: u64) -> ProcessEmergencyCap {
        Self::with_capacity_and_ramp(process_per_second, Self::DEFAULT_WARMUP_RAMP_SECS)
    }

    /// Builds a cap with an explicit admissions-per-second rate and an
    /// explicit warm-up ramp (`warmup_ramp_secs = 0.0` disables the ramp).
    ///
    /// # Panics
    ///
    /// Panics if `process_per_second < 1` or `warmup_ramp_secs < 0.0`.
    pub fn with_capacity_and_ramp(
        process_per_second: u64,
        warmup_ramp_secs: f64,
    ) -> ProcessEmergencyCap {
        assert!(process_per_second >= 1, "process_per_second must be >= 1");
        assert!(
            warmup_ramp_secs >= 0.0,
            "warmup_ramp_secs must be >= 0 (0 disables the ramp)"
        );
        ProcessEmergencyCap {
            process_per_second,
            warmup_ramp_secs,
            stamps: Mutex::new(VecDeque::new()),
            start: Instant::now(),
        }
    }

    /// The admissions-per-second cap.
    pub fn process_per_second(&self) -> u64 {
        self.process_per_second
    }

    /// The warm-up ramp length in seconds (0.0 = ramp disabled).
    pub fn warmup_ramp_secs(&self) -> f64 {
        self.warmup_ramp_secs
    }

    /// The cap in force at the given elapsed seconds: the full
    /// `process_per_second` after the warm-up ramp, and during the ramp a
    /// linear interpolation from the floor of `max(1, cap / 10)`. Monotonic
    /// in elapsed, so the queue can never hold more than the full cap (the
    /// O(1) amortized front-prune is preserved).
    fn effective_cap(&self, elapsed_secs: f64) -> u64 {
        if self.warmup_ramp_secs <= 0.0 || elapsed_secs >= self.warmup_ramp_secs {
            return self.process_per_second;
        }
        let floor = (self.process_per_second / 10).max(1);
        let ramped =
            (self.process_per_second as f64 * elapsed_secs / self.warmup_ramp_secs).floor();
        (ramped as u64).max(floor)
    }

    /// True when the process may proceed within the current window. Also
    /// marks the current moment as consumed. Expired entries are dequeued
    /// from the front, in amortized O(1) per admission.
    pub fn allow(&self) -> bool {
        let now = self.start.elapsed().as_secs_f64();
        let cutoff = now - 1.0;
        let mut stamps = self.stamps.lock().unwrap_or_else(|p| p.into_inner());
        while stamps.front().is_some_and(|t| *t <= cutoff) {
            stamps.pop_front();
        }
        if stamps.len() as u64 >= self.effective_cap(now) {
            return false;
        }
        stamps.push_back(now);
        true
    }

    /// True when the window is currently saturated.
    pub fn is_open(&self) -> bool {
        let now = self.start.elapsed().as_secs_f64();
        let cutoff = now - 1.0;
        let mut stamps = self.stamps.lock().unwrap_or_else(|p| p.into_inner());
        while stamps.front().is_some_and(|t| *t <= cutoff) {
            stamps.pop_front();
        }
        stamps.len() as u64 >= self.effective_cap(now)
    }
}

/// The adaptive risk engine.
///
/// `classifier` and `keys` are retained as owned configuration (the
/// classifier is passed by the caller for its observation pipeline; the
/// keys feed the identity factory) — the engine itself uses the derived
/// [`RiskIdentityFactory`].
///
/// The store bounds include the optional risk-v2 capability traits
/// [`SessionContextTagStore`] + [`SessionTlsTagStore`]: their default
/// methods report no record surface, `Ok(None)`, so a v1 store without
/// the capabilities still satisfies the bounds and the engine degrades the
/// session-first-tag signals to neutral (consistent) — exactly the
/// backend-miss semantics.
///
/// Opt-in for third-party stores: a store implementing only
/// [`RiskStateStore`] must add the two empty capability impls
/// (`impl SessionContextTagStore for MyStore {}` and
/// `impl SessionTlsTagStore for MyStore {}`) to opt in — the default
/// methods then provide the neutral v2 behavior. The built-in Redis store
/// implements the real record surfaces.
pub struct RiskEngine<
    S: RiskStateStore + SessionContextTagStore + SessionTlsTagStore,
    N: NetworkClassifier,
> {
    store: S,
    #[allow(dead_code)]
    classifier: N,
    policy: Arc<RiskPolicy>,
    #[allow(dead_code)]
    keys: RiskKeys,
    identity: RiskIdentityFactory,
    breaker: breaker::CircuitBreaker,
    pub source_epoch_secs: u64,
    pub subnet_epoch_secs: u64,
    pub session_ttl_secs: u64,
    pub principal_ttl_secs: u64,
    pub dedupe_ttl_secs: u64,
    pub saturations: Saturations,
    limiter: ProcessEmergencyCap,
    calibration: Option<Arc<dyn CalibrationStore>>,
    metrics: Metrics,
    current_global_level: AtomicU8,
    enable_global_pressure: bool,
    hysteresis: crate::hysteresis::ScopeActionHysteresis,
}

impl<S: RiskStateStore + SessionContextTagStore + SessionTlsTagStore, N: NetworkClassifier>
    RiskEngine<S, N>
{
    /// Builds an engine with the contract defaults (900 s epochs, 1800 s
    /// session TTL, 86400 s principal TTL, 60 s dedupe TTL, default
    /// saturations, 2-failure/1000 ms breaker, 10000 req/s process cap).
    /// No calibration store (optional via [`RiskEngine::with_calibration`]).
    /// Global pressure is enabled (see [`RiskEngine::with_global_pressure`]).
    pub fn new(
        store: S,
        classifier: N,
        policy: Arc<RiskPolicy>,
        keys: RiskKeys,
    ) -> RiskEngine<S, N> {
        RiskEngine {
            store,
            classifier,
            policy,
            identity: RiskIdentityFactory::new(keys.clone()),
            keys,
            breaker: breaker::CircuitBreaker::default(),
            source_epoch_secs: 900,
            subnet_epoch_secs: 900,
            session_ttl_secs: 1800,
            principal_ttl_secs: 86400,
            dedupe_ttl_secs: 60,
            saturations: Saturations::default(),
            limiter: ProcessEmergencyCap::default(),
            calibration: None,
            metrics: Metrics::new(),
            current_global_level: AtomicU8::new(0),
            enable_global_pressure: true,
            hysteresis: crate::hysteresis::ScopeActionHysteresis::new(),
        }
    }

    /// Builds an engine with explicit breaker and process cap (tests).
    pub fn with_components(
        store: S,
        classifier: N,
        policy: Arc<RiskPolicy>,
        keys: RiskKeys,
        breaker: breaker::CircuitBreaker,
        limiter: ProcessEmergencyCap,
    ) -> RiskEngine<S, N> {
        let mut engine = RiskEngine::new(store, classifier, policy, keys);
        engine.breaker = breaker;
        engine.limiter = limiter;
        engine
    }

    /// Toggles the global-pressure signal, level and cooldown (default:
    /// enabled). When disabled, `assess_pre_issue()` zeroes
    /// `global_pressure` on the
    /// returned vector and reports level 0 / no cooldown to the policy —
    /// the global-pressure channel and its floors/cooldown are entirely
    /// inert, while per-source signals keep working.
    pub fn with_global_pressure(mut self, enable: bool) -> RiskEngine<S, N> {
        self.enable_global_pressure = enable;
        self
    }

    /// Attaches an outcome-feedback calibration store: every decision
    /// registers atomically (receipt + sampled denominator + outcome
    /// ledger — the ledger is always on, so confirmed outcomes work
    /// identically without calibration), the scope bias is applied to the
    /// score, and confirmed outcomes consume their receipts. All failures
    /// are silent.
    pub fn with_calibration(mut self, calibration: Arc<dyn CalibrationStore>) -> RiskEngine<S, N> {
        self.calibration = Some(calibration);
        self
    }

    /// Policy version of the loaded snapshot.
    pub fn policy_version(&self) -> u32 {
        self.policy.version
    }

    /// Last observed global pressure level (0..4), for metrics.
    pub fn current_global_level(&self) -> u8 {
        self.current_global_level.load(Ordering::Relaxed)
    }

    /// Metrics snapshot.
    pub fn metrics(&self) -> &Metrics {
        &self.metrics
    }

    /// Assesses ONE PreIssue request and returns a [`RiskDecision`].
    ///
    /// The emergency cap is checked first (the single per-process window);
    /// on a cap hit the engine returns a HardRateLimit decision without
    /// touching the store. `idempotency_key` becomes the event_id (dedupe
    /// key) via [`normalize_idempotency_key`]; `None` draws a random 16-byte
    /// hex id. Every decision gets a fresh `decision_id` and registers its
    /// always-on outcome ledger (with calibration attached, the calibration
    /// receipt + sampled denominator atomically with it).
    ///
    /// # Errors
    ///
    /// [`RiskError::InvalidIdempotencyKey`] when the caller key exceeds the
    /// 4096-byte contract limit.
    pub fn assess_pre_issue(
        &self,
        ctx: RiskContext<'_>,
        idempotency_key: Option<String>,
    ) -> Result<RiskDecision, RiskError> {
        self.assess_pre_issue_impl(ctx, None, idempotency_key, None)
    }

    /// Risk-v2 variant of [`RiskEngine::assess_pre_issue`]: the identical
    /// pipeline plus the additive risk-v2 evidence factors
    /// (honeypot/decoy evidence, session client-context consistency,
    /// trusted-edge TLS consistency) from `v2`. The risk-v1 contract
    /// semantics are unchanged — with an empty `v2` context the decision is
    /// byte-identical to the v1 path. `v2_weights` is the operator-tunable
    /// weights override for the additive risk-v2 factors; `None` uses the
    /// default weights (identical scores to today).
    ///
    /// # Errors
    ///
    /// [`RiskError::InvalidIdempotencyKey`] when the caller key exceeds the
    /// 4096-byte contract limit.
    pub fn assess_pre_issue_v2(
        &self,
        ctx: RiskContext<'_>,
        v2: &RiskV2Context,
        idempotency_key: Option<String>,
        v2_weights: Option<RiskV2Weights>,
    ) -> Result<RiskDecision, RiskError> {
        self.assess_pre_issue_impl(ctx, Some(v2), idempotency_key, v2_weights)
    }

    fn assess_pre_issue_impl(
        &self,
        ctx: RiskContext<'_>,
        v2: Option<&RiskV2Context>,
        idempotency_key: Option<String>,
        v2_weights: Option<RiskV2Weights>,
    ) -> Result<RiskDecision, RiskError> {
        if !self.limiter.allow() {
            self.metrics.incr("denied:limiter");
            let decision = RiskDecision {
                score: 1000,
                action: RiskAction::Deny,
                reasons: [Some(RiskReason::HardRateLimit), None, None, None],
                policy_version: self.policy.version,
                model_revision: RISK_MODEL_REVISION,
                global_level: self.current_global_level(),
                retry_after_ms: Some(1000),
                band: 10,
                decision_id: String::new(),
            };
            self.record_decision_metrics(ctx.scope, &decision);
            return Ok(self.finalize_decision(ctx.scope, decision, None, false));
        }
        self.assess_inner(ctx, v2, idempotency_key, v2_weights)
    }

    /// Deprecated alias of [`RiskEngine::assess_pre_issue`].
    #[deprecated(
        note = "renamed to assess_pre_issue (the emergency caps apply only there); use reassess for limiter-free assessments"
    )]
    pub fn assess(
        &self,
        ctx: RiskContext<'_>,
        idempotency_key: Option<String>,
    ) -> Result<RiskDecision, RiskError> {
        self.assess_pre_issue(ctx, idempotency_key)
    }

    /// Re-assesses a request without any emergency-cap check: identical
    /// pipeline to [`RiskEngine::assess_pre_issue`] (observation, breaker,
    /// store, scorer with calibration bias, policy, receipt) minus the
    /// limiter gate — used for follow-up assessments of an already-admitted
    /// flow, where the cap must not apply.
    ///
    /// # Errors
    ///
    /// [`RiskError::InvalidIdempotencyKey`] when the caller key exceeds the
    /// 4096-byte contract limit.
    pub fn reassess(
        &self,
        ctx: RiskContext<'_>,
        idempotency_key: Option<String>,
    ) -> Result<RiskDecision, RiskError> {
        self.assess_inner(ctx, None, idempotency_key, None)
    }

    /// Risk-v2 variant of [`RiskEngine::reassess`]: the identical pipeline
    /// plus the additive risk-v2 evidence factors from `v2` (honeypot
    /// evidence, session client-context consistency, trusted-edge TLS
    /// consistency). `v2_weights` is the operator-tunable weights override
    /// for the additive risk-v2 factors; `None` uses the default weights
    /// (identical scores to today).
    ///
    /// # Errors
    ///
    /// [`RiskError::InvalidIdempotencyKey`] when the caller key exceeds the
    /// 4096-byte contract limit.
    pub fn reassess_v2(
        &self,
        ctx: RiskContext<'_>,
        v2: &RiskV2Context,
        idempotency_key: Option<String>,
        v2_weights: Option<RiskV2Weights>,
    ) -> Result<RiskDecision, RiskError> {
        self.assess_inner(ctx, Some(v2), idempotency_key, v2_weights)
    }

    /// The shared assessment pipeline (no limiter); only
    /// [`RiskEngine::assess_pre_issue`] gates on the emergency caps.
    fn assess_inner(
        &self,
        ctx: RiskContext<'_>,
        v2: Option<&RiskV2Context>,
        idempotency_key: Option<String>,
        v2_weights: Option<RiskV2Weights>,
    ) -> Result<RiskDecision, RiskError> {
        let now_ms = now_ms();
        let observation = self.build_observation(&ctx, now_ms, idempotency_key)?;

        if self.breaker.is_open() {
            self.metrics.incr("degraded:breaker");
            let decision = self
                .policy
                .degraded_decision(ctx.scope, self.current_global_level());
            self.record_decision_metrics(ctx.scope, &decision);
            return Ok(self.finalize_decision(ctx.scope, decision, None, false));
        }

        // The pending outcome-ledger registration to fold into the
        // consolidated assessment. Only the calibration-less path
        // consolidates: with calibration attached, the calibrator's
        // register_decision.lua books the receipt + sample denominator +
        // ledger atomically, so the engine keeps that as the sole
        // authority. The decision_id is generated here so the ledger and
        // the returned decision carry the same id.
        let decision_id = if self.calibration.is_none() {
            Some(hex::encode(fresh_decision_id()))
        } else {
            None
        };
        let effective_v2_weights = v2_weights.unwrap_or_default();
        let registration = decision_id.as_ref().map(|id| OutcomeRegistration {
            decision_id: id.clone(),
            decision_hour: (now_ms / 3_600_000) as i64,
            base_risk: self.policy.base_risk(ctx.scope),
            global_pressure_enabled: self.enable_global_pressure,
            honeypot_hit: v2.map(|v2ctx| v2ctx.honeypot_hit).unwrap_or(false),
            v1_weights: self.policy.weights,
            v2_weights: effective_v2_weights,
        });

        let start = Instant::now();
        let consolidated = self.store.assess_v2(
            &observation,
            presented_context_tag(v2, observation.session_id),
            presented_tls_tag(v2, observation.session_id),
            registration.as_ref(),
        );
        let outcome = match consolidated {
            Err(_) => {
                self.breaker.record_failure();
                self.metrics.incr("degraded:store");
                let decision = self
                    .policy
                    .degraded_decision(ctx.scope, self.current_global_level());
                self.record_decision_metrics(ctx.scope, &decision);
                return Ok(self.finalize_decision(ctx.scope, decision, None, false));
            }
            Ok(Some(reply)) => {
                self.metrics
                    .add_latency_us("store:observe", start.elapsed().as_micros() as u64);
                self.breaker.record_success();
                let v2_signals = v2.map(|v2ctx| {
                    self.derive_v2_signals_from_records(
                        v2ctx,
                        reply.existing_context_tag.as_deref(),
                        reply.existing_tls_tag.as_deref(),
                        ctx.event,
                    )
                });
                (reply.observed, v2_signals, registration.is_some())
            }
            Ok(None) => {
                // Store without the consolidated capability: the plain
                // observe plus the individual session-first-tag record
                // reads (identical semantics).
                let observed = match self.store.observe(&observation) {
                    Ok(o) => o,
                    Err(_) => {
                        self.breaker.record_failure();
                        self.metrics.incr("degraded:store");
                        let decision = self
                            .policy
                            .degraded_decision(ctx.scope, self.current_global_level());
                        self.record_decision_metrics(ctx.scope, &decision);
                        return Ok(self.finalize_decision(ctx.scope, decision, None, false));
                    }
                };
                self.metrics
                    .add_latency_us("store:observe", start.elapsed().as_micros() as u64);
                self.breaker.record_success();
                let v2_signals = v2
                    .map(|v2ctx| self.derive_v2_signals(v2ctx, observation.session_id, ctx.event));
                (observed, v2_signals, false)
            }
        };

        let (observed, v2_signals, outcome_registered) = outcome;
        // When global pressure is disabled, the signal, the level
        // and the cooldown are ALL zeroed before any policy or
        // cooldown-deny check: the global channel is inert (the
        // per-source signals keep flowing).
        let mut vector = observed.vector;
        let global_level;
        let cooldown_until_ms;
        if self.enable_global_pressure {
            global_level = observed.global_level;
            cooldown_until_ms = observed.cooldown_until_ms;
        } else {
            vector.global_pressure = 0;
            global_level = 0;
            cooldown_until_ms = 0;
        }
        self.current_global_level
            .store(global_level, Ordering::Relaxed);
        let mut base = self.policy.base_risk(ctx.scope);
        if let Some(calibration) = &self.calibration {
            // Bounded automatic calibration: clamp(base + bias,
            // 0, 1000) before band mapping (same sign, same clamp
            // as PHP).
            let bias = calibration.bias_for_scope(ctx.scope, now_ms as i64);
            base = (base as i32 + bias).clamp(0, 1000) as u16;
        }
        let score = match &v2_signals {
            Some(signals) => crate::score::score_v2(
                base,
                &vector,
                &self.policy.weights,
                signals,
                &effective_v2_weights,
            ),
            None => compute_score(base, &vector, &self.policy.weights),
        };
        let mut decision = self.policy.decide_with_hysteresis(
            ctx.scope,
            score,
            &vector,
            &ctx.resources,
            global_level,
            now_ms,
            cooldown_until_ms,
            Some(&self.hysteresis),
        );
        self.merge_contributor_reasons(&mut decision, &vector);
        self.record_decision_metrics(ctx.scope, &decision);
        Ok(self.finalize_decision(ctx.scope, decision, decision_id, outcome_registered))
    }

    /// Derives the bounded risk-v2 signal vector from the v2 context:
    ///
    /// - `honeypot` = 1000 when the context reports a honeypot hit OR the
    ///   current observation is one of the honeypot event kinds (ANY of the
    ///   three derives the signal — probabilistic evidence, never a gate);
    /// - `session_inconsistency` = 1000 when the session's first-seen
    ///   client-context tag differs from the current tag; 0 when the tag is
    ///   absent (first request), the session is absent, the record read
    ///   fails (neutral degradation), or the store lacks the optional
    ///   [`SessionContextTagStore`] capability — the default `Ok(None)`
    ///   degrades exactly like a backend miss;
    /// - `tls_inconsistency` = 1000 when the session's first-seen
    ///   trusted-edge TLS classification tag differs from the current tag;
    ///   0 when the tag is absent (first request), the session is absent,
    ///   the tag exceeds the 64-char bound (treated as absent), the record
    ///   read fails (neutral degradation), or the store lacks the optional
    ///   [`SessionTlsTagStore`] capability.
    fn derive_v2_signals(
        &self,
        v2: &RiskV2Context,
        session_id: Option<[u8; 16]>,
        event: RiskEventKind,
    ) -> crate::signals::RiskV2Signals {
        let honeypot = if v2.honeypot_hit || event.is_honeypot() {
            1000
        } else {
            0
        };
        let session_inconsistency = match (session_id, v2.client_context_tag.as_deref()) {
            (Some(session), Some(tag)) if !tag.is_empty() => {
                match self.store.session_first_context_tag(&session, tag) {
                    Ok(Some(first)) if first != tag => 1000,
                    _ => 0,
                }
            }
            _ => 0,
        };
        let tls_inconsistency = match (session_id, v2.tls_tag.as_deref()) {
            (Some(session), Some(tag)) if !tag.is_empty() && tag.len() <= 64 => {
                match self.store.session_first_tls_tag(&session, tag) {
                    Ok(Some(first)) if first != tag => 1000,
                    _ => 0,
                }
            }
            _ => 0,
        };
        crate::signals::RiskV2Signals {
            honeypot,
            session_inconsistency,
            tls_inconsistency,
        }
    }

    /// Derives the bounded risk-v2 signal vector from the tags recorded by
    /// the consolidated assessment call (the store has already applied the
    /// first-seen records atomically with the observation).
    ///
    /// - `honeypot` = 1000 when the context reports a honeypot hit OR the
    ///   current observation is one of the honeypot event kinds;
    /// - `session_inconsistency` = 1000 when the session's recorded
    ///   first-seen client-context tag differs from the current tag; 0
    ///   when no record exists (first request), the tag is absent, or the
    ///   record read failed (neutral degradation);
    /// - `tls_inconsistency` = 1000 when the session's recorded first-seen
    ///   trusted-edge TLS classification tag differs from the current tag;
    ///   0 when no record exists (first request), the tag is absent, or
    ///   the record read failed (neutral degradation).
    ///
    /// The tags returned by the consolidated call are non-`None` exactly
    /// when a tag was presented, so `existing_* == None` implies the
    /// current tag is absent — identical to the individual-record path.
    fn derive_v2_signals_from_records(
        &self,
        v2: &RiskV2Context,
        existing_context_tag: Option<&str>,
        existing_tls_tag: Option<&str>,
        event: RiskEventKind,
    ) -> crate::signals::RiskV2Signals {
        let honeypot = if v2.honeypot_hit || event.is_honeypot() {
            1000
        } else {
            0
        };
        let session_inconsistency = match (existing_context_tag, v2.client_context_tag.as_deref()) {
            (Some(first), Some(tag)) if !first.is_empty() && first != tag => 1000,
            _ => 0,
        };
        let tls_inconsistency = match (existing_tls_tag, v2.tls_tag.as_deref()) {
            (Some(first), Some(tag)) if !first.is_empty() && first != tag => 1000,
            _ => 0,
        };
        crate::signals::RiskV2Signals {
            honeypot,
            session_inconsistency,
            tls_inconsistency,
        }
    }

    /// Outcome feedback path (e.g. a post-solve protected action): stores
    /// the event and returns an [`EventReceipt`]. Never runs the limiter
    /// and never calls [`RiskEngine::assess_pre_issue`].
    ///
    /// Confirmation events (ConfirmedLegitimate/ConfirmedAbuse) are
    /// rejected with [`RiskError::ConfirmationApiRequired`]: they carry an
    /// outcome for an assessed decision and must go through
    /// [`RiskEngine::confirmed_legitimate`] / [`RiskEngine::confirmed_abuse`]
    /// (the wrappers require the decision_id the always-on outcome ledger
    /// needs and confirm it before booking the reputation event).
    ///
    /// # Errors
    ///
    /// [`RiskError::InvalidIdempotencyKey`] when the caller key exceeds the
    /// 4096-byte contract limit; [`RiskError::ConfirmationApiRequired`] for
    /// ConfirmedLegitimate/ConfirmedAbuse events.
    pub fn record_feedback(
        &self,
        event: RiskEventKind,
        ctx: RiskContext<'_>,
        idempotency_key: Option<String>,
        decision_id: Option<String>,
    ) -> Result<EventReceipt, RiskError> {
        if matches!(
            event,
            RiskEventKind::ConfirmedLegitimate | RiskEventKind::ConfirmedAbuse
        ) {
            return Err(RiskError::ConfirmationApiRequired);
        }
        self.emit_feedback(event, ctx, idempotency_key, decision_id, None)
    }

    /// The shared feedback pipeline; `weight` is the calibrator's inverse
    /// sampling probability (only the confirmed* wrappers pass it — they
    /// bypass the [`RiskError::ConfirmationApiRequired`] guard of
    /// [`RiskEngine::record_feedback`]).
    fn emit_feedback(
        &self,
        event: RiskEventKind,
        ctx: RiskContext<'_>,
        idempotency_key: Option<String>,
        decision_id: Option<String>,
        weight: Option<f64>,
    ) -> Result<EventReceipt, RiskError> {
        let now_ms = now_ms();
        let observation = self.build_observation(&ctx, now_ms, idempotency_key)?;

        let confirmed = matches!(
            event,
            RiskEventKind::ConfirmedLegitimate | RiskEventKind::ConfirmedAbuse
        );
        if confirmed {
            if let Some(receipt_id) = decision_id.filter(|d| !d.is_empty()) {
                let legitimate = event == RiskEventKind::ConfirmedLegitimate;
                // First the atomic ledger confirmation (calibrator when
                // attached — its confirm.lua flips the always-on ledger —
                // else the calibration-independent store script).
                // Reputation gating: the reputation event is booked only on
                // the first confirmation (status 1 or 2); status 0
                // (missing/already consumed) and backend errors book
                // nothing — the receipt/ledger survives an error, so a
                // retry applies the outcome exactly once instead of
                // amplifying it.
                match self.confirm_outcome(&receipt_id, legitimate, weight) {
                    Ok(0) | Err(_) => {
                        return Ok(EventReceipt {
                            event_id: observation.event_id,
                            is_duplicate: true,
                            signals: SignalVector::zero(),
                        });
                    }
                    Ok(_) => {}
                }
            }
        }

        let observed = self
            .store
            .observe(&observation)
            .unwrap_or_else(|_| Observed {
                vector: SignalVector::zero(),
                global_level: 0,
                cooldown_until_ms: 0,
                is_duplicate: false,
            });

        Ok(EventReceipt {
            event_id: observation.event_id,
            is_duplicate: observed.is_duplicate,
            signals: observed.vector,
        })
    }

    /// Confirms the outcome of an assessed decision: ONE atomic
    /// ledger operation that flips the decision's pending entry exactly
    /// once. With calibration attached the calibrator's confirm script also
    /// consumes the receipt and records the exact score into the decision-
    /// time bucket (or discards an unsampled receipt); without calibration
    /// the calibration-independent store script flips the always-on ledger
    /// alone — ConfirmedLegitimate/ConfirmedAbuse work identically in both
    /// configurations.
    ///
    /// Returns the shared accepted-outcome status (wire contract with PHP):
    /// `0` nothing consumed (missing / already confirmed / corrupt /
    /// unsampled-discard), `1` first confirmation with calibration
    /// recorded, `2` first confirmation, deliberately unsampled. Only
    /// statuses 1 and 2 authorize the first-party reputation event (see
    /// [`RiskEngine::record_feedback`]); the reputation event itself is
    /// booked separately. `weight` is the inverse sampling probability for
    /// weighted sampling (default 1.0).
    ///
    /// # Errors
    ///
    /// [`RiskError::EmptyDecisionId`] when `decision_id` is empty;
    /// [`RiskError::Calibration`] when the calibration backend fails;
    /// [`RiskError::Store`] when the state backend fails (no calibration).
    pub fn confirm_outcome(
        &self,
        decision_id: &str,
        legitimate: bool,
        weight: Option<f64>,
    ) -> Result<u8, RiskError> {
        if decision_id.is_empty() {
            return Err(RiskError::EmptyDecisionId);
        }
        match &self.calibration {
            Some(calibration) => calibration
                .confirm_outcome(decision_id, legitimate, weight)
                .map_err(|e| RiskError::Calibration(e.to_string())),
            None => self
                .store
                .confirm_outcome(decision_id, legitimate)
                .map_err(|e| RiskError::Store(e.to_string())),
        }
    }

    /// Compensating-state correction: flips a decision's always-on outcome
    /// ledger entry L <-> A — the corrected outcome is authoritative for
    /// future events while the prior ephemeral reputation pressure decays
    /// naturally (no synthetic identities are involved; the ledger itself
    /// is the once-only authority). With calibration attached the
    /// calibrator's correction script also reverses the original bucket
    /// contribution (exact recorded weight, clamped at zero) and adds the
    /// corrected one; without calibration the calibration-independent
    /// store script flips the ledger alone.
    ///
    /// `legitimate` is the corrected outcome (a first confirmation of
    /// `legitimate = true` is corrected with `legitimate = false` and vice
    /// versa).
    ///
    /// Returns `Ok(true)` when the ledger was flipped, `Ok(false)` when
    /// the decision is unknown or already carries the target outcome.
    ///
    /// # Errors
    ///
    /// [`RiskError::EmptyDecisionId`] when `decision_id` is empty;
    /// [`RiskError::Calibration`] when the calibration backend fails;
    /// [`RiskError::Store`] when the state backend fails (no calibration).
    pub fn confirm_correction(
        &self,
        decision_id: &str,
        legitimate: bool,
        weight: Option<f64>,
    ) -> Result<bool, RiskError> {
        if decision_id.is_empty() {
            return Err(RiskError::EmptyDecisionId);
        }
        match &self.calibration {
            Some(calibration) => calibration
                .correct_outcome(decision_id, legitimate, weight)
                .map_err(|e| RiskError::Calibration(e.to_string())),
            None => self
                .store
                .correct_outcome(decision_id, legitimate)
                .map_err(|e| RiskError::Store(e.to_string())),
        }
    }

    /// Deprecated alias of [`RiskEngine::record_feedback`].
    #[deprecated(note = "use record_feedback")]
    pub fn record(
        &self,
        event: RiskEventKind,
        ctx: RiskContext<'_>,
        idempotency_key: Option<String>,
        decision_id: Option<String>,
    ) -> Result<EventReceipt, RiskError> {
        self.record_feedback(event, ctx, idempotency_key, decision_id)
    }

    /// Records a confirmed-legitimate outcome. `decision_id` is the id of
    /// the assessed decision (required — the always-on outcome ledger is
    /// confirmed under it; with calibration the receipt is consumed too).
    /// `sampling_probability_ppm` is the server-side sampling probability
    /// in parts per million: weighted sampling derives the confirmation
    /// weight as `1_000_000 / ppm` so the calibration population stays
    /// unbiased; `None` uses weight 1.0.
    ///
    /// # Errors
    ///
    /// [`RiskError::EmptyDecisionId`] when `decision_id` is empty;
    /// [`RiskError::InvalidIdempotencyKey`] when the caller key exceeds the
    /// 4096-byte contract limit.
    pub fn confirmed_legitimate(
        &self,
        ctx: RiskContext<'_>,
        idempotency_key: Option<String>,
        decision_id: &str,
        sampling_probability_ppm: Option<u32>,
    ) -> Result<EventReceipt, RiskError> {
        if decision_id.is_empty() {
            return Err(RiskError::EmptyDecisionId);
        }
        let weight = sampling_probability_ppm.map(|ppm| 1_000_000.0 / ppm as f64);
        self.emit_feedback(
            RiskEventKind::ConfirmedLegitimate,
            ctx,
            idempotency_key,
            Some(decision_id.to_string()),
            weight,
        )
    }

    /// Records a confirmed-abuse outcome. `decision_id` is the id of the
    /// assessed decision (required — the always-on outcome ledger is
    /// confirmed under it; with calibration the receipt is consumed too).
    /// `sampling_probability_ppm` is the server-side sampling probability
    /// in parts per million: weighted sampling derives the confirmation
    /// weight as `1_000_000 / ppm` so the calibration population stays
    /// unbiased; `None` uses weight 1.0.
    ///
    /// # Errors
    ///
    /// [`RiskError::EmptyDecisionId`] when `decision_id` is empty;
    /// [`RiskError::InvalidIdempotencyKey`] when the caller key exceeds the
    /// 4096-byte contract limit.
    pub fn confirmed_abuse(
        &self,
        ctx: RiskContext<'_>,
        idempotency_key: Option<String>,
        decision_id: &str,
        sampling_probability_ppm: Option<u32>,
    ) -> Result<EventReceipt, RiskError> {
        if decision_id.is_empty() {
            return Err(RiskError::EmptyDecisionId);
        }
        let weight = sampling_probability_ppm.map(|ppm| 1_000_000.0 / ppm as f64);
        self.emit_feedback(
            RiskEventKind::ConfirmedAbuse,
            ctx,
            idempotency_key,
            Some(decision_id.to_string()),
            weight,
        )
    }

    /// Records a per-source rate-limit hit (event 15): `bad + 3000` on the
    /// source/session reputation only — the caller observed its OWN limit
    /// being enforced. The context's `event` field must be
    /// `SourceRateLimitHit`.
    ///
    /// # Errors
    ///
    /// [`RiskError::InvalidIdempotencyKey`] when the caller key exceeds the
    /// 4096-byte contract limit.
    pub fn source_rate_limit_hit(
        &self,
        ctx: RiskContext<'_>,
        idempotency_key: Option<String>,
    ) -> Result<EventReceipt, RiskError> {
        self.record_feedback(
            RiskEventKind::SourceRateLimitHit,
            ctx,
            idempotency_key,
            None,
        )
    }

    /// Records a deployment-capacity hit (event 16): raises only the
    /// global pressure (never the visitor's source/session/principal
    /// reputation) so an overloaded deployment is not blamed on individual
    /// traffic. The context's `event` field must be `GlobalCapacityHit`.
    ///
    /// # Errors
    ///
    /// [`RiskError::InvalidIdempotencyKey`] when the caller key exceeds the
    /// 4096-byte contract limit.
    pub fn global_capacity_hit(
        &self,
        ctx: RiskContext<'_>,
        idempotency_key: Option<String>,
    ) -> Result<EventReceipt, RiskError> {
        self.record_feedback(RiskEventKind::GlobalCapacityHit, ctx, idempotency_key, None)
    }

    /// Records a risk-denied outcome (event 17): a no-op in the state
    /// script — a decision that already denied must not be double-counted,
    /// this only books the idempotency receipt. The context's `event` field
    /// must be `RiskDenied`.
    ///
    /// # Errors
    ///
    /// [`RiskError::InvalidIdempotencyKey`] when the caller key exceeds the
    /// 4096-byte contract limit.
    pub fn risk_denied(
        &self,
        ctx: RiskContext<'_>,
        idempotency_key: Option<String>,
    ) -> Result<EventReceipt, RiskError> {
        self.record_feedback(RiskEventKind::RiskDenied, ctx, idempotency_key, None)
    }

    fn build_observation(
        &self,
        ctx: &RiskContext<'_>,
        now_ms: u64,
        idempotency_key: Option<String>,
    ) -> Result<RiskObservation, RiskError> {
        let now_secs = (now_ms / 1000) as i64;
        let src_epoch = now_secs / self.source_epoch_secs as i64;
        let net_epoch = now_secs / self.subnet_epoch_secs as i64;
        let session_id = ctx.session_id.map(|s| self.identity.session_id(s));
        let principal_id = ctx.principal_id.map(|p| self.identity.principal_id(p));
        // Canonical idempotency normalization shared with PHP: verbatim keys
        // become the lowercase hex of the hmac-sha256 MAC over event_key,
        // pack('N', scope), chr(event) and key — domain-separated per scope
        // and event kind; empty/None draw a random 16-byte id, and keys
        // over 4096 bytes are rejected.
        let event_id = normalize_idempotency_key(
            idempotency_key.as_deref(),
            ctx.scope,
            ctx.event,
            &self.keys.event,
        )?;

        Ok(RiskObservation {
            event: ctx.event,
            scope: ctx.scope,
            source_epoch: src_epoch,
            source_id_prev: self
                .identity
                .source_id_for_epoch(ctx.source_ip, src_epoch - 1),
            source_id: self.identity.source_id_for_epoch(ctx.source_ip, src_epoch),
            source_id_next: self
                .identity
                .source_id_for_epoch(ctx.source_ip, src_epoch + 1),
            subnet_epoch: net_epoch,
            subnet_id_prev: self
                .identity
                .subnet_id_for_epoch(ctx.source_ip, net_epoch - 1),
            subnet_id: self.identity.subnet_id_for_epoch(ctx.source_ip, net_epoch),
            subnet_id_next: self
                .identity
                .subnet_id_for_epoch(ctx.source_ip, net_epoch + 1),
            session_id,
            principal_id,
            event_id,
            network_risk: ctx.network_flags.network_risk(),
            now_ms,
        })
    }

    /// Policy override reasons first, then top contributor reasons,
    /// deduplicated and capped at 4 total.
    fn merge_contributor_reasons(&self, decision: &mut RiskDecision, vector: &SignalVector) {
        let mut reasons: Vec<RiskReason> = decision.reasons_vec();
        for reason in crate::score::top_contributor_reasons(vector, &self.policy.weights) {
            if !reasons.contains(&reason) {
                reasons.push(reason);
            }
        }
        reasons.truncate(4);
        let mut out = [None; 4];
        for (i, reason) in reasons.iter().enumerate() {
            out[i] = Some(*reason);
        }
        decision.reasons = out;
    }

    /// Assigns the decision_id and registers the decision with its exact
    /// risk score (silently on failure — never breaks issuance). The
    /// outcome ledger is always on and independent of calibration:
    ///
    /// - calibration attached → `record_receipt` (register_decision.lua):
    ///   receipt + the sampled decision-time denominator + the pending
    ///   outcome ledger in ONE atomic script invocation;
    /// - no calibration → the pending outcome ledger alone, either folded
    ///   into the consolidated assessment (`outcome_registered = true`,
    ///   the assess_v2.lua call already registered the entry atomically)
    ///   or via `store.register_outcome` (outcome_register.lua).
    ///
    /// `decision_id` is the pre-generated id the consolidated assessment
    /// registered the ledger under (`None` draws a fresh random id);
    /// `outcome_registered` tells the calibration-less path that the
    /// ledger entry already exists.
    ///
    /// `decision_hour = now_ms / 3_600_000` anchors the decision to its
    /// hour (confirmed outcomes are bucketed by decision time).
    fn finalize_decision(
        &self,
        scope: u32,
        mut decision: RiskDecision,
        decision_id: Option<String>,
        outcome_registered: bool,
    ) -> RiskDecision {
        decision.decision_id = decision_id.unwrap_or_else(|| hex::encode(fresh_decision_id()));
        let decision_hour = (crate::now_ms() / 3_600_000) as i64;
        match &self.calibration {
            Some(calibration) => {
                let sampled = calibration.sample();
                let _ = calibration.record_receipt(
                    &decision.decision_id,
                    scope,
                    decision.band,
                    decision.action,
                    decision.score as u32,
                    sampled,
                    decision_hour,
                    1.0,
                );
            }
            None => {
                if !outcome_registered {
                    let _ = self.store.register_outcome(
                        &decision.decision_id,
                        scope,
                        decision_hour,
                        decision.score as u32,
                    );
                }
            }
        }
        decision
    }

    fn record_decision_metrics(&self, scope: u32, decision: &RiskDecision) {
        self.metrics.incr(&format!(
            "decisions:{scope}:{}:{}",
            decision.action.as_str(),
            decision.band
        ));
    }
}

pub(crate) fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

/// A fresh 16-byte random decision id (hex), the internal handle the
/// always-on outcome ledger is keyed under.
fn fresh_decision_id() -> [u8; 16] {
    let mut id = [0u8; 16];
    thread_rng().fill_bytes(&mut id);
    id
}

/// The client-context tag to present to the consolidated assessment call:
/// the v2 context's tag when a session pseudonym exists and the tag is
/// non-empty, else `None` (no record is written). Mirrors the guards of
/// the fallback `derive_v2_signals` path exactly.
fn presented_context_tag(v2: Option<&RiskV2Context>, session_id: Option<[u8; 16]>) -> Option<&str> {
    let v2 = v2?;
    session_id?;
    let tag = v2.client_context_tag.as_deref()?;
    if tag.is_empty() {
        return None;
    }
    Some(tag)
}

/// The trusted-edge TLS tag to present to the consolidated assessment
/// call: the v2 context's tag when a session pseudonym exists and the tag
/// is non-empty and within the 64-char bound, else `None` (no record is
/// written). Mirrors the guards of the fallback `derive_v2_signals` path
/// exactly.
fn presented_tls_tag(v2: Option<&RiskV2Context>, session_id: Option<[u8; 16]>) -> Option<&str> {
    let v2 = v2?;
    session_id?;
    let tag = v2.tls_tag.as_deref()?;
    if tag.is_empty() || tag.len() > 64 {
        return None;
    }
    Some(tag)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::action::RiskAction;
    use crate::calibration::CalibrationStore;
    use crate::event::RiskEventKind;
    use crate::network::{CidrEntry, CidrNetworkClassifier, NetworkFlags};
    use crate::policy::RiskPolicy;
    use crate::resources::ResourcePressure;
    use crate::signals::SignalVector;
    use crate::store::{AssessV2Reply, RiskStoreError};
    use ::redis::Commands;
    use serde_json::json;
    use std::collections::{HashMap, HashSet};
    use std::net::IpAddr;
    use std::sync::atomic::AtomicUsize;

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
        RiskKeys::from_master(&[0x42; 32])
    }

    fn classifier() -> CidrNetworkClassifier {
        CidrNetworkClassifier::from_entries(vec![(
            CidrEntry::parse("203.0.113.0/24").unwrap(),
            NetworkFlags {
                known_hosting: true,
                ..Default::default()
            },
        )])
    }

    fn context() -> RiskContext<'static> {
        RiskContext::new(
            1,
            "203.0.113.27".parse().unwrap(),
            None,
            None,
            RiskEventKind::PreIssue,
            NetworkFlags {
                known_hosting: true,
                ..Default::default()
            },
            ResourcePressure::default(),
        )
    }

    /// In-memory always-on outcome ledger (models outcome_register.lua /
    /// outcome_confirm.lua / outcome_correct.lua exactly): an entry is
    /// pending (`None`) once registered, flips exactly once on confirm, and
    /// flips again on correction unless it already carries the target
    /// outcome.
    #[derive(Default)]
    struct OutcomeLedger {
        entries: Mutex<HashMap<String, Option<bool>>>,
    }

    impl OutcomeLedger {
        fn register(&self, decision_id: &str) -> bool {
            let mut entries = self.entries.lock().unwrap();
            if entries.contains_key(decision_id) {
                return false;
            }
            entries.insert(decision_id.to_string(), None);
            true
        }

        fn confirm(&self, decision_id: &str, legitimate: bool) -> u8 {
            let mut entries = self.entries.lock().unwrap();
            match entries.get(decision_id) {
                Some(None) => {
                    entries.insert(decision_id.to_string(), Some(legitimate));
                    1
                }
                _ => 0,
            }
        }

        fn correct(&self, decision_id: &str, legitimate: bool) -> bool {
            let mut entries = self.entries.lock().unwrap();
            match entries.get(decision_id) {
                Some(current) if *current != Some(legitimate) => {
                    entries.insert(decision_id.to_string(), Some(legitimate));
                    true
                }
                _ => false,
            }
        }
    }

    struct MockStore {
        level: u8,
        vector: SignalVector,
        cooldown_until_ms: u64,
        calls: AtomicUsize,
        fail: bool,
        fail_calls: usize,
        outcomes: OutcomeLedger,
    }

    impl MockStore {
        fn new(vector: SignalVector, level: u8) -> MockStore {
            MockStore {
                level,
                vector,
                cooldown_until_ms: 0,
                calls: AtomicUsize::new(0),
                fail: false,
                fail_calls: 0,
                outcomes: OutcomeLedger::default(),
            }
        }

        fn with_cooldown(vector: SignalVector, level: u8, cooldown_until_ms: u64) -> MockStore {
            MockStore {
                level,
                vector,
                cooldown_until_ms,
                calls: AtomicUsize::new(0),
                fail: false,
                fail_calls: 0,
                outcomes: OutcomeLedger::default(),
            }
        }

        fn failing() -> MockStore {
            MockStore {
                level: 0,
                vector: SignalVector::zero(),
                cooldown_until_ms: 0,
                calls: AtomicUsize::new(0),
                fail: true,
                fail_calls: usize::MAX,
                outcomes: OutcomeLedger::default(),
            }
        }

        fn failing_then_ok(fail_calls: usize) -> MockStore {
            MockStore {
                level: 0,
                vector: SignalVector {
                    source_fast: 500,
                    ..Default::default()
                },
                cooldown_until_ms: 0,
                calls: AtomicUsize::new(0),
                fail: true,
                fail_calls,
                outcomes: OutcomeLedger::default(),
            }
        }
    }

    impl RiskStateStore for MockStore {
        fn observe(&self, _o: &RiskObservation) -> Result<Observed, RiskStoreError> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            if self.fail && self.calls.load(Ordering::Relaxed) <= self.fail_calls {
                return Err(RiskStoreError::BackendUnavailable("redis down".into()));
            }
            Ok(Observed {
                vector: self.vector,
                global_level: self.level,
                cooldown_until_ms: self.cooldown_until_ms,
                is_duplicate: false,
            })
        }

        fn register_outcome(
            &self,
            decision_id: &str,
            _scope: u32,
            _decision_hour: i64,
            _score: u32,
        ) -> Result<bool, RiskStoreError> {
            Ok(self.outcomes.register(decision_id))
        }

        fn confirm_outcome(
            &self,
            decision_id: &str,
            legitimate: bool,
        ) -> Result<u8, RiskStoreError> {
            Ok(self.outcomes.confirm(decision_id, legitimate))
        }

        fn correct_outcome(
            &self,
            decision_id: &str,
            legitimate: bool,
        ) -> Result<bool, RiskStoreError> {
            Ok(self.outcomes.correct(decision_id, legitimate))
        }

        fn last_global_level(&self) -> u8 {
            self.level
        }
    }

    // The v1 test stores declare NO session-first-tag record surface: the
    // default capability methods report `Ok(None)` and the engine degrades
    // the v2 consistency signals to neutral, exactly like a backend miss.
    impl SessionContextTagStore for MockStore {}
    impl SessionTlsTagStore for MockStore {}

    struct CapturingStore(pub Mutex<Vec<RiskObservation>>, OutcomeLedger);

    impl RiskStateStore for CapturingStore {
        fn observe(&self, o: &RiskObservation) -> Result<Observed, RiskStoreError> {
            self.0.lock().unwrap().push(o.clone());
            Ok(Observed {
                vector: SignalVector::zero(),
                global_level: 0,
                cooldown_until_ms: 0,
                is_duplicate: false,
            })
        }

        fn register_outcome(
            &self,
            decision_id: &str,
            _scope: u32,
            _decision_hour: i64,
            _score: u32,
        ) -> Result<bool, RiskStoreError> {
            Ok(self.1.register(decision_id))
        }

        fn confirm_outcome(
            &self,
            decision_id: &str,
            legitimate: bool,
        ) -> Result<u8, RiskStoreError> {
            Ok(self.1.confirm(decision_id, legitimate))
        }

        fn correct_outcome(
            &self,
            decision_id: &str,
            legitimate: bool,
        ) -> Result<bool, RiskStoreError> {
            Ok(self.1.correct(decision_id, legitimate))
        }
    }

    impl SessionContextTagStore for CapturingStore {}
    impl SessionTlsTagStore for CapturingStore {}

    /// Store alternating boundary scores (449/451) on every observe — the
    /// engine-level hysteresis wiring check.
    #[derive(Default)]
    struct OscillatingStore {
        calls: AtomicUsize,
        outcomes: OutcomeLedger,
    }

    impl RiskStateStore for OscillatingStore {
        fn observe(&self, _o: &RiskObservation) -> Result<Observed, RiskStoreError> {
            let n = self.calls.fetch_add(1, Ordering::Relaxed);
            // source_fast 900 + bad_proof 810/819 -> scores 449/451: the
            // 450 edge of the Sha18/Sha20 bands (both signals stay below
            // the hard-deny thresholds).
            Ok(Observed {
                vector: SignalVector {
                    source_fast: 900,
                    bad_proof: if n.is_multiple_of(2) { 810 } else { 819 },
                    ..Default::default()
                },
                global_level: 0,
                cooldown_until_ms: 0,
                is_duplicate: false,
            })
        }

        fn register_outcome(
            &self,
            decision_id: &str,
            _scope: u32,
            _decision_hour: i64,
            _score: u32,
        ) -> Result<bool, RiskStoreError> {
            Ok(self.outcomes.register(decision_id))
        }

        fn confirm_outcome(
            &self,
            decision_id: &str,
            legitimate: bool,
        ) -> Result<u8, RiskStoreError> {
            Ok(self.outcomes.confirm(decision_id, legitimate))
        }

        fn correct_outcome(
            &self,
            decision_id: &str,
            legitimate: bool,
        ) -> Result<bool, RiskStoreError> {
            Ok(self.outcomes.correct(decision_id, legitimate))
        }

        fn last_global_level(&self) -> u8 {
            0
        }
    }

    impl SessionContextTagStore for OscillatingStore {}
    impl SessionTlsTagStore for OscillatingStore {}

    /// Store with the risk-v2 session first-tag record semantics (SET NX:
    /// the first tag a session presents is recorded and returned forever).
    #[derive(Default)]
    struct V2FirstTagStore {
        tags: Mutex<HashMap<[u8; 16], String>>,
        tls_tags: Mutex<HashMap<[u8; 16], String>>,
        outcomes: OutcomeLedger,
    }

    impl RiskStateStore for V2FirstTagStore {
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
            decision_id: &str,
            _scope: u32,
            _decision_hour: i64,
            _score: u32,
        ) -> Result<bool, RiskStoreError> {
            Ok(self.outcomes.register(decision_id))
        }

        fn confirm_outcome(
            &self,
            decision_id: &str,
            legitimate: bool,
        ) -> Result<u8, RiskStoreError> {
            Ok(self.outcomes.confirm(decision_id, legitimate))
        }

        fn correct_outcome(
            &self,
            decision_id: &str,
            legitimate: bool,
        ) -> Result<bool, RiskStoreError> {
            Ok(self.outcomes.correct(decision_id, legitimate))
        }
    }

    impl SessionContextTagStore for V2FirstTagStore {
        fn session_first_context_tag(
            &self,
            session_id: &[u8; 16],
            tag: &str,
        ) -> Result<Option<String>, RiskStoreError> {
            let mut tags = self.tags.lock().unwrap_or_else(|p| p.into_inner());
            Ok(Some(
                tags.entry(*session_id)
                    .or_insert_with(|| tag.to_string())
                    .clone(),
            ))
        }
    }

    impl SessionTlsTagStore for V2FirstTagStore {
        fn session_first_tls_tag(
            &self,
            session_id: &[u8; 16],
            tag: &str,
        ) -> Result<Option<String>, RiskStoreError> {
            let mut tags = self.tls_tags.lock().unwrap_or_else(|p| p.into_inner());
            Ok(Some(
                tags.entry(*session_id)
                    .or_insert_with(|| tag.to_string())
                    .clone(),
            ))
        }
    }

    fn v2_context(honeypot_hit: bool, tag: Option<&str>, tls_tag: Option<&str>) -> RiskV2Context {
        RiskV2Context {
            honeypot_hit,
            client_context_tag: tag.map(str::to_string),
            tls_tag: tls_tag.map(str::to_string),
        }
    }

    /// Risk-v2 honeypot evidence feeds the decision: a honeypot hit with an
    /// otherwise-clean vector raises the score (100 -> 300, Sha18) without
    /// hard-denying.
    #[test]
    fn v2_honeypot_evidence_raises_the_score_but_never_denies_alone() {
        let engine = RiskEngine::new(V2FirstTagStore::default(), classifier(), policy(), keys());
        let clean = engine.assess_pre_issue(context(), None).unwrap();
        assert_eq!(clean.score, 100);
        assert_eq!(clean.action, RiskAction::Allow);

        // A fresh engine (no scope-action hysteresis memory): the plain
        // band mapping applies — 300 maps to Sha18 (a stronger profile is
        // selected, never a hard denial).
        let fresh = RiskEngine::new(V2FirstTagStore::default(), classifier(), policy(), keys());
        let hit = fresh
            .assess_pre_issue_v2(context(), &v2_context(true, None, None), None, None)
            .unwrap();
        assert_eq!(hit.score, 300); // 100 + weighted(1000, honeypot 200)
        assert_eq!(hit.action, RiskAction::Sha18);
        assert_ne!(
            hit.action,
            RiskAction::Deny,
            "a lone honeypot hit must never deny"
        );

        // Through the same engine the decision escalates (Allow -> Sha16)
        // instead of staying flat: the honeypot evidence moved the profile.
        let escalated = engine
            .assess_pre_issue_v2(context(), &v2_context(true, None, None), None, None)
            .unwrap();
        assert_eq!(escalated.score, 300);
        assert_eq!(escalated.action, RiskAction::Sha16);
        assert!(
            escalated.action.rank() > clean.action.rank(),
            "honeypot evidence must select a stronger profile"
        );
    }

    /// ANY of the three honeypot event kinds derives the honeypot signal,
    /// even without an explicit context flag.
    #[test]
    fn v2_honeypot_event_kinds_derive_the_signal() {
        let engine = RiskEngine::new(V2FirstTagStore::default(), classifier(), policy(), keys());
        for kind in [
            RiskEventKind::HoneypotTriggered,
            RiskEventKind::DecoyEndpointTouched,
            RiskEventKind::DecoyFieldSubmitted,
        ] {
            let ctx = RiskContext {
                event: kind,
                ..context()
            };
            let decision = engine
                .assess_pre_issue_v2(ctx, &v2_context(false, None, None), None, None)
                .unwrap();
            assert_eq!(
                decision.score, 300,
                "{kind:?} must derive the honeypot signal"
            );
        }
    }

    /// Session client-context consistency: a consistent tag (the session's
    /// first-seen tag) is neutral; a changed tag raises the aggregate; an
    /// absent tag (first request) is neutral.
    #[test]
    fn v2_session_client_context_consistency() {
        let engine = RiskEngine::new(V2FirstTagStore::default(), classifier(), policy(), keys());
        let session: &[u8] = b"session-bytes";
        let with_session = |_tag: &str| RiskContext {
            session_id: Some(session),
            ..context()
        };

        // First request: the tag is recorded as the first-seen tag and the
        // consistency signal is neutral (score 100).
        let first = engine
            .assess_pre_issue_v2(
                with_session("ta"),
                &v2_context(false, Some("ta"), None),
                None,
                None,
            )
            .unwrap();
        assert_eq!(first.score, 100, "first tag-bearing request is neutral");

        // Same tag again: still consistent, still neutral.
        let again = engine
            .assess_pre_issue_v2(
                with_session("ta"),
                &v2_context(false, Some("ta"), None),
                None,
                None,
            )
            .unwrap();
        assert_eq!(again.score, 100, "an unchanged tag stays neutral");

        // Changed tag: inconsistency raises the aggregate (100 + 120 = 220).
        let changed = engine
            .assess_pre_issue_v2(
                with_session("tb"),
                &v2_context(false, Some("tb"), None),
                None,
                None,
            )
            .unwrap();
        assert_eq!(changed.score, 220, "a changed tag must raise the aggregate");
    }

    /// An absent session or absent tag carries NO inconsistency signal
    /// (neutral), and the risk-v2 path is byte-identical to v1 with an
    /// empty context.
    #[test]
    fn v2_absent_tag_and_empty_context_are_neutral() {
        let engine = RiskEngine::new(V2FirstTagStore::default(), classifier(), policy(), keys());
        let plain = engine.assess_pre_issue(context(), None).unwrap();
        let empty = engine
            .assess_pre_issue_v2(context(), &v2_context(false, None, None), None, None)
            .unwrap();
        assert_eq!(empty.score, plain.score);
        assert_eq!(empty.action, plain.action);

        let no_tag = engine
            .assess_pre_issue_v2(
                RiskContext {
                    session_id: Some(b"session-bytes"),
                    ..context()
                },
                &v2_context(false, None, None),
                None,
                None,
            )
            .unwrap();
        assert_eq!(no_tag.score, 100, "a session without a tag stays neutral");
    }

    /// Trusted-edge TLS consistency: a consistent tag (the session's
    /// first-seen TLS classification) is neutral; a changed tag raises the
    /// aggregate; an absent tag (first request) is neutral.
    #[test]
    fn v2_tls_consistency() {
        let engine = RiskEngine::new(V2FirstTagStore::default(), classifier(), policy(), keys());
        let session: &[u8] = b"tls-session-bytes";
        let with_session = |_tag: &str| RiskContext {
            session_id: Some(session),
            ..context()
        };

        // First request: the TLS tag is recorded as the first-seen tag and
        // the consistency signal is neutral (score 100).
        let first = engine
            .assess_pre_issue_v2(
                with_session("tls13|http2"),
                &v2_context(false, None, Some("tls13|http2")),
                None,
                None,
            )
            .unwrap();
        assert_eq!(first.score, 100, "first TLS tag-bearing request is neutral");

        // Same tag again: still consistent, still neutral.
        let again = engine
            .assess_pre_issue_v2(
                with_session("tls13|http2"),
                &v2_context(false, None, Some("tls13|http2")),
                None,
                None,
            )
            .unwrap();
        assert_eq!(again.score, 100, "an unchanged TLS tag stays neutral");

        // Changed tag: TLS inconsistency raises the aggregate (100 + 80 = 180).
        let changed = engine
            .assess_pre_issue_v2(
                with_session("tls12|http1"),
                &v2_context(false, None, Some("tls12|http1")),
                None,
                None,
            )
            .unwrap();
        assert_eq!(
            changed.score, 180,
            "a changed TLS tag must raise the aggregate"
        );
    }

    /// An absent TLS tag, a session without any TLS tag, and a TLS tag
    /// over the 64-char bound (treated as absent) carry NO inconsistency
    /// signal (neutral).
    #[test]
    fn v2_absent_or_overbound_tls_tag_is_neutral() {
        let engine = RiskEngine::new(V2FirstTagStore::default(), classifier(), policy(), keys());
        let session: &[u8] = b"tls-absent-session";

        let first = engine
            .assess_pre_issue_v2(
                RiskContext {
                    session_id: Some(session),
                    ..context()
                },
                &v2_context(false, None, Some("tls13|http2")),
                None,
                None,
            )
            .unwrap();
        assert_eq!(first.score, 100);

        // Session without a TLS tag: neutral.
        let no_tag = engine
            .assess_pre_issue_v2(
                RiskContext {
                    session_id: Some(session),
                    ..context()
                },
                &v2_context(false, None, None),
                None,
                None,
            )
            .unwrap();
        assert_eq!(
            no_tag.score, 100,
            "a session without a TLS tag stays neutral"
        );

        // A TLS tag over the 64-char bound is treated as absent and must
        // never raise the aggregate — and it must not be recorded either.
        let overbound = "y".repeat(65);
        let first_overbound = engine
            .assess_pre_issue_v2(
                RiskContext {
                    session_id: Some(b"tls-overbound-session"),
                    ..context()
                },
                &v2_context(false, None, Some(overbound.as_str())),
                None,
                None,
            )
            .unwrap();
        assert_eq!(
            first_overbound.score, 100,
            "an over-bound TLS tag is treated as absent"
        );
        let changed_overbound = engine
            .assess_pre_issue_v2(
                RiskContext {
                    session_id: Some(b"tls-overbound-session"),
                    ..context()
                },
                &v2_context(false, None, Some("z".repeat(65).as_str())),
                None,
                None,
            )
            .unwrap();
        assert_eq!(
            changed_overbound.score, 100,
            "an over-bound TLS tag must never raise the aggregate"
        );
    }

    /// The v2 weights override tunes the additive factors: `None` uses the
    /// default weights (identical scores to today); an override changes
    /// only the weighted contribution.
    #[test]
    fn v2_weights_override_tunes_the_additive_factors() {
        let engine = RiskEngine::new(V2FirstTagStore::default(), classifier(), policy(), keys());

        // Null override: the default weights apply (100 + 1000*200/1000 = 300).
        let default = engine
            .assess_pre_issue_v2(context(), &v2_context(true, None, None), None, None)
            .unwrap();
        assert_eq!(
            default.score, 300,
            "a null weights override must produce the default score"
        );

        // Operator-tuned weights: honeypot weight 100 -> 100 + 1000*100/1000 = 200.
        let tuned = engine
            .assess_pre_issue_v2(
                context(),
                &v2_context(true, None, None),
                None,
                Some(RiskV2Weights {
                    honeypot: 100,
                    ..Default::default()
                }),
            )
            .unwrap();
        assert_eq!(
            tuned.score, 200,
            "the v2 weights override must tune the additive factors"
        );
    }

    /// Wraps the real Redis store and counts the store-surface calls an
    /// assessment makes (the Rust mirror of the PHP command-count seam):
    /// an established-session assessment must issue exactly ONE
    /// consolidated script call and no separate register_outcome. The
    /// counters are shared via `Arc` so the test can read them after the
    /// store is moved into the engine.
    struct CountingConsolidatedRedisStore {
        inner: crate::redis::RedisRiskStateStore,
        assess_v2_calls: Arc<AtomicUsize>,
        observe_calls: Arc<AtomicUsize>,
        register_outcome_calls: Arc<AtomicUsize>,
    }

    impl CountingConsolidatedRedisStore {
        fn new(
            inner: crate::redis::RedisRiskStateStore,
            assess_v2_calls: Arc<AtomicUsize>,
            observe_calls: Arc<AtomicUsize>,
            register_outcome_calls: Arc<AtomicUsize>,
        ) -> CountingConsolidatedRedisStore {
            CountingConsolidatedRedisStore {
                inner,
                assess_v2_calls,
                observe_calls,
                register_outcome_calls,
            }
        }
    }

    impl RiskStateStore for CountingConsolidatedRedisStore {
        fn observe(&self, o: &RiskObservation) -> Result<Observed, RiskStoreError> {
            self.observe_calls.fetch_add(1, Ordering::Relaxed);
            self.inner.observe(o)
        }

        fn register_outcome(
            &self,
            decision_id: &str,
            scope: u32,
            decision_hour: i64,
            score: u32,
        ) -> Result<bool, RiskStoreError> {
            self.register_outcome_calls.fetch_add(1, Ordering::Relaxed);
            self.inner
                .register_outcome(decision_id, scope, decision_hour, score)
        }

        fn assess_v2(
            &self,
            o: &RiskObservation,
            context_tag: Option<&str>,
            tls_tag: Option<&str>,
            registration: Option<&OutcomeRegistration>,
        ) -> Result<Option<AssessV2Reply>, RiskStoreError> {
            self.assess_v2_calls.fetch_add(1, Ordering::Relaxed);
            self.inner.assess_v2(o, context_tag, tls_tag, registration)
        }

        fn confirm_outcome(
            &self,
            decision_id: &str,
            legitimate: bool,
        ) -> Result<u8, RiskStoreError> {
            self.inner.confirm_outcome(decision_id, legitimate)
        }

        fn correct_outcome(
            &self,
            decision_id: &str,
            legitimate: bool,
        ) -> Result<bool, RiskStoreError> {
            self.inner.correct_outcome(decision_id, legitimate)
        }

        fn last_global_level(&self) -> u8 {
            self.inner.last_global_level()
        }

        fn last_cooldown_until_ms(&self) -> u64 {
            self.inner.last_cooldown_until_ms()
        }
    }

    impl SessionContextTagStore for CountingConsolidatedRedisStore {
        fn session_first_context_tag(
            &self,
            session_id: &[u8; 16],
            tag: &str,
        ) -> Result<Option<String>, RiskStoreError> {
            self.inner.session_first_context_tag(session_id, tag)
        }
    }

    impl SessionTlsTagStore for CountingConsolidatedRedisStore {
        fn session_first_tls_tag(
            &self,
            session_id: &[u8; 16],
            tag: &str,
        ) -> Result<Option<String>, RiskStoreError> {
            self.inner.session_first_tls_tag(session_id, tag)
        }
    }

    /// The established-session assessment issues exactly ONE script call:
    /// the full calibration-less assessment path (observation +
    /// first-seen tags + outcome registration) runs as a single
    /// assess_v2 invocation, and the separate observe/register_outcome
    /// surfaces are not touched.
    #[test]
    fn established_session_assessment_issues_exactly_one_script_call() {
        let Some(url) = std::env::var("RISK_REDIS_URL")
            .ok()
            .filter(|u| !u.is_empty())
        else {
            eprintln!("skipping Redis test: RISK_REDIS_URL not set");
            return;
        };
        let url = url
            .strip_prefix("tcp://")
            .map(|rest| format!("redis://{rest}"))
            .unwrap_or(url);
        let mut suffix = [0u8; 4];
        rand::thread_rng().fill_bytes(&mut suffix);
        let inner = crate::redis::RedisRiskStateStore::new(
            ::redis::Client::open(url.clone()).expect("url parses"),
            &format!("engcount{}", hex::encode(suffix)),
        )
        .with_io_timeouts(2_000, 2_000);
        let assess_calls = Arc::new(AtomicUsize::new(0));
        let observe_calls = Arc::new(AtomicUsize::new(0));
        let register_calls = Arc::new(AtomicUsize::new(0));
        let store = CountingConsolidatedRedisStore::new(
            inner,
            assess_calls.clone(),
            observe_calls.clone(),
            register_calls.clone(),
        );
        let engine = RiskEngine::new(store, classifier(), policy(), keys());
        let session: [u8; 22] = *b"established-session-id";

        // Prime: the first assessment records the session tag records and
        // registers its own decision atomically.
        let first = engine
            .assess_pre_issue_v2(
                RiskContext {
                    session_id: Some(&session),
                    ..context()
                },
                &v2_context(false, Some("aa"), Some("tls13|http2")),
                None,
                None,
            )
            .unwrap();
        assess_calls.store(0, Ordering::Relaxed);
        observe_calls.store(0, Ordering::Relaxed);
        register_calls.store(0, Ordering::Relaxed);

        // Established session: the whole assessment is ONE consolidated
        // script call.
        let second = engine
            .assess_pre_issue_v2(
                RiskContext {
                    session_id: Some(&session),
                    ..context()
                },
                &v2_context(false, Some("aa"), Some("tls13|http2")),
                None,
                None,
            )
            .unwrap();
        assert_eq!(
            assess_calls.load(Ordering::Relaxed),
            1,
            "the established-session assessment must issue exactly ONE consolidated script call"
        );
        assert_eq!(
            observe_calls.load(Ordering::Relaxed),
            0,
            "the consolidated path must not fall back to the plain observe"
        );
        assert_eq!(
            register_calls.load(Ordering::Relaxed),
            0,
            "the outcome registration must run inside the consolidated call"
        );

        // The decision's pending ledger entry exists with the exact
        // decision score (the registration ran inside that one call).
        let mut conn = ::redis::Client::open(url)
            .expect("url parses")
            .get_connection()
            .expect("connection");
        let key = format!(
            "{{kiwi:engcount{}}}:outcome:{}",
            hex::encode(suffix),
            second.decision_id
        );
        let raw: String = conn.get(&key).expect("get");
        let value: serde_json::Value = serde_json::from_str(&raw).expect("json");
        assert_eq!(value["o"], "P");
        assert_eq!(
            value["score"].as_u64().unwrap() as u16,
            second.score,
            "the consolidated ledger score must be the exact decision score"
        );
        assert_ne!(
            first.decision_id, second.decision_id,
            "each assessment registers its own decision"
        );
    }

    #[test]
    fn assess_normal_path() {
        let store = MockStore::new(
            SignalVector {
                source_fast: 500,
                ..Default::default()
            },
            2,
        );
        let engine = RiskEngine::new(store, classifier(), policy(), keys());
        let decision = engine.assess_pre_issue(context(), None).unwrap();
        assert_eq!(decision.score, 195); // 100 + weighted(500, 190)
        assert_eq!(decision.action, RiskAction::Sha18); // band Sha16 raised by global floor 2
        assert_eq!(decision.policy_version, 3);
        assert_eq!(decision.model_revision, RISK_MODEL_REVISION);
        assert_eq!(decision.global_level, 2);
        assert_eq!(decision.band, 1);
        assert_eq!(decision.decision_id.len(), 32);

        let snapshot = engine.metrics().snapshot();
        assert!(snapshot.iter().any(|(k, _)| k == "decisions:1:sha18:1"));
        assert!(snapshot.iter().any(|(k, _)| k == "store:observe:count"));
    }

    /// Engine-level wiring: the engine passes its per-process
    /// scope-action hysteresis map into the policy, so an oscillating
    /// boundary score (449/451/449…) yields a stable action instead of a
    /// flip-flopping challenge profile.
    #[test]
    fn scope_action_hysteresis_stabilizes_oscillating_boundary_scores() {
        let engine = RiskEngine::new(OscillatingStore::default(), classifier(), policy(), keys());
        for i in 0..8 {
            let decision = engine.assess_pre_issue(context(), None).unwrap();
            assert_eq!(
                decision.score,
                449 + i % 2 * 2,
                "iteration {i}: the scores must oscillate at the 450 edge"
            );
            assert_eq!(
                decision.action,
                RiskAction::Sha18,
                "iteration {i}: the oscillating boundary score must not flip the profile"
            );
        }
    }

    #[test]
    fn observation_carries_epoch_scoped_pseudonyms() {
        let store = CapturingStore(Mutex::new(Vec::new()), OutcomeLedger::default());
        let engine = RiskEngine::new(store, classifier(), policy(), keys());
        engine.assess_pre_issue(context(), None).unwrap();

        let captured = engine.store.0.lock().unwrap();
        let observation = &captured[0];
        assert_eq!(observation.event, RiskEventKind::PreIssue);
        assert_eq!(observation.scope, 1);
        assert_eq!(observation.source_id.len(), 32);
        assert_eq!(observation.subnet_id.len(), 32);
        // Epoch-correct pseudonyms: prev/current/next differ and are each
        // 32 hex chars.
        assert_eq!(observation.source_id_prev.len(), 32);
        assert_eq!(observation.source_id_next.len(), 32);
        assert_ne!(observation.source_id_prev, observation.source_id);
        assert_ne!(observation.source_id_next, observation.source_id);
        assert_ne!(observation.source_id_prev, observation.source_id_next);
        assert_eq!(observation.session_id, None);
        assert_eq!(observation.principal_id, None);
        assert_eq!(observation.network_risk, 600); // hosting flag
        assert_eq!(observation.event_id.len(), 32);

        // The epochs in the observation match the engine windows.
        let now_secs = (observation.now_ms / 1000) as i64;
        assert_eq!(observation.source_epoch, now_secs / 900);
        assert_eq!(observation.subnet_epoch, now_secs / 900);
    }

    #[test]
    fn idempotency_key_becomes_the_normalized_event_id() {
        let store = CapturingStore(Mutex::new(Vec::new()), OutcomeLedger::default());
        let engine = RiskEngine::new(store, classifier(), policy(), keys());
        let decision = engine
            .assess_pre_issue(context(), Some("deadbeef".to_string()))
            .unwrap();
        assert_eq!(decision.decision_id.len(), 32);
        let captured = engine.store.0.lock().unwrap();
        assert_eq!(
            captured[0].event_id,
            crate::event::normalize_idempotency_key(
                Some("deadbeef"),
                1,
                RiskEventKind::PreIssue,
                &keys().event,
            )
            .unwrap(),
            "verbatim keys are HMAC'd (scope + event domain-separated) before they become Redis suffixes"
        );
        assert_eq!(captured[0].event_id.len(), 64);

        // The same caller key under a different event kind (e.g. a feedback
        // wrapper) must never collide with the PreIssue dedupe id.
        let engine2 = RiskEngine::new(
            CapturingStore(Mutex::new(Vec::new()), OutcomeLedger::default()),
            classifier(),
            policy(),
            keys(),
        );
        let mut feedback_ctx = context();
        feedback_ctx.event = RiskEventKind::ChallengeIssued;
        engine2
            .record_feedback(
                RiskEventKind::ChallengeIssued,
                feedback_ctx,
                Some("deadbeef".to_string()),
                None,
            )
            .unwrap();
        let captured2 = engine2.store.0.lock().unwrap();
        assert_ne!(captured[0].event_id, captured2[0].event_id);
    }

    #[test]
    fn oversized_idempotency_key_errors() {
        let store = MockStore::new(SignalVector::zero(), 0);
        let engine = RiskEngine::new(store, classifier(), policy(), keys());
        let long = "x".repeat(4097);
        assert_eq!(
            engine.assess_pre_issue(context(), Some(long)),
            Err(RiskError::InvalidIdempotencyKey(4097))
        );
        assert_eq!(
            engine.reassess(context(), Some("y".repeat(4097))),
            Err(RiskError::InvalidIdempotencyKey(4097))
        );
        assert_eq!(
            engine.record_feedback(
                RiskEventKind::ChallengeIssued,
                context(),
                Some("z".repeat(4097)),
                None,
            ),
            Err(RiskError::InvalidIdempotencyKey(4097))
        );
        assert_eq!(
            engine.store.calls.load(Ordering::Relaxed),
            0,
            "an invalid key must fail before the store is touched"
        );
    }

    #[test]
    fn emergency_limiter_denies_with_retry_after() {
        // Ramp disabled: the original full-burst window semantics.
        let limiter = ProcessEmergencyCap::with_capacity_and_ramp(100, 0.0);
        for _ in 0..100 {
            assert!(limiter.allow());
        }
        let store = MockStore::new(SignalVector::zero(), 0);
        let engine = RiskEngine::with_components(
            store,
            classifier(),
            policy(),
            keys(),
            breaker::CircuitBreaker::default(),
            limiter,
        );
        let decision = engine.assess_pre_issue(context(), None).unwrap();
        assert_eq!(decision.action, RiskAction::Deny);
        assert!(decision.has_reason(RiskReason::HardRateLimit));
        assert_eq!(decision.retry_after_ms, Some(1000));
        assert_eq!(decision.model_revision, RISK_MODEL_REVISION);
        assert_eq!(decision.decision_id.len(), 32);
        assert_eq!(
            engine.store.calls.load(Ordering::Relaxed),
            0,
            "the store must not be touched when the limiter is open"
        );
    }

    #[test]
    fn emergency_limiter_defaults_to_10000_per_second() {
        let limiter = ProcessEmergencyCap::new();
        assert_eq!(limiter.process_per_second(), 10_000);
        // A healthy burst far below the default cap is admitted...
        for _ in 0..1000 {
            assert!(limiter.allow());
        }
        // ...and a saturated window denies.
        let small = ProcessEmergencyCap::with_capacity_and_ramp(2, 0.0);
        assert!(small.allow());
        assert!(small.allow());
        assert!(!small.allow());
        assert!(small.is_open());
    }

    /// Warm-up ramp: a fresh process must NOT start with a
    /// full burst. At t≈0 the effective cap is the floor
    /// max(1, cap/10); cap 1000 -> floor 100: exactly 100 admissions fit,
    /// the 101st is denied.
    #[test]
    fn warmup_fresh_cap_allows_only_the_floor_rate() {
        let limiter = ProcessEmergencyCap::with_capacity_and_ramp(1000, 0.3);
        assert_eq!(limiter.warmup_ramp_secs(), 0.3);
        for _ in 0..100 {
            assert!(limiter.allow(), "floor admission");
        }
        assert!(limiter.is_open(), "the floor window must be saturated");
        assert!(
            !limiter.allow(),
            "the floor+1th must be denied during the ramp"
        );
    }

    /// After the ramp the cap reaches the full value: a short
    /// ramp + sleep (the implementation uses the fixed Instant clock).
    #[test]
    fn warmup_reaches_full_cap_after_the_ramp() {
        let limiter = ProcessEmergencyCap::with_capacity_and_ramp(1000, 0.3);
        for _ in 0..100 {
            assert!(limiter.allow());
        }
        std::thread::sleep(std::time::Duration::from_millis(350));
        assert!(
            !limiter.is_open(),
            "the floor window must have expired with the ramp"
        );
        // The 100 ramp-phase stamps are still inside the sliding 1 s window,
        // so 900 more admissions fit at the full cap (100 + 900 = 1000).
        for _ in 0..900 {
            assert!(limiter.allow(), "full-cap admission");
        }
        assert!(limiter.is_open());
        assert!(!limiter.allow(), "the full cap+1th must be denied");
    }

    /// The floor is never below 1 admission.
    #[test]
    fn warmup_floor_never_below_one() {
        let limiter = ProcessEmergencyCap::with_capacity_and_ramp(5, 0.3);
        assert!(limiter.allow(), "cap 5 floors at max(1, 0) = 1");
        assert!(limiter.is_open());
        assert!(!limiter.allow(), "the 2nd must be denied during the ramp");
    }

    /// The ramp must never raise the cap above the configured
    /// value.
    #[test]
    fn warmup_never_exceeds_configured_cap() {
        let limiter = ProcessEmergencyCap::with_capacity_and_ramp(10, 0.3);
        assert!(limiter.allow());
        std::thread::sleep(std::time::Duration::from_millis(350));
        // The 1 ramp-phase stamp is still in the 1 s window: 9 more fit.
        for _ in 0..9 {
            assert!(limiter.allow(), "full-cap admission");
        }
        assert!(
            !limiter.allow(),
            "the ramp must not lift the cap above process_per_second"
        );
    }

    #[test]
    fn reassess_ignores_the_emergency_cap() {
        let store = MockStore::new(
            SignalVector {
                source_fast: 500,
                ..Default::default()
            },
            2,
        );
        // A saturated 1-admission process cap: the pre-issue path must
        // deny...
        let limiter = ProcessEmergencyCap::with_capacity_and_ramp(1, 0.0);
        assert!(limiter.allow(), "burn the single admission");
        let engine = RiskEngine::with_components(
            store,
            classifier(),
            policy(),
            keys(),
            breaker::CircuitBreaker::default(),
            limiter,
        );

        let denied = engine.assess_pre_issue(context(), None).unwrap();
        assert!(denied.has_reason(RiskReason::HardRateLimit));
        assert_eq!(
            engine.store.calls.load(Ordering::Relaxed),
            0,
            "the limiter gate must fire before the store"
        );

        // ...but reassess never consults the cap: the same saturated engine
        // still runs the full pipeline and returns a real decision.
        let decision = engine.reassess(context(), None).unwrap();
        assert!(!decision.has_reason(RiskReason::HardRateLimit));
        assert_eq!(decision.score, 195);
        assert_eq!(decision.action, RiskAction::Sha18);
        assert_eq!(decision.decision_id.len(), 32);
        assert_eq!(engine.store.calls.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn store_failure_degrades_and_opens_breaker() {
        let store = MockStore::failing();
        let engine = RiskEngine::with_components(
            store,
            classifier(),
            policy(),
            keys(),
            breaker::CircuitBreaker::new(2, 60_000),
            ProcessEmergencyCap::new(),
        );

        let d1 = engine.assess_pre_issue(context(), None).unwrap();
        assert_eq!(d1.action, RiskAction::Sha20); // degraded sha20
        assert!(d1.has_reason(RiskReason::CapacityPressure));
        assert_eq!(engine.store.calls.load(Ordering::Relaxed), 1);

        let d2 = engine.assess_pre_issue(context(), None).unwrap();
        assert_eq!(d2.action, RiskAction::Sha20);
        assert_eq!(engine.store.calls.load(Ordering::Relaxed), 2);

        // Breaker is now open: the store is bypassed.
        let d3 = engine.assess_pre_issue(context(), None).unwrap();
        assert_eq!(d3.action, RiskAction::Sha20);
        assert_eq!(
            engine.store.calls.load(Ordering::Relaxed),
            2,
            "open breaker must bypass the store"
        );
    }

    #[test]
    fn breaker_recovers_after_window() {
        let store = MockStore::failing_then_ok(2);
        let engine = RiskEngine::with_components(
            store,
            classifier(),
            policy(),
            keys(),
            breaker::CircuitBreaker::new(2, 50),
            ProcessEmergencyCap::new(),
        );

        engine.assess_pre_issue(context(), None).unwrap();
        engine.assess_pre_issue(context(), None).unwrap();
        assert!(engine.breaker.is_open());

        std::thread::sleep(std::time::Duration::from_millis(60));
        let decision = engine.assess_pre_issue(context(), None).unwrap();
        assert_eq!(decision.score, 195);
        assert_eq!(decision.action, RiskAction::Sha16);
        assert_eq!(engine.store.calls.load(Ordering::Relaxed), 3);
        assert!(!engine.breaker.is_open());
    }

    #[test]
    fn record_feedback_maps_events_without_limiter_or_assess() {
        let store = CapturingStore(Mutex::new(Vec::new()), OutcomeLedger::default());
        let engine = RiskEngine::new(store, classifier(), policy(), keys());
        let ctx = |event| {
            RiskContext::new(
                1,
                "203.0.113.27".parse().unwrap(),
                None,
                None,
                event,
                NetworkFlags::default(),
                ResourcePressure::default(),
            )
        };

        let receipt = engine
            .record_feedback(
                RiskEventKind::ProtectedActionFailure,
                ctx(RiskEventKind::ProtectedActionFailure),
                Some("feedback-1".to_string()),
                None,
            )
            .unwrap();
        assert_eq!(
            receipt.event_id,
            crate::event::normalize_idempotency_key(
                Some("feedback-1"),
                1,
                RiskEventKind::ProtectedActionFailure,
                &keys().event,
            )
            .unwrap()
        );
        assert!(!receipt.is_duplicate);

        // Confirmed* events are rejected by record_feedback: they carry an
        // outcome for an assessed decision and must go through the
        // confirmed_* wrappers (which require the decision_id).
        assert_eq!(
            engine.record_feedback(
                RiskEventKind::ConfirmedLegitimate,
                ctx(RiskEventKind::ConfirmedLegitimate),
                None,
                None,
            ),
            Err(RiskError::ConfirmationApiRequired)
        );
        assert_eq!(
            engine.record_feedback(
                RiskEventKind::ConfirmedAbuse,
                ctx(RiskEventKind::ConfirmedAbuse),
                None,
                None,
            ),
            Err(RiskError::ConfirmationApiRequired)
        );

        let events: Vec<RiskEventKind> = {
            let captured = engine.store.0.lock().unwrap();
            captured.iter().map(|o| o.event).collect()
        };
        assert_eq!(events, vec![RiskEventKind::ProtectedActionFailure]);

        // The confirmed_* wrappers bypass the guard: they confirm the
        // always-on outcome ledger first (status 1 = first confirmation,
        // reputation eligible) and then book the reputation event.
        engine.store.register_outcome("d-fb-1", 1, 1, 100).unwrap();
        engine.store.register_outcome("d-fb-2", 1, 1, 100).unwrap();
        let sess_ctx = RiskContext::new(
            1,
            "203.0.113.27".parse().unwrap(),
            Some(b"sess"),
            Some(b"principal-1"),
            RiskEventKind::ConfirmedAbuse,
            NetworkFlags::default(),
            ResourcePressure::default(),
        );
        engine
            .confirmed_legitimate(
                ctx(RiskEventKind::ConfirmedLegitimate),
                None,
                "d-fb-1",
                None,
            )
            .unwrap();
        engine
            .confirmed_abuse(sess_ctx, None, "d-fb-2", None)
            .unwrap();
        let captured = engine.store.0.lock().unwrap();
        assert_eq!(captured.len(), 3);
        assert_eq!(captured[1].event, RiskEventKind::ConfirmedLegitimate);
        assert_eq!(captured[2].event, RiskEventKind::ConfirmedAbuse);
        assert_eq!(
            captured[2].session_id,
            Some(crate::identity::pseudonym(
                &keys().session,
                b"sess",
                0,
                b"sess"
            ))
        );
        assert_eq!(
            captured[2].principal_id,
            Some(crate::identity::pseudonym(
                &keys().principal,
                b"prin",
                0,
                b"principal-1"
            ))
        );
    }

    #[test]
    fn new_events_record_through_wrappers_without_limiter_or_assess() {
        let store = CapturingStore(Mutex::new(Vec::new()), OutcomeLedger::default());
        let engine = RiskEngine::new(store, classifier(), policy(), keys());
        let ctx = |event| {
            RiskContext::new(
                1,
                "203.0.113.27".parse().unwrap(),
                None,
                None,
                event,
                NetworkFlags::default(),
                ResourcePressure::default(),
            )
        };

        let receipt = engine
            .source_rate_limit_hit(
                ctx(RiskEventKind::SourceRateLimitHit),
                Some("srl-1".to_string()),
            )
            .unwrap();
        assert!(!receipt.is_duplicate);
        let receipt = engine
            .global_capacity_hit(
                ctx(RiskEventKind::GlobalCapacityHit),
                Some("gch-1".to_string()),
            )
            .unwrap();
        assert!(!receipt.is_duplicate);
        let receipt = engine
            .risk_denied(ctx(RiskEventKind::RiskDenied), Some("deny-1".to_string()))
            .unwrap();
        assert!(!receipt.is_duplicate);

        let events: Vec<RiskEventKind> = {
            let captured = engine.store.0.lock().unwrap();
            captured.iter().map(|o| o.event).collect()
        };
        assert_eq!(
            events,
            vec![
                RiskEventKind::SourceRateLimitHit,
                RiskEventKind::GlobalCapacityHit,
                RiskEventKind::RiskDenied,
            ]
        );
        // The dedupe ids are event-domain-separated: the same caller key
        // across the three wrappers maps to three different event_ids.
        let ids: Vec<String> = {
            let captured = engine.store.0.lock().unwrap();
            captured.iter().map(|o| o.event_id.clone()).collect()
        };
        assert_ne!(ids[0], ids[1]);
        assert_ne!(ids[1], ids[2]);
        assert_ne!(ids[0], ids[2]);
    }

    #[test]
    fn decision_json_serialization() {
        let store = MockStore::new(SignalVector::zero(), 0);
        let engine = RiskEngine::new(store, classifier(), policy(), keys());
        let decision = engine.assess_pre_issue(context(), None).unwrap();
        let json = serde_json::to_value(&decision).unwrap();
        assert_eq!(json["action"], "allow");
        assert_eq!(json["score"], 100);
        assert_eq!(json["band"], 1);
        assert_eq!(json["reasons"], serde_json::json!([]));
    }

    #[test]
    fn serialization_omits_decision_id() {
        let store = MockStore::new(SignalVector::zero(), 0);
        let engine = RiskEngine::new(store, classifier(), policy(), keys());
        let decision = engine.assess_pre_issue(context(), None).unwrap();
        // The struct still carries the id (used by record_receipt)...
        assert_eq!(decision.decision_id.len(), 32);
        // ...but the public JSON excludes it, mirroring PHP.
        let json = serde_json::to_value(&decision).unwrap();
        assert!(
            json.get("decision_id").is_none(),
            "decision_id must never leak into the serialized decision"
        );
        // 8 public fields: score, action, reasons, policy_version,
        // model_revision, global_level, retry_after_ms, band.
        assert_eq!(json.as_object().unwrap().len(), 8);
        assert_eq!(json["model_revision"], 17);
    }

    #[test]
    fn contributor_reasons_merge_behind_policy_overrides() {
        let store = MockStore::new(
            SignalVector {
                replay: 700, // policy override + contributor
                malformed: 300,
                source_fast: 500,
                ..Default::default()
            },
            0,
        );
        let engine = RiskEngine::new(store, classifier(), policy(), keys());
        let decision = engine.assess_pre_issue(context(), None).unwrap();
        assert_eq!(decision.action, RiskAction::Deny);
        let reasons = decision.reasons_vec();
        // Policy override first, then contributors, deduped.
        assert_eq!(reasons[0], RiskReason::ReplayTraffic);
        assert_eq!(reasons.len(), 3); // ReplayTraffic, MalformedTraffic, SourceBurst
        assert!(reasons.contains(&RiskReason::SourceBurst));
    }

    // ── Calibration bias parity (in-memory calibration store) ──

    /// (decision_id, scope, band, action, score, sampled, decision_hour,
    /// weight).
    type ReceiptLog = Vec<(String, u32, u8, RiskAction, u32, bool, i64, f64)>;

    struct StaticCalibration {
        bias: i32,
        confirm_status: u8,
        receipts: Mutex<ReceiptLog>,
        confirmed: Mutex<Vec<(String, bool, Option<f64>)>>,
        corrected: Mutex<HashSet<(String, bool)>>,
    }

    impl CalibrationStore for StaticCalibration {
        fn record_receipt(
            &self,
            decision_id: &str,
            scope: u32,
            band: u8,
            action: RiskAction,
            score: u32,
            sampled: bool,
            decision_hour: i64,
            weight: f64,
        ) -> Result<bool, crate::calibration::CalibrationError> {
            self.receipts.lock().unwrap().push((
                decision_id.to_string(),
                scope,
                band,
                action,
                score,
                sampled,
                decision_hour,
                weight,
            ));
            Ok(true)
        }

        fn confirm_outcome(
            &self,
            decision_id: &str,
            legitimate: bool,
            weight: Option<f64>,
        ) -> Result<u8, crate::calibration::CalibrationError> {
            self.confirmed
                .lock()
                .unwrap()
                .push((decision_id.to_string(), legitimate, weight));
            // The mock models the real receipt lifecycle: the first confirm
            // for a decision returns the configured status (1/2), every
            // later confirm sees the receipt consumed and returns 0.
            let status = if self
                .confirmed
                .lock()
                .unwrap()
                .iter()
                .filter(|(id, _, _)| id == decision_id)
                .count()
                <= 1
            {
                self.confirm_status
            } else {
                0
            };
            Ok(status)
        }

        fn correct_outcome(
            &self,
            decision_id: &str,
            legitimate: bool,
            _weight: Option<f64>,
        ) -> Result<bool, crate::calibration::CalibrationError> {
            // Models the ledger flip: the first correction to a target
            // outcome applies, a repeat to the same outcome does not.
            let mut corrected = self.corrected.lock().unwrap();
            if corrected.contains(&(decision_id.to_string(), legitimate)) {
                return Ok(false);
            }
            corrected.insert((decision_id.to_string(), legitimate));
            Ok(true)
        }

        fn sample(&self) -> bool {
            true
        }

        fn bias_for_scope(&self, _scope: u32, _now_ms: i64) -> i32 {
            self.bias
        }
    }

    fn static_calibration(bias: i32, confirm_status: u8) -> Arc<StaticCalibration> {
        Arc::new(StaticCalibration {
            bias,
            confirm_status,
            receipts: Mutex::new(Vec::new()),
            confirmed: Mutex::new(Vec::new()),
            corrected: Mutex::new(HashSet::new()),
        })
    }

    #[test]
    fn calibration_bias_applies_to_base_before_band_mapping() {
        let store = MockStore::new(SignalVector::zero(), 0);
        let cal = static_calibration(60, 1);
        let engine =
            RiskEngine::new(store, classifier(), policy(), keys()).with_calibration(cal.clone());
        let decision = engine.assess_pre_issue(context(), None).unwrap();
        // base 100 + bias 60 = 160 -> band 1, score 160.
        assert_eq!(decision.score, 160);
        assert_eq!(decision.band, 1);
        // A receipt was registered for the decision with the exact score
        // and the sampling flag.
        let receipts = cal.receipts.lock().unwrap();
        assert_eq!(receipts.len(), 1);
        assert_eq!(receipts[0].1, 1); // scope
        assert_eq!(receipts[0].4, 160); // exact risk score
        assert!(receipts[0].5); // sampled (Complete-like mock)
        assert_eq!(
            receipts[0].6,
            (crate::now_ms() / 3_600_000) as i64,
            "the receipt carries the decision hour"
        );
        assert_eq!(receipts[0].7, 1.0, "registration weight is 1.0");
    }

    #[test]
    fn confirmed_outcome_consumes_receipt_and_records() {
        let store = MockStore::new(SignalVector::zero(), 0);
        let cal = static_calibration(0, 1);
        let engine =
            RiskEngine::new(store, classifier(), policy(), keys()).with_calibration(cal.clone());
        let ctx = RiskContext::new(
            1,
            "203.0.113.27".parse().unwrap(),
            None,
            None,
            RiskEventKind::ConfirmedLegitimate,
            NetworkFlags::default(),
            ResourcePressure::default(),
        );
        let receipt = engine
            .confirmed_legitimate(ctx, None, "decision-x", None)
            .unwrap();
        assert!(!receipt.is_duplicate);
        // First the atomic confirm (legitimate, default weight 1.0)...
        let confirmed = cal.confirmed.lock().unwrap();
        assert_eq!(confirmed.len(), 1);
        assert_eq!(
            confirmed[0],
            ("decision-x".to_string(), true, None),
            "the calibrator must be confirmed before the reputation event"
        );
    }

    #[test]
    fn an_already_consumed_receipt_skips_the_reputation_event() {
        let store = MockStore::new(SignalVector::zero(), 0);
        // The receipt was already consumed elsewhere: the confirm reports
        // status 0 (missing/already confirmed) -> NO reputation event, and
        // the receipt reports the outcome as a no-op.
        let cal = static_calibration(0, 0);
        let engine =
            RiskEngine::new(store, classifier(), policy(), keys()).with_calibration(cal.clone());
        let ctx = RiskContext::new(
            1,
            "203.0.113.27".parse().unwrap(),
            None,
            None,
            RiskEventKind::ConfirmedAbuse,
            NetworkFlags::default(),
            ResourcePressure::default(),
        );
        let receipt = engine
            .confirmed_abuse(ctx, None, "decision-x", None)
            .unwrap();
        // The calibrator was still asked to confirm...
        assert_eq!(cal.confirmed.lock().unwrap().len(), 1);
        // ...but the state store was never touched: a retry can no longer
        // amplify ConfirmedAbuse.
        assert_eq!(engine.store.calls.load(Ordering::Relaxed), 0);
        assert!(receipt.is_duplicate);
        assert_eq!(receipt.signals, SignalVector::zero());
        assert_eq!(receipt.event_id.len(), 32);
    }

    #[test]
    fn engine_confirm_outcome_delegates_and_validates() {
        let store = MockStore::new(SignalVector::zero(), 0);
        let cal = static_calibration(0, 1);
        let engine =
            RiskEngine::new(store, classifier(), policy(), keys()).with_calibration(cal.clone());
        assert_eq!(
            engine.confirm_outcome("", true, None),
            Err(RiskError::EmptyDecisionId)
        );
        assert_eq!(
            engine
                .confirm_outcome("decision-z", false, Some(10.0))
                .unwrap(),
            1,
            "the engine delegates to the calibrator (weight included)"
        );
        assert_eq!(
            cal.confirmed.lock().unwrap()[0],
            ("decision-z".to_string(), false, Some(10.0))
        );
        // Without a calibration store the always-on ledger is flipped by
        // the store: an unknown decision is status 0 (never an error).
        let plain = RiskEngine::new(
            MockStore::new(SignalVector::zero(), 0),
            classifier(),
            policy(),
            keys(),
        );
        assert_eq!(plain.confirm_outcome("decision-z", true, None).unwrap(), 0);
        // A registered decision confirms through the store exactly once.
        assert!(plain
            .store
            .register_outcome("decision-z", 1, 1, 100)
            .unwrap());
        assert_eq!(plain.confirm_outcome("decision-z", true, None).unwrap(), 1);
        assert_eq!(plain.confirm_outcome("decision-z", true, None).unwrap(), 0);
    }

    #[test]
    fn confirmed_outcomes_require_a_decision_id() {
        let store = MockStore::new(SignalVector::zero(), 0);
        let engine = RiskEngine::new(store, classifier(), policy(), keys());
        let ctx = |event| {
            RiskContext::new(
                1,
                "203.0.113.27".parse().unwrap(),
                None,
                None,
                event,
                NetworkFlags::default(),
                ResourcePressure::default(),
            )
        };
        assert_eq!(
            engine.confirmed_legitimate(ctx(RiskEventKind::ConfirmedLegitimate), None, "", None),
            Err(RiskError::EmptyDecisionId)
        );
        assert_eq!(
            engine.confirmed_abuse(ctx(RiskEventKind::ConfirmedAbuse), None, "", None),
            Err(RiskError::EmptyDecisionId)
        );
        // An unregistered decision cannot be confirmed: status 0 -> the
        // reputation event is NOT booked (the receipt reports a no-op).
        let receipt = engine
            .confirmed_legitimate(
                ctx(RiskEventKind::ConfirmedLegitimate),
                None,
                "decision-y",
                None,
            )
            .unwrap();
        assert!(receipt.is_duplicate);
        assert_eq!(engine.store.calls.load(Ordering::Relaxed), 0);
        // record_feedback rejects Confirmed* outright.
        assert_eq!(
            engine.record_feedback(
                RiskEventKind::ConfirmedLegitimate,
                ctx(RiskEventKind::ConfirmedLegitimate),
                None,
                None,
            ),
            Err(RiskError::ConfirmationApiRequired)
        );
    }

    #[test]
    fn first_confirmation_gates_reputation_and_retries_cannot_amplify() {
        let store = CapturingStore(Mutex::new(Vec::new()), OutcomeLedger::default());
        // The mock models a live receipt: the first confirm returns status 1
        // (recorded), every retry returns 0 (already consumed).
        let cal = static_calibration(0, 1);
        let engine =
            RiskEngine::new(store, classifier(), policy(), keys()).with_calibration(cal.clone());
        let ctx = |event| {
            RiskContext::new(
                1,
                "203.0.113.27".parse().unwrap(),
                None,
                None,
                event,
                NetworkFlags::default(),
                ResourcePressure::default(),
            )
        };

        // First confirmation: calibration records AND the reputation event
        // is booked once.
        let receipt = engine
            .confirmed_abuse(
                ctx(RiskEventKind::ConfirmedAbuse),
                None,
                "decision-amp",
                None,
            )
            .unwrap();
        assert!(!receipt.is_duplicate);
        {
            let captured = engine.store.0.lock().unwrap();
            assert_eq!(captured.len(), 1, "exactly one reputation event");
            assert_eq!(captured[0].event, RiskEventKind::ConfirmedAbuse);
        }

        // Retry of the same decision: status 0 -> the reputation event must
        // NOT be booked again (retries can no longer amplify).
        let receipt = engine
            .confirmed_abuse(
                ctx(RiskEventKind::ConfirmedAbuse),
                None,
                "decision-amp",
                None,
            )
            .unwrap();
        assert!(receipt.is_duplicate, "the retry reports a no-op");
        let captured = engine.store.0.lock().unwrap();
        assert_eq!(
            captured.len(),
            1,
            "a retry must never book a second reputation event"
        );
    }

    #[test]
    fn status_two_confirmation_mutates_reputation_once_without_calibration_feed() {
        let store = CapturingStore(Mutex::new(Vec::new()), OutcomeLedger::default());
        // Status 2 = first confirmation, deliberately unsampled: the
        // reputation event is authorized exactly once, calibration is
        // untouched (the calibration.rs suite asserts the bucket stays
        // empty for status 2).
        let cal = static_calibration(0, 2);
        let engine =
            RiskEngine::new(store, classifier(), policy(), keys()).with_calibration(cal.clone());
        let ctx = RiskContext::new(
            1,
            "203.0.113.27".parse().unwrap(),
            None,
            None,
            RiskEventKind::ConfirmedLegitimate,
            NetworkFlags::default(),
            ResourcePressure::default(),
        );
        let receipt = engine
            .confirmed_legitimate(ctx, None, "decision-u", None)
            .unwrap();
        assert!(!receipt.is_duplicate);
        let captured = engine.store.0.lock().unwrap();
        assert_eq!(captured.len(), 1);
        assert_eq!(captured[0].event, RiskEventKind::ConfirmedLegitimate);
        assert_eq!(cal.confirmed.lock().unwrap().len(), 1);
    }

    #[test]
    fn confirm_correction_flips_the_ledger_through_the_calibrator() {
        let store = CapturingStore(Mutex::new(Vec::new()), OutcomeLedger::default());
        let cal = static_calibration(0, 1);
        let engine =
            RiskEngine::new(store, classifier(), policy(), keys()).with_calibration(cal.clone());

        // Empty decision id is rejected up front.
        assert_eq!(
            engine.confirm_correction("", true, None),
            Err(RiskError::EmptyDecisionId)
        );

        // A first correction of legitimate=true (the mistaken outcome was
        // abuse, corrected to legitimate) applies once...
        assert!(
            engine.confirm_correction("decision-c", true, None).unwrap(),
            "the ledger flip applies on the first correction"
        );
        assert!(cal
            .corrected
            .lock()
            .unwrap()
            .contains(&("decision-c".to_string(), true)));
        // ...and a repeat to the same outcome is a no-op (the ledger
        // already carries it). NO reputation event is ever booked — the
        // correction never touches the state store.
        assert!(!engine.confirm_correction("decision-c", true, None).unwrap());
        assert_eq!(
            engine.store.0.lock().unwrap().len(),
            0,
            "the ledger correction must not book reputation events"
        );

        // The opposite direction applies independently.
        assert!(engine
            .confirm_correction("decision-d", false, None)
            .unwrap());
    }

    #[test]
    fn no_calibration_confirmed_outcomes_work_through_the_store_ledger() {
        // The architecture: the outcome ledger is always on and independent
        // of calibration. Without a calibration store the engine registers
        // the pending ledger at decision time and the confirmed* wrappers
        // flip it through the store: ConfirmedLegitimate/ConfirmedAbuse
        // work identically with or without calibration.
        let store = MockStore::new(SignalVector::zero(), 0);
        let engine = RiskEngine::new(store, classifier(), policy(), keys());
        let ctx = |event| {
            RiskContext::new(
                1,
                "203.0.113.27".parse().unwrap(),
                None,
                None,
                event,
                NetworkFlags::default(),
                ResourcePressure::default(),
            )
        };

        // Decision time: the store registers the pending ledger entry.
        let decision = engine
            .assess_pre_issue(context(), Some("nocal-1".to_string()))
            .unwrap();
        let id = decision.decision_id.clone();
        // The registration is once-only (a retried decision cannot
        // overwrite its ledger).
        assert!(!engine.store.outcomes.register(&id));

        // First confirmation: the store flips the ledger -> status 1, the
        // reputation event is booked.
        let receipt = engine
            .confirmed_abuse(
                ctx(RiskEventKind::ConfirmedAbuse),
                Some("nocal-fb".to_string()),
                &id,
                None,
            )
            .unwrap();
        assert!(!receipt.is_duplicate);
        assert_eq!(engine.store.calls.load(Ordering::Relaxed), 2); // assess + reputation event

        // Retry: status 0 -> no-op, no second reputation event.
        let receipt = engine
            .confirmed_abuse(
                ctx(RiskEventKind::ConfirmedAbuse),
                Some("nocal-fb2".to_string()),
                &id,
                None,
            )
            .unwrap();
        assert!(receipt.is_duplicate);
        assert_eq!(engine.store.calls.load(Ordering::Relaxed), 2);

        // Correction without calibration flips the ledger: legitimate=true
        // corrects the abuse confirmation (L <-> A).
        assert!(engine.confirm_correction(&id, true, None).unwrap());
        assert!(
            !engine.confirm_correction(&id, true, None).unwrap(),
            "a ledger already carrying the target outcome must not flip"
        );
        // A resolved (non-pending) ledger is exactly-once: confirming the
        // corrected outcome again is a no-op, never a second reputation
        // event.
        let receipt = engine
            .confirmed_legitimate(ctx(RiskEventKind::ConfirmedLegitimate), None, &id, None)
            .unwrap();
        assert!(receipt.is_duplicate);
        assert_eq!(engine.store.calls.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn record_feedback_rejects_confirmation_events() {
        let store = MockStore::new(SignalVector::zero(), 0);
        let engine = RiskEngine::new(store, classifier(), policy(), keys());
        let ctx = |event| {
            RiskContext::new(
                1,
                "203.0.113.27".parse().unwrap(),
                None,
                None,
                event,
                NetworkFlags::default(),
                ResourcePressure::default(),
            )
        };
        assert_eq!(
            engine.record_feedback(
                RiskEventKind::ConfirmedLegitimate,
                ctx(RiskEventKind::ConfirmedLegitimate),
                None,
                Some("d-1".to_string()),
            ),
            Err(RiskError::ConfirmationApiRequired),
            "record_feedback must reject ConfirmedLegitimate even with a decision_id"
        );
        assert_eq!(
            engine.record_feedback(
                RiskEventKind::ConfirmedAbuse,
                ctx(RiskEventKind::ConfirmedAbuse),
                None,
                Some("d-2".to_string()),
            ),
            Err(RiskError::ConfirmationApiRequired)
        );
        // Non-confirmation events keep flowing.
        assert!(engine
            .record_feedback(
                RiskEventKind::ChallengeIssued,
                ctx(RiskEventKind::ChallengeIssued),
                None,
                None,
            )
            .is_ok());
    }

    #[test]
    fn redis_outcome_ledger_works_without_calibration() {
        let Some(raw_url) = std::env::var("RISK_REDIS_URL")
            .ok()
            .filter(|u| !u.is_empty())
        else {
            eprintln!("skipping Redis ledger test: RISK_REDIS_URL not set");
            return;
        };
        let url = if let Some(rest) = raw_url.strip_prefix("tcp://") {
            format!("redis://{rest}")
        } else {
            raw_url
        };
        let mut suffix = [0u8; 4];
        thread_rng().fill_bytes(&mut suffix);
        let store = redis::RedisRiskStateStore::new(
            ::redis::Client::open(url.clone()).expect("url parses"),
            &format!("led{}", hex::encode(suffix)),
        );
        let engine = RiskEngine::new(store, classifier(), policy(), keys());

        // Decision time registers the pending ledger (no calibration!).
        let decision = engine
            .assess_pre_issue(context(), Some("led-e2e".to_string()))
            .unwrap();
        let mut conn = ::redis::Client::open(url.clone())
            .expect("url parses")
            .get_connection()
            .expect("connection");
        let key = engine.store.outcome_ledger_key(&decision.decision_id);
        let raw: String = conn.get(&key).expect("get");
        let value: serde_json::Value = serde_json::from_str(&raw).expect("json");
        assert_eq!(value["o"], "P");

        // First confirmation flips the ledger and books reputation exactly
        // once; the retry is a duplicate no-op.
        let ip: IpAddr = "203.0.113.27".parse().unwrap();
        let fb = |event: RiskEventKind| {
            RiskContext::new(
                1,
                ip,
                None,
                None,
                event,
                NetworkFlags::default(),
                ResourcePressure::default(),
            )
        };
        let first = engine
            .confirmed_abuse(
                fb(RiskEventKind::ConfirmedAbuse),
                None,
                &decision.decision_id,
                None,
            )
            .unwrap();
        assert!(!first.is_duplicate);
        let retry = engine
            .confirmed_abuse(
                fb(RiskEventKind::ConfirmedAbuse),
                None,
                &decision.decision_id,
                None,
            )
            .unwrap();
        assert!(retry.is_duplicate);
        let raw: String = conn.get(&key).expect("get");
        let value: serde_json::Value = serde_json::from_str(&raw).expect("json");
        assert_eq!(value["o"], "A");

        // Correction without calibration flips the ledger to L.
        assert!(engine
            .confirm_correction(&decision.decision_id, true, None)
            .unwrap());
        let raw: String = conn.get(&key).expect("get");
        let value: serde_json::Value = serde_json::from_str(&raw).expect("json");
        assert_eq!(value["o"], "L");
        assert!(!engine
            .confirm_correction(&decision.decision_id, true, None)
            .unwrap());
    }

    // ── End-to-end with the Redis store (skipped unless the Redis test
    // URL is set) ──────────────────────────────────────────────────────
    #[test]
    fn process_cap_caps_admissions_per_process() {
        // In-process fixed-window cap: 5 admissions fit the window, the 6th
        // and 7th must be denied with HardRateLimit. Needs Redis for the
        // store backend; skipped unless the Redis test URL is set.
        let Some(raw_url) = std::env::var("RISK_REDIS_URL")
            .ok()
            .filter(|u| !u.is_empty())
        else {
            eprintln!("skipping process limiter test: RISK_REDIS_URL not set");
            return;
        };
        let url = if let Some(rest) = raw_url.strip_prefix("tcp://") {
            format!("redis://{rest}")
        } else {
            raw_url
        };
        let mut suffix = [0u8; 4];
        thread_rng().fill_bytes(&mut suffix);
        let namespace = format!("gl{}", hex::encode(suffix));
        let store = redis::RedisRiskStateStore::new(
            ::redis::Client::open(url).expect("url parses"),
            &namespace,
        );
        let engine = RiskEngine::with_components(
            store,
            classifier(),
            policy(),
            keys(),
            breaker::CircuitBreaker::default(),
            ProcessEmergencyCap::with_capacity_and_ramp(5, 0.0),
        );

        let mut allowed = 0;
        let mut denied = 0;
        for i in 0..7u32 {
            let decision = engine
                .assess_pre_issue(context(), Some(format!("gl-{i}")))
                .unwrap();
            if decision.has_reason(RiskReason::HardRateLimit) {
                denied += 1;
            } else {
                allowed += 1;
            }
        }
        assert_eq!(allowed, 5, "exactly the window capacity is allowed");
        assert_eq!(denied, 2, "the overflow admissions are denied");
    }

    #[test]
    fn global_pressure_disabled_zeroes_signal_level_and_cooldown() {
        let now = now_ms();
        let vector = SignalVector {
            global_pressure: 500,
            ..Default::default()
        };
        // Disabled: the signal is zeroed (score stays at base 100 despite
        // the 170-weight channel), the level is 0 (no floor, no cooldown
        // deny even though the store reported level 4 + a future hold).
        let engine = RiskEngine::new(
            MockStore::with_cooldown(vector, 4, now + 5_000),
            classifier(),
            policy(),
            keys(),
        )
        .with_global_pressure(false);
        let decision = engine.assess_pre_issue(context(), None).unwrap();
        assert_eq!(decision.global_level, 0);
        assert_eq!(decision.score, 100);
        assert!(!decision.has_reason(RiskReason::Cooldown));
        assert_ne!(decision.action, RiskAction::Deny);
        assert_eq!(engine.current_global_level(), 0);

        // Enabled (the default): level 4 + a future cooldown is a Cooldown
        // deny, and the pressure signal contributes to the score.
        let engine = RiskEngine::new(
            MockStore::with_cooldown(vector, 4, now + 5_000),
            classifier(),
            policy(),
            keys(),
        );
        let decision = engine.assess_pre_issue(context(), None).unwrap();
        assert_eq!(decision.global_level, 4);
        assert_eq!(decision.score, 185); // 100 + 500 * 170 / 1000
        assert!(decision.has_reason(RiskReason::Cooldown));
        assert_eq!(decision.action, RiskAction::Deny);
        assert_eq!(engine.current_global_level(), 4);
    }

    #[test]
    fn redis_engine_end_to_end() {
        let Some(raw_url) = std::env::var("RISK_REDIS_URL")
            .ok()
            .filter(|u| !u.is_empty())
        else {
            eprintln!("skipping Redis engine test: RISK_REDIS_URL not set");
            return;
        };
        let url = if let Some(rest) = raw_url.strip_prefix("tcp://") {
            format!("redis://{rest}")
        } else {
            raw_url
        };
        let client = ::redis::Client::open(url.clone()).expect("url parses");
        let mut suffix = [0u8; 4];
        thread_rng().fill_bytes(&mut suffix);
        let store = redis::RedisRiskStateStore::new(client, &format!("e2e{}", hex::encode(suffix)));
        let classifier = classifier();
        let flags = classifier.classify("203.0.113.27".parse().unwrap());
        let engine = RiskEngine::new(store, classifier, policy(), keys());

        let mut ctx = context();
        ctx.network_flags = flags;
        let first = engine.assess_pre_issue(ctx, None).unwrap();
        assert!(first.score <= 1000);
        assert_eq!(first.policy_version, 3);
        assert_eq!(first.decision_id.len(), 32);

        // Feed outcomes via record_feedback and confirm the state reacts.
        let ip: IpAddr = "203.0.113.27".parse().unwrap();
        let feedback_ctx = |event: RiskEventKind| {
            RiskContext::new(
                1,
                ip,
                None,
                None,
                event,
                NetworkFlags::default(),
                ResourcePressure::default(),
            )
        };
        let _ = engine
            .record_feedback(
                RiskEventKind::ChallengeIssued,
                feedback_ctx(RiskEventKind::ChallengeIssued),
                Some("e2e-1".to_string()),
                None,
            )
            .unwrap();
        let _ = engine
            .record_feedback(
                RiskEventKind::SolveSuccess,
                feedback_ctx(RiskEventKind::SolveSuccess),
                Some("e2e-2".to_string()),
                None,
            )
            .unwrap();
        let _ = engine
            .record_feedback(
                RiskEventKind::ProtectedActionFailure,
                feedback_ctx(RiskEventKind::ProtectedActionFailure),
                Some("e2e-3".to_string()),
                None,
            )
            .unwrap();
        let _ = engine
            .confirmed_abuse(
                feedback_ctx(RiskEventKind::ConfirmedAbuse),
                Some("e2e-4".to_string()),
                first.decision_id.as_str(),
                None,
            )
            .unwrap();
        let decision = engine.assess_pre_issue(context(), None).unwrap();
        assert!(decision.score <= 1000);
        // Hosting is a 600 network risk: it contributes weight but does NOT
        // trip the >= 900 hard deny (that override is reserved for blocked
        // sources). A fresh source IP on the same namespace keeps the
        // velocity clean so the hosting assessment cannot be denied by
        // other channels.
        let hosting_ctx = RiskContext::new(
            1,
            "198.51.100.5".parse().unwrap(),
            None,
            None,
            RiskEventKind::PreIssue,
            NetworkFlags {
                known_hosting: true,
                ..Default::default()
            },
            ResourcePressure::default(),
        );
        let hosting = engine.assess_pre_issue(hosting_ctx, None).unwrap();
        assert_ne!(
            hosting.action,
            RiskAction::Deny,
            "hosting (600) must not hard-deny"
        );

        // Blocked sources still hard-deny through the same policy override.
        let blocked_classifier = CidrNetworkClassifier::from_entries(vec![(
            CidrEntry::parse("203.0.113.0/24").unwrap(),
            NetworkFlags {
                local_risk_bucket: 255,
                ..Default::default()
            },
        )]);
        let blocked_store = redis::RedisRiskStateStore::new(
            ::redis::Client::open(url).expect("url parses"),
            &format!("e2eb{}", hex::encode(suffix)),
        );
        let blocked_engine = RiskEngine::new(blocked_store, blocked_classifier, policy(), keys());
        let mut blocked_ctx = context();
        blocked_ctx.network_flags = NetworkFlags {
            local_risk_bucket: 255,
            ..Default::default()
        };
        let denied = blocked_engine.assess_pre_issue(blocked_ctx, None).unwrap();
        assert!(denied.has_reason(RiskReason::LocalNetworkRisk));
        assert_eq!(denied.action, RiskAction::Deny);
    }
}
