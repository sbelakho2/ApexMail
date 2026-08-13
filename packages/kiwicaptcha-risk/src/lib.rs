//! KiwiCaptcha Adaptive Risk Engine (risk-v1 protocol).
//!
//! One pipeline turns a [`RiskContext`] into a [`RiskDecision`]:
//! emergency cap (one per-process window; the distributed Redis source
//! limiter handles per-source limits) → observation (epoch-scoped ephemeral
//! pseudonyms) → circuit breaker → state store (canonical Lua via EVALSHA)
//! → scorer (with calibration bias) → policy → top contributor reasons.
//! Backend failure degrades instead of failing the request.

pub mod action;
pub mod breaker;
pub mod calibration;
pub mod context;
pub mod event;
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
use crate::context::RiskContext;
use crate::event::{normalize_idempotency_key, RiskEventKind, RiskObservation};
use crate::identity::RiskIdentityFactory;
use crate::keys::RiskKeys;
use crate::metrics::Metrics;
use crate::network::NetworkClassifier;
use crate::policy::{RiskPolicy, RiskReason};
use crate::score::score as compute_score;
use crate::signals::SignalVector;
use crate::store::{Observed, RiskStateStore};

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
}

/// Immutable risk decision produced by the engine.
///
/// Reasons are internal only (never exposed to the client) and capped at 4
/// (policy overrides first, then top contributor reasons). `decision_id`
/// identifies the decision for outcome calibration (see
/// [`RiskEngine::record_feedback`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RiskDecision {
    pub score: u16,
    pub action: RiskAction,
    pub reasons: [Option<RiskReason>; 4],
    pub policy_version: u32,
    pub global_level: u8,
    pub retry_after_ms: Option<u32>,
    pub band: u8,
    /// Random 16-byte hex id; every decision registers a calibration
    /// receipt under it.
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
        let mut state = serializer.serialize_struct("RiskDecision", 7)?;
        state.serialize_field("score", &self.score)?;
        state.serialize_field("action", self.action.as_str())?;
        state.serialize_field("reasons", &reasons)?;
        state.serialize_field("policy_version", &self.policy_version)?;
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

/// Raw saturation values passed to the Lua script, in its ARGV order
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
    /// The saturations in the Lua ARGV order (indices 8..18 of ARGV).
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
/// observations per second PER PROCESS (default 10000), enforced BEFORE any
/// state backend is touched.
///
/// This is deliberately a PER-PROCESS cap (a `VecDeque` of timestamps in
/// this process's memory); no cross-process synchronization is performed.
/// It is the last line of defense when the Redis/state controls fail — it
/// bounds how much work one process can push at a degraded backend so a
/// burst cannot saturate this process's Redis connection. Per-source (and
/// per-identity) throttling belongs to the DISTRIBUTED keyed layer: the
/// Redis source velocity channels (`source_fast`/`source_slow` in risk-v1)
/// and the policy's per-source overrides. When the window is saturated the
/// engine denies immediately (HardRateLimit) instead of spending time/state
/// on the request.
pub struct ProcessEmergencyCap {
    process_per_second: u64,
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

    /// Builds a cap with the default rate (10000 admissions per second,
    /// per process).
    pub fn new() -> ProcessEmergencyCap {
        ProcessEmergencyCap::with_capacity(Self::DEFAULT_PROCESS_PER_SECOND)
    }

    /// Builds a cap with an explicit admissions-per-second rate.
    ///
    /// # Panics
    ///
    /// Panics if `process_per_second < 1`.
    pub fn with_capacity(process_per_second: u64) -> ProcessEmergencyCap {
        assert!(process_per_second >= 1, "process_per_second must be >= 1");
        ProcessEmergencyCap {
            process_per_second,
            stamps: Mutex::new(VecDeque::new()),
            start: Instant::now(),
        }
    }

    /// The admissions-per-second cap.
    pub fn process_per_second(&self) -> u64 {
        self.process_per_second
    }

    /// True when the process may proceed within the current window. Also
    /// marks the current moment as consumed. Expired entries are dequeued
    /// from the FRONT (amortized O(1) per admission).
    pub fn allow(&self) -> bool {
        let now = self.start.elapsed().as_secs_f64();
        let cutoff = now - 1.0;
        let mut stamps = self.stamps.lock().unwrap_or_else(|p| p.into_inner());
        while stamps.front().is_some_and(|t| *t <= cutoff) {
            stamps.pop_front();
        }
        if stamps.len() as u64 >= self.process_per_second {
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
        stamps.len() as u64 >= self.process_per_second
    }
}

/// The adaptive risk engine.
///
/// `classifier` and `keys` are retained as owned configuration (the
/// classifier is passed by the caller for its observation pipeline; the
/// keys feed the identity factory) — the engine itself uses the derived
/// [`RiskIdentityFactory`].
pub struct RiskEngine<S: RiskStateStore, N: NetworkClassifier> {
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
}

impl<S: RiskStateStore, N: NetworkClassifier> RiskEngine<S, N> {
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
    /// registers a receipt, the scope bias is applied to the score, and
    /// confirmed outcomes consume their receipts. All failures are silent.
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
    /// The emergency cap is checked FIRST (the single per-process window);
    /// on a cap hit the engine returns a HardRateLimit decision without
    /// touching the store. `idempotency_key` becomes the event_id (dedupe
    /// key) via [`normalize_idempotency_key`]; `None` draws a random 16-byte
    /// hex id. Every decision gets a fresh `decision_id` and registers a
    /// calibration receipt.
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
        if !self.limiter.allow() {
            self.metrics.incr("denied:limiter");
            let decision = RiskDecision {
                score: 1000,
                action: RiskAction::Deny,
                reasons: [Some(RiskReason::HardRateLimit), None, None, None],
                policy_version: self.policy.version,
                global_level: self.current_global_level(),
                retry_after_ms: Some(1000),
                band: 10,
                decision_id: String::new(),
            };
            self.record_decision_metrics(ctx.scope, &decision);
            return Ok(self.finalize_decision(ctx.scope, decision));
        }
        self.assess_inner(ctx, idempotency_key)
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

    /// Re-assesses a request WITHOUT any emergency-cap check: identical
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
        self.assess_inner(ctx, idempotency_key)
    }

    /// The shared assessment pipeline (no limiter); only
    /// [`RiskEngine::assess_pre_issue`] gates on the emergency caps.
    fn assess_inner(
        &self,
        ctx: RiskContext<'_>,
        idempotency_key: Option<String>,
    ) -> Result<RiskDecision, RiskError> {
        let now_ms = now_ms();
        let observation = self.build_observation(&ctx, now_ms, idempotency_key)?;

        if self.breaker.is_open() {
            self.metrics.incr("degraded:breaker");
            let decision = self
                .policy
                .degraded_decision(ctx.scope, self.current_global_level());
            self.record_decision_metrics(ctx.scope, &decision);
            return Ok(self.finalize_decision(ctx.scope, decision));
        }

        let start = Instant::now();
        let result = self.store.observe(&observation);
        match result {
            Err(_) => {
                self.breaker.record_failure();
                self.metrics.incr("degraded:store");
                let decision = self
                    .policy
                    .degraded_decision(ctx.scope, self.current_global_level());
                self.record_decision_metrics(ctx.scope, &decision);
                Ok(self.finalize_decision(ctx.scope, decision))
            }
            Ok(observed) => {
                self.metrics
                    .add_latency_us("store:observe", start.elapsed().as_micros() as u64);
                self.breaker.record_success();
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
                    // 0, 1000) BEFORE band mapping (same sign, same clamp
                    // as PHP).
                    let bias = calibration.bias_for_scope(ctx.scope, now_ms as i64);
                    base = (base as i32 + bias).clamp(0, 1000) as u16;
                }
                let score = compute_score(base, &vector, &self.policy.weights);
                let mut decision = self.policy.decide(
                    ctx.scope,
                    score,
                    &vector,
                    &ctx.resources,
                    global_level,
                    now_ms,
                    cooldown_until_ms,
                );
                self.merge_contributor_reasons(&mut decision, &vector);
                self.record_decision_metrics(ctx.scope, &decision);
                Ok(self.finalize_decision(ctx.scope, decision))
            }
        }
    }

    /// Outcome feedback path (e.g. a post-solve protected action): stores
    /// the event and returns an [`EventReceipt`]. NEVER runs the limiter
    /// and NEVER calls [`RiskEngine::assess_pre_issue`].
    ///
    /// When the event is ConfirmedLegitimate/ConfirmedAbuse AND
    /// `decision_id` is given, the calibration receipt of that decision is
    /// confirmed FIRST (one atomic script invocation — consume receipt +
    /// record the exact score into the scope's hourly bucket), and the
    /// reputation event is recorded ONLY when the confirmation is the
    /// FIRST one (status 1 = recorded, status 2 = consumed-but-unsampled).
    /// A retry that finds the receipt already consumed (status 0) is a
    /// no-op: the receipt reports `is_duplicate = true` with empty signals
    /// and NO reputation event is booked, so retries can never amplify a
    /// ConfirmedAbuse. A calibration backend failure is silent and also
    /// skips the reputation event (the receipt survives, so the caller can
    /// retry and the outcome is then applied exactly once). Calibration is
    /// best-effort throughout.
    ///
    /// # Errors
    ///
    /// [`RiskError::InvalidIdempotencyKey`] when the caller key exceeds the
    /// 4096-byte contract limit.
    pub fn record_feedback(
        &self,
        event: RiskEventKind,
        ctx: RiskContext<'_>,
        idempotency_key: Option<String>,
        decision_id: Option<String>,
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
                // FIRST the atomic calibrator confirm. REPUTATION GATING:
                // the reputation event is booked only on the FIRST
                // confirmation (status 1 or 2); status 0 (missing/already
                // consumed) and backend errors book nothing — the receipt
                // survives an error, so a retry applies the outcome exactly
                // once instead of amplifying it.
                match self.confirm_outcome(&receipt_id, legitimate, None) {
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

    /// Confirms the outcome of a previously assessed decision: one atomic
    /// calibrator invocation that consumes the decision's receipt and
    /// records the exact score into the scope's hourly bucket (or discards
    /// it when the receipt is missing/already consumed/unsampled).
    ///
    /// Returns the SHARED accepted-outcome status (wire contract with PHP):
    /// `0` nothing consumed (missing / already confirmed / corrupt /
    /// unsampled-discard), `1` FIRST confirmation with calibration
    /// recorded, `2` FIRST confirmation, deliberately unsampled. Only
    /// statuses 1 and 2 authorize the first-party reputation event (see
    /// [`RiskEngine::record_feedback`]); the reputation event itself is
    /// booked separately. `weight` is the inverse sampling probability for
    /// weighted sampling (default 1.0).
    ///
    /// # Errors
    ///
    /// [`RiskError::EmptyDecisionId`] when `decision_id` is empty;
    /// [`RiskError::Calibration`] when the calibration backend fails.
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
            None => Ok(0),
        }
    }

    /// Compensating-state correction: records the OPPOSITE reputation
    /// event for a decision AT MOST ONCE, guarded by a SET NX reservation
    /// in the calibration store
    /// (`{kiwi:<ns>}:cal:corrected:<hex(sha256(decision_id))>` EX
    /// `receipt_ttl_secs` — see [`CalibrationStore::reserve_correction`]).
    ///
    /// `legitimate` mirrors the (mistaken) FIRST confirmed outcome — a
    /// first confirmation of `legitimate = true` (trust) is compensated by
    /// a ConfirmedAbuse event and vice versa. The compensation lands in
    /// per-decision, decision-anchored pseudonyms (the original identity
    /// context is unrecoverable once the receipt is consumed) and is
    /// additionally dedupe-guarded by a deterministic event_id, so it can
    /// never re-apply or amplify a real visitor. Calibration consumes only
    /// the first confirmed outcome: the correction NEVER touches receipts
    /// or hourly buckets (`weight` is accepted for signature parity with
    /// [`RiskEngine::confirm_outcome`] and unused).
    ///
    /// Returns `Ok(true)` when the compensation was applied (or attempted
    /// best-effort — a state-store failure is silent, and the reservation
    /// stays consumed so a retry cannot double-apply), `Ok(false)` when
    /// the decision was already corrected or no calibration store is
    /// attached (the guard cannot be enforced without its namespace).
    ///
    /// # Errors
    ///
    /// [`RiskError::EmptyDecisionId`] when `decision_id` is empty;
    /// [`RiskError::Calibration`] when the correction guard backend fails.
    pub fn confirm_correction(
        &self,
        decision_id: &str,
        legitimate: bool,
        _weight: Option<f64>,
    ) -> Result<bool, RiskError> {
        if decision_id.is_empty() {
            return Err(RiskError::EmptyDecisionId);
        }
        let Some(calibration) = &self.calibration else {
            return Ok(false);
        };
        if !calibration
            .reserve_correction(decision_id)
            .map_err(|e| RiskError::Calibration(e.to_string()))?
        {
            return Ok(false);
        }
        let event = if legitimate {
            RiskEventKind::ConfirmedAbuse
        } else {
            RiskEventKind::ConfirmedLegitimate
        };
        let observation = self.correction_observation(decision_id, event);
        let _ = self.store.observe(&observation);
        Ok(true)
    }

    /// A deterministic, identity-free observation for a compensation
    /// event: source/subnet pseudonyms and the dedupe event_id are
    /// sha256-derived from the decision_id (distinct salts for the ±1
    /// epoch boundary keys so the rotated pseudonyms never collide), which
    /// isolates every correction's state mutation in its own keys and
    /// makes the event once-only even if the guard key expires.
    fn correction_observation(&self, decision_id: &str, event: RiskEventKind) -> RiskObservation {
        use sha2::{Digest, Sha256};
        let digest = |salt: &[u8]| -> String {
            let mut h = Sha256::new();
            h.update(salt);
            h.update(decision_id.as_bytes());
            hex::encode(h.finalize())
        };
        let now_ms = now_ms();
        let now_secs = (now_ms / 1000) as i64;
        RiskObservation {
            event,
            scope: 0,
            source_epoch: now_secs / self.source_epoch_secs as i64,
            source_id_prev: digest(b"kiwicaptcha:correction:srcp:"),
            source_id: digest(b"kiwicaptcha:correction:srcc:"),
            source_id_next: digest(b"kiwicaptcha:correction:srcn:"),
            subnet_epoch: now_secs / self.subnet_epoch_secs as i64,
            subnet_id_prev: digest(b"kiwicaptcha:correction:netp:"),
            subnet_id: digest(b"kiwicaptcha:correction:netc:"),
            subnet_id_next: digest(b"kiwicaptcha:correction:netn:"),
            session_id: None,
            principal_id: None,
            event_id: digest(b"kiwicaptcha:correction:evt:"),
            network_risk: 0,
            now_ms,
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
    /// the assessed decision (required — the calibration receipt is
    /// consumed under it).
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
    ) -> Result<EventReceipt, RiskError> {
        if decision_id.is_empty() {
            return Err(RiskError::EmptyDecisionId);
        }
        self.record_feedback(
            RiskEventKind::ConfirmedLegitimate,
            ctx,
            idempotency_key,
            Some(decision_id.to_string()),
        )
    }

    /// Records a confirmed-abuse outcome. `decision_id` is the id of the
    /// assessed decision (required — the calibration receipt is consumed
    /// under it).
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
    ) -> Result<EventReceipt, RiskError> {
        if decision_id.is_empty() {
            return Err(RiskError::EmptyDecisionId);
        }
        self.record_feedback(
            RiskEventKind::ConfirmedAbuse,
            ctx,
            idempotency_key,
            Some(decision_id.to_string()),
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

    /// Records a deployment-capacity hit (event 16): raises ONLY the
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

    /// Records a risk-denied outcome (event 17): a NO-OP in the state
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
        // become the lowercase hex of
        // HMAC-SHA256(event_key, pack('N', scope) . chr(event) . key) —
        // domain-separated per scope and event kind; empty/None draw a
        // random 16-byte id, and keys over 4096 bytes are rejected.
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

    /// Assigns the decision_id and registers the calibration receipt with
    /// the decision's EXACT risk score + the calibrator's sampling flag
    /// (silently on failure — never breaks issuance). A SAMPLED decision
    /// also books the assessment-time sample-total counter
    /// (`mark_sampled`), the resolution-gate denominator.
    fn finalize_decision(&self, scope: u32, mut decision: RiskDecision) -> RiskDecision {
        let mut id = [0u8; 16];
        thread_rng().fill_bytes(&mut id);
        decision.decision_id = hex::encode(id);
        if let Some(calibration) = &self.calibration {
            let sampled = calibration.sample();
            let _ = calibration.record_receipt(
                &decision.decision_id,
                scope,
                decision.band,
                decision.action,
                decision.score as u32,
                sampled,
            );
            if sampled {
                let _ = calibration.mark_sampled();
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
    use crate::store::RiskStoreError;
    use serde_json::json;
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

    struct MockStore {
        level: u8,
        vector: SignalVector,
        cooldown_until_ms: u64,
        calls: AtomicUsize,
        fail: bool,
        fail_calls: usize,
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

        fn last_global_level(&self) -> u8 {
            self.level
        }
    }

    struct CapturingStore(pub Mutex<Vec<RiskObservation>>);

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
        assert_eq!(decision.global_level, 2);
        assert_eq!(decision.band, 1);
        assert_eq!(decision.decision_id.len(), 32);

        let snapshot = engine.metrics().snapshot();
        assert!(snapshot.iter().any(|(k, _)| k == "decisions:1:sha18:1"));
        assert!(snapshot.iter().any(|(k, _)| k == "store:observe:count"));
    }

    #[test]
    fn observation_carries_epoch_scoped_pseudonyms() {
        let store = CapturingStore(Mutex::new(Vec::new()));
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
        let store = CapturingStore(Mutex::new(Vec::new()));
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

        // The same caller key under a DIFFERENT event kind (e.g. a feedback
        // wrapper) must never collide with the PreIssue dedupe id.
        let engine2 = RiskEngine::new(
            CapturingStore(Mutex::new(Vec::new())),
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
        let limiter = ProcessEmergencyCap::with_capacity(100);
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
        let small = ProcessEmergencyCap::with_capacity(2);
        assert!(small.allow());
        assert!(small.allow());
        assert!(!small.allow());
        assert!(small.is_open());
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
        let limiter = ProcessEmergencyCap::with_capacity(1);
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

        // ...but reassess NEVER consults the cap: the same saturated engine
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
        let store = CapturingStore(Mutex::new(Vec::new()));
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

        engine
            .record_feedback(
                RiskEventKind::ConfirmedLegitimate,
                ctx(RiskEventKind::ConfirmedLegitimate),
                None,
                None,
            )
            .unwrap();
        engine
            .record_feedback(
                RiskEventKind::ConfirmedAbuse,
                ctx(RiskEventKind::ConfirmedAbuse),
                None,
                None,
            )
            .unwrap();

        let events: Vec<RiskEventKind> = {
            let captured = engine.store.0.lock().unwrap();
            captured.iter().map(|o| o.event).collect()
        };
        assert_eq!(
            events,
            vec![
                RiskEventKind::ProtectedActionFailure,
                RiskEventKind::ConfirmedLegitimate,
                RiskEventKind::ConfirmedAbuse,
            ]
        );
        // Session/principal pseudonyms flow through the identity factory.
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
            .record_feedback(RiskEventKind::ConfirmedAbuse, sess_ctx, None, None)
            .unwrap();
        let captured = engine.store.0.lock().unwrap();
        assert_eq!(
            captured[3].session_id,
            Some(crate::identity::pseudonym(
                &keys().session,
                b"sess",
                0,
                b"sess"
            ))
        );
        assert_eq!(
            captured[3].principal_id,
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
        let store = CapturingStore(Mutex::new(Vec::new()));
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
        assert_eq!(json.as_object().unwrap().len(), 7);
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

    /// (decision_id, scope, band, action, score, sampled).
    type ReceiptLog = Vec<(String, u32, u8, RiskAction, u32, bool)>;

    struct StaticCalibration {
        bias: i32,
        confirm_status: u8,
        receipts: Mutex<ReceiptLog>,
        confirmed: Mutex<Vec<(String, bool, Option<f64>)>>,
        corrected: Mutex<Vec<String>>,
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
        ) -> Result<(), crate::calibration::CalibrationError> {
            self.receipts.lock().unwrap().push((
                decision_id.to_string(),
                scope,
                band,
                action,
                score,
                sampled,
            ));
            Ok(())
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
            // The mock models the real receipt lifecycle: the FIRST confirm
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

        fn sample(&self) -> bool {
            true
        }

        fn mark_sampled(&self) -> Result<(), crate::calibration::CalibrationError> {
            Ok(())
        }

        fn reserve_correction(
            &self,
            decision_id: &str,
        ) -> Result<bool, crate::calibration::CalibrationError> {
            let mut corrected = self.corrected.lock().unwrap();
            if corrected.iter().any(|id| id == decision_id) {
                return Ok(false);
            }
            corrected.push(decision_id.to_string());
            Ok(true)
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
            corrected: Mutex::new(Vec::new()),
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
            .record_feedback(
                RiskEventKind::ConfirmedLegitimate,
                ctx,
                None,
                Some("decision-x".to_string()),
            )
            .unwrap();
        assert!(!receipt.is_duplicate);
        // FIRST the atomic confirm (legitimate, default weight 1.0)...
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
        let receipt = engine.confirmed_abuse(ctx, None, "decision-x").unwrap();
        // The calibrator was still asked to confirm...
        assert_eq!(cal.confirmed.lock().unwrap().len(), 1);
        // ...but the state store was NEVER touched: a retry can no longer
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
        // Without a calibration store: status 0, never an error.
        let plain = RiskEngine::new(
            MockStore::new(SignalVector::zero(), 0),
            classifier(),
            policy(),
            keys(),
        );
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
            engine.confirmed_legitimate(ctx(RiskEventKind::ConfirmedLegitimate), None, ""),
            Err(RiskError::EmptyDecisionId)
        );
        assert_eq!(
            engine.confirmed_abuse(ctx(RiskEventKind::ConfirmedAbuse), None, ""),
            Err(RiskError::EmptyDecisionId)
        );
        // Without a calibration store the decision_id cannot be confirmed:
        // status 0 -> the reputation event is NOT booked (the receipt
        // reports a no-op; there is no receipt to consume).
        let receipt = engine
            .confirmed_legitimate(ctx(RiskEventKind::ConfirmedLegitimate), None, "decision-y")
            .unwrap();
        assert!(receipt.is_duplicate);
        assert_eq!(engine.store.calls.load(Ordering::Relaxed), 0);
        // Without a decision_id the outcome has no receipt to guard: the
        // reputation event proceeds (legacy wrapper semantics).
        let receipt = engine
            .record_feedback(
                RiskEventKind::ConfirmedLegitimate,
                ctx(RiskEventKind::ConfirmedLegitimate),
                None,
                None,
            )
            .unwrap();
        assert!(!receipt.is_duplicate);
    }

    #[test]
    fn first_confirmation_gates_reputation_and_retries_cannot_amplify() {
        let store = CapturingStore(Mutex::new(Vec::new()));
        // The mock models a live receipt: the FIRST confirm returns status 1
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
            .confirmed_abuse(ctx(RiskEventKind::ConfirmedAbuse), None, "decision-amp")
            .unwrap();
        assert!(!receipt.is_duplicate);
        {
            let captured = engine.store.0.lock().unwrap();
            assert_eq!(captured.len(), 1, "exactly one reputation event");
            assert_eq!(captured[0].event, RiskEventKind::ConfirmedAbuse);
        }

        // RETRY of the same decision: status 0 -> the reputation event must
        // NOT be booked again (retries can no longer amplify).
        let receipt = engine
            .confirmed_abuse(ctx(RiskEventKind::ConfirmedAbuse), None, "decision-amp")
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
        let store = CapturingStore(Mutex::new(Vec::new()));
        // Status 2 = FIRST confirmation, deliberately unsampled: the
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
            .confirmed_legitimate(ctx, None, "decision-u")
            .unwrap();
        assert!(!receipt.is_duplicate);
        let captured = engine.store.0.lock().unwrap();
        assert_eq!(captured.len(), 1);
        assert_eq!(captured[0].event, RiskEventKind::ConfirmedLegitimate);
        assert_eq!(cal.confirmed.lock().unwrap().len(), 1);
    }

    #[test]
    fn confirm_correction_applies_the_opposite_event_once() {
        let store = CapturingStore(Mutex::new(Vec::new()));
        let cal = static_calibration(0, 1);
        let engine =
            RiskEngine::new(store, classifier(), policy(), keys()).with_calibration(cal.clone());

        // Empty decision id is rejected up front.
        assert_eq!(
            engine.confirm_correction("", true, None),
            Err(RiskError::EmptyDecisionId)
        );

        // A first confirmation of legitimate=true (trust) is compensated by
        // the OPPOSITE event: ConfirmedAbuse.
        assert!(
            engine.confirm_correction("decision-c", true, None).unwrap(),
            "the winning reservation applies the compensation"
        );
        {
            let captured = engine.store.0.lock().unwrap();
            assert_eq!(captured.len(), 1);
            assert_eq!(captured[0].event, RiskEventKind::ConfirmedAbuse);
        }
        assert_eq!(&*cal.corrected.lock().unwrap(), &["decision-c".to_string()]);

        // Once-only: the second attempt finds the guard consumed.
        assert!(!engine.confirm_correction("decision-c", true, None).unwrap());
        assert_eq!(
            engine.store.0.lock().unwrap().len(),
            1,
            "the compensation must be recorded at most once"
        );

        // The opposite direction: a first confirmation of abuse
        // (legitimate=false) is compensated by ConfirmedLegitimate.
        assert!(engine
            .confirm_correction("decision-d", false, None)
            .unwrap());
        {
            let captured = engine.store.0.lock().unwrap();
            assert_eq!(captured.len(), 2);
            assert_eq!(captured[1].event, RiskEventKind::ConfirmedLegitimate);
        }

        // Without a calibration store there is no namespace to guard in:
        // the correction is refused (never applied).
        let plain = RiskEngine::new(
            CapturingStore(Mutex::new(Vec::new())),
            classifier(),
            policy(),
            keys(),
        );
        assert!(!plain.confirm_correction("decision-e", true, None).unwrap());
    }

    #[test]
    fn redis_correction_guard_is_once_only() {
        let Some(raw_url) = std::env::var("RISK_REDIS_URL")
            .ok()
            .filter(|u| !u.is_empty())
        else {
            eprintln!("skipping Redis correction test: RISK_REDIS_URL not set");
            return;
        };
        let url = if let Some(rest) = raw_url.strip_prefix("tcp://") {
            format!("redis://{rest}")
        } else {
            raw_url
        };
        let mut suffix = [0u8; 4];
        thread_rng().fill_bytes(&mut suffix);
        let calibration = std::sync::Arc::new(crate::calibration::RedisCalibrationStore::new(
            ::redis::Client::open(url.clone()).expect("url parses"),
            &format!("corr{}", hex::encode(suffix)),
        ));
        let engine = RiskEngine::new(
            CapturingStore(Mutex::new(Vec::new())),
            classifier(),
            policy(),
            keys(),
        )
        .with_calibration(calibration.clone());

        assert!(engine.confirm_correction("decision-r", true, None).unwrap());
        assert!(
            !engine.confirm_correction("decision-r", true, None).unwrap(),
            "the SET NX guard must hold across engine calls"
        );
        let captured = engine.store.0.lock().unwrap();
        assert_eq!(captured.len(), 1);
        assert_eq!(captured[0].event, RiskEventKind::ConfirmedAbuse);

        // The guard key exists with the receipt TTL (300 s default).
        use sha2::Digest;
        let mut h = sha2::Sha256::new();
        h.update(b"decision-r");
        let key = format!(
            "{{kiwi:{}}}:cal:corrected:{}",
            calibration.namespace(),
            hex::encode(h.finalize())
        );
        let mut conn = ::redis::Client::open(url.clone())
            .expect("url parses")
            .get_connection()
            .expect("connection");
        let ttl: i64 = ::redis::cmd("TTL").arg(&key).query(&mut conn).expect("ttl");
        assert!(
            (1..=300).contains(&ttl),
            "the guard must expire with the receipt TTL (got {ttl})"
        );
    }

    #[test]
    fn redis_engine_samples_the_total_counter() {
        let Some(raw_url) = std::env::var("RISK_REDIS_URL")
            .ok()
            .filter(|u| !u.is_empty())
        else {
            eprintln!("skipping Redis sampled-counter test: RISK_REDIS_URL not set");
            return;
        };
        let url = if let Some(rest) = raw_url.strip_prefix("tcp://") {
            format!("redis://{rest}")
        } else {
            raw_url
        };
        let mut suffix = [0u8; 4];
        thread_rng().fill_bytes(&mut suffix);
        // ppm 1_000_000: random-sample mode always draws a sample, so every
        // decision books the assessment-time total counter.
        let calibration =
            std::sync::Arc::new(crate::calibration::RedisCalibrationStore::with_options(
                ::redis::Client::open(url.clone()).expect("url parses"),
                &format!("samp{}", hex::encode(suffix)),
                1,
                150,
                10,
                300,
                crate::calibration::SamplingMode::RandomSample,
                1_000_000,
                0.80,
                1.0,
                2.0,
            ));
        let engine = RiskEngine::new(
            CapturingStore(Mutex::new(Vec::new())),
            classifier(),
            policy(),
            keys(),
        )
        .with_calibration(calibration.clone());

        for i in 0..3u32 {
            let decision = engine
                .assess_pre_issue(context(), Some(format!("samp-{i}")))
                .unwrap();
            assert_eq!(decision.decision_id.len(), 32);
        }
        let mut conn = ::redis::Client::open(url)
            .expect("url parses")
            .get_connection()
            .expect("connection");
        let total: i64 = ::redis::cmd("GET")
            .arg(format!(
                "{{kiwi:{}}}:cal:sample:total",
                calibration.namespace()
            ))
            .query(&mut conn)
            .expect("get");
        assert_eq!(
            total, 3,
            "every sampled assessment must INCR the sample-total counter"
        );
    }

    // ── End-to-end with the Redis store (skipped unless RISK_REDIS_URL) ──

    #[test]
    fn process_cap_caps_admissions_per_process() {
        // In-process fixed-window cap: 5 admissions fit the window, the 6th
        // and 7th must be denied with HardRateLimit. Needs Redis for the
        // store backend; skipped unless RISK_REDIS_URL is set.
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
            ProcessEmergencyCap::with_capacity(5),
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
