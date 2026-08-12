//! KiwiCaptcha Adaptive Risk Engine (risk-v1 protocol).
//!
//! One pipeline turns a [`RiskContext`] into a [`RiskDecision`]:
//! emergency caps (per-process source window + optional per-process global
//! window; the distributed Redis source limiter handles per-source limits)
//! → observation (epoch-scoped ephemeral pseudonyms) → circuit
//! breaker → state store (canonical Lua via EVALSHA) → scorer (with
//! calibration bias) → policy → top contributor reasons. Backend failure
//! degrades instead of failing the request.

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

use crate::action::RiskAction;
use crate::calibration::CalibrationStore;
use crate::context::RiskContext;
use crate::event::{RiskEventKind, RiskObservation};
use crate::identity::RiskIdentityFactory;
use crate::keys::RiskKeys;
use crate::metrics::Metrics;
use crate::network::NetworkClassifier;
use crate::policy::{RiskPolicy, RiskReason};
use crate::score::score as compute_score;
use crate::signals::SignalVector;
use crate::store::{Observed, RiskStateStore};

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
        let mut state = serializer.serialize_struct("RiskDecision", 8)?;
        state.serialize_field("score", &self.score)?;
        state.serialize_field("action", self.action.as_str())?;
        state.serialize_field("reasons", &reasons)?;
        state.serialize_field("policy_version", &self.policy_version)?;
        state.serialize_field("global_level", &self.global_level)?;
        state.serialize_field("retry_after_ms", &self.retry_after_ms)?;
        state.serialize_field("band", &self.band)?;
        state.serialize_field("decision_id", &self.decision_id)?;
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

/// In-process emergency guard: a fixed-window cap of 100 observations per
/// second PER PROCESS, enforced BEFORE any state backend is touched.
///
/// This is deliberately a PER-PROCESS cap (a `VecDeque` of timestamps in
/// this process's memory); no cross-process synchronization is performed —
/// the distributed Redis source limiter handles per-source limits across
/// processes. When the window is saturated the engine denies immediately
/// (HardRateLimit) instead of spending time/state on the request.
pub struct ProcessEmergencyCap {
    stamps: Mutex<VecDeque<u64>>,
    max_per_second: usize,
}

impl Default for ProcessEmergencyCap {
    fn default() -> ProcessEmergencyCap {
        ProcessEmergencyCap::new()
    }
}

impl ProcessEmergencyCap {
    pub const MAX_PER_SECOND: usize = 100;

    pub fn new() -> ProcessEmergencyCap {
        ProcessEmergencyCap {
            stamps: Mutex::new(VecDeque::new()),
            max_per_second: Self::MAX_PER_SECOND,
        }
    }

    /// True when the process may proceed within the current window. Also
    /// marks the current moment as consumed.
    pub fn allow(&self) -> bool {
        let now = now_ms();
        let mut stamps = self.stamps.lock().unwrap_or_else(|p| p.into_inner());
        prune(&mut stamps, now);
        if stamps.len() >= self.max_per_second {
            return false;
        }
        stamps.push_back(now);
        true
    }

    /// True when the window is currently saturated.
    pub fn is_open(&self) -> bool {
        let now = now_ms();
        let mut stamps = self.stamps.lock().unwrap_or_else(|p| p.into_inner());
        prune(&mut stamps, now);
        stamps.len() >= self.max_per_second
    }
}

fn prune(stamps: &mut VecDeque<u64>, now: u64) {
    let cutoff = now.saturating_sub(1000);
    while stamps.front().is_some_and(|t| *t <= cutoff) {
        stamps.pop_front();
    }
}

/// In-process GLOBAL emergency window: `max_per_second` admissions per
/// second for THIS process (mirrors the PHP implementation's
/// `LocalEmergencyLimiter::allowGlobal()` exactly — same fixed-window math,
/// `t > now - 1.0` pruning, `count >= cap` denies). Deliberately a
/// PER-PROCESS cap by contract: no cross-process synchronization is
/// performed; the distributed Redis source limiter handles per-source
/// limits across processes. It NEVER touches Redis, so it keeps working
/// when the backend is down; the per-process source window is the primary
/// guard and this is the deployment-scale coarse cap.
pub struct GlobalEmergencyCap {
    max_per_second: u64,
    stamps: Mutex<Vec<f64>>,
    start: std::time::Instant,
}

impl GlobalEmergencyCap {
    pub const DEFAULT_MAX_PER_SECOND: u64 = 10_000;

    /// Builds a cap with the default rate (10000 admissions per second,
    /// per process).
    pub fn new() -> GlobalEmergencyCap {
        GlobalEmergencyCap {
            max_per_second: Self::DEFAULT_MAX_PER_SECOND,
            stamps: Mutex::new(Vec::new()),
            start: std::time::Instant::now(),
        }
    }

    /// Builds a cap with an explicit admissions-per-second rate.
    ///
    /// # Panics
    ///
    /// Panics if `max_per_second < 1`.
    pub fn with_capacity(max_per_second: u64) -> GlobalEmergencyCap {
        assert!(max_per_second >= 1, "max_per_second must be >= 1");
        GlobalEmergencyCap {
            max_per_second,
            stamps: Mutex::new(Vec::new()),
            start: std::time::Instant::now(),
        }
    }

    /// The admissions-per-second cap.
    pub fn max_per_second(&self) -> u64 {
        self.max_per_second
    }

    /// True when an admission is allowed in the current window; also marks
    /// the current moment as consumed. Same semantics as the PHP
    /// `allowGlobal()` (fixed 1-second window, `count >= cap` denies).
    pub fn allow(&self) -> bool {
        let now = self.start.elapsed().as_secs_f64();
        let cutoff = now - 1.0;
        let mut stamps = match self.stamps.lock() {
            Ok(guard) => guard,
            Err(p) => p.into_inner(),
        };
        stamps.retain(|t| *t > cutoff);
        if stamps.len() as u64 >= self.max_per_second {
            return false;
        }
        stamps.push(now);
        true
    }
}

impl Default for GlobalEmergencyCap {
    fn default() -> Self {
        Self::new()
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
    global_limiter: Option<GlobalEmergencyCap>,
    calibration: Option<Arc<dyn CalibrationStore>>,
    metrics: Metrics,
    current_global_level: AtomicU8,
    enable_global_pressure: bool,
}

impl<S: RiskStateStore, N: NetworkClassifier> RiskEngine<S, N> {
    /// Builds an engine with the contract defaults (900 s epochs, 1800 s
    /// session TTL, 86400 s principal TTL, 60 s dedupe TTL, default
    /// saturations, 2-failure/1000 ms breaker, 100 req/s source cap).
    /// No global cap and no calibration store (both optional via
    /// [`RiskEngine::with_global_cap`] / [`RiskEngine::with_calibration`]).
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
            global_limiter: None,
            calibration: None,
            metrics: Metrics::new(),
            current_global_level: AtomicU8::new(0),
            enable_global_pressure: true,
        }
    }

    /// Builds an engine with explicit breaker and caps (tests).
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

    /// Attaches the per-process global admission cap (checked AFTER the
    /// per-process source window in [`RiskEngine::assess`]).
    pub fn with_global_cap(mut self, cap: GlobalEmergencyCap) -> RiskEngine<S, N> {
        self.global_limiter = Some(cap);
        self
    }

    /// Toggles the global-pressure signal, level and cooldown (default:
    /// enabled). When disabled, `assess()` zeroes `global_pressure` on the
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
    /// The emergency caps are checked FIRST (per-process source window,
    /// then the optional per-process global window); on a cap hit the
    /// engine returns a HardRateLimit decision without touching the store.
    /// `idempotency_key` becomes the event_id (dedupe key); `None` draws a
    /// random 16-byte hex id. Every decision gets a fresh `decision_id`
    /// and registers a calibration receipt.
    pub fn assess(&self, ctx: RiskContext<'_>, idempotency_key: Option<String>) -> RiskDecision {
        let now_ms = now_ms();

        if !self.limiter.allow() || !self.global_limiter_allows() {
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
            return self.finalize_decision(ctx.scope, decision);
        }

        let observation = self.build_observation(&ctx, now_ms, idempotency_key);

        if self.breaker.is_open() {
            self.metrics.incr("degraded:breaker");
            let decision = self
                .policy
                .degraded_decision(ctx.scope, self.current_global_level());
            self.record_decision_metrics(ctx.scope, &decision);
            return self.finalize_decision(ctx.scope, decision);
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
                self.finalize_decision(ctx.scope, decision)
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
                self.finalize_decision(ctx.scope, decision)
            }
        }
    }

    /// Outcome feedback path (e.g. a post-solve protected action): stores
    /// the event and returns an [`EventReceipt`]. NEVER runs the limiter
    /// and NEVER calls [`RiskEngine::assess`].
    ///
    /// When the event is ConfirmedLegitimate/ConfirmedAbuse AND
    /// `decision_id` is given, the calibration receipt of that decision is
    /// consumed (GETDEL) and the outcome is recorded into the scope's
    /// hourly buckets.
    pub fn record_feedback(
        &self,
        event: RiskEventKind,
        ctx: RiskContext<'_>,
        idempotency_key: Option<String>,
        decision_id: Option<String>,
    ) -> EventReceipt {
        let now_ms = now_ms();
        let observation = self.build_observation(&ctx, now_ms, idempotency_key);
        let observed = self
            .store
            .observe(&observation)
            .unwrap_or_else(|_| Observed {
                vector: SignalVector::zero(),
                global_level: 0,
                cooldown_until_ms: 0,
                is_duplicate: false,
            });

        let confirmed = matches!(
            event,
            RiskEventKind::ConfirmedLegitimate | RiskEventKind::ConfirmedAbuse
        );
        if confirmed {
            if let Some(receipt_id) = decision_id {
                if let Some(calibration) = &self.calibration {
                    if let Some(receipt) = calibration.consume_receipt(&receipt_id) {
                        let legitimate = event == RiskEventKind::ConfirmedLegitimate;
                        let _ = calibration.record(
                            receipt.scope,
                            receipt.band,
                            receipt.action,
                            legitimate,
                        );
                    }
                }
            }
        }

        EventReceipt {
            event_id: observation.event_id,
            is_duplicate: observed.is_duplicate,
            signals: observed.vector,
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
    ) -> EventReceipt {
        self.record_feedback(event, ctx, idempotency_key, decision_id)
    }

    /// Records a confirmed-legitimate outcome (consumes the calibration
    /// receipt when a decision_id is given).
    pub fn confirmed_legitimate(
        &self,
        ctx: RiskContext<'_>,
        idempotency_key: Option<String>,
        decision_id: Option<String>,
    ) -> EventReceipt {
        self.record_feedback(
            RiskEventKind::ConfirmedLegitimate,
            ctx,
            idempotency_key,
            decision_id,
        )
    }

    /// Records a confirmed-abuse outcome (consumes the calibration receipt
    /// when a decision_id is given).
    pub fn confirmed_abuse(
        &self,
        ctx: RiskContext<'_>,
        idempotency_key: Option<String>,
        decision_id: Option<String>,
    ) -> EventReceipt {
        self.record_feedback(
            RiskEventKind::ConfirmedAbuse,
            ctx,
            idempotency_key,
            decision_id,
        )
    }

    fn global_limiter_allows(&self) -> bool {
        match &self.global_limiter {
            None => true,
            Some(limiter) => limiter.allow(),
        }
    }

    fn build_observation(
        &self,
        ctx: &RiskContext<'_>,
        now_ms: u64,
        idempotency_key: Option<String>,
    ) -> RiskObservation {
        let now_secs = (now_ms / 1000) as i64;
        let src_epoch = now_secs / self.source_epoch_secs as i64;
        let net_epoch = now_secs / self.subnet_epoch_secs as i64;
        let session_id = ctx.session_id.map(|s| self.identity.session_id(s));
        let principal_id = ctx.principal_id.map(|p| self.identity.principal_id(p));
        let event_id = match idempotency_key {
            Some(key) if !key.is_empty() => key,
            _ => RiskObservation::new_event_id(),
        };

        RiskObservation {
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
        }
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

    /// Assigns the decision_id and registers the calibration receipt
    /// (silently on failure — never breaks issuance).
    fn finalize_decision(&self, scope: u32, mut decision: RiskDecision) -> RiskDecision {
        let mut id = [0u8; 16];
        thread_rng().fill_bytes(&mut id);
        decision.decision_id = hex::encode(id);
        if let Some(calibration) = &self.calibration {
            let _ = calibration.record_receipt(
                &decision.decision_id,
                scope,
                decision.band,
                decision.action,
            );
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
        let decision = engine.assess(context(), None);
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
        engine.assess(context(), None);

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
        assert_eq!(observation.network_risk, 1000); // hosting flag
        assert_eq!(observation.event_id.len(), 32);

        // The epochs in the observation match the engine windows.
        let now_secs = (observation.now_ms / 1000) as i64;
        assert_eq!(observation.source_epoch, now_secs / 900);
        assert_eq!(observation.subnet_epoch, now_secs / 900);
    }

    #[test]
    fn idempotency_key_becomes_the_event_id() {
        let store = CapturingStore(Mutex::new(Vec::new()));
        let engine = RiskEngine::new(store, classifier(), policy(), keys());
        let decision = engine.assess(context(), Some("deadbeef".to_string()));
        assert_eq!(decision.decision_id.len(), 32);
        let captured = engine.store.0.lock().unwrap();
        assert_eq!(captured[0].event_id, "deadbeef");
    }

    #[test]
    fn emergency_limiter_denies_with_retry_after() {
        let limiter = ProcessEmergencyCap::new();
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
        let decision = engine.assess(context(), None);
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

        let d1 = engine.assess(context(), None);
        assert_eq!(d1.action, RiskAction::Sha20); // degraded sha20
        assert!(d1.has_reason(RiskReason::CapacityPressure));
        assert_eq!(engine.store.calls.load(Ordering::Relaxed), 1);

        let d2 = engine.assess(context(), None);
        assert_eq!(d2.action, RiskAction::Sha20);
        assert_eq!(engine.store.calls.load(Ordering::Relaxed), 2);

        // Breaker is now open: the store is bypassed.
        let d3 = engine.assess(context(), None);
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

        engine.assess(context(), None);
        engine.assess(context(), None);
        assert!(engine.breaker.is_open());

        std::thread::sleep(std::time::Duration::from_millis(60));
        let decision = engine.assess(context(), None);
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

        let receipt = engine.record_feedback(
            RiskEventKind::ProtectedActionFailure,
            ctx(RiskEventKind::ProtectedActionFailure),
            Some("feedback-1".to_string()),
            None,
        );
        assert_eq!(receipt.event_id, "feedback-1");
        assert!(!receipt.is_duplicate);

        engine.record_feedback(
            RiskEventKind::ConfirmedLegitimate,
            ctx(RiskEventKind::ConfirmedLegitimate),
            None,
            None,
        );
        engine.record_feedback(
            RiskEventKind::ConfirmedAbuse,
            ctx(RiskEventKind::ConfirmedAbuse),
            None,
            None,
        );

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
        engine.record_feedback(RiskEventKind::ConfirmedAbuse, sess_ctx, None, None);
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
    fn decision_json_serialization() {
        let store = MockStore::new(SignalVector::zero(), 0);
        let engine = RiskEngine::new(store, classifier(), policy(), keys());
        let decision = engine.assess(context(), None);
        let json = serde_json::to_value(&decision).unwrap();
        assert_eq!(json["action"], "allow");
        assert_eq!(json["score"], 100);
        assert_eq!(json["band"], 1);
        assert_eq!(json["reasons"], serde_json::json!([]));
        assert_eq!(json["decision_id"].as_str().unwrap().len(), 32);
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
        let decision = engine.assess(context(), None);
        assert_eq!(decision.action, RiskAction::Deny);
        let reasons = decision.reasons_vec();
        // Policy override first, then contributors, deduped.
        assert_eq!(reasons[0], RiskReason::ReplayTraffic);
        assert_eq!(reasons.len(), 3); // ReplayTraffic, MalformedTraffic, SourceBurst
        assert!(reasons.contains(&RiskReason::SourceBurst));
    }

    // ── Calibration bias parity (in-memory calibration store) ──

    struct StaticCalibration {
        bias: i32,
        receipts: Mutex<Vec<(String, u32, u8, RiskAction)>>,
        consumed: Mutex<Vec<String>>,
        recorded: Mutex<Vec<(u32, u8, RiskAction, bool)>>,
    }

    impl CalibrationStore for StaticCalibration {
        fn record(
            &self,
            scope: u32,
            band: u8,
            action: RiskAction,
            legitimate: bool,
        ) -> Result<(), crate::calibration::CalibrationError> {
            self.recorded
                .lock()
                .unwrap()
                .push((scope, band, action, legitimate));
            Ok(())
        }

        fn bias_for_scope(&self, _scope: u32, _now_ms: i64) -> i32 {
            self.bias
        }

        fn record_receipt(
            &self,
            decision_id: &str,
            scope: u32,
            band: u8,
            action: RiskAction,
        ) -> Result<(), crate::calibration::CalibrationError> {
            self.receipts
                .lock()
                .unwrap()
                .push((decision_id.to_string(), scope, band, action));
            Ok(())
        }

        fn consume_receipt(
            &self,
            decision_id: &str,
        ) -> Option<crate::calibration::CalibrationReceipt> {
            self.consumed.lock().unwrap().push(decision_id.to_string());
            Some(crate::calibration::CalibrationReceipt {
                scope: 1,
                band: 1,
                action: RiskAction::Sha16,
            })
        }
    }

    #[test]
    fn calibration_bias_applies_to_base_before_band_mapping() {
        let store = MockStore::new(SignalVector::zero(), 0);
        let cal = Arc::new(StaticCalibration {
            bias: 60,
            receipts: Mutex::new(Vec::new()),
            consumed: Mutex::new(Vec::new()),
            recorded: Mutex::new(Vec::new()),
        });
        let engine =
            RiskEngine::new(store, classifier(), policy(), keys()).with_calibration(cal.clone());
        let decision = engine.assess(context(), None);
        // base 100 + bias 60 = 160 -> band 1, score 160.
        assert_eq!(decision.score, 160);
        assert_eq!(decision.band, 1);
        // A receipt was registered for the decision.
        let receipts = cal.receipts.lock().unwrap();
        assert_eq!(receipts.len(), 1);
        assert_eq!(receipts[0].1, 1); // scope
    }

    #[test]
    fn confirmed_outcome_consumes_receipt_and_records() {
        let store = MockStore::new(SignalVector::zero(), 0);
        let cal = Arc::new(StaticCalibration {
            bias: 0,
            receipts: Mutex::new(Vec::new()),
            consumed: Mutex::new(Vec::new()),
            recorded: Mutex::new(Vec::new()),
        });
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
        let receipt = engine.record_feedback(
            RiskEventKind::ConfirmedLegitimate,
            ctx,
            None,
            Some("decision-x".to_string()),
        );
        assert!(!receipt.is_duplicate);
        assert!(cal
            .consumed
            .lock()
            .unwrap()
            .contains(&"decision-x".to_string()));
        let recorded = cal.recorded.lock().unwrap();
        assert_eq!(recorded.len(), 1);
        assert_eq!(recorded[0], (1, 1, RiskAction::Sha16, true));
    }

    // ── End-to-end with the Redis store (skipped unless RISK_REDIS_URL) ──

    #[test]
    fn global_cap_caps_admissions_per_process() {
        // In-process fixed-window cap (mirrors the PHP implementation):
        // 5 admissions fit the window, the 6th and 7th must be denied
        // with HardRateLimit. Needs Redis for the store backend; skipped
        // unless RISK_REDIS_URL is set.
        let Some(raw_url) = std::env::var("RISK_REDIS_URL")
            .ok()
            .filter(|u| !u.is_empty())
        else {
            eprintln!("skipping global limiter test: RISK_REDIS_URL not set");
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
        let engine = RiskEngine::new(store, classifier(), policy(), keys())
            .with_global_cap(GlobalEmergencyCap::with_capacity(5));

        let mut allowed = 0;
        let mut denied = 0;
        for i in 0..7u32 {
            let decision = engine.assess(context(), Some(format!("gl-{i}")));
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
        let decision = engine.assess(context(), None);
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
        let decision = engine.assess(context(), None);
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
        let client = ::redis::Client::open(url).expect("url parses");
        let mut suffix = [0u8; 4];
        thread_rng().fill_bytes(&mut suffix);
        let store = redis::RedisRiskStateStore::new(client, &format!("e2e{}", hex::encode(suffix)));
        let classifier = classifier();
        let flags = classifier.classify("203.0.113.27".parse().unwrap());
        let engine = RiskEngine::new(store, classifier, policy(), keys());

        let mut ctx = context();
        ctx.network_flags = flags;
        let first = engine.assess(ctx, None);
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
        let _ = engine.record_feedback(
            RiskEventKind::ChallengeIssued,
            feedback_ctx(RiskEventKind::ChallengeIssued),
            Some("e2e-1".to_string()),
            None,
        );
        let _ = engine.record_feedback(
            RiskEventKind::SolveSuccess,
            feedback_ctx(RiskEventKind::SolveSuccess),
            Some("e2e-2".to_string()),
            None,
        );
        let _ = engine.record_feedback(
            RiskEventKind::ProtectedActionFailure,
            feedback_ctx(RiskEventKind::ProtectedActionFailure),
            Some("e2e-3".to_string()),
            None,
        );
        let _ = engine.confirmed_abuse(
            feedback_ctx(RiskEventKind::ConfirmedAbuse),
            Some("e2e-4".to_string()),
            None,
        );
        let decision = engine.assess(context(), None);
        assert!(decision.score <= 1000);
        assert!(
            decision.has_reason(RiskReason::LocalNetworkRisk),
            "hosting network risk must hard-deny"
        );
    }
}
