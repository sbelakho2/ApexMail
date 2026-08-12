//! KiwiCaptcha Adaptive Risk Engine (risk-v1 protocol).
//!
//! One pipeline turns a [`RiskContext`] into a [`RiskDecision`]:
//! emergency limiter → observation (ephemeral pseudonyms) → circuit breaker
//! → state store (canonical Lua via EVALSHA) → scorer → policy. Backend
//! failure degrades instead of failing the request.

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
use std::net::IpAddr;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use rand::{thread_rng, RngCore};
use serde::ser::{Serialize, SerializeStruct, Serializer};

use crate::action::RiskAction;
use crate::context::RiskContext;
use crate::event::{RiskEventKind, RiskObservation};
use crate::identity::{canonical_ip, masked_network, pseudonym};
use crate::keys::RiskKeys;
use crate::metrics::Metrics;
use crate::network::NetworkClassifier;
use crate::policy::{RiskPolicy, RiskReason};
use crate::score::score as compute_score;
use crate::store::RiskStateStore;

/// Immutable risk decision produced by the engine.
///
/// Reasons are internal only (never exposed to the client) and capped at 4.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RiskDecision {
    pub score: u16,
    pub action: RiskAction,
    pub reasons: [Option<RiskReason>; 4],
    pub policy_version: u32,
    pub global_level: u8,
    pub retry_after_ms: Option<u32>,
    pub band: u8,
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

/// Raw saturation values passed to the Lua script, in its ARGV order
/// (src_fast, src_slow, issue, bad, mal, rep, action, switch, global,
/// trust). The defaults mirror the PHP implementation.
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
        }
    }
}

impl Saturations {
    /// The saturations in the Lua ARGV order (indices 8..17 of ARGV).
    pub fn to_arg_order(&self) -> [u32; 10] {
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
        ]
    }
}

/// In-process emergency guard: a fixed-window limiter of 100 observations
/// per second per process, enforced BEFORE any state backend is touched.
///
/// The contract is deliberately per-process (a `VecDeque` of timestamps in
/// this process's memory); no cross-process synchronization is performed.
/// When the window is saturated the engine denies immediately
/// (HardRateLimit) instead of spending time/state on the request.
pub struct LocalEmergencyLimiter {
    stamps: Mutex<VecDeque<u64>>,
    max_per_second: usize,
}

impl Default for LocalEmergencyLimiter {
    fn default() -> LocalEmergencyLimiter {
        LocalEmergencyLimiter::new()
    }
}

impl LocalEmergencyLimiter {
    pub const MAX_PER_SECOND: usize = 100;

    pub fn new() -> LocalEmergencyLimiter {
        LocalEmergencyLimiter {
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

/// The adaptive risk engine.
pub struct RiskEngine<S: RiskStateStore, N: NetworkClassifier> {
    store: S,
    classifier: N,
    policy: Arc<RiskPolicy>,
    keys: RiskKeys,
    breaker: breaker::CircuitBreaker,
    pub source_epoch_secs: u64,
    pub subnet_epoch_secs: u64,
    pub session_ttl_secs: u64,
    pub principal_ttl_secs: u64,
    pub dedupe_ttl_secs: u64,
    pub saturations: Saturations,
    limiter: LocalEmergencyLimiter,
    metrics: Metrics,
    current_global_level: AtomicU8,
}

impl<S: RiskStateStore, N: NetworkClassifier> RiskEngine<S, N> {
    /// Builds an engine with the contract defaults (900 s epochs, 1800 s
    /// session TTL, 86400 s principal TTL, 60 s dedupe TTL, default
    /// saturations, 2-failure/1000 ms breaker, 100 req/s limiter).
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
            keys,
            breaker: breaker::CircuitBreaker::default(),
            source_epoch_secs: 900,
            subnet_epoch_secs: 900,
            session_ttl_secs: 1800,
            principal_ttl_secs: 86400,
            dedupe_ttl_secs: 60,
            saturations: Saturations::default(),
            limiter: LocalEmergencyLimiter::default(),
            metrics: Metrics::new(),
            current_global_level: AtomicU8::new(0),
        }
    }

    /// Builds an engine with explicit breaker and limiter (tests).
    pub fn with_components(
        store: S,
        classifier: N,
        policy: Arc<RiskPolicy>,
        keys: RiskKeys,
        breaker: breaker::CircuitBreaker,
        limiter: LocalEmergencyLimiter,
    ) -> RiskEngine<S, N> {
        let mut engine = RiskEngine::new(store, classifier, policy, keys);
        engine.breaker = breaker;
        engine.limiter = limiter;
        engine
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

    /// Assesses one request and returns a [`RiskDecision`].
    pub fn assess(&self, ctx: RiskContext<'_>) -> RiskDecision {
        let now_ms = now_ms();

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
            };
            self.record_decision_metrics(ctx.scope, &decision);
            return decision;
        }

        let observation = self.build_observation(&ctx, now_ms);

        if self.breaker.is_open() {
            self.metrics.incr("degraded:breaker");
            let decision = self
                .policy
                .degraded_decision(ctx.scope, self.current_global_level());
            self.record_decision_metrics(ctx.scope, &decision);
            return decision;
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
                decision
            }
            Ok(vector) => {
                self.metrics
                    .add_latency_us("store:observe", start.elapsed().as_micros() as u64);
                self.breaker.record_success();
                let global_level = self.store.last_global_level();
                self.current_global_level
                    .store(global_level, Ordering::Relaxed);
                let cooldown_until_ms = self.store.last_cooldown_until_ms();
                let base = self.policy.base_risk(ctx.scope);
                let score = compute_score(base, &vector, &self.policy.weights);
                let decision = self.policy.decide(
                    ctx.scope,
                    score,
                    &vector,
                    &ctx.resources,
                    global_level,
                    now_ms,
                    cooldown_until_ms,
                );
                self.record_decision_metrics(ctx.scope, &decision);
                decision
            }
        }
    }

    /// Outcome feedback path (e.g. a post-solve protected action).
    pub fn record(
        &self,
        event: RiskEventKind,
        scope: u16,
        ip: IpAddr,
        session_id: Option<&[u8]>,
        principal_id: Option<&[u8]>,
    ) {
        let ctx = RiskContext {
            scope,
            source_ip: ip,
            session_id,
            principal_id,
            event,
            network_flags: self.classifier.classify(ip),
            resources: resources::ResourcePressure::default(),
        };
        self.assess(ctx);
    }

    /// Records a confirmed-legitimate outcome.
    pub fn confirmed_legitimate(&self, scope: u16, ip: IpAddr, principal_id: Option<&[u8]>) {
        self.record(
            RiskEventKind::ConfirmedLegitimate,
            scope,
            ip,
            None,
            principal_id,
        );
    }

    /// Records a confirmed-abuse outcome.
    pub fn confirmed_abuse(&self, scope: u16, ip: IpAddr, principal_id: Option<&[u8]>) {
        self.record(RiskEventKind::ConfirmedAbuse, scope, ip, None, principal_id);
    }

    fn build_observation(&self, ctx: &RiskContext<'_>, now_ms: u64) -> RiskObservation {
        let now_secs = now_ms / 1000;
        let src_epoch = now_secs / self.source_epoch_secs;
        let net_epoch = now_secs / self.subnet_epoch_secs;
        let canonical = canonical_ip(ctx.source_ip);
        let source_id = pseudonym(&self.keys.source, b"src", src_epoch, &canonical);
        let subnet_id = pseudonym(
            &self.keys.subnet,
            b"net",
            net_epoch,
            &masked_network(ctx.source_ip, 24, 56),
        );
        let session_id = ctx
            .session_id
            .map(|s| pseudonym(&self.keys.session, b"sess", 0, s));
        let principal_id = ctx
            .principal_id
            .map(|p| pseudonym(&self.keys.principal, b"prin", 0, p));
        let mut event_id = [0u8; 16];
        thread_rng().fill_bytes(&mut event_id);

        RiskObservation {
            event: ctx.event,
            scope: ctx.scope,
            source_id,
            subnet_id,
            session_id,
            principal_id,
            event_id,
            network_risk: ctx.network_flags.network_risk(),
            now_ms,
        }
    }

    fn record_decision_metrics(&self, scope: u16, decision: &RiskDecision) {
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
    use crate::event::RiskEventKind;
    use crate::network::{CidrEntry, CidrNetworkClassifier, NetworkFlags};
    use crate::policy::RiskPolicy;
    use crate::resources::ResourcePressure;
    use crate::signals::SignalVector;
    use crate::store::RiskStoreError;
    use serde_json::json;
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
                    "global_floors": { "1": "sha16", "2": "sha18", "3": "sha20", "4": "sha20" }
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
        calls: AtomicUsize,
        fail: bool,
        fail_calls: usize,
    }

    impl MockStore {
        fn new(vector: SignalVector, level: u8) -> MockStore {
            MockStore {
                level,
                vector,
                calls: AtomicUsize::new(0),
                fail: false,
                fail_calls: 0,
            }
        }

        fn failing() -> MockStore {
            MockStore {
                level: 0,
                vector: SignalVector::zero(),
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
                calls: AtomicUsize::new(0),
                fail: true,
                fail_calls,
            }
        }
    }

    impl RiskStateStore for MockStore {
        fn observe(&self, _o: &RiskObservation) -> Result<SignalVector, RiskStoreError> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            if self.fail && self.calls.load(Ordering::Relaxed) <= self.fail_calls {
                return Err(RiskStoreError::BackendUnavailable("redis down".into()));
            }
            Ok(self.vector)
        }

        fn last_global_level(&self) -> u8 {
            self.level
        }
    }

    struct CapturingStore(pub Mutex<Vec<RiskObservation>>);

    impl RiskStateStore for CapturingStore {
        fn observe(&self, o: &RiskObservation) -> Result<SignalVector, RiskStoreError> {
            self.0.lock().unwrap().push(o.clone());
            Ok(SignalVector::zero())
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
        let decision = engine.assess(context());
        assert_eq!(decision.score, 195); // 100 + weighted(500, 190)
        assert_eq!(decision.action, RiskAction::Sha18); // band Sha16 raised by global floor 2
        assert_eq!(decision.policy_version, 3);
        assert_eq!(decision.global_level, 2);
        assert_eq!(decision.band, 1);

        let snapshot = engine.metrics().snapshot();
        assert!(snapshot.iter().any(|(k, _)| k == "decisions:1:sha18:1"));
        assert!(snapshot.iter().any(|(k, _)| k == "store:observe:count"));
    }

    #[test]
    fn observation_carries_pseudonyms_and_network_risk() {
        let store = CapturingStore(Mutex::new(Vec::new()));
        let engine = RiskEngine::new(store, classifier(), policy(), keys());
        engine.assess(context());

        let captured = engine.store.0.lock().unwrap();
        let observation = &captured[0];
        assert_eq!(observation.event, RiskEventKind::PreIssue);
        assert_eq!(observation.scope, 1);
        assert_eq!(hex::encode(observation.source_id).len(), 32);
        assert_eq!(hex::encode(observation.subnet_id).len(), 32);
        assert_eq!(observation.session_id, None);
        assert_eq!(observation.principal_id, None);
        assert_eq!(observation.network_risk, 1000); // hosting flag
        assert_eq!(hex::encode(observation.event_id).len(), 32);
    }

    #[test]
    fn emergency_limiter_denies_with_retry_after() {
        let limiter = LocalEmergencyLimiter::new();
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
        let decision = engine.assess(context());
        assert_eq!(decision.action, RiskAction::Deny);
        assert!(decision.has_reason(RiskReason::HardRateLimit));
        assert_eq!(decision.retry_after_ms, Some(1000));
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
            LocalEmergencyLimiter::new(),
        );

        let d1 = engine.assess(context());
        assert_eq!(d1.action, RiskAction::Sha20); // degraded sha20
        assert!(d1.has_reason(RiskReason::CapacityPressure));
        assert_eq!(engine.store.calls.load(Ordering::Relaxed), 1);

        let d2 = engine.assess(context());
        assert_eq!(d2.action, RiskAction::Sha20);
        assert_eq!(engine.store.calls.load(Ordering::Relaxed), 2);

        // Breaker is now open: the store is bypassed.
        let d3 = engine.assess(context());
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
            LocalEmergencyLimiter::new(),
        );

        engine.assess(context());
        engine.assess(context());
        assert!(engine.breaker.is_open());

        std::thread::sleep(std::time::Duration::from_millis(60));
        let decision = engine.assess(context());
        assert_eq!(decision.score, 195);
        assert_eq!(decision.action, RiskAction::Sha16);
        assert_eq!(engine.store.calls.load(Ordering::Relaxed), 3);
        assert!(!engine.breaker.is_open());
    }

    #[test]
    fn record_maps_events() {
        let store = CapturingStore(Mutex::new(Vec::new()));
        let engine = RiskEngine::new(store, classifier(), policy(), keys());
        engine.record(
            RiskEventKind::ProtectedActionFailure,
            1,
            "203.0.113.27".parse().unwrap(),
            Some(b"sess"),
            None,
        );
        engine.confirmed_legitimate(1, "203.0.113.27".parse().unwrap(), None);
        engine.confirmed_abuse(1, "203.0.113.27".parse().unwrap(), Some(b"principal-1"));

        let captured = engine.store.0.lock().unwrap();
        let events: Vec<RiskEventKind> = captured.iter().map(|o| o.event).collect();
        assert_eq!(
            events,
            vec![
                RiskEventKind::ProtectedActionFailure,
                RiskEventKind::ConfirmedLegitimate,
                RiskEventKind::ConfirmedAbuse,
            ]
        );
        assert_eq!(
            captured[0].session_id,
            Some(pseudonym(&keys().session, b"sess", 0, b"sess"))
        );
        assert_eq!(
            captured[2].principal_id,
            Some(pseudonym(&keys().principal, b"prin", 0, b"principal-1"))
        );
    }

    #[test]
    fn decision_json_serialization() {
        let store = MockStore::new(SignalVector::zero(), 0);
        let engine = RiskEngine::new(store, classifier(), policy(), keys());
        let decision = engine.assess(context());
        let json = serde_json::to_value(&decision).unwrap();
        assert_eq!(json["action"], "allow");
        assert_eq!(json["score"], 100);
        assert_eq!(json["band"], 1);
        assert_eq!(json["reasons"], serde_json::json!([]));
    }

    // ── End-to-end with the Redis store (skipped unless RISK_REDIS_URL) ──

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
        let first = engine.assess(ctx);
        assert!(first.score <= 1000);
        assert_eq!(first.policy_version, 3);

        // Feed outcomes and confirm the state reacts.
        let ip: IpAddr = "203.0.113.27".parse().unwrap();
        engine.record(RiskEventKind::ChallengeIssued, 1, ip, None, None);
        engine.record(RiskEventKind::SolveSuccess, 1, ip, Some(b"session-1"), None);
        engine.record(
            RiskEventKind::ProtectedActionFailure,
            1,
            ip,
            Some(b"session-1"),
            None,
        );
        engine.confirmed_abuse(1, ip, Some(b"principal-1"));
        let decision = engine.assess(context());
        assert!(decision.score <= 1000);
        assert!(
            decision.has_reason(RiskReason::LocalNetworkRisk),
            "hosting network risk must hard-deny"
        );
    }
}
