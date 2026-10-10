//! The credential-stuffing simulator: the done-when of decisive
//! attacker handling (change.md 3.3.3 / D3.5). One victim account; K
//! attacker identities (distinct session dimensions, three groups
//! sharing an ASN bucket) attempt M logins against the victim. Every
//! attacker identity must be denied within N = 3 attempts of its own
//! traffic, while the victim logs in with exactly one step-up and zero
//! lockouts end-to-end.
//!
//! The simulation is deterministic and policy-layer only: each attempt
//! is a realistic first attempt with a fresh stuffed credential pair
//! (the OpenBullet-class list shape of D3.5 — one pair per attempt, no
//! retries of a malformed token). Attempt j carries the accumulated
//! invalid-proof evidence `bad_proof = min(1000, 250 * j)` through the
//! real scorer and policy; the outcome plane writes the attacker's
//! abuse marks (session plus ASN bucket) once its evidence corroborates
//! (bad_proof at the corroboration floor, attempt 2). When an attempt
//! is not denied it reaches authentication and fails (the stuffed pair
//! is not the victim's password) — and the engine stores that target
//! failure through the typed outcomes facade
//! (`Outcome::AuthenticationFailure` on the target handle), which owns
//! the leaky counter and the spread HLLs. The test never injects the
//! target record: [`MarksView::read`] compiles the attacked-target
//! record from the engine's own state once the count reaches
//! [`kiwicaptcha_risk::marks::TARGET_ATTACK_THRESHOLD`]. A denied
//! attempt never reaches authentication, so it adds no target failure.
//! The marks store is in-memory; with the Redis url variable set the
//! identical simulation runs over the real marks surface.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

use kiwicaptcha_risk::action::RiskAction;
use kiwicaptcha_risk::context::RiskContext;
use kiwicaptcha_risk::event::{RiskEventKind, RiskObservation};
use kiwicaptcha_risk::keys::RiskKeys;
use kiwicaptcha_risk::marks::{MarksView, TARGET_ATTACK_THRESHOLD};
use kiwicaptcha_risk::network::CidrNetworkClassifier;
use kiwicaptcha_risk::network::NetworkFlags;
use kiwicaptcha_risk::outcomes::{
    KiwiOutcomes, MarkDimension, MarkRecord, Outcome, OutcomeHandle, OutcomeMarksStore,
};
use kiwicaptcha_risk::policy::{RiskPolicy, RiskReason};
use kiwicaptcha_risk::resources::ResourcePressure;
use kiwicaptcha_risk::score::{score as compute_score, RiskWeights};
use kiwicaptcha_risk::signals::SignalVector;
use kiwicaptcha_risk::store::{
    Observed, PrincipalNetworkTagStore, RiskStateStore, RiskStoreError, TargetState,
};
use kiwicaptcha_risk::{marks, RiskError};
use serde_json::json;

const K: usize = 24;
const M: u32 = 6;
/// Documented bound: every attacker identity is denied at attempt 2 or 3.
const N: u32 = 3;
const GROUPS: usize = 3;
const T0: u64 = 1_700_000_000_000;
const QUIET_WINDOW_MS: u64 = 900_000;

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

fn attacker_sessions() -> Vec<String> {
    (0..K).map(|i| format!("{:032x}", i + 1)).collect()
}

fn asn_buckets() -> Vec<String> {
    (0..GROUPS)
        .map(|group| format!("a{}", 64496 + group))
        .collect()
}

/// The deterministic stuffing storm over one marks-and-target surface.
/// The credit closure reports the victim's stepUpCompleted outcome
/// through the typed outcomes facade and answers (channel_booked,
/// marks_written); the failure closure reports one attacker
/// authentication failure against the victim target — the engine stores
/// the target failure. Both closures run the real report path.
fn run_simulation(
    store: &dyn OutcomeMarksStore,
    report_failure: &dyn Fn(),
    report_step_up_credit: &dyn Fn() -> (bool, u32),
) {
    let weights = RiskWeights::default();
    let policy = policy();
    let healthy = ResourcePressure::default();
    let ttl = marks::DEFAULT_MARK_TTL_MS;

    // Hex-only 32-char pseudonyms (the handle contract's shape).
    let victim_session = "e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5".to_string();
    let victim_principal = "f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6".to_string();
    let victim_target = "5e2a9b4c1d7f38e6a0b5c9d2e4f6a813".to_string();
    let sessions = attacker_sessions();
    let buckets = asn_buckets();

    let mut last_failure_at = 0u64;
    let mut step_up_completed = false;
    let mut marked = [false; K];
    let mut denied_at: Vec<Option<u32>> = vec![None; K];
    let mut victim_step_ups = 0u32;
    let mut victim_denies = 0u32;

    // Round-robin attempts: round j runs attacker 0..K-1 in order, so
    // each group's first attacker writes the shared ASN bucket mark
    // before its group-mates attempt in the same round. Every attempt
    // is a first attempt with a fresh stuffed credential pair.
    for j in 1..=M {
        for i in 0..K {
            let now = T0 + (((j - 1) as u64 * K as u64) + i as u64) * 1000;
            let bad_proof = (250 * j).min(1000) as u16;
            let signals = SignalVector {
                bad_proof,
                ..Default::default()
            };
            let score = compute_score(100, &signals, &weights);
            let plain = policy.decide(1, score, &signals, &healthy, 0, now, 0);
            if j == 1 {
                // The pre-mark floor check: the attacker's own plain
                // evidence lands it in the Sha16 band, nothing weaker.
                assert_eq!(plain.action.as_str(), "sha16");
            }
            let bucket = &buckets[i * GROUPS / K];
            // The engine compiles the target record from its own
            // failure state — the test injects nothing.
            let view = MarksView::read(
                store,
                &[
                    (MarkDimension::Session, sessions[i].clone()),
                    (MarkDimension::Asn, bucket.clone()),
                ],
                Some(&victim_target),
            )
            .expect("marks read");
            let decision = marks::apply(
                plain,
                &view,
                marks::corroborated(&signals, false),
                now,
                ttl,
                &healthy,
                false,
            );
            if decision.action == RiskAction::Deny {
                denied_at[i].get_or_insert(j);
            } else {
                // The attempt reaches authentication with its fresh
                // stuffed pair and fails: the engine stores the target
                // failure (leaky counter + spread HLLs).
                report_failure();
                last_failure_at = now;
            }
            if !marked[i] && bad_proof >= marks::CORROBORATION_FLOOR {
                // The outcome plane confirms the abuse: long-memory marks
                // on the attacker's session and ASN bucket.
                store
                    .write_mark("session", &sessions[i], "accountBanned", now, "")
                    .expect("session mark");
                store
                    .write_mark("asn", bucket, "accountBanned", now, "")
                    .expect("asn mark");
                marked[i] = true;
            }
        }

        if j == 2 {
            // The victim logs in while the target is under attack (the
            // engine's failure state is at or above the threshold):
            // exactly the interactive step-up, never a lockout.
            let now = T0 + (K as u64 * 2) * 1000;
            let plain = policy.decide(1, 100, &SignalVector::zero(), &healthy, 0, now, 0);
            let view = MarksView::read(
                store,
                &[
                    (MarkDimension::Session, victim_session.clone()),
                    (MarkDimension::Principal, victim_principal.clone()),
                ],
                Some(&victim_target),
            )
            .expect("marks read");
            let decision = marks::apply(plain, &view, false, now, ttl, &healthy, false);
            assert_eq!(decision.action.as_str(), "step_up");
            assert!(decision.has_reason(RiskReason::TargetUnderAttack));
            victim_step_ups += 1;
            if decision.action == RiskAction::Deny {
                victim_denies += 1;
            }

            // The victim completes the step-up: the outcome credit
            // through the typed outcomes facade over the same surface.
            let (channel_booked, marks_written) = report_step_up_credit();
            assert!(channel_booked, "the credit books its trust channel");
            assert_eq!(marks_written, 0, "a trust outcome never writes a mark");
            step_up_completed = true;
        }
    }

    // (a) every attacker identity is denied within N attempts, and the
    // deny arrives only after corroborated evidence exists (attempt 2
    // at the earliest).
    let mut leaders = Vec::new();
    for (i, attempt) in denied_at.iter().enumerate() {
        let attempt = attempt.expect("every attacker identity reaches a deny");
        assert!(
            attempt >= 2,
            "attacker {i} denied at {attempt} (before evidence)"
        );
        assert!(attempt <= N, "attacker {i} denied at {attempt} (beyond N)");
        if attempt == N {
            leaders.push(i);
        }
    }
    // Each group's first attacker is denied at attempt 3 (its own marks
    // land after its second attempt); its group-mates ride the shared
    // ASN bucket mark and are denied at attempt 2.
    assert_eq!(leaders, vec![0, 8, 16]);

    // The attack subsides: denied attempts add no target failures and
    // the step-up completion cleared the counter, so the engine state
    // is below the threshold again (the leaky bucket would also decay
    // it across the quiet window).
    assert!(
        step_up_completed,
        "the victim completed its step-up before relief"
    );
    let quiet_at = last_failure_at + QUIET_WINDOW_MS;
    assert!(quiet_at > 0);
    let state = OutcomeMarksStore::read_target_state(store, &victim_target)
        .expect("target state");
    assert!(
        state.fails < TARGET_ATTACK_THRESHOLD,
        "the engine's target state is relieved (got {})",
        state.fails
    );

    // (b) the victim's next login is the plain allow again: no step-up,
    // no lockout, and exactly one step-up happened overall.
    let plain = policy.decide(1, 100, &SignalVector::zero(), &healthy, 0, quiet_at, 0);
    let view = MarksView::read(
        store,
        &[
            (MarkDimension::Session, victim_session),
            (MarkDimension::Principal, victim_principal),
        ],
        Some(&victim_target),
    )
    .expect("marks read");
    let decision = marks::apply(plain, &view, false, quiet_at, ttl, &healthy, false);
    assert_eq!(decision.action.as_str(), "allow");
    assert!(!decision.has_reason(RiskReason::TargetUnderAttack));
    assert_eq!(victim_step_ups, 1, "the victim saw exactly one step-up");
    assert_eq!(victim_denies, 0, "the victim is never locked out");
}

/// First-attempt valid stuffing (P0-1 success criterion): a valid
/// stolen credential on its very first attempt — no prior failures
/// anywhere, and a network the principal has never been seen from —
/// must yield StepUp, never Allow. The engine derives the novel-network
/// evidence beside the frozen wire and the marks stage forces the
/// interactive step-up before any session credit. Once the step-up
/// completes (the network tag is recorded SET NX), the same login from
/// the same network is the plain allow again.
#[test]
fn first_attempt_valid_stuffing_gets_step_up_not_allow() {
    let store = SimStore::default();
    let networks = Arc::new(SimNetworks::default());
    let engine = kiwicaptcha_risk::RiskEngine::new(
        store.clone(),
        CidrNetworkClassifier::from_entries(vec![]),
        policy(),
        RiskKeys::from_master(&[0x42; 32]),
    )
    .with_principal_networks(networks.clone());
    let principal_bytes = [0xf6u8; 16];
    // The engine addresses the principal by its derived pseudonym, so
    // the tag writes must key the same one.
    let identity = kiwicaptcha_risk::identity::RiskIdentityFactory::new(RiskKeys::from_master(
        &[0x42; 32],
    ));
    let principal_hex = hex::encode(identity.principal_id(&principal_bytes));
    let home_ip = "198.51.100.23".parse().unwrap();
    let home_bucket = hex::encode(kiwicaptcha_risk::identity::masked_network(home_ip, 32, 64));
    let fresh_ip = "203.0.113.99".parse().unwrap();

    let ctx_for = |ip| {
        RiskContext::new(
            1,
            ip,
            None,
            Some(&principal_bytes),
            RiskEventKind::AuthenticationSuccess,
            NetworkFlags::default(),
            ResourcePressure::default(),
        )
    };

    // Attempt 1: the attacker's network has never been seen for this
    // principal and the account carries no trusted network at all —
    // exactly the first-attempt valid stuffing shape. No failures were
    // registered anywhere (the store's target state is empty).
    let decision = engine
        .reassess(ctx_for(home_ip), Some("stuffing-1".to_string()))
        .expect("assess succeeds");
    assert_eq!(
        decision.action.as_str(),
        "step_up",
        "first-attempt valid stuffing must be stepped up, never allowed ({:?})",
        decision.action
    );
    assert!(
        decision.has_reason(RiskReason::NovelNetwork),
        "the step-up must carry the novel-network reason ({:?})",
        decision.reasons
    );

    // The victim completes the step-up: the session credit records the
    // network tag (SET NX) and the account now has a trusted network.
    assert!(
        networks
            .record_principal_network_tag(&principal_hex, &home_bucket)
            .expect("record"),
        "the first established network records its tag"
    );

    // Attempt 2 from the same network: established — the plain allow.
    let decision = engine
        .reassess(ctx_for(home_ip), Some("stuffing-2".to_string()))
        .expect("assess succeeds");
    assert_eq!(
        decision.action.as_str(),
        "allow",
        "an established network is the plain allow again ({:?})",
        decision.action
    );

    // Attempt 3 from a NEW network (the attacker moves): stepped up
    // again — a fresh bucket for a principal is novel while the account
    // still vouches only for its established bucket... and a second
    // network without any established history is the same first-attempt
    // shape.
    let decision = engine
        .reassess(ctx_for(fresh_ip), Some("stuffing-3".to_string()))
        .expect("assess succeeds");
    assert_eq!(
        decision.action.as_str(),
        "step_up",
        "a novel network for the principal is stepped up ({:?})",
        decision.action
    );
}

/// The in-memory principal first-seen network tag store (P0-1): SET NX
/// per (principal, network-bucket) pair, plus the account-level trusted
/// flag the novel-network gate also consults.
#[derive(Default)]
struct SimNetworks {
    pairs: Mutex<HashSet<(String, String)>>,
}

impl kiwicaptcha_risk::store::PrincipalNetworkTagStore for SimNetworks {
    fn principal_network_seen(
        &self,
        principal_id: &str,
        network: &str,
    ) -> Result<Option<bool>, RiskStoreError> {
        Ok(Some(
            self.pairs
                .lock()
                .unwrap()
                .contains(&(principal_id.to_string(), network.to_string())),
        ))
    }

    fn record_principal_network_tag(
        &self,
        principal_id: &str,
        network: &str,
    ) -> Result<bool, RiskStoreError> {
        Ok(self
            .pairs
            .lock()
            .unwrap()
            .insert((principal_id.to_string(), network.to_string())))
    }

    fn principal_has_trusted_network(
        &self,
        principal_id: &str,
    ) -> Result<Option<bool>, RiskStoreError> {
        Ok(Some(self.pairs.lock().unwrap().iter().any(|(p, _)| p == principal_id)))
    }
}

/// The in-memory marks-and-state twin of the PHP RiskStateStoreStub:
/// cloning shares the state, so the engine owns one clone while the
/// simulation drives another. The target state is the engine's own
/// (leaky counter + spread set): `register_target_failure` is what the
/// outcomes facade calls, and `MarksView::read` compiles the
/// attacked-target record from it.
#[derive(Default, Clone)]
struct SimStore {
    observed: Arc<Mutex<Vec<RiskObservation>>>,
    marks: Arc<Mutex<HashMap<(String, String), MarkRecord>>>,
    target_fails: Arc<Mutex<HashMap<String, (u32, i64, i64)>>>,
    target_spread: Arc<Mutex<HashMap<String, HashSet<String>>>>,
}

impl SimStore {
    /// The engine-side failure registration (the exact contract the
    /// Redis target_failure.lua implements).
    fn target_failure_state(&self, target_id: &str) -> TargetState {
        let (fails, first_ms, last_ms) = self
            .target_fails
            .lock()
            .unwrap()
            .get(target_id)
            .copied()
            .unwrap_or((0, 0, 0));
        let set = self.target_spread.lock().unwrap();
        let set = set.get(target_id);
        let spread_sources = set
            .map(|s| s.iter().filter(|e| e.starts_with("src:")).count() as u32)
            .unwrap_or(0);
        let spread_asns = set
            .map(|s| s.iter().filter(|e| e.starts_with("asn:")).count() as u32)
            .unwrap_or(0);
        TargetState {
            fails,
            spread_sources,
            spread_asns,
            first_ms,
            last_ms,
        }
    }
}

impl RiskStateStore for SimStore {
    fn observe(&self, o: &RiskObservation) -> Result<Observed, RiskStoreError> {
        self.observed.lock().unwrap().push(o.clone());
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

    fn register_target_failure(
        &self,
        target_id: &str,
        source: &str,
        asn: &str,
    ) -> Result<TargetState, RiskStoreError> {
        let now_ms = T0 as i64;
        {
            let mut fails = self.target_fails.lock().unwrap();
            let entry = fails.entry(target_id.to_string()).or_insert((0, now_ms, now_ms));
            entry.0 += 1;
            entry.2 = now_ms;
        }
        {
            let mut spread = self.target_spread.lock().unwrap();
            let set = spread.entry(target_id.to_string()).or_default();
            if !source.is_empty() {
                set.insert(format!("src:{source}"));
            }
            if !asn.is_empty() {
                set.insert(format!("asn:{asn}"));
            }
        }
        Ok(self.target_failure_state(target_id))
    }

    fn clear_target_failures(&self, target_id: &str) -> Result<(), RiskStoreError> {
        if let Some(entry) = self.target_fails.lock().unwrap().get_mut(target_id) {
            entry.0 = 0;
        }
        Ok(())
    }

    fn read_target_state(&self, target_id: &str) -> Result<TargetState, RiskStoreError> {
        Ok(self.target_failure_state(target_id))
    }
}

impl kiwicaptcha_risk::store::SessionContextTagStore for SimStore {}
impl kiwicaptcha_risk::store::SessionTlsTagStore for SimStore {}

impl OutcomeMarksStore for SimStore {
    fn mark_key(&self, dimension: &str, id: &str) -> Result<String, RiskError> {
        Ok(format!("mark:{{kiwi:test}}:{dimension}:{id}"))
    }
    fn write_mark(
        &self,
        dimension: &str,
        id: &str,
        kind: &str,
        now_ms: u64,
        _event_id: &str,
    ) -> Result<i64, RiskError> {
        let mut marks = self.marks.lock().unwrap();
        let entry = marks
            .entry((dimension.to_string(), id.to_string()))
            .or_insert(MarkRecord {
                kind: kind.to_string(),
                last_kind: kind.to_string(),
                count: 0,
                first_ms: now_ms as i64,
                last_ms: now_ms as i64,
            });
        if kiwicaptcha_risk::outcomes::mark_kind_severity(kind)
            > kiwicaptcha_risk::outcomes::mark_kind_severity(&entry.kind)
        {
            entry.kind = kind.to_string();
        }
        entry.last_kind = kind.to_string();
        entry.count += 1;
        entry.last_ms = now_ms as i64;
        Ok(entry.count)
    }
    fn read_mark(&self, dimension: &str, id: &str) -> Result<Option<MarkRecord>, RiskError> {
        Ok(self
            .marks
            .lock()
            .unwrap()
            .get(&(dimension.to_string(), id.to_string()))
            .cloned())
    }
    fn forget_marks(&self, dimension: &str, id: &str) -> Result<u32, RiskError> {
        Ok(self
            .marks
            .lock()
            .unwrap()
            .remove(&(dimension.to_string(), id.to_string()))
            .map_or(0, |_| 1))
    }

    fn read_target_state(&self, target_id: &str) -> Result<TargetState, RiskError> {
        Ok(self.target_failure_state(target_id))
    }
}

fn victim_context() -> RiskContext<'static> {
    RiskContext::new(
        1,
        "203.0.113.7".parse().unwrap(),
        None,
        None,
        RiskEventKind::PreIssue,
        NetworkFlags::default(),
        ResourcePressure::default(),
    )
}

#[test]
fn stuffing_storm_denies_attackers_and_saves_the_victim() {
    let store = SimStore::default();
    let engine = kiwicaptcha_risk::RiskEngine::new(
        store.clone(),
        CidrNetworkClassifier::from_entries(vec![]),
        policy(),
        RiskKeys::from_master(&[0x42; 32]),
    );
    let outcomes = KiwiOutcomes::new(&engine, &store);
    let victim_principal = "f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6".to_string();
    let victim_target = "5e2a9b4c1d7f38e6a0b5c9d2e4f6a813".to_string();
    // The engine stores each authentication failure against the target
    // (the outcome-bridge write path) — the simulation never touches the
    // target state directly.
    let report_failure = || {
        outcomes
            .report(
                Outcome::AuthenticationFailure,
                &OutcomeHandle::target(&victim_target).unwrap(),
                Some(format!("stuff-fail-{}", rand::random::<u32>())),
                Some(victim_context()),
            )
            .expect("the target failure report succeeds");
    };
    let report = || {
        let receipt = outcomes
            .report(
                Outcome::StepUpCompleted,
                &OutcomeHandle::principal(&victim_principal).unwrap(),
                Some("victim-step-up-credit".to_string()),
                Some(victim_context()),
            )
            .expect("the credit report succeeds");
        // Completion credits the target too (change.md 3.4.2): the
        // engine clears the target failure counter, so a legitimate
        // user is not stepped up twice.
        outcomes
            .report(
                Outcome::StepUpCompleted,
                &OutcomeHandle::target(&victim_target).unwrap(),
                Some("victim-step-up-target-credit".to_string()),
                Some(victim_context()),
            )
            .expect("the target credit report succeeds");
        (receipt.channel_booked, receipt.marks_written)
    };
    run_simulation(&store, &report_failure, &report);
    assert!(
        !store.observed.lock().unwrap().is_empty(),
        "the credit booked its feedback observation"
    );
}

/// The identical simulation against the real Redis marks surface
/// (marks.lua writes and reads) and the real target-failure state
/// (target_failure.lua).
#[test]
fn stuffing_storm_over_real_redis_marks() {
    let Ok(raw_url) = std::env::var("RISK_REDIS_URL") else {
        eprintln!("skipping: RISK_REDIS_URL not set");
        return;
    };
    let url = raw_url
        .strip_prefix("tcp://")
        .map(|rest| format!("redis://{rest}"))
        .unwrap_or(raw_url);
    let client = ::redis::Client::open(url.clone()).expect("url parses");
    let mut suffix = [0u8; 4];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut suffix);
    let namespace = format!("stuffing{}", hex::encode(suffix));
    let engine_store =
        kiwicaptcha_risk::redis::RedisRiskStateStore::new(client.clone(), &namespace)
            .with_io_timeouts(2_000, 2_000);
    let marks_store = kiwicaptcha_risk::redis::RedisRiskStateStore::new(client, &namespace)
        .with_io_timeouts(2_000, 2_000);

    let engine = kiwicaptcha_risk::RiskEngine::new(
        engine_store,
        CidrNetworkClassifier::from_entries(vec![]),
        policy(),
        RiskKeys::from_master(&[0x42; 32]),
    );
    let outcomes = KiwiOutcomes::new(&engine, &marks_store);
    let victim_principal = "f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6".to_string();
    let victim_target = "5e2a9b4c1d7f38e6a0b5c9d2e4f6a813".to_string();
    let report_failure = || {
        outcomes
            .report(
                Outcome::AuthenticationFailure,
                &OutcomeHandle::target(&victim_target).unwrap(),
                Some(format!("stuff-fail-{}", rand::random::<u32>())),
                Some(victim_context()),
            )
            .expect("the target failure report succeeds");
    };
    let report = || {
        let receipt = outcomes
            .report(
                Outcome::StepUpCompleted,
                &OutcomeHandle::principal(&victim_principal).unwrap(),
                Some("victim-step-up-credit".to_string()),
                Some(victim_context()),
            )
            .expect("the credit report succeeds");
        outcomes
            .report(
                Outcome::StepUpCompleted,
                &OutcomeHandle::target(&victim_target).unwrap(),
                Some("victim-step-up-target-credit".to_string()),
                Some(victim_context()),
            )
            .expect("the target credit report succeeds");
        (receipt.channel_booked, receipt.marks_written)
    };
    // The simulation reads the marks/target state through the same
    // store the engine writes (the target record is compiled from the
    // engine's failure state).
    run_simulation(&marks_store, &report_failure, &report);

    // Cleanup: the exact mark keys of the run plus the target state.
    let mut keys: Vec<String> = Vec::new();
    for session in attacker_sessions() {
        keys.push(marks_store.mark_key("session", &session).unwrap());
    }
    for bucket in asn_buckets() {
        keys.push(marks_store.mark_key("asn", &bucket).unwrap());
    }
    keys.extend(kiwicaptcha_risk::keyspace::target_state_keys(
        &namespace,
        &victim_target,
    ));
    let mut conn = ::redis::Client::open(url)
        .unwrap()
        .get_connection()
        .unwrap();
    use ::redis::Commands;
    let _: i64 = conn.del(keys).unwrap();
}
