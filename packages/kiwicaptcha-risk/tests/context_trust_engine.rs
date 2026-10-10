//! The engine-level wiring of the context-bound trust: when the engine
//! is wired with a trust source (the `with_context_trust` seam), the
//! request's session-trust channel input is the bucket-local credit
//! instead of the aggregate; a foreign bucket earns nothing at engine
//! level; the unwired engine stays byte-identical to the aggregate
//! channel. The credit decision itself is pinned against the shared
//! `protocol/risk-v1/trust-vectors.json` corpus by `tests/trust_vectors.rs`,
//! the same vectors the PHP `TrustVectorsTest` asserts.

use std::net::IpAddr;
use std::sync::Arc;

use kiwicaptcha_risk::context::RiskContext;
use kiwicaptcha_risk::event::{RiskEventKind, RiskObservation};
use kiwicaptcha_risk::keys::RiskKeys;
use kiwicaptcha_risk::network::CidrNetworkClassifier;
use kiwicaptcha_risk::network::NetworkFlags;
use kiwicaptcha_risk::policy::RiskPolicy;
use kiwicaptcha_risk::resources::ResourcePressure;
use kiwicaptcha_risk::signals::SignalVector;
use kiwicaptcha_risk::store::{
    Observed, RiskStateStore, RiskStoreError, SessionContextTagStore, SessionTlsTagStore,
};
use kiwicaptcha_risk::trust::{BucketTrustCredit, ContextTrustSource};
use kiwicaptcha_risk::RiskEngine;

/// The aggregate trust the state script answers with: a mid-band credit
/// the wired engine must replace, never keep.
const AGGREGATE_TRUST: u16 = 700;

/// The in-memory state store: the observation answers the aggregate
/// channel (700 trust credit), so the decision score exposes exactly
/// which trust input the engine applied.
#[derive(Default, Clone)]
struct AggregateStore;

impl RiskStateStore for AggregateStore {
    fn observe(&self, _o: &RiskObservation) -> Result<Observed, RiskStoreError> {
        Ok(Observed {
            vector: SignalVector {
                trust_credit: AGGREGATE_TRUST,
                ..SignalVector::zero()
            },
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
}

impl SessionContextTagStore for AggregateStore {}
impl SessionTlsTagStore for AggregateStore {}

/// The fixture trust source: the session's record keyed by the bucket,
/// the exact decision surface (`ContextBoundTrust::decision`) the
/// shared vectors pin. The bucket resolution is emulated over the two
/// test networks: 198.51.100.0/24 is the home bucket `a64496`, every
/// other address is a foreign bucket with no record (the real dataset
/// resolution is pinned by `tests/trust_vectors.rs`).
struct FixtureTrust {
    home_raw: u32,
}

impl ContextTrustSource for FixtureTrust {
    fn credit_for(
        &self,
        _session_id: &str,
        source_ip: IpAddr,
    ) -> Result<BucketTrustCredit, kiwicaptcha_risk::RiskError> {
        const HOME: &str = "a64496";
        let is_home = match source_ip {
            IpAddr::V4(v4) => {
                v4.octets()[0] == 198 && v4.octets()[1] == 51 && v4.octets()[2] == 100
            }
            IpAddr::V6(_) => false,
        };
        if is_home {
            Ok(kiwicaptcha_risk::trust::bucket_trust_credit(
                HOME,
                Some(self.home_raw),
            ))
        } else {
            // The foreign bucket carries no record: the applied credit
            // is exactly zero and the home record is never consulted.
            Ok(kiwicaptcha_risk::trust::bucket_trust_credit(
                "u4/51968", None,
            ))
        }
    }
}

fn policy() -> Arc<RiskPolicy> {
    Arc::new(
        RiskPolicy::from_config(
            3,
            &serde_json::json!({
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

fn context(ip: IpAddr) -> RiskContext<'static> {
    RiskContext::new(
        1,
        ip,
        Some(&[7u8; 16]),
        None,
        RiskEventKind::PreIssue,
        NetworkFlags::default(),
        ResourcePressure::default(),
    )
}

fn engine(
    trust: Option<Arc<dyn ContextTrustSource>>,
) -> RiskEngine<AggregateStore, CidrNetworkClassifier> {
    let mut engine = RiskEngine::new(
        AggregateStore,
        CidrNetworkClassifier::from_entries(vec![]),
        policy(),
        RiskKeys::from_master(&[0x42; 32]),
    );
    if let Some(source) = trust {
        engine = engine.with_context_trust(source);
    }
    engine
}

const HOME_IP: &str = "198.51.100.42";
const FOREIGN_IP: &str = "203.0.113.9";

#[test]
fn the_wired_engine_applies_the_bucket_local_credit_instead_of_the_aggregate() {
    // The store answers the 700 aggregate; the wired engine must score
    // the request with the bucket-local credit instead.
    let wired = engine(Some(Arc::new(FixtureTrust { home_raw: 4_000 })));
    let decision = wired
        .reassess(context(HOME_IP.parse().unwrap()), None)
        .expect("the wired assessment succeeds");
    let expected = kiwicaptcha_risk::score::score(
        policy().base_risk(1),
        &SignalVector {
            trust_credit: 400,
            ..SignalVector::zero()
        },
        &policy().weights,
    );
    assert_eq!(
        decision.score, expected,
        "the session-trust channel input is the bucket-local credit"
    );
    assert_ne!(
        decision.score,
        kiwicaptcha_risk::score::score(
            policy().base_risk(1),
            &SignalVector {
                trust_credit: AGGREGATE_TRUST,
                ..SignalVector::zero()
            },
            &policy().weights,
        ),
        "the aggregate channel never leaks through the wired engine"
    );
}

#[test]
fn a_foreign_bucket_earns_nothing_at_engine_level() {
    // The session's home record is full; a foreign presentation reads
    // the foreign bucket only, and the applied credit is exactly zero.
    let wired = engine(Some(Arc::new(FixtureTrust { home_raw: 10_000 })));
    let decision = wired
        .reassess(context(FOREIGN_IP.parse().unwrap()), None)
        .expect("the foreign assessment succeeds");
    let expected = kiwicaptcha_risk::score::score(
        policy().base_risk(1),
        &SignalVector::zero(),
        &policy().weights,
    );
    assert_eq!(
        decision.score, expected,
        "the foreign presentation earns nothing: the channel reads zero credit"
    );
}

#[test]
fn the_unwired_engine_keeps_the_aggregate_channel() {
    let aggregate = engine(None);
    let decision = aggregate
        .reassess(context(HOME_IP.parse().unwrap()), None)
        .expect("the unwired assessment succeeds");
    assert_eq!(
        decision.score,
        kiwicaptcha_risk::score::score(
            policy().base_risk(1),
            &SignalVector {
                trust_credit: AGGREGATE_TRUST,
                ..SignalVector::zero()
            },
            &policy().weights,
        ),
        "the unwired engine forwards the aggregate untouched"
    );
}

#[test]
fn a_failed_trust_read_floors_the_channel_fail_closed() {
    struct Failing;
    impl ContextTrustSource for Failing {
        fn credit_for(
            &self,
            _session_id: &str,
            _source_ip: IpAddr,
        ) -> Result<BucketTrustCredit, kiwicaptcha_risk::RiskError> {
            Err(kiwicaptcha_risk::RiskError::Store("down".to_string()))
        }
    }
    let wired = engine(Some(Arc::new(Failing)));
    let decision = wired
        .reassess(context(HOME_IP.parse().unwrap()), None)
        .expect("the assessment itself still succeeds");
    assert_eq!(
        decision.score,
        kiwicaptcha_risk::score::score(
            policy().base_risk(1),
            &SignalVector::zero(),
            &policy().weights,
        ),
        "a failed read floors the channel at zero, never the aggregate"
    );
}
