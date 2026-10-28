//! Shared first-attempt prevention vectors (protocol/risk-v1/
//! first-attempt-vectors.json): every row pins the trusted-history state
//! around one AuthenticationSuccess and the per-mode verdict (the
//! action, the four first-attempt reasons, and the post-Allow binding
//! trust state for the session and the device). The PHP mirror
//! (`tests/FirstAttemptVectorsTest.php`) derives the identical outputs
//! over the same corpus. `RISK_FIRST_ATTEMPT_VECTORS_PATH` overrides
//! the corpus location and `RISK_ASN_DATASET_PATH` the sample dataset.

use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};

use kiwicaptcha_risk::context::{RiskContext, RiskV2Context};
use kiwicaptcha_risk::event::{RiskEventKind, RiskObservation};
use kiwicaptcha_risk::identity::RiskIdentityFactory;
use kiwicaptcha_risk::keys::RiskKeys;
use kiwicaptcha_risk::network::NetworkFlags;
use kiwicaptcha_risk::policy::{RiskPolicy, RiskReason};
use kiwicaptcha_risk::resources::ResourcePressure;
use kiwicaptcha_risk::signals::SignalVector;
use kiwicaptcha_risk::store::{Observed, PrincipalNetworkTagStore, RiskStateStore, RiskStoreError};
use kiwicaptcha_risk::NoveltyEnforcement;
use serde_json::json;

const HOME_IP: &str = "198.51.100.42";
const OTHER_ASN_IP: &str = "203.0.113.42";
const OLD_HOME_IP: &str = "192.0.2.7";
const MASTER: [u8; 32] = [0x42; 32];

fn vectors_path() -> String {
    std::env::var("RISK_FIRST_ATTEMPT_VECTORS_PATH")
        .ok()
        .filter(|p| !p.is_empty())
        .unwrap_or_else(|| {
            concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../protocol/risk-v1/first-attempt-vectors.json"
            )
            .to_string()
        })
}

fn corpus() -> serde_json::Value {
    let raw = std::fs::read_to_string(vectors_path())
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", vectors_path()));
    serde_json::from_str(&raw).expect("valid json")
}

fn sample_dataset() -> Option<kiwicaptcha_risk::asn::AsnDataset> {
    if let Some(path) = std::env::var("RISK_ASN_DATASET_PATH")
        .ok()
        .filter(|p| !p.is_empty())
    {
        return Some(
            kiwicaptcha_risk::asn::AsnDataset::open(path).expect("the sample dataset opens"),
        );
    }
    let doc = corpus();
    let relative = doc["dataset_path"].as_str().expect("dataset_path");
    let root = std::path::Path::new(&vectors_path())
        .parent()
        .and_then(|p| p.parent())
        .and_then(|p| p.parent())
        .expect("the corpus sits three levels under the root")
        .to_path_buf();
    Some(
        kiwicaptcha_risk::asn::AsnDataset::open(root.join(relative))
            .expect("the sample dataset opens"),
    )
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

/// The legacy bucket spelling of a source address (family byte plus
/// the masked bytes, hex). The corpus seeds its history with this
/// spelling, which the gate reads as the legacy form, so every row
/// keeps pinning the same verdicts it pinned before the stable tags.
fn network_bucket(ip: IpAddr) -> String {
    hex::encode(kiwicaptcha_risk::identity::masked_network(ip, 32, 64))
}

/// True when the tag is one of the long-memory network classes whose
/// trusted mirror makes the account trusted (net, asn, or the bare-hex
/// engine bucket spelling). Session and device mirrors never count: a
/// bound cookie is continuity evidence, never a trusted network.
fn is_network_class(tag: &str) -> bool {
    if tag.starts_with("session:") || tag.starts_with("device:") || tag.starts_with("t:") {
        return false;
    }
    if tag.starts_with("net:") || tag.starts_with("asn:") {
        return true;
    }
    !tag.is_empty() && tag.chars().all(|c| c.is_ascii_hexdigit())
}

/// The in-memory trusted-history twin of the canonical Lua semantics:
/// the bare tag carries seen-ness, the `t:` mirror carries trust, a
/// record only ever mints the mirror (never revokes), and the
/// any-trusted probe counts network-class mirrors only. `fail_reads`
/// turns every probe into a backend outage (the fail-closed row).
#[derive(Default, Clone)]
struct VectorNetworks {
    pairs: Arc<Mutex<HashSet<(String, String)>>>,
    trusted: Arc<Mutex<HashSet<(String, String)>>>,
    fail_reads: bool,
}

impl VectorNetworks {
    fn seed(&self, principal_hex: &str, tag: &str, trusted: bool) {
        self.pairs
            .lock()
            .unwrap()
            .insert((principal_hex.to_string(), tag.to_string()));
        if trusted {
            self.trusted
                .lock()
                .unwrap()
                .insert((principal_hex.to_string(), tag.to_string()));
        }
    }

    fn seen(&self, principal_hex: &str, tag: &str) -> bool {
        self.pairs
            .lock()
            .unwrap()
            .contains(&(principal_hex.to_string(), tag.to_string()))
    }

    fn trusted(&self, principal_hex: &str, tag: &str) -> Option<bool> {
        if self.seen(principal_hex, tag) {
            Some(
                self.trusted
                    .lock()
                    .unwrap()
                    .contains(&(principal_hex.to_string(), tag.to_string())),
            )
        } else {
            None
        }
    }
}

impl PrincipalNetworkTagStore for VectorNetworks {
    fn principal_network_seen(
        &self,
        principal_id: &str,
        network: &str,
    ) -> Result<Option<bool>, RiskStoreError> {
        if self.fail_reads {
            return Err(RiskStoreError::BackendUnavailable("probe outage".into()));
        }
        Ok(Some(self.seen(principal_id, network)))
    }

    fn record_principal_network_tag(
        &self,
        principal_id: &str,
        network: &str,
        trusted: bool,
    ) -> Result<bool, RiskStoreError> {
        let is_new = !self.seen(principal_id, network);
        self.seed(principal_id, network, trusted);
        Ok(is_new)
    }

    fn principal_has_trusted_network(
        &self,
        principal_id: &str,
    ) -> Result<Option<bool>, RiskStoreError> {
        if self.fail_reads {
            return Err(RiskStoreError::BackendUnavailable("probe outage".into()));
        }
        let pairs = self.pairs.lock().unwrap();
        let trusted = self.trusted.lock().unwrap();
        Ok(Some(pairs.iter().any(|(p, tag)| {
            p == principal_id
                && is_network_class(tag)
                && trusted.contains(&(p.to_string(), tag.to_string()))
        })))
    }

    fn tag_is_trusted(
        &self,
        principal_id: &str,
        network: &str,
    ) -> Result<Option<bool>, RiskStoreError> {
        if self.fail_reads {
            return Err(RiskStoreError::BackendUnavailable("probe outage".into()));
        }
        Ok(self.trusted(principal_id, network))
    }
}

/// The plain state-store twin: a clean vector, a configurable global
/// level (the scope-pressure row), no cooldown.
#[derive(Default, Clone)]
struct VectorStore {
    global_level: u8,
}

impl RiskStateStore for VectorStore {
    fn observe(&self, _o: &RiskObservation) -> Result<Observed, RiskStoreError> {
        Ok(Observed {
            vector: SignalVector::zero(),
            global_level: self.global_level,
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
    fn read_target_state(
        &self,
        _target_id: &str,
    ) -> Result<kiwicaptcha_risk::store::TargetState, RiskStoreError> {
        Ok(kiwicaptcha_risk::store::TargetState {
            fails: 0,
            spread_sources: 0,
            spread_asns: 0,
            first_ms: 0,
            last_ms: 0,
        })
    }
}

impl kiwicaptcha_risk::store::SessionContextTagStore for VectorStore {}
impl kiwicaptcha_risk::store::SessionTlsTagStore for VectorStore {}

/// One evaluated vector: the seeded history, the request shape, and the
/// two expected mode cells.
struct Case {
    note: String,
    ip: IpAddr,
    with_dataset: bool,
    seed_asn: bool,
    seed_bucket: Option<bool>,
    seed_old_bucket: bool,
    session_seed: Option<bool>,
    probe_failure: bool,
    breached: bool,
    event: RiskEventKind,
    expected_learn: serde_json::Value,
    expected_enforce: serde_json::Value,
}

fn build_case(vector: &serde_json::Value) -> Case {
    let asn = vector["asn"].as_str().expect("asn").to_string();
    let prefix_seen = vector["prefix"].as_str().expect("prefix") == "seen";
    let continuity = vector["continuity"].as_str().expect("continuity");
    let account_trusted = vector["account_trusted"]
        .as_bool()
        .expect("account_trusted");
    let ip: IpAddr = match asn.as_str() {
        "unseen" => OTHER_ASN_IP.parse().unwrap(),
        _ => HOME_IP.parse().unwrap(),
    };
    Case {
        note: vector["note"].as_str().expect("note").to_string(),
        ip,
        with_dataset: asn != "absent",
        seed_asn: asn == "seen",
        seed_bucket: if prefix_seen {
            Some(account_trusted)
        } else {
            None
        },
        seed_old_bucket: account_trusted && !prefix_seen,
        session_seed: match continuity {
            "bound" => Some(true),
            "seen-untrusted" => Some(false),
            _ => None,
        },
        probe_failure: vector["probe_failure"].as_bool().unwrap_or(false),
        breached: vector["breached"].as_bool().unwrap_or(false),
        event: match vector["event"].as_str().unwrap_or("authentication_success") {
            "solve_success" => RiskEventKind::SolveSuccess,
            _ => RiskEventKind::AuthenticationSuccess,
        },
        expected_learn: vector["expected"]["learn"].clone(),
        expected_enforce: vector["expected"]["enforce"].clone(),
    }
}

fn run_cell(case: &Case, enforce: NoveltyEnforcement, expected: &serde_json::Value) {
    let identity = RiskIdentityFactory::new(RiskKeys::from_master(&MASTER));
    let principal_bytes = [0xf6u8; 16];
    let principal_hex = hex::encode(identity.principal_id(&principal_bytes));
    let raw_session = [0xaau8; 16];
    let raw_device = [0xddu8; 16];
    let session_hex = hex::encode(identity.session_id(&raw_session));
    let device_hex = hex::encode(identity.device_id(&raw_device));

    let global_level = if expected["global_attack"].as_bool().unwrap_or(false) {
        1
    } else {
        0
    };
    let store = VectorStore { global_level };
    let networks = VectorNetworks {
        fail_reads: case.probe_failure,
        ..Default::default()
    };
    if let Some(bucket_trusted) = case.seed_bucket {
        networks.seed(&principal_hex, &network_bucket(case.ip), bucket_trusted);
    }
    if case.seed_old_bucket {
        let old: IpAddr = OLD_HOME_IP.parse().unwrap();
        networks.seed(&principal_hex, &network_bucket(old), true);
    }
    if case.seed_asn {
        networks.seed(&principal_hex, "asn:64498", true);
    }
    if let Some(trusted) = case.session_seed {
        networks.seed(&principal_hex, &format!("session:{session_hex}"), trusted);
    }

    let dataset = if case.with_dataset {
        Some(Arc::new(
            sample_dataset().expect("the sample dataset opens"),
        ))
    } else {
        None
    };
    let mut engine =
        kiwicaptcha_risk::RiskEngine::new(store, policy(), RiskKeys::from_master(&MASTER))
            .with_principal_networks(Arc::new(networks.clone()))
            .with_novelty_enforcement(enforce);
    if let Some(dataset) = dataset {
        engine = engine.with_asn_dataset(dataset);
    }

    let ctx = RiskContext::new(
        1,
        case.ip,
        Some(&raw_session),
        Some(&principal_bytes),
        case.event,
        NetworkFlags::default(),
        ResourcePressure::default(),
    )
    .with_device_id(Some(&raw_device));

    let decision = if case.breached {
        let v2 = RiskV2Context {
            breached_credential: true,
            ..Default::default()
        };
        engine
            .reassess_v2(ctx, &v2, Some("vector".to_string()), None)
            .expect("assess succeeds")
    } else {
        engine
            .reassess(ctx, Some("vector".to_string()))
            .expect("assess succeeds")
    };

    let note = &case.note;
    let mode = if expected == &case.expected_enforce {
        "enforce"
    } else {
        "learn"
    };
    assert_eq!(
        decision.action.as_str(),
        expected["action"].as_str().expect("action"),
        "vector {note:?} ({mode}) action"
    );
    assert_eq!(
        decision.has_reason(RiskReason::NovelNetwork),
        expected["novel_network"].as_bool().unwrap_or(false),
        "vector {note:?} ({mode}) novel-network reason"
    );
    assert_eq!(
        decision.has_reason(RiskReason::EvidenceUnavailable),
        expected["evidence_unavailable"].as_bool().unwrap_or(false),
        "vector {note:?} ({mode}) evidence-unavailable reason"
    );
    assert_eq!(
        decision.has_reason(RiskReason::GlobalAttack),
        expected["global_attack"].as_bool().unwrap_or(false),
        "vector {note:?} ({mode}) global-attack reason"
    );
    assert_eq!(
        decision.has_reason(RiskReason::BreachedCredential),
        expected["breached_credential"].as_bool().unwrap_or(false),
        "vector {note:?} ({mode}) breached-credential reason"
    );

    // The post-Allow binding trust state: minted = live trust mirror,
    // unminted = recorded without one, absent = never recorded. The
    // reads go through the local state, not the outage-simulating
    // surface: the probe-failure row keeps its read failures.
    for (tag, column) in [
        (format!("session:{session_hex}"), "session_trust"),
        (format!("device:{device_hex}"), "device_trust"),
    ] {
        match expected[column].as_str().expect(column) {
            "minted" => {
                assert_eq!(
                    networks.trusted(&principal_hex, &tag),
                    Some(true),
                    "vector {note:?} ({mode}) {column} must be minted"
                );
            }
            "unminted" => {
                assert!(
                    networks.seen(&principal_hex, &tag),
                    "vector {note:?} ({mode}) {column} must be recorded"
                );
                assert_eq!(
                    networks.trusted(&principal_hex, &tag),
                    Some(false),
                    "vector {note:?} ({mode}) {column} must stay unminted"
                );
            }
            other => {
                assert!(
                    other == "absent" || other == "unbound",
                    "vector {note:?} ({mode}) unknown {column} state"
                );
                assert!(
                    !networks.seen(&principal_hex, &tag),
                    "vector {note:?} ({mode}) {column} must never be recorded"
                );
            }
        }
    }
}

#[test]
fn shared_first_attempt_vectors_match_php() {
    let doc = corpus();
    assert_eq!(doc["protocol"], "risk-v1");
    assert_eq!(doc["kind"], "first-attempt-vectors");
    let vectors = doc["vectors"].as_array().expect("vectors array");
    assert!(vectors.len() >= 16, "the F16 cross product must stay rich");
    for vector in vectors {
        let case = build_case(vector);
        run_cell(&case, NoveltyEnforcement::Learn, &case.expected_learn);
        run_cell(&case, NoveltyEnforcement::Enforce, &case.expected_enforce);
    }
}
