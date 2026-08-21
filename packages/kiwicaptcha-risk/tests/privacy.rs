//! Redis privacy guarantees (real Redis, skipped unless the Redis test
//! URL is set):
//! issuing observations from a single IP must leave NO raw personal data in
//! the state — keys, hash values and metadata contain only HMAC pseudonyms
//! and numeric counters.
//!
//! The scan pattern is namespace-scoped (`{kiwi:<ns>}:*`): the contract's
//! hash-tagged keys do not start with a bare `kiwi:` prefix, and scoping to
//! the fresh per-test namespace keeps the scan isolated from parallel test
//! binaries. The assertions themselves (raw strings nowhere) are what
//! matter and hold for any key set the store wrote.

mod common;

use kiwicaptcha_risk::event::RiskEventKind;
use kiwicaptcha_risk::identity::{canonical_ip, masked_network, pseudonym};
use kiwicaptcha_risk::keys::RiskKeys;
use kiwicaptcha_risk::redis::RedisRiskStateStore;
use kiwicaptcha_risk::store::RiskStateStore;
use redis::Commands;

const IP: &str = "203.0.113.77";
const UA: &[u8] = b"Mozilla/5.0 (X11; Linux x86_64) KiwiBrowser/125.0";
const PRINCIPAL: &[u8] = b"customer_2847812";
const EMAIL: &[u8] = b"customer_2847812@example.com";

fn client() -> redis::Client {
    redis::Client::open(common::redis_url().expect("RISK_REDIS_URL set")).expect("url parses")
}

#[test]
fn no_raw_pii_anywhere_in_redis_state() {
    let Some(_url) = common::redis_url() else {
        eprintln!("skipping privacy scan test: RISK_REDIS_URL not set");
        return;
    };
    let store = RedisRiskStateStore::new(client(), &common::unique_namespace("privacy"));
    let ns = store.namespace().to_string();

    // Issue real observations derived from the raw values under test.
    let keys = RiskKeys::from_master(&[0x42; 32]);
    let ip: std::net::IpAddr = IP.parse().unwrap();
    let epoch = ((common::T0 / 1000) / 900) as i64;
    // Epoch-correct pseudonyms: each ±1 key uses ITS OWN epoch's id.
    let source_id = hex::encode(pseudonym(&keys.source, b"src", epoch, &canonical_ip(ip)));
    let source_id_prev = hex::encode(pseudonym(
        &keys.source,
        b"src",
        epoch - 1,
        &canonical_ip(ip),
    ));
    let source_id_next = hex::encode(pseudonym(
        &keys.source,
        b"src",
        epoch + 1,
        &canonical_ip(ip),
    ));
    let subnet_id = hex::encode(pseudonym(
        &keys.subnet,
        b"net",
        epoch,
        &masked_network(ip, 24, 56),
    ));
    let subnet_id_prev = hex::encode(pseudonym(
        &keys.subnet,
        b"net",
        epoch - 1,
        &masked_network(ip, 24, 56),
    ));
    let subnet_id_next = hex::encode(pseudonym(
        &keys.subnet,
        b"net",
        epoch + 1,
        &masked_network(ip, 24, 56),
    ));
    let principal_id = pseudonym(&keys.principal, b"prin", 0, PRINCIPAL);
    let session_ua = pseudonym(&keys.session, b"sess", 0, UA);
    let session_email = pseudonym(&keys.session, b"sess", 0, EMAIL);

    let observation = |event: RiskEventKind, session: Option<[u8; 16]>, event_id: u64| {
        kiwicaptcha_risk::event::RiskObservation {
            event,
            scope: 1,
            source_epoch: epoch,
            source_id_prev: source_id_prev.clone(),
            source_id: source_id.clone(),
            source_id_next: source_id_next.clone(),
            subnet_epoch: epoch,
            subnet_id_prev: subnet_id_prev.clone(),
            subnet_id: subnet_id.clone(),
            subnet_id_next: subnet_id_next.clone(),
            session_id: session,
            principal_id: Some(principal_id),
            event_id: common::event_id(event_id),
            network_risk: 0,
            now_ms: common::T0,
        }
    };

    let observations = [
        observation(RiskEventKind::PreIssue, Some(session_ua), 1),
        observation(
            RiskEventKind::ProtectedActionFailure,
            Some(session_email),
            2,
        ),
        observation(RiskEventKind::ConfirmedAbuse, Some(session_ua), 3),
    ];
    for o in &observations {
        store.observe(o).expect("observation applies");
    }

    // Scan the namespace and pull every key, field name and value.
    let mut conn = client().get_connection().expect("connection");
    let pattern = format!("{{kiwi:{ns}}}:*");
    let scanned: Vec<String> = conn.scan_match(pattern).expect("scan").collect();
    assert!(!scanned.is_empty(), "scan must find the issued keys");

    // The current source pseudonym is what got stored (the current-epoch
    // key). The ±1 boundary keys are observer-only in risk.lua (hmget,
    // never saved), so the epoch-scoped prev/next pseudonyms never even
    // enter the key space at the boundary.
    assert!(
        scanned
            .iter()
            .any(|k| k.ends_with(&format!(":risk:src:{epoch}:{source_id}"))),
        "source pseudonym must be what got stored"
    );
    assert!(
        !scanned.iter().any(|k| k.contains(&source_id_prev)),
        "epoch-1 pseudonym must not be persisted (observer-only boundary key)"
    );
    assert!(
        !scanned.iter().any(|k| k.contains(&source_id_next)),
        "epoch+1 pseudonym must not be persisted (observer-only boundary key)"
    );
    // Session/principal state IS persisted when the observation carries
    // them (has_session/has_principal), but only under their HMAC
    // pseudonyms — the key shape is `:risk:principal:<32-hex>` and the raw
    // principal id exists nowhere, in any form (asserted by the blob scan
    // below).
    let principal_hex = hex::encode(principal_id);
    let principal_keys: Vec<&String> = scanned
        .iter()
        .filter(|k| k.contains(":risk:principal:"))
        .collect();
    assert!(
        !principal_keys.is_empty(),
        "principal state must be persisted under its pseudonym"
    );
    for key in principal_keys {
        assert!(
            key.ends_with(&format!(":risk:principal:{principal_hex}")),
            "principal key must be the pure pseudonym, got {key}"
        );
    }

    let mut blob = String::new();
    let mut read_conn = client().get_connection().expect("connection");
    for key in &scanned {
        blob.push_str(key);
        blob.push('\n');
        let kind: String = redis::cmd("TYPE")
            .arg(key)
            .query(&mut read_conn)
            .expect("type");
        match kind.as_str() {
            "hash" => {
                let fields: Vec<String> = redis::cmd("HGETALL")
                    .arg(key)
                    .query(&mut read_conn)
                    .expect("hgetall");
                blob.push_str(&fields.join("\n"));
            }
            "string" => {
                let value: Option<String> = redis::cmd("GET")
                    .arg(key)
                    .query(&mut read_conn)
                    .expect("get");
                if let Some(value) = value {
                    blob.push_str(&value);
                }
            }
            other => panic!("unexpected key type {other} for {key}"),
        }
        blob.push('\n');
    }

    for raw in [
        IP,
        std::str::from_utf8(UA).unwrap(),
        std::str::from_utf8(PRINCIPAL).unwrap(),
        std::str::from_utf8(EMAIL).unwrap(),
    ] {
        assert!(
            !blob.contains(raw),
            "raw {raw:?} leaked into Redis keys/values/metadata"
        );
    }
}
