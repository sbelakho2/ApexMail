//! Redis privacy guarantees (real Redis, skipped unless RISK_REDIS_URL):
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
    let epoch = (common::T0 / 1000) / 900;
    let source_id = pseudonym(&keys.source, b"src", epoch, &canonical_ip(ip));
    let subnet_id = pseudonym(&keys.subnet, b"net", epoch, &masked_network(ip, 24, 56));
    let principal_id = pseudonym(&keys.principal, b"prin", 0, PRINCIPAL);
    let session_ua = pseudonym(&keys.session, b"sess", 0, UA);
    let session_email = pseudonym(&keys.session, b"sess", 0, EMAIL);

    let observations = [
        common::observation(
            RiskEventKind::PreIssue,
            1,
            source_id,
            subnet_id,
            Some(session_ua),
            Some(principal_id),
            common::event_id(1),
            common::T0,
        ),
        common::observation(
            RiskEventKind::ProtectedActionFailure,
            1,
            source_id,
            subnet_id,
            Some(session_email),
            Some(principal_id),
            common::event_id(2),
            common::T0,
        ),
        common::observation(
            RiskEventKind::ConfirmedAbuse,
            1,
            source_id,
            subnet_id,
            Some(session_ua),
            Some(principal_id),
            common::event_id(3),
            common::T0,
        ),
    ];
    for o in &observations {
        store.observe(o).expect("observation applies");
    }

    // SCAN the namespace and pull every key, field name and value.
    let mut conn = client().get_connection().expect("connection");
    let pattern = format!("{{kiwi:{ns}}}:*");
    let scanned: Vec<String> = conn.scan_match(pattern).expect("scan").collect();
    assert!(!scanned.is_empty(), "scan must find the issued keys");

    let source_hex = hex::encode(source_id);
    assert!(
        scanned.iter().any(|k| k.contains(&source_hex)),
        "source pseudonym must be what got stored"
    );
    // Session/principal keys are OBSERVER-ONLY in risk.lua (HMGET, never
    // saved), so their pseudonyms never even enter the key space — the raw
    // principal id exists nowhere, in any form.
    let principal_hex = hex::encode(principal_id);
    assert!(
        !scanned.iter().any(|k| k.contains(&principal_hex)),
        "principal state is observer-only: its pseudonym must not be persisted"
    );

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
