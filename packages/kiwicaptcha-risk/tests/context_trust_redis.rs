//! Context-bound trust against real Redis (skipped unless
//! `RISK_REDIS_URL` is set; start one with
//! `redis-server --port 6423 --save "" --appendonly no`): the
//! thousand-foreign-buckets replay earns nothing, the home-to-mobile
//! commute keeps home credit fully effective, the record TTL follows
//! the session dimension, and the surface validates its ids fail
//! closed. The PHP mirror is `tests/ContextBoundTrustRedisTest.php`.
//!
//! Decay is time-based (2 raw units per second), so the keep-home-credit
//! assertions allow a small wall-clock slack: a foreign presentation
//! itself must never remove a unit, only the passage of time can.

mod common;

use std::net::IpAddr;

use kiwicaptcha_risk::asn::AsnDataset;
use kiwicaptcha_risk::redis::RedisRiskStateStore;
use kiwicaptcha_risk::trust::{bucket_trust_credit, ContextBoundTrust};

/// The session pseudonym (32 lowercase hex chars).
const SESSION: &str = "c7b3e1f9a5d24708b6e0c8a2f4d69123";

/// Wall-clock slack for the decay channel: five seconds of leakage.
const DECAY_SLACK: u32 = 10;

fn dataset() -> AsnDataset {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../protocol/asn/sample-asn.tsv"
    );
    AsnDataset::open(path).expect("the sample dataset opens")
}

fn connection() -> redis::Connection {
    let url = common::redis_url().expect(
        "RISK_REDIS_URL not set; start redis with: redis-server --port 6423 --save \"\" --appendonly no",
    );
    let client = redis::Client::open(url).expect("url parses");
    client.get_connection().expect("test connection opens")
}

fn del_key(conn: &mut redis::Connection, key: &str) {
    redis::cmd("DEL")
        .arg(key)
        .query::<i64>(conn)
        .expect("cleanup del");
}

fn ttl_of(conn: &mut redis::Connection, key: &str) -> i64 {
    redis::cmd("TTL")
        .arg(key)
        .query::<i64>(conn)
        .expect("ttl reads")
}

fn ip(text: &str) -> IpAddr {
    text.parse().unwrap()
}

#[test]
fn a_thousand_foreign_buckets_earn_nothing() {
    let Some(_) = common::redis_url() else {
        eprintln!("RISK_REDIS_URL not set; skipping");
        return;
    };
    let mut conn = connection();
    let client = redis::Client::open(common::redis_url().unwrap()).expect("url parses");
    let store = RedisRiskStateStore::new(client, &common::unique_namespace("botnet"))
        .with_io_timeouts(2_000, 2_000);
    let dataset = dataset();
    let facade = ContextBoundTrust::new(&dataset, &store);

    // The session earns full home credit in its home bucket.
    let home = facade
        .earn(SESSION, ip("198.51.100.42"), 10_000)
        .expect("earn");
    assert_eq!(home.credit, 1000);
    assert!(home.is_home);

    // A trusted cookie replayed from one thousand distinct foreign
    // buckets earns nothing: each foreign bucket starts empty, and the
    // credit decision reads only that foreign record.
    for n in 0u32..1000 {
        let foreign_ip = ip(&format!("{}.{}.0.1", 45 + (n / 250), (n % 250) + 1));
        let decision = facade.credit_for(SESSION, foreign_ip).expect("credit_for");
        assert_eq!(decision.credit, 0, "foreign bucket {n} must earn nothing");
        assert!(!decision.is_home);
    }

    // The home record is untouched by every foreign presentation; only
    // the decay channel may shave the slack window.
    let home_after = facade
        .credit_for(SESSION, ip("198.51.100.42"))
        .expect("home credit");
    assert!(
        home_after.raw_trust + DECAY_SLACK >= 10_000,
        "home trust survives the foreign replay (got {})",
        home_after.raw_trust
    );
    assert!(
        home_after.credit >= 1000 - (DECAY_SLACK / 10) as u16,
        "home credit stays effectively full (got {})",
        home_after.credit
    );

    let home_key = store
        .bucket_trust_key(SESSION, home.bucket.as_str())
        .expect("the home key resolves");
    del_key(&mut conn, &home_key);
}

#[test]
fn the_home_to_mobile_commute_keeps_home_credit() {
    let Some(_) = common::redis_url() else {
        eprintln!("RISK_REDIS_URL not set; skipping");
        return;
    };
    let mut conn = connection();
    let client = redis::Client::open(common::redis_url().unwrap()).expect("url parses");
    let store = RedisRiskStateStore::new(client, &common::unique_namespace("commute"))
        .with_io_timeouts(2_000, 2_000);
    let dataset = dataset();
    let facade = ContextBoundTrust::new(&dataset, &store);
    let home_ip = ip("198.51.100.42");

    let earned = facade.earn(SESSION, home_ip, 8_000).expect("earn at home");
    assert_eq!(earned.credit, 800);

    // A commute through foreign networks: reads only, never a write to
    // the home record, and each foreign read earns nothing.
    for foreign in ["203.0.113.150", "8.8.8.8", "2600::1", "2001:db8:5::1"] {
        let decision = facade
            .credit_for(SESSION, ip(foreign))
            .expect("foreign read");
        assert_eq!(decision.credit, 0, "{foreign} earns nothing");
    }

    // Presenting from home again: the full home credit applies, never
    // reduced by the foreign presentations themselves.
    let back_home = facade.credit_for(SESSION, home_ip).expect("home again");
    assert_eq!(back_home.bucket, earned.bucket);
    assert!(
        back_home.raw_trust + DECAY_SLACK >= 8_000,
        "home trust survives the commute (got {})",
        back_home.raw_trust
    );
    assert!(
        back_home.credit >= 800 - (DECAY_SLACK / 10) as u16,
        "home credit stays effectively full (got {})",
        back_home.credit
    );

    // Earning more at home accumulates within the ceiling.
    let topped = facade.earn(SESSION, home_ip, 5_000).expect("earn more");
    assert!(topped.raw_trust + DECAY_SLACK >= 10_000);
    assert_eq!(topped.credit, 1000);

    let home_key = store
        .bucket_trust_key(SESSION, "a64498")
        .expect("the home key resolves");
    del_key(&mut conn, &home_key);
}

#[test]
fn records_carry_the_session_dimension_ttl_and_pure_reads() {
    let Some(_) = common::redis_url() else {
        eprintln!("RISK_REDIS_URL not set; skipping");
        return;
    };
    let mut conn = connection();
    let client = redis::Client::open(common::redis_url().unwrap()).expect("url parses");
    let store = RedisRiskStateStore::new(client, &common::unique_namespace("ttlive"))
        .with_io_timeouts(2_000, 2_000);
    let dataset = dataset();
    let facade = ContextBoundTrust::new(&dataset, &store);

    let key = store
        .bucket_trust_key(SESSION, "a64498")
        .expect("the key resolves");
    let earned = facade
        .earn(SESSION, ip("198.51.100.42"), 3_000)
        .expect("earn");
    let before = ttl_of(&mut conn, &key);
    assert!(
        before > 0 && before <= 1800,
        "the record TTL follows the session dimension (got {before}s)"
    );

    // A pure read never refreshes the TTL nor mutates the record: after
    // a measurable pause the TTL keeps falling through the reads.
    std::thread::sleep(std::time::Duration::from_millis(1_100));
    let read = facade
        .credit_for(SESSION, ip("198.51.100.42"))
        .expect("pure read");
    assert!(
        read.raw_trust <= earned.raw_trust,
        "a read never adds trust"
    );
    let through_reads = ttl_of(&mut conn, &key);
    assert!(
        through_reads < before,
        "a read must not refresh the TTL ({through_reads}s vs {before}s)"
    );

    del_key(&mut conn, &key);
}

#[test]
fn the_surface_validates_its_ids_fail_closed() {
    let Some(_) = common::redis_url() else {
        eprintln!("RISK_REDIS_URL not set; skipping");
        return;
    };
    let mut conn = connection();
    let client = redis::Client::open(common::redis_url().unwrap()).expect("url parses");
    let store = RedisRiskStateStore::new(client, &common::unique_namespace("tvalid"))
        .with_io_timeouts(2_000, 2_000);

    for bad_session in ["", "NOTHEX", "c7b3e1f9a5d24708b6e0c8a2f4d6912"] {
        assert!(
            store.bucket_trust_key(bad_session, "a1").is_err(),
            "{bad_session:?} must be refused as a session id"
        );
    }
    for bad_bucket in ["", "a0", "u4/65536", "u6/20010db", "x1", "a64496:x"] {
        assert!(
            store.bucket_trust_key(SESSION, bad_bucket).is_err(),
            "{bad_bucket:?} must be refused as a bucket id"
        );
    }
    assert!(store.bucket_trust_key(SESSION, "a64496").is_ok());
    assert!(
        store.credit_bucket_trust(SESSION, "a1", 100_001).is_err(),
        "an over-bound delta must be refused before Redis"
    );

    // The policy computation and the record surface agree on the band.
    store
        .credit_bucket_trust(SESSION, "a1", 2_500)
        .expect("credit");
    let raw = store.read_bucket_trust(SESSION, "a1").expect("read");
    let decision = bucket_trust_credit("a1", Some(raw));
    assert!(raw <= 2_500, "decay can only lower the raw record");
    assert!(decision.credit <= 250);

    let key = store
        .bucket_trust_key(SESSION, "a1")
        .expect("the key resolves");
    del_key(&mut conn, &key);
}
