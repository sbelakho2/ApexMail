//! The target-failure leak watermark (target_failure.lua): one failure
//! leaks per minute, and the watermark must advance only by whole
//! leaked minutes — never reset to `now` on every write. A watermark
//! reset suspends the leak for as long as failures keep arriving less
//! than a minute apart (the stuffing-storm shape), so the counter never
//! walks back under the attack threshold.
//!
//! The scenario the test pins: three failures spaced 30 s apart. After
//! the third failure exactly one minute has elapsed since the
//! watermark's origin, so exactly one failure must have leaked
//! (`fails = 3 - 1 = 2`). With a `ts = now` reset the remainder is
//! erased on every write and the third failure would read `fails = 3`.
//!
//! The clock is Redis TIME inside the script, so the test backdates the
//! stored `ts` watermark between calls to emulate the 30 s spacings.

use kiwicaptcha_risk::keyspace::target_state_keys;
use kiwicaptcha_risk::redis::RedisRiskStateStore;
use kiwicaptcha_risk::store::{RiskStateStore, TargetState};

const TARGET: &str = "5e2a9b4c1d7f38e6a0b5c9d2e4f6a813";

fn redis_url() -> Option<String> {
    std::env::var("RISK_REDIS_URL")
        .ok()
        .filter(|url| !url.is_empty())
        .map(|raw| {
            raw.strip_prefix("tcp://")
                .map(|rest| format!("redis://{rest}"))
                .unwrap_or(raw)
        })
}

fn unique_namespace() -> String {
    use rand::RngCore;
    let mut suffix = [0u8; 4];
    rand::thread_rng().fill_bytes(&mut suffix);
    format!("tfleak{}", hex::encode(suffix))
}

#[test]
fn sub_minute_failures_still_leak_one_per_minute() {
    let Some(url) = redis_url() else {
        eprintln!("skipping: RISK_REDIS_URL not set");
        return;
    };
    let client = ::redis::Client::open(url).expect("url parses");
    let namespace = unique_namespace();
    let store = RedisRiskStateStore::new(client.clone(), &namespace).with_io_timeouts(2_000, 2_000);

    // Failure 1: the record is created, the watermark stamps `now`.
    let state = store
        .register_target_failure(TARGET, "src100000000000000000000000000", "as64496")
        .expect("fail 1");
    assert_eq!(state.fails, 1);
    let key = target_state_keys(&namespace, TARGET)[0].clone();
    let mut conn = client.get_connection().expect("connection");
    let t1: i64 = redis::Commands::hget(&mut conn, key.as_str(), "ts").expect("ts field");
    assert!(t1 > 0, "the first write stamps the watermark");

    // Emulate "30 s later": backdate the watermark 30 s behind the
    // script's clock.
    redis::Commands::hset::<_, _, _, i64>(&mut conn, key.as_str(), "ts", t1 - 30_000).unwrap();

    // Failure 2 (30 s after the origin): no whole minute has passed, so
    // nothing leaks — but the watermark must keep the 30 s remainder
    // instead of resetting to `now`.
    let state = store
        .register_target_failure(TARGET, "src200000000000000000000000000", "as64496")
        .expect("fail 2");
    assert_eq!(state.fails, 2);
    let ts_after_2: i64 = redis::Commands::hget(&mut conn, key.as_str(), "ts").expect("ts field");
    assert!(
        ts_after_2 < t1,
        "the watermark must not reset to now on a sub-minute failure (got {ts_after_2}, t1 {t1})"
    );

    // Emulate "30 s later still" (60 s since the watermark's origin):
    // backdate the surviving watermark another 30 s.
    redis::Commands::hset::<_, _, _, i64>(&mut conn, key.as_str(), "ts", ts_after_2 - 30_000)
        .unwrap();

    // Failure 3: exactly one full minute has now elapsed since the
    // watermark origin, so exactly one failure leaks before this write
    // is counted: fails = 2 - 1 + 1 = 2 (a `ts = now` reset would have
    // erased the remainders and answered 3).
    let state: TargetState = store
        .register_target_failure(TARGET, "src300000000000000000000000000", "as64496")
        .expect("fail 3");
    assert_eq!(
        state.fails, 2,
        "one failure must leak after a minute of sub-minute-spaced failures (got {})",
        state.fails
    );

    // Cleanup: the target's own key family.
    let keys = target_state_keys(&namespace, TARGET);
    let _: i64 = redis::Commands::del(&mut conn, keys.to_vec()).unwrap();
}
