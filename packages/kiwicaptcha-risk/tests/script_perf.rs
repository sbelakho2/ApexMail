//! AUDIT #101 — SLOW-SCRIPT GUARD (a guard, NOT a benchmark): the
//! verification-path scripts (risk-v1.lua + the calibration read) must run
//! well under a generous bound when the state is at its MAXIMUM allowed
//! size (every key carrying its full bounded field set — 12 flat fields
//! per risk state hash, 6 fields per calibration bucket, all 24 buckets +
//! state present). The asserted bound is a generous 50 ms AVERAGE over
//! 100 runs so CI noise can never flake it; typical means are
//! sub-millisecond. Skipped unless RISK_REDIS_URL is set.

mod common;

const RUNS: usize = 100;
const AVG_BUDGET_MS: f64 = 50.0; // generous CI-safe guard, not a spec

const RISK_V1_LUA: &str = include_str!("../resources/risk-v1.lua");
const CALIBRATION_LUA: &str = include_str!("../resources/calibration.lua");

fn client() -> redis::Client {
    redis::Client::open(common::redis_url().expect("RISK_REDIS_URL set")).expect("url parses")
}

fn unique_namespace(prefix: &str) -> String {
    common::unique_namespace(prefix)
}

/// The 12 STATE_FIELDS of the risk state hashes at their maximum.
fn seed_risk_state(conn: &mut redis::Connection, key: &str, now: i64) {
    let cmd = redis::Cmd::hset_multiple(
        key,
        &[
            ("ts", now.to_string()),
            ("rf", "999999999".to_string()),
            ("rs", "999999999".to_string()),
            ("iss", "999999999".to_string()),
            ("bad", "999999999".to_string()),
            ("mal", "999999999".to_string()),
            ("rep", "999999999".to_string()),
            ("af", "999999999".to_string()),
            ("sw", "999999999".to_string()),
            ("trust", "999999999".to_string()),
            ("scope", "1".to_string()),
            ("cool", "0".to_string()),
        ],
    );
    cmd.query::<()>(conn).expect("seed risk state");
}

/// All 6 flat bucket fields on a calibration bucket.
fn seed_bucket(conn: &mut redis::Connection, key: &str) {
    redis::Cmd::hset_multiple(
        key,
        &[
            ("legit_count", "1000000".to_string()),
            ("legit_score_sum", "1000000000".to_string()),
            ("abuse_count", "1000000".to_string()),
            ("abuse_score_sum", "1000000000".to_string()),
            ("sample_total", "1000000".to_string()),
            ("sample_resolved", "900000".to_string()),
        ],
    )
    .query::<()>(conn)
    .expect("seed bucket");
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}

/// risk-v1.lua under MAXIMUM state (all 10 keys present with all 12
/// fields, full event path — session/principal present, dedupe miss):
/// 100 runs must average under the generous 50 ms guard.
#[test]
fn risk_v1_average_stays_under_budget_at_maximum_state() {
    let Some(_url) = common::redis_url() else {
        eprintln!("skipping script-bound guard: RISK_REDIS_URL not set");
        return;
    };
    let mut conn = client().get_connection().expect("connection");
    let ns = unique_namespace("sbr");
    let now = now_ms();

    let mut keys: Vec<String> = Vec::with_capacity(10);
    for i in 0..9 {
        let key = format!("{{kiwi:{ns}}}:risk:perf:{i}");
        keys.push(key.clone());
        seed_risk_state(&mut conn, &key, now);
    }

    let script = redis::Script::new(RISK_V1_LUA);
    let mut times = Vec::with_capacity(RUNS);
    for i in 0..RUNS {
        let dedupe_key = format!("{{kiwi:{ns}}}:risk:dedupe:evt{i}");
        let mut invoke = script.prepare_invoke();
        for key in &keys {
            invoke.key(key.as_str());
        }
        invoke.key(dedupe_key.as_str());
        // event=1 PreIssue, scope 1, now, fresh event_id (dedupe miss),
        // dedupe_ttl 60, state_ttl 1800, hysteresis 60000, saturations,
        // has_session 1, has_principal 1, session_ttl 1800, principal_ttl 86400.
        invoke
            .arg("1")
            .arg("1")
            .arg(now.to_string())
            .arg(format!("{i:032x}"))
            .arg("60")
            .arg("1800")
            .arg("60000")
            .arg("8000")
            .arg("100000")
            .arg("6000")
            .arg("4000")
            .arg("3000")
            .arg("2000")
            .arg("6000")
            .arg("10000")
            .arg("70000")
            .arg("10000")
            .arg("10000")
            .arg("1")
            .arg("1")
            .arg("1800")
            .arg("86400");
        let start = std::time::Instant::now();
        let result: Vec<i64> = invoke.invoke(&mut conn).expect("risk-v1 runs");
        times.push(start.elapsed().as_secs_f64() * 1_000_000.0); // µs
        assert_eq!(
            result.len(),
            16,
            "the script must return the full 16-element vector"
        );
    }

    let mean_us = times.iter().sum::<f64>() / RUNS as f64;
    println!(
        "ScriptBoundPerf: risk-v1.lua {RUNS} runs at max state, mean {mean_us:.2} µs (guard: avg < {AVG_BUDGET_MS:.0} ms)"
    );
    assert!(
        mean_us < AVG_BUDGET_MS * 1000.0,
        "risk-v1.lua average {mean_us:.2} µs exceeds the {AVG_BUDGET_MS:.0} ms guard"
    );
}

/// calibration.lua under MAXIMUM state (24 buckets × 6 fields + rate
/// state): 100 runs must average under the generous 50 ms guard.
#[test]
fn calibration_average_stays_under_budget_at_maximum_state() {
    let Some(_url) = common::redis_url() else {
        eprintln!("skipping script-bound guard: RISK_REDIS_URL not set");
        return;
    };
    let mut conn = client().get_connection().expect("connection");
    let ns = unique_namespace("sbc");
    let now = now_ms();
    let hour = now / 3_600_000;

    let mut keys: Vec<String> = Vec::with_capacity(25);
    for i in 0..24 {
        let key = format!("{{kiwi:{ns}}}:cal:1:{}", hour - i);
        keys.push(key.clone());
        seed_bucket(&mut conn, &key);
    }
    keys.push(format!("{{kiwi:{ns}}}:cal:state:1"));

    let script = redis::Script::new(CALIBRATION_LUA);
    let mut times = Vec::with_capacity(RUNS);
    for _ in 0..RUNS {
        let mut invoke = script.prepare_invoke();
        for key in &keys {
            invoke.key(key.as_str());
        }
        invoke
            .arg(now.to_string())
            .arg("1000") // min_samples
            .arg("150") // max_adjustment
            .arg("10") // max_change_per_minute
            .arg("0.80") // minimum_resolution_ratio
            .arg("1") // random_sample
            .arg("1.0") // false_positive_cost
            .arg("2.0"); // false_negative_cost
        let start = std::time::Instant::now();
        let bias: i64 = invoke.invoke(&mut conn).expect("calibration runs");
        times.push(start.elapsed().as_secs_f64() * 1_000_000.0); // µs
        assert!(
            (-150..=150).contains(&bias),
            "the calibration read must return a bounded integer bias (got {bias})"
        );
    }

    let mean_us = times.iter().sum::<f64>() / RUNS as f64;
    println!(
        "ScriptBoundPerf: calibration.lua {RUNS} runs at max state, mean {mean_us:.2} µs (guard: avg < {AVG_BUDGET_MS:.0} ms)"
    );
    assert!(
        mean_us < AVG_BUDGET_MS * 1000.0,
        "calibration.lua average {mean_us:.2} µs exceeds the {AVG_BUDGET_MS:.0} ms guard"
    );
}
