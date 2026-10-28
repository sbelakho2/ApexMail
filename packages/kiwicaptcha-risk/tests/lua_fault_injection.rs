//! Fault injection at the embedded Lua mutation boundaries.
//!
//! The Rust core embeds the same canonical scripts as the PHP core. These
//! tests exercise the shared bytes directly: a wrong key type, a corrupt
//! persisted number and a command failure injected mid-script. The
//! invariant is that an error plus a retry leaves the same terminal state
//! as one uninterrupted execution.

use std::collections::HashMap;

use redis::Commands;

const RISK_V1: &str = include_str!("../resources/risk-v1.lua");
const REGISTER_DECISION: &str = include_str!("../resources/register_decision.lua");
const CONFIRM: &str = include_str!("../resources/confirm.lua");
const SHARDED_IDENTITY: &str = include_str!("../resources/sharded_identity.lua");
const TARGET_FAILURE: &str = include_str!("../resources/target_failure.lua");
const MARKS: &str = include_str!("../resources/marks.lua");

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

fn namespace(prefix: &str) -> String {
    use rand::RngCore;
    let mut suffix = [0u8; 4];
    rand::thread_rng().fill_bytes(&mut suffix);
    format!("{prefix}{}", hex::encode(suffix))
}

fn connection() -> Option<redis::Connection> {
    let url = redis_url()?;
    let client = redis::Client::open(url).expect("url parses");
    Some(client.get_connection().expect("connects"))
}

/// One state hash without clock/effect metadata, for equality checks.
fn signals(conn: &mut redis::Connection, key: &str) -> HashMap<String, String> {
    let mut fields: HashMap<String, String> = conn.hgetall(key).expect("hgetall");
    for ignored in ["ts", "cool", "fx"] {
        fields.remove(ignored);
    }
    fields
}

/// The adversarial convergence check: the interleaved A/B timelines are
/// separated by a few milliseconds of extra wall time, and the decay
/// leak deducts a handful of units for that (rf leaks 250 per second),
/// so exact equality would flake. A double application differs by 1000
/// or more — the tolerance never comes close to masking the invariant.
fn assert_signals_converged(conn: &mut redis::Connection, clean: &str, fault: &str, label: &str) {
    let clean_signals = signals(conn, clean);
    let fault_signals = signals(conn, fault);
    assert_eq!(
        clean_signals.len(),
        fault_signals.len(),
        "{label}: {clean_signals:?} vs {fault_signals:?}"
    );
    for (field, clean_value) in &clean_signals {
        let fault_value = fault_signals.get(field).expect("the same field set");
        let clean_number: f64 = clean_value.parse().expect("a numeric field");
        let fault_number: f64 = fault_value.parse().expect("a numeric field");
        assert!(
            (clean_number - fault_number).abs() <= 30.0,
            "{label}: field {field} differs beyond the leak tolerance (clean {clean_value}, fault {fault_value})"
        );
    }
}

fn inject_after(script: &str, anchor: &str) -> String {
    let position = script.find(anchor).expect("anchor exists") + anchor.len();
    format!(
        "{}\nerror('injected-command-failure')\n{}",
        &script[..position],
        &script[position..]
    )
}

fn invoke(
    conn: &mut redis::Connection,
    body: &str,
    keys: &[&str],
    args: &[String],
) -> redis::RedisResult<i64> {
    let script = redis::Script::new(body);
    let mut invocation = script.prepare_invoke();
    for key in keys {
        invocation.key(*key);
    }
    for arg in args {
        invocation.arg(arg);
    }
    invocation.invoke(conn)
}

fn invoke_array(
    conn: &mut redis::Connection,
    body: &str,
    keys: &[&str],
    args: &[String],
) -> redis::RedisResult<Vec<i64>> {
    let script = redis::Script::new(body);
    let mut invocation = script.prepare_invoke();
    for key in keys {
        invocation.key(*key);
    }
    for arg in args {
        invocation.arg(arg);
    }
    invocation.invoke(conn)
}

fn risk_args(event_id: &str) -> Vec<String> {
    [
        "1", "1", "0", event_id, "60", "1800", "60000", "8000", "100000", "6000", "4000", "3000",
        "2000", "6000", "10000", "70000", "10000", "10000", "1", "1", "1800", "1800",
    ]
    .iter()
    .map(|value| value.to_string())
    .collect()
}

fn risk_keys(ns: &str, event_id: &str) -> Vec<String> {
    let tag = format!("{{kiwi:{ns}}}");
    vec![
        format!("{tag}:risk:src:1:b"),
        format!("{tag}:risk:src:0:a"),
        format!("{tag}:risk:src:2:c"),
        format!("{tag}:risk:net:1:e"),
        format!("{tag}:risk:net:0:d"),
        format!("{tag}:risk:net:2:f"),
        format!("{tag}:risk:sess:s"),
        format!("{tag}:risk:prin:p"),
        format!("{tag}:risk:global"),
        format!("{tag}:risk:dd:{event_id}"),
    ]
}

fn key_refs(keys: &[String]) -> Vec<&str> {
    keys.iter().map(String::as_str).collect()
}

#[test]
fn risk_v1_corrupt_field_fails_before_any_write() {
    let Some(mut conn) = connection() else {
        eprintln!("skipping: RISK_REDIS_URL not set");
        return;
    };
    let ns = namespace("rsfi");
    let keys = risk_keys(&ns, "corrupt");
    let _: () = conn.hset(&keys[3], "rf", "nan").expect("seed corrupt");

    let result = invoke(&mut conn, RISK_V1, &key_refs(&keys), &risk_args("corrupt"));
    let error = result.expect_err("a non-finite state field must fail closed");
    assert!(error.to_string().contains("storage-corruption"), "{error}");
    let source_exists: i64 = conn.exists(&keys[0]).expect("exists");
    assert_eq!(source_exists, 0, "no source write before the refusal");
    let claim_exists: i64 = conn.exists(&keys[9]).expect("exists");
    assert_eq!(claim_exists, 0, "no dedupe claim before the refusal");

    let _: i64 = conn.del(key_refs(&keys)).expect("cleanup");
}

#[test]
fn risk_v1_wrong_type_fails_before_any_write() {
    let Some(mut conn) = connection() else {
        eprintln!("skipping: RISK_REDIS_URL not set");
        return;
    };
    let ns = namespace("rsfw");
    let keys = risk_keys(&ns, "wrongtype");
    let _: () = conn.set(&keys[3], "not-a-hash").expect("seed wrong type");

    let error = invoke(
        &mut conn,
        RISK_V1,
        &key_refs(&keys),
        &risk_args("wrongtype"),
    )
    .expect_err("a wrong key type must fail closed");
    assert!(error.to_string().contains("storage-corruption"), "{error}");
    let source_exists: i64 = conn.exists(&keys[0]).expect("exists");
    assert_eq!(source_exists, 0);

    let _: i64 = conn.del(key_refs(&keys)).expect("cleanup");
}

#[test]
fn risk_v1_injected_midway_retry_equals_one_execution() {
    let Some(mut conn) = connection() else {
        eprintln!("skipping: RISK_REDIS_URL not set");
        return;
    };
    let clean_ns = namespace("rsclean");
    let fault_ns = namespace("rsfault");
    let clean_keys = risk_keys(&clean_ns, "aaaa");
    let fault_keys = risk_keys(&fault_ns, "bbbb");

    invoke_array(
        &mut conn,
        RISK_V1,
        &key_refs(&clean_keys),
        &risk_args("aaaa"),
    )
    .expect("clean run");

    let injected = inject_after(RISK_V1, "save(KEYS[1], src, state_ttl, effect_marker)");
    let error = invoke(
        &mut conn,
        &injected,
        &key_refs(&fault_keys),
        &risk_args("bbbb"),
    )
    .expect_err("the injected failure aborts");
    assert!(
        error.to_string().contains("injected-command-failure"),
        "{error}"
    );
    let claim: i64 = conn.exists(&fault_keys[9]).expect("exists");
    assert_eq!(claim, 0, "an aborted invocation leaves no claim");

    invoke_array(
        &mut conn,
        RISK_V1,
        &key_refs(&fault_keys),
        &risk_args("bbbb"),
    )
    .expect("retry");

    for index in [0usize, 3, 6, 7, 8] {
        assert_eq!(
            signals(&mut conn, &clean_keys[index]),
            signals(&mut conn, &fault_keys[index]),
            "key {index} must carry exactly one event"
        );
    }
    let marker: Option<String> = conn.get(&fault_keys[9]).expect("marker");
    assert_eq!(marker.as_deref(), Some("1"));

    let _: i64 = conn
        .del(key_refs(&clean_keys))
        .and_then(|_: i64| conn.del(key_refs(&fault_keys)))
        .expect("cleanup");
}

/// The adversarial interleaving the per-event `fx` markers alone cannot
/// order: A applies its effects, keeps its effect completion key
/// (`fxdone`) but stops short of its dedupe claim; B then runs to
/// completion and clobbers every state's `fx` marker; A retries. The
/// retry must converge on the completion key — A's contribution lands
/// exactly once and the state ends at the post-A-and-B reference.
#[test]
fn risk_v1_completion_key_converges_an_interleaved_retry() {
    let Some(mut conn) = connection() else {
        eprintln!("skipping: RISK_REDIS_URL not set");
        return;
    };
    let clean_ns = namespace("rscv");
    let fault_ns = namespace("rsfv");
    // A and B share every state key of a namespace; only the dedupe
    // keys differ, so B's completion really does clobber the markers.
    let clean_a = risk_keys(&clean_ns, "aaaa");
    let clean_b = risk_keys(&clean_ns, "bbbb");
    let fault_a = risk_keys(&fault_ns, "aaaa");
    let fault_b = risk_keys(&fault_ns, "bbbb");

    // The reference: A fully, then B fully.
    invoke_array(&mut conn, RISK_V1, &key_refs(&clean_a), &risk_args("aaaa")).expect("clean A");
    invoke_array(&mut conn, RISK_V1, &key_refs(&clean_b), &risk_args("bbbb")).expect("clean B");

    // A applies its effects and stops after its completion key, before
    // its claim.
    let injected = inject_after(
        RISK_V1,
        "redis.call('SET', effect_done_key, '1', 'EX', dedupe_ttl)",
    );
    let error = invoke(
        &mut conn,
        &injected,
        &key_refs(&fault_a),
        &risk_args("aaaa"),
    )
    .expect_err("the injected failure aborts");
    assert!(
        error.to_string().contains("injected-command-failure"),
        "{error}"
    );
    let claim: i64 = conn.exists(&fault_a[9]).expect("exists");
    assert_eq!(claim, 0, "A stopped short of its claim");
    let completion: i64 = conn
        .exists(format!("{}:fxdone", fault_a[9]))
        .expect("exists");
    assert_eq!(completion, 1, "A's effect completion key stands");

    // B runs to completion: fx now says B on every state hash.
    invoke_array(&mut conn, RISK_V1, &key_refs(&fault_b), &risk_args("bbbb")).expect("B completes");

    // A retries: the completion key (not the clobbered markers) proves
    // the effects landed, so the retry only rewrites the claim.
    invoke_array(&mut conn, RISK_V1, &key_refs(&fault_a), &risk_args("aaaa")).expect("A retries");

    for index in [0usize, 3, 6, 7, 8] {
        assert_signals_converged(
            &mut conn,
            &clean_a[index],
            &fault_a[index],
            &format!("key {index} must carry A once and B once after the retry"),
        );
    }
    let a_claim: Option<String> = conn.get(&fault_a[9]).expect("marker");
    assert_eq!(a_claim.as_deref(), Some("1"), "the retry claims A");
    let b_claim: Option<String> = conn.get(&fault_b[9]).expect("marker");
    assert_eq!(b_claim.as_deref(), Some("1"), "B stays claimed");

    let _: i64 = conn
        .del(key_refs(&clean_a))
        .and_then(|_: i64| conn.del(key_refs(&clean_b)))
        .and_then(|_: i64| conn.del(key_refs(&fault_a)))
        .and_then(|_: i64| conn.del(key_refs(&fault_b)))
        .expect("cleanup");
}

#[test]
fn sharded_identity_injected_midway_retry_equals_one_execution() {
    let Some(mut conn) = connection() else {
        eprintln!("skipping: RISK_REDIS_URL not set");
        return;
    };
    let clean_ns = namespace("sicl");
    let fault_ns = namespace("sifl");
    let clean_keys = vec![
        format!("{{kiwi:{clean_ns}}}:risk:src:100:{}", "b".repeat(32)),
        format!("{{kiwi:{clean_ns}}}:risk:dd:aa"),
    ];
    let fault_keys = vec![
        format!("{{kiwi:{fault_ns}}}:risk:src:100:{}", "b".repeat(32)),
        format!("{{kiwi:{fault_ns}}}:risk:dd:bb"),
    ];
    let clean_args: Vec<String> = ["1", "1", "1", "1", "60", "aa", "1800"]
        .iter()
        .map(|v| v.to_string())
        .collect();
    let fault_args: Vec<String> = ["1", "1", "1", "1", "60", "bb", "1800"]
        .iter()
        .map(|v| v.to_string())
        .collect();

    invoke_array(
        &mut conn,
        SHARDED_IDENTITY,
        &key_refs(&clean_keys),
        &clean_args,
    )
    .expect("clean");
    let injected = inject_after(
        SHARDED_IDENTITY,
        "save(KEYS[1], s, state_ttl, effect_marker)",
    );
    invoke(&mut conn, &injected, &key_refs(&fault_keys), &fault_args)
        .expect_err("the injected failure aborts");
    let claim: i64 = conn.exists(&fault_keys[1]).expect("exists");
    assert_eq!(claim, 0);
    invoke_array(
        &mut conn,
        SHARDED_IDENTITY,
        &key_refs(&fault_keys),
        &fault_args,
    )
    .expect("retry");
    assert_eq!(
        signals(&mut conn, &clean_keys[0]),
        signals(&mut conn, &fault_keys[0])
    );
    let marker: Option<String> = conn.get(&fault_keys[1]).expect("marker");
    assert_eq!(marker.as_deref(), Some("1"));

    let _: i64 = conn.del(key_refs(&clean_keys)).expect("cleanup");
    let _: i64 = conn.del(key_refs(&fault_keys)).expect("cleanup");
}

/// The same interleaving on the sharded identity dimension: A keeps its
/// completion key but stops short of its claim; B clobbers the shard's
/// `fx` marker; A retries and must not double the increment.
#[test]
fn sharded_identity_completion_key_converges_an_interleaved_retry() {
    let Some(mut conn) = connection() else {
        eprintln!("skipping: RISK_REDIS_URL not set");
        return;
    };
    let clean_ns = namespace("sicv");
    let fault_ns = namespace("sifv");
    let clean_a = vec![
        format!("{{kiwi:{clean_ns}}}:risk:src:100:{}", "b".repeat(32)),
        format!("{{kiwi:{clean_ns}}}:risk:dd:aa"),
    ];
    let clean_b = vec![
        format!("{{kiwi:{clean_ns}}}:risk:src:100:{}", "b".repeat(32)),
        format!("{{kiwi:{clean_ns}}}:risk:dd:bb"),
    ];
    let fault_a = vec![
        format!("{{kiwi:{fault_ns}}}:risk:src:100:{}", "b".repeat(32)),
        format!("{{kiwi:{fault_ns}}}:risk:dd:aa"),
    ];
    let fault_b = vec![
        format!("{{kiwi:{fault_ns}}}:risk:src:100:{}", "b".repeat(32)),
        format!("{{kiwi:{fault_ns}}}:risk:dd:bb"),
    ];
    let args = |event: &str| -> Vec<String> {
        ["1", "1", "1", "1", "60", event, "1800"]
            .iter()
            .map(|v| v.to_string())
            .collect()
    };

    invoke_array(
        &mut conn,
        SHARDED_IDENTITY,
        &key_refs(&clean_a),
        &args("aa"),
    )
    .expect("clean A");
    invoke_array(
        &mut conn,
        SHARDED_IDENTITY,
        &key_refs(&clean_b),
        &args("bb"),
    )
    .expect("clean B");

    let injected = inject_after(
        SHARDED_IDENTITY,
        "redis.call('SET', effect_done_key, '1', 'EX', dedupe_ttl)",
    );
    invoke(&mut conn, &injected, &key_refs(&fault_a), &args("aa"))
        .expect_err("the injected failure aborts");
    let claim: i64 = conn.exists(&fault_a[1]).expect("exists");
    assert_eq!(claim, 0, "A stopped short of its claim");
    let completion: i64 = conn
        .exists(format!("{}:fxdone", fault_a[1]))
        .expect("exists");
    assert_eq!(completion, 1, "A's effect completion key stands");

    invoke_array(
        &mut conn,
        SHARDED_IDENTITY,
        &key_refs(&fault_b),
        &args("bb"),
    )
    .expect("B completes");
    invoke_array(
        &mut conn,
        SHARDED_IDENTITY,
        &key_refs(&fault_a),
        &args("aa"),
    )
    .expect("A retries");

    assert_signals_converged(
        &mut conn,
        &clean_a[0],
        &fault_a[0],
        "the shard must carry A once and B once after the retry",
    );
    let a_claim: Option<String> = conn.get(&fault_a[1]).expect("marker");
    assert_eq!(a_claim.as_deref(), Some("1"), "the retry claims A");

    let _: i64 = conn
        .del(key_refs(&clean_a))
        .and_then(|_: i64| conn.del(key_refs(&clean_b)))
        .and_then(|_: i64| conn.del(key_refs(&fault_a)))
        .and_then(|_: i64| conn.del(key_refs(&fault_b)))
        .expect("cleanup");
}

fn register_args(receipt: &str, sampled: bool) -> Vec<String> {
    vec![
        receipt.to_string(),
        "300".into(),
        if sampled { "1".into() } else { "0".into() },
        "86400".into(),
        "9000".into(),
        "1".into(),
        "0".into(),
        "300".into(),
        "1".into(),
    ]
}

#[test]
fn register_decision_injected_midway_books_one_sample() {
    let Some(mut conn) = connection() else {
        eprintln!("skipping: RISK_REDIS_URL not set");
        return;
    };
    let ns = namespace("rdft");
    let receipt_key = format!("{{kiwi:{ns}}}:cal:receipt:reg-1");
    let bucket_key = format!("{{kiwi:{ns}}}:cal:1:0");
    let ledger_key = format!("{{kiwi:{ns}}}:outcome:reg-1");
    let keys = [receipt_key, bucket_key.clone(), ledger_key];
    let receipt =
        r#"{"scope":1,"band":2,"action":"sha18","decision_hour":0,"score":300,"sampled":1}"#;
    let args = register_args(receipt, true);

    let injected = inject_after(
        REGISTER_DECISION,
        "local ledger_ok = redis.call('SET', KEYS[3], cjson.encode(ledger), 'NX', 'EX', ledger_ttl)",
    );
    invoke(&mut conn, &injected, &key_refs(&keys), &args).expect_err("the injected failure aborts");
    let missing: Option<String> = conn.hget(&bucket_key, "sample_total").expect("hget");
    assert_eq!(
        missing, None,
        "the aborted attempt leaves the denominator pending"
    );

    let registered = invoke(&mut conn, REGISTER_DECISION, &key_refs(&keys), &args).expect("retry");
    assert_eq!(registered, 1);
    let total: Option<String> = conn.hget(&bucket_key, "sample_total").expect("hget");
    assert_eq!(
        total.as_deref(),
        Some("1"),
        "the retry books exactly one sample"
    );
    let duplicate =
        invoke(&mut conn, REGISTER_DECISION, &key_refs(&keys), &args).expect("duplicate");
    assert_eq!(duplicate, 0);
    let total: Option<String> = conn.hget(&bucket_key, "sample_total").expect("hget");
    assert_eq!(total.as_deref(), Some("1"));

    let _: i64 = conn.del(key_refs(&keys)).expect("cleanup");
}

fn confirm_args() -> Vec<String> {
    ["2", "1", "1", "86400", "9000", "1", "0"]
        .iter()
        .map(|v| v.to_string())
        .collect()
}

#[test]
fn confirm_injected_after_bucket_retry_equals_one_execution() {
    let Some(mut conn) = connection() else {
        eprintln!("skipping: RISK_REDIS_URL not set");
        return;
    };
    let ns = namespace("cnft");
    let receipt_key = format!("{{kiwi:{ns}}}:cal:receipt:conf-1");
    let bucket_key = format!("{{kiwi:{ns}}}:cal:1:0");
    let ledger_key = format!("{{kiwi:{ns}}}:outcome:conf-1");
    let keys = [receipt_key, bucket_key.clone(), ledger_key];
    let receipt =
        r#"{"scope":1,"band":2,"action":"sha18","decision_hour":0,"score":300,"sampled":1}"#;
    invoke(
        &mut conn,
        REGISTER_DECISION,
        &key_refs(&keys),
        &register_args(receipt, true),
    )
    .expect("register");

    let injected = inject_after(CONFIRM, "redis.call('HSET', KEYS[2], unpack(fields))");
    invoke(&mut conn, &injected, &key_refs(&keys), &confirm_args())
        .expect_err("the injected failure aborts");
    let marker: Option<String> = conn.hget(&bucket_key, "fx:conf-1").expect("marker");
    assert_eq!(
        marker.as_deref(),
        Some("1"),
        "the bucket effect is recorded"
    );

    let status = invoke(&mut conn, CONFIRM, &key_refs(&keys), &confirm_args()).expect("retry");
    assert_eq!(status, 1);
    let count: Option<String> = conn.hget(&bucket_key, "legit_count").expect("count");
    assert_eq!(
        count.as_deref(),
        Some("1"),
        "the retry does not double the sample"
    );
    let score_sum: Option<String> = conn.hget(&bucket_key, "legit_score_sum").expect("sum");
    assert_eq!(score_sum.as_deref(), Some("300"));
    let marker: Option<String> = conn.hget(&bucket_key, "fx:conf-1").expect("marker");
    assert_eq!(marker, None, "the transient marker is removed");

    let _: i64 = conn.del(key_refs(&keys)).expect("cleanup");
}

#[test]
fn target_failure_injected_midway_books_once() {
    let Some(mut conn) = connection() else {
        eprintln!("skipping: RISK_REDIS_URL not set");
        return;
    };
    let ns = namespace("tfft");
    let tag = format!("{{kiwi:{ns}}}");
    let target = "5e2a9b4c1d7f38e6a0b5c9d2e4f6a813";
    let keys = vec![
        format!("{tag}:risk:tgt:{target}"),
        format!("{tag}:risk:tgt:src:{target}"),
        format!("{tag}:risk:tgt:asn:{target}"),
        format!("{tag}:risk:tgt:dd:report-1"),
    ];
    let args: Vec<String> = ["fail", "src-x", "as64500", "3600", "report-1", "60"]
        .iter()
        .map(|v| v.to_string())
        .collect();

    let injected = inject_after(TARGET_FAILURE, "redis.call('PEXPIRE', KEYS[1], ttl * 1000)");
    invoke_array(&mut conn, &injected, &key_refs(&keys), &args)
        .expect_err("the injected failure aborts");
    let claim: i64 = conn.exists(&keys[3]).expect("exists");
    assert_eq!(claim, 0, "an aborted report leaves no claim");

    let reply = invoke_array(&mut conn, TARGET_FAILURE, &key_refs(&keys), &args).expect("retry");
    assert_eq!(reply[0], 1, "the retry books exactly one failure");
    let spread: i64 = conn.pfcount(&keys[1]).expect("pfcount");
    assert_eq!(spread, 1, "the retry records one spread element");
    let marker: Option<String> = conn.get(&keys[3]).expect("marker");
    assert_eq!(marker.as_deref(), Some("1"));

    let _: i64 = conn.del(key_refs(&keys)).expect("cleanup");
}

/// The interleaving on the target dimension: A books its failure, keeps
/// its completion key but stops short of its claim; B books its own
/// (fx = B on the target hash); A retries and must not book twice.
#[test]
fn target_failure_completion_key_converges_an_interleaved_retry() {
    let Some(mut conn) = connection() else {
        eprintln!("skipping: RISK_REDIS_URL not set");
        return;
    };
    let clean_ns = namespace("tfcv");
    let fault_ns = namespace("tffv");
    let target = "5e2a9b4c1d7f38e6a0b5c9d2e4f6a813";
    let keys_with = |ns: &str, report: &str| -> Vec<String> {
        let tag = format!("{{kiwi:{ns}}}");
        vec![
            format!("{tag}:risk:tgt:{target}"),
            format!("{tag}:risk:tgt:src:{target}"),
            format!("{tag}:risk:tgt:asn:{target}"),
            format!("{tag}:risk:tgt:dd:{report}"),
        ]
    };
    let clean_a = keys_with(&clean_ns, "report-a");
    let clean_b = keys_with(&clean_ns, "report-b");
    let fault_a = keys_with(&fault_ns, "report-a");
    let fault_b = keys_with(&fault_ns, "report-b");
    // The event id rides ARGV[5]: A and B are different reports, so the
    // fx marker must never match across them.
    let args = |event: &str| -> Vec<String> {
        ["fail", "src-x", "as64500", "3600", event, "60"]
            .iter()
            .map(|v| v.to_string())
            .collect()
    };

    invoke_array(
        &mut conn,
        TARGET_FAILURE,
        &key_refs(&clean_a),
        &args("report-a"),
    )
    .expect("clean A");
    invoke_array(
        &mut conn,
        TARGET_FAILURE,
        &key_refs(&clean_b),
        &args("report-b"),
    )
    .expect("clean B");

    let injected = inject_after(
        TARGET_FAILURE,
        "redis.call('SET', effect_done_key, '1', 'EX', dedupe_ttl)",
    );
    invoke_array(&mut conn, &injected, &key_refs(&fault_a), &args("report-a"))
        .expect_err("the injected failure aborts");
    let claim: i64 = conn.exists(&fault_a[3]).expect("exists");
    assert_eq!(claim, 0, "A stopped short of its claim");
    let completion: i64 = conn
        .exists(format!("{}:fxdone", fault_a[3]))
        .expect("exists");
    assert_eq!(completion, 1, "A's effect completion key stands");

    invoke_array(
        &mut conn,
        TARGET_FAILURE,
        &key_refs(&fault_b),
        &args("report-b"),
    )
    .expect("B completes");
    invoke_array(
        &mut conn,
        TARGET_FAILURE,
        &key_refs(&fault_a),
        &args("report-a"),
    )
    .expect("A retries");

    let booked: i64 = conn.hget(&fault_a[0], "fails").expect("hget");
    let clean_booked: i64 = conn.hget(&clean_a[0], "fails").expect("hget");
    assert_eq!(booked, clean_booked, "A must be booked once, B once");
    assert_eq!(booked, 2, "two reports, two failures, never three");
    let a_claim: Option<String> = conn.get(&fault_a[3]).expect("marker");
    assert_eq!(a_claim.as_deref(), Some("1"), "the retry claims A");
    let b_claim: Option<String> = conn.get(&fault_b[3]).expect("marker");
    assert_eq!(b_claim.as_deref(), Some("1"), "B stays claimed");

    let _: i64 = conn
        .del(key_refs(&clean_a))
        .and_then(|_: i64| conn.del(key_refs(&clean_b)))
        .and_then(|_: i64| conn.del(key_refs(&fault_a)))
        .and_then(|_: i64| conn.del(key_refs(&fault_b)))
        .expect("cleanup");
}

/// The interleaving on the long-memory marks: A counts its mark, keeps
/// its completion key but stops short of its claim; B counts its own
/// (fx = B); A retries and must not count twice.
#[test]
fn marks_completion_key_converges_an_interleaved_retry() {
    let Some(mut conn) = connection() else {
        eprintln!("skipping: RISK_REDIS_URL not set");
        return;
    };
    let clean_ns = namespace("mkcv");
    let fault_ns = namespace("mkfv");
    let mark_with = |ns: &str, report: &str| -> Vec<String> {
        vec![
            format!(
                "mark:{{kiwi:{ns}}}:session:{}",
                "c7b3e1f9a5d24708b6e0c8a2f4d69123"
            ),
            format!(
                "mark:{{kiwi:{ns}}}:session:{}:dd:{report}",
                "c7b3e1f9a5d24708b6e0c8a2f4d69123"
            ),
        ]
    };
    let clean_a = mark_with(&clean_ns, "mark-a");
    let clean_b = mark_with(&clean_ns, "mark-b");
    let fault_a = mark_with(&fault_ns, "mark-a");
    let fault_b = mark_with(&fault_ns, "mark-b");
    // The event id rides ARGV[4]: A and B are different reports, so the
    // fx marker must never match across them.
    let args = |event: &str| -> Vec<String> {
        ["spamReported", "0", "60000", event]
            .iter()
            .map(|v| v.to_string())
            .collect()
    };

    // The reference: A counts once, B counts once — two reports.
    let clean_a_count =
        invoke(&mut conn, MARKS, &key_refs(&clean_a), &args("mark-a")).expect("clean A");
    assert_eq!(clean_a_count, 1);
    let clean_b_count =
        invoke(&mut conn, MARKS, &key_refs(&clean_b), &args("mark-b")).expect("clean B");
    assert_eq!(clean_b_count, 2);

    // A counts and stops after its completion key, before its claim.
    let injected = inject_after(
        MARKS,
        "if event_id ~= '' then\n    redis.call('SET', effect_done_key, '1', 'PX', RETRY_HORIZON_MS)\n",
    );
    let error = invoke(&mut conn, &injected, &key_refs(&fault_a), &args("mark-a"))
        .expect_err("the injected failure aborts");
    assert!(
        error.to_string().contains("injected-command-failure"),
        "{error}"
    );
    let claim: i64 = conn.exists(&fault_a[1]).expect("exists");
    assert_eq!(claim, 0, "A stopped short of its claim");
    let completion: i64 = conn
        .exists(format!("{}:fxdone", fault_a[1]))
        .expect("exists");
    assert_eq!(completion, 1, "A's effect completion key stands");

    // B counts (the mark hash's fx now says B), then A retries.
    let b_count = invoke(&mut conn, MARKS, &key_refs(&fault_b), &args("mark-b")).expect("B counts");
    assert_eq!(b_count, 2);
    let a_count =
        invoke(&mut conn, MARKS, &key_refs(&fault_a), &args("mark-a")).expect("A retries");
    assert_eq!(a_count, 2, "the retry answers without counting again");

    let count: String = conn.hget(&fault_a[0], "count").expect("hget");
    assert_eq!(count, "2", "A counted once, B once, never three");
    let a_claim: Option<String> = conn.get(&fault_a[1]).expect("marker");
    assert_eq!(a_claim.as_deref(), Some("1"), "the retry claims A");
    let b_claim: Option<String> = conn.get(&fault_b[1]).expect("marker");
    assert_eq!(b_claim.as_deref(), Some("1"), "B stays claimed");

    let _: i64 = conn
        .del(key_refs(&clean_a))
        .and_then(|_: i64| conn.del(key_refs(&clean_b)))
        .and_then(|_: i64| conn.del(key_refs(&fault_a)))
        .and_then(|_: i64| conn.del(key_refs(&fault_b)))
        .expect("cleanup");
}

#[test]
fn persisted_state_fuzz_corpus_is_refused() {
    let Some(mut conn) = connection() else {
        eprintln!("skipping: RISK_REDIS_URL not set");
        return;
    };
    let corpus = [
        "nan",
        "NaN",
        "inf",
        "-inf",
        "Infinity",
        "1e999",
        "-1e999",
        "1e309",
        "",
        "not-a-number",
        "1.5",
        "-1.5",
        "1e-3",
    ];
    for (index, value) in corpus.iter().enumerate() {
        let ns = namespace(&format!("rsfz{index}"));
        let keys = risk_keys(&ns, "fuzz");
        let _: () = conn.hset(&keys[3], "rf", *value).expect("seed corrupt");
        let error = invoke(&mut conn, RISK_V1, &key_refs(&keys), &risk_args("fuzz"))
            .expect_err("the fuzz corpus value must be refused");
        assert!(
            error.to_string().contains("storage-corruption"),
            "{value:?}: {error}"
        );
        let source_exists: i64 = conn.exists(&keys[0]).expect("exists");
        assert_eq!(source_exists, 0, "{value:?} must not write the source");
        let _: i64 = conn.del(key_refs(&keys)).expect("cleanup");
    }
}
