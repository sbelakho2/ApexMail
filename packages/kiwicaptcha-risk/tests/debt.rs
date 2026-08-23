//! The risk-neutral ChallengeCancelled contract (real Redis, skipped
//! unless the Redis test URL is set): a cancellation never refunds issue
//! debt. The issued-and-abandoned challenge keeps its `iss` contribution —
//! the raw channel moves only by the natural leak (40 raw/s), and only an
//! actual SolveSuccess repays it. The adversarial shape (issue on source
//! A, cancel attributed to source B) is pinned too: neither identity's
//! debt changes, because the cancellation observation applies no state
//! mutation at all.
//!
//! The raw `iss` field is read from the Lua state hash itself (the same
//! keys the risk-state tests assert against), and every elapsed-time
//! expectation is bracketed by the Redis-clock readings around the script
//! executions, so a CI scheduling pause can never push an observation
//! across a timing boundary.

mod common;

use kiwicaptcha_risk::event::RiskEventKind;
use kiwicaptcha_risk::redis::RedisRiskStateStore;
use kiwicaptcha_risk::store::RiskStateStore;

fn client() -> redis::Client {
    redis::Client::open(common::redis_url().expect("RISK_REDIS_URL set")).expect("url parses")
}

/// Store with contract defaults on a fresh namespace.
fn store() -> RedisRiskStateStore {
    RedisRiskStateStore::new(client(), &common::unique_namespace("debt"))
        .with_io_timeouts(2_000, 2_000) // CI-jitter-proof test timeouts
}

/// The Redis server clock in milliseconds.
fn redis_now_ms() -> u64 {
    let mut conn = client().get_connection().expect("connection");
    let t: Vec<i64> = redis::cmd("TIME").query(&mut conn).expect("TIME");
    (t[0] * 1000 + t[1] / 1000) as u64
}

/// The raw `iss` field of the observation's current-epoch source hash.
fn raw_iss(store: &RedisRiskStateStore, o: &kiwicaptcha_risk::event::RiskObservation) -> i64 {
    let keys = RedisRiskStateStore::keys_for(
        store.namespace(),
        o.source_epoch,
        &o.source_id_prev,
        &o.source_id,
        &o.source_id_next,
        o.subnet_epoch,
        &o.subnet_id_prev,
        &o.subnet_id,
        &o.subnet_id_next,
        o.session_id.as_ref().map(|v| v.as_slice()),
        o.principal_id.as_ref().map(|v| v.as_slice()),
        &o.event_id,
    );
    let mut conn = client().get_connection().expect("connection");
    let v: Option<i64> = redis::cmd("HGET")
        .arg(&keys[0])
        .arg("iss")
        .query(&mut conn)
        .expect("HGET");
    v.unwrap_or(0)
}

/// The exact decay bracket for the raw `iss` of one ChallengeIssued unit
/// between the script executions bracketed by [t0..t1] (issue) and
/// [t2..t3] (cancel/solve). The Lua's own leak is 40 raw/s:
/// `leak = 1000 - floor(elapsed_ms * 40 / 1000)`, floored at 0.
/// Returns [min, max].
fn debt_bracket(t0: u64, t1: u64, t2: u64, t3: u64) -> (i64, i64) {
    let leak = |elapsed_ms: u64| -> i64 {
        let leaked = elapsed_ms.saturating_mul(40) / 1000;
        (1000_i64 - leaked as i64).max(0)
    };
    (leak(t3 - t0), leak(t2.saturating_sub(t1)))
}

#[test]
fn cancellation_never_refunds_the_issue_debt() {
    let Some(_url) = common::redis_url() else {
        eprintln!("skipping risk-neutral cancellation test: RISK_REDIS_URL not set");
        return;
    };
    let store = store();
    let source = hex::encode([0xAA; 16]);
    let subnet = hex::encode([0xBB; 16]);

    let t0 = redis_now_ms();
    store
        .observe(&common::observation(
            RiskEventKind::ChallengeIssued,
            1,
            source.clone(),
            subnet.clone(),
            None,
            None,
            common::event_id(1),
            common::T0,
        ))
        .expect("issue observation");
    let t1 = redis_now_ms();
    assert_eq!(
        raw_iss(
            &store,
            &common::observation(
                RiskEventKind::PreIssue,
                0,
                source.clone(),
                subnet.clone(),
                None,
                None,
                common::event_id(0),
                common::T0,
            )
        ),
        1000,
        "the issuance leaves exactly one unit of issue debt"
    );

    // A fresh ChallengeCancelled observation from the same source: the
    // debt stays at its post-issue value, moved only by the natural leak
    // inside the real elapsed bracket — never a −1000 refund (the
    // debt-restoring arm would have clamped it to 0).
    let t2 = redis_now_ms();
    let cancelled = store
        .observe(&common::observation(
            RiskEventKind::ChallengeCancelled,
            1,
            source.clone(),
            subnet.clone(),
            None,
            None,
            common::event_id(2),
            common::T0,
        ))
        .expect("cancel observation");
    let t3 = redis_now_ms();
    let (min, max) = debt_bracket(t0, t1, t2, t3);
    let after = raw_iss(
        &store,
        &common::observation(
            RiskEventKind::PreIssue,
            0,
            source.clone(),
            subnet.clone(),
            None,
            None,
            common::event_id(0),
            common::T0,
        ),
    );
    assert!(
        (min..=max).contains(&after),
        "the raw iss after the cancellation must sit in the natural-decay bracket [{min}, {max}], got {after}"
    );
    assert!(
        after > 0,
        "the issued-and-abandoned challenge keeps its issue-debt contribution"
    );
    assert_eq!(
        cancelled.vector.issue_debt,
        (after as u32 * 1000 / 6000).min(1000) as u16,
        "the returned vector mirrors the unchanged raw channel"
    );
}

#[test]
fn cancellation_from_another_source_touches_no_issue_debt() {
    let Some(_url) = common::redis_url() else {
        eprintln!("skipping risk-neutral cancellation test: RISK_REDIS_URL not set");
        return;
    };
    let store = store();
    let source_a = hex::encode([0xAA; 16]);
    let source_b = hex::encode([0xCC; 16]);
    let subnet = hex::encode([0xBB; 16]);
    let obs_a = |event, id| {
        common::observation(
            event,
            1,
            source_a.clone(),
            subnet.clone(),
            None,
            None,
            common::event_id(id),
            common::T0,
        )
    };
    let obs_b = |event, id| {
        common::observation(
            event,
            1,
            source_b.clone(),
            subnet.clone(),
            None,
            None,
            common::event_id(id),
            common::T0,
        )
    };

    store
        .observe(&obs_a(RiskEventKind::ChallengeIssued, 1))
        .expect("issue on A");
    assert_eq!(
        raw_iss(&store, &obs_a(RiskEventKind::PreIssue, 0)),
        1000,
        "source A holds the issued debt"
    );
    assert_eq!(
        raw_iss(&store, &obs_b(RiskEventKind::PreIssue, 0)),
        0,
        "source B has no debt"
    );

    // The cancellation is attributed to B (a different source identity):
    // A's debt is exactly unchanged (B's script never touches A's hash),
    // and B's stays zero.
    store
        .observe(&obs_b(RiskEventKind::ChallengeCancelled, 2))
        .expect("cancel from B");
    assert_eq!(
        raw_iss(&store, &obs_a(RiskEventKind::PreIssue, 0)),
        1000,
        "a cancellation from B never touches A's issue debt"
    );
    assert_eq!(
        raw_iss(&store, &obs_b(RiskEventKind::PreIssue, 0)),
        0,
        "B's debt is unchanged"
    );
}

#[test]
fn repeated_cancellations_never_refund_the_debt() {
    let Some(_url) = common::redis_url() else {
        eprintln!("skipping risk-neutral cancellation test: RISK_REDIS_URL not set");
        return;
    };
    let store = store();
    let source = hex::encode([0xAA; 16]);
    let subnet = hex::encode([0xBB; 16]);
    let obs = |event, id| {
        common::observation(
            event,
            1,
            source.clone(),
            subnet.clone(),
            None,
            None,
            common::event_id(id),
            common::T0,
        )
    };

    store
        .observe(&obs(RiskEventKind::ChallengeIssued, 1))
        .expect("issue");
    let t2 = redis_now_ms();
    for i in 2..7 {
        store
            .observe(&obs(RiskEventKind::ChallengeCancelled, i))
            .expect("repeat cancel");
    }
    let t3 = redis_now_ms();
    let after = raw_iss(&store, &obs(RiskEventKind::PreIssue, 0));
    // Five cancellations move the raw channel only by the natural leak
    // inside the real elapsed bracket — never by five −1000 steps.
    let leaked = |elapsed_ms: u64| -> i64 {
        (1000_i64 - (elapsed_ms.saturating_mul(40) / 1000) as i64).max(0)
    };
    assert!(
        (leaked(t3 - t2)..=1000).contains(&after),
        "repeated cancellations leave the debt in the natural-decay window, got {after}"
    );
    assert!(
        after > 0,
        "repeated cancellations never erase the issued-and-abandoned signal"
    );
}

#[test]
fn solve_still_repays_the_issue_debt() {
    let Some(_url) = common::redis_url() else {
        eprintln!("skipping risk-neutral cancellation test: RISK_REDIS_URL not set");
        return;
    };
    let store = store();
    let source = hex::encode([0xAA; 16]);
    let subnet = hex::encode([0xBB; 16]);
    let obs = |event, id| {
        common::observation(
            event,
            1,
            source.clone(),
            subnet.clone(),
            None,
            None,
            common::event_id(id),
            common::T0,
        )
    };

    store
        .observe(&obs(RiskEventKind::ChallengeIssued, 1))
        .expect("issue");
    assert_eq!(raw_iss(&store, &obs(RiskEventKind::PreIssue, 0)), 1000);
    store
        .observe(&obs(RiskEventKind::SolveSuccess, 2))
        .expect("solve");
    assert_eq!(
        raw_iss(&store, &obs(RiskEventKind::PreIssue, 0)),
        0,
        "a real SolveSuccess still repays the debt (clamped at zero)"
    );
}
