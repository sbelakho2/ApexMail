//! I29 property test: every refund and chargeback recorded at the provider is
//! recorded locally within 24 hours, whoever started it, exactly once.
//!
//! The audit's prescription (30 Oct, "Tests and enforcement", T4):
//!
//! > I29: every refund and chargeback recorded at the provider is recorded
//! > locally within 24 hours, whoever started it.
//!
//! Shape of the proof:
//!
//! * a **scripted provider double** (the same pattern as
//!   `payments::conformance::ConformanceProvider`) holds the provider's OWN
//!   view of a payment: refund objects created in the provider dashboard,
//!   refund updates (pending → processing → succeeded/failed), duplicate
//!   events, chargebacks opened and reversed. `*_as_of(minute)` answers the
//!   provider's current object at a synthetic-clock instant;
//! * a **sweep schedule** {no sweep, one, two, three sweeps} runs the
//!   reconciliation: at each sweep the driver asks the double for the
//!   current provider objects and calls the ENGINE functions the webhook and
//!   repair paths call — [`record_refund_fact`] and [`observe_dispute`];
//! * the **synthetic clock** (`MINUTE_ZERO` + whole minutes) is the only
//!   clock in the property: the 24-hour window is measured between the
//!   provider event and the first sweep at/after it, never against wall time.
//!
//! Asserted properties (every proptest case):
//!
//! 1. every provider refund/chargeback object that a sweep can see is one
//!    row in `payment_provider_refunds` / `payment_disputes` — never two,
//!    even after a duplicate event or a repeated sweep;
//! 2. the row's state equals the provider object's state as of the last
//!    sweep (refunds are additionally monotonic to `succeeded`, so a replayed
//!    stale fact can never un-refund);
//! 3. an object is recorded by the FIRST sweep at/after its creation, and
//!    that sweep is at most 1440 minutes (24 h) later — every generated
//!    schedule has gaps <= 24 h, so the reconciliation window is proven,
//!    not assumed;
//! 4. no sweep => no local fact (the system never invents one);
//! 5. each observed dispute outcome has exactly one `payment_provider_events`
//!    ledger fact and exactly one idempotent journal entry (opened: no money
//!    entry; lost: the debit; won/reversed: the restoration);
//! 6. replaying the final sweep changes nothing — the "exactly once" half of
//!    the invariant.
//!
//! The committed regression seed store lives in
//! `tests/proptest-regressions/invariants_property.txt`.

use billing_service::payments::engine::{observe_dispute, record_refund_fact};
use billing_service::payments::{Dispute, DisputeState, Refund, RefundState};
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use proptest::prelude::*;
use proptest::test_runner::{Config as ProptestConfig, TestRunner};
use sqlx::PgPool;
use std::sync::atomic::{AtomicU64, Ordering};

/// The synthetic clock's epoch. Every scripted time is `epoch + n minutes`;
/// the property never reads wall-clock time.
const MINUTE_ZERO: &str = "2026-01-01T00:00:00Z";

/// The reconciliation contract this property enforces.
const RECONCILIATION_WINDOW_MINUTES: u32 = 24 * 60;

fn minute_zero() -> DateTime<Utc> {
    MINUTE_ZERO
        .parse::<DateTime<Utc>>()
        .expect("synthetic clock epoch")
}

fn at_minute(minute: u32) -> DateTime<Utc> {
    minute_zero() + ChronoDuration::minutes(i64::from(minute))
}

/// The clock/window contract the property relies on: whole synthetic
/// minutes, and a 24-hour reconciliation window (the invariant's bound).
#[test]
fn synthetic_clock_is_whole_minutes_and_the_window_is_24_hours() {
    assert_eq!(at_minute(0), minute_zero());
    assert_eq!(
        (at_minute(1_440) - minute_zero()).num_minutes(),
        1_440,
        "the reconciliation window must be exactly 24 hours"
    );
    assert_eq!(RECONCILIATION_WINDOW_MINUTES, 1_440);
}

/// A provider-side refund object script: created at `created`, moves through
/// processing at `processing`, and reaches `final_state` at `resolved`.
/// Every sweep at or after a step sees that step's state (the provider's
/// current object), which is exactly how a dashboard-created refund looks to
/// a reconciliation sweep.
#[derive(Debug, Clone)]
struct RefundScript {
    id: u8,
    created: u32,
    processing: u32,
    resolved: u32,
    final_state: RefundState,
    amount_minor: i64,
}

impl RefundScript {
    fn state_as_of(&self, provider: &str, minute: u32) -> Option<Refund> {
        if minute < self.created {
            return None;
        }
        let state = if minute >= self.resolved {
            self.final_state
        } else if minute >= self.processing {
            RefundState::Processing
        } else {
            RefundState::Pending
        };
        Some(Refund {
            provider: provider.to_string(),
            provider_refund_id: format!("re_script_{provider}_{}", self.id),
            provider_payment_id: "tr_scripted_payment".to_string(),
            state,
            amount_minor: self.amount_minor,
            currency: "EUR".to_string(),
            created_at: Some(at_minute(self.created)),
        })
    }
}

/// A provider-side chargeback script: opened at `opened`; optionally resolved
/// (lost = money taken, won = reversed/restored) at `resolved`.
#[derive(Debug, Clone)]
struct DisputeScript {
    id: u8,
    opened: u32,
    resolved: Option<(u32, DisputeState)>,
    amount_minor: i64,
}

impl DisputeScript {
    fn state_as_of(&self, provider: &str, minute: u32) -> Option<Dispute> {
        if minute < self.opened {
            return None;
        }
        let state = match self.resolved {
            Some((resolved_at, terminal)) if minute >= resolved_at => terminal,
            _ => DisputeState::Opened,
        };
        Some(Dispute {
            provider: provider.to_string(),
            provider_dispute_id: format!("dp_script_{provider}_{}", self.id),
            provider_payment_id: "tr_scripted_payment".to_string(),
            state,
            amount_minor: self.amount_minor,
            currency: "EUR".to_string(),
            reason: Some("scripted dashboard chargeback".to_string()),
            opened_at: Some(at_minute(self.opened)),
        })
    }
}

#[derive(Debug, Clone)]
struct Scenario {
    refunds: Vec<RefundScript>,
    disputes: Vec<DisputeScript>,
    /// Sorted sweep instants (minutes from the epoch). Empty means "no sweep
    /// yet"; every generated schedule has first gap and inter-sweep gaps at
    /// most 24 h.
    sweeps: Vec<u32>,
}

fn refund_script_strategy() -> impl Strategy<Value = RefundScript> {
    (0u8..3, 0u32..2_880, 0u32..1_441, 1i64..=100_000).prop_map(
        |(id, created, to_processing, amount_minor)| {
            let processing = created.saturating_add(to_processing);
            // A refund reaches a terminal state within 24 h of processing in
            // this script; duplicate sweeps after resolution are the
            // "duplicate event" arm.
            RefundScript {
                id,
                created,
                processing,
                resolved: processing.saturating_add(60),
                final_state: if id % 2 == 0 {
                    RefundState::Succeeded
                } else {
                    RefundState::Failed
                },
                amount_minor,
            }
        },
    )
}

fn dispute_script_strategy() -> impl Strategy<Value = DisputeScript> {
    (
        0u8..3,
        0u32..2_880,
        prop::option::of((
            0u32..1_441,
            prop_oneof![Just(DisputeState::Lost), Just(DisputeState::Won)],
        )),
        1i64..=100_000,
    )
        .prop_map(|(id, opened, resolved, amount_minor)| DisputeScript {
            id,
            opened,
            resolved: resolved.map(|(after, terminal)| (opened.saturating_add(after), terminal)),
            amount_minor,
        })
}

/// A sweep schedule: first sweep within 24 h of the epoch, every later gap at
/// most 24 h — the reconciliation cadence the invariant assumes. Zero sweeps
/// is the explicit "no sweep yet" arm.
fn sweep_schedule_strategy() -> impl Strategy<Value = Vec<u32>> {
    (
        0u32..=RECONCILIATION_WINDOW_MINUTES,
        prop::collection::vec(1u32..=RECONCILIATION_WINDOW_MINUTES, 0..=2),
    )
        .prop_map(|(first, gaps)| {
            let mut sweeps = Vec::with_capacity(1 + gaps.len());
            let mut at = first;
            sweeps.push(at);
            for gap in gaps {
                at = at.saturating_add(gap);
                sweeps.push(at);
            }
            sweeps
        })
        // The "no sweep yet" arm is a first-class schedule.
        .prop_flat_map(|sweeps| prop_oneof![Just(Vec::new()), Just(sweeps)])
}

fn scenario_strategy() -> impl Strategy<Value = Scenario> {
    (
        prop::collection::vec(refund_script_strategy(), 0..=3),
        prop::collection::vec(dispute_script_strategy(), 0..=3),
        sweep_schedule_strategy(),
    )
        .prop_map(|(refunds, disputes, sweeps)| Scenario {
            // Re-key the scripts: a scenario must contain at most one
            // provider object per id (the property is about distinct
            // provider-side refunds/chargebacks, not colliding ids).
            refunds: refunds
                .into_iter()
                .enumerate()
                .map(|(index, mut script)| {
                    script.id = index as u8;
                    script
                })
                .collect(),
            disputes: disputes
                .into_iter()
                .enumerate()
                .map(|(index, mut script)| {
                    script.id = index as u8;
                    script
                })
                .collect(),
            sweeps,
        })
}

async fn db_pool(test_name: &str) -> Option<PgPool> {
    // `optional_pg_pool` applies the workspace's audit-F01 contract: an
    // unset TEST_DATABASE_URL soft-skips; a CONFIGURED provisioning failure
    // panics (never a green skip).
    migrator::test_support::optional_pg_pool(test_name, &format!("i29_{test_name}")).await
}

async fn row_counts(
    pool: &PgPool,
    provider: &str,
    refund_id: &str,
    dispute_id: &str,
) -> (i64, i64) {
    let refunds: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM payment_provider_refunds \
         WHERE provider = $1 AND provider_refund_id = $2",
    )
    .bind(provider)
    .bind(refund_id)
    .fetch_one(pool)
    .await
    .expect("count refund rows");
    let disputes: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM payment_disputes \
         WHERE provider = $1 AND provider_dispute_id = $2",
    )
    .bind(provider)
    .bind(dispute_id)
    .fetch_one(pool)
    .await
    .expect("count dispute rows");
    (refunds, disputes)
}

async fn refund_row_state(pool: &PgPool, provider: &str, refund_id: &str) -> Option<String> {
    sqlx::query_scalar(
        "SELECT state FROM payment_provider_refunds \
         WHERE provider = $1 AND provider_refund_id = $2",
    )
    .bind(provider)
    .bind(refund_id)
    .fetch_optional(pool)
    .await
    .expect("read refund row")
}

async fn dispute_row_state(pool: &PgPool, provider: &str, dispute_id: &str) -> Option<String> {
    sqlx::query_scalar(
        "SELECT state FROM payment_disputes \
         WHERE provider = $1 AND provider_dispute_id = $2",
    )
    .bind(provider)
    .bind(dispute_id)
    .fetch_optional(pool)
    .await
    .expect("read dispute row")
}

async fn dispute_event_kinds(pool: &PgPool, provider: &str, dispute_id: &str) -> Vec<String> {
    sqlx::query_scalar(
        "SELECT event_kind FROM payment_provider_events \
         WHERE provider = $1 AND provider_event_id LIKE $2 ORDER BY event_kind",
    )
    .bind(provider)
    .bind(format!("dispute:{dispute_id}:%"))
    .fetch_all(pool)
    .await
    .expect("read dispute event facts")
}

async fn journal_entries(pool: &PgPool, dispute_id: &str) -> Vec<String> {
    sqlx::query_scalar(
        "SELECT idempotency_key FROM journal_entries WHERE idempotency_key LIKE $1 \
         ORDER BY idempotency_key",
    )
    .bind(format!("dispute:{dispute_id}:%"))
    .fetch_all(pool)
    .await
    .expect("read dispute journal entries")
}

fn expected_state_str_refund(state: RefundState) -> &'static str {
    match state {
        RefundState::Pending => "pending",
        RefundState::Processing => "processing",
        RefundState::Succeeded => "succeeded",
        RefundState::Failed => "failed",
    }
}

fn expected_state_str_dispute(state: DisputeState) -> &'static str {
    match state {
        DisputeState::Opened => "opened",
        DisputeState::Lost => "lost",
        DisputeState::Won => "won",
    }
}

/// One sweep: read the provider's CURRENT objects and write the neutral
/// facts through the same engine functions the webhook/repair paths call.
async fn run_sweep(pool: &PgPool, provider: &str, scenario: &Scenario, minute: u32) {
    for script in &scenario.refunds {
        if let Some(refund) = script.state_as_of(provider, minute) {
            record_refund_fact(pool, &refund)
                .await
                .expect("refund fact write");
        }
    }
    for script in &scenario.disputes {
        if let Some(dispute) = script.state_as_of(provider, minute) {
            observe_dispute(pool, provider, &dispute)
                .await
                .expect("dispute fact write");
        }
    }
}

async fn run_scenario(pool: &PgPool, case: u64, scenario: &Scenario) -> Result<(), TestFailure> {
    let provider = format!("i29_scripted_{case}");

    // The first sweep at/after each object's creation. A probe validates the
    // 24-hour premise the schedule generator promises; a violated schedule
    // is a test-harness bug, not a system violation.
    for script in &scenario.refunds {
        if let Some(first) = scenario
            .sweeps
            .iter()
            .copied()
            .find(|s| *s >= script.created)
        {
            if first - script.created > RECONCILIATION_WINDOW_MINUTES {
                return Err(TestFailure(format!(
                    "schedule bug: first sweep {} is {} minutes after refund {} creation",
                    first,
                    first - script.created,
                    script.id
                )));
            }
        }
    }
    for script in &scenario.disputes {
        if let Some(first) = scenario
            .sweeps
            .iter()
            .copied()
            .find(|s| *s >= script.opened)
        {
            if first - script.opened > RECONCILIATION_WINDOW_MINUTES {
                return Err(TestFailure(format!(
                    "schedule bug: first sweep {} is {} minutes after dispute {} open",
                    first,
                    first - script.opened,
                    script.id
                )));
            }
        }
    }

    for sweep in &scenario.sweeps {
        run_sweep(pool, &provider, scenario, *sweep).await;

        // (3) everything the provider has shown by this sweep is recorded by
        // the FIRST sweep at/after its creation — this exact sweep.
        for script in &scenario.refunds {
            let refund_id = format!("re_script_{provider}_{}", script.id);
            let first_after = scenario
                .sweeps
                .iter()
                .copied()
                .find(|s| *s >= script.created);
            if first_after == Some(*sweep) {
                let (count, _) = row_counts(pool, &provider, &refund_id, "none").await;
                if count != 1 {
                    return Err(TestFailure(format!(
                        "refund {} must be recorded by its first sweep {} (rows={count})",
                        script.id, sweep
                    )));
                }
                // (2) the recorded state is the provider's state as of the
                // sweep that first saw it.
                let expected = script.state_as_of(&provider, *sweep).expect("visible");
                let actual = refund_row_state(pool, &provider, &refund_id).await;
                if actual.as_deref() != Some(expected_state_str_refund(expected.state)) {
                    return Err(TestFailure(format!(
                        "refund {} state {actual:?} != provider {} at sweep {}",
                        script.id,
                        expected_state_str_refund(expected.state),
                        sweep
                    )));
                }
            }
            // (4) an object the provider has NOT shown by this sweep has no
            // local fact.
            if *sweep < script.created {
                let (count, _) = row_counts(pool, &provider, &refund_id, "none").await;
                if count != 0 {
                    return Err(TestFailure(format!(
                        "refund {} has a local row before the provider created it",
                        script.id
                    )));
                }
            }
        }
        for script in &scenario.disputes {
            let dispute_id = format!("dp_script_{provider}_{}", script.id);
            let first_after = scenario
                .sweeps
                .iter()
                .copied()
                .find(|s| *s >= script.opened);
            if first_after == Some(*sweep) {
                let (_, count) = row_counts(pool, &provider, "none", &dispute_id).await;
                if count != 1 {
                    return Err(TestFailure(format!(
                        "dispute {} must be recorded by its first sweep {} (rows={count})",
                        script.id, sweep
                    )));
                }
            }
            if *sweep < script.opened {
                let (_, count) = row_counts(pool, &provider, "none", &dispute_id).await;
                if count != 0 {
                    return Err(TestFailure(format!(
                        "dispute {} has a local row before the provider opened it",
                        script.id
                    )));
                }
            }
        }
    }

    // After all sweeps: the provider's last-visible state is the local state.
    let last_sweep = scenario.sweeps.last().copied();
    for script in &scenario.refunds {
        let refund_id = format!("re_script_{provider}_{}", script.id);
        let (count, _) = row_counts(pool, &provider, &refund_id, "none").await;
        let visible = last_sweep.and_then(|sweep| script.state_as_of(&provider, sweep));
        match visible {
            Some(expected) => {
                if count != 1 {
                    return Err(TestFailure(format!(
                        "refund {} must be exactly one row (rows={count})",
                        script.id
                    )));
                }
                let actual = refund_row_state(pool, &provider, &refund_id).await;
                if actual.as_deref() != Some(expected_state_str_refund(expected.state)) {
                    return Err(TestFailure(format!(
                        "refund {} final state {actual:?} != provider {}",
                        script.id,
                        expected_state_str_refund(expected.state)
                    )));
                }
            }
            None => {
                if count != 0 {
                    return Err(TestFailure(format!(
                        "refund {} recorded without any sweep seeing it",
                        script.id
                    )));
                }
            }
        }
    }
    for script in &scenario.disputes {
        let dispute_id = format!("dp_script_{provider}_{}", script.id);
        let (_, count) = row_counts(pool, &provider, "none", &dispute_id).await;
        let visible = last_sweep.and_then(|sweep| script.state_as_of(&provider, sweep));
        let mut observed_states: Vec<DisputeState> = Vec::new();
        for sweep in &scenario.sweeps {
            if let Some(dispute) = script.state_as_of(&provider, *sweep) {
                if !observed_states.contains(&dispute.state) {
                    observed_states.push(dispute.state);
                }
            }
        }
        match visible {
            Some(expected) => {
                if count != 1 {
                    return Err(TestFailure(format!(
                        "dispute {} must be exactly one row (rows={count})",
                        script.id
                    )));
                }
                let actual = dispute_row_state(pool, &provider, &dispute_id).await;
                if actual.as_deref() != Some(expected_state_str_dispute(expected.state)) {
                    return Err(TestFailure(format!(
                        "dispute {} final state {actual:?} != provider {}",
                        script.id,
                        expected_state_str_dispute(expected.state)
                    )));
                }
            }
            None => {
                if count != 0 {
                    return Err(TestFailure(format!(
                        "dispute {} recorded without any sweep seeing it",
                        script.id
                    )));
                }
            }
        }

        // (5) one ledger fact per OBSERVED outcome; one journal entry per
        // observed terminal outcome (opened moves no money).
        let mut expected_kinds: Vec<String> = observed_states
            .iter()
            .map(|state| {
                let kind = match state {
                    DisputeState::Opened => "disputeOpened",
                    DisputeState::Lost => "disputeLost",
                    DisputeState::Won => "disputeWon",
                };
                format!("dispute:{dispute_id}:{kind}")
            })
            .collect();
        expected_kinds.sort();
        let actual_kinds: Vec<String> = dispute_event_kinds(pool, &provider, &dispute_id)
            .await
            .into_iter()
            .map(|kind| format!("dispute:{dispute_id}:{kind}"))
            .collect();
        if actual_kinds != expected_kinds {
            return Err(TestFailure(format!(
                "dispute {} ledger facts {actual_kinds:?} != observed outcomes {expected_kinds:?}",
                script.id
            )));
        }
        let mut expected_entries: Vec<String> = observed_states
            .iter()
            .filter_map(|state| match state {
                DisputeState::Lost => Some(format!("dispute:{dispute_id}:lost")),
                DisputeState::Won => Some(format!("dispute:{dispute_id}:won")),
                DisputeState::Opened => None,
            })
            .collect();
        expected_entries.sort();
        let actual_entries = journal_entries(pool, &dispute_id).await;
        if actual_entries != expected_entries {
            return Err(TestFailure(format!(
                "dispute {} journal entries {actual_entries:?} != observed terminal outcomes {expected_entries:?}",
                script.id
            )));
        }
    }

    // (6) EXACTLY ONCE: replay the final sweep (a duplicate provider
    // delivery) and prove every count is unchanged.
    if let Some(last) = last_sweep {
        let mut before = Vec::new();
        for script in &scenario.refunds {
            before.push(
                row_counts(
                    pool,
                    &provider,
                    &format!("re_script_{provider}_{}", script.id),
                    "none",
                )
                .await
                .0,
            );
        }
        let mut before_disputes = Vec::new();
        for script in &scenario.disputes {
            before_disputes.push(
                row_counts(
                    pool,
                    &provider,
                    "none",
                    &format!("dp_script_{provider}_{}", script.id),
                )
                .await
                .1,
            );
        }
        let mut before_events = Vec::new();
        let mut before_entries = Vec::new();
        for script in &scenario.disputes {
            let dispute_id = format!("dp_script_{provider}_{}", script.id);
            before_events.push(
                dispute_event_kinds(pool, &provider, &dispute_id)
                    .await
                    .len(),
            );
            before_entries.push(journal_entries(pool, &dispute_id).await.len());
        }

        run_sweep(pool, &provider, scenario, last).await;

        for (index, script) in scenario.refunds.iter().enumerate() {
            let after = row_counts(
                pool,
                &provider,
                &format!("re_script_{provider}_{}", script.id),
                "none",
            )
            .await
            .0;
            if after != before[index] {
                return Err(TestFailure(format!(
                    "replayed sweep duplicated refund {} ({before:?} -> {after})",
                    script.id
                )));
            }
        }
        for (index, script) in scenario.disputes.iter().enumerate() {
            let after = row_counts(
                pool,
                &provider,
                "none",
                &format!("dp_script_{provider}_{}", script.id),
            )
            .await
            .1;
            if after != before_disputes[index] {
                return Err(TestFailure(format!(
                    "replayed sweep duplicated dispute {}",
                    script.id
                )));
            }
            let dispute_id = format!("dp_script_{provider}_{}", script.id);
            if dispute_event_kinds(pool, &provider, &dispute_id)
                .await
                .len()
                != before_events[index]
            {
                return Err(TestFailure(format!(
                    "replayed sweep duplicated dispute {} ledger facts",
                    script.id
                )));
            }
            if journal_entries(pool, &dispute_id).await.len() != before_entries[index] {
                return Err(TestFailure(format!(
                    "replayed sweep duplicated dispute {} journal entries",
                    script.id
                )));
            }
        }
    }

    Ok(())
}

#[derive(Debug)]
struct TestFailure(String);

impl std::fmt::Display for TestFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for TestFailure {}

/// The property, driven by proptest's shrinking runner over a shared,
/// per-test canonical database. Every case is isolated by a unique provider
/// name (`i29_scripted_<case>`), so rows never leak between cases.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn i29_provider_refunds_and_chargebacks_are_recorded_exactly_once_within_24h() {
    let Some(pool) = db_pool("i29_property").await else {
        eprintln!("skipping I29 property: TEST_DATABASE_URL unset");
        return;
    };

    let counter = AtomicU64::new(0);
    let mut runner = TestRunner::new(ProptestConfig {
        cases: 48,
        max_shrink_iters: 2_000,
        // The committed regression seed store (audit T4: "proptest with a
        // committed regression file"). `Direct` because the crate's
        // lib.rs lives one directory down from the manifest root, which
        // defeats proptest's lib.rs discovery walk.
        failure_persistence: Some(Box::new(
            proptest::test_runner::FileFailurePersistence::Direct(
                "tests/proptest-regressions/invariants_property.txt",
            ),
        )),
        ..ProptestConfig::default()
    });
    let outcome = runner.run(&scenario_strategy(), |scenario| {
        let case = counter.fetch_add(1, Ordering::SeqCst);
        // proptest closures are synchronous; step onto the runtime's blocking
        // pool to await the database work on the SAME (multi-thread) runtime
        // that owns the pool.
        let result = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(run_scenario(&pool, case, &scenario))
        });
        result.map_err(|failure| TestCaseError::fail(failure.0))
    });
    pool.close().await;
    outcome.expect(
        "I29 property: every provider refund/chargeback is recorded exactly once within 24 hours",
    );
}
