//! Provider throttle at the relay's effect boundary.
//!
//! The decision engine itself is unit-tested in `outbound_mta::throttle`;
//! these tests prove the RELAY wiring: a throttled submission is requeued
//! durably (never sent, never marked permanent) before any SMTP connection,
//! and a 0 % override lets the same submission through.

use std::sync::Arc;

use outbound_mta::test_support::{FakeSmtpConfig, FakeSmtpServer, MemoryLedger, StaticMxResolver};
use outbound_mta::throttle::{ProviderThrottle, THROTTLE_RETRY_DELAY};
use outbound_mta::warmup::WarmupGate;
use outbound_mta::{Relay, RelayConfig, RelayError, SubmitRequest};

async fn test_pool(name: &str) -> Option<sqlx::PgPool> {
    match migrator::test_support::fresh_canonical_pool(name, name).await {
        Ok(pool) => pool,
        Err(error) => panic!("{}", error.panic_message()),
    }
}

fn unit(prefix: &str) -> String {
    format!("{prefix}:{}", uuid::Uuid::new_v4().simple())
}

fn request(send_unit: &str) -> SubmitRequest {
    SubmitRequest {
        send_unit: send_unit.to_string(),
        tenant_id: Some("tenant-throttle".into()),
        queue_id: None,
        envelope_from: Some("sender@example.com".into()),
        recipients: vec!["user@gmail.com".into()],
        message: b"From: sender@example.com\r\nTo: user@gmail.com\r\nSubject: hi\r\n\r\nbody"
            .to_vec(),
        requested_source_ip: None,
    }
}

async fn insert_override(pool: &sqlx::PgPool, pct: i32) {
    sqlx::query(
        "INSERT INTO outbound_provider_throttle_overrides
           (tenant_id, provider, throttle_pct, reason)
         VALUES (NULL, 'google', $1, 'relay throttle gate test')",
    )
    .bind(pct)
    .execute(pool)
    .await
    .expect("insert override");
}

#[tokio::test]
async fn throttled_submission_is_requeued_before_any_smtp_connection() {
    let Some(pool) = test_pool("throttle_relay_defer").await else {
        return;
    };
    insert_override(&pool, 100).await;
    let server = FakeSmtpServer::start(FakeSmtpConfig::default()).await;
    let ledger = Arc::new(MemoryLedger::new());
    let resolver = Arc::new(StaticMxResolver::new().with_target("gmail.com", vec![server.addr()]));
    let relay = Relay::with_warmup_gate_and_throttle(
        ledger.clone(),
        resolver,
        RelayConfig::default(),
        WarmupGate::none(),
        Some(Arc::new(ProviderThrottle::new(pool.clone()))),
    );

    let send_unit = unit("throttle-defer");
    let before = chrono::Utc::now();
    let error = relay
        .submit(request(&send_unit))
        .await
        .expect_err("a 100% override must not send");
    match error {
        RelayError::RetryScheduled {
            next_attempt_at,
            reason,
            ..
        } => {
            assert!(
                reason.contains("throttle 100%"),
                "reason names the throttle: {reason}"
            );
            assert!(
                next_attempt_at >= before + chrono::Duration::seconds(240),
                "retry is deferred by the bounded throttle window: {next_attempt_at}"
            );
            assert!(
                next_attempt_at
                    <= before
                        + chrono::Duration::from_std(THROTTLE_RETRY_DELAY).expect("duration")
                        + chrono::Duration::seconds(5),
                "retry delay is bounded: {next_attempt_at}"
            );
        }
        other => panic!("expected RetryScheduled, got {other:?}"),
    }

    assert_eq!(
        server.connections(),
        0,
        "the throttle gate must run before any SMTP connection"
    );
    let row = relay
        .get(&send_unit)
        .await
        .expect("ledger read")
        .expect("row exists");
    assert_eq!(row.state, "pending", "deferred, not failed");
    assert_eq!(row.attempt, 1, "no permanent attempt consumed");
    assert!(
        row.last_error
            .as_deref()
            .unwrap_or_default()
            .contains("throttle"),
        "the deferral reason is recorded: {:?}",
        row.last_error
    );
}

#[tokio::test]
async fn zero_percent_override_sends_normally() {
    let Some(pool) = test_pool("throttle_relay_send").await else {
        return;
    };
    insert_override(&pool, 0).await;
    let server = FakeSmtpServer::start(FakeSmtpConfig::default()).await;
    let ledger = Arc::new(MemoryLedger::new());
    let resolver = Arc::new(StaticMxResolver::new().with_target("gmail.com", vec![server.addr()]));
    let relay = Relay::with_warmup_gate_and_throttle(
        ledger,
        resolver,
        RelayConfig::default(),
        WarmupGate::none(),
        Some(Arc::new(ProviderThrottle::new(pool.clone()))),
    );

    let record = relay
        .submit(request(&unit("throttle-send")))
        .await
        .expect("0% override sends everything");
    assert_eq!(record.state, "accepted");
    assert_eq!(server.messages().len(), 1);
}

/// External report 2026-10-28 (P1): an accepted-but-deferred unit has a
/// DEADLINE. With the ledger row parked past OUTBOUND_THROTTLE_DEFER_DEADLINE_SECS
/// (default 6 h), the next deferral decision terminalizes honestly: permanent
/// state, an expiry DSN, and a reason that names the deadline. Reputation
/// protection is preserved — the send still never reaches the wire.
#[tokio::test]
async fn sustained_throttle_deferral_expires_at_the_deadline_with_dsn() {
    let Some(pool) = test_pool("throttle_deadline_expire").await else {
        return;
    };
    std::env::set_var("OUTBOUND_THROTTLE_DEFER_DEADLINE_SECS", "3600");
    insert_override(&pool, 100).await;
    let server = FakeSmtpServer::start(FakeSmtpConfig::default()).await;
    let ledger = Arc::new(MemoryLedger::new());
    let resolver = Arc::new(StaticMxResolver::new().with_target("gmail.com", vec![server.addr()]));
    let relay = Relay::with_warmup_gate_and_throttle(
        ledger.clone(),
        resolver,
        RelayConfig::default(),
        WarmupGate::none(),
        Some(Arc::new(ProviderThrottle::new(pool.clone()))),
    );

    let send_unit = unit("throttle-deadline");
    let first = relay
        .submit(request(&send_unit))
        .await
        .expect_err("100% override defers");
    assert!(matches!(first, RelayError::RetryScheduled { .. }));
    // Age the row past the 1 h deadline the env pinned for this test.
    ledger.age_row(&send_unit, chrono::Duration::seconds(3_600 + 60));

    // The daemon path: a DUE pending row is claimed by the sweep, not by
    // the idempotent admission call — drive process_due like the daemon.
    let report = relay
        .process_due(chrono::Utc::now(), 10)
        .await
        .expect("daemon sweep");
    assert_eq!(report.permanently_failed, 1, "the report: {report:?}");
    // The expiry DSN is a REAL enqueued ledger unit (one per recipient).
    let dsn_rows: Vec<String> = ledger
        .dsn_send_units()
        .into_iter()
        .filter(|unit| unit.starts_with(&format!("{send_unit}:dsn:")))
        .collect();
    assert_eq!(
        dsn_rows.len(),
        1,
        "exactly one expiry DSN unit per recipient: {dsn_rows:?}"
    );
    let row_after = relay
        .get(&send_unit)
        .await
        .expect("ledger read")
        .expect("row exists");
    assert!(
        row_after
            .last_error
            .as_deref()
            .unwrap_or_default()
            .contains("throttle deferral deadline expired"),
        "the terminal reason names the deadline: {:?}",
        row_after.last_error
    );
    let expired_check = relay
        .submit(request(&send_unit))
        .await
        .expect_err("a failed row reports permanently on resubmission");
    match expired_check {
        RelayError::Permanent { reason, dsn_send_units, .. } => {
            assert!(
                reason.contains("throttle deferral deadline expired"),
                "the reason names the honest deadline: {reason}"
            );
            let _ = dsn_send_units;
        }
        other => panic!("expected Permanent after the deadline, got {other:?}"),
    }
    assert_eq!(server.connections(), 0, "reputation protection preserved: nothing sent");
    let row = relay
        .get(&send_unit)
        .await
        .expect("ledger read")
        .expect("row exists");
    assert_eq!(row.state, "failed", "terminal, not parked forever");
    std::env::remove_var("OUTBOUND_THROTTLE_DEFER_DEADLINE_SECS");
}

/// Below the deadline nothing changes except the CAP: the scheduled retry
/// can never run past the deadline instant, so the unit resolves at (not
/// after) its deadline.
#[tokio::test]
async fn sub_deadline_deferral_caps_the_retry_at_the_deadline() {
    let Some(pool) = test_pool("throttle_deadline_cap").await else {
        return;
    };
    std::env::set_var("OUTBOUND_THROTTLE_DEFER_DEADLINE_SECS", "600");
    insert_override(&pool, 100).await;
    let server = FakeSmtpServer::start(FakeSmtpConfig::default()).await;
    let ledger = Arc::new(MemoryLedger::new());
    let resolver = Arc::new(StaticMxResolver::new().with_target("gmail.com", vec![server.addr()]));
    let relay = Relay::with_warmup_gate_and_throttle(
        ledger.clone(),
        resolver,
        RelayConfig::default(),
        WarmupGate::none(),
        Some(Arc::new(ProviderThrottle::new(pool.clone()))),
    );

    let send_unit = unit("throttle-cap");
    let before = chrono::Utc::now();
    let error = relay
        .submit(request(&send_unit))
        .await
        .expect_err("100% override defers");
    match error {
        RelayError::RetryScheduled { next_attempt_at, .. } => {
            let deadline_at = before + chrono::Duration::seconds(600);
            assert!(
                next_attempt_at <= deadline_at,
                "the throttle window is capped at the deadline: {next_attempt_at} > {deadline_at}"
            );
        }
        other => panic!("expected RetryScheduled, got {other:?}"),
    }
    std::env::remove_var("OUTBOUND_THROTTLE_DEFER_DEADLINE_SECS");
}

/// The age evidence: every deferral observes the unit's parked age by
/// reason, and the snapshot carries count/avg/max for /metrics and the
/// OutboundThrottleDeferralAgeHigh alert.
#[tokio::test]
async fn deferral_age_is_observed_by_reason() {
    let Some(pool) = test_pool("throttle_age_metric").await else {
        return;
    };
    insert_override(&pool, 100).await;
    let server = FakeSmtpServer::start(FakeSmtpConfig::default()).await;
    let ledger = Arc::new(MemoryLedger::new());
    let resolver = Arc::new(StaticMxResolver::new().with_target("gmail.com", vec![server.addr()]));
    let relay = Relay::with_warmup_gate_and_throttle(
        ledger.clone(),
        resolver,
        RelayConfig::default(),
        WarmupGate::none(),
        Some(Arc::new(ProviderThrottle::new(pool.clone()))),
    );

    let send_unit = unit("throttle-age");
    let _ = relay.submit(request(&send_unit)).await;
    // Age the row and drive the DAEMON sweep (submit is admission-only for
    // pending rows) so the second deferral decision observes the parked age.
    ledger.age_row(&send_unit, chrono::Duration::seconds(1_200));
    let _ = relay
        .process_due(chrono::Utc::now(), 10)
        .await
        .expect("daemon sweep");

    let snapshot = outbound_mta::relay::throttle_defer_age_snapshot();
    let row = snapshot
        .iter()
        .find(|(reason, ..)| reason.contains("google"))
        .expect("the google throttle reason is observed");
    assert!(row.1 >= 2, "both deferral decisions were observed: {row:?}");
    assert!(row.3 >= 1_200, "the max age reflects the parked time: {row:?}");
}
