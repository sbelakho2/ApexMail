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
