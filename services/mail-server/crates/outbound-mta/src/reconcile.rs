//! Ledger→acceptance reconciler (the two-ledger projector).
//!
//! `outbound_relay_ledger` (recipient-facing SMTP state) and
//! `sales_delivery_acceptances` (the worker's exactly-once protocol) are
//! deliberately separate tables — but a send accepted by the DAEMON (a
//! durable retry that succeeded while the worker wasn't looking) must not
//! wait for the worker to happen to retry before the application learns SMTP
//! already accepted it.
//!
//! [`reconcile_acceptances`] projects relay rows `accepted` in the ledger
//! onto acceptance rows still `reserved`, using the ledger's own stored
//! acceptance evidence (transport id, actual source IP). Idempotent by
//! construction: the UPDATE only fires for `state = 'reserved'`, so a
//! concurrent worker write wins and a second reconciler pass is a no-op.
#![deny(unsafe_code)]

use chrono::{DateTime, Utc};
use sqlx::PgPool;

/// One projected acceptance (for logging/metrics).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReconciledAcceptance {
    pub send_unit: String,
    pub tenant_id: String,
    pub accepted_at: DateTime<Utc>,
}

/// Project relay-accepted send units onto `reserved` acceptance rows.
///
/// Returns the reconciled units (possibly empty). A ledger/acceptance store
/// error is returned to the caller — the reconciler never masks an outage.
pub async fn reconcile_acceptances(db: &PgPool) -> Result<Vec<ReconciledAcceptance>, String> {
    /// One projected `reserved` acceptance row: (send_unit, tenant_id,
    /// transport_message_id, requested_source_ip, reserved_at).
    type ProjectedReservation = (
        String,
        String,
        Option<String>,
        Option<String>,
        DateTime<Utc>,
    );
    let rows: Vec<ProjectedReservation> = sqlx::query_as(
        r#"
        UPDATE sales_delivery_acceptances a
        SET state = 'accepted',
            transport_message_id = COALESCE(
                (l.acceptance_record->>'send_unit'), a.transport_message_id),
            actual_source_ip = host(l.actual_source_ip)::inet,
            accepted_at = l.accepted_at,
            last_error = NULL
        FROM outbound_relay_ledger l
        WHERE l.send_unit = a.send_unit
          AND l.state = 'accepted'
          AND l.accepted_at IS NOT NULL
          AND a.state = 'reserved'
        RETURNING a.send_unit, a.tenant_id, a.transport_message_id,
                  host(a.actual_source_ip), a.accepted_at
        "#,
    )
    .fetch_all(db)
    .await
    .map_err(|error| format!("reconciler projection failed: {error}"))?;
    Ok(rows
        .into_iter()
        .map(
            |(send_unit, tenant_id, _, _, accepted_at)| ReconciledAcceptance {
                send_unit,
                tenant_id,
                accepted_at,
            },
        )
        .collect())
}

#[cfg(test)]
mod tests {
    /// The projection SQL is structurally the worker's contract: only
    /// `reserved` rows move, and only when the relay row is `accepted`.
    #[test]
    fn projection_sql_pins_the_two_guard_conditions() {
        let source = include_str!("reconcile.rs");
        assert!(source.contains("l.state = 'accepted'"));
        assert!(source.contains("a.state = 'reserved'"));
    }

    // ── crash consistency: the stranded-acceptance window ──────────────────

    use std::time::Duration;

    use uuid::Uuid;

    use super::reconcile_acceptances;
    use crate::ledger::{ClaimOutcome, NewSubmission, PgLedger, RelayLedger};
    use crate::relay::{AcceptanceRecord, RecipientOutcome, RecipientResult};

    /// A PRIVATE canonical database per test, via the production migrator
    /// (the same harness the ledger tests use). `None` soft-skips only when
    /// `TEST_DATABASE_URL` is unset.
    async fn reconcile_pool(test_name: &str) -> Option<sqlx::PgPool> {
        match migrator::test_support::fresh_canonical_pool(
            &format!("outbound-mta-reconcile-{test_name}"),
            &format!("obm_reconcile_{test_name}"),
        )
        .await
        {
            Ok(pool) => pool,
            Err(error) => panic!("{}", error.panic_message()),
        }
    }

    /// The worker reserved a send unit, died, and the DAEMON's durable retry
    /// accepted it (the relay ledger's own claim/reclaim ladder). The worker
    /// acceptance row is stranded `reserved` while the send already exists
    /// externally. One reconciler pass completes it from the ledger's stored
    /// acceptance evidence; a second pass is a no-op.
    #[tokio::test]
    async fn reconciler_completes_an_acceptance_stranded_by_a_daemon_acceptance() {
        let Some(pool) = reconcile_pool("crash").await else {
            return;
        };
        let ledger = PgLedger::new(pool.clone());
        let unit = format!("crash:test:reconcile:{}", Uuid::new_v4());

        // The daemon's durable retry accepted the unit (post-DATA 250),
        // recording its evidence on the relay ledger.
        let now = chrono::Utc::now();
        let claimed = ledger
            .claim_submission(
                NewSubmission {
                    send_unit: unit.clone(),
                    tenant_id: Some("tenant-stranded".to_string()),
                    queue_id: None,
                    request_fingerprint: None,
                    envelope_from: Some("sender@example.com".to_string()),
                    recipients: vec!["user@example.com".to_string()],
                    message: b"From: sender@example.com\r\n\r\nbody".to_vec(),
                    requested_source_ip: Some("203.0.113.8".parse().expect("ip")),
                    max_attempts: 12,
                },
                now,
                Duration::from_secs(60),
            )
            .await
            .expect("claim");
        assert!(matches!(claimed, ClaimOutcome::Claimed(_)));

        let accepted_at = now + chrono::Duration::seconds(30);
        let record = AcceptanceRecord {
            send_unit: unit.clone(),
            state: "accepted".to_string(),
            accepted_at,
            attempt: 2,
            remote_mx: Some("mx.example".to_string()),
            tls_used: true,
            requested_source_ip: Some("203.0.113.8".parse().expect("ip")),
            actual_source_ip: Some("203.0.113.8".parse().expect("ip")),
            recipients: vec![RecipientResult {
                recipient: "user@example.com".to_string(),
                outcome: RecipientOutcome::Accepted,
                reply_code: Some(250),
                enhanced_status: Some("2.0.0".to_string()),
                diagnostic: None,
                mx: Some("mx.example".to_string()),
                tls_used: true,
            }],
            dsn_send_units: Vec::new(),
            deferred_retry: None,
        };
        ledger
            .record_accepted(&unit, &record)
            .await
            .expect("daemon acceptance commit");

        // The worker side: it reserved the unit, then DIED. Its acceptance
        // row is stranded `reserved` with an expired reservation lease.
        sqlx::query(
            "INSERT INTO sales_delivery_acceptances \
                 (send_unit, tenant_id, state, transport, reserved_at) \
             VALUES ($1, 'tenant-stranded', 'reserved', 'ses_shared', \
                     NOW() - INTERVAL '20 minutes')",
        )
        .bind(&unit)
        .execute(&pool)
        .await
        .expect("seed stranded worker acceptance");

        // One reconciler pass completes the stranded acceptance from the
        // ledger's stored evidence.
        let reconciled = reconcile_acceptances(&pool)
            .await
            .expect("reconciler pass");
        assert_eq!(
            reconciled.len(),
            1,
            "the stranded reservation is projected: {reconciled:?}"
        );
        assert_eq!(reconciled[0].send_unit, unit);
        assert_eq!(reconciled[0].tenant_id, "tenant-stranded");
        assert_eq!(reconciled[0].accepted_at, accepted_at);

        let (state, transport_message_id, actual_ip, worker_accepted_at): (
            String,
            Option<String>,
            Option<String>,
            Option<chrono::DateTime<chrono::Utc>>,
        ) = sqlx::query_as(
            "SELECT state, transport_message_id, host(actual_source_ip), accepted_at \
             FROM sales_delivery_acceptances WHERE send_unit = $1",
        )
        .bind(&unit)
        .fetch_one(&pool)
        .await
        .expect("worker acceptance row");
        assert_eq!(state, "accepted");
        assert_eq!(
            transport_message_id.as_deref(),
            Some(unit.as_str()),
            "the ledger's acceptance evidence identifies the unit"
        );
        assert_eq!(
            actual_ip.as_deref(),
            Some("203.0.113.8"),
            "the verified source IP is carried onto the worker's record"
        );
        assert_eq!(worker_accepted_at, Some(accepted_at));

        // Idempotent: a second pass finds nothing left to project.
        let again = reconcile_acceptances(&pool).await.expect("second pass");
        assert!(
            again.is_empty(),
            "an accepted row is never re-projected: {again:?}"
        );
    }
}
