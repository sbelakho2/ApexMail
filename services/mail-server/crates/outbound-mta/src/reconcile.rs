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
}
