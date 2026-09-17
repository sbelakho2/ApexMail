//! Durable outbound queue + idempotent acceptance ledger.
//!
//! Backed by `outbound_relay_ledger` (migration
//! `212_outbound_relay_ledger.sql`). Why a dedicated table instead of the
//! worker's `sales_delivery_acceptances`: the worker claims its `send_unit`
//! BEFORE submitting, so the same primary key would already exist when the
//! relay tries to record its own state; the relay additionally needs the
//! message payload, retry schedule and lease that the worker ledger does not
//! carry. The full rationale is in the migration header.
//!
//! The protocol implemented here is:
//!
//! * `claim_submission` — atomic INSERT ... ON CONFLICT DO NOTHING. A fresh
//!   row is claimed `delivering` with attempt 1; a conflicting row is
//!   classified (`accepted` → return the stored record; live lease →
//!   in-flight; `pending` → already queued; `failed` → terminal).
//! * `claim_due` — the daemon's retry claim: one atomic UPDATE ... SKIP
//!   LOCKED, so exactly one worker owns each due row, incrementing `attempt`
//!   and taking a lease.
//! * `record_accepted` / `record_retry` / `record_permanent` — terminal or
//!   retry state transitions for the lease holder.
//! * `reclaim_expired` — crashed `delivering` rows return to `pending`
//!   (never deleted; the attempt counter is preserved).

use std::net::IpAddr;
use std::time::Duration;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::Serialize;
use sqlx::PgPool;
use uuid::Uuid;

use crate::relay::AcceptanceRecord;

/// A new submission to enqueue durably.
#[derive(Debug, Clone)]
pub struct NewSubmission {
    pub send_unit: String,
    pub tenant_id: Option<String>,
    pub queue_id: Option<Uuid>,
    /// H(tenant || envelope_from || canonical_recipients ||
    /// message_sha256 || requested_source_ip) — migration 230. `None` only
    /// for callers that predate the field; the relay always sets it.
    pub request_fingerprint: Option<String>,
    /// `None` = SMTP null reverse path.
    pub envelope_from: Option<String>,
    pub recipients: Vec<String>,
    pub message: Vec<u8>,
    pub requested_source_ip: Option<IpAddr>,
    pub max_attempts: u32,
}

/// A ledger row (queue entry + acceptance evidence).
#[derive(Debug, Clone)]
pub struct QueuedSubmission {
    pub send_unit: String,
    pub tenant_id: Option<String>,
    pub queue_id: Option<Uuid>,
    pub request_fingerprint: Option<String>,
    pub state: String,
    pub envelope_from: Option<String>,
    pub recipients: Vec<String>,
    pub message: Vec<u8>,
    pub requested_source_ip: Option<IpAddr>,
    pub actual_source_ip: Option<IpAddr>,
    pub remote_mx: Option<String>,
    pub tls_used: bool,
    pub attempt: u32,
    pub max_attempts: u32,
    pub next_attempt_at: DateTime<Utc>,
    pub lease_until: Option<DateTime<Utc>>,
    pub acceptance: Option<AcceptanceRecord>,
    pub last_error: Option<String>,
    pub created_at: DateTime<Utc>,
}

/// Result of atomically claiming a submission (or classifying an existing
/// one).
#[derive(Debug, Clone)]
pub enum ClaimOutcome {
    /// This caller owns the delivery attempt and must perform it.
    Claimed(Box<QueuedSubmission>),
    /// A prior attempt recorded a post-DATA 250; the stored record is
    /// returned and MUST NOT be delivered again.
    AlreadyAccepted(Box<AcceptanceRecord>),
    /// Another attempt holds a live lease.
    InFlight {
        attempt: u32,
        next_attempt_at: Option<DateTime<Utc>>,
    },
    /// The row is queued for a retry owned by the daemon (including an
    /// expired lease awaiting reclaim); this submit call must not deliver.
    AlreadyQueued {
        attempt: u32,
        next_attempt_at: DateTime<Utc>,
    },
    /// Terminal permanent failure.
    PermanentlyFailed {
        attempt: u32,
        last_error: Option<String>,
    },
}

/// Ledger/queue counters for the health endpoint.
#[derive(Debug, Clone, Copy, Default, Serialize)]
pub struct LedgerStats {
    pub pending: i64,
    pub delivering: i64,
    pub accepted: i64,
    pub failed: i64,
    /// Age of the OLDEST pending row (EXTRACT(EPOCH FROM NOW() -
    /// MIN(next_attempt_at))), 0 when the queue is empty. This is the
    /// daemon's queue-drain SLO signal: the poll loop claims due rows every
    /// OUTBOUND_MTA_POLL_SECS, so an old pending row means the daemon is
    /// down/wedged or the retry schedule starved legitimate sends.
    pub oldest_pending_age_secs: i64,
}

/// Durable ledger failure. Callers fail closed: an unguarded submit would
/// forfeit exactly-once, so no delivery is attempted when the ledger is
/// unavailable.
#[derive(Debug, thiserror::Error)]
pub enum LedgerError {
    #[error("acceptance ledger database error: {0}")]
    Database(String),
    #[error("corrupt ledger row for {send_unit}: {message}")]
    Corrupt { send_unit: String, message: String },
    #[error("invalid lease duration: {0}")]
    Lease(String),
}

impl From<sqlx::Error> for LedgerError {
    fn from(error: sqlx::Error) -> Self {
        Self::Database(error.to_string())
    }
}

/// The ledger contract. Implemented by [`PgLedger`] in production and by the
/// in-memory test double used by the delivery tests.
#[async_trait]
pub trait RelayLedger: Send + Sync {
    /// The Postgres pool when this ledger is Postgres-backed. Relay-owned
    /// warmup admission reads the dedicated-IP lifecycle from it; the
    /// in-memory double returns None (embedded tests inject their own gate).
    fn pg_pool(&self) -> Option<&sqlx::PgPool> {
        None
    }

    /// Idempotent submission claim (see the module docs).
    async fn claim_submission(
        &self,
        new: NewSubmission,
        now: DateTime<Utc>,
        lease: Duration,
    ) -> Result<ClaimOutcome, LedgerError>;

    /// Claim due retries / expired leases, up to `limit` rows.
    async fn claim_due(
        &self,
        now: DateTime<Utc>,
        lease: Duration,
        limit: i64,
    ) -> Result<Vec<QueuedSubmission>, LedgerError>;

    async fn record_retry(
        &self,
        send_unit: &str,
        attempt: u32,
        next_attempt_at: DateTime<Utc>,
        error: &str,
    ) -> Result<(), LedgerError>;

    async fn record_accepted(
        &self,
        send_unit: &str,
        record: &AcceptanceRecord,
    ) -> Result<(), LedgerError>;

    async fn record_permanent(
        &self,
        send_unit: &str,
        attempt: u32,
        error: &str,
    ) -> Result<(), LedgerError>;

    /// Insert a DSN as a new queued submission. Returns true when the row was
    /// inserted, false when it already existed (idempotent).
    async fn enqueue_dsn(
        &self,
        new: NewSubmission,
        now: DateTime<Utc>,
    ) -> Result<bool, LedgerError>;

    async fn get(&self, send_unit: &str) -> Result<Option<QueuedSubmission>, LedgerError>;

    /// Return crashed `delivering` rows (expired lease) to `pending`.
    async fn reclaim_expired(&self, now: DateTime<Utc>) -> Result<u64, LedgerError>;

    async fn stats(&self) -> Result<LedgerStats, LedgerError>;
}

/// Postgres-backed ledger (production).
pub struct PgLedger {
    pool: PgPool,
}

impl PgLedger {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub fn pool(&self) -> &PgPool {
        &self.pool
    }
}

/// Shared column list. INET columns are cast to text for transport and
/// parsed back into `IpAddr` in [`LedgerRow::into_submission`] — sqlx's
/// Postgres driver does not provide a `Type<Postgres>` impl for
/// `std::net::IpAddr` without extra features, and the wire form (`::text`)
/// is unambiguous for both v4 and v6.
const LEDGER_COLUMNS: &str =
    "send_unit, tenant_id, queue_id, request_fingerprint, state, envelope_from, recipients, \
     message, requested_source_ip::text AS requested_source_ip, \
     actual_source_ip::text AS actual_source_ip, remote_mx, tls_used, attempt, max_attempts, \
     next_attempt_at, lease_until, acceptance_record, last_error, created_at";

#[derive(sqlx::FromRow)]
struct LedgerRow {
    send_unit: String,
    tenant_id: Option<String>,
    queue_id: Option<Uuid>,
    request_fingerprint: Option<String>,
    state: String,
    envelope_from: Option<String>,
    recipients: serde_json::Value,
    message: Vec<u8>,
    requested_source_ip: Option<String>,
    actual_source_ip: Option<String>,
    remote_mx: Option<String>,
    tls_used: bool,
    attempt: i32,
    max_attempts: i32,
    next_attempt_at: DateTime<Utc>,
    lease_until: Option<DateTime<Utc>>,
    acceptance_record: Option<serde_json::Value>,
    last_error: Option<String>,
    created_at: DateTime<Utc>,
}

#[derive(sqlx::FromRow)]
struct ClaimStateRow {
    state: String,
    request_fingerprint: Option<String>,
    attempt: i32,
    next_attempt_at: DateTime<Utc>,
    lease_until: Option<DateTime<Utc>>,
    acceptance_record: Option<serde_json::Value>,
    last_error: Option<String>,
}

impl LedgerRow {
    fn into_submission(self) -> Result<QueuedSubmission, LedgerError> {
        let recipients: Vec<String> =
            serde_json::from_value(self.recipients).map_err(|error| LedgerError::Corrupt {
                send_unit: self.send_unit.clone(),
                message: format!("recipients column is not a string array: {error}"),
            })?;
        let acceptance = match self.acceptance_record {
            Some(value) => {
                Some(
                    serde_json::from_value(value).map_err(|error| LedgerError::Corrupt {
                        send_unit: self.send_unit.clone(),
                        message: format!("acceptance_record is not an AcceptanceRecord: {error}"),
                    })?,
                )
            }
            None => None,
        };
        let attempt = u32::try_from(self.attempt).map_err(|_| LedgerError::Corrupt {
            send_unit: self.send_unit.clone(),
            message: format!("negative attempt {}", self.attempt),
        })?;
        let max_attempts = u32::try_from(self.max_attempts).map_err(|_| LedgerError::Corrupt {
            send_unit: self.send_unit.clone(),
            message: format!("negative max_attempts {}", self.max_attempts),
        })?;
        let send_unit = self.send_unit;
        let requested_source_ip =
            parse_ip(&self.requested_source_ip, "requested_source_ip", &send_unit)?;
        let actual_source_ip = parse_ip(&self.actual_source_ip, "actual_source_ip", &send_unit)?;
        Ok(QueuedSubmission {
            send_unit,
            tenant_id: self.tenant_id,
            queue_id: self.queue_id,
            request_fingerprint: self.request_fingerprint,
            state: self.state,
            envelope_from: self.envelope_from,
            recipients,
            message: self.message,
            requested_source_ip,
            actual_source_ip,
            remote_mx: self.remote_mx,
            tls_used: self.tls_used,
            attempt,
            max_attempts,
            next_attempt_at: self.next_attempt_at,
            lease_until: self.lease_until,
            acceptance,
            last_error: self.last_error,
            created_at: self.created_at,
        })
    }
}

/// Shared classification of an existing row (used by both implementations so
/// their semantics cannot drift).
fn classify_existing(
    send_unit: &str,
    row: &ClaimStateRow,
    now: DateTime<Utc>,
) -> Result<ClaimOutcome, LedgerError> {
    let ClaimStateRow {
        state,
        request_fingerprint: _,
        attempt,
        next_attempt_at,
        lease_until,
        acceptance_record,
        last_error,
    } = row;
    let state = state.as_str();
    let attempt = *attempt;
    let next_attempt_at = *next_attempt_at;
    let lease_until = *lease_until;
    let acceptance_record = acceptance_record.clone();
    let last_error = last_error.clone();
    let attempt = u32::try_from(attempt).map_err(|_| LedgerError::Corrupt {
        send_unit: send_unit.to_string(),
        message: format!("negative attempt {attempt}"),
    })?;
    match state {
        "accepted" => {
            let record = acceptance_record
                .ok_or_else(|| LedgerError::Corrupt {
                    send_unit: send_unit.to_string(),
                    message: "accepted row has no acceptance_record".to_string(),
                })
                .and_then(|value| {
                    serde_json::from_value(value).map_err(|error| LedgerError::Corrupt {
                        send_unit: send_unit.to_string(),
                        message: format!("acceptance_record is not an AcceptanceRecord: {error}"),
                    })
                })?;
            Ok(ClaimOutcome::AlreadyAccepted(Box::new(record)))
        }
        "failed" => Ok(ClaimOutcome::PermanentlyFailed {
            attempt,
            last_error,
        }),
        "delivering" => match lease_until {
            Some(lease) if lease > now => Ok(ClaimOutcome::InFlight {
                attempt,
                next_attempt_at: Some(next_attempt_at),
            }),
            // Expired lease: the daemon's reclaim/claim_due path owns it.
            _ => Ok(ClaimOutcome::AlreadyQueued {
                attempt,
                next_attempt_at,
            }),
        },
        "pending" => Ok(ClaimOutcome::AlreadyQueued {
            attempt,
            next_attempt_at,
        }),
        other => Err(LedgerError::Corrupt {
            send_unit: send_unit.to_string(),
            message: format!("unknown state '{other}'"),
        }),
    }
}

fn parse_ip(
    value: &Option<String>,
    field: &str,
    send_unit: &str,
) -> Result<Option<IpAddr>, LedgerError> {
    match value {
        Some(text) if !text.is_empty() => {
            // Postgres renders `inet` with the netmask (`203.0.113.8/32`);
            // the address itself is what the socket bound.
            let address = text
                .split_once('/')
                .map(|(address, _)| address)
                .unwrap_or(text);
            address
                .parse::<IpAddr>()
                .map(Some)
                .map_err(|error| LedgerError::Corrupt {
                    send_unit: send_unit.to_string(),
                    message: format!("{field} is not an IP address: {error}"),
                })
        }
        _ => Ok(None),
    }
}

fn lease_deadline(now: DateTime<Utc>, lease: Duration) -> Result<DateTime<Utc>, LedgerError> {
    let lease =
        chrono::Duration::from_std(lease).map_err(|error| LedgerError::Lease(error.to_string()))?;
    now.checked_add_signed(lease)
        .ok_or_else(|| LedgerError::Lease("lease deadline overflowed".to_string()))
}

#[async_trait]
impl RelayLedger for PgLedger {
    fn pg_pool(&self) -> Option<&PgPool> {
        Some(&self.pool)
    }

    async fn claim_submission(
        &self,
        new: NewSubmission,
        now: DateTime<Utc>,
        lease: Duration,
    ) -> Result<ClaimOutcome, LedgerError> {
        let lease_until = lease_deadline(now, lease)?;
        let recipients = serde_json::Value::Array(
            new.recipients
                .iter()
                .map(|recipient| serde_json::Value::String(recipient.clone()))
                .collect(),
        );
        let insert = format!(
            "INSERT INTO outbound_relay_ledger \
             (send_unit, tenant_id, queue_id, request_fingerprint, state, envelope_from, \
              recipients, message, requested_source_ip, attempt, max_attempts, next_attempt_at, \
              lease_until, updated_at) \
             VALUES ($1, $2, $3, $4, 'delivering', $5, $6, $7, $8::text::inet, 1, $9, $10, $11, \
                     NOW()) \
             ON CONFLICT (send_unit) DO NOTHING \
             RETURNING {LEDGER_COLUMNS}"
        );
        let inserted: Option<LedgerRow> = sqlx::query_as(&insert)
            .bind(&new.send_unit)
            .bind(&new.tenant_id)
            .bind(new.queue_id)
            .bind(&new.request_fingerprint)
            .bind(&new.envelope_from)
            .bind(&recipients)
            .bind(&new.message)
            .bind(new.requested_source_ip.map(|ip| ip.to_string()))
            .bind(i32::try_from(new.max_attempts).unwrap_or(i32::MAX))
            .bind(now)
            .bind(lease_until)
            .fetch_optional(&self.pool)
            .await?;
        if let Some(row) = inserted {
            return Ok(ClaimOutcome::Claimed(Box::new(row.into_submission()?)));
        }

        let state: Option<ClaimStateRow> = sqlx::query_as(
            "SELECT state, request_fingerprint, attempt, next_attempt_at, lease_until, \
                    acceptance_record, last_error \
             FROM outbound_relay_ledger WHERE send_unit = $1",
        )
        .bind(&new.send_unit)
        .fetch_optional(&self.pool)
        .await?;
        let state = state.ok_or_else(|| LedgerError::Corrupt {
            send_unit: new.send_unit.clone(),
            message: "row vanished between insert conflict and classification".to_string(),
        })?;

        // Migration 230's contract: the same send_unit with a DIFFERENT
        // delivery contract is a typed conflict. A NULL stored fingerprint
        // (a row claimed pre-230) is PINNED to the incoming value on first
        // replay; after that the contract is enforced.
        match (&state.request_fingerprint, &new.request_fingerprint) {
            (Some(stored), Some(incoming)) if stored != incoming => {
                return Err(LedgerError::Corrupt {
                    send_unit: new.send_unit.clone(),
                    message: format!(
                        "idempotency conflict: send_unit reused with a different delivery \
                         contract (stored fingerprint {stored:?}, incoming {incoming:?}) — \
                         reconcile against the existing row; never re-route under the same key"
                    ),
                });
            }
            (None, Some(incoming)) => {
                sqlx::query(
                    "UPDATE outbound_relay_ledger SET request_fingerprint = $2 \
                     WHERE send_unit = $1 AND request_fingerprint IS NULL",
                )
                .bind(&new.send_unit)
                .bind(incoming)
                .execute(&self.pool)
                .await?;
            }
            _ => {}
        }
        classify_existing(&new.send_unit, &state, now)
    }

    async fn claim_due(
        &self,
        now: DateTime<Utc>,
        lease: Duration,
        limit: i64,
    ) -> Result<Vec<QueuedSubmission>, LedgerError> {
        let lease_until = lease_deadline(now, lease)?;
        let update = format!(
            "UPDATE outbound_relay_ledger \
             SET state = 'delivering', attempt = attempt + 1, lease_until = $2, updated_at = NOW() \
             WHERE send_unit IN ( \
                 SELECT send_unit FROM outbound_relay_ledger \
                 WHERE (state = 'pending' AND next_attempt_at <= $1) \
                    OR (state = 'delivering' AND lease_until IS NOT NULL AND lease_until < $1) \
                 ORDER BY next_attempt_at ASC \
                 LIMIT $3 \
                 FOR UPDATE SKIP LOCKED \
             ) \
             RETURNING {LEDGER_COLUMNS}"
        );
        let rows: Vec<LedgerRow> = sqlx::query_as(&update)
            .bind(now)
            .bind(lease_until)
            .bind(limit)
            .fetch_all(&self.pool)
            .await?;
        rows.into_iter().map(LedgerRow::into_submission).collect()
    }

    async fn record_retry(
        &self,
        send_unit: &str,
        attempt: u32,
        next_attempt_at: DateTime<Utc>,
        error: &str,
    ) -> Result<(), LedgerError> {
        sqlx::query(
            "UPDATE outbound_relay_ledger \
             SET state = 'pending', attempt = $2, next_attempt_at = $3, last_error = $4, \
                 lease_until = NULL, updated_at = NOW() \
             WHERE send_unit = $1 AND state = 'delivering'",
        )
        .bind(send_unit)
        .bind(i32::try_from(attempt).unwrap_or(i32::MAX))
        .bind(next_attempt_at)
        .bind(error)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn record_accepted(
        &self,
        send_unit: &str,
        record: &AcceptanceRecord,
    ) -> Result<(), LedgerError> {
        let acceptance = serde_json::to_value(record).map_err(|error| LedgerError::Corrupt {
            send_unit: send_unit.to_string(),
            message: format!("cannot serialize acceptance record: {error}"),
        })?;
        // One transaction: the acceptance evidence and the follow-up unit for
        // the deferred subset (see `AcceptanceRecord::deferred_retry`) commit
        // together, so a crash can neither duplicate the accepted copies nor
        // drop the deferred recipients.
        let mut tx = self.pool.begin().await?;
        sqlx::query(
            "UPDATE outbound_relay_ledger \
             SET state = 'accepted', acceptance_record = $2, actual_source_ip = $3::text::inet, \
                 remote_mx = $4, tls_used = $5, accepted_at = $6, lease_until = NULL, \
                 last_error = NULL, updated_at = NOW() \
             WHERE send_unit = $1 AND state = 'delivering'",
        )
        .bind(send_unit)
        .bind(&acceptance)
        .bind(record.actual_source_ip.map(|ip| ip.to_string()))
        .bind(&record.remote_mx)
        .bind(record.tls_used)
        .bind(record.accepted_at)
        .execute(&mut *tx)
        .await?;
        if let Some(plan) = &record.deferred_retry {
            let recipients = serde_json::Value::Array(
                plan.recipients
                    .iter()
                    .map(|recipient| serde_json::Value::String(recipient.clone()))
                    .collect(),
            );
            // Copy the ORIGINAL envelope/message/tenant/queue id/source IP
            // and the inherited attempt ladder from the just-accepted parent.
            // The child carries only the deferred recipients and is due at
            // the plan's backoff time. Deterministic send_unit + ON CONFLICT
            // DO NOTHING make a replay of the acceptance a no-op.
            sqlx::query(
                "INSERT INTO outbound_relay_ledger \
                 (send_unit, tenant_id, queue_id, state, envelope_from, recipients, message, \
                  requested_source_ip, attempt, max_attempts, next_attempt_at, last_error, \
                  updated_at) \
                 SELECT $2, tenant_id, queue_id, 'pending', envelope_from, $3, message, \
                        requested_source_ip, $4, max_attempts, $5, $6, NOW() \
                   FROM outbound_relay_ledger WHERE send_unit = $1 \
                 ON CONFLICT (send_unit) DO NOTHING",
            )
            .bind(send_unit)
            .bind(&plan.send_unit)
            .bind(&recipients)
            .bind(i32::try_from(plan.attempt).unwrap_or(i32::MAX))
            .bind(plan.next_attempt_at)
            .bind(&plan.reason)
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        Ok(())
    }

    async fn record_permanent(
        &self,
        send_unit: &str,
        attempt: u32,
        error: &str,
    ) -> Result<(), LedgerError> {
        sqlx::query(
            "UPDATE outbound_relay_ledger \
             SET state = 'failed', attempt = $2, last_error = $3, lease_until = NULL, \
                 updated_at = NOW() \
             WHERE send_unit = $1 AND state = 'delivering'",
        )
        .bind(send_unit)
        .bind(i32::try_from(attempt).unwrap_or(i32::MAX))
        .bind(error)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn enqueue_dsn(
        &self,
        new: NewSubmission,
        now: DateTime<Utc>,
    ) -> Result<bool, LedgerError> {
        let recipients = serde_json::Value::Array(
            new.recipients
                .iter()
                .map(|recipient| serde_json::Value::String(recipient.clone()))
                .collect(),
        );
        let result = sqlx::query(
            "INSERT INTO outbound_relay_ledger \
             (send_unit, tenant_id, queue_id, state, envelope_from, recipients, message, \
              requested_source_ip, attempt, max_attempts, next_attempt_at, updated_at) \
             VALUES ($1, $2, $3, 'pending', NULL, $4, $5, $6::text::inet, 0, $7, $8, NOW()) \
             ON CONFLICT (send_unit) DO NOTHING",
        )
        .bind(&new.send_unit)
        .bind(&new.tenant_id)
        .bind(new.queue_id)
        .bind(&recipients)
        .bind(&new.message)
        .bind(new.requested_source_ip.map(|ip| ip.to_string()))
        .bind(i32::try_from(new.max_attempts).unwrap_or(i32::MAX))
        .bind(now)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() == 1)
    }

    async fn get(&self, send_unit: &str) -> Result<Option<QueuedSubmission>, LedgerError> {
        let select =
            format!("SELECT {LEDGER_COLUMNS} FROM outbound_relay_ledger WHERE send_unit = $1");
        let row: Option<LedgerRow> = sqlx::query_as(&select)
            .bind(send_unit)
            .fetch_optional(&self.pool)
            .await?;
        row.map(LedgerRow::into_submission).transpose()
    }

    async fn reclaim_expired(&self, now: DateTime<Utc>) -> Result<u64, LedgerError> {
        let result = sqlx::query(
            "UPDATE outbound_relay_ledger \
             SET state = 'pending', lease_until = NULL, next_attempt_at = $1, \
                 last_error = COALESCE(last_error, \
                     'delivery lease expired before completion; reclaimed for retry'), \
                 updated_at = NOW() \
             WHERE state = 'delivering' AND lease_until IS NOT NULL AND lease_until < $1",
        )
        .bind(now)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected())
    }

    async fn stats(&self) -> Result<LedgerStats, LedgerError> {
        let rows: Vec<(String, i64)> = sqlx::query_as(
            "SELECT state, COUNT(*)::bigint FROM outbound_relay_ledger GROUP BY state",
        )
        .fetch_all(&self.pool)
        .await?;
        let mut stats = LedgerStats::default();
        for (state, count) in rows {
            match state.as_str() {
                "pending" => stats.pending = count,
                "delivering" => stats.delivering = count,
                "accepted" => stats.accepted = count,
                "failed" => stats.failed = count,
                _ => {}
            }
        }
        stats.oldest_pending_age_secs = sqlx::query_scalar(
            "SELECT COALESCE(EXTRACT(EPOCH FROM (NOW() - MIN(next_attempt_at)))::bigint, 0) \
             FROM outbound_relay_ledger WHERE state = 'pending'",
        )
        .fetch_one(&self.pool)
        .await
        .unwrap_or(0);
        Ok(stats)
    }
}

/// In-memory ledger used by the delivery tests (same semantics as
/// [`PgLedger`], including the claim classification). Public under
/// `test-support` so dependent crates can run the real [`crate::Relay`]
/// against it.
#[cfg(any(test, feature = "test-support"))]
pub mod test_support {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Mutex;

    #[derive(Default)]
    pub struct MemoryLedger {
        entries: Mutex<HashMap<String, QueuedSubmission>>,
    }

    impl MemoryLedger {
        pub fn new() -> Self {
            Self::default()
        }

        fn with_entries<T>(
            &self,
            action: impl FnOnce(&mut HashMap<String, QueuedSubmission>) -> T,
        ) -> T {
            let mut guard = self
                .entries
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            action(&mut guard)
        }
    }

    #[async_trait]
    impl RelayLedger for MemoryLedger {
        async fn claim_submission(
            &self,
            new: NewSubmission,
            now: DateTime<Utc>,
            lease: Duration,
        ) -> Result<ClaimOutcome, LedgerError> {
            let lease_until = lease_deadline(now, lease)?;
            self.with_entries(|entries| {
                if let Some(existing) = entries.get(&new.send_unit) {
                    let row = ClaimStateRow {
                        state: existing.state.clone(),
                        request_fingerprint: existing.request_fingerprint.clone(),
                        attempt: existing.attempt as i32,
                        next_attempt_at: existing.next_attempt_at,
                        lease_until: existing.lease_until,
                        acceptance_record: existing
                            .acceptance
                            .as_ref()
                            .and_then(|record| serde_json::to_value(record).ok()),
                        last_error: existing.last_error.clone(),
                    };
                    return classify_existing(&existing.send_unit, &row, now);
                }
                let submission = QueuedSubmission {
                    send_unit: new.send_unit.clone(),
                    tenant_id: new.tenant_id,
                    queue_id: new.queue_id,
                    request_fingerprint: new.request_fingerprint.clone(),
                    state: "delivering".to_string(),
                    envelope_from: new.envelope_from,
                    recipients: new.recipients,
                    message: new.message,
                    requested_source_ip: new.requested_source_ip,
                    actual_source_ip: None,
                    remote_mx: None,
                    tls_used: false,
                    attempt: 1,
                    max_attempts: new.max_attempts,
                    next_attempt_at: now,
                    lease_until: Some(lease_until),
                    acceptance: None,
                    last_error: None,
                    created_at: now,
                };
                entries.insert(new.send_unit, submission.clone());
                Ok(ClaimOutcome::Claimed(Box::new(submission)))
            })
        }

        async fn claim_due(
            &self,
            now: DateTime<Utc>,
            lease: Duration,
            limit: i64,
        ) -> Result<Vec<QueuedSubmission>, LedgerError> {
            let lease_until = lease_deadline(now, lease)?;
            self.with_entries(|entries| {
                let mut due: Vec<QueuedSubmission> = entries
                    .values()
                    .filter(|entry| {
                        (entry.state == "pending" && entry.next_attempt_at <= now)
                            || (entry.state == "delivering"
                                && entry.lease_until.is_some_and(|until| until < now))
                    })
                    .cloned()
                    .collect();
                due.sort_by_key(|entry| (entry.next_attempt_at, entry.created_at));
                due.truncate(usize::try_from(limit.max(0)).unwrap_or(usize::MAX));
                for entry in &mut due {
                    entry.state = "delivering".to_string();
                    entry.attempt += 1;
                    entry.lease_until = Some(lease_until);
                    entries.insert(entry.send_unit.clone(), entry.clone());
                }
                Ok(due)
            })
        }

        async fn record_retry(
            &self,
            send_unit: &str,
            attempt: u32,
            next_attempt_at: DateTime<Utc>,
            error: &str,
        ) -> Result<(), LedgerError> {
            self.with_entries(|entries| {
                if let Some(entry) = entries.get_mut(send_unit) {
                    if entry.state == "delivering" {
                        entry.state = "pending".to_string();
                        entry.attempt = attempt;
                        entry.next_attempt_at = next_attempt_at;
                        entry.last_error = Some(error.to_string());
                        entry.lease_until = None;
                    }
                }
            });
            Ok(())
        }

        async fn record_accepted(
            &self,
            send_unit: &str,
            record: &AcceptanceRecord,
        ) -> Result<(), LedgerError> {
            self.with_entries(|entries| {
                // The follow-up unit for the deferred subset commits with the
                // acceptance, mirroring PgLedger (built under the parent
                // borrow, inserted once it ends).
                let mut follow_up: Option<QueuedSubmission> = None;
                if let Some(entry) = entries.get_mut(send_unit) {
                    if entry.state == "delivering" {
                        entry.state = "accepted".to_string();
                        entry.attempt = record.attempt;
                        entry.actual_source_ip = record.actual_source_ip;
                        entry.remote_mx = record.remote_mx.clone();
                        entry.tls_used = record.tls_used;
                        entry.acceptance = Some(record.clone());
                        entry.lease_until = None;
                        entry.last_error = None;
                        if let Some(plan) = &record.deferred_retry {
                            follow_up = Some(QueuedSubmission {
                                send_unit: plan.send_unit.clone(),
                                tenant_id: entry.tenant_id.clone(),
                                queue_id: entry.queue_id,
                                // The deferred subset's own contract; the
                                // ledger pins its fingerprint on first claim.
                                request_fingerprint: None,
                                state: "pending".to_string(),
                                envelope_from: entry.envelope_from.clone(),
                                recipients: plan.recipients.clone(),
                                message: entry.message.clone(),
                                requested_source_ip: entry.requested_source_ip,
                                actual_source_ip: None,
                                remote_mx: None,
                                tls_used: false,
                                attempt: plan.attempt,
                                max_attempts: entry.max_attempts,
                                next_attempt_at: plan.next_attempt_at,
                                lease_until: None,
                                acceptance: None,
                                last_error: Some(plan.reason.clone()),
                                created_at: Utc::now(),
                            });
                        }
                    }
                }
                if let Some(follow_up) = follow_up {
                    entries
                        .entry(follow_up.send_unit.clone())
                        .or_insert(follow_up);
                }
            });
            Ok(())
        }

        async fn record_permanent(
            &self,
            send_unit: &str,
            attempt: u32,
            error: &str,
        ) -> Result<(), LedgerError> {
            self.with_entries(|entries| {
                if let Some(entry) = entries.get_mut(send_unit) {
                    if entry.state == "delivering" {
                        entry.state = "failed".to_string();
                        entry.attempt = attempt;
                        entry.last_error = Some(error.to_string());
                        entry.lease_until = None;
                    }
                }
            });
            Ok(())
        }

        async fn enqueue_dsn(
            &self,
            new: NewSubmission,
            now: DateTime<Utc>,
        ) -> Result<bool, LedgerError> {
            Ok(self.with_entries(|entries| {
                if entries.contains_key(&new.send_unit) {
                    return false;
                }
                entries.insert(
                    new.send_unit.clone(),
                    QueuedSubmission {
                        send_unit: new.send_unit,
                        tenant_id: new.tenant_id,
                        queue_id: new.queue_id,
                        request_fingerprint: new.request_fingerprint,
                        state: "pending".to_string(),
                        envelope_from: new.envelope_from,
                        recipients: new.recipients,
                        message: new.message,
                        requested_source_ip: new.requested_source_ip,
                        actual_source_ip: None,
                        remote_mx: None,
                        tls_used: false,
                        attempt: 0,
                        max_attempts: new.max_attempts,
                        next_attempt_at: now,
                        lease_until: None,
                        acceptance: None,
                        last_error: None,
                        created_at: now,
                    },
                );
                true
            }))
        }

        async fn get(&self, send_unit: &str) -> Result<Option<QueuedSubmission>, LedgerError> {
            Ok(self.with_entries(|entries| entries.get(send_unit).cloned()))
        }

        async fn reclaim_expired(&self, now: DateTime<Utc>) -> Result<u64, LedgerError> {
            Ok(self.with_entries(|entries| {
                let mut reclaimed = 0u64;
                for entry in entries.values_mut() {
                    if entry.state == "delivering"
                        && entry.lease_until.is_some_and(|until| until < now)
                    {
                        entry.state = "pending".to_string();
                        entry.lease_until = None;
                        entry.next_attempt_at = now;
                        if entry.last_error.is_none() {
                            entry.last_error = Some(
                                "delivery lease expired before completion; reclaimed for retry"
                                    .to_string(),
                            );
                        }
                        reclaimed += 1;
                    }
                }
                reclaimed
            }))
        }

        async fn stats(&self) -> Result<LedgerStats, LedgerError> {
            Ok(self.with_entries(|entries| {
                let mut stats = LedgerStats::default();
                let mut oldest_pending: Option<DateTime<Utc>> = None;
                for entry in entries.values() {
                    match entry.state.as_str() {
                        "pending" => {
                            stats.pending += 1;
                            oldest_pending = Some(match oldest_pending {
                                Some(oldest) if oldest <= entry.next_attempt_at => oldest,
                                _ => entry.next_attempt_at,
                            });
                        }
                        "delivering" => stats.delivering += 1,
                        "accepted" => stats.accepted += 1,
                        "failed" => stats.failed += 1,
                        _ => {}
                    }
                }
                stats.oldest_pending_age_secs = oldest_pending
                    .map(|oldest| (Utc::now() - oldest).num_seconds().max(0))
                    .unwrap_or(0);
                stats
            }))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ledger::test_support::MemoryLedger;
    use crate::relay::{AcceptanceRecord, RecipientOutcome, RecipientResult};

    /// A PRIVATE canonical database per test (the REAL migration chain via
    /// the production migrator). The suite previously shared one table with
    /// a process-local `PG_LEDGER_LOCK`, which only serialises threads:
    /// `cargo nextest` runs every test as its own PROCESS, so a table-wide
    /// sweep (`claim_due` / `reclaim_expired`) in one test raced another
    /// test's rows and failed intermittently under parallel load.
    async fn pg_ledger_pool(test_name: &str) -> Option<PgPool> {
        match migrator::test_support::fresh_canonical_pool(
            &format!("outbound-mta-ledger-{test_name}"),
            &format!("obm_ledger_{test_name}"),
        )
        .await
        {
            Ok(pool) => pool,
            Err(error) => panic!("{}", error.panic_message()),
        }
    }

    /// Kept for `cargo test` (one process, many threads): serialises the
    /// Postgres-backed tests so their table-wide sweeps cannot interleave.
    /// Under nextest each test owns a private database instead.
    static PG_LEDGER_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    async fn seed_row(pool: &PgPool, send_unit: &str, state: &str) {
        sqlx::query(
            "INSERT INTO outbound_relay_ledger \
                 (send_unit, tenant_id, state, recipients, message, attempt, max_attempts, \
                  next_attempt_at, lease_until, accepted_at) \
             VALUES ($1, 'tenant-seed', $2, '[\"seed@example.com\"]'::jsonb, \
                     'seed'::bytea, 1, 12, NOW(), NULL, \
                     CASE WHEN $2 = 'accepted' THEN NOW() ELSE NULL END) \
             ON CONFLICT (send_unit) DO NOTHING",
        )
        .bind(send_unit)
        .bind(state)
        .execute(pool)
        .await
        .expect("seed ledger row");
    }

    /// Round-trips every ledger statement against a REAL Postgres schema
    /// (migration 212). Gated on `TEST_DATABASE_URL` (or the historical
    /// `OUTBOUND_MTA_TEST_DATABASE_URL`) so the default `cargo test` run
    /// stays hermetic.
    #[tokio::test]
    async fn pg_ledger_round_trip_is_idempotent() {
        let _guard = PG_LEDGER_LOCK.lock().await;
        let Some(pool) = pg_ledger_pool("round-trip").await else {
            return;
        };
        let ledger = PgLedger::new(pool.clone());
        let unit = format!("outbound-mta-test:round-trip:{}", Uuid::new_v4());
        let submission = || NewSubmission {
            send_unit: unit.clone(),
            tenant_id: Some("tenant-test".to_string()),
            queue_id: None,
            request_fingerprint: None,
            envelope_from: Some("sender@example.com".to_string()),
            recipients: vec!["user@example.com".to_string()],
            message: b"From: sender@example.com\r\n\r\nbody".to_vec(),
            requested_source_ip: Some("203.0.113.8".parse().expect("ip")),
            max_attempts: 5,
        };

        let now = Utc::now();
        let first = ledger
            .claim_submission(submission(), now, Duration::from_secs(60))
            .await
            .expect("claim submission");
        match first {
            ClaimOutcome::Claimed(row) => {
                assert_eq!(row.state, "delivering");
                assert_eq!(row.attempt, 1);
                assert_eq!(
                    row.requested_source_ip,
                    Some("203.0.113.8".parse().expect("ip"))
                );
            }
            other => panic!("expected Claimed, got {other:?}"),
        }

        // A concurrent duplicate must NOT claim the unit.
        match ledger
            .claim_submission(submission(), now, Duration::from_secs(60))
            .await
            .expect("second claim")
        {
            ClaimOutcome::InFlight { attempt, .. } => assert_eq!(attempt, 1),
            other => panic!("expected InFlight, got {other:?}"),
        }

        // Retry persists attempt/next_attempt_at; a resubmit is queued, not
        // delivered.
        let next_attempt_at = now + chrono::Duration::seconds(300);
        ledger
            .record_retry(&unit, 1, next_attempt_at, "test transient")
            .await
            .expect("record retry");
        match ledger
            .claim_submission(submission(), now, Duration::from_secs(60))
            .await
            .expect("third claim")
        {
            ClaimOutcome::AlreadyQueued {
                attempt,
                next_attempt_at: stored,
            } => {
                assert_eq!(attempt, 1);
                assert_eq!(stored, next_attempt_at);
            }
            other => panic!("expected AlreadyQueued, got {other:?}"),
        }

        // The due sweep claims it and increments the attempt.
        let due = ledger
            .claim_due(
                next_attempt_at + chrono::Duration::seconds(1),
                Duration::from_secs(60),
                10,
            )
            .await
            .expect("claim due");
        let claimed_row = due
            .iter()
            .find(|row| row.send_unit == unit)
            .expect("the unit must be claimed by the due sweep");
        assert_eq!(claimed_row.attempt, 2);

        // Acceptance: recorded once, returned on every repeat submission.
        let record = AcceptanceRecord {
            send_unit: unit.clone(),
            state: "accepted".to_string(),
            accepted_at: Utc::now(),
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
            .expect("record accepted");
        match ledger
            .claim_submission(submission(), Utc::now(), Duration::from_secs(60))
            .await
            .expect("fourth claim")
        {
            ClaimOutcome::AlreadyAccepted(stored) => {
                let stored = *stored;
                assert_eq!(stored.send_unit, unit);
                assert_eq!(stored.actual_source_ip, record.actual_source_ip);
                assert!(stored.warmup_capacity_consumed());
            }
            other => panic!("expected AlreadyAccepted, got {other:?}"),
        }

        // DSN enqueue is idempotent by key.
        let dsn_unit = format!("{unit}:dsn:user@example.com");
        let mut dsn = submission();
        dsn.send_unit = dsn_unit.clone();
        dsn.envelope_from = None;
        dsn.recipients = vec!["sender@example.com".to_string()];
        assert!(
            ledger
                .enqueue_dsn(dsn.clone(), Utc::now())
                .await
                .expect("enqueue DSN"),
            "first DSN insert must succeed"
        );
        assert!(
            !ledger
                .enqueue_dsn(dsn, Utc::now())
                .await
                .expect("re-enqueue DSN"),
            "second DSN insert must be a no-op"
        );

        let stats = ledger.stats().await.expect("stats");
        assert!(stats.accepted >= 1);
        assert!(stats.pending >= 1);

        let _ = sqlx::query("DELETE FROM outbound_relay_ledger WHERE send_unit LIKE $1")
            .bind(format!("{unit}%"))
            .execute(&pool)
            .await;
    }

    #[tokio::test]
    async fn pg_ledger_classifies_existing_rows_and_rejects_corruption() {
        let _guard = PG_LEDGER_LOCK.lock().await;
        let Some(pool) = pg_ledger_pool("classify").await else {
            return;
        };
        let ledger = PgLedger::new(pool.clone());
        let submission = |send_unit: &str| NewSubmission {
            send_unit: send_unit.to_string(),
            tenant_id: Some("tenant-classify".to_string()),
            queue_id: None,
            request_fingerprint: None,
            envelope_from: Some("sender@example.com".to_string()),
            recipients: vec!["user@example.com".to_string()],
            message: b"From: x\r\n\r\nbody".to_vec(),
            requested_source_ip: None,
            max_attempts: 12,
        };

        // A queued (pending) row classifies as AlreadyQueued with its stored
        // schedule.
        let queued = format!("outbound-mta-test:classify:queued:{}", Uuid::new_v4());
        seed_row(&pool, &queued, "pending").await;
        sqlx::query(
            "UPDATE outbound_relay_ledger SET next_attempt_at = NOW() + INTERVAL '1 hour' \
             WHERE send_unit = $1",
        )
        .bind(&queued)
        .execute(&pool)
        .await
        .expect("schedule");
        match ledger
            .claim_submission(submission(&queued), Utc::now(), Duration::from_secs(60))
            .await
            .expect("claim queued")
        {
            ClaimOutcome::AlreadyQueued {
                attempt,
                next_attempt_at,
            } => {
                assert_eq!(attempt, 1);
                assert!(next_attempt_at > Utc::now());
            }
            other => panic!("expected AlreadyQueued, got {other:?}"),
        }

        // A terminal failure returns the stored error text.
        let failed = format!("outbound-mta-test:classify:failed:{}", Uuid::new_v4());
        seed_row(&pool, &failed, "failed").await;
        sqlx::query(
            "UPDATE outbound_relay_ledger SET last_error = '5.1.1 nope' WHERE send_unit = $1",
        )
        .bind(&failed)
        .execute(&pool)
        .await
        .expect("last_error");
        match ledger
            .claim_submission(submission(&failed), Utc::now(), Duration::from_secs(60))
            .await
            .expect("claim failed")
        {
            ClaimOutcome::PermanentlyFailed {
                attempt,
                last_error,
            } => {
                assert_eq!(attempt, 1);
                assert_eq!(last_error.as_deref(), Some("5.1.1 nope"));
            }
            other => panic!("expected PermanentlyFailed, got {other:?}"),
        }

        // A crashed `delivering` row with an EXPIRED lease is daemon-owned:
        // a duplicate submit must not deliver it.
        let crashed = format!("outbound-mta-test:classify:crashed:{}", Uuid::new_v4());
        seed_row(&pool, &crashed, "delivering").await;
        sqlx::query("UPDATE outbound_relay_ledger SET lease_until = NOW() - INTERVAL '1 second' WHERE send_unit = $1")
            .bind(&crashed)
            .execute(&pool)
            .await
            .expect("expire lease");
        assert!(matches!(
            ledger
                .claim_submission(submission(&crashed), Utc::now(), Duration::from_secs(60))
                .await
                .expect("claim crashed"),
            ClaimOutcome::AlreadyQueued { .. }
        ));

        // An `accepted` row WITHOUT an acceptance_record is corrupt evidence,
        // not a silent success.
        let corrupt = format!("outbound-mta-test:classify:corrupt:{}", Uuid::new_v4());
        seed_row(&pool, &corrupt, "accepted").await;
        let error = ledger
            .claim_submission(submission(&corrupt), Utc::now(), Duration::from_secs(60))
            .await
            .expect_err("accepted without a record must be corrupt");
        assert!(
            matches!(error, LedgerError::Corrupt { .. }),
            "got {error:?}"
        );

        // A row whose recipients column is not a string array is corrupt on
        // read rather than delivered.
        let bad_recipients = format!("outbound-mta-test:classify:recipients:{}", Uuid::new_v4());
        seed_row(&pool, &bad_recipients, "pending").await;
        sqlx::query(
            "UPDATE outbound_relay_ledger SET recipients = '{\"not\": \"an-array\"}'::jsonb \
             WHERE send_unit = $1",
        )
        .bind(&bad_recipients)
        .execute(&pool)
        .await
        .expect("corrupt recipients");
        let error = ledger
            .get(&bad_recipients)
            .await
            .expect_err("corrupt recipients are surfaced");
        assert!(
            matches!(error, LedgerError::Corrupt { .. }),
            "got {error:?}"
        );

        for unit in [queued, failed, crashed, corrupt, bad_recipients] {
            let _ = sqlx::query("DELETE FROM outbound_relay_ledger WHERE send_unit = $1")
                .bind(unit)
                .execute(&pool)
                .await;
        }
    }

    #[tokio::test]
    async fn pg_ledger_due_sweep_is_ordered_bounded_and_lease_safe() {
        let _guard = PG_LEDGER_LOCK.lock().await;
        let Some(pool) = pg_ledger_pool("due-sweep").await else {
            return;
        };
        let ledger = PgLedger::new(pool.clone());
        let base = format!("outbound-mta-test:due-sweep:{}", Uuid::new_v4());
        let early = format!("{base}:early");
        let late = format!("{base}:late");
        let live = format!("{base}:live");
        seed_row(&pool, &early, "pending").await;
        seed_row(&pool, &late, "pending").await;
        seed_row(&pool, &live, "delivering").await;
        sqlx::query(
            "UPDATE outbound_relay_ledger SET next_attempt_at = TIMESTAMPTZ '2000-01-01' WHERE send_unit = $1",
        )
        .bind(&early)
        .execute(&pool)
        .await
        .expect("age early");
        sqlx::query(
            "UPDATE outbound_relay_ledger SET next_attempt_at = NOW() - INTERVAL '1 minute' WHERE send_unit = $1",
        )
        .bind(&late)
        .execute(&pool)
        .await
        .expect("age late");
        sqlx::query(
            "UPDATE outbound_relay_ledger SET lease_until = NOW() + INTERVAL '10 minutes' WHERE send_unit = $1",
        )
        .bind(&live)
        .execute(&pool)
        .await
        .expect("live lease");

        // limit 1 → exactly the oldest due row, attempt incremented.
        let first = ledger
            .claim_due(Utc::now(), Duration::from_secs(60), 1)
            .await
            .expect("claim one");
        assert_eq!(first.len(), 1);
        assert_eq!(first[0].send_unit, early);
        assert_eq!(first[0].attempt, 2);

        // The next sweep takes the second; the live lease is never stolen.
        let second = ledger
            .claim_due(Utc::now(), Duration::from_secs(60), 10)
            .await
            .expect("claim rest");
        let ours: Vec<&str> = second
            .iter()
            .filter(|row| row.send_unit.starts_with(&base))
            .map(|row| row.send_unit.as_str())
            .collect();
        assert_eq!(ours, vec![late.as_str()]);

        // The due rows are not re-claimable while their fresh lease lives.
        let again = ledger
            .claim_due(Utc::now(), Duration::from_secs(60), 10)
            .await
            .expect("no double claim");
        assert!(
            !again.iter().any(|row| row.send_unit.starts_with(&base)),
            "a fresh lease must not be double-claimed"
        );

        // Reclaim only EXPIRED delivering rows.
        let reclaimed = ledger
            .reclaim_expired(Utc::now() + chrono::Duration::hours(1))
            .await
            .expect("reclaim");
        assert!(reclaimed >= 1, "the expired delivery lease is reclaimed");
        let row = ledger.get(&live).await.expect("get").expect("row");
        assert_eq!(row.state, "pending");
        assert!(row
            .last_error
            .as_deref()
            .unwrap_or("")
            .contains("lease expired"));

        let stats = ledger.stats().await.expect("stats");
        assert!(stats.pending >= 3);
        let _ = sqlx::query("DELETE FROM outbound_relay_ledger WHERE send_unit LIKE $1")
            .bind(format!("{base}%"))
            .execute(&pool)
            .await;
    }

    #[tokio::test]
    async fn pg_ledger_state_writes_are_fenced_and_round_trip_every_field() {
        let _guard = PG_LEDGER_LOCK.lock().await;
        let Some(pool) = pg_ledger_pool("state-writes").await else {
            return;
        };
        let ledger = PgLedger::new(pool.clone());
        let unit = format!("outbound-mta-test:state-writes:{}", Uuid::new_v4());
        let queue_id = Uuid::new_v4();
        let claimed = ledger
            .claim_submission(
                NewSubmission {
                    send_unit: unit.clone(),
                    tenant_id: Some("tenant-rt".to_string()),
                    queue_id: Some(queue_id),
                    request_fingerprint: None,
                    envelope_from: None,
                    recipients: vec!["Ünïcode@example.com".to_string()],
                    message: b"Subject: rt\r\n\r\nbody\x00binary".to_vec(),
                    requested_source_ip: Some("2001:db8::1".parse().expect("v6")),
                    max_attempts: 7,
                },
                Utc::now(),
                Duration::from_secs(60),
            )
            .await
            .expect("claim");
        let row = match claimed {
            ClaimOutcome::Claimed(row) => *row,
            other => panic!("expected Claimed, got {other:?}"),
        };
        assert_eq!(row.envelope_from, None, "null reverse path round-trips");
        assert_eq!(row.recipients, vec!["Ünïcode@example.com".to_string()]);
        assert_eq!(
            row.requested_source_ip,
            Some("2001:db8::1".parse().expect("v6"))
        );
        assert_eq!(row.queue_id, Some(queue_id));
        assert_eq!(row.max_attempts, 7);

        // record_retry only matches a `delivering` row.
        let next = Utc::now() + chrono::Duration::minutes(5);
        ledger
            .record_retry(&unit, 1, next, "test transient")
            .await
            .expect("record retry");
        // A second retry write now matches a `pending` row and must no-op.
        ledger
            .record_retry(&unit, 1, next, "stale writer")
            .await
            .expect("stale retry is a no-op");
        let stored = ledger.get(&unit).await.expect("get").expect("row");
        assert_eq!(stored.state, "pending");
        assert_eq!(stored.last_error.as_deref(), Some("test transient"));

        // Acceptance requires the `delivering` state.
        let due = ledger
            .claim_due(
                next + chrono::Duration::seconds(1),
                Duration::from_secs(60),
                10,
            )
            .await
            .expect("claim due");
        assert_eq!(due.len(), 1);
        assert_eq!(due[0].attempt, 2);
        let record = AcceptanceRecord {
            send_unit: unit.clone(),
            state: "accepted".to_string(),
            accepted_at: Utc::now(),
            attempt: 2,
            remote_mx: Some("mx.example".to_string()),
            tls_used: true,
            requested_source_ip: Some("2001:db8::1".parse().expect("v6")),
            actual_source_ip: Some("2001:db8::1".parse().expect("v6")),
            recipients: Vec::new(),
            dsn_send_units: Vec::new(),
            deferred_retry: None,
        };
        ledger
            .record_accepted(&unit, &record)
            .await
            .expect("record accepted");
        // A second acceptance write no longer matches `delivering`.
        let mut tampered = record.clone();
        tampered.remote_mx = Some("mx.other".to_string());
        ledger
            .record_accepted(&unit, &tampered)
            .await
            .expect("stale acceptance write no-ops");
        // A permanent write after acceptance no-ops too.
        ledger
            .record_permanent(&unit, 2, "stale failure")
            .await
            .expect("stale permanent write no-ops");

        let stored = ledger.get(&unit).await.expect("get").expect("row");
        assert_eq!(stored.state, "accepted");
        assert_eq!(stored.remote_mx.as_deref(), Some("mx.example"));
        assert!(stored.tls_used);
        assert_eq!(
            stored.actual_source_ip,
            Some("2001:db8::1".parse().expect("v6"))
        );
        let acceptance = stored.acceptance.expect("acceptance record");
        assert_eq!(acceptance.send_unit, unit);
        assert_eq!(acceptance.attempt, 2);

        // A garbage lease duration is refused before touching the table.
        let error = ledger
            .claim_submission(
                NewSubmission {
                    send_unit: format!("{unit}:lease"),
                    tenant_id: None,
                    queue_id: None,
                    request_fingerprint: None,
                    envelope_from: None,
                    recipients: vec!["u@example.com".to_string()],
                    message: b"x".to_vec(),
                    requested_source_ip: None,
                    max_attempts: 1,
                },
                Utc::now(),
                Duration::from_secs(u64::MAX),
            )
            .await
            .expect_err("an impossible lease must be refused");
        assert!(matches!(error, LedgerError::Lease(_)), "got {error:?}");

        let _ = sqlx::query("DELETE FROM outbound_relay_ledger WHERE send_unit LIKE $1")
            .bind(format!("{unit}%"))
            .execute(&pool)
            .await;
    }

    /// A partial acceptance commits the deferred subset's follow-up unit in
    /// the SAME transaction as the acceptance evidence, and a replayed
    /// acceptance write (which no longer matches `delivering`) can neither
    /// duplicate nor alter the child.
    #[tokio::test]
    async fn pg_partial_acceptance_commits_the_followup_unit_atomically() {
        let _guard = PG_LEDGER_LOCK.lock().await;
        let Some(pool) = pg_ledger_pool("partial-acceptance").await else {
            return;
        };
        let ledger = PgLedger::new(pool);
        let unit = format!("outbound-mta-test:partial:{}", Uuid::new_v4());
        let claimed = ledger
            .claim_submission(
                NewSubmission {
                    send_unit: unit.clone(),
                    tenant_id: Some("tenant-pa".to_string()),
                    queue_id: None,
                    request_fingerprint: None,
                    envelope_from: Some("sender@apexmail.ee".to_string()),
                    recipients: vec!["a@example.com".to_string(), "b@example.com".to_string()],
                    message: b"Subject: pa\r\n\r\nbody".to_vec(),
                    requested_source_ip: None,
                    max_attempts: 5,
                },
                Utc::now(),
                Duration::from_secs(60),
            )
            .await
            .expect("claim");
        assert!(matches!(claimed, ClaimOutcome::Claimed(_)));

        let child_unit = format!("{unit}#deferred1");
        // Far future: this suite shares one database, and other tests'
        // due-sweeps use minute/hour horizons — a near-future child row would
        // be claimed by THEIR claim_due (and vice versa). The relay-level
        // tests prove the claim path; this test proves the atomic commit.
        let next_attempt_at = Utc::now() + chrono::Duration::days(90);
        let record = AcceptanceRecord {
            send_unit: unit.clone(),
            state: "accepted".to_string(),
            accepted_at: Utc::now(),
            attempt: 1,
            remote_mx: Some("mx.example".to_string()),
            tls_used: true,
            requested_source_ip: None,
            actual_source_ip: None,
            recipients: vec![
                RecipientResult {
                    recipient: "a@example.com".to_string(),
                    outcome: RecipientOutcome::Accepted,
                    reply_code: Some(250),
                    enhanced_status: None,
                    diagnostic: None,
                    mx: Some("mx.example".to_string()),
                    tls_used: true,
                },
                RecipientResult {
                    recipient: "b@example.com".to_string(),
                    outcome: RecipientOutcome::Deferred,
                    reply_code: Some(450),
                    enhanced_status: Some("4.2.1".to_string()),
                    diagnostic: Some("busy".to_string()),
                    mx: Some("mx.example".to_string()),
                    tls_used: true,
                },
            ],
            dsn_send_units: Vec::new(),
            deferred_retry: Some(crate::relay::DeferredRetryPlan {
                send_unit: child_unit.clone(),
                recipients: vec!["b@example.com".to_string()],
                attempt: 1,
                next_attempt_at,
                reason: "smtp; 450 4.2.1 busy".to_string(),
            }),
        };
        ledger
            .record_accepted(&unit, &record)
            .await
            .expect("record accepted");

        // The child exists, carries ONLY the deferred recipient, keeps the
        // original envelope and message, is pending, and is not due yet.
        let child = ledger
            .get(&child_unit)
            .await
            .expect("get")
            .expect("the follow-up row committed with the acceptance");
        assert_eq!(child.state, "pending");
        assert_eq!(child.recipients, vec!["b@example.com".to_string()]);
        assert_eq!(child.envelope_from.as_deref(), Some("sender@apexmail.ee"));
        assert_eq!(child.tenant_id.as_deref(), Some("tenant-pa"));
        assert_eq!(child.attempt, 1);
        assert_eq!(child.max_attempts, 5);
        assert_eq!(child.message, b"Subject: pa\r\n\r\nbody".to_vec());
        assert!(child.next_attempt_at > Utc::now());
        assert_eq!(child.last_error.as_deref(), Some("smtp; 450 4.2.1 busy"));

        // A replayed acceptance write cannot match `delivering`: the child is
        // neither duplicated nor altered.
        ledger
            .record_accepted(&unit, &record)
            .await
            .expect("replay no-ops");
        let child_after = ledger
            .get(&child_unit)
            .await
            .expect("get")
            .expect("child row");
        assert_eq!(child_after.next_attempt_at, child.next_attempt_at);
    }

    /// The in-memory double must classify, fence and count exactly like the
    /// Postgres ledger.
    #[tokio::test]
    async fn memory_ledger_matches_the_pg_semantics() {
        let ledger = MemoryLedger::new();
        let now = Utc::now();
        let submission = |unit: &str| NewSubmission {
            send_unit: unit.to_string(),
            tenant_id: None,
            queue_id: None,
            request_fingerprint: None,
            envelope_from: None,
            recipients: vec!["u@example.com".to_string()],
            message: b"x".to_vec(),
            requested_source_ip: None,
            max_attempts: 3,
        };

        assert!(ledger.get("missing").await.expect("get").is_none());
        assert_eq!(ledger.reclaim_expired(now).await.expect("reclaim"), 0);
        assert_eq!(
            ledger
                .claim_due(now, Duration::from_secs(1), 0)
                .await
                .expect("limit 0")
                .len(),
            0
        );

        let first = ledger
            .claim_submission(submission("mem-1"), now, Duration::from_secs(60))
            .await
            .expect("claim");
        assert!(matches!(first, ClaimOutcome::Claimed(_)));
        // Writes against a live lease: retry/permanent fence on delivering.
        ledger
            .record_retry("mem-1", 1, now + chrono::Duration::minutes(1), "later")
            .await
            .expect("retry");
        let row = ledger.get("mem-1").await.expect("get").expect("row");
        assert_eq!(row.state, "pending");
        assert_eq!(row.attempt, 1);

        // A queued retry is not yet due.
        assert_eq!(
            ledger
                .claim_due(now, Duration::from_secs(60), 10)
                .await
                .expect("not due")
                .len(),
            0
        );
        let due = ledger
            .claim_due(
                now + chrono::Duration::minutes(2),
                Duration::from_secs(60),
                10,
            )
            .await
            .expect("due");
        assert_eq!(due.len(), 1);
        assert_eq!(due[0].attempt, 2);

        // record_accepted then record_permanent: the second must no-op.
        let record = AcceptanceRecord {
            send_unit: "mem-1".to_string(),
            state: "accepted".to_string(),
            accepted_at: now,
            attempt: 2,
            remote_mx: None,
            tls_used: false,
            requested_source_ip: None,
            actual_source_ip: None,
            recipients: Vec::new(),
            dsn_send_units: Vec::new(),
            deferred_retry: None,
        };
        ledger
            .record_accepted("mem-1", &record)
            .await
            .expect("accept");
        ledger
            .record_permanent("mem-1", 2, "stale")
            .await
            .expect("no-op");
        let row = ledger.get("mem-1").await.expect("get").expect("row");
        assert_eq!(row.state, "accepted");
        assert!(row.acceptance.is_some());

        // DSN enqueue is insert-once; the DSN starts pending with attempt 0.
        let mut dsn = submission("mem-1:dsn");
        dsn.envelope_from = None;
        assert!(ledger.enqueue_dsn(dsn.clone(), now).await.expect("dsn"));
        assert!(!ledger.enqueue_dsn(dsn, now).await.expect("dsn replay"));
        let dsn_row = ledger.get("mem-1:dsn").await.expect("get").expect("row");
        assert_eq!(dsn_row.state, "pending");
        assert_eq!(dsn_row.attempt, 0);
        assert_eq!(dsn_row.envelope_from, None);

        // Stats count every state bucket.
        let stats = ledger.stats().await.expect("stats");
        assert_eq!(stats.accepted, 1);
        assert_eq!(stats.pending, 1);
        assert_eq!(stats.failed, 0);
        assert_eq!(stats.delivering, 0);
    }
}
