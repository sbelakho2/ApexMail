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
    AlreadyAccepted(AcceptanceRecord),
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
const LEDGER_COLUMNS: &str = "send_unit, tenant_id, queue_id, state, envelope_from, recipients, \
     message, requested_source_ip::text AS requested_source_ip, \
     actual_source_ip::text AS actual_source_ip, remote_mx, tls_used, attempt, max_attempts, \
     next_attempt_at, lease_until, acceptance_record, last_error, created_at";

#[derive(sqlx::FromRow)]
struct LedgerRow {
    send_unit: String,
    tenant_id: Option<String>,
    queue_id: Option<Uuid>,
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
    state: &str,
    attempt: i32,
    next_attempt_at: DateTime<Utc>,
    lease_until: Option<DateTime<Utc>>,
    acceptance_record: Option<serde_json::Value>,
    last_error: Option<String>,
    now: DateTime<Utc>,
) -> Result<ClaimOutcome, LedgerError> {
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
            Ok(ClaimOutcome::AlreadyAccepted(record))
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
             (send_unit, tenant_id, queue_id, state, envelope_from, recipients, message, \
              requested_source_ip, attempt, max_attempts, next_attempt_at, lease_until, updated_at) \
             VALUES ($1, $2, $3, 'delivering', $4, $5, $6, $7::text::inet, 1, $8, $9, $10, NOW()) \
             ON CONFLICT (send_unit) DO NOTHING \
             RETURNING {LEDGER_COLUMNS}"
        );
        let inserted: Option<LedgerRow> = sqlx::query_as(&insert)
            .bind(&new.send_unit)
            .bind(&new.tenant_id)
            .bind(new.queue_id)
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
            "SELECT state, attempt, next_attempt_at, lease_until, acceptance_record, last_error \
             FROM outbound_relay_ledger WHERE send_unit = $1",
        )
        .bind(&new.send_unit)
        .fetch_optional(&self.pool)
        .await?;
        let state = state.ok_or_else(|| LedgerError::Corrupt {
            send_unit: new.send_unit.clone(),
            message: "row vanished between insert conflict and classification".to_string(),
        })?;
        classify_existing(
            &new.send_unit,
            &state.state,
            state.attempt,
            state.next_attempt_at,
            state.lease_until,
            state.acceptance_record,
            state.last_error,
            now,
        )
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
        .execute(&self.pool)
        .await?;
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
        Ok(stats)
    }
}

/// In-memory ledger used by the delivery tests (same semantics as
/// [`PgLedger`], including the claim classification).
#[cfg(test)]
pub(crate) mod test_support {
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
                    return classify_existing(
                        &existing.send_unit,
                        &existing.state,
                        existing.attempt as i32,
                        existing.next_attempt_at,
                        existing.lease_until,
                        existing
                            .acceptance
                            .as_ref()
                            .and_then(|record| serde_json::to_value(record).ok()),
                        existing.last_error.clone(),
                        now,
                    );
                }
                let submission = QueuedSubmission {
                    send_unit: new.send_unit.clone(),
                    tenant_id: new.tenant_id,
                    queue_id: new.queue_id,
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
                    }
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
                for entry in entries.values() {
                    match entry.state.as_str() {
                        "pending" => stats.pending += 1,
                        "delivering" => stats.delivering += 1,
                        "accepted" => stats.accepted += 1,
                        "failed" => stats.failed += 1,
                        _ => {}
                    }
                }
                stats
            }))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::relay::{AcceptanceRecord, RecipientOutcome, RecipientResult};

    /// Round-trips every ledger statement against a REAL Postgres schema
    /// (migration 212). Gated on `OUTBOUND_MTA_TEST_DATABASE_URL` so the
    /// default `cargo test` run stays hermetic.
    #[tokio::test]
    async fn pg_ledger_round_trip_is_idempotent() {
        let Ok(url) = std::env::var("OUTBOUND_MTA_TEST_DATABASE_URL") else {
            eprintln!("skipping: OUTBOUND_MTA_TEST_DATABASE_URL is not set");
            return;
        };
        let pool = PgPool::connect(&url)
            .await
            .expect("connect to OUTBOUND_MTA_TEST_DATABASE_URL");
        let ledger = PgLedger::new(pool.clone());
        // Clear rows left behind by a previously failed run of this test.
        let _ = sqlx::query(
            "DELETE FROM outbound_relay_ledger WHERE send_unit LIKE 'outbound-mta-test:%'",
        )
        .execute(&pool)
        .await;
        let unit = format!("outbound-mta-test:{}", Uuid::new_v4());
        let submission = || NewSubmission {
            send_unit: unit.clone(),
            tenant_id: Some("tenant-test".to_string()),
            queue_id: None,
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
}
