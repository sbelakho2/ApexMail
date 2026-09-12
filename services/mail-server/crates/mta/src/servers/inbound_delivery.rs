//! Durable post-accept delivery for inbound mail.
//!
//! The inbound SMTP server used to hand a 250-accepted message to the
//! mailstore inline, after the final `250`; a recipient with no mailstore
//! account was skipped at DEBUG level and a persistent mailstore failure
//! stranded the message with only an ERROR log. That is an accept-then-drop
//! failure. This module closes it with the ledger introduced by migration
//! `210_inbound_delivery_ledger.sql`:
//!
//! * `InboundServer::process_message` writes `inbound_messages` + one
//!   `inbound_recipients` job per accepted recipient in ONE transaction
//!   before the `250` (see [`super::inbound`]).
//! * [`run_sweep`] claims due jobs, attempts mailbox delivery, records every
//!   attempt in `inbound_delivery_attempts`, backs off transient failures,
//!   and — for a permanent post-accept failure whose original envelope
//!   sender is non-null — generates an RFC 3464 DSN exactly once (guarded by
//!   `inbound_recipients.dsn_generated_at`).
//! * A NULL return path (`<>`) never receives a DSN (RFC 5321 §4.5.5); the
//!   job is marked `undeliverable` instead.
//!
//! The worker is scheduling-agnostic: [`run_sweep`] takes `now` as a
//! parameter and the storage/mailstore/DSN effects sit behind small traits,
//! so the retry, idempotency and null-path rules are unit-testable without a
//! live database, mailstore or SMTP network.
//!
//! DSN transport: the MTA has no outbound SMTP stack (submission/mta queue
//! mail through `email_queue`, which `worker-processors` delivers). The DSN
//! is therefore durably enqueued through that same pipeline by
//! [`PgDsnDispatcher`], with the complete RFC 3464 MIME preserved in the
//! queue row; the ledger records `dsn_sent` + `dsn_generated_at` only after
//! the queue row committed.

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use mail_proto::mailstore_service_client::MailstoreServiceClient;
use mail_proto::{
    GetAccountRequest, InternalServiceAuthInterceptor, MessageFlags, StoreMessageRequest,
};
use sqlx::PgPool;
use tokio::sync::Notify;
use tonic::transport::Channel;
use tracing::{debug, error, info, warn};

use super::inbound::recipient_domain;

type MailstoreClient = MailstoreServiceClient<
    tonic::service::interceptor::InterceptedService<Channel, InternalServiceAuthInterceptor>,
>;

// ── status vocabulary (mirrors the CHECK in migration 210) ─────────────────────

pub const STATUS_PENDING: &str = "pending";
pub const STATUS_DELIVERING: &str = "delivering";
pub const STATUS_DEFERRED: &str = "deferred";
pub const STATUS_DELIVERED: &str = "delivered";
pub const STATUS_FAILED: &str = "failed";
pub const STATUS_DSN_SENT: &str = "dsn_sent";
pub const STATUS_UNDELIVERABLE: &str = "undeliverable";

/// The claim predicate in SQL must stay in lockstep with this list.
const CLAIMABLE_STATUSES_SQL: &str = "('pending', 'delivering', 'deferred', 'failed')";

pub const INBOX_MAILBOX: &str = "Inbox";
pub const QUARANTINE_MAILBOX: &str = "Spam";

const MAILSTORE_CHANNEL_TIMEOUT: Duration = Duration::from_secs(10);
const MAILSTORE_RPC_TIMEOUT: Duration = Duration::from_secs(10);

/// Delivery lease for a claimed job: a worker crash leaves the row
/// reclaimable once `next_attempt_at` passes.
const CLAIM_LEASE_SECS: i64 = 120;
const SWEEP_BATCH: i64 = 32;
const SWEEP_POLL_SECS: u64 = 5;
/// Backoff before retrying a DSN dispatch that could not be durably queued
/// (e.g. the receiving domain has no ready DKIM key yet).
const DSN_RETRY_SECS: i64 = 300;

const DSN_SUBJECT: &str = "Undelivered Mail Returned to Sender";
/// Cap on the original message copied into the DSN's `message/rfc822` part;
/// beyond it only the original headers are included (RFC 3464 §6.2 allows
/// returning headers only).
const DSN_MAX_ORIGINAL_BYTES: usize = 256 * 1024;
const DSN_MAX_HEADER_BYTES: usize = 64 * 1024;
const LAST_ERROR_MAX_CHARS: usize = 2000;

// ── data types ─────────────────────────────────────────────────────────────────

/// One recipient job claimed from `inbound_recipients`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecipientJob {
    pub message_id: String,
    pub recipient: String,
    /// `mail_accounts.id` resolved at RCPT time (None for legacy rows).
    pub mailbox_id: Option<String>,
    /// Status BEFORE the claim: `failed` means mailbox delivery is already
    /// over and only a pending DSN dispatch remains.
    pub prior_status: String,
    pub attempt: i32,
    pub last_error: Option<String>,
}

impl RecipientJob {
    /// True when the row was claimed only to retry a previously failed DSN
    /// dispatch (mailbox delivery must not run again).
    pub fn is_dsn_retry(&self) -> bool {
        self.prior_status == STATUS_FAILED
    }
}

/// The stored inbound message a job delivers (or reports on).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredInboundMessage {
    /// Envelope sender; "" for the null return path `<>`.
    pub mail_from: String,
    pub disposition: String,
    /// Refcounted: one buffer backs every job of the same message and every
    /// retry/DSN render.
    pub raw_message: Option<bytes::Bytes>,
}

/// Result of one mailbox delivery attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeliveryOutcome {
    Delivered,
    /// Service/network failure: retry with backoff.
    Transient {
        error: String,
    },
    /// Determinate failure: no more mailbox delivery attempts. `dsn_status`
    /// is the RFC 3463 code to report in the DSN.
    Permanent {
        error: String,
        dsn_status: &'static str,
    },
}

#[derive(Debug, Clone)]
pub struct AttemptRecord {
    pub message_id: String,
    pub recipient: String,
    pub attempt: i32,
    pub stage: &'static str,
    pub outcome: &'static str,
    pub error: Option<String>,
}

/// Backoff policy for post-accept mailbox delivery.
#[derive(Debug, Clone)]
pub struct RetryPolicy {
    pub max_attempts: u32,
    pub backoff_secs: Vec<i64>,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        // ~30 s, 2 min, 10 min, 30 min, 1 h, 2 h, 6 h, 12 h — then the
        // permanent/DSN path. The total window comfortably exceeds a
        // mailstore rolling restart.
        Self {
            max_attempts: 8,
            backoff_secs: vec![30, 120, 600, 1800, 3600, 7200, 21600, 43200],
        }
    }
}

impl RetryPolicy {
    /// Delay before attempt number `attempt` (1-based, i.e. the attempt that
    /// follows `attempt - 1` failures).
    pub fn delay_secs(&self, attempt: u32) -> i64 {
        if self.backoff_secs.is_empty() {
            return 300;
        }
        let index = attempt.saturating_sub(1) as usize;
        self.backoff_secs[index.min(self.backoff_secs.len() - 1)]
    }
}

#[derive(Debug, Clone)]
pub struct SweepConfig {
    pub batch: i64,
    pub lease_secs: i64,
    pub dsn_retry_secs: i64,
    pub hostname: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SweepStats {
    pub claimed: usize,
    pub delivered: usize,
    pub deferred: usize,
    pub permanent: usize,
    pub dsn_sent: usize,
    pub dsn_deferred: usize,
    pub undeliverable: usize,
}

// ── storage / effect traits ────────────────────────────────────────────────────

#[async_trait]
pub trait InboundDeliveryStore: Send + Sync {
    async fn claim_due(
        &self,
        now: DateTime<Utc>,
        limit: i64,
        lease_secs: i64,
    ) -> anyhow::Result<Vec<RecipientJob>>;
    async fn load_message(&self, message_id: &str) -> anyhow::Result<Option<StoredInboundMessage>>;
    async fn record_attempt(&self, record: &AttemptRecord) -> anyhow::Result<()>;
    async fn mark_delivered(&self, job: &RecipientJob, attempt: i32) -> anyhow::Result<()>;
    async fn mark_deferred(
        &self,
        job: &RecipientJob,
        attempt: i32,
        next_attempt_at: DateTime<Utc>,
        error: &str,
    ) -> anyhow::Result<()>;
    async fn mark_permanent_failure(
        &self,
        job: &RecipientJob,
        attempt: i32,
        error: &str,
    ) -> anyhow::Result<()>;
    async fn mark_undeliverable(
        &self,
        job: &RecipientJob,
        attempt: i32,
        error: &str,
    ) -> anyhow::Result<()>;
    /// Atomically guards one DSN dispatch per recipient: returns true only
    /// while `status <> 'dsn_sent'`, stamping `dsn_generated_at`. A crash
    /// between claim and `mark_dsn_sent` re-dispatches on the next sweep
    /// (at-least-once: a duplicate DSN is preferable to a lost one); a
    /// finalized `dsn_sent` row can never be claimed again.
    async fn claim_dsn(&self, job: &RecipientJob) -> anyhow::Result<bool>;
    async fn mark_dsn_sent(&self, job: &RecipientJob, attempt: i32) -> anyhow::Result<()>;
    async fn release_dsn_claim(
        &self,
        job: &RecipientJob,
        next_attempt_at: DateTime<Utc>,
        error: &str,
    ) -> anyhow::Result<()>;
}

#[async_trait]
pub trait MailboxDeliverer: Send + Sync {
    async fn deliver(&self, job: &RecipientJob, message: &StoredInboundMessage) -> DeliveryOutcome;
}

#[async_trait]
pub trait DsnDispatcher: Send + Sync {
    /// Durably hands the DSN to the outbound path. `Err` means nothing was
    /// committed and the claim must be released for a later retry.
    async fn dispatch(&self, dsn: &DeliveryStatusNotification) -> Result<(), String>;
}

// ── RFC 3464 DSN ───────────────────────────────────────────────────────────────

/// A delivery status notification (RFC 3464) about one permanently failed
/// inbound recipient.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeliveryStatusNotification {
    /// Reporting MTA hostname (`Reporting-MTA: dns; <hostname>`).
    pub reporting_mta: String,
    pub original_sender: String,
    pub original_recipient: String,
    pub original_message_id: String,
    pub arrival_date: DateTime<Utc>,
    pub status: String,
    pub diagnostic: String,
    /// The original stored message; the headers are always included, the
    /// body only up to [`DSN_MAX_ORIGINAL_BYTES`]. Refcounted with the
    /// delivery path's buffer.
    pub original_message: Option<bytes::Bytes>,
}

/// True when a DSN may be generated for a message with this envelope sender:
/// a non-empty reverse-path that is not the null sender `<>`.
pub fn dsn_eligible(mail_from: &str) -> bool {
    let trimmed = mail_from.trim();
    !trimmed.is_empty() && trimmed != "<>"
}

impl DeliveryStatusNotification {
    /// Deterministic per failed recipient: a retried dispatch that already
    /// reached a mailstore reuses the same Message-ID and is deduplicated
    /// there (StoreMessage dedups on Message-ID).
    pub fn message_id(&self) -> String {
        let hash = short_hash(&format!(
            "{}|{}|{}",
            self.original_message_id, self.original_recipient, self.original_sender
        ));
        format!(
            "<dsn.{hash}@{}>",
            sanitize_header_value(&self.reporting_mta)
        )
    }

    pub fn boundary(&self) -> String {
        format!(
            "=_apexmail_dsn_{}",
            short_hash(&format!(
                "{}|{}",
                self.original_message_id, self.original_recipient
            ))
        )
    }

    /// Human-readable first part of the report (also used as the outbound
    /// plain-text body).
    pub fn human_readable(&self) -> String {
        format!(
            "This is the mail delivery system at {mta}.\r\n\
             \r\n\
             Your message could not be delivered to one or more recipients.\r\n\
             \r\n\
             \x20   <{recipient}>: {diagnostic}\r\n\
             \r\n\
             No action is required on your part.\r\n",
            mta = sanitize_header_value(&self.reporting_mta),
            recipient = single_line(&self.original_recipient, 998),
            diagnostic = single_line(&self.diagnostic, LAST_ERROR_MAX_CHARS),
        )
    }

    /// Render the complete RFC 3464 `multipart/report` message with CRLF
    /// line endings. All interpolated values are single-lined first: a
    /// hostile address or diagnostic string can never inject a header or a
    /// MIME part.
    pub fn render(&self, envelope_from: &str) -> Vec<u8> {
        let boundary = self.boundary();
        let from = sanitize_header_value(envelope_from);
        let to = sanitize_header_value(&self.original_sender);
        let status = sanitize_status(&self.status);
        let diagnostic = single_line(&self.diagnostic, LAST_ERROR_MAX_CHARS);
        let reporting_mta = sanitize_header_value(&self.reporting_mta);
        let original_recipient = single_line(&self.original_recipient, 998);
        let original_message_id = single_line(&self.original_message_id, 998);
        let date = self.arrival_date.to_rfc2822();

        let mut out =
            Vec::with_capacity(1024 + self.original_message.as_ref().map_or(0, bytes::Bytes::len));
        push_str(
            &mut out,
            &format!(
                "From: Mail Delivery Subsystem <{from}>\r\n\
                 To: <{to}>\r\n\
                 Subject: {DSN_SUBJECT}\r\n\
                 Date: {date}\r\n\
                 Message-ID: {}\r\n\
                 Auto-Submitted: auto-replied\r\n\
                 MIME-Version: 1.0\r\n\
                 Content-Type: multipart/report; report-type=delivery-status;\r\n\
                 \x20boundary=\"{boundary}\"\r\n\
                 \r\n\
                 --{boundary}\r\n\
                 Content-Type: text/plain; charset=us-ascii\r\n\
                 Content-Transfer-Encoding: 7bit\r\n\
                 \r\n",
                self.message_id(),
            ),
        );
        push_str(&mut out, &self.human_readable());
        push_str(
            &mut out,
            &format!(
                "\r\n--{boundary}\r\n\
                 Content-Type: message/delivery-status\r\n\
                 \r\n\
                 Reporting-MTA: dns; {reporting_mta}\r\n\
                 X-Queue-ID: {original_message_id}\r\n\
                 Arrival-Date: {date}\r\n\
                 \r\n\
                 Final-Recipient: rfc822; {original_recipient}\r\n\
                 Original-Recipient: rfc822; {original_recipient}\r\n\
                 Action: failed\r\n\
                 Status: {status}\r\n\
                 Diagnostic-Code: X-APEXMAIL; {diagnostic}\r\n",
            ),
        );

        if let Some(original) = self.original_part() {
            push_str(
                &mut out,
                &format!("\r\n--{boundary}\r\nContent-Type: message/rfc822\r\n\r\n"),
            );
            out.extend_from_slice(&original);
        }

        push_str(&mut out, &format!("\r\n--{boundary}--\r\n"));
        out
    }

    /// The `message/rfc822` part: the full original when small, otherwise
    /// the headers only (bounded).
    fn original_part(&self) -> Option<bytes::Bytes> {
        let raw = self.original_message.as_ref()?;
        if raw.is_empty() {
            return None;
        }
        if raw.len() <= DSN_MAX_ORIGINAL_BYTES {
            return Some(raw.clone());
        }
        let header_end = find_header_end(raw).unwrap_or(raw.len());
        let cap = header_end.min(DSN_MAX_HEADER_BYTES);
        Some(bytes::Bytes::copy_from_slice(&raw[..cap]))
    }
}

/// RFC 3463 status code whitelist; anything malformed becomes `5.4.7`
/// (delivery time expired), the catch-all permanent post-accept failure.
fn sanitize_status(value: &str) -> String {
    let value = value.trim();
    let parts: Vec<&str> = value.split('.').collect();
    let valid = parts.len() == 3
        && (parts[0] == "4" || parts[0] == "5")
        && parts.iter().all(|part| {
            !part.is_empty() && part.len() <= 3 && part.chars().all(|c| c.is_ascii_digit())
        });
    if valid {
        value.to_string()
    } else {
        "5.4.7".to_string()
    }
}

/// Strip CR/LF (and NUL) so a value can never break a header line.
fn sanitize_header_value(value: &str) -> String {
    value
        .chars()
        .map(|c| match c {
            '\r' | '\n' | '\0' => ' ',
            other => other,
        })
        .collect::<String>()
        .trim()
        .to_string()
}

/// One physical line, capped; embedded CR/LF become spaces.
fn single_line(value: &str, cap: usize) -> String {
    let mut line = sanitize_header_value(value);
    if line.chars().count() > cap {
        line = line.chars().take(cap).collect();
    }
    line
}

fn push_str(out: &mut Vec<u8>, value: &str) {
    out.extend_from_slice(value.as_bytes());
}

fn find_header_end(raw: &[u8]) -> Option<usize> {
    raw.windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|position| position + 4)
        .or_else(|| {
            raw.windows(2)
                .position(|window| window == b"\n\n")
                .map(|position| position + 2)
        })
}

/// FNV-1a: stable, dependency-free identifier hashing (not security).
fn fnv1a64(bytes: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

fn short_hash(value: &str) -> String {
    format!("{:016x}", fnv1a64(value.as_bytes()))
}

fn truncate_error(error: &str) -> String {
    if error.chars().count() <= LAST_ERROR_MAX_CHARS {
        return error.to_string();
    }
    error.chars().take(LAST_ERROR_MAX_CHARS).collect()
}

// ── sweep core ─────────────────────────────────────────────────────────────────

/// One pass over the due recipient jobs. Pure orchestration over the three
/// traits + an explicit `now`, so retry/idempotency semantics are testable
/// without a database.
pub async fn run_sweep(
    store: &dyn InboundDeliveryStore,
    deliverer: &dyn MailboxDeliverer,
    dsn_dispatcher: &dyn DsnDispatcher,
    policy: &RetryPolicy,
    config: &SweepConfig,
    now: DateTime<Utc>,
) -> anyhow::Result<SweepStats> {
    let jobs = store
        .claim_due(now, config.batch, config.lease_secs)
        .await?;
    let mut stats = SweepStats {
        claimed: jobs.len(),
        ..SweepStats::default()
    };
    // Multi-recipient messages share one loaded copy per sweep (the raw
    // message is refcounted `Bytes`; `clone` never copies the body).
    let mut message_cache: std::collections::HashMap<String, StoredInboundMessage> =
        std::collections::HashMap::new();

    for job in jobs {
        let message = if let Some(cached) = message_cache.get(&job.message_id) {
            cached.clone()
        } else {
            match store.load_message(&job.message_id).await {
                Ok(Some(message)) => {
                    message_cache.insert(job.message_id.clone(), message.clone());
                    message
                }
                Ok(None) => {
                    defer_with_error(store, &job, now, policy, "inbound_messages row is missing")
                        .await?;
                    stats.deferred += 1;
                    continue;
                }
                Err(error) => {
                    defer_with_error(
                        store,
                        &job,
                        now,
                        policy,
                        &format!("failed to load inbound message: {error}"),
                    )
                    .await?;
                    stats.deferred += 1;
                    continue;
                }
            }
        };

        if job.is_dsn_retry() {
            // Mailbox delivery already failed permanently in an earlier
            // sweep; only the DSN dispatch is outstanding.
            let diagnostic = job
                .last_error
                .clone()
                .unwrap_or_else(|| "permanent post-accept delivery failure".to_string());
            dispatch_dsn(
                store,
                dsn_dispatcher,
                &job,
                &message,
                job.attempt.max(1),
                &diagnostic,
                "5.4.7",
                now,
                config,
                &mut stats,
            )
            .await?;
            continue;
        }

        let attempt = job.attempt + 1;
        match deliverer.deliver(&job, &message).await {
            DeliveryOutcome::Delivered => {
                store.mark_delivered(&job, attempt).await?;
                store
                    .record_attempt(&AttemptRecord {
                        message_id: job.message_id.clone(),
                        recipient: job.recipient.clone(),
                        attempt,
                        stage: "delivery",
                        outcome: "delivered",
                        error: None,
                    })
                    .await?;
                metrics::counter!("mta.inbound.recipient_delivered").increment(1);
                stats.delivered += 1;
            }
            DeliveryOutcome::Transient { error } => {
                if attempt >= policy.max_attempts as i32 {
                    let error = format!(
                        "retries exhausted after {attempt} attempt(s): {}",
                        truncate_error(&error)
                    );
                    handle_permanent_failure(
                        store,
                        dsn_dispatcher,
                        &job,
                        &message,
                        attempt,
                        &error,
                        "5.4.7",
                        now,
                        config,
                        &mut stats,
                    )
                    .await?;
                } else {
                    let next_attempt_at =
                        now + chrono::Duration::seconds(policy.delay_secs(attempt as u32));
                    store
                        .mark_deferred(&job, attempt, next_attempt_at, &truncate_error(&error))
                        .await?;
                    store
                        .record_attempt(&AttemptRecord {
                            message_id: job.message_id.clone(),
                            recipient: job.recipient.clone(),
                            attempt,
                            stage: "delivery",
                            outcome: "transient",
                            error: Some(truncate_error(&error)),
                        })
                        .await?;
                    metrics::counter!("mta.inbound.recipient_deferred").increment(1);
                    stats.deferred += 1;
                }
            }
            DeliveryOutcome::Permanent { error, dsn_status } => {
                handle_permanent_failure(
                    store,
                    dsn_dispatcher,
                    &job,
                    &message,
                    attempt,
                    &truncate_error(&error),
                    dsn_status,
                    now,
                    config,
                    &mut stats,
                )
                .await?;
            }
        }
    }

    Ok(stats)
}

async fn defer_with_error(
    store: &dyn InboundDeliveryStore,
    job: &RecipientJob,
    now: DateTime<Utc>,
    policy: &RetryPolicy,
    error: &str,
) -> anyhow::Result<()> {
    let attempt = job.attempt + 1;
    let next_attempt_at = now + chrono::Duration::seconds(policy.delay_secs(attempt as u32));
    let error = truncate_error(error);
    store
        .mark_deferred(job, attempt, next_attempt_at, &error)
        .await?;
    store
        .record_attempt(&AttemptRecord {
            message_id: job.message_id.clone(),
            recipient: job.recipient.clone(),
            attempt,
            stage: "delivery",
            outcome: "transient",
            error: Some(error),
        })
        .await?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn handle_permanent_failure(
    store: &dyn InboundDeliveryStore,
    dsn_dispatcher: &dyn DsnDispatcher,
    job: &RecipientJob,
    message: &StoredInboundMessage,
    attempt: i32,
    error: &str,
    dsn_status: &'static str,
    now: DateTime<Utc>,
    config: &SweepConfig,
    stats: &mut SweepStats,
) -> anyhow::Result<()> {
    if !dsn_eligible(&message.mail_from) {
        // NULL return path: RFC 5321 §4.5.5 forbids generating a DSN. The
        // ledger records the terminal state instead of silently dropping.
        store.mark_undeliverable(job, attempt, error).await?;
        store
            .record_attempt(&AttemptRecord {
                message_id: job.message_id.clone(),
                recipient: job.recipient.clone(),
                attempt,
                stage: "delivery",
                outcome: "permanent",
                error: Some(error.to_string()),
            })
            .await?;
        warn!(
            message_id = %job.message_id,
            recipient = %mail_common::pii::redact_email(&job.recipient),
            error = %error,
            "Inbound recipient permanently failed with a null return path; no DSN permitted"
        );
        metrics::counter!("mta.inbound.recipient_undeliverable").increment(1);
        stats.undeliverable += 1;
        return Ok(());
    }

    store.mark_permanent_failure(job, attempt, error).await?;
    store
        .record_attempt(&AttemptRecord {
            message_id: job.message_id.clone(),
            recipient: job.recipient.clone(),
            attempt,
            stage: "delivery",
            outcome: "permanent",
            error: Some(error.to_string()),
        })
        .await?;
    error!(
        message_id = %job.message_id,
        recipient = %mail_common::pii::redact_email(&job.recipient),
        error = %error,
        "Inbound recipient permanently failed after acceptance; generating a DSN"
    );
    metrics::counter!("mta.inbound.recipient_permanent").increment(1);
    stats.permanent += 1;

    dispatch_dsn(
        store,
        dsn_dispatcher,
        job,
        message,
        attempt,
        error,
        dsn_status,
        now,
        config,
        stats,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn dispatch_dsn(
    store: &dyn InboundDeliveryStore,
    dsn_dispatcher: &dyn DsnDispatcher,
    job: &RecipientJob,
    message: &StoredInboundMessage,
    attempt: i32,
    diagnostic: &str,
    dsn_status: &'static str,
    now: DateTime<Utc>,
    config: &SweepConfig,
    stats: &mut SweepStats,
) -> anyhow::Result<()> {
    // Single-dispatch guard: a finalized (`dsn_sent`) row can never be
    // claimed again, so a second sweep/worker sees false and sends nothing.
    // A crash between claim and `mark_dsn_sent` re-dispatches on a later
    // sweep — at-least-once, never a lost DSN.
    if !store.claim_dsn(job).await? {
        debug!(
            message_id = %job.message_id,
            recipient = %mail_common::pii::redact_email(&job.recipient),
            "DSN already generated for this recipient; skipping"
        );
        return Ok(());
    }

    let dsn = DeliveryStatusNotification {
        reporting_mta: config.hostname.clone(),
        original_sender: message.mail_from.clone(),
        original_recipient: job.recipient.clone(),
        original_message_id: job.message_id.clone(),
        arrival_date: now,
        status: dsn_status.to_string(),
        diagnostic: single_line(diagnostic, LAST_ERROR_MAX_CHARS),
        original_message: message.raw_message.clone(),
    };

    match dsn_dispatcher.dispatch(&dsn).await {
        Ok(()) => {
            store.mark_dsn_sent(job, attempt).await?;
            store
                .record_attempt(&AttemptRecord {
                    message_id: job.message_id.clone(),
                    recipient: job.recipient.clone(),
                    attempt: attempt.max(1),
                    stage: "dsn",
                    outcome: "delivered",
                    error: None,
                })
                .await?;
            info!(
                message_id = %job.message_id,
                recipient = %mail_common::pii::redact_email(&job.recipient),
                "RFC 3464 DSN enqueued for permanently failed inbound recipient"
            );
            metrics::counter!("mta.inbound.dsn_generated").increment(1);
            stats.dsn_sent += 1;
        }
        Err(error) => {
            let next_attempt_at = now + chrono::Duration::seconds(config.dsn_retry_secs);
            let error = truncate_error(&error);
            store
                .release_dsn_claim(
                    job,
                    next_attempt_at,
                    &format!("DSN dispatch failed: {error}"),
                )
                .await?;
            store
                .record_attempt(&AttemptRecord {
                    message_id: job.message_id.clone(),
                    recipient: job.recipient.clone(),
                    attempt: attempt.max(1),
                    stage: "dsn",
                    outcome: "transient",
                    error: Some(error),
                })
                .await?;
            metrics::counter!("mta.inbound.dsn_deferred").increment(1);
            stats.dsn_deferred += 1;
        }
    }

    Ok(())
}

// ── PostgreSQL store ───────────────────────────────────────────────────────────

pub struct PgInboundDeliveryStore {
    pool: PgPool,
}

impl PgInboundDeliveryStore {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl InboundDeliveryStore for PgInboundDeliveryStore {
    async fn claim_due(
        &self,
        now: DateTime<Utc>,
        limit: i64,
        lease_secs: i64,
    ) -> anyhow::Result<Vec<RecipientJob>> {
        // One statement: the CTE locks due rows (SKIP LOCKED for concurrent
        // workers) and the UPDATE claims them with a fresh lease. A crashed
        // worker's `delivering` row becomes due again when the lease expires.
        let sql = format!(
            r#"
            WITH due AS (
                SELECT message_id, recipient, status AS prior_status
                  FROM inbound_recipients
                 WHERE next_attempt_at <= $1
                   AND status IN {CLAIMABLE_STATUSES_SQL}
                 ORDER BY next_attempt_at ASC
                 LIMIT $3
                 FOR UPDATE SKIP LOCKED
            )
            UPDATE inbound_recipients AS ir
               SET status = 'delivering',
                   next_attempt_at = $1::timestamptz + make_interval(secs => $2),
                   updated_at = NOW()
              FROM due
             WHERE ir.message_id = due.message_id
               AND ir.recipient = due.recipient
            RETURNING ir.message_id, ir.recipient, ir.mailbox_id,
                      due.prior_status, ir.attempt, ir.last_error
            "#
        );
        let rows: Vec<(String, String, Option<String>, String, i32, Option<String>)> =
            sqlx::query_as(&sql)
                .bind(now)
                .bind(lease_secs as f64)
                .bind(limit)
                .fetch_all(&self.pool)
                .await?;
        Ok(rows
            .into_iter()
            .map(
                |(message_id, recipient, mailbox_id, prior_status, attempt, last_error)| {
                    RecipientJob {
                        message_id,
                        recipient,
                        mailbox_id,
                        prior_status,
                        attempt,
                        last_error,
                    }
                },
            )
            .collect())
    }

    async fn load_message(&self, message_id: &str) -> anyhow::Result<Option<StoredInboundMessage>> {
        let row: Option<(Option<String>, Option<String>, Option<Vec<u8>>)> = sqlx::query_as(
            "SELECT mail_from, disposition, raw_message FROM inbound_messages WHERE id = $1",
        )
        .bind(message_id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(
            |(mail_from, disposition, raw_message)| StoredInboundMessage {
                mail_from: mail_from.unwrap_or_default(),
                disposition: disposition.unwrap_or_default(),
                raw_message: raw_message.map(bytes::Bytes::from),
            },
        ))
    }

    async fn record_attempt(&self, record: &AttemptRecord) -> anyhow::Result<()> {
        sqlx::query(
            "INSERT INTO inbound_delivery_attempts
                 (message_id, recipient, attempt, stage, outcome, error)
             VALUES ($1, $2, $3, $4, $5, $6)",
        )
        .bind(&record.message_id)
        .bind(&record.recipient)
        .bind(record.attempt)
        .bind(record.stage)
        .bind(record.outcome)
        .bind(record.error.as_deref())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn mark_delivered(&self, job: &RecipientJob, attempt: i32) -> anyhow::Result<()> {
        sqlx::query(
            "UPDATE inbound_recipients
                SET status = 'delivered', attempt = $3, delivered_at = NOW(),
                    next_attempt_at = NOW(), last_error = NULL, updated_at = NOW()
              WHERE message_id = $1 AND recipient = $2",
        )
        .bind(&job.message_id)
        .bind(&job.recipient)
        .bind(attempt)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn mark_deferred(
        &self,
        job: &RecipientJob,
        attempt: i32,
        next_attempt_at: DateTime<Utc>,
        error: &str,
    ) -> anyhow::Result<()> {
        sqlx::query(
            "UPDATE inbound_recipients
                SET status = 'deferred', attempt = $3, next_attempt_at = $4,
                    last_error = $5, updated_at = NOW()
              WHERE message_id = $1 AND recipient = $2",
        )
        .bind(&job.message_id)
        .bind(&job.recipient)
        .bind(attempt)
        .bind(next_attempt_at)
        .bind(error)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn mark_permanent_failure(
        &self,
        job: &RecipientJob,
        attempt: i32,
        error: &str,
    ) -> anyhow::Result<()> {
        sqlx::query(
            "UPDATE inbound_recipients
                SET status = 'failed', attempt = $3, next_attempt_at = NOW(),
                    last_error = $4, updated_at = NOW()
              WHERE message_id = $1 AND recipient = $2",
        )
        .bind(&job.message_id)
        .bind(&job.recipient)
        .bind(attempt)
        .bind(error)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn mark_undeliverable(
        &self,
        job: &RecipientJob,
        attempt: i32,
        error: &str,
    ) -> anyhow::Result<()> {
        sqlx::query(
            "UPDATE inbound_recipients
                SET status = 'undeliverable', attempt = $3, next_attempt_at = NOW(),
                    last_error = $4, updated_at = NOW()
              WHERE message_id = $1 AND recipient = $2",
        )
        .bind(&job.message_id)
        .bind(&job.recipient)
        .bind(attempt)
        .bind(error)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn claim_dsn(&self, job: &RecipientJob) -> anyhow::Result<bool> {
        let result = sqlx::query(
            "UPDATE inbound_recipients
                SET dsn_generated_at = NOW(), updated_at = NOW()
              WHERE message_id = $1 AND recipient = $2
                AND status <> 'dsn_sent'",
        )
        .bind(&job.message_id)
        .bind(&job.recipient)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() == 1)
    }

    async fn mark_dsn_sent(&self, job: &RecipientJob, attempt: i32) -> anyhow::Result<()> {
        sqlx::query(
            "UPDATE inbound_recipients
                SET status = 'dsn_sent', attempt = $3,
                    dsn_generated_at = COALESCE(dsn_generated_at, NOW()),
                    next_attempt_at = NOW(), updated_at = NOW()
              WHERE message_id = $1 AND recipient = $2",
        )
        .bind(&job.message_id)
        .bind(&job.recipient)
        .bind(attempt)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn release_dsn_claim(
        &self,
        job: &RecipientJob,
        next_attempt_at: DateTime<Utc>,
        error: &str,
    ) -> anyhow::Result<()> {
        sqlx::query(
            "UPDATE inbound_recipients
                SET status = 'failed', dsn_generated_at = NULL,
                    next_attempt_at = $3, last_error = $4, updated_at = NOW()
              WHERE message_id = $1 AND recipient = $2",
        )
        .bind(&job.message_id)
        .bind(&job.recipient)
        .bind(next_attempt_at)
        .bind(error)
        .execute(&self.pool)
        .await?;
        Ok(())
    }
}

// ── mailstore delivery implementation ──────────────────────────────────────────

pub struct MailstoreDeliverer {
    client: MailstoreClient,
}

impl MailstoreDeliverer {
    pub fn new(client: MailstoreClient) -> Self {
        Self { client }
    }
}

/// Run one mailstore RPC under a bounded deadline. `None` = timed out.
async fn rpc_with_deadline<T>(fut: impl Future<Output = T>, dur: Duration) -> Option<T> {
    match tokio::time::timeout(dur, fut).await {
        Ok(value) => Some(value),
        Err(_) => {
            warn!(timeout = %dur.as_secs(), "mailstore RPC timed out");
            None
        }
    }
}

fn transient(cause: impl std::fmt::Display) -> DeliveryOutcome {
    DeliveryOutcome::Transient {
        error: cause.to_string(),
    }
}

fn permanent(cause: impl std::fmt::Display, dsn_status: &'static str) -> DeliveryOutcome {
    DeliveryOutcome::Permanent {
        error: cause.to_string(),
        dsn_status,
    }
}

/// Map a tonic status to the delivery outcome. NotFound is the mailstore's
/// "no such account/mailbox" answer (determinate); availability/timeout
/// errors are transient and must be retried, never dropped.
fn outcome_from_status(status: &tonic::Status) -> DeliveryOutcome {
    use tonic::Code;
    match status.code() {
        Code::NotFound => permanent(format!("mailstore: {status}"), "5.1.1"),
        Code::InvalidArgument | Code::FailedPrecondition | Code::PermissionDenied => {
            permanent(format!("mailstore refused delivery: {status}"), "5.3.0")
        }
        Code::ResourceExhausted => {
            permanent(format!("mailstore quota exhausted: {status}"), "5.2.2")
        }
        _ => transient(format!("mailstore unavailable: {status}")),
    }
}

#[async_trait]
impl MailboxDeliverer for MailstoreDeliverer {
    async fn deliver(&self, job: &RecipientJob, message: &StoredInboundMessage) -> DeliveryOutcome {
        let Some(raw) = message.raw_message.as_ref() else {
            return permanent("stored inbound message has no body", "5.3.0");
        };

        let mut client = self.client.clone();
        let account_id = match resolve_mailstore_account(&mut client, job).await {
            Ok(account_id) => account_id,
            Err(outcome) => return outcome,
        };

        // DMARC p=quarantine lands in the Junk folder ("Spam" is the
        // mailstore's name for the \Junk special-use mailbox).
        let requested = if message.disposition.eq_ignore_ascii_case("quarantine") {
            QUARANTINE_MAILBOX
        } else {
            INBOX_MAILBOX
        };
        let mut mailbox = requested.to_string();
        loop {
            let request = StoreMessageRequest {
                account_id: account_id.clone(),
                mailbox: mailbox.clone(),
                raw_message: raw.clone(),
                flags: Some(MessageFlags {
                    recent: true,
                    ..Default::default()
                }),
                internal_date: Utc::now().timestamp(),
                dedup_exempt: false,
            };
            match rpc_with_deadline(client.store_message(request), MAILSTORE_RPC_TIMEOUT).await {
                Some(Ok(response)) => {
                    info!(
                        message_id = %job.message_id,
                        recipient = %mail_common::pii::redact_email(&job.recipient),
                        mailbox = %mailbox,
                        uid = response.into_inner().uid,
                        "Inbound message delivered to mailstore mailbox"
                    );
                    return DeliveryOutcome::Delivered;
                }
                Some(Err(status)) if status.code() == tonic::Code::NotFound => {
                    if mailbox == INBOX_MAILBOX {
                        // Even the Inbox is gone: determinate, not a service
                        // failure. The ledger + DSN path owns it from here.
                        return permanent("mailstore has no Inbox for the account", "5.1.1");
                    }
                    warn!(
                        message_id = %job.message_id,
                        mailbox = %mailbox,
                        "Mailbox not found for delivery; falling back to Inbox"
                    );
                    mailbox = INBOX_MAILBOX.to_string();
                }
                Some(Err(status)) => return outcome_from_status(&status),
                None => return transient("mailstore store_message RPC timed out"),
            }
        }
    }
}

async fn resolve_mailstore_account(
    client: &mut MailstoreClient,
    job: &RecipientJob,
) -> Result<String, DeliveryOutcome> {
    // Prefer the account id resolved at RCPT time (canonical, immune to
    // address case), falling back to the recipient address for legacy rows.
    let by_id = job.mailbox_id.clone().unwrap_or_default();
    let by_email = if by_id.is_empty() {
        job.recipient.clone()
    } else {
        String::new()
    };
    if by_id.is_empty() && by_email.is_empty() {
        return Err(permanent("recipient has no mailbox identity", "5.1.1"));
    }
    let lookup = GetAccountRequest {
        account_id: by_id,
        email: by_email,
    };
    match rpc_with_deadline(client.get_account(lookup), MAILSTORE_RPC_TIMEOUT).await {
        Some(Ok(response)) => {
            let account_id = response.into_inner().account_id;
            if account_id.is_empty() {
                Err(permanent(
                    "mailstore has no account for the recipient",
                    "5.1.1",
                ))
            } else {
                Ok(account_id)
            }
        }
        Some(Err(status)) => Err(outcome_from_status(&status)),
        None => Err(transient("mailstore get_account RPC timed out")),
    }
}

// ── DSN dispatch implementation ────────────────────────────────────────────────

pub struct PgDsnDispatcher {
    pool: PgPool,
}

impl PgDsnDispatcher {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl DsnDispatcher for PgDsnDispatcher {
    async fn dispatch(&self, dsn: &DeliveryStatusNotification) -> Result<(), String> {
        let recipient_domain = recipient_domain(&dsn.original_recipient)
            .ok_or_else(|| {
                "original recipient has no domain to originate the DSN from".to_string()
            })?
            .trim_end_matches('.')
            .to_ascii_lowercase();

        // The DSN is originated by the receiving domain (the domain that
        // accepted the message), exactly like any other outbound mail: the
        // outbound worker validates the envelope sender's domain and needs a
        // ready DKIM identity for it. A domain that is not ready yet is a
        // retryable dispatch failure — the claim is released and retried.
        let domain_row: Option<(uuid::Uuid, Option<uuid::Uuid>)> = sqlx::query_as(
            "SELECT id, tenant_id FROM domains
              WHERE LOWER(name) = LOWER($1)
                AND status = 'verified'
                AND dkim_enabled = true
                AND dkim_selector IS NOT NULL
                AND dkim_private_key IS NOT NULL
              LIMIT 1",
        )
        .bind(&recipient_domain)
        .fetch_optional(&self.pool)
        .await
        .map_err(|error| format!("DSN domain lookup failed: {error}"))?;
        let (domain_id, tenant_id) = domain_row.ok_or_else(|| {
            format!("no ready DKIM domain '{recipient_domain}' to originate the DSN")
        })?;

        let envelope_from = format!("MAILER-DAEMON@{recipient_domain}");
        let mime = dsn.render(&envelope_from);
        let text_body = dsn.human_readable();
        let html_body = format!(
            "<html><body><pre>{}</pre></body></html>",
            escape_html(&text_body)
        );
        let headers = serde_json::json!({
            "X-ApexMail-DSN-Recipient": dsn.original_recipient,
            "X-ApexMail-DSN-Status": sanitize_status(&dsn.status),
        });
        let metadata = serde_json::json!({
            "dsn": {
                "original_message_id": dsn.original_message_id,
                "original_recipient": dsn.original_recipient,
                "final_recipient": dsn.original_recipient,
                "action": "failed",
                "status": sanitize_status(&dsn.status),
                "reporting_mta": dsn.reporting_mta,
            }
        });

        let queue_id = uuid::Uuid::new_v4();
        sqlx::query(
            r#"INSERT INTO email_queue (
                id, message_id, tenant_id, domain_id, from_address, to_addresses,
                subject, "from", "to", html, text, raw_headers, headers,
                attachments, metadata, scheduled_at, priority, status,
                created_at, updated_at
            ) VALUES (
                $1, NULL, $2, $3, $4, ARRAY[$5],
                $6, $4, $5, $7, $8, $9, $10,
                '[]'::jsonb, $11, NULL, 5, 'pending',
                NOW(), NOW()
            )"#,
        )
        .bind(queue_id)
        .bind(tenant_id)
        .bind(domain_id)
        .bind(&envelope_from)
        .bind(&dsn.original_sender)
        .bind(DSN_SUBJECT)
        .bind(&html_body)
        .bind(&text_body)
        // The complete RFC 3464 report is preserved on the queue row (the
        // outbound worker renders the transported MIME from html/text).
        .bind(String::from_utf8_lossy(&mime).to_string())
        .bind(headers)
        .bind(metadata)
        .execute(&self.pool)
        .await
        .map_err(|error| format!("failed to enqueue DSN: {error}"))?;

        info!(
            queue_id = %queue_id,
            original_message_id = %dsn.original_message_id,
            to = %mail_common::pii::redact_email(&dsn.original_sender),
            "DSN enqueued for outbound delivery"
        );
        Ok(())
    }
}

fn escape_html(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

// ── worker runtime ─────────────────────────────────────────────────────────────

pub struct InboundDeliveryWorker {
    store: Arc<dyn InboundDeliveryStore>,
    deliverer: Arc<dyn MailboxDeliverer>,
    dsn_dispatcher: Arc<dyn DsnDispatcher>,
    policy: RetryPolicy,
    config: SweepConfig,
    poll_interval: Duration,
}

impl InboundDeliveryWorker {
    /// Production worker wired to the shared Postgres pool and the
    /// mailstore gRPC endpoint.
    pub fn new(pool: PgPool, mailstore_addr: &str, hostname: String) -> anyhow::Result<Self> {
        let channel = Channel::from_shared(mailstore_addr.to_string())
            .map_err(|error| anyhow::anyhow!("invalid MAILSTORE_GRPC_ADDR: {error}"))?
            .timeout(MAILSTORE_CHANNEL_TIMEOUT)
            .connect_lazy();
        let interceptor = InternalServiceAuthInterceptor::from_env().map_err(|error| {
            anyhow::anyhow!("invalid internal mailstore authentication: {error}")
        })?;
        let client = MailstoreServiceClient::with_interceptor(channel, interceptor);
        Ok(Self {
            store: Arc::new(PgInboundDeliveryStore::new(pool.clone())),
            deliverer: Arc::new(MailstoreDeliverer::new(client)),
            dsn_dispatcher: Arc::new(PgDsnDispatcher::new(pool)),
            policy: RetryPolicy::default(),
            config: SweepConfig {
                batch: SWEEP_BATCH,
                lease_secs: CLAIM_LEASE_SECS,
                dsn_retry_secs: DSN_RETRY_SECS,
                hostname,
            },
            poll_interval: Duration::from_secs(SWEEP_POLL_SECS),
        })
    }

    pub async fn run_once(&self) -> anyhow::Result<SweepStats> {
        run_sweep(
            &*self.store,
            &*self.deliverer,
            &*self.dsn_dispatcher,
            &self.policy,
            &self.config,
            Utc::now(),
        )
        .await
    }

    /// Poll loop; the first tick fires immediately so a message is delivered
    /// right after its `250` whenever the worker is idle.
    ///
    /// Returns `Ok(())` only when `shutdown` is notified; it is meant to run
    /// inside the binary's listener supervisor, so a panic or unexpected exit
    /// fails the process (and the orchestrator restarts it) instead of
    /// leaving accepted mail undelivered behind a healthy-looking MTA.
    pub async fn run(self: Arc<Self>, shutdown: Arc<Notify>) -> anyhow::Result<()> {
        let mut ticker = tokio::time::interval(self.poll_interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                _ = ticker.tick() => {
                    match self.run_once().await {
                        Ok(stats) if stats.claimed > 0 => {
                            debug!(?stats, "Inbound delivery sweep completed");
                        }
                        Ok(_) => {}
                        Err(error) => {
                            // A transient DB/mailstore outage must not kill
                            // the worker: the ledger rows stay due and the
                            // next tick retries them.
                            error!(%error, "Inbound delivery sweep failed; will retry on the next tick");
                        }
                    }
                }
                _ = shutdown.notified() => break,
            }
        }
        Ok(())
    }
}

// ── tests ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::Mutex;

    fn utc(seconds: i64) -> DateTime<Utc> {
        DateTime::from_timestamp(1_800_000_000 + seconds, 0).unwrap()
    }

    fn test_config() -> SweepConfig {
        SweepConfig {
            batch: 32,
            lease_secs: 120,
            dsn_retry_secs: 300,
            hostname: "mail.test".to_string(),
        }
    }

    fn test_policy() -> RetryPolicy {
        RetryPolicy {
            max_attempts: 4,
            backoff_secs: vec![30, 120, 600, 3600],
        }
    }

    fn message(mail_from: &str) -> StoredInboundMessage {
        StoredInboundMessage {
            mail_from: mail_from.to_string(),
            disposition: "accept".to_string(),
            raw_message: Some(bytes::Bytes::from_static(b"Subject: hi\r\n\r\nbody\r\n")),
        }
    }

    #[derive(Debug, Clone)]
    struct MemRecipient {
        message_id: String,
        recipient: String,
        mailbox_id: Option<String>,
        status: String,
        attempt: i32,
        next_attempt_at: DateTime<Utc>,
        delivered_at: Option<DateTime<Utc>>,
        dsn_generated_at: Option<DateTime<Utc>>,
        last_error: Option<String>,
    }

    /// In-memory `InboundDeliveryStore` mirroring the SQL semantics of
    /// migration 210 (claim predicate, lease, DSN claim guard).
    struct MemStore {
        jobs: Mutex<Vec<MemRecipient>>,
        messages: Mutex<std::collections::HashMap<String, StoredInboundMessage>>,
        attempts: Mutex<Vec<AttemptRecord>>,
    }

    impl MemStore {
        fn new(jobs: Vec<MemRecipient>) -> Self {
            Self {
                jobs: Mutex::new(jobs),
                messages: Mutex::new(std::collections::HashMap::new()),
                attempts: Mutex::new(Vec::new()),
            }
        }

        fn with_message(self, message_id: &str, message: StoredInboundMessage) -> Self {
            self.messages
                .lock()
                .unwrap()
                .insert(message_id.to_string(), message);
            self
        }

        fn job(&self, message_id: &str, recipient: &str) -> MemRecipient {
            self.jobs
                .lock()
                .unwrap()
                .iter()
                .find(|job| job.message_id == message_id && job.recipient == recipient)
                .cloned()
                .expect("job exists")
        }

        fn attempts(&self) -> Vec<AttemptRecord> {
            self.attempts.lock().unwrap().clone()
        }

        fn update<F: FnOnce(&mut MemRecipient)>(&self, job: &RecipientJob, apply: F) {
            let mut jobs = self.jobs.lock().unwrap();
            let row = jobs
                .iter_mut()
                .find(|row| row.message_id == job.message_id && row.recipient == job.recipient)
                .expect("job exists");
            apply(row);
        }
    }

    #[async_trait]
    impl InboundDeliveryStore for MemStore {
        async fn claim_due(
            &self,
            now: DateTime<Utc>,
            limit: i64,
            lease_secs: i64,
        ) -> anyhow::Result<Vec<RecipientJob>> {
            let mut jobs = self.jobs.lock().unwrap();
            let mut due: Vec<usize> = jobs
                .iter()
                .enumerate()
                .filter(|(_, job)| {
                    job.next_attempt_at <= now
                        && matches!(
                            job.status.as_str(),
                            STATUS_PENDING | STATUS_DELIVERING | STATUS_DEFERRED | STATUS_FAILED
                        )
                })
                .map(|(index, _)| index)
                .collect();
            due.sort_by_key(|index| jobs[*index].next_attempt_at);
            due.truncate(limit as usize);
            let mut claimed = Vec::new();
            for index in due {
                let row = &mut jobs[index];
                let prior_status = row.status.clone();
                row.status = STATUS_DELIVERING.to_string();
                row.next_attempt_at = now + chrono::Duration::seconds(lease_secs);
                claimed.push(RecipientJob {
                    message_id: row.message_id.clone(),
                    recipient: row.recipient.clone(),
                    mailbox_id: row.mailbox_id.clone(),
                    prior_status,
                    attempt: row.attempt,
                    last_error: row.last_error.clone(),
                });
            }
            Ok(claimed)
        }

        async fn load_message(
            &self,
            message_id: &str,
        ) -> anyhow::Result<Option<StoredInboundMessage>> {
            Ok(self.messages.lock().unwrap().get(message_id).cloned())
        }

        async fn record_attempt(&self, record: &AttemptRecord) -> anyhow::Result<()> {
            self.attempts.lock().unwrap().push(record.clone());
            Ok(())
        }

        async fn mark_delivered(&self, job: &RecipientJob, attempt: i32) -> anyhow::Result<()> {
            self.update(job, |row| {
                row.status = STATUS_DELIVERED.to_string();
                row.attempt = attempt;
                row.delivered_at = Some(Utc::now());
                row.last_error = None;
            });
            Ok(())
        }

        async fn mark_deferred(
            &self,
            job: &RecipientJob,
            attempt: i32,
            next_attempt_at: DateTime<Utc>,
            error: &str,
        ) -> anyhow::Result<()> {
            self.update(job, |row| {
                row.status = STATUS_DEFERRED.to_string();
                row.attempt = attempt;
                row.next_attempt_at = next_attempt_at;
                row.last_error = Some(error.to_string());
            });
            Ok(())
        }

        async fn mark_permanent_failure(
            &self,
            job: &RecipientJob,
            attempt: i32,
            error: &str,
        ) -> anyhow::Result<()> {
            self.update(job, |row| {
                row.status = STATUS_FAILED.to_string();
                row.attempt = attempt;
                row.next_attempt_at = Utc::now();
                row.last_error = Some(error.to_string());
            });
            Ok(())
        }

        async fn mark_undeliverable(
            &self,
            job: &RecipientJob,
            attempt: i32,
            error: &str,
        ) -> anyhow::Result<()> {
            self.update(job, |row| {
                row.status = STATUS_UNDELIVERABLE.to_string();
                row.attempt = attempt;
                row.last_error = Some(error.to_string());
            });
            Ok(())
        }

        async fn claim_dsn(&self, job: &RecipientJob) -> anyhow::Result<bool> {
            let mut claimed = false;
            self.update(job, |row| {
                if row.status != STATUS_DSN_SENT {
                    row.dsn_generated_at = Some(Utc::now());
                    claimed = true;
                }
            });
            Ok(claimed)
        }

        async fn mark_dsn_sent(&self, job: &RecipientJob, attempt: i32) -> anyhow::Result<()> {
            self.update(job, |row| {
                row.status = STATUS_DSN_SENT.to_string();
                row.attempt = attempt;
                row.dsn_generated_at.get_or_insert_with(Utc::now);
            });
            Ok(())
        }

        async fn release_dsn_claim(
            &self,
            job: &RecipientJob,
            next_attempt_at: DateTime<Utc>,
            error: &str,
        ) -> anyhow::Result<()> {
            self.update(job, |row| {
                row.status = STATUS_FAILED.to_string();
                row.next_attempt_at = next_attempt_at;
                row.dsn_generated_at = None;
                row.last_error = Some(error.to_string());
            });
            Ok(())
        }
    }

    struct ScriptedDeliverer {
        outcomes: Mutex<VecDeque<DeliveryOutcome>>,
        fallback: DeliveryOutcome,
        calls: AtomicUsize,
    }

    impl ScriptedDeliverer {
        fn new(outcomes: Vec<DeliveryOutcome>) -> Self {
            Self {
                outcomes: Mutex::new(outcomes.into()),
                fallback: DeliveryOutcome::Delivered,
                calls: AtomicUsize::new(0),
            }
        }

        /// Every call returns `outcome` once the script is exhausted.
        fn always(outcome: DeliveryOutcome) -> Self {
            Self {
                outcomes: Mutex::new(VecDeque::new()),
                fallback: outcome,
                calls: AtomicUsize::new(0),
            }
        }
    }

    #[async_trait]
    impl MailboxDeliverer for ScriptedDeliverer {
        async fn deliver(
            &self,
            _job: &RecipientJob,
            _message: &StoredInboundMessage,
        ) -> DeliveryOutcome {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.outcomes
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or_else(|| self.fallback.clone())
        }
    }

    struct RecordingDsn {
        sent: Mutex<Vec<DeliveryStatusNotification>>,
        fail_next: AtomicBool,
    }

    impl RecordingDsn {
        fn new() -> Self {
            Self {
                sent: Mutex::new(Vec::new()),
                fail_next: AtomicBool::new(false),
            }
        }

        fn sent_count(&self) -> usize {
            self.sent.lock().unwrap().len()
        }
    }

    #[async_trait]
    impl DsnDispatcher for RecordingDsn {
        async fn dispatch(&self, dsn: &DeliveryStatusNotification) -> Result<(), String> {
            if self.fail_next.swap(false, Ordering::SeqCst) {
                return Err("outbound queue unavailable".to_string());
            }
            self.sent.lock().unwrap().push(dsn.clone());
            Ok(())
        }
    }

    fn job_row(message_id: &str, recipient: &str) -> MemRecipient {
        MemRecipient {
            message_id: message_id.to_string(),
            recipient: recipient.to_string(),
            mailbox_id: Some("11111111-1111-1111-1111-111111111111".to_string()),
            status: STATUS_PENDING.to_string(),
            attempt: 0,
            next_attempt_at: utc(0),
            delivered_at: None,
            dsn_generated_at: None,
            last_error: None,
        }
    }

    #[tokio::test]
    async fn transient_failure_is_retried_and_eventually_delivered() {
        let store = MemStore::new(vec![job_row("inb_1", "user@managed.test")])
            .with_message("inb_1", message("sender@remote.test"));
        let deliverer = ScriptedDeliverer::new(vec![
            DeliveryOutcome::Transient {
                error: "mailstore unavailable".into(),
            },
            DeliveryOutcome::Delivered,
        ]);
        let dsn = RecordingDsn::new();
        let policy = test_policy();
        let config = test_config();

        let first = run_sweep(&store, &deliverer, &dsn, &policy, &config, utc(0))
            .await
            .unwrap();
        assert_eq!(first.deferred, 1);
        assert_eq!(first.delivered, 0);
        let row = store.job("inb_1", "user@managed.test");
        assert_eq!(row.status, STATUS_DEFERRED);
        assert_eq!(row.attempt, 1);
        assert_eq!(row.next_attempt_at, utc(30));

        // Not due yet: no claim, no extra attempt.
        let early = run_sweep(&store, &deliverer, &dsn, &policy, &config, utc(10))
            .await
            .unwrap();
        assert_eq!(early.claimed, 0);
        assert_eq!(deliverer.calls.load(Ordering::SeqCst), 1);

        let second = run_sweep(&store, &deliverer, &dsn, &policy, &config, utc(31))
            .await
            .unwrap();
        assert_eq!(second.delivered, 1);
        let row = store.job("inb_1", "user@managed.test");
        assert_eq!(row.status, STATUS_DELIVERED);
        assert_eq!(row.attempt, 2);
        assert!(row.delivered_at.is_some());
        assert_eq!(dsn.sent_count(), 0, "a delivered message needs no DSN");

        let outcomes: Vec<&str> = store
            .attempts()
            .iter()
            .map(|attempt| attempt.outcome)
            .collect();
        assert_eq!(outcomes, vec!["transient", "delivered"]);
    }

    #[tokio::test]
    async fn permanent_failure_generates_exactly_one_dsn_across_sweeps() {
        let store = MemStore::new(vec![job_row("inb_2", "gone@managed.test")])
            .with_message("inb_2", message("sender@remote.test"));
        let deliverer = ScriptedDeliverer::new(vec![DeliveryOutcome::Permanent {
            error: "mailstore has no Inbox for the account".into(),
            dsn_status: "5.1.1",
        }]);
        let dsn = RecordingDsn::new();
        let policy = test_policy();
        let config = test_config();

        let first = run_sweep(&store, &deliverer, &dsn, &policy, &config, utc(0))
            .await
            .unwrap();
        assert_eq!(first.permanent, 1);
        assert_eq!(first.dsn_sent, 1);
        assert_eq!(dsn.sent_count(), 1);
        let row = store.job("inb_2", "gone@managed.test");
        assert_eq!(row.status, STATUS_DSN_SENT);
        assert!(row.dsn_generated_at.is_some());

        // A second and third pass must not produce another DSN.
        for later in [utc(3600), utc(7200)] {
            let stats = run_sweep(&store, &deliverer, &dsn, &policy, &config, later)
                .await
                .unwrap();
            assert_eq!(stats.claimed, 0);
        }
        assert_eq!(dsn.sent_count(), 1, "DSN generation must be idempotent");

        // The generated report is a real RFC 3464 multipart/report.
        let report = dsn.sent.lock().unwrap()[0].clone();
        let rendered = String::from_utf8(report.render("MAILER-DAEMON@managed.test")).unwrap();
        assert!(rendered.contains("multipart/report; report-type=delivery-status"));
        assert!(rendered.contains("Final-Recipient: rfc822; gone@managed.test"));
        assert!(rendered.contains("Action: failed"));
        assert!(rendered.contains("Status: 5.1.1"));
        assert!(rendered.contains("Reporting-MTA: dns; mail.test"));
    }

    #[tokio::test]
    async fn null_return_path_never_generates_a_dsn() {
        let store = MemStore::new(vec![
            job_row("inb_3", "gone@managed.test"),
            job_row("inb_4", "bounce@managed.test"),
        ])
        .with_message(
            "inb_3",
            StoredInboundMessage {
                mail_from: String::new(), // stored form of <>
                disposition: "accept".into(),
                raw_message: Some(bytes::Bytes::from_static(b"Subject: dsn\r\n\r\n")),
            },
        )
        .with_message(
            "inb_4",
            StoredInboundMessage {
                mail_from: "<>".to_string(),
                disposition: "accept".into(),
                raw_message: Some(bytes::Bytes::from_static(b"Subject: dsn\r\n\r\n")),
            },
        );
        let deliverer = ScriptedDeliverer::new(vec![
            DeliveryOutcome::Permanent {
                error: "no account".into(),
                dsn_status: "5.1.1",
            },
            DeliveryOutcome::Permanent {
                error: "no account".into(),
                dsn_status: "5.1.1",
            },
        ]);
        let dsn = RecordingDsn::new();

        let stats = run_sweep(
            &store,
            &deliverer,
            &dsn,
            &test_policy(),
            &test_config(),
            utc(0),
        )
        .await
        .unwrap();
        assert_eq!(stats.undeliverable, 2);
        assert_eq!(stats.dsn_sent, 0);
        assert_eq!(dsn.sent_count(), 0, "null return path must never get a DSN");
        assert_eq!(
            store.job("inb_3", "gone@managed.test").status,
            STATUS_UNDELIVERABLE
        );
        assert_eq!(
            store.job("inb_4", "bounce@managed.test").status,
            STATUS_UNDELIVERABLE
        );
        assert!(store
            .job("inb_3", "gone@managed.test")
            .dsn_generated_at
            .is_none());
    }

    #[tokio::test]
    async fn exhausted_transient_retries_become_permanent_then_dsn() {
        let store = MemStore::new(vec![job_row("inb_5", "user@managed.test")])
            .with_message("inb_5", message("sender@remote.test"));
        let deliverer = ScriptedDeliverer::always(DeliveryOutcome::Transient {
            error: "mailstore down".into(),
        });
        let dsn = RecordingDsn::new();
        let policy = RetryPolicy {
            max_attempts: 2,
            backoff_secs: vec![30],
        };
        let config = test_config();

        let stats = run_sweep(&store, &deliverer, &dsn, &policy, &config, utc(0))
            .await
            .unwrap();
        assert_eq!(stats.deferred, 1, "first attempt defers");

        let stats = run_sweep(&store, &deliverer, &dsn, &policy, &config, utc(31))
            .await
            .unwrap();
        assert_eq!(stats.permanent, 1);
        assert_eq!(stats.dsn_sent, 1);
        assert_eq!(dsn.sent_count(), 1);
        let row = store.job("inb_5", "user@managed.test");
        assert_eq!(row.status, STATUS_DSN_SENT);
        assert_eq!(row.attempt, 2);
    }

    #[tokio::test]
    async fn failed_dsn_dispatch_is_retried_without_duplicating() {
        let store = MemStore::new(vec![job_row("inb_6", "gone@managed.test")])
            .with_message("inb_6", message("sender@remote.test"));
        let deliverer = ScriptedDeliverer::new(vec![DeliveryOutcome::Permanent {
            error: "no account".into(),
            dsn_status: "5.1.1",
        }]);
        let dsn = RecordingDsn::new();
        dsn.fail_next.store(true, Ordering::SeqCst);
        let policy = test_policy();
        let config = test_config();

        let stats = run_sweep(&store, &deliverer, &dsn, &policy, &config, utc(0))
            .await
            .unwrap();
        assert_eq!(stats.dsn_deferred, 1);
        assert_eq!(dsn.sent_count(), 0);
        let row = store.job("inb_6", "gone@managed.test");
        assert_eq!(row.status, STATUS_FAILED);
        assert!(row.dsn_generated_at.is_none(), "claim must be released");
        assert_eq!(row.next_attempt_at, utc(300));

        // The retry must not re-attempt mailbox delivery (it already failed
        // permanently) and must produce exactly one DSN.
        let calls_before = deliverer.calls.load(Ordering::SeqCst);
        let stats = run_sweep(&store, &deliverer, &dsn, &policy, &config, utc(301))
            .await
            .unwrap();
        assert_eq!(stats.dsn_sent, 1);
        assert_eq!(deliverer.calls.load(Ordering::SeqCst), calls_before);
        assert_eq!(dsn.sent_count(), 1);

        let stats = run_sweep(&store, &deliverer, &dsn, &policy, &config, utc(4000))
            .await
            .unwrap();
        assert_eq!(stats.claimed, 0);
        assert_eq!(dsn.sent_count(), 1);
    }

    #[tokio::test]
    async fn dsn_claim_crash_is_redispatched_not_lost() {
        // A worker that crashed between `claim_dsn` and `mark_dsn_sent`
        // leaves status='failed' with dsn_generated_at already stamped. The
        // next sweep must re-dispatch (at-least-once) rather than leave the
        // recipient without a DSN forever.
        let mut row = job_row("inb_8", "gone@managed.test");
        row.status = STATUS_FAILED.to_string();
        row.attempt = 1;
        row.dsn_generated_at = Some(utc(0));
        row.next_attempt_at = utc(0);
        row.last_error = Some("no mailstore account".into());
        let store = MemStore::new(vec![row]).with_message("inb_8", message("sender@remote.test"));
        let deliverer = ScriptedDeliverer::new(vec![DeliveryOutcome::Permanent {
            error: "no account".into(),
            dsn_status: "5.1.1",
        }]);
        let dsn = RecordingDsn::new();

        let stats = run_sweep(
            &store,
            &deliverer,
            &dsn,
            &test_policy(),
            &test_config(),
            utc(10),
        )
        .await
        .unwrap();
        assert_eq!(stats.dsn_sent, 1);
        assert_eq!(dsn.sent_count(), 1);
        assert_eq!(deliverer.calls.load(Ordering::SeqCst), 0);
        assert_eq!(
            store.job("inb_8", "gone@managed.test").status,
            STATUS_DSN_SENT
        );

        // Once finalized, later sweeps remain silent.
        let stats = run_sweep(
            &store,
            &deliverer,
            &dsn,
            &test_policy(),
            &test_config(),
            utc(5000),
        )
        .await
        .unwrap();
        assert_eq!(stats.claimed, 0);
        assert_eq!(dsn.sent_count(), 1);
    }

    #[tokio::test]
    async fn claimed_lease_expiry_recovers_a_crashed_worker() {
        // A row left in 'delivering' with an expired lease is claimable
        // again — a crashed worker cannot strand a message forever.
        let mut row = job_row("inb_7", "user@managed.test");
        row.status = STATUS_DELIVERING.to_string();
        row.next_attempt_at = utc(0);
        let store = MemStore::new(vec![row]).with_message("inb_7", message("sender@remote.test"));
        let deliverer = ScriptedDeliverer::new(vec![DeliveryOutcome::Delivered]);
        let dsn = RecordingDsn::new();

        let stats = run_sweep(
            &store,
            &deliverer,
            &dsn,
            &test_policy(),
            &test_config(),
            utc(120),
        )
        .await
        .unwrap();
        assert_eq!(stats.delivered, 1);
        assert_eq!(
            store.job("inb_7", "user@managed.test").status,
            STATUS_DELIVERED
        );
    }

    #[test]
    fn dsn_eligibility_matrix() {
        assert!(dsn_eligible("sender@remote.test"));
        assert!(!dsn_eligible(""));
        assert!(!dsn_eligible("   "));
        assert!(!dsn_eligible("<>"));
        assert!(!dsn_eligible(" <> "));
    }

    #[test]
    fn dsn_renders_strict_crlf_and_sanitises_status() {
        let dsn = DeliveryStatusNotification {
            reporting_mta: "mail.test".into(),
            original_sender: "sender@remote.test".into(),
            original_recipient: "user@managed.test".into(),
            original_message_id: "inb_abc".into(),
            arrival_date: utc(0),
            status: "not-a-status".into(),
            diagnostic: "mailstore exploded".into(),
            original_message: Some(bytes::Bytes::from_static(b"Subject: hi\r\n\r\nbody\r\n")),
        };
        let rendered = String::from_utf8(dsn.render("MAILER-DAEMON@managed.test")).unwrap();
        assert!(
            rendered.contains("Status: 5.4.7"),
            "malformed status must fall back"
        );
        assert!(
            rendered.contains("Subject: hi"),
            "original must be attached"
        );
        // CRLF-only: removing every CRLF must leave no bare LF.
        assert!(!rendered.replace("\r\n", "").contains('\n'));
        // Deterministic Message-ID.
        assert_eq!(dsn.message_id(), dsn.clone().message_id());
    }

    #[test]
    fn hostile_values_cannot_inject_dsn_headers() {
        let dsn = DeliveryStatusNotification {
            reporting_mta: "mail.test\r\nX-Injected: yes".into(),
            original_sender: "victim@example.com\r\nBcc: attacker@evil.test".into(),
            original_recipient: "user@managed.test\r\nX-Injected: 1".into(),
            original_message_id: "inb_1\r\nX-Injected: 2".into(),
            arrival_date: utc(0),
            status: "5.1.1".into(),
            diagnostic: "boom\r\nX-Injected: 3".into(),
            original_message: Some(bytes::Bytes::from_static(b"Subject: ok\r\n\r\n")),
        };
        let rendered = String::from_utf8(dsn.render("MAILER-DAEMON@managed.test")).unwrap();
        assert!(
            !rendered.contains("\r\nBcc:"),
            "header injection via sender"
        );
        assert!(
            !rendered.contains("\r\nX-Injected:"),
            "header injection via fields"
        );
        assert!(!rendered.replace("\r\n", "").contains('\n'));
    }

    #[test]
    fn hostile_recipients_do_not_panic() {
        for recipient in [
            "",
            "   ",
            "@",
            "user@",
            "@example.com",
            "a@b@c",
            &"x".repeat(10_000),
            "user@exämple.com",
            "user@managed.test\r\n",
            "<>",
        ] {
            let dsn = DeliveryStatusNotification {
                reporting_mta: "mail.test".into(),
                original_sender: "sender@remote.test".into(),
                original_recipient: recipient.to_string(),
                original_message_id: "inb_x".into(),
                arrival_date: utc(0),
                status: "5.1.1".into(),
                diagnostic: String::new(),
                original_message: None,
            };
            let rendered = dsn.render("MAILER-DAEMON@managed.test");
            assert!(!rendered.is_empty());
            let _ = dsn.human_readable();
            let _ = dsn.message_id();
        }
    }

    #[tokio::test]
    async fn rpc_with_deadline_bounds_hung_calls() {
        let result =
            rpc_with_deadline(std::future::pending::<()>(), Duration::from_millis(20)).await;
        assert_eq!(result, None);
        assert_eq!(
            rpc_with_deadline(async { 42 }, Duration::from_millis(50)).await,
            Some(42)
        );
    }

    #[test]
    fn retry_policy_delay_is_capped_at_last_step() {
        let policy = RetryPolicy {
            max_attempts: 10,
            backoff_secs: vec![30, 120],
        };
        assert_eq!(policy.delay_secs(1), 30);
        assert_eq!(policy.delay_secs(2), 120);
        assert_eq!(policy.delay_secs(9), 120);
        let empty = RetryPolicy {
            max_attempts: 1,
            backoff_secs: vec![],
        };
        assert_eq!(empty.delay_secs(1), 300);
    }
}
